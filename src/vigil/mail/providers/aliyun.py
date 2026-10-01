"""Aliyun DirectMail (阿里云邮件推送) -- HTTPS API delivery, RPC style.

This provider exists because "just use SMTP" is not always available on a
mainland host: outbound port 25 is commonly blocked, and DirectMail is the
relay most Chinese operators already have an account for.

The API is Aliyun's classic **RPC style**, which is materially different
from the REST/JSON vendors in this package:

* **The request is form-encoded, not JSON.** Every parameter -- including
  ``Action``, ``Version`` and the signature itself -- is a form field. The
  response is JSON when ``Format=JSON`` is requested.
* **Requests are signed with HMAC-SHA1 over a canonical string.** The
  signature is computed from the sorted, percent-encoded parameters, then
  itself added as the ``Signature`` parameter. The two encoding details
  that break naive implementations are: a space must become ``%20`` (never
  ``+``) and ``~`` must stay literal, so we post-process
  :func:`urllib.parse.quote` exactly as the specification describes.
* **The ``Timestamp`` must be UTC ISO8601 ending in ``Z``.** A local-time
  stamp is rejected with ``InvalidTimeStamp.Expired`` even when the clock
  is right, which is a confusing failure on a CST-configured host.
* **A ``SignatureNonce`` is mandatory** so a retry is not mistaken for a
  replay.

Two operational facts the hints repeat because they cause almost every
first-time failure:

1. the sending domain must be verified in the Aliyun console (a TXT record
   plus, for DirectMail, a CNAME for the tracking/return path), and
2. ``AccountName`` must be an address *on that verified domain* -- it is
   the envelope sender and cannot be an arbitrary mailbox.

Application errors also come back with HTTP 200 and a JSON ``Code`` field.
We translate the auth-ish codes into :class:`AuthError`, the throttling and
quota codes into :class:`RateLimitError`, and everything else into
:class:`ProviderError`, so the router's fallback logic still works.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone

from ...core.errors import AuthError, ProviderError, RateLimitError
from ..message import Message
from .base import EMAIL, PASSWORD, TEXT, Field, Provider, register

API_HOST = "https://dm.aliyuncs.com/"
API_VERSION = "2015-11-23"
SIGNATURE_METHOD = "HMAC-SHA1"
SIGNATURE_VERSION = "1.0"
FORMAT = "JSON"
ACTION = "SingleSendMail"

#: Error codes that mean "the credentials are wrong", not "try later".
_AUTH_CODES = {
    "InvalidAccessKeyId.NotFound",
    "InvalidAccessKeyId.Inactive",
    "SignatureDoesNotMatch",
    "Forbidden",
    "NoPermission",
    "Forbidden.AccountNotAuthorized",
}
#: Error codes that mean "slow down" or "quota gone"; retrying elsewhere is
#: the router's job, retrying here will not help.
_RATE_CODES = {
    "Throttling",
    "Throttling.User",
    "Throttling.Api",
    "InvalidSendTimes",
    "DailyLimitExceeded",
    "QuotaExceeded",
    "AccountDailyLimit",
    "ExceedDailyQuota",
    "ExceedHourlyQuota",
}


def _percent_encode(value) -> str:
    """RFC 3986 encoding as Aliyun's RPC signature spec requires.

    ``urllib.parse.quote`` leaves ``~`` alone (correct) but ``urlencode``
    turns spaces into ``+`` (incorrect for the signature base string).
    Applying :func:`quote` after str() gives us ``%20`` and then we put
    ``~`` back in case a caller already encoded it.
    """
    encoded = urllib.parse.quote(str(value), safe="")
    return encoded.replace("+", "%20").replace("*", "%2A").replace("%7E", "~")


def _build_signature(params: dict, secret: str) -> str:
    """Compute the RPC-v1.0 HMAC-SHA1 signature for *params*.

    Base string = ``POST&%2F&`` + percent-encoded sorted canonical query,
    signed with ``"<secret>&"`` -- the trailing ampersand is part of the
    spec and is the single most common omission.
    """
    canonical = "&".join(
        "%s=%s" % (_percent_encode(k), _percent_encode(params[k]))
        for k in sorted(params)
    )
    string_to_sign = "POST&%s&%s" % (_percent_encode("/"), _percent_encode(canonical))
    digest = hmac.new(
        (secret + "&").encode("utf-8"),
        string_to_sign.encode("utf-8"),
        hashlib.sha1,
    ).digest()
    return base64.b64encode(digest).decode("ascii")


def _post_signed(fields: dict, timeout: float = 20.0):
    """POST the already-signed form. Returns (status, parsed-body-or-text)."""
    body = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(API_HOST, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "vigil/1.0 (+server-monitor)")
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read().decode("utf-8", "replace")
            try:
                return resp.status, json.loads(raw)
            except ValueError:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = ""
        try:
            raw = e.read().decode("utf-8", "replace")
        except Exception:
            pass
        # Aliyun returns structured errors even on non-2xx; parse if we can
        # so the raised error carries the vendor's own Code.
        parsed = None
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = None
        if e.code in (401, 403):
            raise AuthError("aliyun: 凭据被拒绝（HTTP %d）" % e.code,
                            hint=_code_hint(parsed, raw))
        if e.code == 429:
            raise RateLimitError("aliyun: 触发频率限制（HTTP 429）",
                                 hint=_code_hint(parsed, raw))
        if parsed and isinstance(parsed, dict) and parsed.get("Code"):
            _raise_for_code(parsed, http_status=e.code)
        raise ProviderError("aliyun: 接口返回 HTTP %d" % e.code,
                            hint=_code_hint(parsed, raw))
    except urllib.error.URLError as e:
        raise ProviderError("aliyun: 网络错误：%s" % e.reason)
    except socket.timeout:
        raise ProviderError("aliyun: 请求超时")


def _code_hint(parsed, raw: str) -> str:
    if isinstance(parsed, dict) and parsed.get("Message"):
        return "%s: %s" % (parsed.get("Code", ""), parsed.get("Message", ""))[:300]
    return str(raw)[:300]


def _raise_for_code(body: dict, http_status: int = 200) -> None:
    """Turn an Aliyun error body (HTTP 200 included) into an exception."""
    code = str(body.get("Code") or "")
    message = str(body.get("Message") or code)
    if code in _AUTH_CODES:
        raise AuthError("aliyun: %s" % message, hint=_CHINESE_HINT)
    if code in _RATE_CODES:
        raise RateLimitError("aliyun: %s" % message, hint=_CHINESE_HINT)
    raise ProviderError("aliyun: %s (%s)" % (message, code), hint=_CHINESE_HINT)


_CHINESE_HINT = (
    "请检查：① AccessKey ID/Secret 是否正确且已启用；"
    "② 发件域名是否已在阿里云邮件推送控制台完成验证（DNS 的 TXT/CNAME 记录）；"
    "③ AccountName 是否为该已验证域名下的地址；"
    "④ 是否已开通邮件推送服务并创建了发信地址。"
)


@register
class AliyunDirectMail(Provider):
    id = "aliyun"
    label = "阿里云邮件推送 DirectMail（HTTPS API）"
    label_en = "Aliyun DirectMail (HTTPS API)"
    kind = "api"
    blurb = ("阿里云邮件推送，走 HTTPS 的 RPC 接口，不依赖本机 25 端口。"
             "需先在阿里云控制台验证发件域名并创建发信地址。")
    blurb_en = ("Aliyun DirectMail over the signed HTTPS RPC API; no outbound "
                "port 25 needed. The sending domain must be verified first.")
    docs_url = "https://help.aliyun.com/zh/direct-mail/developer-reference/api-dm-2015-11-23-singlesendmail"

    fields = (
        Field("access_key_id", "AccessKey ID", "AccessKey ID", kind=TEXT,
              secret=True, example="LTAIxxxxxxxxxxxx",
              hint="阿里云控制台右上角头像 → AccessKey 管理。建议使用 RAM 子账号，"
                   "并只授予邮件推送（DirectMail）权限，不要用主账号 AccessKey。",
              hint_en="Aliyun console -> AccessKey management. Prefer a RAM "
                      "user limited to DirectMail permissions."),
        Field("access_key_secret", "AccessKey Secret", "AccessKey Secret",
              kind=PASSWORD, secret=True,
              hint="创建 AccessKey 时显示一次，请立即保存。注意与 ID 不要填反。",
              hint_en="Shown only once when the AccessKey is created."),
        Field("account_name", "发信地址（AccountName）", "Sending address",
              kind=EMAIL, example="alert@mail.example.com",
              hint="必须是已在「邮件推送控制台 → 发信地址」中创建、"
                   "且域名已通过验证的地址；不能随便填一个邮箱。",
              hint_en="Must be a sending address created in the DirectMail "
                      "console on a verified domain."),
        Field("region_id", "地域（RegionId）", "Region", required=False,
              default="cn-hangzhou",
              hint="默认 cn-hangzhou（华东1）。一般保持默认即可，"
                   "DirectMail 的发信端点多数地域共用。",
              hint_en="Defaults to cn-hangzhou; usually fine as-is."),
        Field("from_alias", "发件人昵称", "From alias", required=False,
              hint="显示在收件人邮箱中的发件人名称（形如「服务器监控」）。"
                   "留空则只显示发信地址。",
              hint_en="Display name shown to recipients; optional."),
        Field("reply_to", "回复地址", "Reply-To", kind=EMAIL, required=False,
              hint="建议填管理员邮箱。aliyun 需要开启 ReplyToAddress=true，"
                   "本插件在你填写该字段时会自动开启。",
              hint_en="Optional admin mailbox; enables ReplyToAddress "
                      "automatically."),
    )

    # -- request construction --------------------------------------------
    def _base_params(self) -> dict:
        """Common RPC parameters for every DirectMail call.

        Kept separate from the action-specific ones because the signature is
        computed over the union, and mixing them up is how the
        ``SignatureDoesNotMatch`` error appears.
        """
        return {
            "Format": FORMAT,
            "Version": API_VERSION,
            "AccessKeyId": self.p("access_key_id"),
            "SignatureMethod": SIGNATURE_METHOD,
            "SignatureVersion": SIGNATURE_VERSION,
            "SignatureNonce": str(uuid.uuid4()),
            # Explicit UTC instead of datetime.utcnow(), which is deprecated
            # from Python 3.12 and would emit a warning in the daemon log.
            "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "RegionId": self.p("region_id") or "cn-hangzhou",
            "Action": ACTION,
        }

    def _signed_fields(self, api_params: dict) -> dict:
        params = self._base_params()
        params.update(api_params)
        params["Signature"] = _build_signature(params,
                                               self.p("access_key_secret"))
        return params

    # -- sending ----------------------------------------------------------
    def send(self, msg: Message, to: str) -> str:
        key_id = self.p("access_key_id")
        secret = self.p("access_key_secret")
        if not key_id or not secret:
            raise AuthError("aliyun: 未配置 AccessKey ID 或 AccessKey Secret",
                            hint="运行 `vigil mail setup` 填写阿里云 AccessKey。")
        account = self.p("account_name")
        if not account:
            raise ProviderError("aliyun: 未配置发信地址（account_name）",
                                hint=_CHINESE_HINT)
        if not to:
            raise ProviderError("aliyun: 收件人地址为空")

        api_params = {
            "AccountName": account,
            "AddressType": 1,               # 1 = random/alias address
            "ReplyToAddress": "false",
            "ToAddress": to,
            "Subject": msg.subject,
        }
        alias = self.p("from_alias") or msg.from_name
        if alias:
            api_params["FromAlias"] = alias
        # HtmlBody wins when present; otherwise send the plain text so a
        # text-only alert still renders. Never send both as empty.
        if msg.html and msg.html.strip():
            api_params["HtmlBody"] = msg.html
        else:
            api_params["TextBody"] = msg.text or ""
        reply_to = self.p("reply_to") or msg.reply_to
        if reply_to:
            api_params["ReplyToAddress"] = "true"
            api_params["ReplyTo"] = reply_to

        status, body = _post_signed(self._signed_fields(api_params))
        if status not in (200, 201):
            raise ProviderError("aliyun: 意外的 HTTP %s" % status,
                                hint=str(body)[:300])
        if isinstance(body, dict):
            # DirectMail signals application errors with HTTP 200 + Code.
            if body.get("Code"):
                _raise_for_code(body, http_status=status)
            if body.get("RequestId"):
                return str(body["RequestId"])
        return "aliyun-ok"

    # -- health -----------------------------------------------------------
    def health(self):
        """Validate parameters and credential shape without sending mail.

        There is no read-only DirectMail call that verifies an AccessKey
        safely (``GetAccountList`` is not part of the public API), and this
        probe must never burn a paid sending quota or land in a real inbox.
        So we check what can be checked locally and say so explicitly rather
        than pretending we made a live call.
        """
        problems = self.validate()
        if problems:
            return False, "; ".join(problems)
        if len(self.p("access_key_secret")) < 10:
            return False, "AccessKey Secret 长度异常，请确认没有把 ID 和 Secret 填反"
        return True, "参数已填写（阿里云无只读探活接口，未发起实际请求）"
