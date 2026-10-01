"""Mailgun (https://www.mailgun.com) -- HTTPS API delivery.

Mailgun's message endpoint speaks **``application/x-www-form-urlencoded``**,
not JSON. The base class helper :meth:`Provider._http_json` only serialises
JSON, so this module does the HTTP call itself with :mod:`urllib.request`.
That is not a workaround for missing functionality -- it is the contract:
sending JSON here returns ``400`` with a body like ``to parameter is not a
valid address``, which sends people hunting for a broken address instead of
a broken content type.

Authentication is HTTP Basic with the fixed user ``api`` and the private
API key as the password, which is what the ``auth=(user, password)``
parameter of the base helper does. Because we build the request by hand,
this file adds the ``Authorization: Basic ...`` header itself and maps the
status codes to the same error types the router expects.

Two vendor-specific details:

* The endpoint is per-domain (``/v3/<domain>/messages``). There is no
  "default domain"; the operator must copy the sending domain out of the
  Mailgun control panel. A wrong domain yields HTTP 404, so we turn that
  into an explicit Chinese hint rather than a bare status code.
* The Reply-To header must be form-encoded as ``h:Reply-To``. Mailgun
  understands ``h:<Header-Name>`` for arbitrary headers, and plain
  ``reply-to`` is silently ignored -- another quiet failure that costs an
  evening.

The EU region uses a different host (``api.eu.mailgun.net``). We expose it
as a region choice instead of hardcoding one endpoint, because an account
created in the EU cannot authenticate against the US host at all.
"""
from __future__ import annotations

import base64
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

from ...core.errors import AuthError, ProviderError, RateLimitError
from ..message import Message
from .base import CHOICE, EMAIL, PASSWORD, Field, Provider, register

US_HOST = "https://api.mailgun.net"
EU_HOST = "https://api.eu.mailgun.net"
REGIONS = ("us", "eu")


def _region_host(region: str) -> str:
    return EU_HOST if (region or "us").strip().lower() == "eu" else US_HOST


def _post_form(url: str, fields: dict, user: str, password: str,
               timeout: float = 20.0):
    """POST ``fields`` as a form. Returns (status, parsed-body-or-text).

    Mirrors the error mapping of :meth:`Provider._http_json` -- AuthError on
    401/403, RateLimitError on 429, ProviderError otherwise -- so the router
    can reason about fallbacks identically across providers.
    """
    body = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "vigil/1.0 (+server-monitor)")
    token = base64.b64encode(("%s:%s" % (user, password)).encode()).decode()
    req.add_header("Authorization", "Basic " + token)

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
        if e.code in (401, 403):
            raise AuthError("mailgun: 凭据被拒绝（HTTP %d）" % e.code,
                            hint=raw[:300])
        if e.code == 429:
            raise RateLimitError("mailgun: 触发频率限制（HTTP 429）",
                                 hint=raw[:300])
        raise ProviderError("mailgun: 接口返回 HTTP %d" % e.code,
                            hint=raw[:300])
    except urllib.error.URLError as e:
        raise ProviderError("mailgun: 网络错误：%s" % e.reason)
    except socket.timeout:
        raise ProviderError("mailgun: 请求超时")


@register
class Mailgun(Provider):
    id = "mailgun"
    label = "Mailgun（HTTPS API）"
    label_en = "Mailgun (HTTPS API)"
    kind = "api"
    blurb = ("Mailgun 的 messages 接口，按发送域名区分端点。"
             "不依赖本机 MTA；需先在 Mailgun 验证发件域名并拿到 API Key。")
    blurb_en = ("Mailgun messages API, addressed per sending domain. Needs no "
                "local MTA; verify the domain and copy the API key first.")
    docs_url = "https://documentation.mailgun.com/en/latest/api-sending.html"

    fields = (
        Field("api_key", "API 密钥", "API key", kind=PASSWORD, secret=True,
              hint="Mailgun 控制台 → Settings → API Keys → Private API key"
                   "（形如 key-xxxxxxxx）。注意不是 Public validation key，"
                   "后者无法发信。",
              hint_en="Mailgun dashboard -> Settings -> API Keys -> Private "
                      "API key (key-...). The public validation key cannot "
                      "send mail."),
        Field("domain", "发送域名", "Sending domain",
              example="mg.example.com",
              hint="Mailgun 控制台 → Sending → Domains 里的域名，"
                   "不是邮箱地址，也不要带 http:// 前缀。",
              hint_en="The domain from Mailgun's Sending -> Domains page, "
                      "not an email address."),
        Field("region", "API 区域", "API region", kind=CHOICE,
              choices=REGIONS, default="us", required=False,
              hint="美国区填 us，欧洲区（EU）填 eu。选错区域会直接返回 401。",
              hint_en="Pick the region the account was created in; the wrong "
                      "one returns 401."),
        Field("from_address", "发件地址", "From address", kind=EMAIL,
              example="alerts@mg.example.com",
              hint="必须属于上面填写的发送域名的子域，例如 mg.example.com "
                   "下可用 alerts@mg.example.com。",
              hint_en="Must be on the sending domain configured above."),
        Field("from_name", "发件人显示名", "Display name", required=False,
              default="Server Monitor"),
        Field("reply_to", "回复地址", "Reply-To", kind=EMAIL, required=False,
              hint="建议填管理员邮箱；本插件会以 h:Reply-To 形式提交。",
              hint_en="Optional admin mailbox; sent as the h:Reply-To field."),
    )

    # -- sending ----------------------------------------------------------
    def send(self, msg: Message, to: str) -> str:
        key = self.p("api_key")
        if not key:
            raise AuthError("mailgun: 未配置 API 密钥（api_key）",
                            hint="运行 `vigil mail setup` 填写 Mailgun 私有 API Key。")
        domain = self.p("domain").strip()
        if not domain:
            raise ProviderError("mailgun: 未配置发送域名（domain）",
                                hint="在 Mailgun 控制台的 Sending → Domains 中查看。")

        frm = self.p("from_address") or msg.from_address
        if not frm:
            raise ProviderError("mailgun: 未配置发件地址（from_address）")
        name = self.p("from_name") or msg.from_name
        from_hdr = "%s <%s>" % (name, frm) if name else frm

        # Form fields, not JSON. Empty optional values are omitted because an
        # empty `html=` overrides the text part with an empty body.
        fields = {
            "from": from_hdr,
            "to": to,
            "subject": msg.subject,
            "text": msg.text or "",
        }
        if msg.html and msg.html.strip():
            fields["html"] = msg.html
        reply_to = self.p("reply_to") or msg.reply_to
        if reply_to:
            fields["h:Reply-To"] = reply_to

        url = "%s/v3/%s/messages" % (_region_host(self.p("region")),
                                     urllib.parse.quote(domain, safe=""))
        status, body = _post_form(url, fields, "api", key)
        if status not in (200, 201):
            raise ProviderError("mailgun: 意外的 HTTP %s" % status,
                                hint=str(body)[:300])
        if isinstance(body, dict):
            if body.get("id"):
                return str(body["id"])
            if body.get("message"):
                raise ProviderError("mailgun: %s" % body["message"])
        return "mailgun-ok"

    # -- health -----------------------------------------------------------
    def health(self):
        """List the account's domains -- read-only, and it proves the key.

        This doubles as a configuration check: if the configured domain is
        not in the list, the operator has almost certainly typed the wrong
        one (or is pointed at the wrong region), and that is worth saying
        here rather than at 3am on the first alert.
        """
        problems = self.validate()
        if problems:
            return False, "; ".join(problems)
        host = _region_host(self.p("region"))
        url = "%s/v3/domains?limit=100" % host
        req = urllib.request.Request(url, method="GET")
        token = base64.b64encode(("api:%s" % self.p("api_key")).encode()).decode()
        req.add_header("Authorization", "Basic " + token)
        req.add_header("Accept", "application/json")
        ctx = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace") or "{}")
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                return False, ("Mailgun 拒绝了该 API Key（HTTP %d）；"
                               "请检查密钥与区域设置" % e.code)
            return False, "Mailgun 接口返回 HTTP %d" % e.code
        except urllib.error.URLError as e:
            return False, "无法连接 Mailgun：%s" % e.reason
        except ValueError:
            return False, "Mailgun 返回了非 JSON 响应"

        want = self.p("domain").strip().lower()
        names = [str(d.get("name", "")).lower()
                 for d in (data.get("items") or [])]
        if names and want not in names:
            return False, ("API Key 有效，但账号下没有域名 %s（当前区域 %s）"
                           % (want, self.p("region") or "us"))
        return True, "Mailgun API Key 与域名 %s 可用" % want
