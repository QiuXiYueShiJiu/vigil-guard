"""Brevo (formerly Sendinblue) -- HTTPS API delivery.

Brevo's transactional endpoint is plain JSON, so the base class helper does
all the work; the only things worth documenting are the small differences
from the other providers that trip people up:

* **Authentication is a custom header, not a bearer token.** The key goes
  in ``api-key:``. Sending ``Authorization: Bearer`` yields 401, and the
  Brevo panel shows both an API key and an SMTP key -- only the API key
  works over HTTPS, the SMTP key is for port 587.
* **The field names are not the obvious ones.** The body carries
  ``sender`` (an object), ``to`` (a list of objects), ``textContent`` and
  ``htmlContent``, and ``replyTo`` (an object). A body written with
  ``from``/``subject``-style names borrowed from another vendor fails with
  a validation error listing several unrelated fields.
* **Success is 201, but 200 is also accepted.** Brevo has returned 201
  historically and 200 in some deployments; treating either as success
  avoids a false failure on an alert that was actually delivered.

Brevo's free tier stamps a "Sent with Brevo" footer onto messages unless
the account has a paid plan and the sending domain is authenticated. That
is a billing nuance, not a bug, so we only mention it in the hint.
"""
from __future__ import annotations

from ...core.errors import AuthError, ProviderError
from ..message import Message
from .base import EMAIL, PASSWORD, Field, Provider, register

API_URL = "https://api.brevo.com/v3/smtp/email"


@register
class Brevo(Provider):
    id = "brevo"
    label = "Brevo / Sendinblue（HTTPS API）"
    label_en = "Brevo / Sendinblue (HTTPS API)"
    kind = "api"
    blurb = ("Brevo 事务邮件接口，每天有免费额度。不依赖本机 MTA，"
             "免费版会在邮件尾部附加 Brevo 签名。")
    blurb_en = ("Brevo transactional email with a free daily quota. Needs no "
                "local MTA; the free plan appends a Brevo footer.")
    docs_url = "https://developers.brevo.com/reference/sendtransacemail"

    fields = (
        Field("api_key", "API 密钥", "API key", kind=PASSWORD, secret=True,
              example="xkeysib-xxxxxxxxxxxxxxxxxxxx",
              hint="Brevo 控制台 → SMTP & API → API Keys → 生成 v3 API Key"
                   "（形如 xkeysib-）。注意不要填 SMTP Key，那个只能用于 SMTP。",
              hint_en="Brevo dashboard -> SMTP & API -> API Keys -> create a "
                      "v3 key (xkeysib-...). The SMTP key will not work here."),
        Field("from_address", "发件地址", "From address", kind=EMAIL,
              example="alerts@example.com",
              hint="建议使用已在 Brevo 验证的发件域名下的地址；"
                   "未验证域名在免费版会附加 Brevo 推广页脚。",
              hint_en="Prefer an address on a domain authenticated in Brevo."),
        Field("from_name", "发件人显示名", "Display name", required=False,
              default="Server Monitor"),
        Field("reply_to", "回复地址", "Reply-To", kind=EMAIL, required=False,
              hint="建议填管理员邮箱，便于直接回复告警。",
              hint_en="Optional admin mailbox for replies."),
    )

    # -- sending ----------------------------------------------------------
    def send(self, msg: Message, to: str) -> str:
        key = self.p("api_key")
        if not key:
            raise AuthError("brevo: 未配置 API 密钥（api_key）",
                            hint="运行 `vigil mail setup` 填写 Brevo v3 API Key。")

        frm = self.p("from_address") or msg.from_address
        if not frm:
            raise ProviderError("brevo: 未配置发件地址（from_address）")
        name = self.p("from_name") or msg.from_name

        sender = {"email": frm}
        if name:
            sender["name"] = name

        payload = {
            "sender": sender,
            "to": [{"email": to}],
            "subject": msg.subject,
            "textContent": msg.text or "",
        }
        if msg.html and msg.html.strip():
            payload["htmlContent"] = msg.html
        reply_to = self.p("reply_to") or msg.reply_to
        if reply_to:
            # Object again, not a string -- see the module docstring.
            payload["replyTo"] = {"email": reply_to}

        status, _headers, body = self._http_json(
            API_URL, payload, headers={"api-key": key},
        )
        if status not in (200, 201):
            raise ProviderError("brevo: 意外的 HTTP %s" % status,
                                hint=str(body)[:300])
        if isinstance(body, dict):
            mid = body.get("messageId") or body.get("messageIds")
            if isinstance(mid, list) and mid:
                return str(mid[0])
            if mid:
                return str(mid)
            # Brevo reports some validation problems with HTTP 2xx + code.
            if body.get("code") and body.get("message"):
                raise ProviderError("brevo: %s" % body["message"])
        return "brevo-ok"

    # -- health -----------------------------------------------------------
    def health(self):
        """Validate parameters only.

        Brevo's read-only account endpoint (``GET /v3/account``) is
        restricted on many plans and would report a false failure for a key
        that can send perfectly well. There is no cheap, universally
        permitted probe, so we deliberately stop at parameter validation
        instead of making a write call or a misleading read call.
        """
        problems = self.validate()
        if problems:
            return False, "; ".join(problems)
        return True, "参数已填写（Brevo 无只读探活接口，未发起实际请求）"
