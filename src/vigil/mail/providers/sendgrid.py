"""SendGrid (https://sendgrid.com) -- HTTPS API delivery.

SendGrid's v3 Mail Send endpoint is not a flat JSON object like Resend's.
Everything a human would call "the message" is nested inside
``personalizations``: the recipient list lives there, not at the top level.
Getting that wrong is the classic first-integration bug -- the API answers
``400 Bad Request`` with a body that does not point at the nesting.

Three quirks shaped this file:

* **Success is HTTP 202 with an empty body.** There is no message id to
  hand back, unlike Resend. We synthesise one from the ``X-Message-Id``
  response header when SendGrid provides it, and fall back to a fixed
  marker otherwise. Callers only need a short string for the log line.
* **``reply_to`` must be an object** (``{"email": ...}``), not the plain
  string every other vendor accepts. Sending a string yields a validation
  error, so we never take the shortcut here.
* **``from`` must be an object** as well, and its address has to live on a
  domain authenticated in SendGrid (Sender Authentication). A mismatch is
  rejected at send time, which is why the hint below tells the operator to
  set that up before wiring alerts to it.

We deliberately send one HTTP request per recipient, matching the rest of
the product: a single request carrying N recipients still bills as N
emails, but a partial failure is then indistinguishable from success.
"""
from __future__ import annotations

from ...core.errors import AuthError, ProviderError
from ..message import Message
from .base import EMAIL, PASSWORD, Field, Provider, register

API_URL = "https://api.sendgrid.com/v3/mail/send"

#: v3 scope needed by Mail Send; the health probe asks for exactly this.
SEND_SCOPE = "mail.send"


@register
class Sendgrid(Provider):
    id = "sendgrid"
    label = "SendGrid（HTTPS API）"
    label_en = "SendGrid (HTTPS API)"
    kind = "api"
    blurb = ("Twilio SendGrid 的 v3 邮件接口。不依赖本机 MTA，"
             "但发件域名必须先在 SendGrid 完成 Sender Authentication 认证。")
    blurb_en = ("Twilio SendGrid v3 Mail Send. Needs no local MTA, but the "
                "From domain must be authenticated in SendGrid first.")
    docs_url = "https://www.twilio.com/docs/sendgrid/api-reference/mail-send"

    fields = (
        Field("api_key", "API 密钥", "API key", kind=PASSWORD, secret=True,
              example="SG.xxxxxxxxxxxxxxxxxxxxxx",
              hint="SendGrid 控制台 → Settings → API Keys → Create API Key，"
                   "权限至少勾选 Mail Send（mail.send）。以 SG. 开头。",
              hint_en="SendGrid dashboard -> Settings -> API Keys -> Create "
                      "API Key with at least the Mail Send scope."),
        Field("from_address", "发件地址", "From address", kind=EMAIL,
              example="alerts@mail.example.com",
              hint="必须属于已在 SendGrid 完成 Sender Authentication"
                   "（域名认证）的域名，否则接口会直接拒绝发送。",
              hint_en="Must belong to a domain authenticated in SendGrid "
                      "(Sender Authentication)."),
        Field("from_name", "发件人显示名", "Display name", required=False,
              default="Server Monitor",
              hint="显示在收件人邮箱里的发件人名称，可留空。",
              hint_en="Display name shown in the recipient's mailbox."),
        Field("reply_to", "回复地址", "Reply-To", kind=EMAIL, required=False,
              hint="建议填管理员邮箱，便于直接回复告警。SendGrid 要求这里是"
                   "对象形式，本插件已自动处理。",
              hint_en="Optional admin mailbox for replies; the provider wraps "
                      "it into the object form SendGrid requires."),
    )

    # -- sending ----------------------------------------------------------
    def send(self, msg: Message, to: str) -> str:
        key = self.p("api_key")
        if not key:
            raise AuthError("sendgrid: 未配置 API 密钥（api_key）",
                            hint="运行 `vigil mail setup` 填写 SendGrid API Key。")

        frm = self.p("from_address") or msg.from_address
        if not frm:
            raise ProviderError("sendgrid: 未配置发件地址（from_address）",
                                hint="在 SendGrid 已验证的域名下选择一个发件地址。")
        name = self.p("from_name") or msg.from_name

        from_obj = {"email": frm}
        if name:
            from_obj["name"] = name

        # Both parts are always sent: SendGrid content is an ordered list and
        # a text/plain alternative is what keeps the alert readable in
        # text-only clients. An empty html part would be worse than omitting
        # it, so we only add it when there is something to add.
        content = [{"type": "text/plain", "value": msg.text or ""}]
        if msg.html and msg.html.strip():
            content.append({"type": "text/html", "value": msg.html})

        payload = {
            "personalizations": [{"to": [{"email": to}]}],
            "from": from_obj,
            "subject": msg.subject,
            "content": content,
        }

        reply_to = self.p("reply_to") or msg.reply_to
        if reply_to:
            # NOT a bare string: SendGrid validates this field as an object.
            payload["reply_to"] = {"email": reply_to}

        status, headers, body = self._http_json(
            API_URL, payload, headers={"Authorization": "Bearer %s" % key},
        )
        if status != 202:
            raise ProviderError("sendgrid: 意外的 HTTP %s" % status,
                                hint=str(body)[:300])

        # 202 carries no body, so the response header is the only id source.
        sent_id = ""
        if isinstance(headers, dict):
            sent_id = str(headers.get("X-Message-Id")
                          or headers.get("x-message-id") or "")
        return sent_id or "sendgrid-ok"

    # -- health -----------------------------------------------------------
    def health(self):
        """Ask SendGrid which scopes this key holds.

        ``GET /v3/scopes`` is a read-only call that proves both the key and
        its permissions, so it is safe to run from ``vigil doctor``. It is
        much friendlier than discovering a Mail-Send-only key is missing a
        scope at the moment the first alert fires.
        """
        problems = self.validate()
        if problems:
            return False, "; ".join(problems)
        key = self.p("api_key")
        try:
            _s, _h, body = self._http_json(
                "https://api.sendgrid.com/v3/scopes", None, method="GET",
                headers={"Authorization": "Bearer %s" % key},
            )
        except AuthError as e:
            return False, "SendGrid 拒绝了该 API Key：%s" % e.render()
        except ProviderError as e:
            return False, "无法访问 SendGrid：%s" % e.render()

        scopes = body.get("scopes", []) if isinstance(body, dict) else []
        if scopes and SEND_SCOPE not in scopes:
            return False, ("API Key 有效但缺少 %s 权限，无法发送邮件" % SEND_SCOPE)
        return True, "SendGrid API Key 有效，已授权 %s" % SEND_SCOPE
