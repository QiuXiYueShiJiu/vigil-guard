"""Outbound webhooks -- chat rooms and arbitrary HTTP endpoints.

Not email. Nobody has an "address" here: the destination is baked into the
provider configuration, so the ``to`` argument every other provider gets is
ignored, and ``is_mail = False`` marks that for the router (a webhook
cannot bounce, and a recipient list makes no sense for it).

Every chat vendor invented its own payload, so the interesting work is the
table of shapes below rather than the HTTP call. The important detail that
shapes the whole design is that **three of them report application errors
with HTTP 200**. WeCom, Feishu and DingTalk answer ``200 OK`` and put
``{"errcode": 93000, "errmsg": "invalid webhook url"}`` in the body. If we
only checked the status code, a rotated or mistyped webhook URL would look
like a successful alert forever -- the worst possible failure mode for a
monitoring tool. Hence :meth:`Webhook.send` parses the body for those three
kinds and raises a :class:`ProviderError` on a non-zero code.

Other per-vendor notes that cost real debugging time:

* WeCom and DingTalk only render ``markdown`` payloads. Their ``text``
  message type ignores the body we would send, so we always build markdown.
* Feishu's bot payload is ``msg_type``/``content`` with a nested ``text``;
  the *event* API uses a completely different envelope. This is the bot one.
* Slack wants a single ``text`` string; Discord wants ``content`` and
  hard-caps it at 2000 characters, which a full alert with sections can
  exceed. We truncate to 1900 to stay clear of the limit.
* Telegram is the odd one out: the bot token is part of the URL and
  ``chat_id`` is mandatory, so its target is (bot_token, chat_id) instead
  of a URL. Be careful with tokens in logs -- it is marked secret.

The ``url`` field is marked secret too: chat webhook URLs are bearer
credentials in all but name -- anyone holding one can post into the room.
"""
from __future__ import annotations

from ..message import Message, hostname
from ...core.errors import AuthError, ProviderError
from .base import CHOICE, PASSWORD, TEXT, Field, Provider, register

KIND_GENERIC = "generic"
KIND_WECOM = "wecom"
KIND_FEISHU = "feishu"
KIND_DINGTALK = "dingtalk"
KIND_SLACK = "slack"
KIND_DISCORD = "discord"
KIND_TELEGRAM = "telegram"

KINDS = (KIND_GENERIC, KIND_WECOM, KIND_FEISHU, KIND_DINGTALK,
         KIND_SLACK, KIND_DISCORD, KIND_TELEGRAM)

#: Kinds that return HTTP 200 even when the payload was rejected.
BODY_CHECKED = (KIND_WECOM, KIND_FEISHU, KIND_DINGTALK)

#: Discord's hard limit is 2000 characters; leave room for the marker.
DISCORD_LIMIT = 1900

TELEGRAM_API = "https://api.telegram.org"

KIND_LABELS = {
    KIND_GENERIC: "通用 JSON（自建服务 / 其他机器人）",
    KIND_WECOM: "企业微信（群机器人）",
    KIND_FEISHU: "飞书（自定义机器人）",
    KIND_DINGTALK: "钉钉（自定义机器人）",
    KIND_SLACK: "Slack（Incoming Webhook）",
    KIND_DISCORD: "Discord（Webhook）",
    KIND_TELEGRAM: "Telegram（Bot API）",
}


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    # Keep the head: an alert's first lines carry the host and severity.
    return text[:limit - 20] + "\n...(内容过长已截断)"


@register
class Webhook(Provider):
    id = "webhook"
    label = "Webhook 通知（企业微信 / 飞书 / 钉钉 / Slack / Discord / Telegram）"
    label_en = ("Webhook notification (WeCom / Feishu / DingTalk / Slack / "
                "Discord / Telegram)")
    kind = "webhook"
    blurb = ("把告警推到聊天群，适合不常看邮箱的值班场景。"
             "注意：这不是邮件通道，不占用收件人地址。")
    blurb_en = ("Push alerts into a chat room for on-call rotations. Not an "
                "email channel; recipients do not apply.")
    docs_url = "https://core.telegram.org/bots/api"
    #: A webhook is a fixed drop: nobody to address, and nothing to bounce.
    is_mail = False

    fields = (
        Field("url", "Webhook 地址", "Webhook URL", kind=PASSWORD,
              secret=True, required=False,
              example="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx",
              hint="企业微信 / 飞书 / 钉钉 / Slack / Discord 的群机器人地址，"
                   "在对应群的「添加机器人」里获取。Telegram 请改为填写 bot_token"
                   " 与 chat_id，此处留空。该地址等同密码，请勿外泄。",
              hint_en="Incoming-webhook URL for WeCom/Feishu/DingTalk/Slack/"
                      "Discord. For Telegram leave this empty and fill "
                      "bot_token + chat_id instead."),
        Field("kind", "Webhook 类型", "Webhook kind", kind=CHOICE,
              choices=KINDS, default=KIND_WECOM,
              hint="决定发送的 JSON 结构。选错类型通常表现为对方返回"
                   "「参数错误」或消息不显示。",
              hint_en="Selects the payload shape; a mismatch usually shows up "
                      "as a vendor-side parameter error."),
        Field("bot_token", "Telegram Bot Token", "Telegram bot token",
              kind=PASSWORD, secret=True, required=False,
              hint="仅 Telegram 需要。在 Telegram 里找 @BotFather → /newbot "
                   "获取，形如 123456:ABC-DEF...。",
              hint_en="Telegram only: obtain from @BotFather (/newbot)."),
        Field("chat_id", "Telegram Chat ID", "Telegram chat ID",
              kind=TEXT, required=False, example="-1001234567890",
              hint="仅 Telegram 需要。可先用 getUpdates 查看，群组 ID 通常以 - 开头。",
              hint_en="Telegram only; group ids usually start with -."),
    )

    # -- helpers ----------------------------------------------------------
    def kind_name(self) -> str:
        kind = (self.p("kind") or KIND_GENERIC).strip().lower()
        return kind if kind in KINDS else KIND_GENERIC

    def is_telegram(self) -> bool:
        return self.kind_name() == KIND_TELEGRAM

    def target_url(self) -> str:
        if self.is_telegram():
            return "%s/bot%s/sendMessage" % (TELEGRAM_API,
                                             self.p("bot_token").strip())
        return self.p("url").strip()

    def validate(self) -> list:
        """Webhook needs *either* a URL or a Telegram bot token + chat id.

        The base implementation would demand every field, which is wrong
        here: filling ``url`` and ``bot_token`` at once is normal when the
        operator is switching kinds, and only one of them is used.
        """
        problems = []
        if not self.p("kind"):
            problems.append("webhook: 未选择 webhook 类型（kind）")
        elif self.kind_name() != (self.p("kind") or "").strip().lower():
            problems.append("webhook: 未知的 webhook 类型 %s" % self.p("kind"))
        if self.is_telegram():
            if not self.p("bot_token"):
                problems.append("webhook: Telegram 需要 bot_token")
            if not self.p("chat_id"):
                problems.append("webhook: Telegram 需要 chat_id")
        elif not self.p("url"):
            problems.append("webhook: 未填写 webhook 地址（url）")
        return problems

    def payload(self, msg: Message) -> dict:
        """Build the vendor-specific JSON body.

        The plain-text rendering is used everywhere rather than the HTML
        one: chat clients do not render email HTML, and a markdown renderer
        that receives ``<table>`` markup shows it literally.
        """
        kind = self.kind_name()
        subject = msg.subject or ""
        text = msg.text or ""
        # Most chat bots have no separate subject line, so the subject is
        # folded into the body with a blank line.
        both = "%s\n\n%s" % (subject, text) if subject else text

        if kind == KIND_GENERIC:
            # Deliberately boring: host/subject/text/severity is what a
            # self-hosted receiver or an automation bridge can parse.
            return {
                "host": hostname(),
                "subject": subject,
                "text": text,
                "severity": msg.severity,
            }
        if kind == KIND_WECOM:
            return {"msgtype": "markdown", "markdown": {"content": both}}
        if kind == KIND_FEISHU:
            return {"msg_type": "text", "content": {"text": both}}
        if kind == KIND_DINGTALK:
            # DingTalk shows `title` in the notification preview and `text`
            # in the bubble; markdown is required for line breaks.
            return {"msgtype": "markdown",
                    "markdown": {"title": subject, "text": both}}
        if kind == KIND_SLACK:
            return {"text": both}
        if kind == KIND_DISCORD:
            return {"content": _truncate(both, DISCORD_LIMIT)}
        if kind == KIND_TELEGRAM:
            return {"chat_id": self.p("chat_id"),
                    "text": both,
                    "disable_web_page_preview": True}
        # Unreachable via kind_name(), kept for safety if a new kind is added
        # to KINDS without extending this method.
        raise ProviderError("webhook: 不支持的类型 %s" % kind)

    # -- body-level error detection --------------------------------------
    @staticmethod
    def _body_error(kind: str, body) -> str:
        """Return a non-empty message when the vendor rejected the payload.

        WeCom/DingTalk use ``errcode``/``errmsg`` (0/"ok" on success), Feishu
        uses ``code``/``msg``. Anything unexpected in the body is treated as
        an error rather than silently ignored, because a chat vendor that
        returns 200 with neither shape means our parser is wrong, and the
        alert may not have arrived.
        """
        if not isinstance(body, dict):
            # A 200 with an unparsable body is suspicious enough to report
            # for the checked kinds; Slack/Discord may legitimately return
            # an empty body, and they are not in this branch.
            return "响应不是 JSON，无法确认是否发送成功"
        if kind in (KIND_WECOM, KIND_DINGTALK):
            code = body.get("errcode")
            if code in (0, "0", None):
                # errcode missing entirely: check errmsg before accepting.
                msg = str(body.get("errmsg", "") or "")
                if msg and msg.lower() != "ok":
                    return msg
                return ""
            return "%s (%s)" % (body.get("errmsg") or "未知错误", code)
        if kind == KIND_FEISHU:
            code = body.get("code")
            if code in (0, "0", None):
                msg = str(body.get("msg", "") or "")
                if msg and msg.lower() not in ("ok", "success"):
                    return msg
                return ""
            return "%s (%s)" % (body.get("msg") or "未知错误", code)
        return ""

    # -- sending ----------------------------------------------------------
    def send(self, msg: Message, to: str) -> str:
        # `to` is intentionally unused: the destination is the configured
        # webhook, not a per-alert recipient. Kept in the signature because
        # the router calls every provider the same way.
        del to

        problems = self.validate()
        if problems:
            raise ProviderError("; ".join(problems))

        kind = self.kind_name()
        payload = self.payload(msg)

        # One code path for every kind: for Telegram target_url() already
        # embeds the bot token, so a rejected token arrives as HTTP 401 and
        # the base helper turns it into AuthError exactly like any other
        # vendor. No special case needed, which keeps error mapping uniform.
        status, _headers, body = self._http_json(self.target_url(), payload,
                                                 timeout=15.0)

        if status not in (200, 201, 204):
            raise ProviderError("webhook: 接口返回 HTTP %s" % status,
                                hint=str(body)[:300])

        if kind in BODY_CHECKED:
            problem = self._body_error(kind, body)
            if problem:
                # HTTP 200 but the vendor refused it. This is the failure
                # mode that makes HTTP-only checks dangerous.
                raise ProviderError(
                    "webhook: %s 拒绝了消息：%s"
                    % (KIND_LABELS.get(kind, kind), problem),
                    hint="请检查 webhook 地址/机器人是否仍有效，"
                         "以及消息类型（kind）是否选对。")

        if kind == KIND_TELEGRAM and isinstance(body, dict) and not body.get("ok"):
            # Telegram also answers 200 for some errors, with ok=false.
            raise ProviderError("webhook: Telegram 拒绝发送：%s"
                                % str(body.get("description") or body)[:200])

        return "webhook-ok-%s" % kind

    # -- health -----------------------------------------------------------
    def health(self):
        """Validate the target without posting a message.

        A POST is the only way to fully prove a chat webhook, and doing that
        from ``vigil doctor`` would spam the room on every run. We therefore
        check everything that can be checked locally, plus the one safe live
        call Telegram offers (``getMe``, which identifies the bot and sends
        nothing), and say plainly which part was not verified.
        """
        problems = self.validate()
        if problems:
            return False, "; ".join(problems)
        kind = self.kind_name()

        if kind == KIND_TELEGRAM:
            token = self.p("bot_token")
            try:
                _s, _h, body = self._http_json(
                    "%s/bot%s/getMe" % (TELEGRAM_API, token), None,
                    method="GET", timeout=15.0)
            except AuthError as e:
                return False, "Telegram 拒绝了该 bot_token：%s" % e.render()
            except ProviderError as e:
                return False, "无法访问 Telegram：%s" % e.render()
            if isinstance(body, dict) and body.get("ok"):
                uname = (body.get("result") or {}).get("username", "")
                return True, ("Telegram 机器人 %s 可用；"
                              "chat_id 需实际发送时验证" % uname)
            return False, "Telegram getMe 返回异常"

        url = self.target_url()
        if not url.lower().startswith("https://"):
            # Everything in KINDS is an HTTPS API; plain http would leak the
            # alert body and the webhook secret to the network.
            return False, "webhook 地址必须是 https://（当前地址不安全）"
        return True, ("参数已填写（%s）；为避免打扰群聊，"
                      "未实际发送测试消息" % KIND_LABELS.get(kind, kind))
