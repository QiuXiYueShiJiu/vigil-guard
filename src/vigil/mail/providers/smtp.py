"""Generic SMTP provider with per-vendor presets.

This is the channel most people will actually use, so the interesting work
is not the SMTP call (``smtplib`` does that) but the *presets*: host, port,
TLS mode, which credential to ask for, and where to get it.

The subtle part is **From-address alignment**, which cost real debugging
time on the host this project grew out of. Free consumer mailboxes (QQ,
163, Gmail, Outlook) relay your mail through their own infrastructure and
sign it with *their* DKIM key, not yours. If you put your own domain in the
From header, the receiving side compares the From domain against SPF and
DKIM and finds neither -- so the message lands in spam while the sending
server reports "250 OK queued". The symptom is "the DSN says delivered but
the inbox is empty".

Therefore each preset declares ``signs_dkim``. When it is False we warn,
and by default we pin the From header to the authenticated account. When it
is True (transactional relays: SendGrid, Mailgun, SES, Postmark, ...) a
custom From on a verified domain is correct and expected.
"""
from __future__ import annotations

import smtplib
import socket
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from ...core.errors import AuthError, ProviderError
from ..message import Message
from .base import (CHOICE, EMAIL, NUMBER, PASSWORD, TEXT, Field, Provider,
                   register)

SSL_MODE, STARTTLS, PLAIN = "ssl", "starttls", "plain"

# --------------------------------------------------------------------------
# Presets
# --------------------------------------------------------------------------
# credential_kind is shown to the operator so they know whether to paste an
# account password, an app password, or an API key.
PRESETS = {
    "qq": {
        "label": "QQ 邮箱", "host": "smtp.qq.com", "port": 465, "tls": SSL_MODE,
        "signs_dkim": False, "user_is_email": True,
        "credential": "授权码",
        "hint": "QQ邮箱 → 设置 → 账户 → 开启「POP3/SMTP服务」→ 生成授权码（16 位）。"
                "注意：不是 QQ 密码，是那个授权码。用户名填完整邮箱地址。",
    },
    "qq_exmail": {
        "label": "腾讯企业邮", "host": "smtp.exmail.qq.com", "port": 465,
        "tls": SSL_MODE, "signs_dkim": True, "user_is_email": True,
        "credential": "登录密码或客户端专用密码",
        "hint": "腾讯企业邮 → 设置 → 邮箱绑定 → 客户端专用密码。"
                "若已在管理后台配置 SPF/DKIM，可自定义发件地址。",
    },
    "163": {
        "label": "网易 163 邮箱", "host": "smtp.163.com", "port": 465,
        "tls": SSL_MODE, "signs_dkim": False, "user_is_email": True,
        "credential": "授权码",
        "hint": "163邮箱 → 设置 → POP3/SMTP/IMAP → 开启 SMTP → 新增授权密码。",
    },
    "126": {
        "label": "网易 126 邮箱", "host": "smtp.126.com", "port": 465,
        "tls": SSL_MODE, "signs_dkim": False, "user_is_email": True,
        "credential": "授权码", "hint": "同 163：设置中开启 SMTP 并生成授权密码。",
    },
    "aliyun": {
        "label": "阿里云企业邮箱", "host": "smtp.qiye.aliyun.com", "port": 465,
        "tls": SSL_MODE, "signs_dkim": True, "user_is_email": True,
        "credential": "登录密码",
        "hint": "使用完整企业邮箱地址作为用户名；若开启了安全设置，"
                "需在网页端生成「客户端专用密码」。",
    },
    "aliyun_personal": {
        "label": "阿里云个人邮箱", "host": "smtp.aliyun.com", "port": 465,
        "tls": SSL_MODE, "signs_dkim": False, "user_is_email": True,
        "credential": "登录密码", "hint": "阿里云个人邮箱使用登录密码。",
    },
    "feishu": {
        "label": "飞书企业邮箱", "host": "smtp.feishu.cn", "port": 465,
        "tls": SSL_MODE, "signs_dkim": True, "user_is_email": True,
        "credential": "客户端专用密码",
        "hint": "飞书邮箱 → 设置 → 客户端专用密码。",
    },
    "gmail": {
        "label": "Gmail / Google Workspace", "host": "smtp.gmail.com", "port": 587,
        "tls": STARTTLS, "signs_dkim": False, "user_is_email": True,
        "credential": "应用专用密码（App Password）",
        "hint": "需先在 Google 账户开启两步验证，然后生成「应用专用密码」"
                "（16 位，不含空格）。普通账户密码无法用于 SMTP。",
    },
    "outlook": {
        "label": "Outlook / Hotmail", "host": "smtp-mail.outlook.com", "port": 587,
        "tls": STARTTLS, "signs_dkim": False, "user_is_email": True,
        "credential": "账户密码或应用密码",
        "hint": "若账户开启了两步验证，需生成「应用密码」。"
                "微软个人账户的 SMTP 基本认证可能已被停用。",
    },
    "office365": {
        "label": "Microsoft 365", "host": "smtp.office365.com", "port": 587,
        "tls": STARTTLS, "signs_dkim": True, "user_is_email": True,
        "credential": "账户密码或应用密码",
        "hint": "管理员需为邮箱启用 SMTP AUTH（默认常被关闭）。",
    },
    "zoho": {
        "label": "Zoho Mail", "host": "smtp.zoho.com", "port": 465,
        "tls": SSL_MODE, "signs_dkim": True, "user_is_email": True,
        "credential": "应用专用密码",
        "hint": "Zoho → 安全 → 应用专用密码。自有域名在 Zoho 验证后即可自定义发件地址。",
    },
    "yandex": {
        "label": "Yandex Mail", "host": "smtp.yandex.com", "port": 465,
        "tls": SSL_MODE, "signs_dkim": False, "user_is_email": True,
        "credential": "应用密码",
        "hint": "Yandex ID → 安全 → 应用密码。",
    },
    "gmx": {
        "label": "GMX", "host": "mail.gmx.com", "port": 587,
        "tls": STARTTLS, "signs_dkim": False, "user_is_email": True,
        "credential": "账户密码", "hint": "GMX 需在设置中允许 POP3/IMAP 访问。",
    },
    "sendgrid": {
        "label": "SendGrid（SMTP）", "host": "smtp.sendgrid.net", "port": 587,
        "tls": STARTTLS, "signs_dkim": True, "user_is_email": False,
        "fixed_user": "apikey", "credential": "API Key",
        "hint": "用户名固定填 `apikey`，密码填 SendGrid 的 API Key。"
                "发件地址需属于已在 SendGrid 完成域名认证（Sender Authentication）的域名。",
    },
    "mailgun": {
        "label": "Mailgun（SMTP）", "host": "smtp.mailgun.org", "port": 587,
        "tls": STARTTLS, "signs_dkim": True, "user_is_email": False,
        "credential": "SMTP 密码",
        "hint": "用户名形如 postmaster@mg.example.com（Mailgun 域名设置页可见）。",
    },
    "brevo": {
        "label": "Brevo / Sendinblue（SMTP）", "host": "smtp-relay.brevo.com",
        "port": 587, "tls": STARTTLS, "signs_dkim": True, "user_is_email": True,
        "credential": "SMTP Key",
        "hint": "Brevo → SMTP & API → SMTP 页面获取登录名与 SMTP Key。",
    },
    "mailjet": {
        "label": "Mailjet（SMTP）", "host": "in-v3.mailjet.com", "port": 587,
        "tls": STARTTLS, "signs_dkim": True, "user_is_email": False,
        "credential": "API Secret",
        "hint": "用户名填 API Key，密码填 API Secret（Mailjet 控制台可查）。",
    },
    "postmark": {
        "label": "Postmark（SMTP）", "host": "smtp.postmarkapp.com", "port": 587,
        "tls": STARTTLS, "signs_dkim": True, "user_is_email": False,
        "credential": "Server Token",
        "hint": "用户名与密码都填同一个 Server Token。",
    },
    "resend_smtp": {
        "label": "Resend（SMTP）", "host": "smtp.resend.com", "port": 587,
        "tls": STARTTLS, "signs_dkim": True, "user_is_email": False,
        "fixed_user": "resend", "credential": "API Key",
        "hint": "用户名固定填 `resend`，密码填 Resend API Key。",
    },
    "ses": {
        "label": "Amazon SES（SMTP）",
        "host": "email-smtp.us-east-1.amazonaws.com", "port": 587,
        "tls": STARTTLS, "signs_dkim": True, "user_is_email": False,
        "credential": "SMTP 密码",
        "hint": "SES 控制台 → SMTP settings → Create SMTP credentials。"
                "请把 host 改成你所在区域的端点（如 email-smtp.eu-west-1.amazonaws.com）。",
    },
    "custom": {
        "label": "自建 / 其他 SMTP 服务器", "host": "", "port": 587,
        "tls": STARTTLS, "signs_dkim": None, "user_is_email": True,
        "credential": "密码",
        "hint": "手动填写 SMTP 主机与端口。signs_dkim 未知，"
                "若无法确定请勾选「发件地址与账号一致」。",
    },
}

_CHOICES = tuple(PRESETS.keys())


def preset_choices() -> tuple:
    return _CHOICES


def preset_label(key: str) -> str:
    return PRESETS.get(key, {}).get("label", key)


@register
class Smtp(Provider):
    id = "smtp"
    label = "SMTP 邮箱（内置各家预设）"
    label_en = "SMTP mailbox (built-in presets)"
    kind = "smtp"
    blurb = ("把你的邮箱当作发信中继。适合已有邮箱、不想接入第三方 API 的情况。"
             "注意免费邮箱不支持自定义发件域名。")
    blurb_en = ("Relay through a mailbox you already own. Note that free "
                "mailboxes do not let you use a custom From domain.")

    fields = (
        Field("preset", "邮箱类型", "Mailbox type", kind=CHOICE,
              choices=_CHOICES, default="qq",
              hint="选择后会带出正确的服务器、端口与加密方式。"),
        Field("host", "SMTP 服务器", "SMTP host", example="smtp.example.com"),
        Field("port", "端口", "Port", kind=NUMBER, default="587",
              hint="465 = SSL 直连；587 = STARTTLS；25 常被机房封禁。"),
        Field("security", "加密方式", "Encryption", kind=CHOICE,
              choices=(SSL_MODE, STARTTLS, PLAIN), default=STARTTLS),
        Field("username", "登录用户名", "Username", kind=EMAIL,
              hint="多数邮箱就是完整地址；SendGrid 填 apikey，Resend 填 resend。"),
        Field("password", "密码 / 授权码", "Password / auth code",
              kind=PASSWORD, secret=True,
              hint="通常是「授权码」或「应用专用密码」，不是网页登录密码。"),
        Field("from_address", "发件地址", "From address", kind=EMAIL,
              required=False,
              hint="留空则使用登录用户名。免费邮箱请务必留空或填同一个地址，"
                   "否则邮件会被判为伪造而进垃圾箱。"),
        Field("from_name", "发件人显示名", "Display name", required=False,
              default="Server Monitor"),
    )

    # -- parameter synthesis ---------------------------------------------
    def apply_preset(self, key: str) -> dict:
        """Return the preset's server parameters, keeping user overrides."""
        p = PRESETS.get(key)
        if not p:
            return {}
        params = {
            "host": p.get("host", ""),
            "port": str(p.get("port", 587)),
            "security": p.get("tls", STARTTLS),
        }
        if p.get("fixed_user"):
            params["username"] = p["fixed_user"]
        return params

    def preset(self) -> dict:
        return PRESETS.get(self.p("preset") or "custom", PRESETS["custom"])

    def signs_dkim(self):
        return self.preset().get("signs_dkim")

    # -- validation -------------------------------------------------------
    def validate(self) -> list:
        problems = []
        if not self.p("host"):
            problems.append("smtp: host is required")
        try:
            port = int(self.p("port") or 0)
        except ValueError:
            port = 0
        if not (0 < port < 65536):
            problems.append("smtp: port is not a valid number")
        if not self.p("username"):
            problems.append("smtp: username is required")
        if not self.p("password"):
            problems.append("smtp: password/auth code is required")
        return problems

    def effective_from(self) -> str:
        """The From address we will actually put in the header."""
        return self.p("from_address") or self.p("username")

    def alignment_warning(self) -> str:
        """Warn when a custom From on a non-signing relay will be spam-foldered."""
        frm = self.p("from_address")
        user = self.p("username")
        if not frm or not user or "@" not in frm or "@" not in user:
            return ""
        if frm.lower() == user.lower():
            return ""
        if self.signs_dkim() is True:
            return ""
        if self.signs_dkim() is False:
            return ("发件地址 %s 与登录账号 %s 的域名不一致，而 %s 不会为你的域名做 "
                    "DKIM 签名 —— 收件方会判定为伪造，邮件很可能直接进垃圾箱"
                    "（发信日志却显示已投递）。建议把发件地址留空。"
                    % (frm, user, preset_label(self.p("preset"))))
        return ("无法确定 %s 是否会为你的域名签名；若收不到邮件，"
                "请先把发件地址改为与登录账号一致。"
                % preset_label(self.p("preset")))

    # -- sending ----------------------------------------------------------
    def _connect(self):
        host = self.p("host")
        port = int(self.p("port") or 587)
        mode = self.p("security") or STARTTLS
        ctx = ssl.create_default_context()
        if mode == SSL_MODE:
            server = smtplib.SMTP_SSL(host, port, timeout=25,
                                      context=ctx, local_hostname=None)
        else:
            server = smtplib.SMTP(host, port, timeout=25)
            server.ehlo()
            if mode == STARTTLS:
                server.starttls(context=ctx)
                server.ehlo()
        return server

    def send(self, msg: Message, to: str) -> str:
        frm = self.effective_from()
        if not frm:
            raise ProviderError("smtp: no from address could be determined")
        name = self.p("from_name") or msg.from_name

        mail = EmailMessage()
        mail["Subject"] = msg.subject
        mail["From"] = ("%s <%s>" % (name, frm)) if name else frm
        mail["To"] = to
        reply_to = self.p("reply_to") or msg.reply_to
        if reply_to:
            mail["Reply-To"] = reply_to
        mail["Date"] = formatdate(localtime=True)
        domain = frm.split("@", 1)[1] if "@" in frm else "localhost"
        mail["Message-ID"] = make_msgid(domain=domain)
        mail["X-Vigil-Alert"] = "1"
        # The command channel polls the same mailbox it sends to. Without a
        # marker it reads its own reply back as a command and answers
        # forever; see the loop-prevention notes in mail/commandd.py.
        mail["X-Vigil-Machine"] = "1"
        mail["Auto-Submitted"] = "auto-generated"
        mail.set_content(msg.text, charset="utf-8")
        if msg.html and msg.html.strip():
            mail.add_alternative(msg.html, subtype="html", charset="utf-8")

        try:
            server = self._connect()
        except (socket.timeout, OSError) as e:
            raise ProviderError("smtp: cannot reach %s:%s (%s)"
                                % (self.p("host"), self.p("port"), e))
        try:
            try:
                server.login(self.p("username"), self.p("password"))
            except smtplib.SMTPAuthenticationError as e:
                raise AuthError(
                    "smtp: authentication rejected by %s"
                    % preset_label(self.p("preset")),
                    hint=("check that you pasted the %s rather than the web "
                          "login password; server said: %s"
                          % (self.preset().get("credential", "credential"),
                             str(e)[:200])))
            server.send_message(mail)
            return "smtp-ok"
        finally:
            try:
                server.quit()
            except Exception:
                try:
                    server.close()
                except Exception:
                    pass

    # -- health -----------------------------------------------------------
    def health(self):
        problems = self.validate()
        if problems:
            return False, "; ".join(problems)
        try:
            server = self._connect()
        except (socket.timeout, OSError) as e:
            return False, "cannot connect to %s:%s (%s)" % (
                self.p("host"), self.p("port"), e)
        try:
            try:
                server.login(self.p("username"), self.p("password"))
            except smtplib.SMTPAuthenticationError as e:
                return False, "authentication rejected: %s" % str(e)[:200]
            except smtplib.SMTPException as e:
                return False, "SMTP error during login: %s" % str(e)[:200]
            return True, "connected and authenticated to %s:%s" % (
                self.p("host"), self.p("port"))
        finally:
            try:
                server.quit()
            except Exception:
                try:
                    server.close()
                except Exception:
                    pass
