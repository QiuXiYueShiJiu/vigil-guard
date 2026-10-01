"""Local MTA delivery via a sendmail-compatible binary.

The cheapest channel on a host that already runs Postfix, Exim, msmtp or
OpenSMTPD: hand the message to the local binary and let the MTA deal with
queues, retries and DKIM. No credentials, no third-party account.

Three things make this provider special enough to deserve its own module:

* **The base helper cannot be used.** ``vigil.core.shell.run`` fixes
  ``stdin=DEVNULL`` on purpose -- several system tools misbehave when stdin
  is a pipe (see ``shell.py``) -- and a mail binary needs the RFC822
  message on stdin. So we call :func:`subprocess.run` directly here with
  ``stdin=PIPE`` and keep the rest of ``shell.run``'s guarantees: a hard
  timeout, captured output, and never an inherited stdin.
* **Queueing is not delivery.** A sendmail binary exits 0 as soon as it
  has accepted the message into *its* queue. The MTA may defer, bounce or
  drop it afterwards. That is why the class sets ``async_confirm = True``:
  the router must confirm delivery out of band (for example from the MTA
  log or a bounce mailbox) instead of treating exit 0 as a delivered alert.
  Reporting "sent" here would make the monitoring system lie, which is the
  one bug this project cannot afford.
* **An absent binary is a configuration error, not a delivery error.** We
  surface it with the path we tried and `postfix`/`msmtp` install hints so
  the operator can fix it in one step.

The argument vector is ``[binary] + extra_args.split() + ["-f", from]``.
``-f`` sets the envelope sender, which must match the From header or the
MTA rewrites the header and breaks SPF alignment. ``-t -i`` (the default)
makes the binary read recipients from the headers and ignore a lone dot
line, which is the behaviour every sendmail clone implements.
"""
from __future__ import annotations

import os
import subprocess
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from ...core.errors import AuthError, ProviderError
from ...core import shell
from ..message import Message
from .base import EMAIL, TEXT, Field, Provider, register

#: Where sendmail-compatible binaries live across the common distros. Used
#: only for the error hint -- the provider never guesses a binary on its
#: own, because silently picking the wrong MTA is worse than failing.
COMMON_PATHS = (
    "/usr/sbin/sendmail",
    "/usr/lib/sendmail",
    "/usr/sbin/msmtp",
    "/usr/bin/msmtp",
    "/usr/sbin/exim4",
    "/usr/sbin/exim",
)


@register
class LocalSendmail(Provider):
    id = "sendmail"
    label = "本机 MTA（sendmail 兼容程序）"
    label_en = "Local MTA (sendmail-compatible binary)"
    kind = "local"
    blurb = ("交给本机 Postfix/Exim/msmtp 投递，零成本、无需第三方账号。"
             "注意：二进制返回 0 只代表「已入队」，不代表已投递成功。")
    blurb_en = ("Hand off to the local Postfix/Exim/msmtp. Free and needs no "
                "account, but exit 0 only means queued, not delivered.")
    docs_url = "https://www.postfix.org/sendmail.1.html"

    #: Queue submission is not delivery -- the router must verify out of
    #: band (bounce mailbox, MTA log) before counting the alert as sent.
    async_confirm = True

    fields = (
        Field("binary", "sendmail 程序路径", "sendmail binary", kind=TEXT,
              default="/usr/sbin/sendmail",
              example="/usr/sbin/sendmail",
              hint="常见路径：Postfix 为 /usr/sbin/sendmail，"
                   "msmtp 为 /usr/bin/msmtp，Exim 为 /usr/sbin/exim4。"
                   "可用 `command -v sendmail` 查看。",
              hint_en="Common paths: /usr/sbin/sendmail (Postfix), "
                      "/usr/bin/msmtp, /usr/sbin/exim4."),
        Field("from_address", "发件地址", "From address", kind=EMAIL,
              example="root@example.com",
              hint="作为信封发件人（-f）与邮件头 From 使用。"
                   "该地址的域名最好已配置 SPF，否则容易进垃圾箱。",
              hint_en="Used as both envelope sender (-f) and the From "
                      "header; its domain should have SPF configured."),
        Field("from_name", "发件人显示名", "Display name", required=False,
              default="Server Monitor"),
        Field("extra_args", "附加参数", "Extra arguments", required=False,
              default="-t -i",
              hint="默认 `-t -i`：从邮件头读取收件人、忽略单独的英文句点行。"
                   "除非你清楚 MTA 的行为，否则不要修改。",
              hint_en="Defaults to `-t -i` (read recipients from headers, "
                      "ignore a lone dot). Usually leave unchanged."),
        Field("reply_to", "回复地址", "Reply-To", kind=EMAIL, required=False,
              hint="可选，建议填写管理员邮箱。",
              hint_en="Optional admin mailbox for replies."),
    )

    # -- local checks -----------------------------------------------------
    def binary_path(self) -> str:
        return self.p("binary") or "/usr/sbin/sendmail"

    def binary_is_executable(self) -> bool:
        path = self.binary_path()
        return os.path.isfile(path) and os.access(path, os.X_OK)

    #: `Field.default` is documentation for the wizard: `Provider.p()` returns
    #: "" for a key that was never stored, so argv() must apply the fallback
    #: itself. Losing "-t" would make the MTA ignore the To header and accept
    #: nothing, i.e. a silent no-op.
    DEFAULT_EXTRA_ARGS = "-t -i"

    def argv(self) -> list:
        """The full argument vector, minus the message on stdin."""
        binary = self.binary_path()
        extra = (self.p("extra_args") or self.DEFAULT_EXTRA_ARGS).strip()
        args = extra.split() if extra else []
        # Tolerate a paste that included the binary itself; a duplicated
        # binary name would be parsed as a recipient by some MTAs.
        if args and (args[0].endswith("sendmail") or args[0].endswith("msmtp")
                     or args[0].endswith("exim") or args[0].endswith("exim4")):
            args = args[1:]
        # Envelope sender must match the From header or the MTA rewrites it.
        return [binary] + args + ["-f", self.p("from_address")]

    # -- sending ----------------------------------------------------------
    def send(self, msg: Message, to: str) -> str:
        frm = self.p("from_address") or msg.from_address
        if not frm:
            raise ProviderError("sendmail: 未配置发件地址（from_address）",
                                hint="本机投递必须指定发件地址，否则 MTA 会使用 "
                                     "默认值并可能被收件方判为伪造。")
        to = (to or "").strip()
        if not to:
            raise ProviderError("sendmail: 收件人地址为空")

        binary = self.binary_path()
        if not self.binary_is_executable():
            raise ProviderError("sendmail: 找不到可执行的 %s" % binary,
                                hint=_binary_hint(binary))

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
        # Machine markers. The reply-command channel reads the mailbox it
        # writes to, so without these it consumes its own output as input.
        mail["X-Vigil-Machine"] = "1"
        mail["Auto-Submitted"] = "auto-generated"
        mail.set_content(msg.text or "", charset="utf-8")
        if msg.html and msg.html.strip():
            # multipart/alternative, exactly as the SMTP provider builds it,
            # so both channels produce byte-identical messages.
            mail.add_alternative(msg.html, subtype="html", charset="utf-8")

        try:
            proc = subprocess.run(
                self.argv(),
                # `input=` alone wires a PIPE to the child's stdin and closes
                # it, so the child never inherits our stdin. Passing
                # stdin=PIPE as well is an error in Python 3.12+, and
                # duplicate kwargs for the same target are a TypeError.
                input=mail.as_bytes(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=25,
                env=shell._BASE_ENV,
            )
        except FileNotFoundError:
            raise ProviderError("sendmail: 无法执行 %s" % binary,
                                hint=_binary_hint(binary))
        except PermissionError:
            raise AuthError("sendmail: 没有权限执行 %s" % binary,
                            hint="请检查该文件权限，或改用有权限的 MTA 程序。")
        except subprocess.TimeoutExpired:
            raise ProviderError("sendmail: %s 在 25 秒内没有返回" % binary,
                                hint="MTA 可能正在等待上游服务器；"
                                     "请检查本机邮件队列（mailq）与日志。")
        except OSError as e:
            raise ProviderError("sendmail: 调用 %s 失败：%s" % (binary, e),
                                hint=_binary_hint(binary))

        stderr = proc.stderr.decode("utf-8", "replace").strip()
        if proc.returncode != 0:
            raise ProviderError(
                "sendmail: %s 退出码 %d" % (binary, proc.returncode),
                hint=(stderr[:300] or "请检查 MTA 日志（如 /var/log/mail.log）"))
        # Exit 0 means "accepted into the queue", nothing more. The short id
        # below is what the router logs before scheduling async validation.
        return "local-queued"

    # -- health -----------------------------------------------------------
    def health(self):
        problems = self.validate()
        if problems:
            return False, "; ".join(problems)
        path = self.binary_path()
        if not os.path.exists(path):
            return False, "找不到 %s；%s" % (path, _binary_hint(path))
        if not os.access(path, os.X_OK):
            return False, "%s 存在但没有执行权限" % path
        return True, ("%s 可执行；注意本通道是入队投递，"
                      "需另行确认实际送达（async_confirm=True）" % path)


def _binary_hint(path: str) -> str:
    return ("未找到 %s。请安装并启用本机 MTA（如 `apt install postfix` 或 "
            "`apt install msmtp-mta`），或把 binary 改成实际路径；"
            "常见路径：%s" % (path, "、".join(COMMON_PATHS)))
