"""The mail-driven control channel, plus backlog replay.

Two jobs, both run from the same timer:

1. **Replay parked alerts.** When every delivery channel is down, alerts go
   to a digest file rather than being dropped. This replays them once a
   channel recovers, so a provider outage delays an alert instead of losing
   it.
2. **Answer commands sent by email.** The operator replies to an alert;
   we poll the mailbox over IMAP and act on it. This exists because inbound
   SMTP is unreliable (many hosts block port 25 both ways) while IMAP over
   993 almost always works.

Security notes, because this is a remote-control surface:

* Only addresses in the configured recipient list (plus the authenticated
  account) are honoured. Everything else is logged and ignored.
* The rate limit is evaluated **before** the command runs. (The previous
  implementation checked it afterwards, so it told the operator "not
  executed" while the command had in fact already run -- a lie with real
  consequences.)
* Replies go to the sender only. Broadcasting results would trip a relay's
  rate limits and leak one admin's commands to the other.
* Arbitrary shell execution is opt-in and off by default. When enabled it
  still passes a destructive-command blacklist, a timeout, and an output cap.
"""
from __future__ import annotations

import email
import email.header
import email.utils
import html as _html
import imaplib
import json
import re
import subprocess
import time
from datetime import datetime

from ..core import paths, shell
from ..core.config import load as load_config
from ..core.logging import get as get_logger
from ..core.state import locked, read_json, write_json
from . import queue as q
from . import send_digest, send_text
from .message import KIND_REPLY, SEV_INFO, Alert
from .render import render_reply

STATE = paths.STATE_STATE / "commandd.json"
LOCK = paths.RUN / "vigil-maild.lock"

#: Destructive patterns. Not a sandbox -- a guard rail against a mistyped or
#: maliciously injected one-liner. Matched case-insensitively.
DANGEROUS = [
    r"rm\s+-[rf]{1,2}\s+/(\s|$)", r"rm\s+-[rf]{1,2}\s+/\*", r"mkfs",
    r"dd\s+.*of=/dev/", r":\(\)\s*\{.*\};\s*:", r"shutdown|reboot|halt|poweroff",
    r">\s*/dev/[sh]d", r"chmod\s+-R\s+777\s+/", r"iptables\s+-F",
    r"ufw\s+disable", r"systemctl\s+(stop|disable|mask)\s+(ssh|sshd|networkd|systemd-networkd)",
    r"kill\s+-9\s+-1", r">\s*/etc/(passwd|shadow|sudoers)", r"mv\s+/\*",
    r"userdel\s+-r\s+root", r"passwd\s+root",
]

HELP = """可用命令（回复本邮件即可执行，结果只发回给你）：

  帮助                     显示本说明
  状态                     服务器概况与告警通道状态
  解禁 <IP>                解除对某个 IP 的封禁
  封禁 <IP> [秒数]         手动封禁
  白名单                   查看白名单
  白名单添加 <IP> confirm  把 IP 加入白名单（需 confirm 确认）
  扫描                     立即做一次安全巡检
  封禁列表                 当前所有封禁
  邮件状态                 告警通道与额度
  日志 [行数]              查看程序日志（默认 40 行）
  服务                     关键服务状态
  磁盘                     磁盘与内存使用
  网络                     当前对外连接
  命令 <多行 shell>        执行 shell（需在配置中开启，且空行结束）

提示：邮件客户端会自动换行，用 `/n` 表示换行，例如
  命令 systemctl status nginx /n df -h
"""


# --------------------------------------------------------------------------
# IMAP
# --------------------------------------------------------------------------


def _imap_settings(cfg) -> dict:
    """Resolve IMAP connection details.

    Prefers an explicit configuration; otherwise infers from the SMTP
    channel, because the mailbox that sends the alerts is almost always the
    one that receives the replies.
    """
    host = cfg.get("mail.imap.host", "")
    port = int(cfg.get("mail.imap.port", 993) or 993)
    user = cfg.get("mail.imap.username", "")
    password = cfg.get("mail.imap.password", "")
    if host and user and password:
        return {"host": host, "port": port, "user": user, "password": password}

    for entry in cfg.providers():
        if entry.get("provider") != "smtp":
            continue
        params = cfg.provider_params("smtp")
        smtp_host = str(params.get("host", ""))
        user = str(params.get("username", ""))
        password = str(params.get("password", ""))
        if smtp_host and user and password:
            host = (smtp_host.replace("smtp.", "imap.", 1)
                    if smtp_host.startswith("smtp.") else smtp_host)
            return {"host": host, "port": port, "user": user,
                    "password": password}
    return {}


def _decode_header(raw) -> str:
    if not raw:
        return ""
    try:
        parts = email.header.decode_header(raw)
    except Exception:                                   # noqa: BLE001
        return str(raw)
    out = []
    for text, charset in parts:
        if isinstance(text, bytes):
            for enc in (charset, "utf-8", "gb18030", "latin-1"):
                if not enc:
                    continue
                try:
                    out.append(text.decode(enc))
                    break
                except (LookupError, UnicodeDecodeError):
                    continue
            else:
                out.append(text.decode("utf-8", "replace"))
        else:
            out.append(text)
    return "".join(out)


def _body_text(msg) -> str:
    """Extract a readable body, preferring text/plain."""
    plain, rich = None, None
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            if "attachment" in disp:
                continue
            if ctype == "text/plain" and plain is None:
                plain = _payload(part)
            elif ctype == "text/html" and rich is None:
                rich = _payload(part)
    else:
        if msg.get_content_type() == "text/html":
            rich = _payload(msg)
        else:
            plain = _payload(msg)
    if plain:
        return plain
    if rich:
        text = re.sub(r"(?is)<(script|style).*?</\1>", "", rich)
        text = re.sub(r"(?i)<br\s*/?>|</p>|</div>", "\n", text)
        text = re.sub(r"<[^>]+>", "", text)
        return _html.unescape(text)
    return ""


def _payload(part) -> str:
    try:
        data = part.get_payload(decode=True)
    except Exception:                                   # noqa: BLE001
        return ""
    if data is None:
        return ""
    for enc in (part.get_content_charset(), "utf-8", "gb18030", "latin-1"):
        if not enc:
            continue
        try:
            return data.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("utf-8", "replace")


def _strip_quote(text: str) -> str:
    lines = []
    for line in str(text or "").splitlines():
        if line.lstrip().startswith(">"):
            continue
        if re.search(r"(在.*写道|On .* wrote|-{2,}\s*原始邮件|Original Message|-{5,})",
                     line):
            break
        lines.append(line)
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Loop prevention
#
# This channel reads a mailbox and writes to it. That combination is a closed
# loop waiting to happen, and on 2026-09-27 it happened: the fnchess game
# mailed a registration code from the monitored account to itself, the
# listener answered "没有识别这条命令", and the answer landed back in the
# inbox as the next command. Twenty minutes and 26 messages later
# (#000422..#000447) the operator had a mailbox full of junk and no idea why.
#
# The old rate limiter could not stop it, and made it worse: it refused the
# command but still *sent a mail* saying so -- into the same mailbox. A cap
# that is enforced by sending more mail is not a cap.
#
# Three independent guards:
#
#   1. Marker headers. Outgoing mail carries X-Vigil-Machine and
#      Auto-Submitted; anything wearing them is ours and is dropped before
#      it is ever parsed as a command.
#   2. A content signature, because the API transports (Resend, Brevo,
#      Mailgun, SendGrid) post JSON and never see an SMTP header block. A
#      marker alone would leave the loop open on exactly the channel this
#      host prefers.
#   3. A hard budget on *replies*. Guards 1 and 2 must both fail before it
#      is reached, and when it trips the channel goes quiet rather than
#      talking to itself.
# --------------------------------------------------------------------------

#: Subject of our own automatic reply, e.g. `[#000444] 执行结果`.
_OWN_SUBJECT = re.compile(r"^\s*\[#\d{6}\]\s*(?:执行结果|Command result)\s*$")

#: The text every outgoing message is prefixed with (see mail/__init__.py).
#: The sequence number is optional because the prefix is applied before the
#: number is known in some paths.
_OWN_BODY = re.compile(r"^\s*邮件编号\s*[:：]\s*#?\d{0,6}\s*$")

#: RFC 3834. A vacation responder, a ticketing system or another monitoring
#: agent sets one of these; answering it is how two robots argue forever.
_AUTO_SUBMITTED = re.compile(
    r"^(?:auto-generated|auto-replied|auto-notified)$", re.I)
_BULK_PRECEDENCE = {"bulk", "auto_reply", "junk", "list"}


def _own_mail_reason(msg, subject: str = "", body: str = "") -> str:
    """Why this message is one we sent, or "" if it is not.

    Returns a short reason rather than a bool so the log records *which*
    tell fired. A silent drop is impossible to debug six months later.
    """
    for header in ("X-Vigil-Machine", "X-Vigil-Alert"):
        if (msg.get(header) or "").strip():
            return "自带 %s 标记头" % header
    auto = (msg.get("Auto-Submitted") or "").strip()
    if _AUTO_SUBMITTED.match(auto):
        return "Auto-Submitted: %s" % auto
    prec = (msg.get("Precedence") or "").strip().lower()
    if prec in _BULK_PRECEDENCE:
        return "Precedence: %s" % prec
    if _OWN_SUBJECT.match(subject or ""):
        return "主题是本程序的回执格式"
    for line in (body or "").splitlines():
        if line.strip():
            if _OWN_BODY.match(line):
                return "正文首行是本程序的编号前缀"
            break
    return ""


class ReplyBudget:
    """Hard cap on automatic replies per hour.

    Separate from the command cap on purpose. The command cap refuses the
    *action*; this refuses the *mail*. Without it, any refusal that is
    itself announced by mail keeps the loop alive at full speed.
    """

    def __init__(self, cfg, state, log):
        self.limit = int(cfg.get("commands.max_replies_per_hour", 12) or 12)
        self.log = log
        self.state = state
        now = time.time()
        self.times = [t for t in (state.get("reply_times") or [])
                      if now - t < 3600]
        self.tripped = False

    def allow(self) -> bool:
        if len(self.times) >= self.limit:
            if not self.tripped:
                self.tripped = True
                self.log.warn(
                    "一小时内已自动回复 %d 封，达到上限 %d，暂停回复以避免自回环；"
                    "指令仍会执行并记入审计日志。如确需提高："
                    "vigil config set commands.max_replies_per_hour <N>"
                    % (len(self.times), self.limit))
            return False
        return True

    def note(self) -> None:
        self.times.append(time.time())

    def save(self) -> None:
        self.state["reply_times"] = self.times[-120:]


# --------------------------------------------------------------------------
# Command dispatch
# --------------------------------------------------------------------------


def _allowed_senders(cfg) -> set:
    allowed = {a.lower() for a in cfg.recipients("alert")}
    allowed |= {a.lower() for a in cfg.recipients("login")}
    imap = _imap_settings(cfg)
    if imap.get("user"):
        allowed.add(str(imap["user"]).lower())
    # Any configured From address is trusted: it is the account that already
    # controls where alerts are sent.
    frm = cfg.get("mail.from_address", "")
    if frm:
        allowed.add(str(frm).lower())
    return allowed


def _dangerous(cmd: str) -> str:
    for pat in DANGEROUS:
        if re.search(pat, cmd, re.I):
            return pat
    return ""


def _run_shell(cmd: str, timeout: int = 30, limit: int = 3500) -> str:
    bad = _dangerous(cmd)
    if bad:
        return "⛔ 已拦截：命令匹配到危险模式 `%s`。" % bad
    try:
        p = subprocess.run(["/bin/bash", "-lc", cmd], stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout)
        out = p.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return "⏱ 命令超时（%d 秒）" % timeout
    except Exception as e:                              # noqa: BLE001
        return "命令执行失败: %s" % e
    if len(out) > limit:
        out = out[:limit] + "\n…（输出过长已截断）"
    return out or "（无输出）"


def _svc_status(targets=None) -> str:
    ok, listing, _ = shell.run(
        ["systemctl", "list-unit-files", "--type=service", "--no-legend",
         "--no-pager"], timeout=20)
    if not ok:
        return "无法查询服务状态"
    lines = []
    for line in listing.splitlines():
        name = line.split()[0] if line.split() else ""
        if not name.endswith(".service"):
            continue
        stem = name[:-8]
        if targets and stem not in targets:
            continue
        state = shell.out(["systemctl", "is-active", name])
        if state == "active" or targets:
            lines.append("  %-24s %s" % (stem, state))
    return "\n".join(lines) or "（没有匹配的服务）"


COMMANDS = [
    (r"^(帮助|help|\?|菜单)\s*$", "help"),
    (r"^(状态|status|概况)\s*$", "status"),
    (r"^(解禁|解封|unban)\s+(\S+)\s*$", "unban"),
    (r"^(封禁|ban)\s+(\S+)(?:\s+(\d+))?\s*$", "ban"),
    (r"^(白名单添加|whitelist\s+add)\s+(\S+)\s+(confirm|确认)\s*$", "wl_add"),
    (r"^(白名单|whitelist)\s*$", "wl_list"),
    (r"^(扫描|scan|巡检)\s*$", "scan"),
    (r"^(封禁列表|bans?|banlist)\s*$", "banlist"),
    (r"^(邮件状态|mail)\s*$", "mail"),
    (r"^(日志|log)\s*(\d+)?\s*$", "log"),
    (r"^(服务|service|svc)\s*$", "service"),
    (r"^(磁盘|disk|df)\s*$", "disk"),
    (r"^(网络|net|连接|conn)\s*$", "net"),
    (r"^(重启服务|restart)\s+(\S+)\s*$", "restart"),
    (r"^(命令|command|cmd|运行|执行)\b[\s]*(.*)$", "exec"),
]


def dispatch(cfg, line: str, log) -> str:
    """Execute one command line and return the reply body."""
    for pattern, action in COMMANDS:
        m = re.match(pattern, line, re.I | re.S)
        if not m:
            continue
        groups = m.groups()
        try:
            return _ACTIONS[action](cfg, groups, log)
        except Exception as e:                          # noqa: BLE001
            return "执行 %s 时出错: %s" % (action, e)
    return ("没有识别这条命令。\n\n" + HELP)


def _act_help(cfg, g, log):
    return HELP


def _act_status(cfg, g, log):
    from . import stats as mail_stats
    st = mail_stats(cfg)
    lines = [
        "主机: %s" % (cfg.get("hostname", "") or "?"),
        "时间: %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "",
        "告警渠道: %s" % (", ".join(st["providers"]) or "未配置"),
        "收件人: %s" % (", ".join(st["recipients"]) or "未配置"),
        "今日额度: %d / %s" % (st["quota_used"], st["quota_total"] or "不限"),
        "积压待补发: %d" % st["overflow_files"],
        "",
        "负载: %s" % shell.out(["cat", "/proc/loadavg"]),
        "内存: %s" % _mem_line(),
        "磁盘: %s" % _disk_line(),
        "运行时长: %s" % _uptime_line(),
    ]
    try:
        from ..guards import threat
        snap = threat.status_snapshot(cfg)
        lines.append("当前封禁: %d 个" % snap.get("banned_count", 0))
    except Exception:                                   # noqa: BLE001
        pass
    return "\n".join(lines)


def _mem_line() -> str:
    try:
        info = {}
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                k, _, v = line.partition(":")
                info[k] = int(v.split()[0])
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", 0)
        if total:
            return "%.0f%% 可用（%.0f/%.0f MB）" % (
                avail * 100.0 / total, avail / 1024, total / 1024)
    except (OSError, ValueError, IndexError):
        pass
    return "未知"


def _disk_line() -> str:
    return shell.out(["df", "-h", "/"]).splitlines()[-1] if shell.have("df") else "未知"


def _uptime_line() -> str:
    from ..guards.checks.util import uptime_seconds, human_seconds
    return human_seconds(uptime_seconds())


def _act_unban(cfg, g, log):
    ip = g[1]
    from ..guards import threat
    ok, detail = threat.unban(cfg, ip)
    return ("已解禁 %s" % ip) if ok else ("解禁失败：%s" % detail)


def _act_ban(cfg, g, log):
    ip, secs = g[1], g[2]
    from ..guards import threat
    ok, detail = threat.manual_ban(cfg, ip, int(secs or 0), "管理员邮件指令封禁")
    return ("已封禁 %s" % ip) if ok else ("封禁失败：%s" % detail)


def _act_wl_add(cfg, g, log):
    ip = g[1]
    from ..guards import threat
    if not threat.is_valid_address(ip):
        return "不是合法的 IP 或网段：%s" % ip
    cur = set(cfg.get("threat.whitelist", []) or [])
    if ip in cur:
        return "%s 已在白名单中" % ip
    cur.add(ip)
    cfg.set("threat.whitelist", sorted(cur))
    cfg.save()
    return "已把 %s 加入白名单" % ip


def _act_wl_list(cfg, g, log):
    wl = cfg.get("threat.whitelist", []) or []
    return "\n".join("  %s" % x for x in wl) or "（白名单为空）"


def _act_scan(cfg, g, log):
    from ..guards import health
    result = health.run_once(cfg, log, notify=False)
    lines = ["巡检完成：%d 项检查，%d 项异常" % (result["total"],
                                                len(result["problems"]))]
    for p in result["problems"][:15]:
        lines.append("  [%s] %s" % (p["status"], p["label"]))
        for detail_line in (p["detail"] or "").split("\n")[:4]:
            lines.append("      " + detail_line)
    if not result["problems"]:
        lines.append("  全部正常。")
    return "\n".join(lines)


def _act_banlist(cfg, g, log):
    from ..guards import threat
    bans = threat.list_bans(cfg)
    if not bans:
        return "当前没有被封禁的 IP"
    from ..guards.checks.util import human_seconds
    return "\n".join("  %-18s %-8s %s" % (b.get("ip", ""),
                                          human_seconds(b.get("remaining", 0)),
                                          b.get("reason", "")[:40])
                     for b in bans)


def _act_mail(cfg, g, log):
    from . import stats as mail_stats
    st = mail_stats(cfg)
    return json.dumps(st, ensure_ascii=False, indent=2)


def _act_log(cfg, g, log):
    n = int(g[1] or 40)
    out = []
    for name, path in (("threat", paths.LOG_THREAT), ("health", paths.LOG_HEALTH),
                       ("mail", paths.LOG_MAIL)):
        if not path.exists():
            continue
        out.append("── %s ──" % name)
        from ..core.logging import tail
        out.extend(tail(path, max(5, n // 3)))
    return "\n".join(out) or "暂无日志"


def _act_service(cfg, g, log):
    return _svc_status()


def _act_restart(cfg, g, log):
    name = g[1]
    allowed = set(cfg.get("commands.restartable", []) or [])
    if not allowed:
        allowed = {"nginx", "mysqld", "mariadb", "php-fpm", "postfix",
                   "fail2ban", "redis", "redis-server", "vigil-threatd"}
    if name not in allowed:
        return ("不在允许重启的列表内：%s\n允许的: %s"
                % (name, ", ".join(sorted(allowed))))
    for suffix in (".service", ""):
        unit = name + suffix
        ok, _o, err = shell.run(["systemctl", "restart", unit], timeout=90)
        if ok:
            return "已重启 %s" % unit
    return "重启失败：%s" % name


def _act_disk(cfg, g, log):
    return "\n".join([
        shell.out(["df", "-h"]),
        "",
        shell.out(["free", "-m"]),
    ])


def _act_net(cfg, g, log):
    return shell.out(["ss", "-tunp"]) or "无法获取网络连接"


def _act_exec(cfg, g, log):
    if not cfg.get("commands.allow_shell", False):
        return ("远程 shell 执行当前是关闭的。\n"
                "如需开启：vigil config set commands.allow_shell true\n"
                "（开启后请务必保留危险命令拦截与审计日志）")
    body = g[1] or ""
    body = body.replace("\r\n", "\n").replace("\r", "\n")
    # `/n` is the newline escape: a mail client folds long lines, and the
    # token only expands before something that looks like a command, so a
    # path such as `/nginx` is not mangled.
    body = re.sub(r"/n(?=\s*(?:sudo\s+)?[a-zA-Z0-9_./-])", "\n", body)
    if body.count("\n") > 10:
        return "命令过长（最多 10 行）"
    lines = [l for l in body.splitlines() if l.strip()]
    if not lines:
        return "没有收到命令"
    log.warn("执行远程命令: %s" % " ; ".join(lines)[:300])
    _audit(cfg, "exec", " ; ".join(lines))
    return _run_shell("\n".join(lines))


_ACTIONS = {
    "help": _act_help, "status": _act_status, "unban": _act_unban,
    "ban": _act_ban, "wl_add": _act_wl_add, "wl_list": _act_wl_list,
    "scan": _act_scan, "banlist": _act_banlist, "mail": _act_mail,
    "log": _act_log, "service": _act_service, "restart": _act_restart,
    "disk": _act_disk, "net": _act_net, "exec": _act_exec,
}


def _audit(cfg, action: str, detail: str, sender: str = "", result: str = "") -> None:
    rec = {"ts": datetime.now().isoformat(timespec="seconds"),
           "action": action, "sender": sender,
           "detail": str(detail)[:500], "result": str(result)[:1000]}
    try:
        paths.LOG_COMMANDS.parent.mkdir(parents=True, exist_ok=True)
        with open(paths.LOG_COMMANDS, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


# --------------------------------------------------------------------------
# Poll loop
# --------------------------------------------------------------------------


def poll_commands(cfg=None, log=None) -> dict:
    cfg = cfg or load_config()
    log = log or get_logger("commands")
    if not cfg.get("commands.enabled", True):
        return {"skipped": "命令通道已关闭"}
    imap = _imap_settings(cfg)
    if not imap:
        return {"skipped": "未配置 IMAP，无法接收回复指令"}

    state = read_json(STATE, {}) or {}
    seen = set(state.get("seen_uids", []) or [])
    times = [t for t in (state.get("cmd_times", []) or [])
             if time.time() - t < 3600]
    limit = int(cfg.get("commands.max_per_hour", 30) or 30)
    allowance = limit - len(times)

    handled = 0
    conn = None
    try:
        conn = imaplib.IMAP4_SSL(imap["host"], imap["port"], timeout=30)
        conn.login(imap["user"], imap["password"])
        conn.select("INBOX")
        typ, data = conn.uid("search", None, "ALL")
        if typ != "OK":
            return {"skipped": "无法读取邮箱"}
        uids = [u.decode() for u in (data[0] or b"").split()]

        if not seen:
            # First run: remember what is already there instead of executing
            # whatever happens to be sitting in the inbox.
            state["seen_uids"] = uids[-200:]
            state["last_run"] = time.time()
            write_json(STATE, state, mode=0o640)
            log.info("首次运行：已记录 %d 封存量邮件为基线，不执行历史指令"
                     % len(state["seen_uids"]))
            return {"first_run": True}

        todo = [u for u in uids if u not in seen]
        if not todo:
            return {"handled": 0}

        allowed = _allowed_senders(cfg)
        budget = ReplyBudget(cfg, state, log)
        for uid in todo:
            typ, msgdata = conn.uid("fetch", uid, "(RFC822)")
            seen.add(uid)
            if typ != "OK" or not msgdata or not msgdata[0]:
                continue
            try:
                msg = email.message_from_bytes(msgdata[0][1])
            except Exception:                           # noqa: BLE001
                continue
            sender = email.utils.parseaddr(msg.get("From", ""))[1].lower()
            subject = _decode_header(msg.get("Subject", ""))

            if sender not in allowed:
                log.warn("忽略来自非白名单地址的邮件: %s" % (sender or "?"))
                _audit(cfg, "rejected", subject, sender)
                continue

            body = _strip_quote(_body_text(msg))

            # Drop our own output before anything else looks at it. This is
            # the guard that keeps the channel from eating itself.
            reason = _own_mail_reason(msg, subject, body)
            if reason:
                log.info("忽略本程序自己发出的邮件（%s），不做解析以免自回环"
                         % reason)
                continue

            line = ""
            for cand in body.splitlines():
                if cand.strip():
                    line = cand.strip().rstrip("。.,，;；")
                    break
            if not line:
                continue

            # Rate limit BEFORE running anything.
            if allowance <= 0:
                log.warn("已达到每小时命令上限（%d 条），忽略：%s" % (limit, line[:80]))
                reply = ("已达每小时命令上限（%d 条），本条**未执行**。"
                         "请稍后再试。" % limit)
                _audit(cfg, "ratelimited", line, sender, reply)
                _reply(cfg, sender, subject, reply, log, budget=budget)
                continue

            log.info("执行邮件指令 from=%s: %s" % (sender, line[:120]))
            result = dispatch(cfg, line, log)
            allowance -= 1
            times.append(time.time())
            handled += 1
            _audit(cfg, "executed", line, sender, result)
            _reply(cfg, sender, subject, result, log, budget=budget)

        state["seen_uids"] = list(seen)[-500:]
        state["cmd_times"] = times[-60:]
        budget.save()
        state["last_run"] = time.time()
        write_json(STATE, state, mode=0o640)
    except imaplib.IMAP4.error as e:
        log.warn("IMAP 登录或操作失败: %s" % e)
        return {"error": str(e)}
    except Exception as e:                              # noqa: BLE001
        log.warn("轮询邮箱失败: %s: %s" % (type(e).__name__, e))
        return {"error": str(e)}
    finally:
        if conn is not None:
            try:
                conn.logout()
            except Exception:                           # noqa: BLE001
                pass
    return {"handled": handled}


def _reply(cfg, sender: str, subject: str, body: str, log, budget=None) -> None:
    """Reply to the requester only.

    Not to everyone: broadcasting would leak one admin's commands to the
    others and would very quickly trip a relay's per-hour limits.

    `budget` is the hourly reply cap. It is optional so a direct call (a
    test, or `send_text` from another command) still works, but the poll
    loop always passes one -- see the loop-prevention notes above.
    """
    from . import send_alert
    if budget is not None:
        if not budget.allow():
            return
        budget.note()
    alert = Alert(title="执行结果", severity=SEV_INFO, kind=KIND_REPLY,
                  summary=(subject or "")[:120])
    alert.add_section("输出", [body])
    rep = send_alert(alert, cfg, log, recipients=[sender], allow_dedupe=False)
    log.info("已回复 %s：%s" % (sender, rep.summary()))


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def run_once(cfg=None, log=None) -> dict:
    cfg = cfg or load_config()
    log = log or get_logger("commands")
    out = {}
    # Replay parked alerts first: they represent something that already
    # happened and could not be delivered.
    try:
        rep = send_digest(cfg, log, max_files=int(
            cfg.get("mail.overflow_per_run", 1) or 1))
        if rep.summary():
            out["digest"] = rep.summary()
    except Exception as e:                              # noqa: BLE001
        log.warn("补发积压告警失败: %s" % e)
    out["commands"] = poll_commands(cfg, log)
    return out


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="vigil-maild",
                                description="Replay parked alerts and poll "
                                            "the mailbox for reply commands.")
    p.add_argument("--commands-only", action="store_true")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    log = get_logger("mail")
    if args.commands_only:
        result = poll_commands(log=log)
    else:
        result = run_once(log=log)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
