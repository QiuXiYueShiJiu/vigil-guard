"""`vigil setup` -- one interactive pass from nothing to a working install.

The install wizard already exists, but it asks about *features*. What an
operator actually has in mind when they run it is a much smaller set of
questions: how do I reach the admin pages, who can log in, what is it called,
and will it be able to email me. This asks those, then does the wiring --
including the parts that are easy to get subtly wrong by hand (the reverse
proxy block, the TLS certificate, the credential hash, the test mail).

Every answer has a default, and every default is the safe one: no public
domain unless asked, password authentication, page names derived from the
machine rather than invented here. Pressing Enter through the whole thing
produces a working install that only listens on loopback.
"""
from __future__ import annotations

import getpass
import sys

from .. import ui
from ..core import shell, units
from ..core.config import load as load_config

#: The admin pages this program can serve. The list lives here so the question
#: ("configure which?") and the wiring stay in step -- and so adding a page is
#: one edit rather than three.
PAGES = (
    ("status", "状态与反馈", "本机实时状态、最近的检查项与诱饵命中，附带反馈入口"),
    ("gate", "登录网关概览", "各登录网关的配置与命中情况（不含面板本身的操作）"),
)


# --------------------------------------------------------------------------
# 界面：对外只有方框、进度和结果。内部细节（路径、单元名、配置键）一律不出现
# —— 使用者要知道的是「配好了没有」，不是「写到了哪个文件」。
# --------------------------------------------------------------------------

TOTAL_STEPS = 6


def _panel(lines, title: str = "", color=None) -> None:
    """一个圆角方框。宽度按终端实际宽度自适应，窄终端也不会折断。"""
    w = max(46, min(ui.width(), 76))
    inner = w - 4
    top = "╭" + "─" * (w - 2) + "╮"
    bot = "╰" + "─" * (w - 2) + "╯"
    ui.out(ui.c(top, color or "cyan"))
    if title:
        t = title[:inner]
        ui.out(ui.c("│ ", color or "cyan") + ui.bold(t)
               + " " * max(0, inner - ui._display_len(t)) + ui.c(" │", color or "cyan"))
        ui.out(ui.c("├" + "─" * (w - 2) + "┤", color or "cyan"))
    for ln in lines:
        text = str(ln)
        pad = inner - ui._display_len(text)
        ui.out(ui.c("│ ", color or "cyan") + text + " " * max(0, pad)
               + ui.c(" │", color or "cyan"))
    ui.out(ui.c(bot, color or "cyan"))


def _step(n: int, title: str) -> None:
    ui.out()
    bar = "●" * n + "○" * (TOTAL_STEPS - n)
    ui.out(ui.c("  %s  " % bar, "cyan")
           + ui.dim("第 %d/%d 步 · " % (n, TOTAL_STEPS)) + ui.bold(title))


def _ok(text: str) -> None:
    ui.out("  " + ui.ok("✓") + " " + text)


def _warn(text: str) -> None:
    ui.out("  " + ui.warn("!") + " " + text)


def _ask(prompt: str, default: str = "") -> str:
    if not sys.stdin.isatty():                     # pragma: no cover - 交互路径
        return default
    shown = " [%s]" % default if default else ""
    got = input("%s%s：" % (prompt, shown)).strip()
    return got or default


def _yesno(prompt: str, default: bool = False) -> bool:
    d = "Y/n" if default else "y/N"
    if not sys.stdin.isatty():                     # pragma: no cover
        return default
    got = input("%s [%s]：" % (prompt, d)).strip().lower()
    if not got:
        return default
    return got in ("y", "yes", "是", "1", "true")


def _ask_password(min_len: int = 10) -> str:
    if not sys.stdin.isatty():                     # pragma: no cover
        ui.failure("设置密码需要交互式终端（不接受从参数或管道传入）")
        return ""
    while True:
        p1 = getpass.getpass("  设置密码（至少 %d 位，不回显）：" % min_len)
        if len(p1) < min_len:
            print("    太短了，至少 %d 位。" % min_len)
            continue
        if p1 != getpass.getpass("  再输一次："):
            print("    两次不一致，重来。")
            continue
        return p1


def cmd_setup(args) -> int:
    cfg = load_config(args.config or None)

    ui.out()
    _panel([
        "检测、封禁、告警、诱饵、自修正 —— 一个守护程序。",
        "",
        "接下来会问你 %d 个问题，然后自动把管理页面配好。" % TOTAL_STEPS,
        "每个问题都有默认值，一路回车即可得到一个可用的安装。",
    ], title="vigil · 快速设置")

    # ── 1/6 页面 ──────────────────────────────────────────────────────────
    _step(1, "要配置哪些管理页面")
    _panel(["%d  %-10s %s" % (i, title, desc)
            for i, (_k, title, desc) in enumerate(PAGES, 1)])
    picked = _ask("  选择（逗号分隔，all=全部）", "all")
    if picked.lower() in ("all", "全部", ""):
        chosen = [k for k, _t, _d in PAGES]
    else:
        chosen = []
        for tok in picked.replace("，", ",").split(","):
            tok = tok.strip()
            if tok.isdigit() and 1 <= int(tok) <= len(PAGES):
                chosen.append(PAGES[int(tok) - 1][0])
    if not chosen:
        ui.out()
        ui.failure("没有选中任何页面")
        return 2
    _ok("将配置 %d 个页面" % len(chosen))

    # ── 2/6 名字 ──────────────────────────────────────────────────────────
    _step(2, "页面叫什么")
    _panel(["这个名字会显示在页面上。留空则用本机主机名（运行时获取）。"])
    display = _ask("  显示名字", "")
    _ok("显示为 %s" % (display or "本机主机名"))

    # ── 3/6 访问方式 ──────────────────────────────────────────────────────
    _step(3, "怎么访问")
    _panel(["只在域名访问时才对外开放；否则只监听本机，最安全。",
            "对外开放需要你已经有域名解析，证书会自动尝试签发。"])
    public = _yesno("  用域名对外访问吗", False)
    domain, out_port = "", 443
    if public:
        domain = _ask("  域名（例如 status.example.com）", "")
        if not domain:
            _warn("没填域名，按「只监听本机」处理")
            public = False
        else:
            out_port = int(_ask("  对外端口", "443") or 443)
    listen_port = int(_ask("  本地监听端口", "9177") or 9177)
    _ok("对外：%s" % ("https://%s/" % domain if public else "仅本机"))

    # ── 4/6 登录方式 ──────────────────────────────────────────────────────
    _step(4, "谁可以登录")
    _panel(["1  只用密码            最省事",
            "2  密码 + 人机验证      更抗暴力破解"])
    auth = _ask("  选择", "1")
    captcha = auth.strip() in ("2", "both", "都有")
    username = _ask("  登录账号", "admin")
    if args.password_stdin:
        password = sys.stdin.readline().strip()
    else:
        password = _ask_password()
    if not password:
        ui.out()
        ui.failure("没有设置密码，页面会拒绝登录")
        return 1
    _ok("账号 %s 已设置（只保存派生值，密码不入库）" % username)

    # ── 5/6 邮件 ──────────────────────────────────────────────────────────
    _step(5, "出了事通知谁")
    _panel(["留空则跳过。填了会在最后发一封测试邮件，确认通道真的通。"])
    email_to = _ask("  告警收件邮箱", "")
    sender = _ask("  发件人地址", email_to) if email_to else ""
    _ok("告警邮箱：%s" % (email_to or "未配置（可稍后 vigil mail setup）"))

    if args.dry_run:
        ui.out()
        _panel(["预演结束，没有写入任何东西。"], title="完成", color="yellow")
        return 0

    # ── 6/6 落地 ──────────────────────────────────────────────────────────
    _step(6, "正在配置")
    from . import web as web_cmd
    from ..web import server as web_server

    cfg.set("web.enabled", True)
    cfg.set("web.listen", "127.0.0.1")
    cfg.set("web.port", listen_port)
    cfg.set("web.domain", domain)
    cfg.set("web.display_name", display)
    cfg.set("web.captcha", bool(captcha))
    if email_to:
        cfg.set("mail.recipients", [email_to])
        cfg.set("mail.from_address", sender or email_to)
    cfg.save()
    web_server.set_password(cfg, username, password)
    _ok("账号与登录方式已写入")

    if public and domain:
        if web_cmd.cmd_install(_NS(domain=domain, config=args.config)) == 0:
            _ok("对外访问已就绪（反代 + 证书）")
        else:
            _warn("对外配置没成功，页面仍只在本机可用")
    else:
        _ok("只监听本机 %s:%d" % ("127.0.0.1", listen_port))

    web_cmd.cmd_unit(_NS(config=args.config))
    _ok("服务已启动并设为开机自启")

    mail_ok = None
    if email_to:
        from ..guards import threat as threat_mod
        try:
            alert = threat_mod.Alert(title="vigil 安装完成：这是一封测试邮件",
                                     severity=threat_mod.SEV_INFO,
                                     kind=threat_mod.KIND_ALERT,
                                     dedupe_key="setup|test")
            sec = alert.add_section("测试邮件")
            sec.add("收到这封信，说明告警通道已经配好了。")
            mail_ok = bool(threat_mod.send_alert(alert, cfg=cfg))
        except Exception as e:                                 # noqa: BLE001
            mail_ok = False
            _warn("测试邮件发送失败：%s" % str(e)[:80])
        if mail_ok:
            _ok("测试邮件已发出，请查收")

    ui.out()
    _panel([
        "页面      %s" % (", ".join(dict((k, t) for k, t, _ in PAGES)[c]
                                    for c in chosen)),
        "地址      %s" % ("https://%s/" % domain if public and domain
                          else "http://127.0.0.1:%d/" % listen_port),
        "登录      %s" % ("%s + 人机验证" % username if captcha else username),
        "告警      %s" % (email_to or "未配置"),
        "邮件通道  %s" % ("已验证" if mail_ok else ("未验证" if email_to else "未配置")),
    ], title="配置完成", color="green")
    ui.out()
    ui.out(ui.dim("  随时改：vigil setup ｜ 只改密码：vigil web passwd ｜ "
                  "看状态：vigil status"))
    return 0


class _NS:
    """Tiny namespace so sub-commands can be called with the same shape the
    parser would hand them."""

    def __init__(self, **kw):
        self.__dict__.update(kw)


def register(sub) -> None:
    p = sub.add_parser(
        "setup", help="交互式快速设置：一次问答配好管理页面",
        description="问几个问题（配哪些页面、是否域名访问、端口、登录方式、"
                    "页面名字、告警邮箱），然后自动完成反代、证书、凭据与测试邮件。"
                    "所有默认值都是保守的：不问就不对外，默认只用密码登录。")
    p.add_argument("--config")
    p.add_argument("--dry-run", action="store_true", help="只问答，不写入")
    p.add_argument("--password-stdin", action="store_true",
                   help="从标准输入读一行作为密码（无人值守安装用）")
    p.set_defaults(func=cmd_setup)
