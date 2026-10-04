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
    ui.header("vigil 快速设置", "一次问答，把管理页面配好")

    # ---- 1. 要配哪些页面 -------------------------------------------------
    ui.out("可配置的管理页面：")
    for i, (key, title, desc) in enumerate(PAGES, 1):
        ui.out("  %d) %-8s %s —— %s" % (i, key, title, desc))
    picked = _ask("要配置哪些（逗号分隔序号，all=全部）", "all")
    if picked.lower() in ("all", "全部", ""):
        chosen = [k for k, _t, _d in PAGES]
    else:
        chosen = []
        for tok in picked.replace("，", ",").split(","):
            tok = tok.strip()
            if tok.isdigit() and 1 <= int(tok) <= len(PAGES):
                chosen.append(PAGES[int(tok) - 1][0])
    if not chosen:
        ui.failure("没有选中任何页面")
        return 2
    ui.success("将配置：%s" % "、".join(chosen))

    # ---- 2. 名字与访问方式 -----------------------------------------------
    host = _ask("页面显示的名字（留空则用主机名）", "")
    public = _yesno("是否用域名对外访问（否则只监听本机）", False)
    domain, port = "", 9177
    if public:
        domain = _ask("域名（例如 status.example.com）", "")
        if not domain:
            ui.warning("没填域名，按「只监听本机」处理")
            public = False
        else:
            port = int(_ask("对外端口（443 表示走 HTTPS）", "443") or 443)
    listen_port = int(_ask("本地监听端口", "9177") or 9177)

    # ---- 3. 登录方式 ------------------------------------------------------
    ui.out("登录方式：")
    ui.out("  1) 只用密码")
    ui.out("  2) 密码 + 人机验证")
    auth = _ask("选择", "1")
    captcha = auth.strip() in ("2", "both", "都有")
    username = _ask("登录账号", "admin")
    password = ""
    if args.password_stdin:                        # 供无人值守安装使用
        password = sys.stdin.readline().strip()
    else:
        password = _ask_password()
    if not password:
        ui.failure("没有设置密码，页面会拒绝登录")
        return 1

    # ---- 4. 邮件 ----------------------------------------------------------
    email_to = _ask("告警收件邮箱（留空则跳过邮件配置）", "")
    sender = _ask("发件人地址（留空则用收件邮箱）", email_to) if email_to else ""

    if args.dry_run:
        ui.out()
        ui.note("预演结束，未写入任何配置。")
        return 0

    # ---- 5. 落地 ----------------------------------------------------------
    from . import web as web_cmd
    from ..web import server as web_server

    cfg.set("web.enabled", True)
    cfg.set("web.listen", "127.0.0.1")
    cfg.set("web.port", listen_port)
    cfg.set("web.domain", domain)
    cfg.set("web.display_name", host)
    cfg.set("web.captcha", bool(captcha))
    if email_to:
        cfg.set("mail.recipients", [email_to])
        cfg.set("mail.from_address", sender or email_to)
    cfg.save()
    web_server.set_password(cfg, username, password)
    ui.success("账号密码已设置（只保存派生值）")

    if public and domain:
        res = web_cmd.cmd_install(_NS(domain=domain, config=args.config))
        if res != 0:
            ui.warning("反代配置未完成，页面仍只在本机可用")
    else:
        ui.note("未选择域名访问：页面只监听 %s:%d" % ("127.0.0.1", listen_port))

    web_cmd.cmd_unit(_NS(config=args.config))
    ui.kv("访问", "https://%s/" % domain if (public and domain)
           else "http://127.0.0.1:%d/（本机）" % listen_port)

    # ---- 6. 测试邮件 ------------------------------------------------------
    if email_to:
        ui.out()
        ui.out("发一封测试邮件确认通道可用……")
        from ..guards import threat as threat_mod
        try:
            alert = threat_mod.Alert(title="vigil 安装完成：这是一封测试邮件",
                                     severity=threat_mod.SEV_INFO,
                                     kind=threat_mod.KIND_ALERT,
                                     dedupe_key="setup|test")
            sec = alert.add_section("测试邮件")
            sec.add("如果你收到这封信，说明告警通道已经配好了。")
            sec.add("收件人：%s" % email_to)
            ok = threat_mod.send_alert(alert, cfg=cfg)
            (ui.success if ok else ui.warning)(
                "测试邮件已发出" if ok else "测试邮件发送失败（检查发件服务配置）")
        except Exception as e:                                 # noqa: BLE001
            ui.warning("测试邮件发送失败：%s" % str(e)[:120])

    ui.out()
    ui.success("设置完成")
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
