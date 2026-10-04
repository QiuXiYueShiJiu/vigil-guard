"""`vigil web` -- the built-in status and feedback page.

Credentials are set here, interactively, on the machine. There is deliberately
no default account and no non-interactive way to pass a password: a monitoring
page with a shipped default login is an admin panel that someone else already
knows the password to, and a password in shell history or in `ps` is the same
mistake with extra steps.
"""
from __future__ import annotations

import getpass
import sys

from .. import ui
from ..core import paths, shell, units
from ..core.config import load as load_config
from ..web import server as web_server
from ..web import status as web_status

SNIPPET = "vigil-web.conf"


def _ask_password() -> str:
    if not sys.stdin.isatty():                    # pragma: no cover - 交互路径
        ui.failure("需要交互式终端才能设置密码（不接受从参数或管道传入）")
        return ""
    while True:
        p1 = getpass.getpass("新密码（至少 10 位，输入时不回显）：")
        if len(p1) < 10:
            print("  太短了，至少 10 位。")
            continue
        p2 = getpass.getpass("再输一次：")
        if p1 != p2:
            print("  两次不一致，重来。")
            continue
        return p1


def cmd_passwd(args) -> int:
    cfg = load_config(args.config or None)
    ui.header("设置状态页账号密码", "只在本机交互设置，只保存派生值")
    user = args.username or ""
    if not user:
        if not sys.stdin.isatty():                # pragma: no cover
            ui.failure("请用 --username 指定账号，并在交互终端里输入密码")
            return 2
        user = input("账号：").strip()
    if not user:
        ui.failure("账号不能为空")
        return 2
    pwd = _ask_password()
    if not pwd:
        return 1
    web_server.set_password(cfg, user, pwd)
    ui.success("已设置：账号 %s" % user)
    ui.kv("密码存放", "只保存 PBKDF2 派生值与随机盐，位于 secrets.json（0600）")
    ui.kv("配置文件", "不含密码，可安全贴进工单")
    ui.out()
    ui.note("忘了密码就重新执行一次本命令覆盖即可，不需要知道旧密码。")
    return 0


def cmd_serve(args) -> int:
    cfg = load_config(args.config or None)
    if not bool(cfg.get("web.enabled", True)):
        ui.note("状态页未启用（web.enabled=false）")
        return 0
    ui.header("状态页", "仅监听本机；对外访问请用反代")
    if not web_server.credentials_set(cfg):
        ui.warning("尚未设置账号密码，页面会提示且无法登录")
        ui.hint("设置：vigil web passwd")
    return web_server.serve(cfg, host=args.host,
                            port=args.port, log=lambda m: ui.out("  " + m))


def cmd_status(args) -> int:
    cfg = load_config(args.config or None)
    ui.header("状态页", "本机实时状态")
    board = web_status.board(cfg)
    ui.kv("主机名", board["host"]["hostname"])
    for c in board["cards"]:
        ui.kv(c["title"], "%s%s" % (c["value"], ("　" + c["note"]) if c.get("note") else ""))
    ui.out()
    ui.kv("监听", "%s:%s（仅本机）" % (cfg.get("web.listen", "127.0.0.1"),
                                     cfg.get("web.port", 9177)))
    ui.kv("对外域名", str(cfg.get("web.domain", "") or "（未设置，用 web.install 配置）"))
    ui.kv("账号", str(cfg.get("web.username", "") or "（未设置）"))
    ui.kv("凭据状态", "已设置" if web_server.credentials_set(cfg) else "**未设置**")
    if not web_server.credentials_set(cfg):
        ui.hint("设置：vigil web passwd")
    return 0


def render_conf(cfg) -> str:
    """The reverse-proxy block.

    Generated from what the host already reports -- the domain comes from the
    configuration, the upstream from the configured listen address. Nothing
    here knows about a particular machine.
    """
    domain = str(cfg.get("web.domain", "") or "")
    listen = str(cfg.get("web.listen", "127.0.0.1") or "127.0.0.1")
    port = int(cfg.get("web.port", 9177) or 9177)
    server_name = domain or "_"
    return """# >>> vigil web (generated; do not edit) >>>
# 状态页反代。上游只监听本机，TLS 由这一层负责。
server {
    listen 80;
    server_name %(name)s;
    location / { return 301 https://$host$request_uri; }
}
server {
    listen 443 ssl http2;
    server_name %(name)s;
    location / {
        proxy_pass http://%(up)s:%(port)d;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    access_log /www/wwwlogs/vigil-web.log;
}
# <<< vigil web <<<
""" % {"name": server_name, "up": listen, "port": port}


def cmd_install(args) -> int:
    cfg = load_config(args.config or None)
    domain = args.domain or str(cfg.get("web.domain", "") or "")
    if not domain:
        ui.failure("请用 --domain 指定对外域名")
        return 2
    if args.domain:
        cfg.set("web.domain", domain)
    # 安装即意图明确：把开关打开（默认是关的，装不装由运维决定）
    cfg.set("web.enabled", True)
    cfg.save()
    ui.header("安装状态页", "生成反代配置并接入本机现有 Web 服务")

    target = None
    for cand in ("/www/server/panel/vhost/nginx", "/etc/nginx/conf.d"):
        if paths_path(cand).is_dir():
            target = paths_path(cand) / ("%s.conf" % domain)
            break
    if target is None:
        ui.failure("找不到可用的 nginx 配置目录")
        return 1
    target.write_text(render_conf(cfg), encoding="utf-8")
    ui.success("已写入 %s" % target)

    ok, out, err = shell.run(["nginx", "-t"], timeout=20)
    if not ok:
        target.unlink(missing_ok=True)
        ui.failure("nginx 拒绝新配置，已撤回：%s" % (err or out).strip()[:200])
        return 1
    ui.success("nginx 配置检查通过")
    shell.systemd_reload()
    shell.run(["systemctl", "reload", "nginx"], timeout=30)
    ui.success("已重新加载 nginx")
    ui.out()
    ui.kv("访问地址", "https://%s/" % domain)
    ui.note("还需要两件事：① 把 %s 解析到本机；② 为它签发证书（面板网站设置里一键即可）。"
            % domain)
    ui.hint("然后设置账号密码：vigil web passwd")
    return 0


def paths_path(p):
    from pathlib import Path
    return Path(p)


def cmd_uninstall(args) -> int:
    cfg = load_config(args.config or None)
    domain = args.domain or str(cfg.get("web.domain", "") or "")
    from pathlib import Path
    for cand in ("/www/server/panel/vhost/nginx", "/etc/nginx/conf.d"):
        f = Path(cand) / ("%s.conf" % domain)
        if f.is_file():
            f.unlink()
            ui.success("已移除 %s" % f)
    shell.run(["systemctl", "reload", "nginx"], timeout=30)
    return 0


def cmd_unit(args) -> int:
    """Write the systemd unit for the page."""
    cfg = load_config(args.config or None)
    content = units.service(
        "vigil-web.service", "Built-in status and feedback page",
        ["%s -m vigil.cli web serve" % units.python_bin()],
        stype="simple", restart="always", restart_sec=5,
        nice=5, cpu_quota="3%", memory_max="128M",
        alerting=False, oom_score=300)
    p = units.write_unit("vigil-web.service", content)
    units.ensure_timers_running(log=lambda m: ui.out("  " + m))
    shell.systemd_reload()
    shell.run(["systemctl", "enable", "--now", "vigil-web.service"], timeout=60)
    ui.success("已安装并启动 %s" % p)
    return 0


def register(sub) -> None:
    p = sub.add_parser(
        "web", help="自带的状态与反馈页面",
        description="一个只监听本机、由 nginx 反代对外的实时状态页。"
                    "账号与密码由使用者在本机命令行交互设置，程序不自带默认凭据，"
                    "也不接受把密码写在参数里。")
    ps = p.add_subparsers(dest="web_action", metavar="<操作>")

    sp = ps.add_parser("passwd", help="交互设置账号与密码（只保存派生值）")
    sp.add_argument("--username", help="账号；不给则在终端里问")
    sp.add_argument("--config")
    sp.set_defaults(func=cmd_passwd)

    sp = ps.add_parser("serve", help="前台运行（systemd 用）")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=None)
    sp.add_argument("--config")
    sp.set_defaults(func=cmd_serve)

    sp = ps.add_parser("status", help="看页面会展示的状态与配置")
    sp.add_argument("--config")
    sp.set_defaults(func=cmd_status)

    sp = ps.add_parser("install", help="生成反代配置并接入现有 Web 服务")
    sp.add_argument("--domain", help="对外域名，例如 status.example.com")
    sp.add_argument("--config")
    sp.set_defaults(func=cmd_install)

    sp = ps.add_parser("uninstall", help="移除反代配置")
    sp.add_argument("--domain")
    sp.add_argument("--config")
    sp.set_defaults(func=cmd_uninstall)

    sp = ps.add_parser("unit", help="安装并启动 systemd 单元")
    sp.add_argument("--config")
    sp.set_defaults(func=cmd_unit)
