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

#: Marks a vhost this program wrote. Before overwriting or deleting anything in
#: a web server's configuration directory we check for these two lines: the
#: directory also holds files other programs and the operator generated, and
#: there is no way to tell "mine" from "theirs" by filename -- they are all
#: ``<domain>.conf``. A real accident: `vigil web install --domain X` silently
#: replaced a carefully tuned vhost another program had made for X.
CONF_BEGIN = "# >>> vigil web (generated; do not edit) >>>"
CONF_END = "# <<< vigil web <<<"

#: Where a reverse-proxy vhost is written. The first directory that exists
#: wins: the panel's own vhost directory when there is one, /etc/nginx/conf.d
#: otherwise. A module constant rather than inline literals so a test can point
#: the command at a temporary directory instead of the host's real config.
CONF_DIRS = ("/www/server/panel/vhost/nginx", "/etc/nginx/conf.d")


def _generated_vhost(path) -> bool:
    """Did *this* program write the file at *path*?

    Deliberately strict and cheap: the begin marker must be its own line (the
    first non-empty one), and the end marker must still be present. A file
    whose header was edited, or whose footer was cut off, is treated as
    somebody else's -- refusing to overwrite a file we are not sure about is
    the safe direction, and the operator can always pass ``--force``.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    if CONF_END not in text:
        return False
    for line in text.splitlines():
        if not line.strip():
            continue
        return line.strip() == CONF_BEGIN
    return False


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
    body = """# 状态页反代。上游只监听本机，TLS 由这一层负责。
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
""" % {"name": server_name, "up": listen, "port": port}
    return "%s\n%s%s\n" % (CONF_BEGIN, body, CONF_END)


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
    for cand in CONF_DIRS:
        d = paths_path(cand)
        if d.is_dir():
            target = d / ("%s.conf" % domain)
            break
    if target is None:
        ui.failure("找不到可用的 nginx 配置目录")
        return 1

    # Never silently overwrite somebody else's vhost. The panel writes
    # `<domain>.conf` too, so the filename proves nothing; only the marker
    # does. Refusing is the default, and `--force` is the explicit way past it.
    previous = None
    if target.exists():
        if not _generated_vhost(target):
            if not getattr(args, "force", False):
                ui.failure("目标已存在，且不是本程序生成的配置，拒绝覆盖")
                ui.kv("路径", str(target))
                ui.note("它可能是面板或另一个程序生成的、你手工调过的 vhost。"
                        "vigil 不会静默覆盖别人的配置。")
                ui.hint("确认要用状态页反代替换它，请加 --force 重跑本命令。")
                return 1
            previous = target.read_text(encoding="utf-8", errors="replace")
            ui.warning("--force：将覆盖不是本程序生成的配置 %s" % target)
        else:
            previous = target.read_text(encoding="utf-8", errors="replace")

    target.write_text(render_conf(cfg), encoding="utf-8")
    ui.success("已写入 %s" % target)

    ok, out, err = shell.run(["nginx", "-t"], timeout=20)
    if not ok:
        # Put back exactly what was there: deleting the file outright would
        # destroy a vhost the operator had before this command ran.
        if previous is None:
            target.unlink(missing_ok=True)
        else:
            target.write_text(previous, encoding="utf-8")
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
    removed, skipped = [], []
    for cand in CONF_DIRS:
        f = Path(cand) / ("%s.conf" % domain)
        if not f.is_file():
            continue
        # Absolutely never delete a vhost this program did not write. The
        # directory is shared, and `<domain>.conf` is exactly the name a panel
        # would pick, so deleting by name would remove somebody else's site.
        if not _generated_vhost(f):
            skipped.append(f)
            continue
        f.unlink()
        removed.append(f)
        ui.success("已移除 %s" % f)
    if skipped:
        ui.warning("以下配置不是本程序生成的，未删除：")
        for f in skipped:
            ui.out("  " + str(f))
        ui.note("vigil 只删除自己生成的文件；如果它确实该删，请自行确认后手动删除。")
    if not removed and not skipped:
        ui.note("没有找到 %s 对应的反代配置" % domain)
    if removed:
        shell.run(["systemctl", "reload", "nginx"], timeout=30)
    return 0


def cmd_unit(args) -> int:
    """Write the systemd unit for the page."""
    cfg = load_config(args.config or None)
    content = units.service(
        "vigil-web.service", "Built-in status and feedback page",
        "ExecStart=%s -m vigil.cli web serve" % units.python_bin(),
        stype="simple", restart="always", restart_sec=5,
        nice=5, cpu_quota="3%", memory_max="128M",
        alerting=False, oom_score=300)
    # 短名：`unit_path()` 会自己加上 UNIT_PREFIX（传全名会得到 vigil-vigil-web）
    p = units.write_unit("web.service", content)
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
    sp.add_argument("--force", action="store_true",
                    help="目标已有一个不是本程序生成的配置时，仍然覆盖它"
                         "（默认拒绝覆盖，避免踩掉别人调好的 vhost）")
    sp.add_argument("--config")
    sp.set_defaults(func=cmd_install)

    sp = ps.add_parser("uninstall", help="移除反代配置")
    sp.add_argument("--domain")
    sp.add_argument("--config")
    sp.set_defaults(func=cmd_uninstall)

    sp = ps.add_parser("unit", help="安装并启动 systemd 单元")
    sp.add_argument("--config")
    sp.set_defaults(func=cmd_unit)
