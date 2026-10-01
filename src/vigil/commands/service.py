"""`vigil service` -- start, stop, inspect and read logs of our units."""
from __future__ import annotations

import time

from .. import ui
from ..core import logging as vlog
from ..core import paths, shell, units
from ..core.errors import VigilError

ACTIONS = ("start", "stop", "restart", "status", "logs", "enable", "disable")


def _resolve(name: str) -> str:
    """Accept 'threatd', 'vigil-threatd', or 'vigil-threatd.service'."""
    if not name:
        raise VigilError("缺少服务名", hint="运行 `vigil service status` 查看全部单元")
    unit = name if name.startswith(paths.UNIT_PREFIX) else paths.UNIT_PREFIX + name
    if not unit.endswith((".service", ".timer")):
        unit += ".service"
    if not (paths.SYSTEMD_UNIT_DIR / unit).exists():
        avail = [u for u, _a, _e in units.list_units()]
        raise VigilError("未找到服务 %s" % unit,
                         hint="可用: %s" % (", ".join(avail) or "（无）"))
    return unit


def cmd_service(args) -> int:
    action = args.action or "status"

    if action == "status":
        rows = []
        for unit, active, enabled in units.list_units():
            rows.append([unit,
                         ("运行中" if active == "active" else active),
                         ("已启用" if enabled == "enabled" else enabled),
                         shell.out(["systemctl", "show", unit,
                                    "-p", "ActiveEnterTimestamp", "--value"])])
        if not rows:
            ui.note("没有已安装的服务单元")
            ui.hint("运行 `vigil install` 安装")
            return 0
        ui.header("服务状态")
        ui.table(rows, headers=["单元", "状态", "开机自启", "启动时间"])
        return 0

    if action == "logs":
        unit = _resolve(args.name) if args.name else ""
        if not unit:
            # No name: show our own application logs, which are more useful
            # than journald for a first look.
            return _show_app_logs(args)
        ok, out, err = shell.run(
            ["journalctl", "-u", unit, "-n", str(args.lines),
             "--no-pager", "-o", "short-iso"], timeout=20)
        if not ok:
            ui.failure("读取日志失败: %s" % err.strip()[:200])
            return 1
        ui.out(out.rstrip())
        return 0

    # Actions that change state.
    targets = [_resolve(args.name)] if args.name else \
        [u for u, _a, _e in units.list_units() if u.endswith(".service")]
    if not targets:
        ui.note("没有可操作的服务单元")
        return 0
    rc = 0
    for unit in targets:
        if action in ("start", "stop", "restart"):
            ok, _o, err = shell.run(["systemctl", action, unit], timeout=90)
        elif action == "enable":
            ok, _o, err = shell.run(["systemctl", "enable", unit], timeout=30)
        elif action == "disable":
            ok, _o, err = shell.run(["systemctl", "disable", unit], timeout=30)
        else:
            raise VigilError("未知操作: %s" % action,
                             hint="可用: %s" % ", ".join(ACTIONS))
        if ok:
            ui.success("%s %s" % (action, unit))
        else:
            ui.failure("%s %s: %s" % (action, unit, err.strip()[:200]))
            rc = 1
    return rc


def _show_app_logs(args) -> int:
    """Tail the application's own logs, newest last."""
    names = args.name.split(",") if args.name else ["main", "mail", "threat",
                                                    "health"]
    table = {
        "main": paths.LOG_MAIN, "mail": paths.LOG_MAIL,
        "threat": paths.LOG_THREAT, "health": paths.LOG_HEALTH,
        "login": paths.LOG_LOGIN, "commands": paths.LOG_COMMANDS,
        "gate": paths.LOG_GATE,
    }
    shown = False
    for name in names:
        name = name.strip()
        path = table.get(name)
        if not path or not path.exists():
            continue
        shown = True
        ui.section("%s  (%s)" % (name, path))
        for line in vlog.tail(path, args.lines):
            _colorize(line)
    if not shown:
        ui.note("暂无日志文件")
        ui.hint("指定具体服务查看 journald 日志：vigil service logs threatd")
    return 0


def _colorize(line: str) -> None:
    if "[CRIT]" in line or "[ERROR]" in line:
        ui.out(ui.err(line))
    elif "[WARN]" in line:
        ui.out(ui.warn(line))
    elif "[ALERT]" in line:
        ui.out(ui.c(line, "magenta"))
    else:
        ui.out(line)


def register(sub) -> None:
    p = sub.add_parser("service", help="服务管理：启停、状态、日志",
                       description="管理本程序安装的 systemd 服务与定时器。")
    p.add_argument("action", nargs="?", default="status",
                   choices=ACTIONS,
                   help="要执行的操作（默认 status）")
    p.add_argument("name", nargs="?", default="",
                   help="服务名，可省略前缀；logs 时可用 main,mail,threat,health")
    p.add_argument("-n", "--lines", type=int, default=60, help="日志行数")
    p.set_defaults(func=cmd_service)
