"""Command line interface.

One entry point, a browsable tree, and ``--help`` at every level. The help
text is generated from the same tables the dispatcher uses, so a command
cannot exist without appearing in the menu.

Conventions for every subcommand:

* exit code 0 on success, 1 on a handled failure, 2 on bad usage;
* ``--json`` where machine-readable output is useful;
* nothing interactive happens unless stdin is a TTY (see :mod:`vigil.ui`).
"""
from __future__ import annotations

import argparse
import os
import sys

from . import ui
from .i18n import set_language, t
from .version import NAME, SUMMARY, __version__

PROG = "vigil"

BANNER = r"""
   __     ___       _ __
   \ \   / (_) __ _(_) /
    \ \ / /| |/ _` | | |
     \ V / | | (_| | | |
      \_/  |_|\__, |_|_|
              |___/
"""

#: (name, one-line description). Order is the order shown in the menu.
COMMAND_GROUPS = [
    ("开始使用", [
        ("init", "交互式配置界面（首次使用推荐）"),
        ("install", "安装、重装、卸载本系统"),
        ("doctor", "环境自检：检测本机支持哪些能力"),
        ("status", "运行状态总览"),
    ]),
    ("告警通道", [
        ("mail", "邮件/Webhook 告警通道配置与测试"),
    ]),
    ("防护能力", [
        ("threat", "实时风控：查看封禁、手动封禁/解禁、白名单"),
        ("health", "安全巡检：运行检查、查看检查项与说明"),
        ("gate", "登录界面防护：宝塔面板 / DSH 登录网关"),
        ("shield", "Web 层防护：扫描器拦截与站点限流（nginx 全局）"),
        ("exposure", "敏感文件暴露：扫出能被公网下载的备份/凭据/源码"),
        ("audit-source", "发布前自检：随包文件里是否混入本机信息"),
        ("decoy", "诱饵端点：让扫描器自投罗网"),
        ("bouncer", "Web 层封禁：第二个执行点"),
        ("autoresponse", "可疑进程自动处置：看它暂停了谁、一键撤销"),
        ("learn", "自学习：从观测中挖掘新特征（带误报门控）"),
        ("hygiene", "请求卫生：限制请求行与 Host 头的大小"),
        ("drill", "攻击演练：多来源多层次，仅对本机"),
        ("lure", "诱导面：让诱饵被找到，并衡量是否有效"),
        ("evolve", "自修正：有边界地改进自己，并监控它"),
        ("web", "自带的状态与反馈页面（只监听本机）"),
        ("setup", "交互式快速设置：一次问答配好管理页面"),
        ("audit", "内核审计规则（文件改动归因）"),
    ]),
    ("运维", [
        ("service", "服务管理：启停、状态、日志"),
        ("config", "配置管理：查看、修改、导入导出、校验"),
        ("update", "从源码更新本程序"),
        ("rollback", "回滚到上一次更新之前的版本"),
        ("backup", "备份配置、凭据与基线"),
        ("restore", "从归档恢复"),
        ("selftest", "安装自检：确认装好的东西真的在工作"),
    ]),
]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=PROG,
        description="%s —— %s" % (NAME, SUMMARY),
        epilog="运行 `%s <命令> --help` 查看该命令的详细用法。" % PROG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-V", "--version", action="version",
                   version="%s %s" % (NAME, __version__))
    p.add_argument("--lang", choices=("zh", "en"), default="",
                   help="输出语言（默认跟随系统区域设置）")
    p.add_argument("--no-color", action="store_true", help="禁用彩色输出")
    p.add_argument("--json", action="store_true",
                   help="以 JSON 输出（适用于支持的子命令）")
    p.add_argument("--yes", "-y", action="store_true",
                   help="对所有确认提示自动回答「是」")
    p.add_argument("--config", default="",
                   help="使用非默认的配置文件路径")

    sub = p.add_subparsers(dest="command", metavar="<命令>")

    from .commands import (audit as cmd_audit, config as cmd_config,
                           diag as cmd_diag, gate as cmd_gate,
                           health as cmd_health, install as cmd_install,
                           mail as cmd_mail, service as cmd_service,
                           shield as cmd_shield, threat as cmd_threat,
                           exposure as cmd_exposure,
                           audit_source as cmd_audit_source,
                           backup as cmd_backup, bouncer as cmd_bouncer,
                           autoresponse as cmd_autoresponse,
                           decoy as cmd_decoy, learn as cmd_learn,
                           hygiene as cmd_hygiene,
                           drill as cmd_drill,
                           lure as cmd_lure,
                           evolve as cmd_evolve,
                           web as cmd_web,
                           setup as cmd_setup,
                           selftest as cmd_selftest,
                           update as cmd_update,
                           wizard as cmd_wizard)

    cmd_wizard.register(sub)
    cmd_install.register(sub)
    cmd_diag.register(sub)
    cmd_mail.register(sub)
    cmd_threat.register(sub)
    cmd_health.register(sub)
    cmd_gate.register(sub)
    cmd_shield.register(sub)
    cmd_exposure.register(sub)
    cmd_audit_source.register(sub)
    cmd_audit.register(sub)
    cmd_service.register(sub)
    cmd_config.register(sub)
    cmd_update.register(sub)  # update + rollback
    cmd_backup.register(sub)
    cmd_selftest.register(sub)
    cmd_decoy.register(sub)
    cmd_learn.register(sub)
    cmd_bouncer.register(sub)
    cmd_autoresponse.register(sub)
    cmd_hygiene.register(sub)
    cmd_drill.register(sub)
    cmd_lure.register(sub)
    cmd_evolve.register(sub)
    cmd_web.register(sub)
    cmd_setup.register(sub)
    return p


def print_menu() -> None:
    """The default screen: what this is, and what it can do."""
    ui.out(ui.c(BANNER, "cyan"))
    ui.out("  %s  %s" % (ui.bold("%s %s" % (NAME, __version__)),
                         ui.dim(SUMMARY)))
    ui.out()
    for group, cmds in COMMAND_GROUPS:
        ui.out("  %s" % ui.bold(group))
        for name, desc in cmds:
            pad = " " * max(1, 12 - len(name))
            ui.out("    %s%s%s" % (ui.c(name, "green"), pad, ui.dim(desc)))
        ui.out()
    ui.out("  %s" % ui.dim("常用示例："))
    for example, what in (
        ("vigil install", "安装并配置"),
        ("vigil mail setup", "配置告警邮箱（推荐先做这个）"),
        ("vigil mail test", "发一封测试邮件确认通道可用"),
        ("vigil status", "看一眼现在是否一切正常"),
        ("vigil gate detect", "检测本机已有的登录防护配置"),
    ):
        ui.out("    %s  %s" % (ui.c(example, "cyan"), ui.dim("# " + what)))
    ui.out()
    ui.out("  %s" % ui.dim("运行 `vigil <命令> --help` 查看详细用法。"))


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # `vigil` with no arguments is a request for the menu, not an error.
    if not argv:
        print_menu()
        return 0

    if argv[0] in ("help", "--help", "-h") and len(argv) == 1:
        print_menu()
        return 0

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.no_color or os.environ.get("NO_COLOR"):
        ui.set_color(False)
    set_language(args.lang)

    if not args.command:
        print_menu()
        return 0

    if args.config:
        from .core import paths
        paths.CONFIG = paths.Path(args.config)
        paths.SECRETS = paths.CONFIG.parent / "secrets.json"

    handler = getattr(args, "func", None)
    if handler is None:
        parser.print_help()
        return 2

    from .core.errors import ConfigError, PermissionDenied, VigilError
    try:
        rc = handler(args)
        return int(rc) if rc is not None else 0
    except KeyboardInterrupt:
        ui.out()
        ui.warning("已取消")
        return 130
    except PermissionDenied as e:
        ui.failure(e.render())
        return 1
    except VigilError as e:
        ui.failure(e.render())
        return 1
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0


if __name__ == "__main__":
    sys.exit(main())
