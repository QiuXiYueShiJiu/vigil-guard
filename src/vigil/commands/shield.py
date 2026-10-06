"""`vigil shield` -- host-wide web-layer hardening in nginx.

The gate command protects the admin surface. This protects everything else:
it rejects the tools that spend their lives looking for something to exploit,
and it caps how much of the machine one address can use.

Kept separate from `gate` because the two have different blast radii. A gate
is one vhost; a mistake here affects every site on the host, which is why
every change is proven with `nginx -t` before it is applied and rolled back
automatically when it is not.
"""
from __future__ import annotations

from .. import ui
from ..core.config import load as load_config
from ..core.errors import VigilError


def cmd_shield(args) -> int:
    from ..gates import shield

    action = getattr(args, "shield_action", "") or "status"

    if action == "status":
        st = shield.status()
        ui.header("Web 层防护", "nginx http{} 作用域")
        ui.kv("nginx 主配置", st["conf"])
        ui.kv("防护片段", st["shield_file"],
              "green" if st["shield_present"] else "yellow")
        ui.kv("已被 include",
              "是" if st["shield_included"] else "否",
              "green" if st["shield_included"] else "yellow")
        ui.kv("屏蔽的扫描器 UA", "%d 条" % st["agents"])
        ui.out()
        if st["legacy_present"]:
            ui.warning("旧版加固文件仍在：%s" % st["legacy_file"])
            ui.note("它定义的同名变量与限流区仍被站点配置引用，所以不能直接删。")
            ui.hint("vigil shield install   # 迁移进本系统并安全退役旧文件")
        elif st["legacy_included"]:
            ui.warning("nginx 仍在 include 一个已不存在的旧文件")
            ui.hint("vigil shield install")
        else:
            ui.success("旧版加固文件已退役")
        if not st["shield_included"] and not st["legacy_included"]:
            ui.out()
            ui.warning("当前没有 Web 层防护生效")
            ui.hint("vigil shield install")
        return 0

    if action == "install":
        ui.header("安装 Web 层防护", "按 UA 拦截扫描器 + 站点级限流")
        ui.note("写入前会先跑 `nginx -t` 验证；验证不通过会自动全部回滚。")
        if not args.yes and ui.is_interactive():
            if not ui.confirm("继续？", default=True):
                return 0
        res = shield.install(retire=not args.keep_legacy)
        for path in res["written"]:
            ui.bullet("已写入 %s" % path)
        if res["backup"]:
            ui.bullet("旧文件备份 %s" % res["backup"])
        if res["retired"]:
            ui.bullet("旧文件已退役 %s" % res["retired"])
        if res["reloaded"]:
            ui.bullet("nginx 已重载（%s）" % res["reloaded"])
        ui.out()
        for p in res["problems"]:
            ui.failure(p)
        if res["ok"]:
            ui.success("Web 层防护已生效")
            ui.hint("vigil shield status")
            return 0
        # Three different failures, three different next actions. Saying
        # "rolled back" when the file was written and only a restart can load
        # it would send the operator looking in the wrong place.
        if res.get("refused"):
            ui.failure("已拒绝写入，磁盘保持原样")
        elif res.get("rolled_back"):
            ui.failure("未生效，已回滚到改动前的状态")
        else:
            ui.warning("文件已写入，但运行中的 nginx 没有使用它"
                       "——需要完整重启才能生效")
        return 1

    if action == "uninstall":
        ui.header("移除 Web 层防护", "会恢复到旧版文件（若站点仍引用它）")
        if not args.yes and ui.is_interactive():
            if not ui.confirm("继续？", default=False):
                return 0
        res = shield.uninstall()
        if res["removed"]:
            ui.bullet("已移除 %s" % res["removed"])
        if res["restored"]:
            ui.bullet("已恢复 %s（站点仍引用其中的定义）" % res["restored"])
        for p in res["problems"]:
            ui.failure(p)
        if res["ok"]:
            ui.success("已移除")
            return 0
        return 1

    ui.failure("未知操作：%s" % action)
    return 1


def register(sub) -> None:
    p = sub.add_parser(
        "shield", help="Web 层防护：按 UA 拦截扫描器 + 站点级限流（nginx 全局）",
        description="在 nginx 的 http{} 作用域生效的通用 Web 加固。"
                    "与 `gate` 分开，因为影响面不同：gate 只影响一个站点，"
                    "这里影响整台机器上的所有站点，所以每次改动都会先用 "
                    "`nginx -t` 验证，失败则自动回滚。")
    ps = p.add_subparsers(dest="shield_action", metavar="<操作>")
    p.set_defaults(func=cmd_shield, shield_action="status")

    sp = ps.add_parser("status", help="查看当前状态")
    sp.set_defaults(func=cmd_shield, shield_action="status")

    sp = ps.add_parser("install", help="安装/更新防护片段",
                       description="写入防护片段并接入 nginx。"
                                   "若存在旧版加固文件，会在验证通过后安全退役它。")
    sp.add_argument("--keep-legacy", action="store_true",
                    help="不要动旧版加固文件（默认会退役它）")
    sp.add_argument("--yes", "-y", action="store_true")
    sp.set_defaults(func=cmd_shield, shield_action="install")

    sp = ps.add_parser("uninstall", help="移除防护片段")
    sp.add_argument("--yes", "-y", action="store_true")
    sp.set_defaults(func=cmd_shield, shield_action="uninstall")
