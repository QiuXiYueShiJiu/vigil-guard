"""`vigil hygiene` -- bound the request line and Host header per site."""
from __future__ import annotations

from .. import ui
from ..guards import hygiene as hyg


def cmd_install(args) -> int:
    ui.header("请求卫生", "在 server{} 作用域收紧请求行与 Host 头的大小")
    ui.kv("URI 上限", "%d 字节（超出回 414）" % hyg.MAX_URI)
    ui.kv("Host 上限", "%d 字节（超出断开 444）" % hyg.MAX_HOST)

    if args.dry_run:
        st = hyg.status()
        for _site, conf in hyg.targets():
            ui.out("    %s" % conf)
        ui.out()
        ui.note("预演结束：共 %d 个站点，未写入任何文件" % st["sites"])
        return 0

    ok, msg = hyg.install()
    if not ok:
        ui.failure(msg)
        return 1
    ui.success(msg)
    ui.out()
    ui.note("超长请求现在在 nginx 解析阶段就被拒绝，不再被缓冲和记入日志。")
    ui.hint("查看状态：vigil hygiene")
    return 0


def cmd_uninstall(args) -> int:
    ok, msg = hyg.uninstall()
    (ui.success if ok else ui.failure)(msg)
    return 0 if ok else 1


def cmd_status(args) -> int:
    st = hyg.status()
    ui.header("请求卫生", "限制请求行与 Host 头")
    ui.kv("受保护站点", "%d 个" % st["sites"])
    ui.kv("已生效", "%d 个" % st["installed"])
    ui.kv("URI 上限", "%d 字节" % st["max_uri"])
    ui.kv("Host 上限", "%d 字节" % st["max_host"])
    if st["stale"]:
        ui.section("未安装或内容已过期")
        for p in st["stale"]:
            ui.out("    %s" % p)
        ui.out()
        ui.hint("应用：vigil hygiene install")
    return 0


def register(sub) -> None:
    p = sub.add_parser(
        "hygiene", help="请求卫生：限制请求行与 Host 头的大小",
        description="在站点的 server{} 作用域写入请求行与 Host 头的长度上限。"
                    "本机从面板继承了 32k 的请求头缓冲，实测 16KB 的 URI 和 "
                    "4KB 的 Host 都会被正常接受并写入日志；这些正是扫描器与"
                    "资源消耗型流量的形态。此项让它们在 nginx 解析阶段就被拒绝。")
    ps = p.add_subparsers(dest="hygiene_action", metavar="<操作>")

    sp = ps.add_parser("install", help="写入并生效（会校验 nginx 是否真的加载）")
    sp.add_argument("--dry-run", action="store_true", help="只显示将要写入什么")
    sp.set_defaults(func=cmd_install)

    sp = ps.add_parser("uninstall", help="移除")
    sp.set_defaults(func=cmd_uninstall)

    p.set_defaults(func=cmd_status)
