"""`vigil lure` -- the crawler-facing lure surfaces and whether they work."""
from __future__ import annotations

from .. import ui
from ..core.config import load as load_config
from ..guards import lure as lure_mod


def cmd_status(args) -> int:
    cfg = load_config(args.config or None)
    st = lure_mod.status(cfg)
    ui.header("诱导面", "让诱饵被自动化流量找到，并衡量是否真的有效")
    ui.out(lure_mod.format_status(st))
    ui.out()
    ui.kv("robots.txt", "站点自己的规则保留，vigil 只追加带标记的段落")
    ui.kv("sitemap.xml", "由 nginx 片段提供，不在站点目录里留文件")
    if not st["sitemap_installed"] or not st["robots_installed"]:
        ui.hint("发布：vigil lure install")
    return 0


def cmd_install(args) -> int:
    cfg = load_config(args.config or None)
    ui.header("发布诱导面", "把最强的诱饵放到自动化流量会读的地方")
    res = lure_mod.install(cfg, dry_run=args.dry_run)
    if args.dry_run:
        ui.kv("将宣传", "%d 条路径" % len(res.get("advertised") or []))
        for p in res.get("advertised") or []:
            ui.out("    %s" % p)
        ui.out()
        ui.note("预演结束，未写入任何文件")
        return 0
    if not res.get("ok"):
        for p in res.get("problems") or ["未知原因"]:
            ui.failure(p)
        return 1
    ui.success(res.get("robots") or "已发布")
    ui.kv("sitemap 片段", res.get("conf") or "")
    ui.kv("宣传路径", "%d 条" % len(res.get("advertised") or []))
    ui.out()
    ui.note("Disallow 在这里是路标不是围栏：值得抓的自动化流量读 robots.txt"
            "恰恰是为了找被禁止的路径，而守规矩的爬虫什么也不会损失——"
            "这些路径本来就不存在。")
    ui.hint("查看效果：vigil lure")
    return 0


def cmd_uninstall(args) -> int:
    cfg = load_config(args.config or None)
    res = lure_mod.uninstall(cfg)
    (ui.success if res.get("ok") else ui.failure)(
        res.get("robots") or "已撤销诱导面")
    for p in res.get("problems") or []:
        ui.warning(p)
    return 0 if res.get("ok") else 1


def cmd_show(args) -> int:
    cfg = load_config(args.config or None)
    if args.show_action == "sitemap":
        ui.out(lure_mod.sitemap_xml(cfg))
    else:
        ui.out(lure_mod.robots_block(cfg))
    return 0


def register(sub) -> None:
    p = sub.add_parser(
        "lure", help="诱导面：让诱饵被找到，并衡量是否真的有效",
        description="把最强的诱饵路径发布到自动化流量真正会读的地方，"
                    "并埋一个只在这里出现的金丝雀路径。"
                    "已有研究一致指出：提高命中率的不是「更多路径」，而是"
                    "「放在爬虫会看的位置」与「命名足够真实」；而衡量有效性"
                    "不能只看命中数量。因此这里既发布位置，也回答「诱导面到底"
                    "有没有被读过」——金丝雀被请求过就是被读过。")
    ps = p.add_subparsers(dest="lure_action", metavar="<操作>")

    sp = ps.add_parser("install", help="发布（先过 nginx -t，不通过整体回滚）")
    sp.add_argument("--dry-run", action="store_true", help="只显示将发布什么")
    sp.set_defaults(func=cmd_install)

    sp = ps.add_parser("uninstall", help="撤销，并把 robots.txt 还原")
    sp.set_defaults(func=cmd_uninstall)

    sp = ps.add_parser("show", help="打印将写入的内容")
    sp.add_argument("show_action", nargs="?", default="robots",
                    choices=["robots", "sitemap"])
    sp.set_defaults(func=cmd_show)

    p.set_defaults(func=cmd_status)
