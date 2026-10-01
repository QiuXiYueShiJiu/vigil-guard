"""`vigil decoy` -- install and inspect the decoy endpoints."""
from __future__ import annotations

from .. import ui
from ..core.config import load as load_config
from ..guards import decoy as decoy_mod


def cmd_install(args) -> int:
    cfg = load_config(args.config or None)
    ui.header("安装诱饵端点", "把扫描器最爱猜的路径变成确定性的证据")

    if args.dry_run:
        domain, webroot = decoy_mod._site(cfg)
        safe, rejected = decoy_mod.screen(webroot)
        ui.kv("站点", "%s（%s）" % (domain or "?", webroot or "?"))
        ui.kv("将通过", "%d 个" % len(safe))
        for path, _t, why in safe:
            ui.out("    %s  %s" % (path, why))
        if rejected:
            ui.section("已排除（安全检查未通过）")
            for path, why in rejected:
                ui.out("    %s  —— %s" % (path, why))
        ui.out()
        ui.note("预演结束，未写入任何文件")
        return 0

    result = decoy_mod.install(cfg)
    if result.get("rejected"):
        ui.section("已排除（会误伤正常访客）")
        for path, why in result["rejected"]:
            ui.out("    %s  —— %s" % (path, why))
    if not result.get("ok"):
        for problem in result.get("problems", []):
            ui.failure(problem)
        return 1

    ui.success("已写入 %s" % result["written"])
    ui.kv("生效的诱饵", "%d 个" % len(result["paths"]))
    ui.kv("命中日志", result["log"])
    ui.out()
    ui.note("任何一次命中都会被立刻封禁（诱饵路径不存在、站点也不引用它，"
            "不存在正常解释）")
    ui.hint("确认状态：vigil decoy status；查看命中：vigil decoy hits")
    return 0


def cmd_uninstall(args) -> int:
    cfg = load_config(args.config or None)
    result = decoy_mod.uninstall(cfg)
    if not result.get("ok"):
        for problem in result.get("problems", []):
            ui.failure(problem)
        return 1
    if result.get("removed"):
        ui.success("已移除 %s" % result["removed"])
    else:
        ui.note("本来就没有安装诱饵端点")
    return 0


def cmd_status(args) -> int:
    cfg = load_config(args.config or None)
    st = decoy_mod.status(cfg)
    ui.header("诱饵端点", "让扫描器的试探变成确定性的封禁依据")
    ui.kv("是否启用", "是" if st.get("enabled") else "否（threat.decoy.enabled=false）")
    ui.kv("是否已安装", "是" if st.get("installed") else "否")
    if st.get("conf"):
        ui.kv("片段文件", st["conf"])
    if st.get("webroot"):
        ui.kv("保护站点", st["webroot"])
    ui.kv("命中日志", "%s%s" % (st.get("log"),
                                "" if st.get("log_present") else "（尚未产生）"))
    paths = st.get("paths") or []
    ui.kv("生效诱饵", "%d 个" % len(paths))
    for path in paths:
        ui.out("    %s" % path)
    if not st.get("installed"):
        ui.out()
        ui.hint("安装：vigil decoy install")
    return 0


def cmd_hits(args) -> int:
    """What the decoys have caught.

    Also reports which candidates were rejected and why: an operator who
    wonders why `/.env` is not among the decoys deserves the answer.
    """
    cfg = load_config(args.config or None)
    hits = decoy_mod.read_hits(limit=args.limit)
    if not hits:
        ui.header("诱饵命中", "还没有命中")
        ui.note("诱饵的价值在于「一旦命中就毫无争议」—— 平时安静是正常的")
        return 0

    ui.header("诱饵命中", "共记录 %d 次" % len(hits))
    by_ip = {}
    for h in hits:
        by_ip.setdefault(h.get("ip", "?"), []).append(h)
    ui.kv("独立来源", "%d 个" % len(by_ip))
    ui.section("最近命中")
    for h in hits[-args.limit:][::-1]:
        import datetime as _dt
        when = _dt.datetime.fromtimestamp(
            float(h.get("ts", 0))).strftime("%Y-%m-%d %H:%M:%S")
        ui.out("    %s  %-16s  %s" % (when, h.get("ip", "?"), h.get("uri", "?")))
    return 0


def cmd_why(args) -> int:
    """Explain why a path did or did not become a decoy."""
    cfg = load_config(args.config or None)
    wanted = args.path
    st = decoy_mod.status(cfg)
    if wanted in (st.get("paths") or []):
        ui.success("%s 是生效中的诱饵：命中即封禁" % wanted)
        return 0
    domain, webroot = decoy_mod._site(cfg)
    safe, rejected = decoy_mod.screen(webroot)
    for path, why in rejected:
        if path == wanted:
            ui.warning("%s 未被安装：%s" % (wanted, why))
            ui.note("宁可少一个诱饵，也不要封掉一个正常访客")
            return 0
    for path, _t, _w in safe:
        if path == wanted:
            ui.note("%s 通过了安全检查，但尚未安装 —— 运行 vigil decoy install"
                    % wanted)
            return 0
    ui.note("%s 不在候选列表里（共 %d 个候选）" % (wanted, len(decoy_mod.DECOYS)))
    return 0


def register(sub) -> None:
    p = sub.add_parser(
        "decoy", help="诱饵端点：让扫描器的试探成为确定性的封禁依据",
        description="在站点上放置一组「不存在、也没有任何页面引用」的路径，"
                    "并为它们单独记录日志。因为不存在正常解释，所以任何一次命中"
                    "都会被立即长期封禁。安装前会逐个检查：路径在磁盘上不存在、"
                    "且站点内容没有引用它——任一不满足就放弃该诱饵。")
    ps = p.add_subparsers(dest="decoy_action", metavar="<操作>")

    sp = ps.add_parser("install", help="安装诱饵端点（会先做安全检查）")
    sp.add_argument("--dry-run", action="store_true", help="只显示将要安装什么")
    sp.set_defaults(func=cmd_install)

    sp = ps.add_parser("uninstall", help="移除诱饵端点")
    sp.set_defaults(func=cmd_uninstall)

    sp = ps.add_parser("status", help="查看诱饵状态")
    sp.set_defaults(func=cmd_status)

    sp = ps.add_parser("hits", help="查看诱饵命中记录")
    sp.add_argument("--limit", type=int, default=20, help="显示多少条")
    sp.set_defaults(func=cmd_hits)

    sp = ps.add_parser("why", help="解释某个路径为什么（没）被选为诱饵")
    sp.add_argument("path", help="路径，例如 /.env")
    sp.set_defaults(func=cmd_why)
