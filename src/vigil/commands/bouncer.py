"""`vigil bouncer` -- the web-server enforcement point."""
from __future__ import annotations

from .. import ui
from ..core.config import load as load_config
from ..guards import bouncer as bmod


def cmd_install(args) -> int:
    cfg = load_config(args.config or None)
    ui.header("接入 Web 层封禁", "同一批决定，第二个执行点")
    if not args.yes:
        ui.note("这会在 nginx 的 http{} 里加一行 include，并生成 %s"
                % bmod.conf_path())
        ui.note("效果：被封禁的地址在 Web 层直接收到 403 —— "
                "在缺少 ipset 的主机上依然有效，而且可以当作文件审计")
        ui.out()
        ui.hint("确认后加 --yes 执行")
        return 0
    result = bmod.install(cfg)
    if not result.get("ok"):
        for problem in result.get("problems") or ["未知原因"]:
            ui.failure(problem)
        return 1
    try:
        cfg.set("bouncer.enabled", True)
        cfg.save()
    except OSError as e:
        ui.warning("已接入但写配置失败：%s" % e)
    ui.success("已接入 %s" % result.get("path", ""))
    ui.kv("当前封禁条目", bmod.status(cfg).get("entries", 0))
    ui.hint("立即生成一次：vigil bouncer sync")
    return 0


def cmd_uninstall(args) -> int:
    cfg = load_config(args.config or None)
    result = bmod.uninstall(cfg)
    if not result.get("ok"):
        for problem in result.get("problems") or ["未知原因"]:
            ui.failure(problem)
        return 1
    try:
        cfg.set("bouncer.enabled", False)
        cfg.save()
    except OSError:
        pass
    if result.get("removed"):
        ui.success("已移除 %s 及其 include" % result["removed"])
    else:
        ui.note("本来就没有接入")
    return 0


def cmd_sync(args) -> int:
    cfg = load_config(args.config or None)
    result = bmod.sync(cfg, dry_run=args.dry_run)
    bmod.record_sync(result)
    if not result.get("ok"):
        for problem in result.get("problems") or ["未知原因"]:
            ui.failure(problem)
        return 1
    if result.get("problems"):
        ui.note(result["problems"][0])
        return 0
    if result.get("changed"):
        ui.success("已更新封禁列表：%d 条%s"
                   % (result.get("count", 0),
                      "（预演，未写入）" if args.dry_run else "，nginx 已 reload"))
    else:
        ui.note("没有变化（%d 条封禁），未触碰 nginx"
                % result.get("count", 0))
    ui.kv("文件", result.get("path", ""))
    return 0


def cmd_status(args) -> int:
    cfg = load_config(args.config or None)
    st = bmod.status(cfg)
    ui.header("Web 层封禁", "与 ipset 并行的第二个执行点")
    ui.kv("是否启用", "是" if st.get("enabled") else "否", 
          "" if st.get("enabled") else "yellow")
    ui.kv("片段文件", st.get("path", ""))
    ui.kv("文件存在", "是" if st.get("installed") else "否")
    ui.kv("已接入 nginx", "是" if st.get("includes") else "否",
          "" if st.get("includes") else "yellow")
    ui.kv("封禁条目", "%d 条（写入 %d 个 server 块）"
          % (st.get("entries", 0), st.get("copies", 1)))
    ui.kv("ipset 可用", "是" if st.get("ipset") else "否 —— 这个执行点是唯一依靠")
    last = bmod.last_sync()
    if last:
        import time
        age = time.time() - float(last.get("at", 0) or 0)
        ui.kv("上次同步", "%.0f 秒前（%d 条）" % (age, last.get("count", 0)))
    if not st.get("installed"):
        ui.out()
        ui.hint("接入：vigil bouncer install --yes")
    return 0


def register(sub) -> None:
    p = sub.add_parser(
        "bouncer", help="Web 层封禁：把封禁决定同时执行在 nginx 上",
        description="当前所有封禁只在一个地方执行：ipset + iptables。"
                    "在没有 ipset 的主机上，那等于完全没有执行；而且封禁是"
                    "全有全无的，共享地址会被误伤。这个执行点把同一批决定"
                    "渲染成 nginx 的 deny 列表：Web 层直接返回 403，"
                    "并且可以当作文件阅读和审计。")
    ps = p.add_subparsers(dest="bouncer_action", metavar="<操作>")

    sp = ps.add_parser("install", help="接入 nginx（会加一行 include）")
    sp.add_argument("--yes", action="store_true", help="确实执行")
    sp.set_defaults(func=cmd_install)

    sp = ps.add_parser("uninstall", help="移除并还原 nginx 配置")
    sp.set_defaults(func=cmd_uninstall)

    sp = ps.add_parser("sync", help="按当前封禁列表重新生成并 reload")
    sp.add_argument("--dry-run", action="store_true", help="只看会写什么")
    sp.set_defaults(func=cmd_sync)

    sp = ps.add_parser("status", help="查看状态")
    sp.set_defaults(func=cmd_status)
