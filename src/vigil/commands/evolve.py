"""`vigil evolve` -- bounded self-improvement, and the watchdog that watches it.

The command surface is deliberately the same shape as every other part of this
program: look first (`status`, `scan`, `plan`), then change (`apply`), with the
undo (`rollback`) sitting next to the do.
"""
from __future__ import annotations

from .. import ui
from ..core.config import load as load_config
from ..evolve import (adopted, apply as evolve_apply, format_status,
                      format_watchdog, ledger, loop, plan, rollback, scan,
                      status, watchdog)


def cmd_status(args) -> int:
    cfg = load_config(args.config or None)
    st = status(cfg)
    ui.header("自修正循环", "读本机真实流量，做有边界、可回滚的小改动")
    ui.out(format_status(st))
    ui.out()
    items = st["adopted"]
    if items:
        ui.kv("最近采纳", "%d 条" % len(items))
        for e in items[-8:]:
            ui.out("    %s  ← %s" % (e.get("path"), (e.get("why") or "")[:56]))
    ui.out()
    ui.note("它只能自动采纳「诱饵路径」这类行为数据；改源码必须显式开启 "
            "evolve.allow_code_edits，并且每次都会先发邮件、留备份、跑测试，"
            "测试不过就自动还原。")
    if not st["enabled"]:
        ui.hint("启用：vigil config set evolve.enabled true")
    return 0


def cmd_scan(args) -> int:
    cfg = load_config(args.config or None)
    ev = scan(cfg)
    ui.header("自修正：证据", "只看事实，不做任何改动")
    ui.kv("已读取观测", "%d 条" % ev["observed"])
    ui.kv("已知诱饵", "%d 条" % ev["known"])
    ui.kv("证据门槛", "≥%d 次且 ≥%d 个独立来源" % (ev["min_hits"], ev["min_ips"]))
    ui.out()
    if not ev["candidates"]:
        ui.out("没有满足门槛的新路径。")
        return 0
    ui.out("满足门槛的候选（%d 条）：" % len(ev["candidates"]))
    for c in ev["candidates"][:20]:
        ui.out("    %-42s %4d 次 / %2d 来源  模型分 %.2f%s"
               % (c["path"], c["hits"], c["ips"], c["score"],
                  "  ← 名字像探测" if c["probe_like"] else ""))
    return 0


def cmd_plan(args) -> int:
    cfg = load_config(args.config or None)
    p = plan(cfg)
    ui.header("自修正：计划", "将要做什么，以及为什么")
    props = p["proposals"]
    if not props:
        ui.out("没有要执行的改动。")
        return 0
    for x in props:
        ui.out("  · %s" % x["title"])
        ui.out("      依据：%s" % x["why"])
        ui.out("      会先发邮件告知，改完写台账，可用 evolve rollback %s 撤销" % x["id"])
    ui.out()
    ui.hint("执行：vigil evolve apply --all   （预演加 --dry-run）")
    return 0


def cmd_apply(args) -> int:
    cfg = load_config(args.config or None)
    ui.header("自修正：执行", "改前发邮件，改后留台账，随时可回滚")
    props = plan(cfg)["proposals"]
    if args.id:
        props = [p for p in props if p["id"] == args.id]
    elif not args.all:
        ui.failure("要么给 --id，要么给 --all")
        return 2
    if not props:
        ui.out("没有匹配的提案。")
        return 0
    bad = 0
    for x in props:
        res = evolve_apply(cfg, x, dry_run=args.dry_run)
        if res.get("ok"):
            ui.success("%s%s" % (x["title"], "（预演，未写入）" if args.dry_run else ""))
            if res.get("code"):
                ui.out("      源码：%s" % res["code"])
            if not args.dry_run:
                ui.out("      邮件：%s" % ("已发出" if res.get("mailed") else "未发出（检查邮件配置）"))
        else:
            bad += 1
            ui.warning("%s 未执行：%s" % (x["title"], res.get("err")))
    return 1 if bad else 0


def cmd_rollback(args) -> int:
    cfg = load_config(args.config or None)
    res = rollback(cfg, args.id)
    (ui.success if res.get("ok") else ui.failure)(
        ("已撤销 %s，剩余 %d 条" % (args.id, res.get("remaining", 0)))
        if res.get("ok") else res.get("err", "失败"))
    if res.get("ok"):
        ui.note("源码层的改动请用 git 复核：cd 源码树 && git diff")
    return 0 if res.get("ok") else 1


def cmd_loop(args) -> int:
    cfg = load_config(args.config or None)
    if not bool(cfg.get("evolve.enabled", False)) and not args.force:
        ui.note("自修正循环未启用（evolve.enabled=false），本次不做任何改动。")
        ui.hint("启用：vigil config set evolve.enabled true")
        return 0
    res = loop(cfg, max_rounds=args.max_rounds)
    if res.get("skipped"):
        ui.note("本次未开工：%s" % res["skipped"])
        return 0
    ui.header("自修正：一轮结束")
    ui.kv("观测样本", "%d 条" % res["evidence"]["observed"])
    ui.kv("执行改动", "%d 条" % len(res["applied"]))
    ui.kv("未执行", "%d 条" % len(res["failed"]))
    ui.kv("上报", "成功" if res["report"].get("ok") else
           "失败（%s）" % res["report"].get("err", res["report"].get("status", "?")))
    return 0


def cmd_watchdog(args) -> int:
    cfg = load_config(args.config or None)
    res = watchdog(cfg)
    ui.header("自修正监控", "看着那个会改自己的进程")
    ui.out(format_watchdog(res))
    return 0 if res["ok"] else 1


def register(sub) -> None:
    p = sub.add_parser(
        "evolve", help="自修正：有边界地改进自己，并监控它",
        description="读本机真实流量，采纳新的诱饵路径；改源码必须显式开启，"
                    "且每次先发邮件、留备份、跑测试，测试不过自动还原。"
                    "所有改动写入只增台账，可逐条回滚。")
    ps = p.add_subparsers(dest="evolve_action", metavar="<操作>")

    sp = ps.add_parser("status", help="当前状态、已采纳的改动与资源预算")
    sp.add_argument("--config")
    sp.set_defaults(func=cmd_status)

    sp = ps.add_parser("scan", help="只看证据，不改任何东西")
    sp.add_argument("--config")
    sp.set_defaults(func=cmd_scan)

    sp = ps.add_parser("plan", help="列出将要做的改动及依据")
    sp.add_argument("--config")
    sp.set_defaults(func=cmd_plan)

    sp = ps.add_parser("apply", help="执行改动（改前发邮件）")
    sp.add_argument("--id", help="只执行这一条")
    sp.add_argument("--all", action="store_true", help="执行全部提案")
    sp.add_argument("--dry-run", action="store_true", help="预演，不写入")
    sp.add_argument("--config")
    sp.set_defaults(func=cmd_apply)

    sp = ps.add_parser("rollback", help="撤销一条已采纳的改动")
    sp.add_argument("id")
    sp.add_argument("--config")
    sp.set_defaults(func=cmd_rollback)

    sp = ps.add_parser("loop", help="跑一轮完整的自修正（供定时器调用）")
    sp.add_argument("--max-rounds", type=int, default=6)
    sp.add_argument("--force", action="store_true", help="即使未启用电也跑（仅调试）")
    sp.add_argument("--config")
    sp.set_defaults(func=cmd_loop)

    sp = ps.add_parser("watchdog", help="检查自修正循环是否异常")
    sp.add_argument("--config")
    sp.set_defaults(func=cmd_watchdog)
