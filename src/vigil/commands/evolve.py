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
from ..evolve import train as train_mod
from ..evolve import corpus as corpus_mod


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


def cmd_train(args) -> int:
    cfg = load_config(args.config or None)
    ui.header("自修正：自我训练", "标签来自本机已经发生的处置结果，不需要人工标注")
    if args.bulk:
        res = train_mod.train_bulk(cfg, epochs=args.epochs)
        if not res.get("ok"):
            ui.failure(res.get("err", "批量训练未完成"))
            return 1
        ui.kv("语料规模", "%d 条（正 %d / 负 %d，含本机真实样本 %d）"
               % (res["corpus"], res["positives"], res["negatives"], res["host_samples"]))
        ui.kv("语料内准确率", "%.1f%%" % res["corpus_accuracy"])
        ui.out()
        ui.out(corpus_mod.format_novel(res["novel"]))
        return 0
    res = train_mod.train(cfg, epochs=args.epochs)
    if not res.get("ok"):
        ui.warning(res.get("err", "训练未完成"))
        ui.kv("正样本", res.get("positives", 0))
        ui.kv("负样本", res.get("negatives", 0))
        return 1
    ui.kv("训练样本", "%d 条（保留 %d 条做检验）" % (res["trained"], res["held_out"]))
    ui.kv("标签来源", "正 %d（命中诱饵 / 随后被封禁）｜负 %d（被正常服务）"
           % (res["positives"], res["negatives"]))
    ui.kv("训练集准确率", "%.1f%%" % res["accuracy_fit"])
    ui.kv("留出集准确率", "%.1f%%" % res["accuracy_holdout"])
    ui.kv("模型累计学习", "%d 次观测" % res["model_seen"])
    ui.out()
    ui.note("留出集是抽出来没参与训练的样本：只报训练集准确率等于自己给自己打分。")
    return 0


def cmd_novel(args) -> int:
    cfg = load_config(args.config or None)
    from ..evolve import corpus as corpus_mod
    from ..evolve import score as score_mod, train as train_mod
    ui.header("自修正：全新族类攻击测试",
              "这几个族类整族排除在训练之外，用它检验是泛化还是背诵")
    model = score_mod.Scorer.load(train_mod.MODEL)
    ui.out(corpus_mod.format_novel(corpus_mod.novel_attack_test(model)))
    ui.out()
    ui.note("注意对照组：只报「认出多少攻击」没有意义 —— 一个把所有请求都判成"
            "攻击的模型同样能拿到 100%。这里同时给出正常路径的均分与误报数。")
    return 0


def cmd_outcomes(args) -> int:
    cfg = load_config(args.config or None)
    ui.header("自修正：回看自己改过的东西", "没用的就撤掉，别让采纳表只增不减")
    ui.out(train_mod.format_outcomes(train_mod.outcomes(cfg)))
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

    sp = ps.add_parser("train", help="用本机处置结果自我训练（自监督，无需标注）")
    sp.add_argument("--epochs", type=int, default=15)
    sp.add_argument("--bulk", action="store_true",
                    help="用内置大语料训练，并报告对「从未见过的族类」的识别能力")
    sp.add_argument("--config")
    sp.set_defaults(func=cmd_train)

    sp = ps.add_parser("novel", help="用整族未见过的攻击测试泛化能力")
    sp.add_argument("--config")
    sp.set_defaults(func=cmd_novel)

    sp = ps.add_parser("outcomes", help="回看自己采纳的改动有没有用")
    sp.add_argument("--config")
    sp.set_defaults(func=cmd_outcomes)

    sp = ps.add_parser("watchdog", help="检查自修正循环是否异常")
    sp.add_argument("--config")
    sp.set_defaults(func=cmd_watchdog)
