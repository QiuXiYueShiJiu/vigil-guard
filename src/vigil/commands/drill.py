"""`vigil drill` -- attack this host from many sources and see what it does."""
from __future__ import annotations

from .. import ui
from ..core.config import load as load_config
from ..guards import drill as drill_mod


def cmd_plan(args) -> int:
    res = drill_mod.run(rounds=args.rounds, n_sources=args.sources,
                        per_source=args.per_source, dry_run=True,
                        target=args.target)
    ui.header("攻击演练 · 预演", "只生成计划，不发出任何流量")
    ui.out(drill_mod.format_report(res))
    ui.out()
    ui.note("计划里包含一个「对照」层：普通请求必须始终可用。"
            "没有对照，一个「什么都拒绝」的主机看起来会是最安全的。")
    return 0


def cmd_run(args) -> int:
    cfg = load_config(args.config or None)
    ui.header("攻击演练", "多来源 · 多层次 · 反复 · 跳跃式，仅对本机")
    ui.kv("来源", "%d 个（各自独立 /24）" % args.sources)
    ui.kv("轮次", "%d 轮 × 每来源 %d 次" % (args.rounds, args.per_source))
    ui.kv("护栏", "内存下限 %d MB，conntrack 上限 %.0f%%，%d 秒上限"
           % (drill_mod.MEM_FLOOR_MB, drill_mod.CONNTRACK_CEILING, args.seconds))
    ui.kv("停止", "touch %s" % drill_mod.STOP_FILE)
    ui.out()

    if not args.yes:
        ui.warning("演练会产生真实攻击流量，需要 --yes 确认")
        ui.hint("先看计划：vigil drill plan")
        return 2

    ui.note("开始…… 期间告警会正常发出，演练结束后自动补发清空队列。")
    res = drill_mod.run(cfg, rounds=args.rounds, n_sources=args.sources,
                        per_source=args.per_source, workers=args.workers,
                        target=args.target, deadline_seconds=args.seconds,
                        settle_seconds=args.settle, log=None)
    ui.out(drill_mod.format_report(res))
    ui.out()

    if not args.keep_bans:
        c2 = drill_mod.cleanup_lab_bans(cfg)
        ui.section("清理演练自身的封禁")
        ui.kv("已解除", "%d 个" % len(c2["removed"]))
        if c2.get("remaining"):
            ui.warning("仍被封禁（检测可能仍在追赶）：%s"
                       % "、".join(c2["remaining"]))
        else:
            ui.success("演练来源已全部解除封禁")

    # The drill provokes alerts on purpose, so it also clears them. Leaving a
    # backlog behind would mean the next real alert arrives behind a wall of
    # test noise.
    if args.drain:
        ui.section("清空邮件积压")
        d = drill_mod.drain_mail(cfg)
        ui.kv("已补发", "%d 封" % d["sent"])
        ui.kv("剩余积压", "%d 封" % d["remaining"])
        if d["remaining"]:
            ui.warning("仍有 %d 封未发出（可能触及配额上限，配额每日重置）"
                       % d["remaining"])
        else:
            ui.success("邮件队列已清空")
    return 0


def cmd_lab(args) -> int:
    if args.lab_action == "down":
        n = drill_mod.lab_down()
        ui.success("已清理 %d 个演练来源" % n)
        return 0
    srcs = drill_mod.lab_up(args.sources)
    ui.success("已建立 %d 个演练来源" % len(srcs))
    for s in srcs:
        ui.out("    %-16s %s  （%s）" % (s["name"], s["ip"], s["net24"]))
    ui.out()
    ui.hint("清理：vigil drill lab down")
    return 0


def register(sub) -> None:
    p = sub.add_parser(
        "drill", help="攻击演练：多来源多层次，仅对本机",
        description="从多个真实来源地址、用多种攻击形态、反复且跳跃地打本机，"
                    "然后报告防御到底做了什么。来源用网络命名空间建立，每个都在"
                    "自己的 /24 里，所以日志里看到的是真实且彼此独立的地址。"
                    "只允许对本机演练（目标必须是本机地址），并带停止文件、"
                    "内存下限、conntrack 上限与时间上限四道护栏。")
    ps = p.add_subparsers(dest="drill_action", metavar="<操作>")

    sp = ps.add_parser("plan", help="只生成计划，不发流量")
    sp.add_argument("--sources", type=int, default=8)
    sp.add_argument("--rounds", type=int, default=drill_mod.DEFAULT_ROUNDS)
    sp.add_argument("--per-source", type=int, default=3)
    sp.add_argument("--target", default="",
                    help="演练目标，默认取本机地址")
    sp.set_defaults(func=cmd_plan)

    sp = ps.add_parser("run", help="执行演练")
    sp.add_argument("--sources", type=int, default=8)
    sp.add_argument("--rounds", type=int, default=drill_mod.DEFAULT_ROUNDS)
    sp.add_argument("--per-source", type=int, default=3)
    sp.add_argument("--workers", type=int, default=16)
    sp.add_argument("--target", default="",
                    help="演练目标，默认取本机地址")
    sp.add_argument("--seconds", type=int, default=300)
    sp.add_argument("--settle", type=int, default=20,
                    help="结束后等待检测落地的秒数")
    sp.add_argument("--yes", action="store_true", help="确认执行")
    sp.add_argument("--drain", action="store_true", default=True,
                    help="结束后补发并清空邮件队列（默认开启）")
    sp.add_argument("--no-drain", dest="drain", action="store_false")
    sp.add_argument("--keep-bans", action="store_true",
                    help="保留演练来源的封禁（默认演练后自动解除）")
    sp.set_defaults(func=cmd_run)

    sp = ps.add_parser("lab", help="单独建立/清理演练来源")
    sp.add_argument("lab_action", nargs="?", default="up",
                    choices=["up", "down"])
    sp.add_argument("--sources", type=int, default=8)
    sp.set_defaults(func=cmd_lab)

    p.set_defaults(func=cmd_plan)
