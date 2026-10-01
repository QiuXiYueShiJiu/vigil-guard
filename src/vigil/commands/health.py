"""`vigil health` -- run and explain the inspection checks."""
from __future__ import annotations

import json as _json
import time

from .. import ui
from ..core.config import load as load_config
from ..core.errors import VigilError


def _framework():
    from ..guards.checks import base
    base.load_all()
    return base


def cmd_run(args) -> int:
    cfg = load_config(args.config or None)
    from ..guards import health
    ui.note("正在运行检查…")
    result = health.run_once(cfg, log=_log(), notify=not args.no_notify,
                             only=args.only.split(",") if args.only else None)
    if args.json:
        ui.out(_json.dumps(result, ensure_ascii=False, indent=2, default=str))
        return 0

    ui.header("巡检结果", result.get("when", ""))
    problems = result.get("problems") or []
    recoveries = result.get("recoveries") or []
    results = result.get("results") or {}

    if results:
        ui.section("全部检查项")
        rows = []
        for name, info in results.items():
            status = info.get("status", "?")
            rows.append(["%s %s" % (ui.status_badge(status), name),
                         status, (info.get("detail") or "")[:64]])
        ui.table(rows)

    ui.out()
    if problems:
        ui.section("异常明细")
        for p in problems:
            ui.warning("[%s] %s" % (p.get("status"), p.get("label")))
            for line in (p.get("detail") or "").split("\n"):
                ui.out("      " + line)
            if p.get("consequence"):
                ui.hint("可能后果: %s" % p["consequence"])
            if p.get("action"):
                ui.hint("建议处置: %s" % p["action"])
    if recoveries:
        ui.section("已恢复")
        for r in recoveries:
            ui.success(r)

    ui.out()
    if not problems:
        ui.success("全部正常（%d 项检查）" % len(results))
    else:
        ui.warning("发现 %d 项异常" % len(problems))
        if args.no_notify:
            ui.note("已指定 --no-notify，未发送告警邮件")
    return 1 if problems else 0


def cmd_list(args) -> int:
    base = _framework()
    checks = base.all_checks()
    if args.json:
        ui.out(_json.dumps(
            [{"id": c.id, "label": c.label, "group": c.group,
              "stateful": c.stateful, "description": c.description}
             for c in checks], ensure_ascii=False, indent=2))
        return 0
    ui.header("检查项", "共 %d 项" % len(checks))
    groups = base.by_group()
    for g in base.GROUP_ORDER:
        items = groups.get(g) or []
        if not items:
            continue
        ui.section(items[0].group_label())
        rows = []
        for c in items:
            rows.append([c.id, c.label, c.description or ""])
        ui.table(rows, headers=["ID", "名称", "检测内容"])
    ui.out()
    ui.note("只运行部分检查：vigil health run --only cpu,disk,watch_files")
    return 0


def cmd_explain(args) -> int:
    """Say what a finding means and what to do about it."""
    from ..guards import knowledge
    item = knowledge.explain(args.key)
    if not item:
        # Fall back to a check id -> description lookup.
        base = _framework()
        c = base.get(args.key)
        if c:
            ui.header(c.label)
            ui.kv("ID", c.id)
            ui.kv("分组", c.group_label())
            ui.kv("说明", c.description)
            ui.kv("有状态", "是" if c.stateful else "否")
            return 0
        ui.failure("没有找到与 %s 相关的说明" % args.key)
        ui.hint("运行 `vigil health list` 查看全部检查项 ID")
        return 1
    ui.header(item.get("title", args.key))
    for label in ("what", "why", "consequence", "action"):
        text = item.get(label)
        if text:
            ui.section({"what": "是什么", "why": "为什么会发生",
                        "consequence": "可能后果",
                        "action": "建议处置"}[label])
            for line in str(text).split("\n"):
                ui.out("  " + line)
    return 0


def cmd_ack(args) -> int:
    """Stop one finding from emailing, for a while.

    The alternative people actually use is turning the check off, which is
    permanent and silent. This is the reversible version: the finding keeps
    being detected, printed and recorded; only the email stops -- and it
    starts again by itself.
    """
    from ..guards import health as health_mod
    base = _framework()

    if args.list:
        state = health_mod.load_state()
        acks = health_mod.active_acks(state)
        if not acks:
            ui.note("当前没有处于静默期的检查项")
            return 0
        ui.header("静默中的检查项", "到期后自动恢复发信；检查本身仍在运行")
        rows = []
        for check_id, rec in sorted(acks.items()):
            left = max(0, int(rec.get("until", 0) - time.time()))
            c = base.get(check_id)
            rows.append(("%s %s" % (check_id, ("（%s）" % c.label) if c else ""),
                         "%s 后到期%s" % (_human(left),
                                          ("　" + rec["note"]) if rec.get("note") else "")))
        for left, right in rows:
            ui.kv(left, right)
        return 0

    check_id = (args.check or "").strip()
    if not check_id:
        ui.failure("请给出检查项 ID")
        ui.hint("运行 `vigil health list` 查看全部检查项 ID")
        return 1

    if args.clear:
        if health_mod.clear_ack(check_id):
            ui.success("已取消 %s 的静默，恢复正常发信" % check_id)
            return 0
        ui.note("%s 本来就不在静默中" % check_id)
        return 0

    if not base.get(check_id):
        ui.failure("没有这个检查项：%s" % check_id)
        return 1
    try:
        seconds = health_mod.parse_duration(args.for_)
    except ValueError as exc:
        ui.failure(str(exc))
        ui.hint("时长写法：30m / 2h / 7d / 900（秒）")
        return 1
    if seconds > health_mod.ACK_MAX_SECONDS:
        ui.failure("静默期最长 %d 天" % (health_mod.ACK_MAX_SECONDS // 86400))
        return 1

    rec = health_mod.add_ack(check_id, seconds, args.note or "")
    ui.success("已静默 %s 的邮件通知，%s 后自动恢复"
               % (check_id, _human(int(rec["until"] - time.time()))))
    ui.note("检查仍会运行、仍会记录，只是不再发邮件；"
            "`vigil health run` 与 `vigil status` 依旧会显示它")
    return 0


def _human(seconds: int) -> str:
    if seconds >= 86400:
        return "%.1f 天" % (seconds / 86400.0)
    if seconds >= 3600:
        return "%.1f 小时" % (seconds / 3600.0)
    return "%d 分钟" % max(1, seconds // 60)


def cmd_rebaseline(args) -> int:
    """Accept the current state as the new baseline.

    Needed because "the baseline changed" and "the baseline changed and I
    know why" are different facts, and only the operator can tell them
    apart. `vigil update` does this automatically for its own files.
    """
    from ..guards import health as health_mod
    base = _framework()
    ids = [i.strip() for i in str(args.check or "").split(",") if i.strip()]
    if not ids:
        ui.failure("请给出要重建基线的检查项 ID")
        ui.hint("运行 `vigil health list` 查看全部检查项 ID")
        return 1
    unknown = [i for i in ids if not base.get(i)]
    if unknown:
        ui.failure("没有这个检查项：%s" % "、".join(unknown))
        return 1
    done = 0
    for check_id in ids:
        if health_mod.rebaseline(check_id, _log()):
            ui.success("已重建 %s 的基线，下次巡检不会再报这次的变化" % check_id)
            done += 1
        else:
            ui.note("%s 目前没有存过基线（下次巡检会自动建立）" % check_id)
    return 0 if done or ids else 1


def _log():
    from ..core import logging as vlog
    return vlog.get("health")


def register(sub) -> None:
    p = sub.add_parser("health", help="安全巡检：运行检查、查看检查项与说明",
                       description="对服务器做全面检查：资源、文件完整性、"
                                   "可疑进程、WebShell、权限、服务、证书等。")
    ps = p.add_subparsers(dest="health_action", metavar="<操作>")

    sp = ps.add_parser("run", help="立即运行一次巡检")
    sp.add_argument("--only", default="", help="只运行指定检查（ID，逗号分隔）")
    sp.add_argument("--no-notify", action="store_true", help="不发送告警邮件")
    sp.set_defaults(func=cmd_run)

    sp = ps.add_parser("list", help="列出全部检查项")
    sp.set_defaults(func=cmd_list)

    sp = ps.add_parser("explain", help="解释某项检查或异常的含义")
    sp.add_argument("key", help="检查项 ID 或名称")
    sp.set_defaults(func=cmd_explain)

    sp = ps.add_parser("rebaseline",
                       help="把当前状态接受为新基线（确认某次变更无害后）")
    sp.add_argument("check", help="检查项 ID，逗号分隔（如 self_integrity,watch_files）")
    sp.set_defaults(func=cmd_rebaseline)

    sp = ps.add_parser("ack",
                       help="静默某个检查项的邮件通知（检查本身照常运行）")
    sp.add_argument("check", nargs="?", default="",
                    help="检查项 ID（--list 时可不填）")
    sp.add_argument("--for", dest="for_", default="24h",
                    help="静默时长：30m / 2h / 7d / 900，默认 24h")
    sp.add_argument("--note", default="", help="记一句为什么静默它")
    sp.add_argument("--list", action="store_true", help="列出当前静默中的检查项")
    sp.add_argument("--clear", action="store_true", help="取消静默，立即恢复发信")
    sp.set_defaults(func=cmd_ack)
