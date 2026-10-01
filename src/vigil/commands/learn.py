"""`vigil learn` -- what the program worked out on its own, and what it did not.

The interesting part of this command is not the mining, it is the boundary.
Automatic adoption happens only where a mistake is additive and reversible
(a new decoy endpoint). Everything that would change what gets *blocked* is
written down as a suggestion and waits for a human. This command exists so
that boundary is visible rather than buried in a docstring.
"""
from __future__ import annotations

from .. import ui
from ..core.config import load as load_config
from ..core.state import read_json
from ..guards import learning as lmod


def cmd_report(args) -> int:
    cfg = load_config(args.config or None)
    data = read_json(lmod.learned_path(), {}) or {}
    suggestions = read_json(lmod.suggestions_path(), {}) or {}
    observations = lmod.read_observations()

    ui.header("自学习", "从真实流量里找新特征，但只自动采纳不会造成伤害的那一类")

    if args.json:
        import json
        ui.out(json.dumps({
            "observations": len(observations),
            "adopted": data,
            "suggestions": (suggestions or {}).get("items", []),
        }, ensure_ascii=False, indent=2, default=str))
        return 0

    ui.kv("已观察请求", "%d 条" % len(observations))
    ui.kv("已自动采纳的诱饵", "%d 个" % len(data))
    ui.kv("待人工确认的建议", "%d 条" % len((suggestions or {}).get("items") or []))
    ui.out()

    if data:
        ui.section("已自动采纳（新增诱饵端点 —— 可加可撤）")
        for token, rec in sorted(data.items()):
            ui.kv(token, "置信度 %s，%s 个独立来源"
                  % (rec.get("confidence", "?"), rec.get("distinct_ips", "?")))
        ui.out()
        ui.note("下一步：vigil decoy install —— 把新候选经过安全检查后写进 nginx")

    items = (suggestions or {}).get("items") or []
    if items:
        ui.section("建议（不会自动执行）")
        for item in items[:20]:
            ui.out("    %-28s %s" % (item.get("token", "?"),
                                     item.get("reason", "")))
        if len(items) > 20:
            ui.out("    …… 另有 %d 条" % (len(items) - 20))
        ui.out()
        ui.note("为什么这些不自动执行：它们会改变「封禁谁」，而一个错误的封禁"
                "签名会在防火墙上挡掉真实用户 —— 那是运维来告诉你的，不是你"
                "自己发现的。诱饵不在此列：加错了最坏是多一个没人访问的路径。")

    if not data and not items:
        ui.note("还没有足够证据。需要同一路径被多个独立来源请求，"
                "且从未被成功访问过。")
    return 0


def cmd_run(args) -> int:
    cfg = load_config(args.config or None)
    result = lmod.run(cfg, adopt=not args.no_adopt)
    ui.header("运行自学习", "挖掘 → 用合法流量做误报门控 → 只采纳安全的那一类")
    ui.kv("观察样本", result.get("observed", 0))
    ui.kv("候选特征", result.get("candidates", 0))
    ui.kv("合法流量语料", "%d 条（用于排除误报）" % result.get("legit_corpus", 0))
    ui.kv("通过门控", result.get("adoptable", 0))
    ui.kv("仅建议", result.get("suggestions", 0))
    adopted = result.get("adopted") or []
    if adopted:
        ui.success("已采纳为诱饵候选：%s" % "、".join(adopted[:8]))
        ui.hint("写入 nginx：vigil decoy install")
    else:
        ui.note("本次没有可自动采纳的候选")
    return 0


def cmd_why(args) -> int:
    """Explain a verdict, including a refusal."""
    cfg = load_config(args.config or None)
    token = args.token
    webroot = ""
    try:
        from ..guards import decoy
        _d, webroot = decoy._site(cfg)
    except (ImportError, OSError):
        webroot = ""
    legit = lmod.legitimate_corpus(cfg)
    candidates = {c["token"]: c for c in lmod.mine()}
    candidate = candidates.get(token)
    if candidate is None:
        ui.note("%s 不在当前候选中（可能独立来源不足 %d 个）"
                % (token, lmod.MIN_DISTINCT))
        return 0
    verdict = lmod.evaluate(candidate, legit, webroot)
    ui.header(token)
    ui.kv("独立来源", verdict.get("distinct_ips"))
    ui.kv("曾被成功访问", verdict.get("served_ok"))
    ui.kv("404/403 次数", verdict.get("not_found"))
    ui.kv("结论", verdict.get("verdict"))
    ui.kv("置信度", verdict.get("confidence"))
    ui.kv("原因", verdict.get("reason"))
    return 0


def register(sub) -> None:
    p = sub.add_parser(
        "learn", help="自学习：从真实观测里挖掘新特征（带误报门控）",
        description="从观察到的请求中挖掘候选特征，先用「服务器真的成功服务过"
                    "的路径」和站点自身内容做误报门控，再按置信度决定是否采纳。"
                    "自动采纳仅限诱饵候选；任何会改变封禁行为的特征只写为建议，"
                    "等待人工确认。")
    ps = p.add_subparsers(dest="learn_action", metavar="<操作>")

    sp = ps.add_parser("report", help="已采纳的与仅建议的分别列出")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_report)

    sp = ps.add_parser("run", help="立即挖掘一次")
    sp.add_argument("--no-adopt", action="store_true",
                    help="只评估，不写入任何候选")
    sp.set_defaults(func=cmd_run)

    sp = ps.add_parser("why", help="解释某个候选为什么被采纳或被拒")
    sp.add_argument("token", help="候选特征，例如 /wp-content")
    sp.set_defaults(func=cmd_why)
