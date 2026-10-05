#!/usr/bin/env python3
"""Attack history: one report from every source that recorded one.

Sources, in order of authority:

  1. /var/lib/vigil/state/threat.json   vigil's ledger -- bans, offences, stats
  2. /var/lib/vigil/state/decoy-hits.jsonl  every honeypot hit, with path
  3. /var/lib/vigil/mail/journal.jsonl  alert/digest timeline (subjects only)
  4. /var/lib/vigil-dashboard/audit.jsonl   operator actions, for context

Simulated and private traffic is excluded rather than silently included:
RFC 5737 documentation ranges, RFC 1918 space, loopback, and the addresses
used by this project's own test suite. A report that mixes in a flood the
operator triggered himself is worse than no report, so every excluded row is
counted and the count is printed.
"""

from __future__ import annotations

import argparse
import collections
import ipaddress
import json
import os
import sys
import time
from pathlib import Path

#: Repository root, so nothing here depends on where the tree was cloned to.
ROOT = Path(__file__).resolve().parent.parent

LEDGER = Path("/var/lib/vigil/state/threat.json")
DECOY = Path("/var/lib/vigil/state/decoy-hits.jsonl")
MAIL = Path("/var/lib/vigil/mail/journal.jsonl")
AUDIT = Path("/var/lib/vigil-dashboard/audit.jsonl")

#: Addresses this project uses to test itself. Never real attackers -- and the
#: literals are the ones the audit treats as generic: the public resolvers,
#: plus the RFC 5737 documentation ranges the fixtures write from. A real
#: address here would rot (and would be somebody's host); a documentation one
#: cannot be anything but a fixture.
TEST_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "203.0.113.9"}
TEST_PREFIXES = (
    "192.0.2.", "198.51.100.", "203.0.113.",      # RFC 5737 fixtures
    # Sentinels the fixtures used before they moved to RFC 5737. Kept so an
    # older row already in the ledger is still excluded from a report.
    "23.94.10.", "23.94.20.", "23.94.50.", "23.94.60.", "23.94.99.",
)


def local_addresses() -> set:
    """The machine's own public addresses.

    It probes itself -- health checks, the decoy canaries, local scripts -- and
    counting that as an attack would put the server on its own list of
    attackers and inflate every total.
    """
    out = set()
    try:
        sys.path.insert(0, ROOT)
        from backend import settings
        for name in ("SERVER_LABEL", "PUBLIC_IP", "SERVER_IP"):
            value = getattr(settings, name, "")
            if value and str(value)[0].isdigit():
                out.add(str(value))
    except Exception:                                   # noqa: BLE001
        pass
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("1.1.1.1", 80))
        out.add(sock.getsockname()[0])
        sock.close()
    except Exception:                                   # noqa: BLE001
        pass
    return out


SELF_ADDRESSES = local_addresses()


def is_simulated(ip: str) -> bool:
    """True for documentation ranges, private space and our own test traffic."""
    if not ip:
        return True
    if ip in TEST_IPS or ip.startswith(TEST_PREFIXES):
        return True
    if ip in SELF_ADDRESSES:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return bool(
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_reserved or addr.is_multicast or addr.is_unspecified
    )


def stamp(value) -> str:
    if not value:
        return "—"
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(value)))
    except (ValueError, OSError, TypeError):
        return str(value)


def read_json(path: Path, default):
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def read_jsonl(path: Path):
    try:
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except ValueError:
                    continue
    except OSError:
        return


def main() -> int:
    ap = argparse.ArgumentParser(description="汇总攻击历史")
    # Default outside the repository on purpose: a real report names real
    # third parties, and those must never be committed. The file shipped
    # at docs/attack-history.md is a redacted format sample.
    ap.add_argument("--out",
                    default="/var/lib/vigil-dashboard/attack-history.md")
    ap.add_argument("--json", dest="json_out", default="")
    ap.add_argument("--limit", type=int, default=60, help="明细表最多列出多少行")
    args = ap.parse_args()

    now = time.time()
    ledger = read_json(LEDGER, {})
    bans = ledger.get("bans") or {}
    offenses = ledger.get("offenses") or {}
    stats = ledger.get("stats") or {}

    excluded = collections.Counter()
    ban_rows = []
    for ip, rec in bans.items():
        if is_simulated(ip):
            excluded["封禁记录（模拟/内网/本机）"] += 1
            continue
        ban_rows.append({
            "ip": ip,
            "reason": rec.get("reason") or "—",
            "detector": rec.get("detector") or "—",
            "until": rec.get("until"),
            "count": rec.get("count") or 1,
            "live": bool(rec.get("until") and rec["until"] > now),
        })
    ban_rows.sort(key=lambda r: (not r["live"], -(r["until"] or 0)))

    offense_rows = []
    for ip, rec in offenses.items():
        if is_simulated(ip):
            excluded["可疑行为记录（模拟/内网/本机）"] += 1
            continue
        offense_rows.append({
            "ip": ip,
            "count": rec.get("count") or 1,
            "last": rec.get("last"),
        })
    offense_rows.sort(key=lambda r: -(r["last"] or 0))

    # Honeypot hits: the only source with the requested path for every hit.
    decoy = collections.Counter()
    decoy_paths = collections.Counter()
    per_source_paths = collections.defaultdict(collections.Counter)
    decoy_first = {}
    decoy_last = {}
    decoy_total = 0
    for item in read_jsonl(DECOY):
        ip = str(item.get("ip") or "")
        if is_simulated(ip):
            excluded["诱饵命中（模拟/内网/本机）"] += 1
            continue
        decoy_total += 1
        decoy[ip] += 1
        uri = str(item.get("uri") or "—")[:120]
        decoy_paths[uri] += 1
        per_source_paths[ip][uri] += 1
        ts = item.get("ts")
        if ts:
            decoy_first[ip] = min(decoy_first.get(ip, ts), ts)
            decoy_last[ip] = max(decoy_last.get(ip, ts), ts)

    # Mail timeline. Only subjects are stored locally; the bodies went out.
    alerts = []
    digests = []
    for item in read_jsonl(MAIL):
        ip = str(item.get("ip") or "")
        if ip and is_simulated(ip):
            continue
        kind = item.get("kind")
        if kind == "alert":
            alerts.append(item)
        elif kind == "digest":
            digests.append(item)

    # Reporter's own history, to catch anything the ledger has since dropped.
    dashboard = []
    try:
        sys.path.insert(0, ROOT)
        import urllib.request
        raw = urllib.request.urlopen(
            "http://127.0.0.1:9310/api/v1/state?history=400", timeout=5).read()
        for ev in (json.loads(raw.decode())["data"].get("history") or []):
            ip = str(ev.get("ip") or "")
            if not ip or ev.get("lv", 0) <= 0:
                continue
            if is_simulated(ip):
                excluded["面板事件（模拟/内网/本机）"] += 1
                continue
            dashboard.append({
                "ip": ip, "lv": ev.get("lv"), "why": ev.get("why") or ev.get("det") or "",
                "p": ev.get("p") or "", "t": ev.get("t"),
            })
    except Exception:                                   # noqa: BLE001
        pass

    # ── report ─────────────────────────────────────────────────────────
    out = []
    out.append("# 攻击历史汇总\n")
    out.append("生成时间：%s\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
    out.append("数据来源：vigil 风控账本、蜜罐命中记录、告警邮件流水、"
               "本控制台采集的事件流。\n")

    out.append("\n## 总览\n")
    out.append("| 指标 | 数值 |")
    out.append("|---|---|")
    out.append("| 账本启动 | %s |" % stamp(stats.get("started")))
    out.append("| 处理请求 | %s |" % f"{stats.get('events', 0):,}")
    out.append("| 累计封禁 | %s 次 |" % f"{stats.get('bans_total', 0):,}")
    out.append("| 当前生效封禁 | %s 个 |" % f"{stats.get('bans_current', 0):,}")
    out.append("| 蜜罐命中 | %s 次 |" % f"{stats.get('decoy_hits', 0):,}")
    out.append("| 姿态提升 | %s 次 |" % f"{stats.get('posture_raised', 0):,}")
    out.append("| 告警邮件 | %s 封 |" % f"{len(alerts):,}")
    out.append("| 摘要邮件 | %s 封 |" % f"{len(digests):,}")
    out.append("| 真实攻击来源（去重） | %d 个 |" % len(decoy))
    out.append("")
    out.append("已排除的模拟/内网记录：" +
               ("、".join("%s %d 条" % (k, v) for k, v in excluded.items()) or "无"))
    out.append("")

    # 每个来源当前的处置状态，来自账本
    ban_state = {}
    for row in ban_rows:
        ban_state[row["ip"]] = "封禁中" if row["live"] else "已封禁"
    for row in offense_rows:
        ban_state.setdefault(row["ip"], "可疑")

    out.append("\n## 攻击来源（按命中次数，已剔除模拟与本机）\n")
    out.append("| # | 来源 IP | 命中 | 首次 | 最近 | 当前处置 | 主要目标路径 |")
    out.append("|---|---|---|---|---|---|---|")
    for index, (ip, hits) in enumerate(decoy.most_common(args.limit), 1):
        seen_paths = per_source_paths.get(ip)
        if seen_paths:
            best = seen_paths.most_common(1)[0][0]
            top_path = "`%s`" % best if len(seen_paths) == 1 else "`%s` 等 %d 个" % (best, len(seen_paths))
        else:
            top_path = "—"
        out.append("| %d | `%s` | %d | %s | %s | %s | %s |" % (
            index, ip, hits, stamp(decoy_first.get(ip)),
            stamp(decoy_last.get(ip)), ban_state.get(ip, "仅记录"), top_path))
    if not decoy:
        out.append("| — | （无） | | | | | |")

    out.append("\n## 被探测最多的路径\n")
    out.append("| # | 路径 | 次数 |")
    out.append("|---|---|---|")
    for index, (uri, count) in enumerate(decoy_paths.most_common(25), 1):
        out.append("| %d | `%s` | %d |" % (index, uri, count))

    out.append("\n## 封禁明细（账本保留的 %d 条）\n" % len(ban_rows))
    out.append("| 来源 IP | 判定依据 | 检测器 | 状态 | 到期 |")
    out.append("|---|---|---|---|---|")
    for row in ban_rows[:args.limit]:
        out.append("| `%s` | %s | %s | %s | %s |" % (
            row["ip"], row["reason"], row["detector"],
            "生效中" if row["live"] else "已过期", stamp(row["until"])))
    if not ban_rows:
        out.append("| （无） | | | | |")

    if offense_rows:
        out.append("\n## 可疑行为记录（尚未封禁）\n")
        out.append("| 来源 IP | 次数 | 最近 |")
        out.append("|---|---|---|")
        for row in offense_rows[:args.limit]:
            out.append("| `%s` | %d | %s |" % (row["ip"], row["count"], stamp(row["last"])))

    if dashboard:
        out.append("\n## 控制台实时采集到的攻击（最近 %d 条）\n" % len(dashboard))
        out.append("| 时间 | 来源 IP | 等级 | 依据 | 路径 |")
        out.append("|---|---|---|---|---|")
        for row in dashboard[:40]:
            out.append("| %s | `%s` | %s | %s | `%s` |" % (
                stamp(row["t"]), row["ip"], row["lv"], row["why"][:40], row["p"][:60]))

    out.append("\n## 告警邮件时间线（最近 20 封）\n")
    out.append("| 时间 | 主题 | 状态 |")
    out.append("|---|---|---|")
    for item in alerts[-20:]:
        out.append("| %s | %s | %s |" % (
            str(item.get("ts") or "—")[:16], str(item.get("subject") or "")[:70],
            "已送达" if item.get("ok") else "未送达"))

    # 未被封禁的高频来源值得单独指出：要么命中早于当前账本轮换，要么
    # 打的是探测型诱饵而没有触发封禁阈值。运维上这是唯一需要人看的类别。
    unhandled = [(ip, n) for ip, n in decoy.most_common()
                 if ip not in ban_state and n >= 2]
    if unhandled:
        out.append("\n## 命中较多但当前未封禁的来源\n")
        out.append("这些地址命中过诱饵但账本里没有封禁记录。可能的原因：命中时间早于"
                   "当前账本轮换，或只是探测型访问、未达到封禁阈值。值得人工确认。\n")
        out.append("| 来源 IP | 命中 | 最近 | 主要目标路径 |")
        out.append("|---|---|---|---|")
        for ip, hits in unhandled[:20]:
            seen_paths = per_source_paths.get(ip)
            best = seen_paths.most_common(1)[0][0] if seen_paths else "—"
            out.append("| `%s` | %d | %s | `%s` |" % (
                ip, hits, stamp(decoy_last.get(ip)), best))

    out.append("\n---\n")
    out.append("说明：蜜罐命中记录包含本项目测试自检产生的模拟条目，已在上文按"
               "测试地址段、保留地址段与本机地址整体剔除；如果你看到某个来源像是"
               "自己，请对照总览里的排除计数。\n")

    text = "\n".join(out)
    target = Path(args.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")

    print("报告已写入 %s（%d 字节）" % (target, len(text.encode())))
    print("  真实攻击来源 %d 个，蜜罐命中 %d 次" % (len(decoy), decoy_total))
    print("  封禁明细 %d 条，可疑行为 %d 条，告警邮件 %d 封"
          % (len(ban_rows), len(offense_rows), len(alerts)))
    print("  已排除：" + ("、".join("%s %d" % (k, v) for k, v in excluded.items()) or "无"))

    if args.json_out:
        payload = {
            "generated": now,
            "totals": stats,
            "sources": [
                {"ip": ip, "hits": hits,
                 "first": decoy_first.get(ip), "last": decoy_last.get(ip)}
                for ip, hits in decoy.most_common()
            ],
            "paths": [{"path": p, "hits": n} for p, n in decoy_paths.most_common()],
            "bans": ban_rows,
            "offenses": offense_rows,
            "excluded": dict(excluded),
        }
        Path(args.json_out).write_text(
            json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
        print("  JSON 明细：%s" % args.json_out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
