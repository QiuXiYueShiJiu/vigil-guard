"""Live status for the page: read, never write, and never guess.

Everything host-specific here is *discovered at runtime* -- hostname via the OS,
domain from the configured gate/nginx context. Nothing is compiled in, which is
the same rule the source audit enforces on the rest of the package.
"""
from __future__ import annotations

import json
import os
import platform
import socket
import time
from pathlib import Path

from ..core import paths


def _json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _jsonl_tail(path: Path, n: int = 200) -> list:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-n:]
    except OSError:
        return []
    out = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def _hostname() -> str:
    """Ask the OS. A hostname in the source would be one machine's, and this
    page runs on every machine that installs the package."""
    try:
        return socket.gethostname()
    except OSError:
        return platform.node() or ""


def _uptime_text(seconds: float) -> str:
    seconds = max(0, int(seconds))
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    if d:
        return "%d 天 %d 小时" % (d, h)
    if h:
        return "%d 小时 %d 分" % (h, m)
    return "%d 分" % m


def board(cfg=None) -> dict:
    """Everything the page shows, as plain data."""
    from ..version import __version__

    health = _json(paths.STATE_STATE / "health.json") or {}
    items = health.get("items") or []
    ok = sum(1 for i in items if i.get("status") == "ok")
    warn = sum(1 for i in items if i.get("status") == "warn")
    fail = sum(1 for i in items if i.get("status") == "fail")

    threat = _json(paths.STATE_STATE / "threat.json") or {}
    bans = threat.get("bans") or {}
    stats = threat.get("stats") or {}
    now = time.time()
    active = [ip for ip, b in bans.items()
              if float((b or {}).get("until") or 0) > now]

    hits = _jsonl_tail(paths.STATE_STATE / "decoy-hits.jsonl", 5000)
    hit_ips = {str(h.get("ip")) for h in hits if h.get("ip")}

    adopted = _json(paths.STATE_STATE / "evolve-adopted.json") or []
    ledger = _jsonl_tail(paths.STATE_STATE / "evolve-ledger.jsonl", 500)
    applied = [e for e in ledger if e.get("kind") == "applied"]

    try:
        up = float(Path("/proc/uptime").read_text().split()[0])
    except (OSError, ValueError, IndexError):
        up = 0.0

    def _mem():
        try:
            info = {}
            for line in Path("/proc/meminfo").read_text().splitlines():
                k, _, rest = line.partition(":")
                info[k.strip()] = int(rest.split()[0])
            total = info.get("MemTotal") or 0
            avail = info.get("MemAvailable") or 0
            if total:
                return "%.0f%% 可用（%.1f/%.1f GB）" % (
                    100.0 * avail / total, avail / 1048576.0, total / 1048576.0)
        except (OSError, ValueError, IndexError):
            pass
        return "—"

    return {
        "host": {
            "hostname": _hostname(),
            "subtitle": "本机实时状态 · vigil %s · %s" % (__version__, platform.system()),
        },
        "cards": [
            {"title": "运行时长", "value": _uptime_text(up) if up else "—"},
            {"title": "版本", "value": __version__},
            {"title": "检查通过", "value": "%d / %d" % (ok, len(items)),
             "cls": "ok" if not fail else "bad",
             "note": ("%d 项警告" % warn) if warn else ""},
            {"title": "当前封禁", "value": str(len(active)),
             "cls": "ok" if not active else "warn"},
            {"title": "诱饵命中", "value": str(len(hits)),
             "note": "%d 个独立来源" % len(hit_ips) if hits else ""},
            {"title": "累计封禁", "value": str(int(stats.get("bans_total") or 0))},
            {"title": "自修正改动", "value": str(len(applied)),
             "note": "%d 条已采纳诱饵" % len(adopted) if adopted else ""},
            {"title": "可用内存", "value": _mem()},
        ],
        "tables": [
            {"title": "最近的检查项", "rows": [
                (i.get("label") or i.get("key") or "?", i.get("detail") or "")
                for i in items[-12:]]},
            {"title": "最近的诱饵命中", "rows": [
                (time.strftime("%m-%d %H:%M", time.localtime(float(h.get("ts") or 0))),
                 h.get("uri") or "") for h in hits[-12:]][::-1]},
        ],
    }


def feedback_store() -> Path:
    return paths.STATE_STATE / "web-feedback.jsonl"


def add_feedback(cfg, text: str, source: str = "") -> dict:
    """Store a note, and put it in front of the operator.

    Goes through the same alert channel as everything else rather than sitting
    in a file only this page reads: a feedback box nobody is notified about is
    a box nobody reads.
    """
    text = (text or "").strip()[:2000]
    if not text:
        return {"ok": False, "err": "内容为空"}
    entry = {"ts": time.time(), "text": text, "from": (source or "")[:64]}
    try:
        p = feedback_store()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as e:
        return {"ok": False, "err": "写入失败：%s" % e}

    # 通知失败不能把反馈弄丢（它已经落盘了），但也不能不吭声：一个
    # 「提交成功」而维护者永远收不到的消息，比提交失败更糟 —— 使用者会
    # 以为已经有人知道了。
    try:
        from ..evolve import report as report_mod
        mailed = bool(report_mod.mail(cfg, "收到一条页面反馈",
                                      [text[:1500],
                                       "",
                                       "来源：%s" % (source or "（未记录）")],
                                      severity="info"))
    except Exception as e:                                     # noqa: BLE001
        return {"ok": True, "mailed": False,
                "warn": "已记录，但通知维护者失败：%s" % str(e)[:120]}
    return {"ok": True, "mailed": mailed}


def recent_feedback(limit: int = 20) -> list:
    out = []
    for e in _jsonl_tail(feedback_store(), limit)[::-1]:
        e = dict(e)
        e["at_text"] = time.strftime("%m-%d %H:%M",
                                     time.localtime(float(e.get("ts") or 0)))
        out.append(e)
    return out
