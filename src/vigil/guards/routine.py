"""跨进程的例行事件暂存。

为什么需要它：``loadshed`` 是**独立进程**，没法把事件交给 ``threatd``
进程内的 reporter。它原先直接调 ``send_alert()`` —— 那是当时唯一能发的
路径，代价是这些告警**完全绕过**了合并、去重窗口和共享的每日额度。

在一台在线机器上实测：594 封已送达邮件里 **130 封（22%）** 是负载保护的开/
关，而且它们反复横跳（67 次开、63 次关），一封都没受过去重约束。同一批数据
里"已自动封禁 N 个攻击源"占 261 封，其中 247 封只含 1 个攻击源 —— 收件箱就是
这样被淹掉的，而真正需要立刻知道的（封禁失败、熔断、白名单命中）反而混在
里面看不见。

例行事件现在写到这里，由 ``threatd`` 的 reporter 线程排空，走和其它事件完全
相同的摘要路径。这份文件有上界：丢一条例行事件可以接受，无界增长不可以。
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from ..core import paths

#: 最多保留多少条。一次负载保护横跳产生两条，这个量级够容纳最坏观测到的
#: 速率下很多天的事件。
MAX_LINES = 500

_FILE = "routine-events.jsonl"


def path() -> Path:
    """Spool location, resolved on each call so tests can redirect it."""
    return paths.STATE_STATE / _FILE


def spool(record: dict) -> bool:
    """Append one routine event.

    Never raises: a routine event that cannot be written must not take down
    the guard that produced it. Losing one is survivable; crashing the
    load-shedder is not.
    """
    try:
        line = json.dumps(record, ensure_ascii=False, sort_keys=True)
        target = path()
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        _trim(target)
        return True
    except (OSError, TypeError, ValueError):
        return False


def drain() -> list:
    """Take everything spooled so far, and clear it.

    Read-and-clear so an event is reported exactly once. The unlink happens
    before parsing: a record we cannot parse is still a record we have taken
    responsibility for, and re-reading it forever would be worse than
    dropping it.
    """
    target = path()
    try:
        with open(target, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return []
    try:
        os.unlink(target)
    except OSError:
        pass

    out = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict):
            out.append(record)
    return out


def _trim(target: Path) -> None:
    """Keep the newest ``MAX_LINES`` lines."""
    try:
        with open(target, "r", encoding="utf-8", errors="replace") as fh:
            lines = [l for l in fh.read().splitlines() if l.strip()]
    except OSError:
        return
    if len(lines) <= MAX_LINES:
        return
    tmp = target.with_name(target.name + ".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines[-MAX_LINES:]) + "\n")
        os.replace(tmp, target)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
