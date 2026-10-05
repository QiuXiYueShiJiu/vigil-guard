"""Append-only audit trail for everything the console changes.

Every mutation goes through here: site switches, file writes, deletions,
uploads, logins, logouts. One JSON object per line so the file can be read
with ``tail`` while the console is running, which is the whole point -- when
something went wrong at 03:00, you want a flat file, not a query.
"""
from __future__ import annotations

import json
import os
import threading
import time

from . import settings

_lock = threading.Lock()
_MAX_BYTES = 8 * 1024 * 1024


def _rotate(path: str) -> None:
    try:
        if os.path.getsize(path) < _MAX_BYTES:
            return
        os.replace(path, path + ".1")
    except OSError:
        pass


def record(action: str, actor: str = "", ip: str = "", target: str = "",
           ok: bool = True, detail: str = "", extra: dict = None) -> None:
    settings.ensure_state_dir()
    line = {
        "t": round(time.time(), 3),
        "at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "actor": actor or "-",
        "ip": ip or "-",
        "target": target or "",
        "ok": bool(ok),
        "detail": (detail or "")[:600],
    }
    if extra:
        line["extra"] = extra
    blob = json.dumps(line, ensure_ascii=False)
    with _lock:
        _rotate(str(settings.AUDIT_LOG))
        try:
            with open(settings.AUDIT_LOG, "a", encoding="utf-8") as fh:
                fh.write(blob + "\n")
        except OSError:
            pass


def tail(limit: int = 200) -> list:
    path = str(settings.AUDIT_LOG)
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return out
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    out.reverse()
    return out
