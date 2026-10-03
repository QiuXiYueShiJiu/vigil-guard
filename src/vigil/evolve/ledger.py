"""Append-only ledger, and the backups that make every change reversible.

The rule this file exists to enforce: **nothing is changed before it is written
down**. An entry is appended first (with the before/after and the evidence),
then the change is attempted, then the outcome is appended. If the process dies
mid-change, the ledger still says what was being attempted, which is the case
that matters when you come back to a host that is behaving oddly.

Every file-level change is preceded by a backup, so `vigil evolve rollback`
is a real operation and not a promise.
"""
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

from ..core import paths

LEDGER = paths.STATE_STATE / "evolve-ledger.jsonl"
BACKUP_DIR = paths.STATE_STATE / "evolve-backup"

#: Keep the ledger bounded. The evolve loop runs for the life of the install;
#: an unbounded log is itself a resource leak, and the recent window is what
#: anyone actually reads.
MAX_LINES = 5000


def _trim(path: Path, keep: int = MAX_LINES) -> None:
    try:
        if path.stat().st_size < 1024 * 1024:
            return
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if len(lines) > keep:
            path.write_text("\n".join(lines[-keep:]) + "\n", encoding="utf-8")
    except OSError:
        pass


def record(kind: str, **fields) -> dict:
    """Append one entry. Never raises: losing the audit write must not abort
    the work, but it must also never be silently skipped -- callers see the
    returned dict and the `written` flag."""
    entry = {"ts": round(time.time(), 2), "kind": str(kind)}
    entry.update({k: v for k, v in fields.items()})
    try:
        LEDGER.parent.mkdir(parents=True, exist_ok=True)
        with open(LEDGER, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        entry["written"] = True
        _trim(LEDGER)
    except (OSError, TypeError, ValueError):
        entry["written"] = False
    return entry


def read(limit: int = 200) -> list:
    out = []
    try:
        for line in LEDGER.read_text(encoding="utf-8",
                                      errors="replace").splitlines()[-limit:]:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    except OSError:
        return []
    return out


def stats() -> dict:
    entries = read(limit=MAX_LINES)
    applied = [e for e in entries if e.get("kind") == "applied"]
    rolled = [e for e in entries if e.get("kind") == "rolled-back"]
    return {
        "entries": len(entries),
        "applied": len(applied),
        "rolled_back": len(rolled),
        "last": entries[-1] if entries else None,
        "path": str(LEDGER),
    }


# -- backups ---------------------------------------------------------------

def backup(target) -> str:
    """Copy *target* aside; returns the backup path ('' when it failed).

    Named by timestamp so repeated changes never overwrite each other -- the
    one you need is always the one before the change that broke things.
    """
    src = Path(target)
    if not src.is_file():
        return ""
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        dst = BACKUP_DIR / ("%s.%s" % (src.name, stamp))
        n = 1
        while dst.exists():
            dst = BACKUP_DIR / ("%s.%s-%d" % (src.name, stamp, n))
            n += 1
        shutil.copy2(str(src), str(dst))
        return str(dst)
    except OSError:
        return ""


def restore(backup_path, target) -> bool:
    src, dst = Path(backup_path), Path(target)
    if not src.is_file():
        return False
    try:
        shutil.copy2(str(src), str(dst))
        return True
    except OSError:
        return False
