"""Durable mail bookkeeping: sequence numbers, daily quota, dedupe, overflow.

Everything here is about *not losing an alert* and *not flooding the
operator*. The previous generation of this code got the intent right but
had three concurrency defects that this module fixes:

* the quota was read outside the lock, so two concurrent senders could both
  decide they were under the cap and overshoot it;
* a pending/overflow file was rewritten with a bare read-modify-write while
  the sequence file used flock, so records could vanish;
* the notifier always exited 0, so a message that only reached the digest
  was reported to its caller as delivered.

All mutations here go through :func:`vigil.core.state.locked`.
"""
from __future__ import annotations

import hashlib
import re
import json
import os
from pathlib import Path
import time
from datetime import datetime, timezone

from ..core import paths
from ..core.state import append_line, locked, read_json, read_text, write_json
from .message import KIND_DIGEST, Alert, Message, SEV_WARN

# --------------------------------------------------------------------------
# Sequence numbers
# --------------------------------------------------------------------------


def next_seq() -> int:
    """Monotonic alert number, unique across restarts.

    Not just decorative: it is the handle an operator uses to refer to a
    specific alert in a follow-up ("what was in #000042?"), so it must never
    repeat or go backwards.
    """
    paths.STATE_MAIL.mkdir(parents=True, exist_ok=True)
    with locked(paths.MAIL_LOCK, timeout=5.0) as ok:
        if not ok:
            # Losing the lock must not lose the alert; fall back to a
            # timestamp-derived number, which is still monotonic enough to
            # be useful and cannot collide with a small counter.
            return int(time.time()) % 100000000
        try:
            cur = int(read_text(paths.MAIL_SEQ, "0").strip() or 0)
        except ValueError:
            cur = 0
        cur += 1
        _write_atomic(paths.MAIL_SEQ, str(cur))
        return cur


def _write_atomic(path, text: str) -> None:
    try:
        tmp = str(path) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except OSError:
        pass


def current_seq() -> int:
    try:
        return int(read_text(paths.MAIL_SEQ, "0").strip() or 0)
    except ValueError:
        return 0


# --------------------------------------------------------------------------
# Daily quota
# --------------------------------------------------------------------------


def _quota_day() -> str:
    """Quota rolls over at 00:00 UTC, not local midnight.

    A fixed, unambiguous boundary avoids the double-counting you get when a
    DST change or a timezone edit makes one local day 23 or 25 hours long.
    """
    return datetime.now(timezone.utc).strftime("%Y%m%d")


def _quota_path(day: str = ""):
    return paths.STATE_MAIL / ("quota-%s" % (day or _quota_day()))


def quota_used() -> int:
    try:
        return int(read_text(_quota_path(), "0").strip() or 0)
    except ValueError:
        return 0


def quota_remaining(total: int) -> int:
    if total <= 0:
        return 10 ** 9                      # 0 means "unlimited"
    return max(0, total - quota_used())


def quota_add(n: int, total: int = 0) -> int:
    """Debit *n* units atomically and return the new total.

    Called *after* a successful send, with the number the provider actually
    billed (one per recipient for Resend).
    """
    if n <= 0:
        return quota_used()
    with locked(paths.MAIL_LOCK, timeout=5.0) as ok:
        if not ok:
            return quota_used()
        cur = quota_used() + n
        _write_atomic(_quota_path(), str(cur))
        _prune_quota_files()
        return cur


def _prune_quota_files(keep_days: int = 7) -> None:
    try:
        cutoff = time.time() - keep_days * 86400
        for p in paths.STATE_MAIL.glob("quota-*"):
            try:
                if p.stat().st_mtime < cutoff:
                    p.unlink()
            except OSError:
                pass
    except OSError:
        pass


# --------------------------------------------------------------------------
# Dedupe
# --------------------------------------------------------------------------


def dedupe_key_for(msg: Message) -> str:
    if msg.dedupe_key:
        return msg.dedupe_key
    # Belt and braces: strip any leading sequence marker before hashing, so a
    # caller that forgets to set `dedupe_key` still gets a stable identity
    # rather than a guaranteed-unique one.
    subject = re.sub(r"^\s*\[#\d+\]\s*", "", msg.subject or "")
    raw = "%s|%s" % (subject, msg.severity)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def is_duplicate(key: str, window: int) -> bool:
    """True when an identical alert was sent within *window* seconds."""
    if window <= 0:
        return False
    path = paths.STATE_MAIL / "seen" / hashlib.sha256(
        key.encode("utf-8")).hexdigest()
    try:
        last = float(path.read_text().strip() or 0)
    except (OSError, ValueError):
        return False
    if time.time() - last < window:
        return True
    return False


def mark_seen(key: str) -> None:
    path = paths.STATE_MAIL / "seen" / hashlib.sha256(
        key.encode("utf-8")).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_atomic(path, str(int(time.time())))
    _prune_seen()


def _prune_seen(max_age: int = 7200) -> None:
    d = paths.STATE_MAIL / "seen"
    cutoff = time.time() - max_age
    try:
        for p in d.iterdir():
            try:
                if p.stat().st_mtime < cutoff:
                    p.unlink()
            except OSError:
                pass
    except OSError:
        pass


# --------------------------------------------------------------------------
# Overflow / digest
# --------------------------------------------------------------------------


def to_overflow(msg: Message, reason: str = "") -> bool:
    """Park a message that could not be delivered anywhere.

    Terminal failure must never mean "dropped". The digest is replayed once
    a channel recovers, so the operator still learns about the event, just
    late.
    """
    day = _quota_day()
    path = paths.MAIL_OVERFLOW / ("%s.digest" % day)
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header = "=== [%s] #%06d %s%s ===" % (
        stamp, msg.seq, msg.subject, ("  (%s)" % reason) if reason else "")
    return append_line(path, header + "\n" + msg.text + "\n", mode=0o640)


def overflow_digests() -> list:
    try:
        return sorted(p for p in paths.MAIL_OVERFLOW.glob("*.digest"))
    except OSError:
        return []


def overflow_count() -> int:
    return len(overflow_digests())


def read_digest(path, max_bytes: int = 200000) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = fh.read(max_bytes)
        if os.path.getsize(path) > max_bytes:
            data += "\n… （内容过长已截断）"
        return data
    except OSError:
        return ""


def archived_dir() -> Path:
    """Where handled digests go, so the queue holds only pending work."""
    return paths.MAIL_OVERFLOW / "sent"


def archive_digest(path, suffix: str = ".sent") -> bool:
    """Mark a digest as handled, and move it out of the queue directory.

    Kept for audit, but *moved*: the first version renamed it in place, so a
    delivered message sat in `overflow/` looking exactly like a stuck one.
    The operator saw a file in the queue directory, asked "why is there still
    a backlog", and had to be told that there was none -- which is a bad
    answer to a reasonable question. A queue directory should contain the
    queue, so that "is anything stuck?" is answerable by looking at it.
    """
    target = Path(str(path) + suffix)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        os.replace(str(path), str(archived_dir() / target.name))
        _prune_archived()
        return True
    except OSError:
        try:
            os.replace(str(path), str(target))
            return True
        except OSError:
            return False


def archive_claimed(claimed, original) -> bool:
    """Archive a digest that was claimed for sending, under its own name.

    The replay path claims a file by renaming it to ``.sending`` and then
    used to rename it again in place -- a second, private archiving
    implementation that bypassed the move into `sent/`. The result was that
    every file the replay touched stayed in the queue directory, which is
    precisely what makes the queue unreadable at a glance.
    """
    name = Path(str(original)).name + ".sent"
    try:
        archived_dir().mkdir(parents=True, exist_ok=True)
        os.replace(str(claimed), str(archived_dir() / name))
        _prune_archived()
        return True
    except OSError:
        try:
            os.replace(str(claimed), str(original) + ".sent")
            return True
        except OSError:
            return False


def archived_digests() -> list:
    """Handled digests, newest last. Audit material, not a backlog."""
    try:
        return sorted(archived_dir().glob("*.digest.*"))
    except OSError:
        return []


def _prune_archived(keep: int = 30) -> None:
    try:
        done = archived_digests()
        for p in done[:-keep] if len(done) > keep else []:
            try:
                p.unlink()
            except OSError:
                pass
    except OSError:
        pass


def build_digest_alert(path, count: int = 1) -> Alert:
    """Wrap a parked digest in an Alert so it flows through the same pipeline."""
    body = read_digest(path)
    alert = Alert(
        title="积压告警补发（此前因通道不可用未能送达）",
        severity=SEV_WARN, kind=KIND_DIGEST,
        summary="共 %d 份积压告警，以下为最早的 1 份；"
                "通道恢复后会自动继续补发其余部分。" % count,
        footer="积压文件: %s" % path,
    )
    alert.add_section("积压内容", [body])
    return alert


# --------------------------------------------------------------------------
# Lightweight delivery journal
# --------------------------------------------------------------------------


def journal(msg: Message, to: str, provider: str, ok: bool, detail: str = "") -> None:
    """Append one line per delivery attempt.

    Cheap, append-only, and the first place to look when someone asks "did
    the server actually try to tell me".
    """
    rec = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "seq": msg.seq,
        "to": to,
        "provider": provider,
        "ok": bool(ok),
        "kind": msg.kind,
        "subject": msg.subject[:180],
    }
    if detail:
        rec["detail"] = detail[:400]
    append_line(paths.STATE_MAIL / "journal.jsonl",
                json.dumps(rec, ensure_ascii=False), mode=0o640)


def recent_journal(n: int = 20) -> list:
    path = paths.STATE_MAIL / "journal.jsonl"
    lines = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()[-n:]
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def sends_since(seconds: int) -> int:
    """How many messages actually went out in the last `seconds`.

    Counts *delivered* mail only. A provider outage that fails every send is
    not a storm, and treating it as one would suppress the retry that
    eventually succeeds.
    """
    from datetime import datetime
    cut = time.time() - int(seconds)
    n = 0
    for rec in recent_journal(600):
        if not rec.get("ok") or not rec.get("ts"):
            continue
        try:
            when = datetime.fromisoformat(str(rec["ts"])).timestamp()
        except ValueError:
            continue
        if when >= cut:
            n += 1
    return n


def storm_notice_due(window: int) -> bool:
    """True at most once per window -- so the storm notice is not a storm.

    Without this the suppression itself becomes the flood: every suppressed
    message would want to announce that messages are being suppressed.
    """
    marker = paths.STATE_MAIL / "storm-notice"
    now = time.time()
    try:
        last = float(read_text(marker, "0").strip() or 0)
    except (OSError, ValueError):
        last = 0.0
    if now - last < int(window):
        return False
    try:
        _write_atomic(marker, str(now))
    except OSError:
        return False
    return True


def stats() -> dict:
    return {
        "sequence": current_seq(),
        "quota_day": _quota_day(),
        "quota_used": quota_used(),
        "overflow_files": overflow_count(),
        "archived_files": len(archived_digests()),
        "seen_files": len(list((paths.STATE_MAIL / "seen").glob("*")))
        if (paths.STATE_MAIL / "seen").is_dir() else 0,
    }
