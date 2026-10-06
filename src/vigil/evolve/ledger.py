"""Append-only ledger, and the backups that make every change reversible.

The rule this file exists to enforce: **nothing is changed before it is written
down**. An entry is appended first (with the before/after and the evidence),
then the change is attempted, then the outcome is appended. If the process dies
mid-change, the ledger still says what was being attempted, which is the case
that matters when you come back to a host that is behaving oddly.

Every file-level change is preceded by a backup, so `vigil evolve rollback`
is a real operation and not a promise.

Why the chain, and why an HMAC
------------------------------

This ledger is now load-bearing for a security decision: ``self_integrity``
uses it to tell "the program legitimately edited its own decoy table" apart
from "somebody edited the code that decides what to ban". That makes the
ledger an **attack target**. A plain JSONL file that anyone can append to is a
laundering channel: append one line saying "I changed this file, here is its
new hash", and a malicious edit is indistinguishable from a sanctioned one.
The check would then report "自修正（已记录）" about the attacker's edit --
strictly worse than not having the feature.

So two things are added, and they defend against different attackers:

* every record carries ``prev`` -- the MAC of the record before it -- which
  makes the file a chain. Deleting a record, reordering records, or dropping
  one in the middle breaks the links and is *detected*;
* the MAC is an HMAC-SHA256 under a key that lives in ``secrets.json``
  (mode 0600, outside the repository). Root can of course do anything, but
  root *rewriting history* now also means forging an HMAC without the key,
  which is not something a scripted attacker gets by accident. Without the
  key an appended record cannot be validated, and an unverifiable record is
  never used to excuse a change.

A plain hash chain alone would not have been enough: recomputing a chain of
hashes needs no secret at all, so anyone willing to rewrite the file can
produce a consistent one. The secret is what makes the chain mean something.

**Failure is not "ignore the ledger".** When the chain does not verify, the
attribution code treats *everything* as unattributed and says where the chain
broke. Failing open here would be the wash-out channel again, one level up.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
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

#: Config key holding the HMAC secret. The name contains "key", so
#: ``core.config._is_secret`` routes it into ``secrets.json`` (0600) rather
#: than ``config.json`` -- which is the property this design depends on.
MAC_KEY_PATH = "evolve.ledger_mac_key"


def _trim(path: Path, keep: int = MAX_LINES) -> None:
    try:
        if path.stat().st_size < 1024 * 1024:
            return
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if len(lines) > keep:
            path.write_text("\n".join(lines[-keep:]) + "\n", encoding="utf-8")
    except OSError:
        pass


#: Field names that carry the chain, skipped when computing a record's own
#: MAC. They are excluded because the MAC covers the rest of the record, and
#: including them would be circular.
_CHAIN_FIELDS = ("mac", "prev", "written")


def _mac_key(cfg=None) -> bytes:
    """The HMAC secret, created on first use and kept in ``secrets.json``.

    Creation is lazy rather than instal-time so an existing installation
    starts chaining with its next write, without a migration step that could
    itself be interrupted. The key is never returned to a caller that might
    log it -- only into the MAC functions below.
    """
    if cfg is None:
        try:
            from ..core.config import load as load_config
            cfg = load_config()
        except Exception:                                   # noqa: BLE001
            return b""
    try:
        stored = str(cfg.get(MAC_KEY_PATH, "") or "")
    except Exception:                                       # noqa: BLE001
        return b""
    if len(stored) >= 32:
        return stored.encode("utf-8")
    fresh = secrets.token_hex(32)
    try:
        cfg.set(MAC_KEY_PATH, fresh)
        cfg.save()
    except Exception:                                       # noqa: BLE001
        # Cannot persist a key -> do not invent an unverifiable one. A record
        # without a MAC is honest; a record with a MAC nobody can check is
        # worse than none, because it looks verified.
        return b""
    return fresh.encode("utf-8")


def _canonical(entry: dict) -> bytes:
    """The bytes a MAC covers: every field except the chain fields.

    ``sort_keys`` so that a field's position in the JSON object cannot change
    the MAC, and ``ensure_ascii=False`` so a Chinese value hashes the same way
    it is stored.
    """
    payload = {k: v for k, v in entry.items() if k not in _CHAIN_FIELDS}
    return json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")


def compute_mac(entry: dict, prev: str, key: bytes) -> str:
    """HMAC-SHA256 over ``prev || entry``, hex encoded.

    ``prev`` is inside the MAC, not beside it: that is what makes each record
    commit to the whole history before it, so a deleted or reordered line
    cannot be papered over by recomputing one MAC.
    """
    if not key:
        return ""
    return hmac.new(key, (str(prev or "") + "\n").encode("utf-8")
                    + _canonical(entry), hashlib.sha256).hexdigest()


def _last_mac() -> str:
    """The ``mac`` of the last usable line, or ``""`` for a fresh ledger."""
    try:
        lines = LEDGER.read_text(encoding="utf-8",
                                 errors="replace").splitlines()
    except OSError:
        return ""
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            # A truncated trailing line (a crash mid-append) is the one
            # case where ignoring it is right: it was never a record.
            return ""
        return str(entry.get("mac") or "")
    return ""


def record(kind: str, cfg=None, **fields) -> dict:
    """Append one entry, chained to the one before it.

    Never raises: losing the audit write must not abort the work, but it must
    also never be silently skipped -- callers see the returned dict; a
    non-empty ``mac`` is what says the entry is verifiable.

    The MAC is computed **before** the write, over the previous record's MAC
    plus this record's contents. An entry that could not be chained (no key
    available) is still written, without a MAC: an unverifiable record is
    reported as unverifiable, which is the honest outcome, and losing the
    audit line entirely would be worse.

    *cfg* is optional and only supplies where the HMAC key lives. Callers that
    already hold a ``Config`` should pass it, so that a program running
    against a relocated state directory (root, tests, a packager) chains and
    verifies with the same key. Without it the key is read through the normal
    config path, which is what the daemon wants.
    """
    entry = {"ts": round(time.time(), 2), "kind": str(kind)}
    entry.update({k: v for k, v in fields.items()})
    try:
        prev = _last_mac()
        key = _mac_key(cfg)
        mac = compute_mac(entry, prev, key)
        entry["prev"] = prev
        entry["mac"] = mac
    except Exception:                                       # noqa: BLE001
        entry["prev"] = ""
        entry["mac"] = ""
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
    """Raw entries, newest last. Format only -- no verification.

    Deliberately unverified: most callers want a count or the last outcome,
    and verification needs the key. Anything that makes a *decision* from the
    ledger must use :func:`verified`, which refuses to answer when the chain
    does not hold.
    """
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


def verify(limit: int = 200, cfg=None) -> dict:
    """Walk the chain and report where (if anywhere) it breaks.

    Returns ``{ok, entries, checked, legacy, break_at, break_kind,
    break_reason, key_available}``.

    Three outcomes, and the middle one is the one that matters:

    * ``ok`` with ``legacy`` > 0 -- the first lines predate the chain. They
      are reported as unverifiable-but-old, not as a break: refusing every
      history that existed before the feature would make the feature useless
      on the first day.
    * ``ok`` false -- a link does not connect, a MAC does not match, or a
      chained record follows an unchained one. ``break_at`` is the 1-based
      line number within the examined window, so the report can name it.
    * anything after a break is **not** trustworthy, and no caller may use it
      to excuse a change.
    """
    out = {"ok": True, "entries": [], "checked": 0, "legacy": 0,
           "break_at": 0, "break_kind": "", "break_reason": "",
           "key_available": False}
    key = _mac_key(cfg)
    out["key_available"] = bool(key)
    try:
        lines = LEDGER.read_text(encoding="utf-8",
                                 errors="replace").splitlines()[-limit:]
    except OSError:
        return out

    prev = ""
    seen_any = False
    for index, raw in enumerate(lines, 1):
        text = raw.strip()
        if not text:
            continue
        try:
            entry = json.loads(text)
        except ValueError:
            out["ok"] = False
            out["break_at"] = index
            out["break_kind"] = "unparsable"
            out["break_reason"] = "第 %d 行不是合法的 JSON —— 台账被截断或改写" % index
            return out
        out["checked"] += 1
        mac = str(entry.get("mac") or "")
        recorded_prev = str(entry.get("prev") or "")
        if not mac:
            if seen_any:
                # A chained history followed by an unchained record. This is
                # how a forged line looks: appended by something that could
                # not produce a MAC.
                out["ok"] = False
                out["break_at"] = index
                out["break_kind"] = "unchained-after-chain"
                out["break_reason"] = (
                    "第 %d 行（kind=%s, ts=%s）没有 MAC，却出现在已加链的记录之后 "
                    "—— 该记录无法由本程序的密钥产生，台账自此处起不可信"
                    % (index, entry.get("kind"), entry.get("ts")))
                return out
            out["legacy"] += 1
            out["entries"].append(entry)
            prev = ""
            continue

        seen_any = True
        if not key:
            out["ok"] = False
            out["break_at"] = index
            out["break_kind"] = "no-key"
            out["break_reason"] = ("记录带 MAC，但本机没有台账密钥"
                                   "（%s）—— 无法验证，一律按不可信处理" % MAC_KEY_PATH)
            return out
        if recorded_prev != prev:
            out["ok"] = False
            out["break_at"] = index
            out["break_kind"] = "link"
            out["break_reason"] = (
                "第 %d 行（kind=%s, ts=%s）的 prev 与上一行的 MAC 不匹配 —— "
                "该行之前有记录被删除、插入或重排"
                % (index, entry.get("kind"), entry.get("ts")))
            return out
        if not hmac.compare_digest(compute_mac(entry, prev, key), mac):
            out["ok"] = False
            out["break_at"] = index
            out["break_kind"] = "mac"
            out["break_reason"] = (
                "第 %d 行（kind=%s, ts=%s）的内容与它的 MAC 不符 —— "
                "该行被改写过" % (index, entry.get("kind"), entry.get("ts")))
            return out
        out["entries"].append(entry)
        prev = mac
    return out


def verified(limit: int = 200, cfg=None) -> tuple:
    """``(entries, verdict)`` for callers that make a decision.

    Entries from an unverified chain are **dropped**, not returned with a
    warning attached: a caller that forgot to check the warning would be the
    whole vulnerability. The verdict carries the explanation.
    """
    verdict = verify(limit=limit, cfg=cfg)
    if not verdict["ok"]:
        return [], verdict
    return verdict["entries"], verdict


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
