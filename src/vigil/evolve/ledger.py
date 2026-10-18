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
import os
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
    """The HMAC secret, created on first use.

    Two homes, tried in order, because the chain must work everywhere:

    1. ``evolve.ledger_mac_key`` in ``secrets.json`` (mode 0600). The name
       contains "key", so ``core.config._is_secret`` routes it there rather
       than into ``config.json``, and it is outside the repository. This is
       the preferred home;
    2. ``state/ledger-key`` beside the ledger, created mode 0600. This is the
       fallback for the case the first one cannot serve -- no ``Config`` in
       hand (the daemon writes records from several code paths), or a
       relocated state directory in a test. It is *not* a weaker secret: the
       threat the MAC answers is "somebody appended a record that looks
       legitimate", and that somebody can already read the ledger this key
       sits next to. What would be weaker is an *absent* key, where a record
       silently stops being verifiable -- which is exactly how the first
       version of this failed on a host whose ``/etc/vigil`` did not yet
       exist.

    Creation is lazy rather than install-time so an existing installation
    starts chaining with its next write, with no migration step that could
    itself be interrupted.
    """
    keys = _candidate_keys(cfg)
    if keys:
        return keys[0]
    # Neither home has a key yet. Mint one and write it to *both*, so a
    # verifier can never come back with a different value than the writer
    # used -- that mismatch is the whole of the failure this replaces: a host
    # whose config gained a key after the ledger had already been chained
    # with the state file reported every chained record as altered.
    fresh = secrets.token_hex(32)
    wrote = _write_secret_file(LEDGER.parent / "ledger-key", fresh)
    if cfg is not None:
        try:
            cfg.set(MAC_KEY_PATH, fresh)
            cfg.save()
            wrote = True
        except (OSError, ValueError):
            pass
    return fresh.encode("utf-8") if wrote else b""


def _candidate_keys(cfg=None) -> list:
    """Every key this ledger may have been chained with, most likely first.

    The key has two homes (see :func:`_mac_key`), and a host can end up with a
    different value in each: the daemon wrote a record from a code path with
    no ``Config`` in hand, or an upgrade rotated one home and not the other.
    That split is an operational fact, not tampering, so verification offers
    both instead of declaring every record in the file altered -- which is
    exactly what happened here: the ledger was chained with
    ``state/ledger-key``, the config later gained a second key, and the
    tamper check reported the *reset* line as rewritten forever after.

    The state file comes first: it sits beside the ledger and is what a writer
    without a ``Config`` uses, so it is the one the file has actually been
    chained with on any host that runs anything headless.
    """
    out = []
    state = _read_state_key()
    if state:
        out.append(state)
    if cfg is not None:
        try:
            stored = str(cfg.get(MAC_KEY_PATH, "") or "")
        except Exception:                                   # noqa: BLE001
            stored = ""
        if len(stored) >= 32:
            raw = stored.encode("utf-8")
            if raw not in out:
                out.append(raw)
    return out


def _read_state_key() -> bytes:
    """The fallback key from ``state/ledger-key``, or ``b""``."""
    path = LEDGER.parent / "ledger-key"
    try:
        if path.is_file():
            stored = path.read_text(encoding="utf-8").strip()
            return stored.encode("utf-8") if len(stored) >= 32 else b""
    except OSError:
        return b""
    return b""


def _write_secret_file(path, value: str) -> bool:
    """Write *value* to *path* with 0600, atomically. False on any failure."""
    import tempfile
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".key-",
                                   suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(value)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, str(path))
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return True
    except (OSError, ValueError):
        return False


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
    except Exception:                                       # noqa: BLE001
        mac = ""
        prev = ""
    if mac:
        entry["prev"] = prev
        entry["mac"] = mac
    else:
        # No key: write the record in the *pre-HMAC shape* -- no `mac` and no
        # `prev` at all. Not `"mac": ""`, which would be indistinguishable
        # from a record whose signature was stripped, and would make every
        # later verification call "tampering" on a host that had simply not
        # created its key yet. An unchained old-format record is honest: it
        # says "this one predates the chain and proves nothing", which is the
        # truth, and it is why the chain may only be *added* to.
        entry.pop("mac", None)
        entry.pop("prev", None)
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

    Tries every key this ledger could have been chained with (see
    :func:`_candidate_keys`). A chain that holds under the second key is
    reported as ``ok`` with ``key_split`` set: the ledger is intact, and the
    operational problem is the two divergent key homes -- which the caller can
    repair. Reporting that as tampering fires a CRIT on every run and teaches
    the operator that this check lies, which is the one outcome a tamper check
    cannot afford.
    """
    keys = _candidate_keys(cfg)
    out = _verify_one(limit, cfg, keys)
    if out["ok"] and len(keys) > 1:
        out["key_split"] = True
        out["key_note"] = (
            "台账的密钥曾在串联中途更换（config 与 state 各存有一把），"
            "每条记录的 MAC 都由本机的其中一把密钥签署、链接完整；"
            "建议统一两处密钥，以免人工核对时误以为链条断了")
    return out


def _verify_one(limit: int, cfg, keys) -> dict:
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
           "key_available": bool(keys)}
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
        mac = entry.get("mac")
        recorded_prev = str(entry.get("prev") or "")
        if mac is not None and not str(mac).strip():
            # An explicit empty MAC is unambiguous: `record()` either writes a
            # real one or leaves the field out entirely, so a present-but-empty
            # value is a signature that was stripped. That is the narrow case
            # this check *can* catch, and it costs nothing to catch it.
            out["ok"] = False
            out["break_at"] = index
            out["break_kind"] = "stripped"
            out["break_reason"] = (
                "第 %d 行（kind=%s, ts=%s）的 mac 字段存在但为空 —— "
                "本程序不会写出这种记录，说明签名被人抹掉了"
                % (index, entry.get("kind"), entry.get("ts")))
            return out
        if not mac:
            # An unchained record is *legacy*, wherever it sits in the file --
            # every version before this one wrote exactly this shape, and a
            # host that has been running for a while has thousands of them
            # interleaved with new chained records (the daemon writes while an
            # operator runs the CLI). Treating "unchained after chained" as
            # forgery would therefore fire on every upgrade, which is how a
            # tamper check becomes something people turn off.
            #
            # The honest limit, stated here rather than implied: the chain
            # proves that no **chained** record has been altered, deleted or
            # reordered *relative to the next chained record*. It cannot prove
            # that an unchained line was not appended, because the whole point
            # of the MAC is that an appended line cannot be made to look
            # chained. Records that cannot vouch for themselves are counted
            # and never used to excuse a change (see `attribute`).
            out["legacy"] += 1
            out["entries"].append(entry)
            # Reset the chain to "" *because that is what the writer did*:
            # `_last_mac()` looks at the final line of the file, sees no MAC
            # there, and writes the next record with `prev: ""`. The verifier
            # has to model the writer, or the two disagree on the very first
            # record after any legacy run -- which is precisely the state a
            # host is in the moment it is upgraded.
            prev = ""
            continue

        seen_any = True
        if not keys:
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
        if not any(hmac.compare_digest(compute_mac(entry, prev, k), mac)
                   for k in keys):
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
