"""Durable JSON state with atomic writes and advisory locking.

Three requirements shaped this module:

* **Crash safety.** A monitoring daemon is killed by OOM, by ``systemctl
  restart``, and by the operator at 3am. A half written state file must never
  be readable, so every write goes to a temp file in the same directory
  followed by ``os.replace`` (atomic within a filesystem).
* **Single writer.** Timers can overlap if a run takes longer than its
  period. ``locked()`` provides an flock based mutual exclusion that the
  kernel releases even if we are SIGKILLed.
* **Forward compatibility.** State written by an older version must not
  crash a newer one. Readers always merge over a default dict.
"""
from __future__ import annotations

import copy

import errno
import fcntl
import json
import os
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from . import paths


def read_json(path, default: Any = None) -> Any:
    """Read JSON, returning *default* on any problem (missing, truncated,
    unreadable). Monitoring code must degrade, never explode."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def write_json(path, data: Any, mode: int = 0o600) -> bool:
    """Atomically write *data* as JSON. Returns success."""
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-",
                                   suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2, sort_keys=False)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, mode)
            os.replace(tmp, path)
            return True
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception:
        return False


def read_text(path, default: str = "") -> str:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return default


def write_text(path, text: str, mode: int = 0o600) -> bool:
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, mode)
            os.replace(tmp, path)
            return True
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception:
        return False


def append_line(path, line: str, mode: int = 0o600) -> bool:
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        new = not path.exists()
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line.rstrip("\n") + "\n")
        if new:
            os.chmod(path, mode)
        return True
    except OSError:
        return False


@contextmanager
def locked(lock_path=None, timeout: float = 0.0):
    """Advisory exclusive lock.

    ``timeout=0`` means "try once, do not wait" -- the right default for
    periodic jobs, where skipping a cycle beats stacking them up.
    Yields True when the lock was acquired and False otherwise, so callers
    can simply do ``with locked() as ok: if not ok: return``.
    """
    lock_path = Path(lock_path or paths.MAIL_LOCK)
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    except OSError:
        yield False
        return
    got = False
    try:
        if timeout > 0:
            deadline = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    got = True
                    break
                except OSError as e:
                    if e.errno not in (errno.EACCES, errno.EAGAIN):
                        break
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(0.05)
        else:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                got = True
            except OSError:
                got = False
        yield got
    finally:
        if got:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(fd)


class Store:
    """A JSON document backed by a file, with dotted-path access.

    ``store.get("thresholds.cpu.warn", 85)`` keeps call sites readable and
    makes missing keys a non-event -- important because config schema will
    grow between versions.
    """

    def __init__(self, path, defaults: dict | None = None, mode: int = 0o600):
        self.path = Path(path)
        self.mode = mode
        self._defaults = defaults or {}
        self.data = self._load()

    def _load(self) -> dict:
        raw = read_json(self.path, None)
        if not isinstance(raw, dict):
            raw = {}
        # deepcopy, not dict(): a shallow copy still shares the nested dicts
        # and lists with the module-level DEFAULTS, so merging a saved file
        # into it wrote straight into the defaults. Every Store built
        # afterwards in the same process then started from polluted defaults
        # -- one command setting `mail.providers` was enough to make the next
        # one believe providers were already configured.
        return deep_merge(copy.deepcopy(self._defaults), raw)

    def reload(self) -> dict:
        self.data = self._load()
        return self.data

    def save(self) -> bool:
        return write_json(self.path, self.data, self.mode)

    def get(self, dotted: str, default: Any = None) -> Any:
        cur: Any = self.data
        for part in dotted.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur

    def set(self, dotted: str, value: Any) -> None:
        parts = dotted.split(".")
        cur = self.data
        for part in parts[:-1]:
            nxt = cur.get(part)
            if not isinstance(nxt, dict):
                nxt = {}
                cur[part] = nxt
            cur = nxt
        cur[parts[-1]] = value

    def update(self, patch: dict) -> None:
        self.data = deep_merge(self.data, patch)


def deep_merge(base: dict, patch: dict) -> dict:
    """Recursively merge *patch* into a copy of *base*.

    Lists are replaced wholesale rather than concatenated: for something
    like a whitelist, "the new value wins" is the only unsurprising rule.
    """
    out = dict(base)
    for k, v in (patch or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out
