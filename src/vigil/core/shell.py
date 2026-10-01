"""Subprocess helpers.

Two rules learned the hard way on production hosts:

1. **Never let a child inherit our stdin.** Several system tools
   (``ausearch`` among them) silently switch to reading stdin when it is a
   pipe, and then return "no results" instead of the data you asked for.
   Every call here passes ``stdin=DEVNULL``.
2. **Always time out.** A hung child inside a monitoring daemon is a dead
   monitoring daemon.

Everything returns ``(ok, stdout, stderr)`` rather than raising, because
most callers want to branch on failure rather than unwind.
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from typing import Iterable, Sequence

DEFAULT_TIMEOUT = 20

# Inherited environment is fine, but force a predictable, non-interactive
# locale so we can parse tool output reliably on non-English hosts.
_BASE_ENV = dict(os.environ)
_BASE_ENV.update({
    "LC_ALL": "C",
    "LANG": "C",
    "DEBIAN_FRONTEND": "noninteractive",
})


def run(argv: Sequence[str], timeout: float = DEFAULT_TIMEOUT,
        env: dict | None = None, cwd: str | None = None):
    """Run *argv*, returning ``(ok, stdout, stderr)``. Never raises."""
    try:
        p = subprocess.run(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env={**_BASE_ENV, **(env or {})},
            cwd=cwd,
        )
        return (p.returncode == 0,
                p.stdout.decode("utf-8", "replace"),
                p.stderr.decode("utf-8", "replace"))
    except FileNotFoundError:
        return False, "", "not found: %s" % argv[0]
    except subprocess.TimeoutExpired:
        return False, "", "timeout after %ss: %s" % (timeout, argv[0])
    except Exception as e:                       # pragma: no cover - defensive
        return False, "", "%s: %s" % (type(e).__name__, e)


def run_ok(argv: Sequence[str], **kw) -> bool:
    return run(argv, **kw)[0]


def out(argv: Sequence[str], default: str = "", **kw) -> str:
    """Return stripped stdout, or *default* when the command fails."""
    ok, o, _ = run(argv, **kw)
    return o.strip() if ok else default


def shell(script: str, timeout: float = DEFAULT_TIMEOUT, **kw):
    """Run a shell snippet. Only for things that genuinely need a pipeline."""
    return run(["/bin/sh", "-c", script], timeout=timeout, **kw)


def have(program: str) -> bool:
    return shutil.which(program) is not None


def which(program: str, *fallbacks: str) -> str:
    """Locate a program, trying *fallbacks* as literal paths.

    PATH is unreliable in daemon context (systemd gives a minimal one), so
    callers that need a specific binary pass known absolute locations.
    """
    found = shutil.which(program)
    if found:
        return found
    for f in fallbacks:
        if os.path.isfile(f) and os.access(f, os.X_OK):
            return f
    return ""


def quote(argv: Iterable[str]) -> str:
    """Human-readable command line, safe to paste into a terminal."""
    return " ".join(shlex.quote(str(a)) for a in argv)


def systemctl(action: str, unit: str, timeout: float = 30):
    return run(["systemctl", action, unit], timeout=timeout)


def unit_active(unit: str) -> bool:
    return out(["systemctl", "is-active", unit]) == "active"


def unit_enabled(unit: str) -> bool:
    return out(["systemctl", "is-enabled", unit]) in ("enabled", "enabled-runtime",
                                                      "static", "alias")


def systemd_reload() -> None:
    run(["systemctl", "daemon-reload"], timeout=30)
