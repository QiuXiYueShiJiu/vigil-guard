"""Logging.

Deliberately tiny and stdlib-only. Two sinks:

* a rotating file under the log directory, one line per event, greppable;
* optionally stderr, for interactive CLI commands.

We do not use the ``logging`` module's configuration machinery because the
daemons want a stable, predictable single-line format that ``tail -f`` and
``grep`` handle well, and because the alert mail body reuses the same lines.
"""
from __future__ import annotations

import os
import sys
import time
from datetime import datetime
from pathlib import Path

from . import paths

_LEVELS = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40, "CRIT": 50}
_MAX_BYTES = 2 * 1024 * 1024          # rotate at 2 MiB; these hosts are small
_KEEP = 3                             # .1 .2 .3


class Logger:
    def __init__(self, path, level: str = "INFO", echo: bool = False,
                 tag: str = ""):
        self.path = Path(path)
        self.level = _LEVELS.get(str(level).upper(), 20)
        self.echo = echo
        self.tag = tag

    # -- internals ---------------------------------------------------------
    def _rotate_if_needed(self) -> None:
        try:
            if self.path.exists() and self.path.stat().st_size > _MAX_BYTES:
                for i in range(_KEEP - 1, 0, -1):
                    src = self.path.with_suffix(self.path.suffix + ".%d" % i)
                    dst = self.path.with_suffix(self.path.suffix + ".%d" % (i + 1))
                    if src.exists():
                        os.replace(src, dst)
                os.replace(self.path, self.path.with_suffix(self.path.suffix + ".1"))
        except OSError:
            pass                                    # never let logging kill us

    def log(self, level: str, message: str, *args) -> None:
        lvl = _LEVELS.get(str(level).upper(), 20)
        if lvl < self.level:
            return
        if args:
            try:
                message = message % args
            except (TypeError, ValueError):
                message = "%s %s" % (message, args)
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        prefix = "[%s] [%s]" % (stamp, level.upper())
        if self.tag:
            prefix += " [%s]" % self.tag
        line = "%s %s" % (prefix, message)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            new = not self.path.exists()
            self._rotate_if_needed()
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            if new:
                os.chmod(self.path, 0o640)
        except OSError:
            pass
        if self.echo:
            print(line, file=sys.stderr)

    # -- convenience -------------------------------------------------------
    def debug(self, m, *a): self.log("DEBUG", m, *a)
    def info(self, m, *a): self.log("INFO", m, *a)
    def warn(self, m, *a): self.log("WARN", m, *a)
    def error(self, m, *a): self.log("ERROR", m, *a)
    def crit(self, m, *a): self.log("CRIT", m, *a)


def tail(path, lines: int = 50):
    """Return the last *lines* lines of a text file (best effort)."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            block = min(size, max(8192, lines * 400))
            fh.seek(size - block)
            data = fh.read().decode("utf-8", "replace")
        return data.splitlines()[-lines:]
    except OSError:
        return []


def get(name: str = "main", echo: bool = False, level: str = "INFO") -> Logger:
    """Fetch a logger by logical name (matches paths.LOG_*)."""
    table = {
        "main": (paths.LOG_MAIN, ""),
        "mail": (paths.LOG_MAIL, "mail"),
        "threat": (paths.LOG_THREAT, "threat"),
        "health": (paths.LOG_HEALTH, "health"),
        "login": (paths.LOG_LOGIN, "login"),
        "commands": (paths.LOG_COMMANDS, "cmd"),
        "gate": (paths.LOG_GATE, "gate"),
    }
    path, tag = table.get(name, (paths.LOG_MAIN, name))
    return Logger(path, level=level, echo=echo, tag=tag)
