"""Terminal presentation and prompting.

Kept separate from the command modules so the interaction style is
consistent everywhere: the same colour rules, the same box drawing, the
same prompt behaviour when stdin is not a TTY.

Design notes:

* **Colour is opt-out and auto-detected.** ``NO_COLOR``, ``--no-color``, a
  non-TTY stdout, or ``TERM=dumb`` all disable it. Piping ``vigil doctor``
  into a file must produce clean plain text.
* **Prompts never hang a script.** When stdin is not a TTY, ``ask`` returns
  the default instead of blocking; anything mandatory must be supplied as a
  flag. A wizard that hangs in CI is worse than one that fails.
* **Secrets are echoed as ``*``** and never placed in the shell history.
"""
from __future__ import annotations

import getpass
import os
import shutil
import sys
import textwrap

# --------------------------------------------------------------------------
# Capability detection
# --------------------------------------------------------------------------

_COLOR = None
_WIDTH = None


def color_enabled() -> bool:
    global _COLOR
    if _COLOR is not None:
        return _COLOR
    _COLOR = bool(
        sys.stdout.isatty()
        and os.environ.get("TERM", "") != "dumb"
        and "NO_COLOR" not in os.environ
    )
    return _COLOR


def set_color(enabled: bool) -> None:
    global _COLOR
    _COLOR = bool(enabled)


def width(default: int = 78) -> int:
    global _WIDTH
    if _WIDTH is None:
        try:
            _WIDTH = min(shutil.get_terminal_size((default, 24)).columns, 100)
        except OSError:
            _WIDTH = default
    return _WIDTH


C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
    "grey": "\033[90m",
}


def c(text: str, color: str) -> str:
    if not color_enabled():
        return str(text)
    return "%s%s%s" % (C.get(color, ""), text, C["reset"])


def bold(s): return c(s, "bold")
def dim(s): return c(s, "dim")
def ok(s): return c(s, "green")
def warn(s): return c(s, "yellow")
def err(s): return c(s, "red")
def info(s): return c(s, "cyan")


# --------------------------------------------------------------------------
# Output primitives
# --------------------------------------------------------------------------


def out(text: str = "") -> None:
    sys.stdout.write(str(text) + "\n")


def rule(char: str = "─", w: int = None) -> str:
    return char * (w or width())


def header(title: str, subtitle: str = "") -> None:
    out()
    out(bold(title))
    if subtitle:
        out(dim(subtitle))
    out(dim(rule()))


def section(title: str) -> None:
    out()
    out(bold("▌ " + title))


def kv(key: str, value, color: str = "") -> None:
    text = "—" if value in (None, "", []) else str(value)
    if color:
        text = c(text, color)
    pad = " " * max(1, 22 - _display_len(str(key)))
    out("  %s%s%s" % (key, pad, text))


def _display_len(s: str) -> int:
    """Approximate width, counting CJK characters as two columns."""
    n = 0
    for ch in s:
        n += 2 if _is_wide(ch) else 1
    return n


def _is_wide(ch: str) -> bool:
    o = ord(ch)
    return (0x1100 <= o <= 0x115F or 0x2E80 <= o <= 0xA4CF
            or 0xAC00 <= o <= 0xD7A3 or 0xF900 <= o <= 0xFAFF
            or 0xFE30 <= o <= 0xFE6F or 0xFF00 <= o <= 0xFF60
            or 0xFFE0 <= o <= 0xFFE6 or 0x20000 <= o <= 0x3FFFD)


def bullet(text: str, mark: str = "·") -> None:
    out("  %s %s" % (mark, text))


def wrap(text: str, indent: int = 2) -> str:
    return textwrap.fill(str(text), width=width(),
                         initial_indent=" " * indent,
                         subsequent_indent=" " * indent)


def table(rows, headers=None, gap: int = 2) -> None:
    """Left-aligned table that accounts for double-width CJK glyphs."""
    rows = [[("" if v is None else str(v)) for v in r] for r in rows]
    if headers:
        rows = [[str(h) for h in headers]] + rows
    if not rows:
        return
    cols = max(len(r) for r in rows)
    widths = [0] * cols
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], _display_len(cell))
    for idx, r in enumerate(rows):
        line = []
        for i in range(cols):
            cell = r[i] if i < len(r) else ""
            pad = widths[i] - _display_len(cell)
            line.append(cell + " " * pad)
        text = (" " * gap).join(line).rstrip()
        out(bold(text) if (headers and idx == 0) else text)


STATUS_STYLE = {
    "OK": ("✔", "green"), "WARN": ("!", "yellow"), "CRIT": ("✘", "red"),
    "EVENT": ("•", "cyan"), "INFO": ("·", "grey"), "SKIP": ("-", "grey"),
}


def status_badge(status: str) -> str:
    mark, color = STATUS_STYLE.get(str(status).upper(), ("?", "grey"))
    return c(mark, color)


def success(msg: str) -> None:
    out("  %s %s" % (ok("✔"), msg))


def failure(msg: str) -> None:
    out("  %s %s" % (err("✘"), msg))


def warning(msg: str) -> None:
    out("  %s %s" % (warn("!"), msg))


def note(msg: str) -> None:
    out("  %s %s" % (dim("·"), dim(msg)))


def hint(msg: str) -> None:
    out("    %s %s" % (dim("→"), dim(msg)))


# --------------------------------------------------------------------------
# Prompting
# --------------------------------------------------------------------------


def _tty() -> bool:
    try:
        return sys.stdin.isatty()
    except (ValueError, AttributeError):
        return False


def is_interactive() -> bool:
    return _tty() and sys.stdout.isatty()


def ask(question: str, default: str = "", hint_text: str = "",
        required: bool = False, secret: bool = False) -> str:
    """Prompt for a value.

    Non-interactive callers get the default (or an empty string), so a
    scripted run with all flags supplied never blocks.
    """
    if hint_text:
        for line in textwrap.wrap(hint_text, width=width() - 6):
            out("    %s %s" % (dim("·"), dim(line)))
    suffix = " %s" % dim("[%s]" % default) if default else ""
    tail = c("（必填）", "yellow") if (required and not default) else ""
    prompt = "  %s%s %s" % (question, tail, suffix)

    if not _tty():
        out("%s → %s" % (prompt, dim(default or "(空)")))
        return default
    try:
        if secret:
            value = getpass.getpass(prompt + " ")
        else:
            value = input(prompt + " ").strip()
    except (EOFError, KeyboardInterrupt):
        out()
        return default
    value = (value or "").strip()
    return value or default


def confirm(question: str, default: bool = False) -> bool:
    if not _tty():
        return default
    mark = "Y/n" if default else "y/N"
    try:
        ans = input("  %s %s " % (question, dim("[%s]" % mark))).strip().lower()
    except (EOFError, KeyboardInterrupt):
        out()
        return default
    if not ans:
        return default
    return ans in ("y", "yes", "是", "1", "true")


def choose(question: str, options, default: int = 1, allow_multiple: bool = False):
    """Numbered menu. *options* is a list of (value, label) or plain strings.

    Returns the chosen value (or list of values when ``allow_multiple``).
    Non-interactive callers get the default option.
    """
    norm = []
    for o in options:
        if isinstance(o, (tuple, list)):
            norm.append((o[0], o[1]))
        else:
            norm.append((o, o))

    out()
    out(bold("  " + question))
    for i, (_val, label) in enumerate(norm, 1):
        marker = c("❯", "cyan") if i == default else " "
        out("   %s %s %s" % (marker, c("%2d." % i, "bold"), label))
    if allow_multiple:
        note("可多选，用逗号分隔，例如 1,3；直接回车使用默认")

    if not _tty():
        out("  → %s" % dim(str(norm[default - 1][1]) if norm else ""))
        return [norm[default - 1][0]] if allow_multiple else (
            norm[default - 1][0] if norm else None)

    while True:
        try:
            raw = input("  %s " % dim("选择:")).strip()
        except (EOFError, KeyboardInterrupt):
            out()
            raw = ""
        if not raw:
            return [norm[default - 1][0]] if allow_multiple else (
                norm[default - 1][0] if norm else None)
        picked = []
        bad = False
        for part in raw.replace("，", ",").split(","):
            part = part.strip()
            if not part:
                continue
            if not part.isdigit() or not (1 <= int(part) <= len(norm)):
                bad = True
                break
            picked.append(norm[int(part) - 1][0])
        if bad or not picked:
            warning("输入无效，请输入 1-%d 之间的编号" % len(norm))
            continue
        if not allow_multiple:
            return picked[0]
        return picked


def pause(msg: str = "按回车继续…") -> None:
    if not _tty():
        return
    try:
        input("  " + dim(msg))
    except (EOFError, KeyboardInterrupt):
        out()


# --------------------------------------------------------------------------
# Higher-level blocks
# --------------------------------------------------------------------------


def panel(title: str, rows, footer: str = "") -> None:
    """A bordered summary block, used by `install` and `doctor`."""
    header(title)
    for row in rows:
        if len(row) == 2:
            kv(row[0], row[1])
        else:
            kv(row[0], row[1], row[2])
    if footer:
        out()
        out(dim("  " + footer))


def problems_block(problems, title: str = "需要处理的问题") -> None:
    if not problems:
        return
    section(title)
    for p in problems:
        warning(p)


def ok_block(items, title: str = "全部正常") -> None:
    if not items:
        return
    section(title)
    for i in items:
        success(i)
