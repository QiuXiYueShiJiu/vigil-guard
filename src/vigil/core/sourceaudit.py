"""What must not ship: one definition, used by the test and by the CLI.

Why this exists
---------------

The package is published, so anything in it is public. The failure mode is
not a dramatic leak; it is a slow accumulation of small facts -- an IP, a
site's Chinese name, a customer's file naming, a personal mailbox in an
example config -- each of which looked harmless where it was written.

An earlier version of this check lived inside the test suite and scanned only
``src/**/*.py`` and ``src/**/*.tmpl``. It therefore walked straight past the
real host's IP address in ``tests/``, the hosting brand next to it, a
site-specific directory name inside a *product* rule, a personal QQ address in
``examples/``, and -- the one that stings -- the operator's genuine leaked
filenames used as test fixtures. A guard that only looks at part of the tree
is worse than no guard, because it is believed.

So: one module, one list of rules, applied to **every file the packaging
script would ship**. The test asserts it is clean; ``vigil audit-source``
runs the same code on somebody else's fork before they publish it.

Rules are *shapes*, never a list of one operator's own values: a rule that
enumerates the secrets it forbids ships them in the guard.

Being precise matters as much as being thorough. ``198.51.100.x``,
``192.168.x.x`` and ``/www/server/panel`` are legitimate: the first are the
RFC 5737 documentation ranges, the last is the default path of the panel this
project targets. A scanner that flags those teaches people to ignore it.
"""
from __future__ import annotations

import re
from pathlib import Path

#: IPs that carry no information about a deployment, so a literal is fine.
ALLOWED_IP_PREFIXES = (
    r"127\.", r"10\.", r"192\.168\.", r"172\.(1[6-9]|2[0-9]|3[01])\.",
    r"0\.0\.0\.0", r"255\.",
    r"203\.0\.113\.", r"198\.51\.100\.", r"192\.0\.2\.",   # RFC 5737
    r"169\.254\.", r"192\.0\.0\.", r"100\.64\.", r"198\.18\.",
    r"192\.88\.99\.", r"240\.",
    r"8\.8\.8\.8", r"8\.8\.4\.4", r"1\.1\.1\.1",           # public resolvers
    r"93\.184\.216\.34",                                    # example.com
)

#: (pattern, why it matters). These apply to every shipped file.
RULES: tuple = (
    (r"xn--[a-z0-9]{6,}", "an internationalised (punycode) domain"),
    (r"RainYun|阿里云ECS|腾讯云服务器|雨云", "a specific hosting brand"),
    (r"\b[A-Za-z0-9._%+-]+@(qq|163|126|outlook|gmail|foxmail)\.com\b",
     "a personal mailbox used as configuration"),
    # A date-stamped directory is an artefact of one deployment -- a
    # quarantine folder, a dated backup -- not something a product needs.
    (r"/(?:[A-Za-z0-9_.-]*/)*\d{4}-\d{2}-\d{2}-[A-Za-z0-9_-]+/",
     "a date-stamped deployment directory"),
    # A site's own name, a customer's project, an editor plugin's marker:
    # these have no shape at all -- the operator's project name looks like
    # any other word. They cannot live in this table either, because a guard
    # that enumerates the secrets it forbids publishes them. They go in
    # LOCAL_FORBID, which is per-install and never shipped.
    (r"学生|作业批改|成绩|学号|座位表", "personal data belonging to real people"),
)

#: Applies to shipped product files but not to the test suite.
#:
#: The tests exercise banning and netblock escalation, which needs addresses
#: that look genuinely public: the product classifies the RFC 5737 ranges as
#: reserved and would refuse to ban them, so a test using `198.51.100.x` as a
#: "normal" address is testing the wrong branch. The real address of the
#: machine this was developed on is still caught, because it belongs in
#: `tools/source-forbid.txt`, which applies everywhere including tests.
RULES_NOT_IN_TESTS: tuple = (
    (r"\b(?!%s)(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
     r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b"
     % "|".join(ALLOWED_IP_PREFIXES), "a public IP literal"),
)

#: Extensions worth reading. Binaries are excluded from the sweep, but an
#: unexpected binary in the tree is itself reported -- see `scan`.
TEXT_SUFFIXES = frozenset(
    ".py .tmpl .md .json .sh .conf .txt .yml .yaml .toml .cfg .ini .html .js "
    ".css .example .php .lua .service .timer .spec .in".split())

SKIP_DIRS = frozenset({"__pycache__", ".git", ".pytest_cache", "node_modules",
                       ".mypy_cache", ".ruff_cache"})


#: Path *suffixes* exempt from the sweep. A guard necessarily contains the
#: shapes it forbids -- that is what a pattern is -- so the rule table exempts
#: itself. A suffix rather than a repository-relative path, because the command
#: is meant to run against any tree: with the path spelled out, auditing the
#: installed copy reported the rule table as a finding. Found by pointing the
#: new command at /usr/local/lib/vigil, which is exactly what it is for.
#: The tuple is asserted to hold exactly one entry so the exemption cannot
#: grow into a list of files, which would make the whole check optional.
EXEMPT_SUFFIXES = ("vigil/core/sourceaudit.py",)

#: Per-install literals to forbid, one per line as `value` or `value:why`.
#: Kept out of the repository on purpose (see .gitignore): this is where an
#: operator writes their own site name, project name, editor plugin, customer
#: code -- anything that has no shape but must never be published. The file is
#: optional; without it only the generic rules run.
LOCAL_FORBID = "tools/source-forbid.txt"


def local_forbid(root) -> list:
    """(value, why) pairs from the operator's own list, if they keep one."""
    path = Path(root) / LOCAL_FORBID
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        value, _, why = line.partition(":")
        value = value.strip()
        if value:
            out.append((value, why.strip() or "本地禁止清单里的字面量"))
    return out


def shipped_files(root) -> list:
    """Every text file the package would publish.

    Mirrors what ``scripts/package.sh`` copies: the repository minus caches,
    minus anything ignored. Deliberately includes ``tests/``, ``docs/``,
    ``examples/`` and the top-level markdown -- those ship, so they are
    audited.
    """
    root = Path(root)
    out = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.suffix != "":
            continue
        rel = str(path.relative_to(root))
        # The operator's own forbid list and the rule table are the two files
        # that cannot be judged by the rules: one defines them, the other
        # necessarily contains the values.
        if rel.endswith(EXEMPT_SUFFIXES) or rel == LOCAL_FORBID:
            continue
        out.append(path)
    return out


def _is_test(rel: str) -> bool:
    """Is this path part of the test suite?

    Tests are shipped, so they are scanned -- but they are allowed to contain
    public IP literals, for the reason given at RULES_NOT_IN_TESTS.
    """
    return rel.startswith("tests/") or "/tests/" in rel


def scan(root) -> list:
    """Findings as dicts: path, line, text, why."""
    root = Path(root)
    product_only = [(re.compile(p), why) for p, why in RULES_NOT_IN_TESTS]
    local = [(re.compile(re.escape(v)), why) for v, why in local_forbid(root)]
    findings = []
    for path in shipped_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        rules = list(RULES) if not _is_test(rel) else []
        compiled = [(re.compile(p), why) for p, why in rules]
        if not _is_test(rel):
            compiled += product_only
        compiled += local
        for rx, why in compiled:
            for m in rx.finditer(text):
                findings.append({
                    "path": str(path.relative_to(root)),
                    "line": text.count("\n", 0, m.start()) + 1,
                    "text": m.group(0)[:80],
                    "why": why,
                })
    return findings


def summarise(findings) -> str:
    """A short report, grouped by file, for a terminal."""
    if not findings:
        return "no host-specific data found"
    by_file = {}
    for f in findings:
        by_file.setdefault(f["path"], []).append(f)
    lines = []
    for path in sorted(by_file):
        rows = by_file[path]
        lines.append("  %s  (%d)" % (path, len(rows)))
        for r in rows[:6]:
            lines.append("      line %-5d %-30s %s"
                         % (r["line"], r["text"], r["why"]))
        if len(rows) > 6:
            lines.append("      ... 另有 %d 处" % (len(rows) - 6))
    return "\n".join(lines)
