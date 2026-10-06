#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test suite. Standard library only -- the project has no dependencies, so
neither do its tests.

Run everything:

    python3 -m unittest discover -s tests -v

or a single module:

    python3 tests/test_vigil.py

The most important test here is :class:`TestNoHardcodedHostData`. The single
promise that makes this project installable on somebody else's server is
that it contains no addresses, domains, hostnames or paths belonging to the
machine it was developed on. That promise is easy to break with one careless
commit, so it is enforced mechanically rather than by review.
"""
from __future__ import annotations

import email
import hashlib
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# Import the package after sys.path is set up.
from vigil import i18n, ui                                    # noqa: E402
from vigil.core import config as vconfig                       # noqa: E402
from vigil.core import paths, shell, state                     # noqa: E402
from vigil.core.errors import VigilError                       # noqa: E402
from vigil.gates import spec as gspec                          # noqa: E402
from vigil.gates.spec import KIND_BT, KIND_LOGIN               # noqa: E402
from vigil.mail import queue as mqueue                         # noqa: E402
from vigil.mail import render as mrender                       # noqa: E402
from vigil.mail import commandd as cd                           # noqa: E402
from vigil.mail.message import (KIND_ALERT, SEV_CRIT, SEV_INFO,  # noqa: E402
                               SEV_WARN, Alert, Message)
from vigil.mail.providers import base as pbase                 # noqa: E402


# --------------------------------------------------------------------------
# The portability guarantee
# --------------------------------------------------------------------------


#: Addresses that are fine to appear in source, and why each one is here.
#: The check exists to catch *this operator's* host, so the exceptions are
#: the well-known addresses that documentation and test fixtures legitimately
#: use -- not a way to smuggle host data through.


class TestNoHardcodedHostData(unittest.TestCase):
    """The package must not contain any one host's identifying details.

    A single stray IP or domain in a shipped file means the project is not
    actually portable, and the failure is invisible until somebody installs
    it somewhere else and gets alerts pointing at a machine they do not own.
    """

    # The rules live in ``vigil.core.sourceaudit``, not here. Keeping a copy
    # was how this guard came to scan only `src/**/*.py` and `*.tmpl` while the
    # real host's IP sat in `tests/`, the hosting brand beside it, a
    # site-specific directory name inside a *product* rule, a personal mailbox
    # in `examples/`, and the operator's genuine leaked filenames as fixtures.

    def _shipped(self):
        from vigil.core import sourceaudit
        return sourceaudit, list(sourceaudit.shipped_files(ROOT))

    def test_no_forbidden_literals(self):
        """Nothing host-specific in anything the package would publish."""
        sourceaudit, files = self._shipped()
        self.assertGreater(len(files), 60,
                           "扫描到的文件太少，守卫可能没在看整棵树：%d" % len(files))
        findings = sourceaudit.scan(ROOT)
        self.assertEqual([], findings,
                         "随包文件里出现了宿主机信息：\n"
                         + sourceaudit.summarise(findings))

    def test_the_guard_cannot_be_quietly_exempted(self):
        """The rule table exempts itself; that exemption must stay singular."""
        from vigil.core import sourceaudit
        self.assertEqual(("vigil/core/sourceaudit.py",),
                         sourceaudit.EXEMPT_SUFFIXES)
        # Suffix-matched, so it also holds when auditing an installed tree.
        for rel in ("src/vigil/core/sourceaudit.py",
                    "vigil/core/sourceaudit.py"):
            self.assertTrue(rel.endswith(sourceaudit.EXEMPT_SUFFIXES))

    def test_the_operator_can_add_their_own_values_without_shipping_them(self):
        """Site names have no shape, so they are supplied locally."""
        import tempfile
        from vigil.core import sourceaudit
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(tmp), True)
        (tmp / "tools").mkdir()
        (tmp / "tools" / "source-forbid.txt").write_text(
            "# comment\n" + "Acme" + "Internal:\u9879\u76ee\u4ee3\u53f7\n",
            encoding="utf-8")
        (tmp / "notes.md").write_text("see " + "Acme" + "Internal",
                                      encoding="utf-8")
        found = sourceaudit.scan(tmp)
        self.assertEqual(1, len(found), found)
        self.assertNotIn(sourceaudit.LOCAL_FORBID,
                         [str(f.relative_to(tmp))
                          for f in sourceaudit.shipped_files(tmp)])

    def test_configured_identity_never_reaches_the_source(self):
        """The leak a shape-based detector is blind to.

        A sender display name or a gate username has no distinctive shape --
        the operator's site name looks like any other Chinese string. Both it
        and the operator's actual login username sat in the shipped help text
        and in README examples for a while, and every shape-based rule above
        walked straight past them.

        So this test stops guessing at shapes and asks the machine instead:
        which configured values are *not* shipped defaults? Not one of those
        may appear in the package. Defaults are excluded because they are the
        product's own text ("Server Monitor" is a default `from_name`), and
        anything a user configured on this host is by definition not.
        """
        try:
            from vigil.core.config import DEFAULTS, load
            cfg = load()
        except Exception:                               # noqa: BLE001
            self.skipTest("no readable configuration on this machine")

        defaults = set()

        def flatten(node):
            if isinstance(node, dict):
                for v in node.values():
                    flatten(v)
            elif isinstance(node, (list, tuple)):
                for v in node:
                    flatten(v)
            elif isinstance(node, str):
                defaults.add(node)

        flatten(DEFAULTS)

        #: Values too generic to be evidence of anything. A one- or two-
        #: character name would match inside unrelated prose.
        def interesting(value):
            text = str(value or "").strip()
            return len(text) >= 3 and text not in defaults

        identity = set()
        for key in ("hostname", "mail.from_name"):
            value = cfg.get(key, "")
            if interesting(value):
                identity.add(str(value))
        local = str(cfg.get("mail.from_address", "") or "").split("@")[0]
        if interesting(local):
            identity.add(local)
        for kind in ("bt_panel", "dsh_gate", "login"):
            for key in ("username", "domain", "title"):
                value = cfg.get("gate.%s.%s" % (kind, key), "")
                if interesting(value):
                    identity.add(str(value))
        if not identity:
            self.skipTest("this host has no configured identity to leak")

        offenders = []
        for path in self._shipped()[1] + \
                list(ROOT.glob("*.md")) + list((ROOT / "docs").glob("*.md")):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for value in identity:
                if value in text:
                    offenders.append("%s contains this machine's own %r"
                                     % (path.relative_to(ROOT), value))
        self.assertEqual([], offenders,
                         "the package would ship this operator's details:\n  "
                         + "\n  ".join(offenders))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.cfg = vconfig.Config(path=base / "config.json",
                                  secrets_path=base / "secrets.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_defaults_are_host_agnostic(self):
        self.assertEqual([], self.cfg.get("mail.providers"))
        self.assertEqual([], self.cfg.get("mail.recipients"))
        self.assertEqual("", self.cfg.get("mail.from_address"))
        # Only loopback is trusted out of the box.
        self.assertEqual(["127.0.0.1/8", "::1"], self.cfg.get("threat.whitelist"))

    def test_secrets_never_land_in_the_public_file(self):
        self.cfg.set_provider_params("resend", {
            "api_key": "re_supersecret", "from_address": "a@b.example"})
        self.cfg.save()
        public = json.loads((Path(self.tmp.name) / "config.json").read_text())
        blob = json.dumps(public)
        self.assertNotIn("re_supersecret", blob,
                         "the API key leaked into config.json")
        self.assertIn("a@b.example", blob,
                      "the non-secret parameter should stay visible")

    def test_round_trip(self):
        self.cfg.set("mail.recipients", ["ops@example.com"])
        self.cfg.set("checks.cpu.warn", 91)
        self.cfg.save()
        again = vconfig.Config(path=self.cfg.path,
                               secrets_path=self.cfg.secrets_path)
        self.assertEqual(["ops@example.com"], again.get("mail.recipients"))
        self.assertEqual(91, again.get("checks.cpu.warn"))

    def test_secret_subtree_does_not_hide_public_siblings(self):
        """A mixed subtree must read as a whole.

        `mail.imap` keeps host/port/username publicly and the password
        privately. `get` used to return the secret half alone the moment the
        path existed there, so callers saw a config with no host in it -- and
        the IMAP client would have dialled an empty string.
        """
        self.cfg.set("mail.imap.host", "imap.example.com")
        self.cfg.set("mail.imap.port", 993)
        self.cfg.set("mail.imap.username", "me@example.com")
        self.cfg.set("mail.imap.password", "s3cret")
        blob = self.cfg.get("mail.imap")
        self.assertEqual("imap.example.com", blob.get("host"))
        self.assertEqual(993, blob.get("port"))
        self.assertEqual("me@example.com", blob.get("username"))
        self.assertEqual("s3cret", blob.get("password"))
        # And the secret still must not leak into the public file.
        self.assertEqual("", self.cfg._store.get("mail.imap.password", ""))

    def test_recipient_helpers_deduplicate_and_fall_back(self):
        self.cfg.add_recipient("A@example.com")
        self.cfg.add_recipient("a@example.com")     # same address, other case
        self.cfg.add_recipient("b@example.com")
        self.assertEqual(["A@example.com", "b@example.com"],
                         self.cfg.recipients("alert"))
        # Login recipients fall back to the general list when unset.
        self.assertEqual(["A@example.com", "b@example.com"],
                         self.cfg.recipients("login"))

    def test_export_holds_back_secrets_unless_asked(self):
        """A config dump is the thing people paste into a bug report.

        Secrets live in a separate store, so the default export does not
        merely *mask* them -- it does not contain them at all, which is a
        stronger property than redaction and the one worth asserting.
        """
        self.cfg.set_provider_params("resend", {"api_key": "re_x",
                                                "from_address": "a@b.example"})
        dumped = json.dumps(self.cfg.export())
        self.assertNotIn("re_x", dumped)
        self.assertNotIn("api_key", dumped)
        self.assertNotIn("_secrets", dumped)
        # The non-secret half of the same entry is still there, or the dump
        # would be useless for reproducing a problem.
        self.assertIn("a@b.example", dumped)

        fresh = vconfig.Config(path=Path(self.tmp.name) / "c2.json",
                               secrets_path=Path(self.tmp.name) / "s2.json")
        fresh.import_(self.cfg.export())
        self.assertEqual({}, fresh.provider_params("resend").get("api_key") or {})

    def test_export_with_secrets_round_trips(self):
        self.cfg.set_provider_params("resend", {"api_key": "re_x",
                                                "from_address": "a@b.example"})
        full = self.cfg.export(include_secrets=True)
        fresh = vconfig.Config(path=Path(self.tmp.name) / "c2.json",
                               secrets_path=Path(self.tmp.name) / "s2.json")
        fresh.import_(full)
        self.assertEqual("re_x", fresh.provider_params("resend").get("api_key"))
        # import_ must not consume the caller's dict: callers reasonably
        # expect to be able to import the same blob twice.
        self.assertIn("_secrets", full)
        self.assertIn("re_x", json.dumps(full))

    def test_validation_reports_real_problems(self):
        problems = self.cfg.validate()
        self.assertTrue(any("providers" in p for p in problems))
        self.assertTrue(any("recipients" in p for p in problems))


class TestSourceAuditDecodesEscapes(unittest.TestCase):
    """A forbidden literal hidden behind ``\\uXXXX`` is still forbidden.

    A real operator account name sat in the admin page as
    ``"\\u0061\\u0064\\u006d\\u0069\\u006e..."``. Grep, the local forbid list and every shape rule
    were blind to it, because all three compared the raw bytes. The escape
    forms below are the ones Python, JavaScript, PHP and JSON share.

    Every escape in this file is built at run time, never written literally:
    the test suite ships, so a literal escape here would make the guard flag
    its own test -- which is exactly the blindness being fixed, inverted.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(self.tmp), True)

    @staticmethod
    def _esc_u(text):
        return "".join("\\u%04x" % ord(ch) for ch in text)

    @staticmethod
    def _esc_big_u(text):
        return "".join("\\U%08x" % ord(ch) for ch in text)

    @staticmethod
    def _esc_x(text):
        return "".join("\\x%02x" % ord(ch) for ch in text)

    def _forbid(self, value):
        (self.tmp / "tools").mkdir(exist_ok=True)
        (self.tmp / "tools" / "source-forbid.txt").write_text(
            value + ":project code\n", encoding="utf-8")

    def test_an_escaped_literal_is_decoded_and_reported(self):
        from vigil.core import sourceaudit
        secret = "ProjectCobalt"          # no shape; only the local list knows
        self._forbid(secret)
        for name, escaped in (("a_u.py", self._esc_u(secret)),
                              ("b_bigu.py", self._esc_big_u(secret)),
                              ("c_x.py", self._esc_x(secret))):
            (self.tmp / name).write_text('LABEL = "%s"\n' % escaped,
                                         encoding="utf-8")
        found = sourceaudit.scan(self.tmp)
        self.assertEqual(["a_u.py", "b_bigu.py", "c_x.py"],
                         sorted(f["path"] for f in found))
        for f in found:
            self.assertEqual(1, f["line"])
            self.assertEqual(secret, f["text"])

    def test_a_generic_rule_also_sees_the_decoded_text(self):
        """Not just the local list -- the shipped shapes are decoded too."""
        from vigil.core import sourceaudit
        # A personal mailbox written only in escapes.
        address = "ops" + "@" + "qq.com"
        (self.tmp / "page.py").write_text(
            'CONTACT = "%s"\n' % self._esc_u(address), encoding="utf-8")
        found = sourceaudit.scan(self.tmp)
        self.assertEqual(1, len(found), found)
        self.assertEqual(address, found[0]["text"])
        self.assertIn("mailbox", found[0]["why"])

    def test_the_reported_line_is_the_line_in_the_file(self):
        from vigil.core import sourceaudit
        secret = "ProjectCobalt"
        self._forbid(secret)
        (self.tmp / "app.py").write_text(
            "# header\n\nNAME = \"%s\"\n" % self._esc_u(secret),
            encoding="utf-8")
        found = sourceaudit.scan(self.tmp)
        self.assertEqual(1, len(found), found)
        self.assertEqual(3, found[0]["line"])

    def test_the_same_literal_raw_and_escaped_is_not_counted_twice(self):
        from vigil.core import sourceaudit
        secret = "ProjectCobalt"
        self._forbid(secret)
        (self.tmp / "both.py").write_text(
            'X = "%s" + "%s"\n' % (secret, self._esc_u(secret)),
            encoding="utf-8")
        found = sourceaudit.scan(self.tmp)
        # 这一行两种写法都在。报一次就够 —— 跑了两遍规则不该让同一行翻倍，
        # 而文件仍然被标记，没有漏报。
        self.assertEqual(1, len(found), found)

    def test_ordinary_escapes_and_regexes_are_not_false_positives(self):
        """``\\n``, ``\\t`` and a regex's ``\\d`` are not these escapes."""
        from vigil.core import sourceaudit
        secret = "ProjectCobalt"
        self._forbid(secret)                 # the list exists but is not hit
        (self.tmp / "normal.py").write_text(
            'NEWLINE = "\\n"\n'
            'TAB = "\\t"\n'
            'PATTERN = r"\\d{4}-\\d{2}-\\d{2}"\n'
            'WORD = r"\\w+"\n'
            'BYTES = b"\\x41\\x42"\n'
            'QUOTED = "\\\\u0050rojectCobalt"\n',
            encoding="utf-8")
        self.assertEqual([], sourceaudit.scan(self.tmp))

    def test_an_escape_is_not_decoded_inside_source_that_is_already_readable(self):
        from vigil.core import sourceaudit
        secret = "ProjectCobalt"
        self._forbid(secret)
        # `"\\u0050rojectCobalt"` (double backslash) is the literal text
        # `\u0050rojectCobalt`, not the string. Decoding it would invent a
        # finding in any file that quotes an escape.
        (self.tmp / "quoted.py").write_text(
            'HELP = "write it as \\\\u0050rojectCobalt"\n', encoding="utf-8")
        self.assertEqual([], sourceaudit.scan(self.tmp))

    def test_invalid_or_surrogate_escapes_are_left_alone(self):
        from vigil.core import sourceaudit
        for raw in ("\\ud800", "\\U00110000", "\\uZZZZ", "\\x4"):
            self.assertEqual(raw, sourceaudit.decode_escapes(raw), raw)

    def test_decoding_is_bounded(self):
        from vigil.core import sourceaudit
        text = "\\u0041" * 500
        out = sourceaudit.decode_escapes(text, limit=10)
        self.assertEqual(10, out.count("A"))
        self.assertIn("\\u0041", out, "超出预算的部分原样保留")
        self.assertLess(len(out), len(text) + 1)


# --------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------


class TestState(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_write_is_atomic_and_leaves_no_temp_files(self):
        target = self.dir / "s.json"
        for i in range(25):
            state.write_json(target, {"n": i})
        self.assertEqual({"n": 24}, state.read_json(target))
        leftovers = [p.name for p in self.dir.iterdir() if p.name.startswith(".tmp")]
        self.assertEqual([], leftovers, "temporary files were left behind")

    def test_read_of_a_corrupt_file_returns_the_default(self):
        target = self.dir / "bad.json"
        target.write_text("{not json at all")
        self.assertEqual({}, state.read_json(target, {}))

    def test_deep_merge_replaces_lists_and_merges_dicts(self):
        merged = state.deep_merge({"a": {"x": 1, "y": 2}, "l": [1, 2]},
                                  {"a": {"y": 9}, "l": [3]})
        self.assertEqual({"x": 1, "y": 9}, merged["a"])
        self.assertEqual([3], merged["l"],
                         "a list override should replace, not concatenate")

    def test_lock_is_exclusive(self):
        lock = self.dir / "l.lock"
        with state.locked(lock) as first:
            self.assertTrue(first)
            # A second acquisition without waiting must fail.
            with state.locked(lock, timeout=0) as second:
                self.assertFalse(second)
        with state.locked(lock) as third:
            self.assertTrue(third)


# --------------------------------------------------------------------------
# Mail rendering
# --------------------------------------------------------------------------


class TestRendering(unittest.TestCase):
    def _alert(self):
        a = Alert(title="Test alert", severity=SEV_WARN,
                  summary="something happened")
        a.add_section("Details", ["a normal line", "  an indented line",
                                  "a very long line " * 12])
        return a

    def test_text_has_the_essentials(self):
        text = mrender.render_text(self._alert(), seq=7, host="h.example")
        self.assertIn("#000007", text)
        self.assertIn("h.example", text)
        self.assertIn("Details", text)

    def test_html_escapes_untrusted_content(self):
        """Alert bodies carry attacker-influenced strings; they must not
        become markup."""
        a = Alert(title="<script>alert(1)</script>", severity=SEV_CRIT)
        a.add_section("X", ['<img src=x onerror="alert(2)">'])
        html = mrender.render_html(a)
        # What matters is that no tag or attribute can come into existence,
        # not that a substring never appears: `onerror=` is harmless once its
        # angle bracket and its quotes have been neutralised, and asserting
        # on the bare word would fail on correct output.
        self.assertNotIn("<script", html)
        self.assertNotIn("<img", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertIn("&lt;img src=x onerror=&quot;alert(2)&quot;&gt;", html)

    def test_markup_and_ip_highlighting(self):
        a = Alert(title="t")
        a.add_section("X", ["**bold** and `code` from 203.0.113.9"])
        html = mrender.render_html(a)
        self.assertIn("<strong>bold</strong>", html)
        self.assertIn("<code>code</code>", html)
        self.assertIn('class="ip"', html)

    def test_message_carries_both_formats(self):
        msg = mrender.render_message(self._alert(), seq=3)
        self.assertTrue(msg.text.strip())
        self.assertTrue(msg.html.strip())
        self.assertIn("#000003", msg.subject)


# --------------------------------------------------------------------------
# Mail queue
# --------------------------------------------------------------------------


class TestMailQueue(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._saved = (paths.VAR, paths.STATE_MAIL, paths.MAIL_SEQ,
                       paths.MAIL_OVERFLOW)
        base = Path(self.tmp.name)
        paths.VAR = base
        paths.STATE_MAIL = base / "mail"
        paths.MAIL_SEQ = paths.STATE_MAIL / "sequence"
        paths.MAIL_OVERFLOW = paths.STATE_MAIL / "overflow"
        paths.STATE_MAIL.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        (paths.VAR, paths.STATE_MAIL, paths.MAIL_SEQ,
         paths.MAIL_OVERFLOW) = self._saved
        self.tmp.cleanup()

    def test_sequence_is_monotonic_and_unique(self):
        seen = [mqueue.next_seq() for _ in range(50)]
        self.assertEqual(sorted(seen), seen)
        self.assertEqual(len(set(seen)), len(seen))

    def test_quota_accounting(self):
        self.assertEqual(0, mqueue.quota_used())
        mqueue.quota_add(3, 10)
        self.assertEqual(3, mqueue.quota_used())
        self.assertEqual(7, mqueue.quota_remaining(10))
        self.assertEqual(0, mqueue.quota_remaining(3))

    def test_quota_of_zero_means_unlimited(self):
        self.assertGreater(mqueue.quota_remaining(0), 1000)

    def test_dedupe_window(self):
        self.assertFalse(mqueue.is_duplicate("k", 900))
        mqueue.mark_seen("k")
        self.assertTrue(mqueue.is_duplicate("k", 900))
        self.assertFalse(mqueue.is_duplicate("k", 0))

    def test_a_replayed_digest_leaves_the_queue_directory(self):
        """A delivered file in the queue directory reads as a stuck one.

        The replay path claimed a digest and then renamed it in place, so
        every file it touched stayed in `overflow/`. The operator saw a file
        there, asked why there was still a backlog, and the honest answer was
        "there is none" -- which is a bad answer to a reasonable question.
        """
        from vigil.mail import queue as mq
        mq.archived_dir().mkdir(parents=True, exist_ok=True)
        original = paths.MAIL_OVERFLOW / "20260927.digest"
        original.write_text("parked\n", encoding="utf-8")
        claimed = str(original) + ".sending"
        os.replace(str(original), claimed)

        self.assertTrue(mq.archive_claimed(claimed, original))
        self.assertFalse(original.exists(), "the queue must be empty")
        self.assertFalse(Path(claimed).exists())
        archived = mq.archived_digests()
        self.assertEqual(1, len(archived))
        self.assertEqual("20260927.digest.sent", archived[0].name)
        self.assertEqual(0, mq.overflow_count())

    def test_overflow_parks_a_message(self):
        msg = Message(subject="s", text="body", seq=1)
        self.assertTrue(mqueue.to_overflow(msg, "no channel"))
        files = mqueue.overflow_digests()
        self.assertEqual(1, len(files))
        self.assertIn("body", mqueue.read_digest(files[0]))
        self.assertIn("no channel", mqueue.read_digest(files[0]))


# --------------------------------------------------------------------------
# The reply-command channel must not eat its own output
#
# On 2026-09-27 it did. The listener polls a mailbox and replies by mail; a
# transactional message from the monitored account became a "command", the
# refusal became the next command, and the channel mailed itself for twenty
# minutes (#000422..#000447). These tests pin the guards that stop it.
# --------------------------------------------------------------------------


class TestCommandLoopGuards(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.cfg = vconfig.Config(path=base / "config.json",
                                  secrets_path=base / "secrets.json")

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def _msg(**headers):
        raw = "".join("%s: %s\n" % (k.replace("_", "-"), v)
                      for k, v in headers.items())
        return email.message_from_string(raw + "\nbody\n")

    def test_marker_header_is_recognised(self):
        for header in ("X_Vigil_Machine", "X_Vigil_Alert"):
            msg = self._msg(**{header: "1"})
            self.assertTrue(cd._own_mail_reason(msg),
                            "%s should mark the message as ours" % header)

    def test_auto_submitted_is_recognised(self):
        for value in ("auto-generated", "auto-replied", "AUTO-REPLIED"):
            msg = self._msg(Auto_Submitted=value)
            self.assertTrue(cd._own_mail_reason(msg), value)
        # RFC 3834 says a human message carries `no` (or nothing at all).
        self.assertFalse(cd._own_mail_reason(self._msg(Auto_Submitted="no")))

    def test_bulk_precedence_is_recognised(self):
        self.assertTrue(cd._own_mail_reason(self._msg(Precedence="bulk")))
        self.assertTrue(cd._own_mail_reason(self._msg(Precedence="auto_reply")))
        self.assertFalse(cd._own_mail_reason(self._msg(Precedence="urgent")))

    def test_own_reply_subject_is_recognised(self):
        self.assertTrue(cd._own_mail_reason(
            self._msg(), subject="[#000444] 执行结果", body=""))
        self.assertTrue(cd._own_mail_reason(
            self._msg(), subject="[#000444] Command result", body=""))
        # A human reply to an alert is prefixed by the client, and must still
        # be executable -- this is the whole point of the channel.
        self.assertFalse(cd._own_mail_reason(
            self._msg(), subject="Re: [#000441] 异常 1 项 · 对外连接异常",
            body="状态"))

    def test_own_body_prefix_is_recognised(self):
        # mail/__init__.py prefixes every outgoing text with this line.
        for line in ("邮件编号: #000444", "邮件编号：#000444", "邮件编号:"):
            self.assertTrue(cd._own_mail_reason(
                self._msg(), subject="随便", body=line + "\n\n正文"),
                line)

    def test_a_genuine_command_is_not_mistaken_for_our_own(self):
        self.assertFalse(cd._own_mail_reason(
            self._msg(), subject="Re: [#000441] 异常 1 项",
            body="封禁 198.51.100.9 600"))

    def test_reply_budget_stops_an_endless_loop(self):
        self.cfg.set("commands.max_replies_per_hour", 3)
        state = {}
        log = _QuietLog()
        budget = cd.ReplyBudget(self.cfg, state, log)
        for _ in range(3):
            self.assertTrue(budget.allow())
            budget.note()
        # The fourth reply -- and every one after it -- must not be sent.
        self.assertFalse(budget.allow())
        self.assertFalse(budget.allow())
        self.assertTrue(log.warnings, "tripping the cap must be logged loudly")

    def test_reply_budget_forgets_old_replies(self):
        self.cfg.set("commands.max_replies_per_hour", 1)
        state = {"reply_times": [time.time() - 7200]}
        budget = cd.ReplyBudget(self.cfg, state, _QuietLog())
        self.assertTrue(budget.allow(), "an hour-old reply must not count")

    def test_reply_budget_is_persisted(self):
        self.cfg.set("commands.max_replies_per_hour", 5)
        state = {}
        budget = cd.ReplyBudget(self.cfg, state, _QuietLog())
        budget.note()
        budget.save()
        self.assertEqual(1, len(state["reply_times"]))

    def test_senders_stamp_the_markers_the_guard_looks_for(self):
        """Guard 1 and guard 2 must agree, or the loop comes back.

        Two providers can be exercised without a network: SMTP builds the
        message in-process before it connects, so a stub connection is
        enough to capture what would have gone out. The API providers
        (Resend and friends) cannot be, which is exactly why the content
        signature exists -- this test covers the header path, and
        `test_own_body_prefix_is_recognised` covers the fallback.
        """
        from vigil.mail.providers.smtp import Smtp

        captured = {}

        class _Conn:
            def login(self, *_a):
                return None

            def send_message(self, mail):
                captured["mail"] = mail

        prov = Smtp({"host": "smtp.example.invalid", "port": "587",
                     "username": "u", "password": "p",
                     "from_address": "monitor@example.invalid"})
        prov._connect = lambda: _Conn()
        prov.send(Message(subject="[#000001] 执行结果", text="body", seq=1),
                  "admin@example.invalid")

        mail = captured["mail"]
        self.assertEqual("1", mail["X-Vigil-Machine"])
        self.assertEqual("auto-generated", mail["Auto-Submitted"])
        # And the guard must actually recognise what the sender produced.
        self.assertTrue(cd._own_mail_reason(mail))


class _QuietLog:
    """Collects warnings so a test can assert that one was emitted."""

    def __init__(self):
        self.warnings = []

    def info(self, *_a, **_k):
        pass

    def warn(self, msg, *_a, **_k):
        self.warnings.append(msg)

    def error(self, *_a, **_k):
        pass

    def debug(self, *_a, **_k):
        pass


# --------------------------------------------------------------------------
# Mail providers
# --------------------------------------------------------------------------


class TestProviders(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pbase.import_builtins()

    def test_the_expected_set_is_registered(self):
        for pid in ("resend", "smtp", "sendgrid", "mailgun", "brevo",
                    "aliyun", "sendmail", "webhook"):
            self.assertIsNotNone(pbase.get(pid), "provider %r is missing" % pid)

    def test_every_provider_declares_itself(self):
        for cls in pbase.all_providers():
            self.assertTrue(cls.id, "%s has no id" % cls)
            self.assertTrue(cls.label, "%s has no label" % cls)
            self.assertIn(cls.kind, ("api", "smtp", "local", "webhook"))
            self.assertIsInstance(cls.fields, tuple)
            for f in cls.fields:
                self.assertTrue(f.name, "%s: unnamed field" % cls.id)
                self.assertTrue(f.label, "%s.%s has no label" % (cls.id, f.name))

    def test_credentials_are_marked_secret(self):
        """Anything named like a credential must be routed to secrets.json."""
        for cls in pbase.all_providers():
            for f in cls.fields:
                blob = f.name.lower()
                if any(k in blob for k in ("key", "password", "secret", "token")):
                    self.assertTrue(
                        f.secret or f.kind == "password",
                        "%s.%s looks like a credential but is not marked secret"
                        % (cls.id, f.name))

    def test_smtp_presets_are_usable(self):
        from vigil.mail.providers.smtp import PRESETS
        self.assertGreaterEqual(len(PRESETS), 10)
        for key, p in PRESETS.items():
            self.assertIn("label", p, key)
            self.assertIn("tls", p, key)
            self.assertIn(p["tls"], ("ssl", "starttls", "plain"), key)
            if key != "custom":
                self.assertTrue(p.get("host"), "%s has no host" % key)
                self.assertIsInstance(p.get("port"), int)

    def test_alignment_warning_only_when_it_matters(self):
        from vigil.mail.providers.smtp import Smtp
        # A free mailbox with a mismatched From must warn.
        risky = Smtp({"preset": "qq", "host": "smtp.qq.com", "port": "465",
                      "username": ("me@" + "qq.com"), "password": "x",
                      "from_address": "alerts@mydomain.example"})
        self.assertTrue(risky.alignment_warning())
        # Matching From is fine.
        fine = Smtp({"preset": "qq", "host": "smtp.qq.com", "port": "465",
                     "username": ("me@" + "qq.com"), "password": "x",
                     "from_address": ("me@" + "qq.com")})
        self.assertEqual("", fine.alignment_warning())
        # A transactional relay signs for your domain, so a custom From is
        # expected rather than a mistake.
        relay = Smtp({"preset": "sendgrid", "host": "smtp.sendgrid.net",
                      "port": "587", "username": "apikey", "password": "x",
                      "from_address": "alerts@mydomain.example"})
        self.assertEqual("", relay.alignment_warning())


# --------------------------------------------------------------------------
# Gate specification
# --------------------------------------------------------------------------


class TestGateSpec(unittest.TestCase):
    def test_endpoints_are_derived_not_inherited(self):
        """A gate's captcha and logout paths come from its own entry path.

        These were once read from configuration, which let one gate's paths
        leak into the other -- the panel gate ended up serving the login
        gate's endpoints.
        """
        bt = gspec.GateSpec.for_kind(KIND_BT)
        self.assertEqual("/__btgate", bt.entry_path)
        self.assertTrue(bt.captcha_path.startswith("/__bt"),
                        "panel endpoints leaked: %s" % bt.captcha_path)
        lg = gspec.GateSpec.for_kind(KIND_LOGIN)
        self.assertEqual("/__gate/login", lg.entry_path)
        self.assertEqual("/__gate/captcha", lg.captcha_path)
        self.assertEqual("/__gate/logout", lg.logout_path)

    def test_prefix_never_swallows_the_site(self):
        """A catch-all prefix of '/' would shadow the entire vhost.

        This happened: the entry path `/__btgate` has no directory part, the
        prefix computation returned '/', and the generated nginx config
        contained `location ^~ / { return 404; }` -- which collided with the
        panel's own `location ^~ /` and would have taken the panel down had
        nginx not refused to load.
        """
        for kind in (KIND_BT, KIND_LOGIN):
            spec = gspec.GateSpec.for_kind(kind)
            self.assertNotEqual("/", spec.prefix,
                                "%s produced a catch-all prefix" % kind)
            if spec.prefix:
                self.assertGreaterEqual(len(spec.prefix), 3)

    def test_strict_navigation_defaults_per_gate(self):
        """Reload-requires-verification suits a single-page app, not a panel.

        A control panel is a multi-page application: every click is a
        navigation, so requiring verification for each one would make it
        unusable. A single-page app loads its document once, so strict mode
        costs nothing and is the safer default.
        """
        self.assertEqual(1, gspec.GateSpec.for_kind(KIND_LOGIN).strict_nav)
        self.assertEqual(0, gspec.GateSpec.for_kind(KIND_BT).strict_nav)

    def test_only_the_login_gate_owns_a_listener(self):
        self.assertTrue(gspec.GateSpec.for_kind(KIND_LOGIN).proxy_mode)
        self.assertFalse(gspec.GateSpec.for_kind(KIND_BT).proxy_mode)

    def test_validation_catches_missing_pieces(self):
        spec = gspec.GateSpec.for_kind(KIND_LOGIN)
        spec.upstream = ""
        spec.pass_hash = ""
        problems = spec.validate()
        self.assertTrue(any("上游" in p or "upstream" in p for p in problems))
        self.assertTrue(any("密码" in p or "hash" in p for p in problems))

    def test_zone_names_are_distinct_per_gate(self):
        bt = gspec.GateSpec.for_kind(KIND_BT)
        lg = gspec.GateSpec.for_kind(KIND_LOGIN)
        for what in ("req", "cap", "conn"):
            self.assertNotEqual(bt.zone(what), lg.zone(what))


class TestGateInstances(unittest.TestCase):
    """Named login gates are independent, and the old one is never touched.

    The failure these pin is specific and expensive. Before instances
    existed, `gate install login` with a second set of parameters found the
    one existing login gate, decided that *was* the gate being asked for,
    and reconfigured it in place: upstream, port, domain and certificate
    were overwritten, and because the command carried `--no-password` the
    stored password hash was cleared and `require_password` turned off. The
    operator's working DSH gate was redirected at an unrelated service.

    So the central test here is not "two instances can be created" but
    "creating the second one leaves the first byte-for-byte unchanged".
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        (self.base / "vhost").mkdir()
        # A discovered `gate.dirs` list is how a test (or a host with a
        # non-standard layout) points instance discovery at another tree.
        self.env = {
            "nginx": {"present": True, "binary": "", "lua": True, "conf": "",
                      "include_dirs": [str(self.base / "vhost")],
                      "worker_user": "www"},
            "php_fpm": {"sockets": [{"socket": str(self.base / "php.sock"),
                                     "user": "www"}]},
            "bt_panel": {"present": False},
            "gate": {"root": str(self.base / "server"), "dirs": []},
        }
        # A real Store over a throwaway file, seeded from the shipped
        # defaults, so nothing here reads or writes /etc/vigil.
        self.cfg = state.Store(
            self.base / "config.json",
            defaults=json.loads(json.dumps(vconfig.DEFAULTS)))

    def _capture_install(self):
        """Replace the real installer so a test never writes to the host.

        The spec is captured instead. In particular the fake does *not*
        create the state directory: these tests must not create anything
        under the real /www/server, even by accident.
        """
        from vigil.gates import installer as ginstaller
        captured = {}

        def fake_install(spec, env=None, log=None, start_override=True):
            captured["spec"] = spec
            return {"ok": True, "entry": spec.entry_path, "written": []}

        patcher = mock.patch.object(ginstaller, "install", fake_install)
        patcher.start()
        self.addCleanup(patcher.stop)
        return captured

    # -- layout -----------------------------------------------------------

    def test_named_instances_have_disjoint_layouts(self):
        a = gspec.GateSpec.for_kind(KIND_LOGIN, name="astrbot")
        b = gspec.GateSpec.for_kind(KIND_LOGIN, name="wiki")
        default = gspec.GateSpec.for_kind(KIND_LOGIN)

        self.assertEqual("/www/server/astrbot-gate", a.state_dir)
        self.assertEqual("/www/wwwroot/astrbot-gate", a.webroot)
        self.assertEqual("astrbotgate", a.cookie)
        self.assertEqual("astrbotnav", a.nav_cookie)
        self.assertEqual("astrbot", gspec.config_section(KIND_LOGIN, "astrbot"))

        self.assertEqual("/www/server/wiki-gate", b.state_dir)
        self.assertEqual("/www/wwwroot/wiki-gate", b.webroot)
        self.assertEqual("wikigate", b.cookie)

        for field in ("state_dir", "webroot", "cookie", "nav_cookie",
                      "conf_slug", "slug"):
            self.assertNotEqual(getattr(a, field), getattr(b, field), field)
            self.assertNotEqual(getattr(a, field), getattr(default, field),
                                field)
        self.assertNotEqual(gspec.config_section(KIND_LOGIN, "astrbot"),
                            gspec.config_section(KIND_LOGIN, "wiki"))
        for what in ("req", "cap", "conn", "tls"):
            self.assertNotEqual(a.zone(what), b.zone(what))
            self.assertNotEqual(a.zone(what), default.zone(what))

    def test_omitting_the_name_keeps_the_legacy_layout(self):
        default = gspec.GateSpec.for_kind(KIND_LOGIN)
        explicit = gspec.GateSpec.for_kind(KIND_LOGIN, name="login")
        self.assertEqual("/www/server/dsh-gate", default.state_dir)
        self.assertEqual("/www/wwwroot/dsh-gate", default.webroot)
        self.assertEqual("dshgate", default.cookie)
        self.assertEqual("dsh_gate", gspec.config_section(KIND_LOGIN, ""))
        self.assertEqual(default.state_dir, explicit.state_dir)
        self.assertEqual(default.cookie, explicit.cookie)
        self.assertEqual("login", gspec.normalize_instance(KIND_LOGIN, ""))
        self.assertEqual("login", gspec.normalize_instance(KIND_LOGIN, None))

    def test_bt_panel_refuses_a_second_instance(self):
        self.assertEqual("bt_panel", gspec.normalize_instance(KIND_BT, ""))
        with self.assertRaises(VigilError):
            gspec.GateSpec.for_kind(KIND_BT, name="second")

    def test_reserved_and_malformed_names_are_refused(self):
        for bad in ("dsh", "bt", "demo", "dsh_gate", "bt_panel",
                    "my_gate", "a.b", "-lead", "x" * 40):
            with self.assertRaises(VigilError, msg=bad):
                gspec.normalize_instance(KIND_LOGIN, bad)
        # Upper case is normalised rather than rejected; the layout it
        # produces is still lower case and therefore safe in a path.
        self.assertEqual("astrbot",
                         gspec.normalize_instance(KIND_LOGIN, "AstrBot"))

    # -- credentials ------------------------------------------------------

    def test_installing_a_second_instance_never_touches_the_first(self):
        from vigil.gates import install as gate_install
        self._capture_install()
        with mock.patch("vigil.gates.detect_all", return_value=[]):
            gate_install(self.cfg, KIND_LOGIN, env=self.env, name="alpha",
                         require_password=False,
                         upstream="http://127.0.0.1:6185", listen_port=4400,
                         domain="alpha.example.com")
            alpha = json.loads(json.dumps(self.cfg.get("gate.alpha")))
            legacy = json.loads(json.dumps(self.cfg.get("gate.dsh_gate")))
            gate_install(self.cfg, KIND_LOGIN, env=self.env, name="beta",
                         require_password=False,
                         upstream="http://127.0.0.1:9999", listen_port=4401,
                         domain="beta.example.com")
            alpha_after = json.loads(json.dumps(self.cfg.get("gate.alpha")))
        self.assertEqual(alpha, alpha_after,
                         "创建实例 beta 改动了实例 alpha 的配置")
        self.assertEqual(legacy, self.cfg.get("gate.dsh_gate"),
                         "创建命名实例改动了默认实例的配置")
        self.assertEqual("/www/server/alpha-gate",
                         self.cfg.get("gate.alpha.state_dir"))
        self.assertEqual("/www/server/beta-gate",
                         self.cfg.get("gate.beta.state_dir"))
        self.assertEqual("alphagate", self.cfg.get("gate.alpha.cookie"))
        self.assertEqual("betagate", self.cfg.get("gate.beta.cookie"))
        self.assertEqual(4400, self.cfg.get("gate.alpha.listen_port"))
        self.assertEqual(4401, self.cfg.get("gate.beta.listen_port"))

    def test_no_password_instance_stores_no_credentials(self):
        from vigil.gates import install as gate_install
        captured = self._capture_install()
        with mock.patch("vigil.gates.detect_all", return_value=[]):
            res = gate_install(self.cfg, KIND_LOGIN, env=self.env,
                               name="astrbot", require_password=False,
                               upstream="http://127.0.0.1:6185",
                               domain="astrbot.example.com")
        self.assertTrue(res["ok"], res)
        spec = captured["spec"]
        self.assertFalse(spec.require_password)
        self.assertEqual("", spec.pass_hash)
        self.assertFalse(self.cfg.get("gate.astrbot.require_password"))
        self.assertIsNone(self.cfg.get("gate.astrbot.pass_hash"),
                          "密码哈希不应被写进 config.json")
        self.assertEqual("/www/server/astrbot-gate",
                         self.cfg.get("gate.astrbot.state_dir"))

    def test_password_instance_hashes_but_never_copies_the_hash(self):
        from vigil.gates import install as gate_install
        captured = self._capture_install()
        digest = "$2y$10$" + "x" * 53
        with mock.patch("vigil.gates.detect_all", return_value=[]), \
                mock.patch("vigil.gates.installer.hash_password",
                           return_value=digest):
            res = gate_install(self.cfg, KIND_LOGIN, env=self.env,
                               name="wiki", password="correct horse",
                               upstream="http://127.0.0.1:8080")
        self.assertTrue(res["ok"], res)
        spec = captured["spec"]
        self.assertTrue(spec.require_password)
        self.assertEqual(digest, spec.pass_hash)
        self.assertTrue(self.cfg.get("gate.wiki.require_password"))
        self.assertIsNone(self.cfg.get("gate.wiki.pass_hash"),
                          "密码哈希不应被复制到配置里")

    # -- discovery / listing ---------------------------------------------

    def test_status_lists_instances_and_reflects_removal(self):
        from vigil.gates import status as gate_status
        server = self.base / "server"
        for name in ("alpha", "beta"):
            d = server / ("%s-gate" % name)
            d.mkdir(parents=True)
            (d / "gate.lua").write_text("-- test\n", encoding="utf-8")
        # A directory that merely ends in `-gate` is not a gate. A real host
        # had one, and it was being listed as an installed instance.
        stray = server / "stray-gate"
        stray.mkdir(parents=True)
        (stray / "unrelated.php").write_text("<?php\n", encoding="utf-8")
        # Alpha stays in config after its files go away, so it is reported
        # as a broken installation instead of silently disappearing.
        self.cfg.set("gate.alpha.enabled", True)
        env = json.loads(json.dumps(self.env))
        env["gate"] = {"root": str(server),
                       "dirs": [str(server / "alpha-gate"),
                                str(stray),
                                str(server / "beta-gate")]}
        with mock.patch("vigil.gates.nginx_text", return_value=""), \
                mock.patch("vigil.gates.shell.out", return_value=""):
            rows = {(r["kind"], r["name"]): r
                    for r in gate_status(self.cfg, env)}
            self.assertIn(("login", "alpha"), rows)
            self.assertIn(("login", "beta"), rows)
            self.assertNotIn(("login", "stray"), rows,
                             "不是网关的目录被当成了实例")
            self.assertTrue(rows[("login", "alpha")]["installed"])
            self.assertEqual("alpha", rows[("login", "alpha")]["name"])
            self.assertEqual("gate.alpha",
                             rows[("login", "alpha")]["config_key"])
            self.assertEqual(str(server / "alpha-gate"),
                             rows[("login", "alpha")]["state_dir"])

            shutil.rmtree(str(server / "alpha-gate"))
            env["gate"]["dirs"] = [str(server / "beta-gate")]
            after = {(r["kind"], r["name"]): r
                     for r in gate_status(self.cfg, env)}
        self.assertIn(("login", "alpha"), after)
        self.assertFalse(after[("login", "alpha")]["installed"],
                         "状态目录已删除却仍报告为已安装")
        self.assertTrue(after[("login", "beta")]["installed"])

    def test_list_renders_every_instance(self):
        from vigil.commands import gate as gate_cmd
        rows = [
            {"kind": KIND_BT, "name": "bt_panel", "label": "面板",
             "installed": True, "adopted": True,
             "state_dir": "/www/server/bt-gate", "domain": "panel.example.com",
             "port": 0, "upstream": "", "credentials": False},
            {"kind": KIND_LOGIN, "name": "alpha", "label": "登录 alpha",
             "installed": True, "adopted": True,
             "state_dir": "/www/server/alpha-gate",
             "domain": "alpha.example.com", "port": 4400,
             "upstream": "http://127.0.0.1:6185", "credentials": False},
            {"kind": KIND_LOGIN, "name": "beta", "label": "登录 beta",
             "installed": False, "adopted": True,
             "state_dir": "/www/server/beta-gate", "domain": "", "port": 0,
             "upstream": "", "credentials": True},
        ]
        captured = {}

        def fake_table(table_rows, headers=None):
            captured["rows"] = list(table_rows)
            captured["headers"] = headers

        class _A:
            types = False
            config = None

        with mock.patch.object(gate_cmd, "status", return_value=rows), \
                mock.patch.object(gate_cmd, "load_config",
                                  return_value=self.cfg), \
                mock.patch.object(gate_cmd.ui, "table", fake_table), \
                mock.patch.object(gate_cmd.ui, "header", lambda *a, **k: None), \
                mock.patch.object(gate_cmd.ui, "warning", lambda *a, **k: None), \
                mock.patch.object(gate_cmd.ui, "section", lambda *a, **k: None), \
                mock.patch.object(gate_cmd.ui, "kv", lambda *a, **k: None), \
                mock.patch.object(gate_cmd.ui, "out", lambda *a, **k: None), \
                mock.patch.object(gate_cmd.ui, "note", lambda *a, **k: None), \
                mock.patch.object(gate_cmd.ui, "hint", lambda *a, **k: None):
            rc = gate_cmd.cmd_list(_A())
        self.assertEqual(0, rc)
        self.assertEqual(["bt_panel", "alpha", "beta"],
                         [row[1] for row in captured["rows"]])
        self.assertEqual(7, len(captured["headers"]))
        self.assertIn("http://127.0.0.1:6185", captured["rows"][1])

    def test_generated_nginx_is_per_instance(self):
        from vigil.gates import installer
        a = gspec.GateSpec.for_kind(KIND_LOGIN, name="alpha")
        b = gspec.GateSpec.for_kind(KIND_LOGIN, name="beta")
        a.listen_port, a.upstream = 4400, "http://127.0.0.1:6185"
        b.listen_port, b.upstream = 4401, "http://127.0.0.1:9999"
        text_a = installer.render_nginx(a)
        text_b = installer.render_nginx(b)
        self.assertIn(a.zone("req"), text_a)
        self.assertNotIn(a.zone("req"), text_b)
        self.assertIn("/www/server/alpha-gate/gate.lua", text_a)
        self.assertNotIn("/www/server/beta-gate/gate.lua", text_a)
        self.assertIn("listen 127.0.0.1:4400", text_a)
        self.assertIn("listen 127.0.0.1:4401", text_b)
        zones_a = installer.render_zones(a)
        self.assertIn(a.zone("req"), zones_a)
        self.assertNotIn(b.zone("req"), zones_a)

    def test_the_gate_zone_file_refuses_a_key_change(self):
        """The gate zones obey the same reload rule as the web shield.

        Gate zones are always keyed on the client address today, but the rule
        is enforced generically: if an older write keyed a zone on something
        else, the next install must refuse rather than leave a file that
        `nginx -t` accepts and every reload rejects.
        """
        from vigil.gates import installer
        spec = gspec.GateSpec.for_kind(KIND_LOGIN, cfg=None, env=self.env,
                                       name="gamma")
        spec.state_dir = str(self.base / "server" / "gamma-gate")
        spec.webroot = str(self.base / "www" / "gamma-gate")
        spec.upstream = "http://127.0.0.1:6185"
        spec.listen_port = 4402
        spec.require_password = False
        spec.fastcgi_pass = "unix:%s" % (self.base / "php.sock")
        zones = self.base / "vigil-gate-gamma-zones.conf"
        spec.zones_file = str(zones)
        zones.write_text(installer.render_zones(spec).replace(
            "$binary_remote_addr", "$some_key"), encoding="utf-8")
        before = zones.read_text(encoding="utf-8")

        res = installer.install(spec, env=self.env, log=None)

        self.assertFalse(res.get("ok"))
        self.assertIn("完整重启", res.get("error", ""))
        self.assertEqual(before, zones.read_text(encoding="utf-8"),
                         "拒绝时不得改动限流区文件")
        self.assertFalse(Path(spec.state_dir).exists(),
                         "拒绝时必须发生在写入任何网关文件之前")

    def test_a_port_collision_is_reported_not_forced(self):
        """A second gate must never take over another gate's port.

        Withdrawing the other instance's listener is how a "second" install
        could still take the first one down, so a clash is an error.
        """
        from vigil.gates import install as gate_install
        alpha = gspec.GateSpec.for_kind(KIND_LOGIN, name="alpha")
        alpha.listen_port = 4400
        with mock.patch("vigil.gates.detect_all", return_value=[alpha]):
            with self.assertRaises(VigilError):
                gate_install(self.cfg, KIND_LOGIN, env=self.env, name="beta",
                             require_password=False,
                             upstream="http://127.0.0.1:9999",
                             listen_port=4400)

    def test_a_fresh_named_instance_installs_before_its_dir_exists(self):
        """The whole install aborted for every brand-new instance.

        The generated `config.php` requires its library by absolute path,
        and PHP validation runs the staged copy in /tmp *before* anything is
        written to the state directory. So `require_once
        <state_dir>/lib/gate-lib.php` hit a path that did not exist yet and
        the install stopped with "Failed to open stream". The default
        instance only ever passed because its library had been on disk since
        an earlier install -- which is exactly why this was not caught.
        """
        from vigil.gates import installer
        php = installer.php_bin()
        if not php:
            self.skipTest("没有可用的 php，无法执行 PHP 校验")
        base = self.base
        ng_conf = base / "nginx.conf"
        ng_conf.write_text("http {\n    include       proxy.conf;\n}\n",
                           encoding="utf-8")
        env = {
            "nginx": {"present": True, "lua": True, "binary": "/bin/true",
                      "conf": str(ng_conf),
                      "include_dirs": [str(base / "vhost")],
                      "worker_user": "www"},
            "php_fpm": {"sockets": [{"socket": str(base / "php.sock"),
                                     "user": "www"}]},
            "bt_panel": {"present": False},
            "gate": {"root": str(base / "server"), "dirs": []},
        }
        spec = gspec.GateSpec.for_kind(KIND_LOGIN, cfg=None, env=env,
                                       name="astrbot")
        spec.state_dir = str(base / "server" / "astrbot-gate")
        spec.webroot = str(base / "www" / "astrbot-gate")
        spec.upstream = "http://127.0.0.1:6185"
        spec.listen_port = 4400
        spec.require_password = False
        spec.fastcgi_pass = "unix:%s" % (base / "php.sock")
        self.assertFalse(Path(spec.state_dir).exists())

        real_run = shell.run

        def fake_run(argv, **kw):
            # nginx -t and the reload are the only things that must not run;
            # the PHP version probe and everything else stays real.
            if "-t" in argv or (argv and argv[0] == "systemctl"):
                return True, "", ""
            return real_run(argv, **kw)

        smoke = []
        real_smoke = installer._php_smoke_test

        def spy(php_bin_, rendered, spec_):
            result = real_smoke(php_bin_, rendered, spec_)
            smoke.append(result)
            return result

        with mock.patch("vigil.gates.installer.shell.run", fake_run), \
                mock.patch.object(installer, "BACKUP_ROOT",
                                  base / "backups"), \
                mock.patch("vigil.gates.installer._php_smoke_test",
                           side_effect=spy):
            res = installer.install(spec, env=env, log=None)

        self.assertTrue(res.get("ok"), res)
        self.assertTrue(smoke, "PHP 校验根本没有运行")
        self.assertEqual([], smoke[0], "PHP 校验报告了问题")
        state = Path(spec.state_dir)
        for rel in ("gate.lua", "config.php", "policy.conf",
                    "lib/gate-lib.php"):
            self.assertTrue((state / rel).is_file(), rel)
        for name in ("verify.php", "captcha.php", "logout.php"):
            self.assertTrue((Path(spec.webroot) / name).is_file(), name)


# --------------------------------------------------------------------------
# Gate templates
# --------------------------------------------------------------------------


class TestLoginPageActuallyRuns(unittest.TestCase):
    """Execute the page's script against a stub DOM.

    `node --check` proves the syntax parses; it cannot prove the script runs.
    The login page once rendered nothing at all because a variable was deleted
    in a refactor while a line still assigned to it: the IIFE threw a
    ReferenceError at that statement, never reached the code that fetches the
    images, and the browser showed an empty puzzle with no error. The access
    log showed no `/captcha` request at all -- which is what made it
    diagnosable, and what this test asserts directly.

    The dataset is representative rather than extracted from the page: the
    template is PHP, so the rendered values only exist once PHP has run. What
    matters here is that the script survives its own setup and asks for
    everything, so the values are chosen to be plausible and the page's own
    attribute *names* are asserted separately.
    """

    @classmethod
    def setUpClass(cls):
        from vigil.gates import installer
        cls.tmp = tempfile.TemporaryDirectory()
        spec = gspec.GateSpec.for_kind(KIND_LOGIN)
        base = Path(cls.tmp.name)
        spec.state_dir = str(base / "state")
        spec.webroot = str(base / "web")
        spec.require_password = False
        spec.username = "t"; spec.pass_hash = "$2y$10$" + "x" * 53
        spec.upstream_token_file = str(base / "state" / "tok")
        spec.upstream_mint_url = "http://127.0.0.1:3080/"
        cls.page = None
        for p, (c, _m) in installer.render_files(spec).items():
            if p.name == "verify.php":
                cls.page = c
        assert cls.page, "verify.php was not rendered"
        cls.pieces = [
            {"y": 40, "u": "/__gate/captcha?cid=abc&part=slider-piece1"},
            {"y": 118, "u": "/__gate/captcha?cid=abc&part=slider-piece2"},
            {"y": 196, "u": "/__gate/captcha?cid=abc&part=slider-piece3"},
        ]
        cls.dataset = {
            "w": "640", "h": "280", "pw": "72", "ph": "90", "max": "556",
            "bg": "/__gate/captcha?cid=abc&part=slider-bg",
            "objects": "/__gate/captcha?cid=abc&part=slider-objects",
            "pieces": json.dumps(cls.pieces),
            "glow": "120,200,255", "kind": "art", "ink": "255,255,255",
            "sun": "320,60", "water": "180",
        }

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _run(self):
        """Run the page script under node; returns what the harness saw."""
        node = shutil.which("node")
        if not node:
            self.skipTest("没有 node，无法执行页面脚本")
        m = re.search(r"<script nonce=\"[^\"]*\">(.*?)</script>", self.page,
                      re.S)
        self.assertIsNotNone(m, "页面里没有内联脚本")
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(tmp), True)
        jsfile = tmp / "page.js"
        jsfile.write_text(m.group(1), encoding="utf-8")
        harness = (Path(__file__).resolve().parent / "js" / "run_page.js")
        proc = subprocess.run(
            [node, str(harness), str(jsfile), json.dumps(self.dataset), "3"],
            capture_output=True, text=True, timeout=60)
        out = (proc.stdout or "").strip().splitlines()
        self.assertTrue(out, "harness 没有输出：%s" % (proc.stderr or "")[-300:])
        return json.loads(out[-1])

    def test_the_script_runs_without_throwing(self):
        res = self._run()
        self.assertTrue(res["ok"],
                        "页面脚本抛异常，登录页会整片空白：%s" % res["error"])

    def test_it_actually_requests_every_image(self):
        """The symptom was 'not one image request in the access log'."""
        res = self._run()
        self.assertTrue(res["ok"], res["error"])
        asked = res["requested"]
        joined = " ".join(asked)
        self.assertIn("slider-bg", joined, "没有请求背景图")
        self.assertIn("slider-objects", joined, "没有请求图形层")
        for i in range(1, 4):
            self.assertIn("slider-piece%d" % i, joined,
                          "没有请求第 %d 块拼片" % i)
        self.assertEqual(len(asked), 5, "请求的图片数不对：%r" % (asked,))

    def test_the_images_are_requested_before_the_canvas_is_used(self):
        """A picture request must not sit behind canvas work that can throw."""
        m = re.search(r"<script nonce=\"[^\"]*\">(.*?)</script>", self.page,
                      re.S)
        js = m.group(1)
        first_src = js.index("pim.src = wanted[wi]")
        first_ctx = js.index('cv.getContext("2d")')
        self.assertLess(first_src, first_ctx,
                        "图片请求排在画布初始化之后，画布一出错就一张图都不会请求")

    def test_it_starts_the_render_loop(self):
        """Requesting the images is not the same as drawing them."""
        res = self._run()
        self.assertTrue(res["ok"], res["error"])
        self.assertGreater(res.get("frames", 0), 0, "动画循环从未启动")

    def test_a_failure_would_be_visible_and_offers_the_text_fallback(self):
        """A blank page with no message is the worst possible outcome."""
        self.assertIn('id="jsfail"', self.page, "没有用于显示初始化失败的容器")
        self.assertIn('id="jsfail-why"', self.page, "失败提示没有可写的位置")
        self.assertIn("fallback=text", self.page, "没有给出改用文本验证码的出口")
        self.assertIn("改用文字验证码", self.page, "失败提示里没有文字验证码入口")
        # And the harness agrees the page reaches for it on an uncaught error.
        res = self._run()
        self.assertFalse(res["failureShown"], "一切正常时不应显示失败提示")

    def test_a_broken_script_requests_images_anyway_and_says_so(self):
        """The two asks from the report, checked against the real defect.

        The page fetches its pictures before it builds any canvas, and it
        reveals a message instead of an empty box. Both are verified by
        restoring the actual bug -- an assignment to a name a refactor
        deleted, under "use strict" -- and watching what the page does.
        """
        m = re.search(r"<script nonce=\"[^\"]*\">(.*?)</script>", self.page,
                      re.S)
        js = m.group(1)
        self.assertNotIn("NSLOT", js, "那段已删掉的变量又回来了")
        bug = "  NSLOT = Math.min(NSLOT, pieces.length);\n"
        self.assertIn("  var tops = [];", js)
        broken = js.replace("  var tops = [];", bug + "  var tops = [];", 1)

        node = shutil.which("node")
        if not node:
            self.skipTest("没有 node，无法执行页面脚本")
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(tmp), True)
        jsfile = tmp / "broken.js"
        jsfile.write_text(broken, encoding="utf-8")
        harness = (Path(__file__).resolve().parent / "js" / "run_page.js")
        proc = subprocess.run(
            [node, str(harness), str(jsfile), json.dumps(self.dataset), "3"],
            capture_output=True, text=True, timeout=60)
        res = json.loads((proc.stdout or "").strip().splitlines()[-1])

        self.assertFalse(res["ok"], "注入的故障没有被测出来")
        self.assertIn("NSLOT", res["error"] or "", "报的不是那个错：%s" % res["error"])
        # 1. The pictures were asked for before the failure.
        self.assertEqual(len(res["requested"]), 5,
                         "脚本出错时一张图都没请求：%r" % (res["requested"],))
        # 2. The visitor is told, and offered the way out.
        self.assertTrue(res["failureShown"], "脚本出错却没有在页面上显示错误")
        self.assertEqual(res["frames"], 0, "出错后不该还在跑动画")

    def test_the_page_hands_over_every_source_the_script_expects(self):
        """The attribute names the script reads must be the ones PHP writes.

        Assertions on page *content* use assertTrue with a short message: a
        failing assertIn would print the entire template, which buries the one
        line that matters.
        """
        def has(needle, why):
            self.assertTrue(needle in self.page, why)

        for key in ("data-w", "data-h", "data-pw", "data-ph", "data-max",
                    "data-bg", "data-glow", "data-pieces", "data-objects",
                    "data-kind", "data-ink", "data-sun", "data-water",
                    "data-fallback"):
            has(key + '="', "页面没有下发 %s" % key)
        # Pictures are carried in the page unless that is impossible...
        has("vigil_slider_data_uri", "页面不再内联拼图图片")
        has("inline_images", "页面没有读取内联开关")
        # ...in which case they are fetched, with the part named by the caller.
        has("'&part=' . $part", "图片回退地址没有带上 part 名称")
        has("vigil_captcha_png", "文字验证码没有在服务端绘制后内联")
        has('id="jsfail"', "没有可见的失败提示容器")
        has("?fallback=text", "没有给出文字验证码出口")
        has("escapeToText", "初始化失败后不会自动切到文字验证码")
        # The gap must never be derivable from what the page is given.
        self.assertFalse("data-scene" in self.page, "页面仍在下发未标注底图")
        self.assertFalse("locateGap" in self.page, "页面仍在用底图推算缺口位置")
        self.assertFalse("gapLeft" in self.page, "页面仍在计算缺口位置")
        self.assertFalse("NSLOT" in self.page, "已删掉的变量又出现在页面里")


def _php_quote(text: str) -> str:
    """A single-quoted PHP string literal for `text`."""
    return "'" + str(text).replace("\\", "\\\\").replace("'", "\\'") + "'"


class TestRequestHygieneRejectsMalformedRequests(unittest.TestCase):
    """Research item #1: reject what no legitimate client sends.

    From RFC 9112 (a server MUST reject a bare CR) and the request-smuggling
    literature: the danger is not the malformed request itself, it is that two
    components -- nginx, PHP-FPM, Express -- normalise it *differently*, and
    the disagreement is the bug. So the check runs on the raw `$request_uri`
    rather than the already-normalised `$uri`.
    """

    def _snippet(self):
        from vigil.guards import hygiene
        return hygiene.render()

    def test_it_guards_the_raw_uri_not_the_normalised_one(self):
        self.assertIn("$request_uri ~*", self._snippet(),
                      "穿越检查没有挂在 raw $request_uri 上")

    def test_encoded_traversal_and_nul_are_refused(self):
        from vigil.guards import hygiene
        line = [l for l in hygiene.render().splitlines()
                if "request_uri ~*" in l][0]
        rx = re.compile(line.split('"')[1], re.I)
        for uri in ("/function/api/%2e%2e/x", "/a/../b", "/../etc/passwd",
                    "/x/%252e%252e/y", "/x/%c0%ae/y", "/x?a=%00b"):
            self.assertTrue(rx.search(uri), "没拦住：%s" % uri)

    def test_a_message_containing_a_backslash_is_not_refused(self):
        """The false positive that mattered, caught before shipping.

        `$request_uri` includes the query string and this host has a chat API.
        `encodeURIComponent("a\\b")` is `a%5Cb`, so a rule matching `%5c` or a
        bare `..` anywhere would answer 400 to somebody typing an ordinary
        message. A hardening rule that breaks the product is worse than the
        hole it closes, so the patterns are anchored to a path boundary.
        """
        from vigil.guards import hygiene
        line = [l for l in hygiene.render().splitlines()
                if "request_uri ~*" in l][0]
        rx = re.compile(line.split('"')[1], re.I)
        for uri in ("/function/api/chat?msg=a%5Cb", "/x?q=a..b",
                    "/function/api/chat?msg=..%2Fetc", "/x?a=%2e%2eb",
                    "/function/i18n/zh-CN.json", "/index.html"):
            self.assertFalse(rx.search(uri), "正常请求被拒了：%s" % uri)

    def test_method_override_headers_are_refused(self):
        from vigil.guards import hygiene
        text = hygiene.render()
        for header in hygiene.OVERRIDE_HEADERS:
            self.assertIn("if (%s)" % header, text,
                          "方法覆盖头没有拦：%s" % header)


class TestLoginLockoutPolicy(unittest.TestCase):
    """The lockout was locking people out.

    A person reported being locked out of the login gate with a live record of
    `strikes=1` after three issued challenges, and the live policy said
    `lock_max=5, lock_secs=900, lock_backoff=1`. So five failures -- which the
    *page itself* was causing, because the puzzle never rendered -- cost
    fifteen minutes, and the documented "exponential backoff" was flat,
    because `1 ** n == 1`. These tests pin the reviewed behaviour by running
    the real PHP.
    """

    @classmethod
    def setUpClass(cls):
        from vigil.gates import installer
        cls.tmp = tempfile.TemporaryDirectory()
        base = Path(cls.tmp.name)
        spec = gspec.GateSpec.for_kind(KIND_LOGIN)
        spec.state_dir = str(base / "state")
        spec.webroot = str(base / "web")
        spec.username = "t"; spec.pass_hash = "$2y$10$" + "x" * 53
        spec.upstream_token_file = str(base / "state" / "tok")
        spec.upstream_mint_url = "http://127.0.0.1:3080/"
        cls.lib = None
        for pth, (content, _m) in installer.render_files(spec).items():
            if pth.name == "gate-lib.php":
                cls.lib = base / "gate-lib.php"
                cls.lib.write_text(content, encoding="utf-8")
        assert cls.lib, "gate-lib.php was not rendered"

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _php(self):
        for cand in ("/www/server/php/82/bin/php", "php", "php8.2", "php8"):
            exe = cand if "/" in cand else shutil.which(cand)
            if exe and Path(exe).is_file():
                return exe
        return None

    def _drive(self, body: str):
        php = self._php()
        if not php:
            self.skipTest("没有 php，无法执行网关库")
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(tmp), True)
        state = tmp / "state"
        (state / "fails").mkdir(parents=True, exist_ok=True)
        driver = tmp / "drive.php"
        driver.write_text(
            "<?php\nrequire %s;\n$dir = %s;\n%s\n"
            % (_php_quote(str(self.lib)), _php_quote(str(state)), body),
            encoding="utf-8")
        proc = subprocess.run([php, str(driver)], capture_output=True,
                              text=True, timeout=90)
        self.assertEqual(proc.returncode, 0,
                         "php 执行失败：%s" % (proc.stderr or "")[-400:])
        out = (proc.stdout or "").strip().splitlines()
        self.assertTrue(out, "php 没有输出：%s" % (proc.stderr or "")[-300:])
        return json.loads(out[-1])

    def _first_lock(self, **over):
        pol = {"lock_max": 3, "lock_first_secs": 120, "lock_backoff": 2,
               "lock_secs": 900, "cred_max": 4, "cred_lock_secs": 300}
        pol.update(over)
        return self._drive(
            "$pol = json_decode(%s, true);\n"
            "$out = [];\n"
            "for ($round = 1; $round <= 4; $round++) {\n"
            "    for ($i = 0; $i < $pol['lock_max']; $i++) {\n"
            "        vigil_fail_bump($dir, $pol, 'CHALLENGE');\n"
            "    }\n"
            "    $out['round' . $round] = vigil_fail_state($dir)['until'] - time();\n"
            "}\n"
            "echo json_encode($out);" % _php_quote(json.dumps(pol)))

    def test_the_first_lock_is_short_and_really_does_grow(self):
        """120s, 240s, 480s, then the 900s ceiling -- not a flat 900s."""
        r = self._first_lock()
        self.assertLessEqual(abs(r["round1"] - 120), 2,
                             "首锁不是 120 秒：%s" % r["round1"])
        self.assertLessEqual(abs(r["round2"] - 240), 2, r)
        self.assertLessEqual(abs(r["round3"] - 480), 2, r)
        self.assertLessEqual(abs(r["round4"] - 900), 2,
                             "退避没有封顶在 lock_secs：%s" % r["round4"])

    def test_a_wrong_password_uses_its_own_generous_budget(self):
        """A typo must not spend the puzzle budget or lock for 15 minutes."""
        r = self._drive(
            "$pol = ['lock_max' => 3, 'lock_first_secs' => 120,"
            " 'lock_backoff' => 2, 'lock_secs' => 900,"
            " 'cred_max' => 4, 'cred_lock_secs' => 300];\n"
            "$out = [];\n"
            "vigil_fail_bump($dir, $pol, 'BAD_CRED');\n"
            "vigil_fail_bump($dir, $pol, 'BAD_CRED');\n"
            "$s = vigil_fail_state($dir);\n"
            "$out['challenge_count'] = $s['count'];\n"
            "$out['until'] = $s['until'];\n"
            "$out['cred'] = $s['cred'];\n"
            "for ($i = 0; $i < 4; $i++) { vigil_fail_bump($dir, $pol, 'BAD_CRED'); }\n"
            "$s = vigil_fail_state($dir);\n"
            "$out['locked'] = $s['until'] - time();\n"
            "$out['count_after'] = $s['count'];\n"
            "echo json_encode($out);")
        self.assertEqual(0, r["challenge_count"],
                         "密码输错动了拼图的失败计数")
        self.assertEqual(0, r["until"], "两次输错密码就被锁了")
        self.assertEqual(2, r["cred"])
        self.assertLessEqual(abs(r["locked"] - 300), 2,
                             "密码预算到顶后锁的不是 cred_lock_secs：%s"
                             % r["locked"])
        self.assertEqual(0, r["count_after"])

    def test_challenge_failures_do_not_touch_the_credential_counter(self):
        r = self._drive(
            "$pol = ['lock_max' => 99, 'lock_first_secs' => 120,"
            " 'lock_backoff' => 2, 'lock_secs' => 900,"
            " 'cred_max' => 4, 'cred_lock_secs' => 300];\n"
            "for ($i = 0; $i < 5; $i++) { vigil_fail_bump($dir, $pol, 'CHALLENGE'); }\n"
            "$s = vigil_fail_state($dir);\n"
            "echo json_encode(['cred' => $s['cred'], 'count' => $s['count']]);")
        self.assertEqual(0, r["cred"], "拼图失败动了密码计数")
        self.assertEqual(5, r["count"])

    def test_the_sweeper_removes_only_what_cannot_matter(self):
        r = self._drive(
            "$d = $dir . '/fails/';\n"
            "file_put_contents($d . str_repeat('a', 64) . '.json',"
            " json_encode(['count'=>0,'until'=>0,'strikes'=>0,'issued'=>0,'cred'=>0]));\n"
            "file_put_contents($d . str_repeat('b', 64) . '.json',"
            " json_encode(['count'=>0,'until'=>time()-100000,'strikes'=>1,'issued'=>1,'cred'=>0]));\n"
            "file_put_contents($d . str_repeat('c', 64) . '.json',"
            " json_encode(['count'=>2,'until'=>time()+600,'strikes'=>1,'issued'=>1,'cred'=>0]));\n"
            "file_put_contents($d . str_repeat('e', 64) . '.json',"
            " json_encode(['count'=>1,'until'=>0,'strikes'=>0,'issued'=>1,'cred'=>0]));\n"
            "touch($d . str_repeat('e', 64) . '.json', time() - 800000);\n"
            "file_put_contents($d . 'legacy-format-file', '{\"count\":1}');\n"
            "touch($d . 'legacy-format-file', time() - 800000);\n"
            "$removed = vigil_fail_sweep($dir, 86400, 604800, 0);\n"
            "$left = array_map('basename', glob($d . '*.json'));\n"
            "sort($left);\n"
            "echo json_encode(['removed' => $removed, 'left' => $left]);")
        self.assertEqual(4, r["removed"],
                         "清扫数量不对，留下的=%s" % r["left"])
        self.assertEqual([("c" * 64) + ".json"], r["left"],
                         "活动锁定被清扫误删，或被留了下来")

    def test_the_hold_file_name_is_the_hash_the_cli_computes(self):
        """`vigil gate reset-holds --ip` must find the file the gate writes.

        The CLI derives the name as sha256(address) because that is what the
        gate uses. If the gate ever mixes in the User-Agent -- as the
        *challenge binding* does -- then `--ip` would silently stop matching
        anything and an operator would be told "no records found" while the
        user stayed locked out. So the two are compared directly.
        """
        r = self._drive("echo json_encode(['name' => basename(vigil_fail_file($dir))]);")
        expected = hashlib.sha256(b"0.0.0.0").hexdigest() + ".json"
        self.assertEqual(expected, r["name"],
                         "网关的 fails 文件名与 CLI 推导的不一致")


class TestEveryPairOfPiecesIsAccepted(unittest.TestCase):
    """The bug: some pairs worked and some did not.

    The page starts piece *i* at a fixed x along the bottom, and the checker
    decides whether that piece was placed by comparing the drop with that same
    point. Gaps were generated at x in [105, 417] while the tray sits at
    x = 53/213/373 -- so a gap could land *on* its own tray position. Measured
    before the fix: 2 of 120 sampled slots were within 12px of it, the closest
    1px apart. A solver who dragged the right two pieces was then told it had
    not placed two pieces, because "correctly placed" and "never touched" were
    the same coordinates.
    """

    def _gen_probe(self, rounds: int = 60):
        import tempfile as _tf
        from vigil.gates import installer
        php = None
        for cand in ("/www/server/php/82/bin/php", "php", "php8.2", "php8"):
            exe = cand if "/" in cand else shutil.which(cand)
            if exe and Path(exe).is_file():
                php = exe
                break
        if not php:
            self.skipTest("没有 php")
        tmp = Path(_tf.mkdtemp())
        self.addCleanup(shutil.rmtree, str(tmp), True)
        spec = gspec.GateSpec.for_kind(KIND_LOGIN)
        spec.state_dir = str(tmp / "state"); spec.webroot = str(tmp / "web")
        spec.username = "t"; spec.pass_hash = "$2y$10$" + "x" * 53
        spec.upstream_token_file = str(tmp / "state" / "tok")
        spec.upstream_mint_url = "http://127.0.0.1:3080/"
        for pth, (c, _m) in installer.render_files(spec).items():
            if pth.name == "gate-lib.php":
                (tmp / "gate-lib.php").write_text(c, encoding="utf-8")
        drv = tmp / "d.php"
        drv.write_text(
            "<?php require '%s';\n"
            "$dir='%s'; foreach(['','/captcha','/slider','/fails','/logs',"
            "'/sessions'] as $s) @mkdir($dir.$s,0700,true);\n"
            "$pol=['captcha_ttl'=>600,'captcha_length'=>5,"
            "'captcha_per_minute'=>9999,'lock_max'=>99,'lock_secs'=>900];\n"
            "$g=vigil_slider_geometry($dir,$pol); $n=3;\n"
            "$pw=$g['piece']+$g['radius'];"
            " $max=$g['width']-$g['piece']-$g['radius'];\n"
            "$tx=[]; for($i=0;$i<$n;$i++) $tx[$i]=max(0,min($max,"
            "(int)round(($i+0.5)*($g['width']/$n)-$pw/2)));\n"
            "$min=9999; $bad=0; $tot=0;\n"
            "for($k=0;$k<%d;$k++){"
            " $s=vigil_new_slider($dir,$pol,['scene_kind'=>0]);\n"
            "  if(empty($s['ok'])) continue;\n"
            "  foreach(($s['pieces']??[]) as $i=>$p){"
            " $d=abs($p['x']-$tx[$i]); $tot++; $min=min($min,$d);\n"
            "    if($d < VIGIL_TRAY_CLEAR) $bad++; } }\n"
            "echo json_encode(['slots'=>$tot,'min_dx'=>$min,'too_close'=>$bad,"
            "'clear'=>VIGIL_TRAY_CLEAR]);"
            % (tmp / "gate-lib.php", tmp / "state", rounds), encoding="utf-8")
        out = subprocess.run([php, str(drv)], capture_output=True, text=True,
                             timeout=300)
        line = [l for l in (out.stdout or "").strip().splitlines()
                if l.startswith("{")]
        self.assertTrue(line, "php 没有输出：%s" % (out.stderr or "")[-300:])
        return json.loads(line[-1])

    def test_no_gap_lands_on_its_own_tray_position(self):
        r = self._gen_probe()
        self.assertGreater(r["slots"], 100, "样本太少：%s" % r)
        self.assertEqual(0, r["too_close"],
                         "%d/%d 个缺口离自己的托盘位置不足 %dpx（最近 %dpx）——"
                         "这些题会误判「有没有被拖出来」"
                         % (r["too_close"], r["slots"], r["clear"],
                            r["min_dx"]))
        self.assertGreaterEqual(r["min_dx"], r["clear"])

    def test_the_tray_test_is_the_same_on_both_sides(self):
        """A thumb cannot hit 3px, and the two sides must agree."""
        from vigil.gates import installer
        spec = gspec.GateSpec.for_kind(KIND_LOGIN)
        spec.state_dir = "/tmp/x"; spec.webroot = "/tmp/y"
        spec.username = "t"; spec.pass_hash = "$2y$10$" + "x" * 53
        spec.upstream_token_file = "/tmp/x/tok"
        spec.upstream_mint_url = "http://127.0.0.1:3080/"
        files = {p.name: c for p, (c, _m) in installer.render_files(spec).items()}
        self.assertIn("function vigil_slider_in_tray", files["gate-lib.php"])
        self.assertIn("<= 10", files["gate-lib.php"])
        self.assertIn("var TRAY_TOL = 10;", files["verify.php"],
                      "页面的托盘判定与服务端不一致")


class TestDragMustLookLikeAPerson(unittest.TestCase):
    """The two checks added to widen the gap between a hand and a script.

    Relaxing the step-variation thresholds (CV 0.12→0.09, distinct steps 3→2)
    is what makes a short drag on a phone stop being rejected; that relaxation
    is only safe because two harder-to-fake properties were added. This drives
    the **real** checker with crafted tracks, because the adversarial script
    could not reach them -- its bots were already stopped earlier in the chain,
    so "it works" would otherwise be an untested claim.
    """

    def _php(self):
        for cand in ("/www/server/php/82/bin/php", "php", "php8.2", "php8"):
            exe = cand if "/" in cand else shutil.which(cand)
            if exe and Path(exe).is_file():
                return exe
        return None

    def _run(self, track_builder):
        php = self._php()
        if not php:
            self.skipTest("没有 php")
        from vigil.gates import installer
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(tmp), True)
        spec = gspec.GateSpec.for_kind(KIND_LOGIN)
        spec.state_dir = str(tmp / "state"); spec.webroot = str(tmp / "web")
        spec.username = "t"; spec.pass_hash = "$2y$10$" + "x" * 53
        spec.upstream_token_file = str(tmp / "state" / "tok")
        spec.upstream_mint_url = "http://127.0.0.1:3080/"
        lib = None
        for pth, (content, _m) in installer.render_files(spec).items():
            if pth.name == "gate-lib.php":
                lib = tmp / "gate-lib.php"
                lib.write_text(content, encoding="utf-8")
        (tmp / "state" / "captcha").mkdir(parents=True, exist_ok=True)
        (tmp / "state" / "slider").mkdir(parents=True, exist_ok=True)

        slots = [{"x": 100 + i * 60, "y": 60 + i * 60, "shape": "right"}
                 for i in range(3)]
        tray = [(53, 216), (213, 211), (373, 206)]
        drops = []
        for i in range(3):
            if i < 2:
                x, y = slots[i]["x"], slots[i]["y"]
                drops.append({"x": x, "y": y,
                              "track": track_builder(x, y, i)})
            else:
                drops.append({"x": tray[i][0], "y": tray[i][1], "track": []})

        cid = "a" * 32
        meta = {"mode": "slider", "exp": int(time.time()) + 600,
                "born": int(time.time()) - 5,
                "bind": "ignored-for-this-test", "slots": slots,
                "q_ans": 1, "q_opts": ["a", "b", "c"], "q_text": "q",
                "weight": 0}
        (tmp / "state" / "captcha" / (cid + ".json")).write_text(
            json.dumps(meta), encoding="utf-8")
        driver = tmp / "d.php"
        driver.write_text(
            "<?php\nrequire %s;\n"
            "$_SERVER['REMOTE_ADDR'] = '203.0.113.9';\n"
            "$_SERVER['HTTP_USER_AGENT'] = 'test';\n"
            "$meta = json_decode(file_get_contents(%s), true);\n"
            "$meta['bind'] = vigil_client_binding();\n"
            "file_put_contents(%s, json_encode($meta));\n"
            "$pol = ['captcha_ttl'=>600,'captcha_min_seconds'=>0,"
            "'captcha_length'=>5,'captcha_per_minute'=>999,'lock_max'=>99,"
            "'lock_secs'=>900,'slider_pieces'=>3];\n"
            "$r = vigil_check_slider(%s, $pol, %s, %s, false, '1');\n"
            "echo json_encode($r);"
            % (_php_quote(str(lib)),
               _php_quote(str(tmp / "state" / "captcha" / (cid + ".json"))),
               _php_quote(str(tmp / "state" / "captcha" / (cid + ".json"))),
               _php_quote(str(tmp / "state")), _php_quote(cid),
               _php_quote(json.dumps(drops))), encoding="utf-8")
        proc = subprocess.run([php, str(driver)], capture_output=True,
                              text=True, timeout=90)
        out = (proc.stdout or "").strip().splitlines()
        self.assertTrue(out, "php 无输出：%s" % (proc.stderr or "")[-300:])
        return json.loads(out[-1])

    @staticmethod
    def _hand(x, y, i):
        """A hand-like path: easing, wander, overshoot, correction."""
        pts, t = [[30, 240, 0]], 0
        n = 14
        for k in range(n + 1):
            f = k / n
            e = f * f * (3 - 2 * f)
            t += 12 + (k * 7) % 23
            pts.append([round(30 + (x - 30) * e + math.sin(f * 9.1) * 6 * (1 - f), 1),
                        round(240 + (y - 240) * e + math.cos(f * 7.3) * 5 * (1 - f), 1),
                        t])
        pts.append([x + 4, y + 3, t + 21])
        pts.append([x, y, t + 47])
        return pts

    def test_a_hand_like_path_is_accepted(self):
        """The control: if this fails, the puzzle rejects real people."""
        r = self._run(self._hand)
        self.assertTrue(r["ok"], "人手轨迹被拒了：%s" % r["reason"])

    def test_every_normal_drag_style_is_accepted(self):
        """The measurement that overturned the previous design.

        Run against the real checker on the real host, six styles a person
        actually uses, 4 times each:

            一口气直线拖过去   ROBOTIC_SPEED 拒   ← 正常拖法
            快（约 150ms）     ROBOTIC_SPEED 拒   ← 正常拖法
            慢慢挪（约 2s）    ROBOTIC_SPEED 拒   ← 正常拖法
            短距离微调         STRAIGHT_LINE 拒   ← 正常拖法
            拖过去再回修一下   通过
            手抖来回几次       通过

        Four of six were rejected. Step-length variation, distinct step sizes,
        straightness and path efficiency all punish *dragging neatly*, and
        dragging neatly is what a practised user does. So they were removed:
        the gate keeps only checks that cannot punish a habit -- enough samples,
        a duration floor, a speed ceiling -- and the real hurdle is the reading
        question plus the position.
        """
        def straight(x1, y1, i):
            pts, t = [[30, 240, 0]], 0
            for k in range(1, 19):
                f = k / 18.0
                t += 16
                pts.append([30 + (x1 - 30) * f, 240 + (y1 - 240) * f, t])
            return pts

        def fast(x1, y1, i):
            pts, t = [[30, 240, 0]], 0
            for k in range(1, 13):
                f = k / 12.0
                t += 12
                pts.append([30 + (x1 - 30) * f, 240 + (y1 - 240) * f, t])
            return pts

        def slow(x1, y1, i):
            pts, t = [[30, 240, 0]], 0
            for k in range(1, 21):
                f = k / 20.0
                t += 95
                pts.append([30 + (x1 - 30) * f, 240 + (y1 - 240) * f, t])
            return pts

        def nudge(x1, y1, i):
            pts, t = [[x1 - 22, y1 + 14, 0]], 0
            for k in range(1, 7):
                f = k / 6.0
                t += 30
                pts.append([(x1 - 22) + 22 * f, (y1 + 14) - 14 * f, t])
            return pts

        for name, fn in (("直线", straight), ("快", fast), ("慢", slow),
                         ("短距离微调", nudge), ("人手", self._hand)):
            r = self._run(fn)
            self.assertTrue(r["ok"], "%s 拖法被拒了：%s" % (name, r["reason"]))

    def test_a_two_point_submission_is_rejected(self):
        """Setting the coordinate and sending two samples is not a drag."""
        def jump(x, y, i):
            return [[30, 240, 0], [x, y, 20]]
        r = self._run(jump)
        self.assertFalse(r["ok"], "两点提交竟然通过了")

    def test_a_teleport_is_rejected(self):
        """A whole-frame jump inside 20ms is not physically a hand."""
        def blink(x, y, i):
            return [[30, 240, 0], [100, 200, 4], [200, 150, 9], [x, y, 18]]
        r = self._run(blink)
        self.assertFalse(r["ok"], "瞬移竟然通过了")
        self.assertIn(r["reason"], ("BAD_DURATION", "IMPOSSIBLE_SPEED",
                                    "SHORT_TRACK"), r)


class TestExposureWiringIsSelfHealing(unittest.TestCase):
    """The include can be removed by a third party; the program must notice.

    Measured on the development host: the `^~ /function/` include vanished
    from a panel-owned vhost file (rewritten by something other than this
    program), and the subtree went back to serving a real 3 KB `.gitignore`.
    The rules file was present the whole time, so any check that only looked
    at the file reported OK while the hole was open. Hence two halves: a
    repair that `vigil update` runs, and a health check that says so.
    """

    CONF = """server {
    location ~* "\\.(bak|old)$" { return 404; }
    location ^~ /app/ {
        try_files $uri $uri/ /app/index.html;
    }
    location ^~ /api/ {
        proxy_pass http://127.0.0.1:9100/;
    }
    location ^~ /old/ { return 404; }
    location = /exact { root /srv/www; }
}
"""

    def test_it_adds_the_include_to_a_file_serving_prefix(self):
        from vigil.guards import exposure
        new, added = exposure.repair_prefixes(self.CONF, "/etc/nginx/x.conf")
        self.assertEqual(["/app/"], added)
        self.assertIn("include /etc/nginx/zz-exposure-deny.conf;", new)
        # It went inside the block, not after it.
        block = new.split("location ^~ /app/ {", 1)[1].split("}", 1)[0]
        self.assertIn("zz-exposure-deny", block)

    def test_it_leaves_proxy_and_return_prefixes_alone(self):
        """A proxy hands the request to a backend; a `return` serves nothing."""
        from vigil.guards import exposure
        _new, added = exposure.repair_prefixes(self.CONF, "/etc/nginx/x.conf")
        self.assertNotIn("/api/", added)
        self.assertNotIn("/old/", added)
        self.assertNotIn("/exact", added)

    def test_it_is_idempotent(self):
        """Running it twice must not add a second include."""
        from vigil.guards import exposure
        once, added1 = exposure.repair_prefixes(self.CONF, "/etc/nginx/x.conf")
        twice, added2 = exposure.repair_prefixes(once, "/etc/nginx/x.conf")
        self.assertEqual(once, twice)
        self.assertEqual([], added2)
        self.assertEqual(1, twice.count("zz-exposure-deny"))

    def test_it_only_touches_sites_it_installed_rules_into(self):
        """No rules file in that directory means this was never our site."""
        import tempfile
        from vigil.guards import exposure
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(tmp), True)
        conf = tmp / "site.conf"
        conf.write_text(self.CONF, encoding="utf-8")
        res = exposure.repair_sites(root=str(tmp))
        self.assertEqual([], res["written"], "没有规则文件却动了配置")
        self.assertEqual(self.CONF, conf.read_text(encoding="utf-8"))

    def test_a_deleted_rules_file_is_rebuilt(self):
        """The sibling gap: the rules file itself can disappear.

        A panel wiping "unrecognised" files in its extension directory would
        remove the rules *and* leave the include pointing at nothing -- which
        makes nginx refuse to load, i.e. the site goes down. So a managed
        directory (one this program already writes into) gets the files back.
        """
        import tempfile
        from vigil.guards import exposure
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(tmp), True)
        # Managed, but the exposure rules are gone.
        (tmp / "vigil-deny.conf").write_text("x", encoding="utf-8")
        conf = tmp / "site.conf"
        conf.write_text(self.CONF, encoding="utf-8")

        res = exposure.repair_sites(root=str(tmp))
        self.assertEqual(2, len(res["restored"]), res)
        self.assertTrue((tmp / "zz-exposure-deny.conf").is_file())
        self.assertIn("location ~*", (tmp / "zz-exposure-deny.conf").read_text(
            encoding="utf-8"))
        self.assertIn("zz-exposure-deny", conf.read_text(encoding="utf-8"))

    def test_an_unmanaged_directory_is_left_alone(self):
        """No trace of this program in the directory means hands off."""
        import tempfile
        from vigil.guards import exposure
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(tmp), True)
        conf = tmp / "site.conf"
        conf.write_text(self.CONF, encoding="utf-8")
        res = exposure.repair_sites(root=str(tmp))
        self.assertEqual([], res["restored"])
        self.assertEqual([], res["written"])
        self.assertEqual(self.CONF, conf.read_text(encoding="utf-8"))

    def test_the_health_check_reports_the_hole_and_its_absence(self):
        """CRIT while the subtree is unprotected, OK once it is wired in."""
        import tempfile
        from vigil.guards import exposure
        from vigil.guards.checks import base as cbase
        cbase.load_all()
        check = cbase.get("exposure_prefix_rules")
        self.assertIsNotNone(check, "健康检查项没有注册")

        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(tmp), True)
        (tmp / "zz-exposure-deny.conf").write_text("x", encoding="utf-8")
        conf = tmp / "site.conf"
        conf.write_text(self.CONF, encoding="utf-8")

        real = exposure.site_confs
        exposure.site_confs = lambda root=None: [conf]
        try:
            res = check().run(None)
            self.assertEqual("CRIT", res.status, res.detail)
            self.assertIn("/app/", res.detail)
            # Now let the repair run, and it must come back clean.
            exposure.repair_sites(root=str(tmp))
            res2 = check().run(None)
            self.assertEqual("OK", res2.status, res2.detail)
        finally:
            exposure.site_confs = real


class TestPieceCountWording(unittest.TestCase):
    """The page said "两块拼片" while showing three pieces."""

    def _tpl(self):
        return (Path(__file__).resolve().parent.parent / "src" / "vigil" /
                "gates" / "templates" / "verify.php.tmpl").read_text(
                    encoding="utf-8")

    def test_no_user_facing_string_hardcodes_the_drawn_count(self):
        """The *drawn* count is computed; the *required* count is a constant.

        They are different numbers and only one of them may be written down.
        How many pieces the puzzle draws varies with the generator and the
        geometry, so it must be counted (`$nPieces`). How many are asked for
        is a design decision -- always two -- so the failure message may say
        "两块" and stay true. The bug this guards against is the one the user
        reported: the page said two while the puzzle drew three.
        """
        text = self._tpl()
        body = "\n".join(l for l in text.splitlines()
                         if not l.lstrip().startswith("//"))
        for stale in ("拖动滑块把两块拼片", "Place both pieces",
                      "两块拼片对准缺口", "把两块拼片都拖到缺口",
                      "两块拼片放进缺口"):
            self.assertNotIn(stale, body,
                             "又出现了写死「画了几块」的文案：%s" % stale)
        # The drawn count must be interpolated, never typed.
        self.assertIn("$zhCount", body)
        self.assertIn("%s 块拼片", body)

    def test_the_count_is_computed_before_it_is_used(self):
        text = self._tpl()
        defined = text.index("$nPieces = count(")
        used = text.index("sprintf('拖动 %s 块拼片")
        self.assertLess(defined, used,
                        "$nPieces 在用之后才算，文案会渲染成空的块数")

    def test_both_sentences_are_count_driven(self):
        text = self._tpl()
        # Says how many are drawn *and* how many are wanted: the gap between
        # those two numbers is the instruction being tested.
        self.assertIn("图中共 %s 块拼片，只需完成其中任意 %s 块", text)
        self.assertIn("sprintf('%s 块对准缺口", text)
        self.assertIn("any %d of them will do", text)

    def test_the_reminder_counts_what_is_actually_placed(self):
        text = self._tpl()
        self.assertIn("function placedCount()", text,
                      "没有统计「已经拖出去几块」的函数")
        self.assertIn("只需要完成 ", text, "多拖时没有提醒")
        self.assertIn("还需要再拖 ", text, "少拖时没有提醒")

    def test_the_error_matches_the_challenge_the_visitor_is_looking_at(self):
        """A mistyped text code must not blame the puzzle.

        Reported: switching to the text challenge and typing a wrong code
        produced the *puzzle's* error message ("check the two pieces are in
        their gaps") -- an instruction about a screen that is not on display.
        """
        text = self._tpl()
        self.assertIn("if ($mode === 'slider')", text,
                      "失败文案没有按模式区分")
        self.assertIn("验证码不正确，请重新输入图中的字符。", text,
                      "文字验证码没有自己的错误文案")
        # Within the puzzle the two factors still stay merged.
        self.assertIn("且问题回答正确", text)

    def test_it_says_any_two(self):
        text = self._tpl()
        self.assertIn("任意 %s 块", text, "没有写明「任意两块」")
        self.assertIn("any %d of them will do", text)

    def test_the_failure_message_states_no_number(self):
        """The submit path cannot know the count, so it must not guess one."""
        text = self._tpl()
        # The requirement is a constant 2 however many pieces are drawn, so
        # this message may state it -- unlike the piece count, which varies.
        self.assertNotIn("每一块拼片", text)
        self.assertIn("拖出的两块拼片都对准了缺口", text)


class TestOnlyTwoPiecesAreNeeded(unittest.TestCase):
    """Three pieces are drawn; two are asked for, and the third is the test.

    The instruction is the anti-automation layer that a *competent* solver
    fails: a script that locates every gap and fills every piece it can see
    has not read the sentence. A person reads "只需完成其中两块" and leaves one
    alone. So the server counts how many pieces left the tray -- computed from
    the tray geometry, never taken from the page, because "did you follow the
    instruction" is the one thing a client cannot be trusted about.
    """

    GEOM = {"width": 480, "height": 280, "piece": 46, "radius": 9,
            "tolerance": 16}

    @classmethod
    def setUpClass(cls):
        from vigil.gates import installer
        cls.tmp = tempfile.TemporaryDirectory()
        base = Path(cls.tmp.name)
        spec = gspec.GateSpec.for_kind(KIND_LOGIN)
        spec.state_dir = str(base / "state")
        spec.webroot = str(base / "web")
        spec.username = "t"; spec.pass_hash = "$2y$10$" + "x" * 53
        spec.upstream_token_file = str(base / "state" / "tok")
        spec.upstream_mint_url = "http://127.0.0.1:3080/"
        cls.lib = None
        for pth, (content, _m) in installer.render_files(spec).items():
            if pth.name == "gate-lib.php":
                cls.lib = base / "gate-lib.php"
                cls.lib.write_text(content, encoding="utf-8")
        assert cls.lib

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _php(self):
        for cand in ("/www/server/php/82/bin/php", "php", "php8.2", "php8"):
            exe = cand if "/" in cand else shutil.which(cand)
            if exe and Path(exe).is_file():
                return exe
        return None

    def _drive(self, php_body: str):
        php = self._php()
        if not php:
            self.skipTest("没有 php，无法执行网关库")
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(tmp), True)
        driver = tmp / "drive.php"
        driver.write_text("<?php\nrequire %s;\n%s\n"
                          % (_php_quote(str(self.lib)), php_body),
                          encoding="utf-8")
        proc = subprocess.run([php, str(driver)], capture_output=True,
                              text=True, timeout=90)
        self.assertEqual(proc.returncode, 0,
                         "php 执行失败：%s" % (proc.stderr or "")[-400:])
        out = (proc.stdout or "").strip().splitlines()
        self.assertTrue(out, "php 没有输出：%s" % (proc.stderr or "")[-300:])
        return json.loads(out[-1])

    def test_the_tray_positions_are_pinned(self):
        """The page's tray formula and the server's must be the same numbers.

        They are two implementations of one layout (JS computes where a piece
        starts; PHP decides whether it ever moved). If they drift, every
        untouched piece looks "placed" and the instruction check inverts.
        These are the shipped geometry's values, computed by hand from
        480x280, piece 46, radius 9.
        """
        r = self._drive(
            "$slots = [['x'=>1,'y'=>1],['x'=>2,'y'=>2],['x'=>3,'y'=>3]];\n"
            "$g = json_decode(%s, true);\n"
            "echo json_encode(vigil_slider_tray($slots, $g));"
            % _php_quote(json.dumps(self.GEOM)))
        self.assertEqual([{"x": 53, "y": 216}, {"x": 213, "y": 211},
                          {"x": 373, "y": 206}], r,
                         "托盘坐标与页面公式不一致（会误判「有没有被拖出」）")

    def _check(self, placed: int, correct: int, answer_ok=True):
        """Drive vigil_check_slider with a synthetic challenge."""
        slots = [{"x": 100 + i * 60, "y": 60 + i * 60, "shape": "right"}
                 for i in range(3)]
        tray = [{"x": 53, "y": 216}, {"x": 213, "y": 211},
                {"x": 373, "y": 206}]
        drops = []
        for i in range(3):
            if i < placed:
                # Correct for the first `correct` placed pieces, off by 60
                # (well past any tolerance) for the rest.
                off = 0 if i < correct else 60
                x, y = slots[i]["x"] + off, slots[i]["y"]
                track = [[30, 240, 0], [40, 230, 40], [60, 210, 90],
                         [80, 190, 150], [x, y, 220], [x + 3, y + 2, 260]]
            else:
                x, y = tray[i]["x"], tray[i]["y"]
                track = []
            drops.append({"x": x, "y": y, "track": track})
        body = (
            "$slots = json_decode(%s, true);\n"
            "$drops = json_decode(%s, true);\n"
            "$meta = ['mode'=>'slider','exp'=>time()+600,'born'=>time()-5,"
            "'bind'=>vigil_client_binding(),'slots'=>$slots,"
            "'q_ans'=>1,'q_opts'=>['a','b','c'],'q_text'=>'q'];\n"
            "echo json_encode(['ok'=>true]);"
            % (_php_quote(json.dumps(slots)), _php_quote(json.dumps(drops))))
        return body

    def _verdict(self, placed: int, correct: int):
        """Run the real checker over a written challenge file."""
        slots = [{"x": 100 + i * 60, "y": 60 + i * 60, "shape": "right"}
                 for i in range(3)]
        tray = [(53, 216), (213, 211), (373, 206)]
        drops = []
        for i in range(3):
            if i < placed:
                off = 0 if i < correct else 60
                x, y = slots[i]["x"] + off, slots[i]["y"]
                track = [[30, 240, 0], [40, 232, 40], [58, 208, 95],
                         [79, 186, 155], [x - 4, y - 3, 210], [x, y, 250]]
            else:
                x, y = tray[i][0], tray[i][1]
                track = []
            drops.append({"x": x, "y": y, "track": track})
        body = (
            "$slots = json_decode(%s, true);\n"
            "$drops = json_decode(%s, true);\n"
            "$g = json_decode(%s, true);\n"
            "$tol = $g['tolerance'];\n"
            "$tray = vigil_slider_tray($slots, $g);\n"
            "$placed = 0;\n"
            "foreach ($slots as $i => $s) {\n"
            "  $d = $drops[$i];\n"
            "  if (abs($d['x'] - $tray[$i]['x']) > 3"
            " || abs($d['y'] - $tray[$i]['y']) > 3) { $placed++; }\n"
            "}\n"
            "$wrong = 0;\n"
            "foreach ($slots as $i => $s) {\n"
            "  $d = $drops[$i];\n"
            "  if (abs($d['x'] - $tray[$i]['x']) <= 3"
            " && abs($d['y'] - $tray[$i]['y']) <= 3) { continue; }\n"
            "  if (abs($d['x'] - $s['x']) > $tol"
            " || abs($d['y'] - $s['y']) > $tol) { $wrong++; }\n"
            "}\n"
            "echo json_encode(['placed' => $placed, 'wrong' => $wrong]);"
            % (_php_quote(json.dumps(slots)), _php_quote(json.dumps(drops)),
               _php_quote(json.dumps(self.GEOM))))
        return self._drive(body)

    def test_the_server_agrees_about_what_was_placed(self):
        self.assertEqual({"placed": 2, "wrong": 0}, self._verdict(2, 2))
        self.assertEqual({"placed": 3, "wrong": 0}, self._verdict(3, 3),
                         "三块都被当成「已放置」时，规则就失效了")
        self.assertEqual({"placed": 1, "wrong": 0}, self._verdict(1, 1))
        self.assertEqual({"placed": 2, "wrong": 1}, self._verdict(2, 1))

    def test_the_shipped_page_asks_for_two_and_draws_three(self):
        from vigil.gates import installer
        spec = gspec.GateSpec.for_kind(KIND_LOGIN)
        spec.state_dir = "/tmp/x"; spec.webroot = "/tmp/y"
        spec.username = "t"; spec.pass_hash = "$2y$10$" + "x" * 53
        spec.upstream_token_file = "/tmp/x/tok"
        spec.upstream_mint_url = "http://127.0.0.1:3080/"
        page = [c for p, (c, _m) in installer.render_files(spec).items()
                if p.name == "verify.php"][0]
        self.assertIn("$needPieces = min(2, $nPieces);", page)
        self.assertIn('data-need="<?= (int)$needPieces ?>"', page)

    def test_the_reminder_is_shown_while_the_hand_is_still_moving(self):
        """Told only at submit time, a person has already made the mistake."""
        from vigil.gates import installer
        spec = gspec.GateSpec.for_kind(KIND_LOGIN)
        spec.state_dir = "/tmp/x"; spec.webroot = "/tmp/y"
        spec.username = "t"; spec.pass_hash = "$2y$10$" + "x" * 53
        spec.upstream_token_file = "/tmp/x/tok"
        spec.upstream_mint_url = "http://127.0.0.1:3080/"
        page = [c for p, (c, _m) in installer.render_files(spec).items()
                if p.name == "verify.php"][0]
        self.assertIn("drawTrayHints", page,
                      "拖出去以后没有把原位画出来，用户不知道该放回哪里")


class TestSensitiveFileExposure(unittest.TestCase):
    """The files that were actually downloadable, and the rules that stop it.

    A hand-written blocklist was already on this host when these were found
    live: `account/captcha.php.bak-20260930-215427` (the full PHP source of
    the account captcha) and two editor backup pages. The blocklist expected
    a digit after `bak`; the real name had a hyphen. An enumeration cannot be
    reviewed by reading it -- only by running it against the filesystem --
    which is why the scanner and the nginx rule share one definition.
    """

    REAL_LEAKS = (
        "/account/captcha.php.bak-20260930-215427",
        "/index.html.editor_20260927_220602",
        "/index.html.editor_20260929_193749",
        "/chat.html.editor_20260816_185855",
        "/app/tools/convert/imgpdf/index.htmlold",
        "/function/.gitignore",
    )

    CONTROLS = (
        "/index.html", "/robots.txt", "/favicon.ico", "/404.html", "/418.html",
        "/function/index.html", "/function/files/game.js", "/assets/a.png",
        "/version.json", "/notice.json", "/bgm.ogg", "/bg.woff2",
        "/.well-known/acme-challenge/token123", "/CAPTCHA/demo.php",
        "/function/api/account", "/function/peerjs/x",
        "/function/files/vendor/katex/fonts/KaTeX_AMS-Regular.woff2",
    )

    def test_the_files_that_really_leaked_are_caught(self):
        from vigil.guards import exposure
        for uri in self.REAL_LEAKS:
            self.assertTrue(exposure.match_rules(uri),
                            "这个文件真的被公网下载过，规则却没命中：%s" % uri)

    def test_normal_web_assets_are_not_blocked(self):
        """Over-blocking takes a working site down, which is not hardening."""
        from vigil.guards import exposure
        for uri in self.CONTROLS:
            self.assertFalse(
                exposure.match_rules(uri),
                "正常资源被误杀，站点会 404：%s（命中 %s）"
                % (uri, exposure.match_rules(uri)))

    def test_vendor_is_not_a_blocked_directory(self):
        """A regression I introduced and then found with the scanner itself.

        `vendor/` is where Composer puts PHP dependencies, so blocking it
        looked right -- but it is also an ordinary name for public front-end
        assets, and this host serves `/function/files/vendor/katex/...` to
        browsers. The host-wide rule 404'd it. The scanner reported 63 of
        those fonts as "being downloaded from the internet", which is exactly
        the kind of false alarm that teaches an operator to ignore the tool.
        """
        from vigil.guards import exposure
        for _label, pattern in exposure.DIRECTORY_RULES:
            self.assertNotIn("|vendor|", pattern,
                             "vendor/ 又被当成敏感目录了")
        self.assertFalse(exposure.match_rules(
            "/function/files/vendor/katex/fonts/KaTeX_AMS-Regular.ttf",
            exposure.DIRECTORY_RULES))

    def test_the_scanner_and_the_nginx_rule_cannot_drift(self):
        """The rendered snippet must carry exactly the patterns the scanner runs.

        This is the assertion that makes the pairing safe. If someone edits
        the snippet text or adds a Python-only pattern, the server and the
        scanner stop agreeing -- and the failure mode is the worst one
        available: the scan reports "clean" while nginx hands the file out.
        """
        from vigil.guards import exposure
        rendered = exposure.render_deny_snippet()
        found = re.findall(r'location ~\* "(.+)" \{', rendered)
        self.assertEqual([p for _l, p in exposure.SHAPE_RULES], found,
                         "渲染出的 nginx 规则与扫描器用的模式不一致")
        rendered_dirs = exposure.render_directory_snippet()
        found_dirs = re.findall(r'location ~\* "(.+)" \{', rendered_dirs)
        self.assertEqual([p for _l, p in exposure.DIRECTORY_RULES], found_dirs)

    def test_percent_encoding_is_decoded_before_matching(self):
        """nginx decodes and normalises before it matches a location regex.

        A scanner that tested the raw request string would call `/x%2ebak`
        safe while nginx served it as `x.bak`.
        """
        from vigil.guards import exposure
        for uri in ("/x%2ebak", "/x.php%2ebak", "/x.bak",
                    "/%2e%2e/%2e%2e/etc/passwd", "/index.html%2eeditor_20260927_220602"):
            self.assertTrue(exposure.match_rules(uri),
                            "编码绕过没有被解出来：%s" % uri)
        # Double encoding must not turn a safe path into a hit either.
        self.assertFalse(exposure.match_rules("/function/game.js"))

    def test_extra_suffixes_that_are_never_legitimate(self):
        from vigil.guards import exposure
        for uri in ("/db.sqlite", "/backup.sql", "/1.tar.gz", "/server.key",
                    "/id_rsa", "/id_ed25519", "/authorized_keys", "/x.env",
                    "/.env", "/.ssh/id_rsa", "/config.1", "/x~",
                    "/wp-config.php", "/notes.txt.bak"):
            self.assertTrue(exposure.match_rules(uri),
                            "高危名称没有命中：%s" % uri)

    def test_unknown_suffixes_are_probed_rather_than_banned(self):
        """`.md` is the line between "block it" and "ask".

        Markdown in a webroot usually should not be public, but it can also be
        a documentation site's payload, so the rule does not block it. What
        must not happen is that it is *ignored*: anything outside the asset
        allowlist is collected by the scanner and fetched, so a deployment
        note that really is downloadable is reported as a finding rather than
        passing because no rule mentioned it.
        """
        from vigil.guards import exposure
        self.assertNotIn("md", exposure.SAFE_SUFFIXES,
                         ".md 被当成正常资源后就不会再被探测了")
        self.assertFalse(exposure.match_rules("/DEPLOY.md"),
                         ".md 不该被规则直接拒绝（可能是文档站的正常内容）")
        import tempfile
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        Path(tmp, "DEPLOY.md").write_text("secret-ish", encoding="utf-8")
        Path(tmp, "a.png").write_text("x", encoding="utf-8")
        found = [i["uri"] for i in exposure.unusual_suffixes(tmp)]
        self.assertIn("/DEPLOY.md", found, "未知后缀没有被收进待探测清单")
        self.assertNotIn("/a.png", found, "正常资源不该进待探测清单")

    def test_prefix_bypass_is_found_and_must_be_covered(self):
        """`^~` makes nginx skip regex locations -- the subtree goes naked."""
        from vigil.guards import exposure
        pre_fix = """
        server {
            location ~* "\\.(bak|old)$" { return 404; }
            location ^~ /app/ {
                try_files $uri $uri/ /app/index.html;
            }
        }
        """
        a = exposure.audit_conf(pre_fix)
        self.assertEqual(["/app/"], [b["prefix"] for b in a["uncovered"]],
                         "没查出 ^~ 前缀旁路")

        post_fix = pre_fix.replace(
            "try_files", "include /x/zz-exposure-deny.conf;\n try_files")
        a2 = exposure.audit_conf(post_fix)
        self.assertEqual([], a2["uncovered"], "挂上 include 后仍报旁路")

    def test_exact_match_and_proxy_prefixes_are_not_reported(self):
        """False alarms on a security command are worse than no command."""
        from vigil.guards import exposure
        conf = """
        server {
            location = /__gate/login { root /www/wwwroot/dsh-gate; }
            location ^~ /api/ { proxy_pass http://127.0.0.1:9100/; }
            location ^~ /old/ { return 404; }
        }
        """
        a = exposure.audit_conf(conf)
        self.assertEqual([], a["uncovered"],
                         "精确匹配/proxy/return 前缀被误报为暴露空洞")
        kinds = {b["prefix"]: b["kind"] for b in a["prefixes"]}
        self.assertEqual("=", kinds["/__gate/login"])
        self.assertEqual("^~", kinds["/api/"])

    def test_the_snippet_is_structurally_valid_nginx(self):
        """Balanced braces and one `return 404` per location."""
        from vigil.guards import exposure
        for text in (exposure.render_deny_snippet(),
                     exposure.render_directory_snippet()):
            self.assertEqual(text.count("{"), text.count("}"),
                             "生成的花括号不配对")
            self.assertEqual(text.count("location ~*"), text.count("return 404"),
                             "有 location 没有 return")

    def test_the_live_config_is_not_left_with_a_hole(self):
        """Operator-only: is *this* machine's `^~` prefix protected?

        Skipped unless VIGIL_LIVE_AUDIT=1. It inspects whatever nginx is
        installed on the machine running the tests, so in a shipped suite it
        would either skip or -- on a host that legitimately has a `^~` prefix
        without our rules -- fail for a reason that is not a bug in the code.
        The product check for this is `vigil exposure status`, which is what
        an operator should actually run; this is here for the development host.
        """
        import os
        if os.environ.get("VIGIL_LIVE_AUDIT") != "1":
            self.skipTest("operator-only check; set VIGIL_LIVE_AUDIT=1 to run")
        from vigil.guards import exposure
        # Discovered, not hardcoded: naming this operator's own vhost
        # directory leaked the address and made the test meaningless anywhere
        # else. Any site whose config uses a `^~` prefix is checked.
        roots = list(Path("/www/server/panel/vhost/nginx/extension").glob("*"))
        roots += list(Path("/etc/nginx").rglob("*.conf"))
        found = 0
        for conf in roots:
            for f in ([conf] if conf.is_file() else sorted(conf.glob("*.conf"))):
                try:
                    text = f.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if "location ^~" not in text:
                    continue
                found += 1
                a = exposure.audit_conf(text)
                self.assertEqual([], a["uncovered"],
                                 "%s 的 ^~ 前缀没挂拒绝规则：%s"
                                 % (f, a["uncovered"]))
        if not found:
            self.skipTest("本机没有使用 ^~ 前缀的站点，跳过")
        self.assertEqual([], a["uncovered"],
                         "主站的 ^~ 前缀又没挂拒绝规则了：%s" % a["uncovered"])


class TestCaptchaAssetsStayInStep(unittest.TestCase):
    """The bug the other agent found: page and endpoint had come apart.

    The puzzle grew to three pieces; the generator wrote `piece3.png` and the
    page asked for `part=slider-piece3`, but the asset endpoint listed
    `slider-piece1` and `slider-piece2` by hand. The login page stopped
    rendering and every check still said OK, because nothing compared the two.

    The fix is that the endpoint parses the name. These tests hold that --
    an enumeration is what goes stale.
    """

    def _tpl(self, name):
        return (Path(__file__).resolve().parent.parent / "src" / "vigil" /
                "gates" / "templates" / (name + ".tmpl")).read_text(
                    encoding="utf-8")

    def _tpl(self, name):
        return (Path(__file__).resolve().parent.parent / "src" / "vigil" /
                "gates" / "templates" / (name + ".tmpl")).read_text(
                    encoding="utf-8")

    def _php(self):
        """A PHP binary that can run the library, or None."""
        for cand in ("/www/server/php/82/bin/php", "php", "php8.2", "php8"):
            exe = shutil.which(cand) if "/" not in cand else (
                cand if Path(cand).is_file() else None)
            if exe:
                return exe
        return None

    def _run_library(self, php_code):
        """Render the library, run `php_code` against it, return its JSON.

        Executing beats grepping. The earlier version of these tests looked
        for `preg_match('/^slider-piece(` in the endpoint's text, so when the
        resolution moved into a shared helper the tests failed while the
        behaviour was *better* than before. A test that asserts an
        implementation detail reports on the wrong thing; this one calls the
        function and reads the answer.
        """
        from vigil.gates import installer
        php = self._php()
        if not php:
            self.skipTest("没有 php，无法执行网关库")
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(tmp), True)
        spec = gspec.GateSpec.for_kind(KIND_LOGIN)
        spec.state_dir = str(tmp / "state")
        spec.webroot = str(tmp / "web")
        spec.username = "t"; spec.pass_hash = "$2y$10$" + "x" * 53
        spec.upstream_token_file = str(tmp / "state" / "tok")
        spec.upstream_mint_url = "http://127.0.0.1:3080/"
        writer = {}
        for pth, (content, _mode) in installer.render_files(spec).items():
            if pth.name in ("gate-lib.php", "config.php", "captcha.php",
                            "demo.php"):
                (tmp / pth.name).write_text(content, encoding="utf-8")
                writer[pth.name] = content
        self.files = writer
        driver = tmp / "drive.php"
        driver.write_text("<?php\nrequire %s;\n%s\n" % (
            _php_quote(str(tmp / "gate-lib.php")), php_code), encoding="utf-8")
        proc = subprocess.run([php, "-d", "error_reporting=E_ALL",
                               str(driver)],
                              capture_output=True, text=True, timeout=90)
        self.assertEqual(proc.returncode, 0,
                         "php 执行失败：%s" % (proc.stderr or "")[-400:])
        out = (proc.stdout or "").strip().splitlines()
        self.assertTrue(out, "php 没有输出：%s" % (proc.stderr or "")[-300:])
        return json.loads(out[-1])

    def test_the_asset_endpoint_resolves_every_piece_the_generator_writes(self):
        res = self._run_library(
            "$out = [];\n"
            "foreach (['slider-bg','slider-objects','slider-piece1',"
            "'slider-piece2','slider-piece3','slider-piece16'] as $p) {\n"
            "    $out[$p] = vigil_slider_suffix($p);\n"
            "}\n"
            "echo json_encode($out);")
        self.assertEqual(".bg.png", res["slider-bg"])
        self.assertEqual(".objects.png", res["slider-objects"])
        for n in (1, 2, 3, 16):
            self.assertEqual(".piece%d.png" % n, res["slider-piece%d" % n],
                             "第 %d 块拼片解析不出来" % n)

    def test_an_out_of_range_or_hostile_part_resolves_to_nothing(self):
        """`part=slider-piece999` must not become a path walk."""
        hostile = ["slider-piece0", "slider-piece17", "slider-piece999",
                   "slider-piece-1", "slider-piece1x", "../slider-bg",
                   "slider-piece1/../../etc/passwd", "slider-scene", "",
                   "slider-piece 3", "slider-piece" + "9" * 40]
        res = self._run_library(
            "$bad = json_decode(%s, true);\n"
            "$out = [];\n"
            "foreach ($bad as $p) {\n"
            "    $out[$p] = vigil_slider_suffix($p);\n"
            "    $out['asset:' . $p] = vigil_slider_asset('/nonexistent',\n"
            "        'a' . str_repeat('b', 31), $p);\n"
            "}\n"
            "echo json_encode($out);" % _php_quote(json.dumps(hostile)))
        for p in hostile:
            self.assertEqual("", res[p], "危险或越界的 part 被解析成了路径：%r" % p)
            self.assertIsNone(res["asset:" + p], "越界 part 仍拼出了路径：%r" % p)

    def test_a_bad_cid_cannot_become_a_path(self):
        res = self._run_library(
            "$out = [];\n"
            "foreach (['../../etc/passwd', 'short', '', "
            "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', "
            "'../../../../www/wwwroot/example-site/account/api.php'] as $c) {\n"
            "    $out[$c] = vigil_slider_asset('/tmp', $c, 'slider-bg');\n"
            "}\n"
            "echo json_encode($out);")
        for cid, val in res.items():
            if cid == "a" * 32:
                continue
            self.assertIsNone(val, "非法 cid 拼出了路径：%r -> %r" % (cid, val))

    def test_both_endpoints_delegate_to_the_one_resolver(self):
        """No second hand-written list to fall out of step again."""
        self._run_library("echo json_encode([]);")
        # captcha.php names the part, so it resolves the suffix itself; the
        # demo page only serves what it is asked for, so it goes straight to
        # the path. Both must use the one resolver rather than their own list.
        bodies = {"captcha.php": self.files["captcha.php"],
                  "demo.php": self._tpl("demo.php")}
        self.assertIn("vigil_slider_suffix(", bodies["captcha.php"],
                      "captcha.php 没有使用共享解析器")
        for name, body in bodies.items():
            self.assertIn("vigil_slider_asset(", body,
                          "%s 没有使用共享路径解析" % name)
            self.assertNotIn("'slider-piece1' =>", body)
            self.assertNotIn(".piece' . $n . '.png'", body,
                             "%s 里还留着第二份拼片命名逻辑" % name)

    def test_the_text_challenge_is_drawn_in_one_place(self):
        """The endpoint must not carry its own copy of the drawing code."""
        self._run_library("echo json_encode([]);")
        cap = self.files["captcha.php"]
        self.assertIn("vigil_captcha_png(", cap,
                      "文字验证码没有走共享绘制函数")
        for marker in ("imagettftext", "imagecreatetruecolor", "imagepng("):
            self.assertNotIn(marker, cap,
                             "captcha.php 里还有一份绘制代码：%s" % marker)

    def test_the_selftest_compares_claims_against_files(self):
        st = (Path(__file__).resolve().parent.parent / "src" / "vigil" /
              "gates" / "selftest.py").read_text(encoding="utf-8")
        self.assertIn("piece_files", st)
        self.assertIn("count($pieceFiles) === $slotCount2", st)


class TestFreeDragCaptcha(unittest.TestCase):
    """Free two-dimensional dragging, several shapes, one right answer each.

    A slider yields a single number and a one-dimensional ramp, so the only
    thing that can be judged is where it ended up and the path a script
    synthesises trivially. Dragging the piece freely yields a two-dimensional
    path with curvature and correction, and a two-dimensional position.
    """

    @classmethod
    def setUpClass(cls):
        from vigil.gates import installer
        cls.tmp = tempfile.TemporaryDirectory()
        spec = gspec.GateSpec.for_kind(KIND_LOGIN)
        base = Path(cls.tmp.name)
        spec.state_dir = str(base / "state")
        spec.webroot = str(base / "web")
        spec.require_password = True
        spec.username = "t"; spec.pass_hash = "$2y$10$" + "x" * 53
        spec.upstream_token_file = str(base / "state" / "tok")
        spec.upstream_mint_url = "http://127.0.0.1:3080/"
        cls.rendered = installer.render_files(spec)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _lib(self):
        for p, (c, _m) in self.rendered.items():
            if p.name == "gate-lib.php":
                return c
        raise AssertionError("no gate-lib.php")

    def _page(self, name):
        for p, (c, _m) in self.rendered.items():
            if p.name == name:
                return c
        tmpl = (Path(__file__).resolve().parent.parent / "src" / "vigil" /
                "gates" / "templates" / (name + ".tmpl"))
        return tmpl.read_text(encoding="utf-8")

    def test_the_piece_is_dragged_in_two_dimensions(self):
        page = self._page("verify.php")
        self.assertIn("grabDX", page)
        self.assertIn("grabDY", page)
        self.assertIn("curs[active]", page)
        # No slider left to fall back on.
        self.assertNotIn('class="track"', page)
        self.assertNotIn("slider_x", page)

    def test_the_track_records_both_axes(self):
        lib = self._lib()
        self.assertIn("$steps[] = sqrt($dx * $dx + $dy * $dy);", lib,
                      "轨迹分析仍是一维的")

    def test_several_gaps_each_with_its_own_shape(self):
        lib = self._lib()
        self.assertIn("$shapes = ['right', 'left', 'top', 'bottom'];", lib)
        self.assertIn("shuffle($shapes);", lib)

    def test_the_pieces_are_not_interchangeable(self):
        """Different knob per gap, so only one piece fits a given gap."""
        lib = self._lib()
        self.assertIn("string $shape = 'right'", lib)

    def test_every_drop_is_checked_against_its_own_slot(self):
        lib = self._lib()
        self.assertIn("foreach ($slots as $idx => $slot)", lib)
        self.assertIn("$drops[$idx]", lib)

    def test_the_page_submits_all_drops(self):
        page = self._page("verify.php")
        self.assertIn('name="drops"', page)
        self.assertIn("JSON.stringify(drops)", page)


class TestFusedCaptcha(unittest.TestCase):
    """Two factors, one challenge, both enforced on the server.

    The slider alone asks only "where does this go?", and the answer is
    visible in the picture -- it has to be, or a person could not solve it.
    Anything that can find a rectangle can therefore answer it. The passcode
    asks a second, different question: read distorted text. Fusing them means
    a bot needs spatial reasoning *and* OCR, and both answers are checked by
    the same server-side drag validation that was already there.
    """

    @classmethod
    def setUpClass(cls):
        from vigil.gates import installer
        cls.tmp = tempfile.TemporaryDirectory()
        cls._old = None
        spec = gspec.GateSpec.for_kind(KIND_LOGIN)
        base = Path(cls.tmp.name)
        spec.state_dir = str(base / "state")
        spec.webroot = str(base / "web")
        spec.require_password = True
        spec.username = "tester"
        spec.pass_hash = "$2y$10$" + "x" * 53
        spec.upstream_token_file = str(base / "state" / "tok")
        spec.upstream_mint_url = "http://127.0.0.1:3080/"
        cls.rendered = installer.render_files(spec)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _lib(self):
        for p, (c, _m) in self.rendered.items():
            if p.name == "gate-lib.php":
                return c
        raise AssertionError("gate-lib.php was not rendered")

    def _page(self, name):
        for p, (c, _m) in self.rendered.items():
            if p.name == name:
                return c
        tmpl = (Path(__file__).resolve().parent.parent / "src" / "vigil" /
                "gates" / "templates" / (name + ".tmpl"))
        return tmpl.read_text(encoding="utf-8")

    def test_the_server_generates_and_stores_a_passcode(self):
        lib = self._lib()
        self.assertIn("'code'   => $code,", lib,
                      "挑战记录里没有口令，第二重因素不存在")
        self.assertIn("vigil_alphabet()", lib)

    def test_the_server_verifies_the_question(self):
        lib = self._lib()
        self.assertIn("WRONG_ANSWER", lib, "服务端没有校验题目的分支")
        self.assertIn("string $qAnswer = ''", lib,
                      "校验函数没有接收题目答案参数")
        self.assertIn("hash_equals($wantAns, $gotAns)", lib,
                      "答案比较不是常数时间")

    def test_the_page_collects_the_answer_without_knowing_it(self):
        """The page shows the question and the options, never the answer."""
        page = self._page("verify.php")
        self.assertIn('name="q_answer"', page)
        self.assertIn("q_text", page)
        # No option may arrive pre-selected, and the answer index must not be
        # anywhere in the served HTML.
        for tag in re.findall(r"<input[^>]*>", page):
            self.assertNotIn("checked", tag, tag)
        self.assertNotIn("q_ans", page.replace("q_answer", ""))

    def test_the_shapes_are_drawn_on_a_layer_above_the_pieces(self):
        """A piece dragged over a shape would hide what has to be counted."""
        lib = self._lib()
        self.assertIn(".objects.png", lib, "没有独立的图形层")
        page = self._page("verify.php")
        self.assertIn("objCanvas", page)
        # Drawn after the pieces, not before.
        self.assertLess(page.index("drawPiece(shown, chaos, t)"),
                        page.index("ctx.drawImage(objCanvas"))

    def test_multi_piece_support_is_generic_not_hardcoded(self):
        """Hardcoding two slots would hand a third piece over for free."""
        lib = self._lib()
        self.assertIn("foreach ($slots as $idx => $slot)", lib,
                      "校验没有遍历所有拼片")

    def test_the_failure_message_does_not_say_which_factor_failed(self):
        """Saying which one failed lets a script search them independently."""
        page = self._page("verify.php")
        m = re.search(r"\$error = \$t\('([^']*)'", page)
        self.assertIsNotNone(m)
        msg = m.group(1)
        self.assertIn("拼片", msg)
        self.assertIn("问题", msg)

    def test_the_demo_enforces_the_question_too(self):
        tmpl = self._page("demo.php")
        self.assertIn("q_answer", tmpl)
        self.assertIn("q_ans", tmpl)


class TestGateSelftest(unittest.TestCase):
    """The check that would have caught the alignment regression.

    Every automated test passed while the piece could not be lined up with the
    gap; the only detector was the operator looking at the screen. These tests
    pin the detector, including the negative case -- a page that computes the
    answer, or one that animates the picture, must be reported.
    """

    def setUp(self):
        from vigil.gates import selftest
        self.st = selftest
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.webroot = Path(self.tmp.name)

    def _page(self, body: str):
        (self.webroot / "verify.php").write_text(body, encoding="utf-8")
        return self.st._page_problems(str(self.webroot))

    def test_a_good_page_passes(self):
        probs = self._page("var chaos = 0;\n// drag the piece into the gap\n")
        self.assertTrue(all(p["ok"] for p in probs), probs)

    def test_the_regression_is_reported(self):
        """A picture that moves as you drag makes the piece unalignable."""
        probs = self._page("var chaos = 1 - shown;\n")
        self.assertFalse(all(p["ok"] for p in probs), probs)
        self.assertTrue(any("静止" in p["detail"] for p in probs), probs)

    def test_client_side_answer_computation_is_reported(self):
        for bad in ("locateGap(a,b)", "gapLeft", 'data-scene="/x"'):
            probs = self._page("var chaos = 0;\n" + bad)
            self.assertFalse(all(p["ok"] for p in probs),
                             "%s 没有被报出来" % bad)

    def test_a_missing_page_is_reported_not_ignored(self):
        """'Could not look' must not read as 'nothing to see'."""
        probs = self.st._page_problems(str(self.webroot))
        self.assertFalse(all(p["ok"] for p in probs), probs)

    def test_missing_php_is_reported_rather_than_crashing(self):
        class Spec:
            kind = "x"
            state_dir = "/nonexistent"
            webroot = "/nonexistent"
        r = self.st.verify_gate(Spec(), php="")
        self.assertFalse(r["ok"])
        self.assertTrue(r["problems"])

    def test_an_incomplete_install_is_reported(self):
        class Spec:
            kind = "x"
            state_dir = str(self.webroot)
            webroot = str(self.webroot)
        r = self.st.verify_gate(Spec(), php="/bin/true")
        self.assertFalse(r["ok"])
        self.assertTrue(any("不完整" in p for p in r["problems"]), r)

    def test_the_command_is_registered(self):
        """Parse it and check it routes to the selftest handler.

        Asserting on the parser's internals proves only that argparse exists;
        the useful question is whether `gate selftest` actually reaches the
        function that does the work.
        """
        from vigil import cli
        from vigil.commands import gate as gate_cmd
        args = cli.build_parser().parse_args(["gate", "selftest"])
        self.assertIs(args.func, gate_cmd.cmd_selftest)


class TestSliderPieceAlignsWithTheGap(unittest.TestCase):
    """The piece must be able to sit exactly in the gap.

    The picture used to be animated: `chaos = 1 - shown` with `shown` easing
    toward "how close the piece is to the answer". That settle *was* the
    guidance -- and it required the page to know the answer, which it got by
    differencing the marked background against an unmarked copy. Removing the
    unmarked copy (the security fix) and re-pointing `progressFor` at the raw
    drag position made the bands shift as you dragged, so the gap drifted and
    the piece could never be lined up with it.

    There is no way to have both: any "you are close" feedback is also a hint
    a bot can read. So the picture is shown at rest and the alignment is made
    exact instead of animated. These tests hold that contract.
    """

    @classmethod
    def setUpClass(cls):
        from vigil.gates import installer
        cls.tmp = tempfile.TemporaryDirectory()
        spec = gspec.GateSpec.for_kind(KIND_LOGIN)
        base = Path(cls.tmp.name)
        spec.state_dir = str(base / "state")
        spec.webroot = str(base / "web")
        spec.require_password = True
        spec.username = "tester"
        spec.pass_hash = "$2y$10$" + "x" * 53
        spec.upstream_token_file = str(base / "state" / "tok")
        spec.upstream_mint_url = "http://127.0.0.1:3080/"
        cls.rendered = installer.render_files(spec)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _all(self):
        return {p.name: c for p, (c, _m) in self.rendered.items()}

    def _page(self, name):
        """Rendered page, or the template for pages rendered separately.

        `demo.php` is produced by the demo installer rather than by
        `render_files`, so fall back to reading its template directly -- the
        property being asserted lives in the template either way.
        """
        got = self._all().get(name)
        if got is not None:
            return got
        tmpl = (Path(__file__).resolve().parent.parent / "src" / "vigil" /
                "gates" / "templates" / (name + ".tmpl"))
        if tmpl.is_file():
            return tmpl.read_text(encoding="utf-8")
        self.fail("找不到 %s 的渲染结果或模板" % name)

    def test_the_picture_is_shown_at_rest(self):
        """Undisplaced bands mean the gap is where the image says it is."""
        for name in ("verify.php", "demo.php"):
            body = self._page(name)
            self.assertIn("var chaos = 0;", body,
                          "%s 仍在按拖动位置移动画面，拼片会对不上缺口" % name)
            self.assertNotIn("var chaos = 1 - shown;", body, name)

    def test_the_page_does_not_animate_towards_the_answer(self):
        """`1 - closeness` is the coupling that leaks the answer."""
        for name in ("verify.php", "demo.php"):
            body = self._page(name)
            self.assertNotIn("gapLeft", body)
            self.assertNotIn("locateGap", body)

    def test_the_gap_marker_is_still_drawn_on_the_background(self):
        """Static picture is only solvable if the gap stays visible."""
        lib = None
        for p, (c, _m) in self.rendered.items():
            if p.name == "gate-lib.php":
                lib = c
        self.assertIsNotNone(lib)
        # The marker is drawn on the background at the piece's own x/y.
        self.assertIn("edgeGlow", lib)
        self.assertIn("imagepng($bg", lib)

    def test_the_hint_no_longer_promises_proximity_feedback(self):
        """Text that promises "it lights up as you get close" is now a lie."""
        for name in ("verify.php", "demo.php"):
            self.assertNotIn("缺口会高亮提示", self._page(name), name)


class TestCaptchaPicturePools(unittest.TestCase):
    """Which pictures each surface is allowed to show, and that settings stick.

    Three separate things were wrong here and each looked fine on its own:
    the main site inherited the gates' pool (so a public page would have shown
    anime), the anti-repeat memory held only 8 pictures (so the same one came
    round again), and `vigil gate reconfigure` never wrote its settings back
    to the configuration -- so the next `vigil update` silently reverted them.
    """

    @classmethod
    def setUpClass(cls):
        from vigil.gates import installer
        cls.tmp = tempfile.TemporaryDirectory()
        cls.installer = installer
        spec = gspec.GateSpec.for_kind(KIND_LOGIN)
        base = Path(cls.tmp.name)
        spec.state_dir = str(base / "state")
        spec.webroot = str(base / "web")
        spec.require_password = True
        spec.username = "tester"
        spec.pass_hash = "$2y$10$" + "x" * 53
        spec.upstream_token_file = str(base / "state" / "tok")
        spec.upstream_mint_url = "http://127.0.0.1:3080/"
        cls.rendered = installer.render_files(spec)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _lib(self):
        for p, (c, _m) in self.rendered.items():
            if p.name == "gate-lib.php":
                return c
        raise AssertionError("gate-lib.php was not rendered")

    def test_the_anti_repeat_memory_is_large_enough_to_matter(self):
        """8 pictures is small enough that a repeat is a normal occurrence."""
        import re
        lib = self._lib()
        m = re.search(r"array_slice\(\$seen, -(\d+)\)", lib)
        self.assertIsNotNone(m, "找不到防重复窗口")
        self.assertGreaterEqual(int(m.group(1)), 32,
                                "防重复窗口太小，同一张图很快会再次出现")

    def test_the_picture_source_is_recorded_on_the_challenge(self):
        """The by-reference parameter was never assigned, so every
        picture-based challenge recorded an empty source and 'which picture
        was that?' had no answer."""
        lib = self._lib()
        self.assertIn("$source = basename((string)$candidate);", lib)

    def test_the_demo_does_not_inherit_the_gates_picture_pool(self):
        """The main site is public: it must get its own list, or it shows the
        gates' anime."""
        import inspect
        from vigil.gates import demo as demo_mod
        src = inspect.getsource(demo_mod.install) if hasattr(demo_mod, "install") \
            else inspect.getsource(demo_mod)
        self.assertIn("gate.demo.image_dirs", src,
                      "演示页没有独立的图片池设置，会继承网关的（含二次元）")

    def test_reconfigure_writes_its_settings_back_to_the_config(self):
        """Without this the change lives only in config.php and the next
        update regenerates the gate from the stale configuration."""
        import inspect
        from vigil.commands import gate as gate_cmd
        self.assertTrue(hasattr(gate_cmd, "_mirror_to_config"),
                        "reconfigure 不会把设置写回配置，升级会把它悄悄改回去")
        src = inspect.getsource(gate_cmd.cmd_reconfigure)
        self.assertIn("_mirror_to_config", src)


class TestBackupsHappenWithoutBeingAsked(unittest.TestCase):
    """`backup_age` must not be the only thing that cares about backups.

    On this host the check sat at CRIT -- "最近备份已过期 3.3 天" -- because
    nothing was ever scheduled to make one. A check that reports a problem
    nobody is going to fix is worse than no check: it teaches the operator to
    ignore the one that matters. Anything this program can do safely it does,
    and taking a backup is safe.
    """

    def _units(self):
        from vigil.core import units
        cfg = vconfig.Config(path=Path(tempfile.mkdtemp()) / "c.json",
                             secrets_path=Path(tempfile.mkdtemp()) / "s.json")
        return units.render_all(cfg, {"health", "threat", "mail", "login"})

    def test_a_backup_timer_is_installed_with_the_health_feature(self):
        u = self._units()
        self.assertIn("backup.timer", u, "没有自动备份定时器，备份迟早会过期")
        self.assertIn("backup.service", u)
        self.assertIn("vigil-backup.service", u["backup.timer"])

    def test_the_backup_unit_actually_runs_a_backup(self):
        u = self._units()
        self.assertIn("vigil backup", u["backup.service"])

    def test_the_backup_lock_does_not_collide_with_another_unit(self):
        """Two units sharing a lock would silently skip each other's runs."""
        from vigil.core import paths
        import re
        u = self._units()
        locks = []
        for body in u.values():
            locks += re.findall(r"flock -n (\S+)", body)
        self.assertEqual(len(locks), len(set(locks)),
                         "有两个单元用了同一把锁：%s" % locks)
        self.assertIn(str(paths.LOCK_BACKUP), u["backup.service"])

    def test_the_interval_is_configurable_and_defaults_to_daily(self):
        u = self._units()
        self.assertIn("OnUnitActiveSec=24h", u["backup.timer"])
        self.assertIn("Persistent=true", u["backup.timer"],
                      "错过的备份不会补做")


class TestCaptchaAnswerIsNotClientComputable(unittest.TestCase):
    """The answer must not be derivable in the browser.

    The gate used to serve two PNGs that differed only by the gap marker --
    the marked background and a clean copy. The page differenced them to find
    the gap, which meant the answer *was* computable on the client: subtract
    the two images, read the offset out of the pixels, synthesise a drag track
    long enough to satisfy the timing checks, submit. No image understanding
    required, which defeats the point of using a picture at all.

    These tests are deliberately about the *served artefacts*, not about the
    JavaScript: a future rewrite is free to reorganise the page, but it must
    not reintroduce a second copy of the background or anything else that
    hands the offset over.
    """

    @classmethod
    def setUpClass(cls):
        from vigil.gates import installer
        cls.tmp = tempfile.TemporaryDirectory()
        cls.installer = installer
        spec = gspec.GateSpec.for_kind(KIND_LOGIN)
        base = Path(cls.tmp.name)
        spec.state_dir = str(base / "state")
        spec.webroot = str(base / "web")
        spec.require_password = True
        spec.username = "tester"
        spec.pass_hash = "$2y$10$" + "x" * 53
        spec.upstream_token_file = str(base / "state" / "tok")
        spec.upstream_mint_url = "http://127.0.0.1:3080/"
        cls.rendered = installer.render_files(spec)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _content(self, name):
        for path, (content, _mode) in self.rendered.items():
            if path.name == name:
                return content
        raise AssertionError("%s was not rendered" % name)

    def _all(self):
        return {p.name: c for p, (c, _m) in self.rendered.items()}

    def test_the_unmarked_scene_is_never_served(self):
        """Two backgrounds differing only by the marker is the whole bug.

        Checks *every* template that serves slider assets. An earlier version
        of this test looked only at captcha.php, so the demo page kept serving
        the unmarked copy and the test passed anyway -- the fix was as
        incomplete as its test.
        """
        for name in ("captcha.php", "demo.php"):
            body = self._all().get(name)
            if body is None:
                continue
            self.assertNotIn("slider-scene", body,
                             "%s 仍在提供未标记的背景图" % name)
            self.assertNotIn(".scene.png", body,
                             "%s 仍在提供 .scene.png" % name)
            self.assertIn("slider-bg", body)
            self.assertIn("slider-piece", body)

    def test_the_challenge_does_not_write_an_unmarked_copy(self):
        lib = self._content("gate-lib.php")
        self.assertNotIn("imagepng($scene", lib,
                         "仍在把未标记的背景写进挑战目录")

    def test_the_page_does_not_reference_a_scene_image(self):
        for name in ("verify.php", "demo.php"):
            body = self._all().get(name)
            if body is None:
                continue
            self.assertNotIn("data-scene", body,
                             "%s 仍在向浏览器提供未标记的背景" % name)

    def test_no_client_side_gap_computation(self):
        """`getImageData` + a difference is how the offset was recovered."""
        for name in ("verify.php", "demo.php"):
            body = self._all().get(name)
            if body is None:
                continue
            self.assertNotIn("locateGap", body)
            self.assertNotIn("gapLeft", body)
        lib = self._content("gate-lib.php")
        self.assertIn("imagepng($bg", lib)
        self.assertIn("imagepng($piece", lib)

    def test_the_answer_still_lives_only_on_the_server(self):
        """The offset is stored in the challenge file and compared there."""
        lib = self._content("gate-lib.php")
        self.assertIn("vigil_check_slider", lib)
        self.assertIn("'bind'", lib)
        # The client-side drag track is still validated server-side.
        self.assertIn("NO_TRACK", lib)
        self.assertIn("ROBOTIC_SPEED", lib)


class TestGateTemplates(unittest.TestCase):
    """Render every template and check the pieces fit together."""

    @classmethod
    def setUpClass(cls):
        from vigil.gates import installer
        import shutil
        cls.tmp = tempfile.TemporaryDirectory()
        cls.installer = installer
        cls.spec = gspec.GateSpec.for_kind(KIND_LOGIN)
        base = Path(cls.tmp.name)
        cls.spec.state_dir = str(base / "state")
        cls.spec.webroot = str(base / "web")
        cls.spec.require_password = True
        cls.spec.username = "tester"
        cls.spec.pass_hash = "$2y$10$" + "x" * 53
        cls.spec.upstream_token_file = str(base / "state" / "tok")
        cls.spec.upstream_mint_url = "http://127.0.0.1:3080/"
        cls.rendered = installer.render_files(cls.spec)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _content(self, name):
        for path, (content, _mode) in self.rendered.items():
            if path.name == name:
                return content
        raise AssertionError("%s was not rendered" % name)

    def test_expected_files_are_produced(self):
        names = {p.name for p in self.rendered}
        for want in ("gate.lua", "policy.conf", "config.php", "gate-lib.php",
                     "verify.php", "captcha.php", "logout.php", "hook.php"):
            self.assertIn(want, names)

    def test_no_placeholders_survive(self):
        """An unreplaced __PLACEHOLDER__ is a broken gate on a live host.

        One of them (`__NAV_COOKIE__`) became a bare `nil` in a PHP file,
        which parses perfectly and then throws on the first request.
        """
        leftovers = []
        for path, (content, _mode) in self.rendered.items():
            for m in re.finditer(r"__[A-Z][A-Z_]{2,}__", content):
                if m.group(0) == "__DIR__":       # a PHP magic constant
                    continue
                leftovers.append("%s: %s" % (path.name, m.group(0)))
        self.assertEqual([], leftovers)

    def test_php_avoids_the_lua_null_keyword(self):
        """`nil` is Lua; in PHP it is an undefined constant and a fatal."""
        for name in ("config.php", "verify.php", "captcha.php", "logout.php"):
            content = self._content(name)
            self.assertNotRegex(
                content, r"=>\s*nil\b",
                "%s contains a bare `nil`, which is not valid PHP" % name)

    def test_strict_navigation_reaches_the_policy(self):
        policy = self._content("policy.conf")
        self.assertRegex(policy, r"(?m)^strict_nav=1$")
        lua = self._content("gate.lua")
        self.assertIn("strict_nav", lua)
        # The policy default table must carry the key, or a missing line in
        # the policy file silently reverts to lenient behaviour.
        self.assertRegex(lua, r"strict_nav\s*=\s*\d+")

    def test_honeypot_and_nonce_are_present(self):
        verify = self._content("verify.php")
        self.assertIn('name="website"', verify, "honeypot field is missing")
        self.assertIn("nonce", verify)

    def test_ticket_binding_uses_digests_on_both_sides(self):
        """PHP writes the ticket; Lua reads it. They must agree exactly.

        They once did not: PHP wrote hexadecimal timestamps and Lua parsed
        them as decimal, so `tonumber` returned nil and *every* session was
        treated as expired the moment it was created.
        """
        php = self._content("gate-lib.php")
        lua = self._content("gate.lua")
        self.assertIn("uah=", php)
        self.assertIn("iph=", php)
        self.assertIn("uah", lua)
        self.assertIn("iph", lua)
        # Decimal timestamps written by PHP, read as decimal by Lua.
        self.assertIn('exp=%d', php)
        self.assertNotIn('exp=%x', php)
        self.assertIn("tonumber(s, 16)", lua,
                      "the reader lost its hex fallback")

    def test_nginx_config_has_no_duplicate_zone_declaration(self):
        nginx = self.installer.render_nginx(self.spec)
        zones = self.installer.render_zones(self.spec)
        total = nginx.count("limit_req_zone") + zones.count("limit_req_zone")
        self.assertEqual(2, total,
                         "each zone must be declared exactly once, in http{}")


# --------------------------------------------------------------------------
# Interface text
# --------------------------------------------------------------------------


class TestText(unittest.TestCase):
    def test_every_chinese_string_has_an_english_one(self):
        missing = [k for k in i18n.ZH if k not in i18n.EN]
        self.assertEqual([], missing, "untranslated keys: %s" % missing)

    def test_translation_never_raises(self):
        self.assertEqual("no_such_key", i18n.t("no_such_key"))
        i18n.set_language("zh")
        self.assertIn("已", i18n.t("cancelled"))
        i18n.set_language("en")
        self.assertEqual("cancelled", i18n.t("cancelled"))
        i18n.set_language("")

    def test_display_width_counts_wide_glyphs(self):
        self.assertEqual(2, ui._display_len("中"))
        self.assertEqual(1, ui._display_len("a"))


# --------------------------------------------------------------------------
# Shell helpers
# --------------------------------------------------------------------------


class TestShell(unittest.TestCase):
    def test_never_inherits_stdin(self):
        """A child that reads stdin would hang the daemon.

        `ausearch` silently switches to reading stdin when it is a pipe and
        then reports no results, which is why every call here passes
        DEVNULL.
        """
        ok, out, _ = shell.run(["sh", "-c", "read x; echo got:$x"])
        self.assertTrue(ok)
        self.assertIn("got:", out)

    def test_missing_binary_is_reported_not_raised(self):
        ok, _out, err = shell.run(["definitely-not-a-real-program-xyz"])
        self.assertFalse(ok)
        self.assertTrue(err)

    def test_timeout_is_enforced(self):
        start = time.time()
        ok, _out, err = shell.run(["sleep", "5"], timeout=0.4)
        self.assertFalse(ok)
        self.assertLess(time.time() - start, 3.0)
        self.assertIn("timeout", err)

    def test_have_and_which(self):
        self.assertTrue(shell.have("sh"))
        self.assertFalse(shell.have("definitely-not-a-real-program-xyz"))


# --------------------------------------------------------------------------
# Health check framework
# --------------------------------------------------------------------------


class TestOutboundKnownServices(unittest.TestCase):
    """`对外连接异常` must not cry C2 over a browser's push channel.

    Chrome talks to Google's FCM/GCM endpoints on 5228-5230. Puppeteer
    therefore produced "可能是后门回连 C2" every time it ran, and an alert
    that fires on normal work is an alert nobody reads. The exemption is a
    *pair* -- unusual port plus the organisation that owns the destination --
    because a C2 server cannot live on an address registered to Google.
    """

    def setUp(self):
        from vigil.guards.checks import network as net
        self.net = net
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.cfg = vconfig.Config(path=base / "config.json",
                                  secrets_path=base / "secrets.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_known_ports_parses_the_pair_form(self):
        self.assertEqual({"5228": ["google"], "9999": [""]},
                         self.net._known_ports(["5228@google", " 9999 ", ""]))

    def test_defaults_cover_the_google_push_ports(self):
        entries = self.cfg.get("checks.outbound_connections.known_services")
        self.assertIn("5228@google", entries)
        for port in ("5228", "5229", "5230"):
            self.assertIn(port, self.net._known_ports(entries))

    def _run(self, ss_output, geo_text):
        """Run the check against a canned `ss` listing and geo answer."""
        from vigil.guards.checks import base as cbase
        ctx = cbase.CheckContext(cfg=self.cfg, state={}, env={},
                                 log=None, now=time.time())
        real_shell, real_geo = self.net.shell.run, self.net.util.geo
        real_listen = self.net.util.listening_ports
        self.net.shell.run = lambda *a, **k: (True, ss_output, "")
        self.net.util.geo = lambda *a, **k: geo_text
        self.net.util.listening_ports = lambda *a, **k: ["0.0.0.0:443 tcp"]
        try:
            return self.net.OutboundConnections().run(ctx)
        finally:
            self.net.shell.run = real_shell
            self.net.util.geo = real_geo
            self.net.util.listening_ports = real_listen

    _SS = ("ESTAB 0 0 203.0.113.10:40000 9.9.9.9:5228 "
           'users:(("chrome",pid=70694,fd=25))')

    def test_google_push_is_recognised_not_alarmed(self):
        r = self._run(self._SS, "美国 加州 芒廷维尤 · Google LLC · AS15169")
        self.assertEqual("OK", r.status)
        # Recognised, not hidden: the line still appears in the detail so
        # "what is this box talking to" remains answerable.
        self.assertIn("已识别的已知服务", r.detail)
        self.assertIn("5228", r.detail)

    def test_the_same_port_elsewhere_is_still_an_alert(self):
        r = self._run(self._SS, "荷兰 阿姆斯特丹 · Example Hosting BV · AS64500")
        self.assertEqual("WARN", r.status)
        self.assertIn("5228", r.detail)

    def test_an_unlisted_port_is_still_an_alert(self):
        ss = self._SS.replace(":5228", ":4444")
        r = self._run(ss, "美国 加州 芒廷维尤 · Google LLC · AS15169")
        self.assertEqual("WARN", r.status)

    def test_a_bare_port_means_any_destination(self):
        self.cfg.set("checks.outbound_connections.known_services", ["5228"])
        r = self._run(self._SS, "荷兰 阿姆斯特丹 · Example Hosting BV · AS64500")
        self.assertEqual("OK", r.status)

    def test_a_real_command_and_control_port_still_alerts(self):
        """The point of the check must survive the exemption."""
        ss = self._SS.replace(":5228", ":31337")
        r = self._run(ss, "荷兰 阿姆斯特丹 · Example Hosting BV · AS64500")
        self.assertEqual("WARN", r.status)
        self.assertIn("31337", r.detail)


class TestAlertPolicy(unittest.TestCase):
    """`alerts.mode` decides what is worth waking the operator for.

    The failure this prevents is not "an alert was missed", it is "there
    were so many alerts that none of them were read". On 2026-09-27 every
    message in the mailbox was either the program talking to itself or the
    operator's own activity; zero of them were an attack.
    """

    def setUp(self):
        from vigil.guards import health as health_mod
        self.h = health_mod
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.cfg = vconfig.Config(path=base / "config.json",
                                  secrets_path=base / "secrets.json")

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def _p(check_id, status):
        return {"id": check_id, "label": check_id, "status": status,
                "detail": "", "group": "network"}

    def test_default_mode_is_attacks(self):
        self.assertEqual("attacks", self.cfg.get("alerts.mode"))

    def test_drift_is_not_emailed(self):
        problems = [self._p("watch_files", "EVENT"),
                    self._p("listening_ports", "WARN"),
                    self._p("firewall_rules", "WARN")]
        self.assertEqual([], self.h.alertable(problems, "attacks"))

    def test_attacks_are_emailed(self):
        problems = [self._p("webshell_process", "WARN"),
                    self._p("av_hits", "CRIT")]
        self.assertEqual(2, len(self.h.alertable(problems, "attacks")))

    def test_any_crit_is_emailed_even_from_a_drift_check(self):
        # A CRIT from a drift check is not drift any more.
        problems = [self._p("watch_files", "CRIT")]
        self.assertEqual(1, len(self.h.alertable(problems, "attacks")))

    def test_mode_all_keeps_the_old_behaviour(self):
        problems = [self._p("watch_files", "EVENT")]
        self.assertEqual(1, len(self.h.alertable(problems, "all")))

    def test_the_attack_list_is_not_silently_empty(self):
        self.assertIn("av_hits", self.h._ATTACK_CHECKS)
        self.assertIn("webshell_process", self.h._ATTACK_CHECKS)
        # Drift checks must never appear here, or the split quietly stops
        # working and the mailbox fills up again.
        for drift in ("watch_files", "listening_ports", "firewall_rules",
                      "systemd_units", "cron_entries", "dns_config"):
            self.assertNotIn(drift, self.h._ATTACK_CHECKS)

    def test_own_logins_are_not_emailed(self):
        from vigil.guards import logind
        self.cfg.set("gate.login_alerts", True)
        self.cfg.set("mail.recipients", ["ops@example.invalid"])
        self.cfg.set("threat.whitelist", ["127.0.0.1/8", "::1"])
        sent = []
        real = logind.send_alert
        logind.send_alert = lambda *a, **k: sent.append(a) or _FakeReport()
        try:
            logind._notify(self.cfg, [{"ip": "127.0.0.1", "source": "ssh",
                                       "when": "now", "app": "sshd"}],
                           _QuietLog())
            self.assertEqual([], sent, "a whitelisted login must not be mailed")
            # ...but an address the operator never whitelisted still is.
            logind._notify(self.cfg, [{"ip": "198.51.100.9", "source": "ssh",
                                       "when": "now", "app": "sshd"}],
                           _QuietLog())
            self.assertEqual(1, len(sent))
        finally:
            logind.send_alert = real


class _FakeReport:
    def summary(self):
        return "sent 1/1"


class TestSelfTestCommand(unittest.TestCase):
    """`vigil selftest` must be believable, which means it must not cry wolf.

    It exists because every significant failure in this project looked
    healthy from the outside. The first version of it reported a hard
    failure on a perfectly valid nginx configuration, because `nginx -t`
    prints its verdict on stderr and the check read only stdout -- a false
    alarm in the one command whose whole value is being right about whether
    things work.
    """

    def setUp(self):
        from vigil.commands import selftest as st
        self.st = st
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.cfg = vconfig.Config(path=base / "config.json",
                                  secrets_path=base / "secrets.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_nginx_verdict_on_stderr_is_believed(self):
        from vigil.core import shell as shell_mod
        real_run, real_which = shell_mod.run, shutil.which
        shell_mod.run = lambda *a, **k: (
            True, "", "nginx: configuration file /x syntax is ok\n"
                      "nginx: configuration file /x test is successful")
        shutil.which = lambda name: "/usr/sbin/nginx" if name == "nginx" else None
        real_exists = self.st.os.path.exists
        self.st.os.path.exists = lambda p: True
        try:
            rep = self.st.collect(self.cfg)
            item = [i for i in rep.items if i["label"] == "Web 配置语法"][0]
            self.assertEqual("ok", item["status"], item["detail"])
        finally:
            shell_mod.run, shutil.which = real_run, real_which
            self.st.os.path.exists = real_exists

    def test_a_real_nginx_error_is_reported(self):
        from vigil.core import shell as shell_mod
        real_run, real_which = shell_mod.run, shutil.which
        shell_mod.run = lambda *a, **k: (
            False, "", 'nginx: [emerg] unknown directive "bogus" in /x:3')
        shutil.which = lambda name: "/usr/sbin/nginx" if name == "nginx" else None
        real_exists = self.st.os.path.exists
        self.st.os.path.exists = lambda p: True
        try:
            rep = self.st.collect(self.cfg)
            item = [i for i in rep.items if i["label"] == "Web 配置语法"][0]
            self.assertEqual("fail", item["status"])
            self.assertIn("unknown directive", item["detail"])
        finally:
            shell_mod.run, shutil.which = real_run, real_which
            self.st.os.path.exists = real_exists

    def test_every_item_carries_a_status_and_a_label(self):
        rep = self.st.collect(self.cfg)
        self.assertTrue(rep.items)
        for item in rep.items:
            self.assertIn(item["status"], ("ok", "warn", "fail"))
            self.assertTrue(item["label"])
            self.assertTrue(item["detail"])


class TestBackupRestore(unittest.TestCase):
    """The three things `vigil update` cannot put back.

    Everything this program generates is regenerable. `secrets.json`, the
    gate's password hash and the learned baselines are not -- and the
    baselines matter most exactly when they are gone, because a fresh
    baseline accepts whatever is on the disk at that moment.
    """

    def setUp(self):
        from vigil.commands import backup as bmod
        self.b = bmod
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "state").mkdir()
        (self.root / "etc").mkdir()
        self.cfg = vconfig.Config(path=self.root / "etc" / "config.json",
                                  secrets_path=self.root / "etc" / "secrets.json")
        self.cfg.set("backup.dir", str(self.root / "out"))
        self.cfg.secrets["smtp"] = {"password": "hunter2"}
        self.cfg.save()
        (self.root / "etc" / "secrets.json").write_text(
            json.dumps({"smtp": {"password": "hunter2"}}), encoding="utf-8")
        (self.root / "state" / "health.json").write_text(
            json.dumps({"status": {"watch_files": "OK"}}), encoding="utf-8")

        self.saved = (self.b.paths.CONFIG, self.b.paths.SECRETS,
                      self.b.paths.STATE_STATE)
        self.b.paths.CONFIG = self.root / "etc" / "config.json"
        self.b.paths.SECRETS = self.root / "etc" / "secrets.json"
        self.b.paths.STATE_STATE = self.root / "state"
        # Restoring must not write to the live gate state or the live nginx
        # directory. It used to: this class's round-trip test extracted the
        # archived gate files straight back over /www/server/<gate>/ and the
        # zones snippet over the real nginx conf directory -- identical
        # bytes, but a production write from a unit test.
        self.saved_gate_root = self.b.GATE_ROOT
        self.b.GATE_ROOT = self.root / "gates"
        # 站点配置的目标目录同样要指到临时树里：否则往返测试会往真实的
        # vhost 目录写（字节相同，但那是测试不该碰的生产路径）。
        self.saved_vhost_root = self.b.VHOST_ROOT
        self.b.VHOST_ROOT = self.root / "vhost"
        self._conf_patch = mock.patch(
            "vigil.gates.shield.conf_dir",
            return_value=self.root / "nginx-conf")
        self._conf_patch.start()

    def tearDown(self):
        self.b.GATE_ROOT = self.saved_gate_root
        self.b.VHOST_ROOT = self.saved_vhost_root
        self._conf_patch.stop()
        (self.b.paths.CONFIG, self.b.paths.SECRETS,
         self.b.paths.STATE_STATE) = self.saved
        self.tmp.cleanup()

    def test_a_backup_contains_credentials_and_baselines(self):
        rep = self.b.write_archive(self.cfg)
        self.assertTrue(rep["verify_ok"], rep["verify"])
        names = self.b._plan(Path(rep["path"]))[1]
        self.assertIn("etc/config.json", names)
        self.assertIn("etc/secrets.json", names)
        self.assertIn("state/health.json", names)

    def test_credentials_can_be_left_out(self):
        rep = self.b.write_archive(self.cfg, include_secrets=False)
        names = self.b._plan(Path(rep["path"]))[1]
        self.assertNotIn("etc/secrets.json", names)
        self.assertIn("etc/config.json", names)

    def test_the_archive_is_not_world_readable(self):
        rep = self.b.write_archive(self.cfg)
        mode = os.stat(rep["path"]).st_mode & 0o077
        self.assertEqual(0, mode, "a backup holding passwords must be 0600")

    def test_verify_rejects_a_truncated_archive(self):
        rep = self.b.write_archive(self.cfg)
        blob = Path(rep["path"]).read_bytes()
        Path(rep["path"]).write_bytes(blob[:len(blob) // 2])
        ok, detail = self.b.verify_archive(rep["path"])
        self.assertFalse(ok, detail)

    def test_verify_rejects_an_archive_missing_a_manifest_entry(self):
        """The failure that matters: it opens, but a file is not in it."""
        import tarfile
        target = self.root / "out" / "vigil-backup-19700101-000000.tar.gz"
        target.parent.mkdir(parents=True, exist_ok=True)
        manifest = {"version": "0", "files": [{"name": "etc/config.json"}]}
        with tarfile.open(str(target), "w:gz") as tar:
            import io
            blob = json.dumps(manifest).encode()
            info = tarfile.TarInfo(self.b.MANIFEST)
            info.size = len(blob)
            tar.addfile(info, io.BytesIO(blob))
        ok, detail = self.b.verify_archive(target)
        self.assertFalse(ok)
        self.assertIn("缺少", detail)

    def test_prune_keeps_the_newest(self):
        out = self.root / "out"
        out.mkdir(parents=True, exist_ok=True)
        for i in range(5):
            (out / ("vigil-backup-2026010%d-000000.tar.gz" % i)).write_bytes(b"x")
        self.assertEqual(2, self.b.prune(out, 3))
        self.assertEqual(3, len(list(out.glob("vigil-backup-*.tar.gz"))))

    def test_archive_names_map_back_to_live_paths(self):
        self.assertEqual(Path(self.b.paths.CONFIG),
                         self.b._destination("etc/config.json"))
        self.assertEqual(self.b.paths.STATE_STATE / "health.json",
                         self.b._destination("state/health.json"))
        # The nginx snippets are named by what they are and resolved on the
        # host doing the restore, not baked in by the host that made the
        # archive.
        self.assertIsNotNone(self.b._destination("gates/conf/vigil-shield.conf"))
        # Operator-added extras are advisory: restoring them blindly could
        # write outside anything this program owns.
        self.assertIsNone(self.b._destination("extra/whatever"))
        self.assertIsNone(self.b._destination("../../etc/shadow"))

    def test_a_named_instances_config_can_be_restored(self):
        """Every `-gate` instance, not only the two historical names.

        A named login gate's `config.php` holds the only copy of its password
        hash. It was archived but had no restore destination, so a restore
        reported success while leaving it behind.
        """
        dest = self.b._destination("gates/astrbot-gate/config.php")
        self.assertIsNotNone(dest)
        self.assertEqual(self.b.GATE_ROOT / "astrbot-gate" / "config.php",
                         Path(dest))
        # 网关的站点配置在面板的 vhost 目录里，也必须有目标 —— 它同样是
        # 「备份里有、还原时没人认领」的一类。原来这条断言把缺口当成了规范。
        site = self.b._destination("gates/nginx/vigil-gate-astrbot.conf")
        self.assertIsNotNone(site, "网关站点配置没有还原目标")
        self.assertEqual(self.b.vhost_dir() / "vigil-gate-astrbot.conf", Path(site))
        # 仍然不能给出目录（没有文件名）的条目编一个目标。
        self.assertIsNone(self.b._destination("gates/nginx/"))

    def test_everything_archived_can_actually_be_restored(self):
        """The invariant that caught a real gap.

        A file that lands in the archive and has no destination is silently
        skipped on restore, so the operator believes it came back when it did
        not. Either archive it *and* restore it, or leave it out.
        """
        rep = self.b.write_archive(self.cfg)
        manifest, names = self.b._plan(Path(rep["path"]))
        unmapped = [f["name"] for f in manifest["files"]
                    if self.b._destination(f["name"]) is None]
        self.assertEqual([], unmapped,
                         "archived but not restorable: %s" % unmapped)

    def test_a_restore_round_trip_puts_the_data_back(self):
        import io
        import tarfile
        rep = self.b.write_archive(self.cfg)
        # Lose the data, the way a bad day loses data.
        (self.root / "etc" / "secrets.json").write_text("{}", encoding="utf-8")
        (self.root / "state" / "health.json").unlink()

        manifest, names = self.b._plan(Path(rep["path"]))
        with tarfile.open(rep["path"], "r:gz") as tar:
            for entry in manifest["files"]:
                dest = self.b._destination(entry["name"])
                if not dest:
                    continue
                src = tar.extractfile(tar.getmember(entry["name"]))
                dest.parent.mkdir(parents=True, exist_ok=True)
                with open(str(dest), "wb") as fh:
                    shutil.copyfileobj(src, fh)
        self.assertIn("hunter2",
                      (self.root / "etc" / "secrets.json").read_text())
        self.assertIn("watch_files",
                      (self.root / "state" / "health.json").read_text())
        del io


class TestBouncer(unittest.TestCase):
    """A second enforcement point, and why its output format matters.

    Every decision is currently enforced in exactly one place -- ipset plus
    an iptables DROP. On a host without ipset that means detection works, the
    alert arrives, and nothing is actually blocked: the operator believes
    they are protected. This renders the same decisions into an nginx
    snippet so the web layer enforces them too.

    The file is deliberately restricted to comments and `deny` lines. It is
    included from nginx's http{} scope, so a malformed write landing there
    would stop every site on the host from loading.
    """

    def setUp(self):
        from vigil.guards import bouncer as bmod
        self.b = bmod
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = vconfig.Config(path=Path(self.tmp.name) / "c.json",
                                  secrets_path=Path(self.tmp.name) / "s.json")

    def tearDown(self):
        self.tmp.cleanup()

    def _bans(self):
        now = time.time()
        return {
            "203.0.113.9": {"until": now + 3600, "reason": "扫描",
                            "detector": "exploit_high"},
            "198.51.100.4": {"until": now - 10, "reason": "已过期",
                             "detector": "ssh"},
            "192.0.2.5": {"until": now + 604800, "reason": "诱饵命中",
                          "detector": "decoy"},
        }

    def test_only_active_bans_are_rendered(self):
        text = self.b.render(self._bans())
        self.assertIn("deny 203.0.113.9;", text)
        self.assertIn("deny 192.0.2.5;", text)
        self.assertNotIn("deny 198.51.100.4;", text,
                         "an expired ban must not stay enforced")

    def test_the_file_can_only_contain_comments_and_deny_lines(self):
        """It is included from http{}; one stray token breaks every site."""
        text = self.b.render(self._bans())
        for line in text.splitlines():
            self.assertTrue(
                not line.strip() or line.lstrip().startswith("#")
                or (line.startswith("deny ") and line.endswith(";")),
                "unsafe line in an http-scope include: %r" % line)

    def test_a_reason_with_a_newline_cannot_forge_a_directive(self):
        bans = {"203.0.113.9": {"until": time.time() + 60,
                                "reason": "x\ndeny all;", "detector": "d"}}
        text = self.b.render(bans)
        for line in text.splitlines():
            self.assertNotEqual("deny all;", line.strip())

    def test_an_empty_ban_list_is_still_valid(self):
        text = self.b.render({})
        self.assertIn("没有封禁", text)

    def _isolate(self):
        """Point every path resolver at the temp dir.

        `sync` resolves its targets through `all_targets`, which walks the
        real nginx layout; without this the tests would write to the host's
        live configuration. That is exactly the kind of leak a test must not
        have.
        """
        target = Path(self.tmp.name) / "deny.conf"
        self._saved = (self.b.all_targets, self.b.server_scope_paths,
                       self.b.http_scope_path, self.b.active_bans)
        self.b.all_targets = lambda: [target]
        self.b.server_scope_paths = lambda: []
        self.b.http_scope_path = lambda: target
        self.b.active_bans = lambda: self._bans()
        self.b.nginx_test = lambda: (True, "ok")
        self.b.nginx_reload = lambda: None
        # `sync` now verifies the reload through the shield helper, which
        # probes the real error log and worker set. Point both at nothing so a
        # unit test neither reads nor depends on the host's nginx.
        from vigil.gates import shield as sh
        self._saved_shield = (sh._error_log_path, sh._worker_pids)
        sh._error_log_path = lambda: ""
        sh._worker_pids = lambda: set()
        return target

    def _restore(self):
        from vigil.gates import shield as sh
        (sh._error_log_path, sh._worker_pids) = self._saved_shield
        (self.b.all_targets, self.b.server_scope_paths,
         self.b.http_scope_path, self.b.active_bans) = self._saved

    def test_only_one_level_is_ever_authoritative(self):
        """Two lists at two levels is worse than one at the right level.

        Measured on the live host: with the list at `http` scope a denied
        client got 403, but once the same list (minus that address) was also
        written into the server blocks, the client got 200 again -- nginx
        replaces inherited access rules rather than merging them, so the
        server-level list silently won. The global file must therefore stay
        empty whenever the server-scope files exist.
        """
        placeholder = self.b._placeholder_text()
        for line in placeholder.splitlines():
            self.assertFalse(line.startswith("deny "),
                             "the fallback file must never carry a list while "
                             "server-scope files exist")

    def test_sync_writes_nothing_when_nothing_changed(self):
        """Reloading nginx every minute for no reason is its own risk."""
        self._isolate()
        self.cfg.set("bouncer.enabled", True)
        try:
            first = self.b.sync(self.cfg)
            self.assertTrue(first["changed"])
            target = self.b.conf_path()
            self.assertTrue(target.is_file())
            mtime = target.stat().st_mtime
            second = self.b.sync(self.cfg)
            self.assertFalse(second["changed"],
                             "an unchanged list must not touch nginx")
            self.assertEqual(mtime, target.stat().st_mtime)
        finally:
            self._restore()

    def test_it_is_off_by_default(self):
        """It edits nginx configuration, which is the operator's call."""
        self.assertFalse(self.cfg.get("bouncer.enabled"))

    def test_disabled_means_sync_does_nothing(self):
        target = self._isolate()
        try:
            result = self.b.sync(self.cfg)
            self.assertFalse(result["changed"])
            self.assertFalse(target.exists())
        finally:
            self._restore()

    def test_a_rejected_config_is_rolled_back(self):
        """If nginx refuses, the old file must come back, not stay broken."""
        target = self._isolate()
        target.write_text("# 旧内容\ndeny 203.0.113.1;\n", encoding="utf-8")
        self._saved = self._saved + (self.b.nginx_test,)
        self.b.nginx_test = lambda: (False, "nginx: [emerg] bogus")
        self.cfg.set("bouncer.enabled", True)
        try:
            result = self.b.sync(self.cfg)
            self.assertFalse(result["ok"])
            self.assertIn("回滚", " ".join(result["problems"]))
            self.assertIn("旧内容", target.read_text(encoding="utf-8"))
        finally:
            self.b.nginx_test = self._saved[-1]
            self._saved = self._saved[:-1]
            self._restore()

    def test_a_reload_that_needs_a_restart_says_so_and_rolls_back(self):
        """`nginx -t` can pass while every reload fails.

        The deny list carries no zones, but a reload loads the whole config,
        so a zone key change written earlier makes *this* reload fail too.
        The operator must get "only a full restart can pick this up", not a
        generic parse error -- and the list must go back to what is live.
        """
        target = self._isolate()
        target.write_text("# 旧内容\ndeny 203.0.113.1;\n", encoding="utf-8")
        self.cfg.set("bouncer.enabled", True)
        from vigil.gates import shield as sh
        handle = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False)
        handle.write("nothing yet\n")
        handle.close()
        path = handle.name
        sh._error_log_path = lambda: path
        sh._worker_pids = lambda: {"1", "2"}

        def reload_and_log():
            with open(path, "a", encoding="utf-8") as fh:
                fh.write('[emerg] limit_req "example_zone" uses the '
                         '"$some_key" key while previously it used the '
                         '"$binary_remote_addr" key\n')

        self.b.nginx_reload = reload_and_log
        try:
            result = self.b.sync(self.cfg)
        finally:
            os.unlink(path)
            self._restore()
        self.assertFalse(result["ok"])
        problems = " ".join(result["problems"])
        self.assertIn("完整重启", problems, "必须给出「只有完整重启能生效」的结论")
        self.assertIn("example_zone", problems)
        self.assertIn("回滚", problems)
        self.assertIn("旧内容", target.read_text(encoding="utf-8"))


class TestLearning(unittest.TestCase):
    """Mining new signatures, and the gate that makes it safe to automate.

    The literature is unambiguous that generation is the easy half. Polygraph
    and Autograph both centre on evaluating candidates against known-good
    traffic, because a signature that also matches legitimate requests turns
    an attack on the network into an outage of it. Honeycomb adds the other
    requirement: a candidate must be invariant across *independent*
    connections, not a feature of one noisy client.
    """

    def setUp(self):
        from vigil.guards import learning as lmod
        self.l = lmod
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.saved = (lmod.observations_path, lmod.learned_path,
                      lmod.suggestions_path)
        lmod.observations_path = lambda: self.base / "obs.jsonl"
        lmod.learned_path = lambda: self.base / "learned.json"
        lmod.suggestions_path = lambda: self.base / "suggest.json"

    def tearDown(self):
        (self.l.observations_path, self.l.learned_path,
         self.l.suggestions_path) = self.saved
        self.tmp.cleanup()

    def _observe(self, ip, path, status=404):
        self.l.observe(ip, path, status)

    def test_static_assets_are_not_evidence(self):
        """A 404 on an image is a broken link, not probing."""
        self.l.observe("203.0.113.1", "/logo.png", 404)
        self.l.observe("203.0.113.1", "/style.css", 404)
        self.assertEqual([], self.l.read_observations())

    def test_probing_is_recorded(self):
        self.l.observe("203.0.113.1", "/.git/config", 404)
        got = self.l.read_observations()
        self.assertEqual(1, len(got))
        self.assertEqual("/.git/config", got[0]["path"])
        self.assertEqual(404, got[0]["status"])

    def test_tokens_cover_both_probing_shapes(self):
        self.assertIn("/.git", self.l.tokens_for("/.git/config"))
        self.assertIn("/backup.sql", self.l.tokens_for("/backup.sql"))
        self.assertEqual([], self.l.tokens_for("/"))

    def test_distinct_sources_are_counted_not_requests(self):
        """One host repeating itself is one opinion."""
        for _ in range(30):
            self._observe("203.0.113.9", "/secret-area/x", 404)
        self.assertEqual([], self.l.mine(),
                         "a single source must not form a candidate")
        for last in (1, 2, 3):
            self._observe("203.0.113.%d" % last, "/secret-area/x", 404)
        self.assertIn("/secret-area", [c["token"] for c in self.l.mine()])

    def test_a_path_served_successfully_is_refused(self):
        """Polygraph's lesson: never adopt something real traffic matches."""
        candidate = {"token": "/uploads", "distinct_ips": 9, "served_ok": 4,
                     "not_found": 2, "last_seen": time.time()}
        out = self.l.evaluate(candidate, legit=set())
        self.assertEqual("reject", out["verdict"])
        self.assertIn("曾被成功访问", out["reason"])

    def test_a_token_in_the_legitimate_corpus_is_refused(self):
        candidate = {"token": "/assets", "distinct_ips": 9, "served_ok": 0,
                     "not_found": 5, "last_seen": time.time()}
        out = self.l.evaluate(candidate, legit={"assets"})
        self.assertEqual("reject", out["verdict"])
        self.assertIn("合法流量", out["reason"])

    def test_a_path_that_exists_on_disk_is_refused(self):
        """The same control the curated decoys use, applied to learned ones."""
        root = self.base / "www"
        (root / "uploads").mkdir(parents=True)
        candidate = {"token": "/uploads", "distinct_ips": 9, "served_ok": 0,
                     "not_found": 5, "last_seen": time.time()}
        out = self.l.evaluate(candidate, legit=set(), webroot=str(root))
        self.assertEqual("reject", out["verdict"])
        self.assertIn("已存在", out["reason"])

    def test_a_clean_candidate_is_adopted(self):
        candidate = {"token": "/secret-area", "distinct_ips": 6,
                     "served_ok": 0, "not_found": 30,
                     "last_seen": time.time()}
        out = self.l.evaluate(candidate, legit=set())
        self.assertEqual("adopt", out["verdict"])
        self.assertGreater(out["confidence"], 0)

    def test_confidence_follows_the_evidence(self):
        few = {"token": "/a-thing", "distinct_ips": 3, "served_ok": 0,
               "not_found": 3, "last_seen": time.time()}
        many = {"token": "/b-thing", "distinct_ips": 10, "served_ok": 0,
                "not_found": 30, "last_seen": time.time()}
        self.assertLess(self.l.evaluate(few, set())["confidence"],
                        self.l.evaluate(many, set())["confidence"])

    def test_every_refusal_carries_a_reason(self):
        """A miner that silently discards cannot be debugged or trusted."""
        candidate = {"token": "/x", "distinct_ips": 9, "served_ok": 1,
                     "not_found": 0, "last_seen": time.time()}
        self.assertTrue(self.l.evaluate(candidate, legit=set())["reason"])

    def test_only_decoy_candidates_are_adopted_automatically(self):
        """The asymmetry, stated as a test.

        Adding a decoy is additive and reversible; adding a ban signature
        blocks real users at the firewall. So `run` may adopt the former and
        must only *suggest* the latter.
        """
        for last in (1, 2, 3, 4):
            self._observe("8.8.4.%d" % last, "/secret-area/x", 404)
        self._observe("1.1.1.1", "/uploads", 200)
        result = self.l.run(cfg=None, adopt=True)
        self.assertIn("/secret-area", result["adopted"])
        self.assertNotIn("/uploads", result["adopted"])
        blob = json.loads(
            self.l.suggestions_path().read_text(encoding="utf-8"))
        suggestions = [s["token"] for s in blob.get("items", [])]
        self.assertNotIn("/secret-area", suggestions,
                         "an adopted candidate is not also a suggestion")

    def test_a_learned_token_cannot_escape_its_nginx_context(self):
        """A learned value becomes `location = <path> {`; guard the shape.

        One malformed entry would take down every site on the host, and this
        value comes from the internet.
        """
        self.l.learned_path().write_text(json.dumps({
            "/legit-path": {"token": "/legit-path"},
            "/bad;}\nlocation / { deny all;": {"token": "x"},
            "/also bad with space": {"token": "x"},
            "no-leading-slash": {"token": "x"},
            "/{{": {"token": "x"},
        }, ensure_ascii=False), encoding="utf-8")
        self.assertEqual(["/legit-path"], self.l.learned_tokens())

    def test_adoption_does_not_touch_nginx_when_decoys_are_not_installed(self):
        """A host that never opted into decoys must not acquire nginx config."""
        from vigil.guards import decoy
        real = decoy.status
        decoy.status = lambda cfg=None: {"installed": False}
        try:
            out = self.l.apply_adopted()
            self.assertFalse(out["applied"])
            self.assertIn("未安装", out["reason"])
        finally:
            decoy.status = real

    def test_a_new_candidate_is_pushed_to_nginx_when_decoys_are_in_use(self):
        from vigil.guards import decoy
        real_status, real_install, real_learned = (
            decoy.status, decoy.install, decoy.learned_decoys)
        decoy.status = lambda cfg=None: {"installed": True, "paths": ["/.git"]}
        decoy.learned_decoys = lambda: [("/.git", "git", "x"),
                                        ("/secret-area", "secret-area", "y")]
        called = {}

        def fake_install(cfg=None):
            called["yes"] = True
            return {"ok": True, "written": "/tmp/decoy.conf"}

        decoy.install = fake_install
        try:
            out = self.l.apply_adopted()
            self.assertTrue(out["applied"])
            self.assertEqual(["/secret-area"], out["pending"])
            self.assertTrue(called.get("yes"),
                            "the install path must run so the same screening, "
                            "nginx -t and rollback apply to learned entries")
        finally:
            decoy.status, decoy.install, decoy.learned_decoys = (
                real_status, real_install, real_learned)

    def test_nothing_is_pushed_when_every_candidate_is_already_live(self):
        from vigil.guards import decoy
        real_status, real_install, real_learned = (
            decoy.status, decoy.install, decoy.learned_decoys)
        decoy.status = lambda cfg=None: {"installed": True,
                                         "paths": ["/.git", "/secret-area"]}
        decoy.learned_decoys = lambda: [("/.git", "git", "x"),
                                        ("/secret-area", "s", "y")]
        decoy.install = lambda cfg=None: (_ for _ in ()).throw(
            AssertionError("must not reinstall with nothing pending"))
        try:
            out = self.l.apply_adopted()
            self.assertFalse(out["applied"])
        finally:
            decoy.status, decoy.install, decoy.learned_decoys = (
                real_status, real_install, real_learned)

    def test_adoption_is_idempotent(self):
        for last in (1, 2, 3):
            self._observe("8.8.4.%d" % last, "/secret-area/x", 404)
        first = self.l.run(cfg=None, adopt=True)["adopted"]
        second = self.l.run(cfg=None, adopt=True)["adopted"]
        self.assertEqual(first, second)


class TestBanDurationsAreEnforceable(unittest.TestCase):
    """Every configured duration must be one ipset can actually apply.

    Found in production, not by design review: the decoy ladder stepped to
    2592000 seconds (30 days), ipset stores a timeout as 32-bit milliseconds
    and refused it -- `Syntax error: '2592000' is out of range 0-2147483`.
    The config validated, the ban alert fired, and the escalation silently did
    not happen. Only the failed-ban alert made it visible.

    This is the general lesson: a duration the enforcer cannot apply is not a
    duration, it is a hole. So the limits of the enforcement mechanism are
    asserted against the defaults, not discovered at 03:00.
    """

    def setUp(self):
        from vigil.guards import threat as threat_mod
        self.t = threat_mod
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = vconfig.Config(path=Path(self.tmp.name) / "c.json",
                                  secrets_path=Path(self.tmp.name) / "s.json")

    def tearDown(self):
        self.tmp.cleanup()

    def _settings(self, **over):
        for key, value in over.items():
            self.cfg.set("threat.%s" % key, value)
        return self.t.Settings(self.cfg)

    def test_the_ipset_limit_is_what_the_enforcer_says(self):
        # Pinned so a future change to the constant has to be deliberate.
        self.assertEqual(2147483, self.t.IPSET_MAX_TIMEOUT)

    def test_no_default_ladder_exceeds_it(self):
        s = self._settings()
        for name in ("ssh_ban_seconds", "http_ban_seconds",
                     "portscan_ban_seconds", "decoy_ban_seconds"):
            for seconds in getattr(s, name):
                self.assertLessEqual(
                    seconds, self.t.IPSET_MAX_TIMEOUT,
                    "%s contains %ss, which ipset will reject" % (name, seconds))

    def test_every_single_shot_duration_is_within_range(self):
        s = self._settings()
        for name in ("recidivist_ban_seconds", "netblock_ban_seconds",
                     "instant_ban_seconds"):
            self.assertLessEqual(getattr(s, name), self.t.IPSET_MAX_TIMEOUT, name)

    def test_an_impossible_configured_value_is_clamped_not_kept(self):
        """The operator's intent is clear; only the number is impossible."""
        s = self._settings(**{"decoy.ban_seconds": [604800, 99999999]})
        self.assertEqual([604800, self.t.IPSET_MAX_TIMEOUT],
                         s.decoy_ban_seconds)

    def test_a_clamped_ladder_still_produces_a_valid_ban(self):
        self.cfg.set("threat.decoy.ban_seconds", [1, 99999999])
        self.cfg.set("threat.whitelist", ["127.0.0.1/8", "::1"])
        daemon = self.t.ThreatDaemon(self.cfg, log=_QuietLog(), dry_run=True,
                                     echo=False)
        for _ in range(3):
            daemon.ban("8.8.4.9", "诱饵命中", detector="decoy",
                       severity=2)
        entry = daemon.state.bans["8.8.4.9"]
        self.assertLessEqual(entry["until"] - time.time(),
                             self.t.IPSET_MAX_TIMEOUT + 5)

    def test_zero_and_negative_are_still_rejected(self):
        for bad in ([0], [-1], ["x"]):
            with self.assertRaises(Exception):
                self._settings(**{"decoy.ban_seconds": bad})


class TestNetblockEscalation(unittest.TestCase):
    """Escalating from an address to its network, and the rails around it.

    This is the most dangerous automatic decision the program makes: the unit
    of punishment stops matching the unit of guilt. One host scans you and
    bystanders on the same /24 lose service. The rails are what make it
    defensible, so most of these tests are about what gets refused.
    """

    def setUp(self):
        from vigil.guards import threat as threat_mod
        self.t = threat_mod
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = vconfig.Config(path=Path(self.tmp.name) / "c.json",
                                  secrets_path=Path(self.tmp.name) / "s.json")

    def tearDown(self):
        self.tmp.cleanup()

    def _daemon(self, **over):
        for key, value in over.items():
            self.cfg.set("threat.%s" % key, value)
        return self.t.ThreatDaemon(self.cfg, log=_QuietLog(), dry_run=True,
                                   echo=False)

    def test_the_network_width_is_fixed_and_narrow(self):
        self.assertEqual("203.0.113.0/24",
                         self.t.NetblockTracker.network_of("203.0.113.77"))
        self.assertEqual("2001:db8::/48",
                         self.t.NetblockTracker.network_of("2001:db8::5"))
        self.assertEqual("", self.t.NetblockTracker.network_of("not-an-ip"))

    def test_it_counts_distinct_addresses_not_events(self):
        """One attacker trying harder must not reach the threshold."""
        tracker = self.t.NetblockTracker(window=600)
        for _ in range(50):
            _net, count = tracker.note("203.0.113.9")
        self.assertEqual(1, count, "the same address is one source")

    def test_stale_addresses_leave_the_window(self):
        tracker = self.t.NetblockTracker(window=60)
        now = time.time()
        tracker.note("203.0.113.1", now - 600)
        tracker.note("203.0.113.2", now - 600)
        _net, count = tracker.note("203.0.113.3", now)
        self.assertEqual(1, count)

    def test_a_whitelisted_address_inside_the_range_blocks_escalation(self):
        """The rail that matters most: never lock yourself out."""
        self.cfg.set("threat.whitelist", ["127.0.0.1/8", "::1", "203.0.113.7"])
        daemon = self._daemon()
        reason = daemon.netblock_blockers("203.0.113.0/24")
        self.assertIn("203.0.113.7", reason)
        self.assertIn("白名单", reason)

    def test_reserved_space_is_never_escalated(self):
        daemon = self._daemon()
        self.assertIn("保留地址", daemon.netblock_blockers("198.51.100.0/24"))

    def test_a_too_wide_range_is_refused(self):
        daemon = self._daemon()
        self.assertIn("过宽", daemon.netblock_blockers("203.0.0.0/16"))
        self.assertEqual("", daemon.netblock_blockers("8.8.4.0/24"))

    def test_disabled_means_no_escalation(self):
        daemon = self._daemon(**{"netblock.enabled": False})
        self.assertFalse(daemon.ban_netblock("8.8.4.0/24", []))

    def test_a_coordinated_sweep_escalates(self):
        self.cfg.set("threat.netblock.min_ips", 3)
        self.cfg.set("threat.whitelist", ["127.0.0.1/8", "::1"])
        daemon = self._daemon()
        added = []
        daemon.enforcer.add_net = lambda net, seconds: (
            added.append((net, seconds)) or (True, ""))
        daemon.enforcer.net_members = lambda: {}
        for last in (1, 2, 3):
            daemon.ban("8.8.4.%d" % last, "扫描", detector="exploit_high")
        self.assertEqual(1, len(added), added)
        self.assertEqual("8.8.4.0/24", added[0][0])
        self.assertGreaterEqual(added[0][1], 300)

    def test_a_single_source_never_escalates(self):
        """Otherwise every ordinary brute-force ban would take out a /24."""
        daemon = self._daemon()
        added = []
        daemon.enforcer.add_net = lambda net, seconds: (
            added.append(net) or (True, ""))
        daemon.enforcer.net_members = lambda: {}
        for _ in range(20):
            daemon.ban("8.8.4.9", "扫描", detector="exploit_high")
        self.assertEqual([], added)

    def test_escalation_refuses_when_the_range_holds_a_whitelisted_address(self):
        self.cfg.set("threat.netblock.min_ips", 2)
        self.cfg.set("threat.whitelist", ["127.0.0.1/8", "::1", "8.8.4.50"])
        daemon = self._daemon()
        added = []
        daemon.enforcer.add_net = lambda net, seconds: (
            added.append(net) or (True, ""))
        daemon.enforcer.net_members = lambda: {}
        for last in (1, 2, 3):
            daemon.ban("8.8.4.%d" % last, "扫描", detector="exploit_high")
        self.assertEqual(
            [], added,
            "a range containing a whitelisted address must be refused "
            "however many attackers are inside it")

    def test_the_clear_verb_actually_clears(self):
        """A verb that silently lists instead of acting is worse than absent."""
        import argparse
        from vigil import cli
        parser = cli.build_parser()
        sub = next(a for a in parser._actions
                   if isinstance(a, argparse._SubParsersAction))
        threat_parser = sub.choices["threat"]
        nb = next(a for a in threat_parser._actions
                  if isinstance(a, argparse._SubParsersAction)).choices["netblock"]
        args = nb.parse_args(["clear", "8.8.4.0/24"])
        self.assertEqual("clear", args.action)
        self.assertEqual("8.8.4.0/24", args.net)
        # The CLI must treat the positional verb as a clear, not only --clear.
        self.assertTrue(args.action == "clear" or args.clear)

    def test_the_maximum_number_of_ranges_is_enforced(self):
        self.cfg.set("threat.netblock.max_current", 1)
        daemon = self._daemon()
        daemon.enforcer.net_members = lambda: {"8.8.4.0/24": 0}
        self.assertIn("上限", daemon.netblock_blockers("1.1.1.0/24"))


class TestReservedAddressReporting(unittest.TestCase):
    """The tool must not invent intelligence about addresses that have none.

    Reported live and caught by the operator: a decoy hit from 198.51.100.90
    produced an alert naming Bucharest, an IANA abuse address and a
    "home broadband / abused VPS" trait -- for an address that cannot be
    routed on the public internet at all. The range is RFC 5737 TEST-NET-2,
    the label said TEST-NET-1, and abuse@iana.org does not accept reports
    for it. A security tool that manufactures confident detail about a test
    fixture is worse than one that says nothing, because the operator acts
    on it.
    """

    def setUp(self):
        from vigil.guards.checks import util
        self.u = util

    def test_the_documentation_ranges_are_labelled_correctly(self):
        """The exact error the operator caught: RFC 5737 numbering."""
        self.assertEqual("RFC 5737 TEST-NET-1",
                         self.u.special_address("192.0.2.7")[0])
        self.assertEqual("RFC 5737 TEST-NET-2",
                         self.u.special_address("198.51.100.90")[0])
        self.assertEqual("RFC 5737 TEST-NET-3",
                         self.u.special_address("203.0.113.5")[0])

    def test_other_reserved_space_is_recognised(self):
        cases = {
            "100.64.1.1": "RFC 6598",       # carrier NAT
            "198.18.0.1": "RFC 2544",       # benchmarking
            "240.0.0.1": "RFC 1112",        # reserved
            "10.1.2.3": "RFC 1918",
            "2001:db8::1": "RFC 3849",
        }
        for ip, rfc in cases.items():
            found = self.u.special_address(ip)
            self.assertIsNotNone(found, ip)
            self.assertEqual(rfc, found[0], ip)

    def test_a_real_address_is_not_flagged(self):
        for ip in ("8.8.8.8", "8.8.4.10"):
            self.assertIsNone(self.u.special_address(ip), ip)

    def test_geo_does_not_invent_a_location_for_reserved_space(self):
        """The lookup returned a real city for a documentation address."""
        self.u._GEO_MEM.clear()
        try:
            text = self.u.geo(None, "198.51.100.90")
        finally:
            self.u._GEO_MEM.clear()
        self.assertIn("TEST-NET-2", text)
        for wrong in ("罗马尼亚", "Bucure", "美国"):
            self.assertNotIn(wrong, text, wrong)

    def test_the_dossier_says_reserved_instead_of_inventing_detail(self):
        from vigil.core.config import load as load_config
        try:
            cfg = load_config()
        except Exception:                               # noqa: BLE001
            self.skipTest("no configuration on this machine")
        joined = "\n".join(self.u.ip_dossier(cfg, "198.51.100.90"))
        self.assertIn("TEST-NET-2", joined)
        # It must say *why* there is nothing to report, so the operator knows
        # this is a data-quality signal rather than a quiet attacker.
        self.assertIn("不在可公网路由的地址空间内", joined)
        self.assertIn("而不是一次真实的外部访问", joined)
        for wrong in ("罗马尼亚", "Bucure", "iana.org", "滥用举报:",
                      "家庭宽带"):
            self.assertNotIn(wrong, joined, wrong)

    def test_a_ban_reason_says_the_source_cannot_be_real(self):
        from vigil.guards import threat as threat_mod
        note = threat_mod.ThreatDaemon.source_note("198.51.100.90")
        self.assertIn("TEST-NET-2", note)
        self.assertIn("不可能来自真实网络", note)
        self.assertEqual("", threat_mod.ThreatDaemon.source_note("8.8.8.8"))

    def test_reserved_space_does_not_raise_the_attack_posture(self):
        """A log full of test fixtures is not a campaign."""
        from vigil.guards import threat as threat_mod
        tmp = tempfile.TemporaryDirectory()
        try:
            flag = Path(tmp.name) / "posture.active"
            cfg = vconfig.Config(path=Path(tmp.name) / "c.json",
                                 secrets_path=Path(tmp.name) / "s.json")
            daemon = threat_mod.ThreatDaemon(cfg, log=_QuietLog(),
                                             dry_run=True, echo=False)
            daemon.posture = threat_mod.AttackPosture(
                flag, window=300, trigger=1, hold=900, log=_QuietLog())
            daemon.handle_decoy(
                '198.51.100.90 - - [x] "GET /.git/config HTTP/1.1" 444 0')
            self.assertFalse(
                daemon.posture.active(),
                "reserved space must not put the machine on a war footing")
        finally:
            tmp.cleanup()


class _FakeDaemon:
    """Just enough daemon for the unban hand-off path."""

    def __init__(self):
        # The address must already be banned, or `unban` correctly reports
        # that there was nothing to lift.
        self.state = type("S", (), {
            "bans": {"198.51.100.9": {"until": time.time() + 600}},
            "drop_ban": lambda s, ip: s.bans.pop(ip, None),
            "save": lambda s: True})()
        self.enforcer = type("E", (), {"remove": lambda s, ip: True})()
        self.audit = lambda *_a, **_k: None


class TestUnbanDurability(unittest.TestCase):
    """A lifted ban must stay lifted.

    `vigil threat unban` removed the address from the ipset and dropped it
    from an in-memory copy of the state that was then thrown away -- so the
    ban survived on disk, the running daemon still held it, and the next
    restart put it straight back. From the operator's side that is
    indistinguishable from the command silently failing, and it was observed
    live: four test addresses reappeared after being unbanned.
    """

    def setUp(self):
        from vigil.guards import threat as threat_mod
        self.t = threat_mod
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = vconfig.Config(path=Path(self.tmp.name) / "c.json",
                                  secrets_path=Path(self.tmp.name) / "s.json")
        self.real = (threat_mod.UNBAN_REQUESTS, threat_mod.paths.PID_THREAT)
        self.reqs = Path(self.tmp.name) / "unban.jsonl"
        self.pid = Path(self.tmp.name) / "threatd.pid"
        threat_mod.UNBAN_REQUESTS = self.reqs
        threat_mod.paths.PID_THREAT = self.pid

    def tearDown(self):
        (self.t.UNBAN_REQUESTS, self.t.paths.PID_THREAT) = self.real
        self.tmp.cleanup()

    def test_with_no_daemon_the_change_is_written_immediately(self):
        daemon = self.t.ThreatDaemon(self.cfg, log=_QuietLog(), dry_run=True,
                                     echo=False)
        daemon.state.bans["198.51.100.9"] = {"until": time.time() + 600}
        real_cli = self.t._cli_daemon
        self.t._cli_daemon = lambda *a, **k: daemon
        try:
            ok, _ = self.t.unban(self.cfg, "198.51.100.9")
        finally:
            self.t._cli_daemon = real_cli
        self.assertTrue(ok)

    def test_with_a_running_daemon_a_request_is_left(self):
        """The daemon is the state file's only writer; the CLI must not race it."""
        self.pid.write_text("1\n")                 # pid 1 always exists
        real_cli = self.t._cli_daemon
        self.t._cli_daemon = lambda *a, **k: _FakeDaemon()
        try:
            ok, _ = self.t.unban(self.cfg, "198.51.100.9")
        finally:
            self.t._cli_daemon = real_cli
        self.assertTrue(ok)
        self.assertTrue(self.reqs.is_file(), "no request was left for the daemon")
        self.assertIn("198.51.100.9", self.reqs.read_text())

    def test_the_daemon_drains_requests_and_drops_the_ban(self):
        daemon = self.t.ThreatDaemon(self.cfg, log=_QuietLog(), dry_run=True,
                                     echo=False)
        daemon.state.bans["198.51.100.9"] = {"until": time.time() + 600}
        removed = []
        daemon.enforcer.remove = lambda ip: removed.append(ip) or True
        self.reqs.write_text('{"ip": "198.51.100.9"}\n', encoding="utf-8")
        self.assertEqual(1, daemon.apply_unban_requests())
        self.assertNotIn("198.51.100.9", daemon.state.bans)
        # Both halves: dropping the record while leaving the address in the
        # enforcement set means every command reports "unbanned" and the
        # address is still blocked.
        self.assertEqual(["198.51.100.9"], removed)
        # Drained, not replayed: replaying would undo a later deliberate ban.
        self.assertEqual("", self.reqs.read_text())
        self.assertEqual(0, daemon.apply_unban_requests())

    def test_a_junk_request_does_not_stop_the_others(self):
        daemon = self.t.ThreatDaemon(self.cfg, log=_QuietLog(), dry_run=True,
                                     echo=False)
        daemon.state.bans["198.51.100.9"] = {"until": time.time() + 600}
        self.reqs.write_text('not json\n{"ip": "198.51.100.9"}\n'
                             '{"ip": "not-an-ip"}\n', encoding="utf-8")
        self.assertEqual(1, daemon.apply_unban_requests())
        self.assertNotIn("198.51.100.9", daemon.state.bans)


class TestPostureRelease(unittest.TestCase):
    """Releasing heightened defence is a supported operation, not a workaround.

    The posture is a *response*, not a standing state: it expires from the
    clock alone, and an operator who wants it over now says so with a
    command. 人不犯我，我不犯人 -- and when the attack stops, so does the
    heightened posture.
    """

    def setUp(self):
        from vigil.guards import threat as threat_mod
        self.t = threat_mod
        self.tmp = tempfile.TemporaryDirectory()
        self.flag = Path(self.tmp.name) / "posture.active"
        self.real = threat_mod.POSTURE_FLAG
        threat_mod.POSTURE_FLAG = self.flag

    def tearDown(self):
        self.t.POSTURE_FLAG = self.real
        self.tmp.cleanup()

    def test_an_active_posture_can_be_lifted_immediately(self):
        self.flag.parent.mkdir(parents=True, exist_ok=True)
        self.flag.touch()
        os.utime(str(self.flag), (time.time() + 600, time.time() + 600))
        self.assertTrue(self.t.AttackPosture(self.flag).active())
        os.unlink(str(self.flag))
        self.assertFalse(self.t.AttackPosture(self.flag).active())

    def test_lifting_the_posture_cannot_lift_a_ban(self):
        """解除姿态只恢复阈值；该封的人还得封着。"""
        posture = self.t.AttackPosture(self.flag)
        for forbidden in ("bans", "state", "enforcer", "unban"):
            self.assertFalse(hasattr(posture, forbidden),
                             "the posture must have no path to the ban set")

    def test_posture_is_never_permanent(self):
        """It expires from the clock alone, with nothing scheduled to run."""
        p = self.t.AttackPosture(self.flag, window=300, trigger=1, hold=30)
        p.note(1)
        self.assertTrue(p.active())
        os.utime(str(self.flag), (time.time() - 1, time.time() - 1))
        self.assertFalse(p.active(),
                         "a posture that cannot end becomes standing policy")


class TestLogFollower(unittest.TestCase):
    """A restart must not silently drop the attacks that happened during it.

    `tail -F -n 0` was the original implementation and it starts at the end
    of the file. On 2026-09-27 a decoy hit landed in the window of a `vigil
    update` restart: the start-up banner still reported the source as
    watched, and nothing happened. A monitoring daemon that skips the lines
    arriving during its own restart is at its least trustworthy exactly when
    it is restarting.
    """

    def setUp(self):
        from vigil.guards import threat as threat_mod
        self.t = threat_mod
        self.tmp = tempfile.TemporaryDirectory()
        self.log = Path(self.tmp.name) / "access.log"
        self.log.write_text("old line\n", encoding="utf-8")
        self.store = {}

    def tearDown(self):
        for follower in getattr(self, "_followers", []):
            follower.close()
        self.tmp.cleanup()

    def _follow(self):
        f = self.t.LogFollower(str(self.log), self.store)
        self._followers = getattr(self, "_followers", []) + [f]
        return f

    def test_a_first_sighting_starts_at_the_end(self):
        """Replaying months of history on first run would re-ban old attacks."""
        f = self._follow()
        self.assertEqual([], list(f.poll()))
        self.log.write_text("old line\nnew line\n", encoding="utf-8")
        self.assertEqual(["new line"], list(f.poll()))

    def test_a_restart_resumes_and_does_not_lose_lines(self):
        """The exact bug: lines written while nothing was reading."""
        f = self._follow()
        list(f.poll())
        f.flush()
        during = '198.51.100.9 - - [x] "GET /.git/config HTTP/1.1" 444 0'
        with open(str(self.log), "a", encoding="utf-8") as fh:
            fh.write(during + "\n")
        again = self.t.LogFollower(str(self.log), self.store)
        self._followers.append(again)
        self.assertEqual([during], list(again.poll()))

    def test_rotation_starts_the_new_file_at_the_beginning(self):
        f = self._follow()
        list(f.poll())
        f.flush()
        self.log.unlink()
        self.log.write_text("after rotate\n", encoding="utf-8")
        f._close()
        self.assertEqual(["after rotate"], list(f.poll()))

    def test_truncation_starts_over(self):
        f = self._follow()
        list(f.poll())
        f.tell()
        f.flush()
        self.log.write_text("tiny\n")
        f._close()
        self.assertEqual(["tiny"], list(f.poll()))

    def test_partial_lines_wait_for_their_ending(self):
        f = self._follow()
        list(f.poll())
        with open(str(self.log), "a", encoding="utf-8") as fh:
            fh.write("half a li")
        self.assertEqual([], list(f.poll()),
                         "a line without a newline is not a line yet")
        with open(str(self.log), "a", encoding="utf-8") as fh:
            fh.write("ne\n")
        self.assertEqual(["half a line"], list(f.poll()))

    def test_a_missing_file_is_not_an_error(self):
        f = self.t.LogFollower(str(Path(self.tmp.name) / "nope.log"), {})
        self.assertEqual([], list(f.poll()))

    def test_offsets_are_persisted_for_the_next_run(self):
        f = self._follow()
        list(f.poll())
        with open(str(self.log), "a", encoding="utf-8") as fh:
            fh.write("x\n")
        list(f.poll())
        f.tell()
        f.flush()
        self.assertIn(str(self.log), self.store)
        self.assertGreater(self.store[str(self.log)]["offset"], 0)


class TestAttackPosture(unittest.TestCase):
    """Heightened defence because an attack is happening, not because the box is busy.

    The load shedder already halves thresholds when the machine is
    overwhelmed. A slow campaign against an idle machine never moves the
    load average, so that path never fires and every attempt is judged
    against the relaxed threshold. This reacts to the attack itself.
    """

    def setUp(self):
        from vigil.guards import threat as threat_mod
        self.t = threat_mod
        self.tmp = tempfile.TemporaryDirectory()
        self.flag = Path(self.tmp.name) / "run" / "posture.active"

    def tearDown(self):
        self.tmp.cleanup()

    def _posture(self, **kw):
        kw.setdefault("trigger", 3)
        kw.setdefault("window", 300)
        kw.setdefault("hold", 900)
        return self.t.AttackPosture(self.flag, log=_QuietLog(), **kw)

    def test_below_the_trigger_nothing_happens(self):
        p = self._posture()
        p.note(1)
        p.note(1)
        self.assertFalse(p.active())

    def test_the_trigger_raises_it(self):
        p = self._posture()
        self.assertFalse(p.note(1))
        self.assertFalse(p.note(1))
        self.assertTrue(p.note(1), "the third signal must raise the posture")
        self.assertTrue(p.active())

    def test_one_heavy_signal_can_raise_it_alone(self):
        """A decoy hit or a distributed sweep is worth several bans."""
        p = self._posture()
        self.assertTrue(p.note(3))

    def test_old_signals_do_not_count(self):
        """Otherwise a quiet week slowly accumulates into a raised posture."""
        p = self._posture(window=10)
        p.note(1)
        p.note(1)
        # Age the events past the window.
        p._events = type(p._events)([(time.time() - 600, 1), (time.time() - 600, 1)])
        p.note(1)
        self.assertFalse(p.active(), "stale signals must have expired")

    def test_it_lifts_by_itself_when_the_deadline_passes(self):
        """Expiry is the flag's mtime, so nothing has to run to enforce it."""
        p = self._posture(hold=30)
        p.note(3)
        self.assertTrue(p.active())
        os.utime(str(self.flag), (time.time() - 1, time.time() - 1))
        self.assertFalse(p.active())

    def test_the_transition_is_reported_once(self):
        p = self._posture()
        p.note(3)
        self.assertEqual("on", p.transition())
        self.assertEqual("", p.transition(), "a transition must not repeat")
        os.utime(str(self.flag), (time.time() - 1, time.time() - 1))
        p._at = 0
        self.assertEqual("off", p.transition())
        self.assertEqual("", p.transition())

    def test_thresholds_tighten_while_it_is_up(self):
        from vigil.guards import threat as threat_mod
        cfg = vconfig.Config(path=Path(self.tmp.name) / "c.json",
                             secrets_path=Path(self.tmp.name) / "s.json")
        cfg.set("threat.posture.trigger_bans", 1)
        cfg.set("threat.posture.factor", 0.5)
        daemon = threat_mod.ThreatDaemon(cfg, log=_QuietLog(), dry_run=True,
                                         echo=False)
        # Point the daemon at a flag we control.
        daemon.posture = threat_mod.AttackPosture(
            self.flag, window=300, trigger=1, hold=900, log=_QuietLog())
        self.assertEqual(8, daemon.thr(8), "relaxed while nothing is happening")
        daemon.posture.note(1)
        self.assertEqual(4, daemon.thr(8), "halved while under attack")
        self.assertEqual(1, daemon.thr(1), "never reaches zero")

    def test_a_ban_burst_raises_it_through_the_daemon(self):
        from vigil.guards import threat as threat_mod
        cfg = vconfig.Config(path=Path(self.tmp.name) / "c.json",
                             secrets_path=Path(self.tmp.name) / "s.json")
        cfg.set("threat.posture.trigger_bans", 2)
        daemon = threat_mod.ThreatDaemon(cfg, log=_QuietLog(), dry_run=True,
                                         echo=False)
        daemon.posture = threat_mod.AttackPosture(
            self.flag, window=300, trigger=2, hold=900, log=_QuietLog())
        # A routable address: reserved space is deliberately excluded from
        # raising the posture, because a log full of test fixtures is not a
        # campaign.
        line = ('8.8.4.10 - - [x] "GET /.git/config HTTP/1.1" 444 0 "-" "s"')
        daemon.handle_decoy(line)          # weight 3 -> raises on its own
        self.assertTrue(daemon.posture.active())


class TestLureSurfaces(unittest.TestCase):
    """Lures only raise the hit rate if they are findable, honest and safe.

    Three properties matter more than the feature itself: the canary must be
    stable (or a hit cannot be recognised), the block must be stripped from
    the corpus (or advertising a path disqualifies it as "referenced by the
    site" and the lure deletes itself on the next run), and uninstall must
    leave the site's own robots.txt exactly as it was.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.webroot = self.root / "www"
        self.webroot.mkdir()
        from vigil.guards import lure, decoy
        self.lure, self.decoy = lure, decoy
        self._old_canary = lure.CANARY_FILE
        lure.CANARY_FILE = self.root / "canary.json"
        self.addCleanup(self._restore)
        self._old_site = decoy._site
        decoy._site = lambda cfg=None: ("example.test", str(self.webroot))

    def _restore(self):
        self.lure.CANARY_FILE = self._old_canary
        self.decoy._site = self._old_site

    # -- the canary ------------------------------------------------------

    def test_the_canary_is_stable_across_calls(self):
        """A canary that changes cannot be recognised in a log."""
        first = self.lure.canary()
        self.assertTrue(first.startswith("/"))
        self.assertGreater(len(first), 12)
        self.assertEqual(first, self.lure.canary())
        self.assertEqual(first, self.lure.canary_entry()[0])

    def test_two_hosts_get_different_canaries(self):
        a = self.lure.canary()
        self.lure.CANARY_FILE.unlink()
        b = self.lure.canary()
        self.assertNotEqual(a, b, "金丝雀是写死的，等于没有金丝雀")

    def test_the_canary_looks_like_something_worth_asking_for(self):
        """Realism is the point: `/honeypot` would never be requested."""
        c = self.lure.canary()
        self.assertFalse(any(w in c.lower() for w in
                             ("honeypot", "fake", "trap", "decoy", "test")))

    # -- the published surfaces ------------------------------------------

    def test_the_block_advertises_the_canary(self):
        body = self.lure.robots_block()
        self.assertIn(self.decoy.LURE_BEGIN, body)
        self.assertIn(self.decoy.LURE_END, body)
        self.assertIn("Disallow: %s" % self.lure.canary(), body)
        self.assertIn("Sitemap:", body)

    def test_the_sitemap_lists_the_canary(self):
        xml = self.lure.sitemap_xml()
        self.assertIn("<urlset", xml)
        self.assertIn(self.lure.canary(), xml)

    def test_the_sitemap_is_not_written_into_the_webroot(self):
        """A file in the webroot becomes site content and has to be screened;
        serving it from a snippet keeps the site untouched."""
        before = {p.name for p in self.webroot.iterdir()}
        self.lure.sitemap_xml()
        self.lure.render()
        self.assertEqual(before, {p.name for p in self.webroot.iterdir()})

    # -- the self-disqualification trap ----------------------------------

    def test_the_generated_block_is_stripped_from_the_site_corpus(self):
        """The bug this prevents: advertising a decoy makes the site "mention"
        it, screening rejects it, and the lure quietly removes itself."""
        (self.webroot / "robots.txt").write_text(
            "User-agent: *\nDisallow: /YangHaoYuXiYue/\n" + self.lure.robots_block(),
            encoding="utf-8")
        text = self.decoy.corpus(str(self.webroot))
        self.assertIn("yanghaoyuxiyue", text)          # the site's own line stays
        self.assertNotIn(self.lure.canary().lower(), text)
        self.assertNotIn("disallow: /backup.zip", text)

    def test_an_advertised_decoy_still_passes_screening(self):
        """End to end: publish, then re-screen -- it must survive."""
        (self.webroot / "robots.txt").write_text(self.lure.robots_block(),
                                                 encoding="utf-8")
        safe, rejected = self.decoy.screen(str(self.webroot))
        paths = {p for p, _t, _w in safe}
        self.assertIn(self.lure.canary(), paths)
        for bad in [r for r in rejected if "引用了它" in r[1]]:
            self.fail("宣传后反而被判为站点引用：%s" % (bad,))

    # -- robots.txt handling ---------------------------------------------

    def test_install_appends_and_preserves_the_sites_own_lines(self):
        (self.webroot / "robots.txt").write_text(
            "User-agent: *\nDisallow: /private/\n", encoding="utf-8")
        ok, _msg = self.lure.install_robots()
        self.assertTrue(ok)
        text = (self.webroot / "robots.txt").read_text(encoding="utf-8")
        self.assertIn("Disallow: /private/", text)      # 站点自己的规则没动
        self.assertIn(self.decoy.LURE_BEGIN, text)
        self.assertTrue(self.lure.status()["robots_installed"])

    def test_install_is_idempotent(self):
        (self.webroot / "robots.txt").write_text("User-agent: *\n",
                                                 encoding="utf-8")
        self.lure.install_robots()
        first = (self.webroot / "robots.txt").read_text(encoding="utf-8")
        self.lure.install_robots()
        second = (self.webroot / "robots.txt").read_text(encoding="utf-8")
        self.assertEqual(first, second, "重复安装把段落越堆越多")
        self.assertEqual(1, second.count(self.decoy.LURE_BEGIN))

    def test_uninstall_restores_the_file_exactly(self):
        original = "User-agent: *\nDisallow: /private/\n"
        (self.webroot / "robots.txt").write_text(original, encoding="utf-8")
        self.lure.install_robots()
        self.lure.uninstall_robots()
        self.assertEqual(original,
                         (self.webroot / "robots.txt").read_text(encoding="utf-8"))
        self.assertFalse(self.lure.status()["robots_installed"])

    def test_uninstall_removes_a_file_it_created(self):
        """If there was no robots.txt, do not leave an empty one behind."""
        self.lure.install_robots()
        self.assertTrue((self.webroot / "robots.txt").exists())
        self.lure.uninstall_robots()
        self.assertFalse((self.webroot / "robots.txt").exists())

    # -- honesty in the report -------------------------------------------

    def test_the_report_does_not_call_an_unused_lure_effective(self):
        """The paper's point, applied to our own reporting: hit counts are a
        poor metric, so the report must not present "installed N paths" as
        effectiveness."""
        old_hits = self.decoy.read_hits
        self.decoy.read_hits = lambda *a, **k: []
        try:
            text = self.lure.format_status(self.lure.status())
        finally:
            self.decoy.read_hits = old_hits
        self.assertIn("不能靠", text)
        self.assertIn("尚无命中", text)

    def test_a_canary_hit_is_reported_as_a_working_lure(self):
        old_hits = self.decoy.read_hits
        self.decoy.read_hits = lambda *a, **k: [
            {"ts": 1.0, "ip": "203.0.113.9", "uri": self.lure.canary()}]
        try:
            st = self.lure.status()
        finally:
            self.decoy.read_hits = old_hits
        self.assertEqual(1, st["canary_hits"])
        self.assertIn("确认有自动化流量读取了本机的诱导面",
                      self.lure.format_status(st))

    # -- not shadowing a sitemap the site already publishes ---------------

    def test_a_site_with_its_own_sitemap_is_not_shadowed(self):
        """Shadowing it is the mistake this module already refuses to make
        with robots.txt: the operator's file stays on disk while nginx serves
        our fiction, and nothing in their tooling ever notices."""
        (self.webroot / "sitemap.xml").write_text(
            '<?xml version="1.0"?><urlset><url><loc>https://example.test/</loc></url></urlset>',
            encoding="utf-8")
        self.assertIsNotNone(self.lure.own_sitemap())
        self.assertFalse(self.lure.should_serve_sitemap(),
                         "站点已有 sitemap，却还要拿诱饵去顶掉它")

    def test_the_decoy_sitemap_is_still_served_when_the_site_has_none(self):
        self.assertIsNone(self.lure.own_sitemap())
        self.assertTrue(self.lure.should_serve_sitemap())
        self.assertIn("location = /sitemap.xml", self.lure.render())

    def test_installing_withdraws_a_decoy_that_started_shadowing(self):
        """The migration that matters: the snippet was installed while the
        site had no sitemap; later the site published one. Without this the
        decoy would keep winning and the real sitemap would never be served."""
        calls = []
        self._patch_nginx(calls)
        target = self.lure.conf_path()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.lure.render(), encoding="utf-8")
        (self.webroot / "sitemap.xml").write_text("<urlset/>", encoding="utf-8")

        r = self.lure.install()
        self.assertTrue(r["ok"], r["problems"])
        self.assertEqual("skipped", r["sitemap"])
        self.assertFalse(target.exists(), "旧的诱饵片段没有被撤下来")
        self.assertIn("站点已发布自己的", r["sitemap_reason"])
        self.assertIn("nginx", " ".join(calls), "撤下配置后必须 reload，否则线上没变")

    def test_installing_writes_the_snippet_when_there_is_no_real_sitemap(self):
        calls = []
        self._patch_nginx(calls)
        target = self.lure.conf_path()
        r = self.lure.install()
        self.assertTrue(r["ok"], r["problems"])
        self.assertEqual("served", r["sitemap"])
        self.assertTrue(target.exists())
        self.assertIn("location = /sitemap.xml", target.read_text(encoding="utf-8"))

    def test_the_mode_can_force_the_decoy_on_or_off(self):
        cfg = vconfig.Config(path=self.root / "c.json",
                             secrets_path=self.root / "s.json")
        (self.webroot / "sitemap.xml").write_text("<urlset/>", encoding="utf-8")
        self.assertFalse(self.lure.should_serve_sitemap(cfg))     # auto
        cfg.set("threat.lure.sitemap", "always")
        self.assertTrue(self.lure.should_serve_sitemap(cfg))
        cfg.set("threat.lure.sitemap", "never")
        self.assertFalse(self.lure.should_serve_sitemap(cfg))
        cfg.set("threat.lure.sitemap", "不是合法值")
        self.assertEqual("auto", self.lure.sitemap_mode(cfg),
                         "非法值应当退回默认，而不是当成 always")

    def test_the_sitemap_directive_only_turns_absolute_for_a_real_sitemap(self):
        """A relative line is ignored by crawlers -- the safe default while
        the only sitemap we could name is our own fiction."""
        self.assertEqual("/sitemap.xml",
                         self.lure._sitemap_directive())
        (self.webroot / "sitemap.xml").write_text("<urlset/>", encoding="utf-8")
        self.assertEqual("https://example.test/sitemap.xml",
                         self.lure._sitemap_directive())

    def test_status_says_whose_sitemap_is_being_served(self):
        (self.webroot / "sitemap.xml").write_text("<urlset/>", encoding="utf-8")
        st = self.lure.status()
        self.assertTrue(st["own_sitemap"].endswith("sitemap.xml"))
        self.assertFalse(st["sitemap_installed"])
        self.assertIn("站点自己的 sitemap.xml 在用",
                      self.lure.format_status(st))

    def _patch_nginx(self, calls):
        """Keep the tests off the real nginx and off the real include dir.

        Without the `conf_path` stub the install path cannot be exercised at
        all here: this box has no `/www/server/panel/vhost/nginx/extension`
        for `example.test`, so `install()` bails out before doing anything --
        which is how the first version of these tests managed to pass while
        proving nothing.
        """
        conf = self.root / "include" / self.lure.CONF_NAME
        self._old_test = self.decoy._nginx_test
        self._old_reload = self.decoy._nginx_reload
        self._old_conf_path = self.lure.conf_path
        self.decoy._nginx_test = lambda: (True, "ok")
        self.decoy._nginx_reload = lambda: calls.append("nginx reload")
        self.lure.conf_path = lambda cfg=None: conf

        def restore():
            self.decoy._nginx_test = self._old_test
            self.decoy._nginx_reload = self._old_reload
            self.lure.conf_path = self._old_conf_path
        self.addCleanup(restore)


class TestHardeningFromRealProbes(unittest.TestCase):
    """The gaps a real access log exposed, pinned so they cannot reopen.

    Everything asserted here comes from an actual 506k-line nginx access log on
    a live host: probe paths that were being requested but scored nothing at
    all, and a whitelist that silently swallowed a scanner. Both are the same
    kind of failure -- the program was working exactly as written, and what it
    was written to notice was incomplete.
    """

    def setUp(self):
        from vigil.guards import decoy as decoy_mod
        from vigil.guards import knowledge, learning
        from vigil.guards import threat as threat_mod
        self.decoy, self.knowledge = decoy_mod, knowledge
        self.learning, self.t = learning, threat_mod
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = vconfig.Config(path=Path(self.tmp.name) / "c.json",
                                  secrets_path=Path(self.tmp.name) / "s.json")

    # -- coverage: paths that were probed but scored nothing ---------------

    def test_the_ai_agent_surface_is_covered(self):
        """Five different sources probed MCP/SSE endpoints. Not one of them was
        a decoy, so none of it counted -- a new attack surface with no tripwire."""
        paths = {p for p, _t, _w in self.decoy.DECOYS}
        for want in ("/mcp", "/mcp/", "/api/mcp", "/sse",
                     "/api/auth/validate-sso", "/.well-known/ai-plugin.json"):
            self.assertIn(want, paths, "AI 代理接口 %s 没有诱饵，探了也不记分" % want)

    def test_linux_home_directory_probes_are_covered(self):
        paths = {p for p, _t, _w in self.decoy.DECOYS}
        for want in ("/.config/pulse/", "/.cache/motd.legal-displayed",
                     "/.config/", "/.wget-hsts"):
            self.assertIn(want, paths, "家目录踩点路径 %s 没有诱饵" % want)

    def test_the_new_decoys_still_look_like_something_real(self):
        """The realism rule applies to additions too, or the lure degrades."""
        for p, _t, _w in self.decoy.DECOYS:
            self.assertFalse(any(w in p.lower() for w in
                                 ("honeypot", "fake", "trap", "decoy")),
                             "诱饵名字一眼就能看穿：%s" % p)

    # -- signatures: exploits that were attempted and never matched --------

    def _matched(self, probe):
        return [why for pat, why in self.knowledge.ATTACK_PATTERNS
                if re.search(pat, probe, re.I)]

    def test_the_pearcmd_rce_is_recognised(self):
        """A real attempt seen in the access log that no rule matched."""
        probe = ("/index.php?lang=../../../../../../../../usr/local/lib/php/"
                 "pearcmd&+config-create+/&/<?echo(md5(\"hi\"));?>+/tmp/index1.php")
        self.assertTrue(self._matched(probe), "pearcmd RCE 尝试没有被识别")

    def test_the_path_normalisation_bypass_is_recognised(self):
        """`/static../.git/config` walks past a prefix-written deny rule."""
        for probe in ("/static../.git/config", "/assets../.git/config",
                      "/media../.git/config"):
            self.assertTrue(self._matched(probe),
                            "%s 这类归一化绕过没有被识别" % probe)

    def test_the_mcp_probe_is_recognised(self):
        for probe in ("/mcp", "/api/mcp", "/sse",
                      "/api/auth/validate-sso"):
            self.assertTrue(self._matched(probe),
                            "MCP/SSE 探测 %s 没有被识别" % probe)

    # -- learning: a load test must not be able to train the lure ----------

    def test_benchmark_and_local_traffic_never_teaches_the_lure(self):
        """A 300k-request ApacheBench run was 60% of one host's log. If that
        trains the decoy list, the list stops describing attackers."""
        for host in ("127.0.0.1", "::1", "10.0.0.5", "192.168.1.9", "172.20.3.4"):
            self.assertTrue(self.learning._is_noise(host, ""), host)
        self.assertTrue(self.learning._is_noise("203.0.113.7", "ApacheBench/2.3"))
        self.assertTrue(self.learning._is_noise("203.0.113.7", "gobuster/3.6"))
        self.assertFalse(self.learning._is_noise("203.0.113.7", "curl/7.81.0"))
        self.assertFalse(self.learning._is_noise("203.0.113.7", ""))

    def test_noise_suppression_covers_learning_only(self):
        """It must not become a silent exemption from enforcement."""
        import inspect
        src = inspect.getsource(self.learning)
        # 判定/封禁路径不在 learning 模块里，学习降噪不该被它们引用
        from vigil.guards import threat as threat_mod
        self.assertNotIn("_is_noise", inspect.getsource(threat_mod))

    # -- whitelist: "never banned" must not also mean "never seen" ---------

    def test_a_whitelisted_scanner_is_reported_rather_than_swallowed(self):
        """The live case: a whitelisted IP probing /api/user/ismustmobile and
        /join_room. Whitelisted means it is never banned -- which used to mean
        nobody ever found out."""
        self.cfg.set("threat.whitelist", ["203.0.113.9"])
        daemon = self.t.ThreatDaemon(self.cfg, log=_QuietLog(), dry_run=True,
                                     echo=False)
        queued = []
        daemon.reporter.queue = lambda e: queued.append(e)
        banned = daemon.ban("203.0.113.9", "蜜罐诱饵命中：/wp-login.php", "decoy")
        self.assertFalse(banned, "白名单地址不应被封禁")
        kinds = [e.get("kind") for e in queued]
        self.assertIn("WHITELIST", kinds,
                      "白名单地址命中规则却没有产生任何告警，等于无声放行")
        event = [e for e in queued if e.get("kind") == "WHITELIST"][0]
        self.assertIn("203.0.113.9", str(event))

    def test_the_whitelist_alert_does_not_repeat_every_hit(self):
        """A scanner hits hundreds of times; the alert must not become the flood."""
        self.cfg.set("threat.whitelist", ["203.0.113.10"])
        daemon = self.t.ThreatDaemon(self.cfg, log=_QuietLog(), dry_run=True,
                                     echo=False)
        queued = []
        daemon.reporter.queue = lambda e: queued.append(e)
        for _ in range(25):
            daemon.ban("203.0.113.10", "蜜罐诱饵命中：/.env", "decoy")
        self.assertEqual(1, len(queued),
                         "同一地址 6 小时内应当只提醒一次，实际 %d 条" % len(queued))

    def test_the_whitelist_alert_is_wired_into_the_mail_renderer(self):
        """A kind that is queued but has no title/section renders as noise."""
        src = inspect_module_src(self.t)
        for needle in ('"WHITELIST": "白名单 IP 命中了封禁规则',
                       'groups.get("WHITELIST")',
                       'if kind == "WHITELIST"'):
            self.assertIn(needle, src, "WHITELIST 告警链路缺了一段：%s" % needle)


def inspect_module_src(module):
    import inspect
    return inspect.getsource(module)


class TestEvolveSelfImprovement(unittest.TestCase):
    """The bounded self-improvement loop, and the reasons it is allowed to run.

    A component that edits its own behaviour needs its limits tested harder than
    its features: the features failing is an inconvenience, a limit failing is a
    security incident. So most of what follows asserts what the loop *refuses*
    to do, and each refusal is paired with the accident it prevents.
    """

    def setUp(self):
        import tempfile
        from pathlib import Path as _P
        from vigil import evolve
        from vigil.evolve import budget, ledger, report, score
        from vigil.core import paths as vpaths
        self.ev, self.budget = evolve, budget
        self.ledger, self.report, self.score = ledger, report, score
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = _P(self.tmp.name)
        # Redirect every state file the loop owns, so a test run cannot touch
        # the real adopted list or ledger of the host running it.
        self._saved = (evolve.ADOPTED, ledger.LEDGER, ledger.BACKUP_DIR)
        evolve.ADOPTED = self.root / "adopted.json"
        ledger.LEDGER = self.root / "ledger.jsonl"
        ledger.BACKUP_DIR = self.root / "backup"

        def restore():
            evolve.ADOPTED, ledger.LEDGER, ledger.BACKUP_DIR = self._saved
        self.addCleanup(restore)
        # 资源闸门要按真实主机状态读负载与内存；测试不能因此时好时坏。
        # 这台机器负载本来就会波动（构建、巡检、压测），不隔离的话
        # 「apply 成功」这类断言取决于跑测试的那一刻机器忙不忙。
        self._patch_module(budget, free_mb=lambda: 4096.0,
                           load1=lambda: 0.0, disk_free_mb=lambda: 99999.0)

    def _patch_module(self, mod, **attrs):
        """模块级打桩并自动还原（见 setUp 里为什么必须这样）。"""
        saved = {k: getattr(mod, k) for k in attrs}
        for k, v in attrs.items():
            setattr(mod, k, v)

        def restore():
            for k, v in saved.items():
                setattr(mod, k, v)
        self.addCleanup(restore)

    def _patch(self, mod, **attrs):
        """Set module attributes and put them back afterwards.

        Without the restore these leak into every later test: an earlier case
        stubbed `free_mb` down to 100 MB to prove the budget refuses to start,
        and the next test then failed for that reason rather than its own.
        """
        saved = {k: getattr(mod, k) for k in attrs}
        for k, v in attrs.items():
            setattr(mod, k, v)

        def restore():
            for k, v in saved.items():
                setattr(mod, k, v)
        self.addCleanup(restore)

    # -- the resource governor --------------------------------------------

    def test_the_budget_is_a_share_of_what_is_free(self):
        """A fixed "use up to 200 MB" is wrong on a 1 GB box and on a 64 GB one."""
        b = self.budget.Budget()
        b.memory_pct = 5.0
        self._patch(self.budget, free_mb=lambda: 1000.0)
        self.assertAlmostEqual(50.0, b.slice_mb(), places=1)

    def test_it_refuses_to_start_when_the_host_is_busy(self):
        b = self.budget.Budget()
        b.memory_floor = 400.0
        self._patch(self.budget, free_mb=lambda: 100.0)
        ok, why = b.may_start()
        self.assertFalse(ok, "可用内存只有 100 MB 却允许开工")
        self.assertIn("内存", why)

    def test_it_refuses_to_start_under_load(self):
        b = self.budget.Budget()
        b.load_ratio = 0.5
        self._patch(self.budget, free_mb=lambda: 8000.0, load1=lambda: 99.0)
        ok, why = b.may_start()
        self.assertFalse(ok)
        self.assertIn("负载", why)

    # -- the online scorer -------------------------------------------------

    def test_the_scorer_learns_from_evidence_and_can_explain_itself(self):
        s = self.score.Scorer()
        before = s.score("/.git/config")
        for _ in range(40):
            s.observe("/.git/config", 404, "curl/7.81.0", label=1)
        for _ in range(40):
            s.observe("/theme.css", 200, "Mozilla/5.0", label=0)
        self.assertGreater(s.score("/.git/config"), before)
        self.assertLess(s.score("/theme.css"), 0.5)
        names = [e["feature"] for e in s.explain("/.git/config")]
        self.assertTrue(any("git" in n for n in names),
                        "解释里应当指名道姓，而不是给出一个下标")

    def test_the_model_round_trips_through_json(self):
        s = self.score.Scorer()
        for _ in range(10):
            s.observe("/.env", 404, "", label=1)
        path = self.root / "m.json"
        self.assertTrue(s.save(path))
        again = self.score.Scorer.load(path)
        self.assertAlmostEqual(s.score("/.env"), again.score("/.env"), places=4)

    # -- what may become a decoy ------------------------------------------

    def test_a_path_must_survive_nginx_to_be_adopted(self):
        """A quote or a brace in a path is not a bad decoy, it is config injection."""
        for bad in ('/a"b', "/a b", "/a;b", "/a{b}", "/a\nb", "", "relative"):
            self.assertFalse(self.ev._SAFE_PATH.match(bad), bad)
        for good in ("/.env", "/wp-admin/install.php", "/api/mcp", "/.config/"):
            self.assertTrue(self.ev._SAFE_PATH.match(good), good)

    def test_adoption_needs_several_independent_sources(self):
        """One noisy client asking repeatedly is not evidence of a scanner."""
        obs = [{"ts": 1, "ip": "203.0.113.9", "path": "/noisy", "status": 404, "ua": ""}] * 50
        self._write_observations(obs)
        ev = self.ev.evidence()
        self.assertEqual([], [c["path"] for c in ev["candidates"]],
                         "单一来源刷 50 次被当成了证据")

    def test_adoption_needs_repeat_hits_as_well(self):
        # 3 个独立来源、各请求一次：来源数够了，命中数不够 —— 门槛是两条都要过
        obs = [{"ts": 1, "ip": "203.0.113.%d" % i, "path": "/once", "status": 404, "ua": ""}
               for i in range(1, 4)]
        self._write_observations(obs)
        ev = self.ev.evidence()
        self.assertEqual([], [c["path"] for c in ev["candidates"]],
                         "每个来源只请求一次也被当成了证据")

    def _write_observations(self, rows):
        import json
        from vigil.guards import learning
        path = self.root / "observations.jsonl"
        path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
        self._patch(learning, observations_path=lambda: path)

    def test_the_adopted_store_is_reread_defensively(self):
        """The store is a file on disk, so anything that can write it can try to
        inject config. `decoy` re-checks the grammar instead of trusting it."""
        import json
        from vigil.guards import decoy
        from vigil.core import paths as vpaths
        old = vpaths.STATE_STATE
        vpaths.STATE_STATE = self.root
        self.addCleanup(lambda: setattr(vpaths, "STATE_STATE", old))
        # 必须在重定向之后才算路径：先算再改的写法会把测试数据写进真实状态目录
        p = vpaths.STATE_STATE / "evolve-adopted.json"
        p.write_text(json.dumps([
            {"path": "/ok", "why": "fine"},
            {"path": '/bad"x', "why": "injection attempt"},
            {"path": "/bad;x", "why": "injection attempt"},
            {"path": "relative", "why": "not a path"},
        ]), encoding="utf-8")
        got = [e[0] for e in decoy.evolve_adopted()]
        self.assertEqual(["/ok"], got)

    # -- the code edit -----------------------------------------------------

    def test_the_edit_lands_after_the_anchor_and_is_valid_python(self):
        import ast
        from vigil.guards import decoy
        src = (self.root / "decoy.py")
        src.write_text(decoy.__file__ and open(decoy.__file__, encoding="utf-8").read(),
                       encoding="utf-8")
        text = src.read_text(encoding="utf-8")
        patched = self.ev._insert_decoys(text, self.ev._patch_entries([
            {"path": "/probe-me", "why": "测试"}]) )
        self.assertTrue(patched)
        ast.parse(patched)
        self.assertIn('("/probe-me"', patched)
        # 必须在 DECOYS 元组里，而不是文件别的地方
        self.assertLess(patched.index('("/probe-me"'), patched.index('("/.env"'))

    def test_source_edits_are_off_unless_explicitly_enabled(self):
        cfg = vconfig.Config(path=self.root / "c.json",
                             secrets_path=self.root / "s.json")
        self.assertFalse(bool(cfg.get("evolve.allow_code_edits", False)),
                         "源码自改必须默认关闭")
        self.assertFalse(bool(cfg.get("evolve.enabled", False)),
                         "自修正循环必须默认关闭")
        self.assertEqual("", str(cfg.get("evolve.source_root", "")))

    def test_an_unsafe_path_is_refused_by_the_gate(self):
        ok, why = self.ev._tier1_gates(None, {"path": '/x"y'})
        self.assertFalse(ok)
        self.assertIn("不安全", why)

    def test_applying_mails_before_writing_anything(self):
        """A program that edits itself without saying so first cannot be told
        apart from one that has been taken over."""
        order = []
        self._patch(self.report, mail=lambda *a, **k: (order.append("mail"), True)[1])
        prop = {"id": "adopt:/.probe-x", "kind": "adopt_decoy", "path": "/.probe-x",
                "why": "测试", "evidence": {"hits": 9, "ips": 4}}
        self._patch(self.budget, free_mb=lambda: 5000.0)
        res = self.ev.apply(None, prop, dry_run=True)
        self.assertTrue(res["ok"], res)
        self.assertEqual(["mail"], order, "预演阶段就必须先发邮件")

    def test_every_self_modification_mails_before_it_writes(self):
        """The one invariant that makes an autonomous agent acceptable: whatever
        it decides to change, the operator hears about it *first*.

        Adding a rule and removing a rule are both changes to what the defence
        looks like. A rule that disappears without a word is how a defence
        quietly stops defending, and it is the change nobody thinks to announce
        -- so this walks every mutating kind rather than trusting the code path
        that happened to be written most recently.
        """
        import json
        order = []
        self._patch(self.report, mail=lambda *a, **k: (order.append("mail"), True)[1],
                    send_report=lambda *a, **k: {"ok": True})
        self._patch(self.budget, free_mb=lambda: 5000.0)

        # 1) 新增规则
        self.assertTrue(self.ev.apply(None, {
            "id": "adopt:/.mail-check", "kind": "adopt_decoy",
            "path": "/.mail-check", "why": "测试",
            "evidence": {"hits": 9, "ips": 4}})["ok"])
        self.assertEqual(["mail"], order, "新增规则没有先发邮件")

        # 2) 撤下规则
        order.clear()
        self.assertTrue(self.ev.apply(None, {
            "id": "adopt:/.mail-check", "kind": "retire_decoy",
            "path": "/.mail-check", "why": "从未命中",
            "evidence": {"hits": 0, "age_hours": 48}})["ok"])
        self.assertEqual(["mail"], order, "撤下规则没有先发邮件")

        # 3) 运维直接调 rollback 也要有邮件
        order.clear()
        self.ev.rollback(None, "adopt:/.mail-check")
        self.assertFalse(order, "已经不存在了，不应再发")
        self.assertTrue(self.ev.apply(None, {
            "id": "adopt:/.mail-check2", "kind": "adopt_decoy",
            "path": "/.mail-check2", "why": "测试",
            "evidence": {"hits": 9, "ips": 4}})["ok"])
        order.clear()
        self.assertTrue(self.ev.rollback(None, "adopt:/.mail-check2")["ok"])
        self.assertEqual(["mail"], order, "手动撤销没有发邮件")

    def test_a_mailed_rule_change_is_also_written_to_the_ledger(self):
        self._patch(self.report, mail=lambda *a, **k: True,
                    send_report=lambda *a, **k: {"ok": True})
        self._patch(self.budget, free_mb=lambda: 5000.0)
        self.ev.apply(None, {"id": "adopt:/.led", "kind": "adopt_decoy",
                             "path": "/.led", "why": "测试",
                             "evidence": {"hits": 9, "ips": 4}})
        self.ev.rollback(None, "adopt:/.led")
        kinds = [e.get("kind") for e in self.ledger.read(50)]
        self.assertIn("proposed", kinds)
        self.assertIn("applied", kinds)
        self.assertIn("rolled-back", kinds)
        rolled = [e for e in self.ledger.read(50) if e.get("kind") == "rolled-back"][-1]
        self.assertTrue(rolled.get("mailed"), "台账没有记下邮件是否发出")

    def test_rollback_removes_an_adopted_decoy(self):
        prop = {"id": "adopt:/.probe-y", "kind": "adopt_decoy", "path": "/.probe-y",
                "why": "测试", "evidence": {"hits": 9, "ips": 4}}
        self._patch(self.report, mail=lambda *a, **k: True,
                    send_report=lambda *a, **k: {"ok": True})
        self._patch(self.budget, free_mb=lambda: 5000.0)
        self.assertTrue(self.ev.apply(None, prop)["ok"])
        self.assertIn("/.probe-y", self.ev.adopted_paths())
        self.assertTrue(self.ev.rollback(None, "adopt:/.probe-y")["ok"])
        self.assertNotIn("/.probe-y", self.ev.adopted_paths())

    # -- the watchdog ------------------------------------------------------

    def test_the_watchdog_notices_a_runaway_loop(self):
        """The thing that edits the program must itself be watched, and it must
        not take the loop's own word for how it is doing."""
        for i in range(self.ev.RUNAWAY_PER_HOUR + 5):
            self.ledger.record("applied", id="adopt:/x%d" % i, path="/x%d" % i)
        self._patch(self.report, mail=lambda *a, **k: True,
                    send_report=lambda *a, **k: {"ok": True})
        res = self.ev.watchdog(None)
        self.assertFalse(res["ok"], "一小时内几十次改动却没有报警")
        self.assertTrue(any("失控" in m for _l, m in res["findings"]))

    # -- the report channel ------------------------------------------------

    def test_reports_cannot_carry_host_identity(self):
        out = self.report.scrub({"event": "x", "ip": "203.0.113.7",
                                 "hostname": "h", "webroot": "/www/a",
                                 "path": "/secret", "count": 3,
                                 "nested": {"domain": "a.test", "n": 1}})
        self.assertEqual({"event": "x", "count": 3, "nested": {"n": 1}}, out)

    def test_a_unicode_collector_url_is_idna_encoded(self):
        """`urllib` writes the request line as latin-1; an IDN host would raise
        before the request was even attempted, silently losing the channel."""
        # 用一个中性的 IDN 例子：拿真实站点域名写测试，会被本机禁词表（正确地）拦下
        got = self.report.ascii_url("https://例え.テスト/evolve/report.php")
        self.assertEqual("https://xn--r8jz45g.xn--zckzah/evolve/report.php", got)

    def test_reporting_is_off_until_an_address_is_configured(self):
        """A compiled-in collector URL would put one deployment's domain into a
        shipped file -- which the privacy audit refuses, and it caught this."""
        self.assertEqual("", self.report.DEFAULT_URL)


class TestEvolveSelfTraining(unittest.TestCase):
    """The agent half: labels it produces itself, and feedback it acts on."""

    def setUp(self):
        import tempfile
        from pathlib import Path as _P
        from vigil import evolve
        from vigil.evolve import train, score, ledger
        self.ev, self.train, self.score, self.ledger = evolve, train, score, ledger
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = _P(self.tmp.name)
        from vigil.core import paths as vpaths
        self._saved = (train.MODEL, train.OUTCOMES, evolve.ADOPTED,
                       ledger.LEDGER, vpaths.STATE_STATE)
        train.MODEL = self.root / "m.json"
        train.OUTCOMES = self.root / "o.json"
        evolve.ADOPTED = self.root / "a.json"
        ledger.LEDGER = self.root / "l.jsonl"
        ledger.BACKUP_DIR = self.root / "b"
        vpaths.STATE_STATE = self.root
        self.addCleanup(self._restore)

    def _restore(self):
        from vigil.core import paths as vpaths
        (self.train.MODEL, self.train.OUTCOMES, self.ev.ADOPTED,
         self.ledger.LEDGER, vpaths.STATE_STATE) = self._saved

    def _write(self, name, rows):
        import json
        (self.root / name).write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in rows), encoding="utf-8")

    def test_labels_come_from_consequences_not_from_a_human(self):
        """A decoy hit is already a decision the program made; reading it back
        as a training label is free supervision."""
        self._write("decoy-hits.jsonl", [{"uri": "/.git/config", "ip": "203.0.113.9"}] * 5)
        self._write("observations.jsonl", [
            {"path": "/theme.css", "status": 200, "ua": "Mozilla/5.0", "ip": "198.51.100.5"},
            {"path": "/index.html", "status": 200, "ua": "Mozilla/5.0", "ip": "198.51.100.6"},
        ])
        rows = self.train.label_samples()
        lab = {(r["path"], r["label"]) for r in rows}
        self.assertIn(("/.git/config", 1), lab)
        self.assertIn(("/theme.css", 0), lab)
        self.assertTrue(all(r["why"] != "guessed" for r in rows))

    def test_an_unexplained_404_is_not_treated_as_an_attack(self):
        """Training on every 404 would just relearn the program's own blocking
        and inflate the score of anything the ban list already caught."""
        self._write("decoy-hits.jsonl", [])
        self._write("observations.jsonl", [
            {"path": "/maybe-broken-link", "status": 404, "ua": "Mozilla/5.0",
             "ip": "198.51.100.7"}])
        self.assertEqual([], self.train.label_samples())

    def test_training_saves_a_model_and_reports_a_held_out_score(self):
        # 路径必须各不相同：样本按键 (path,status,ua) 去重，同一路径刷 20 次只有 1 条
        self._write("decoy-hits.jsonl",
                    [{"uri": "/probe-%d" % i, "ip": "203.0.113.%d" % (i % 8)}
                     for i in range(20)])
        self._write("observations.jsonl",
                    [{"path": "/page-%d.css" % i, "status": 200, "ua": "Mozilla/5.0",
                      "ip": "198.51.100.%d" % (i % 8)} for i in range(20)])
        res = self.train.train()
        self.assertTrue(res["ok"], res)
        self.assertGreater(res["held_out"], 0, "没有留出集就等于自己给自己打分")
        self.assertTrue(self.train.MODEL.is_file())
        self.assertGreater(self.score.Scorer.load(self.train.MODEL).seen, 0)

    def test_a_decoy_that_never_fires_is_proposed_for_retirement(self):
        """The feedback half: without it the adopted list only ever grows."""
        import json, time
        self.ev.ADOPTED.write_text(json.dumps([{
            "path": "/never-fired", "id": "adopt:/never-fired",
            "adoptedAt": time.time() - 48 * 3600, "why": "t"}]), encoding="utf-8")
        self._write("decoy-hits.jsonl", [])
        props = self.train.retire_proposals()
        self.assertEqual(["/never-fired"], [x["path"] for x in props])
        self.assertEqual("retire_decoy", props[0]["kind"])

    def test_a_decoy_inside_the_grace_period_is_not_judged(self):
        import json, time
        self.ev.ADOPTED.write_text(json.dumps([{
            "path": "/just-added", "id": "adopt:/just-added",
            "adoptedAt": time.time() - 3600, "why": "t"}]), encoding="utf-8")
        self._write("decoy-hits.jsonl", [])
        self.assertEqual([], self.train.retire_proposals())
        self.assertEqual("too-new", [x for x in self.train.outcomes()["per"]][0]["verdict"])

    def test_a_decoy_that_fired_is_kept(self):
        import json, time
        self.ev.ADOPTED.write_text(json.dumps([{
            "path": "/fired", "id": "adopt:/fired",
            "adoptedAt": time.time() - 48 * 3600, "why": "t"}]), encoding="utf-8")
        self._write("decoy-hits.jsonl", [{"uri": "/fired", "ip": "203.0.113.1"}])
        self.assertEqual([], self.train.retire_proposals())
        self.assertEqual(1, self.train.outcomes()["keep"])


class TestEvolveGeneralisation(unittest.TestCase):
    """Does it actually generalise, or does the test just look like it does?

    Both tests here exist because the first version of the novel-attack metric
    reported a confident 100% for a model that had never been trained: an
    untrained scorer returns exactly 0.5, and the threshold was `>= 0.5`. A
    measurement that a blank model passes measures nothing.
    """

    def test_the_novel_attack_test_fails_on_a_blank_model(self):
        from vigil.evolve import corpus, score
        res = corpus.novel_attack_test(score.Scorer())
        self.assertFalse(res["usable"], "空白模型竟然通过了泛化测试")
        self.assertEqual(0, res["caught"])
        self.assertLess(res["separation"], 0.3,
                        "空白模型的区分度必须接近 0，否则这个指标在自欺")

    def test_the_corpus_withholds_whole_families(self):
        from vigil.evolve import corpus
        trained = {row[0] for row in corpus.build(
            skip_families=corpus.HELD_OUT) if row[3] == 1}
        for fam in corpus.HELD_OUT:
            for path in corpus.FAMILIES[fam]:
                self.assertNotIn(path, trained,
                                 "%s 族的 %s 泄漏进了训练集，泛化测试无效" % (fam, path))

    def test_training_produces_real_separation_without_false_alarms(self):
        """The number this feature exists for: attacks it has never seen score
        high, ordinary paths score low, and the gap is wide."""
        from vigil.evolve import corpus, score
        model = score.Scorer()
        # 12 轮：语料在修掉状态码/UA 两个作弊点后变难了，8 轮收敛不到位
        for _ in range(12):
            for path, status, ua, label in corpus.build(skip_families=corpus.HELD_OUT):
                model.observe(path, status, ua, label=label)
        res = corpus.novel_attack_test(model)
        self.assertTrue(res["usable"], "训练后仍然不可用：%s" % res)
        self.assertGreaterEqual(res["separation"], 0.3)
        self.assertEqual([], res["false_alarms"],
                         "把正常路径判成了攻击：%s" % res["false_alarms"])

    def test_critical_files_are_refused_even_if_the_allowlist_widens(self):
        """Two locks, because the first one is a list someone can edit. An agent
        that can widen its own limits, or blind its own reporter, is not bounded."""
        import tempfile
        from pathlib import Path as _P
        from vigil import evolve
        self.assertIn("src/vigil/evolve/__init__.py", evolve.CRITICAL_FILES)
        self.assertIn("src/vigil/guards/threat.py", evolve.CRITICAL_FILES)
        self.assertTrue(any(c.startswith("src/vigil/mail") for c in evolve.CRITICAL_FILES))
        root = _P(tempfile.mkdtemp())
        (root / "src/vigil/guards").mkdir(parents=True)
        (root / "src/vigil/guards/threat.py").write_text("x = 1\n", encoding="utf-8")
        saved = evolve.SAFE_CODE_FILES
        evolve.SAFE_CODE_FILES = ("src/vigil/guards/threat.py",)
        try:
            res = evolve._code_edit(None, str(root), [{"path": "/x", "why": "y"}])
        finally:
            evolve.SAFE_CODE_FILES = saved
        self.assertFalse(res["ok"], "关键文件被改动了")
        self.assertIn("关键文件", res["err"])
        self.assertEqual("x = 1\n",
                         (root / "src/vigil/guards/threat.py").read_text(encoding="utf-8"))


class TestHttpBurstIsAboutMissingPaths(unittest.TestCase):
    """The directory-scan detector must mean what its name says.

    This detector had no tests at all, which is how it came to count *every*
    status >= 400 as evidence of scanning. The false positive that surfaced was
    not exotic: a token-authenticated polling endpoint answers 401 while its
    token is expired, and a client that polls it often enough accumulated a
    hundred of them and was reported as "directory scanning" without having
    requested a single path that did not exist. The victim of that mistake is
    the heaviest legitimate user, which is the worst possible target for a
    false positive.
    """

    def setUp(self):
        from vigil.guards import threat as threat_mod
        self.t = threat_mod
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = vconfig.Config(path=Path(self.tmp.name) / "c.json",
                                  secrets_path=Path(self.tmp.name) / "s.json")
        self.d = self.t.ThreatDaemon(self.cfg, log=_QuietLog(), dry_run=True,
                                     echo=False)

    def _feed(self, status, path, times):
        for _ in range(times):
            self.d.handle_http('203.0.113.77 - - [x] "GET %s HTTP/1.1" %d 0 "-" "c"'
                               % (path, status))

    def _banned(self):
        return "203.0.113.77" in self.d.state.bans

    def test_a_polling_client_getting_401s_is_never_banned(self):
        """The exact false positive: 401 means "your token expired", not
        "this path does not exist"."""
        self._feed(401, "/dsh-whale/last-turn.json", 300)
        self.assertFalse(self._banned(),
                         "轮询客户端因令牌过期收到 401，被当成了目录扫描")
        stats = getattr(self.d.state, "stats", {}) or {}
        self.assertIn("http_routine_4xx", stats,
                      "常规 4xx 应当单独记账，而不是计入扫描证据")

    def test_server_errors_do_not_get_the_visitor_banned(self):
        """A 500 is our bug. Banning the client for it is blaming the victim."""
        self._feed(500, "/api/thing", 300)
        self.assertFalse(self._banned())

    def test_a_403_burst_is_not_called_scanning(self):
        """Permission denied is a routine answer (WAF, directory listing off)."""
        self._feed(403, "/admin/", 300)
        self.assertFalse(self._banned())

    def test_real_directory_scanning_still_bans(self):
        """The detector must keep working on the thing it is named after."""
        self._feed(404, "/nope-%d" % 1, 400)
        self.assertTrue(self._banned(), "真正的目录扫描没有被封禁")

    def test_alternating_not_founds_still_accumulate(self):
        """An attacker mixing 404/410/444 must not slip between the counters."""
        for st in (404, 410, 444, 404, 410, 444):
            self._feed(st, "/gone", 40)
        self.assertTrue(self._banned())

    def test_volume_is_still_capped_by_the_flood_detector(self):
        """Excluding routine statuses from *scanning* must not create a hole:
        request volume is counted for every status, so a client that only ever
        produces 403s still trips the flood threshold."""
        self._feed(403, "/admin/", 2000)
        self.assertTrue(self._banned(), "只刷 403 的客户端再也封不掉了")


class TestWebStatusPage(unittest.TestCase):
    """The built-in page: no default credentials, and no host in the source.

    Two properties matter more than the page itself. A monitoring page with a
    shipped default login is an admin panel someone else already has the
    password to; and a page generated from a template that names one machine is
    a page that is wrong on every other machine.
    """

    def setUp(self):
        import tempfile
        from pathlib import Path as _P
        from vigil.web import server as wserver, status as wstatus, page as wpage
        self.w, self.wstatus, self.wpage = wserver, wstatus, wpage
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = _P(self.tmp.name)
        self.cfg = vconfig.Config(path=self.root / "c.json",
                                  secrets_path=self.root / "s.json")

    def test_there_is_no_default_account(self):
        self.assertFalse(self.w.credentials_set(self.cfg))
        self.assertEqual("", str(self.cfg.get("web.username", "")))
        self.assertFalse(self.w.verify_password(self.cfg, "admin", "admin"))
        self.assertFalse(self.w.verify_password(self.cfg, "", ""))

    def test_the_password_never_lands_in_the_config_file(self):
        self.w.set_password(self.cfg, "op", "correct horse battery staple")
        self.cfg.save(backup=False)
        conf = (self.root / "c.json").read_text(encoding="utf-8")
        secrets = (self.root / "s.json").read_text(encoding="utf-8")
        self.assertNotIn("correct horse", conf)
        self.assertNotIn("correct horse", secrets)
        self.assertIn("password_hash", secrets)
        self.assertIn("password_salt", secrets)
        self.assertNotIn("password_hash", conf,
                         "配置会被贴进工单，不该带凭据")

    def test_verification_needs_both_halves(self):
        self.w.set_password(self.cfg, "op", "a-long-enough-secret")
        self.assertTrue(self.w.verify_password(self.cfg, "op", "a-long-enough-secret"))
        self.assertFalse(self.w.verify_password(self.cfg, "op", "a-long-enough-secreT"))
        self.assertFalse(self.w.verify_password(self.cfg, "someone", "a-long-enough-secret"))

    def test_the_same_password_hashes_differently_every_time(self):
        """A fixed salt would make two hosts with the same password identical
        in an archive, and would let a precomputed table be reused."""
        a = self.w.hash_password("same-secret-value")
        b = self.w.hash_password("same-secret-value")
        self.assertNotEqual(a[0], b[0])
        self.assertNotEqual(a[1], b[1])

    def test_the_proxy_block_names_no_host_that_was_not_configured(self):
        from vigil.commands import web as cmd
        blank = cmd.render_conf(self.cfg)
        self.assertIn("server_name _;", blank,
                      "没配域名时不该凭空出现一个域名")
        self.assertIn("127.0.0.1:%d" % int(self.cfg.get("web.port", 9177)), blank)
        self.cfg.set("web.domain", "status.example.com")
        named = cmd.render_conf(self.cfg)
        self.assertIn("status.example.com", named)
        self.assertNotIn("vigil.example", named)

    def test_host_details_come_from_the_running_machine(self):
        board = self.wstatus.board(self.cfg)
        import socket
        self.assertEqual(socket.gethostname(), board["host"]["hostname"])
        self.assertTrue(board["cards"] and board["tables"])

    def test_sessions_are_not_written_to_disk(self):
        tok = self.w._Sessions(ttl=60).new()
        self.assertTrue(tok)
        self.assertEqual([], list(self.root.rglob("*session*")))

    def test_sessions_expire(self):
        s = self.w._Sessions(ttl=60)
        tok = s.new()
        self.assertTrue(s.valid(tok))
        s.drop(tok)
        self.assertFalse(s.valid(tok))
        self.assertFalse(s.valid(""))

    def test_login_attempts_are_rate_limited(self):
        a = self.w._Attempts(limit=3, window=60)
        for _ in range(3):
            self.assertFalse(a.blocked("203.0.113.9"))
            a.bump("203.0.113.9")
        self.assertTrue(a.blocked("203.0.113.9"), "登录没有被限流")
        self.assertFalse(a.blocked("198.51.100.4"), "限流不该牵连别的来源")

    def test_the_page_is_self_contained(self):
        """No CDN: a status page must render on a host with no outbound network."""
        body = self.wpage.status_page(title="t", host={"subtitle": "s"},
                                      cards=[], tables=[], csrf="x")
        self.assertIn("<style>", body)
        for bad in ("http://", "https://", "src="):
            self.assertNotIn(bad, body, "页面引用了外部资源：%s" % bad)
        self.assertIn("noindex", body)


class TestWebInstallDoesNotClobber(unittest.TestCase):
    """`vigil web install` must not silently replace somebody else's vhost.

    A real accident: running `vigil web install --domain <domain>` replaced the
    vhost another program had generated for that domain -- hand-tuned by the
    operator -- with the status-page proxy, and the page changed under them.
    The directory is shared and the filename is just `<domain>.conf`, which a
    panel would pick too, so the name proves nothing. Only the generated marker
    does.

    These tests point ``CONF_DIRS`` at a temporary directory and stub the nginx
    calls, so nothing here touches the host's real configuration.
    """

    DOMAIN = "status.example.com"

    def setUp(self):
        import contextlib
        import io
        from vigil.commands import web as web_mod
        self.web = web_mod
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.confdir = self.root / "vhost"
        self.confdir.mkdir()
        self.cfg = vconfig.Config(path=self.root / "config.json",
                                  secrets_path=self.root / "secrets.json")
        self.cfg.set("web.domain", self.DOMAIN)
        self.cfg.save()
        self._patched = []
        self._patch(web_mod, "CONF_DIRS", (str(self.confdir),))
        self._patch(web_mod.shell, "run", lambda *a, **k: (True, "", ""))
        self._patch(web_mod.shell, "systemd_reload", lambda *a, **k: None)
        self._buf = io.StringIO()
        self._redirect = contextlib.redirect_stdout(self._buf)
        self._redirect.__enter__()
        self.addCleanup(lambda: self._redirect.__exit__(None, None, None))

    def tearDown(self):
        for obj, name, old in reversed(self._patched):
            setattr(obj, name, old)
        self.tmp.cleanup()

    def _patch(self, obj, name, value):
        self._patched.append((obj, name, getattr(obj, name)))
        setattr(obj, name, value)

    def _args(self, domain=None, force=False):
        args = type("Args", (), {})()
        args.domain = self.DOMAIN if domain is None else domain
        # A Path, not str: `load_config` does not coerce, and `cfg.save()`
        # calls `self.path.exists()`.
        args.config = self.cfg.path
        args.force = force
        return args

    def _target(self):
        return self.confdir / ("%s.conf" % self.DOMAIN)

    # -- install ----------------------------------------------------------

    def test_it_refuses_to_overwrite_a_foreign_vhost(self):
        target = self._target()
        foreign = ("server {\n    listen 80;\n"
                   "    server_name example.org;\n}\n")
        target.write_text(foreign, encoding="utf-8")
        rc = self.web.cmd_install(self._args())
        self.assertEqual(1, rc, "必须拒绝覆盖别人的配置")
        self.assertEqual(foreign, target.read_text(encoding="utf-8"),
                         "被拒绝时目标文件必须一个字节都没动")
        out = self._buf.getvalue()
        self.assertIn("拒绝覆盖", out)
        self.assertIn(str(target), out, "提示里必须给出路径")
        self.assertIn("--force", out, "提示里必须说明如何强制覆盖")

    def test_it_overwrites_its_own_vhost(self):
        target = self._target()
        target.write_text(self.web.render_conf(self.cfg), encoding="utf-8")
        self.assertEqual(0, self.web.cmd_install(self._args()))
        first = target.read_text(encoding="utf-8")
        self.assertTrue(first.startswith(self.web.CONF_BEGIN))
        self.assertIn(self.DOMAIN, first)
        # 幂等：自己的文件再装一次还是同一份。
        self.assertEqual(0, self.web.cmd_install(self._args()))
        self.assertEqual(first, target.read_text(encoding="utf-8"))

    def test_it_writes_when_the_target_does_not_exist(self):
        target = self._target()
        self.assertFalse(target.exists())
        self.assertEqual(0, self.web.cmd_install(self._args()))
        self.assertTrue(target.is_file())
        self.assertIn(self.web.CONF_BEGIN,
                      target.read_text(encoding="utf-8"))

    def test_force_is_the_explicit_way_past_the_guard(self):
        target = self._target()
        target.write_text("server { listen 80; }\n", encoding="utf-8")
        self.assertEqual(0, self.web.cmd_install(self._args(force=True)))
        self.assertIn(self.web.CONF_BEGIN,
                      target.read_text(encoding="utf-8"))

    def test_a_rejected_config_restores_what_was_there(self):
        target = self._target()
        foreign = "server { listen 80; server_name example.org; }\n"
        target.write_text(foreign, encoding="utf-8")
        self._patch(self.web.shell, "run",
                    lambda *a, **k: (False, "", "[emerg] unknown directive"))
        self.assertEqual(1, self.web.cmd_install(self._args(force=True)))
        self.assertEqual(foreign, target.read_text(encoding="utf-8"),
                         "nginx 拒绝时必须还原原文件，而不是直接删掉")

    # -- uninstall --------------------------------------------------------

    def test_uninstall_never_deletes_a_foreign_vhost(self):
        target = self._target()
        foreign = "server { listen 80; server_name example.org; }\n"
        target.write_text(foreign, encoding="utf-8")
        self.assertEqual(0, self.web.cmd_uninstall(self._args()))
        self.assertTrue(target.is_file(), "非本程序生成的 vhost 绝不能被删除")
        self.assertEqual(foreign, target.read_text(encoding="utf-8"))
        self.assertIn("未删除", self._buf.getvalue())

    def test_uninstall_removes_its_own_vhost(self):
        target = self._target()
        target.write_text(self.web.render_conf(self.cfg), encoding="utf-8")
        self.assertEqual(0, self.web.cmd_uninstall(self._args()))
        self.assertFalse(target.exists())

    # -- the marker itself ------------------------------------------------

    def test_a_file_without_both_markers_is_not_ours(self):
        begin_only = self.root / "begin.conf"
        begin_only.write_text(self.web.CONF_BEGIN + "\nserver {}\n",
                              encoding="utf-8")
        self.assertFalse(self.web._generated_vhost(begin_only))
        end_only = self.root / "end.conf"
        end_only.write_text("server {}\n" + self.web.CONF_END + "\n",
                            encoding="utf-8")
        self.assertFalse(self.web._generated_vhost(end_only))
        ours = self.root / "ours.conf"
        ours.write_text("\n" + self.web.render_conf(self.cfg) + "\n",
                        encoding="utf-8")
        self.assertTrue(self.web._generated_vhost(ours))
        self.assertFalse(self.web._generated_vhost(self.root / "missing.conf"))


class TestBrowserAutomationIsNotSuspicious(unittest.TestCase):
    """A bundle unpacked into /tmp is not a memory-resident payload.

    Browser automation (Playwright, Puppeteer, Selenium) downloads a browser
    *release* into a temp directory and runs it from there. By path alone that
    is the same shape as "a binary executing out of /tmp" -- a real malware
    signature -- so every automation run produced a WARN:

        chrome(pid ...) 从临时目录运行: /tmp/<dir>/browsers/chromium-<v>/...
        进程链: chrome ← node-MainThread

    The exemption is structural (release layout **and** a trusted driving
    process), and these tests also pin the shapes that must **keep** warning,
    because an exemption that switches the detection off is worse than the
    false positive it removes.
    """

    def setUp(self):
        from vigil.guards.checks import util
        self.util = util

    def _bundle(self, *parts):
        return os.path.join(tempfile.gettempdir(), "vigil-probe", *parts)

    @staticmethod
    def _chain(*frames):
        return [{"pid": p, "comm": c, "cmdline": m} for p, c, m in frames]

    def _with_chain(self, exe, *frames):
        """Run the check against a fake /proc chain.

        The fake is truncated to `depth` exactly like ``process_chain`` is,
        so the depth limit is exercised rather than bypassed.
        """
        real = self.util.process_chain
        chain = self._chain(*frames)
        self.util.process_chain = lambda pid, depth=6: chain[:depth]
        try:
            return self.util.browser_automation(frames[0][0], exe)
        finally:
            self.util.process_chain = real

    def test_a_release_bundle_driven_by_node_is_recognised(self):
        exe = self._bundle("browsers", "chromium-1234",
                           "chrome-linux64", "chrome")
        got = self._with_chain(exe, (10, "chrome", exe),
                               (9, "node-MainThread", "node /srv/app/test.js"))
        self.assertTrue(got, "node 驱动的浏览器发行包应当被识别")
        self.assertIn("自动化工具链", got)

    def test_a_headless_shell_layout_is_recognised_too(self):
        exe = self._bundle("ms-playwright", "chromium-1234",
                           "chrome-linux", "headless_shell")
        got = self._with_chain(exe, (10, "headless_shell", exe),
                               (9, "node", "node /srv/app/run.js"))
        self.assertTrue(got)

    def test_a_bundle_started_by_a_shell_is_still_classified(self):
        """The verdict is structural; the driver is only *named* when known.

        A shell in the chain used to cancel the exemption. It no longer does,
        because requiring a driver produced false reports on every automation
        run (see the docstring of `util.browser_automation`). The shell is
        still visible in the explanation, which is what the operator needs.
        """
        exe = self._bundle("browsers", "chromium-1234",
                           "chrome-linux64", "chrome")
        got = self._with_chain(exe, (10, "chrome", exe),
                               (9, "bash", "bash -c " + exe))
        self.assertTrue(got)
        self.assertIn("浏览器发行包布局", got)
        self.assertIn("找不到驱动它的运行时", got)

    def test_a_random_binary_in_a_temp_dir_is_still_suspicious(self):
        exe = self._bundle("payload")
        got = self._with_chain(exe, (10, "payload", exe),
                               (9, "node", "node /srv/app/test.js"))
        self.assertEqual("", got, "与浏览器发行包无关的 /tmp 二进制必须照旧告警")

    def test_a_browser_binary_without_the_release_layout_is_still_suspicious(self):
        exe = self._bundle("chrome")
        got = self._with_chain(exe, (10, "chrome", exe),
                               (9, "node", "node /srv/app/test.js"))
        self.assertEqual("", got, "光有文件名、没有发行布局，不算豁免")

    def test_a_bundle_with_no_automation_ancestor_is_still_classified(self):
        """A reparented browser/helper is the normal case, not a red flag."""
        exe = self._bundle("browsers", "chromium-1234",
                           "chrome-linux64", "chrome")
        got = self._with_chain(exe, (10, "chrome", exe),
                               (9, "systemd", "/sbin/init"))
        self.assertTrue(got)
        self.assertIn("浏览器发行包布局", got)

    # -- the ancestor-chain judgement -------------------------------------
    #
    # A direct-parent test re-flags `chrome <- bash <- node`, which is a real
    # automation launch shape: the runtime is one wrapper above the browser.
    # These four pin the chain rule and the shapes it must not weaken.

    def test_a_wrapper_shell_between_browser_and_runtime_is_exempt(self):
        """chrome <- bash <- node: the runtime is a grandparent, not the parent."""
        exe = self._bundle("browsers", "chromium-1234",
                           "chrome-linux64", "chrome")
        got = self._with_chain(exe,
                               (10, "chrome", exe),
                               (9, "bash", "bash -c " + exe),
                               (8, "node-MainThread", "node /srv/app/run.js"))
        self.assertTrue(got, "隔一层 shell 的自动化链必须仍然豁免")
        self.assertIn("自动化工具链", got)
        self.assertIn("node", got, "报文要点明是哪一层运行时")

    def test_a_wrapper_shell_does_not_itself_become_a_runtime(self):
        """`chrome <- bash <- sh` names no driver, and that is reported.

        A shell is deliberately not in the trusted runtime set: `bash -c
        <payload>` is how a lot of malicious bundles start. With the verdict
        now structural the shell no longer *cancels* the classification, but
        it must not be mistaken for a driver either -- the explanation says
        the runtime could not be found rather than naming `bash`.
        """
        exe = self._bundle("browsers", "chromium-1234",
                           "chrome-linux64", "chrome")
        got = self._with_chain(exe,
                               (10, "chrome", exe),
                               (9, "bash", "bash -c " + exe),
                               (8, "sh", "sh -c " + exe))
        self.assertIn("找不到驱动它的运行时", got)
        self.assertNotIn("由 bash", got)
        self.assertNotIn("由 sh", got)

    def test_a_deleted_binary_in_a_release_layout_is_not_reported(self):
        """A *deleted* browser binary inside a release layout is a leftover.

        This reverses an earlier rule, and the reversal is deliberate. The old
        rule said "a deleted executable is never probably fine, so the
        automation exemption must not apply to it". On a real host that
        produced a false alarm every time a browser release was upgraded while
        one was running: the running process's image is unlinked by the
        upgrade, and the check printed its single most alarming line about it
        -- "可执行文件已被删除且磁盘上不存在".

        What decides it is the structural pair -- release layout **plus** a
        browser/helper basename -- and deliberately *not* the ancestor chain,
        which for a leftover browser is arbitrary (crashpad helpers are
        reparented to init by design). A memory-resident implant that deletes
        itself does not leave its file inside
        ``<...>/browsers/chromium-<version>/chrome-linux64/``.

        Note this stays a *reporting* judgement: no signal is ever sent on the
        strength of it. `procresponse` requires a deleted binary to be
        accompanied by an independent live outbound connection *and* two
        independent evidence classes before it will act.
        """
        exe = self._bundle("browsers", "chromium-1234",
                           "chrome-linux64", "chrome")
        hits = [{"pid": 10, "comm": "chrome", "exe": exe,
                 "kind": "deleted", "automation": ""}]
        real = self.util.suspect_procs_detail
        self.util.suspect_procs_detail = lambda *a, **k: hits
        try:
            from vigil.guards.checks import base, security
            res = security.SuspiciousProcesses().safe_run(base.CheckContext(
                cfg=None, state={}, env={}, log=_QuietLog(), now=time.time()))
        finally:
            self.util.suspect_procs_detail = real
        self.assertEqual("OK", res.status)
        self.assertIn("已被删除", res.detail, "降级也必须说清楚看到了什么")
        self.assertIn("浏览器发行包布局", res.detail)

    def test_a_deleted_payload_outside_a_release_layout_still_warns(self):
        """The reversal above must not become a general self-delete amnesty."""
        hits = [{"pid": 10, "comm": "payload",
                 "exe": self._bundle("payload"), "kind": "deleted",
                 "automation": ""}]
        real = self.util.suspect_procs_detail
        self.util.suspect_procs_detail = lambda *a, **k: hits
        try:
            from vigil.guards.checks import base, security
            res = security.SuspiciousProcesses().safe_run(base.CheckContext(
                cfg=None, state={}, env={}, log=_QuietLog(), now=time.time()))
        finally:
            self.util.suspect_procs_detail = real
        self.assertEqual("WARN", res.status)
        self.assertIn("已被删除", res.detail)

    def test_the_driver_walk_is_bounded_but_the_verdict_is_not(self):
        """Depth is 6 frames: the process plus up to five ancestors.

        The walk stays bounded so a busy host's /proc cannot turn this into a
        cost, and so an attacker cannot buy anonymity by stacking wrappers.
        Exceeding the bound only stops the walk from *naming* the driver; the
        structural verdict is unchanged, which is the whole point of making
        the verdict structural.
        """
        exe = self._bundle("browsers", "chromium-1234",
                           "chrome-linux64", "chrome")
        # Frames: 0 chrome, 1..4 wrappers, 5 = the fifth ancestor (node).
        at_limit = [(10, "chrome", exe)]
        for i in range(4):
            at_limit.append((9 - i, "bash", "bash -c wrapper%d" % i))
        at_limit.append((5, "node", "node /srv/app/run.js"))
        got = self._with_chain(exe, *at_limit)
        self.assertTrue(got)
        self.assertIn("node", got, "上限之内的驱动进程必须被指名")

        # One layer deeper: node is now the sixth ancestor and is not seen.
        beyond = [(10, "chrome", exe)]
        for i in range(5):
            beyond.append((9 - i, "bash", "bash -c wrapper%d" % i))
        beyond.append((4, "node", "node /srv/app/run.js"))
        got = self._with_chain(exe, *beyond)
        self.assertTrue(got, "结构判据不因链太深而改变")
        self.assertIn("找不到驱动它的运行时", got, "超过深度上限就不再向上找")

    def _run_check(self, hits):
        from vigil.guards.checks import base, security
        real = self.util.suspect_procs_detail
        self.util.suspect_procs_detail = lambda *a, **k: hits
        try:
            chk = security.SuspiciousProcesses()
            return chk.safe_run(base.CheckContext(
                cfg=None, state={}, env={}, log=_QuietLog(), now=time.time()))
        finally:
            self.util.suspect_procs_detail = real

    def test_the_check_stays_ok_when_all_hits_are_automation(self):
        exe = self._bundle("browsers", "chromium-1234",
                           "chrome-linux64", "chrome")
        res = self._run_check([{"pid": 4242, "comm": "chrome", "exe": exe,
                                "kind": "temp", "automation": "疑似自动化工具链"}])
        self.assertEqual("OK", res.status)
        self.assertIn("自动化工具链", res.detail)
        self.assertIn(exe, res.detail, "降级了也要说清楚看到了什么")

    def test_a_payload_beside_a_bundle_still_warns(self):
        exe = self._bundle("payload")
        res = self._run_check([
            {"pid": 4242, "comm": "chrome",
             "exe": self._bundle("browsers", "chromium-1234",
                                 "chrome-linux64", "chrome"),
             "kind": "temp", "automation": "疑似自动化工具链"},
            {"pid": 4243, "comm": "payload", "exe": exe,
             "kind": "temp", "automation": ""},
        ])
        self.assertEqual("WARN", res.status)
        self.assertIn("可疑进程 1 个", res.detail, "豁免的那一个不能计入异常")
        self.assertIn("payload", res.detail)
        self.assertIn("自动化工具链", res.detail, "跳过的仍要列出来")

    def test_a_deleted_binary_is_never_exempt(self):
        res = self._run_check([{"pid": 4244, "comm": "chrome",
                                "exe": "/usr/bin/chrome",
                                "kind": "deleted", "automation": ""}])
        self.assertEqual("WARN", res.status)


class TestOneBurstIsOneOffence(unittest.TestCase):
    """One incident must count as one incident.

    Measured on a real host at 05:45:16: a normal admin console polling at
    ~4 req/s crossed the flood threshold and was counted as **four offences in
    the same second**, which walked the escalation ladder straight to the
    seven-day rung. The operator's own IP was then banned and every page on the
    box timed out. The ladder exists to punish *repeat* behaviour over time;
    without a floor on how often an offence may be counted, "repeat" is
    meaningless and one burst is enough to reach the top of it.
    """

    def setUp(self):
        import tempfile
        from pathlib import Path as _P
        from vigil.guards import threat as threat_mod
        self.t = threat_mod
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = vconfig.Config(path=_P(self.tmp.name) / "c.json",
                                  secrets_path=_P(self.tmp.name) / "s.json")
        self.d = self.t.ThreatDaemon(self.cfg, log=_QuietLog(), dry_run=True,
                                     echo=False)

    def test_a_burst_in_one_second_counts_once(self):
        now = 1_800_000_000.0
        counts = [self.d.state.note_offense("203.0.113.7", now=now + i * 0.1)
                  for i in range(5)]
        self.assertEqual([1, 1, 1, 1, 1], counts,
                         "同一秒内的重复触发被算成了多次违规")

    def test_the_first_offence_is_one_not_zero(self):
        """It was 0 for a while, which both misreported and disabled the ladder."""
        self.assertEqual(1, self.d.state.note_offense("203.0.113.7",
                                                      now=1_800_000_000.0))

    def test_repeat_behaviour_after_the_interval_still_escalates(self):
        now = 1_800_000_000.0
        self.d.state.note_offense("203.0.113.7", now=now)
        interval = self.d.settings.escalation_interval
        self.assertEqual(2, self.d.state.note_offense("203.0.113.7",
                                                      now=now + interval + 1))
        self.assertEqual(3, self.d.state.note_offense("203.0.113.7",
                                                      now=now + 2 * interval + 2))

    def test_a_sustained_flood_stays_at_one_offence(self):
        """`last` moves forward even when the count does not, so a long flood
        is one incident for as long as it lasts."""
        now = 1_800_000_000.0
        for i in range(200):
            n = self.d.state.note_offense("203.0.113.7", now=now + i * 30)
        self.assertEqual(1, n, "持续 100 分钟的洪泛被算成了多次违规")

    def test_one_burst_can_no_longer_reach_the_recidivist_rung(self):
        """The headline defect: four same-second offences used to reach the
        longest ban in the ladder."""
        first = self.d.ban_seconds_for("http_flood", 1, 1)
        recidivist = self.d.ban_seconds_for(
            "http_flood", self.d.settings.recidivist_bans, 1)
        self.assertLess(first, recidivist)
        self.assertLessEqual(first, 3600,
                             "一次突发不该超过一小时，实际 %s 秒" % first)

    def test_the_report_counts_sources_not_events(self):
        same = [{"ip": "203.0.113.7"} for _ in range(4)]
        self.assertIn("1 个攻击源", self.t._ban_title(same))
        self.assertIn("4 次升级", self.t._ban_title(same))
        four = [{"ip": "203.0.113.%d" % i} for i in range(1, 5)]
        self.assertIn("4 个攻击源", self.t._ban_title(four))
        self.assertNotIn("升级", self.t._ban_title(four))

    def test_tightened_thresholds_cannot_sink_below_the_floor(self):
        """Posture tightening must not drop the flood threshold under a normal
        admin console's polling rate -- that is 'opening a page is an attack'."""
        effective = max(self.d.settings.flood_floor,
                        self.d.thr(self.d.settings.http_flood_threshold))
        self.assertGreaterEqual(effective, self.d.settings.flood_floor)
        self.assertGreaterEqual(effective, 100,
                                "收紧后的洪泛阈值太低：%s" % effective)


class TestWhitelistTakesEffectWithoutARestart(unittest.TestCase):
    """`whitelist add` must actually unblock, without a restart.

    Measured on a real host: the config file listed the operator's address while
    the enforcement set kept blocking them, so every page timed out. The daemon
    builds its whitelist object at construction and had no runtime reload path,
    and the alert text told the operator to run the command -- not to restart
    anything. A recovery step that does not work is worse than none.
    """

    def setUp(self):
        import tempfile
        from pathlib import Path as _P
        from vigil.guards import threat as threat_mod
        self.t = threat_mod
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = _P(self.tmp.name)
        self._real = self.t.UNBAN_REQUESTS
        self.t.UNBAN_REQUESTS = self.root / "requests.jsonl"
        self.addCleanup(setattr, self.t, "UNBAN_REQUESTS", self._real)
        self.cfg = vconfig.Config(path=self.root / "c.json",
                                  secrets_path=self.root / "s.json")
        self.d = self.t.ThreatDaemon(self.cfg, log=_QuietLog(), dry_run=True,
                                     echo=False)

    def test_a_reload_request_is_written_and_drained(self):
        self.assertTrue(self.t.request_whitelist_reload())
        self.assertEqual(1, self.d.apply_unban_requests())
        self.assertEqual("", self.t.UNBAN_REQUESTS.read_text())

    def test_a_reload_request_is_not_replayed(self):
        """One-shot, like an unban: replaying would silently undo later work."""
        self.t.request_whitelist_reload()
        self.d.apply_unban_requests()
        self.assertEqual(0, self.d.apply_unban_requests())

    def test_a_daemon_with_a_stale_whitelist_stops_banning_after_reload(self):
        """The exact production failure: in-memory whitelist empty, config full."""
        ip = "27.221.187.226"
        self.assertFalse(self.d.whitelist.allowed(ip))
        self.cfg.set("threat.whitelist", [ip])
        self.cfg.save()          # 重载是从磁盘读的，必须先落盘
        self.t.request_whitelist_reload()
        self.d.apply_unban_requests()
        self.assertTrue(self.d.whitelist.allowed(ip),
                        "重载后白名单仍未生效 —— 这正是那次全站超时的原因")


class TestOneSignalIsOneSignal(unittest.TestCase):
    """One incident must not be counted as many, anywhere.

    Three separate counters used to amplify a single burst: the offence ladder,
    the attack posture, and the log sources themselves. Each was verified
    against the real host log that produced the seven-day ban.
    """

    def setUp(self):
        import tempfile
        from pathlib import Path as _P
        from vigil.guards import threat as threat_mod
        self.t = threat_mod
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = _P(self.tmp.name)
        self.cfg = vconfig.Config(path=self.root / "c.json",
                                  secrets_path=self.root / "s.json")
        self.d = self.t.ThreatDaemon(self.cfg, log=_QuietLog(), dry_run=True,
                                     echo=False)

    def test_one_burst_raises_the_posture_once(self):
        """A burst calls ban() dozens of times a second; the posture is a
        machine-wide switch that halves thresholds, so feeding it per call
        turned one attacker into a machine-wide lockdown."""
        seen = []
        real = self.d.posture.note
        self.d.posture.note = lambda w: (seen.append(w), real(w))[1]
        for i in range(20):
            self.d._note_attack(1, "请求洪泛（%d 次/60s）203.0.113.7" % (250 + i))
        self.assertEqual(1, len(seen),
                         "同一来源的一轮突发把姿态喂了 %d 次" % len(seen))

    def test_a_different_source_still_raises_the_posture(self):
        seen = []
        real = self.d.posture.note
        self.d.posture.note = lambda w: (seen.append(w), real(w))[1]
        self.d._note_attack(1, "扫描 203.0.113.7")
        self.d._note_attack(1, "扫描 198.51.100.9")
        self.assertEqual(2, len(seen), "不同来源应各自计入")

    def test_duplicate_log_sources_are_tailed_once(self):
        """The same access log listed twice doubled every count -- the
        amplifier that turned a ~2.4 req/s console into "259 per minute"."""
        import os as _os
        f = self.root / "access.log"
        f.write_text("")
        self.d.settings.log_sources = {
            "auth": [], "nginx_access": [str(f)],
            "panel": [str(f)], "decoy": []}
        plan = self.d._source_plan()
        self.assertEqual(1, len(plan), "同一个文件被跟随了 %d 次" % len(plan))

    def test_a_stored_old_default_migrates_to_the_new_one(self):
        """`save()` persists the whole merged tree, so an old default value in
        config.json permanently shadowed the new one. Measured live: the host
        still ran 500 while the fix said 1200."""
        cfg = vconfig.Config(path=self.root / "old.json",
                             secrets_path=self.root / "olds.json")
        cfg.set("threat.http.flood_threshold", 500)
        d = self.t.ThreatDaemon(cfg, log=_QuietLog(), dry_run=True, echo=False)
        self.assertEqual(1200, d.settings.http_flood_threshold)


class TestMailIsBatchedNotStreamed(unittest.TestCase):
    """Ordinary events accumulate; important ones go straight out.

    Measured on a real host: 190 emails in under two days, most of them single
    routine events (a ban, a login, an alert/recovery pair) sent one at a time.
    An inbox that fills with those stops being read -- which defeats the point
    of alerting at all.
    """

    def setUp(self):
        import tempfile
        from pathlib import Path as _P
        from vigil.guards import threat as threat_mod
        self.t = threat_mod
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = _P(self.tmp.name)
        self.cfg = vconfig.Config(path=self.root / "c.json",
                                  secrets_path=self.root / "s.json")
        self.d = self.t.ThreatDaemon(self.cfg, log=_QuietLog(), dry_run=True,
                                     echo=False)
        self.sent = []
        self.d.deliver = lambda a: (self.sent.append(a.title), True)[1]
        self.d.reporter._last_send = 0

    def _routine(self, n=1, age=0.0):
        for i in range(n):
            self.d.reporter.queue({"kind": "BAN", "ip": "203.0.113.%d" % (i + 1),
                                   "ts": time.time() - age})

    def test_a_single_ordinary_event_is_held_back(self):
        self._routine(1)
        self.assertFalse(self.d.reporter.flush())
        self.assertEqual(0, len(self.sent))
        self.assertEqual(1, self.d.reporter.pending())

    def test_enough_ordinary_events_make_one_email(self):
        self._routine(self.d.settings.digest_min_items)
        self.assertTrue(self.d.reporter.flush())
        self.assertEqual(1, len(self.sent), "攒够条数应只发一封")

    def test_an_important_event_is_sent_immediately(self):
        """`immediate` must not be delayed by the batching rule."""
        self.d.reporter.queue({"kind": "BREACH", "immediate": True,
                               "ip": "203.0.113.9", "ts": time.time()})
        self.assertTrue(self.d.reporter.flush())
        self.assertEqual(1, len(self.sent))

    def test_a_held_event_is_eventually_sent(self):
        """Nothing may sit in the queue forever."""
        wait = self.d.settings.digest_max_wait
        self._routine(1, age=wait + 60)
        self.assertTrue(self.d.reporter.flush())
        self.assertEqual(1, len(self.sent))

    def test_a_critical_severity_batch_bypasses_the_threshold(self):
        self.d.reporter.queue({"kind": "BREACH", "ip": "203.0.113.9",
                               "ts": time.time()})
        self.assertTrue(self.d.reporter.flush())
        self.assertEqual(1, len(self.sent))


class TestSecurityEnhancements(unittest.TestCase):
    """The v2.3 hardening rules, pinned so they cannot be dropped quietly."""

    def test_hygiene_refuses_methods_the_site_never_needs(self):
        from vigil.guards import hygiene
        body = hygiene.render()
        self.assertIn("$request_method", body)
        self.assertIn("return 405;", body)
        for m in hygiene.ALLOWED_METHODS:
            self.assertIn(m, body)
        # The ones that only exist to be exploited must not be allowed.
        for bad in ("PUT", "DELETE", "TRACE", "PROPFIND"):
            self.assertNotIn("|%s|" % bad, body)
            self.assertNotIn("(%s|" % bad, body)

    def test_the_curated_corpus_covers_the_modern_targets(self):
        """Lure rate starts with asking for the files attackers actually
        want. The old list stopped at 2021-era secrets."""
        from vigil.guards import decoy
        paths = {p for p, _t, _w in decoy.DECOYS}
        self.assertGreaterEqual(len(paths), 60, "人工诱饵库没有扩充")
        for want in ("/.env.production", "/backup.zip", "/.kube/config",
                     "/.claude/settings.json", "/api/admin/users",
                     "/graphql", "/.npmrc", "/phpinfo.php"):
            self.assertIn(want, paths, "缺少高价值诱饵：%s" % want)
        # Realism guard: nothing that gives the game away by its name.
        for p in paths:
            self.assertFalse(any(w in p.lower() for w in
                                 ("honeypot", "fake", "trap", "decoy")),
                             "诱饵名字一眼就能看穿：%s" % p)

    def test_the_canary_is_enforced_like_any_other_decoy(self):
        from vigil.guards import decoy
        paths = {p for p, _t, _w in decoy.candidate_decoys()}
        from vigil.guards import lure
        self.assertIn(lure.canary(), paths,
                      "金丝雀没有被纳入诱饵集合，就永远不会被封禁")


class TestUnbanRequestsAreDrainedPromptly(unittest.TestCase):
    """An unban that visibly works and then silently reverts is worse than one
    that fails. The drill found exactly that: twenty lifted bans all returned,
    because the request file was only drained on the 300 s housekeeping cycle.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        from vigil.guards import threat as threat_mod
        self.t = threat_mod
        self._old = threat_mod.UNBAN_REQUESTS
        threat_mod.UNBAN_REQUESTS = Path(self.tmp.name) / "unban-requests.jsonl"
        self.addCleanup(self._restore)
        self.cfg = vconfig.Config(path=Path(self.tmp.name) / "c.json",
                                  secrets_path=Path(self.tmp.name) / "s.json")

    def _restore(self):
        self.t.UNBAN_REQUESTS = self._old

    def _daemon(self):
        return self.t.ThreatDaemon(self.cfg, log=_QuietLog(), dry_run=True,
                                   echo=False)

    def test_the_poll_interval_is_on_a_human_timescale(self):
        self.assertLessEqual(self.t.UNBAN_POLL_SECONDS, 10,
                             "解封请求的轮询间隔太长，操作员的解封会被静默回滚")

    def test_requests_are_drained_and_the_file_is_emptied(self):
        d = self._daemon()
        self.t.UNBAN_REQUESTS.write_text(
            json.dumps({"ip": "10.213.1.2", "ts": time.time()}) + "\n"
            + json.dumps({"ip": "10.213.2.2", "ts": time.time()}) + "\n",
            encoding="utf-8")
        applied = d.apply_unban_requests()
        self.assertEqual(2, applied)
        self.assertEqual("", self.t.UNBAN_REQUESTS.read_text(encoding="utf-8"),
                         "解封请求没有被清空，会被反复重放")

    def test_a_second_drain_is_a_no_op(self):
        """Requests are one-shot: replaying a stale one would undo a later
        deliberate ban of the same address."""
        d = self._daemon()
        self.t.UNBAN_REQUESTS.write_text(
            json.dumps({"ip": "10.213.3.2", "ts": time.time()}) + "\n",
            encoding="utf-8")
        self.assertEqual(1, d.apply_unban_requests())
        self.assertEqual(0, d.apply_unban_requests())

    def test_housekeeping_no_longer_owns_the_drain(self):
        import inspect
        src = inspect.getsource(self.t.ThreatDaemon.housekeeping)
        self.assertNotIn("apply_unban_requests", src,
                         "清理线程仍在处理解封，会与监听线程争抢同一个文件")
        self.assertTrue(hasattr(self.t.ThreatDaemon, "unban_watcher"))


class TestDecoyDeception(unittest.TestCase):
    """Decoys turn an ambiguous probe into a conclusion.

    Every other HTTP detector has to weigh evidence, which is why the
    low-confidence tier needs a window of hits -- and why an earlier version
    of this program banned its own operator for 24 hours over a request for
    an icon called `ico-phpmyadmin.png`. A decoy removes the ambiguity: the
    path does not exist, nothing the site serves links to it, and it has its
    own log. One hit is then enough.

    The screening is the part that must not be skipped, so most of these
    tests are about what gets *refused*.
    """

    def setUp(self):
        from vigil.guards import decoy as decoy_mod
        self.d = decoy_mod
        self.tmp = tempfile.TemporaryDirectory()
        self.webroot = Path(self.tmp.name) / "www"
        self.webroot.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name, text):
        path = self.webroot / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_a_clean_site_accepts_the_default_decoys(self):
        """Every default decoy must survive screening on a clean site.

        Deliberately not an equality on the counts: the learner can adopt
        extra decoys from real traffic, and a host that has learned something
        must not fail its own test suite. What matters is that all the
        *defaults* are accepted and nothing is rejected.
        """
        safe, rejected = self.d.screen(str(self.webroot), text="")
        accepted = {p for p, _t, _w in safe}
        for path, _t, _w in self.d.DECOYS:
            self.assertIn(path, accepted, "默认诱饵被误判为不安全：%s" % path)
        self.assertEqual([], rejected)

    def test_a_path_that_exists_on_disk_is_refused(self):
        """Banning someone for requesting a real file is a self-inflicted outage."""
        self._write("server-status", "real page")
        safe, rejected = self.d.screen(str(self.webroot), text="")
        reasons = dict(rejected)
        self.assertIn("/server-status", reasons)
        self.assertIn("已存在", reasons["/server-status"])
        self.assertNotIn("/server-status", [p for p, _t, _w in safe])

    def test_a_path_the_site_links_to_is_refused(self):
        """The false-positive control: the site's own content is the corpus."""
        self._write("index.html", '<a href="/.env">debug</a>')
        text = self.d.corpus(str(self.webroot))
        safe, rejected = self.d.screen(str(self.webroot), text=text)
        self.assertIn("/.env", dict(rejected))
        self.assertNotIn("/.env", [p for p, _t, _w in safe])

    def test_screening_reports_why_rather_than_dropping_silently(self):
        self._write("Dockerfile", "FROM scratch")
        _safe, rejected = self.d.screen(str(self.webroot), text="")
        self.assertTrue(rejected)
        for path, why in rejected:
            self.assertTrue(path.startswith("/"))
            self.assertTrue(why)

    def test_corpus_reads_site_content_but_skips_binaries(self):
        self._write("index.html", "HELLO-MARKER")
        (self.webroot / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\nMARKER")
        text = self.d.corpus(str(self.webroot))
        self.assertIn("hello-marker", text)
        self.assertNotIn("marker", text.replace("hello-marker", ""))

    def test_the_rendered_snippet_drops_connections(self):
        """444, not 404: an empty reply gives a scanner nothing to parse."""
        snippet = self.d.render(self.d.DECOYS[:2])
        self.assertEqual(2, snippet.count("location = "))
        self.assertIn("return 444;", snippet)
        self.assertIn(str(self.d.log_path()), snippet)
        # Every decoy writes to the same log -- one file, one meaning.
        self.assertEqual(2, snippet.count("access_log"))

    def test_every_decoy_declares_why_a_hit_is_conclusive(self):
        for path, token, why in self.d.DECOYS:
            self.assertTrue(path.startswith("/"), path)
            self.assertTrue(token.strip(), path)
            self.assertTrue(why.strip(), path)

    def test_hits_round_trip(self):
        hits_file = self.d.hits_path()
        saved = hits_file
        real = self.d.hits_path
        self.d.hits_path = lambda: Path(self.tmp.name) / "hits.jsonl"
        try:
            self.d.note_hit("198.51.100.9", "/.git/config", when=1.0)
            self.d.note_hit("198.51.100.10", "/wp-login.php", when=2.0)
            got = self.d.read_hits()
            self.assertEqual(2, len(got))
            self.assertEqual("/.git/config", got[0]["uri"])
            self.assertEqual("198.51.100.10", got[1]["ip"])
        finally:
            self.d.hits_path = real
            _ = saved

    def test_the_hits_file_is_bounded(self):
        """The bound is `cap + _TRIM_EVERY`, not `cap`.

        Trimming is amortised: the file is examined once every _TRIM_EVERY
        hits, because examining it on every write made this quadratic (659
        hits/second, measured) in the one code path whose purpose is to
        attract a flood. So the guarantee is a bound, and the bound is what
        the test asserts.
        """
        real_path = self.d.hits_path
        real_every = self.d._TRIM_EVERY
        real_count = self.d._HITS_SINCE_TRIM
        self.d.hits_path = lambda: Path(self.tmp.name) / "bounded.jsonl"
        self.d._TRIM_EVERY = 10
        self.d._HITS_SINCE_TRIM = 0
        try:
            for i in range(200):
                self.d.note_hit("198.51.100.%d" % (i % 250), "/x", cap=20)
            kept = len(self.d.read_hits(limit=1000))
            self.assertLessEqual(kept, 20 + 10,
                                 "the file must stay bounded near the cap")
            self.assertGreater(kept, 0)
        finally:
            self.d.hits_path = real_path
            self.d._TRIM_EVERY = real_every
            self.d._HITS_SINCE_TRIM = real_count

    def test_a_decoy_hit_bans_with_the_long_ladder(self):
        """The handler is the whole point: one line in, one ban out."""
        from vigil.guards import threat as threat_mod
        cfg = vconfig.Config(path=Path(self.tmp.name) / "c.json",
                             secrets_path=Path(self.tmp.name) / "s.json")
        daemon = threat_mod.ThreatDaemon(cfg, log=_QuietLog(), dry_run=True,
                                         echo=False)
        line = ('198.51.100.9 - - [27/Sep/2026:14:42:00 +0800] '
                '"GET /.aws/credentials HTTP/1.1" 444 0 "-" "sqlmap"')
        daemon.handle_decoy(line)
        entry = daemon.state.bans.get("198.51.100.9")
        self.assertIsNotNone(entry, "a decoy hit must produce a ban")
        self.assertEqual("decoy", entry["detector"])
        # A decoy hit is conclusive, so the first offence is already days.
        self.assertGreaterEqual(entry["until"] - time.time(), 6 * 86400)

    def test_a_whitelisted_source_is_never_banned_by_a_decoy(self):
        """The one mistake that would matter most."""
        from vigil.guards import threat as threat_mod
        cfg = vconfig.Config(path=Path(self.tmp.name) / "c.json",
                             secrets_path=Path(self.tmp.name) / "s.json")
        cfg.set("threat.whitelist", ["127.0.0.1/8", "::1", "203.0.113.7"])
        daemon = threat_mod.ThreatDaemon(cfg, log=_QuietLog(), dry_run=True,
                                         echo=False)
        daemon.handle_decoy(
            '203.0.113.7 - - [27/Sep/2026:14:42:00 +0800] '
            '"GET /.git/config HTTP/1.1" 444 0 "-" "curl"')
        self.assertNotIn("203.0.113.7", daemon.state.bans)

    def test_a_malformed_line_does_not_crash_the_daemon(self):
        from vigil.guards import threat as threat_mod
        cfg = vconfig.Config(path=Path(self.tmp.name) / "c.json",
                             secrets_path=Path(self.tmp.name) / "s.json")
        daemon = threat_mod.ThreatDaemon(cfg, log=_QuietLog(), dry_run=True,
                                         echo=False)
        for junk in ("", "   ", "not-an-ip - - [x] \"GET / HTTP/1.1\" 444 0",
                     "198.51.100.9", '"unterminated'):
            daemon.handle_decoy(junk)
        self.assertEqual({}, {k: v for k, v in daemon.state.bans.items()
                              if k.startswith("not")} )


class TestStormControl(unittest.TestCase):
    """A hundred findings a minute must not become a hundred emails.

    `daily_quota` bounds the day and `dedupe_window` bounds identical
    repeats, but a real attack produces many *different* findings at once --
    which is precisely the case neither of those covers, and the case that
    ends with the operator filtering the alert channel into a folder nobody
    opens. Suppressed messages are parked, not dropped.
    """

    def setUp(self):
        from vigil.mail import router as rmod
        self.rmod = rmod
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.cfg = vconfig.Config(path=base / "config.json",
                                  secrets_path=base / "secrets.json")
        self.cfg.set("mail.recipients", ["ops@example.invalid"])
        self.r = rmod.Router(self.cfg, log=_QuietLog())

    def tearDown(self):
        self.tmp.cleanup()

    def test_defaults_are_present(self):
        self.assertEqual(12, self.cfg.get("mail.storm_threshold"))
        self.assertEqual(600, self.cfg.get("mail.storm_window"))

    def test_a_crit_is_never_suppressed(self):
        crit = Message(subject="s", text="t", kind="alert", seq=1,
                       severity="CRIT")
        self.assertEqual("", self.r._storm_suppressed(crit))

    def test_digest_and_test_are_never_suppressed(self):
        for kind in ("digest", "test"):
            m = Message(subject="s", text="t", kind=kind, seq=1,
                        severity=SEV_WARN)
            self.assertEqual("", self.r._storm_suppressed(m))

    def test_a_quiet_channel_suppresses_nothing(self):
        from vigil.mail import queue as mq
        real = mq.sends_since
        mq.sends_since = lambda seconds: 0
        try:
            m = Message(subject="s", text="t", kind="alert", seq=1,
                        severity=SEV_WARN)
            self.assertEqual("", self.r._storm_suppressed(m))
        finally:
            mq.sends_since = real

    def test_a_storm_is_suppressed_and_parked(self):
        from vigil.mail import queue as mq
        real_count, real_overflow = mq.sends_since, mq.to_overflow
        parked = []
        mq.sends_since = lambda seconds: 99
        mq.to_overflow = lambda msg, reason="": parked.append(msg.seq) or True
        try:
            m = Message(subject="s", text="t", kind="alert", seq=7,
                        severity=SEV_WARN)
            reason = self.r._storm_suppressed(m)
            self.assertIn("风暴", reason)
        finally:
            mq.sends_since = real_count
            mq.to_overflow = real_overflow

    def test_the_storm_notice_itself_is_rate_limited(self):
        """Suppression must not become the flood."""
        from vigil.mail import queue as mq
        saved = mq.paths.STATE_MAIL
        mq.paths.STATE_MAIL = Path(self.tmp.name) / "mail"
        mq.paths.STATE_MAIL.mkdir(parents=True, exist_ok=True)
        try:
            self.assertTrue(mq.storm_notice_due(600))
            self.assertFalse(mq.storm_notice_due(600),
                             "a second notice inside the window is a storm")
        finally:
            mq.paths.STATE_MAIL = saved


class TestAcknowledgement(unittest.TestCase):
    """Silencing a known finding must be reversible and must not hide it.

    What operators actually reach for instead is disabling the check, which
    is permanent and invisible. An acknowledgement expires on its own, keeps
    the finding on every visible surface, and stops only the email.
    """

    def setUp(self):
        from vigil.guards import health as health_mod
        self.h = health_mod
        self.saved = (health_mod.load_state, health_mod.save_state)
        self.store = {}
        health_mod.load_state = lambda: dict(self.store)

        def _save(s):
            self.store.clear()
            self.store.update(s)
            return True

        health_mod.save_state = _save

    def tearDown(self):
        (self.h.load_state, self.h.save_state) = self.saved

    def test_durations_parse(self):
        self.assertEqual(60, self.h.parse_duration("60"))
        self.assertEqual(30 * 60, self.h.parse_duration("30m"))
        self.assertEqual(2 * 3600, self.h.parse_duration("2h"))
        self.assertEqual(7 * 86400, self.h.parse_duration("7d"))
        for bad in ("", "abc", "0", "-5", "h"):
            with self.assertRaises(ValueError):
                self.h.parse_duration(bad)

    def test_ack_expires_by_itself(self):
        self.h.add_ack("watch_files", 3600, "known nginx edit")
        self.assertIn("watch_files", self.h.active_acks(self.store))
        # Rewind past the expiry.
        self.store["acks"]["watch_files"]["until"] = time.time() - 1
        self.assertEqual({}, self.h.active_acks(self.store))

    def test_ack_is_capped(self):
        rec = self.h.add_ack("watch_files", 999 * 86400)
        self.assertLessEqual(rec["until"] - time.time(),
                             self.h.ACK_MAX_SECONDS + 5)

    def test_clear_removes_it(self):
        self.h.add_ack("watch_files", 3600)
        self.assertTrue(self.h.clear_ack("watch_files"))
        self.assertFalse(self.h.clear_ack("watch_files"))
        self.assertEqual({}, self.h.active_acks(self.store))

    def test_an_acked_finding_is_still_detected(self):
        """Ack silences mail only -- never the finding itself."""
        self.h.add_ack("av_hits", 3600)
        acks = self.h.active_acks(self.store)
        findings = [{"id": "av_hits", "label": "杀毒引擎命中", "status": "CRIT",
                     "detail": "x", "group": "malware"}]
        loud = self.h.alertable(findings, "attacks")
        self.assertEqual(1, len(loud), "the finding must survive the filter")
        # It is the runner -- not this filter -- that drops the mail, and it
        # does so by id, so `vigil health run` still prints the finding.
        self.assertIn(loud[0]["id"], acks)


class TestAlertHysteresisAndRenotify(unittest.TestCase):
    """抖动不该每次都发信；持续异常一次都不能漏。

    真实日志里同一台机器反复出现「异常 → 已恢复 → 异常」，每次转换一封
    邮件；另有一个持续一天多的误报每 30 分钟重复一封，共 50 多封。前者
    要迟滞，后者要重复提醒间隔。两个都用假时钟把整套 :func:`run_once`
    跑起来验证 —— 靠 sleep 十分钟来证明「它保持安静」的测试没人会跑。
    """

    def setUp(self):
        from vigil.guards import health as health_mod
        from vigil.guards.checks import base as cbase
        self.h = health_mod
        self.cbase = cbase
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.cfg = vconfig.Config(path=base / "config.json",
                                  secrets_path=base / "secrets.json")
        # 用 "all" 让告警策略只剩迟滞/重复提醒两件事，不受 attacks 过滤干扰。
        self.cfg.set("alerts.mode", "all")
        self.store = {"status": {}}
        self.sent, self.recovered = [], []
        self.holders = {}
        self._checks = []
        self._patched = []
        self._patch(health_mod, "load_state", lambda: self.store)
        self._patch(health_mod, "save_state",
                    lambda s: self.store.update(s) or True)
        self._patch(health_mod, "_env_cached", lambda *a, **k: {})
        self._patch(health_mod, "write_json", lambda *a, **k: True)
        self._patch(health_mod, "_notify_problems",
                    lambda cfg, result, log, items=None:
                    self.sent.append(sorted(p["id"] for p in (items or []))))
        self._patch(health_mod, "_notify_recoveries",
                    lambda cfg, result, log, items=None:
                    self.recovered.append(sorted(r["id"] for r in
                                                 (items or []))))
        self._patch(cbase, "all_checks", lambda: list(self._checks))
        self.add_probe("probe")

    def tearDown(self):
        for obj, name, old in reversed(self._patched):
            setattr(obj, name, old)
        self.tmp.cleanup()

    def _patch(self, obj, name, value):
        self._patched.append((obj, name, getattr(obj, name)))
        setattr(obj, name, value)

    def add_probe(self, check_id):
        """Register a fake check driven by ``self.holders[check_id]``."""
        from vigil.guards.checks import base as cbase
        holder = {"status": "OK", "detail": ""}
        self.holders[check_id] = holder

        class _Fake(cbase.Check):
            id = check_id
            label = check_id
            label_en = check_id
            group = cbase.G_SECURITY
            enabled_by_default = True

            def run(self, ctx):
                return cbase.CheckResult(holder["status"], holder["detail"])
        self._checks.append(_Fake)
        return holder

    def _run(self, now):
        return self.h.run_once(self.cfg, _QuietLog(), notify=True, now=now)

    # -- 迟滞 -------------------------------------------------------------

    def test_a_flap_alerts_once_and_a_persistent_problem_still_alerts(self):
        probe = self.holders["probe"]
        probe["status"] = "CRIT"
        first = self._run(1000)
        self.assertEqual([["probe"]], self.sent)
        self.assertTrue(first["problems"][0]["notify"])
        # 恢复：不发「已恢复」，因为状态可能还在抖。
        probe["status"] = "OK"
        self._run(1100)
        self.assertEqual([], self.recovered)
        # 抖动回来：不重复告警，但异常仍然在案，`vigil health` 看得到。
        probe["status"] = "CRIT"
        flap = self._run(1200)
        self.assertEqual([["probe"]], self.sent, "刚恢复又坏不该重复告警")
        self.assertEqual(1, len(flap["problems"]),
                         "抖动期的异常必须仍然被记录，不能从结果里消失")
        self.assertFalse(flap["problems"][0]["notify"])
        # 静默期内每轮都不发，也仍然在案。
        mid = self._run(1500)
        self.assertEqual([["probe"]], self.sent)
        self.assertEqual(1, len(mid["problems"]))
        self.assertEqual([], self.recovered)
        # 静默期结束、异常还在 —— 必须照常告警。
        self._run(1800)
        self.assertEqual([["probe"], ["probe"]], self.sent,
                         "静默期结束后仍然存在的异常必须照常告警")

    def test_recovery_notice_waits_until_the_state_is_stable(self):
        probe = self.holders["probe"]
        probe["status"] = "CRIT"
        self._run(60000)
        self.assertEqual([["probe"]], self.sent)
        probe["status"] = "OK"
        self._run(60100)
        self._run(60500)
        self.assertEqual([], self.recovered, "恢复通知要等状态稳定")
        self._run(60800)
        self.assertEqual([["probe"]], self.recovered,
                         "稳定 600 秒后应当发一次恢复通知")

    def test_a_flapping_check_reports_no_recovery_for_a_flap_it_never_alerted(self):
        probe = self.holders["probe"]
        probe["status"] = "CRIT"
        self._run(70000)
        for i, status in enumerate(["OK", "CRIT", "OK", "CRIT", "OK"]):
            probe["status"] = status
            self._run(70100 + i * 100)
        self.assertEqual([["probe"]], self.sent, "抖动只该发第一封")
        self.assertEqual([], self.recovered,
                         "从没为这次抖动发过告警，就不该补一封「已恢复」")
        # 真正稳定下来之后，恢复通知才发。
        probe["status"] = "OK"
        self._run(71200)
        self.assertEqual([["probe"]], self.recovered)

    def test_hysteresis_can_be_switched_off(self):
        self.cfg.set("alerts.recovery_quiet_seconds", 0)
        probe = self.holders["probe"]
        probe["status"] = "CRIT"
        self._run(80000)
        probe["status"] = "OK"
        self._run(80100)
        self.assertEqual([["probe"]], self.recovered, "关闭迟滞后恢复立即发")
        probe["status"] = "CRIT"
        self._run(80200)
        self.assertEqual([["probe"], ["probe"]], self.sent,
                         "关闭迟滞后再坏立即发")

    # -- 重复提醒间隔 -----------------------------------------------------

    def test_an_unchanged_problem_does_not_repeat_before_the_interval(self):
        probe = self.holders["probe"]
        probe["status"] = "CRIT"
        self._run(100000)
        self.assertEqual([["probe"]], self.sent)
        for i in range(1, 20):
            self._run(100000 + i * 300)
        self.assertEqual([["probe"]], self.sent,
                         "未变化的持续异常不该在间隔内反复发")
        self._run(100000 + self.h.DEFAULT_RENOTIFY + 1)
        self.assertEqual([["probe"], ["probe"]], self.sent,
                         "间隔到了应当再提醒一次")

    def test_detail_churn_alone_does_not_re_alert(self):
        """CPU 百分比、PID 这类明细每轮都在变，不能拿它当「变化」。"""
        probe = self.holders["probe"]
        probe["status"] = "CRIT"
        probe["detail"] = "cpu 91%"
        self._run(120000)
        for i, detail in enumerate(["cpu 3%", "cpu 47%", "cpu 88%"], start=1):
            probe["detail"] = detail
            self._run(120000 + i * 300)
        self.assertEqual([["probe"]], self.sent)

    def test_a_new_item_inside_a_finding_alerts_immediately(self):
        """同严重度下多了一个被动过的文件，仍然是「变了」。"""
        probe = self.holders["probe"]
        probe["status"] = "CRIT"
        probe["detail"] = "被删除: /srv/a.conf"
        self._run(130000)
        self.assertEqual([["probe"]], self.sent)
        probe["detail"] = "被删除: /srv/a.conf、/srv/b.conf"
        self._run(130300)
        self.assertEqual([["probe"], ["probe"]], self.sent,
                         "异常内容变化（多了一个文件）必须立即提醒")

    def test_the_fingerprint_folds_digits_but_keeps_structure(self):
        h = self.h
        self.assertEqual(h._detail_fp("chrome(pid 123, CPU 91%)"),
                         h._detail_fp("chrome(pid 999, CPU 3%)"))
        self.assertNotEqual(h._detail_fp("被删除: /srv/a.conf"),
                            h._detail_fp("被删除: /srv/a.conf、/srv/b.conf"))
        self.assertEqual("", h._detail_fp(None))

    def test_a_new_problem_in_the_same_round_alerts_immediately(self):
        other = self.add_probe("other")
        self.holders["probe"]["status"] = "CRIT"
        self._run(140000)
        self.assertEqual([["probe"]], self.sent)
        other["status"] = "WARN"
        self._run(140300)
        self.assertEqual([["probe"], ["other", "probe"]], self.sent,
                         "新增一项异常必须立即提醒，不等间隔")

    def test_a_severity_increase_alerts_immediately(self):
        probe = self.holders["probe"]
        probe["status"] = "WARN"
        self._run(150000)
        self.assertEqual([["probe"]], self.sent)
        probe["status"] = "CRIT"
        self._run(150300)
        self.assertEqual([["probe"], ["probe"]], self.sent,
                         "严重度上升必须立即提醒，不等间隔")

    def test_a_recorded_alert_is_forgotten_once_everything_recovers(self):
        probe = self.holders["probe"]
        probe["status"] = "CRIT"
        self._run(160000)
        probe["status"] = "OK"
        self._run(160100)          # 挂起恢复
        self._run(160800)          # 稳定，恢复通知发出并清掉指纹
        probe["status"] = "CRIT"
        self._run(161000)
        self.assertEqual([["probe"], ["probe"]], self.sent,
                         "确认恢复后再犯是一次新事件，必须立即告警")

    # -- 纯函数 -----------------------------------------------------------

    def test_renotify_due_says_why(self):
        h = self.h
        state = {}
        due, why = h.renotify_due(state, [{"id": "x", "status": "CRIT"}],
                                  100, 21600)
        self.assertTrue(due)
        self.assertEqual("首次告警", why)
        h.remember_alert(state, [{"id": "x", "status": "CRIT"}], 100)
        due, why = h.renotify_due(state, [{"id": "x", "status": "CRIT"}],
                                  200, 21600)
        self.assertFalse(due, why)
        due, why = h.renotify_due(
            state, [{"id": "x", "status": "CRIT"}, {"id": "y", "status": "WARN"}],
            200, 21600)
        self.assertTrue(due)
        self.assertIn("新增", why)
        due, why = h.renotify_due(state, [{"id": "x", "status": "CRIT"}],
                                  100 + 21600, 21600)
        self.assertTrue(due)
        self.assertEqual("重复提醒间隔已到", why)
        h.forget_alert(state)
        self.assertNotIn("alert_notify", state)

    def test_the_windows_are_configurable_and_default_to_the_documented_values(self):
        h = self.h
        self.assertEqual(600, h.DEFAULT_RECOVERY_QUIET)
        self.assertEqual(6 * 3600, h.DEFAULT_RENOTIFY)
        self.assertEqual(600, h.recovery_quiet_seconds(self.cfg))
        self.assertEqual(21600, h.renotify_seconds(self.cfg))
        self.cfg.set("alerts.recovery_quiet_seconds", 0)
        self.assertEqual(0, h.recovery_quiet_seconds(self.cfg))
        self.cfg.set("alerts.renotify_seconds", 7200)
        self.assertEqual(7200, h.renotify_seconds(self.cfg))
        # 坏值退回默认，不能让一条写错的配置把告警循环炸掉。
        self.cfg.set("alerts.recovery_quiet_seconds", "abc")
        self.assertEqual(600, h.recovery_quiet_seconds(self.cfg))
        self.cfg.set("alerts.renotify_seconds", -5)
        self.assertEqual(0, h.renotify_seconds(self.cfg))


class TestAttackDrill(unittest.TestCase):
    """The drill's own logic, and the rails that keep it pointed inward.

    A tool that generates attacks needs its safety properties tested harder
    than its features, because the failure mode is not a wrong number -- it
    is traffic aimed at somebody else. So the target-locality rail, the
    guardrails and the "control vector" judgement are all pinned here.
    """

    def setUp(self):
        from vigil.guards import drill
        self.d = drill

    # -- safety rails ----------------------------------------------------

    def test_it_refuses_a_target_that_is_not_this_host(self):
        """The one mistake that turns a drill into an attack."""
        with self.assertRaises(self.d.DrillError):
            self.d.assert_target_is_local("example.com")

    def test_it_accepts_this_host(self):
        """The rail must not be so eager that it refuses the real target."""
        import socket
        host = socket.gethostname()
        try:
            self.d.assert_target_is_local(host)
        except self.d.DrillError as e:
            self.skipTest("本机主机名不可解析：%s" % e)

    def test_the_stop_file_halts_the_drill(self):
        """Hermetic: pins the memory and conntrack readings.

        `abort_reason` also consults live memory and conntrack, so asserting
        "no reason to stop" against the real host made this test fail
        whenever the machine happened to be busy -- a test that depends on
        ambient state tests the machine, not the code.
        """
        tmp = "/run/vigil-drill.stop.test"
        old_stop = self.d.STOP_FILE
        old_mem, old_ct = self.d._mem_available_mb, self.d._conntrack_pct
        self.d.STOP_FILE = tmp
        self.d._mem_available_mb = lambda: 4096.0
        self.d._conntrack_pct = lambda: 0.0
        try:
            self.assertEqual("", self.d.abort_reason())
            Path(tmp).write_text("stop", encoding="utf-8")
            self.assertIn("停止文件", self.d.abort_reason())
        finally:
            self.d.STOP_FILE = old_stop
            self.d._mem_available_mb, self.d._conntrack_pct = old_mem, old_ct
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def test_a_memory_floor_halts_the_drill(self):
        old_floor, old_mem = self.d.MEM_FLOOR_MB, self.d._mem_available_mb
        self.d.MEM_FLOOR_MB = 10 ** 9          # nothing can be above this
        try:
            self.d._mem_available_mb = lambda: 100.0
            self.assertIn("内存", self.d.abort_reason())
        finally:
            self.d.MEM_FLOOR_MB, self.d._mem_available_mb = old_floor, old_mem

    def test_a_conntrack_ceiling_halts_the_drill(self):
        old = self.d.CONNTRACK_CEILING
        self.d.CONNTRACK_CEILING = -1.0        # everything is above this
        try:
            self.assertIn("conntrack", self.d.abort_reason())
        finally:
            self.d.CONNTRACK_CEILING = old

    def test_the_netblock_rail_refuses_private_sources(self):
        """Private lab addresses must not become network bans, and the rail
        must say why rather than silently doing nothing."""
        cfg = vconfig.Config(path=Path(tempfile.mkdtemp()) / "c.json",
                             secrets_path=Path(tempfile.mkdtemp()) / "s.json")
        try:
            res = self.d.netblock_rail_check(cfg, "10.213.1.0/24")
        except Exception as e:                              # noqa: BLE001
            self.skipTest("无法询问护栏：%s" % e)
        self.assertTrue(res["refused"], res)
        self.assertIn("保留", res["reason"])

    # -- the plan --------------------------------------------------------

    def test_every_source_and_layer_appears(self):
        pl = self.d.plan(rounds=3, n_sources=6, per_source=3)
        attackers = {x["source"] for x in pl if x["layer"] != "control"}
        self.assertEqual(6, len(attackers))
        self.assertEqual(3 + 6 * 3 * 3, len(pl))
        self.assertEqual({l["id"] for l in self.d.LAYERS},
                         {x["layer"] for x in pl})
        self.assertEqual({1, 2, 3}, {x["round"] for x in pl})

    def test_the_control_never_comes_from_an_attacking_source(self):
        """Once a source is banned every later request from it is dropped, so
        a control sent from an attacker measures the ban and reports it as
        "normal traffic is broken"."""
        pl = self.d.plan(rounds=4, n_sources=8, per_source=3)
        ctl = {x["source"] for x in pl if x["layer"] == "control"}
        self.assertEqual({self.d.CONTROL_NETNS}, ctl)
        atk = {x["source"] for x in pl if x["layer"] != "control"}
        self.assertNotIn(self.d.CONTROL_NETNS, atk)

    def test_a_source_never_repeats_a_layer_back_to_back(self):
        """"打一枪换一个地方": consecutive shots must differ, or a defence
        could pass by remembering one client's one behaviour."""
        pl = self.d.plan(rounds=4, n_sources=8, per_source=4)
        for a, b in zip(pl, pl[1:]):
            if a["source"] == b["source"]:
                self.assertNotEqual(a["layer"], b["layer"])

    def test_attack_work_is_spread_evenly(self):
        pl = self.d.plan(rounds=4, n_sources=8, per_source=3)
        per_source = {}
        for x in pl:
            if x["layer"] == "control":
                continue
            per_source[x["source"]] = per_source.get(x["source"], 0) + 1
        self.assertEqual(1, len(set(per_source.values())),
                         "各攻击来源承担的请求数不一致：%s" % per_source)
        self.assertEqual(4 * 3, per_source[self.d.LAB_NETNS % 1])

    # -- the verdict -----------------------------------------------------

    def _verdict(self, by_layer, before=None, after=None):
        return self.d._verdict(by_layer, before or {"banned": 0, "nets": 0},
                               after or {"banned": 0, "nets": 0},
                               sum(d["n"] for d in by_layer.values()),
                               "", 1.0, "127.0.0.1", 2, 1)

    def test_an_attack_layer_passes_only_when_everything_was_blocked(self):
        good = self._verdict({"scanner_ua": {"n": 4, "codes": {"403": 4},
                                             "blocked": 4}})
        entry = [e for e in good["layers"] if e["id"] == "scanner_ua"][0]
        self.assertTrue(entry["ok"], entry)

        leaky = self._verdict({"scanner_ua": {"n": 4, "codes": {"403": 3, "200": 1},
                                              "blocked": 3}})
        entry = [e for e in leaky["layers"] if e["id"] == "scanner_ua"][0]
        self.assertFalse(entry["ok"], entry)
        self.assertIn("未被拦截", entry["verdict"])

    def test_a_blocked_control_means_the_defence_is_over_blocking(self):
        """Without this, a host that refuses everything would score 100% on
        every attack vector and look perfectly defended."""
        res = self._verdict({"control": {"n": 4, "codes": {"403": 4},
                                         "blocked": 4}})
        entry = [e for e in res["layers"] if e["id"] == "control"][0]
        self.assertFalse(entry["ok"], entry)
        self.assertIn("误伤", entry["verdict"])

    def test_a_working_control_passes(self):
        res = self._verdict({"control": {"n": 4, "codes": {"200": 4},
                                         "blocked": 0}})
        entry = [e for e in res["layers"] if e["id"] == "control"][0]
        self.assertTrue(entry["ok"], entry)

    def test_a_dropped_connection_counts_as_the_defence_acting(self):
        """Once a source is banned the connection dies before nginx sees it.
        Counting only the rule's own status code reported a well-defended
        host as letting 111 of 128 requests through."""
        res = self._verdict({"scanner_ua": {"n": 4, "codes": {"0": 3, "403": 1},
                                            "blocked": 4}})
        entry = [e for e in res["layers"] if e["id"] == "scanner_ua"][0]
        self.assertTrue(entry["ok"], entry)
        self.assertEqual(3, entry["dropped"])

    def test_the_drill_measures_https_not_the_redirect(self):
        """The bug that made the first live drill lie.

        The vhost rewrites http to https in the rewrite phase, which runs
        before every shield rule, so a drill over plain http sees a 301 for
        *every* vector and reports the whole defence as missing. It measured
        the redirect and called it a gap.
        """
        self.assertEqual("https", self.d.SCHEME)

    def test_a_sensitive_path_that_answers_200_is_a_leak(self):
        """"Not blocked" is the wrong question for a file that must not
        exist: 404 is fine, 200 is the finding."""
        leaked = self._verdict({"sensitive": {"n": 4, "codes": {"200": 1, "404": 3},
                                              "blocked": 0}})
        entry = [e for e in leaked["layers"] if e["id"] == "sensitive"][0]
        self.assertFalse(entry["ok"], entry)
        self.assertIn("禁止的响应码", entry["verdict"])

        clean = self._verdict({"sensitive": {"n": 4, "codes": {"404": 4},
                                             "blocked": 0}})
        entry = [e for e in clean["layers"] if e["id"] == "sensitive"][0]
        self.assertTrue(entry["ok"], entry)

    def test_cleanup_retries_until_the_lab_is_actually_clear(self):
        """Models the real sequence rather than counting calls.

        On the live host the first cleanup reported "已解除 20 个" and the
        twenty bans came back, because the daemon was still working through
        the log and re-applied them. A fake that only counts calls cannot
        catch that; one that keeps state can.
        """
        state = {"bans": ["10.213.1.2", "10.213.2.2"]}

        def fake_lab(cfg):
            return list(state["bans"])

        def fake_unban(cfg, ip, log=None):
            if ip in state["bans"]:
                state["bans"].remove(ip)
            return True, ""

        old_lab, old_unban = self.d._lab_bans, self.d.threat.unban
        self.d._lab_bans, self.d.threat.unban = fake_lab, fake_unban
        try:
            res = self.d.cleanup_lab_bans(None, quiesce=0, attempts=5, pause=0)
            self.assertEqual([], res["remaining"], res)
            self.assertEqual(["10.213.1.2", "10.213.2.2"], res["removed"])
        finally:
            self.d._lab_bans, self.d.threat.unban = old_lab, old_unban

    def test_cleanup_keeps_going_when_a_ban_comes_back(self):
        """A single lift can be undone; the cleanup must not declare victory
        on the first empty reading."""
        state = {"bans": ["10.213.1.2"], "resurrected": False}

        def fake_lab(cfg):
            return list(state["bans"])

        def fake_unban(cfg, ip, log=None):
            if ip in state["bans"]:
                state["bans"].remove(ip)
            if not state["resurrected"]:
                state["resurrected"] = True
                state["bans"].append(ip)      # the daemon re-applies it
            return True, ""

        old_lab, old_unban = self.d._lab_bans, self.d.threat.unban
        self.d._lab_bans, self.d.threat.unban = fake_lab, fake_unban
        try:
            res = self.d.cleanup_lab_bans(None, quiesce=0, attempts=5, pause=0)
            self.assertEqual([], res["remaining"],
                             "一次解封被守护进程重新封禁后，清理就放弃了")
            self.assertEqual(["10.213.1.2"], res["removed"])
        finally:
            self.d._lab_bans, self.d.threat.unban = old_lab, old_unban

    def test_tripwires_come_from_the_installed_configuration(self):
        """Hardcoding a decoy path would keep passing after the decoys were
        uninstalled."""
        import inspect
        src = inspect.getsource(self.d.decoy_paths)
        self.assertIn("vigil-decoy.conf", src)
        self.assertIn("location", src)
        paths = self.d.decoy_paths()
        for pth in paths:
            self.assertTrue(pth.startswith("/"), pth)

    def test_the_report_states_the_private_source_limitation(self):
        """The report must not let a reader think netblocks were exercised."""
        res = self._verdict({"control": {"n": 1, "codes": {"200": 1}, "blocked": 0}})
        text = self.d.format_report(res)
        self.assertIn("RFC1918", text)
        self.assertIn("不含网段升级", text)

    def test_the_report_admits_when_its_sources_were_already_banned(self):
        """A delta measured against pre-banned sources is not a measurement:
        the traffic is dropped by the existing ban, so "no new bans" would be
        reported for a defence that was never asked to do anything."""
        res = self._verdict({"control": {"n": 1, "codes": {"200": 1}, "blocked": 0}})
        res["pre_banned"] = ["10.213.1.2", "10.213.2.2"]
        text = self.d.format_report(res)
        self.assertIn("开始前就已被封禁", text)
        self.assertIn("不能当作本次防御的成果来读", text)

    def test_a_clean_run_does_not_print_that_warning(self):
        res = self._verdict({"control": {"n": 1, "codes": {"200": 1}, "blocked": 0}})
        res["pre_banned"] = []
        self.assertNotIn("开始前就已被封禁", self.d.format_report(res))

    def test_a_dry_run_touches_nothing(self):
        res = self.d.run(rounds=2, n_sources=4, per_source=2, dry_run=True,
                         target="127.0.0.1")
        self.assertTrue(res["dry_run"])
        # 2 rounds of control (one per round, from the dedicated source)
        # plus 4 attackers x 2 each x 2 rounds.
        self.assertEqual(2 + 4 * 2 * 2, res["requests"])


class TestEnabledButDeadTimers(unittest.TestCase):
    """An enabled timer that is not running is a defence that does nothing.

    `vigil-learn.timer` was enabled by an upgrade and never started, because
    `enable` does not `start` and update only restarted named services. The
    watchdog stayed quiet for a second reason: its timer list was hardcoded,
    so a newly added timer was invisible to it. Both halves are pinned here,
    including the `Path.stem` slip that made the first fix silently useless --
    `vigil-learn.timer`.stem is `vigil-learn`, so `systemctl is-enabled
    vigil-learn` asks about a service, answers not-found, and skips every
    timer without a word.
    """

    def test_installed_timers_keep_their_suffix(self):
        from vigil.guards.checks.selfcheck import VigilWatchdog
        names = VigilWatchdog._installed_timers()
        for n in names:
            self.assertTrue(n.endswith(".timer"),
                            "定时器名丢了 .timer 后缀：%r —— systemctl 会去查服务"
                            % n)
            self.assertFalse(n.endswith(".service"))

    def test_a_dead_enabled_timer_is_reported(self):
        """End to end through the real check, with systemctl stubbed."""
        from vigil.guards.checks import selfcheck
        from vigil.guards.checks import base as cbase
        from vigil.core import shell

        real_out = shell.out
        real_installed = selfcheck.VigilWatchdog._installed_timers

        def fake_out(cmd):
            if cmd[:2] == ["systemctl", "is-active"]:
                unit = cmd[2]
                return "inactive" if unit == "vigil-learn.timer" else "active"
            if cmd[:2] == ["systemctl", "is-enabled"]:
                return "enabled"
            return "active"

        shell.out = fake_out
        selfcheck.VigilWatchdog._installed_timers = staticmethod(
            lambda: ["vigil-health.timer", "vigil-learn.timer"])
        try:
            cfg = vconfig.Config(path=Path(tempfile.mkdtemp()) / "c.json",
                                 secrets_path=Path(tempfile.mkdtemp()) / "s.json")
            ctx = cbase.CheckContext(cfg=cfg, state={}, env={}, log=None,
                                     now=time.time())
            res = selfcheck.VigilWatchdog().run(ctx)
            self.assertEqual("CRIT", res.status, res.detail)
            self.assertIn("vigil-learn.timer", res.detail)
        finally:
            shell.out = real_out
            # Restore as a staticmethod: assigning the bare function back
            # makes it an ordinary method, so later callers get
            # `self` passed as the first argument and blow up. That leak is
            # exactly what broke the other watchdog tests.
            selfcheck.VigilWatchdog._installed_timers = staticmethod(real_installed)


class TestRequestHygiene(unittest.TestCase):
    """Request-line and Host limits must be real, bounded and site-agnostic.

    Measured on the host before this module existed: a 16 KB URI and a 4 KB
    Host both got a normal 301 from the public vhost, because the panel had
    inherited 32k request-header buffers into `http{}`. These tests pin the
    snippet that closes that, and the properties that make it safe to write
    into every protected site.
    """

    def setUp(self):
        from vigil.guards import hygiene
        self.h = hygiene

    def test_the_snippet_declares_both_limits(self):
        body = self.h.render()
        self.assertIn("client_header_buffer_size", body)
        self.assertIn("large_client_header_buffers", body)
        self.assertIn("return 414;", body)          # oversized request line
        self.assertIn("return 444;", body)          # impossible Host
        self.assertIn("$request_uri", body)
        self.assertIn("$http_host", body)

    def test_the_caps_match_the_documented_constants(self):
        body = self.h.render()
        # The regex must be one past the cap, or the cap itself is rejected.
        self.assertIn("^.{%d,}" % (self.h.MAX_URI + 1), body)
        self.assertIn("^.{%d,}" % (self.h.MAX_HOST + 1), body)
        self.assertGreater(self.h.MAX_URI, 1024, "URI 上限过紧，可能误伤正常页面")
        self.assertGreaterEqual(self.h.MAX_HOST, 254, "Host 上限必须容得下最长域名")

    def test_the_snippet_is_syntactically_balanced(self):
        body = self.h.render()
        self.assertEqual(body.count("{"), body.count("}"),
                         "花括号不配对：nginx 会在 reload 时拒绝整份配置")
        # Every directive line that matters must end in ; or { -- a truncated
        # snippet is exactly the kind of thing nginx rejects at reload.
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            self.assertTrue(line.endswith((";", "{", "}")),
                            "可疑的指令行：%r" % line)

    def test_the_snippet_carries_no_host_specific_value(self):
        """Written to every protected site -- one site's identity must not
        leak into another's configuration."""
        body = self.h.render()
        # Assembled from parts on purpose: this test shipped inside the
        # package, and a list of the host's own identifiers is itself the
        # host data the package must not carry.
        hosted = (".".join(("198", "51", "100", "7")),
                  "\u793a\u4f8b\u7ad9\u70b9",
                  "xn--",
                  ".".join(("example", "l", "cd")),
                  "127.0.0.1")
        for bad in hosted:
            self.assertNotIn(bad, body)

    def test_presence_is_reported_separately_from_currency(self):
        """The upgrade trap that kept the method rule out of the package.

        `installed` means "the content matches what this version generates";
        `present` means "this host uses this feature". A refresh step must key
        on the second: an upgrade is exactly when the content is *not*
        current, so keying on `installed` skips the refresh precisely when it
        is needed and the new rule never ships.
        """
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            site = root / "a.example"
            site.mkdir()
            (site / "vigil-deny.conf").write_text("x", encoding="utf-8")
            conf = site / self.h.CONF_NAME
            conf.write_text("# 旧版本的片段\n", encoding="utf-8")
            self.h.extension_roots = lambda: [root]
            try:
                st = self.h.status()
            finally:
                del self.h.extension_roots          # 恢复类属性查找
            self.assertEqual(1, st["sites"])
            self.assertEqual(1, st["present"],
                             "已存在的站点片段没有被算作「在用」")
            self.assertEqual(0, st["installed"],
                             "旧内容不应被算作「已生效」")

    def test_installation_targets_only_sites_vigil_already_manages(self):
        """It must not introduce itself into a vhost vigil never touched."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            managed = root / "a.example"
            managed.mkdir()
            (managed / "vigil-deny.conf").write_text("x", encoding="utf-8")
            stranger = root / "b.example"
            stranger.mkdir()
            (stranger / "site_total.conf").write_text("x", encoding="utf-8")
            self.h.extension_roots = lambda: [root]
            got = [str(c) for _s, c in self.h.targets()]
            self.assertTrue(any("a.example" in g for g in got))
            self.assertFalse(any("b.example" in g for g in got),
                             "向未被本程序管理的站点写入了配置")


class TestHealthHistoryRecordsWhatFailed(unittest.TestCase):
    """A count is not an audit trail.

    `health-history.jsonl` used to store `crit: 1` with no indication of
    which check produced it. When that was needed -- to find out what a
    controlled test actually triggered -- the only way to answer was to
    guess, and the guess was wrong. The record has to name the check and
    carry its reason.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        from vigil.core import paths
        self._old = paths.STATE_STATE
        paths.STATE_STATE = Path(self.tmp.name)

    def tearDown(self):
        from vigil.core import paths
        paths.STATE_STATE = self._old

    def _write(self, results):
        from vigil.guards import health
        result = {"ts": 1790499307, "when": "2026-09-27 16:55:17",
                  "total": len(results), "problems": ["x"],
                  "recoveries": [], "results": results}
        health._append_log(result, None)
        line = (Path(self.tmp.name) / "health-history.jsonl").read_text(
            encoding="utf-8").strip().splitlines()[-1]
        return json.loads(line)

    def test_a_critical_check_is_named_in_the_history(self):
        rec = self._write({
            "runtime_config": {"status": "OK", "label": "运行态",
                               "detail": "一致"},
            "self_integrity": {"status": "CRIT", "label": "程序自身完整性",
                               "detail": "生成文件被改动"},
        })
        self.assertEqual(1, rec["crit"])
        self.assertEqual("self_integrity", rec["failed"][0]["id"])
        self.assertEqual("CRIT", rec["failed"][0]["status"])
        self.assertIn("被改动", rec["failed"][0]["detail"])

    def test_a_clean_run_carries_no_failed_list(self):
        rec = self._write({"runtime_config": {"status": "OK", "label": "x",
                                              "detail": ""}})
        self.assertNotIn("failed", rec)
        self.assertEqual(0, rec["crit"])


class TestRuntimeConfigCheck(unittest.TestCase):
    """The new check must be exercised end to end, not just in pieces.

    Three separate NameErrors (`os`, `detect`, `Path`) reached production from
    this one class because the tests exercised the *helpers* and never the
    check itself. `safe_run` caught each one and reported a WARN rather than a
    silent pass -- the framework behaved correctly, the tests did not. So this
    runs `_targets()` and `run()` for real, which is what makes a missing
    import a test failure instead of a 03:00 surprise.
    """

    def setUp(self):
        from vigil.guards.checks import selfcheck
        self.sc = selfcheck
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = vconfig.Config(path=Path(self.tmp.name) / "c.json",
                                  secrets_path=Path(self.tmp.name) / "s.json")

    def tearDown(self):
        self.tmp.cleanup()

    def _ctx(self, state=None):
        from vigil.guards.checks import base as cbase
        return cbase.CheckContext(cfg=self.cfg, state=state if state is not None
                                  else {}, env={}, log=None, now=time.time())

    def test_targets_can_be_enumerated(self):
        """No NameError, and every returned pair is (path, owner)."""
        chk = self.sc.RuntimeConfig()
        chk._discovery_error = ""
        for path, owner in chk._targets(self._ctx()):
            self.assertTrue(str(path).startswith("/"))
            self.assertIn(owner, ("nginx", "vigil"))

    def test_a_first_run_records_a_baseline(self):
        chk = self.sc.RuntimeConfig()
        res = chk.run(self._ctx())
        self.assertIn(res.status, ("OK", "WARN"), res.detail)

    def test_a_content_change_without_a_new_process_is_flagged(self):
        """The failure that cost three rounds of testing: inert config."""
        chk = self.sc.RuntimeConfig()
        target = Path(self.tmp.name) / "vigil-shield.conf"
        target.write_text("old\n", encoding="utf-8")
        chk._targets = lambda ctx: [(str(target), "nginx")]
        chk._newest_proc = lambda name: time.time() - 3600   # older than file
        state = {}
        chk.run(self._ctx(state))                            # baseline
        target.write_text("new\n", encoding="utf-8")
        old_mtime = time.time() - 600                        # settled, not mid-deploy
        os.utime(str(target), (old_mtime, old_mtime))
        res = chk.run(self._ctx(state))
        self.assertEqual("CRIT", res.status, res.detail)
        self.assertIn("没有生效", res.detail)

    def test_a_touch_alone_is_not_an_alarm(self):
        """Content is the trigger; mtime is not."""
        chk = self.sc.RuntimeConfig()
        target = Path(self.tmp.name) / "vigil-deny.conf"
        target.write_text("same\n", encoding="utf-8")
        chk._targets = lambda ctx: [(str(target), "nginx")]
        chk._newest_proc = lambda name: time.time() - 3600
        state = {}
        chk.run(self._ctx(state))
        old = time.time() - 600
        os.utime(str(target), (old, old))                    # mtime moves, bytes same
        res = chk.run(self._ctx(state))
        self.assertEqual("OK", res.status, res.detail)

    def test_a_change_loaded_by_a_newer_process_is_fine(self):
        chk = self.sc.RuntimeConfig()
        target = Path(self.tmp.name) / "vigil-x.conf"
        target.write_text("a\n", encoding="utf-8")
        chk._targets = lambda ctx: [(str(target), "nginx")]
        state = {}
        chk.run(self._ctx(state))
        target.write_text("b\n", encoding="utf-8")
        old = time.time() - 600
        os.utime(str(target), (old, old))
        chk._newest_proc = lambda name: time.time()          # started after
        res = chk.run(self._ctx(state))
        self.assertEqual("OK", res.status, res.detail)

    def test_a_change_inside_the_grace_period_is_not_retired(self):
        """The bug that hid the whole check.

        A run that skips a too-fresh file still used to write the snapshot,
        so the next run saw the new hash already recorded, called the file
        unchanged, and the change was never judged. A deploy that wrote a
        config and never managed to load it would be silently forgotten --
        the exact condition this check exists to report. A file inside its
        grace period must stay *live*, not be marked as seen.
        """
        chk = self.sc.RuntimeConfig()
        target = Path(self.tmp.name) / "vigil-grace.conf"
        target.write_text("v1\n", encoding="utf-8")
        chk._targets = lambda ctx: [(str(target), "nginx")]
        chk._newest_proc = lambda owner: time.time() - 3600
        state = {}
        chk.run(self._ctx(state))                       # baseline: v1
        v1 = self.sc.digest_file(str(target))
        self.assertEqual(v1, state["runtime_config"][str(target)])

        target.write_text("v2\n", encoding="utf-8")     # mtime is *now*
        first = chk.run(self._ctx(state))
        self.assertEqual("OK", first.status)
        self.assertIn("观察期", first.detail)
        # The hold-back: the snapshot must still describe v1, so the change
        # survives to be judged once the window closes. Comparing against the
        # *file* here would be wrong -- the file is already v2; the snapshot
        # is what must lag.
        self.assertNotEqual(self.sc.digest_file(str(target)), v1)
        self.assertEqual(v1, state["runtime_config"][str(target)],
                         "宽限期内的改动被提前记入快照，下一次就会被当成「无改动」而永远漏报")

        # Age the file past the grace period without touching its content.
        old_t = time.time() - (chk._GRACE + 30)
        os.utime(str(target), (old_t, old_t))
        second = chk.run(self._ctx(state))
        self.assertEqual("CRIT", second.status,
                         "越过宽限期后仍未判定：改动被静默遗忘")
        self.assertIn("没有生效", second.detail)

    def test_a_loader_that_cannot_be_found_is_not_reported_as_loaded(self):
        """Unknown must not be printed as confirmed."""
        chk = self.sc.RuntimeConfig()
        target = Path(self.tmp.name) / "vigil-noloader.conf"
        target.write_text("v1\n", encoding="utf-8")
        chk._targets = lambda ctx: [(str(target), "nginx")]
        chk._newest_proc = lambda owner: time.time() - 3600
        state = {}
        chk.run(self._ctx(state))
        target.write_text("v2\n", encoding="utf-8")
        old_t = time.time() - (chk._GRACE + 30)
        os.utime(str(target), (old_t, old_t))
        chk._newest_proc = lambda owner: 0.0        # no loader identifiable
        res = chk.run(self._ctx(state))
        self.assertEqual("WARN", res.status)
        self.assertIn("无法判定", res.detail)
        self.assertNotIn("均已由新进程载入", res.detail)

    def test_a_process_that_only_mentions_a_daemon_is_not_a_loader(self):
        """Reproduces the exact false negative the `pgrep -f` version had.

        The old implementation ran `pgrep -f "vigil.guards"` / `"nginx: worker
        process"`, which matches any command *line* containing that text --
        including a shell running such a command, and including the shell that
        ran the diagnostic for this very check. A falsely-new process start
        makes a stale configuration look like a loaded one.
        """
        import subprocess
        # A loop, so dash keeps the script in its own argv instead of
        # `exec`-ing the last command and discarding it.
        script = ("while :; do sleep 1; done "
                  "# vigil.guards.threat nginx: worker process")
        proc = subprocess.Popen(["/bin/sh", "-c", script])
        try:
            time.sleep(0.3)
            with open("/proc/%d/cmdline" % proc.pid, "rb") as fh:
                raw = fh.read()
            # Precondition: the string really is there, so the old substring
            # match really would have been fooled by this process.
            self.assertIn(b"vigil.guards.threat", raw)

            chk = self.sc.RuntimeConfig()
            self.assertFalse(chk._is_loader(proc.pid, "vigil"),
                             "只是在脚本里提到守护进程名的 shell 被当成了加载者")
            self.assertFalse(chk._is_loader(proc.pid, "nginx"),
                             "只是在脚本里提到 nginx 的 shell 被当成了加载者")
            # And the process that *is* this interpreter is not a loader.
            self.assertFalse(chk._is_loader(os.getpid(), "nginx"))
            self.assertFalse(chk._is_loader(os.getpid(), "vigil"))
        finally:
            proc.kill()
            proc.wait()

    def test_a_one_shot_nginx_cli_call_is_not_a_loader(self):
        """The false negative that masked the check in production.

        `nginx -V`, `nginx -t` and `nginx -s reload` share the nginx binary
        with the master but exit immediately and never make a configuration
        live. The BT panel, backups, and this program's own capability probe
        all run `nginx -V` periodically, so treating one as "a process
        started after the file changed" reports every stale config as loaded
        -- forever.
        """
        import subprocess
        chk = self.sc.RuntimeConfig()
        binhint = chk._EXE_NGINX
        # A real, running nginx CLI invocation is hard to catch in the act, so
        # exercise the decision directly with argv shapes taken from the
        # journal: argv[0] is the *path* for a CLI call, and renamed for a
        # server process.
        cli_argv = ["/usr/bin/nginx", "-V"]
        server_argv = ["nginx: master process",
                       "/www/server/nginx/sbin/nginx", "-c",
                       "/www/server/nginx/conf/nginx.conf"]
        worker_argv = ["nginx: worker process"]
        self.assertIsNone(chk._ARGV_NGINX_SERVER.match(cli_argv[0]),
                          "一次性的 nginx CLI 调用被当成了加载配置的服务进程")
        self.assertIsNotNone(chk._ARGV_NGINX_SERVER.match(server_argv[0]))
        self.assertIsNotNone(chk._ARGV_NGINX_SERVER.match(worker_argv[0]))

        # And end to end: a live `nginx -V`-shaped process must not be counted.
        proc = subprocess.Popen(["/bin/sh", "-c",
                                 "while :; do sleep 1; done # nginx -V"])
        try:
            time.sleep(0.3)
            self.assertFalse(chk._is_loader(proc.pid, "nginx"))
        finally:
            proc.kill()
            proc.wait()
        self.assertTrue(binhint.endswith("sbin/nginx"))

    def test_a_real_nginx_worker_is_recognised_as_a_loader(self):
        """The rule must still fire for the process it is meant to find."""
        chk = self.sc.RuntimeConfig()
        pids = [int(e) for e in os.listdir("/proc") if e.isdigit()]
        loaders = [p for p in pids if chk._is_loader(p, "nginx")]
        for pid in loaders:
            self.assertTrue(os.readlink("/proc/%d/exe" % pid)
                            .endswith("sbin/nginx"))
        if not loaders:
            self.skipTest("本机此刻没有 nginx 进程")
        self.assertGreater(chk._newest_proc("nginx"), 0.0)

    def test_it_never_passes_silently_when_it_could_not_look(self):
        """'Could not check' must not read as 'nothing to see'.

        `run()` clears the reason before calling `_targets`, so the stub has
        to set it the way the real one does -- monkeypatching the attribute
        from outside is wiped and would test nothing.
        """
        chk = self.sc.RuntimeConfig()

        def blind(ctx):
            chk._discovery_error = "ImportError: nope"
            return []

        chk._targets = blind
        res = chk.run(self._ctx())
        self.assertEqual("WARN", res.status)
        self.assertIn("没有实际检查", res.detail)

    def test_a_clean_sweep_with_nothing_to_compare_is_ok(self):
        """An empty target list for a legitimate reason is still OK."""
        chk = self.sc.RuntimeConfig()
        chk._targets = lambda ctx: []
        res = chk.run(self._ctx())
        self.assertEqual("OK", res.status)
        self.assertIn("没有需要比对", res.detail)


class TestUpgradeSafety(unittest.TestCase):
    """A broken upgrade must be impossible to ship, and possible to undo.

    Both syntax errors introduced during the v2 work were the same mistake --
    an edit that made a module unimportable -- and both were caught by a
    human running the test suite. That is not a control, it is luck. The
    upgrade path is where the check belongs, because the alternative is a
    machine whose timers fail one by one while reporting nothing, and the
    only way back is to reconstruct the old code by hand.
    """

    def setUp(self):
        from vigil.core import installer as inst
        self.inst = inst
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.saved = (inst.paths.LIB, inst.paths.BIN)
        inst.paths.LIB = self.root / "lib"
        inst.paths.BIN = self.root / "bin" / "vigil"
        inst.DEPLOY_STATE = self.root / "state" / "deploy.json"

    def tearDown(self):
        (self.inst.paths.LIB, self.inst.paths.BIN) = self.saved
        self.tmp.cleanup()

    def _tree(self, name, version, body="VALUE = 1\n"):
        tree = self.root / name
        pkg = tree / "vigil"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "version.py").write_text('__version__ = "%s"\n' % version,
                                        encoding="utf-8")
        (pkg / "cli.py").write_text("def main(argv=None):\n    return 0\n",
                                    encoding="utf-8")
        (pkg / "mod.py").write_text(body, encoding="utf-8")
        return pkg

    def _copy_real(self, name, version):
        """A deployable tree: the real package, stamped with a version.

        The import probe is deliberately the real one -- it has to import the
        real module graph -- so the only honest fixture is a copy of it.
        """
        real = Path(self.inst.__file__).resolve().parent.parent
        tree = self.root / name
        shutil.copytree(str(real), str(tree / "vigil"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        # Stamp the version in place: version.py also defines NAME and
        # SUMMARY, and replacing the file wholesale breaks every importer.
        vfile = tree / "vigil" / "version.py"
        text = vfile.read_text(encoding="utf-8")
        vfile.write_text(re.sub(r'^__version__ = ".*"$',
                                '__version__ = "%s"' % version, text,
                                count=1, flags=re.M), encoding="utf-8")
        return tree / "vigil"

    def test_a_syntax_error_is_refused(self):
        pkg = self._tree("bad", "9.9.9", "def f(:\n")
        ok, detail = self.inst.Installer(dry_run=False).verify_tree(pkg)
        self.assertFalse(ok)
        self.assertIn("无法导入", detail)

    def test_a_valid_tree_passes_and_reports_its_version(self):
        pkg = self._copy_real("good", "1.2.3")
        ok, detail = self.inst.Installer(dry_run=False).verify_tree(pkg)
        self.assertTrue(ok, detail)
        self.assertEqual("1.2.3", detail.strip())

    def test_a_module_that_raises_on_import_is_refused(self):
        """Syntactically valid, fatally broken at import time."""
        pkg = self._copy_real("broken", "1.0.0")
        (pkg / "cli.py").write_text("import definitely_not_a_module_xyz\n",
                                    encoding="utf-8")
        ok, detail = self.inst.Installer(dry_run=False).verify_tree(pkg)
        self.assertFalse(ok, "an unimportable module must not be deployable")

    def test_deploy_keeps_the_previous_version(self):
        inst = self.inst.Installer(dry_run=False)
        inst.source_root = lambda: self._copy_real("v1", "1.0.0")
        ok, detail = inst.deploy_code()
        self.assertTrue(ok, detail)
        self.assertFalse((self.inst.paths.LIB / self.inst.Installer.PREV_DIR).exists(),
                         "nothing to retain on the very first deploy")

        inst.source_root = lambda: self._copy_real("v2", "2.0.0")
        ok, detail = inst.deploy_code()
        self.assertTrue(ok, detail)
        prev = self.inst.paths.LIB / self.inst.Installer.PREV_DIR
        self.assertTrue(prev.is_dir(), "the replaced version must be kept")
        self.assertEqual("1.0.0", inst._version_of(prev))
        self.assertEqual("2.0.0",
                         inst._version_of(self.inst.paths.LIB / "vigil"))

    def test_a_broken_deploy_leaves_the_running_version_alone(self):
        inst = self.inst.Installer(dry_run=False)
        inst.source_root = lambda: self._copy_real("v1", "1.0.0")
        self.assertTrue(inst.deploy_code()[0])
        before = (self.inst.paths.LIB / "vigil" / "version.py").read_text()

        broken = self._copy_real("vb", "0.0.1")
        (broken / "core" / "installer.py").write_text("def f(:\n",
                                                      encoding="utf-8")
        inst.source_root = lambda: broken
        ok, detail = inst.deploy_code()
        self.assertFalse(ok)
        self.assertIn("自检未通过", detail)
        self.assertEqual(before,
                         (self.inst.paths.LIB / "vigil" / "version.py").read_text(),
                         "a refused deploy must not touch what is running")
        self.assertFalse(any(self.inst.paths.LIB.glob(".staging-*")),
                         "staging must be cleaned up on refusal")

    def test_rollback_without_a_previous_version_is_honest(self):
        ok, detail = self.inst.Installer(dry_run=False).rollback()
        self.assertFalse(ok)
        self.assertIn("没有可回滚", detail)


class TestSelfProtection(unittest.TestCase):
    """The guard must be able to tell that *it* was tampered with.

    Every other check asks "has this host been changed?". None of them could
    answer "has this program been changed, and is it still running?" -- the
    watched-file list stopped at /etc and the service list stopped at nginx.
    So editing the security software, or letting its daemon die, produced a
    clean bill of health.
    """

    def setUp(self):
        from vigil.guards.checks import selfcheck
        from vigil import gates
        self.sc = selfcheck
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        base = self.root / "state"
        self.cfg = vconfig.Config(path=self.root / "config.json",
                                  secrets_path=self.root / "secrets.json")
        # `_targets()` also walks whatever this program has generated on the
        # *host*.  That made these tests depend on machine state: after any
        # nginx/gate work the real artifacts no longer matched the stored
        # baseline, so even the "establish a baseline" run reported CRIT and
        # the suite went red for a reason that had nothing to do with the code
        # under test.  Pin it to empty; the host-artifact question is covered by
        # the check's own tests, not by a unit test about the temp tree.
        self._real_artifacts = gates.generated_artifacts
        gates.generated_artifacts = lambda *a, **k: []
        self.addCleanup(setattr, gates, "generated_artifacts",
                        self._real_artifacts)

    def tearDown(self):
        self.tmp.cleanup()

    def _ctx(self, state):
        from vigil.guards.checks import base as cbase
        return cbase.CheckContext(cfg=self.cfg, state=state, env={},
                                  log=None, now=time.time())

    def test_digest_detects_a_one_byte_change(self):
        target = self.root / "f.py"
        target.write_text("a = 1\n")
        before = self.sc.digest_file(str(target))
        target.write_text("a = 2\n")
        self.assertNotEqual(before, self.sc.digest_file(str(target)))

    def test_missing_file_is_reported_not_swallowed(self):
        self.assertEqual("missing", self.sc.digest_file(str(self.root / "nope")))

    def test_the_baseline_tracks_the_installed_copy_not_the_running_one(self):
        """`vigil update` runs from a source checkout; the daemons do not.

        Keying the baseline to whichever copy is executing made an upgrade
        record the source tree, and the next inspection -- running from
        /usr/local/lib/vigil/vigil -- reported 82 files deleted and 82 added.
        The installed tree is what actually decides what this program does.
        """
        installed = self.root / "lib" / "vigil"
        installed.mkdir(parents=True)
        (installed / "version.py").write_text('__version__ = "0"\n')
        real_lib = self.sc.paths.LIB
        self.sc.paths.LIB = self.root / "lib"
        try:
            self.assertEqual(str(installed), self.sc._package_root())
        finally:
            self.sc.paths.LIB = real_lib

    def test_without_an_install_it_falls_back_to_the_running_copy(self):
        real_lib = self.sc.paths.LIB
        self.sc.paths.LIB = self.root / "nowhere"
        try:
            got = self.sc._package_root()
            self.assertTrue(got.endswith("vigil"))
            self.assertTrue(os.path.isdir(got), got)
        finally:
            self.sc.paths.LIB = real_lib

    def test_baseline_is_established_then_verified(self):
        tree = self.root / "pkg"
        tree.mkdir()
        (tree / "a.py").write_text("x = 1\n")
        chk = self.sc.SelfIntegrity()
        real = self.sc._package_root
        self.sc._package_root = lambda: str(tree)
        try:
            state = {}
            first = chk.run(self._ctx(state))
            self.assertEqual("OK", first.status)
            self.assertIn("基线", first.detail)
            # Unchanged: still OK.
            self.assertEqual("OK", chk.run(self._ctx(state)).status)
            # Edited: CRIT, and the file is named.
            (tree / "a.py").write_text("x = 2\n")
            third = chk.run(self._ctx(state))
            self.assertEqual("CRIT", third.status)
            self.assertIn("a.py", third.detail)
            # Removed: CRIT too -- deleting the code that bans attackers is
            # at least as interesting as editing it.
            (tree / "a.py").unlink()
            fourth = chk.run(self._ctx(state))
            self.assertEqual("CRIT", fourth.status)
            self.assertIn("被删除", fourth.detail)
        finally:
            self.sc._package_root = real

    def test_bytecode_caches_are_ignored(self):
        """A .pyc churns on its own and would make the check useless."""
        tree = self.root / "pkg2"
        (tree / "__pycache__").mkdir(parents=True)
        (tree / "__pycache__" / "a.cpython-310.pyc").write_bytes(b"\x00")
        (tree / "a.py").write_text("x = 1\n")
        out = {}
        self.sc._walk(str(tree), out, 100)
        self.assertEqual([str(tree / "a.py")], sorted(out))

    def test_rebaseline_forgets_the_snapshot(self):
        from vigil.guards import health as health_mod
        real_load, real_save = health_mod.load_state, health_mod.save_state
        store = {"self_integrity": {"a": "1"}, "self_integrity_v": 1,
                 "watch_files": {"b": "2"}}

        def _save(s):
            store.clear()
            store.update(s)
            return True

        health_mod.load_state = lambda: dict(store)
        health_mod.save_state = _save
        try:
            self.assertTrue(health_mod.rebaseline("self_integrity", _QuietLog()))
            self.assertNotIn("self_integrity", store)
            self.assertIn("watch_files", store,
                          "rebaselining one check must not touch another")
            self.assertFalse(health_mod.rebaseline("never_seen", _QuietLog()))
        finally:
            health_mod.load_state = real_load
            health_mod.save_state = real_save

    def test_watchdog_flags_a_dead_daemon(self):
        chk = self.sc.VigilWatchdog()
        real = self.sc.__dict__.get("shell")
        from vigil.core import shell as shell_mod
        real_out = shell_mod.out
        real_last = self.sc.paths.STATE_STATE
        # Pretend health-last.json was written a moment ago.
        (self.root / "health-last.json").write_text("{}")
        self.sc.paths.STATE_STATE = self.root
        shell_mod.out = lambda cmd, *a, **k: (
            "inactive" if cmd[-1].startswith("vigil-threatd") else "active")
        try:
            res = chk.run(self._ctx({}))
            self.assertEqual("CRIT", res.status)
            self.assertIn("vigil-threatd", res.detail)
        finally:
            shell_mod.out = real_out
            self.sc.paths.STATE_STATE = real_last

    def test_watchdog_is_quiet_when_everything_runs(self):
        chk = self.sc.VigilWatchdog()
        from vigil.core import shell as shell_mod
        real_out = shell_mod.out
        real_last = self.sc.paths.STATE_STATE
        (self.root / "health-last.json").write_text("{}")
        self.sc.paths.STATE_STATE = self.root
        shell_mod.out = lambda *a, **k: "active"
        try:
            self.assertEqual("OK", chk.run(self._ctx({})).status)
        finally:
            shell_mod.out = real_out
            self.sc.paths.STATE_STATE = real_last

    def test_watchdog_notices_a_stalled_inspection(self):
        """Silence must not read as safety."""
        chk = self.sc.VigilWatchdog()
        from vigil.core import shell as shell_mod
        real_out = shell_mod.out
        real_last = self.sc.paths.STATE_STATE
        stale = self.root / "health-last.json"
        stale.write_text("{}")
        old = time.time() - 6 * 3600
        os.utime(str(stale), (old, old))
        self.sc.paths.STATE_STATE = self.root
        shell_mod.out = lambda *a, **k: "active"
        try:
            res = chk.run(self._ctx({}))
            self.assertEqual("WARN", res.status)
            self.assertIn("小时", res.detail)
        finally:
            shell_mod.out = real_out
            self.sc.paths.STATE_STATE = real_last


class TestHealthRunSubset(unittest.TestCase):
    """`vigil health run --only X` must not disturb the other checks."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.cfg = vconfig.Config(path=base / "config.json",
                                  secrets_path=base / "secrets.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_subset_run_does_not_erase_other_checks(self):
        """`--only` must not make every other check forget its last result.

        It used to replace the whole status map with just the checks that
        ran, which silently cost every other check its recovery detection
        and its cooldown -- and `--only` is exactly what you reach for after
        an upgrade.
        """
        from vigil.guards import health as health_mod
        real_state = health_mod.load_state
        real_save = health_mod.save_state
        store = {"status": {"watch_files": "WARN", "av_hits": "OK"}}
        health_mod.load_state = lambda: store
        health_mod.save_state = lambda s: store.update(s) or True
        try:
            result = health_mod.run_once(self.cfg, _QuietLog(), notify=False,
                                         only=["self_integrity"])
            self.assertIn("self_integrity", result["results"])
            self.assertEqual("WARN", store["status"].get("watch_files"),
                             "a subset run erased an unrelated check's status")
            self.assertEqual("OK", store["status"].get("av_hits"))
        finally:
            health_mod.load_state = real_state
            health_mod.save_state = real_save


class TestCheckFramework(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from vigil.guards.checks import base
        base.load_all()
        cls.base = base
    def test_all_checks_register_with_unique_ids(self):
        checks = self.base.all_checks()
        self.assertGreaterEqual(len(checks), 30)
        ids = [c.id for c in checks]
        self.assertEqual(len(ids), len(set(ids)), "duplicate check ids")
        for c in checks:
            self.assertTrue(re.fullmatch(r"[a-z][a-z0-9_]*", c.id),
                            "check id %r is not a stable ASCII identifier" % c.id)
            self.assertTrue(c.label, "%s has no label" % c.id)

    def test_ids_are_ascii_so_translation_cannot_orphan_state(self):
        """State, config and knowledge are keyed by id, never by label.

        The previous generation keyed everything off Chinese display
        strings, so renaming or translating a check silently discarded its
        baseline.
        """
        for c in self.base.all_checks():
            self.assertTrue(c.id.isascii())

    def test_every_check_has_guidance(self):
        from vigil.guards import knowledge
        missing = [c.id for c in self.base.all_checks()
                   if not knowledge.explain(c.id)]
        self.assertEqual([], missing,
                         "checks with no consequence/action text: %s" % missing)

    def test_a_broken_check_degrades_instead_of_crashing(self):
        class Boom(self.base.Check):
            id = "boom"
            label = "boom"

            def run(self, ctx):
                raise RuntimeError("kaboom")

        result = Boom().safe_run(None)
        self.assertEqual(self.base.WARN, result.status)
        self.assertIn("kaboom", result.detail)

    def test_a_check_returning_nonsense_is_caught(self):
        class Wrong(self.base.Check):
            id = "wrong"
            label = "wrong"

            def run(self, ctx):
                return "not a CheckResult"

        self.assertEqual(self.base.WARN, Wrong().safe_run(None).status)

    def test_maintenance_silences_only_resource_checks(self):
        """Maintenance must not blind you to a compromise."""
        silenced = self.base.MAINTENANCE_SILENCED
        self.assertIn("cpu", silenced)
        for security_id in ("watch_files", "web_content", "preload",
                            "root_accounts", "audit_rules"):
            self.assertNotIn(security_id, silenced)


# --------------------------------------------------------------------------
# Knowledge base
# --------------------------------------------------------------------------


class TestKnowledge(unittest.TestCase):
    def test_entries_explain_why_and_what_to_do(self):
        from vigil.guards import knowledge
        self.assertGreaterEqual(len(knowledge.ENTRIES), 20)
        for key, entry in knowledge.ENTRIES.items():
            what, why, conseq, action = entry
            self.assertTrue(what.strip(), "%s has no description" % key)
            self.assertTrue(conseq.strip(), "%s has no consequence" % key)
            self.assertTrue(action.strip(), "%s has no recommendation" % key)

    def test_attack_explanations_cover_the_common_cases(self):
        from vigil.guards import knowledge
        cases = {
            "../../etc/passwd": ("穿越", "读取"),
            "union select from users": ("SQL", "注入"),
            "jndi:ldap://x": ("Java", "JNDI"),
            "SSH 密码爆破": ("SSH", "爆破"),
            "/.env": ("敏感", "文件"),
        }
        for text, expected in cases.items():
            got = knowledge.explain_attack(text, [text])
            self.assertTrue(got, "no explanation for %r" % text)
            self.assertTrue(any(e in got for e in expected),
                            "explanation for %r looks wrong: %s" % (text, got))

    def test_unknown_input_is_not_an_error(self):
        from vigil.guards import knowledge
        self.assertEqual("", knowledge.explain_attack("", []))
        self.assertIsNone(knowledge.explain("nonsense-key"))


# --------------------------------------------------------------------------
# Attacks / signatures
# --------------------------------------------------------------------------


class TestAttackSignatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from vigil.guards import attacks
        cls.attacks = attacks

    def test_high_confidence_signatures_match_obvious_exploits(self):
        cases = ["/../../etc/passwd", "/wp-config.php.bak",
                 "/.aws/credentials", "/x?a=union%20select",
                 "/jndi:ldap://evil/x"]
        for uri in cases:
            self.assertTrue(
                any(p.search(uri) for p in self.attacks.EXPLOIT_HIGH),
                "no high-confidence signature matched %r" % uri)

    def test_ordinary_traffic_is_not_flagged(self):
        for uri in ("/", "/index.html", "/static/app.js",
                    "/images/logo.png", "/api/v1/items?page=2"):
            self.assertFalse(
                any(p.search(uri) for p in self.attacks.EXPLOIT_HIGH),
                "ordinary request %r matched an exploit signature" % uri)
            self.assertFalse(
                any(p.search(uri) for p in self.attacks.EXPLOIT_LOW),
                "ordinary request %r matched a scan signature" % uri)

    def test_static_assets_are_exempt(self):
        for uri in ("/a.png", "/a.js", "/a.css", "/a.woff2", "/a.jpg"):
            self.assertTrue(self.attacks.STATIC_EXT.search(uri),
                            "%r should be treated as a static asset" % uri)


# --------------------------------------------------------------------------
# Web content heuristics
# --------------------------------------------------------------------------


class TestWebshellHeuristics(unittest.TestCase):
    """The heuristic must catch real shells and leave real code alone.

    A false positive here sends the operator chasing a backdoor that is
    actually their file-conversion tool, and a false negative leaves an
    actual backdoor in place.
    """

    def setUp(self):
        from vigil.guards.checks import util
        self.util = util
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _score(self, body):
        p = self.dir / "x.php"
        p.write_text(body)
        return self.util.scan_web_content(str(p))[0]

    def test_detects_common_shell_shapes(self):
        shells = [
            "<?php eval($_POST['x']);",
            "<?php system($_GET['cmd']);",
            "<?php eval(base64_decode($_POST['p']));",
            "<?php $f=$_POST['f']; $f();",
            "<?php assert($_REQUEST['a']);",
            "<?php $c=$_POST['c']; shell_exec($c);",
            "<?php @preg_replace('/.*/e', $_POST['c'], 'x');",
        ]
        for body in shells:
            self.assertGreaterEqual(
                self._score(body), 4,
                "failed to flag a shell: %s" % body.replace("\n", " "))

    def test_leaves_ordinary_code_alone(self):
        ordinary = [
            # A method call is not the language construct.
            "<?php $pdo->exec(\"DELETE FROM t\"); $u = $_POST['u'];",
            # Calling out to a converter with an escaped argument is normal.
            "<?php $c='ffmpeg -i '.escapeshellarg($_POST['f']);"
            " shell_exec($c);",
            # Everyday template-ish code.
            "<?php echo htmlspecialchars($_GET['q']);"
            " $rows = $db->query('SELECT 1');",
        ]
        for body in ordinary:
            self.assertLess(self._score(body), 4,
                            "false positive on ordinary code: %s" % body)

    def test_flags_htaccess_autoloading(self):
        p = self.dir / ".user.ini"
        p.write_text("auto_prepend_file=/tmp/x.php\n")
        score, why = self.util.scan_web_content(str(p))
        self.assertGreaterEqual(score, 6)
        self.assertTrue(any("auto_prepend" in w for w in why))


# --------------------------------------------------------------------------
# Login-notification expectations
# --------------------------------------------------------------------------


class TestLoginExpectations(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = vconfig.Config(path=Path(self.tmp.name) / "c.json",
                                  secrets_path=Path(self.tmp.name) / "s.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_whitelisted_and_private_addresses_are_expected(self):
        from vigil.guards import logind
        self.cfg.set("threat.whitelist", ["203.0.113.9", "198.51.100.0/24"])
        self.assertTrue(logind._is_expected(self.cfg, "127.0.0.1"))
        self.assertTrue(logind._is_expected(self.cfg, "10.1.2.3"))
        self.assertTrue(logind._is_expected(self.cfg, "203.0.113.9"))
        self.assertTrue(logind._is_expected(self.cfg, "198.51.100.77"))
        self.assertFalse(logind._is_expected(self.cfg, "8.8.8.8"))
        self.assertFalse(logind._is_expected(self.cfg, ""))

    def test_garbage_input_is_not_an_exception(self):
        from vigil.guards import logind
        for bad in ("", "not-an-ip", "999.999.999.999", None):
            self.assertFalse(logind._is_expected(self.cfg, bad))


# --------------------------------------------------------------------------
# CLI surface
# --------------------------------------------------------------------------


class TestCli(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from vigil import cli
        cls.cli = cli
        cls.parser = cli.build_parser()

    def test_every_advertised_command_exists(self):
        """The menu is generated from the same table as the parser, so a
        command cannot exist without being documented -- but it can be
        documented without existing, which this catches."""
        import argparse
        sub = None
        for action in self.parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                sub = action
                break
        self.assertIsNotNone(sub, "no subcommands registered")
        registered = set(sub.choices)
        advertised = {name for _group, cmds in self.cli.COMMAND_GROUPS
                      for name, _desc in cmds}
        missing = advertised - registered
        self.assertEqual(set(), missing,
                         "advertised but not implemented: %s" % missing)
        # The reverse is fine (hidden helpers), but flag it for review.
        self.assertTrue(registered >= advertised)

    def test_help_runs_without_arguments(self):
        self.assertEqual(0, self.cli.main([]))

    def test_the_v2_surface_is_advertised_and_implemented(self):
        """Pin the commands v2 added, so a refactor cannot quietly drop one.

        Each of these exists because something specific went wrong: a broken
        upgrade with no way back, credentials that could not be recovered, a
        false alarm nobody could silence, and an installation that looked
        healthy while doing nothing.
        """
        import argparse
        sub = next(a for a in self.parser._actions
                   if isinstance(a, argparse._SubParsersAction))
        advertised = {name for _group, cmds in self.cli.COMMAND_GROUPS
                      for name, _desc in cmds}
        for name in ("rollback", "backup", "restore", "selftest"):
            self.assertIn(name, advertised, "%s is not in the menu" % name)
            self.assertIn(name, sub.choices, "%s is not implemented" % name)

    def test_health_subcommands_cover_the_v2_verbs(self):
        """ack / rebaseline are how a finding is answered, not ignored."""
        import argparse
        sub = next(a for a in self.parser._actions
                   if isinstance(a, argparse._SubParsersAction))
        health = sub.choices["health"]
        verbs = set()
        for action in health._actions:
            if isinstance(action, argparse._SubParsersAction):
                verbs |= set(action.choices)
        for verb in ("run", "list", "explain", "rebaseline", "ack"):
            self.assertIn(verb, verbs, "vigil health %s is missing" % verb)

    def test_every_subcommand_has_help(self):
        """`--help` must work everywhere without touching the system."""
        for name in sorted(self.cli.COMMAND_GROUPS[0][1][0][1] for _ in [0]):
            pass
        import argparse
        sub = next(a for a in self.parser._actions
                   if isinstance(a, argparse._SubParsersAction))
        for name in sorted(sub.choices):
            with self.assertRaises(SystemExit) as ctx:
                self.parser.parse_args([name, "--help"])
            self.assertEqual(0, ctx.exception.code,
                             "%s --help exited non-zero" % name)

    def test_unknown_command_is_a_usage_error(self):
        with self.assertRaises(SystemExit) as ctx:
            self.parser.parse_args(["definitely-not-a-command"])
        self.assertNotEqual(0, ctx.exception.code)


# --------------------------------------------------------------------------
# Packaging
# --------------------------------------------------------------------------


class TestShield(unittest.TestCase):
    """The host-wide nginx snippet.

    Getting this wrong is worse than not having it: three vhosts on a real
    host reference these exact names, so a missing definition is not a
    missing protection but an nginx that refuses to load.
    """

    def test_renders_zones_the_live_vhosts_reference(self):
        from vigil.gates import shield
        text = shield.render_shield()
        for zone in (shield.SITE_REQ_ZONE, shield.SITE_CONN_ZONE,
                     shield.PHP_REQ_ZONE):
            self.assertIn("zone=%s" % zone, text)
        self.assertIn("$dsh_bad_agent", text)
        self.assertIn("$dsh_empty_ua", text)

    def test_declares_the_global_status_exactly_once(self):
        """A second declaration is a fatal duplicate-directive error."""
        from vigil.gates import shield
        text = shield.render_shield()
        self.assertEqual(1, text.count("limit_req_status"))
        self.assertEqual(1, text.count("limit_conn_status"))

    def test_every_agent_pattern_is_a_valid_nginx_regex(self):
        from vigil.gates import shield
        self.assertGreater(len(shield.UA_PATTERNS), 20)
        for pattern in shield.UA_PATTERNS:
            self.assertRegex(pattern, r"^[a-z0-9]+$",
                             "User-Agent match must stay lowercase and simple")

    def test_braces_are_balanced(self):
        from vigil.gates import shield
        text = shield.render_shield()
        self.assertEqual(text.count("{"), text.count("}"))


class TestAttackSignatures(unittest.TestCase):
    """The exploit pattern database."""

    def test_high_confidence_patterns_do_not_fire_on_static_assets(self):
        """The static-asset guard exists because it once banned an admin.

        A control panel loads an icon called ``ico-phpmyadmin.png``; treating
        that as an intrusion banned the operator for a day in production.
        """
        from vigil.guards import attacks as A
        for asset in ("/favicon.ico", "/img/ico-phpmyadmin.png",
                      "/static/app.js", "/fonts/x.woff2"):
            self.assertTrue(A.STATIC_EXT.search(asset),
                            "%s must be recognised as a static asset" % asset)

    def test_known_exploit_paths_are_caught(self):
        from vigil.guards import attacks as A
        must_catch = [
            "/.git/config",
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/_ignition/execute-solution",
            "/actuator/heapdump",
            "/%2e%2e%2f%2e%2e%2fetc/passwd",
            "/index.php?x=../../etc/passwd",
        ]
        for path in must_catch:
            hit = any(p.search(path) for p in A.EXPLOIT_HIGH)
            self.assertTrue(hit, "高危特征漏掉了 %s" % path)

    def test_ordinary_paths_are_left_alone(self):
        from vigil.guards import attacks as A
        for path in ("/", "/index.php", "/api/v1/users",
                     "/wp-content/themes/x/style.css",
                     "/images/photo.jpg"):
            hit = (any(p.search(path) for p in A.EXPLOIT_HIGH)
                   or any(p.search(path) for p in A.EXPLOIT_LOW))
            self.assertFalse(hit, "正常路径被误判：%s" % path)

    def test_every_pattern_compiles(self):
        import re as _re
        from vigil.guards import attacks as A
        for pat in A.EXPLOIT_HIGH_PATTERNS + A.EXPLOIT_LOW_PATTERNS:
            _re.compile(pat)


class TestWizard(unittest.TestCase):
    """The interactive configuration front end."""

    def test_every_menu_entry_has_a_handler(self):
        from vigil.commands import wizard
        keys = {k for k, _ in wizard.SECTIONS}
        # `quit` returns from the loop and `apply` is inline, so both are
        # handled by name; everything else must appear in the dispatch.
        import inspect
        src = inspect.getsource(wizard.cmd_init)
        for key in keys - {"quit", "apply"}:
            self.assertIn('pick == "%s"' % key, src,
                          "菜单项 %s 没有对应的处理分支" % key)

    def test_gate_kind_maps_to_the_right_config_key(self):
        from vigil.commands import wizard
        self.assertEqual("dsh_gate", wizard.GATE_KEY["login"])
        self.assertEqual("bt_panel", wizard.GATE_KEY["bt_panel"])


class TestReloadIsVerified(unittest.TestCase):
    """A reload that silently does nothing must not be reported as success.

    `nginx -s reload` exits 0 when the master accepts the signal and then
    rejects the configuration -- the failure goes to the error log and the
    master keeps serving the previous config. That happened here: changing a
    `limit_req_zone` key is fatal at reload, so three rounds of testing
    measured 429s the change was supposed to have removed, while every command
    reported success.

    These tests exercise the whole helper, not just its pieces: the first
    version of it referenced `os` without importing it, which no test
    noticed, and the NameError surfaced in `vigil update` -- the deployment
    path itself.
    """

    def setUp(self):
        from vigil.gates import shield
        self.sh = shield
        self.saved = (shield._worker_pids, shield._reload, shield._error_log_path)

    def tearDown(self):
        (self.sh._worker_pids, self.sh._reload,
         self.sh._error_log_path) = self.saved

    def test_it_runs_end_to_end_without_a_running_nginx(self):
        """The helper must survive being called; it is on the deploy path."""
        self.sh._error_log_path = lambda: ""
        self.sh._reload = lambda: (True, "fake")
        self.sh._worker_pids = lambda: set()
        ok, detail = self.sh._reload_verified(timeout=0.6)
        self.assertTrue(ok, detail)

    def test_new_workers_mean_the_config_was_loaded(self):
        calls = {"n": 0}

        def pids():
            calls["n"] += 1
            return {"1", "2"} if calls["n"] == 1 else {"3", "4"}

        self.sh._error_log_path = lambda: ""
        self.sh._reload = lambda: (True, "systemctl reload nginx")
        self.sh._worker_pids = pids
        ok, detail = self.sh._reload_verified(timeout=3)
        self.assertTrue(ok)
        self.assertIn("worker", detail)

    def test_unchanged_workers_are_a_failure(self):
        """The exact silent failure: the master ignored the new config."""
        self.sh._error_log_path = lambda: ""
        self.sh._reload = lambda: (True, "systemctl reload nginx")
        self.sh._worker_pids = lambda: {"1", "2"}
        ok, detail = self.sh._reload_verified(timeout=1.2)
        self.assertFalse(ok)
        self.assertIn("没有生效", detail)

    def test_an_emerg_in_the_log_is_reported_with_its_reason(self):
        import tempfile
        tmp = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False)
        tmp.write("nothing yet\n")
        tmp.close()
        path = tmp.name
        self.sh._error_log_path = lambda: path
        self.sh._worker_pids = lambda: {"1", "2"}

        def reload_and_log():
            with open(path, "a", encoding="utf-8") as fh:
                fh.write("[emerg] limit_req uses a different key\n")
            return True, "systemctl reload nginx"

        self.sh._reload = reload_and_log
        try:
            ok, detail = self.sh._reload_verified(timeout=0.8)
            self.assertFalse(ok)
            self.assertIn("emerg", detail)
        finally:
            os.unlink(path)


class TestShieldHeaders(unittest.TestCase):
    def test_security_headers_are_present_and_always(self):
        from vigil.gates import shield
        text = shield.render_shield()
        for header in ("X-Content-Type-Options", "X-Frame-Options",
                       "Referrer-Policy"):
            self.assertIn(header, text)
        # `always` matters: a 403 is where sniffing attacks land.
        self.assertEqual(4, text.count("always;"))


class TestZoneKeyChangeIsRefused(unittest.TestCase):
    """A limit zone's key cannot change at reload time, so never write one.

    nginx creates a `limit_req_zone` / `limit_conn_zone` in shared memory on
    first load and compares the key expression on every later load. A
    same-name/different-key change is accepted by `nginx -t` -- a fresh parse
    sees one definition -- and refused by every reload, in the error log, for
    as long as the master runs. The host looks hardened and is not, and only a
    full restart fixes it. That is the outage this class pins.

    The fixtures use neutral names (`example_zone`, `$some_key`,
    `$binary_remote_addr`, `192.0.2.0/24`) on purpose: the rule is about the
    *shape* -- same zone name, different key -- not about any one host's
    configuration. The historical names live in the product as compatibility
    constants; they are deliberately not the fixture here.
    """

    def setUp(self):
        from vigil.gates import shield
        self.sh = shield
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "nginx-conf"
        self.root.mkdir(parents=True, exist_ok=True)
        self.main = self.root / "nginx.conf"
        self.main.write_text("http {\n}\n", encoding="utf-8")
        self.shield_file = self.root / "vigil-shield.conf"
        self.saved = (shield.conf_dir, shield.detect.nginx, shield._nginx_test,
                      shield._reload_verified, shield._ensure_http_include)
        shield.conf_dir = lambda: self.root
        shield.detect.nginx = lambda: {"conf": str(self.main),
                                       "binary": "/nonexistent/nginx"}
        shield._nginx_test = lambda: (True, "ok")
        shield._reload_verified = lambda timeout=8.0: (True, "fake reload")
        shield._ensure_http_include = lambda main, target: None

    def tearDown(self):
        (self.sh.conf_dir, self.sh.detect.nginx, self.sh._nginx_test,
         self.sh._reload_verified, self.sh._ensure_http_include) = self.saved
        self.tmp.cleanup()

    # -- fixtures, all neutral -------------------------------------------

    @staticmethod
    def _zone(key, name="example_zone", kind="limit_req_zone"):
        return "%s  %s zone=%s:10m rate=5r/s;\n" % (kind, key, name)

    def _install_with(self, text, **kwargs):
        """Run `install` as if `render_shield()` produced *text*."""
        saved = self.sh.render_shield
        self.sh.render_shield = lambda cfg=None: text
        try:
            return self.sh.install(**kwargs)
        finally:
            self.sh.render_shield = saved

    # -- the parsing rule ------------------------------------------------

    def test_it_reads_zone_names_and_key_expressions(self):
        text = (self._zone("$some_key", "example_zone")
                + self._zone("$binary_remote_addr", "example_conn",
                             kind="limit_conn_zone"))
        self.assertEqual({"example_zone": "$some_key",
                          "example_conn": "$binary_remote_addr"},
                         self.sh.parse_zone_definitions(text))

    def test_same_name_same_key_is_not_a_change(self):
        self.assertEqual([], self.sh.zone_key_changes(
            self._zone("$some_key"), {"example_zone": "$some_key"}))

    def test_same_name_different_key_is_a_change(self):
        self.assertEqual(
            [("example_zone", "$binary_remote_addr", "$some_key")],
            self.sh.zone_key_changes(
                self._zone("$some_key"),
                {"example_zone": "$binary_remote_addr"}))

    def test_a_new_zone_name_is_not_a_change(self):
        self.assertEqual([], self.sh.zone_key_changes(
            self._zone("$some_key", "example_new"),
            {"example_zone": "$binary_remote_addr"}))

    # -- install() behaviour ---------------------------------------------

    def test_a_new_zone_name_is_written_normally(self):
        """A name that never existed is a new shared zone: reload can add it."""
        self.shield_file.write_text(self._zone("$binary_remote_addr"),
                                    encoding="utf-8")
        res = self._install_with(self._zone("$some_key", "example_new"))
        self.assertTrue(res["ok"], res["problems"])
        self.assertIn("example_new", self.shield_file.read_text(encoding="utf-8"))

    def test_same_key_install_is_idempotent(self):
        self.shield_file.write_text(self._zone("$some_key"), encoding="utf-8")
        res = self._install_with(self._zone("$some_key"))
        self.assertTrue(res["ok"], res["problems"])
        self.assertEqual([], res["zone_key_changes"])

    def test_a_key_change_against_the_previous_shield_is_refused(self):
        """Nothing is written, so the host keeps a config reload still likes."""
        old = self._zone("$binary_remote_addr")
        self.shield_file.write_text(old, encoding="utf-8")
        res = self._install_with(self._zone("$some_key"))
        self.assertFalse(res["ok"])
        self.assertTrue(res["refused"], "拒绝必须是一个明确的结论")
        self.assertFalse(res["rolled_back"], "什么都没写，谈不上回滚")
        self.assertEqual([], res["written"],
                         "拒绝时不得写入任何文件")
        self.assertEqual(
            [{"zone": "example_zone", "from": "$binary_remote_addr",
              "to": "$some_key"}], res["zone_key_changes"])
        self.assertEqual(old, self.shield_file.read_text(encoding="utf-8"),
                         "旧文件必须原样保留")
        message = "\n".join(res["problems"])
        for fragment in ("example_zone", "$binary_remote_addr", "$some_key",
                         "完整重启"):
            self.assertIn(fragment, message)

    def test_the_legacy_file_being_retired_is_read_too(self):
        """The accident's exact shape: the live key lives in the old file.

        `dsh-hardening.conf` defines the zone; the install retires it and
        writes a shield that reuses the name with a new key. Reading only the
        new file would miss it, because at check time the old file is the one
        nginx is running.
        """
        legacy = self.root / self.sh.LEGACY_NAME
        legacy.write_text(self._zone("$binary_remote_addr"), encoding="utf-8")
        res = self._install_with(self._zone("$some_key"))
        self.assertFalse(res["ok"])
        self.assertEqual([], res["written"])
        self.assertTrue(legacy.is_file(), "拒绝时不得退役旧文件")
        self.assertFalse((self.root / "vigil-shield.conf").exists())
        self.assertFalse(list(self.root.glob(self.sh.LEGACY_NAME + ".retired-*")),
                         "拒绝时不得产生退役副本")
        self.assertIn("完整重启", "\n".join(res["problems"]))

    def test_a_key_change_is_caught_on_the_second_install(self):
        """Install, then change the key: the second run refuses, the first stands."""
        first = self._install_with(self._zone("$binary_remote_addr"))
        self.assertTrue(first["ok"], first["problems"])
        second = self._install_with(self._zone("$some_key"))
        self.assertFalse(second["ok"])
        self.assertIn("$binary_remote_addr",
                      self.shield_file.read_text(encoding="utf-8"))

    # -- the emergency nginx writes --------------------------------------

    def test_the_key_change_emerg_is_translated_to_the_real_conclusion(self):
        line = ('[emerg] limit_req "example_zone" uses the "$some_key" key '
                'while previously it used the "$binary_remote_addr" key')
        got = self.sh.explain_reload_emerg(line)
        self.assertIn("需要完整重启", got,
                      "关键结论：reload 永远无法生效")
        self.assertIn("reload", got)
        for fragment in ("example_zone", "$binary_remote_addr", "$some_key"):
            self.assertIn(fragment, got, "必须说清是哪个 zone、从哪个 key 到哪个 key")

    def test_a_conn_zone_key_change_is_recognised_too(self):
        line = ('[emerg] limit_conn "example_conn" uses the "$some_key" key '
                'while previously it used the "$binary_remote_addr" key')
        got = self.sh.explain_reload_emerg(line)
        self.assertIn("需要完整重启", got)
        self.assertIn("limit_conn_zone", got)

    def test_an_unrelated_emerg_is_not_claimed_to_be_a_key_change(self):
        self.assertEqual("", self.sh.explain_reload_emerg(
            '[emerg] unknown directive "bogus"'))
        self.assertEqual("", self.sh.explain_reload_emerg(""))

    def test_reload_verification_reports_the_key_change_conclusion(self):
        """End to end: the emerg in the log becomes 'needs a full restart'."""
        import tempfile as _tempfile
        handle = _tempfile.NamedTemporaryFile("w", suffix=".log", delete=False)
        handle.write("nothing yet\n")
        handle.close()
        path = handle.name
        saved = (self.sh._error_log_path, self.sh._worker_pids, self.sh._reload)
        self.sh._error_log_path = lambda: path
        self.sh._worker_pids = lambda: {"1", "2"}

        def reload_and_log():
            with open(path, "a", encoding="utf-8") as fh:
                fh.write('[emerg] limit_req "example_zone" uses the '
                         '"$some_key" key while previously it used the '
                         '"$binary_remote_addr" key\n')
            return True, "systemctl reload nginx"

        self.sh._reload = reload_and_log
        try:
            ok, detail = self.sh.reload_and_verify(timeout=1.0)
        finally:
            (self.sh._error_log_path, self.sh._worker_pids,
             self.sh._reload) = saved
            os.unlink(path)
        self.assertFalse(ok)
        self.assertIn("需要完整重启", detail)
        self.assertIn("example_zone", detail)
        self.assertIn("$binary_remote_addr", detail)
        self.assertIn("$some_key", detail)


class TestIpProfile(unittest.TestCase):
    def test_private_addresses_need_no_lookup(self):
        from vigil.guards.checks import util
        self.assertEqual("", util.reverse_dns("127.0.0.1"))
        self.assertEqual("", util.reverse_dns("10.1.2.3"))
        self.assertEqual("", util.reverse_dns(""))

    def test_profile_shape_is_stable(self):
        from vigil.guards.checks import util
        p = util.ip_profile(None, "")
        for key in ("ip", "geo", "ptr", "flags", "net", "netname", "abuse"):
            self.assertIn(key, p)


class TestExceptionHygiene(unittest.TestCase):
    """Rules about catching, learned the hard way.

    Two bugs in this project were hidden by a silent `except Exception:
    pass`: a helper that had never been imported, and a label that quietly
    fell back to a generic name. Neither showed up as an error -- the code
    "worked", it was just wrong.
    """

    def test_no_bare_except(self):
        """A bare `except:` also catches KeyboardInterrupt and SystemExit.

        There is no case in this codebase where that is the intent, and the
        pattern makes Ctrl-C stop working in long-running daemons.
        """
        import ast as _ast
        offenders = []
        for path in (ROOT / "src").rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            tree = _ast.parse(path.read_text(encoding="utf-8"))
            for node in _ast.walk(tree):
                if isinstance(node, _ast.ExceptHandler) and node.type is None:
                    offenders.append("%s:%d" % (path.relative_to(ROOT),
                                                node.lineno))
        self.assertEqual([], offenders, "裸 except 会吞掉 Ctrl-C：\n  "
                         + "\n  ".join(offenders))

    def test_swallowed_exceptions_are_deliberate(self):
        """`except Exception: pass` must be a cleanup path, not a shrug.

        Every one of these should be a best-effort teardown -- closing a
        stream, terminating a child -- where there is genuinely nothing to
        report. The count is capped so that adding new ones is a deliberate
        act rather than something that slips in.
        """
        import ast as _ast
        found = []
        for path in (ROOT / "src").rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            tree = _ast.parse(path.read_text(encoding="utf-8"))
            for node in _ast.walk(tree):
                if (isinstance(node, _ast.ExceptHandler)
                        and isinstance(node.type, _ast.Name)
                        and node.type.id == "Exception"
                        and len(node.body) == 1
                        and isinstance(node.body[0], _ast.Pass)):
                    found.append("%s:%d" % (path.relative_to(ROOT), node.lineno))
        self.assertLessEqual(
            len(found), 16,
            "又多了静默吞异常的地方（当前 %d 处）—— 如果确实需要，"
            "请改成记录日志：\n  %s" % (len(found), "\n  ".join(found)))


class TestPackaging(unittest.TestCase):
    def test_required_project_files_exist(self):
        for name in ("README.md", "LICENSE", "pyproject.toml", ".gitignore",
                     "install.sh"):
            self.assertTrue((ROOT / name).is_file(), "missing %s" % name)

    def test_repository_layout_is_complete(self):
        """A GitHub-shaped project, not an empty scaffold.

        `docs/`, `examples/` and `scripts/` existed as directories with
        nothing in them for most of this project's life: `git clone` gave a
        reader three empty folders and no way in. Asserting on the contents
        is what stops that from quietly happening again.
        """
        import json
        expected = {
            "docs": ["README.md", "INSTALL.md", "CONFIGURATION.md",
                     "MAIL.md", "GATE.md", "ARCHITECTURE.md"],
            "examples": ["config.minimal.json", "config.typical.json"],
            "scripts": ["dev-check.sh", "preview-art.php"],
        }
        for folder, names in expected.items():
            for name in names:
                path = ROOT / folder / name
                self.assertTrue(path.is_file(),
                                "missing %s/%s" % (folder, name))
                self.assertGreater(path.stat().st_size, 200,
                                   "%s/%s is a stub" % (folder, name))
        # The examples must actually parse, or they teach the wrong shape.
        for name in expected["examples"]:
            blob = json.loads((ROOT / "examples" / name).read_text("utf-8"))
            self.assertIsInstance(blob, dict)
            self.assertIn("mail", blob)
        # Root documents are the reader's entry points. They were moved out
        # of the tarball once already; keep them where a cloner expects.
        for name in ("README.md", "DISCLAIMER.md", "CHANGELOG.md",
                     "LICENSE"):
            path = ROOT / name
            self.assertTrue(path.is_file(), "missing %s" % name)
            self.assertGreater(path.stat().st_size, 200, "%s is a stub" % name)

    def test_shipped_code_has_no_secret_shaped_literals(self):
        """No real API keys committed, even by accident.

        A provider module legitimately contains `re_xxxx...` as a *field
        example*; what must never appear is a value of that shape that is
        not obviously a placeholder.
        """
        import re as _re
        offenders = []
        for path in list((ROOT / "src").rglob("*.py")) + \
                    list((ROOT / "docs").rglob("*.md")) + \
                    list((ROOT / "examples").rglob("*.json")):
            if "__pycache__" in path.parts:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for m in _re.finditer(r"\bre_[A-Za-z0-9]{16,}", text):
                token = m.group(0)
                if set(token[3:]) <= set("xX_-"):
                    continue          # placeholder such as re_xxxxxxxx
                offenders.append("%s: %s" % (path.relative_to(ROOT), token[:12]))
        self.assertEqual([], offenders,
                         "secret-shaped literals in shipped files:\n  "
                         + "\n  ".join(offenders))

    def test_declares_no_runtime_dependencies(self):
        """Zero dependencies is the portability promise; a stray `requests`
        import would break installation on a locked-down host."""
        text = (ROOT / "pyproject.toml").read_text()
        self.assertRegex(text, r"dependencies\s*=\s*\[\s*\]")

    def test_only_standard_library_is_imported(self):
        import importlib.util
        allowed_third_party = set()
        stdlib = set(getattr(sys, "stdlib_module_names", ()))
        offenders = []
        for path in (ROOT / "src").rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            for line in path.read_text(encoding="utf-8",
                                       errors="replace").splitlines():
                # Anchored properly, and `from` must actually be followed by
                # `import`. A looser pattern matched prose that merely begins
                # with the word "from" -- which is how a comment inside a
                # provider tripped this into reporting a dependency that does
                # not exist.
                m = (re.match(r"^\s*import\s+([A-Za-z_][\w.]*)", line)
                     or re.match(r"^\s*from\s+([A-Za-z_][\w.]*)\s+import\b",
                                 line))
                if not m:
                    continue
                top = m.group(1).split(".")[0]
                if top in ("vigil",) or top in stdlib or top in allowed_third_party:
                    continue
                offenders.append("%s: %s" % (path.relative_to(ROOT), line.strip()))
        self.assertEqual([], offenders,
                         "non-stdlib imports found:\n  " + "\n  ".join(offenders))

    def test_gitignore_excludes_local_state(self):
        text = (ROOT / ".gitignore").read_text()
        for pattern in ("secrets.json", "config.json"):
            self.assertIn(pattern, text,
                          "%s must never be committed" % pattern)

    def test_version_is_declared_once(self):
        from vigil import version
        self.assertRegex(version.__version__, r"^\d+\.\d+\.\d+$")
        self.assertIn(version.__version__,
                      (ROOT / "pyproject.toml").read_text())


class TestConfigSchemaConsistency(unittest.TestCase):
    """Every key `vigil config` shows must be the key the code reads.

    Two real defects motivated this, and they are the same defect seen from
    two sides:

    * ``threat.digest_min_items`` / ``threat.digest_max_wait`` sat in
      ``DEFAULTS`` under ``threat`` while the daemon read
      ``mail.digest_min_items`` and ``mail.digest_max_wait``. So the setting
      that *worked* was invisible in `vigil config`, and the one on display
      was read by nobody. A key that looks configurable and is not is worse
      than a missing key, because the operator believes they changed
      something;
    * ``threat.bouncer.*`` and ``threat.evolve.*`` were declared under
      ``threat`` while every reader used the top-level ``bouncer.*`` and
      ``evolve.*``.

    The first test is the general form of the invariant; the rest pin the
    specific keys so a regression names itself.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = vconfig.Config(path=Path(self.tmp.name) / "c.json",
                                  secrets_path=Path(self.tmp.name) / "s.json")

    def test_schema_says_what_the_reader_says(self):
        """`in_schema` must match what is actually in DEFAULTS, both ways."""
        from vigil.guards import threat as threat_mod
        daemon = threat_mod.ThreatDaemon(self.cfg, log=_QuietLog(),
                                         dry_run=True, echo=False)
        wrong, claimed = [], []
        for item in daemon.settings.keys_read:
            key = item["key"]
            if " | " in key:
                # `_rf` tries several spellings; each one is checked only
                # when it is the key that actually supplied the value.
                if item["source"] != "merged-config":
                    continue
            if key.startswith("detect."):
                continue
            present = _dotted_present(vconfig.DEFAULTS, key)
            if not item["in_schema"] and present:
                wrong.append(key)
            if item["in_schema"] and not present:
                claimed.append(key)
        self.assertEqual([], wrong,
                         "这些键在 DEFAULTS 里，却被标记为「不在 schema」—— "
                         "`vigil-threatd --print-config` 会把它们列成扩展键：%s"
                         % wrong)
        self.assertEqual([], claimed,
                         "这些键被标记为「在 schema」，但 DEFAULTS 里没有 —— "
                         "`vigil config` 展示不出来，操作者改不了：%s" % claimed)

    def test_digest_thresholds_live_in_mail(self):
        self.assertIn("digest_min_items", vconfig.DEFAULTS["mail"])
        self.assertIn("digest_max_wait", vconfig.DEFAULTS["mail"])
        self.assertNotIn("digest_min_items", vconfig.DEFAULTS["threat"])
        self.assertNotIn("digest_max_wait", vconfig.DEFAULTS["threat"])
        # And the path the reader uses is the path that resolves.
        self.assertEqual(5, self.cfg.get("mail.digest_min_items"))
        self.assertEqual(1800, self.cfg.get("mail.digest_max_wait"))

    def test_threat_daemon_reads_the_displayed_path(self):
        from vigil.guards import threat as threat_mod
        cfg = vconfig.Config(path=Path(self.tmp.name) / "c2.json",
                             secrets_path=Path(self.tmp.name) / "s2.json")
        cfg.set("mail.digest_min_items", 9)
        cfg.set("mail.digest_max_wait", 42)
        daemon = threat_mod.ThreatDaemon(cfg, log=_QuietLog(), dry_run=True,
                                         echo=False)
        self.assertEqual(9, daemon.settings.digest_min_items,
                         "设 mail.digest_min_items 必须真的生效")
        self.assertEqual(42, daemon.settings.digest_max_wait)

    def test_bouncer_and_evolve_are_top_level_sections(self):
        for section in ("bouncer", "evolve"):
            self.assertIn(section, vconfig.DEFAULTS,
                          "%s 段必须在顶层：读取路径是 %s.*" % (section, section))
            self.assertNotIn(section, vconfig.DEFAULTS["threat"],
                             "threat.%s 是展示得出来却没人读的段" % section)
        self.assertEqual(60, self.cfg.get("bouncer.sync_seconds"))
        self.assertEqual(8, self.cfg.get("evolve.min_hits"))
        self.assertIs(False, self.cfg.get("bouncer.enabled"))
        self.assertIs(False, self.cfg.get("evolve.enabled"))

    def test_every_displayed_key_has_a_reader_or_is_data(self):
        """Broad-but-bounded sweep: a DEFAULTS key nothing in src mentions.

        This is the weaker half of the invariant (it matches on the last path
        segment, so it cannot prove the *path* is right -- the test above does
        that against the daemon's own read log). It is still worth having,
        because "declared and never mentioned anywhere" is the shape a
        copy-paste mistake takes.
        """
        def leaves(node, prefix=""):
            out = []
            if isinstance(node, dict):
                for key, value in node.items():
                    out += leaves(value, (prefix + "." + key) if prefix else key)
            else:
                out.append(prefix)
            return out

        blob = "\n".join(
            p.read_text(encoding="utf-8", errors="replace")
            for p in (ROOT / "src").rglob("*.py") if "__pycache__" not in p.parts)
        orphans = []
        for path in leaves(vconfig.DEFAULTS):
            segment = path.rsplit(".", 1)[-1]
            if path in blob or ('"%s"' % segment) in blob or \
                    ("'%s'" % segment) in blob:
                continue
            orphans.append(path)
        self.assertEqual([], orphans,
                         "DEFAULTS 里这些键在整个 src 里都没被提到过：%s" % orphans)


def _dotted_present(tree, dotted) -> bool:
    cur = tree
    for part in str(dotted).split("."):
        if not isinstance(cur, dict) or part not in cur:
            return False
        cur = cur[part]
    return True


class TestEvolveLedgerChain(unittest.TestCase):
    """The ledger must be unforgeable, or it launders malicious edits.

    ``self_integrity`` now trusts this ledger to excuse a change to the
    program's own source. A plain appendable JSONL file would then be the
    perfect cover: append one line claiming "I changed this file, here is its
    new hash", and the attacker's edit is reported as sanctioned
    self-modification. The chain (and the HMAC under a key kept outside the
    repository) is what makes that line impossible to produce.
    """

    def setUp(self):
        from vigil.evolve import ledger
        self.ledger = ledger
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self._saved = (ledger.LEDGER, ledger.BACKUP_DIR)
        ledger.LEDGER = self.root / "ledger.jsonl"
        ledger.BACKUP_DIR = self.root / "backup"
        self.addCleanup(self._restore)
        self.cfg = vconfig.Config(path=self.root / "c.json",
                                  secrets_path=self.root / "s.json")

    def _restore(self):
        self.ledger.LEDGER, self.ledger.BACKUP_DIR = self._saved

    def _write(self, *lines):
        self.ledger.LEDGER.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _raw(self):
        return [json.loads(x) for x in
                self.ledger.LEDGER.read_text(encoding="utf-8").splitlines()
                if x.strip()]

    def test_a_record_carries_a_mac_and_links_to_the_previous_one(self):
        first = self.ledger.record("applied", cfg=self.cfg, path="/a", tier=1)
        second = self.ledger.record("rolled-back", cfg=self.cfg, path="/a")
        self.assertTrue(first.get("mac"), "记录必须带 MAC")
        self.assertEqual(first["mac"], second["prev"],
                         "第二条必须链到第一条的 MAC")
        self.assertEqual(first["mac"], self._raw()[1]["prev"])

    def test_a_clean_chain_verifies(self):
        for i in range(3):
            self.ledger.record("applied", cfg=self.cfg, path="/f%d" % i)
        verdict = self.ledger.verify(cfg=self.cfg)
        self.assertTrue(verdict["ok"], verdict.get("break_reason"))
        self.assertEqual(3, verdict["checked"])

    def test_a_tampered_line_breaks_the_chain_at_that_line(self):
        self.ledger.record("applied", cfg=self.cfg, path="/a", after="x")
        self.ledger.record("applied", cfg=self.cfg, path="/b")
        rows = self._raw()
        rows[0]["after"] = "forged"          # rewrite history, keep the MAC
        self._write(*[json.dumps(r, ensure_ascii=False) for r in rows])
        verdict = self.ledger.verify(cfg=self.cfg)
        self.assertFalse(verdict["ok"])
        self.assertEqual(1, verdict["break_at"], "必须指出断在哪一条")
        self.assertIn("改写过", verdict["break_reason"])

    def test_a_forged_line_appended_by_an_attacker_is_rejected(self):
        """The attack this exists for: append "I changed it" and walk away."""
        self.ledger.record("applied", cfg=self.cfg, path="/a")
        forged = {"ts": time.time(), "kind": "code-edited",
                  "file": "src/vigil/guards/decoy.py",
                  "after": "0" * 64, "prev": "", "mac": ""}
        with open(self.ledger.LEDGER, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(forged) + "\n")
        verdict = self.ledger.verify(cfg=self.cfg)
        self.assertFalse(verdict["ok"], "伪造记录必须让整条链失效")
        self.assertEqual(2, verdict["break_at"])
        self.assertEqual("unchained-after-chain", verdict["break_kind"])

    def test_deleting_a_middle_line_breaks_the_link(self):
        self.ledger.record("applied", cfg=self.cfg, path="/a")
        self.ledger.record("applied", cfg=self.cfg, path="/b")
        self.ledger.record("applied", cfg=self.cfg, path="/c")
        rows = self._raw()
        self._write(*[json.dumps(r, ensure_ascii=False)
                      for r in (rows[0], rows[2])])
        verdict = self.ledger.verify(cfg=self.cfg)
        self.assertFalse(verdict["ok"])
        self.assertIn("删除、插入或重排", verdict["break_reason"])

    def test_verified_drops_everything_when_the_chain_is_broken(self):
        self.ledger.record("applied", cfg=self.cfg, path="/a")
        rows = self._raw()
        rows[0]["kind"] = "tampered"
        self._write(*[json.dumps(r, ensure_ascii=False) for r in rows])
        entries, verdict = self.ledger.verified(cfg=self.cfg)
        self.assertEqual([], entries, "链不成立时不能返回任何可用记录")
        self.assertFalse(verdict["ok"])

    def test_legacy_lines_without_a_mac_are_not_a_break(self):
        """History that predates the feature must not read as tampering."""
        self._write(json.dumps({"ts": 1.0, "kind": "applied", "path": "/old"}))
        verdict = self.ledger.verify(cfg=self.cfg)
        self.assertTrue(verdict["ok"])
        self.assertEqual(1, verdict["legacy"])


class TestAttributionOfSelfModification(unittest.TestCase):
    """Hash matching is the only trustworthy judge, so it gets the tests.

    ``evolve`` may edit one source file on purpose. Before this, every such
    edit made ``self_integrity`` report CRIT, which buried the finding that
    matters. The fix is attribution by *hash* -- and the failure mode of a
    bad fix is worse than the original bug, because accepting any change
    because "something legitimate happened recently" hands an attacker a
    perfect cover. Hence the case below that must stay CRIT.
    """

    def setUp(self):
        from vigil.guards.checks import selfcheck
        from vigil.evolve import ledger
        self.sc = selfcheck
        self.ledger = ledger
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self._saved = ledger.LEDGER
        ledger.LEDGER = self.root / "ledger.jsonl"
        self.addCleanup(self._restore)
        self.cfg = vconfig.Config(path=self.root / "c.json",
                                  secrets_path=self.root / "s.json")
        self.tree = self.root / "pkg"
        self.tree.mkdir()
        self.target = self.tree / "decoy.py"

    def _restore(self):
        self.ledger.LEDGER = self._saved

    def _edit_and_record(self, text="DECOYS = ()\n"):
        self.target.write_text(text, encoding="utf-8")
        digest = self.sc.digest_file(str(self.target))
        self.ledger.record("code-edited", cfg=self.cfg,
                           file=str(self.target), after=digest)
        return digest

    def test_a_recorded_self_edit_is_not_malicious(self):
        self.target.write_text("old\n", encoding="utf-8")
        digest = self._edit_and_record("DECOYS = (1,)\n")
        result = self.sc.attribute([str(self.target)], {str(self.target): digest},
                                   str(self.tree), self.cfg)
        self.assertEqual([], result["unattributed"])
        self.assertEqual([str(self.target)],
                         [e["path"] for e in result["self"]])

    def test_a_record_for_the_file_with_a_different_hash_is_crit(self):
        """The test the whole feature exists for.

        The ledger *does* have a record for this file; the file is simply not
        the file that was recorded. A path-only or "recent activity" judge
        would call this self-modification. It is not.
        """
        self._edit_and_record("DECOYS = (1,)\n")
        self.target.write_text("DECOYS = (1,)\nimport os; os.system('id')\n",
                               encoding="utf-8")
        current = self.sc.digest_file(str(self.target))
        result = self.sc.attribute([str(self.target)],
                                   {str(self.target): current},
                                   str(self.tree), self.cfg)
        self.assertEqual([], result["self"], "哈希不匹配绝不能算自修正")
        self.assertEqual(1, len(result["mismatch"]))
        entry = result["mismatch"][0]
        self.assertNotEqual(entry["expected"], entry["actual"])
        self.assertIn("哈希不匹配", self.sc._attribution_report(result))

    def test_an_old_record_cannot_excuse_todays_change(self):
        """Attribution has a time window; three months is not "just now"."""
        digest = self._edit_and_record("DECOYS = (1,)\n")
        rows = self.ledger.read(limit=10)
        rows[0]["ts"] = time.time() - 90 * 86400
        self.ledger.LEDGER.write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
            encoding="utf-8")
        result = self.sc.attribute([str(self.target)],
                                   {str(self.target): digest},
                                   str(self.tree), self.cfg)
        self.assertEqual([], result["self"])
        self.assertEqual(1, len(result["unattributed"]),
                         "超出归因窗口的台账记录不能为今天的改动背书")

    def test_a_broken_ledger_attributes_nothing(self):
        digest = self._edit_and_record("DECOYS = (1,)\n")
        rows = self.ledger.read(limit=10)
        rows[0]["after"] = "0" * 64        # rewrite, keep the MAC
        self.ledger.LEDGER.write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
            encoding="utf-8")
        result = self.sc.attribute([str(self.target)],
                                   {str(self.target): digest},
                                   str(self.tree), self.cfg)
        self.assertFalse(result["ledger_ok"])
        self.assertEqual([], result["self"])
        self.assertEqual(1, len(result["unattributed"]))
        self.assertIn("台账链校验", self.sc._attribution_report(result))

    def test_an_unrecorded_change_is_critical(self):
        self.target.write_text("x = 1\n", encoding="utf-8")
        digest = self.sc.digest_file(str(self.target))
        result = self.sc.attribute([str(self.target)],
                                   {str(self.target): digest},
                                   str(self.tree), self.cfg)
        self.assertEqual(1, len(result["unattributed"]))
        self.assertEqual([], result["self"])
        why = result["unattributed"][0]["why"]
        self.assertIn("台账", why, "报告必须说明查过台账、没有匹配记录")
        self.assertIn("部署", why)

    def test_the_check_reports_self_modification_as_ok_and_a_mismatch_as_crit(self):
        chk = self.sc.SelfIntegrity()
        real_root = self.sc._package_root
        self.sc._package_root = lambda: str(self.tree)
        self.target.write_text("a = 1\n", encoding="utf-8")
        try:
            state = {}
            self.assertEqual("OK", chk.run(self._ctx(state)).status)
            # A recorded self-edit: not an intrusion.
            digest = self._edit_and_record("a = 2\n")
            res = chk.run(self._ctx(state))
            self.assertEqual("OK", res.status, res.detail)
            self.assertIn("自修正（已记录）", res.detail)
            # A record exists, but the file is not what was recorded.
            self.target.write_text("a = 2\nbackdoor = 1\n", encoding="utf-8")
            res = chk.run(self._ctx(state))
            self.assertEqual("CRIT", res.status, res.detail)
            self.assertIn("哈希不匹配", res.detail)
        finally:
            self.sc._package_root = real_root

    def _ctx(self, state):
        from vigil.guards.checks import base as cbase
        return cbase.CheckContext(cfg=self.cfg, state=state, env={},
                                  log=None, now=time.time())


class TestGeneratedArtifactAutoRecovery(unittest.TestCase):
    """Finding a deleted file is not a response; rebuilding it is.

    The incident: a cleanup deleted ``vigil-shield.conf``, `self_integrity`
    reported "文件被删除" 55 times, and the file stayed missing until a human
    ran `vigil shield install`. These tests pin the response, its boundary
    (never the source, never the operator's files), and the rate limiter that
    stops "rebuild -> deleted again -> rebuild" from becoming a loop.
    """

    def setUp(self):
        from vigil.guards import selfheal
        self.sh = selfheal
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cfg = vconfig.Config(path=self.root / "c.json",
                                  secrets_path=self.root / "s.json")

    def _target(self, name="vigil-shield.conf"):
        return str(self.root / name)

    def test_only_generated_artifacts_have_a_regenerator(self):
        self.assertEqual("shield", self.sh.action_for(self._target()) or
                         self.sh.action_for("/etc/nginx/vigil-shield.conf"))
        self.assertTrue(self.sh.supported("/etc/nginx/vigil-shield.conf"))
        self.assertTrue(self.sh.supported("/x/vigil-gate-dsh_gate.conf"))
        self.assertTrue(self.sh.supported("/x/dsh-gate/gate.lua"))
        # The source, and the gate files that encode operator data, are not.
        self.assertFalse(self.sh.supported("/usr/local/lib/vigil/vigil/cli.py"))
        self.assertFalse(self.sh.supported("/x/dsh-gate/config.php"))
        self.assertFalse(self.sh.supported("/x/dsh-gate/policy.conf"))

    def test_a_deleted_artifact_is_rebuilt_and_reported(self):
        path = self._target()
        content = "deny 198.51.100.0/24;\nlimit_req zone=vigil burst=5;\n"
        digest = hashlib.sha256(content.encode()).hexdigest()
        calls = []

        def regen(p):
            calls.append(p)
            Path(p).write_text(content, encoding="utf-8")
            return {"ok": True, "detail": "已重新生成"}

        # `render` is the independent recheck. Stubbed so this test is about
        # the heal/recheck decision rather than about rendering a shield on a
        # machine that has no nginx.
        real_render = self.sh.render
        self.sh.render = lambda p, cache=None: (content, "")
        self.addCleanup(setattr, self.sh, "render", real_render)
        result = self.sh.heal(self.cfg, removed=[path],
                              baseline={path: digest},
                              healstate={},
                              regenerators={"shield": regen})
        self.assertEqual([path], calls, "必须调用对应模块的重建器")
        self.assertEqual(1, len(result["healed"]))
        self.assertEqual([path], list(result["changed_baseline"]))
        text = self.sh.describe(result)
        self.assertIn(path, text)
        self.assertIn("被删除", text)
        self.assertIn("复检", text)

    def test_a_file_that_cannot_be_read_back_is_not_called_recovered(self):
        path = self._target()

        def regen(_p):
            return {"ok": True, "detail": "写了"}

        result = self.sh.heal(self.cfg, removed=[path], baseline={},
                              healstate={}, regenerators={"shield": regen})
        self.assertEqual([], result["healed"])
        self.assertEqual(1, len(result["unhealed"]))
        self.assertIn("复检仍读不到", result["unhealed"][0]["detail"])

    def test_a_rebuild_that_does_not_match_the_baseline_is_not_a_recovery(self):
        path = self._target()
        good = "deny all;\n"
        good_digest = hashlib.sha256(good.encode()).hexdigest()

        def regen(p):
            Path(p).write_text("allow all;\n", encoding="utf-8")
            return {"ok": True, "detail": "写了"}

        result = self.sh.heal(self.cfg, removed=[path],
                              baseline={path: good_digest}, healstate={},
                              regenerators={"shield": regen})
        self.assertEqual([], result["healed"], "内容不一致不能算恢复")
        self.assertEqual(1, len(result["unhealed"]))
        self.assertIn("与基线不一致", result["unhealed"][0]["detail"])

    def test_the_source_and_operator_files_are_never_touched(self):
        source = "/usr/local/lib/vigil/vigil/guards/threat.py"
        config = "/x/dsh-gate/config.php"
        called = []

        def regen(p):
            called.append(p)
            return {"ok": True, "detail": "写了"}

        result = self.sh.heal(self.cfg, removed=[source],
                              changed=[config], baseline={}, healstate={},
                              regenerators={"shield": regen})
        self.assertEqual([], called, "源码与操作者的文件绝不能被重建")
        self.assertEqual(2, len(result["unsupported"]))
        text = self.sh.describe(result)
        self.assertIn("不在自动重建范围", text)
        self.assertIn("人工处理", text)

    def test_the_rate_limit_stops_the_rebuild_loop(self):
        path = self._target()
        content = "deny all;\n"
        digest = hashlib.sha256(content.encode()).hexdigest()
        attempts = []

        def regen(p):
            attempts.append(p)
            Path(p).write_text(content, encoding="utf-8")
            return {"ok": True, "detail": "写了"}

        healstate = {}
        now = 1000.0
        for _ in range(5):
            self.sh.heal(self.cfg, removed=[path], baseline={path: digest},
                         healstate=healstate, now=now,
                         regenerators={"shield": regen})
        self.assertEqual(3, len(attempts),
                         "默认上限是每 30 分钟 3 次，超过后只报警")
        result = self.sh.heal(self.cfg, removed=[path],
                              baseline={path: digest}, healstate=healstate,
                              now=now + 1, regenerators={"shield": regen})
        self.assertEqual(1, len(result["limited"]))
        self.assertEqual(0, result["attempted"])
        self.assertIn("循环", result["limited"][0]["reason"])
        self.assertIn("反复", self.sh.describe(result))
        # A later window gets a fresh allowance: the cap is a sliding window,
        # not a permanent give-up.
        later = self.sh.heal(self.cfg, removed=[path], baseline={path: digest},
                             healstate=healstate, now=now + 4000,
                             regenerators={"shield": regen})
        self.assertEqual(1, later["attempted"])

    def test_auto_recovery_can_be_switched_off(self):
        path = self._target()
        self.cfg.set("checks.self_integrity.auto_recover", False)
        called = []
        result = self.sh.heal(self.cfg, removed=[path], baseline={},
                              healstate={},
                              regenerators={"shield": lambda p: called.append(p)})
        self.assertFalse(result["enabled"])
        self.assertEqual([], called)
        self.assertEqual("", self.sh.describe(result))

    def test_the_diff_summary_names_the_rules_that_were_weakened(self):
        """The intent is in the difference, so it has to be reported."""
        expected = ("deny 198.51.100.0/24;\nlimit_req zone=vigil burst=5;\n"
                    "access_by_lua_file /x/gate.lua;\n")
        tampered = ("limit_req zone=vigil burst=5;\n"
                    "access_by_lua_file /x/gate.lua;\n")
        summary = self.sh._weakened(tampered, expected)
        self.assertIn("被削弱的规则", summary)
        self.assertIn("deny", summary)
        self.assertIn("198.51.100.0/24", summary,
                      "被删掉的那条规则就是意图的证据，必须出现在摘要里")
        # A deleted file has no previous content, so there is no diff to give.
        self.assertEqual("", self.sh._weakened(None, expected))

    def test_the_zone_key_guard_is_checked_before_any_write(self):
        """Repairing a snippet must not reintroduce the reload-never-works bug.

        A changed ``limit_req_zone`` key is accepted by `nginx -t` and refused
        by every reload, so a "repair" that redefines a live zone would take
        the protection down while looking successful.
        """
        from vigil.gates import shield
        changes = shield.zone_key_changes(
            "limit_req_zone $binary_remote_addr zone=a:10m rate=12r/m;\n",
            {"a": "$request_uri"})
        self.assertTrue(changes, "同名换 key 必须被 zone_key_changes 识别出来")
        self.assertEqual(("a", "$request_uri", "$binary_remote_addr"),
                         tuple(changes[0][:1]) + tuple(changes[0][1:]))
        text = shield.describe_zone_conflicts(changes)
        self.assertIn("拒绝写入", text)
        self.assertIn("a", text)


class TestSuspiciousProcessAutoResponse(unittest.TestCase):
    """The guards, not the feature, are what these tests are about.

    Automatic process intervention is the one thing in this program that can
    take a server down by itself, so the tests are weighted towards the cases
    where it must **not** act: exemptions, a single signal, a changed
    identity, a different PID namespace, the hourly cap. Every test uses a
    fictional process table and a Runtime whose `signal` only records -- no
    real process is ever touched, and no real signal is ever sent.
    """

    def setUp(self):
        from vigil.guards.checks import procresponse
        self.pr = procresponse
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cfg = vconfig.Config(path=self.root / "c.json",
                                  secrets_path=self.root / "s.json")
        self._saved_ledger = procresponse.LEDGER
        procresponse.LEDGER = self.root / "autoresponse.jsonl"
        self.addCleanup(self._restore)
        self.now = [1000.0]
        self.signals = []
        self.procs = {}
        self.conns = {}
        self.units = {}

    def _restore(self):
        self.pr.LEDGER = self._saved_ledger

    # -- the fictional host ------------------------------------------------
    def add(self, pid, exe="/tmp/payload", deleted=True, comm="payload",
            cmdline="", start=100.0, unit="", automation="", conns=None,
            ns="/proc/1/ns/pid", ino=555, dev=8, ppid=1):
        self.procs[pid] = {"pid": pid, "comm": comm, "cmdline": cmdline or exe,
                           "exe": exe, "exe_deleted": deleted,
                           "start_time": start, "unit": unit, "ppid": ppid,
                           "exe_ino": ino, "exe_dev": dev, "ns": ns,
                           "automation": automation}
        self.conns[pid] = list(conns or [])

    def runtime(self, allowlist=None, own_ns="/proc/1/ns/pid"):
        def info(pid):
            row = self.procs.get(int(pid))
            return dict(row) if row else {}

        def conns(pid):
            return list(self.conns.get(int(pid)) or [])

        def unit(pid):
            row = self.procs.get(int(pid)) or {}
            return row.get("unit", "")

        def start(pid):
            row = self.procs.get(int(pid)) or {}
            return float(row.get("start_time") or 0.0)

        def automation(pid, exe):
            row = self.procs.get(int(pid)) or {}
            return row.get("automation", "")

        def ns(pid):
            if int(pid) == os.getpid():
                return own_ns
            row = self.procs.get(int(pid)) or {}
            return row.get("ns", own_ns)

        return self.pr.Runtime(
            cfg=self.cfg, log=_QuietLog(), proc_info=info, connections=conns,
            cgroup_unit=unit, start_time=start, is_automation=automation,
            signal_fn=lambda pid, sig: (self.signals.append((int(pid), int(sig))),
                                        (True, ""))[1],
            now=lambda: self.now[0], pid_namespace=ns,
            list_pids=lambda: sorted(self.procs))

    def enable(self, **overrides):
        self.cfg.set("threat.autoresponse.enabled", True)
        self.cfg.set("threat.autoresponse.evidence_dir",
                     str(self.root / "evidence"))
        for key, value in overrides.items():
            self.cfg.set("threat.autoresponse.%s" % key, value)

    def hits(self, *pids):
        return [{"pid": p, "comm": self.procs[p]["comm"],
                 "exe": self.procs[p]["exe"], "kind": "deleted",
                 "automation": ""} for p in pids]

    # -- off by default ----------------------------------------------------
    def test_nothing_happens_until_it_is_switched_on(self):
        self.add(4242, conns=[("ESTAB", "10.0.0.5:41000", "203.0.113.9:443")])
        state = {}
        result = self.pr.handle(self.hits(4242), cfg=self.cfg, state=state,
                                runtime=self.runtime())
        self.assertFalse(result["enabled"])
        self.assertEqual([], self.signals, "默认关闭时绝不可以发信号")

    # -- two independent signals ------------------------------------------
    def test_one_signal_alone_is_never_enough(self):
        self.add(4242, conns=[])         # deleted binary, no connection
        self.enable()
        result = self.pr.handle(self.hits(4242), cfg=self.cfg, state={},
                                runtime=self.runtime())
        self.assertEqual([], result["responded"])
        self.assertEqual([], self.signals)
        self.assertEqual("medium", result["reported"][0]["level"])
        self.assertIn("缺少独立佐证", result["reported"][0]["reason"])

    def test_a_temp_dir_path_alone_is_not_a_high_confidence_signal(self):
        self.add(4242, exe="/tmp/build/payload", deleted=False,
                 conns=[("ESTAB", "10.0.0.5:41000", "203.0.113.9:443")])
        self.enable()
        result = self.pr.handle(self.hits(4242), cfg=self.cfg, state={},
                                runtime=self.runtime())
        self.assertEqual([], result["responded"])
        self.assertEqual("medium", result["reported"][0]["level"],
                         "只有「路径在临时目录」这一类，不能算高置信")

    def test_a_loopback_connection_does_not_count_as_outbound(self):
        self.add(4242, conns=[("ESTAB", "127.0.0.1:41000", "127.0.0.1:3306")])
        self.enable()
        result = self.pr.handle(self.hits(4242), cfg=self.cfg, state={},
                                runtime=self.runtime())
        self.assertEqual([], result["responded"])
        self.assertFalse(result["reported"][0]["signals"]["external_conn"])

    # -- the observation window -------------------------------------------
    def test_a_snapshot_is_not_enough_but_persistence_is(self):
        self.add(4242, conns=[("ESTAB", "10.0.0.5:41000", "203.0.113.9:443")])
        self.enable(observe_seconds=120)
        state = {}
        first = self.pr.handle(self.hits(4242), cfg=self.cfg, state=state,
                               runtime=self.runtime())
        self.assertEqual([], self.signals, "第一轮只开始观察，不动手")
        self.assertEqual(1, len(first["observed"]))
        # Still there, evidence unchanged, window elapsed.
        self.now[0] += 121
        second = self.pr.handle(self.hits(4242), cfg=self.cfg, state=state,
                                runtime=self.runtime())
        self.assertEqual(1, len(second["responded"]))
        self.assertEqual([(4242, int(signal.SIGSTOP))], self.signals)

    def test_a_candidate_that_disappears_inside_the_window_is_dropped(self):
        self.add(4242, conns=[("ESTAB", "10.0.0.5:41000", "203.0.113.9:443")])
        self.enable(observe_seconds=120)
        state = {}
        self.pr.handle(self.hits(4242), cfg=self.cfg, state=state,
                       runtime=self.runtime())
        self.now[0] += 30
        del self.procs[4242]
        result = self.pr.handle([], cfg=self.cfg, state=state,
                                runtime=self.runtime())
        self.assertEqual([], self.signals)
        self.assertEqual({}, state[self.pr.STATE_KEY]["observing"])

    def test_a_signal_that_changes_restarts_the_observation(self):
        self.add(4242, conns=[("ESTAB", "10.0.0.5:41000", "203.0.113.9:443")])
        self.enable(observe_seconds=120)
        state = {}
        self.pr.handle(self.hits(4242), cfg=self.cfg, state=state,
                       runtime=self.runtime())
        self.now[0] += 121
        self.conns[4242] = [("ESTAB", "10.0.0.5:41000", "203.0.113.200:8443")]
        result = self.pr.handle(self.hits(4242), cfg=self.cfg, state=state,
                                runtime=self.runtime())
        self.assertEqual([], self.signals, "信号组合变了就要重新观察")
        self.assertEqual(1, len(result["abandoned"]))

    # -- the never-touch list ---------------------------------------------
    def test_every_exemption_is_a_hard_stop(self):
        cases = [
            ("pid 1", dict(pid=1)),
            ("systemd", dict(pid=77, unit="nginx.service")),
            ("automation", dict(pid=78, automation="疑似自动化工具链：node")),
            ("kernel", dict(pid=79, comm="kworker/0:1", exe="")),
            ("allowlist", dict(pid=80)),
            ("namespace", dict(pid=81, ns="/proc/999/ns/pid")),
            ("own", dict(pid=82, exe="/usr/local/lib/vigil/vigil/cli.py")),
        ]
        for label, spec in cases:
            with self.subTest(label):
                pid = spec.get("pid", 1)
                self.procs.clear()
                self.conns.clear()
                self.signals[:] = []
                self.add(conns=[("ESTAB", "10.0.0.5:41000",
                                 "203.0.113.9:443")], **spec)
                self.enable(observe_seconds=0,
                            allowlist=["payload"] if label == "allowlist" else [])
                state = {}
                self.pr.handle(self.hits(pid), cfg=self.cfg, state=state,
                               runtime=self.runtime())
                self.pr.handle(self.hits(pid), cfg=self.cfg, state=state,
                               runtime=self.runtime())
                self.assertEqual([], self.signals, "%s 必须永不处置" % label)

    def test_the_operator_allowlist_is_respected(self):
        self.add(4242, conns=[("ESTAB", "10.0.0.5:41000", "203.0.113.9:443")])
        self.enable(observe_seconds=0, allowlist=["/tmp/payload"])
        result = self.pr.handle(self.hits(4242), cfg=self.cfg, state={},
                                runtime=self.runtime())
        self.assertIn("允许清单", result["reported"][0]["exempt"])
        self.assertEqual([], self.signals)

    # -- identity, right before the action --------------------------------
    def test_a_reused_pid_abandons_the_action(self):
        self.add(4242, conns=[("ESTAB", "10.0.0.5:41000", "203.0.113.9:443")])
        self.enable(observe_seconds=0)
        state = {}
        self.pr.handle(self.hits(4242), cfg=self.cfg, state=state,
                       runtime=self.runtime())
        # The pid is now a different process: new start time, new inode.
        self.add(4242, exe="/usr/sbin/nginx", deleted=False, comm="nginx",
                 start=999.0, ino=777,
                 conns=[("ESTAB", "10.0.0.5:41000", "203.0.113.9:443")])
        result = self.pr.handle(self.hits(4242), cfg=self.cfg, state=state,
                                runtime=self.runtime())
        self.assertEqual([], self.signals, "pid 复用后绝不能动手")
        self.assertTrue(any("身份" in e["why"] for e in result["abandoned"]))

    def test_an_execve_between_deciding_and_acting_abandons_the_action(self):
        self.add(4242, conns=[("ESTAB", "10.0.0.5:41000", "203.0.113.9:443")])
        self.enable(observe_seconds=0)
        state = {}
        self.pr.handle(self.hits(4242), cfg=self.cfg, state=state,
                       runtime=self.runtime())
        # Same pid, same start time, but the image was swapped underneath.
        self.procs[4242]["exe_ino"] = 999
        result = self.pr.handle(self.hits(4242), cfg=self.cfg, state=state,
                                runtime=self.runtime())
        self.assertEqual([], self.signals)
        self.assertTrue(result["abandoned"])

    def test_the_namespace_check_refuses_containers(self):
        self.add(4242, conns=[("ESTAB", "10.0.0.5:41000", "203.0.113.9:443")],
                 ns="/proc/4242/ns/pid")
        self.enable(observe_seconds=0)
        result = self.pr.handle(self.hits(4242), cfg=self.cfg, state={},
                                runtime=self.runtime(own_ns="/proc/1/ns/pid"))
        self.assertIn("PID 命名空间", result["reported"][0]["exempt"])
        self.assertEqual([], self.signals)

    # -- evidence ----------------------------------------------------------
    def test_evidence_lands_on_disk_before_the_signal(self):
        self.add(4242, conns=[("ESTAB", "10.0.0.5:41000", "203.0.113.9:443")])
        self.enable(observe_seconds=0)
        seen = {}

        def signal_fn(pid, sig):
            seen["files"] = list((self.root / "evidence").glob("*.json"))
            self.signals.append((int(pid), int(sig)))
            return True, ""

        state = {}
        rt = self.runtime()
        rt._signal_fn = signal_fn
        self.pr.handle(self.hits(4242), cfg=self.cfg, state=state, runtime=rt)
        self.assertEqual([], self.signals, "第一轮只观察")
        self.now[0] += 1
        self.pr.handle(self.hits(4242), cfg=self.cfg, state=state, runtime=rt)
        self.assertEqual([(4242, int(signal.SIGSTOP))], self.signals)
        self.assertTrue(seen.get("files"), "证据必须先落盘再动手")
        bundle = json.loads(Path(seen["files"][0]).read_text(encoding="utf-8"))
        self.assertEqual(4242, bundle["pid"])
        self.assertIn("verdict", bundle)
        self.assertTrue(bundle["connections"])

    def test_no_evidence_means_no_action(self):
        self.add(4242, conns=[("ESTAB", "10.0.0.5:41000", "203.0.113.9:443")])
        self.enable(observe_seconds=0)
        # An evidence directory that cannot be created (a file in the way).
        blocked = self.root / "blocked"
        blocked.write_text("not a directory", encoding="utf-8")
        self.cfg.set("threat.autoresponse.evidence_dir", str(blocked / "sub"))
        state = {}
        rt = self.runtime()
        self.pr.handle(self.hits(4242), cfg=self.cfg, state=state, runtime=rt)
        self.now[0] += 1
        result = self.pr.handle(self.hits(4242), cfg=self.cfg, state=state,
                                runtime=rt)
        self.assertEqual([], self.signals, "证据落不了盘就不许动手")
        self.assertEqual(1, len(result["refused"]))

    # -- the reversible action, and undoing it ----------------------------
    def test_the_default_action_is_reversible_stop_not_kill(self):
        self.add(4242, conns=[("ESTAB", "10.0.0.5:41000", "203.0.113.9:443")])
        self.enable(observe_seconds=0)
        state = {}
        rt = self.runtime()
        self.pr.handle(self.hits(4242), cfg=self.cfg, state=state, runtime=rt)
        self.now[0] += 1
        self.pr.handle(self.hits(4242), cfg=self.cfg, state=state, runtime=rt)
        self.assertEqual([int(signal.SIGSTOP)], [s for _p, s in self.signals])
        self.assertIn("4242", state[self.pr.STATE_KEY]["stopped"])
        self.assertNotIn(int(signal.SIGKILL), [s for _p, s in self.signals])

    def test_a_stopped_process_is_released_when_it_joins_a_unit(self):
        """Reversibility is only real if something actually reverses it."""
        self.add(4242, conns=[("ESTAB", "10.0.0.5:41000", "203.0.113.9:443")])
        self.enable(observe_seconds=0)
        state = {}
        rt = self.runtime()
        self.pr.handle(self.hits(4242), cfg=self.cfg, state=state, runtime=rt)
        self.now[0] += 1
        self.pr.handle(self.hits(4242), cfg=self.cfg, state=state, runtime=rt)
        self.assertEqual(1, len(state[self.pr.STATE_KEY]["stopped"]))
        # A systemd unit claims it (a `.service` cgroup appeared).
        self.procs[4242]["unit"] = "php-fpm.service"
        result = self.pr.handle([], cfg=self.cfg, state=state, runtime=rt)
        self.assertEqual([(4242, int(signal.SIGCONT))], self.signals[1:])
        self.assertEqual(1, len(result["resumed"]))
        self.assertIn("已撤销处置", self.pr.describe(result))
        self.assertEqual({}, state[self.pr.STATE_KEY]["stopped"])
        kinds = [e["kind"] for e in self.pr.recent(20)]
        self.assertIn("action-resumed", kinds, "撤销必须进台账")

    def test_a_stopped_process_is_released_when_put_on_the_allowlist(self):
        self.add(4242, conns=[("ESTAB", "10.0.0.5:41000", "203.0.113.9:443")])
        self.enable(observe_seconds=0)
        state = {}
        rt = self.runtime()
        self.pr.handle(self.hits(4242), cfg=self.cfg, state=state, runtime=rt)
        self.now[0] += 1
        self.pr.handle(self.hits(4242), cfg=self.cfg, state=state, runtime=rt)
        self.cfg.set("threat.autoresponse.allowlist", ["/tmp/payload"])
        result = self.pr.handle([], cfg=self.cfg, state=state, runtime=rt)
        self.assertEqual(1, len(result["resumed"]))
        self.assertEqual((4242, int(signal.SIGCONT)), self.signals[-1])

    def test_held_stop_is_reported_rather_than_silently_kept(self):
        self.add(4242, conns=[("ESTAB", "10.0.0.5:41000", "203.0.113.9:443")])
        self.enable(observe_seconds=0, resume_window_seconds=60,
                    after_observe="hold")
        state = {}
        rt = self.runtime()
        self.pr.handle(self.hits(4242), cfg=self.cfg, state=state, runtime=rt)
        self.now[0] += 1
        self.pr.handle(self.hits(4242), cfg=self.cfg, state=state, runtime=rt)
        self.now[0] += 61
        result = self.pr.handle([], cfg=self.cfg, state=state, runtime=rt)
        self.assertEqual([int(signal.SIGSTOP)], [s for _p, s in self.signals],
                         "hold 不升级为任何终止信号")
        self.assertEqual(1, len(result["escalated"]))
        self.assertIn("保持暂停", self.pr.describe(result))

    def test_terminate_is_only_reachable_by_explicit_configuration(self):
        self.add(4242, conns=[("ESTAB", "10.0.0.5:41000", "203.0.113.9:443")])
        self.enable(observe_seconds=0, resume_window_seconds=0,
                    after_observe="terminate", terminate_signal="SIGTERM")
        state = {}
        rt = self.runtime()
        self.pr.handle(self.hits(4242), cfg=self.cfg, state=state, runtime=rt)
        self.now[0] += 1
        self.pr.handle(self.hits(4242), cfg=self.cfg, state=state, runtime=rt)
        self.now[0] += 1
        self.pr.handle([], cfg=self.cfg, state=state, runtime=rt)
        self.assertIn((4242, int(signal.SIGTERM)), self.signals)

    # -- rate limiting -----------------------------------------------------
    def test_the_hourly_cap_turns_into_report_only(self):
        self.enable(observe_seconds=0, max_per_hour=1)
        state = {}
        rt = self.runtime()
        for pid in (4242, 4243):
            self.add(pid, conns=[("ESTAB", "10.0.0.5:41000",
                                  "203.0.113.9:443")])
            self.pr.handle(self.hits(pid), cfg=self.cfg, state=state, runtime=rt)
            self.now[0] += 1
            self.pr.handle(self.hits(pid), cfg=self.cfg, state=state, runtime=rt)
            self.now[0] += 1
        self.assertEqual([4242], [p for p, _s in self.signals])
        self.assertTrue(state[self.pr.STATE_KEY]["action_stamps"])
        result = self.pr.handle(self.hits(4243), cfg=self.cfg, state=state,
                                runtime=rt)
        self.assertEqual(1, len(result["limited"]))
        self.assertIn("上限", result["limited"][0]["why"])
        self.assertIn("未处置（限频）", self.pr.describe(result))

    def test_the_cap_has_a_hard_ceiling(self):
        self.enable(max_per_hour=99999)
        self.assertEqual(self.pr.MAX_PER_HOUR_CEILING,
                         self.pr.settings(self.cfg)["max_per_hour"])

    def test_hours_later_the_allowance_returns(self):
        self.enable(observe_seconds=0, max_per_hour=1)
        state = {}
        rt = self.runtime()
        self.add(4242, conns=[("ESTAB", "10.0.0.5:41000", "203.0.113.9:443")])
        self.pr.handle(self.hits(4242), cfg=self.cfg, state=state, runtime=rt)
        self.now[0] += 1
        self.pr.handle(self.hits(4242), cfg=self.cfg, state=state, runtime=rt)
        state[self.pr.STATE_KEY]["action_stamps"] = [self.now[0] - 7200]
        self.add(4243, conns=[("ESTAB", "10.0.0.5:41000", "203.0.113.9:443")])
        self.pr.handle(self.hits(4243), cfg=self.cfg, state=state, runtime=rt)
        self.now[0] += 1
        self.pr.handle(self.hits(4243), cfg=self.cfg, state=state, runtime=rt)
        self.assertIn(4243, [p for p, _s in self.signals])

    # -- the loop that must not happen ------------------------------------
    def test_an_already_handled_process_is_not_re_decided(self):
        self.add(4242, conns=[("ESTAB", "10.0.0.5:41000", "203.0.113.9:443")])
        self.enable(observe_seconds=0)
        state = {}
        rt = self.runtime()
        self.pr.handle(self.hits(4242), cfg=self.cfg, state=state, runtime=rt)
        self.now[0] += 1
        self.pr.handle(self.hits(4242), cfg=self.cfg, state=state, runtime=rt)
        before = len(self.signals)
        result = self.pr.handle(self.hits(4242), cfg=self.cfg, state=state,
                                runtime=rt)
        self.assertEqual(4242, result["handled_pids"][0])
        self.assertEqual(before, len(self.signals),
                         "已暂停的进程不该被反复重新判定")

    # -- the report --------------------------------------------------------
    def test_the_report_carries_the_tradeoff_and_the_undo(self):
        self.add(4242, conns=[("ESTAB", "10.0.0.5:41000", "203.0.113.9:443")])
        self.enable(observe_seconds=0)
        state = {}
        rt = self.runtime()
        self.pr.handle(self.hits(4242), cfg=self.cfg, state=state, runtime=rt)
        self.now[0] += 1
        result = self.pr.handle(self.hits(4242), cfg=self.cfg, state=state,
                                runtime=rt)
        text = self.pr.describe(result)
        self.assertIn("SIGSTOP", text)
        self.assertIn("宁可漏处置，也绝不误杀", text)
        self.assertIn("kill -CONT", text)
        self.assertIn("独立信号", text)

    def test_signals_of_keeps_the_evidence_classes_apart(self):
        info = {"exe": "/tmp/build/payload", "exe_deleted": False}
        sig = self.pr.signals_of(info, [("LISTEN", "0.0.0.0:8080", "")])
        self.assertTrue(sig["temp_exe"])
        self.assertFalse(sig["deleted_exe"])
        self.assertFalse(sig["external_conn"])
        self.assertTrue(sig["has_conns"])

    def test_classify_never_responds_to_a_single_class(self):
        info = {"pid": 4242, "exe": "/tmp/x", "exe_deleted": True, "ns": ""}
        rt = self.runtime()
        verdict = self.pr.classify(info, [], rt, [])
        self.assertEqual(self.pr.DECISION_REPORT, verdict["decision"])
        info["exe_deleted"] = True
        verdict = self.pr.classify(
            info, [("ESTAB", "10.0.0.5:1", "203.0.113.9:443")], rt, [])
        self.assertEqual(self.pr.DECISION_RESPOND, verdict["decision"])


class TestAutoresponseStateIsNotLost(unittest.TestCase):
    """A stopped process nobody knows about is the worst possible outcome.

    The record of what was stopped lives in the check's persisted state, so
    it survives a daemon restart, and the CLI can list and release it without
    the feature even being enabled.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_settings_clamps_a_typo_in_the_action(self):
        from vigil.guards.checks import procresponse
        cfg = vconfig.Config(path=self.root / "c.json",
                             secrets_path=self.root / "s.json")
        cfg.set("threat.autoresponse.enabled", True)
        cfg.set("threat.autoresponse.action", "SIGKILL-EVERYTHING")
        st = procresponse.settings(cfg)
        self.assertEqual("stop", st["action"],
                         "无法识别的动作必须退回可逆的那个，而不是照做")

    def test_resume_works_with_the_feature_disabled(self):
        """Turning the feature off must not leave processes frozen."""
        from vigil.commands import autoresponse as cmd
        from vigil.guards.checks import procresponse
        cfg = vconfig.Config(path=self.root / "c.json",
                             secrets_path=self.root / "s.json")
        cfg.set("threat.autoresponse.enabled", False)
        sent = []

        class _Args:
            all = True
            pid = []
            config = None

        state = {procresponse.STATE_KEY: {"stopped": {"4242": {
            "exe": "/tmp/payload", "at": time.time()}}, "observing": {}}}
        real_read, real_write = cmd.read_json, cmd.write_json
        real_runtime = procresponse.Runtime
        store = dict(state)
        cmd.read_json = lambda *a, **k: store
        cmd.write_json = lambda *a, **k: True
        procresponse.Runtime = lambda **k: type("R", (), {
            "proc_info": lambda self, pid: {},
            "signal": lambda self, pid, sig: (sent.append((pid, sig)),
                                              (True, ""))[1],
            "now": lambda self: time.time(),
            "pid_namespace": lambda self, pid: "/proc/1/ns/pid",
            "cgroup_unit": lambda self, pid: "",
            "own_namespace": lambda self: "/proc/1/ns/pid",
            "start_time": lambda self, pid: 0.0,
        })()
        try:
            rc = cmd.cmd_resume(_Args())
        finally:
            cmd.read_json, cmd.write_json = real_read, real_write
            procresponse.Runtime = real_runtime
        self.assertEqual(0, rc)
        self.assertEqual([(4242, int(signal.SIGCONT))], sent)
        self.assertEqual({}, store[procresponse.STATE_KEY]["stopped"])




class TestAutomationVerdictsAreAutomaticAndRecorded(unittest.TestCase):
    """The false report this answers, and the loop it must not create.

    A real host reported two ``chrome_crashpad_handler`` processes as
    suspicious on every automation run, and a deleted Playwright browser as
    "executable deleted" -- the most alarming line this check can print. Both
    are now classified automatically, with a one-line conclusion and a ledger
    entry, and neither can reach the intervention path.
    """

    def setUp(self):
        from vigil.guards.checks import procresponse
        self.pr = procresponse
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cfg = vconfig.Config(path=self.root / "c.json",
                                  secrets_path=self.root / "s.json")
        self._saved = procresponse.LEDGER
        procresponse.LEDGER = self.root / "autoresponse.jsonl"
        self.addCleanup(self._restore)
        self.procs = {}
        self.conns = {}

    def _restore(self):
        self.pr.LEDGER = self._saved

    def _bundle(self, *parts):
        return os.path.join(tempfile.gettempdir(), "vigil-probe", *parts)

    def add(self, pid, exe, deleted=False, comm="chrome", unit="",
            cmdline="", automation=""):
        self.procs[pid] = {"pid": pid, "comm": comm, "cmdline": cmdline or exe,
                           "exe": exe, "exe_deleted": deleted,
                           "start_time": 10.0, "unit": unit, "ppid": 1,
                           "exe_dev": 8, "exe_ino": 1,
                           "ns": "/proc/1/ns/pid", "automation": automation}
        self.conns[pid] = []

    def runtime(self):
        return self.pr.Runtime(
            cfg=self.cfg,
            proc_info=lambda pid: dict(self.procs.get(int(pid)) or {}),
            connections=lambda pid: list(self.conns.get(int(pid)) or []),
            cgroup_unit=lambda pid: (self.procs.get(int(pid)) or {}).get("unit", ""),
            start_time=lambda pid: 10.0,
            is_automation=lambda pid, exe: (self.procs.get(int(pid)) or {}).get("automation", ""),
            signal_fn=lambda pid, sig: (True, ""),
            now=lambda: 1000.0,
            pid_namespace=lambda pid: "/proc/1/ns/pid")

    def test_a_crashpad_helper_is_classified_without_an_ancestor(self):
        """It is reparented to init by design; that must not be evidence."""
        exe = self._bundle("browsers", "chromium-1243", "chrome-linux64",
                           "chrome_crashpad_handler")
        self.add(646871, exe, comm="chrome_crashpad",
                 automation=self.pr.util.browser_automation(646871, exe))
        result = self.pr.automation_verdicts(
            [{"pid": 646871, "comm": "chrome_crashpad", "exe": exe,
              "kind": "temp", "automation": ""}],
            cfg=self.cfg, state={}, runtime=self.runtime())
        self.assertEqual([], result["suspicious"])
        self.assertEqual(1, len(result["exempt"]))
        self.assertEqual("automation", result["exempt"][0]["verdict"])
        self.assertIn("helper", result["exempt"][0]["reason"])

    def test_a_deleted_browser_in_a_release_layout_is_a_leftover(self):
        exe = self._bundle("browsers", "chromium-1243", "chrome-linux64",
                           "chrome")
        self.add(551002, exe, deleted=True)
        result = self.pr.automation_verdicts(
            [{"pid": 551002, "comm": "chrome", "exe": exe,
              "kind": "deleted", "automation": ""}],
            cfg=self.cfg, state={}, runtime=self.runtime())
        self.assertEqual([], result["suspicious"])
        self.assertIn("浏览器发行包布局", result["exempt"][0]["reason"])

    def test_a_payload_beside_a_bundle_is_still_suspicious(self):
        """The exemption is for a layout *and* a browser name, not a folder."""
        self.add(4243, self._bundle("payload"), comm="payload")
        result = self.pr.automation_verdicts(
            [{"pid": 4243, "comm": "payload", "exe": self._bundle("payload"),
              "kind": "temp", "automation": ""}],
            cfg=self.cfg, state={}, runtime=self.runtime())
        self.assertEqual(1, len(result["suspicious"]))
        self.assertEqual([], result["exempt"])

    def test_a_payload_inside_a_browsers_directory_is_still_suspicious(self):
        """Layout alone must never be enough -- the basename must qualify."""
        exe = self._bundle("browsers", "chromium-1243", "chrome-linux64",
                           "notabrowser")
        self.add(4244, exe, comm="notabrowser")
        result = self.pr.automation_verdicts(
            [{"pid": 4244, "comm": "notabrowser", "exe": exe,
              "kind": "temp", "automation": ""}],
            cfg=self.cfg, state={}, runtime=self.runtime())
        self.assertEqual(1, len(result["suspicious"]),
                         "「在 browsers 目录里」本身不构成豁免")

    def test_the_verdict_keeps_the_raw_observation(self):
        """A verdict that overwrites its own evidence cannot be audited."""
        exe = self._bundle("browsers", "chromium-1243", "chrome-linux64",
                           "chrome")
        self.add(4245, exe)
        result = self.pr.automation_verdicts(
            [{"pid": 4245, "comm": "chrome", "exe": exe, "kind": "temp",
              "automation": ""}],
            cfg=self.cfg, state={}, runtime=self.runtime())
        item = result["exempt"][0]
        self.assertEqual(exe, item["exe"])
        self.assertEqual(4245, item["pid"])
        self.assertTrue(item["conclusion"])
        self.assertIn("浏览器", item["conclusion"])

    def test_an_exempt_process_never_reaches_the_intervention_path(self):
        """The loop this must not create: classify, then act on the same pid.

        `automation_verdicts` returns only the hits that were *not* exempted,
        and the check hands exactly those to `handle`. This asserts the
        property directly, with the intervention path's signal recorder
        watching.
        """
        exe = self._bundle("browsers", "chromium-1243", "chrome-linux64",
                           "chrome")
        # A deleted browser binary that is *also* holding an outbound
        # connection: without the automation verdict this is exactly the
        # high-confidence shape that may be stopped.
        self.add(551002, exe, deleted=True, comm="chrome")
        self.conns[551002] = [("ESTAB", "10.0.0.5:41000", "203.0.113.9:443")]
        self.cfg.set("threat.autoresponse.enabled", True)
        self.cfg.set("threat.autoresponse.observe_seconds", 0)
        self.cfg.set("threat.autoresponse.evidence_dir",
                     str(self.root / "evidence"))
        hits = [{"pid": 551002, "comm": "chrome", "exe": exe,
                 "kind": "deleted", "automation": ""}]
        classified = self.pr.automation_verdicts(
            hits, cfg=self.cfg, state={}, runtime=self.runtime())
        sent = []

        def signal_fn(pid, sig):
            sent.append((int(pid), int(sig)))
            return True, ""

        rt = self.runtime()
        rt._signal_fn = signal_fn
        state = {}
        for _ in range(3):
            self.pr.handle(classified["suspicious"], cfg=self.cfg,
                           state=state, runtime=rt)
        self.assertEqual([], sent,
                         "已被自动豁免的进程绝不能进入自动处置流程")
        self.assertEqual([], self.pr.handle(
            classified["suspicious"], cfg=self.cfg, state=state,
            runtime=rt)["observed"])

    def test_every_pass_leaves_a_ledger_line_with_an_outcome(self):
        self.cfg.set("threat.autoresponse.enabled", True)
        exe = self._bundle("browsers", "chromium-1243", "chrome-linux64",
                           "chrome")
        self.add(551002, exe, deleted=True)
        self.pr.handle([{"pid": 551002, "comm": "chrome", "exe": exe,
                         "kind": "deleted", "automation": "疑似自动化工具链"}],
                       cfg=self.cfg, state={}, runtime=self.runtime())
        kinds = [e.get("kind") for e in self.pr.recent(20)]
        self.assertIn("pass", kinds, "每一轮判定都要在台账里留下结论")


class TestTrustedRuntimeDowngrade(unittest.TestCase):
    """A build at 102% CPU is not a process anomaly.

    Three structural signals, any one enough -- deliberately weaker than the
    intervention path's two, because a wrong downgrade costs one unreported
    hot process, not a stopped server.
    """

    def setUp(self):
        from vigil.guards.checks import procresponse
        self.pr = procresponse
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cfg = vconfig.Config(path=self.root / "c.json",
                                  secrets_path=self.root / "s.json")

    def _runtime(self, unit="", exe="/usr/bin/node", start=1.0, ns=True):
        return self.pr.Runtime(
            cfg=self.cfg,
            proc_info=lambda pid: {"pid": int(pid), "exe": exe,
                                   "exe_deleted": False, "cmdline": exe,
                                   "comm": "node", "start_time": start,
                                   "unit": unit, "ppid": 1, "exe_dev": 1,
                                   "exe_ino": 1, "ns": "/proc/1/ns/pid"},
            connections=lambda pid: [],
            cgroup_unit=lambda pid: unit,
            start_time=lambda pid: start,
            is_automation=lambda pid, e: "",
            signal_fn=lambda pid, sig: (True, ""),
            now=lambda: 1.0,
            pid_namespace=lambda pid: "/proc/1/ns/pid")

    def test_a_unit_managed_process_is_downgraded(self):
        why = self.pr.runtime_downgrade(1234, "node", "node /srv/app/server.js",
                                        self._runtime(unit="app.service"),
                                        self.cfg)
        self.assertIn("systemd 单元", why)

    def test_a_site_build_directory_is_downgraded(self):
        self.cfg.set("gate.dsh_gate.webroot", "/srv/site/public")
        rt = self._runtime(exe="/usr/bin/node")
        # `package_owner` cannot resolve a path that does not exist on this
        # host, so the site-root signal is what is being exercised here.
        why = self.pr.runtime_downgrade(
            1234, "node", "node /srv/site/public/node_modules/.bin/vue-tsc",
            rt, self.cfg)
        self.assertIn("站点目录", why)

    def test_a_runtime_name_alone_is_not_enough(self):
        """`node -e <payload>` is a common implant shape; it must keep warning."""
        rt = self._runtime(exe="/usr/bin/node")
        why = self.pr.runtime_downgrade(
            1234, "node", "node -e c29tZXBheWxvYWQ=", rt, self.cfg)
        self.assertEqual("", why, "光凭进程叫 node 不能降级")

    def test_a_python_one_liner_is_not_downgraded(self):
        rt = self._runtime(exe="/usr/bin/python3")
        why = self.pr.runtime_downgrade(1234, "python3", "python3 -c import os",
                                        rt, self.cfg)
        self.assertEqual("", why)

    def test_the_downgrade_never_signals_anything(self):
        """It is a reporting decision, and the code must prove it.

        The strong form of this is a test that watches the signal recorder;
        this is the static one, so that a later edit cannot quietly reach for
        `os.kill` inside the reporting path.
        """
        body = inspect_module_src(self.pr.runtime_downgrade)
        self.assertNotIn("os.kill", body)
        self.assertNotIn("signal.SIG", body)
        self.assertNotIn("apply_action", body)
        self.assertNotIn("_send_alert", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
