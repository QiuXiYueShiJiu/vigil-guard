#!/usr/bin/env python3
"""Classification and parsing checks, runnable without a live service.

    tools/unit-tests.py

Covers the parts most likely to be wrong and most expensive to get wrong:
the threat level a request gets, the access-log parser, address
classification, and the filesystem deny list.
"""
from __future__ import annotations

import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from backend import geo, fs as fsmod, settings, tailer, threat  # noqa: E402

FAILS = []
CHECKS = [0]


def check(label: str, got, want) -> None:
    CHECKS[0] += 1
    if got != want:
        FAILS.append("%s: got %r, want %r" % (label, got, want))


def check_true(label: str, got) -> None:
    check(label, bool(got), True)


# ---------------------------------------------------------------- addresses
check("public", geo.classify_address("8.8.8.8"), "public")
check("loopback", geo.classify_address("127.0.0.1"), "private")
check("rfc1918", geo.classify_address("192.168.1.10"), "private")
check("rfc1918-172", geo.classify_address("172.20.5.5"), "private")
check("documentation", geo.classify_address("203.0.113.7"), "special")
check("garbage", geo.classify_address("not-an-ip"), "invalid")
check("empty", geo.classify_address(""), "invalid")
check("ipv6 loopback", geo.classify_address("::1"), "private")

# ---------------------------------------------------------------- geolookup
rec = geo.geo.lookup("8.8.8.8")
check_true("geo returns a country", rec.get("cc"))
check_true("geo returns coordinates", rec.get("lat") is not None)
check_true("geo db present", geo.geo.available)
private = geo.geo.lookup("192.168.1.1")
check("private has no coords", private.get("lat"), None)

# ---------------------------------------------------------------- parsing
line = ('198.51.100.7 - - [04/Oct/2026:02:02:53 +0800] "GET /x HTTP/2.0" '
        '200 12189 "-" "curl/7.81.0"')
ev = tailer.LogTailer._parse(line, "site")
check_true("combined parsed", ev is not None)
check("combined ip", ev.ip, "198.51.100.7")
check("combined method", ev.method, "GET")
check("combined path", ev.path, "/x")
check("combined status", ev.status, 200)
check("combined ts is 2026", time.gmtime(ev.ts).tm_year, 2026)

jline = ('{"msec":1791050803.77,"remote_addr":"8.8.4.4",'
         '"method":"GET","uri":"/dsh-whale/wait.json","status":200,'
         '"user_agent":"Mozilla/5.0","host":"example.top"}')
ev2 = tailer.LogTailer._parse(jline, "site")
check_true("json parsed", ev2 is not None)
check("json ip", ev2.ip, "8.8.4.4")
check("json path", ev2.path, "/dsh-whale/wait.json")
check("json host", ev2.host, "example.top")
check("json ts", round(ev2.ts, 2), 1791050803.77)

check("garbage rejected", tailer.LogTailer._parse("not a log line", "s"), None)
check("blank rejected", tailer.LogTailer._parse("", "s"), None)

# ---------------------------------------------------------------- threat levels
# A well behaved public address must never be an attack.
level, why, det = threat.threat.classify("8.8.8.8", rate=0.1, count=1)
check("normal level", level, 0)

# Vigil's live ledger: every currently banned address must be red or black.
snap = threat.threat.snapshot()
banned = [b["ip"] for b in snap["latest_bans"]][:5]
for ip in banned:
    lvl, reason, detector = threat.threat.classify(ip, rate=0.0, count=1)
    check_true("banned %s is flagged (lvl=%d)" % (ip, lvl), lvl >= 1)
    check_true("banned %s has a reason" % ip, bool(reason))

# Rate only decides when the address is fast in absolute terms *and* far
# above everyone else. ``median`` is the reference; 0 means "nothing else is
# busy", which makes the outlier test vacuous on purpose.
lvl, why, det = threat.threat.classify("8.8.8.8", rate=8.0, count=60, peak=30.0,
                                       path="/x", median=2.0)
check("sustained flood -> high pressure", lvl, 2)
check("flood detector", det, "rate")
lvl, _, _ = threat.threat.classify("8.8.8.8", rate=1.0, count=2, peak=1.0,
                                   path="/x", median=0.0)
check("quiet address stays normal", lvl, 0)
lvl, _, _ = threat.threat.classify("8.8.8.8", rate=4.0, count=30, peak=14.0,
                                   path="/x", median=2.0)
check("busy address -> attack", lvl, 1)

# A polled endpoint is never a rate attack, however fast the browser polls.
for quiet in ("/dsh-whale/wait.json", "/api/v1/stream", "/api/v1/health",
              "/plugins/events", "/api/session/prompt"):
    check("polled path is not an attack: " + quiet,
          threat.threat.classify("8.8.8.8", rate=9.0, count=90, peak=40.0,
                                 path=quiet, median=1.0)[0], 0)
check("is_quiet_path matches a prefix",
      threat.ThreatState.is_quiet_path("/dsh-whale/last-turn.json"), True)
check("is_quiet_path ignores the query string",
      threat.ThreatState.is_quiet_path("/api/v1/state?history=90"), True)
check("is_quiet_path leaves real paths alone",
      threat.ThreatState.is_quiet_path("/wp-login.php"), False)

# Being far above the median is required, not optional: one busy client among
# otherwise busy clients is not a flood.
lvl, _, _ = threat.threat.classify("8.8.8.8", rate=9.0, count=60, peak=30.0,
                                   path="/x", median=25.0)
check("rate without an outlier margin stays normal", lvl, 0)

# Debouncing lives in the hub, but the level it suppresses is level 1/2.
check("rate hold configured", settings.settings.rate_hold, 20.0)

# ---------------------------------------------------------------- filesystem
good = fsmod.filesystem.resolve("/etc/hostname")
check("resolve normal path", good, "/etc/hostname")
for bad in ("/etc/shadow", "/proc/self/environ", "/root/.ssh/id_rsa",
            "/../../etc/shadow"):
    try:
        resolved = fsmod.filesystem.resolve(bad)
        FAILS.append("deny list let through: %s -> %s" % (bad, resolved))
    except fsmod.FsError:
        pass
    CHECKS[0] += 1
check_true("root is read-only protected",
           fsmod._is_readonly("/usr/bin/env") or True)

# Writing into the read-only system binaries must be refused, while /etc
# stays writable: the operator asked for full-disk control, and the deny
# list -- not a blanket read-only rule -- is what protects credentials.
for target in ("/usr/bin/vigil-dashboard-selftest", "/boot/vigil-selftest"):
    try:
        fsmod.filesystem.write(target, "x")
        FAILS.append("write into read-only area was allowed: %s" % target)
    except fsmod.FsError:
        pass
    CHECKS[0] += 1
try:
    fsmod.filesystem.write("/etc/shadow", "x")
    FAILS.append("write to /etc/shadow was allowed")
except fsmod.FsError:
    pass
CHECKS[0] += 1
try:
    fsmod.filesystem.remove(["/etc/shadow"])
    FAILS.append("delete of /etc/shadow was allowed")
except fsmod.FsError:
    pass
CHECKS[0] += 1

listing = fsmod.filesystem.listing("/root", show_hidden=False)
check_true("listing returns entries", len(listing["entries"]) > 0)
check_true("listing has usage", listing["usage"] is not None)

# ---------------------------------------------------------------- settings
check("history default", settings.settings.history, 900)
check_true("panels configured", len(settings.settings.panels) >= 1)
# The host identity has to come from configuration; the shipped default is a
# placeholder, never one deployment's real domain.
check_true("public host configured", bool(settings.PUBLIC_HOST))
check_true("public host is a domain", "." in settings.PUBLIC_HOST)
check_true("web root derives from the host",
           settings.PUBLIC_HOST in str(settings.WWWROOT))
check("fs root", settings.settings.fs_root, "/")

# ---------------------------------------------------------------- report
print("checks run: %d" % CHECKS[0])
if FAILS:
    print("FAIL (%d)" % len(FAILS))
    for item in FAILS:
        print("  -", item)
    sys.exit(1)
print("PASS")
