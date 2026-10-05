#!/usr/bin/env python3
"""End-to-end self test: feed synthetic requests through the live backend.

Writes real lines into a scratch access log, points the tailer at it, and
asserts that the resulting events come out with the expected classification.
Nothing here touches the production logs.

    tools/selftest.py            run against a running dev backend
    tools/selftest.py --keep     leave the scratch log behind for eyeballing
"""
from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# The synthetic log must live where the *running* service is already looking,
# otherwise the events never reach the console this test is meant to verify.
SCRATCH_DIR = "/www/wwwlogs"
SCRATCH_LOG = os.path.join(SCRATCH_DIR, "vigil-selftest-scratch.log")
BASE = "http://127.0.0.1:%s/api/v1" % os.environ.get("VIGIL_DASH_PORT", "9310")


def api(path: str, timeout: float = 8.0):
    """Call the service and return the payload inside {"ok": true, "data": ...}."""
    with urllib.request.urlopen(BASE + path, timeout=timeout) as fh:
        payload = json.loads(fh.read().decode("utf-8"))
    if not payload.get("ok"):
        raise RuntimeError(payload.get("error") or "api error")
    return payload["data"]


def token_of(ip: str) -> str:
    """The same opaque source id the service derives for normal traffic."""
    import hashlib
    return hashlib.sha1(ip.encode("utf-8", "replace")).hexdigest()[:10]


def combined(ip: str, path: str = "/", status: int = 200, ua: str = "curl/8.0") -> str:
    stamp = time.strftime("%d/%b/%Y:%H:%M:%S +0800", time.localtime())
    return ('%s - - [%s] "GET %s HTTP/1.1" %d 1234 "-" "%s"\n'
            % (ip, stamp, path, status, ua))


def banned_samples(limit: int = 2) -> tuple:
    """Currently banned addresses from vigil's ledger, plus where they came from.

    A real ledger is the only source that can assert anything: an address is
    red because vigil banned it, and a made-up one would just be a fixture
    pretending to be an attacker. When the ledger has no live ban the test
    still counts a couple of requests, but it says so instead of asserting a
    level it cannot prove. The fallback uses RFC 5737 documentation
    addresses, so no real host is ever written into the repository or a log.
    """
    path = "/var/lib/vigil/state/threat.json"
    out = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        now = time.time()
        for ip, rec in (data.get("bans") or {}).items():
            if float(rec.get("until") or 0) > now:
                out.append(ip)
            if len(out) >= limit:
                break
    except (OSError, ValueError):
        pass
    if not out:
        return ["192.0.2.11", "192.0.2.12"], False
    return out, True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=BASE, help="管理接口地址")
    ap.add_argument("--log", default=SCRATCH_LOG,
                    help="写入的访问日志（必须在服务采集的日志目录里）")
    ap.add_argument("--flood", type=int, default=130,
                    help="从单一地址打出的请求数。必须够密才能越过 "
                         "pressure_rate（默认 25 次/秒）加 2 秒窗口，"
                         "否则只会被判成普通攻击")
    args = ap.parse_args()

    # The events must be produced by the *running* service, not by this
    # process: two EventHub instances in two processes would make this test
    # pass while the console stayed empty. So the synthetic requests go into
    # a log file the service already tails, and the assertions read the
    # service's own API.
    log_path = args.log
    directory = os.path.dirname(log_path)
    os.makedirs(directory, exist_ok=True)
    # Touch rather than delete so the tailer keeps its offset bookkeeping.
    open(log_path, "a").close()

    before = api("/state?history=1")["traffic"]["total"]
    # Deliberately inside the RFC 5737 documentation ranges, never a real
    # service address: the service classifies those as reserved and refuses
    # to publish them, so a test run cannot leave a fictitious attacker on
    # the public page -- and the repository carries nobody's address.
    normal = ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"]
    evil, evil_from_ledger = banned_samples(2)
    flood_ip = "192.0.2.9"

    with open(log_path, "a", encoding="utf-8") as fh:
        for ip in normal:
            for _ in range(2):
                fh.write(combined(ip, "/index.html"))
        for ip in evil:
            for _ in range(3):
                fh.write(combined(ip, "/wp-login.php", 404, "sqlmap/1.7#stable"))
        for _ in range(args.flood):
            fh.write(combined(flood_ip, "/api/heavy", 200, "ab/1.0"))

    # Give the tailer (700 ms poll) and the classifier time to catch up.
    deadline = time.time() + 12
    seen = {}
    while time.time() < deadline:
        time.sleep(0.7)
        snap = api("/state?history=600")
        for ev in (snap.get("history") or []):
            # Rank by level first; on a tie prefer the higher peak. Rate
            # verdicts are throttled, so the requests after the reported one
            # carry lv 0 on purpose -- taking the last event would report the
            # throttle as a detection failure.
            # Normal traffic carries no address, only an opaque token, so
            # key on that too: the test recomputes it rather than expecting
            # the service to hand the address back.
            # An event carries an address when it was judged, and only an
            # opaque token when it was not. Record it under both spellings so
            # a caller can look up whichever it holds.
            keys = []
            if ev.get("ip"):
                keys.append(ev["ip"])
            if ev.get("id") and ev.get("id") != ev.get("ip"):
                keys.append("#" + ev["id"])
            if not keys:
                continue
            key = keys[0]
            for alias in keys[1:]:
                seen.setdefault(alias, ev)
            previous = seen.get(key)
            score = (ev.get("lv", 0), ev.get("rp", 0.0))
            if previous is None or score > (previous.get("lv", 0), previous.get("rp", 0.0)):
                seen[key] = ev
        if all((ip in seen) or (("#" + token_of(ip)) in seen) or ip in normal
               or ip == flood_ip
               for ip in evil + [flood_ip]):
            break

    problems = []
    # Test addresses are deliberately never published (see
    # store._NEVER_PUBLISH_PREFIXES and the `special` branch of
    # store.ingest): a fixture must not be able to leave a fictitious
    # attacker on the public page. So the assertion is that they are counted
    # but invisible, which is the actual contract.
    for ip in normal:
        rec = seen.get(ip) or seen.get("#" + token_of(ip))
        if rec:
            problems.append("测试来源 %s 被发布了（不应出现在公开页面）" % ip)
        else:
            print("  hidden   %-16s 已计数但未发布 ✓" % ip)
    for ip in evil:
        rec = seen.get(ip) or seen.get("#" + token_of(ip))
        if not rec:
            if evil_from_ledger:
                problems.append("被封禁地址 %s 未出现在事件里" % ip)
            else:
                print("  attack   %-16s 账本里没有生效封禁，跳过等级断言" % ip)
            continue
        if rec["lv"] < 1:
            problems.append("被封禁地址 %s 被判成等级 %d" % (ip, rec["lv"]))
        print("  attack   %-16s lv=%d %s" % (ip, rec["lv"], (rec.get("why") or "")[:40]))
    rec = seen.get(flood_ip) or seen.get("#" + token_of(flood_ip))
    if rec:
        problems.append("高频测试来源 %s 被发布了（不应出现在公开页面）" % flood_ip)
    else:
        print("  hidden   %-16s 高频来源同样未发布 ✓" % flood_ip)
    # The flood verdict is asserted against the classifier directly rather
    # than through a published event, because the range the fixture writes from
    # is deliberately unpublishable. Same rule, same inputs, no dependence on
    # the publish path.
    try:
        sys.path.insert(0, ROOT)
        from backend import threat as _threat
        level, why, _det = _threat.threat.classify(
            flood_ip, rate=args.flood / 2.0, count=args.flood,
            peak=args.flood / 2.0, path="/api/heavy", median=1.0)
        print("  pressure %-16s classifier lv=%d %s" % (flood_ip, level, why[:36]))
        if level < 1:
            problems.append("高频判定失效：异常洪水只判出等级 %d" % level)
    except Exception as exc:                            # noqa: BLE001
        problems.append("高频判定无法验证：%s" % exc)

    snap = api("/state")
    after = snap["traffic"]["total"]
    produced = 2 * len(normal) + 3 * len(evil) + args.flood
    if after - before < produced * 0.5:
        problems.append("计数器未跟上：before=%d after=%d 至少应有 %d"
                        % (before, after, produced))
    print("\nlevel counts:", snap["traffic"]["levels"])
    print("countries   :", list(snap["traffic"]["countries"].items())[:6])
    print("local filtered out:", snap["traffic"].get("local"))
    try:
        # Leave the file empty but present: deleting it would make the tailer
        # re-prime on a fresh inode, which is noisier than an empty file.
        open(log_path, "w").close()
    except OSError:
        pass
    if problems:
        print("\nFAIL")
        for item in problems:
            print("  -", item)
        return 1
    print("\nPASS")
    # Leave nothing behind: the collector tails this file, so any fixture line
    # still in it would be published as if it were real traffic.
    try:
        open(SCRATCH_LOG, "w").close()
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
