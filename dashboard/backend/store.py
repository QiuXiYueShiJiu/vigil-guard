"""The live event bus: tailed log lines go in, classified map events come out.

Everything that has to agree on "what is happening right now" agrees here.
The tailer feeds raw requests in; this module geolocates them, asks vigil
what it thinks of the source, keeps a rolling history, and fan-outs to every
connected browser.

Design notes worth keeping:

* Only *public* sources are published on the map. Local traffic (the panel
  health checks hammering 127.0.0.1 every few seconds) would otherwise bury
  real events and draw arcs from nowhere.
* The per-address burst window is a deque of timestamps, not a counter, so
  the rate is always "over the last N seconds" rather than "since reboot".
* Subscribers get a bounded queue. A browser on a slow link is allowed to
  fall behind and skip, never allowed to make the server grow.
"""
from __future__ import annotations

import collections
import hashlib
import threading
import json
import threading
import time

from . import geo, settings, threat, sysinfo


class Subscriber:
    """One browser's outbox."""

    __slots__ = ("q", "created", "sent", "last")

    def __init__(self, maxsize: int = 400) -> None:
        self.q: collections.deque = collections.deque(maxlen=maxsize)
        self.created = time.time()
        self.sent = 0
        self.last = time.time()

    def push(self, item) -> None:
        self.q.append(item)
        self.sent += 1

    def drain(self, limit: int = 200) -> list:
        out = []
        while self.q and len(out) < limit:
            out.append(self.q.popleft())
        self.last = time.time()
        return out


#: Addresses that belong to whoever runs this machine.
#:
#: Requests from these are still counted, but they are never published. The
#: operator's own address appearing on a public map is exactly the kind of
#: detail that should not be inferable from a dashboard: it would let anyone
#: correlate "this IP watches the console" with "this IP administers it".
#:
#: Populated when a login succeeds (`vigil-dash` and the console both call
#: mark_operator) and when a request arrives on a panel-only path. Entries
#: expire so a rotating home connection does not accumulate forever.
_OPERATOR_IPS: dict = {}
_OPERATOR_LOCK = threading.Lock()
_OPERATOR_TTL = 86400.0


#: Addresses that are public but can never be a real browser: the public
#: resolver anycast addresses. A request "from" one of these is a health
#: probe, a fixture, or a forged header, and putting it on the public map
#: manufactures an attacker out of nothing. These literals are the ones the
#: audit treats as generic -- a public resolver belongs to everyone and so
#: identifies nobody.
_NEVER_PUBLISH_SOURCES = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1",              # Google / Cloudflare DNS
}

#: The same rule spelled as ranges: the rest of those resolvers' anycast
#: blocks, plus the sentinels this project's tests used to write from. Tests
#: have to write into a log the collector is watching to prove the
#: log-to-map path works, and that means fixture traffic reaches the
#: collector; the only safe answer is that the collector never publishes
#: anything from these ranges, however it got there. Without this, a test
#: flood stayed on the public page indefinitely.
#:
#: New fixtures use the RFC 5737 documentation ranges instead, which the
#: ``special`` branch below already refuses to publish; the older sentinels
#: stay listed so a stale buffer or an old log line cannot resurface.
_NEVER_PUBLISH_PREFIXES = (
    "9.9.9.", "1.0.0.",                           # Quad9 anycast / Cloudflare
    "23.94.70.", "23.94.10.", "23.94.20.", "23.94.50.", "23.94.60.", "23.94.77.",
    "45.33.9.", "104.21.7.", "23.94.5.",
)


def _vigil_verdict(detector: str) -> bool:
    """True when the verdict came from vigil's ledger rather than from here.

    Detector names produced by this console's own rules are excluded: `rate`
    is our threshold arithmetic and `offense` is our repeat counter. `decoy`,
    `exploit`, `bouncer` and the rest are vigil's, and those are the ones the
    attack list is allowed to assert.
    """
    name = (detector or "").strip().lower()
    if not name:
        return False
    return name not in ("rate", "offense", "heuristic")


def mark_operator(ip: str) -> None:
    """Remember that `ip` is the operator's, for a day."""
    if not ip or ip in ("-", "127.0.0.1", "::1"):
        return
    with _OPERATOR_LOCK:
        _OPERATOR_IPS[ip] = time.time() + _OPERATOR_TTL


def operator_marks() -> dict:
    """A copy of the operator registry, for the loopback admin endpoint."""
    with _OPERATOR_LOCK:
        return dict(_OPERATOR_IPS)


def is_operator(ip: str) -> bool:
    if not ip:
        return False
    now = time.time()
    with _OPERATOR_LOCK:
        expiry = _OPERATOR_IPS.get(ip)
        if expiry is None:
            return False
        if expiry < now:
            _OPERATOR_IPS.pop(ip, None)
            return False
        return True


class EventHub:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._history: collections.deque = collections.deque(
            maxlen=int(settings.settings.history))
        self._subs: dict = {}
        self._burst: dict = {}            # ip -> deque[timestamps] over burst_window
        self._peak: dict = {}             # ip -> deque[timestamps] over peak_window
        self._minute: dict = {}           # minute bucket -> counts
        self._epm_bucket: list = []        # published event times (60s)
        self._req_bucket: list = []        # every request time (60s)
        self._level_counts = {"normal": 0, "attack": 0, "pressure": 0}
        self._country_counts: dict = {}
        self._site_counts: dict = {}
        self._status_counts: dict = {}
        self._started = time.time()
        self._total = 0
        self._local = 0
        self._worst: dict = {}            # ip -> last attack record
        self._recent_attacks: collections.deque = collections.deque(maxlen=200)
        self._rate_flagged: dict = {}     # ip -> last rate-based attack
        self._median_cache: tuple = ()    # (computed_at, value)
        self._counter_lock = threading.Lock()

    # -- write path ------------------------------------------------------

    def _median_peak(self, max_age: float = 0.7) -> float:
        """Median peak rate across busy addresses, recomputed at most every
        ``max_age`` seconds.

        This is the reference a flood has to stand out from. It is cached
        because it is a sort over every address seen, and the ingest path
        cannot afford that per event; at the poll cadence it costs nothing.
        """
        now = time.time()
        cached = self._median_cache
        if cached and now - cached[0] < max_age:
            return cached[1]
        with self._lock:
            samples = sorted(len(pk) / float(settings.settings.peak_window)
                             for pk in self._peak.values() if len(pk) >= 3)
        value = samples[len(samples) // 2] if samples else 0.0
        self._median_cache = (now, value)
        return value

    def ingest(self, ev) -> None:
        """Classify one request and publish it if it belongs on the map."""
        ip = ev.ip
        now = time.time()
        with self._lock:
            window = float(settings.settings.burst_window)
            peak_window = float(settings.settings.peak_window)
            # Log timestamps are second-granular, so a flood written by one
            # process can look like it trickled in. The short window is what
            # actually answers "is this address hammering us right now".
            stamp = ev.ts if ev.ts and abs(ev.ts - now) < 3600 else now
            dq = self._burst.get(ip)
            if dq is None:
                dq = collections.deque()
                self._burst[ip] = dq
            dq.append(stamp)
            cutoff = now - window
            while dq and dq[0] < cutoff:
                dq.popleft()
            count = len(dq)
            rate = count / window if window > 0 else 0.0

            pk = self._peak.get(ip)
            if pk is None:
                pk = collections.deque()
                self._peak[ip] = pk
            pk.append(stamp)
            peak_cutoff = now - peak_window
            while pk and pk[0] < peak_cutoff:
                pk.popleft()
            peak = len(pk) / peak_window if peak_window > 0 else 0.0
            # Bound the tables: an attack with 100k sources must not eat RAM.
            if len(self._burst) > 20000:
                for key in list(self._burst)[:5000]:
                    if not self._burst[key]:
                        self._burst.pop(key, None)
                        self._peak.pop(key, None)
        median_peak = self._median_peak()

        place = geo.geo.lookup(ip)
        kind = place.get("kind")
        with self._counter_lock:
            self._total += 1
            # Sliding one-minute list for the "events / minute" readout. A
            # per-minute bucket cannot answer this: it would report the whole
            # current minute, so the number jumps at the boundary and reads
            # zero right after it.
            # Two windows, because they answer two different questions.
            # `_req_bucket` is request throughput (hidden requests included);
            # `_epm_bucket` is how many marks actually reached the map, which
            # is what the page labels "地图事件 / 分钟".
            cutoff = now - 60.0
            req = self._req_bucket
            req.append(now)
            while req and req[0] < cutoff:
                req.pop(0)
            minute = int(now // 60)
            self._minute[minute] = self._minute.get(minute, 0) + 1
            for stale in [m for m in self._minute if m < minute - 180]:
                self._minute.pop(stale, None)
            if kind != "public":
                self._local += 1
            site = ev.site or "-"
            self._site_counts[site] = self._site_counts.get(site, 0) + 1
            self._status_counts[str(ev.status)] = \
                self._status_counts.get(str(ev.status), 0) + 1

        if kind != "public":
            # Local and reserved addresses never reach the map.
            level, reason, detector = threat.threat.classify(
                ip, rate, count, peak, ev.path, median_peak)
            if level:
                self._note_attack(ev, place, level, reason, detector)
            return

        level, reason, detector = threat.threat.classify(
            ip, rate, count, peak, ev.path, median_peak)
        if level and detector == "rate":
            # Rate verdicts are throttled, not repeated: without this a flood
            # from one address produced an attack event -- and a red line --
            # for every request in it, which is a wall of red rather than an
            # alarm. Two details matter here:
            #
            #   * the hold is renewed only when a verdict is actually
            #     *reported*. Renewing it on every suppressed call (the first
            #     version did that) means a continuous flood reports once and
            #     then goes quiet for as long as it lasts.
            #   * an escalation still gets through immediately, so a flood
            #     that turns into a heavier flood is not swallowed by the
            #     hold from its own earlier, milder verdict.
            hold = float(settings.settings.rate_hold)
            with self._lock:
                held_until, last_level = self._rate_flagged.get(ip, (0.0, 0))
                if now < held_until and level <= last_level:
                    level = 0
                else:
                    self._rate_flagged[ip] = (now + hold, level)
                    if len(self._rate_flagged) > 5000:
                        for key in sorted(self._rate_flagged,
                                          key=lambda k: self._rate_flagged[k][0])[:2000]:
                            self._rate_flagged.pop(key, None)
        name = "normal" if level == 0 else ("attack" if level == 1 else "pressure")
        # Wire format is deliberately terse: this object is repeated a few
        # hundred times in the first snapshot, once per page load. Field
        # names are short, empty strings are omitted, and the user agent is
        # not carried at all -- nothing renders it, and it is the single
        # biggest string in a request.
        # Requests that only happen because someone is using a control panel.
        # Counted in the totals, never published: the map, the stream and the
        # readout are public, and a URL on them tells every visitor where the
        # management surfaces are.
        # Documentation and reserved ranges. A real packet never comes from
        # one, so an event claiming to is a fixture, a leftover from an older
        # buffer, or a forged header. Counting it is fine; publishing it puts
        # a fictitious attacker on the public map, which is exactly how a test
        # address ended up appearing on every page load.
        if (kind == "special" or ip in _NEVER_PUBLISH_SOURCES
                or ip.startswith(_NEVER_PUBLISH_PREFIXES)):
            return

        # The operator's own traffic never reaches the public map, whatever
        # path it used. Checked first, before anything else can leak it.
        private = is_operator(ip)
        discreet = private or threat.threat.is_discreet_path(ev.path or "")
        # Privacy: a visitor who is merely browsing is described by where they
        # are, never by who they are. Their address is replaced with a stable
        # token so repeat visits still group into one meteor, and the real
        # address never leaves the process. An attack keeps its address,
        # because "who did this" is the entire point of that row.
        if level == 0:
            ident = hashlib.sha1(ip.encode("utf-8", "replace")).hexdigest()[:10]
            addr = ""
        else:
            ident = ip
            addr = ip
        payload = {
            "t": round(ev.ts or now, 3),
            "id": ident,
            "lat": place.get("lat"),
            "lon": place.get("lon"),
            "lv": level,
            # When this console first published it. `t` is the log line's own
            # timestamp, which for a replayed log line can be hours old, while
            # a history buffer holds the last few minutes of events and every
            # page load replays them. Without `nt` the browser cannot tell
            # "this just happened" from "this is being handed to me again", and
            # a ban from two hours ago reappears as a fresh strike on every
            # refresh.
            "nt": round(now, 3),
        }
        if addr:
            payload["ip"] = addr
        if discreet:
            payload["q"] = 1
        for key, value in (("cc", place.get("cc")), ("co", place.get("country")),
                           ("ci", place.get("city")), ("op", place.get("operator")),
                           ("why", reason), ("det", detector), ("m", ev.method),
                           ("p", (ev.path or "")[:180]), ("site", ev.site)):
            if value:
                payload[key] = value
        if ev.status:
            payload["s"] = ev.status
        if rate >= 1.0:
            payload["r"] = round(rate, 1)
        if peak >= 4.0:
            payload["rp"] = round(peak, 1)
        with self._lock:
            if not discreet:
                self._epm_bucket.append(now)
            self._level_counts[name] += 1
            cc = payload["cc"] or "--"
            self._country_counts[cc] = self._country_counts.get(cc, 0) + 1
            if not discreet:
                self._history.append(payload)
                # Only vigil's own verdicts count as attacks. The console's
                # heuristic rate verdicts still colour the map (they are draws,
                # not claims), but the attack table is a list of things the
                # security system actually decided -- mixing in a guess would
                # make the table untrustworthy exactly where trust matters.
                if level and _vigil_verdict(detector):
                    self._recent_attacks.append(payload)
            subs = list(self._subs.values())
        if not discreet:
            for sub in subs:
                sub.push(payload)
        if level and not discreet and _vigil_verdict(detector):
            self._note_attack(ev, place, level, reason, detector)

    def _note_attack(self, ev, place: dict, level: int, reason: str,
                     detector: str) -> None:
        rec = {
            "t": round(ev.ts or time.time(), 3), "ip": ev.ip, "lv": level,
            "why": reason, "det": detector, "cc": place.get("cc") or "",
            "co": place.get("country") or "", "ci": place.get("city") or "",
            "lat": place.get("lat"), "lon": place.get("lon"),
            "p": (ev.path or "")[:160], "s": ev.status,
            # Kept so a repeated source can be traced back to the log line it
            # came from instead of being argued about.
            "src": getattr(ev, "src", "") or "",
            "seen": round(time.time(), 3),
        }
        with self._lock:
            self._worst[ev.ip] = rec
            if len(self._worst) > 5000:
                for key in sorted(self._worst,
                                  key=lambda k: self._worst[k]["t"])[:2000]:
                    self._worst.pop(key, None)

    def forget_source(self, ip: str) -> int:
        """Remove already-published marks that came from `ip`.

        Marking an address as the operator's only affects future requests; a
        couple of minutes of its history would otherwise stay on the map until
        the traces expired on their own.
        """
        if not ip:
            return 0
        removed = 0
        with self._lock:
            keep = []
            for item in self._history:
                if item.get("ip") == ip:
                    removed += 1
                    continue
                keep.append(item)
            self._history = collections.deque(keep, maxlen=self._history.maxlen)
            self._recent_attacks = collections.deque(
                (x for x in self._recent_attacks if x.get("ip") != ip),
                maxlen=self._recent_attacks.maxlen)
        if removed:
            threat.threat.clear_ip(ip)
        return removed

    # -- subscriber plumbing --------------------------------------------

    def subscribe(self) -> tuple:
        token = "%d-%d" % (time.time() * 1000, id(object()) % 100000)
        sub = Subscriber()
        with self._lock:
            self._subs[token] = sub
        return token, sub

    def unsubscribe(self, token: str) -> None:
        with self._lock:
            self._subs.pop(token, None)

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subs)

    # -- read path -------------------------------------------------------

    def history(self, limit: int = 400) -> list:
        with self._lock:
            items = list(self._history)
        return items[-limit:] if limit > 0 else items

    def _events_per_minute(self, now: float) -> int:
        """Events seen in the last 60 seconds, rolled up here not in the UI."""
        cutoff = now - 60.0
        with self._counter_lock:
            bucket = self._epm_bucket
            while bucket and bucket[0] < cutoff:
                bucket.pop(0)
            return len(bucket)

    def requests_per_minute_recent(self, now: float) -> int:
        """Every request in the last 60s, hidden ones included."""
        cutoff = now - 60.0
        with self._counter_lock:
            bucket = self._req_bucket
            while bucket and bucket[0] < cutoff:
                bucket.pop(0)
            return len(bucket)

    def _threat_summary(self) -> dict:
        """The threat fields the page actually paints, and nothing else.

        `latest_bans` is trimmed to the five fields the ban table reads; the
        full ledger entry carries path, user agent, method and more, which was
        most of the 2 KiB this used to cost per snapshot.
        """
        full = threat.threat.snapshot()
        bans = []
        for item in (full.get("latest_bans") or [])[:12]:
            ip = item.get("ip") or ""
            # Real location, resolved here. The page used to stuff `detector`
            # into the country field, so every ban rendered as an unexplained
            # flagless row -- which is what made a live ban look like a
            # fabricated attack.
            place = geo.geo.lookup(ip) if ip else {}
            bans.append({
                "ip": ip,
                "reason": item.get("reason"),
                "detector": item.get("detector"),
                "until": item.get("until"),
                "cc": place.get("cc") or "",
                "co": place.get("country") or "",
                "ci": place.get("city") or "",
                "lat": place.get("lat"),
                "lon": place.get("lon"),
                # Which layer produced this: always vigil for this list.
                "src": item.get("detector") or "",
            })
        return {
            "live_bans": full.get("live_bans", 0),
            "bans_total": full.get("bans_total", 0),
            "ledger_age": full.get("ledger_age"),
            "posture": full.get("posture") or {"active": False},
            "latest_bans": bans,
        }

    def snapshot(self, history: int = 0, include_attacks: bool = False) -> dict:
        """One page-sized view of current state.

        Two rules keep this small, because the page pulls it every few seconds
        and parses it on the main thread:

        * Nothing the page cannot display. `top_offenders`, per-detector
          counts and the per-site breakdown were all being computed, shipped
          and parsed for panels that no longer render them.
        * Derived values are computed once here rather than per event in the
          browser. The client's job is to paint, not to reduce.
        """
        now = time.time()
        with self._counter_lock:
            stats = {
                "total": self._total,
                "local": self._local,
                "status": dict(sorted(self._status_counts.items(),
                                      key=lambda kv: kv[1], reverse=True)[:8]),
                "levels": dict(self._level_counts),
                "countries": dict(sorted(self._country_counts.items(),
                                         key=lambda kv: kv[1], reverse=True)[:16]),
            }
            minute = self._minute
            recent = [minute.get(int(now // 60) - i, 0) for i in range(11, -1, -1)]
            per_min_now = minute.get(int(now // 60), 0)
        with self._lock:
            worst = sorted(self._worst.values(), key=lambda r: r["t"],
                           reverse=True)[:40]
            attacks = list(self._recent_attacks)[-40:]
            ups = self._total
        elapsed = max(1.0, now - self._started)
        out = {
            "ts": round(now, 3),
            # The host is described by its address only. No hostname, no
            # provider, no city name -- the console is public, and how the
            # machine is built is not the public's business.
            # Coordinates and nothing else. No label, no name, no address.
            "server": {"lat": settings.SERVER_LAT, "lon": settings.SERVER_LON},
            "traffic": {
                "total": ups,
                "rpm": per_min_now,
                "avg_rps": round(ups / elapsed, 2),
                "minute_series": recent,
                "levels": stats["levels"],
                "countries": stats["countries"],
                "status": stats["status"],
                "local": stats["local"],
                # Blended on the server: the page only needs the number, and
                # doing it here keeps the reduce off the main thread.
                "epm": self._events_per_minute(now),
                "rps": round(self.requests_per_minute_recent(now) / 60.0, 2),
            },
            "threat": self._threat_summary(),
            "geo": geo.geo.stats(),
        }
        # The two big arrays are opt-in. A fresh page renders from the live
        # stream within a second, so paying 60 KiB up front for a map that is
        # about to be redrawn anyway is the wrong trade -- especially on a
        # phone link.
        if history:
            out["history"] = self.history(history)
        if include_attacks:
            out["recent_attacks"] = attacks
            out["worst"] = worst[:20]
        return out


hub = EventHub()
