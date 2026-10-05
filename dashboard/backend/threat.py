"""What vigil thinks is going on, read straight from its own ledger.

The dashboard does not re-detect anything. It reads ``threat.json`` -- the
file vigil-threatd already maintains -- and turns it into two things the UI
needs: a classification for an address at this instant, and a counters block
for the status rail.

Classification is deliberately conservative. A visitor is only drawn as an
attacker when vigil has actually banned them or has them on a stated number
of offences; everything else is traffic. Guessing beyond that would put red
arcs on ordinary people, which is worse than missing an attack.
"""
from __future__ import annotations

import json
import os
import threading
import time
from collections import OrderedDict

from . import settings

#: Path prefixes that are polled on a timer by design. A browser sitting on
#: the DSH console asks for two of these every couple of seconds, forever, and
#: a dashboard that paints that red is worse than useless -- it trains the
#: operator to ignore red. Rate-based judging skips these; vigil's own ban
#: decisions still apply, because those are evidence rather than inference.
_QUIET_PATHS = (
    "/dsh-whale/", "/api/v1/stream", "/api/v1/health", "/api/v1/state",
    "/api/v1/resources", "/api/session/", "/favicon.ico", "/healthz",
    "/api/events", "/plugins/events", "/wp-json/",
)

#: Detector/reason fingerprints that mean "this is not a scanner, this is an
#: attempt to break in". Used to promote a ban to the black pressure colour.
_HIGH_MARKERS = (
    "exploit", "rce", "\u6f0f\u6d1e", "\u5229\u7528", "webshell",
    "\u6728\u9a6c", "\u540e\u95e8", "\u547d\u4ee4\u6267\u884c", "sql",
    "\u7206\u7834", "\u5f31\u53e3\u4ee4",
)


#: Endpoints that exist only because an operator is using a control panel.
#: These are counted, but never published on the public page: the map and the
#: event stream are visible to anyone, and printing "someone requested
#: /dsh-whale/wait.json" tells every visitor where the management surfaces
#: live. A visitor has no business knowing that path exists.
#:
#: Written separately from _QUIET_PATHS on purpose. The two lists start out
#: similar and mean different things: that one says "do not infer an attack
#: from this", this one says "do not show this to the public". Conflating them
#: would mean a future rate-rule change silently starts leaking paths.
_DISCREET_PATHS = (
    "/dsh-whale/", "/api/session/", "/api/v1/", "/plugins/",
    "/panel", "/btwaf", "/8889", "/admin", "/manage",
)


class ThreatState:
    """A cached, thread-safe view of vigil's threat ledger."""

    def __init__(self, path=None) -> None:
        self._path = path or settings.VIGIL_THREAT_STATE
        self._lock = threading.Lock()
        self._bans: dict = {}          # ip -> {until, reason, count, detector}
        self._offenses: dict = {}      # ip -> {count, last}
        self._stats: dict = {}
        self._mtime = 0.0
        self._loaded = 0.0
        self._fingerprint = ""
        #: Addresses banned in the last couple of minutes. Their requests are
        #: already in the access log by the time the ban lands, so an event
        #: arriving late still gets the right colour.
        self._recent: "OrderedDict[str, float]" = OrderedDict()
        self._err = ""

    # -- loading ---------------------------------------------------------

    def _refresh(self, force: bool = False) -> None:
        now = time.time()
        if not force and (now - self._loaded) < 1.0:
            return
        self._loaded = now
        try:
            st = os.stat(self._path)
        except OSError as exc:
            with self._lock:
                self._err = "无法读取 %s：%s" % (self._path, exc)
                self._bans, self._offenses, self._stats = {}, {}, {}
            return
        with self._lock:
            unchanged = (st.st_mtime == self._mtime and self._bans)
        if unchanged and not force:
            return
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            with self._lock:
                self._err = "威胁账本解析失败：%s" % exc
            return
        bans = data.get("bans") or {}
        offenses = data.get("offenses") or {}
        stats = data.get("stats") or {}
        # Hash without the clock: vigil rewrites counters constantly and we
        # only want to notice when the set of actors changes.
        fp = "%d/%d" % (len(bans), len(offenses))
        with self._lock:
            self._bans, self._offenses, self._stats = bans, offenses, stats
            self._mtime = st.st_mtime
            self._fingerprint = fp
            self._err = ""
            for ip, rec in bans.items():
                self._recent[ip] = float(rec.get("until") or now)
            cutoff = now - 180
            for ip in list(self._recent):
                if self._recent[ip] < cutoff:
                    self._recent.pop(ip, None)
            while len(self._recent) > 4000:
                self._recent.popitem(last=False)

    def refresh(self) -> None:
        self._refresh(True)

    # -- queries ---------------------------------------------------------

    def ban(self, ip: str) -> dict:
        self._refresh()
        with self._lock:
            rec = self._bans.get(ip)
            if rec:
                out = dict(rec)
                out["live"] = True
            else:
                out = {"live": False}
            if ip in self._recent:
                out["recent"] = True
        return out

    def offense(self, ip: str) -> dict:
        self._refresh()
        with self._lock:
            return dict(self._offenses.get(ip) or {})

    def classify(self, ip: str, rate: float = 0.0, count: int = 0,
                 peak: float = 0.0, path: str = "", median: float = 0.0) -> tuple:
        """``(level, reason, detector)`` for one address.

        level: 0 normal, 1 attack, 2 high-pressure.

        Order matters, and so does restraint:

        1. A live or recent vigil ban is taken at face value. That is evidence
           produced by the security system, not an inference by this console.
        2. A stated number of offences is taken at face value too.
        3. Rate only decides when **all** of these hold: the path is not one
           that gets polled on a timer, the peak is high in absolute terms,
           it is far above what every other address is doing right now, and
           the window holds enough requests to be a pattern rather than a page
           load. An earlier version used a flat 4 req/s floor, which painted
           the DSH console's own long-poll red every few seconds.

        ``median`` is the median peak rate across active addresses; comparing
        against it is what separates "one busy client" from "a flood", and it
        needs no fixed threshold to be tuned per deployment.
        """
        ban = self.ban(ip)
        off = self.offense(ip)
        if ban.get("live") or ban.get("recent"):
            detector = (ban.get("detector") or "").strip()
            reason = (ban.get("reason") or "\u5c01\u7981\u4e2d").strip()
            lvl = 1
            blob = (detector + " " + reason).lower()
            if any(mark in blob for mark in _HIGH_MARKERS):
                lvl = 2
            if count >= 40 or rate >= 30:
                lvl = 2
            return lvl, reason, detector

        off_count = int(off.get("count") or 0)
        if off_count >= 3:
            return 1, "\u5df2\u8bb0\u5f55 %d \u6b21\u53ef\u7591\u884c\u4e3a" % off_count, "offense"

        if self.is_quiet_path(path):
            return 0, "", ""

        floor = max(1.0, median * settings.settings.rate_outlier_factor)
        if (peak >= settings.settings.pressure_rate and count >= 40
                and peak >= floor):
            return (2, "\u6301\u7eed\u9ad8\u9891 %.0f \u6b21/\u79d2\uff08\u5176\u4ed6\u6765\u6e90\u4e2d\u4f4d\u6570 %.1f\uff09"
                    % (peak, median), "rate")
        if (peak >= settings.settings.attack_rate and count >= 25
                and peak >= floor):
            return (1, "\u8bf7\u6c42\u9891\u7387\u5f02\u5e38 %.0f \u6b21/\u79d2\uff08\u5176\u4ed6\u6765\u6e90\u4e2d\u4f4d\u6570 %.1f\uff09"
                    % (peak, median), "rate")
        return 0, "", ""

    @staticmethod
    def is_discreet_path(path: str) -> bool:
        """True for paths that must never appear on the public console."""
        if not path:
            return False
        text = path.split("?")[0]
        lowered = text.lower()
        for prefix in _DISCREET_PATHS:
            if prefix.endswith("/"):
                if lowered.startswith(prefix):
                    return True
            elif lowered == prefix or lowered.startswith(prefix + "/"):
                return True
        return False

    @staticmethod
    def is_quiet_path(path: str) -> bool:
        """True for endpoints that are polled on a timer by a normal client."""
        if not path:
            return False
        text = path.split("?")[0]
        for prefix in _QUIET_PATHS:
            if prefix.endswith("/"):
                if text.startswith(prefix):
                    return True
            elif text == prefix or text.startswith(prefix + "/") or text.startswith(prefix + "?"):
                return True
        return False

    def clear_ip(self, ip: str) -> None:
        """Drop a cached offence record for one address.

        Used when an address turns out to be the operator's: their earlier
        requests should stop being described as offences, and nothing about
        them should remain in the published summary.
        """
        with self._lock:
            self._cache = {}
            getattr(self, "_offenses", {}).pop(ip, None)

    # -- aggregate -------------------------------------------------------

    def snapshot(self) -> dict:
        self._refresh()
        with self._lock:
            bans = self._bans
            offenses = self._offenses
            stats = dict(self._stats or {})
            recent = len(self._recent)
            err = self._err
            mtime = self._mtime
        now = time.time()
        live = 0
        by_reason: dict = {}
        by_detector: dict = {}
        newest = []
        for ip, rec in bans.items():
            until = float(rec.get("until") or 0)
            if until and until < now:
                continue
            live += 1
            reason = (rec.get("reason") or "\u672a\u8bf4\u660e").strip()
            detector = (rec.get("detector") or "\u672a\u77e5").strip()
            by_reason[reason] = by_reason.get(reason, 0) + 1
            by_detector[detector] = by_detector.get(detector, 0) + 1
            newest.append({"ip": ip, "reason": reason, "detector": detector,
                           "until": until, "count": int(rec.get("count") or 0)})
        newest.sort(key=lambda x: x["until"], reverse=True)
        top_off = sorted(
            ({"ip": ip, "count": int(r.get("count") or 0),
              "last": float(r.get("last") or 0)} for ip, r in offenses.items()),
            key=lambda x: (x["count"], x["last"]), reverse=True)[:20]
        return {
            "live_bans": live,
            "recent_bans": recent,
            "bans_total": int(stats.get("bans_total") or 0),
            "events": int(stats.get("events") or 0),
            "offenses": len(offenses),
            "alerts": int(stats.get("alerts") or 0),
            "breaker_tripped": int(stats.get("breaker_tripped") or 0),
            "decoy_hits": int(stats.get("decoy_hits") or 0),
            "posture_raised": int(stats.get("posture_raised") or 0),
            "distributed_events": int(stats.get("distributed_events") or 0),
            "whitelist_hits": int(stats.get("whitelist_hits") or 0),
            "uptime": int(now - float(stats.get("started") or now)),
            "ledger_age": round(now - mtime, 1) if mtime else None,
            "by_reason": sorted(by_reason.items(), key=lambda kv: kv[1], reverse=True)[:8],
            "by_detector": sorted(by_detector.items(), key=lambda kv: kv[1], reverse=True)[:8],
            "latest_bans": newest[:12],
            "top_offenders": top_off,
            "posture": self.posture(),
            "error": err,
        }

    # -- posture ---------------------------------------------------------

    def posture(self) -> dict:
        """Whether vigil has raised its guard, and how long is left."""
        path = settings.VIGIL_POSTURE_FLAG
        out = {"active": False, "until": None, "remaining": 0, "why": ""}
        try:
            text = path.read_text(encoding="utf-8").strip()
        except OSError:
            return out
        until = None
        why = ""
        try:
            data = json.loads(text)
            until = float(data.get("until") or 0) or None
            why = str(data.get("why") or data.get("reason") or "")
        except ValueError:
            # Older builds wrote a bare epoch.
            try:
                until = float(text)
            except ValueError:
                until = None
        now = time.time()
        if until and until > now:
            out.update({"active": True, "until": until,
                        "remaining": int(until - now), "why": why})
        return out


threat = ThreatState()
