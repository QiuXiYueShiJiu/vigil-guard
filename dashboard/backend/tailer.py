"""Tail the nginx access logs and turn them into map events.

One background thread. It keeps a byte offset per log file, re-reads from
the top when a log is rotated, and pushes finished events onto a callback.
Nothing else in the process touches the log files.

Two access-log formats show up on this host and both are handled:

* the panel's JSON format (``log_format site_total escape=json``), written
  by the individual vhosts;
* the classic combined format that the older vhosts still use.

The parser is deliberately forgiving: a malformed line is counted and
skipped, never allowed to kill the tailer. A traffic log is hostile input.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time

from . import settings

#: 198.51.100.7 - - [04/Oct/2026:02:02:53 +0800] "GET /x HTTP/2.0" 200 12189 "-" "curl/7.81.0"
_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<req>(?P<method>[A-Z]+) (?P<path>\S+)[^"]*)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

_MONTHS = {m: i + 1 for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"))}

#: Cache directory for the built-in browser checks: a request path that looks
#: like a probe for a file that is rarely a real visitor.
_STATUS_LEVEL = {401: 0, 403: 1, 404: 1, 444: 1, 502: 2, 503: 2, 500: 2}


def _parse_combined_ts(text: str) -> float:
    """``04/Oct/2026:02:02:53 +0800`` -> epoch seconds (local clock)."""
    try:
        stamp, _, zone = text.partition(" ")
        date, _, clock = stamp.partition(":")
        day, month, year = date.split("/")
        hh, mm, ss = clock.split(":")
        base = time.mktime((int(year), _MONTHS.get(month, 1), int(day),
                            int(hh), int(mm), int(ss), 0, 0, -1))
        if zone and (zone[0] in "+-") and len(zone) == 5:
            off = (int(zone[1:3]) * 3600 + int(zone[3:5]) * 60)
            base -= off if zone[0] == "+" else -off
        return base
    except Exception:                               # noqa: BLE001
        return time.time()


class Event:
    """One request, already trimmed to what the map draws."""

    __slots__ = ("ts", "ip", "method", "path", "status", "ua", "host", "site",
                 "src")

    def __init__(self, ts, ip, method, path, status, ua, host, site, src="") -> None:
        self.ts = ts
        self.ip = ip
        self.method = method
        self.path = path
        self.status = status
        self.ua = ua
        self.host = host
        self.site = site
        # Which log file this line came from. Without it, tracking down a
        # repeated source means guessing between a dozen files.
        self.src = src

    def as_dict(self) -> dict:
        return {"ts": round(self.ts, 3), "ip": self.ip, "m": self.method,
                "p": (self.path or "")[:220], "s": self.status,
                "ua": (self.ua or "")[:180], "h": self.host or "",
                "site": self.site}


class LogTailer:
    """Follows every site log in the log directory."""

    def __init__(self, on_event, log_dir=None) -> None:
        self._on_event = on_event
        self._dir = log_dir or settings.LOG_DIR
        self._offsets: dict = {}       # path -> {"pos": int, "ino": int, "carry": bytes}
        self._thread = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._stats = {"lines": 0, "events": 0, "bad": 0, "files": 0,
                       "last_read": 0.0, "skipped_no_geo": 0}

    # -- file discovery --------------------------------------------------

    def _files(self) -> list:
        out = []
        try:
            entries = list(os.scandir(self._dir))
        except OSError:
            return out
        for entry in entries:
            try:
                if not entry.is_file(follow_symlinks=True):
                    continue
            except OSError:
                continue
            name = entry.name
            if name in settings.LOG_SKIP:
                continue
            if name.endswith(settings.LOG_SUFFIX_DROP):
                continue
            if not (name.endswith(".log") or name.endswith(".log.1")):
                continue
            out.append(entry.path)
        out.sort()
        return out

    # -- parsing ---------------------------------------------------------

    @staticmethod
    def _parse(line: str, site: str, src: str = ""):
        line = line.strip()
        if not line:
            return None
        if line.startswith("{"):
            try:
                d = json.loads(line)
            except ValueError:
                return None
            ts = d.get("msec")
            if ts is None:
                raw = d.get("time_iso8601") or d.get("time_local") or ""
                if "T" in raw:
                    from datetime import datetime
                    try:
                        ts = datetime.fromisoformat(raw).timestamp()
                    except ValueError:
                        ts = None
                if ts is None and raw:
                    ts = _parse_combined_ts(raw)
            try:
                ts = float(ts) if ts is not None else time.time()
            except (TypeError, ValueError):
                ts = time.time()
            ip = (d.get("remote_addr") or d.get("client_ip")
                  or d.get("x_real_ip") or d.get("true_client_ip") or "").strip()
            if not ip:
                return None
            try:
                status = int(d.get("status") or 0)
            except (TypeError, ValueError):
                status = 0
            return Event(ts, ip, (d.get("method") or "").strip(),
                         (d.get("uri") or d.get("request_uri") or "").strip(),
                         status, (d.get("user_agent") or "").strip(),
                         (d.get("host") or "").strip(), site, src)

        m = _COMBINED.match(line)
        if not m:
            return None
        g = m.groupdict()
        return Event(_parse_combined_ts(g["ts"]), g["ip"], g["method"] or "",
                     g["path"] or "", int(g["status"] or 0), g["ua"] or "",
                     "", site, src)

    # -- reading ---------------------------------------------------------

    def _read_file(self, path: str) -> list:
        events = []
        try:
            st = os.stat(path)
        except OSError:
            return events
        rec = self._offsets.get(path)
        if rec is None or rec["ino"] != st.st_ino or st.st_size < rec["pos"]:
            # New file, or the log was rotated/truncated: start at the end so
            # a restart does not replay a million historical lines.
            rec = {"pos": st.st_size, "ino": st.st_ino, "carry": b""}
            self._offsets[path] = rec
            return events
        if st.st_size == rec["pos"]:
            return events
        try:
            with open(path, "rb") as fh:
                fh.seek(rec["pos"])
                chunk = fh.read(1024 * 1024)
                rec["pos"] = fh.tell()
        except OSError:
            return events
        if not chunk:
            return events
        data = rec["carry"] + chunk
        lines = data.split(b"\n")
        rec["carry"] = lines.pop() if lines else b""
        # A pathological single line must not grow without bound.
        if len(rec["carry"]) > 65536:
            rec["carry"] = b""
        site = _site_of(path)
        for raw in lines:
            if not raw:
                continue
            self._stats["lines"] += 1
            try:
                text = raw.decode("utf-8", "replace")
            except Exception:                       # noqa: BLE001
                self._stats["bad"] += 1
                continue
            ev = self._parse(text, site, os.path.basename(path))
            if ev is None:
                self._stats["bad"] += 1
                continue
            events.append(ev)
        return events

    def poll(self) -> list:
        """One pass over every log. Returns the events found."""
        files = self._files()
        self._stats["files"] = len(files)
        found = []
        budget = int(settings.settings.max_events_per_poll)
        for path in files:
            if len(found) >= budget:
                break
            batch = self._read_file(path)
            if batch:
                found.extend(batch[:budget - len(found)])
        self._stats["last_read"] = time.time()
        if found:
            found.sort(key=lambda e: e.ts)
            self._stats["events"] += len(found)
        return found

    def run(self) -> None:
        interval = max(0.15, float(settings.settings.poll_ms) / 1000.0)
        while not self._stop.is_set():
            try:
                events = self.poll()
                for ev in events:
                    self._on_event(ev)
            except Exception:                       # noqa: BLE001
                pass
            self._stop.wait(interval)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self.run, name="log-tailer",
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def stats(self) -> dict:
        with self._lock:
            out = dict(self._stats)
        out["tracked"] = len(self._offsets)
        return out


def _site_of(path: str) -> str:
    """Human label for a log file: which site it belongs to."""
    name = os.path.basename(path)
    if name.endswith(".log"):
        name = name[:-4]
    if name.startswith("xn--") or name.startswith("www."):
        return name
    return name
