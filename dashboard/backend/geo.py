"""Offline GeoIP: address -> place, never a network call.

The panel already ships a GeoLite2 city database for its own firewall view,
so the dashboard reuses it. That matters more than it looks: the moment a
server is under attack is exactly the moment an external geolocation API
starts rate-limiting you, and this console has to keep drawing the map.

The database the panel installs is a re-cut GeoLite2 with a flat shape::

    {"country": {"country": "\u7f8e\u56fd", "en_short_code": "US",
                 "operator": "Level3", "latitude": ..., "longitude": ...}}

but a stock MaxMind file uses the nested ``country``/``city``/``location``
shape. Both are handled, because an operator may drop in a stock file.
"""
from __future__ import annotations

import ipaddress
import threading
from collections import OrderedDict

from . import settings

try:                                                # vendored, stdlib-only
    import sys
    _vendor = str(settings.VENDOR)
    if _vendor not in sys.path:
        sys.path.insert(0, _vendor)
    import maxminddb
except Exception:                                   # pragma: no cover
    maxminddb = None


# --------------------------------------------------------------------------
# Address classification
# --------------------------------------------------------------------------

_PRIVATE = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)

#: Ranges RFC 5737 and friends reserve for documentation. A real packet never
#: comes from one, so if they appear it is a test fixture or forged traffic --
#: worth saying out loud instead of pinning it on a country.
_SPECIAL = {
    "192.0.2.0/24": "\u6587\u6863\u793a\u4f8b\u5730\u5740",
    "198.51.100.0/24": "\u6587\u6863\u793a\u4f8b\u5730\u5740",
    "203.0.113.0/24": "\u6587\u6863\u793a\u4f8b\u5730\u5740",
    "198.18.0.0/15": "\u7f51\u7edc\u8bbe\u5907\u6d4b\u8bd5\u5730\u5740",
}


def classify_address(ip: str) -> str:
    """``public`` | ``private`` | ``special`` | ``invalid``."""
    text = (ip or "").strip()
    if not text:
        return "invalid"
    try:
        addr = ipaddress.ip_address(text.split("%")[0])
    except ValueError:
        return "invalid"
    if addr.is_loopback or addr.is_link_local or addr.is_unspecified:
        return "private"
    for net in _PRIVATE:
        if addr.version == net.version and addr in net:
            return "private"
    for cidr in _SPECIAL:
        net = ipaddress.ip_network(cidr)
        if addr.version == net.version and addr in net:
            return "special"
    if not addr.is_global:
        return "private"
    return "public"


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------

class GeoDB:
    """A lazily opened MaxMind database plus a bounded result cache.

    Lookups run at tens of thousands per second with the vendored pure-python
    reader, so the cache is not there for speed; it is there so a flood from
    one address costs a dictionary hit per event instead of a database walk.
    """

    def __init__(self, path=None, cache_size: int = 20000) -> None:
        self._lock = threading.Lock()
        self._reader = None
        self._path = path
        self._cache: OrderedDict = OrderedDict()
        self._cache_size = max(256, int(cache_size))
        self._misses = 0
        self._hits = 0

    # -- opening ---------------------------------------------------------

    def _open(self):
        if self._reader is not None or maxminddb is None:
            return self._reader
        candidates = [self._path] if self._path else list(settings.GEODB_CANDIDATES)
        for cand in candidates:
            try:
                if cand and cand.exists():
                    self._reader = maxminddb.open_database(str(cand))
                    self._path = cand
                    break
            except Exception:                       # noqa: BLE001
                continue
        return self._reader

    @property
    def available(self) -> bool:
        return self._open() is not None

    @property
    def path(self) -> str:
        return str(self._path or "")

    # -- lookup ----------------------------------------------------------

    def lookup(self, ip: str) -> dict:
        """Place for *ip*, always a dict. Unknown addresses get empty fields.

        Keys: ``cc`` (ISO-3166 alpha-2), ``country`` (Chinese name when the
        database has one), ``city``, ``operator``, ``lat``, ``lon``, ``kind``.
        """
        text = (ip or "").strip()
        if not text:
            return {}
        cached = self._cache.get(text)
        if cached is not None:
            self._hits += 1
            self._cache.move_to_end(text)
            return cached

        kind = classify_address(text)
        if kind != "public":
            rec = {"kind": kind, "cc": "", "country": "", "city": "",
                   "operator": "", "lat": None, "lon": None}
            self._remember(text, rec)
            return rec

        rec = {"kind": "public", "cc": "", "country": "", "city": "",
               "operator": "", "lat": None, "lon": None}
        reader = self._open()
        if reader is not None:
            try:
                raw = reader.get(text)
            except Exception:                       # noqa: BLE001
                raw = None
            if raw:
                rec.update(self._flatten(raw))
        if not rec["cc"] and rec["lat"] is None:
            self._misses += 1
        self._remember(text, rec)
        return rec

    def _remember(self, ip: str, rec: dict) -> None:
        with self._lock:
            self._cache[ip] = rec
            self._cache.move_to_end(ip)
            while len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)

    @staticmethod
    def _flatten(raw: dict) -> dict:
        """Accept both the panel's flat file and a stock MaxMind record."""
        out = {"cc": "", "country": "", "city": "", "operator": "",
               "lat": None, "lon": None}

        # Panel shape: everything under a single "country" dict.
        c = raw.get("country")
        if isinstance(c, dict) and "en_short_code" in c:
            out["cc"] = (c.get("en_short_code") or "").strip().upper()
            out["country"] = (c.get("country") or "").strip()
            out["city"] = (c.get("city") or "").strip()
            out["operator"] = (c.get("operator") or "").strip()
            for key, dest in (("latitude", "lat"), ("longitude", "lon")):
                try:
                    out[dest] = float(c.get(key))
                except (TypeError, ValueError):
                    pass
            return out

        # Stock shape.
        country = raw.get("country") or {}
        out["cc"] = (country.get("iso_code") or "").strip().upper()
        names = country.get("names") or {}
        out["country"] = (names.get("zh-CN") or names.get("en") or "").strip()
        cnames = (raw.get("city") or {}).get("names") or {}
        out["city"] = (cnames.get("zh-CN") or cnames.get("en") or "").strip()
        loc = raw.get("location") or {}
        try:
            out["lat"] = float(loc.get("latitude"))
            out["lon"] = float(loc.get("longitude"))
        except (TypeError, ValueError):
            out["lat"] = out["lon"] = None
        traits = raw.get("traits") or {}
        asn = raw.get("asn") or ""
        out["operator"] = (traits.get("isp") or traits.get("organization")
                           or (("AS%s" % asn) if asn else "")).strip()
        return out

    def stats(self) -> dict:
        return {"db": self.path, "available": self.available,
                "cached": len(self._cache), "hits": self._hits,
                "misses": self._misses}


def server_point() -> dict:
    """The place every arc ends at."""
    return {"lat": settings.SERVER_LAT, "lon": settings.SERVER_LON,
            "cc": "HK",
            "country": "\u4e2d\u56fd\u9999\u6e2f"}


geo = GeoDB(cache_size=settings.settings.geo_cache)
