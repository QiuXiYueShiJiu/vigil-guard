#!/usr/bin/env python3
"""Build the flat world map the console draws.

Output: ``backend/data/world.json``

Design decisions, all of them driven by "the page must be usable on a slow
phone link":

* **Flat, not a globe.** This is a dashboard, not a planetarium. A plate
  carree plate is faster to draw, easier to read, and lets the map sit at the
  top of the page with no rotation maths at all.

* **Coordinates are not stored as text.** Plain ``[[x,y],[x,y],...]`` JSON
  costs roughly 13 bytes per point and this host's 1:10m coastline is half a
  million points. Each ring is delta-encoded, zig-zagged, packed as varints
  and base64'd instead: about 1.4 bytes per point, with a twenty-line decoder
  in the browser. The file a phone has to download drops by ~85%.

* **The CHN worldview edition of Natural Earth is the source of truth.** It
  is the edition in which Taiwan is part of China and no "Republic of China"
  feature exists, which is the correct rendering for this deployment.

Usage:
    python3 tools/build-map.py --src /tmp/ne/countries_chn.geojson
"""
from __future__ import annotations

import argparse
import base64
import json
import math
import os
import sys
import time
import zlib

SCALE = 1000          # milli-degrees: ~110 m of ground accuracy
MAX_LAT = 84.0        # Mercator runs to infinity at the poles


def rings_of(geom: dict):
    t = geom.get("type")
    if t == "Polygon":
        for ring in geom.get("coordinates", []):
            yield ring
    elif t == "MultiPolygon":
        for poly in geom.get("coordinates", []):
            for ring in poly:
                yield ring


def perp_distance(pt, a, b) -> float:
    if a == b:
        return math.hypot(pt[0] - a[0], pt[1] - a[1])
    x0, y0 = pt
    x1, y1 = a
    x2, y2 = b
    dx, dy = x2 - x1, y2 - y1
    denom = math.hypot(dx, dy) or 1.0
    return abs(dy * x0 - dx * y0 + x2 * y1 - y2 * x1) / denom


def simplify(points, tolerance: float):
    """Douglas-Peucker, iterative so a 40k-point ring cannot blow the stack."""
    if tolerance <= 0 or len(points) < 3:
        return points
    keep = [False] * len(points)
    keep[0] = keep[-1] = True
    stack = [(0, len(points) - 1)]
    while stack:
        first, last = stack.pop()
        if last <= first + 1:
            continue
        worst, index = 0.0, first
        for i in range(first + 1, last):
            dist = perp_distance(points[i], points[first], points[last])
            if dist > worst:
                worst, index = dist, i
        if worst > tolerance:
            keep[index] = True
            stack.append((first, index))
            stack.append((index, last))
    return [p for p, k in zip(points, keep) if k]


def _zigzag(value: int) -> int:
    return (value << 1) if value >= 0 else ((-value << 1) - 1)


def _varint(buf: bytearray, value: int) -> None:
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            buf.append(byte | 0x80)
        else:
            buf.append(byte)
            return


def encode_ring(ring, scale: int) -> tuple:
    """Ring -> (base64(delta + zigzag + varint), byte length).

    The byte length travels with the string so the client can check that its
    decoder produced exactly that many bytes. A truncated download, a proxy
    that mangled the body, or a stale cached copy from an older data format
    all fail that check loudly instead of quietly drawing a wrong map -- or,
    in the case of a format change, throwing a bare `atob` error with no hint
    of what went wrong.
    """
    buf = bytearray()
    px = py = 0
    for lon, lat in ring:
        x = int(round(lon * scale))
        y = int(round(lat * scale))
        _varint(buf, _zigzag(x - px))
        _varint(buf, _zigzag(y - py))
        px, py = x, y
    return base64.b64encode(bytes(buf)).decode("ascii"), len(buf)


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default="/tmp/ne/countries_chn.geojson")
    ap.add_argument("--out", default=os.path.join(root, "backend", "data", "world.json"))
    ap.add_argument("--tolerance", type=float, default=0.014,
                    help="Douglas-Peucker tolerance in degrees (~1.5 km)")
    ap.add_argument("--min-area", type=float, default=0.002,
                    help="drop rings smaller than this many square degrees")
    ap.add_argument("--scale", type=int, default=SCALE)
    args = ap.parse_args()

    with open(args.src, "r", encoding="utf-8") as fh:
        src = json.load(fh)

    countries, labels = [], []
    points_in = points_out = rings_dropped = 0

    for feat in src.get("features", []):
        pr = feat.get("properties") or {}
        zh = (pr.get("NAME_ZH") or pr.get("NAME_ZHT") or pr.get("ADMIN")
              or pr.get("NAME") or "").strip()
        en = (pr.get("ADMIN") or pr.get("NAME") or "").strip()
        iso2 = (pr.get("ISO_A2") or "").strip()
        if iso2 in ("", "-99"):
            iso2 = (pr.get("ISO_A2_EH") or "").strip()

        kept = []
        for ring in rings_of(feat.get("geometry") or {}):
            if len(ring) < 4:
                continue
            points_in += len(ring)
            area = 0.0
            for i in range(len(ring)):
                x1, y1 = ring[i]
                x2, y2 = ring[(i + 1) % len(ring)]
                area += x1 * y2 - x2 * y1
            if abs(area) / 2.0 < args.min_area:
                rings_dropped += 1
                continue
            simp = simplify(ring, args.tolerance)
            if len(simp) < 4:
                continue
            if simp[0] != simp[-1]:
                simp.append(simp[0])
            kept.append(simp)
            points_out += len(simp)
        if not kept:
            continue

        index = len(countries)
        encoded = [encode_ring(r, args.scale) for r in kept]
        countries.append({
            "i": index,
            "r": [item[0] for item in encoded],
            "b": [item[1] for item in encoded],   # decoded byte length
            "n": [len(r) for r in kept],
        })

        lx, ly = pr.get("LABEL_X"), pr.get("LABEL_Y")
        if lx is None or ly is None:
            big = max(kept, key=len)
            lx = sum(p[0] for p in big) / len(big)
            ly = sum(p[1] for p in big) / len(big)
        labels.append({
            "i": index,
            "n": zh or en,
            "x": round(float(lx), 2),
            "y": round(float(ly), 2),
            "c": iso2,
        })

    doc = {
        "v": 2,
        "meta": {
            "source": "Natural Earth 1:10m Admin 0 - Countries (CHN worldview edition)",
            "source_url": "https://www.naturalearthdata.com/",
            "license": "Public domain",
            "note": ("Boundary editions follow the People's Republic of China's "
                     "official position; no disputed entity is drawn as an "
                     "independent state."),
            "projection": "equirectangular",
            "encoding": "b64-delta-zigzag-varint",
            "scale": args.scale,
            "tolerance_deg": args.tolerance,
            "lat_clamp": MAX_LAT,
            "countries": len(countries),
            "points": points_out,
            "points_source": points_in,
            "rings_dropped": rings_dropped,
            "built": int(time.time()),
        },
        "countries": countries,
        "labels": labels,
    }

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, separators=(",", ":"))

    size = os.path.getsize(args.out)
    with open(args.out, "rb") as fh:
        gz = len(zlib.compress(fh.read(), 9))
    print("countries=%d points=%d->%d rings_dropped=%d"
          % (len(countries), points_in, points_out, rings_dropped))
    print("wrote %s  %.1f KiB  (gzip %.1f KiB)"
          % (args.out, size / 1024, gz / 1024))
    return 0


if __name__ == "__main__":
    sys.exit(main())
