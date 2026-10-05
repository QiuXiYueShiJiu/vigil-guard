#!/usr/bin/env python3
"""Render the map exactly as the browser engine computes it, to a PNG.

This exists because there is no headless browser on this host, and the flat
map's geometry is easy to get subtly wrong -- the first version of
``frontend/assets/map.js`` had four separate projection bugs that all drew
something plausible. This re-implements the *same* formulas (projectionY,
_yScale, the pan/zoom transform) and rasterises them with the standard
library, so a wrong map is visible in one command instead of in a browser
you cannot open.

Keep the three constants below in step with map.js:

    MERC_LIMIT = log(tan(pi/4 + 84deg/2))
    yScale     = max(width/2, height) / 2
    xScale     = width * zoom / 360

    tools/render-map.py --preset asia -o /tmp/asia.png
    tools/render-map.py --preset world --width 1200 --height 600 -o w.png
"""
from __future__ import annotations

import argparse
import base64
import json
import math
import os
import struct
import sys
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORLD = os.path.join(ROOT, "backend", "data", "world.json")

DEG = math.pi / 180
MERC_LIMIT = math.log(math.tan(math.pi / 4 + (84 * DEG) / 2))

# Keep in step with VIEWS in frontend/assets/map.js. `zoom=0` means "fit the
# whole plate": render-map.py computes it the same way map.js does.
PRESETS = {
    "world":    dict(lon=0, lat=0, zoom=0),
    "asia":     dict(lon=115, lat=18, zoom=1.55),
    "europe":   dict(lon=18, lat=42, zoom=2.6),
    "americas": dict(lon=-70, lat=16, zoom=1.5),
}

# Matches frontend/assets/map.js: warm paper water, grey land, orange beacon.
# Matches frontend/assets/map.js
SEA_TOP = (247, 236, 220)
SEA_MID = (251, 245, 238)
SEA_BOT = (255, 253, 250)
LAND_TOP = (239, 230, 215)
LAND_BOT = (226, 212, 193)
COAST = (150, 128, 100)
GRAT = (198, 172, 142)
BEACON = (194, 104, 38)
LEVEL_COLOUR = {0: (58, 122, 82), 1: (208, 64, 48), 2: (132, 30, 24)}


def projection_y(lat: float) -> float:
    clamped = max(-84.0, min(84.0, lat))
    merc = math.log(math.tan(math.pi / 4 + (clamped * DEG) / 2))
    return -merc / MERC_LIMIT


def decode_ring(b64: str):
    blob = base64.b64decode(b64)
    out = []
    i = 0
    x = y = 0
    while i < len(blob):
        shift = value = 0
        while True:
            byte = blob[i]
            i += 1
            value |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                break
        x += -((value + 1) >> 1) if value & 1 else value >> 1
        shift = value = 0
        while True:
            byte = blob[i]
            i += 1
            value |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                break
        y += -((value + 1) >> 1) if value & 1 else value >> 1
        out.append((x / 1000.0, y / 1000.0))
    return out


class Plate:
    def __init__(self, doc, width, height, lon, lat, zoom):
        self.doc = doc
        self.w = width
        self.h = height
        self.lon = lon
        self.lat = lat
        self.zoom = zoom
        self.cx = width / 2
        self.cy = height / 2
        if zoom <= 0:
            # Fit the whole plate: lat centred on the band, zoom solved from
            # the height constraint (projectionY spans -1..1).
            north = projection_y(84)
            south = projection_y(-84)
            centre = (north + south) / 2
            lat = (2 * math.atan(math.exp(centre * MERC_LIMIT)) - math.pi / 2) / DEG
            half = abs(north - centre)
            zoom = min(1.0, (2 * height) / (width * half)) * 0.99
            lon = 0.0
        self.lat = lat
        self.lon = lon
        self.zoom = zoom
        self.x_scale = width * zoom / 360.0
        # Fixed 2:1 plate: 360 degrees wide, projectionY spans -1..1.
        self.y_scale = self.x_scale * 90.0
        self.proj_y = projection_y(lat)

    def project(self, plon, plat):
        return (self.cx + (plon - self.lon) * self.x_scale,
                self.cy + (projection_y(plat) - self.proj_y) * self.y_scale)

    def unproject(self, x, y):
        plon = self.lon + (x - self.cx) / self.x_scale
        proj = self.proj_y + (y - self.cy) / self.y_scale
        merc = -proj * MERC_LIMIT
        plat = (2 * math.atan(math.exp(merc)) - math.pi / 2) / DEG
        return plon, plat


class Canvas:
    def __init__(self, w, h, sea=SEA_MID):
        self.w, self.h = w, h
        self.buf = bytearray(sea * (w * h))

    def put(self, x, y, colour, weight=1):
        xi, yi = int(x), int(y)
        half = weight // 2
        for dy in range(-half, half + 1):
            for dx in range(-half, half + 1):
                xx, yy = xi + dx, yi + dy
                if 0 <= xx < self.w and 0 <= yy < self.h:
                    k = (yy * self.w + xx) * 3
                    self.buf[k:k + 3] = bytes(colour)

    def line(self, x0, y0, x1, y1, colour, weight=1):
        steps = int(max(abs(x1 - x0), abs(y1 - y0))) + 1
        for t in range(steps + 1):
            k = t / steps
            self.put(x0 + (x1 - x0) * k, y0 + (y1 - y0) * k, colour, weight)

    def fill_rings(self, rings, colour):
        edges = []
        ymin, ymax = 1e9, -1e9
        for pts in rings:
            n = len(pts)
            for i in range(n):
                ax, ay = pts[i]
                bx, by = pts[(i + 1) % n]
                if ay == by:
                    continue
                edges.append((ax, ay, bx, by))
                ymin = min(ymin, ay, by)
                ymax = max(ymax, ay, by)
        if not edges:
            return
        for y in range(max(0, int(ymin)), min(self.h - 1, int(ymax)) + 1):
            yc = y + 0.5
            xs = []
            for (ax, ay, bx, by) in edges:
                if (ay <= yc < by) or (by <= yc < ay):
                    xs.append(ax + (bx - ax) * (yc - ay) / (by - ay))
            if not xs:
                continue
            xs.sort()
            for i in range(0, len(xs) - 1, 2):
                for x in range(max(0, int(xs[i])), min(self.w - 1, int(xs[i + 1])) + 1):
                    k = (y * self.w + x) * 3
                    self.buf[k:k + 3] = bytes(colour)

    def shelf(self, rings, colour, width):
        """A wide soft outline drawn under the coastline: the shallow-water
        shelf. Drawn by stamping discs along the ring, which is cheap and
        reads better than a thick polyline at corners."""
        r = max(1, width // 2)
        for pts in rings:
            for i in range(len(pts) - 1):
                x0, y0 = pts[i]
                x1, y1 = pts[i + 1]
                steps = int(max(abs(x1 - x0), abs(y1 - y0))) + 1
                for t in range(0, steps + 1, 2):
                    k = t / steps
                    self._disc(x0 + (x1 - x0) * k, y0 + (y1 - y0) * k, r, colour)

    def _disc(self, cx, cy, r, colour):
        for oy in range(-r, r + 1):
            for ox in range(-r, r + 1):
                if ox * ox + oy * oy > r * r:
                    continue
                x, y = int(cx) + ox, int(cy) + oy
                if 0 <= x < self.w and 0 <= y < self.h:
                    k = (y * self.w + x) * 3
                    self.buf[k:k + 3] = bytes(colour)

    def fill_rings_gradient(self, rings, top, bottom):
        """Even-odd scanline fill with a vertical gradient, matching the
        browser's createLinearGradient(0, 0, 0, h) on the land path."""
        edges = []
        ymin, ymax = 1e9, -1e9
        for pts in rings:
            n = len(pts)
            for i in range(n):
                ax, ay = pts[i]
                bx, by = pts[(i + 1) % n]
                if ay == by:
                    continue
                edges.append((ax, ay, bx, by))
                ymin = min(ymin, ay, by)
                ymax = max(ymax, ay, by)
        if not edges:
            return
        span = max(1, self.h - 1)
        for y in range(max(0, int(ymin)), min(self.h - 1, int(ymax)) + 1):
            t = y / span
            colour = bytes(int(top[i] + (bottom[i] - top[i]) * t) for i in range(3))
            yc = y + 0.5
            xs = []
            for (ax, ay, bx, by) in edges:
                if (ay <= yc < by) or (by <= yc < ay):
                    xs.append(ax + (bx - ax) * (yc - ay) / (by - ay))
            if not xs:
                continue
            xs.sort()
            for i in range(0, len(xs) - 1, 2):
                for x in range(max(0, int(xs[i])), min(self.w - 1, int(xs[i + 1])) + 1):
                    k = (y * self.w + x) * 3
                    self.buf[k:k + 3] = colour

    def write_png(self, path):
        raw = b"".join(b"\x00" + bytes(self.buf[y * self.w * 3:(y + 1) * self.w * 3])
                       for y in range(self.h))

        def chunk(tag, data):
            body = tag + data
            return (struct.pack(">I", len(data)) + body
                    + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF))

        header = struct.pack(">IIBBBBB", self.w, self.h, 8, 2, 0, 0, 0)
        with open(path, "wb") as fh:
            fh.write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
                     + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--preset", choices=sorted(PRESETS), default="asia")
    ap.add_argument("--lon", type=float)
    ap.add_argument("--lat", type=float)
    ap.add_argument("--zoom", type=float)
    ap.add_argument("--width", type=int, default=1000)
    ap.add_argument("--height", type=int, default=470)
    ap.add_argument("--marks", default="",
                    help="lat,lon,level;lat,lon,level  (0 visit, 1 attack, 2 pressure)")
    ap.add_argument("-o", "--out", default="/tmp/map-preview.png")
    args = ap.parse_args()

    cfg = dict(PRESETS[args.preset])
    for key in ("lon", "lat", "zoom"):
        value = getattr(args, key)
        if value is not None:
            cfg[key] = value

    with open(WORLD, "r", encoding="utf-8") as fh:
        doc = json.load(fh)

    plate = Plate(doc, args.width, args.height, cfg["lon"], cfg["lat"], cfg["zoom"])
    canvas = Canvas(args.width, args.height)

    # Sea: the same three-stop vertical gradient the browser paints.
    for y in range(args.height):
        t = y / max(1, args.height - 1)
        if t < 0.45:
            k = t / 0.45
            col = tuple(int(SEA_TOP[i] + (SEA_MID[i] - SEA_TOP[i]) * k) for i in range(3))
        else:
            k = (t - 0.45) / 0.55
            col = tuple(int(SEA_MID[i] + (SEA_BOT[i] - SEA_MID[i]) * k) for i in range(3))
        for x in range(args.width):
            k = (y * args.width + x) * 3
            canvas.buf[k:k + 3] = bytes(col)

    # Graticule, skipped at world scale exactly like the browser does.
    step = 10 if plate.zoom > 3.5 else (5 if plate.zoom > 7 else 20)
    if step <= 20:
        lat_of = lambda p: (2 * math.atan(math.exp(-p * MERC_LIMIT)) - math.pi / 2) / DEG
        top_proj = plate.proj_y - plate.cy / plate.y_scale
        bot_proj = plate.proj_y + (plate.h - plate.cy) / plate.y_scale
        lat_line = math.floor(lat_of(top_proj) / step) * step
        while lat_line >= lat_of(bot_proj):
            _, y = plate.project(0, lat_line)
            canvas.line(0, y, plate.w, y, GRAT)
            lat_line -= step
        lon_span = 360 / plate.zoom
        lon_line = math.floor((cfg["lon"] - lon_span / 2) / step) * step
        while lon_line <= cfg["lon"] + lon_span / 2:
            x, _ = plate.project(lon_line, 0)
            canvas.line(x, 0, x, plate.h, GRAT)
            lon_line += step

    rings = []
    for country in doc["countries"]:
        for encoded in country["r"]:
            rings.append([plate.project(a, b) for (a, b) in decode_ring(encoded)])

    # Shallow-water shelf: a wide soft ring under the coastline.
    canvas.shelf(rings, (246, 232, 212), 4)
    canvas.shelf(rings, (240, 220, 196), 2)

    # Land with the vertical gradient.
    canvas.fill_rings_gradient(rings, LAND_TOP, LAND_BOT)
    for pts in rings:
        for i in range(len(pts) - 1):
            canvas.line(pts[i][0], pts[i][1], pts[i + 1][0], pts[i + 1][1], COAST)

    # Labels with the same thinning and halo as the browser.
    labels = doc.get("labels", [])
    lstep = 1 if plate.zoom > 9 else 2 if plate.zoom > 4.5 else 4 if plate.zoom > 2 else 10
    for index, label in enumerate(labels):
        if index % lstep:
            continue
        x, y = plate.project(label["x"], label["y"])
        if x < 30 or x > plate.w - 30 or y < 14 or y > plate.h - 14:
            continue
        canvas.put(x - 3, y, (253, 248, 241), 6)   # halo blot
        canvas.put(x - 1, y, (100, 82, 62), 2)     # a mark where the name goes

    # Meteor traces: head + gradient tail + fading source dot.
    origin = plate.project(114.1694, 22.3193)
    for item in [m for m in args.marks.split(";") if m]:
        parts = item.split(",")
        if len(parts) < 3:
            continue
        mlat, mlon, level = float(parts[0]), float(parts[1]), int(parts[2])
        sx, sy = plate.project(mlon, mlat)
        colour = LEVEL_COLOUR.get(level, LEVEL_COLOUR[0])
        head = 0.72
        hx = sx + (origin[0] - sx) * head
        hy = sy + (origin[1] - sy) * head
        tail = 0.45 if level == 0 else 0.55
        tx = hx + (sx - hx) * tail
        ty = hy + (sy - hy) * tail
        steps = int(max(abs(hx - tx), abs(hy - ty))) + 1
        for i in range(steps + 1):
            k = i / steps
            fade_k = k * k
            blend = tuple(int(SEA_MID[j] + (colour[j] - SEA_MID[j]) * fade_k) for j in range(3))
            canvas.put(tx + (hx - tx) * k, ty + (hy - ty) * k, blend,
                       1 if level == 0 else 2 if level == 1 else 3)
        canvas.put(hx, hy, (255, 255, 255), 3)
        canvas.put(sx, sy, colour, 2 if level == 0 else 3)
        for radius in (5, 9, 13):
            for angle in range(0, 360, 3):
                canvas.put(origin[0] + radius * math.cos(math.radians(angle)),
                           origin[1] + radius * math.sin(math.radians(angle)), colour)

    for radius in (4, 8, 12):
        for angle in range(0, 360, 3):
            canvas.put(origin[0] + radius * math.cos(math.radians(angle)),
                       origin[1] + radius * math.sin(math.radians(angle)), BEACON)
    canvas.put(origin[0], origin[1], (255, 255, 255), 3)
    canvas.put(origin[0], origin[1], BEACON, 1)

    canvas.write_png(args.out)
    print("preset=%-9s centre=(%.1f, %.1f) zoom=%.2f  x-scale=%.2f  y-scale=%.2f"
          % (args.preset, cfg["lat"], cfg["lon"], cfg["zoom"], plate.x_scale, plate.y_scale))
    for name, (plon, plat) in (("北京", (116.4, 39.9)), ("主机", (114.17, 22.3)),
                               ("伦敦", (-0.1, 51.5)), ("悉尼", (151.2, -33.9))):
        x, y = plate.project(plon, plat)
        print("  %-4s -> (%6.0f, %6.0f)" % (name, x, y))
    print("wrote", args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
