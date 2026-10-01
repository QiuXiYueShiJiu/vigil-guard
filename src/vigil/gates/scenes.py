"""Picture sources for the slider puzzle.

The gate can build its challenge from two very different things:

``art``
    A landscape rendered on the spot, in a flat cel-shaded style. Always
    available, always the right shape, and it ships with the package.

``image``
    A picture from a directory the operator points at. Better looking, but
    the package must not carry one: the images belong to whoever installed
    it, and a security tool that bundles decoration is a security tool that
    ages badly.

``auto``
    Whichever is available, chosen fresh for every challenge, so the "new
    puzzle" link changes the kind of picture as well as the picture.

Scanning is done here rather than in PHP so the command line can report what
it found before anything is installed. The filters must stay in step with
:func:`vigil_slider_pool` in the gate library -- this decides what the
operator is told, that decides what is actually served, and a disagreement
between them would be a confusing bug to chase. Both are written out in
``_USABLE`` below.

Standard library only, like the rest of the project, which is why the image
headers are parsed by hand instead of with Pillow.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

SCENE_KINDS = ("art", "image", "auto")

#: Extensions the gate will look at. Kept in step with ``vigil_slider_pool``.
_SUFFIXES = (".jpg", ".jpeg", ".png", ".webp")

#: Minimum file size. Anything smaller is a sticker, an icon or a thumbnail --
#: none of which survive being cropped to a 17:10 band.
MIN_BYTES = 45_000

#: Minimum source resolution, for the same reason.
MIN_WIDTH = 640
MIN_HEIGHT = 360

#: Accepted aspect ratio. Portrait is allowed but only mildly: below roughly
#: 0.85 the wide crop throws away so much of the frame that the result stops
#: being a picture and becomes a texture. The upper bound rules out banners.
MIN_RATIO = 0.85
MAX_RATIO = 3.6

#: Directories worth probing on an unfamiliar host. These are *patterns*, not
#: content: nothing server-specific is baked into the package, and an empty
#: result is a perfectly normal outcome that simply leaves the pool empty.
DISCOVERY_GLOBS = (
    # Desktop wallpaper and background collections, which is what a host that
    # already holds a picture library almost always has.
    "/usr/share/backgrounds",
    "/usr/share/backgrounds/*",
    "/usr/share/wallpapers",
    "/usr/share/wallpapers/*",
    "/usr/share/pixmaps/*",
    # The usual hand-curated homes.
    "/root/pictures",
    "/root/Pictures",
    "/root/images",
    "/root/wallpaper",
    "/srv/pictures",
    "/data/pictures",
    "/opt/pictures",
    # Web application upload directories: a site that hosts images already
    # has a corpus, and the operator has already decided they are fit to be
    # served in public.
    "/www/wwwroot/*/assets/img",
    "/www/wwwroot/*/assets/images",
    "/var/www/*/assets/img",
    "/var/www/html/wp-content/uploads/*",
)

#: Directories that must never be used, however many pictures they hold.
#: These are caches and scratch space: their contents are whatever happened to
#: pass through the host, which on a chat bot means memes, screenshots, other
#: people's profile photos, and occasionally something the operator would
#: rather not have on a login page. Offered as a warning, never as a default.
TRANSIENT_HINTS = ("/tmp/", "/var/tmp/", "/temp/", "/cache/", "/.cache/",
                   "/media_image", "/downloads/", "/.trash/")


def _png_size(head: bytes):
    if len(head) < 24 or head[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    w, h = struct.unpack(">II", head[16:24])
    return int(w), int(h)


def _gif_size(head: bytes):
    if len(head) < 10 or head[:3] != b"GIF":
        return None
    w, h = struct.unpack("<HH", head[6:10])
    return int(w), int(h)


def _webp_size(head: bytes):
    if len(head) < 30 or head[:4] != b"RIFF" or head[8:12] != b"WEBP":
        return None
    kind = head[12:16]
    if kind == b"VP8 ":
        w, h = struct.unpack("<HH", head[26:30])
        return int(w) & 0x3FFF, int(h) & 0x3FFF
    if kind == b"VP8L":
        bits = struct.unpack("<I", head[21:25])[0]
        return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
    if kind == b"VP8X":
        w = head[24] | (head[25] << 8) | (head[26] << 16)
        h = head[27] | (head[28] << 8) | (head[29] << 16)
        return w + 1, h + 1
    return None


def _jpeg_size(head: bytes):
    """Walk the JPEG marker chain to the frame header.

    The size is not at a fixed offset -- it lives in whichever SOFn segment
    comes first -- so the segments have to be skipped one by one. Progressive
    JPEGs put it in SOF2, and treating SOF0 as the only possibility is the
    classic way to report "0x0" for half the photos on a disk.
    """
    if len(head) < 4 or head[:2] != b"\xff\xd8":
        return None
    i = 2
    n = len(head)
    while i + 9 < n:
        if head[i] != 0xFF:
            i += 1
            continue
        marker = head[i + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        if marker == 0xD9 or marker == 0xDA:
            break
        seglen = struct.unpack(">H", head[i + 2:i + 4])[0]
        if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
                      0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            h, w = struct.unpack(">HH", head[i + 5:i + 9])
            return int(w), int(h)
        i += 2 + seglen
    return None


def image_size(path) -> tuple:
    """Return ``(width, height)`` for a JPEG/PNG/GIF/WebP, or ``None``.

    Only the header is read, so pointing this at a directory of two thousand
    photographs costs a few milliseconds rather than a few seconds.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return None
    for probe in (_png_size, _jpeg_size, _webp_size, _gif_size):
        try:
            got = probe(head)
        except (struct.error, IndexError):
            got = None
        if got:
            return got
    return None


def usable(path) -> tuple:
    """Is this file usable as a puzzle picture?

    Returns ``(True, "")`` or ``(False, reason)``. The reasons are meant to be
    read by a person deciding what to do about it.
    """
    p = Path(path)
    try:
        if not p.is_file():
            return False, "不是文件"
        size = p.stat().st_size
    except OSError:
        return False, "无法读取"
    if size < MIN_BYTES:
        return False, "文件太小（%d KB）" % (size // 1024)
    dims = image_size(p)
    if not dims:
        return False, "不是可识别的 JPEG/PNG/WebP"
    w, h = dims
    if w < MIN_WIDTH or h < MIN_HEIGHT:
        return False, "分辨率不足（%dx%d）" % (w, h)
    ratio = w / max(1, h)
    if ratio < MIN_RATIO:
        return False, "过于竖长（%dx%d，宽高比 %.2f）" % (w, h, ratio)
    if ratio > MAX_RATIO:
        return False, "过于扁长（%dx%d，宽高比 %.2f）" % (w, h, ratio)
    return True, ""


def scan_dir(directory) -> dict:
    """Count usable and rejected pictures in one directory (not recursive)."""
    d = Path(directory)
    result = {"dir": str(d), "total": 0, "usable": 0, "reasons": {},
              "samples": []}
    if not d.is_dir():
        result["reasons"]["目录不存在"] = 1
        return result
    try:
        entries = sorted(d.iterdir())
    except OSError:
        result["reasons"]["无权读取"] = 1
        return result
    blocked = load_blocklist(Path(d).parent)
    for entry in entries:
        if not entry.is_file():
            continue
        if entry.suffix.lower() not in _SUFFIXES:
            continue
        if is_blocked(entry, blocked):
            result["blocked"] = result.get("blocked", 0) + 1
            continue
        result["total"] += 1
        ok, why = usable(entry)
        if ok:
            result["usable"] += 1
            if len(result["samples"]) < 3:
                result["samples"].append(entry.name)
        else:
            key = why.split("（")[0]
            result["reasons"][key] = result["reasons"].get(key, 0) + 1
    return result


#: Filename stem used as the blocking key: `wallhaven-abc123.jpg` -> the
#: upload's own id where there is one, otherwise the whole stem. Stable across
#: re-downloads, which is the point -- re-fetching must not resurrect a
#: picture the operator already rejected.
def picture_key(path) -> str:
    stem = Path(path).stem
    if "-" in stem:
        head, _, tail = stem.partition("-")
        if head in ("wallhaven", "konachan", "openverse") and tail:
            return tail
    return stem


def blocklist_path(state_dir) -> Path:
    return Path(state_dir) / "image_blocklist.json"


def load_blocklist(state_dir) -> dict:
    """Read the operator's reject list: ``{key: reason}``."""
    path = blocklist_path(state_dir)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    entries = data.get("blocked", data) if isinstance(data, dict) else {}
    if not isinstance(entries, dict):
        return {}
    return {str(k): str(v) for k, v in entries.items()}


def save_blocklist(state_dir, entries: dict, share_with=()) -> str:
    """Write the reject list, and mirror it into any shared library.

    Several gates can point at one picture directory. A rejection is a fact
    about the picture, so it is written beside the pictures as well as in
    the gate's own state directory -- otherwise the second gate would happily
    serve the thing the first one rejected.
    """
    payload = json.dumps(
        {"note": "Rejected pictures. Re-fetching will not bring these back.",
         "blocked": dict(sorted(entries.items()))},
        ensure_ascii=False, indent=2)
    path = blocklist_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    for directory in share_with or ():
        d = Path(directory)
        if d.is_dir():
            try:
                (d / ".blocklist.json").write_text(payload, encoding="utf-8")
            except OSError:
                pass
    return str(path)


def is_blocked(path, entries: dict) -> bool:
    if not entries:
        return False
    key = picture_key(path)
    return key in entries or Path(path).name in entries


def is_transient(directory) -> bool:
    """Does this path look like scratch space rather than a collection?"""
    low = str(directory).lower().rstrip("/") + "/"
    return any(hint in low for hint in TRANSIENT_HINTS)


def discover(extra=()) -> list:
    """Probe the host for directories that could serve as a picture pool.

    Returns a list of :func:`scan_dir` results that contain at least one
    usable picture, best first, plus any explicitly supplied directories.
    """
    import glob as _glob

    seen = set()
    found = []
    candidates = []
    for pattern in DISCOVERY_GLOBS:
        candidates.extend(sorted(_glob.glob(pattern)))
    candidates.extend(str(d) for d in extra)
    for cand in candidates:
        real = str(Path(cand))
        if real in seen:
            continue
        seen.add(real)
        if not Path(real).is_dir():
            continue
        info = scan_dir(real)
        if info["usable"] > 0:
            info["transient"] = is_transient(real)
            found.append(info)
    found.sort(key=lambda r: (r["transient"], -r["usable"], r["dir"]))
    return found
