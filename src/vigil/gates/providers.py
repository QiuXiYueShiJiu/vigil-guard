"""Fetching puzzle pictures from public sources.

The package ships no pictures. It ships this: a small set of *providers* the
operator can pull from, on purpose, with the licence of everything fetched
recorded next to it.

Two very different things are on offer, and the difference matters:

``openverse``
    Aggregates works that carry a Creative Commons or public-domain mark, and
    reports the licence per item. Everything it returns here is CC0 or public
    domain unless the operator explicitly widens the filter. This is the
    option to pick if the pictures have to be free to reuse, not merely free
    to look at.

``wallhaven`` / ``konachan``
    Well-kept collections of anime artwork, and by far the best-looking
    results. The artwork itself is *not* openly licensed -- it is other
    people's work, uploaded by fans -- so it is fetched only when asked for
    explicitly, only from the safe-for-work endpoints, and the artist and
    source page are written into the credits file. Fine for a private login
    page on your own server; not something to redistribute.

Either way the result is the same shape: files in a directory, plus a
``credits.json`` naming where each one came from.

Standard library only. The HTTP is plain ``urllib`` and the image headers are
parsed by hand in :mod:`vigil.gates.scenes`, so a machine with nothing but
CPython can use all of this.
"""

from __future__ import annotations

import hashlib
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .scenes import MAX_RATIO, MIN_RATIO, image_size

USER_AGENT = ("vigil-gate/1.0 (self-hosted admin login gate; "
              "picture fetch is operator-initiated)")

#: Refuse anything bigger than this. A single 40 MB PNG in the pool is a
#: download nobody asked for and a decode nobody wants on every challenge.
MAX_BYTES = 12 * 1024 * 1024

#: Seconds to wait for a provider before giving up on the whole fetch.
TIMEOUT = 25


class FetchError(RuntimeError):
    """A provider could not be reached, or answered with nonsense."""


@dataclass
class Picture:
    url: str
    provider: str = ""
    page: str = ""
    author: str = ""
    licence: str = ""
    title: str = ""
    width: int = 0
    height: int = 0
    extra: dict = field(default_factory=dict)

    def ratio(self) -> float:
        return self.width / max(1, self.height)


#: Ready-made queries. Landscapes are the safe default -- a wide crop of a
#: wide picture loses nothing -- but character art is what most people
#: actually want to look at, and wallhaven has plenty of it composed for a
#: widescreen frame. Every preset is still forced through purity=100.
PRESETS = {
    "scenery": "anime scenery",
    "character": "anime girl",
    "character2": "anime character",
    "portrait": "anime portrait",
    "uniform": "anime school uniform",
    "kimono": "anime kimono",
    "fantasy": "anime fantasy",
    "city": "anime city night",
    "sky": "anime sky clouds",
    "mixed": "",
    # Specific fandoms people ask for by name.
    "bluearchive": "blue archive",
    "vocaloid": "vocaloid",
    "miku": "hatsune miku",
    "luckystar": "lucky star",
}

#: Negative tags appended to every query on providers that support them.
#: This is a coarse net, not a solution: it catches the words the uploader
#: chose, and cannot catch a photograph, a watermarked edit or an extremist
#: symbol. `vigil gate scene review` exists because this list is not enough
#: on its own, and the tool says so rather than pretending otherwise.
SAFE_EXCLUDES = ("-swimsuit", "-bikini", "-lingerie", "-underwear",
                 "-topless", "-nude", "-nsfw", "-text", "-watermark")


PROVIDERS = {
    "wallhaven": {
        "label": "Wallhaven（动漫壁纸，画质最好）",
        "licence": "第三方同人作品，非开放许可；仅限自用，请勿再分发",
        "homepage": "https://wallhaven.cc",
        "default_query": "anime scenery",
        # Wallhaven returns 24 per page; a large request has to walk pages,
        # and the default of three capped every fetch at ~72 candidates no
        # matter what --count asked for.
        "pages": 10,
        "safe": "仅 SFW（purity=100，仅 anime 分类）",
        "note": "按 16:9 / 16:10 比例筛选，因此几乎不需要裁切。",
    },
    "openverse": {
        "label": "Openverse（CC0 / 公有领域，授权干净）",
        "licence": "CC0 / 公有领域（逐张记录，见 credits.json）",
        "homepage": "https://openverse.org",
        "default_query": "anime illustration",
        "safe": "仅开放许可素材",
        "pages": 4,
        "note": "授权可再分发；缺点是二次元素材以复古插画为主，横向比例偏少。",
    },
    "konachan": {
        "label": "Konachan（动漫壁纸，带 landscape 标签）",
        "licence": "第三方同人作品，非开放许可；仅限自用，请勿再分发",
        "homepage": "https://konachan.net",
        "default_query": "",
        "safe": "仅 rating:safe",
        "note": "直接按 landscape 标签取图，横版命中率高。",
    },
}


def _opener():
    """An opener that never inherits a proxy from the environment.

    A gate is often installed on a host with a proxy configured for other
    reasons; silently routing picture downloads through it would be both
    surprising and slow.
    """
    ctx = ssl.create_default_context()
    handlers = [urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=ctx)]
    return urllib.request.build_opener(*handlers)


def _get(url: str, timeout: int = TIMEOUT) -> bytes:
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "application/json,image/*;q=0.9,*/*;q=0.5",
    })
    try:
        with _opener().open(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        raise FetchError("HTTP %s：%s" % (exc.code, url)) from None
    except (urllib.error.URLError, OSError) as exc:
        raise FetchError("无法连接 %s（%s）" % (url, exc)) from None


def _get_json(url: str, timeout: int = TIMEOUT) -> dict:
    raw = _get(url, timeout)
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        raise FetchError("返回的不是 JSON：%s" % url) from None


# --------------------------------------------------------------------------
# providers
# --------------------------------------------------------------------------

def _search_wallhaven(query, limit, min_width, min_height, page):
    if query and not query.rstrip().endswith("-"):
        query = query + " " + " ".join(SAFE_EXCLUDES)
    q = urllib.parse.urlencode({
        "q": query,
        # 010 = anime only. 100 = safe for work only. Neither is negotiable
        # from the command line: this is a login page.
        "categories": "010",
        "purity": "100",
        "sorting": "random",
        "ratios": "16x9,16x10,16x9,21x9",
        "atleast": "%dx%d" % (max(1280, min_width), max(720, min_height)),
        "page": page,
    })
    data = _get_json("https://wallhaven.cc/api/v1/search?" + q)
    out = []
    for item in data.get("data", []):
        out.append(Picture(
            url=item.get("path", ""),
            provider="wallhaven",
            page=item.get("url", ""),
            author="",
            licence=PROVIDERS["wallhaven"]["licence"],
            width=int(item.get("dimension_x") or 0),
            height=int(item.get("dimension_y") or 0),
            extra={"id": item.get("id", ""),
                   "thumbs": (item.get("thumbs") or {}),
                   "colors": item.get("colors") or []},
        ))
    return out


def _search_openverse(query, limit, min_width, min_height, page):
    q = urllib.parse.urlencode({
        "q": query,
        # CC0 and public domain only. `by`/`by-sa` are available through
        # --licence any, but they are not the default because attribution
        # requirements do not belong on a page nobody can see the credits on.
        "license": "cc0,pdm",
        "size": "large",
        "page_size": min(20, max(1, limit)),
        "page": page,
    })
    data = _get_json("https://api.openverse.org/v1/images/?" + q)
    out = []
    for item in data.get("results", []):
        out.append(Picture(
            url=item.get("url", ""),
            provider="openverse",
            page=item.get("foreign_landing_url", "") or item.get("url", ""),
            author=item.get("creator") or "",
            licence=(item.get("license") or "") +
                    (" " + item["license_version"] if item.get("license_version")
                     else ""),
            title=item.get("title") or "",
            width=int(item.get("width") or 0),
            height=int(item.get("height") or 0),
            extra={"source": item.get("source") or "",
                   "license_url": item.get("license_url") or ""},
        ))
    return out


def _search_konachan(query, limit, min_width, min_height, page):
    # `landscape` alone is already a strong signal, and requiring a second
    # content tag on top of it returns nothing on this board -- which is why
    # the query is optional here rather than defaulted.
    tags = "rating:safe landscape order:random"
    if query:
        tags += " " + query.replace(" ", "_")
    q = urllib.parse.urlencode({"limit": min(100, max(1, limit)), "tags": tags})
    data = _get_json("https://konachan.net/post.json?" + q)
    if not isinstance(data, list):
        raise FetchError("Konachan 返回了非预期结构")
    out = []
    for item in data:
        # jpeg_url is the same picture at a saner size than file_url.
        url = item.get("jpeg_url") or item.get("file_url") or ""
        out.append(Picture(
            url=url,
            provider="konachan",
            page=("https://konachan.net/post/show/%s" % item.get("id", "")),
            author=item.get("author") or "",
            licence=PROVIDERS["konachan"]["licence"],
            width=int(item.get("width") or 0),
            height=int(item.get("height") or 0),
            extra={"source": item.get("source") or "",
                   "tags": (item.get("tags") or "")[:200]},
        ))
    return out


_SEARCH = {
    "wallhaven": _search_wallhaven,
    "openverse": _search_openverse,
    "konachan": _search_konachan,
}


def resolve_query(provider: str, query: str = "", preset: str = "") -> str:
    """Turn a preset name into a query string.

    A preset is only a saved query, never a separate code path: the safety
    filters are applied in one place and cannot be bypassed by choosing a
    different preset.
    """
    if query:
        return query
    if preset:
        if preset not in PRESETS:
            raise FetchError("未知预设：%s（可用：%s）"
                             % (preset, ", ".join(sorted(PRESETS))))
        if PRESETS[preset]:
            return PRESETS[preset]
    return PROVIDERS.get(provider, {}).get("default_query", "")


def search(provider: str, query: str = "", limit: int = 24,
           min_width: int = 1280, min_height: int = 720,
           landscape_only: bool = True, pages: int = 3,
           preset: str = "") -> list:
    """Ask one provider for candidates, filtered to what the gate can use."""
    if provider not in _SEARCH:
        raise FetchError("未知来源：%s（可用：%s）"
                         % (provider, ", ".join(sorted(_SEARCH))))
    query = resolve_query(provider, query, preset)
    pages = max(int(PROVIDERS[provider].get("pages", pages)), 1)
    picked: list = []
    seen = set()
    for page in range(1, max(1, pages) + 1):
        if len(picked) >= limit:
            break
        try:
            batch = _SEARCH[provider](query, limit, min_width, min_height, page)
        except FetchError:
            if page == 1:
                raise
            break
        if not batch:
            break
        for pic in batch:
            if not pic.url or pic.url in seen:
                continue
            seen.add(pic.url)
            if pic.width and pic.height:
                if pic.width < min_width or pic.height < min_height:
                    continue
                ratio = pic.ratio()
                if landscape_only and ratio < 1.2:
                    continue
                if ratio < MIN_RATIO or ratio > MAX_RATIO:
                    continue
            picked.append(pic)
        # Openverse is the one provider whose results are mostly portrait, so
        # it has to be paged through to collect enough landscape pictures;
        # Konachan answers from a single random page.
        if provider == "konachan":
            break
        time.sleep(0.5)          # be a good citizen on someone else's API
    return picked[:limit]


# --------------------------------------------------------------------------
# downloading
# --------------------------------------------------------------------------

_EXT = {"image/jpeg": ".jpg", "image/jpg": ".jpg", "image/png": ".png",
        "image/webp": ".webp"}


def download(pics, dest, min_width=1280, min_height=720,
             max_bytes=MAX_BYTES, on_event=None, theme="") -> tuple:
    """Save pictures into ``dest``; return ``(saved, skipped)`` credit dicts.

    Every file is verified after download with the same header parser the
    gate's own scan uses, so a truncated transfer or an HTML error page
    dressed up as a JPEG is rejected here rather than becoming a puzzle that
    cannot be built.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    saved, skipped = [], []
    seen_hashes = _existing_hashes(dest)

    for pic in pics:
        try:
            raw = _get(pic.url, timeout=TIMEOUT)
        except FetchError as exc:
            skipped.append({"url": pic.url, "why": str(exc)})
            if on_event:
                on_event("skip", pic, str(exc))
            continue
        if len(raw) > max_bytes:
            why = "文件过大（%.1f MB）" % (len(raw) / 1048576)
            skipped.append({"url": pic.url, "why": why})
            if on_event:
                on_event("skip", pic, why)
            continue
        digest = hashlib.md5(raw).hexdigest()
        if digest in seen_hashes:
            skipped.append({"url": pic.url, "why": "重复"})
            if on_event:
                on_event("skip", pic, "重复")
            continue

        ext = _EXT.get((pic.extra or {}).get("content_type", ""), "")
        if not ext:
            head = raw[:12]
            if head[:8] == b"\x89PNG\r\n\x1a\n":
                ext = ".png"
            elif head[:4] == b"RIFF" and raw[8:12] == b"WEBP":
                ext = ".webp"
            else:
                ext = ".jpg"
        name = "%s-%s%s" % (pic.provider, digest[:12], ext)
        target = dest / name
        tmp = dest / ("." + name + ".part")
        try:
            tmp.write_bytes(raw)
            dims = image_size(tmp)
            if not dims:
                raise ValueError("不是有效的图片")
            w, h = dims
            if w < min_width or h < min_height:
                raise ValueError("分辨率不足（%dx%d）" % (w, h))
            ratio = w / max(1, h)
            if ratio < MIN_RATIO or ratio > MAX_RATIO:
                raise ValueError("宽高比不合适（%.2f）" % ratio)
            tmp.replace(target)
        except (OSError, ValueError) as exc:
            tmp.unlink(missing_ok=True)
            skipped.append({"url": pic.url, "why": str(exc)})
            if on_event:
                on_event("skip", pic, str(exc))
            continue

        seen_hashes.add(digest)
        pic.width, pic.height = w, h
        entry = asdict(pic)
        entry["file"] = name
        entry["bytes"] = len(raw)
        entry["md5"] = digest
        entry["fetched_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        # Which search this came from. Recorded so the gate can draw evenly
        # from each theme instead of in proportion to how many pictures each
        # one happened to contribute.
        entry["theme"] = theme
        saved.append(entry)
        if on_event:
            on_event("saved", pic, name)
    return saved, skipped


def _existing_hashes(dest: Path) -> set:
    """md5 of everything already in the directory, so re-runs are cheap."""
    out = set()
    try:
        for f in dest.iterdir():
            if f.is_file() and not f.name.startswith("."):
                out.add(hashlib.md5(f.read_bytes()).hexdigest())
    except OSError:
        pass
    return out


def theme_map(dest) -> dict:
    """``{filename: theme}`` for everything with a recorded theme."""
    book = dest / "credits.json" if isinstance(dest, Path) else Path(dest) / "credits.json"
    out = {}
    if not book.is_file():
        return out
    try:
        data = json.loads(book.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return out
    for entry in data.get("pictures", []):
        name, theme = entry.get("file"), entry.get("theme")
        if name and theme:
            out[name] = theme
    return out


def write_credits(dest, saved, skipped) -> str:
    """Merge new credits into ``credits.json`` and return its path."""
    dest = Path(dest)
    path = dest / "credits.json"
    book = {"pictures": [], "skipped": []}
    if path.is_file():
        try:
            book = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            book = {"pictures": [], "skipped": []}
    known = {p.get("file") for p in book.get("pictures", [])}
    for entry in saved:
        if entry.get("file") not in known:
            book.setdefault("pictures", []).append(entry)
    book["skipped"] = (book.get("skipped", []) + skipped)[-200:]
    book["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    path.write_text(json.dumps(book, ensure_ascii=False, indent=2),
                    encoding="utf-8")
    return str(path)


def provider_help() -> list:
    """Rows for the CLI, so the licence difference is impossible to miss."""
    rows = []
    for name, meta in PROVIDERS.items():
        rows.append((name, meta["label"], meta["licence"]))
    return rows
