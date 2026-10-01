"""Lure surfaces: make the decoys findable, and measure whether they are found.

Why this exists
---------------
A decoy nobody requests catches nobody. The curated paths in `decoy` are
*potential* tripwires -- they only fire if something thinks to ask for them.
That is fine against a scanner walking a dictionary, and useless against
everything else.

The published guidance on web decoys is consistent about what actually raises
the hit rate, and it is not more paths:

* place lures where **crawlers look**, not where visitors look -- `robots.txt`
  and sitemaps are read by exactly the automated traffic worth catching, and
  a `Disallow:` line is widely treated as a signpost rather than a fence;
* keep the naming **realistic** -- `/honeypot.html` and `/fake-admin` are
  recognised instantly, while `/backup.zip` and `/.env.production` are the
  files attackers actually spend requests on;
* **layer** the surfaces (crawler-visible, comment-visible, API-visible)
  instead of relying on one.

The empirical work on honeypot effectiveness points the same way from the
other side: telemetry-driven studies find that *realism* drives dwell time,
interaction depth and behavioural diversity, and they are blunt that raw
connection counts are a poor effectiveness metric. So this module does two
things, and the second matters as much as the first:

1. publishes a small, realistic set of the strongest decoys where automated
   traffic will find them; and
2. plants a **canary** -- a path that appears in no other place on this host.
   A request for it can only come from something that read one of these
   surfaces, which turns "how many hits did we get" into "did the lure work",
   a question answerable without guessing.

The canary is what makes the effect measurable, and measurement is what keeps
this honest: a lure that is never requested is a decoration, and the report
should say so rather than counting installed paths and calling it coverage.

Safety
------
Everything here is reversible and additive:

* the `robots.txt` block is appended between explicit markers and removed
  verbatim on uninstall; the site's own lines are never touched;
* the sitemap is served by nginx from a generated snippet, so no file appears
  in the site's webroot;
* the block is stripped from the site corpus before decoy screening, so
  advertising a path cannot make that path look "referenced by the site" and
  quietly disqualify itself on the next run.
"""
from __future__ import annotations

import json
import os
import secrets
import time
from pathlib import Path

from ..core import paths
from . import decoy

#: Where the per-host canary is remembered. It must be stable: a canary that
#: changes on every run cannot be recognised in a log, and one that is
#: regenerated would let an old hit be explained away as a different path.
CANARY_FILE = paths.STATE_STATE / "lure-canary.json"

#: Written into each site's include directory, so nginx serves the sitemap
#: without any file landing in the webroot.
CONF_NAME = "vigil-lure.conf"

#: How many decoys to advertise. Advertising everything would be noise and
#: would make the sitemap implausible; a handful of the most tempting paths
#: is both more realistic and easier to reason about.
ADVERTISE = 6

#: Paths worth advertising, most tempting first. Chosen for the categories
#: that dictionaries and crawlers actually reach for. Deliberately a subset
#: of `decoy.DECOYS`, so every advertised path is also enforced.
PREFERRED = (
    "/backup.zip",
    "/.env.production",
    "/.git/config",
    "/database.sql",
    "/admin/",
    "/.aws/credentials",
    "/.kube/config",
    "/api/admin/users",
    "/phpinfo.php",
    "/.htpasswd",
)


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return {}


def canary() -> str:
    """This host's canary path, created once and then stable.

    Named to look like the thing attackers want, and placed under a directory
    that does not exist, so the only way to learn it is to read the lure.
    """
    data = _read_json(CANARY_FILE)
    path = str(data.get("path", "") or "")
    if path.startswith("/") and len(path) > 8:
        return path
    path = "/backup/%s.sql" % secrets.token_hex(6)
    try:
        paths.STATE_STATE.mkdir(parents=True, exist_ok=True)
        CANARY_FILE.write_text(json.dumps(
            {"path": path, "created": time.time()}, ensure_ascii=False),
            encoding="utf-8")
        os.chmod(CANARY_FILE, 0o600)
    except OSError:
        pass
    return path


def canary_entry() -> tuple:
    """The canary as a decoy entry, so it is enforced like any other."""
    path = canary()
    return (path, path.lstrip("/"),
            "诱导面金丝雀：只出现在 robots.txt / sitemap 中，命中即证明对方读过它")


def advertised(cfg=None) -> list:
    """Paths to publish: the strongest decoys, plus the canary.

    Filtered against what actually got installed, so the lure never
    advertises a path this host does not enforce -- which would tell an
    attacker the sitemap is fiction.
    """
    installed = set()
    try:
        st = decoy.status(cfg) if cfg is not None else decoy.status()
        installed = set(st.get("paths") or [])
    except Exception:                                       # noqa: BLE001
        installed = set()
    out = [p for p in PREFERRED if not installed or p in installed]
    out = out[:ADVERTISE]
    c = canary()
    if not installed or c in installed:
        out.append(c)
    return out


def robots_block(cfg=None) -> str:
    """The marked block appended to the site's robots.txt.

    `Disallow` is used as a signpost, not a fence: the traffic worth catching
    reads this file precisely to find what it is told to stay away from, and
    the well-behaved crawlers that honour it lose nothing, because none of
    these paths exists.
    """
    lines = [decoy.LURE_BEGIN,
             "# 以下路径由 vigil 生成：本站不存在这些文件。",
             "# 正常访客与正常爬虫不会请求它们。",
             "User-agent: *"]
    for p in advertised(cfg):
        lines.append("Disallow: %s" % p)
    lines.append("Sitemap: /sitemap.xml")
    lines.append(decoy.LURE_END)
    return "\n".join(lines) + "\n"


def sitemap_xml(cfg=None) -> str:
    """A sitemap listing the lure paths.

    Served by nginx rather than written to the webroot: a file in the webroot
    would be part of the site's own content and would have to be excluded
    from screening, and it would be one more thing to clean up on uninstall.
    """
    base = ""
    try:
        domain, _webroot = decoy._site(cfg)
        if domain:
            base = "https://%s" % domain
    except Exception:                                       # noqa: BLE001
        base = ""
    items = []
    for p in advertised(cfg):
        items.append("  <url><loc>%s%s</loc><lastmod>%s</lastmod>"
                     "<priority>0.8</priority></url>"
                     % (base, p, time.strftime("%Y-%m-%d")))
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
            + "\n".join(items) + "\n</urlset>\n")


def render(cfg=None) -> str:
    """The server-scope snippet that serves the sitemap.

    Only the sitemap is served from here. `robots.txt` is *not* overridden:
    this site already has one, and silently replacing an operator's file to
    add a lure would trade their control of their own site for our hit rate.
    """
    xml = sitemap_xml(cfg).replace("\\", "\\\\").replace('"', '\\"')
    xml = xml.replace("\n", "\\n")
    return """# 由 vigil 生成：诱导面（请勿手工编辑）
#
# 只提供 sitemap.xml —— robots.txt 由 vigil 追加带标记的段落，不覆盖站点原文件。
# 这两处是自动化流量真正会读的地方；诱饵路径本身在 vigil-decoy.conf 里执行。

location = /sitemap.xml {
    default_type application/xml;
    add_header Cache-Control "no-store";
    return 200 "%s";
}
""" % xml


def _site_file(cfg, name: str):
    try:
        _domain, webroot = decoy._site(cfg)
    except Exception:                                       # noqa: BLE001
        return None
    if not webroot:
        return None
    return Path(webroot) / name


def install_robots(cfg=None, dry_run: bool = False) -> tuple:
    """Append the marked lure block to the site's robots.txt.

    Idempotent, additive, and reversible. If the block is already present it
    is replaced rather than duplicated, so repeated installs converge instead
    of growing the file.
    """
    target = _site_file(cfg, "robots.txt")
    if target is None:
        return False, "找不到站点根目录，未写入 robots.txt 诱导段"
    try:
        old = target.read_text(encoding="utf-8", errors="replace") \
            if target.exists() else ""
    except OSError as e:
        return False, "读取 robots.txt 失败：%s" % e
    stripped = decoy._strip_lure_block(old)
    if stripped and not stripped.endswith("\n"):
        stripped += "\n"
    new = stripped + ("\n" if stripped else "") + robots_block(cfg)
    if new == old:
        return True, "robots.txt 诱导段已是最新"
    if dry_run:
        return True, "预演：将更新 %s" % target
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(new, encoding="utf-8")
    except OSError as e:
        return False, "写入 robots.txt 失败：%s" % e
    return True, "已写入 robots.txt 诱导段（%d 条 Disallow）" % len(advertised(cfg))


def uninstall_robots(cfg=None) -> tuple:
    target = _site_file(cfg, "robots.txt")
    if target is None or not target.exists():
        return True, "没有需要清理的 robots.txt"
    try:
        old = target.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return False, str(e)
    if decoy.LURE_BEGIN not in old:
        return True, "robots.txt 里没有 vigil 诱导段"
    stripped = decoy._strip_lure_block(old).rstrip("\n")
    try:
        if stripped:
            target.write_text(stripped + "\n", encoding="utf-8")
        else:
            target.unlink()
    except OSError as e:
        return False, str(e)
    return True, "已移除 robots.txt 诱导段"


def conf_path(cfg=None):
    """Where the sitemap snippet goes: the site's include directory."""
    try:
        domain, _webroot = decoy._site(cfg)
    except Exception:                                       # noqa: BLE001
        return None
    if not domain:
        return None
    include_dir = decoy._include_dir(domain)
    if include_dir is None:
        return None
    return Path(include_dir) / CONF_NAME


def install(cfg=None, dry_run: bool = False) -> dict:
    """Publish both surfaces. All-or-nothing, and validated by nginx."""
    out = {"ok": False, "robots": "", "conf": "", "advertised": [],
           "problems": []}
    out["advertised"] = advertised(cfg)
    if not out["advertised"]:
        out["problems"].append("没有已安装的诱饵可供宣传（先运行 vigil decoy install）")
        return out

    target = conf_path(cfg)
    if target is None:
        out["problems"].append("找不到站点 include 目录，无法放置 sitemap 片段")
        return out
    out["conf"] = str(target)

    if dry_run:
        out["ok"] = True
        return out

    # Write the snippet first and validate before reloading: a snippet that
    # breaks the config takes every site on this host down, which is far
    # worse than an unpublished lure.
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(render(cfg), encoding="utf-8")
        os.chmod(target, 0o644)
    except OSError as e:
        out["problems"].append("写入 sitemap 片段失败：%s" % e)
        return out

    ok, msg = decoy._nginx_test()
    if not ok:
        try:
            target.unlink()
        except OSError:
            pass
        out["problems"].append("nginx 拒绝新配置，已撤回诱导片段：%s" % msg)
        return out

    ok, detail = install_robots(cfg)
    out["robots"] = detail
    if not ok:
        out["problems"].append(detail)
        try:
            target.unlink()
        except OSError:
            pass
        return out

    decoy._nginx_reload()
    out["ok"] = True
    return out


def uninstall(cfg=None) -> dict:
    out = {"ok": True, "problems": []}
    target = conf_path(cfg)
    if target is not None and target.exists():
        try:
            target.unlink()
        except OSError as e:
            out["ok"] = False
            out["problems"].append(str(e))
    ok, detail = uninstall_robots(cfg)
    if not ok:
        out["ok"] = False
        out["problems"].append(detail)
    out["robots"] = detail
    if out["ok"]:
        decoy._nginx_reload()
    return out


def status(cfg=None) -> dict:
    """What is published, and whether it has ever worked."""
    target = conf_path(cfg)
    adv = advertised(cfg)
    c = canary()
    hits = []
    try:
        hits = decoy.read_hits()
    except Exception:                                       # noqa: BLE001
        hits = []
    adv_set = set(adv)
    lure_hits = [h for h in hits if str(h.get("uri", "")) in adv_set]
    canary_hits = [h for h in hits if str(h.get("uri", "")) == c]
    return {
        "advertised": adv,
        "canary": c,
        "sitemap_installed": bool(target and target.exists()),
        "sitemap_conf": str(target) if target else "",
        "robots_installed": _robots_has_block(cfg),
        "lure_hits": len(lure_hits),
        "canary_hits": len(canary_hits),
        "distinct_sources": len({str(h.get("ip", "")) for h in lure_hits}),
    }


def _robots_has_block(cfg=None) -> bool:
    target = _site_file(cfg, "robots.txt")
    if target is None or not target.exists():
        return False
    try:
        return decoy.LURE_BEGIN in target.read_text(encoding="utf-8",
                                                    errors="replace")
    except OSError:
        return False


def format_status(st: dict) -> str:
    """Report the lure the way it should be judged: did it work?"""
    lines = ["宣传的诱饵路径  %d 条" % len(st["advertised"]),
             "sitemap.xml     %s" % ("已发布" if st["sitemap_installed"]
                                     else "未发布"),
             "robots.txt      %s" % ("已写入诱导段" if st["robots_installed"]
                                     else "未写入"),
             "金丝雀          %s" % st["canary"],
             "诱导面命中      %d 次（%d 个独立来源）"
             % (st["lure_hits"], st["distinct_sources"]),
             "金丝雀命中      %d 次" % st["canary_hits"]]
    if st["canary_hits"]:
        lines.append("→ 金丝雀被请求过：确认有自动化流量读取了本机的诱导面。")
    elif st["lure_hits"]:
        lines.append("→ 有诱饵被命中，但金丝雀还没有 —— 命中的可能是字典扫描，"
                     "而不是读了诱导面的爬虫。")
    else:
        lines.append("→ 诱导面尚无命中。它是装饰还是有效，要由这个数字回答，"
                     "不能靠「已安装多少条」来判断。")
    return "\n".join(lines)


def main(argv=None) -> int:  # pragma: no cover
    import argparse
    ap = argparse.ArgumentParser(description="诱导面：让诱饵被找到，并衡量是否有效")
    ap.add_argument("action", nargs="?", default="status",
                    choices=["status", "install", "uninstall", "robots",
                             "sitemap"])
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    if a.action == "robots":
        print(robots_block())
        return 0
    if a.action == "sitemap":
        print(sitemap_xml())
        return 0
    if a.action == "install":
        r = install(dry_run=a.dry_run)
        print(r)
        return 0 if r.get("ok") else 1
    if a.action == "uninstall":
        print(uninstall())
        return 0
    print(format_status(status()))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
