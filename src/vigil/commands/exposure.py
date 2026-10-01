"""`vigil exposure` -- what is this webroot handing out, and is it stopped?

The scan half exists because a hand-written nginx blocklist was already in
place on this host and three files were still downloadable from the public
internet -- including a `.bak-<timestamp>` copy of the account captcha's PHP
source. A blocklist cannot be reviewed by reading it, because the question
"which of my files match this?" has to be answered against the filesystem.

So: enumerate the webroot, run the *same* patterns nginx is configured with
(:mod:`vigil.guards.exposure` defines them once), and where a URL is
available, fetch it and see what actually comes back. A finding is a 200 with
the file's own bytes, not a guess.

Nothing here changes the filesystem. ``install`` writes nginx snippet files
and reloads, with `nginx -t` and a verified reload, rolling back on failure --
the same discipline as ``vigil shield``.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from .. import ui
from ..guards import exposure

#: Where BT/aaPanel and plain nginx keep per-site configuration. Probed in
#: order; the first that exists wins for discovery, but all are scanned.
CONF_GLOBS = (
    "/www/server/panel/vhost/nginx/*.conf",
    "/etc/nginx/conf.d/*.conf",
    "/etc/nginx/sites-enabled/*",
    "/usr/local/nginx/conf/vhost/*.conf",
)
_SERVER_NAME = re.compile(r"^\s*server_name\s+([^;]+);", re.M)
_ROOT = re.compile(r"^\s*root\s+([^;]+);", re.M)


def _sites() -> list:
    """Every (server_name, root) pair we can find, de-duplicated by root."""
    seen, out = set(), []
    for pattern in CONF_GLOBS:
        for conf in sorted(Path("/").glob(pattern.lstrip("/"))):
            try:
                text = conf.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            names = [n for m in _SERVER_NAME.finditer(text)
                     for n in m.group(1).split()]
            for m in _ROOT.finditer(text):
                root = m.group(1).strip().strip('"').strip("'")
                if not root.startswith("/") or root in seen:
                    continue
                seen.add(root)
                out.append({"conf": str(conf), "root": root,
                            "server_name": names[0] if names else "-"})
    return out


def _conf_texts(site) -> list:
    """The site's own conf plus every include inside its extension dir."""
    texts = []
    conf = Path(site["conf"])
    try:
        texts.append((str(conf), conf.read_text(encoding="utf-8",
                                                errors="replace")))
    except OSError:
        pass
    ext = conf.parent / "extension" / conf.stem
    if ext.is_dir():
        for f in sorted(ext.glob("*.conf")):
            try:
                texts.append((str(f), f.read_text(encoding="utf-8",
                                                 errors="replace")))
            except OSError:
                pass
    return texts


def _probe(url: str, timeout: int = 8) -> dict:
    """Fetch one URL and report what came back, without following redirects."""
    cmd = ["curl", "-sk", "-o", "/dev/null", "-w",
           "%{http_code} %{size_download} %{content_type}",
           "--max-time", str(timeout), url]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        parts = (p.stdout or "").strip().split(None, 2)
        code = parts[0] if parts else "000"
        size = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        ctype = parts[2] if len(parts) > 2 else ""
    except (subprocess.SubprocessError, OSError):
        return {"code": "000", "size": 0, "ctype": "", "reachable": False}
    return {"code": code, "size": size, "ctype": ctype, "reachable": True}


def cmd_exposure(args) -> int:
    action = getattr(args, "exposure_action", "") or "status"

    if action == "status":
        sites = _sites()
        ui.header("敏感文件暴露面", "nginx 站点 · 规则是否到位")
        if not sites:
            ui.warning("没有发现任何站点配置")
            return 0
        problems = 0
        for site in sites:
            texts = _conf_texts(site)
            blob = "\n".join(t for _p, t in texts)
            has_shape = bool(re.search(r'location\s+~\*?\s*["\'].*bak', blob))
            has_dir = bool(re.search(r'location\s+~\*?\s*["\'].*node_modules',
                                     blob))
            audit = exposure.audit_conf(blob)
            ui.out()
            ui.kv("站点", site["server_name"])
            ui.kv("根目录", site["root"])
            ui.kv("文件/目录规则",
                  ("文件✓ 目录✓" if has_shape and has_dir
                   else "文件✓ 目录✗" if has_shape
                   else "文件✗ 目录✗"),
                  "green" if has_shape and has_dir else "yellow")
            serving = [b for b in audit["prefixes"] if b["serves"]]
            ui.kv("会读磁盘的前缀（^~）",
                  "%d 个" % len(serving) if serving else "无")
            for b in serving:
                ui.bullet("%s  %s" % (b["prefix"],
                                      "已挂拒绝规则" if b["covered"]
                                      else "**未覆盖：该子树跳过全部正则规则**"),
                          mark=" " if b["covered"] else "!")
            if not serving:
                ui.bullet("无（`location =` 是精确匹配，覆盖不到子树，不算旁路）")
            if audit["uncovered"]:
                problems += 1
                ui.note("^~ 会让 nginx 跳过同级正则 location，"
                        "所以这些前缀里的敏感文件不会被上面的规则挡住。")
        ui.out()
        if problems:
            ui.failure("%d 个站点存在 ^~ 前缀旁路" % problems)
            ui.hint("vigil exposure install   # 生成规则并挂进每个 ^~ 前缀")
            return 1
        ui.success("没有发现 ^~ 前缀旁路")
        ui.hint("vigil exposure scan --site <根目录>   # 看实际有哪些文件能被下载")
        return 0

    if action == "scan":
        roots = ([getattr(args, "root", "") or getattr(args, "site", "")]
                 or [s["root"] for s in _sites()])
        roots = [r for r in roots if r]
        if not roots:
            ui.failure("没有可扫描的站点根目录（用 --site 指定）")
            return 1

        base_url = (getattr(args, "url", "") or "").rstrip("/")
        as_json = bool(getattr(args, "json", False))
        limit = getattr(args, "limit", 40)
        report = {"roots": [], "findings": []}
        hits = 0

        for root in roots:
            shape = [i for i in exposure.exposed_paths(root)
                     if not (i.get("dir_only") and i.get("asset"))]
            unusual = exposure.unusual_suffixes(root)
            report["roots"].append({"root": root, "shape_hits": len(shape),
                                    "unusual": len(unusual)})
            if not as_json:
                ui.header("扫描 %s" % root, "用 nginx 会用的同一套规则")
                ui.kv("命中「形状」规则的文件", "%d 个" % len(shape),
                      "red" if shape else "green")
                ui.kv("后缀不在白名单的文件", "%d 个（未知，不等于有问题）"
                      % len(unusual))

            # Two candidate pools, one verdict rule. A file counts as exposed
            # only when a request for it comes back 200 with *its own bytes*:
            # a SPA fallback and a decoy page both answer 200 for paths that
            # do not exist, and reporting those as leaks is how a report stops
            # being read.
            candidates = [dict(i, why="shape") for i in shape]
            candidates += [dict(i, why="unknown-suffix", rule="(不匹配任何规则)")
                           for i in unusual]
            for item in candidates:
                rec = dict(item, http="-")
                if base_url:
                    res = _probe(base_url + item["uri"])
                    rec["http"] = "%s %dB" % (res["code"], res["size"])
                    served = (res["code"] == "200" and item["bytes"] > 0
                              and res["size"] == item["bytes"])
                    if served:
                        rec["verdict"] = "**正在被公网下载**"
                        hits += 1
                    elif res["code"] == "200":
                        rec["verdict"] = "200 但不是这个文件（兜底页/诱饵）"
                    else:
                        rec["verdict"] = "已拒绝（%s）" % res["code"]
                else:
                    rec["verdict"] = ("规则会拒绝（但仍应从 webroot 移走）"
                                      if item["why"] == "shape"
                                      else "后缀不认识，未探测（加 --url 实测）")
                if rec["verdict"].startswith("已拒绝") and item["why"] == "shape":
                    continue          # already blocked: not worth listing
                report["findings"].append(rec)

            if not as_json:
                shown = [f for f in report["findings"]
                         if f["uri"].startswith("/")
                         and f.get("http", "-") != "-"]
                for f in shown[:limit]:
                    mark = "!" if "公网" in f["verdict"] else "·"
                    ui.bullet("%-12s %-46s %s"
                              % (f.get("http", "-"), f["uri"], f["verdict"]),
                              mark=mark)
                rest = len(shown) - len(shown[:limit])
                if rest > 0:
                    ui.note("（还有 %d 项，用 --json 看全量）" % rest)
                if not shown:
                    ui.success("规则内没有命中，未知后缀也没有一个能被下载")
                if not shape:
                    ui.success("没有备份/轮转/凭据形状的文件")

        if as_json:
            ui.out(json.dumps(report, ensure_ascii=False, indent=2))
            return 1 if hits else 0
        ui.out()
        if hits:
            ui.failure("%d 个文件正在被公网直接下载" % hits)
            ui.hint("把命中文件移出 webroot（不是删掉），再确认规则已挂进每个 ^~ 前缀")
            return 1
        ui.success("没有发现可被直接下载的敏感文件")
        return 0

    if action == "install":
        from ..gates import shield as gateshield

        sites = _sites()
        if not sites:
            ui.failure("没有发现站点配置")
            return 1
        ui.header("安装敏感文件拒绝规则", "按形状匹配，写进每个站点的 extension 目录")
        written, problems = [], []
        backups = []
        for site in sites:
            conf = Path(site["conf"])
            ext = conf.parent / "extension" / conf.stem
            text = ""
            try:
                text = conf.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "extension/%s" % conf.stem not in text and \
                    "extension/%s/" % conf.stem not in text:
                # No extension include in this vhost: appending one would be a
                # change to the panel's file, which the panel may rewrite.
                problems.append("%s 没有 extension 目录的 include，跳过"
                                % conf.name)
                continue
            ext.mkdir(parents=True, exist_ok=True)
            shape = ext / "zz-exposure-deny.conf"
            dirs = ext / "zz-exposure-deny-dirs.conf"
            for target, content in ((shape, exposure.render_deny_snippet()),
                                    (dirs, exposure.render_directory_snippet())):
                if target.is_file():
                    keep = target.with_suffix(".conf.vigil-prev")
                    keep.write_text(target.read_text(encoding="utf-8"),
                                    encoding="utf-8")
                    backups.append(str(keep))
                target.write_text(content, encoding="utf-8")
                target.chmod(0o644)
                written.append(str(target))
            for _p, t in _conf_texts(site):
                for b in exposure.audit_conf(t)["uncovered"]:
                    problems.append("%s 的 %s 前缀仍未覆盖（需要在其中 include "
                                    "zz-exposure-deny.conf）"
                                    % (conf.name, b["prefix"]))
        ok, msg = gateshield._reload_verified()
        if not ok:
            for path in backups:
                src = Path(path)
                dst = Path(str(src).replace(".conf.vigil-prev", ".conf"))
                try:
                    dst.write_text(src.read_text(encoding="utf-8"),
                                   encoding="utf-8")
                except OSError:
                    pass
            ui.failure("nginx 拒绝新配置，已回滚：%s" % msg)
            return 1
        for path in written:
            ui.bullet("已写入 %s" % path)
        ui.kv("nginx", msg)
        for p in problems:
            ui.warning(p)
        ui.success("规则已生效")
        ui.hint("vigil exposure scan --url https://<域名>   # 实际探一遍")
        return 0

    ui.failure("未知操作：%s" % action)
    return 1


def register(sub) -> None:
    p = sub.add_parser(
        "exposure", help="敏感文件暴露：扫描 webroot 里能被下载的备份/凭据/源码",
        description="把手写的后缀黑名单换成按「形状」匹配的规则，并且用同一套规则"
                    "反过来扫自己的 webroot —— 因为黑名单无法靠阅读来审查，"
                    "「我的哪些文件匹配它」只能对着文件系统回答。")
    ps = p.add_subparsers(dest="exposure_action", metavar="<操作>")
    p.set_defaults(func=cmd_exposure, exposure_action="status")

    sp = ps.add_parser("status", help="看每个站点的规则与 ^~ 前缀旁路")
    sp.set_defaults(func=cmd_exposure, exposure_action="status")

    sp = ps.add_parser("scan", help="扫描 webroot，找出能被直接下载的文件")
    sp.add_argument("--site", default="", help="站点根目录（默认：自动发现）")
    sp.add_argument("--root", default="", help="同 --site")
    sp.add_argument("--url", default="",
                    help="站点根 URL，给了就实际发请求验证（如 https://example.com）")
    sp.add_argument("--limit", type=int, default=40, help="未知后缀最多列几个")
    sp.add_argument("--json", action="store_true", help="输出 JSON")
    sp.set_defaults(func=cmd_exposure, exposure_action="scan")

    sp = ps.add_parser("install", help="生成规则文件并挂到每个站点")
    sp.add_argument("--yes", "-y", action="store_true")
    sp.set_defaults(func=cmd_exposure, exposure_action="install")
