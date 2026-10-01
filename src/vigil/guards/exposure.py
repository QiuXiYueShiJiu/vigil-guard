"""Sensitive-file exposure: find what a webroot is handing out, and stop it.

Why this module exists
----------------------

A hand-written nginx blocklist had already been added to this host's main
site: ``bak|bak[0-9]*|backup|old|orig|...``. It looked thorough. It was not,
and three files were downloadable from the public internet anyway:

  · ``account/captcha.php.bak-20260930-215427`` — the blocklist expected a
    digit after ``bak``; the real name had a hyphen. This served the **full
    PHP source of the account captcha** as ``application/octet-stream``.
  · ``index.htmlold`` — the pattern was ``old$``; this file's extension is
    ``htmlold``, which never matches.
  · ``index.html.editor_20260927_220602`` — an editor's timestamped backup.
    No suffix list contains ``editor_20260927_220602``, and none ever will.

The lesson is the same one this codebase keeps relearning: **an enumeration
goes stale**. "Backup" is not a set of extensions, it is a *shape* — a
rotation number, a timestamp tail, an editor's leftovers, a doubled
extension. So this module matches shapes.

The second lesson is that a detector and the rule it feeds must be the same
object. The regexes below are defined **once**, in
:data:`SHAPE_RULES`; :func:`render_deny_snippet` writes them into nginx and
:func:`exposed_paths` runs them over real URIs with Python's ``re``. A test
proves the two agree over a corpus of names, so the scanner cannot report
"clean" while the server hands the file out — and the rule cannot drift away
from the scanner the way the piece-name enumeration drifted from the page.

The third lesson: a prefix location with ``^~`` makes nginx **skip every
regex location at the same level**, so a site's ``location ^~ /app/``
silently disables the whole sensitive-file ruleset for that subtree. That was
true here: ``/function/.gitignore`` (a real 3239-byte file) was served with
HTTP 200 while the blocklist sat right above it in the same server block.
:func:`prefix_bypasses` finds that shape in a vhost config.
"""
from __future__ import annotations

import re
from pathlib import Path

# --------------------------------------------------------------------------
# The one definition. Order matters for nothing but reporting.
# --------------------------------------------------------------------------
# Each entry: (human label, PCRE-compatible pattern). These patterns are used
# verbatim in nginx (`location ~* "<pattern>"`) and compiled here by `re`.
SHAPE_RULES: tuple = (
    ("编辑器/轮转/点文件",
     r"(~$"
     r"|(^|/)[.](?!well-known)"
     r"|[._-](bak|backup|old|orig|save|saved|copy|swp|swo|tmp|temp)[0-9._-]*$"
     r"|[._-][0-9]{8}[._-][0-9]{4,6}$"
     r"|[.][0-9]{1,4}$"
     r"|(^|/)[.](editor|vscode|idea|sublime))"),
    ("源码后粘备份标记",
     r"[.](php[0-9]?|phtml|html?|js|mjs|json|css|txt|md|xml|yml|yaml|conf|ini"
     r"|sql|sh|py|rb|pl|lua|log|db|sqlite3?)"
     r"(old|bak|backup|orig|save|copy|tmp|temp|swp|swo)[0-9._-]*$"),
    ("证书/私钥/压缩包/数据导出",
     r"[.](pem|key|crt|cer|der|p12|pfx|jks|keystore|csr|sql|sqlite|sqlite3|db"
     r"|dump|tar|tgz|tbz2|gz|bz2|xz|zip|rar|7z|war|jar|iso|img)$"),
    ("配置/脚本/环境/依赖清单",
     r"[.](conf|ini|cfg|cnf|yml|yaml|toml|sh|bash|zsh|py|rb|pl|lua|lock|log"
     r"|env|dist|sample|example|map)$"),
    ("凭据/密钥文件名（非点文件也常见）",
     r"/(id_rsa|id_dsa|id_ecdsa|id_ed25519|authorized_keys|known_hosts"
     r"|netrc|git-credentials|my[.]cnf|pgpass|credentials|credentials[.]json"
     r"|secrets?[.]ya?ml|shadow|master[.]passwd|wp-config[.]php"
     r"|configuration[.]php[.]txt|npmrc|htpasswd)$"),
    ("工程元数据",
     r"/(LICENSE|README[.]md|CHANGELOG|composer[.](json|lock)"
     r"|package(-lock)?[.]json|yarn[.]lock|pnpm-lock[.]yaml|Dockerfile"
     r"|docker-compose[.]ya?ml|Makefile|user[.]ini|htaccess|htpasswd"
     r"|gitignore|gitattributes|gitmodules|npmrc|editorconfig)$"),
)

#: Directories that must never be walkable. Kept apart from the file shapes
#: because these names collide with ordinary application layout much more
#: often, so they are the ones worth being able to switch off alone.
DIRECTORY_RULES: tuple = (
    ("版本控制/依赖/备份目录",
     # `vendor` is deliberately NOT here. It is where Composer puts PHP
     # dependencies, but it is also an ordinary name for a directory of public
     # front-end assets -- and on this host `/function/files/vendor/katex/...`
     # is served to browsers on purpose. A host-wide rule that 404s it breaks
     # a working site, and the scan that found this was the point of having a
     # scan at all.
     r"/([.]git|[.]svn|[.]hg|[.]bzr|[.]idea|[.]vscode|node_modules"
     r"|bower_components|backups?|dumps?|[.]Recycle_bin)(/|$)"),
)

#: What a site is allowed to serve. Anything whose final extension is not
#: here is worth probing -- *not* necessarily a finding, because a project may
#: legitimately serve something unusual. Probing turns it into fact.
SAFE_SUFFIXES: frozenset = frozenset("""
html htm xhtml css js mjs cjs json json5 map txt xml svg ico png jpg jpeg gif
webp avif bmp tiff woff woff2 ttf otf eot wasm mp3 ogg oga wav m4a mp4 webm
ogv mov avi pdf csv vtt srt glb gltf obj mtl bin dat pak unityweb asset
resS resource manifest webmanifest appcache php phtml
""".split())

#: Extensions that are a finding on their own, without any probing: no
#: legitimate site serves these, and each one has leaked real secrets
#: somewhere. Used to rank the report, not to decide the verdict.
DANGEROUS_SUFFIXES: frozenset = frozenset("""
sql sqlite sqlite3 db dump bak backup old orig save swp swo tmp temp log
pem key crt cer der p12 pfx jks keystore csr env ini conf cfg cnf yml yaml
toml sh bash zsh py rb pl lua lock dist sample example tar tgz gz bz2 xz
zip rar 7z war jar iso img pem
""".split())

_COMPILED = tuple((label, re.compile(pat)) for label, pat in SHAPE_RULES)


def _uri_path(uri: str) -> str:
    """The path part of a URI, percent-decoded, as nginx matches it.

    nginx normalises the request before matching a location regex: it decodes
    percent-escapes and resolves ``.``/``..`` segments. A scanner that tested
    the raw request string would miss `/x%2ebak`, which nginx happily serves
    as `x.bak` -- so the decode happens here, on the same string nginx will
    use.
    """
    from urllib.parse import unquote

    path = uri.split("?", 1)[0].split("#", 1)[0]
    # Decode twice: some stacks decode once before nginx sees it, and a
    # double-encoded value is the classic way past a single-pass filter.
    once = unquote(path)
    twice = unquote(once)
    return twice if twice != once else once


def match_rules(path: str, rules=None) -> str:
    """Return the label of the first rule matching `path`, else ''."""
    target = _uri_path(path)
    for label, rx in (_COMPILED if rules is None else
                      tuple((l, re.compile(p)) for l, p in rules)):
        if rx.search(target):
            return label
    return ""


def exposed_paths(root, extra_roots=()) -> list:
    """Every file under `root` that our own rules would refuse to serve.

    This is the detector half. It deliberately walks *all* files, not just
    the suspicious-looking ones: a file named `backup.tar.gz` inside a
    directory nobody browses is still one URL away from the internet.
    """
    roots = [Path(root)] + [Path(r) for r in extra_roots]
    found = []
    for base in roots:
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            if not p.is_file() or p.is_symlink():
                continue
            rel = "/" + str(p.relative_to(base))
            shape = match_rules(rel)
            dirs = match_rules(rel, DIRECTORY_RULES)
            if not shape and not dirs:
                continue
            suffix = p.suffix[1:].lower() if p.suffix else ""
            found.append({
                "path": str(p), "uri": rel,
                # Which kind of rule matched decides how much it matters. A
                # *shape* match says "this is a backup or a credential"; a
                # *directory* match only says "this lives in a directory that
                # is usually not public", and a site may legitimately serve
                # from it. Only the shape half is a finding on its own.
                "rule": shape or dirs, "shape": bool(shape),
                "dir_only": bool(dirs) and not shape,
                "bytes": p.stat().st_size,
                "suffix": suffix,
                "asset": suffix in SAFE_SUFFIXES,
                "dangerous": suffix in DANGEROUS_SUFFIXES,
            })
    return found


def unusual_suffixes(root, limit=200) -> list:
    """Files whose final extension is simply not a web asset type.

    Kept separate from :func:`exposed_paths` on purpose. This list is
    "unknown", not "guilty" -- it is what you point a prober at, because the
    shapes above cannot cover an editor nobody has heard of yet. That is how
    `index.html.editor_20260927_220602` was found.
    """
    base = Path(root)
    out = []
    if not base.is_dir():
        return out
    for p in sorted(base.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        suffix = p.suffix[1:].lower() if p.suffix else ""
        if suffix in SAFE_SUFFIXES:
            continue
        # Skip anything already refused by the directory rules. Otherwise a
        # single `node_modules/` buries the interesting files under hundreds
        # of `LICENSE`/`README.md` entries that no rule will ever let through.
        rel = "/" + str(p.relative_to(base))
        if match_rules(rel, DIRECTORY_RULES):
            continue
        out.append({
            "path": str(p),
            "uri": "/" + str(p.relative_to(base)),
            "bytes": p.stat().st_size,
            "suffix": suffix or "(无后缀)",
        })
        if len(out) >= limit:
            break
    return out


def render_deny_snippet(rules=None) -> str:
    """The nginx locations, generated from :data:`SHAPE_RULES`.

    Included verbatim at server scope **and again inside every `^~` prefix**:
    a prefix location makes nginx skip regex locations at the same level, so
    including it only at server scope leaves those subtrees unprotected.
    """
    lines = [
        "    # ============================================================",
        "    # 敏感/备份/源码文件拒绝规则 —— 由 vigil 生成，请勿手改",
        "    #",
        "    # 这些正则同时被 `vigil exposure scan` 用来判断「哪些文件本来就不该",
        "    # 被服务」。定义只有一份（vigil/guards/exposure.py 的 SHAPE_RULES），",
        "    # 因为扫描器和服务器规则一旦各写各的，就会出现「扫描说干净、服务器",
        "    # 却在往外发」这种最糟的情况。",
        "    #",
        "    # 必须在 server{} 作用域，并且要用 include 再挂进每一个 `^~` 前缀里。",
        "    # ============================================================",
    ]
    for label, pattern in (SHAPE_RULES if rules is None else rules):
        lines.append("    # %s" % label)
        lines.append('    location ~* "%s" {' % pattern)
        lines.append("        return 404;")
        lines.append("    }")
    return "\n".join(lines) + "\n"


def render_directory_snippet(rules=None) -> str:
    """The directory-shaped rules, in their own file so they can be dropped."""
    lines = [
        "    # ============================================================",
        "    # 敏感**目录**拒绝规则 —— 由 vigil 生成，请勿手改",
        "    #",
        "    # 与文件形状规则分开：`data/`、`private/`、`vendor/` 这些名字在正常",
        "    # 项目里也可能出现，误判就等于一个功能直接 404。所以它们单独一份，",
        "    # 需要时整份摘掉即可，不必动文件规则。",
        "    # ============================================================",
    ]
    for label, pattern in (DIRECTORY_RULES if rules is None else rules):
        lines.append("    # %s" % label)
        lines.append('    location ~* "%s" {' % pattern)
        lines.append("        return 404;")
        lines.append("    }")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# The `^~` hole
# --------------------------------------------------------------------------
_LOCATION_PREFIX = re.compile(
    r"^\s*location\s+(\^~|=)\s*(\S+?)\s*\{", re.M)
_INCLUDE = re.compile(r"^\s*include\s+(\S+?)\s*;", re.M)


def prefix_bypasses(conf_text: str, include_marks=("zz-exposure-deny",)) -> list:
    """`^~`/`=` prefixes that switch off the server-level regex denies.

    Returns one dict per prefix location, saying whether the sensitive-file
    ruleset is re-applied inside it. ``=` (exact match) is included because it
    skips regex locations for the same reason, though it can only ever match
    one exact URI, so it is reported with a lower weight.
    """
    out = []
    for m in _LOCATION_PREFIX.finditer(conf_text):
        kind, prefix = m.group(1), m.group(2)
        # Find the body of this location by brace counting from the opening
        # brace. Regex on nested braces would be wrong here, and this text is
        # generated by humans and panels, not by us.
        i = conf_text.index("{", m.end() - 1)
        depth, j = 1, i + 1
        while j < len(conf_text) and depth:
            if conf_text[j] == "{":
                depth += 1
            elif conf_text[j] == "}":
                depth -= 1
            j += 1
        body = conf_text[i + 1:j - 1]
        includes = _INCLUDE.findall(body)
        covered = any(any(mark in inc for mark in include_marks)
                      for inc in includes)
        # Three kinds of prefix, and only the first can hand out a file:
        #   · serves  -- try_files/root/alias: nginx reads the disk
        #   · proxies -- proxy_pass: nginx never touches the filesystem, so a
        #                sensitive file under this path is the backend's
        #                problem, not a hole in this ruleset. Reporting it
        #                would be noise, and noise is how real findings get
        #                ignored.
        #   · returns -- only `return`: cannot serve anything.
        serves = bool(re.search(r"^\s*(try_files|root|alias)", body, re.M))
        proxies = bool(re.search(r"^\s*proxy_pass", body, re.M))
        only_return = bool(re.search(r"^\s*return\s+\d+", body, re.M)) and \
            not serves and not proxies
        nested_deny = bool(re.search(
            r"^\s*location\s+~\*?\s+[\"']?(\(\^\|/\)\[\.\]|\S*\(bak)", body,
            re.M))
        if serves:
            kind_of = "serves"
        elif proxies:
            kind_of = "proxies"
        else:
            kind_of = "returns"
        # `location = /x` is an *exact* match: it covers one URI and no
        # subtree, so it cannot hide a file behind a prefix. Treating it as a
        # hole made this command report the gate's own `/__btgate` entry
        # points as exposures -- a false alarm loud enough to teach an
        # operator to ignore the command, which is worse than not having it.
        exact = (kind == "=")
        out.append({
            "kind": kind, "prefix": prefix, "covered": covered,
            "serves": serves and not exact, "proxies": proxies, "exact": exact,
            "safe": (covered or only_return or nested_deny or proxies
                     or exact),
            "includes": includes,
        })
    return out


def include_line(conf_path: str) -> str:
    """The `include` statement that re-applies the rules inside a `^~` prefix."""
    ext = Path(conf_path).parent
    return "include %s/zz-exposure-deny.conf;" % ext


def repair_prefixes(text: str, conf_path: str) -> tuple:
    """Put the ruleset back inside every file-serving `^~` prefix.

    Returns ``(new_text, added_prefixes)``.

    Why this exists: the include has to live *inside* the site's own
    configuration, and on a panel-managed host that file belongs to the panel.
    Measured on the development host, the include silently disappeared from
    `zz-function.conf` -- the file was rewritten by something other than this
    program -- which re-opened a hole where a real 3 KB `.gitignore` and any
    future `.env` under that prefix became publicly downloadable. A guard that
    can be removed by a third party without anyone noticing is not a guard, so
    the repair is automatic and the health check reports when it was needed.
    """
    if "zz-exposure-deny" in text:
        return text, []
    line = include_line(conf_path)
    added = []
    out, pos = [], 0
    for m in re.finditer(r"^[ \t]*location\s+\^~\s*(\S+?)\s*\{", text, re.M):
        prefix = m.group(1)
        # Only file-serving prefixes: a `return 404` block cannot hand out a
        # file, and adding an include to it would be noise.
        close = text.find("}", m.end())
        body = text[m.end():close]
        if "return 404" in body and "try_files" not in body \
                and "proxy_pass" not in body:
            continue
        if "proxy_pass" in body:
            continue
        out.append(text[pos:m.end()])
        out.append("\n        # 由 vigil 补回：`^~` 会跳过同级正则规则。\n"
                   "        " + line + "\n")
        pos = m.end()
        added.append(prefix)
    out.append(text[pos:])
    return "".join(out), added


def site_confs(root=None) -> list:
    """Per-site nginx config files that may carry a `^~` prefix."""
    roots = [Path(root)] if root else [
        Path("/www/server/panel/vhost/nginx/extension"),
        Path("/etc/nginx/conf.d"),
        Path("/etc/nginx/sites-enabled"),
    ]
    out = []
    for base in roots:
        if not base.exists():
            continue
        for entry in sorted(base.iterdir()):
            if entry.is_file() and entry.suffix == ".conf":
                out.append(entry)
            elif entry.is_dir():
                out.extend(sorted(entry.glob("*.conf")))
    return out


def repair_sites(root=None) -> dict:
    """Re-apply the include everywhere it is missing, then prove nginx loads.

    Only touches a directory that already contains `zz-exposure-deny.conf`:
    if the file is not there, this installation never put rules in that site,
    and adding an include would break a config that does not have the target.
    """
    from ..gates import shield as _shield

    #: Files this program writes into a site's extension directory. If any of
    #: them is present, the directory is one we manage -- which is what makes
    #: it safe to also (re)create the rules files there. A directory with none
    #: of them has never been ours, and writing an include into its config
    #: would point at a file that does not exist, breaking nginx.
    managed_marks = ("zz-exposure-deny.conf", "vigil-deny.conf",
                     "vigil-hygiene.conf", "vigil-lure.conf", "vigil-decoy.conf")

    touched, added, problems, restored = [], [], [], []
    for conf in site_confs(root):
        ext = conf.parent
        if not (ext / "zz-exposure-deny.conf").is_file():
            if not any((ext / m).is_file() for m in managed_marks):
                continue
            # The rules file itself is gone -- a wiped extension directory, or
            # a panel that cleaned up files it did not recognise. Recreate it,
            # otherwise the include below would reference nothing and nginx
            # would refuse to load at all.
            for name, content in (("zz-exposure-deny.conf",
                                   render_deny_snippet()),
                                  ("zz-exposure-deny-dirs.conf",
                                   render_directory_snippet())):
                (ext / name).write_text(content, encoding="utf-8")
                restored.append(str(ext / name))
        try:
            text = conf.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            problems.append("%s：%s" % (conf, exc))
            continue
        if "location ^~" not in text:
            continue
        new, added_here = repair_prefixes(text, str(conf))
        if not added_here:
            continue
        conf.write_text(new, encoding="utf-8")
        touched.append(str(conf))
        added.extend(added_here)
    if not touched and not restored:
        return {"ok": True, "written": [], "prefixes": [], "restored": [],
                "problems": problems, "reloaded": ""}
    ok, how = _shield._reload_verified()
    if not ok:
        problems.append("nginx 拒绝新配置：%s" % how)
    return {"ok": ok, "written": touched, "prefixes": added,
            "restored": restored, "problems": problems,
            "reloaded": how if ok else ""}


def audit_conf(conf_text: str) -> dict:
    """Everything worth reporting about one vhost's exposure posture."""
    bypasses = prefix_bypasses(conf_text)
    return {
        "has_shape_rule": "return 404" in conf_text and bool(
            re.search(r"location\s+~\*?\s*[\"'].*bak", conf_text)),
        "has_dir_rule": bool(re.search(
            r"location\s+~\*?\s*[\"'].*node_modules", conf_text)),
        "prefixes": bypasses,
        # Only prefixes that read the disk *and* skip the rules are findings.
        "uncovered": [b for b in bypasses if b["serves"] and not b["safe"]],
    }
