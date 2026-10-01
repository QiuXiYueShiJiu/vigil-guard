"""Request hygiene: bound the request line and the Host header.

Why this exists
---------------
Measured on this host before the module was written: a **16 KB URI** and a
**4 KB Host header** both received a normal `301` from the public vhost.
Neither was rejected, and every byte of both was buffered and written to the
access log.

That is not a theoretical concern. Oversized request lines and absurd `Host`
values are the signature of exactly two kinds of traffic:

* **scanners**, which walk long dictionary paths and probe for log injection
  -- the same traffic the rest of this program exists to catch, arriving in a
  form that costs the host the most to handle;
* **deliberate resource pressure**, where the cheap side of the connection
  makes the expensive side allocate. Four concurrent connections are already
  capped by `limit_conn`, but the per-connection buffer is what decides how
  much each of those four costs.

The host had inherited `client_header_buffer_size 32k` and
`large_client_header_buffers 4 32k` from the panel's own `nginx.conf`, which
is 32x nginx's default request-line headroom. Those live in `http{}` and are
shared by every vhost, so this module does not touch them. It writes a
**server-scope** snippet into each site's `extension/` directory instead --
the same mechanism the decoy lures use -- which tightens the limits for the
sites this program protects without editing a file the panel owns and
rewrites.

What it sets, and why those numbers
-----------------------------------
* `client_header_buffer_size 4k` / `large_client_header_buffers 4 8k`
  -- nginx's own defaults. A request line longer than 8 KB is answered with
  `414` by nginx itself, before any of this program's Lua or rule matching
  runs, which is the cheapest possible place to refuse it.
* an explicit `$request_uri` length cap, so that oversized requests are
  refused *and* the refusal is legible, rather than arriving as a bare
  parse error. Set well above any real path on these sites.
* an explicit `$http_host` length cap at 254 bytes, the longest a DNS name
  can be. `444` closes the connection without a response body, which is the
  right answer for a `Host` that cannot be a real name.

Nothing here is a substitute for authentication or for the rate limits in
`shield`; it only removes the cheapest way to make the server do work for
free.
"""
from __future__ import annotations

import os
from pathlib import Path

from ..core import detect, paths

#: Written into each site's `extension/` directory, so nginx includes it
#: inside the `server{}` block. The name sorts near the other vigil files.
CONF_NAME = "vigil-hygiene.conf"

#: Longest URI we will accept, in bytes, including the query string.
MAX_URI = 4096
#: Longest `Host` we will accept, in bytes. 253 is the DNS maximum.
MAX_HOST = 254

#: Methods this host serves. Everything else is refused with 405.
#:
#: The site is a set of static pages plus a small API surface: it has nothing
#: that is legitimately written to over HTTP. `PUT`, `DELETE`, `TRACE`,
#: `PROPFIND`, `MKCOL` and friends exist here only as something to exploit --
#: WebDAV misconfiguration, cross-site tracing, and the long tail of CMS
#: upload bugs all begin with a method the site never needed. Refusing them
#: at the top of the server block costs nothing and removes a whole class of
#: request before any other rule has to consider it.
ALLOWED_METHODS = ("GET", "HEAD", "POST")

#: Path shapes that are never a legitimate request, rejected on the **raw**
#: `$request_uri` rather than the normalised `$uri`.
#:
#: Why raw matters: nginx decodes `%XX`, collapses `//` and resolves `.`/`..`
#: *before* it matches a location, so a rule written against `$uri` sees the
#: clean result and cannot tell a probe from an honest request. Every path we
#: proxy (`/function/api/`, the panel's FastCGI entries) then hands the
#: original, still-encoded path to a backend that does its own decoding --
#: Express, PHP and Python each normalise differently, and that difference is
#: where traversal lives. Measured on this host, nginx already answers 400 to
#: `%2f`/`%00` and never forwards `..`, so this is defence in depth rather
#: than a live hole -- and its main product is a *log line*: with this rule,
#: "someone is probing traversal" is one explicit 400 instead of an
#: indistinguishable 404.
# Anchored on a `/` boundary on purpose. `$request_uri` includes the query
# string, and this host has a chat API: `encodeURIComponent("a\\b")` is
# `a%5Cb`, so a pattern matching `%5c` anywhere would answer 400 to a person
# typing a backslash into a message. That is a hardening rule breaking the
# product -- the one outcome worse than the hole it closes. Requiring a path
# boundary keeps `/%2e%2e/x` out and leaves `?msg=..` alone. `%00` stays
# unanchored: a NUL is never legitimate in either half.
BAD_URI = (r"((^|/)(\.\./|\.\.$|%2e%2e|%252e|%c0%ae|%e0%80%ae)|%00)")

#: Headers whose only purpose is to change the verb after the method check has
#: already run. Nothing on this host uses them: the game backend does not
#: mount Express's `methodOverride`, and neither do the PHP pages. They turn a
#: POST into a PUT/DELETE for anything downstream that honours them, which is
#: precisely the method the rules above just refused.
OVERRIDE_HEADERS = ("$http_x_http_method_override", "$http_x_method_override")


def render() -> str:
    """The server-scope snippet.

    Kept free of any host-specific value: this file is written to every
    protected site and must not carry one site's identity into another's
    configuration.
    """
    return """# 由 vigil 生成：请求卫生（请勿手工编辑，vigil update/卸载会重建或删除）
#
# 在 server{} 作用域收紧请求行与 Host 头的大小。面板在 http{} 里把它们
# 放大到了 32k，那是所有站点共用的；这里只收紧本程序保护的站点。
# 目的：让超长请求在 nginx 解析阶段就被拒绝，而不是先缓冲、先记日志、
# 再交给后面的规则去处理。

client_header_buffer_size     4k;
large_client_header_buffers   4 8k;

# 只接受本站真正需要的请求方法。其余（PUT / DELETE / TRACE / PROPFIND …）
# 在本站没有任何合法用途，只可能是被利用的对象。
if ($request_method !~ ^(%(methods)s)$) {
    return 405;
}

# 超长请求行：nginx 自己在超过 large_client_header_buffers 时就会回 414。
# 这条把界限提前到 %(max_uri)d 字节，并让拒绝原因在日志里可读。
if ($request_uri ~ "^.{%(uri_re)d,}") {
    return 414;
}

# 超长 Host：DNS 名字最长 253 字节，再长不可能解析得到。444 直接断开，
# 不回响应体 —— 对不可能存在的域名，这是最省事也最准确的答复。
if ($http_host ~ "^.{%(host_re)d,}") {
    return 444;
}

# 路径穿越与 NUL 的**原始**形态（见 BAD_URI 的说明：这里故意用
# $request_uri 而不是 $uri —— nginx 在匹配 location 之前就已经解码并归一化，
# 而代理给后端的正是未归一的原始串）。
if ($request_uri ~* "%(bad_uri)s") {
    return 400;
}

# 方法覆盖头：只检查 $request_method 是拦不住它们的。
%(override)s
""" % {"max_uri": MAX_URI, "uri_re": MAX_URI + 1, "host_re": MAX_HOST + 1,
       "methods": "|".join(ALLOWED_METHODS), "bad_uri": BAD_URI,
       "override": "\n".join(
           "if (%s) { return 400; }" % h for h in OVERRIDE_HEADERS)}


def extension_roots() -> list:
    """Directories whose `*.conf` files nginx includes inside `server{}`."""
    roots = []
    try:
        conf = (detect.nginx() or {}).get("conf", "")
        if conf:
            roots.append(Path(conf).parent / "vhost" / "nginx" / "extension")
    except (OSError, AttributeError):
        pass
    roots.append(Path("/www/server/panel/vhost/nginx/extension"))
    out = []
    for r in roots:
        if r.is_dir() and r not in out:
            out.append(r)
    return out


def targets() -> list:
    """Every `(site_dir, conf_path)` pair that should carry the snippet.

    A site directory only counts if it already holds a generated vigil file,
    so this never introduces the snippet into a vhost this program has not
    otherwise touched.
    """
    out = []
    for root in extension_roots():
        try:
            sites = sorted(p for p in root.iterdir() if p.is_dir())
        except OSError:
            continue
        for site in sites:
            if (site / "vigil-deny.conf").is_file() or \
               (site / CONF_NAME).is_file() or \
               (site / "vigil-decoy.conf").is_file():
                out.append((site, site / CONF_NAME))
    return out


def install(dry_run: bool = False) -> tuple:
    """Write the snippet and prove nginx took it. All-or-nothing."""
    from ..gates import shield

    pairs = targets()
    if not pairs:
        return False, "没有找到受保护的站点（扩展目录为空）"
    body = render()
    written, created = [], []
    try:
        for _site, conf in pairs:
            existed = conf.exists()
            old = conf.read_text(encoding="utf-8") if existed else None
            if old == body:
                written.append(str(conf))
                continue
            if dry_run:
                written.append(str(conf))
                continue
            conf.parent.mkdir(parents=True, exist_ok=True)
            conf.write_text(body, encoding="utf-8")
            os.chmod(conf, 0o644)
            written.append(str(conf))
            created.append((conf, old))
    except OSError as e:
        for conf, old in created:
            try:
                if old is None:
                    conf.unlink()
                else:
                    conf.write_text(old, encoding="utf-8")
            except OSError:
                pass
        return False, "写入失败，已回滚：%s" % e
    if dry_run:
        return True, "预演：将写入 %d 个站点" % len(written)
    # Validate before reloading, and roll back if nginx rejects the snippet.
    # Writing first and reloading second is what leaves a host one restart
    # away from an outage: a rejected reload keeps the old config running, so
    # everything looks fine until something restarts nginx and it will not
    # come up. `nginx -t` reads the files exactly as a restart would.
    ok, detail = shield._nginx_test()
    if not ok:
        for conf, old in created:
            try:
                if old is None:
                    conf.unlink()
                else:
                    conf.write_text(old, encoding="utf-8")
            except OSError:
                pass
        return False, "nginx -t 未通过，已全部回滚：%s" % detail[:300]
    ok, how = shield._reload_verified()
    if not ok:
        return False, "nginx 未接受新配置：%s" % how
    return True, "已写入 %d 个站点并重载：%s" % (len(written), how)


def uninstall() -> tuple:
    from ..gates import shield

    removed = 0
    for _site, conf in targets():
        try:
            if conf.exists():
                conf.unlink()
                removed += 1
        except OSError:
            pass
    if not removed:
        return True, "没有需要移除的请求卫生配置"
    ok, how = shield._reload_verified()
    return ok, "已移除 %d 个站点：%s" % (removed, how)


def status() -> dict:
    pairs = targets()
    active = [(str(conf), conf.exists() and
               conf.read_text(encoding="utf-8") == render())
              for _site, conf in pairs]
    return {"sites": len(pairs),
            "installed": sum(1 for _p, ok in active if ok),
            # `present` answers "is this feature in use here?"; `installed`
            # answers "is the content current?". They are different questions
            # and the upgrade path needs the first one: an upgrade is exactly
            # when the content is *not* current, so a refresh step that keyed
            # on `installed` skipped itself and the new rule never shipped.
            "present": sum(1 for p, _ok in active if Path(p).exists()),
            "stale": [p for p, ok in active if not ok],
            "max_uri": MAX_URI, "max_host": MAX_HOST,
            "allowed_methods": list(ALLOWED_METHODS)}


def main(argv=None) -> int:
    """Small entry point so the module can be exercised on its own."""
    import argparse
    ap = argparse.ArgumentParser(description="请求卫生：限制请求行与 Host 头")
    ap.add_argument("action", nargs="?", default="status",
                    choices=["install", "uninstall", "status", "render"])
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    if a.action == "render":
        print(render())
        return 0
    if a.action == "install":
        ok, msg = install(dry_run=a.dry_run)
    elif a.action == "uninstall":
        ok, msg = uninstall()
    else:
        st = status()
        print("站点 %d 个，已生效 %d 个，上限 URI=%d 字节 Host=%d 字节"
              % (st["sites"], st["installed"], st["max_uri"], st["max_host"]))
        for p in st["stale"]:
            print("  未生效/待更新：%s" % p)
        return 0
    print(("✔ " if ok else "✖ ") + msg)
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
