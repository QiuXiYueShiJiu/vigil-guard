"""The public slider-puzzle playground.

Serves the gate's own puzzle at a fixed path on a site, with none of the
gate's machinery: no session, no rate limit, no lockout, no protected
upstream. Nothing is behind it, so there is nothing to attack -- which is
what makes it safe to leave open, and why every piece of the security
apparatus is deliberately absent rather than merely disabled.

Installed as a single nginx ``location =`` pointing at one PHP file. That
file answers the page, the images and the verdict, so there is exactly one
URL to configure and no state directory to expose.

The drawing code is the gate's own ``gate-lib.php``, so what a visitor plays
with is identical to what the real gate serves. A demo that drifts from the
product teaches people the wrong thing.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

from ..core import detect
from .installer import TEMPLATES, _atomic_write, _ensure_http_include, _render

DEMO_PATH = "/CAPTCHA"
CONF_NAME = "zz-vigil-captcha-demo.conf"
MARKER = "# Vigil CAPTCHA playground"


def _spec(cfg):
    """The gate spec for whichever gate fronts this host's panel.

    Reused rather than re-derived: resolving a site's document root, its
    PHP socket and the vhost that serves it is exactly the problem
    ``GateSpec`` already solves, and doing it a second way here would be a
    second thing to keep correct.
    """
    from ..core import detect as _d
    from . import detect_one
    env = _d.full()
    for kind in ("bt_panel", "login"):
        try:
            spec = detect_one(kind, env)
        except Exception:                              # noqa: BLE001
            continue
        if getattr(spec, "webroot", "") and Path(spec.webroot).is_dir():
            return spec
    return None


def _site(cfg) -> tuple:
    """``(domain, webroot)`` for the site that serves this host's panel.

    Deliberately *not* the gate's own webroot. The gate's files live in a
    small directory of their own that nginx is pointed at by path; the site
    a visitor reaches is a different document root, and publishing the demo
    into the gate's directory would put a public page inside the state of a
    security component.
    """
    spec = _spec(cfg)
    domain = ""
    if spec is not None:
        domain = str(getattr(spec, "domain", "") or "").strip()
        if not domain:
            name = str(getattr(spec, "server_name", "") or "").strip()
            if name and name not in ("_", "-", "*"):
                domain = name.split()[0]
        if not domain:
            # The gate's nginx fragment lives in the panel's per-site
            # `extension/<domain>/` directory. That path is the most reliable
            # statement of which site the gate is wired into -- more reliable
            # than `server_name`, which on a panel-managed host is often the
            # catch-all `_` because the panel writes a separate vhost per
            # domain and leaves this one generic.
            domain = _domain_from_conf(str(getattr(spec, "nginx_conf", "") or ""))
    if not domain:
        return "", ""
    ascii_domain = _domain_ascii(str(getattr(spec, "nginx_conf", "") or ""))
    # The panel subdomain is where the gate protects the panel; the demo
    # belongs on the *main* site, because that is the address people type.
    # So the search widens from the exact host to the registrable domain
    # behind it, and settles on whichever vhost answers that name.
    main = _main_site_ascii(ascii_domain)
    root = _site_root_by_scan(main, _decode(main)) if main else ""
    if root and main:
        # Report the address people will actually type, not the one the
        # gate happens to sit behind.
        return _decode(main), root
    if not root:
        root = _site_root_by_scan(ascii_domain, domain)
    return domain, root


def _decode(raw: str) -> str:
    if not raw:
        return ""
    try:
        import encodings.idna as _idna
        return ".".join(_idna.ToUnicode(l.encode("ascii"))
                        if l.startswith("xn--") else l
                        for l in raw.split("."))
    except Exception:                                  # noqa: BLE001
        return raw


def _main_site_ascii(ascii_domain: str) -> str:
    """The vhost that answers the registrable domain, not a subdomain.

    `panel.example.com` is a subdomain; `example.com` is the site, and the
    site is where people already are. The registrable domain is taken as the
    last two labels -- right for `.top`, `.com` and the rest of the common
    suffixes, and the alternative (a public-suffix list) is a dependency
    this project does not take.
    """
    labels = [l for l in (ascii_domain or "").split(".") if l]
    if len(labels) < 2:
        return ""
    registrable = ".".join(labels[-2:])
    wanted = {registrable, _decode(registrable)}
    main_conf = detect.nginx().get("conf", "")
    bases = [Path(main_conf).parent / "vhost",
             Path("/www/server/panel/vhost/nginx")]
    for base in bases:
        if not base.is_dir():
            continue
        for conf in sorted(base.glob("*.conf")):
            if conf.name.startswith(("0.", "waf", "phpfpm")):
                continue
            try:
                text = conf.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line in text.splitlines():
                stripped = line.strip()
                if not stripped.startswith("server_name"):
                    continue
                names = stripped.split(None, 1)[1] if " " in stripped else ""
                if any(n in names.split() for n in wanted):
                    return registrable
    return ""


def _site_root_by_scan(ascii_domain: str, display: str = "") -> str:
    """Document root of whichever vhost answers a name.

    Scanned rather than looked up by filename: a panel names the vhost after
    the first domain it was created for, so a site that also answers the
    registrable domain often lives in a file called something else entirely.
    """
    wanted = {x for x in (ascii_domain, display) if x}
    if not wanted:
        return ""
    main_conf = detect.nginx().get("conf", "")
    bases = [Path(main_conf).parent / "vhost",
             Path("/www/server/panel/vhost/nginx")]
    for base in bases:
        if not base.is_dir():
            continue
        for conf in sorted(base.glob("*.conf")):
            if conf.name.startswith(("0.", "waf", "phpfpm")):
                continue
            try:
                text = conf.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            names = set()
            root = ""
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("server_name"):
                    names.update(stripped.split(None, 1)[1].split()
                                 if " " in stripped else [])
                elif stripped.startswith("root ") and stripped.endswith(";") and not root:
                    root = stripped.split(None, 1)[1].rstrip(";").strip()
            if names & wanted and root:
                return root
    return ""
def _domain_ascii(conf_path: str) -> str:
    """The ASCII domain of the site a panel extension path belongs to."""
    parts = Path(conf_path).parts
    if "extension" in parts:
        idx = parts.index("extension")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return ""


def _domain_from_conf(conf_path: str) -> str:
    """Same domain, in the form a browser and a certificate use."""
    return _decode(_domain_ascii(conf_path))


def _nginx_bits() -> tuple:
    ng = detect.nginx()
    spec = _spec(None)
    fastcgi = (getattr(spec, "fastcgi_pass", "") if spec else "") or ""
    fastcgi_conf = (getattr(spec, "fastcgi_conf", "") if spec else "") or "fastcgi.conf"
    return (ng.get("conf", ""),
            ng.get("binary") or "/usr/local/nginx/sbin/nginx",
            fastcgi or "unix:/tmp/php-cgi-82.sock",
            fastcgi_conf)


def _conf_dir(main_conf: str) -> Path:
    return Path(main_conf).parent


def _php_bin() -> str:
    from .installer import php_bin
    return php_bin()


def render_conf(domain: str, webroot: str, server_name: str) -> str:
    """The server-scope snippet that exposes the demo."""
    main_conf, _bin, fastcgi, fastcgi_conf = _nginx_bits()
    script = str(Path(webroot) / "CAPTCHA" / "demo.php")
    return """%s
# GENERATED -- regenerate with `vigil gate demo install`
#
# One location, one file. It answers the page, the images and the verdict,
# so there is no directory to expose and no index to get wrong.
#
# This path is intentionally unprotected. Nothing is behind it: there is no
# session to steal, no account to brute force, and no upstream to reach. It
# is a toy, and treating it as anything else would be the actual mistake.
# The exact match below does not cover a trailing slash, and a request for
# `/CAPTCHA/` then falls through to the site's default handler -- which
# answers 403 because there is no directory listing. People type the slash.
location = %s/ {
    return 301 %s;
}

location = %s {
    limit_except GET POST { deny all; }
    include %s;
    fastcgi_pass %s;
    fastcgi_param SCRIPT_FILENAME %s;
    # A playground is hit repeatedly by one person watching the animation.
    # No rate limit here on purpose -- it is not protecting anything.
    add_header Cache-Control "no-store" always;
}
""" % (MARKER, DEMO_PATH, DEMO_PATH, DEMO_PATH, fastcgi_conf,
       fastcgi, script)


def status(cfg=None) -> dict:
    from ..core.config import load as load_config
    cfg = cfg or load_config()
    main_conf, _b, _f, _c = _nginx_bits()
    domain, webroot = _site(cfg)
    conf = _conf_dir(main_conf) / CONF_NAME
    script = Path(webroot) / "CAPTCHA" / "demo.php" if webroot else None
    text = Path(main_conf).read_text(encoding="utf-8", errors="replace") \
        if Path(main_conf).is_file() else ""
    return {
        "domain": domain,
        "webroot": webroot,
        "url": ("https://%s%s" % (domain, DEMO_PATH)) if domain else "",
        "conf": str(conf),
        "conf_present": conf.is_file(),
        "conf_included": CONF_NAME in text,
        "script": str(script) if script else "",
        "script_present": bool(script and script.is_file()),
    }


def install(cfg=None) -> dict:
    from ..core.config import load as load_config
    cfg = cfg or load_config()
    out = {"written": [], "url": "", "problems": [], "ok": False}

    domain, webroot = _site(cfg)
    if not webroot or not Path(webroot).is_dir():
        out["problems"].append("找不到站点根目录（配置里没有 gate.bt_panel.domain，"
                               "也无法从 nginx 推断）")
        return out
    out["url"] = "https://%s%s" % (domain, DEMO_PATH) if domain else DEMO_PATH

    main_conf, binary, _f, _c = _nginx_bits()
    conf_dir = _conf_dir(main_conf)

    # The demo draws with the gate library, so it needs a copy it can read.
    lib_src = Path(cfg.get("gate.bt_panel.state_dir", "") or "") / "lib" / "gate-lib.php"
    if not lib_src.is_file():
        # Fall back to any installed gate's library.
        for state in ("/www/server/bt-gate", "/www/server/dsh-gate"):
            cand = Path(state) / "lib" / "gate-lib.php"
            if cand.is_file():
                lib_src = cand
                break
    if not lib_src.is_file():
        out["problems"].append("找不到网关库 gate-lib.php —— 先安装一个登录网关，"
                               "或运行 vigil gate reconfigure")
        return out

    target_dir = Path(webroot) / "CAPTCHA"
    target_dir.mkdir(parents=True, exist_ok=True)
    state = target_dir / "state"
    state.mkdir(parents=True, exist_ok=True)

    # Its own copy of the library: the demo must keep working if a gate is
    # later removed, and a shared file that two things own is a file that
    # eventually gets overwritten by one of them.
    lib_dst = target_dir / "gate-lib.php"
    shutil.copy2(str(lib_src), str(lib_dst))
    out["written"].append(str(lib_dst))

    # The picture pool, handed to the page so it can actually use it.
    # Without these the demo silently served generated art only, and the
    # pictures it was supposed to be showing never appeared.
    # The main site gets its own list first. Falling straight through to the
    # gates' list is what would hand the public page the anime pool.
    pool_dirs = list(cfg.get("gate.demo.image_dirs") or [])
    if not pool_dirs:
        pool_dirs = list(cfg.get("gate.bt_panel.image_dirs")
                         or cfg.get("gate.dsh_gate.image_dirs") or [])
    text = _render("demo.php.tmpl", {
        "LIB_PATH": str(lib_dst),
        "DEMO_STATE": str(state),
        "DEMO_PATH": DEMO_PATH,
        # The vigil config stores this as a word and the gate's own
        # config.php as an integer; the page reads the integer form, so the
        # conversion has to handle both. `int("auto")` raised and took the
        # whole install down.
        "DEMO_SCENE_KIND": _scene_kind_int(
            cfg.get("gate.demo.scene_kind")
            or cfg.get("gate.bt_panel.scene_kind")
            or cfg.get("gate.dsh_gate.scene_kind")),
        "DEMO_IMAGE_DIRS": "[" + ", ".join("'%s'" % d for d in pool_dirs) + "]",
        # Single-quoted PHP literals: these are substituted straight into an
        # array, and an unquoted path is a parse error, not a string.
        "DEMO_IMAGE_CACHE": "'" + (str(Path(pool_dirs[0]) / ".cache")
                                   if pool_dirs else str(state / "cache")) + "'",
        "DEMO_IMAGE_BLOCK": ("'" + str(Path(pool_dirs[0]) / ".blocklist.json") + "'")
                            if pool_dirs else "''",
    })
    script = target_dir / "demo.php"
    _atomic_write(script, text, 0o644)
    out["written"].append(str(script))

    # The web server must be able to write the puzzle images and read both
    # files; root keeps ownership so the copy cannot be edited from the web.
    ng = detect.nginx()
    user = ng.get("worker_user") or "www"
    for path, mode in ((target_dir, 0o750), (state, 0o770),
                       (lib_dst, 0o640), (script, 0o644)):
        try:
            os.chmod(path, mode)
        except OSError:
            pass
    try:
        import grp
        gid = grp.getgrnam(user).gr_gid
        # The library is copied from the gate's state directory, where it is
        # 0600 root:root on purpose. Copying those permissions straight over
        # left the web server unable to read it, and the page died on
        # `require_once` with "Permission denied". Every file the page needs
        # has to be made readable by the worker, explicitly.
        for path in (state, target_dir):
            os.chown(path, 0, gid)
        for path in (lib_dst, script):
            os.chown(path, 0, gid)
        os.chmod(lib_dst, 0o640)
        os.chmod(script, 0o644)
    except (KeyError, OSError):
        pass

    conf = conf_dir / CONF_NAME
    if conf.exists():
        shutil.copy2(str(conf), "%s.bak-%s" % (conf, time.strftime("%Y%m%d-%H%M%S")))
    _atomic_write(conf, render_conf(domain, webroot, domain), 0o644)
    out["written"].append(str(conf))

    # A server-scope snippet has to be included from the vhost, not from
    # http{}. This panel includes `vhost/nginx/extension/<domain>/*.conf`
    # from each site, so that is exactly where it goes -- derived from the
    # site's own vhost, not from our gate's fragment (which lives in the same
    # tree and, in an earlier version, got its own path appended to it,
    # producing `extension/<domain>/extension/<x>/`, a directory nothing
    # includes).
    ascii_domain = _domain_ascii(str(getattr(spec_of(cfg), "nginx_conf", "") or "")) \
        if spec_of(cfg) is not None else ""
    server_name = domain or "_"
    # Find the directory the site's own configuration already includes from,
    # by looking at what the vhost actually says. Guessing at a layout put a
    # `location` block into `http{}` -- which nginx rejects outright, so the
    # whole server refused to reload. Reading the include line cannot guess
    # wrong.
    # The *site's* domain, not the gate's: the gate sits behind a panel
    # subdomain, and that subdomain's vhost is not the one serving the main
    # page. Passing the wrong name here meant no vhost matched and the
    # fragment could not be placed at all.
    site_ascii = _main_site_ascii(ascii_domain) or ascii_domain
    include_dir = _site_include_dir(site_ascii)
    if include_dir is None and site_ascii != ascii_domain:
        include_dir = _site_include_dir(ascii_domain)
    if include_dir is None:
        out["problems"].append(
            "找不到站点用来 include 片段的目录 —— 本机的 nginx 布局不是"
            "面板式的，请手工把 conf 片段接入站点")
        return out
    else:
        include_dir.mkdir(parents=True, exist_ok=True)
        target = include_dir / CONF_NAME
        _atomic_write(target, render_conf(domain, webroot, server_name), 0o644)
        out["written"].append(str(target))
        conf.unlink(missing_ok=True)
        _drop_include(main_conf, conf)

    good, detail = _nginx_test(binary)
    if not good:
        out["problems"].append("nginx -t 失败：%s" % detail[:300])
        return out
    ok, how = _reload()
    if not ok:
        out["problems"].append("nginx 重载失败：%s" % how)
        return out
    out["ok"] = True
    return out


def uninstall() -> dict:
    out = {"removed": [], "problems": [], "ok": False}
    main_conf, binary, _f, _c = _nginx_bits()
    for pattern in ("**/" + CONF_NAME,):
        for conf in Path(main_conf).parent.glob(pattern):
            conf.unlink(missing_ok=True)
            out["removed"].append(str(conf))
    st = status()
    if st["script_present"]:
        d = Path(st["script"]).parent
        shutil.rmtree(str(d), ignore_errors=True)
        out["removed"].append(str(d))
    good, detail = _nginx_test(binary)
    if not good:
        out["problems"].append("nginx -t 失败：%s" % detail[:300])
        return out
    ok, how = _reload()
    out["ok"] = ok
    if not ok:
        out["problems"].append("nginx 重载失败：%s" % how)
    return out


# --------------------------------------------------------------------------

def _find_site_conf(server_name: str) -> str:
    """The vhost file that serves *server_name*, if it can be found."""
    spec = _spec(None)
    if spec is not None and getattr(spec, "nginx_conf", ""):
        return str(spec.nginx_conf)
    main_conf, _b, _f, _c = _nginx_bits()
    root = Path(main_conf).parent
    for base in (root / "vhost", root.parent / "panel" / "vhost" / "nginx"):
        if not base.is_dir():
            continue
        for conf in sorted(base.glob("*.conf")):
            try:
                text = conf.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if server_name and server_name in text and "server_name" in text:
                return str(conf)
    return ""


def _panel_dir_for(server_name: str) -> str:
    return server_name


def _nginx_test(binary: str) -> tuple:
    try:
        proc = subprocess.run([binary, "-t"], capture_output=True, text=True,
                              timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    return proc.returncode == 0, (proc.stderr or proc.stdout or "").strip()


def _reload() -> tuple:
    for cmd in (["systemctl", "reload", "nginx"], ["nginx", "-s", "reload"]):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if proc.returncode == 0:
                return True, " ".join(cmd)
        except (OSError, subprocess.SubprocessError):
            continue
    return False, "所有重载方式都失败了"


def spec_of(cfg):
    """Public alias for the gate spec this module resolves against."""
    return _spec(cfg)


def _drop_include(main_conf: str, conf: Path) -> None:
    """Remove an include of *conf* from the main configuration, if present."""
    main = Path(main_conf)
    if not main.is_file():
        return
    try:
        text = main.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    line = "    include %s;" % conf
    if line not in text and str(conf) not in text:
        return
    kept = [ln for ln in text.splitlines() if str(conf) not in ln]
    _atomic_write(main, "\n".join(kept) + "\n", 0o644)


def _site_include_dir(ascii_domain: str):
    """The directory a site includes ``*.conf`` from, or None.

    Read from the vhost's own `include` lines rather than assumed. A wrong
    guess here is not a cosmetic problem: a server-scope `location` written
    into `http{}` makes nginx refuse to load at all.
    """
    main_conf = detect.nginx().get("conf", "")
    bases = [Path(main_conf).parent / "vhost",
             Path("/www/server/panel/vhost/nginx")]
    wanted = {ascii_domain, _decode(ascii_domain)}
    for base in bases:
        if not base.is_dir():
            continue
        for site in sorted(base.glob("*.conf")):
            try:
                text = site.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            names = set()
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("server_name") and " " in stripped:
                    names.update(stripped.split(None, 1)[1].split())
            if not (names & wanted):
                continue
            for line in text.splitlines():
                stripped = line.strip()
                if not stripped.startswith("include"):
                    continue
                target = stripped.split(None, 1)[1].rstrip(";").strip()
                if not target.endswith("*.conf"):
                    continue
                directory = Path(target).parent
                if directory.is_dir():
                    return directory
    return None


def _scene_kind_int(value) -> int:
    """0 = generated art, 1 = pictures only, 2 = both, at random."""
    if isinstance(value, int):
        return value if value in (0, 1, 2) else 2
    return {"art": 0, "image": 1, "auto": 2}.get(str(value or "").strip(), 2)
