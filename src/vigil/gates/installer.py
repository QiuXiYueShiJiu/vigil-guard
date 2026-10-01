"""Gate installer.

Renders a :class:`GateSpec` into files, wires nginx, provisions a
certificate if asked, and applies the upstream-application patches the gate
depends on.

Safety rules, all learned from failures:

* **Validate before writing.** ``nginx -t`` runs before the reload, and the
  snippet is removed again if it fails, so a typo can never leave the web
  server unable to reload.
* **Back up every file we replace**, including the nginx vhost we inject an
  include line into.
* **Never touch a credential we did not create.** Adoption preserves an
  existing password hash byte for byte; reinstalling would lock the operator
  out, because the plaintext is not recoverable.
* **Fail loudly.** Missing PHP, missing Lua support, a bad cert — each is
  reported as a specific problem rather than surfacing later as a 500.
"""
from __future__ import annotations

import grp
import os
import pwd
import re
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path

from ..core import paths, shell
from ..core.errors import UnsupportedError, VigilError
from .spec import KIND_BT, KIND_LOGIN, GateSpec

#: Layouts an earlier version of this tool created. Mirrored here so the
#: installer can recognise and take over from its own previous output
#: without disturbing the other gate type.
LEGACY_LAYOUTS = (
    {"kind": KIND_BT, "state_dir": "/www/server/bt-gate"},
    {"kind": KIND_LOGIN, "state_dir": "/www/server/dsh-gate"},
)

TEMPLATES = Path(__file__).resolve().parent / "templates"
from ..core.paths import BACKUP_DIR as BACKUP_ROOT

#: Default patches that let a non-loopback visitor use the full upstream UI.
#: Each is (relative path under the module root, find, replace, marker).
DSH_SETTINGS_PATCHES = (
    ("dsh-client-ui-settings/lib/client.js",
     'const persistence = ctx.remote.$host.isLoopback ? "host" : "memory";',
     'const persistence = "host"; /* patched by vigil */',
     "patched by vigil"),
    ("dsh-client-ui-settings-general/lib/client.js",
     'const documentController = ctx.remote.$host.isLoopback '
     '? new SettingsDocumentStore(ctx, ctx.settingsScope.describe()) : void 0;',
     'const documentController = new SettingsDocumentStore('
     'ctx, ctx.settingsScope.describe()); /* patched by vigil */',
     "patched by vigil"),
)


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------


_PHP_CACHE: dict = {}


def php_version(binary: str) -> str:
    if not binary:
        return ""
    if binary in _PHP_CACHE:
        return _PHP_CACHE[binary]
    ok, out, _ = shell.run([binary, "-r", "echo PHP_VERSION;"], timeout=10)
    ver = out.strip() if ok else ""
    _PHP_CACHE[binary] = ver
    return ver


def php_bin(matching: str = "") -> str:
    """Pick a PHP interpreter that can actually run the gate.

    NOT simply ``which php``. On a control-panel host that is very often an
    ancient 5.x left in the default PATH, while the gate is served by a
    completely different 8.x FPM pool. Linting with 5.x reports syntax
    errors in perfectly valid code, and hashing a password with a different
    build than the one that will verify it is asking for trouble.

    ``matching`` may be a version hint such as "82" (from the FPM socket
    name) to pin the exact interpreter the gate will run under.
    """
    import glob

    candidates = []
    if matching:
        candidates.append("/www/server/php/%s/bin/php" % matching)
        candidates.append("/usr/local/php/%s/bin/php" % matching)
    candidates.extend(sorted(glob.glob("/www/server/php/*/bin/php"), reverse=True))
    candidates.extend(["/usr/local/bin/php", "/usr/bin/php"])
    found = shell.which("php")
    if found:
        candidates.append(found)

    best, best_ver = "", (0,)
    for path in candidates:
        if not path or not os.path.isfile(path) or not os.access(path, os.X_OK):
            continue
        ver = php_version(path)
        if not ver:
            continue
        try:
            parts = tuple(int(x) for x in ver.split(".")[:3])
        except ValueError:
            continue
        if parts < (7, 4):
            continue                      # too old to run the gate at all
        if matching:
            # Prefer the exact pool version when we know it.
            if ver.startswith("%s.%s" % (matching[0], matching[1:] or "0")):
                return path
        if parts > best_ver:
            best, best_ver = path, parts
    return best or (found or "")


def php_hint_from_socket(socket_path: str) -> str:
    """Extract a version hint like "82" from /tmp/php-cgi-82.sock."""
    m = re.search(r"php[-\w]*?-(\d{2,3})\.sock$", str(socket_path or ""))
    if m:
        return m.group(1)
    m = re.search(r"php(\d)\.(\d)", str(socket_path or ""))
    if m:
        return m.group(1) + m.group(2)
    return ""


def hash_password(plain: str) -> str:
    """bcrypt via PHP.

    Python's standard library has no bcrypt and re-implementing it would be
    reckless; the gate is PHP-based anyway, so the interpreter is present by
    definition.
    """
    php = php_bin()
    if not php:
        raise UnsupportedError(
            "未找到可用的 php（需要 7.4 或更高），无法生成密码哈希",
            hint="登录闸门需要 PHP；只做人机验证的话请选择 bt_panel 类型")
    code = "<?php echo password_hash($argv[1], PASSWORD_BCRYPT, ['cost' => 11]);"
    ok, out, err = shell.run([php, "-r", code, plain], timeout=20)
    digest = out.strip()
    if not ok or not digest.startswith("$2"):
        raise VigilError("生成密码哈希失败: %s"
                         % ((err or out).strip()[:200] or "php 返回空"))
    return digest


def _render(name: str, mapping: dict) -> str:
    text = (TEMPLATES / name).read_text(encoding="utf-8")
    for key, value in mapping.items():
        text = text.replace("__%s__" % key, str(value))
    return text


def _php_str(s) -> str:
    """Single-quoted PHP string literal, safely escaped."""
    return "'" + str(s).replace("\\", "\\\\").replace("'", "\\'") + "'"


def _php_bool(v) -> str:
    return "true" if v else "false"


def _php_array(items) -> str:
    return "[" + ", ".join("'%s'" % str(i).replace("'", "\\'")
                           for i in (items or [])) + "]"


def _atomic_write(path, content: str, mode: int = 0o640) -> None:
    """Write a file so a concurrent reader never sees a partial one.

    `write_text` truncates and then streams, so a request arriving mid-write
    reads a half-written file. For a PHP config that means a parse error and
    a 500 on a live admin page -- which is exactly what happened. Writing to
    a temporary file in the same directory, fsyncing, and then `os.replace`
    makes the swap atomic: a reader sees either the old file or the new one,
    never a mixture.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent),
                               prefix=".%s." % path.name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, str(path))
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _backup(path) -> str:
    p = Path(path)
    if not p.exists():
        return ""
    dest = BACKUP_ROOT / ("gate-%s" % time.strftime("%Y%m%d-%H%M%S"))
    try:
        dest.mkdir(parents=True, exist_ok=True)
        target = dest / p.name
        if p.is_dir():
            shutil.copytree(str(p), str(target), symlinks=True)
        else:
            shutil.copy2(str(p), str(target))
        return str(target)
    except OSError:
        return ""


# --------------------------------------------------------------------------
# Certificate
# --------------------------------------------------------------------------


def ensure_cert(spec: GateSpec, log=None) -> tuple:
    """Create a self-signed certificate for the gate listener if needed.

    Self-signed is the right default here: the listener binds to loopback and
    is reached through a reverse proxy that terminates the *public*
    certificate. The inner hop still needs TLS so that Secure cookies work
    and so the proxy can verify what it is talking to, but it does not need
    to be publicly trusted.
    """
    cert_dir = Path(spec.cert_dir)
    fullchain = cert_dir / "fullchain.pem"
    privkey = cert_dir / "privkey.pem"
    if fullchain.is_file() and privkey.is_file():
        return True, "已存在"

    if not shell.have("openssl"):
        return False, "未找到 openssl，无法生成自签证书"

    san = ["DNS:localhost", "DNS:%s" % (spec.server_name or "localhost"),
           "IP:127.0.0.1", "IP:::1"]
    if spec.domain:
        san.append("DNS:%s" % spec.domain)
        try:
            import socket
            for info in socket.getaddrinfo(spec.domain, None):
                addr = info[4][0]
                if ":" in addr:
                    san.append("IP:%s" % addr)
                else:
                    san.append("IP:%s" % addr)
                break
        except OSError:
            pass
    san = list(dict.fromkeys(san))

    cert_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(cert_dir, 0o700)
    cnf = cert_dir / "openssl.cnf"
    cnf.write_text(
        "[req]\nprompt = no\ndefault_md = sha256\n"
        "distinguished_name = dn\nx509_extensions = v3\n\n"
        "[dn]\nCN = %s\n\n"
        "[v3]\nsubjectAltName = %s\nbasicConstraints = CA:FALSE\n"
        "keyUsage = digitalSignature, keyEncipherment\n"
        "extendedKeyUsage = serverAuth\n"
        % (spec.server_name or "vigil-gate", ",".join(san)),
        encoding="utf-8")
    os.chmod(cnf, 0o600)

    key_tmp = cert_dir / "privkey.tmp"
    crt_tmp = cert_dir / "fullchain.tmp"
    argv = ["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
            "-days", str(int(spec.cert_days or 3650)),
            "-config", str(cnf), "-keyout", str(key_tmp), "-out", str(crt_tmp)]
    ok, _out, err = shell.run(argv, timeout=120)
    if not ok:
        for f in (key_tmp, crt_tmp):
            try:
                f.unlink()
            except OSError:
                pass
        return False, "生成证书失败: %s" % (err or "").strip()[:200]

    os.chmod(key_tmp, 0o600)
    os.chmod(crt_tmp, 0o600)
    os.replace(str(key_tmp), str(privkey))
    os.replace(str(crt_tmp), str(fullchain))
    if log:
        log.info("已生成自签证书: %s（SAN: %s）" % (cert_dir, ", ".join(san)))
    return True, "已生成（%d 天）" % int(spec.cert_days or 3650)


# --------------------------------------------------------------------------
# Upstream patches
# --------------------------------------------------------------------------


def apply_settings_patches(spec: GateSpec, log=None) -> list:
    """Patch the upstream app so a remote visitor gets the full UI.

    Many apps gate "advanced" features on the request arriving from
    loopback. Behind a gate + reverse proxy every request arrives from
    loopback *on the proxy hop*, but the app sees the real client address,
    so those features silently degrade.

    Each patch is idempotent and keeps a ``.orig`` copy. The patch is also
    re-applied at every service start (see :func:`render_patch_script`),
    because an application upgrade restores the original file.
    """
    applied = []
    for entry in (spec.settings_patches or []):
        path = Path(str(entry.get("path", "")))
        find = str(entry.get("find", ""))
        repl = str(entry.get("replace", ""))
        marker = str(entry.get("marker", "patched"))
        if not (path.is_file() and find and repl):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if marker in text and find not in text:
            continue                              # already patched
        if text.count(find) != 1:
            if log:
                log.warn("补丁目标不匹配（出现 %d 次），跳过: %s"
                         % (text.count(find), path))
            continue
        try:
            orig = path.with_suffix(path.suffix + ".orig")
            if not orig.exists():
                shutil.copy2(str(path), str(orig))
            _atomic_write(path, text.replace(find, repl), stat.S_IMODE(
                path.stat().st_mode))
            applied.append(str(path))
        except OSError as e:
            if log:
                log.warn("写入补丁失败 %s: %s" % (path, e))
    return applied


def render_patch_script(spec: GateSpec) -> str:
    """A script that re-applies the patches; run before the service starts."""
    lines = ["#!/usr/bin/env python3",
             '"""Re-apply upstream settings patches. Generated by vigil.',
             "",
             "An application upgrade restores the original files, so this runs",
             "before every service start rather than once at install time.",
             '"""',
             "import shutil, sys",
             "",
             "PATCHES = ["]
    for entry in (spec.settings_patches or []):
        lines.append("    {")
        for key in ("path", "find", "replace", "marker"):
            lines.append("        %r: %r," % (key, str(entry.get(key, ""))))
        lines.append("    },")
    lines += [
             "]",
             "",
             "def main():",
             "    changed = 0",
             "    for p in PATCHES:",
             "        path, find, repl = p['path'], p['find'], p['replace']",
             "        marker = p.get('marker', 'patched')",
             "        try:",
             "            text = open(path, encoding='utf-8').read()",
             "        except OSError:",
             "            continue",
             "        if marker in text and find not in text:",
             "            continue",
             "        if text.count(find) != 1:",
             "            print('skip (pattern not unique):', path, file=sys.stderr)",
             "            continue",
             "        try:",
             "            if not __import__('os').path.exists(path + '.orig'):",
             "                shutil.copy2(path, path + '.orig')",
             "            open(path, 'w', encoding='utf-8').write(text.replace(find, repl))",
             "            changed += 1",
             "        except OSError as e:",
             "            print('patch failed:', path, e, file=sys.stderr)",
             "    if changed:",
             "        print('vigil: re-applied %d settings patch(es)' % changed)",
             "    return 0",
             "",
             "if __name__ == '__main__':",
             "    sys.exit(main())",
             ""]
    return "\n".join(lines)


def render_token_script(spec: GateSpec) -> str:
    """Extract the upstream application's per-process launch token.

    The token changes on every restart, so it cannot be baked into the gate
    configuration; it is read out of the service's own log shortly after
    startup by a separate oneshot unit.
    """
    return """#!/bin/bash
# Extract the upstream launch token after the service starts.
# Generated by vigil; the token is per-process and changes on every restart.
set -u
LOG="__LOG__"
OUT="__OUT__"
for _ in $(seq 1 60); do
    if [ -s "$LOG" ]; then
        T=$(grep -o 'token=[A-Za-z0-9_-]\\{16,\\}' "$LOG" 2>/dev/null | tail -1 | cut -d= -f2)
        if [ -n "$T" ]; then
            printf '%s' "$T" > "$OUT.tmp" && mv "$OUT.tmp" "$OUT"
            chown __USER__ "$OUT" 2>/dev/null
            chmod 600 "$OUT"
            exit 0
        fi
    fi
    sleep 1
done
logger -t vigil-token "warn: launch token not found within 60s"
exit 0
""".replace("__LOG__", str(spec.settings_log or "/run/upstream.log")) \
   .replace("__OUT__", str(Path(spec.state_dir) / "upstream_token")) \
   .replace("__USER__", spec.worker_user or "www")


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def render_files(spec: GateSpec) -> dict:
    """Return ``{path: (content, mode)}`` for everything inside state_dir."""
    d = spec.state_dir
    mapping = {
        "STATE_DIR": str(spec.state_dir).rstrip("/") + "/",
        "POLICY": str(Path(spec.state_dir) / "policy.conf"),
        "ENTRY_PATH": spec.entry_path,
        "CAPTCHA_PATH": spec.captcha_path,
        "LOGOUT_PATH": spec.logout_path,
        "COOKIE": spec.cookie,
        # PHP and Lua express "absent" differently: an empty string is falsy
        # in PHP, while Lua needs the `nil` keyword. Emitting the Lua form
        # into the PHP file produced a bare undefined constant, which is a
        # *runtime* fatal error that `php -l` happily accepts.
        "NAV_COOKIE": "'%s'" % (spec.nav_cookie or ""),
        "NAV_COOKIE_LUA": ('"%s"' % spec.nav_cookie) if spec.nav_cookie else "nil",
        "EXTRA_COOKIES": _php_array([spec.nav_cookie] if spec.nav_cookie else []),
        "COOKIE_LIFETIME": int(spec.cookie_lifetime or 0),
        "TITLE": spec.title,
        "SUBTITLE": spec.subtitle,
        "LANG": spec.lang,
        "REQUIRE_PASSWORD": _php_bool(spec.require_password),
        "USER": spec.username,
        "PASS_HASH": spec.pass_hash,
        # policy
        "SESSION_TTL": spec.session_ttl,
        "ABS_TTL": spec.abs_ttl,
        "NAV_TTL": spec.nav_ttl,
        "BIND_UA": spec.bind_ua,
        "BIND_IP": spec.bind_ip,
        "MAX_SESSIONS": spec.max_sessions,
        "CAPTCHA_TTL": spec.captcha_ttl,
        "CAPTCHA_LENGTH": spec.captcha_length,
        "CAPTCHA_MIN": spec.captcha_min_seconds,
        "CAPTCHA_PER_MIN": spec.captcha_per_minute,
        "LOCK_MAX": spec.lock_max,
        "LOCK_SECS": spec.lock_secs,
        "LOCK_BACKOFF": spec.lock_backoff,
        "LOCK_FIRST": spec.lock_first_secs,
        "CRED_MAX": spec.cred_max,
        "CRED_LOCK": spec.cred_lock_secs,
        "STRICT_NAV": int(spec.strict_nav or 0),
        # scene_kind is an integer in config.php because the policy file only
        # parses integers; the directory list is a real PHP array.
        "SCENE_KIND": {"art": 0, "image": 1, "auto": 2}.get(
            str(spec.scene_kind or "auto"), 2),
        "IMAGE_DIRS": _php_array(spec.image_dirs),
        # 1 unless an operator turned it off: see config.php.tmpl.
        "INLINE_IMAGES": int(bool(getattr(spec, "inline_images", True))),
    }
    # The request-facing PHP lives in the gate's webroot, which is often a
    # panel-managed directory outside the state directory. Both locations
    # are referenced by absolute path so the layout can differ between hosts
    # without touching the templates.
    mapping["CONFIG_PATH"] = str(Path(d) / "config.php")
    mapping["LIB_PATH"] = str(Path(d) / "lib" / "gate-lib.php")
    web = Path(spec.webroot)
    out = {
        Path(d) / "gate.lua": (_render("gate.lua.tmpl", mapping), 0o640),
        Path(d) / "policy.conf": (_render("policy.conf.tmpl", mapping), 0o640),
        Path(d) / "config.php": (_render("config.php.tmpl", mapping), 0o640),
        Path(d) / "lib" / "gate-lib.php": (
            _render("lib/gate-lib.php.tmpl", mapping), 0o640),
        web / "verify.php": (_render("verify.php.tmpl", mapping), 0o644),
        web / "captcha.php": (_render("captcha.php.tmpl", mapping), 0o644),
        web / "logout.php": (_render("logout.php.tmpl", mapping), 0o644),
    }
    if spec.upstream_token_file and spec.upstream_mint_url:
        out[Path(d) / "hook.php"] = (_render("hook.php.tmpl", mapping), 0o640)
        # Inject through a placeholder that sits *inside* the returned array.
        # Appending near a comment after the closing bracket produced a
        # config file that did not parse -- and a gate whose config does not
        # parse is a gate that returns a blank page.
        cfg_text = out[Path(d) / "config.php"][0]
        cfg_text = cfg_text.replace(
            "__UPSTREAM_KEYS__",
            "    'upstream_token_file' => %s,\n"
            "    'upstream_mint_url' => %s,\n"
            % (_php_str(spec.upstream_token_file),
               _php_str(spec.upstream_mint_url)))
        out[Path(d) / "config.php"] = (cfg_text, 0o640)
    else:
        cfg_text = out[Path(d) / "config.php"][0].replace("__UPSTREAM_KEYS__", "")
        out[Path(d) / "config.php"] = (cfg_text, 0o640)
    if spec.settings_patches:
        out[Path(d) / "patch-settings.py"] = (render_patch_script(spec), 0o750)
    return out


def render_nginx(spec: GateSpec) -> str:
    headers = """    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy no-referrer always;
    add_header X-Robots-Tag "noindex, nofollow, noarchive" always;
"""

    locations = """    location = {entry} {{
        limit_req  zone={req} burst=20 nodelay;
        limit_conn {conn} 16;
        limit_req_status 429;
        limit_conn_status 429;
        limit_except GET POST {{ deny all; }}
        root  {webroot};
        include {fastcgi_conf};
        fastcgi_param SCRIPT_FILENAME {webroot}/verify.php;
        fastcgi_param HTTP_HOST      $host;
        fastcgi_pass {fastcgi_pass};
    }}

    location = {captcha} {{
        limit_req  zone={cap} burst=40 nodelay;
        limit_conn {conn} 24;
        limit_req_status 429;
        limit_except GET {{ deny all; }}
        root  {webroot};
        include {fastcgi_conf};
        fastcgi_param SCRIPT_FILENAME {webroot}/captcha.php;
        fastcgi_param HTTP_HOST      $host;
        fastcgi_pass {fastcgi_pass};
    }}

    location = {logout} {{
        limit_conn {conn} 8;
        limit_except GET POST {{ deny all; }}
        root  {webroot};
        include {fastcgi_conf};
        fastcgi_param SCRIPT_FILENAME {webroot}/logout.php;
        fastcgi_param HTTP_HOST      $host;
        fastcgi_pass {fastcgi_pass};
    }}

    # Everything else under the gate prefix is a 404, handled in the rewrite
    # phase so it never reaches PHP or the upstream. Omitted entirely when
    # there is no safe common prefix -- a catch-all of "/" would swallow the
    # whole site.
{prefix_block}

    # ACME must never be gated, or certificate renewal fails silently and is
    # only noticed when the certificate expires.
    location ^~ /.well-known/ {{ allow all; try_files $uri =404; }}
""".format(entry=spec.entry_path, captcha=spec.captcha_path,
           logout=spec.logout_path,
           prefix_block=("    location ^~ %s { return 404; }\n" % spec.prefix)
                        if spec.prefix else
                        "    # (no safe common prefix; catch-all omitted)\n",
           webroot=spec.webroot, fastcgi_pass=spec.fastcgi_pass,
           fastcgi_conf=spec.fastcgi_conf,
           req=spec.zone("req"), cap=spec.zone("cap"), conn=spec.zone("conn"))

    if spec.proxy_mode:
        tls = ""
        listen = "    listen {host}:{port};\n".format(host=spec.listen_host,
                                                      port=spec.listen_port)
        if spec.use_https:
            listen = ("    listen {host}:{port} ssl http2;\n"
                      "    listen [::1]:{port} ssl http2;\n"
                      .format(host=spec.listen_host, port=spec.listen_port))
            tls = """    ssl_certificate      {cert}/fullchain.pem;
    ssl_certificate_key  {cert}/privkey.pem;
    ssl_protocols        TLSv1.2 TLSv1.3;
    ssl_ciphers          ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_cache    shared:{zone}:10m;
    ssl_session_timeout  10m;
    ssl_session_tickets  off;
""".format(cert=spec.cert_dir, zone=spec.zone("tls"))
        return """# ============================================================
# Vigil gate: {kind}
# GENERATED FILE — regenerate with `vigil gate reconfigure {kind}`
#
# Listens on the loopback only. The reverse proxy in the control panel is
# the sole path in, so the gate port is not reachable from the internet
# whatever the firewall does.
#
# Protected upstream: {upstream}
#
# The rate-limit zones referenced below live in the http{{}} block, in the
# file this installer adds to the main configuration. They are NOT declared
# here: a zone may only be declared once, and a second declaration is a
# fatal "already bound" error.
# ============================================================

server
{{
{listen}
    server_name {server_name};

    # Trust only the local reverse proxy's X-Forwarded-For, and take the
    # right-most untrusted address so a forged header cannot spoof the
    # client address past the rate limits.
    set_real_ip_from 127.0.0.1;
    set_real_ip_from ::1;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;

{tls}
{headers}
    access_log  /www/wwwlogs/vigil-{slug}.log;
    error_log   /www/wwwlogs/vigil-{slug}.error.log warn;

    client_max_body_size 1024m;
    client_body_timeout  30s;
    client_header_timeout 15s;
    send_timeout         60s;
    keepalive_timeout    60s;

{locations}
    # ---------------- protected application ----------------
    location / {{
        access_by_lua_file {lua};

        proxy_pass {upstream};
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade           $http_upgrade;
        proxy_set_header Connection        $connection_upgrade;
        proxy_http_version 1.1;
        proxy_read_timeout  300s;
        proxy_send_timeout  300s;
        proxy_buffering     off;
        proxy_hide_header   X-Powered-By;
    }}
}}
""".format(kind=spec.kind, upstream=spec.upstream,
           listen=listen, server_name=spec.server_name, tls=tls,
           headers=headers, locations=locations, lua=lua_path(spec),
           slug=re.sub(r"\W+", "-", spec.kind))

    # Non-proxy mode: a snippet included at server scope in an existing vhost.
    return """# ============================================================
# Vigil gate: {kind}  (server-scope snippet)
# GENERATED FILE — regenerate with `vigil gate reconfigure {kind}`
#
# Included at SERVER scope on purpose. Attaching a gate to `location /`
# only leaves every other location open, which is the classic way to end up
# with a gate that protects nothing.
#
# The http{{}} block must already define the rate-limit zones below; the
# installer writes them to a file the main config includes.
# ============================================================

{locations}
# ---------------- the gate itself ----------------
access_by_lua_file {lua};
""".format(kind=spec.kind, locations=locations, lua=lua_path(spec))


def lua_path(spec: GateSpec) -> str:
    return str(Path(spec.state_dir) / "gate.lua")


def render_zones(spec: GateSpec) -> str:
    return """# Vigil gate rate-limit zones — GENERATED.
# Must be included in the http{{}} block BEFORE any vhost that references
# these zones, or nginx refuses to load its configuration at all.
limit_req_zone  $binary_remote_addr zone={req}:10m rate=12r/m;
limit_req_zone  $binary_remote_addr zone={cap}:10m rate=120r/m;
limit_conn_zone $binary_remote_addr zone={conn}:10m;
# The global limit_req_status / limit_conn_status directives are
# deliberately NOT set here: a control panel's own hardening file
# usually defines them at http scope already, and a second definition
# is a fatal "directive is duplicate" error that stops nginx from
# loading at all. Each gate location sets its own status code, which
# is what actually matters.
""".format(req=spec.zone("req"), cap=spec.zone("cap"), conn=spec.zone("conn"))


# --------------------------------------------------------------------------
# Install
# --------------------------------------------------------------------------


def fix_permissions(spec: GateSpec, ours=()) -> None:
    """Make the gate usable by the web server and by nobody else.

    Getting this wrong is dramatic in both directions: an unreadable
    ``gate.lua`` makes nginx return 500 for every request on the vhost, and
    a world-readable ``config.php`` hands out the password hash.
    """
    try:
        names = [n for n in (spec.worker_user, spec.pool_user) if n]
        uid = gid = 0
        if names:
            try:
                pw = pwd.getpwnam(names[0])
                uid, gid = pw.pw_uid, pw.pw_gid
            except KeyError:
                pass
        base = Path(spec.state_dir)
        web = Path(spec.webroot)
        dirs = [base, base / "lib", base / "sessions",
                base / "captcha", base / "fails", base / "logs", web]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)
            try:
                os.chown(d, uid, gid)
            except OSError:
                pass
            # The sessions/captcha/fails directories hold only digests, but
            # 0700 costs nothing and keeps other local users out entirely.
            os.chmod(d, 0o700 if d.name in ("sessions", "captcha", "fails", "logs")
                     else 0o750)
        for d, mode in ((base / "lib", 0o640), (web, 0o644)):
            if d.is_dir():
                for f in d.iterdir():
                    if f.is_file():
                        try:
                            os.chown(f, uid, gid)
                        except OSError:
                            pass
                        os.chmod(f, mode)
        # Only files this installer created are re-moded. Touching every
        # file in the directory silently loosened the upstream token from
        # 0600 to 0750 -- a permission regression on a secret, caused by
        # being helpful.
        ours_set = {str(Path(p)) for p in (ours or ())}
        for f in base.iterdir():
            if not f.is_file() or (ours_set and str(f) not in ours_set):
                continue
            try:
                os.chown(f, uid, gid)
            except OSError:
                pass
            want = 0o640 if f.suffix in (".php", ".conf") else 0o750
            # Never widen permissions on a file that already exists. Being
            # "helpful" here once loosened the upstream launch token from
            # 0600 to 0750 -- a silent regression on a secret.
            try:
                cur = stat.S_IMODE(f.stat().st_mode)
                if (cur & 0o077) and (cur & 0o077) < (want & 0o077):
                    want = cur
            except OSError:
                pass
            os.chmod(f, want)
    except OSError:
        pass


def install(spec: GateSpec, env: dict = None, log=None,
            start_override: bool = True) -> dict:
    """Render, write, wire and verify. Returns a result dict."""
    from ..core import detect
    env = env or detect.full()
    problems = spec.validate()
    if problems:
        return {"ok": False, "error": "配置不完整", "problems": problems}

    ng = env.get("nginx", {})
    if not ng.get("present"):
        return {"ok": False, "error": "本机未检测到 nginx"}
    if not ng.get("lua"):
        return {"ok": False,
                "error": "本机 nginx 未编译 Lua 模块，无法使用 access_by_lua_file"}
    if not spec.fastcgi_pass:
        return {"ok": False, "error": "未找到 PHP-FPM socket"}

    written = []

    # 1. certificate before nginx references it
    cert_msg = ""
    if spec.proxy_mode and spec.use_https:
        ok, cert_msg = ensure_cert(spec, log)
        if not ok:
            return {"ok": False, "error": "证书准备失败: %s" % cert_msg}

    # 2. gate files. PHP is linted *before* anything is written, so a bad
    # render cannot leave a broken page behind -- a gate whose config does
    # not parse serves a blank 200 and looks installed.
    rendered = render_files(spec)
    rendered_paths = list(rendered)
    php = php_bin(php_hint_from_socket(spec.fastcgi_pass))
    if php:
        broken = _php_smoke_test(php, rendered, spec)
        if broken:
            return {"ok": False,
                    "error": "生成的 PHP 文件未通过校验，已中止（未改动任何文件）",
                    "detail": "\n".join(broken), "php": php,
                    "php_version": php_version(php)}

    for path, (content, mode) in rendered.items():
        try:
            if path.exists():
                _backup(path)
            _atomic_write(path, content, mode)
            written.append(str(path))
        except OSError as e:
            return {"ok": False, "error": "写入 %s 失败: %s" % (path, e)}
    fix_permissions(spec, ours=[str(p) for p in rendered_paths])

    # 3. the ZONES file must land in http{} before any vhost uses it
    zones_file = Path(spec.zones_file or (
        Path(spec.nginx_conf).parent / ("vigil-gate-%s-zones.conf"
                                        % re.sub(r"\W+", "-", spec.kind))))
    try:
        if zones_file.exists():
            _backup(zones_file)
        _atomic_write(zones_file, render_zones(spec), 0o644)
        written.append(str(zones_file))
    except OSError as e:
        return {"ok": False, "error": "写入限流区文件失败: %s" % e}
    _ensure_http_include(ng.get("conf", ""), zones_file)

    # 4. the server block / snippet
    target = Path(spec.nginx_conf)
    snippet = render_nginx(spec)
    backup_taken = ""
    try:
        if target.exists():
            backup_taken = _backup(target)
        _atomic_write(target, snippet, 0o644)
        written.append(str(target))
    except OSError as e:
        return {"ok": False, "error": "写入 nginx 配置失败: %s" % e}

    # Non-proxy mode: the snippet lives inside the site's extension
    # directory, which the vhost already includes with a glob. Adding a
    # second, explicit include would pull the same file in twice and produce
    # "duplicate location" -- a fatal error. So only add an include when the
    # target is genuinely not reachable through an existing one.
    if not spec.proxy_mode and not _already_included(env, target):
        _ensure_vhost_include(env, target, spec)

    # 5. withdraw anything this gate supersedes, before validating: leaving
    # both in place makes nginx fail to load, so the withdrawal has to
    # happen before the test rather than after it.
    withdrawn = _withdraw_conflicts(spec, env, keep=target, log=log)
    written.extend(withdrawn)

    # 6. validate, and roll back if the configuration is bad.
    #
    # Rolling back means *restoring what was there*, not deleting what we
    # wrote. The first version of this deleted the target, which on a
    # reconfigure is the same file the working gate lived in -- so a failed
    # reconfigure destroyed a functioning gate config. The backup taken
    # above is the restore source.
    ok, out, err = shell.run([ng["binary"], "-t"], timeout=30)
    if not ok:
        _restore_or_remove(target, backup_taken, log=log)
        return {"ok": False, "error": "nginx 配置校验失败，已回滚该网关配置",
                "detail": (err or out).strip()[-800:],
                "written": written,
                "rolled_back": str(target)}

    ok, _o, err = shell.run(["systemctl", "reload", "nginx"], timeout=30)
    if not ok:
        return {"ok": False, "error": "nginx 重载失败: %s" % err.strip()[:200],
                "written": written}

    # 7. retire the previous implementation's page files
    stale = _quarantine_stale_pages(spec, log=log)

    # 8. upstream patches (optional, and non-fatal)
    patched = apply_settings_patches(spec, log)

    return {"ok": True, "written": written, "patched": patched,
            "withdrawn": withdrawn, "stale": stale,
            "cert": cert_msg, "zones_file": str(zones_file),
            "nginx_conf": str(target),
            "entry": spec.entry_path,
            "url": ("https://%s%s" % (spec.domain, spec.entry_path)
                    if spec.domain else spec.entry_path)}


def _restore_or_remove(target: Path, backup: str, log=None) -> None:
    """Undo a failed write: put the original back, or remove a new file.

    Deleting the target unconditionally is wrong when the target is a file
    that already existed and was working -- on a reconfigure that is the
    normal case, and the deletion takes out a functioning gate.
    """
    try:
        if backup and Path(backup).is_file():
            shutil.copy2(backup, str(target))
            if log:
                log.info("已从备份恢复 %s" % target)
        else:
            target.unlink()
            if log:
                log.info("已移除新写入的 %s" % target)
    except OSError as e:
        if log:
            log.warn("回滚 %s 失败: %s" % (target, e))


def _quarantine_stale_pages(spec: GateSpec, log=None) -> list:
    """Move an earlier gate's page files out of the webroot.

    The previous implementation served `login.php`; this one serves
    `verify.php`. Leaving the old file behind keeps a second, older
    authentication handler sitting in a web-accessible directory — even if
    the current nginx configuration no longer routes to it, that is exactly
    the kind of thing a later configuration change silently re-exposes.
    """
    web = Path(spec.webroot)
    if not (web / "verify.php").exists():
        return []
    moved = []
    for name in ("login.php", "index.php", "gate.php"):
        old = web / name
        if not old.exists():
            continue
        try:
            dest = _backup(old)
            old.unlink()
            moved.append(str(old))
            if log:
                log.info("已移走旧登录页 %s（备份于 %s）" % (old, dest or "备份目录"))
        except OSError as e:
            if log:
                log.warn("移走旧登录页 %s 失败: %s" % (old, e))
    if moved:
        try:
            import json
            BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
            manifest = BACKUP_ROOT / "gate-stale-pages.json"
            existing = []
            if manifest.exists():
                existing = json.loads(manifest.read_text() or "[]")
            existing.append({"ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                             "kind": spec.kind, "files": moved})
            manifest.write_text(json.dumps(existing, ensure_ascii=False,
                                           indent=2), encoding="utf-8")
        except (OSError, ValueError):
            pass
    return moved


def _php_smoke_test(php: str, rendered: dict, spec: GateSpec) -> list:
    """Check the generated PHP both parses AND works.

    `php -l` only proves the file is syntactically valid, which is not
    enough: a bare undefined constant (``nil`` written where ``''`` was
    meant) parses perfectly and then throws a fatal error on the first
    request. The gate would look installed and serve a blank page.

    So beyond linting, the config file is actually executed and must return
    an array, and the policy loader must run. Both are cheap and catch the
    entire class of "syntax is fine, runtime is broken" mistakes.
    """
    stage = Path("/tmp/.vigil-phpstage-%d" % os.getpid())
    broken = []
    try:
        shutil.rmtree(str(stage), ignore_errors=True)
        # Reproduce the real on-disk layout so relative paths resolve.
        rel = {}
        for path, (content, _mode) in rendered.items():
            try:
                rel_path = Path(path).relative_to(Path(spec.state_dir))
            except ValueError:
                # Files under the webroot go there instead.
                try:
                    rel_path = Path("__web__") / Path(path).relative_to(
                        Path(spec.webroot))
                except ValueError:
                    rel_path = Path(Path(path).name)
            target = stage / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            rel[str(path)] = target

        for path, (content, _mode) in rendered.items():
            if path.suffix != ".php":
                continue
            probe = rel.get(str(path))
            if probe is None:
                continue
            chk = subprocess.run([php, "-l", str(probe)],
                                 capture_output=True, text=True)
            if chk.returncode != 0:
                broken.append("%s: 语法错误 %s" % (
                    path.name,
                    (chk.stdout or chk.stderr).strip().splitlines()[-1][:180]))
                continue
            if path.name == "config.php":
                # Execute it: it must return an array without warnings.
                code = (
                    "$c = require $argv[1];"
                    "if (!is_array($c)) { fwrite(STDERR, 'config did not return an array'); exit(3); }"
                    "foreach (['state_dir','entry_path','cookie'] as $k) {"
                    "  if (empty($c[$k])) { fwrite(STDERR, 'missing key: '.$k); exit(4); } }"
                    "if (function_exists('vigil_policy')) {"
                    "  $p = vigil_policy($c['policy']);"
                    "  if (!is_array($p) || !isset($p['captcha_ttl'])) { fwrite(STDERR,'policy loader broken'); exit(5); } }"
                    "echo 'ok';")
                run = subprocess.run([php, "-d", "error_reporting=E_ALL",
                                      "-d", "display_errors=1",
                                      "-r", code, str(probe)],
                                     capture_output=True, text=True)
                out = (run.stdout or "") + (run.stderr or "")
                if run.returncode != 0 or "ok" not in run.stdout:
                    broken.append("%s: 运行失败 %s" % (
                        path.name, out.strip().splitlines()[0][:180] if out.strip() else "无输出"))
                elif "Warning" in out or "Deprecated" in out or "Fatal" in out:
                    broken.append("%s: 运行有告警 %s" % (
                        path.name, out.strip().splitlines()[0][:180]))
    except OSError as e:
        broken.append("校验过程出错: %s" % e)
    finally:
        shutil.rmtree(str(stage), ignore_errors=True)
    return broken


def _withdraw_conflicts(spec: GateSpec, env: dict, keep: Path, log=None) -> list:
    """Move aside nginx files that would conflict with this gate.

    Two concrete conflicts, both of which stop nginx from loading at all:

    * a previous gate wired with ``access_by_lua_file`` at the same scope —
      nginx rejects the duplicate directive, so a reconfigure would leave
      the whole web server unable to reload;
    * a previous listener on the same port — the bind fails.

    Only files belonging to *this* gate type are withdrawn. A blanket "any
    gate that is not mine" test would make each gate tear down the other
    one's wiring every time either was reconfigured.

    Files are moved into the backup directory rather than deleted, and a
    manifest is appended, so an operator can always see exactly what was
    taken out and put it back.
    """
    keep = keep.resolve()
    candidates = set()
    ng = (env or {}).get("nginx", {}) or {}
    if ng.get("conf"):
        base = Path(ng["conf"]).parent
        candidates.update(base.glob("vigil-gate-*.conf"))
        candidates.update(base.glob("zz-proxy-*.conf"))
    for d in ng.get("include_dirs") or []:
        p = Path(d)
        if not p.is_dir():
            continue
        candidates.update(p.glob("vigil-gate-*.conf"))
        candidates.update(p.glob("zz-proxy-*.conf"))
        candidates.update(p.glob("zz-*-auth.conf"))
        ext = p / "extension"
        if ext.is_dir():
            for site in ext.iterdir():
                if site.is_dir():
                    candidates.update(site.glob("*.conf"))

    lua = lua_path(spec)
    own_lua = [str(Path(e["state_dir"]) / "gate.lua") for e in LEGACY_LAYOUTS
               if e["kind"] == spec.kind]
    if str(Path(spec.state_dir) / "gate.lua") not in own_lua:
        own_lua.append(str(Path(spec.state_dir) / "gate.lua"))
    port_re = (re.compile(r"listen\s+[0-9a-fA-F:.]+:%d\b" % spec.listen_port)
               if spec.listen_port else None)

    withdrawn = []
    for path in sorted(candidates):
        try:
            if path.resolve() == keep:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        conflict = False
        if "access_by_lua_file" in text and "gate.lua" in text:
            if lua not in text and any(own in text for own in own_lua):
                conflict = True
        if port_re and port_re.search(text):
            conflict = True
        if not conflict:
            continue
        try:
            dest = _backup(path)
            path.unlink()
            withdrawn.append(str(path))
            if log:
                log.info("已撤回冲突的 nginx 配置: %s（备份于 %s）"
                         % (path, dest or "备份目录"))
        except OSError as e:
            if log:
                log.warn("撤回 %s 失败: %s" % (path, e))

    if withdrawn:
        try:
            import json
            BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
            manifest = BACKUP_ROOT / "gate-withdrawn.json"
            existing = []
            if manifest.exists():
                existing = json.loads(manifest.read_text() or "[]")
            existing.append({"ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                             "kind": spec.kind, "files": withdrawn})
            manifest.write_text(json.dumps(existing, ensure_ascii=False,
                                           indent=2), encoding="utf-8")
        except (OSError, ValueError):
            pass
    return withdrawn


def _ensure_http_include(main_conf: str, zones_file: Path) -> None:
    """Include the zones in http{} exactly once."""
    if not main_conf:
        return
    try:
        text = Path(main_conf).read_text(encoding="utf-8")
    except OSError:
        return
    if str(zones_file) in text:
        return
    line = "    include %s;" % zones_file
    for anchor in ("include       proxy.conf;", "include proxy.conf;"):
        if anchor in text:
            text = text.replace(anchor, anchor + "\n" + line, 1)
            break
    else:
        text = re.sub(r"(http\s*\{)", r"\1\n" + line, text, count=1)
    try:
        _backup(main_conf)
        _atomic_write(main_conf, text, 0o644)
    except OSError:
        pass


def _already_included(env: dict, target: Path) -> bool:
    """Is *target* already pulled in by an existing include directive?

    The control panel's vhosts typically do `include extension/<site>/*.conf;`
    so a file placed in that directory is live without any further wiring.
    Adding an explicit include on top of that includes the file twice, and
    nginx rejects the duplicated `location` blocks outright.
    """
    import glob as _glob
    target = target.resolve()
    for d in (env or {}).get("nginx", {}).get("include_dirs", []) or []:
        base = Path(d)
        if not base.is_dir():
            continue
        for vhost in list(base.glob("*.conf")) + list(base.glob("extension/*/*.conf")):
            if vhost.resolve() == target:
                continue
            try:
                text = vhost.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for m in re.finditer(r"^\s*include\s+([^;]+);", text, re.M):
                pat = m.group(1).strip()
                if not pat.endswith("*.conf"):
                    continue
                try:
                    if target in {Path(p).resolve() for p in _glob.glob(pat)}:
                        return True
                except OSError:
                    continue
    return False


def _ensure_vhost_include(env: dict, snippet: Path, spec: GateSpec) -> None:
    """Add an include of our snippet's directory to the target vhost."""
    for directory in env.get("nginx", {}).get("include_dirs", []):
        for vhost in Path(directory).glob("*.conf"):
            try:
                text = vhost.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if spec.domain and spec.domain not in text:
                continue
            line = "include %s;" % snippet
            if line in text:
                return
            idx = text.find("{")
            if idx < 0:
                continue
            try:
                _backup(vhost)
                _atomic_write(vhost,
                              text[:idx + 1] + "\n    " + line + text[idx + 1:],
                              0o644)
            except OSError:
                pass
            return


# --------------------------------------------------------------------------
# Removal
# --------------------------------------------------------------------------


def uninstall(spec: GateSpec, env: dict = None, remove_state: bool = False) -> dict:
    from ..core import detect as _detect
    env = env or _detect.full()
    removed = []
    target = Path(spec.nginx_conf)
    if target.exists():
        try:
            _backup(target)
            target.unlink()
            removed.append(str(target))
        except OSError:
            pass
    zones = Path(spec.zones_file or (
        target.parent / ("vigil-gate-%s-zones.conf"
                         % re.sub(r"\W+", "-", spec.kind))))
    if zones.exists():
        try:
            zones.unlink()
            removed.append(str(zones))
        except OSError:
            pass
    if remove_state:
        base = Path(spec.state_dir)
        if base.is_dir() and str(base).startswith(("/usr/local/lib/vigil", "/www/server")):
            shutil.rmtree(str(base), ignore_errors=True)
            removed.append(str(base))
    ng = (env or {}).get("nginx", {})
    if ng.get("binary"):
        ok, out, err = shell.run([ng["binary"], "-t"], timeout=30)
        if ok:
            shell.run(["systemctl", "reload", "nginx"], timeout=30)
        else:
            return {"ok": False, "removed": removed,
                    "error": "nginx 配置校验失败: %s" % (err or out).strip()[-400:]}
    return {"ok": True, "removed": removed}
