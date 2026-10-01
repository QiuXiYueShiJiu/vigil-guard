"""Login gates: detection, adoption, installation.

Two gate types are supported and both are strictly optional:

``bt_panel``
    Human verification in front of a control panel. Holds no credentials —
    the panel keeps its own login, so this layer only makes automated
    credential stuffing and scanning expensive.

``login``
    A full sign-in gate: CAPTCHA plus username/password (bcrypt), in front
    of anything that should not be directly exposed. Designed for the case
    where a service listens on loopback and needs to be reachable from the
    internet without being *published* to it.

**Adoption is as important as installation.** A host that already has a
working gate must not have it reinstalled: that destroys live sessions and,
if the password is only stored as a hash, locks the operator out
permanently. So detection runs first and :func:`adopt` records the existing
layout without writing a single byte to it.
"""
from __future__ import annotations

import glob
import os
import re
from pathlib import Path

from ..core import detect, shell
from ..core.errors import VigilError
from . import installer
from .spec import KIND_BT, KIND_LOGIN, KIND_META, GateSpec

__all__ = [
    "KIND_BT", "KIND_LOGIN", "KIND_META", "GateSpec",
    "detect_all", "detect_one", "adopt", "status", "install", "uninstall",
    "reconfigure", "hash_password",
]

#: Layouts produced by earlier versions of this tool, or configured by hand.
#: Each is still fully readable, so an existing installation can be adopted
#: rather than replaced.
LEGACY_LAYOUTS = (
    {
        "kind": KIND_BT,
        "state_dir": "/www/server/bt-gate",
        "webroot": "/www/wwwroot/bt-gate",
        "entry": "/__btgate",
        "cookie": "btgate",
    },
    {
        "kind": KIND_LOGIN,
        "state_dir": "/www/server/dsh-gate",
        "webroot": "/www/wwwroot/dsh-gate",
        "entry": "/__gate/login",
        "cookie": "dshgate",
        "nav_cookie": "dshnav",
    },
)


# --------------------------------------------------------------------------
# Parsing helpers
# --------------------------------------------------------------------------


def parse_policy(path) -> dict:
    out = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = re.match(r"\s*([a-z_]+)\s*=\s*(\d+)", line)
                if m:
                    out[m.group(1)] = int(m.group(2))
    except OSError:
        pass
    return out


def parse_php_config(path) -> dict:
    """Pull scalar keys out of a PHP config file without executing it.

    Executing a file we do not own — possibly written by another project —
    would be both unsafe and slow; a regex over a known shape is enough.
    """
    out = {}
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for key in ("state_dir", "policy", "cookie", "entry_path", "captcha",
                "logout", "title", "subtitle", "lang", "user", "pass_hash",
                "nav_cookie", "upstream_token_file", "upstream_mint_url"):
        m = re.search(r"['\"]%s['\"]\s*=>\s*['\"]([^'\"]*)['\"]" % key, text)
        if m:
            out[key] = m.group(1)
    m = re.search(r"['\"]require_password['\"]\s*=>\s*(true|false)", text, re.I)
    if m:
        out["require_password"] = m.group(1).lower() == "true"
    # The picture settings are not strings, and leaving them out here is how a
    # plain `vigil gate reconfigure` silently emptied the operator's image
    # library: the live file was never read back, so the re-render used the
    # empty defaults.
    m = re.search(r"['\"]scene_kind['\"]\s*=>\s*(\d+)", text)
    if m:
        out["scene_kind"] = int(m.group(1))
    m = re.search(r"['\"]image_dirs['\"]\s*=>\s*(\[[^\]]*\])", text, re.S)
    if m:
        out["image_dirs"] = re.findall(r"['\"]([^'\"]*)['\"]", m.group(1))
    return out


def parse_listen(conf_text: str) -> dict:
    """Extract listener, TLS and upstream facts from an nginx config."""
    out = {"port": 0, "host": "", "https": False, "upstream": "",
           "server_name": "", "cert_dir": "", "domain": ""}
    if not conf_text:
        return out
    m = re.search(r"listen\s+([0-9a-fA-F:.]+):(\d+)([^;]*);", conf_text)
    if m:
        out["host"] = m.group(1)
        out["port"] = int(m.group(2))
        out["https"] = "ssl" in m.group(3)
    m = re.search(r"proxy_pass\s+(https?://[^\s;]+);", conf_text)
    if m:
        out["upstream"] = m.group(1)
    m = re.search(r"server_name\s+([^;]+);", conf_text)
    if m:
        out["server_name"] = m.group(1).strip()
        if out["server_name"] not in ("_", ""):
            out["domain"] = out["server_name"]
    m = re.search(r"ssl_certificate\s+(\S+)/fullchain\.pem", conf_text)
    if m:
        out["cert_dir"] = m.group(1)
        out["https"] = True
    return out


def nginx_text(env=None) -> str:
    env = env or detect.nginx()
    binary = env.get("binary") or ""
    if not binary:
        return ""
    ok, out, _ = shell.run([binary, "-T"], timeout=30)
    return out if ok else ""


def _find_gate_nginx_conf(kind: str, env, conf_text: str) -> tuple:
    """Locate the nginx file that owns this gate, and its text.

    Checked in order of specificity: our own generated file, then whatever
    the current installation used, then a scan of the effective config for
    the Lua reference.
    """
    state_dir = None
    for legacy in LEGACY_LAYOUTS:
        if legacy["kind"] == kind:
            state_dir = Path(legacy["state_dir"])
            break
    lua = str((state_dir or Path("/nonexistent")) / "gate.lua")
    ours = Path("/usr/local/lib/vigil/gate") / kind / "gate.lua"

    candidates = []
    ng_conf = env.get("nginx", {}).get("conf", "")
    if ng_conf:
        base = Path(ng_conf).parent
        candidates.extend(sorted(base.glob("vigil-gate-*.conf")))
        candidates.extend(sorted(base.glob("zz-proxy-*.conf")))
    for vhost_dir in env.get("nginx", {}).get("include_dirs", []):
        d = Path(vhost_dir)
        if not d.is_dir():
            continue
        candidates.extend(sorted(d.glob("zz-proxy-*.conf")))
        candidates.extend(sorted(d.glob("zz-*-auth.conf")))
        ext = d / "extension"
        if ext.is_dir():
            candidates.extend(sorted(ext.glob("*/*.conf")))

    for path in candidates:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "access_by_lua_file" not in text:
            continue
        if lua in text or str(ours) in text or kind.replace("_", "-") in path.name:
            return str(path), text
    return "", ""


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------


def detect_one(kind: str, env=None, conf_text: str = "") -> GateSpec:
    """Reconstruct the spec of an installed gate, or a blank one."""
    env = env or detect.full()
    spec = GateSpec.for_kind(kind, cfg=None, env=env)

    legacy = next((l for l in LEGACY_LAYOUTS if l["kind"] == kind), None)
    if not legacy:
        return spec

    state_dir = Path(legacy["state_dir"])
    if not state_dir.is_dir():
        ours = Path("/usr/local/lib/vigil/gate") / kind
        if not ours.is_dir():
            return spec
        state_dir = ours
        legacy = dict(legacy, state_dir=str(ours), webroot=str(ours / "web"))

    spec.state_dir = str(state_dir)
    spec.webroot = legacy["webroot"]
    spec.entry_path = legacy["entry"]
    spec.cookie = legacy["cookie"]
    spec.nav_cookie = legacy.get("nav_cookie", "")
    base = spec.entry_path.rsplit("/", 1)[0]
    spec.captcha_path = base + "/captcha"
    spec.logout_path = base + "/logout"

    php = parse_php_config(state_dir / "config.php")
    for key, attr in (("state_dir", "state_dir"), ("cookie", "cookie"),
                      ("nav_cookie", "nav_cookie"),
                      ("entry_path", "entry_path"),
                      ("captcha", "captcha_path"),
                      ("logout", "logout_path"), ("title", "title"),
                      ("subtitle", "subtitle"), ("lang", "lang"),
                      ("user", "username"), ("pass_hash", "pass_hash"),
                      ("upstream_token_file", "upstream_token_file"),
                      ("upstream_mint_url", "upstream_mint_url")):
        if php.get(key):
            setattr(spec, attr, php[key])
    if "scene_kind" in php:
        spec.scene_kind = {0: "art", 1: "image", 2: "auto"}.get(
            php["scene_kind"], "auto")
    spec.image_dirs = list(php.get("image_dirs") or [])
    if php.get("pass_hash"):
        spec.require_password = True
    elif "require_password" in php:
        spec.require_password = bool(php["require_password"])

    for key, val in parse_policy(state_dir / "policy.conf").items():
        if hasattr(spec, key):
            setattr(spec, key, val)

    if not spec.upstream_token_file and (state_dir / "dsh_token").exists():
        spec.upstream_token_file = str(state_dir / "dsh_token")
    if not spec.upstream_mint_url and spec.proxy_mode and spec.upstream:
        # Derived from the upstream actually being protected rather than
        # hardcoded to one application's port. This used to say 3080, the
        # port a specific dashboard happens to listen on -- a fact about one
        # host that has no business being a default in a distributed tool.
        base = spec.upstream
        if not base.endswith("/"):
            base += "/"
        spec.upstream_mint_url = base

    nginx_conf, ntext = _find_gate_nginx_conf(kind, env, conf_text)
    if nginx_conf:
        spec.nginx_conf = nginx_conf
        info = parse_listen(ntext)
        if info["port"]:
            spec.listen_port = info["port"]
            spec.listen_host = info["host"] or "127.0.0.1"
        if info["https"]:
            spec.use_https = True
        if info["cert_dir"]:
            spec.cert_dir = info["cert_dir"]
        if info["upstream"]:
            spec.upstream = info["upstream"]
        if info["domain"]:
            spec.domain = info["domain"]
        if info["server_name"]:
            spec.server_name = info["server_name"]
    spec.nginx_binary = env.get("nginx", {}).get("binary", "")
    return spec


def detect_all(env=None) -> list:
    """Every gate currently present on this host."""
    env = env or detect.full()
    text = nginx_text(env)
    out = []
    for kind in (KIND_BT, KIND_LOGIN):
        spec = detect_one(kind, env, text)
        if (Path(spec.state_dir) / "gate.lua").exists() or (
                spec.nginx_conf and Path(spec.nginx_conf).exists()):
            out.append(spec)
    return out


# --------------------------------------------------------------------------
# Adoption
# --------------------------------------------------------------------------


#: Extensions worth protecting inside a gate's state directory.
#:
#: ``.json`` is deliberately absent. The JSON files in there are *state*, not
#: configuration: ``image_kind_history.json`` is rewritten on every captcha
#: drawn and ``image_pool.json`` is a cache. A baseline that includes them
#: changes by itself between two inspections, so the check would report
#: "your security program was modified" every five minutes -- which is how a
#: real finding gets lost in noise. An operator who wants one of them
#: protected can name it in ``checks.self_integrity.paths``.
_CONFIG_EXT = (".php", ".lua", ".conf", ".ini")


def generated_artifacts(env=None) -> list:
    """Every *configuration* file this program writes outside its package.

    Used by two callers that must agree: the installer, which records what to
    protect, and the ``self_integrity`` check, which verifies it later. They
    are the same question asked at two moments, so they are the same function
    -- two implementations would drift, and the drift would be silent.

    Only files, and only the ones that decide behaviour: the nginx snippets
    (what reaches the login gate), each gate's ``config.php`` / ``gate.lua``
    / policy, and the audit rules. Missing paths are omitted -- on a host
    with no gate installed there is nothing to list, and that is not an
    error.
    """
    out = set()
    for spec in detect_all(env) or ():
        state_dir = getattr(spec, "state_dir", "")
        if not state_dir or not os.path.isdir(state_dir):
            continue
        # Top level only. Subdirectories hold sessions and image batches.
        for name in sorted(os.listdir(state_dir)):
            full = os.path.join(state_dir, name)
            if os.path.isfile(full) and name.endswith(_CONFIG_EXT):
                out.add(full)

    try:
        from . import shield
        out.add(str(shield.shield_file()))
    except (ImportError, OSError):
        pass

    bases = []
    ng = (env if env is not None else {}).get("nginx") or detect.nginx()
    if ng.get("conf"):
        bases.append(str(Path(ng["conf"]).parent))
    for extra in ng.get("include_dirs", []) or []:
        bases.append(str(extra))
    for directory in bases:
        d = Path(directory)
        if not d.is_dir():
            continue
        for pattern in ("vigil-gate-*.conf", "vigil-shield.conf"):
            out.update(str(p) for p in d.glob(pattern))

    return sorted(p for p in out if p)


def adopt(cfg, kind: str, spec: GateSpec = None) -> dict:
    """Record an existing gate in our configuration. Writes nothing else.

    Explicitly preserved, because losing any of them would be an outage:

    * the live state directory, so **sessions in flight keep working**;
    * the existing password hash, because the plaintext is unrecoverable;
    * the login log's byte offset, so the login notifier resumes instead of
      re-sending the whole history.
    """
    spec = spec or detect_one(kind)
    if not Path(spec.state_dir).is_dir():
        raise VigilError("没有检测到已安装的 %s 网关"
                         % KIND_META.get(kind, {}).get("label", kind))

    section = "gate.bt_panel" if kind == KIND_BT else "gate.dsh_gate"
    cfg.set("%s.enabled" % section, True)
    for field in ("state_dir", "webroot", "entry_path", "cookie",
                  "captcha_path", "logout_path", "title", "subtitle",
                  "lang", "session_ttl", "abs_ttl", "nav_ttl", "bind_ua",
                  "bind_ip", "max_sessions", "captcha_ttl", "lock_max",
                  "lock_secs", "listen_port", "listen_host", "use_https",
                  "cert_dir", "upstream", "domain", "server_name",
                  "nginx_conf", "upstream_token_file", "upstream_mint_url"):
        val = getattr(spec, field, None)
        if val not in (None, "", 0, False):
            cfg.set("%s.%s" % (section, field), val)
    # The username is kept for display. The hash deliberately stays out of
    # config.json and is only ever read from the gate's own file.
    if spec.username:
        cfg.set("%s.username" % section, spec.username)

    auth_log = Path(spec.state_dir) / "logs" / "auth.log"
    if auth_log.parent.is_dir():
        cfg.set("%s.auth_log" % section, str(auth_log))
        try:
            st = auth_log.stat()
            cfg.set("%s.auth_ino" % section, st.st_ino)
            cfg.set("%s.auth_off" % section, st.st_size)
        except OSError:
            pass

    return {
        "kind": kind,
        "state_dir": spec.state_dir,
        "entry": spec.entry_path,
        "port": spec.listen_port,
        "https": spec.use_https,
        "credentials": bool(spec.pass_hash),
        "username": spec.username,
        "wired": bool(spec.nginx_conf and Path(spec.nginx_conf).exists()),
    }


# --------------------------------------------------------------------------
# Status
# --------------------------------------------------------------------------


def status(cfg, env=None) -> list:
    env = env or detect.full()
    text = nginx_text(env)
    listening = shell.out(["ss", "-tlnH"], timeout=10)
    rows = []
    for kind, meta in KIND_META.items():
        spec = detect_one(kind, env, text)
        installed = Path(spec.state_dir).is_dir()
        wired = bool(spec.nginx_conf) and Path(spec.nginx_conf).exists()
        section = "bt_panel" if kind == KIND_BT else "dsh_gate"
        notes = []
        if installed and not wired:
            notes.append("网关文件存在但 nginx 未引用 —— 当前**没有生效**")
        if spec.proxy_mode and installed and spec.listen_port:
            if (":%d " % spec.listen_port) not in listening:
                notes.append("端口 %d 当前没有在监听" % spec.listen_port)
        rows.append({
            "kind": kind,
            "label": meta["label"],
            "installed": installed,
            "wired": wired,
            "state_dir": spec.state_dir,
            "entry": spec.entry_path,
            "port": spec.listen_port,
            "https": spec.use_https,
            "upstream": spec.upstream,
            "domain": spec.domain,
            "username": spec.username,
            "credentials": bool(spec.pass_hash),
            "ours": spec.state_dir.startswith("/usr/local/lib/vigil"),
            "adopted": bool(cfg.get("gate.%s.enabled" % section, False)),
            "spec": spec,
            "notes": notes,
        })
    return rows


# --------------------------------------------------------------------------
# Install / reconfigure
# --------------------------------------------------------------------------


def hash_password(plain: str) -> str:
    return installer.hash_password(plain)


def _spec_from_current(kind: str, cfg, env) -> GateSpec:
    """Start from what is live on disk, then let config fill any gaps."""
    current = detect_one(kind, env)
    spec = GateSpec.for_kind(kind, cfg=cfg, env=env)
    for field in ("state_dir", "webroot", "entry_path", "captcha_path",
                  "logout_path", "cookie", "nav_cookie", "title", "subtitle",
                  "lang", "require_password", "username", "pass_hash",
                  "session_ttl", "abs_ttl", "nav_ttl", "bind_ua", "bind_ip",
                  "max_sessions", "captcha_ttl", "captcha_length",
                  "captcha_min_seconds", "captcha_per_minute", "lock_max",
                  "lock_secs", "lock_backoff", "listen_host", "listen_port",
                  "use_https", "cert_dir", "server_name", "domain",
                  "upstream", "upstream_token_file", "upstream_mint_url",
                  "settings_log", "nginx_conf", "nginx_binary",
                  "fastcgi_pass", "fastcgi_conf", "worker_user", "pool_user"):
        val = getattr(current, field, None)
        if val not in (None, ""):
            setattr(spec, field, val)
    return spec


def _default_patches(kind: str) -> list:
    """Patches this gate needs for the upstream app to work fully."""
    if kind != KIND_LOGIN:
        return []
    base = upstream_module_base()
    if not base:
        return []
    return [{"path": str(base / rel), "find": find, "replace": repl,
             "marker": marker}
            for rel, find, repl, marker in installer.DSH_SETTINGS_PATCHES]


def upstream_module_base():
    """Locate the DSH client module tree, if present.

    Discovered from the installed node version rather than hardcoded, so a
    node upgrade does not silently stop the patches from applying.
    """
    for base in sorted(glob.glob(
            "/www/server/nodejs/*/lib/node_modules/@deepseek-ai/dsh/"
            "node_modules/@deepseek-ai"), reverse=True):
        if Path(base).is_dir():
            return Path(base)
    return None


def install(cfg, kind: str, env=None, save: bool = True, **overrides) -> dict:
    """Build a spec from config plus overrides and install it."""
    env = env or detect.full()
    password = overrides.pop("password", "")
    spec = _spec_from_current(kind, cfg, env)
    for k, v in overrides.items():
        if v is not None and hasattr(spec, k):
            setattr(spec, k, v)
    if spec.kind == KIND_LOGIN and not spec.settings_patches:
        spec.settings_patches = _default_patches(KIND_LOGIN)
    if spec.require_password:
        if password:
            spec.pass_hash = installer.hash_password(password)
        elif not spec.pass_hash:
            raise VigilError("登录网关需要密码",
                             hint="用 --password 指定，或改用 bt_panel 类型")
    result = installer.install(spec, env=env, log=_log())
    if result.get("ok") and save:
        _persist(cfg, kind, spec)
    return result


def reconfigure(cfg, kind: str, **overrides) -> dict:
    """Re-apply an existing gate with new parameters.

    The state directory comes from the live installation so sessions in
    flight survive; only the requested fields change.
    """
    env = detect.full()
    if not Path(detect_one(kind, env).state_dir).is_dir():
        raise VigilError("没有可重新配置的 %s 网关" % kind,
                         hint="请先用 `vigil gate install %s` 安装" % kind)
    return install(cfg, kind, env=env, **overrides)


def _persist(cfg, kind: str, spec: GateSpec) -> None:
    section = "gate.bt_panel" if kind == KIND_BT else "gate.dsh_gate"
    cfg.set("%s.enabled" % section, True)
    for field in ("entry_path", "cookie", "listen_port", "listen_host",
                  "use_https", "cert_dir", "upstream", "domain",
                  "server_name", "nginx_conf", "username"):
        val = getattr(spec, field, None)
        if val not in (None, "", 0, False):
            cfg.set("%s.%s" % (section, field), val)
    cfg.save()


def uninstall(cfg, kind: str, remove_state: bool = False, env=None) -> dict:
    spec = detect_one(kind, env)
    result = installer.uninstall(spec, env=env, remove_state=remove_state)
    if result.get("ok"):
        section = "gate.bt_panel" if kind == KIND_BT else "gate.dsh_gate"
        cfg.set("%s.enabled" % section, False)
        cfg.save()
    return result


def _log():
    from ..core.logging import get as get_logger
    return get_logger("gate")
