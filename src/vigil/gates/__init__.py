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
from .spec import (BT_INSTANCE_NAME, KIND_BT, KIND_LOGIN, KIND_META,
                   LEGACY_LOGIN_NAME, GateSpec, config_section,
                   instance_cookie, instance_dir_basename, instance_label,
                   instance_nav_cookie, instance_state_dir, instance_webroot,
                   normalize_instance, package_state_dir)

__all__ = [
    "KIND_BT", "KIND_LOGIN", "KIND_META", "GateSpec",
    "BT_INSTANCE_NAME", "LEGACY_LOGIN_NAME",
    "config_section", "instance_candidates", "instance_label",
    "normalize_instance",
    "detect_all", "detect_one", "adopt", "status", "install", "uninstall",
    "reconfigure", "hash_password",
]

#: Layouts produced by earlier versions of this tool, or configured by hand.
#: Each is still fully readable, so an existing installation can be adopted
#: rather than replaced. Kept as data because they are also the source of the
#: default instance's directory, cookie and config key.
LEGACY_LAYOUTS = (
    {
        "kind": KIND_BT,
        "name": BT_INSTANCE_NAME,
        "state_dir": "/www/server/bt-gate",
        "webroot": "/www/wwwroot/bt-gate",
        "entry": "/__btgate",
        "cookie": "btgate",
    },
    {
        "kind": KIND_LOGIN,
        "name": LEGACY_LOGIN_NAME,
        "state_dir": "/www/server/dsh-gate",
        "webroot": "/www/wwwroot/dsh-gate",
        "entry": "/__gate/login",
        "cookie": "dshgate",
        "nav_cookie": "dshnav",
    },
)

def conf_slug(kind: str, name: str = "") -> str:
    """Hyphenated slug used in this instance's nginx file names."""
    return re.sub(r"\W+", "-", normalize_instance(kind, name))


def instance_name_from_dir(path) -> str:
    """Recover an instance name from a `*-gate` state directory."""
    base = os.path.basename(str(path).rstrip("/"))
    if base == "bt-gate":
        return BT_INSTANCE_NAME
    if base == "dsh-gate":
        return LEGACY_LOGIN_NAME
    if not base.endswith("-gate"):
        return ""
    try:
        # `dsh-gate` and `bt-gate` are handled above; anything else that
        # normalises back to a reserved name is not an instance we created.
        return normalize_instance(KIND_LOGIN, base[:-len("-gate")])
    except VigilError:
        return ""


def declared_instances(cfg) -> list:
    """``(config_section, kind, name)`` for every instance in the config.

    The two original gates are always present, whether or not they are
    installed, because `status` has always shown both. Named instances are
    read from `gate.<name>` sections -- that key is the instance's identity,
    so no separate index needs to be kept in sync with it.
    """
    out = [("bt_panel", KIND_BT, BT_INSTANCE_NAME),
           ("dsh_gate", KIND_LOGIN, LEGACY_LOGIN_NAME)]
    gate_cfg = cfg.get("gate") if cfg is not None else None
    if not isinstance(gate_cfg, dict):
        return out
    for key in sorted(gate_cfg):
        if key in ("bt_panel", "dsh_gate", "demo"):
            continue
        if not isinstance(gate_cfg[key], dict):
            continue
        try:
            name = normalize_instance(KIND_LOGIN, key)
        except VigilError:
            continue
        if name == key:
            out.append((key, KIND_LOGIN, name))
    return out


def _env_gate_dirs(env) -> list:
    """State directories discovered on this host, from env or a live scan."""
    found = (env or {}).get("gate")
    if isinstance(found, dict) and found.get("dirs") is not None:
        return [Path(d) for d in (found.get("dirs") or [])]
    return [Path(d) for d in (detect.gate_instances().get("dirs") or [])]


def _resolve_state_dir(kind: str, name: str, env):
    """Where this instance's files actually are, or None.

    The canonical ``/www/server/<name>-gate`` wins. A directory discovered
    under a different root -- a non-standard layout, or a test tree -- is
    accepted when its name is the one this instance would use, so discovery
    and detection cannot disagree about which directory belongs to which
    instance.
    """
    canonical = Path(instance_state_dir(kind, name))
    if canonical.is_dir():
        return canonical
    want = instance_dir_basename(kind, name)
    for cand in _env_gate_dirs(env):
        if cand.is_dir() and cand.name == want:
            return cand
    return None


def _directory_is_gate(directory, kind: str, name: str, env) -> bool:
    """Does this `*-gate` directory actually hold a gate?

    A directory whose name merely ends in `-gate` is not an instance. On a
    real host there is an unrelated `convert-gate` directory, and treating
    it as a login gate listed it with every field blank -- a fabricated
    instance is worse than a missing one, because it invites the operator to
    reconfigure it. The same two facts the detector uses decide it: a
    `gate.lua`, or nginx wiring that points at this instance's script.
    """
    if (Path(directory) / "gate.lua").is_file():
        return True
    conf, _text = _find_gate_nginx_conf(kind, env, "", name, str(directory))
    return bool(conf)


def instance_candidates(env=None, cfg=None) -> list:
    """``(kind, name)`` for every instance that could exist here.

    Filesystem discovery comes first because it is the truth; config is
    consulted as well so an instance whose files were removed still appears
    as a broken installation instead of silently vanishing from `status`.
    """
    env = env or detect.full()
    out = [(KIND_BT, BT_INSTANCE_NAME), (KIND_LOGIN, LEGACY_LOGIN_NAME)]
    seen = set(out)
    for directory in _env_gate_dirs(env):
        name = instance_name_from_dir(directory)
        if not name:
            continue
        kind = KIND_BT if name == BT_INSTANCE_NAME else KIND_LOGIN
        if not _directory_is_gate(directory, kind, name, env):
            continue
        key = (kind, name)
        if key not in seen:
            seen.add(key)
            out.append(key)
    for _section, kind, name in declared_instances(cfg):
        if (kind, name) not in seen:
            seen.add((kind, name))
            out.append((kind, name))
    return out


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


def _find_gate_nginx_conf(kind: str, env, conf_text: str,
                          name: str = "", state_dir: str = "") -> tuple:
    """Locate the nginx file that owns *this instance*, and its text.

    Matching is by the Lua script the file points at, which is unique per
    instance. A *name* match is only accepted against the exact file this
    instance generates -- a substring match would let instance `log` claim
    instance `login`'s wiring.
    """
    name = normalize_instance(kind, name)
    if not state_dir:
        state_dir = instance_state_dir(kind, name)
    lua = str(Path(state_dir) / "gate.lua")
    ours = os.path.join(package_state_dir(kind, name), "gate.lua")

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

    want = "vigil-gate-%s.conf" % conf_slug(kind, name)
    fallback = ""
    for path in candidates:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "access_by_lua_file" not in text:
            continue
        if lua in text or ours in text:
            return str(path), text
        if not fallback and path.name == want:
            fallback = (str(path), text)
    if fallback:
        return fallback
    return "", ""


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------


def detect_one(kind: str, env=None, conf_text: str = "",
               name: str = "") -> GateSpec:
    """Reconstruct the spec of one installed instance, or a blank one.

    *name* selects the instance; empty means the original login/panel gate,
    so every pre-instances caller keeps its behaviour.
    """
    env = env or detect.full()
    name = normalize_instance(kind, name)
    spec = GateSpec.for_kind(kind, cfg=None, env=env, name=name)

    state_dir = _resolve_state_dir(kind, name, env)
    webroot = instance_webroot(kind, name)
    if state_dir is None:
        ours = Path(package_state_dir(kind, name))
        if not ours.is_dir():
            return spec
        state_dir = ours
        webroot = str(ours / "web")

    spec.state_dir = str(state_dir)
    spec.webroot = webroot
    spec.entry_path = KIND_META[kind]["default_entry"]
    spec.cookie = instance_cookie(kind, name)
    spec.nav_cookie = instance_nav_cookie(kind, name)
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

    nginx_conf, ntext = _find_gate_nginx_conf(kind, env, conf_text, name,
                                              str(state_dir))
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


def detect_all(env=None, cfg=None) -> list:
    """Every gate instance currently present on this host."""
    env = env or detect.full()
    text = nginx_text(env)
    out = []
    for kind, name in instance_candidates(env, cfg):
        spec = detect_one(kind, env, text, name=name)
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


def adopt(cfg, kind: str, spec: GateSpec = None, name: str = "") -> dict:
    """Record an existing gate in our configuration. Writes nothing else.

    Explicitly preserved, because losing any of them would be an outage:

    * the live state directory, so **sessions in flight keep working**;
    * the existing password hash, because the plaintext is unrecoverable;
    * the login log's byte offset, so the login notifier resumes instead of
      re-sending the whole history.
    """
    spec = spec or detect_one(kind, name=name)
    if not Path(spec.state_dir).is_dir():
        raise VigilError("没有检测到已安装的 %s 网关"
                         % KIND_META.get(kind, {}).get("label", kind))

    section = "gate.%s" % config_section(kind, spec.name)
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
    """One row per candidate instance, installed or not.

    The two original gates are always listed -- that is what `vigil gate
    status` has always shown -- and named instances appear as soon as their
    directory or their `gate.<name>` config section exists.
    """
    env = env or detect.full()
    text = nginx_text(env)
    listening = shell.out(["ss", "-tlnH"], timeout=10)
    rows = []
    for kind, name in instance_candidates(env, cfg):
        section = config_section(kind, name)
        spec = detect_one(kind, env, text, name=name)
        installed = Path(spec.state_dir).is_dir()
        wired = bool(spec.nginx_conf) and Path(spec.nginx_conf).exists()
        notes = []
        if installed and not wired:
            notes.append("网关文件存在但 nginx 未引用 —— 当前**没有生效**")
        if spec.proxy_mode and installed and spec.listen_port:
            if (":%d " % spec.listen_port) not in listening:
                notes.append("端口 %d 当前没有在监听" % spec.listen_port)
        rows.append({
            "kind": kind,
            "name": name,
            "section": section,
            "config_key": "gate.%s" % section,
            "label": instance_label(kind, name),
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


def _port_owner(cfg, env, spec) -> str:
    """Name of another instance already listening on *spec*'s port, if any."""
    for other in detect_all(env, cfg):
        if (other.kind, other.name) == (spec.kind, spec.name):
            continue
        if other.listen_port and int(other.listen_port) == int(spec.listen_port):
            return instance_label(other.kind, other.name)
    return ""


def _allocate_port(cfg, env, spec) -> None:
    """Give a proxy-mode gate a port that is not already taken.

    Two gates on one port is a bind conflict, not a choice: nginx fails to
    load and takes every other site down with it. An explicitly requested
    port is never silently changed -- that is reported instead -- while an
    instance with no port yet gets the first free one from the historical
    4399 upwards, so the first instance keeps the number existing wiring
    expects and the next one gets a predictable neighbour.
    """
    if not spec.proxy_mode:
        return
    if spec.listen_port:
        owner = _port_owner(cfg, env, spec)
        if owner:
            raise VigilError(
                "端口 %d 已被网关实例「%s」占用" % (spec.listen_port, owner),
                hint="换一个 --port，或先卸载/改端口那个实例")
        return
    used = {int(o.listen_port) for o in detect_all(env, cfg)
            if o.listen_port and (o.kind, o.name) != (spec.kind, spec.name)}
    port = 4399
    while port in used:
        port += 1
    if port > 65535:
        raise VigilError("没有可用的监听端口")
    spec.listen_port = port


def _allocate_cert(spec) -> None:
    """Fill in the conventional certificate directory once the port is known.

    The port is not known when the spec is first built for a named instance
    (it is allocated above), so doing this earlier produced a path ending in
    `local-0`.
    """
    if spec.use_https and not spec.cert_dir and spec.proxy_mode \
            and spec.listen_port:
        spec.cert_dir = ("/www/server/panel/vhost/cert/local-%d"
                         % spec.listen_port)


# --------------------------------------------------------------------------
# Install / reconfigure
# --------------------------------------------------------------------------


def hash_password(plain: str) -> str:
    return installer.hash_password(plain)


def _spec_from_current(kind: str, cfg, env, name: str = "") -> GateSpec:
    """Start from what is live on disk, then let config fill any gaps."""
    name = normalize_instance(kind, name)
    current = detect_one(kind, env, name=name)
    spec = GateSpec.for_kind(kind, cfg=cfg, env=env, name=name)
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
    spec.name = name
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


def install(cfg, kind: str, env=None, save: bool = True, name: str = "",
            **overrides) -> dict:
    """Build a spec from config plus overrides and install one instance."""
    env = env or detect.full()
    name = normalize_instance(kind, name or overrides.pop("name", ""))
    password = overrides.pop("password", "")
    spec = _spec_from_current(kind, cfg, env, name)
    for k, v in overrides.items():
        if v is not None and hasattr(spec, k):
            setattr(spec, k, v)
    spec.name = name
    if spec.kind == KIND_LOGIN and not spec.settings_patches:
        spec.settings_patches = _default_patches(KIND_LOGIN)
    if spec.require_password:
        if password:
            spec.pass_hash = installer.hash_password(password)
        elif not spec.pass_hash:
            raise VigilError("登录网关需要密码",
                             hint="用 --password 指定，或改用 bt_panel 类型")
    _allocate_port(cfg, env, spec)
    _allocate_cert(spec)
    result = installer.install(spec, env=env, log=_log())
    if result.get("ok") and save:
        _persist(cfg, kind, spec)
    return result


def reconfigure(cfg, kind: str, name: str = "", **overrides) -> dict:
    """Re-apply an existing instance with new parameters.

    The state directory comes from the live installation so sessions in
    flight survive; only the requested fields change.
    """
    env = detect.full()
    name = normalize_instance(kind, name or overrides.pop("name", ""))
    if not Path(detect_one(kind, env, name=name).state_dir).is_dir():
        raise VigilError("没有可重新配置的 %s 网关%s"
                         % (kind, "（%s）" % name
                            if name != LEGACY_LOGIN_NAME else ""),
                         hint="请先用 `vigil gate install %s --name %s` 安装"
                              % (kind, name))
    return install(cfg, kind, env=env, name=name, **overrides)


def _persist(cfg, kind: str, spec: GateSpec) -> None:
    section = "gate.%s" % config_section(kind, spec.name)
    cfg.set("%s.enabled" % section, True)
    cfg.set("%s.name" % section, spec.name)
    # Persisted even when False: "this gate needs no password" is a setting,
    # not the absence of one, and rewriting it as absent would turn the next
    # reconfigure into a gate that suddenly demands credentials.
    cfg.set("%s.require_password" % section, bool(spec.require_password))
    for field in ("state_dir", "webroot", "entry_path", "cookie",
                  "nav_cookie", "listen_port", "listen_host", "use_https",
                  "cert_dir", "upstream", "domain", "server_name",
                  "nginx_conf"):
        val = getattr(spec, field, None)
        if val not in (None, "", 0, False):
            cfg.set("%s.%s" % (section, field), val)
    # The username is kept for display. The hash deliberately stays out of
    # config.json and is only ever read from the gate's own file.
    if spec.username:
        cfg.set("%s.username" % section, spec.username)
    cfg.save()


def uninstall(cfg, kind: str, remove_state: bool = False, env=None,
              name: str = "") -> dict:
    name = normalize_instance(kind, name)
    spec = detect_one(kind, env, name=name)
    result = installer.uninstall(spec, env=env, remove_state=remove_state)
    if result.get("ok"):
        section = "gate.%s" % config_section(kind, name)
        cfg.set("%s.enabled" % section, False)
        cfg.save()
    return result


def _log():
    from ..core.logging import get as get_logger
    return get_logger("gate")
