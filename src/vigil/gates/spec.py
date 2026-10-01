"""Gate configuration model.

A gate is fully described by a :class:`GateSpec`. Everything that varies
between installations lives here — credentials, ports, TLS, session policy,
CAPTCHA difficulty — so the installer is a pure function of the spec and
"reconfigure" is just "build a new spec and re-render".

The defaults encode the values a working installation actually uses, which
is why several of them look oddly specific: they were chosen for a real
host and are known to behave. They are defaults, not constants; every one
can be overridden.
"""
from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

from ..core import detect

KIND_BT = "bt_panel"
KIND_LOGIN = "login"

KIND_META = {
    KIND_BT: {
        "label": "宝塔面板 / aaPanel 人机验证",
        "desc": "在面板入口前加一层人机验证。不保存任何账号密码 —— "
                "真正的登录仍然由面板自己完成，因此即使这一层被绕过，"
                "攻击者面对的仍是面板自身的认证。",
        "no_credentials": True,
        "default_strict_nav": 0,
        "default_entry": "/__btgate",
        # Endpoint stem used when the entry path sits at the vhost root and
        # therefore has no directory part to derive siblings from.
        "endpoint_stem": "/__bt",
        "default_cookie": "btgate",
        # A one-time navigation ticket needs a cookie to live in. Without one
        # there is nothing to consume on a reload, so strict mode would have
        # no effect at all on this gate.
        "default_nav_cookie": "btnav",
        "default_dir": "/www/server/bt-gate",
        "default_webroot": "/www/wwwroot/bt-gate",
        # The panel is reached through a plain vhost, so there is no local
        # proxy hop and therefore no separate port to listen on.
        "proxy_mode": False,
    },
    KIND_LOGIN: {
        "label": "独立登录页（人机验证 + 账号密码）",
        "desc": "完整的登录闸门：图形验证码 + 账号密码（bcrypt 存储）。"
                "适合自建面板、内部工具，或需要把某个只监听本机的服务"
                "安全地投影到公网。",
        "no_credentials": False,
        "default_strict_nav": 1,
        "default_entry": "/__gate/login",
        "endpoint_stem": "/__gate/",
        "default_cookie": "dshgate",
        "default_nav_cookie": "dshnav",
        "default_dir": "/www/server/dsh-gate",
        "default_webroot": "/www/wwwroot/dsh-gate",
        # The protected app listens on loopback and cannot be exposed, so
        # the gate itself becomes the only listener on its own port, and a
        # control-panel reverse proxy points at it.
        "proxy_mode": True,
    },
}


def _derive_endpoints(spec: "GateSpec") -> None:
    """Set the captcha and logout paths from the entry path.

    Derived, never inherited: reading these from config let one gate's paths
    leak into the other, so the BT gate ended up serving `/__gate/captcha`
    instead of its own endpoint. Where the entry path sits at the vhost root
    (`/__btgate`) there is no directory part to derive from, so the kind's
    own stem is used.
    """
    base = spec.entry_path.rsplit("/", 1)[0]
    if base:
        spec.captcha_path = base + "/captcha"
        spec.logout_path = base + "/logout"
        return
    stem = KIND_META.get(spec.kind, {}).get("endpoint_stem", "/__vigil/")
    if not stem.endswith("/"):
        stem += "/"
    spec.captcha_path = stem + "captcha"
    spec.logout_path = stem + "logout"


def _slug(kind: str) -> str:
    return re.sub(r"\W+", "_", kind)


def _resolve_nginx_targets(spec: "GateSpec", env: dict) -> None:
    """Work out where the gate config and the rate-limit zones must live.

    This is easy to get wrong in a way that looks fine and does nothing: a
    file dropped into nginx's ``conf`` directory is simply never read unless
    the main config includes it. So the target is derived from the *include
    list* rather than from a convention.
    """
    import os
    ng = (env or {}).get("nginx", {}) or {}
    conf = ng.get("conf", "")
    conf_dir = os.path.dirname(conf) if conf else "/etc/nginx"

    # Zones: http{}-scope, so the main config must include the file.
    spec.zones_file = os.path.join(conf_dir, "vigil-gate-%s-zones.conf" % _slug(spec.kind))

    include_dirs = [d for d in (ng.get("include_dirs") or []) if os.path.isdir(d)]
    # The vhost directory is the one that is included as *.conf at http scope.
    vhost_dir = ""
    for d in include_dirs:
        if d.rstrip("/").endswith("vhost/nginx"):
            vhost_dir = d
            break
    if not vhost_dir:
        for d in include_dirs:
            if d.rstrip("/").endswith(("sites-enabled", "conf.d")):
                vhost_dir = d
                break
    if not vhost_dir:
        vhost_dir = conf_dir

    lua = os.path.join(spec.state_dir, "gate.lua")
    existing = _existing_gate_conf(kind=spec.kind, lua=lua,
                                   listen_port=spec.listen_port,
                                   vhost_dir=vhost_dir, env=env)
    if existing:
        # Reuse the file an earlier installation used, so a reconfigure
        # updates in place. Writing to a new name instead would leave two
        # files wiring the same Lua hook -- a duplicate directive, and nginx
        # would refuse to load at all.
        spec.nginx_conf = existing
        return

    if spec.proxy_mode:
        # A whole server{} block, dropped into the included vhost directory.
        spec.nginx_conf = os.path.join(vhost_dir, "vigil-gate-%s.conf" % _slug(spec.kind))
    else:
        # A server-scope snippet, which only makes sense inside an existing
        # vhost, so it goes into that site's extension directory.
        site = _panel_site_dir(env) or spec.domain or "vigil"
        ext = os.path.join(vhost_dir, "extension", site)
        spec.nginx_conf = os.path.join(ext, "zz-vigil-gate.conf")


def _existing_gate_conf(kind: str, lua: str, listen_port: int,
                        vhost_dir: str, env: dict) -> str:
    """Find the nginx file an earlier installation of this gate used."""
    import os
    if not vhost_dir or not os.path.isdir(vhost_dir):
        return ""
    candidates = []
    for pat in ("zz-proxy-*.conf", "vigil-gate-*.conf", "zz-*-auth.conf"):
        candidates.extend(sorted(__import__("glob").glob(
            os.path.join(vhost_dir, pat))))
    ext = os.path.join(vhost_dir, "extension")
    if os.path.isdir(ext):
        for site in sorted(os.listdir(ext)):
            site_dir = os.path.join(ext, site)
            if os.path.isdir(site_dir):
                candidates.extend(sorted(__import__("glob").glob(
                    os.path.join(site_dir, "*.conf"))))
    for path in candidates:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "access_by_lua_file" not in text or "gate.lua" not in text:
            continue
        if lua not in text:
            continue
        # Same Lua hook. If it also has a listener, the port must match, or
        # this is the other gate type sharing a state directory.
        if listen_port and "listen " in text:
            if (":%d" % listen_port) not in text:
                continue
        return path
    return ""


def _panel_site_dir(env: dict) -> str:
    """Which site's vhost should carry the gate.

    Resolution order, most reliable first:

    1. **an existing gate wiring** — if a previous installation already put
       a snippet under ``extension/<site>/``, that site is the answer, and
       reusing it is what makes a reconfigure update in place instead of
       leaving a second, conflicting gate behind;
    2. the vhost whose proxy configuration points at the panel port (the
       panel's own site);
    3. the vhost whose name matches the configured domain.
    """
    import os
    panel = (env or {}).get("bt_panel", {}) or {}
    vhost_dir = (panel.get("vhost_dir")
                 or next((d for d in (env or {}).get("nginx", {}).get("include_dirs", [])
                          if d.rstrip("/").endswith("vhost/nginx")), ""))
    if not os.path.isdir(vhost_dir):
        return ""

    # 1. existing gate wiring
    ext_root = os.path.join(vhost_dir, "extension")
    if os.path.isdir(ext_root):
        for site in sorted(os.listdir(ext_root)):
            site_dir = os.path.join(ext_root, site)
            if not os.path.isdir(site_dir):
                continue
            for f in os.listdir(site_dir):
                if not f.endswith(".conf"):
                    continue
                try:
                    text = open(os.path.join(site_dir, f),
                                encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                if "access_by_lua_file" in text and "gate.lua" in text:
                    return site

    # 2. the site that proxies to the panel port
    port = str(panel.get("port") or "")
    if port:
        proxy_root = os.path.join(vhost_dir, "proxy")
        if os.path.isdir(proxy_root):
            for site in sorted(os.listdir(proxy_root)):
                site_dir = os.path.join(proxy_root, site)
                if not os.path.isdir(site_dir):
                    continue
                for f in os.listdir(site_dir):
                    try:
                        text = open(os.path.join(site_dir, f),
                                    encoding="utf-8", errors="replace").read()
                    except OSError:
                        continue
                    if "127.0.0.1:%s" % port in text:
                        return site
        # 3. fall back to scanning the vhosts themselves
        for name in sorted(os.listdir(vhost_dir)):
            if not name.endswith(".conf"):
                continue
            try:
                text = open(os.path.join(vhost_dir, name),
                            encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            if "127.0.0.1:%s" % port in text:
                return name[:-len(".conf")]
    return ""


@dataclass
class GateSpec:
    # -- identity ---------------------------------------------------------
    kind: str = KIND_BT
    state_dir: str = ""
    webroot: str = ""
    entry_path: str = ""
    captcha_path: str = ""
    logout_path: str = ""
    cookie: str = ""
    nav_cookie: str = ""
    title: str = ""
    subtitle: str = ""
    lang: str = "zh"

    # -- authentication ---------------------------------------------------
    #: False for a pure human-verification gate: no credential exists at all.
    require_password: bool = True
    username: str = ""
    #: bcrypt digest. The plaintext is only ever held in memory while the
    #: spec is being built, and is never written anywhere.
    pass_hash: str = ""

    # -- session policy ---------------------------------------------------
    session_ttl: int = 1800        # sliding idle timeout
    abs_ttl: int = 43200           # absolute lifetime
    nav_ttl: int = 120             # one-time navigation ticket
    bind_ua: int = 1
    bind_ip: int = 0
    max_sessions: int = 50
    #: When set, a *navigation* (a person loading or reloading a page) is
    #: accepted only with a one-time navigation ticket, never with the
    #: session ticket. The practical effect is that pressing F5 always asks
    #: for verification again, while the page's own background requests keep
    #: working off the session ticket.
    #:
    #: Defaults differ per gate on purpose. The login gate fronts a
    #: single-page application, where the document loads once and everything
    #: afterwards is XHR -- so strict navigation is exactly what the operator
    #: wants and costs nothing. A control panel is the opposite: every click
    #: is a full page load, and requiring verification for each one would
    #: make the panel unusable.
    strict_nav: int = 0

    # ---- puzzle artwork -------------------------------------------------
    # What the slider is built from. `art` renders a generated Q-style
    # landscape every time; `image` uses files from `image_dirs`; `auto`
    # picks per challenge, which is what makes the "new puzzle" link change
    # the kind of picture as well as the picture.
    scene_kind: str = "auto"
    # Directories scanned for pictures. Never shipped with the package: the
    # installer probes for known art libraries on the host and otherwise
    # leaves this empty, and the gate falls back to generated art.
    image_dirs: list = field(default_factory=list)
    #: Carry the puzzle pictures inside the page as `data:` URIs instead of
    #: fetching them from the asset endpoint. On by default: a picture that
    #: must be fetched is a picture that can fail to be fetched, and when it
    #: failed the server saw nothing at all -- no request, no log line, no way
    #: to tell a broken page from a slow one.
    inline_images: bool = True
    #: 0 = session cookie (dies with the browser). A positive value keeps
    #: the visitor signed in across restarts, which is convenient and less
    #: safe; it is opt-in.
    cookie_lifetime: int = 0

    # -- CAPTCHA ----------------------------------------------------------
    captcha_ttl: int = 180
    captcha_length: int = 5
    captcha_min_seconds: int = 1
    captcha_per_minute: int = 12

    # -- lockout ----------------------------------------------------------
    lock_max: int = 8
    lock_secs: int = 900
    #: Lock duration multiplies by this on each repeat offence, capped.
    #: Length of the *first* lockout, before the multiplier applies. The old
    #: shape used lock_secs for the first lock as well, so a person's first
    #: mistake cost the full fifteen minutes.
    lock_first_secs: int = 120
    lock_backoff: int = 2
    #: Wrong passwords are counted apart from failed challenges: the puzzle
    #: already bounds password guessing, and a typo must not spend the
    #: challenge budget.
    cred_max: int = 20
    cred_lock_secs: int = 300

    # -- listener / TLS ---------------------------------------------------
    #: Empty host means "attach to an existing vhost" instead of listening.
    listen_host: str = "127.0.0.1"
    listen_port: int = 0
    use_https: bool = False
    cert_dir: str = ""
    cert_days: int = 3650
    server_name: str = "_"
    #: Public domain, used for URLs in messages and for the certificate SAN.
    domain: str = ""

    # -- upstream application ---------------------------------------------
    upstream: str = ""
    upstream_token_file: str = ""
    upstream_mint_url: str = ""
    #: Where the upstream service writes its startup log, used to extract
    #: the per-process launch token.
    settings_log: str = ""
    #: Settings patches applied before the upstream service starts, so a
    #: non-loopback visitor gets the full UI. Each entry is
    #: ``{"path", "find", "replace", "marker"}``.
    settings_patches: list = field(default_factory=list)

    # -- host wiring ------------------------------------------------------
    nginx_conf: str = ""
    #: Existing nginx files this gate supersedes and which must be
    #: withdrawn, or nginx refuses to start: two access_by_lua_file
    #: directives at server scope are a duplicate, and two listeners on the
    #: same port is a bind conflict.
    replace_confs: list = field(default_factory=list)
    #: Where the http{}-scope rate-limit zones live. Must be a file the main
    #: config actually includes, or nginx will not start.
    zones_file: str = ""
    nginx_binary: str = ""
    fastcgi_pass: str = ""
    fastcgi_conf: str = "fastcgi.conf"
    worker_user: str = "www"
    pool_user: str = "www"

    # ------------------------------------------------------------------
    @property
    def meta(self) -> dict:
        return KIND_META.get(self.kind, {})

    @property
    def proxy_mode(self) -> bool:
        return bool(self.meta.get("proxy_mode"))

    @property
    def prefix(self) -> str:
        """Common prefix of the gate's own paths, for the 404 catch-all.

        Returns "" when there is no safe common prefix, and an empty prefix
        means "emit no catch-all at all".

        The first version of this returned "/" for an entry path like
        `/__btgate` (no further slashes to trim at), which produced
        `location ^~ / { return 404; }` -- a block that swallows the entire
        site and collides with the control panel's own `location ^~ /`.
        nginx rejected the configuration outright, which is the only reason
        it did not take a live panel down.
        """
        import os as _os
        paths = [p for p in (self.entry_path, self.captcha_path,
                             self.logout_path) if p]
        if not paths:
            return ""
        pref = _os.path.commonprefix(paths)
        if not pref.endswith("/"):
            pref = pref.rsplit("/", 1)[0] + "/" if "/" in pref else ""
        # A prefix of "/" or "" would match everything; refuse.
        if len(pref) < 3:
            return ""
        return pref

    def zone(self, what: str) -> str:
        return "vigil_%s_%s" % (_slug(self.kind), what)

    def validate(self) -> list:
        problems = []
        if self.kind not in KIND_META:
            problems.append("未知的网关类型: %s" % self.kind)
        if not self.state_dir:
            problems.append("state_dir 未设置")
        if not self.webroot:
            problems.append("webroot 未设置")
        if not self.entry_path.startswith("/"):
            problems.append("入口路径必须以 / 开头")
        if self.require_password:
            if not self.username:
                problems.append("需要账号密码时必须提供用户名")
            if not self.pass_hash:
                problems.append("需要账号密码时必须提供密码哈希")
            elif not self.pass_hash.startswith(("$2y$", "$2a$", "$2b$")):
                problems.append("密码哈希不是 bcrypt 格式")
        if self.proxy_mode:
            if not (0 < self.listen_port < 65536):
                problems.append("监听端口无效: %s" % self.listen_port)
            if not self.upstream:
                problems.append("需要指定要保护的上游地址（upstream）")
            elif not re.match(r"^https?://", self.upstream):
                problems.append("上游地址必须以 http:// 或 https:// 开头")
        if self.use_https and not self.cert_dir:
            problems.append("启用 HTTPS 时必须指定证书目录")
        if self.bind_ip not in (0, 1):
            problems.append("bind_ip 只能是 0 或 1")
        if not (4 <= self.captcha_length <= 8):
            problems.append("验证码长度应在 4-8 之间")
        return problems

    def to_dict(self) -> dict:
        return asdict(self)

    # -- construction ------------------------------------------------------
    @classmethod
    def for_kind(cls, kind: str, cfg=None, env: dict = None,
                 **overrides) -> "GateSpec":
        """Build a spec for *kind*, seeded from config and host discovery."""
        meta = KIND_META[kind]
        env = env or detect.full()
        ng = env.get("nginx", {})
        socks = env.get("php_fpm", {}).get("sockets", [])
        panel = env.get("bt_panel", {})

        spec = cls(kind=kind)
        spec.state_dir = meta["default_dir"]
        spec.webroot = meta["default_webroot"]
        spec.entry_path = meta["default_entry"]
        spec.cookie = meta["default_cookie"]
        spec.nav_cookie = meta.get("default_nav_cookie", "")

        base = spec.entry_path.rsplit("/", 1)[0] or "/__gate"
        spec.captcha_path = base + "/captcha"
        spec.logout_path = base + "/logout"

        spec.require_password = not meta.get("no_credentials", False)
        spec.strict_nav = int(meta.get("default_strict_nav", 0))
        spec.scene_kind = str(meta.get("scene_kind", "auto"))
        spec.image_dirs = list(meta.get("image_dirs", []) or [])
        spec.title = "访问验证" if kind == KIND_BT else "管理员登录"
        spec.subtitle = "请完成人机验证后继续" if kind == KIND_BT else "请登录后继续"

        spec.nginx_binary = ng.get("binary", "")
        _resolve_nginx_targets(spec, env)
        spec.worker_user = ng.get("worker_user", "www")
        if socks:
            spec.fastcgi_pass = "unix:%s" % socks[0]["socket"]
            spec.pool_user = socks[0].get("user", "") or spec.worker_user
        for cand in ("/www/server/nginx/conf/fastcgi.conf",
                     "/etc/nginx/fastcgi.conf"):
            import os
            if os.path.exists(cand):
                spec.fastcgi_conf = cand
                break

        # Per-kind panel wiring.
        if kind == KIND_BT and panel.get("present"):
            spec.domain = cfg.get("gate.bt_panel.domain", "") if cfg else ""

        # Then anything already recorded in config, then explicit overrides.
        if cfg is not None:
            section = "gate.bt_panel" if kind == KIND_BT else "gate.dsh_gate"
            for f in fields(cls):
                if f.name in ("kind", "pass_hash", "username",
                              "settings_patches"):
                    continue
                val = cfg.get("%s.%s" % (section, f.name), None)
                if val not in (None, "", []):
                    setattr(spec, f.name, val)
            user = cfg.get("%s.username" % section, "")
            if user:
                spec.username = user

        for k, v in (overrides or {}).items():
            if v is not None and hasattr(spec, k):
                setattr(spec, k, v)

        # The captcha and logout endpoints are *derived* from the entry
        # path, never inherited independently. Reading them from config let
        # one gate's paths leak into the other, producing a snippet that
        # served the wrong endpoints.
        _derive_endpoints(spec)

        # Derived invariants that must hold whatever the caller passed.
        if spec.proxy_mode and not spec.listen_port:
            spec.listen_port = 4399
        if spec.use_https and not spec.cert_dir and spec.proxy_mode:
            spec.cert_dir = "/www/server/panel/vhost/cert/local-%d" % spec.listen_port
        if not spec.nav_cookie and spec.proxy_mode:
            spec.nav_cookie = "dshnav"
        return spec

    @classmethod
    def from_dict(cls, data: dict) -> "GateSpec":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in (data or {}).items() if k in known})
