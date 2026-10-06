"""A small status/feedback server, standard library only.

Why it exists in this form
--------------------------
`vigil` already watches a host and already emails when something is wrong.
What it lacked was a place to *ask* it something without waiting for an alert.
This serves that page.

Design constraints, each for a reason:

* **Loopback only, by default.** It is proxied by the web server that is already
  there, so the process itself never needs to be reachable. Binding it publicly
  would mean re-implementing TLS, and getting that subtly wrong is how a status
  page becomes the weakest thing on the host.
* **Credentials are set on the machine, interactively, and only a hash is
  stored.** No default account, because a default account on a monitoring page
  is an unauthenticated admin panel with extra steps. The password lives in
  `secrets.json` (0600), never in the config file that gets shared in tickets.
* **No third-party dependency.** Same promise as the rest of the package: a
  locked-down host can run it.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import secrets as pysecrets
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from ..core import paths
from . import page as page_mod
from . import status as status_mod

#: PBKDF2 rounds. Chosen to be slow enough to matter for an offline crack and
#: fast enough that a login on a 1-core VPS is not a denial of service.
PBKDF2_ROUNDS = 240000

#: Login attempts per source address per window before it is refused outright.
LOGIN_MAX = 8
LOGIN_WINDOW = 600

#: Session lifetime. Short enough that a forgotten browser tab is not a
#: permanent key to the host's operational data.
SESSION_SECONDS = 3600

#: Direct peers whose ``X-Forwarded-For`` may be believed.
#:
#: The service binds loopback and is proxied by the web server that is already
#: there, so the socket peer is *always* the proxy. Rate limiting on
#: ``client_address`` therefore collapsed every visitor into one bucket, and a
#: stranger typing eight wrong passwords locked the operator out for ten
#: minutes. Reading the header instead is the fix -- but only from a peer that
#: is actually the proxy, otherwise any client can invent a fresh source
#: address per attempt and the limit stops existing in the other direction.
DEFAULT_TRUSTED_PROXIES = ("127.0.0.1/8", "::1")

#: Guards the CSRF table. It used to be a `with threading.Lock():` *inside*
#: :meth:`Handler._csrf_for` -- a brand-new lock per call, which excludes
#: nothing at all. Two threads issuing a token for the same session could then
#: race and overwrite each other, and the loser's form was rejected.
_CSRF_LOCK = threading.Lock()


def _norm_ip(text: str) -> str:
    """One IP address from whatever a peer or a forwarded header looks like.

    ``X-Forwarded-For`` may carry a port, brackets, or an IPv4-mapped IPv6
    form. Anything that is not an address is dropped rather than passed
    through: an unparsable value must never become a rate-limit key, or it
    would be its own bypass.
    """
    raw = str(text or "").strip()
    if not raw:
        return ""
    if raw.startswith("["):                      # [2001:db8::1]:443
        raw = raw[1:].split("]", 1)[0]
    elif raw.count(":") == 1:                    # 203.0.113.9:41234
        raw = raw.split(":", 1)[0]
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return ""
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return str(addr)


def _trusted_peer(peer: str, trusted=None) -> bool:
    """Is *peer* one of the reverse proxies we are allowed to believe?"""
    addr = _norm_ip(peer)
    if not addr:
        return False
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    for entry in (trusted if trusted is not None
                  else DEFAULT_TRUSTED_PROXIES):
        try:
            if "/" in str(entry):
                if ip in ipaddress.ip_network(str(entry), strict=False):
                    return True
            elif ip == ipaddress.ip_address(str(entry)):
                return True
        except ValueError:
            continue
    return False


def client_key(peer: str, forwarded_for: str = "", trusted=None) -> str:
    """The address a request is rate-limited against.

    Two failure modes have to be avoided at once, and they pull in opposite
    directions:

    * keying on the socket peer collapses every visitor behind a reverse
      proxy into one bucket -- eight wrong passwords from anyone locks out
      everyone (measured on this host: the peer was always ``127.0.0.1``);
    * believing ``X-Forwarded-For`` unconditionally lets a client mint a new
      source address per attempt, which is not a rate limit either.

    So the header is consulted **only** when the direct peer is a trusted
    proxy. Within the header the *rightmost* entry is the one the nearest
    proxy actually observed; everything to its left was supplied by the
    client and is not evidence. Trusted hops are skipped from the right, so a
    chain of proxies resolves to the first address that had to be real.
    """
    peer = _norm_ip(peer)
    if not _trusted_peer(peer, trusted):
        return peer or "unknown"
    hops = [h.strip() for h in str(forwarded_for or "").split(",")]
    for hop in reversed(hops):
        addr = _norm_ip(hop)
        if addr and not _trusted_peer(addr, trusted):
            return addr
    return peer or "unknown"


_DEFAULT_LOGGER = None


def _default_logger():
    # Cached: this is reached on every 4xx/5xx, and constructing a Logger
    # re-reads the logging configuration each time.
    global _DEFAULT_LOGGER
    if _DEFAULT_LOGGER is None:
        from ..core.logging import get as get_logger
        _DEFAULT_LOGGER = get_logger("web")
    return _DEFAULT_LOGGER


def hash_password(password: str, salt: str = "") -> tuple:
    salt = salt or pysecrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             salt.encode("utf-8"), PBKDF2_ROUNDS)
    return salt, dk.hex()


def verify_password(cfg, username: str, password: str) -> bool:
    want_user = str(cfg.get("web.username", "") or "")
    salt = str(cfg.secrets.get("web.password_salt", "") or "")
    want_hash = str(cfg.secrets.get("web.password_hash", "") or "")
    if not (want_user and salt and want_hash):
        return False
    # Compare both, and keep comparing even when the username is wrong: an
    # early return on the username turns the response time into a user oracle.
    _, got = hash_password(password, salt)
    user_ok = hmac.compare_digest(username, want_user)
    pass_ok = hmac.compare_digest(got, want_hash)
    return user_ok and pass_ok


def set_password(cfg, username: str, password: str) -> bool:
    salt, digest = hash_password(password)
    cfg.set("web.username", username)
    cfg.secrets["web.password_salt"] = salt
    cfg.secrets["web.password_hash"] = digest
    cfg.save()
    return True


def credentials_set(cfg) -> bool:
    return bool(cfg.get("web.username", "") and
                cfg.secrets.get("web.password_hash", ""))


class _Sessions:
    """In-memory sessions with expiry and a hard cap.

    In memory on purpose: restarting the service should log everyone out, and
    a session token written to disk is one more thing to leak.
    """

    def __init__(self, ttl: int = SESSION_SECONDS, cap: int = 500):
        self._d = {}
        self._lock = threading.Lock()
        self._ttl = max(60, int(ttl))
        self._cap = cap

    def new(self) -> str:
        tok = pysecrets.token_urlsafe(32)
        with self._lock:
            if len(self._d) >= self._cap:
                now = time.time()
                for k in [k for k, t in self._d.items() if now - t > self._ttl]:
                    self._d.pop(k, None)
                if len(self._d) >= self._cap:
                    self._d.clear()
            self._d[tok] = time.time()
        return tok

    def valid(self, tok: str) -> bool:
        if not tok:
            return False
        with self._lock:
            t = self._d.get(tok)
        return bool(t and (time.time() - t) <= self._ttl)

    def drop(self, tok: str) -> None:
        with self._lock:
            self._d.pop(tok, None)


class _Attempts:
    """Per-address login rate limit, so the page cannot be brute forced."""

    def __init__(self, limit: int = LOGIN_MAX, window: int = LOGIN_WINDOW):
        self._d = {}
        self._lock = threading.Lock()
        self._limit = limit
        self._window = window

    def blocked(self, key: str) -> bool:
        with self._lock:
            hits = [t for t in self._d.get(key, []) if time.time() - t < self._window]
            self._d[key] = hits
            return len(hits) >= self._limit

    def bump(self, key: str) -> None:
        with self._lock:
            self._d.setdefault(key, []).append(time.time())

    def clear(self, key: str) -> None:
        """Forget a source's failures after it authenticates successfully.

        Otherwise an operator who mistypes a few times and then gets it right
        still carries the strikes, and the next typo -- days later, if the
        window is generous -- is the one that locks them out.
        """
        with self._lock:
            self._d.pop(key, None)


class Handler(BaseHTTPRequestHandler):
    server_version = "vigil"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    cfg = None
    sessions = _Sessions()
    attempts = _Attempts()
    csrf = {}
    #: Addresses whose forwarding headers are believed. Overridden per server
    #: from ``web.trusted_proxies`` so a proxy on a non-loopback address can be
    #: declared; the default is loopback only, because that is where this
    #: service is designed to sit.
    trusted_proxies = DEFAULT_TRUSTED_PROXIES
    #: Logger for request/auth/5xx lines. A test passes its own object so a
    #: test run never appends to the host's real journal.
    logger = None

    # -- plumbing ---------------------------------------------------------

    def _log(self):
        return type(self).logger or _default_logger()

    def _client_key(self) -> str:
        peer = ""
        try:
            peer = self.client_address[0]
        except (TypeError, IndexError, AttributeError):
            peer = ""
        return client_key(peer, self.headers.get("X-Forwarded-For") or "",
                          getattr(type(self), "trusted_proxies", None))

    def log_message(self, fmt, *args):                          # noqa: A003
        """One line per request, at a level that matches its outcome.

        The previous override returned early and wrote *nothing*, so a failed
        login and a 500 left no trace anywhere: the operator could see that
        people were being locked out and never see who or why. Routine
        requests stay at DEBUG (invisible at the default INFO), while a 4xx
        or 5xx is recorded with the source it was attributed to.
        """
        try:
            text = (fmt % args) if args else str(fmt)
        except (TypeError, ValueError):
            text = "%s %s" % (fmt, args)
        code = 0
        for arg in args:
            try:
                value = int(arg)
            except (TypeError, ValueError):
                continue
            if 100 <= value <= 599:
                code = value
                break
        logger = self._log()
        if code >= 500:
            logger.error("web %s -> %d（来源 %s）", text, code, self._client_key())
        elif code >= 400:
            logger.warn("web %s -> %d（来源 %s）", text, code, self._client_key())
        else:
            logger.debug("web %s", text)

    def _send(self, code: int, body: bytes, ctype: str = "text/html; charset=utf-8",
              cookies=None, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "form-action 'self'; base-uri 'none'")
        for c in (cookies or []):
            self.send_header("Set-Cookie", c)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _html(self, code: int, text: str, cookies=None):
        self._send(code, text.encode("utf-8"), cookies=cookies)

    def _json(self, code: int, data: dict):
        self._send(code, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                   ctype="application/json; charset=utf-8")

    # -- auth -------------------------------------------------------------

    def _token(self) -> str:
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "vigil_session":
                return v
        return ""

    def _authed(self) -> bool:
        return self.sessions.valid(self._token())

    def _csrf_for(self, tok: str) -> str:
        # One lock for the table, not one per call: `with threading.Lock()`
        # created a fresh lock each time and therefore excluded nothing, so two
        # concurrent renders of the same session could overwrite each other's
        # token and one of the two forms would fail its CSRF check.
        with _CSRF_LOCK:
            v = self.csrf.get(tok)
            if not v:
                v = pysecrets.token_urlsafe(24)
                self.csrf[tok] = v
            return v

    def _csrf_ok(self, form: dict) -> bool:
        got = (form.get("csrf") or [""])[0]
        want = self.csrf.get(self._token(), "")
        return bool(got and want and hmac.compare_digest(got, want))

    def _gate(self) -> bool:
        """True when the request may proceed; sends the login page otherwise."""
        if self._authed():
            return True
        self._html(HTTPStatus.OK, page_mod.login_page(title="vigil · 登录"))
        return False

    # -- routes -----------------------------------------------------------

    def do_GET(self):                                           # noqa: N802
        path = urlsplit(self.path).path
        if path == "/healthz":
            return self._send(HTTPStatus.OK, b"ok", ctype="text/plain")
        if path == "/favicon.ico":
            return self._send(HTTPStatus.NO_CONTENT, b"", ctype="image/x-icon")
        if path == "/logout":
            self.sessions.drop(self._token())
            return self._html(HTTPStatus.OK, page_mod.login_page(
                title="vigil · 已退出"), cookies=["vigil_session=; Max-Age=0; Path=/; HttpOnly"])
        if not self._gate():
            return
        if path == "/api/status":
            data = status_mod.board(self.cfg)
            return self._json(HTTPStatus.OK, data)
        data = status_mod.board(self.cfg)
        cfg = self.cfg
        configured = credentials_set(cfg)
        flash = "" if configured else "尚未设置账号密码：请在本机执行 vigil web passwd"
        return self._html(HTTPStatus.OK, page_mod.status_page(
            title="vigil · %s" % data["host"]["hostname"],
            host=data["host"], cards=data["cards"], tables=data["tables"],
            flash=flash, flash_ok=configured,
            csrf=self._csrf_for(self._token()),
            feedback=status_mod.recent_feedback()))

    def do_POST(self):                                          # noqa: N802
        path = urlsplit(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        if length > 64 * 1024:
            return self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                              {"ok": False, "err": "请求过大"})
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        form = parse_qs(raw)

        if path == "/login":
            # Per *source*, not per socket peer. The service is loopback-only
            # behind nginx, so `client_address[0]` was "127.0.0.1" for every
            # visitor on earth: eight wrong passwords from any stranger locked
            # the operator out for ten minutes.
            key = self._client_key()
            if self.attempts.blocked(key):
                return self._html(HTTPStatus.TOO_MANY_REQUESTS, page_mod.login_page(
                    title="vigil · 登录", error="尝试次数过多，请稍后再试"))
            user = (form.get("username") or [""])[0]
            pwd = (form.get("password") or [""])[0]
            if not verify_password(self.cfg, user, pwd):
                self.attempts.bump(key)
                return self._html(HTTPStatus.UNAUTHORIZED, page_mod.login_page(
                    title="vigil · 登录", error="账号或密码不正确"))
            # Success clears the strikes for this source: the failures on the
            # way in were typos, not an attack, and leaving them counted means
            # the next typo is the one that locks the operator out.
            self.attempts.clear(key)
            old = self._token()
            tok = self.sessions.new()
            with _CSRF_LOCK:
                self.csrf.pop(old, None)
                # The empty key was never a session; dropping it was a no-op.
                self.csrf.pop("", None)
            return self._html(HTTPStatus.OK, page_mod.login_page(
                title="vigil · 已登录"), cookies=[
                    "vigil_session=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d"
                    % (tok, SESSION_SECONDS)])

        if not self._authed():
            return self._json(HTTPStatus.UNAUTHORIZED, {"ok": False, "err": "未登录"})
        if not self._csrf_ok(form):
            return self._json(HTTPStatus.FORBIDDEN, {"ok": False, "err": "CSRF 校验失败"})

        if path == "/feedback":
            text = (form.get("text") or [""])[0]
            src = str(self.cfg.get("web.domain", "") or self.headers.get("Host") or "")
            res = status_mod.add_feedback(self.cfg, text, src)
            data = status_mod.board(self.cfg)
            return self._html(HTTPStatus.OK if res.get("ok") else HTTPStatus.BAD_REQUEST,
                              page_mod.status_page(
                                  title="vigil · %s" % data["host"]["hostname"],
                                  host=data["host"], cards=data["cards"],
                                  tables=data["tables"],
                                  flash="反馈已提交" if res.get("ok") else res.get("err", "失败"),
                                  flash_ok=bool(res.get("ok")),
                                  csrf=self._csrf_for(self._token()),
                                  feedback=status_mod.recent_feedback()))
        return self._json(HTTPStatus.NOT_FOUND, {"ok": False, "err": "未知路径"})


def _trusted_from_cfg(cfg) -> tuple:
    """``web.trusted_proxies`` if set, else the loopback-only default."""
    try:
        entries = list(cfg.get("web.trusted_proxies",
                               list(DEFAULT_TRUSTED_PROXIES)) or [])
    except AttributeError:
        return DEFAULT_TRUSTED_PROXIES
    return tuple(entries) or DEFAULT_TRUSTED_PROXIES


def make_server(cfg, host: str = "127.0.0.1", port: int = None,
                logger=None) -> ThreadingHTTPServer:
    if port is None:
        bind_port = int(cfg.get("web.port", 9177) if cfg else 9177)
    else:
        # `port=0` must mean "any free port" (the test suite uses it); the old
        # `port or default` turned it into the configured port instead.
        bind_port = int(port)
    # Fresh rate-limit / session / CSRF state per server. These used to be
    # shared class attributes, so two servers in one process -- or two tests
    # in one suite -- counted each other's logins and a token issued by one
    # was accepted by the other.
    handler = type("BoundHandler", (Handler,), {
        "cfg": cfg,
        "sessions": _Sessions(),
        "attempts": _Attempts(),
        "csrf": {},
        "trusted_proxies": _trusted_from_cfg(cfg),
        "logger": logger,
    })
    srv = ThreadingHTTPServer((host, bind_port), handler)
    srv.daemon_threads = True
    return srv


def serve(cfg, host: str = "127.0.0.1", port: int = None, log=None) -> int:
    if not credentials_set(cfg):
        if log:
            log("尚未设置账号密码，页面会提示但不接受登录。"
                "请先执行：vigil web passwd")
    srv = make_server(cfg, host, port)
    if log:
        log("状态页已启动：http://%s:%d/（仅本机；对外请用 web.install 配置反代）"
            % (host, srv.server_address[1]))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0
