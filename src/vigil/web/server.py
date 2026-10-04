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


class Handler(BaseHTTPRequestHandler):
    server_version = "vigil"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    cfg = None
    sessions = _Sessions()
    attempts = _Attempts()
    csrf = {}

    # -- plumbing ---------------------------------------------------------

    def log_message(self, fmt, *args):                          # noqa: A003
        # The default writes every request to stderr, which on a monitored host
        # means the journal fills with page loads. Keep it to one line, and
        # only when something went wrong enough to be worth reading.
        if getattr(self, "_logged", False):
            return

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
        with threading.Lock():
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
            key = self.client_address[0]
            if self.attempts.blocked(key):
                return self._html(HTTPStatus.TOO_MANY_REQUESTS, page_mod.login_page(
                    title="vigil · 登录", error="尝试次数过多，请稍后再试"))
            user = (form.get("username") or [""])[0]
            pwd = (form.get("password") or [""])[0]
            if not verify_password(self.cfg, user, pwd):
                self.attempts.bump(key)
                return self._html(HTTPStatus.UNAUTHORIZED, page_mod.login_page(
                    title="vigil · 登录", error="账号或密码不正确"))
            tok = self.sessions.new()
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


def make_server(cfg, host: str = "127.0.0.1", port: int = None) -> ThreadingHTTPServer:
    bind_port = int(port or (cfg.get("web.port", 9177) if cfg else 9177))
    handler = type("BoundHandler", (Handler,), {"cfg": cfg})
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
