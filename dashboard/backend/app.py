"""The HTTP surface: JSON API, server-sent events, and static files.

Runs on 127.0.0.1 behind nginx. Only the API and the SSE stream live here;
the pages themselves are served straight off disk by nginx, so a busy map
never puts a Python process in the path of a static asset.

Response shape is uniform::

    {"ok": true,  "data": {...}}
    {"ok": false, "error": "readable message", "code": 403}

Security posture, given that this process runs as root and exposes a file
browser to the internet:

* bound to the loopback interface, never 0.0.0.0;
* the session cookie must survive a same-site check *and* the caller must
  echo the session token in ``X-Vigil-Token``, so a cross-site form post
  cannot mutate anything;
* requests are refused when the Host header is not the panel's own, which
  kills DNS-rebinding against the loopback listener;
* destructive file operations need a confirmation token that the server
  minted for that exact path, so a stray click cannot delete a tree.
"""
from __future__ import annotations

import errno
import hashlib
import hmac
import json
import mimetypes
import os
import queue
import re
import secrets
import socket
import sys
import threading
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import audit, auth, fs, geo, settings, sites, store, threat
from . import resources as res

API_PREFIX = "/api/v1"
CONFIRM_TTL = 300
COOKIE = "vigil_session"
JSON_CT = "application/json; charset=utf-8"

#: Tokens for destructive operations, minted per path.
_confirmations: dict = {}
_confirm_lock = threading.Lock()

#: Browser-side error reports, rate limited so a broken page in a loop cannot
#: fill the disk with its own complaints.
_clientlog_state: dict = {}
_clientlog_lock = threading.Lock()


def _mint_confirmation(path: str) -> str:
    token = secrets.token_urlsafe(18)
    with _confirm_lock:
        now = time.time()
        for key in [k for k, v in _confirmations.items() if v["exp"] < now]:
            _confirmations.pop(key, None)
        _confirmations[token] = {"path": os.path.realpath(path), "exp": now + CONFIRM_TTL}
    return token


def _check_confirmation(token: str, path: str) -> bool:
    with _confirm_lock:
        rec = _confirmations.pop(token or "", None)
    if not rec:
        return False
    if rec["exp"] < time.time():
        return False
    return rec["path"] == os.path.realpath(path)


def _host_ok(host_header: str) -> bool:
    if not host_header:
        return True
    host = host_header.split(":")[0].strip().lower().strip("[]")
    if host in ("127.0.0.1", "localhost", "::1", settings.HOSTNAME.lower()):
        return True
    # The hostname this console is published under, in either spelling: the
    # ASCII form certificates and vhosts use, and the Unicode form a person
    # types. Both come from configuration, not from this file.
    allowed = {name for name in (settings.PUBLIC_HOST.lower(),
                                 settings.DISPLAY_HOST.lower()) if name}
    if host in allowed:
        return True
    for base in allowed:
        if host.endswith("." + base):
            return True
    # Anything else the operator listed: an apex domain, an alias, one of
    # their other sites. These only reach this listener through nginx, which
    # is also what rewrites the peer address.
    for extra in settings.EXTRA_HOSTS:
        if host == extra or host.endswith("." + extra):
            return True
    return False


class Handler(BaseHTTPRequestHandler):
    server_version = "vigil-dashboard"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # -- plumbing --------------------------------------------------------

    def log_message(self, fmt, *args):      # noqa: A003 - stdlib signature
        # Keep the journal readable: one line per API call is noise, and the
        # access log is nginx's job anyway.
        pass

    def _note_operator(self) -> None:
        """Remember that the caller is the operator, by address.

        Called on a successful login. The operator's own requests are then
        never published on the public map, so nobody watching the dashboard
        can work out which address administers it -- or where the person
        running it lives. Also withdraws any marks already published from that
        address, which would otherwise linger until the traces expired.
        """
        ip = self._client_ip()
        if ip and ip not in ("-", "127.0.0.1", "::1"):
            store.mark_operator(ip)
            store.hub.forget_source(ip)

    def _client_ip(self) -> str:
        fwd = self.headers.get("X-Forwarded-For") or self.headers.get("X-Real-IP")
        if fwd and settings.PANEL_HOST in ("127.0.0.1", "::1", "localhost"):
            first = fwd.split(",")[0].strip()
            if first:
                return first
        return self.client_address[0] if self.client_address else "-"

    def _cookies(self) -> dict:
        raw = self.headers.get("Cookie") or ""
        out = {}
        for part in raw.split(";"):
            if "=" in part:
                key, _, val = part.partition("=")
                out[key.strip()] = val.strip()
        return out

    def _session(self) -> tuple:
        """Resolve the caller's session.

        Two carriers are accepted. The cookie is the normal one; the
        ``X-Vigil-Token`` header is the fallback, and it is also what every
        mutation already has to echo, so a client that carries the token in
        a header is equally authenticated and slightly harder to attack
        because nothing rides along automatically.

        The cookie is deliberately *not* marked Secure here. The service
        speaks plain HTTP to nginx on loopback, and a Secure cookie is one
        that well-behaved agents refuse to send over http -- which is
        precisely how the first end-to-end test failed. nginx adds the flag
        on the way out with ``proxy_cookie_flags``.
        """
        token = self._cookies().get(COOKIE) or ""
        rec = auth.auth.get_session(token)
        if rec:
            return token, rec
        header = (self.headers.get("X-Vigil-Token") or "").strip()
        if header:
            rec = auth.auth.get_session(header)
            if rec:
                return header, rec
        return "", {}

    def _require_admin(self) -> tuple:
        token, rec = self._session()
        if not rec:
            self._json({"ok": False, "error": "\u8bf7\u5148\u767b\u5f55", "code": 401}, 401)
            return "", {}
        if rec.get("role") != auth.ROLE_ADMIN:
            self._json({"ok": False, "error": "\u6743\u9650\u4e0d\u8db3", "code": 403}, 403)
            return "", {}
        header = (self.headers.get("X-Vigil-Token") or "").strip()
        if not header or not hmac.compare_digest(header, token):
            self._json({"ok": False,
                        "error": "\u4f1a\u8bdd\u6821\u9a8c\u5931\u8d25\uff0c\u8bf7\u5237\u65b0\u9875\u9762\u91cd\u8bd5",
                        "code": 403}, 403)
            return "", {}
        return token, rec

    # -- responses -------------------------------------------------------

    def _send(self, status: int, body: bytes, ctype: str,
              extra: dict = None, head_only: bool = False) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for key, val in (extra or {}).items():
            self.send_header(key, val)
        self.end_headers()
        if not head_only:
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

    def _json(self, payload: dict, status: int = 200, extra: dict = None) -> None:
        body = json.dumps(payload, ensure_ascii=False,
                          separators=(",", ":")).encode("utf-8")
        self._send(status, body, JSON_CT, extra)

    def _error(self, message: str, code: int = 400) -> None:
        self._json({"ok": False, "error": message, "code": code}, code)

    def _body(self, limit: int = 8 * 1024 * 1024) -> bytes:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return b""
        if length > limit:
            raise ValueError("请求体过大")
        return self.rfile.read(length)

    def _json_body(self) -> dict:
        raw = self._body()
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ValueError("请求体不是合法 JSON")
        if not isinstance(data, dict):
            raise ValueError("请求体应为 JSON 对象")
        return data

    # -- verbs -----------------------------------------------------------

    def do_GET(self):                                   # noqa: N802
        self._dispatch("GET")

    def do_HEAD(self):                                  # noqa: N802
        self._dispatch("HEAD")

    def do_POST(self):                                  # noqa: N802
        self._dispatch("POST")

    def do_PUT(self):                                   # noqa: N802
        self._dispatch("PUT")

    def do_DELETE(self):                                # noqa: N802
        self._dispatch("DELETE")

    def do_OPTIONS(self):                               # noqa: N802
        self._send(204, b"", "text/plain",
                   {"Allow": "GET,HEAD,POST,PUT,DELETE,OPTIONS"})

    # -- routing ---------------------------------------------------------

    def _dispatch(self, method: str) -> None:
        if not _host_ok(self.headers.get("Host") or ""):
            self._error("Host 校验失败", 421)
            return
        parsed = urllib.parse.urlparse(self.path)
        path = urllib.parse.unquote(parsed.path)
        query = urllib.parse.parse_qs(parsed.query)
        head_only = method == "HEAD"
        try:
            if path.startswith(API_PREFIX):
                self._api(method, path[len(API_PREFIX):] or "/", query, head_only)
            else:
                self._static(path, head_only)
        except BrokenPipeError:
            pass
        except Exception as exc:                        # noqa: BLE001
            try:
                self._error("服务内部错误：%s" % exc, 500)
            except Exception:                           # noqa: BLE001
                pass

    # -- API -------------------------------------------------------------

    def _api(self, method: str, route: str, query: dict,
             head_only: bool = False) -> None:
        route = route.rstrip("/") or "/"

        # ---- public read-only ------------------------------------------
        if route == "/state" and method in ("GET", "HEAD"):
            history = int((query.get("history") or ["0"])[0] or 0)
            attacks = (query.get("attacks") or ["0"])[0] == "1"
            # Resource sampling is opt-in here. The home page runs it on its
            # own timer against /resources, so bundling it into every snapshot
            # meant shipping and parsing the same 5 KiB twice, and it tied the
            # resource readout to the event stream's cadence.
            want_resources = (query.get("resources") or ["0"])[0] == "1"
            payload = store.hub.snapshot(history=min(400, max(0, history)),
                                         include_attacks=attacks)
            if want_resources:
                payload["resources"] = res.sampler.snapshot()
            self._json({"ok": True, "data": payload})
            return

        if route == "/world" and method in ("GET", "HEAD"):
            self._send_world(head_only)
            return

        if route == "/traffic" and method in ("GET", "HEAD"):
            # One snapshot, not three: each call rebuilds and sorts the whole
            # counter table.
            snap = store.hub.snapshot(include_attacks=True)
            payload = {
                "ts": snap["ts"],
                "traffic": snap["traffic"],
                "threat": store.hub._threat_summary(),
                "recent_attacks": snap["recent_attacks"],
            }
            self._json({"ok": True, "data": payload})
            return

        if route == "/resources" and method in ("GET", "HEAD"):
            self._json({"ok": True, "data": res.sampler.snapshot()})
            return

        if route == "/stream" and method == "GET":
            self._stream(query)
            return

        if route == "/session" and method == "GET":
            token, rec = self._session()
            # The session token is handed back so the page can echo it in
            # X-Vigil-Token. That header has to carry the *session* token: the
            # cookie is HttpOnly and therefore unreadable from script, and the
            # mutating endpoints compare the header against the cookie
            # token -- sending the CSRF value there is what produced
            # "会话校验失败" immediately after a successful login.
            self._json({"ok": True, "data": {
                "authenticated": bool(rec),
                "role": rec.get("role") or "",
                "expires": rec.get("expires") or 0,
                "dashboard_password": auth.auth.dashboard_password_set(),
                "root_credential": bool(auth.auth._shadow_hash()),
                # Unicode form: this is the vhost we serve on, not the
                # machine, and punycode reads as gibberish in a header chip.
                "host": settings.DISPLAY_HOST,
                # Session token, for the X-Vigil-Token header (see above).
                "token": token,
            }})
            return

        if route == "/login" and method == "POST":
            self._login()
            return

        if route == "/admin/operator" and method in ("GET", "POST"):
            # Loopback-only, like /admin/unlock: this changes what the public
            # page is allowed to reveal, so it must not be reachable through
            # nginx (which rewrites the peer to the real client address).
            if not (self.client_address and
                    self.client_address[0] in ("127.0.0.1", "::1")):
                self._error("仅允许本机调用", 403)
                return
            if method == "GET":
                now = time.time()
                marks = [{"ip": ip, "remaining": max(0, int(exp - now))}
                         for ip, exp in store.operator_marks().items()]
                self._json({"ok": True, "data": {"operators": marks}})
                return
            try:
                body = self._json_body()
            except ValueError:
                body = {}
            ip = str(body.get("ip") or "").strip()
            if not ip:
                self._error("缺少 ip", 400)
                return
            store.mark_operator(ip)
            removed = store.hub.forget_source(ip)
            audit.record("admin_operator", ip=self._client_ip(), ok=True,
                         detail="登记运维方地址 %s，撤销 %d 条记录" % (ip, removed))
            self._json({"ok": True, "data": {"ip": ip, "removed": removed}})
            return

        if route == "/admin/unlock" and method == "POST":
            # Loopback-only maintenance hook used by `vigil-dash unlock`.
            # It cannot be reached through nginx, because nginx rewrites the
            # peer to the real client address via X-Forwarded-For.
            if not (self.client_address and
                    self.client_address[0] in ("127.0.0.1", "::1")):
                self._error("仅允许本机调用", 403)
                return
            try:
                body = self._json_body()
            except ValueError:
                body = {}
            cleared = auth.auth.clear_failures(str(body.get("ip") or ""))
            audit.record("admin_unlock", ip=self._client_ip(), ok=True,
                         detail="清除登录失败记录 %d 条" % cleared)
            self._json({"ok": True, "data": {"cleared": cleared}})
            return

        if route == "/clientlog" and method == "POST":
            # Browser-side failure reporting. The pages call this from their
            # own error handlers, so it must stay cheap, unauthenticated and
            # impossible to turn into a log flood.
            ip = self._client_ip()
            try:
                body = self._json_body()
            except ValueError:
                body = {}
            page = str(body.get("page") or "?")[:20]
            kind = str(body.get("kind") or "?")[:40]
            detail = str(body.get("detail") or "")[:500]
            with _clientlog_lock:
                now = time.time()
                if now - _clientlog_state.get("at", 0) > 60:
                    _clientlog_state["at"] = now
                    _clientlog_state["count"] = 0
                _clientlog_state["count"] = _clientlog_state.get("count", 0) + 1
                allowed = _clientlog_state["count"] <= 30
            if allowed:
                sys.stderr.write("[client] %s %s %s %s\n" % (page, kind, ip, detail))
                sys.stderr.flush()
                audit.record("client_" + kind.replace(" ", "_"), ip=ip,
                             target=page, ok=False, detail=detail)
            self._json({"ok": True, "data": {"recorded": allowed}})
            return

        if route == "/health":
            self._json({"ok": True, "data": {
                "ts": time.time(), "pid": os.getpid(),
                "subscribers": store.hub.subscriber_count(),
                "geo": geo.geo.stats(),
            }})
            return

        # ---- management -------------------------------------------------
        if route == "/logout" and method == "POST":
            token, _rec = self._session()
            ip = self._client_ip()
            auth.auth.destroy_session(token)
            audit.record("logout", ip=ip, ok=True)
            self._json({"ok": True, "data": {"logged_out": True}},
                       extra={"Set-Cookie": self._clear_cookie()})
            return

        if route == "/sites" and method in ("GET", "HEAD"):
            _t, rec = self._require_admin()
            if not rec:
                return
            self._json({"ok": True, "data": {
                "sites": sites.sites.list_sites(),
                "deny_list": sites.sites.global_deny_list(120),
            }})
            return

        if route == "/sites/switch" and method == "POST":
            token, rec = self._require_admin()
            if not rec:
                return
            self._site_switch(rec)
            return

        if route == "/sites/test" and method == "POST":
            _t, rec = self._require_admin()
            if not rec:
                return
            ok, detail = sites.sites.test_config()
            self._json({"ok": True, "data": {"valid": ok,
                                             "detail": detail.strip()[-2000:]}})
            return

        if route == "/panels" and method in ("GET", "HEAD"):
            _t, rec = self._require_admin()
            if not rec:
                return
            self._json({"ok": True, "data": {"panels": settings.settings.panels}})
            return

        if route == "/services" and method in ("GET", "HEAD"):
            _t, rec = self._require_admin()
            if not rec:
                return
            self._json({"ok": True, "data": {
                "services": settings.settings.local_services}})
            return

        if route.startswith("/fs"):
            self._fs_api(method, route, query)
            return

        if route == "/audit" and method in ("GET", "HEAD"):
            _t, rec = self._require_admin()
            if not rec:
                return
            limit = int((query.get("limit") or ["120"])[0] or 120)
            self._json({"ok": True, "data": {
                "events": audit.tail(min(500, max(1, limit))),
                "log": str(settings.AUDIT_LOG),
            }})
            return

        if route == "/diagnostics" and method in ("GET", "HEAD"):
            _t, rec = self._require_admin()
            if not rec:
                return
            from . import tailer
            self._json({"ok": True, "data": {
                "config": settings.settings.as_dict(),
                "tailer": tailer_holder.get("tailer").stats()
                if tailer_holder.get("tailer") else {},
                "geo": geo.geo.stats(),
                "sessions": auth.auth.session_count(),
                "subscribers": store.hub.subscriber_count(),
                "sites": sites.sites.state_summary(),
                "audit_file": str(settings.AUDIT_LOG),
            }})
            return

        self._error("未知接口：%s" % route, 404)

    # -- auth ------------------------------------------------------------

    @staticmethod
    def _clear_cookie() -> str:
        return ("%s=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
                % COOKIE)

    def _login(self) -> None:
        ip = self._client_ip()
        wait = auth.auth.throttle(ip)
        if wait > 0:
            audit.record("login", ip=ip, ok=False,
                         detail="尝试过于频繁，剩余 %ds" % wait)
            self._json({"ok": False,
                        "error": "\u5c1d\u8bd5\u6b21\u6570\u8fc7\u591a\uff0c\u8bf7 %d \u79d2\u540e\u518d\u8bd5" % wait,
                        "code": 429}, 429)
            return
        try:
            body = self._json_body()
        except ValueError as exc:
            self._error(str(exc), 400)
            return
        account = str(body.get("account") or "").strip()
        password = str(body.get("password") or "")
        # The account name is configuration (`console_account`), never a
        # literal in this file. It used to be the operator's own site name,
        # written as a \u escape so a plain grep would not see it -- the same
        # disclosure with a different spelling, and exactly what the release
        # audit exists to prevent.
        if not settings.settings.console_account \
                or account != str(settings.settings.console_account):
            auth.auth.note_failure(ip)
            audit.record("login", actor=account, ip=ip, ok=False,
                         detail="账号不匹配")
            self._json({"ok": False, "error": "\u8d26\u53f7\u6216\u5bc6\u7801\u9519\u8bef",
                        "code": 401}, 401)
            return
        ok, method = auth.auth.verify_password(password)
        if not ok:
            auth.auth.note_failure(ip)
            audit.record("login", actor=account, ip=ip, ok=False,
                         detail="密码校验失败（%s）" % method)
            self._json({"ok": False, "error": "\u8d26\u53f7\u6216\u5bc6\u7801\u9519\u8bef",
                        "code": 401}, 401)
            return
        auth.auth.note_success(ip)
        token, rec = auth.auth.create_session(
            ip, self.headers.get("User-Agent") or "", auth.ROLE_ADMIN)
        audit.record("login", actor=account, ip=ip, ok=True,
                     detail="登录成功（凭据来源：%s）" % method)
        self._note_operator()
        # No Secure flag: nginx terminates TLS and adds it (see _session).
        cookie = ("%s=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict"
                  % (COOKIE, token, int(float(settings.settings.session_days) * 86400)))
        csrf = hashlib.sha256(("csrf" + token).encode()).hexdigest()[:32]
        self._json({"ok": True, "data": {"role": auth.ROLE_ADMIN,
                                         "expires": rec["expires"],
                                         "csrf": csrf,
                                         # See the /session route: the header
                                         # must carry the session token, not
                                         # the CSRF value.
                                         "token": token,
                                         "credential": method}},
                   extra={"Set-Cookie": cookie,
                          "X-Vigil-Csrf": csrf})

    # -- sites -----------------------------------------------------------

    def _site_switch(self, rec: dict) -> None:
        ip = self._client_ip()
        actor = "admin"
        try:
            body = self._json_body()
        except ValueError as exc:
            self._error(str(exc), 400)
            return
        key = str(body.get("key") or "").strip()
        blocked = bool(body.get("blocked"))
        allow = body.get("allow") or []
        note = str(body.get("note") or "")[:160]
        if not key or not re.match(r"^[A-Za-z0-9._-]+$", key):
            self._error("站点标识非法", 400)
            return
        try:
            result = sites.sites.set_blocked(key, blocked, allow=allow,
                                             note=note, operator=actor)
        except sites.NginxError as exc:
            audit.record("site_switch", actor=actor, ip=ip, target=key,
                         ok=False, detail=str(exc))
            self._json({"ok": False, "error": str(exc),
                        "detail": exc.detail[-1500:], "code": 500}, 500)
            return
        audit.record("site_switch", actor=actor, ip=ip, target=key, ok=True,
                     detail="关闭站点" if blocked else "放行站点",
                     extra={"allow": allow, "reloaded": result.get("reloaded")})
        self._json({"ok": True, "data": result})

    # -- filesystem ------------------------------------------------------

    def _fs_api(self, method: str, route: str, query: dict) -> None:
        _t, rec = self._require_admin()
        if not rec:
            return
        ip = self._client_ip()

        if route == "/fs/list" and method in ("GET", "HEAD"):
            path = (query.get("path") or ["/"])[0]
            show_hidden = (query.get("hidden") or ["1"])[0] != "0"
            sort = (query.get("sort") or ["name"])[0]
            try:
                data = fs.filesystem.listing(path, show_hidden, sort)
            except fs.FsError as exc:
                self._json({"ok": False, "error": str(exc), "code": exc.code},
                           exc.code)
                return
            self._json({"ok": True, "data": data})
            return

        if route == "/fs/read" and method in ("GET", "HEAD"):
            path = (query.get("path") or [""])[0]
            try:
                data = fs.filesystem.read(path)
            except fs.FsError as exc:
                self._json({"ok": False, "error": str(exc), "code": exc.code},
                           exc.code)
                return
            self._json({"ok": True, "data": data})
            return

        if route == "/fs/download" and method in ("GET", "HEAD"):
            self._fs_download(query)
            return

        if route == "/fs/tree" and method in ("GET", "HEAD"):
            path = (query.get("path") or ["/"])[0]
            depth = int((query.get("depth") or ["1"])[0] or 1)
            try:
                data = fs.filesystem.tree(path, depth)
            except fs.FsError as exc:
                self._json({"ok": False, "error": str(exc), "code": exc.code},
                           exc.code)
                return
            self._json({"ok": True, "data": data})
            return

        if route == "/fs/du" and method in ("GET", "HEAD"):
            path = (query.get("path") or ["/"])[0]
            try:
                data = fs.filesystem.du(path)
            except fs.FsError as exc:
                self._json({"ok": False, "error": str(exc), "code": exc.code},
                           exc.code)
                return
            self._json({"ok": True, "data": data})
            return

        if route == "/fs/search" and method in ("GET", "HEAD"):
            path = (query.get("path") or ["/"])[0]
            pattern = (query.get("q") or [""])[0]
            content = (query.get("content") or ["0"])[0] == "1"
            try:
                data = fs.filesystem.search(path, pattern, content=content)
            except fs.FsError as exc:
                self._json({"ok": False, "error": str(exc), "code": exc.code},
                           exc.code)
                return
            self._json({"ok": True, "data": data})
            return

        if route == "/fs/write" and method == "POST":
            try:
                body = self._json_body()
                data = fs.filesystem.write(str(body.get("path") or ""),
                                           str(body.get("content") or ""))
            except (fs.FsError, ValueError) as exc:
                code = getattr(exc, "code", 400)
                audit.record("fs_write", ip=ip, ok=False, detail=str(exc))
                self._json({"ok": False, "error": str(exc), "code": code}, code)
                return
            audit.record("fs_write", ip=ip, target=data["path"], ok=True,
                         detail="%d 字节" % data["bytes"])
            self._json({"ok": True, "data": data})
            return

        if route == "/fs/mkdir" and method == "POST":
            try:
                body = self._json_body()
                data = fs.filesystem.mkdir(str(body.get("path") or ""))
            except (fs.FsError, ValueError) as exc:
                code = getattr(exc, "code", 400)
                self._json({"ok": False, "error": str(exc), "code": code}, code)
                return
            audit.record("fs_mkdir", ip=ip, target=data["path"], ok=True)
            self._json({"ok": True, "data": data})
            return

        if route == "/fs/rename" and method == "POST":
            try:
                body = self._json_body()
                data = fs.filesystem.rename(str(body.get("path") or ""),
                                            str(body.get("target") or ""))
            except (fs.FsError, ValueError) as exc:
                code = getattr(exc, "code", 400)
                self._json({"ok": False, "error": str(exc), "code": code}, code)
                return
            audit.record("fs_rename", ip=ip, target=data["from"], ok=True,
                         detail="-> %s" % data["to"])
            self._json({"ok": True, "data": data})
            return

        if route == "/fs/chmod" and method == "POST":
            try:
                body = self._json_body()
                data = fs.filesystem.chmod(str(body.get("path") or ""),
                                           str(body.get("mode") or ""))
            except (fs.FsError, ValueError) as exc:
                code = getattr(exc, "code", 400)
                self._json({"ok": False, "error": str(exc), "code": code}, code)
                return
            audit.record("fs_chmod", ip=ip, target=data["path"], ok=True,
                         detail=data["mode"])
            self._json({"ok": True, "data": data})
            return

        if route == "/fs/confirm" and method == "POST":
            try:
                body = self._json_body()
                raw = body.get("paths")
                paths = [str(p) for p in (raw if isinstance(raw, list) else [raw]) if p]
                if not paths:
                    raise fs.FsError("缺少路径")
                resolved = [fs.filesystem.resolve(p) for p in paths]
                token = secrets.token_urlsafe(18)
                with _confirm_lock:
                    now = time.time()
                    for k in [k for k, v in _confirmations.items() if v["exp"] < now]:
                        _confirmations.pop(k, None)
                    _confirmations[token] = {"path": "\n".join(sorted(resolved)),
                                             "exp": now + CONFIRM_TTL}
            except (fs.FsError, ValueError) as exc:
                code = getattr(exc, "code", 400)
                self._json({"ok": False, "error": str(exc), "code": code}, code)
                return
            self._json({"ok": True, "data": {"token": token, "ttl": CONFIRM_TTL,
                                             "paths": resolved}})
            return

        if route == "/fs/delete" and method == "POST":
            try:
                body = self._json_body()
                raw = body.get("paths")
                paths = [str(p) for p in (raw if isinstance(raw, list) else [raw]) if p]
                if not paths:
                    raise fs.FsError("缺少路径")
                resolved = [fs.filesystem.resolve(p) for p in paths]
                token = str(body.get("token") or "")
                with _confirm_lock:
                    rec2 = _confirmations.pop(token, None)
                if not rec2 or rec2["exp"] < time.time() or \
                        rec2["path"] != "\n".join(sorted(resolved)):
                    raise fs.FsError("确认令牌无效或已过期，请重新确认", 403)
                data = fs.filesystem.remove(resolved)
            except (fs.FsError, ValueError) as exc:
                code = getattr(exc, "code", 400)
                audit.record("fs_delete", ip=ip, ok=False, detail=str(exc))
                self._json({"ok": False, "error": str(exc), "code": code}, code)
                return
            audit.record("fs_delete", ip=ip, ok=True,
                         detail="删除 %d 项" % len(data["removed"]),
                         extra={"removed": data["removed"][:40],
                                "failed": data["failed"][:10]})
            self._json({"ok": True, "data": data})
            return

        if route == "/fs/upload" and method == "POST":
            self._fs_upload(query)
            return

        self._error("未知文件接口：%s" % route, 404)

    def _fs_download(self, query: dict) -> None:
        path = (query.get("path") or [""])[0]
        try:
            target = fs.filesystem.resolve(path)
        except fs.FsError as exc:
            self._json({"ok": False, "error": str(exc), "code": exc.code},
                       exc.code)
            return
        if not os.path.isfile(target):
            self._error("不是普通文件", 400)
            return
        try:
            size = os.path.getsize(target)
        except OSError as exc:
            self._error("无法读取：%s" % exc, 400)
            return
        name = os.path.basename(target)
        ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(size))
        self.send_header("Content-Disposition",
                         "attachment; filename*=UTF-8''%s"
                         % urllib.parse.quote(name))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            with open(target, "rb") as fh:
                while True:
                    chunk = fh.read(256 * 1024)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def _fs_upload(self, query: dict) -> None:
        ip = self._client_ip()
        directory = (query.get("path") or ["/"])[0]
        raw_name = (query.get("name") or [""])[0]
        try:
            target = fs.filesystem.make_upload_path(directory, raw_name)
            fs.filesystem.check_writable(target)
        except fs.FsError as exc:
            self._json({"ok": False, "error": str(exc), "code": exc.code},
                       exc.code)
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        maximum = int(settings.settings.upload_max)
        if length <= 0:
            self._error("缺少上传内容", 400)
            return
        if length > maximum:
            self._error("文件超过上限 %d MiB" % (maximum // 1048576), 413)
            return
        tmp = target + ".vigilpart"
        written = 0
        try:
            with open(tmp, "wb") as fh:
                remaining = length
                while remaining > 0:
                    chunk = self.rfile.read(min(256 * 1024, remaining))
                    if not chunk:
                        break
                    fh.write(chunk)
                    written += len(chunk)
                    remaining -= len(chunk)
            os.replace(tmp, target)
            try:
                os.chmod(target, 0o644)
            except OSError:
                pass
        except OSError as exc:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            audit.record("fs_upload", ip=ip, target=target, ok=False,
                         detail=str(exc))
            self._error("写入失败：%s" % exc, 500)
            return
        audit.record("fs_upload", ip=ip, target=target, ok=True,
                     detail="%d 字节" % written)
        self._json({"ok": True, "data": {"path": target, "bytes": written}})

    # -- SSE -------------------------------------------------------------

    def _stream(self, query: dict) -> None:
        token, sub = store.hub.subscribe()
        try:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store, no-transform")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
        except OSError:
            store.hub.unsubscribe(token)
            return

        read_every = float(settings.settings.read_interval)
        sample_every = float(settings.settings.sample_interval)
        try:
            self._sse_event("hello", {"ts": time.time(), "interval": read_every,
                                      # coordinates only, same as the snapshot
                                      "server": {"lat": settings.SERVER_LAT,
                                                 "lon": settings.SERVER_LON}})
            # Backfill only what is genuinely recent. The ring holds a few
            # minutes of events and every new connection gets it in full, so
            # handing all of it over made an attack from earlier look like it
            # was happening again on each page load.
            # Same short window as the page's own backfill: a new connection
            # gets the last few seconds so the stream is not empty, not a
            # slice of unrelated history.
            backfill_cutoff = time.time() - 10.0
            for item in store.hub.history(120):
                if (item.get("nt") or item.get("t") or 0) < backfill_cutoff:
                    continue
                self._sse_event("traffic", item)
            last_sample = 0.0
            last_ping = time.time()
            empty_rounds = 0
            while True:
                items = sub.drain(240)
                now = time.time()
                for item in items:
                    self._sse_event("traffic", item)
                if now - last_sample >= sample_every:
                    last_sample = now
                    self._sse_event("resources", res.sampler.latest())
                    self._sse_event("summary", self._summary())
                    empty_rounds = 0
                if not items:
                    empty_rounds += 1
                    # Idle: wait a little longer, but never go silent long
                    # enough for a proxy to drop the connection.
                    if now - last_ping >= 15:
                        self._sse_event("ping", {"ts": now,
                                                 "subs": store.hub.subscriber_count()})
                        last_ping = now
                    time.sleep(min(1.0, read_every * (1 + empty_rounds // 10)))
                if self._client_gone():
                    break
        except (BrokenPipeError, ConnectionResetError, OSError, ValueError):
            pass
        finally:
            store.hub.unsubscribe(token)

    def _client_gone(self) -> bool:
        try:
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            return True
        return False

    def _summary(self) -> dict:
        """The periodic roll-up the page paints KPIs from.

        The per-detector and per-reason breakdowns used to ride along here for
        a panel that no longer shows them, and `minute_series` is dropped
        because the page counts attacks as they stream in -- it never needed
        the server's tally for that.
        """
        snap = store.hub.snapshot()
        traffic = snap["traffic"]
        return {
            "ts": snap["ts"],
            "traffic": {
                "total": traffic["total"],
                "rpm": traffic["rpm"],
                "epm": traffic.get("epm", 0),
                "levels": traffic["levels"],
                "countries": traffic["countries"],
                "local": traffic["local"],
                "minute_series": traffic["minute_series"],
            },
            "threat": snap["threat"],
            "subs": store.hub.subscriber_count(),
        }

    def _sse_event(self, name: str, payload: dict) -> None:
        blob = "event: %s\ndata: %s\n\n" % (
            name, json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
        self.wfile.write(blob.encode("utf-8"))
        self.wfile.flush()

    # -- static ----------------------------------------------------------

    def _send_world(self, head_only: bool) -> None:
        path = settings.DATA / "world.json"
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
        except OSError:
            self._error("地图数据缺失，请重新执行 tools/build-map.py", 500)
            return
        self._send(200, blob, JSON_CT,
                   {"Cache-Control": "public, max-age=86400"}, head_only)

    def _static(self, path: str, head_only: bool) -> None:
        """Last-resort static serving; nginx normally handles the pages."""
        root = os.path.realpath(".")
        rel = os.path.normpath(path.lstrip("/")) if path != "/" else "index.html"
        candidate = os.path.realpath(os.path.join(root, rel))
        if not candidate.startswith(root):
            self._error("路径非法", 403)
            return
        if os.path.isdir(candidate):
            candidate = os.path.join(candidate, "index.html")
        try:
            with open(candidate, "rb") as fh:
                blob = fh.read()
        except OSError:
            self._send(404, b"404 - not found", "text/plain; charset=utf-8",
                       head_only=head_only)
            return
        ctype = mimetypes.guess_type(candidate)[0] or "application/octet-stream"
        self._send(200, blob, ctype, head_only=head_only)


#: Keeps a handle on the tailer for the diagnostics endpoint without making
#: it a module-level import cycle.
tailer_holder: dict = {}


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128
    #: SSE connections are long-lived; a short socket timeout would kill them.
    timeout = 300


def build_server(host: str = None, port: int = None) -> Server:
    host = host or settings.PANEL_HOST
    port = int(port or settings.PANEL_PORT)
    if ":" in host:
        class V6Server(Server):
            address_family = socket.AF_INET6
        srv = V6Server((host, port), Handler)
    else:
        srv = Server((host, port), Handler)
    return srv
