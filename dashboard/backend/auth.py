"""Sign-in for the management console.

Exactly one credential opens this console: the password hash kept in
PASSWORD_FILE, set with ``vigil-dash set-password``. Nothing else is
consulted -- in particular the machine's root password is **not** accepted.
An earlier version fell back to root's ``/etc/shadow`` entry, which made the
login page a second door into the server for anyone who had ever learned that
password; it is also why the page used to advertise "the same as root", a
sentence that handed a visitor the credential's origin for free.

Sessions are opaque random tokens mapped to a file under ``/var/lib``; the
cookie is HttpOnly + SameSite=Strict, and the token itself is never
accepted from a query string. Login attempts are rate limited per address.
"""
from __future__ import annotations

import base64
import crypt
import hashlib
import hmac
import json
import os
import secrets
import threading
import time

from . import settings

ROLE_ADMIN = "admin"
ROLE_GUEST = "guest"


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Auth:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: dict = {}
        self._failures: dict = {}            # ip -> [timestamps]
        self._persist_mtime = 0.0
        self._load()

    # -- persistence -----------------------------------------------------

    def _load(self) -> None:
        settings.ensure_state_dir()
        try:
            with open(settings.SESSIONS_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                self._sessions = data.get("sessions") or {}
                self._failures = data.get("failures") or {}
        except (OSError, ValueError):
            self._sessions, self._failures = {}, {}

    def _save(self) -> None:
        tmp = settings.SESSIONS_FILE.with_suffix(".tmp")
        payload = {"sessions": self._sessions, "failures": self._failures}
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            os.chmod(tmp, 0o600)
            os.replace(tmp, settings.SESSIONS_FILE)
        except OSError:
            pass

    # -- credentials -----------------------------------------------------

    @staticmethod
    def _shadow_hash() -> str:
        try:
            with open("/etc/shadow", "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.startswith("root:"):
                        return line.split(":", 2)[1].strip()
        except OSError:
            return ""
        return ""

    def dashboard_password_set(self) -> bool:
        try:
            with open(settings.PASSWORD_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return bool(data.get("hash"))
        except (OSError, ValueError):
            return False

    def set_dashboard_password(self, plain: str, method: str = "sha256") -> None:
        """Store a dashboard-only password (independent of root)."""
        settings.ensure_state_dir()
        if method == "sha256":
            digest = hashlib.sha256(plain.encode("utf-8")).hexdigest()
            blob = {"algo": "sha256", "hash": digest, "set": time.time()}
        else:
            salt = crypt.mksalt(crypt.METHOD_SHA512)
            blob = {"algo": "crypt", "hash": crypt.crypt(plain, salt),
                    "set": time.time()}
        tmp = settings.PASSWORD_FILE.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(blob, fh)
        os.chmod(tmp, 0o600)
        os.replace(tmp, settings.PASSWORD_FILE)

    def clear_dashboard_password(self) -> None:
        try:
            os.unlink(settings.PASSWORD_FILE)
        except OSError:
            pass

    def verify_password(self, plain: str) -> tuple:
        """``(ok, method)``. Never raises, never logs the password."""
        plain = plain or ""
        if not plain:
            return False, "empty"
        # 1) dashboard-specific password
        try:
            with open(settings.PASSWORD_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            algo = data.get("algo") or "sha256"
            stored = data.get("hash") or ""
            if stored:
                if algo == "sha256":
                    ok = hmac.compare_digest(
                        stored, hashlib.sha256(plain.encode("utf-8")).hexdigest())
                else:
                    try:
                        ok = hmac.compare_digest(stored, crypt.crypt(plain, stored))
                    except (ValueError, OSError):
                        ok = False
                if ok:
                    return True, "dashboard"
        except (OSError, ValueError):
            pass

        # No fallback to root. There used to be one -- the console accepted the
        # server's root password as well -- which meant the login page was a
        # second door into the machine for anyone who had ever learned that
        # password, and it is why the old page advertised "same as root". The
        # console now has exactly one credential: the one stored in
        # PASSWORD_FILE, set with `vigil-dash set-password`.
        return False, "dashboard"

    # -- rate limiting ---------------------------------------------------

    def throttle(self, ip: str) -> int:
        """Seconds the caller must wait, 0 when allowed to try now."""
        now = time.time()
        window = float(settings.settings.login_fail_window)
        limit = int(settings.settings.login_fail_limit)
        with self._lock:
            hist = [t for t in self._failures.get(ip, []) if now - t < window]
            self._failures[ip] = hist
            if len(hist) >= limit:
                return int(window - (now - hist[0])) + 1
        return 0

    def note_failure(self, ip: str) -> None:
        with self._lock:
            self._failures.setdefault(ip, []).append(time.time())
            if len(self._failures) > 5000:
                for key in list(self._failures)[:2000]:
                    self._failures.pop(key, None)
            self._save()

    def note_success(self, ip: str) -> None:
        with self._lock:
            self._failures.pop(ip, None)

    # -- sessions --------------------------------------------------------

    def create_session(self, ip: str, ua: str, role: str = ROLE_ADMIN) -> tuple:
        token = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
        now = time.time()
        days = float(settings.settings.session_days)
        rec = {"role": role, "ip": ip, "ua": (ua or "")[:160],
               "created": now, "expires": now + days * 86400,
               "last": now, "fp": _hash_token((ua or "")[:160])[:16]}
        with self._lock:
            self._prune_locked(now)
            self._sessions[_hash_token(token)] = rec
            while len(self._sessions) > int(settings.settings.max_sessions):
                oldest = min(self._sessions,
                             key=lambda k: self._sessions[k].get("last", 0))
                self._sessions.pop(oldest, None)
            self._save()
        return token, rec

    def _prune_locked(self, now: float) -> None:
        for key in [k for k, v in self._sessions.items()
                    if float(v.get("expires") or 0) < now]:
            self._sessions.pop(key, None)

    def get_session(self, token: str, touch: bool = True) -> dict:
        if not token:
            return {}
        key = _hash_token(token)
        now = time.time()
        with self._lock:
            self._prune_locked(now)
            rec = self._sessions.get(key)
            if not rec:
                return {}
            if float(rec.get("expires") or 0) < now:
                self._sessions.pop(key, None)
                self._save()
                return {}
            if touch and now - float(rec.get("last") or 0) > 300:
                rec["last"] = now
                self._save()
            return dict(rec)

    def destroy_session(self, token: str) -> None:
        if not token:
            return
        with self._lock:
            self._sessions.pop(_hash_token(token), None)
            self._save()

    def clear_failures(self, ip: str = "") -> int:
        """Forget login-throttle history, for one address or all of them.

        Exposed because the counter is in memory: an operator locked out by
        their own testing has no way to wait 15 minutes gracefully, and the
        alternative (restarting the service) throws away the event history
        the console is watching.
        """
        with self._lock:
            if ip:
                removed = 1 if self._failures.pop(ip, None) else 0
            else:
                removed = len(self._failures)
                self._failures = {}
            self._save()
        return removed

    def destroy_all(self) -> int:
        with self._lock:
            count = len(self._sessions)
            self._sessions = {}
            self._save()
        return count

    def session_count(self) -> int:
        with self._lock:
            self._prune_locked(time.time())
            return len(self._sessions)


auth = Auth()
