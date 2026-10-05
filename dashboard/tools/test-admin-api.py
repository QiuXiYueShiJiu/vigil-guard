#!/usr/bin/env python3
"""End-to-end check of the management API against a live instance.

Starts nothing itself: point it at a running dashboard (default
http://127.0.0.1:9310) or a scratch instance via --base.

    tools/test-admin-api.py                      # needs a dashboard on 9310
    tools/test-admin-api.py --base http://127.0.0.1:9315

It creates a dashboard-specific password for the run and removes it
afterwards, so it never needs to know root's password. The root-password
path is the same ``verify_password`` branch and is covered by
tests/unit-tests.py through ``crypt``.
"""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

ACCOUNT = "\u79cb\u5915\u6708\u62fe\u65e7" "0926"
TEST_PASSWORD = "Vigil-Console-Selftest-2026"
LANCZOS = "\u4e2d\u6587\u6d4b\u8bd5\u5185\u5bb9 line2"


class Client:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = ""
        self.token = ""

    def call(self, path, method="GET", body=None, expect_ok=True, raw=False):
        url = self.base + "/api/v1" + path
        data = None
        # The tests carry the session token in a header as well as the cookie,
        # which is the documented fallback and makes the checks independent of
        # cookie policies over plain HTTP.
        headers = {"X-Vigil-Token": self.token or self.csrf}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=30) as res:
                payload = res.read()
                status = res.status
                self.csrf = res.headers.get("X-Vigil-Csrf") or self.csrf
                cookie = res.headers.get("Set-Cookie") or ""
                if "vigil_session=" in cookie:
                    self.token = cookie.split("vigil_session=", 1)[1].split(";", 1)[0]
                    headers_token = self.token
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            status = exc.code
        parsed = None
        if payload:
            try:
                parsed = json.loads(payload.decode())
            except ValueError:
                parsed = {"raw": payload[:200].decode("utf-8", "replace")}
        if raw:
            return status, parsed
        if expect_ok and (not parsed or parsed.get("ok") is not True):
            raise AssertionError("%s %s -> %s %s"
                                 % (method, path, status, json.dumps(parsed)[:300]))
        return parsed.get("data") if parsed else None


class Report:
    def __init__(self):
        self.passed = 0
        self.failed = []

    def check(self, label, condition, detail=""):
        if condition:
            self.passed += 1
            print("  ok   %s" % label)
        else:
            self.failed.append("%s %s" % (label, detail))
            print("  FAIL %s %s" % (label, detail))

    def done(self):
        print("\n%d checks passed, %d failed" % (self.passed, len(self.failed)))
        for item in self.failed:
            print("  - %s" % item)
        return 1 if self.failed else 0


def restore_site_backup(key: str) -> None:
    """Undo whatever the site-switch test did to one vhost."""
    from backend import settings, sites
    site = {s["key"]: s for s in sites.sites.list_sites()}.get(key)
    if site:
        sites.sites._strip_include(site["conf"])
    snippet = sites.sites.snippet_path(key)
    if os.path.exists(snippet):
        os.unlink(snippet)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:9310")
    ap.add_argument("--scratch", action="store_true",
                    help="start a private instance on port 9315 and stop it after")
    ap.add_argument("--site", default="",
                    help="vhost key to flip during the test (default: pick one)")
    args = ap.parse_args()

    proc = None
    base = args.base
    if args.scratch:
        env = dict(os.environ, VIGIL_DASH_PORT="9315")
        proc = subprocess.Popen([sys.executable, os.path.join(ROOT, "backend", "serve.py")],
                                env=env, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, cwd=ROOT)
        base = "http://127.0.0.1:9315"
        time.sleep(4)

    report = Report()
    client = Client(base)
    password_file = "/var/lib/vigil-dashboard/dashboard-password.json"
    saved_password = None
    if os.path.exists(password_file):
        saved_password = open(password_file, "rb").read()

    from backend import auth as authmod
    from backend import settings, sites

    # Clear any login-failure history for loopback before starting: earlier
    # runs of this very test are what fill it up, and a 429 would otherwise
    # make the suite fail on its own past behaviour.
    try:
        with authmod.auth._lock:
            authmod.auth._failures.pop("127.0.0.1", None)
            authmod.auth._save()
    except Exception:                               # noqa: BLE001
        pass

    try:
        print("── public surface ──")
        session = client.call("/session")
        report.check("session endpoint reports unauthenticated",
                     session and session.get("authenticated") is False)
        health = client.call("/health")
        report.check("health endpoint", health and health.get("pid"))
        state = client.call("/state?history=5")
        report.check("state endpoint", state and "threat" in state)
        report.check("state omits resources by default",
                     "resources" not in state)
        # resources is opt-in on /state now; the page pulls it separately so
        # the per-second snapshot stays small. Ask for it like a client does.
        state_res = client.call("/state?resources=1")
        report.check("state carries live resource sample",
                     state_res.get("resources", {}).get("cpu") is not None)

        print("── authentication ──")
        status, payload = client.call("/login", "POST",
                                      {"account": ACCOUNT, "password": "definitely-wrong"},
                                      expect_ok=False, raw=True)
        report.check("wrong password rejected", status == 401, "status=%s" % status)
        status, payload = client.call("/login", "POST",
                                      {"account": "someone-else", "password": TEST_PASSWORD},
                                      expect_ok=False, raw=True)
        report.check("wrong account rejected", status == 401, "status=%s" % status)

        status, payload = client.call("/sites", expect_ok=False, raw=True)
        report.check("management requires a session", status == 401, "status=%s" % status)

        auth = client.call("/login", "POST",
                           {"account": ACCOUNT, "password": TEST_PASSWORD},
                           expect_ok=False, raw=True)
        if auth[1] and auth[1].get("ok"):
            # A dashboard password was already configured and happens to match.
            pass
        else:
            from backend import auth as authmod
            authmod.auth.set_dashboard_password(TEST_PASSWORD)
            auth = client.call("/login", "POST",
                               {"account": ACCOUNT, "password": TEST_PASSWORD},
                               expect_ok=False, raw=True)
        status, payload = auth
        report.check("login with the configured password succeeds", status == 200,
                     "status=%s %s" % (status, json.dumps(payload)[:200]))
        if payload and payload.get("ok"):
            client.csrf = payload["data"].get("csrf") or ""
        report.check("csrf token issued", bool(client.csrf))

        status, payload = client.call("/sites", expect_ok=False, raw=True)
        report.check("management reachable after login", status == 200, "status=%s" % status)

        print("── filesystem ──")
        listing = client.call("/fs/list?path=/root&hidden=0")
        report.check("list /root", listing and listing.get("count", 0) > 0)
        report.check("listing reports disk usage", listing.get("usage") is not None)

        scratch = "/tmp/vigil-dashboard-selftest"
        client.call("/fs/mkdir", "POST", {"path": scratch})
        report.check("mkdir", os.path.isdir(scratch))

        target = os.path.join(scratch, "hello.txt")
        client.call("/fs/write", "POST", {"path": target, "content": LANCZOS})
        with open(target, "r", encoding="utf-8") as fh:
            report.check("write persists UTF-8", fh.read() == LANCZOS)

        readback = client.call("/fs/read?path=" + urllib.parse.quote(target))
        report.check("read returns the same bytes", readback["content"] == LANCZOS)

        client.call("/fs/write", "POST", {"path": target, "content": "second"})
        backups = [n for n in os.listdir(scratch) if ".vigilbak." in n]
        report.check("overwrite leaves a backup", len(backups) == 1, str(backups))

        status, payload = client.call("/fs/read?path=/etc/shadow",
                                      expect_ok=False, raw=True)
        report.check("deny list blocks /etc/shadow", status == 403, "status=%s" % status)
        status, payload = client.call("/fs/list?path=/proc/self",
                                      expect_ok=False, raw=True)
        report.check("deny list blocks /proc", status == 403, "status=%s" % status)

        status, payload = client.call("/fs/delete", "POST",
                                      {"paths": [target], "token": "bogus"},
                                      expect_ok=False, raw=True)
        report.check("delete without a valid token is refused", status == 403,
                     "status=%s" % status)

        token = client.call("/fs/confirm", "POST", {"paths": [target]})
        client.call("/fs/delete", "POST", {"paths": [target], "token": token["token"]})
        report.check("confirmed delete removes the file", not os.path.exists(target))

        # upload, mirroring what the browser does
        blob = b"upload-body-" + os.urandom(16)
        url = (base + "/api/v1/fs/upload?path=" + urllib.parse.quote(scratch)
               + "&name=uploaded.bin")
        # Without the token header the upload must be refused outright.
        bare = urllib.request.Request(url, data=blob, method="POST",
                                      headers={"Content-Type": "application/octet-stream"})
        try:
            with client.opener.open(bare, timeout=30) as res:
                refused = res.status
        except urllib.error.HTTPError as exc:
            refused = exc.code
        report.check("upload without the token is refused", refused == 403,
                     "status=%s" % refused)

        req = urllib.request.Request(url, data=blob, method="POST",
                                     headers={"X-Vigil-Token": client.token or client.csrf,
                                              "Content-Type": "application/octet-stream"})
        with client.opener.open(req, timeout=30) as res:
            up = json.loads(res.read().decode())
        report.check("upload accepted", up.get("ok") is True)
        with open(os.path.join(scratch, "uploaded.bin"), "rb") as fh:
            report.check("upload body intact", fh.read() == blob)
        report.check("delete of a directory tree",
                     client.call("/fs/confirm", "POST", {"paths": [scratch]}) is not None)
        token = client.call("/fs/confirm", "POST", {"paths": [scratch]})
        client.call("/fs/delete", "POST", {"paths": [scratch], "token": token["token"]})
        report.check("scratch directory gone", not os.path.exists(scratch))

        print("── sites ──")
        data = client.call("/sites")
        report.check("site list non-empty", len(data.get("sites") or []) > 0)
        report.check("deny list reported", "deny_list" in data)
        key = args.site or (data["sites"][0]["key"] if data["sites"] else "")
        if key:
            site = [s for s in data["sites"] if s["key"] == key][0]
            conf_original = open(site["conf"], "r", encoding="utf-8").read()
            snippet = site["snippet"]
            snippet_existed = os.path.exists(snippet)
            snippet_original = open(snippet, "r", encoding="utf-8").read() if snippet_existed else None
            try:
                res = client.call("/sites/switch", "POST",
                                  {"key": key, "blocked": True, "note": "selftest"})
                report.check("switch closes a site", res.get("blocked") is True)
                report.check("nginx -t passed during the switch", "ok" in (res.get("test") or "")
                             or "successful" in (res.get("test") or "")
                             or "test is successful" in (res.get("test") or ""),
                             (res.get("test") or "")[:200])
                body = open(snippet, "r", encoding="utf-8").read()
                report.check("snippet contains deny all", "deny all;" in body)
                report.check("include injected into vhost",
                             "vigil-dashboard-sites" in open(site["conf"], "r", encoding="utf-8").read())
                res2 = client.call("/sites/switch", "POST",
                                   {"key": key, "blocked": False, "note": "selftest"})
                report.check("switch reopens a site", res2.get("blocked") is False)
                report.check("snippet cleared", "deny all;" not in
                             open(snippet, "r", encoding="utf-8").read())
                # simulate a bad config: a deliberately broken snippet
                os.makedirs(os.path.dirname(snippet), exist_ok=True)
                with open(snippet, "w") as fh:
                    fh.write("this is not valid nginx;\n")
                status, payload = client.call("/sites/test", "POST",
                                              expect_ok=False, raw=True)
                report.check("nginx -t detects a broken snippet",
                             bool(payload) and payload.get("ok") is True
                             and payload["data"]["valid"] is False,
                             json.dumps(payload)[:200])
            finally:
                with open(site["conf"], "w", encoding="utf-8") as fh:
                    fh.write(conf_original)
                if snippet_existed:
                    with open(snippet, "w", encoding="utf-8") as fh:
                        fh.write(snippet_original or "")
                elif os.path.exists(snippet):
                    os.unlink(snippet)
                ok, detail = sites.sites.test_config()
                report.check("config restored and valid", ok, detail[-200:])
                sites.sites.reload()
        else:
            report.check("a site was available to switch", False, "none found")

        print("── audit + diagnostics ──")
        audit = client.call("/audit?limit=50")
        report.check("audit log has entries", len(audit.get("events") or []) > 0)
        actions = [e.get("action") for e in audit["events"]]
        report.check("audit recorded the login", "login" in actions, str(actions[:8]))
        report.check("audit recorded the file write", "fs_write" in actions, str(actions[:8]))
        diag = client.call("/diagnostics")
        report.check("diagnostics returns config", "config" in diag and "tailer" in diag)

        print("── authorization ──")
        status, payload = client.call("/fs/list?path=/", method="GET",
                                      expect_ok=False, raw=True)
        report.check("still authorized after all of that", status == 200)

        client.call("/logout", "POST")
        status, payload = client.call("/sites", expect_ok=False, raw=True)
        report.check("logout ends the session", status == 401, "status=%s" % status)

    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
        if args.site or True:
            try:
                restore_site_backup(args.site)
            except Exception:                       # noqa: BLE001
                pass
        # Never leave the throwaway password behind: it is a known credential.
        try:
            from backend import auth as authmod
            if saved_password is None:
                authmod.auth.clear_dashboard_password()
                authmod.auth.destroy_all()
            else:
                with open(password_file, "wb") as fh:
                    fh.write(saved_password)
        except Exception:                           # noqa: BLE001
            pass

    return report.done()


if __name__ == "__main__":
    sys.exit(main())
