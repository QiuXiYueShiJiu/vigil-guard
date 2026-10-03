"""Where a self-change reports to: the operator, and the upstream project.

Two destinations, deliberately:

* **mail, before the change.** A system that edits itself without telling anyone
  first is indistinguishable from one that has been compromised. The mail states
  exactly what will change, why, and how to stop it.
* **the project's own endpoint, after the change.** The loop records what it did
  so the change can be read back and, if it turns out to generalise, shipped to
  everyone in a normal release. This is the "learn from the fleet" half.

Nothing identifying the host is sent: no addresses, no hostname, no site names,
no config values -- only the shape of the change (kind, target key, before/after
for bounded numerics, counts). A telemetry channel that leaks the thing the
product protects would be a poor joke.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

#: Where reports go. Deliberately **empty** by default.
#:
#: A compiled-in collector URL would mean a shipped file contains one specific
#: deployment's domain -- which is exactly what `core/sourceaudit.py` refuses to
#: let into the package, and it caught this line during development of this very
#: feature. Point `evolve.report_url` at your collector, or leave it empty and
#: nothing is sent: a host with no outbound network is a supported setup.
DEFAULT_URL = ""

#: Keys that must never leave the host, whatever a caller passes.
_FORBIDDEN = ("ip", "addr", "hostname", "domain", "email", "token", "secret",
              "password", "key", "whitelist", "webroot", "path", "site")


def scrub(payload: dict) -> dict:
    """Drop anything host-identifying. Shape is kept, identity is not."""
    out = {}
    for k, v in (payload or {}).items():
        low = str(k).lower()
        if any(bad in low for bad in _FORBIDDEN):
            continue
        if isinstance(v, dict):
            out[k] = scrub(v)
        elif isinstance(v, (list, tuple)):
            out[k] = [scrub(x) if isinstance(x, dict) else x for x in v[:50]]
        elif isinstance(v, (int, float, bool)) or v is None:
            out[k] = v
        else:
            out[k] = str(v)[:400]
    return out


def ascii_url(url: str) -> str:
    """Make a URL safe for a request line.

    `urllib` encodes the request line as latin-1, so a Unicode host -- an IDN
    like a Chinese domain -- raises before the request is even attempted. The
    fix is the standard one: IDNA-encode the host and percent-encode the path.
    Without this the reporting channel silently fails on exactly the kind of
    deployment most likely to want it.
    """
    text = str(url or "").strip()
    if not text:
        return ""
    try:
        parts = urllib.parse.urlsplit(text)
    except ValueError:
        return text
    host = parts.hostname or ""
    if not host:
        return text
    if any(ord(c) > 127 for c in host):
        host = host.encode("idna").decode("ascii")
    netloc = host
    if parts.port:
        netloc = "%s:%d" % (host, parts.port)
    if parts.username:
        auth = parts.username
        if parts.password:
            auth += ":" + parts.password
        netloc = "%s@%s" % (auth, netloc)
    path = urllib.parse.quote(parts.path or "/", safe="/%")
    query = urllib.parse.quote(parts.query, safe="=&%")
    return urllib.parse.urlunsplit((parts.scheme, netloc, path, query, ""))


def send_report(cfg, payload: dict) -> dict:
    """POST the report upstream. Returns a dict; never raises."""
    if cfg is not None and not bool(cfg.get("evolve.report_enabled", True)):
        return {"ok": False, "err": "已按配置关闭上报"}
    url = DEFAULT_URL
    if cfg is not None:
        url = str(cfg.get("evolve.report_url", DEFAULT_URL) or "").strip()
    if not url:
        return {"ok": False, "err": "未配置上报地址（evolve.report_url），仅写本地台账"}
    url = ascii_url(url)
    if not url:
        return {"ok": False, "err": "上报地址无效"}
    body = json.dumps({"schema": 1, "payload": scrub(payload)},
                      ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json; charset=utf-8",
                 "User-Agent": "vigil-evolve/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return {"ok": r.status in (200, 201, 202), "status": r.status,
                    "body": r.read(300).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code,
                "err": e.read(200).decode("utf-8", "replace")[:200]}
    except Exception as e:                                     # noqa: BLE001
        return {"ok": False, "err": str(e)[:200]}


def mail(cfg, title: str, lines: list, severity: str = "info", log=None) -> bool:
    """One message out. Uses the same channel as every other alert, so the
    operator has a single place to look and a single place to mute."""
    try:
        from ..mail import send_alert
        from ..mail.message import Alert, KIND_ALERT, SEV_CRIT, SEV_INFO, SEV_WARN
    except Exception:                                          # noqa: BLE001
        return False
    sev = {"crit": SEV_CRIT, "warn": SEV_WARN}.get(str(severity).lower(), SEV_INFO)
    try:
        alert = Alert(title=title, severity=sev, kind=KIND_ALERT,
                      dedupe_key="evolve|%s" % title)
        sec = alert.add_section("自修正")
        for line in lines:
            sec.add(line)
        return bool(send_alert(alert, cfg=cfg, log=log))
    except Exception:                                          # noqa: BLE001
        return False
