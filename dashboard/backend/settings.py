"""Runtime paths and tunables for the vigil dashboard.

Everything the dashboard knows about its host lives here, so the rest of the
code never has to build a path by hand. Values that an operator may want to
change between restarts can be overridden in ``config.json`` next to the
service; secrets never live in that file.

**Nothing that identifies a particular deployment has a default in this
file.** The published hostname, the site's display name, the web root and the
coordinates the map draws its arcs to are configuration: the values below are
placeholders, ``config.example.json`` documents them, and
``deploy/install.sh`` refuses to install while ``public_host`` is still the
placeholder. That is what keeps one operator's domain out of the published
package.
"""
from __future__ import annotations

import json
import os
import socket
from pathlib import Path

# --------------------------------------------------------------------------
# Where we are
# --------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent          # dashboard/
BACKEND = ROOT / "backend"
DATA = BACKEND / "data"
CONFIG_FILE = Path(os.environ.get("VIGIL_DASH_CONFIG", ROOT / "config.json"))
VENDOR = BACKEND / "vendor"

#: Files the service creates. ``/var/lib`` is the right place for state that
#: must survive a redeploy of the code tree.
STATE_DIR = Path(os.environ.get("VIGIL_DASH_STATE", "/var/lib/vigil-dashboard"))
SESSIONS_FILE = STATE_DIR / "sessions.json"
AUDIT_LOG = STATE_DIR / "audit.jsonl"
SECRET_FILE = STATE_DIR / "secret.key"
PASSWORD_FILE = STATE_DIR / "dashboard-password.json"

# --------------------------------------------------------------------------
# Host integration
# --------------------------------------------------------------------------

#: vigil's live threat ledger: bans, per-address offence counts and counters.
VIGIL_THREAT_STATE = Path("/var/lib/vigil/state/threat.json")
#: Raised when an attack is in progress. Read through the filesystem because
#: the flag lives in vigil's RuntimeDirectory, which systemd wipes on restart.
VIGIL_POSTURE_FLAG = Path("/run/vigil/posture.active")
#: GeoLite2 city database installed by the panel. Offline, so the dashboard
#: keeps working when the network is the thing being attacked.
GEODB_CANDIDATES = (
    Path("/www/server/panel/config/GeoLite2-City.mmdb"),
    Path("/www/server/panel/data/GeoLite2-City.mmdb"),
    DATA / "GeoLite2-City.mmdb",
)

#: nginx access logs, one file per public site.
LOG_DIR = Path("/www/wwwlogs")
#: Files in LOG_DIR that are not site traffic.
LOG_SKIP = {
    "access.log",            # the panel's own default vhost
    "nginx_error.log",
    "vigil-decoy.log",
    "vigil-login.log",
    "tcp-access.log",
    # The self-test writes synthetic requests into /www/wwwlogs so that it can
    # verify the real log-to-map path. Those lines are fixtures, not traffic,
    # but the collector could not tell them apart -- a test flood showed up on
    # the public page forever after, and its fixture address kept reappearing
    # on every refresh. The file exists only for the duration of a test run.
    "vigil-dashboard-selftest.log",
}
LOG_SUFFIX_DROP = (".error.log", ".error_log")

#: Big nginx controls.
NGINX_BIN = Path("/www/server/nginx/sbin/nginx")
NGINX_DENY_HTTP = Path("/www/server/nginx/conf/vigil-deny.conf")
VHOST_DIR = Path("/www/server/panel/vhost/nginx")
#: Our own per-site switches. One file per site, included from that site's
#: server block by the panel-side helper.
SITE_DIR = Path("/www/server/nginx/conf/vigil-dashboard-sites")
SITES_FILE = STATE_DIR / "sites.json"

PANEL_PORT = int(os.environ.get("VIGIL_DASH_PORT", "9310"))
PANEL_HOST = os.environ.get("VIGIL_DASH_BIND", "127.0.0.1")
HOSTNAME = socket.gethostname()


def display_domain(host: str) -> str:
    """punycode -> Unicode, for display only.

    The ASCII form is what certificates, vhost files and the Host header use,
    so it stays authoritative everywhere on disk and on the wire; a punycode
    label shown to a person is just noise. Decoding is per label, so
    ``a.xn--b.top`` works and a name that is already Unicode passes through.
    Falls back to the input whenever decoding is not possible.
    """
    if not host or "xn--" not in host:
        return host
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return host


# Backwards-compatible alias for the single-host case.
_display_host = display_domain


# --------------------------------------------------------------------------
# Tunables (overridable through config.json)
# --------------------------------------------------------------------------

DEFAULTS: dict = {
    # ── host identity ──────────────────────────────────────────────────
    # Every one of these is the operator's to set; the values here are
    # placeholders that identify nobody. `public_host` in particular is what
    # the Host check, the certificate path and the nginx vhost are built
    # from, and deploy/install.sh refuses to install while it is unset.
    "public_host": "status.example.com",
    #: Shown in the console chrome and the page title. Empty means "use the
    #: Unicode form of public_host".
    "display_name": "",
    #: Static web root nginx serves the pages from. Empty means the panel's
    #: convention for public_host.
    "webroot": "",
    #: Extra Host values this console answers to: the apex domain, the
    #: operator's other sites, an alias. Sub-domains of public_host are
    #: accepted automatically; anything else goes here.
    "extra_hosts": [],
    #: Where the traffic terminates, used to draw every arc. No default that
    #: means anything: the coordinates of a machine are exactly the kind of
    #: fact this repository does not carry.
    "server_lat": 0.0,
    "server_lon": 0.0,

    # ── quick links rendered by the management page ────────────────────
    # ``local`` entries are only reachable through the panel's gateway, so
    # they are shown as hints instead of being proxied. Kept as data rather
    # than markup so no deployment's URLs end up in the shipped HTML.
    "panels": [
        {"id": "vigil", "name": "Vigil 防护系统", "desc": "实时风控与封禁台账",
         "url": "/", "group": "应用"},
    ],
    #: Local (loopback-only) admin services, listed for convenience.
    "local_services": [
        {"name": "MySQL", "url": "127.0.0.1:3306", "note": "数据库，仅本机"},
    ],

    # Event pipeline
    "history": 900,              # events kept in memory for new visitors
    "max_events_per_poll": 400,  # ceiling per ingest pass, protects the CPU
    "poll_ms": 700,              # how often the log tailer reads (idle cost ~0)
    "geo_cache": 20000,          # addresses remembered, LRU
    "burst_window": 10.0,        # seconds used for the per-address rate
    "peak_window": 2.0,          # short window used to judge pressure
    # Rate only decides when the address is both fast in absolute terms and
    # far above what everyone else is doing. See threat.ThreatState.classify.
    "attack_rate": 6.0,          # req/s that starts to look like hammering
    "pressure_rate": 25.0,       # req/s that looks like a flood
    "rate_outlier_factor": 6.0,  # multiple of the median rate required
    "rate_hold": 20.0,           # seconds a rate verdict suppresses the next one
    "read_interval": 8.0,        # seconds between file pushes to a browser
    "sample_interval": 2.0,      # seconds between resource samples pushed
    "cpu_history": 120,          # samples kept for the sparklines
    "processes": 8,              # rows in the process table

    # Auth
    "session_days": 7,
    "max_sessions": 40,
    "login_fail_window": 900,    # seconds
    "login_fail_limit": 8,       # attempts per window per address

    # File manager
    "fs_root": "/",              # browsing is allowed anywhere below this
    "upload_max": 512 * 1024 * 1024,
    "read_max": 4 * 1024 * 1024,
    "deny_paths": [
        "/proc", "/sys", "/dev", "/run",
        "/etc/shadow", "/etc/gshadow", "/etc/sudoers",
        "/root/.ssh", "/root/.config/gh", "/root/.config/gh-token",
        "/www/server/panel/data/default.db",
    ],
    # Paths the console refuses to *modify* even though root could. Reading is
    # still allowed: seeing them is how you operate a server.
    "readonly_paths": [
        "/boot", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt",
        "/var/lib/mysql", "/www/server/mysql", "/www/server/panel",
    ],
}


def _load_overrides() -> dict:
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        return {}


class Settings:
    """Attribute access over the merged defaults, refreshed on demand."""

    def __init__(self) -> None:
        self.reload()

    def reload(self) -> None:
        merged = dict(DEFAULTS)
        merged.update(_load_overrides())
        self._d = merged

    def __getattr__(self, name: str):
        try:
            return self._d[name]
        except KeyError as exc:                     # pragma: no cover
            raise AttributeError(name) from exc

    def as_dict(self) -> dict:
        return dict(self._d)


settings = Settings()


# --------------------------------------------------------------------------
# Resolved at import, from the configuration above
#
# Module attributes rather than ``settings.settings.foo`` because that is how
# the rest of the code (and the operator's own scripts) reads them.
# --------------------------------------------------------------------------

#: Published hostname in its ASCII form -- what certificates, vhost files and
#: the Host header use. A placeholder until the operator configures one.
PUBLIC_HOST = str(settings.public_host or "").strip()

#: What the console shows in its own chrome: an explicit ``display_name`` if
#: the operator set one, otherwise the Unicode form of the published host.
DISPLAY_HOST = (str(settings.display_name or "").strip()
                or display_domain(PUBLIC_HOST))

#: Additional Host values this console answers to (apex domain, aliases, the
#: operator's other sites). Sub-domains of PUBLIC_HOST need no entry here.
EXTRA_HOSTS = tuple(
    str(item).strip().lower() for item in (settings.extra_hosts or [])
    if str(item).strip())

#: Static web root. Defaults to the panel's convention for PUBLIC_HOST.
WWWROOT = Path(str(settings.webroot or "").strip()
               or ("/www/wwwroot/" + PUBLIC_HOST))

#: TLS material the panel issued for the published host.
CERT_DIR = Path("/www/server/panel/vhost/cert") / PUBLIC_HOST

#: Where the traffic terminates. Used to draw every arc.
SERVER_LAT = float(settings.server_lat or 0.0)
SERVER_LON = float(settings.server_lon or 0.0)
#: Nothing about the host is published: no address, no hostname, no provider,
#: no city. The map draws a beacon at the coordinates above and says nothing
#: next to it; the coordinates themselves are required to draw the arcs.
SERVER_LABEL = ""

#: True while the host identity is still the shipped placeholder. The service
#: runs either way (so a half-configured install is visible and debuggable);
#: deploy/install.sh is what refuses to publish it.
HOST_IS_PLACEHOLDER = (PUBLIC_HOST in ("", "status.example.com"))


def ensure_state_dir() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(STATE_DIR, 0o750)
    except OSError:
        pass
