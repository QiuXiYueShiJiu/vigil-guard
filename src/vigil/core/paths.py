"""Filesystem layout.

Every path the project touches is declared here and **nowhere else**, so the
whole tree can be relocated for tests or for distributions that use a
different prefix.

Overrides (useful for tests and for packagers):

    VIGIL_ETC   config dir      default /etc/vigil
    VIGIL_VAR   persistent dir  default /var/lib/vigil
    VIGIL_LOG   log dir         default /var/log/vigil
    VIGIL_RUN   runtime dir     default /run/vigil

Nothing in this module is host specific: no hostname, no IP, no domain.
"""
from __future__ import annotations

import os
from pathlib import Path

# --------------------------------------------------------------------------
# Base directories
# --------------------------------------------------------------------------
ETC = Path(os.environ.get("VIGIL_ETC", "/etc/vigil"))
VAR = Path(os.environ.get("VIGIL_VAR", "/var/lib/vigil"))
LOG = Path(os.environ.get("VIGIL_LOG", "/var/log/vigil"))
RUN = Path(os.environ.get("VIGIL_RUN", "/run/vigil"))

# Where the Python package itself lives once installed.
LIB = Path(os.environ.get("VIGIL_LIB", "/usr/local/lib/vigil"))
BIN = Path(os.environ.get("VIGIL_BIN", "/usr/local/bin/vigil"))

# --------------------------------------------------------------------------
# Configuration files
# --------------------------------------------------------------------------
CONFIG = ETC / "config.json"           # machine readable, the single source of truth
SECRETS = ETC / "secrets.json"         # credentials, mode 0600
LEGACY_ENV = ETC / "mail.env"          # optional shell-style override (advanced users)

# --------------------------------------------------------------------------
# Persistent state (survives reboot, safe to delete)
# --------------------------------------------------------------------------
STATE_MAIL = VAR / "mail"              # sequence numbers, quota, overflow queue
STATE_STATE = VAR / "state"            # per-check hysteresis state
STATE_CACHE = VAR / "cache"            # geoip cache etc.
STATE_AUDIT = VAR / "auditd"           # audit watch bookkeeping
STATE_GATE = VAR / "gate"              # gate session bookkeeping

MAIL_SEQ = STATE_MAIL / "sequence"
MAIL_QUOTA = STATE_MAIL / "quota"      # per UTC-day counters
MAIL_PENDING = STATE_MAIL / "pending.jsonl"
MAIL_OVERFLOW = STATE_MAIL / "overflow"
MAIL_SUBJECTS = STATE_MAIL / "subjects.json"
MAIL_PROBE = STATE_MAIL / "probe.stamp"
MAIL_LOCK = STATE_MAIL / ".lock"

HEALTH_STATE = STATE_STATE / "health.json"
THREAT_STATE = STATE_STATE / "threat.json"
LOGIN_STATE = STATE_STATE / "login.json"
AV_OFFSET = STATE_STATE / "av-offset"
WEBSCAN_CACHE = STATE_STATE / "webscan.json"

GEOIP_CACHE = STATE_CACHE / "geoip.json"

# --------------------------------------------------------------------------
# Logs
# --------------------------------------------------------------------------
LOG_MAIN = LOG / "vigil.log"
LOG_MAIL = LOG / "mail.log"
LOG_THREAT = LOG / "threat.log"
LOG_HEALTH = LOG / "health.log"
LOG_LOGIN = LOG / "login.log"
LOG_COMMANDS = LOG / "commands.log"        # audit trail of remote command execution
LOG_GATE = LOG / "gate.log"

# --------------------------------------------------------------------------
# Runtime (pid files, locks; cleared on reboot)
# --------------------------------------------------------------------------
PID_THREAT = RUN / "threatd.pid"
LOCK_HEALTH = RUN / "healthd.lock"
LOCK_BACKUP = RUN / "backup.lock"
LOCK_THREAT = RUN / "threatd.lock"

# --------------------------------------------------------------------------
# systemd
# --------------------------------------------------------------------------
SYSTEMD_UNIT_DIR = Path("/etc/systemd/system")
UNIT_PREFIX = "vigil-"

# --------------------------------------------------------------------------
# Host integration points.
#
# These are *discovery defaults* only. The concrete values are resolved at
# install time by core.detect and stored in config.json; hardcoding them
# anywhere else would break portability, which is the whole point of the
# project.
# --------------------------------------------------------------------------
PANEL_CANDIDATES = (
    Path("/www/server/panel"),
    Path("/www/server/panel/"),
)
NGINX_CONF_CANDIDATES = (
    Path("/www/server/nginx/conf/nginx.conf"),
    Path("/etc/nginx/nginx.conf"),
)
NGINX_VHOST_DIR_CANDIDATES = (
    Path("/www/server/panel/vhost/nginx"),
    Path("/etc/nginx/conf.d"),
    Path("/etc/nginx/sites-enabled"),
)
PHP_FPM_GLOB = "/www/server/php/*/sbin/php-fpm"
WEBROOT_CANDIDATES = (Path("/www/wwwroot"), Path("/var/www"), Path("/var/www/html"))


def ensure_dirs() -> None:
    """Create every directory this project owns. Idempotent."""
    for d in (ETC, VAR, LOG, RUN, STATE_MAIL, STATE_STATE, STATE_CACHE,
              STATE_AUDIT, STATE_GATE):
        d.mkdir(parents=True, exist_ok=True)


def describe() -> dict:
    """Return the resolved layout, for `vigil doctor` and diagnostics."""
    return {
        "etc": str(ETC),
        "var": str(VAR),
        "log": str(LOG),
        "run": str(RUN),
        "lib": str(LIB),
        "config": str(CONFIG),
        "secrets": str(SECRETS),
    }


#: Where an upgrade puts the files it replaces, so `vigil` can be rolled back.
#:
#: Defined once and imported: it used to be a literal in two installers, which
#: could drift until an upgrade wrote its backups where the rollback path does
#: not look. Overridable, because "root's home directory" is a fine default on
#: a single-admin box and wrong on a host that keeps /root on a small volume.
BACKUP_DIR = Path(os.environ.get("VIGIL_BACKUP_DIR") or "/var/lib/vigil-backup")
