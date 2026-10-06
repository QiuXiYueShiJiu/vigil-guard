"""Installer / uninstaller / legacy migration.

Everything that writes to the system lives here, so the blast radius of an
install is auditable in one file.

Safety rules this module follows:

* **Back up before overwriting anything.** Every replaced file is copied to
  the backup directory with a timestamp first.
* **Never delete data on uninstall unless asked.** ``uninstall`` removes the
  program and its units but keeps configuration, state and logs; ``purge``
  (explicit) is the only thing that deletes them.
* **Adopt, do not clobber.** When a previous generation of this software is
  detected, its settings are read and carried over, and its units are
  stopped before ours start -- never the other way round.
* **Refuse to half-install.** A failure anywhere rolls back the units it
  already created, so you never end up with timers pointing at code that is
  not there.
"""
from __future__ import annotations

import grp
import os
import pwd
import shutil
import time
from pathlib import Path

from . import detect, paths, shell, units
from .config import Config, DEFAULTS, bootstrap_defaults
from .errors import ConfigError, VigilError
from .state import read_json, write_json

from ..core.paths import BACKUP_DIR

#: Units belonging to the previous monitoring generation.
#:
#: Listed **explicitly** rather than matched with a `dsh-*` glob. A glob
#: also matches the DSH application's own units (`dsh-web`, `dsh-token`),
#: and stopping those takes the operator's dashboard down while the
#: installer is still running -- which is a real outage, not a theoretical
#: one. Never go back to a prefix match here.
LEGACY_UNITS = (
    "dsh-threatd.service",
    "dsh-loadshed.service",
    "dsh-healthd.service", "dsh-healthd.timer",
    "dsh-mailcmd.service", "dsh-mailcmd.timer",
    "dsh-mail-guard.service", "dsh-mail-guard.timer",
    "dsh-logind.service", "dsh-logind.timer",
    "dsh-security-monitor.service", "dsh-security-monitor.timer",
    "dsh-avscan.service", "dsh-avscan.timer",
    "dsh-avscan-full.service", "dsh-avscan-full.timer",
    "dsh-backup.service", "dsh-backup.timer",
    "dsh-weekly-scan.service", "dsh-weekly-scan.timer",
)

#: Never touched, whatever they are named. These belong to a different
#: application that merely shares the name prefix.
LEGACY_PROTECTED = ("dsh-web", "dsh-token")
LEGACY_FILES = (
    "/usr/local/sbin/dsh-threatd.py",
    "/usr/local/sbin/dsh-healthd.py",
    "/usr/local/sbin/dsh-notify.sh",
    "/usr/local/sbin/dsh-mailcmd.py",
    "/usr/local/sbin/dsh-mail-guard.py",
    "/usr/local/sbin/dsh-logind.py",
    "/usr/local/sbin/dsh-loadshed.py",
    "/usr/local/sbin/dsh-ipinfo.py",
    "/usr/local/sbin/dsh-mailfmt.py",
    "/usr/local/sbin/dsh-security-monitor.sh",
    "/usr/local/sbin/dsh-net-monitor.sh",
    "/usr/local/sbin/dsh-avscan.sh",
    "/usr/local/sbin/dsh-backup.sh",
    "/usr/local/sbin/dsh-weekly-scan.sh",
    "/usr/local/sbin/dsh-set-relay.sh",
    "/usr/local/sbin/dsh-set-resend-domain.sh",
)
LEGACY_CONF = "/etc/dsh-security.conf"

#: Records which version is deployed and which one it replaced, so
#: `vigil rollback` can report what it is undoing rather than just doing it.
DEPLOY_STATE = paths.STATE_STATE / "deploy.json"


def _is_default(cfg, dotted: str, default) -> bool:
    """True when a config value is still at its built-in default.

    Used by adoption so that inheriting from a previous installation does
    not depend on the default being empty.
    """
    cur = cfg.get(dotted, default)
    return cur in (default, "", None, [], {})


def _is_installed_tree(pkg) -> bool:
    """Is *pkg* the tree this program actually runs from?

    Compared against ``paths.LIB``, the configured install root -- not a
    hardcoded path, so a relocated install still works. Anything else is a
    copy: an operator staging a release, a packaging run, or a test that made
    a temporary tree and called the installer.
    """
    try:
        return os.path.abspath(str(pkg)).startswith(
            os.path.abspath(str(paths.LIB)) + os.sep)
    except (OSError, TypeError, ValueError):
        return False


class Installer:
    def __init__(self, cfg: Config = None, log=None, dry_run: bool = False):
        self.cfg = cfg or Config()
        self.log = log
        self.dry_run = dry_run
        self.env = {}
        self.actions: list = []
        self.adopted: dict = {}

    # -- helpers ----------------------------------------------------------
    def _record(self, action: str) -> None:
        self.actions.append(action)
        if self.log:
            self.log.info(action)
        if not self.dry_run:
            return

    def _backup(self, path) -> str:
        """Copy *path* into the backup dir. Returns the backup location."""
        p = Path(path)
        if not p.exists():
            return ""
        stamp = time.strftime("%Y%m%d-%H%M%S")
        dest_dir = BACKUP_DIR / stamp
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / p.name
        try:
            if p.is_dir():
                shutil.copytree(str(p), str(dest), symlinks=True)
            else:
                shutil.copy2(str(p), str(dest))
            return str(dest)
        except OSError as e:
            if self.log:
                self.log.warn("备份 %s 失败: %s" % (path, e))
            return ""

    def _write(self, path, content: str, mode: int = 0o644, owner: str = "") -> bool:
        p = Path(path)
        if self.dry_run:
            self._record("would write %s" % p)
            return True
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            if p.exists():
                self._backup(p)
            p.write_text(content, encoding="utf-8")
            os.chmod(p, mode)
            if owner and ":" in owner:
                user, group = owner.split(":", 1)
                try:
                    os.chown(p, pwd.getpwnam(user).pw_uid,
                             grp.getgrnam(group).gr_gid)
                except (KeyError, OSError):
                    pass
            return True
        except OSError as e:
            if self.log:
                self.log.error("写入 %s 失败: %s" % (p, e))
            return False

    # -- preflight --------------------------------------------------------
    def preflight(self, need_root: bool = True) -> list:
        problems = []
        if need_root and os.geteuid() != 0:
            problems.append("需要 root 权限，请使用 sudo 运行")
        if not shell.have("systemctl"):
            problems.append("未检测到 systemd —— 本程序依赖 systemd 管理服务")
        if Path("/run/systemd/system").is_dir() is False:
            problems.append("systemd 未在运行")
        if not shell.have("python3"):
            problems.append("未找到 python3")
        env = self.env or detect.summary()
        if env.get("init") != "systemd":
            problems.append("当前系统未使用 systemd 作为 init")
        return problems

    # -- discovery --------------------------------------------------------
    def discover(self) -> dict:
        self.env = detect.full()
        return self.env

    # -- feature set -------------------------------------------------------
    def default_features(self, want_gate: bool = False) -> set:
        env = self.env or self.discover()
        feats = {"mail", "threat", "health"}
        if env.get("log_sources", {}).get("auth"):
            feats.add("login")
        if env.get("malware", {}).get("engine") not in (None, "none"):
            feats.add("av")
        if want_gate:
            feats.add("gate")
        return feats

    # -- configuration -----------------------------------------------------
    def build_config(self, features: set, recipients=None, from_address: str = "",
                     whitelist=None, adopt: bool = True) -> Config:
        """Create or update config.json from discovery + operator answers."""
        cfg = self.cfg
        env = self.env or self.discover()

        # Adopt before anything else so operator-provided values win over
        # inherited ones, and so an explicit answer is never overwritten.
        self.adopted = self.adopt_legacy(cfg) if adopt else {}

        bootstrap_defaults(cfg, env["system"]["hostname"])

        # Record which components were enabled. Without this the feature set
        # only ever existed as a local variable during install, so `vigil
        # update` had no way to know which systemd units to refresh -- and
        # regenerating the wrong set would either drop timers that should
        # exist or install ones the operator deliberately left off.
        cfg.set("features", sorted(features))

        # Log sources: discovered, never guessed.
        src = env.get("log_sources", {})
        cfg.set("threat.log_sources.nginx_access", src.get("nginx_access", [])[:50])
        cfg.set("threat.log_sources.auth", src.get("auth", [])[:5])
        cfg.set("threat.log_sources.panel", src.get("panel", [])[:20])

        # Services worth watching: only ones that exist on this host.
        known = []
        for name in ("nginx", "apache2", "httpd", "mysqld", "mariadb", "mysql",
                     "postgresql", "redis", "redis-server", "ssh", "sshd",
                     "fail2ban", "postfix", "exim4", "docker", "maldet",
                     "clamav-daemon", "bt", "php-fpm"):
            if shell.unit_active(name) or shell.unit_enabled(name) or \
                    shell.out(["systemctl", "list-unit-files", "%s.service" % name]):
                known.append(name)
        # Panel/pHP units have versioned names; pick them up by glob.
        ok, listing, _ = shell.run(
            ["systemctl", "list-unit-files", "--type=service", "--no-legend",
             "--no-pager"], timeout=20)
        if ok:
            for line in listing.splitlines():
                name = line.split()[0] if line.split() else ""
                if not name.endswith(".service"):
                    continue
                stem = name[:-len(".service")]
                if stem.startswith(("php-fpm", "php", "nginx", "mysqld", "bt")):
                    if stem not in known:
                        known.append(stem)
        if known:
            cfg.set("checks.services", sorted(set(known)))

        # Files whose integrity matters: our own plus anything the operator
        # already cared about.
        watch = set(cfg.get("checks.watch_files", []) or [])
        for candidate in (
            str(paths.CONFIG), str(paths.SECRETS),
            "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config",
            "/etc/ld.so.preload", "/etc/crontab",
        ):
            if os.path.exists(candidate):
                watch.add(candidate)
        for extra in self.web_stack_paths(env):
            watch.add(extra)
        cfg.set("checks.watch_files", sorted(watch))

        # Our own generated configuration. Separate from `watch_files`
        # because it is a different question -- "did someone edit the guard"
        # rather than "did a system file change" -- and because it must be
        # refreshed by every `vigil update`.
        mine = set(cfg.get("checks.self_integrity.paths", []) or [])
        mine.update(self.self_integrity_paths(env))
        cfg.set("checks.self_integrity.paths", sorted(mine))

        # Directories to watch in auditd (the rename-overwrite blind spot).
        dirs = set(cfg.get("checks.watch_dirs", []) or [])
        for d in ("/etc", "/etc/ssh", "/etc/sudoers.d", "/etc/cron.d",
                  "/var/spool/cron", "/root/.ssh", str(paths.ETC)):
            if os.path.isdir(d):
                dirs.add(d)
        cfg.set("checks.watch_dirs", sorted(dirs))

        # Web roots for content scanning and (optionally) malware monitoring.
        roots = []
        for r in env.get("web_roots", []):
            if os.path.isdir(r):
                roots.append(r)
        if not roots:
            for p in ("/var/www/html", "/var/www"):
                if os.path.isdir(p):
                    roots.append(p)
        cfg.set("checks.web_roots", roots)
        if env.get("malware", {}).get("engine") == "maldet":
            cfg.set("malware.monitor_paths", roots)

        cert_dirs = []
        for c in ("/www/server/panel/vhost/cert", "/etc/letsencrypt/live",
                  "/etc/ssl/private", "/etc/pki/tls/certs"):
            if os.path.isdir(c):
                cert_dirs.append(c)
        if cert_dirs:
            cfg.set("checks.certificates.dirs", cert_dirs)

        if whitelist:
            cur = set(cfg.get("threat.whitelist", []) or [])
            cur.update(whitelist)
            cfg.set("threat.whitelist", sorted(cur))
        if recipients:
            for r in recipients:
                if r.strip():
                    cfg.add_recipient(r.strip(), "alert")
        if from_address:
            cfg.set("mail.from_address", from_address)

        # Public IP is display-only, but useful in alerts.
        ip = detect.public_ip()
        if ip:
            cfg.set("public_ip", ip)
        return cfg

    def self_integrity_paths(self, env) -> list:
        """Files this program generates, which it must notice being edited.

        The watched-file list above covers the host's own critical files.
        These are ours: the nginx snippets that decide what reaches the login
        gate, each gate's ``config.php``, and the audit rules. An attacker who
        can edit those turns the protection off without touching a single
        system file -- which is precisely why they get their own baseline
        even though they live in directories nobody else watches.

        The discovery itself lives in :func:`gates.generated_artifacts` so
        that the check which verifies these files and the installer which
        records them can never disagree about the list.
        """
        out = set()
        try:
            from ..gates import generated_artifacts
            out.update(generated_artifacts(env))
        except (ImportError, OSError):
            pass

        rules = ""
        try:
            rules = str(paths.ETC / "audit" / "vigil.rules")
        except (AttributeError, TypeError):
            rules = ""
        if rules and os.path.exists(rules):
            out.add(rules)

        return sorted(p for p in out if p)

    def web_stack_paths(self, env) -> list:
        out = []
        ng = env.get("nginx", {})
        if ng.get("conf"):
            out.append(ng["conf"])
        panel = env.get("bt_panel", {})
        if panel.get("present"):
            out.append(str(Path(panel["data_dir"]) / "port.pl"))
            out.append(str(Path(panel["data_dir"]) / "admin_path.pl"))
        return [p for p in out if p]

    # -- legacy adoption ---------------------------------------------------
    def legacy_present(self) -> dict:
        """Detect a previous installation. Read-only and cheap."""
        found = {"config": os.path.exists(LEGACY_CONF), "files": [],
                 "units": [], "protected": []}
        for f in LEGACY_FILES:
            if os.path.exists(f):
                found["files"].append(f)
        for name in LEGACY_UNITS:
            if (paths.SYSTEMD_UNIT_DIR / name).exists():
                found["units"].append(name)
        # Report -- but never act on -- units we deliberately leave alone.
        for stem in LEGACY_PROTECTED:
            for suffix in (".service", ".timer"):
                if (paths.SYSTEMD_UNIT_DIR / (stem + suffix)).exists():
                    found["protected"].append(stem + suffix)
        return found

    def adopt_legacy(self, cfg: Config) -> dict:
        """Carry settings over from the previous generation.

        Only *preferences* are adopted. Credentials are read so the operator
        does not have to retype them, but they are written to the new
        secrets file rather than the shared config.
        """
        got = {}
        if not os.path.exists(LEGACY_CONF):
            return got
        values = {}
        try:
            with open(LEGACY_CONF, "r", encoding="utf-8",
                      errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("DSH_") and "=" in line:
                        k, _, v = line.partition("=")
                        values[k.strip()] = v.strip().strip('"').strip("'")
        except OSError:
            return got

        def gv(key, default=""):
            return values.get(key, default) or default

        recipients = [a.strip() for a in gv("DSH_ALERT_EMAIL").split(",") if a.strip()]
        if recipients and not cfg.get("mail.recipients"):
            cfg.set("mail.recipients", recipients)
            got["recipients"] = recipients
        login_to = [a.strip() for a in gv("DSH_LOGIN_ALERT_TO").split(",") if a.strip()]
        if login_to and not cfg.get("mail.login_recipients"):
            cfg.set("mail.login_recipients", login_to)
            got["login_recipients"] = login_to

        # "Not set" must mean "still at the built-in default", not merely
        # falsy -- a non-empty default would otherwise make the adoption
        # condition永 false and silently drop the operator's existing
        # branding.
        if gv("DSH_ALERT_FROM") and _is_default(cfg, "mail.from_address", ""):
            cfg.set("mail.from_address", gv("DSH_ALERT_FROM"))
            got["from_address"] = gv("DSH_ALERT_FROM")
        if gv("DSH_FROM_NAME") and _is_default(cfg, "mail.from_name",
                                               "Server Monitor"):
            cfg.set("mail.from_name", gv("DSH_FROM_NAME"))
            got["from_name"] = gv("DSH_FROM_NAME")
        if gv("DSH_REPLY_TO") and not cfg.get("mail.reply_to"):
            cfg.set("mail.reply_to", gv("DSH_REPLY_TO"))
        total = gv("DSH_QUOTA_TOTAL")
        if total.isdigit() and total != "100":
            cfg.set("mail.daily_quota", int(total))

        # Resend credentials -> a proper provider entry.
        rkey = gv("DSH_RESEND_KEY")
        rfrom = gv("DSH_DISPLAY_FROM") or gv("DSH_RESEND_FROM")
        if rkey and not cfg.providers():
            import re
            addr = ""
            m = re.search(r"<([^>]+)>", rfrom or "")
            addr = m.group(1) if m else (rfrom or "")
            params = {"api_key": rkey, "from_address": addr,
                      "from_name": gv("DSH_FROM_NAME", "Server Monitor"),
                      "reply_to": gv("DSH_REPLY_TO")}
            cfg.set_provider_params("resend", params)
            if addr and not cfg.get("mail.from_address"):
                cfg.set("mail.from_address", addr)
            got["resend"] = True

        # Threat settings worth keeping.
        try:
            old = read_json("/etc/dsh-threatd.conf", {}) or {}
        except Exception:                               # noqa: BLE001
            old = {}
        wl = old.get("whitelist")
        if isinstance(wl, list) and wl:
            cur = set(cfg.get("threat.whitelist", []) or [])
            cur.update(str(x) for x in wl)
            cfg.set("threat.whitelist", sorted(cur))
            got["whitelist"] = len(wl)
        for old_key, new_key in (("ssh_fail_threshold", "threat.ssh.max_failures"),
                                 ("ssh_fail_window", "threat.ssh.window_seconds"),
                                 ("http_4xx_threshold", "threat.http.max_attacks"),
                                 ("ban_escalation", "threat.ssh.ban_seconds")):
            if old.get(old_key) not in (None, "", []):
                cfg.set(new_key, old[old_key])
        # Log sources configured by hand previously.
        old_logs = old.get("log_files")
        if isinstance(old_logs, list) and old_logs:
            cfg.set("threat.log_sources.nginx_access", old_logs)
        if old.get("auth_log"):
            cfg.set("threat.log_sources.auth", [old["auth_log"]])
        return got

    # -- safety net --------------------------------------------------------
    def protected_state(self) -> dict:
        """Runtime state of the units we promise never to touch.

        Captured before and after the install so we can *prove* we did not
        take the operator's own application down. That failure happened
        once, cost a 502 on a live dashboard, and must not be possible to
        repeat silently.
        """
        state = {}
        for stem in LEGACY_PROTECTED:
            for suffix in (".service", ".timer"):
                unit = stem + suffix
                if not (paths.SYSTEMD_UNIT_DIR / unit).exists():
                    continue
                state[unit] = {
                    "active": shell.out(["systemctl", "is-active", unit]),
                    "enabled": shell.out(["systemctl", "is-enabled", unit]),
                }
        return state

    def protected_regressions(self, before: dict) -> list:
        """Units that were running before the install and are not now."""
        problems = []
        after = self.protected_state()
        for unit, was in (before or {}).items():
            now = after.get(unit) or {}
            if was.get("active") == "active" and now.get("active") != "active":
                problems.append("%s 从 %s 变成了 %s"
                                % (unit, was.get("active"), now.get("active")))
            if was.get("enabled") == "enabled" and now.get("enabled") != "enabled":
                problems.append("%s 的开机自启被关闭了" % unit)
        return problems

    def stop_legacy(self) -> list:
        """Stop and disable the previous monitoring generation.

        Only units named in :data:`LEGACY_UNITS` are touched. Anything in
        :data:`LEGACY_PROTECTED` is skipped and logged, because it is a
        different application that shares our name prefix and stopping it
        would be an outage the operator did not ask for.
        """
        stopped, skipped = [], []
        for name in LEGACY_UNITS:
            if not (paths.SYSTEMD_UNIT_DIR / name).exists():
                continue
            stem = name.split(".")[0]
            if stem in LEGACY_PROTECTED:
                skipped.append(name)
                continue
            if self.dry_run:
                self._record("would stop legacy unit %s" % name)
                stopped.append(name)
                continue
            shell.run(["systemctl", "stop", name], timeout=30)
            shell.run(["systemctl", "disable", name], timeout=30)
            stopped.append(name)
        if skipped and self.log:
            self.log.info("保留未动（属于其它应用）: %s" % ", ".join(skipped))
        if stopped and not self.dry_run:
            shell.systemd_reload()
        return stopped

    def quarantine_legacy(self) -> list:
        """Move the old scripts aside (never delete them here)."""
        moved = []
        stamp = time.strftime("%Y%m%d-%H%M%S")
        dest = BACKUP_DIR / ("legacy-%s" % stamp)
        for f in LEGACY_FILES:
            p = Path(f)
            if not p.exists():
                continue
            # Belt and braces: the file list must never contain anything
            # belonging to the DSH application itself.
            if any(prot in p.name for prot in LEGACY_PROTECTED):
                if self.log:
                    self.log.warn("拒绝移动受保护文件: %s" % f)
                continue
            if self.dry_run:
                self._record("would move %s -> %s" % (f, dest))
                moved.append(f)
                continue
            try:
                dest.mkdir(parents=True, exist_ok=True)
                shutil.move(str(p), str(dest / p.name))
                moved.append(f)
            except OSError as e:
                if self.log:
                    self.log.warn("移走旧文件 %s 失败: %s" % (f, e))
        if moved and not self.dry_run:
            write_json(dest / "MANIFEST.json",
                       {"moved": moved, "ts": stamp}, mode=0o600)
        return moved

    # -- audit rules -------------------------------------------------------
    def render_audit_rules(self, cfg: Config) -> str:
        """Build the auditd rule file.

        Every ``-w`` target is checked for existence first. A rule pointing
        at a path that does not exist makes ``augenrules`` abandon *all*
        rules after it -- a silent failure that leaves attribution broken
        while everything still looks healthy.
        """
        lines = [
            "# Generated by vigil -- do not edit by hand.",
            "# Regenerate with: vigil audit install",
            "-D",
            "-b 8192",
            "--backlog_wait_time 60000",
            "-f 1",
            "",
            "# Privileged command execution by unprivileged callers.",
            "-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -k vigil_exec",
            "-a always,exit -F arch=b32 -S execve -F euid=0 -F auid>=1000 -k vigil_exec",
            "",
            "# File watches. Existence is verified because a missing target",
            "# aborts the remainder of the file.",
        ]
        key = cfg.get("auditd.key", "vigil_watch")
        skipped = []
        for path in cfg.get("checks.watch_files", []) or []:
            p = str(path)
            if not os.path.exists(p):
                skipped.append(p)
                continue
            lines.append("-w %s -p wa -k %s" % (p, key))
        lines.append("")
        lines.append("# Directory watches: a file watch binds to the inode, so a")
        lines.append("# write-temp-then-rename replacement evades it entirely.")
        for path in cfg.get("checks.watch_dirs", []) or []:
            p = str(path)
            if not os.path.isdir(p):
                skipped.append(p)
                continue
            lines.append("-w %s -p wa -k %s" % (p, key))
        lines.append("")
        if cfg.get("auditd.immutable", True):
            lines.append("# Make the rules immutable until reboot so they cannot be")
            lines.append("# relaxed at runtime by an intruder. MUST stay last.")
            lines.append("-e 2")
        text = "\n".join(lines) + "\n"
        if skipped:
            text += ("\n# Skipped (path does not exist):\n"
                     + "".join("#   %s\n" % s for s in skipped))
        return text

    def quarantine_legacy_audit_rules(self) -> list:
        """Move a previous installation's rule file out of rules.d.

        Leaving it in place is actively harmful: augenrules concatenates
        every file in rules.d, and the old file contains its own ``-D`` and
        a mid-file ``-e 2``. Once ``-e 2`` is set the configuration is
        immutable, so our rules -- which sort after it -- can never load,
        and the earlier ``-D`` wipes whatever came before. The result looks
        healthy while attribution is silently broken.
        """
        moved = []
        target = paths.Path("/etc/audit/rules.d/dsh-watch.rules")
        if not target.exists():
            return moved
        if self.dry_run:
            self._record("would quarantine %s" % target)
            return [str(target)]
        dest = BACKUP_DIR / ("legacy-%s" % time.strftime("%Y%m%d-%H%M%S"))
        try:
            dest.mkdir(parents=True, exist_ok=True)
            shutil.move(str(target), str(dest / target.name))
            moved.append(str(target))
        except OSError as e:
            if self.log:
                self.log.warn("移走旧审计规则失败: %s" % e)
        return moved

    def install_audit_rules(self, cfg: Config) -> tuple:
        env = self.env or self.discover()
        a = env.get("auditd", {})
        if not a.get("present"):
            return False, "本机未安装 auditd"
        self.quarantine_legacy_audit_rules()
        target = Path(a.get("rules_file") or
                      "/etc/audit/rules.d/vigil.rules")
        if self.dry_run:
            self._record("would write %s" % target)
            return True, "dry-run"
        text = self.render_audit_rules(cfg)
        if not self._write(target, text, 0o640):
            return False, "写入规则文件失败"
        # What we just asked for, so the verification below can compare the
        # kernel against *our* file rather than against a total.
        audit_key = str(cfg.get("auditd.key", "vigil_watch") or "vigil_watch")
        want_watches = sum(1 for ln in text.splitlines()
                           if ln.strip().startswith("-w "))
        want_syscalls = sum(1 for ln in text.splitlines()
                            if ln.strip().startswith("-a "))
        shell.run(["systemctl", "enable", "auditd"], timeout=30)
        if not shell.unit_active("auditd"):
            shell.run(["systemctl", "start", "auditd"], timeout=30)
        ok, _o, err = shell.run(["augenrules", "--load"], timeout=60)
        if not ok:
            # Loading can fail because another file in rules.d is broken;
            # report the real reason rather than claiming success.
            return False, "augenrules 加载失败: %s" % err.strip()[:300]

        # Count *ours*, not whatever the kernel happens to be holding. An
        # earlier version counted every loaded rule and cheerfully reported
        # success while the kernel was still running a previous product's
        # rules and none of ours -- the number looked right and the
        # protection was absent.
        live = shell.out(["auditctl", "-l"])
        mine = sum(1 for line in live.splitlines() if audit_key in line)
        state = shell.out(["auditctl", "-s"])
        immutable = "enabled 2" in state
        if mine == 0 and want_watches + want_syscalls > 0:
            if immutable:
                # `-e 2` makes the rule set unchangeable until reboot, and
                # `augenrules` answers "No change" without explaining why.
                # Saying so is the difference between an actionable message
                # and an operator concluding the tool is broken.
                return False, ("审计规则已写入文件，但**不可变模式（-e 2）已生效**，"
                               "运行时无法载入 —— 需要**重启**后生效"
                               "（`augenrules --load` 现在只会回答 No change）")
            return False, ("审计规则未生效：文件中 %d 条，内核中 0 条"
                           % (want_watches + want_syscalls))
        return True, "审计规则已加载（本程序 %d 条）" % mine

    # -- code deployment ---------------------------------------------------
    def source_root(self) -> Path:
        """Where the package we are running from actually lives."""
        import vigil
        return Path(vigil.__file__).resolve().parent

    #: Where the version that was running before the last deploy is kept.
    #: Deliberately not deleted after a successful swap: "it worked this
    #: time" is not the same as "I will never need to go back", and the one
    #: moment you need the old copy is the moment you no longer have it.
    PREV_DIR = "vigil.prev"

    def verify_tree(self, tree) -> tuple:
        """Prove a staged copy can actually run, before it replaces this one.

        Both of the syntax errors introduced during the v2 work were the same
        kind of mistake -- a bad edit that made a module unimportable -- and
        both were caught by a human running the test suite, not by the
        upgrade path. The upgrade path is exactly where that check belongs:
        a copy that cannot be imported must never become the running copy,
        because the timers would then fail one by one and the failure would
        look like "the server is quiet tonight".
        """
        import subprocess
        import sys as _sys

        parent = str(Path(tree).parent)
        env = dict(os.environ)
        env["PYTHONPATH"] = parent
        env["VIGIL_LIB"] = parent
        env.pop("PYTHONDONTWRITEBYTECODE", None)

        # Import *every* module, not a hand-picked few. The first version of
        # this probe imported `vigil.cli` and stopped there -- and cli.py
        # imports its subcommands lazily, so a syntax error in
        # core/installer.py sailed straight through the guard that exists to
        # catch exactly that. walk_packages leaves nothing to remember.
        probe = (
            "import importlib, pkgutil, sys, traceback\n"
            "import vigil\n"
            "print(vigil.__version__)\n"
            "bad = []\n"
            "for m in pkgutil.walk_packages(vigil.__path__, 'vigil.'):\n"
            "    try:\n"
            "        importlib.import_module(m.name)\n"
            "    except BaseException as e:\n"
            "        bad.append('%s: %s: %s' % (m.name, type(e).__name__, e))\n"
            "if bad:\n"
            "    print('FAILED')\n"
            "    for line in bad:\n"
            "        print('  ' + line)\n"
            "    sys.exit(3)\n"
        )
        try:
            done = subprocess.run([_sys.executable, "-c", probe],
                                  cwd=parent, env=env, timeout=60,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT)
        except (OSError, subprocess.SubprocessError) as e:
            return False, "无法验证新代码：%s" % e
        out = (done.stdout or b"").decode("utf-8", "replace").strip()
        if done.returncode != 0:
            return False, "新代码无法导入：%s" % (out.splitlines()[-1:] or [""])[0]
        return True, out or "ok"

    def deploy_code(self) -> tuple:
        """Copy the package to the install prefix and write the launcher.

        The running copy is replaced by a staged copy that has been *proved
        importable* first (see :meth:`verify_tree`), and the copy it replaced
        is kept as ``vigil.prev`` so `vigil rollback` can undo the upgrade.
        """
        src = self.source_root()
        lib = paths.LIB
        pkg = lib / "vigil"
        if self.dry_run:
            self._record("would deploy %s -> %s" % (src, pkg))
            return True, "dry-run"

        staging = lib / (".staging-%d" % os.getpid())
        try:
            lib.mkdir(parents=True, exist_ok=True)
            if staging.exists():
                shutil.rmtree(str(staging), ignore_errors=True)
            shutil.copytree(str(src), str(staging / "vigil"),
                            ignore=shutil.ignore_patterns(
                                "__pycache__", "*.pyc", "*.pyo", "*.egg-info"))

            # Nothing has been touched yet. This is the last moment at which
            # giving up is free.
            ok, detail = self.verify_tree(staging / "vigil")
            if not ok:
                shutil.rmtree(str(staging), ignore_errors=True)
                return False, ("新代码自检未通过，已放弃切换（当前版本未受影响）：%s"
                               % detail)

            prev = lib / self.PREV_DIR
            if prev.exists():
                shutil.rmtree(str(prev), ignore_errors=True)
            if pkg.exists():
                os.rename(str(pkg), str(prev))
            os.rename(str(staging / "vigil"), str(pkg))
            shutil.rmtree(str(staging), ignore_errors=True)
            self._record_deploy(pkg, detail)
        except OSError as e:
            shutil.rmtree(str(staging), ignore_errors=True)
            return False, "部署代码失败: %s" % e

        launcher = (
            "#!/usr/bin/env python3\n"
            "# Vigil launcher -- generated by `vigil install`.\n"
            "import os, sys\n"
            "sys.path.insert(0, %r)\n"
            "os.environ.setdefault('VIGIL_LIB', %r)\n"
            "from vigil.cli import main\n"
            "if __name__ == '__main__':\n"
            "    sys.exit(main())\n"
        ) % (str(lib), str(lib))
        try:
            paths.BIN.parent.mkdir(parents=True, exist_ok=True)
            paths.BIN.write_text(launcher, encoding="utf-8")
            os.chmod(paths.BIN, 0o755)
        except OSError as e:
            return False, "写入启动器失败: %s" % e
        return True, "代码已部署到 %s，命令 %s 可用" % (lib, paths.BIN)

    def _record_deploy(self, pkg, version: str) -> None:
        """Remember what is running and what it replaced, for `rollback`."""
        rec = read_json(DEPLOY_STATE, {}) or {}
        prev = paths.LIB / self.PREV_DIR
        # `previous` is read from the retained tree, not copied from the old
        # record: the retained tree is the fact, and a record that disagrees
        # with the disk is worse than no record.
        rec["previous"] = self._version_of(prev)
        rec["previous_at"] = rec.get("current_at") or 0
        rec["current"] = str(version or "").strip()
        rec["current_at"] = time.time()
        rec["rollback_available"] = prev.is_dir()
        rec["rollback_version"] = rec["previous"]
        write_json(DEPLOY_STATE, rec, mode=0o640)
        # Also write the deploy into the audit ledger. `self_integrity` uses
        # it to tell "the code changed because this program was upgraded"
        # apart from "the code changed", and the ledger is the record of every
        # sanctioned change to this program's own files -- a deploy is the
        # largest of them. Written after the state file so that file stays the
        # source of truth for `vigil rollback`.
        try:
            from ..evolve import ledger as _ledger
            # Only a deploy of the *installed* tree is a deployment of this
            # program. A tree somewhere else -- a staging copy, a packaging
            # run, a test's temporary "installed" directory -- records into
            # ``deploy.json`` (which is what `vigil rollback` reads) but must
            # not append to the audit ledger: that ledger answers "did this
            # program's own code change because it was upgraded", and a
            # rehearsal is not an upgrade.
            if _is_installed_tree(pkg):
                _ledger.record("deployed", cfg=self.cfg, file=str(pkg),
                               version=rec["current"],
                               previous=rec["previous"],
                               rollback_available=rec["rollback_available"])
        except Exception as exc:                            # noqa: BLE001
            # Reported, not swallowed: `self_integrity` reads this ledger to
            # tell an upgrade apart from an intrusion, so a silent failure
            # here would quietly make every later upgrade look suspicious.
            if self.log:
                self.log.warn("写入部署台账失败：%s: %s" % (type(exc).__name__, exc))

    @staticmethod
    def _version_of(tree) -> str:
        """Read ``__version__`` out of a package tree without importing it."""
        path = Path(tree) / "version.py"
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return ""
        import re as _re
        m = _re.search(r'^__version__\s*=\s*"([^"]+)"', text, _re.M)
        return m.group(1) if m else ""

    def rollback(self) -> tuple:
        """Put the previous version back.

        The situation this exists for is specific: the new version started,
        the daemons came up, and *then* something turned out to be wrong --
        an inspection that crashes, a gate that stops authenticating, alerts
        that stopped arriving. Without a rollback the only way back is to
        reconstruct the old code by hand, on a machine that is currently
        failing at its one job.
        """
        lib = paths.LIB
        pkg = lib / "vigil"
        prev = lib / self.PREV_DIR
        if not prev.is_dir():
            return False, "没有可回滚的上一版（%s 不存在）" % prev

        back_to = self._version_of(prev)
        from_now = self._version_of(pkg)

        ok, detail = self.verify_tree(prev)
        if not ok:
            return False, "上一版本身无法导入，已放弃回滚：%s" % detail

        swapped = lib / (".rollback-%d" % os.getpid())
        try:
            if swapped.exists():
                shutil.rmtree(str(swapped), ignore_errors=True)
            os.rename(str(pkg), str(swapped))
            os.rename(str(prev), str(pkg))
            os.rename(str(swapped), str(prev))
        except OSError as e:
            # Put things back the way we found them if the middle step failed.
            if not pkg.exists() and swapped.exists():
                try:
                    os.rename(str(swapped), str(pkg))
                except OSError:
                    pass
            return False, "回滚失败: %s" % e

        rec = read_json(DEPLOY_STATE, {}) or {}
        rec["current"], rec["previous"] = back_to, from_now
        rec["current_at"] = time.time()
        rec["rollback_version"] = from_now
        rec["rollback_available"] = True
        write_json(DEPLOY_STATE, rec, mode=0o640)
        return True, "已回滚：%s → %s（上一版仍保留为 %s）" % (
            from_now or "?", back_to or "?", self.PREV_DIR)

    def remove_code(self) -> None:
        if self.dry_run:
            return
        try:
            if paths.BIN.exists() and "Vigil launcher" in \
                    paths.BIN.read_text(encoding="utf-8", errors="replace")[:200]:
                paths.BIN.unlink()
        except OSError:
            pass
        try:
            shutil.rmtree(str(paths.LIB / "vigil"), ignore_errors=True)
        except OSError:
            pass
