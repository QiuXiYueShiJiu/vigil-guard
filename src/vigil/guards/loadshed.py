# -*- coding: utf-8 -*-
"""Load shedder -- automatic, reversible relief under sustained load.

When the host is under pressure the shedder enters *protect* mode and does
three reversible things:

1. caps **per-source concurrent connections** (connection-exhaustion attacks);
2. caps **per-source new-connection rate** (request floods);
3. writes a runtime flag that makes :mod:`vigil.guards.threat` switch to
   *strict mode*, where ban thresholds are halved and attacks are cut off
   sooner.

Everything is a separate iptables/ip6tables chain, so protection can be added
and removed atomically and leaves no residue.  This module owns the runtime
flag; the threat daemon caches it with a short TTL.

Defects fixed relative to the original ``dsh-loadshed.py``
---------------------------------------------------------

* **``ss`` field parsing.**  ``ss -Htn state established`` omits the *State*
  column, so positional indexing read the peer port and the shedder counted
  *outbound* connections to :80/:443 instead of inbound ones.  We never index
  positionally: :func:`parse_ss_established` matches ``addr:port`` tokens, so
  the result is correct with or without the State column.
* **Startup reconciliation.**  A SIGKILL while protecting used to leave the
  rate-limit rules installed forever and the threat daemon permanently in
  strict mode.  :meth:`LoadShedder.reconcile` inspects both the runtime flag
  and the real firewall state and either adopts the previous state or cleans
  it up deliberately.
* **Whitelist parity.**  The original dropped every whitelist entry that was
  not a bare ``/32`` and passed IPv6 addresses to an IPv4-only ``iptables -s``.
  We split entries by address family and install matching ``RETURN`` rules in
  the IPv4 and IPv6 chains; loopback is always exempt.
* **No work in a signal handler.**  Handlers only set a flag; the main loop
  performs the shutdown and cleanup.
* **No hardcoded INPUT position.**  The jump into our chain is inserted
  *after* the threat daemon's DROP rule (computed at run time), not at a magic
  rule number.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import signal
import sys
import threading
import time

from ..core import paths, shell
from ..core.config import load as load_config
from ..core.logging import get as get_logger
from ..core.state import write_text
from ..i18n import language, set_language, t as i18n_t
from ..mail.message import Alert, KIND_ALERT, SEV_INFO, SEV_WARN
from .attacks import ConfigError, assert_config_parsable
from .checks.util import oneline

# --------------------------------------------------------------------------
# Fixed locations (derived from core.paths -- never hardcoded)
# --------------------------------------------------------------------------
#: Runtime flag shared with the threat daemon, which caches it with a TTL.
SHED_FLAG = paths.RUN / "loadshed.active"
#: Planned-maintenance marker.  ``guards.checks.base`` uses the same path, so
#: a maintenance window silences the shedder and the health checks together.
MAINTENANCE_FLAG = paths.RUN.parent / "vigil-maintenance"

LEVEL_NORMAL = "NORMAL"
LEVEL_PROTECT = "PROTECT"

_MISSING = object()


# --------------------------------------------------------------------------
# i18n
# --------------------------------------------------------------------------
_TEXT = {
    "zh": {
        "started": "loadshed 启动（PID %d，CPU %d 核）",
        "thresholds": "阈值：进入 负载>%.1f 或 连接>%d｜解除 负载<%.1f 且 连接<%d",
        "already_protecting": "检测到上次运行留下的保护模式（规则与标记均在），已接管继续保护",
        "stale_flag": "检测到残留标记但防火墙规则已不存在，已清理标记并恢复正常",
        "stale_rules": "检测到上次异常退出留下的限流规则，正在主动清理",
        "protect_on": "负载保护已启用",
        "protect_off": "负载保护已解除",
        "no_firewall": "未找到 iptables，无法启用负载保护（仍会记录告警）",
        "enable_failed": "启用负载保护失败，保持正常模式，稍后重试",
        "warn_load": "负载偏高警示：load1=%.2f 连接=%d",
        "cycle_error": "监控循环异常：%s",
        "signal": "收到信号 %d，准备退出并解除限流",
        "stopped": "已退出，限流规则已清理",
        "skip_maintenance": "处于计划内维护窗口，暂不进入保护模式",
        "sampled": "采样：load1=%.2f 连接=%d（阈值 进入 %.1f/%d，解除 %.1f/%d）",
        "chain_missing": "限流链 %s 不存在",
        "no_ip6tables": "未找到 ip6tables，IPv6 方向无法限流（存在防护缺口）",
        "bad_whitelist": "白名单条目非法，已忽略：%s",
    },
    "en": {
        "started": "loadshed starting (pid %d, %d cpu)",
        "thresholds": "thresholds: protect load>%.1f or conn>%d | release load<%.1f and conn<%d",
        "already_protecting": "previous protect mode found (rules and flag present); adopting it",
        "stale_flag": "runtime flag found but firewall rules are gone; clearing flag",
        "stale_rules": "leftover rate-limit rules from an unclean shutdown; cleaning up",
        "protect_on": "Load protection enabled",
        "protect_off": "Load protection released",
        "no_firewall": "iptables not found; cannot enable load protection",
        "enable_failed": "failed to enable load protection; staying in normal mode",
        "warn_load": "load is high: load1=%.2f conns=%d",
        "cycle_error": "monitor loop error: %s",
        "signal": "signal %d received, shutting down and cleaning up",
        "stopped": "stopped, rate-limit rules removed",
        "skip_maintenance": "planned maintenance window; not entering protect mode",
        "sampled": "sample: load1=%.2f conns=%d (protect %.1f/%d, release %.1f/%d)",
        "chain_missing": "shed chain %s is missing",
        "no_ip6tables": "ip6tables not found; IPv6 cannot be rate-limited",
        "bad_whitelist": "invalid whitelist entry ignored: %s",
    },
}


def _t(key: str, *args) -> str:
    """Translate a fixed string, formatting with *args when given.

    ``vigil.i18n`` is consulted first; because it has no loadshed table yet it
    returns the key unchanged and we fall back to the module table below.
    Adding the keys to ``i18n.py`` later automatically takes precedence.
    """
    text = i18n_t(key)
    if text == key:
        table = _TEXT.get(language(), _TEXT["zh"])
        text = table.get(key) or _TEXT["en"].get(key) or key
    if args:
        try:
            return text % args
        except (TypeError, ValueError):
            return text
    return text


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
#: Heuristic defaults.  NOTE: there is no ``loadshed`` section in
#: ``core/config.py`` yet, so every value below is read as an *extension* key
#: (``loadshed.<name>``) with these fallbacks.  The shared whitelist is read
#: from the schema's ``threat.whitelist`` so banning and rate-limiting agree.
LOADSHED_DEFAULTS = {
    "check_interval": 10,
    "warn_load": 3.0,
    "warn_conn": 400,
    "protect_load": 6.0,
    "protect_conn": 800,
    "release_load": 2.0,
    "release_conn": 200,
    "protect_confirm": 2,
    "release_confirm": 3,
    "connlimit_per_ip": 50,
    "newconn_rate_per_ip": 30,
    "newconn_burst": 60,
    "chain": "VIGIL_SHED",
    "ports": [80, 443],
    "hashlimit_expire_ms": 10000,
    "hashlimit_name": "vigil_shed",
    "alert_cooldown": 600,
}


def _cfg(cfg, key: str, default):
    value = cfg.get("loadshed.%s" % key, _MISSING)
    return default if value is _MISSING else value


# --------------------------------------------------------------------------
# ``ss`` parsing (defect: positional indexing of a filtered but header-less
# listing read the peer port instead of the local port)
# --------------------------------------------------------------------------
_HEX_ADDR = re.compile(r"^[0-9A-Fa-f:.]+$")


def _addr_port(token: str):
    """Return the port text of an ``addr:port`` token, else ``None``.

    Works for ``10.0.0.1:80``, ``0.0.0.0:80``, ``*:80``, ``[::]:443`` and
    ``[fe80::1]:51000``.  Non address tokens (``ESTAB``, queue counters,
    ``timer:(keepalive,1min,0)``, ``users:((\"nginx\",pid=1,fd=2))``) return
    ``None``, which is what makes positional indexing unnecessary.
    """
    if not token or ":" not in token:
        return None
    host, _, port = token.rpartition(":")
    if port != "*" and not port.isdigit():
        return None
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host in ("", "*"):
        return port
    if not _HEX_ADDR.match(host):
        return None
    return port


def parse_ss_established(text: str, ports) -> tuple:
    """Count inbound established connections to *ports*.

    Returns ``(inbound, total)``.  The *local* address is always printed before
    the peer address, so the first address token on a line is the local one --
    that holds whether or not ``ss`` printed the State column, which is exactly
    what the original code got wrong.
    """
    want = set()
    for p in ports or ():
        try:
            want.add(int(p))
        except (TypeError, ValueError):
            continue
    inbound = 0
    total = 0
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        tokens = line.split()
        addrs = [t for t in tokens if _addr_port(t) is not None]
        if not addrs:
            continue
        total += 1
        port = _addr_port(addrs[0])
        if port and port.isdigit() and int(port) in want:
            inbound += 1
    return inbound, total


# --------------------------------------------------------------------------
# Address / whitelist helpers
# --------------------------------------------------------------------------
def local_addresses() -> set:
    """Every address configured on a local interface, plus loopback."""
    found = {"127.0.0.1", "::1"}
    ok, out, _ = shell.run(["ip", "-o", "addr", "show"], timeout=5)
    if ok:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) > 3:
                addr = parts[3].split("/")[0]
                try:
                    found.add(str(ipaddress.ip_address(addr)))
                except ValueError:
                    continue
    return found


def whitelist_sources(entries, auto_local: bool = True) -> tuple:
    """Split whitelist *entries* into firewall-ready v4/v6 source strings.

    Returns ``(v4, v6, bad)``.  CIDRs are preserved (the original dropped
    anything that was not a bare ``/32``) and IPv6 never reaches ``iptables``.
    Loopback is always included so neither daemon can ever throttle itself.
    """
    sources = list(entries or [])
    sources += ["127.0.0.0/8", "::1/128"]
    if auto_local:
        sources += sorted(local_addresses())
    v4, v6, bad = [], [], []
    for item in sources:
        text = str(item).strip()
        if not text:
            continue
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            bad.append(text)
            continue
        target = v4 if net.version == 4 else v6
        rendered = str(net)
        if rendered not in target:
            target.append(rendered)
    return v4, v6, bad


# --------------------------------------------------------------------------
# The shedder
# --------------------------------------------------------------------------
class LoadShedder:
    """Monitors load/connections and switches protection on and off."""

    def __init__(self, cfg, log=None, dry_run: bool = False, echo: bool = False):
        # Defence in depth: refuse to run on an unparseable config even when a
        # caller constructs the shedder directly instead of going through main().
        assert_config_parsable(cfg.path)
        self.cfg = cfg
        self.dry_run = dry_run
        self.log = log or get_logger("threat", echo=echo)
        self.stop = threading.Event()
        self._exit_signal = 0
        self.trace = []                    # decisions, used by --self-test

        self.check_interval = float(_cfg(cfg, "check_interval",
                                         LOADSHED_DEFAULTS["check_interval"]))
        self.warn_load = float(_cfg(cfg, "warn_load", LOADSHED_DEFAULTS["warn_load"]))
        self.warn_conn = int(_cfg(cfg, "warn_conn", LOADSHED_DEFAULTS["warn_conn"]))
        self.protect_load = float(_cfg(cfg, "protect_load",
                                       LOADSHED_DEFAULTS["protect_load"]))
        self.protect_conn = int(_cfg(cfg, "protect_conn",
                                     LOADSHED_DEFAULTS["protect_conn"]))
        self.release_load = float(_cfg(cfg, "release_load",
                                       LOADSHED_DEFAULTS["release_load"]))
        self.release_conn = int(_cfg(cfg, "release_conn",
                                     LOADSHED_DEFAULTS["release_conn"]))
        self.protect_confirm = max(1, int(_cfg(cfg, "protect_confirm",
                                               LOADSHED_DEFAULTS["protect_confirm"])))
        self.release_confirm = max(1, int(_cfg(cfg, "release_confirm",
                                               LOADSHED_DEFAULTS["release_confirm"])))
        self.connlimit = int(_cfg(cfg, "connlimit_per_ip",
                                  LOADSHED_DEFAULTS["connlimit_per_ip"]))
        self.newconn_rate = int(_cfg(cfg, "newconn_rate_per_ip",
                                     LOADSHED_DEFAULTS["newconn_rate_per_ip"]))
        self.newconn_burst = int(_cfg(cfg, "newconn_burst",
                                      LOADSHED_DEFAULTS["newconn_burst"]))
        self.chain = str(_cfg(cfg, "chain", LOADSHED_DEFAULTS["chain"]))
        self.ports = [int(p) for p in (_cfg(cfg, "ports",
                                            LOADSHED_DEFAULTS["ports"]) or [])]
        self.hashlimit_expire = str(_cfg(cfg, "hashlimit_expire_ms",
                                         LOADSHED_DEFAULTS["hashlimit_expire_ms"]))
        self.hashlimit_name = str(_cfg(cfg, "hashlimit_name",
                                       LOADSHED_DEFAULTS["hashlimit_name"]))
        self.alert_cooldown = int(_cfg(cfg, "alert_cooldown",
                                       LOADSHED_DEFAULTS["alert_cooldown"]))

        # Shared, schema-owned configuration.
        self.threat_set = str(cfg.get("threat.ipset_set", "vigil_threat"))
        self.whitelist_entries = list(cfg.get("threat.whitelist",
                                              ["127.0.0.1/8", "::1"]) or [])
        self.auto_whitelist_local = bool(cfg.get("threat.auto_whitelist_local", True))

        self.level = LEVEL_NORMAL
        self.hits = {"protect": 0, "release": 0}
        self._adopted = False
        self._last_alert = 0.0
        self._iptables = shell.which("iptables", "/usr/sbin/iptables", "/sbin/iptables")
        self._ip6tables = shell.which("ip6tables", "/usr/sbin/ip6tables",
                                      "/sbin/ip6tables")
        self._ss = shell.which("ss", "/usr/sbin/ss", "/bin/ss", "/usr/bin/ss")

    # -- small helpers -----------------------------------------------------
    def audit(self, message: str) -> None:
        self.trace.append(message)
        self.log.info(message)

    def _plan(self, argv) -> None:
        """Record (and in dry-run, print) a firewall command without running it."""
        line = shell.quote(argv)
        self.trace.append("+ " + line)
        if self.dry_run:
            self.log.info("[dry-run] %s", line)

    def families(self):
        """Address families we can actually manage on this host."""
        out = []
        if self._iptables:
            out.append(4)
        if self._ip6tables:
            out.append(6)
        return out

    def _binary(self, family: int) -> str:
        return self._iptables if family == 4 else self._ip6tables

    def _ipt(self, family: int, args, timeout: float = 15):
        binary = self._binary(family)
        if not binary:
            return False, "", "not found"
        if self.dry_run:
            self._plan([binary] + list(args))
            return True, "", ""
        return shell.run([binary] + list(args), timeout=timeout)

    # -- metrics -----------------------------------------------------------
    def read_load(self) -> float:
        try:
            return float(os.getloadavg()[0])
        except (OSError, ValueError):
            return 0.0

    def read_established(self) -> tuple:
        """(inbound 80/443 connections, total established)."""
        if not self._ss:
            return 0, 0
        ok, out, _ = shell.run([self._ss, "-Htn", "state", "established"], timeout=10)
        if not ok or not out.strip():
            # Older/limited builds reject the state filter; fall back to a
            # plain listing.  The parser is header/column independent, so the
            # fallback cannot silently change which field we read.
            ok, out, _ = shell.run([self._ss, "-Htn"], timeout=10)
        if not ok:
            return 0, 0
        return parse_ss_established(out, self.ports)

    def metrics(self) -> tuple:
        load1 = self.read_load()
        conns, total = self.read_established()
        self.log.debug(_t("sampled", load1, conns, self.protect_load,
                          self.protect_conn, self.release_load, self.release_conn))
        return load1, conns, total

    # -- firewall inspection ----------------------------------------------
    def chain_exists(self, family: int) -> bool:
        ok, _out, _err = self._ipt(family, ["-S", self.chain])
        return ok

    def chain_present(self, family: int) -> bool:
        ok, out, _err = self._ipt(family, ["-S", self.chain])
        if not ok:
            return False
        return any(l.startswith("-A") for l in out.splitlines())

    def jump_present(self, family: int) -> bool:
        ok, out, _err = self._ipt(family, ["-S", "INPUT"])
        if not ok:
            return False
        return any(l.startswith("-A INPUT") and ("-j %s" % self.chain) in l
                   for l in out.splitlines())

    def _input_lines(self, family: int):
        ok, out, _err = self._ipt(family, ["-S", "INPUT"])
        return out.splitlines() if ok else []

    def _jump_position(self, family: int):
        """(current rule number or None, target rule number)."""
        lines = self._input_lines(family)
        jump_at = None
        threat_at = None
        for idx, line in enumerate(lines):
            if not line.startswith("-A INPUT"):
                continue
            if ("-j %s" % self.chain) in line:
                jump_at = idx
            if ("--match-set %s src" % self.threat_set) in line:
                threat_at = idx
        # Rule number equals the line index: index 0 is the "-P INPUT" policy.
        # Place our jump directly after the threat DROP rule when it exists, so
        # bans win but shed rules still run before permissive rules.
        target = (threat_at + 1) if threat_at is not None else 1
        return jump_at, target

    def _ensure_jump(self, family: int) -> bool:
        jump_at, target = self._jump_position(family)
        if jump_at == target:
            return True
        if jump_at is not None:
            lines = self._input_lines(family)
            spec = lines[jump_at].split()
            # "-A INPUT -j CHAIN" -> "-D INPUT -j CHAIN"
            argv = ["-D"] + spec[1:]
            self._ipt(family, argv)
            self.log.warn("已调整 %s 链跳转顺序（从第 %d 条移到第 %d 条）",
                          "IPv4" if family == 4 else "IPv6", jump_at, target)
        ok, _out, err = self._ipt(family, ["-I", "INPUT", str(target), "-j", self.chain])
        if not ok:
            self.log.error("插入 %s 限流跳转失败：%s", self.chain, oneline(err, 160))
        return ok

    def _drop_jump(self, family: int) -> None:
        lines = self._input_lines(family)
        for idx, line in enumerate(lines):
            if line.startswith("-A INPUT") and ("-j %s" % self.chain) in line:
                self._ipt(family, ["-D"] + line.split()[1:])
                self.log.info("已移除 %s 限流跳转（第 %d 条）", self.chain, idx)

    # -- firewall mutation -------------------------------------------------
    def _whitelist_sources(self) -> tuple:
        v4, v6, bad = whitelist_sources(self.whitelist_entries,
                                        self.auto_whitelist_local)
        for item in bad:
            self.log.warn(_t("bad_whitelist", item))
        return v4, v6

    def enable(self) -> bool:
        """Install the shed rules and raise the runtime flag."""
        families = self.families()
        if 4 not in families and not self.dry_run:
            self.log.error(_t("no_firewall"))
            return False
        if 6 not in families and self._iptables:
            self.log.warn(_t("no_ip6tables"))
        if not self.ports:
            self.log.error("未配置需要限流的端口（loadshed.ports 为空），拒绝启用")
            return False

        v4, v6 = self._whitelist_sources()
        for family in families:
            if not self.chain_exists(family):
                self._ipt(family, ["-N", self.chain])
            self._ipt(family, ["-F", self.chain])
            # 1) whitelist is exempt from BOTH limit rules
            for src in (v4 if family == 4 else v6):
                self._ipt(family, ["-A", self.chain, "-s", src, "-j", "RETURN"])
            ports = ",".join(str(p) for p in self.ports)
            # 2) per-source concurrent connections
            mask = "32" if family == 4 else "128"
            self._ipt(family, [
                "-A", self.chain, "-p", "tcp",
                "-m", "multiport", "--dports", ports,
                "-m", "connlimit", "--connlimit-above", str(self.connlimit),
                "--connlimit-mask", mask,
                "-j", "REJECT", "--reject-with", "tcp-reset",
            ])
            # 3) per-source new-connection rate
            name = self.hashlimit_name if family == 4 else self.hashlimit_name + "6"
            self._ipt(family, [
                "-A", self.chain, "-p", "tcp",
                "-m", "multiport", "--dports", ports,
                "-m", "conntrack", "--ctstate", "NEW",
                "-m", "hashlimit",
                "--hashlimit-above", "%d/sec" % self.newconn_rate,
                "--hashlimit-burst", str(self.newconn_burst),
                "--hashlimit-mode", "srcip",
                "--hashlimit-name", name,
                "--hashlimit-htable-expire", self.hashlimit_expire,
                "-j", "DROP",
            ])
            self._ensure_jump(family)
        self._write_flag()
        self.log.warn("已进入保护模式：单源并发<=%d，单源新建<=%d/s（端口 %s）",
                      self.connlimit, self.newconn_rate,
                      ",".join(str(p) for p in self.ports))
        return True

    def disable(self, quiet: bool = False) -> None:
        """Remove the jump and the chain, then clear the flag."""
        for family in (4, 6):
            if not self._binary(family):
                continue
            self._drop_jump(family)
            self._ipt(family, ["-F", self.chain])
            self._ipt(family, ["-X", self.chain])
        self._clear_flag()
        if not quiet:
            self.log.warn("已解除保护模式，限流规则已撤销")

    # -- runtime flag ------------------------------------------------------
    def _write_flag(self) -> None:
        if self.dry_run:
            self.trace.append("+ write %s" % SHED_FLAG)
            return
        try:
            SHED_FLAG.parent.mkdir(parents=True, exist_ok=True)
            write_text(SHED_FLAG, "%d\n" % int(time.time()), mode=0o644)
        except OSError as exc:
            self.log.warn("写入严格模式标记失败：%s", exc)

    def _clear_flag(self) -> None:
        if self.dry_run:
            self.trace.append("+ remove %s" % SHED_FLAG)
            return
        try:
            os.remove(SHED_FLAG)
        except FileNotFoundError:
            pass
        except OSError as exc:
            self.log.warn("清除严格模式标记失败：%s", exc)

    # -- startup reconciliation (defect: SIGKILL left rules forever) -------
    def reconcile(self) -> str:
        """Adopt or clean up whatever the previous run left behind.

        The runtime flag is the authoritative record of *intent*; the chain is
        the record of *effect*.  Adopt only when both agree that we were
        protecting (the flag was written only after the rules were installed,
        so an unclean kill during protection leaves all three).  Anything else
        is an inconsistent leftover and is removed deliberately -- that is what
        stops a SIGKILL from rate-limiting the host forever.
        """
        flag = SHED_FLAG.exists()
        rules = self.chain_present(4) or self.chain_present(6)
        jump = self.jump_present(4) or self.jump_present(6)

        if flag and rules and jump:
            # Previous run was protecting when it died (or systemd restarted us
            # mid-protection).  Keep protecting.
            self.level = LEVEL_PROTECT
            self._adopted = True
            self.log.warn(_t("already_protecting"))
            return "adopted"
        if flag and not rules and not jump:
            # Flag written but the firewall is clean (rules cleared by a panel
            # reload, or a crash between flag write and... nothing else).  Drop
            # the flag so the threat daemon leaves strict mode.
            self._clear_flag()
            self.log.warn(_t("stale_flag"))
            return "stale-flag"
        if rules or jump:
            # Leftover rules without a matching flag, or half-installed
            # protection (jump with an empty chain, chain with no jump).
            # Neither is a state we can trust, so undo it.
            self.log.warn(_t("stale_rules"))
            self.disable(quiet=True)
            return "cleaned"
        return "clean"

    # -- state machine -----------------------------------------------------
    def evaluate(self, load1: float, conns: int, maintenance: bool = False) -> str:
        """One decision cycle.  Returns an action string.

        Kept separate from :meth:`run` so ``--self-test`` exercises the real
        hysteresis logic without touching the firewall.
        """
        if maintenance and self.level == LEVEL_NORMAL:
            self.hits["protect"] = 0
            return "maintenance"

        over = load1 > self.protect_load or conns > self.protect_conn
        under = load1 < self.release_load and conns < self.release_conn

        if self.level == LEVEL_NORMAL:
            self.hits["release"] = 0
            if over:
                self.hits["protect"] += 1
                if self.hits["protect"] >= self.protect_confirm:
                    self.hits["protect"] = 0
                    if self.enable():
                        self.level = LEVEL_PROTECT
                        return "protect"
                    return "protect-failed"
            else:
                self.hits["protect"] = 0
        else:
            self.hits["protect"] = 0
            if under:
                self.hits["release"] += 1
                if self.hits["release"] >= self.release_confirm:
                    self.hits["release"] = 0
                    self.disable()
                    self.level = LEVEL_NORMAL
                    return "release"
            else:
                self.hits["release"] = 0
        return "hold"

    # -- alerting ----------------------------------------------------------
    def notify_state(self, enabled: bool, load1: float, conns: int) -> None:
        title = _t("protect_on") if enabled else _t("protect_off")
        alert = Alert(
            title=title,
            severity=SEV_WARN if enabled else SEV_INFO,
            kind=KIND_ALERT,
            summary=("检测到负载异常，已自动启用单源限流以保护服务可用性。"
                     if enabled else
                     "负载已恢复正常，限流规则已全部撤销。"),
            dedupe_key="loadshed|%s" % ("on" if enabled else "off"),
        )
        alert.add_section("触发指标", [
            "1 分钟负载：%.2f（进入阈值 %.1f / 解除阈值 %.1f）"
            % (load1, self.protect_load, self.release_load),
            "80/443 已建立连接：%d（进入阈值 %d / 解除阈值 %d）"
            % (conns, self.protect_conn, self.release_conn),
            "CPU 核心数：%d" % (os.cpu_count() or 1),
        ])
        if enabled:
            alert.add_section("已实施动作", [
                "单源并发连接上限：%d" % self.connlimit,
                "单源新建连接速率上限：%d/s（突发 %d）"
                % (self.newconn_rate, self.newconn_burst),
                "限流链：%s（IPv4 %s / IPv6 %s）" % (
                    self.chain,
                    "已安装" if self._iptables else "不可用",
                    "已安装" if self._ip6tables else "不可用"),
                "风控已进入严格模式：封禁阈值收紧，攻击源会被更快切断。",
            ])
            v4, v6 = self._whitelist_sources()
            alert.add_section("白名单豁免（不受限流影响）", [
                "IPv4：%s" % ("、".join(v4) if v4 else "无"),
                "IPv6：%s" % ("、".join(v6) if v6 else "无"),
            ])
            alert.footer = ("负载回落到解除阈值以下并连续确认 %d 次后，"
                            "限流会自动撤销。" % self.release_confirm)
        else:
            alert.add_section("已撤销动作", [
                "限流链 %s 已清空并删除，INPUT 跳转已移除。" % self.chain,
                "风控已恢复常规阈值。",
            ])
            alert.footer = "查看当前状态：`ipset list %s`" % self.threat_set

        if self.dry_run:
            self.trace.append("ALERT: %s" % title)
            return
        # Reuse the threat daemon's alert sink so both guards route through the
        # same mail path.  Imported lazily to keep this module import-light.
        try:
            from .threat import send_alert
        except Exception as exc:                       # noqa: BLE001
            self.log.warn("告警模块不可用，本次告警未发出：%s", exc)
            return
        send_alert(alert, cfg=self.cfg, log=self.log)

    # -- lifecycle ---------------------------------------------------------
    def _on_signal(self, signum, _frame) -> None:
        # Signal handlers must stay async-signal-safe: no subprocess, no file
        # I/O.  Record the signal and let the main loop do the cleanup.
        self._exit_signal = signum
        self.stop.set()

    def run(self) -> int:
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, self._on_signal)
            except (ValueError, OSError):
                pass

        self.log.warn(_t("started", os.getpid(), os.cpu_count() or 1))
        self.log.info(_t("thresholds", self.protect_load, self.protect_conn,
                         self.release_load, self.release_conn))
        self.reconcile()
        if self.level == LEVEL_PROTECT:
            self.log.info("当前状态：保护模式（已接管）")

        try:
            while not self.stop.is_set():
                try:
                    load1, conns, _total = self.metrics()
                    action = self.evaluate(load1, conns,
                                           maintenance=MAINTENANCE_FLAG.exists())
                    if action == "protect":
                        self.notify_state(True, load1, conns)
                    elif action == "release":
                        self.notify_state(False, load1, conns)
                    elif action == "protect-failed":
                        self.log.error(_t("enable_failed"))
                    elif action == "maintenance":
                        self.log.info(_t("skip_maintenance"))
                    elif load1 > self.warn_load and self.level == LEVEL_NORMAL:
                        self.log.warn(_t("warn_load", load1, conns))
                except Exception as exc:               # noqa: BLE001
                    self.log.warn(_t("cycle_error", exc))
                self.stop.wait(self.check_interval)
        finally:
            if self.level == LEVEL_PROTECT:
                # Graceful stop always releases protection; an unclean stop is
                # handled by reconcile() on the next start.
                self.disable(quiet=True)
            self.log.warn(_t("stopped"))
        return 0

    # -- introspection -----------------------------------------------------
    def describe(self) -> dict:
        return {
            "level": self.level,
            "adopted": self._adopted,
            "flag": str(SHED_FLAG),
            "flag_present": SHED_FLAG.exists(),
            "chain": self.chain,
            "chain_v4": self.chain_present(4),
            "chain_v6": self.chain_present(6),
            "jump_v4": self.jump_present(4),
            "jump_v6": self.jump_present(6),
            "iptables": self._iptables,
            "ip6tables": self._ip6tables,
            "ports": self.ports,
            "connlimit_per_ip": self.connlimit,
            "newconn_rate_per_ip": self.newconn_rate,
            "whitelist_source_key": "threat.whitelist",
            "whitelist_entries": self.whitelist_entries,
        }


# --------------------------------------------------------------------------
# Self test / status
# --------------------------------------------------------------------------
_SS_SAMPLES = [
    ("带 State 列（inbound 80）", "ESTAB 0 0 10.0.0.1:80 10.0.0.9:51000"),
    ("无 State 列（inbound 443）", "0 0 10.0.0.1:443 10.0.0.9:51001"),
    ("无 State 列（outbound 80，不应计数）", "0 0 10.0.0.1:51002 93.184.216.34:80"),
    ("IPv6 inbound（[::]:443）", "[::]:443 [2001:db8::9]:51003"),
    ("通配地址（*:80）", "*:80 10.0.0.9:51004"),
]


def self_test(cfg) -> int:
    """Exercise the real parsers and hysteresis logic.  No firewall access."""
    shed = LoadShedder(cfg, dry_run=True, echo=True)
    print("=" * 68)
    print("loadshed self-test (dry-run: iptables/ip6tables are NOT touched)")
    print("ports=%s chain=%s" % (shed.ports, shed.chain))
    print("=" * 68)
    print("\n[1] ss 解析（修复位置索引缺陷：含/不含 State 列、IPv4/IPv6）")
    for label, text in _SS_SAMPLES:
        inbound, total = parse_ss_established(text, shed.ports)
        print("  %-34s inbound=%d total=%d" % (label, inbound, total))
    mixed = "\n".join(text for _label, text in _SS_SAMPLES)
    inbound, total = parse_ss_established(mixed, shed.ports)
    print("  合并样本 -> inbound=%d total=%d（期望 inbound=4, total=5）"
          % (inbound, total))

    print("\n[2] 状态机（滞回 + 连续确认），进入 2 次、解除 3 次")
    seq = [(8.0, 1200), (8.0, 1200), (8.0, 1200), (1.0, 100),
           (1.0, 100), (1.0, 100), (1.0, 100)]
    for load, conns in seq:
        action = shed.evaluate(load, conns)
        print("  load1=%4.1f conns=%5d -> level=%-7s action=%s"
              % (load, conns, shed.level, action))
        if action == "protect":
            shed.notify_state(True, load, conns)
        elif action == "release":
            shed.notify_state(False, load, conns)
    print("\n[3] 白名单拆分（CIDR 保留、IPv6 不交给 iptables）")
    v4, v6, bad = whitelist_sources(["10.0.0.0/8", "192.168.1.5", "::1",
                                     "2001:db8::/32", "not-an-ip"], auto_local=False)
    print("  IPv4: %s" % v4)
    print("  IPv6: %s" % v6)
    print("  非法: %s" % bad)
    print("\n[4] 防火墙动作计划（dry-run，未执行）")
    for line in shed.trace:
        if line.startswith("+"):
            print("  " + line)
    print("\nself-test 完成：未执行任何 iptables/ipset 命令。")
    return 0


def _print_status(cfg) -> int:
    shed = LoadShedder(cfg)
    info = shed.describe()
    print(json.dumps(info, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="vigil-loadshed",
        description="Vigil load shedder: reversible per-source rate limiting.")
    parser.add_argument("--config", default=None,
                        help="path to config.json (default: %s)" % paths.CONFIG)
    parser.add_argument("--self-test", action="store_true",
                        help="validate ss parsing and hysteresis, touch nothing")
    parser.add_argument("--status", action="store_true",
                        help="print runtime/flag/chain state and exit")
    parser.add_argument("--dry-run", action="store_true",
                        help="decide but never change the firewall")
    parser.add_argument("--lang", default="", help="ui language: zh or en")
    args = parser.parse_args(argv)

    if args.lang:
        set_language(args.lang)

    cfg = load_config(args.config) if args.config else load_config()
    # Loud config handling: never silently fall back on a broken file.
    try:
        assert_config_parsable(cfg.path)
    except ConfigError as exc:
        print("错误：%s" % exc, file=sys.stderr)
        return 2

    if args.self_test:
        return self_test(cfg)
    if args.status:
        return _print_status(cfg)
    return LoadShedder(cfg, dry_run=args.dry_run, echo=True).run()


if __name__ == "__main__":                              # pragma: no cover
    sys.exit(main())
