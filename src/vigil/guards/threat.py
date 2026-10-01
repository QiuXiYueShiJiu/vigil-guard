# -*- coding: utf-8 -*-
"""Real-time attack detection and automatic banning.

This is the port of the original ``dsh-threatd.py`` onto the Vigil core.  The
detection capability is preserved; the defects found in the original are fixed.
Each fix is called out where it lives:

======================  =====================================================
Defect                  Where it is fixed
======================  =====================================================
signatures compiled     :meth:`ThreatDaemon._compile_signatures` runs from the
before config merge     **merged** config, after ``Config`` is loaded.
silent config fallback  :func:`attacks.assert_config_parsable` +
                        :func:`_ladder` refuse to start on a broken file.
``ss`` field parsing    :mod:`vigil.guards.loadshed` (owned there).
load-shed startup       :meth:`LoadShedder.reconcile` (owned there).
unverified bans         :meth:`ThreatDaemon.ban` checks the ``ipset add``
                        result and reports ``封禁失败`` when it did not work.
rule priority           :meth:`Enforcer.assert_priority` verifies the DROP
                        rule's position and moves it back to first.
whitelist parity        :class:`Whitelist` + ``loadshed.whitelist_sources``
                        (CIDR and IPv6 everywhere).
fail closed on bad IP   :meth:`Whitelist._compute` returns ``False`` (and
                        logs) for an address it cannot parse.
bounded maps            :class:`Windows`, :class:`BehaviorStore`,
                        :class:`CooldownMap`, :class:`DistributedTracker`,
                        :class:`ThreatState` all prune.
non-blocking alerts     :class:`EventReporter` -- tail threads only enqueue.
signal-safe shutdown    :meth:`ThreatDaemon._on_signal` only sets a flag.
cached strict mode      :class:`StrictMode` (short TTL instead of a stat per
                        log line).
real HTTP status class  :meth:`ThreatDaemon.handle_http` prints ``4xx``/``5xx``
                        from ``status // 100``.
======================  =====================================================

Configuration comes exclusively from ``Config.get("threat...")``; the exact
key names are those in ``core/config.py``.  Keys that the schema does not yet
define are read as documented extensions and listed by ``--show-config``.
"""
from __future__ import annotations

import argparse
import inspect
import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path

from ..core import detect, paths, shell
from ..core.config import load as load_config
from ..core.logging import get as get_logger
from ..core.state import locked, read_json, write_json, write_text
from ..i18n import language, set_language, t as i18n_t
from ..mail.message import (Alert, KIND_ALERT, SEV_CRIT, SEV_INFO, SEV_WARN)
from . import attacks
from .attacks import ConfigError, assert_config_parsable
from .checks import util
from .checks.util import geo, human_seconds, oneline
from .loadshed import SHED_FLAG

_MISSING = object()

# --------------------------------------------------------------------------
# i18n
# --------------------------------------------------------------------------
_TEXT = {
    "zh": {
        "started": "threatd 启动（PID %d）",
        "ready": "就绪：监控 %d 个日志源",
        "whitelist": "白名单：%s",
        "sources": "日志源：auth=%s | nginx=%s | panel=%s",
        "stopped": "已退出，状态已保存",
        "signal": "收到信号 %d，准备退出（由主循环完成收尾）",
        "strict_on": "严格模式已启用：封禁阈值收紧",
        "strict_off": "严格模式已解除",
        "tail_reconnect": "%s 的 tail 中断，5 秒后重连",
        "tail_missing": "无法 tail %s：%s",
        "tail_binary": "从自动探测结果中剔除二进制日志：%s",
        "enforce_failed": "封禁 %s 失败（未生效）：%s",
        "enforce_ok": "封禁 %s 共 %s（第 %d 次违规，检测器 %s，原因：%s）",
        "ban_skip_whitelist": "白名单地址命中规则，已放行（不封禁）：%s（%s）",
        "ban_bad_ip": "地址非法，拒绝封禁：%s",
        "breaker": "熔断：暂停封禁（%d/%d 次），请人工确认是否遭受伪造源地址攻击",
        "distributed": "分布式爆破：%d 个来源 IP / %d 次认证失败（%d 秒窗口）",
        "restored": "已恢复 %d 条未到期封禁",
        "purged": "已强制解封白名单地址 %d 个：%s",
        "selfheal": "检测到风控规则缺失（set缺失=%s, 规则缺失=%s），正在自愈",
        "set_created": "已创建 ipset 集合 %s",
        "rule_inserted": "已插入拦截规则（%s 第 1 条，集合 %s）",
        "rule_reordered": "拦截规则原在第 %d 条，已恢复到第 1 条",
        "no_tail": "未找到 tail 命令，无法跟踪日志",
        "lock_busy": "另一个 threatd 实例正在运行，拒绝启动",
        "housekeeping": "清理完成：违规=%d 封禁=%d 行为=%d 窗口=%d",
        "breach": "疑似爆破成功",
        "offwhitelist": "非白名单 IP 成功登录",
        "event_flush": "上报事件：%s（%d 条）",
        "alert_no_mail": "邮件模块不可用，告警仅在日志中记录：%s",
        "alert_no_func": "邮件模块未提供 send_alert()，告警仅在日志中记录：%s",
        "alert_failed": "告警发送失败：%s",
        "http_bad_line": "无法解析的访问日志行，已忽略：%s",
        "signature_bad": "签名正则非法，已忽略：%s",
        "signature_empty": "漏洞签名表为空，拒绝启动（会导致检测失效）",
        "static_bad": "static_ext 正则非法，拒绝启动",
    },
    "en": {
        "started": "threatd starting (pid %d)",
        "ready": "ready: watching %d log sources",
        "whitelist": "whitelist: %s",
        "sources": "sources: auth=%s | nginx=%s | panel=%s",
        "stopped": "stopped, state saved",
        "signal": "signal %d received, shutting down from the main loop",
        "strict_on": "strict mode enabled: ban thresholds tightened",
        "strict_off": "strict mode released",
        "tail_reconnect": "tail of %s ended, reconnecting in 5s",
        "tail_missing": "cannot tail %s: %s",
        "tail_binary": "dropped binary log from auto-detection: %s",
        "enforce_failed": "ban of %s FAILED (not enforced): %s",
        "enforce_ok": "banned %s for %s (offense %d, detector %s, reason: %s)",
        "ban_skip_whitelist": "whitelisted address matched a rule, allowing: %s (%s)",
        "ban_bad_ip": "invalid address, refusing to ban: %s",
        "breaker": "circuit breaker: banning paused (%d/%d), check for spoofed sources",
        "distributed": "distributed brute force: %d source IPs / %d auth failures (%ds)",
        "restored": "restored %d unexpired bans",
        "purged": "force-unbanned %d whitelisted addresses: %s",
        "selfheal": "enforcement rules missing (set=%s, rule=%s), healing",
        "set_created": "created ipset set %s",
        "rule_inserted": "inserted DROP rule (%s position 1, set %s)",
        "rule_reordered": "DROP rule was at position %d, moved back to 1",
        "no_tail": "tail not found; cannot follow logs",
        "lock_busy": "another threatd instance is running; refusing to start",
        "housekeeping": "pruned: offenses=%d bans=%d behavior=%d windows=%d",
        "breach": "probable brute-force success",
        "offwhitelist": "successful login from a non-whitelisted IP",
        "event_flush": "reporting events: %s (%d)",
        "alert_no_mail": "mail package unavailable, alert logged only: %s",
        "alert_no_func": "mail package has no send_alert(), alert logged only: %s",
        "alert_failed": "alert delivery failed: %s",
        "http_bad_line": "unparseable access log line ignored: %s",
        "signature_bad": "invalid signature regex ignored: %s",
        "signature_empty": "exploit signature table is empty; refusing to start",
        "static_bad": "static_ext regex invalid; refusing to start",
    },
}


def _t(key: str, *args) -> str:
    """Translate a fixed string, formatting with *args when given."""
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
# Small config coercion helpers (all failures are loud where it matters)
# --------------------------------------------------------------------------
def _int(value, default: int, minimum=None) -> int:
    try:
        out = int(value)
    except (TypeError, ValueError):
        return default
    if minimum is not None and out < minimum:
        return minimum
    return out


def _num(value, default: float, minimum=None) -> float:
    try:
        out = float(value)
    except (TypeError, ValueError):
        return default
    if minimum is not None and out < minimum:
        return minimum
    return out


#: The largest timeout `ipset` will accept, in seconds.
#:
#: ipset stores a timeout as a signed 32-bit count of *milliseconds*, so the
#: ceiling is 2147483 seconds -- about 24.8 days, not "thirty days". A ladder
#: that stepped past it was accepted by the config validator, passed
#: `nginx -t`-style syntax checks, and then failed **at the moment of
#: enforcement**: `ipset v7.15: Syntax error: '2592000' is out of range`.
#: The ban simply did not happen, and the only reason it was noticed at all is
#: that a failed ban raises its own alert. Durations are therefore clamped
#: here, at configuration time, because an unenforceable duration is not a
#: duration -- it is a silent hole in the defence.
IPSET_MAX_TIMEOUT = 2147483


def _clamp_seconds(seconds: int, where: str = "") -> int:
    if seconds > IPSET_MAX_TIMEOUT:
        return IPSET_MAX_TIMEOUT
    return seconds


def _ladder(value, default) -> list:
    """Validate and normalise a ban-duration ladder.

    A malformed ladder is fatal: silently substituting the default could either
    ban an innocent address for a week or release an attacker in seconds.

    Values above what the enforcer can actually apply are clamped rather than
    rejected, because the operator's *intent* -- "ban this for as long as
    possible" -- is clear and achievable; it is only the number that is
    impossible.
    """
    if value is None:
        return [int(x) for x in default]
    if not isinstance(value, (list, tuple)) or not value:
        raise ConfigError("ban_seconds 必须是非空的秒数列表（当前：%r）" % (value,))
    out = []
    for item in value:
        try:
            seconds = int(item)
        except (TypeError, ValueError):
            raise ConfigError("ban_seconds 只能包含数字（当前：%r）" % (value,))
        if seconds <= 0:
            raise ConfigError("ban_seconds 不能包含非正数（当前：%r）" % (value,))
        out.append(_clamp_seconds(seconds))
    return out


_BINARY_AUTH_LOGS = ("wtmp", "btmp", "lastlog", "utmp")


class Settings:
    """Resolved ``threat`` settings, with an audit trail of every key read.

    Every value comes from ``cfg.get("threat...", default)``.  Values marked
    ``in_schema=False`` are extension keys: the schema in ``core/config.py``
    does not define them yet, so the built-in default applies unless the
    operator adds them (see ``--show-config`` and the port report).
    """

    def __init__(self, cfg):
        self.cfg = cfg
        self.keys_read: list = []

        # -- daemon ------------------------------------------------------
        self.enabled = bool(self._r("threat.enabled", True))
        self.poll_interval = _num(self._r("threat.poll_interval", 5), 5, minimum=1)
        self.whitelist = list(self._r("threat.whitelist",
                                      ["127.0.0.1/8", "::1"]) or [])
        self.auto_whitelist_local = bool(
            self._r("threat.auto_whitelist_local", True, in_schema=False))
        self.notify_bans = bool(self._r("threat.notify_bans", True))
        self.notify_ssh_success = bool(self._r("threat.notify_ssh_success", True))
        self.max_bans_per_hour = _int(self._r("threat.max_bans_per_hour", 60), 60,
                                      minimum=1)
        self.recidivist_bans = _int(self._r("threat.recidivist_bans", 3), 3,
                                    minimum=1)
        self.recidivist_ban_seconds = _clamp_seconds(_int(
            self._r("threat.recidivist_ban_seconds", 604800), 604800,
            minimum=1))

        # -- SSH ---------------------------------------------------------
        self.ssh_enabled = bool(self._r("threat.ssh.enabled", True))
        self.ssh_max_failures = _int(self._r("threat.ssh.max_failures", 5), 5,
                                     minimum=1)
        self.ssh_window = _int(self._r("threat.ssh.window_seconds", 300), 300,
                               minimum=1)
        self.ssh_ban_seconds = _ladder(
            self._r("threat.ssh.ban_seconds", [600, 3600, 21600, 86400]),
            [600, 3600, 21600, 86400])
        # Original had a dedicated ssh_invalid_threshold (8 with a default
        # max_failures of 5).  The schema has no such key, so it is derived to
        # preserve the original tuning and remains overridable.
        self.ssh_invalid_threshold = _int(
            self._r("threat.ssh.invalid_user_threshold",
                    max(self.ssh_max_failures, int(round(self.ssh_max_failures * 1.6))),
                    in_schema=False),
            max(self.ssh_max_failures, int(round(self.ssh_max_failures * 1.6))),
            minimum=1)

        # -- HTTP --------------------------------------------------------
        self.http_enabled = bool(self._r("threat.http.enabled", True))
        self.http_max_attacks = _int(self._r("threat.http.max_attacks", 10), 10,
                                     minimum=1)
        self.http_window = _int(self._r("threat.http.window_seconds", 300), 300,
                                minimum=1)
        self.http_ban_seconds = _ladder(
            self._r("threat.http.ban_seconds", [600, 3600, 21600, 86400]),
            [600, 3600, 21600, 86400])

        # Signatures: read from the MERGED config (defect #1).  Both a nested
        # and a legacy top-level location are accepted; the built-in table in
        # attacks.py is the fallback.
        # An empty list/string here means "no override", not "no
        # signatures". Treating it as the latter made the daemon refuse to
        # start on a fresh install whose config carried empty defaults --
        # a self-inflicted outage. The `or` makes the intent explicit and
        # also protects an operator who clears the key by accident.
        self.exploit_high_patterns = list(self._rf(
            ["threat.http.exploit_high", "threat.exploit_high"],
            attacks.EXPLOIT_HIGH_PATTERNS) or attacks.EXPLOIT_HIGH_PATTERNS)
        self.exploit_low_patterns = list(self._rf(
            ["threat.http.exploit_low", "threat.exploit_low"],
            attacks.EXPLOIT_LOW_PATTERNS) or attacks.EXPLOIT_LOW_PATTERNS)
        self.static_ext_pattern = str(self._rf(
            ["threat.http.static_ext", "threat.static_ext"],
            attacks.STATIC_EXT_PATTERN) or attacks.STATIC_EXT_PATTERN)
        # Low-confidence probing: schema's http.max_attacks/window is the
        # intended knob; the original's 3/300 is the fallback for the window.
        self.exploit_low_hits = _int(self._rf(["threat.http.exploit_low_hits"],
                                              self.http_max_attacks), 
                                     self.http_max_attacks, minimum=1)
        self.exploit_low_window = _int(self._rf(["threat.http.exploit_low_window"],
                                                self.http_window),
                                       self.http_window, minimum=1)
        # Burst / flood thresholds have no schema key; original tuning kept.
        self.http_burst_threshold = _int(
            self._rf(["threat.http.burst_threshold"], 100), 100, minimum=1)
        self.http_burst_window = _int(
            self._rf(["threat.http.burst_window"], 60), 60, minimum=1)
        self.http_flood_threshold = _int(
            self._rf(["threat.http.flood_threshold"], 500), 500, minimum=1)
        self.http_flood_window = _int(
            self._rf(["threat.http.flood_window"], 60), 60, minimum=1)

        # -- port scan (schema section; the original had no detector) ----
        self.portscan_enabled = bool(self._r("threat.portscan.enabled", True))
        self.portscan_max_ports = _int(self._r("threat.portscan.max_ports", 30), 30,
                                       minimum=1)
        self.portscan_window = _int(self._r("threat.portscan.window_seconds", 120),
                                    120, minimum=1)
        self.portscan_ban_seconds = _ladder(
            self._r("threat.portscan.ban_seconds", [3600, 21600, 86400]),
            [3600, 21600, 86400])

        # -- netblock escalation -------------------------------------------
        # The most dangerous automatic decision this program makes: the unit
        # of punishment stops matching the unit of guilt. Off by default is
        # tempting, but a coordinated sweep from one subnet is exactly the
        # case per-address thresholds handle badly, so it is on -- with the
        # rails below doing the work that "off" would otherwise do.
        self.netblock_enabled = bool(self._r("threat.netblock.enabled", True))
        self.netblock_min_ips = _int(
            self._r("threat.netblock.min_ips", 6), 6, minimum=3)
        self.netblock_window = _int(
            self._r("threat.netblock.window_seconds", 1800), 1800, minimum=60)
        self.netblock_ban_seconds = _clamp_seconds(_int(
            self._r("threat.netblock.ban_seconds", 86400), 86400,
            minimum=300))
        self.netblock_max_current = _int(
            self._r("threat.netblock.max_current", 16), 16, minimum=1)
        self.netblock_confirm = _int(
            self._r("threat.netblock.ban_seconds", 86400), 86400, minimum=300)

        # -- attack-driven posture ----------------------------------------
        # Distinct from the load shedder: a slow, patient campaign against an
        # idle machine never moves the load average, so nothing would tighten
        # and every attempt would get the relaxed threshold.
        self.posture_enabled = bool(self._r("threat.posture.enabled", True))
        self.posture_window = _int(
            self._r("threat.posture.window_seconds", 300), 300, minimum=10)
        self.posture_trigger = _int(
            self._r("threat.posture.trigger_bans", 5), 5, minimum=1)
        self.posture_hold = _int(
            self._r("threat.posture.hold_seconds", 900), 900, minimum=30)
        self.posture_factor = _num(
            self._r("threat.posture.factor", 0.5), 0.5)

        # -- decoy endpoints ---------------------------------------------
        # A hit on a decoy path is not evidence, it is a conclusion: the
        # path does not exist on disk and nothing the site serves links to
        # it. There is no legitimate explanation to weigh, which is why the
        # first hit already earns a long ban rather than a warning.
        self.decoy_enabled = bool(self._r("threat.decoy.enabled", True))
        # 7 days / 14 days / the longest ipset can express (~24.8 days).
        # The previous 30d and 90d steps were unenforceable, so every decoy
        # escalation beyond the first silently failed.
        self.decoy_ban_seconds = _ladder(
            self._r("threat.decoy.ban_seconds",
                    [604800, 1209600, IPSET_MAX_TIMEOUT]),
            [604800, 1209600, IPSET_MAX_TIMEOUT])

        # -- ban policy --------------------------------------------------
        # Instant minimum for high-severity hits.  No schema key: derived from
        # the top of the enabled ladders (86400 for the defaults, matching the
        # original instant_ban_seconds).
        derived_instant = max(max(self.ssh_ban_seconds), max(self.http_ban_seconds))
        self.instant_ban_seconds = _clamp_seconds(_int(
            self._r("threat.instant_ban_seconds", derived_instant,
                    in_schema=False),
            derived_instant, minimum=1))
        self.offense_decay = _int(
            self._r("threat.offense_decay", 86400, in_schema=False), 86400,
            minimum=60)
        self.alert_cooldown = _int(
            self._r("threat.alert_cooldown", 600, in_schema=False), 600,
            minimum=0)

        # -- operations --------------------------------------------------
        self.selfheal_interval = _int(
            self._r("threat.selfheal_interval", 30, in_schema=False), 30,
            minimum=5)
        self.housekeeping_interval = _int(
            self._r("threat.housekeeping_interval", 300, in_schema=False), 300,
            minimum=30)
        self.min_flush_interval = _int(
            self._r("threat.min_flush_interval", 30, in_schema=False), 30,
            minimum=0)
        self.event_flush_interval = _int(
            self._r("threat.event_flush_interval", 60, in_schema=False), 60,
            minimum=1)
        self.event_queue_max = _int(
            self._r("threat.event_queue_max", 1000, in_schema=False), 1000,
            minimum=10)
        self.strict_flag_ttl = _num(
            self._r("threat.strict_flag_ttl", 5, in_schema=False), 5, minimum=0.5)
        self.strict_factor = _num(
            self._r("threat.strict_factor", 0.5, in_schema=False), 0.5,
            minimum=0.05)
        self.max_tracked_ips = _int(
            self._r("threat.max_tracked_ips", 20000, in_schema=False), 20000,
            minimum=100)
        self.behavior_max_ips = _int(
            self._r("threat.behavior_max_ips", 4000, in_schema=False), 4000,
            minimum=100)
        self.behavior_max_uris = _int(
            self._r("threat.behavior_max_uris", 8, in_schema=False), 8,
            minimum=1)
        self.track_idle_ttl = _int(
            self._r("threat.track_idle_ttl", 3600, in_schema=False), 3600,
            minimum=60)

        # -- enforcement (names are configuration, never hardcoded) ------
        self.ipset_set = str(self._r("threat.ipset_set", "vigil_threat",
                                     in_schema=False))
        self.iptables_chain = str(self._r("threat.iptables_chain", "INPUT",
                                          in_schema=False))
        self.ipset_program = str(self._r("threat.ipset_program", "ipset",
                                         in_schema=False))
        self.iptables_program = str(self._r("threat.iptables_program", "iptables",
                                            in_schema=False))

        # -- distributed brute force -------------------------------------
        self.distributed_window = _int(
            self._rf(["threat.distributed.window"], 300), 300, minimum=10)
        self.distributed_min_ips = _int(
            self._rf(["threat.distributed.min_ips"], 15), 15, minimum=2)
        self.distributed_min_fails = _int(
            self._rf(["threat.distributed.min_fails"], 20), 20, minimum=2)

        # -- log sources -------------------------------------------------
        self.log_sources = self._resolve_log_sources()

    # -- read helpers ------------------------------------------------------
    def _r(self, dotted: str, default, in_schema: bool = True):
        value = self.cfg.get(dotted, _MISSING)
        self.keys_read.append({
            "key": dotted,
            "in_schema": in_schema,
            # "merged-config" only means the key exists in the loaded document;
            # DEFAULTS always supplies schema keys, so it does not prove the
            # operator set it.  "fallback-default" means the key was absent.
            "source": "merged-config" if value is not _MISSING else "fallback-default",
        })
        return default if value is _MISSING else value

    def _rf(self, keys, default, in_schema: bool = False):
        """First present of *keys* wins; records which one was used."""
        for key in keys:
            value = self.cfg.get(key, _MISSING)
            if value is not _MISSING:
                self.keys_read.append({"key": key, "in_schema": in_schema,
                                       "source": "merged-config"})
                return value
        self.keys_read.append({"key": " | ".join(keys), "in_schema": in_schema,
                               "source": "fallback-default"})
        return default

    def _resolve_log_sources(self) -> dict:
        access = [str(p) for p in (self._r("threat.log_sources.nginx_access", []) or [])]
        auth = [str(p) for p in (self._r("threat.log_sources.auth", []) or [])]
        panel = [str(p) for p in (self._r("threat.log_sources.panel", []) or [])]
        decoy = [str(p) for p in (self._r("threat.log_sources.decoy", []) or [])]

        auto = None
        if not access or not auth or not panel:
            try:
                auto = detect.log_sources() or {}
            except Exception:                          # noqa: BLE001
                auto = None
        if not decoy:
            # The decoy log is written by a snippet this program installs, so
            # its path is known rather than discovered. Adding it here means
            # installing decoys is enough to start catching them -- there is
            # no second step to forget.
            try:
                from . import decoy as decoy_mod
                candidate = str(decoy_mod.log_path())
                if os.path.exists(candidate):
                    decoy = [candidate]
            except (ImportError, OSError):
                decoy = []
        if auto:
            if not access:
                access = [str(p) for p in (auto.get("nginx_access") or [])]
            if not panel:
                panel = [str(p) for p in (auto.get("panel") or [])]
            if not auth:
                candidates = [str(p) for p in (auto.get("auth") or [])]
                auth = [p for p in candidates
                        if os.path.basename(p).lower() not in _BINARY_AUTH_LOGS]
                dropped = [p for p in candidates if p not in auth]
                for p in dropped:
                    # wtmp/btmp are binary; tailing them yields garbage.  This
                    # is why detect.log_sources() is filtered rather than used
                    # verbatim.
                    self.keys_read.append({"key": "detect.log_sources().auth",
                                           "in_schema": False,
                                           "source": "dropped-binary:%s" % p})
        return {
            "nginx_access": _dedupe(access),
            "auth": _dedupe(auth),
            "panel": _dedupe(panel),
            "decoy": _dedupe(decoy),
        }


def _dedupe(items) -> list:
    seen, out = set(), []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


# --------------------------------------------------------------------------
# Whitelist (defect: CIDR/IPv6 handling and the "allow what we cannot parse"
# fallback)
# --------------------------------------------------------------------------
class Whitelist:
    """Addresses that must never be banned and never rate-limited.

    IPv4 and IPv6, plain addresses and CIDRs, loopback always exempt, and an
    option to trust every address configured on a local interface.  An address
    that cannot be parsed is **not** trusted: the original returned ``True``
    ("allowed") in that case, which turned a parsing quirk into a whitelist
    bypass.
    """

    def __init__(self, entries, auto_local: bool = True, log=None,
                 max_cache: int = 4096):
        self.log = log
        self.auto_local = auto_local
        self._max_cache = max_cache
        self._lock = threading.Lock()
        self._v4 = []
        self._v6 = []
        self._ips = set()
        self.bad = []
        self._cache = {}
        self.reload(entries)

    def reload(self, entries=None) -> None:
        entries = list(entries or [])
        v4, v6, ips, bad = [], [], set(), []
        for item in entries:
            text = str(item).strip()
            if not text:
                continue
            try:
                if "/" in text:
                    net = ipaddress.ip_network(text, strict=False)
                    (v4 if net.version == 4 else v6).append(net)
                else:
                    ips.add(str(ipaddress.ip_address(text)))
            except ValueError:
                bad.append(text)
        if self.auto_local:
            for addr in local_addresses():
                try:
                    ips.add(str(ipaddress.ip_address(addr)))
                except ValueError:
                    continue
        with self._lock:
            self._v4, self._v6, self._ips, self.bad = v4, v6, ips, bad
            self._cache.clear()
        for item in bad:
            if self.log:
                self.log.warn("白名单条目非法，已忽略：%s", item)

    def allowed(self, ip: str) -> bool:
        ip = (ip or "").strip()
        if not ip:
            return False
        with self._lock:
            cached = self._cache.get(ip)
        if cached is not None:
            return cached
        result = self._compute(ip)
        with self._lock:
            if len(self._cache) >= self._max_cache:
                for key in list(self._cache)[: self._max_cache // 2]:
                    self._cache.pop(key, None)
            self._cache[ip] = result
        return result

    def _compute(self, ip: str) -> bool:
        if ip in self._ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            if self.log:
                self.log.warn("无法解析的地址，按不可信处理（fail closed）：%s",
                              oneline(ip, 64))
            return False
        if addr.is_loopback:
            return True
        nets = self._v4 if addr.version == 4 else self._v6
        for net in nets:
            if addr in net:
                return True
        return False

    def v4_sources(self) -> list:
        with self._lock:
            return [str(n) for n in self._v4]

    def v6_sources(self) -> list:
        with self._lock:
            return [str(n) for n in self._v6]

    def entries(self) -> list:
        with self._lock:
            return ([str(n) for n in self._v4] + [str(n) for n in self._v6]
                    + sorted(self._ips))


def local_addresses() -> set:
    """Addresses configured on local interfaces, plus loopback."""
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


# --------------------------------------------------------------------------
# Bounded in-memory maps (defect: the original leaked per-IP state forever)
# --------------------------------------------------------------------------
class Windows:
    """Sliding-window counters keyed by ``(ip, detector)`` with time expiry."""

    def __init__(self, max_ips: int = 20000, idle_ttl: int = 3600, log=None):
        self._lock = threading.Lock()
        self._d = {}                      # ip -> {"w": {key: deque}, "seen": ts}
        self._max_ips = max_ips
        self._idle_ttl = idle_ttl
        self._log = log
        self._ops = 0

    def bump(self, ip: str, key: str, window: float, limit: int):
        now = time.time()
        with self._lock:
            entry = self._d.get(ip)
            if entry is None:
                if len(self._d) >= self._max_ips:
                    self._evict(now, force=True)
                entry = {"w": {}, "seen": now}
                self._d[ip] = entry
            entry["seen"] = now
            dq = entry["w"].get(key)
            if dq is None:
                dq = entry["w"][key] = deque()
            dq.append(now)
            cutoff = now - window
            while dq and dq[0] < cutoff:
                dq.popleft()
            n = len(dq)
            self._ops += 1
            if self._ops % 512 == 0:
                self._evict(now)
            return n >= limit, n

    def count(self, ip: str, key: str, window: float) -> int:
        now = time.time()
        with self._lock:
            entry = self._d.get(ip)
            if not entry:
                return 0
            dq = entry["w"].get(key)
            if not dq:
                return 0
            cutoff = now - window
            while dq and dq[0] < cutoff:
                dq.popleft()
            return len(dq)

    def forget(self, ip: str) -> None:
        with self._lock:
            self._d.pop(ip, None)

    def _evict(self, now: float, force: bool = False) -> None:
        for ip in [k for k, v in self._d.items()
                   if now - v["seen"] > self._idle_ttl]:
            self._d.pop(ip, None)
        if force and len(self._d) >= self._max_ips:
            victims = sorted(self._d, key=lambda k: self._d[k]["seen"])
            for ip in victims[: max(1, self._max_ips // 10)]:
                self._d.pop(ip, None)

    def prune(self) -> int:
        with self._lock:
            self._evict(time.time())
            return len(self._d)

    def size(self) -> int:
        with self._lock:
            return len(self._d)


class BehaviorStore:
    """A bounded sample of what each source IP actually did."""

    def __init__(self, max_ips: int = 4000, max_uris: int = 8,
                 idle_ttl: int = 3600):
        self._lock = threading.Lock()
        self._d = {}
        self._max_ips = max_ips
        self._max_uris = max_uris
        self._idle_ttl = idle_ttl

    def record(self, ip: str, uri: str = "", status=None,
               kind: str = "http") -> None:
        if not ip:
            return
        now = time.time()
        with self._lock:
            entry = self._d.get(ip)
            if entry is None:
                if len(self._d) >= self._max_ips:
                    self._evict(now, force=True)
                entry = {"first": now, "last": now, "count": 0, "uris": [],
                         "classes": {}, "kinds": {}}
                self._d[ip] = entry
            entry["last"] = now
            entry["count"] += 1
            entry["kinds"][kind] = entry["kinds"].get(kind, 0) + 1
            if status:
                try:
                    cls = "%dxx" % (int(status) // 100)
                    entry["classes"][cls] = entry["classes"].get(cls, 0) + 1
                except (TypeError, ValueError):
                    pass
            if uri and uri not in entry["uris"]:
                entry["uris"].append(uri)
                while len(entry["uris"]) > self._max_uris:
                    entry["uris"].pop(0)

    def snapshot(self, ip: str):
        with self._lock:
            entry = self._d.get(ip)
            if not entry:
                return None
            return {"first": entry["first"], "last": entry["last"],
                    "count": entry["count"], "uris": list(entry["uris"]),
                    "classes": dict(entry["classes"]),
                    "kinds": dict(entry["kinds"])}

    def _evict(self, now: float, force: bool = False) -> None:
        for ip in [k for k, v in self._d.items()
                   if now - v["last"] > self._idle_ttl]:
            self._d.pop(ip, None)
        if force and len(self._d) >= self._max_ips:
            victims = sorted(self._d, key=lambda k: self._d[k]["last"])
            for ip in victims[: max(1, self._max_ips // 10)]:
                self._d.pop(ip, None)

    def prune(self) -> int:
        with self._lock:
            self._evict(time.time())
            return len(self._d)

    def size(self) -> int:
        with self._lock:
            return len(self._d)


class CooldownMap:
    """Per-key alert cooldowns with expiry and a hard size cap."""

    def __init__(self, ttl: float = 600, max_keys: int = 5000):
        self._lock = threading.Lock()
        self._d = {}
        self._ttl = max(0.0, float(ttl))
        self._max = max_keys
        self._ops = 0

    def allow(self, key: str) -> bool:
        """True when *key* may fire; records the attempt when it does."""
        now = time.time()
        if self._ttl <= 0:
            return True
        with self._lock:
            last = self._d.get(key)
            if last is not None and now - last < self._ttl:
                return False
            self._d[key] = now
            self._ops += 1
            if self._ops % 256 == 0 or len(self._d) > self._max:
                self._evict(now)
            return True

    def _evict(self, now: float) -> None:
        for k in [k for k, t in self._d.items() if now - t > self._ttl]:
            self._d.pop(k, None)
        if len(self._d) > self._max:
            for k in sorted(self._d, key=lambda x: self._d[x])[: self._max // 2]:
                self._d.pop(k, None)

    def prune(self) -> int:
        with self._lock:
            self._evict(time.time())
            return len(self._d)


class DistributedTracker:
    """Global timeline of authentication failures across source IPs."""

    def __init__(self, window: int = 300, maxlen: int = 20000):
        self._lock = threading.Lock()
        self._window = max(1, int(window))
        self._fails = deque(maxlen=maxlen)

    def note(self, ip: str):
        now = time.time()
        with self._lock:
            self._fails.append((now, ip))
            cutoff = now - self._window
            while self._fails and self._fails[0][0] < cutoff:
                self._fails.popleft()
            ips = {entry[1] for entry in self._fails}
            return len(ips), len(self._fails)

    def prune(self) -> int:
        now = time.time()
        with self._lock:
            cutoff = now - self._window
            while self._fails and self._fails[0][0] < cutoff:
                self._fails.popleft()
            return len(self._fails)


class NetblockTracker:
    """Counts *distinct* offending addresses inside the same network.

    Escalating from an address to its network is the most dangerous thing
    this program can decide to do, because the unit of punishment stops
    matching the unit of guilt: one host scans you, and two hundred
    bystanders on the same /24 lose service. So the trigger is deliberately
    narrow, and it is a count of *distinct addresses*, not of events.

    A single attacker rotating through one subnet cannot reach the
    threshold by trying harder; it takes several independent hosts in the
    same network behaving the same way inside the window, which is what a
    coordinated sweep actually looks like.
    """

    #: Only these widths are ever produced: /24 for IPv4, /48 for IPv6.
    #: Anything wider trades a small amount of protection for a large amount
    #: of collateral damage -- banning a /16 can take out an ISP.
    V4_PREFIX = 24
    V6_PREFIX = 48

    def __init__(self, window: int = 1800, maxnets: int = 512, log=None):
        self._window = max(60, int(window))
        self._maxnets = max(8, int(maxnets))
        self._log = log
        self._seen = {}
        self._lock = threading.Lock()

    @classmethod
    def network_of(cls, ip: str) -> str:
        """The network an address belongs to, at the fixed width. "" if none."""
        try:
            addr = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return ""
        if addr.version == 4:
            net = ipaddress.ip_network("%s/%d" % (addr, cls.V4_PREFIX),
                                       strict=False)
        else:
            net = ipaddress.ip_network("%s/%d" % (addr, cls.V6_PREFIX),
                                       strict=False)
        return str(net)

    def note(self, ip: str, now: float = None):
        """Record an offending address. Returns ``(network, count)``.

        The count is of distinct addresses still inside the window.
        """
        now = now if now is not None else time.time()
        net = self.network_of(ip)
        if not net:
            return "", 0
        with self._lock:
            seen = self._seen.setdefault(net, {})
            seen[str(ip)] = now
            cutoff = now - self._window
            for key in [k for k, at in seen.items() if at < cutoff]:
                seen.pop(key, None)
            if not seen:
                self._seen.pop(net, None)
                return net, 0
            if len(self._seen) > self._maxnets:
                # Keep the table bounded: drop the oldest networks.
                for key in sorted(self._seen,
                                  key=lambda n: max(self._seen[n].values())
                                  )[:_maxnets // 4]:
                    self._seen.pop(key, None)
            return net, len(seen)

    def members(self, net: str) -> list:
        with self._lock:
            return sorted((self._seen.get(net) or {}).keys())

    def forget(self, net: str) -> None:
        with self._lock:
            self._seen.pop(net, None)

    def prune(self, now: float = None) -> int:
        now = now if now is not None else time.time()
        cutoff = now - self._window
        removed = 0
        with self._lock:
            for net in list(self._seen):
                seen = self._seen[net]
                for key in [k for k, at in seen.items() if at < cutoff]:
                    seen.pop(key, None)
                if not seen:
                    self._seen.pop(net, None)
                    removed += 1
        return removed


class BanBreaker:
    """Circuit breaker: at most *limit* bans per rolling *window*."""

    def __init__(self, limit: int = 60, window: int = 3600):
        self._lock = threading.Lock()
        self._limit = max(1, int(limit))
        self._window = max(1, int(window))
        self._times = deque()

    def record(self) -> None:
        with self._lock:
            self._times.append(time.time())

    def recent(self) -> int:
        now = time.time()
        with self._lock:
            cutoff = now - self._window
            while self._times and self._times[0] < cutoff:
                self._times.popleft()
            return len(self._times)

    def tripped(self):
        count = self.recent()
        return count >= self._limit, count

    def limit(self) -> int:
        return self._limit

    def window(self) -> int:
        return self._window


#: Where each followed log was left off, so a restart resumes instead of
#: jumping to the end. One small file, written at most once per interval.
LOG_OFFSETS = paths.STATE_STATE / "log-offsets.json"

#: Unban requests, handed from the CLI to the running daemon.
#:
#: The daemon owns the threat state and rewrites it from memory (on every
#: housekeeping tick, and at shutdown). So a `vigil threat unban` that edited
#: the state file directly would be correct only until the daemon next saved
#: -- and the ban would come back. That is exactly what was observed: an
#: address disappeared from the ipset, then reappeared a restart later.
#: Requests go through a file the daemon drains, so there is one writer.
#:
#: It lives in the *state* directory, not ``/run``. The first attempt used
#: ``/run/vigil``, which the unit declares as its systemd RuntimeDirectory:
#: restarting the service recreates that directory, so the pending request
#: was destroyed before the daemon could read it and the bans came straight
#: back. A file whose whole purpose is to survive a restart cannot live
#: somewhere a restart wipes.
UNBAN_REQUESTS = paths.STATE_STATE / "unban-requests.jsonl"

#: How often the daemon drains CLI unban requests. Deliberately far shorter
#: than the housekeeping cycle: an unban is an operator instruction, and one
#: that visibly works and then silently comes back is worse than one that
#: fails outright. Measured during an attack drill, where twenty lifted bans
#: all returned because draining waited on a 300 s timer.
UNBAN_POLL_SECONDS = 3


class LogFollower:
    """Follow a log file from a remembered byte offset.

    The obvious implementation -- ``tail -F -n 0`` -- starts at the end of
    the file, which means every line written while the daemon was down, or
    in the gap between one ``tail`` dying and the next starting, is dropped
    without a trace. On 2026-09-27 that was observed directly: a decoy hit
    landed in the window of a `vigil update` restart, the start-up banner
    reported the source as watched, and nothing happened. For a daemon whose
    entire job is to notice things, silently skipping the lines that arrive
    during its own restart is the worst possible blind spot, because the
    output still claims coverage.

    So position is persisted as ``(inode, offset)`` per file and restored on
    start-up:

    * same inode, offset within the file -> resume exactly there;
    * different inode -> the file was rotated, start the new one at the
      beginning (its contents are new by definition);
    * offset past the end -> the file was truncated, start at the beginning.

    A first sighting of a file starts at the end, which is deliberate: the
    alternative is replaying months of history through the detectors on the
    first run, and re-banning for attacks that are long over.
    """

    def __init__(self, path: str, store: dict, log=None, save=None):
        self.path = str(path)
        self.store = store
        self.log = log
        self._save = save
        self._fh = None
        self._ino = None
        self._buf = b""
        self._dirty = False

    # -- position --------------------------------------------------------
    def _remembered(self):
        rec = self.store.get(self.path) or {}
        try:
            return int(rec.get("inode", 0) or 0), int(rec.get("offset", 0) or 0)
        except (TypeError, ValueError):
            return 0, 0

    def _remember(self, ino: int, offset: int) -> None:
        self.store[self.path] = {"inode": int(ino), "offset": int(offset)}
        self._dirty = True

    def flush(self) -> None:
        if self._dirty and self._save:
            self._save(self.store)
            self._dirty = False

    # -- following -------------------------------------------------------
    def _open(self) -> bool:
        try:
            st = os.stat(self.path)
        except OSError:
            return False
        try:
            if self._fh is not None:
                self._fh.close()
        except OSError:
            pass
        # Binary, deliberately. A text-mode file object's `tell()` is an
        # opaque cookie, not promised to be a byte offset, and seeking to a
        # cookie from a *previous process* is not guaranteed to work. Since
        # the whole point here is resuming across restarts, offsets have to
        # be real byte positions -- and some of the sources this follows
        # (`wtmp`, `btmp`) are not text at all.
        try:
            fh = open(self.path, "rb")
        except OSError:
            return False

        prev_ino, prev_off = self._remembered()
        if st.st_ino != prev_ino:
            # Rotated, or first sighting. First sighting starts at the end.
            start = 0 if prev_ino else st.st_size
        elif prev_off > st.st_size:
            start = 0                      # truncated in place
        else:
            start = prev_off
        try:
            fh.seek(start)
        except OSError:
            start = 0
        self._fh = fh
        self._ino = st.st_ino
        self._remember(st.st_ino, start)
        if start < st.st_size:
            self.log and self.log.info(
                "续读 %s：从第 %d 字节继续（不跳过停机期间的日志）"
                % (self.path, start))
        return True

    def poll(self):
        """Yield complete new lines. Never raises."""
        if self._fh is None and not self._open():
            return
        try:
            chunk = self._fh.read()
        except (OSError, ValueError):
            self._close()
            return
        if not chunk:
            self._check_rotation()
            return
        self._buf += chunk
        # Split on bytes and decode each *complete* line: decoding the raw
        # chunk first would corrupt a multi-byte character straddling the
        # boundary, and the corruption would appear as text in an alert.
        *lines, self._buf = self._buf.split(b"\n")
        for raw in lines:
            yield raw.decode("utf-8", "replace")

    def _check_rotation(self) -> None:
        try:
            st = os.stat(self.path)
        except OSError:
            return
        if self._ino is not None and st.st_ino != self._ino:
            self._close()

    def tell(self) -> None:
        """Record how far we have read. Cheap enough to call per line."""
        if self._fh is None:
            return
        try:
            # Byte arithmetic is exact now that the buffer holds bytes.
            self._remember(self._ino or 0, self._fh.tell() - len(self._buf))
        except (OSError, ValueError):
            pass

    def close(self) -> None:
        """Release the handle. Safe to call more than once."""
        self._close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.flush()
        self._close()
        return False

    def _close(self) -> None:
        try:
            if self._fh is not None:
                self._fh.close()
        except OSError:
            pass
        self._fh = None
        self._ino = None
        self._buf = b""


#: Where the attack-driven posture records itself. Other components may read
#: this file; its mtime *is* the deadline, so expiry needs no daemon, no
#: timer and no cleanup pass -- one stat answers "are we heightened, and
#: until when".
POSTURE_FLAG = paths.RUN / "posture.active"


class AttackPosture:
    """Heightened defence because an attack is in progress.

    The load shedder already answers "is this machine overwhelmed", and
    halves thresholds when it is. That is a different question from "is this
    machine under attack", and conflating them leaves a gap that matters: a
    slow, patient campaign against a completely idle machine never moves the
    load average, so nothing tightens and every attempt gets the relaxed
    threshold.

    So this triggers on *attack* signals -- a burst of bans, a distributed
    sweep, or a single decoy hit -- and stays up for a hold period after the
    last one. What it changes while up is bounded and reversible: thresholds
    tighten, which shortens the evidence needed for the next ban. It never
    escalates a ban duration by itself and never touches the whitelist.

    Expiry is stored as the flag file's mtime rather than as a deadline
    someone has to enforce. A file whose mtime is in the future *is* an
    active posture; when the wall clock passes it, the posture is over. No
    cleanup runs, so nothing can fail to run.
    """

    def __init__(self, flag=None, window: int = 300, trigger: int = 5,
                 hold: int = 900, log=None):
        self._flag = str(flag if flag is not None else POSTURE_FLAG)
        self._window = max(10, int(window))
        self._trigger = max(1, int(trigger))
        self._hold = max(30, int(hold))
        self._log = log
        self._events = deque()
        self._lock = threading.Lock()
        self._was = False
        self._at = 0.0

    # -- triggers --------------------------------------------------------
    def note(self, weight: int = 1) -> bool:
        """Record an attack signal. Returns True if this raised the posture."""
        now = time.time()
        with self._lock:
            self._events.append((now, weight))
            cutoff = now - self._window
            while self._events and self._events[0][0] < cutoff:
                self._events.popleft()
            total = sum(w for _t, w in self._events)
            if total < self._trigger:
                return False
            self._write(now + self._hold)
            self._events.clear()
            return True

    def _write(self, until: float) -> None:
        try:
            Path(self._flag).parent.mkdir(parents=True, exist_ok=True)
            Path(self._flag).touch()
            os.utime(self._flag, (until, until))
        except OSError:
            pass

    # -- state -----------------------------------------------------------
    def active(self) -> bool:
        try:
            return os.path.getmtime(self._flag) > time.time()
        except OSError:
            return False

    def until(self) -> float:
        try:
            return os.path.getmtime(self._flag)
        except OSError:
            return 0.0

    def clear(self) -> None:
        try:
            os.unlink(self._flag)
        except OSError:
            pass

    def seconds_left(self) -> int:
        return max(0, int(self.until() - time.time()))

    def transition(self) -> str:
        """``"on"`` / ``"off"`` when the state changed, else ``""``.

        Polled rather than event-driven because two things change the state:
        this class raising it, and the clock passing the deadline. Only the
        second one happens while nobody is calling in, so a transition can
        only be noticed by looking.
        """
        now = time.time()
        if now - self._at < 1.0:
            return ""
        self._at = now
        active = self.active()
        if active == self._was:
            return ""
        self._was = active
        if self._log:
            if active:
                self._log.warn("进入高压防护姿态：阈值收紧，持续 %d 秒"
                               % self.seconds_left())
            else:
                self._log.info("高压防护姿态结束：阈值恢复")
        return "on" if active else "off"


class StrictMode:
    """Cached view of the load shedder's runtime flag (defect: stat per line)."""

    def __init__(self, flag, ttl: float = 5.0, log=None):
        self._flag = str(flag)
        self._ttl = max(0.5, float(ttl))
        self._log = log
        self._value = False
        self._at = 0.0
        self._lock = threading.Lock()

    def active(self) -> bool:
        now = time.time()
        with self._lock:
            if now - self._at < self._ttl:
                return self._value
            try:
                value = os.path.exists(self._flag)
            except OSError:
                value = False
            if value != self._value and self._log:
                self._log.warn(_t("strict_on") if value else _t("strict_off"))
            self._value = value
            self._at = now
            return value


def ban_history(ip: str) -> str:
    """One line of what we already know about an address.

    Read from the persisted ledger rather than from a live daemon object, so
    the periodic checks and the alert renderer can both call it without
    holding a reference to the running detector. "Have we seen this before"
    is the first question anyone asks about an address in an alert, and the
    answer was previously only visible by running a separate command.
    """
    from ..core import paths
    ip = (ip or "").strip()
    if not ip:
        return ""
    data = read_json(paths.THREAT_STATE, None)
    if not isinstance(data, dict):
        return ""
    now = time.time()
    bits = []
    entry = (data.get("offenses") or {}).get(ip)
    if isinstance(entry, dict):
        count = int(entry.get("count", 0) or 0)
        last = float(entry.get("last", 0) or 0)
        if count:
            when = ""
            if last:
                try:
                    when = "，最近 %s" % datetime.fromtimestamp(last).strftime(
                        "%m-%d %H:%M")
                except (ValueError, OSError):
                    when = ""
            bits.append("违规 %d 次%s" % (count, when))
    banned = (data.get("bans") or {}).get(ip)
    if isinstance(banned, dict):
        until = float(banned.get("until", 0) or 0)
        if until > now:
            bits.append("**当前封禁中**（剩余 %s）"
                        % human_seconds(int(until - now)))
        else:
            bits.append("曾被封禁（已于 %s 到期）"
                        % datetime.fromtimestamp(until).strftime("%m-%d %H:%M"))
    return "；".join(bits)


class ThreatState:
    """Persistent offences, bans and counters.

    Offence counts decay after ``offense_decay`` seconds so escalation is
    "recent behaviour", not "forever"; entries are capped so a long-lived
    daemon cannot grow without bound.
    """

    def __init__(self, path, decay: int, max_ips: int, log=None,
                 persist: bool = True):
        self.path = Path(path)
        self.decay = max(60, int(decay))
        self.max_ips = max(100, int(max_ips))
        self.log = log
        self.persist = persist
        self.lock = threading.RLock()
        self.offenses = {}
        self.bans = {}
        self.stats = {
            "started": time.time(), "events": 0, "bans_total": 0,
            "bans_failed": 0, "bans_current": 0, "alerts": 0, "last_ban": None,
            "distributed_events": 0, "breaker_tripped": 0, "decoy_hits": 0,
            "posture_raised": 0, "netblock_bans": 0, "netblock_failed": 0,
            "offwhitelist_logins": 0,
        }
        # Read always; write only when allowed. Those are two different
        # questions, and conflating them made `vigil status` print
        # "当前封禁 0 / 累计封禁 0" on a host holding two live bans: the
        # read-only view builds a dry-run daemon, and `persist=False` skipped
        # the load along with the save. Loading is read-only -- a dry run has
        # no reason to hide the real state from itself.
        self.load()

    # -- persistence -------------------------------------------------------
    def load(self) -> None:
        data = read_json(self.path, None)
        if not isinstance(data, dict):
            return
        now = time.time()
        with self.lock:
            self.offenses = {k: v for k, v in (data.get("offenses") or {}).items()
                             if isinstance(v, dict)
                             and now - v.get("last", 0) < self.decay}
            self.bans = {k: v for k, v in (data.get("bans") or {}).items()
                         if isinstance(v, dict) and v.get("until", 0) > now}
            stored = data.get("stats") or {}
            if isinstance(stored, dict):
                for key, value in stored.items():
                    self.stats[key] = value
                self.stats["started"] = time.time()
            if self.log:
                self.log.info("已载入状态：%d 条违规记录，%d 个未到期封禁",
                              len(self.offenses), len(self.bans))

    def save(self) -> bool:
        if not self.persist:
            return True
        with self.lock:
            snapshot = {
                "offenses": dict(self.offenses),
                "bans": dict(self.bans),
                "stats": dict(self.stats),
                "saved": time.time(),
            }
        return write_json(self.path, snapshot, mode=0o600)

    # -- mutation ----------------------------------------------------------
    def note_offense(self, ip: str, now=None) -> int:
        now = now or time.time()
        with self.lock:
            entry = self.offenses.get(ip)
            if not entry or now - entry.get("last", 0) > self.decay:
                entry = {"count": 0, "last": now}
            entry["count"] += 1
            entry["last"] = now
            self.offenses[ip] = entry
            return entry["count"]

    def offense_count(self, ip: str):
        with self.lock:
            entry = self.offenses.get(ip)
            return int(entry.get("count", 0)) if entry else 0

    def note_ban(self, ip: str, until: float, reason: str, count: int,
                 detector: str) -> None:
        with self.lock:
            self.bans[ip] = {"until": until, "reason": reason, "count": count,
                             "detector": detector}
            self.stats["bans_total"] = int(self.stats.get("bans_total", 0)) + 1
            self.stats["last_ban"] = {"ip": ip, "reason": reason,
                                      "until": until, "at": time.time(),
                                      "seconds": int(until - time.time()),
                                      "offense": count, "detector": detector}

    def drop_ban(self, ip: str) -> None:
        with self.lock:
            self.bans.pop(ip, None)

    def prune(self) -> dict:
        now = time.time()
        with self.lock:
            self.offenses = {k: v for k, v in self.offenses.items()
                             if now - v.get("last", 0) <= self.decay}
            self.bans = {k: v for k, v in self.bans.items()
                         if v.get("until", 0) > now}
            if len(self.offenses) > self.max_ips:
                victims = sorted(self.offenses,
                                 key=lambda k: self.offenses[k].get("last", 0))
                for ip in victims[: len(self.offenses) - self.max_ips]:
                    self.offenses.pop(ip, None)
            if len(self.bans) > self.max_ips:
                victims = sorted(self.bans, key=lambda k: self.bans[k].get("until", 0))
                for ip in victims[: len(self.bans) - self.max_ips]:
                    self.bans.pop(ip, None)
            return {"offenses": len(self.offenses), "bans": len(self.bans)}

    def pending(self):
        now = time.time()
        with self.lock:
            return [(ip, int(v["until"] - now)) for ip, v in self.bans.items()
                    if v.get("until", 0) > now]


# --------------------------------------------------------------------------
# Enforcement: ipset + iptables
# --------------------------------------------------------------------------
class Enforcer:
    """Applies and verifies the ipset/iptables ban mechanism.

    The set name and chain come from configuration.  Every call reports whether
    it actually succeeded, because a ban alert that claims success while
    ``ipset add`` failed is worse than no alert at all.
    """

    def __init__(self, set_name: str, chain: str, ipset: str = "ipset",
                 iptables: str = "iptables", maxelem: int = 20000,
                 dry_run: bool = False, log=None, net_set_name: str = ""):
        self.set_name = set_name
        # A separate `hash:net` set for network ranges. It cannot share the
        # per-address set: that one is `hash:ip`, and adding a /24 to it does
        # not store a range -- it silently expands into 256 host entries.
        # Measured, not assumed: `ipset add vigil_threat 198.18.0.0/24` put
        # 256 individual addresses in the set, which would fill a 20000-entry
        # table after 78 netblocks.
        self.net_set_name = net_set_name or (set_name + "_net")
        self.chain = chain
        self.maxelem = maxelem
        self.dry_run = dry_run
        self.log = log
        self.ipset = shell.which(ipset, "/usr/sbin/ipset", "/sbin/ipset") or ipset
        self.iptables = (shell.which(iptables, "/usr/sbin/iptables",
                                     "/sbin/iptables") or iptables)

    def _plan(self, argv) -> None:
        if self.log:
            self.log.info("[dry-run] %s", shell.quote(argv))

    def _run(self, argv, timeout: float = 15):
        if self.dry_run:
            self._plan(argv)
            return True, "", ""
        return shell.run(argv, timeout=timeout)

    # -- set ---------------------------------------------------------------
    def set_exists(self) -> bool:
        names = shell.out([self.ipset, "list", "-n"], timeout=10)
        return self.set_name in names.split()

    def ensure(self) -> bool:
        """Create the set and re-assert the INPUT match rule at position 1."""
        if self.dry_run:
            self._plan([self.ipset, "create", self.set_name, "hash:ip",
                        "timeout", "0", "maxelem", str(self.maxelem)])
            self._plan([self.iptables, "-I", self.chain, "1", "-m", "set",
                        "--match-set", self.set_name, "src", "-j", "DROP"])
            return True
        created = False
        if not self.set_exists():
            ok, _out, err = self._run([
                self.ipset, "create", self.set_name, "hash:ip", "timeout", "0",
                "maxelem", str(self.maxelem)])
            created = ok
            if ok and self.log:
                self.log.info(_t("set_created", self.set_name))
            elif not ok and self.log:
                self.log.error("创建 ipset 集合 %s 失败：%s", self.set_name,
                              oneline(err, 160))
        self.ensure_net_set()
        self.assert_priority()
        return created or self.set_exists()

    # -- the network-range set --------------------------------------------
    def net_set_exists(self) -> bool:
        ok, out, _err = self._run([self.ipset, "list", "-n"], timeout=10)
        if not ok:
            return False
        return self.net_set_name in out.split()

    def ensure_net_set(self) -> bool:
        """Create the hash:net set and its rule, if the kernel allows it.

        Best-effort: an old ipset build or a locked-down container may refuse
        either. Netblock escalation is an enhancement, and losing it must
        never take down the per-address enforcement that is already working.
        """
        if self.dry_run:
            self._plan([self.ipset, "create", self.net_set_name, "hash:net",
                        "timeout", "0", "maxelem", "512"])
            self._plan([self.iptables, "-I", self.chain, "1", "-m", "set",
                        "--match-set", self.net_set_name, "src", "-j", "DROP"])
            return True
        try:
            if not self.net_set_exists():
                ok, _out, err = self._run([
                    self.ipset, "create", self.net_set_name, "hash:net",
                    "timeout", "0", "maxelem", "512"])
                if not ok and self.log:
                    self.log.warn("创建网段集合 %s 失败（网段升级将不可用）：%s",
                                  self.net_set_name, oneline(err, 140))
        except OSError:
            return False
        # The rule has to exist too, or the set is decorative.
        ok, out, _err = self._run([self.iptables, "-S", self.chain])
        if ok and ("--match-set %s src" % self.net_set_name) not in out:
            self._run([self.iptables, "-I", self.chain, "1", "-m", "set",
                       "--match-set", self.net_set_name, "src", "-j", "DROP"])
        return self.net_set_exists()

    def add_net(self, cidr: str, seconds: int):
        """Add a network range with a timeout. Returns ``(ok, stderr)``."""
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False, "invalid network"
        if not self.ensure_net_set():
            return False, "no hash:net set available"
        ok, _out, err = self._run([
            self.ipset, "add", self.net_set_name, cidr, "timeout",
            str(int(seconds)), "-exist"])
        return ok, (err or "")

    def remove_net(self, cidr: str) -> bool:
        ok, _out, _err = self._run(
            [self.ipset, "del", self.net_set_name, cidr])
        return ok

    def net_members(self) -> dict:
        if self.dry_run:
            return {}
        ok, out, _err = self._run(
            [self.ipset, "list", self.net_set_name], timeout=10)
        result = {}
        if not ok:
            return result
        for line in out.splitlines():
            bits = line.split()
            if not bits:
                continue
            # Validate rather than filter on known headers. `ipset list`
            # ends with "Number of entries: N", whose third token is
            # "entries:" -- a header list that misses one line crashes on
            # `int()`, and the crash is in the path an operator reaches for
            # when they are trying to undo something.
            try:
                ipaddress.ip_network(bits[0], strict=False)
            except ValueError:
                continue
            left = None
            match = re.search(r"timeout (\d+)", line)
            if match:
                left = int(match.group(1))
            result[bits[0]] = left
        return result

    def rule_position(self):
        """Position (1-based) of our match rule in the chain, or None."""
        ok, out, _err = self._run([self.iptables, "-S", self.chain])
        if not ok:
            return None
        for idx, line in enumerate(out.splitlines()):
            if not line.startswith("-A %s" % self.chain):
                continue
            if ("--match-set %s src" % self.set_name) in line and "-j DROP" in line:
                # Index equals rule number: index 0 is the "-P chain POLICY" line.
                return idx
        return None

    def assert_priority(self) -> bool:
        """Verify the DROP rule is first, and move it back if it is not.

        Do not hardcode an INPUT position: compute the intended position (1,
        before every other rule) and compare with reality.  A panel or
        fail2ban reload that inserts rules ahead of ours must not silently
        disable banning.
        """
        position = self.rule_position()
        if position == 1:
            return True
        if position is None:
            ok, _out, err = self._run([
                self.iptables, "-I", self.chain, "1", "-m", "set",
                "--match-set", self.set_name, "src", "-j", "DROP"])
            if ok and self.log:
                self.log.info(_t("rule_inserted", self.chain, self.set_name))
            elif not ok and self.log:
                self.log.error("插入拦截规则失败：%s", oneline(err, 160))
            return ok
        # Present but not first: delete and re-insert at 1.
        spec = self._rule_spec()
        if spec is None:
            return False
        ok, _out, err = self._run([self.iptables, "-D", self.chain] + spec)
        if not ok:
            if self.log:
                self.log.error("删除错位拦截规则失败：%s", oneline(err, 160))
            return False
        ok, _out, err = self._run([
            self.iptables, "-I", self.chain, "1", "-m", "set",
            "--match-set", self.set_name, "src", "-j", "DROP"])
        if ok and self.log:
            self.log.warn(_t("rule_reordered", position))
        return ok

    def _rule_spec(self):
        ok, out, _err = self._run([self.iptables, "-S", self.chain])
        if not ok:
            return None
        prefix = "-A %s " % self.chain
        for line in out.splitlines():
            if line.startswith(prefix) and ("--match-set %s src" % self.set_name) in line:
                return line[len(prefix):].split()
        return None

    # -- membership --------------------------------------------------------
    def add(self, ip: str, seconds: int):
        """Add *ip* with a timeout.  Returns ``(ok, stderr)``."""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return False, "invalid address"
        ok, _out, err = self._run([
            self.ipset, "add", self.set_name, ip, "timeout",
            str(int(seconds)), "-exist"])
        return ok, (err or "")

    def remove(self, ip: str) -> bool:
        ok, _out, _err = self._run([self.ipset, "del", self.set_name, ip])
        return ok

    def members(self) -> dict:
        if self.dry_run:
            return {}
        ok, out, _err = self._run([self.ipset, "list", self.set_name], timeout=10)
        result = {}
        if not ok:
            return result
        for line in out.splitlines():
            parts = line.split()
            if not parts:
                continue
            token = parts[0]
            if not re.match(r"^[0-9a-fA-F:.]+$", token):
                continue
            try:
                ipaddress.ip_address(token)
            except ValueError:
                continue
            timeout = None
            match = re.search(r"timeout (\d+)", line)
            if match:
                timeout = int(match.group(1))
            result[token] = timeout
        return result


# --------------------------------------------------------------------------
# Alert delivery
# --------------------------------------------------------------------------
def _accepted_positional(fn) -> int:
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return 1
    required = 0
    for param in sig.parameters.values():
        if param.kind in (param.POSITIONAL_ONLY, param.POSITIONAL_OR_KEYWORD):
            if param.default is param.empty:
                required += 1
    return required


def _plain_body(alert: Alert) -> str:
    from ..mail.render import render_text
    return render_text(alert, host=_hostname(), lang=language())


def _hostname() -> str:
    try:
        return os.uname().nodename
    except OSError:
        return ""


def send_alert(alert: Alert, cfg=None, log=None) -> bool:
    """Deliver a structured :class:`~vigil.mail.message.Alert`.

    ``vigil/mail/__init__.py`` does not exist yet, so the public entry point
    this module codes against is::

        vigil.mail.send_alert(alert)              # preferred
        vigil.mail.send_alert(subject, body)      # fallback

    The arity is detected with :func:`inspect.signature`, so either shape works
    without the guards knowing which one the mail package ends up providing.
    The alert is *always* written to the threat log first; a mail failure is
    reported, never silently swallowed.

    Returns True when a handler accepted the alert.
    """
    try:
        from .. import mail
    except Exception as exc:                       # noqa: BLE001
        if log:
            log.warn(_t("alert_no_mail", exc))
        return False
    fn = getattr(mail, "send_alert", None)
    if not callable(fn):
        if log:
            log.warn(_t("alert_no_func", alert.title))
        return False
    try:
        if _accepted_positional(fn) >= 2:
            fn(alert.title, _plain_body(alert))
        else:
            fn(alert)
        return True
    except Exception as exc:                       # noqa: BLE001
        if log:
            log.warn(_t("alert_failed", exc))
        return False


# --------------------------------------------------------------------------
# Event reporting (batched, never blocks a tail thread)
# --------------------------------------------------------------------------
_CRIT_KINDS = frozenset({"BREACH", "DIST", "BAN_FAIL"})
_KIND_ORDER = ("BREACH", "BAN_FAIL", "DIST", "NETBLOCK", "POSTURE", "BAN",
               "SSH", "OFFWHITELIST", "BREAKER", "INFO")


class EventReporter:
    """Queue events from detector threads; send them from a dedicated thread.

    The original flushed synchronously with a 40s timeout from inside the
    auth-log reader, stalling that thread during login bursts.  Here
    :meth:`queue` only appends to a deque and optionally wakes the flusher.
    """

    def __init__(self, daemon):
        self.d = daemon
        settings = daemon.settings
        self._q = deque(maxlen=settings.event_queue_max)
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = daemon.stop
        self._flush_interval = settings.event_flush_interval
        self._min_interval = settings.min_flush_interval
        self._last_send = 0.0

    def queue(self, event: dict) -> None:
        with self._lock:
            self._q.append(event)
        if event.get("immediate"):
            self._wake.set()

    def run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(self._flush_interval)
            self._wake.clear()
            if self._stop.is_set():
                break
            try:
                self.flush()
            except Exception as exc:                   # noqa: BLE001
                self.d.log.warn("事件发送线程异常：%s", exc)

    def pending(self) -> int:
        with self._lock:
            return len(self._q)

    def flush(self, force: bool = False) -> bool:
        with self._lock:
            if not self._q:
                return False
            items = list(self._q)
            self._q.clear()
        severity = self._severity(items)
        now = time.time()
        # Respect the provider rate limit for ordinary batches, but never delay
        # a critical alert (the original's inline flush had the same intent).
        if not force and severity != SEV_CRIT and \
                now - self._last_send < self._min_interval:
            with self._lock:
                self._q.extendleft(reversed(items))
            return False
        alert = self.build_alert(items)
        self.d.log.warn(_t("event_flush", alert.title, len(items)))
        self._last_send = now
        with self.d.state.lock:
            self.d.state.stats["alerts"] = int(
                self.d.state.stats.get("alerts", 0)) + 1
        return self.d.deliver(alert)

    # -- rendering ---------------------------------------------------------
    @staticmethod
    def _severity(items) -> str:
        severity = SEV_INFO
        for event in items:
            kind = event.get("kind")
            if kind in _CRIT_KINDS:
                return SEV_CRIT
            if kind == "BAN" and int(event.get("severity", 1)) >= 2:
                return SEV_CRIT
            if kind in ("BAN", "SSH", "OFFWHITELIST", "BREAKER", "POSTURE",
                        "NETBLOCK"):
                severity = SEV_WARN if severity == SEV_INFO else severity
        return severity

    def build_alert(self, items) -> Alert:
        groups = {}
        for event in items:
            groups.setdefault(event.get("kind", "INFO"), []).append(event)
        order = [k for k in _KIND_ORDER if k in groups]
        kind = order[0] if order else "INFO"
        severity = self._severity(items)

        title_map = {
            "BREACH": "疑似爆破成功，请立即核查",
            "BAN_FAIL": "封禁失败（未生效，需人工确认）",
            "DIST": "检测到分布式爆破攻击",
            "BAN": "已自动封禁 %d 个攻击源" % len(groups.get("BAN", [])),
            "SSH": "SSH 登录事件 %d 条" % len(groups.get("SSH", [])),
            "OFFWHITELIST": "非白名单 IP 成功登录",
            "BREAKER": "风控熔断触发",
            "POSTURE": "自动进入高压防护",
            "NETBLOCK": "自动升级为网段封禁",
            "INFO": "自动化处置事件 %d 条" % len(items),
        }
        title = title_map.get(kind, title_map["INFO"])
        summary = self._summary(kind, groups, severity)
        alert = Alert(title=title, severity=severity, kind=KIND_ALERT,
                      summary=summary,
                      dedupe_key="threat|%s" % kind)

        for event in groups.get("NETBLOCK") or []:
            sec = alert.add_section("网段升级封禁")
            sec.add("网段: %s（%s 秒）" % (event.get("net", "?"),
                                          event.get("seconds", "?")))
            ips = event.get("ips") or []
            sec.add("该网段内被单独封禁的来源（%d 个）：" % len(ips))
            for ip in ips:
                sec.add("    %s" % ip)
            sec.add("")
            sec.add("为什么升级：同一网段内多个独立来源在同一窗口内攻击，"
                    "逐地址封禁挡不住协同扫描。")
            sec.add("影响：该网段内的无关地址也会被阻断。共享出口"
                    "（运营商、校园、机房）误伤面较大。")
            sec.add("撤回：vigil threat netblock clear %s" % event.get("net", ""))
        if groups.get("BREACH"):
            section = alert.add_section("安全警告：疑似爆破成功")
            for event in groups["BREACH"]:
                section.add("⚠ %s 在已有 %d 次违规记录的情况下，成功登录为 %s"
                            % (self.d.geo_text(event.get("ip")),
                               int(event.get("count", 0)),
                               event.get("user", "?")))
                section.add("  请立即执行 `who`、`ss -tnp` 核查会话，"
                            "确认是否为未授权访问；必要时修改口令并吊销密钥。")
                section.add("")
        if groups.get("OFFWHITELIST"):
            section = alert.add_section("非白名单登录")
            for event in groups["OFFWHITELIST"]:
                section.add("%s 以 %s 身份成功登录，但不在风控白名单内。"
                            % (self.d.geo_text(event.get("ip")),
                               event.get("user", "?")))
                section.add("  若这是你本人（如手机/宽带换 IP），请把该地址加入 "
                            "`threat.whitelist`；若不是你，请立即核查在线会话。")
                section.add("")
        if groups.get("BAN_FAIL"):
            section = alert.add_section("封禁失败（拦截未生效）")
            for event in groups["BAN_FAIL"]:
                section.add("⚠ %s 应被封禁但 **未生效**，请检查 ipset/iptables 是否可用。"
                            % self.d.geo_text(event.get("ip")))
                section.add("  原因: %s" % event.get("reason", ""))
                section.add("  错误: %s" % oneline(event.get("err", ""), 200))
                section.add("  命令: `%s add %s %s timeout %s -exist` 返回失败"
                            % (self.d.enforcer.ipset, self.d.settings.ipset_set,
                               event.get("ip"), event.get("seconds")))
                section.add("")
        if groups.get("DIST"):
            section = alert.add_section("分布式爆破")
            for event in groups["DIST"]:
                section.add("过去 %s 内有 %d 个不同来源 IP 发起共 %d 次认证失败 —— "
                            "典型僵尸网络协同爆破。"
                            % (human_seconds(event.get("window", 0)),
                               int(event.get("ips", 0)), int(event.get("fails", 0))))
                section.add("  单 IP 阈值无法覆盖此类攻击；建议临时收紧 SSH 策略"
                            "（仅密钥登录 / 限制来源网段）。")
        if groups.get("BAN"):
            section = alert.add_section("自动封禁")
            for event in groups["BAN"]:
                section.extend(self._ban_lines(event))
        if groups.get("SSH"):
            section = alert.add_section("SSH 登录事件")
            for event in groups["SSH"]:
                section.add("%s 以 %s 身份登录成功（方式 %s，白名单：%s）"
                            % (self.d.geo_text(event.get("ip")),
                               event.get("user", "?"),
                               event.get("method", "?"),
                               "是" if event.get("whitelisted") else "**否（请核实）**"))
        if groups.get("BREAKER"):
            section = alert.add_section("风控熔断")
            for event in groups["BREAKER"]:
                section.add("过去 %s 内封禁次数达到 %d（上限 %d），已暂停自动封禁。"
                            % (human_seconds(event.get("window", 0)),
                               int(event.get("count", 0)),
                               int(event.get("limit", 0))))
                section.add("  请人工确认是否遭受伪造源地址攻击，"
                            "避免把正常用户误封。")
        if groups.get("INFO"):
            section = alert.add_section("其它")
            for event in groups["INFO"]:
                section.add(str(event.get("text", "")))

        alert.footer = (
            "查询当前封禁：`%s list %s`\n"
            "手动解封：    `%s del %s <IP>`\n"
            "如需长期放行，请把该地址加入配置的 `threat.whitelist`。"
            % (self.d.enforcer.ipset, self.d.settings.ipset_set,
               self.d.enforcer.ipset, self.d.settings.ipset_set))
        return alert

    def _summary(self, kind, groups, severity) -> str:
        if kind == "BREACH":
            return "有 IP 在留有攻击记录的情况下登录成功，极可能口令已被攻破。"
        if kind == "BAN_FAIL":
            return "检测到攻击但封禁命令未生效，当前处于未防护状态。"
        if kind == "DIST":
            return "多来源协同爆破，单 IP 阈值无法覆盖。"
        if kind == "BAN":
            return "已按分级策略封禁攻击源，详见下方逐条说明。"
        if kind == "BREAKER":
            return "封禁频率异常，已熔断以保护正常用户。"
        if kind == "SSH":
            return "有 SSH 登录成功事件，请核对是否为本人操作。"
        if kind == "NETBLOCK":
            return ("同一网段内多个独立来源同时攻击，已按网段封禁。"
                    "这会影响该网段内与你无关的地址 —— 若确认是共享出口"
                    "（运营商/校园/机房），请用 `vigil threat netblock clear` 撤回。")
        if kind == "POSTURE":
            return ("攻击信号达到阈值，本机已自动收紧封禁阈值；"
                    "平静一段时间后会自动恢复。")
        return "自动化处置事件汇总。"

    def _ban_lines(self, event) -> list:
        d = self.d
        ip = event.get("ip", "")
        enforced = bool(event.get("enforced"))
        lines = ["● %s" % d.geo_text(ip)]
        # Full dossier on first mention of an address, so the reader does not
        # have to go and look it up. `behavior_lines` below covers what it
        # did on this host; this covers who it is.
        try:
            for extra in util.ip_dossier(d.cfg, ip):
                if not extra.startswith("地址:"):
                    lines.append("  " + extra)
        except Exception:                              # noqa: BLE001
            pass
        lines.append("  处置: 封禁 %s（第 %d 次违规 · 检测器 %s）— %s"
                     % (human_seconds(event.get("seconds", 0)),
                        int(event.get("offense", 1)),
                        event.get("detector", "?"),
                        "已生效" if enforced else "**未生效（封禁失败）**"))
        lines.append("  原因: %s" % event.get("reason", ""))
        if not enforced and event.get("err"):
            lines.append("  错误: %s" % oneline(event["err"], 200))
        lines.extend(d.behavior_lines(ip))
        explanation = attacks.explain(event.get("reason", ""),
                                      event.get("uris") or [])
        if explanation:
            lines.append("  解读: %s" % explanation)
        hint = attacks.remediation(event.get("reason", ""))
        if hint:
            lines.append("  " + hint)
        lines.append("")
        return lines


# --------------------------------------------------------------------------
# The daemon
# --------------------------------------------------------------------------
class ThreatDaemon:
    """Multi-threaded log tailer, detector and enforcer."""

    RE_SSH_FAIL = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port")
    RE_SSH_INVALID = re.compile(r"Invalid user (\S+) from (\S+)")
    RE_SSH_ACCEPT = re.compile(r"Accepted \S+ for (\S+) from (\S+) port")
    RE_SSH_PAM = re.compile(r"authentication failure;.*rhost=(\S+)")
    RE_HTTP = re.compile(r'^(\S+) \S+ \S+ \[[^\]]*\] "([^"]*)" (\d{3})')
    RE_HTTP_STATUS = re.compile(r'"\s+(\d{3})\s+')
    RE_IP = re.compile(r"^[0-9a-fA-F:.]+$")

    def __init__(self, cfg, log=None, dry_run: bool = False, echo: bool = False):
        # Defence in depth: refuse to run on an unparseable config even when a
        # caller constructs the daemon directly instead of going through main().
        assert_config_parsable(cfg.path)
        self.cfg = cfg
        self.dry_run = dry_run
        self.log = log or get_logger("threat", echo=echo)
        self.stop = threading.Event()
        self._exit_signal = 0
        self.trace: list = []

        self.settings = Settings(cfg)
        # Defect #1: compile signatures NOW, from the merged config.
        self.signatures = self._compile_signatures()

        self.whitelist = Whitelist(self.settings.whitelist,
                                   self.settings.auto_whitelist_local,
                                   log=self.log,
                                   max_cache=max(512, self.settings.max_tracked_ips // 4))
        self.windows = Windows(self.settings.max_tracked_ips,
                               self.settings.track_idle_ttl, self.log)
        self.behavior = BehaviorStore(self.settings.behavior_max_ips,
                                      self.settings.behavior_max_uris,
                                      self.settings.track_idle_ttl)
        self.cooldowns = CooldownMap(self.settings.alert_cooldown,
                                     max_keys=self.settings.max_tracked_ips)
        self.distributed = DistributedTracker(self.settings.distributed_window)
        self.netblocks = NetblockTracker(
            window=self.settings.netblock_window,
            log=self.log)
        self.breaker = BanBreaker(self.settings.max_bans_per_hour, 3600)
        self.strict = StrictMode(SHED_FLAG, self.settings.strict_flag_ttl,
                                 self.log)
        # One offsets store for the whole daemon, not one per follow thread.
        # The first version gave each thread its own snapshot and wrote that
        # snapshot back, so seventeen threads clobbered each other and the
        # file ended up holding whichever wrote last -- which meant most
        # sources silently started at the end of the file again.
        self._log_offsets = read_json(LOG_OFFSETS, {}) or {}
        if not isinstance(self._log_offsets, dict):
            self._log_offsets = {}
        self._log_offsets_lock = threading.Lock()

        self.posture = AttackPosture(
            POSTURE_FLAG,
            window=self.settings.posture_window,
            trigger=self.settings.posture_trigger,
            hold=self.settings.posture_hold,
            log=self.log)
        self.state = ThreatState(paths.THREAT_STATE, self.settings.offense_decay,
                                 self.settings.max_tracked_ips, self.log,
                                 persist=not dry_run)
        self.enforcer = Enforcer(self.settings.ipset_set,
                                 self.settings.iptables_chain,
                                 self.settings.ipset_program,
                                 self.settings.iptables_program,
                                 self.settings.max_tracked_ips,
                                 dry_run=dry_run, log=self.log)
        self.reporter = EventReporter(self)

        self._last_primary = {}
        self._last_primary_lock = threading.Lock()
        self._geo_cache = {}
        self._geo_lock = threading.Lock()
        self._threads = []
        self._log_source_list = []

    # -- signatures --------------------------------------------------------
    def _compile_signatures(self) -> dict:
        high, errors = attacks.compile_patterns(self.settings.exploit_high_patterns)
        low, errors_low = attacks.compile_patterns(self.settings.exploit_low_patterns)
        for bad in errors + errors_low:
            self.log.warn(_t("signature_bad", bad))
        if not high and not low:
            raise ConfigError(_t("signature_empty"))
        static = attacks.compile_static(self.settings.static_ext_pattern)
        if static is None:
            raise ConfigError(_t("static_bad"))
        self.log.info("签名表已从合并后的配置编译：高危 %d 条，低危 %d 条",
                      len(high), len(low))
        return {"high": high, "low": low, "static": static}

    # -- small helpers -----------------------------------------------------
    def audit(self, message: str) -> None:
        self.trace.append(message)
        self.log.info(message)

    def bump_stat(self, key: str, delta: int = 1) -> None:
        with self.state.lock:
            self.state.stats[key] = int(self.state.stats.get(key, 0)) + delta

    def thr(self, value):
        """Tighten a threshold when the machine is busy *or* under attack.

        Two independent reasons to demand less evidence before acting, and
        they compose: a host that is both overloaded and being attacked
        should not be the one place where thresholds stay relaxed.
        """
        if not isinstance(value, (int, float)):
            return value
        factor = 1.0
        if self.strict.active():
            factor = min(factor, self.settings.strict_factor)
        if self.posture.active():
            factor = min(factor, self.settings.posture_factor)
        if factor >= 1.0:
            return value
        return max(1, int(value * factor))

    @staticmethod
    def source_note(ip: str) -> str:
        """A caveat to attach when the source cannot be a real remote host.

        Reserved space in a log means the record is synthetic, desensitised,
        or fabricated upstream -- never an attacker in a specific city. The
        ban is harmless either way (the address cannot route), but an alert
        that names a country for it is misinformation, so the reason says so
        plainly.
        """
        try:
            from .checks import util
            found = util.special_address(ip)
        except (ImportError, OSError):
            return ""
        if not found:
            return ""
        return "（注意：%s 属于%s，不可能来自真实网络，请核查日志来源）" % (ip,
                                                                       found[0])

    @staticmethod
    def _valid_ip(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def geo_text(self, ip: str) -> str:
        """Geo/ASN enrichment, cached, skipped entirely in self-test."""
        if self.dry_run:
            return ip
        with self._geo_lock:
            cached = self._geo_cache.get(ip)
        if cached:
            return cached
        try:
            text = geo(self.cfg, ip)
        except Exception:                              # noqa: BLE001
            text = ip
        with self._geo_lock:
            if len(self._geo_cache) > 4096:
                self._geo_cache.clear()
            self._geo_cache[ip] = text
        return text

    def behavior_lines(self, ip: str) -> list:
        entry = self.behavior.snapshot(ip)
        if not entry:
            return []
        duration = max(1.0, entry["last"] - entry["first"])
        lines = []
        if entry["count"] > 1:
            lines.append("  行为: %d 秒内请求 %d 次（约 %.1f 次/秒）"
                         % (duration, entry["count"], entry["count"] / duration))
        else:
            lines.append("  行为: 单次请求")
        try:
            lines.append("  时间: %s ~ %s" % (
                datetime.fromtimestamp(entry["first"]).strftime("%H:%M:%S"),
                datetime.fromtimestamp(entry["last"]).strftime("%H:%M:%S")))
        except (ValueError, OSError):
            pass
        uris = entry.get("uris") or []
        if uris:
            shown = uris[-5:]
            lines.append("  请求样本: %s%s"
                         % ("、".join(oneline(u, 60) for u in shown),
                            "（等）" if len(uris) > 5 else ""))
        classes = entry.get("classes") or {}
        if classes:
            lines.append("  状态码分布: %s" % " ".join(
                "%s×%d" % (k, classes[k]) for k in sorted(classes)))
        return lines

    # -- ban policy --------------------------------------------------------
    def _ladder_for(self, detector: str) -> list:
        if detector.startswith("ssh"):
            return self.settings.ssh_ban_seconds
        if detector.startswith("portscan"):
            return self.settings.portscan_ban_seconds
        if detector.startswith("decoy"):
            return self.settings.decoy_ban_seconds
        return self.settings.http_ban_seconds

    def ban_seconds_for(self, detector: str, offense: int, severity: int) -> int:
        ladder = self._ladder_for(detector)
        seconds = ladder[min(max(offense, 1) - 1, len(ladder) - 1)]
        if severity >= 2:
            # High-confidence hit: never less than the instant minimum.
            seconds = max(seconds, self.settings.instant_ban_seconds)
        if offense >= self.settings.recidivist_bans:
            seconds = max(seconds, self.settings.recidivist_ban_seconds)
        return int(seconds)

    def ban(self, ip: str, reason: str, detector: str, severity: int = 1) -> bool:
        """Ban *ip*, escalating by offence count.  Returns whether it worked."""
        if not self._valid_ip(ip):
            self.audit("[跳过] %s" % _t("ban_bad_ip", ip))
            return False
        if self.whitelist.allowed(ip):
            self.audit("[放行] %s" % _t("ban_skip_whitelist", ip, reason))
            return False

        tripped, recent = self.breaker.tripped()
        if tripped:
            self.bump_stat("breaker_tripped")
            self.audit("[熔断] " + _t("breaker", recent, self.breaker.limit()))
            if self.cooldowns.allow("breaker"):
                self.reporter.queue({
                    "kind": "BREAKER", "immediate": True, "count": recent,
                    "limit": self.breaker.limit(), "window": self.breaker.window(),
                })
            return False

        self.breaker.record()
        note = self.source_note(ip)
        if note:
            reason = reason + note
        else:
            # Reserved space is not a campaign, so it must not be counted
            # towards a heightened posture -- otherwise a log full of test
            # fixtures would put the machine on a war footing.
            self._note_attack(1, "封禁 %s" % ip)
        offense = self.state.note_offense(ip)
        seconds = self.ban_seconds_for(detector, offense, severity)
        ok, err = self.enforcer.add(ip, seconds)

        if ok:
            self.state.note_ban(ip, time.time() + seconds, reason, offense,
                                detector)
        else:
            self.bump_stat("bans_failed")
        self.audit(("[封禁] %s -> %ss 第%d次 检测器=%s 原因=%s"
                    % (ip, seconds, offense, detector, reason)) if ok else
                   ("[封禁失败] %s -> %ss 检测器=%s 原因=%s 错误=%s"
                    % (ip, seconds, detector, reason, oneline(err, 120))))

        # Count the network this address belongs to. Escalation is only
        # considered *after* the address itself is banned, so an escalation
        # always has per-address bans behind it rather than standing alone.
        if ok and self.settings.netblock_enabled:
            try:
                net, distinct = self.netblocks.note(ip)
            except (OSError, ValueError):
                net, distinct = "", 0
            if net and distinct >= self.settings.netblock_min_ips:
                members = self.netblocks.members(net)
                self.ban_netblock(net, members)

        if self.settings.notify_bans:
            event = {
                "kind": "BAN" if ok else "BAN_FAIL",
                "immediate": severity >= 2 or not ok,
                "ip": ip, "reason": reason, "seconds": seconds,
                "offense": offense, "detector": detector, "severity": severity,
                "enforced": ok, "err": err,
                "uris": (self.behavior.snapshot(ip) or {}).get("uris", []),
            }
            self.reporter.queue(event)
        return ok

    def unban(self, ip: str) -> bool:
        ok = self.enforcer.remove(ip)
        self.state.drop_ban(ip)
        self.audit("解封 %s（%s）" % (ip, "成功" if ok else "失败"))
        return ok

    # -- SSH detectors -----------------------------------------------------
    def handle_ssh(self, line: str) -> None:
        match = self.RE_SSH_FAIL.search(line)
        if match:
            user, ip = match.group(1), match.group(2)
            self.behavior.record(ip, kind="ssh")
            self.on_ssh_failure(ip, user)
            return
        match = self.RE_SSH_INVALID.search(line)
        if match:
            user, ip = match.group(1), match.group(2)
            self.behavior.record(ip, kind="ssh")
            over, count = self.windows.bump(
                ip, "ssh_inv", self.settings.ssh_window,
                self.thr(self.settings.ssh_invalid_threshold))
            if over:
                self.ban(ip, "SSH 用户名枚举（%d 次/%ds）"
                         % (count, self.settings.ssh_window),
                         detector="ssh_invalid")
                self.windows.forget(ip)
            return
        match = self.RE_SSH_ACCEPT.search(line)
        if match:
            user, ip = match.group(1), match.group(2)
            self.on_ssh_success(ip, user, "password/key")
            return
        # PAM lines intentionally do not score: pam_unix emits
        # "authentication failure" immediately before "Failed password", so
        # counting both halves the effective threshold.
        if self.RE_SSH_PAM.search(line):
            return

    def on_ssh_failure(self, ip: str, user: str, primary: bool = True) -> None:
        now = time.time()
        with self._last_primary_lock:
            if primary:
                self._last_primary[ip] = now
                if len(self._last_primary) > self.settings.max_tracked_ips:
                    for key in list(self._last_primary)[
                            : max(1, self.settings.max_tracked_ips // 10)]:
                        self._last_primary.pop(key, None)
            elif now - self._last_primary.get(ip, 0) < 2.0:
                return

        over, count = self.windows.bump(
            ip, "ssh", self.settings.ssh_window,
            self.thr(self.settings.ssh_max_failures))
        n_ips, n_total = self.distributed.note(ip)
        if (n_ips >= self.settings.distributed_min_ips
                and n_total >= self.settings.distributed_min_fails):
            self.bump_stat("distributed_events")
            self._note_attack(5, "分布式爆破")
            self.audit("[分布式] " + _t("distributed", n_ips, n_total,
                                        self.settings.distributed_window))
            if self.cooldowns.allow("distributed"):
                self.reporter.queue({
                    "kind": "DIST", "immediate": True, "ips": n_ips,
                    "fails": n_total, "window": self.settings.distributed_window,
                })
        if over:
            self.ban(ip, "SSH 密码爆破（用户 %s，%d 次/%ds）"
                     % (user, count, self.settings.ssh_window), detector="ssh")
            self.windows.forget(ip)

    def on_ssh_success(self, ip: str, user: str, method: str) -> None:
        offense = self.state.offense_count(ip)
        whitelisted = self.whitelist.allowed(ip)
        if offense > 0:
            self.audit("[爆破成功?] %s 在 %d 次违规后登录为 %s"
                       % (ip, offense, user))
            if self.cooldowns.allow("breach-%s" % ip):
                self.reporter.queue({"kind": "BREACH", "immediate": True,
                                     "ip": ip, "user": user, "count": offense})
        elif not whitelisted:
            self.bump_stat("offwhitelist_logins")
            self.audit("[非白名单登录] %s -> %s" % (ip, user))
            if self.cooldowns.allow("offwl-%s" % ip):
                self.reporter.queue({"kind": "OFFWHITELIST", "immediate": True,
                                     "ip": ip, "user": user})
        if self.settings.notify_ssh_success:
            self.reporter.queue({"kind": "SSH", "ip": ip, "user": user,
                                 "method": method, "whitelisted": whitelisted})
        self.audit("SSH 登录成功: %s@%s%s"
                   % (user, ip, "" if whitelisted else "（非白名单，已告警）"))

    # -- netblock escalation ----------------------------------------------
    def netblock_blockers(self, net: str) -> str:
        """Why this network must NOT be banned, or "" if it is safe.

        Deliberately returns a reason rather than a boolean. Every refusal
        goes to the audit log, because "we did not escalate" and "we tried to
        escalate and were stopped by a rail" are different facts, and only
        the second one tells an operator whether the rails are doing anything.
        """
        try:
            network = ipaddress.ip_network(net, strict=False)
        except ValueError:
            return "无法解析的网段"

        # 1. Never a range that contains an address we must never block.
        #    This is the rail that matters most: a /24 that contains the
        #    operator's own address, or a whitelisted one, must be refused
        #    outright, however many attackers are in it.
        for entry in self.whitelist.entries():
            try:
                allowed = ipaddress.ip_network(str(entry), strict=False)
            except ValueError:
                continue
            if allowed.version != network.version:
                continue
            if network.overlaps(allowed):
                return ("白名单地址 %s 落在该网段内" % entry)

        # 2. Never a range containing this host's own addresses.
        try:
            for local in local_addresses() or ():
                addr = ipaddress.ip_address(str(local).split("/")[0])
                if addr.version == network.version and addr in network:
                    return "本机地址 %s 落在该网段内" % local
        except (ValueError, OSError):
            pass

        # 3. Never reserved or special-purpose space. Those ranges belong to
        #    nobody, so banning them protects nothing and hides a data
        #    problem behind an enforcement action.
        first = str(network.network_address)
        try:
            from .checks import util
            if util.special_address(first):
                return "保留地址空间（%s）" % util.special_address(first)[0]
        except (ImportError, OSError):
            pass

        # 4. Never wider than the fixed width, whatever the caller passed.
        want = NetblockTracker.V4_PREFIX if network.version == 4 \
            else NetblockTracker.V6_PREFIX
        if network.prefixlen < want:
            return "网段过宽（/%d），只允许 /%d" % (network.prefixlen, want)

        # 5. A cap on how many networks can be blocked at once, so a spray
        #    from many subnets cannot turn into an unbounded rule set.
        current = self.enforcer.net_members()
        if net not in current and len(current) >= self.settings.netblock_max_current:
            return "同时封禁的网段已达上限 %d" % self.settings.netblock_max_current
        return ""

    def ban_netblock(self, net: str, sample=None) -> bool:
        """Escalate from addresses to their network, if every rail allows it."""
        if not self.settings.netblock_enabled:
            return False
        blocker = self.netblock_blockers(net)
        if blocker:
            self.audit("[网段升级-拒绝] %s：%s" % (net, blocker))
            return False

        seconds = self.settings.netblock_ban_seconds
        ok, err = self.enforcer.add_net(net, seconds)
        if ok:
            self.netblocks.forget(net)
            self.bump_stat("netblock_bans")
            self.audit("[网段升级] %s -> %ss（窗口内 %d 个独立来源）"
                       % (net, seconds, len(sample or [])))
            if self.settings.notify_bans:
                self.reporter.queue({
                    "kind": "NETBLOCK", "immediate": True, "net": net,
                    "seconds": seconds, "ips": list(sample or [])[:12],
                    "count": len(sample or [])})
        else:
            self.bump_stat("netblock_failed")
            self.audit("[网段升级-失败] %s：%s" % (net, oneline(err, 140)))
        return ok

    def _note_attack(self, weight: int, why: str) -> None:
        """Feed an attack signal to the posture, and announce transitions.

        Announcements happen here rather than at the call sites so that
        entering and leaving heightened defence is reported exactly once,
        whichever signal caused it. A posture change that nobody is told
        about is indistinguishable from the protection silently changing
        behaviour, which is how operators learn to distrust the alerts.
        """
        if not self.settings.posture_enabled:
            return
        try:
            raised = self.posture.note(weight)
        except (OSError, ValueError):
            return
        if raised:
            self.bump_stat("posture_raised")
            self.audit("[高压姿态] 由「%s」触发，阈值收紧，持续 %d 秒"
                       % (why, self.settings.posture_hold))
            if self.settings.notify_bans:
                self.reporter.queue({
                    "kind": "POSTURE", "state": "on", "why": why,
                    "hold": self.settings.posture_hold,
                    "factor": self.settings.posture_factor})

    def check_posture_decay(self) -> None:
        """Notice the *end* of a posture, which only the clock can cause."""
        if not self.settings.posture_enabled:
            return
        try:
            change = self.posture.transition()
        except OSError:
            return
        if change == "off":
            self.audit("[高压姿态] 结束，阈值恢复")
            if self.settings.notify_bans:
                self.reporter.queue({"kind": "POSTURE", "state": "off"})

    def note_decoy_hit(self, ip: str, uri: str) -> None:
        """Persist a decoy hit for the learning pass.

        Never allowed to break the ban path: if the record cannot be written
        the response still happens. Losing a data point is a small loss;
        losing the ban because of it would be a large one.
        """
        try:
            from . import decoy as decoy_mod
            decoy_mod.note_hit(ip, uri)
        except (ImportError, OSError):
            pass
        self.bump_stat("decoy_hits")

    # -- HTTP detectors ----------------------------------------------------
    def handle_decoy(self, line: str) -> None:
        """One line in the decoy log means one deliberate probe. Ban it.

        This is the shortest path in the whole program from observation to
        action, and that is the point. Every other detector has to decide how
        much evidence is enough; here the evidence is structural:

        * the path does not exist on disk,
        * nothing the site serves links to it, and
        * the only clients that request it are scanners.

        So a single hit is conclusive rather than suggestive -- no window, no
        threshold, no second chance -- and the resulting ban is measured in
        weeks rather than minutes.

        Nothing else in the line is interpreted: the path is not matched
        against signatures and the user agent is not consulted. A request
        that arrived in *this* log was already classified by the fact that it
        arrived at all.
        """
        if not self.settings.decoy_enabled:
            return
        first = line.split(None, 1)
        if not first:
            return
        ip = first[0]
        if not self.RE_IP.match(ip):
            return
        # Which decoy was touched. It goes into the alert, and it is the raw
        # material the learning pass mines for new candidates.
        uri = ""
        parts = line.split('"')
        if len(parts) >= 2:
            bits = parts[1].split()
            if len(bits) >= 2:
                uri = bits[1]
        self.note_decoy_hit(ip, uri)
        if not self.source_note(ip):
            self._note_attack(3, "诱饵命中")
        self.ban(ip, "蜜罐诱饵命中：请求了不存在的诱饵路径 %s" % (uri or "?"),
                 detector="decoy", severity=2)

    def handle_http(self, line: str) -> None:
        match = self.RE_HTTP.match(line)
        if match:
            ip, request, status = match.group(1), match.group(2), int(match.group(3))
        else:
            fallback = self.RE_HTTP_STATUS.search(line)
            if not fallback:
                return
            first = line.split()
            if not first:
                return
            ip, request, status = first[0], "", int(fallback.group(1))
        if not self.RE_IP.match(ip):
            return

        uris = []
        if request:
            parts = request.split()
            uri = parts[1] if len(parts) >= 2 else request
            uris = [uri]
            self.behavior.record(ip, uri, status)
            # Evidence for the learning pass: what was asked for, by whom,
            # and what came back. Best-effort and bounded -- the access logs
            # remain the authoritative record.
            try:
                from . import learning
                learning.observe(ip, uri, status)
            except (ImportError, OSError):
                pass

            # A static asset is never judged by the exploit signatures: panels
            # load icons whose names contain "phpmyadmin", and that once banned
            # an administrator for 24 hours.
            if not (self.signatures["static"]
                    and self.signatures["static"].search(uri)):
                for pattern in self.signatures["high"]:
                    if pattern.search(uri):
                        self.ban(ip, "高危漏洞利用尝试: %s" % oneline(uri, 80),
                                 detector="exploit_high", severity=2)
                        self.windows.forget(ip)
                        return
                for pattern in self.signatures["low"]:
                    if pattern.search(uri):
                        over, count = self.windows.bump(
                            ip, "exploit_low", self.settings.exploit_low_window,
                            self.thr(self.settings.exploit_low_hits))
                        if over:
                            self.ban(ip, "敏感路径扫描（%d 次命中，如 %s）"
                                     % (count, oneline(uri, 60)),
                                     detector="exploit_low")
                            self.windows.forget(ip)
                            return
                        break

        if status >= 400:
            # Defect #13: report the real class (5xx must not print as 4xx).
            cls = "%dxx" % (status // 100)
            threshold = self.thr(self.settings.http_burst_threshold)
            # Bump the class-specific counter (accurate reporting) and a
            # combined one (an attacker alternating 403/500 must still trip it,
            # which is what the original's single counter did).
            over_cls, count_cls = self.windows.bump(
                ip, "http_%s" % cls, self.settings.http_burst_window, threshold)
            over_all, count_all = self.windows.bump(
                ip, "http_err", self.settings.http_burst_window, threshold)
            if over_cls or over_all:
                self.ban(ip, "目录扫描/异常请求（%d 次 %s/%ds）"
                         % (max(count_cls, count_all), cls,
                            self.settings.http_burst_window),
                         detector="http_burst")
                self.windows.forget(ip)
                return
        over, count = self.windows.bump(
            ip, "http_flood", self.settings.http_flood_window,
            self.thr(self.settings.http_flood_threshold))
        if over:
            self.ban(ip, "请求洪泛（%d 次/%ds）"
                     % (count, self.settings.http_flood_window),
                     detector="http_flood")

    # -- threads -----------------------------------------------------------
    def save_log_offsets(self) -> None:
        """Merge this daemon's read positions into the on-disk map.

        Re-reads before writing so that a second daemon (or a manual run)
        cannot lose the other's positions, and takes the lock so the follow
        threads cannot interleave a read-modify-write.
        """
        with self._log_offsets_lock:
            current = read_json(LOG_OFFSETS, {}) or {}
            if not isinstance(current, dict):
                current = {}
            current.update(self._log_offsets)
            try:
                write_json(LOG_OFFSETS, current, mode=0o640)
            except OSError:
                pass

    def tail_file(self, path: str, handler, kind: str) -> None:
        """Follow one log, resuming from where the last run stopped.

        Replaces `tail -F -n 0`, which dropped every line written while the
        daemon was restarting -- see :class:`LogFollower` for how that was
        found and why a security daemon cannot afford it.
        """
        follower = LogFollower(path, self._log_offsets, log=self.log,
                               save=lambda _store: self.save_log_offsets())
        tick = 0
        while not self.stop.is_set():
            got = False
            try:
                for line in follower.poll():
                    got = True
                    if self.stop.is_set():
                        break
                    if not line.strip():
                        follower.tell()
                        continue
                    self.bump_stat("events")
                    try:
                        handler(line)
                    except Exception as exc:               # noqa: BLE001
                        self.log.debug("处理异常 %s: %s", kind, exc)
                    follower.tell()
            except Exception as exc:                       # noqa: BLE001
                self.log.debug("跟随 %s 出错：%s", path, exc)
                follower._close()

            tick += 1
            if tick % 20 == 0 or not got:
                follower.flush()
            self.stop.wait(1 if got else 3)
        follower.flush()

    def selfheal(self) -> None:
        """Re-assert the set and the INPUT rule after ufw/panel reloads."""
        while not self.stop.wait(self.settings.selfheal_interval):
            try:
                set_missing = not self.enforcer.set_exists()
                rule_pos = self.enforcer.rule_position()
                if set_missing or rule_pos is None or rule_pos != 1:
                    self.log.warn(_t("selfheal", set_missing, rule_pos != 1))
                    self.enforcer.ensure()
                if set_missing:
                    pending = self.state.pending()
                    restored = 0
                    for ip, seconds in pending:
                        if seconds > 0:
                            ok, err = self.enforcer.add(ip, seconds)
                            if ok:
                                restored += 1
                            else:
                                self.log.warn("恢复封禁 %s 失败：%s", ip, err)
                    if restored:
                        self.log.info(_t("restored", restored))
                self.save_stats()
            except Exception as exc:                       # noqa: BLE001
                self.log.warn("自愈线程异常：%s", exc)

    def housekeeping(self) -> None:
        # Unban requests are *not* drained here any more. This cycle runs
        # every `housekeeping_interval` (300 s by default) and an operator's
        # unban must not wait five minutes to become durable -- see
        # `unban_watcher`, which owns that job now. Keeping both would also
        # put two threads on the same read-then-truncate file.
        while not self.stop.wait(self.settings.housekeeping_interval):
            try:
                self.prune()
                self.state.save()
            except Exception as exc:                       # noqa: BLE001
                self.log.warn("清理线程异常：%s", exc)

    def unban_watcher(self) -> None:
        """Apply CLI unban requests promptly.

        `vigil threat unban` removes the address from the enforcement set
        immediately, but the running daemon still holds the ban in memory and
        re-applies it on its next save. The request file is how the two are
        reconciled -- so it has to be drained on a human timescale, not on
        the housekeeping one. While it was drained every 300 s, an unban
        looked like it had worked and then quietly reverted; twenty lifted
        bans returned during one drill.
        """
        while not self.stop.wait(UNBAN_POLL_SECONDS):
            try:
                n = self.apply_unban_requests()
                if n:
                    self.log.info("已应用 %d 条解封请求" % n)
            except Exception as exc:                       # noqa: BLE001
                self.log.warn("解封监听异常：%s", exc)

    def apply_unban_requests(self) -> int:
        """Drain unban requests written by the CLI. Returns how many applied.

        Draining (truncating) rather than re-reading is deliberate: these are
        one-shot instructions, and replaying a stale one would silently undo
        a later, deliberate ban of the same address.
        """
        path = str(UNBAN_REQUESTS)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        except OSError:
            return 0
        if not raw.strip():
            return 0
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("")
        except OSError:
            return 0
        applied = 0
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except ValueError:
                continue
            ip = str(req.get("ip", "")).strip()
            if ip and self._valid_ip(ip):
                # Both halves are required. Dropping the record alone left
                # the address in the enforcement set, so it stayed blocked
                # while every command reported it as unbanned -- the exact
                # "looks fixed, still broken" shape this project keeps
                # finding. Removing from the set alone was the earlier bug
                # in the other direction.
                self.enforcer.remove(ip)
                self.state.drop_ban(ip)
                applied += 1
        if applied:
            self.audit("[解封] 应用了 %d 条来自命令行的解封请求" % applied)
            self.state.save()
        return applied

    def prune(self) -> None:
        with self._last_primary_lock:
            if len(self._last_primary) > self.settings.max_tracked_ips:
                for key in list(self._last_primary)[
                        : max(1, self.settings.max_tracked_ips // 10)]:
                    self._last_primary.pop(key, None)
        counts = self.state.prune()
        self.windows.prune()
        self.behavior.prune()
        self.cooldowns.prune()
        self.distributed.prune()
        self.netblocks.prune()
        # A posture ends when its deadline passes, and nothing calls in at
        # that moment -- so the change has to be looked for.
        self.check_posture_decay()
        self.log.debug(_t("housekeeping", counts["offenses"], counts["bans"],
                          self.behavior.size(), self.windows.size()))

    def save_stats(self) -> None:
        self.save_log_offsets()
        with self.state.lock:
            self.state.stats["uptime"] = int(
                time.time() - self.state.stats.get("started", time.time()))
        if not self.dry_run:
            self.state.stats["bans_current"] = len(self.enforcer.members())
        self.state.save()

    # -- lifecycle ---------------------------------------------------------
    def _on_signal(self, signum, _frame) -> None:
        # Async-signal-safe: no subprocess, no file I/O, no locking.
        self._exit_signal = signum
        self.stop.set()

    def _install_signals(self) -> None:
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, self._on_signal)
            except (ValueError, OSError):
                pass

    def _source_plan(self):
        sources = self.settings.log_sources
        plan = []
        for path in sources.get("auth", []):
            plan.append((path, self.handle_ssh, "auth"))
        for path in sources.get("nginx_access", []):
            plan.append((path, self.handle_http, "http"))
        for path in sources.get("panel", []):
            plan.append((path, self.handle_http, "panel"))
        for path in sources.get("decoy", []):
            plan.append((path, self.handle_decoy, "decoy"))
        return plan

    def run(self) -> int:
        if self.dry_run:
            return self._run()
        paths.ensure_dirs()
        with locked(paths.LOCK_THREAT) as got:
            if not got:
                self.log.crit(_t("lock_busy"))
                return 1
            return self._run()

    def _run(self) -> int:
        self.log.info("=" * 60)
        self.log.info(_t("started", os.getpid()))
        self.log.info(_t("whitelist", "、".join(self.whitelist.entries())))
        sources = self.settings.log_sources
        # Every category is printed, including the decoy log. A source that
        # is watched but not listed in the start-up banner is a source nobody
        # can confirm is being watched -- and "looks healthy while doing
        # nothing" is this program's recurring failure mode.
        self.log.info(_t("sources", sources.get("auth"), sources.get("nginx_access"),
                         sources.get("panel")))
        self.log.info("decoy sources: %s" % (sources.get("decoy") or "（无）"))

        if not self.dry_run:
            try:
                write_text(paths.PID_THREAT, "%d\n" % os.getpid(), mode=0o644)
            except OSError:
                pass
            self.enforcer.ensure()

        self._purge_whitelisted_bans()
        self._restore_pending_bans()
        # A request written while the daemon was down must be applied *after*
        # the restore, or the restore puts the ban straight back.
        self.apply_unban_requests()

        plan = self._source_plan()
        if not plan:
            self.log.warn("没有可监控的日志源（请检查 threat.log_sources 或 detect.log_sources()）")
        self._log_source_list = [p for p, _h, _k in plan]

        self._install_signals()

        self._threads = [
            threading.Thread(target=self.selfheal, daemon=True, name="selfheal"),
            threading.Thread(target=self.housekeeping, daemon=True, name="housekeeping"),
            threading.Thread(target=self.unban_watcher, daemon=True, name="unbans"),
            threading.Thread(target=self.reporter.run, daemon=True, name="reporter"),
        ]
        for path, handler, kind in plan:
            self._threads.append(threading.Thread(
                target=self.tail_file, args=(path, handler, kind),
                daemon=True, name="tail-%s" % os.path.basename(path) or kind))
        for thread in self._threads:
            thread.start()
        self.log.info(_t("ready", len(plan)))

        try:
            while not self.stop.is_set():
                self.stop.wait(self.settings.poll_interval)
                if self.stop.is_set():
                    break
                self.save_stats()
        finally:
            # Everything that touches the disk or the network happens here,
            # never in the signal handler.
            if self._exit_signal:
                self.log.warn(_t("signal", self._exit_signal))
            try:
                self.reporter.flush(force=True)
            except Exception as exc:                       # noqa: BLE001
                self.log.warn("退出前上报事件失败：%s", exc)
            self.save_stats()
            if not self.dry_run:
                try:
                    os.remove(str(paths.PID_THREAT))
                except OSError:
                    pass
            self.log.info(_t("stopped"))
        return 0

    def _purge_whitelisted_bans(self) -> None:
        """Safety valve: a whitelisted address is never left banned."""
        purged = []
        with self.state.lock:
            for ip in list(self.state.bans):
                if self.whitelist.allowed(ip):
                    self.state.bans.pop(ip, None)
                    self.state.offenses.pop(ip, None)
                    purged.append(ip)
        for ip in purged:
            if not self.dry_run:
                self.enforcer.remove(ip)
        if purged:
            self.log.warn(_t("purged", len(purged), "、".join(purged)))

    def _restore_pending_bans(self) -> None:
        pending = self.state.pending()
        restored = 0
        for ip, seconds in pending:
            if seconds <= 0:
                continue
            if self.dry_run:
                restored += 1
                continue
            ok, err = self.enforcer.add(ip, seconds)
            if ok:
                restored += 1
            else:
                self.log.warn("恢复封禁 %s 失败：%s", ip, err)
        if restored:
            self.log.info(_t("restored", restored))

    def deliver(self, alert: Alert) -> bool:
        if self.dry_run:
            self.trace.append("ALERT: %s" % alert.title)
            return True
        return send_alert(alert, cfg=self.cfg, log=self.log)

    def describe(self) -> dict:
        return {
            "ipset_set": self.settings.ipset_set,
            "iptables_chain": self.settings.iptables_chain,
            "signatures": {"high": len(self.signatures["high"]),
                           "low": len(self.signatures["low"])},
            "whitelist": self.whitelist.entries(),
            "whitelist_auto_local": self.settings.auto_whitelist_local,
            "log_sources": self.settings.log_sources,
            "strict_mode": self.strict.active(),
            "bans": len(self.state.bans),
            "offenses": len(self.state.offenses),
            "stats": dict(self.state.stats),
        }


# --------------------------------------------------------------------------
# Self test -- fixed sample lines through every detector, no enforcement
# --------------------------------------------------------------------------
def _sample(ip, request, status):
    return ('%s - - [27/Feb/2026:10:00:00 +0800] "%s" %d 512 "-" "curl/8.0"'
            % (ip, request, status))


def self_test(cfg) -> int:
    """Run every detector against fixed lines; touch neither ipset nor iptables."""
    daemon = ThreatDaemon(cfg, dry_run=True, echo=True)
    print("=" * 72)
    print("threat self-test (dry-run: ipset/iptables are NOT touched)")
    print("ipset set=%s chain=%s | signatures high=%d low=%d"
          % (daemon.settings.ipset_set, daemon.settings.iptables_chain,
             len(daemon.signatures["high"]), len(daemon.signatures["low"])))
    print("ssh: max_failures=%d/%ds invalid=%d | http: low_hits=%d/%ds "
          "burst=%d/%ds flood=%d/%ds"
          % (daemon.settings.ssh_max_failures, daemon.settings.ssh_window,
             daemon.settings.ssh_invalid_threshold,
             daemon.settings.exploit_low_hits, daemon.settings.exploit_low_window,
             daemon.settings.http_burst_threshold, daemon.settings.http_burst_window,
             daemon.settings.http_flood_threshold, daemon.settings.http_flood_window))
    print("=" * 72)

    cases = []
    brute_ip = "203.0.113.9"
    cases.append(("SSH 密码爆破（阈值内 4 次，不应封禁）",
                  [("ssh", 'Feb 27 10:00:%02d host sshd[1]: Failed password for '
                           'invalid user admin from %s port 51%03d ssh2'
                           % (i, brute_ip, i)) for i in range(4)]))
    cases.append(("SSH 密码爆破（第 5 次达阈值 -> 封禁）",
                  [("ssh", 'Feb 27 10:00:05 host sshd[1]: Failed password for '
                           'invalid user admin from %s port 51999 ssh2' % brute_ip)]))

    enum_ip = "203.0.113.10"
    cases.append(("SSH 用户名枚举（%d 次阈值）"
                  % daemon.settings.ssh_invalid_threshold,
                  [("ssh", 'Feb 27 10:01:%02d host sshd[1]: Invalid user u%d from '
                           '%s port 5200%d' % (i, i, enum_ip, i))
                   for i in range(daemon.settings.ssh_invalid_threshold)]))

    cases.append(("SSH 爆破后成功登录（高危告警）",
                  [("ssh", 'Feb 27 10:02:00 host sshd[1]: Accepted password for '
                           'root from %s port 53000 ssh2' % brute_ip),
                   ("ssh", 'Feb 27 10:02:01 host sshd[1]: Accepted publickey for '
                           'root from 203.0.113.55 port 53001 ssh2')]))

    cases.append(("HTTP 高危漏洞特征（单次命中 -> 立即长封禁）",
                  [("http", _sample("203.0.113.20",
                                    "GET /../../etc/passwd HTTP/1.1", 200))]))

    cases.append(("HTTP 静态资源豁免（宝塔面板 phpmyadmin 图标，不应封禁）",
                  [("http", _sample("203.0.113.21",
                                    "GET /static/img/soft_ico/ico-phpmyadmin.png "
                                    "HTTP/1.1", 200))
                   for _ in range(daemon.settings.exploit_low_hits + 2)]))

    low_ip = "203.0.113.22"
    cases.append(("HTTP 敏感路径扫描（低置信度累计 %d 次 -> 封禁）"
                  % daemon.settings.exploit_low_hits,
                  [("http", _sample(low_ip, "GET /wp-login.php HTTP/1.1", 200))
                   for _ in range(daemon.settings.exploit_low_hits)]))

    cases.append(("HTTP 5xx 突发（原因必须显示 5xx，不能写成 4xx）",
                  [("http", _sample("203.0.113.23", "GET /api/x HTTP/1.1", 503))
                   for _ in range(daemon.settings.http_burst_threshold)]))

    cases.append(("HTTP 请求洪泛（%d 次）" % daemon.settings.http_flood_threshold,
                  [("http", _sample("203.0.113.24", "GET / HTTP/1.1", 200))
                   for _ in range(daemon.settings.http_flood_threshold)]))

    cases.append(("白名单地址（127.0.0.1）命中高危特征：放行，不封禁",
                  [("http", _sample("127.0.0.1",
                                    "GET /../../etc/passwd HTTP/1.1", 200))]))
    cases.append(("无法解析的地址：fail closed，拒绝封禁并记录",
                  [("http", _sample("999.999.999.999",
                                    "GET /../../etc/passwd HTTP/1.1", 200))]))

    for title, lines in cases:
        print("\n[用例] %s" % title)
        for kind, line in lines:
            mark = len(daemon.trace)
            handler = daemon.handle_ssh if kind == "ssh" else daemon.handle_http
            handler(line)
            for entry in daemon.trace[mark:]:
                print("    " + entry)

    print("\n[状态]")
    print("    封禁数=%d 违规记录=%d 失败=%d 熔断=%d 分布式=%d 日志事件=%d"
          % (len(daemon.state.bans), len(daemon.state.offenses),
             daemon.state.stats.get("bans_failed", 0),
             daemon.state.stats.get("breaker_tripped", 0),
             daemon.state.stats.get("distributed_events", 0),
             daemon.state.stats.get("events", 0)))
    print("    示例告警标题：%s" % daemon.reporter.build_alert(
        [{"kind": "BAN", "ip": low_ip, "reason": "敏感路径扫描（3 次命中，如 /wp-login.php）",
          "seconds": 3600, "offense": 1, "detector": "exploit_low", "severity": 1,
          "enforced": True, "uris": ["/wp-login.php"]}]).title)
    print("\nself-test 完成：未执行任何 ipset/iptables 命令，未写入任何状态文件。")
    return 0


def _print_config(cfg) -> int:
    daemon = ThreatDaemon(cfg, dry_run=True)
    print("=" * 72)
    print("resolved threat configuration (and every config key read)")
    print("=" * 72)
    print(json.dumps(daemon.describe(), ensure_ascii=False, indent=2,
                     sort_keys=True))
    print("\n[config keys read]  (in_schema=False means not in core/config.py DEFAULTS)")
    for item in daemon.settings.keys_read:
        print("  %-46s schema=%-5s source=%s"
              % (item["key"], item["in_schema"], item["source"]))
    print("\nmissing_from_schema (extension keys actually consulted):")
    for item in sorted({i["key"] for i in daemon.settings.keys_read
                        if not i["in_schema"]}):
        print("  " + item)
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="vigil-threatd",
        description="Vigil threat daemon: real-time detection and auto-banning.")
    parser.add_argument("--config", default=None,
                        help="path to config.json (default: %s)" % paths.CONFIG)
    parser.add_argument("--self-test", action="store_true",
                        help="run fixed samples through every detector; "
                             "never touches ipset/iptables")
    parser.add_argument("--dry-run", action="store_true",
                        help="run the daemon but never enforce or persist")
    parser.add_argument("--show-config", action="store_true",
                        help="print resolved settings and every key read")
    parser.add_argument("--lang", default="", help="ui language: zh or en")
    args = parser.parse_args(argv)

    if args.lang:
        set_language(args.lang)

    cfg = load_config(args.config) if args.config else load_config()
    # Defect #2: a broken config file stops us loudly instead of silently
    # falling back to defaults.
    try:
        assert_config_parsable(cfg.path)
    except ConfigError as exc:
        print("错误：%s" % exc, file=sys.stderr)
        return 2

    if args.self_test:
        return self_test(cfg)
    if args.show_config:
        return _print_config(cfg)

    daemon = ThreatDaemon(cfg, dry_run=args.dry_run, echo=True)
    if not daemon.settings.enabled and not args.dry_run:
        daemon.log.warn("threat.enabled=false，按配置退出")
        return 0
    return daemon.run()


# --------------------------------------------------------------------------
# Public interface for the CLI
# --------------------------------------------------------------------------
# The daemon is a long-running object; the CLI needs to ask the *same*
# questions without starting it. These helpers build a daemon in dry-run
# mode (so nothing is enforced) purely to reuse its configuration parsing,
# whitelist and state loading, then read or mutate exactly one thing.

def _cli_daemon(cfg, log=None, dry_run: bool = False) -> "ThreatDaemon":
    return ThreatDaemon(cfg, log=log or get_logger("threat"),
                        dry_run=dry_run, echo=False)


def is_valid_address(value: str) -> bool:
    """Accept a bare IPv4/IPv6 address or a CIDR network."""
    text = str(value or "").strip()
    if not text:
        return False
    try:
        if "/" in text:
            ipaddress.ip_network(text, strict=False)
        else:
            ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def status_snapshot(cfg, log=None) -> dict:
    """Everything `vigil threat status` shows."""
    daemon = _cli_daemon(cfg, log, dry_run=True)
    info = daemon.describe()
    members = {}
    try:
        members = daemon.enforcer.members()
    except Exception:                                   # noqa: BLE001
        members = {}

    sources = []
    notes = []
    for entry in (info.get("log_sources") or {}).items():
        kind, paths = entry
        for path in (paths if isinstance(paths, list) else [paths]):
            if not path:
                continue
            exists = os.path.isfile(path)
            sources.append({"path": path, "kind": kind, "exists": exists})
            if not exists:
                # A configured log that does not exist is the single most
                # common reason a detector is silently dead.
                notes.append("配置的日志不存在，该来源不会被监控：%s" % path)

    stats = info.get("stats") or {}
    if not info.get("whitelist"):
        notes.append("白名单为空 —— 存在被自己的风控锁在外面的风险")
    if not daemon.enforcer.set_exists() and not daemon.dry_run:
        notes.append("封禁集合 %s 不存在，自动封禁当前未生效"
                     % info.get("ipset_set"))

    return {
        "enabled": bool(cfg.get("threat.enabled", True)),
        "ipset": info.get("ipset_set"),
        "chain": info.get("iptables_chain"),
        "whitelist_count": len(info.get("whitelist") or []),
        "banned_count": len(members) or len(daemon.state.bans),
        "bans_total": stats.get("bans_total", 0),
        "offenses": len(daemon.state.offenses),
        "sources": len(sources),
        "source_list": sources,
        "signatures": info.get("signatures"),
        "strict_mode": info.get("strict_mode"),
        "stats": stats,
        "notes": notes,
        "daemon": info,
    }


def list_bans(cfg, log=None) -> list:
    """Current bans, richest source first.

    The kernel's ipset membership is authoritative for *what is actually
    blocked*; the state file additionally knows why and until when. When
    they disagree the kernel wins, because that is what is really happening.
    """
    daemon = _cli_daemon(cfg, log, dry_run=True)
    now = time.time()
    members = {}
    try:
        members = daemon.enforcer.members()
    except Exception:                                   # noqa: BLE001
        members = {}

    out = {}
    for ip, info in (daemon.state.bans or {}).items():
        until = float(info.get("until", 0) or 0)
        out[ip] = {
            "ip": ip,
            "reason": info.get("reason", ""),
            "detector": info.get("detector", ""),
            "offense": info.get("offense", info.get("count", 0)),
            "until": until,
            "remaining": max(0, int(until - now)) if until else 0,
            "geo": daemon.geo_text(ip),
        }
    for ip, left in members.items():
        if ip in out:
            if left is not None:
                out[ip]["remaining"] = int(left)
            continue
        out[ip] = {"ip": ip, "reason": "（内核中存在，本程序无记录）",
                   "detector": "", "offense": 0,
                   "until": now + (left or 0), "remaining": int(left or 0),
                   "geo": daemon.geo_text(ip)}
    return sorted(out.values(), key=lambda b: b["remaining"])


def manual_ban(cfg, ip: str, seconds: int = 0, reason: str = "",
               log=None) -> tuple:
    """Ban an address now. Returns ``(ok, detail)``."""
    if not is_valid_address(ip):
        return False, "不是合法的 IP 或网段: %s" % ip
    daemon = _cli_daemon(cfg, log, dry_run=False)
    if daemon.whitelist.allowed(ip):
        return False, ("%s 在白名单中，已拒绝封禁。"
                       "如需强制封禁，请先用 "
                       "`vigil threat whitelist remove %s`" % (ip, ip))
    if seconds:
        # Enforcer.add returns (ok, err); treating the tuple as a bool would
        # report a ban that was never enforced (the original defect this port
        # exists to fix).
        ok, err = daemon.enforcer.add(ip, int(seconds))
        if ok:
            daemon.state.bans[ip] = {
                "until": time.time() + int(seconds),
                "reason": reason or "管理员手动封禁",
                "detector": "manual",
            }
            daemon.state.save()
            return True, "时长 %d 秒" % int(seconds)
        # Report the failure honestly rather than claiming a ban happened.
        return False, "ipset 写入失败：%s" % (
            err or "封禁集合可能不存在，或缺少 ipset 命令")
    ok = daemon.ban(ip, reason or "管理员手动封禁", detector="manual")
    if ok:
        info = daemon.state.bans.get(ip) or {}
        left = int(max(0, float(info.get("until", 0)) - time.time()))
        return True, "时长 %d 秒" % left if left else ""
    return False, "封禁未生效，请查看日志 %s" % paths.LOG_THREAT


def net_members(cfg=None, log=None) -> dict:
    """Networks currently blocked, as ``{cidr: seconds_remaining}``.

    Module-level like :func:`unban`, because the CLI has no daemon of its own
    and the enforcement set is the only authoritative record of what is
    actually blocked -- the state file describes intent, the kernel describes
    reality.
    """
    cfg = cfg or load_config()
    daemon = _cli_daemon(cfg, log, dry_run=False)
    try:
        return daemon.enforcer.net_members()
    except (OSError, AttributeError):
        return {}


def remove_net(cfg, net: str, log=None) -> bool:
    """Withdraw one network-range ban. Returns whether it was lifted."""
    if not is_valid_address(net) and "/" not in str(net):
        return False
    daemon = _cli_daemon(cfg, log, dry_run=False)
    ok = daemon.enforcer.remove_net(net)
    if ok:
        daemon.audit("[网段升级-撤回] %s" % net)
        daemon.state.save()
    return ok


def unban(cfg, ip: str, log=None) -> tuple:
    """Lift a ban, durably. Returns ``(ok, detail)``.

    Two steps, because the running daemon owns the state file:

    * remove it from the enforcement set now, so the effect is immediate;
    * leave a request for the daemon, which is the only writer of the state
      file, so the removal survives the daemon's next save and the next
      restart. Without the second step the address reappeared minutes later,
      which looks exactly like the unban silently failing.
    """
    if not is_valid_address(ip):
        return False, "不是合法的 IP 或网段: %s" % ip
    daemon = _cli_daemon(cfg, log, dry_run=False)

    # Three steps, because each covers a different failure:
    #
    # 1. drop it from the enforcement set -- the effect the operator asked
    #    for, visible immediately;
    # 2. leave a request for the daemon, which is the state file's only
    #    long-lived writer. This is what makes the lift *durable*: without
    #    it the daemon's next periodic save resurrected the ban from memory,
    #    which is precisely what was observed;
    # 3. apply it here as well, so a host with no daemon at all converges
    #    without waiting for one to start.
    #
    # The request is written unconditionally. An earlier version tried to
    # detect whether a daemon was running first, and the detection was wrong
    # (the pid file lives in systemd's per-unit runtime directory, which is
    # not visible from the CLI) -- so on the real host it took the direct
    # path, the daemon clobbered it, and the bans came back. A request that
    # is always written cannot be skipped by a bad guess.
    daemon.enforcer.remove(ip)
    try:
        os.makedirs(os.path.dirname(str(UNBAN_REQUESTS)), exist_ok=True)
        with open(str(UNBAN_REQUESTS), "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ip": ip, "ts": time.time()}) + "\n")
    except OSError as e:
        log and log.warn("写入解封请求失败（仍会直接修改状态）：%s" % e)

    existed = ip in daemon.state.bans
    daemon.state.drop_ban(ip)
    daemon.state.save()
    if not existed:
        # Still correct to have removed it from the set and recorded the
        # request; report the state honestly rather than claiming a change.
        daemon.audit("解封 %s（该地址不在封禁记录中，已确保不在封禁集合）" % ip)
        return False, "该地址当前不在封禁记录中"
    daemon.audit("解封 %s（已提交，守护进程会持久化）" % ip)
    return True, ""


if __name__ == "__main__":                              # pragma: no cover
    sys.exit(main())
