"""systemd unit generation.

Units are rendered from templates rather than shipped as static files
because almost every path in them depends on discovery: where nginx lives,
which PHP socket to use, which python interpreter, what the config path is.

Two hardening decisions worth stating:

* **`StateDirectory=`/`RuntimeDirectory=`** instead of pre-creating paths by
  hand. systemd then owns the lifecycle, sets the right mode and owner, and
  cleans the runtime dir on stop -- which removes a whole class of "works
  after install, breaks after reboot" bugs.
* **`Nice=-5` only for the threat daemon.** It must win CPU against an
  attacker's traffic; nothing else gets to preempt normal work.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

from . import paths, shell

UNIT_TEMPLATE_SERVICE = """[Unit]
Description={description}
After=network-online.target{after_extra}
Wants=network-online.target
{unit_extra}
[Service]
Type={stype}
# The package is deployed to a prefix that is not on the default sys.path,
# so tell the interpreter where to find it. Without this every unit fails
# with ModuleNotFoundError -- which is exactly what happened the first time
# this was installed.
Environment=PYTHONPATH={lib_dir}
Environment=VIGIL_LIB={lib_dir}
{exec_lines}
{restart_lines}
User=root
Group=root
{resource_lines}
StateDirectory={state_dir}
RuntimeDirectory={runtime_dir}
StateDirectoryMode=0750
RuntimeDirectoryMode=0750
StandardOutput=journal
StandardError=journal
SyslogIdentifier={syslog_id}
{hardening}
[Install]
WantedBy=multi-user.target
"""

UNIT_TEMPLATE_TIMER = """[Unit]
Description={description}

[Timer]
OnBootSec={on_boot}
OnUnitActiveSec={interval}
AccuracySec={accuracy}
{persistent}
Unit={unit}

[Install]
WantedBy=timers.target
"""

#: Baseline hardening. These are all safe for our daemons because they only
#: ever run as root against the local system with no need for a writable
#: home, a setuid helper, or kernel-module loading.
HARDENING = """NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=no
ProtectKernelTunables=no
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
"""


def python_bin() -> str:
    return shutil.which("python3") or "/usr/bin/python3"


def module_entry(module: str) -> str:
    """Command that runs ``vigil.<module>`` as a program."""
    return "%s -m vigil.%s" % (python_bin(), module)


def service(name: str, description: str, exec_lines, stype: str = "simple",
            restart: str = "always", restart_sec: int = 5,
            state_dir: str = "", runtime_dir: str = "", nice: int = 0,
            after_extra: str = "", memory_max: str = "",
            cpu_quota: str = "", io_weight: str = "",
            memory_min: str = "48M", alerting: bool = True,
            oom_score: int = 0,
            hardening: bool = True, unit_extra: str = "") -> str:
    """Render one service unit.

    ``alerting`` marks a unit that is part of the notification path, and it
    gets three guarantees that ordinary work does not:

    * ``MemoryMin`` -- a real cgroup-v2 reservation. Under memory pressure the
      kernel reclaims from everything else first, so the component that tells
      you what is happening cannot be the one that dies and takes the news
      with it.
    * ``IOSchedulingClass``/``IOSchedulingPriority`` -- the alert is written
      and delivered promptly even while a bulk job saturates the disk.
    * a positive ``OOMScoreAdjust`` would be wrong here; leaving it at 0 while
      batch work runs with a high score means the batch is the victim.

    This is not theoretical: a stress test on this host put the machine at
    full CPU and 92% IO-wait, and the question that mattered was whether an
    alert could still get out. These settings are the answer that does not
    depend on luck.
    """
    restart_lines = ""
    if restart and stype != "oneshot":
        restart_lines = ("Restart=%s\nRestartSec=%d\n"
                         "StartLimitIntervalSec=0\n" % (restart, restart_sec))
    res = []
    if nice:
        res.append("Nice=%d" % nice)
    if alerting:
        if memory_min:
            res.append("MemoryMin=%s" % memory_min)
        res.append("IOSchedulingClass=best-effort")
        res.append("IOSchedulingPriority=2")
    if oom_score:
        # Must be in [Service]. `unit_extra` lands in [Unit], where systemd
        # ignores it without complaint -- which is exactly how a "protect the
        # batch job from being the victim" setting silently does nothing.
        res.append("OOMScoreAdjust=%d" % oom_score)
    if cpu_quota:
        res.append("CPUQuota=%s" % cpu_quota)
    if io_weight:
        res.append("IOWeight=%s" % io_weight)
    if memory_max:
        res.append("MemoryMax=%s" % memory_max)
        res.append("MemoryHigh=%s" % memory_max)
    return UNIT_TEMPLATE_SERVICE.format(
        lib_dir=str(paths.LIB),
        description=description,
        after_extra=("\nAfter=" + after_extra) if after_extra else "",
        unit_extra=unit_extra,
        stype=stype,
        exec_lines=exec_lines.rstrip(),
        restart_lines=restart_lines,
        resource_lines=("\n".join(res) + "\n") if res else "",
        state_dir=state_dir or "vigil",
        runtime_dir=runtime_dir or "vigil",
        syslog_id=name,
        hardening=HARDENING if hardening else "",
    )


def timer(name: str, description: str, unit: str, interval: str,
          on_boot: str = "1min", accuracy: str = "10s",
          persistent: bool = True) -> str:
    return UNIT_TEMPLATE_TIMER.format(
        description=description,
        on_boot=on_boot,
        interval=interval,
        accuracy=accuracy,
        persistent="Persistent=true\n" if persistent else "",
        unit=unit,
    )


def unit_path(name: str) -> Path:
    return paths.SYSTEMD_UNIT_DIR / ("%s%s" % (paths.UNIT_PREFIX, name))


def write_unit(name: str, content: str) -> Path:
    target = unit_path(name)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    os.chmod(target, 0o644)
    return target


def render_all(cfg, features) -> dict:
    """Build every unit this installation needs.

    *features* is a set of enabled component names so a minimal install
    does not ship timers for subsystems the operator turned off.
    """
    units = {}
    state = "vigil"
    run = "vigil"

    if "threat" in features:
        units["threatd.service"] = service(
            "vigil-threatd", "Vigil real-time threat detection and auto-ban",
            "ExecStart=%s" % module_entry("guards.threat"),
            stype="simple", restart="always", restart_sec=5,
            state_dir=state, runtime_dir=run, nice=-5,
            after_extra="fail2ban.service",
        )

        # Learning runs on a timer, not only when asked. "Generate new
        # signatures from real observations" is only true if it happens
        # without somebody remembering to type a command -- a self-improvement
        # pass that never runs is a feature that exists in the documentation
        # and nowhere else.
        units["learn.service"] = service(
            "vigil-learn", "Vigil signature learning from observed traffic",
            "ExecStart=%s" % module_entry("guards.learning"),
            stype="oneshot", nice=15, state_dir=state, runtime_dir=run,
            # Bulk work: it reads a large observation file and a corpus of
            # legitimate paths. It is not part of the alerting path, so it
            # yields to everything that is.
            alerting=False, oom_score=300)
        units["learn.timer"] = timer(
            "learn.timer", "Mine new decoy candidates from observed probes",
            "vigil-learn.service", interval="1h", on_boot="8min",
            accuracy="5min")

    if "loadshed" in features:
        units["loadshed.service"] = service(
            "vigil-loadshed", "Vigil load shedding under attack",
            "ExecStart=%s" % module_entry("guards.loadshed"),
            stype="simple", restart="always", restart_sec=10,
            state_dir=state, runtime_dir=run, nice=-5,
            after_extra="vigil-threatd.service",
        )

    if "health" in features:
        units["health.service"] = service(
            "vigil-healthd", "Vigil periodic health and security inspection",
            "ExecStart=/usr/bin/flock -n %s %s"
            % (paths.LOCK_HEALTH, module_entry("guards.health")),
            stype="oneshot", nice=10, state_dir=state, runtime_dir=run,
        )
        units["health.timer"] = timer(
            "health.timer", "Run the Vigil inspection every few minutes",
            "vigil-health.service",
            interval="%ds" % int(cfg.get("checks.interval", 120) or 120),
            on_boot="2min", accuracy="15s")

        # Backups run on a timer too.
        #
        # `backup_age` has always been able to shout that the newest archive
        # is stale -- and nothing ever made one, so on this host it sat at
        # CRIT ("最近备份已过期 3.3 天") for three days. A check that reports a
        # problem nobody is scheduled to fix is a check that trains the
        # operator to ignore it. The rule elsewhere in this program is that
        # anything it can do safely it does; making a backup is safe.
        units["backup.service"] = service(
            "vigil-backup", "Vigil configuration and credential backup",
            "ExecStart=/usr/bin/flock -n %s %s backup"
            % (paths.LOCK_BACKUP, paths.BIN),
            stype="oneshot", nice=15, alerting=False, oom_score=300,
            state_dir=state, runtime_dir=run)
        units["backup.timer"] = timer(
            "backup.timer", "Take a Vigil backup every day",
            "vigil-backup.service",
            interval="%dh" % int(cfg.get("backup.interval_hours", 24) or 24),
            on_boot="10min", accuracy="10min")

    if "login" in features:
        units["logind.service"] = service(
            "vigil-logind", "Vigil login notification",
            "ExecStart=/usr/bin/flock -n /run/vigil-logind.lock %s"
            % module_entry("guards.logind"),
            stype="oneshot", nice=10, state_dir=state, runtime_dir=run)
        units["logind.timer"] = timer(
            "logind.timer", "Check for new panel/gate logins",
            "vigil-logind.service", interval="30s", on_boot="2min",
            accuracy="5s")

    if "mail" in features:
        units["maild.service"] = service(
            "vigil-maild", "Vigil mail backlog replay and command channel",
            "ExecStart=/usr/bin/flock -n /run/vigil-maild.lock %s"
            % module_entry("mail.commandd"),
            stype="oneshot", nice=10, state_dir=state, runtime_dir=run)
        units["maild.timer"] = timer(
            "maild.timer", "Replay parked alerts and poll for reply commands",
            "vigil-maild.service", interval="120s", on_boot="3min",
            accuracy="20s")

    if cfg.get("bouncer.enabled", False):
        # Only rendered when the operator has opted in. The sync is a timer,
        # not a step in the daemon's hot path: ipset already enforces
        # instantly, and a second mechanism on the critical path would be a
        # second thing that can fail during an attack.
        units["bouncer.service"] = service(
            "vigil-bouncer", "Vigil web-layer ban enforcement",
            "ExecStart=%s" % module_entry("guards.bouncer"),
            stype="oneshot", nice=15, state_dir=state, runtime_dir=run)
        units["bouncer.timer"] = timer(
            "bouncer.timer", "Keep the nginx deny list in step with bans",
            "vigil-bouncer.service",
            interval="%ds" % int(cfg.get("bouncer.sync_seconds", 60) or 60),
            on_boot="2min", accuracy="10s")

    if "av" in features:
        units["avscan.service"] = service(
            "vigil-avscan", "Vigil malware scan",
            "ExecStart=%s" % module_entry("guards.avscan"),
            stype="oneshot", nice=18, state_dir=state, runtime_dir=run,
            cpu_quota="40%", io_weight="20", memory_max="700M",
            # Bulk work, explicitly not part of the alerting path: it is the
            # first thing that should be squeezed, and the first thing the
            # OOM killer should take. A scan that walks the whole disk must
            # never be the reason a notification fails to go out.
            alerting=False, oom_score=500)
        units["avscan.timer"] = timer(
            "vigil-avscan.timer", "Periodic malware scan",
            "vigil-avscan.service",
            interval="%dh" % int(cfg.get("malware.scan_interval_hours", 24) or 24),
            on_boot="10min", accuracy="5min")

    # -- 自修正进程：占系统资源的一个固定小比例 ---------------------------
    # 资源上限全部按「可用量的百分比」的思路给：CPU 配额 5%（即最多半个核），
    # 内存上限按宿主机可用内存的一小部分，IO 权重最低，nice 19。它做的是
    # 可选工作，任何时候都不该和真正对外服务的进程抢资源。
    if "evolve" in features:
        units["evolve.service"] = service(
            "vigil-evolve.service",
            "Self-improvement loop (bounded, evidence-gated, reversible)",
            ["%s -m vigil.cli evolve loop" % python_bin()],
            stype="oneshot",
            restart="no",
            nice=19, cpu_quota="5%", io_weight="10", memory_max="256M",
            # 明确不属于告警链路：出问题时它应该是第一个被压缩的，
            # 也是最该被 OOM 杀掉的，绝不能因为它而让通知发不出去。
            alerting=False, oom_score=800,
            unit_extra="CPUWeight=10\nIOAccounting=yes\nMemoryAccounting=yes")
        units["evolve.timer"] = timer(
            "vigil-evolve.timer", "Periodic self-improvement pass",
            "vigil-evolve.service",
            interval="%dh" % int(cfg.get("evolve.interval_hours", 6) or 6),
            on_boot="20min", accuracy="10min")

    # -- 监控进程：守着自修正循环本身 --------------------------------------
    # 一个能改自己行为的组件，必须有人看着它。这个进程只做一件事：
    # 确认自修正循环还活着、没跑飞、台账没异常增长、资源没超限。
    if "watchdog" in features:
        units["watchdog.service"] = service(
            "vigil-watchdog.service",
            "Watchdog for the self-improvement loop",
            ["%s -m vigil.cli evolve watchdog" % python_bin()],
            stype="simple", restart="always", restart_sec=30,
            nice=10, cpu_quota="3%", io_weight="10", memory_max="128M",
            alerting=True, oom_score=100)

    return units


def install_units(units: dict, start: bool = True, log=None) -> list:
    """Write units, reload systemd, enable and start them."""
    written = []
    for name, content in units.items():
        written.append(write_unit(name, content))
    shell.systemd_reload()

    enabled = []
    for name in units:
        unit = "%s%s" % (paths.UNIT_PREFIX, name)
        ok, _o, e = shell.run(["systemctl", "enable", unit], timeout=30)
        if not ok:
            if log:
                log.warn("启用 %s 失败: %s" % (unit, e.strip()[:200]))
            continue
        enabled.append(unit)

    if start:
        for unit in enabled:
            ok, _o, e = shell.run(["systemctl", "restart", unit], timeout=60)
            if not ok and log:
                log.warn("启动 %s 失败: %s" % (unit, e.strip()[:200]))
    return enabled


def ensure_timers_running(log=None) -> list:
    """Start every enabled vigil timer that is not currently active.

    `systemctl enable` writes a symlink; it does not start anything, and a
    timer installed after boot stays dead until the next reboot. That is how
    `vigil-learn.timer` was enabled and yet never ran: `update` refreshed the
    units with `start=False` and then restarted only the named *services*, so
    every timer added by an upgrade quietly did nothing.

    A timer is a promise that something will happen later. An enabled timer
    that is not active has broken that promise, so this starts it and then
    checks that it actually came up rather than trusting the exit code.
    """
    started, failed = [], []
    try:
        # `p.name`, not `p.stem`: stem strips the ".timer" suffix, and
        # `systemctl is-enabled vigil-learn` then asks about a *service* that
        # does not exist, answers "not-found", and every timer is skipped in
        # silence. The whole point of this function is defeated by one
        # missing suffix.
        names = sorted(p.name for p in
                       paths.SYSTEMD_UNIT_DIR.glob("%s*.timer"
                                                   % paths.UNIT_PREFIX))
    except OSError:
        return started
    for name in names:
        if shell.out(["systemctl", "is-enabled", name]) != "enabled":
            continue
        if shell.out(["systemctl", "is-active", name]) == "active":
            continue
        ok, _o, e = shell.run(["systemctl", "start", name], timeout=60)
        # `start` on an already-satisfied timer can report success and leave
        # it dead, so ask the only question that matters: is it running now?
        if ok and shell.out(["systemctl", "is-active", name]) == "active":
            started.append(name)
        else:
            failed.append("%s(%s)" % (name, e.strip()[:120] or "未激活"))
    if failed and log:
        log.warn("以下定时器已启用但未能启动：%s" % "、".join(failed))
    return started


def remove_units(prefix: str = "", log=None) -> list:
    """Stop, disable and delete every unit we own."""
    prefix = prefix or paths.UNIT_PREFIX
    removed = []
    try:
        entries = sorted(paths.SYSTEMD_UNIT_DIR.glob("%s*" % prefix))
    except OSError:
        entries = []
    for path in entries:
        unit = path.name
        shell.run(["systemctl", "stop", unit], timeout=30)
        shell.run(["systemctl", "disable", unit], timeout=30)
        try:
            path.unlink()
            removed.append(unit)
        except OSError:
            pass
    # Drop-in directories too.
    for d in paths.SYSTEMD_UNIT_DIR.glob("%s*.d" % prefix):
        if d.is_dir():
            shutil.rmtree(str(d), ignore_errors=True)
    shell.systemd_reload()
    return removed


def list_units() -> list:
    """(unit, active, enabled) for everything we manage."""
    out = []
    try:
        entries = sorted(paths.SYSTEMD_UNIT_DIR.glob("%s*" % paths.UNIT_PREFIX))
    except OSError:
        return out
    for path in entries:
        if path.suffix not in (".service", ".timer"):
            continue
        unit = path.name
        out.append((unit,
                    shell.out(["systemctl", "is-active", unit]) or "unknown",
                    shell.out(["systemctl", "is-enabled", unit]) or "unknown"))
    return out
