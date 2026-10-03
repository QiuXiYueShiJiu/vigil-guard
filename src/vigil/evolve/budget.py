"""Resource governor: the evolve loop may only ever use a slice of what is free.

Why a governor and not a `nice` value: this process is optional. Everything it
does -- re-reading logs, scoring paths, drafting a patch -- is work the machine
can live without, while the thing it shares the box with (a web server, a
database) cannot. So the cap is not "how much may it use" but "how little must
be left before it stops": it computes a budget from *free* resources, and
refuses to start when free memory, load or disk headroom says the host is
already busy.

Nothing here is measured in absolute gigabytes on purpose -- a fixed "use up to
200 MB" is wrong on both a 1 GB VPS and a 64 GB host. Percentages travel.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

#: Share of *free* memory the loop may work with. Deliberately small: the
#: failure mode we are avoiding is not "the evolve loop was slow", it is
#: "the evolve loop triggered the OOM killer on a shared box".
DEFAULT_MEMORY_PCT = 5.0

#: Never start below this much free memory, whatever the percentage says.
DEFAULT_MEMORY_FLOOR_MB = 96.0

#: Refuse to run when 1-minute load exceeds cores * this.
DEFAULT_LOAD_RATIO = 0.7

#: Hard wall-clock ceiling for one evolve pass, in seconds.
DEFAULT_TIME_BUDGET = 120.0


def _meminfo() -> dict:
    out = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, _, rest = line.partition(":")
            parts = rest.split()
            if parts:
                out[key.strip()] = int(parts[0])          # kB
    except (OSError, ValueError):
        pass
    return out


def free_mb() -> float:
    """MemAvailable in MB, or 0.0 when it cannot be read.

    `MemAvailable` (not `MemFree`) is the right input: page cache is free in
    every sense that matters here, and treating it as used would make the loop
    refuse to run on a healthy host.
    """
    info = _meminfo()
    kb = info.get("MemAvailable") or info.get("MemFree") or 0
    return round(kb / 1024.0, 1)


def cpu_count() -> int:
    try:
        return max(1, len(os.sched_getaffinity(0)))
    except (AttributeError, OSError):
        return max(1, os.cpu_count() or 1)


def load1() -> float:
    try:
        return float(Path("/proc/loadavg").read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return 0.0


def disk_free_mb(path=None) -> float:
    target = str(path or "/var/lib/vigil")
    while target and not os.path.exists(target):
        target = os.path.dirname(target)
    try:
        st = os.statvfs(target or "/")
        return round(st.f_bavail * st.f_frsize / (1024.0 * 1024.0), 1)
    except OSError:
        return 0.0


class Budget:
    """The governor. One instance per pass."""

    def __init__(self, cfg=None):
        self.memory_pct = self._num(cfg, "evolve.memory_pct", DEFAULT_MEMORY_PCT)
        self.memory_floor = self._num(cfg, "evolve.memory_floor_mb",
                                      DEFAULT_MEMORY_FLOOR_MB)
        self.load_ratio = self._num(cfg, "evolve.load_ratio", DEFAULT_LOAD_RATIO)
        self.time_budget = self._num(cfg, "evolve.time_budget", DEFAULT_TIME_BUDGET)
        self.started = time.time()

    @staticmethod
    def _num(cfg, key, default):
        try:
            return float(cfg.get(key, default)) if cfg is not None else float(default)
        except (TypeError, ValueError):
            return float(default)

    # -- decisions --------------------------------------------------------

    def slice_mb(self) -> float:
        """How much memory this pass may work with, from what is free now."""
        return round(free_mb() * self.memory_pct / 100.0, 2)

    def may_start(self) -> tuple:
        """(ok, reason). Cheap, non-raising, safe to call in a loop."""
        free = free_mb()
        if free and free < self.memory_floor:
            return False, "可用内存 %.0f MB 低于下限 %.0f MB" % (free, self.memory_floor)
        if free and self.slice_mb() < 8:
            return False, "本次预算只有 %.1f MB，不值得开工" % self.slice_mb()
        load = load1()
        ceiling = cpu_count() * self.load_ratio
        if load > ceiling:
            return False, "1 分钟负载 %.2f 超过上限 %.2f（%d 核 × %.1f）" % (
                load, ceiling, cpu_count(), self.load_ratio)
        if disk_free_mb() and disk_free_mb() < 200:
            return False, "磁盘可用空间不足 200 MB"
        return True, "ok"

    def expired(self) -> bool:
        return (time.time() - self.started) > self.time_budget

    def remaining(self) -> float:
        return max(0.0, self.time_budget - (time.time() - self.started))

    def describe(self) -> dict:
        return {
            "free_mb": free_mb(),
            "slice_mb": self.slice_mb(),
            "memory_pct": self.memory_pct,
            "memory_floor_mb": self.memory_floor,
            "load1": load1(),
            "cores": cpu_count(),
            "load_ratio": self.load_ratio,
            "disk_free_mb": disk_free_mb(),
            "time_budget": self.time_budget,
        }

    def format(self) -> str:
        d = self.describe()
        return ("资源预算  取可用内存的 %.1f%%（现为 %.1f MB，可用 %.0f MB）\n"
                "          负载上限 %.2f（当前 %.2f / %d 核）｜单次时限 %.0f 秒\n"
                "          磁盘可用 %.0f MB"
                % (d["memory_pct"], d["slice_mb"], d["free_mb"],
                   d["cores"] * d["load_ratio"], d["load1"], d["cores"],
                   d["time_budget"], d["disk_free_mb"]))
