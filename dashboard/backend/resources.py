"""The resource sampler behind the home page tiles.

A background thread takes a reading every couple of seconds and keeps a
short history for the sparklines. The web layer only ever reads the last
sample, so a slow /proc or a hung disk can never block a request.
"""
from __future__ import annotations

import collections
import shutil
import threading
import time

from . import settings, sysinfo


class Sampler:
    def __init__(self, interval: float = 2.0, history: int = 120) -> None:
        self._interval = max(0.5, float(interval))
        self._history = collections.deque(maxlen=max(16, int(history)))
        self._lock = threading.RLock()
        self._thread = None
        self._stop = threading.Event()
        self._latest: dict = {}
        self._prev_cpu: dict = {}
        self._prev_io: dict = {}
        self._prev_net: dict = {}
        self._prev_ticks: dict = {}
        self._prev_wall = 0.0
        self._boot = os_uptime_seconds()
        self._errors = 0

    # -- collection ------------------------------------------------------

    def sample(self) -> dict:
        wall = time.time()
        cur_cpu = sysinfo._read_cpu_times()
        usage = sysinfo.cpu_usage(self._prev_cpu, cur_cpu) if self._prev_cpu else {}
        self._prev_cpu = cur_cpu

        io_now = sysinfo.disk_io()
        net_now = sysinfo.net_counters()
        dt = wall - self._prev_wall if self._prev_wall else 0.0
        io_rate = {}
        net_rate = {}
        if dt > 0.2:
            for dev, cur in io_now.items():
                prev = self._prev_io.get(dev)
                if prev:
                    io_rate[dev] = {
                        "read": max(0, int((cur["read_bytes"] - prev["read_bytes"]) / dt)),
                        "write": max(0, int((cur["write_bytes"] - prev["write_bytes"]) / dt)),
                    }
            for dev, cur in net_now.items():
                prev = self._prev_net.get(dev)
                if prev:
                    net_rate[dev] = {
                        "rx": max(0, int((cur["rx"] - prev["rx"]) / dt)),
                        "tx": max(0, int((cur["tx"] - prev["tx"]) / dt)),
                    }
            procs, ticks = sysinfo.sample_processes(
                self._prev_ticks, self._prev_wall, wall,
                int(settings.settings.processes))
            self._prev_ticks = ticks
        else:
            procs = []
        self._prev_io = io_now
        self._prev_net = net_now
        self._prev_wall = wall

        cpu_total = usage.get("cpu")
        if cpu_total is None:
            cores = [v for k, v in usage.items() if k != "cpu"]
            cpu_total = round(sum(cores) / len(cores), 1) if cores else 0.0

        mounts = sysinfo.mounts()
        mem = sysinfo.memory()
        sample = {
            "t": round(wall, 3),
            "cpu": {
                "percent": cpu_total,
                "per_core": [usage.get("cpu%d" % i, 0.0)
                             for i in range(max(1, (len(usage) - 1) or 2))],
                "info": sysinfo.cpu_info(),
                "load": sysinfo.load_average(),
                "temp": sysinfo.cpu_temperature(),
            },
            "memory": mem,
            "disk": {
                "mounts": mounts,
                "io": io_rate,
                "health": sysinfo.disk_health(),
            },
            "net": net_rate,
            "processes": procs,
            "top_memory": sysinfo.top_memory(int(settings.settings.processes)),
            "uptime": sysinfo.uptime(),
            "system": sysinfo.system_info(),
        }
        return sample

    # -- loop ------------------------------------------------------------

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                sample = self.sample()
                with self._lock:
                    self._latest = sample
                    self._history.append({
                        "t": sample["t"],
                        "cpu": sample["cpu"]["percent"],
                        "mem": sample["memory"].get("percent", 0.0),
                        "disk": (sample["disk"]["mounts"][0]["percent"]
                                 if sample["disk"]["mounts"] else 0.0),
                        "rx": sum(v["rx"] for v in sample["net"].values()),
                        "tx": sum(v["tx"] for v in sample["net"].values()),
                    })
            except Exception:                       # noqa: BLE001
                self._errors += 1
            self._stop.wait(self._interval)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self.run, name="sampler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    # -- read ------------------------------------------------------------

    def latest(self) -> dict:
        with self._lock:
            return dict(self._latest) if self._latest else {}

    def series(self, limit: int = 0) -> list:
        with self._lock:
            items = list(self._history)
        return items[-limit:] if limit else items

    def snapshot(self) -> dict:
        out = self.latest()
        out["series"] = self.series(int(settings.settings.cpu_history))
        out["sampler"] = {"errors": self._errors,
                          "interval": self._interval}
        return out


def os_uptime_seconds() -> float:
    try:
        with open("/proc/uptime", "r") as fh:
            return float(fh.read().split()[0])
    except (OSError, ValueError):
        return 0.0


sampler = Sampler(interval=settings.settings.sample_interval,
                  history=settings.settings.cpu_history)
