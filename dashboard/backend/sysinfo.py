"""Host resource sampling from /proc and /sys, no third-party modules.

The panel's home page shows CPU, memory and disk; this is the same idea done
from first principles so the console keeps reporting while the machine is in
trouble. Every reader is defensive: a container host can be missing any of
these files, and a missing file must degrade one tile, not the page.
"""
from __future__ import annotations

import os
import time

# --------------------------------------------------------------------------
# CPU
# --------------------------------------------------------------------------


def _read_cpu_times() -> dict:
    out = {}
    try:
        with open("/proc/stat", "r", encoding="utf-8") as fh:
            for line in fh:
                if not line.startswith("cpu"):
                    break
                parts = line.split()
                name = parts[0]
                vals = [int(x) for x in parts[1:11]]
                while len(vals) < 10:
                    vals.append(0)
                idle = vals[3] + vals[4]                    # idle + iowait
                total = sum(vals)
                out[name] = {"total": total, "idle": idle}
    except (OSError, ValueError):
        pass
    return out


def cpu_usage(prev: dict, cur: dict) -> dict:
    """Delta between two ``_read_cpu_times`` snapshots, as percentages."""
    out = {}
    for name, c in cur.items():
        p = prev.get(name)
        if not p:
            continue
        dt = c["total"] - p["total"]
        di = c["idle"] - p["idle"]
        if dt <= 0:
            continue
        pct = max(0.0, min(100.0, (dt - di) * 100.0 / dt))
        out[name] = round(pct, 1)
    return out


def load_average() -> dict:
    try:
        a, b, c = os.getloadavg()
    except OSError:
        return {"1": 0.0, "5": 0.0, "15": 0.0}
    return {"1": round(a, 2), "5": round(b, 2), "15": round(c, 2)}


def cpu_info() -> dict:
    model = ""
    mhz = 0.0
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("model name") and not model:
                    model = line.split(":", 1)[1].strip()
                elif line.startswith("cpu MHz"):
                    try:
                        mhz = max(mhz, float(line.split(":", 1)[1].strip()))
                    except ValueError:
                        pass
                elif line.strip() == "" and model:
                    break
    except OSError:
        pass
    return {"model": model or _cpu_model_arm(), "mhz": round(mhz),
            "cores": os.cpu_count() or 1}


def _cpu_model_arm() -> str:
    try:
        with open("/proc/device-tree/model", "rb") as fh:
            return fh.read().decode("utf-8", "replace").strip("\x00").strip()
    except OSError:
        return ""


def cpu_temperature() -> float:
    """Package temperature in Celsius, or 0 when the host exposes none."""
    try:
        base = "/sys/class/thermal"
        for name in sorted(os.listdir(base)):
            if not name.startswith("thermal_zone"):
                continue
            try:
                with open(os.path.join(base, name, "temp"), "r") as fh:
                    milli = float(fh.read().strip())
            except (OSError, ValueError):
                continue
            if milli > 1000:
                milli /= 1000.0
            if 0 < milli < 130:
                return round(milli, 1)
    except OSError:
        pass
    for path in ("/sys/class/hwmon/hwmon0/temp1_input",):
        try:
            with open(path, "r") as fh:
                milli = float(fh.read().strip())
            if milli > 1000:
                milli /= 1000.0
            if 0 < milli < 130:
                return round(milli, 1)
        except (OSError, ValueError):
            continue
    return 0.0


# --------------------------------------------------------------------------
# Memory
# --------------------------------------------------------------------------


def memory() -> dict:
    raw = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                key, _, rest = line.partition(":")
                raw[key.strip()] = rest.strip()
    except OSError:
        return {}

    def kb(key: str) -> int:
        val = raw.get(key, "0 kB").split()[0]
        try:
            return int(val) * 1024
        except ValueError:
            return 0

    total = kb("MemTotal")
    free = kb("MemFree")
    buffers = kb("Buffers")
    cached = kb("Cached") + kb("SReclaimable") - kb("Shmem")
    available = kb("MemAvailable") or (free + buffers + max(0, cached))
    used = max(0, total - available)
    swap_total = kb("SwapTotal")
    swap_free = kb("SwapFree")
    return {
        "total": total, "free": free, "available": available,
        "used": used, "buffers": buffers, "cached": max(0, cached),
        "percent": round(used * 100.0 / total, 1) if total else 0.0,
        "swap_total": swap_total, "swap_free": swap_free,
        "swap_used": max(0, swap_total - swap_free),
        "swap_percent": (round((swap_total - swap_free) * 100.0 / swap_total, 1)
                         if swap_total else 0.0),
    }


# --------------------------------------------------------------------------
# Disk
# --------------------------------------------------------------------------

_SKIP_FS = {
    "tmpfs", "devtmpfs", "squashfs", "overlay", "proc", "sysfs", "cgroup",
    "cgroup2", "devpts", "securityfs", "debugfs", "tracefs", "pstore",
    "bpf", "autofs", "mqueue", "hugetlbfs", "fusectl", "configfs", "ramfs",
    "binfmt_misc", "nsfs", "efivarfs", "rpc_pipefs",
}
_SKIP_MNT = ("/run/", "/sys/", "/proc/", "/dev/", "/snap/", "/var/lib/docker/",
             "/var/lib/kubelet/", "/boot/efi", "/var/snap/")


def mounts() -> list:
    out = []
    try:
        with open("/proc/mounts", "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return out
    seen = set()
    for line in lines:
        parts = line.split()
        if len(parts) < 3:
            continue
        dev, mnt, fstype = parts[0], parts[1], parts[2]
        if fstype in _SKIP_FS:
            continue
        if any(mnt.startswith(pre) for pre in _SKIP_MNT):
            continue
        if mnt != "/" and mnt.count("/") > 1:
            # Keep the root and first-level mounts; deeper ones are usually
            # bind mounts of the same filesystem.
            if dev in seen:
                continue
        if dev in seen:
            continue
        seen.add(dev)
        try:
            st = os.statvfs(mnt)
        except OSError:
            continue
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        if total <= 0:
            continue
        used = total - free
        out.append({
            "mount": mnt, "device": dev, "fstype": fstype,
            "total": total, "used": used, "free": free,
            "percent": round(used * 100.0 / total, 1),
        })
    out.sort(key=lambda d: (d["mount"] != "/", -d["total"]))
    return out


def disk_io() -> dict:
    """Cumulative sectors/blocks per physical device (used for deltas)."""
    out = {}
    try:
        with open("/proc/diskstats", "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 14:
                    continue
                name = parts[2]
                # Only whole disks: sda, vda, nvme0n1, xvda, mmcblk0.
                if name[-1].isdigit() and not name.startswith(("nvme", "mmcblk")):
                    continue
                try:
                    out[name] = {
                        "read_bytes": int(parts[5]) * 512,
                        "write_bytes": int(parts[9]) * 512,
                    }
                except (IndexError, ValueError):
                    continue
    except OSError:
        pass
    return out


def net_counters() -> dict:
    out = {}
    try:
        with open("/proc/net/dev", "r", encoding="utf-8") as fh:
            for line in fh:
                if ":" not in line:
                    continue
                name, _, rest = line.partition(":")
                name = name.strip()
                if name == "lo" or name.startswith(("veth", "docker", "br-", "virbr")):
                    continue
                cols = rest.split()
                try:
                    out[name] = {"rx": int(cols[0]), "tx": int(cols[8])}
                except (IndexError, ValueError):
                    continue
    except OSError:
        pass
    return out


# --------------------------------------------------------------------------
# Processes
# --------------------------------------------------------------------------


def sample_processes(prev: dict, prev_wall: float, wall: float, limit: int) -> tuple:
    """Returns ``(rows, new_ticks)`` so callers can chain snapshots."""
    ticks = {}
    try:
        names = [n for n in os.listdir("/proc") if n.isdigit()]
    except OSError:
        return [], {}
    for pid in names:
        try:
            with open("/proc/%s/stat" % pid, "r", encoding="utf-8",
                      errors="replace") as fh:
                stat = fh.read()
        except OSError:
            continue
        rp = stat.rfind(")")
        if rp < 0:
            continue
        fields = stat[rp + 2:].split()
        try:
            ticks[pid] = int(fields[11]) + int(fields[12])
        except (IndexError, ValueError):
            continue

    rows = []
    hz = os.sysconf("SC_CLK_TCK") or 100
    if prev and wall > prev_wall:
        for pid, t in ticks.items():
            p = prev.get(pid)
            if p is None:
                continue
            try:
                with open("/proc/%s/stat" % pid, "r", encoding="utf-8",
                          errors="replace") as fh:
                    stat = fh.read()
                comm = stat[stat.find("(") + 1:stat.rfind(")")]
            except OSError:
                continue
            cpu = (t - p) / hz * 100.0 / (wall - prev_wall)
            rows.append({"pid": int(pid), "name": comm[:40], "cpu": round(cpu, 1)})
        rows.sort(key=lambda r: r["cpu"], reverse=True)
        rows = rows[:limit]
    return rows, ticks


def top_memory(limit: int = 8) -> list:
    rows = []
    try:
        names = [n for n in os.listdir("/proc") if n.isdigit()]
    except OSError:
        return rows
    for pid in names:
        info = {}
        try:
            with open("/proc/%s/status" % pid, "r", encoding="utf-8",
                      errors="replace") as fh:
                for line in fh:
                    if line.startswith(("Name:", "VmRSS:", "Uid:")):
                        key, _, val = line.partition(":")
                        info[key] = val.strip()
                    if len(info) >= 3:
                        break
        except OSError:
            continue
        try:
            rss = int(info.get("VmRSS", "0 kB").split()[0]) * 1024
        except (ValueError, IndexError):
            continue
        if rss <= 0:
            continue
        rows.append({"pid": int(pid), "name": info.get("Name", "?")[:40],
                     "rss": rss})
    rows.sort(key=lambda r: r["rss"], reverse=True)
    return rows[:limit]


def uptime() -> dict:
    try:
        with open("/proc/uptime", "r") as fh:
            secs = float(fh.read().split()[0])
    except (OSError, ValueError):
        return {"seconds": 0, "text": ""}
    days, rem = divmod(int(secs), 86400)
    hours, rem = divmod(rem, 3600)
    mins = rem // 60
    text = ("%d 天 %d 小时 %d 分" % (days, hours, mins) if days
            else "%d 小时 %d 分" % (hours, mins))
    return {"seconds": int(secs), "text": text}


def system_info() -> dict:
    """Facts about the machine, minus its identity.

    The console is a public page. The model, core count and disk figures are
    the point of the resource panel; the node name is not, so it is left out
    here rather than filtered at the edge -- a field that is never collected
    cannot leak through some later code path.
    """
    info = {"kernel": os.uname().release}
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("PRETTY_NAME="):
                    info["os"] = line.split("=", 1)[1].strip().strip('"')
                    break
    except OSError:
        pass
    total, used, _free = (0, 0, 0)
    try:
        st = os.statvfs("/")
        total = st.f_blocks * st.f_frsize
        used = (st.f_blocks - st.f_bfree) * st.f_frsize
    except OSError:
        pass
    info["disk_total"] = total
    info["disk_used"] = used
    return info


def disk_health() -> list:
    """SMART-ish summary: what the kernel says about each block device."""
    out = []
    try:
        base = "/sys/block"
        for name in sorted(os.listdir(base)):
            if name.startswith(("loop", "ram", "dm-", "sr")):
                continue
            entry = {"name": name}
            for attr, dest in (("size", "sectors"), ("rotational", "rotational")):
                try:
                    with open(os.path.join(base, name, attr), "r") as fh:
                        entry[dest] = int(fh.read().strip())
                except (OSError, ValueError):
                    pass
            out.append(entry)
    except OSError:
        pass
    return out
