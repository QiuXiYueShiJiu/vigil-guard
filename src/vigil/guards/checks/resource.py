"""Resource-pressure checks (group ``resource``).

Ported from the previous generation's ``c_cpu`` / ``c_mem`` / ``c_swap`` /
``c_disk`` / ``c_inode`` / ``c_io`` / ``c_conntrack``. The detection logic is
preserved; what changed is the plumbing:

* every threshold is read from the ``checks.*`` config schema, never baked in;
* sampling state goes through :meth:`CheckContext.snapshot`, so the runner
  persists it atomically and a crash never leaves a half-written baseline;
* a missing tool or a missing /proc file degrades to OK with an explanation
  instead of raising.

User-visible ``detail`` text is Chinese because it is rendered verbatim into
the alert mail; code and comments stay English.
"""
from __future__ import annotations

import os

from . import util
from .base import (CRIT, G_RESOURCE, OK, WARN, Check, CheckContext,
                   CheckResult, register)

#: Filesystems that carry no meaningful capacity for us (the shared helper
#: already drops most pseudo filesystems; these slip through it).
_SKIP_FS = frozenset({"devpts", "binfmt_misc", "nsfs", "mqueue", "hugetlbfs"})


def _meminfo() -> dict:
    """Parse /proc/meminfo into ``{key: kB}``. Empty dict when unreadable."""
    info: dict = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                key, sep, rest = line.partition(":")
                if not sep:
                    continue
                parts = rest.split()
                if parts:
                    try:
                        info[key.strip()] = int(parts[0])
                    except ValueError:
                        continue
    except OSError:
        return {}
    return info


def _proc_stat() -> list:
    """First line of /proc/stat as a list of ints (user, nice, system, ...)."""
    try:
        with open("/proc/stat", "r", encoding="utf-8") as fh:
            parts = fh.readline().split()[1:]
        return [int(x) for x in parts]
    except (OSError, ValueError, IndexError):
        return []


def _candidate_mounts(ctx) -> list:
    """Real mount points worth watching, plus any configured extra paths."""
    out: list = []
    seen: set = set()
    for _dev, mnt, fstype in util.mount_points():
        if fstype in _SKIP_FS or mnt.startswith(("/proc", "/sys", "/dev")):
            continue
        if mnt in seen:
            continue
        seen.add(mnt)
        out.append(mnt)
    for p in (ctx.copt("disk", "paths", ["/"]) or []):
        p = str(p)
        if p not in seen and os.path.isdir(p):
            seen.add(p)
            out.append(p)
    return out


def _load_note() -> str:
    try:
        l1, l5, _l15 = os.getloadavg()
        return "（%d 核，1 分钟负载 %.2f，5 分钟负载 %.2f）" % (
            os.cpu_count() or 1, l1, l5)
    except OSError:
        return ""


@register
class CpuUsage(Check):
    id = "cpu"
    label = "CPU 占用率"
    label_en = "CPU usage"
    group = G_RESOURCE
    stateful = True
    description = "两次采样 /proc/stat 计算 CPU 占用率，持续高于阈值才告警"

    def run(self, ctx: CheckContext) -> CheckResult:
        warn = float(ctx.copt("cpu", "warn", 85))
        crit = float(ctx.copt("cpu", "crit", 95))
        sustain = max(1, int(ctx.copt("cpu", "sustain", 3) or 1))

        busy, total = util.read_proc_stat()
        prev = ctx.snapshot("cpu_prev", [busy, total])
        if total <= 0:
            return CheckResult(OK, "无法读取 /proc/stat，跳过 CPU 检查")
        if not prev or len(prev) != 2:
            return CheckResult(OK, "CPU 采集中（首次运行，下一轮给出占用率）")

        db = busy - int(prev[0])
        dt = total - int(prev[1])
        if dt <= 0:
            return CheckResult(OK, "CPU 采样间隔为 0（进程刚重启？），本轮跳过")
        pct = db * 100.0 / dt

        high = pct >= warn
        streak = int(ctx.state.get("cpu_high_streak") or 0)
        streak = streak + 1 if high else 0
        ctx.snapshot("cpu_high_streak", streak)

        note = _load_note()
        top = util.top_procs("cpu", 3)
        top_note = ("\n     占用最高: " + "；".join(top)) if top else ""

        if high and streak >= sustain:
            status = CRIT if pct >= crit else WARN
            return CheckResult(status, "CPU 占用率过高：**%.1f%%**%s"
                               "\n     已连续 %d 次采样超过阈值 %.0f%%%s"
                               % (pct, note, streak, warn, top_note))
        if high:
            return CheckResult(OK, "CPU 占用 %.1f%%%s（已连续 %d/%d 次超过阈值 %.0f%%，"
                                   "达到后才会告警）%s"
                               % (pct, note, streak, sustain, warn, top_note))
        return CheckResult(OK, "CPU 占用 %.1f%%%s" % (pct, note))


@register
class MemoryUsage(Check):
    id = "memory"
    label = "内存"
    label_en = "Memory"
    group = G_RESOURCE
    description = "按 /proc/meminfo 的可用内存比例判断内存压力"

    def run(self, ctx) -> CheckResult:
        warn_pct = float(ctx.copt("memory", "warn_available_pct", 20))
        crit_pct = float(ctx.copt("memory", "crit_available_pct", 10))

        info = _meminfo()
        total = info.get("MemTotal", 0)
        if total <= 0:
            return CheckResult(OK, "无法读取 /proc/meminfo，跳过内存检查")
        avail = info.get("MemAvailable", info.get("MemFree", 0))
        pct = avail * 100.0 / total
        size = "（%.1f GB / %.1f GB 可用）" % (
            avail / 1024.0 / 1024.0, total / 1024.0 / 1024.0)

        # Both the ratio and an absolute floor, because the ratio alone is a
        # false alarm on a small host. A 2 GB machine running one build drops
        # below 20% available while being perfectly healthy; the same 20% on a
        # 64 GB machine is 12 GB free, which is not a problem either. So the
        # percentage says *how much of the machine is left*, the floor says
        # *whether that is still enough to work with*, and a finding needs
        # both. Crossing the floor is also not enough on its own: a machine
        # that is simply small reports low absolute numbers all day.
        warn_mb = _memory_floor_mb(
            ctx.copt("memory", "warn_available_mb", 0), total, 0.08)
        crit_mb = _memory_floor_mb(
            ctx.copt("memory", "crit_available_mb", 0), total, 0.03)
        avail_mb = avail / 1024.0
        # The ratio alone is a bad proxy in both directions, so three things
        # have to agree before a finding is raised:
        #
        #   1. the percentage is below the line. On a small host the line
        #      itself is relaxed (see `_scaled_pct`) because a 2 GB machine
        #      running one build drops below a fixed 20% while being healthy;
        #   2. there is less than the *scaled* absolute floor left. A 64 GB
        #      host with 300 MB free is minutes from the OOM killer; a 1.9 GB
        #      host at the same figure is survivable, so this line scales with
        #      the machine (`_memory_floor_mb`);
        #   3. there is less than a headroom cap -- a percentage of the total
        #      (`_mem_headroom_mb`). This is what stops a *large* host from
        #      being nagged at 17% when 17% is eleven gigabytes.
        #
        # An operator-set MB floor replaces 2 and 3 entirely: they told us the
        # number their workload needs, and second-guessing it would make the
        # key useless.
        warn_pct, _ = _scaled_pct(warn_pct, total, 20)
        crit_pct, _ = _scaled_pct(crit_pct, total, 10)
        head_mb = _mem_headroom_mb(total)
        warn_floor = _memory_floor_mb(
            ctx.copt("memory", "warn_available_mb", 0), total, 0.08)
        crit_floor = _memory_floor_mb(
            ctx.copt("memory", "crit_available_mb", 0), total, 0.03)
        if not float(ctx.copt("memory", "warn_available_mb", 0) or 0):
            warn_floor = max(warn_floor, head_mb)
            crit_floor = max(crit_floor, head_mb / 2.0)
        avail_mb = avail / 1024.0

        if pct <= crit_pct and avail_mb <= crit_floor:
            top = util.top_procs("mem", 3)
            return CheckResult(CRIT, "可用内存严重不足：仅 **%.1f%%**%s"
                               % (pct, size)
                               + (("\n     占用最高: " + "；".join(top)) if top else "")
                               + "\n     内存耗尽会触发 OOM Killer 随机杀进程，"
                                 "数据库或 Web 服务可能被强制终止。")
        elif pct <= warn_pct and avail_mb <= warn_floor:
            top = util.top_procs("mem", 3)
            return CheckResult(WARN, "可用内存偏低：%.1f%%%s" % (pct, size)
                               + (("\n     占用最高: " + "；".join(top)) if top else ""))
        # Say which of the gates held, so a machine that is *small* rather
        # than pressured is visibly distinguished from a healthy one. Both
        # explanations exist because either gate can be the deciding one.
        if pct <= warn_pct:
            return CheckResult(
                OK, "可用内存 %.1f%%%s —— 比例虽低，但可用内存仍有 %.0f MB，"
                    "高于本机判定下限 %.0f MB，对这台机器属于正常波动"
                % (pct, size, avail_mb, warn_floor))
        return CheckResult(
            OK, "可用内存 %.1f%%%s —— 比例高于本机（小内存）换算后的告警线 "
                "%.0f%%，且可用 %.0f MB 仍高于下限 %.0f MB，"
                "对这台机器属于正常波动"
            % (pct, size, warn_pct, avail_mb, warn_floor))


def _memory_floor_mb(configured, total_kb: int, ratio: float) -> float:
    """The absolute "still enough to work with" floor, in MB.

    *configured* wins when it is a positive number -- an operator who knows
    their workload sets it once. Otherwise it scales with the machine: a fixed
    300 MB floor would never fire on a host with 64 GB (where 300 MB free is
    an emergency) and would fire constantly on a 1 GB host (where 300 MB free
    is the normal state). Scaling keeps the same *meaning* -- "this fraction
    of the machine is all that is left" -- across sizes.
    """
    try:
        value = float(configured or 0)
    except (TypeError, ValueError):
        value = 0.0
    if value > 0:
        return value
    return max(1.0, (total_kb / 1024.0) * float(ratio))


def _scaled_pct(configured, total_kb: int, default: float) -> tuple:
    """``(percentage, was_scaled)`` for the available-memory thresholds.

    A fixed 20% is a false alarm on a small host: a 2 GB machine running one
    build drops below it while being perfectly healthy. So when the config
    still holds the *default*, the line is relaxed in proportion to how small
    the machine is. An operator-supplied value is returned untouched -- two
    different people may have written that number for two different reasons,
    and this function cannot tell which.

    The shape is deliberately gentle: 20% normally, 16% at 4 GB, 12% at 2 GB
    and below. The point is to stop nagging a small machine, not to stop
    noticing when it really is out of memory -- the absolute floors below and
    the separate `crit` threshold still fire.
    """
    try:
        value = float(configured)
    except (TypeError, ValueError):
        value = float(default)
    if abs(value - float(default)) > 1e-9:
        return value, False
    total_mb = total_kb / 1024.0
    if total_mb <= 2048:
        return 12.0, True
    if total_mb <= 4096:
        return 16.0, True
    return value, True


def _mem_headroom_mb(total_kb: int) -> float:
    """The "that is still a lot of bytes" cap, in MB, from the total size.

    Scaled to the machine so the same *judgement* holds everywhere: a few
    hundred megabytes is ample on a 2 GB host and negligible on a 64 GB one.
    Five percent of the total is the line -- 256 MB on a 2 GB box (the floor,
    so a tiny host still gets a sane figure) and 3.2 GB on a 64 GB box (the
    ceiling, so the cap cannot run away from the scaled floor and start
    alerting a large host again).

    In other words: "more than 5% of this machine is still free" is not
    pressure, whatever the available-memory *percentage* threshold says. The
    critical line is half of this, so "300 MB is a usable amount" can never
    excuse a 64 GB host that is nearly out.
    """
    return min(3277.0, max(256.0, (total_kb / 1024.0) * 0.05))


@register
class SwapUsage(Check):
    id = "swap"
    label = "Swap"
    label_en = "Swap"
    group = G_RESOURCE
    description = "Swap 使用率过高说明物理内存已严重不足"

    def run(self, ctx) -> CheckResult:
        warn_pct = float(ctx.copt("swap", "warn_pct", 50))
        crit_pct = float(ctx.copt("swap", "crit_pct", 80))

        info = _meminfo()
        total = info.get("SwapTotal", 0)
        if total <= 0:
            return CheckResult(OK, "未启用 swap")
        free = info.get("SwapFree", 0)
        used_pct = (total - free) * 100.0 / total
        if used_pct >= crit_pct:
            return CheckResult(CRIT, "Swap 使用率过高：**%.1f%%**（%.1f MB / %.1f MB）—— "
                                     "物理内存已严重不足，系统会频繁换页导致整体卡顿。"
                               % (used_pct, (total - free) / 1024.0, total / 1024.0))
        if used_pct >= warn_pct:
            return CheckResult(WARN, "Swap 使用率偏高：%.1f%%（%.1f MB / %.1f MB）"
                               % (used_pct, (total - free) / 1024.0, total / 1024.0))
        return CheckResult(OK, "Swap 使用率 %.1f%%（%.1f MB / %.1f MB）"
                           % (used_pct, (total - free) / 1024.0, total / 1024.0))


@register
class DiskUsage(Check):
    id = "disk"
    label = "磁盘空间"
    label_en = "Disk space"
    group = G_RESOURCE
    description = "检查各真实挂载点的磁盘使用率，写满会导致数据库与网站不可用"

    def run(self, ctx) -> CheckResult:
        warn_pct = float(ctx.copt("disk", "warn_pct", 80))
        crit_pct = float(ctx.copt("disk", "crit_pct", 90))

        mounts = _candidate_mounts(ctx)
        if not mounts:
            return CheckResult(OK, "无法枚举挂载点，跳过磁盘检查")

        bad_crit, bad_warn, worst = [], [], None
        checked = 0
        for mnt in mounts:
            try:
                st = os.statvfs(mnt)
            except OSError:
                continue
            if st.f_blocks <= 0:
                continue
            checked += 1
            pct = (st.f_blocks - st.f_bfree) * 100.0 / st.f_blocks
            free = util.human_bytes(st.f_bavail * st.f_frsize)
            item = "%s 已用 %.0f%%（剩余 %s）" % (mnt, pct, free)
            if worst is None or pct > worst[0]:
                worst = (pct, mnt)
            if pct >= crit_pct:
                bad_crit.append(item)
            elif pct >= warn_pct:
                bad_warn.append(item)

        if bad_crit:
            return CheckResult(CRIT, "磁盘空间严重不足（阈值 %.0f%%）：\n     %s"
                               % (crit_pct, "\n     ".join(bad_crit[:8]))
                               + ("\n     另有 %d 个挂载点同样超限" % (len(bad_crit) - 8)
                                  if len(bad_crit) > 8 else "")
                               + "\n     磁盘写满会导致数据库无法写入、日志中断、"
                                 "网站彻底不可用，请立即清理。")
        if bad_warn:
            return CheckResult(WARN, "磁盘空间偏高（阈值 %.0f%%）：\n     %s"
                               % (warn_pct, "\n     ".join(bad_warn[:8]))
                               + ("\n     另有 %d 个挂载点同样偏高" % (len(bad_warn) - 8)
                                  if len(bad_warn) > 8 else ""))
        if worst:
            return CheckResult(OK, "磁盘空间正常（已检查 %d 个挂载点，最高 %s 已用 %.0f%%）"
                               % (checked, worst[1], worst[0]))
        return CheckResult(OK, "无法读取挂载点容量，跳过磁盘检查")


@register
class InodeUsage(Check):
    id = "inode"
    label = "inode"
    label_en = "inodes"
    group = G_RESOURCE
    description = "inode 耗尽后即使磁盘有空间也无法创建任何新文件"

    def run(self, ctx) -> CheckResult:
        warn_pct = float(ctx.copt("inode", "warn_pct", 80))
        crit_pct = float(ctx.copt("inode", "crit_pct", 90))

        mounts = _candidate_mounts(ctx)
        bad_crit, bad_warn, worst = [], [], None
        checked = 0
        for mnt in mounts:
            try:
                st = os.statvfs(mnt)
            except OSError:
                continue
            if st.f_files <= 0:
                continue
            checked += 1
            pct = (st.f_files - st.f_ffree) * 100.0 / st.f_files
            if worst is None or pct > worst[0]:
                worst = (pct, mnt)
            item = "%s 已用 %.0f%%（已用 %d / 共 %d）" % (
                mnt, pct, st.f_files - st.f_ffree, st.f_files)
            if pct >= crit_pct:
                bad_crit.append(item)
            elif pct >= warn_pct:
                bad_warn.append(item)

        if bad_crit:
            return CheckResult(CRIT, "inode 严重不足（阈值 %.0f%%）：\n     %s"
                               % (crit_pct, "\n     ".join(bad_crit[:8]))
                               + ("\n     另有 %d 个挂载点超限" % (len(bad_crit) - 8)
                                  if len(bad_crit) > 8 else "")
                               + "\n     inode 耗尽后即使磁盘还有空间也无法创建新文件，"
                                 "会话、缓存、邮件队列都会失败。")
        if bad_warn:
            return CheckResult(WARN, "inode 使用率偏高（阈值 %.0f%%）：\n     %s"
                               % (warn_pct, "\n     ".join(bad_warn[:8]))
                               + ("\n     另有 %d 个挂载点偏高" % (len(bad_warn) - 8)
                                  if len(bad_warn) > 8 else ""))
        if worst:
            return CheckResult(OK, "inode 正常（已检查 %d 个挂载点，最高 %s 已用 %.0f%%）"
                               % (checked, worst[1], worst[0]))
        return CheckResult(OK, "无法读取挂载点 inode，跳过检查")


@register
class DiskIoWait(Check):
    id = "disk_io"
    label = "磁盘 I/O 等待"
    label_en = "Disk I/O wait"
    group = G_RESOURCE
    stateful = True
    description = "两次采样 /proc/stat 的 iowait 占比，判断磁盘是否成为瓶颈"

    def run(self, ctx) -> CheckResult:
        warn = float(ctx.copt("io_wait", "warn", 20))
        crit = float(ctx.copt("io_wait", "crit", 40))

        vals = _proc_stat()
        if len(vals) <= 4:
            return CheckResult(OK, "无法读取 /proc/stat，跳过 I/O 等待检查")
        iowait, total = vals[4], sum(vals)
        prev = ctx.snapshot("io_prev", [iowait, total])
        if not prev or len(prev) != 2:
            return CheckResult(OK, "I/O 采集中（首次运行，下一轮给出等待率）")
        di = iowait - int(prev[0])
        dt = total - int(prev[1])
        if dt <= 0:
            return CheckResult(OK, "I/O 采样间隔为 0，本轮跳过")
        pct = di * 100.0 / dt
        if pct >= crit:
            return CheckResult(CRIT, "磁盘 I/O 等待过高：**%.1f%%**（阈值 %.0f%%）—— "
                                     "磁盘已成为瓶颈，读写操作排队会导致整机卡顿；"
                                     "也可能是磁盘硬件故障的前兆。"
                               % (pct, crit))
        if pct >= warn:
            return CheckResult(WARN, "磁盘 I/O 等待偏高：%.1f%%（阈值 %.0f%%）"
                               % (pct, warn))
        return CheckResult(OK, "磁盘 I/O 等待 %.1f%%" % pct)


@register
class ConntrackUsage(Check):
    id = "conntrack"
    label = "连接跟踪表"
    label_en = "conntrack table"
    group = G_RESOURCE
    description = "conntrack 表濒临耗尽时内核会直接丢弃新连接（典型 DDoS 征兆）"

    def run(self, ctx) -> CheckResult:
        warn_pct = float(ctx.copt("conntrack", "warn_pct", 70))
        crit_pct = float(ctx.copt("conntrack", "crit_pct", 90))

        base = "/proc/sys/net/netfilter"
        try:
            with open(base + "/nf_conntrack_count", "r", encoding="utf-8") as fh:
                count = int(fh.read().strip())
            with open(base + "/nf_conntrack_max", "r", encoding="utf-8") as fh:
                maximum = int(fh.read().strip())
        except (OSError, ValueError):
            return CheckResult(OK, "未启用 conntrack（/proc/sys/net/netfilter 不可读）")
        if maximum <= 0:
            return CheckResult(OK, "conntrack 上限为 0，跳过检查")
        pct = count * 100.0 / maximum
        if pct >= crit_pct:
            return CheckResult(CRIT, "连接跟踪表濒临耗尽：**%d/%d（%.1f%%）** —— "
                                     "新连接将被内核丢弃，网站与 SSH 都会连不上，"
                                     "这是典型的 DDoS 攻击征兆。"
                               % (count, maximum, pct))
        if pct >= warn_pct:
            return CheckResult(WARN, "连接跟踪表用量偏高：%d/%d（%.1f%%）"
                               % (count, maximum, pct))
        return CheckResult(OK, "连接跟踪表 %d/%d（%.1f%%）" % (count, maximum, pct))
