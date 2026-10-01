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

        if pct <= crit_pct:
            top = util.top_procs("mem", 3)
            return CheckResult(CRIT, "可用内存严重不足：仅 **%.1f%%**%s"
                               % (pct, size)
                               + (("\n     占用最高: " + "；".join(top)) if top else "")
                               + "\n     内存耗尽会触发 OOM Killer 随机杀进程，"
                                 "数据库或 Web 服务可能被强制终止。")
        if pct <= warn_pct:
            top = util.top_procs("mem", 3)
            return CheckResult(WARN, "可用内存偏低：%.1f%%%s" % (pct, size)
                               + (("\n     占用最高: " + "；".join(top)) if top else ""))
        return CheckResult(OK, "可用内存 %.1f%%%s" % (pct, size))


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
