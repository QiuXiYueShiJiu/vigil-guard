"""Integrity and change-detection checks (group ``integrity``).

Ported from ``c_files`` / ``c_ports`` / ``c_suid`` / ``c_kmod`` / ``c_cron`` /
``c_systemd_units`` / ``c_firewall`` / ``c_dns`` / ``c_audit_rules``.

All of these are **additive events**: a file was replaced, a port appeared, a
module was loaded. They return ``EVENT`` rather than WARN/CRIT on purpose --
an event has nothing to "recover" to, so the runner must not send a second,
meaningless recovery mail when the new baseline is accepted.

Several defects of the original are fixed here, each one observed in
production before it was fixed upstream:

* firewall rules are read with ``iptables -S`` (``iptables-save`` embeds
  packet counters that change every run, so its hash never matches) and every
  ``f2b-*`` fail2ban chain is excluded from both sides of the comparison;
* ``lsmod`` output is filtered against the families of modules the kernel
  loads on demand (``xt_*``, ``nf_*``, ``*_diag``, ...) so normal firewalling
  and ``ss`` calls do not look like a rootkit;
* detail blocks are capped (6-12 entries plus a "等 N 项" summary) so one
  noisy change cannot turn the alert into a megabyte of text.
"""
from __future__ import annotations

import hashlib
import os
import re

from . import util
from .base import (CRIT, EVENT, G_INTEGRITY, OK, WARN, Check, CheckContext,
                   CheckResult, register)
from ...core import shell

#: How many individual entries to spell out before summarising. Kept small
#: because this text is rendered into an email body.
_DETAIL_CAP = 6
_SUID_DETAIL_CAP = 12

#: Standard Linux privilege-bearing directories. These are universal, not
#: host specific; control-panel trees are discovered from ``ctx.env``.
_STD_SUID_ROOTS = ("/usr/bin", "/usr/sbin", "/bin", "/sbin",
                   "/usr/local/bin", "/usr/local/sbin", "/opt")

#: Modules the kernel loads on demand. Reporting these would be pure noise:
#: ``udp_diag`` is loaded by our own ``ss`` call, ``xt_*``/``nf_*``/``ipt_*``
#: by any iptables operation.
_AUTO_BENIGN = re.compile(
    r"^("
    r"\w+_diag|"
    r"xt_\w+|"
    r"nf_\w+|"
    r"ipt_\w+|ip6t_\w+|"
    r"iptable_\w+|ip6table_\w+|"
    r"nft_\w+|"
    r"binfmt_\w+|crc32\w*|crypto_\w+|zstd|"
    r"\w+_tables"
    r")$")

#: Very short, generic explanation of what a watched file is and what a
#: change to it means. Keyed by full path first, then by basename. Only
#: standard system paths appear here; nothing host specific.
_FILE_HINTS = {
    "/etc/passwd": ("系统账号数据库。新增行 = 多出一个可登录账号；把某账号 uid 改为 0 = "
                    "获得与 root 完全相同的权限。",
                    "立即 `cat /etc/passwd`，核对是否有陌生账号或 uid 为 0 的非 root 账号。"),
    "/etc/shadow": ("账号口令哈希库。",
                    "某账号口令可能已被替换成攻击者已知的值，改密码也挡不住；"
                    "核对最近被修改的账号并检查登录记录。"),
    "/etc/gshadow": ("组口令/管理员哈希库。",
                     "组权限可能被改动，核对 sudo/组管理配置。"),
    "/etc/sudoers": ("sudo 提权规则。",
                     "某普通账号可能获得免密 sudo 权限；执行 `visudo -c` 校验并逐条核对来源。"),
    "/etc/ssh/sshd_config": ("SSH 服务配置。",
                             "注意 PermitRootLogin / PasswordAuthentication / Port 是否被放宽。"),
    "/etc/crontab": ("系统计划任务。",
                     "可能被植入定时回连或重新植入后门的任务；核对每条任务来源。"),
    "/etc/ld.so.preload": ("动态链接库全局预加载。",
                           "rootkit 常见手法：恶意库可劫持所有进程并隐藏自身。"),
    "authorized_keys": ("SSH 免密登录公钥。",
                        "新增公钥 = 攻击者已能免密登录，改密码无法阻止；逐条核对指纹。"),
    "nginx.conf": ("Web 服务主配置。",
                   "可能新增恶意反代或把流量转发到外部；核对 proxy_pass 与监听端口。"),
}

_CONSEQUENCE_GENERIC = ("被改动可能意味着配置被正常调整，也可能是入侵者植入后门或"
                        "修改认证逻辑。")


def _capped(items, limit: int, indent: str = "       ") -> str:
    """Render at most *limit* items, then a Chinese "等 N 项" summary."""
    lines = [indent + str(x) for x in items[:limit]]
    if len(items) > limit:
        lines.append("%s…… 等 %d 项未展开" % (indent, len(items) - limit))
    return "\n".join(lines)


def _file_hint(path: str):
    hint = _FILE_HINTS.get(path)
    if hint is None:
        base = os.path.basename(path)
        hint = _FILE_HINTS.get(base)
    if hint is None:
        for known, value in _FILE_HINTS.items():
            if os.path.basename(known) == base:
                hint = value
                break
    if hint is None:
        hint = ("受监控的关键文件。", _CONSEQUENCE_GENERIC)
    return hint


def _sig_inode(sig: str) -> str:
    return util.sig_parts(sig)[1] if sig else ""


@register
class WatchFiles(Check):
    id = "watch_files"
    label = "关键文件变更"
    label_en = "Watched file changes"
    group = G_INTEGRITY
    stateful = True
    heavy = True
    description = "对比关键文件的内容哈希与 inode，报告变更并附 auditd 归因"

    def run(self, ctx: CheckContext) -> CheckResult:
        targets = self._targets(ctx)
        if not targets:
            return CheckResult(OK, "未配置需要监控的关键文件"
                                   "（checks.watch_files / watch_dirs 均为空）")

        cur = {}
        for path in targets:
            cur[path] = util.file_sig(path) if os.path.exists(path) else "missing"

        # Format version 3 == "sha256:inode"; older formats are not comparable.
        prev = ctx.versioned("watch_files", 3, cur)
        if prev is None:
            return CheckResult(OK, "已建立 %d 个关键文件的基线" % len(cur))

        changed = []
        for path in sorted(cur):
            old = prev.get(path)
            new = cur[path]
            if old is None or old == new:
                continue
            if old == "missing":
                how = "新增文件"
            elif new == "missing":
                how = "**文件已消失**（被删除或改名）"
            elif _sig_inode(old) != _sig_inode(new):
                how = "整体替换（inode 变更，常见于部署脚本/文件管理工具写入）"
            else:
                how = "原地修改（inode 未变，直接写入内容）"
            changed.append((path, old, how))

        if not changed:
            return CheckResult(OK, "关键文件无变化（共监控 %d 个）" % len(cur))

        names = [os.path.basename(p) for p, _o, _h in changed]
        header = "关键文件发生变更：**%d 个** —— %s" % (
            len(changed), "、".join(names[:_DETAIL_CAP]))

        attr = {}
        try:
            attr = util.audit_attribution(
                ctx.cfg, names, since_ts=ctx.state.get("last_run"))
        except Exception:                                    # noqa: BLE001
            attr = {}

        blocks = []
        for path, old, how in changed[:_DETAIL_CAP]:
            hint = _file_hint(path)
            lines = ["── %s ──" % path,
                     "改动方式: %s%s" % (how, "（基线中不存在）" if old == "missing" else ""),
                     "这是什么: %s" % hint[0],
                     "可能后果: %s" % hint[1]]
            try:
                import time as _time
                lines.append("修改时间: %s" % _time.strftime(
                    "%Y-%m-%d %H:%M:%S", _time.localtime(os.path.getmtime(path))))
            except OSError:
                pass
            found = attr.get(os.path.basename(path))
            if found:
                lines.append("── auditd 归因（谁改的）──")
                lines.extend(str(x) for x in found)
            blocks.append("\n       ".join(lines))

        detail = header + "\n       " + "\n\n       ".join(blocks)
        if len(changed) > _DETAIL_CAP:
            detail += "\n       …… 另有 %d 个文件变更未展开" % (len(changed) - _DETAIL_CAP)
        if not attr:
            detail += ("\n       （未取得 auditd 归因：可能未安装/未启用 auditd，"
                       "或改动为 rename 整体替换——auditd 的 -w 监视绑在 inode 上，"
                       "rename 会绕过它。请人工核查。）")
        return CheckResult(EVENT, detail)

    #: Filesystems whose contents are generated by the kernel and change
    #: without anyone touching them. Watching one produces an alert every
    #: time the kernel updates it, which is to say continuously.
    VOLATILE_ROOTS = ("/proc", "/sys", "/dev", "/run")

    @classmethod
    def _volatile(cls, path: str) -> bool:
        """Is this path kernel-generated rather than a real file?

        Two ways to be caught, and both matter: a path directly under a
        virtual filesystem, and a symlink that resolves into one. `/etc/mtab`
        is the second kind -- it looks like an ordinary file in /etc and is
        in fact a link to `/proc/self/mounts`, which the kernel rewrites on
        every mount event. Watching it produced an alert every two minutes
        for a file nobody had touched.
        """
        real = os.path.realpath(path)
        for candidate in (path, real):
            norm = os.path.normpath(candidate)
            for root in cls.VOLATILE_ROOTS:
                if norm == root or norm.startswith(root + "/"):
                    return True
        return False

    @classmethod
    def _targets(cls, ctx: CheckContext) -> list:
        explicit = [str(x) for x in (ctx.opt("watch_files", []) or []) if x]
        extra = []
        for d in (ctx.opt("watch_dirs", []) or []):
            d = str(d).rstrip("/")
            # A watch_dir may be a plain directory or already a glob pattern.
            patterns = [d] if any(ch in d for ch in "*?[") else [d + "/*"]
            extra.extend(p for p in util.expand_globs(patterns)
                         if os.path.isfile(p))
        kept = []
        skipped = 0
        for path in dict.fromkeys(explicit + extra):
            if cls._volatile(path):
                skipped += 1
                continue
            kept.append(path)
        if skipped and ctx.log:
            ctx.log.info("跳过 %d 个内核虚拟文件（/proc、/sys、/dev、/run 及其符号链接目标）"
                         % skipped)
        return sorted(kept)


@register
class ListeningPorts(Check):
    id = "listening_ports"
    label = "监听端口变化"
    label_en = "Listening port changes"
    group = G_INTEGRITY
    stateful = True
    description = "发现从未出现过的对外监听端口（后门或误配置）"

    def run(self, ctx: CheckContext) -> CheckResult:
        raw = util.listening_ports()
        if not raw:
            return CheckResult(OK, "无法读取监听端口（ss 不可用或无输出），跳过检查")

        external, loopback = [], []
        for item in raw:
            local = item.partition(" ")[2]
            (loopback if _is_loopback(local) else external).append(item)
        cur = sorted(set(external))

        seed = [str(x) for x in (ctx.opt("ports", []) or []) if x]
        # Accumulating "ever seen" set: a service restart makes a port vanish
        # for a moment, and a plain previous-snapshot diff would then report
        # its return as a brand new backdoor port.
        prev = ctx.versioned("listen_ports", 2, cur)
        seen = set(ctx.state.get("listen_seen") or []) | set(seed)
        added = sorted(set(cur) - seen)
        ctx.snapshot("listen_seen", sorted(seen | set(cur)))

        suffix = "（另有 %d 个仅本机监听，未纳入基线）" % len(loopback) if loopback else ""
        if prev is None:
            return CheckResult(OK, "已建立对外监听端口基线（%d 个）%s"
                               % (len(cur), suffix))
        if not added:
            return CheckResult(OK, "对外监听端口无变化（%d 个）%s" % (len(cur), suffix))

        lines = []
        for item in added:
            proto = item.partition(" ")[0]
            port = item.partition(" ")[2].rsplit(":", 1)[-1]
            owner = util.port_owner(port) or "未知进程"
            lines.append("%s/%s ← %s" % (proto, item.partition(" ")[2], owner))
        return CheckResult(EVENT,
                           "新增对外监听端口 **%d 个**（从未出现过，请确认是否为预期变更）：\n       %s"
                           % (len(added), _capped(lines, _DETAIL_CAP)))


def _is_loopback(local: str) -> bool:
    addr = local.rsplit(":", 1)[0]
    if addr.startswith("127."):
        return True
    return addr in ("[::1]", "::1", "localhost")


@register
class SuidFiles(Check):
    id = "suid_files"
    label = "SUID/SGID 文件变化"
    label_en = "SUID/SGID file changes"
    group = G_INTEGRITY
    stateful = True
    heavy = True
    description = "发现新增的 SUID/SGID 可执行文件（本地提权常用手段）"

    def run(self, ctx: CheckContext) -> CheckResult:
        cur, scanned, truncated = self._scan(ctx)
        prev = ctx.state.get("suid_files")
        first = prev is None
        known = set(prev or [])
        added = sorted(set(cur) - known)

        try:
            refresh_days = float(ctx.opt("suid_baseline_refresh_days", 30) or 0)
        except (TypeError, ValueError):
            refresh_days = 0.0
        last = ctx.state.get("suid_files_ts") or 0
        refreshed = False
        if not first and refresh_days > 0 and (ctx.now - float(last)) >= refresh_days * 86400:
            known = set()          # periodic refresh: drop entries that vanished
            refreshed = True
            ctx.snapshot("suid_files_ts", ctx.now)
        ctx.snapshot("suid_files", sorted(known | set(cur)))

        note = "（共扫描 %d 个文件，基线 %d 个%s）" % (
            scanned, len(cur), "，已按周期刷新基线" if refreshed else "")
        if truncated:
            note += "（扫描文件数达到上限，结果可能不完整）"
        if first:
            return CheckResult(OK, "已建立 SUID/SGID 基线 %d 个%s" % (len(cur), note))
        if not added:
            return CheckResult(OK, "SUID/SGID 无新增%s" % note)
        return CheckResult(EVENT,
                           "新增 SUID/SGID 文件 **%d 个**（可以文件属主权限运行，"
                           "是本地提权的经典手段）:\n       %s"
                           % (len(added), _capped(added, _SUID_DETAIL_CAP)))

    @staticmethod
    def _roots(ctx: CheckContext) -> list:
        roots = list(_STD_SUID_ROOTS)
        for extra in (ctx.copt("suid_files", "extra_dirs", []) or []):
            roots.append(str(extra))
        env = ctx.env
        nginx = env.get("nginx") or {}
        if nginx.get("binary"):
            roots.append(os.path.dirname(os.path.realpath(nginx["binary"])))
        for binary in (env.get("php_fpm") or {}).get("binaries") or []:
            roots.append(os.path.dirname(os.path.realpath(binary)))
        for root in env.get("web_roots") or []:
            roots.append(str(root))
        panel = env.get("bt_panel") or {}
        if panel.get("present") and panel.get("dir"):
            roots.append(str(panel["dir"]))

        out, seen = [], set()
        for root in roots:
            try:
                real = os.path.realpath(root)
            except OSError:
                continue
            if not real or real in seen or not os.path.isdir(real):
                continue
            seen.add(real)
            out.append(real)
        return out

    @staticmethod
    def _scan(ctx: CheckContext):
        found, scanned, truncated = set(), 0, False
        for base in SuidFiles._roots(ctx):
            for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
                if dirpath[len(base):].count(os.sep) >= 6:
                    dirnames[:] = []
                for name in filenames:
                    path = os.path.join(dirpath, name)
                    try:
                        st = os.lstat(path)
                    except OSError:
                        continue
                    scanned += 1
                    if scanned > 20000:
                        return sorted(found), scanned, True
                    if st.st_mode & 0o4000:
                        found.add(path + "  [SUID]")
                    elif st.st_mode & 0o2000:
                        found.add(path + "  [SGID]")
        return sorted(found), scanned, truncated


@register
class KernelModules(Check):
    id = "kernel_modules"
    label = "内核模块"
    label_en = "Kernel modules"
    group = G_INTEGRITY
    stateful = True
    description = "发现新加载的内核模块（LKM rootkit 常用手法）"

    def run(self, ctx: CheckContext) -> CheckResult:
        if not shell.have("lsmod"):
            return CheckResult(OK, "lsmod 不可用，跳过内核模块检查")
        ok, out, err = shell.run(["lsmod"], timeout=10)
        if not ok:
            return CheckResult(OK, "无法读取内核模块列表（%s）"
                               % util.first_line(err, 80))
        cur = sorted(line.split()[0] for line in out.splitlines()[1:] if line.strip())
        prev = ctx.snapshot("kmods", cur)
        if prev is None:
            return CheckResult(OK, "已建立内核模块基线（%d 个）" % len(cur))
        added = [m for m in sorted(set(cur) - set(prev)) if not _AUTO_BENIGN.match(m)]
        if not added:
            return CheckResult(OK, "内核模块无变化（%d 个）" % len(cur))
        lines = []
        for mod in added[:5]:
            path = shell.out(["modinfo", "-n", mod]).strip()
            lines.append("%s%s" % (mod, ("  文件: %s" % path) if path else ""))
        return CheckResult(EVENT,
                           "新加载内核模块 **%d 个**（非系统按需加载的常见模块，"
                           "请核实来源；内核级 rootkit 通过模块获得最高权限）:\n       %s"
                           % (len(added), "\n       ".join(lines)))


@register
class CronEntries(Check):
    id = "cron_entries"
    label = "计划任务"
    label_en = "Cron entries"
    group = G_INTEGRITY
    stateful = True
    description = "发现新增的 cron 任务（定时回连/重新植入后门的持久化手法）"

    def run(self, ctx: CheckContext) -> CheckResult:
        cur = self._entries()
        prev = ctx.snapshot("cron_entries", cur)
        if prev is None:
            return CheckResult(OK, "已建立计划任务基线（%d 条）" % len(cur))
        added = sorted(set(cur) - set(prev))
        if not added:
            return CheckResult(OK, "计划任务无变化（%d 条）" % len(cur))
        shown = [a.split("  ", 1)[-1] for a in added]
        return CheckResult(EVENT,
                           "新增计划任务 **%d 条**（攻击者常用 cron 实现持久化，"
                           "请核对是否为你本人添加）:\n       %s"
                           % (len(added), _capped(shown, _DETAIL_CAP)))

    @staticmethod
    def _entries() -> list:
        lines = []
        ok, out, _err = shell.run(["crontab", "-l"], timeout=10)
        if ok and out:
            lines.extend(out.splitlines())
        for path in ("/etc/crontab", "/etc/anacrontab"):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    lines.extend(fh.read().splitlines())
            except OSError:
                pass
        for pattern in ("/etc/cron.d/*", "/var/spool/cron/crontabs/*",
                        "/var/spool/cron/*"):
            for path in util.expand_globs([pattern]):
                if not os.path.isfile(path):
                    continue
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as fh:
                        lines.extend(fh.read().splitlines())
                except OSError:
                    continue

        items = set()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            digest = hashlib.sha256(
                line.encode("utf-8", "replace")).hexdigest()[:16]
            items.add("%s  %s" % (digest, line[:90]))
        return sorted(items)


@register
class SystemdUnits(Check):
    id = "systemd_units"
    label = "systemd 单元"
    label_en = "systemd units"
    group = G_INTEGRITY
    stateful = True
    description = "发现新增的 systemd 服务单元（开机自动启动后门的常用手法）"

    def run(self, ctx: CheckContext) -> CheckResult:
        if not shell.have("systemctl"):
            return CheckResult(OK, "systemctl 不可用（可能不是 systemd 系统），跳过检查")
        ok, out, err = shell.run(
            ["systemctl", "list-unit-files", "--type=service", "--no-legend",
             "--no-pager"], timeout=20)
        if not ok:
            return CheckResult(OK, "无法枚举 systemd 单元（%s）"
                               % util.first_line(err, 80))
        cur = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                cur.append("%s|%s" % (parts[0], parts[1]))
        cur = sorted(set(cur))
        if not cur:
            return CheckResult(OK, "systemd 单元列表为空，跳过检查")
        prev = ctx.snapshot("systemd_units", cur)
        if prev is None:
            return CheckResult(OK, "已建立 systemd 单元基线（%d 个）" % len(cur))
        added = sorted(set(cur) - set(prev))
        if not added:
            return CheckResult(OK, "systemd 单元无变化（%d 个）" % len(cur))
        return CheckResult(EVENT,
                           "新增 systemd 服务单元 **%d 个**（可能被用于开机自动启动后门，"
                           "请核对文件路径与内容）:\n       %s"
                           % (len(added), _capped(added, _DETAIL_CAP)))


def _keep_firewall_line(line: str) -> bool:
    """Drop blank lines and every fail2ban-owned rule.

    fail2ban adds and removes ``f2b-*`` chains/rules each time it bans an
    address. Keeping them would mail an alert for every single ban; excluding
    the whole family still notices fail2ban being switched off, because the
    chains it owns would then all disappear at once.
    """
    text = line.strip()
    return bool(text) and "f2b-" not in text


@register
class FirewallRules(Check):
    id = "firewall_rules"
    label = "防火墙规则"
    label_en = "Firewall rules"
    group = G_INTEGRITY
    stateful = True
    description = "对比 iptables/ufw/nft 规则集合，报告新增或移除的规则"

    def run(self, ctx: CheckContext) -> CheckResult:
        current = [line for line in self._rules() if _keep_firewall_line(line)]
        if not current:
            return CheckResult(OK, "未取得防火墙规则"
                                   "（iptables/ufw/nft 均不可用或规则为空），跳过检查")
        prev = ctx.versioned("fw_rules", 2, current)
        if prev is not None:
            prev = [line for line in prev if _keep_firewall_line(line)]
        if prev is None:
            return CheckResult(OK, "已建立防火墙规则基线（%d 条）" % len(current))
        added = [r for r in current if r not in prev]
        removed = [r for r in prev if r not in current]
        if not added and not removed:
            return CheckResult(OK, "防火墙规则无变化（%d 条）" % len(current))
        msg = "防火墙规则发生变化（新增 %d 条 / 移除 %d 条，共 %d 条）" % (
            len(added), len(removed), len(current))
        if added:
            msg += "\n       新增规则:\n%s" % _capped(
                ["+ " + r[:110] for r in added], _DETAIL_CAP, "         ")
        if removed:
            msg += "\n       移除规则:\n%s" % _capped(
                ["- " + r[:110] for r in removed], _DETAIL_CAP, "         ")
        msg += "\n       攻击者取得权限后常先关闭防火墙或放开一个端口。"
        return CheckResult(EVENT, msg)

    @staticmethod
    def _rules() -> list:
        lines = []
        if shell.have("iptables"):
            ok, out, _err = shell.run(["iptables", "-S"], timeout=15)
            if ok:
                lines.extend("iptables %s" % l.strip()
                             for l in out.splitlines() if l.strip())
        if shell.have("ufw"):
            ok, out, _err = shell.run(["ufw", "status"], timeout=15)
            if ok:
                lines.extend("ufw %s" % l.strip()
                             for l in out.splitlines() if l.strip())
        if not lines and shell.have("nft"):
            ok, out, _err = shell.run(["nft", "-s", "list", "ruleset"], timeout=15)
            if ok:
                lines.extend("nft %s" % l.strip()
                             for l in out.splitlines() if l.strip())
        return [line for line in lines if _keep_firewall_line(line)]


@register
class DnsConfig(Check):
    id = "dns_config"
    label = "DNS 解析配置"
    label_en = "DNS resolver config"
    group = G_INTEGRITY
    stateful = True
    description = "监控 /etc/hosts、resolv.conf、nsswitch.conf 的变化（可被用于域名劫持）"

    _FILES = ("/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf")

    def run(self, ctx: CheckContext) -> CheckResult:
        parts, readable = [], []
        for path in self._FILES:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    parts.append(path + "|" + fh.read())
                readable.append(path)
            except OSError:
                continue
        if not readable:
            return CheckResult(OK, "无法读取 DNS 解析配置，跳过检查")
        digest = hashlib.sha256(
            "\n".join(parts).encode("utf-8", "replace")).hexdigest()[:32]
        prev = ctx.versioned("dns_hash", 2, digest)
        if prev is None:
            return CheckResult(OK, "已建立 DNS 配置基线（%s）" % "、".join(readable))
        if prev == digest:
            return CheckResult(OK, "DNS 配置无变化")
        hosts, resolvers = self._summarise()
        detail = ("DNS 解析配置（%s）发生变化 —— **可能被用于劫持域名解析**，"
                  "把流量导向攻击者服务器。" % "、".join(readable))
        if hosts:
            detail += "\n       当前 hosts: %s" % hosts
        if resolvers:
            detail += "\n       当前 DNS: %s" % resolvers
        return CheckResult(EVENT, detail)

    @staticmethod
    def _summarise() -> tuple:
        hosts = []
        try:
            with open("/etc/hosts", "r", encoding="utf-8", errors="replace") as fh:
                hosts = [l.strip() for l in fh
                         if l.strip() and not l.strip().startswith("#")]
        except OSError:
            pass
        resolvers = []
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8",
                      errors="replace") as fh:
                resolvers = [l.strip() for l in fh if l.strip().startswith("nameserver")]
        except OSError:
            pass
        return ("；".join(hosts[:6]) + ("……" if len(hosts) > 6 else ""),
                "；".join(resolvers[:4]))


@register
class AuditRules(Check):
    id = "audit_rules"
    label = "审计规则完整性"
    label_en = "Audit rule integrity"
    group = G_INTEGRITY
    description = "对比规则文件与内核实际加载的审计规则，防止静默降级"

    def run(self, ctx: CheckContext) -> CheckResult:
        env_audit = ctx.env.get("auditd") or {}
        override = (ctx.copt("audit_rules", "rules_file", "") or "").strip()
        if not override:
            rules_dir = env_audit.get("rules_dir") or "/etc/audit/rules.d"
            override = os.path.join(rules_dir, "vigil.rules")
        rules_file = override

        if not shell.have("auditctl"):
            return CheckResult(OK, "auditctl 不可用（未安装/未启用 auditd），跳过检查")
        if not os.path.isfile(rules_file):
            return CheckResult(WARN, "审计规则文件缺失：%s —— "
                                     "关键文件的改动将无法通过 auditd 归因"
                               % rules_file)

        try:
            with open(rules_file, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            return CheckResult(WARN, "无法读取审计规则文件 %s：%s"
                               % (rules_file, exc))

        want_w = want_a = 0
        missing = []
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("-w "):
                want_w += 1
                m = re.match(r"-w\s+(\S+)", line)
                if m and not os.path.exists(m.group(1)):
                    missing.append(m.group(1))
            elif line.startswith("-a "):
                want_a += 1

        ok, out, err = shell.run(["auditctl", "-l"], timeout=15)
        if not ok:
            return CheckResult(WARN, "无法读取内核审计规则（auditctl -l 失败：%s）"
                               % util.first_line(err, 80))
        got_w = sum(1 for l in out.splitlines() if l.strip().startswith("-w "))
        got_a = sum(1 for l in out.splitlines() if l.strip().startswith("-a "))

        _ok2, state, _e = shell.run(["auditctl", "-s"], timeout=10)
        immutable = "enabled 2" in state

        problems = []
        if missing:
            problems.append(
                "规则指向不存在的路径（会让 augenrules **放弃其后所有规则**，"
                "造成审计静默缺失）：%s" % "、".join(missing[:6]))
        if got_w < want_w:
            problems.append(
                "文件级/目录级 watch 未全部生效：内核 %d 条 < 文件 %d 条 —— "
                "缺失的规则意味着该处改动无法归因" % (got_w, want_w))
        if got_a < want_a:
            problems.append("syscall 规则未全部生效：内核 %d 条 < 文件 %d 条"
                            % (got_a, want_a))
        if problems:
            tail = ""
            if immutable:
                # With `-e 2` set the kernel refuses every rule change, and
                # `augenrules --load` answers "No change" without saying why.
                # Telling the operator to reload is telling them to waste an
                # hour; the only thing that works is a reboot.
                tail = ("\n     **不可变模式（-e 2）已生效，运行时无法更改规则** —— "
                        "以上差异只能在**重启后**消失。`augenrules --load` 现在"
                        "只会回答 No change，这是正常的。重启前请确认文件内容正确："
                        "任何一个 `-w` 指向不存在的路径，都会让 augenrules 丢弃"
                        "其后**全部**规则。")
            return CheckResult(CRIT, "\n     ".join(problems) + tail)
        if not immutable:
            return CheckResult(WARN,
                               "审计规则已全部加载（%d 条 watch），但**未置为不可变**"
                               "（`-e 2` 未生效）—— 攻击者可在运行时增删审计规则以掩盖行踪。"
                               % got_w)
        return CheckResult(OK, "审计规则 %d 条全部生效且已置不可变（-e 2）" % got_w)
