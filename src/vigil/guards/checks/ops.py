"""Operational-hygiene checks (group ``ops``).

Ported from ``c_services`` / ``c_mailq`` / ``c_backup`` / ``c_certs`` /
``c_reboot`` / ``c_oom`` / ``c_dmesg_err``.

Fixes carried over from the audit of the original:

* ``services`` returns **WARN**, not "CRIT for every unit", when
  ``systemctl`` is unusable or the units are unknown. A non-systemd host or a
  config listing a service that was renamed must not look like a total outage.
* ``backup_age`` reads its globs from ``checks.backup.globs`` instead of one
  host's hardcoded backup directory.
* ``certificates`` discovers certificate directories from the detected control
  panel and the standard certbot location instead of a hardcoded panel path.
"""
from __future__ import annotations

import calendar
import os
import re
import time
from datetime import datetime

from . import util
from .base import (CRIT, EVENT, G_OPS, OK, WARN, Check, CheckContext,
                   CheckResult, register)
from ...core import shell

#: Substrings that mark an OOM kill in kernel output.
_OOM_MARKERS = ("Out of memory", "oom-kill", "Killed process", "oom_reaper")


@register
class Services(Check):
    id = "services"
    label = "关键服务"
    label_en = "Critical services"
    group = G_OPS
    description = "检查配置中的关键服务是否处于 active 状态"

    def run(self, ctx: CheckContext) -> CheckResult:
        services = [str(s) for s in (ctx.opt("services", []) or []) if s]
        if not services:
            return CheckResult(OK, "未配置需要监控的服务（checks.services 为空），跳过检查")
        if not shell.have("systemctl"):
            return CheckResult(WARN, "systemctl 不可用（可能不是 systemd 系统），"
                                     "无法检查服务状态（应监控 %d 个）" % len(services))

        down, unknown = [], []
        for svc in services:
            _ok, out, _err = shell.run(["systemctl", "is-active", svc], timeout=10)
            state = (out or "").strip()
            if state == "active":
                continue
            # `is-active` reports an unknown unit as plain "inactive" on some
            # systemd versions, so ask for the load state to tell a missing
            # unit apart from a genuinely stopped one.
            _ok2, load, _err2 = shell.run(
                ["systemctl", "show", "-p", "LoadState", "--value", svc],
                timeout=10)
            load = (load or "").strip()
            if load in ("", "not-found", "bad-setting"):
                unknown.append("%s(%s)" % (svc, load or state or "未知"))
                continue
            # A unit that is masked or disabled is not broken -- it is a
            # decision someone made. Reporting it as a critical service
            # failure trains the operator to ignore the alert, which is worse
            # than not having it: this list contained a deliberately masked
            # clamav and an obsolete PHP build, and both fired CRIT every
            # cycle.
            _ok3, unit_file, _err3 = shell.run(
                ["systemctl", "show", "-p", "UnitFileState", "--value", svc],
                timeout=10)
            unit_file = (unit_file or "").strip()
            if unit_file in ("masked", "disabled", "masked-runtime",
                             "linked-runtime", "alias", "indirect"):
                continue
            down.append("%s(%s)" % (svc, state or load))
        if down:
            return CheckResult(CRIT,
                               "关键服务未运行：**%s**\n"
                               "       请立即 `systemctl status <服务>` 查看失败原因并尝试重启；"
                               "对应功能此刻不可用。"
                               % "、".join(down[:10])
                               + ("\n       另有 %d 个服务异常" % (len(down) - 10)
                                  if len(down) > 10 else "")
                               + ("\n       另有无法识别的单元：%s" % "、".join(unknown[:6])
                                  if unknown else ""))
        if unknown:
            return CheckResult(WARN,
                               "以下服务单元不存在或无法识别（systemctl 无法确认其状态）："
                               "%s\n       可能已改名/卸载，或本机不是 systemd 系统；"
                               "请核对 checks.services 配置。"
                               % "、".join(unknown[:10]))
        return CheckResult(OK, "%d 个关键服务全部运行正常" % len(services))


@register
class MailQueue(Check):
    id = "mail_queue"
    label = "邮件队列"
    label_en = "Mail queue"
    group = G_OPS
    description = "邮件队列积压说明告警通道可能已堵塞"

    def run(self, ctx: CheckContext) -> CheckResult:
        warn = int(ctx.copt("mailq", "warn", 20) or 20)
        crit = int(ctx.copt("mailq", "crit", 100) or 100)

        if shell.have("mailq"):
            argv = ["mailq"]
        elif shell.have("postqueue"):
            argv = ["postqueue", "-p"]
        else:
            return CheckResult(OK, "未安装 mailq/postqueue，跳过邮件队列检查")

        ok, out, err = shell.run(argv, timeout=15)
        text = out or ""
        if not ok and not text:
            return CheckResult(OK, "无法读取邮件队列（%s 执行失败：%s）"
                               % (argv[0], util.first_line(err, 80)))
        if "queue is empty" in text.lower():
            count = 0
        else:
            m = re.search(r"(\d+)\s+Requests?", text)
            if m:
                count = int(m.group(1))
            else:
                count = sum(1 for l in text.splitlines()
                            if re.match(r"^[0-9A-Fa-f]{5,}\*?\s", l))
        if count >= crit:
            return CheckResult(CRIT, "邮件队列严重积压：**%d 封**（阈值 %d）—— "
                                     "告警通道可能已堵塞，后续告警将无法送达。"
                               % (count, crit))
        if count >= warn:
            return CheckResult(WARN, "邮件队列积压：%d 封（阈值 %d）"
                               % (count, warn))
        return CheckResult(OK, "邮件队列正常（%d 封）" % count)


@register
class BackupAge(Check):
    id = "backup_age"
    label = "备份时效"
    label_en = "Backup age"
    group = G_OPS
    description = "最近备份是否过旧或缺失（备份路径由 checks.backup.globs 配置）"

    def run(self, ctx: CheckContext) -> CheckResult:
        warn_h = float(ctx.copt("backup", "warn_hours", 36))
        crit_h = float(ctx.copt("backup", "crit_hours", 72))

        patterns = [str(g) for g in (ctx.copt("backup", "globs", []) or []) if g]
        if not patterns:
            return CheckResult(OK, "未配置备份路径（checks.backup.globs 为空），"
                                   "跳过备份时效检查")
        paths = util.expand_globs(patterns)
        if not paths:
            return CheckResult(WARN, "备份路径未匹配到任何文件或目录：%s —— "
                                     "请确认备份任务是否仍在执行"
                               % "、".join(patterns[:4]))

        newest, newest_mtime = "", 0.0
        for path in paths:
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                continue
            if mtime > newest_mtime:
                newest, newest_mtime = path, mtime
        if not newest:
            return CheckResult(WARN, "备份路径存在但无法读取修改时间：%s"
                               % "、".join(paths[:4]))
        age_h = (ctx.now - newest_mtime) / 3600.0
        human = util.human_seconds(age_h * 3600)
        if age_h >= crit_h:
            return CheckResult(CRIT, "最近备份已过期 **%s**（阈值 %.0f 小时）：%s\n"
                                     "       一旦发生数据损坏或误删将无法恢复到近期状态，"
                                     "请尽快补做一次完整备份。"
                               % (human, crit_h, newest))
        if age_h >= warn_h:
            return CheckResult(WARN, "最近备份偏旧：%s（阈值 %.0f 小时）：%s"
                               % (human, warn_h, newest))
        return CheckResult(OK, "最近备份于 %s 前（%s）" % (human, newest))


@register
class Certificates(Check):
    id = "certificates"
    label = "SSL 证书"
    label_en = "SSL certificates"
    group = G_OPS
    heavy = True
    description = "扫描证书目录，报告即将过期的 SSL 证书"

    def run(self, ctx: CheckContext) -> CheckResult:
        warn_days = float(ctx.copt("certificates", "warn_days", 21))
        crit_days = float(ctx.copt("certificates", "crit_days", 7))

        dirs = self._dirs(ctx)
        if not dirs:
            return CheckResult(OK, "未配置/未发现证书目录，跳过证书检查")
        if not shell.have("openssl"):
            return CheckResult(WARN, "未安装 openssl，无法检查证书有效期"
                                     "（证书目录：%s）" % "、".join(dirs[:3]))

        checked, results = 0, []
        for base in dirs:
            for path in self._files(base):
                days = self._days_left(path)
                if days is None:
                    continue
                checked += 1
                results.append((days, path))
        if not checked:
            return CheckResult(OK, "证书目录中未找到可解析的证书文件"
                                   "（已检查 %d 个目录）" % len(dirs))

        results.sort(key=lambda x: x[0])
        worst_days = results[0][0]
        soon = ["%s（剩 %.0f 天）" % (path, days)
                for days, path in results if days <= warn_days]
        if worst_days <= crit_days:
            return CheckResult(CRIT,
                               "SSL 证书即将到期（阈值 %.0f 天）：\n       %s\n"
                               "       到期后浏览器会显示安全警告并可能阻断访问，"
                               "API 调用也会因证书校验失败而中断，请立即续期。"
                               % (crit_days, "\n       ".join(soon[:8])))
        if soon:
            return CheckResult(WARN, "SSL 证书临近到期（阈值 %.0f 天）：\n       %s"
                               % (warn_days, "\n       ".join(soon[:8])))
        return CheckResult(OK, "已检查 %d 张证书，最早到期还剩 %.0f 天"
                           % (checked, worst_days))

    @staticmethod
    def _dirs(ctx: CheckContext) -> list:
        dirs = [str(d) for d in (ctx.copt("certificates", "dirs", []) or []) if d]
        panel = ctx.env.get("bt_panel") or {}
        if panel.get("present") and panel.get("dir"):
            dirs.append(os.path.join(str(panel["dir"]), "vhost", "cert"))
        dirs.append("/etc/letsencrypt/live")
        out = []
        for d in dirs:
            if os.path.isdir(d) and d not in out:
                out.append(d)
        return out

    @staticmethod
    def _files(base: str) -> list:
        out, seen = [], set()
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            for name in filenames:
                if name not in ("fullchain.pem", "cert.pem"):
                    continue
                path = os.path.join(dirpath, name)
                try:
                    real = os.path.realpath(path)
                except OSError:
                    real = path
                if real in seen:
                    continue
                seen.add(real)
                out.append(path)
        return out

    @staticmethod
    def _days_left(path: str):
        ok, out, _err = shell.run(
            ["openssl", "x509", "-enddate", "-noout", "-in", path], timeout=15)
        if not ok:
            return None
        m = re.search(r"notAfter=(.+)", out)
        if not m:
            return None
        try:
            when = datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
            expires = calendar.timegm(when.timetuple())
        except ValueError:
            return None
        return (expires - time.time()) / 86400.0


@register
class RebootDetected(Check):
    id = "reboot"
    label = "系统重启"
    label_en = "System reboot"
    group = G_OPS
    stateful = True
    description = "通过 /proc/uptime 回退判断系统是否发生过重启"

    def run(self, ctx: CheckContext) -> CheckResult:
        try:
            min_drop = float(ctx.copt("reboot", "min_drop_seconds", 60) or 60)
        except (TypeError, ValueError):
            min_drop = 60.0

        uptime = util.uptime_seconds()
        prev = ctx.snapshot("uptime", uptime)
        if uptime <= 0:
            return CheckResult(OK, "无法读取 /proc/uptime，跳过重启检测")
        if prev is not None and uptime < float(prev) - min_drop:
            return CheckResult(EVENT,
                               "检测到系统重启：重启前已运行 %s，当前已运行 %s。\n"
                               "       若非你本人操作，可能意味着内核崩溃、硬件故障"
                               "或被强制重启，请核对 `last reboot` 与内核日志。"
                               % (util.human_seconds(prev), util.human_seconds(uptime)))
        return CheckResult(OK, "系统已运行 %s" % util.human_seconds(uptime))


@register
class OomEvents(Check):
    id = "oom"
    label = "OOM 内存杀进程"
    label_en = "OOM kills"
    group = G_OPS
    description = "近一段时间内核是否因内存耗尽强制杀进程"

    def run(self, ctx: CheckContext) -> CheckResult:
        try:
            window = int(ctx.copt("oom", "window_minutes", 10) or 10)
        except (TypeError, ValueError):
            window = 10

        lines, source = [], ""
        if shell.have("journalctl"):
            ok, out, _err = shell.run(
                ["journalctl", "-k", "--since", "%d min ago" % window,
                 "--no-pager"], timeout=25)
            if ok:
                source = "journalctl"
                lines = [l for l in out.splitlines()
                         if any(k in l for k in _OOM_MARKERS)]
        if not lines and shell.have("dmesg"):
            # Only a time-filtered dmesg is safe here: an unfiltered dump can
            # contain an OOM from weeks ago and would re-alert forever.
            ok, out, _err = shell.run(
                ["dmesg", "--since", "%d min ago" % window], timeout=15)
            if ok:
                source = "dmesg"
                lines = [l for l in out.splitlines()
                         if any(k in l for k in _OOM_MARKERS)]
        if not source:
            return CheckResult(OK, "journalctl/dmesg 均不可用，跳过 OOM 检查")
        if not lines:
            return CheckResult(OK, "近 %d 分钟无 OOM 内存杀进程事件" % window)
        recent = [util.oneline(l, 160) for l in lines[-3:]]
        return CheckResult(CRIT,
                           "近 %d 分钟检测到 **%d 条** OOM 内存杀进程事件：\n       %s\n"
                           "       被杀的可能是数据库或 Web 服务，存在数据丢失与服务中断风险。"
                           % (window, len(lines), "\n       ".join(recent)))


@register
class KernelErrors(Check):
    id = "kernel_errors"
    label = "内核错误"
    label_en = "Kernel errors"
    group = G_OPS
    description = "内核日志中的错误（可能是硬件故障、驱动问题或内核级 rootkit）"

    def run(self, ctx: CheckContext) -> CheckResult:
        try:
            max_lines = int(ctx.copt("kernel_errors", "max_lines", 10) or 10)
        except (TypeError, ValueError):
            max_lines = 10

        lines, source = [], ""
        if shell.have("dmesg"):
            ok, out, _err = shell.run(
                ["dmesg", "-l", "err,crit,alert,emerg"], timeout=15)
            if ok:
                source = "dmesg"
                lines = [l for l in out.splitlines() if l.strip()]
        if not lines and shell.have("journalctl"):
            ok, out, _err = shell.run(
                ["journalctl", "-k", "-p", "err", "--no-pager", "-n", "50"],
                timeout=20)
            if ok:
                source = "journalctl"
                lines = [l for l in out.splitlines() if l.strip()]
        if not source:
            return CheckResult(OK, "dmesg/journalctl 均不可用，跳过内核错误检查")
        if len(lines) <= max_lines:
            return CheckResult(OK, "内核错误 %d 条（阈值 %d），无异常"
                               % (len(lines), max_lines))
        recent = [util.oneline(l, 150) for l in lines[-2:]]
        return CheckResult(WARN,
                           "内核错误日志 %d 条（阈值 %d），最近：\n       %s\n"
                           "       可能是硬件故障（磁盘/内存）、驱动问题，"
                           "或内核级 rootkit 活动的痕迹；反复出现同一硬件错误时请尽快排查。"
                           % (len(lines), max_lines, "\n       ".join(recent)))
