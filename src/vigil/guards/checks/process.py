"""Process and business-availability checks (group ``process``).

Ported from ``c_proc_anomaly`` / ``c_zombie`` / ``c_site``.

The original ``c_site`` hardcoded one host's domain, IP-named log file and
HTTPS probe. That is exactly the kind of value this project must not contain,
so the port reads the site identity from the config (``gate.*.domain`` or an
optional ``checks.site_availability.domain``) and the access log from
:func:`vigil.core.detect.log_sources`. When no site is configured the check
returns OK and says so instead of probing a stranger's hostname.
"""
from __future__ import annotations

import os
import re

from . import util
from .base import (CRIT, G_PROCESS, OK, WARN, Check, CheckContext,
                   CheckResult, register)
from ...core import shell

#: HTTP codes that still mean "the site answered".
_HEALTHY_CODES = ("200", "204", "301", "302", "303", "307", "308")


def _proc_count() -> int:
    try:
        return sum(1 for e in os.listdir("/proc") if e.isdigit())
    except OSError:
        return 0


# --------------------------------------------------------------------------
# Process identity and whitelisting
# --------------------------------------------------------------------------

#: Always exempt, whatever the operator configures.
#:
#: Matching on `comm` alone would be wrong here and dangerously so: every
#: daemon in this project runs as `python3` in `ps`, so a name-based
#: whitelist would exempt *all* of Python and quietly stop reporting the
#: single most likely place for hostile code to hide. These patterns are
#: matched against the command line and the executable path as well, and
#: they name this project specifically.
BUILTIN_WHITELIST = (
    "vigil",                    # the CLI and the console scripts
    "vigil-*",                  # daemon entry points
    "python3 -m vigil.*",       # daemons as they actually appear in `ps`
    "python3 -m vigil",
    "/usr/local/lib/vigil/*",   # anything running out of our own tree
    "/usr/local/bin/vigil",
)


def _proc_identity(pid: str) -> dict:
    """comm, cmdline and exe for one process, cheaply and without raising."""
    comm = cmdline = exe = ""
    try:
        with open("/proc/%s/comm" % pid, "r", encoding="utf-8",
                  errors="replace") as fh:
            comm = fh.read().strip()
    except OSError:
        pass
    try:
        with open("/proc/%s/cmdline" % pid, "rb") as fh:
            cmdline = fh.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
    except OSError:
        pass
    try:
        exe = os.readlink("/proc/%s/exe" % pid)
    except OSError:
        pass
    return {"comm": comm, "cmdline": cmdline, "exe": exe}


def _matches(identity: dict, pattern: str) -> bool:
    """Does a whitelist pattern describe this process?

    Three surfaces are checked, because any one of them alone is either too
    loose or too easy to evade by renaming: the short name, the full command
    line, and the resolved executable path.
    """
    haystacks = [identity.get("comm", ""), identity.get("cmdline", ""),
                 identity.get("exe", "")]
    pat = pattern.strip()
    if not pat:
        return False
    for text in haystacks:
        if not text:
            continue
        if "*" in pat or "?" in pat or "[" in pat:
            # Glob against the whole string and against each word, so
            # "python3 -m vigil.*" matches without needing a leading star.
            import fnmatch
            if fnmatch.fnmatch(text, pat) or fnmatch.fnmatch(text, "*" + pat):
                return True
            for word in text.split():
                if fnmatch.fnmatch(word, pat):
                    return True
        elif pat.startswith("/"):
            if text == pat or text.startswith(pat.rstrip("/") + "/"):
                return True
        elif pat in text.split() or text == pat:
            return True
    return False


def process_whitelist(ctx) -> tuple:
    """The active patterns, built-ins first. Returns ``(patterns, custom)``."""
    custom = [str(x) for x in (ctx.copt("process_anomaly", "whitelist", []) or [])
              if str(x).strip()]
    return list(BUILTIN_WHITELIST) + custom, custom


def process_detail(pid: str, cfg=None) -> list:
    """Everything worth knowing about one process, as printable lines.

    This is the "who is this and what is it doing" block. It answers the
    questions an operator actually asks when a process looks wrong: what
    binary is it really, has that binary been replaced or deleted,
    what started it, is it managed by a service, what is it listening on,
    and who is it talking to.
    """
    ident = _proc_identity(pid)
    lines = []

    exe = ident.get("exe") or "?"
    deleted = ""
    if exe.endswith(" (deleted)"):
        # A running binary whose file is gone is how a self-deleting
        # implant hides: the process keeps running from the open inode.
        deleted = "  **可执行文件已被删除（进程仍从已打开的文件继续运行，典型的自删除手法）**"
    lines.append("可执行文件: %s%s" % (exe, deleted))
    if ident.get("cmdline"):
        lines.append("完整命令行: %s" % ident["cmdline"])

    digest = _exe_digest(pid)
    if digest:
        lines.append("二进制 SHA256: %s" % digest)

    # Parent chain, up to four levels: a shell spawned by a web server is a
    # different story from one spawned by cron, and the chain is the evidence.
    chain = []
    cur = pid
    for _ in range(4):
        try:
            with open("/proc/%s/stat" % cur, "r", encoding="utf-8",
                      errors="replace") as fh:
                fields = fh.read().rsplit(")", 1)[1].split()
            ppid = fields[1]
        except (OSError, IndexError):
            break
        if ppid in ("0", ""):
            break
        p_ident = _proc_identity(ppid)
        chain.append("%s(%s)" % (p_ident.get("comm") or "?", ppid))
        cur = ppid
    if chain:
        lines.append("父进程链: %s" % " ← ".join(chain))

    unit = _cgroup_unit(pid)
    if unit:
        lines.append("所属服务: %s" % unit)

    started = _started_at(pid)
    if started:
        lines.append("启动时间: %s" % started)

    listen, conns = _sockets_of(pid)
    if listen:
        lines.append("监听端口: %s" % "、".join(listen[:6]))
    if conns:
        lines.append("对外连接: %s" % "、".join(conns[:6]))
    return lines


def _exe_digest(pid: str) -> str:
    """sha256 of the running executable, or "" if it cannot be read."""
    import hashlib
    try:
        with open("/proc/%s/exe" % pid, "rb") as fh:
            h = hashlib.sha256()
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def _cgroup_unit(pid: str) -> str:
    try:
        with open("/proc/%s/cgroup" % pid, "r", encoding="utf-8",
                  errors="replace") as fh:
            for line in fh:
                if ".service" in line:
                    tail = line.rstrip().rsplit("/", 1)[-1]
                    return tail
    except OSError:
        pass
    return ""


def _started_at(pid: str) -> str:
    ok, out, _err = shell.run(["ps", "-o", "lstart=", "-p", pid], timeout=6)
    return (out or "").strip() if ok else ""


def _sockets_of(pid: str) -> tuple:
    """Listening ports and established peers owned by this pid."""
    listen, conns = [], []
    if not (shell.have("ss") or shell.have("netstat")):
        return listen, conns
    ok, out, _err = shell.run(["ss", "-H", "-tunap"], timeout=10)
    if not ok:
        return listen, conns
    needle = "pid=%s," % pid
    for line in (out or "").splitlines():
        if needle not in line:
            continue
        fields = line.split()
        if len(fields) < 6:
            continue
        state, local, peer = fields[0], fields[3], fields[4]
        if state == "LISTEN":
            listen.append(local)
        elif state == "ESTAB" and not peer.startswith(("127.", "[::1]", "0.0.0.0")):
            conns.append("%s→%s" % (local, peer))
    return listen, conns


@register
class ProcessAnomaly(Check):
    id = "process_anomaly"
    label = "进程异常"
    label_en = "Process anomaly"
    group = G_PROCESS
    description = "高 CPU 占用进程或进程总数异常偏高，可能是故障或被入侵"

    def run(self, ctx: CheckContext) -> CheckResult:
        cpu_warn = float(ctx.copt("process_anomaly", "cpu_warn", 80))
        count_warn = int(ctx.copt("process_anomaly", "count_warn", 600) or 600)

        patterns, custom = process_whitelist(ctx)
        hot = []
        exempt = []
        downgraded = []
        # Imported inside the method on purpose: `procresponse` imports this
        # module for its whitelist, and a module-level import here would close
        # the cycle while the package is still initialising.
        from . import procresponse
        runtime = procresponse.Runtime(cfg=ctx.cfg, log=ctx.log)
        ok, out, _err = shell.run(
            ["ps", "-eo", "pcpu=,pmem=,pid=,user=,comm=", "--sort=-pcpu"],
            timeout=10)
        if ok:
            for line in out.splitlines():
                parts = line.split(None, 4)
                if len(parts) < 5:
                    continue
                try:
                    pcpu = float(parts[0])
                    pmem = float(parts[1])
                except ValueError:
                    continue
                if pcpu < cpu_warn:
                    continue
                pid, user, comm = parts[2], parts[3], parts[4]
                identity = _proc_identity(pid)
                if any(_matches(identity, pat) for pat in patterns):
                    exempt.append("%s(pid %s，CPU %.0f%%)" % (comm, pid, pcpu))
                    continue
                # A build (vue-tsc, esbuild, webpack) or a service pinned at
                # 100% is not an anomaly. Downgraded only on *structural*
                # evidence -- a systemd unit, a package-managed binary, or a
                # command line pointing at a site this host already serves --
                # never on the process merely being called `node`, because
                # `node -e <payload>` is a common way to run an implant.
                why = procresponse.runtime_downgrade(
                    pid, comm, identity.get("cmdline", ""), runtime, ctx.cfg)
                if why:
                    downgraded.append("%s(pid %s，CPU %.0f%%，%s)"
                                      % (comm, pid, pcpu, why))
                    continue
                # Detail is only gathered for processes that will actually be
                # reported: reading /proc and hashing a binary for every busy
                # process on a large host is real work for no output.
                detail = process_detail(pid, ctx.cfg)
                hot.append("%s(pid %s %s，CPU %.0f%%，内存 %.0f%%)"
                           % (comm, pid, user, pcpu, pmem))
                if detail:
                    hot.append("       " + "\n       ".join(detail))
                if len(hot) >= 24:
                    break

        total = _proc_count()
        problems = []
        if hot:
            problems.append("高占用进程（CPU ≥ %.0f%%，已排除白名单）：\n       %s"
                            % (cpu_warn, "\n       ".join(hot)))
        if exempt:
            # Reported, not hidden. An operator who sees nothing at all
            # cannot tell "nothing was wrong" from "something was filtered",
            # and a whitelist nobody can audit is how a compromise goes
            # unnoticed.
            problems.append("已按白名单跳过 %d 个高占用进程：%s"
                            % (len(exempt), "、".join(exempt[:6])))
        if downgraded:
            # Reported too, and with the reason: an automatic downgrade the
            # operator cannot audit is indistinguishable from a check that
            # stopped working.
            problems.append("已自动降级 %d 个高占用进程（结构性判据，非异常）：%s"
                            % (len(downgraded), "、".join(downgraded[:6])))
        if total >= count_warn:
            problems.append("进程总数异常偏高：%d 个（阈值 %d）—— 可能是 fork 炸弹、"
                            "服务重启风暴，或恶意程序大量派生子进程"
                            % (total, count_warn))
        if hot:
            extra = ("\n     " + "\n     ".join(problems[1:])
                     if len(problems) > 1 else "")
            return CheckResult(WARN, problems[0] + extra)
        if exempt or downgraded:
            bits = []
            if exempt:
                bits.append("%d 个高占用进程命中白名单（%s）"
                            % (len(exempt), "、".join(exempt[:4])))
            if downgraded:
                bits.append("已自动降级 %d 个（%s）"
                            % (len(downgraded), "、".join(downgraded[:4])))
            return CheckResult(OK, "进程 %d 个；%s" % (total, "；".join(bits)))
        return CheckResult(OK, "进程 %d 个，无 CPU 占用超过 %.0f%% 的进程"
                           % (total, cpu_warn))


@register
class ZombieProcesses(Check):
    id = "zombie"
    label = "僵尸进程"
    label_en = "Zombie processes"
    group = G_PROCESS
    description = "僵尸进程堆积说明父进程未正确回收子进程，长期会耗尽进程表"

    def run(self, ctx: CheckContext) -> CheckResult:
        warn = int(ctx.copt("zombie", "warn", 5) or 5)
        crit = int(ctx.copt("zombie", "crit", 20) or 20)

        zombies = []
        try:
            entries = os.listdir("/proc")
        except OSError:
            return CheckResult(OK, "无法读取 /proc，跳过僵尸进程检查")
        for pid in entries:
            if not pid.isdigit():
                continue
            try:
                with open("/proc/%s/stat" % pid, "r", encoding="utf-8") as fh:
                    data = fh.read()
                # comm may contain spaces/parens, so parse after the last ')'
                rest = data[data.rfind(") ") + 2:].split()
                if not rest or rest[0] != "Z":
                    continue
                comm = data[data.find("(") + 1:data.rfind(")")]
                ppid = rest[1] if len(rest) > 1 else "?"
            except (OSError, ValueError, IndexError):
                continue
            parent = util.proc_comm(ppid) or "?"
            zombies.append("%s(pid %s，父进程 %s(pid %s))" % (comm, pid, parent, ppid))
            if len(zombies) >= 12:
                break

        if not zombies:
            return CheckResult(OK, "无僵尸进程")
        head = "僵尸进程堆积：%d 个（阈值：警告 %d / 严重 %d）" % (len(zombies), warn, crit)
        body = "\n       ".join(zombies[:6])
        more = ("\n       …… 等 %d 项未展开" % (len(zombies) - 6)) if len(zombies) > 6 else ""
        tail = "\n     僵尸进程说明父进程未回收子进程，长期累积会耗尽进程表；" \
               "可重启父进程（`ps -eo pid,ppid,stat,comm | grep Z` 定位）。"
        if len(zombies) >= crit:
            return CheckResult(CRIT, head + "\n       " + body + more + tail)
        if len(zombies) >= warn:
            return CheckResult(WARN, head + "\n       " + body + more + tail)
        return CheckResult(OK, "僵尸进程 %d 个（低于告警阈值 %d）" % (len(zombies), warn))


@register
class SiteAvailability(Check):
    id = "site_availability"
    label = "网站可用性"
    label_en = "Site availability"
    group = G_PROCESS
    description = "通过回环地址探测站点首页，并统计访问日志里的 5xx 比例"

    def run(self, ctx: CheckContext) -> CheckResult:
        warn_pct = float(ctx.copt("site_availability", "warn_5xx_pct", 5))
        crit_pct = float(ctx.copt("site_availability", "crit_5xx_pct", 20))
        log_lines = int(ctx.copt("site_availability", "log_lines", 200) or 200)

        domain = (ctx.copt("site_availability", "domain", "") or "").strip()
        if not domain:
            domain = (ctx.cfg.get("gate.dsh_gate.domain", "") or "").strip()
        if not domain:
            domain = (ctx.cfg.get("gate.bt_panel.domain", "") or "").strip()
        if not domain:
            return CheckResult(OK, "未配置站点域名（checks.site_availability.domain 或 "
                                   "gate.*.domain），跳过网站可用性检查")

        problems = []
        status = OK

        if not shell.have("curl"):
            problems.append("未安装 curl，无法探测站点 HTTP 状态")
            status = WARN
            code = ""
        else:
            try:
                port = int(ctx.copt("site_availability", "port", 443) or 443)
            except (TypeError, ValueError):
                port = 443
            scheme = "https" if port in (443, 8443) else "http"
            ok, out, _err = shell.run(
                ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
                 "--max-time", "8",
                 "--resolve", "%s:%d:127.0.0.1" % (domain, port),
                 "-H", "Host: %s" % domain,
                 "%s://%s/" % (scheme, domain)], timeout=12)
            code = (out or "").strip() if ok else ""
            if not code or code == "000":
                status = CRIT
                problems.append("站点首页无响应（%s://%s/ 返回 %s）—— 站点可能已宕机，"
                                "请检查 nginx 与 PHP-FPM/数据库"
                                % (scheme, domain, code or "无响应"))
            elif code.startswith("5"):
                status = CRIT
                problems.append("站点首页返回 **HTTP %s**，后端服务可能已崩溃" % code)
            elif code not in _HEALTHY_CODES:
                if status == OK:
                    status = WARN
                problems.append("站点首页返回异常 HTTP %s（期望 200/3xx）" % code)

        # 5xx ratio from the tail of the first nginx access log we know about.
        logs = list((ctx.env.get("log_sources") or {}).get("nginx_access") or [])
        ratio_note = ""
        if logs:
            log = logs[0]
            codes = self._tail_codes(log, log_lines)
            if codes:
                bad = sum(1 for c in codes if c.startswith("5"))
                pct = bad * 100.0 / len(codes)
                ratio_note = "最近 %d 条请求中 5xx 占 %.1f%%（%d 条），日志 %s" % (
                    len(codes), pct, bad, log)
                if pct >= crit_pct:
                    status = CRIT
                    problems.append("网站 5xx 错误率过高：**%.1f%%**（%d/%d）"
                                    % (pct, bad, len(codes)))
                elif pct >= warn_pct:
                    if status == OK:
                        status = WARN
                    problems.append("网站 5xx 错误率偏高：%.1f%%（%d/%d）"
                                    % (pct, bad, len(codes)))

        if problems:
            return CheckResult(status, "\n     ".join(problems))
        if ratio_note:
            return CheckResult(OK, "网站正常（HTTP %s）；%s" % (code, ratio_note))
        return CheckResult(OK, "网站正常（HTTP %s，未找到可统计的访问日志）" % code)

    @staticmethod
    def _tail_codes(path, want: int) -> list:
        """HTTP status codes from the last *want* lines of an access log."""
        try:
            size = os.path.getsize(path)
            with open(path, "rb") as fh:
                fh.seek(max(0, size - 200000))
                text = fh.read().decode("utf-8", "replace")
        except OSError:
            return []
        lines = text.splitlines()[-want:]
        return re.findall(r'"\s+(\d{3})\s', "\n".join(lines))
