"""Shared helpers for checks.

Everything host-specific is resolved here from the context or from
:mod:`vigil.core.detect`; nothing below hardcodes a path belonging to one
particular distribution or control panel.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import pwd
import re
import time

from ...core import shell
from ...core.state import read_json, write_json

# --------------------------------------------------------------------------
# Small text / process utilities
# --------------------------------------------------------------------------


def oneline(s, limit: int = 160) -> str:
    """Collapse whitespace to single spaces and truncate.

    Multi-line commands and stack traces wreck the indentation of an alert
    body, so anything interpolated into a detail line goes through here.
    """
    text = re.sub(r"\s+", " ", str(s or "")).strip()
    if limit and len(text) > limit:
        text = text[:limit - 1] + "…"
    return text


def first_line(s, limit: int = 200) -> str:
    for line in str(s or "").splitlines():
        if line.strip():
            return oneline(line, limit)
    return ""


def proc_cmdline(pid) -> str:
    try:
        with open("/proc/%s/cmdline" % pid, "rb") as fh:
            raw = fh.read()
        parts = [p.decode("utf-8", "replace") for p in raw.split(b"\x00") if p]
        return oneline(" ".join(parts), 200)
    except OSError:
        return ""


def proc_comm(pid) -> str:
    try:
        with open("/proc/%s/comm" % pid, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def proc_alive(pid) -> bool:
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if os.path.isdir("/proc/%d" % pid):
        return True
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def proc_exe(pid) -> str:
    try:
        return os.readlink("/proc/%s/exe" % pid)
    except OSError:
        return ""


def proc_ppid(pid) -> int:
    try:
        with open("/proc/%s/stat" % pid, "r", encoding="utf-8") as fh:
            data = fh.read()
        # comm may contain spaces and parens, so split after the last ')'
        return int(data.rsplit(") ", 1)[1].split()[1])
    except (OSError, IndexError, ValueError):
        return 0


def process_chain(pid, depth: int = 3) -> list:
    """Walk up the parent chain, nearest first."""
    chain = []
    cur = pid
    for _ in range(depth):
        try:
            cur = int(cur)
        except (TypeError, ValueError):
            break
        if cur <= 1:
            break
        comm, cmd = proc_comm(cur), proc_cmdline(cur)
        if not comm and not cmd:
            break
        chain.append({"pid": cur, "comm": comm, "cmdline": cmd})
        cur = proc_ppid(cur)
    return chain


def user_name(uid) -> str:
    """Map a uid to a name, labelling the kernel 'unset' sentinel clearly."""
    if str(uid) in ("4294967295", "-1", "", "None"):
        return "无登录会话" if _zh() else "no login session"
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except (KeyError, ValueError, TypeError):
        return str(uid)


def _zh() -> bool:
    from ...i18n import language
    return language() == "zh"


def top_procs(by: str = "cpu", n: int = 3) -> list:
    """Top processes by CPU or RSS, from ps. Returns formatted strings."""
    key = "pcpu" if by == "cpu" else "pmem"
    ok, out, _ = shell.run(
        ["ps", "-eo", "pcpu=,pmem=,rss=,comm=,args=", "--sort=-%s" % key],
        timeout=10)
    if not ok:
        return []
    rows = []
    for line in out.splitlines()[1:]:
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        try:
            cpu = float(parts[0])
        except ValueError:
            continue
        if by == "cpu" and cpu < 1.0:
            continue
        rows.append("%s (CPU %.1f%% / 常驻 %.0fMB)" % (
            oneline(parts[4], 70), cpu, _kb(parts[2])))
        if len(rows) >= n:
            break
    return rows


def _kb(value) -> float:
    try:
        return int(value) / 1024.0
    except (TypeError, ValueError):
        return 0.0


def port_owner(port) -> str:
    """Which process listens on *port*."""
    ok, out, _ = shell.run(["ss", "-tlnpH"], timeout=10)
    if not ok:
        return ""
    needle = ":%s " % port
    for line in out.splitlines():
        if needle in line:
            m = re.search(r'users:\(\("([^"]+)"', line)
            return m.group(1) if m else oneline(line, 90)
    return ""


def listening_ports() -> list:
    """Currently listening TCP/UDP sockets as ``proto:addr:port`` strings."""
    ports = []
    for flag, proto in (("-tlnH", "tcp"), ("-ulnH", "udp")):
        ok, out, _ = shell.run(["ss", flag], timeout=10)
        if not ok:
            continue
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            local = parts[3]
            ports.append("%s %s" % (proto, local))
    return sorted(set(ports))


# --------------------------------------------------------------------------
# File integrity
# --------------------------------------------------------------------------


def file_digest(path) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def file_sig(path) -> str:
    """``sha256:inode`` fingerprint.

    The inode matters as much as the content: an unchanged inode means the
    file was edited in place, a changed one means it was replaced wholesale
    (write-temp-then-rename). Telling those apart is usually the difference
    between "the package manager updated this" and "someone swapped it".
    """
    try:
        st = os.stat(path)
    except OSError:
        return "missing"
    return "%s:%d" % (file_digest(path), st.st_ino)


def sig_parts(sig: str):
    """Split a :func:`file_sig` value into (hash, inode)."""
    if not sig or ":" not in sig:
        return sig, ""
    h, _, inode = sig.rpartition(":")
    return h, inode


# --------------------------------------------------------------------------
# auditd attribution
# --------------------------------------------------------------------------


def audit_attribution(cfg, basenames, since_ts=None) -> dict:
    """Who touched these files, according to auditd.

    Returns ``{basename: [lines]}``. Several quirks of ``ausearch`` are
    load-bearing here, each of which produced silently empty output until it
    was handled:

    * it reads *stdin* instead of the logs when stdin is a pipe, so
      ``--input-logs`` is mandatory (our shell helper always passes
      ``DEVNULL``, which makes stdin effectively a pipe);
    * on the ausearch versions seen in the wild, an explicit ``-ts <date>``
      can return zero rows even for dates that definitely have events, so we
      ask for ``today``/``recent`` and filter on epoch ourselves;
    * records are emitted oldest first, so the *last* match for a file is
      the most recent writer and must win.
    """
    if not basenames:
        return {}
    key = cfg.get("auditd.key", "vigil_watch")
    ok, out, _ = shell.run(
        ["ausearch", "--input-logs", "-k", key, "-ts", "today"], timeout=25)
    if not ok or not out:
        ok, out, _ = shell.run(
            ["ausearch", "--input-logs", "-k", key, "-ts", "recent"], timeout=25)
    if not ok or not out:
        return {}

    floor = 0.0
    if since_ts:
        try:
            floor = float(since_ts)
        except (TypeError, ValueError):
            floor = 0.0
    want = set(basenames)
    found: dict = {}

    for block in out.split("----"):
        if "type=SYSCALL" not in block:
            continue
        if floor:
            m = re.search(r"audit\((\d+)(?:\.\d+)?:", block)
            if m and float(m.group(1)) < floor:
                continue

        def g(k):
            m = re.search(r'\b%s=(?:"([^"]*)"|(\S+))' % k, block)
            return (m.group(1) or m.group(2)) if m else ""

        names = [os.path.basename(x)
                 for x in re.findall(r'name="([^"]+)"', block)]
        hit = [n for n in names if n in want]
        if not hit:
            continue

        comm, exe, pid, ppid = g("comm"), g("exe"), g("pid"), g("ppid")
        auid, uid = g("auid"), g("uid")

        cmd = proc_cmdline(pid) if pid else ""
        if not cmd:
            m = re.search(r"proctitle=([0-9A-Fa-f]+)", block)
            if m:
                try:
                    cmd = " ".join(
                        x.decode("utf-8", "replace")
                        for x in bytes.fromhex(m.group(1)).split(b"\x00") if x)
                except (ValueError, TypeError):
                    cmd = ""

        lines = ["进程: %s%s" % (comm or "?",
                                "（仍在运行）" if proc_alive(pid) else "（已退出）")]
        # `python3 -` / `sh -c` read their program from stdin, so the
        # command line itself explains nothing. Say so explicitly and lean
        # on the surrounding evidence instead.
        if cmd and re.search(r"(-|/dev/stdin)$", cmd.strip()):
            lines.append("命令: %s  ← 该进程从标准输入读取代码，"
                         "命令行本身无法说明它在做什么" % oneline(cmd, 120))
        elif cmd:
            lines.append("命令: %s" % oneline(cmd, 160))
        if exe:
            lines.append("程序: %s" % exe)
        if pid:
            lines.append("PID: %s" % pid)
        for depth, frame in enumerate(process_chain(ppid, 2)):
            tag = "父进程" if depth == 0 else "上层调用"
            lines.append("%s: %s(pid %s)%s" % (
                tag, frame["comm"] or "?", frame["pid"],
                ("  " + oneline(frame["cmdline"], 110)) if frame["cmdline"] else ""))
        mc = re.search(r'type=CWD.*?cwd="([^"]*)"', block)
        if mc:
            lines.append("工作目录: %s" % mc.group(1))
        lines.append("用户: 操作用户=%s  有效用户=%s  %s" % (
            user_name(auid), user_name(uid),
            "登录会话发起" if auid not in ("4294967295", "", "-1")
            else "非登录会话（服务/定时任务）"))
        # Last write wins: ausearch is chronological and the newest writer
        # is the one that matters. setdefault would keep the oldest.
        for n in hit:
            found[n] = lines
    return found


# --------------------------------------------------------------------------
# Suspicious process detection
# --------------------------------------------------------------------------


#: Executable basenames that are browsers or their headless builds.
_BROWSER_BINARIES = frozenset({
    "chrome", "chromium", "chromium-browser", "headless_shell",
    "chrome-headless-shell", "chrome_crashpad_handler", "firefox",
    "firefox-bin", "msedge", "msedgewebview2", "opera", "brave",
})

#: A path component naming a browser *distribution layout*, as opposed to a
#: random directory. Playwright/Puppeteer/Selenium unpack a versioned release
#: and run the binary from inside it, so the parents are named things like
#: ``chromium-1234``, ``chrome-linux64``, ``browsers``, ``ms-playwright``.
#: This is structure, not a fixed path: the same names appear on any host.
_BROWSER_LAYOUT_RX = re.compile(
    r"^(?:browsers?|ms-playwright|playwright|puppeteer"
    r"|(?:chromium|chrome|firefox|headless[_-]?shell|chrome[_-]headless[_-]shell)"
    r"(?:[-_.][\w.]*)?)$", re.I)

#: Runtimes that legitimately drive a browser unpacked into a temp dir.
#: Deliberately does *not* include shells, perl or php: a browser bundle
#: started by ``bash -c`` is exactly the shape that should keep warning.
#: Matched against an ancestor's ``comm`` or the basename of its argv[0], so
#: Node's ``node-MainThread`` counts as ``node``.
_AUTOMATION_RUNTIME_RX = re.compile(
    r"^(?:node|nodejs|npm|npx|yarn|pnpm|bun|deno"
    r"|python3?(?:\.\d+)?|java|dotnet|ruby"
    r"|playwright|puppeteer|pytest|jest|mocha|vitest|karma|selenium"
    r"|webdriver|chromedriver|geckodriver|msedgedriver|electron"
    r")(?:[-_.].*)?$", re.I)


def _automation_frame(frame) -> bool:
    """Is this process one of the runtimes that drives headless browsers?"""
    comm = str(frame.get("comm") or "")
    first = ""
    cmdline = str(frame.get("cmdline") or "")
    if cmdline:
        first = os.path.basename(cmdline.split(" ")[0])
    return any(c and _AUTOMATION_RUNTIME_RX.match(c) for c in (comm, first))


def browser_automation(pid, exe: str, depth: int = 6) -> str:
    """Describe *exe* as a browser-automation bundle, or ``""`` if it is not.

    A browser automation tool downloads a browser *release* into a temp
    directory and runs it from there. By path alone that is the same shape as
    "a binary executing out of /tmp", which is a real malware signature -- so
    every automation run tripped the check.

    The exemption is structural, never path-specific. All three must hold:

      * the executable's basename is a known browser binary, **and**
      * some parent directory of it names a browser distribution layout
        (``chromium-<version>``, ``chrome-linux64``, ``browsers``, ...),
        **and**
      * an ancestor process is a known automation runtime (node, python,
        playwright, a webdriver, ...).

    All three, not any one: an arbitrary ELF dropped in ``/tmp`` still warns,
    a browser binary outside a release layout still warns, and a real browser
    bundle launched by a shell still warns. Only the shape that automation
    actually produces is downgraded.
    """
    name = os.path.basename(str(exe).rstrip("/"))
    if name.lower() not in _BROWSER_BINARIES:
        return ""
    parts = [p for p in str(exe).split("/") if p]
    if not any(_BROWSER_LAYOUT_RX.match(p) for p in parts[:-1]):
        return ""
    for frame in process_chain(pid, depth):
        if _automation_frame(frame):
            return ("疑似自动化工具链：%s 浏览器发行包，由 %s(pid %s) 驱动"
                    % (name, frame.get("comm") or "?", frame.get("pid")))
    return ""


def suspect_procs_detail(tmp_dirs=("/tmp", "/var/tmp", "/dev/shm")) -> list:
    """Suspicious processes as dicts.

    Each hit is ``{pid, comm, exe, kind, automation}``. ``kind`` is
    ``"deleted"`` (the binary is gone from disk) or ``"temp"`` (running out of
    a temp dir); ``automation`` is a non-empty description when the temp-dir
    hit matches a browser-automation bundle. Only the temp-dir branch can be
    downgraded -- a genuinely deleted binary is never "probably fine".
    """
    hits = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        exe = proc_exe(pid)
        if not exe:
            continue
        comm = proc_comm(pid)
        if "(deleted)" in exe:
            real = exe.replace(" (deleted)", "")
            # A service that replaced its own binary on disk (package
            # upgrade, panel self-update) leaves the same pattern. Only flag
            # it when the path is genuinely gone.
            if not os.path.exists(real):
                hits.append({"pid": int(pid), "comm": comm, "exe": real,
                             "kind": "deleted", "automation": ""})
        elif any(exe.startswith(d.rstrip("/") + "/") for d in tmp_dirs):
            hits.append({"pid": int(pid), "comm": comm, "exe": exe,
                         "kind": "temp",
                         "automation": browser_automation(pid, exe)})
    return hits


def suspect_line(hit: dict) -> str:
    """One human-readable line for a :func:`suspect_procs_detail` hit."""
    if hit.get("kind") == "deleted":
        return ("%s(pid %s) 可执行文件已被删除且磁盘上不存在: %s"
                % (hit.get("comm") or "?", hit.get("pid"), hit.get("exe")))
    return ("%s(pid %s) 从临时目录运行: %s"
            % (hit.get("comm") or "?", hit.get("pid"), hit.get("exe")))


def suspect_procs(tmp_dirs=("/tmp", "/var/tmp", "/dev/shm")) -> list:
    """Every raw hit as a string, automation bundles included.

    Kept as the text-only view of :func:`suspect_procs_detail`; callers that
    need to tell an automation bundle from a payload should use the detail
    version, which carries the ``automation`` tag.
    """
    return [suspect_line(h) for h in suspect_procs_detail(tmp_dirs)]


# --------------------------------------------------------------------------
# Web content scanning
# --------------------------------------------------------------------------

WEB_SCAN_EXT = (".php", ".phtml", ".php5", ".php7", ".phar", ".inc")
WEB_SCAN_SKIP_DIRS = frozenset({
    "node_modules", ".git", "vendor", "cache", "logs", "log", "runtime",
    "storage", "tmp", "tests", "locale", "examples", "docs", "doc",
})

# Dangerous sinks: something that turns a string into code or a command.
# The negative lookbehind excludes *method* calls -- `$pdo->exec()` is not
# PHP's `exec()` and flagging it produces instant false positives.
WS_EXEC = re.compile(
    r"(?<!->)(?<!::)\b(eval|assert|system|shell_exec|passthru|popen|proc_open"
    r"|pcntl_exec|create_function|exec|call_user_func_array)\s*\(")
WS_SUPER = r"\$_(POST|GET|REQUEST|COOKIE|FILES|SERVER)\b"
WS_OBF = re.compile(
    r"base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|convert_uudecode"
    r"|\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}|chr\s*\(\s*\d+\s*\)\s*\.")
WS_DYN = re.compile(r"\$\$[A-Za-z_]|\{\$\{")
WS_BAD = re.compile(r"preg_replace\s*\(\s*['\"][^'\"]*/e|"
                    r"(?:eval|assert)\s*\(\s*\$_")
# Lightweight taint tracking. Real shells almost never write $_POST straight
# into the sink; they assign first:
#     $c = $_POST['c']; shell_exec($c);
#     $f = $_POST['f']; $f();
# Without this, the two most common shapes are missed.
TAINT_ASSIGN = re.compile(r"\$([A-Za-z_]\w*)\s*=\s*[^;\n]{0,120}?" + WS_SUPER)
VARFUNC = re.compile(r"(?<!->)(?<!::)\$([A-Za-z_]\w*)\s*\(")
WS_ESCAPED = re.compile(r"escapeshellarg\s*\(|escapeshellcmd\s*\(")


def webscan_files(root) -> list:
    out = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames
                       if d not in WEB_SCAN_SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if fn in (".htaccess", ".user.ini") or fn.lower().endswith(WEB_SCAN_EXT):
                out.append(os.path.join(dirpath, fn))
    return out


def _flow_to_exec(window: str, tainted) -> str:
    if re.search(WS_SUPER, window):
        return "超全局变量"
    for v in tainted:
        if re.search(r"\$%s\b" % re.escape(v), window):
            return "变量 $%s" % v
    return ""


def scan_web_content(path, max_bytes: int = 512 * 1024):
    """Heuristically score one file. Returns ``(score, reasons)``.

    Scoring rather than keyword matching, because ``eval`` and
    ``base64_decode`` appear constantly in legitimate code. The signal is
    *external input reaching a sink*, which is why the taint pass exists.
    """
    try:
        if os.path.getsize(path) > max_bytes:
            return 0, []
        with open(path, "rb") as fh:
            txt = fh.read().decode("utf-8", "replace")
    except OSError:
        return 0, []

    score, why = 0, []
    escaped = bool(WS_ESCAPED.search(txt))
    has_obf = bool(WS_OBF.search(txt))
    tainted = {m.group(1) for m in TAINT_ASSIGN.finditer(txt)}

    flow = ""
    for m in WS_EXEC.finditer(txt):
        flow = _flow_to_exec(txt[m.end():m.end() + 200], tainted)
        if flow:
            break

    if WS_BAD.search(txt):
        score += 6
        why.append("eval/assert 直接执行外部输入，或 preg_replace 使用 /e 修饰符")
    if flow:
        score += 7
        why.append("外部输入（%s）流进执行函数实参" % flow)
        if escaped:
            score -= 4
            why.append("（全文使用了 escapeshellarg/escapeshellcmd，已降权）")

    vf = ""
    for m in VARFUNC.finditer(txt):
        if m.group(1) in tainted:
            vf = m.group(1)
            break
    if vf:
        score += 8
        why.append("变量函数后门：$%s 由外部输入赋值后被当作函数调用" % vf)

    if has_obf and (flow or vf):
        score += 3
        why.append("编码/混淆 + 输入可达执行点")
    elif has_obf and re.search(r"(eval|assert)\s*\(", txt):
        score += 3
        why.append("编码/混淆紧邻代码执行函数")
    if WS_DYN.search(txt):
        score += 3
        why.append("变量变量写法")

    base = os.path.basename(path)
    if base in (".htaccess", ".user.ini") and re.search(
            r"auto_(prepend|append)_file", txt, re.I):
        score += 6
        why.append("通过 auto_prepend/append_file 自动加载外部 PHP（后门持久化）")
    return score, why


# --------------------------------------------------------------------------
# GeoIP (optional, cached, never blocks a check)
# --------------------------------------------------------------------------

_GEO_MEM: dict = {}


#: Address space that is not a real remote source, with the RFC that says so.
#:
#: This exists because the tool used to report whatever the lookups returned
#: for such an address, and the lookups returned nonsense. Asked about
#: 198.51.100.90 -- a documentation address that cannot be routed on the
#: public internet -- the geo service answered "Bucharest, Romania", whois
#: produced an IANA abuse address that does not accept reports, and the
#: no-PTR heuristic announced a trait of "home broadband and abused VPSes".
#: All of it was presented as fact about an attacker.
#:
#: A tool that manufactures confident detail about an address that has no
#: location, no owner and no abuse desk is worse than one that says nothing:
#: it sends the operator to complain to IANA about a test fixture. So these
#: ranges short-circuit every lookup and are reported for what they are.
_SPECIAL = (
    ("192.0.2.0/24", "RFC 5737 TEST-NET-1", "文档与示例专用"),
    ("198.51.100.0/24", "RFC 5737 TEST-NET-2", "文档与示例专用"),
    ("203.0.113.0/24", "RFC 5737 TEST-NET-3", "文档与示例专用"),
    ("198.18.0.0/15", "RFC 2544", "网络设备基准测试专用"),
    ("100.64.0.0/10", "RFC 6598", "运营商级 NAT（共享地址，封禁会误伤大量用户）"),
    ("10.0.0.0/8", "RFC 1918", "内网地址"),
    ("172.16.0.0/12", "RFC 1918", "内网地址"),
    ("192.168.0.0/16", "RFC 1918", "内网地址"),
    ("169.254.0.0/16", "RFC 3927", "链路本地地址"),
    ("127.0.0.0/8", "RFC 1122", "环回地址"),
    ("0.0.0.0/8", "RFC 1122", "“本网络”保留地址"),
    ("192.0.0.0/24", "RFC 6890", "IETF 协议专用地址"),
    ("192.88.99.0/24", "RFC 7526", "6to4 中继保留地址"),
    ("240.0.0.0/4", "RFC 1112", "保留地址，不可能作为来源出现"),
    ("255.255.255.255/32", "RFC 919", "受限广播地址"),
    ("2001:db8::/32", "RFC 3849", "IPv6 文档与示例专用"),
    ("fc00::/7", "RFC 4193", "IPv6 唯一本地地址"),
    ("fe80::/10", "RFC 4291", "IPv6 链路本地地址"),
    ("::1/128", "RFC 4291", "IPv6 环回地址"),
    ("ff00::/8", "RFC 4291", "IPv6 组播地址"),
)


def special_address(ip: str):
    """``(rfc, note)`` when *ip* is not a real remote source, else ``None``.

    "Real remote source" is the question that matters. A packet in a log can
    only have come from somewhere routable, so a reserved address in a log
    means one of: the log was synthesised, the pipeline rewrote addresses
    for privacy, or something upstream is fabricating traffic. All three are
    worth telling the operator, and none of them is an attacker in Romania.
    """
    text = (ip or "").strip()
    if not text:
        return None
    try:
        import ipaddress as _ip
        addr = _ip.ip_address(text.split("%")[0])
    except ValueError:
        return None
    for cidr, rfc, note in _SPECIAL:
        try:
            net = _ip.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if addr.version == net.version and addr in net:
            return rfc, note
    return None


def special_address_text(ip: str) -> str:
    """One line explaining why this address is not a real source."""
    found = special_address(ip)
    if not found:
        return ""
    rfc, note = found
    return ("%s —— 保留地址（%s，%s），不可能来自真实网络。"
            "请核查这条日志是不是测试数据、脱敏占位地址或上游伪造。"
            % (ip, rfc, note))


def reverse_dns(ip: str, timeout: float = 3.0) -> str:
    """PTR record for an address, or "" when there is none.

    The single most useful extra field for triage. An ASN says "this is a
    cloud provider"; a PTR says "this is `scan-12.shodan.io`" or
    `ec2-...amazonaws.com`, which is what actually tells an operator in one
    glance what they are dealing with. Absent for most residential and
    scanner ranges, and that absence is itself informative.
    """
    ip = (ip or "").strip()
    if not ip:
        return ""
    if ip.startswith(("127.", "10.", "192.168.", "169.254.", "::1", "fe80:")):
        return ""
    try:
        if shell.have("dig"):
            ok, out, _err = shell.run(["dig", "+short", "-x", ip], timeout=timeout)
            if ok:
                for line in (out or "").splitlines():
                    line = line.strip().rstrip(".")
                    if line and not line.startswith(";"):
                        return line
            return ""
        import socket
        name = socket.gethostbyaddr(ip)[0]
        return (name or "").rstrip(".")
    except Exception:                                  # noqa: BLE001
        return ""


def ip_profile(cfg, ip: str) -> dict:
    """Structured intelligence about an address, from several angles.

    One lookup is not enough to be precise. `ip-api` gives a city and an ISP,
    which is often the *registered* location of a hosting company rather than
    where the traffic came from, and it says nothing about who to complain
    to. This gathers what is cheap and reliable and keeps it in one place:

      · geo/ASN, plus the proxy / hosting / mobile flags -- a "mobile" hit is
        a phone on a carrier NAT, which changes what a ban means entirely;
      · the announcement block and its abuse contact, from `whois`. That is
        the difference between "somewhere in the Netherlands" and "report it
        to abuse@transip.nl";
      · the PTR, which is what actually names the operator.
    """
    from ...core import paths
    ip = (ip or "").strip()
    out = {"ip": ip, "geo": "", "ptr": "", "flags": [], "net": "",
           "netname": "", "abuse": "", "country": "", "asn": ""}
    if not ip:
        return out

    # Before the cache and before any network call. A cached bad answer from
    # an earlier run would otherwise keep coming back for 30 days.
    found = special_address(ip)
    if found:
        rfc, note = found
        out["special"] = "%s（%s，%s）" % (ip, rfc, note)
        return out

    cache = read_json(paths.GEOIP_CACHE, {}) or {}
    entry = cache.get(ip) if isinstance(cache.get(ip), dict) else None
    now = time.time()
    if entry and (now - entry.get("t", 0)) < 30 * 86400 and entry.get("p"):
        return dict(entry["p"], ip=ip)

    # -- geo + flags ----------------------------------------------------
    ok, raw, _err = shell.run(
        ["curl", "-fsS", "--max-time", "5",
         "http://ip-api.com/json/%s?lang=zh-CN&fields=status,message,country,"
         "countryCode,regionName,city,isp,org,as,asname,reverse,proxy,hosting,"
         "mobile,timezone,query" % ip], timeout=7)
    if ok and (raw or "").strip().startswith("{"):
        try:
            d = json.loads(raw)
            if d.get("status") == "success":
                bits = [b for b in (d.get("country"), d.get("regionName"),
                                    d.get("city")) if b]
                isp = d.get("isp") or d.get("org") or ""
                asn = d.get("as") or ""
                tail = " · ".join(x for x in (isp, asn) if x)
                out["geo"] = "（%s）" % " · ".join(
                    x for x in (" ".join(bits), tail) if x)
                out["country"] = d.get("countryCode") or ""
                out["asn"] = asn
                out["ptr"] = (d.get("reverse") or "").strip()
                for key, label in (("hosting", "数据中心/托管"),
                                   ("proxy", "代理/VPN"),
                                   ("mobile", "移动网络")):
                    if d.get(key):
                        out["flags"].append(label)
        except (ValueError, KeyError):
            pass

    if not out["ptr"]:
        out["ptr"] = reverse_dns(ip)

    # -- network block and abuse contact --------------------------------
    if shell.have("whois"):
        wcache = (cache.get(ip) or {}).get("w") if entry else None
        if isinstance(wcache, dict) and (now - wcache.get("t", 0)) < 90 * 86400:
            out.update({k: wcache.get(k, "") for k in ("net", "netname", "abuse")})
        else:
            ok2, raw2, _e2 = shell.run(["whois", ip], timeout=12)
            if ok2 and raw2:
                net = netname = abuse = ""
                for line in raw2.splitlines():
                    low = line.lower()
                    key, _, val = line.partition(":")
                    key = key.strip().lower()
                    val = val.strip()
                    if not val:
                        continue
                    if key in ("cidr", "inetnum", "netrange") and not net:
                        net = val
                    elif key in ("netname", "orgname", "descr") and not netname:
                        netname = val[:60]
                    elif "abuse" in key and "email" in key and not abuse:
                        abuse = val
                    elif key in ("orgabuseemail", "abuse-mailbox") and not abuse:
                        abuse = val
                out.update({"net": net, "netname": netname, "abuse": abuse})
            if entry is None:
                entry = {}
            entry["w"] = {"net": out["net"], "netname": out["netname"],
                          "abuse": out["abuse"], "t": now}

    # -- persist --------------------------------------------------------
    payload = {k: v for k, v in out.items() if k != "ip"}
    cache[ip] = dict(entry or {}, t=now, p=payload)
    if len(cache) > 5000:
        for k in sorted(cache, key=lambda k: (cache[k] or {}).get("t", 0))[:2000]:
            cache.pop(k, None)
    try:
        write_json(paths.GEOIP_CACHE, cache, mode=0o640)
    except Exception:                                  # noqa: BLE001
        pass
    return out


def ip_dossier(cfg, ip: str) -> list:
    """Everything known about an address, as printable lines.

    Built for the moment an alert is read: who is this, where from, have we
    seen them before, and what did they do.
    """
    ip = (ip or "").strip()
    if not ip:
        return []
    p = ip_profile(cfg, ip)
    if p.get("special"):
        # No location, no owner, no abuse desk. Reporting anything here would
        # be fabrication, and the fabrication is the kind an operator acts
        # on: complaining to IANA about a Romanian attacker that never
        # existed.
        lines = ["地址: %s" % p["special"],
                 "说明: 该地址不在可公网路由的地址空间内，因此没有地理位置、"
                 "归属机构或滥用联系人 —— 这些信息对它没有意义。",
                 "判断: 日志里出现保留地址，说明这条记录很可能来自测试数据、"
                 "脱敏占位或上游伪造，而不是一次真实的外部访问。"]
        try:
            from .. import threat as _threat
            hist = _threat.ban_history(ip)
        except Exception:                              # noqa: BLE001
            hist = None
        if hist:
            lines.append("历史: %s" % hist)
        return lines
    lines = ["地址: %s%s" % (ip, p["geo"])]
    if p["ptr"]:
        lines.append("反向解析(PTR): %s" % p["ptr"])
    else:
        lines.append("反向解析(PTR): 无 —— 家庭宽带、被滥用的 VPS 与扫描器的常见特征")
    if p["net"] or p["netname"]:
        block = p["net"] or "?"
        if p["netname"]:
            block += "（%s）" % p["netname"]
        lines.append("所属网段: %s" % block)
    if p["flags"]:
        # Changes what a ban means. A carrier-NAT mobile address may be
        # shared by thousands of people, so banning it punishes bystanders;
        # a hosting address that is scanning you is almost certainly rented
        # for the purpose.
        lines.append("网络性质: %s" % "、".join(p["flags"]))
    if p["abuse"]:
        lines.append("滥用举报: %s" % p["abuse"])
    else:
        lines.append("滥用举报: 未能从 whois 取得（该网段未公布滥用联系人）")
    try:
        from .. import threat as _threat
        hist = _threat.ban_history(ip)
    except Exception:                                  # noqa: BLE001
        hist = None
    if hist:
        lines.append("历史: %s" % hist)
    return lines


def geo(cfg, ip: str, timeout: float = 4.0) -> str:
    """Human summary of an IP's location/ASN, or the IP unchanged.

    Cached on disk for 30 days because alert storms involve the same
    addresses repeatedly and a rate-limited lookup service is worse than no
    lookup at all.
    """
    from ...core import paths
    ip = (ip or "").strip()
    if not ip or ip in _GEO_MEM:
        return _GEO_MEM.get(ip, ip)
    # Reserved space is answered locally and never looked up. The service
    # used to return real-looking cities for documentation addresses --
    # 198.51.100.90 came back as "Bucharest, Romania" -- and a confident
    # wrong answer is worse than none, because it reads like intelligence.
    found = special_address(ip)
    if found:
        text = "%s（%s）" % (ip, found[0])
        _GEO_MEM[ip] = text
        return text
    if ip.startswith(("127.", "10.", "192.168.", "::1", "169.254.")):
        _GEO_MEM[ip] = ip
        return ip

    cache = read_json(paths.GEOIP_CACHE, {}) or {}
    entry = cache.get(ip)
    if isinstance(entry, dict) and (time.time() - entry.get("t", 0)) < 30 * 86400:
        text = entry.get("s") or ip
        _GEO_MEM[ip] = text
        return text

    text = ip
    ok, out, _ = shell.run(
        ["curl", "-fsS", "--max-time", str(int(timeout)),
         "http://ip-api.com/json/%s?lang=zh-CN&fields=status,country,regionName,"
         "city,isp,as,query" % ip], timeout=timeout + 2)
    if ok and out.strip().startswith("{"):
        try:
            d = json.loads(out)
            if d.get("status") == "success":
                bits = [b for b in (d.get("country"), d.get("regionName"),
                                    d.get("city")) if b]
                loc = " ".join(bits)
                isp = d.get("isp") or ""
                asn = (d.get("as") or "").split()[0] if d.get("as") else ""
                tail = " · ".join(x for x in (isp, asn) if x)
                text = "%s（%s）" % (ip, " · ".join(x for x in (loc, tail) if x))
        except (ValueError, KeyError):
            pass
    if text != ip:
        cache[ip] = {"s": text, "t": time.time()}
        # Keep the cache bounded; alert storms can involve thousands of IPs.
        if len(cache) > 5000:
            for k in sorted(cache, key=lambda k: cache[k].get("t", 0))[:2000]:
                cache.pop(k, None)
        write_json(paths.GEOIP_CACHE, cache, mode=0o640)
    _GEO_MEM[ip] = text
    return text


# --------------------------------------------------------------------------
# Misc
# --------------------------------------------------------------------------


def human_seconds(sec) -> str:
    try:
        sec = int(sec)
    except (TypeError, ValueError):
        return str(sec)
    if sec < 60:
        return "%d 秒" % sec
    if sec < 3600:
        return "%d 分钟" % (sec // 60)
    if sec < 86400:
        return "%.1f 小时" % (sec / 3600.0)
    return "%.1f 天" % (sec / 86400.0)


def human_bytes(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return str(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return "%.1f %s" % (n, unit)
        n /= 1024.0
    return str(n)


def read_proc_stat():
    """(busy_jiffies, total_jiffies) for the whole CPU."""
    try:
        with open("/proc/stat", "r", encoding="utf-8") as fh:
            parts = fh.readline().split()
        vals = [int(x) for x in parts[1:]]
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
        return sum(vals) - idle, sum(vals)
    except (OSError, ValueError, IndexError):
        return 0, 0


def uptime_seconds() -> float:
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as fh:
            return float(fh.read().split()[0])
    except (OSError, ValueError, IndexError):
        return 0.0


def mount_points(exclude_fs=("tmpfs", "devtmpfs", "squashfs", "overlay",
                             "proc", "sysfs", "cgroup", "cgroup2", "ramfs",
                             "autofs", "tracefs", "debugfs", "securityfs",
                             "pstore", "bpf", "configfs", "fusectl", "mqueue",
                             "hugetlbfs", "efivarfs", "nsfs")):
    """Real filesystems worth watching for fullness."""
    out = []
    seen = set()
    try:
        with open("/proc/mounts", "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 3:
                    continue
                dev, mnt, fstype = parts[0], parts[1], parts[2]
                if fstype in exclude_fs:
                    continue
                if mnt in seen:
                    continue
                seen.add(mnt)
                out.append((dev, mnt, fstype))
    except OSError:
        pass
    return out


def expand_globs(patterns) -> list:
    out = []
    for pat in patterns or []:
        out.extend(glob.glob(pat))
    return sorted(set(out))
