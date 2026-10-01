"""Answer "what is this, and what is it doing" for a process or an address.

Both questions come up at the same moment -- an alert fires, and the reader
wants to know whether the thing it names is dangerous. The pieces existed
across three modules (process detail, IP dossier, connection tables) but
nothing joined them, so answering took four commands and a mental join.

This module is that join, and nothing else: it adds no detection and makes no
judgement. It reports.
"""
from __future__ import annotations

from .checks import util


def trace_ip(cfg, ip: str) -> dict:
    """Everything known about a remote address."""
    out = {"kind": "ip", "target": ip, "dossier": [], "connections": [],
           "processes": [], "history": ""}
    ip = (ip or "").strip()
    if not ip:
        return out
    out["dossier"] = util.ip_dossier(cfg, ip)
    from . import threat
    out["history"] = threat.ban_history(ip)
    # Who on this host is talking to it, and from which process.
    from ..core import shell
    if shell.have("ss"):
        ok, text, _e = shell.run(["ss", "-H", "-tnp"], timeout=10)
        for line in (text or "").splitlines():
            if ip not in line:
                continue
            fields = line.split()
            if len(fields) >= 5:
                out["connections"].append(" ".join(fields[:5]))
            for token in fields:
                if token.startswith("users:"):
                    out["processes"].append(token.strip("users:()"))
    out["processes"] = sorted(set(out["processes"]))[:12]
    return out


def trace_pid(pid: str) -> dict:
    """Everything known about a local process."""
    from .checks.process import _proc_identity, process_detail
    pid = str(pid or "").strip()
    out = {"kind": "process", "target": pid, "identity": {}, "detail": [],
           "tree": [], "threads": ""}
    if not pid.isdigit():
        return out
    out["identity"] = _proc_identity(pid)
    out["detail"] = process_detail(pid)
    # Children: a shell that spawned a miner tells a different story from a
    # miner running alone.
    from ..core import shell
    ok, text, _e = shell.run(["ps", "--ppid", pid, "-o", "pid=,comm="],
                             timeout=10)
    if ok:
        out["tree"] = [ln.strip() for ln in (text or "").splitlines() if ln.strip()][:20]
    ok2, th, _e2 = shell.run(["sh", "-c",
                              "ls /proc/%s/task 2>/dev/null | wc -l" % pid],
                             timeout=8)
    if ok2:
        out["threads"] = (th or "").strip()
    return out
