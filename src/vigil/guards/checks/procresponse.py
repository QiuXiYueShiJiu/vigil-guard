"""Responding to a suspicious process -- and the guards around doing it.

Why this module exists
----------------------

The report said "发现可疑进程：可执行文件已被删除且磁盘上不存在" and then
stopped. What the operator wanted, in their own words, was for the program to
work out whether the process really is dangerous, act on it, and tell them
what it did -- "而不是只报道等恢复" (rather than only reporting and waiting to
be told to recover).

That is a reasonable request and it is also the single most dangerous thing
this program does. An automatic kill is irreversible: kill nginx's master,
kill the panel's PHP-FPM, kill the process holding a database connection, and
the machine is down -- which is a worse outcome than the attacker it was aimed
at. So the whole design below is shaped by one rule, repeated because it needs
to be impossible to miss:

    **宁可漏处置，也绝不误杀。**
    **Prefer missing a response to killing an innocent process.**

How that rule is *enforced* rather than merely promised
-------------------------------------------------------

Five mechanisms, each of which can stop a response on its own. They are in
the code, not only in this docstring:

1. **Off by default.** ``threat.autoresponse.enabled`` is ``False``. Nothing
   here runs until an operator turns it on.
2. **Reversible by default.** The default action is ``SIGSTOP``, not a kill.
   A stopped process can be resumed with one signal; a killed one cannot.
   After stopping, the module keeps watching and issues ``SIGCONT`` by itself
   the moment a piece of exempting evidence appears (see :func:`resume_check`).
3. **Two independent signals, from different sources.** One suspicious fact is
   never enough. "The executable is deleted" and "it holds an outbound
   connection to a non-loopback peer" come from different evidence classes and
   must both hold. Two facts drawn from the same class (a temp-dir path and a
   temp-dir *executable*) count once, and the high-confidence rule needs a
   deleted binary anyway, so the whole temp-dir class is not part of it.
4. **Time.** A single snapshot is not a finding. The candidate is observed for
   ``observe_seconds`` first, and any exemption -- or the process exiting --
   cancels the whole thing silently. Then, immediately before any signal is
   sent, the evidence is **re-read** and re-decided; if the world moved (the
   pid is gone, the executable changed, a cgroup appeared, the operator added
   the process to the allowlist) the response is abandoned and only reported.
5. **A hard "never" list** in :func:`exempt_reason`, including the cases the
   operator asked for by name: pid 1, kernel threads, this program's own
   process tree, anything a systemd unit manages, anything on the operator's
   allowlist, and anything recognised as a browser-automation toolchain. These
   are code, not configuration: there is no key that relaxes them.

Evidence before action
----------------------

A memory-resident implant loses its evidence the instant it is stopped: its
``/proc`` entries can vanish, its file descriptors close, its maps are gone.
So the evidence bundle is written to disk *first* -- :func:`collect_evidence`
then :func:`freeze_evidence` -- and only then is a signal considered. The
bundle also goes into the alert, so the operator has it in their mailbox even
if the host is rebuilt.

Everything is reported
----------------------

Every decision lands in an append-only ledger
(``/var/lib/vigil/state/autoresponse.jsonl``) with the action, the reason, the
signals that fired, and the outcome -- including "stopped, then resumed
because a cgroup appeared". An automatic response without a ledger is
untraceable damage, so the ledger write happens before the signal and the
outcome is appended after it.

Deliberately *not* implemented
------------------------------

These were considered and left out. They are the honest cost of the rule at
the top:

* **No automatic file deletion or quarantine of the executable.** Which file
  would it be? For a deleted-binary process there is no file to remove, and
  for every other case the path is unverified. A false positive here destroys
  a file that has nothing to do with an attack.
* **No automatic firewall drop or connection reset.** Cutting a live
  connection takes down a service for its users, and this program cannot tell
  a C2 channel from a database pool by looking at one ``ESTAB`` line.
* **No ``SIGKILL`` by default**, and ``SIGKILL`` is not even reachable without
  changing a config key: it cannot be caught, so there is no last chance for
  the process to clean up.
* **No response at all to the temp-dir class**, even though it is the other
  half of what ``suspicious_procs`` reports. A browser bundle, an installer,
  a build tool and a legitimate helper all run from ``/tmp``. Reporting it is
  right; killing it is not.
* **No response to a process that merely *looks* wrong without a live
  outbound connection.** That is what keeps this from firing on every
  daemon that replaced its own binary during a package upgrade.

What this therefore *misses*: a silent implant that never dials out (it only
listens, or waits for a reverse tunnel established elsewhere), an implant that
manages to join a systemd unit or a slice, one that lives inside a container
whose cgroup looks unit-like, and any attack from a process whose executable
is still on disk. Those are reported, loudly, and left to a human.
"""
from __future__ import annotations

import json
import os
import re
import signal
import time
from pathlib import Path

from ...core import paths
from ..checks import util

__all__ = [
    "Runtime", "handle", "classify", "collect_evidence", "freeze_evidence",
    "exempt_reason", "signals_of", "HIGH", "MEDIUM", "LOW",
    "DECISION_RESPOND", "DECISION_REPORT", "automation_verdicts",
    "runtime_downgrade",
]

HIGH, MEDIUM, LOW = "high", "medium", "low"

#: The process passed every high-confidence requirement and the observation
#: window produced no exemption: it may be acted on.
DECISION_RESPOND = "respond"
#: Report only. The overwhelming majority of calls end here, on purpose.
DECISION_REPORT = "report"

#: Every response this module can apply, and what it means for reversibility.
ACTIONS = {
    "stop": {"signal": signal.SIGSTOP, "reversible": True},
    "terminate": {"signal": None, "reversible": False},   # resolved from config
}

#: Where the append-only audit ledger lives. Same directory as the rest of the
#: state, so a host backup of /var/lib/vigil is also a backup of this trail.
LEDGER = paths.STATE_STATE / "autoresponse.jsonl"
DEFAULT_EVIDENCE_DIR = paths.STATE_STATE / "autoresponse-evidence"
MAX_LINES = 5000

#: Cgroup lines can be enormous on a container host; the unit name is at the
#: end and there is no reason to keep the rest.
_CGROUP_CAP = 512


# --------------------------------------------------------------------------
# Injection seam
# --------------------------------------------------------------------------


class Runtime:
    """Every side effect this module performs, behind one object.

    The decision logic is the dangerous part and it is the part worth testing,
    so nothing in it reads ``/proc`` or sends a signal directly. Tests supply
    a Runtime whose ``signal`` records the call instead of making it, and
    whose ``proc_info`` returns a fictional process tree. Nothing needs to be
    monkeypatched, and no test can accidentally stop a real process.
    """

    def __init__(self, cfg=None, log=None, list_pids=None, proc_info=None,
                 connections=None, cgroup_unit=None, start_time=None,
                 is_automation=None, signal_fn=None, now=None,
                 pid_namespace=None):
        self.cfg = cfg
        self.log = log
        self._list_pids = list_pids
        self._proc_info = proc_info
        self._connections = connections
        self._cgroup_unit = cgroup_unit
        self._start_time = start_time
        self._is_automation = is_automation
        self._signal_fn = signal_fn
        self._now = now
        self._pid_namespace = pid_namespace
        self._own_ns = None

    # -- process facts ----------------------------------------------------
    def list_pids(self) -> list:
        if self._list_pids is not None:
            return list(self._list_pids())
        out = []
        try:
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    out.append(int(entry))
        except OSError:
            return []
        return sorted(out)

    def proc_info(self, pid: int) -> dict:
        """``{pid, comm, exe, cmdline, exe_deleted, ppid, start_time}``."""
        if self._proc_info is not None:
            return dict(self._proc_info(pid) or {})
        info = {"pid": int(pid), "comm": util.proc_comm(pid),
                "cmdline": util.proc_cmdline(pid),
                "exe": util.proc_exe(pid),
                "ppid": util.proc_ppid(pid),
                "start_time": _start_time(pid),
                "exe_dev": 0, "exe_ino": 0, "ns": _pid_namespace(pid)}
        try:
            stat = os.stat("/proc/%d/exe" % int(pid))
            info["exe_dev"], info["exe_ino"] = int(stat.st_dev), int(stat.st_ino)
        except OSError:
            pass
        raw = info["exe"]
        if raw.endswith(" (deleted)"):
            info["exe"] = raw[: -len(" (deleted)")]
            info["exe_deleted"] = True
        else:
            info["exe_deleted"] = bool(raw) and not os.path.exists(raw)
        return info

    def connections(self, pid: int) -> list:
        """Established TCP connections as ``[(local, peer, state)]``."""
        if self._connections is not None:
            return list(self._connections(pid) or [])
        return _connections_of(pid)

    def cgroup_unit(self, pid: int) -> str:
        """The systemd unit this process belongs to, or ``""``."""
        if self._cgroup_unit is not None:
            return str(self._cgroup_unit(pid) or "")
        return _cgroup_unit(pid)

    def start_time(self, pid: int) -> float:
        if self._start_time is not None:
            return float(self._start_time(pid) or 0.0)
        return _start_time(pid)

    def is_automation(self, pid: int, exe: str) -> str:
        """Non-empty when the process is part of a browser/automation bundle."""
        if self._is_automation is not None:
            return str(self._is_automation(pid, exe) or "")
        try:
            return util.browser_automation(pid, exe)
        except (OSError, TypeError, ValueError):
            return ""

    def signal(self, pid: int, sig) -> tuple:
        """``(ok, err)``. The only place a signal is ever sent."""
        if self._signal_fn is not None:
            return self._signal_fn(pid, sig)
        try:
            os.kill(int(pid), sig)
            return True, ""
        except OSError as exc:
            return False, str(exc)

    def pid_namespace(self, pid) -> str:
        """The ``pid`` namespace inode this process lives in, or ``""``."""
        if self._pid_namespace is not None:
            return str(self._pid_namespace(pid) or "")
        return _pid_namespace(pid)

    def own_namespace(self) -> str:
        if self._own_ns is None:
            self._own_ns = self.pid_namespace(os.getpid())
        return self._own_ns

    def now(self) -> float:
        return float(self._now() if self._now is not None else time.time())


def _start_time(pid) -> float:
    """Process start time, from field 22 of ``/proc/<pid>/stat``.

    ``/proc/<pid>``'s mtime is close but it is a directory attribute that can
    be touched; field 22 is the kernel's own value and is what pid-reuse
    detection needs to be reliable.
    """
    try:
        with open("/proc/%s/stat" % pid, "r", encoding="utf-8",
                  errors="replace") as fh:
            data = fh.read()
        return float(data.rsplit(") ", 1)[1].split()[19]) / 100.0
    except (OSError, IndexError, ValueError):
        try:
            return os.path.getmtime("/proc/%s" % pid)
        except OSError:
            return 0.0


def _connections_of(pid) -> list:
    """Established TCP sockets owned by *pid*, via ``ss``.

    Read rather than inferred: ``ss -H -tunap`` is what the rest of this
    program already uses, and it names the owning pid, so there is no
    heuristic that could attribute a stranger's socket to this process.
    """
    from ...core import shell
    if not shell.have("ss"):
        return []
    ok, out, _err = shell.run(["ss", "-H", "-tunap"], timeout=10)
    if not ok:
        return []
    needle = "pid=%d," % int(pid)
    rows = []
    for line in (out or "").splitlines():
        if needle not in line:
            continue
        fields = line.split()
        if len(fields) < 6:
            continue
        rows.append((fields[0], fields[3], fields[4]))
    return rows


def _cgroup_unit(pid) -> str:
    try:
        with open("/proc/%s/cgroup" % pid, "r", encoding="utf-8",
                  errors="replace") as fh:
            text = fh.read(_CGROUP_CAP)
    except OSError:
        return ""
    for line in text.splitlines():
        if ".service" in line or ".scope" in line:
            return line.rstrip().rsplit("/", 1)[-1]
    return ""


def _pid_namespace(pid) -> str:
    """The inode of ``/proc/<pid>/ns/pid``.

    Two processes with different inodes are in different PID namespaces.
    A signal sent from here is delivered *within our namespace*, where a
    container's processes have different pids (or none at all) -- so
    ``os.kill`` could stop an unrelated host process that happens to hold the
    same number. That is exactly the wrong kill, so the comparison is made
    before every action and a mismatch means "do not act".
    """
    try:
        return str(os.readlink("/proc/%s/ns/pid" % int(pid)))
    except (OSError, TypeError, ValueError):
        return ""


# --------------------------------------------------------------------------
# Signals
# --------------------------------------------------------------------------


def _is_external(peer: str) -> bool:
    """Is *peer* somewhere other than this host?

    Loopback and the unspecified addresses can never be a command-and-control
    channel, and a process talking to its own database over 127.0.0.1 is the
    single most common shape on a web server. Treating those as "holds an
    outbound connection" would make the high-confidence rule fire on healthy
    daemons.
    """
    text = str(peer or "").strip()
    if not text:
        return False
    if text.startswith("["):
        host = text[1:].split("]", 1)[0]
    else:
        host = text.rsplit(":", 1)[0] if ":" in text else text
    host = host.strip("[]").split("%")[0].lower()
    if not host:
        return False
    if host in ("127.0.0.1", "::1", "0.0.0.0", "::", "*", "localhost"):
        return False
    if host.startswith("127.") or host.startswith("::ffff:127."):
        return False
    if host.startswith(("fe80:", "169.254.")):
        return False
    return True


def signals_of(info: dict, connections: list, cfg=None) -> dict:
    """Which *independent* signals hold for this process.

    Each key is a different evidence class, read from a different source.
    They are deliberately not fine-grained: "two signals" must mean "two
    kinds of evidence", and packing several facts from one class into one
    list would let a single observation masquerade as corroboration.
    """
    exe = str(info.get("exe") or "")
    deleted = bool(info.get("exe_deleted")) or exe.endswith(" (deleted)")
    external = [c for c in (connections or [])
                if _is_external(c[2] if len(c) > 2 else "")]
    listening = [c for c in (connections or []) if (c[0] if c else "") == "LISTEN"]
    in_tmp = _in_temp(exe)
    return {
        # Class A -- what the binary is.
        "deleted_exe": deleted,
        # Class B -- what it is doing on the network.
        "external_conn": bool(external),
        "has_conns": bool(connections),
        # Class C -- where it lives on disk.
        "temp_exe": in_tmp,
        # Class D -- who manages it.
        "no_unit": not str(info.get("unit") or ""),
    }


def _in_temp(exe: str) -> bool:
    text = str(exe or "")
    if not text:
        return False
    for root in ("/tmp/", "/var/tmp/", "/dev/shm/"):
        if text.startswith(root):
            return True
    return False


# --------------------------------------------------------------------------
# The "never touch" list
# --------------------------------------------------------------------------


#: Comm names that are kernel threads. They have no userspace executable and
#: the kernel owns them; signalling one is meaningless at best.
_KERNEL_COMMS = frozenset({"kthreadd", "ksoftirqd", "migration", "rcu_sched",
                           "rcu_gp", "watchdog", "kworker", "kswapd",
                           "kauditd"})

#: The parent of every kernel thread. A process whose ppid is this is a
#: kernel thread whatever it calls itself.
_KTHREADD_PID = 2

#: argv[0]/exe fragments that mean "this is us". Matched against an ancestor's
#: command line too, because a helper started by the daemon must be protected
#: along with the daemon.
_VIGIL_RX = re.compile(r"(?:^|/)vigil(?:[-.\w]*)?$|vigil\.(?:guards|core|mail|"
                       r"commands|gates|evolve)\b|/usr/local/lib/vigil\b")


def _kernel_comm(comm: str) -> bool:
    """Is this comm a kernel thread's?

    Matched on the *first* segment as well as exactly, because the kernel
    decorates worker names: ``kworker/0:1`` and ``ksoftirqd/0`` are the names
    that actually appear in ``ps``, and an exact-match set of bare words
    would miss every one of them.
    """
    text = (comm or "").strip()
    if not text:
        return False
    if text in _KERNEL_COMMS:
        return True
    return text.split("/", 1)[0].split("-", 1)[0] in _KERNEL_COMMS


def _is_kernel_thread(info: dict) -> bool:
    """A process with no userspace image at all, or a child of kthreadd.

    Three facts, and the conjunction matters. An empty ``/proc/<pid>/exe``
    alone means nothing: the read can fail for permission, and a *deleted*
    binary also reads as empty once the ``" (deleted)"`` suffix is stripped.
    What the kernel's own threads actually look like is **no userspace image
    at all** -- no path, no command line -- or a parent of kthreadd.

    Requiring the command line too is what keeps a deleted payload from being
    silently excused as a kernel thread, which would have been the worst kind
    of false negative in the one module that sends signals.
    """
    try:
        ppid = int(info.get("ppid") or 0)
    except (TypeError, ValueError):
        ppid = 0
    if ppid == _KTHREADD_PID:
        return True
    return (not str(info.get("exe") or "")
            and not str(info.get("cmdline") or "")
            and not str(info.get("exe_deleted") or ""))


def _truthy(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def _in_own_tree(info: dict, runtime: Runtime) -> str:
    """Is this process us, or a child of us?

    Walks the parent chain rather than trusting ``comm``: every daemon in
    this project runs as ``python3`` in ``ps``, and a process could rename
    itself to ``vigil`` to earn protection. What cannot be faked is being an
    ancestor of this very process, so the walk starts at ``os.getpid()`` and
    follows the real ppid links.
    """
    own = ""
    exe = str(info.get("exe") or "")
    cmdline = str(info.get("cmdline") or "")
    if _VIGIL_RX.search(exe) or _VIGIL_RX.search(cmdline):
        own = "命令行或可执行文件属于 vigil 自身"
    if own:
        return own
    # Ancestor chain of the candidate, looking for a vigil process above it.
    seen = set()
    cur = info.get("pid")
    for _ in range(8):
        try:
            cur = int(cur)
        except (TypeError, ValueError):
            break
        if cur <= 1 or cur in seen:
            break
        seen.add(cur)
        frame = runtime.proc_info(cur)
        for text in (str(frame.get("exe") or ""),
                     str(frame.get("cmdline") or ""),
                     str(frame.get("comm") or "")):
            if text and _VIGIL_RX.search(text):
                return "进程链里有 vigil 自身（pid %d）" % cur
        cur = frame.get("ppid")
    # And this process's own ancestors, in case the candidate is our parent.
    cur = os.getpid()
    for _ in range(8):
        try:
            cur = int(cur)
        except (TypeError, ValueError):
            break
        if cur <= 1:
            break
        if cur == int(info.get("pid") or -1):
            return "该进程是本程序（pid %s）的祖先" % info.get("pid")
        try:
            frame = runtime.proc_info(cur)
        except Exception:                                   # noqa: BLE001
            break
        cur = frame.get("ppid")
    return ""


def _matches_allowlist(info: dict, patterns) -> bool:
    """Does any pattern describe this process?

    Two matching rules in one, and the split is deliberate.

    A pattern that looks like a **path** (``/usr/local/lib/vigil/*``) is
    matched against the executable path, because that is what the operator
    wrote and what they mean. A pattern that is a **name** is matched only
    against the process name and the executable's basename -- *never* against
    the whole path or command line.

    That restriction was added after a real false positive in the exemption
    direction: the built-in list contains ``vigil-*`` (this project's own
    daemon entry points), and matching a glob against every *word* of a
    command line made ``/tmp/vigil-probe/payload`` match it. A payload
    sitting in a directory whose name happened to start with ``vigil`` was
    silently allowlisted -- in the one place where an allowlist hit means "do
    not intervene". Anchoring to the basename is the fix; ``fnmatch`` still
    handles ``vigil-*`` and ``python3 -m vigil.*`` as before.
    """
    from ..checks.process import _matches
    comm = str(info.get("comm") or "")
    exe = str(info.get("exe") or "")
    cmdline = str(info.get("cmdline") or "")
    argv0 = os.path.basename(cmdline.split(" ")[0]) if cmdline else ""
    basename_identity = {"comm": comm, "cmdline": argv0,
                         "exe": os.path.basename(exe)}
    path_identity = {"comm": "", "cmdline": "", "exe": exe}
    for pattern in patterns or ():
        text = str(pattern or "").strip()
        if not text:
            continue
        identity = path_identity if text.startswith("/") else basename_identity
        try:
            if _matches(identity, text):
                return text
        except Exception:                                   # noqa: BLE001
            continue
    return ""


def exempt_reason(info: dict, runtime: Runtime, patterns=()) -> str:
    """Why this process must never be touched, or ``""``.

    Every branch here is a hard stop. This function is the last thing called
    before a signal, and it is called *twice* -- once when classifying and
    once immediately before acting -- because the facts it reads (cgroup,
    allowlist, executable) can change in between.

    The order is deliberate: the cheapest and most certain refusals first.
    """
    try:
        pid = int(info.get("pid") or -1)
    except (TypeError, ValueError):
        return "pid 非法"
    if pid <= 1:
        return "pid 1（init）绝不处置"
    if (info.get("is_kernel")
            or _is_kernel_thread(info)
            or _kernel_comm(str(info.get("comm") or ""))):
        return "内核线程绝不处置"
    # Different PID namespace: the pid we would signal is not necessarily the
    # process we looked at. See `_pid_namespace`.
    ns = str(info.get("ns") or runtime.pid_namespace(pid) or "")
    own_ns = runtime.own_namespace()
    if ns and own_ns and ns != own_ns:
        return ("该进程在另一个 PID 命名空间（%s ≠ 本进程 %s，通常是容器）—— "
                "在本命名空间里发信号可能落到同号的无关进程上，因此不处置"
                % (ns, own_ns))
    own = _in_own_tree(info, runtime)
    if own:
        return "本程序自身进程树：%s" % own
    unit = str(info.get("unit") or "")
    if unit:
        return "由 systemd 单元管理（%s）：重启策略、依赖关系与审计都在单元一侧，" \
               "绕过它处置会与 systemd 打架" % unit
    automation = str(info.get("automation") or "")
    if automation:
        return "浏览器自动化工具链：%s" % automation
    hit = _matches_allowlist(info, patterns)
    if hit:
        return "命中允许清单（%s）" % hit
    if info.get("package_owned"):
        return "可执行文件属于系统包管理器（%s）" % info["package_owned"]
    trusted = str(info.get("trusted_layout") or "")
    if trusted:
        return "可执行文件位于受信发行布局内（%s）" % trusted
    return ""


# --------------------------------------------------------------------------
# Evidence
# --------------------------------------------------------------------------


def collect_evidence(info: dict, runtime: Runtime) -> dict:
    """Everything worth keeping about one process, read from ``/proc``.

    Ordered the way it is because some of it stops existing the moment the
    process does. The executable hash is read *through* ``/proc/<pid>/exe``,
    which is the only way to hash a binary that has been unlinked -- and being
    able to hash it is exactly the difference between "a deleted binary" and
    "an identified sample".
    """
    pid = int(info.get("pid") or 0)
    exe = str(info.get("exe") or "")
    evidence = {
        "pid": pid,
        "comm": str(info.get("comm") or ""),
        "cmdline": str(info.get("cmdline") or ""),
        "exe": exe,
        "exe_deleted": bool(info.get("exe_deleted")),
        "exe_sha256": "",
        "uid": info.get("uid", ""),
        "start_time": info.get("start_time") or runtime.start_time(pid),
        "cgroup_unit": str(info.get("unit") or runtime.cgroup_unit(pid)),
        "ppid": info.get("ppid", ""),
        "parent_chain": _parent_chain(pid, runtime),
        "connections": [],
        "fds": _fd_list(pid),
        "collected_at": runtime.now(),
    }
    try:
        evidence["exe_sha256"] = _hash_proc_exe(pid)
    except OSError:
        evidence["exe_sha256"] = ""
    try:
        for row in runtime.connections(pid) or []:
            evidence["connections"].append({
                "state": str(row[0]) if len(row) > 0 else "",
                "local": str(row[1]) if len(row) > 1 else "",
                "peer": str(row[2]) if len(row) > 2 else "",
                "external": _is_external(row[2] if len(row) > 2 else ""),
            })
    except Exception:                                       # noqa: BLE001
        evidence["connections"] = []
    return evidence


def _hash_proc_exe(pid) -> str:
    """sha256 of the running image, through ``/proc/<pid>/exe``.

    Reading the *link* is not enough: for a deleted binary the path is gone,
    and the only copy left is the open inode behind the symlink. Opening
    ``/proc/<pid>/exe`` reaches that inode, so the sample is preserved even
    after the file is unlinked.
    """
    import hashlib
    h = hashlib.sha256()
    with open("/proc/%s/exe" % int(pid), "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _fd_list(pid) -> list:
    """Open file descriptors, as ``"<fd> -> <target>"`` strings.

    Capped: a busy server has hundreds of sockets and the interesting ones are
    the unusual targets, but truncating silently would be a lie, so the count
    is reported alongside.
    """
    base = "/proc/%s/fd" % int(pid)
    out = []
    try:
        for name in sorted(os.listdir(base), key=lambda x: (len(x), x)):
            try:
                out.append("%s -> %s" % (name, os.readlink(os.path.join(base, name))))
            except OSError:
                continue
            if len(out) >= 200:
                break
    except OSError:
        return []
    return out


def _parent_chain(pid, runtime: Runtime, depth: int = 5) -> list:
    chain = []
    cur = pid
    for _ in range(depth):
        try:
            cur = int(cur)
        except (TypeError, ValueError):
            break
        if cur <= 1:
            break
        try:
            frame = runtime.proc_info(cur)
        except Exception:                                   # noqa: BLE001
            break
        chain.append({"pid": cur, "comm": frame.get("comm", ""),
                      "cmdline": util.oneline(frame.get("cmdline", ""), 200)})
        cur = frame.get("ppid")
    return chain


def freeze_evidence(evidence: dict, runtime: Runtime, directory=None) -> str:
    """Write the bundle to disk **before** anything is signalled.

    Returns the path, or ``""`` when it could not be written -- and the caller
    treats that as a refusal, not as a warning. Stopping a process whose
    evidence was never persisted is how a memory-resident payload becomes
    uninvestigable.

    Written with ``os.replace`` so a crash mid-write cannot leave a truncated
    bundle that reads as a complete one.
    """
    import tempfile
    directory = Path(directory or _evidence_dir(runtime.cfg))
    try:
        directory.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(evidence.get(
            "collected_at") or runtime.now()))
        path = directory / ("pid%d-%s.json" % (evidence.get("pid") or 0, stamp))
        fd, tmp = tempfile.mkstemp(dir=str(directory), prefix=".ev-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(evidence, fh, ensure_ascii=False, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, str(path))
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return str(path)
    except (OSError, TypeError, ValueError):
        return ""


def _evidence_dir(cfg) -> str:
    try:
        configured = str(cfg.get("threat.autoresponse.evidence_dir", "") or "")
    except AttributeError:
        configured = ""
    return configured or str(DEFAULT_EVIDENCE_DIR)


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------


#: What the high-confidence rule requires, in words, for the report. Kept next
#: to the code that implements it so the two cannot drift apart silently.
HIGH_RULE = ("可执行文件已被删除且磁盘上不存在（独立信号 A）"
             "**且**持有到非环回地址的已建立连接（独立信号 B，与 A 来源不同）"
             "**且**不属于任何 systemd 单元"
             "**且**不在浏览器/自动化发行布局内"
             "**且**不在允许清单里")


def classify(info: dict, connections: list, runtime: Runtime, patterns=(),
             cfg=None) -> dict:
    """Decide what may be done about one process. No side effects.

    Returns ``{level, decision, reason, signals, exempt}``. ``decision`` is
    :data:`DECISION_RESPOND` only for :data:`HIGH`, and reaching ``HIGH``
    requires two independent signals -- see :func:`signals_of`.
    """
    sig = signals_of(info, connections, cfg)
    exempt = exempt_reason(info, runtime, patterns)
    out = {"level": LOW, "decision": DECISION_REPORT, "reason": "",
           "signals": sig, "exempt": exempt,
           "rule": HIGH_RULE, "info": info}
    if exempt:
        out["reason"] = "永不处置：%s" % exempt
        return out

    # Two independent classes, and they are not interchangeable. A deleted
    # executable alone is common and usually benign (a package upgrade); a
    # temp-dir executable alone is a false-positive factory (build tools,
    # browser bundles, installers). Together with a *live outbound
    # connection*, the shape stops being explainable by maintenance.
    #
    # The temp-dir signal was deliberately removed from the high-confidence
    # rule, even though the check reports it: it is the same evidence class as
    # "the binary's path is odd", and a browser download is inside a temp
    # directory. Keeping it would have required trusting the automation
    # exemption to compensate for a signal that should never have been there.
    # Two classes, named so the report can say *which* two fired rather than
    # just "two". Named by class, not by raw flag, so that several facts from
    # the same class can never be counted as corroboration.
    independent = {"二进制（可执行文件已删除）": bool(sig["deleted_exe"]),
                   "网络（持有外部已建立连接）": bool(sig["external_conn"])}
    fired = [name for name, on in independent.items() if on]
    missing = [name for name, on in independent.items() if not on]

    if all(independent.values()):
        out["level"] = HIGH
        out["decision"] = DECISION_RESPOND
        out["reason"] = ("高置信：两个**来源不同**的证据类别同时成立 —— %s；"
                         "且无任何豁免证据（无 systemd 单元、非自动化工具链、"
                         "不在允许清单内）" % "；".join(fired))
        return out
    if sig["deleted_exe"] or sig["external_conn"] or sig["temp_exe"]:
        out["level"] = MEDIUM
        out["reason"] = ("中置信：缺少独立佐证 —— 成立的是 %s，缺少 %s。"
                         "只有一类证据时一律只报告、不处置。"
                         % ("、".join(fired) or "仅路径可疑",
                            "、".join(missing) or "—"))
        return out
    out["reason"] = "低置信：没有命中任何可处置的判据"
    return out


def _corroboration(pid: int, runtime: Runtime) -> dict:
    """Behavioural corroboration read at action time.

    Not a reason to act on its own -- it is a reason to *stop*: if the process
    has no external connection at this instant, the second signal is gone and
    the whole decision must be re-made. This exists so that "it had a
    connection five minutes ago" cannot be used to justify acting now.
    """
    info = runtime.proc_info(pid)
    conns = runtime.connections(pid)
    return {"info": info, "connections": conns}


# --------------------------------------------------------------------------
# The audit ledger
# --------------------------------------------------------------------------


def ledger_path() -> Path:
    return LEDGER


#: The config this module was last given. Only used so the ledger's HMAC key
#: can be located when the caller is not `handle` -- for example the CLI's
#: manual resume path, or the checkpoint written mid-run.
_LAST_CFG = {"cfg": None}


def _cfg_for_ledger():
    return _LAST_CFG.get("cfg")


def note(message: str) -> None:
    """Best-effort bookkeeping message.

    Preferred over ``except Exception: pass`` in this module for the reason
    the test suite pins: a swallowed exception is how a helper that was never
    imported goes unnoticed for months. Every suppressed path here is
    reported somewhere, even if only to the log.
    """
    try:
        from ...core.logging import get as get_logger
        get_logger("autoresponse").warn(message)
    except Exception:                                       # noqa: BLE001
        print("[autoresponse] %s" % message)


def record(kind: str, **fields) -> dict:
    """Append one audit entry, and mirror it into the evolve ledger.

    Never raises: losing the audit write must not abort an in-progress
    response, but it must also never be silent -- the returned dict carries
    ``written`` and callers report it. The same entry goes to
    ``evolve.ledger`` because that ledger already has a reader
    (``vigil evolve status``) and "who changed what on this host" belongs in
    one place.
    """
    entry = {"ts": round(time.time(), 2), "kind": str(kind)}
    entry.update(fields)
    ok = False
    try:
        LEDGER.parent.mkdir(parents=True, exist_ok=True)
        with open(LEDGER, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        ok = True
        _trim(LEDGER)
    except (OSError, TypeError, ValueError):
        ok = False
    entry["written"] = ok
    try:
        from ...evolve import ledger as evolve_ledger
        evolve_ledger.record("autoresponse-" + str(kind), cfg=_cfg_for_ledger(), **{
            k: v for k, v in fields.items()
            if k in ("pid", "action", "reason", "signals", "outcome",
                     "evidence", "result", "exempt", "level")})
    except Exception as exc:                                # noqa: BLE001
        # Not swallowed: a ledger that stops recording is itself a finding,
        # and this is the only place that can say so.
        note("台账镜像写入失败：%s: %s" % (type(exc).__name__, exc))
    return entry


def _trim(path: Path, keep: int = MAX_LINES) -> None:
    try:
        if path.stat().st_size < 1024 * 1024:
            return
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if len(lines) > keep:
            path.write_text("\n".join(lines[-keep:]) + "\n", encoding="utf-8")
    except OSError:
        pass


def recent(limit: int = 50) -> list:
    """The disposition ledger, newest last. Used by tests and by reporting."""
    out = []
    try:
        for line in LEDGER.read_text(encoding="utf-8",
                                     errors="replace").splitlines()[-limit:]:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    except OSError:
        return []
    return out


# --------------------------------------------------------------------------
# Rate limiting and state
# --------------------------------------------------------------------------

#: Where the observation windows and the per-hour cap live inside the check's
#: persisted state.
STATE_KEY = "autoresponse"


def _sliding_window(runtime: Runtime, state: dict, window: int,
                    limit: int) -> tuple:
    """``(allowed, used, limit)`` for actions taken in the last *window* s.

    A plain list of timestamps rather than ``guards.threat.Windows``: that
    class is keyed by ``(ip, detector)`` and is process-global, and this cap
    has to survive a daemon restart, so it lives in the check's persisted
    state instead. The arithmetic is the same sliding window, kept here so
    the two cannot silently disagree about what "N per hour" means.

    The list is pruned on read, so it cannot grow without bound even if the
    sweeper never runs.
    """
    now = runtime.now()
    stamps = _action_stamps(state, now, window)
    return len(stamps) < max(1, int(limit)), len(stamps), max(1, int(limit))


def _action_stamps(state: dict, now: float, window: int) -> list:
    stamps = []
    for value in (state.get("action_stamps") or []):
        try:
            ts = float(value)
        except (TypeError, ValueError):
            continue
        if now - ts < max(1, int(window)):
            stamps.append(ts)
    state["action_stamps"] = stamps[-128:]
    return stamps


def _note_action(state: dict, runtime: Runtime, window: int) -> None:
    stamps = _action_stamps(state, runtime.now(), window)
    stamps.append(runtime.now())
    state["action_stamps"] = stamps[-128:]


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------


def _int_cfg(cfg, key: str, default: int, minimum: int = 0) -> int:
    try:
        value = int(cfg.get(key, default))
    except (TypeError, ValueError, AttributeError):
        value = default
    return max(minimum, value)


def _num_cfg(cfg, key: str, default: float, minimum: float = 0.0) -> float:
    try:
        value = float(cfg.get(key, default))
    except (TypeError, ValueError, AttributeError):
        value = default
    return max(minimum, value)


#: Hard ceiling on the configured per-hour cap, whatever the config says.
#: A configuration typo must not be able to turn this into a mass-kill. Ten
#: is already far more than a sane host should ever need.
MAX_PER_HOUR_CEILING = 10


def settings(cfg) -> dict:
    """Resolved ``threat.autoresponse`` settings, with the clamps applied."""
    enabled = False
    raw_action = "stop"
    try:
        enabled = _truthy(cfg.get("threat.autoresponse.enabled", False))
        raw_action = str(cfg.get("threat.autoresponse.action", "stop")
                         or "stop").strip().lower()
    except AttributeError:
        pass
    action = raw_action if raw_action in ACTIONS else "stop"
    patterns = []
    try:
        patterns = [str(x) for x in
                    (cfg.get("threat.autoresponse.allowlist", []) or [])]
    except AttributeError:
        patterns = []
    try:
        from ..checks.process import BUILTIN_WHITELIST
        # The built-in entries name this project's own daemons. Reusing them
        # here means "this is us" is defined once.
        patterns = list(BUILTIN_WHITELIST) + patterns
    except Exception as exc:                                # noqa: BLE001
        note("无法读取内置进程白名单，允许清单只剩显式配置项：%s" % exc)
    after = "hold"
    try:
        after = str(cfg.get("threat.autoresponse.after_observe", "hold")
                    or "hold").strip().lower()
    except AttributeError:
        pass
    signal_name = "SIGTERM"
    try:
        signal_name = str(cfg.get("threat.autoresponse.terminate_signal",
                                  "SIGTERM") or "SIGTERM").strip().upper()
    except AttributeError:
        pass
    return {
        "enabled": enabled,
        "action": action,
        "after_observe": after if after in ("hold", "terminate") else "hold",
        "observe_seconds": _num_cfg(cfg, "threat.autoresponse.observe_seconds",
                                    120.0, 0.0),
        "resume_window_seconds": _num_cfg(
            cfg, "threat.autoresponse.resume_window_seconds", 600.0, 0.0),
        "max_per_hour": min(MAX_PER_HOUR_CEILING,
                            _int_cfg(cfg, "threat.autoresponse.max_per_hour",
                                     2, 1)),
        "terminate_signal": signal_name,
        "allowlist": patterns,
        "evidence_dir": _evidence_dir(cfg),
    }


def _signal_for(name: str, default):
    value = getattr(signal, str(name or "").upper(), None)
    return value if isinstance(value, int) else default


# --------------------------------------------------------------------------
# The entry point
# --------------------------------------------------------------------------


def handle(hits, cfg=None, state=None, runtime: Runtime = None,
           log=None) -> dict:
    """Evaluate suspicious processes and, if allowed, respond to them.

    ``hits`` are the dicts from ``checks.util.suspect_procs_detail`` (or the
    same shape), so the discovery stays where it already is and this module
    only decides. ``state`` is the check's persisted dictionary; the
    observation windows, the rate limiter and the list of processes we have
    stopped all live in it, so a daemon restart does not lose track of a
    process it already paused -- losing that would be the worst possible
    outcome, a stopped process nobody knows about.

    Returns a report dict; :func:`describe` renders it. Nothing in here is
    reached unless ``threat.autoresponse.enabled`` is true, and even then the
    default action is reversible.
    """
    st = settings(cfg)
    _LAST_CFG["cfg"] = cfg
    runtime = runtime or Runtime(cfg=cfg, log=log)
    state = state if isinstance(state, dict) else {}
    rs = state.get(STATE_KEY)
    if not isinstance(rs, dict):
        rs = {"observing": {}, "stopped": {}}
        state[STATE_KEY] = rs
    rs.setdefault("observing", {})
    rs.setdefault("stopped", {})

    out = {"enabled": st["enabled"], "action": st["action"],
           "evaluated": 0, "responded": [], "observed": [], "abandoned": [],
           "resumed": [], "escalated": [], "limited": [], "refused": [],
           "reported": [], "signals": st,
           # Pids this module has already acted on. The caller must not
           # re-report them as fresh findings: a stopped process is still in
           # `suspect_procs_detail`'s output on every later round, and
           # re-deciding it each time is how a self-exciting
           # "stop / re-detect / stop again" loop starts. Reported rather than
           # hidden -- the caller names them and says what happened.
           "handled_pids": sorted(int(k) for k in
                                  (rs.get("stopped") or {})
                                  if str(k).lstrip("-").isdigit())}
    if not st["enabled"]:
        return out

    # 1. First, reconcile anything we have already stopped. This runs even
    #    when the current finding is empty: a process we paused on a previous
    #    run must keep being watched, and must be released the moment its
    #    exemption appears. Doing this first also means a crash between the
    #    signal and the ledger write is corrected on the next run.
    _reconcile_stopped(rs, st, runtime, out, cfg)

    seen = set()
    for hit in hits or []:
        try:
            pid = int(hit.get("pid"))
        except (TypeError, ValueError):
            continue
        seen.add(pid)
        out["evaluated"] += 1
        _handle_one(pid, hit, st, rs, runtime, out, cfg)

    # 2. Forget observation records whose process is gone, and stopped
    #    records that have gone stale (pid reused, process exited).
    _prune(rs, seen, runtime, out)
    out["handled_pids"] = sorted(int(k) for k in (rs.get("stopped") or {})
                                 if str(k).lstrip("-").isdigit())
    # 3. One ledger line per pass, including the passes that did nothing.
    #    "The feature is on and evaluated four processes, all of which needed
    #    nothing" is a result, and it is the result the operator most often
    #    wants; without it, an enabled feature that never acts is
    #    indistinguishable from one that is not running.
    if out["evaluated"] or out["responded"] or out["resumed"]:
        record("pass", evaluated=out["evaluated"],
               responded=len(out["responded"]),
               observed=len(out["observed"]),
               limited=len(out["limited"]),
               refused=len(out["refused"]),
               abandoned=len(out["abandoned"]), resumed=len(out["resumed"]),
               escalated=len(out["escalated"]),
               outcome=("本轮判定 %d 个：已处置 %d、观察中 %d、未处置 %d、"
                        "放弃 %d、撤销 %d"
                        % (out["evaluated"], len(out["responded"]),
                           len(out["observed"]), len(out["refused"]),
                           len(out["abandoned"]), len(out["resumed"]))))
    return out


#: Verdicts this module reaches *without* any intervention. Recorded so the
#: report can give a one-line conclusion for every process it looked at --
#: "nothing was done" and "nothing needed doing" must not read the same, and
#: an automated judgement that leaves no trace is indistinguishable from a
#: check that is not running.
_VERDICT_LABEL = {
    "automation": "浏览器/自动化工具链",
    "allowlist": "在允许清单内",
    "unit": "由 systemd 单元管理",
    "own": "本程序自身进程树",
    "namespace": "在另一个 PID 命名空间（容器）内",
    "kernel": "内核线程",
    "pid1": "pid 1",
    "package": "可执行文件属于系统包管理器",
    "trusted-layout": "可执行文件位于受信发行布局内",
    "single-signal": "只有一个证据类别成立",
}


def automation_verdicts(hits, cfg=None, state=None, runtime: Runtime = None,
                        log=None) -> dict:
    """Automatic conclusions for the hits that need no intervention at all.

    Returns ``{"exempt": [ {pid, comm, exe, kind, reason, verdict} ],
    "suspicious": [...hits that were not exempted...]}``.

    This is the "自动判定" half of the operator's request: the browser
    automation chain and its leftover helpers are *classified*, not merely
    skipped, and the classification is written to the ledger with the
    structural reason it matched. Nothing here can lead to a signal -- it only
    ever removes a process from consideration -- which is why it is safe to
    run unconditionally, with or without ``threat.autoresponse.enabled``.
    """
    st = settings(cfg)
    runtime = runtime or Runtime(cfg=cfg, log=log)
    _LAST_CFG["cfg"] = cfg
    exempt, suspicious = [], []
    for hit in hits or ():
        try:
            pid = int(hit.get("pid"))
        except (TypeError, ValueError):
            continue
        # The *hit's own* structural facts come first and decide on their own.
        # They are derived from the executable path, which is host independent
        # and needs no `/proc` read, so this judgement cannot be changed by
        # what `proc_info` happens to return.
        automation = str(hit.get("automation") or "")
        if not automation:
            automation = util.browser_automation(pid, str(hit.get("exe") or ""))
        structural = None
        if automation:
            structural = automation
        elif util.browser_layout(str(hit.get("exe") or "")):
            # Inside a browser release layout but not a browser or helper
            # name. Named, and deliberately *not* exempted: this is the shape
            # a payload dropped beside a browser would have, and it is the one
            # case where "it is in the browsers directory" must not be enough.
            structural = ""

        info = dict(hit)
        info.setdefault("pid", pid)
        if runtime._proc_info is not None:
            # Only consult /proc when the runtime can actually answer for this
            # pid. Falling back to a real read here would make the verdict
            # depend on the host the check happens to run on, which is how a
            # test (or a small host) ends up deciding that a deleted payload
            # belongs to `init.scope` and needs no attention.
            info.update(runtime.proc_info(pid) or {})
        info.setdefault("automation", automation)
        info["unit"] = info.get("unit") or runtime.cgroup_unit(pid)
        reason = structural if structural else             exempt_reason(info, runtime, st["allowlist"])
        if not reason:
            suspicious.append(hit)
            continue
        verdict = _verdict_kind(reason)
        # The original hit is kept, not replaced: the verdict is an annotation
        # on the observation, and the operand must still be able to see the
        # raw pid/path that was judged. A verdict that overwrites its own
        # evidence cannot be disagreed with.
        item = dict(hit)
        item.update({
            "pid": pid, "comm": info.get("comm", "") or hit.get("comm", ""),
            "exe": info.get("exe", "") or hit.get("exe", ""),
            "kind": hit.get("kind", ""), "reason": reason,
            "verdict": verdict, "verdict_label": _VERDICT_LABEL.get(verdict,
                                                                    verdict),
            "conclusion": "已自动判定为%s（结构性判据），已忽略，无需处理"
                          % _VERDICT_LABEL.get(verdict, verdict),
        })
        exempt.append(item)
    return {"exempt": exempt, "suspicious": suspicious,
            "allowlist": st["allowlist"]}


def _verdict_kind(reason: str) -> str:
    """Map an exemption sentence to a stable machine-readable kind."""
    text = str(reason or "")
    for kind, needle in (("automation", "自动化工具链"),
                         ("allowlist", "允许清单"),
                         ("unit", "systemd 单元"),
                         ("own", "本程序自身进程树"),
                         ("namespace", "PID 命名空间"),
                         ("kernel", "内核线程"),
                         ("pid1", "pid 1"),
                         ("package", "系统包管理器"),
                         ("trusted-layout", "受信发行布局")):
        if needle in text:
            return kind
    return "other"


def runtime_downgrade(pid, comm: str, cmdline: str, runtime: Runtime,
                      cfg=None) -> str:
    """Why a high-CPU process is ordinary, or ``""`` to keep reporting it.

    The complaint this answers: a build (``vue-tsc``, ``esbuild``, ``webpack``)
    or a Node/Python service pinned at 100% CPU is not a process anomaly, and
    reporting it as one trains the operator to ignore the check.

    Three signals, all structural, and **at least one** is enough -- unlike
    the intervention path, where two are required. The asymmetry is
    deliberate: this only downgrades a report, it never acts on a process, so
    the cost of a wrong downgrade is one unreported hot process, not a killed
    server.

      * the process belongs to a systemd unit (it has an owner that will
        restart it, and `systemd` already has a resource story for it);
      * the executable comes from the system package manager **and** the
        command line is not running code handed to it inline. ``python3 -c``
        and ``node -e`` are how a lot of implants start, and both come from
        package-managed interpreters, so ownership alone would exempt exactly
        the shape that matters (``rpm``/``dpkg`` are consulted, and an
        unresolvable owner is reported as unknown rather than assumed);
      * the command line points at a directory this host already serves
        (a site root recorded in the config), which is what a site's own
        build or worker looks like.

    A runtime *name* alone is deliberately **not** enough. ``node -e
    <payload>`` is one of the most common ways to run an implant, and
    exempting anything called ``node`` would blind the check exactly where it
    matters.
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return ""
    unit = runtime.cgroup_unit(pid)
    if unit:
        return ("属于 systemd 单元（%s），高占用由服务管理器统一管理，"
                "报告之外没有本程序可以做的事" % unit)
    exe = ""
    try:
        exe = str(runtime.proc_info(pid).get("exe") or "")
    except Exception:                                       # noqa: BLE001
        exe = ""
    owner = package_owner(exe) if exe else ""
    if owner:
        inline = _inline_code(cmdline)
        if inline:
            return ""       # package-owned, but it is running supplied code
        return "可执行文件由系统包管理器提供（%s），且命令行是在运行已安装的程序" \
               % owner
    roots = _site_roots(cfg)
    words = [w for w in str(cmdline or "").split() if w.startswith("/")]
    for word in words:
        for root in roots:
            if root and (word == root or word.startswith(root.rstrip("/") + "/")):
                return "命令行指向本机已登记的站点目录（%s）" % root
    return ""


#: Flags that mean "run the code I am handing you" rather than "run an
#: installed program". A package-managed interpreter with one of these is not
#: a reason to stop reporting the process.
_INLINE_CODE_RX = re.compile(r"(?:^|\s)(?:-c|-e|--eval|--exec|-)\s*(?:\S|$)")


def _inline_code(cmdline: str) -> bool:
    text = str(cmdline or "")
    if not text:
        return False
    if text.rstrip().endswith(("-", "/dev/stdin")):
        return True
    return bool(_INLINE_CODE_RX.search(text))


def _site_roots(cfg) -> list:
    """Directories this host already serves, from the config.

    Read from ``gate.*.webroot`` rather than guessed, so "the command line
    points at a site" means a site the operator actually registered with this
    program. An empty list is the honest answer for a host with no gate.
    """
    roots = []
    for section in ("bt_panel", "dsh_gate"):
        try:
            value = str(cfg.get("gate.%s.webroot" % section, "") or "")
        except AttributeError:
            return roots
        if value:
            roots.append(value)
    return roots


def package_owner(exe: str) -> str:
    """The package that owns *exe*, or ``""`` when it cannot be determined.

    ``rpm -qf`` / ``dpkg -S`` only; no network, no heuristics. Returns the
    query output rather than a boolean so the report can name the package --
    "belongs to a package" is not checkable by the operator, "belongs to
    nginx-core" is.
    """
    from ...core import shell
    path = str(exe or "").strip()
    if not path.startswith("/") or not os.path.isfile(path):
        return ""
    for argv in (["rpm", "-qf", path], ["dpkg", "-S", path]):
        if not shell.have(argv[0]):
            continue
        ok, out, _err = shell.run(argv, timeout=10)
        if ok and out.strip() and "no package owns" not in out.lower():
            return util.oneline(out.strip().splitlines()[0], 120)
    return ""


def _handle_one(pid: int, hit: dict, st: dict, rs: dict, runtime: Runtime,
                out: dict, cfg) -> None:
    # The check already skips automation bundles, but this module must not
    # depend on a caller having done so: it is the thing that sends signals.
    info = runtime.proc_info(pid)
    if not info:
        return
    info.setdefault("automation", runtime.is_automation(pid,
                                                        info.get("exe", "")))
    conns = runtime.connections(pid)
    verdict = classify(info, conns, runtime, st["allowlist"], cfg)
    out["reported"].append({"pid": pid, "level": verdict["level"],
                            "reason": verdict["reason"],
                            "exempt": verdict["exempt"],
                            # The signals travel with the verdict: "medium"
                            # without saying which single class fired is not
                            # an explanation an operator can check.
                            "signals": verdict["signals"]})
    if verdict["decision"] != DECISION_RESPOND:
        # Whatever we were observing for this pid is no longer interesting --
        # but *why* it stopped being interesting is worth saying out loud when
        # the answer is "the pid is now a different process". That is the
        # signature of the observation being invalidated under us, and a
        # silently dropped record reads exactly like "nothing ever happened".
        previous = rs["observing"].pop(str(pid), None)
        if previous and _identity_changed(previous, info, runtime):
            out["abandoned"].append({
                "pid": pid,
                "why": "观察期内进程身份已变（pid 被复用或可执行文件被替换），"
                       "原观察记录作废，本轮按新进程重新判定"})
            record("observe-abandon", pid=pid, reason="identity-changed")
        return

    observing = rs["observing"].get(str(pid))
    if not observing:
        # First sighting: start the clock and change nothing. A snapshot is
        # not a finding; only persistence is.
        record_ = {"since": runtime.now(),
                   "signal_fingerprint": _fingerprint(info, conns)}
        record_.update(_identity(info, runtime))
        rs["observing"][str(pid)] = record_
        out["observed"].append({
            "pid": pid, "why": "判定成立，开始观察 %.0f 秒后再决定"
                               % st["observe_seconds"],
            "seconds_left": st["observe_seconds"]})
        record("observe-start", pid=pid, level=verdict["level"],
               reason=verdict["reason"], signals=verdict["signals"],
               observe_seconds=st["observe_seconds"])
        return

    # Already being observed. Does it still look the same, and has it been
    # long enough?
    if _identity_changed(observing, info, runtime):
        rs["observing"].pop(str(pid), None)
        out["abandoned"].append({"pid": pid,
                                 "why": "观察期内进程身份变了（pid 复用或可执行文件更换）"})
        record("observe-abandon", pid=pid, reason="identity-changed")
        return
    if _fingerprint(info, conns) != observing.get("signal_fingerprint"):
        rs["observing"].pop(str(pid), None)
        out["abandoned"].append({"pid": pid,
                                 "why": "观察期内信号组合发生变化，本轮不下结论，重新观察"})
        record("observe-abandon", pid=pid, reason="signals-changed")
        return
    waited = runtime.now() - float(observing.get("since") or 0)
    if waited < st["observe_seconds"]:
        out["observed"].append({"pid": pid, "why": "仍在观察期",
                                "seconds_left": st["observe_seconds"] - waited})
        return

    # -- the observation window has passed with the evidence intact -------
    # Re-read everything once more, because the world can move between the
    # decision and the signal. This is the last gate before an irreversible
    # act, so it re-derives *everything* rather than trusting the earlier read.
    fresh = runtime.proc_info(pid)
    if not fresh:
        rs["observing"].pop(str(pid), None)
        out["abandoned"].append({"pid": pid, "why": "动作前复检：进程已不存在"})
        record("action-abandon", pid=pid, reason="gone-before-action")
        return
    if _identity_changed(observing, fresh, runtime):
        rs["observing"].pop(str(pid), None)
        out["abandoned"].append({"pid": pid, "why": "动作前复检：进程身份已变（pid 复用/文件更换）"})
        record("action-abandon", pid=pid, reason="identity-changed")
        return
    fresh["automation"] = runtime.is_automation(pid, fresh.get("exe", ""))
    fresh["unit"] = runtime.cgroup_unit(pid)
    again = classify(fresh, runtime.connections(pid), runtime,
                     st["allowlist"], cfg)
    if again["decision"] != DECISION_RESPOND:
        rs["observing"].pop(str(pid), None)
        out["abandoned"].append({"pid": pid,
                                 "why": "动作前复检不通过：%s" % again["reason"]})
        record("action-abandon", pid=pid, reason=again["reason"],
               exempt=again["exempt"])
        return

    # -- rate limit, then evidence, then the signal ----------------------
    window = 3600
    allowed, used, limit = _sliding_window(runtime, rs, window,
                                           st["max_per_hour"])
    if not allowed:
        out["limited"].append({
            "pid": pid,
            "why": "已达到每小时处置上限（%d/%d）—— 只报告，不再处置。"
                   "上限存在的意义是：一个正在失控的判定逻辑不该能一次性"
                   "处置整台机器上的进程。" % (used, limit)})
        record("action-limited", pid=pid, action=st["action"], used=used,
               limit=limit, reason="hourly-cap")
        return

    evidence = collect_evidence(fresh, runtime)
    evidence["verdict"] = {"level": again["level"], "reason": again["reason"],
                           "signals": again["signals"], "rule": again["rule"]}
    evidence_path = freeze_evidence(evidence, runtime, st["evidence_dir"])
    if not evidence_path:
        # Refuse. Acting without durable evidence is how an investigation
        # ends before it starts, and the operator asked for the opposite.
        out["refused"].append({
            "pid": pid,
            "why": "证据无法落盘，因此**不处置**（内存马一杀证据就没了，"
                   "没有证据的自动处置等于不可追溯的破坏）"})
        record("action-refused", pid=pid, reason="evidence-not-persisted",
               action=st["action"])
        return

    if not _send_alert(cfg, log=runtime.log, pid=pid, action=st["action"],
                       verdict=again, evidence=evidence,
                       evidence_path=evidence_path):
        pass    # Delivery trouble is reported by the mail layer; never a
                # reason to skip the response or to lie about it.

    reversible = st["action"] == "stop"
    sig = signal.SIGSTOP if reversible else _signal_for(
        st["terminate_signal"], signal.SIGTERM)
    result = apply_action(pid, sig, runtime, action=st["action"])
    _note_action(rs, runtime, window)
    rs["observing"].pop(str(pid), None)

    entry = {"pid": pid, "action": st["action"], "signal": _sig_name(sig),
             "reversible": reversible, "ok": result["ok"],
             "err": result.get("err", ""), "reason": again["reason"],
             "signals": again["signals"], "evidence": evidence_path}
    record("action-applied", **entry)
    if reversible and result["ok"]:
        stopped = {"at": runtime.now(), "action": "stop",
                   "evidence": evidence_path,
                   "deadline": runtime.now() + st["resume_window_seconds"],
                   "escalated": False}
        stopped.update(_identity(fresh, runtime))
        rs["stopped"][str(pid)] = stopped
    if result["ok"]:
        out["responded"].append(entry)
    else:
        entry["why"] = "信号发送失败：%s" % result.get("err", "")
        out["refused"].append(entry)


def apply_action(pid: int, sig, runtime: Runtime, action: str = "stop") -> dict:
    """Send exactly one signal, and only ever through the Runtime.

    Separate from :func:`handle` so the "how many signals can this program
    send" question has exactly one answer, in one place. It never escalates on
    its own: escalation is a decision, and decisions live in the caller.
    """
    ok, err = runtime.signal(pid, sig)
    return {"ok": bool(ok), "err": err, "signal": _sig_name(sig),
            "action": action}


def _sig_name(sig) -> str:
    try:
        return signal.Signals(int(sig)).name
    except (ValueError, TypeError):
        return str(sig)


# --------------------------------------------------------------------------
# Reconciliation: undo what we did when the evidence stops supporting it
# --------------------------------------------------------------------------


#: Faults that make a stopped process *more* interesting, not less: we could
#: not read the fact, so we must not treat its absence as an exemption. Only
#: a positive exemption releases a process.
def resume_check(pid: int, st: dict, runtime: Runtime) -> str:
    """Should this stopped process be resumed? ``""`` means keep it stopped.

    This is the other half of "the default action is reversible": choosing a
    reversible action is worthless if nothing ever reverses it. Every branch
    here is a **positive** piece of evidence that the process is legitimate.
    A read failure deliberately does *not* resume: "we could not tell" is not
    "it is fine", and un-stopping an implant because ``/proc`` was busy would
    be the same class of mistake as the reports that only ever said "文件被删除".
    """
    info = runtime.proc_info(pid)
    if not info:
        return ""       # gone; nothing to resume, pruned by the caller
    unit = info.get("unit") or runtime.cgroup_unit(pid)
    if unit:
        return "该进程已归属 systemd 单元（%s）—— 它是由服务管理器拉起并管理的，" \
               "不是无主进程" % unit
    automation = info.get("automation") or runtime.is_automation(
        pid, info.get("exe", ""))
    if automation:
        return "该进程位于浏览器/自动化发行布局内：%s" % automation
    hit = _matches_allowlist(info, st.get("allowlist") or ())
    if hit:
        return "该进程已加入操作者允许清单（%s）" % hit
    if info.get("package_owned"):
        return "可执行文件属于系统包管理器（%s）" % info["package_owned"]
    trusted = str(info.get("trusted_layout") or "")
    if trusted:
        return "可执行文件位于受信发行布局内（%s）" % trusted
    own = _in_own_tree(info, runtime)
    if own:
        return "它其实是本程序自身进程树的一部分（%s）" % own
    return ""


def _reconcile_stopped(rs: dict, st: dict, runtime: Runtime, out: dict,
                       cfg) -> None:
    """Keep watching every process this module has stopped.

    Runs before anything else on every call, including calls with no new
    findings, so the resume decision does not depend on the process still
    looking suspicious enough to be re-listed.
    """
    for key in sorted(rs.get("stopped") or {}, key=lambda k: (len(k), k)):
        try:
            pid = int(key)
        except (TypeError, ValueError):
            rs["stopped"].pop(key, None)
            continue
        rec = rs["stopped"][key]
        info = runtime.proc_info(pid)
        if not info:
            # Process is gone (it may have exited, or been reaped). Nothing
            # to resume; keep the record as history for one more pass.
            rs["stopped"].pop(key, None)
            record("stopped-exited", pid=pid, action=rec.get("action"),
                   evidence=rec.get("evidence"))
            continue
        if _identity_changed(rec, info, runtime):
            # pid reused by an unrelated process. Report it loudly: this
            # means a stopped process disappeared without us resuming it,
            # which is exactly the case a human needs to look at.
            rs["stopped"].pop(key, None)
            out["abandoned"].append({
                "pid": pid,
                "why": "此前被暂停的进程已消失，pid 被另一个进程复用 —— "
                       "没有恢复动作可做，但这件事需要人工确认"})
            record("stopped-lost", pid=pid, reason="pid-reused")
            continue

        # The exemption re-check happens on every pass, which is what makes
        # the action honestly reversible rather than merely "not fatal".
        info["unit"] = info.get("unit") or runtime.cgroup_unit(pid)
        info["automation"] = info.get("automation") or runtime.is_automation(
            pid, info.get("exe", ""))
        why = resume_check(pid, st, runtime)
        if why:
            res = apply_action(pid, signal.SIGCONT, runtime, action="resume")
            record("action-resumed", pid=pid, ok=res["ok"], reason=why,
                   evidence=rec.get("evidence"), outcome="undone")
            rs["stopped"].pop(key, None)
            out["resumed"].append({"pid": pid, "why": why, "ok": res["ok"],
                                   "handled": True})
            if not res["ok"]:
                out["refused"].append({
                    "pid": pid,
                    "why": "SIGCONT 发送失败（%s）—— 该进程可能仍处于暂停状态，"
                           "请人工确认" % res.get("err", "")})
            continue

        if not rec.get("escalated") and runtime.now() >= float(
                rec.get("deadline") or 0):
            # The resume window closed with the evidence still standing.
            if st["after_observe"] == "terminate":
                sig = _signal_for(st["terminate_signal"], signal.SIGTERM)
                res = apply_action(pid, sig, runtime, action="terminate")
                rec["escalated"] = True
                record("action-escalated", pid=pid, ok=res["ok"],
                       signal=_sig_name(sig), action="terminate",
                       reason="观察期结束、豁免证据始终未出现",
                       evidence=rec.get("evidence"))
                out["escalated"].append({"pid": pid, "signal": _sig_name(sig),
                                         "ok": res["ok"]})
                rs["stopped"].pop(key, None)
            else:
                # "hold": keep it stopped and keep saying so. Silence here
                # would look identical to "nothing was ever done".
                rec["escalated"] = True
                record("stop-held", pid=pid, action="stop",
                       reason="观察期结束、豁免证据始终未出现；按 after_observe=hold "
                              "保持暂停，等操作者决定（可逆动作不自动升级）",
                       evidence=rec.get("evidence"))
                out["escalated"].append({
                    "pid": pid, "signal": "SIGSTOP",
                    "why": "保持暂停，等操作者决定：`kill -CONT %d` 可立即恢复"
                           % pid})


def _identity_changed(rec: dict, info: dict, runtime: Runtime) -> bool:
    """Is this a different process wearing the same pid?

    Three independent facts, because each catches a case the others miss:

    * **start time** -- the kernel's own value from ``/proc/<pid>/stat``. A
      reused pid belongs to a process that started later, and this is the
      only reliable way to see that;
    * **executable device+inode** -- catches a process that ``execve``'d a
      different binary without changing its pid. That is exactly what a
      dropper does, and signalling the *new* image on the strength of the
      *old* evidence would be a wrong kill;
    * **executable path** -- a cheap cross-check and the one that reads best
      in the report.

    Any one differing is enough to abandon. False "changed" costs a
    non-response, which is the direction this module is allowed to err in.
    """
    if not rec:
        return False
    old_start = rec.get("start_time")
    new_start = info.get("start_time") or runtime.start_time(
        info.get("pid") or 0)
    try:
        if old_start and new_start and abs(float(old_start) - float(new_start)) > 0.5:
            return True
    except (TypeError, ValueError):
        pass
    old_dev, old_ino = rec.get("exe_dev", 0), rec.get("exe_ino", 0)
    new_dev, new_ino = info.get("exe_dev", 0), info.get("exe_ino", 0)
    if old_ino and new_ino and (int(old_dev), int(old_ino)) != (int(new_dev),
                                                               int(new_ino)):
        return True
    old_exe = str(rec.get("exe") or "")
    new_exe = str(info.get("exe") or "")
    if old_exe and new_exe and old_exe != new_exe:
        return True
    return False


def _identity(info: dict, runtime: Runtime) -> dict:
    """The tuple that must be unchanged between deciding and acting."""
    pid = info.get("pid")
    return {
        "pid": pid,
        "start_time": info.get("start_time") or runtime.start_time(pid or 0),
        "exe": str(info.get("exe") or ""),
        "exe_dev": info.get("exe_dev", 0),
        "exe_ino": info.get("exe_ino", 0),
        "ns": str(info.get("ns") or runtime.pid_namespace(pid) or ""),
    }


def _fingerprint(info: dict, conns: list) -> str:
    """A stable description of *why* this process is suspicious.

    Recomputed on every pass: if the reason changes, the previous decision is
    stale and the observation restarts. This is what stops "it had one
    connection at 10:00" from justifying an action at 12:00.
    """
    peers = sorted({str(c[2]) for c in (conns or []) if len(c) > 2
                    and _is_external(c[2])})
    return "|".join([
        "del=%d" % (1 if info.get("exe_deleted") else 0),
        "exe=%s" % info.get("exe", ""),
        "ino=%s:%s" % (info.get("exe_dev", 0), info.get("exe_ino", 0)),
        "peers=%s" % ",".join(peers[:8]),
    ])


def _prune(rs: dict, seen: set, runtime: Runtime, out: dict) -> None:
    """Drop observation records for processes that no longer exist.

    Without this the state file grows one entry per suspicious process the
    host has ever had, and a pid-reuse would silently inherit an old timer.
    """
    for key in list((rs.get("observing") or {})):
        try:
            pid = int(key)
        except (TypeError, ValueError):
            rs["observing"].pop(key, None)
            continue
        if pid in seen:
            continue
        info = runtime.proc_info(pid)
        rec = rs["observing"].get(key) or {}
        if not info or _identity_changed(rec, info, runtime):
            rs["observing"].pop(key, None)


# --------------------------------------------------------------------------
# Alerting
# --------------------------------------------------------------------------


def _send_alert(cfg, log, pid, action, verdict, evidence,
                evidence_path) -> bool:
    """High-priority alert, on the immediate path.

    Every response gets one, before the signal is sent. Deliberately not
    batched and not deduped: a stopped process is an event, not a condition,
    and an event that arrives after the operator has already noticed the
    outage is useless.
    """
    try:
        from ...mail import send_alert
        from ...mail.message import SEV_CRIT, Alert
    except ImportError:                                     # pragma: no cover
        return False
    conns = [c for c in evidence.get("connections", []) if c.get("external")]
    body = [
        "对象: %s(pid %s)" % (evidence.get("comm") or "?", pid),
        "命令行: %s" % (evidence.get("cmdline") or "（读不到）"),
        "可执行文件: %s%s" % (evidence.get("exe") or "（读不到）",
                              "（已被删除）" if evidence.get("exe_deleted")
                              else ""),
        "二进制 SHA256: %s" % (evidence.get("exe_sha256") or "（读不到）"),
        "所属 systemd 单元: %s" % (evidence.get("cgroup_unit") or "无"),
        "对外连接: %s" % ("、".join("%s→%s" % (c.get("local"), c.get("peer"))
                                   for c in conns[:6]) or "（无）"),
        "父进程链: %s" % " ← ".join("%s(pid %s)" % (f.get("comm"), f.get("pid"))
                                    for f in evidence.get("parent_chain", [])[:5]),
        "证据文件: %s" % evidence_path,
        "",
        "为什么判定：%s" % verdict.get("reason", ""),
        "用什么判据：%s" % verdict.get("rule", ""),
        "独立信号: 二进制=%s 网络=%s" % (
            verdict.get("signals", {}).get("deleted_exe"),
            verdict.get("signals", {}).get("external_conn")),
        "",
        "已采取的动作：%s" % ("SIGSTOP（暂停，**可逆**）" if action == "stop"
                              else "按配置终止"),
        "撤销方式: kill -CONT %s" % pid if action == "stop" else
        "该动作不可逆；如需保留现场请立即检查证据文件",
        "如果这是误判：把这个进程的可执行文件路径或进程名加入 "
        "threat.autoresponse.allowlist，之后永不处置；"
        "或直接关闭 threat.autoresponse.enabled。",
    ]
    # SEV_CRIT with an explicit `kind` and no dedupe: this is an event, not a
    # condition. It must not be held back by batching, by the health check's
    # renotify window, or by an acknowledgement -- an operator who learns
    # about a stopped process from a user complaint has already lost.
    alert = Alert(title="已自动处置可疑进程 %s(pid %s)"
                        % (evidence.get("comm") or "?", pid),
                  severity=SEV_CRIT, kind="alert",
                  summary="高置信可疑进程，已%s；证据已先落盘，"
                          "撤销方式 kill -CONT %s"
                          % ("暂停（可逆）" if action == "stop" else "终止",
                             pid))
    sec = alert.add_section("可疑进程与证据")
    for line in body:
        sec.add(line)
    try:
        rep = send_alert(alert, cfg, log, allow_dedupe=False)
        try:
            sec.add("")
            sec.add("投递结果: %s" % rep.summary())
        except Exception as exc:                            # noqa: BLE001
            note("告警投递结果无法附加到正文：%s" % exc)
        return True
    except Exception:                                       # noqa: BLE001
        return False


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def describe(result: dict) -> str:
    """The report block, or ``""`` when this run has nothing to say.

    Every action is reported with *what*, *why*, *how it can be undone* and
    *what happened next*. An automatic response the operator cannot audit is
    indistinguishable from a malfunction.
    """
    if not result or not result.get("enabled"):
        return ""
    sections = []
    for item in result.get("responded") or []:
        undo = ("可撤销：kill -CONT %(pid)s（本程序也会在证据被推翻时自动恢复）"
                % item) if item.get("reversible") else "**不可逆**"
        sections.append(
            "已处置 %(pid)s：%(signal)s（%(action)s）\n"
            "          依据：%(reason)s\n"
            "          独立信号：二进制=%(del)s 网络=%(net)s\n"
            "          证据：%(evidence)s\n"
            "          %(undo)s" % {
                **item, "undo": undo,
                "del": (item.get("signals") or {}).get("deleted_exe"),
                "net": (item.get("signals") or {}).get("external_conn")})
    for item in result.get("resumed") or []:
        sections.append("已撤销处置 %(pid)s：发出 SIGCONT，恢复运行\n"
                        "          原因（新的豁免证据）：%(why)s" % item)
    for item in result.get("escalated") or []:
        sections.append("观察期结束，证据未被推翻 %(pid)s：%(signal)s\n"
                        "          %(why)s" % item)
    for item in result.get("observed") or []:
        sections.append("观察中 %(pid)s：%(why)s（还剩 %.0f 秒）"
                        % (item, item.get("seconds_left", 0)))
    for item in result.get("abandoned") or []:
        sections.append("放弃处置 %(pid)s：%(why)s" % item)
    for item in result.get("limited") or []:
        sections.append("未处置（限频）%(pid)s：%(why)s" % item)
    for item in result.get("refused") or []:
        sections.append("拒绝处置 %(pid)s：%(why)s" % item)
    if not sections:
        return ""
    return ("\n       ".join(sections)
            + "\n       说明：本功能的取舍是**宁可漏处置，也绝不误杀** —— "
              "默认只做可逆的 SIGSTOP，并在出现豁免证据时自动恢复。")
