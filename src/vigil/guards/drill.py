"""Attack drills: multi-source, multi-layer traffic, and whether the host noticed.

What this is for
----------------
Every other part of this program *claims* something: the shield claims to
block scanners, the decoys claim to be tripwires, the threat daemon claims to
ban, the mailer claims to deliver. A drill is how those claims get checked
against a running host instead of against a unit test. It generates real
traffic from real distinct source addresses, in several shapes, over several
rounds, and then reports what the defences actually did.

The shape of the traffic is deliberately unpleasant in a specific way:

* **multiple sources** -- every request comes from a different address, so
  nothing can be dismissed as "one noisy client";
* **multiple layers** -- scanning, tripwires, oversized requests, bad hosts,
  PHP probing and the login gate, so a defence that covers only one shape is
  visibly incomplete;
* **repeated and jumping** ("打一枪换一个地方") -- each source fires once and
  moves on, over many rounds, so per-IP reputation alone cannot explain the
  result;
* **a control vector** -- ordinary requests that must keep succeeding. A
  drill that only measures blocking cannot tell "defended" from "broken": a
  host that refuses everything scores perfectly on every attack vector. The
  control is what makes the other numbers mean anything.

How the sources are real
------------------------
A source address in a log is only interesting if it is real. This module
builds a small network lab with network namespaces, one per source, each in
its own ``/24`` on a private bridge, and sends genuine TCP from them. The host
sees genuine connections from genuinely distinct addresses, so the whole
pipeline -- nginx logging, log tailing, detection, ipset enforcement -- is
exercised end to end rather than simulated.

Those addresses are RFC1918, which this program's own rails correctly refuse
to escalate into a *network* ban, and it correctly declines to let them raise
the host's threat posture. So a private lab exercises per-host banning and
every detection path, but not netblock escalation; that is reported honestly
rather than papered over.

Safety
------
A tool that generates attacks has to be harder to point at the wrong thing
than a tool that does not. So: the target must resolve to an address that is
local to this host, the drill refuses to start without an explicit
confirmation, it stops on a STOP file, a memory floor, a conntrack ceiling or
a deadline, and the lab is torn down in a ``finally`` so a crash cannot leave
namespaces, bridges or addresses behind.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import threat

#: Bridge and address prefix for the lab. Deliberately outside anything this
#: host routes today; `lab_up` refuses to build on an in-use prefix.
LAB_BRIDGE = "vigil-lab"
LAB_PREFIX = "10.213"
LAB_NETNS = "vigil-lab-%d"
LAB_VETH = "vigil-lh-%d"
#: A source that never attacks, used only for the control layer.
CONTROL_NETNS = "vigil-lab-ctl"
CONTROL_IP = "10.213.254.2"

#: Guardrails. A drill is a load generator, so it needs the same rails a
#: stress test needs -- and the memory floor is the one that matters most on
#: a 2 GB host that must keep alerting while the drill runs.
STOP_FILE = "/run/vigil-drill.stop"
MEM_FLOOR_MB = 180
CONNTRACK_CEILING = 75.0
DEFAULT_MAX_REQUESTS = 4000
DEFAULT_ROUNDS = 6

#: Layers whose request shape is fixed. Anything derived from the installed
#: configuration (the tripwires) is added by `build_layers` instead.
#:
#: `blocked` lists the codes that mean the defence acted; `forbid` lists
#: codes that must never appear. The distinction matters: a sensitive path
#: answering 404 is fine and answering 200 is a leak, and calling that
#: "blocked" would confuse "we refused it" with "it was never there".
FIXED_LAYERS = (
    {"id": "control", "label": "对照（必须一直可用）",
     "path": "/", "headers": {}, "blocked": (), "forbid": ()},
    # 0 is included on every attack layer: once a source is banned the
    # connection is dropped before nginx even sees it, which is a stronger
    # outcome than a refusal, not a miss. Counting only the rule's own status
    # code made a well-defended host look like it was letting traffic
    # through. "The server is down" is ruled out separately by the control
    # layer, which comes from a source that is never banned.
    {"id": "scanner_ua", "label": "扫描器 UA（shield 拦截）",
     "path": "/", "headers": {"User-Agent": "Nikto/2.1.6"},
     "blocked": (403, 0), "forbid": ()},
    {"id": "long_uri", "label": "超长 URI（请求行拒绝）",
     "path": "/" + "a" * 5000, "headers": {}, "blocked": (414, 444, 0),
     "forbid": ()},
    {"id": "bad_host", "label": "超长 Host（连接断开）",
     "path": "/", "headers": {"Host": "a" * 600 + ".top"},
     "blocked": (444, 0), "forbid": ()},
    {"id": "sensitive", "label": "敏感文件（不得返回 200）",
     "paths": ["/.env", "/wp-config.php.bak", "/.git/HEAD"],
     "headers": {}, "blocked": (), "forbid": (200,)},
)

#: The scheme matters more than it looks. This host's vhost rewrites http to
#: https with `rewrite ... permanent` in the *rewrite* phase, which runs
#: before any of the shield's rules. A drill over plain http therefore
#: measures the redirect and reports every attack layer as unblocked -- an
#: instrument that lies, which is the failure this codebase keeps finding in
#: other people's software. The protected surface is https.
SCHEME = "https"


def _extension_roots() -> list:
    from ..core import detect
    roots = []
    try:
        conf = (detect.nginx() or {}).get("conf", "")
        if conf:
            roots.append(Path(conf).parent / "vhost" / "nginx" / "extension")
    except (OSError, AttributeError):
        pass
    roots.append(Path("/www/server/panel/vhost/nginx/extension"))
    return [r for r in roots if r.is_dir()]


def decoy_paths(limit: int = 4) -> list:
    """The tripwires actually installed, read from the generated config.

    Derived rather than hardcoded: a drill that tests a path this site does
    not actually trap proves nothing about the tripwires that are there, and
    would keep "passing" after the decoys were uninstalled.
    """
    out = []
    for root in _extension_roots():
        try:
            sites = sorted(p for p in root.iterdir() if p.is_dir())
        except OSError:
            continue
        for site in sites:
            conf = site / "vigil-decoy.conf"
            if not conf.is_file():
                continue
            try:
                text = conf.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for m in re.finditer(r"location\s*=\s*(\S+)\s*\{", text):
                path = m.group(1)
                if path not in out:
                    out.append(path)
    return out[:limit]


def build_layers(with_decoys: bool = True) -> list:
    """The full layer set for this host, tripwires included."""
    layers = [dict(l) for l in FIXED_LAYERS]
    if with_decoys:
        paths = decoy_paths()
        if paths:
            layers.insert(3, {"id": "decoy", "label": "诱饵路径（触发即封）",
                              "paths": paths, "headers": {},
                              "blocked": (403, 404, 444, 0), "forbid": ()})
    return layers


LAYERS = build_layers()
LAYER_BY_ID = {l["id"]: l for l in LAYERS}


class DrillError(RuntimeError):
    """Raised when a drill cannot start, or must stop."""


# --------------------------------------------------------------------------
# safety
# --------------------------------------------------------------------------

def local_addresses() -> set:
    """Every address this host answers on."""
    out = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            out.add(info[4][0])
    except OSError:
        pass
    try:
        proc = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True,
                              text=True, timeout=10)
        for line in (proc.stdout or "").splitlines():
            parts = line.split()
            if len(parts) >= 4:
                out.add(parts[3].split("/")[0])
    except (OSError, subprocess.SubprocessError):
        pass
    return out


def default_target() -> str:
    """This host's own routable address, for when the caller names none.

    Resolved rather than hardcoded: the shipped package must not carry one
    installation's address, and a drill run on a different host must aim at
    *that* host without being edited.
    """
    for addr in sorted(local_addresses()):
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if ip.version == 4 and not ip.is_loopback and not ip.is_link_local:
            return str(ip)
    return "127.0.0.1"


def assert_target_is_local(target: str) -> str:
    """Refuse to aim a drill at anybody but ourselves.

    This is the rail that keeps a load generator from becoming an attack
    tool. It resolves the target and requires the result to be an address
    this host actually holds.
    """
    try:
        infos = socket.getaddrinfo(target, None)
    except OSError as e:
        raise DrillError("无法解析目标 %s：%s" % (target, e))
    addrs = {i[4][0] for i in infos}
    mine = local_addresses()
    if not (addrs & mine):
        raise DrillError(
            "目标 %s 解析为 %s，但本机地址是 %s —— 只允许对本机演练"
            % (target, "、".join(sorted(addrs)), "、".join(sorted(mine))))
    return sorted(addrs & mine)[0]


# --------------------------------------------------------------------------
# guardrails
# --------------------------------------------------------------------------

def _mem_available_mb() -> float:
    try:
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) / 1024.0
    except (OSError, ValueError, IndexError):
        pass
    return 9999.0


def _conntrack_pct() -> float:
    try:
        with open("/proc/sys/net/netfilter/nf_conntrack_count") as fh:
            cur = int(fh.read().strip())
        with open("/proc/sys/net/netfilter/nf_conntrack_max") as fh:
            mx = int(fh.read().strip())
        return 100.0 * cur / mx if mx else 0.0
    except (OSError, ValueError):
        return 0.0


def abort_reason(deadline: float = 0.0) -> str:
    """Why the drill must stop now, or "" to continue.

    Checked between rounds rather than between requests: stopping mid-round
    leaves the lab half-used and makes the numbers harder to read, and one
    round is short enough that this is still an early stop.
    """
    if os.path.exists(STOP_FILE):
        return "检测到停止文件 %s" % STOP_FILE
    if deadline and time.time() > deadline:
        return "已到时间上限"
    free = _mem_available_mb()
    if free < MEM_FLOOR_MB:
        return "可用内存 %.0f MB 低于下限 %d MB" % (free, MEM_FLOOR_MB)
    ct = _conntrack_pct()
    if ct > CONNTRACK_CEILING:
        return "conntrack 使用率 %.1f%% 超过上限 %.0f%%" % (ct, CONNTRACK_CEILING)
    return ""


def guardrail_state() -> dict:
    return {"mem_available_mb": round(_mem_available_mb(), 1),
            "mem_floor_mb": MEM_FLOOR_MB,
            "conntrack_pct": round(_conntrack_pct(), 2),
            "conntrack_ceiling_pct": CONNTRACK_CEILING,
            "stop_file": STOP_FILE}


# --------------------------------------------------------------------------
# the lab
# --------------------------------------------------------------------------

def _run(cmd: list, timeout: int = 20) -> tuple:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode == 0, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)


def lab_present() -> bool:
    ok, _o = _run(["ip", "netns", "list"])
    if not ok:
        return False
    ok2, out = _run(["ip", "netns", "list"])
    return any(LAB_NETNS % i in out for i in range(1, 64))


def lab_up(count: int = 8, log=None) -> list:
    """Build `count` sources, each its own address in its own /24."""
    if not shutil.which("ip"):
        raise DrillError("缺少 ip 命令，无法建立多来源实验网")
    if count < 1:
        raise DrillError("来源数量必须大于 0")

    ok, out = _run(["ip", "route", "show"])
    if ok and ("%s." % LAB_PREFIX) in out and LAB_BRIDGE not in out:
        raise DrillError("%s 前缀已被占用，拒绝在现有路由上建实验网" % LAB_PREFIX)

    sources = []
    _run(["ip", "link", "add", LAB_BRIDGE, "type", "bridge"])
    _run(["ip", "addr", "add", "%s.0.1/16" % LAB_PREFIX, "dev", LAB_BRIDGE])
    _run(["ip", "link", "set", LAB_BRIDGE, "up"])

    for i in range(1, count + 1):
        ns = LAB_NETNS % i
        vh, vg = LAB_VETH % i, "vigil-lg-%d" % i
        ip = "%s.%d.2" % (LAB_PREFIX, i)
        _run(["ip", "netns", "add", ns])
        _run(["ip", "link", "add", vh, "type", "veth", "peer", "name", vg])
        _run(["ip", "link", "set", vg, "netns", ns])
        _run(["ip", "link", "set", vh, "master", LAB_BRIDGE])
        _run(["ip", "link", "set", vh, "up"])
        # /16 on the interface so the gateway is on-link, while the *address*
        # still sits in its own /24 -- the /24 is what makes the sources
        # genuinely independent for anything that groups by network.
        _run(["ip", "netns", "exec", ns, "ip", "addr", "add",
              "%s/16" % ip, "dev", vg])
        _run(["ip", "netns", "exec", ns, "ip", "link", "set", vg, "up"])
        _run(["ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"])
        _run(["ip", "netns", "exec", ns, "ip", "route", "add", "default",
              "via", "%s.0.1" % LAB_PREFIX])
        sources.append({"name": ns, "netns": ns, "ip": ip,
                        "net24": str(ipaddress.ip_network("%s/24" % ip,
                                                          strict=False))})
    # The control source is deliberately *not* one of the attackers. Once a
    # source is banned, every later request from it is dropped at the
    # firewall, so a control sent from an attacking source measures "the
    # attacker was banned" and reports it as "normal traffic is broken". The
    # control has to come from a client that never attacks, or it proves
    # nothing about ordinary visitors.
    vh, vg = "vigil-lh-ctl", "vigil-lg-ctl"
    _run(["ip", "netns", "add", CONTROL_NETNS])
    _run(["ip", "link", "add", vh, "type", "veth", "peer", "name", vg])
    _run(["ip", "link", "set", vg, "netns", CONTROL_NETNS])
    _run(["ip", "link", "set", vh, "master", LAB_BRIDGE])
    _run(["ip", "link", "set", vh, "up"])
    _run(["ip", "netns", "exec", CONTROL_NETNS, "ip", "addr", "add",
          "%s/16" % CONTROL_IP, "dev", vg])
    _run(["ip", "netns", "exec", CONTROL_NETNS, "ip", "link", "set", vg, "up"])
    _run(["ip", "netns", "exec", CONTROL_NETNS, "ip", "link", "set", "lo", "up"])
    _run(["ip", "netns", "exec", CONTROL_NETNS, "ip", "route", "add", "default",
          "via", "%s.0.1" % LAB_PREFIX])
    sources.append({"name": CONTROL_NETNS, "netns": CONTROL_NETNS,
                    "ip": CONTROL_IP,
                    "net24": str(ipaddress.ip_network("%s/24" % CONTROL_IP,
                                                      strict=False))})
    if log:
        log.info("已建立 %d 个演练来源" % len(sources))
    return sources


def lab_down(log=None) -> int:
    """Remove the lab. Safe to call when nothing is up."""
    removed = 0
    for i in range(1, 64):
        ok, _o = _run(["ip", "netns", "del", LAB_NETNS % i])
        if ok:
            removed += 1
        _run(["ip", "link", "del", LAB_VETH % i])
    _run(["ip", "netns", "del", CONTROL_NETNS])
    _run(["ip", "link", "del", "vigil-lh-ctl"])
    _run(["ip", "link", "del", LAB_BRIDGE])
    if log and removed:
        log.info("已清理 %d 个演练来源" % removed)
    return removed


# --------------------------------------------------------------------------
# planning and execution
# --------------------------------------------------------------------------

def plan(rounds: int = DEFAULT_ROUNDS, n_sources: int = 8,
         per_source: int = 3, layers: tuple = None) -> list:
    """Build the request schedule.

    Jumping is the point: consecutive requests from one source use different
    layers, and consecutive requests for one layer come from different
    sources, so no defence can pass by remembering a single client.
    """
    layers = [l for l in (layers or [x["id"] for x in LAYERS])
              if l != "control"]
    out = []
    for r in range(rounds):
        # One ordinary request per round, from the source that never attacks.
        out.append({"round": r + 1, "source": CONTROL_NETNS, "layer": "control"})
        for s in range(1, n_sources + 1):
            for k in range(per_source):
                lid = layers[(r + s + k) % len(layers)]
                out.append({"round": r + 1, "source": LAB_NETNS % s,
                            "layer": lid})
    return out


def _one_request(src: dict, layer: dict, target: str, timeout: int = 8,
                 pick: int = 0) -> dict:
    """Fire one request from one source. Returns code and layer id."""
    path = layer.get("path")
    if not path:
        paths = layer.get("paths") or ["/"]
        path = paths[pick % len(paths)]
    # -k: the lab has no DNS, so the request goes to the address with SNI
    # equal to it and the certificate will not match. That is irrelevant to
    # what is being measured -- whether the rules fire -- and refusing to
    # skip verification would measure the certificate instead.
    url = "%s://%s%s" % (SCHEME, target, path)
    cmd = ["ip", "netns", "exec", src["netns"], "curl", "-sk", "-o", "/dev/null",
           "-w", "%{http_code}", "--max-time", str(timeout), "-H",
           "Connection: close"]
    for k, v in layer["headers"].items():
        cmd += ["-H", "%s: %s" % (k, v)]
    cmd.append(url)
    started = time.time()
    ok, out = _run(cmd, timeout=timeout + 4)
    code = 0
    text = (out or "").strip().splitlines()[-1] if ok and out.strip() else "0"
    try:
        code = int(text)
    except ValueError:
        code = 0
    return {"layer": layer["id"], "source": src["ip"], "code": code,
            "seconds": round(time.time() - started, 3)}


def run(cfg=None, rounds: int = DEFAULT_ROUNDS, n_sources: int = 8,
        per_source: int = 3, workers: int = 16, target: str = "",
        deadline_seconds: int = 300, max_requests: int = DEFAULT_MAX_REQUESTS,
        settle_seconds: int = 20, dry_run: bool = False, log=None) -> dict:
    """Run a drill and report what happened.

    Never raises for a defence that did not respond -- that is a *finding*,
    and a drill that crashes on a finding is a drill nobody runs twice. It
    raises only for conditions that make the result meaningless: a target
    that is not us, or a lab that cannot be built.
    """
    ip = assert_target_is_local(target or default_target())
    schedule = plan(rounds, n_sources, per_source)
    if len(schedule) > max_requests:
        schedule = schedule[:max_requests]
    if dry_run:
        return {"dry_run": True, "target": ip, "requests": len(schedule),
                "sources": n_sources, "rounds": rounds,
                "layers": [l["id"] for l in LAYERS],
                "guardrails": guardrail_state()}

    before = _enforcement_snapshot(cfg)
    deadline = time.time() + deadline_seconds if deadline_seconds else 0.0
    by_layer, ok_count, aborted = {}, 0, ""
    started = time.time()
    held = lab_up(n_sources, log=log)
    # Were any of these sources already banned before we started? If so the
    # ban *delta* is not a measurement -- the traffic will be dropped by the
    # existing ban and "no new bans" would be reported for a defence that was
    # never asked to do anything. This is the observation failure this
    # codebase keeps meeting, so the drill checks for it and says so.
    pre_banned = []
    try:
        pre_banned = [s["ip"] for s in held if s["ip"] in set(_lab_bans(cfg))]
    except Exception:                                       # noqa: BLE001
        pre_banned = []
    try:
        srcs = {s["netns"]: s for s in held}
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            for rnd in range(1, rounds + 1):
                reason = abort_reason(deadline)
                if reason:
                    aborted = reason
                    break
                batch = [s for s in schedule if s["round"] == rnd]
                if not batch:
                    continue
                futs = [pool.submit(_one_request, srcs[s["source"]],
                                    LAYER_BY_ID[s["layer"]], ip, 8, i)
                        for i, s in enumerate(batch) if s["source"] in srcs]
                for f in futs:
                    r = f.result()
                    ok_count += 1
                    d = by_layer.setdefault(r["layer"],
                                            {"n": 0, "codes": {}, "blocked": 0})
                    d["n"] += 1
                    d["codes"][str(r["code"])] = d["codes"].get(str(r["code"]), 0) + 1
                    if r["code"] in LAYER_BY_ID[r["layer"]]["blocked"]:
                        d["blocked"] += 1
    finally:
        lab_down(log=log)

    # Let the pipeline finish before judging it. Traffic stops the instant the
    # last request returns, but detection is asynchronous: the daemon has to
    # tail the log, decide, and write the ban. Measuring immediately reports
    # "no new bans" for a defence that is about to ban everything -- a false
    # finding produced entirely by the measurement, which is the failure this
    # program keeps finding in other people's software.
    if settle_seconds:
        time.sleep(settle_seconds)
    after = _enforcement_snapshot(cfg)
    res = _verdict(by_layer, before, after, ok_count, aborted,
                   round(time.time() - started, 1), ip, n_sources, rounds)
    res["netblock_rail"] = netblock_rail_check(cfg)
    res["pre_banned"] = pre_banned
    return res


def _enforcement_snapshot(cfg) -> dict:
    """Ban counts before/after, so the drill can tell "we banned it" from
    "we merely refused the request".

    Uses the same reader `vigil status` uses rather than re-deriving the ban
    list, so the drill cannot disagree with the product about what is banned.
    """
    snap = {"banned": 0, "nets": 0, "error": ""}
    try:
        snap["banned"] = len(threat.list_bans(cfg) or [])
    except Exception as e:                                  # noqa: BLE001
        snap["error"] = "读取封禁列表失败：%s" % e
    try:
        snap["nets"] = len(threat.net_members(cfg) or {})
    except Exception:                                       # noqa: BLE001
        pass
    return snap


def netblock_rail_check(cfg, sample_net: str = "") -> dict:
    """Ask the rails directly whether the lab range may become a netblock.

    A drill whose sources are private addresses cannot produce a netblock
    ban, and that is correct behaviour rather than a gap. Saying so is only
    credible if the rail is actually consulted, so this asks it and reports
    the reason it gives.
    """
    net = sample_net or ("%s.1.0/24" % LAB_PREFIX)
    try:
        daemon = threat._cli_daemon(cfg, None, dry_run=True)
        # `netblock_blockers` belongs to the daemon, not to the enforcer.
        # Asking the wrong object raises AttributeError, and an earlier
        # version of this function turned that into "could not ask the rail"
        # -- printed as though it were an answer.
        reason = daemon.netblock_blockers(net)
    except Exception as e:                                  # noqa: BLE001
        return {"net": net, "refused": False, "reason": "无法询问护栏：%s" % e}
    return {"net": net, "refused": bool(reason), "reason": reason or "未拒绝"}


def _verdict(by_layer, before, after, n, aborted, seconds, ip,
             n_sources, rounds) -> dict:
    """Turn raw counts into a statement about the defences.

    The control layer is judged differently from the attack layers, and that
    difference is the whole point: a host that blocks everything passes every
    attack layer and fails the control.
    """
    layers = []
    for lid, d in sorted(by_layer.items()):
        spec = LAYER_BY_ID[lid]
        total = d["n"] or 1
        entry = {"id": lid, "label": spec["label"], "requests": d["n"],
                 "codes": d["codes"],
                 "blocked_pct": round(100.0 * d["blocked"] / total, 1),
                 "dropped": d["codes"].get("0", 0),
                 "blocked_codes": list(spec.get("blocked") or ()),
                 "forbid": list(spec.get("forbid") or ())}
        if lid == "control":
            # The control is the only layer where a 200 is the pass mark, and
            # it is what stops "refuses everything" from scoring perfectly.
            allowed = d["codes"].get("200", 0)
            entry["ok"] = allowed == d["n"] and d["n"] > 0
            entry["verdict"] = ("对照流量全部通过（防御没有误伤正常访问）"
                                if entry["ok"] else
                                "对照流量被拦截：防御过度，会误伤真实访客")
        elif spec.get("forbid"):
            # "Not blocked" is the wrong question for a sensitive path: 404
            # means it was never there, which is fine. The question is
            # whether anything served it.
            leaked = sum(c for code, c in d["codes"].items()
                         if int(code) in spec["forbid"])
            entry["ok"] = leaked == 0 and d["n"] > 0
            entry["verdict"] = ("未泄露（没有一次返回 %s）"
                                % "/".join(str(x) for x in spec["forbid"])
                                if entry["ok"] else
                                "%d 次返回了禁止的响应码" % leaked)
        else:
            entry["ok"] = d["blocked"] == d["n"] and d["n"] > 0
            entry["verdict"] = ("全部被拒" if entry["ok"] else
                                "有 %d/%d 个请求未被拦截" % (d["n"] - d["blocked"], d["n"]))
        layers.append(entry)

    banned_new = max(0, after.get("banned", 0) - before.get("banned", 0))
    return {"target": ip, "sources": n_sources, "rounds": rounds,
            "requests": n, "seconds": seconds, "aborted": aborted,
            "layers": layers,
            "bans_before": before.get("banned", 0),
            "bans_after": after.get("banned", 0),
            "new_bans": banned_new,
            "nets_before": before.get("nets", 0),
            "nets_after": after.get("nets", 0),
            "guardrails": guardrail_state(),
            "note": ("实验来源是 RFC1918 私有地址，本程序的保护栏会正确拒绝"
                     "把它们升级成网段封禁、也不允许它们抬高威胁姿态 —— "
                     "所以本次演练覆盖单机封禁与全部检测路径，不含网段升级。")}


def format_report(res: dict) -> str:
    """A drill report meant to be read, not skimmed for a number."""
    if res.get("dry_run"):
        return ("预演：%d 个请求，%d 个来源 × %d 轮，层次 %s\n护栏：%s"
                % (res["requests"], res["sources"], res["rounds"],
                   "、".join(res["layers"]), res["guardrails"]))
    lines = ["演练目标 %s ｜ %d 个来源 × %d 轮 ｜ 共 %d 个请求 ｜ 耗时 %.1f 秒"
             % (res["target"], res["sources"], res["rounds"], res["requests"],
                res["seconds"])]
    if res.get("aborted"):
        lines.append("提前停止：%s" % res["aborted"])
    lines.append("")
    for e in res["layers"]:
        mark = "✔" if e["ok"] else "✖"
        extra = ""
        if e.get("dropped"):
            # 0 means the connection was dropped, which on this host is what
            # a firewall ban looks like -- not a rule refusing a request.
            # Saying so keeps "blocked" from being read as "matched a rule".
            extra = "（其中 %d 次连接被丢弃＝通常已被封禁）" % e["dropped"]
        lines.append("%s %-26s %3d 个请求  分布 %s  %s%s"
                     % (mark, e["label"], e["requests"],
                        ", ".join("%s×%d" % (k, v)
                                  for k, v in sorted(e["codes"].items())),
                        e["verdict"], extra))
    lines.append("")
    lines.append("封禁条目 %d → %d（新增 %d）｜ 网段 %d → %d"
                 % (res["bans_before"], res["bans_after"], res["new_bans"],
                    res["nets_before"], res["nets_after"]))
    if res.get("pre_banned"):
        lines.append("⚠ 本次有 %d 个来源在演练开始前就已被封禁，"
                     "它们的请求在网络层就被丢弃 —— 因此上方的「新增封禁」"
                     "不能当作本次防御的成果来读。"
                     % len(res["pre_banned"]))
    lines.append(res["note"])
    rail = res.get("netblock_rail") or {}
    if rail:
        lines.append("网段护栏：%s %s（%s）"
                     % (rail.get("net", ""),
                        "已拒绝" if rail.get("refused") else "未拒绝",
                        rail.get("reason", "")))
    lines.append("护栏：可用内存 %.0f MB（下限 %d）｜ conntrack %.1f%%（上限 %.0f%%）"
                 % (res["guardrails"]["mem_available_mb"],
                    res["guardrails"]["mem_floor_mb"],
                    res["guardrails"]["conntrack_pct"],
                    res["guardrails"]["conntrack_ceiling_pct"]))
    return "\n".join(lines)


def _lab_bans(cfg) -> list:
    prefix = "%s." % LAB_PREFIX
    try:
        return [str(b.get("ip", "")) for b in (threat.list_bans(cfg) or [])
                if str(b.get("ip", "")).startswith(prefix)]
    except Exception:                                       # noqa: BLE001
        return []


def cleanup_lab_bans(cfg, log=None, quiesce: float = 20.0,
                     attempts: int = 12, pause: float = 6.0) -> dict:
    """Lift the bans this drill caused, and make sure they stay lifted.

    Judged by the final state, and it takes two consecutive empty readings to
    believe it. Three things make one pass unreliable, all measured on this
    host:

    * detection is asynchronous, so after the traffic stops the daemon is
      still working through the log. Lifting early simply loses the race --
      the drill reported "已解除 20 个" and twenty bans came back;
    * `threat.unban` reports False when the address is in the kernel set but
      not yet in the daemon's records, although it has already removed it.
      Trusting that code reports a successful cleanup as a failure;
    * a ban is re-applied from the daemon's own state, so a single lift can
      be undone a few seconds later.

    So: wait for the ban count to stop moving, lift, and require the list to
    read empty twice in a row before believing it. Only the lab prefix is
    touched -- nothing a real attacker earned is lifted.
    """
    if quiesce:
        time.sleep(quiesce)
    # Let the count settle before deciding anything.
    last = -1
    for _ in range(10):
        cur = len(_lab_bans(cfg))
        if cur == last:
            break
        last = cur
        time.sleep(pause)
    first = set(_lab_bans(cfg))
    empty_streak = 0
    for _ in range(max(1, attempts)):
        current = _lab_bans(cfg)
        if current:
            empty_streak = 0
            for ip in current:
                try:
                    threat.unban(cfg, ip, log=log)
                except Exception:                           # noqa: BLE001
                    pass
        else:
            empty_streak += 1
            if empty_streak >= 2:
                break
        time.sleep(pause)
    remaining = _lab_bans(cfg)
    return {"removed": sorted(first - set(remaining)),
            "remaining": sorted(remaining),
            "failed": sorted(remaining)}


def drain_mail(cfg=None, log=None, max_rounds: int = 40) -> dict:
    """Send everything waiting in the overflow queue, and prove it is empty.

    The drill deliberately provokes alerts, so it is also responsible for
    clearing them. A queue that is still full afterwards means the operator
    is about to be told about a test they already know about -- and the
    backlog hides anything real that arrives behind it.
    """
    from ..mail import queue, send_digest

    sent, rounds = 0, 0
    while rounds < max_rounds:
        left = queue.overflow_count()
        if left <= 0:
            break
        rep = send_digest(cfg, log=log, max_files=25)
        rounds += 1
        delivered = sum(1 for r in rep.results.values() if getattr(r, "ok", False))
        if delivered == 0:
            break
        sent += left - queue.overflow_count()
        if queue.overflow_count() >= left:
            break
    return {"sent": sent, "remaining": queue.overflow_count(),
            "rounds": rounds}


def main(argv=None) -> int:  # pragma: no cover
    import argparse
    ap = argparse.ArgumentParser(description="多来源多层次攻击演练（仅对本机）")
    ap.add_argument("action", nargs="?", default="plan",
                    choices=["plan", "run", "lab-up", "lab-down", "guardrails"])
    ap.add_argument("--sources", type=int, default=8)
    ap.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS)
    ap.add_argument("--per-source", type=int, default=3)
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--target", default="",
                    help="演练目标，默认取本机地址")
    ap.add_argument("--seconds", type=int, default=300)
    ap.add_argument("--settle", type=int, default=20,
                    help="结束后等待检测落地的秒数")
    ap.add_argument("--yes", action="store_true")
    a = ap.parse_args(argv)
    if a.action == "guardrails":
        print(guardrail_state())
        return 0
    if a.action == "lab-up":
        print(lab_up(a.sources))
        return 0
    if a.action == "lab-down":
        print("removed %d" % lab_down())
        return 0
    if a.action == "plan":
        print(format_report(run(rounds=a.rounds, n_sources=a.sources,
                                per_source=a.per_source, dry_run=True)))
        return 0
    if not a.yes:
        print("拒绝执行：演练会产生真实攻击流量，需要 --yes 确认")
        return 2
    print(format_report(run(rounds=a.rounds, n_sources=a.sources,
                            per_source=a.per_source, workers=a.workers,
                            target=a.target, deadline_seconds=a.seconds)))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
