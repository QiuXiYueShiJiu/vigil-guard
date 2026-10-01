"""Network checks (group ``network``).

Ported from ``c_netconn``: find connections this host opened *outbound* to an
uncommon remote port -- a backdoor calling home, or a miner talking to its
pool.

The direction distinction is the whole point and was a real defect before it
was fixed: an inbound client connecting to our 443 has a *client-side
ephemeral* remote port, which is never in the "common ports" list, so a naive
check reports every visitor as an intruder. We therefore take the set of local
listening ports first and only consider a connection outbound when its local
port is **not** in that set.

A second defect: ``ss -H state established`` omits the State column, so the
fields shift left and positional indexing picks the process name as the peer
address. Addresses are matched by shape (``addr:port``) instead.
"""
from __future__ import annotations

import re

from . import util
from .base import (G_NETWORK, OK, WARN, Check, CheckContext, CheckResult,
                   register)
from ...core import shell

#: Remote ports that are overwhelmingly legitimate outbound traffic (web,
#: DNS, mail submission, ssh, ntp, git). Generic protocol defaults, not host
#: specific; override with ``checks.outbound_connections.safe_ports``.
_DEFAULT_SAFE = ("22", "25", "53", "80", "123", "443", "465", "587", "993",
                 "995", "9418", "8080", "8443")

#: Ports that are unusual *unless* they lead to the organisation that owns
#: them, written ``port@owner-substring``. The pair is the whole point: the
#: exception needs the port **and** the destination's registered owner to
#: match, and nobody runs a command-and-control server on an address the
#: WHOIS/geo databases attribute to Google. A bare ``port`` (no ``@``) means
#: "never report this port", which is a deliberate operator choice.
#:
#: This exists because a headless browser kept tripping the check. Chrome's
#: push-messaging channel is FCM/GCM on 5228-5230, so every Puppeteer run
#: produced "可能是后门回连 C2" -- and the honest answer is "known service",
#: not "stop looking at unusual ports".
#:
#: Override with ``checks.outbound_connections.known_services``.
_DEFAULT_KNOWN = ("5228@google", "5229@google", "5230@google")

_ADDR = re.compile(r"(\[[0-9a-fA-F:]+\]|[0-9]{1,3}(?:\.[0-9]{1,3}){3}):(\d+)")
_PROC = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')


def _known_ports(known) -> dict:
    """``{"5228": ["google"]}`` -- empty owner list means "any destination"."""
    out = {}
    for item in known or ():
        text = str(item or "").strip().lower()
        if not text:
            continue
        port, _, owner = text.partition("@")
        port = port.strip()
        if port:
            out.setdefault(port, []).append(owner.strip())
    return out


@register
class OutboundConnections(Check):
    id = "outbound_connections"
    label = "对外连接异常"
    label_en = "Outbound connections"
    group = G_NETWORK
    description = "本机主动发起的、远端端口不常见的对外连接（后门回连/矿池）"

    def run(self, ctx: CheckContext) -> CheckResult:
        listening = self._listening_ports()
        if listening is None:
            return CheckResult(OK, "ss 不可用，跳过对外连接检查")

        ok, out, _err = shell.run(
            ["ss", "-tnpH", "state", "established"], timeout=15)
        if not ok:
            return CheckResult(OK, "无法读取已建立连接（ss 执行失败），跳过检查")

        safe = set(str(p) for p in (
            ctx.copt("outbound_connections", "safe_ports", _DEFAULT_SAFE)
            or _DEFAULT_SAFE))
        known = _known_ports(
            ctx.copt("outbound_connections", "known_services", _DEFAULT_KNOWN)
            or _DEFAULT_KNOWN)
        found = []
        recognised = []
        for line in out.splitlines():
            addrs = _ADDR.findall(line)
            if len(addrs) < 2:
                continue
            local_ip, local_port = addrs[0]
            peer_ip, peer_port = addrs[1]
            if local_port in listening:
                continue                       # we are the server: inbound
            if peer_ip.startswith("127.") or peer_ip in ("[::1]", "::1"):
                continue
            if peer_ip.startswith("169.254."):
                continue
            if peer_port in safe:
                continue
            m = _PROC.search(line)
            who = "%s(pid %s)" % (m.group(1), m.group(2)) if m else "未知进程"
            local = "%s:%s" % (local_ip, local_port)

            owners = known.get(peer_port)
            if owners is not None:
                # Only resolved for ports somebody asked about, so the common
                # case costs no lookup.
                where = util.geo(ctx.cfg, peer_ip)
                flat = where.lower()
                if any(not o or o in flat for o in owners):
                    recognised.append("%s → %s:%s  [%s]" % (local, where,
                                                            peer_port, who))
                    continue

            found.append((local, peer_ip, peer_port, who))

        if not found:
            detail = "无异常对外连接"
            if recognised:
                detail += ("（另有 %d 条已识别的已知服务连接：%s）"
                           % (len(recognised), "；".join(recognised[:3])))
            return CheckResult(OK, detail)

        lines = []
        for local, peer_ip, peer_port, who in found[:5]:
            where = util.geo(ctx.cfg, peer_ip)
            lines.append("%s\n           → %s:%s  [%s]" % (local, where,
                                                           peer_port, who))
        if len(found) > 5:
            lines.append("…… 等 %d 条未展开" % (len(found) - 5))
        hint = ""
        if not recognised:
            hint = ("\n       若确认是已知服务，可加入白名单："
                    "vigil config set checks.outbound_connections.known_services "
                    "'[\"端口@机构关键字\"]'")
        return CheckResult(WARN,
                           "发现 **%d 条**本机主动发起的非常用端口连接"
                           "（可能是后门回连 C2 或数据外传，请确认目标是否为你已知的服务）：\n"
                           "       %s\n"
                           "       确认为陌生后请终止对应进程并对全盘查杀。%s"
                           % (len(found), "\n       ".join(lines), hint))

    @staticmethod
    def _listening_ports():
        """Set of local listening ports, or None when ``ss`` is unusable."""
        items = util.listening_ports()
        if not items:
            return None
        ports = set()
        for item in items:
            local = item.partition(" ")[2]
            if local:
                ports.add(local.rsplit(":", 1)[-1])
        return ports
