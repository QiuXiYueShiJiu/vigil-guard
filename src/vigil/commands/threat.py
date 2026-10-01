"""`vigil threat` -- inspect and steer the real-time risk engine."""
from __future__ import annotations

from pathlib import Path

import json as _json
import os
import time

from .. import ui
from ..core.config import load as load_config
from ..core.errors import VigilError


def _engine(cfg):
    from ..guards import threat
    return threat


def cmd_netblock(args) -> int:
    """Show or withdraw network-range bans.

    Withdrawing is a first-class operation, not an afterthought. Escalation
    trades precision for reach, and the moment an operator can see that a
    range was banned there has to be a way to undo it -- otherwise the honest
    response to the alert ("did this hit a shared ISP range?") has nowhere to
    go, and the range stays blocked out of inertia.
    """
    from ..guards import threat as threat_mod

    cfg = load_config(args.config or None)
    engine = _engine(cfg)
    members = engine.net_members(cfg)

    # Two ways in on purpose: `vigil threat netblock clear <net>` reads
    # naturally, and `--clear` matches the posture command. Checking only the
    # flag made the verb a no-op that silently listed instead of clearing.
    if args.clear or args.action == "clear":
        target = args.net or "all"
        if target == "all":
            if not members:
                ui.note("当前没有网段封禁")
                return 0
            for net in list(members):
                engine.remove_net(cfg, net)
            ui.success("已解除全部 %d 个网段封禁" % len(members))
            ui.note("被单独封禁的地址不受影响")
            return 0
        if target not in members:
            ui.failure("%s 当前不在网段封禁列表中" % target)
            return 1
        ok = engine.remove_net(cfg, target)
        (ui.success if ok else ui.failure)(
            "已解除 %s" % target if ok else "解除 %s 失败" % target)
        return 0 if ok else 1

    ui.header("网段升级封禁", "同一网段内多个独立来源协同攻击时的自动升级")
    ui.kv("开关", "启用" if cfg.get("threat.netblock.enabled", True) else "已关闭",
          "" if cfg.get("threat.netblock.enabled", True) else "yellow")
    ui.kv("触发条件", "%d 秒内同一网段出现 %s 个独立来源"
          % (cfg.get("threat.netblock.window_seconds"),
             cfg.get("threat.netblock.min_ips")))
    ui.kv("封禁时长", "%s 秒" % cfg.get("threat.netblock.ban_seconds"))
    ui.kv("同时上限", "%s 个网段" % cfg.get("threat.netblock.max_current"))
    ui.kv("只允许宽度", "/24（IPv4）与 /48（IPv6）—— 更宽会波及无辜")
    ui.out()

    if not members:
        ui.note("当前没有被网段封禁的地址段")
        return 0

    ui.section("当前封禁的网段")
    for net, left in sorted(members.items()):
        ui.kv(net, "剩 %s" % ("%.1f 小时" % (left / 3600.0) if left > 3600
                              else "%d 分钟" % max(1, left // 60)))
    ui.out()
    ui.note("网段封禁会影响该网段内与你无关的地址。若确认是共享出口"
            "（运营商 / 校园 / 机房），请撤回：")
    ui.hint("vigil threat netblock clear <网段>　或　vigil threat netblock clear all")
    return 0


def cmd_posture(args) -> int:
    """Show or release the attack-driven heightened defence.

    Releasing is a supported operation, not a workaround. The posture exists
    to meet an attack and is meant to end -- it already expires by itself --
    and an operator who wants it over *now* should be able to say so with a
    command rather than by deleting a flag file. 人不犯我，我不犯人; heightened
    defence is a response, not a standing state.
    """
    from ..guards import threat as threat_mod

    cfg = load_config(args.config or None)
    flag = threat_mod.POSTURE_FLAG

    if args.clear:
        existed = os.path.exists(str(flag))
        try:
            os.unlink(str(flag))
        except OSError:
            pass
        if existed:
            ui.success("已解除高压防护姿态，封禁阈值恢复为常态")
            ui.note("已封禁的地址不受影响 —— 解防不等于解禁")
        else:
            ui.note("当前本来就不在高压姿态中")
        return 0

    active = False
    left = 0
    try:
        left = int(os.path.getmtime(str(flag)) - time.time())
        active = left > 0
    except OSError:
        active = False

    ui.header("高压防护姿态", "检测到攻击时自动收紧阈值，平静后自动恢复")
    if active:
        ui.kv("状态", "进行中", "yellow")
        ui.kv("剩余", "%.1f 分钟" % (left / 60.0))
    else:
        ui.kv("状态", "常态")
    ui.kv("触发条件", "%d 秒内累计权重达到 %s（一次诱饵命中记 3，"
                        "分布式爆破记 5，普通封禁记 1）"
          % (cfg.get("threat.posture.window_seconds"),
             cfg.get("threat.posture.trigger_bans")))
    ui.kv("持续时长", "%s 秒" % cfg.get("threat.posture.hold_seconds"))
    ui.kv("收紧系数", cfg.get("threat.posture.factor"))
    ui.kv("开关", "启用" if cfg.get("threat.posture.enabled", True) else "已关闭",
          "" if cfg.get("threat.posture.enabled", True) else "yellow")
    ui.out()
    if active:
        ui.hint("立即解除：vigil threat posture --clear")
    ui.note("解除姿态只恢复阈值，不会解禁任何已封禁地址")
    return 0


def cmd_status(args) -> int:
    cfg = load_config(args.config or None)
    snap = _engine(cfg).status_snapshot(cfg)
    if args.json:
        ui.out(_json.dumps(snap, ensure_ascii=False, indent=2, default=str))
        return 0
    ui.header("风控状态")
    ui.kv("引擎", "已启用" if cfg.get("threat.enabled", True) else "已停用",
          "" if cfg.get("threat.enabled", True) else "yellow")
    ui.kv("白名单条目", snap.get("whitelist_count", 0))
    ui.kv("当前封禁", snap.get("banned_count", 0),
          "yellow" if snap.get("banned_count") else "green")
    ui.kv("累计封禁", snap.get("bans_total", 0))
    ui.kv("监控日志源", snap.get("sources", 0))

    sources = snap.get("source_list") or []
    if sources:
        ui.section("监控的日志")
        for s in sources:
            exists = s.get("exists")
            ui.bullet("%s %s" % ("" if exists else ui.warn("[缺失] "), s.get("path")))
    for n in snap.get("notes") or []:
        ui.warning(n)

    bans = _engine(cfg).list_bans(cfg)
    ui.section("当前封禁列表")
    if not bans:
        ui.note("当前没有被封禁的 IP")
    else:
        rows = []
        for b in bans:
            left = b.get("remaining", 0)
            rows.append([b.get("ip", ""), b.get("geo", ""),
                         ui_human(left), b.get("reason", "")[:40]])
        ui.table(rows, headers=["IP", "归属", "剩余", "原因"])
    return 0


def ui_human(sec) -> str:
    from ..guards.checks.util import human_seconds
    return human_seconds(sec)



def cmd_trace(args) -> int:
    """Everything known about one address or one process.

    The pieces existed across three modules; nothing joined them. An alert
    names an IP or a process and the reader wants to know whether it is
    dangerous -- answering that should be one command, not four and a mental
    join.
    """
    from ..guards import trace as _trace
    target = (args.target or "").strip()
    if not target:
        ui.failure("给出一个 IP 地址或进程号")
        return 1

    if target.isdigit():
        info = _trace.trace_pid(target)
        ui.header("进程溯源", "pid %s" % target)
        ident = info["identity"]
        if not ident.get("comm"):
            ui.failure("没有这个进程（可能已退出）")
            return 1
        for line in info["detail"]:
            ui.bullet(line)
        if info["threads"]:
            ui.kv("线程数", info["threads"])
        if info["tree"]:
            ui.out()
            ui.section("子进程")
            for line in info["tree"]:
                ui.bullet(line)
        else:
            ui.note("没有子进程")
        return 0

    info = _trace.trace_ip(load_config(args.config or None), target)
    ui.header("地址溯源", target)
    for line in info["dossier"]:
        ui.bullet(line)
    if info["history"]:
        ui.kv("历史", info["history"])
    ui.out()
    ui.section("本机与它的连接")
    if info["connections"]:
        for line in info["connections"]:
            ui.bullet(line)
    else:
        ui.note("当前没有活动连接")
    if info["processes"]:
        ui.out()
        ui.section("涉及的本机进程")
        for line in info["processes"]:
            ui.bullet(line)
    return 0

def cmd_list(args) -> int:
    cfg = load_config(args.config or None)
    bans = _engine(cfg).list_bans(cfg)
    if args.json:
        ui.out(_json.dumps(bans, ensure_ascii=False, indent=2))
        return 0
    if not bans:
        ui.note("当前没有被封禁的 IP")
        return 0
    rows = [[b.get("ip", ""), b.get("geo", ""), ui_human(b.get("remaining", 0)),
             b.get("reason", "")[:50]] for b in bans]
    ui.table(rows, headers=["IP", "归属", "剩余时间", "原因"])
    return 0


def cmd_ban(args) -> int:
    cfg = load_config(args.config or None)
    engine = _engine(cfg)
    seconds = args.seconds or 0
    ok, detail = engine.manual_ban(cfg, args.ip, seconds,
                                   args.reason or "管理员手动封禁")
    if ok:
        ui.success("已封禁 %s%s" % (args.ip, ("（%s）" % detail) if detail else ""))
        return 0
    ui.failure("封禁失败: %s" % detail)
    if "白名单" in str(detail):
        ui.hint("该地址在白名单中。如确需封禁，先用 "
                "`vigil threat whitelist remove %s`" % args.ip)
    return 1


def cmd_unban(args) -> int:
    cfg = load_config(args.config or None)
    ok, detail = _engine(cfg).unban(cfg, args.ip)
    (ui.success if ok else ui.failure)(
        "已解禁 %s" % args.ip if ok else "解禁失败: %s" % detail)
    return 0 if ok else 1


def cmd_whitelist(args) -> int:
    cfg = load_config(args.config or None)
    engine = _engine(cfg)
    action = args.action or "list"

    if action == "list":
        wl = cfg.get("threat.whitelist", []) or []
        if args.json:
            ui.out(_json.dumps(wl, ensure_ascii=False, indent=2))
            return 0
        ui.section("风控白名单（列表内的地址永不被封禁）")
        for entry in wl:
            ui.bullet(entry)
        if not wl:
            ui.warning("白名单为空 —— 有把自己锁在外面的风险")
        ui.out()
        ui.note("注意：白名单只影响风控，不影响防火墙本身的规则。")
        return 0

    if action in ("add", "remove", "rm"):
        if not args.value:
            raise VigilError("缺少 IP 或网段",
                             hint="例如 vigil threat whitelist add 203.0.113.7")
        value = args.value.strip()
        if not engine.is_valid_address(value):
            raise VigilError("不是合法的 IP 或网段: %s" % value)
        cur = list(cfg.get("threat.whitelist", []) or [])
        if action == "add":
            if value in cur:
                ui.note("已在白名单中")
                return 0
            cur.append(value)
            cfg.set("threat.whitelist", sorted(set(cur)))
            cfg.save()
            ui.success("已把 %s 加入白名单" % value)
            if cfg.get("threat.auto_sync_fail2ban", False):
                _sync_fail2ban(cfg)
            return 0
        if value not in cur:
            ui.note("不在白名单中")
            return 0
        cur.remove(value)
        cfg.set("threat.whitelist", cur)
        cfg.save()
        ui.success("已把 %s 移出白名单" % value)
        return 0

    raise VigilError("未知操作: %s" % action)


def _sync_fail2ban(cfg) -> None:
    """Optionally mirror the whitelist into fail2ban's ignoreip.

    Off by default: rewriting another tool's configuration behind its back
    is how you get two divergent lists and a support nightmare. When on, we
    read-modify-write only the ignoreip line.
    """
    from ..core import shell
    jail = "/etc/fail2ban/jail.local"
    import os
    if not os.path.exists(jail) or not shell.have("fail2ban-client"):
        return
    try:
        text = Path(jail).read_text(encoding="utf-8")
    except OSError:
        return
    import re
    wl = " ".join(cfg.get("threat.whitelist", []) or [])
    new = re.sub(r"(?m)^ignoreip\s*=.*$", "ignoreip = %s" % wl, text)
    if new == text:
        return
    try:
        open(jail, "w", encoding="utf-8").write(new)
    except OSError:
        return
    shell.run(["fail2ban-client", "reload"], timeout=30)
    ui.note("已同步白名单到 fail2ban，并重新加载")


def cmd_test(args) -> int:
    """Feed synthetic attacks through the detectors without enforcing.

    self_test() prints its own detailed transcript (including the exact
    verdict per detector) and returns a failure count, so we surface that
    count rather than trying to re-render the transcript here.
    """
    cfg = load_config(args.config or None)
    ui.header("风控自检", "使用内置样例日志验证检测规则，不会真的封禁任何地址")
    rc = _engine(cfg).self_test(cfg)
    ui.out()
    if rc:
        ui.failure("自检发现 %d 个用例未按预期触发" % rc)
        return 1
    ui.success("全部用例按预期触发")
    return 0


def register(sub) -> None:
    p = sub.add_parser("threat", help="实时风控：查看封禁、手动封禁/解禁、白名单",
                       description="实时识别 SSH 爆破、漏洞扫描、请求洪泛等攻击行为"
                                   "并自动封禁来源 IP。")
    ps = p.add_subparsers(dest="threat_action", metavar="<操作>")

    sp = ps.add_parser("status", help="风控状态与封禁列表")
    sp.set_defaults(func=cmd_status)

    sp = ps.add_parser(
        "netblock", help="查看或撤回「网段升级封禁」",
        description="同一网段内出现多个独立来源协同攻击时，本程序会自动"
                    "把封禁从单个地址升级到 /24。这会波及该网段内与你无关的"
                    "地址，所以这里可以查看并随时撤回。")
    sp.add_argument("action", nargs="?", default="list",
                    choices=("list", "clear"))
    sp.add_argument("net", nargs="?", default="",
                    help="要撤回的网段；clear all 表示全部")
    sp.add_argument("--clear", action="store_true",
                    help="等同于 clear（兼容写法）")
    sp.set_defaults(func=cmd_netblock)

    sp = ps.add_parser(
        "posture", help="查看或解除「高压防护姿态」",
        description="攻击信号达到阈值时，本程序会自动收紧封禁阈值；平静一段时间后"
                    "自动恢复。这里可以查看当前状态，也可以立即解除——解除只恢复"
                    "阈值，不会解禁任何已封禁的地址。")
    sp.add_argument("--clear", action="store_true", help="立即解除，阈值恢复常态")
    sp.set_defaults(func=cmd_posture)

    sp = ps.add_parser("trace", help="溯源：一个 IP 或一个进程的完整画像",
                       description="把地址画像（地理位置、网段、网络性质、"
                                   "滥用举报联系人、历史）与进程画像（可执行文件、"
                                   "SHA256、父进程链、所属服务、连接）汇总到一条命令。")
    sp.add_argument("target", help="IP 地址或进程号")
    sp.set_defaults(func=cmd_trace)

    sp = ps.add_parser("list", help="列出当前封禁的 IP")
    sp.set_defaults(func=cmd_list)

    sp = ps.add_parser("ban", help="手动封禁一个 IP")
    sp.add_argument("ip")
    sp.add_argument("seconds", nargs="?", type=int, default=0,
                    help="封禁秒数（默认按违规阶梯自动计算）")
    sp.add_argument("--reason", default="", help="封禁原因")
    sp.set_defaults(func=cmd_ban)

    sp = ps.add_parser("unban", help="解禁一个 IP")
    sp.add_argument("ip")
    sp.set_defaults(func=cmd_unban)

    sp = ps.add_parser("whitelist", help="查看/修改风控白名单")
    sp.add_argument("action", nargs="?", default="list",
                    choices=("list", "add", "remove", "rm"))
    sp.add_argument("value", nargs="?", default="", help="IP 或网段")
    sp.set_defaults(func=cmd_whitelist)

    sp = ps.add_parser("test", help="用样例日志验证检测规则")
    sp.set_defaults(func=cmd_test)
