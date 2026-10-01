"""`vigil install` / `uninstall` -- put the system on this host, or take it off."""
from __future__ import annotations

import os
from pathlib import Path

from .. import ui
from ..core import detect, units
from ..core.config import load as load_config
from ..core.errors import VigilError
from ..core.installer import BACKUP_DIR, Installer
from ..version import __version__


def _log():
    from ..core import logging as vlog
    return vlog.get("main")


def _print_env(env) -> None:
    s = env["system"]
    rows = [
        ("主机名", s["hostname"]),
        ("系统", s["distro"]),
        ("内核 / 架构", "%s / %s" % (s["kernel"], s["arch"])),
        ("Python", s["python"]),
        ("CPU / 内存", "%d 核 / %d MB" % (s["cpu_count"], env["memory_mb"])),
    ]
    ng = env.get("nginx", {})
    rows.append(("Web 服务器", ("nginx %s%s" % (
        ng.get("version", "?"),
        "（支持 Lua，可安装登录网关）" if ng.get("lua") else "（无 Lua 模块）"))
        if ng.get("present") else "未检测到 nginx"))
    panel = env.get("bt_panel", {})
    rows.append(("控制面板", ("宝塔面板 %s（端口 %s）" % (
        panel.get("version") or "?", panel.get("port")))
        if panel.get("present") else "未检测到"))
    fw = env.get("firewall", {})
    rows.append(("防火墙", "%s（%s）" % (fw.get("kind", "none"),
                                        "已启用" if fw.get("active") else "未启用")))
    ad = env.get("auditd", {})
    rows.append(("内核审计", "已安装（支持文件改动归因）" if ad.get("present")
                 else "未安装（无法追溯是谁改的文件）"))
    mal = env.get("malware", {})
    rows.append(("恶意软件引擎", mal.get("engine", "none")
                 if mal.get("engine") != "none" else "未检测到"))
    rows.append(("本地发信能力", "可用" if env.get("local_mta", {}).get("present")
                 else "无本地 MTA"))
    rows.append(("出口 25 端口", "可用" if env.get("port25_open")
                 else "被机房封禁（需用 API 或 587/465 提交端口）"))
    ui.panel("环境检测结果", rows)


def _features_menu(env):
    """Return (default_features, opt_in_features) for this host."""
    opts = [
        ("threat", "实时风控与自动封禁 —— 识别 SSH 爆破、漏洞扫描、请求洪泛并自动拦截"),
        ("loadshed", "负载保护 —— 被攻击导致负载过高时自动限流自保"),
        ("health", "安全巡检 —— 文件完整性、可疑进程、WebShell 内容、权限、服务等数十项"),
        ("login", "登录通知 —— 面板/网关登录成功时告知来源 IP 与归属地"),
        ("av", "恶意软件扫描 —— 使用本机已安装的杀毒引擎（未安装则自动跳过）"),
    ]
    # The gate touches the web server configuration, so it is never part
    # of the default set: installing it is a deliberate follow-up step
    # with its own command (`vigil gate install`).
    opt_in = [
        ("gate", "登录界面防护 —— 为宝塔面板/管理页面加人机验证"
                 "（建议安装后用 `vigil gate install` 单独进行）"),
    ]
    avail = []
    for key, label in opts:
        if key == "login" and not env.get("log_sources", {}).get("auth"):
            ui.note("跳过「登录通知」：本机未找到认证日志")
            continue
        if key == "av" and not env.get("malware", {}).get("present"):
            ui.note("跳过「恶意软件扫描」：本机未安装 maldet/clamav")
            continue
        avail.append((key, label))
    return avail, opt_in


def cmd_install(args) -> int:
    inst = Installer(log=_log(), dry_run=args.dry_run)
    log = _log()

    ui.header("Vigil 安装向导", "版本 %s" % __version__)

    problems = inst.preflight()
    if problems:
        ui.problems_block(problems)
        return 1

    ui.out()
    ui.note("正在检测本机环境…")
    env = inst.discover()
    _print_env(env)

    # Snapshot the units we promise never to touch, so we can prove at the
    # end that the operator's own application is still up.
    protected_before = inst.protected_state()

    # -- existing installation -------------------------------------------
    legacy = inst.legacy_present()
    if legacy["files"] or legacy["units"]:
        ui.section("检测到旧版本（DSH 系列组件）")
        ui.kv("旧的配置文件", "/etc/dsh-security.conf"
              if legacy["config"] else "无")
        ui.kv("旧组件脚本", "%d 个" % len(legacy["files"]))
        ui.kv("旧 systemd 单元", "%d 个" % len(legacy["units"]))
        ui.out()
        ui.note("安装时会：读取旧配置里的邮箱/白名单等设置 → 停止并停用旧服务"
                " → 把旧脚本移到备份目录（不删除） → 安装新版本。")

    already = Path("/usr/local/lib/vigil/vigil").is_dir()
    if already and not args.force:
        ui.out()
        ui.warning("检测到本程序已安装")
        ui.hint("使用 `vigil install --force` 重装，或 `vigil update` 更新代码")
        if not ui.confirm("继续重装？", default=False):
            return 0

    # -- features ---------------------------------------------------------
    avail, opt_in = _features_menu(env)
    if args.features:
        chosen = [f.strip() for f in args.features.split(",") if f.strip()]
    elif args.no_prompt or not ui.is_interactive():
        # Non-interactive: take everything safe-to-enable by default. The
        # gate is excluded on purpose -- it rewrites web server config and
        # deserves a deliberate decision.
        #
        # `not ui.is_interactive()` belongs in this branch, and leaving it out
        # was a genuinely dangerous default: with no terminal `ui.choose`
        # returns only its first option, so `sh install.sh` silently enabled
        # one feature out of five and reported success. Health checks, login
        # alerts, backlog replay and malware scanning were all left off, and
        # nothing in the output said so.
        if not args.no_prompt and not args.features:
            ui.warning("未检测到终端：按非交互模式安装，启用全部默认防护")
            ui.hint("想挑选功能：在终端里运行，或用 "
                    "--features %s" % ",".join(k for k, _ in avail))
        chosen = [k for k, _ in avail]
    else:
        ui.out()
        chosen = ui.choose("请选择要启用的防护功能（可多选）",
                           avail + opt_in, allow_multiple=True, default=1)
        if not chosen:
            ui.warning("一个功能都没选 —— 本程序将只安装代码，不做任何防护")
            if not ui.confirm("确定继续？", default=False):
                return 0

    # -- identity -----------------------------------------------------------
    # Asked before the summary so the operator sees it in the plan. Both
    # names are cosmetic but matter a lot in practice: a cloud hostname is
    # usually an unrecognisable string, and "Server Monitor" tells you
    # nothing when you are scanning an inbox at 3am.
    sys_host = env["system"]["hostname"]
    if args.no_prompt:
        host_label = args.hostname or sys_host
        sender_name = args.sender_name or "Server Monitor"
    else:
        ui.out()
        ui.section("告警中的身份")
        ui.note("这两项只影响邮件外观，便于你在收件箱里一眼认出是哪台机器。")
        host_label = args.hostname or ui.ask(
            "主机显示名", default=sys_host,
            hint_text="出现在告警正文的「主机:」一栏，多台服务器时尤其有用")
        sender_name = args.sender_name or ui.ask(
            "发件人显示名", default="Server Monitor",
            hint_text="出现在收件箱的「发件人」一栏")

    ui.out()
    ui.section("即将执行")
    ui.bullet("部署程序到 /usr/local/lib/vigil，创建命令 /usr/local/bin/vigil")
    ui.bullet("写入配置 /etc/vigil/config.json（凭据单独存放，权限 600）")
    ui.bullet("安装并启用 systemd 服务：%s" % ", ".join(
        sorted(k for k in chosen)) or "无")
    ui.bullet("建立审计规则（让文件改动可以被追溯到具体进程）")
    if legacy["files"]:
        ui.bullet("停止旧服务并把旧脚本移入 %s" % BACKUP_DIR)
    if args.dry_run:
        ui.out()
        ui.warning("这是预演模式（--dry-run），不会真正修改系统")

    if not args.yes and not args.no_prompt and not args.dry_run:
        ui.out()
        if not ui.confirm("确认开始安装？", default=True):
            ui.note("已取消")
            return 0

    # -- run ---------------------------------------------------------------
    ui.header("开始安装")

    # 1. config (before units, so the daemons have something to read)
    cfg = load_config(args.config or None)
    inst.build_config(set(chosen), adopt=True)
    adopted = getattr(inst, "adopted", {})
    if not args.dry_run:
        from ..core import paths
        paths.ensure_dirs()
        cfg.save()
        ui.success("配置已写入 %s" % cfg.path)
        if adopted:
            for k, v in adopted.items():
                ui.note("已从旧版本继承 %s: %s" % (k, v))
    else:
        ui.note("预演：跳过写入配置")

    identity_changed = False
    if host_label:
        cfg.set("hostname", host_label)
        identity_changed = True
    if sender_name:
        cfg.set("mail.from_name", sender_name)
        identity_changed = True
        # A per-channel value would shadow the global one, so keep any
        # already-configured channels consistent with what was just chosen.
        for entry in cfg.providers():
            pid = entry.get("provider", "")
            if not pid:
                continue
            params = cfg.provider_params(pid)
            if params.get("from_name"):
                params["from_name"] = sender_name
                cfg.set_provider_params(pid, params)
                identity_changed = True
    # The identity is chosen after the first save, so persist it now --
    # otherwise the operator's chosen names are silently discarded.
    if identity_changed and not args.dry_run:
        cfg.save()
        ui.success("已保存主机显示名与发件人显示名")

    # 2. code
    ok, detail = inst.deploy_code()
    (ui.success if ok else ui.failure)(detail)
    if not ok and not args.dry_run:
        return 1

    # 3. stop legacy before starting ours
    if legacy["units"] or legacy["files"]:
        stopped = inst.stop_legacy()
        if stopped:
            verb = "将停止" if args.dry_run else "已停止"
            ui.success("%s %d 个旧服务单元" % (verb, len(stopped)))
        moved = inst.quarantine_legacy()
        if moved:
            verb = "将移入" if args.dry_run else "已把"
            ui.success("%s %d 个旧脚本移入备份目录（不删除）" % (verb, len(moved)))
            ui.hint("如需回退：%s" % BACKUP_DIR)

    # 4. audit rules
    if env.get("auditd", {}).get("present") and "health" in chosen:
        good, msg = inst.install_audit_rules(cfg)
        (ui.success if good else ui.warning)(msg)
    elif not env.get("auditd", {}).get("present"):
        ui.warning("未安装 auditd —— 文件改动可以检测到，但无法追溯是谁改的")
        ui.hint("安装后可运行 `vigil audit install` 补上（apt install auditd）")

    # 5. units
    feat_set = set(chosen)
    if "health" in feat_set:
        feat_set.add("mail")            # the backlog replayer is part of mail
    rendered = units.render_all(cfg, feat_set)
    enabled = units.install_units(rendered, start=not args.dry_run, log=log)
    if args.dry_run:
        ui.note("预演：将安装 %d 个 systemd 单元" % len(rendered))
    else:
        ui.success("已安装并启动 %d 个 systemd 单元" % len(enabled))

    # 6. prove we did not break anything we promised not to touch
    regressions = inst.protected_regressions(protected_before)
    if regressions:
        ui.out()
        ui.header("⚠ 检测到不该发生的影响")
        for r in regressions:
            ui.failure(r)
        ui.hint("这些服务不属于本程序，安装过程本不应影响它们。")
        ui.hint("尝试恢复：systemctl start <服务名>")
        ui.hint("请把上面的信息反馈给开发者。")
    elif protected_before:
        ui.success("未影响任何非本程序的服务（已核对 %d 个）"
                   % len(protected_before))

    # 7. summary
    ui.header("安装完成")
    rows = [("程序版本", __version__), ("配置", str(cfg.path)),
            ("主机显示名", cfg.get("hostname", "")),
            ("发件人显示名", cfg.get("mail.from_name", "")),
            ("已启用功能", "、".join(sorted(chosen)) or "无"),
            ("systemd 单元", "%d 个" % len(enabled))]
    rec = cfg.recipients("alert")
    rows.append(("告警收件人", ", ".join(rec) if rec else "尚未配置"))
    provs = cfg.providers()
    rows.append(("告警渠道", ", ".join(p.get("provider", "?") for p in provs)
                 if provs else "尚未配置"))
    ui.panel("安装摘要", rows)

    ui.out()
    if not provs or not rec:
        ui.warning("还没有配置告警通道 —— 服务器发现问题时无法通知你")
        ui.hint("运行 `vigil mail setup` 配置邮箱（配置完会自动发测试邮件）")
    else:
        ui.hint("可运行 `vigil mail test` 再验证一次通道")
    ui.hint("随时可改：vigil mail sender --hostname \"新名字\" --name \"新显示名\"")
    ui.hint("运行 `vigil status` 查看运行状态，`vigil doctor` 复查环境")
    return 0


def cmd_uninstall(args) -> int:
    inst = Installer(log=_log(), dry_run=args.dry_run)
    ui.header("卸载 Vigil")
    if os.geteuid() != 0:
        raise VigilError("需要 root 权限", hint="使用 sudo 运行")

    ui.note("默认行为：停止并删除服务与程序，**保留**配置、状态与日志。")
    if args.purge:
        ui.out()
        ui.warning("你指定了 --purge：配置、状态、日志与备份都将被删除，且不可恢复！")

    if not args.yes:
        if not ui.confirm("确认卸载？", default=False):
            ui.note("已取消")
            return 0
    if args.purge and not args.yes:
        if not ui.confirm("再次确认彻底清除所有数据？", default=False):
            ui.note("已取消")
            return 0

    removed = units.remove_units(log=_log())
    ui.success("已停止并删除 %d 个 systemd 单元" % len(removed))

    from ..core import paths
    if args.purge:
        import shutil
        if not args.dry_run:
            for d in (paths.ETC, paths.VAR, paths.LOG):
                shutil.rmtree(str(d), ignore_errors=True)
        ui.success("已删除配置/状态/日志")
    else:
        ui.note("已保留 %s、%s、%s" % (paths.ETC, paths.VAR, paths.LOG))

    inst.remove_code()
    ui.success("已移除程序文件与命令")

    # Leave the firewall alone: our bans live in an ipset that expires on
    # its own, and touching the firewall on the way out is how you lock
    # yourself out of a machine.
    ui.out()
    ui.note("未改动防火墙规则（封禁条目会按各自超时自动失效）。")
    if not args.purge:
        ui.hint("如需彻底清除：vigil uninstall --purge")
    return 0


def cmd_update(args) -> int:
    inst = Installer(log=_log(), dry_run=args.dry_run)
    ok, detail = inst.deploy_code()
    (ui.success if ok else ui.failure)(detail)
    if not ok:
        return 1
    for unit in ("vigil-threatd.service", "vigil-health.service",
                 "vigil-maild.service", "vigil-logind.service"):
        from ..core import shell
        if shell.out(["systemctl", "is-active", unit]) == "active":
            shell.run(["systemctl", "restart", unit], timeout=60)
            ui.note("已重启 %s" % unit)
    ui.success("更新完成")
    return 0


# --------------------------------------------------------------------------


def register(sub) -> None:
    p = sub.add_parser("install", help="安装、重装本系统",
                       description="检测本机环境，安装程序与服务，"
                                   "并可从旧版本自动继承配置。")
    p.add_argument("--force", action="store_true", help="已安装时强制重装")
    p.add_argument("--dry-run", action="store_true", help="只显示将要执行的操作")
    p.add_argument("--no-prompt", action="store_true",
                   help="非交互：启用全部可用功能并使用默认值")
    p.add_argument("--features", default="",
                   help="指定启用的功能，逗号分隔：threat,health,login,av,gate")
    p.add_argument("--hostname", default="",
                   help="告警正文中显示的主机名（默认使用系统主机名）")
    p.add_argument("--sender-name", dest="sender_name", default="",
                   help="发件人显示名（出现在收件箱）")
    p.add_argument("--recipient", default="",
                   help="直接指定管理员收件邮箱（逗号分隔）")
    p.add_argument("--from", dest="from_address", default="",
                   help="直接指定发件地址")
    p.add_argument("--yes", "-y", action="store_true", help="跳过确认")
    p.set_defaults(func=cmd_install)

    p = sub.add_parser("uninstall", help="卸载本系统")
    p.add_argument("--purge", action="store_true",
                   help="同时删除配置、状态与日志（不可恢复）")
    p.add_argument("--dry-run", action="store_true", help="只显示将要执行的操作")
    p.add_argument("--yes", "-y", action="store_true", help="跳过确认")
    p.set_defaults(func=cmd_uninstall)
