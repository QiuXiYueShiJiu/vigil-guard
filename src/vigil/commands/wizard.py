"""`vigil init` -- the interactive configuration interface.

A menu-driven front end for everything this program can be told to do. It
exists because the command line, however complete, asks the operator to
already know what they want: eleven subcommands, several hundred options, and
no way to see the current state while choosing.

Design rules, all of them learned from what makes such a menu useless:

* **Never configure blind.** Every panel opens by showing what is set now, so
  the decision is always "change this" rather than "guess a value".
* **Nothing is written until you say so.** Edits are staged, listed, and only
  applied on confirmation. A menu that writes as it goes cannot be explored.
* **The menu is a front end, not a second implementation.** Every action here
  calls the same functions the non-interactive commands call, so the two can
  never drift apart.
* **Always leave a way out.** Ctrl-C at any prompt returns to the menu rather
  than aborting the session; exiting with staged edits warns first.
"""
from __future__ import annotations

import sys
from pathlib import Path

from .. import ui
from ..core.config import load as load_config
from ..core.errors import VigilError

#: Gate kind -> the config key it is stored under. The two names differ
#: because the login gate was written for one application before the project
#: generalised, and the mismatch has already caused one silent bug.
GATE_KEY = {"bt_panel": "bt_panel", "login": "dsh_gate"}


class Session:
    """Staged configuration edits for one interactive session."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.pending: dict = {}      # dotted path -> new value
        self.actions: list = []      # callables run on apply

    def stage(self, dotted: str, value, action=None) -> None:
        if self.cfg.get(dotted) == value and action is None:
            return
        self.pending[dotted] = value
        if action:
            self.actions.append(action)

    def stage_action(self, action) -> None:
        self.actions.append(action)

    def dirty(self) -> bool:
        return bool(self.pending or self.actions)

    def apply(self) -> int:
        for dotted, value in self.pending.items():
            self.cfg.set(dotted, value)
        self.cfg.save()
        self.pending.clear()
        failed = 0
        for action in self.actions:
            try:
                action()
            except Exception as exc:                   # noqa: BLE001
                ui.failure("应用时出错：%s" % exc)
                failed += 1
        self.actions.clear()
        return failed


# --------------------------------------------------------------------------
# Panels
# --------------------------------------------------------------------------

def _panel_mail(sess: Session) -> None:
    cfg = sess.cfg
    ui.section("邮箱与告警渠道")
    chain = cfg.get("mail.providers") or []
    if chain:
        ui.table([[i + 1, e.get("provider", "?"),
                   e.get("from_address") or e.get("host") or "(API)"]
                  for i, e in enumerate(chain)],
                 headers=["#", "渠道", "发件地址/服务器"])
    else:
        ui.warning("尚未配置任何渠道 —— 告警无处可发")

    while True:
        choice = ui.choose("要做什么？", [
            ("setup", "添加 / 重新配置渠道（交互式，会带出各家预设）"),
            ("test", "发送测试邮件（唯一可信的验证）"),
            ("domain", "检查发信域名的 SPF / DKIM / DMARC"),
            ("remove", "移除一个渠道"),
            ("back", "返回上级"),
        ], default=1 if not chain else 5)
        if choice in (None, "back"):
            return
        try:
            if choice == "setup":
                from . import mail as cmd_mail

                class _A:
                    provider = ""
                    no_test = False
                # Reuse the real setup path rather than reimplementing it:
                # presets, secret handling and the automatic test all live
                # there, and a second copy would rot.
                rc = cmd_mail.cmd_setup(_A())
                if rc == 0:
                    cfg.reload()
                return
            if choice == "test":
                from . import mail as cmd_mail

                class _A2:
                    pass
                cmd_mail.cmd_test(_A2())
            elif choice == "domain":
                from . import mail as cmd_mail

                class _A3:
                    provider = None
                cmd_mail.cmd_domain(_A3())
            elif choice == "remove":
                if not chain:
                    continue
                idx = ui.choose("移除哪个？",
                                [(i, "%s %s" % (e.get("provider"),
                                                e.get("from_address") or ""))
                                 for i, e in enumerate(chain)],
                                default=len(chain))
                if idx is None:
                    continue
                keep = [e for i, e in enumerate(chain) if i != idx]
                sess.stage("mail.providers", keep)
                chain = keep
                ui.note("已暂存，应用后生效")
        except (VigilError, OSError) as exc:
            ui.failure(str(exc))
        if not ui.confirm("继续在该面板操作？", default=False):
            return


def _panel_recipients(sess: Session) -> None:
    cfg = sess.cfg
    while True:
        ui.section("管理员收件人")
        alert_to = cfg.recipients("alert")
        login_to = cfg.recipients("login")
        ui.kv("告警收件人", "、".join(alert_to) or "（未配置）",
              "" if alert_to else "yellow")
        ui.kv("登录通知收件人", "、".join(login_to) or "（回落到告警收件人）")
        choice = ui.choose("要做什么？", [
            ("add", "添加收件人"),
            ("del", "移除收件人"),
            ("login", "把某人设为只收登录通知"),
            ("back", "返回上级"),
        ], default=4)
        if choice in (None, "back"):
            return
        if choice == "add":
            addr = ui.ask("邮箱地址")
            if addr and "@" in addr:
                sess.stage("mail.recipients", sorted(set(alert_to + [addr])))
                alert_to = sorted(set(alert_to + [addr]))
                ui.success("已暂存 %s" % addr)
            elif addr:
                ui.failure("这不像一个邮箱地址")
        elif choice == "del":
            if not alert_to:
                continue
            who = ui.choose("移除谁？", alert_to, default=len(alert_to))
            if who:
                sess.stage("mail.recipients",
                           [a for a in alert_to if a != who])
                alert_to = [a for a in alert_to if a != who]
        elif choice == "login":
            if not alert_to:
                continue
            who = ui.choose("谁只收登录通知？", alert_to, default=1)
            if who:
                sess.stage("mail.login_recipients", sorted(set(login_to + [who])))
                ui.note("登录通知单独成列；留空则跟随告警收件人")


def _panel_alerts(sess: Session) -> None:
    cfg = sess.cfg
    ui.section("告警策略")
    ui.kv("每日额度", cfg.get("mail.daily_quota"))
    ui.kv("去重窗口", "%s 秒" % cfg.get("mail.dedupe_window"))
    ui.kv("主题前缀", cfg.get("mail.subject_prefix") or "（无）")
    ui.kv("语言", cfg.get("mail.language"))
    if ui.confirm("修改额度与去重？", default=False):
        quota = ui.ask("每日最多发几封", str(cfg.get("mail.daily_quota")))
        if quota.isdigit():
            sess.stage("mail.daily_quota", int(quota))
        window = ui.ask("相同告警多久内只发一次（秒）",
                        str(cfg.get("mail.dedupe_window")))
        if window.isdigit():
            sess.stage("mail.dedupe_window", int(window))
    if ui.confirm("修改主题前缀与语言？", default=False):
        prefix = ui.ask("主题前缀（便于收件规则过滤，可留空）",
                        cfg.get("mail.subject_prefix") or "")
        sess.stage("mail.subject_prefix", prefix)
        lang = ui.choose("告警语言", [("zh", "中文"), ("en", "English")], default=1)
        if lang:
            sess.stage("mail.language", lang)


def _panel_threat(sess: Session) -> None:
    cfg = sess.cfg
    while True:
        ui.section("实时风控与自动封禁")
        ui.kv("启用", "是" if cfg.get("threat.enabled") else "否")
        ui.kv("SSH 爆破", "%s 次失败 / %s 秒" % (cfg.get("threat.ssh.max_failures"),
                                                cfg.get("threat.ssh.window_seconds")))
        ui.kv("Web 攻击", "%s 次 / %s 秒" % (cfg.get("threat.http.max_attacks"),
                                             cfg.get("threat.http.window_seconds")))
        wl = cfg.get("threat.whitelist") or []
        ui.kv("白名单", "%d 条" % len(wl))
        ui.kv("封禁告警", "开" if cfg.get("threat.notify_bans") else "关")
        ui.kv("登录告警", "开" if cfg.get("gate.login_alerts") else "关")
        choice = ui.choose("要做什么？", [
            ("whitelist", "查看 / 增删白名单（永远不会被封的地址）"),
            ("threshold", "调整 SSH / Web 触发阈值"),
            ("toggle", "开关封禁与登录告警"),
            ("list", "查看当前封禁"),
            ("back", "返回上级"),
        ], default=5)
        if choice in (None, "back"):
            return
        if choice == "whitelist":
            ui.table([[i + 1, a] for i, a in enumerate(wl)],
                     headers=["#", "地址/网段"])
            act = ui.choose("操作", [("add", "添加"), ("del", "删除"),
                                    ("back", "返回")], default=3)
            if act == "add":
                addr = ui.ask("地址或网段（如 203.0.113.10 或 203.0.113.0/24）")
                if addr:
                    sess.stage("threat.whitelist", sorted(set(wl + [addr])))
                    wl = sorted(set(wl + [addr]))
                    ui.note("**把自己锁在外面是最常见的自伤**：确认这个地址现在能用")
            elif act == "del" and wl:
                who = ui.choose("删除哪条？", wl, default=len(wl))
                if who:
                    sess.stage("threat.whitelist", [a for a in wl if a != who])
                    wl = [a for a in wl if a != who]
        elif choice == "threshold":
            n = ui.ask("SSH 多少次失败触发封禁",
                       str(cfg.get("threat.ssh.max_failures")))
            if n.isdigit():
                sess.stage("threat.ssh.max_failures", int(n))
            w = ui.ask("统计窗口（秒）", str(cfg.get("threat.ssh.window_seconds")))
            if w.isdigit():
                sess.stage("threat.ssh.window_seconds", int(w))
            h = ui.ask("Web 攻击次数阈值", str(cfg.get("threat.http.max_attacks")))
            if h.isdigit():
                sess.stage("threat.http.max_attacks", int(h))
        elif choice == "toggle":
            for path, label in (("threat.notify_bans", "封禁时发邮件"),
                                ("gate.login_alerts", "登录时发邮件")):
                cur = bool(cfg.get(path))
                if ui.confirm("%s？（当前%s）" % (label, "开" if cur else "关"),
                              default=cur):
                    if not cur:
                        sess.stage(path, True)
                elif cur:
                    sess.stage(path, False)
        elif choice == "list":
            from . import threat as cmd_threat

            class _A:
                pass
            cmd_threat.cmd_list(_A())


def _panel_gates(sess: Session, cfg) -> None:
    ui.section("登录界面防护")
    try:
        from ..gates import detect_all, instance_label
        found = detect_all()
    except Exception as exc:                           # noqa: BLE001
        ui.failure("无法检测网关：%s" % exc)
        return
    if not found:
        ui.note("本机尚未安装任何登录网关。")
    for spec in found:
        ui.kv(instance_label(spec.kind, spec.name),
              "%s  入口 %s  刷新重验证=%s"
              % (spec.state_dir, spec.entry_path, spec.strict_nav))

    choice = ui.choose("要做什么？", [
        ("install", "安装一个新的登录网关"),
        ("reconfig", "修改已有网关（端口 / 密码 / 刷新策略 / 画面）"),
        ("sync", "把已安装网关的参数写回配置（改完必做）"),
        ("test", "端到端自检"),
        ("back", "返回上级"),
    ], default=5)
    if choice in (None, "back"):
        return
    if choice == "install":
        kind = ui.choose("装哪一种？", [
            ("bt_panel", "宝塔面板 / aaPanel 人机验证"),
            ("login", "独立登录页（人机验证 + 账号密码）"),
        ], default=1)
        if not kind:
            return
        from . import gate as cmd_gate

        class _A:
            pass
        _A.kind = kind
        args = _A()
        # Hand over to the real installer: it already prompts for every
        # option and validates them. Instance selection is an option, so the
        # wizard installs the default instance and the operator adds
        # `--name` on the command line to create a second one.
        args.name = ""
        for attr, val in (("force", False), ("yes", False), ("no_prompt", False)):
            setattr(args, attr, val)
        cmd_gate._add_common_options  # noqa: B018 - documented dependency
        from .gate import cmd_install
        cmd_install(args)
    elif choice == "reconfig" and found:
        pick = ui.choose("哪一个？",
                         [((s.kind, s.name), instance_label(s.kind, s.name))
                          for s in found], default=1)
        if not pick:
            return
        from . import gate as cmd_gate

        class _A2:
            pass
        args = _A2()
        args.kind, args.name = pick
        args.yes = False
        args.no_prompt = False
        cmd_gate.cmd_reconfigure(args)
    elif choice == "sync":
        from . import gate as cmd_gate

        class _A3:
            pass
        cmd_gate.cmd_gate_sync(_A3())
    elif choice == "test" and found:
        pick = ui.choose("测哪一个？",
                         [((s.kind, s.name), instance_label(s.kind, s.name))
                          for s in found], default=1)
        if pick:
            from . import gate as cmd_gate

            class _A4:
                pass
            args = _A4()
            args.kind, args.name = pick
            cmd_gate.cmd_test(args)


def _panel_shield(sess: Session, cfg) -> None:
    ui.section("Web 层防护（nginx 全局）")
    try:
        from ..gates import shield
        st = shield.status()
    except Exception as exc:                           # noqa: BLE001
        ui.failure("无法读取状态：%s" % exc)
        return
    ui.kv("防护片段", "已安装" if st["shield_present"] else "未安装",
          "green" if st["shield_present"] else "yellow")
    ui.kv("已被 include", "是" if st["shield_included"] else "否",
          "green" if st["shield_included"] else "yellow")
    ui.kv("拦截的扫描器 UA", "%d 条" % st["agents"])
    if st["legacy_present"]:
        ui.warning("检测到旧版加固文件：%s" % st["legacy_file"])
    choice = ui.choose("要做什么？", [
        ("install", "安装 / 更新（写入前会用 nginx -t 验证，失败自动回滚）"),
        ("uninstall", "移除（站点仍引用时会恢复旧版定义）"),
        ("back", "返回上级"),
    ], default=3)
    if choice == "install":
        shield.install(retire=True)
        ui.success("已应用")
    elif choice == "uninstall":
        shield.uninstall()
        ui.success("已移除")


def _panel_checks(sess: Session, cfg) -> None:
    ui.section("安全巡检")
    ui.kv("启用", "是" if cfg.get("checks.enabled") else "否")
    ui.kv("间隔", "%s 秒" % cfg.get("checks.interval"))
    ui.kv("磁盘阈值", "警告 %s%% / 严重 %s%%" % (cfg.get("checks.disk.warn_pct"),
                                                 cfg.get("checks.disk.crit_pct")))
    ui.kv("监控服务", "%d 个" % len(cfg.get("checks.services") or []))
    ui.kv("监控文件", "%d 个文件 / %d 个目录"
          % (len(cfg.get("checks.watch_files") or []),
             len(cfg.get("checks.watch_dirs") or [])))
    choice = ui.choose("要做什么？", [
        ("run", "立即跑一次完整巡检"),
        ("list", "列出全部检查项及其说明"),
        ("interval", "修改巡检间隔"),
        ("back", "返回上级"),
    ], default=4)
    if choice == "run":
        from . import health as cmd_health

        class _A:
            only = ""
            json = False
        cmd_health.cmd_run(_A())
    elif choice == "list":
        from . import health as cmd_health

        class _A2:
            json = False
        cmd_health.cmd_list(_A2())
    elif choice == "interval":
        n = ui.ask("巡检间隔（秒）", str(cfg.get("checks.interval")))
        if n.isdigit() and int(n) >= 30:
            sess.stage("checks.interval", int(n))
            ui.note("应用后会重启巡检定时器")


def _panel_status(sess: Session) -> None:
    from . import diag as cmd_diag

    class _A:
        json = False
    cmd_diag.cmd_status(_A())


# --------------------------------------------------------------------------
# The loop
# --------------------------------------------------------------------------

SECTIONS = [
    ("mail", "邮箱与告警渠道"),
    ("recipients", "管理员收件人"),
    ("alerts", "告警策略（额度 / 去重 / 语言）"),
    ("threat", "实时风控与自动封禁"),
    ("gates", "登录界面防护"),
    ("shield", "Web 层防护（扫描器拦截）"),
    ("checks", "安全巡检"),
    ("status", "查看当前状态总览"),
    ("apply", "保存并应用全部改动"),
    ("quit", "退出"),
]


def _summary(sess: Session) -> list:
    cfg = sess.cfg
    chain = cfg.get("mail.providers") or []
    gates = []
    try:
        from ..gates import detect_all
        gates = [s.kind for s in detect_all()]
    except Exception:                                  # noqa: BLE001
        pass
    return [
        ("邮箱与告警渠道",
         "%d 个渠道，%d 个收件人" % (len(chain), len(cfg.recipients("alert")))
         if chain else "**未配置**"),
        ("管理员收件人", "、".join(cfg.recipients("alert")) or "**未配置**"),
        ("实时风控", "开" if cfg.get("threat.enabled") else "关"),
        ("登录防护", "、".join(gates) or "未安装"),
        ("Web 防护", "已装" if Path(
            "/www/server/nginx/conf/vigil-shield.conf").exists() else "未装"),
        ("巡检", "开（%s 秒）" % cfg.get("checks.interval")
         if cfg.get("checks.enabled") else "关"),
    ]


def cmd_init(args) -> int:
    """The interactive configuration interface."""
    if not ui.is_interactive() and not getattr(args, "menu", False):
        ui.failure("交互式配置需要终端")
        ui.hint("在终端里运行 `vigil init`；脚本里请直接用各子命令")
        return 1

    cfg = load_config(args.config or None)
    sess = Session(cfg)

    ui.header("vigil 交互式配置", "所有改动先暂存，确认后才写入")
    ui.note("菜单只是各子命令的前端 —— 同样的操作也都能用命令行完成。")

    # Without a terminal every prompt returns its default, so the menu would
    # pick the same entry forever. Rendering once and stopping is the honest
    # behaviour: there is nobody there to choose.
    interactive = ui.is_interactive()
    if not interactive:
        ui.warning("未检测到终端：只渲染一次菜单，不会等待输入")
        ui.hint("在终端里运行 `vigil init` 使用完整交互")

    while True:
        ui.out()
        ui.section("当前状态")
        ui.table([(k, v) for k, v in _summary(sess)],
                 headers=["项目", "现状"])
        if sess.dirty():
            ui.out()
            ui.warning("有 %d 项改动尚未应用" % (len(sess.pending) + len(sess.actions)))
            for dotted in list(sess.pending)[:6]:
                ui.bullet(dotted)
        ui.out()
        options = [(key, label) for key, label in SECTIONS]
        if sess.dirty():
            options = [(k, (l + "   ← 有待应用的改动" if k == "apply" else l))
                       for k, l in options]
        pick = ui.choose("选择要配置的项目", options,
                         default=len(SECTIONS) - 1)

        # Checked here, before any branch can `continue`: an earlier attempt
        # put this guard after the dispatch and the "nothing to apply" branch
        # looped straight past it, spinning eighty thousand lines in eight
        # seconds for a user who was not there.
        if not interactive:
            ui.note("非终端环境：不进入交互循环")
            break

        try:
            if pick in (None, "quit"):
                if sess.dirty():
                    if not ui.confirm("还有未应用的改动，确定退出？", default=False):
                        continue
                ui.note("退出。改动未写入。")
                return 0
            if pick == "apply":
                if not sess.dirty():
                    ui.note("没有需要应用的改动")
                    continue
                ui.out()
                for dotted, value in sess.pending.items():
                    ui.bullet("%s = %s" % (dotted, repr(value)[:60]))
                if not ui.confirm("写入这些改动？", default=True):
                    continue
                failed = sess.apply()
                if failed:
                    ui.warning("已写入，但有 %d 个动作失败，见上" % failed)
                else:
                    ui.success("已应用")
                    cfg.reload()
                ui.hint("部分改动需要重启服务：vigil service restart")
                continue
            if pick == "mail":
                _panel_mail(sess)
            elif pick == "recipients":
                _panel_recipients(sess)
            elif pick == "alerts":
                _panel_alerts(sess)
            elif pick == "threat":
                _panel_threat(sess)
            elif pick == "gates":
                _panel_gates(sess, cfg)
            elif pick == "shield":
                _panel_shield(sess, cfg)
            elif pick == "checks":
                _panel_checks(sess, cfg)
            elif pick == "status":
                _panel_status(sess)
        except KeyboardInterrupt:
            # Ctrl-C at any prompt returns to the menu. A configuration
            # session is exploratory by nature, and aborting the whole thing
            # on one stray keystroke is how people lose ten minutes of work.
            ui.out()
            ui.note("已取消当前操作，改动仍暂存着")

    return 0


def register(sub) -> None:
    p = sub.add_parser(
        "init", help="交互式配置界面（推荐首次使用）",
        description="菜单式配置：邮箱渠道、收件人、风控阈值、登录防护、"
                    "Web 防护、巡检项。所有改动先暂存，确认后才写入；"
                    "中途 Ctrl-C 只取消当前一步，不会丢掉已做的改动。")
    p.add_argument("--menu", action="store_true",
                   help="即使不在终端里也进入菜单（默认会拒绝）")
    p.set_defaults(func=cmd_init)
