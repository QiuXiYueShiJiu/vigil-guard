"""`vigil selftest` -- is this installation actually doing its job?

`vigil doctor` answers "what can this host do?" and `vigil health run` asks
"has this host been tampered with?". Neither answers the question that cost
this project the most time: **is the thing I installed actually wired up and
running?** Every significant failure in its history was of that kind --

* a channel that silently fell through to the backup provider,
* an inspection whose baseline could never match, so it reported forever,
* a mail listener that read its own output as commands,
* a check that reported 0 bans on a host holding two,
* generated config written to a directory nothing includes.

Each one looked healthy from the outside. So this command is deliberately
blunt: it checks the wiring end to end and exits non-zero if anything is
actually broken, which makes it usable from cron, from CI, or from a shell
after an upgrade.

Exit codes: 0 = fine, 1 = something is broken, 2 = warnings only.
"""
from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

from .. import ui
from ..core import paths, shell
from ..core.config import load as load_config
from ..core.state import read_json

OK, WARN, FAIL = "ok", "warn", "fail"



class Report:
    def __init__(self):
        self.items = []

    def add(self, status, label, detail="", fix=""):
        self.items.append({"status": status, "label": label,
                           "detail": detail, "fix": fix})

    @property
    def failed(self):
        return [i for i in self.items if i["status"] == FAIL]

    @property
    def warned(self):
        return [i for i in self.items if i["status"] == WARN]


def _unit_active(unit: str) -> str:
    return shell.out(["systemctl", "is-active", unit]) or "unknown"


def collect(cfg) -> Report:
    rep = Report()
    root = os.geteuid() == 0

    # -- environment ------------------------------------------------------
    rep.add(OK if root else FAIL, "运行权限",
            "root" if root else "非 root：防火墙、封禁、单元管理都不可用",
            "" if root else "用 root 运行：sudo vigil selftest")
    missing = [c for c in ("systemctl", "ss") if not shutil.which(c)]
    rep.add(OK if not missing else FAIL, "基础命令",
            "systemctl、ss 可用" if not missing else "缺少：%s" % "、".join(missing),
            "" if not missing else "安装 systemd 与 iproute2")

    # -- configuration ----------------------------------------------------
    problems = []
    try:
        problems = cfg.validate()
    except Exception as exc:                            # noqa: BLE001
        problems = ["配置无法校验：%s" % exc]
    rep.add(OK if not problems else FAIL, "配置有效性",
            "配置检查通过" if not problems else "；".join(problems[:4]),
            "" if not problems else "运行 `vigil config show` 逐项核对")

    secrets = Path(paths.SECRETS)
    if secrets.exists():
        mode = secrets.stat().st_mode & 0o077
        rep.add(OK if mode == 0 else FAIL, "凭据文件权限",
                "0600" if mode == 0 else "权限过宽（%o），同机其他用户可以读到"
                % (secrets.stat().st_mode & 0o777),
                "" if mode == 0 else "chmod 600 %s" % secrets)
    else:
        rep.add(WARN, "凭据文件权限", "还没有 %s（尚未配置邮件通道）" % secrets,
                "vigil mail setup")

    # -- our own units ----------------------------------------------------
    dead = [u for u in ("vigil-threatd.service", "vigil-loadshed.service")
            if _unit_active(u) != "active"]
    rep.add(OK if not dead else FAIL, "守护进程",
            "威胁检测与限流都在运行" if not dead else "未运行：%s" % "、".join(dead),
            "" if not dead else "systemctl start %s" % dead[0])
    dead_t = [u for u in ("vigil-health.timer", "vigil-logind.timer",
                          "vigil-maild.timer")
              if _unit_active(u) != "active"]
    rep.add(OK if not dead_t else FAIL, "定时器",
            "巡检、登录通知、邮件通道已排程" if not dead_t
            else "未激活：%s" % "、".join(dead_t),
            "" if not dead_t else "systemctl start %s" % dead_t[0])

    # -- generated configuration -----------------------------------------
    rules = 0
    try:
        rules = len(shell.out(["auditctl", "-l"]).splitlines()) if \
            shutil.which("auditctl") else 0
    except OSError:
        rules = 0
    rep.add(OK if rules else WARN, "审计规则",
            "%d 条审计规则已加载" % rules if rules
            else "没有读到审计规则（auditd 未运行或规则未加载）",
            "" if rules else "systemctl status auditd；vigil update")

    nginx = shutil.which("nginx") or "/www/server/nginx/sbin/nginx"
    if os.path.exists(nginx):
        # nginx prints its verdict on **stderr**, not stdout. Reading only
        # stdout made this report a hard failure on a perfectly valid
        # configuration -- a false alarm in the command whose entire job is
        # to be believable about whether things work.
        ok, out, err = shell.run([nginx, "-t"], timeout=20)
        text = ("%s\n%s" % (out or "", err or "")).strip()
        good = ok and ("successful" in text or "syntax is ok" in text)
        rep.add(OK if good else FAIL, "Web 配置语法",
                "nginx -t 通过" if good else (text[:200] or "nginx -t 没有输出"),
                "" if good else "按上面那条报错修；常见原因是某个 include 指错了目录")
    else:
        rep.add(WARN, "Web 配置语法", "没有找到 nginx，跳过")

    # -- alerting ---------------------------------------------------------
    providers = cfg.get("mail.providers", []) or []
    recipients = cfg.recipients("alert")
    if not providers or not recipients:
        rep.add(FAIL, "告警通道",
                "未配置渠道或收件人：出了问题你不会收到任何通知",
                "vigil mail setup")
        last_ok = False
    else:
        from ..mail import queue as q
        journal = q.recent_journal(200)
        sent = [r for r in journal if r.get("ok")]
        last_ok = bool(sent)
        when = sent[-1].get("ts", "?") if sent else "从未成功发出过"
        rep.add(OK if last_ok else WARN, "告警通道",
                "%d 个渠道 / %d 个收件人；最近成功投递：%s"
                % (len(providers), len(recipients), when),
                "" if last_ok else "vigil mail test")

    quota = int(cfg.get("mail.daily_quota", 0) or 0)
    if quota > 0:
        from ..mail import queue as q
        left = q.quota_remaining(quota)
        rep.add(OK if left > 0 else WARN, "今日邮件额度",
                "%d / %d 已用" % (q.quota_used(), quota) if left > 0
                else "已用尽（%d / %d），今天的告警会走备用渠道或积压"
                % (q.quota_used(), quota),
                "" if left > 0 else "额度按日重置；无需手工改动计数器")

    # -- inspection freshness --------------------------------------------
    last = paths.STATE_STATE / "health-last.json"
    if last.exists():
        age = time.time() - last.stat().st_mtime
        fresh = age < 3600
        rep.add(OK if fresh else WARN, "巡检新鲜度",
                "最近一次巡检在 %d 分钟前" % int(age // 60) if fresh
                else "最近一次巡检在 %.1f 小时前" % (age / 3600.0),
                "" if fresh else "systemctl list-timers 'vigil-*'")
        data = read_json(last, {}) or {}
        probs = data.get("problems") or []
        crit = [p for p in probs if p.get("status") == "CRIT"]
        rep.add(OK if not crit else FAIL, "当前严重异常",
                "没有严重异常" if not crit
                else "%d 项：%s" % (len(crit), "、".join(
                    p.get("label", "?") for p in crit[:3])),
                "" if not crit else "vigil health run 看详情")
    else:
        rep.add(WARN, "巡检新鲜度", "巡检从未运行过", "vigil health run")

    # -- upgrade safety ---------------------------------------------------
    rec = read_json(paths.STATE_STATE / "deploy.json", {}) or {}
    prev = paths.LIB / "vigil.prev"
    rep.add(OK if prev.is_dir() else WARN, "可回滚性",
            "保留了上一版（%s），可 `vigil rollback`"
            % (rec.get("previous") or "?") if prev.is_dir()
            else "没有保留上一版，出问题只能手工部署",
            "" if prev.is_dir() else "跑一次 `vigil update` 即会保留")

    backups = sorted(Path(str(cfg.get("backup.dir", "") or
                              "/var/backups/vigil")).glob("vigil-backup-*.tar.gz"))
    if backups:
        age_h = (time.time() - backups[-1].stat().st_mtime) / 3600.0
        rep.add(OK if age_h < 72 else WARN, "备份",
                "最近备份 %.1f 小时前（%d 份）" % (age_h, len(backups)),
                "" if age_h < 72 else "vigil backup")
    else:
        rep.add(WARN, "备份",
                "还没有备份：凭据与网关口令哈希丢了只能从控制台重来",
                "vigil backup")

    # -- self-integrity baseline -----------------------------------------
    from ..guards import health as health_mod
    state = health_mod.load_state()
    has_baseline = bool(state.get("self_integrity"))
    rep.add(OK if has_baseline else WARN, "自身完整性基线",
            "已建立，能发现程序被改动" if has_baseline
            else "尚未建立（下次巡检会建立）",
            "" if has_baseline else "vigil health run --only self_integrity")

    # -- login gate puzzle -----------------------------------------------
    # The one check here that looks at pixels rather than at flags. A gate
    # whose piece cannot be lined up with its gap locks the operator out
    # while every other line of this report says OK -- which is exactly what
    # happened once, and was caught by a person rather than by the program.
    try:
        from ..gates import detect_all, selftest as gate_st
        gates = detect_all()
    except Exception as e:                                  # noqa: BLE001
        gates, gate_st = [], None
        rep.add(WARN, "登录网关自检", "无法检测网关：%s" % e, "vigil gate selftest")
    if gate_st is not None and gates:
        results = gate_st.verify_all(gates)
        bad = [r for r in results if not r["ok"]]
        for r in results:
            detail = "；".join(c.get("detail", "")
                               for c in r["checks"].values() if c.get("ok")) \
                or "未通过"
            rep.add(OK if r["ok"] else FAIL,
                    "验证码可用性（%s）" % r["kind"],
                    detail if r["ok"] else "；".join(r["problems"]),
                    "" if r["ok"] else "vigil gate selftest")
    elif gate_st is not None:
        rep.add(OK, "登录网关", "没有安装网关，跳过", "")

    return rep


def cmd_selftest(args) -> int:
    cfg = load_config(args.config or None)
    rep = collect(cfg)

    if args.json:
        import json
        ui.out(json.dumps({"items": rep.items,
                           "failed": len(rep.failed),
                           "warned": len(rep.warned)},
                          ensure_ascii=False, indent=2))
        return 1 if rep.failed else (2 if rep.warned else 0)

    ui.header("安装自检", "回答一个问题：装好的东西是不是真的在工作")
    for status in (FAIL, WARN, OK):
        for item in rep.items:
            if item["status"] != status:
                continue
            # No mark of our own: ui.success/warning/failure already print
            # one, and two of them read as a rendering bug.
            line = "%-14s %s" % (item["label"], item["detail"])
            if status == FAIL:
                ui.failure(line)
            elif status == WARN:
                ui.warning(line)
            else:
                ui.success(line)
            if item["fix"]:
                ui.out("    → %s" % item["fix"])

    ui.out()
    if rep.failed:
        ui.failure("%d 项故障、%d 项警告 —— 这台机器现在的防护是不完整的"
                   % (len(rep.failed), len(rep.warned)))
        return 1
    if rep.warned:
        ui.warning("没有故障，%d 项警告（不影响防护，但值得看一眼）"
                   % len(rep.warned))
        return 2
    ui.success("全部通过：安装是通的，而且正在工作")
    return 0


def register(sub) -> None:
    p = sub.add_parser(
        "selftest", help="安装自检：确认装好的东西真的在工作",
        description="检查权限、配置、自身单元、生成物、告警通道、巡检新鲜度、"
                    "可回滚性与备份。出现故障时退出码为 1，只有警告时为 2，"
                    "全部通过为 0，可直接用于 cron 或 CI。")
    p.add_argument("--json", action="store_true", help="输出 JSON")
    p.set_defaults(func=cmd_selftest)
