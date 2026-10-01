"""`vigil doctor` and `vigil status` -- is this host able to do the job, and
is it currently doing it."""
from __future__ import annotations

import json as _json
import os
import time
from pathlib import Path

from .. import ui
from ..core import detect, paths, shell, units
from ..core.config import load as load_config
from ..version import __version__


def _log():
    from ..core import logging as vlog
    return vlog.get("main")


def cmd_doctor(args) -> int:
    """Environment self-check.

    Reports what this host *can* do, and what is missing that would degrade
    protection. The point is to make silent capability loss visible -- the
    most damaging failure mode in this project's history was a component
    that looked healthy while doing nothing.
    """
    env = detect.full()
    if args.json:
        ui.out(_json.dumps(env, ensure_ascii=False, indent=2, default=str))
        return 0

    s = env["system"]
    ui.header("环境自检", "%s · %s" % (s["distro"], s["kernel"]))

    ui.section("系统")
    ui.kv("主机名", s["hostname"])
    ui.kv("架构 / Python", "%s / %s" % (s["arch"], s["python"]))
    ui.kv("CPU / 内存", "%d 核 / %d MB" % (s["cpu_count"], env["memory_mb"]))
    ui.kv("init 系统", s["init"])
    ui.kv("权限", "root" if os.geteuid() == 0 else "普通用户（部分功能不可用）",
          "" if os.geteuid() == 0 else "yellow")

    ui.section("Web 环境")
    ng = env.get("nginx", {})
    if ng.get("present"):
        ui.kv("nginx", "%s（%s）" % (ng.get("version", "?"), ng.get("conf", "")))
        ui.kv("Lua 模块", "支持（可安装登录网关）" if ng.get("lua")
              else "不支持（登录网关无法安装）",
              "" if ng.get("lua") else "yellow")
        ui.kv("工作进程用户", ng.get("worker_user", "?"))
    else:
        ui.kv("nginx", "未检测到", "yellow")
    panel = env.get("bt_panel", {})
    if panel.get("present"):
        ui.kv("宝塔面板", "版本 %s，端口 %s" % (panel.get("version") or "?",
                                                panel.get("port")))
        ui.kv("面板入口路径", panel.get("admin_path") or "（默认）")
    socks = env.get("php_fpm", {}).get("sockets", [])
    if socks:
        ui.kv("PHP-FPM", ", ".join("%s（%s）" % (x["socket"], x["user"] or "?")
                                   for x in socks[:3]))
    roots = env.get("web_roots", [])
    ui.kv("网站目录", "%d 个" % len(roots) if roots else "未检测到")

    ui.section("防护能力")
    fw = env.get("firewall", {})
    ui.kv("防火墙", "%s（%s）" % (fw.get("kind", "none"),
                                  "已启用" if fw.get("active") else "未启用"),
          "green" if fw.get("active") else "yellow")
    ad = env.get("auditd", {})
    ui.kv("内核审计 auditd", "已安装" if ad.get("present") else "未安装",
          "green" if ad.get("present") else "yellow")
    if ad.get("present"):
        rules = shell.out(["auditctl", "-l"]).count("\n")
        ui.kv("已加载审计规则", "%d 条" % rules)
    mal = env.get("malware", {})
    engine = mal.get("engine", "none")
    ui.kv("恶意软件引擎", engine if engine != "none" else "未检测到",
          "green" if engine != "none" else "yellow")
    f2b = env.get("fail2ban", {})
    if f2b.get("present"):
        ui.kv("fail2ban", "已安装，%d 个 jail" % len(f2b.get("jails", [])))

    ui.section("告警通道")
    ui.kv("本地 MTA", "可用" if env.get("local_mta", {}).get("present") else "无")
    ui.kv("出口 25 端口", "可用" if env.get("port25_open") else "被封锁",
          "green" if env.get("port25_open") else "yellow")
    tools = env.get("tools", {})
    ui.kv("工具", ", ".join("%s=%s" % (k, "有" if v else "无")
                            for k, v in sorted(tools.items())))

    ui.section("日志来源")
    ls = env.get("log_sources", {})
    ui.kv("Web 访问日志", "%d 个" % len(ls.get("nginx_access", [])))
    for p in ls.get("nginx_access", [])[:5]:
        ui.bullet(ui.dim(p))
    ui.kv("认证日志", ", ".join(ls.get("auth", [])) or "未找到")

    # -- installed state ---------------------------------------------------
    ui.section("本程序状态")
    installed = Path("/usr/local/lib/vigil/vigil").is_dir()
    ui.kv("安装状态", "已安装" if installed else "未安装",
          "green" if installed else "yellow")
    if installed:
        ui.kv("版本", __version__)
        cfg = load_config(args.config or None)
        ui.kv("配置文件", "%s（%s）" % (cfg.path,
                                        "存在" if cfg.exists() else "缺失"))
        probs = cfg.validate()
        if probs:
            ui.problems_block(probs)
        for unit, active, enabled in units.list_units():
            style = "green" if active == "active" else "yellow"
            ui.kv(unit, "%s / %s" % (active, enabled), style)

    # -- recommendations ---------------------------------------------------
    recs = []
    if not env.get("firewall", {}).get("active"):
        recs.append("防火墙未启用 —— 建议启用 ufw/firewalld 限制暴露端口")
    if not env.get("auditd", {}).get("present"):
        recs.append("未安装 auditd —— 装上之后才能追溯「是谁改了哪个文件」"
                    "（apt install auditd）")
    if env.get("malware", {}).get("engine") == "none":
        recs.append("未安装恶意软件引擎 —— 无法按签名检出已知木马"
                    "（可选：apt install maldet 或 clamav）")
    if not env.get("port25_open"):
        recs.append("出口 25 端口被机房封锁 —— 自建邮局不可用，"
                    "请使用 API 渠道或 587/465 提交端口")
    if env.get("nginx", {}).get("present") and not env.get("nginx", {}).get("lua"):
        recs.append("nginx 未编译 Lua 模块 —— 登录网关功能不可用")
    ui.out()
    if recs:
        ui.section("建议")
        for r in recs:
            ui.warning(r)
    else:
        ui.out()
        ui.success("未发现需要处理的问题")
    return 0


def cmd_status(args) -> int:
    cfg = load_config(args.config or None)
    if args.json:
        ui.out(_json.dumps(_collect(cfg), ensure_ascii=False, indent=2, default=str))
        return 0

    ui.header("Vigil 运行状态", cfg.get("hostname", "") or "")

    installed = Path("/usr/local/lib/vigil/vigil").is_dir()
    if not installed:
        ui.warning("本程序尚未安装到系统目录（当前从源码目录运行）")

    # -- services ----------------------------------------------------------
    ui.section("服务")
    rows = []
    for unit, active, enabled in units.list_units():
        rows.append([unit,
                     "运行中" if active == "active" else active,
                     "已启用" if enabled == "enabled" else enabled])
    if rows:
        ui.table(rows, headers=["单元", "状态", "开机自启"])
    else:
        ui.note("没有已安装的服务单元")

    # -- mail ---------------------------------------------------------------
    ui.section("告警通道")
    from ..mail import stats as mail_stats
    from ..mail.router import Router
    st = mail_stats(cfg)
    ui.kv("渠道", ", ".join(st["providers"]) or "未配置",
          "" if st["providers"] else "yellow")
    ui.kv("收件人", ", ".join(st["recipients"]) or "未配置",
          "" if st["recipients"] else "yellow")
    total = st["quota_total"]
    ui.kv("今日额度", "%d / %s" % (st["quota_used"], total or "不限"))
    ui.kv("积压待补发", st["overflow_files"],
          "yellow" if st["overflow_files"] else "")
    # Archives sit outside the queue directory now, but the count is shown so
    # "nothing is pending" cannot be misread as "something is stuck": a file
    # in a directory called `overflow/` read exactly like a backlog, and the
    # operator asked about a queue that was already empty.
    if st.get("archived_files"):
        ui.kv("已补发归档", "%d 份（已送达，仅留档）" % st["archived_files"])
    ui.kv("邮件编号", "#%06d" % st["sequence"])

    # -- threat -------------------------------------------------------------
    ui.section("风控")
    threat_state = None
    try:
        from ..guards import threat as threat_mod
        threat_state = threat_mod.status_snapshot(cfg)
    except Exception as e:                              # noqa: BLE001
        ui.note("风控模块不可用: %s" % e)
    if threat_state:
        ui.kv("白名单条目", threat_state.get("whitelist_count", 0))
        ui.kv("当前封禁", threat_state.get("banned_count", 0))
        ui.kv("累计封禁", threat_state.get("bans_total", 0))
        ui.kv("监控日志源", threat_state.get("sources", 0))
        notes = threat_state.get("notes") or []
        for n in notes:
            ui.warning(n)

    # -- health -------------------------------------------------------------
    ui.section("巡检")
    try:
        from ..guards import health as health_mod
        h = health_mod.last_result()
        if h:
            # `problems` is a count in a history row and a *list of problem
            # dicts* in health-last.json. Passing the list to %d raised
            # "a real number is required, not list", which the except below
            # then reported as "巡检模块不可用" -- so a real summary line
            # looked like a broken module.
            problems = h.get("problems", 0)
            if isinstance(problems, (list, tuple)):
                problems = len(problems)
            ui.kv("上次运行", h.get("when", "?"))
            ui.kv("检查项", "%d 项" % h.get("total", 0))
            ui.kv("异常", "%d 项" % problems,
                  "red" if problems else "green")
        else:
            ui.note("尚未运行过巡检")
    except Exception as e:                              # noqa: BLE001
        ui.note("巡检模块不可用: %s" % e)

    ui.out()
    probs = cfg.validate()
    ui.problems_block(probs)
    if not probs:
        ui.success("配置检查通过")
    return 0


def _collect(cfg) -> dict:
    out = {
        "version": __version__,
        "installed": Path("/usr/local/lib/vigil/vigil").is_dir(),
        "hostname": cfg.get("hostname", ""),
        "units": [{"unit": u, "active": a, "enabled": e}
                  for u, a, e in units.list_units()],
        "config_problems": cfg.validate(),
        "ts": int(time.time()),
    }
    try:
        from ..mail import stats as mail_stats
        out["mail"] = mail_stats(cfg)
    except Exception as e:                              # noqa: BLE001
        out["mail"] = {"error": str(e)}
    try:
        from ..guards import threat as threat_mod
        out["threat"] = threat_mod.status_snapshot(cfg)
    except Exception as e:                              # noqa: BLE001
        out["threat"] = {"error": str(e)}
    try:
        from ..guards import health as health_mod
        out["health"] = health_mod.last_result()
    except Exception as e:                              # noqa: BLE001
        out["health"] = {"error": str(e)}
    return out


def register(sub) -> None:
    p = sub.add_parser("doctor", help="环境自检：检测本机支持哪些能力",
                       description="检测系统、Web 环境、防护能力与告警通道，"
                                   "并指出会导致防护能力下降的缺失项。")
    p.add_argument("--json", action="store_true", help="以 JSON 输出")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("status", help="运行状态总览",
                       description="汇总服务状态、告警通道、风控与巡检结果。")
    p.add_argument("--json", action="store_true", help="以 JSON 输出")
    p.set_defaults(func=cmd_status)
