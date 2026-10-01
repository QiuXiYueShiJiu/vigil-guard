"""`vigil audit` -- kernel audit rules, the basis of change attribution."""
from __future__ import annotations

from pathlib import Path

import json as _json

from .. import ui
from ..core import detect, shell
from ..core.config import load as load_config
from ..core.errors import VigilError
from ..core.installer import Installer


def _log():
    from ..core import logging as vlog
    return vlog.get("main")


def _status_line() -> dict:
    env = detect.auditd()
    out = dict(env)
    if env.get("present"):
        out["active"] = shell.out(["systemctl", "is-active", "auditd"])
        rules = shell.out(["auditctl", "-l"])
        out["loaded_w"] = sum(1 for l in rules.splitlines()
                              if l.strip().startswith("-w "))
        out["loaded_total"] = len([l for l in rules.splitlines() if l.strip()])
        s = shell.out(["auditctl", "-s"])
        out["immutable"] = "enabled 2" in s
        rf = env.get("rules_file", "")
        try:
            text = Path(rf).read_text(encoding="utf-8") if rf else ""
        except OSError:
            text = ""
        out["file_w"] = sum(1 for l in text.splitlines()
                            if l.strip().startswith("-w "))
        out["configured"] = bool(text)
    return out


def cmd_status(args) -> int:
    st = _status_line()
    if args.json:
        ui.out(_json.dumps(st, ensure_ascii=False, indent=2))
        return 0
    ui.header("内核审计状态")
    if not st.get("present"):
        ui.failure("本机未安装 auditd")
        ui.hint("安装后即可追溯「是哪个进程改了哪个文件」：apt install auditd")
        return 1
    ui.kv("服务状态", st.get("active", "?"))
    ui.kv("开机自启", st.get("enabled", "?"))
    ui.kv("规则文件", st.get("rules_file", ""))
    ui.kv("文件中规则", "%d 条 watch" % st.get("file_w", 0))
    ui.kv("内核已加载", "%d 条" % st.get("loaded_total", 0))
    ui.kv("已置不可变", "是" if st.get("immutable") else "否（可被运行时改写）",
          "green" if st.get("immutable") else "yellow")
    if st.get("file_w") and st.get("loaded_w", 0) < st.get("file_w"):
        ui.out()
        ui.warning("规则未全部生效：内核 %d 条 < 文件 %d 条"
                   % (st.get("loaded_w", 0), st.get("file_w")))
        ui.hint("常见原因：某条 -w 指向不存在的路径，会使其后的规则被整体丢弃。"
                "运行 `vigil audit install` 重新生成。")
    return 0


def cmd_install(args) -> int:
    cfg = load_config(args.config or None)
    inst = Installer(cfg, log=_log())
    ui.note("正在生成并加载审计规则…")
    ok, detail = inst.install_audit_rules(cfg)
    (ui.success if ok else ui.failure)(detail)
    if not ok:
        ui.hint("检查 /etc/audit/rules.d/ 下其它规则文件是否有语法错误")
        return 1
    return cmd_status(args)


def cmd_show(args) -> int:
    """Print the rules that would be installed, without touching anything."""
    cfg = load_config(args.config or None)
    inst = Installer(cfg)
    text = inst.render_audit_rules(cfg)
    if args.json:
        ui.out(_json.dumps({"rules": text.splitlines()}, ensure_ascii=False,
                           indent=2))
        return 0
    ui.header("将要写入的审计规则")
    ui.out(text)
    targets = [l.split()[1] for l in text.splitlines() if l.startswith("-w ")]
    missing = [t for t in targets if not __import__("os").path.exists(t)]
    if missing:
        ui.warning("以下路径当前不存在，已被自动剔除（否则会导致其后规则被丢弃）：")
        for m in missing:
            ui.bullet(m)
    return 0


def cmd_off(args) -> int:
    """Remove our rule file. Requires a reboot to take effect once immutable."""
    cfg = load_config(args.config or None)
    env = detect.auditd()
    target = env.get("rules_file") or "/etc/audit/rules.d/vigil.rules"
    import os
    if not os.path.exists(target):
        ui.note("未找到我们的规则文件")
        return 0
    if not args.yes and not ui.confirm("删除审计规则文件 %s？" % target, default=False):
        return 0
    try:
        os.unlink(target)
    except OSError as e:
        ui.failure("删除失败: %s" % e)
        return 1
    ui.success("已删除 %s" % target)
    shell.run(["augenrules", "--load"], timeout=60)
    ui.note("若规则已置为不可变（-e 2），需重启后才会真正失效。")
    return 0


def register(sub) -> None:
    p = sub.add_parser("audit", help="内核审计规则（文件改动归因）",
                       description="管理 auditd 规则。有了它才能在文件被改动时"
                                   "追溯到具体是哪个进程、以什么身份改的。")
    ps = p.add_subparsers(dest="audit_action", metavar="<操作>")

    sp = ps.add_parser("status", help="查看审计规则状态")
    sp.set_defaults(func=cmd_status)

    sp = ps.add_parser("install", help="生成并加载审计规则")
    sp.set_defaults(func=cmd_install)

    sp = ps.add_parser("show", help="只显示将要写入的规则，不做修改")
    sp.set_defaults(func=cmd_show)

    sp = ps.add_parser("off", help="删除本程序添加的审计规则")
    sp.add_argument("--yes", "-y", action="store_true")
    sp.set_defaults(func=cmd_off)
