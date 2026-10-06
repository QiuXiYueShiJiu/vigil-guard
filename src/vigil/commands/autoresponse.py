"""``vigil autoresponse`` -- see, and undo, automatic process intervention.

Why this command exists at all
------------------------------

The automatic response stops processes, and an automated action with no way
back is not automation, it is damage with a delay. So the operator gets two
things here, and both are requirements rather than conveniences:

* ``status`` -- which processes this program currently has stopped, why, and
  with what evidence. An operator who cannot see what was paused will find
  out from a user complaining that a service is hung;
* ``resume`` -- one command to release them. Whatever the reason a process
  was stopped, the human's decision overrides it, immediately, without
  editing config or restarting anything.

``resume`` sends ``SIGCONT`` and nothing else. It does not "fix" anything,
and it deliberately does not need ``threat.autoresponse.enabled`` to be on:
turning the feature off must not leave processes frozen.
"""
from __future__ import annotations

import signal
import time

from .. import ui
from ..core.config import load as load_config
from ..core.state import read_json, write_json
from ..core import paths
from ..guards.checks import procresponse


def _state_path():
    return paths.HEALTH_STATE


def _load_state() -> dict:
    data = read_json(_state_path(), {})
    return data if isinstance(data, dict) else {}


def cmd_status(args) -> int:
    cfg = load_config(args.config or None)
    st = procresponse.settings(cfg)
    state = _load_state().get(procresponse.STATE_KEY) or {}
    stopped = state.get("stopped") or {}
    observing = state.get("observing") or {}
    now = time.time()

    ui.header("可疑进程自动响应", "会自动动别的进程，所以护栏比功能本身重要")
    ui.kv("总开关", "已启用（%s）" % st["action"] if st["enabled"]
          else "未启用（threat.autoresponse.enabled=false）")
    if st["enabled"]:
        ui.kv("动作", "%s（%s）" % (
            st["action"],
            "可逆：随后继续观察，证据被推翻会自动 SIGCONT 恢复"
            if st["action"] == "stop" else "**不可逆**"))
        ui.kv("观察期", "%.0f 秒（判定成立后先观察，期间出现豁免证据即放弃）"
              % st["observe_seconds"])
        ui.kv("恢复观察窗", "%.0f 秒（暂停后继续观察，证据被推翻就自动恢复）"
              % st["resume_window_seconds"])
        ui.kv("限频", "每小时最多处置 %d 个" % st["max_per_hour"])
        ui.kv("观察期后", "保持暂停等操作者决定"
              if st["after_observe"] == "hold"
              else "升级为 %s" % st["terminate_signal"])
        ui.kv("允许清单", "%d 条" % len(st["allowlist"]))
    ui.out()

    if not stopped and not observing:
        ui.info("当前没有由本程序暂停或正在观察的进程")
    for pid, rec in sorted(stopped.items(), key=lambda kv: int(kv[0]) if
                           str(kv[0]).isdigit() else 0):
        if not str(pid).isdigit():
            continue
        left = max(0.0, float(rec.get("deadline") or 0) - now)
        ui.out(ui.c("● 已暂停 pid %s" % pid, "yellow"))
        ui.kv("  可执行文件", rec.get("exe") or "（未记录）", indent=2)
        ui.kv("  暂停于", _when(rec.get("at")), indent=2)
        ui.kv("  证据", rec.get("evidence") or "（未记录）", indent=2)
        if rec.get("escalated"):
            ui.kv("  状态", "观察期已结束，按配置保持暂停（等待你的决定）",
                  indent=2)
        else:
            ui.kv("  状态", "恢复观察窗还剩 %.0f 秒（期间出现豁免证据会自动恢复）"
                  % left, indent=2)
    for pid, rec in sorted(observing.items()):
        if not str(pid).isdigit():
            continue
        ui.out(ui.c("◐ 观察中 pid %s" % pid, "cyan"))
        ui.kv("  可执行文件", rec.get("exe") or "（未记录）", indent=2)
        ui.kv("  自", _when(rec.get("since")), indent=2)
    if stopped:
        ui.out()
        ui.hint("撤销全部：vigil autoresponse resume --all")
        ui.hint("撤销一个：vigil autoresponse resume <pid>")
    return 0


def cmd_resume(args) -> int:
    cfg = load_config(args.config or None)
    state = _load_state()
    rs = state.get(procresponse.STATE_KEY)
    if not isinstance(rs, dict):
        ui.info("没有本程序暂停的进程")
        return 0
    stopped = rs.get("stopped") or {}
    targets = sorted(stopped, key=lambda k: int(k) if str(k).isdigit() else 0)
    if not args.all:
        if not args.pid:
            ui.failure("需要指定 PID，或用 --all 撤销全部")
            return 1
        wanted = {str(int(x)) for x in args.pid}
        targets = [p for p in targets if str(p) in wanted]
    if not targets:
        ui.info("没有匹配的已暂停进程")
        return 0

    runtime = procresponse.Runtime(cfg=cfg)
    resumed, failed = 0, 0
    for pid in targets:
        if not str(pid).isdigit():
            continue
        rec = stopped.get(pid) or {}
        # Identity re-check before resuming too, for the same reason it is
        # done before stopping: a reused pid belongs to an unrelated process,
        # and SIGCONT on an arbitrary process is its own kind of wrong.
        info = runtime.proc_info(int(pid))
        changed = bool(info) and procresponse._identity_changed(rec, info,
                                                               runtime)
        res = procresponse.apply_action(int(pid), signal.SIGCONT, runtime,
                                        action="resume")
        if res.get("ok"):
            resumed += 1
            procresponse.record("action-resumed", pid=int(pid), ok=True,
                                reason="操作者手动撤销（vigil autoresponse resume）",
                                evidence=rec.get("evidence"), outcome="undone")
            ui.success("已恢复 pid %s%s" % (pid, "（注意：pid 已被复用，"
                                            "恢复的可能不是原进程）"
                                            if changed else ""))
        else:
            failed += 1
            ui.failure("恢复 pid %s 失败：%s" % (pid, res.get("err")))
        rs["stopped"].pop(str(pid), None)
    write_json(_state_path(), state, mode=0o640)
    ui.out()
    ui.kv("已恢复", "%d 个" % resumed)
    if failed:
        ui.kv("失败", "%d 个" % failed)
    return 1 if failed else 0


def cmd_log(args) -> int:
    entries = procresponse.recent(limit=int(args.limit or 50))
    if not entries:
        ui.info("处置台账为空（%s）" % procresponse.ledger_path())
        return 0
    ui.header("处置台账", "每一次判定与动作都在这里，可追溯")
    for entry in entries:
        ui.out("%s  %s  pid=%s  %s" % (
            _when(entry.get("ts")), entry.get("kind"), entry.get("pid", "-"),
            ui.dim(str(entry.get("reason") or entry.get("outcome") or "")
                   [:110])))
    return 0


def _when(ts) -> str:
    try:
        return time.strftime("%F %T", time.localtime(float(ts)))
    except (TypeError, ValueError):
        return "时间未知"


def register(sub) -> None:
    p = sub.add_parser(
        "autoresponse",
        help="可疑进程的自动处置：查看暂停了哪些进程、一键撤销")
    sp = p.add_subparsers(dest="action")
    sp.required = True

    s = sp.add_parser("status", help="本程序当前暂停/观察了哪些进程")
    s.add_argument("--config", default=None)
    s.set_defaults(func=cmd_status)

    s = sp.add_parser("resume", help="撤销处置：对进程发送 SIGCONT 让它继续运行")
    s.add_argument("pid", nargs="*", help="要恢复的 PID；配合 --all 时可省略")
    s.add_argument("--all", action="store_true", help="恢复本程序暂停的全部进程")
    s.add_argument("--config", default=None)
    s.set_defaults(func=cmd_resume)

    s = sp.add_parser("log", help="处置台账（何时暂停、依据什么、何时恢复）")
    s.add_argument("--limit", default=50)
    s.set_defaults(func=cmd_log)
