"""Inspection runner.

Owns the lifecycle the individual checks do not care about: loading the
state, running every check, deciding what is worth an email, batching it,
and persisting the new state.

Four behaviours are deliberate and worth stating, because each one fixes
a way the previous generation either spammed or went silent:

* **One email per round.** Twenty problems are one message, not twenty.
* **A problem alerts once, then stays quiet for a while.** A condition that
  persists for six hours should not produce 180 identical emails -- but it
  must re-notify eventually, because a mail can be missed. What counts as
  "changed" is the set of failing checks *and the structure of each finding*
  (which files, which processes), with volatile numbers like a CPU percentage
  or a PID folded out: comparing those raw would re-alert faster than the old
  30-minute timer did, and changing severity or gaining a new tampered file
  must still alert at once.
* **Hysteresis on recovery.** A check that recovers and then fails again a
  few minutes later is flapping, not two separate incidents. The second
  failure is not emailed, and the "recovered" notice is held back until the
  state has been stable for ``alerts.recovery_quiet_seconds``. The finding
  is never hidden -- it stays in ``problems``, in ``vigil health`` and in
  the history -- and a failure that is still there once the quiet window
  ends is emailed exactly as before.
* **Recovery is reported once it is stable.** If an alert was sent, the
  operator needs to know when it stopped being true, or they will keep
  worrying.
"""
from __future__ import annotations

import json
import re
import time
from datetime import datetime

from ..core import paths
from ..core.config import load as load_config
from ..core.logging import get as get_logger
from ..core.state import read_json, write_json
from ..mail import send_alert, send_recovery
from ..mail.message import SEV_CRIT, SEV_EVENT, SEV_INFO, SEV_WARN, Alert
from . import knowledge
from .checks import base as cbase

STATUS_LOG = paths.HEALTH_STATE
LAST_RESULT = paths.STATE_STATE / "health-last.json"

_SEV_FOR = {cbase.OK: SEV_INFO, cbase.WARN: SEV_WARN,
            cbase.CRIT: SEV_CRIT, cbase.EVENT: SEV_EVENT}


def _log():
    return get_logger("health")


#: 抖动迟滞窗口的默认值（秒）：恢复后 10 分钟内再次变坏不重复告警。
DEFAULT_RECOVERY_QUIET = 600
#: 未变化的持续异常重复提醒间隔的默认值（秒，6 小时）。
DEFAULT_RENOTIFY = 6 * 3600


def recovery_quiet_seconds(cfg) -> int:
    """抖动迟滞窗口：某项检查恢复后多久内再次变坏不重复告警。

    0 表示关闭迟滞（恢复即告警、再坏即告警）。
    """
    try:
        value = int(cfg.get("alerts.recovery_quiet_seconds",
                            DEFAULT_RECOVERY_QUIET) or 0)
    except (TypeError, ValueError):
        value = DEFAULT_RECOVERY_QUIET
    return max(0, value)


def renotify_seconds(cfg) -> int:
    """同一个**未变化**的异常最长多久重复提醒一次。0 表示每次都提醒。"""
    try:
        value = int(cfg.get("alerts.renotify_seconds", DEFAULT_RENOTIFY) or 0)
    except (TypeError, ValueError):
        value = DEFAULT_RENOTIFY
    return max(0, value)


def _alert_items(items) -> list:
    """JSON-friendly fingerprint of the alertable set.

    Each entry is ``[id, status, folded-detail]``. The detail is folded rather
    than dropped so that a *new* item inside a finding -- one more tampered
    file, one more hot process -- re-alerts immediately, while the parts that
    churn every round do not.
    """
    return sorted([str(p.get("id", "")), str(p.get("status", "")),
                   _detail_fp(p.get("detail", ""))]
                  for p in (items or []))


#: Runs of digits in a detail. See :func:`_detail_fp`.
_DIGITS_RX = re.compile(r"\d+")


def _detail_fp(detail: str) -> str:
    """A detail string with the volatile parts folded out.

    Several checks put a CPU percentage, a PID, a count or a duration in the
    detail, and those change on every run -- `process_anomaly` literally
    prints `chrome(pid 1234, CPU 91%)`. Comparing the detail raw would make a
    persistent finding re-alert every inspection, which is worse than the
    old 30-minute timer. Folding digits to `#` keeps what is structural: a
    changed file list, a changed process name, a changed reason. A genuinely
    numeric change is not lost -- it is still in the next re-notify, and the
    finding is on every visible surface the whole time.
    """
    return _DIGITS_RX.sub("#", " ".join(str(detail or "").split()))[:500]


def renotify_due(state: dict, items, now: float, window: int) -> tuple:
    """(是否该发信, 原因)：同一个未变化的异常不反复发。

    比对的是「本轮要发信的异常集合」（id + 严重度 + 折叠掉数字的 detail）。
    真正需要立即提醒的是集合的变化：新的一项变坏、严重度上升、或一项异常
    的内容变了（多了个被动过的文件）。数字抖动（CPU 百分比、PID）不算变化。
    """
    current = {(str(p.get("id", "")), str(p.get("status", "")),
                _detail_fp(p.get("detail", "")))
               for p in (items or [])}
    rec = state.get("alert_notify")
    if not isinstance(rec, dict) or not rec:
        return True, "首次告警"
    previous = set()
    for row in (rec.get("items") or []):
        try:
            previous.add(tuple(str(x) for x in row))
        except TypeError:                               # pragma: no cover
            continue
    added = current - previous
    if added:
        return True, ("新增异常、严重度上升或异常内容变化：%s"
                      % "、".join("%s[%s]" % (a, b)
                                  for a, b, _d in sorted(added)))
    try:
        at = float(rec.get("at", 0) or 0)
    except (TypeError, ValueError):
        at = 0.0
    if window <= 0 or (now - at) >= window:
        return True, "重复提醒间隔已到"
    return False, "同一异常未变化，仍在重复提醒间隔内"


def remember_alert(state: dict, items, now: float) -> None:
    """记下这一批异常与发信时间，供下一轮判断「有没有变化」。"""
    state["alert_notify"] = {"at": now, "items": _alert_items(items)}


def forget_alert(state: dict) -> None:
    """异常全部消失：忘掉上一批，这样再犯时算「新的一次」。"""
    state.pop("alert_notify", None)


def load_state() -> dict:
    data = read_json(STATUS_LOG, {})
    if not isinstance(data, dict):
        data = {}
    data.setdefault("status", {})
    return data


def save_state(state: dict) -> bool:
    return write_json(STATUS_LOG, state, mode=0o640)


#: Longest an acknowledgement may last. Silence that never expires is how a
#: real finding gets buried under a decision somebody made months ago.
ACK_MAX_SECONDS = 30 * 24 * 3600


def parse_duration(text: str) -> int:
    """``30m`` / ``2h`` / ``7d`` / ``900`` -> seconds. Raises ValueError."""
    raw = str(text or "").strip().lower()
    if not raw:
        raise ValueError("空时长")
    unit = raw[-1]
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(unit)
    if mult is None:
        mult, raw = 1, raw
    else:
        raw = raw[:-1]
    try:
        value = float(raw)
    except ValueError:
        raise ValueError("无法理解的时长：%s" % text)
    if value <= 0:
        raise ValueError("时长必须为正")
    return int(value * mult)


def active_acks(state: dict, now: float = None) -> dict:
    """Acknowledgements that have not expired."""
    now = now if now is not None else time.time()
    out = {}
    for check_id, rec in (state.get("acks") or {}).items():
        if not isinstance(rec, dict):
            continue
        if float(rec.get("until", 0) or 0) > now:
            out[check_id] = rec
    return out


def add_ack(check_id: str, seconds: int, note: str = "") -> dict:
    """Silence one check's *emails* for a while. It is still logged."""
    seconds = max(60, min(int(seconds), ACK_MAX_SECONDS))
    state = load_state()
    acks = state.get("acks") or {}
    until = time.time() + seconds
    acks[check_id] = {"until": until, "note": str(note or "")[:200],
                      "at": time.time()}
    state["acks"] = acks
    save_state(state)
    return acks[check_id]


def clear_ack(check_id: str) -> bool:
    state = load_state()
    acks = state.get("acks") or {}
    if check_id not in acks:
        return False
    acks.pop(check_id, None)
    state["acks"] = acks
    save_state(state)
    return True


def last_result() -> dict:
    data = read_json(LAST_RESULT, {})
    return data if isinstance(data, dict) else {}


def rebaseline(check_id: str, log=None) -> bool:
    """Forget the stored baseline for a stateful check.

    Used after `vigil update` (the program's own files legitimately changed)
    and by `vigil health rebaseline <check>` when the operator has looked at
    a finding and accepted it. Deleting the snapshot is enough: the next run
    sees no previous value and establishes a fresh one.
    """
    log = log or _log()
    state = load_state()
    dropped = [k for k in list(state)
               if k == check_id or k == check_id + "_v"]
    if not dropped:
        log.info("没有 %s 的基线可重建" % check_id)
        return False
    for key in dropped:
        state.pop(key, None)
    save_state(state)
    log.info("已清除 %s 的基线（%s），下次巡检将重新建立"
             % (check_id, "、".join(dropped)))
    return True


def run_once(cfg=None, log=None, notify: bool = True, only=None,
             now: float = None) -> dict:
    """Run every check once and return a structured result.

    ``now`` is a testability seam: the alert policy is time-dependent
    (hysteresis windows, re-notify intervals), and a test that has to sleep
    ten minutes to prove "it stayed quiet" is not a test anybody runs. It
    defaults to the real clock and is never set by the daemon.
    """
    cfg = cfg or load_config()
    log = log or _log()
    started = time.time()
    now = float(now) if now is not None else time.time()

    cbase.load_all()
    checks = cbase.all_checks()
    if only:
        wanted = {x.strip() for x in only if x.strip()}
        checks = [c for c in checks if c.id in wanted]
        if not checks:
            from ..core.errors import VigilError
            raise VigilError("没有匹配的检查项: %s" % ", ".join(sorted(wanted)),
                             hint="运行 `vigil health list` 查看可用 ID")

    env = _env_cached()
    state = load_state()
    prev_status = dict(state.get("status") or {})

    ctx = cbase.CheckContext(cfg, state, env, log, now)
    maintenance = ctx.maintenance

    quiet_secs = recovery_quiet_seconds(cfg)
    renotify_secs = renotify_seconds(cfg)
    #: check id -> 最近一次「异常转正常」的时间戳。抖动迟滞用它判断
    #: 「刚恢复就又坏」。
    recovered_at = dict(state.get("recovered_at") or {})
    #: check id -> 已恢复、但还在等状态稳定的待发恢复通知。恢复信不立刻发：
    #: 先等 recovery_quiet_seconds；抖动没结束就取消，免得为一个从未告警过
    #: 的波动补一封「已恢复」。
    pending_recovery = dict(state.get("pending_recovery") or {})

    problems, recoveries, results = [], [], {}
    new_status = {}

    for cls in checks:
        if not cls.enabled_by_default:
            continue
        chk = cls(cfg)
        if maintenance and cls.id in cbase.MAINTENANCE_SILENCED:
            new_status[cls.id] = prev_status.get(cls.id, cbase.OK)
            results[cls.id] = {"status": new_status[cls.id],
                               "label": chk.label_for(_lang(cfg)),
                               "detail": "维护模式：已跳过"}
            continue

        res = chk.safe_run(ctx)
        new_status[cls.id] = res.status
        results[cls.id] = {"status": res.status,
                           "label": chk.label_for(_lang(cfg)),
                           "detail": res.detail or ""}

        prev = prev_status.get(cls.id, cbase.OK)
        if res.status in cbase.PROBLEM_STATUSES:
            item = {"id": cls.id, "label": chk.label_for(_lang(cfg)),
                    "status": res.status, "detail": res.detail or "",
                    "group": cls.group,
                    **_knowledge_for(cls.id)}
            # 迟滞：刚恢复就又坏 —— 这是抖动，不是新事件。仍然记进
            # `problems`（`vigil health` 看得到、退出码照样是 1），只是这一轮
            # 不发信。静默期一过、异常还在，下一轮就照常告警。
            recovered = recovered_at.get(cls.id)
            if (recovered is not None and quiet_secs > 0
                    and (now - float(recovered)) < quiet_secs):
                item["notify"] = False
                item["quiet_for"] = round(now - float(recovered), 1)
                pending_recovery.pop(cls.id, None)
            else:
                item["notify"] = True
            problems.append(item)
        elif res.status == cbase.EVENT:
            # Events describe something that already happened; they are
            # always worth reporting and never have a recovery.
            problems.append({"id": cls.id, "label": chk.label_for(_lang(cfg)),
                             "status": res.status, "detail": res.detail or "",
                             "group": cls.group, "notify": True,
                             **_knowledge_for(cls.id)})
        elif res.status == cbase.OK:
            if prev in cbase.PROBLEM_STATUSES:
                # 异常转正常：记下恢复时间（迟滞窗口从这里算），并把恢复
                # 通知挂起，等状态稳定后再发。
                recovered_at[cls.id] = now
                pending_recovery[cls.id] = {
                    "at": now, "label": chk.label_for(_lang(cfg)),
                    "detail": res.detail or ""}
            pend = pending_recovery.get(cls.id)
            if pend is not None:
                try:
                    age = now - float(pend.get("at", now))
                except (TypeError, ValueError):
                    age = float(quiet_secs)
                if age >= quiet_secs:
                    recoveries.append({"id": cls.id,
                                       "label": pend.get("label")
                                       or chk.label_for(_lang(cfg)),
                                       "detail": pend.get("detail", "")})
                    pending_recovery.pop(cls.id, None)

    if only:
        # A subset run must not erase what the other checks last reported.
        # `vigil health run --only X` used to replace the whole status map
        # with just X, so every other check silently forgot its previous
        # state -- which costs it its recovery detection and its hysteresis.
        merged = dict(prev_status)
        merged.update(new_status)
        state["status"] = merged
    else:
        state["status"] = new_status
    state["recovered_at"] = recovered_at
    state["pending_recovery"] = pending_recovery
    # 旧的 per-check `cooldown` 字段是「上次发信时间」，语义已被
    # alerts.renotify_seconds 取代。清掉死数据，别让它看起来还在生效。
    state.pop("cooldown", None)
    state["last_run"] = now
    save_state(state)

    elapsed = time.time() - started
    result = {
        "when": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ts": int(now),
        "elapsed": round(elapsed, 3),
        "total": len(results),
        "problems": problems,
        "recoveries": recoveries,
        "results": results,
        "maintenance": maintenance,
    }
    write_json(LAST_RESULT, result, mode=0o640)

    counts = _counts(results)
    log.info("巡检完成：%d 项，耗时 %.2fs，异常 %d 项（严重 %d / 警告 %d / 事件 %d）"
             % (len(results), elapsed, len(problems),
                counts[cbase.CRIT], counts[cbase.WARN], counts[cbase.EVENT]))

    mode = str(cfg.get("alerts.mode", "attacks") or "attacks")
    acks = active_acks(state)

    if notify and problems:
        loud = alertable(problems, mode)
        # 迟滞静默：不发信，但异常本身还在 `problems` 里。
        flapping = [p for p in loud if not p.get("notify", True)]
        if flapping:
            loud = [p for p in loud if p.get("notify", True)]
            log.info("抖动期静默（刚恢复，不重复告警）：%s"
                     % "、".join(p["label"] for p in flapping))
        # An acknowledgement silences the *email*, never the finding. It is
        # still printed here, still in the history, still in `vigil status`
        # -- the operator said "I know about this one", not "stop looking".
        silenced = [p for p in loud if p.get("id") in acks]
        if silenced:
            loud = [p for p in loud if p.get("id") not in acks]
            log.info("已确认（静默期内不发信）：%s"
                     % "、".join(p["label"] for p in silenced))
        if loud:
            due, why = renotify_due(state, loud, now, renotify_secs)
            if due:
                if why != "首次告警":
                    log.info("再次提醒（%s）" % why)
                _notify_problems(cfg, result, log, items=loud)
                remember_alert(state, loud, now)
                save_state(state)
            else:
                log.info("同一异常未变化，处于重复提醒间隔内（%.1f 小时），"
                         "本轮不发信（共 %d 项）；异常变化或间隔到时将再次提醒"
                         % (renotify_secs / 3600.0, len(loud)))
        else:
            # 这一轮没有任何**该发信**的异常：忘掉上一批指纹，这样同一项异常
            # 重新出现时算「新的一次」，不会被重复提醒窗口压住。
            if state.get("alert_notify"):
                forget_alert(state)
                save_state(state)
            if silenced:
                log.info("本轮异常均在静默期内，不发信（共 %d 项）" % len(silenced))
            elif flapping:
                log.info("本轮异常均为刚恢复后的抖动，不发信（共 %d 项）"
                         % len(flapping))
            else:
                names = "、".join(p["label"] for p in problems[:4])
                log.info("巡检异常 %d 项（%s）均为本机变更而非攻击，"
                         "按 alerts.mode=attacks 仅记录不发信"
                         % (len(problems), names))
    elif notify:
        # 这一轮没有任何异常（或只剩恢复）：忘掉上一批指纹，这样同一项异常
        # 在确认恢复之后重新出现时算「新的一次」，不会被重复提醒窗口压住。
        if state.get("alert_notify"):
            forget_alert(state)
            save_state(state)
        if recoveries:
            loud = ([r for r in recoveries if r.get("id") in _ATTACK_CHECKS]
                    if mode == "attacks" else list(recoveries))
            if loud:
                _notify_recoveries(cfg, result, log, items=loud)
    for p in problems:
        flag = "" if p.get("notify", True) else "（抖动期静默）"
        log.warn("  [%s] %s%s: %s" % (p["status"], p["label"], flag,
                                      (p["detail"] or "").replace("\n", " ")[:200]))
    return result


def _lang(cfg) -> str:
    from ..i18n import language
    return cfg.get("mail.language", "") or language()


def _knowledge_for(check_id: str) -> dict:
    entry = knowledge.explain(check_id)
    if not entry:
        return {}
    return {"consequence": entry.get("consequence", ""),
            "action": entry.get("action", "")}


#: Checks whose findings are an attack, or evidence that a security control
#: has been switched off. These always go to the operator.
#:
#: Everything else this program looks at is *drift*: "a file on this machine
#: changed", "the listening ports changed", "you logged in". On a box its
#: owner actually works on, drift is almost always the owner -- and a mailbox
#: that fills up with "nginx.conf changed" every time you edit nginx.conf
#: teaches you to ignore the alert that matters. Drift is still recorded,
#: still printed by `vigil health` and `vigil status`, and still escalates to
#: mail when it reaches CRIT.
_ATTACK_CHECKS = frozenset({
    "av_hits",             # the antivirus found something
    "webshell_process",    # a web server spawned a shell
    "suspicious_procs",    # a process looking like a known tool
    "process_anomaly",     # something is eating the CPU
    "root_accounts",       # a new uid=0 account
    "preload",             # ld.so.preload hijack
    "file_permissions",    # a critical file became world-writable
    "audit_rules",         # the audit trail was tampered with
    "web_content",         # a webshell on disk
    "outbound_connections",  # a connection to somewhere unexpected
    "php_config",          # a PHP setting that enables remote execution
    "panel_auth",          # the panel answering unauthenticated probes
    "services",            # a security service stopped
})


def alertable(problems, mode: str = "attacks") -> list:
    """The subset of `problems` that deserves an email.

    `mode="all"` keeps the old behaviour. `mode="attacks"` (the default)
    drops pure drift, on the reasoning that the operator already knows what
    they just did to their own server.
    """
    items = list(problems or [])
    if str(mode or "").strip().lower() != "attacks":
        return items
    return [p for p in items
            if p.get("status") == cbase.CRIT or p.get("id") in _ATTACK_CHECKS]


def _counts(results: dict) -> dict:
    out = {cbase.OK: 0, cbase.WARN: 0, cbase.CRIT: 0, cbase.EVENT: 0}
    for info in results.values():
        s = info.get("status", cbase.OK)
        out[s] = out.get(s, 0) + 1
    return out


def _notify_problems(cfg, result, log, items=None) -> None:
    problems = list(items if items is not None else result["problems"])
    counts = {cbase.CRIT: 0, cbase.WARN: 0, cbase.EVENT: 0}
    for p in problems:
        if p.get("status") in counts:
            counts[p["status"]] += 1
    crit = counts[cbase.CRIT]
    names = "、".join(p["label"] for p in problems[:3])
    if crit:
        title = "严重异常 %d 项（需立即处理）" % len(problems)
    else:
        title = "异常 %d 项" % len(problems)
    if names:
        title += " · " + names

    sev = SEV_CRIT if crit else SEV_WARN
    alert = Alert(title=title, severity=sev, kind="alert",
                  summary="共 %d 项异常（严重 %d，警告 %d，事件 %d）"
                          % (len(problems), counts[cbase.CRIT],
                             counts[cbase.WARN], counts[cbase.EVENT]))
    if crit:
        alert.footer = "含严重项，建议优先处理。"

    # Group by area so a long list stays readable.
    groups: dict = {}
    for p in problems:
        groups.setdefault(p.get("group") or "other", []).append(p)
    for group in cbase.GROUP_ORDER + ("other",):
        items = groups.get(group) or []
        if not items:
            continue
        pair = cbase.GROUP_LABEL.get(group, (group, group))
        sec = alert.add_section(pair[0] if _lang(cfg) != "en" else pair[1])
        for p in items:
            sec.add("[%s] %s" % (p["status"], p["label"]))
            for line in (p["detail"] or "").split("\n"):
                sec.add("    " + line)
            if p.get("consequence"):
                sec.add("    ▶ 可能后果: %s" % p["consequence"])
            if p.get("action"):
                sec.add("    ▶ 建议处置: %s" % p["action"])
            sec.add("")

    if result.get("elapsed"):
        alert.footer = ("%s巡检耗时 %.2f 秒（共 %d 项检查）。"
                        % (alert.footer + " " if alert.footer else "",
                           result["elapsed"], result["total"]))
    rep = send_alert(alert, cfg, log)
    log.info("已转发巡检告警：%s" % rep.summary())
    _append_log(result, rep)


def _notify_recoveries(cfg, result, log, items=None) -> None:
    items = list(items if items is not None else result["recoveries"])
    title = "异常已恢复 %d 项" % len(items)
    alert = Alert(title=title, severity=SEV_INFO, kind="recovery",
                  summary="此前报告的问题已恢复正常")
    sec = alert.add_section("已恢复")
    for r in items:
        sec.add("%s%s" % (r["label"], ("　" + r["detail"]) if r["detail"] else ""))
    rep = send_recovery(title, "", cfg, log) if False else send_alert(
        alert, cfg, log, allow_dedupe=False)
    log.info("已转发恢复通知：%s" % rep.summary())
    _append_log(result, rep)


def _append_log(result: dict, rep) -> None:
    """Keep a compact history so `vigil status` can show trends."""
    hist = paths.STATE_STATE / "health-history.jsonl"
    # Record *which* checks failed, not merely how many. A history line that
    # says "crit: 1" and nothing else is not an audit trail: when this was
    # first needed -- to answer "what actually alerted, and why?" after a
    # controlled test -- the answer had to be guessed, and the guess was
    # wrong. Counts age into uselessness; the id and the reason do not.
    bad = [{"id": cid, "status": (r or {}).get("status"),
            "detail": ((r or {}).get("detail") or "")[:300]}
           for cid, r in sorted(result.get("results", {}).items())
           if (r or {}).get("status") not in (cbase.OK, None)]
    rec = {"ts": result["ts"], "when": result["when"],
           "total": result["total"], "problems": len(result["problems"]),
           "crit": _counts(result["results"])[cbase.CRIT],
           "delivery": rep.summary() if rep else ""}
    if bad:
        rec["failed"] = bad[:10]
    try:
        paths.STATE_STATE.mkdir(parents=True, exist_ok=True)
        with open(hist, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        if hist.stat().st_size > 512 * 1024:
            lines = hist.read_text(encoding="utf-8").splitlines()[-500:]
            hist.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError:
        pass


_ENV_CACHE = {"ts": 0, "env": {}}


def _env_cached(ttl: int = 600) -> dict:
    """Host discovery is not free; cache it within a run and across tightly
    spaced runs."""
    import time as _t
    if _t.time() - _ENV_CACHE["ts"] > ttl or not _ENV_CACHE["env"]:
        from ..core import detect
        _ENV_CACHE["env"] = detect.full()
        _ENV_CACHE["ts"] = _t.time()
    return _ENV_CACHE["env"]


def list_checks(cfg=None) -> list:
    cbase.load_all()
    lang = _lang(cfg or load_config())
    return [{"id": c.id, "label": c.label_for(lang), "group": c.group,
             "group_label": c.group_label(lang), "stateful": c.stateful,
             "description": c.description} for c in cbase.all_checks()]


def main(argv=None) -> int:
    """Entry point for the ``vigil.guards.health`` module (systemd unit)."""
    import argparse
    p = argparse.ArgumentParser(prog="vigil-healthd",
                                description="Run one inspection round.")
    p.add_argument("--only", default="")
    p.add_argument("--no-notify", action="store_true")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--exit-code", action="store_true",
                   help="发现异常时返回退出码 1（供外部脚本判断；"
                        "systemd 定时任务不要用）")
    args = p.parse_args(argv)
    result = run_once(only=args.only.split(",") if args.only else None,
                      notify=not args.no_notify)
    if not args.quiet:
        print("巡检完成：%d 项，异常 %d 项"
              % (result["total"], len(result["problems"])))
    # Exit 0 even when problems were found. This runs from a systemd timer,
    # and a non-zero exit marks the *service* as failed -- which is both
    # untrue (the inspection succeeded) and actively harmful, because
    # `vigil status` and `systemctl --failed` would then show a broken unit
    # every time a disk filled up, training the operator to ignore them.
    # The alert email is the signal; the exit code is not.
    if args.exit_code:
        return 1 if result["problems"] else 0
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
