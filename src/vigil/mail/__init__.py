"""Alerting subsystem -- the public entry points other components use.

Typical call from a check or a daemon::

    from vigil.mail import send_alert
    from vigil.mail.message import Alert, SEV_CRIT

    alert = Alert(title="检测到 SSH 爆破", severity=SEV_CRIT,
                  summary="同一来源在 300 秒内失败 12 次")
    alert.add_section("来源", ["203.0.113.9（示例地区 · 示例运营商）"])
    send_alert(alert)

Everything else -- rendering, provider fallback, quota, dedupe, overflow --
happens inside. Callers never touch a transport.
"""
from __future__ import annotations

import time

from ..core import paths
from ..core.config import Config, load as load_config
from ..i18n import language, t
from . import queue as q
from .message import (KIND_ALERT, KIND_DIGEST, KIND_LOGIN, KIND_REPLY,
                      KIND_TEST, SEV_CRIT, SEV_EVENT, SEV_INFO, SEV_WARN, Alert,
                      Message, Section, hostname)
from .render import (render_html, render_message, render_reply, render_test,
                     render_text, severity_label)
from .router import DeliveryReport, Router

__all__ = [
    "Alert", "Message", "Section", "DeliveryReport", "Router",
    "send_alert", "send_text", "send_recovery", "send_digest",
    "render_message", "render_html", "render_text", "render_reply",
    "render_test", "severity_label",
    "SEV_INFO", "SEV_WARN", "SEV_CRIT", "SEV_EVENT",
    "KIND_ALERT", "KIND_LOGIN", "KIND_REPLY", "KIND_TEST", "KIND_DIGEST",
    "make_router", "stats",
]


def make_router(cfg: Config = None, log=None) -> Router:
    """Build a delivery router.

    Named `make_router`, not `router`, and that is not a style preference:
    a function called `router` in this package shadows the `router`
    *submodule*, so `from ..mail import router` handed callers a function
    and every `router.Router(...)` in the command layer raised
    AttributeError. `vigil mail status` and `vigil mail test` -- the one
    command whose entire job is to prove the mail path works -- were both
    dead because of it.
    """
    return Router(cfg or load_config(), log)


def _emit(alert: Alert, cfg: Config, log=None, recipients=None,
          allow_dedupe: bool = True) -> DeliveryReport:
    """Render, number, and deliver one alert. The single funnel."""
    cfg = cfg or load_config()
    log = log or _default_log()
    paths.ensure_dirs()

    seq = q.next_seq()
    msg = render_message(
        alert, seq=seq,
        host=cfg.get("hostname", "") or hostname(),
        lang=cfg.get("mail.language", "zh") or language(),
        subject_prefix=cfg.get("mail.subject_prefix", "") or "",
    )
    msg.from_address = cfg.get("mail.from_address", "") or ""
    msg.from_name = cfg.get("mail.from_name", "") or ""
    msg.reply_to = cfg.get("mail.reply_to", "") or ""
    # Keep the number inside the body too, so a quoted reply preserves it.
    msg.text = "邮件编号: %s\n%s\n\n%s" % (msg.mail_id or "-", "─" * 56, msg.text)

    rt = make_router(cfg, log)
    rep = rt.deliver(msg, recipients=recipients, allow_dedupe=allow_dedupe)
    return rep


_LOG = None


def _default_log():
    global _LOG
    if _LOG is None:
        from ..core import logging as vlog
        _LOG = vlog.get("mail")
    return _LOG


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def send_alert(alert: Alert, cfg: Config = None, log=None,
               recipients=None, allow_dedupe: bool = True) -> DeliveryReport:
    """Deliver *alert*. Returns a report; never raises for delivery trouble.

    Dedupe is on by default: a check that keeps firing the same condition
    should not produce a mail every cycle. Pass ``allow_dedupe=False`` for
    interactive traffic such as command replies.
    """
    try:
        return _emit(alert, cfg, log, recipients, allow_dedupe)
    except Exception as e:                          # noqa: BLE001
        lg = log or _default_log()
        lg.error("告警发送失败: %s: %s" % (type(e).__name__, e))
        rep = DeliveryReport()
        rep.skipped = "内部错误: %s" % e
        return rep


def send_text(subject: str, body: str, severity: str = SEV_INFO,
              kind: str = KIND_ALERT, cfg: Config = None, log=None,
              recipients=None, allow_dedupe: bool = True) -> DeliveryReport:
    """Convenience wrapper for code that already has a formatted body."""
    alert = Alert(title=subject, severity=severity, kind=kind)
    alert.add_section("详情", [body])
    return send_alert(alert, cfg, log, recipients, allow_dedupe)


def send_recovery(title: str, detail: str = "", cfg: Config = None,
                  log=None) -> DeliveryReport:
    """A condition returned to normal. Never deduped -- the absence of a
    recovery is itself information the operator relies on."""
    alert = Alert(title=title, severity=SEV_INFO, kind=KIND_ALERT,
                  summary="此前报告的问题已恢复正常")
    if detail:
        alert.add_section("详情", [detail])
    return send_alert(alert, cfg, log, allow_dedupe=False)


def send_digest(cfg: Config = None, log=None, max_files: int = 1) -> DeliveryReport:
    """Replay alerts that were parked because every channel was down.

    Each digest file is claimed by renaming it first, so two concurrent
    runs cannot both send the same backlog (the old implementation marked a
    file '.sent' even when the replay had itself been re-parked).
    """
    cfg = cfg or load_config()
    log = log or _default_log()
    digests = q.overflow_digests()
    if not digests:
        return DeliveryReport(skipped="无积压告警")

    sent_any = False
    sent = 0
    for path in digests[:max_files]:
        claimed = str(path) + ".sending"
        try:
            import os
            os.replace(str(path), claimed)
        except OSError:
            continue
        alert = q.build_digest_alert(claimed, count=len(digests))
        rep = send_alert(alert, cfg, log, allow_dedupe=False)
        try:
            import os
            if rep.any_ok():
                # One archiving implementation, shared with everything else,
                # so a replayed file ends up in `sent/` rather than sitting in
                # the queue directory looking stuck.
                q.archive_claimed(claimed, path)
                sent_any = True
                sent += 1
            else:
                # Put it back untouched so nothing is lost.
                os.replace(claimed, str(path))
        except OSError:
            pass
    # Report what actually happened. The old return was a fresh, empty report,
    # so a successful replay summarised as "无收件人" -- the same defect as a
    # deferred alert printing as a failed one, and just as misleading: it sent
    # me looking for a message that had already been delivered.
    out = DeliveryReport(skipped="" if sent_any else "积压补发未成功")
    if sent:
        out.results["(积压补发)"] = {"provider": "digest", "ok": True,
                                     "detail": "%d 份" % sent}
    return out


def stats(cfg: Config = None) -> dict:
    cfg = cfg or load_config()
    base = q.stats()
    total = int(cfg.get("mail.daily_quota", 100) or 0)
    base["quota_total"] = total
    base["quota_remaining"] = q.quota_remaining(total)
    base["recipients"] = cfg.recipients("alert")
    base["login_recipients"] = cfg.recipients("login")
    try:
        base["providers"] = [p.id for p in make_router(cfg).chain()]
    except Exception:                               # noqa: BLE001
        base["providers"] = []
    base["ts"] = int(time.time())
    return base
