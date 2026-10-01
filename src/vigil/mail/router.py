"""Delivery router.

Takes a rendered :class:`Message` and gets it to every recipient, trying
each configured provider in order. The properties that matter:

* **Per-recipient isolation.** One bad address must not stop the others.
  Each recipient independently walks the chain.
* **Quota awareness per provider.** A provider declares what one delivery
  costs (Resend bills one unit per recipient). When the day's budget for a
  provider is gone we move to the next channel instead of failing.
* **Honest reporting.** The caller gets a structured report saying which
  provider delivered to whom, and whether anything had to be parked. The
  previous implementation always exited 0, so callers could not tell
  "delivered" from "written to a file nobody reads".
* **Never drop.** If every channel fails, the message goes to the overflow
  digest, which a later run replays.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..core.errors import AuthError, ProviderError, RateLimitError
from . import queue as q
from .message import Message
from .providers import base as pbase


@dataclass
class DeliveryReport:
    seq: int = 0
    #: recipient -> {"provider": str, "ok": bool, "detail": str}
    results: dict = field(default_factory=dict)
    overflowed: list = field(default_factory=list)
    skipped: str = ""

    def ok(self) -> bool:
        return bool(self.results) and all(r.get("ok") for r in self.results.values())

    def any_ok(self) -> bool:
        return any(r.get("ok") for r in self.results.values())

    def delivered_count(self) -> int:
        return sum(1 for r in self.results.values() if r.get("ok"))

    def summary(self) -> str:
        if self.skipped:
            return "skipped: %s" % self.skipped
        good = [t for t, r in self.results.items() if r.get("ok")]
        bad = [t for t, r in self.results.items() if not r.get("ok")]
        bits = []
        if good:
            bits.append("已送达 %d/%d" % (len(good), len(self.results)))
        if bad:
            bits.append("失败: %s" % ", ".join(bad))
        if self.overflowed:
            bits.append("已转入积压待补发 %d 条" % len(self.overflowed))
        return "；".join(bits) or "无收件人"


class Router:
    def __init__(self, cfg, log=None):
        self.cfg = cfg
        self.log = log
        self._chain = None

    # -- provider chain ---------------------------------------------------
    def chain(self) -> list:
        """Instantiate the configured provider chain, best first.

        Built lazily and cached for the process; a provider that cannot even
        be constructed (unknown id) is skipped with a log line rather than
        taking down alerting entirely.
        """
        if self._chain is not None:
            return self._chain
        out = []
        try:
            pbase.import_builtins()
        except Exception as e:                      # pragma: no cover
            if self.log:
                self.log.error("无法载入邮件渠道模块: %s" % e)
        entries = list(self.cfg.providers())
        # Explicit priority wins; everything else keeps its configured order.
        # List order alone was the only control, which meant "try QQ first"
        # required deleting and re-adding channels -- and the order the
        # operator actually wanted was invisible unless they read the JSON.
        # Lower number = tried earlier. Entries without one keep their
        # position, so an existing configuration behaves exactly as before.
        if any(isinstance(e, dict) and "priority" in e for e in entries):
            def _rank(item):
                idx, entry = item
                try:
                    return (int((entry or {}).get("priority", idx + 1000)), idx)
                except (TypeError, ValueError):
                    return (idx + 1000, idx)
            entries = [e for _i, e in sorted(enumerate(entries), key=_rank)]

        for entry in entries:
            pid = (entry or {}).get("provider")
            if not pid:
                continue
            params = dict(entry)
            params.pop("provider", None)
            # Secrets from secrets.json win over anything inline.
            stored = self.cfg.get("providers.%s" % pid, {}) or {}
            if isinstance(stored, dict):
                params.update(stored)
            cls = pbase.get(pid)
            if cls is None:
                if self.log:
                    self.log.warn("跳过未知邮件渠道: %s" % pid)
                continue
            try:
                prov = cls(params, {"hostname": self.cfg.get("hostname", ""),
                                    "language": self.cfg.get("mail.language", "zh")})
            except Exception as e:
                if self.log:
                    self.log.warn("邮件渠道 %s 初始化失败: %s" % (pid, e))
                continue
            out.append(prov)
        self._chain = out
        return out

    def describe_chain(self, lang: str = "zh") -> list:
        return [p.label_for(lang) for p in self.chain()]

    # -- delivery ---------------------------------------------------------
    #: Message kinds that are never suppressed. A digest *is* the summary a
    #: storm produces, and a test message is the operator checking whether
    #: mail works at all -- suppressing either would be self-defeating.
    STORM_EXEMPT_KINDS = ("digest", "test")

    def _storm_suppressed(self, msg) -> str:
        """Reason to park this message instead of sending it, or "".

        Volume control, not a mute button. A real attack can produce hundreds
        of findings in a minute; sending one mail each is how an operator
        ends up filtering the alert channel into a folder nobody opens. The
        message is parked, not dropped: `vigil-maild` replays parked mail as
        a digest, and every finding stays visible in `vigil health` and
        `vigil status`.

        CRIT is never suppressed. If an attacker can generate critical
        findings, the answer is to show them -- a breaker in the threat
        daemon already bounds how fast bans can accumulate.
        """
        if msg.kind in self.STORM_EXEMPT_KINDS or msg.severity == "CRIT":
            return ""
        try:
            window = int(self.cfg.get("mail.storm_window", 600) or 600)
            limit = int(self.cfg.get("mail.storm_threshold", 12) or 12)
        except (TypeError, ValueError):
            return ""
        if window <= 0 or limit <= 0:
            return ""
        recent = q.sends_since(window)
        if recent < limit:
            return ""
        return ("告警风暴抑制：%d 秒内已发出 %d 封（阈值 %d），本条并入积压待补发"
                % (window, recent, limit))

    def deliver(self, msg: Message, recipients=None, allow_dedupe: bool = True,
                quota_total: int = None) -> DeliveryReport:
        rep = DeliveryReport(seq=msg.seq)
        chain = self.chain()
        if not chain:
            rep.skipped = "未配置任何邮件渠道"
            q.to_overflow(msg, rep.skipped)
            rep.overflowed.append(msg.seq)
            return rep

        recipients = list(recipients if recipients is not None
                          else self.cfg.recipients(msg.kind))
        if not recipients:
            # A webhook-only setup legitimately has no recipients.
            if any(not p.is_mail for p in chain):
                return self._deliver_webhooks(msg, rep)
            rep.skipped = "未配置收件人"
            q.to_overflow(msg, rep.skipped)
            rep.overflowed.append(msg.seq)
            return rep

        if quota_total is None:
            quota_total = int(self.cfg.get("mail.daily_quota", 100) or 0)

        # Storm control, before dedupe: if the channel has already sent a lot
        # in the last few minutes, this message waits rather than adding to
        # the pile. Parked, never dropped -- `vigil-maild` replays it as a
        # digest, and every finding stays visible in `vigil health`.
        suppressed = self._storm_suppressed(msg)
        if suppressed:
            rep.skipped = suppressed
            q.to_overflow(msg, suppressed)
            rep.overflowed.append(msg.seq)
            if self.log:
                self.log.warn("%s -> #%06d %s" % (suppressed, msg.seq,
                                                  msg.subject))
            return rep

        window = int(self.cfg.get("mail.dedupe_window", 900) or 0)
        if allow_dedupe and window > 0:
            key = q.dedupe_key_for(msg)
            if q.is_duplicate(key, window):
                rep.skipped = "重复告警，%d 秒内已发送过相同内容" % window
                if self.log:
                    self.log.info("去重跳过 #%06d %s" % (msg.seq, msg.subject))
                return rep
            q.mark_seen(key)

        # Chat-style channels deliver once, not per recipient.
        mail_chain = [p for p in chain if p.is_mail]
        hook_chain = [p for p in chain if not p.is_mail]

        if mail_chain:
            for to in recipients:
                self._deliver_one(msg, to, mail_chain, rep, quota_total)
        if hook_chain:
            self._deliver_webhooks(msg, rep, hook_chain)

        if self.log:
            self.log.info("#%06d %s -> %s" % (msg.seq, msg.subject, rep.summary()))
        return rep

    def _deliver_webhooks(self, msg: Message, rep: DeliveryReport,
                          hook_chain=None) -> DeliveryReport:
        hooks = hook_chain if hook_chain is not None else [
            p for p in self.chain() if not p.is_mail]
        for prov in hooks:
            try:
                prov.send(msg, "")
                rep.results["webhook:%s" % prov.id] = {
                    "provider": prov.id, "ok": True, "detail": ""}
                q.journal(msg, "webhook", prov.id, True)
            except (AuthError, RateLimitError, ProviderError) as e:
                rep.results["webhook:%s" % prov.id] = {
                    "provider": prov.id, "ok": False, "detail": e.message}
                q.journal(msg, "webhook", prov.id, False, e.message)
                if self.log:
                    self.log.warn("Webhook %s 失败: %s" % (prov.id, e.message))
            except Exception as e:                  # noqa: BLE001
                rep.results["webhook:%s" % prov.id] = {
                    "provider": prov.id, "ok": False, "detail": str(e)}
        return rep

    def _deliver_one(self, msg: Message, to: str, chain: list,
                     rep: DeliveryReport, quota_total: int) -> None:
        errors = []
        for prov in chain:
            cost = int(getattr(prov, "quota_per_recipient", 0) or 0)
            if cost and quota_total > 0:
                if q.quota_remaining(quota_total) < cost:
                    left = q.quota_remaining(quota_total)
                    errors.append("%s: 当日额度已用尽" % prov.id)
                    # Silently skipping a channel is how an operator ends up
                    # reading "已送达" while wondering why mail suddenly
                    # leaves from the backup provider. On 2026-09-27 a reply
                    # loop ate the whole 100/day quota and every message
                    # moved to the fallback without a word about it.
                    if self.log:
                        self.log.warn("渠道 %s 跳过 %s：当日额度已用尽"
                                      "（剩余 %d，本渠道每封需 %d）"
                                      % (prov.id, to, left, cost))
                    continue
            # Cheap pre-flight: do not burn a network round trip on a
            # provider that is obviously unconfigured.
            problems = prov.validate()
            if problems:
                errors.append("%s: %s" % (prov.id, "; ".join(problems)))
                if self.log:
                    self.log.warn("渠道 %s 未配置就绪，跳过 %s：%s"
                                  % (prov.id, to, "; ".join(problems)))
                continue
            try:
                prov.send(msg, to)
            except (AuthError, RateLimitError, ProviderError) as e:
                errors.append("%s: %s" % (prov.id, e.message))
                q.journal(msg, to, prov.id, False, e.message)
                if self.log:
                    self.log.warn("渠道 %s 投递 %s 失败: %s" % (prov.id, to, e.message))
                if e.hint and self.log:
                    self.log.warn("  提示: %s" % e.hint)
                continue
            except Exception as e:                  # noqa: BLE001
                errors.append("%s: %s" % (prov.id, e))
                q.journal(msg, to, prov.id, False, str(e))
                # Not one of the three expected failure kinds: that is a bug,
                # not a bad credential. Swallowing it silently made a provider
                # crashing on every send look merely "not preferred".
                if self.log:
                    self.log.warn("渠道 %s 投递 %s 时异常退出: %s: %s"
                                  % (prov.id, to, type(e).__name__, e))
                continue

            if cost:
                q.quota_add(cost, quota_total)
            rep.results[to] = {"provider": prov.id, "ok": True, "detail": ""}
            q.journal(msg, to, prov.id, True)
            return

        # Every channel failed for this recipient.
        rep.results[to] = {"provider": "", "ok": False,
                           "detail": "; ".join(errors) or "无可用渠道"}
        q.to_overflow(msg, "无可用通道 -> %s（%s）" % (to, "; ".join(errors)[:200]))
        rep.overflowed.append(msg.seq)

    # -- health / diagnosis ----------------------------------------------
    def probe(self, only: str = "") -> list:
        """Check each channel's connectivity. Returns [(id, ok, detail)]."""
        out = []
        for prov in self.chain():
            if only and prov.id != only:
                continue
            try:
                ok, detail = prov.health()
            except Exception as e:                  # noqa: BLE001
                ok, detail = False, "%s: %s" % (type(e).__name__, e)
            out.append((prov.id, ok, detail))
        return out

    def preflight(self) -> list:
        """Problems that would stop an alert being delivered."""
        problems = []
        if not self.cfg.providers():
            problems.append("未配置任何邮件渠道（运行 `vigil mail setup`）")
        if not self.cfg.recipients():
            problems.append("未配置收件人（运行 `vigil mail recipient add <邮箱>`）")
        if not self.cfg.get("mail.from_address"):
            for p in self.chain():
                if getattr(p, "id", "") in ("sendmail",) and not p.p("from_address"):
                    problems.append("本地 sendmail 渠道未设置发件地址")
        for prov in self.chain():
            problems.extend(prov.validate())
            align = getattr(prov, "alignment_warning", None)
            if callable(align):
                warn = align()
                if warn:
                    problems.append(warn)
        return problems
