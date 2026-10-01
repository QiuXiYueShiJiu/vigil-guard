"""Rendering: :class:`Alert` -> plain text and HTML.

Why both formats: plain text survives every transport and every client, and
is what ``grep``/``less`` handle; HTML is what makes a wall of technical
detail actually readable on a phone at 3am. We always send both and let the
client choose (``multipart/alternative``).

The text format keeps a small amount of markup -- ``**bold**`` and
``\\`code\\``` -- because it is pleasant in clients that render Markdown and
harmless in those that do not.
"""
from __future__ import annotations

import html as _html
import re
from datetime import datetime

from ..i18n import t
from .message import (SEV_CRIT, SEV_EVENT, SEV_INFO, SEV_WARN, Alert, Message,
                      hostname)

RULE = "─" * 56

_SEV_LABEL = {
    SEV_CRIT: ("严重", "CRITICAL", "#c0392b"),
    SEV_WARN: ("警告", "WARNING", "#d68910"),
    SEV_EVENT: ("事件", "EVENT", "#2471a3"),
    SEV_INFO: ("信息", "INFO", "#1e8449"),
}

# IPv4 / IPv6-ish, highlighted because in this product's domain the address
# is almost always the single most important token on the line.
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
_CODE_RE = re.compile(r"`([^`]+)`")


def severity_label(sev: str, lang: str = "zh") -> str:
    idx = 1 if lang == "en" else 0
    return _SEV_LABEL.get(sev, _SEV_LABEL[SEV_INFO])[idx]


def severity_color(sev: str) -> str:
    return _SEV_LABEL.get(sev, _SEV_LABEL[SEV_INFO])[2]


# --------------------------------------------------------------------------
# Plain text
# --------------------------------------------------------------------------


def _wrap(line: str, width: int, indent: str) -> list:
    """Wrap a line on spaces, preserving any leading indent."""
    if len(line) <= width:
        return [line]
    words = line.split(" ")
    out, cur = [], ""
    for w in words:
        cand = (cur + " " + w) if cur else w
        if len(cand) > width and cur:
            out.append(cur)
            cur = indent + w
        else:
            cur = cand
    if cur:
        out.append(cur)
    return out


def render_text(alert: Alert, seq: int = 0, when: datetime | None = None,
                host: str = "", lang: str = "zh") -> str:
    when = when or datetime.now()
    host = host or hostname()
    label = severity_label(alert.severity, lang)
    head = alert.title
    if seq:
        head = "#%06d  %s" % (seq, head)

    lines = [head, RULE]
    lines.append("主机: %s" % host)
    lines.append("时间: %s" % when.strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("级别: %s" % label)
    if alert.summary:
        lines.append("")
        lines.append("【概要】%s" % alert.summary)

    for sec in alert.sections:
        if sec.is_empty():
            continue
        lines.append("")
        lines.append("【%s】" % sec.title)
        for raw in sec.lines:
            text = "" if raw is None else str(raw)
            if not text.strip():
                lines.append("")
                continue
            for sub in text.split("\n"):
                # Keep existing structure; only wrap genuinely long lines.
                for piece in _wrap(sub, 76, "    "):
                    lines.append("  " + piece)

    if alert.footer:
        lines.append("")
        lines.append(RULE)
        lines.append(alert.footer)
    return "\n".join(lines)


def render_message(alert: Alert, seq: int = 0, when: datetime | None = None,
                   host: str = "", lang: str = "zh",
                   subject_prefix: str = "") -> Message:
    """Render *alert* into a deliverable :class:`Message`."""
    when = when or datetime.now()
    host = host or hostname()
    text = render_text(alert, seq=seq, when=when, host=host, lang=lang)
    html = render_html(alert, seq=seq, when=when, host=host, lang=lang)
    prefix = ("%s " % subject_prefix) if subject_prefix else ""
    subject = "%s%s%s" % (prefix, ("[#%06d] " % seq) if seq else "",
                          alert.title)
    # Dedupe identity comes from the *alert*, never from the rendered
    # subject. The subject carries the per-message sequence number, so a key
    # derived from it was unique by construction and dedupe could not fire
    # for any alert that did not set one explicitly -- which is how one
    # changing file turned into an alert every two minutes.
    dedupe = alert.dedupe_key or ("%s|%s|%s" % (alert.kind or "", alert.title,
                                                alert.severity))
    return Message(subject=subject, text=text, html=html, kind=alert.kind,
                   severity=alert.severity, seq=seq, dedupe_key=dedupe)


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------


def _md_inline(text: str, escape: bool = True) -> str:
    """Escape, then apply the two markup forms we support."""
    out = _html.escape(text) if escape else text
    out = _BOLD_RE.sub(r"<strong>\1</strong>", out)
    out = _CODE_RE.sub(r"<code>\1</code>", out)
    out = _IP_RE.sub(r'<span class="ip">\g<0></span>', out)
    return out


def render_html(alert: Alert, seq: int = 0, when: datetime | None = None,
                host: str = "", lang: str = "zh") -> str:
    """Rendered with inline styles and a table layout, on purpose.

    The first version leaned on a `<style>` block and CSS classes. Mail
    clients do not honour that: Outlook drops `<style>` outright, QQ Mail and
    Gmail strip most of it, and none of them support flexbox, `gap` or CSS
    custom properties. The message arrived structurally complete and visually
    unstyled -- which reads as "the HTML didn't finish loading".

    So every visual property is written on the element it applies to, and the
    layout is tables, which is the one thing every client agrees on. The
    `<style>` block that remains carries only the dark-mode preference and is
    pure enhancement: delete it and the light rendering is still correct.
    """
    when = when or datetime.now()
    host = host or hostname()
    color = severity_color(alert.severity)
    label = severity_label(alert.severity, lang)
    zh = lang == "zh"

    font = ('font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",'
            '"PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif')
    mono = ('font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,'
            '"Liberation Mono",monospace')

    parts = []
    for sec in alert.sections:
        if sec.is_empty():
            continue
        body = []
        for raw in sec.lines:
            text = "" if raw is None else str(raw)
            if not text.strip():
                body.append('<div style="height:8px;line-height:8px">&nbsp;</div>')
                continue
            for sub in text.split("\n"):
                style = "margin:0 0 4px;word-break:break-word;"
                if _looks_technical(sub):
                    style += mono + ";font-size:13px;white-space:pre-wrap;"
                body.append('<div style="%s">%s</div>' % (style, _md_inline(sub)))
        parts.append(
            '<tr><td style="padding:0 22px 14px">'
            '<div style="%s;font-size:14px;font-weight:600;color:#374151;'
            'border-bottom:1px solid #eceff3;padding-bottom:5px;margin:16px 0 9px">'
            '%s</div>%s</td></tr>'
            % (font, _md_inline(sec.title), "".join(body))
        )

    meta = [("ID" if not zh else "编号", "#%06d" % seq) if seq else None,
            ("主机" if zh else "Host", host),
            ("时间" if zh else "Time", when.strftime("%Y-%m-%d %H:%M:%S")),
            ("级别" if zh else "Severity", label)]
    meta_rows = []
    for item in meta:
        if not item:
            continue
        k, v = item
        meta_rows.append(
            '<tr>'
            '<td style="%s;font-size:12.5px;color:#7c8798;padding:2px 10px 2px 0;'
            'white-space:nowrap;vertical-align:top">%s</td>'
            '<td style="%s;font-size:13px;color:#1b2233;padding:2px 0;'
            'word-break:break-all">%s</td></tr>' % (font, _html.escape(k), font,
                                                   _html.escape(v)))

    summary = ""
    if alert.summary:
        summary = (
            '<tr><td style="padding:0 22px 12px">'
            '<div style="%s;font-size:14px;line-height:1.65;color:#6b4c14;'
            'background:#fff8e6;border-left:4px solid #f0b429;'
            'border-radius:4px;padding:10px 13px">%s</div></td></tr>'
            % (font, _md_inline(alert.summary)))

    footer = ""
    if alert.footer:
        footer = (
            '<tr><td style="padding:12px 22px 16px;border-top:1px solid #e8eaed">'
            '<div style="%s;font-size:12px;color:#7c8798;white-space:pre-wrap">'
            '%s</div></td></tr>' % (font, _md_inline(alert.footer)))

    title = _html.escape(alert.title)

    return """<!DOCTYPE html>
<html lang="%(lang)s"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>%(title)s</title>
<style>
  /* Enhancement only. Every property that matters is inline, because most
     clients discard this block entirely. */
  a { color:#1d4ed8 }
  @media (prefers-color-scheme: dark) {
    body { background:#0f141c !important }
    .vg-card { background:#171d27 !important }
    .vg-body, .vg-body div, .vg-body td { color:#e6edf6 !important }
    .vg-head { background:#1d2430 !important }
    .vg-sub { color:#9aa4b2 !important }
    .vg-rule { border-color:#2b3341 !important }
  }
</style></head>
<body style="margin:0;padding:18px 10px;background:#f4f5f7;%(font)s">
<!-- Table layout, not flexbox: this is the one construct every mail
     client, including Outlook, renders the same way. -->
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0"
       border="0" style="border-collapse:collapse;background:#f4f5f7">
<tr><td align="center" style="padding:0">
  <table role="presentation" class="vg-card" width="720" cellpadding="0"
         cellspacing="0" border="0"
         style="border-collapse:collapse;width:100%%;max-width:720px;
                background:#ffffff;border-radius:10px;
                box-shadow:0 1px 3px rgba(20,32,58,.12);overflow:hidden">
    <tr><td class="vg-head"
            style="padding:16px 22px;border-left:5px solid %(color)s;
                   background:#fafbfc">
      <div style="%(font)s;font-size:17px;line-height:1.45;font-weight:700;
                  color:#111827;word-break:break-word">%(title)s</div>
      <div style="margin-top:8px">
        <span style="%(font)s;display:inline-block;font-size:12px;
                     font-weight:600;letter-spacing:.3px;color:#ffffff;
                     background:%(color)s;border-radius:11px;
                     padding:3px 11px">%(label)s</span>
      </div>
    </td></tr>
    <tr><td class="vg-body" style="padding:12px 22px 4px">
      <table role="presentation" cellpadding="0" cellspacing="0" border="0"
             style="border-collapse:collapse">%(meta)s</table>
    </td></tr>
    %(summary)s
    %(parts)s
    %(footer)s
  </table>
</td></tr></table>
</body></html>
""" % {
        "lang": _html.escape(lang), "title": title, "font": font,
        "color": color, "label": _html.escape(label),
        "meta": "".join(meta_rows), "summary": summary,
        "parts": "".join(parts), "footer": footer,
    }

def _looks_technical(line: str) -> bool:
    """Heuristic: indented or symbol-dense lines are technical detail."""
    if line.startswith("  ") or line.startswith("\t"):
        return True
    if line.count("/") >= 2 or line.count(":") >= 2:
        return True
    return len(line) > 60 and line.count(" ") < 6


def render_reply(body: str, seq: int = 0, host: str = "", lang: str = "zh") -> Message:
    """A command-channel reply: plain text, deliberately unstyled.

    Replies are read on a phone by someone who wants the answer, not a
    dashboard, so this stays as close to text as possible.
    """
    host = host or hostname()
    head = "#%06d  " % seq if seq else ""
    text = "%s%s\n%s\n\n%s\n" % (head, host, RULE, body.strip())
    esc = _html.escape(body.strip())
    html = ("<pre style=\"font:13px/1.5 ui-monospace,Menlo,Consolas,monospace;"
            "white-space:pre-wrap;word-break:break-word\">%s</pre>" % esc)
    subject = "%s%s" % (head, ("命令结果" if lang == "zh" else "Command result"))
    return Message(subject=subject, text=text, html=html, kind="reply", seq=seq)


def render_test(seq: int, cfg_from: str, providers: list, host: str = "",
                lang: str = "zh") -> Message:
    """The message sent by `vigil mail test`.

    It states which provider would be used first and which others are
    configured, because the most common support question is "why did this
    arrive from the wrong service".
    """
    from ..version import __version__
    host = host or hostname()
    when = datetime.now()
    lines = [
        "这是一封测试邮件，收到它说明告警通道已经完全打通。" if lang == "zh"
        else "This is a test message. Receiving it means alerting works.",
        "",
        "主机: %s" % host,
        "时间: %s" % when.strftime("%Y-%m-%d %H:%M:%S"),
        "Vigil 版本: %s" % __version__,
        "发件地址: %s" % cfg_from,
        "",
        "渠道优先级（自上而下，失败自动降级）:" if lang == "zh"
        else "Channel priority (top first, falls back on failure):",
    ]
    for i, p in enumerate(providers, 1):
        lines.append("  %d. %s" % (i, p))
    body = "\n".join(lines)
    alert = Alert(
        title="Vigil 测试邮件" if lang == "zh" else "Vigil test message",
        severity=SEV_INFO, kind="test",
        summary="告警通道验证" if lang == "zh" else "Alert channel verification",
        sections=[],
    )
    msg = render_message(alert, seq=seq, when=when, host=host, lang=lang)
    msg.text = body
    msg.html = ("<pre style=\"font:13px/1.6 ui-monospace,Menlo,Consolas,"
                "monospace;white-space:pre-wrap\">%s</pre>" % _html.escape(body))
    return msg
