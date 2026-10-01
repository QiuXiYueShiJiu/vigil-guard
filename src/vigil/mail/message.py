"""Message model.

An :class:`Alert` is the structured description of something worth telling
the operator about. Providers never see it: they receive a fully rendered
:class:`Message` (subject + plain text + optional HTML + recipients), which
keeps the "how do I describe this" concern and the "how do I deliver this"
concern apart.

The model is deliberately small. Anything a check wants to say goes into a
:class:`Section`; anything the transport needs (ids, quota, retries) lives
on :class:`Message`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

SEV_INFO = "INFO"
SEV_WARN = "WARN"
SEV_CRIT = "CRIT"
SEV_EVENT = "EVENT"

_SEV_ORDER = {SEV_INFO: 0, SEV_EVENT: 1, SEV_WARN: 2, SEV_CRIT: 3}

#: Kinds drive routing and are stable identifiers -- never translate them.
KIND_ALERT = "alert"
KIND_LOGIN = "login"
KIND_TEST = "test"
KIND_DIGEST = "digest"
KIND_REPLY = "reply"
KIND_RECOVERY = "recovery"


@dataclass
class Section:
    """One titled block inside an alert."""
    title: str
    lines: list = field(default_factory=list)

    def add(self, text: str = "") -> "Section":
        self.lines.append(text)
        return self

    def extend(self, texts: Iterable[str]) -> "Section":
        self.lines.extend(texts)
        return self

    def is_empty(self) -> bool:
        return not any(str(x).strip() for x in self.lines)


@dataclass
class Alert:
    """A structured thing that happened."""
    title: str
    severity: str = SEV_INFO
    kind: str = KIND_ALERT
    summary: str = ""
    sections: list = field(default_factory=list)
    footer: str = ""
    tags: list = field(default_factory=list)
    #: Deduplication key. When empty the router derives one from title+today.
    dedupe_key: str = ""

    def section(self, title: str) -> Section:
        """Fetch or create a section, so callers can build incrementally."""
        for s in self.sections:
            if s.title == title:
                return s
        s = Section(title)
        self.sections.append(s)
        return s

    def add_section(self, title: str, lines: Iterable[str] = ()) -> Section:
        s = Section(title, list(lines))
        self.sections.append(s)
        return s

    def worst(self, other: str) -> str:
        return other if _SEV_ORDER.get(other, 0) > _SEV_ORDER.get(self.severity, 0) \
            else self.severity

    def is_critical(self) -> bool:
        return self.severity == SEV_CRIT


@dataclass
class Message:
    """A rendered, deliverable message."""
    subject: str
    text: str
    html: str = ""
    to: list = field(default_factory=list)
    from_address: str = ""
    from_name: str = ""
    reply_to: str = ""
    kind: str = KIND_ALERT
    severity: str = SEV_INFO
    #: Assigned by the queue just before sending; appears in subject and body.
    seq: int = 0
    #: Provider ids that already failed, so a retry does not repeat them.
    tried: list = field(default_factory=list)
    created: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    dedupe_key: str = ""

    @property
    def mail_id(self) -> str:
        return "#%06d" % self.seq if self.seq else ""


def derive_dedupe_key(title: str, extra: str = "") -> str:
    """Coarse key: same title and same day collapse together."""
    day = datetime.now().strftime("%Y%m%d")
    blob = re.sub(r"\s+", " ", "%s|%s" % (title, extra)).strip().lower()
    return "%s|%s" % (day, blob[:160])


def hostname() -> str:
    import socket
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"
