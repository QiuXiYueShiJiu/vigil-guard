"""Provider framework.

A *provider* is one way of getting a message off the box. The product ships
several and chains them: the first that succeeds wins, the next is tried on
failure. That is the whole reason alerting here is trustworthy -- no single
vendor outage can silence the server.

Every provider declares its parameters as :class:`Field` objects. That one
declaration drives four things at once:

* the interactive ``vigil mail setup`` wizard,
* the ``--help`` text for non-interactive flags,
* the secret/public split when persisting config,
* the generated provider documentation.

Keeping those in sync by hand is how configuration wizards rot, so they are
derived instead.
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field as dc_field
from typing import Callable, Iterable

from ...core.errors import AuthError, ProviderError, RateLimitError
from ..message import Message

# --------------------------------------------------------------------------
# Field description
# --------------------------------------------------------------------------

TEXT, PASSWORD, EMAIL, NUMBER, CHOICE, BOOL = (
    "text", "password", "email", "number", "choice", "bool")


@dataclass
class Field:
    name: str
    label: str                       # Chinese label (primary audience)
    label_en: str = ""
    kind: str = TEXT
    required: bool = True
    default: str = ""
    choices: tuple = ()
    hint: str = ""                   # Chinese guidance
    hint_en: str = ""
    example: str = ""
    secret: bool = False             # routed to secrets.json

    def display(self, lang: str = "zh") -> str:
        return self.label if lang != "en" else (self.label_en or self.label)

    def guidance(self, lang: str = "zh") -> str:
        return self.hint if lang != "en" else (self.hint_en or self.hint)


# --------------------------------------------------------------------------
# Provider base
# --------------------------------------------------------------------------


class Provider:
    """Base class. Subclasses set the class attributes and implement send()."""

    id: str = ""
    label: str = ""
    label_en: str = ""
    kind: str = "api"                # api | smtp | local | webhook
    #: One line describing when to pick this one.
    blurb: str = ""
    blurb_en: str = ""
    #: Where the operator obtains credentials; shown by the wizard.
    docs_url: str = ""
    fields: tuple = ()
    #: Whether this channel can address arbitrary recipients (mail) or is a
    #: fixed drop (webhook -> a chat room).
    is_mail: bool = True
    #: Whether From-address alignment matters (SMTP relays often require it).
    needs_aligned_from: bool = False

    def __init__(self, params: dict | None = None, settings: dict | None = None):
        self.params = dict(params or {})
        self.settings = dict(settings or {})

    # -- parameter access -------------------------------------------------
    def p(self, name: str, default: str = "") -> str:
        v = self.params.get(name, default)
        return "" if v is None else str(v)

    def p_int(self, name: str, default: int = 0) -> int:
        try:
            return int(str(self.params.get(name, default)).strip())
        except (TypeError, ValueError):
            return default

    def p_bool(self, name: str, default: bool = False) -> bool:
        v = self.params.get(name)
        if v is None:
            return default
        if isinstance(v, bool):
            return v
        return str(v).strip().lower() in ("1", "true", "yes", "on", "y")

    # -- contract ---------------------------------------------------------
    def label_for(self, lang: str = "zh") -> str:
        return self.label if lang != "en" else (self.label_en or self.label)

    def validate(self) -> list:
        """Return a list of problems; empty means the parameters look sane."""
        problems = []
        for f in self.fields:
            if f.required and not self.p(f.name).strip():
                problems.append("%s: %s" % (self.id, f.display()))
        return problems

    def send(self, msg: Message, to: str) -> str:
        """Deliver *msg* to *to*. Return a provider-side id.

        Raise one of ProviderError / AuthError / RateLimitError on failure so
        the router can decide whether falling back is worthwhile.
        """
        raise NotImplementedError

    def health(self) -> tuple:
        """Cheap connectivity/credential probe. Returns (ok, detail)."""
        problems = self.validate()
        if problems:
            return False, "; ".join(problems)
        return True, "parameters present"

    def describe(self) -> str:
        """Short human label for the fallback chain listing."""
        return self.label_for()

    # -- helpers ----------------------------------------------------------
    def _http_json(self, url: str, payload: dict, headers: dict | None = None,
                   method: str = "POST", timeout: float = 20.0,
                   auth: tuple | None = None):
        """POST/GET JSON. Returns (status, headers, parsed-body-or-text).

        Raises AuthError on 401/403 and RateLimitError on 429, because those
        two change what the router should do: an auth failure will not be
        fixed by retrying, a rate limit might be fixed by another channel.
        """
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", "vigil/1.0 (+server-monitor)")
        for k, v in (headers or {}).items():
            if v is not None:
                req.add_header(k, str(v))
        if auth:
            import base64
            token = base64.b64encode(("%s:%s" % auth).encode()).decode()
            req.add_header("Authorization", "Basic " + token)

        ctx = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                raw = resp.read().decode("utf-8", "replace")
                try:
                    return resp.status, dict(resp.headers), json.loads(raw)
                except ValueError:
                    return resp.status, dict(resp.headers), raw
        except urllib.error.HTTPError as e:
            raw = ""
            try:
                raw = e.read().decode("utf-8", "replace")
            except Exception:
                pass
            if e.code in (401, 403):
                raise AuthError("provider rejected the credentials (HTTP %d)" % e.code,
                                hint=raw[:300])
            if e.code == 429:
                raise RateLimitError("provider rate limit hit (HTTP 429)",
                                     hint=raw[:300])
            raise ProviderError("HTTP %d from provider" % e.code, hint=raw[:300])
        except urllib.error.URLError as e:
            raise ProviderError("network error talking to provider: %s" % e.reason)
        except socket.timeout:
            raise ProviderError("timed out talking to provider")


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

_REGISTRY: dict = {}
_ORDER: list = []


def register(cls):
    """Class decorator adding a provider to the registry."""
    if not cls.id:
        raise ValueError("provider %r has no id" % cls)
    _REGISTRY[cls.id] = cls
    if cls.id not in _ORDER:
        _ORDER.append(cls.id)
    return cls


def get(provider_id: str):
    return _REGISTRY.get(provider_id)


def all_providers() -> list:
    return [_REGISTRY[i] for i in _ORDER]


def by_kind() -> dict:
    out: dict = {}
    for p in all_providers():
        out.setdefault(p.kind, []).append(p)
    return out


def ids() -> list:
    return list(_ORDER)


def build(entry: dict, settings: dict | None = None):
    """Instantiate the provider described by a config chain entry.

    Credentials may be inline in the entry (hand written config) or supplied
    separately from secrets.json; the caller merges them before calling.
    """
    pid = (entry or {}).get("provider", "")
    cls = get(pid)
    if cls is None:
        raise ProviderError("unknown provider %r" % pid,
                            hint="run `vigil mail providers` to list valid ids")
    params = {k: v for k, v in entry.items() if k != "provider"}
    return cls(params, settings)


def import_builtins() -> None:
    """Import the shipped provider modules so their decorators run.

    Explicit rather than a package scan: an implicit scan hides import
    errors and makes the set of channels depend on filesystem order.
    """
    from . import (aliyun, brevo, mailgun, resend, sendgrid, sendmail,  # noqa
                   smtp, webhook)
    _ = (aliyun, brevo, mailgun, resend, sendgrid, sendmail, smtp, webhook)
