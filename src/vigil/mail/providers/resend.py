"""Resend (https://resend.com) -- HTTPS API delivery.

Chosen as the reference API provider because it is the cheapest reliable
way to send *from your own domain* without operating an MTA, which matters
a lot on hosts where the provider blocks outbound port 25.

Two facts drive the implementation:

* **Billing is per recipient, not per request.** Putting five addresses in
  ``to`` costs five emails. So we send one request per recipient; a single
  call covering everybody would silently burn quota five times faster.
* **The From address must live on a domain verified in Resend.** A From on
  an unverified domain is rejected, so :meth:`Resend.check_domain` and the
  ``vigil mail domain`` command exist to make that failure obvious *before*
  the first real alert needs to go out.

``onboarding@resend.dev`` is Resend's sandbox sender: it only delivers to
the account owner's own address. We surface that explicitly rather than
letting someone configure it and wonder why alerts vanish.
"""
from __future__ import annotations

from ...core.errors import AuthError, ProviderError
from ..message import Message
from .base import EMAIL, PASSWORD, TEXT, Field, Provider, register

API_BASE = "https://api.resend.com"
SANDBOX_FROM = "onboarding@resend.dev"


@register
class Resend(Provider):
    id = "resend"
    label = "Resend（HTTPS API，支持自有域名）"
    label_en = "Resend (HTTPS API, custom domain)"
    kind = "api"
    blurb = "推荐。不依赖本机发信能力，无出口 25 端口也能用；需在 Resend 验证域名。"
    blurb_en = ("Recommended. Needs no local MTA and works when outbound port 25 "
                "is blocked; requires a domain verified in Resend.")
    docs_url = "https://resend.com/docs"
    #: 1 quota unit per recipient -- see the module docstring.
    quota_per_recipient = 1

    fields = (
        Field("api_key", "API 密钥", "API key", kind=PASSWORD, secret=True,
              example="re_xxxxxxxx_xxxxxxxxxxxx",
              hint="登录 Resend → API Keys → Create API Key，权限选 Sending access。"
                   "以 re_ 开头。",
              hint_en="Resend dashboard -> API Keys -> Create API Key "
                      "(Sending access). Starts with re_."),
        Field("from_address", "发件地址", "From address", kind=EMAIL,
              example="alerts@mail.example.com",
              hint="必须属于在 Resend 已验证的域名。可先留空，"
                   "运行 `vigil mail domain` 验证域名后再填。",
              hint_en="Must belong to a domain verified in Resend."),
        Field("from_name", "发件人显示名", "Display name", required=False,
              default="Server Monitor"),
        Field("reply_to", "回复地址", "Reply-To", kind=EMAIL, required=False,
              hint="建议填管理员邮箱，这样直接回复告警即可（若启用了命令通道）。",
              hint_en="Set this to the admin mailbox so replies reach you."),
    )

    # -- sending ---------------------------------------------------------
    def send(self, msg: Message, to: str) -> str:
        key = self.p("api_key")
        if not key:
            raise AuthError("resend: api_key is not configured")

        frm = self.p("from_address") or msg.from_address
        if not frm:
            raise ProviderError("resend: from_address is not configured")
        name = self.p("from_name") or msg.from_name
        from_hdr = "%s <%s>" % (name, frm) if name else frm

        reply_to = self.p("reply_to") or msg.reply_to
        payload = {
            "from": from_hdr,
            "to": [to],                      # one recipient per call, by design
            "subject": msg.subject,
            "text": msg.text,
            # The reply-command channel polls the mailbox it posts to. Resend
            # builds the MIME message itself, so the marker has to travel as
            # an API field; without it the loop guard falls back to matching
            # our own text (which works, but only because the body format is
            # stable). Belt and braces: send both.
            "headers": {
                "X-Vigil-Machine": "1",
                "Auto-Submitted": "auto-generated",
            },
        }
        if msg.html and msg.html.strip():
            payload["html"] = msg.html
        if reply_to:
            # Resend accepts a string here. The old shell implementation
            # disagreed with its own helper script (string vs list); we pick
            # the string form and stay consistent.
            payload["reply_to"] = reply_to

        status, _hdrs, body = self._http_json(
            "%s/emails" % API_BASE, payload,
            headers={"Authorization": "Bearer %s" % key},
        )
        if status not in (200, 201):
            raise ProviderError("resend: unexpected HTTP %s" % status)
        if isinstance(body, dict):
            if body.get("id"):
                return str(body["id"])
            if body.get("message"):
                # Resend reports validation problems with HTTP 200 + message
                raise ProviderError("resend: %s" % body["message"])
        return "resend-ok"

    # -- health ----------------------------------------------------------
    def health(self):
        problems = self.validate()
        if problems:
            return False, "; ".join(problems)
        try:
            ok, detail = self.check_domain()
        except AuthError:
            # Resend keys can be scoped to *sending* only, and such a key is
            # refused by the management endpoints this probe reads. That is a
            # permission boundary, not a bad credential: the channel sends
            # perfectly well. Reporting it as a failure made a working mail
            # path look broken in `vigil mail status` and sent the operator
            # off to regenerate a key that was never the problem.
            return True, ("密钥为发送专用权限，读不到域名状态；"
                          "实际发信不受影响")
        except ProviderError as e:
            return False, e.render()
        if not ok:
            return False, detail
        if self.p("from_address").lower() == SANDBOX_FROM:
            return True, ("sandbox sender in use; delivers only to the account "
                          "owner's own address")
        return True, detail

    # -- domain provisioning --------------------------------------------
    def is_configured(self) -> bool:
        return bool(self.p("api_key"))

    # -- DNS, reachable as methods so the command layer can treat every
    #    provider the same way ------------------------------------------
    def audit_dns(self, domain: str = "") -> dict:
        return audit_dns(domain or self.domain_of_from())

    def suggested_records(self, domain: str = "") -> list:
        return suggested_records(domain or self.domain_of_from())

    def domain_of_from(self) -> str:
        frm = self.p("from_address")
        return frm.split("@", 1)[1].lower() if "@" in frm else ""

    def list_domains(self) -> list:
        """Return Resend's domains with their verification status."""
        key = self.p("api_key")
        if not key:
            raise AuthError("resend: api_key is not configured")
        _s, _h, body = self._http_json(
            "%s/domains" % API_BASE, None, method="GET",
            headers={"Authorization": "Bearer %s" % key},
        )
        if isinstance(body, dict):
            return body.get("data", []) or []
        return []

    def get_domain(self, domain: str) -> dict:
        for d in self.list_domains():
            if str(d.get("name", "")).lower() == domain.lower():
                return d
        return {}

    def create_domain(self, domain: str) -> dict:
        key = self.p("api_key")
        _s, _h, body = self._http_json(
            "%s/domains" % API_BASE, {"name": domain},
            headers={"Authorization": "Bearer %s" % key},
        )
        return body if isinstance(body, dict) else {}

    def verify_domain(self, domain_id: str) -> dict:
        key = self.p("api_key")
        _s, _h, body = self._http_json(
            "%s/domains/%s/verify" % (API_BASE, domain_id), {},
            headers={"Authorization": "Bearer %s" % key},
        )
        return body if isinstance(body, dict) else {}

    def check_domain(self) -> tuple:
        """Is the From domain present and verified?

        Returns (ok, message). Used by `vigil mail test` and `vigil doctor`
        so a misconfiguration is reported in plain language instead of as a
        provider error code at 3am.
        """
        dom = self.domain_of_from()
        if not dom:
            return False, "from_address is not set, so no sending domain is known"
        if dom.endswith("resend.dev"):
            return True, "using Resend's sandbox domain"
        try:
            found = self.get_domain(dom)
        except AuthError:
            # Resend keys can be scoped to *sending* only, and the management
            # endpoints this reads are closed to such a key. That is a
            # permission boundary, not a bad credential -- the channel sends
            # perfectly well. Reporting it as a failure made a working mail
            # path look broken in `vigil mail status` and sent the operator
            # off to regenerate a key that was never the problem.
            return True, ("密钥为发送专用权限，读不到域名状态；"
                          "实际发信不受影响")
        except ProviderError as e:
            return False, "cannot query Resend: %s" % e.message
        if not found:
            return False, ("domain %s is not registered in this Resend account"
                           % dom)
        status = str(found.get("status", "")).lower()
        if status != "verified":
            return False, ("domain %s status is %r (DNS records not applied yet "
                           "or not propagated)" % (dom, status))
        return True, "domain %s verified" % dom

    def dns_records(self) -> list:
        """The DNS records Resend wants for this domain.

        Returned as ``[{type, name, value, ttl, priority, record}]`` so both
        the CLI and the docs renderer can consume them unchanged.
        """
        dom = self.domain_of_from()
        if not dom:
            return []
        info = self.get_domain(dom)
        return list(info.get("records") or [])


# --------------------------------------------------------------------------
# DNS verification
# --------------------------------------------------------------------------

def _dig(name: str, rtype: str) -> list:
    """Query a record type, using whichever resolver tool the host has.

    Shelling out rather than speaking DNS in-process: the project has no
    third-party dependencies, and a resolver is the one thing every Linux
    host already has. When none is present the caller reports "unknown"
    rather than pretending the record is missing.
    """
    import subprocess
    for tool in (["dig", "+short", rtype, name, "@8.8.8.8"],
                 ["dig", "+short", rtype, name],
                 ["nslookup", "-type=%s" % rtype, name]):
        try:
            proc = subprocess.run(tool, capture_output=True, text=True,
                                  timeout=12)
        except (OSError, subprocess.SubprocessError):
            continue
        out = (proc.stdout or "").strip()
        if proc.returncode == 0:
            return [ln.strip().strip('"') for ln in out.splitlines() if ln.strip()]
    return []


def audit_dns(domain: str) -> dict:
    """Check the records that decide whether mail lands in the inbox.

    Deliberately independent of the Resend API. A sending-scoped key cannot
    read the domain endpoints, and "I can't ask the API" must not become
    "everything is fine" -- the DNS answer is the one that actually decides
    whether a message is filtered, and it is readable from anywhere.
    """
    result = {"domain": domain, "spf": [], "dkim": [], "dmarc": [],
              "mx": [], "problems": [], "unknown": False}

    def txt(name):
        return [t for t in _dig(name, "TXT") if t and not t.startswith(";")]

    all_txt = txt(domain)
    result["spf"] = [t for t in all_txt if t.lower().startswith("v=spf1")]

    dkim_name = "resend._domainkey." + domain
    result["dkim"] = [t for t in txt(dkim_name) if "p=" in t]

    dmarc = [t for t in txt("_dmarc." + domain) if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        # A DMARC record on the organisational domain covers subdomains that
        # publish none of their own, so an empty subdomain record is not
        # automatically a problem.
        parts = domain.split(".", 1)
        if len(parts) == 2:
            dmarc = [t for t in txt("_dmarc." + parts[1])
                     if t.lower().startswith("v=dmarc1")]
            if dmarc:
                dmarc = ["%s（继承自 %s）" % (dmarc[0], parts[1])]
    result["dmarc"] = dmarc

    result["mx"] = _dig(domain, "MX")

    if not result["spf"]:
        result["problems"].append(
            "缺少 SPF 记录：收件方没有「这台服务器有权代发」的授权依据，"
            "Outlook / QQ 会直接判为垃圾邮件或拒收")
    if not result["dkim"]:
        result["problems"].append("缺少 DKIM 记录：邮件没有密码学签名")
    if not result["dmarc"]:
        result["problems"].append(
            "缺少 DMARC 记录：收件方拿不到你的处理策略，通常会从严处理")
    if not result["mx"] and not result["spf"] and not result["dkim"]:
        result["unknown"] = True
    return result


def suggested_records(domain: str) -> list:
    """The records to publish, in the shape a DNS panel wants them."""
    return [
        ("TXT", domain, "v=spf1 include:amazonses.com ~all",
         "SPF：授权 Resend（Amazon SES）代发"),
        ("TXT", "_dmarc." + domain, "v=DMARC1; p=none; rua=mailto:postmaster@"
         + domain.split(".", 1)[-1],
         "DMARC：先只观察（p=none），确认没问题再收紧到 quarantine"),
    ]
