"""Check framework.

The previous generation of this code keyed everything -- state, cooldown,
knowledge base lookups, the maintenance skip list -- off the *human* check
name, which was Chinese prose. Renaming a check silently orphaned its
baseline and re-alerted; translating it was impossible. So the contract
here is deliberate:

* ``id``    stable ASCII identifier. State, config and knowledge are keyed
            off this. It never changes once released.
* ``label`` human text, translated at render time.

A check is a class with a declarative header and a single :meth:`run`. The
registry collects them by import order, and ``ctx.state`` is the mutable
cross-run dictionary the runner persists, so a check that needs memory just
writes to it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# -- statuses ---------------------------------------------------------------
OK = "OK"
WARN = "WARN"
CRIT = "CRIT"
#: A one-shot additive event (a file changed, a port appeared). It alerts but
#: never produces a recovery mail, because there is nothing to recover to.
EVENT = "EVENT"

STATUSES = (OK, WARN, CRIT, EVENT)
PROBLEM_STATUSES = (WARN, CRIT)

# -- groups (drive ordering and the maintenance skip list) ------------------
G_RESOURCE = "resource"
G_PROCESS = "process"
G_INTEGRITY = "integrity"
G_SECURITY = "security"
G_NETWORK = "network"
G_SERVICES = "services"
G_MALWARE = "malware"
G_OPS = "ops"

GROUP_ORDER = (G_RESOURCE, G_PROCESS, G_INTEGRITY, G_SECURITY, G_NETWORK,
               G_SERVICES, G_MALWARE, G_OPS)

GROUP_LABEL = {
    G_RESOURCE: ("资源压力", "Resources"),
    G_PROCESS: ("进程与业务", "Processes & service"),
    G_INTEGRITY: ("完整性与变更", "Integrity & change"),
    G_SECURITY: ("系统安全", "System security"),
    G_NETWORK: ("网络", "Network"),
    G_SERVICES: ("服务与运维", "Services & operations"),
    G_MALWARE: ("恶意软件", "Malware"),
    G_OPS: ("运维保障", "Operational hygiene"),
}

#: Checks silenced while /run/vigil-maintenance exists. Deliberately
#: resource-only: maintenance should not blind you to a compromise.
MAINTENANCE_SILENCED = frozenset({
    "cpu", "memory", "swap", "disk_io", "process_anomaly", "site_availability",
})


@dataclass
class CheckResult:
    status: str = OK
    detail: str = ""
    #: Optional structured extras, e.g. {"paths": [...]} for the renderer.
    extra: dict = field(default_factory=dict)

    def is_problem(self) -> bool:
        return self.status in PROBLEM_STATUSES


class CheckContext:
    """Everything a check may need, resolved once per run.

    Built by the runner so checks never reach for globals. ``state`` is the
    live dictionary that will be persisted, so a stateful check mutates it
    in place.
    """

    def __init__(self, cfg, state: dict, env: dict, log, now: float,
                 notify=None):
        self.cfg = cfg
        self.state = state
        self.env = env or {}
        self.log = log
        self.now = now
        self._notify = notify

    # -- convenience ------------------------------------------------------
    def opt(self, dotted: str, default: Any = None) -> Any:
        return self.cfg.get("checks.%s" % dotted, default)

    def copt(self, group: str, key: str, default: Any = None) -> Any:
        """Read ``checks.<group>.<key>`` with a default."""
        return self.cfg.get("checks.%s.%s" % (group, key), default)

    @property
    def hostname(self) -> str:
        return self.cfg.get("hostname", "")

    @property
    def maintenance(self) -> bool:
        import os
        return os.path.exists("/run/vigil-maintenance")

    def notify(self, subject: str, body: str) -> bool:
        """Rarely needed: most checks return a result and let the runner
        batch. Exposed for checks that must escalate immediately."""
        if self._notify is None:
            return False
        return bool(self._notify(subject, body))

    # -- state helpers ----------------------------------------------------
    def snapshot(self, key: str, value: Any) -> Any:
        """Store *value* under *key* and return the previous value.

        The one-liner that makes stateful checks readable:

            prev = ctx.snapshot("ports", current)
            if prev is None:
                return CheckResult(OK, "baseline established")
        """
        prev = self.state.get(key)
        self.state[key] = value
        return prev

    def versioned(self, key: str, version: int, value: Any):
        """Snapshot with a format version, resetting when it changes.

        Without this a state-format change silently mis-compares old and new
        values -- which is how the previous implementation ended up with a
        legacy key lingering in its state file for months.
        """
        vkey = key + "_v"
        if self.state.get(vkey) != version:
            self.state[vkey] = version
            self.state[key] = value
            return None
        return self.snapshot(key, value)


class Check:
    """Base class. Subclasses set the header and implement :meth:`run`."""

    id: str = ""
    label: str = ""
    label_en: str = ""
    group: str = G_SECURITY
    #: True when the check reads or writes ctx.state across runs.
    stateful: bool = False
    #: True when the check is expensive; the runner may skip it on a fast pass.
    heavy: bool = False
    #: False to omit from the default set (still runnable by id).
    enabled_by_default: bool = True
    #: One line explaining what it looks for, shown by `vigil checks list`.
    description: str = ""

    def __init__(self, cfg=None):
        self.cfg = cfg

    # -- interface --------------------------------------------------------
    def run(self, ctx: CheckContext) -> CheckResult:
        raise NotImplementedError

    # -- helpers ----------------------------------------------------------
    def label_for(self, lang: str = "zh") -> str:
        return self.label if lang != "en" else (self.label_en or self.label)

    @classmethod
    def group_label(cls, lang: str = "zh") -> str:
        """Human name for this check's group.

        A classmethod because it is called on the *class* as often as on an
        instance -- the registry stores classes, and `vigil health list` used
        `items[0].group_label()` on one of them, which raised
        "missing 1 required positional argument: 'self'" and took the whole
        listing down.
        """
        pair = GROUP_LABEL.get(cls.group, (cls.group, cls.group))
        return pair[0] if lang != "en" else pair[1]

    # -- safety net -------------------------------------------------------
    def safe_run(self, ctx: CheckContext) -> CheckResult:
        """Run, converting any exception into a WARN.

        A crashing check must degrade to a visible warning, never take the
        whole inspection round down -- otherwise one bug blinds you to
        everything else.
        """
        try:
            res = self.run(ctx)
        except Exception as e:                       # noqa: BLE001
            return CheckResult(WARN, "检查执行异常 (%s: %s)"
                               % (type(e).__name__, e))
        if not isinstance(res, CheckResult):
            return CheckResult(WARN, "检查返回了非法结果: %r" % (res,))
        if res.status not in STATUSES:
            return CheckResult(WARN, "检查返回了未知状态: %r" % (res.status,))
        return res


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

_REGISTRY: list = []
_BY_ID: dict = {}


def register(cls):
    """Class decorator adding a check to the registry."""
    if not cls.id:
        raise ValueError("check %r has no id" % cls)
    if cls.id in _BY_ID:
        raise ValueError("duplicate check id %r" % cls.id)
    _REGISTRY.append(cls)
    _BY_ID[cls.id] = cls
    return cls


def all_checks() -> list:
    return list(_REGISTRY)


def get(check_id: str):
    return _BY_ID.get(check_id)


def ids() -> list:
    return [c.id for c in _REGISTRY]


def by_group() -> dict:
    out: dict = {}
    for c in _REGISTRY:
        out.setdefault(c.group, []).append(c)
    return out


def load_all() -> None:
    """Import every check module so the decorators run.

    Explicit imports, not a directory scan: a scan hides syntax errors
    until the worst possible moment and makes the check set depend on
    filesystem ordering.
    """
    from . import (exposure, integrity, malware, network, ops,  # noqa: F401
                   process, resource, security, selfcheck)
    _ = (exposure, integrity, malware, network, ops, process, resource,
         security, selfcheck)
