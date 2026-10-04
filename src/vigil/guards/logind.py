"""Login notification.

Watching for successful logins is not about catching the break-in -- by then
it has already happened. It is about **noticing** it: an alert saying "your
panel was accessed from an address you have never used, at 03:12" is often
the first and only signal that something is wrong.

Three sources are supported, each discovered rather than assumed:

``panel``
    A control panel's own login log. For BT/aaPanel that is a SQLite table;
    we read it read-only and only ever move forward by row id, so a restart
    never replays history.

``gate``
    The audit log written by our login gate: a TSV file we tail by inode and
    byte offset, so log rotation is handled without missing or duplicating
    entries.

``ssh``
    Successful SSH logins from the system auth log.

Adoption matters here: when this replaces an earlier installation it must
continue from the previous reader's offsets. Replaying the whole log would
send the operator a flood of historical logins, which trains them to ignore
the alerts.
"""
from __future__ import annotations

from pathlib import Path

import ipaddress
import os
import re
import sqlite3
import time
from datetime import datetime

from ..core import paths
from ..core.config import load as load_config
from ..core.logging import get as get_logger
from ..core.state import locked, read_json, write_json
from ..mail import send_alert
from ..mail.message import SEV_INFO, SEV_WARN, Alert
from .checks.util import geo, oneline

#: Genuinely non-routable space. See `_is_expected` for why this is spelled
#: out instead of using the much broader `ipaddress.is_private`.
_INTERNAL_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
    "fc00::/7", "fe80::/10"))

STATE = paths.LOGIN_STATE
LOCK = paths.RUN / "vigil-logind.lock"

RE_SSH_ACCEPT = re.compile(
    r"Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)")
RE_TTY_LOGIN = re.compile(r"\b(su|sudo):.*session opened for user (\S+)")

#: Panel log databases, in the order we probe them.
PANEL_DBS = (
    "/www/server/panel/data/db/log.db",
    "/www/server/panel/data/default.db",
)


def _log():
    return get_logger("login")


def _lang(cfg) -> str:
    from ..i18n import language
    return cfg.get("mail.language", "") or language()


# --------------------------------------------------------------------------
# Panel source
# --------------------------------------------------------------------------


def _panel_db(cfg) -> str:
    configured = cfg.get("gate.bt_panel.panel_db", "")
    if configured and os.path.isfile(configured):
        return configured
    for p in PANEL_DBS:
        if os.path.isfile(p):
            return p
    return ""


def read_panel_logins(cfg, state: dict) -> list:
    """New successful panel logins since the last row id."""
    db = _panel_db(cfg)
    if not db:
        return []
    last = int(state.get("panel_last_id", 0) or 0)
    events = []
    try:
        # Read-only URI so we can never corrupt the panel's database.
        conn = sqlite3.connect("file:%s?mode=ro" % db, uri=True, timeout=5)
        try:
            cur = conn.cursor()
            if not last:
                cur.execute("SELECT IFNULL(MAX(id),0) FROM logs")
                state["panel_last_id"] = int(cur.fetchone()[0] or 0)
                return []
            cur.execute(
                "SELECT id, log, addtime FROM logs "
                "WHERE id > ? AND type = '用户登录' AND log LIKE '登录成功%' "
                "ORDER BY id", (last,))
            rows = cur.fetchall()
        finally:
            conn.close()
    except (sqlite3.Error, OSError) as e:
        _log().warn("读取面板登录日志失败: %s" % e)
        return []

    for rid, text, addtime in rows:
        state["panel_last_id"] = max(int(state.get("panel_last_id", 0)), int(rid))
        events.append({
            "source": "panel",
            "account": _grab(text, r"帐号[:：]\s*([^,\s]+)") or "?",
            "ip": _bare_ip(_grab(text, r"登录IP[:：]\s*([0-9a-fA-F:.]+)")),
            "when": addtime or "",
            "raw": oneline(text, 200),
        })
    return events


def _grab(text: str, pattern: str) -> str:
    m = re.search(pattern, str(text or ""))
    return m.group(1) if m else ""


def _bare_ip(value: str) -> str:
    """Strip a port, brackets and trailing annotation from an address.

    The control panel logs ``登录IP:198.51.100.77:12345>归属地：…``. The
    naive capture kept the port, and an address with a port is not an
    address: the geo lookup could not resolve it, the whitelist comparison
    never matched, and the alert therefore reported every panel login as
    coming from "unknown" and "not in your whitelist" -- which reads exactly
    like the feature is missing.
    """
    addr = str(value or "").strip()
    if not addr:
        return ""
    # Drop any trailing annotation the panel appends.
    for sep in (">", " ", "，", ","):
        if sep in addr:
            addr = addr.split(sep, 1)[0]
    if addr.startswith("["):                 # [::1]:port
        end = addr.find("]")
        if end != -1:
            return addr[1:end]
    if addr.count(":") == 1:                 # ipv4:port
        host, _, port = addr.partition(":")
        if port.isdigit():
            return host
    return addr


# --------------------------------------------------------------------------
# Gate source
# --------------------------------------------------------------------------


#: What each gate kind actually is. The alert leads with this, because
#: "管理界面登录" on a host with two gates is an unanswerable statement --
#: the reader's first question is always *which* one.
GATE_APP = {
    "bt_panel": "宝塔面板",
    "login": "独立登录页",
}

#: Config key -> gate kind. The two names differ because the login gate was
#: written for one application before this project generalised. Kept as the
#: seed for :func:`gate_config_keys`, which adds the named instances.
GATE_KEY_KIND = {"dsh_gate": "login", "bt_panel": "bt_panel"}

#: Instance name shown for the two original config keys.
GATE_KEY_NAME = {"dsh_gate": "login", "bt_panel": "bt_panel"}


def gate_config_keys(cfg) -> list:
    """``[(config_key, kind, name)]`` for every configured gate instance.

    The two original keys are always present; named login instances are
    discovered from their own ``gate.<name>`` section, which is the
    instance's identity. Reading only the fixed map made every named
    instance's logins invisible to the alert reader.
    """
    out = [(key, kind, GATE_KEY_NAME.get(key, key))
           for key, kind in GATE_KEY_KIND.items()]
    gate_cfg = cfg.get("gate") if cfg is not None else None
    if isinstance(gate_cfg, dict):
        for key in sorted(gate_cfg):
            if key in GATE_KEY_KIND or key == "demo":
                continue
            if not isinstance(gate_cfg[key], dict):
                continue
            out.append((key, "login", key))
    return out


def _gate_app_label(state_dir: str, kind: str, name: str = "") -> str:
    """What this gate actually protects, as a person would name it.

    Taken from the gate's own generated config where possible: a gate knows
    its own title, and an operator who renamed it should see their name in
    the alert rather than a generic category. The kind is only a fallback.
    """
    app = GATE_APP.get(kind, kind or "网关")
    if name and name != kind:
        # Two login gates on one host produce two identical category names;
        # the instance name is what tells them apart in the inbox.
        app = "%s［%s］" % (app, name)
    cfg_path = os.path.join(state_dir, "config.php")
    if os.path.isfile(cfg_path):
        try:
            from ..gates import parse_php_config
            info = parse_php_config(Path(cfg_path))
            title = (info.get("title") or "").strip()
            upstream = (info.get("upstream")
                        or info.get("upstream_mint_url") or "").strip()
            # The application name leads; the gate's own page title and the
            # upstream it protects are the detail that removes the remaining
            # ambiguity -- "独立登录页 -> 127.0.0.1:<port>" identifies which
            # projection was reached in a way the category alone cannot.
            detail = []
            if title:
                detail.append(title)
            if upstream:
                # The port is the identifying part; the scheme and path are
                # noise in a one-line label.
                import re as _re
                m = _re.search(r":(\d+)", upstream)
                detail.append("→ 本机 %s" % (m.group(1) if m else upstream))
            if detail:
                return "%s（%s）" % (app, " · ".join(detail))
        except Exception as exc:                       # noqa: BLE001
            # Not silent. A swallowed NameError here made the label fall back
            # to a generic name and nobody could tell why -- the alert looked
            # fine, it was just wrong.
            import logging as _logging
            _logging.getLogger("vigil.logind").debug(
                "读取网关标题失败（%s），使用回退名", exc)
    return app


def gate_log_sources(cfg) -> list:
    """``[(path, app_label, kind)]`` for every gate audit log.

    The label matters: an alert that says "管理界面登录" without saying
    *which* management interface leaves the reader to guess, and on a host
    with two gates the guess is wrong half the time. The path alone cannot
    answer it, so the pairing is resolved here and carried through to the
    message.
    """
    out = []
    seen = set()
    for key, kind, name in gate_config_keys(cfg):
        path = str(cfg.get("gate.%s.auth_log" % key, "") or "")
        if not path or path in seen:
            continue
        state_dir = str(cfg.get("gate.%s.state_dir" % key, "") or "")
        if not state_dir:
            base = path.rsplit("/logs/", 1)[0]
            if base and base != path:
                state_dir = base
        seen.add(path)
        out.append((path, _gate_app_label(state_dir, kind, name), kind))
    # Always look at the live installations too. A gate can be installed and
    # working before anything writes its `auth_log` into the config (that
    # happens on adopt/sync), and it must not stay invisible just because
    # some *other* gate was configured first.
    try:
        from ..gates import detect_all
        for spec in detect_all():
            state_dir = getattr(spec, "state_dir", "") or ""
            if not state_dir:
                continue
            candidate = os.path.join(state_dir, "logs", "auth.log")
            if not os.path.isfile(candidate) or candidate in seen:
                continue
            seen.add(candidate)
            out.append((candidate,
                        _gate_app_label(state_dir, spec.kind, spec.name),
                        spec.kind))
    except Exception:
        # A gate that cannot be inspected must not stop SSH login alerts.
        pass
    return out


def gate_auth_logs(cfg) -> list:
    """Just the paths -- see :func:`gate_log_sources` for the labels."""
    return [path for path, _label, _kind in gate_log_sources(cfg)]


def read_gate_logins(cfg, state: dict) -> list:
    """New successful gate logins, tailed per file by inode + offset.

    Each log keeps its own cursor: two gates means two files, and a single
    shared offset would make them consume each other's positions.
    """
    events = []
    for auth_log, app, _kind in gate_log_sources(cfg):
        for event in _read_one_gate_log(auth_log, state):
            event["app"] = app
            events.append(event)
    return events


def _read_one_gate_log(auth_log: str, state: dict) -> list:
    if not auth_log or not os.path.isfile(auth_log):
        return []
    try:
        st = os.stat(auth_log)
    except OSError:
        return []

    # Always keyed by path. Two gates means two files, and a single shared
    # cursor made each one read from the other's byte offset -- which is how
    # a baseline pass reported sixty old logins as brand new.
    suffix = re.sub(r"\W", "_", auth_log)
    k_ino = "gate_ino_" + suffix
    k_off = "gate_off_" + suffix
    last_ino = state.get(k_ino)
    last_off = int(state.get(k_off, 0) or 0)
    if last_ino is None:
        # First run: baseline without reporting, so a fresh install does not
        # mail the operator a history lesson.
        state[k_ino] = st.st_ino
        state[k_off] = st.st_size
        return []
    if last_ino != st.st_ino or st.st_size < last_off:
        # Rotated or truncated: read the new file from the start.
        last_off = 0
    if st.st_size == last_off:
        state[k_ino] = st.st_ino
        return []

    events = []
    try:
        with open(auth_log, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(last_off)
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 4 or parts[1] != "OK":
                    continue
                events.append({
                    "source": "gate",
                    "account": "",
                    "ip": parts[2],
                    "when": parts[0],
                    "user_agent": parts[3],
                    "raw": oneline(line, 200),
                })
            last_off = fh.tell()
    except OSError:
        return []
    state[k_ino] = st.st_ino
    state[k_off] = last_off
    return events


# --------------------------------------------------------------------------
# SSH source
# --------------------------------------------------------------------------


def read_ssh_logins(cfg, state: dict) -> list:
    sources = cfg.get("threat.log_sources.auth", []) or []
    if not sources:
        return []
    events = []
    for path in sources[:3]:
        if not os.path.isfile(path):
            continue
        key = "ssh_off_%s" % re.sub(r"\W", "_", path)
        try:
            st = os.stat(path)
        except OSError:
            continue
        last_ino = state.get(key + "_ino")
        last_off = int(state.get(key, 0) or 0)
        if last_ino is None:
            state[key + "_ino"] = st.st_ino
            state[key] = st.st_size
            continue
        if last_ino != st.st_ino or st.st_size < last_off:
            last_off = 0
        if st.st_size <= last_off:
            state[key + "_ino"] = st.st_ino
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(last_off)
                for line in fh:
                    m = RE_SSH_ACCEPT.search(line)
                    if not m:
                        continue
                    method, user, ip, _port = m.groups()
                    events.append({
                        "source": "ssh",
                        "account": user,
                        "method": method,
                        "ip": ip,
                        "when": line[:15].strip(),
                        "raw": oneline(line, 200),
                    })
                last_off = fh.tell()
        except OSError:
            continue
        state[key + "_ino"] = st.st_ino
        state[key] = last_off
    return events


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

SOURCE_LABEL = {
    "panel": ("面板登录", "Panel login"),
    "gate": ("管理界面登录", "Admin UI login"),
    "ssh": ("SSH 登录", "SSH login"),
}


def run_once(cfg=None, log=None) -> dict:
    cfg = cfg or load_config()
    log = log or _log()
    started = time.time()

    with locked(LOCK, timeout=0.0) as got:
        if not got:
            return {"skipped": "已有实例在运行"}
        state = read_json(STATE, {}) or {}
        first_run = not state

        events = []
        events += read_panel_logins(cfg, state)
        events += read_gate_logins(cfg, state)
        events += read_ssh_logins(cfg, state)

        state["last_run"] = started
        paths.STATE_STATE.mkdir(parents=True, exist_ok=True)
        write_json(STATE, state, mode=0o640)

    if first_run:
        log.info("首次运行：已建立位置基线，不发送历史登录通知")
        return {"first_run": True, "events": 0}
    if not events:
        log.info("没有新的登录事件")
        return {"events": 0}

    # Enrich with geo information; this is the part that makes the alert
    # useful ("an address you have never used" is only visible with it).
    for e in events:
        e["geo"] = geo(cfg, e.get("ip", ""))

    _notify(cfg, events, log)
    log.warn("检测到 %d 次成功登录" % len(events))
    return {"events": len(events), "items": events,
            "elapsed": round(time.time() - started, 3)}


def _notify(cfg, events: list, log) -> None:
    if not cfg.get("gate.login_alerts", True):
        log.info("登录通知已关闭")
        return
    recipients = cfg.recipients("login")
    if not recipients:
        log.warn("未配置登录通知收件人，跳过")
        return

    n = len(events)
    offline = [e for e in events if not _is_expected(cfg, e.get("ip", ""))]

    # Which logins are worth an email?
    #
    #   panel  (default) -- a successful login to the panel or to a login
    #       gateway is always worth knowing, even from your own address:
    #       those are the two doors that lead to everything else, they are
    #       reached from the public internet, and "was that me?" is a
    #       question you want to be asked. SSH is different -- it is already
    #       key-only and rate-limited, and every session you open would
    #       generate mail, so it only reports from addresses you never
    #       whitelisted.
    #   offwhitelist -- the quieter policy: only unexpected addresses.
    #   all -- everything, including your own SSH sessions.
    notify_mode = str(cfg.get("gate.login_notify", "panel") or "panel").lower()
    console = [e for e in events if e.get("source") in ("panel", "gate")]
    if notify_mode == "offwhitelist":
        loud = [e for e in events if not _is_expected(cfg, e.get("ip", ""))]
    elif notify_mode == "all":
        loud = list(events)
    else:
        loud = console + [e for e in events
                          if e not in console
                          and not _is_expected(cfg, e.get("ip", ""))]

    if not loud:
        for e in events:
            log.info("登录来自已白名单地址 %s（%s），按 gate.login_notify=%s 不发信"
                     % (e.get("ip") or "?", e.get("app") or e.get("source") or "?",
                        notify_mode))
        return

    n = len(loud)
    offline = [e for e in loud if not _is_expected(cfg, e.get("ip", ""))]
    title = "登录成功 %d 次" % n
    if offline:
        title = "登录成功 %d 次（%d 次来自非白名单地址）" % (n, len(offline))
    elif console and n == len(console):
        title = "管理界面登录成功 %d 次" % n

    alert = Alert(title=title,
                  severity=SEV_WARN if offline else SEV_INFO, kind="login",
                  summary="管理员/管理界面被登录，请确认是你本人。")
    sec = alert.add_section("登录明细")
    for e in loud:
        label = SOURCE_LABEL.get(e["source"], (e["source"],))[0]
        # Name the protected application, not just the category. "管理界面
        # 登录" with two gates configured tells the reader nothing.
        if e.get("app"):
            label = "%s · %s" % (label, e["app"])
        head = "【%s】%s" % (label, e.get("when") or "")
        if e.get("account"):
            head += "  账号: %s" % e["account"]
        sec.add(head)
        sec.add("    来源: %s" % (e.get("geo") or e.get("ip") or "未知"))
        if e.get("method"):
            sec.add("    方式: %s" % e["method"])
        if e.get("user_agent"):
            sec.add("    客户端: %s" % oneline(e["user_agent"], 90))
        if not _is_expected(cfg, e.get("ip", "")):
            sec.add("    ⚠ 该地址不在你的白名单中")
        sec.add("")

    sec.add("如果不是你本人登录：立即修改面板与 SSH 密码，"
            "检查是否被加入了 SSH 公钥或新增了账号，"
            "并运行 `vigil health run` 做一次全面检查。")

    rep = send_alert(alert, cfg, log, recipients=recipients, allow_dedupe=False)
    log.info("登录通知已发送：%s" % rep.summary())


def _is_expected(cfg, ip: str) -> bool:
    """Is this a known-good address (the host itself, or the whitelist)?

    "The host itself" is written out as an explicit list of internal
    networks rather than ``addr.is_private``. Python's ``is_private`` is much
    broader than the name suggests: it is *also* true for 198.51.100.0/24,
    203.0.113.0/24 (both RFC 5737 documentation ranges) and 192.0.0.0/24, so
    the old test quietly blessed addresses that only look internal. On a
    public host the source of an inbound connection is a public address;
    anything genuinely non-routable is the machine talking to itself.
    """
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback:
        return True
    for net in _INTERNAL_NETS:
        if addr.version == net.version and addr in net:
            return True
    for entry in cfg.get("threat.whitelist", []) or []:
        try:
            if "/" in str(entry):
                if addr in ipaddress.ip_network(str(entry), strict=False):
                    return True
            elif addr == ipaddress.ip_address(str(entry)):
                return True
        except ValueError:
            continue
    return False


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="vigil-logind",
                                description="Check for new successful logins.")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    result = run_once()
    if args.json:
        import json
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
