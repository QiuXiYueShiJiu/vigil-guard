"""Host-wide web-layer shield.

The login gate protects the *admin* surface. This protects everything else:
it rejects the tools that spend their lives looking for something to exploit,
and it caps how much of the machine one address can consume.

It is one nginx ``http{}``-scope snippet, generated the same way the gate's
zone files are, and it exists because of a migration that had to be done
carefully rather than quickly.

**Why the identifiers are kept, not renamed.** An earlier generation of this
project wrote the same maps and zones under ``dsh_*`` names, and the live
vhosts on this host still reference them directly::

    if ($dsh_bad_agent) { return 403; }
    limit_req  zone=dsh_site_req burst=60 nodelay;
    limit_conn dsh_site_conn 40;

Deleting that file would therefore have taken every one of those sites down
with ``unknown "dsh_bad_agent" variable`` -- nginx refuses to load at all, so
the failure is not a missing protection but a dead web server. Renaming would
have meant editing every site configuration, which is a far riskier change
for no benefit a user can see. So the definitions move into a file this
project owns, and the names stay.

Everything here is idempotent and verified before it is applied: the new
snippet is written first, ``nginx -t`` decides whether it is kept, and the old
file is only retired once the replacement is proven to load.

**The one change a reload cannot make.** nginx ties a shared limit zone to the
*key expression* it was first created with. Redefining ``dsh_site_req`` with a
different key is accepted by ``nginx -t`` -- a fresh parse sees one definition
-- and then refused by every reload, forever, until the master is restarted.
That is not a soft failure: ``nginx -s reload`` exits 0 while the old
configuration keeps serving, so the host looks hardened and is not. The
migration in this module's history did exactly that, and the emergency log
filled with ``limit_req "..." uses the "..." key while previously it used the
"..." key``.

So the zone definitions on disk are read *before* anything is written, and a
same-name/different-key change is refused rather than applied (see
:func:`zone_key_changes`). The alternative -- renaming the zone so nginx
treats it as new -- was rejected: live vhosts, which this program does not
own, reference these historical names in their own ``limit_req`` /
``limit_conn`` directives, so a rename either breaks every one of them at
``nginx -t`` or has to keep the old name alive with the old key, silently
splitting enforcement between two zones. A refusal is the only option that
cannot leave a half-applied policy behind.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from ..core import detect
from .installer import _atomic_write, _ensure_http_include

#: Tools that identify themselves honestly. A scanner that lies is handled by
#: the behavioural detection in :mod:`vigil.guards.threat`; this list is for
#: the large majority that do not bother.
UA_PATTERNS = (
    # 漏扫 / 渗透框架
    "nikto", "sqlmap", "nmap", "masscan", "zgrab", "nessus", "openvas",
    "acunetix", "w3af", "nuclei", "xray", "goby",
    # 目录爆破
    "dirbuster", "gobuster", "wfuzz", "dirb", "feroxbuster",
    # 口令爆破
    "hydra", "brutus", "medusa",
    # 互联网测绘 / 情报扫描
    "l9scan", "l9explore", "leakix", "infrawatch", "censys",
    "shadowserver", "internetmeasurement",
    # 已知恶意抓取
    "morfeus", "absinthe", "havij", "pangolin", "mysqloit", "bsqlbf",
)

#: Zone names and rates. The names are load-bearing -- see the module
#: docstring -- so they are constants rather than derived strings.
SITE_REQ_ZONE = "dsh_site_req"
SITE_CONN_ZONE = "dsh_site_conn"
PHP_REQ_ZONE = "dsh_php_req"
SITE_REQ_RATE = "25r/s"
SITE_REQ_BURST = 60
PHP_REQ_RATE = "8r/s"

LEGACY_NAME = "dsh-hardening.conf"


# --------------------------------------------------------------------------
# What nginx refuses to change at reload time
# --------------------------------------------------------------------------
#
# A `limit_req_zone` / `limit_conn_zone` is created in shared memory the first
# time nginx loads a config that declares it. On every later load the module
# compares the key expression with the one the live zone was created with; a
# difference is a fatal `[emerg]`, which a reload reports to the error log and
# then abandons. `nginx -t` does not catch it -- it parses one config in
# isolation and never sees the running zone -- which is what makes this worth
# a dedicated check rather than another `nginx -t` call.

#: One `limit_req_zone` / `limit_conn_zone` declaration, as written in
#: nginx.conf. The key expression is the first token; the zone name follows
#: `zone=` and ends at the `:` that introduces the size.
_ZONE_DEF_RX = re.compile(
    r"^[ \t]*(?P<kind>limit_req_zone|limit_conn_zone)[ \t]+"
    r"(?P<key>\"[^\"]*\"|\S+)[ \t]+"
    r"zone[ \t]*=[ \t]*(?P<zone>[^\s;:]+)",
    re.MULTILINE | re.IGNORECASE)

#: nginx's own wording for "the live zone was created with a different key".
#: The module name is printed as `limit_req` / `limit_conn` (the zone suffix
#: is dropped), so both spellings are accepted. This is the one config error
#: that `nginx -t` accepts and a reload refuses, so callers must not pass it
#: through as a generic parse failure.
_KEY_CHANGE_EMERG_RX = re.compile(
    r"(?P<module>limit_(?:req|conn)(?:_zone)?)[ \t]+\"?(?P<zone>[^\"\s]+)\"?[ \t]+"
    r"uses[ \t]+the[ \t]+\"(?P<new>[^\"]+)\"[ \t]+key[ \t]+"
    r"while[ \t]+previously[ \t]+it[ \t]+used[ \t]+the[ \t]+"
    r"\"(?P<old>[^\"]+)\"[ \t]+key",
    re.IGNORECASE)


def parse_zone_definitions(text: str) -> dict:
    """``zone name -> key expression`` for every limit zone in *text*.

    Only the two directives that create a shared limit zone are considered.
    A name defined twice in one text keeps the last definition, which mirrors
    nginx's own "duplicate zone" error rather than hiding it.
    """
    out = {}
    for m in _ZONE_DEF_RX.finditer(text or ""):
        key = m.group("key").strip()
        if len(key) >= 2 and key[0] == '"' and key[-1] == '"':
            key = key[1:-1]
        out[m.group("zone")] = key
    return out


def zone_key_changes(new_text: str, previous: dict) -> list:
    """``[(zone, old_key, new_key)]`` for zones redefined with a new key.

    An empty list means the change is safe to apply by reload. A non-empty one
    means it is not, and the caller must not write the file: nginx would accept
    it on disk and refuse it on every reload.
    """
    changes = []
    for zone, new_key in parse_zone_definitions(new_text).items():
        old_key = (previous or {}).get(zone)
        if old_key is not None and old_key != new_key:
            changes.append((zone, old_key, new_key))
    return sorted(changes)


def superseded_zone_definitions(where=None) -> dict:
    """Zone definitions the next shield write would replace or retire.

    Two files can hold them and both stop being the definition on disk during
    an install: the previous ``vigil-shield.conf`` and the legacy hardening
    file that is retired in the same pass. Both are read, so the check works
    on a host whose live zones were written by an older generation of this
    program -- which is the case that caused the outage.
    """
    base = Path(where) if where else conf_dir()
    out = {}
    # Legacy first so the current shield file wins when both exist: it is the
    # one the main config includes once it has been written.
    for name in (LEGACY_NAME, "vigil-shield.conf"):
        path = base / name
        try:
            if path.is_file():
                out.update(parse_zone_definitions(
                    path.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue
    return out


def describe_zone_conflicts(changes) -> str:
    """The operator-facing explanation for a refused zone-key change."""
    lines = ["检测到限流区同名换 key，已拒绝写入（未改动任何文件）："]
    for zone, old, new in changes:
        lines.append("  zone=%s：key %s → %s" % (zone, old, new))
    lines.append(
        "       nginx 不允许在运行期更换已有 zone 的 key：这样的文件能通过 "
        "`nginx -t`，\n"
        "       但从写入那一刻起，每一次 reload 都会以 [emerg] 失败，"
        "只有完整重启才能恢复。")
    lines.append(
        "       处理方式（这份配置本程序不会替你写）：\n"
        "       · 要保留原 zone 名：在维护窗口手工写入新 key，然后**完整重启**"
        "（systemctl restart nginx，会中断现有连接）——restart 而不是 reload；\n"
        "       · 要能 reload：把 zone 改成一个新名字，并同步更新所有引用它的 "
        "limit_req / limit_conn。\n"
        "       先完整重启、再重跑本操作没有帮助：只要新旧定义同名不同 key，"
        "本程序仍会拒绝。")
    return "\n".join(lines)


def explain_reload_emerg(line: str) -> str:
    """Translate nginx's zone-key-change ``[emerg]`` into what to do about it.

    Returns ``""`` for every other emergency, so the caller can fall back to
    quoting nginx verbatim. The point is the conclusion, not the translation:
    this is the only nginx config error that no amount of reloading will fix.
    """
    m = _KEY_CHANGE_EMERG_RX.search(line or "")
    if not m:
        return ""
    module = m.group("module").lower()
    directive = "limit_req_zone" if module.startswith("limit_req") else \
        "limit_conn_zone"
    return (
        "nginx 拒绝了新配置：仅靠 reload 无法生效，需要完整重启 nginx —— "
        "nginx 不允许在运行期更换已有 zone 的 key（%s）。\n"
        "       zone=%s，key 由 %s 变为 %s。\n"
        "       请完整重启：systemctl restart nginx（会中断现有连接）；"
        "或在维护窗口执行。\n"
        "       nginx 原文：%s"
        % (directive, m.group("zone"), m.group("old"), m.group("new"),
           (line or "").strip()[:220]))


def reload_reason(emerg: str) -> str:
    """A reload failure as an actionable sentence."""
    return explain_reload_emerg(emerg) or ("nginx 拒绝了新配置：%s"
                                           % (emerg or "").strip())


def conf_dir() -> Path:
    ng = detect.nginx()
    conf = ng.get("conf", "")
    return Path(conf).parent if conf else Path("/usr/local/nginx/conf")


def shield_file() -> Path:
    return conf_dir() / "vigil-shield.conf"


def _trusted_geo(cfg=None) -> str:
    """A `geo` block marking the addresses the operator said are their own.

    Rate limiting an operator's own traffic is how a legitimate action becomes
    an outage. The concrete case: the game on this host pulls ~80 assets on
    first load, the 25 r/s zone answered with 429s, and the browser reported a
    broken page rather than a rate limit -- so the fault looked like the game
    and the cause was the shield. The same 25 r/s is also applied to an
    attacker, which is the point of the zone and the wrong treatment for a
    known-good network.

    Exemption, not a separate zone, because nginx cannot choose a zone
    per-request: the key is what varies, and an empty key means "not limited".
    The trade-off is stated rather than hidden: a whitelisted address gets no
    rate limit, so the remaining protection for it is signature detection, the
    login gate and the connection limit. Set `shield.exempt_whitelist` to
    false to keep whitelisted addresses under the normal rate.
    """
    from ..core.config import load as load_config
    cfg = cfg or load_config()
    entries = []
    for item in (cfg.get("threat.whitelist", []) or []):
        text = str(item or "").strip()
        if not text or any(ch in text for ch in ";{}\n\r\t "):
            # This is written into an nginx directive; a value that can close
            # the block would let a config field inject configuration.
            continue
        entries.append(text)
    entries = sorted(set(entries))
    if not entries:
        return ""
    lines = "\n".join("    %-24s 1;" % e for e in entries)
    return """
# ---- 1b) trusted sources (not rate limited) ----
# The addresses the operator listed as their own. An empty limit key means
# nginx does not apply the limit at all, which is the only way to give one
# network different treatment from another -- zones are chosen by key, not
# per request.
geo $dsh_trusted {
    default 0;
%s
}
map $dsh_trusted $dsh_rl_key {
    1       "";
    default $binary_remote_addr;
}
""" % lines


def render_shield(cfg=None) -> str:
    """The http-scope snippet.

    ``limit_req_status`` / ``limit_conn_status`` are set here and *only*
    here. Declaring them a second time is a fatal "directive is duplicate"
    error that stops nginx loading at all, which is exactly how a hardening
    file once took a working server down.
    """
    agents = "\n".join('    "~*%s"%s1;' % (p, " " * max(1, 28 - len(p)))
                       for p in UA_PATTERNS)
    return """# ============================================================
# Vigil web shield -- GENERATED FILE.
# Regenerate with: vigil shield install
#
# Rejects known scanning and exploitation tools by User-Agent, and caps the
# request rate and concurrent connections a single address may use.
#
# The map and zone names below are intentionally the historical `dsh_*`
# names: existing site configurations reference them directly, and renaming
# would break every one of those vhosts. See vigil/gates/shield.py.
#
# Must be included in the http{{}} block.
# ============================================================

# ---- 1) known scanning / exploitation tools ----
map $http_user_agent $dsh_bad_agent {{
    default 0;

{agents}
}}

# An empty User-Agent is a common script signature, but also some embedded
# devices and health probes. Flagged for observation, never blocked here.
map $http_user_agent $dsh_empty_ua {{
    default 0;
    ""      1;
    "-"     1;
}}

{trusted}
# ---- 2) rate-limit zones ----
# Keyed on $dsh_rl_key, which is empty for whitelisted sources and the client
# address for everyone else. Normal traffic: {site_rate} per address,
# burst {burst}.
limit_req_zone  $dsh_rl_key zone={site_zone}:10m  rate={site_rate};
limit_conn_zone $dsh_rl_key zone={conn_zone}:10m;
# Dynamic requests are far more expensive per hit than a static file.
limit_req_zone  $dsh_rl_key zone={php_zone}:10m   rate={php_rate};

# ---- 3) status codes ----
limit_req_status  429;
limit_conn_status 429;

# ---- 4) security response headers ----
# At http scope these are inherited by every server that does not set its own
# `add_header`. nginx discards *all* inherited headers the moment a child
# context declares any, so a vhost with its own header block will not get
# these -- which is expected and harmless, not a silent failure worth
# chasing. `always` makes them apply to error responses too, where they
# matter most: a 403 or 500 is exactly where content sniffing and framing
# attacks get their footing.
add_header X-Content-Type-Options  nosniff always;
add_header X-Frame-Options         SAMEORIGIN always;
add_header Referrer-Policy         strict-origin-when-cross-origin always;
add_header X-Permitted-Cross-Domain-Policies none always;
""".format(agents=agents, trusted=_trusted_geo(),
           site_zone=SITE_REQ_ZONE, conn_zone=SITE_CONN_ZONE,
           php_zone=PHP_REQ_ZONE, site_rate=SITE_REQ_RATE,
           burst=SITE_REQ_BURST, php_rate=PHP_REQ_RATE)


def _nginx_test() -> tuple:
    binary = detect.nginx().get("binary") or "/usr/local/nginx/sbin/nginx"
    try:
        proc = subprocess.run([binary, "-t"], capture_output=True, text=True,
                              timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    return proc.returncode == 0, (proc.stderr or proc.stdout or "").strip()


def _reload() -> tuple:
    ng = detect.nginx()
    binary = ng.get("binary") or "/usr/local/nginx/sbin/nginx"
    # A control panel owns the nginx service; reload through it when it is
    # there, because the panel also rewrites configuration on its own
    # schedule and would otherwise fight a plain `nginx -s reload`.
    for cmd in (["systemctl", "reload", "nginx"],
                ["systemctl", "reload", "nginx.service"],
                [binary, "-s", "reload"]):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=30)
            if proc.returncode == 0:
                return True, " ".join(cmd)
        except (OSError, subprocess.SubprocessError):
            continue
    return False, "所有重载方式都失败了"


def _worker_pids() -> set:
    """PIDs of running nginx worker processes."""
    try:
        proc = subprocess.run(["pgrep", "-f", "nginx: worker process"],
                              capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return set()
    return {p.strip() for p in (proc.stdout or "").split() if p.strip()}


def _error_log_path() -> str:
    """The error log nginx is actually writing to."""
    for cand in ("/www/wwwlogs/nginx_error.log",
                 str(conf_dir().parent / "logs" / "error.log"),
                 "/var/log/nginx/error.log"):
        if os.path.isfile(cand):
            return cand
    return ""


def _log_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _new_emerg(path: str, since: int) -> str:
    """Any `[emerg]` written since `since`, as a one-line reason."""
    if not path:
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            if since:
                fh.seek(since)
            tail = fh.read(200000)
    except OSError:
        return ""
    for line in reversed(tail.splitlines()):
        if "[emerg]" in line:
            return line.strip()[:220]
    return ""


def reload_and_verify(reload_fn=None, timeout: float = 8.0) -> tuple:
    """Reload nginx through *reload_fn* and *prove* the config is in use.

    A return code is not evidence. `nginx -s reload` exits 0 when the master
    accepts the signal and then rejects the configuration -- the failure goes
    to the error log and the master keeps serving the previous config. The
    concrete case, measured on this host: changing a `limit_req_zone` key
    variable is a fatal `[emerg]` at reload time, so nothing a later edit did
    took effect, `nginx -t` still said "successful", and three rounds of
    testing produced the exact 429s the edit was supposed to have removed.

    Two independent signals, because either alone can be fooled:
      * the worker set changed -- a graceful reload starts new workers, so an
        unchanged set means the master did not pick the config up;
      * a fresh `[emerg]` in the error log -- which also says *why*, and is
        translated by :func:`reload_reason` so a key change is reported as
        "this needs a full restart" instead of a generic parse failure.

    The error log is polled as well as checked at the deadline, so the
    unfixable-by-reload case is reported as soon as nginx writes it rather
    than after the full timeout.
    """
    reload_fn = reload_fn or _reload
    log = _error_log_path()
    mark = _log_size(log)
    before = _worker_pids()

    ok, how = reload_fn()
    if not ok:
        return False, how

    deadline = time.time() + timeout
    while True:
        if _worker_pids() != before:
            return True, "%s（worker %d -> %d）" % (how, len(before),
                                                   len(_worker_pids()))
        emerg = _new_emerg(log, mark)
        if emerg:
            return False, reload_reason(emerg)
        if time.time() >= deadline:
            break
        time.sleep(0.5)
    if before:
        return False, ("reload 后 nginx worker 未更换，新配置很可能没有生效"
                       "（需要完整重启：systemctl restart nginx）")
    # No workers visible at all: this is not nginx, or not a layout we can
    # read. Do not cry wolf about something we cannot observe.
    return True, how


def _reload_verified(timeout: float = 8.0) -> tuple:
    """Reload with the standard ladder, then verify. Kept as the old name."""
    return reload_and_verify(timeout=timeout)


def status() -> dict:
    ng = detect.nginx()
    main = Path(ng.get("conf", ""))
    text = main.read_text(encoding="utf-8", errors="replace") if main.is_file() else ""
    ours = str(shield_file())
    legacy = conf_dir() / LEGACY_NAME
    return {
        "conf": str(main),
        "shield_file": ours,
        "shield_present": Path(ours).is_file(),
        "shield_included": ours in text,
        "legacy_file": str(legacy),
        "legacy_present": legacy.is_file(),
        "legacy_included": (LEGACY_NAME in text),
        "agents": len(UA_PATTERNS),
    }


def install(retire: bool = True) -> dict:
    """Write the shield, prove it loads, then retire the old file.

    Order matters and is the whole point. Writing first and testing second
    means a bad snippet is caught by ``nginx -t`` while the old config is
    still on disk to fall back to. Retiring the legacy include only after the
    replacement has been proven means there is no window in which neither is
    active -- which on this host would mean the vhosts reference an undefined
    variable and nginx stops serving entirely.

    The one change that is refused rather than applied is a same-name zone
    with a different key: it is the only thing here that `nginx -t` accepts
    and a reload can never use, so nothing is written and
    ``result["problems"]`` carries the explanation.
    """
    result = {"written": [], "retired": "", "backup": "", "reloaded": "",
              "problems": [], "ok": False, "zone_key_changes": [],
              "refused": False, "rolled_back": False}
    target = shield_file()
    legacy = conf_dir() / LEGACY_NAME
    main = Path(detect.nginx().get("conf", ""))

    # Before a single byte is written: would this redefine a live zone with a
    # different key? nginx accepts that on disk and refuses it on every reload,
    # so it must not reach the disk at all. Checked here rather than after the
    # write because "write, then discover reload cannot use it" is the failure.
    wanted = render_shield()
    changes = zone_key_changes(wanted, superseded_zone_definitions())
    if changes:
        result["refused"] = True
        result["problems"].append(describe_zone_conflicts(changes))
        result["zone_key_changes"] = [
            {"zone": zone, "from": old, "to": new} for zone, old, new in changes]
        return result

    before_text = main.read_text(encoding="utf-8", errors="replace") \
        if main.is_file() else ""
    before_shield = target.read_text(encoding="utf-8") \
        if target.is_file() else None
    before_legacy = legacy.read_bytes() if legacy.is_file() else None

    _atomic_write(target, wanted, 0o644)
    result["written"].append(str(target))
    _ensure_http_include(str(main), target)

    if retire and legacy.is_file():
        backup = conf_dir() / ("%s.retired-%s"
                               % (LEGACY_NAME, time.strftime("%Y%m%d-%H%M%S")))
        shutil.copy2(str(legacy), str(backup))
        result["backup"] = str(backup)
        # Drop the include line, then move the file aside. Leaving it in
        # place would keep two definitions of the same maps and zones, and a
        # duplicate limit_req_zone is a fatal error.
        text = main.read_text(encoding="utf-8", errors="replace")
        stripped = "\n".join(
            line for line in text.splitlines()
            if LEGACY_NAME not in line or line.strip().startswith("#"))
        if stripped != text:
            _atomic_write(main, stripped + "\n", 0o644)
        legacy.rename(backup)
        result["retired"] = str(backup)

    good, detail = _nginx_test()
    if not good:
        result["problems"].append("nginx -t 失败：%s" % detail[:300])
        result["rolled_back"] = True
        # Roll every file back: a failed test must leave the host exactly as
        # it was, because a broken nginx means every site is down.
        if main.is_file():
            _atomic_write(main, before_text, 0o644)
        if before_shield is None:
            target.unlink(missing_ok=True)
        else:
            _atomic_write(target, before_shield, 0o644)
        if before_legacy is not None:
            legacy.write_bytes(before_legacy)
        retired = result.get("retired")
        if retired:
            Path(retired).unlink(missing_ok=True)
        result["retired"] = ""
        _nginx_test()
        return result

    ok, how = _reload_verified()
    result["reloaded"] = how if ok else ""
    if not ok:
        # Say what to do about it. A configuration that is correct on disk but
        # not in the running process is the one failure mode that makes every
        # other security change meaningless, and it is invisible from every
        # surface except this one. When the reason already names the remedy
        # (a zone key change is the case) it is not repeated.
        hint = "" if "完整重启" in how else (
            "\n       请完整重启：systemctl restart nginx")
        result["problems"].append(
            "nginx 未能载入新配置：%s\n"
            "       该文件在磁盘上是正确的，但**运行中的 nginx 没有使用它**"
            "——在此之前它不会保护任何东西。%s" % (how, hint))
        return result
    result["ok"] = True
    return result


def uninstall() -> dict:
    """Remove the shield and re-point the include at nothing.

    Anything the vhosts reference must keep existing, so this restores the
    retired legacy file when there is one -- removing the definitions while
    three vhosts still use them would take the sites down.
    """
    result = {"removed": "", "restored": "", "problems": [], "ok": False}
    main = Path(detect.nginx().get("conf", ""))
    target = shield_file()
    originals = sorted(conf_dir().glob(LEGACY_NAME + ".retired-*"))

    text = main.read_text(encoding="utf-8", errors="replace") if main.is_file() else ""
    stripped = "\n".join(line for line in text.splitlines()
                         if str(target) not in line)
    if stripped != text:
        _atomic_write(main, stripped + "\n", 0o644)
    target.unlink(missing_ok=True)
    result["removed"] = str(target)

    # Bring the definitions back. The site configurations still reference
    # them, so removing the shield without this would leave every vhost
    # pointing at a variable that no longer exists.
    if originals:
        shutil.copy2(str(originals[-1]), str(conf_dir() / LEGACY_NAME))
        _atomic_write(main,
                      (stripped + "\n    include %s;\n" % LEGACY_NAME).rstrip() + "\n",
                      0o644)
        result["restored"] = str(conf_dir() / LEGACY_NAME)

    good, detail = _nginx_test()
    if not good:
        result["problems"].append("nginx -t 失败：%s" % detail[:300])
        return result
    ok, how = _reload_verified()
    result["ok"] = ok
    if not ok:
        result["problems"].append(
            "nginx 未能载入新配置：%s（需要完整重启：systemctl restart nginx）"
            % how)
    return result
