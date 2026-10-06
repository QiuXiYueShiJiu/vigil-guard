"""A second place to enforce a ban: the web server itself.

Everything this program decides is currently enforced in exactly one place,
``ipset`` + an iptables DROP. That is fast and it is the right default, but
it has three consequences worth naming:

* **On a host without ipset, nothing is enforced at all.** Containers,
  shared hosting and locked-down kernels do not always have it. The
  detection still works, the alert still arrives, and the attacker is not
  actually blocked -- the worst possible combination, because the operator
  believes they are protected.
* **A ban is all-or-nothing.** It drops everything: SSH, the panel, the
  site, every port. For a shared address -- carrier NAT, a university, a
  mobile network -- that is collateral damage. The code already knows this
  and flags carrier-NAT addresses, but has no softer action to offer.
* **There is no way to see what is blocked.** The ipset is a kernel object.
  An audit asks "what is this machine blocking, and why", and the answer
  lives in a state file that only this program reads.

So this module renders the same decisions into an nginx snippet. The
architecture is deliberately the one CrowdSec arrived at: detection produces
a *decision*, and separate enforcement points ("bouncers") apply it wherever
it matters. This is the web-server bouncer. It runs on a timer rather than
in the hot path, because ipset already enforces instantly and a second
mechanism on the critical path would be a second thing that can fail during
an attack.

Two things it is careful about:

* the file contains only ``deny`` lines and comments, so a partially written
  file cannot become a broken nginx configuration;
* nginx is asked to validate before it is reloaded, and the previous version
  is restored if it is rejected.
"""
from __future__ import annotations

import os
from pathlib import Path

from ..core import shell
from ..core.state import read_json, write_json

CONF_NAME = "vigil-deny.conf"

#: How long a reload is given to prove the running master took the new list.
#: Only reached when something is wrong; a healthy reload returns as soon as
#: the worker set changes.
RELOAD_VERIFY_TIMEOUT = 6.0

#: Where the rendered list lives. Kept next to the other nginx snippets the
#: program owns, so an operator can read it with the same habits.
HEADER = """# vigil 封禁列表 —— 由 vigil 生成，请勿手工编辑
#
# 这里列出的是当前被本机封禁的来源地址，由 vigil-threatd 的判定生成。
# 与 ipset 的封禁是同一批决定，两个执行点：
#
#   · ipset + iptables  —— 在内核层丢弃，最快，默认启用；
#   · 本文件 + nginx    —— 在 Web 层返回 403，在没有 ipset 的主机上
#                          仍然能起到作用，而且可以直接阅读与审计。
#
# 为什么两个都要：只有 ipset 时，不支持 ipset 的主机等于完全没有执行；
# 只有 nginx 时，SSH 与面板端口不受保护。
#
# 修改后由 `vigil bouncer sync` 重新生成，并在 nginx -t 通过后 reload。
"""


def server_scope_paths() -> list:
    """One deny file per server block nginx will include.

    Placement matters more than it looks, and getting it wrong is silent.
    nginx does **not** merge access rules across levels: if a `server` block
    declares any `allow`/`deny`, the `http`-level rules are discarded for
    that server, and a `location` that declares its own discards the server's
    for that location. So a list written at `http` scope can be loaded,
    valid, visible in `nginx -T`, and enforce nothing.

    That was measured here rather than assumed. With the list at `http`
    scope only, a denied client was blocked (403). After the same list was
    also written into the server blocks -- minus that one address -- the
    denied client got 200 again, because the *server*-level rules replaced
    the http-level ones. Two lists at two levels is worse than one list at
    the right level.

    The right level is the server block, and the panel already provides the
    hook: every vhost does `include extension/<site>/*.conf;` inside its
    server block, which is the same mechanism the demo page and the decoy
    endpoints use. Writing there needs no vhost edits -- the panel rewrites
    those files, so edits would be undone anyway.
    """
    out = []
    try:
        from ..core import detect
        main = (detect.nginx() or {}).get("conf", "")
        if not main:
            return out
        roots = [Path(main).parent / "vhost" / "nginx" / "extension",
                 Path("/www/server/panel/vhost/nginx/extension")]
        seen = set()
        for ext in roots:
            if not ext.is_dir():
                continue
            for site in sorted(ext.iterdir()):
                target = site / CONF_NAME
                if site.is_dir() and str(target) not in seen:
                    seen.add(str(target))
                    out.append(target)
    except OSError:
        return out
    return out


def conf_path() -> Path:
    """The primary deny file: the first server-scope location, if any.

    Falls back to the http-scope path beside the shield snippet on a host
    with no panel-style extension directories, where a single global include
    is the only option available.
    """
    servers = server_scope_paths()
    if servers:
        return servers[0]
    from ..gates import shield
    return shield.conf_dir() / CONF_NAME


def http_scope_path() -> Path:
    """The fallback global include. Never used alongside server scope."""
    from ..gates import shield
    return shield.conf_dir() / CONF_NAME


def all_targets() -> list:
    """Exactly one level, never both.

    Returns the server-scope files when the panel layout provides them, and
    the single global file when it does not. The global file is still
    written in the first case, but only with comments -- leaving it stale
    would put a second, older list at a level the server rules override,
    which is the confusion this function exists to prevent.
    """
    servers = server_scope_paths()
    if servers:
        return servers
    return [http_scope_path()]


def _placeholder_text() -> str:
    """A valid, empty include: the list lives in the server blocks.

    Kept rather than deleted because a global `include` of a missing file is
    a fatal nginx error, and this file may already be referenced.
    """
    return (HEADER + "\n# 当前生效的封禁列表写在各个 server 块的 "
            "vigil-deny.conf 里，\n"
            "# 本文件保持为空：同一份列表写两个层级时，"
            "server 层的规则会\n"
            "# 取代 http 层的规则，反而让 http 层那份失效。\n")


def render(bans: dict, now: float = None) -> str:
    """Render the deny list. Only `deny` lines and comments, ever."""
    import time
    now = now if now is not None else time.time()
    lines = [HEADER]
    active = []
    for ip, rec in (bans or {}).items():
        if not isinstance(rec, dict):
            continue
        until = float(rec.get("until", 0) or 0)
        if until <= now:
            continue
        active.append((ip, rec, until))
    active.sort(key=lambda item: item[2], reverse=True)
    lines.append("# 当前封禁 %d 个（剩余时间最长的在前）\n" % len(active))
    for ip, rec, until in active:
        reason = str(rec.get("reason", "") or "").replace("\n", " ")[:80]
        left = int(until - now)
        lines.append("# 剩 %6d 秒  %s  %s" % (left, ip, reason))
        lines.append("deny %s;" % ip)
    if not active:
        lines.append("# （当前没有封禁）")
    return "\n".join(lines) + "\n"


def active_bans() -> dict:
    from ..core import paths
    data = read_json(paths.THREAT_STATE, {}) or {}
    return data.get("bans") or {}


def sync(cfg=None, dry_run: bool = False) -> dict:
    """Write every copy of the deny list, then reload nginx once.

    All copies or none: a partially updated list is a set of servers with
    different views of who is blocked, which is worse than a stale but
    consistent one.
    """
    import time as _time

    out = {"ok": True, "changed": False, "count": 0,
           "path": str(conf_path()), "written": [], "problems": [],
           "enforced": False}
    if cfg is not None and not cfg.get("bouncer.enabled", False):
        out["problems"].append("未启用（bouncer.enabled=false）")
        return out

    now = _time.time()
    bans = active_bans()
    out["count"] = len([1 for r in bans.values()
                        if isinstance(r, dict)
                        and float(r.get("until", 0) or 0) > now])
    text = render(bans, now)

    targets = all_targets()
    # When the list lives in the server blocks, the global file must not also
    # hold a list: it would be a second, older copy at a level the server
    # rules replace -- the exact confusion that made the first version of
    # this feature look broken. It stays valid and empty instead.
    if server_scope_paths():
        targets = list(targets) + [http_scope_path()]
        placeholder = _placeholder_text()
    else:
        placeholder = None
    out["targets"] = [str(t) for t in targets]
    previous = {}
    changed = []
    for target in targets:
        try:
            old = target.read_text(encoding="utf-8", errors="replace") \
                if target.is_file() else ""
        except OSError:
            old = ""
        previous[str(target)] = old
        wanted = placeholder if (placeholder is not None
                                 and target == http_scope_path()) else text
        if old != wanted:
            changed.append(target)
    if not changed:
        out["enforced"] = True
        out["written"] = [str(t) for t in targets]
        return out
    out["changed"] = True
    if dry_run:
        out["written"] = [str(t) for t in changed]
        return out

    for target in changed:
        body = placeholder if (placeholder is not None
                               and target == http_scope_path()) else text
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = target.with_suffix(".new")
            tmp.write_text(body, encoding="utf-8")
            os.chmod(str(tmp), 0o644)
            os.replace(str(tmp), str(target))
            out["written"].append(str(target))
        except OSError as e:
            out["problems"].append("写入 %s 失败：%s" % (target, e))

    # Validate before reloading, and put every copy back if nginx refuses.
    # Doing this per-file would leave a window where some servers have the
    # new list and some have the old; doing it once, after all writes, means
    # the only two states are "all new" and "all old".
    ok, msg = nginx_test()
    if not ok:
        _rollback(previous)
        out["ok"] = False
        out["problems"].append("nginx 拒绝新配置，已全部回滚：%s" % msg)
        return out

    # A passing `nginx -t` is not proof the running master took the config. A
    # live limit zone whose key changed passes the test and is refused by every
    # reload, and the refusal only appears in the error log -- so this path
    # verifies the reload and reports that one case as "needs a full restart"
    # instead of leaving the operator with a list they believe is enforced.
    from ..gates import shield as _shield

    if not nginx_binary():
        # No server to reload: do not sit on a verification timeout for a
        # binary that is not installed. The list is still written and ready.
        out["enforced"] = True
        return out

    def _one_reload():
        nginx_reload()
        return True, "nginx -s reload"

    ok, why = _shield.reload_and_verify(_one_reload,
                                        timeout=RELOAD_VERIFY_TIMEOUT)
    if not ok:
        _rollback(previous)
        out["ok"] = False
        out["problems"].append("nginx 未能载入新配置，已全部回滚：%s" % why)
        return out
    out["enforced"] = True
    return out


def _rollback(previous: dict) -> None:
    """Restore every written copy to its previous bytes.

    All copies or none: a partially updated list is a set of servers with
    different views of who is blocked, which is worse than a stale but
    consistent one.
    """
    for path, old in (previous or {}).items():
        try:
            if old:
                Path(path).write_text(old, encoding="utf-8")
            elif Path(path).is_file():
                Path(path).unlink()
        except OSError:
            pass


def nginx_binary() -> str:
    from ..core import detect
    ng = detect.nginx() or {}
    for cand in (ng.get("binary"), "/www/server/nginx/sbin/nginx"):
        if cand and os.path.exists(str(cand)):
            return str(cand)
    import shutil
    return shutil.which("nginx") or ""


def nginx_test() -> tuple:
    binary = nginx_binary()
    if not binary:
        return True, "找不到 nginx，跳过语法检查"
    ok, out, err = shell.run([binary, "-t"], timeout=20)
    return ok, ("%s %s" % (out or "", err or "")).strip()


def nginx_reload() -> None:
    binary = nginx_binary()
    if binary:
        shell.run([binary, "-s", "reload"], timeout=20)


def install(cfg=None) -> dict:
    """Wire the snippet into nginx's http scope, once."""
    from ..gates import installer as ginstaller
    from ..core.config import load as load_config

    out = {"ok": False, "includes": [], "problems": []}
    cfg = cfg or load_config()
    target = conf_path()

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.is_file():
            target.write_text(render(active_bans()), encoding="utf-8")
            os.chmod(str(target), 0o644)
        out["path"] = str(target)
    except OSError as e:
        out["problems"].append("写入失败：%s" % e)
        return out

    # `deny` is valid in http scope, so one include covers every server.
    # Reuses the shield's proven include helper rather than editing nginx.conf
    # by hand -- guessing at that file has broken this host twice.
    from ..core import detect
    main = (detect.nginx() or {}).get("conf", "")
    if not main:
        out["problems"].append("找不到 nginx 主配置，无法接入")
        return out
    if server_scope_paths():
        # Nothing to wire: the panel already includes extension/<site>/*.conf
        # from inside every server block. Touching nginx.conf here would only
        # add a second enforcement level that can override the first.
        out["main_conf"] = main
        out["mode"] = "server"
        out["includes"] = [str(t) for t in server_scope_paths()]
    try:
        if not server_scope_paths():
            ginstaller._ensure_http_include(main, target)
            out["mode"] = "http"
    except OSError as e:
        out["problems"].append("写入 nginx include 失败：%s" % e)
        return out

    ok, msg = nginx_test()
    if not ok:
        out["problems"].append("nginx 拒绝新配置：%s" % msg)
        return out
    nginx_reload()
    out["ok"] = True
    return out


def _remove_http_include(main: str, target) -> bool:
    """Drop the include line, leaving every other line byte-identical."""
    from ..gates import installer as ginstaller
    path = Path(main)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    wanted = str(target)
    kept = [l for l in text.splitlines(keepends=True)
            if not (l.strip().startswith("include") and wanted in l)]
    if len(kept) == len(text.splitlines(keepends=True)):
        return False
    try:
        ginstaller._backup(main)
        ginstaller._atomic_write(path, "".join(kept), 0o644)
    except OSError:
        return False
    return True


def uninstall(cfg=None) -> dict:
    from ..core import detect
    out = {"ok": True, "removed": ""}
    target = conf_path()
    main = (detect.nginx() or {}).get("conf", "")
    try:
        if main:
            _remove_http_include(main, target)
        if target.is_file():
            target.unlink()
            out["removed"] = str(target)
    except OSError as e:
        out["ok"] = False
        out["problems"] = [str(e)]
        return out
    ok, msg = nginx_test()
    if not ok:
        out["ok"] = False
        out["problems"] = ["nginx 拒绝移除后的配置：%s" % msg]
        return out
    nginx_reload()
    return out


def status(cfg=None) -> dict:
    """What is actually enforcing, and at which level.

    Reports the *level*, because that is the part that silently matters: a
    list at `http` scope is overridden by any server block that declares its
    own access rules, so "the file exists" and "the rule applies" are
    different statements.
    """
    from ..core.config import load as load_config
    cfg = cfg or load_config()
    servers = server_scope_paths()
    out = {"enabled": bool(cfg.get("bouncer.enabled", False)),
           "mode": "server" if servers else "http",
           "path": str(conf_path()), "installed": False, "includes": [],
           "entries": 0, "ipset": False, "wired": False}

    targets = servers or [http_scope_path()]
    # Every copy holds the same list, so counting them all would report
    # "21 entries" for 7 bans written to 3 server blocks -- a number that
    # looks like more protection than exists.
    for target in targets:
        try:
            if not target.is_file():
                continue
            out["installed"] = True
            if not out["entries"]:
                out["entries"] = len([l for l in target.read_text(
                    encoding="utf-8", errors="replace").splitlines()
                    if l.startswith("deny ")])
        except OSError:
            continue
    out["copies"] = len(targets)

    if servers:
        # The panel's vhosts each do `include extension/<site>/*.conf;`
        # inside their server block, so a file in that directory is live with
        # no include line of our own. Confirm it rather than assuming it.
        try:
            from ..core import detect
            main = (detect.nginx() or {}).get("conf", "")
            vhost_dir = Path(main).parent / "vhost" / "nginx"
            candidates = list(vhost_dir.glob("*.conf")) + \
                list(Path("/www/server/panel/vhost/nginx").glob("*.conf"))
            for vhost in candidates:
                body = vhost.read_text(encoding="utf-8", errors="replace")
                for target in servers:
                    if "include" in body and str(target.parent) + "/*.conf" in body:
                        out["wired"] = True
                        out["includes"].append("%s（由面板 include 覆盖）"
                                               % target.parent)
        except OSError:
            pass
    else:
        try:
            from ..core import detect
            main = (detect.nginx() or {}).get("conf", "")
            if main and os.path.isfile(main):
                body = Path(main).read_text(encoding="utf-8", errors="replace")
                wanted = str(http_scope_path())
                out["includes"] = [l.strip() for l in body.splitlines()
                                   if wanted in l]
                out["wired"] = bool(out["includes"])
        except OSError:
            pass

    try:
        out["ipset"] = bool(shell.out(["ipset", "list", "-n"]).split())
    except OSError:
        out["ipset"] = False
    return out


def last_sync() -> dict:
    from ..core import paths
    return read_json(paths.STATE_STATE / "bouncer.json", {}) or {}


def record_sync(result: dict) -> None:
    from ..core import paths
    import time
    rec = {"at": time.time(), "count": result.get("count", 0),
           "changed": bool(result.get("changed")),
           "ok": bool(result.get("ok")),
           "problems": result.get("problems") or []}
    try:
        write_json(paths.STATE_STATE / "bouncer.json", rec, mode=0o640)
    except OSError:
        pass


def main(argv=None) -> int:
    """Run one sync. This is what the timer invokes.

    Deliberately silent on success: a timer that logs every minute fills the
    journal with nothing, and then the one line that mattered is invisible.
    Only a change or a failure is worth a line, and failures go to stderr so
    systemd records them.
    """
    import argparse
    import sys

    from ..core.config import load as load_config
    from ..core.logging import get as get_logger

    parser = argparse.ArgumentParser(
        prog="vigil-bouncer",
        description="Keep the nginx deny list in step with the active bans.")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    log = get_logger("bouncer")
    try:
        cfg = load_config()
    except Exception as exc:                            # noqa: BLE001
        log.warn("无法读取配置：%s" % exc)
        return 1

    result = sync(cfg, dry_run=args.dry_run)
    record_sync(result)
    if args.json:
        import json
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    if not result.get("ok"):
        for problem in result.get("problems") or ["未知原因"]:
            log.warn("Web 层封禁同步失败：%s" % problem)
        return 1
    if result.get("changed") and not args.dry_run:
        log.info("已更新 Web 层封禁列表：%d 条" % result.get("count", 0))
    return 0


if __name__ == "__main__":                              # pragma: no cover
    import sys
    sys.exit(main())
