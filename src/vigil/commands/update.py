"""`vigil update` -- upgrade an existing installation in place.

This is the supported way to move between versions. It used to redeploy the
code and restart one daemon, which left every *generated* artefact stale: the
systemd units, the login-gate templates, the nginx shield. Applying a release
that changed any of those therefore required an uninstall and a reinstall --
and a reinstall is exactly the operation that can lose an operator's
configuration.

So an update now refreshes everything the version owns, in dependency order,
and reports each step. Nothing it does is destructive: configuration,
sessions, credentials and downloaded pictures are all left alone, and the
gate regeneration path is the same one `vigil gate reconfigure` uses, which
preserves unset values by construction.
"""
from __future__ import annotations

from datetime import datetime

from .. import ui
from ..core import shell, units
from ..core.config import load as load_config
from ..core.installer import Installer
from ..core.state import read_json

#: Units that must be restarted to pick up new code. Timers are reloaded
#: rather than restarted -- they are already correct, and restarting one
#: mid-window would skip a run.
DAEMON_UNITS = ("vigil-threatd.service", "vigil-loadshed.service")
TIMER_UNITS = ("vigil-health.timer", "vigil-logind.timer",
               "vigil-maild.timer", "vigil-avscan.timer")


def cmd_update(args) -> int:
    inst = Installer(log=_log(), dry_run=args.dry_run)
    cfg = load_config(args.config or None)
    env = inst.discover()

    ui.header("更新 vigil", "只更新程序拥有并生成的内容")

    # -- 1. code ---------------------------------------------------------
    ok, detail = inst.deploy_code()
    (ui.success if ok else ui.failure)(detail)
    if not ok:
        return 1

    # A stale .pyc can shadow freshly deployed code, and the symptom is
    # maddening: the fix is on disk, the process keeps importing the old
    # bytecode. deploy_code copies the tree, so anything cached there came
    # from the previous version.
    if args.dry_run:
        ui.note("预演：将清除已安装包的字节码缓存")
    else:
        removed = _clear_caches()
        if removed:
            ui.note("已清除 %d 处字节码缓存（避免旧 .pyc 影子覆盖新代码）" % removed)

    # The self-integrity baseline is refreshed at the END of the upgrade, not
    # here. Taking it at this point -- which is what the first version of
    # this code did -- recorded the state *before* the gates, shield, demo
    # page and audit rules were rewritten, so the very next inspection filed
    # a CRIT against the upgrade that had just finished. The check caught its
    # own author, which is the point of it.

    # -- 2. config schema ------------------------------------------------
    added = _migrate_config(cfg)
    if added:
        ui.note("配置已补充 %d 个新字段：%s" % (len(added), "、".join(added[:6])))

    # -- 3. systemd units ------------------------------------------------
    features = _features(cfg)
    if features:
        rendered = units.render_all(cfg, features)
        if args.dry_run:
            ui.note("预演：将刷新 %d 个 systemd 单元" % len(rendered))
        else:
            installed = units.install_units(rendered, start=False, log=_log())
            ui.success("已刷新 %d 个 systemd 单元" % len(installed))
            # `enable` is not `start`. Restarting the named services below
            # leaves every *timer* added by this version enabled and dead
            # until the next reboot -- the defence is installed and does
            # nothing. Start them, and check they actually came up.
            started = units.ensure_timers_running(log=_log())
            if started:
                ui.success("已启动未运行的定时器：%s" % "、".join(started))
    else:
        ui.note("配置里没有记录启用的功能，跳过单元刷新")
        ui.hint("重新选择：vigil install --force")

    # -- 4. login gates ---------------------------------------------------
    gates = _refresh_gates(cfg, args.dry_run)

    # -- 5. web shield ----------------------------------------------------
    _refresh_shield(args.dry_run)
    _refresh_hygiene(args.dry_run)
    _refresh_lure(args.dry_run)
    _refresh_exposure(args.dry_run)

    # -- 5b. captcha playground -------------------------------------------
    try:
        from ..gates import demo
        st = demo.status(cfg)
        if st.get("script_present"):
            if args.dry_run:
                ui.note("预演：将重新生成验证码演示页")
            else:
                res = demo.install(cfg)
                (ui.success if res.get("ok") else ui.warning)(
                    "验证码演示页已刷新：%s" % res.get("url", ""))
    except Exception as exc:                           # noqa: BLE001
        ui.warning("演示页刷新失败：%s" % exc)

    # -- 6. audit rules ---------------------------------------------------
    if env.get("auditd", {}).get("present") and "health" in features:
        good, msg = inst.install_audit_rules(cfg)
        (ui.success if good else ui.warning)(msg)

    # -- 7. accept the new self-integrity baseline ------------------------
    # Last, after every file this version generates has been written. Taking
    # it earlier recorded a state that the rest of the upgrade then changed,
    # so the next inspection reported the upgrade to itself.
    _refresh_self_baseline(cfg, args.dry_run)

    # -- 8. restart -------------------------------------------------------
    if args.dry_run:
        ui.note("预演：将重启守护进程并重载定时器")
    else:
        _restart_daemons()

    ui.out()
    ui.kv("程序版本", _version())
    if gates:
        ui.kv("已刷新网关", "、".join(gates))
    ui.success("更新完成")
    if not args.dry_run:
        ui.hint("验证：vigil status / vigil health run / vigil mail test")
    return 0


def _refresh_self_baseline(cfg, dry_run: bool) -> None:
    """Accept the state this upgrade produced as the new integrity baseline.

    Clearing alone is not enough: between the clear and the next timer run,
    nothing would notice the program being edited -- and `vigil selftest`
    would warn about the gap. So the baseline is established here, once every
    generated file is in its final state.
    """
    if dry_run:
        ui.note("预演：将重建「程序自身完整性」基线")
        return
    try:
        from ..guards import health as _health
        _health.rebaseline("self_integrity", _log())
        _health.run_once(cfg, _log(), notify=False, only=["self_integrity"])
        ui.note("已重建「程序自身完整性」基线（本次升级的改动不再报警）")
    except (ImportError, OSError) as exc:
        ui.warning("重建自身完整性基线失败：%s" % exc)


def _restart_daemons(dry_run: bool = False) -> None:
    """Restart the daemons so they pick up the code now on disk."""
    if dry_run:
        return
    for unit in DAEMON_UNITS:
        if shell.out(["systemctl", "is-active", unit]) == "active":
            shell.run(["systemctl", "restart", unit], timeout=60)
            ui.note("已重启 %s" % unit)
    for unit in TIMER_UNITS:
        if shell.unit_enabled(unit):
            shell.run(["systemctl", "restart", unit], timeout=30)
    ui.success("守护进程已重启，定时器已重载")


def _version() -> str:
    from .. import version
    return getattr(version, "__version__", "?")


def _clear_caches() -> int:
    """Delete bytecode caches under the installed package."""
    from ..core import paths
    import shutil
    n = 0
    for cache in paths.LIB.rglob("__pycache__"):
        try:
            shutil.rmtree(cache)
            n += 1
        except OSError:
            pass
    return n


def _migrate_config(cfg) -> list:
    """Write any default keys this version added.

    Loading merges defaults in memory, so a missing key is never an error --
    but it is also invisible, and a key that exists only in memory is easy to
    lose the moment anything writes the file from a partial picture.
    Persisting them makes the file describe the version that is running.
    """
    from ..core.config import DEFAULTS
    added = []

    def walk(node, prefix=""):
        for key, value in (node or {}).items():
            path = "%s.%s" % (prefix, key) if prefix else key
            if isinstance(value, dict):
                walk(value, path)
                continue
            if cfg.get(path, None) is None:
                cfg.set(path, value)
                added.append(path)

    walk(DEFAULTS)
    if added:
        cfg.save()
    return added


def _features(cfg) -> set:
    """Which components this installation runs.

    Read from the configuration, falling back to the units actually present
    so that an installation which predates the setting being recorded still
    updates correctly instead of silently losing its timers.
    """
    recorded = set(cfg.get("features") or [])
    if recorded:
        return recorded
    guess = set()
    for name, feature in (("vigil-threatd", "threat"),
                          ("vigil-loadshed", "loadshed"),
                          ("vigil-health", "health"),
                          ("vigil-logind", "login"),
                          ("vigil-maild", "mail"),
                          ("vigil-avscan", "av")):
        if shell.unit_enabled(name + ".service"):
            guess.add(feature)
    return guess


def _refresh_gates(cfg, dry_run: bool) -> list:
    """Regenerate every installed gate from the new templates.

    Uses the same `reconfigure` path the CLI uses, so an unset parameter
    keeps its current value -- including the password hash, which cannot be
    recovered if lost.
    """
    refreshed = []
    try:
        from ..gates import detect_all, instance_label, reconfigure
    except Exception as exc:                           # noqa: BLE001
        ui.warning("无法载入网关模块：%s" % exc)
        return refreshed
    try:
        found = detect_all()
    except Exception as exc:                           # noqa: BLE001
        ui.warning("网关检测失败：%s" % exc)
        return refreshed

    for spec in found:
        label = instance_label(spec.kind, spec.name)
        if dry_run:
            ui.note("预演：将重新生成网关 %s" % label)
            refreshed.append(label)
            continue
        try:
            result = reconfigure(cfg, spec.kind, name=spec.name)
        except Exception as exc:                       # noqa: BLE001
            ui.failure("重新生成网关 %s 失败：%s" % (label, exc))
            continue
        if isinstance(result, dict) and result.get("ok") is False:
            ui.failure("网关 %s 未刷新：%s"
                       % (label, result.get("error") or result))
            continue
        refreshed.append(label)
    if refreshed and not dry_run:
        ui.success("已用新模板重新生成 %d 个登录网关" % len(refreshed))
    return refreshed



def _refresh_exposure(dry_run: bool) -> None:
    """Put the sensitive-file rules back inside every `^~` prefix.

    The ruleset itself is generated into each site's extension directory, but
    the statement that *applies* it inside a `^~` prefix has to live in the
    site's own config -- and on a panel-managed host that file belongs to the
    panel. Measured on the development host, the include silently disappeared
    and the subtree went back to serving files it should refuse (a real 3 KB
    `.gitignore` became downloadable again). An upgrade is the one moment this
    program is already rewriting generated files, so it re-asserts the wiring
    here too, and `vigil health` reports whenever it had to.
    """
    from ..guards import exposure
    if dry_run:
        ui.note("预演：将补回 `^~` 前缀里的敏感文件拒绝规则")
        return
    try:
        res = exposure.repair_sites()
    except Exception as exc:                           # noqa: BLE001
        ui.warning("敏感文件规则接线检查失败：%s" % exc)
        return
    for path in res.get("restored", []):
        ui.bullet("已重建被删掉的拒绝规则文件：%s" % path)
    for path in res["written"]:
        ui.bullet("已补回拒绝规则：%s（前缀 %s）"
                  % (path, "、".join(res["prefixes"])))
    for problem in res["problems"]:
        ui.warning(problem)


def _refresh_shield(dry_run: bool) -> None:
    """Re-apply the nginx shield if this host has one installed.

    Only if it is already there. `update` must not start protecting things
    the operator never asked it to touch -- but if the shield exists, its
    content belongs to the version and has to move with it.
    """
    try:
        from ..gates import shield
        st = shield.status()
    except Exception:                                  # noqa: BLE001
        return
    if not st.get("shield_present"):
        return
    if dry_run:
        ui.note("预演：将重新生成 Web 防护片段")
        return
    result = shield.install(retire=True)
    if result.get("ok"):
        ui.success("Web 层防护已按新版本重新生成")
    else:
        ui.warning("Web 层防护未更新：%s"
                   % "；".join(result.get("problems") or ["未知原因"]))


def _refresh_lure(dry_run: bool) -> None:
    """Re-publish the lure surfaces if this host already publishes them.

    Same rule as everything else here: only touch what is already there. The
    advertised set follows the decoy corpus, so a host that upgraded and
    gained new decoys should gain them in the lure too -- otherwise the
    published paths and the enforced paths drift apart, and the lure starts
    advertising files this host no longer traps.
    """
    try:
        from ..guards import lure
        st = lure.status()
    except Exception:                                       # noqa: BLE001
        return
    if not (st.get("sitemap_installed") or st.get("robots_installed")):
        return
    if dry_run:
        ui.note("预演：将重新发布诱导面")
        return
    res = lure.install()
    if res.get("ok"):
        ui.success("诱导面已按新版本重新发布")
    else:
        ui.warning("诱导面未更新：%s"
                   % "；".join(res.get("problems") or ["未知原因"]))


def _refresh_hygiene(dry_run: bool) -> None:
    """Re-apply the request-line/Host limits if this host already has them.

    Same rule as the shield: only touch what is already there. A host that
    never installed these must not acquire them as a side effect of an
    upgrade; a host that did must not be left running a stale version of the
    snippet after the limits themselves are revised.
    """
    try:
        from ..guards import hygiene
        st = hygiene.status()
    except Exception:                                  # noqa: BLE001
        return
    # Presence, not currency. Keying this on `installed` (content matches)
    # meant the refresh skipped itself precisely when it was needed, so a
    # snippet change could never reach an upgraded host -- the method rule
    # added in 2.3 stayed on disk in the package and nowhere else.
    if not st.get("present"):
        return
    if dry_run:
        ui.note("预演：将重新生成请求卫生片段")
        return
    ok, msg = hygiene.install()
    if ok:
        ui.success("请求卫生已按新版本重新生成")
    else:
        ui.warning("请求卫生未更新：%s" % msg)


def _log():
    from ..core import logging as vlog
    return vlog.get("main")


def cmd_rollback(args) -> int:
    """Go back to the version that was running before the last update."""
    from ..core import paths
    inst = Installer(log=_log(), dry_run=args.dry_run)
    cfg = load_config(args.config or None)

    ui.header("回滚 vigil", "恢复上一次更新之前的版本")

    inst.discover()
    rec = read_json(paths.STATE_STATE / "deploy.json", {}) or {}
    ui.kv("当前版本", "%s（%s）" % (rec.get("current") or "?",
                                   _when(rec.get("current_at"))))
    ui.kv("可回滚到", rec.get("rollback_version") or "（没有保留上一版）")
    if not (paths.LIB / Installer.PREV_DIR).is_dir():
        ui.failure("没有可回滚的上一版")
        ui.hint("只保留最近一次更新之前的版本；更早的版本需要重新部署源码")
        return 1
    if args.dry_run:
        ui.note("预演：将把 %s 与当前版本互换" % Installer.PREV_DIR)
        return 0

    ok, detail = inst.rollback()
    (ui.success if ok else ui.failure)(detail)
    if not ok:
        return 1

    # The code changed under the feet of everything that imports it.
    removed = _clear_caches()
    if removed:
        ui.note("已清除 %d 处字节码缓存" % removed)
    try:
        from ..guards import health as _health
        if _health.rebaseline("self_integrity", _log()):
            ui.note("已重建「程序自身完整性」基线")
    except (ImportError, OSError) as exc:
        ui.warning("重建自身完整性基线失败：%s" % exc)

    _restart_daemons(args.dry_run)
    ui.out()
    ui.hint("确认已恢复后：vigil status / vigil health run")
    return 0


def _when(ts) -> str:
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError, OSError):
        return "时间未知"


def register(sub) -> None:
    p = sub.add_parser(
        "update", help="从源码更新本程序（含单元、网关、防护的完整升级）",
        description="把当前源码目录的代码部署到安装位置，并刷新本程序生成的"
                    "systemd 单元、登录网关模板与 Web 防护片段，最后重启守护进程。"
                    "配置、会话、凭据与图片都不会被动。")
    p.add_argument("--dry-run", action="store_true", help="只显示将要执行的操作")
    p.set_defaults(func=cmd_update)

    p = sub.add_parser(
        "rollback", help="回滚到上一次更新之前的版本",
        description="把上一次更新替换掉的那份代码换回来，并重启守护进程。"
                    "用于新版本上线后才发现问题的情况——那时机器正在出故障，"
                    "而重新手工部署旧版是最不该在那种时候做的事。")
    p.add_argument("--dry-run", action="store_true", help="只说将要做什么")
    p.set_defaults(func=cmd_rollback)
