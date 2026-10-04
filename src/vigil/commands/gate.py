"""`vigil gate` -- optional login gates for admin interfaces.

Every parameter of a gate is settable from this command, and the same
options work for both installing a new gate and reconfiguring an existing
one. Reconfiguration is non-destructive by design: it reads the live
configuration first, so anything not explicitly overridden is preserved —
including the password hash, which cannot be recovered if lost.
"""
from __future__ import annotations

import hashlib
import json as _json
import shutil
import subprocess
import tempfile
import textwrap
import time
from pathlib import Path

from .. import ui
from ..core import detect
from ..core.config import load as load_config
from ..core.errors import VigilError
from ..gates import (KIND_BT, KIND_LOGIN, KIND_META, GateSpec, adopt,
                     config_section, detect_all, detect_one, install,
                     instance_label, nginx_text, normalize_instance,
                     reconfigure, status, uninstall)
from ..gates import scenes


def _log():
    from ..core import logging as vlog
    return vlog.get("gate")


def _wrap(text, width=74):
    return textwrap.wrap(str(text), width=width)


def _spec_name(args, kind: str) -> str:
    """The instance name for a command whose gate *kind* is known."""
    return normalize_instance(kind, getattr(args, "name", "") or "")


def _watched_name(args) -> str:
    """The raw instance selector for commands that span kinds."""
    return (getattr(args, "name", "") or "").strip().lower()


def _instance_matches(spec, want: str) -> bool:
    """Does *spec* answer to *want*?

    Both the instance name and the kind are accepted, so `--name login`
    (the default instance), `--name bt_panel` and `--name astrbot` all do
    what the operator means without a separate lookup.
    """
    if not want:
        return True
    return want in (spec.name, spec.kind)


def _reconfigure_hint(spec) -> str:
    cmd = "vigil gate reconfigure %s" % spec.kind
    if spec.name and spec.name != spec.kind:
        cmd += " --name %s" % spec.name
    return cmd + " [选项]"


def _instance_cmd(action: str, kind: str, name: str = "") -> str:
    """`vigil gate <action> <kind> [--name <instance>]` as a copyable string."""
    cmd = "vigil gate %s %s" % (action, kind)
    if name and name != kind:
        cmd += " --name %s" % name
    return cmd


# --------------------------------------------------------------------------
# Informational
# --------------------------------------------------------------------------


def cmd_list(args) -> int:
    """Every gate instance on this host, one row each.

    Deliberately instance-first rather than type-first: with more than one
    login gate, "which gate am I looking at" is the question this has to
    answer, and the type alone cannot answer it.
    """
    cfg = load_config(args.config or None)
    rows = status(cfg)
    installed = [r for r in rows if r["installed"]]
    ui.header("登录网关实例", "已安装 %d 个" % len(installed))
    ui.table(
        [(r["kind"], r["name"], r["state_dir"], r["domain"] or "—",
          str(r["port"]) if r["port"] else "—", r["upstream"] or "—",
          "是" if r["credentials"] else "否（仅人机验证）")
         for r in rows],
        headers=("类型", "实例名", "状态目录", "域名", "端口", "上游", "要密码"))
    for r in rows:
        if not r["installed"] and r["adopted"]:
            ui.warning("%s（%s）在配置里是启用的，但状态目录不存在"
                       % (r["label"], r["state_dir"]))
    ui.out()
    if getattr(args, "types", False):
        ui.section("支持的网关类型")
        for kind, meta in KIND_META.items():
            ui.kv(kind, meta["label"])
            for line in _wrap(meta["desc"]):
                ui.out("        " + line)
        ui.out()
    ui.note("新增一个独立实例（名字决定状态目录、Cookie 与配置键）：")
    ui.hint("vigil gate install login --name astrbot \\")
    ui.hint("    --domain gate.example.com --upstream http://127.0.0.1:6185 \\")
    ui.hint("    --port 4400 --https --no-password")
    ui.note("类型说明与更多示例：vigil gate list --types")
    return 0


def cmd_detect(args) -> int:
    cfg = load_config(args.config or None)
    env = detect.full()
    found = detect_all(env)
    want = _watched_name(args)
    if want:
        found = [s for s in found if _instance_matches(s, want)]
        if not found:
            ui.failure("没有找到匹配的网关实例：%s" % want)
            ui.hint("先用 `vigil gate list` 看有哪些实例")
            return 1
    if args.json:
        ui.out(_json.dumps([s.to_dict() for s in found],
                           ensure_ascii=False, indent=2, default=str))
        return 0

    ui.header("检测已安装的登录防护", "只读取，不修改任何文件")
    if not found:
        ui.note("本机没有检测到已安装的登录防护")
        ui.hint("安装：vigil gate install bt_panel --domain 你的域名")
        return 0

    rows = {(r["kind"], r["name"]): r for r in status(cfg, env)}
    for spec in found:
        ui.section(instance_label(spec.kind, spec.name))
        ui.kv("类型 ID", spec.kind)
        ui.kv("实例名", spec.name)
        ui.kv("配置键", "gate.%s" % config_section(spec.kind, spec.name))
        ui.kv("状态目录", spec.state_dir)
        ui.kv("验证页目录", spec.webroot)
        ui.kv("入口路径", spec.entry_path)
        ui.kv("会话 Cookie", spec.cookie)
        if spec.proxy_mode:
            ui.kv("监听", "%s:%s" % (spec.listen_host or "127.0.0.1",
                                     spec.listen_port or "?"))
            ui.kv("上游服务", spec.upstream or "（未识别）")
            ui.kv("HTTPS", "开启" if spec.use_https else "关闭")
            if spec.use_https:
                ui.kv("证书目录", spec.cert_dir or "（未识别）")
        ui.kv("登录账号", spec.username or "（无账号，仅人机验证）")
        ui.kv("密码", "已设置（bcrypt，无法读出明文）" if spec.pass_hash
              else "无")
        ui.kv("nginx 配置", spec.nginx_conf or "（未检测到接线）")
        ui.kv("会话策略", "空闲 %ds / 绝对 %ds / 绑定UA=%s 绑定IP=%s"
              % (spec.session_ttl, spec.abs_ttl, spec.bind_ua, spec.bind_ip))
        ui.kv("刷新是否重新验证",
              {1: "是（每次导航都验证）",
               2: "是（仅刷新时验证，站内点击不受影响）"}.get(
                  int(spec.strict_nav or 0), "否（会话有效期内免验证）"),
              "green" if int(spec.strict_nav or 0) >= 1 else "")
        ui.kv("验证码", "长度 %d / 有效 %ds / 最短作答 %ds"
              % (spec.captcha_length, spec.captcha_ttl,
                 spec.captcha_min_seconds))
        ui.kv("锁定策略", "%d 次失败锁 %ds（倍率 %d）"
              % (spec.lock_max, spec.lock_secs, spec.lock_backoff))
        for n in (rows.get((spec.kind, spec.name), {}).get("notes") or []):
            ui.warning(n)

    ui.out()
    ui.note("接入已有配置（不改动任何现有文件与登录状态）：")
    ui.hint("vigil gate adopt")
    ui.note("或者直接改参数重装（会自动保留未指定的项）：")
    ui.hint(_reconfigure_hint(found[0]))
    return 0


def cmd_selftest(args) -> int:
    """Prove the puzzle on each installed gate is actually solvable."""
    from ..gates import selftest as st

    ui.header("登录网关自检", "验证码真的能用吗 —— 用像素和文件回答，不看注释")
    ui.note("为每个网关真实生成一道题，然后检查：缺口是否画在服务端会去比对的位置、"
            "未标记的背景是否已经不再生成、拼片尺寸能否盖住缺口、"
            "页面里是否还有客户端求答案的代码。")
    ui.out()

    want = _watched_name(args)
    gates = [s for s in detect_all() if _instance_matches(s, want)]
    results = st.verify_all(gates)
    if not results:
        ui.warning("没有检测到已安装的登录网关"
                   + ("（实例：%s）" % want if want else ""))
        return 1
    for r in results:
        (ui.success if r["ok"] else ui.failure)("%s（%s）"
                                                % (r["label"], r["kind"]))
        for _name, chk in r["checks"].items():
            (ui.bullet if chk.get("ok") else ui.warning)(chk.get("detail", ""))
        for p in r["problems"]:
            ui.warning(p)
        ui.out()
    bad = [r for r in results if not r["ok"]]
    if bad:
        ui.failure("%d 个网关没有通过自检" % len(bad))
        return 1
    ui.success("全部网关通过：缺口画在会比对的位置，拼片尺寸对得上，"
               "页面里没有可推导的答案")
    return 0


def cmd_status(args) -> int:
    cfg = load_config(args.config or None)
    rows = status(cfg)
    want = _watched_name(args)
    if want:
        rows = [r for r in rows if want in (r["name"], r["kind"])]
        if not rows:
            ui.failure("没有找到匹配的网关实例：%s" % want)
            ui.hint("先用 `vigil gate list` 看有哪些实例")
            return 1
    if args.json:
        ui.out(_json.dumps([{k: v for k, v in r.items() if k != "spec"}
                            for r in rows], ensure_ascii=False, indent=2,
                           default=str))
        return 0
    ui.header("登录防护状态")
    any_installed = False
    for r in rows:
        ui.section(r["label"])
        ui.kv("实例名", r["name"])
        ui.kv("配置键", r["config_key"])
        if not r["installed"]:
            ui.note("未安装")
            continue
        any_installed = True
        ui.kv("状态目录", r["state_dir"])
        ui.kv("安装者", "本程序" if r["ours"] else "早期版本 / 手工配置")
        ui.kv("nginx 已接线", "是" if r["wired"] else "否（当前未生效）",
              "green" if r["wired"] else "red")
        ui.kv("已接入本程序", "是" if r["adopted"] else "否",
              "green" if r["adopted"] else "yellow")
        ui.kv("登录账号", r["username"] or "（无）")
        ui.kv("凭据", "有（bcrypt）" if r["credentials"] else "无（纯人机验证）")
        if r["port"]:
            ui.kv("监听端口", "%s（%s）" % (r["port"],
                                           "HTTPS" if r["https"] else "HTTP"))
        if r["entry"]:
            ui.kv("入口路径", r["entry"])
        for n in r["notes"]:
            ui.warning(n)
    ui.out()
    if any_installed:
        ui.hint("修改参数：vigil gate reconfigure <类型> --name <实例名> [选项]")
        ui.hint("查看全部可用参数：vigil gate install --help")
    return 0


# --------------------------------------------------------------------------
# Parameter collection
# --------------------------------------------------------------------------


def _collect(args, kind: str) -> dict:
    """Turn command-line flags into spec overrides."""
    ov: dict = {}
    for name in ("domain", "listen_host", "server_name", "title", "subtitle",
                 "lang", "cert_dir", "entry_path", "cookie", "nav_cookie",
                 "upstream", "upstream_token_file", "upstream_mint_url"):
        val = getattr(args, name, None)
        if val:
            ov[name] = val
    if getattr(args, "port", 0):
        ov["listen_port"] = args.port
    for name in ("session_ttl", "abs_ttl", "nav_ttl", "max_sessions",
                 "captcha_ttl", "captcha_length", "captcha_min_seconds",
                 "captcha_per_minute", "lock_max", "lock_secs",
                 "lock_backoff", "cookie_lifetime"):
        val = getattr(args, name, None)
        if val is not None:
            ov[name] = val
    if args.bind_ip is not None:
        ov["bind_ip"] = 1 if args.bind_ip else 0
    if args.bind_ua is not None:
        ov["bind_ua"] = 1 if args.bind_ua else 0
    if getattr(args, "strict_nav", None) is not None:
        ov["strict_nav"] = 1 if args.strict_nav else 0
    if getattr(args, "scene_kind", ""):
        ov["scene_kind"] = args.scene_kind
    if getattr(args, "image_dir", None):
        # --image-dir replaces the whole list rather than appending to it,
        # because that is what "configure this gate to use these directories"
        # has to mean for a non-interactive reconfigure to be predictable.
        ov["image_dirs"] = list(args.image_dir)
    if getattr(args, "reload_nav", False):
        # 2 = refuse a reload only. The right choice for a multi-page app,
        # where "1" would re-prompt on every menu click.
        ov["strict_nav"] = 2
    if args.https is not None:
        # The certificate directory is derived *after* the listening port is
        # known. Guessing it here used the requested port or the historical
        # 4399, which is wrong the moment a named instance is allocated a
        # different port -- it produced a certificate path ending in
        # `local-0`. See gates.install.
        ov["use_https"] = bool(args.https)
    if args.no_password:
        ov["require_password"] = False
        ov["username"] = ""
        ov["pass_hash"] = ""
    if args.username:
        ov["username"] = args.username
    if args.password:
        ov["password"] = args.password
    return ov


def _interactive_fill(args, kind: str, spec: GateSpec, for_update: bool) -> dict:
    """Guided configuration. Returns extra overrides."""
    extra: dict = {}
    if args.no_prompt or not ui.is_interactive():
        return extra

    meta = KIND_META[kind]
    ui.out()
    ui.section("交互配置（直接回车保持当前值）")

    if spec.proxy_mode:
        extra["listen_port"] = int(ui.ask(
            "监听端口", default=str(spec.listen_port or 4399),
            hint_text="闸门只监听本机，由反向代理指向它；公网不直接暴露此端口"))
        extra["upstream"] = ui.ask(
            "要保护的上游地址", default=spec.upstream or "http://127.0.0.1:8080",
            hint_text="通常是只监听 127.0.0.1 的服务，例如 http://127.0.0.1:8080")
        https = ui.confirm("为该端口启用 HTTPS（自签证书）？",
                           default=bool(spec.use_https))
        extra["use_https"] = https
        if https:
            extra["cert_dir"] = ui.ask(
                "证书目录", default=spec.cert_dir or (
                    "/www/server/panel/vhost/cert/local-%d"
                    % extra["listen_port"]),
                hint_text="不存在会自动签发自签证书（10 年有效）")

    extra["domain"] = ui.ask(
        "对外访问域名", default=spec.domain or "",
        hint_text="用于生成访问地址与证书 SAN，可留空")

    if not meta.get("no_credentials"):
        ui.out()
        ui.note("当前账号: %s" % (spec.username or "（未设置）"))
        if for_update:
            ui.note("密码留空 = 保持原密码不变（哈希无法反推明文）")
        extra["username"] = ui.ask("登录账号",
                                   default=spec.username or "admin")
        pw = ui.ask("登录密码", default="", secret=True,
                    hint_text="以 bcrypt 哈希存储；不会保存明文",
                    required=not for_update)
        if pw:
            extra["password"] = pw

    if ui.confirm("调整会话与验证码等安全策略？", default=False):
        ui.out()
        extra["session_ttl"] = int(ui.ask(
            "会话空闲超时（秒）", default=str(spec.session_ttl),
            hint_text="超过这个时长无操作需要重新验证"))
        extra["abs_ttl"] = int(ui.ask(
            "会话绝对有效期（秒）", default=str(spec.abs_ttl),
            hint_text="到点必须重新登录，无论是否活跃"))
        extra["bind_ip"] = 1 if ui.confirm(
            "会话是否绑定客户端 IP？（移动网络换网会掉线）",
            default=bool(spec.bind_ip)) else 0
        extra["captcha_length"] = int(ui.ask(
            "验证码位数", default=str(spec.captcha_length),
            hint_text="4-8；越长越难自动化，也越考验人眼"))
        extra["lock_max"] = int(ui.ask(
            "连续失败几次锁定", default=str(spec.lock_max)))
        extra["lock_secs"] = int(ui.ask(
            "锁定时长（秒）", default=str(spec.lock_secs)))
        extra["lock_backoff"] = int(ui.ask(
            "重复触发时锁定倍率", default=str(spec.lock_backoff),
            hint_text="1=不递增；2=每次翻倍（最多 16 倍）"))
    return extra


def _apply_password(ov: dict, kind: str, for_update: bool) -> None:
    """Ensure a password is present for a credential gate."""
    meta = KIND_META[kind]
    if meta.get("no_credentials") or ov.get("require_password") is False:
        return
    if ov.get("password") or for_update:
        return
    if ui.is_interactive():
        pw = ui.ask("登录密码", secret=True, required=True,
                    hint_text="以 bcrypt 哈希存储，不保存明文")
        if not pw:
            raise VigilError("必须设置一个密码")
        ov["password"] = pw
        return
    raise VigilError("非交互安装登录网关必须提供 --password",
                     hint="或加 --no-password 安装纯人机验证网关")


# --------------------------------------------------------------------------
# Install / reconfigure
# --------------------------------------------------------------------------


def _report(result, kind: str, title: str, name: str = "") -> int:
    if not result.get("ok"):
        ui.failure(result.get("error", "操作失败"))
        for p in result.get("problems") or []:
            ui.out("    · %s" % p)
        if result.get("detail"):
            for line in str(result["detail"]).splitlines():
                ui.out("      " + line)
        return 1
    ui.success("%s完成" % title)
    ui.kv("入口路径", result.get("entry"))
    if result.get("url"):
        ui.kv("访问地址", result["url"])
    if result.get("cert"):
        ui.note("证书: %s" % result["cert"])
    if result.get("patched"):
        ui.note("已应用上游补丁 %d 处（服务升级后会自动重打）"
                % len(result["patched"]))
    ui.out()
    ui.note("重要：先用浏览器实际走一遍登录，确认能通过，再关闭当前会话。")
    ui.note("面板「修复 nginx」后接线可能丢失，用 `%s` 恢复。"
            % _instance_cmd("repair", kind, name))
    return 0


def cmd_install(args) -> int:
    cfg = load_config(args.config or None)
    kind = args.kind
    name = _spec_name(args, kind)
    env = detect.full()

    ui.header("安装登录防护", instance_label(kind, name))

    existing = detect_one(kind, env, name=name)
    if Path(existing.state_dir).is_dir() and not args.force:
        ui.warning("检测到实例「%s」已存在：%s" % (name, existing.state_dir))
        ui.note("直接重装会覆盖这个实例（可能打断它正在使用的登录会话；"
                "若不知道原密码，会因只存哈希而无法恢复）")
        ui.note("要新建另一个实例，请换一个 --name。")
        if ui.confirm("改为「重新配置」这个实例？", default=True):
            return cmd_reconfigure(args)

    problems = []
    if not env.get("nginx", {}).get("present"):
        problems.append("本机未检测到 nginx")
    if not env.get("nginx", {}).get("lua"):
        problems.append("本机 nginx 未编译 Lua 模块（网关依赖 access_by_lua_file）")
    if not env.get("php_fpm", {}).get("sockets"):
        problems.append("未找到 PHP-FPM socket（验证页需要 PHP）")
    if problems:
        ui.problems_block(problems)
        return 1

    spec = GateSpec.for_kind(kind, cfg=cfg, env=env, name=name)
    ov = _collect(args, kind)
    ov.update(_interactive_fill(args, kind, spec, for_update=False))
    _apply_password(ov, kind, for_update=False)

    if not args.yes and ui.is_interactive():
        ui.out()
        ui.section("即将执行")
        ui.bullet("实例名 %s（配置键 gate.%s）"
                  % (name, config_section(kind, name)))
        ui.bullet("写入网关文件到 %s" % spec.state_dir)
        if ov.get("listen_port"):
            ui.bullet("监听 %s:%s（仅本机）"
                      % (ov.get("listen_host", "127.0.0.1"), ov["listen_port"]))
        if ov.get("upstream"):
            ui.bullet("保护上游 %s" % ov["upstream"])
        ui.bullet("在 nginx 中创建限流区并接线（校验失败会自动回滚）")
        if ov.get("use_https"):
            ui.bullet("准备自签证书")
        if not ui.confirm("确认安装？", default=True):
            ui.note("已取消")
            return 0

    result = install(cfg, kind, env=env, name=name, **ov)
    return _report(result, kind, "安装", name=name)


def cmd_reconfigure(args) -> int:
    cfg = load_config(args.config or None)
    kind = args.kind
    name = _spec_name(args, kind)
    env = detect.full()
    current = detect_one(kind, env, name=name)
    if not Path(current.state_dir).is_dir():
        ui.failure("没有找到可重新配置的 %s 网关（实例 %s）" % (kind, name))
        ui.hint("改用 `%s` 安装"
                % _instance_cmd("install", kind, name))
        ui.hint("现有实例：vigil gate list")
        return 1

    ui.header("重新配置登录防护", instance_label(kind, name))
    ui.note("未指定的参数保持现状（包括密码哈希）。")

    ov = _collect(args, kind)
    ov.update(_interactive_fill(args, kind, current, for_update=True))
    _apply_password(ov, kind, for_update=True)

    # Re-rendering with no overrides is a legitimate operation: it is how an
    # existing installation picks up an upgraded gate implementation while
    # keeping every configured value. So this does not early-return.
    if ov:
        shown = ", ".join("%s=%s" % (k, "'***'" if k == "password" else v)
                          for k, v in sorted(ov.items()))
        ui.note("将应用：%s" % shown)
    else:
        ui.note("未指定修改项 —— 将按现有参数重新生成网关文件"
                "（用于升级实现，配置保持不变）")
    result = reconfigure(cfg, kind, name=name, **ov)
    rc = _report(result, kind, "重新配置", name=name)
    if rc == 0:
        _mirror_to_config(cfg, kind, name)
    return rc


def cmd_adopt(args) -> int:
    cfg = load_config(args.config or None)
    ui.header("接入已有登录防护", "不会修改现有文件，也不会重置任何登录状态")
    found = detect_all()
    want = _watched_name(args)
    if want:
        found = [s for s in found if _instance_matches(s, want)]
    if not found:
        ui.warning("没有检测到已存在的网关配置"
                   + ("（实例：%s）" % want if want else ""))
        ui.hint("如果要新装：vigil gate install <类型>")
        return 1

    adopted_any = False
    for spec in found:
        if args.kind and spec.kind != args.kind:
            continue
        label = instance_label(spec.kind, spec.name)
        ui.section(label)
        ui.kv("类型 ID", spec.kind)
        ui.kv("实例名", spec.name)
        ui.kv("配置键", "gate.%s" % config_section(spec.kind, spec.name))
        ui.kv("状态目录", spec.state_dir)
        ui.kv("入口路径", spec.entry_path)
        if spec.listen_port:
            ui.kv("监听端口", spec.listen_port)
        ui.kv("登录账号", spec.username or "（无）")
        if not args.yes and not ui.confirm("接入该网关？", default=True):
            continue
        info = adopt(cfg, spec.kind, spec)
        adopted_any = True
        ui.success("已接入 %s" % label)
        if info["credentials"]:
            ui.note("已保留原有账号与密码哈希，未做任何改动")
        if not info["wired"]:
            ui.warning("nginx 未引用该网关脚本 —— 需要重新接线才生效")
            ui.hint("运行 `%s`" % _instance_cmd("repair", spec.kind, spec.name))

    if adopted_any:
        if cfg.save():
            ui.out()
            ui.success("配置已保存到 %s" % cfg.path)
        else:
            ui.failure("保存配置失败")
            return 1
    return 0 if adopted_any else 1


def cmd_repair(args) -> int:
    """Re-apply only the nginx wiring, leaving gate files untouched.

    Needed after a control panel "repair nginx", which rewrites the vhosts
    and drops our include — a silent failure, because the gate files remain
    on disk and the installation still looks intact.
    """
    cfg = load_config(args.config or None)
    kind = args.kind
    name = _spec_name(args, kind)
    spec = detect_one(kind, name=name)
    if not Path(spec.state_dir).is_dir():
        ui.failure("没有找到实例「%s」的网关文件，无法接线" % name)
        ui.hint("改用 `%s`" % _instance_cmd("install", kind, name))
        return 1

    ui.header("重新接线", instance_label(kind, name))
    ui.kv("网关脚本", "%s/gate.lua" % spec.state_dir)
    ui.note("保留全部网关文件与会话，只重写 nginx 配置。")
    return _report(install(cfg, kind, name=name, **{}), kind, "重新接线", name)


def cmd_uninstall(args) -> int:
    cfg = load_config(args.config or None)
    kind = args.kind
    name = _spec_name(args, kind)
    if not args.yes and not ui.confirm(
            "卸载实例「%s」（%s）网关？"
            % (name, KIND_META.get(kind, {}).get("label", kind)),
            default=False):
        return 0
    result = uninstall(cfg, kind, remove_state=args.purge, name=name)
    if not result.get("ok"):
        ui.failure(result.get("error", "卸载失败"))
        return 1
    ui.success("已卸载（移除 %d 项）" % len(result.get("removed", [])))
    if not args.purge:
        ui.note("网关文件已保留（如需一并删除：--purge）")
    return 0


def cmd_test(args) -> int:
    """Exercise the live gate end to end and report what actually happened."""
    cfg = load_config(args.config or None)
    kind = args.kind
    name = _spec_name(args, kind)
    env = detect.full()
    spec = detect_one(kind, env, name=name)
    if not Path(spec.state_dir).is_dir():
        ui.failure("没有安装该网关（实例 %s）" % name)
        return 1

    ui.header("网关自检", instance_label(kind, name))
    ok_all = True

    ui.section("1. nginx 配置")
    ng = env.get("nginx", {})
    # `subprocess.run` returns a CompletedProcess, not a tuple; unpacking it
    # as one raised TypeError and took the whole self-test down before it had
    # checked anything.
    probe = subprocess.run([ng["binary"], "-t"],
                           capture_output=True, text=True)
    if probe.returncode == 0:
        ui.success("配置语法正常")
    else:
        ui.failure("配置有误: %s" % (probe.stderr or probe.stdout or "").strip()[:200])
        ok_all = False

    ui.section("2. 接线")
    text = nginx_text(env)
    lua = "%s/gate.lua" % spec.state_dir
    if lua in text:
        ui.success("nginx 已引用网关脚本")
    else:
        ui.failure("nginx 未引用网关脚本 —— 网关当前无效")
        ui.hint("运行 `%s`" % _instance_cmd("repair", kind, name))
        ok_all = False

    ui.section("3. 验证页与验证码")
    if spec.proxy_mode and spec.listen_port:
        scheme = "https" if spec.use_https else "http"
        base = "%s://127.0.0.1:%d" % (scheme, spec.listen_port)
        r = subprocess.run(
            ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", "8", base + spec.entry_path],
            capture_output=True, text=True)
        code = (r.stdout or "").strip()
        if code == "200":
            ui.success("验证页返回 200")
        else:
            ui.failure("验证页返回 %s" % code)
            ok_all = False

    ui.section("4. 上游服务")
    if spec.upstream:
        r = subprocess.run(
            ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", "8", spec.upstream],
            capture_output=True, text=True)
        code = (r.stdout or "").strip()
        if code in ("200", "302", "401", "403"):
            ui.success("上游 %s 可访问（HTTP %s）" % (spec.upstream, code))
        else:
            ui.failure("上游 %s 无响应（HTTP %s）" % (spec.upstream, code))
            ok_all = False

    ui.section("5. 安全策略")
    ui.kv("刷新需重新验证",
          {1: "是（一次性导航票据，F5 即重验）",
           2: "是（仅 F5 重验，站内点击不受影响）"}.get(
              int(spec.strict_nav or 0), "否（会话有效期内免验证）"))
    ui.kv("会话绑定 UA", "开" if spec.bind_ua else "关")
    ui.kv("会话绑定 IP", "开" if spec.bind_ip else "关")
    ui.kv("验证码最短作答", "%d 秒" % spec.captcha_min_seconds)
    ui.kv("验证码难度", "%d 位，失败后递增" % spec.captcha_length)
    ui.kv("签发限速", "%d 次/分钟/地址" % spec.captcha_per_minute)
    ui.kv("锁定", "%d 次失败锁 %d 秒（倍率 %d）"
          % (spec.lock_max, spec.lock_secs, spec.lock_backoff))
    warn = []
    if not spec.bind_ua:
        warn.append("未绑定 UA：会话票据被复制到别处仍可使用")
    if spec.lock_backoff <= 1:
        warn.append("锁定倍率为 1：持续爆破不会被逐步拖慢")
    if spec.captcha_min_seconds < 1:
        warn.append("未设置最短作答时间：脚本可以瞬间提交")
    for w in warn:
        ui.warning(w)

    ui.out()
    if ok_all:
        ui.success("自检通过")
    else:
        ui.failure("自检发现问题，见上")
    return 0 if ok_all else 1


# --------------------------------------------------------------------------
# Option groups
# --------------------------------------------------------------------------


def _add_name_option(p, help_text: str = "") -> None:
    """The instance selector for commands that operate on one gate."""
    p.add_argument("--name", default="",
                   help=help_text or "网关实例名（省略为默认实例 login）")


def _add_common_options(p) -> None:
    p.add_argument("--name", default="",
                   help="实例名。login 类型可创建任意多个互相独立的实例"
                        "（状态目录、Cookie、端口、nginx 接线与配置键都各自独立）；"
                        "省略即默认实例 login。bt_panel 只有一个面板，"
                        "固定为单实例，不接受其它名字")
    p.add_argument("--domain", default="", help="对外访问域名")

    g = p.add_argument_group("监听与上游")
    g.add_argument("--port", type=int, default=0, help="监听端口（仅本机）")
    g.add_argument("--listen-host", dest="listen_host", default="",
                   help="监听地址（默认 127.0.0.1）")
    g.add_argument("--upstream", default="",
                   help="要保护的上游地址，如 http://127.0.0.1:8080")
    g.add_argument("--entry-path", dest="entry_path", default="",
                   help="验证页入口路径")
    g.add_argument("--cookie", default="", help="会话 Cookie 名称")
    g.add_argument("--nav-cookie", dest="nav_cookie", default="",
                   help="一次性导航票据的 Cookie 名称"
                        "（开启刷新重验证时必需）")
    g.add_argument("--server-name", dest="server_name", default="",
                   help="nginx server_name")

    g = p.add_argument_group("HTTPS")
    g.add_argument("--https", dest="https", action="store_true", default=None,
                   help="为该端口启用 HTTPS（自签证书）")
    g.add_argument("--no-https", dest="https", action="store_false",
                   help="关闭 HTTPS")
    g.add_argument("--cert-dir", dest="cert_dir", default="",
                   help="证书目录（不存在会自动签发）")

    g = p.add_argument_group("账号密码")
    g.add_argument("--username", default="", help="登录账号")
    g.add_argument("--password", default="", help="登录密码（bcrypt 存储）")
    g.add_argument("--no-password", action="store_true",
                   help="不要账号密码，只做人机验证")

    g = p.add_argument_group("会话策略")
    g.add_argument("--session-ttl", dest="session_ttl", type=int, default=None,
                   help="会话空闲超时（秒）")
    g.add_argument("--abs-ttl", dest="abs_ttl", type=int, default=None,
                   help="会话绝对有效期（秒）")
    g.add_argument("--bind-ip", dest="bind_ip", action="store_true",
                   default=None, help="会话绑定客户端 IP")
    g.add_argument("--no-bind-ip", dest="bind_ip", action="store_false",
                   help="不绑定 IP")
    g.add_argument("--bind-ua", dest="bind_ua", action="store_true",
                   default=None, help="会话绑定浏览器 UA")
    g.add_argument("--no-bind-ua", dest="bind_ua", action="store_false",
                   help="不绑定 UA")
    g.add_argument("--max-sessions", dest="max_sessions", type=int,
                   default=None, help="会话票据上限")
    g.add_argument("--cookie-lifetime", dest="cookie_lifetime", type=int,
                   default=None,
                   help="Cookie 存活秒数（0=关浏览器即失效）")
    g.add_argument("--reload-nav", dest="reload_nav", action="store_true",
                   help="F5 重新加载时要求重新验证，但站内正常点击不受影响"
                        "（多页应用选这个，如宝塔面板）")
    g.add_argument("--strict-nav", dest="strict_nav", action="store_true",
                   default=None,
                   help="每次刷新页面都要重新验证（用一次性导航票据）")
    g.add_argument("--no-strict-nav", dest="strict_nav", action="store_false",
                   help="会话有效期内刷新无需重新验证")

    g = p.add_argument_group("画面")
    g.add_argument("--scene", dest="scene_kind", default="",
                   choices=("", "art", "image", "auto"),
                   help="art=只用生成风景图；image=只用图库；"
                        "auto=每次出题随机（默认，约 1:1）")
    g.add_argument("--image-dir", dest="image_dir", action="append",
                   default=None,
                   help="图库目录（可重复指定；会替换现有列表）")

    g = p.add_argument_group("人机验证")
    g.add_argument("--captcha-length", dest="captcha_length", type=int,
                   default=None, help="验证码位数（4-8）")
    g.add_argument("--captcha-ttl", dest="captcha_ttl", type=int,
                   default=None, help="验证码有效期（秒）")
    g.add_argument("--captcha-min-seconds", dest="captcha_min_seconds",
                   type=int, default=None, help="最短作答时间（秒）")
    g.add_argument("--captcha-per-minute", dest="captcha_per_minute",
                   type=int, default=None, help="每分钟每地址最多签发数量")

    g = p.add_argument_group("失败锁定")
    g.add_argument("--lock-max", dest="lock_max", type=int, default=None,
                   help="连续失败几次触发锁定")
    g.add_argument("--lock-secs", dest="lock_secs", type=int, default=None,
                   help="锁定时长（秒）")
    g.add_argument("--lock-backoff", dest="lock_backoff", type=int,
                   default=None, help="重复触发时的锁定倍率")

    g = p.add_argument_group("外观")
    g.add_argument("--title", default="", help="验证页标题")
    g.add_argument("--subtitle", default="", help="验证页副标题")
    g.add_argument("--lang", default="", choices=("", "zh", "en"),
                   help="验证页语言")



# ---------------------------------------------------------------------------
# scene -- what the puzzle is made of
# ---------------------------------------------------------------------------

def _scene_dir(cfg, kind: str, spec: GateSpec) -> Path:
    """Where fetched pictures live for this gate.

    Inside the gate's own state directory, so uninstalling the gate takes its
    downloaded artwork with it and nothing is left orphaned in /tmp.
    """
    explicit = (cfg.get("gate", {}) or {}).get("image_dir", "") or ""
    if explicit:
        return Path(explicit)
    return Path(spec.state_dir) / "images"


def _scene_counts(spec: GateSpec):
    from ..gates import scenes as sc
    dirs = list(spec.image_dirs or [])
    rows = []
    total = 0
    for d in dirs:
        info = sc.scan_dir(d)
        total += info["usable"]
        rows.append((d, info["usable"], info["total"], sc.is_transient(d)))
    return rows, total


def _scene_apply(cfg, kind: str, name: str = "", **ov) -> int:
    """Re-render a gate with only the appearance settings changed.

    Everything else -- password hash, port, certificate, session policy --
    is read from the live installation by `reconfigure`, so changing the
    artwork can never cost the operator their credentials.
    """
    if "image_dirs" in ov:
        ov["image_dirs"] = [str(Path(d).expanduser()) for d in ov["image_dirs"]]
    result = reconfigure(cfg, kind, name=name, **ov)
    rc = _report(result, kind, "更新画面来源", name=name)
    if rc == 0:
        _mirror_to_config(cfg, kind, name)
    return rc



# The gate *kind* and the config *key* are not the same string for the
# default login gate: it is `login` everywhere in the gate module and
# `dsh_gate` in the config schema, from when it was written for one specific
# application. A sync that assumed they matched wrote `gate.login.*`, which
# is not a key the schema knows, so the real entry stayed empty and every
# reader kept seeing blanks. Named instances use their name as the key, which
# `gates.spec.config_section` resolves in one place.

# Fields worth mirroring into the vigil configuration. Deliberately excludes
# the password hash: that lives in the gate's own config.php, is never
# recoverable, and has no business being copied around.
SYNC_FIELDS = ("state_dir", "webroot", "entry_path", "cookie", "nav_cookie",
               "nginx_conf", "strict_nav", "scene_kind", "image_dirs",
               "lock_max", "lock_secs", "lock_backoff", "session_ttl",
               "abs_ttl", "captcha_ttl")


def _mirror_to_config(cfg, kind: str, name: str = "") -> None:
    """Write the live gate's settings back into the vigil configuration.

    Without this, `vigil gate reconfigure --scene image --image-dir ...`
    changed the gate and *nothing else*: the vigil config kept the old values,
    so the next `vigil update` regenerated the gate from those old values and
    silently undid the change. Measured exactly that -- reconfigure set the
    picture pool, update put it back, and nothing said a word.

    Only the appearance/plumbing fields are mirrored (see SYNC_FIELDS); the
    password hash is deliberately not among them.
    """
    key = config_section(kind, name)
    try:
        spec = detect_one(kind, detect.full(), name=name)
    except Exception:                                       # noqa: BLE001
        return
    changed = 0
    for field in SYNC_FIELDS:
        val = getattr(spec, field, None)
        if field == "image_dirs":
            val = list(val or [])
        if val in (None, ""):
            continue
        path = "gate.%s.%s" % (key, field)
        if cfg.get(path) != val:
            cfg.set(path, val)
            changed += 1
    if cfg.get("gate.%s.enabled" % key) is not True:
        cfg.set("gate.%s.enabled" % key, True)
        changed += 1
    if changed:
        cfg.save()


def _gate_state_dirs(cfg, only: str = "", name: str = "") -> list:
    """Installed gates as (label, kind, state_dir)."""
    out = []
    for r in status(cfg):
        if not r.get("installed") or not r.get("state_dir"):
            continue
        if only and r.get("kind") != only:
            continue
        if name and r.get("name") != name:
            continue
        out.append((r.get("label") or r.get("kind") or "?", r.get("kind") or "",
                    str(r["state_dir"])))
    return out


def _reads_holds(state_dir: str) -> list:
    """Every lockout record in a gate's `fails/` directory."""
    d = Path(state_dir) / "fails"
    rows = []
    if not d.is_dir():
        return rows
    for f in sorted(d.glob("*.json")):
        try:
            j = _json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        rows.append({
            "file": str(f), "id": f.stem, "until": int(j.get("until", 0)),
            "count": int(j.get("count", 0)), "strikes": int(j.get("strikes", 0)),
            "cred": int(j.get("cred", 0)), "issued": int(j.get("issued", 0)),
            "mtime": int(f.stat().st_mtime),
        })
    return rows


def _php_sweep(state_dir: str, grace: int = 86400, max_age: int = 604800):
    """Run the gate library's own sweeper, so the policy has one definition.

    Reimplementing "which records are stale" in Python would be the same
    mistake this project keeps finding elsewhere: two sources of truth that
    drift. The CLI calls the function the gate itself uses, with the throttle
    disabled so an explicit request always sweeps.
    """
    lib = Path(state_dir) / "lib" / "gate-lib.php"
    php = shutil.which("php")
    for cand in ("/www/server/php/82/bin/php", "/usr/bin/php"):
        if Path(cand).is_file():
            php = cand
            break
    if not lib.is_file() or not php:
        return None
    code = ("<?php require %s; echo vigil_fail_sweep(%s, %d, %d, 0);"
            % (_php_str(str(lib)), _php_str(str(state_dir)), grace, max_age))
    tmp = Path(tempfile.mkdtemp()) / "sweep.php"
    tmp.write_text(code, encoding="utf-8")
    try:
        proc = subprocess.run([php, str(tmp)], capture_output=True, text=True,
                              timeout=60)
        return int((proc.stdout or "0").strip() or 0)
    except (subprocess.SubprocessError, ValueError, OSError):
        return None
    finally:
        shutil.rmtree(str(tmp.parent), ignore_errors=True)


def _php_str(text: str) -> str:
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'") + "'"


def cmd_holds(args) -> int:
    """List, and reset, the login lockouts on this host."""
    cfg = load_config(args.config or None)
    gates = _gate_state_dirs(cfg, getattr(args, "gate_kind", "") or "",
                             _watched_name(args))
    action = getattr(args, "holds_action", "list")
    now = int(time.time())

    if action == "list":
        rows = []
        for label, kind, state_dir in gates:
            for r in _reads_holds(state_dir):
                r.update({"gate": label, "kind": kind, "state_dir": state_dir,
                          "remaining": max(0, r["until"] - now)})
                rows.append(r)
        active = [r for r in rows if r["remaining"] > 0]
        if args.json:
            ui.out(_json.dumps({"gates": [g[0] for g in gates],
                                "records": len(rows), "active": active},
                               ensure_ascii=False, indent=2))
            return 0
        ui.header("登录封禁状态", "fails/ 目录里的活动锁定")
        if not gates:
            ui.warning("没有已安装的网关")
            return 0
        for label, _kind, state_dir in gates:
            mine = [r for r in rows if r["state_dir"] == state_dir]
            live = [r for r in mine if r["remaining"] > 0]
            ui.section(label)
            ui.kv("状态目录", state_dir)
            ui.kv("记录数", "%d（活动锁定 %d）" % (len(mine), len(live)),
                  "red" if live else "green")
            for r in sorted(live, key=lambda x: -x["remaining"]):
                ui.bullet("%s…  剩余 %s  连续失败 %d/本轮  累计锁定 %d 次  密码错 %d"
                          % (r["id"][:12], _dur(r["remaining"]), r["count"],
                             r["strikes"], r["cred"]), mark="!")
        ui.out()
        if active:
            ui.note("文件名是 sha256(客户端 IP)。要立刻解锁："
                    "vigil gate reset-holds --all（或 --ip <该 IP>）")
        else:
            ui.success("当前没有未到期的封禁")
        return 0

    if action == "reset":
        removed, swept = [], []
        targets = set()
        if getattr(args, "ip", ""):
            fname = hashlib.sha256(args.ip.strip().encode()).hexdigest() + ".json"
            targets.add(fname)
        if getattr(args, "stale", False):
            for label, _k, state_dir in gates:
                n = _php_sweep(state_dir)
                swept.append((label, n))
        if not targets and not (getattr(args, "all", False)
                                or getattr(args, "stale", False)):
            ui.failure("要清哪个？用 --ip <地址>、--all，或 --stale（只清陈旧记录）")
            return 1
        for label, _kind, state_dir in gates:
            d = Path(state_dir) / "fails"
            if not d.is_dir():
                continue
            if getattr(args, "all", False):
                for f in sorted(d.glob("*.json")):
                    f.unlink()
                    removed.append((label, f.stem))
            else:
                for name in targets:
                    f = d / name
                    if f.is_file():
                        f.unlink()
                        removed.append((label, f.stem))
        ui.header("重置登录封禁", "删除锁定记录；立即生效，无需重载")
        for label, ident in removed:
            ui.bullet("%s  %s…" % (label, ident[:12]))
        for label, n in swept:
            if n is None:
                ui.warning("%s：无法调用清扫函数（缺 php 或库文件）" % label)
            else:
                ui.bullet("%s  清理陈旧记录 %d 条" % (label, n))
        ui.out()
        if removed or any(n for _l, n in swept if n):
            ui.success("已重置；下一次请求就会重新检查")
        else:
            ui.note("没有匹配的记录（可能本来就没被封）")
        ui.hint("vigil gate holds   # 确认现在是空的")
        return 0

    ui.failure("未知操作：%s" % action)
    return 1


def _dur(seconds: int) -> str:
    if seconds >= 3600:
        return "%d 小时 %d 分" % (seconds // 3600, (seconds % 3600) // 60)
    if seconds >= 60:
        return "%d 分 %d 秒" % (seconds // 60, seconds % 60)
    return "%d 秒" % seconds


def cmd_gate_sync(args) -> int:
    """Mirror the installed gates into the vigil configuration.

    The gate module reads the live installation directly, so it never needed
    this. Everything else -- the login-alert reader, `vigil status`, any
    future consumer -- reads the *configuration*, and that was full of empty
    strings: `state_dir`, `webroot` and `auth_log` were all blank because
    `adopt` only ever read. The result was a config that described nothing
    that was actually installed.
    """
    cfg = load_config(args.config or None)
    ui.header("同步网关配置", "把已安装网关的真实参数写回 vigil 配置")
    changed = 0
    for spec in detect_all():
        key = config_section(spec.kind, spec.name)
        ui.section("%s（%s）" % (instance_label(spec.kind, spec.name), key))
        for field in SYNC_FIELDS:
            val = getattr(spec, field, None)
            if field == "image_dirs":
                val = list(val or [])
            if val in (None, ""):
                continue
            path = "gate.%s.%s" % (key, field)
            cur = cfg.get(path)
            if cur == val:
                ui.bullet("%-14s %s" % (field, ui.dim("不变")))
                continue
            cfg.set(path, val)
            changed += 1
            ui.bullet("%-14s %s" % (field, ui.c(repr(val)[:52], "cyan")))
        # The audit log has a conventional location; record it so nothing has
        # to guess later.
        state = getattr(spec, "state_dir", "") or ""
        if state:
            log = str(Path(state) / "logs" / "auth.log")
            if cfg.get("gate.%s.auth_log" % key) != log:
                cfg.set("gate.%s.auth_log" % key, log)
                changed += 1
                ui.bullet("%-14s %s" % ("auth_log", ui.c(log, "cyan")))
        if cfg.get("gate.%s.enabled" % key) is not True:
            cfg.set("gate.%s.enabled" % key, True)
            changed += 1
    ui.out()
    if changed:
        cfg.save()
        ui.success("已同步 %d 项" % changed)
    else:
        ui.note("配置已是最新，无需改动")
    return 0



def cmd_demo(args) -> int:
    """Install or remove the public slider-puzzle playground."""
    from ..gates import demo
    action = getattr(args, "demo_action", "") or "status"

    if action == "install":
        ui.header("安装人机验证演示页", "可以随便玩的拼图，不拦截任何东西")
        ui.note("这个页面背后没有任何受保护的服务：无会话、无限流、无封禁。")
        if not args.yes and ui.is_interactive():
            if not ui.confirm("继续？", default=True):
                return 0
        res = demo.install()
        for path in res["written"]:
            ui.bullet("已写入 %s" % path)
        for problem in res["problems"]:
            ui.failure(problem)
        if res["ok"]:
            ui.out()
            ui.success("演示页已上线")
            ui.kv("地址", res["url"], "cyan")
            ui.note("这个路径**没有**任何防护 —— 这是有意为之，"
                    "它背后没有可被攻击的东西。")
            return 0
        return 1

    if action == "uninstall":
        ui.header("移除人机验证演示页", "")
        if not args.yes and ui.is_interactive():
            if not ui.confirm("继续？", default=False):
                return 0
        res = demo.uninstall()
        for path in res["removed"]:
            ui.bullet("已移除 %s" % path)
        for problem in res["problems"]:
            ui.failure(problem)
        if res["ok"]:
            ui.success("已移除")
            return 0
        return 1

    st = demo.status()
    ui.header("人机验证演示页", "可以随便玩的拼图")
    ui.kv("状态", "已安装" if st["conf_present"] and st["script_present"]
          else "未安装", "green" if st["script_present"] else "yellow")
    if st["url"]:
        ui.kv("地址", st["url"], "cyan")
    ui.kv("站点根", st["webroot"] or "（未解析）")
    ui.kv("页面文件", st["script"] or "—")
    ui.out()
    if not st["script_present"]:
        ui.hint("vigil gate demo install")
    else:
        ui.hint("vigil gate demo uninstall")
    return 0


def cmd_scene(args) -> int:
    cfg = load_config(args.config or None)
    action = getattr(args, "scene_action", "") or "show"
    kind = getattr(args, "kind", "") or KIND_LOGIN
    name = _spec_name(args, kind)

    from ..gates import scenes as sc

    if action == "providers":
        ui.header("可取图的公开图库", "两个来源，授权差别很大，请按需选择")
        ui.table([(n, lbl, lic) for n, lbl, lic in _provider_help()],
                 headers=("来源", "说明", "授权"))
        ui.out()
        ui.note("openverse 是唯一授权干净、可再分发的来源（CC0 / 公有领域）。")
        ui.note("wallhaven 与 konachan 是第三方同人作品：仅在你自己的服务器上"
                "自用，不要再分发，署名信息会写进 credits.json。")
        ui.hint("vigil gate scene fetch openverse -n 20")
        return 0

    if action == "fetch":
        return _scene_fetch(cfg, kind, args, name)

    if action in ("clear",):
        spec = detect_one(kind, detect.full(), name=name)
        dest = _scene_dir(cfg, kind, spec)
        if not dest.is_dir():
            ui.note("还没有下载过任何图片：%s" % dest)
            return 0
        files = [f for f in dest.iterdir()
                 if f.is_file() and f.name != "credits.json"]
        if not files:
            ui.note("图片目录是空的：%s" % dest)
            return 0
        if not args.yes and not ui.confirm("删除 %d 个图片文件？（%s）"
                                           % (len(files), dest), default=False):
            return 0
        freed = 0
        for f in files:
            freed += f.stat().st_size
            f.unlink()
        cache = Path(spec.state_dir) / "image-cache"
        if cache.is_dir():
            for f in cache.glob("*.jpg"):
                f.unlink()
        pool = Path(spec.state_dir) / "image_pool.json"
        pool.unlink(missing_ok=True)
        ui.success("已删除 %d 个文件，释放 %.1f MB" % (len(files), freed / 1048576))
        ui.hint("vigil gate scene show")
        return 0

    # ---- mutate the gate config ------------------------------------------
    spec = detect_one(kind, detect.full(), name=name)
    if not Path(spec.state_dir).is_dir():
        ui.failure("没有找到 %s 网关" % kind)
        return 1

    if action == "set":
        want = args.value
        if want not in sc.SCENE_KINDS:
            ui.failure("可选值：%s" % ", ".join(sc.SCENE_KINDS))
            return 1
        rows, total = _scene_counts(spec)
        if want == "image" and total == 0:
            ui.failure("image 模式需要图片池，但当前池子是空的")
            ui.hint("先取图：vigil gate scene fetch wallhaven -n 24")
            return 1
        ui.header("设置画面来源", KIND_META[kind]["label"])
        if want == "auto" and total == 0:
            ui.warning("图片池为空，auto 会一直使用生成风景图")
        return _scene_apply(cfg, kind, name, scene_kind=want)

    if action == "add":
        target = str(Path(args.path).expanduser())
        if not Path(target).is_dir():
            ui.failure("目录不存在：%s" % target)
            return 1
        info = sc.scan_dir(target)
        ui.kv("目录", target)
        ui.kv("可用图片", "%d / %d" % (info["usable"], info["total"]))
        for reason, n in sorted(info["reasons"].items(), key=lambda kv: -kv[1]):
            ui.bullet("%s × %d" % (reason, n), mark="!")
        if info["usable"] == 0:
            ui.failure("这个目录里没有可用图片，未加入")
            return 1
        if sc.is_transient(target):
            ui.warning("这个路径看起来是缓存或下载目录，不是你自己挑的图库。")
            ui.note("缓存目录里放的是这台机器上流过的任何图片 —— 聊天软件、"
                    "浏览器下载、别人的头像都可能在里面，"
                    "不适合出现在登录页上。")
            if not args.yes and not ui.confirm("仍然加入？", default=False):
                return 1
        dirs = list(spec.image_dirs or [])
        if target in dirs:
            ui.note("已在列表中：%s" % target)
            return 0
        dirs.append(target)
        return _scene_apply(cfg, kind, name, image_dirs=dirs)

    if action == "remove":
        target = str(Path(args.path).expanduser())
        dirs = [d for d in (spec.image_dirs or []) if str(d) != target]
        if len(dirs) == len(spec.image_dirs or []):
            ui.failure("不在列表中：%s" % target)
            return 1
        return _scene_apply(cfg, kind, name, image_dirs=dirs)

    if action == "scan":
        ui.header("探测本机可用的图库", "只读，不会改动任何配置")
        found = sc.discover()
        if not found:
            ui.note("没有找到任何图片目录。")
            ui.note("这不是错误：生成风景图始终可用，"
                    "或者用 `vigil gate scene fetch` 主动取图。")
            return 0
        ui.table([(r["dir"], r["usable"], r["total"],
                   "缓存目录" if r.get("transient") else "")
                  for r in found],
                 headers=("目录", "可用", "总数", "提示"))
        ui.out()
        ui.note("加入：vigil gate scene add <目录>")
        return 0

    # ---- show ------------------------------------------------------------
    rows, total = _scene_counts(spec)
    ui.header("画面来源", KIND_META[kind]["label"])
    want = str(getattr(spec, "scene_kind", "auto"))
    labels = {"art": "生成风景图（Q版二次元，始终可用）",
              "image": "图库图片",
              "auto": "自动 —— 每次出题随机（生成图为主）"}
    ui.kv("模式", want, color="cyan")
    ui.kv("含义", labels.get(want, want))
    ui.kv("图片目录数", len(rows))
    ui.kv("可用图片总数", total)
    if rows:
        ui.out()
        ui.table([(d, u, t, len(str(d))) for d, u, t, _ in rows],
                 headers=("目录", "可用", "总数", ""))
    dest = _scene_dir(cfg, kind, spec)
    credits = dest / "credits.json"
    if credits.is_file():
        try:
            book = _json.loads(credits.read_text(encoding="utf-8"))
            pics = book.get("pictures", [])
            ui.out()
            ui.kv("已下载图片", "%d 张" % len(pics))
            from collections import Counter
            by = Counter(p.get("provider", "?") for p in pics)
            for name, n in by.most_common():
                ui.bullet("%s：%d 张" % (name, n))
            lic = Counter(p.get("licence", "") for p in pics)
            for name, n in lic.most_common(4):
                if name:
                    ui.bullet("授权 %s：%d 张" % (name, n))
            ui.hint("vigil gate scene credits   # 逐张查看来源与作者")
        except (OSError, ValueError):
            pass
    if want in ("image", "auto"):
        if total == 0:
            ui.out()
            ui.warning("图片池是空的 —— 实际仍会使用生成风景图。")
            ui.hint("vigil gate scene fetch wallhaven -n 24")
    ui.out()
    ui.hint("vigil gate scene providers          # 有哪些公开图库")
    ui.hint("vigil gate scene scan               # 探测本机已有图库")
    ui.hint("vigil gate scene set art|image|auto")
    return 0


def cmd_scene_credits(args) -> int:
    cfg = load_config(args.config or None)
    kind = getattr(args, "kind", "") or KIND_LOGIN
    name = _spec_name(args, kind)
    spec = detect_one(kind, detect.full(), name=name)
    dest = _scene_dir(cfg, kind, spec)
    book_path = dest / "credits.json"
    if not book_path.is_file():
        ui.note("还没有取过图。")
        ui.hint("vigil gate scene fetch wallhaven -n 24")
        return 0
    try:
        book = _json.loads(book_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        ui.failure("credits.json 无法解析：%s" % book_path)
        return 1
    pics = book.get("pictures", [])
    ui.header("图片出处与授权", "%d 张，记录于 %s" % (len(pics), book_path))
    rows = []
    for p in pics:
        rows.append((p.get("file", "")[:28],
                     (p.get("provider") or "")[:9],
                     "%sx%s" % (p.get("width", "?"), p.get("height", "?")),
                     (p.get("author") or "—")[:16],
                     (p.get("licence") or "")[:18]))
    ui.table(rows, headers=("文件", "来源", "尺寸", "作者", "授权"))
    ui.out()
    for p in pics[:6]:
        if p.get("page"):
            ui.bullet(p["file"][:26] + " → " + p["page"][:60], mark="↗")
    if len(pics) > 6:
        ui.note("其余 %d 张的完整链接见 credits.json" % (len(pics) - 6))
    return 0



def cmd_scene_compact(args) -> int:
    """Re-encode the library in place, keeping the pictures and the quality.

    The wallpaper sources serve 4K originals, so a couple of dozen pictures is
    a hundred megabytes of disk for something the puzzle shows 340x200 of.
    This rewrites every file above the limit as a JPEG no larger than the
    limit on its long side and drops the old one, which usually takes the
    directory down by an order of magnitude. The normalisation cache is
    cleared afterwards so the next challenge rebuilds it from the new files
    rather than serving stale copies.
    """
    from ..gates.installer import php_bin
    cfg = load_config(args.config or None)
    kind = getattr(args, "kind", "") or KIND_LOGIN
    name = _spec_name(args, kind)
    spec = detect_one(kind, detect.full(), name=name)
    dest = _scene_dir(cfg, kind, spec)
    if not dest.is_dir():
        ui.note("还没有下载过任何图片：%s" % dest)
        return 0

    php = php_bin()
    if not php:
        ui.failure("找不到 PHP，无法压缩（网关本身运行也需要它）")
        return 1

    limit = max(640, int(args.limit))
    before = sum(f.stat().st_size for f in dest.iterdir() if f.is_file())
    script = dest.parent / ".vigil-compact.php"
    script.write_text(_COMPACT_PHP.replace("__LIMIT__", str(limit)),
                      encoding="utf-8")
    try:
        # Same memory story as `review`: re-encoding a 4K PNG needs far more
        # than PHP's default 128 MB, and the default limit turns a long job
        # into a confusing fatal error halfway through.
        proc = subprocess.run([str(php), "-d", "memory_limit=640M",
                               str(script), str(dest)],
                              capture_output=True, text=True, timeout=1800)
    except (OSError, subprocess.SubprocessError) as exc:
        ui.failure("压缩失败：%s" % exc)
        return 1
    finally:
        script.unlink(missing_ok=True)

    output = (proc.stdout or "").strip()
    if proc.returncode != 0:
        ui.failure("压缩失败（PHP 退出码 %d）" % proc.returncode)
        if proc.stderr:
            ui.note(proc.stderr.strip()[:400])
        return 1
    for line in output.splitlines()[-8:]:
        if line.strip():
            ui.bullet(line.strip(), mark="·")

    cache = Path(spec.state_dir) / "image-cache"
    if cache.is_dir():
        for f in cache.glob("*.jpg"):
            f.unlink()
    pool = Path(spec.state_dir) / "image_pool.json"
    pool.unlink(missing_ok=True)

    after = sum(f.stat().st_size for f in dest.iterdir() if f.is_file())
    ui.out()
    ui.kv("压缩前", "%.1f MB" % (before / 1048576))
    ui.kv("压缩后", "%.1f MB" % (after / 1048576))
    ui.kv("释放", "%.1f MB" % ((before - after) / 1048576))
    ui.success("完成。图片仍在池中，画质按 %d 长边保留。" % limit)
    return 0


_COMPACT_PHP = """<?php
/**
 * Rewrite oversized pool pictures as smaller JPEGs.
 *
 * Generated by `vigil gate scene compact`; deleted straight afterwards.
 * Only files that actually get smaller are replaced, so running it twice is
 * harmless and a picture that is already small is left exactly as it is.
 */
error_reporting(E_ALL & ~E_DEPRECATED);
$dir = $argv[1] ?? '';
$limit = __LIMIT__;
if ($dir === '' || !is_dir($dir)) { fwrite(STDERR, "no such directory\n"); exit(2); }

$done = 0; $kept = 0; $failed = 0; $freed = 0;
foreach (glob($dir . '/*.{jpg,jpeg,png,webp}', GLOB_BRACE) as $path) {
    $before = (int)filesize($path);
    $info = @getimagesize($path);
    if (!$info) { $failed++; continue; }
    if (max($info[0], $info[1]) <= $limit && $before < 900000) { $kept++; continue; }
    $src = null;
    if ($info[2] === IMAGETYPE_JPEG) { $src = @imagecreatefromjpeg($path); }
    elseif ($info[2] === IMAGETYPE_PNG) { $src = @imagecreatefrompng($path); }
    elseif ($info[2] === IMAGETYPE_WEBP && function_exists('imagecreatefromwebp')) {
        $src = @imagecreatefromwebp($path);
    }
    if (!$src) { $failed++; continue; }
    $k = min(1.0, $limit / max($info[0], $info[1]));
    $nw = max(1, (int)round($info[0] * $k));
    $nh = max(1, (int)round($info[1] * $k));
    $dst = imagecreatetruecolor($nw, $nh);
    imagecopyresampled($dst, $src, 0, 0, 0, 0, $nw, $nh, $info[0], $info[1]);
    imagedestroy($src);
    $tmp = $path . '.compact.jpg';
    $ok = @imagejpeg($dst, $tmp, 90);
    imagedestroy($dst);
    if (!$ok) { @unlink($tmp); $failed++; continue; }
    $after = (int)filesize($tmp);
    if ($after >= $before) { @unlink($tmp); $kept++; continue; }
    $target = preg_replace('/\.(jpeg|png|webp)$/i', '.jpg', $path);
    if ($target !== $path && is_file($target)) { @unlink($tmp); $kept++; continue; }
    if (!@rename($tmp, $target)) { @unlink($tmp); $failed++; continue; }
    if ($target !== $path) { @unlink($path); }
    $freed += $before - $after;
    $done++;
}
printf("压缩 %d 张，跳过 %d 张，失败 %d 张，释放 %.1f MB\n",
       $done, $kept, $failed, $freed / 1048576);
"""



def cmd_scene_review(args) -> int:
    """Render the pool as a labelled contact sheet and open nothing.

    Every automatic filter in this tool is a guess about metadata. This is
    the part that is not a guess: it shows the operator the actual pixels,
    with the id needed to reject any of them, and it is the step the safety
    notes keep pointing at. It is deliberately the only place that can tell
    a photograph from an illustration or a flag from a landscape.
    """
    from ..gates.installer import php_bin
    cfg = load_config(args.config or None)
    kind = getattr(args, "kind", "") or KIND_LOGIN
    name = _spec_name(args, kind)
    spec = detect_one(kind, detect.full(), name=name)
    dest = _scene_dir(cfg, kind, spec)
    pool = [p for p in sorted(dest.glob("*"))
            if p.suffix.lower() in (".jpg", ".jpeg", ".png", ".webp")] if dest.is_dir() else []
    if not pool:
        ui.note("图片池是空的，没有可审查的内容。")
        ui.hint("vigil gate scene fetch wallhaven -n 24 --preset character")
        return 0

    blocked = scenes.load_blocklist(spec.state_dir)
    php = php_bin()
    if not php:
        ui.failure("找不到 PHP，无法生成审查图")
        return 1

    out = Path(args.out) if args.out else Path("/tmp/vigil-scene-review.png")
    script = Path("/tmp/.vigil-review.php")
    script.write_text(_REVIEW_PHP.replace("__COLS__", str(max(2, int(args.cols)))))
    try:
        # A pool of a hundred 4K pictures will exhaust PHP's default 128 MB
        # just decoding them one at a time into a sheet, so the limit is
        # raised here rather than left for the operator to discover.
        proc = subprocess.run([str(php), "-d", "memory_limit=640M",
                               str(script), str(dest), str(out),
                               str(spec.state_dir),
                               str(Path(spec.state_dir) / "image-cache")],
                              capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.SubprocessError) as exc:
        ui.failure("生成审查图失败：%s" % exc)
        return 1
    finally:
        script.unlink(missing_ok=True)
    if proc.returncode != 0:
        ui.failure("生成审查图失败")
        if proc.stderr:
            ui.note(proc.stderr.strip()[:400])
        return 1

    ui.header("图库审查表", "%d 张，已屏蔽 %d 张" % (len(pool), len(blocked)))
    ui.kv("审查图", str(out), color="cyan")
    ui.note("每一格都标了编号与 id。看一遍，把不合适的记下来：")
    ui.hint("vigil gate scene block <id> --reason '不合适的原因'")
    ui.hint("vigil gate scene unblock <id>")
    ui.out()
    ui.bullet("这个工具**无法**自动识别：真人照片、文字水印、极端主义符号、"
              "擦边内容。只能靠这一步。", mark="!")
    for line in (proc.stdout or "").strip().splitlines()[-3:]:
        if line.strip():
            ui.bullet(line.strip(), mark="·")
    try:
        if ui.is_interactive() and ui.confirm("现在打开审查图？", default=False):
            subprocess.Popen(["xdg-open", str(out)],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    except Exception:
        pass
    return 0


def cmd_scene_block(args) -> int:
    cfg = load_config(args.config or None)
    kind = getattr(args, "kind", "") or KIND_LOGIN
    name = _spec_name(args, kind)
    spec = detect_one(kind, detect.full(), name=name)
    dest = _scene_dir(cfg, kind, spec)

    keys = []
    for token in args.key:
        p = Path(token)
        if p.is_file():
            keys.append(scenes.picture_key(p))
        elif Path(dest, token).is_file():
            keys.append(scenes.picture_key(Path(dest, token)))
        else:
            keys.append(token.strip())
    if not keys:
        ui.failure("没有给出要屏蔽的 id 或文件")
        return 1

    entries = scenes.load_blocklist(spec.state_dir)
    added = 0
    for key in keys:
        if key and key not in entries:
            entries[key] = args.reason or "人工审查未通过"
            added += 1
    path = scenes.save_blocklist(spec.state_dir, entries,
                                 share_with=spec.image_dirs or [])
    ui.header("屏蔽图片", "已拒绝的图片不会再出现在验证页上")
    ui.kv("新增", "%d 个" % added)
    ui.kv("累计", "%d 个" % len(entries))
    ui.kv("记录", path)
    for key in keys[:10]:
        ui.bullet("%s — %s" % (key, entries.get(key, "")))
    return 0


def cmd_scene_unblock(args) -> int:
    cfg = load_config(args.config or None)
    kind = getattr(args, "kind", "") or KIND_LOGIN
    name = _spec_name(args, kind)
    spec = detect_one(kind, detect.full(), name=name)
    entries = scenes.load_blocklist(spec.state_dir)
    removed = []
    for token in args.key:
        key = scenes.picture_key(Path(token)) if Path(token).is_file() else token
        if key in entries:
            entries.pop(key)
            removed.append(key)
    if not removed:
        ui.note("这些 id 本来就不在屏蔽列表里。")
        return 0
    scenes.save_blocklist(spec.state_dir, entries,
                         share_with=spec.image_dirs or [])
    ui.success("已解除屏蔽：%s" % "、".join(removed))
    return 0


def cmd_scene_blocked(args) -> int:
    cfg = load_config(args.config or None)
    kind = getattr(args, "kind", "") or KIND_LOGIN
    name = _spec_name(args, kind)
    spec = detect_one(kind, detect.full(), name=name)
    entries = scenes.load_blocklist(spec.state_dir)
    if not entries:
        ui.note("屏蔽列表为空。")
        ui.hint("vigil gate scene review   # 先看一遍再决定")
        return 0
    ui.header("已屏蔽的图片", scenes.blocklist_path(spec.state_dir))
    ui.table([(k, v[:40]) for k, v in sorted(entries.items())],
             headers=("id", "原因"))
    return 0


_REVIEW_PHP = """<?php
/**
 * Tile the pool into a labelled contact sheet.
 *
 * Generated by `vigil gate scene review`; deleted straight afterwards. Each
 * cell carries its index and the id that `vigil gate scene block` takes, so
 * the sheet can be read and acted on without a second window open.
 */
error_reporting(E_ALL & ~E_DEPRECATED);
$dir = $argv[1] ?? ''; $out = $argv[2] ?? ''; $state = $argv[3] ?? '';
$cache = $argv[4] ?? '';
$cols = __COLS__;
if ($dir === '' || !is_dir($dir)) { fwrite(STDERR, "no such directory\\n"); exit(2); }

$blocked = [];
$bf = $state !== '' ? $state . '/image_blocklist.json' : '';
if ($bf !== '' && is_file($bf)) {
    $d = json_decode((string)file_get_contents($bf), true);
    $blocked = is_array($d) ? ($d['blocked'] ?? $d) : [];
    if (!is_array($blocked)) { $blocked = []; }
}

$files = [];
foreach (glob($dir . '/*.{jpg,jpeg,png,webp}', GLOB_BRACE) as $f) {
    $stem = pathinfo($f, PATHINFO_FILENAME);
    $key = $stem;
    if (str_contains($stem, '-')) {
        [$head, $tail] = explode('-', $stem, 2);
        if (in_array($head, ['wallhaven', 'konachan', 'openverse'], true) && $tail !== '') {
            $key = $tail;
        }
    }
    $files[] = [$f, $key, isset($blocked[$key]) || isset($blocked[basename($f)])];
}
sort($files);

$cw = 300; $ch = 172; $lab = 16;
$rows = (int)ceil(count($files) / $cols);
$sheet = imagecreatetruecolor($cw * $cols, ($ch + $lab) * max(1, $rows));
imagefilledrectangle($sheet, 0, 0, imagesx($sheet), imagesy($sheet),
                     imagecolorallocate($sheet, 16, 16, 20));
$ink = imagecolorallocate($sheet, 236, 238, 244);
$red = imagecolorallocate($sheet, 255, 120, 120);

foreach ($files as $i => $row) {
    [$f, $key, $isBlocked] = $row;
    // Prefer the normalised copy when there is one. It is a 1024px JPEG
    // instead of a 4K PNG, which is the difference between a sheet that
    // renders and one that runs the process out of memory -- and it is
    // visually identical at a 300px cell.
    $use = $f;
    $stat = @stat($f);
    if ($cache !== '' && is_dir($cache) && is_array($stat)) {
        $ck = md5($f . '|' . ((int)($stat['size'] ?? 0)) . '|'
                . ((int)($stat['mtime'] ?? 0)) . '|1024x1024');
        $cand = rtrim($cache, '/') . '/' . $ck . '.jpg';
        if (is_file($cand)) { $use = $cand; }
    }
    $info = @getimagesize($use);
    if (!$info) { continue; }
    $ext = strtolower(pathinfo($use, PATHINFO_EXTENSION));
    $src = $ext === 'png' ? @imagecreatefrompng($use)
         : ($ext === 'webp' ? @imagecreatefromwebp($use)
                            : @imagecreatefromjpeg($use));
    if (!$src) { continue; }
    $r = $i % $cols; $c = (int)($i / $cols);
    $ox = $r * $cw; $oy = $c * ($ch + $lab) + $lab;
    imagecopyresampled($sheet, $src, $ox, $oy, 0, 0, $cw, $ch, $info[0], $info[1]);
    imagedestroy($src);
    $label = sprintf('#%-3d %s', $i, $key);
    if ($isBlocked) { $label .= '  [已屏蔽]'; }
    imagestring($sheet, 3, $ox + 4, $c * ($ch + $lab) + 1, $label,
                $isBlocked ? $red : $ink);
}

if (!imagepng($sheet, $out)) { fwrite(STDERR, "cannot write $out\\n"); exit(3); }
printf("审查图 %s（%d 张，%d 列）\\n", $out, count($files), $cols);
"""

def _provider_help():
    from ..gates import providers as pv
    return pv.provider_help()


def _scene_fetch(cfg, kind: str, args, name: str = "") -> int:
    from ..gates import providers as pv

    spec = detect_one(kind, detect.full(), name=name)
    if not Path(spec.state_dir).is_dir():
        ui.failure("没有找到 %s 网关" % kind)
        return 1

    meta = pv.PROVIDERS.get(args.provider)
    if not meta:
        ui.failure("未知来源：%s" % args.provider)
        ui.hint("可选：%s" % ", ".join(pv.PROVIDERS))
        return 1

    ui.header("取图", meta["label"])
    ui.kv("授权", meta["licence"], color="yellow" if "非开放" in meta["licence"] else "green")
    ui.kv("安全过滤", meta["safe"])
    ui.note(meta["note"])
    if "非开放" in meta["licence"]:
        ui.out()
        ui.warning("这些是别人的作品，不是开放素材。")
        ui.note("用于你自己服务器的登录页没有问题；"
                "把它们打进任何对外分发的包里则不行。")
    if not args.yes and ui.is_interactive():
        if not ui.confirm("开始下载 %d 张？" % args.count, default=True):
            return 0

    from ..gates import providers as _pv
    query = _pv.resolve_query(args.provider, args.query, args.preset)
    ui.out()
    ui.note("搜索中：%s（最少 %dx%d%s）"
            % (query, args.min_width, args.min_height,
               "，只要横向" if args.landscape else ""))

    try:
        pics = pv.search(args.provider, query=query, limit=args.count,
                         min_width=args.min_width, min_height=args.min_height,
                         landscape_only=args.landscape)
    except pv.FetchError as exc:
        ui.failure("取图失败：%s" % exc)
        if "wallhaven" in str(exc) or "无法连接" in str(exc):
            ui.hint("确认这台机器能直连外网（curl -I https://%s）"
                    % meta["homepage"].split("//")[-1])
        return 1

    if not pics:
        ui.failure("这个条件下没有搜到合适的图片")
        ui.hint("放宽限制：--min-width 1024 --landscape off，或换 -q 关键词")
        return 1
    ui.success("候选 %d 张，开始下载" % len(pics))

    dest = _scene_dir(cfg, kind, spec)
    counter = {"saved": 0, "skip": 0}

    def on_event(kind_ev, pic, detail):
        if kind_ev == "saved":
            counter["saved"] += 1
            ui.out("  %s %s  %dx%d" % (ui.ok("↓"), detail, pic.width, pic.height))
        else:
            counter["skip"] += 1

    saved, skipped = pv.download(pics, dest, min_width=args.min_width,
                                 min_height=args.min_height, on_event=on_event,
                                 theme=(args.preset or args.query or "other"))
    credits = pv.write_credits(dest, saved, skipped)

    ui.out()
    ui.kv("已保存", "%d 张" % len(saved))
    ui.kv("跳过", "%d 张" % len(skipped))
    ui.kv("目录", str(dest))
    ui.kv("出处记录", credits)
    for item in skipped[:4]:
        ui.bullet("跳过 %s" % item["why"], mark="!")

    if not saved:
        ui.failure("一张都没成功")
        return 1

    dirs = [str(d) for d in (spec.image_dirs or [])]
    if str(dest) not in dirs:
        dirs.append(str(dest))
    ui.out()
    ui.note("正在把图库接入网关并刷新图片池…")
    rc = _scene_apply(cfg, kind, name, image_dirs=dirs,
                      scene_kind=("auto" if getattr(spec, "scene_kind", "auto") == "art"
                                  else getattr(spec, "scene_kind", "auto")))
    if rc == 0:
        ui.out()
        ui.success("完成。刷新验证页即可看到新图片；"
                   "点「换一张」会在风景图与图库之间随机切换。")
        ui.out()
        ui.warning("请务必目视检查一遍再收工。")
        ui.note("自动筛选只看元数据，识别不出真人照片、文字水印、"
                "极端主义符号和擦边内容。")
        ui.hint("vigil gate scene review")
        ui.hint("vigil gate scene block <id> --reason '原因'")
    return rc



def _preset_names():
    from ..gates.providers import PRESETS
    return tuple(sorted(PRESETS))


def _provider_help_names():
    from ..gates.providers import PROVIDERS
    return tuple(PROVIDERS)


def register(sub) -> None:
    p = sub.add_parser("gate", help="登录界面防护：宝塔面板 / 独立登录网关",
                       description="为管理界面增加人机验证或登录页。"
                                   "所有参数均可自定义；已存在的配置可直接接入，"
                                   "重装时未指定的参数会原样保留。")
    ps = p.add_subparsers(dest="gate_action", metavar="<操作>")

    sp = ps.add_parser("scene", help="验证页画面：生成风景图 / 自备图库 / 公开图库取图",
                       description="控制人机验证的背景图。两种画面：程序生成的"
                                   "Q版二次元风景图，以及从图库取用的图片。"
                                   "auto 模式每次出题随机切换，"
                                   "所以「换一张」也会换种类。")
    ss = sp.add_subparsers(dest="scene_action", metavar="<操作>")
    sp.set_defaults(func=cmd_scene, scene_action="", kind=KIND_LOGIN)

    q = ss.add_parser("show", help="查看当前画面来源与图片池")
    q.add_argument("--kind", default=KIND_LOGIN, choices=tuple(KIND_META))
    q.set_defaults(func=cmd_scene, scene_action="show")

    q = ss.add_parser("providers", help="列出可用的公开图库及各自授权")
    q.set_defaults(func=cmd_scene, scene_action="providers")

    q = ss.add_parser("scan", help="探测本机已存在的图片目录")
    q.set_defaults(func=cmd_scene, scene_action="scan")

    q = ss.add_parser("set", help="设置画面来源",
                      description="art=只用生成的风景图；image=只用图库；"
                                  "auto=每次出题随机（推荐）。")
    q.add_argument("value", choices=("art", "image", "auto"))
    q.add_argument("--kind", default=KIND_LOGIN, choices=tuple(KIND_META))
    q.set_defaults(func=cmd_scene, scene_action="set")

    q = ss.add_parser("add", help="把一个图片目录加入图片池")
    q.add_argument("path")
    q.add_argument("--kind", default=KIND_LOGIN, choices=tuple(KIND_META))
    q.add_argument("--yes", "-y", action="store_true")
    q.set_defaults(func=cmd_scene, scene_action="add")

    q = ss.add_parser("remove", help="从图片池移除一个目录")
    q.add_argument("path")
    q.add_argument("--kind", default=KIND_LOGIN, choices=tuple(KIND_META))
    q.set_defaults(func=cmd_scene, scene_action="remove")

    q = ss.add_parser("fetch", help="从公开图库下载图片并入池",
                      description="从公开来源取图。openverse 是 CC0/公有领域，"
                                  "授权干净；wallhaven / konachan 画质更好，"
                                  "但是第三方同人作品，仅供自用。")
    q.add_argument("provider", choices=tuple(_provider_help_names()))
    q.add_argument("-n", "--count", type=int, default=24, help="取几张（默认 24）")
    q.add_argument("-q", "--query", default="", help="搜索关键词")
    q.add_argument("-p", "--preset", default="", choices=tuple(_preset_names()),
                   help="关键词预设（character=人物，scenery=风景）")
    q.add_argument("--min-width", dest="min_width", type=int, default=1280)
    q.add_argument("--min-height", dest="min_height", type=int, default=720)
    q.add_argument("--landscape", dest="landscape", action="store_true",
                   default=True, help="只要横向图（默认开启）")
    q.add_argument("--no-landscape", dest="landscape", action="store_false",
                   help="允许竖图（会被裁切，不推荐）")
    q.add_argument("--kind", default=KIND_LOGIN, choices=tuple(KIND_META))
    q.add_argument("--yes", "-y", action="store_true")
    q.set_defaults(func=cmd_scene, scene_action="fetch")

    q = ss.add_parser("credits", help="逐张列出图片出处、作者与授权")
    q.add_argument("--kind", default=KIND_LOGIN, choices=tuple(KIND_META))
    q.set_defaults(func=cmd_scene_credits, scene_action="credits")

    q = ss.add_parser("review", help="生成图库审查表（逐张目视检查，必做）",
                      description="把图库拼成一张带编号的对照图。自动筛选识别不出"
                                  "真人照片、文字水印、极端主义符号和擦边内容，"
                                  "下载之后请务必跑一遍这个。")
    q.add_argument("--out", default="", help="输出 PNG 路径")
    q.add_argument("--cols", type=int, default=5, help="每行几张（默认 5）")
    q.add_argument("--kind", default=KIND_LOGIN, choices=tuple(KIND_META))
    q.set_defaults(func=cmd_scene_review, scene_action="review")

    q = ss.add_parser("block", help="屏蔽某些图片（按 id 或文件名）")
    q.add_argument("key", nargs="+", help="id（如 6ox1kw）或文件名")
    q.add_argument("--reason", default="", help="记录原因，便于以后回想")
    q.add_argument("--kind", default=KIND_LOGIN, choices=tuple(KIND_META))
    q.set_defaults(func=cmd_scene_block, scene_action="block")

    q = ss.add_parser("unblock", help="解除屏蔽")
    q.add_argument("key", nargs="+")
    q.add_argument("--kind", default=KIND_LOGIN, choices=tuple(KIND_META))
    q.set_defaults(func=cmd_scene_unblock, scene_action="unblock")

    q = ss.add_parser("blocked", help="列出已屏蔽的图片")
    q.add_argument("--kind", default=KIND_LOGIN, choices=tuple(KIND_META))
    q.set_defaults(func=cmd_scene_blocked, scene_action="blocked")

    q = ss.add_parser("compact", help="就地压缩图片，省磁盘（画质按长边保留）")
    q.add_argument("--limit", type=int, default=1920,
                   help="最长边上限（默认 1920）")
    q.add_argument("--kind", default=KIND_LOGIN, choices=tuple(KIND_META))
    q.set_defaults(func=cmd_scene_compact, scene_action="compact")

    q = ss.add_parser("clear", help="删除已下载的图片（保留网关本身）")
    q.add_argument("--kind", default=KIND_LOGIN, choices=tuple(KIND_META))
    q.add_argument("--yes", "-y", action="store_true")
    q.set_defaults(func=cmd_scene, scene_action="clear")

    # Every scene action edits one gate's picture pool, so they all take the
    # same instance selector. Added in one place so a new action cannot ship
    # without it.
    for _q in ss.choices.values():
        _add_name_option(_q, "图片池所属的网关实例名（省略为默认 login 实例）")

    sp = ps.add_parser("demo", help="人机验证演示页（可以随便玩，不拦截任何东西）",
                       description="在站点上发布一个公开的拼图演示页。背后没有"
                                   "受保护的服务，因此没有会话、限流与封禁 —— "
                                   "这是有意为之，不是遗漏。")
    ds = sp.add_subparsers(dest="demo_action", metavar="<操作>")
    sp.set_defaults(func=cmd_demo, demo_action="status")
    for act, helptext in (("status", "查看状态"), ("install", "安装"),
                          ("uninstall", "移除")):
        q = ds.add_parser(act, help=helptext)
        q.add_argument("--yes", "-y", action="store_true")
        q.set_defaults(func=cmd_demo, demo_action=act)

    sp = ps.add_parser("sync", help="把已安装网关的参数写回 vigil 配置",
                       description="网关模块自己读实时安装，不需要这一步；"
                                   "但登录告警、状态总览等依赖*配置*的功能需要。"
                                   "重装或改动网关后跑一次即可。")
    sp.set_defaults(func=cmd_gate_sync)

    sp = ps.add_parser("list", help="列出所有已安装的网关实例")
    sp.add_argument("--types", action="store_true",
                    help="同时列出支持的网关类型与用法示例")
    sp.set_defaults(func=cmd_list)

    sp = ps.add_parser("detect", help="检测已安装的网关并读出全部参数")
    sp.add_argument("--json", action="store_true")
    _add_name_option(sp, "只看这个实例（名字或类型，如 astrbot / login）")
    sp.set_defaults(func=cmd_detect)

    sp = ps.add_parser("holds", help="查看登录封禁（锁定）状态",
                       description="列出 fails/ 目录里未到期的锁定。文件名是 "
                                   "sha256(客户端 IP)，所以这里只能显示摘要，"
                                   "不能反推出地址。")
    sp.add_argument("--json", action="store_true")
    _add_name_option(sp, "只看这个网关实例的锁定")
    sp.set_defaults(func=cmd_holds, holds_action="list")

    sp = ps.add_parser("reset-holds", help="立刻解除登录封禁（解锁）",
                       description="删除锁定记录，立即生效（网关每次请求都会重读"
                                   "该文件，不需要重载）。--stale 只清理陈旧记录。")
    sp.add_argument("--ip", default="", help="只清这个客户端地址的锁定")
    sp.add_argument("--all", action="store_true", help="清掉全部锁定记录")
    sp.add_argument("--stale", action="store_true",
                    help="按清扫策略删除陈旧记录（不碰活动锁定）")
    sp.add_argument("--gate", dest="gate_kind", default="",
                    help="只针对某类网关（login / bt_panel）")
    _add_name_option(sp, "只重置这个网关实例的锁定")
    sp.set_defaults(func=cmd_holds, holds_action="reset")

    sp = ps.add_parser("status", help="网关状态总览")
    sp.add_argument("--json", action="store_true")
    _add_name_option(sp, "只看这个实例（名字或类型，如 astrbot / login）")
    sp.set_defaults(func=cmd_status)

    sp = ps.add_parser(
        "selftest", help="自检：验证码真的能拼上吗（像素级）",
        description="为每个已安装网关真实生成一道题，然后检查缺口标记是否画在"
                    "服务端会去比对的位置、未标记的背景是否已不再生成、拼片尺寸"
                    "能否盖住缺口、页面里是否还有客户端求答案的代码。"
                    "这个检查的存在是因为有一次改动让拼片和缺口完全对不上，"
                    "而所有自动化测试都通过了——唯一发现它的是人眼看屏幕。")
    _add_name_option(sp, "只自检这个实例（名字或类型）")
    sp.set_defaults(func=cmd_selftest)

    sp = ps.add_parser("install", help="安装网关",
                       description="安装一个新的登录防护网关。"
                                   "所有参数都可以用命令行指定；"
                                   "不加参数时进入交互式配置。")
    sp.add_argument("kind", choices=tuple(KIND_META))
    _add_common_options(sp)
    sp.add_argument("--force", action="store_true", help="已存在时强制重装")
    sp.add_argument("--yes", "-y", action="store_true", help="跳过确认")
    sp.add_argument("--no-prompt", action="store_true",
                    help="完全不交互，只用命令行参数")
    sp.set_defaults(func=cmd_install)

    sp = ps.add_parser("reconfigure", help="重新配置已有网关（保留未指定的参数）",
                       description="修改已有网关的参数。未指定的项保持现状，"
                                   "包括密码哈希 —— 密码留空即表示不改密码。")
    sp.add_argument("kind", choices=tuple(KIND_META))
    _add_common_options(sp)
    sp.add_argument("--yes", "-y", action="store_true", help="跳过确认")
    sp.add_argument("--no-prompt", action="store_true", help="完全不交互")
    sp.set_defaults(func=cmd_reconfigure)

    sp = ps.add_parser("adopt", help="接入已存在的网关（不改动任何文件）")
    sp.add_argument("kind", nargs="?", default="",
                    choices=("", KIND_BT, KIND_LOGIN))
    sp.add_argument("--yes", "-y", action="store_true")
    _add_name_option(sp, "只接入这个实例（名字或类型）")
    sp.set_defaults(func=cmd_adopt)

    sp = ps.add_parser("repair", help="只重新接线 nginx，不重建网关文件")
    sp.add_argument("kind", nargs="?", default=KIND_LOGIN,
                    choices=tuple(KIND_META))
    _add_name_option(sp, "要重新接线的实例名（省略为默认 login）")
    sp.set_defaults(func=cmd_repair)

    sp = ps.add_parser("test", help="端到端自检：配置、接线、页面、上游")
    sp.add_argument("kind", nargs="?", default=KIND_LOGIN,
                    choices=tuple(KIND_META))
    _add_name_option(sp, "要自检的实例名（省略为默认 login）")
    sp.set_defaults(func=cmd_test)

    sp = ps.add_parser("uninstall", help="卸载网关")
    sp.add_argument("kind", nargs="?", default=KIND_LOGIN,
                    choices=tuple(KIND_META))
    sp.add_argument("--purge", action="store_true", help="同时删除网关文件")
    sp.add_argument("--yes", "-y", action="store_true")
    _add_name_option(sp, "要卸载的实例名（省略为默认 login）")
    sp.set_defaults(func=cmd_uninstall)
