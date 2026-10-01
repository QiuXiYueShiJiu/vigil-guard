"""`vigil mail` -- configure, inspect and test the alert channels."""
from __future__ import annotations

import argparse
import json as _json
import sys

from .. import ui
from ..core.config import load as load_config
from ..core.errors import ConfigError, VigilError
from ..i18n import t
from ..mail import queue as q
from ..mail.router import Router
from ..mail import stats as mail_stats
from ..mail.message import KIND_TEST
from ..mail.providers import base as pbase
from ..mail.providers.smtp import PRESETS, preset_choices, preset_label
from ..mail.render import render_test

# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------


def _cfg(args):
    return load_config(args.config or None)


def _save(cfg) -> bool:
    if not cfg.save():
        ui.failure("配置写入失败，请检查 %s 的权限" % cfg.path)
        return False
    return True


def _show_status(cfg) -> None:
    rows = []
    provs = cfg.providers()
    for p in provs:
        params = cfg.provider_params(p.get("provider", ""))
        label = preset_label(params.get("preset", "")) if p.get("provider") == "smtp" \
            else pbase_label(p.get("provider", ""))
        detail = params.get("host") or params.get("from_address") or ""
        rows.append([p.get("provider", "?"), label, detail])
    ui.section("发送渠道（按顺序降级尝试）")
    if rows:
        ui.table(rows, headers=["ID", "名称", "服务器/地址"])
    else:
        ui.note("尚未配置任何渠道")

    rec = cfg.recipients("alert")
    ui.section("收件人")
    if rec:
        for r in rec:
            ui.bullet(r)
    else:
        ui.note("尚未配置收件人 —— 收不到任何告警")

    login_rec = cfg.recipients("login")
    if login_rec and login_rec != rec:
        ui.note("登录通知另有收件人: %s" % ", ".join(login_rec))


def pbase_label(pid: str) -> str:
    cls = pbase.get(pid)
    return cls.label if cls else pid


def _ensure_providers_loaded() -> None:
    pbase.import_builtins()


# --------------------------------------------------------------------------
# providers
# --------------------------------------------------------------------------


def cmd_providers(args) -> int:
    _ensure_providers_loaded()
    groups = pbase.by_kind()
    order = (("api", "API 接口（推荐，不依赖本机发信能力）"),
             ("smtp", "SMTP 邮箱"),
             ("local", "本机 MTA"),
             ("webhook", "Webhook / 群机器人"))
    if args.json:
        ui.out(_json.dumps(
            [{"id": p.id, "label": p.label, "kind": p.kind,
              "fields": [f.name for f in p.fields]}
             for p in pbase.all_providers()], ensure_ascii=False, indent=2))
        return 0
    for kind, title in order:
        items = groups.get(kind) or []
        if not items:
            continue
        ui.section(title)
        for p in items:
            ui.out("  %s  %s" % (ui.c(p.id.ljust(14), "green"),
                                 ui.bold(p.label)))
            if p.blurb:
                ui.out("      %s" % ui.dim(p.blurb))
            if p.id == "smtp":
                ui.out("      %s" % ui.dim(
                    "内置预设: " + "、".join(preset_label(k) for k in preset_choices())))
    ui.out()
    ui.note("用 `vigil mail setup` 交互式配置，或 `vigil mail setup --provider <ID>`。")
    return 0


# --------------------------------------------------------------------------
# setup wizard
# --------------------------------------------------------------------------


def _wizard_smtp(cfg, existing: dict) -> dict:
    """Collect SMTP parameters, starting from a vendor preset."""
    opts = [(k, "%s  %s" % (preset_label(k), ui.dim(
        PRESETS[k]["host"] or "手动填写"))) for k in preset_choices()]
    default_idx = 1
    cur = existing.get("preset")
    if cur in preset_choices():
        default_idx = list(preset_choices()).index(cur) + 1
    preset_key = ui.choose("请选择邮箱类型", opts, default=default_idx)
    preset = PRESETS[preset_key]

    params = {"preset": preset_key}
    # Presets fill in everything they can so the operator only types secrets.
    params["host"] = existing.get("host") or preset.get("host", "")
    params["port"] = existing.get("port") or str(preset.get("port", 587))
    params["security"] = existing.get("security") or preset.get("tls", "starttls")

    if preset.get("hint"):
        ui.out()
        ui.out(ui.info("  ℹ " + preset["label"]))
        for line in _wrap_cn(preset["hint"], 74):
            ui.out("    " + ui.dim(line))
    if preset.get("credential"):
        ui.out("    %s %s" % (ui.dim("需要的凭据:"),
                              ui.c(preset["credential"], "yellow")))

    if preset_key == "custom":
        params["host"] = ui.ask("SMTP 服务器地址", default=params["host"],
                                hint_text="例如 smtp.example.com", required=True)
        params["port"] = ui.ask("端口", default=params["port"],
                                hint_text="465 = SSL 直连；587 = STARTTLS；25 常被机房封禁")
        params["security"] = ui.choose(
            "加密方式", [("ssl", "SSL 直连（465）"),
                         ("starttls", "STARTTLS（587）"),
                         ("plain", "不加密（不推荐）")],
            default={"ssl": 1, "starttls": 2}.get(params["security"], 2))
    else:
        ui.note("服务器: %s:%s（%s）" % (params["host"], params["port"],
                                         params["security"]))

    if preset.get("fixed_user"):
        params["username"] = preset["fixed_user"]
        ui.note("用户名固定为 %s" % preset["fixed_user"])
    else:
        params["username"] = ui.ask(
            "登录用户名", default=existing.get("username", ""),
            hint_text="多数邮箱就是完整邮箱地址", required=True)

    params["password"] = ui.ask(
        "密码 / 授权码", default=existing.get("password", ""), secret=True,
        hint_text="注意：通常不是网页登录密码，而是「授权码」或「应用专用密码」",
        required=True)

    # The alignment trap. Get this wrong and mail silently lands in spam.
    ui.out()
    ui.out("  %s" % ui.bold("发件地址"))
    if preset.get("signs_dkim") is False:
        ui.out("    %s" % ui.warn(
            "该邮箱不会为你的自有域名做 DKIM 签名。"))
        ui.out("    %s" % ui.dim(
            "若把发件地址填成自有域名，收件方会判定为伪造 —— 发信日志显示"
            "「已投递」，但邮件进了垃圾箱。"))
        ui.note("建议留空，直接使用登录账号作为发件地址。")
    elif preset.get("signs_dkim") is True:
        ui.note("该服务会为已验证域名签名，可填写自有域名下的任意地址。")
    params["from_address"] = ui.ask(
        "发件地址", default=existing.get("from_address", ""),
        hint_text="留空 = 使用上面的登录用户名")
    params["from_name"] = ui.ask(
        "发件人显示名称", default=existing.get("from_name") or
        cfg.get("mail.from_name", "Server Monitor"))
    return params


def _wizard_generic(prov_cls, cfg, existing: dict) -> dict:
    """Walk a provider's declared fields."""
    params = {}
    lang = "zh"
    ui.out()
    ui.out(ui.info("  ℹ " + prov_cls.label))
    if prov_cls.blurb:
        for line in _wrap_cn(prov_cls.blurb, 74):
            ui.out("    " + ui.dim(line))
    if prov_cls.docs_url:
        ui.out("    %s %s" % (ui.dim("文档:"), ui.dim(prov_cls.docs_url)))
    fields = prov_cls.fields
    # Choice fields first: they often determine the others.
    for f in sorted(fields, key=lambda x: 0 if x.kind == "choice" else 1):
        if f.name in params:
            continue
        label = f.display(lang)
        guidance = f.guidance(lang)
        cur = existing.get(f.name)
        if f.kind == "choice":
            options = [(c, c) for c in f.choices]
            default = options.index((f.default, f.default)) + 1 if \
                f.default in f.choices else 1
            params[f.name] = ui.choose("%s（%s）" % (label, f.name),
                                       options, default=default)
        elif f.kind == "bool":
            params[f.name] = "1" if ui.confirm(
                "%s（%s）" % (label, f.name), default=bool(f.default)) else "0"
        else:
            params[f.name] = ui.ask(
                "%s（%s）" % (label, f.name),
                default=str(cur if cur is not None else f.default),
                hint_text=guidance,
                required=f.required,
                secret=(f.kind == "password" or f.secret))
    return params


def _wrap_cn(text: str, w: int):
    import textwrap
    return textwrap.wrap(text, width=w)


def _provider_menu():
    _ensure_providers_loaded()
    groups = pbase.by_kind()
    opts = []
    order = (("api", "API 接口"), ("smtp", "SMTP 邮箱"), ("local", "本机 MTA"),
             ("webhook", "Webhook / 群机器人"))
    for kind, title in order:
        for p in groups.get(kind) or []:
            tag = "" if p.is_mail else "（群消息，非邮件）"
            opts.append((p.id, "%s %s %s" % (
                p.label, ui.c(tag, "yellow") if tag else "",
                "\n        " + ui.dim(p.blurb) if p.blurb else "")))
    return opts


def cmd_setup(args) -> int:
    cfg = _cfg(args)
    _ensure_providers_loaded()

    ui.header("邮件告警渠道配置向导",
              "配置完成后会自动发送一封测试邮件")

    existing_chain = cfg.providers()
    if existing_chain:
        ui.section("当前已配置")
        _show_status(cfg)
        if not ui.confirm("重新配置发送渠道？", default=True):
            ui.note("已取消")
            return 0

    if args.provider:
        pid = args.provider
        if not pbase.get(pid):
            raise VigilError("未知的渠道 ID: %s" % pid,
                             hint="运行 `vigil mail providers` 查看可用 ID")
    else:
        ui.out()
        ui.out("  %s" % ui.dim(
            "不同渠道的区别：API 接口不依赖本机的发信能力，"
            "机房封禁 25 端口也能用；SMTP 邮箱适合已有邮箱的情况。"))
        pid = ui.choose("请选择告警发送渠道", _provider_menu(), default=1)

    cls = pbase.get(pid)
    existing = cfg.provider_params(pid)

    if pid == "smtp":
        params = _wizard_smtp(cfg, existing)
    else:
        params = _wizard_generic(cls, cfg, existing)

    prov = cls(params, {})
    problems = prov.validate()
    if problems:
        ui.problems_block(problems, "参数不完整")
        if not ui.confirm("仍然保存？（通道在补齐参数前无法发信）", default=False):
            return 1

    align = getattr(prov, "alignment_warning", None)
    if callable(align):
        w = align()
        if w:
            ui.out()
            ui.warning("发件地址对齐问题")
            for line in _wrap_cn(w, 74):
                ui.out("    " + ui.dim(line))
            if not ui.confirm("仍然使用这个发件地址？", default=False):
                params["from_address"] = ""

    cfg.set_provider_params(pid, params)
    if params.get("from_name") and not cfg.get("mail.from_name"):
        cfg.set("mail.from_name", params["from_name"])
    if params.get("from_address"):
        cfg.set("mail.from_address", params["from_address"])

    # Recipients: the single most common reason alerts are never received.
    if not cfg.recipients("alert"):
        ui.out()
        ui.section("管理员收件邮箱")
        ui.note("告警只会发到这些地址。可以填多个，用逗号分隔。")
        raw = ui.ask("收件邮箱", required=True,
                     hint_text="例如 you@example.com, alert@example.com")
        added = _add_recipients(cfg, raw)
        if added:
            ui.success("已添加 %d 个收件地址" % added)

    if not cfg.get("mail.from_address") and params.get("from_address"):
        cfg.set("mail.from_address", params["from_address"])

    if not _save(cfg):
        return 1
    ui.out()
    ui.success("渠道 %s 已保存到 %s" % (cls.label, cfg.path))

    # Auto-send the test mail, as promised by the header.
    ui.out()
    if args.no_test:
        ui.note("已跳过测试邮件（--no-test）")
        return 0
    if not cfg.recipients("alert"):
        ui.warning("尚未配置收件人，跳过测试邮件")
        ui.hint("用 `vigil mail recipient add <邮箱>` 添加后再运行 `vigil mail test`")
        return 0
    return _do_test(cfg, args)


def _add_recipients(cfg, raw: str) -> int:
    n = 0
    for part in str(raw).replace("；", ",").replace(";", ",").replace("，", ",").split(","):
        addr = part.strip()
        if not addr:
            continue
        if "@" not in addr or addr.startswith("@") or addr.endswith("@"):
            ui.warning("跳过无效地址: %s" % addr)
            continue
        if addr not in (cfg.get("mail.recipients", []) or []):
            cfg.add_recipient(addr, "alert")
            n += 1
    return n


# --------------------------------------------------------------------------
# test
# --------------------------------------------------------------------------


def _do_test(cfg, args) -> int:
    recipients = cfg.recipients("alert")
    if not recipients:
        ui.failure("没有配置收件人")
        ui.hint("运行 `vigil mail recipient add <邮箱>`")
        return 1

    rt = Router(cfg, _log())
    chain = rt.chain()
    if not chain:
        ui.failure("没有可用的发送渠道")
        ui.hint("运行 `vigil mail setup`")
        return 1

    problems = rt.preflight()
    hard = [p for p in problems if "未配置" in p]
    if hard:
        ui.problems_block(hard)
        return 1
    if problems:
        ui.problems_block(problems, "提醒（不阻止发送）")

    ui.section("通道连通性检查")
    for pid, good, detail in rt.probe():
        if good:
            ui.success("%s: %s" % (pid, detail))
        else:
            ui.warning("%s: %s" % (pid, detail))

    seq = q.next_seq()
    msg = render_test(seq, cfg.get("mail.from_address", ""),
                      rt.describe_chain(cfg.get("mail.language", "zh")),
                      host=cfg.get("hostname", ""),
                      lang=cfg.get("mail.language", "zh"))
    msg.from_address = cfg.get("mail.from_address", "")
    msg.from_name = cfg.get("mail.from_name", "")
    msg.reply_to = cfg.get("mail.reply_to", "")
    msg.kind = KIND_TEST

    ui.out()
    ui.note("正在发送测试邮件…")
    rep = rt.deliver(msg, recipients=recipients, allow_dedupe=False)

    ui.out()
    if rep.any_ok():
        for to, r in rep.results.items():
            if r.get("ok"):
                ui.success("已通过 %s 送达 %s" % (r["provider"], to))
            else:
                ui.failure("%s 发送失败: %s" % (to, r.get("detail", "")))
        ui.out()
        ui.out("  %s" % ui.bold("邮件编号 #%06d" % seq))
        ui.note("若收件箱没看到，请检查垃圾邮件目录；"
                "免费邮箱把自建域名当发件人时尤其容易被判为垃圾邮件。")
        return 0

    ui.failure("测试邮件发送失败")
    for to, r in rep.results.items():
        ui.out("    %s: %s" % (to, r.get("detail", "")))
    ui.out()
    ui.hint("运行 `vigil mail setup` 重新检查参数，或 `vigil mail providers` 换个渠道")
    return 1


def _log():
    from ..core import logging as vlog
    return vlog.get("mail")


def cmd_test(args) -> int:
    cfg = _cfg(args)
    if args.to:
        cfg.data.setdefault("mail", {})["recipients"] = \
            [a.strip() for a in args.to.split(",") if a.strip()]
    return _do_test(cfg, args)


# --------------------------------------------------------------------------
# recipients
# --------------------------------------------------------------------------


def cmd_recipient(args) -> int:
    cfg = _cfg(args)
    action = args.action or "list"

    if action == "list":
        rec = cfg.recipients("alert")
        if args.json:
            ui.out(_json.dumps(rec, ensure_ascii=False))
            return 0
        ui.section("管理员收件邮箱（告警接收人）")
        if not rec:
            ui.note("尚未配置 —— 服务器不会发出任何告警邮件")
            ui.hint("运行 `vigil mail recipient add <邮箱>`")
            return 0
        for r in rec:
            ui.bullet(r)
        return 0

    if action in ("add", "remove", "rm"):
        if not args.address:
            raise VigilError("缺少邮箱地址",
                             hint="例如 vigil mail recipient add you@example.com")
        if action == "add":
            n = _add_recipients(cfg, args.address)
            if not n:
                ui.note("地址已存在，未重复添加")
                return 0
            if not _save(cfg):
                return 1
            ui.success("已添加 %d 个收件地址" % n)
            ui.note("当前收件人: %s" % ", ".join(cfg.recipients("alert")))
            return 0
        removed = 0
        for part in args.address.replace("，", ",").split(","):
            if cfg.remove_recipient(part.strip(), "alert"):
                removed += 1
        if not removed:
            ui.note("没有找到匹配的地址")
            return 0
        if not _save(cfg):
            return 1
        ui.success("已移除 %d 个地址" % removed)
        return 0

    if action == "login":
        rec = cfg.recipients("login")
        if args.address:
            for part in args.address.replace("，", ",").split(","):
                if part.strip():
                    cfg.add_recipient(part.strip(), "login")
            if not _save(cfg):
                return 1
            ui.success("登录通知收件人: %s" % ", ".join(cfg.recipients("login")))
            return 0
        ui.section("登录通知收件人")
        for r in rec:
            ui.bullet(r)
        if not rec:
            ui.note("未单独设置，将使用告警收件人")
        return 0

    raise VigilError("未知操作: %s" % action)


# --------------------------------------------------------------------------
# status / quota / domain
# --------------------------------------------------------------------------


def cmd_status(args) -> int:
    cfg = _cfg(args)
    st = mail_stats(cfg)
    if args.json:
        ui.out(_json.dumps(st, ensure_ascii=False, indent=2))
        return 0
    ui.header("告警通道状态")
    _show_status(cfg)
    ui.section("发送统计")
    ui.kv("当前邮件编号", "#%06d" % st["sequence"])
    total = st["quota_total"]
    if total:
        used = st["quota_used"]
        pct = int(used * 100 / total) if total else 0
        ui.kv("今日额度（UTC）", "%d / %d（%d%%）" % (used, total, pct),
              "red" if pct >= 95 else ("yellow" if pct >= 80 else ""))
    else:
        ui.kv("今日额度", "未限制")
    ui.kv("积压待补发", st["overflow_files"],
          "yellow" if st["overflow_files"] else "")

    ui.section("通道连通性")
    rt = Router(cfg, _log())
    if not rt.chain():
        ui.warning("尚未配置任何渠道")
    for pid, good, detail in rt.probe():
        (ui.success if good else ui.warning)("%s: %s" % (pid, detail))

    prob = rt.preflight()
    ui.problems_block(prob)
    return 0



def cmd_priority(args) -> int:
    """Show or change the order channels are tried in.

    The chain is tried in order and the first channel that accepts the
    message wins, so this is the single knob that decides which provider
    carries your alerts. It was previously only settable by editing JSON.
    """
    cfg = _cfg(args)
    chain = list(cfg.providers() or [])
    if not chain:
        ui.note("尚未配置任何渠道")
        ui.hint("vigil mail setup")
        return 1

    def label(entry, idx):
        pid = entry.get("provider", "?")
        who = entry.get("from_address") or entry.get("host") or ""
        rank = entry.get("priority")
        shown = "优先级 %s" % rank if rank is not None else "按配置顺序"
        return "%-10s %-42s %s" % (pid, who[:40], shown)

    if args.order:
        wanted = [p.strip() for p in args.order.split(",") if p.strip()]
        known = {e.get("provider") for e in chain}
        unknown = [p for p in wanted if p not in known]
        if unknown:
            ui.failure("没有配置这些渠道：%s" % "、".join(unknown))
            return 1
        # Rewritten in the requested order, with explicit ranks so the
        # intent survives any later reordering of the JSON.
        reordered = []
        for i, pid in enumerate(wanted):
            for entry in chain:
                if entry.get("provider") == pid:
                    entry = dict(entry)
                    entry["priority"] = i + 1
                    reordered.append(entry)
                    break
        for entry in chain:                       # anything not named goes last
            if entry.get("provider") not in wanted:
                entry = dict(entry)
                entry["priority"] = len(wanted) + 1
                reordered.append(entry)
        cfg.set("mail.providers", reordered)
        cfg.save()
        ui.header("发送优先级已更新", "按顺序尝试，第一个接受的胜出")
        for i, e in enumerate(reordered, 1):
            ui.kv("%d" % i, "%s  %s" % (e.get("provider"),
                                        e.get("from_address") or e.get("host") or ""))
        return 0

    ui.header("发送优先级", "按顺序尝试，第一个接受的渠道胜出")
    for i, e in enumerate(chain, 1):
        ui.kv("%d" % i, label(e, i))
    if ui.is_interactive() and not args.yes:
        ui.out()
        ui.note("输入新顺序，例如 `smtp,resend` 让 QQ 优先。")
        order = ui.ask("新顺序（留空不改）", "")
        if order:
            class _A:
                pass
            a = _A()
            a.order = order
            a.config = args.config
            return cmd_priority(a)
    else:
        ui.hint("修改顺序：vigil mail priority --order smtp,resend")
    return 0

def cmd_quota(args) -> int:
    cfg = _cfg(args)
    if args.reset:
        # Only ever done by an operator who understands the provider's
        # billing period: the counter exists to stop an alert storm from
        # draining a metered quota, not to enforce the vendor's limits.
        before = q.quota_used()
        from ..core.state import write_text
        write_text(q._quota_path(), "0")
        ui.success("已把今日额度计数从 %d 重置为 0" % before)
        return 0
    total = int(cfg.get("mail.daily_quota", 100) or 0)
    used = q.quota_used()
    ui.kv("统计日期（UTC）", q._quota_day())
    ui.kv("已用 / 上限", "%d / %s" % (used, total if total else "不限"))
    ui.kv("剩余", q.quota_remaining(total) if total else "不限")
    return 0


def cmd_domain(args) -> int:
    """Inspect / verify the sending domain for API-style providers."""
    cfg = _cfg(args)
    _ensure_providers_loaded()
    target = args.provider or ""
    candidates = []
    for entry in cfg.providers():
        pid = entry.get("provider")
        cls = pbase.get(pid)
        if cls is None:
            continue
        if not hasattr(cls, "check_domain"):
            continue
        if target and pid != target:
            continue
        params = cfg.provider_params(pid)
        candidates.append(cls(params, {}))

    if not candidates:
        ui.note("当前配置的渠道中，没有需要验证发信域名的（只有 API 类渠道需要）。")
        return 0

    rc = 0
    for prov in candidates:
        ui.section("渠道 %s" % prov.label_for())
        dom = getattr(prov, "domain_of_from", lambda: "")()
        if not dom:
            ui.warning("未设置发件地址，无法确定要验证哪个域名")
            rc = 1
            continue
        ui.kv("发信域名", dom)

        # DNS first, and independently of the API. The records decide whether
        # a message lands in the inbox, and they are readable with a
        # sending-scoped key that the domain endpoints refuse -- so asking the
        # API and stopping there would report "fine" for a domain whose mail
        # is being filtered.
        audit = None
        if hasattr(prov, "audit_dns"):
            try:
                audit = prov.audit_dns(dom)
            except Exception:                           # noqa: BLE001
                audit = None
        if audit is not None:
            ui.out()
            for key, label in (("spf", "SPF"), ("dkim", "DKIM"),
                               ("dmarc", "DMARC"), ("mx", "MX")):
                vals = audit.get(key) or []
                if vals:
                    ui.kv(label, str(vals[0])[:74], "green")
                else:
                    ui.kv(label, "缺失", "yellow")
            if audit.get("problems"):
                ui.out()
                for problem in audit["problems"]:
                    ui.warning(problem)
                rc = 1
                if hasattr(prov, "suggested_records"):
                    ui.out()
                    ui.note("在域名服务商处添加以下记录，然后等 DNS 生效：")
                    for rtype, name, value, why in prov.suggested_records(dom):
                        ui.bullet("%s  %s" % (rtype, name))
                        ui.out("        %s" % ui.c(value, "cyan"))
                        ui.out("        %s" % ui.dim("# %s" % why))
            else:
                ui.success("SPF / DKIM / DMARC 齐全，投递认证没问题")

        try:
            good, detail = prov.check_domain()
        except Exception as e:                          # noqa: BLE001
            ui.failure("API 查询失败: %s" % e)
            continue
        ui.out()
        if good:
            ui.success(detail)
            continue
        rc = 1
        ui.failure(detail)
        try:
            records = prov.dns_records()
        except Exception:                               # noqa: BLE001
            records = []
        if not records and hasattr(prov, "list_domains"):
            try:
                found = prov.get_domain(dom)
                if not found and ui.confirm("该域名尚未在本账号注册，现在创建？",
                                            default=True):
                    prov.create_domain(dom)
                    records = prov.dns_records()
            except Exception as e:                      # noqa: BLE001
                ui.warning("创建域名失败: %s" % e)
        if records:
            ui.out()
            ui.out("  %s" % ui.bold("请到域名服务商处添加以下 DNS 记录："))
            rows = []
            for r in records:
                rows.append([r.get("type", ""), r.get("name", ""),
                             (r.get("value") or "")[:52],
                             str(r.get("ttl") or ""),
                             str(r.get("priority") or "")])
            ui.table(rows, headers=["类型", "主机记录", "记录值", "TTL", "优先级"])
            ui.out()
            ui.note("添加后等待 DNS 生效（通常几分钟），再运行本命令复查。")
            if ui.confirm("现在尝试触发验证？", default=False):
                try:
                    did = (prov.get_domain(dom) or {}).get("id")
                    if did:
                        prov.verify_domain(did)
                        ui.success("已提交验证请求，稍后重新运行本命令查看结果")
                except Exception as e:                  # noqa: BLE001
                    ui.warning("触发验证失败: %s" % e)
        else:
            ui.hint("确认 %s 已在服务商后台完成域名验证，并已生成 SPF / DKIM 记录" % dom)
    return rc



# --------------------------------------------------------------------------
# sender identity (hostname / display name / from / reply-to)
# --------------------------------------------------------------------------


def cmd_send(args) -> int:
    """Send an operator message through the configured channel.

    Exists because "tell me before you do something that will generate
    alerts" should be a command, not a habit. Anything that is about to
    produce a burst of automated mail -- a test that injects synthetic
    attacks, a migration, a maintenance window -- can announce itself first,
    through the same channel and with the same journal entry as every other
    message this program sends.

    Deliberately plain: no dedupe, no quota games, no severity games. If the
    operator asks for a message, they get a message, and the journal records
    exactly what was sent to whom.
    """
    from ..mail import send_text
    from ..mail.message import SEV_INFO

    cfg = load_config(args.config or None)
    if not args.subject:
        ui.failure("请给出 --subject")
        return 1
    body = args.text or ""
    if args.text_file:
        try:
            with open(args.text_file, "r", encoding="utf-8",
                      errors="replace") as fh:
                body = fh.read()
        except OSError as e:
            ui.failure("读取 %s 失败：%s" % (args.text_file, e))
            return 1
    if not body:
        body = "(无正文)"

    recipients = [r.strip() for r in (args.to or "").split(",") if r.strip()]
    if not recipients:
        recipients = cfg.recipients("alert")
    if not recipients:
        ui.failure("没有收件人：先运行 vigil mail setup")
        return 1

    severity = {"info": SEV_INFO, "warn": "WARN", "crit": "CRIT"}.get(
        args.severity, SEV_INFO)
    rep = send_text(args.subject, body, severity=severity, cfg=cfg,
                    log=_log(), recipients=recipients, allow_dedupe=False)
    if rep.any_ok():
        ui.success("已发出：%s" % rep.summary())
    elif rep.skipped and "风暴" in rep.skipped:
        # Parked, not lost. Storm control deliberately defers bursts, and the
        # message is replayed by vigil-maild -- reporting that as "发送失败"
        # made a working safety feature look like a broken channel during the
        # stress test, where the three "failed" alerts had in fact all been
        # delivered as backlog replays.
        ui.warning("已延后投递：%s" % rep.skipped)
        ui.note("消息已进入积压队列，会在下一轮由 vigil-maild 补发；"
                "这是告警风暴抑制，不是投递失败")
    else:
        ui.failure("发送失败：%s" % rep.summary())
    ui.kv("收件人", "、".join(recipients))
    return 0 if (rep.any_ok() or rep.overflowed) else 1


def cmd_sender(args) -> int:
    """View or change how this server introduces itself in an alert.

    Two names matter and they are easy to confuse:

    * **主机显示名** appears in the alert *body* ("主机: ..."). It defaults
      to the system hostname, which on a cloud box is usually an unhelpful
      string like ``ip-10-0-3-17`` -- set it to something you recognise at
      a glance when several servers share one inbox.
    * **发件人显示名** appears in the mail client's From column.
    """
    cfg = _cfg(args)
    changed = []
    cur_host = cfg.get("hostname", "")
    cur_name = cfg.get("mail.from_name", "")
    cur_from = cfg.get("mail.from_address", "")
    cur_reply = cfg.get("mail.reply_to", "")

    # Default the hostname to the system one on first use, so the value is
    # always concrete rather than empty.
    if not cur_host:
        import socket
        cur_host = socket.gethostname()

    if args.hostname:
        cfg.set("hostname", args.hostname.strip())
        changed.append(("主机显示名", args.hostname.strip()))
    if args.name:
        cfg.set("mail.from_name", args.name.strip())
        changed.append(("发件人显示名", args.name.strip()))
    if args.address is not None and args.address != "":
        cfg.set("mail.from_address", args.address.strip())
        changed.append(("发件地址", args.address.strip()))
    if args.reply_to:
        cfg.set("mail.reply_to", args.reply_to.strip())
        changed.append(("回复地址", args.reply_to.strip()))

    if args.clear_reply_to:
        cfg.set("mail.reply_to", "")
        changed.append(("回复地址", "（已清空）"))

    # A per-channel from_name shadows the global one, so offer to propagate.
    if args.name and not args.keep_channel_names:
        touched = []
        for entry in cfg.providers():
            pid = entry.get("provider", "")
            if not pid:
                continue
            params = cfg.provider_params(pid)
            if params.get("from_name"):
                params["from_name"] = args.name.strip()
                cfg.set_provider_params(pid, params)
                touched.append(pid)
        if touched:
            changed.append(("同步到渠道", ", ".join(touched)))

    if changed:
        if not _save(cfg):
            return 1
        ui.out()
        for key, value in changed:
            ui.success("%s = %s" % (key, value))
        if any(k == "发件人显示名" for k, _ in changed):
            ui.note("显示名会在下一封邮件生效（无需重启服务）")
        return 0

    # No flags: show the current identity.
    if args.json:
        ui.out(_json.dumps({
            "hostname": cur_host, "from_name": cur_name,
            "from_address": cur_from, "reply_to": cur_reply,
        }, ensure_ascii=False, indent=2))
        return 0
    ui.header("本机在告警中的身份")
    ui.kv("主机显示名", cur_host or "（未设置）",
          "" if cur_host else "yellow")
    ui.kv("发件人显示名", cur_name or "（未设置）")
    ui.kv("发件地址", cur_from or "（未设置，将使用渠道内置值）")
    ui.kv("回复地址", cur_reply or "（未设置）")
    ui.out()
    ui.section("修改方式")
    ui.out("    vigil mail sender --hostname \"阿里云-香港-01\"")
    ui.out("    vigil mail sender --name \"站务通知\"")
    ui.out("    vigil mail sender --address alerts@example.com")
    ui.out("    vigil mail sender --reply-to you@example.com")
    ui.out()
    ui.note("主机显示名出现在邮件正文，用于区分多台服务器；")
    ui.note("发件人显示名出现在收件箱的发件人一栏。")
    return 0

# --------------------------------------------------------------------------
# register
# --------------------------------------------------------------------------


def register(sub) -> None:
    p = sub.add_parser("mail", help="邮件/Webhook 告警通道配置与测试",
                       description="配置服务器告警的发送渠道与收件人。"
                                   "支持 API 接口、SMTP 邮箱、本机 MTA 与群机器人，"
                                   "按顺序自动降级。")
    ps = p.add_subparsers(dest="mail_action", metavar="<操作>")

    sp = ps.add_parser("setup", help="交互式配置发送渠道（推荐）")
    sp.add_argument("--provider", default="",
                    help="直接指定渠道 ID，跳过选择菜单")
    sp.add_argument("--no-test", action="store_true", help="配置后不自动发测试邮件")
    sp.set_defaults(func=cmd_setup)

    sp = ps.add_parser("test", help="发送一封测试邮件")
    sp.add_argument("--to", default="", help="临时指定收件人（逗号分隔）")
    sp.set_defaults(func=cmd_test)

    sp = ps.add_parser(
        "send", help="给管理员发一条消息（例如：接下来要做会产生告警的操作）",
        description="通过已配置的渠道发一条普通消息。用途是让「即将产生一批"
                    "自动告警的操作」先自我声明——测试、迁移、维护窗口——"
                    "走同一条通道、同样记入日志。")
    sp.add_argument("--subject", required=True, help="主题")
    sp.add_argument("--text", default="", help="正文")
    sp.add_argument("--text-file", default="", help="从文件读正文")
    sp.add_argument("--to", default="", help="临时收件人（逗号分隔）")
    sp.add_argument("--severity", default="info",
                    choices=("info", "warn", "crit"))
    sp.set_defaults(func=cmd_send)

    sp = ps.add_parser("recipient", help="管理管理员收件邮箱")
    sp.add_argument("action", nargs="?", default="list",
                    choices=("list", "add", "remove", "rm", "login"))
    sp.add_argument("address", nargs="?", default="", help="邮箱地址（可多个，逗号分隔）")
    sp.set_defaults(func=cmd_recipient)

    sp = ps.add_parser("providers", help="列出所有支持的发送渠道")
    sp.set_defaults(func=cmd_providers)

    sp = ps.add_parser("status", help="查看通道配置与连通性")
    sp.set_defaults(func=cmd_status)

    sp = ps.add_parser("priority", help="查看/修改发送渠道的优先级顺序",
                       description="渠道按顺序尝试，第一个接受的胜出。"
                                   "优先级可自定义，默认按配置顺序。")
    sp.add_argument("--order", default="",
                    help="新顺序，逗号分隔，如 smtp,resend")
    sp.add_argument("--yes", "-y", action="store_true")
    sp.set_defaults(func=cmd_priority)

    sp = ps.add_parser("quota", help="查看发送额度")
    sp.add_argument("--reset", action="store_true", help="把今日计数归零")
    sp.set_defaults(func=cmd_quota)

    sp = ps.add_parser("sender",
                       help="查看/修改主机显示名、发件人显示名与发件地址",
                       description="设置服务器在告警邮件里的自我介绍："
                                   "正文中的主机名、发件人一栏的显示名、"
                                   "发件地址与回复地址。")
    sp.add_argument("--hostname", default="", help="主机显示名（出现在邮件正文）")
    sp.add_argument("--name", default="", help="发件人显示名（出现在收件箱）")
    sp.add_argument("--address", default=None, help="发件地址")
    sp.add_argument("--reply-to", dest="reply_to", default="", help="回复地址")
    sp.add_argument("--clear-reply-to", action="store_true", help="清空回复地址")
    sp.add_argument("--keep-channel-names", action="store_true",
                    help="只改全局显示名，不同步到各渠道")
    sp.set_defaults(func=cmd_sender)

    sp = ps.add_parser("domain", help="查看/验证 API 渠道的发信域名与 DNS 记录")
    sp.add_argument("--provider", default="", help="只处理指定渠道")
    sp.set_defaults(func=cmd_domain)
