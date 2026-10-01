"""Minimal internationalisation.

The product is used on Chinese control-panel hosts and on generic Linux
boxes, so every user facing string goes through :func:`t` and both tables
below are kept complete. Code, comments and log lines stay in English:
logs are read by tools and by people who may not share a language, and a
half translated log is worse than an untranslated one.

Language resolution order:
    1. explicit ``--lang`` / ``VIGIL_LANG``
    2. ``LC_ALL`` / ``LC_MESSAGES`` / ``LANG``
    3. ``zh`` when the locale looks Chinese, otherwise ``en``
"""
from __future__ import annotations

import os

_LANG = ""

ZH = {
    # -- generic ---------------------------------------------------------
    "ok": "正常",
    "warn": "警告",
    "crit": "严重",
    "error": "错误",
    "yes": "是",
    "no": "否",
    "none": "无",
    "unknown": "未知",
    "not_available": "不可用",
    "done": "完成",
    "failed": "失败",
    "skipped": "已跳过",
    "cancelled": "已取消",
    "confirm": "确认",
    "choose": "请选择",
    "invalid_choice": "输入无效，请重新选择",
    "required": "必填",
    "optional": "可留空",
    "root_required": "此操作需要 root 权限，请使用 sudo 重新运行",

    # -- project ---------------------------------------------------------
    "project_tagline": "服务器安全 · 完整性 · 告警防护系统",
    "help_epilog": "更多帮助见 docs/ 目录，或运行 `vigil <命令> --help`",

    # -- install ---------------------------------------------------------
    "install_welcome": "欢迎使用 Vigil 安装向导",
    "install_detecting": "正在检测本机环境…",
    "install_confirm": "确认开始安装？",
    "install_done": "安装完成",
    "install_summary": "安装摘要",
    "install_already": "Vigil 已安装（版本 {version}）。使用 `vigil upgrade` 升级，或 `vigil install --force` 重装。",

    # -- mail ------------------------------------------------------------
    "mail_setup_title": "邮件渠道配置向导",
    "mail_choose_provider": "请选择邮件发送渠道",
    "mail_provider_params": "请填写 {provider} 的参数",
    "mail_recipients": "管理员收件邮箱（告警接收人）",
    "mail_recipients_hint": "可填多个，用逗号分隔。至少填一个，否则收不到任何告警。",
    "mail_from": "发件人地址",
    "mail_from_name": "发件人显示名称",
    "mail_test_sending": "正在发送测试邮件…",
    "mail_test_ok": "测试邮件已发出（编号 #{seq}），请查收 {to}",
    "mail_test_fail": "测试邮件发送失败：{error}",
    "mail_no_provider": "尚未配置任何邮件渠道，请先运行 `vigil mail setup`",

    # -- gate ------------------------------------------------------------
    "gate_none": "未检测到已安装的登录防护",
    "gate_detected": "检测到已存在的 {kind} 配置",
    "gate_adopt_hint": "可用 `vigil gate adopt` 接入现有配置，无需重装",

    # -- doctor ----------------------------------------------------------
    "doctor_title": "环境自检",
}


EN = {
    "ok": "OK",
    "warn": "WARN",
    "crit": "CRIT",
    "error": "ERROR",
    "yes": "yes",
    "no": "no",
    "none": "none",
    "unknown": "unknown",
    "not_available": "not available",
    "done": "done",
    "failed": "failed",
    "skipped": "skipped",
    "cancelled": "cancelled",
    "confirm": "Confirm",
    "choose": "Choose",
    "invalid_choice": "Invalid choice, please try again",
    "required": "required",
    "optional": "optional",
    "root_required": "This operation needs root; re-run with sudo",

    "project_tagline": "Server security, integrity and alerting guard",
    "help_epilog": "See docs/ for more, or run `vigil <command> --help`",

    "install_welcome": "Welcome to the Vigil installer",
    "install_detecting": "Detecting host environment...",
    "install_confirm": "Proceed with installation?",
    "install_done": "Installation complete",
    "install_summary": "Installation summary",
    "install_already": "Vigil is already installed (version {version}). Use `vigil upgrade`, or `vigil install --force`.",

    "mail_setup_title": "Mail channel setup",
    "mail_choose_provider": "Choose a delivery channel",
    "mail_provider_params": "Enter the parameters for {provider}",
    "mail_recipients": "Administrator recipient address(es)",
    "mail_recipients_hint": "Comma separated. At least one is required or no alert can reach you.",
    "mail_from": "Sender address",
    "mail_from_name": "Sender display name",
    "mail_test_sending": "Sending test message...",
    "mail_test_ok": "Test message sent (id #{seq}) to {to}",
    "mail_test_fail": "Test message failed: {error}",
    "mail_no_provider": "No mail channel configured yet; run `vigil mail setup`",

    "gate_none": "No login gate detected",
    "gate_detected": "Existing {kind} configuration detected",
    "gate_adopt_hint": "Run `vigil gate adopt` to reuse it without reinstalling",

    "doctor_title": "Host self-check",
}

_TABLES = {"zh": ZH, "en": EN}


def set_language(lang: str = "") -> str:
    """Pin the language. Empty string restores auto-detection."""
    global _LANG
    _LANG = (lang or "").strip().lower()
    return language()


def language() -> str:
    global _LANG
    if _LANG in _TABLES:
        return _LANG
    forced = os.environ.get("VIGIL_LANG", "").strip().lower()
    if forced in _TABLES:
        return forced
    blob = " ".join(os.environ.get(k, "") for k in
                    ("LC_ALL", "LC_MESSAGES", "LANG"))
    if "zh" in blob.lower() or "chinese" in blob.lower():
        return "zh"
    return "zh" if not blob.strip() else "en"


def t(key: str, **kw) -> str:
    """Translate *key*, formatting with *kw*. Never raises."""
    table = _TABLES.get(language(), EN)
    text = table.get(key) or EN.get(key) or key
    if kw:
        try:
            return text.format(**kw)
        except (KeyError, IndexError, ValueError):
            return text
    return text
