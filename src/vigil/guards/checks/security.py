"""System-security checks (group ``security``).

Ported from ``c_uid0`` / ``c_preload`` / ``c_perm`` / ``c_phpconfig`` /
``c_panel_auth`` / ``c_suspicious``.

Two of these were rewritten rather than transliterated, because the originals
carried defects that produced either false positives or false negatives:

* ``file_permissions`` uses **two** masks. Write access is checked with
  ``0o022``; "readable by other" is a separate ``0o007`` check that only
  applies to credential files. The original conflated them, so a normal
  ``0640 root:shadow`` /etc/shadow was reported as exposed.
* ``php_config`` no longer hardcodes a PHP version/path. The ``php.ini``
  locations are derived from the PHP-FPM binaries :mod:`vigil.core.detect`
  found on this host.
* ``panel_auth`` does nothing (and returns OK) when no control panel is
  present, and otherwise probes the panel's local admin path over loopback
  using a ``Host`` header taken from the config.
"""
from __future__ import annotations

import os
import pwd
import re
import stat

from . import util
from .base import (CRIT, G_SECURITY, OK, WARN, Check, CheckContext,
                   CheckResult, register)
from ...core import shell

#: (path, forbid_world_read). Every file additionally must not be group/other
#: writable. /etc/shadow is normally 0640 root:shadow -- group read is fine,
#: world read is not.
_PERM_FILES = (
    ("/etc/shadow", True),
    ("/etc/gshadow", True),
    ("/etc/passwd", False),
    ("/etc/sudoers", True),
    ("/etc/ssh/sshd_config", False),
)

#: Shells that mean "this account can log in interactively".
_NOLOGIN = ("/sbin/nologin", "/usr/sbin/nologin", "/bin/false",
            "/usr/bin/false", "/bin/sync", "/sbin/shutdown", "/sbin/halt")

#: How many individual entries to spell out in a mail body.
_DETAIL_CAP = 6


def _owner(path: str) -> str:
    try:
        st = os.stat(path)
    except OSError:
        return "?"
    try:
        user = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        user = str(st.st_uid)
    try:
        import grp
        group = grp.getgrgid(st.st_gid).gr_name
    except (ImportError, KeyError):
        group = str(st.st_gid)
    return "%s:%s" % (user, group)


@register
class RootAccounts(Check):
    id = "root_accounts"
    label = "uid=0 账号"
    label_en = "uid 0 accounts"
    group = G_SECURITY
    description = "检查 /etc/passwd 中 root 之外 uid=0 的后门账号"

    def run(self, ctx: CheckContext) -> CheckResult:
        try:
            with open("/etc/passwd", "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError as exc:
            return CheckResult(WARN, "无法读取 /etc/passwd：%s" % exc)

        bad, root_seen, login_accounts = [], False, []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split(":")
            if len(fields) < 7:
                continue
            name, _pw, uid, _gid, _gecos, home, sh = fields[:7]
            if uid == "0":
                if name == "root":
                    root_seen = True
                else:
                    bad.append("%s（uid=0，家目录 %s，shell %s）" % (name, home, sh))
            elif sh and sh not in _NOLOGIN:
                login_accounts.append(name)

        if bad:
            return CheckResult(CRIT,
                               "发现 root 之外 **uid=0** 的账号（攻击者最常用的后门手法，"
                               "该账号拥有与 root 完全相同的权限）：\n       %s\n"
                               "       若非你本人创建，请立即 `userdel -r <账号>` "
                               "并全面排查入侵痕迹。"
                               % "\n       ".join(bad[:8]))
        if not root_seen:
            return CheckResult(WARN, "在 /etc/passwd 中未找到 uid=0 的 root 账号，"
                                     "/etc/passwd 可能已被篡改，请人工核查")
        return CheckResult(OK, "无异常 root 权限账号（可登录账号 %d 个）"
                           % len(login_accounts))


@register
class PreloadHijack(Check):
    id = "preload"
    label = "预加载劫持"
    label_en = "ld.so.preload hijack"
    group = G_SECURITY
    description = "检查 /etc/ld.so.preload 是否被写入全局预加载库（rootkit 手法）"

    def run(self, ctx: CheckContext) -> CheckResult:
        path = "/etc/ld.so.preload"
        if not os.path.exists(path):
            return CheckResult(OK, "无 /etc/ld.so.preload（正常）")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError as exc:
            return CheckResult(WARN, "无法读取 /etc/ld.so.preload：%s" % exc)

        entries = [l.strip() for l in content.splitlines()
                   if l.strip() and not l.strip().startswith("#")]
        if entries:
            return CheckResult(CRIT,
                               "/etc/ld.so.preload 存在预加载项（**疑似 rootkit**）：\n"
                               "       %s\n"
                               "       恶意库可劫持所有进程的函数调用以隐藏自身、窃取凭据，"
                               "常规查杀工具难以发现。该文件正常应为空或不存在；"
                               "请清空后全盘查杀。"
                               % "\n       ".join(entries[:6]))
        return CheckResult(OK, "/etc/ld.so.preload 为空（仅注释或空白）")


@register
class FilePermissions(Check):
    id = "file_permissions"
    label = "文件权限"
    label_en = "File permissions"
    group = G_SECURITY
    description = "检查关键系统文件的权限（可写/口令文件可被他人读取）"

    def run(self, ctx: CheckContext) -> CheckResult:
        extra = []
        for item in (ctx.copt("file_permissions", "files", []) or []):
            if isinstance(item, (list, tuple)) and item:
                extra.append((str(item[0]), bool(item[1]) if len(item) > 1 else True))
        files = list(_PERM_FILES) + extra

        problems = []
        for path, no_other_read in files:
            try:
                st = os.stat(path)
            except OSError:
                continue
            mode = stat.S_IMODE(st.st_mode)
            who = _owner(path)
            if mode & 0o022:
                problems.append("%s 权限 %04o（属主 %s）—— 可被组或其他用户写入，"
                                "存在被篡改风险" % (path, mode, who))
            if no_other_read and (mode & 0o007):
                problems.append("%s 权限 %04o（属主 %s）—— 可被其他用户读取，"
                                "存在凭据泄露风险（正常应为 0640 root:shadow）"
                                % (path, mode, who))
        if problems:
            return CheckResult(CRIT, "关键文件权限异常：\n       %s\n"
                                     "       请立即修正权限并检查是谁、何时修改的"
                                     "（`stat <文件>` 查看变更时间）。"
                               % "\n       ".join(dict.fromkeys(problems)))
        return CheckResult(OK, "关键文件权限正常（已检查 %d 个）" % len(files))


@register
class PhpConfig(Check):
    id = "php_config"
    label = "PHP 安全配置"
    label_en = "PHP configuration"
    group = G_SECURITY
    description = "检查 php.ini 中 disable_functions / open_basedir / allow_url_include"

    def run(self, ctx: CheckContext) -> CheckResult:
        inis = self._ini_paths(ctx)
        if not inis:
            return CheckResult(OK, "未检测到 PHP 配置文件，跳过检查")

        hits = []
        for ini in inis:
            try:
                with open(ini, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            m = re.search(r"^\s*disable_functions\s*=\s*(.*)$", text, re.M)
            if m and not m.group(1).strip():
                hits.append("%s 的 disable_functions 为空（危险函数未被禁用，"
                            "WebShell 可直接执行系统命令）" % ini)
            if re.search(r"^\s*allow_url_include\s*=\s*On", text, re.M | re.I):
                hits.append("%s 开启了 allow_url_include（易被用于远程文件包含）" % ini)
            m = re.search(r"^\s*open_basedir\s*=\s*(.*)$", text, re.M)
            if m and not m.group(1).strip():
                hits.append("%s 未设置 open_basedir（WebShell 可读取任意目录）" % ini)
        if hits:
            return CheckResult(WARN, "PHP 安全配置存在风险：\n       %s\n"
                                     "       这会拆掉 WebShell 面前的最后一道防线，"
                                     "请对照备份恢复。"
                               % "\n       ".join(dict.fromkeys(hits)))
        return CheckResult(OK, "PHP 关键安全配置正常（已检查 %d 个 ini）" % len(inis))

    @staticmethod
    def _ini_paths(ctx: CheckContext) -> list:
        candidates = []
        for binary in (ctx.env.get("php_fpm") or {}).get("binaries") or []:
            prefix = os.path.dirname(os.path.dirname(os.path.realpath(binary)))
            candidates.append(os.path.join(prefix, "etc", "php.ini"))
            candidates.append(os.path.join(prefix, "etc", "php-cli.ini"))
        for pattern in (ctx.copt("php_config", "ini_paths", []) or []):
            candidates.extend(util.expand_globs([str(pattern)]))
        out = []
        for path in candidates:
            if os.path.isfile(path) and path not in out:
                out.append(path)
        return out


@register
class PanelAuth(Check):
    id = "panel_auth"
    label = "面板入口认证"
    label_en = "Panel entry authentication"
    group = G_SECURITY
    description = "实测管理面板入口是否仍拦截未认证访问（未验证不应返回 200）"

    def run(self, ctx: CheckContext) -> CheckResult:
        panel = ctx.env.get("bt_panel") or {}
        if not panel.get("present"):
            return CheckResult(OK, "未检测到管理面板，跳过入口认证检查")

        # Resolution order matters. `server_name` is often the nginx
        # catch-all `_`, which is not a hostname anyone can connect to -- the
        # probe then failed every cycle and reported the panel as down. The
        # check runs on the panel's own machine, so loopback is both the
        # correct fallback and the most reliable target.
        host = (ctx.cfg.get("gate.bt_panel.domain", "") or "").strip()
        if not host:
            candidate = (ctx.cfg.get("gate.bt_panel.server_name", "") or "").strip()
            if candidate and candidate not in ("_", "-", "*"):
                host = candidate
        if not host:
            host = "127.0.0.1"

        if not shell.have("curl"):
            return CheckResult(WARN, "未安装 curl，无法实测面板入口认证")

        try:
            port = int(panel.get("port")
                       or ctx.cfg.get("gate.bt_panel.panel_port", 0) or 0)
        except (TypeError, ValueError):
            port = 0
        if port <= 0:
            port = 443
        admin = (panel.get("admin_path")
                 or ctx.cfg.get("gate.bt_panel.admin_path", "") or "").strip()
        if not admin.startswith("/"):
            admin = "/" + admin
        admin = admin.rstrip("/") or "/"

        code = ""
        for scheme in ("https", "http"):
            code = self._probe(host, port, admin, scheme)
            if code and code != "000":
                break
        if not code or code == "000":
            return CheckResult(WARN, "面板入口无响应（https/http 均未返回状态码，"
                                     "面板可能未运行或未监听 %d）" % port)
        if code == "404":
            # The panel answers 404 for the root and for paths it does not
            # recognise -- hiding its own existence from scanners. That is
            # the *desired* behaviour, not an outage, and treating it as one
            # produced a warning on every cycle.
            return CheckResult(OK, "面板入口不响应未认证探测（%s 返回 404，"
                                   "属于面板的隐藏行为）" % admin)
        if code == "200":
            return CheckResult(CRIT,
                               "面板入口认证**已失效**：未认证请求 %s 直接返回 200，"
                               "登录页对公网裸露。面板一旦被攻破等同于服务器完全失守，"
                               "请立即检查站点/反向代理配置是否被重写。"
                               % admin)
        if code in ("301", "302", "303", "307", "308", "401", "403"):
            return CheckResult(OK, "面板入口认证生效（未认证访问 %s 返回 %s）"
                               % (admin, code))
        return CheckResult(WARN, "面板入口返回异常状态码 %s（%s），期望 3xx/401/403"
                           % (code, admin))

    @staticmethod
    def _probe(host: str, port: int, admin: str, scheme: str) -> str:
        ok, out, _err = shell.run(
            ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", "8",
             "--resolve", "%s:%d:127.0.0.1" % (host, port),
             "-H", "Host: %s" % host,
             "%s://%s%s" % (scheme, host, admin)], timeout=12)
        return (out or "").strip() if ok else ""


@register
class SuspiciousProcesses(Check):
    id = "suspicious_procs"
    label = "可疑进程"
    label_en = "Suspicious processes"
    group = G_SECURITY
    description = "可执行文件已被删除、或从临时目录运行的进程（恶意程序典型特征）"

    def run(self, ctx: CheckContext) -> CheckResult:
        try:
            hits = util.suspect_procs_detail()
        except OSError as exc:
            return CheckResult(OK, "无法枚举进程：%s" % exc)
        if not hits:
            return CheckResult(OK, "无可疑进程")

        # A browser automation tool unpacks a browser release into a temp
        # directory and runs it from there -- structurally the same as "a
        # binary running out of /tmp". `browser_automation` has already
        # required a release layout *and* a trusted driving process; only
        # those are set aside, and they are still named here so the operator
        # can see what was skipped.
        suspicious = [h for h in hits if not h.get("automation")]
        automation = [h for h in hits if h.get("automation")]

        if not suspicious:
            lines = [util.suspect_line(h) for h in automation[:_DETAIL_CAP]]
            return CheckResult(
                OK,
                "发现 %d 个从临时目录运行的浏览器进程，全部识别为自动化工具链"
                "（浏览器发行包布局 + 受信驱动进程），不计为可疑：\n       %s"
                % (len(automation), "\n       ".join(lines)))

        lines = []
        for h in suspicious[:_DETAIL_CAP]:
            lines.append(util.suspect_line(h))
            try:
                chain = util.process_chain(h.get("pid"), 3)
            except (TypeError, ValueError):
                chain = []
            if len(chain) > 1:
                lines.append("   进程链: " + " ← ".join(
                    "%s(pid %s)" % (f.get("comm") or "?", f.get("pid"))
                    for f in chain))
        if len(suspicious) > _DETAIL_CAP:
            lines.append("…… 等 %d 项未展开" % (len(suspicious) - _DETAIL_CAP))
        note = ""
        if automation:
            note = ("\n       （另有 %d 个从临时目录运行的浏览器进程识别为自动化"
                    "工具链，未计为异常）" % len(automation))
        return CheckResult(WARN,
                           "发现可疑进程 %d 个（可执行文件已删除或从临时目录运行，"
                           "是恶意程序/内存马的典型特征）：\n       %s%s\n"
                           "       请保留 /proc/<pid>/ 现场后终止进程，并对全盘做一次扫描。"
                           % (len(suspicious), "\n       ".join(lines), note))
