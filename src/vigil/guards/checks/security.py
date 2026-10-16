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
            # 下面三项来自一台在线生产机的实测：都是「应用能跑，但把内部
            # 信息或会话交给了访客」的配置，靠崩溃是发现不了的。
            #
            # 只对 Web 侧的 ini 生效。命令行下 display_errors=On 是正确的
            # （你就想看见错误），cookie_httponly 在 CLI 里没有意义，
            # 把它们一起算进来只会制造假警报，把真问题淹掉。
            web_facing = "php-cli" not in os.path.basename(ini)
            if web_facing and re.search(r"^\s*display_errors\s*=\s*On",
                                        text, re.M | re.I):
                hits.append("%s 开启了 display_errors（生产环境会把文件路径、"
                            "调用栈、SQL 片段回显给访客，等于免费给攻击者指路）" % ini)
            if web_facing and re.search(
                    r"^\s*session\.cookie_httponly\s*=\s*(off|0)?\s*$",
                    text, re.M | re.I):
                hits.append("%s 未开启 session.cookie_httponly（会话 Cookie 可被 "
                            "JavaScript 读取，一处 XSS 就能直接盗走登录态）" % ini)
            # allow_url_fopen 默认就是 On，且不少应用真的依赖它。把它做成
            # 选择项而不是默认告警，否则这项检查会在几乎每台机器上长鸣。
            if web_facing and \
                    bool(ctx.copt("php_config", "flag_allow_url_fopen", False)) and \
                    re.search(r"^\s*allow_url_fopen\s*=\s*On", text, re.M | re.I):
                hits.append("%s 开启了 allow_url_fopen（配合 SSRF 可让 PHP "
                            "主动去取攻击者指定的远端内容）" % ini)
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


def _conclusion(exempt: list) -> dict:
    """One sentence for the "nothing needed doing" case.

    The operator asked for a *result*, not a list: "已自动判定为浏览器自动化
    工具链（结构性判据），已忽略，无需处理". This is that sentence, and it
    names the structural fact the judgement rests on, so it can be disagreed
    with.
    """
    labels = []
    for item in exempt or ():
        label = item.get("verdict_label") or item.get("label") or ""
        if label and label not in labels:
            labels.append(label)
    text = "、".join(labels) or "已知安全形态"
    return {
        "verdict": "exempt",
        "labels": labels,
        "conclusion": ("已自动判定为%s（结构性判据：可执行文件位于浏览器发行包"
                       "布局内且文件名属浏览器或其 helper），已忽略，无需处理"
                       % text),
    }


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

        # -- the response, before the report -------------------------------
        # This check is where the operator's "自我检测，然后自我处置" belongs,
        # because this is where the candidates already are. It runs
        # unconditionally but does nothing at all unless
        # `threat.autoresponse.enabled` is true; see
        # `checks/procresponse.py` for the guards, which are the point of the
        # feature rather than an afterthought.
        response = {}
        try:
            from . import procresponse
            response = procresponse.handle(
                hits, cfg=ctx.cfg,
                state=ctx.state.setdefault(procresponse.STATE_KEY, {}),
                log=ctx.log)
        except Exception as exc:                            # noqa: BLE001
            # A broken auto-response must be *visible*, not silent: if it
            # cannot be trusted to run, the operator needs to know that the
            # thing they enabled is not doing anything.
            response = {"enabled": False, "error": "%s: %s"
                        % (type(exc).__name__, exc)}
            try:
                from . import procresponse as _pr
                _pr.record("handle-error", err=response["error"])
            except Exception as log_exc:                    # noqa: BLE001
                _pr.note("自动响应失败，且台账写入也失败：%s" % log_exc)

        # A process this module has already stopped must not be re-reported as
        # a fresh finding: it would be re-decided on every round and, without
        # this, re-signalled forever. It is still named, because a stopped
        # process is something the operator has to know about.
        handled = set()
        try:
            handled = {int(p) for p in (response.get("handled_pids") or [])}
            # Released this round: its exemption was proven, so it must not be
            # re-decided from the same evidence in the same run.
            handled |= {int((r or {}).get("pid"))
                        for r in (response.get("resumed") or [])
                        if (r or {}).get("pid") is not None}
        except (TypeError, ValueError):
            handled = set()

        if not hits:
            return CheckResult(OK, "无可疑进程")

        # -- automatic classification of what needs no intervention --------
        # A browser automation tool unpacks a browser release into a temp
        # directory and runs it from there -- structurally the same as "a
        # binary running out of /tmp" -- and its crashpad helper outlives the
        # browser, so its ancestor chain is legitimately broken. Both are
        # judged *structurally* (release layout + browser/helper basename) and
        # the verdict is recorded with its reason, so "nothing was done"
        # never reads the same as "nothing needed doing".
        #
        # This runs whether or not `threat.autoresponse` is enabled: it can
        # only ever *remove* a process from consideration, and a process that
        # never reaches the response path cannot be responded to.
        try:
            from . import procresponse
            rt = procresponse.Runtime(cfg=ctx.cfg, log=ctx.log)
            classified = procresponse.automation_verdicts(
                hits, cfg=ctx.cfg, state=ctx.state, runtime=rt, log=ctx.log)
        except Exception as exc:                            # noqa: BLE001
            classified = {"exempt": [], "suspicious": list(hits),
                          "error": "%s: %s" % (type(exc).__name__, exc)}
        automation = classified.get("exempt") or []
        suspicious = [h for h in (classified.get("suspicious") or [])
                      if not h.get("automation")]

        report = ""
        try:
            from . import procresponse as _pr
            report = _pr.describe(response)
        except Exception:                                   # noqa: BLE001
            report = ""
        if response.get("error"):
            report = ("自动响应执行失败：%s" % response["error"]) + (
                "\n       " + report if report else "")

        if not suspicious:
            lines = [util.suspect_line(h) for h in automation[:_DETAIL_CAP]]
            verdict = _conclusion(automation)
            detail = ("发现 %d 个浏览器/自动化工具链进程（含 helper 与已删除的"
                      "发行包残留），已**自动判定**并忽略，不计为可疑：\n"
                      "       结论：%s\n       %s"
                      % (len(automation), verdict["conclusion"],
                         "\n       ".join(lines)))
            return CheckResult(OK, detail + (("\n       " + report) if report
                                             else ""))

        lines = []
        for h in suspicious[:_DETAIL_CAP]:
            if h.get("pid") in handled:
                lines.append("%s　→ 已由自动响应处置（见下），本轮不重复判定"
                             % util.suspect_line(h))
                continue
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
            verdict = _conclusion(automation)
            note = ("\n       另有 %d 个浏览器/自动化工具链进程被**自动判定**并忽略："
                    "%s" % (len(automation), verdict["conclusion"]))
        tail = ("\n       请保留 /proc/<pid>/ 现场后终止进程，并对全盘做一次扫描。"
                if not handled else
                "\n       其中 %d 个已由自动响应处置，撤销方式见下。" % len(handled))
        return CheckResult(WARN,
                           "发现可疑进程 %d 个（可执行文件已删除或从临时目录运行，"
                           "是恶意程序/内存马的典型特征）：\n       %s%s\n%s"
                           % (len(suspicious), "\n       ".join(lines), note,
                              report + tail if report else tail.lstrip("\n")))


# --------------------------------------------------------------------------
# v3.3.2 新增：三项来自一台在线生产机的实测发现
# --------------------------------------------------------------------------


@register
class SelfProtection(Check):
    id = "self_protection"
    label = "自我封禁防护"
    label_en = "Self-ban protection"
    group = G_SECURITY
    description = "实测本机地址是否真的封不掉（自动豁免这条护栏是否真的在生效）"

    def run(self, ctx: CheckContext) -> CheckResult:
        """Verify the "never ban myself" rail, instead of assuming it.

        ``Whitelist`` already exempts every address found on a local interface,
        and ``netblock_blockers`` refuses a range that contains one -- so this
        check deliberately does **not** re-implement either. What it verifies is
        that the rail is actually load-bearing on *this* host, because it can
        fail silently in two ways:

        * ``local_addresses()`` reads ``ip -o addr show``. If that command is
          missing or fails, it quietly returns loopback only, and the
          self-exemption degrades to "loopback cannot be banned" -- which is
          not the rail anyone is relying on.
        * ``threat.auto_whitelist_local`` can be switched off, after which an
          address is protected only if it is written into ``threat.whitelist``
          by hand.

        Both matter more than they look: vigil's DROP rule sits at INPUT
        position 1, ahead of ufw, so a mistaken ban on this host's own address
        takes out SSH and every admin page at once -- that is the shape of the
        worst outage in this project's history.

        Known limit: on a host behind NAT the public address is not on any
        interface, so nothing here can recognise it. Say so rather than pretend
        otherwise.
        """
        from .. import threat

        entries = list(ctx.cfg.get("threat.whitelist", []) or [])
        auto = bool(ctx.cfg.get("threat.auto_whitelist_local", True))

        try:
            local = sorted(threat.local_addresses())
        except Exception as e:                          # noqa: BLE001
            return CheckResult(
                WARN, "无法枚举本机地址（%s: %s）—— 无法确认「本机封不掉」"
                      "这条护栏是否生效" % (type(e).__name__, e))

        non_loopback = [a for a in local if a not in ("127.0.0.1", "::1")]

        wl = threat.Whitelist(entries, auto)
        exposed = [a for a in local if not wl.allowed(a)]
        if exposed:
            return CheckResult(
                CRIT,
                "本机地址不在封禁豁免内：%s\n"
                "       vigil 的 DROP 规则排在 iptables INPUT 第 1 条、在 ufw 之前，"
                "这些地址一旦被自动封禁，SSH 与全部管理页会同时失联。\n"
                "       请打开 threat.auto_whitelist_local，"
                "或把上述地址显式加入 threat.whitelist。"
                % "、".join(exposed))

        if not non_loopback:
            why = ("`ip` 命令不可用" if not shell.have("ip")
                   else "`ip addr show` 没有返回任何地址")
            return CheckResult(
                WARN,
                "只枚举到回环地址，没有找到任何本机对外地址（%s）—— "
                "「自动豁免本机地址」这条护栏实际上只剩回环在生效。\n"
                "       在修好之前，请把本机的对外地址显式写进 threat.whitelist，"
                "否则一旦误判，服务器会把自己封在门外。" % why)

        note = ""
        if not auto:
            note = ("（threat.auto_whitelist_local 已关闭，当前只靠显式白名单条目"
                    "豁免本机地址）")
        return CheckResult(OK, "本机 %d 个地址均已豁免封禁：%s%s"
                           % (len(local), "、".join(local), note))


@register
class LocalServiceAuth(Check):
    id = "local_service_auth"
    label = "本地服务未授权"
    label_en = "Unauthenticated local services"
    group = G_SECURITY
    description = "探测仅监听回环的服务是否允许无认证访问（Redis 等）"

    #: Redis lines that no longer receive security fixes. The values live in
    #: ``checks.local_service_auth.redis_eol`` (config defaults) rather than
    #: here, so an operator can correct the table without a code change --
    #: this class attribute is only the fallback for a config that predates it.
    _REDIS_EOL = ("5.0", "6.0")

    def run(self, ctx: CheckContext) -> CheckResult:
        """A service bound to loopback is not "safe" if it needs no password.

        Binding to 127.0.0.1 only removes the internet as an attacker; every
        process on the box can still reach it, and a web app's SSRF is the
        classic way in. Redis without a password is a well-worn path to writing
        files and, from there, to running as the web user.

        The probe is behavioural rather than config-reading: what matters is
        whether an unauthenticated client gets an answer, not what the config
        file intended.
        """
        problems, verified = [], []
        self._check_redis(ctx, problems, verified)
        if problems:
            return CheckResult(
                WARN, "本地服务允许未授权访问：\n       %s\n"
                      "       仅监听回环只是挡住了外网；本机任何进程，"
                      "以及 Web 应用的 SSRF，都仍然够得着。"
                      % "\n       ".join(problems))
        if verified:
            return CheckResult(OK, "本地服务均要求认证（已核实：%s）"
                               % "、".join(verified))
        return CheckResult(OK, "未检测到需要检查的本地服务")

    def _check_redis(self, ctx: CheckContext, problems: list,
                     verified: list) -> None:
        if not shell.have("redis-cli"):
            return
        port = int(ctx.copt("local_service_auth", "redis_port", 6379) or 6379)
        ok, out, err = shell.run(
            ["redis-cli", "-h", "127.0.0.1", "-p", str(port), "PING"],
            timeout=6)
        text = "%s %s" % (out or "", err or "")
        if "PONG" in text:
            detail = "Redis（127.0.0.1:%d）**未设密码** —— PING 直接返回 PONG" % port
            version = self._redis_version()
            if version:
                detail += "；版本 %s" % version
                if self._redis_eol(ctx, version):
                    detail += "（该版本已停止安全支持）"
            problems.append(detail)
        elif any(s in text for s in ("NOAUTH", "WRONGPASS",
                                     "Authentication required")):
            verified.append("Redis 已设密码")
        # "Could not connect" simply means it is not running: not a finding.

    @staticmethod
    def _redis_version() -> str:
        ok, out, _err = shell.run(["redis-server", "-v"], timeout=5)
        if not ok:
            return ""
        m = re.search(r"v=([0-9][0-9.]*)", out or "")
        return m.group(1).rstrip(".") if m else ""

    def _redis_eol(self, ctx: CheckContext, version: str) -> bool:
        lines = ctx.copt("local_service_auth", "redis_eol", None)
        if lines is None:
            lines = list(self._REDIS_EOL)
        line = ".".join(str(version).split(".")[:2])
        return line in {str(x) for x in lines or []}


@register
class SshHardening(Check):
    id = "ssh_hardening"
    label = "SSH 加固"
    label_en = "SSH hardening"
    group = G_SECURITY
    description = "检查 sshd 是否允许 root 直接登录、是否用口令登录且没配密钥"

    #: Where the fallback parse reads from when `sshd -T` is unavailable.
    #: A class attribute so a test can point it at a fixture instead of the
    #: host's real file.
    CONFIG_PATH = "/etc/ssh/sshd_config"

    def run(self, ctx: CheckContext) -> CheckResult:
        """Report the two settings that decide how guessable SSH is.

        This check only ever *reports*: it never edits sshd_config. Turning off
        password authentication from a program that is not holding a verified
        working key is how an operator locks themselves out of their own
        machine -- the change has to be made by a human who has just confirmed
        the key works.
        """
        effective = self._effective()
        if effective is None:
            return CheckResult(OK, "无法读取 sshd 生效配置（可能未安装 SSH），跳过检查")

        problems = []
        root_login = (effective.get("permitrootlogin") or "").strip().lower()
        password = (effective.get("passwordauthentication") or "").strip().lower()

        if root_login == "yes":
            problems.append("`PermitRootLogin yes` —— 允许以 root 身份直接登录，"
                            "攻击者不需要先猜到一个普通用户名")

        keys = self._authorized_key_files()
        if password == "yes" and not keys:
            problems.append("`PasswordAuthentication yes` 且整机没有任何 "
                            "authorized_keys —— 登录唯一的防线就是口令强度，"
                            "没有密钥这一层")
        elif password == "yes":
            problems.append("`PasswordAuthentication yes`（已配置 %d 个 "
                            "authorized_keys，建议在确认密钥可用后关闭口令登录）"
                            % len(keys))

        if not problems:
            return CheckResult(OK, "SSH 关键项正常（未允许 root 直接登录，"
                                   "且未开启口令登录）")
        return CheckResult(WARN, "SSH 配置偏松：\n       %s\n"
                                 "       本项只报告、不修改：关掉口令登录前，"
                                 "必须先确认密钥真的能登上，否则会把自己锁在门外。"
                           % "\n       ".join(problems))

    @staticmethod
    def _effective() -> dict:
        """``sshd -T`` if we can get it, else a flat read of sshd_config.

        ``sshd -T`` is worth preferring because it is what sshd itself will
        use -- it resolves Include files and fills in compiled-in defaults,
        neither of which a grep over the config file does.
        """
        if shell.have("sshd"):
            ok, out, _err = shell.run(["sshd", "-T"], timeout=10)
            if ok and out:
                result = {}
                for line in out.splitlines():
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        result[parts[0].strip().lower()] = parts[1].strip()
                if result:
                    return result
        try:
            with open(SshHardening.CONFIG_PATH, "r",
                      encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            return None
        result = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                result[parts[0].strip().lower()] = parts[1].strip()
        return result or None

    @staticmethod
    def _authorized_key_files() -> list:
        found = []
        for home in ("/root",) + tuple(
                p.pw_dir for p in pwd.getpwall()
                if p.pw_dir.startswith("/home/")):
            path = os.path.join(home, ".ssh", "authorized_keys")
            try:
                if os.path.isfile(path) and os.path.getsize(path) > 0:
                    found.append(path)
            except OSError:
                continue
        return found
