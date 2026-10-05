"""Site switches: turn a website on or off from the console.

"Quickly allow or close a given website" is implemented as a file inject: the
console keeps one small snippet per site under
``/www/server/nginx/conf/vigil-dashboard-sites/<site>.conf`` and makes the
site's ``server`` block pull it in. Closing a site means writing ``deny
all;`` into that snippet; opening it means emptying the snippet again.

Why a file and not a database flag: nginx is the thing that has to act, and
the panel rewrites vhost files whenever you save a site. A one-line
``include`` survives that rewrite far better than an edited vhost body, and
if the panel ever does drop the include, this module notices and puts it
back the next time the switch is used.

Every change is validated with ``nginx -t`` before a reload. A console that
can leave nginx unable to start is a console that takes the whole server
down, so a failed test rolls the snippet back.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import time

from . import settings

_SERVER_NAME = re.compile(r"^\s*server_name\s+([^;]+);", re.M)
_SERVER_OPEN = re.compile(r"^\s*server\s*\{", re.M)
_ROOT = re.compile(r"^\s*root\s+([^;]+);", re.M)
_SSL = re.compile(r"^\s*ssl_certificate\s+([^;]+);", re.M)
_LISTEN = re.compile(r"^\s*listen\s+([^;]+);", re.M)
#: The wildcard form is deliberate: a vhost whose include names one specific
#: file breaks nginx outright if that file is ever missing, and the panel
#: rewrites these lines often enough that it will be missing at some point.
_INCLUDE = "include %s/*.conf;" % settings.SITE_DIR


class NginxError(Exception):
    def __init__(self, message: str, detail: str = "") -> None:
        super().__init__(message)
        self.detail = detail


class SiteControl:
    def __init__(self) -> None:
        self._lock = threading.RLock()

    # -- discovery -------------------------------------------------------

    def _vhost_files(self) -> list:
        out = []
        try:
            for name in sorted(os.listdir(settings.VHOST_DIR)):
                if not name.endswith(".conf"):
                    continue
                if name.startswith(("0.", "zz-", "phpfpm", "waf2monitor")):
                    continue
                out.append(os.path.join(settings.VHOST_DIR, name))
        except OSError:
            pass
        return out

    @staticmethod
    def _read(path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return ""

    def snippet_path(self, key: str) -> str:
        return os.path.join(settings.SITE_DIR, "%s.conf" % key)

    def list_sites(self) -> list:
        states = self._load_state()
        sites = []
        for path in self._vhost_files():
            text = self._read(path)
            key = os.path.basename(path)[:-5]
            names = []
            for match in _SERVER_NAME.finditer(text):
                for token in match.group(1).split():
                    token = token.strip()
                    if token and token not in ("_", "localhost") and token not in names:
                        names.append(token)
            if not names:
                continue
            names = [n for n in names if not n.replace(".", "").isdigit()]
            if not names:
                continue
            root = (_ROOT.search(text).group(1).strip().strip('"')
                    if _ROOT.search(text) else "")
            cert = _SSL.search(text)
            ports = sorted({m.group(1).strip() for m in _LISTEN.finditer(text)})
            snippet = self.snippet_path(key)
            body = self._read(snippet)
            blocked = bool(re.search(r"^\s*deny\s+all\s*;", body, re.M))
            record = states.get(key) or {}
            sites.append({
                "key": key,
                "conf": path,
                # 界面显示用中文原文；key / conf / log 保持 ASCII，
                # 它们是文件名与查找键，转码形式才是权威。
                "names": [settings.display_domain(n) for n in names],
                "names_raw": names,
                "primary": settings.display_domain(names[0]),
                "root": root,
                "ssl": bool(cert),
                "ports": ports[:6],
                "blocked": blocked,
                "snippet": snippet,
                "include_ok": _INCLUDE in text,
                "log": "/www/wwwlogs/%s.log" % key,
                "note": record.get("note", ""),
                "changed": record.get("changed", 0),
            })
        sites.sort(key=lambda s: s["primary"])
        # primary 现在是显示名，排序已按中文完成，符合直觉。
        return sites

    # -- state -----------------------------------------------------------

    def _load_state(self) -> dict:
        try:
            with open(settings.SITES_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_state(self, key: str, **fields) -> None:
        settings.ensure_state_dir()
        with self._lock:
            data = self._load_state()
            rec = data.get(key) or {}
            rec.update(fields)
            data[key] = rec
            tmp = settings.SITES_FILE.with_suffix(".tmp")
            try:
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, ensure_ascii=False, indent=1)
                os.replace(tmp, settings.SITES_FILE)
            except OSError:
                pass

    # -- mutation --------------------------------------------------------

    def ensure_include(self, site: dict) -> bool:
        """Make sure the site's server block pulls in our snippet."""
        path = site["conf"]
        text = self._read(path)
        if _INCLUDE in text:
            return True
        match = _SERVER_NAME.search(text)
        if not match:
            raise NginxError("在 %s 中找不到 server_name，无法注入开关"
                             % os.path.basename(path))
        # Insert after the whole server_name line.
        end = text.find(";", match.start())
        if end < 0:
            raise NginxError("server_name 指令格式异常")
        insert_at = end + 1
        new_text = (text[:insert_at] + "\n    " + _INCLUDE
                    + "  # vigil-dashboard: 站点开关，由控制台维护" + text[insert_at:])
        self._backup(path)
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(new_text)
        except OSError as exc:
            raise NginxError("写入 vhost 失败：%s" % exc)
        return True

    def _backup(self, path: str, keep: int = 5) -> None:
        try:
            stamp = time.strftime("%Y%m%d-%H%M%S")
            shutil.copy2(path, "%s.vigildash.%s" % (path, stamp))
            folder = os.path.dirname(path)
            prefix = os.path.basename(path) + ".vigildash."
            olds = sorted(n for n in os.listdir(folder) if n.startswith(prefix))
            for name in olds[:-keep]:
                os.unlink(os.path.join(folder, name))
        except OSError:
            pass

    def render_snippet(self, blocked: bool, allow: list, reason: str,
                       operator: str) -> str:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            "# vigil-dashboard 站点开关 —— 由管理控制台生成，请勿手工编辑为妙",
            "# 站点：%s" % reason,
            "# 状态：%s" % ("已关闭（对外拒绝访问）" if blocked else "已放行"),
            "# 更新：%s%s" % (stamp, ("  操作者：%s" % operator) if operator else ""),
            "",
        ]
        if blocked:
            for item in allow or []:
                item = str(item).strip()
                if item:
                    lines.append("allow %s;" % item)
            lines.append("deny all;")
        else:
            lines.append("# 放行状态，无附加规则")
        lines.append("")
        return "\n".join(lines)

    def set_blocked(self, key: str, blocked: bool, allow: list = None,
                    note: str = "", operator: str = "", dry_run: bool = False) -> dict:
        """Flip one site's switch. Validates nginx config before reloading."""
        allow = allow or []
        sites = {s["key"]: s for s in self.list_sites()}
        site = sites.get(key)
        if not site:
            raise NginxError("未找到该站点：%s" % key)
        allow = [a for a in allow if re.match(r"^[0-9a-fA-F:.]+(/\d+)?$", str(a))]

        body = self.render_snippet(blocked, allow, site["primary"], operator)
        snippet = site["snippet"]
        previous = self._read(snippet) if os.path.exists(snippet) else None

        if dry_run:
            return {"dry_run": True, "key": key, "blocked": blocked,
                    "snippet": body}

        os.makedirs(settings.SITE_DIR, exist_ok=True)
        wrote_include = False
        try:
            if not site["include_ok"]:
                self.ensure_include(site)
                wrote_include = True
            tmp = snippet + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(body)
            os.replace(tmp, snippet)
            os.chmod(snippet, 0o644)
        except OSError as exc:
            raise NginxError("写入开关文件失败：%s" % exc)

        ok, detail = self.test_config()
        if not ok:
            # Roll back both the snippet and, if we added it, the include.
            try:
                if previous is None:
                    os.path.exists(snippet) and os.unlink(snippet)
                else:
                    with open(snippet, "w", encoding="utf-8") as fh:
                        fh.write(previous)
                if wrote_include:
                    self._strip_include(site["conf"])
            except OSError:
                pass
            raise NginxError("nginx 配置校验未通过，已回滚本次修改", detail)

        reloaded, rdetail = self.reload()
        self._save_state(key, blocked=bool(blocked), note=note,
                         changed=time.time(), allow=allow,
                         include_ok=True)
        return {"key": key, "blocked": bool(blocked), "reloaded": reloaded,
                "reload_detail": rdetail, "test": detail.strip()[-400:],
                "allow": allow, "snippet": snippet}

    def _strip_include(self, path: str) -> None:
        text = self._read(path)
        if _INCLUDE not in text:
            return
        lines = [line for line in text.splitlines(True)
                 if _INCLUDE not in line]
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("".join(lines))
        except OSError:
            pass

    # -- nginx -----------------------------------------------------------

    @staticmethod
    def test_config() -> tuple:
        binary = str(settings.NGINX_BIN)
        if not os.path.exists(binary):
            binary = shutil.which("nginx") or "nginx"
        try:
            proc = subprocess.run([binary, "-t"], capture_output=True,
                                  text=True, timeout=25)
        except (OSError, subprocess.SubprocessError) as exc:
            return False, "无法执行 nginx -t：%s" % exc
        detail = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode == 0, detail

    @staticmethod
    def reload() -> tuple:
        binary = str(settings.NGINX_BIN)
        if not os.path.exists(binary):
            binary = shutil.which("nginx") or "nginx"
        try:
            proc = subprocess.run([binary, "-s", "reload"], capture_output=True,
                                  text=True, timeout=25)
        except (OSError, subprocess.SubprocessError) as exc:
            return False, str(exc)
        detail = ((proc.stdout or "") + (proc.stderr or "")).strip()
        if proc.returncode != 0:
            # Fall back to systemd, which is how the panel starts nginx here.
            try:
                proc2 = subprocess.run(["systemctl", "reload", "nginx"],
                                       capture_output=True, text=True, timeout=25)
                if proc2.returncode == 0:
                    return True, "systemctl reload nginx"
                detail += " / " + ((proc2.stdout or "") + (proc2.stderr or ""))
            except (OSError, subprocess.SubprocessError):
                pass
        return proc.returncode == 0, detail

    def state_summary(self) -> dict:
        sites = self.list_sites()
        return {
            "total": len(sites),
            "blocked": sum(1 for s in sites if s["blocked"]),
            "missing_include": sum(1 for s in sites if not s["include_ok"]),
            "sites": sites,
        }

    # -- global deny list (vigil's own bouncer file) ---------------------

    def global_deny_list(self, limit: int = 400) -> dict:
        path = settings.NGINX_DENY_HTTP
        text = self._read(path)
        entries = [line.strip() for line in text.splitlines()
                   if line.strip().lower().startswith(("deny", "allow"))]
        return {"path": str(path), "count": len(entries),
                "entries": entries[:limit],
                "exists": os.path.exists(path)}


sites = SiteControl()
