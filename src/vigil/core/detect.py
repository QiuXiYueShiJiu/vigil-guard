"""Host detection.

The installer must work on a bare Debian/Ubuntu box, on a cPanel host, and
on a Chinese control-panel host (BT/aaPanel) alike. Rather than asking the
operator twenty questions, we look around and only ask about what we cannot
determine.

Everything returned here is plain data (no side effects), so ``vigil
doctor`` can display it and the installer can act on it.
"""
from __future__ import annotations

import glob
import os
import platform
import re
import socket
from pathlib import Path

from . import paths, shell

# --------------------------------------------------------------------------
# OS / runtime
# --------------------------------------------------------------------------


def os_release() -> dict:
    info = {}
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as fh:
            for line in fh:
                if "=" in line:
                    k, _, v = line.strip().partition("=")
                    info[k] = v.strip().strip('"')
    except OSError:
        pass
    return info


def summary() -> dict:
    rel = os_release()
    return {
        "hostname": socket.gethostname(),
        "distro": rel.get("PRETTY_NAME") or platform.platform(),
        "distro_id": (rel.get("ID") or "").lower(),
        "distro_like": (rel.get("ID_LIKE") or "").lower(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "python": platform.python_version(),
        "init": "systemd" if Path("/run/systemd/system").is_dir() else "other",
        "is_root": os.geteuid() == 0,
        "cpu_count": os.cpu_count() or 1,
    }


def memory_mb() -> int:
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def is_debian_family() -> bool:
    s = summary()
    blob = s["distro_id"] + " " + s["distro_like"]
    return any(x in blob for x in ("debian", "ubuntu", "kali", "raspbian",
                                   "linuxmint", "pop"))


def package_manager() -> str:
    for pm in ("apt-get", "dnf", "yum", "apk", "zypper", "pacman"):
        if shell.have(pm):
            return pm
    return ""


def install_packages(names: list) -> tuple:
    """Best-effort package install. Returns (ok, message)."""
    pm = package_manager()
    if not pm:
        return False, "no supported package manager found"
    if pm == "apt-get":
        argv = ["apt-get", "install", "-y", "--no-install-recommends"] + names
    elif pm in ("dnf", "yum"):
        argv = [pm, "install", "-y"] + names
    elif pm == "apk":
        argv = ["apk", "add", "--no-cache"] + names
    elif pm == "zypper":
        argv = ["zypper", "--non-interactive", "install"] + names
    else:
        argv = ["pacman", "-S", "--noconfirm"] + names
    ok, _o, err = shell.run(argv, timeout=600)
    return ok, (err.strip()[:300] if not ok else "")


# --------------------------------------------------------------------------
# Web stack
# --------------------------------------------------------------------------


def nginx() -> dict:
    binary = shell.which("nginx",
                         "/www/server/nginx/sbin/nginx",
                         "/usr/sbin/nginx",
                         "/usr/local/nginx/sbin/nginx")
    if not binary:
        return {"present": False}
    # `-V` prints the configure arguments on stderr; `-v` prints only the
    # version. Using the wrong one makes the Lua check silently always
    # false, which in turn makes the gate installer refuse to run on a host
    # that supports it perfectly well.
    _ok, ver_out, ver_err = shell.run([binary, "-V"])
    ver = (ver_out or "") + (ver_err or "")
    version = ""
    m = re.search(r"nginx/([\d.]+)", ver)
    if m:
        version = m.group(1)

    confs = [str(p) for p in paths.NGINX_CONF_CANDIDATES if p.exists()]
    if not confs:
        found = glob.glob("/usr/local/nginx/conf/nginx.conf")
        confs = found
    conf = confs[0] if confs else ""
    lua = "/www/server/nginx/src/lua_nginx_module" in ver
    worker = ""
    if conf:
        try:
            with open(conf, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    m = re.match(r"\s*user\s+([^\s;]+)", line)
                    if m:
                        worker = m.group(1)
                        break
        except OSError:
            pass
    return {
        "present": True,
        "binary": binary,
        "version": version,
        "conf": conf,
        "lua": lua,
        "worker_user": worker or "www-data",
        "include_dirs": _nginx_include_dirs(conf),
    }


def _nginx_include_dirs(conf: str) -> list:
    """Directories nginx pulls vhost configs from.

    We append our snippet to one of these rather than editing the main
    config, because the main config is owned by whatever control panel is
    installed and will be regenerated.
    """
    dirs = []
    if not conf:
        return [str(p) for p in paths.NGINX_VHOST_DIR_CANDIDATES]
    try:
        text = Path(conf).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [str(p) for p in paths.NGINX_VHOST_DIR_CANDIDATES]
    for m in re.finditer(r"^\s*include\s+([^;]+);", text, re.M):
        pat = m.group(1).strip()
        if not pat.endswith("*.conf"):
            continue
        base = os.path.dirname(pat)
        if "vhost" in pat or "sites-enabled" in pat or "conf.d" in pat:
            if os.path.isdir(base):
                dirs.append(base)
    for p in paths.NGINX_VHOST_DIR_CANDIDATES:
        if p.is_dir() and str(p) not in dirs:
            dirs.append(str(p))
    return dirs


def php_fpm_sockets() -> list:
    """Discover PHP-FPM unix sockets and their pool users.

    A socket path alone is not enough: our gate files must be readable by
    whichever user the pool runs as, and that differs between a distro
    package (www-data) and a control panel (www).
    """
    socks = set()
    for pat in ("/tmp/php-cgi-*.sock", "/run/php/*.sock", "/var/run/php/*.sock",
                "/dev/shm/php-cgi-*.sock"):
        socks.update(glob.glob(pat))
    out = []
    for s in sorted(socks):
        out.append({"socket": s, "user": _socket_owner_user(s)})
    return out


def _socket_owner_user(sock: str) -> str:
    try:
        st = os.stat(sock)
    except OSError:
        return ""
    try:
        import pwd
        return pwd.getpwuid(st.st_uid).pw_name
    except (ImportError, KeyError):
        return str(st.st_uid)


def php_fpm_binaries() -> list:
    return sorted(glob.glob(paths.PHP_FPM_GLOB))


def web_roots() -> list:
    """Document roots that actually contain something."""
    roots = []
    for base in paths.WEBROOT_CANDIDATES:
        if not base.is_dir():
            continue
        if base.name == "html":
            roots.append(str(base))
            continue
        try:
            for child in sorted(base.iterdir()):
                if child.is_dir() and not child.name.startswith("."):
                    roots.append(str(child))
        except OSError:
            pass
    return roots


# --------------------------------------------------------------------------
# Control panels
# --------------------------------------------------------------------------


def bt_panel() -> dict:
    """Detect BT panel / aaPanel.

    We never assume the default port or entry path: both are commonly
    changed precisely because attackers scan for them, and reading them is
    trivial compared to guessing wrong.
    """
    panel = Path("/www/server/panel")
    if not panel.is_dir():
        return {"present": False}

    version = ""
    try:
        text = (panel / "class" / "common.py").read_text(
            encoding="utf-8", errors="replace")
        m = re.search(r"g\.version\s*=\s*['\"]([^'\"]+)", text)
        if m:
            version = m.group(1)
    except OSError:
        pass
    if not version:
        try:
            version = (panel / "class" / "config.json").read_text(
                encoding="utf-8", errors="replace")[:0] or ""
        except OSError:
            pass

    port = 0
    try:
        port = int((panel / "data" / "port.pl").read_text().strip())
    except (OSError, ValueError):
        port = 8888

    admin_path = ""
    try:
        admin_path = (panel / "data" / "admin_path.pl").read_text().strip()
    except OSError:
        admin_path = ""

    api_key = ""
    try:
        api_key = (panel / "data" / "api.json").read_text().strip()[:0] or ""
    except OSError:
        pass

    return {
        "present": True,
        "dir": str(panel),
        "version": version,
        "port": port,
        "admin_path": admin_path,
        "vhost_dir": str(panel / "vhost" / "nginx"),
        "extension_dir": str(panel / "vhost" / "nginx" / "extension"),
        "data_dir": str(panel / "data"),
        "wwwroot": "/www/wwwroot",
        "user": "www",
    }


def cpanel() -> dict:
    return {"present": Path("/usr/local/cpanel").is_dir()}


def plesk() -> dict:
    return {"present": Path("/opt/psa").is_dir() or Path("/usr/local/psa").is_dir()}


# --------------------------------------------------------------------------
# Firewall / enforcement
# --------------------------------------------------------------------------


def firewall() -> dict:
    """Which firewall can we actually drive?

    ``ufw`` is preferred where present because its CLI is atomic and
    idempotent. Hand written iptables chains were the source of a
    production outage during this project's own development, so they are
    explicitly not offered as the default.
    """
    out = {"kind": "none", "cmd": "", "active": False, "alternatives": []}
    if shell.have("ufw"):
        out["alternatives"].append("ufw")
    if shell.have("firewall-cmd"):
        out["alternatives"].append("firewalld")
    if shell.have("nft"):
        out["alternatives"].append("nftables")
    if shell.have("iptables"):
        out["alternatives"].append("iptables")
    if shell.have("fail2ban-client"):
        out["alternatives"].append("fail2ban")

    if shell.have("ufw"):
        st = shell.out(["ufw", "status"])
        active = st.startswith("Status: active")
        out.update(kind="ufw", cmd="ufw", active=active)
        return out
    if shell.have("firewall-cmd"):
        active = shell.out(["firewall-cmd", "--state"]) == "running"
        out.update(kind="firewalld", cmd="firewall-cmd", active=active)
        return out
    if shell.have("nft"):
        ok, o, _ = shell.run(["nft", "list", "ruleset"])
        out.update(kind="nftables", cmd="nft", active=bool(ok and o.strip()))
        return out
    if shell.have("iptables"):
        ok, o, _ = shell.run(["iptables", "-S"])
        out.update(kind="iptables", cmd="iptables", active=len(o.splitlines()) > 3)
        return out
    return out


def fail2ban() -> dict:
    if not shell.have("fail2ban-client"):
        return {"present": False}
    _ok, o, _e = shell.run(["fail2ban-client", "status"])
    jails = re.findall(r"Jail list:\s*(.*)", o)
    names = [j.strip() for j in jails[0].split(",")] if jails and jails[0].strip() else []
    return {"present": True, "jails": names}


# --------------------------------------------------------------------------
# Auditing / malware
# --------------------------------------------------------------------------


def auditd() -> dict:
    present = shell.have("auditctl") and shell.have("auditd")
    enabled = shell.out(["systemctl", "is-enabled", "auditd"]) if present else ""
    active = shell.out(["systemctl", "is-active", "auditd"]) if present else ""
    rules_dir = Path("/etc/audit/rules.d")
    return {
        "present": present,
        "enabled": enabled,
        "active": active,
        "rules_dir": str(rules_dir),
        "rules_dir_writable": os.access(str(rules_dir), os.W_OK),
        "rules_file": str(rules_dir / "vigil.rules"),
        "augenrules": shell.have("augenrules"),
        "ausearch": shell.have("ausearch"),
    }


def maldet() -> dict:
    binary = shell.which("maldet", "/usr/local/maldetect/maldet")
    if not binary:
        return {"present": False}
    return {
        "present": True,
        "binary": binary,
        "conf": "/usr/local/maldetect/conf.maldet",
        "monitor_paths": "/usr/local/maldetect/monitor_paths",
        "ignore_inotify": "/usr/local/maldetect/ignore_inotify",
        "hits": "/usr/local/maldetect/sess/hits.hist",
        "sessdir": "/usr/local/maldetect/sess",
        "sigsdir": "/usr/local/maldetect/sigs",
        "service": "maldet",
    }


def clamav() -> dict:
    return {
        "present": shell.have("clamscan") or shell.have("clamdscan"),
        "binary": shell.which("clamscan", "/usr/bin/clamscan"),
        "daemon": shell.which("clamdscan", "/usr/bin/clamdscan"),
        "service": "clamav-daemon",
        "freshclam": "clamav-freshclam",
    }


def malware_engine() -> dict:
    m = maldet()
    if m["present"]:
        return {"engine": "maldet", **m}
    c = clamav()
    if c["present"]:
        return {"engine": "clamav", **c}
    return {"engine": "none", "present": False}


# --------------------------------------------------------------------------
# Mail
# --------------------------------------------------------------------------


def local_mta() -> dict:
    for name in ("sendmail", "postfix", "exim4", "msmtp", "mail"):
        path = shell.which(name, "/usr/sbin/%s" % name, "/usr/lib/sendmail")
        if path:
            return {"present": True, "program": name, "path": path}
    return {"present": False}


_PORT25_CACHE: dict = {}


def port25_open(timeout: float = 4.0, refresh: bool = False) -> bool:
    """Whether we can open outbound TCP/25.

    Many VPS providers block it. Knowing this up front is the difference
    between "your alerts are broken" and "pick a submission port".
    """
    if "v" in _PORT25_CACHE and not refresh:
        return _PORT25_CACHE["v"]
    result = _port25_probe(timeout)
    _PORT25_CACHE["v"] = result
    return result


def _port25_probe(timeout: float) -> bool:
    for host in ("gmail-smtp-in.l.google.com", "mx1.qq.com"):
        try:
            info = socket.getaddrinfo(host, 25, socket.AF_INET,
                                      socket.SOCK_STREAM)
        except OSError:
            continue
        for family, stype, proto, _c, addr in info[:1]:
            s = socket.socket(family, stype, proto)
            s.settimeout(timeout)
            try:
                s.connect(addr)
                s.close()
                return True
            except OSError:
                continue
            finally:
                try:
                    s.close()
                except OSError:
                    pass
    return False


# --------------------------------------------------------------------------
# Log sources
# --------------------------------------------------------------------------


def log_sources() -> dict:
    """Locate the logs worth tailing for attack detection."""
    nginx_access = []
    for pat in ("/www/wwwlogs/*.log",
                "/var/log/nginx/*access*.log",
                "/usr/local/nginx/logs/*access*.log",
                "/var/log/httpd/*access*.log"):
        nginx_access.extend(glob.glob(pat))
    # Control panel vhost logs frequently live beside the site logs; drop
    # anything that is obviously an error log.
    nginx_access = [p for p in sorted(set(nginx_access))
                    if "error" not in os.path.basename(p).lower()]

    auth = []
    for p in ("/var/log/auth.log", "/var/log/secure",
              "/var/log/btmp", "/var/log/wtmp"):
        if os.path.isfile(p):
            auth.append(p)

    panel = []
    for p in ("/www/server/panel/logs/request/*.log",
              "/www/server/panel/logs/*.log"):
        panel.extend(glob.glob(p))

    return {
        "nginx_access": nginx_access[:200],
        "auth": auth,
        "panel": sorted(set(panel))[:50],
        "journald": Path("/run/systemd/journal/socket").exists(),
    }


def sshd_config() -> dict:
    out = {"present": False, "port": 22, "permit_root_login": "", "password_auth": ""}
    p = Path("/etc/ssh/sshd_config")
    if not p.is_file():
        return out
    out["present"] = True
    try:
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            k, v = parts[0].lower(), parts[1]
            if k == "port":
                try:
                    out["port"] = int(v)
                except ValueError:
                    pass
            elif k == "permitrootlogin":
                out["permit_root_login"] = v
            elif k == "passwordauthentication":
                out["password_auth"] = v
    except OSError:
        pass
    # Drop-in configs override the main file
    for drop in sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf")):
        try:
            with open(drop, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 2 and not line.strip().startswith("#"):
                        k, v = parts[0].lower(), parts[1]
                        if k == "port":
                            out["port"] = int(v) if v.isdigit() else out["port"]
                        elif k == "permitrootlogin":
                            out["permit_root_login"] = v
                    elif k == "passwordauthentication":
                        out["password_auth"] = v
        except OSError:
            pass
    return out


# --------------------------------------------------------------------------
# Aggregate
# --------------------------------------------------------------------------


_FULL_CACHE: dict = {}


def full(refresh: bool = False) -> dict:
    """Everything at once -- this is what `vigil doctor` prints.

    Cached, because it is not cheap: it shells out to nginx, systemctl and
    php-fpm, and it opens a real TCP connection to port 25 to find out
    whether the host can send mail directly. Callers such as
    :meth:`GateSpec.for_kind` and the installer ask for it repeatedly, and
    without a cache a single command spent most of its time re-probing the
    same facts.
    """
    if _FULL_CACHE.get("data") is not None and not refresh:
        return _FULL_CACHE["data"]
    data = _full_uncached()
    _FULL_CACHE["data"] = data
    return data


def _full_uncached() -> dict:
    return {
        "system": summary(),
        "memory_mb": memory_mb(),
        "package_manager": package_manager(),
        "debian_family": is_debian_family(),
        "nginx": nginx(),
        "php_fpm": {"sockets": php_fpm_sockets(), "binaries": php_fpm_binaries()},
        "web_roots": web_roots(),
        "bt_panel": bt_panel(),
        "cpanel": cpanel(),
        "plesk": plesk(),
        "firewall": firewall(),
        "fail2ban": fail2ban(),
        "auditd": auditd(),
        "malware": malware_engine(),
        "local_mta": local_mta(),
        "port25_open": port25_open(),
        "log_sources": log_sources(),
        "sshd": sshd_config(),
        "tools": {
            "curl": shell.have("curl"),
            "openssl": shell.have("openssl"),
            "lsof": shell.have("lsof"),
            "ss": shell.have("ss"),
            "inotifywait": shell.have("inotifywait"),
        },
    }


def public_ip(timeout: float = 5.0) -> str:
    """Best-effort public IPv4, used only for display and whitelist offers."""
    if not shell.have("curl"):
        return ""
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip",
                "https://ipinfo.io/ip"):
        ok, o, _ = shell.run(["curl", "-fsS", "--max-time", str(int(timeout)), url],
                             timeout=timeout + 2)
        if ok:
            ip = o.strip()
            if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
                return ip
    return ""
