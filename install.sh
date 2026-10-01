#!/usr/bin/env bash
# vigil-guard bootstrap installer.
#
# This script does exactly two things: make sure the box has what the package
# needs to run, then hand over to `vigil install`, which does the real work
# (environment detection, feature selection, systemd units, audit rules).
#
# Kept deliberately small and dependency-free so it can be read in full before
# being run as root -- which is the only honest way to ship an install script.
#
#   ./install.sh                 # check, install what is missing, hand over
#   ./install.sh --check         # only report what is missing, change nothing
#   ./install.sh --no-deps       # skip dependency handling entirely
#   ./install.sh --with-optional # also install the optional bits for this distro
#
# The package itself has NO third-party Python dependencies: it is standard
# library only, so there is nothing to fetch from PyPI and nothing to vendor.
# What can be missing is *system* tooling -- python3 itself, and the optional
# pieces that back individual features. Those are what this handles.

set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${VIGIL_LIB:-/usr/local/lib/vigil}"
BIN="${VIGIL_BIN:-/usr/local/bin/vigil}"

CHECK_ONLY=0
USE_DEPS=1
WITH_OPTIONAL=0
PASSTHRU=()
for arg in "$@"; do
    case "$arg" in
        --check)         CHECK_ONLY=1 ;;
        --no-deps)       USE_DEPS=0 ;;
        --with-optional) WITH_OPTIONAL=1 ;;
        *)               PASSTHRU+=("$arg") ;;
    esac
done

say()  { printf '==> %s\n' "$*"; }
warn() { printf '!!  %s\n' "$*" >&2; }

# --------------------------------------------------------------------------
# Which distribution is this? Only used to pick the right package names.
# --------------------------------------------------------------------------
PM=""
PM_INSTALL=""
detect_pm() {
    for cand in apt-get dnf yum pacman zypper apk; do
        if command -v "$cand" >/dev/null 2>&1; then
            PM="$cand"
            case "$cand" in
                apt-get) PM_INSTALL="apt-get install -y" ;;
                dnf|yum) PM_INSTALL="$cand install -y" ;;
                pacman)  PM_INSTALL="pacman -S --noconfirm --needed" ;;
                zypper)  PM_INSTALL="zypper --non-interactive install" ;;
                apk)     PM_INSTALL="apk add" ;;
            esac
            return 0
        fi
    done
    return 1
}

# Package name per distribution for one logical dependency.
pkg_name() {
    local key="$1"
    case "$key:$PM" in
        python3:apt-get|python3:dnf|python3:yum|python3:pacman|python3:zypper|python3:apk)
                         echo "python3" ;;
        nginx:apt-get|nginx:dnf|nginx:yum|nginx:pacman|nginx:zypper|nginx:apk)
                         echo "nginx" ;;
        php:apt-get)     echo "php-fpm php-gd" ;;
        php:dnf|php:yum) echo "php-fpm php-gd" ;;
        php:pacman)      echo "php php-gd" ;;
        php:zypper)      echo "php8-fpm php8-gd" ;;
        php:apk)         echo "php83-fpm php83-gd" ;;
        audit:apt-get)   echo "auditd" ;;
        audit:dnf|audit:yum|audit:pacman|audit:zypper|audit:apk)
                         echo "audit" ;;
        ipset:*)         echo "ipset" ;;
        firewall:apt-get|firewall:dnf|firewall:yum|firewall:zypper)
                         echo "iptables" ;;
        firewall:pacman) echo "iptables-nft" ;;
        firewall:apk)    echo "iptables" ;;
        *)               echo "" ;;
    esac
}

have() { command -v "$1" >/dev/null 2>&1; }

# --------------------------------------------------------------------------
# What is missing? Report always; install only what is absent.
# --------------------------------------------------------------------------
missing_required=()
missing_optional=()

probe() {
    have python3 || missing_required+=("python3")
    have nginx   || missing_optional+=("nginx")
    if ! have php-fpm && ! have php8.2-fpm && ! have php-fpm8.2; then
        missing_optional+=("php")
    fi
    have auditctl || missing_optional+=("audit")
    have ipset    || missing_optional+=("ipset")
    have iptables || missing_optional+=("firewall")
}

say "探测系统环境"
detect_pm || true
if [ -n "$PM" ]; then
    say "包管理器：$PM"
else
    warn "没识别出包管理器，缺失项需要手动安装"
fi
probe

if [ "${#missing_required[@]}" -eq 0 ]; then
    say "必需依赖：齐全（python3 $(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])'))"
else
    say "必需依赖缺失：${missing_required[*]}"
fi
if [ "${#missing_optional[@]}" -eq 0 ]; then
    say "可选依赖：齐全"
else
    say "可选依赖缺失：${missing_optional[*]}（缺哪个就少哪个能力，其余照常工作）"
fi

# --------------------------------------------------------------------------
# Install. Interactive by default: this runs as root, so it prints the exact
# command and asks first. In a non-interactive shell it never installs
# anything on its own -- it prints the command and stops.
# --------------------------------------------------------------------------
install_list() {
    local pkgs=() key p
    for key in "$@"; do
        p="$(pkg_name "$key")"
        [ -n "$p" ] && pkgs+=($p)
    done
    [ "${#pkgs[@]}" -eq 0 ] && return 1
    echo "${pkgs[@]}"
}

ask_install() {
    local cmd="$1"
    [ -z "$PM_INSTALL" ] && return 0
    [ -z "$cmd" ] && return 0
    say "需要安装：$cmd"
    if [ -t 0 ]; then
        printf '    执行 `%s %s` 吗？[y/N] ' "$PM_INSTALL" "$cmd"
        read -r reply || reply="n"
        case "$reply" in
            y|Y|yes|YES) $PM_INSTALL $cmd ;;
            *) warn "已跳过。可稍后手动执行：$PM_INSTALL $cmd" ;;
        esac
    else
        warn "非交互环境，未自动安装。请手动执行：$PM_INSTALL $cmd"
    fi
}

if [ "$USE_DEPS" -eq 1 ]; then
    if [ "${#missing_required[@]}" -gt 0 ]; then
        targets=("${missing_required[@]}")
        [ "$WITH_OPTIONAL" -eq 1 ] && targets+=("${missing_optional[@]}")
        ask_install "$(install_list "${targets[@]}" || true)"
    elif [ "$WITH_OPTIONAL" -eq 1 ] && [ "${#missing_optional[@]}" -gt 0 ]; then
        ask_install "$(install_list "${missing_optional[@]}" || true)"
    fi
fi

if [ "$CHECK_ONLY" -eq 1 ]; then
    say "--check 模式：只报告，未做任何改动"
    exit 0
fi

# --------------------------------------------------------------------------
# From here on the package only needs python3.
# --------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    warn "需要 root 权限：sudo $0"
    exit 1
fi

PY="$(command -v python3 || true)"
if [ -z "$PY" ]; then
    warn "仍然没有 python3，请先安装 Python 3.8 或更高版本"
    exit 1
fi

PYVER="$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
case "$PYVER" in
    3.8|3.9|3.1[0-9]|3.[2-9][0-9]) ;;
    *) warn "Python 版本过低（$PYVER），需要 3.8 或更高"; exit 1 ;;
esac

say "部署程序到 $LIB_DIR"
mkdir -p "$LIB_DIR"
rm -rf "$LIB_DIR/vigil"
cp -a "$SRC_DIR/src/vigil" "$LIB_DIR/vigil"
find "$LIB_DIR/vigil" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true

say "创建命令 $BIN"
cat > "$BIN" <<LAUNCHER
#!/usr/bin/env python3
# vigil launcher -- generated by install.sh
import os, sys
sys.path.insert(0, "$LIB_DIR")
os.environ.setdefault("VIGIL_LIB", "$LIB_DIR")
from vigil.cli import main
if __name__ == "__main__":
    sys.exit(main())
LAUNCHER
chmod 755 "$BIN"

say "运行安装向导"
if [ "${#PASSTHRU[@]}" -gt 0 ]; then
    exec "$BIN" install "${PASSTHRU[@]}"
fi
exec "$BIN" install
