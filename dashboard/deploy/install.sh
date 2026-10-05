#!/bin/bash
# Deploy / refresh the vigil console on this host.
#
#   deploy/install.sh                     install or update; host identity
#                                         comes from config.json
#   deploy/install.sh --host HOST         set (or change) the published host
#   deploy/install.sh --site-name NAME    set the name shown in the chrome
#   deploy/install.sh --webroot PATH      set the static web root
#   deploy/install.sh --no-nginx          only refresh code and restart the service
#
# Idempotent. Safe to re-run after changing anything under backend/ or
# frontend/: it copies the tree into place, publishes the static assets the
# way nginx expects, and restarts the unit.
#
# **Host identity is configuration, never a literal in this repository.**
# Everything below -- the vhost name, the certificate directory, the web
# root, the display name -- is read back through backend/settings.py, so this
# script and the running service can never disagree about which host they are
# on. `--host` / `--site-name` / `--webroot` write into config.json (0600)
# and then the same read-back path is used.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SITES_DIR="/www/server/nginx/conf/vigil-dashboard-sites"
DO_NGINX=1
HOST_OVERRIDE=""
NAME_OVERRIDE=""
WEBROOT_OVERRIDE=""

usage() {
  sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)      HOST_OVERRIDE="${2:-}"; shift 2 ;;
    --site-name) NAME_OVERRIDE="${2:-}"; shift 2 ;;
    --webroot)   WEBROOT_OVERRIDE="${2:-}"; shift 2 ;;
    --no-nginx)  DO_NGINX=0; shift ;;
    -h|--help)   usage; exit 0 ;;
    *) echo "未知参数：$1（--help 看用法）" >&2; exit 2 ;;
  esac
done

say() { printf '\033[36m[deploy]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[deploy:error]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "需要 root 权限"
[[ -f "$SRC/backend/serve.py" ]] || die "找不到 backend/serve.py，请从仓库根目录运行"

# ── 0. 主机身份 ────────────────────────────────────────────────────────
# Overrides go into config.json first; then every value is read back through
# the backend, which is the single definition of what this deployment is.
if [[ -n "$HOST_OVERRIDE$NAME_OVERRIDE$WEBROOT_OVERRIDE" ]]; then
  python3 - "$SRC" "$HOST_OVERRIDE" "$NAME_OVERRIDE" "$WEBROOT_OVERRIDE" <<'PY'
import json, os, sys
src, host, name, webroot = sys.argv[1:5]
path = os.path.join(src, "config.json")
try:
    with open(path, encoding="utf-8") as fh:
        cfg = json.load(fh)
    if not isinstance(cfg, dict):
        cfg = {}
except (OSError, ValueError):
    cfg = {}
if host:
    cfg["public_host"] = host
if name:
    cfg["display_name"] = name
if webroot:
    cfg["webroot"] = webroot
with open(path, "w", encoding="utf-8") as fh:
    json.dump(cfg, fh, ensure_ascii=False, indent=2, sort_keys=True)
    fh.write("\n")
os.chmod(path, 0o600)
PY
  say "已写入主机身份到 config.json"
fi

CFG="$(python3 - "$SRC" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from backend import settings
print(settings.PUBLIC_HOST)
print(settings.DISPLAY_HOST)
print(settings.WWWROOT)
print(settings.SERVER_LAT)
print(settings.SERVER_LON)
PY
)" || die "读取 config.json 失败（backend/settings.py 无法导入）"

HOST="$(printf '%s\n' "$CFG" | sed -n 1p)"
SITE_NAME="$(printf '%s\n' "$CFG" | sed -n 2p)"
WEBROOT="$(printf '%s\n' "$CFG" | sed -n 3p)"
LAT="$(printf '%s\n' "$CFG" | sed -n 4p)"
LON="$(printf '%s\n' "$CFG" | sed -n 5p)"

[[ -n "$HOST" ]] || die "config.json 里没有 public_host"
if [[ "$HOST" == "status.example.com" ]]; then
  cat >&2 <<'MSG'
[deploy:error] public_host 还是占位值 status.example.com。
  请先指定这台机器真正对外发布的域名，例如：
      bash deploy/install.sh --host status.example.com --site-name "状态页"
  或直接编辑 config.json：
      {"public_host": "...", "display_name": "...", "webroot": "...",
       "server_lat": 0.0, "server_lon": 0.0}
  这条检查是故意的：域名是这个控制台的 Host 校验、证书路径与 vhost 的
  来源，装错等于对外发布一个连不上的站点。
MSG
  exit 1
fi
if [[ "$LAT" == "0.0" || "$LON" == "0.0" ]]; then
  printf '\033[33m[deploy:warn]\033[0m server_lat / server_lon 未配置（当前 %s, %s）。\n' "$LAT" "$LON"
  echo "               地图会把所有流星画到几内亚湾，请在 config.json 里补上这台机器"
  echo "               的真实经纬度（只影响画线起点，不影响采集与封禁）。"
fi

CONF="/www/server/panel/vhost/nginx/${HOST}.conf"
CERTDIR="/www/server/panel/vhost/cert/${HOST}"

[[ -f "$SRC/backend/serve.py" ]] || die "找不到 backend/serve.py"

# ── 1. 代码 ────────────────────────────────────────────────────────────
say "同步代码到 $SRC（就地更新）"
find "$SRC" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true

# ── 2. 静态资源 ────────────────────────────────────────────────────────
say "发布静态资源到 $WEBROOT"
install -d -m 0755 "$WEBROOT"
install -d -m 0755 "$WEBROOT/assets"

# ── content-hashed asset names ──────────────────────────────────────────
# These files were previously served with `max-age=604800, immutable`, which
# meant a redeploy was invisible to anyone who had already loaded the page:
# the browser does not even revalidate an immutable response, so the operator
# keeps seeing the old design for a week. Naming each asset after a hash of
# its own bytes fixes that properly -- the URL changes when the file changes,
# so the long cache is safe and correctness does not depend on anyone
# pressing Ctrl-Shift-R.
ASSETS="$WEBROOT/assets"
rm -f "$ASSETS"/*.css "$ASSETS"/*.js "$ASSETS"/*.mjs

# original basename -> installed (hashed) basename. The rewrite below needs
# the *original* name to match against the HTML; hashing the installed name
# and looking for that in the HTML finds nothing, which is exactly how the
# first version of this left every stylesheet and script pointing at a file
# that no longer existed.
declare -A ASSET_MAP=()
for f in "$SRC"/frontend/assets/*; do
  base="$(basename "$f")"
  case "$base" in
    world.json|*.gz) continue ;;          # handled below, keyed by the loader
    *.js|*.mjs)
      # A syntax error here would ship a page that does nothing at all, and
      # `node --check` catches it in milliseconds.
      if command -v node >/dev/null 2>&1; then
        node --check "$f" || die "语法检查失败：$base"
      fi
      ;;
  esac
  hash="$(md5sum "$f" | cut -c1-10)"
  ext="${base##*.}"
  stem="${base%.*}"
  installed="${stem}.${hash}.${ext}"
  install -m 0644 "$f" "$ASSETS/$installed"
  ASSET_MAP["$base"]="$installed"
done

# ES module imports refer to each other by relative name ("from './map.js'").
# Renaming the files without rewriting those specifiers leaves the browser
# requesting a file that no longer exists -- the whole page's JavaScript then
# fails to load, which looks exactly like "my change did nothing".
# core.js is imported by both pages and by the other modules, so normalise it
# first, then rewrite every specifier in every installed script.
rewrite_module_imports() {
  local file name target
  for file in "${!ASSET_MAP[@]}"; do
    case "$file" in *.js|*.mjs) ;; *) continue ;; esac
    for name in "${!ASSET_MAP[@]}"; do
      case "$name" in *.js|*.mjs) ;; *) continue ;; esac
      [[ "$name" == "$file" ]] && continue
      target="$ASSETS/${ASSET_MAP[$file]}"
      sed -i "s|\(\./\)${name}\b|\1${ASSET_MAP[$name]}|g" "$target"
      sed -i "s|\(/\)${name}\b|\1${ASSET_MAP[$name]}|g" "$target"
    done
  done
}
rewrite_module_imports

build_manifest() {
  : > "$WEBROOT/asset-manifest.txt"
  local name
  for name in "${!ASSET_MAP[@]}"; do
    printf '%s -> %s\n' "$name" "${ASSET_MAP[$name]}" >> "$WEBROOT/asset-manifest.txt"
  done
  sort -o "$WEBROOT/asset-manifest.txt" "$WEBROOT/asset-manifest.txt"
}
# world.json is fetched by a stable path from the page JS, and its own meta
# carries a build timestamp, so it keeps a plain name and a short cache.
install -m 0644 "$SRC/backend/data/world.json" "$ASSETS/world.json"
gzip -9 -kf "$ASSETS/world.json"

# Rewrite the HTML to point at the hashed names.
rewrite_html() {
  local src="$1" dest="$2"
  local out name
  out="$(cat "$src")"
  for name in "${!ASSET_MAP[@]}"; do
    out="${out//\/assets\/${name}/\/assets\/${ASSET_MAP[$name]}}"
  done
  printf '%s' "$out" > "$dest"
  chmod 0644 "$dest"
}

# Fail loudly rather than shipping a page that references missing files.
verify_html() {
  local file="$1"
  local missing
  missing="$(grep -oE '/assets/[A-Za-z0-9._-]+' "$file" \
    | sort -u \
    | while read -r ref; do
        [[ -f "$WEBROOT$ref" || -f "$WEBROOT$ref.gz" ]] || echo "$ref"
      done)"
  if [[ -n "$missing" ]]; then
    printf '\033[31m[deploy:error]\033[0m %s 引用了不存在的资源：\n%s\n' \
      "$(basename "$file")" "$missing" >&2
    return 1
  fi
}

# Every relative import in every installed script must resolve, or the page
# loads its HTML and then dies silently.
verify_imports() {
  local bad=""
  local f spec
  for f in "$ASSETS"/*.js "$ASSETS"/*.mjs; do
    [[ -f "$f" ]] || continue
    for spec in $(grep -oE "from '[^']+'" "$f" | sed "s/from '//; s/'//"); do
      case "$spec" in
        ./*)
          [[ -f "$ASSETS/${spec#./}" ]] || bad="$bad\n  $(basename "$f") -> $spec"
          ;;
      esac
    done
  done
  if [[ -n "$bad" ]]; then
    printf '\033[31m[deploy:error]\033[0m 模块导入指向不存在的文件：%b\n' "$bad" >&2
    return 1
  fi
}
rewrite_html "$SRC/frontend/index.html" "$WEBROOT/index.html"
rewrite_html "$SRC/frontend/admin.html" "$WEBROOT/admin.html"
build_manifest
verify_html "$WEBROOT/index.html"
verify_html "$WEBROOT/admin.html"
verify_imports
say "资源清单：$(wc -l < "$WEBROOT/asset-manifest.txt") 个文件（内容哈希命名）"
install -d -m 0700 "$CERTDIR"

# ── 3. 运行期目录 ──────────────────────────────────────────────────────
say "准备运行期目录"
install -d -m 0750 /var/lib/vigil-dashboard
install -d -m 0755 "$SITES_DIR"

# ── 4. systemd ─────────────────────────────────────────────────────────
# The unit carries __DASHBOARD_DIR__ rather than a checkout path, so the same
# file works from wherever this repository is cloned.
say "安装 systemd 单元"
sed -e "s|__DASHBOARD_DIR__|$SRC|g" \
  "$SRC/deploy/vigil-dashboard.service" \
  > /etc/systemd/system/vigil-dashboard.service
chmod 0644 /etc/systemd/system/vigil-dashboard.service
systemctl daemon-reload
systemctl enable vigil-dashboard.service >/dev/null

# ── 5. nginx 站点 ──────────────────────────────────────────────────────
if [[ $DO_NGINX -eq 1 ]]; then
  if [[ -s "$CERTDIR/fullchain.pem" && -s "$CERTDIR/privkey.pem" ]]; then
    say "已存在证书，写入 vhost：$CONF"
  else
    say "尚未签发证书，先写入自签占位证书（HTTPS 可用但浏览器会告警）"
    openssl req -x509 -nodes -newkey rsa:2048 -days 30 \
      -keyout "$CERTDIR/privkey.pem" -out "$CERTDIR/fullchain.pem" \
      -subj "/CN=${HOST}" >/dev/null 2>&1
    chmod 0600 "$CERTDIR/privkey.pem"
    chmod 0644 "$CERTDIR/fullchain.pem"
  fi
  # The vhost includes three sidecar files the panel convention expects.
  # Create them empty (or with a comment) so nginx never fails on a missing
  # include: a half-installed site is worse than an unconfigured one.
  install -d -m 0755 "/www/server/panel/vhost/nginx/extension/${HOST}"
  install -d -m 0755 "/www/server/panel/vhost/nginx/well-known"
  install -d -m 0755 "$SITES_DIR"
  [[ -f "/www/server/panel/vhost/nginx/extension/${HOST}/vigil-deny.conf" ]] || \
    printf '# vigil 封禁列表（本站点）——由 vigil bouncer 维护，请勿手工编辑\n' \
      > "/www/server/panel/vhost/nginx/extension/${HOST}/vigil-deny.conf"
  [[ -f "/www/server/panel/vhost/nginx/well-known/${HOST}.conf" ]] || \
    printf '# 证书申请文件校验目录（certbot webroot 模式写入 /www/wwwroot）\nlocation ^~ /.well-known/acme-challenge/ {\n    alias /www/wwwroot/.well-known/acme-challenge/;\n    default_type text/plain;\n    access_log off;\n}\n' \
      > "/www/server/panel/vhost/nginx/well-known/${HOST}.conf"
  # Always leave a valid snippet for this host so the console can be told to
  # close its own site without a broken include in between.
  [[ -f "$SITES_DIR/${HOST}.conf" ]] || \
    printf '# vigil-dashboard 站点开关（本控制台自身站点）\n# 放行状态，无附加规则\n' \
      > "$SITES_DIR/${HOST}.conf"
  chmod 0644 "$SITES_DIR/${HOST}.conf"
  # Render the vhost template with this deployment's identity.
  sed -e "s|__PUBLIC_HOST__|$HOST|g" \
      -e "s|__WEBROOT__|$WEBROOT|g" \
      -e "s|__SITES_DIR__|$SITES_DIR|g" \
      "$SRC/deploy/nginx-vigil.conf" > "$CONF"
  chmod 0644 "$CONF"
  # The certbot deploy hook must carry the host too: certbot runs it without
  # any of this script's environment. Never clobber a hook the operator
  # already has.
  if [[ ! -e /usr/local/bin/vigil-cert-sync ]]; then
    sed -e "s|__PUBLIC_HOST__|$HOST|g" "$SRC/deploy/certbot-hook.sh" \
      > /usr/local/bin/vigil-cert-sync
    chmod 0755 /usr/local/bin/vigil-cert-sync
    say "已安装证书同步钩子 /usr/local/bin/vigil-cert-sync"
  fi
  if /www/server/nginx/sbin/nginx -t >/tmp/vigil-deploy-nginx.log 2>&1; then
    say "nginx 配置校验通过"
  else
    cat /tmp/vigil-deploy-nginx.log >&2
    die "nginx 配置校验失败，未重载（vhost 已写入，请检查后手动 nginx -t）"
  fi
fi

# ── 6. 服务 ────────────────────────────────────────────────────────────
say "启动 / 重载服务"
systemctl restart vigil-dashboard.service
sleep 2
if systemctl is-active --quiet vigil-dashboard.service; then
  say "vigil-dashboard 运行中"
else
  journalctl -u vigil-dashboard.service -n 30 --no-pager >&2 || true
  die "服务启动失败"
fi
curl -fsS --max-time 8 http://127.0.0.1:9310/api/v1/health >/dev/null \
  && say "接口自检通过" || die "接口无响应"

if [[ $DO_NGINX -eq 1 ]]; then
  /www/server/nginx/sbin/nginx -s reload && say "nginx 已重载"
fi

say "完成。主页 https://${HOST}/   管理页 https://${HOST}/admin.html  显示名 ${SITE_NAME}"
