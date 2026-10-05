#!/bin/bash
# Publish the Let's Encrypt certificate into the panel's cert directory.
#
# Runs two ways, and must behave identically both times:
#   * as a certbot deploy hook, with RENEWED_LINEAGE set;
#   * by hand, which is what deploy/install.sh does after issuing a cert.
#
# It copies rather than symlinks on purpose. certbot's /etc/letsencrypt
# trees are 0700 root, so nginx (running as www) cannot follow a symlink
# into them; the copy is what lets the worker read the key at all.
#
# __PUBLIC_HOST__ is replaced by deploy/install.sh with this deployment's
# published host when the hook is installed to /usr/local/bin: certbot runs
# it from cron with none of the install script's environment, so the value
# has to be baked in. There is no fallback domain on purpose -- running the
# unrendered copy would silently expect a certificate that does not exist.
set -euo pipefail

SRC="${RENEWED_LINEAGE:-}"
if [[ -z "$SRC" ]]; then
  # VIGIL_DASH_HOST lets a hand-run copy point at another host; the installed
  # copy has the value baked in at deploy time.
  HOST="${VIGIL_DASH_HOST:-__PUBLIC_HOST__}"
  if [[ "$HOST" == "__PUBLIC_HOST__" ]]; then
    echo "certbot-hook: 钩子尚未渲染（请用 deploy/install.sh 安装，或设 VIGIL_DASH_HOST）" >&2
    exit 1
  fi
  SRC="/etc/letsencrypt/live/${HOST}"
fi
NAME="$(basename "$SRC")"
DEST="/www/server/panel/vhost/cert/${NAME}"

[[ -s "$SRC/fullchain.pem" && -s "$SRC/privkey.pem" ]] || {
  echo "certbot-hook: no certificate at $SRC" >&2
  exit 1
}

install -d -m 0700 "$DEST"
if cmp -s "$SRC/fullchain.pem" "$DEST/fullchain.pem" 2>/dev/null \
   && cmp -s "$SRC/privkey.pem" "$DEST/privkey.pem" 2>/dev/null; then
  echo "certbot-hook: $NAME unchanged"
  exit 0
fi

install -m 0644 "$SRC/fullchain.pem" "$DEST/fullchain.pem"
install -m 0600 "$SRC/privkey.pem" "$DEST/privkey.pem"

if [[ -z "${RENEWED_LINEAGE:-}" ]] || systemctl is-active --quiet nginx; then
  if /www/server/nginx/sbin/nginx -t >/dev/null 2>&1; then
    /www/server/nginx/sbin/nginx -s reload
    echo "certbot-hook: $NAME installed, nginx reloaded"
  else
    echo "certbot-hook: $NAME installed but nginx -t failed; not reloading" >&2
    exit 1
  fi
else
  echo "certbot-hook: $NAME installed"
fi
