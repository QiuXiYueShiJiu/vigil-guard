#!/bin/bash
# Local dev runner for the dashboard backend. Not used in production: the
# deployed service is a systemd unit. This exists so the code can be
# restarted and probed during development without hand-managing PIDs.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIDFILE="/tmp/vigil-dash-dev.pid"
LOG="/tmp/vigil-dash-dev.log"

stop() {
  if [ -f "$PIDFILE" ]; then
    local pid
    pid="$(cat "$PIDFILE" 2>/dev/null || true)"
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      for _ in $(seq 1 30); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
      done
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$PIDFILE"
  fi
}

start() {
  cd "$ROOT" || exit 1
  VIGIL_DASH_PORT="${PORT:-9310}" nohup /usr/bin/python3 \
    "$ROOT/backend/serve.py" >"$LOG" 2>&1 &
  echo $! > "$PIDFILE"
  sleep "${WAIT:-6}"
  cat "$LOG"
}

case "${1:-restart}" in
  stop) stop ;;
  start) start ;;
  *) stop; start ;;
esac
