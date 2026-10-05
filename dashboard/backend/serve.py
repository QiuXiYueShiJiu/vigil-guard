#!/usr/bin/env python3
"""Entry point for the vigil dashboard service.

    backend/serve.py            run in the foreground
    backend/serve.py --check    verify imports, config and data, then exit

Everything long-lived is started here: the log tailer, the resource sampler,
then the HTTP server.
"""
from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import app, audit, auth, geo, settings, sites, store, threat  # noqa: E402
from backend import resources as res                                      # noqa: E402
from backend.tailer import LogTailer                                      # noqa: E402


def preflight() -> list:
    """Problems worth refusing to start over."""
    problems = []
    world = settings.DATA / "world.json"
    if not world.exists():
        problems.append("缺少地图数据 %s（运行 tools/build-map.py）" % world)
    if not settings.LOG_DIR.exists():
        problems.append("日志目录不存在：%s" % settings.LOG_DIR)
    if not geo.geo.available:
        problems.append("未找到 GeoLite2 数据库，地图将无法定位来源")
    if not threat.threat.snapshot().get("ledger_age") and \
            not settings.VIGIL_THREAT_STATE.exists():
        problems.append("未找到 vigil 威胁账本：%s" % settings.VIGIL_THREAT_STATE)
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description="vigil dashboard backend")
    ap.add_argument("--host", default=settings.PANEL_HOST)
    ap.add_argument("--port", type=int, default=settings.PANEL_PORT)
    ap.add_argument("--check", action="store_true",
                    help="自检后退出，不启动服务")
    args = ap.parse_args()

    problems = preflight()
    for item in problems:
        sys.stderr.write("[warn] %s\n" % item)

    if args.check:
        print(json_dump({
            "ok": not problems,
            "problems": problems,
            "paths": {
                "root": str(settings.ROOT),
                "data": str(settings.DATA),
                "state": str(settings.STATE_DIR),
                "logs": str(settings.LOG_DIR),
                "geo": geo.geo.path,
                "world": str(settings.DATA / "world.json"),
            },
            "geo_available": geo.geo.available,
            "threat": threat.threat.snapshot(),
            "sites": sites.sites.state_summary()["total"],
            "world_bytes": (settings.DATA / "world.json").stat().st_size
            if (settings.DATA / "world.json").exists() else 0,
        }))
        return 0 if not problems else 1

    tailer = LogTailer(store.hub.ingest)
    app.tailer_holder["tailer"] = tailer
    tailer.start()
    res.sampler.start()

    server = app.build_server(args.host, args.port)
    stop = threading.Event()

    def shutdown(signum, _frame):
        sys.stderr.write("[vigil-dashboard] signal %s, stopping\n" % signum)
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    sys.stderr.write(
        "[vigil-dashboard] listening on http://%s:%d  host=%s  geo=%s\n"
        % (args.host, args.port, settings.HOSTNAME,
           os.path.basename(geo.geo.path) or "none"))
    audit.record("service_start", ip="-", ok=True,
                 detail="监听 %s:%d" % (args.host, args.port))
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        tailer.stop()
        res.sampler.stop()
        server.server_close()
        audit.record("service_stop", ok=True)
    return 0


def json_dump(obj) -> str:
    import json
    return json.dumps(obj, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    sys.exit(main())
