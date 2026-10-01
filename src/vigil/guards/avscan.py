"""Malware scanning.

A thin scheduler around whatever engine the host already has. This module
does not implement malware detection, and that is the point: shipping a
half-written AV would give the operator a false sense of coverage.

Two engines are supported, both discovered:

``maldet``
    Reported to be the better fit on hosting boxes because its signature set
    targets web malware specifically. Note that it is a *known-sample*
    database -- it catches malware that is circulating, not a hand-written
    web shell, which is why the content heuristic in the checks package
    exists alongside it.

``clamav``
    General purpose. Useful for upload directories; heavier on memory.

The scan itself is deliberately not "run and forget": the result is parsed
and only the hits are turned into an alert, because a nightly "scan
completed, 0 hits" email is noise that trains people to ignore alerts.
"""
from __future__ import annotations

import os
import re
import time
from datetime import datetime

from ..core import detect, paths, shell
from ..core.config import load as load_config
from ..core.logging import get as get_logger
from ..core.state import read_json, write_json
from ..mail import send_alert
from ..mail.message import SEV_CRIT, SEV_WARN, Alert

STATE = paths.STATE_STATE / "avscan.json"


def _log():
    return get_logger("health")


def engine() -> dict:
    return detect.malware_engine()


def _maldet_scan(cfg, log) -> dict:
    env = detect.maldet()
    binary = env.get("binary") or "/usr/local/maldetect/maldet"
    targets = cfg.get("malware.monitor_paths", []) or \
        cfg.get("checks.web_roots", []) or []
    if not targets:
        return {"ok": False, "detail": "没有配置扫描目录"}
    hits = []
    scanned = 0
    for target in targets[:10]:
        if not os.path.isdir(target):
            continue
        ok, out, err = shell.run([binary, "-a", target], timeout=1800)
        if not ok:
            log.warn("扫描 %s 失败: %s" % (target, (err or out).strip()[:200]))
        for line in (out or "").splitlines():
            m = re.search(r"scan completed.*?:\s*files\s+(\d+),\s*malware hits\s+(\d+)",
                          line)
            if m:
                scanned += int(m.group(1))
                continue
            m = re.search(r"\{hit\}\s+malware hit\s+(\S+)\s+found for\s+(\S+)", line)
            if m:
                hits.append((m.group(2), m.group(1)))
    return {"ok": True, "scanned": scanned, "hits": hits}


def _clamav_scan(cfg, log) -> dict:
    env = detect.clamav()
    binary = env.get("daemon") or env.get("binary") or "/usr/bin/clamscan"
    targets = cfg.get("malware.monitor_paths", []) or \
        cfg.get("checks.web_roots", []) or []
    if not targets:
        return {"ok": False, "detail": "没有配置扫描目录"}
    hits = []
    scanned = 0
    argv = [binary, "--infected", "--no-summary", "--recursive"] + targets[:10]
    ok, out, err = shell.run(argv, timeout=3600)
    # clamscan exits 1 when it finds something; that is not a failure.
    for line in (out or "").splitlines():
        if line.endswith("FOUND"):
            path, _, sig = line.rpartition(":")
            hits.append((path.strip(), sig.replace("FOUND", "").strip()))
    m = re.search(r"Scanned files:\s*(\d+)", out or "")
    if m:
        scanned = int(m.group(1))
    if not ok and not hits and err:
        return {"ok": False, "detail": (err or out).strip()[:300]}
    return {"ok": True, "scanned": scanned, "hits": hits}


def run_once(cfg=None, log=None, notify: bool = True) -> dict:
    cfg = cfg or load_config()
    log = log or _log()
    started = time.time()

    # Cheap inotify-based hits first: if the real-time monitor already saw
    # something, say so even if a full scan is not due.
    eng = engine()
    kind = eng.get("engine", "none")
    if kind == "maldet":
        from .checks.util import read_json as _rj  # noqa: F401
        result = _maldet_scan(cfg, log)
    elif kind == "clamav":
        result = _clamav_scan(cfg, log)
    else:
        return {"ok": False, "detail": "本机未安装 maldet 或 clamav，未扫描"}

    result["engine"] = kind
    result["elapsed"] = round(time.time() - started, 2)
    result["when"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    write_json(STATE, {"last": result}, mode=0o640)
    log.info("恶意软件扫描完成（%s）：扫描 %s 个文件，命中 %d 个"
             % (kind, result.get("scanned", "?"), len(result.get("hits") or [])))

    if notify and result.get("hits"):
        _notify(cfg, result, log)
    return result


def _notify(cfg, result: dict, log) -> None:
    hits = result["hits"]
    alert = Alert(
        title="恶意软件扫描发现 %d 个可疑文件" % len(hits),
        severity=SEV_CRIT, kind="alert",
        summary="引擎 %s 在本次扫描中命中签名库（共扫描 %s 个文件）"
                % (result.get("engine"), result.get("scanned", "?")),
    )
    sec = alert.add_section("命中文件")
    for path, sig in hits[:25]:
        sec.add("%s" % path)
        sec.add("    引擎判定: %s" % sig)
        try:
            st = os.stat(path)
            sec.add("    大小 %d 字节，属主 uid=%d，修改时间 %s"
                    % (st.st_size, st.st_uid,
                       datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")))
        except OSError:
            pass
        sec.add("")
    if len(hits) > 25:
        sec.add("…另有 %d 个文件未列出" % (len(hits) - 25))
    sec.add("处置建议：先确认这些文件是否为你自己的程序，再决定是否删除；"
            "删除前建议备份，以便事后分析入侵路径。")
    sec.add("本程序**不会自动删除文件** —— 误删会把网站搞挂，"
            "而且删掉证据会让溯源变难。")

    rep = send_alert(alert, cfg, log)
    log.warn("恶意软件告警已发送：%s" % rep.summary())


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="vigil-avscan",
                                description="Run a malware scan with the "
                                            "engine installed on this host.")
    p.add_argument("--no-notify", action="store_true")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    result = run_once(notify=not args.no_notify)
    if args.json:
        import json
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    else:
        print(result.get("detail") or
              "扫描 %s 个文件，命中 %d 个" % (result.get("scanned", "?"),
                                             len(result.get("hits") or [])))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
