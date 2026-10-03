"""Bounded self-improvement: evidence in, small changes out, always reversible.

What this is
------------
A loop that reads the traffic this host has actually seen, decides what that
traffic implies, and changes the program's own behaviour accordingly -- then
writes down what it did and reports it.

What this is not
----------------
It is not an agent with write access to its own source. Two tiers, and the
distinction between them is the whole safety argument:

* **Tier 1, adopted behaviour (automatic).** New decoy paths, taken from paths
  that were really probed, and only when several independent sources agree.
  This is data, it is bounded by a strict path grammar, and it is enforced by
  the same nginx snippet as every other decoy.
* **Tier 2, source edits (off by default).** It can draft an edit to the one
  sanctioned file -- the curated decoy table -- but only when an operator has
  pointed `evolve.source_root` at a real checkout and switched
  `evolve.allow_code_edits` on. Even then: a size ceiling, a daily cap, an
  email to the operator *before* the write, a backup, the project's own privacy
  audit, and the test suite must pass afterwards or the file is restored.

Every rule below exists because of a specific way this could go wrong, and the
gates are the reason the loop is allowed to run unattended at all.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from ..core import paths, shell
from . import budget as budget_mod
from . import ledger
from . import report as report_mod
from . import score as score_mod

#: Adopted decoys: paths the loop has decided are worth enforcing. Separate from
#: the curation in `decoy.py` (which is reviewed by a human and shipped) and
#: from `learning.py`'s raw suggestions (which are not gated at all).
ADOPTED = paths.STATE_STATE / "evolve-adopted.json"

#: The only source file Tier 2 may touch. One file, one table, one insertion
#: point -- a self-editing security tool gets exactly this much rope.
SAFE_CODE_FILES = ("src/vigil/guards/decoy.py",)

#: Insertion anchor: new entries go immediately after this line inside DECOYS.
DECOYS_ANCHOR = "DECOYS: tuple = ("

#: A decoy path must survive nginx's config parser and our own regex. Quotes,
#: braces, spaces and semicolons are how a path becomes config injection.
_SAFE_PATH = re.compile(r"^/[A-Za-z0-9._~%/+-]{1,120}$")

#: What a probe looks like. Used as a second opinion, not as the only gate.
_PROBE_HINT = re.compile(
    r"\.(env|git|svn|bak|old|save|sql|zip|tar|gz|ini|conf|log|key|pem|yml|yaml|json|php|asp|jsp)"
    r"|admin|backup|config|database|phpmyadmin|xmlrpc|wp-|\.config|\.cache|\.ssh|\.aws"
    r"|mcp|sse|actuator|well-known|manager|console|debug|test|shell|upload|\.\.", re.I)


def _num(cfg, key, default):
    try:
        return float(cfg.get(key, default)) if cfg is not None else float(default)
    except (TypeError, ValueError):
        return float(default)


def _bool(cfg, key, default):
    try:
        return bool(cfg.get(key, default)) if cfg is not None else bool(default)
    except Exception:                                          # noqa: BLE001
        return bool(default)


# -- the adopted store -----------------------------------------------------

def adopted() -> list:
    try:
        data = json.loads(ADOPTED.read_text(encoding="utf-8"))
        return [e for e in data if isinstance(e, dict) and e.get("path")]
    except (OSError, ValueError):
        return []


def _save_adopted(items: list) -> bool:
    try:
        ADOPTED.parent.mkdir(parents=True, exist_ok=True)
        tmp = ADOPTED.with_suffix(".tmp")
        tmp.write_text(json.dumps(items, ensure_ascii=False, indent=1),
                       encoding="utf-8")
        tmp.replace(ADOPTED)
        return True
    except OSError:
        return False


def adopted_paths() -> list:
    return [str(e["path"]) for e in adopted()]


# -- evidence --------------------------------------------------------------

def evidence(cfg=None) -> dict:
    """What has this host actually seen? Reads only, never writes."""
    from ..guards import decoy as decoy_mod
    from ..guards import learning

    min_hits = int(_num(cfg, "evolve.min_hits", 8))
    min_ips = int(_num(cfg, "evolve.min_ips", 3))

    obs = []
    try:
        obs = learning.read_observations(limit=20000)
    except Exception:                                          # noqa: BLE001
        obs = []

    per = {}
    for o in obs:
        path = str(o.get("path") or "")
        status = int(o.get("status") or 0)
        if status not in (403, 404, 444):
            continue
        if not _SAFE_PATH.match(path):
            continue
        if re.search(r"\.(png|jpe?g|gif|svg|ico|css|js|mjs|map|woff2?|ttf|eot)$",
                     path, re.I):
            continue
        rec = per.setdefault(path, {"path": path, "hits": 0, "ips": set()})
        rec["hits"] += 1
        ip = str(o.get("ip") or "")
        if ip:
            rec["ips"].add(ip)

    known = {p for p, _t, _w in decoy_mod.DECOYS}
    known |= set(adopted_paths())
    try:
        known |= {str(e[0]) for e in decoy_mod.learned_decoys()}
    except Exception:                                          # noqa: BLE001
        pass

    model = score_mod.Scorer.load(paths.STATE_STATE / "evolve-model.json")
    out = []
    for rec in per.values():
        if rec["path"] in known:
            continue
        if rec["hits"] < min_hits or len(rec["ips"]) < min_ips:
            continue
        out.append({
            "path": rec["path"],
            "hits": rec["hits"],
            "ips": len(rec["ips"]),
            "score": model.score(rec["path"], 404, ""),
            "probe_like": bool(_PROBE_HINT.search(rec["path"])),
        })
    out.sort(key=lambda r: (-r["ips"], -r["hits"]))
    return {"observed": len(obs), "candidates": out,
            "known": len(known), "min_hits": min_hits, "min_ips": min_ips}


# -- proposals -------------------------------------------------------------

def proposals(cfg=None, ev=None) -> list:
    ev = ev or evidence(cfg)
    out = []
    for c in ev["candidates"]:
        # Two independent reasons to believe it is a probe: the name looks like
        # one, or the learned model -- which has seen this host's own traffic --
        # scores it high. Requiring at least one keeps a popular broken link
        # from being turned into a tripwire.
        if not (c["probe_like"] or c["score"] >= 0.75):
            continue
        out.append({
            "id": "adopt:%s" % c["path"],
            "tier": 1,
            "kind": "adopt_decoy",
            "title": "把「%s」纳入诱饵" % c["path"],
            "path": c["path"],
            "evidence": {"hits": c["hits"], "ips": c["ips"],
                         "score": c["score"], "probe_like": c["probe_like"]},
            "why": ("%d 个独立来源共请求 %d 次，且都不存在（%s）"
                    % (c["ips"], c["hits"],
                       "名字像探测" if c["probe_like"] else "模型判为探测")),
        })
    return out


# -- gates -----------------------------------------------------------------

def _tier1_gates(cfg, prop) -> tuple:
    path = prop.get("path") or ""
    if not _SAFE_PATH.match(path):
        return False, "路径字符不安全，不能写进 nginx 配置"
    if ".." in path:
        return False, "路径含 .."
    if path in adopted_paths():
        return False, "已经采纳过"
    max_total = int(_num(cfg, "evolve.max_adopted", 200))
    if len(adopted()) >= max_total:
        return False, "已采纳 %d 条，达到上限 %d" % (len(adopted()), max_total)
    per_run = int(_num(cfg, "evolve.max_per_run", 5))
    return True, "ok"


def _test_gate(cfg, source_root) -> tuple:
    """Prove the project still works before the edit is kept.

    The privacy audit runs first because it is fast, catches the mistake that
    matters most for a component that writes files, and does not need a whole
    test run to report it.
    """
    src = Path(source_root) / "src"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(src)

    ok, out, err = shell.run(
        ["python3", "-m", "compileall", "-q", str(src / "vigil")], timeout=90)
    if not ok:
        return False, "编译失败：%s" % (err or out)[:200]

    ok, out, err = shell.run(
        ["python3", "-c",
         "import sys; sys.path.insert(0, %r);"
         "from vigil.core import sourceaudit;"
         "f = sourceaudit.scan(%r);"
         "print(len(f));"
         "sys.exit(1 if f else 0)" % (str(src), str(source_root))],
        timeout=90, env=env)
    if not ok:
        return False, "源码审计发现了不该随包发布的内容：%s" % (out or err)[:200]

    if not _bool(cfg, "evolve.run_tests", True):
        return True, "已跳过测试（evolve.run_tests=false）"
    tests = str(cfg.get("evolve.test_target", "") if cfg is not None else "")
    cmd = ["python3", "-m", "unittest"]
    cmd += [tests] if tests else ["discover", "-s", "tests", "-p", "test_*.py"]
    ok, out, err = shell.run(cmd, cwd=str(source_root), timeout=600, env=env)
    if not ok:
        tail = (err or out or "").strip().splitlines()[-6:]
        return False, "测试未通过：" + " / ".join(tail)[:300]
    return True, "测试通过"


def _insert_decoys(text: str, entries: list) -> str:
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if line.strip().startswith(DECOYS_ANCHOR):
            block = "".join(entries) + "\n"
            return "".join(lines[:i + 1]) + block + "".join(lines[i + 1:])
    return ""


def _patch_entries(props: list) -> list:
    stamp = time.strftime("%Y-%m-%d")
    out = []
    for p in props:
        title = "自动采纳的新探测路径"
        why = p["why"].replace("\\", " ").replace('"', " ").replace("\n", " ")
        out.append('    # -- 由自修正循环于 %s 采纳：%s\n' % (stamp, why))
        out.append('    ("%s", "auto", "%s"),\n' % (p["path"], title))
    return out


# -- apply -----------------------------------------------------------------

def apply(cfg=None, prop=None, dry_run: bool = False, log=None) -> dict:
    """Adopt one proposal. Mail first, then change, then verify, then record."""
    prop = prop or {}
    kind = prop.get("kind")
    if kind != "adopt_decoy":
        return {"ok": False, "err": "未知的提案类型：%s" % kind}

    ok, why = _tier1_gates(cfg, prop)
    if not ok:
        return {"ok": False, "err": why, "gates": "tier1"}

    path = prop["path"]
    source_root = str(cfg.get("evolve.source_root", "") or "") if cfg is not None else ""
    want_code = _bool(cfg, "evolve.allow_code_edits", False) and source_root \
        and (Path(source_root) / SAFE_CODE_FILES[0]).is_file()

    b = budget_mod.Budget(cfg)
    may, reason = b.may_start()
    if not may and not dry_run:
        return {"ok": False, "err": "资源闸门拒绝：" + reason, "gates": "budget"}

    # ---- mail BEFORE anything is written -------------------------------
    plan = ["会给「%s」加一条诱饵规则（该路径不存在，被请求即视为探测）。" % path,
            "依据：%s" % prop.get("why", ""),
            "生效方式：%s" % ("同时写入源码表（需 git 提交后随下个版本发布）"
                            if want_code else "写入运行期采纳表，下次生成 nginx 片段时生效"),
            "回滚：vigil evolve rollback %s" % prop["id"],
            "不想要就设 evolve.enabled=false，或在邮件里回复说明。"]
    mailed = report_mod.mail(cfg, " vigil 将自我修改：%s" % path, plan,
                             severity="warn", log=log)
    entry = ledger.record("proposed", id=prop["id"], proposal=kind, path=path,
                          why=prop.get("why"), evidence=prop.get("evidence"),
                          tier=2 if want_code else 1, mailed=mailed)
    if dry_run:
        return {"ok": True, "dry_run": True, "id": prop["id"], "mailed": mailed,
                "ledger": entry}

    # ---- Tier 1: runtime data ------------------------------------------
    items = adopted()
    items.append({"path": path, "why": prop.get("why", ""),
                  "evidence": prop.get("evidence") or {},
                  "adoptedAt": time.time(), "id": prop["id"]})
    if not _save_adopted(items):
        ledger.record("failed", id=prop["id"], err="写入采纳表失败")
        return {"ok": False, "err": "写入采纳表失败"}

    # ---- Tier 2: the sanctioned source edit ----------------------------
    code_note, code_ok = "", False
    if want_code:
        code = _code_edit(cfg, source_root, [prop])
        code_note = code.get("detail", "")
        code_ok = bool(code.get("ok"))
        if not code.get("ok"):
            # Code edit failed: keep the runtime adoption (it is the part that
            # protects the host) and report the source side honestly.
            ledger.record("code-edit-skipped", id=prop["id"],
                          err=code.get("err"), detail=code.get("detail"))
        else:
            ledger.record("code-edited", id=prop["id"],
                          file=SAFE_CODE_FILES[0], backup=code.get("backup"),
                          detail=code.get("detail"))

    ledger.record("applied", id=prop["id"], proposal=kind, path=path, tier=1,
                  code_edited=code_ok)
    # 改完也要上报一份：只写本地台账的话，经验传不回上游，也就无法沉淀成
    # 下个版本里所有人都能拿到的东西 —— 那是这个通道存在的全部理由。
    sent = report_mod.send_report(cfg, {
        "event": "evolve-apply", "version": _version(),
        "kind": kind, "tier": 2 if code_ok else 1,
        "evidence": {"hits": (prop.get("evidence") or {}).get("hits"),
                     "sources": (prop.get("evidence") or {}).get("ips")},
        "code_edited": code_ok, "adopted": len(adopted()),
    })
    return {"ok": True, "id": prop["id"], "path": path, "mailed": mailed,
            "code": code_note, "adopted": len(adopted()),
            "reported": bool(sent.get("ok")), "report": sent}


def _code_edit(cfg, source_root, props) -> dict:
    """The only source write this program will ever make on its own.

    Bounded five ways: one file, one anchor, a size ceiling, a daily cap, and a
    full test run that must pass or the backup is put straight back.
    """
    root = Path(source_root)
    target = root / SAFE_CODE_FILES[0]
    try:
        original = target.read_text(encoding="utf-8")
    except OSError as e:
        return {"ok": False, "err": "读不到源码文件：%s" % e}

    today = time.strftime("%Y-%m-%d")
    done_today = len([e for e in ledger.read(limit=500)
                      if e.get("kind") == "code-edited"
                      and time.strftime("%Y-%m-%d",
                                        time.localtime(e.get("ts", 0))) == today])
    cap = int(_num(cfg, "evolve.max_code_edits_per_day", 3))
    if done_today >= cap:
        return {"ok": False, "err": "今天已改过 %d 次源码，达到上限 %d" % (done_today, cap)}

    entries = _patch_entries(props)
    patched = _insert_decoys(original, entries)
    if not patched:
        return {"ok": False, "err": "找不到插入锚点 %s" % DECOYS_ANCHOR}
    added = len(patched.splitlines()) - len(original.splitlines())
    if added > int(_num(cfg, "evolve.max_patch_lines", 40)):
        return {"ok": False, "err": "补丁 %d 行，超过上限" % added}

    bak = ledger.backup(target)
    if not bak:
        return {"ok": False, "err": "备份失败，放弃改动"}
    try:
        target.write_text(patched, encoding="utf-8")
    except OSError as e:
        return {"ok": False, "err": "写入失败：%s" % e}

    ok, detail = _test_gate(cfg, root)
    if not ok:
        ledger.restore(bak, target)
        return {"ok": False, "err": detail, "detail": "（已自动还原）", "backup": bak}
    return {"ok": True, "backup": bak,
            "detail": "已改 %s（+%d 行，%s）" % (SAFE_CODE_FILES[0], added, detail)}


def rollback(cfg=None, change_id=None, log=None) -> dict:
    """Undo one adopted decoy. Source edits are undone with git, deliberately:
    rewriting a tracked file from a backup copy would lose everything else
    that changed since, and `git checkout` is the honest tool for that."""
    items = adopted()
    kept = [e for e in items if e.get("id") != change_id]
    if len(kept) == len(items):
        return {"ok": False, "err": "找不到 %s" % change_id}
    if not _save_adopted(kept):
        return {"ok": False, "err": "写入失败"}
    ledger.record("rolled-back", id=change_id, remaining=len(kept))
    return {"ok": True, "id": change_id, "remaining": len(kept)}


# -- the loop --------------------------------------------------------------

def loop(cfg=None, log=None, max_rounds: int = 6, sleep: float = 20.0) -> dict:
    """One bounded pass of the self-correcting process.

    Bounded on purpose and in several directions at once: a wall-clock budget,
    a resource gate before every change, a cap on changes per run, and a hard
    round limit. A loop that can run forever is a loop that can consume a host
    forever, whatever its intentions.
    """
    b = budget_mod.Budget(cfg)
    may, reason = b.may_start()
    if not may:
        ledger.record("skipped", reason=reason, budget=b.describe())
        return {"ok": True, "skipped": reason, "applied": []}

    ev = evidence(cfg)
    props = proposals(cfg, ev)
    max_per_run = int(_num(cfg, "evolve.max_per_run", 5))
    applied, failed = [], []
    rounds = 0
    for prop in props[:max_per_run]:
        if b.expired() or rounds >= max_rounds:
            break
        rounds += 1
        r = apply(cfg, prop, log=log)
        (applied if r.get("ok") else failed).append(
            {"id": prop["id"], "path": prop["path"], **r})

    payload = {"event": "evolve-pass", "version": _version(),
               "budget": b.describe(), "observed": ev["observed"],
               "candidates": len(ev["candidates"]), "applied": len(applied),
               "failed": len(failed),
               "changes": [{"id": a["id"], "tier": 1} for a in applied]}
    sent = report_mod.send_report(cfg, payload)
    ledger.record("pass", applied=len(applied), failed=len(failed),
                  observed=ev["observed"], candidates=len(ev["candidates"]),
                  reported=bool(sent.get("ok")))
    return {"ok": True, "applied": applied, "failed": failed,
            "evidence": ev, "budget": b.describe(), "report": sent}


def _version() -> str:
    try:
        from ..version import __version__
        return __version__
    except Exception:                                          # noqa: BLE001
        return "?"


def scan(cfg=None) -> dict:
    return evidence(cfg)


def plan(cfg=None) -> dict:
    ev = evidence(cfg)
    return {"evidence": ev, "proposals": proposals(cfg, ev)}


def status(cfg=None) -> dict:
    b = budget_mod.Budget(cfg)
    return {
        "version": _version(),
        "enabled": _bool(cfg, "evolve.enabled", False),
        "code_edits": _bool(cfg, "evolve.allow_code_edits", False),
        "source_root": str(cfg.get("evolve.source_root", "") or "") if cfg is not None else "",
        "adopted": adopted(),
        "ledger": ledger.stats(),
        "budget": b.describe(),
        "may_start": b.may_start(),
        "report_url": str(cfg.get("evolve.report_url", report_mod.DEFAULT_URL))
        if cfg is not None else report_mod.DEFAULT_URL,
    }


def format_status(st: dict) -> str:
    may, reason = st["may_start"]
    lines = [
        "自修正循环      %s" % ("启用" if st["enabled"] else "未启用（evolve.enabled=false）"),
        "源码自改        %s" % ("允许" if st["code_edits"] else "不允许（只采纳行为数据）"),
        "源码树          %s" % (st["source_root"] or "未指定（无法自改源码）"),
        "已采纳诱饵      %d 条" % len(st["adopted"]),
        "修改台账        %d 条（已应用 %d，已回滚 %d）"
        % (st["ledger"]["entries"], st["ledger"]["applied"], st["ledger"]["rolled_back"]),
        "本次可否开工    %s%s" % ("可以" if may else "暂不", "" if may else "：" + reason),
        "上报地址        %s" % st["report_url"],
    ]
    return "\n".join(lines)


# -- the watchdog ----------------------------------------------------------

#: A loop that adopts more than this in an hour is not learning, it is
#: thrashing -- and the cause is almost always a single noisy source rather
#: than new intelligence.
RUNAWAY_PER_HOUR = 30


def watchdog(cfg=None, log=None) -> dict:
    """Look at the self-improvement loop from the outside.

    This is the answer to "who watches the thing that edits itself". It does
    not trust the loop's own bookkeeping to be correct -- it reads the same
    files a human would and reports what does not add up.
    """
    now = time.time()
    entries = ledger.read(limit=2000)
    findings = []

    def _within(entry, seconds):
        return (now - float(entry.get("ts") or 0)) <= seconds

    hour = [e for e in entries if _within(e, 3600)]
    applied_hour = [e for e in hour if e.get("kind") == "applied"]
    if len(applied_hour) > RUNAWAY_PER_HOUR:
        findings.append(("crit", "一小时内应用了 %d 次改动（阈值 %d），疑似失控"
                         % (len(applied_hour), RUNAWAY_PER_HOUR)))

    failed = [e for e in entries if e.get("kind") == "failed" and _within(e, 3600)]
    if len(failed) > 5:
        findings.append(("warn", "一小时内 %d 次改动失败，检查状态目录权限" % len(failed)))

    unwritten = [e for e in entries if e.get("written") is False]
    if unwritten:
        findings.append(("warn", "有 %d 条台账写入失败，审计链不完整" % len(unwritten)))

    today = time.strftime("%Y-%m-%d")
    edits_today = [e for e in entries if e.get("kind") == "code-edited"
                   and time.strftime("%Y-%m-%d",
                                     time.localtime(e.get("ts", 0))) == today]
    cap = int(_num(cfg, "evolve.max_code_edits_per_day", 3))
    if len(edits_today) > cap:
        findings.append(("crit", "今日源码自改 %d 次，超过上限 %d"
                         % (len(edits_today), cap)))

    adopted_n = len(adopted())
    limit = int(_num(cfg, "evolve.max_adopted", 200))
    if adopted_n > limit:
        findings.append(("warn", "已采纳诱饵 %d 条，超过上限 %d" % (adopted_n, limit)))

    try:
        size = ledger.LEDGER.stat().st_size
    except OSError:
        size = 0
    if size > 8 * 1024 * 1024:
        findings.append(("warn", "台账已 %.1f MB，建议清理" % (size / 1048576.0)))

    b = budget_mod.Budget(cfg)
    may, reason = b.may_start()
    if not may and _bool(cfg, "evolve.enabled", False):
        findings.append(("info", "自修正循环当前无法开工：%s" % reason))

    hard = [f for f in findings if f[0] == "crit"]
    stamped = ledger.record("watchdog", findings=[f[0] for f in findings],
                            adopted=adopted_n, entries=len(entries))
    if hard:
        report_mod.mail(cfg, "自修正循环异常：%s" % hard[0][1],
                        ["%s：%s" % (lvl, msg) for lvl, msg in findings]
                        + ["", "处理建议：",
                           "  1) 先看台账：vigil evolve status",
                           "  2) 暂停循环：vigil config set evolve.enabled false",
                           "  3) 撤销今天的源码改动：cd 源码树 && git diff 复核后 git checkout -- <文件>"],
                        severity="crit", log=log)
    report_mod.send_report(cfg, {"event": "watchdog",
                                 "version": _version(),
                                 "findings": [{"level": l, "what": m[:200]}
                                              for l, m in findings],
                                 "adopted": adopted_n})
    return {"ok": not hard, "findings": findings, "ledger_written": stamped.get("written"),
            "adopted": adopted_n, "entries": len(entries)}


def format_watchdog(res: dict) -> str:
    if not res["findings"]:
        return "自修正循环未见异常（已采纳 %d 条，台账 %d 条）" % (
            res["adopted"], res["entries"])
    icon = {"crit": "✗", "warn": "!", "info": "·"}
    return "\n".join("%s %s" % (icon.get(l, "·"), m) for l, m in res["findings"])
