"""Learning new signatures from what actually arrives, without guessing.

The objective this module serves is "generate new signatures from real
observations". The literature on doing that automatically is unanimous about
the hard part, and it is not the generation:

* Honeycomb (Kreibich & Crowcroft) derives signatures from traffic that
  reached a honeypot, and requires the pattern to be an **invariant across
  several independent connections**, not a feature of one;
* Polygraph and Autograph (Newsome et al.) add the step that matters most:
  every candidate signature is evaluated against a corpus of **known-good
  traffic**, and any candidate that matches it is discarded. Their central
  contribution was showing that generation is easy and false-positive
  control is the entire problem -- a signature that also matches legitimate
  requests converts an attack on the network into an outage of it.

So this module does three things in that order, and refuses to skip the
second:

1. **Observe** what arrives, and what happened to it. A request that was
   served 200 is evidence of legitimacy; a request that was served 404 to
   many independent sources is evidence of probing.
2. **Mine** candidates that are invariant across distinct source addresses,
   because one host repeating itself is not a pattern.
3. **Gate** every candidate against legitimate traffic -- both paths this
   server actually served and the site's own content -- and record the
   reason whenever one is refused.

And one deliberate asymmetry, which the objective asks to be stated plainly:

**Adoption is automatic only for the decoy candidate list.** Adding a decoy
is additive and reversible: the worst case is that a path nobody legitimate
requests answers with a dropped connection. Adding a *ban* signature is not
reversible in the same way -- a bad one blocks real users at the firewall,
and the operator finds out from them. So mined patterns that would make good
ban signatures are written to a **suggestion** file and never applied
without a human saying so. That is a decision, not a limitation.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from ..core import paths, shell
from ..core.state import read_json, write_json

#: Rolling record of requests and their outcomes. Bounded; this is evidence,
#: not a log -- the logs already exist and are the authoritative copy.
MAX_OBSERVATIONS = 20000

#: Tokens shorter than this match too much to be a signature of anything.
MIN_TOKEN = 4

#: A candidate must be seen from at least this many *distinct* sources.
MIN_DISTINCT = 3

#: Automatically adopted candidates must not have been seen this many times
#: served successfully by anyone. Zero is the honest bar for "never
#: legitimate", and the corpus gate enforces it; this is a second net.
MAX_LEGIT_HITS = 0

#: Statuses that mean "the resource is there but you may not have it".
#:
#: These are **not** evidence of a path nobody uses: an API that answers 401
#: to an unauthenticated request is a working endpoint. Treating them as
#: suspicious is how the self-learning pass adopted a real authenticated
#: interface as a seven-day decoy trap -- the operator's own tooling would
#: then have been banned by the tripwire built from its traffic.
AUTH_STATUSES = (401, 403)

#: A candidate must show this much "the path really is not there" evidence
#: (404/444 from independent sources) before it may be adopted. This is the
#: hard gate that keeps a popular broken link or an auth-protected route from
#: becoming a tripwire without a human looking at it.
MIN_NOTFOUND = 1


def observations_path() -> Path:
    return paths.STATE_STATE / "observations.jsonl"


def learned_path() -> Path:
    return paths.STATE_STATE / "learned-decoys.json"


def suggestions_path() -> Path:
    return paths.STATE_STATE / "learned-suggestions.json"


#: 压测/基准工具与「不是人也不是爬虫」的 User-Agent 特征。
#: 它们产出的路径不是情报，学进去只会让诱饵库变脏。
_NOISE_UA = ("apachebench", "ab/", "wrk", "siege", "jmeter", "locust",
             "hey/", "vegeta", "httperf", "gobuster", "nuclei", "nikto")


def _is_noise(ip: str, ua: str) -> bool:
    """本机 / 内网 / 压测工具的请求，不作为学习样本。

    只影响**学习**，不影响判定与封禁：来自这些地址的真实越界请求照样会被
    记录与处置，只是不拿来训练「哪些路径值得当诱饵」。
    """
    host = str(ip or "").strip()
    if host in ("127.0.0.1", "::1", "localhost"):
        return True
    if host.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                        "172.19.", "172.2", "172.30.", "172.31.")):
        return True
    low = str(ua or "").lower()
    return any(tok in low for tok in _NOISE_UA)


def observe(ip: str, path: str, status: int, ua: str = "",
            when: float = None) -> None:
    """Record one request. Never raises: this is best-effort evidence.

    Only paths that are not static assets are worth recording -- an image
    request that 404s is a broken link, not probing.
    """
    text = str(path or "").split("?")[0].split("#")[0]
    if not text or not text.startswith("/"):
        return
    # 压测与本机流量不是「有人在探测」的证据，却是最容易被误学成诱饵的东西：
    # 一台机器跑一轮 ApacheBench 就能刷出三十万条 `GET /`，把学习结果淹没。
    # 实测本机曾有一波 29.9 万行压测日志（UA ApacheBench/2.3），占全部日志 60%。
    if _is_noise(ip, ua):
        return
    low = text.lower()
    if re.search(r"\.(png|jpe?g|gif|webp|svg|ico|css|js|mjs|map|woff2?|ttf|eot"
                 r"|mp4|webm|mp3|wav|pdf)(\?|$)", low):
        return
    path_file = observations_path()
    try:
        path_file.parent.mkdir(parents=True, exist_ok=True)
        with open(str(path_file), "a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "ts": round(when if when is not None else time.time(), 2),
                "ip": str(ip or "")[:64],
                "path": text[:300],
                "status": int(status or 0),
                "ua": str(ua or "")[:160],
            }, ensure_ascii=False) + "\n")
    except (OSError, ValueError):
        return
    _trim(path_file, MAX_OBSERVATIONS)


def _trim(path: Path, keep: int) -> None:
    try:
        if path.stat().st_size < 4 * 1024 * 1024:
            return
        with open(str(path), "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        if len(lines) > keep:
            with open(str(path), "w", encoding="utf-8") as fh:
                fh.writelines(lines[-keep:])
    except OSError:
        pass


def read_observations(limit: int = MAX_OBSERVATIONS) -> list:
    out = []
    try:
        with open(str(observations_path()), "r", encoding="utf-8",
                  errors="replace") as fh:
            for line in fh.readlines()[-limit:]:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        return []
    return out


def tokens_for(path: str) -> list:
    """Candidate tokens for one path, most specific first.

    Two shapes, because probing has two shapes: a *directory* that should
    never exist (``/.git``, ``/wp-content``) and a *file* that gives itself
    away by its extension (``/backup.sql``). Both are things a decoy can
    safely claim.
    """
    text = str(path or "").strip()
    if not text or not text.startswith("/"):
        return []
    out = []
    parts = [p for p in text.split("/") if p]
    if not parts:
        return []
    last = parts[-1]
    if "." in last[1:] and len(last) >= MIN_TOKEN:
        out.append("/" + "/".join(parts[:-1] + [last]) if len(parts) > 1
                   else "/" + last)
    if len(parts) >= 1 and len(parts[0]) >= MIN_TOKEN:
        out.append("/" + parts[0])
    if len(parts) >= 2 and len(parts[1]) >= MIN_TOKEN:
        out.append("/" + parts[0] + "/" + parts[1])
    seen, uniq = set(), []
    for token in out:
        if token not in seen:
            seen.add(token)
            uniq.append(token)
    return uniq


def legitimate_corpus(cfg=None, max_files: int = 40) -> set:
    """Paths this server actually served successfully, and site content.

    This is the Polygraph gate. Anything in here is by definition something
    legitimate clients ask for, so no candidate matching it may be adopted.
    """
    legit = set()
    try:
        from ..core import detect
        for path in (detect.log_sources() or {}).get("nginx_access", []) or []:
            legit.update(_successful_paths(str(path), max_files))
    except (ImportError, OSError):
        pass
    try:
        from . import decoy
        from ..core.config import load as load_config
        cfg = cfg or load_config()
        domain, webroot = decoy._site(cfg)
        if webroot:
            text = decoy.corpus(webroot)
            for word in re.findall(r"[A-Za-z0-9_.-]{%d,}" % MIN_TOKEN, text):
                legit.add(word.lower())
    except (ImportError, OSError, ValueError):
        pass
    return legit


def _successful_paths(log_path: str, max_lines: int = 4000) -> set:
    """Every path the access log shows as reachable.

    A 2xx/3xx is obviously reachable. A 401/403 is reachable too -- the
    server found something there and asked for credentials -- so those count
    as legitimate corpus as well. Omitting them made "this endpoint requires
    authentication" look identical to "nobody ever asked for this", which is
    exactly the confusion the adoption gate must not have.
    """
    out = set()
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()[-max_lines:]
    except OSError:
        return out
    for line in lines:
        match = re.search(r'"(?:GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH) '
                          r'(\S+) [^"]*" (\d{3})', line)
        if not match:
            continue
        code = match.group(2)
        if not (code.startswith(("2", "3")) or int(code) in AUTH_STATUSES):
            continue
        path = match.group(1).split("?")[0]
        if not path.startswith("/"):
            continue
        out.add(path.lower())
        for token in tokens_for(path):
            out.add(token.lower())
    return out


def mine(observations=None, min_distinct: int = MIN_DISTINCT) -> list:
    """Group observations into candidates with their evidence.

    The unit of evidence is the number of **distinct source addresses**, not
    the number of requests: one host repeating a request a thousand times is
    one opinion.
    """
    observations = observations if observations is not None else \
        read_observations()
    stats = {}
    for rec in observations:
        path = str(rec.get("path", ""))
        ip = str(rec.get("ip", ""))
        status = int(rec.get("status", 0) or 0)
        for token in tokens_for(path):
            entry = stats.setdefault(token, {"ips": set(), "ok": 0, "auth": 0,
                                             "notfound": 0, "last": 0})
            if ip:
                entry["ips"].add(ip)
            # 401/403 mean "there is something here, you may not have it" --
            # a working authenticated endpoint, not a path nobody uses.
            if 200 <= status < 400 or status in AUTH_STATUSES:
                entry["ok"] += 1
                if status in AUTH_STATUSES:
                    entry["auth"] += 1
            elif status == 404:
                entry["notfound"] += 1
            entry["last"] = max(entry["last"], float(rec.get("ts", 0) or 0))
    candidates = []
    for token, entry in stats.items():
        distinct = len(entry["ips"])
        if distinct < min_distinct:
            continue
        candidates.append({
            "token": token,
            "distinct_ips": distinct,
            "served_ok": entry["ok"],
            "auth_hits": entry["auth"],
            "not_found": entry["notfound"],
            "last_seen": entry["last"],
        })
    candidates.sort(key=lambda c: (-c["distinct_ips"], c["token"]))
    return candidates


def evaluate(candidate: dict, legit: set, webroot: str = "") -> dict:
    """Decide whether a candidate is safe to adopt, and say why.

    Returns the candidate with ``verdict`` (``adopt`` / ``suggest``),
    ``confidence`` and ``reason`` attached. Every refusal carries a reason:
    a miner that silently discards candidates cannot be debugged or trusted.
    """
    token = candidate["token"]
    out = dict(candidate)
    bare = token.strip("/").lower()
    if len(bare) < MIN_TOKEN:
        out.update(verdict="reject", confidence=0.0, reason="token 过短")
        return out
    if candidate.get("auth_hits", 0) > 0:
        # 401/403 is a *live* endpoint asking for credentials. It is not
        # evidence that nobody legitimately uses the path, so it can never be
        # the basis of a tripwire: the next legitimate authenticated request
        # would be banned by a decoy built from its own traffic. Checked
        # before the generic "served successfully" gate so the reason names
        # the real problem.
        out.update(verdict="reject", confidence=0.0,
                   reason="曾以 401/403 应答 %d 次（需要鉴权），不能证明"
                          "该路径无人合法访问" % candidate["auth_hits"])
        return out
    if candidate.get("served_ok", 0) > MAX_LEGIT_HITS:
        out.update(verdict="reject", confidence=0.0,
                   reason="曾被成功访问过 %d 次，说明是正常资源"
                          % candidate["served_ok"])
        return out
    if candidate.get("not_found", 0) < MIN_NOTFOUND:
        # No evidence that the path is absent at all -- only "nobody sent a
        # credential". Adopting on that basis is guessing, and the guess is
        # installed as a trap.
        out.update(verdict="reject", confidence=0.0,
                   reason="缺少「路径不存在」的证据（404/444 命中 %d 次）"
                          % candidate.get("not_found", 0))
        return out
    if token.lower() in legit or bare in legit:
        out.update(verdict="reject", confidence=0.0,
                   reason="出现在合法流量或站点内容里")
        return out
    if webroot:
        try:
            if (Path(webroot) / bare).exists():
                out.update(verdict="reject", confidence=0.0,
                           reason="磁盘上已存在这个路径")
                return out
        except OSError:
            pass
    # Confidence is evidence-shaped, not a hand-picked number: how many
    # independent sources agreed, and how one-sided the outcome was.
    distinct = int(candidate.get("distinct_ips", 0))
    confidence = min(1.0, distinct / 10.0)
    if candidate.get("not_found", 0) == 0:
        confidence *= 0.5
    out["confidence"] = round(confidence, 2)
    out["verdict"] = "adopt" if distinct >= MIN_DISTINCT else "suggest"
    out["reason"] = ("%d 个独立来源请求过，且从未被成功访问"
                     % distinct)
    return out


def run(cfg=None, adopt: bool = True) -> dict:
    """Mine, gate, and (optionally) adopt the safe candidates."""
    from ..core.config import load as load_config
    cfg = cfg or load_config()
    webroot = ""
    try:
        from . import decoy
        _domain, webroot = decoy._site(cfg)
    except (ImportError, OSError):
        webroot = ""
    legit = legitimate_corpus(cfg)
    candidates = mine()
    evaluated = [evaluate(c, legit, webroot) for c in candidates]
    adoptable = [c for c in evaluated
                 if c["verdict"] == "adopt" and c["confidence"] > 0]
    suggestions = [c for c in evaluated if c["verdict"] != "adopt"]

    adopted = []
    if adopt and adoptable:
        try:
            current = read_json(learned_path(), {}) or {}
            if not isinstance(current, dict):
                current = {}
            for cand in adoptable:
                current[cand["token"]] = {
                    "token": cand["token"],
                    "confidence": cand["confidence"],
                    "distinct_ips": cand["distinct_ips"],
                    "reason": cand["reason"],
                    "adopted_at": time.time(),
                }
                adopted.append(cand["token"])
            write_json(learned_path(), current, mode=0o640)
        except OSError:
            adopted = []
    try:
        write_json(suggestions_path(),
                   {"at": time.time(), "items": suggestions[:200]},
                   mode=0o640)
    except OSError:
        pass

    return {"observed": len(read_observations()),
            "candidates": len(candidates),
            "adoptable": len(adoptable),
            "suggestions": len(suggestions),
            "adopted": adopted,
            "legit_corpus": len(legit),
            "evaluated": evaluated}


def learned_tokens() -> list:
    """Tokens adopted so far, for the decoy module to merge."""
    data = read_json(learned_path(), {}) or {}
    if not isinstance(data, dict):
        return []
    out = []
    for token, rec in data.items():
        if not isinstance(rec, dict):
            continue
        if not str(token).startswith("/") or len(str(token)) < MIN_TOKEN:
            # Never let a learned value become an nginx directive. The decoy
            # renderer writes `location = <path> {`, so a token containing a
            # brace or newline would escape its context and one malformed
            # entry would take down every site on the host.
            continue
        if any(ch in str(token) for ch in "{};\n\r\t \"'\\"):
            continue
        out.append(str(token))
    return sorted(set(out))


def apply_adopted(cfg=None) -> dict:
    """Push newly adopted candidates into nginx, if decoys are already in use.

    Deliberately conditional. A host that has not opted into decoy endpoints
    must never silently acquire web-server configuration: the operator's
    decision to run `vigil decoy install` is what authorises editing nginx,
    and an automatic pass has no business making that decision for them.

    When they have opted in, the full install path runs again -- including the
    per-candidate screening, the `nginx -t` validation and the rollback -- so
    a learned candidate is subject to exactly the same checks as a curated
    one. Learning does not confer trust.
    """
    from . import decoy
    try:
        st = decoy.status(cfg)
    except (ImportError, OSError):
        return {"applied": False, "reason": "诱饵模块不可用"}
    if not st.get("installed"):
        return {"applied": False, "reason": "诱饵端点未安装，新候选只记录不落盘"}

    installed = set(st.get("paths") or [])
    wanted = {path for path, _token, _why in decoy.learned_decoys()}
    pending = wanted - installed
    if not pending:
        return {"applied": False, "reason": "没有尚未落盘的新候选"}
    result = decoy.install(cfg)
    return {"applied": bool(result.get("ok")),
            "pending": sorted(pending),
            "written": result.get("written", ""),
            "problems": result.get("problems") or []}


def main(argv=None) -> int:
    """Timer entry point: mine and adopt, quietly."""
    import argparse

    from ..core.logging import get as get_logger

    parser = argparse.ArgumentParser(
        prog="vigil-learn",
        description="Mine new decoy candidates from observed probing.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    log = get_logger("learn")
    try:
        result = run()
    except Exception as exc:                            # noqa: BLE001
        log.warn("自学习失败：%s" % exc)
        return 1
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    if result.get("adopted"):
        log.info("自学习：采纳 %d 个新诱饵候选（%s）"
                 % (len(result["adopted"]), "、".join(result["adopted"][:5])))
        applied = apply_adopted()
        result["apply"] = applied
        if applied.get("applied"):
            log.info("自学习：已把新候选写入 Web 层（%s）"
                     % applied.get("written", ""))
        elif applied.get("problems"):
            log.warn("自学习：写入新候选失败：%s"
                     % "；".join(applied["problems"]))
    return 0


if __name__ == "__main__":                              # pragma: no cover
    import sys
    sys.exit(main())
