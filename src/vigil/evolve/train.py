"""Self-training, and the feedback that closes the loop.

Where the labels come from
--------------------------
Nothing here is hand-labelled, and that is the point: an agent that needs a
human to tell it which requests were attacks is a classifier with extra steps.
The host produces its own supervision, because two outcomes are already known
without anyone's opinion:

* **positive** -- a request that subsequently got banned, or that hit a decoy.
  By construction the program already decided those were probes. Reading that
  decision back as a training label is free.
* **negative** -- a request that was served (2xx/3xx) to a real client. The
  server answered it, so it was not probing for something that does not exist.

So the model trains on the operator's own consequences: every ban the running
system issues becomes a labelled example for the scorer that will help decide
the next one. That is genuinely self-training, and it needs no GPU.

Closing the loop
----------------
Training alone would make the agent *confident*, not *better*. What makes it an
agent is that it checks whether its own changes worked: a decoy it adopted which
never fires is retired again. Without that step the adopted list only ever grows
and the whole thing degrades into an append-only pile of good intentions.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from ..core import paths
from . import ledger
from . import corpus as corpus_mod

corpus = corpus_mod   # 供命令层直接用，避免从 train 里再摸一层
from . import score as score_mod

MODEL = paths.STATE_STATE / "evolve-model.json"
OUTCOMES = paths.STATE_STATE / "evolve-outcomes.json"

#: A decoy younger than this is not judged -- traffic is bursty and a path can
#: legitimately go a day without a hit.
GRACE_HOURS = 24

#: How many observed hits make an adopted decoy worth keeping.
KEEP_HITS = 1


def _read_jsonl(path: Path, limit: int = 20000) -> list:
    out = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]:
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


def _bans() -> dict:
    """Banned addresses, and the paths named in their reasons."""
    try:
        data = json.loads((paths.STATE_STATE / "threat.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"ips": set(), "paths": set()}
    ips, hints = set(), set()
    for ip, meta in (data.get("bans") or {}).items():
        ips.add(str(ip))
        why = str((meta or {}).get("why") or (meta or {}).get("reason") or "")
        for tok in why.replace("：", " ").replace(":", " ").split():
            if tok.startswith("/") and len(tok) > 1:
                hints.add(tok.split("?")[0][:120])
    return {"ips": ips, "paths": hints}


def label_samples(cfg=None, limit: int = 8000) -> list:
    """Build (path, status, ua, label) from what already happened.

    Positive evidence, strongest first:
      1. the request hit a decoy  -> the program called it a probe
      2. the source address was later banned, and the reason names the path
      3. the path is in the adopted/curated decoy list and was requested
    Negative:
      4. the request was answered (2xx/3xx) -- real traffic
    """
    pos, neg = {}, {}
    decoy_hits = _read_jsonl(paths.STATE_STATE / "decoy-hits.jsonl", limit)
    bans = _bans()
    obs = _read_jsonl(paths.STATE_STATE / "observations.jsonl", limit)

    for h in decoy_hits:
        p = str(h.get("uri") or "").split("?")[0][:160]
        ip = str(h.get("ip") or "")
        if p.startswith("/"):
            pos[(p, 404, "")] = {"ip": ip, "why": "hit_decoy"}

    for o in obs:
        p = str(o.get("path") or "").split("?")[0][:160]
        if not p.startswith("/"):
            continue
        st = int(o.get("status") or 0)
        ua = str(o.get("ua") or "")[:120]
        ip = str(o.get("ip") or "")
        if st in (403, 404, 444) and (ip in bans["ips"] or p in bans["paths"]):
            pos.setdefault((p, st, ua), {"ip": ip, "why": "later_banned"})
        elif st in (403, 404, 444):
            # Unknown outcome: not a labelled example either way. Skipping is
            # what keeps the model from learning "404 means attack", which
            # would just relearn its own blocking.
            continue
        elif 200 <= st < 400:
            neg[(p, st, ua)] = {"ip": ip}

    samples = []
    for (p, st, ua), meta in pos.items():
        samples.append({"path": p, "status": st, "ua": ua, "label": 1,
                        "why": meta.get("why")})
    for (p, st, ua) in neg:
        if (p, st, ua) in pos:
            continue
        samples.append({"path": p, "status": st, "ua": ua, "label": 0,
                        "why": "served"})
    return samples


def train(cfg=None, epochs: int = 15, limit: int = 8000) -> dict:
    """One self-training pass. Idempotent and cheap: a few thousand dot products."""
    samples = label_samples(cfg, limit=limit)
    if not samples:
        return {"ok": False, "err": "还没有可用的监督信号（既没有封禁记录也没有被服务的请求）",
                "positives": 0, "negatives": 0}

    positives = sum(1 for s in samples if s["label"] == 1)
    negatives = len(samples) - positives
    if positives < 3 or negatives < 3:
        return {"ok": False, "err": "正负样本都太少，训练没有意义",
                "positives": positives, "negatives": negatives}

    model = score_mod.Scorer.load(MODEL)
    before = model.seen
    # Hold out a slice to report something honest rather than training accuracy.
    hold = samples[::7]
    fit = [s for i, s in enumerate(samples) if i % 7]
    for _ in range(max(1, epochs)):
        for s in fit:
            model.observe(s["path"], s["status"], s["ua"], label=s["label"])

    def accuracy(rows):
        if not rows:
            return 0.0
        ok = sum(1 for s in rows
                 if (model.score(s["path"], s["status"], s["ua"]) >= 0.5) == bool(s["label"]))
        return round(100.0 * ok / len(rows), 1)

    saved = model.save(MODEL)
    res = {"ok": saved, "trained": len(fit), "held_out": len(hold),
           "positives": positives, "negatives": negatives,
           "accuracy_fit": accuracy(fit), "accuracy_holdout": accuracy(hold),
           "model_seen": model.seen, "model_seen_before": before,
           "model": str(MODEL)}
    ledger.record("trained", **{k: v for k, v in res.items() if k != "ok"})
    return res


# -- outcome evaluation: did the agent's own changes work? -----------------

def outcomes(cfg=None) -> dict:
    """Score the adopted decoys by whether they ever fired.

    This is the half that makes it an agent rather than an accumulating rule
    list: a change that produced nothing gets proposed for removal.
    """
    from ..guards import decoy as decoy_mod
    from ..evolve import adopted

    hits = {}
    for h in _read_jsonl(paths.STATE_STATE / "decoy-hits.jsonl"):
        p = str(h.get("uri") or "").split("?")[0]
        if p:
            hits[p] = hits.get(p, 0) + 1

    now = time.time()
    per = []
    for e in adopted():
        p = str(e.get("path") or "")
        age_h = (now - float(e.get("adoptedAt") or now)) / 3600.0
        n = hits.get(p, 0)
        verdict = ("keep" if n >= KEEP_HITS
                   else ("too-new" if age_h < GRACE_HOURS else "retire"))
        per.append({"path": p, "id": e.get("id") or ("adopt:%s" % p),
                    "hits": n, "age_hours": round(age_h, 1), "verdict": verdict})

    effective = [x for x in per if x["verdict"] == "keep"]
    wasteful = [x for x in per if x["verdict"] == "retire"]
    total_hits = sum(x["hits"] for x in per)
    res = {"entries": len(per), "keep": len(effective), "retire": len(wasteful),
           "total_hits": total_hits, "per": per}
    try:
        OUTCOMES.write_text(json.dumps({"at": now, "summary":
                                        {k: v for k, v in res.items() if k != "per"}},
                                       ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass
    return res


def retire_proposals(cfg=None) -> list:
    """Adopted decoys that never fired, as rollback proposals."""
    out = []
    for x in outcomes(cfg)["per"]:
        if x["verdict"] != "retire":
            continue
        out.append({
            "id": x["id"], "tier": 1, "kind": "retire_decoy",
            "title": "撤下从未命中的诱饵「%s」" % x["path"],
            "path": x["path"],
            "evidence": {"hits": 0, "age_hours": x["age_hours"]},
            "why": "采纳 %.0f 小时以来一次都没被请求过，留着只会让配置变长"
                   % x["age_hours"],
        })
    return out


def format_outcomes(res: dict) -> str:
    lines = ["已采纳 %d 条；其中 %d 条命中过（累计 %d 次），%d 条从未命中"
             % (res["entries"], res["keep"], res["total_hits"], res["retire"])]
    for x in res["per"][:12]:
        mark = {"keep": "✔", "retire": "×", "too-new": "·"}[x["verdict"]]
        lines.append("  %s %-38s 命中 %-4d 已存在 %.0f 小时"
                     % (mark, x["path"], x["hits"], x["age_hours"]))
    return "\n".join(lines)


def train_bulk(cfg=None, epochs: int = 12, include_host: bool = True) -> dict:
    """Train on the built-in corpus, plus whatever this host has produced.

    The held-out families are excluded from the fit *and* kept aside, so the
    headline number is generalisation rather than memory. That is the whole
    reason the corpus is organised by family instead of by path.
    """
    rows = corpus_mod.build(skip_families=corpus_mod.HELD_OUT)
    host = label_samples(cfg) if include_host else []
    for h in host:
        rows.append((h["path"], h["status"], h["ua"], h["label"]))

    seen, data = set(), []
    for r in rows:
        if r in seen:
            continue
        seen.add(r)
        data.append(r)
    pos = sum(1 for r in data if r[3] == 1)
    if pos < 10 or len(data) - pos < 5:
        return {"ok": False, "err": "语料不足", "trained": 0}

    model = score_mod.Scorer.load(MODEL)
    for _ in range(max(1, epochs)):
        for path, status, ua, label in data:
            model.observe(path, status, ua, label=label)
    saved = model.save(MODEL)

    novel = corpus_mod.novel_attack_test(model)
    in_corpus = sum(1 for path, st, ua, lab in data
                    if (model.score(path, st, ua) >= 0.5) == bool(lab))
    res = {"ok": saved, "corpus": len(data), "positives": pos,
           "negatives": len(data) - pos, "host_samples": len(host),
           "corpus_accuracy": round(100.0 * in_corpus / max(1, len(data)), 1),
           "novel": novel, "model_seen": model.seen, "model": str(MODEL)}
    ledger.record("trained-bulk", corpus=len(data), positives=pos,
                  host_samples=len(host), novel_rate=novel["rate"],
                  corpus_accuracy=res["corpus_accuracy"])
    return res
