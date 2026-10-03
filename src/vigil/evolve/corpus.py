"""A large training corpus, and the held-out families used to test it.

Where the volume comes from
---------------------------
A host that has been up for a week produces a few hundred labelled requests --
enough to fit a line, not enough to trust one. So the corpus is built from the
knowledge the project already carries and has already reviewed: the curated
decoy table, the attack signatures, and the naming conventions that real
scanners actually use. Combined with the host's own self-supervised samples,
that is thousands of examples instead of dozens, with no labelling cost.

What the held-out families are for
----------------------------------
An accuracy number on data the model trained on proves nothing. `HELD_OUT` names
path *families* -- whole naming conventions -- that `build()` can exclude, so the
only honest question can be asked: shown an attack of a kind it has never seen,
does it still recognise it? The families excluded from training are exactly the
ones `novel_attack_test()` then scores.
"""
from __future__ import annotations

import itertools

#: Path words that appear in scanner dictionaries, grouped by family. The
#: families matter more than the words: they are what gets held out whole.
FAMILIES = {
    "vcs": ["/.git/config", "/.git/HEAD", "/.svn/entries", "/.hg/hgrc",
            "/.gitignore", "/.git-credentials"],
    "env": ["/.env", "/.env.local", "/.env.production", "/.env.bak",
            "/env.js", "/config/.env"],
    "backup": ["/backup.zip", "/backup.tar.gz", "/db.sql", "/database.sql",
               "/site.bak", "/www.zip", "/backup/2024.sql", "/old/index.php.bak"],
    "cloud": ["/.aws/credentials", "/.aws/config", "/.kube/config",
              "/.docker/config.json", "/.npmrc", "/.pypirc"],
    "cms": ["/wp-login.php", "/wp-config.php.bak", "/xmlrpc.php",
            "/wp-admin/install.php", "/administrator/", "/typo3/",
            "/drupal/CHANGELOG.txt"],
    "db": ["/phpmyadmin/index.php", "/adminer.php", "/pma/", "/db.php",
           "/mysql/admin/", "/sqlite.db"],
    "infra": ["/actuator/env", "/actuator/health", "/metrics", "/debug/vars",
              "/.well-known/security.txt", "/server-status", "/nginx_status"],
    "ai": ["/mcp", "/api/mcp", "/sse", "/v1/models", "/api/chat",
           "/.well-known/ai-plugin.json", "/api/auth/validate-sso"],
    "home": ["/.bash_history", "/.ssh/id_rsa", "/.config/pulse/",
             "/.cache/motd.legal-displayed", "/.wget-hsts", "/.local/share/"],
    "traversal": ["/../../etc/passwd", "/..%2f..%2fetc%2fshadow",
                  "/static../.git/config", "/index.php?lang=../../etc/passwd"],
    "shell": ["/shell.php", "/cmd.php", "/upload.php", "/1.php",
              "/c99.php", "/webshell.php", "/.well-known/x.php"],
    "api": ["/graphql", "/api/v1/users", "/api/admin/users", "/swagger.json",
            "/openapi.json", "/api/remote.mux"],
}

#: The families withheld when training the model that is then asked to catch
#: them. Chosen because they are naming conventions, not single paths: if the
#: model can only memorise, holding them out makes that visible immediately.
HELD_OUT = ("ai", "infra", "shell")

#: Ordinary paths a real site serves. The negative class has to be varied too,
#: or the model just learns "has a file extension = fine".
NEGATIVE_SHAPES = [
    "/", "/index.html", "/about", "/contact/", "/task/", "/tools/",
    "/static/css/main.css", "/static/js/app.js", "/assets/logo.png",
    "/images/hero.webp", "/fonts/inter.woff2", "/api/user/profile",
    "/api/task/today", "/l/01/", "/thanks/", "/cipre/", "/taez/tools/qr/",
    "/favicon.ico", "/robots.txt", "/sitemap.xml", "/manifest.webmanifest",
]

#: File extensions scanners reach for, and the query shapes they append.
PROBE_EXT = ("", ".php", ".bak", ".old", ".save", ".zip", ".tar.gz", ".sql",
             ".json", ".yml", ".ini", ".log", ".txt")
PROBE_QUERY = ("", "?debug=1", "?id=1", "?file=../../etc/passwd",
               "?cmd=id", "?url=http://169.254.169.254/")

UAS = ("", "-", "curl/7.81.0", "python-requests/2.31", "Go-http-client/1.1",
       "masscan/1.3", "nmap scripting engine", "Mozilla/5.0", "zgrab/0.x")


def build(skip_families=(), with_negatives=True) -> list:
    """Samples as (path, status, ua, label). `skip_families` withholds whole
    naming conventions, which is how a genuine held-out test is constructed."""
    rows = []
    for fam, paths in FAMILIES.items():
        if fam in skip_families:
            continue
        for path in paths:
            rows.append((path, 404, "", 1))
            # The same probe spelled a few other ways: a scanner that tries
            # `/x` also tries `/x.php`, `/x.bak` and `/x?debug=1`.
            if "." not in path.rsplit("/", 1)[-1]:
                for ext in (".php", ".bak", ".zip"):
                    rows.append((path + ext, 404, "", 1))
            for q in ("?debug=1", "?id=1"):
                rows.append((path + q, 404, "", 1))
    for path, _st, _ua, _lab in list(rows):
        for ua in ("curl/7.81.0", "python-requests/2.31", "Go-http-client/1.1"):
            rows.append((path, 404, ua, 1))
    if with_negatives:
        for shape in NEGATIVE_SHAPES:
            rows.append((shape, 200, "Mozilla/5.0", 0))
            rows.append((shape + "?v=2", 200, "Mozilla/5.0", 0))
            rows.append((shape, 301, "Mozilla/5.0", 0))
        for shape, q in itertools.product(NEGATIVE_SHAPES[:10], ("?page=2", "?lang=zh")):
            rows.append((shape + q, 200, "Mozilla/5.0", 0))
    # De-duplicate; the same (path, status, ua) twice teaches nothing twice.
    seen, out = set(), []
    for r in rows:
        key = (r[0], r[1], r[2], r[3])
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def novel_attack_test(model, families=HELD_OUT, threshold: float = 0.7) -> dict:
    """Show the model attacks of a kind it has never seen, and score it honestly.

    Two traps this has to avoid, both of which produced a confident 100% the
    first time it was written:

    * **The threshold must be a call, not a coin flip.** An untrained model
      returns exactly 0.5 for everything; counting `>= 0.5` as "caught" makes a
      blank model score 100%. A confident call is required instead.
    * **Only attacks are not enough.** If the model answers "attack" to
      everything, it also catches every novel attack -- and is useless. So a
      benign control set is scored alongside, and the reported number is the
      *separation* between the two populations.
    """
    benign = [sh for sh in NEGATIVE_SHAPES]

    def _mean(paths, status):
        vals = [model.score(p, status, "") for p in paths]
        return round(sum(vals) / max(1, len(vals)), 4), vals

    per = {}
    for fam in families:
        paths = FAMILIES.get(fam) or []
        vals = [model.score(p, 404, "") for p in paths]
        caught = [p for p, v in zip(paths, vals) if v >= threshold]
        per[fam] = {"paths": len(paths), "caught": len(caught),
                    "mean": round(sum(vals) / max(1, len(vals)), 3),
                    "missed": [p for p, v in zip(paths, vals) if v < threshold][:4]}

    total = sum(v["paths"] for v in per.values())
    hit = sum(v["caught"] for v in per.values())
    probe_mean, _ = _mean([p for fam in families for p in (FAMILIES.get(fam) or [])], 404)
    benign_mean, benign_vals = _mean(benign, 200)
    false_alarm = [p for p, v in zip(benign, benign_vals) if v >= threshold]
    return {"families": per, "total": total, "caught": hit,
            "rate": round(100.0 * hit / max(1, total), 1),
            "threshold": threshold,
            "probe_mean": probe_mean, "benign_mean": benign_mean,
            "separation": round(probe_mean - benign_mean, 4),
            "false_alarms": false_alarm,
            "usable": bool(probe_mean >= threshold and probe_mean - benign_mean >= 0.3)}


def format_novel(res: dict) -> str:
    lines = ["从未见过的新族类攻击：%d/%d 被识别（置信阈值 %.2f）"
             % (res["caught"], res["total"], res.get("threshold", 0.7)),
             "  区分度：攻击均分 %.3f － 正常均分 %.3f = **%.3f**%s"
             % (res["probe_mean"], res["benign_mean"], res["separation"],
                "" if res["usable"] else "   ← 不足，模型不可用"),
             "  误报（正常路径被判为攻击）：%d 条%s"
             % (len(res["false_alarms"]),
                ("　" + "、".join(res["false_alarms"][:4])) if res["false_alarms"] else "")]
    for fam, v in res["families"].items():
        lines.append("  %-9s %2d/%2d 命中   平均分 %.2f%s"
                     % (fam, v["caught"], v["paths"], v["mean"],
                        ("   漏掉：" + "、".join(v["missed"])) if v["missed"] else ""))
    return "\n".join(lines)
