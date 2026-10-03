"""Online scorer: hashed features with an online logistic model.

Why not a neural network
------------------------
The signal being learned here is "does this request look like a probe", from a
path, a status code and a user agent. That is a sparse bag-of-tokens problem,
and on this host it is very nearly linearly separable -- scanners reuse the
same few hundred path shapes. A convolutional network would cost orders of
magnitude more CPU for the same decision, and -- the part that actually rules
it out -- its answer could not be read back as a sentence a human can check
before the change is adopted. A security component that cannot explain itself
is not one you want editing its own behaviour.

So: hashed feature vector, logistic output, one SGD step per observation. The
whole model is a few hundred floats in a JSON file, scoring takes microseconds,
and `explain()` names the features that moved the decision.

This is genuinely *learning* -- the weights change with traffic and the score
for a path shape improves as evidence accumulates -- it is just learning of the
kind that stays auditable.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path

DIM = 512                 # hashed feature space; small enough to keep in RAM always
LR = 0.05                 # SGD step
L2 = 1e-4
MODEL_VERSION = 1

_ASSET = re.compile(r"\.(png|jpe?g|gif|webp|svg|ico|css|js|mjs|map|woff2?|ttf|"
                    r"eot|mp4|webm|mp3|wav)$", re.I)
_EXT = re.compile(r"(\.[a-z0-9]{1,8})$", re.I)
_PROBE_DIR = ("/.git", "/.svn", "/.env", "/.aws", "/.ssh", "/wp-", "/admin",
              "/backup", "/config", "/database", "/phpmyadmin", "/xmlrpc",
              "/.config", "/.cache", "/mcp", "/sse", "/actuator", "/.well-known")


def featurize(path: str, status: int = 404, ua: str = "") -> list:
    """Names of the features this request lights up.

    Human-readable on purpose: the same strings are what `explain()` prints, so
    a reviewer reads "feat:prefix=/.git" rather than "index 217".
    """
    feats = []
    p = str(path or "").split("?")[0][:300]
    low = p.lower()
    segs = [s for s in low.split("/") if s]
    feats.append("bias")
    if len(segs) > 0:
        feats.append("depth=%d" % min(len(segs), 6))
    if segs:
        first = "/" + segs[0]
        feats.append("seg0=%s" % first[:24])
        feats.append("prefix=%s" % first[:12])
    if p.count(".") and len(segs) > 1:
        feats.append("dotfile=%s" % ("yes" if segs[-1].startswith(".") else "no"))
    m = _EXT.search(low)
    if m:
        feats.append("ext=%s" % m.group(1))
    for d in _PROBE_DIR:
        if d in low:
            feats.append("probedir=%s" % d)
    if ".." in low or "%2e" in low:
        feats.append("traversal=yes")
    if _ASSET.search(low):
        feats.append("looks_like_asset=yes")
    feats.append("status=%d" % int(status or 0))
    u = str(ua or "").lower()
    if not u or u == "-":
        feats.append("ua=empty")
    else:
        for tok in ("curl", "python", "go-http", "nmap", "nikto", "nuclei",
                    "masscan", "zgrab", "gobuster", "wpscan", "sqlmap",
                    "mozilla", "googlebot", "bingbot"):
            if tok in u:
                feats.append("ua=%s" % tok)
    return feats


def _bucket(name: str) -> int:
    return int(hashlib.blake2b(name.encode("utf-8"), digest_size=4).hexdigest(), 16) % DIM


def sigmoid(z: float) -> float:
    if z < -60:
        return 0.0
    if z > 60:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))


class Scorer:
    """The model itself: weights, one online update, an explanation."""

    def __init__(self, weights=None):
        self.w = list(weights) if weights else [0.0] * DIM
        self.seen = 0
        self.updated = 0

    # -- inference --------------------------------------------------------

    def _z(self, feats) -> float:
        return sum(self.w[_bucket(f)] for f in feats)

    def score(self, path: str, status: int = 404, ua: str = "") -> float:
        return round(sigmoid(self._z(featurize(path, status, ua))), 4)

    def explain(self, path: str, status: int = 404, ua: str = "", top: int = 6) -> list:
        feats = featurize(path, status, ua)
        ranked = sorted(((self.w[_bucket(f)], f) for f in feats),
                        key=lambda x: -abs(x[0]))
        return [{"feature": f, "weight": round(v, 4)} for v, f in ranked[:top]]

    # -- learning ---------------------------------------------------------

    def observe(self, path: str, status: int = 404, ua: str = "",
                label: int = 0) -> float:
        """One SGD step. `label` 1 = this really was a probe, 0 = it was not."""
        feats = featurize(path, status, ua)
        p = sigmoid(self._z(feats))
        err = (1.0 if label else 0.0) - p
        for f in feats:
            i = _bucket(f)
            self.w[i] += LR * (err - L2 * self.w[i])
        self.seen += 1
        if err:
            self.updated += 1
        return round(p, 4)

    # -- persistence ------------------------------------------------------

    def to_dict(self) -> dict:
        return {"version": MODEL_VERSION, "dim": DIM, "lr": LR,
                "seen": self.seen, "updated": self.updated,
                "weights": [round(x, 6) for x in self.w]}

    @classmethod
    def from_dict(cls, data) -> "Scorer":
        if not isinstance(data, dict) or int(data.get("dim", 0)) != DIM:
            return cls()
        s = cls(data.get("weights") or None)
        s.seen = int(data.get("seen", 0))
        s.updated = int(data.get("updated", 0))
        return s

    @classmethod
    def load(cls, path) -> "Scorer":
        try:
            return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
        except (OSError, ValueError):
            return cls()

    def save(self, path) -> bool:
        p = Path(path)
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(p.suffix + ".tmp")
            tmp.write_text(json.dumps(self.to_dict(), ensure_ascii=False),
                           encoding="utf-8")
            tmp.replace(p)
            return True
        except OSError:
            return False
