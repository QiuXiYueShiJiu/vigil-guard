"""Self-protection: is the guard still the guard? (group ``security``)

Every other check in this program asks "has something on this host been
tampered with?". This module asks the one question none of them can answer
from the outside: **has this program itself been tampered with, and is it
still running at all?**

That gap was real and it was embarrassing. The watched-file list covered
``/etc/shadow``, ``/etc/sudoers`` and the panel's admin path -- but not
``/usr/local/lib/vigil``, not the nginx snippets this program writes, and
not the audit rules it installs. And ``checks.services`` listed nginx,
sshd, mysql, postfix, fail2ban, maldet... but neither of vigil's own
daemons. If ``vigil-threatd`` died, or somebody edited the code that decides
what to ban, this program would have reported "全部正常" while doing it.

Two checks:

``self_integrity``
    Hashes the installed package and everything this program generates, and
    compares against a baseline kept *outside* the package
    (``/var/lib/vigil/state/health.json``). Root can of course edit both --
    root can do anything -- but the baseline living outside the thing it
    describes is what makes a casual edit show up as a finding instead of
    as silence.

``vigil_watchdog``
    Are the daemons and timers alive, and is the inspection still running on
    schedule? A monitoring program that has quietly stopped monitoring is
    worse than none, because its silence reads as safety.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import os
import re
import time

from .base import (CRIT, G_SECURITY, OK, WARN, Check, CheckContext,
                   CheckResult, register)
from ...core import detect, paths

#: Package files are small; this is a sanity bound, not a limit we expect to
#: reach. It stops a pathologically large tree from turning a five-minute
#: inspection into a five-minute disk read.
_FILE_CAP = 4000

#: Format version for the stored baseline. Bump when the shape changes.
#: v2 adds the attribution pass (see :func:`attribute`): the baseline itself
#: is unchanged, but the *meaning* of a difference is, and a v1 state file has
#: no ledger fingerprint to work from.
_BASELINE_V = 2

#: Ledger kinds that mean "this program changed one of its own files on
#: purpose", and the field carrying the hash of the file afterwards.
_EDIT_KINDS = ("code-edited", "applied")

#: Peer hashes that are not hashes and must never be compared as one.
_NOT_A_HASH = ("", "missing", "too-big", "unreadable", "not-recorded")


def _is_hash(value) -> bool:
    text = str(value or "")
    if text in _NOT_A_HASH or text.startswith(("too-big:", "unreadable:")):
        return False
    return len(text) == 64


def attribute(paths_changed, cur, package_root, cfg, now=None,
              ledger_entries=None, ledger_verdict=None) -> dict:
    """Decide *why* each changed file changed, by hash, before crying wolf.

    The failure this fixes is real and it ran in both directions. ``evolve``
    is allowed to edit one source file on purpose (``decoy.py``, the decoy
    table); every such edit made ``self_integrity`` report CRIT, so the
    finding that matters -- "somebody rewrote the code that decides what to
    ban" -- was buried in a stream of legitimate self-modification. And the
    opposite mistake is worse: accepting any change because "we changed
    something recently" hands an attacker the perfect cover.

    So the judge is a **hash**, never a timestamp and never "there is a
    record in the ledger":

      * a ledger record whose recorded post-edit hash equals the file's hash
        *now* -> ``self`` (self-modification, recorded);
      * a ledger record for this file whose hash does **not** match -> a
        mismatch, reported as suspected tampering with both hashes. This is
        the case that matters most: the file was recorded once and is not the
        file that was recorded;
      * no record, but the change happened while ``vigil update`` was
        deploying -> ``deploy``;
      * anything else -> ``unattributed``, reported as CRIT.

    Two further guards, both about not being fooled by the ledger itself:

    * the ledger must pass its own integrity check (:func:`vigil.evolve.
      ledger.verify`). A broken chain means the file was edited, so *nothing*
      in it is trusted and the break is named in the report;
    * records must be recent (``attribution_window_seconds``). A
      self-modification from three months ago cannot excuse today's edit --
      otherwise every later change hides in its shadow forever.
    """
    now = time.time() if now is None else float(now)
    window = _int_cfg(cfg, "checks.self_integrity.attribution_window_seconds",
                      86400, minimum=1)

    entries, verdict = _ledger(ledger_entries, ledger_verdict, cfg)
    out = {"self": [], "deploy": [], "mismatch": [], "unattributed": [],
           "ledger_ok": bool(verdict.get("ok", True)), "ledger": verdict,
           "window": window}
    if not verdict.get("ok", True):
        # Fail closed, and say where. Every file becomes suspicious; the
        # report explains that the reason is the ledger, not the files.
        for path in sorted(paths_changed):
            out["unattributed"].append({
                "path": path, "why": "台账链校验失败（%s），台账不可信"
                                     % verdict.get("break_reason", "原因未知")})
        return out

    recent = []
    for entry in entries or ():
        try:
            ts = float(entry.get("ts") or 0)
        except (TypeError, ValueError):
            continue
        if now - ts <= window:
            recent.append(entry)

    deploy = _deploy_window(cfg, now)
    for path in sorted(paths_changed):
        digest = cur.get(path)
        match, mismatched = _match_by_hash(path, digest, recent,
                                           package_root, cur)
        if match:
            out["self"].append({"path": path, "entry": match})
            continue
        if mismatched:
            out["mismatch"].append({"path": path, "entry": mismatched,
                                    "expected": mismatched.get("after", ""),
                                    "actual": digest})
            continue
        if deploy and _in_package(path, package_root):
            stamp = _mtime(path)
            if stamp and deploy[0] - deploy[1] <= stamp <= deploy[0] + 60:
                out["deploy"].append({"path": path,
                                      "version": deploy[2] or "?",
                                      "at": deploy[0]})
                continue
        out["unattributed"].append({
            "path": path,
            "why": _why_not(recent, path, package_root, deploy, now, window)})
    return out


def _int_cfg(cfg, key: str, default: int, minimum: int = 0) -> int:
    try:
        value = int(cfg.get(key, default))
    except (TypeError, ValueError, AttributeError):
        value = default
    return max(minimum, value)


def _ledger(entries, verdict, cfg):
    """``(entries, verdict)``, read from disk unless the caller supplied it."""
    if entries is not None and verdict is not None:
        return entries, verdict
    try:
        from ...evolve import ledger
        # `cfg` is passed through because the chain's HMAC key lives in
        # secrets.json, and this call may run before the config was loaded
        # for any other purpose.
        got = ledger.verify(limit=ledger.MAX_LINES, cfg=cfg)
        return got.get("entries") or [], got
    except Exception as exc:                                # noqa: BLE001
        return [], {"ok": False, "break_reason":
                    "无法读取台账：%s: %s" % (type(exc).__name__, exc)}


def _match_by_hash(path, digest, entries, package_root, cur):
    """Find the ledger record that produced *this exact content*.

    Returns ``(matching_entry, mismatching_entry)``. The path test comes
    first because a hash match on a *different* file is coincidence, not
    attribution -- and the attacker controls neither the hash of the file
    they want excused nor our ability to compare paths.

    The path is compared three ways: absolute (what ``applied`` records),
    relative to the source root (what a source checkout produces), and by
    basename *only when it is unique among the changed files* -- a basename
    alone must never let one file claim another's record.
    """
    if not _is_hash(digest):
        return None, None
    names = [os.path.basename(str(p)) for p in (cur or {})]
    basename_unique = names.count(os.path.basename(str(path))) == 1
    source_root = ""
    try:
        source_root = str(package_root or "")
    except Exception:                                       # noqa: BLE001
        source_root = ""
    mismatch = None
    for entry in reversed(entries or ()):
        if entry.get("kind") not in _EDIT_KINDS:
            continue
        recorded = str(entry.get("after") or "")
        if recorded in _NOT_A_HASH:
            continue
        target = str(entry.get("file") or entry.get("path") or "")
        if not _same_file(path, target, source_root, basename_unique):
            continue
        if recorded == str(digest):
            return entry, None
        if mismatch is None:
            mismatch = entry
    return None, mismatch


def _same_file(path, recorded, source_root, basename_unique: bool) -> bool:
    if not recorded:
        return False
    real, rec = os.path.abspath(str(path)), os.path.abspath(str(recorded))
    if real == rec:
        return True
    if source_root:
        if rec == os.path.abspath(os.path.join(source_root, str(recorded))):
            return True
        rel = os.path.relpath(real, os.path.abspath(source_root))
        if not rel.startswith("..") and rel == str(recorded):
            return True
    if basename_unique and os.path.basename(real) == os.path.basename(rec):
        # Only reachable when the changed set contains exactly one file with
        # this name, so it cannot be used to make one file vouch for another.
        return True
    return False


def _in_package(path, package_root) -> bool:
    if not package_root:
        return False
    real = os.path.abspath(str(path))
    root = os.path.abspath(str(package_root))
    return real == root or real.startswith(root.rstrip("/") + "/")


def _deploy_window(cfg, now):
    """``(timestamp, window, version)`` of the last deploy, or ``None``.

    Read from ``deploy.json``, which ``vigil update`` already writes for
    ``vigil rollback``. It is a second, independent source: an update changes
    the installed package and nothing in the evolve ledger, so without this
    an upgrade would look exactly like an intrusion.
    """
    try:
        from ...core.state import read_json
        rec = read_json(paths.STATE_STATE / "deploy.json", {}) or {}
    except Exception:                                       # noqa: BLE001
        return None
    try:
        at = float(rec.get("current_at") or 0)
    except (TypeError, ValueError):
        return None
    if at <= 0:
        return None
    window = _int_cfg(cfg, "checks.self_integrity.deploy_window_seconds",
                      900, minimum=30)
    return at, window, str(rec.get("current") or "")


def _mtime(path) -> float:
    try:
        return os.path.getmtime(str(path))
    except OSError:
        return 0.0


def _why_not(entries, path, package_root, deploy, now, window) -> str:
    """One honest sentence for the report, saying what was looked at."""
    bits = []
    if _in_package(path, package_root):
        bits.append("它在本程序源码树内（源码永不自动还原，静默回滚会掩盖入侵）")
    else:
        bits.append("它是本程序之外的文件" if not _in_package(path, package_root)
                    else "")
    if deploy:
        age = now - deploy[0]
        bits.append("最近一次部署在 %.0f 秒前、窗口 %d 秒" % (age, deploy[1]))
    else:
        bits.append("没有可用的部署记录")
    bits.append("台账里 %d 条记录都在 %d 秒窗口内，没有一条的「改动后哈希」"
                "等于该文件当前的哈希" % (len(entries or ()), window))
    return "；".join(b for b in bits if b)


def _attribution_report(attr: dict) -> str:
    """The "why we did / did not call this malicious" block, or ``""``.

    Reported even when the verdict is "self-modification": the operator must
    be able to see *which* ledger entry was accepted and *why*, otherwise the
    attribution is a black box that could be excusing anything.
    """
    if not attr:
        return ""
    lines = []
    if not attr.get("ledger_ok", True):
        verdict = attr.get("ledger") or {}
        lines.append("⚠️ 台账链校验**失败**：%s\n"
                     "          因此不以台账为任何改动背书，全部按疑似恶意处理。"
                     % verdict.get("break_reason", "原因未知"))
    for entry in attr.get("self", [])[:6]:
        rec = entry.get("entry") or {}
        lines.append("✅ 自修正（已记录）: %s\n"
                     "          台账条目 kind=%s ts=%s id=%s，"
                     "记录的改动后哈希与当前文件一致"
                     % (entry["path"], rec.get("kind"), rec.get("ts"),
                        rec.get("id") or "-"))
    for entry in attr.get("deploy", [])[:6]:
        lines.append("✅ 部署（vigil update %s）: %s"
                     % (entry.get("version") or "?", entry["path"]))
    for entry in attr.get("mismatch", [])[:6]:
        lines.append("❌ 台账里有该文件的记录，但**哈希不匹配** —— 疑似恶意更改: %s\n"
                     "          台账期望 %s… / 实际 %s…（台账 id=%s）"
                     % (entry["path"], str(entry.get("expected"))[:12],
                        str(entry.get("actual"))[:12],
                        (entry.get("entry") or {}).get("id") or "-"))
    for entry in attr.get("unattributed", [])[:6]:
        lines.append("❌ 无归因: %s\n          %s"
                     % (entry["path"], entry.get("why", "")))
    if not lines:
        return ""
    return "\n       ".join(lines)


def digest_file(path: str, cap: int = 8 * 1024 * 1024) -> str:
    """sha256 of a file, or a marker for "missing"/"unreadable"."""
    try:
        if not os.path.isfile(path):
            return "missing"
        size = os.path.getsize(path)
        if size > cap:
            return "too-big:%d" % size
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(131072), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError as e:
        return "unreadable:%s" % e.errno


def _package_root() -> str:
    """The *installed* copy of this program, not the copy now running.

    Those are different whenever `vigil update` is run from a source
    checkout: the command runs from the source tree while the
    daemons execute ``/usr/local/lib/vigil/vigil``. Keying the baseline by
    the running copy made an upgrade record the source tree, and the very
    next inspection -- running from the installed tree -- reported 82 files
    deleted and 82 added. The installed tree is the one that decides what
    this program does, so it is the one worth verifying.
    """
    installed = paths.LIB / "vigil"
    if (installed / "version.py").is_file():
        return str(installed)
    import vigil
    return os.path.dirname(os.path.abspath(vigil.__file__))


def _walk(root: str, out: dict, cap: int) -> None:
    if not os.path.isdir(root):
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for name in sorted(filenames):
            if name.endswith((".pyc", ".pyo")):
                continue
            full = os.path.join(dirpath, name)
            out[full] = digest_file(full)
            if len(out) >= cap:
                return


@register
class SelfIntegrity(Check):
    id = "self_integrity"
    label = "程序自身完整性"
    label_en = "Program self-integrity"
    group = G_SECURITY
    stateful = True
    heavy = True
    description = ("校验已安装的 vigil 代码与本程序生成的配置文件是否被改动"
                   "（基线保存在程序目录之外）")

    def run(self, ctx: CheckContext) -> CheckResult:
        targets = self._targets(ctx)
        cur = {p: digest_file(p) for p in targets}

        # Deliberately NOT `ctx.versioned(...)`, which advances the baseline
        # every run. That behaviour is right for drift ("nginx.conf changed"
        # -- you did it, fine, stop nagging) and exactly wrong here: an
        # edited security program would be reported once and then silently
        # accepted for the rest of the machine's life. The baseline only
        # moves when somebody says so -- `vigil health rebaseline
        # self_integrity`, or `vigil update`, which is the one legitimate
        # reason for these files to change on their own.
        prev = ctx.state.get("self_integrity")
        if ctx.state.get("self_integrity_v") != _BASELINE_V or not prev:
            ctx.state["self_integrity_v"] = _BASELINE_V
            ctx.state["self_integrity"] = cur
            return CheckResult(OK, "已建立自身完整性基线（%d 个文件）"
                                   % len(cur))

        added, changed, removed = [], [], []
        # Union, not just `cur`: a file that disappeared is *absent* from
        # `cur` and would otherwise be invisible. Deleting the code that
        # decides what to ban is at least as interesting as editing it.
        for path in sorted(set(cur) | set(prev)):
            old = prev.get(path)
            new = cur.get(path)
            if old is None:
                added.append(path)
            elif new is None or new == "missing":
                removed.append(path)
            elif old != new:
                changed.append(path)

        if not (added or changed or removed):
            return CheckResult(OK, "程序自身与生成物均未改动（共校验 %d 个文件）"
                                   % len(cur))

        # -- respond, before reporting ------------------------------------
        # Detection without a response is how a deleted shield snippet got
        # reported 55 times and rebuilt zero times. So the recoverable class
        # is repaired here, and every repair is reported below whether it
        # worked or not. See `guards/selfheal.py` for the boundary: only
        # files this program generated, never its own source, never the
        # operator's files.
        heal_result = {}
        if removed or changed:
            try:
                from .. import selfheal
                heal_result = selfheal.heal(
                    ctx.cfg, removed=removed, changed=changed, baseline=prev,
                    healstate=ctx.state.setdefault(
                        selfheal.HEAL_STATE_KEY, {}))
            except Exception as exc:                        # noqa: BLE001
                heal_result = {"enabled": True, "attempted": 0, "healed": [],
                               "unhealed": [], "limited": [],
                               "unsupported": [], "changed_baseline": {},
                               "err": "%s: %s" % (type(exc).__name__, exc)}
        healed = heal_result.get("changed_baseline") or {}
        if healed:
            # The stored baseline moves for exactly the files a rebuild
            # *proved* it restored. Not for the others: a file that is still
            # wrong must keep failing until a human looks at it, and a file
            # we merely wrote must not be blessed by implication.
            fresh = dict(prev)
            fresh.update(healed)
            ctx.state["self_integrity"] = fresh
            prev = fresh

        report = ""
        try:
            from .. import selfheal as _sh
            report = _sh.describe(heal_result)
        except Exception:                                   # noqa: BLE001
            report = ""
        if heal_result.get("err"):
            # A response that could not even be attempted is still something
            # the operator has to be told about -- "the auto-recovery itself
            # is broken" is a finding, not a silence.
            report = ("自动重建未能执行：%s" % heal_result["err"]) + (
                "\n       " + report if report else "")

        # Recompute the finding *after* the response. A file that came back
        # is no longer a finding; one that did not is still one.
        changed = [p for p in changed if p not in healed]
        removed = [p for p in removed if p not in healed]
        unresolved = bool(added or changed or removed)

        # -- attribute, before calling anything malicious ------------------
        # `evolve` is *allowed* to edit one source file on purpose; treating
        # that as an intrusion buried the real finding, and treating every
        # change as self-modification would hide the real one. The judge is
        # the hash in the ledger, and only the hash -- see `attribute`.
        attribution = {"self": [], "deploy": [], "mismatch": [],
                       "unattributed": [], "ledger_ok": True, "ledger": {}}
        if changed:
            try:
                attribution = attribute(changed, cur, _package_root(), ctx.cfg)
            except Exception as exc:                        # noqa: BLE001
                # An attribution pass that crashes must not become "no
                # attribution needed". Fail closed and say so.
                attribution = {
                    "self": [], "deploy": [], "mismatch": [],
                    "unattributed": [{"path": p,
                                      "why": "归因过程异常：%s: %s"
                                             % (type(exc).__name__, exc)}
                                     for p in changed],
                    "ledger_ok": False, "ledger": {}}
        self_ok = {e["path"] for e in attribution.get("self", [])}
        deploy_ok = {e["path"] for e in attribution.get("deploy", [])}
        mismatched = {e["path"] for e in attribution.get("mismatch", [])}
        attributed = self_ok | deploy_ok
        malicious = [p for p in changed if p not in attributed]

        attr_report = _attribution_report(attribution)

        blocks = []
        for label, items in (("被修改", malicious), ("被删除", removed),
                             ("新增", added)):
            for path in items[:4]:
                blocks.append("%s: %s" % (label, path))
        extra = (len(malicious) + len(removed) + len(added)) - len(blocks)
        if extra > 0:
            blocks.append("…… 另有 %d 个文件未展开" % extra)

        sections = [s for s in (attr_report, report) if s]
        notes = ("\n       " + "\n       ".join(sections)) if sections else ""

        if not unresolved:
            # Everything that changed was something this program generates,
            # and it has been put back. That is still news -- the operator is
            # told exactly which file was rebuilt and why -- but it is not a
            # compromise of the program.
            return CheckResult(
                OK,
                "程序自身的生成物曾被改动，已自动重建并复核通过：%s"
                % (notes or "（无详情）"))

        if not malicious and not removed and not added:
            # Every remaining difference is either a recorded self-edit or a
            # deploy. This is the case that used to produce a false CRIT on
            # every single `evolve` run.
            return CheckResult(
                OK,
                "程序自身有 %d 处变化，全部已归因，不作为篡改：%s"
                % (len(attributed), notes))

        if not blocks:
            blocks.append("（没有可展开的未解决项）")
        # Severity ladder for what is left. A file this program generates but
        # deliberately will not rewrite on its own (see `guards/selfheal.py`)
        # needs a human but is not evidence of an intrusion; a deleted
        # *source* file, or a brute-force rewrite of a watched artifact, is.
        severity = CRIT
        leftovers = list(removed) + list(added)
        if not malicious and leftovers and all(
                _unrepairable_artifact(p) for p in leftovers):
            severity = WARN
            if heal_result.get("limited"):
                # Repeated deletion/modification of the same artifact is not
                # drift -- it is the signature of something actively fighting
                # the repair. Escalated rather than filed as a warning.
                severity = CRIT
        return CheckResult(
            severity,
            "%s程序自身或它生成的配置发生了变化：**%d 个**（改动 %d / 删除 %d / "
            "新增 %d）\n       %s\n%s"
            "       不在自动重建范围内的文件（重建会覆盖手改内容或运行时数据）"
            "只报告；源码与生成物被改动一律按疑似篡改处理。\n"
            "       确认无误后重建基线：`vigil health rebaseline self_integrity`"
            % ("**疑似恶意更改**：" if severity == CRIT else "",
               len(malicious) + len(removed) + len(added), len(malicious),
               len(removed), len(added), "\n       ".join(blocks), notes))


    def _targets(self, ctx: CheckContext) -> list:
        out = {}

        # 1. The installed program. Discovered by walking, not by a list, so
        #    a new module is protected the day it is deployed.
        _walk(_package_root(), out, _FILE_CAP)

        # 2. What this program generates elsewhere on the host. Discovered at
        #    run time rather than read from an install-time list: a config
        #    entry goes stale the moment a gate is added, and a stale
        #    integrity list is worse than none because it looks like coverage.
        try:
            from ...gates import generated_artifacts
            out.update({p: None for p in generated_artifacts()})
        except (ImportError, OSError):
            pass

        # 3. Whatever the operator added by hand.
        for path in ctx.copt("self_integrity", "paths", []) or []:
            path = str(path)
            if os.path.isdir(path):
                _walk(path, out, _FILE_CAP)
            else:
                out[path] = None
        return sorted(out)


@register
class RuntimeConfig(Check):
    """Is the configuration that is *on disk* the one that is *running*?

    This check exists because the same failure happened three separate times
    in one day, in three different components, and every time it looked like
    success:

      * `nginx -s reload` exits 0 when the master accepts the signal and then
        rejects the configuration. Changing a `limit_req_zone` key is fatal
        at reload, so every later edit to that file was inert, `nginx -t`
        still said "successful", and the only trace was one line in an error
        log. Three rounds of testing measured 429s the changed zone was
        supposed to have removed.
      * `OOMScoreAdjust` written into `[Unit]` instead of `[Service]` -- a
        valid file, a valid unit, a setting that does nothing.
      * a decoy ban ladder stepping past ipset's timeout ceiling -- accepted
        by the config validator, rejected at enforcement, so the escalation
        silently did not happen.

    The common shape is not "the code is wrong". It is "the thing you
    configured is not the thing that is running", and nothing compared those
    two states. So this does, with the crudest question that cannot be wrong:
    **has any generated configuration changed without a process starting
    afterwards?** If so, the running process is using the previous version,
    whatever the file says.

    It keys on content, not modification time. A `touch`, a redeploy of
    identical bytes, or a backup tool restoring the same file all move the
    mtime without changing one byte -- and a check that cries wolf on those is
    a check nobody reads.
    """
    id = "runtime_config"
    label = "运行态配置是否生效"
    label_en = "Running config is current"
    group = G_SECURITY
    stateful = True
    description = ("比对已生成的配置文件与加载它们的进程：内容变了却没有新进程"
                   "加载，说明运行中的服务仍在用旧配置")

    _STATE_V = 2

    #: How long a changed file is left unjudged, so that a deploy which
    #: writes and then reloads is not reported as broken.
    _GRACE = 90

    #: Suffix of the nginx executable path, used to recognise loaders.
    _EXE_NGINX = "sbin/nginx"
    #: An argv[0] that marks a real nginx server process (master/worker/...),
    #: as opposed to a one-shot CLI invocation of the same binary.
    _ARGV_NGINX_SERVER = re.compile(r"^nginx:\s+\S+")
    #: An argv element that names a vigil daemon module, exactly.
    _ARGV_VIGIL = re.compile(r"^vigil\.guards\.[a-z_]+$")

    def _targets(self, ctx: CheckContext) -> list:
        """(path, owner) pairs whose staleness is a security problem."""
        out = []
        # `shield` and `generated_artifacts` live in the gates package;
        # `bouncer` and `decoy` live in this one. Getting that wrong raised
        # ImportError, the bare `except` below turned it into an empty target
        # list, and the check reported "nothing to compare" -- a check that
        # silently checks nothing, which is the exact failure it was written
        # to detect. Hence: the reason is kept and reported.
        try:
            from ...gates import generated_artifacts, shield
            from .. import bouncer, decoy
            # `decoy` has no single conf path: its snippet is written into
            # each site's include directory. Ask the module where those are
            # rather than assume a function exists -- the first version called
            # `decoy.conf_path()`, which does not exist, and the framework
            # turned the AttributeError into a visible WARN instead of a
            # silent pass, which is exactly what `safe_run` is for.
            for path in (shield.shield_file(), bouncer.http_scope_path()):
                if os.path.isfile(str(path)):
                    out.append((str(path), "nginx"))
            try:
                from ...gates import demo
                main = (detect.nginx() or {}).get("conf", "")
                ext_roots = [Path(main).parent / "vhost" / "nginx" / "extension",
                             Path("/www/server/panel/vhost/nginx/extension")]
                for root in ext_roots:
                    if not root.is_dir():
                        continue
                    for site in root.iterdir():
                        cand = site / decoy.CONF_NAME
                        if cand.is_file():
                            out.append((str(cand), "nginx"))
            except (ImportError, OSError, AttributeError):
                pass
            for path in generated_artifacts():
                if str(path).endswith((".conf", ".lua")) and os.path.isfile(path):
                    out.append((str(path), "nginx"))
        except (ImportError, OSError) as exc:
            self._discovery_error = "%s: %s" % (type(exc).__name__, exc)
        return sorted(set(out))

    @staticmethod
    def _proc_start(pid: int) -> float:
        """Process start time. `/proc/<pid>`'s mtime is its creation time."""
        try:
            return os.path.getmtime("/proc/%d" % pid)
        except OSError:
            return 0.0

    @staticmethod
    def _argv(pid: int, cap: int = 4096) -> list:
        """The process's argv, as a list of strings."""
        try:
            with open("/proc/%d/cmdline" % pid, "rb") as fh:
                raw = fh.read(cap)
        except OSError:
            return []
        return [a.decode("utf-8", "replace") for a in raw.split(b"\0") if a]

    def _is_loader(self, pid: int, owner: str) -> bool:
        """Could this process have loaded a configuration file for `owner`?

        Recognised two ways, both chosen so that a *shell* or a *one-shot CLI
        invocation* can never satisfy them:

          * nginx -- the resolved executable is the nginx binary *and* the
            process is a server process. The executable test alone is not
            enough: `nginx -V`, `nginx -t` and `nginx -s reload` run the same
            binary but exit immediately, and they do not make a configuration
            live. Backups, the BT panel and this program itself all run
            `nginx -V` from time to time, and each one would look like "a
            process started after the file changed" -- so a genuinely stale
            config would be reported as loaded, permanently, every time the
            panel polled. The master and its workers rename themselves to
            `nginx: <role>`, which is what distinguishes them.
          * vigil -- some argv element is exactly `vigil.guards.<name>`. A
            shell passes its entire script as a *single* argument, so its
            elements are `bash`, `-c` and one long blob -- never an exact
            match.
        """
        if owner == "nginx":
            try:
                if not os.readlink("/proc/%d/exe" % pid).endswith(self._EXE_NGINX):
                    return False
            except OSError:
                return False
            argv = self._argv(pid)
            if not argv or not argv[0].startswith("nginx:"):
                return False
            return self._ARGV_NGINX_SERVER.match(argv[0]) is not None
        return any(self._ARGV_VIGIL.match(a) for a in self._argv(pid))


    def _newest_proc(self, owner: str) -> float:
        """Start time of the newest live process that could have loaded config.

        This deliberately does *not* shell out to `pgrep -f <string>`. That
        matches any command line merely *containing* the string -- while
        diagnosing this very check it matched the shell running the
        diagnostic. A falsely-new process start is not harmless: it makes a
        stale configuration look like a loaded one, which is a false
        negative in the single check whose whole job is catching "the thing
        you configured is not the thing that is running".
        """
        newest = 0.0
        try:
            entries = os.listdir("/proc")
        except OSError:
            return 0.0
        for entry in entries:
            if not entry.isdigit():
                continue
            pid = int(entry)
            if self._is_loader(pid, owner):
                newest = max(newest, self._proc_start(pid))
        return newest

    def run(self, ctx: CheckContext) -> CheckResult:
        self._discovery_error = ""
        targets = self._targets(ctx)
        if not targets:
            if self._discovery_error:
                # Never let "could not look" pass as "nothing to see".
                return CheckResult(
                    WARN, "无法枚举需要比对的生成配置（%s）—— "
                          "本项本次没有实际检查任何东西" % self._discovery_error)
            return CheckResult(OK, "没有需要比对的生成配置")

        current = {path: digest_file(path) for path, _owner in targets}
        prev = ctx.state.get("runtime_config")
        if ctx.state.get("runtime_config_v") != self._STATE_V or not prev:
            ctx.state["runtime_config_v"] = self._STATE_V
            ctx.state["runtime_config"] = current
            return CheckResult(OK, "已记录 %d 个生成配置的内容基线"
                                   % len(current))

        started = {"nginx": self._newest_proc("nginx"),
                   "vigil": self._newest_proc("vigil")}
        owners = dict(targets)

        changed = [p for p, h in current.items() if prev.get(p) != h]
        stale = []
        pending = {}
        for path in changed:
            owner = owners.get(path, "nginx")
            when = started.get(owner) or 0.0
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                continue
            # Grace period. A deploy writes the file and *then* reloads, so
            # for a few seconds the file is legitimately newer than the
            # running process -- and a health check that lands in that window
            # (the timer fires every few minutes, updates happen whenever)
            # would raise a CRIT about a deployment that is working exactly as
            # designed. So the change is not judged yet.
            age = time.time() - mtime
            if age < self._GRACE:
                pending[path] = age
                continue
            # A process that started after the file was written has read it.
            if when and mtime > when + 2:
                stale.append((path, owner, mtime - when))

        # Advance the snapshot -- but *hold back* anything still inside its
        # grace period. Advancing it would retire the question before it was
        # ever asked: the next run would see the new hash already recorded,
        # call the file unchanged, and a configuration that never took effect
        # would be forgotten rather than reported. Holding the old hash keeps
        # the change live until the window closes and it can be judged.
        snapshot = dict(current)
        for path in pending:
            if path in prev:
                snapshot[path] = prev[path]
            else:
                snapshot.pop(path, None)
        ctx.state["runtime_config"] = snapshot

        if not stale:
            if not changed:
                return CheckResult(OK, "生成配置与运行态一致")
            if pending:
                # Do not call this "loaded" and do not call it "stale": the
                # change is real but still settling, so the honest answer is
                # that this run makes no claim. The snapshot held it back, so
                # a later run will judge it.
                return CheckResult(
                    OK, "%d 个生成配置刚刚改动（最近 %.0f 秒），处于 %d 秒观察期，"
                        "本次不下结论，稍后复核"
                    % (len(pending), min(pending.values()), self._GRACE))
            # "No stale file found" only means the config is live if we also
            # found the process that would have loaded it. When no loader can
            # be identified, the honest report is "could not tell" -- saying
            # "loaded by a newer process" here is the same reporting failure
            # this program keeps finding in other people's software: an
            # absence of evidence printed as evidence.
            unknown = [p for p in changed
                       if not started.get(owners.get(p, "nginx"))]
            if unknown:
                return CheckResult(
                    WARN, "%d 个生成配置有改动，但本机找不到加载它们的进程，"
                          "本次**无法判定**这些改动是否已生效（不是「已生效」）\n"
                          "       %s"
                    % (len(unknown), "\n       ".join(unknown[:6])))
            return CheckResult(
                OK, "生成配置与运行态一致（%d 个文件有改动，均已由新进程载入；"
                    "nginx 进程启动于 %s）"
                    % (len(changed),
                       time.strftime("%F %T",
                                     time.localtime(started.get("nginx") or 0))))

        blocks = ["%s（比 %s 进程新 %.0f 秒）" % (p, o, age)
                  for p, o, age in stale[:6]]
        if len(stale) > 6:
            blocks.append("…… 另有 %d 个" % (len(stale) - 6))
        return CheckResult(
            CRIT,
            "**磁盘上的配置没有生效**：%d 个生成文件的内容已改变，"
            "但加载它们的进程仍早于这次改动\n"
            "       %s\n"
            "       文件是对的，此刻的运行态不是 —— 这份配置现在不提供任何保护。\n"
            "       常见原因：nginx 拒绝 reload（`[emerg]`，例如改动了 "
            "limit_req_zone 的键变量），或服务没有重启。\n"
            "       处理：systemctl restart nginx，然后 vigil shield install 复核。"
            % (len(stale), "\n       ".join(blocks)))


@register
class VigilWatchdog(Check):
    id = "vigil_watchdog"
    label = "本程序运行状态"
    label_en = "Vigil watchdog"
    group = G_SECURITY
    description = "本程序的守护进程与定时器是否存活、巡检是否还在按时运行"

    #: Units that must be running for protection to actually exist. The
    #: timers are checked separately: a timer that is merely "active" while
    #: its service has been failing for an hour is the failure mode this
    #: check exists for.
    REQUIRED_SERVICES = ("vigil-threatd.service", "vigil-loadshed.service")
    REQUIRED_TIMERS = ("vigil-health.timer", "vigil-logind.timer",
                       "vigil-maild.timer")

    @staticmethod
    def _installed_timers() -> list:
        """Every vigil timer unit actually present on disk.

        Deliberately not a hardcoded list. This check used to look only at
        the three timers named above, so when a fourth (`vigil-learn.timer`)
        arrived in an upgrade and was enabled but never started, the one
        check whose whole job is to notice a defence that is not running
        reported all clear. A new timer must be covered the moment it is
        installed, without anyone remembering to add it here.
        """
        from ...core import paths
        try:
            # `p.name`, not `p.stem` -- see units.ensure_timers_running:
            # dropping the ".timer" suffix makes systemctl query a service
            # that does not exist and quietly report "not-found".
            return sorted(p.name for p in
                          paths.SYSTEMD_UNIT_DIR.glob("%s*.timer"
                                                      % paths.UNIT_PREFIX))
        except OSError:
            return []

    def run(self, ctx: CheckContext) -> CheckResult:
        from ...core import shell

        dead, dead_timers = [], []
        for unit in self.REQUIRED_SERVICES:
            if shell.out(["systemctl", "is-active", unit]) != "active":
                dead.append(unit)
        # The core timers must be up. Any *other* installed timer must be up
        # too, but only if it is enabled -- a disabled timer for a feature
        # the operator did not choose is not a fault.
        timers = list(self.REQUIRED_TIMERS)
        for name in self._installed_timers():
            if name in timers:
                continue
            if shell.out(["systemctl", "is-enabled", name]) == "enabled":
                timers.append(name)
        for unit in timers:
            state = shell.out(["systemctl", "is-active", unit])
            if state not in ("active",):
                dead_timers.append("%s(%s)" % (unit, state or "unknown"))

        # Is the inspection itself still happening? A monitoring program that
        # has stopped monitoring reports nothing, and nothing looks exactly
        # like "all clear".
        stale = self._stale_hours(ctx)

        if dead or dead_timers:
            bits = []
            if dead:
                bits.append("守护进程未运行：%s" % "、".join(dead))
            if dead_timers:
                bits.append("定时器未激活：%s" % "、".join(dead_timers))
            if stale is not None:
                bits.append("最近一次巡检在 %.1f 小时前" % stale)
            return CheckResult(
                CRIT,
                "**本程序的防护没有在运行**：%s\n"
                "       这不是被攻击的迹象，而是防护出现了缺口——在这段时间里发生"
                "的攻击不会有人处理。\n"
                "       请执行：systemctl status %s ；"
                "journalctl -u %s -n 50 查看失败原因。"
                % ("；".join(bits), (dead or dead_timers)[0],
                   (dead or dead_timers)[0].split("(")[0]))

        if stale is not None:
            return CheckResult(
                WARN,
                "巡检已经 %.1f 小时没有运行（预期间隔 %.0f 分钟）。\n"
                "       守护进程都在，所以这是调度或执行失败："
                "systemctl list-timers 'vigil-*' 与 "
                "journalctl -u vigil-health -n 50。"
                % (stale, self._interval_minutes(ctx)))

        return CheckResult(OK, "本程序的守护进程与定时器运行正常，巡检未停滞")

    @staticmethod
    def _interval_minutes(ctx: CheckContext) -> float:
        try:
            return float(ctx.cfg.get("health.interval_minutes", 5) or 5)
        except (TypeError, ValueError):
            return 5.0

    def _stale_hours(self, ctx: CheckContext):
        """Hours since the last completed inspection, or None if it is fine.

        The inspection writes ``health-last.json`` at the end of every run,
        so its mtime is the honest answer to "is this thing still working".
        """
        last = paths.STATE_STATE / "health-last.json"
        try:
            age = time.time() - os.path.getmtime(str(last))
        except OSError:
            return None
        # Allow a generous multiple: one missed run is a hiccup, not a story.
        if age < self._interval_minutes(ctx) * 60 * 3:
            return None
        return age / 3600.0


def _unrepairable_artifact(path) -> bool:
    """Is this a generated file that selfheal deliberately will not rewrite?

    The distinction decides the severity: "the shield snippet was deleted and
    we could not rebuild it" is a critical loss of protection, while "the
    gate's config.php was deleted and we refuse to rewrite it because that
    would drop your hand-edits" is a warning that needs a human. Only files
    that are *in* the generated-artifact set count; anything else -- source
    files especially -- stays critical.
    """
    try:
        from ...gates import generated_artifacts
        from .. import selfheal
        known = {str(p) for p in generated_artifacts()}
    except Exception:                                       # noqa: BLE001
        return False
    if str(path) not in known:
        return False
    try:
        return not selfheal.supported(str(path))
    except Exception:                                       # noqa: BLE001
        return False
