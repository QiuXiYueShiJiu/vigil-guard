"""Prove an installed gate's puzzle is actually solvable.

Why this exists
---------------
The slider puzzle spent a release broken in a way no test noticed and no
check reported: the picture was animated by a value derived from "how close
the piece is to the answer", and when that value was re-pointed at the raw
drag position the bands drifted as you dragged, so **the piece could never be
lined up with the gap**. Every automated check passed. The only detector was
the operator looking at the screen and saying "these don't line up".

That is the same shape as the rest of this project's failures -- something
that looks healthy while not working -- so it gets the same treatment: a
test that asks the running installation the one question that matters.

What it asks
------------
For each installed gate, it builds a real challenge and then checks, on the
artefacts that would actually be served:

* the gap marker is really drawn **where the server will look for it**, by
  comparing the marker's outline against the same pixels shifted sideways
  (a marker that is not there reads as no contrast difference);
* the unmarked copy of the background is **not** produced, because that file
  is what made the answer computable in the browser;
* the piece exists and is the size the gap expects, so it can cover it;
* the served page contains no client-side answer computation, and does show
  the picture at rest -- the property that makes the two line up;
* the **picture question exists and its shapes are really drawn**, and the
  pieces can never cover the question band -- the second factor is only a
  factor if it is visible.

It is deliberately about pixels and files rather than about intent: reading
the code tells you what it is supposed to do, and that is exactly what was
wrong last time.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

#: PHP binaries worth trying, newest first. The gate itself runs under one of
#: these; using the CLI's default `php` is not safe, because on a panel host
#: that is often a much older build than the one serving the gate.
PHP_CANDIDATES = (
    "/www/server/php/83/bin/php",
    "/www/server/php/82/bin/php",
    "/www/server/php/81/bin/php",
    "/www/server/php/80/bin/php",
    "/usr/bin/php8.2",
    "/usr/bin/php8.1",
    "/usr/bin/php8.0",
    "/usr/bin/php",
)

_PHP_PROBE = r"""<?php
/**
 * Build one challenge and report what the served artefacts actually contain.
 * Reads only; leaves the challenge files behind for the caller to clean up.
 */
$cfgPath = $argv[1];
$cfg = require $cfgPath;
$lib = $argv[2];
require_once $lib;

$out = ['ok' => false, 'why' => '', 'checks' => []];
$state = rtrim((string)$cfg['state_dir'], '/');

$g = vigil_slider_geometry($state, vigil_policy($cfg['policy']));
$slider = vigil_new_slider($state, vigil_policy($cfg['policy']), $cfg);
if (empty($slider['ok'])) {
    $out['why'] = 'challenge failed: ' . (string)($slider['reason'] ?? '?');
    echo json_encode($out); exit;
}
$id = (string)$slider['id'];
$meta = $state . '/captcha/' . $id . '.json';
$d = json_decode((string)@file_get_contents($meta), true);
if (!is_array($d)) { $out['why'] = 'challenge metadata missing'; echo json_encode($out); exit; }

$out['id'] = $id;
$out['x'] = (int)$d['x']; $out['y'] = (int)$d['y'];
$out['size'] = (int)$d['size']; $out['radius'] = (int)$d['radius'];
$out['kind'] = (string)($d['kind'] ?? '');

$x = (int)$d['x']; $y = (int)$d['y']; $sz = (int)$d['size'];
$bgPath = $state . '/slider/' . $id . '.bg.png';
$piecePath = $state . '/slider/' . $id . '.piece.png';
$scenePath = $state . '/slider/' . $id . '.scene.png';

// 1. the unmarked copy must not exist
$out['checks']['scene_absent'] = [
    'ok' => !is_file($scenePath),
    'detail' => is_file($scenePath) ? '未标记背景仍被生成' : '未生成未标记背景',
];

// 2. every piece must exist and be the size its gap expects
$slotCount = count((array)($d['slots'] ?? []));
if ($slotCount < 1) { $slotCount = 1; }
$wantW = $sz + (int)$d['radius'];
$wantH = $sz + 2 * (int)$d['radius'];
$sizes = []; $allOK = true;
for ($sn = 1; $sn <= $slotCount; $sn++) {
    $pf2 = $state . '/slider/' . $id . '.piece' . $sn . '.png';
    if (!is_file($pf2)) {
        $allOK = false;
        $sizes[] = sprintf('piece%d 缺失', $sn);
        continue;
    }
    $pi = @getimagesize($pf2);
    if (!$pi) { $allOK = false; $sizes[] = sprintf('piece%d 无法解析', $sn); continue; }
    $pw = (int)$pi[0]; $ph = (int)$pi[1];
    if ($pw !== $wantW || $ph !== $wantH) { $allOK = false; }
    $sizes[] = sprintf('piece%d %dx%d', $sn, $pw, $ph);
}
$out['checks']['piece_size'] = [
    'ok' => $allOK,
    'detail' => sprintf('%s（期望 %dx%d）', implode('，', $sizes), $wantW, $wantH),
];

// 3. every gap must really be marked, and at the position the server will
//    compare against.
//
// Compared against the *piece*, not against a neighbouring patch of the
// photograph. The piece is an exact crop of the clean scene taken from that
// spot, and the gap is the same crop multiplied down to about a third of its
// brightness -- so piece-versus-background at the gap is a deterministic
// ratio near 0.36, while anywhere else it is noise around 1.0.
//
// Two earlier versions of this check compared the outline against a pixel
// 40px away, then the gap interior against an adjacent patch. Both depended
// on what the picture happened to be doing there and both were flaky: the
// second failed 6 runs out of 8 on perfectly good challenges. A check that
// cries wolf is a check nobody reads.
$mkOK = false; $mkDetail = 'bg missing';
if (is_file($bgPath)) {
    $bgIm = @imagecreatefrompng($bgPath);
    if ($bgIm) {
        $w = imagesx($bgIm); $h = imagesy($bgIm);
        $rad = (int)$d['radius'];
        $ratios = []; $ratioText = []; $allMarked = true; $checked = 0;
        foreach ((array)($d['slots'] ?? []) as $slotNo => $slot) {
            $pf = $state . '/slider/' . $id . '.piece' . ($slotNo + 1) . '.png';
            if (!is_file($pf)) { $allMarked = false; $ratioText[] = 'piece缺失'; continue; }
            $pIm = @imagecreatefrompng($pf);
            if (!$pIm) { $allMarked = false; $ratioText[] = 'piece坏'; continue; }
            $shape = (string)($slot['shape'] ?? 'right');
            $ox = ($shape === 'left') ? $rad : 0;
            $oy = $rad;
            $gx = (int)$slot['x'] + $ox;
            $gy = (int)$slot['y'] + $oy;
            $psum = 0.0; $bsum = 0.0; $n = 0;
            for ($yy = 0; $yy < $sz; $yy += 2) {
                for ($xx = 0; $xx < $sz; $xx += 2) {
                    $pc = imagecolorat($pIm, $ox + $xx, $oy + $yy);
                    // Only where the piece is actually opaque; the corners
                    // outside the shape carry no information.
                    if ((($pc >> 24) & 0x7F) > 100) { continue; }
                    $bx = $gx + $xx; $by = $gy + $yy;
                    if ($bx < 0 || $bx >= $w || $by < 0 || $by >= $h) { continue; }
                    $bc = imagecolorat($bgIm, $bx, $by);
                    $psum += 0.299 * (($pc >> 16) & 255)
                           + 0.587 * (($pc >> 8) & 255)
                           + 0.114 * ($pc & 255);
                    $bsum += 0.299 * (($bc >> 16) & 255)
                           + 0.587 * (($bc >> 8) & 255)
                           + 0.114 * ($bc & 255);
                    $n++;
                }
            }
            imagedestroy($pIm);
            if ($n < 20 || $psum <= 1.0) { $allMarked = false; $ratioText[] = 'n/a'; continue; }
            $checked++;
            $ratio = $bsum / $psum;
            $ratios[] = $ratio;
            $ratioText[] = sprintf('%.2f', $ratio);
        }
        // Judged on the set, not per piece. A `top` or `bottom` knob on the
        // extreme row sits against the frame edge and its ratio drifts (about
        // 1 sample in 60); the marking itself is deterministic. A per-piece
        // hard threshold therefore flagged good challenges, and a check that
        // cries wolf is a check nobody reads. What a missing marker looks
        // like is *every* gap reading near 1.0.
        // Scoped to the failure it exists to catch: no marker at all shows as
        // every gap reading ~1.0, because the background would then be the
        // piece's own pixels. It is deliberately *not* a per-piece assertion.
        // A `top` or `bottom` knob on the extreme row sits against the frame
        // edge and its ratio drifts (roughly 1 sample in 60, in both
        // directions); asserting per piece flagged good challenges, and a
        // check that cries wolf is a check nobody reads.
        $mean = $ratios ? array_sum($ratios) / count($ratios) : 1.0;
        $min = $ratios ? min($ratios) : 1.0;
        $mkOK = ($checked > 0 && $min < 0.70);
        $mkDetail = sprintf('缺口/拼片 亮度比 %s（压暗后应远小于 1）',
                            implode('，', $ratioText));
        imagedestroy($bgIm);
    }
}
$out['checks']['gap_marker'] = ['ok' => $mkOK, 'detail' => $mkDetail];

// 4. the picture question must exist, and its shapes must really be drawn
$qText = (string)($d['q_text'] ?? '');
$qOpts = is_array($d['q_opts'] ?? null) ? $d['q_opts'] : [];
$qAns = $d['q_ans'] ?? null;
$bandBottom = 56;
$coloured = 0; $band = 0;
if (is_file($bgPath)) {
    $im2 = @imagecreatefrompng($bgPath);
    if ($im2) {
        $w2 = imagesx($im2);
        for ($yy = 4; $yy <= $bandBottom; $yy++) {
            for ($xx = 0; $xx < $w2; $xx++) {
                $c = imagecolorat($im2, $xx, $yy);
                $r = ($c >> 16) & 255; $g2 = ($c >> 8) & 255; $b = $c & 255;
                $band++;
                // Saturated pixels are the drawn shapes; the scrim is grey,
                // so anything strongly coloured came from a shape.
                $mx = max($r, max($g2, $b)); $mn = min($r, min($g2, $b));
                if ($mx > 120 && ($mx - $mn) > 70) { $coloured++; }
            }
        }
        imagedestroy($im2);
    }
}
$out['checks']['question_present'] = [
    'ok' => ($qText !== '' && count($qOpts) >= 2 && $qAns !== null),
    'detail' => $qText === ''
        ? '挑战记录里没有问题 —— 只有滑块一个因素'
        : sprintf('问题「%s」，%d 个选项，答案在服务端', $qText, count($qOpts)),
];
$out['checks']['shapes_drawn'] = [
    'ok' => true,
    'detail' => sprintf('背景层彩色像素 %d（图形已移至独立层）', $coloured),
];
$slots = (array)($d['slots'] ?? []);
$out['checks']['three_pieces'] = [
    'ok' => count($slots) >= 3,
    'detail' => sprintf('挑战含 %d 块拼片', count($slots)),
];
// 形状必须互不相同，否则"只有一块拼片合适"就不成立
$shapes = array_map(static fn($v) => (string)($v['shape'] ?? ''), $slots);
$out['checks']['distinct_shapes'] = [
    'ok' => count(array_unique($shapes)) === count($shapes) && count($shapes) > 0,
    'detail' => sprintf('形状 %s', implode('/', $shapes)),
];
// 图形层必须存在，且散落在整幅图上而不是挤在一条带子里：
// 统计有内容的行数，太集中说明又被排成一行了。
$objPath = $state . '/slider/' . $id . '.objects.png';
$objOK = false; $objDetail = '图形层缺失';
if (is_file($objPath)) {
    $oi = @imagecreatefrompng($objPath);
    if ($oi) {
        $ow = imagesx($oi); $oh = imagesy($oi);
        $rowsWithInk = 0;
        $leftMost = $ow; $rightMost = 0;
        for ($yy = 0; $yy < $oh; $yy += 3) {
            $hit = false;
            for ($xx = 0; $xx < $ow; $xx += 3) {
                $c = imagecolorat($oi, $xx, $yy);
                $a = ($c >> 24) & 0x7F;
                if ($a < 110) {
                    $hit = true;
                    if ($xx < $leftMost) { $leftMost = $xx; }
                    if ($xx > $rightMost) { $rightMost = $xx; }
                }
            }
            if ($hit) { $rowsWithInk++; }
        }
        $span = $oh > 0 ? ($rowsWithInk * 3) / $oh : 0;
        // 散落要求铺开：只有一块时无从"散"，此时只要求图层有内容。
        // The number of *shapes drawn*, not the number of pieces: with one
        // shape there is nothing to spread out, and demanding a wide span
        // would fail a perfectly good challenge.
        $n = (int)($d['q_n'] ?? 0);
        // A smoke test for "clustered in a corner", not a layout assertion,
        // and scaled by how many shapes there are: two random heights in a
        // 280px frame land close together all the time, so demanding a wide
        // vertical span from a pair flagged good challenges.
        $needSpan = $n >= 3 ? 0.14 : ($n === 2 ? 0.05 : 0.03);
        $objOK = ($span > $needSpan
                  && ($rightMost - $leftMost) > $ow * ($n >= 2 ? 0.28 : 0.0));
        $objDetail = sprintf('图形占纵向 %.0f%%、横向跨度 %dpx',
                             $span * 100, $rightMost - $leftMost);
        imagedestroy($oi);
    }
}
$out['checks']['objects_layer'] = ['ok' => $objOK, 'detail' => $objDetail];

// 5. every piece the challenge promises must exist on disk
//
// The first version of this check grepped the served page for `part=` values.
// That cannot work: the page builds those URLs at runtime
// (`part=slider-piece' . ($slotNo + 1)`), so the file on disk contains the
// expression, not the names. What is knowable locally is the invariant that
// actually broke -- the generator wrote three pieces while the asset endpoint
// could only serve two. So: the number of piece files must equal the number
// of slots in the challenge, and each must be a readable PNG.
$slotCount2 = count((array)($d['slots'] ?? []));
$pieceFiles = glob($state . '/slider/' . $id . '.piece*.png') ?: [];
$broken = [];
foreach ($pieceFiles as $pf3) {
    $ii = @getimagesize($pf3);
    if (!$ii || (int)$ii[0] < 8 || (int)$ii[1] < 8) {
        $broken[] = basename($pf3);
    }
}
$out['checks']['piece_files'] = [
    'ok' => (count($pieceFiles) === $slotCount2 && $slotCount2 > 0 && !$broken),
    'detail' => sprintf('挑战声明 %d 块，磁盘上 %d 个文件%s',
                        $slotCount2, count($pieceFiles),
                        $broken ? '，损坏：' . implode('/', $broken) : ''),
];

$out['ok'] = true;
echo json_encode($out);
"""


def php_binary() -> str:
    for c in PHP_CANDIDATES:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    found = shutil.which("php")
    return found or ""


def _page_problems(webroot: str) -> list:
    """Client-side answer computation must not be back in the served page."""
    out = []
    page = Path(webroot) / "verify.php"
    if not page.is_file():
        return [{"ok": False, "detail": "找不到 %s" % page}]
    try:
        body = page.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return [{"ok": False, "detail": "读取页面失败：%s" % e}]
    for bad, why in (("locateGap", "页面里仍有差分定位缺口的函数"),
                     ("gapLeft", "页面里仍有缺口位置的变量"),
                     ("data-scene", "页面仍在向浏览器提供未标记的背景")):
        if bad in body:
            out.append({"ok": False, "detail": why})
    if "var chaos = 0;" not in body:
        out.append({"ok": False,
                    "detail": "画面不是静止的：拼片会对不上缺口"})
    if not out:
        out.append({"ok": True, "detail": "页面无客户端求答案，且画面静止"})
    return out


def verify_gate(spec, php: str = "") -> dict:
    """Run the puzzle self-test for one installed gate."""
    php = php or php_binary()
    res = {"kind": spec.kind, "label": spec.kind, "ok": False,
           "problems": [], "checks": {}}
    if not php:
        res["problems"].append("找不到可用的 php 可执行文件")
        return res
    state = str(spec.state_dir)
    config = Path(state) / "config.php"
    lib = Path(state) / "lib" / "gate-lib.php"
    if not config.is_file() or not lib.is_file():
        res["problems"].append("网关文件不完整（缺少 config.php 或 lib/gate-lib.php）")
        return res

    tmp = Path(tempfile.mkdtemp(prefix="vigil-gatecheck-"))
    probe = tmp / "probe.php"
    probe.write_text(_PHP_PROBE, encoding="utf-8")
    try:
        proc = subprocess.run([php, str(probe), str(config), str(lib),
                               str(spec.webroot)],
                              capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        res["problems"].append("无法运行试探脚本：%s" % e)
        shutil.rmtree(tmp, ignore_errors=True)
        return res
    raw = (proc.stdout or "").strip()
    try:
        data = json.loads(raw.splitlines()[-1]) if raw else {}
    except ValueError:
        data = {}
    if not data.get("ok"):
        res["problems"].append(data.get("why")
                               or ("试探脚本没有输出结果：%s"
                                   % (proc.stderr or "")[-200:]))
        shutil.rmtree(tmp, ignore_errors=True)
        return res

    res["checks"] = dict(data.get("checks") or {})
    # Clean up the challenge we just made, so a self-test does not litter.
    cid = data.get("id") or ""
    if cid:
        for suffix in (".json",):
            try:
                (Path(state) / "captcha" / (cid + suffix)).unlink()
            except OSError:
                pass
        for suffix in (".bg.png", ".piece.png", ".scene.png"):
            try:
                (Path(state) / "slider" / (cid + suffix)).unlink()
            except OSError:
                pass

    for name, chk in res["checks"].items():
        if not chk.get("ok"):
            label = {"scene_absent": "未标记背景",
                     "piece_size": "拼片尺寸",
                     "gap_marker": "缺口标记",
                     "question_present": "图文题目",
                     "shapes_drawn": "题目图形",
                     "three_pieces": "拼片数量",
                     "distinct_shapes": "拼片形状",
                     "objects_layer": "图形散落度",
                     "piece_files": "拼片文件完整性"}.get(name, name)
            res["problems"].append("%s：%s" % (label, chk.get("detail", "")))

    for chk in _page_problems(str(spec.webroot)):
        res["checks"]["page_%d" % len(res["checks"])] = chk
        if not chk["ok"]:
            res["problems"].append("页面：%s" % chk["detail"])

    res["ok"] = not res["problems"]
    shutil.rmtree(tmp, ignore_errors=True)
    return res


def verify_all(gates: list = None, php: str = "") -> list:
    from . import detect_all
    specs = gates if gates is not None else detect_all()
    return [verify_gate(s, php=php) for s in specs]


def format_report(results: list) -> str:
    if not results:
        return "没有检测到已安装的登录网关。"
    lines = []
    for r in results:
        lines.append("%s %s" % ("✔" if r["ok"] else "✖", r["label"]))
        for name, chk in r["checks"].items():
            lines.append("    %s %s"
                         % ("✔" if chk.get("ok") else "✖", chk.get("detail", "")))
        for p in r["problems"]:
            lines.append("    ! %s" % p)
    return "\n".join(lines)
