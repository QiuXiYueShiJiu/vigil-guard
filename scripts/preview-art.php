<?php
/**
 * Render the generated puzzle artwork to a contact sheet.
 *
 * Development aid. The slider background is drawn entirely in code, and the
 * only honest way to judge a change to it is to look at a spread of results
 * rather than at the one lucky seed that happened to come up.
 *
 *   php scripts/preview-art.php [count] [out.png] [cell-width]
 *
 * Needs only the PHP GD extension -- the same requirement the gate itself
 * has, so it runs anywhere the product does.
 */
declare(strict_types=1);

$root = dirname(__DIR__);
$lib = $root . '/src/vigil/gates/templates/lib/gate-lib.php.tmpl';
if (!is_file($lib)) {
    fwrite(STDERR, "找不到网关模板：$lib\n");
    exit(2);
}
if (!function_exists('imagecreatetruecolor')) {
    fwrite(STDERR, "需要 PHP GD 扩展\n");
    exit(2);
}
require $lib;

$count = max(1, (int)($argv[1] ?? 12));
$out = $argv[2] ?? ($root . '/art-preview.png');
$W = max(120, (int)($argv[3] ?? 340));
$H = (int)round($W * 200 / 340);

$scenes = array_keys(vigil_slider_scenes());
$cols = 3;
$lab = 16;
$pad = 8;
$rows = (int)ceil($count / $cols);
$sheet = imagecreatetruecolor($cols * ($W + $pad) + $pad,
                              $rows * ($H + $lab + $pad) + $pad);
imagefilledrectangle($sheet, 0, 0, imagesx($sheet), imagesy($sheet),
                     imagecolorallocate($sheet, 18, 18, 24));
$ink = imagecolorallocate($sheet, 236, 238, 244);
$t0 = microtime(true);

for ($i = 0; $i < $count; $i++) {
    // Cycle the presets rather than picking at random, so a change to one
    // palette is always visible in the sheet instead of maybe visible.
    $scene = $scenes[$i % count($scenes)];
    $art = vigil_slider_background($W, $H, $scene);
    $r = $i % $cols;
    $c = (int)($i / $cols);
    $ox = $pad + $r * ($W + $pad);
    $oy = $pad + $c * ($H + $lab + $pad) + $lab;
    imagecopy($sheet, $art['image'], $ox, $oy, 0, 0, $W, $H);
    imagestring($sheet, 3, $ox, $oy - 13, sprintf('%02d %s', $i + 1, $scene), $ink);
    imagedestroy($art['image']);
}
imagepng($sheet, $out);
imagedestroy($sheet);
printf("%d 张 -> %s（%.0f ms/张）\n", $count, $out,
       (microtime(true) - $t0) * 1000 / $count);
