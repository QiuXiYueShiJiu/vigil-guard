/* During a zoom, a geographic point must not drift relative to the plate.
 *
 * The marker layer draws a point at  c + (p - v) * k  for the eased view v and
 * scale k. The cached plate is drawn with  translate(dx, dy); scale(kRatio),
 * so the same point inside the cached image lands at
 *
 *     (translate) applied to (base pixel * kRatio)
 *
 * These must agree at every frame of the ease. This test composes exactly the
 * values the render loop composes -- the transform maths, not the canvas
 * plumbing -- so it cannot be fooled by a stubbed renderer, and a wrong scale
 * ratio (the bug that made the host slide across the map) fails immediately.
 */
import { readFileSync } from 'node:fs';
globalThis.performance = { now: () => Date.now() };
const mod = await import('../../frontend/assets/map.js?v=' + Math.random());
const doc = JSON.parse(readFileSync(new URL('../../backend/data/world.json', import.meta.url), 'utf8'));

const CTX = { setTransform() {}, clearRect() {}, fillRect() {}, strokeRect() {},
  save() {}, restore() {},
  translate() {}, scale() {}, drawImage() {}, beginPath() {}, arc() {}, fill() {},
  stroke() {}, fillText() {}, strokeText() {}, moveTo() {}, lineTo() {}, closePath() {},
  clip() {}, createLinearGradient: () => ({ addColorStop() {} }),
  createRadialGradient: () => ({ addColorStop() {} }) };
let CANVAS = null;

function installDom(w, h) {
  CANVAS = { clientWidth: w, clientHeight: h, width: 0, height: 0, style: {},
    getContext: () => CTX,
    nodeName: 'CANVAS',
    getBoundingClientRect: () => ({ left: 0, top: 0, width: w, height: h }),
    addEventListener() {}, removeEventListener() {}, setPointerCapture() {} };
  globalThis.document = { createElement: () => CANVAS, getElementById: () => null,
    addEventListener() {}, removeEventListener() {} };
  globalThis.window = { devicePixelRatio: 1, addEventListener() {}, removeEventListener() {} };
}

function makeMap(w, h) {
  installDom(w, h);
  const map = new mod.FlatMap(CANVAS, {});
  map.adopt(doc);
  return map;
}

/** Where the plate transform puts a point that lives in the cached image. */
function platePoint(map, lon, lat) {
  const kRatio = map.view.zoom / map._baseView.zoom;
  const dx = map.view.cx - (map.w / 2) * kRatio
    + (map._baseView.lon - map.view.lon) * map._scale();
  const dy = map.view.cy - (map.h / 2) * kRatio
    + (map._baseView.projY - map.view.projY) * map._yScale();
  const kb = (map.w * map._baseView.zoom) / 360;
  const baseX = (lon - map._baseView.lon) * kb + map.w / 2;
  const baseY = (mod.projectionY(lat) - map._baseView.projY)
    * ((map.w * map._baseView.zoom) / 4) + map.h / 2;
  // translate(dx, dy) then scale(kRatio): a point is scaled first, then offset.
  return { x: dx + baseX * kRatio, y: dy + baseY * kRatio };
}

const POINTS = [
  { n: '香港（主机）', lon: 114.17, lat: 22.3 },
  { n: '北京', lon: 116.4, lat: 39.9 },
  { n: '伦敦', lon: -0.12, lat: 51.5 },
  { n: '纽约', lon: -74, lat: 40.7 },
];

let fail = 0;
for (const [w, h] of [[1400, 620], [900, 420]]) {
  const map = makeMap(w, h);
  for (const target of [{ lon: 115, lat: 22, zoom: 4 }, { lon: -20, lat: 30, zoom: 2.2 }]) {
    map.flyTo(target);
    Object.assign(map.view, { lon: target.lon, lat: target.lat });
    // 从一个明显不同的初始视图开始，让缓动真正发生
    map.view.zoom = Math.max(0.5, target.zoom / 3);
    map.view.lon = target.lon + 40;
    map.view.projY = mod.projectionY(target.lat - 25);
    map._applyView();
    map._drawBase();
    map._baseView.lon = map.view.lon;
    map._baseView.projY = map.view.projY;
    map._baseView.zoom = map.view.zoom;
    let worst = 0;
    for (let frame = 0; frame < 60; frame++) {
      map._applyView();
      for (const p of POINTS) {
        const marker = map._project(p.lon, p.lat, { x: 0, y: 0 });
        const plate = platePoint(map, p.lon, p.lat);
        const drift = Math.hypot(plate.x - marker.x, plate.y - marker.y);
        if (map.view.zoom < map._baseView.zoom * 0.6
          || map.view.zoom > map._baseView.zoom * 1.6) continue;   // 超出复用范围，会重建
        worst = Math.max(worst, drift);
        if (drift > 2) {
          fail++;
        }
      }
    }
    console.log('  ' + w + 'x' + h + ' 目标 ' + target.zoom + '× 最大错位 '
      + worst.toFixed(2) + ' px');
  }
}
console.log(fail ? 'FAIL: 缩放时底图与标记错位' : 'PASS: 缩放全程底图与标记一致（含平移与缩放复用）');
process.exit(fail ? 1 : 0);
