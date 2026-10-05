/* Self-contained: measures the real draw path and counts base rebuilds. */
import { readFileSync } from 'node:fs';
// Must be a real function before anything else loads: a stub that proxies
// every property returns a function from performance.now(), and every timing
// silently becomes NaN.
globalThis.performance = { now: () => Date.now() };
let counts = { drawImage: 0, fill: 0, stroke: 0, arc: 0 };
const listeners = {};
const ctx = new Proxy({}, {
  get: (_, key) => {
    if (key in counts) return () => { counts[key] += 1; };
    if (key === 'createLinearGradient' || key === 'createRadialGradient')
      return () => ({ addColorStop() {} });
    if (key === 'getImageData') return () => ({ data: new Uint8ClampedArray(4) });
    return () => {};
  },
  set: () => true,
});
const mkCanvas = () => ({
  clientWidth: 1400, clientHeight: 620, width: 0, height: 0, style: {},
  getContext: () => ctx,
  getBoundingClientRect: () => ({ left: 0, top: 0, width: 1400, height: 620 }),
  addEventListener(t, f) { (listeners[t] = listeners[t] || []).push(f); },
  removeEventListener() {}, setPointerCapture() {},
});
globalThis.document = { createElement: mkCanvas, getElementById: () => null,
  addEventListener() {}, removeEventListener() {} };
globalThis.window = { devicePixelRatio: 1, addEventListener() {}, removeEventListener() {} };
globalThis.Path2D = class { moveTo() {} lineTo() {} closePath() {} };
globalThis.requestAnimationFrame = () => 0;

const mod = await import('../../frontend/assets/map.js?v=' + Math.random());
const doc = JSON.parse(readFileSync(new URL('../../backend/data/world.json', import.meta.url), 'utf8'));
const canvas = mkCanvas();
const map = new mod.FlatMap(canvas, {});
map.w = 1400; map.h = 620; map.adopt(doc);
map._running = true;

console.log('单次底图绘制耗时（不同缩放）：');
for (const z of [0.8, 1.5, 3, 6, 12]) {
  map.flyTo({ lon: 115, lat: 25, zoom: z });
  Object.assign(map.view, map.target); map._applyView();
  const t0 = Date.now();
  map._drawBase();
  const ms = Date.now() - t0;
  const verdict = ms < 8 ? '可 60fps' : ms < 16 ? '可 60fps（偏紧）' : ('只能 ' + Math.round(1000 / ms) + ' fps');
  console.log('  缩放 ' + z.toFixed(1).padStart(5) + '×  ' + ms.toString().padStart(5) + ' ms  ' + verdict);
}

// 拖动 60 帧：底图应只在开始时画一次
map.flyTo('world'); Object.assign(map.view, map.target); map._applyView();
map._drawBase();
let baseBefore = map.stats.baseDraws;
const fire = (t, x, y) => (listeners[t] || []).forEach((f) => f({
  pointerId: 1, clientX: x, clientY: y, preventDefault() {},
}));
fire('pointerdown', 700, 300);
let t = 1000;
for (let i = 0; i < 60; i++) {
  fire('pointermove', 700 + i * 5, 300);
  t += 16.7;
  map._loop(t);
}
const rebuilt = map.stats.baseDraws - baseBefore;
const avg = map.stats.frameMs / Math.max(1, map.stats.frames);
console.log('');
console.log('拖动 60 帧：底图重建 ' + rebuilt + ' 次（每帧重建会是 60 次）');
console.log('  每帧总耗时均值 ' + avg.toFixed(2) + ' ms → 上限 ' + Math.round(1000 / Math.max(0.01, avg)) + ' fps');
console.log('  平均每帧花在底图上的时间 ' + ((map.stats.baseMs / Math.max(1, map.stats.baseDraws)) * rebuilt / Math.max(1, map.stats.frames)).toFixed(2) + ' ms');
