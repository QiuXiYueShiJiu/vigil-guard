import { readFileSync } from 'node:fs';
// A canvas that actually delivers events, so the pan handler can be tested.
const listeners = {};
const ctx = new Proxy({}, { get: () => () => ({ addColorStop() {} }) });
const canvas = {
  clientWidth: 1200, clientHeight: 600, width: 0, height: 0, style: {},
  getContext: () => ctx,
  getBoundingClientRect: () => ({ left: 0, top: 0, width: 1200, height: 600 }),
  addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
  removeEventListener() {},
  setPointerCapture() {},
};
globalThis.document = {
  createElement: () => ({ ...canvas, style: {}, getContext: () => ctx }),
  getElementById: () => null,
  addEventListener() {}, removeEventListener() {},
};
globalThis.window = { devicePixelRatio: 1, addEventListener() {}, removeEventListener() {} };
globalThis.Path2D = class { moveTo() {} lineTo() {} closePath() {} };
globalThis.performance = globalThis.performance || { now: () => Date.now() };
globalThis.requestAnimationFrame = () => 0;

const mod = await import('../../frontend/assets/map.js?v=' + Math.random());
const doc = JSON.parse(readFileSync(new URL('../../backend/data/world.json', import.meta.url), 'utf8'));
const map = new mod.FlatMap(canvas, {});
map.w = 1200; map.h = 600; map.adopt(doc);

const fireId = (type, id, x, y) => (listeners[type] || []).forEach((f) => f({
  type, pointerId: id, clientX: x, clientY: y, preventDefault() {},
}));
const fire = (type, x, y) => fireId(type, 1, x, y);
const lat = () => mod.projectionLat(map.target.projY);
const lon = () => map.target.lon;
const reset = () => { map.flyTo('world'); Object.assign(map.view, map.target); map._applyView(); };
let pass = 0, fail = 0;
const check = (name, cond, actual) => {
  if (cond) { pass++; console.log('  ✓ ' + name + '  (' + actual + ')'); }
  else { fail++; console.log('  ✗ ' + name + '  (' + actual + ')'); }
};
console.log('已注册:', Object.keys(listeners).join(', '));

reset(); fire('pointerdown', 600, 300); fire('pointermove', 600, 400);
check('向下拖 → 往北看（纬度变大）', lat() > 1, '纬度 ' + lat().toFixed(2));

reset(); fire('pointerdown', 600, 300); fire('pointermove', 600, 200);
check('向上拖 → 往南看（纬度变小）', lat() < -1, '纬度 ' + lat().toFixed(2));

reset(); fire('pointerdown', 600, 300); fire('pointermove', 700, 300);
check('向右拖 → 往西看（经度变小）', lon() < -1, '经度 ' + lon().toFixed(2));

reset(); fire('pointerdown', 600, 300); fire('pointermove', 500, 300);
check('向左拖 → 往东看（经度变大）', lon() > 1, '经度 ' + lon().toFixed(2));

// 缩放：区域视角下才有放大空间
const wheel = (dy, x, y) => (listeners.wheel || []).forEach((f) => f({
  clientX: x, clientY: y, deltaY: dy, preventDefault() {},
}));
map.flyTo({ lon: 115, lat: 18, zoom: 2 });
Object.assign(map.view, map.target); map._applyView();
const z0 = map.target.zoom;
wheel(-100, 600, 300);
check('滚轮向上 → 放大', map.target.zoom > z0, z0.toFixed(2) + ' → ' + map.target.zoom.toFixed(2));
const z1 = map.target.zoom;
wheel(100, 600, 300);
check('滚轮向下 → 缩小', map.target.zoom < z1, z1.toFixed(2) + ' → ' + map.target.zoom.toFixed(2));

// 双指捏合
map.flyTo({ lon: 115, lat: 18, zoom: 2 });
Object.assign(map.view, map.target); map._applyView();
const z2 = map.target.zoom;
// 真实的触摸是一连串 move 事件；逐帧张开
// 两个手指必须是不同的 pointerId，否则 Map 里会被覆盖成一个
fireId('pointerdown', 1, 550, 300); fireId('pointerdown', 2, 650, 300);
for (const gap of [120, 160, 200, 240, 280]) {
  fireId('pointermove', 1, 600 - gap / 2, 300);
  fireId('pointermove', 2, 600 + gap / 2, 300);
}
check('双指张开 → 放大', map.target.zoom > z2, z2.toFixed(2) + ' → ' + map.target.zoom.toFixed(2)
  + '  [pointers=' + map._pointers.size + ' pinch=' + map._pinch + ']');

// 点按拾取
map.traces.length = 0;
map.push({ lat: 48.85, lon: 2.35, lv: 1, ip: '9.9.9.9', det: '测试' });
const pt = map._project(2.35, 48.85, { x: 0, y: 0 });
const picked = map._pick(pt.x, pt.y);
check('点按能拾取来源', picked && picked.ip === '9.9.9.9', picked ? picked.ip : 'null');

console.log(fail ? 'FAIL: ' + fail + ' 项' : 'PASS: 交互方向全部正确 (' + pass + ' 项)');
process.exit(fail ? 1 : 0);
