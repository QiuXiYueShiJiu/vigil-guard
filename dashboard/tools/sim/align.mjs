/* Marker/coastline alignment and zoom-anchor pinning.
 *
 * The failure this guards against: after a zoom, sources drift away from the
 * coastlines they belong to. That happens when the anchor maths mixes scales,
 * and it is invisible in any test that only checks that a projection returns
 * *a* number.
 */
import { readFileSync } from 'node:fs';

const listeners = {};
const ctx = new Proxy({}, { get: () => () => ({ addColorStop() {} }) });
const canvas = {
  clientWidth: 1200, clientHeight: 600, width: 0, height: 0, style: {},
  getContext: () => ctx,
  getBoundingClientRect: () => ({ left: 0, top: 0, width: 1200, height: 600 }),
  addEventListener(t, f) { (listeners[t] = listeners[t] || []).push(f); },
  removeEventListener() {}, setPointerCapture() {},
};
globalThis.document = {
  createElement: () => ({ ...canvas, getContext: () => ctx }),
  getElementById: () => null,
  addEventListener() {}, removeEventListener() {},
};
globalThis.window = { devicePixelRatio: 2, addEventListener() {}, removeEventListener() {} };
globalThis.Path2D = class { moveTo() {} lineTo() {} closePath() {} };
globalThis.requestAnimationFrame = () => 0;

const mod = await import('../../frontend/assets/map.js?v=' + Math.random());
const doc = JSON.parse(readFileSync(new URL('../../backend/data/world.json', import.meta.url), 'utf8'));
const map = new mod.FlatMap(canvas, {});
map.w = 1200; map.h = 600; map.adopt(doc);

let pass = 0, fail = 0;
const check = (name, ok, detail) => {
  if (ok) { pass++; console.log('  ✓ ' + name + (detail ? '  (' + detail + ')' : '')); }
  else { fail++; console.log('  ✗ ' + name + (detail ? '  (' + detail + ')' : '')); }
};
const settle = () => { Object.assign(map.view, map.target); map._applyView(); };
const at = (lon, lat) => map._project(lon, lat, { x: 0, y: 0 });

// 城市坐标系：每个点都要一直贴在同一块陆地上
const CITIES = [
  { n: '北京', lon: 116.4, lat: 39.9 },
  { n: '香港', lon: 114.17, lat: 22.3 },
  { n: '东京', lon: 139.69, lat: 35.68 },
  { n: '伦敦', lon: -0.12, lat: 51.5 },
  { n: '纽约', lon: -74, lat: 40.7 },
];

console.log('1) 缩放锚点必须钉在同一个像素上');
map.flyTo({ lon: 115, lat: 18, zoom: 2 }); settle();
const anchorX = 300, anchorY = 180;               // 左上角附近，最容易暴露错误
const under = map._unproject(anchorX, anchorY);
for (const f of [1.4, 1.4, 0.7, 1.4]) {
  map.zoomBy(f, anchorX, anchorY);
  settle();
  const now = at(under.lon, under.lat);
  const dx = Math.abs(now.x - anchorX), dy = Math.abs(now.y - anchorY);
  check('锚点漂移 ' + dx.toFixed(3) + ',' + dy.toFixed(3) + ' px',
    dx < 0.5 && dy < 0.5, '缩放 ' + map.view.zoom.toFixed(2));
}

console.log('2) 缩放后点与底图仍用同一套投影（相对位置不变）');
map.flyTo({ lon: 115, lat: 18, zoom: 1.2 }); settle();
const shots = [];
for (const z of [0.9, 1.8, 3.6, 7.2]) {
  map.target.zoom = z; settle();
  // 两点之间的像素距离必须与缩放成正比，且方向不变
  const a = at(CITIES[0].lon, CITIES[0].lat);
  const b = at(CITIES[1].lon, CITIES[1].lat);
  shots.push({ z, dx: b.x - a.x, dy: b.y - a.y });
}
let proportional = true;
for (let i = 1; i < shots.length; i += 1) {
  const ratioZ = shots[i].z / shots[i - 1].z;
  const ratioX = shots[i].dx / shots[i - 1].dx;
  const ratioY = shots[i].dy / shots[i - 1].dy;
  if (Math.abs(ratioX - ratioZ) > 0.02 || Math.abs(ratioY - ratioZ) > 0.02) {
    proportional = false;
    console.log('    z=' + shots[i].z + ' 期望比例 ' + ratioZ.toFixed(3)
      + ' 实际 ' + ratioX.toFixed(3) + '/' + ratioY.toFixed(3));
  }
}
check('两个城市的间距随缩放线性变化', proportional);

console.log('3) 平移后点跟着地图走（同一位移量）');
map.flyTo({ lon: 115, lat: 18, zoom: 2 }); settle();
const before = at(139.69, 35.68);
const fireId = (t, id, x, y) => (listeners[t] || []).forEach((f) => f({
  type: t, pointerId: id, clientX: x, clientY: y, preventDefault() {},
}));
fireId('pointerdown', 1, 600, 300);
fireId('pointermove', 1, 700, 340);      // 拖 (100, 40)
settle();
const after = at(139.69, 35.68);
check('东京跟着拖拽位移', Math.abs((after.x - before.x) - 100) < 0.5
  && Math.abs((after.y - before.y) - 40) < 0.5,
'dx=' + (after.x - before.x).toFixed(2) + ' dy=' + (after.y - before.y).toFixed(2));

console.log('4) 服务端信标与流星同源（同一 lat/lon 必落同一像素）');
map.setServer({ lat: 22.3, lon: 114.17 });
const beacon = map._project(map.opts.server.lon, map.opts.server.lat, { x: 0, y: 0 });
const same = at(114.17, 22.3);
check('信标与香港同点', Math.abs(beacon.x - same.x) < 1e-6 && Math.abs(beacon.y - same.y) < 1e-6);

console.log(fail ? 'FAIL: ' + fail + ' 项' : 'PASS: 对齐与锚点全部正确 (' + pass + ' 项)');
process.exit(fail ? 1 : 0);
