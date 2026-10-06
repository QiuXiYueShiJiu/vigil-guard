/* 地图交互：手势**已停用**，选中改由按钮驱动。
 *
 * 这个文件以前断言的是拖拽方向、滚轮缩放与双指捏合。手势停用之后那些用例
 * 必然全红 —— 而「设计上就该红」和「真的坏了」在输出里长得一模一样，过一阵
 * 就没人分得清哪条该修、哪条该留。所以它们换成断言**手势确实不可用**：
 *
 *   1. `GESTURES_ENABLED` 为 false，并且画布上**一个**手势监听器都没注册
 *      （不是"注册了但不会触发"——那正是老代码的坑）；
 *   2. 合成出来的 pointer / wheel 事件既不动视野，也不触发选中。
 *      最后这条钉的是老代码的真实缺陷：`pointerup` 没有守卫，而 `_moved`
 *      只在带守卫的 `pointerdown` 里被重置，永远停在 0，于是 `0 < 6` 恒成立，
 *      「已停用」的地图每次抬手仍会报告一次点选；
 *   3. 取而代之的按钮路径真的能选中：`selectLatest()` 走 `onSelect` 回调，
 *      而且取的是**最近上屏**的那一条（不是随便一条）；
 *   4. `_pick()`（纯几何，与手势无关）仍然正确 —— 将来把开关改回 true，
 *      按坐标拾取可以直接用。
 *
 * 断言的是当前的设计，不是"曾经的行为"。要把手势重新打开，就得连同这些用例
 * 一起改，那正是应该发生的。 */
import { readFileSync } from 'node:fs';

// A canvas that actually delivers events, so the listener contract can be tested.
const listeners = {};
const winListeners = {};
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
globalThis.window = {
  devicePixelRatio: 1,
  addEventListener(t, f) { (winListeners[t] = winListeners[t] || []).push(f); },
  removeEventListener() {},
};
globalThis.Path2D = class { moveTo() {} lineTo() {} closePath() {} };
globalThis.performance = globalThis.performance || { now: () => Date.now() };
globalThis.requestAnimationFrame = () => 0;

const mod = await import('../../frontend/assets/map.js?v=' + Math.random());
const doc = JSON.parse(readFileSync(new URL('../../backend/data/world.json', import.meta.url), 'utf8'));
// 记录每一次 onSelect：手势路径与按钮路径都必须经过这一个回调。
const picked = [];
const map = new mod.FlatMap(canvas, { onSelect: (event) => picked.push(event) });
map.w = 1200; map.h = 600; map.adopt(doc);

const fireId = (type, id, x, y, extra) => (listeners[type] || []).forEach((f) => f(Object.assign({
  type, pointerId: id, clientX: x, clientY: y, preventDefault() {},
}, extra || {})));
const fire = (type, x, y, extra) => fireId(type, 1, x, y, extra);
const wheel = (dy, x, y) => fire('wheel', x, y, { deltaY: dy });
const lat = () => mod.projectionLat(map.target.projY);
const lon = () => map.target.lon;
const zoom = () => map.target.zoom;
const reset = () => { map.flyTo('world'); Object.assign(map.view, map.target); map._applyView(); };
let pass = 0, fail = 0;
const check = (name, cond, actual) => {
  if (cond) { pass++; console.log('  ✓ ' + name + '  (' + actual + ')'); }
  else { fail++; console.log('  ✗ ' + name + '  (' + actual + ')'); }
};

console.log('画布上已注册的监听器:', Object.keys(listeners).join(', ') || '（一个都没有）');

/* ── 1. 开关与注册：没有手势是"可证明的" ─────────────────────────── */

check('GESTURES_ENABLED 为 false（交互设计取舍，不是修复）',
  mod.GESTURES_ENABLED === false, String(mod.GESTURES_ENABLED));

const GESTURE_EVENTS = ['pointerdown', 'pointermove', 'pointerup', 'pointercancel',
  'pointerleave', 'pointerenter', 'wheel', 'touchstart', 'touchmove', 'touchend'];
const registered = GESTURE_EVENTS.filter((t) => (listeners[t] || []).length);
check('画布上没有注册任何 pointer / wheel / touch 监听器',
  registered.length === 0, registered.length ? '注册了 ' + registered.join(', ') : '一个都没有');

check('窗口 resize 监听保留（重算画布尺寸，与手势无关）',
  (winListeners.resize || []).length === 1,
  (winListeners.resize || []).length + ' 个');

/* ── 2. 合成事件既不移动视野，也不触发选中 ───────────────────────── */

reset();
const before = { lon: lon(), lat: lat(), zoom: zoom() };
// 先在"手指底下"放一条来源：如果 pointerup 还有处理函数，它一定会选中这条。
map.traces.length = 0;
picked.length = 0;
map.push({ lat: 48.85, lon: 2.35, lv: 1, ip: '203.0.113.9', det: '合成事件用' });
const tap = map._project(2.35, 48.85, { x: 0, y: 0 });

fire('pointerdown', tap.x, tap.y);
fire('pointermove', tap.x + 100, tap.y + 40);
fire('pointermove', tap.x + 200, tap.y + 90);
fire('pointerup', tap.x + 200, tap.y + 90);
fire('pointercancel', tap.x + 200, tap.y + 90);
fire('pointerleave', tap.x + 200, tap.y + 90);
check('拖拽不再平移视野（纬度 / 经度都没动）',
  Math.abs(lon() - before.lon) < 1e-9 && Math.abs(lat() - before.lat) < 1e-9,
  '经度 ' + lon().toFixed(2) + ' 纬度 ' + lat().toFixed(2));

wheel(-100, 600, 300);
wheel(100, 600, 300);
check('滚轮不再缩放', Math.abs(zoom() - before.zoom) < 1e-9,
  before.zoom.toFixed(2) + ' → ' + zoom().toFixed(2));

check('抬手不再触发选中（这正是老代码的缺陷）', picked.length === 0,
  picked.length + ' 次 onSelect');

// 双指：真实的触摸是一连串 move 事件，逐帧张开。
map.flyTo({ lon: 115, lat: 18, zoom: 2 });
Object.assign(map.view, map.target); map._applyView();
const z2 = zoom();
fireId('pointerdown', 1, 550, 300);
fireId('pointerdown', 2, 650, 300);
for (const gap of [120, 160, 200, 240, 280]) {
  fireId('pointermove', 1, 600 - gap / 2, 300);
  fireId('pointermove', 2, 600 + gap / 2, 300);
}
check('双指张开不再缩放', Math.abs(zoom() - z2) < 1e-9,
  z2.toFixed(2) + ' → ' + zoom().toFixed(2));
check('没有留下任何指针状态（监听器根本没注册）', map._pointers.size === 0,
  'pointers=' + map._pointers.size + ' pinch=' + map._pinch);

/* ── 3. 按钮路径：selectLatest() ──────────────────────────────────── */

// 几何拾取本身与手势无关，留着它将来直接可用。
map.traces.length = 0;
map.push({ lat: 48.85, lon: 2.35, lv: 1, ip: '203.0.113.9', det: '坐标拾取用' });
const pt = map._project(2.35, 48.85, { x: 0, y: 0 });
const byPoint = map._pick(pt.x, pt.y);
check('_pick 仍能按坐标拾取来源', byPoint && byPoint.ip === '203.0.113.9',
  byPoint ? byPoint.ip : 'null');

picked.length = 0;
const chosen = map.selectLatest();
check('selectLatest() 返回被选中的来源', chosen && chosen.ip === '203.0.113.9',
  chosen ? chosen.ip : 'null');
check('selectLatest() 与手势走同一个 onSelect 回调',
  picked.length === 1 && picked[0] === chosen,
  picked.length + ' 次回调');

// "最近"必须是最近上屏的那一条，而不是数组里的第一条。
map.traces.length = 0;
picked.length = 0;
map.push({ lat: 48.85, lon: 2.35, lv: 1, ip: '203.0.113.9', det: '早先上屏' });
map.traces[0].age = 2000;                       // 毫秒：已经上屏 2 秒
map.push({ lat: 35.68, lon: 139.69, lv: 2, ip: '203.0.113.7', det: '刚刚上屏' });
const latest = map.latestSource();
check('latestSource() 取的是最近上屏的一条，不是第一条',
  latest && latest.ip === '203.0.113.7', latest ? latest.ip : 'null');

// 没有来源时按钮必须能说"没有"，而不是抛异常或静默。
map.traces.length = 0;
picked.length = 0;
const empty = map.selectLatest();
check('没有来源时 selectLatest() 返回 null 且不回调',
  empty === null && picked.length === 0,
  empty === null ? 'null，0 次回调' : String(empty));

console.log(fail ? 'FAIL: ' + fail + ' 项' : 'PASS: 手势确实不可用，按钮选中路径可用 (' + pass + ' 项)');
process.exit(fail ? 1 : 0);
