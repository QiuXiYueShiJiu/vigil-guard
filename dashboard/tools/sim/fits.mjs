import { readFileSync } from 'node:fs';
await import('../dom-stub.mjs');
const mod = await import('../../frontend/assets/map.js?v=' + Math.random());
const doc = JSON.parse(readFileSync(new URL('../../backend/data/world.json', import.meta.url), 'utf8'));
let bad = 0;
for (const [w, h] of [[1400,560],[1200,620],[900,420],[1920,760],[420,300],[700,900],[2560,900],[3840,1200]]) {
  const canvas = globalThis.document.createElement('canvas');
  canvas.clientWidth = w; canvas.clientHeight = h;
  const map = new mod.FlatMap(canvas, {});
  map.w = w; map.h = h; map.adopt(doc);
  map.flyTo('world'); Object.assign(map.view, map.target); map._applyView();
  const at = (lon, lat) => map._project(lon, lat, { x: 0, y: 0 });
  const x0 = at(-180, 0).x, x1 = at(180, 0).x, y0 = at(0, 84).y, y1 = at(0, -84).y;
  const over = Math.max(0, -x0, x1 - w, -y0, y1 - h);
  if (over > 1) bad++;
  console.log('  ' + String(w).padStart(4) + 'x' + String(h).padEnd(4)
    + ' zoom ' + map.view.zoom.toFixed(2)
    + ' | 经度 ' + (x1 - x0).toFixed(0).padStart(5) + '/' + String(w).padEnd(5)
    + ' 纬度 ' + (y1 - y0).toFixed(0).padStart(4) + '/' + String(h).padEnd(4)
    + (over <= 1 ? '  ✓' : '  ✗ 溢出 ' + over.toFixed(1)));
}
console.log(bad ? 'FAIL: ' + bad + ' 种尺寸仍有裁切' : 'PASS: 所有画布比例下整幅地图完整可见，无裁切');
