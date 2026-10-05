/* A replayed history entry must not be drawn as a live attack.
 *
 * The history ring holds a couple of minutes of events and is handed to every
 * new page. Without an age check, a ban from earlier reappears as a fresh
 * strike on each refresh -- which is what "the map still shows fake sources"
 * was. This drives the real home.js against a fixture containing one recent
 * and one stale attack, and asserts only the recent one becomes a mark.
 */
import { readFileSync } from 'node:fs';
await import('../dom-stub.mjs');

const now = Date.now() / 1000;
const mkEvent = (ip, nt, lv) => ({
  t: nt, nt, id: ip, ip, lat: 40, lon: -74, lv,
  cc: 'US', co: '美国', p: '/wp-login.php', s: 404,
});
const state = {
  ts: now,
  server: { lat: 22.3193, lon: 114.1694 },
  traffic: { total: 10, rpm: 1, epm: 0, levels: { normal: 0, attack: 0, pressure: 0 },
    countries: { US: 2 }, local: 0, minute_series: new Array(12).fill(0) },
  threat: {
    live_bans: 1, bans_total: 5, ledger_age: 2,
    posture: { active: false },
    latest_bans: [{ ip: '9.9.8.8', reason: '蜜罐诱饵命中', detector: 'decoy',
      until: now + 3600, cc: 'US', co: '美国', ci: '' }],
  },
  geo: { available: true, cached: 1 },
  // Three entries: one just now (must be replayed), one from two and a half
  // minutes ago and one from ten minutes ago (both must be skipped). The
  // middle one is the shape of the real bug: a scanner that probed the home
  // page while nobody was looking, surfacing as a "new visitor" on every
  // refresh because the replay window was wide enough to reach it.
  history: [
    mkEvent('185.199.7.1', now - 3, 1),
    mkEvent('45.198.224.125', now - 150, 0),
    mkEvent('185.199.7.2', now - 600, 1),
  ],
};
const resources = JSON.parse(readFileSync('/tmp/fixture-resources.json', 'utf8'));

globalThis.__fetch = async (url) => {
  const u = String(url);
  const body = u.includes('/assets/world.json') ? { v: 2, meta: { scale: 1000 }, countries: [], labels: [] }
    : u.includes('/api/v1/resources') ? { ok: true, data: resources }
    : u.includes('/api/v1/state') ? { ok: true, data: state }
    : { ok: true, data: {} };
  return { ok: true, status: 200, text: async () => JSON.stringify(body), json: async () => body };
};

await import('../../frontend/assets/home.js?t=' + Math.random());
await new Promise((r) => setTimeout(r, 600));

// The page records what it accepted, keyed by the source id it was given.
// Each accepted event appends exactly one row to the stream table, so the
// row count is a direct measure of what was treated as live: two events were
// offered, only the recent one may be accepted.
const stream = globalThis.__byId.get('stream');
const rows = stream ? stream.children.length : -1;
console.log('服务端提供了 3 条历史（1 条刚发生、1 条 2.5 分钟前、1 条 10 分钟前）');
console.log('页面接受并回放的事件数:', rows, rows === 1 ? '✓' : '✗');
console.log('  → 较早的探测没有重现为新访问:', rows === 1 ? '✓' : '✗');

const ok = rows === 1;
console.log(ok ? 'PASS: 只回放近期事件，过期历史不会重现为攻击' : 'FAIL');
process.exit(ok ? 0 : 1);
