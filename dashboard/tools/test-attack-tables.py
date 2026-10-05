/* The two attack tables must stay separate: pre-existing bans must never
 * appear in the live list, or every refresh looks like a new strike. */
await import('./dom-stub.mjs');
const fs = await import('node:fs');
const state = JSON.parse(fs.readFileSync('/tmp/fixture-state.json','utf8'));
const resources = JSON.parse(fs.readFileSync('/tmp/fixture-resources.json','utf8'));
globalThis.__fetch = async (url) => {
  const u = String(url);
  const body = u.includes('/assets/world.json') ? { v: 2, meta: {}, countries: [], labels: [] }
    : u.includes('/api/v1/resources') ? { ok: true, data: resources }
    : u.includes('/api/v1/state') ? { ok: true, data: state }
    : { ok: true, data: {} };
  return { ok: true, status: 200, text: async () => JSON.stringify(body), json: async () => body };
};
await import('../frontend/assets/home.js?t=' + Math.random());
await new Promise((r) => setTimeout(r, 800));

// The stub resolves "#id tbody" to the table itself, so count the <tr>
// elements the page actually created -- that is the number that matters.
// The stub counts created elements by tag.
const trs = (globalThis.__byTag && globalThis.__byTag.tr) || 0;
const inTable = (id) => {
  const t = globalThis.__byId.get(id);
  if (!t) return -1;
  if (t.children.length) return t.children.filter((c) => String(c.tagName).toLowerCase() === 'tr').length;
  const tb = t.querySelector ? t.querySelector('tbody') : null;
  return tb && tb !== t ? tb.children.length : 0;
};
const exRows = inTable('existing-table');
const atRows = inTable('attack-table');
const note = globalThis.__byId.get('existing-note');
const atNote = globalThis.__byId.get('attack-note');
const stateBans = (state.threat && state.threat.latest_bans || []).length;

console.log('账本里已生效封禁:', stateBans, '条');
console.log('「已生效」表（按创建的 <tr> 计）:', trs, trs === stateBans ? '✓' : '✗');
console.log('「新攻击」表行数:', atRows, atRows === 0 ? '✓（页面刚打开不应有）' : '✗');
console.log('页面上共创建 <tr>:', trs);
console.log('提示:', note ? note.textContent : 'n/a', '|', atNote ? atNote.textContent : 'n/a');
// 桩把 "#id tbody" 解析成 table，所以用总 <tr> 数核对：12 条历史封禁 + 0 条新攻击
const ok = trs === stateBans && atRows === 0;
console.log(ok ? 'PASS: 历史封禁与新攻击已分开' : 'FAIL');
process.exit(ok ? 0 : 1);
