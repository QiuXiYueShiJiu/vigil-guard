/* ──────────────────────────────────────────────────────────────
   vigil console · shared runtime
   Small on purpose: no framework, no build step. The map does the
   heavy lifting, everything else is DOM.
   ────────────────────────────────────────────────────────────── */
'use strict';

export const API = '/api/v1';

/* CSRF token handed out at login; echoed on every mutation. */
let csrf = '';
try { csrf = sessionStorage.getItem('vigil-csrf') || ''; } catch (_) { csrf = ''; }

/* The session token, used as X-Vigil-Token.

   The cookie carrying it is HttpOnly on purpose, so script cannot read it;
   the service therefore returns it once at login (and from /session) purely
   so the page can echo it back in a header. Sending the CSRF value here --
   which is what this used to do -- fails the server's comparison and shows
   "会话校验失败，请刷新页面重试" straight after a successful login. Kept in
   sessionStorage so a refresh does not lose it. */
let authToken = '';
try { authToken = sessionStorage.getItem('vigil-token') || ''; } catch (_) { authToken = ''; }

export function setAuthToken(value) {
  authToken = value || '';
  try {
    if (authToken) sessionStorage.setItem('vigil-token', authToken);
    else sessionStorage.removeItem('vigil-token');
  } catch (_) { /* private mode */ }
}

export function getAuthToken() { return authToken; }
export function setCsrf(value) {
  csrf = value || '';
  try { sessionStorage.setItem('vigil-csrf', csrf); } catch (_) { /* private mode */ }
}
export function getCsrf() { return csrf; }

export async function api(path, options = {}) {
  const opts = Object.assign({ credentials: 'same-origin' }, options);
  // Session token when we have it; the CSRF value only as a last resort, so a
  // stale page from before this change still behaves as it did.
  opts.headers = Object.assign({ 'X-Vigil-Token': authToken || csrf }, opts.headers || {});
  if (opts.body && typeof opts.body !== 'string' && !(opts.body instanceof Blob)) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(opts.body);
  }
  const res = await fetch(API + path, opts);
  let payload = null;
  const text = await res.text();
  try { payload = text ? JSON.parse(text) : null; } catch (_) { payload = { ok: false, error: text }; }
  if (payload && payload.ok === false) {
    const err = new Error(payload.error || ('HTTP ' + res.status));
    err.code = payload.code || res.status;
    err.detail = payload.detail || '';
    throw err;
  }
  if (!res.ok && payload === null) throw new Error('HTTP ' + res.status);
  return payload ? payload.data : null;
}

/* ── formatting ─────────────────────────────────────────────── */

export function bytes(n, digits = 1) {
  if (n === null || n === undefined || isNaN(n)) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0, v = Number(n);
  while (Math.abs(v) >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return (i === 0 ? v.toFixed(0) : v.toFixed(digits)) + ' ' + units[i];
}

export function rate(n) { return bytes(n, 1) + '/s'; }

export function pct(n, digits = 1) {
  if (n === null || n === undefined || isNaN(n)) return '—';
  return Number(n).toFixed(digits) + '%';
}

export function num(n) {
  if (n === null || n === undefined) return '—';
  return Number(n).toLocaleString('zh-CN');
}

export function duration(seconds) {
  if (!seconds && seconds !== 0) return '—';
  const s = Math.max(0, Math.floor(seconds));
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d) return d + ' 天 ' + h + ' 小时';
  if (h) return h + ' 小时 ' + m + ' 分';
  if (m) return m + ' 分 ' + (s % 60) + ' 秒';
  return s + ' 秒';
}

export function clock(ts) {
  const d = ts ? new Date(ts * 1000) : new Date();
  const p = (x) => String(x).padStart(2, '0');
  return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}

export function stamp(ts) {
  const d = ts ? new Date(ts * 1000) : new Date();
  const p = (x) => String(x).padStart(2, '0');
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' '
    + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}

/* ── sparkline / tiny charts ────────────────────────────────── */

export function drawSeries(canvas, values, opts = {}) {
  if (!canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth || 120, h = canvas.clientHeight || 32;
  if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
    canvas.width = w * dpr; canvas.height = h * dpr;
  }
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  const data = (values || []).filter((v) => typeof v === 'number' && isFinite(v));
  if (data.length < 2) return;
  const max = opts.max !== undefined ? opts.max : Math.max.apply(null, data.concat([1]));
  const min = opts.min !== undefined ? opts.min : Math.min.apply(null, data.concat([0]));
  const span = Math.max(1e-6, max - min);
  const step = w / (data.length - 1);
  const y = (v) => h - 2 - ((v - min) / span) * (h - 4);
  const stroke = opts.stroke || '#d2762e';
  const fill = opts.fill || 'rgba(210,118,46,.16)';

  ctx.beginPath();
  ctx.moveTo(0, y(data[0]));
  for (let i = 1; i < data.length; i += 1) ctx.lineTo(i * step, y(data[i]));
  if (opts.area !== false) {
    ctx.save();
    ctx.lineTo(w, h); ctx.lineTo(0, h); ctx.closePath();
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, fill);
    grad.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = grad;
    ctx.fill();
    ctx.restore();
  }
  ctx.beginPath();
  ctx.moveTo(0, y(data[0]));
  for (let i = 1; i < data.length; i += 1) ctx.lineTo(i * step, y(data[i]));
  ctx.strokeStyle = stroke;
  ctx.lineWidth = opts.width || 1.6;
  ctx.lineJoin = 'round';
  ctx.shadowColor = opts.glow || stroke;
  ctx.shadowBlur = opts.blur === undefined ? 6 : opts.blur;
  ctx.stroke();
  ctx.shadowBlur = 0;
}

/* ── dom helpers ────────────────────────────────────────────── */

export function $(sel, root = document) { return root.querySelector(sel); }
export function $$(sel, root = document) { return Array.prototype.slice.call(root.querySelectorAll(sel)); }

export function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  Object.keys(attrs).forEach((key) => {
    const val = attrs[key];
    if (val === null || val === undefined || val === false) return;
    if (key === 'class') node.className = val;
    else if (key === 'text') node.textContent = val;
    else if (key === 'html') node.innerHTML = val;
    else if (key === 'dataset') Object.assign(node.dataset, val);
    else if (key.startsWith('on') && typeof val === 'function') {
      node.addEventListener(key.slice(2).toLowerCase(), val);
    } else node.setAttribute(key, val);
  });
  (Array.isArray(children) ? children : [children]).forEach((child) => {
    if (child === null || child === undefined) return;
    node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
  });
  return node;
}

export function escapeHtml(text) {
  return String(text === null || text === undefined ? '' : text)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/* Country flag emoji from an ISO-3166 alpha-2 code. */
export function flag(cc) {
  if (!cc || cc.length !== 2 || !/^[A-Za-z]{2}$/.test(cc)) return '🌐';
  const base = 0x1f1e6;
  const up = cc.toUpperCase();
  return String.fromCodePoint(base + up.charCodeAt(0) - 65,
    base + up.charCodeAt(1) - 65);
}

export function toast(message, kind = 'info', timeout = 3200) {
  let host = document.getElementById('toast-host');
  if (!host) {
    host = el('div', { id: 'toast-host', class: 'toast-host' });
    document.body.appendChild(host);
  }
  const node = el('div', { class: 'toast toast-' + kind, text: message });
  host.appendChild(node);
  requestAnimationFrame(() => node.classList.add('in'));
  setTimeout(() => {
    node.classList.remove('in');
    setTimeout(() => node.remove(), 320);
  }, timeout);
}

export function confirmDialog(message, opts = {}) {
  return new Promise((resolve) => {
    const host = el('div', { class: 'modal-host' });
    const close = (value) => { host.remove(); document.removeEventListener('keydown', onKey); resolve(value); };
    const onKey = (ev) => { if (ev.key === 'Escape') close(false); };
    document.addEventListener('keydown', onKey);
    const box = el('div', { class: 'modal' }, [
      el('h3', { text: opts.title || '请确认' }),
      el('p', { text: message }),
      opts.detail ? el('pre', { class: 'modal-detail', text: opts.detail }) : null,
      el('div', { class: 'modal-actions' }, [
        el('button', { class: 'btn ghost', text: opts.cancel || '取消', onclick: () => close(false) }),
        el('button', { class: 'btn ' + (opts.danger ? 'danger' : 'primary'), text: opts.ok || '确定', onclick: () => close(true) }),
      ]),
    ]);
    host.appendChild(box);
    host.addEventListener('click', (ev) => { if (ev.target === host) close(false); });
    document.body.appendChild(host);
    requestAnimationFrame(() => box.classList.add('in'));
  });
}

/* Ask the panel for a delete confirmation token, then perform the delete.
   Two round trips is the price of not being able to lose a directory to a
   stray click or a replayed request. */
export async function confirmedDelete(paths, label) {
  const ok = await confirmDialog(
    '确定要永久删除 ' + (paths.length > 1 ? paths.length + ' 个项目' : label || paths[0]) + ' 吗？',
    {
      title: '危险操作',
      detail: paths.slice(0, 12).join('\n') + (paths.length > 12 ? '\n…' : ''),
      ok: '删除', danger: true,
    });
  if (!ok) return false;
  const token = await api('/fs/confirm', { method: 'POST', body: { paths } });
  await api('/fs/delete', { method: 'POST', body: { paths, token: token.token } });
  return true;
}
