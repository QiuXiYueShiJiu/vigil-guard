/* ──────────────────────────────────────────────────────────────
   vigil console · management behaviour

   The login gate, the six tabs, and the three things that actually
   change state: the site switches, the file manager and the audit
   trail. Everything mutating goes through core.js's api(), which
   echoes the session token in X-Vigil-Token -- the server refuses a
   write without it, so a cross-site form post cannot close a site.

   This file was accidentally truncated to zero bytes once, during a
   careless shell loop that copied a scratch file over it. The repository
   is now under version control, which is the real fix for that class of
   mistake rather than a promise to be careful.
   ────────────────────────────────────────────────────────────── */
'use strict';

import {
  api, bytes, clock, confirmedDelete, el, getAuthToken, getCsrf, num, pct,
  setAuthToken, setCsrf, stamp, toast,
} from './core.js';

const dom = {
  gate: document.getElementById('gate'),
  console: document.getElementById('console'),
  form: document.getElementById('login-form'),
  account: document.getElementById('login-account'),
  password: document.getElementById('login-password'),
  error: document.getElementById('login-error'),
  submit: document.getElementById('login-submit'),
  host: document.getElementById('admin-host'),
  who: document.getElementById('who'),
  tabs: document.getElementById('tabs'),
  logout: document.getElementById('logout-btn'),
  footNote: document.getElementById('foot-note'),
  modal: document.getElementById('modal-host'),

  overviewCards: document.getElementById('overview-cards'),
  ovSites: document.querySelector('#ov-sites tbody'),
  ovSitesNote: document.getElementById('ov-sites-note'),
  ovBans: document.querySelector('#ov-bans tbody'),
  ovBansNote: document.getElementById('ov-bans-note'),
  diag: document.getElementById('diag'),
  diagNote: document.getElementById('diag-note'),
  diagFull: document.getElementById('diag-full'),
  diagRefresh: document.getElementById('diag-refresh'),

  sitesTable: document.querySelector('#sites-table tbody'),
  sitesRefresh: document.getElementById('sites-refresh'),
  nginxTest: document.getElementById('nginx-test'),
  nginxResult: document.getElementById('nginx-result'),
  denyList: document.getElementById('deny-list'),
  denyNote: document.getElementById('deny-note'),

  fmList: document.getElementById('fm-list'),
  fmPath: document.getElementById('fm-path'),
  fmUp: document.getElementById('fm-up'),
  fmHome: document.getElementById('fm-home'),
  fmGo: document.getElementById('fm-go'),
  fmRefresh: document.getElementById('fm-refresh'),
  fmSearch: document.getElementById('fm-search'),
  fmContent: document.getElementById('fm-content'),
  fmHidden: document.getElementById('fm-hidden'),
  fmMkdir: document.getElementById('fm-mkdir'),
  fmNewfile: document.getElementById('fm-newfile'),
  fmUploadBtn: document.getElementById('fm-upload-btn'),
  fmUpload: document.getElementById('fm-upload'),
  fmDelete: document.getElementById('fm-delete'),
  fmProgress: document.getElementById('fm-progress'),
  fmStat: document.getElementById('fm-stat'),
  fmDisk: document.getElementById('fm-disk'),
  fmEditor: document.getElementById('fm-editor'),
  fmEditorHint: document.getElementById('fm-editor-hint'),
  fmFileName: document.getElementById('fm-file-name'),
  fmFileMeta: document.getElementById('fm-file-meta'),
  fmBox: document.getElementById('fm-content-box'),
  fmSave: document.getElementById('fm-save'),
  fmDownload: document.getElementById('fm-download'),
  fmClose: document.getElementById('fm-close'),

  panelGrid: document.getElementById('panel-grid'),
  servicesBody: document.getElementById('services-body'),
  sysCards: document.getElementById('sys-cards'),
  sysNote: document.getElementById('sys-note'),
  auditFile: document.getElementById('audit-file'),
  auditTable: document.querySelector('#audit-table tbody'),
  auditRefresh: document.getElementById('audit-refresh'),
};

const app = {
  sites: [],
  session: null,
  path: '/',
  file: null,
  selected: new Set(),
  timer: null,
};

/* ── boot ─────────────────────────────────────────────────── */

async function boot() {
  // The account is never written into the page. It used to be pre-filled for
  // convenience, which meant the name was in the HTML source and in the
  // browser's saved-form suggestions -- i.e. published to anyone who opened
  // the login page.
  if (dom.account) dom.account.value = '';
  if (dom.footNote) dom.footNote.textContent = '页面载入于 ' + stamp();
  wire();
  try {
    const session = await api('/session');
    app.session = session;
    // Restore the token after a refresh: the cookie survives, but script
    // cannot read it, so the server hands the token back here.
    if (session && session.token) setAuthToken(session.token);
    if (session && session.authenticated) enterConsole();
    else showGate();
  } catch (err) {
    showGate();
    setError('无法连接管理接口：' + err.message);
  }
  if (window.location.hash === '#login') showGate();
}

function showGate() {
  dom.gate.hidden = false;
  dom.console.hidden = true;
  setTimeout(() => { try { dom.password.focus(); } catch (_) { /* ignore */ } }, 120);
}

function setError(message) {
  if (!dom.error) return;
  dom.error.hidden = !message;
  dom.error.textContent = message || '';
}

function enterConsole() {
  dom.gate.hidden = true;
  dom.console.hidden = false;
  dom.host.textContent = (app.session && app.session.host) || 'vigil';
  dom.who.textContent = '管理员';
  // The page title carries the deployment's own name, which the service knows
  // and this file does not: nothing here hard-codes one operator's domain.
  if (app.session && app.session.host) {
    document.title = 'Vigil 管理控制台 · ' + app.session.host;
  }
  loadOverview();
  loadSites();
  loadPanels();
  loadServices();
  loadFiles('/');
  loadAudit();
  loadDiagnostics();
  if (app.timer) clearInterval(app.timer);
  app.timer = setInterval(loadResources, 5000);
}

/* A 401/403 anywhere means the session went away. Say so, instead of leaving
   the operator clicking buttons that silently do nothing. */
function guard(err) {
  if (err && (err.code === 401 || err.code === 403)) {
    toast(err.message || '会话已失效，请重新登录', 'error', 5000);
    setError(err.message || '会话已失效，请重新登录');
    showGate();
    return true;
  }
  return false;
}

/* ── events ───────────────────────────────────────────────── */

function wire() {
  dom.form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    setError('');
    dom.submit.disabled = true;
    dom.submit.textContent = '校验中…';
    try {
      const data = await api('/login', {
        method: 'POST',
        body: { account: dom.account.value.trim(), password: dom.password.value },
      });
      // Two different values: the CSRF token guards mutations, the session
      // token is what X-Vigil-Token must carry. Conflating them was the bug.
      setCsrf(data.csrf);
      setAuthToken(data.token);
      dom.password.value = '';
      app.session = await api('/session');
      toast('登录成功', 'ok');
      enterConsole();
    } catch (err) {
      setError(err.message || '登录失败');
      try { dom.password.select(); } catch (_) { /* ignore */ }
    } finally {
      dom.submit.disabled = false;
      dom.submit.textContent = '进入控制台';
    }
  });

  dom.logout.addEventListener('click', async () => {
    try { await api('/logout', { method: 'POST' }); } catch (_) { /* ignore */ }
    setCsrf('');
    setAuthToken('');
    window.location.href = '/';
  });

  dom.tabs.addEventListener('click', (ev) => {
    const btn = ev.target.closest('.tab');
    if (!btn) return;
    document.querySelectorAll('.tab').forEach((tab) => tab.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('.stage-panel').forEach((panel) => {
      panel.classList.toggle('active', panel.dataset.stage === btn.dataset.tab);
    });
    if (btn.dataset.tab === 'audit') loadAudit();
    if (btn.dataset.tab === 'system') loadDiagnostics();
    if (btn.dataset.tab === 'overview') { loadOverview(); loadSites(); }
    if (btn.dataset.tab === 'sites') loadSites();
  });

  dom.sitesRefresh.addEventListener('click', loadSites);
  dom.nginxTest.addEventListener('click', testNginx);
  dom.auditRefresh.addEventListener('click', loadAudit);
  dom.diagRefresh.addEventListener('click', loadDiagnostics);
  wireFileManager();
}

/* ── overview ─────────────────────────────────────────────── */

async function loadOverview() {
  try {
    const [state, diag] = await Promise.all([
      api('/state?attacks=1&resources=1'),
      api('/diagnostics').catch(() => null),
    ]);
    renderCards(state, diag);
    renderOverviewSites();
    renderOverviewBans(state.threat);
    if (diag) {
      dom.diag.textContent = formatDiag(diag);
      dom.diagNote.textContent = '更新于 ' + clock();
    }
  } catch (err) {
    if (guard(err)) return;
    toast('总览加载失败：' + err.message, 'error');
  }
}

function metric(label, value, sub, kind) {
  return el('div', { class: 'metric' }, [
    el('span', { class: 'm-label', text: label }),
    el('b', { class: 'm-value' + (kind ? ' ' + kind : ''), text: value }),
    el('span', { class: 'm-sub', text: sub || '' }),
  ]);
}

function renderCards(state, diag) {
  const host = dom.overviewCards;
  host.innerHTML = '';
  const res = state.resources || {};
  const threat = state.threat || {};
  const traffic = state.traffic || {};
  const cpu = res.cpu || {};
  const mem = res.memory || {};
  const root = ((res.disk || {}).mounts || []).find((m) => m.mount === '/') || {};
  const posture = threat.posture && threat.posture.active ? '已提升' : '常规';

  host.appendChild(metric('主机', '本机', (res.system && res.system.os) || ''));
  host.appendChild(metric('CPU', pct(cpu.percent || 0),
    cpu.load ? '负载 ' + cpu.load['1'].toFixed(2) : '',
    (cpu.percent || 0) > 85 ? 'bad' : ''));
  host.appendChild(metric('内存', pct(mem.percent || 0),
    bytes(mem.used) + ' / ' + bytes(mem.total), (mem.percent || 0) > 90 ? 'bad' : ''));
  host.appendChild(metric('硬盘', pct(root.percent || 0),
    bytes(root.used) + ' / ' + bytes(root.total), (root.percent || 0) > 90 ? 'bad' : ''));
  host.appendChild(metric('实时封禁', num(threat.live_bans || 0),
    '累计 ' + num(threat.bans_total || 0), (threat.live_bans || 0) > 50 ? 'bad' : 'ok'));
  host.appendChild(metric('防护姿态', posture,
    threat.ledger_age !== null && threat.ledger_age !== undefined
      ? '账本 ' + threat.ledger_age + ' 秒前' : '',
    posture === '已提升' ? 'bad' : 'ok'));
  host.appendChild(metric('外网请求', num(traffic.total || 0),
    num(traffic.rpm || 0) + ' 次/分钟'));
  host.appendChild(metric('站点', String(app.sites.length || 0),
    diag && diag.sites ? '已关闭 ' + diag.sites.blocked + ' 个' : ''));
}

function renderOverviewSites() {
  const body = dom.ovSites;
  body.innerHTML = '';
  if (!app.sites.length) {
    body.appendChild(el('tr', { class: 'empty' }, [el('td', { colspan: '4', text: '暂无站点' })]));
    return;
  }
  app.sites.slice(0, 12).forEach((site) => {
    body.appendChild(el('tr', {}, [
      el('td', { class: 'mono', text: site.primary }),
      el('td', {}, [el('span', {
        class: 'badge ' + (site.blocked ? 'off' : 'on'),
        text: site.blocked ? '已关闭' : '放行中',
      })]),
      el('td', { class: 'path', title: site.root, text: site.root || '—' }),
      el('td', {}, [switchNode(site)]),
    ]));
  });
  dom.ovSitesNote.textContent = app.sites.length + ' 个站点，关闭 '
    + app.sites.filter((s) => s.blocked).length + ' 个';
}

function renderOverviewBans(threat) {
  const body = dom.ovBans;
  body.innerHTML = '';
  const bans = (threat && threat.latest_bans) || [];
  if (!bans.length) {
    body.appendChild(el('tr', { class: 'empty' }, [el('td', { colspan: '4', text: '当前无封禁' })]));
  }
  bans.slice(0, 12).forEach((ban) => {
    body.appendChild(el('tr', {}, [
      el('td', { class: 'ip', text: ban.ip }),
      el('td', { text: ban.detector || '—' }),
      el('td', { class: 'path', title: ban.reason, text: ban.reason }),
      el('td', { class: 'mono', text: ban.until ? clock(ban.until) : '—' }),
    ]));
  });
  dom.ovBansNote.textContent = ((threat && threat.live_bans) || 0) + ' 个生效中';
}

function switchNode(site) {
  const input = el('input', {
    type: 'checkbox',
    onchange: (ev) => toggleSite(site, ev.target.checked, ev.target),
  });
  if (!site.blocked) input.checked = true;
  return el('label', { class: 'switch', title: site.blocked ? '当前已关闭' : '当前放行中' },
    [input, el('span')]);
}

function formatDiag(diag) {
  const lines = [];
  if (diag.geo) {
    lines.push('GeoIP         ' + (diag.geo.available ? '离线库可用' : '不可用'));
    lines.push('GeoIP 缓存    ' + diag.geo.cached + ' 个地址（命中 ' + diag.geo.hits
      + ' / 未命中 ' + diag.geo.misses + '）');
  }
  if (diag.tailer) {
    lines.push('日志采集      已跟踪 ' + diag.tailer.tracked + ' 个日志文件 · 解析 '
      + diag.tailer.events + ' 条事件 · 丢弃 ' + diag.tailer.bad + ' 行');
  }
  lines.push('会话 / 订阅   ' + diag.sessions + ' 个会话 · ' + diag.subscribers + ' 个实时订阅');
  if (diag.sites) {
    lines.push('站点开关      ' + diag.sites.total + ' 个站点 · 关闭 ' + diag.sites.blocked
      + ' · 缺少注入 ' + diag.sites.missing_include);
  }
  lines.push('审计文件      ' + diag.audit_file);
  if (diag.config && diag.config.panels) {
    lines.push('后台入口      ' + diag.config.panels.length + ' 个');
  }
  return lines.join('\n');
}

/* ── sites ────────────────────────────────────────────────── */

async function loadSites() {
  try {
    const data = await api('/sites');
    app.sites = data.sites || [];
    renderSites();
    renderOverviewSites();
    const deny = data.deny_list || {};
    dom.denyNote.textContent = deny.count + ' 条规则 · ' + deny.path;
    dom.denyList.textContent = (deny.entries || []).join('\n') || '（当前为空）';
  } catch (err) {
    if (guard(err)) return;
    toast('站点列表加载失败：' + err.message, 'error');
  }
}

function renderSites() {
  const body = dom.sitesTable;
  body.innerHTML = '';
  if (!app.sites.length) {
    body.appendChild(el('tr', { class: 'empty' }, [el('td', { colspan: '6', text: '没有发现站点' })]));
    return;
  }
  app.sites.forEach((site) => {
    body.appendChild(el('tr', {}, [
      el('td', {}, [
        el('div', { class: 'mono', text: site.primary }),
        el('div', { class: 'note', text: (site.names || []).slice(1).join('  ') || '' }),
      ]),
      el('td', {}, [el('span', {
        class: 'badge ' + (site.blocked ? 'off' : 'on'),
        text: site.blocked ? '已关闭' : '放行中',
      })]),
      el('td', {}, [
        el('span', { class: 'badge info', text: site.ssl ? 'HTTPS' : 'HTTP' }),
        site.include_ok ? null : el('span', {
          class: 'badge warn', text: '待注入开关',
          title: '首次切换时会自动写入 include',
        }),
      ]),
      el('td', { class: 'path', title: site.root, text: site.root || '—' }),
      el('td', { class: 'mono', title: site.log, text: (site.log || '').split('/').pop() }),
      el('td', {}, [switchNode(site)]),
    ]));
  });
}

async function toggleSite(site, open, input) {
  const blocked = !open;
  if (blocked && !(await confirmSite(site))) {
    input.checked = true;
    return;
  }
  input.disabled = true;
  try {
    const res = await api('/sites/switch', {
      method: 'POST',
      body: { key: site.key, blocked: blocked, note: '控制台切换' },
    });
    toast(site.primary + (blocked ? ' 已关闭' : ' 已放行')
      + (res.reloaded ? '，nginx 已重载' : '，但 nginx 未重载，请手动检查'),
      res.reloaded ? 'ok' : 'error', 5000);
    await loadSites();
    loadOverview();
  } catch (err) {
    if (guard(err)) return;
    toast('切换失败：' + err.message, 'error', 7000);
    dom.nginxResult.hidden = false;
    dom.nginxResult.classList.add('bad');
    dom.nginxResult.textContent = (err.message || '') + '\n' + (err.detail || '');
    input.checked = !input.checked;
  } finally {
    input.disabled = false;
  }
}

function confirmSite(site) {
  return new Promise((resolve) => {
    const host = dom.modal;
    host.hidden = false;
    host.innerHTML = '';
    const close = (value) => {
      host.hidden = true;
      host.innerHTML = '';
      resolve(value);
    };
    const box = el('div', { class: 'modal' }, [
      el('h3', { text: '关闭站点：' + site.primary }),
      el('p', { text: '关闭后该域名的所有访问都会收到 nginx 的 403，包括你自己。确认继续？' }),
      el('p', { class: 'note', text: '根目录：' + (site.root || '—') }),
      el('div', { class: 'modal-actions' }, [
        el('button', { class: 'btn ghost', text: '取消', onclick: () => close(false) }),
        el('button', { class: 'btn danger', text: '确认关闭', onclick: () => close(true) }),
      ]),
    ]);
    host.appendChild(box);
    host.addEventListener('click', (ev) => { if (ev.target === host) close(false); });
    requestAnimationFrame(() => box.classList.add('in'));
  });
}

async function testNginx() {
  dom.nginxResult.hidden = false;
  dom.nginxResult.classList.remove('bad');
  dom.nginxResult.textContent = '校验中…';
  try {
    const res = await api('/sites/test', { method: 'POST' });
    dom.nginxResult.classList.toggle('bad', !res.valid);
    dom.nginxResult.textContent = (res.valid ? 'nginx 配置有效 ✓\n' : 'nginx 配置存在问题 ✗\n')
      + (res.detail || '');
  } catch (err) {
    dom.nginxResult.classList.add('bad');
    dom.nginxResult.textContent = '校验请求失败：' + err.message;
  }
}

/* ── quick links ──────────────────────────────────────────── */

async function loadPanels() {
  try {
    const data = await api('/panels');
    dom.panelGrid.innerHTML = '';
    (data.panels || []).forEach((panel) => {
      const external = /^https?:/i.test(panel.url);
      dom.panelGrid.appendChild(el('a', {
        class: 'panel-link',
        href: panel.url,
        target: external ? '_blank' : '_self',
        rel: 'noopener',
      }, [
        el('div', { class: 'pl-top' }, [
          el('span', { class: 'pl-name', text: panel.name }),
          el('span', { class: 'pl-group', text: panel.group || '' }),
        ]),
        el('div', { class: 'pl-desc', text: panel.desc || '' }),
        el('div', { class: 'pl-url', text: panel.url }),
      ]));
    });
  } catch (err) {
    if (guard(err)) return;
    toast('后台入口加载失败：' + err.message, 'error');
  }
}

/* Local (loopback-only) services, from the backend's `local_services` list.
   They used to be five hard-coded rows in admin.html, which meant every
   deployment published whichever services one machine happened to run. */
async function loadServices() {
  if (!dom.servicesBody) return;
  try {
    const data = await api('/services');
    const rows = data.services || [];
    dom.servicesBody.innerHTML = '';
    rows.forEach((svc) => {
      dom.servicesBody.appendChild(el('tr', {}, [
        el('td', { text: svc.name || '' }),
        el('td', { class: 'mono', text: svc.url || '' }),
        el('td', { text: svc.note || '' }),
      ]));
    });
    if (!rows.length) {
      dom.servicesBody.appendChild(el('tr', {}, [
        el('td', { text: '—' }),
        el('td', { class: 'mono', text: '' }),
        el('td', { text: '未配置（config.json 的 local_services）' }),
      ]));
    }
  } catch (err) {
    if (guard(err)) return;
    toast('本地服务列表加载失败：' + err.message, 'error');
  }
}

/* ── audit ────────────────────────────────────────────────── */

async function loadAudit() {
  try {
    const data = await api('/audit?limit=200');
    dom.auditFile.textContent = data.log;
    const body = dom.auditTable;
    body.innerHTML = '';
    if (!data.events.length) {
      body.appendChild(el('tr', { class: 'empty' }, [el('td', { colspan: '6', text: '暂无记录' })]));
      return;
    }
    data.events.forEach((item) => {
      body.appendChild(el('tr', {}, [
        el('td', { class: 'mono', text: item.at || stamp(item.t) }),
        el('td', {}, [el('span', { class: 'badge info', text: item.action })]),
        el('td', { class: 'path', title: item.target, text: item.target || '—' }),
        el('td', { class: 'mono', text: item.ip || '—' }),
        el('td', {}, [el('span', {
          class: 'badge ' + (item.ok ? 'on' : 'off'), text: item.ok ? '成功' : '失败',
        })]),
        el('td', { class: 'path', title: item.detail, text: item.detail || '' }),
      ]));
    });
  } catch (err) {
    if (guard(err)) return;
    toast('审计加载失败：' + err.message, 'error');
  }
}

/* ── system ───────────────────────────────────────────────── */

async function loadDiagnostics() {
  try {
    const diag = await api('/diagnostics');
    if (dom.diagFull) dom.diagFull.textContent = JSON.stringify(diag, null, 2);
    dom.diagNote.textContent = '更新于 ' + clock();
  } catch (err) {
    if (guard(err)) return;
    if (dom.diagFull) dom.diagFull.textContent = '自检失败：' + err.message;
  }
}

async function loadResources() {
  try {
    const res = await api('/resources');
    if (!dom.sysCards) return;
    const cpu = res.cpu || {};
    const mem = res.memory || {};
    const root = ((res.disk || {}).mounts || []).find((m) => m.mount === '/') || {};
    dom.sysCards.innerHTML = '';
    dom.sysCards.appendChild(metric('CPU', pct(cpu.percent || 0),
      cpu.info ? cpu.info.cores + ' 核' : ''));
    dom.sysCards.appendChild(metric('内存', pct(mem.percent || 0), bytes(mem.used)));
    dom.sysCards.appendChild(metric('硬盘', pct(root.percent || 0), bytes(root.used)));
    dom.sysCards.appendChild(metric('运行时间', (res.uptime && res.uptime.text) || '—', ''));
    dom.sysNote.textContent = '更新于 ' + clock();
  } catch (_) { /* the interval keeps trying */ }
}

/* ── file manager ─────────────────────────────────────────── */

function wireFileManager() {
  dom.fmGo.addEventListener('click', () => loadFiles(dom.fmPath.value.trim() || '/'));
  dom.fmPath.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') loadFiles(dom.fmPath.value.trim() || '/');
  });
  dom.fmRefresh.addEventListener('click', () => loadFiles(app.path));
  dom.fmHome.addEventListener('click', () => loadFiles('/'));
  dom.fmUp.addEventListener('click', () => {
    const parent = app.path.replace(/\/[^/]+\/?$/, '') || '/';
    loadFiles(parent || '/');
  });
  dom.fmHidden.addEventListener('change', () => loadFiles(app.path));
  dom.fmSearch.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') searchFiles();
  });
  dom.fmSave.addEventListener('click', saveFile);
  dom.fmDownload.addEventListener('click', () => {
    if (!app.file) return;
    window.location.href = '/api/v1/fs/download?path=' + encodeURIComponent(app.file.path);
  });
  dom.fmClose.addEventListener('click', () => { dom.fmEditor.hidden = true; app.file = null; });

  dom.fmMkdir.addEventListener('click', async () => {
    const name = window.prompt('新目录名称', 'new-folder');
    if (!name) return;
    try {
      await api('/fs/mkdir', { method: 'POST', body: { path: join(name) } });
      toast('目录已创建', 'ok');
      loadFiles(app.path);
    } catch (err) {
      if (guard(err)) return;
      toast('创建失败：' + err.message, 'error');
    }
  });

  dom.fmNewfile.addEventListener('click', async () => {
    const name = window.prompt('新文件名称', 'untitled.txt');
    if (!name) return;
    const path = join(name);
    try {
      await api('/fs/write', { method: 'POST', body: { path: path, content: '' } });
      toast('文件已创建', 'ok');
      await loadFiles(app.path);
      openFile(path);
    } catch (err) {
      if (guard(err)) return;
      toast('创建失败：' + err.message, 'error');
    }
  });

  dom.fmDelete.addEventListener('click', async () => {
    const paths = Array.from(app.selected);
    if (!paths.length) { toast('先勾选要删除的项目', 'error'); return; }
    try {
      if (await confirmedDelete(paths, paths.length === 1 ? paths[0] : null)) {
        toast('已删除 ' + paths.length + ' 项', 'ok');
        loadFiles(app.path);
      }
    } catch (err) {
      if (guard(err)) return;
      toast('删除失败：' + err.message, 'error');
    }
  });

  dom.fmUploadBtn.addEventListener('click', () => dom.fmUpload.click());
  dom.fmUpload.addEventListener('change', async () => {
    const files = Array.from(dom.fmUpload.files || []);
    dom.fmUpload.value = '';
    if (!files.length) return;
    dom.fmProgress.hidden = false;
    const bar = dom.fmProgress.querySelector('i');
    const label = dom.fmProgress.querySelector('span');
    let done = 0;
    for (const file of files) {
      try {
        await uploadOne(file, (loaded, total) => {
          const overall = ((done + loaded / total) / files.length) * 100;
          bar.style.width = overall.toFixed(1) + '%';
          label.textContent = '上传 ' + file.name + ' · ' + bytes(loaded) + ' / ' + bytes(total);
        });
        done += 1;
        toast('已上传 ' + file.name, 'ok');
      } catch (err) {
        if (guard(err)) break;
        toast('上传失败 ' + file.name + '：' + err.message, 'error', 6000);
      }
    }
    dom.fmProgress.hidden = true;
    bar.style.width = '0%';
    loadFiles(app.path);
  });

  ['dragover', 'drop'].forEach((type) => {
    dom.fmList.addEventListener(type, (ev) => {
      ev.preventDefault();
      if (type !== 'drop') {
        dom.fmList.style.outline = '2px dashed var(--blue)';
        return;
      }
      dom.fmList.style.outline = '';
      if (!ev.dataTransfer || !ev.dataTransfer.files || !ev.dataTransfer.files.length) return;
      dom.fmUpload.files = ev.dataTransfer.files;
      dom.fmUpload.dispatchEvent(new Event('change'));
    });
  });
  dom.fmList.addEventListener('dragleave', () => { dom.fmList.style.outline = ''; });
}

function join(name) {
  return app.path.replace(/\/$/, '') + '/' + name;
}

async function loadFiles(path) {
  try {
    const data = await api('/fs/list?path=' + encodeURIComponent(path)
      + '&hidden=' + (dom.fmHidden.checked ? '1' : '0'));
    app.path = data.path;
    dom.fmPath.value = data.path;
    app.selected.clear();
    renderList(data);
  } catch (err) {
    if (guard(err)) return;
    toast('目录读取失败：' + err.message, 'error');
  }
}

function fileIcon(entry) {
  if (entry.kind === 'dir') return '📁';
  const name = entry.name.toLowerCase();
  if (/\.(png|jpe?g|gif|webp|svg|ico|bmp)$/.test(name)) return '🖼️';
  if (/\.(mp4|mkv|mov|webm|avi)$/.test(name)) return '🎬';
  if (/\.(mp3|wav|flac|ogg|m4a)$/.test(name)) return '🎵';
  if (/\.(zip|tar|gz|tgz|bz2|xz|7z|rar)$/.test(name)) return '🗜️';
  if (/\.(js|ts|py|php|sh|go|rs|c|h|cpp|java|lua|rb|pl|json|ya?ml|toml|ini|conf|css|html?)$/.test(name)) return '📜';
  if (entry.link) return '🔗';
  return '📄';
}

function renderList(data) {
  dom.fmList.innerHTML = '';
  if (!data.entries.length) {
    dom.fmList.appendChild(el('div', { class: 'fm-empty', text: '（空目录）' }));
  }
  data.entries.forEach((entry) => {
    const row = el('div', {
      class: 'fm-row' + (entry.kind === 'dir' ? ' dir' : ''),
      onclick: () => (entry.kind === 'dir' ? loadFiles(entry.path) : openFile(entry.path)),
    }, [
      el('div', { class: 'fm-icon' }, [
        el('input', {
          type: 'checkbox',
          onclick: (ev) => {
            ev.stopPropagation();
            if (ev.target.checked) app.selected.add(entry.path);
            else app.selected.delete(entry.path);
            row.classList.toggle('sel', ev.target.checked);
          },
        }),
      ]),
      el('div', {
        class: 'fm-name',
        title: entry.name + (entry.target ? ' -> ' + entry.target : ''),
        text: fileIcon(entry) + ' ' + entry.name,
      }),
      el('div', { class: 'fm-size', text: entry.kind === 'dir' ? '—' : bytes(entry.size) }),
      el('div', { class: 'fm-time', text: stamp(entry.mtime) }),
      el('div', { class: 'fm-mode', text: entry.mode + (entry.ro ? ' 🔒' : '') }),
    ]);
    dom.fmList.appendChild(row);
  });
  dom.fmStat.textContent = data.count + ' 项 · ' + data.path;
  dom.fmDisk.textContent = data.usage
    ? '磁盘 ' + pct(data.usage.percent) + ' 已用 · 剩余 ' + bytes(data.usage.free)
    : '';
  dom.fmUp.disabled = data.path === '/';
}

async function openFile(path) {
  try {
    const data = await api('/fs/read?path=' + encodeURIComponent(path));
    app.file = data;
    dom.fmEditor.hidden = false;
    dom.fmFileName.textContent = data.path;
    dom.fmFileMeta.textContent = bytes(data.size) + ' · ' + data.mode + ' · '
      + data.owner + ' · ' + stamp(data.mtime) + (data.binary ? ' · 二进制预览' : '');
    dom.fmBox.value = data.binary
      ? ('（二进制文件，显示前 512 字节十六进制）\n\n' + data.hex)
      : data.content;
    dom.fmBox.readOnly = !!data.binary;
    dom.fmSave.disabled = !!data.binary;
    dom.fmEditorHint.textContent = data.truncated
      ? '文件较大，只载入了前 4 MiB；保存会覆盖整个文件，请谨慎。'
      : '保存前会在同目录留一份 .vigilbak.* 备份（最多 5 份）。';
  } catch (err) {
    if (guard(err)) return;
    toast('读取失败：' + err.message, 'error');
  }
}

async function saveFile() {
  if (!app.file) return;
  try {
    const res = await api('/fs/write', {
      method: 'POST',
      body: { path: app.file.path, content: dom.fmBox.value },
    });
    toast('已保存 ' + res.path + '（' + bytes(res.bytes) + '）', 'ok');
    loadFiles(app.path);
  } catch (err) {
    if (guard(err)) return;
    toast('保存失败：' + err.message, 'error');
  }
}

async function searchFiles() {
  const query = dom.fmSearch.value.trim();
  if (!query) { loadFiles(app.path); return; }
  try {
    const data = await api('/fs/search?path=' + encodeURIComponent(app.path)
      + '&q=' + encodeURIComponent(query)
      + '&content=' + (dom.fmContent.checked ? '1' : '0'));
    dom.fmList.innerHTML = '';
    dom.fmStat.textContent = '搜索 “' + query + '” 命中 ' + data.count + ' 项'
      + (data.truncated ? '（已截断）' : '') + ' · 用时 ' + data.elapsed + 's';
    if (!data.count) {
      dom.fmList.appendChild(el('div', { class: 'fm-empty', text: '没有命中' }));
      return;
    }
    data.hits.forEach((hit) => {
      dom.fmList.appendChild(el('div', {
        class: 'fm-row',
        onclick: () => (hit.kind === 'dir' ? loadFiles(hit.path) : openFile(hit.path)),
      }, [
        el('div', { class: 'fm-icon', text: hit.kind === 'dir' ? '📁' : '📄' }),
        el('div', {
          class: 'fm-name',
          title: hit.path,
          text: hit.kind === 'file' && hit.line
            ? (hit.path + ':' + hit.line + '  ' + (hit.text || ''))
            : hit.path,
        }),
        el('div', { class: 'fm-size', text: hit.size ? bytes(hit.size) : '' }),
        el('div', { class: 'fm-time', text: '' }),
        el('div', { class: 'fm-mode', text: '' }),
      ]));
    });
  } catch (err) {
    if (guard(err)) return;
    toast('搜索失败：' + err.message, 'error');
  }
}

/* XHR rather than fetch: upload progress events are what make a large
   transfer on a slow link tolerable to watch. */
function uploadOne(file, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    const url = '/api/v1/fs/upload?path=' + encodeURIComponent(app.path)
      + '&name=' + encodeURIComponent(file.name);
    xhr.open('POST', url, true);
    xhr.setRequestHeader('X-Vigil-Token', getAuthToken() || getCsrf());
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    xhr.upload.addEventListener('progress', (ev) => {
      if (ev.lengthComputable) onProgress(ev.loaded, ev.total);
    });
    xhr.addEventListener('load', () => {
      let payload = null;
      try { payload = JSON.parse(xhr.responseText); } catch (_) { payload = null; }
      if (xhr.status >= 200 && xhr.status < 300 && payload && payload.ok) resolve(payload.data);
      else reject(new Error((payload && payload.error) || ('HTTP ' + xhr.status)));
    });
    xhr.addEventListener('error', () => reject(new Error('网络错误')));
    xhr.send(file);
  });
}

boot();
