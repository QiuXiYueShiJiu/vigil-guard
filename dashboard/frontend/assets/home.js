/* ──────────────────────────────────────────────────────────────
   vigil console · home page behaviour

   Load order matters and is deliberate:

     1. paint the shell from HTML (instant, no JS needed);
     2. fetch /api/v1/state and fill every number -- small payload;
     3. fetch the map data in parallel and start drawing when it lands.

   The map is the biggest asset on the page, so nothing waits for it:
   if it takes two seconds on a phone, the numbers are already on
   screen and a spinner sits where the plate will be.
   ────────────────────────────────────────────────────────────── */
'use strict';

import {
  api, bytes, clock, drawSeries, duration, el, flag, num, pct, rate,
} from './core.js';
import { FlatMap, LEVEL_STYLE } from './map.js';

const dom = {
  live: document.getElementById('live-indicator'),
  liveText: document.getElementById('live-text'),
  clock: document.getElementById('clock'),
  kpiHost: document.getElementById('kpi-host'),
  kpiLoc: document.getElementById('kpi-loc'),
  kpiTotal: document.getElementById('kpi-total'),
  kpiRpm: document.getElementById('kpi-rpm'),
  kpiBans: document.getElementById('kpi-bans'),
  kpiBansSub: document.getElementById('kpi-bans-sub'),
  kpiPosture: document.getElementById('kpi-posture'),
  kpiPostureSub: document.getElementById('kpi-posture-sub'),
  kpiLoad: document.getElementById('kpi-load'),
  kpiUptime: document.getElementById('kpi-uptime'),
  kpiEpm: document.getElementById('kpi-epm'),
  kpiSub: document.getElementById('kpi-sub'),
  cnt: [document.getElementById('cnt-0'), document.getElementById('cnt-1'), document.getElementById('cnt-2')],
  cntLive: document.getElementById('cnt-live'),
  cntZoom: document.getElementById('cnt-zoom'),
  mapFit: document.getElementById('map-fit'),
  stream: document.getElementById('stream'),
  streamNote: document.getElementById('stream-note'),
  attackTable: document.querySelector('#attack-table tbody'),
  existingTable: document.querySelector('#existing-table tbody'),
  existingNote: document.getElementById('existing-note'),
  attackNote: document.getElementById('attack-note'),
  countries: document.getElementById('countries'),
  distNote: document.getElementById('dist-note'),
  trend: document.getElementById('trend-canvas'),
  trendNote: document.getElementById('trend-note'),
  procs: document.getElementById('procs'),
  guardNote: document.getElementById('guard-note'),
  readout: document.getElementById('readout'),
  roTitle: document.getElementById('ro-title'),
  roBody: document.getElementById('ro-body'),
  mapSub: document.getElementById('map-sub'),
  mapLoading: document.getElementById('map-loading'),
  resNote: document.getElementById('res-note'),
  footStatus: document.getElementById('foot-status'),
  adminEntry: document.getElementById('admin-entry'),
  mapPause: document.getElementById('map-pause'),
  zoomIn: document.getElementById('zoom-in'),
  zoomOut: document.getElementById('zoom-out'),

  cpuPct: document.getElementById('cpu-pct'),
  cpuSpark: document.getElementById('cpu-spark'),
  cpuModel: document.getElementById('cpu-model'),
  cpuCores: document.getElementById('cpu-cores'),
  cpuLoad: document.getElementById('cpu-load'),
  cpuTemp: document.getElementById('cpu-temp'),
  memPct: document.getElementById('mem-pct'),
  memBar: document.getElementById('mem-bar'),
  memUsed: document.getElementById('mem-used'),
  memTotal: document.getElementById('mem-total'),
  memCached: document.getElementById('mem-cached'),
  memSwap: document.getElementById('mem-swap'),
  diskPct: document.getElementById('disk-pct'),
  diskBar: document.getElementById('disk-bar'),
  diskUsed: document.getElementById('disk-used'),
  diskTotal: document.getElementById('disk-total'),
  diskRead: document.getElementById('disk-read'),
  diskWrite: document.getElementById('disk-write'),
  netTotal: document.getElementById('net-total'),
  netSpark: document.getElementById('net-spark'),
  netRx: document.getElementById('net-rx'),
  netTx: document.getElementById('net-tx'),
  netIf: document.getElementById('net-if'),
  netUptime: document.getElementById('net-uptime'),
};

const state = {
  levels: { 0: 0, 1: 0, 2: 0 },
  counted: false,
  minuteSeries: [],
  countries: {},
  sites: {},
  latest: null,
  series: [],
  paused: false,
};

// Building the map touches the canvas and installs listeners; if any of that
// throws, the page would otherwise just sit there with a blank plate.
let map;
try {
  map = new FlatMap(document.getElementById('world-canvas'), {
    pulse: true,
    onFrame: (stats) => {
      dom.cntLive.textContent = num(stats.traces);
      if (dom.cntZoom) dom.cntZoom.textContent = stats.zoom.toFixed(2) + '×';
    },
    onSelect: (event) => { if (event) showReadout(event); },
  });
} catch (err) {
  // A stub that satisfies the rest of boot(); every call is a no-op.
  map = {
    opts: { server: {} }, ready: false, meta: {},
    load: async () => { throw err; }, adopt: () => {}, setServer() {},
    flyTo() {}, zoomBy() {}, start() {}, stop() {}, push: () => false,
  };
  setTimeout(() => showMapError('init', err.message), 0);
}

/* ── boot ─────────────────────────────────────────────────── */

async function boot() {
  wireControls();
  dom.clock.textContent = clock();
  setInterval(() => { dom.clock.textContent = clock(); }, 1000);
  drawTrend();

  // Numbers first: one request with no history array, no dependency on the
  // map. The stream delivers the recent events a moment later, and the map
  // is redrawn from them anyway.
  try {
    const snap = await api('/state?attacks=1');
    applySnapshot(snap);
    setLive(true, '实时链路已建立');
  } catch (err) {
    setLive(false, '数据接口不可用');
    dom.footStatus.textContent = '接口错误：' + err.message;
  }
  connect();

  // Report measured frame cost to the service, so "it feels slow" becomes a
  // number in the diagnostics instead of a guess.
  window.__vigilMapStats = (stats) => {
    api('/clientlog', {
      method: 'POST',
      body: { page: 'home', kind: 'map-perf', detail: JSON.stringify(stats) },
    }).catch(() => {});
  };

  // Resource panel: the stream pushes a sample every couple of seconds, but
  // the first one is up to a sample interval away and the panel would sit on
  // dashes until then. One small request fills it immediately.
  api('/resources').then(applyResources).catch(() => {});

  // Map last, in the background. Nothing above waits on it.
  loadMap();
}

async function loadMap() {
  let doc = null;
  try {
    doc = await map.load('/assets/world.json');
  } catch (first) {
    // A stale cached copy of the data is the single most likely cause of a
    // decode failure, and it costs one request to rule out. Retry with the
    // cache bypassed before telling the operator anything.
    try {
      doc = await map.load('/assets/world.json', true);
      dom.footStatus.textContent = '已重新获取地图数据（本地缓存副本已失效）';
    } catch (second) {
      showMapError(second.kind === 'network' ? 'network' : 'data', second.message);
      return;
    }
  }
  try {
    // Whole world first, so nothing is cropped on arrival. The regional
    // presets are one click away and zoom in on purpose.
    map.flyTo('world');
    map.start();
    dom.mapLoading.classList.add('gone');
    dom.mapSub.textContent = '数据源：nginx 访问日志 + vigil 实时风控 · '
      + num((doc.meta || {}).points) + ' 个坐标点';
    // Backfill so the plate is not empty on arrival. Fetched only once the
    // map can actually draw, so the wait overlaps the download.
    try {
      const back = await api('/state?history=90');
      // Replay only what is actually recent. The history ring keeps the last
      // few minutes and is handed out in full to every new page, so replaying
      // it verbatim made a ban from earlier reappear as a fresh strike on
      // every refresh -- the complaint that the map "still shows fake sources"
      // long after the attack itself ended.
      const cutoff = Date.now() / 1000 - REPLAY_WINDOW;
      const fresh = (back.history || []).filter((ev) => (ev.nt || ev.t || 0) >= cutoff);
      fresh.forEach((ev) => { const e = normalise(ev); map.push(e); addRow(e); });
      if (!fresh.length) {
        const skipped = (back.history || []).length;
        dom.streamNote.textContent = skipped
          ? '等待新事件（' + skipped + ' 条较早记录未回放）'
          : '等待新事件';
      }
    } catch (_) { /* the live stream will fill it */ }
  } catch (err) {
    showMapError('render', err.message);
  }
}

/* A map that fails to load must say why, on screen, and leave a trace on the
   server: a failure that only reproduces on one device is otherwise
   impossible to diagnose. */
function showMapError(kind, message) {
  const hint = kind === 'network'
    ? '检查 /assets/world.json 是否可访问。'
    : '把这条信息发我，或在服务器执行 vigil-dash mapcheck。';
  dom.mapLoading.classList.remove('gone');
  dom.mapLoading.innerHTML = '<span>地图加载失败：' + message + ' ' + hint + '</span>';
  dom.mapSub.textContent = '地图数据不可用';
  api('/clientlog', {
    method: 'POST',
    body: { page: 'home', kind: 'map-' + kind, detail: String(message).slice(0, 500) },
  }).catch(() => {});
}

function wireControls() {
  document.querySelectorAll('[data-view]').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('[data-view]').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      map.flyTo(btn.dataset.view);
    });
  });
  const first = document.querySelector('[data-view="world"]');
  if (first) first.classList.add('active');

  dom.zoomIn.addEventListener('click', () => map.zoomBy(1.5));
  dom.zoomOut.addEventListener('click', () => map.zoomBy(1 / 1.5));
  dom.mapPause.addEventListener('click', () => {
    state.paused = !state.paused;
    dom.mapPause.classList.toggle('active', state.paused);
    dom.mapPause.textContent = state.paused ? '继续' : '暂停';
    if (state.paused) map.stop();
    else map.start();
  });
  if (dom.mapFit) {
    dom.mapFit.addEventListener('click', () => {
      map.fitWorld();
      document.querySelectorAll('.chip[data-view]').forEach((c) => {
        c.classList.toggle('active', c.dataset.view === 'world');
      });
    });
  }
  dom.adminEntry.addEventListener('click', (ev) => {
    ev.preventDefault();
    window.location.href = '/admin.html';
  });
}

/* ── live stream ──────────────────────────────────────────── */

let source = null;
let retries = 0;

function connect() {
  if (source) source.close();
  source = new EventSource('/api/v1/stream');
  source.addEventListener('open', () => { retries = 0; setLive(true, '实时链路已建立'); });
  source.addEventListener('error', () => {
    setLive(false, '链路重连中…');
    retries += 1;
    if (retries > 8) { source.close(); setTimeout(connect, 5000); }
  });
  source.addEventListener('hello', (ev) => {
    const data = JSON.parse(ev.data);
    if (data.server) {
      map.setServer({ lat: data.server.lat, lon: data.server.lon });
    }
  });
  source.addEventListener('traffic', (ev) => {
    const item = JSON.parse(ev.data);
    // Same window as the HTTP backfill: a replayed buffer entry must not be
    // drawn as a live mark.
    const stamp = item.nt || item.t || 0;
    if (stamp && Date.now() / 1000 - stamp > REPLAY_WINDOW) {
      state.skipped = (state.skipped || 0) + 1;
      return;
    }
    onTraffic(item);
  });
  source.addEventListener('resources', (ev) => applyResources(JSON.parse(ev.data)));
  source.addEventListener('summary', (ev) => applySummary(JSON.parse(ev.data)));
  source.addEventListener('ping', () => setLive(true, '实时链路已建立'));
}

function setLive(ok, text) {
  dom.live.classList.toggle('offline', !ok);
  dom.liveText.textContent = text;
}

/* ── traffic ──────────────────────────────────────────────── */

const rows = [];

/* How much of the history ring may be replayed as marks.

   Deliberately short. The ring holds a couple of minutes of events and is
   handed to every new page, and a window wide enough to "fill the list" will
   happily surface an unrelated probe that happened while nobody was looking
   -- which is how a scanner that visits twice a day appeared to be a new
   visitor on every refresh. Ten seconds is enough to cover the gap between
   the snapshot and the stream connecting; anything older is history, and the
   page says so instead of drawing it. */
const REPLAY_WINDOW = 10;

/* The service sends short field names (co/ci/op) because these objects are
   repeated hundreds of times per page load. Older cached builds may still
   send the long ones, so both are accepted. */

/* What a source is called on screen.

   A visitor who is just browsing is identified by where they are, not by who
   they are: the service sends no address for normal traffic, so there is
   nothing here to leak. An attack keeps its address -- identifying it is the
   point of that row -- and `ip` is absent for everything else. */
function labelOf(item) {
  if (!item) return '—';
  if (item.ip) return item.ip;
  const place = [item.ci, item.co].filter(Boolean).join(' · ');
  return place || (item.cc && item.cc !== '--' ? item.cc : '未知位置');
}

function normalise(item) {
  if (!item) return item;
  if (!item.co && item.country) item.co = item.country;
  if (!item.ci && item.city) item.ci = item.city;
  if (!item.op && item.operator) item.op = item.operator;
  return item;
}

function onTraffic(raw) {
  const item = normalise(raw);
  // Test observability: records what was treated as live. Harmless in the
  // browser and the only way to assert the replay window from Node.
  if (typeof window !== 'undefined') {
    (window.__mapPushed = window.__mapPushed || []).push(item.id || item.ip);
  }
  // Belt and braces: the service already drops requests that only exist
  // because someone is using a control panel, but an event replayed from an
  // older buffer must not leak the path either.
  if (item.q) return;
  map.push(item);
  // Deliberately no local tallying. The server counts the same events and
  // ships the totals every couple of seconds; counting here as well made the
  // numbers jump between a local delta and a server total, and there is no
  // reason for the browser to redo an addition the server already did.
  addRow(item);
  if (item.lv > 0) addAttack(item);
  showReadout(item);
}

function statusClass(code) {
  if (code >= 500) return 'bad';
  if (code >= 400) return 'warn';
  return '';
}

function addRow(item) {
  const row = el('div', { class: 'ev lv' + item.lv }, [
    el('span', { class: 'ev-time', text: clock(item.t) }),
    el('span', { class: 'ev-flag', text: flag(item.cc) }),
    el('span', { class: 'ev-main' }, [
      el('b', { class: 'ev-ip', text: labelOf(item) }),
      ' ' + (item.ci ? item.ci + ' ' : '') + (item.co || ''),
      el('span', { class: 'ev-path', text: '  ' + (item.m || 'GET') + ' ' + (item.p || '/') }),
    ]),
    el('span', { class: 'ev-right' }, [
      el('span', { class: 'ev-status ' + statusClass(item.s), text: String(item.s) }),
      item.lv ? el('span', {
        class: 'ev-badge ' + (item.lv === 2 ? 'black' : 'red'),
        text: levelLabel(item.lv),
      }) : null,
    ]),
  ]);
  dom.stream.insertBefore(row, dom.stream.firstChild);
  rows.push(row);
  while (rows.length > 90) {
    const dead = rows.shift();
    if (dead && dead.parentNode) dead.parentNode.removeChild(dead);
  }
}

function levelLabel(lv) { return (LEVEL_STYLE[lv] || LEVEL_STYLE[0]).label; }

function renderExistingBans(bans) {
  const body = dom.existingTable;
  if (!body) return;
  body.innerHTML = '';
  if (!bans.length) {
    body.appendChild(el('tr', { class: 'empty' }, [
      el('td', { colspan: '4', text: '账本中没有生效封禁' }),
    ]));
    set(dom.existingNote, '—');
    return;
  }
  bans.forEach((ban) => {
    body.appendChild(el('tr', {}, [
      el('td', { class: 'ip', text: ban.ip || '—' }),
      el('td', {}, [
        el('span', { class: 'flag-cell', text: flag(ban.cc) }),
        ' ' + (ban.co || '未知') + (ban.ci ? ' · ' + ban.ci : ''),
      ]),
      el('td', { class: 'reason', title: ban.reason || '', text: ban.reason || '封禁' }),
      el('td', { class: 'time', text: ban.until ? clock(ban.until) + ' 到期' : '—' }),
    ]));
  });
  set(dom.existingNote, num(bans.length) + ' 条 · 均为 vigil 风控判定');
}

function addAttack(item) {
  const row = el('tr', {}, [
    el('td', { class: 'ip', text: labelOf(item) }),
    el('td', {}, [
      el('span', { class: 'flag-cell', text: flag(item.cc) }),
      ' ' + (item.co || '未知') + (item.ci ? ' · ' + item.ci : ''),
    ]),
    el('td', { class: 'reason', title: item.why || '', text: item.why || '攻击' }),
    el('td', { class: 'time', text: clock(item.t) }),
  ]);
  const empty = dom.attackTable.querySelector('.empty');
  if (empty) empty.parentNode.removeChild(empty);
  dom.attackTable.insertBefore(row, dom.attackTable.firstChild);
  while (dom.attackTable.children.length > 50) {
    dom.attackTable.removeChild(dom.attackTable.lastChild);
  }
  dom.attackNote.textContent = '最近 ' + dom.attackTable.children.length + ' 条';
}

let legendKey = '';
function updateLegend() {
  const key = state.levels[0] + '|' + state.levels[1] + '|' + state.levels[2];
  if (key === legendKey) return;
  legendKey = key;
  dom.cnt[0].textContent = num(state.levels[0] || 0);
  dom.cnt[1].textContent = num(state.levels[1] || 0);
  dom.cnt[2].textContent = num(state.levels[2] || 0);
}

function showReadout(event) {
  if (!event) return;
  state.latest = event;
  dom.roTitle.textContent = flag(event.cc) + ' ' + (event.co || '未知')
    + (event.ci ? ' · ' + event.ci : '');
  dom.roBody.textContent = [
    labelOf(event) + (event.op ? '  ' + event.op : ''),
    (event.m || 'GET') + ' ' + (event.p || '/') + '  →  ' + event.s,
    event.lv ? (levelLabel(event.lv) + '：' + (event.why || '')) : '正常访问',
  ].join('\n');
  dom.readout.classList.toggle('hot', !!event.lv);
}

/* ── summary / resources ──────────────────────────────────── */

function applySnapshot(snap) {
  if (!snap) return;
  if (snap.server) {
    map.setServer({ lat: snap.server.lat, lon: snap.server.lon });
  }
  if (snap.resources) applyResources(snap.resources);
  if (snap.traffic) {
    state.levels = {
      0: (snap.traffic.levels && snap.traffic.levels.normal) || 0,
      1: (snap.traffic.levels && snap.traffic.levels.attack) || 0,
      2: (snap.traffic.levels && snap.traffic.levels.pressure) || 0,
    };
    state.counted = true;
    updateLegend();
  }
  applySummary({ traffic: snap.traffic, threat: snap.threat });
  if (snap.geo) {
    dom.footStatus.textContent = 'GeoIP ' + (snap.geo.available ? '离线库就绪' : '不可用')
      + ' · 已缓存 ' + num(snap.geo.cached) + ' 个地址';
  }
  // The live ban list, loaded once and labelled as history. Re-adding it on
  // every snapshot made the same two or three bans look like a fresh attack
  // on every page refresh.
  // Pre-existing bans go in their own table, never the live attack list.
  // Reloading them into "recent attacks" on every refresh made two hours-old
  // bans look like a fresh strike each time the page was opened.
  if (!state.bansLoaded) {
    state.bansLoaded = true;
    renderExistingBans((snap.threat && snap.threat.latest_bans) || []);
  }
}

function applySummary(summary) {
  if (!summary) return;
  const traffic = summary.traffic;
  if (traffic) {
    if (typeof traffic.total === 'number') dom.kpiTotal.textContent = num(traffic.total);
    if (typeof traffic.rpm === 'number') {
      dom.kpiRpm.textContent = num(traffic.rpm) + ' / 分钟';
    }
    // Computed on the server from a sliding 60s list. The page used to count
    // events itself, which drifted from the server's figure.
    if (typeof traffic.epm === 'number') {
      dom.kpiEpm.textContent = num(traffic.epm);
    }
    if (traffic.minute_series) { state.minuteSeries = traffic.minute_series; drawTrend(); }
    if (traffic.countries) { state.countries = Object.assign(state.countries, traffic.countries); renderCountries(); }
    if (traffic.local !== undefined) {
      dom.distNote.textContent = '外网 ' + num(traffic.total) + ' · 本机 ' + num(traffic.local);
    }
  }
  const threat = summary.threat;
  if (threat) {
    dom.kpiBans.textContent = num(threat.live_bans);
    dom.kpiBansSub.textContent = '累计 ' + num(threat.bans_total)
      + (threat.ledger_age !== null && threat.ledger_age !== undefined
        ? ' · 账本 ' + threat.ledger_age + 's' : '');
    applyPosture(threat.posture);
    // The note must describe the table it sits on. It used to report the
    // global live-ban count here, so an empty "new attacks" table carried a
    // number that made it look as though something had just happened.
    const rows = dom.attackTable ? dom.attackTable.children.length : 0;
    dom.attackNote.textContent = rows
      ? '本次访问期间 ' + num(rows) + ' 条'
      : '页面打开后暂无新攻击';
  }
}

function applyPosture(posture) {
  const active = posture && posture.active;
  dom.kpiPosture.textContent = active ? '已提升' : '常规';
  dom.kpiPosture.classList.toggle('danger', !!active);
  dom.kpiPostureSub.textContent = active
    ? '剩余 ' + duration(posture.remaining)
    : 'vigil 风控 · 无提升';
}

function applyResources(res) {
  if (!res) return;
  const cpu = res.cpu || {};
  const mem = res.memory || {};
  const disk = res.disk || {};
  const net = res.net || {};
  // Write only on change. Assigning the same string still costs a style
  // recalculation on some engines, and this panel is rebuilt 30 times a
  // minute with values that rarely move.
  const set = (node, value) => {
    if (node && node.textContent !== value) node.textContent = value;
  };

  set(dom.resNote, clock());

  if (res.system) {
    set(dom.kpiHost, '本机');
    set(dom.kpiLoc, res.system.os ? res.system.os.replace(/^[^ ]+ /, '') : '—');
  }
  if (cpu.load) {
    set(dom.kpiLoad, cpu.load['1'].toFixed(2));
    set(dom.kpiUptime, res.uptime && res.uptime.text ? '已运行 ' + res.uptime.text : '—');
  }

  const cpuPct = cpu.percent || 0;
  set(dom.cpuPct, pct(cpuPct));
  set(dom.cpuModel, (cpu.info && cpu.info.model) || '—');
  set(dom.cpuCores, cpu.info && cpu.info.cores ? cpu.info.cores + ' 核' : '');
  set(dom.cpuLoad, cpu.load
    ? [cpu.load['1'], cpu.load['5'], cpu.load['15']].map((x) => x.toFixed(2)).join(' / ')
    : '—');
  set(dom.cpuTemp, cpu.temp ? cpu.temp.toFixed(1) + '°C' : '—');

  const memPct = mem.percent || 0;
  set(dom.memPct, pct(memPct));
  if (dom.memBar) {
    dom.memBar.style.width = Math.min(100, memPct) + '%';
    dom.memBar.className = memPct > 90 ? 'danger' : memPct > 75 ? 'warn' : '';
  }
  set(dom.memUsed, '已用 ' + bytes(mem.used));
  set(dom.memTotal, '共 ' + bytes(mem.total));
  set(dom.memCached, bytes(mem.cached));
  set(dom.memSwap, mem.swap_total ? pct(mem.swap_percent, 0) + ' · ' + bytes(mem.swap_used) : '无');

  const root = (disk.mounts || []).find((m) => m.mount === '/') || (disk.mounts || [])[0];
  if (root) {
    set(dom.diskPct, pct(root.percent));
    if (dom.diskBar) {
      dom.diskBar.style.width = Math.min(100, root.percent) + '%';
      dom.diskBar.className = root.percent > 90 ? 'danger' : root.percent > 78 ? 'warn' : '';
    }
    set(dom.diskUsed, '已用 ' + bytes(root.used));
    set(dom.diskTotal, '共 ' + bytes(root.total));
  }
  const io = disk.io || {};
  const readRate = Object.keys(io).reduce((sum, key) => sum + io[key].read, 0);
  const writeRate = Object.keys(io).reduce((sum, key) => sum + io[key].write, 0);
  set(dom.diskRead, rate(readRate));
  set(dom.diskWrite, rate(writeRate));

  let rx = 0, tx = 0;
  Object.keys(net).forEach((key) => { rx += net[key].rx; tx += net[key].tx; });
  set(dom.netTotal, rate(rx + tx));
  set(dom.netRx, rate(rx));
  set(dom.netTx, rate(tx));
  set(dom.netIf, Object.keys(net).slice(0, 3).join(' · ') || '—');
  set(dom.netUptime, res.system && res.system.kernel ? '内核 ' + res.system.kernel : '');

  if (res.series) {
    state.series = res.series;
    // Two canvas clears + path builds per sample is the most expensive thing
    // in this function, and the shape barely moves in a second. Cap it.
    const now = performance.now();
    if (now - lastSpark > 1000) {
      lastSpark = now;
      drawSeries(dom.cpuSpark, res.series.map((s) => s.cpu),
        { max: 100, stroke: '#d2762e', glow: 'rgba(210,118,46,.45)', fill: 'rgba(210,118,46,.14)' });
      drawSeries(dom.netSpark, res.series.map((s) => s.rx + s.tx),
        { stroke: '#3a7a52', glow: 'rgba(58,122,82,.45)', fill: 'rgba(58,122,82,.14)' });
    }
  }
  renderProcs(res.processes || []);
}

let lastSpark = 0;
let procsKey = '';
function renderProcs(list) {
  // Rebuilding seven rows thirty times a minute for identical content is pure
  // layout churn; compare first.
  const key = list.slice(0, 7).map((r) => r.pid + ':' + r.cpu).join('|');
  if (key === procsKey) return;
  procsKey = key;
  dom.procs.innerHTML = '';
  if (!list.length) {
    dom.procs.appendChild(el('div', { class: 'mini-row' }, [el('span', { text: '暂无采样' })]));
    return;
  }
  list.slice(0, 7).forEach((row) => {
    dom.procs.appendChild(el('div', { class: 'mini-row' }, [
      el('span', { text: row.name, title: row.name + ' (PID ' + row.pid + ')' }),
      el('span', { class: 'v' + (row.cpu > 60 ? ' hot' : ''), text: pct(row.cpu) }),
      el('span', { class: 'm', text: '#' + row.pid }),
    ]));
  });
}

let countriesKey = '';
function renderCountries() {
  const key = Object.entries(state.countries).sort((a, b) => b[1] - a[1]).slice(0, 8)
    .map((p) => p[0] + ':' + p[1]).join('|');
  if (key === countriesKey) return;
  countriesKey = key;
  const entries = Object.entries(state.countries)
    .filter(([cc]) => cc && cc !== '--')
    .sort((a, b) => b[1] - a[1]).slice(0, 8);
  const max = entries.length ? entries[0][1] : 1;
  dom.countries.innerHTML = '';
  if (!entries.length) {
    dom.countries.appendChild(el('div', { class: 'empty', text: '暂无来源数据' }));
    return;
  }
  entries.forEach(([cc, count]) => {
    dom.countries.appendChild(el('div', { class: 'dist-row' }, [
      el('span', { class: 'flag-cell', text: flag(cc) }),
      el('span', {}, [
        el('span', { class: 'dist-name', text: cc }),
        el('span', { class: 'dist-bar' }, [el('i', { style: 'width:' + Math.max(4, (count / max) * 100) + '%' })]),
      ]),
      el('b', { text: num(count) }),
    ]));
  });
}



/* ── trend chart ──────────────────────────────────────────── */

function drawTrend() {
  const canvas = dom.trend;
  if (!canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth || 480;
  const h = canvas.clientHeight || 240;
  if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
    canvas.width = w * dpr; canvas.height = h * dpr;
  }
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);

  const data = state.minuteSeries.length ? state.minuteSeries : new Array(12).fill(0);
  const max = Math.max(4, Math.max.apply(null, data));
  const padL = 38, padB = 22, padT = 10, padR = 12;
  const innerW = w - padL - padR, innerH = h - padT - padB;

  ctx.strokeStyle = 'rgba(198,178,156,.34)';
  ctx.fillStyle = 'rgba(146,130,113,.9)';
  ctx.font = '10px "JetBrains Mono",ui-monospace,monospace';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i += 1) {
    const y = padT + (innerH / 4) * i;
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(w - padR, y);
    ctx.stroke();
    ctx.fillText(String(Math.round(max - (max / 4) * i)), 8, y + 3);
  }

  const step = innerW / Math.max(1, data.length - 1);
  const y = (v) => padT + innerH - (v / max) * innerH;

  data.forEach((v, i) => {
    const bx = padL + i * step;
    const bw = Math.max(3, step - 7);
    ctx.fillStyle = 'rgba(226,168,110,.30)';
    ctx.fillRect(bx - bw / 2, y(v), bw, padT + innerH - y(v));
  });

  ctx.beginPath();
  data.forEach((v, i) => {
    const px = padL + i * step, py = y(v);
    if (i === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
  });
  ctx.strokeStyle = '#d2762e';
  ctx.lineWidth = 2;
  ctx.lineJoin = 'round';
  ctx.stroke();

  ctx.fillStyle = 'rgba(146,130,113,.9)';
  const now = new Date();
  for (let i = 0; i < data.length; i += 2) {
    const d = new Date(now.getTime() - (data.length - 1 - i) * 60000);
    const label = String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
    ctx.fillText(label, padL + i * step - 14, h - 6);
  }
  set(dom.trendNote, '峰值 ' + max + ' · 当前 ' + data[data.length - 1]);
}

const set = (node, value) => { if (node) node.textContent = value; };

window.addEventListener('resize', () => drawTrend());
setInterval(drawTrend, 20000);

boot();
