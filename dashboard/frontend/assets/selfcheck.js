/* ──────────────────────────────────────────────────────────────
   vigil console · in-page self check

   Nothing here is clever, and that is the point. A page whose wiring
   is broken looks exactly like a page with no traffic: quiet. This
   module makes the quiet case loud in two places at once --

     * a banner on the page, so whoever is looking knows immediately;
     * a report to /api/v1/clientlog, so it is also in the journal and
       in the audit file for later.

   It also catches uncaught errors and unhandled rejections anywhere in
   the page, which is how a mistake in an event handler gets noticed at
   all.
   ────────────────────────────────────────────────────────────── */
'use strict';

import { api } from './core.js';

const REQUIRED_HOME = [
  ['world-canvas', '地图画布'],
  ['map-loading', '地图加载提示'],
  ['stream', '实时事件流'],
  ['kpi-total', '外网请求'],
  ['kpi-bans', '实时封禁'],
  ['cpu-pct', 'CPU 指标'],
  ['mem-pct', '内存指标'],
  ['disk-pct', '硬盘指标'],
  ['net-total', '网络指标'],
  ['cpu-spark', 'CPU 曲线'],
  ['trend-canvas', '请求量曲线'],
  ['attack-table', '攻击表格'],
  ['countries', '来源分布'],
  ['zoom-in', '缩放控件'],
  ['map-sub', '地图说明'],
];

const REQUIRED_ADMIN = [
  ['login-form', '登录表单'],
  ['console', '控制台容器'],
  ['tabs', '标签栏'],
  ['sites-table', '站点表格'],
  ['fm-list', '文件列表'],
  ['fm-path', '路径输入'],
  ['panel-grid', '后台入口'],
  ['audit-table', '审计表格'],
];

export function installSelfCheck(page) {
  const required = page === 'admin' ? REQUIRED_ADMIN : REQUIRED_HOME;
  const missing = [];
  required.forEach(([id, label]) => {
    if (!document.getElementById(id)) missing.push(label + ' (#' + id + ')');
  });

  const problems = [];
  if (missing.length) problems.push('缺少页面元素：' + missing.join('、'));

  const report = (kind, detail) => {
    try {
      const blob = JSON.stringify({ page: page, kind: kind, detail: String(detail).slice(0, 800) });
      if (navigator.sendBeacon) {
        navigator.sendBeacon('/api/v1/clientlog', new Blob([blob], { type: 'application/json' }));
      } else {
        api('/clientlog', {
          method: 'POST',
          body: { page: page, kind: kind, detail: String(detail).slice(0, 800) },
        }).catch(() => {});
      }
    } catch (_) { /* reporting must never be the thing that breaks the page */ }
  };

  window.addEventListener('error', (ev) => {
    const where = ev.filename ? ev.filename.split('/').pop() + ':' + ev.lineno : '?';
    report('error', where + ' ' + (ev.message || 'unknown'));
  });
  window.addEventListener('unhandledrejection', (ev) => {
    const reason = ev.reason && ev.reason.message ? ev.reason.message : ev.reason;
    report('rejection', reason);
  });

  const banner = (message) => {
    const node = document.createElement('div');
    node.className = 'vigil-warn';
    node.setAttribute('role', 'alert');
    node.textContent = message;
    document.body.appendChild(node);
  };

  if (problems.length) {
    banner('页面自检未通过：' + problems.join('；'));
    report('missing-elements', problems.join('；'));
    return false;
  }

  // A page that loaded but never received data is the failure that is hardest
  // to notice, because it looks fine. Say so after a grace period.
  setTimeout(() => {
    const alive = page === 'admin'
      ? document.querySelectorAll('#sites-table tbody tr').length > 0
      : (document.getElementById('stream') || {}).childElementCount > 0
        || (document.getElementById('kpi-total') || {}).textContent !== '—';
    if (!alive) {
      banner('页面已就绪，但 15 秒内没有收到任何数据 —— 请检查 '
        + '<code>/api/v1/stream</code> 与 nginx 代理。');
      report('no-data', '15 秒内没有数据到达');
    }
  }, 15000);

  return true;
}
