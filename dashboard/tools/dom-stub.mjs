/* Boot the real modules against a DOM built from the real HTML, so that a
   typo in an id or a selector shows up here instead of as a blank page. */
import { readFileSync } from 'node:fs';

const calls = { fill: 0, stroke: 0, arc: 0, text: 0, drawImage: 0, gradients: 0, fetch: [], dom: 0 };
function gradient() { calls.gradients++; return { addColorStop() {} }; }
function ctx2d() {
  return new Proxy({}, {
    get(t, p) {
      if (p in t) return t[p];
      return (...a) => {
        if (p === 'fill') calls.fill++;
        else if (p === 'stroke') calls.stroke++;
        else if (p === 'arc') calls.arc++;
        else if (p === 'fillText') calls.text++;
        else if (p === 'drawImage') calls.drawImage++;
        else if (p === 'createLinearGradient' || p === 'createRadialGradient') return gradient();
        else if (p === 'measureText') return { width: 40 };
        return undefined;
      };
    },
    set(t, p, v) { t[p] = v; return true; },
  });
}
const byId = new Map();
const createdByTag = {};
function element(tag = 'div', id = '') {
  const t = String(tag).toLowerCase();
  createdByTag[t] = (createdByTag[t] || 0) + 1;
  const node = {
    tagName: String(tag).toUpperCase(), id, style: {}, dataset: {},
    classList: { _s: new Set(), add(c) { this._s.add(c); }, remove(c) { this._s.delete(c); },
                 toggle(c, on) { const has = this._s.has(c); const want = on === undefined ? !has : !!on;
                                 if (want) this._s.add(c); else this._s.delete(c); return want; },
                 contains(c) { return this._s.has(c); } },
    children: [], parentNode: null, hidden: false, disabled: false, readOnly: false,
    width: 0, height: 0, clientWidth: 1100, clientHeight: 620, value: '', files: null,
    checked: false, _text: '', _html: '',
    getContext: () => ctx2d(),
    getBoundingClientRect: () => ({ width: 1100, height: 620, left: 0, top: 0 }),
    addEventListener() {}, removeEventListener() {}, dispatchEvent() {},
    appendChild(c) { c.parentNode = node; node.children.push(c); calls.dom++; return c; },
    insertBefore(c) { c.parentNode = node; node.children.unshift(c); calls.dom++; return c; },
    removeChild(c) { const i = node.children.indexOf(c); if (i >= 0) node.children.splice(i, 1); return c; },
    remove() { if (node.parentNode) node.parentNode.removeChild(node); },
    setAttribute() {}, getAttribute() { return null; }, closest() { return null; },
    // A selector must resolve to the same node every time, otherwise the page
    // appends rows to one object and the test counts another.
    querySelector(sel) {
      // "#id tbody" must yield the same table node the id maps to, otherwise
      // the page appends rows somewhere the test never looks.
      const m = /^#([\w-]+)/.exec(String(sel));
      if (m) {
        if (!byId.has(m[1])) element('div', m[1]);
        return byId.get(m[1]);
      }
      node._sel = node._sel || new Map();
      if (!node._sel.has(sel)) node._sel.set(sel, element('div'));
      return node._sel.get(sel);
    },
    querySelectorAll() { return []; },
    focus() {}, select() {}, click() {}, setPointerCapture() {},
    get firstChild() { return node.children[0] || null; },
    get lastChild() { return node.children[node.children.length - 1] || null; },
    get textContent() { return node._text; },
    set textContent(v) { node._text = String(v); },
    get innerHTML() { return node._html; },
    set innerHTML(v) { node._html = String(v); node.children.length = 0; },
    get className() { return Array.from(node.classList._s).join(' '); },
    set className(v) { node.classList._s = new Set(String(v).split(/\s+/).filter(Boolean)); },
  };
  if (id) byId.set(id, node);
  return node;
}
const document = {
  createElement: (t) => element(t),
  createTextNode: (t) => ({ nodeType: 3, textContent: t }),
  // Look-up-or-create, and remember: the page modules grab their elements at
  // import time, so a stub that hands out a fresh object each call would hide
  // exactly the wiring the simulation is meant to verify.
  getElementById: (id) => {
    if (!byId.has(id)) element('div', id);
    return byId.get(id);
  },
  _sel: new Map(),
  querySelector(sel) {
    if (!document._sel.has(sel)) document._sel.set(sel, element('div'));
    return document._sel.get(sel);
  },
  querySelectorAll: () => [],
  addEventListener() {}, removeEventListener() {},
  body: element('body'),
  documentElement: element('html'),
};
// collect every id the pages actually reference
// Resolved against this file, not the working directory, so the sim scripts
// can be run from anywhere.
const REPO = new URL('../', import.meta.url);
for (const file of ['frontend/index.html', 'frontend/admin.html']) {
  const html = readFileSync(new URL(file, REPO), 'utf8');
  for (const m of html.matchAll(/\sid="([^"]+)"/g)) element('div', m[1]);
}
const listeners = {};
const frames = [];
const window = {
  devicePixelRatio: 2,
  innerWidth: 1100, innerHeight: 620,
  addEventListener(t, f) { (listeners[t] = listeners[t] || []).push(f); },
  removeEventListener() {},
  location: { hash: '', href: 'https://vigil.test/' },
  requestAnimationFrame: (f) => { frames.push(f); return frames.length; },
  setTimeout: (f, ms) => setTimeout(f, ms), clearTimeout,
  setInterval: () => 0, clearInterval() {},
  performance: { now: () => Date.now() },
  prompt: () => null, confirm: () => false,
  fetch: (url, opts) => { calls.fetch.push(String(url)); return globalThis.__fetch(url, opts); },
  EventSource: class { constructor(u) { this.url = u; } addEventListener() {} close() {} },
  XMLHttpRequest: class { open() {} setRequestHeader() {} addEventListener() {} send() {} },
  IntersectionObserver: class { observe() {} disconnect() {} },
  sessionStorage: { getItem: () => '', setItem() {} },
};
globalThis.document = document;
globalThis.window = window;
globalThis.requestAnimationFrame = window.requestAnimationFrame;
globalThis.sessionStorage = window.sessionStorage;
globalThis.IntersectionObserver = window.IntersectionObserver;
globalThis.EventSource = window.EventSource;
globalThis.XMLHttpRequest = window.XMLHttpRequest;
globalThis.location = window.location;
globalThis.performance = window.performance;
globalThis.setInterval = () => 0;
globalThis.fetch = window.fetch;
globalThis.__frames = frames;
globalThis.__calls = calls;
globalThis.__byId = byId;
globalThis.__listeners = listeners;
export { element };

globalThis.__byTag = createdByTag;
export { createdByTag };
