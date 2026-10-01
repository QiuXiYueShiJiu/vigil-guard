/* Execute the gate's inline script against a stub DOM.
 *
 * `node --check` only proves the syntax parses. It cannot catch a name that
 * no longer exists -- and that is exactly how the login page came to render
 * nothing at all: a variable was deleted in one refactor while a line still
 * assigned to it, so the whole IIFE threw a ReferenceError on the first
 * statement that touched it and never reached the code that fetches the
 * images. The browser showed an empty puzzle and said nothing; the access log
 * showed no /captcha requests at all.
 *
 * So: run it, record which image URLs it asks for, and report both -- plus
 * whether the animation loop was ever reached, because "requested the images"
 * and "started drawing them" are two different claims.
 *
 * A second lesson is baked in. The page now issues its image requests before
 * it touches a canvas, and attaches the onload handlers afterwards, so an
 * image may well have finished before the handler exists. The stub therefore
 * delivers `load` on the next microtask, exactly as a browser delivers it on
 * a later task, and the harness flushes microtasks before reporting. A stub
 * that fired `load` inside the `src` setter would call a handler that had not
 * been attached yet and quietly prove nothing.
 *
 * argv[2] = the inline script
 * argv[3] = the puzzle element's data-* attributes, as JSON
 * argv[4] = count of q_answer radios to provide (optional)
 */
const fs = require("fs");

const script = fs.readFileSync(process.argv[2], "utf8");
const dataset = JSON.parse(process.argv[3] || "{}");
const radios = parseInt(process.argv[4] || "0", 10);
const requested = [];

function ctxStub() {
  return new Proxy({}, {
    get(t, k) {
      if (k === "createRadialGradient" || k === "createLinearGradient") {
        return () => ({ addColorStop() {} });
      }
      if (k === "getImageData") {
        return () => ({ data: new Uint8ClampedArray(64) });
      }
      if (k === "measureText") { return () => ({ width: 10 }); }
      if (k in t) { return t[k]; }
      return () => {};
    },
    set(t, k, v) { t[k] = v; return true; }
  });
}

function el(id) {
  const node = {
    id: id, dataset: {}, style: {}, width: 480, height: 280,
    offsetWidth: 46, clientWidth: 300, tabIndex: 0, textContent: "",
    classList: { add() {}, remove() {}, contains() { return false; } },
    addEventListener() {}, removeEventListener() {},
    appendChild() {}, removeChild() {}, cloneNode() { return el(id); },
    getContext: () => ctxStub(),
    querySelector: () => null, querySelectorAll: () => [],
    getBoundingClientRect: () => ({ left: 0, top: 0, width: 480, height: 280 }),
    focus() {}, setAttribute() {}, getAttribute() { return null; }
  };
  return node;
}

const host = el("puzzle");
host.dataset = dataset;

const answers = [];
for (let i = 0; i < radios; i++) {
  answers.push({ value: String(i), checked: i === 0 });
}

// One node per id, like a document: the page holds on to the elements it
// looks up, so the harness must be able to look up the same objects again to
// see what the page did to them.
const byId = { puzzle: host };
global.document = {
  getElementById: (id) => (byId[id] || (byId[id] = el(id))),
  createElement: () => el("made"),
  querySelector: (sel) => (sel && sel.indexOf("q_answer") >= 0
                            ? (answers[0] || null) : null),
  querySelectorAll: () => answers,
  addEventListener() {}, removeEventListener() {},
  body: el("body"), documentElement: el("html")
};
global.window = global;
global.navigator = { userAgent: "node-stub" };
// window listeners are kept, not ignored: the page's "tell the visitor what
// went wrong" hook is a window error listener, and a stub that swallowed it
// would let the visible-failure path rot untested.
const winListeners = Object.create(null);
global.addEventListener = (t, fn) => {
  (winListeners[t] || (winListeners[t] = [])).push(fn);
};
global.removeEventListener = () => {};
let frames = 0;
global.requestAnimationFrame = () => { frames++; return 1; };  // count, do not run
global.cancelAnimationFrame = () => {};
// Timers are recorded but never fired: the page's watchdog must not decide
// the verdict here, and a pending timer would keep the process alive.
const timers = [];
global.setTimeout = (fn) => { timers.push(fn); return timers.length; };
global.clearTimeout = () => {};

// Records the request immediately; delivers `load` on a later microtask, the
// way a browser does. Nothing here is synchronous-on-assignment, so a page
// that sets `src` before it sets `onload` is still exercised properly.
global.Image = function Image() {
  const self = this;
  self.naturalWidth = 640;
  self.naturalHeight = 400;
  self.complete = false;
  Object.defineProperty(this, "src", {
    get() { return self._src || ""; },
    set(v) {
      self._src = v;
      if (v) { requested.push(String(v)); }
      queueMicrotask(() => {
        self.complete = true;
        if (typeof self.onload === "function") { self.onload(); }
        else if (typeof self.onerror === "function") { self.onerror(); }
      });
    }
  });
};

(async () => {
  let error = null;
  try {
    (0, eval)(script);
  } catch (e) {
    error = (e && e.message) ? e.message : String(e);
    // A browser does not catch this: the exception escapes the script element
    // and an `error` event is dispatched on window. Do the same, so the page's
    // own failure handling is exercised rather than described.
    for (const fn of (winListeners.error || [])) {
      try { fn({ message: error }); } catch (_) { /* a listener may itself fail */ }
    }
  }
  // Let every queued image callback run before judging the page.
  await new Promise((r) => setImmediate(r));
  const shown = global.document.getElementById("jsfail");
  process.stdout.write(JSON.stringify({
    ok: error === null, error: error, requested: requested,
    frames: frames,
    failureShown: !!(shown && shown.style && shown.style.display === "block")
  }));
})();
