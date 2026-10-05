/* ──────────────────────────────────────────────────────────────
   vigil console · flat map engine

   A plane, not a globe: equirectangular in longitude, Web-Mercator in
   latitude, composed into a single affine transform. Panning and zooming are
   two multiplications per point, which is why the whole plate is cached in an
   offscreen canvas and only redrawn when the view actually moves.

   Every mark is a meteor: a bright head flying from the source to the host, a
   gradient tail behind it, and a dot at the source that fades as the head
   pulls away.

   This file was rewritten from scratch after a run of surgical edits left it
   with four copies of _scale(), four of _yScale(), three constructors and
   four fitWorld() definitions. Later definitions silently shadowed earlier
   ones, so fixes frequently appeared to do nothing at all. Hence the note:
   when an edit is described as "replace the block from index A to index B",
   count the members afterwards.
   ────────────────────────────────────────────────────────────── */
'use strict';

const DEG = Math.PI / 180;
const TAU = Math.PI * 2;

/** Palette. Light and warm, so the data reads as data rather than as neon. */
export const LEVEL_STYLE = {
  0: {
    name: 'normal', label: '正常访问',
    line: '58,122,82',
    width: 1.7, ttl: 2600, sweep: 900,
  },
  1: {
    name: 'attack', label: '攻击',
    line: '208,64,48',
    width: 2.2, ttl: 4000, sweep: 700,
  },
  2: {
    name: 'pressure', label: '高压攻击',
    line: '132,30,24',
    width: 3.0, ttl: 5200, sweep: 600,
  },
};

/* Framing presets. `zoom` is how many times the 360-degree world width fits
   across the canvas; a preset with no zoom means "fit the whole plate", which
   flyTo() resolves through fitZoom(). */
const VIEWS = {
  world: { lon: 0, lat: 0, zoom: 0 },
  asia: { lon: 115, lat: 18, zoom: 1.55 },
  europe: { lon: 18, lat: 42, zoom: 2.6 },
  americas: { lon: -70, lat: 16, zoom: 1.5 },
};

/*: Bumped whenever the ring encoding changes. The data file carries the same
   number; a mismatch is reported as exactly that instead of surfacing as a
   bare `atob` failure. */
export const DATA_VERSION = 2;

class MapDataError extends Error {
  constructor(message, kind) {
    super(message);
    this.name = 'MapDataError';
    this.kind = kind || 'format';     // format | version | network
  }
}

/* Latitude is clamped just short of the poles so the projection stays finite;
   at 84 degrees the scale factor is ~11.6x, a chart convention that keeps
   Greenland recognisable instead of infinitely tall. */
const MERC_LIMIT = Math.log(Math.tan(Math.PI / 4 + (84 * DEG) / 2));

/** Latitude -> -1..1, north negative so it matches canvas y. */
function projectionY(lat) {
  const clamped = Math.max(-84, Math.min(84, lat));
  return -Math.log(Math.tan(Math.PI / 4 + (clamped * DEG) / 2)) / MERC_LIMIT;
}

/** Inverse of projectionY. */
function projectionLat(py) {
  return (2 * Math.atan(Math.exp(-py * MERC_LIMIT)) - Math.PI / 2) / DEG;
}

const MIN_Y = projectionY(80);
const MAX_Y = projectionY(-70);
// 手势控制已停用：小地图的交互设计不过关（拖拽/捏合的判定在真机上难以predictably
// 表现），改为**只用 UI 按钮**控制 —— 放大 / 缩小由 `#zoom-in`、`#zoom-out` 驱动。
//
// 保留下面这段处理代码而不是删除：手势逻辑本身没有错，是设计没做好；将来重新设计
// 时把这里改回 true 即可一处恢复，不必去各处找回被删掉的监听器。
const GESTURES_ENABLED = false;

const MIN_ZOOM = 0.15;
const MAX_ZOOM = 40;

function clamp(value, low, high) {
  return value < low ? low : value > high ? high : value;
}

/** Decode one ring: base64 -> varint deltas -> [lon, projY, lon, projY, ...].

    ``expectedBytes`` comes from the data file. Checking it costs nothing and
    turns three failure modes -- a truncated body, a proxy that mangled the
    response, and a stale file in an older format -- into one readable error
    instead of a wrong-looking map or a bare `atob` exception. */
function decodeRing(b64, scale, expectedBytes) {
  let bin;
  try {
    bin = atob(b64);
  } catch (err) {
    throw new MapDataError('地图数据不是合法的 base64（'
      + (b64 === null || b64 === undefined ? 'ring 为空'
        : typeof b64 !== 'string' ? 'ring 类型是 ' + typeof b64
          : '长度 ' + b64.length + '，可能被截断')
      + '）。多半是浏览器缓存里的旧版地图数据，强制刷新即可。', 'format');
  }
  if (expectedBytes && bin.length !== expectedBytes) {
    throw new MapDataError('地图数据长度不符：ring 期望 ' + expectedBytes
      + ' 字节，实际 ' + bin.length + ' 字节。数据可能被截断或版本错配。', 'format');
  }
  const n = bin.length;
  const out = new Float64Array(n);
  let i = 0;
  let k = 0;
  let x = 0;
  let y = 0;
  while (i < n) {
    let shift = 0;
    let val = 0;
    let byte;
    do { byte = bin.charCodeAt(i); i += 1; val |= (byte & 0x7f) << shift; shift += 7; } while (byte & 0x80);
    x += (val & 1) ? -((val + 1) >> 1) : (val >> 1);
    shift = 0;
    val = 0;
    do { byte = bin.charCodeAt(i); i += 1; val |= (byte & 0x7f) << shift; shift += 7; } while (byte & 0x80);
    y += (val & 1) ? -((val + 1) >> 1) : (val >> 1);
    out[k] = x / scale;
    out[k + 1] = projectionY(y / scale);
    k += 2;
  }
  return out.subarray(0, k);
}

/* ── one meteor ───────────────────────────────────────────────────── */

class Trace {
  constructor(level, from, to, event) {
    this.level = level;
    this.style = LEVEL_STYLE[level] || LEVEL_STYLE[0];
    this.from = from;
    this.to = to;
    this.event = event || {};
    this.age = 0;
    this.ttl = this.style.ttl;
    this.dead = false;
  }

  update(dt) {
    this.age += dt;
    if (this.age >= this.ttl) this.dead = true;
  }

  /** 0..1 along the route. Attacks are held back a moment so a burst is seen
      travelling rather than appearing already arrived. */
  get head() {
    const delay = this.level === 0 ? 0 : 220;
    return clamp((this.age - delay) / this.style.sweep, 0, 1);
  }

  get fade() {
    const left = this.ttl - this.age;
    if (left <= 0) return 0;
    // Full strength for most of the life, then away quickly, so a busy map
    // does not settle into a uniform haze.
    return clamp(left / (this.ttl * 0.35), 0, 1);
  }
}

/* ── the plate ────────────────────────────────────────────────────── */

export class FlatMap {
  constructor(canvas, options = {}) {
    this.canvas = canvas;
    this.opts = Object.assign({
      server: { lat: 22.3193, lon: 114.1694 },
      pulse: true,
      labels: true,
      onFrame: null,
      onSelect: null,
    }, options);

    this.w = 1;
    this.h = 1;
    this.dpr = 1;
    this.countries = [];
    this.labels = [];
    this.meta = {};
    this.traces = [];
    this.ready = false;
    this._running = false;
    this._dirty = true;
    this._baseReady = false;
    this._baseDrawnAt = 0;
    this._last = 0;
    this._dragging = false;
    this._moved = 0;
    this._drawn = 0;
    this._pointers = new Map();
    this._pinch = 0;
    // Frame cost, measured rather than guessed. "It feels laggy" is not
    // actionable; "the plate redraw averages 9ms and happens 24 times a
    // second" is. Reported to the service when a session ends.
    this.stats = { frames: 0, baseDraws: 0, baseMs: 0, frameMs: 0, worstMs: 0 };
    // The view the cached plate was rendered for. While a pan keeps the same
    // zoom, the plate can simply be drawn at an offset instead of rebuilt.
    this._baseView = { lon: 0, projY: 0, zoom: 0 };

    this.view = { lon: 0, projY: 0, zoom: 1, cx: 0.5, cy: 0.5 };
    this.target = { lon: 0, projY: 0, zoom: 1 };

    this.ctx = canvas.getContext('2d');
    this.base = document.createElement('canvas');
    this._baseCtx = this.base.getContext('2d');

    this._onResize = () => this.resize();
    this._bind();
    this.resize();
  }

  /* ── data ───────────────────────────────────────────────────────── */

  async load(url = '/assets/world.json', bust = false) {
    const target = bust ? url + (url.indexOf('?') < 0 ? '?' : '&') + 'v=' + Date.now() : url;
    let res;
    try {
      res = await fetch(target, bust ? { cache: 'reload' } : { cache: 'force-cache' });
    } catch (err) {
      throw new MapDataError('地图数据请求失败：' + err.message, 'network');
    }
    if (!res.ok) throw new MapDataError('地图数据加载失败 HTTP ' + res.status, 'network');
    let doc;
    try {
      doc = await res.json();
    } catch (err) {
      throw new MapDataError('地图数据不是合法 JSON：' + err.message, 'format');
    }
    if (Number(doc.v || 0) !== DATA_VERSION) {
      throw new MapDataError('地图数据版本 ' + (doc.v || '未知') + ' 与解码器要求的 '
        + DATA_VERSION + ' 不一致，取到的是旧缓存。', 'version');
    }
    return this.adopt(doc);
  }

  adopt(doc) {
    const scale = (doc.meta && doc.meta.scale) || 1000;
    this.meta = doc.meta || {};
    this.labels = doc.labels || [];
    this.countries = (doc.countries || []).map((c) => {
      const rings = new Array(c.r.length);
      const bytes = c.b || [];
      for (let i = 0; i < c.r.length; i += 1) {
        try {
          rings[i] = decodeRing(c.r[i], scale, bytes[i]);
        } catch (err) {
          if (err instanceof MapDataError) {
            err.message = '国家 #' + (c.i !== undefined ? c.i : '?') + ' 第 ' + i
              + ' 个环：' + err.message;
          }
          throw err;
        }
      }
      return rings;
    });
    this.ready = true;
    this._dirty = true;
    this._baseReady = false;
    return doc;
  }

  setServer(point) {
    if (!point) return;
    this.opts.server = Object.assign({}, this.opts.server, point);
  }

  /* ── geometry ───────────────────────────────────────────────────── */

  resize() {
    const rect = this.canvas.getBoundingClientRect
      ? this.canvas.getBoundingClientRect()
      : { width: this.canvas.clientWidth, height: this.canvas.clientHeight };
    const w = Math.max(240, Math.round(rect.width || this.canvas.clientWidth || 960));
    const h = Math.max(180, Math.round(rect.height || this.canvas.clientHeight || 480));
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    if (w === this.w && h === this.h && dpr === this.dpr && this._baseReady) return;
    this.w = w;
    this.h = h;
    this.dpr = dpr;
    this.canvas.width = Math.round(w * dpr);
    this.canvas.height = Math.round(h * dpr);
    this.base.width = Math.round(w * dpr);
    this.base.height = Math.round(h * dpr);
    this._baseReady = false;
    this._dirty = true;
    if (!this._running) this.draw();
  }

  /** Horizontal pixels per degree of longitude. */
  _scale() {
    return (this.w * this.view.zoom) / 360;
  }

  /* Vertical pixels per unit of projectionY.

     Must keep the plate's true shape: longitude spans 360 degrees and
     projectionY spans exactly -1..1, so the matching vertical scale is
     (w * zoom / 360) * 180 = w * zoom / 2 per unit -- which is this halved,
     because projectionY already runs -1..1 across 180 degrees of latitude.
     Keeping it proportional to zoom is what lets the whole world fit any
     canvas. An earlier version pinned it to the canvas size, so zooming out
     did nothing to the latitude span and the poles were always cropped. */
  _yScale() {
    return (this.w * Math.max(0.05, this.view.zoom)) / 4;
  }

  /* The zoom at which the entire plate fits the canvas on both axes.

     Longitude: 360 degrees at w*zoom/360 must fit in w, so zoom <= 1.
     Latitude: the visible band must fit in h/2 either side of centre, so
     zoom <= 2h / (w * halfSpan).

     Both are real constraints; clamping to one rather than taking the smaller
     is what left the poles cropped on canvases narrower than 2:1. */
  fitZoom() {
    const north = projectionY(84);
    const south = projectionY(-84);
    const centre = (north + south) / 2;
    const halfSpan = Math.abs(north - centre);
    const byHeight = (2 * this.h) / (this.w * halfSpan);
    return clamp(Math.min(1, byHeight) * 0.99, MIN_ZOOM, MAX_ZOOM);
  }

  /** Projection value that puts the visible band's midpoint on the canvas. */
  _centreProj() {
    return (projectionY(84) + projectionY(-84)) / 2;
  }

  _project(lon, lat, out) {
    out.x = this.view.cx + (lon - this.view.lon) * this._scale();
    out.y = this.view.cy + (projectionY(lat) - this.view.projY) * this._yScale();
    return out;
  }

  _unproject(x, y) {
    return {
      lon: this.view.lon + (x - this.view.cx) / this._scale(),
      lat: projectionLat(this.view.projY + (y - this.view.cy) / this._yScale()),
    };
  }

  _wrapLon(lon) {
    let v = lon;
    while (v > 180) v -= 360;
    while (v < -180) v += 360;
    return v;
  }

  /* ── view control ───────────────────────────────────────────────── */

  flyTo(name, zoom) {
    const preset = typeof name === 'string' ? VIEWS[name] : name;
    if (!preset) return;
    const world = typeof name === 'string' && name === 'world';
    if (world) {
      // Recentre and fit. Any non-zero view longitude pushes half the excess
      // off one edge, and an off-centre latitude band gets its poles cropped
      // while every "does the span fit" check agrees that it does.
      this.target.lon = 0;
      this.target.projY = this._centreProj();
      this.target.zoom = this.fitZoom();
    } else {
      this.target.lon = preset.lon;
      this.target.projY = clamp(projectionY(preset.lat), MIN_Y, MAX_Y);
      this.target.zoom = clamp(zoom || preset.zoom || 1, MIN_ZOOM, MAX_ZOOM);
    }
    this._dirty = true;
    if (!this._running) { this._applyView(); this.draw(); }
  }

  /** Frame the whole world. */
  fitWorld() {
    this.target.lon = 0;
    this.target.projY = this._centreProj();
    this.target.zoom = this.fitZoom();
    this._dirty = true;
    if (!this._running) { this._applyView(); this.draw(); }
  }

  zoomBy(factor, anchorX, anchorY) {
    const next = clamp(this.target.zoom * factor, MIN_ZOOM, MAX_ZOOM);
    if (Math.abs(next - this.target.zoom) < 1e-6) return;
    const anchored = typeof anchorX === 'number' && typeof anchorY === 'number';
    // The geographic point currently under the cursor / between the fingers.
    const geo = anchored ? this._unproject(anchorX, anchorY) : null;
    this.target.zoom = next;
    if (anchored) {
      /* Pin that point to the same screen position while the scale changes.

         x = cx + (lon - view.lon) * kx   with kx = w * zoom / 360
         => view.lon = lon - (x - cx) / kx
         y = cy + (projY(lat) - view.projY) * ky   with ky = w * zoom / 4
         => view.projY = projY(lat) - (y - cy) / ky

         Both use the *new* scale. An earlier version mixed the old scale into
         one axis, so every zoom dragged the sources sideways across the map
         and nothing lined up with the coastlines. */
      const kx = (this.w * next) / 360;
      const ky = (this.w * next) / 4;
      this.target.lon = this._wrapLon(geo.lon - (anchorX - this.view.cx) / kx);
      this.target.projY = clamp(projectionY(geo.lat) - (anchorY - this.view.cy) / ky,
        MIN_Y, MAX_Y);
    }
    this._dirty = true;
  }

  /* ── input ──────────────────────────────────────────────────────── */

  _bind() {
    const canvas = this.canvas;
    let lastX = 0;
    let lastY = 0;

    const panTo = (dx, dy) => {
      this.target.lon = this._wrapLon(this.target.lon
        - dx * (360 / (this.w * this.target.zoom)));
      // Panning happens in projection space, not latitude space.
      // projectionY grows southward, and dragging the map down (dy > 0) should
      // reveal what lies north -- so the view's projection value *decreases*.
      // An earlier version added dy and then negated the result again, which
      // inverted vertical panning on every pointer device, touch included.
      const yScale = (this.w * this.target.zoom) / 4;
      this.target.projY = clamp(this.target.projY - dy / yScale, MIN_Y, MAX_Y);
      this._dirty = true;
    };

    canvas.addEventListener('pointerdown', (ev) => {
      if (!GESTURES_ENABLED) return;
      this._pointers.set(ev.pointerId, { x: ev.clientX, y: ev.clientY });
      if (this._pointers.size === 1) {
        this._dragging = true;
        this._moved = 0;
        lastX = ev.clientX;
        lastY = ev.clientY;
        if (canvas.setPointerCapture) {
          try { canvas.setPointerCapture(ev.pointerId); } catch (_) { /* ignore */ }
        }
      } else if (this._pointers.size === 2) {
        // Baseline the pinch distance the moment the second finger lands.
        // Waiting for the next pointermove swallowed the first gesture and
        // made pinch-to-zoom feel dead on touch.
        const pts = Array.from(this._pointers.values());
        this._pinch = Math.hypot(pts[0].x - pts[1].x, pts[0].y - pts[1].y);
      }
      if (canvas.style) canvas.style.cursor = 'grabbing';
    });

    canvas.addEventListener('pointermove', (ev) => {
      if (!GESTURES_ENABLED) return;
      if (!this._pointers.has(ev.pointerId)) return;
      this._pointers.set(ev.pointerId, { x: ev.clientX, y: ev.clientY });

      if (this._pointers.size >= 2) {
        const pts = Array.from(this._pointers.values());
        const dist = Math.hypot(pts[0].x - pts[1].x, pts[0].y - pts[1].y);
        if (this._pinch > 0) {
          const rect = canvas.getBoundingClientRect();
          this.zoomBy(dist / this._pinch,
            (pts[0].x + pts[1].x) / 2 - rect.left,
            (pts[0].y + pts[1].y) / 2 - rect.top);
          this._dirty = true;
        }
        this._pinch = dist;
        this._moved = 99;
        return;
      }

      if (!this._dragging) return;
      const dx = ev.clientX - lastX;
      const dy = ev.clientY - lastY;
      lastX = ev.clientX;
      lastY = ev.clientY;
      this._moved += Math.abs(dx) + Math.abs(dy);
      panTo(dx, dy);
    });

    const endPointer = (ev) => {
      this._pointers.delete(ev.pointerId);
      if (this._pointers.size < 2) this._pinch = 0;
      if (canvas.style) canvas.style.cursor = 'grab';
      if (this._pointers.size > 0) return;
      this._dragging = false;
      // A tap, not a drag: report the nearest source under the finger.
      if (this._moved < 6 && this.opts.onSelect) {
        const rect = canvas.getBoundingClientRect();
        this.opts.onSelect(this._pick(ev.clientX - rect.left, ev.clientY - rect.top));
      }
    };
    canvas.addEventListener('pointerup', endPointer);
    canvas.addEventListener('pointercancel', endPointer);
    canvas.addEventListener('pointerleave', (ev) => { if (this._dragging) endPointer(ev); });

    canvas.addEventListener('wheel', (ev) => {
      if (!GESTURES_ENABLED) return;
      ev.preventDefault();
      const rect = canvas.getBoundingClientRect();
      this.zoomBy(ev.deltaY < 0 ? 1.12 : 1 / 1.12,
        ev.clientX - rect.left, ev.clientY - rect.top);
    }, { passive: false });

    window.addEventListener('resize', this._onResize);
  }

  /** Nearest active source to a canvas position. */
  _pick(x, y) {
    let best = null;
    let bestDist = 900;      // px^2, roughly 30px
    const pt = { x: 0, y: 0 };
    for (let i = 0; i < this.traces.length; i += 1) {
      const t = this.traces[i];
      this._project(t.from.lon, t.from.lat, pt);
      const d = (pt.x - x) * (pt.x - x) + (pt.y - y) * (pt.y - y);
      if (d < bestDist) { bestDist = d; best = t; }
    }
    return best ? best.event : null;
  }

  /* ── events ─────────────────────────────────────────────────────── */

  push(event) {
    if (!this.ready || !event) return false;
    const lat = Number(event.lat);
    const lon = Number(event.lon);
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) return false;
    const level = clamp(Math.round(Number(event.lv) || 0), 0, 2);
    // Reuse an in-flight trace from the same source and level instead of
    // stacking a hundred identical meteors on one city. Keyed on the event's
    // opaque source id, not an address: normal traffic is anonymised before
    // it reaches here and carries no address at all.
    const ident = event.id || event.ip || (lon + ',' + lat);
    for (let i = 0; i < this.traces.length; i += 1) {
      const t = this.traces[i];
      if (t.level === level && t.key === ident && t.age < 300) {
        t.age = 0;
        t.event = event;
        return true;
      }
    }
    const trace = new Trace(level, { lat, lon },
      { lat: this.opts.server.lat, lon: this.opts.server.lon }, event);
    trace.key = ident;
    this.traces.push(trace);
    let count = 0;
    let oldest = null;
    for (let i = 0; i < this.traces.length; i += 1) {
      if (this.traces[i].level === level) {
        count += 1;
        if (!oldest || this.traces[i].age > oldest.age) oldest = this.traces[i];
      }
    }
    const cap = level === 0 ? 160 : 90;
    if (count > cap && oldest) this.traces.splice(this.traces.indexOf(oldest), 1);
    return true;
  }

  /* ── rendering ──────────────────────────────────────────────────── */

  /** One full repaint, for use when the animation loop is not running. */
  draw() {
    const ctx = this.ctx;
    ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    ctx.clearRect(0, 0, this.w, this.h);
    if (!this._baseReady) this._drawBase();
    ctx.drawImage(this.base, 0, 0, this.w, this.h);
    this._drawTraces(ctx, performance.now());
    this._drawServer(ctx, performance.now());
  }

  _applyView() {
    const v = this.view;
    const t = this.target;
    v.lon += (t.lon - v.lon) * 0.18;
    v.projY += (t.projY - v.projY) * 0.18;
    v.zoom += (t.zoom - v.zoom) * 0.18;
    if (Math.abs(t.lon - v.lon) < 1e-4) v.lon = t.lon;
    if (Math.abs(t.projY - v.projY) < 1e-5) v.projY = t.projY;
    if (Math.abs(t.zoom - v.zoom) < 1e-4) v.zoom = t.zoom;
    v.cx = this.w / 2;
    v.cy = this.h / 2;
  }

  _viewMoving() {
    return Math.abs(this.target.lon - this.view.lon) > 1e-4
      || Math.abs(this.target.projY - this.view.projY) > 1e-5
      || Math.abs(this.target.zoom - this.view.zoom) > 1e-4;
  }

  /* The expensive pass: one stroke of every coastline in the world. Cached in
     an offscreen canvas, rebuilt only when the view moves. */
  _drawBase() {
    const baseStart = performance.now();
    const ctx = this._baseCtx;
    ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    ctx.clearRect(0, 0, this.w, this.h);

    const water = ctx.createLinearGradient(0, 0, 0, this.h);
    water.addColorStop(0, '#f7ecdc');
    water.addColorStop(0.45, '#fbf5ee');
    water.addColorStop(1, '#fffdfa');
    ctx.fillStyle = water;
    ctx.fillRect(0, 0, this.w, this.h);

    if (!this.ready) {
      this._baseReady = false;
      return;
    }

    const scaleX = this._scale();
    const scaleY = this._yScale();
    const ox = this.view.cx - this.view.lon * scaleX;
    const oy = this.view.cy - this.view.projY * scaleY;
    const toX = (lon) => ox + lon * scaleX;
    const toY = (py) => oy + py * scaleY;

    // ── graticule ──────────────────────────────────────────────────
    const step = this._graticuleStep();
    if (step > 0) {
      const topLat = projectionLat((0 - oy) / scaleY);
      const botLat = projectionLat((this.h - oy) / scaleY);
      const leftLon = this.view.lon - this.view.cx / scaleX;
      const rightLon = this.view.lon + (this.w - this.view.cx) / scaleX;
      ctx.strokeStyle = 'rgba(198,172,142,.30)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      for (let lat = Math.floor(topLat / step) * step; lat >= botLat; lat -= step) {
        const y = Math.round(toY(projectionY(lat))) + 0.5;
        ctx.moveTo(0, y);
        ctx.lineTo(this.w, y);
      }
      for (let lon = Math.floor(leftLon / step) * step; lon <= rightLon; lon += step) {
        const x = Math.round(toX(lon)) + 0.5;
        ctx.moveTo(x, 0);
        ctx.lineTo(x, this.h);
      }
      ctx.stroke();
    }

    // ── land path ──────────────────────────────────────────────────
    // Built straight in screen space from the cached projection: no per-point
    // bounds test (the offscreen canvas clips anyway), and sub-pixel points
    // are skipped, which is invisible and roughly halves the path cost.
    const land = this._path();
    // Sub-pixel decimation, keyed to the actual pixels-per-degree. At world
    // zoom one degree is under 3px, so most of the 85k points land on a pixel
    // their neighbour already covers; skipping them is invisible and is the
    // single biggest saving in this pass. Zoomed in, nothing is skipped and
    // the full detail comes back.
    const skip = scaleX > 6 ? 0 : scaleX > 3 ? 1 : scaleX > 1.5 ? 2 : scaleX > 0.8 ? 3 : 4;
    const stride = skip + 2;
    for (let c = 0; c < this.countries.length; c += 1) {
      const rings = this.countries[c];
      for (let r = 0; r < rings.length; r += 1) {
        const flat = rings[r];
        if (!flat || flat.length < 6) continue;
        let px = toX(flat[0]);
        let py = toY(flat[1]);
        land.moveTo(px, py);
        for (let i = 2; i < flat.length; i += 2) {
          const nx = toX(flat[i]);
          const ny = toY(flat[i + 1]);
          if (skip > 0 && i + 2 < flat.length
            && Math.abs(nx - px) < 1 && Math.abs(ny - py) < 1) {
            if (Math.abs(toX(flat[i + 2]) - nx) < 1
              && Math.abs(toY(flat[i + 3]) - ny) < 1) continue;
          }
          land.lineTo(nx, ny);
          px = nx;
          py = ny;
        }
        land.closePath();
      }
    }

    // Shallow water: one wide soft stroke under the fill.
    ctx.save();
    ctx.lineJoin = 'round';
    ctx.lineCap = 'round';
    ctx.strokeStyle = 'rgba(246,232,212,.9)';
    ctx.lineWidth = 7;
    ctx.stroke(land);
    ctx.restore();

    // Land, lit from above.
    const grad = ctx.createLinearGradient(0, 0, 0, this.h);
    grad.addColorStop(0, '#efe6d7');
    grad.addColorStop(0.55, '#e9dece');
    grad.addColorStop(1, '#e2d4c1');
    ctx.fillStyle = grad;
    ctx.fill(land, 'evenodd');

    // Relief, only where a 2px shadow can be seen at all.
    if (this.view.zoom > 2.5) {
      ctx.save();
      ctx.clip(land, 'evenodd');
      ctx.globalCompositeOperation = 'destination-out';
      ctx.strokeStyle = 'rgba(0,0,0,.06)';
      ctx.lineWidth = 2.6;
      ctx.lineJoin = 'round';
      const offsets = [[1.6, 1.6], [-1.6, 1.6], [1.6, -1.6]];
      for (let i = 0; i < offsets.length; i += 1) {
        ctx.save();
        ctx.translate(offsets[i][0], offsets[i][1]);
        ctx.stroke(land);
        ctx.restore();
      }
      ctx.restore();
    }

    ctx.save();
    ctx.lineJoin = 'round';
    ctx.strokeStyle = 'rgba(150,128,100,.58)';
    ctx.lineWidth = 0.85;
    ctx.stroke(land);
    ctx.restore();

    if (this.opts.labels) this._drawLabels(ctx);
    this._baseReady = true;
    this._baseDrawnAt = performance.now();
    this._baseView.lon = this.view.lon;
    this._baseView.projY = this.view.projY;
    this._baseView.zoom = this.view.zoom;
    this.stats.baseDraws += 1;
    this.stats.baseMs += performance.now() - baseStart;
  }

  _path() {
    if (typeof Path2D !== 'undefined') return new Path2D();
    const c = this._baseCtx;
    return {
      moveTo: (x, y) => c.moveTo(x, y),
      lineTo: (x, y) => c.lineTo(x, y),
      closePath: () => c.closePath(),
    };
  }

  /** Degrees between graticule lines, or 0 to draw none. */
  _graticuleStep() {
    const z = this.view.zoom;
    if (z > 6) return 2;
    if (z > 3) return 5;
    if (z > 1.6) return 10;
    return 15;
  }

  _drawLabels(ctx) {
    const z = this.view.zoom;
    const step = z > 6 ? 1 : z > 3 ? 2 : z > 1.5 ? 3 : 6;
    const pt = { x: 0, y: 0 };
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.lineJoin = 'round';
    for (let i = 0; i < this.labels.length; i += 1) {
      if ((i % step) !== 0) continue;
      const label = this.labels[i];
      this._project(label.lon, label.y, pt);
      if (pt.x < 26 || pt.x > this.w - 26 || pt.y < 14 || pt.y > this.h - 14) continue;
      const important = label.c === 'CN' || label.c === 'US' || label.c === 'RU'
        || label.c === 'IN' || label.c === 'JP' || label.c === 'AU'
        || label.c === 'BR' || label.c === 'GB' || label.c === 'FR'
        || label.c === 'DE' || label.c === 'HK';
      if (z < 1.2 && !important) continue;
      ctx.font = (important ? '600 11.5px ' : '500 10.5px ')
        + '"PingFang SC","Microsoft YaHei",system-ui,sans-serif';
      // A halo is what keeps a name readable across a coastline.
      ctx.lineWidth = 3;
      ctx.strokeStyle = 'rgba(253,248,241,.85)';
      ctx.strokeText(label.n, pt.x, pt.y);
      ctx.fillStyle = important ? 'rgba(84,64,44,.95)' : 'rgba(122,106,86,.85)';
      ctx.fillText(label.n, pt.x, pt.y);
    }
  }

  /* The host beacon: a pulse and a dot, and no label of any kind. Its
     position already says "this is the host"; printing an address, hostname,
     provider or city beside it is information the public page has no reason
     to give away. */
  _drawServer(ctx, now) {
    const { x, y } = this._project(this.opts.server.lon, this.opts.server.lat, { x: 0, y: 0 });
    if (x < -30 || x > this.w + 30 || y < -30 || y > this.h + 30) return;
    ctx.save();
    const halo = ctx.createRadialGradient(x, y, 0, x, y, 22);
    halo.addColorStop(0, 'rgba(210,118,46,.28)');
    halo.addColorStop(1, 'rgba(210,118,46,0)');
    ctx.fillStyle = halo;
    ctx.beginPath();
    ctx.arc(x, y, 22, 0, TAU);
    ctx.fill();

    const pulse = (now % 2400) / 2400;
    ctx.lineWidth = 1.3;
    for (let k = 0; k < 2; k += 1) {
      const phase = (pulse + k / 2) % 1;
      ctx.beginPath();
      ctx.arc(x, y, 4 + phase * 17, 0, TAU);
      ctx.strokeStyle = 'rgba(194,104,38,' + (0.5 * (1 - phase)).toFixed(3) + ')';
      ctx.stroke();
    }
    ctx.beginPath();
    ctx.arc(x, y, 4.4, 0, TAU);
    ctx.fillStyle = '#c2682a';
    ctx.fill();
    ctx.beginPath();
    ctx.arc(x, y, 1.9, 0, TAU);
    ctx.fillStyle = '#fff';
    ctx.fill();
    ctx.restore();
  }

  /* ── traffic ────────────────────────────────────────────────────── */

  _drawTraces(ctx, now) {
    const total = this.traces.length;
    this._drawn = 0;
    if (!total) return;
    const pt = { x: 0, y: 0 };
    const sources = [];      // x, y, alpha, level
    const arrivals = [];     // x, y, k, level, fade

    // Tails, grouped by level so each group is one stroke rather than one
    // gradient object per trace per frame.
    for (let level = 2; level >= 0; level -= 1) {
      const style = LEVEL_STYLE[level];
      let any = false;
      ctx.beginPath();
      for (let i = 0; i < total; i += 1) {
        const t = this.traces[i];
        if (t.level !== level || t.fade <= 0.02) continue;
        this._project(t.from.lon, t.from.lat, pt);
        const x0 = pt.x;
        const y0 = pt.y;
        this._project(t.to.lon, t.to.lat, pt);
        if ((x0 < -80 && pt.x < -80) || (x0 > this.w + 80 && pt.x > this.w + 80)
          || (y0 < -80 && pt.y < -80) || (y0 > this.h + 80 && pt.y > this.h + 80)) continue;
        this._drawn += 1;
        ctx.moveTo(x0, y0);
        ctx.lineTo(pt.x, pt.y);
        any = true;
      }
      if (any) {
        ctx.save();
        ctx.lineCap = 'round';
        ctx.strokeStyle = 'rgba(' + style.line + ',.16)';
        ctx.lineWidth = style.width;
        ctx.stroke();
        ctx.restore();
      }
    }

    // Heads, tails and source dots.
    for (let i = 0; i < total; i += 1) {
      const t = this.traces[i];
      const fade = t.fade;
      if (fade <= 0.02) continue;
      const style = t.style;
      const head = t.head;
      this._project(t.from.lon, t.from.lat, pt);
      const x0 = pt.x;
      const y0 = pt.y;
      this._project(t.to.lon, t.to.lat, pt);
      const x1 = pt.x;
      const y1 = pt.y;

      ctx.save();
      ctx.lineCap = 'round';
      if (head > 0.005) {
        const hx = x0 + (x1 - x0) * head;
        const hy = y0 + (y1 - y0) * head;
        const back = t.level === 0 ? 0.45 : 0.6;
        const tx = hx + (x0 - hx) * back;
        const ty = hy + (y0 - hy) * back;
        const g = ctx.createLinearGradient(tx, ty, hx, hy);
        g.addColorStop(0, 'rgba(' + style.line + ',0)');
        g.addColorStop(0.55, 'rgba(' + style.line + ',' + (0.45 * fade).toFixed(3) + ')');
        g.addColorStop(1, 'rgba(' + style.line + ',' + (0.98 * fade).toFixed(3) + ')');
        ctx.beginPath();
        ctx.moveTo(tx, ty);
        ctx.lineTo(hx, hy);
        ctx.strokeStyle = g;
        ctx.lineWidth = style.width + (t.level === 0 ? 0.2 : 0.9);
        ctx.stroke();

        // Head: a white core inside the level colour, not a fat ball.
        const r = t.level === 0 ? 6 : t.level === 1 ? 8 : 10;
        const glow = ctx.createRadialGradient(hx, hy, 0, hx, hy, r);
        glow.addColorStop(0, 'rgba(255,255,255,' + (0.95 * fade).toFixed(3) + ')');
        glow.addColorStop(0.35, 'rgba(' + style.line + ',' + (0.85 * fade).toFixed(3) + ')');
        glow.addColorStop(1, 'rgba(' + style.line + ',0)');
        ctx.fillStyle = glow;
        ctx.beginPath();
        ctx.arc(hx, hy, r, 0, TAU);
        ctx.fill();
      }

      // The sender fades out as the meteor pulls away. Collected per level
      // and stroked once below -- an individual fill/stroke pair per trace is
      // what made a busy map expensive.
      const sourceFade = Math.max(0, 1 - head * 1.6) * fade;
      if (sourceFade > 0.02) {
        sources.push(x0, y0, sourceFade, t.level);
      }
      if (t.age < 520) {
        arrivals.push(x1, y1, t.age / 520, t.level, fade);
      }
      ctx.restore();
    }

    // Source dots, batched by level.
    for (let level = 2; level >= 0; level -= 1) {
      const style = LEVEL_STYLE[level];
      const radius = level === 2 ? 3.6 : level === 1 ? 3 : 2.4;
      let any = false;
      let alpha = 0;
      ctx.beginPath();
      for (let i = 0; i < sources.length; i += 4) {
        if (sources[i + 3] !== level) continue;
        ctx.moveTo(sources[i] + radius, sources[i + 1]);
        ctx.arc(sources[i], sources[i + 1], radius, 0, TAU);
        alpha = Math.max(alpha, sources[i + 2]);
        any = true;
      }
      if (any) {
        ctx.fillStyle = 'rgba(' + style.line + ',' + (0.9 * alpha).toFixed(3) + ')';
        ctx.fill();
      }
      ctx.beginPath();
      let ringAlpha = 0;
      let rings = false;
      for (let i = 0; i < sources.length; i += 4) {
        if (sources[i + 3] !== level) continue;
        ctx.moveTo(sources[i] + radius + 2.5, sources[i + 1]);
        ctx.arc(sources[i], sources[i + 1], radius + 2.5, 0, TAU);
        ringAlpha = Math.max(ringAlpha, sources[i + 2]);
        rings = true;
      }
      if (rings) {
        ctx.strokeStyle = 'rgba(' + style.line + ',' + (0.35 * ringAlpha).toFixed(3) + ')';
        ctx.lineWidth = 1;
        ctx.stroke();
      }
    }

    // Arrival rings, batched by level.
    for (let level = 2; level >= 0; level -= 1) {
      const style = LEVEL_STYLE[level];
      let any = false;
      let alpha = 0;
      ctx.beginPath();
      for (let i = 0; i < arrivals.length; i += 5) {
        if (arrivals[i + 3] !== level) continue;
        const k = arrivals[i + 2];
        const r = 3 + k * (level === 0 ? 14 : 20);
        ctx.moveTo(arrivals[i] + r, arrivals[i + 1]);
        ctx.arc(arrivals[i], arrivals[i + 1], r, 0, TAU);
        alpha = Math.max(alpha, 0.55 * (1 - k) * arrivals[i + 4]);
        any = true;
      }
      if (any) {
        ctx.strokeStyle = 'rgba(' + style.line + ',' + alpha.toFixed(3) + ')';
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }
    }
  }

  /* ── frame loop ─────────────────────────────────────────────────── */

  _loop(now) {
    if (!this._running) return;
    const dt = Math.min(120, now - this._last);
    this._last = now;
    this._applyView();
    for (let i = this.traces.length - 1; i >= 0; i -= 1) {
      this.traces[i].update(dt);
      if (this.traces[i].dead) this.traces.splice(i, 1);
    }
    // The base map is the expensive part. While the view is still easing it
    // is rebuilt at ~25fps rather than every frame: the meteors keep
    // animating at the display rate, so a drag looks smooth while the plate
    // lags a frame or two behind, which nobody can see.
    const moving = this._viewMoving();
    const baseDue = !this._baseReady
      || (this._dirty && (moving ? (now - this._baseDrawnAt) > 40 : true));
    const t0 = performance.now();
    const ctx = this.ctx;
    ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    ctx.clearRect(0, 0, this.w, this.h);

    /* While panning at a fixed zoom, slide the cached plate instead of
       re-stroking 85k points. Between two views with the same zoom the whole
       difference is a translation, so this is exact, not an approximation --
       the only cost is that a strip at the leading edge has no cached pixels
       yet. Redrawing is deferred until the gesture pauses (or the offset grows
       past the margin), which is what makes a drag run at the display rate
       rather than at the speed of the coastline pass. */
    /* Reuse the cached plate by transforming it to the current view instead of
       re-stroking 85k points every frame.

       The transform has to be the *same* one the markers get, or the two
       layers disagree and a point appears to slide over the coastline during a
       zoom. For a fixed geographic point, the marker layer draws it at

           c + (p - v) * k        for the current view v and scale k

       and the cached plate was built for view b at scale k_b. Expressing the
       first in terms of the second gives

           draw the plate scaled by k/k_b, translated so that b maps to
           c + (b - v) * k

       which is what the two calls below do. Getting the scale ratio wrong (an
       earlier version assumed it was always 1, i.e. translation only) is
       exactly what made the host move relative to the map while zooming. */
    let shifted = false;
    if (this._baseReady && this._baseView.zoom > 0) {
      const kRatio = this.view.zoom / this._baseView.zoom;
      /* Where to put the cached image.

         The plate is drawn as translate(dx,dy); scale(kRatio). Order matters:
         the image coordinates are scaled first, then offset. The base view's
         centre sits at (w/2, h/2) inside the cached image, and after scaling it
         lands at (w/2 * kRatio, h/2 * kRatio) -- so dx has to cancel that term
         as well. Forgetting it (the first version of this code) left the plate
         off by (kRatio - 1) * half-size, which is hundreds of pixels during a
         zoom: the host appeared to swim across the map while zooming. */
      const dx = this.view.cx - (this.w / 2) * kRatio
        + (this._baseView.lon - this.view.lon) * this._scale();
      const dy = this.view.cy - (this.h / 2) * kRatio
        + (this._baseView.projY - this.view.projY) * this._yScale();
      if (Math.abs(kRatio - 1) < 0.002) {
        // Pure translation, the common case while dragging: keep it exact by
        // drawing unscaled.
        if (Math.abs(dx) + Math.abs(dy) > 0.25
            && Math.abs(dx) < this.w * 0.5 && Math.abs(dy) < this.h * 0.5) {
          ctx.drawImage(this.base, 0, 0, this.w, this.h, dx, dy, this.w, this.h);
          shifted = true;
        }
      } else if (kRatio > 0.5 && kRatio < 2) {
        // Zoom in progress: scale about the view centre so the plate and the
        // markers move together.
        ctx.save();
        ctx.translate(dx, dy);
        ctx.scale(kRatio, kRatio);
        ctx.drawImage(this.base, 0, 0, this.w, this.h);
        ctx.restore();
        shifted = true;
      }
    }

    if (baseDue && !shifted) {
      this._drawBase();
      this._dirty = false;
    } else if (baseDue && shifted && !this._viewMoving()) {
      // The gesture has stopped: rebuild cleanly so the cached copy is exact
      // and no scaling softness or edge seam is left behind.
      this._drawBase();
      this._dirty = false;
      shifted = false;
      ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
      ctx.clearRect(0, 0, this.w, this.h);
    }
    if (!shifted) ctx.drawImage(this.base, 0, 0, this.w, this.h);
    this._drawTraces(ctx, now);
    this._drawServer(ctx, now);
    const cost = performance.now() - t0;
    const st = this.stats;
    st.frames += 1;
    st.frameMs += cost;
    if (cost > st.worstMs) st.worstMs = cost;
    if (this.opts.onFrame) {
      this.opts.onFrame({
        traces: this.traces.length,
        zoom: this.view.zoom,
        lon: this.view.lon,
        lat: projectionLat(this.view.projY),
      });
    }
    // Publish the measured cost so the console can show it instead of the
    // operator having to describe the lag.
    if (st.frames > 0 && st.frames % 120 === 0 && window.__vigilMapStats) {
      window.__vigilMapStats(this.snapshotStats());
    }
    requestAnimationFrame((t) => this._loop(t));
  }

  /** Average per-frame cost since the last read. */
  snapshotStats() {
    const st = this.stats;
    const out = {
      frames: st.frames,
      baseDraws: st.baseDraws,
      avgFrameMs: st.frames ? +(st.frameMs / st.frames).toFixed(2) : 0,
      avgBaseMs: st.baseDraws ? +(st.baseMs / st.baseDraws).toFixed(2) : 0,
      worstMs: +st.worstMs.toFixed(2),
      zoom: +this.view.zoom.toFixed(2),
      traces: this.traces.length,
    };
    this.stats = { frames: 0, baseDraws: 0, baseMs: 0, frameMs: 0, worstMs: 0 };
    // The view the cached plate was rendered for. While a pan keeps the same
    // zoom, the plate can simply be drawn at an offset instead of rebuilt.
    this._baseView = { lon: 0, projY: 0, zoom: 0 };
    return out;
  }

  start() {
    if (this._running) return;
    this._running = true;
    this._last = performance.now();
    this._dirty = true;
    this._baseReady = false;
    requestAnimationFrame((t) => this._loop(t));
  }

  stop() {
    this._running = false;
    window.removeEventListener('resize', this._onResize);
  }
}

export { VIEWS, projectionY, projectionLat };
