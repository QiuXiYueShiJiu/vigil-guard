/* Two CSS mistakes that both look like "a mystery overlay on the page":
 *
 * 1. A class that sets `display` on an element whose visibility is controlled
 *    by the `hidden` attribute. A class selector beats the browser's built-in
 *    `[hidden] { display: none }`, so the element stays on screen. That is
 *    exactly what happened to the modal overlay: z-index 10001, a dim wash and
 *    a blur over every page, including the login form.
 * 2. A stray backdrop-filter on a full-viewport layer.
 *
 * Neither is visible in a screenshot as a wrong colour, which is why both cost
 * a while to find. This test reads the deployed CSS directly.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

/* Repository stylesheets by default, so the check runs before a deploy; set
   VIGIL_ASSET_DIR to the published directory to check what nginx serves.
   Neither path carries a host. */
const root = process.env.VIGIL_ASSET_DIR
  || fileURLToPath(new URL('../../frontend/assets/', import.meta.url));
// Deployed assets carry a content hash in the name, so resolve them.
const present = readdirSync(root);
const find = (stem) => present.find((n) => n.startsWith(stem + '.') && n.endsWith('.css'));
const files = ['base', 'admin', 'home'].map((stem) => {
  const name = find(stem);
  if (!name) return { name: stem + '.css', text: '' };
  try { return { name, text: readFileSync(root + name, 'utf8') }; }
  catch { return { name, text: '' }; }
});
console.log('  读取:', files.map((f) => f.name).join(', '));

let fail = 0;
const check = (name, ok, detail) => {
  console.log('  ' + (ok ? '✓' : '✗') + ' ' + name + (detail ? '  (' + detail + ')' : ''));
  if (!ok) fail++;
};

const pick = (stem) => (files.find((f) => f.name.startsWith(stem + '.')) || { text: '' }).text;
const base = pick('base');
check('[hidden] 被强制隐藏', /\[hidden\]\s*\{[^}]*display:\s*none\s*!important/.test(base),
  '浏览器默认规则会被 class 覆盖，必须显式压过');

// .modal-host 同时带 hidden 属性和 display:flex，是这次的元凶
const modalRule = base.match(/\.modal-host\s*\{([^}]*)\}/);
check('.modal-host 的 display 由 [hidden] 优先', Boolean(modalRule)
  && /\[hidden\]\s*\{[^}]*display:\s*none\s*!important/.test(base),
  modalRule ? '规则存在，靠 [hidden] 压制' : '未找到 .modal-host');

// 登录层不得有滤镜
const admin = pick('admin');
const gateBlock = admin.match(/\.gate\s*\{([^}]*)\}/);
check('登录层无 backdrop-filter',
  Boolean(gateBlock) && !/backdrop-filter/.test(gateBlock[1])
  || /\.gate\s*\{[^}]*backdrop-filter:\s*none/.test(admin),
  gateBlock ? '已声明 none' : '未找到 .gate');

// 全屏层清单，供人工核对
const fullscreen = [];
for (const f of files) {
  for (const m of f.text.matchAll(/([^{}]+)\{([^}]*)\}/g)) {
    const body = m[2];
    if (/position:\s*fixed/.test(body) && /inset:\s*0/.test(body)) {
      const blur = /backdrop-filter:\s*(?!none)[^;]+/.exec(body);
      fullscreen.push({ file: f.name, sel: m[1].trim().split('\n').pop().trim(), blur: blur ? blur[0] : '' });
    }
  }
}
console.log('  全屏固定层（人工核对）:');
for (const item of fullscreen) {
  console.log('    ' + item.file + ' ' + item.sel + (item.blur ? '  ' + item.blur : ''));
}

console.log(fail ? '\nFAIL: CSS 覆盖检查未通过' : '\nPASS: 无隐藏元素被强制显示，登录层无滤镜');
process.exit(fail ? 1 : 0);
