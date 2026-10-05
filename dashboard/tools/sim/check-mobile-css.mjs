/* 手机上的这次塌陷：顶栏固定高度 + 不换行 + 主机名不可截断，三者叠加导致
   同一行的文字被挤成竖排。这个检查不渲染像素，只核对那几条"必须存在"的
   声明——它们一旦被删掉，症状会原样回来。 */
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

/* Read the repository's own stylesheets by default, so the check works before
   a deploy; point VIGIL_ASSET_DIR at the published (content-hashed) directory
   to check what nginx is actually serving. Neither path names a host. */
const root = process.env.VIGIL_ASSET_DIR
  || fileURLToPath(new URL('../../frontend/assets/', import.meta.url));
const name = readdirSync(root).find((n) => n.startsWith('admin.') && n.endsWith('.css'));
const css = readFileSync(root + name, 'utf8');

// 取出 860px 断点那段
const block = css.slice(css.indexOf('@media (max-width: 860px)'));
const mobile = block.slice(0, block.indexOf('@media (max-width: 420px)') + 1);

let fail = 0;
const check = (label, ok) => {
  console.log('  ' + (ok ? '✓' : '✗') + ' ' + label);
  if (!ok) fail++;
};
const has = (re) => re.test(mobile);

console.log('  读取:', name);
check('顶栏允许换行（否则主机名把同排元素挤竖排）', has(/\.admin-top\s*\{[^}]*flex-wrap:\s*wrap/));
check('顶栏高度自适应而非固定', has(/\.admin-top\s*\{[^}]*height:\s*auto/));
check('主机名可截断', has(/\.admin-top\s*\.host-chip\s*\{[^}]*text-overflow:\s*ellipsis/));
check('主机名有宽度上限', has(/\.admin-top\s*\.host-chip\s*\{[^}]*max-width/));
check('窄屏隐藏次要文字（标题副文案）', has(/\.title span\s*\{\s*display:\s*none/));
check('窄屏隐藏「管理员」', has(/\.admin-top\s*\.who\s*\{\s*display:\s*none/));
check('指标卡改单列', has(/\.cards\s*\{\s*grid-template-columns:\s*1fr/));
check('指标数值用带前缀的选择器（否则被桌面规则覆盖）', has(/\.metric\s+\.m-value\s*\{[^}]*font-size/));
check('表格自己横向滚动', has(/\.table-wrap\s*\{[^}]*overflow-x:\s*auto/));

// 桌面规则不能被破坏
check('桌面端指标数值仍是 22px', /\.metric \.m-value \{ font-size: 22px/.test(css));
// .topbar 的桌面规则在 base.css 里，别在 admin.css 里找
const baseName = readdirSync(root).find((n) => n.startsWith('base.') && n.endsWith('.css'));
const baseCss = readFileSync(root + baseName, 'utf8');
check('桌面端顶栏仍是固定高度（base.css）',
  /\.topbar \{[^}]*height: var\(--topbar-h\)/.test(baseCss));

console.log(fail ? '\nFAIL: 移动端布局规则缺失' : '\nPASS: 移动端布局规则完整');
process.exit(fail ? 1 : 0);
