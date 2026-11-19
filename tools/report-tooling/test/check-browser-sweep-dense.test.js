'use strict';
/* T-0537 round 2 (luna review of final b88c2963): the dense-report pick must check the
   preferred slug's content too, not only that its page exists. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

function site(pages) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-sweep-dense-'));
  for (const [url, html] of Object.entries(pages)) {
    fs.mkdirSync(path.join(dir, url), { recursive: true });
    fs.writeFileSync(path.join(dir, url, 'index.html'), html);
  }
  return dir;
}
function load(dir) {
  process.env.HL_SITE_DIR = dir;
  delete require.cache[require.resolve('../check-browser-sweep.js')];
  return require('../check-browser-sweep.js');
}
const DENSE = '<pre class="highlight"><code>x</code></pre><table><tr><td>1</td></tr></table>';

test('a preferred page that lost its code or table is not picked; the search finds a dense one', () => {
  const dir = site({ 'reports/new-enc-exe': '<p>prose only</p>', 'reports/zz-dense': DENSE });
  assert.strictEqual(load(dir).pickDenseReport(), '/reports/zz-dense/');
});
test('the preferred page is picked while it still holds both (control)', () => {
  const dir = site({ 'reports/new-enc-exe': DENSE, 'reports/aa-dense': DENSE });
  assert.strictEqual(load(dir).pickDenseReport(), '/reports/new-enc-exe/');
});
test('no dense page anywhere gives null, never a page without both', () => {
  const dir = site({ 'reports/new-enc-exe': '<table></table>', 'reports/b': '<pre class="highlight"></pre>' });
  assert.strictEqual(load(dir).pickDenseReport(), null);
});
