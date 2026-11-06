'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path');
const CW = require('../lib/check-wire');
const root = path.resolve(__dirname, '../../..');
const src = fs.readFileSync(path.join(root, 'wire/index.md'), 'utf8');
const includes = Object.fromEntries(fs.readdirSync(path.join(root, '_includes')).filter(n => /^wire-.*\.html$/.test(n)).map(n => [n, fs.readFileSync(path.join(root, '_includes', n), 'utf8')]));
const check = s => CW.checkPage(s, includes);
test('both explanation panels pass check-wire with the full page as control', () => {
  assert.equal(check(src).status, 'PASS');
  assert.equal((src.match(/<summary>Explanation and data used<\/summary>/g) || []).length, 2);
});
for (const id of ['nkev-explanation', 'cves-explanation']) {
  const panel = src.match(new RegExp('<details class="hl-wire-explanation" id="' + id + '"[^>]*>[\\s\\S]*?</details>'))[0];
  test(id + ' removal, duplication, open default, wrong title and dash controls fail', () => {
    for (const changed of ['', panel + panel, panel.replace('<details ', '<details open '), panel.replace('Explanation and data used', 'More'), ...['—', '–', '&mdash;', '&#8211;', '&#x2014;'].map(dash => panel.replace('</p>', dash + '</p>'))]) {
      const result = check(src.replace(panel, changed));
      assert.equal(result.status, 'FAIL');
      assert.match(result.problems.join(' '), /explanation|Explanation/);
    }
  });
}
