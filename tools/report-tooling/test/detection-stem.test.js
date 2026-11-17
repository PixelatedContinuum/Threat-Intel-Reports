'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { detectionStem } = require('../lib/detection-stem.js');

const DIR = path.join(__dirname, '..', '..', '..', 'hunting-detections');

/* Every detection page in the corpus resolves, by its own permalink, to the
   file that serves it. This is the control: it includes the one page whose
   permalink is shorter than its file name (T-0635), which the old URL-tail
   rule resolved to a file that does not exist. */
test('every detection permalink resolves to the file that carries it', () => {
  let checked = 0, shortened = 0;
  for (const f of fs.readdirSync(DIR)) {
    if (!f.endsWith('.md') || f === 'index.md') continue;
    const fm = /^---\r?\n([\s\S]*?)\r?\n---/.exec(fs.readFileSync(path.join(DIR, f), 'utf8'));
    const p = fm && /^permalink:\s*["']?([^"'\s#]+)/m.exec(fm[1]);
    if (!p) continue;
    const stem = f.replace(/\.md$/, '');
    assert.equal(detectionStem(p[1]), stem, f);
    assert.equal(detectionStem(p[1].replace(/\/+$/, '')), stem, f + ' (catalog form, no slash)');
    if (p[1].replace(/\/+$/, '').split('/').pop() !== stem) shortened++;
    checked++;
  }
  assert.ok(checked > 0, 'no detection page was checked');
  console.log(`detection-stem: ${checked} page(s) checked, ${shortened} with a permalink unlike the file name`);
});

test('a URL with no matching permalink keeps the old tail rule', () => {
  assert.equal(detectionStem('/hunting-detections/no-such-page-t0635-detections'), 'no-such-page-t0635-detections');
});
