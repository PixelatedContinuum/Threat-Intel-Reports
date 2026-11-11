'use strict';

/* The companion-value gate (check-companions.js): detection_page, ioc_feed and stix_bundle in a
   report's front matter must name something that exists. Run as a process over a temp repo.
   T-0603, M39. */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const GATE = path.join(__dirname, '..', 'check-companions.js');

function repo(reportFm) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-comp-'));
  const w = (rel, text) => {
    const p = path.join(d, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, text);
  };
  w('hunting-detections/a-detections.md', '---\npermalink: /hunting-detections/a-detections/\nredirect_from: /hunting-detections/a/\n---\n');
  w('ioc-feeds/a/index.md', '---\npermalink: /ioc-feeds/a/\nioc_slug: "a.json"\n---\n');
  w('ioc-feeds/a.json', '{}');
  w('stix/a.json', '{}');
  w('reports/a/index.md', '---\ntitle: A\npermalink: /reports/a/\n' + reportFm + '---\nbody\n');
  return d;
}
const GOODFM = 'detection_page: /hunting-detections/a-detections/\nioc_feed: /ioc-feeds/a/\nstix_bundle: /stix/a.json\n';
function run(d) { return spawnSync(process.execPath, [GATE, '--root', d], { encoding: 'utf8' }); }
function withRepo(fm, fn) {
  const d = repo(fm);
  try { fn(d); } finally { fs.rmSync(d, { recursive: true, force: true }); }
}

test('real companion values pass, with the denominator', () => {
  withRepo(GOODFM, (d) => {
    const r = run(d);
    assert.strictEqual(r.status, 0, r.stdout);
    assert.match(r.stdout, /^PASS .*\(3 companion values in 1 of 1 report files/);
  });
});

test('planted: a detection_page naming a page that does not exist fails', () => {
  withRepo(GOODFM.replace('a-detections/', 'no-such-page/'), (d) => {
    const r = run(d);
    assert.strictEqual(r.status, 1, r.stdout);
    assert.match(r.stdout, /FAIL  a\/index\.md: detection_page \/hunting-detections\/no-such-page\//);
  });
});

test('planted: an ioc_feed naming a page that does not exist fails; a missing trailing slash is named', () => {
  withRepo(GOODFM.replace('/ioc-feeds/a/', '/ioc-feeds/nothing'), (d) => {
    const r = run(d);
    assert.strictEqual(r.status, 1, r.stdout);
    assert.match(r.stdout, /ioc_feed \/ioc-feeds\/nothing matches no source page/);
    assert.match(r.stdout, /no trailing slash/);
  });
});

test('planted: a stix_bundle naming no file fails', () => {
  withRepo(GOODFM.replace('stix/a.json', 'stix/gone.json'), (d) => {
    assert.strictEqual(run(d).status, 1);
  });
});

test('a value that resolves only through a redirect_from stub passes and is counted', () => {
  withRepo('detection_page: /hunting-detections/a/\n', (d) => {
    const r = run(d);
    assert.strictEqual(r.status, 0, r.stdout);
    assert.match(r.stdout, /1 only through a redirect_from stub/);
  });
});

test('a report with no companion value at all is NOT CHECKED, not PASS', () => {
  withRepo('', (d) => {
    const r = run(d);
    assert.strictEqual(r.status, 2, r.stdout);
    assert.match(r.stdout, /^NOT CHECKED/);
  });
});

test('a tree with no reports directory is NOT CHECKED', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-comp-'));
  try { assert.strictEqual(run(d).status, 2); } finally { fs.rmSync(d, { recursive: true, force: true }); }
});
