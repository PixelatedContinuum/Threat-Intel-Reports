'use strict';

/* The post-build link gate (check-links.js), run as a process over a small built site made
   in a temp directory. Each planted defect has a clean twin (the control). T-0603, M1. */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const CL = require('../lib/check-links.js');

const GATE = path.join(__dirname, '..', 'check-links.js');

function site(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-links-'));
  Object.keys(files).forEach((rel) => {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, files[rel]);
  });
  return dir;
}
function gate(dir, extra) {
  return spawnSync(process.execPath, [GATE, '--site', dir].concat(extra || []), { encoding: 'utf8' });
}
const page = (body) => '<html><body>' + body + '</body></html>';
const GOOD = {
  'index.html': page('<a href="/reports/a/">a</a> <a href="/ioc-feeds/a.json">feed</a> <a href="/reports/a/#top">t</a>'),
  'reports/a/index.html': page('<h1 id="top">A</h1><a href="#top">up</a> <a href="https://example.org/x/">ext</a>'),
  'ioc-feeds/a.json': '{}'
};

test('a clean site passes and prints its denominators', () => {
  const d = site(GOOD);
  try {
    const r = gate(d);
    assert.strictEqual(r.status, 0, r.stdout);
    assert.match(r.stdout, /^PASS .*\(2 pages, \d+ internal links/);
    assert.match(r.stdout, /control 11\/11 rows held/);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('planted: a trailing slash on a file fails and is named; the corrected twin passes', () => {
  const bad = Object.assign({}, GOOD, { 'index.html': page('<a href="/ioc-feeds/a.json/">feed</a><a href="/reports/a/">a</a>') });
  const d = site(bad);
  try {
    const r = gate(d);
    assert.strictEqual(r.status, 1, r.stdout);
    assert.match(r.stdout, /slash on a file\s+1 of/);
    assert.match(r.stdout, /FAIL slash-on-file\s+\/ioc-feeds\/a\.json\//);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('planted: a link to a page that does not exist fails', () => {
  const d = site(Object.assign({}, GOOD, { 'index.html': page('<a href="/reports/a/">a</a><a href="/hunting-detections/none/">x</a>') }));
  try {
    const r = gate(d);
    assert.strictEqual(r.status, 1, r.stdout);
    assert.match(r.stdout, /dead links\s+1 of/);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('planted: a #fragment with no id fails, and --anchors warn reports it without failing', () => {
  const d = site(Object.assign({}, GOOD, { 'index.html': page('<a href="/reports/a/#nope">x</a><a href="/reports/a/">a</a>') }));
  try {
    assert.strictEqual(gate(d).status, 1);
    const w = gate(d, ['--anchors', 'warn']);
    assert.strictEqual(w.status, 0, w.stdout);
    assert.match(w.stdout, /dead #anchors\s+1 of/);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('a site with no pages, a missing directory, and a bad flag are NOT CHECKED, exit 2', () => {
  const d = site({ 'a.json': '{}' });
  try {
    assert.strictEqual(gate(d).status, 2);
    assert.strictEqual(gate(path.join(d, 'nope')).status, 2);
    assert.strictEqual(gate(d, ['--anchors', 'x']).status, 2);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('a site whose pages hold no internal link is NOT CHECKED, not PASS', () => {
  const d = site({ 'index.html': page('<a href="https://example.org/">x</a>') });
  try {
    const r = gate(d);
    assert.strictEqual(r.status, 2, r.stdout);
    assert.match(r.stdout, /0 internal links/);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('the resolver follows the host: /x.json/ is a 404, /x.json serves, /x serves x.html', () => {
  const files = { 'x.json': 1, 'about.html': 1, 'r/index.html': 1 };
  const fsx = { isFile: (r) => !!files[r], isDir: (r) => r === 'r' };
  assert.strictEqual(CL.resolve('/x.json/', fsx, 'index.html'), null);
  assert.strictEqual(CL.resolve('/x.json', fsx, 'index.html'), 'x.json');
  assert.strictEqual(CL.resolve('/about', fsx, 'index.html'), 'about.html');
  assert.strictEqual(CL.resolve('/r', fsx, 'index.html'), 'r/index.html');
  assert.strictEqual(CL.resolve('../r/', fsx, 'q/index.html'), 'r/index.html');
  assert.strictEqual(CL.control().bad.length, 0);
});
