'use strict';

/* check-browser-defang.js needs a real Chromium, which `npm test` does not start (the browser gates run under the shared lock). What this suite proves is the part that does not need one:
   the page selection (--list), the exit status of a run that selects nothing, and the scanner the browser gate hands the rendered DOM and every captured string to (lib/defang-site.js
   makeScanner), each against a planted positive and its clean twin. The browser half is exercised by check-browser-defang-control.sh (staged in tasks/runs/T-0500.1.7.4/build/fix-r1/). */
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');
const S = require('../lib/defang-site.js');

const ALLOW = path.join(__dirname, '..', '..', '..', '_data', 'defang_allow.yml');
const GATE = path.join(__dirname, '..', 'check-browser-defang.js');

function site(files) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-bdg-'));
  Object.keys(files).forEach((rel) => { const f = path.join(d, rel); fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, files[rel]); });
  return d;
}
const PAGE = (body) => '<!doctype html><html><head><title>t</title></head><body><main>' + body + '</main></body></html>';

test('--list selects every page of a small type and samples a big one at even spacing, naming both', () => {
  const files = {};
  for (let i = 0; i < 12; i++) files['actors/UTA-' + i + '/index.html'] = PAGE('<p>x</p>');
  files['index.html'] = PAGE('<p>home</p>');
  files['pagefind/index.html'] = PAGE('<p>asset directory: excluded</p>');
  const d = site(files);
  const all = cp.spawnSync('node', [GATE, '--site', d, '--list'], { encoding: 'utf8' });
  assert.strictEqual(all.status, 0);
  assert.match(all.stdout, /# 13 of 13 pages; actor: all 12; home: all 1/, 'the excluded asset directory is not counted');
  const some = cp.spawnSync('node', [GATE, '--site', d, '--list', '--sample', '4'], { encoding: 'utf8' });
  assert.match(some.stdout, /# 5 of 13 pages; actor: sampled 4 of 12; home: all 1/);
});

test('a run that selects no page FAILs (exit 1): a gate that visits nothing passes nothing', () => {
  const d = site({ 'index.html': PAGE('<p>home</p>') });
  const r = cp.spawnSync('node', [GATE, '--site', d, '--only', '^no-such-page$'], { encoding: 'utf8' });
  assert.strictEqual(r.status, 1);
  assert.match(r.stdout, /no page selected/);
});

test('a missing --site is NOT CHECKED (exit 2), never a pass', () => {
  const r = cp.spawnSync('node', [GATE], { encoding: 'utf8' });
  assert.strictEqual(r.status, 2);
  assert.match(r.stdout, /NOT CHECKED/);
});

test('makeScanner: the DOM a page has after its scripts ran is judged like a built page (planted raw text, tooltip and link fail; the clean twin passes)', () => {
  const sc = S.makeScanner(ALLOW);
  const bad = sc.scan('actors/UTA-1/index.html', PAGE('<p>Planted: C2 at 198.51.100.17 and evil-host.example.xyz</p><p title="198.51.100.77">tip</p><a href="http://198.51.100.17/x">go</a>'));
  assert.ok(bad.length >= 3, 'text, tooltip and link: ' + JSON.stringify(bad.map((f) => f.kind)));
  const good = sc.scan('actors/UTA-2/index.html', PAGE('<p>Planted: C2 at 198[.]51[.]100[.]17 and evil-host[.]example[.]xyz</p><p title="198[.]51[.]100[.]77">tip</p>'));
  assert.deepStrictEqual(good, []);
});

test('makeScanner.scanText: a copied, shared or downloaded string is judged line by line; a defanged or hash-only string passes', () => {
  const sc = S.makeScanner(ALLOW);
  const bad = sc.scanText('reports/x/index.html', 'clip:copy', 'http://198.51.100.17/payload.php\nevil-host.example.xyz');
  assert.strictEqual(bad.length, 2);
  assert.ok(bad.every((f) => f.ctx === 'clip:copy'));
  assert.deepStrictEqual(sc.scanText('reports/x/index.html', 'clip:copy', 'hxxp://198[.]51[.]100[.]17/payload[.]php\n' + 'a'.repeat(64)), []);
});

test('makeScanner.scanText with the page\'s data-literal cells: a captured filename that looks like a domain passes, a raw address on the same line or a URL-shaped "literal" still fails (the exemption cannot hide a raw indicator)', () => {
  const sc = S.makeScanner(ALLOW);
  const lits = [{ type: 'filename', value: 'gs.sh' }, { type: 'filename', value: 'http://198.51.100.17/a' }, { type: 'sha256', value: '198.51.100.17' }];
  const P = 'ioc-feeds/x/index.html';
  assert.ok(sc.scanText(P, 'clip:copy', 'gs.sh').length >= 1, 'without the literal list the filename is judged as a domain (control)');
  assert.deepStrictEqual(sc.scanText(P, 'clip:copy', 'gs.sh,filename,,HIGH', lits), []);
  assert.ok(sc.scanText(P, 'clip:copy', 'gs.sh,beacon 198.51.100.17', lits).length >= 1, 'a raw address next to a literal is still flagged');
  assert.ok(sc.scanText(P, 'clip:copy', 'http://198.51.100.17/a', lits).length >= 1, 'a URL-shaped value is never honoured as literal');
  assert.ok(sc.scanText(P, 'clip:copy', '198.51.100.17', lits).length >= 1, 'a sha256 cell that is not a hash is never honoured');
});
