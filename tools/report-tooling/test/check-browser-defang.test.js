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

test('wireDetailsSplit: a finding in a Wire details panel is exempt only when its token is a string of the details file; a token the file does not hold is kept (the browser control covers the page-type scope)', () => {
  const sc = S.makeScanner(ALLOW);
  const file = JSON.stringify({ rows: { 'cve-1': { desc: 'Cisco ASA Software: 9.16.2.7 and Outlook.com, see https://help.example-vendor.com/a b', fixed: ['9.16.2.11'] } } });
  const strings = S.wireDetailsStrings(file);
  assert.deepStrictEqual(strings.length, 2, 'every string value is read, nested and in arrays');
  const panel = PAGE('<div class="hl-dt__panel"><p>Cisco ASA Software: 9.16.2.7 and Outlook.com</p><p>Planted: C2 at 198.51.100.17</p></div>');
  const found = sc.scan('wire/index.html', panel);
  assert.ok(found.length >= 3, 'the unexempted scanner flags the version, the vendor name and the planted address: ' + JSON.stringify(found.map((f) => f.token)));
  const sp = S.wireDetailsSplit(found, strings);
  assert.deepStrictEqual(sp.kept.map((f) => f.token), ['198.51.100.17'], 'only the planted address is kept');
  assert.ok(sp.exempt.length >= 2 && sp.exempt.every((f) => /9\.16\.2\.7|Outlook\.com/.test(f.token)));
  assert.strictEqual(S.wireDetailsSplit(found, []).kept.length, found.length, 'an empty or unreadable details file exempts nothing');
});

/* ---- fix-r2, review finding S4: a literal is exempt as a WHOLE cell, never as a substring, and a network-bearing path is not a literal ----
   The reviewer's two probes: a filename literal "evil-host.example.xyz" removed from a copied "http://evil-host.example.xyz/a" left zero findings, and a UNC path with a raw host
   (data-literal="path") was accepted as a literal and its cell skipped. The controls are the cases that must still pass: the literal as the whole line, as a whole CSV field (quoted or
   not), an ordinary Windows path and a filename that looks like a domain (gs.sh). The names are RFC 2606 / the review's own fixture. */
const UNC = String.fromCharCode(92, 92) + 'evil-host.example.xyz' + String.fromCharCode(92) + 'share';
test('S4: the literal exemption is whole-field: a filename literal does not hide the same host inside a copied URL or a longer line', () => {
  const sc = S.makeScanner(ALLOW);
  const P = 'ioc-feeds/x/index.html';
  const lits = [{ type: 'filename', value: 'evil-host.example.xyz' }];
  assert.ok(sc.scanText(P, 'clip:copy', 'http://evil-host.example.xyz/a', lits).length >= 1, 'a URL that holds the literal as a substring is judged (the review probe)');
  assert.ok(sc.scanText(P, 'clip:copy', 'evil-host.example.xyz,beacon http://evil-host.example.xyz/a', lits).length >= 1, 'a URL inside another field of the row is judged');
  assert.ok(sc.scanText(P, 'clip:copy', 'see evil-host.example.xyz now', lits).length >= 1, 'the literal inside a sentence is not a whole cell');
  assert.ok(sc.scanText(P, 'clip:copy', 'evil-host.example.xyz.other.net', lits).length >= 1, 'a longer name that starts with the literal is judged');
  // controls: the whole cell, in every shape the viewer writes it, still passes
  assert.deepStrictEqual(sc.scanText(P, 'clip:copy', 'evil-host.example.xyz', lits), [], '.txt / clipboard line that is the literal');
  assert.deepStrictEqual(sc.scanText(P, 'blob:csv', 'evil-host.example.xyz,filename,dropped,HIGH', lits), [], 'csv first field');
  assert.deepStrictEqual(sc.scanText(P, 'blob:csv', '"evil-host.example.xyz",filename,"dropped, then run"', lits), [], 'csv quoted field');
  assert.deepStrictEqual(sc.scanText(P, 'blob:csv', 'value,type\nevil-host.example.xyz\tfilename', lits), [], 'a tab-separated field');
  assert.ok(sc.scanText(P, 'blob:csv', 'hxxp://x[.]example[.]xyz/a,filename', []).length === 0, 'control: a defanged value passes with no literal list');
});
test('S4: a network-bearing path, filename or registry value is not a literal: the DOM cell is judged and the capture exemption is refused', () => {
  const sc = S.makeScanner(ALLOW);
  const P = 'ioc-feeds/x/index.html';
  const bad = sc.scan(P, PAGE('<p>safe text</p><code data-literal="path">' + UNC + '</code>'));
  assert.ok(bad.some((f) => f.kind === 'LITERAL-MISUSE'), 'the UNC path cell is reported as a misused literal: ' + JSON.stringify(bad.map((f) => f.kind)));
  assert.ok(bad.some((f) => f.ctx !== 'literal'), 'and its text is judged like prose, so the raw host is a finding in its own right');
  assert.ok(sc.scanText(P, 'clip:copy', UNC, [{ type: 'path', value: UNC }]).length >= 1, 'a UNC path is not honoured as a captured literal either');
  [['filename', 'http://evil-host.example.xyz/x.exe'], ['filename', '1468_US_23.106.161.1_28-01-26.cab'], ['registry', 'HKLM' + String.fromCharCode(92) + 'x' + String.fromCharCode(92) + 'http://evil-host.example.xyz'],
   ['path', '//evil-host.example.xyz/share']].forEach(([ty, v]) => {
    assert.ok(sc.scan(P, PAGE('<code data-literal="' + ty + '">' + v + '</code>')).some((f) => f.kind === 'LITERAL-MISUSE'), ty + ' ' + v);
  });
  // controls: an ordinary Windows path, a registry key, a filename that merely looks like a domain and a version number in a name stay literal
  [['path', 'C:' + String.fromCharCode(92) + 'Windows' + String.fromCharCode(92) + 'x.exe'], ['registry', 'HKLM' + String.fromCharCode(92) + 'SYSTEM' + String.fromCharCode(92) + 'Svc.Key'],
   ['filename', 'gs.sh'], ['filename', 'setup_1.2.exe'], ['sha256', 'a'.repeat(64)]].forEach(([ty, v]) => {
    assert.deepStrictEqual(sc.scan(P, PAGE('<code data-literal="' + ty + '">' + v + '</code>')), [], ty + ' ' + v + ' stays literal');
  });
});
