'use strict';

/* T-0500.1.7.4 fix-r2, review findings S1, S5 and S6, driven through the REAL gate in a real Chromium on scratch sites the test writes itself (RFC 5737 / RFC 2606 fixtures).
   Opt-in, because it launches a browser, and a browser runs only under the shared lock:

     flock /home/jharrison/ai-workflows/tasks/runs/T-0500.1.10/gate.lock env HL_CDP_LIVE_TESTS=1 node --test test/browser-defang-live.test.js

   Without HL_CDP_LIVE_TESTS=1 every test is skipped and says so (NOT CHECKED, not passed). Each planted page has a clean twin; the gate must report the planted ones for their own defect and
   the twins not at all. */
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');

const LIVE = process.env.HL_CDP_LIVE_TESTS === '1';
const SKIP = LIVE ? false : 'NOT CHECKED: set HL_CDP_LIVE_TESTS=1 (under the shared browser lock) to launch the real browser';
const GATE = path.join(process.env.HL_GATE_DIR || path.join(__dirname, '..'), 'check-browser-defang.js');

const PAGE = (body, script) => '<!doctype html><html><head><meta charset="utf-8"><title>t</title></head><body><main>' + body + '</main>' + (script ? '<script>' + script + '</script>' : '') + '</body></html>';
const BTN = (label) => '<button type="button" id="b">' + label + '</button>';
const ON_CLICK = (js) => 'document.getElementById("b").addEventListener("click",function(){' + js + '});';
const RAW = 'C2 at 198.51.100.17 and evil-host.example.xyz';
const SAFE = 'C2 at 198[.]51[.]100[.]17 and evil-host[.]example[.]xyz';

const PAGES = {
  // clean twins
  'reports/clean-copy/index.html': PAGE(BTN('Copy indicator'), ON_CLICK('navigator.clipboard.writeText("' + SAFE + '");')),
  'hunting-detections/rule-copy/index.html': PAGE('<pre>' + BTN('Copy rule') + ' rule body ' + RAW + '</pre>', ON_CLICK('navigator.clipboard.writeText("' + RAW + '");')),
  'hunting-detections/picker/index.html': PAGE('<div class="hl-picker"><button type="button" class="hl-picker__btn" id="b" data-act="dl">Download selected</button></div>',
    ON_CLICK('URL.createObjectURL(new Blob(["rule: ' + RAW + '"],{type:"text/plain"}));')),
  'actors/UTA-2/index.html': PAGE('<p>safe text</p><input id="q" type="text">' + BTN('Copy x'), 'setTimeout(function(){document.getElementById("q").value="' + SAFE + '";},150);' + ON_CLICK('navigator.clipboard.writeText("ok");')),
  // planted
  'reports/raw-share/index.html': PAGE(BTN('Share this report'), ON_CLICK('navigator.share({title:"' + RAW + '",url:location.href});')),
  'hunting-detections/raw-share/index.html': PAGE(BTN('Share this rule'), ON_CLICK('navigator.share({title:"' + RAW + '",url:location.href});')),
  'hunting-detections/loose-copy/index.html': PAGE(BTN('Copy link'), ON_CLICK('navigator.clipboard.writeText("http://198.51.100.17/x");')),
  'actors/UTA-1/index.html': PAGE('<p>safe text</p><input id="q" type="text">' + BTN('Copy x'), 'setTimeout(function(){document.getElementById("q").value="' + RAW + '";},150);' + ON_CLICK('navigator.clipboard.writeText("ok");')),
  'home-planted-index.html': null
};
delete PAGES['home-planted-index.html'];
const CLEAN = ['reports/clean-copy', 'hunting-detections/rule-copy', 'hunting-detections/picker', 'actors/UTA-2'];
const PLANTED = { 'reports/raw-share': /^share:/, 'hunting-detections/raw-share': /^share:/, 'hunting-detections/loose-copy': /^clip:/, 'actors/UTA-1': /^attr:value$/ };

function site(files) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-bdl-'));
  Object.keys(files).forEach((rel) => { const f = path.join(d, rel); fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, files[rel]); });
  return d;
}
function run(d, extra) {
  const out = path.join(d, '..', path.basename(d) + '.json');
  const r = cp.spawnSync('node', [GATE, '--site', d, '--out', out].concat(extra || []), { encoding: 'utf8', timeout: 240000 });
  return { status: r.status, stdout: r.stdout + r.stderr, json: fs.existsSync(out) ? JSON.parse(fs.readFileSync(out, 'utf8')) : null };
}

test('LIVE S5 and S6: the gate fails a raw share on a detection page, a loose copy there and a script-written input value; it passes a rule-block copy, the picker bundle and the clean twins', { skip: SKIP }, () => {
  const r = run(site(PAGES));
  assert.strictEqual(r.status, 1, r.stdout);
  const by = {};
  r.json.findings.forEach((f) => { (by[f.page.replace(/\/index\.html$/, '')] = by[f.page.replace(/\/index\.html$/, '')] || []).push(f.ctx); });
  Object.keys(PLANTED).forEach((p) => assert.ok((by[p] || []).some((c) => PLANTED[p].test(c)), p + ' reported for its own defect: ' + JSON.stringify(by[p])));
  CLEAN.forEach((p) => {
    assert.ok(r.json.perPage[p + '/index.html'] && r.json.perPage[p + '/index.html'].runs > 0, p + ' was visited');
    assert.strictEqual((by[p] || []).length, 0, p + ' (clean twin) is not reported: ' + JSON.stringify(by[p]));
  });
  assert.ok(r.json.totals.exempt >= 2, 'the rule-block copy and the picker bundle were counted as exempt (' + r.json.totals.exempt + ')');
});

test('LIVE S1: the clean twins alone are PASS (exit 0, the control); with an IOC search page whose index cannot be read the same run is NOT CHECKED (exit 2)', { skip: SKIP }, () => {
  const twins = {};
  CLEAN.forEach((p) => { twins[p + '/index.html'] = PAGES[p + '/index.html']; });
  const ok = run(site(twins));
  assert.strictEqual(ok.status, 0, ok.stdout);
  assert.match(ok.stdout, /^PASS /m);
  const withSearch = Object.assign({}, twins, {
    'ioc-feeds/index.html': PAGE('<textarea class="hl-iocsearch__in"></textarea><div class="hl-iocsearch__result"></div>') });
  const nc = run(site(withSearch));
  assert.strictEqual(nc.status, 2, nc.stdout);
  assert.match(nc.stdout, /NOT CHECKED .*ioc-index\.json unreadable/);
  assert.match(nc.stdout, /^NOT CHECKED /m);
  assert.doesNotMatch(nc.stdout, /^PASS /m);
  assert.strictEqual(nc.json.verdict, 'NOT CHECKED');
  // a FAIL outranks the NOT CHECKED surface
  const both = run(site(Object.assign({}, withSearch, { 'reports/raw-share/index.html': PAGES['reports/raw-share/index.html'] })));
  assert.strictEqual(both.status, 1, both.stdout);
});
