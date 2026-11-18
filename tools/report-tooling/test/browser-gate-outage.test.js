'use strict';

/* T-0678: a browser gate's OWN instrument failing is NOT CHECKED (exit 2), never FAIL (exit 1), and a
   crash that is not the instrument still FAILs. A FAIL says the site is broken; when the debugging
   connection is the thing that broke, the site was never read and the run learned nothing.

   Each gate's real source runs here under cdp-fixtures/cdp-outage-stub.js (`node --require`): lib/cdp.js
   and lib/page-server.js are the only false things in the run, and HL_STUB_FETCH_HTML answers the page
   fetch the gate makes before it opens a browser, so nothing reaches the network. The stub's
   HL_STUB_CDP_HARD=1 sends the same failure with no notChecked mark: that is the control, and it must
   still end FAIL, so these cases are not a gate that gives up on everything.

   The failure point in each case is the first browser command the gate issues after it has a page, so
   what is asserted is the gate's own verdict handling, not a gate that never started. */

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');

const TOOL = path.join(__dirname, '..');
const STUB = path.join(TOOL, 'cdp-fixtures', 'cdp-outage-stub.js');
const PAGE = '<!doctype html><html><head><title>t</title></head><body></body></html>';

function runGate(gate, env, args) {
  const e = {};
  Object.keys(process.env).forEach((k) => { if (!/^HL_/.test(k)) e[k] = process.env[k]; });
  Object.keys(env).forEach((k) => { if (env[k] === undefined) delete e[k]; else e[k] = env[k]; });
  return cp.spawnSync(process.execPath, ['--require', STUB, path.join(TOOL, gate)].concat(args || []),
    { encoding: 'utf8', env: e, timeout: 120000 });
}

function assertNotChecked(r, method, label) {
  assert.strictEqual(r.status, 2, label + ': exit 2, not ' + r.status + '\n' + r.stdout + r.stderr);
  assert.match(r.stdout, /NOT CHECKED .*lost before /, label + ': ' + r.stdout);
  assert.ok(r.stdout.indexOf('lost before ' + method) > -1, label + ': the outage is named, not a page finding\n' + r.stdout);
  assert.doesNotMatch(r.stdout, /^FAIL/m, label + ': no FAIL line\n' + r.stdout);
}

function assertFail(r, label) {
  assert.strictEqual(r.status, 1, label + ': an unmarked error is still FAIL (exit 1), not ' + r.status + '\n' + r.stdout + r.stderr);
  assert.match(r.stdout, /^FAIL/m, label + '\n' + r.stdout);
}

/* ---- check-browser-downloads.js: first browser command after open is armDownloads(). ---- */
const DOWNLOADS = 'check-browser-downloads.js';
const DL_ENV = { HL_STUB_FETCH_HTML: PAGE, HL_STUB_CDP_FAIL_ON: 'Browser.setDownloadBehavior' };

test('T-0678 downloads: the debugging connection lost after the browser opened is NOT CHECKED (exit 2), never FAIL', () => {
  assertNotChecked(runGate(DOWNLOADS, DL_ENV), 'Browser.setDownloadBehavior', 'downloads');
});

test('T-0678 downloads control: an error with no notChecked mark at the same point is still FAIL (exit 1)', () => {
  assertFail(runGate(DOWNLOADS, Object.assign({}, DL_ENV, { HL_STUB_CDP_HARD: '1' })), 'downloads control');
});

/* ---- check-browser-report.js: the first browser command after open is the page read in
   waitForStableInputs(), i.e. Runtime.evaluate. ---- */
const REPORT = 'check-browser-report.js';
const REPORT_ENV = { HL_STUB_FETCH_HTML: PAGE, HL_STUB_CDP_FAIL_ON: 'Runtime.evaluate' };

test('T-0678 report: the debugging connection lost after the browser opened is NOT CHECKED (exit 2), never FAIL', () => {
  assertNotChecked(runGate(REPORT, REPORT_ENV, ['xworm']), 'Runtime.evaluate', 'report');
});

test('T-0678 report control: an error with no notChecked mark at the same point is still FAIL (exit 1)', () => {
  assertFail(runGate(REPORT, Object.assign({}, REPORT_ENV, { HL_STUB_CDP_HARD: '1' }), ['xworm']), 'report control');
});

/* ---- check-browser-wire.js: BUILT mode, first browser command after open is Network.setBlockedURLs. ---- */
const WIRE = 'check-browser-wire.js';
function wireSite() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-wire-outage-'));
  fs.mkdirSync(path.join(d, 'wire'));
  fs.writeFileSync(path.join(d, 'wire', 'index.html'), PAGE);
  return d;
}
const site = wireSite();
const WIRE_ENV = { HL_SITE_DIR: site, HL_STUB_FETCH_HTML: PAGE, HL_STUB_CDP_FAIL_ON: 'Network.setBlockedURLs' };

test('T-0678 wire: the debugging connection lost after the browser opened is NOT CHECKED (exit 2), never FAIL', () => {
  assertNotChecked(runGate(WIRE, WIRE_ENV), 'Network.setBlockedURLs', 'wire');
});

test('T-0678 wire control: an error with no notChecked mark at the same point is still FAIL (exit 1)', () => {
  assertFail(runGate(WIRE, Object.assign({}, WIRE_ENV, { HL_STUB_CDP_HARD: '1' })), 'wire control');
});
