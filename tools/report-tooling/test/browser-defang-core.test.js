'use strict';

/* T-0500.1.7.4 fix-r2, review findings S1, S5 and S6: the browser defang gate's verdict, its capture exemption and its input-value reading, held without a browser.
   (The same behaviours are driven through a real Chromium by test/browser-defang-live.test.js, opt-in under the shared browser lock.) Addresses and names are RFC 5737 / RFC 2606 fixtures. */
const { test } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { JSDOM } = require('jsdom');
const CORE = require('../lib/browser-defang-core.js');
const LEDGER = require('../lib/gate-ledger.js');
const S = require('../lib/defang-site.js');

const ALLOW = path.join(__dirname, '..', '..', '..', '_data', 'defang_allow.yml');
const PAGE = (body) => '<!doctype html><html><head><title>t</title></head><body><main>' + body + '</main></body></html>';

/* ---- S1: NOT CHECKED surfaces make the run NOT CHECKED ---- */
test('S1 verdictOf: a finding is FAIL (exit 1) and outranks a NOT CHECKED surface; only unavailable surfaces is NOT CHECKED (exit 2); neither is PASS (exit 0)', () => {
  assert.deepStrictEqual([CORE.verdictOf({ findings: [], unavailable: [] }).status, CORE.verdictOf({ findings: [], unavailable: [] }).code], ['PASS', 0]);
  assert.deepStrictEqual([CORE.verdictOf({ findings: [], unavailable: ['ioc-index.json unreadable'] }).status, CORE.verdictOf({ findings: [], unavailable: ['x'] }).code], ['NOT CHECKED', 2],
    'the review reproduction: the missing-index NOT CHECKED line with a clean finding list used to end PASS');
  assert.deepStrictEqual([CORE.verdictOf({ findings: [{}], unavailable: ['x'] }).status, CORE.verdictOf({ findings: [{}], unavailable: ['x'] }).code], ['FAIL', 1]);
  assert.strictEqual(CORE.verdictOf({ findings: [{}] }).code, 1);
  assert.strictEqual(CORE.verdictOf({}).code, 0, 'no lists at all is the empty run of the caller, which has its own zero checks; the function itself does not invent a defect');
});
test('S1 gate-ledger (check-browser-wire.js): a zero denominator is NOT CHECKED, never FAIL and never PASS; a FAIL outranks it; a skipped check is NOT CHECKED', () => {
  const lines = [];
  const L = LEDGER.makeLedger((l) => lines.push(l));
  L.chk('rows examined', true, 12, 'rows');
  L.chk('nothing to press', false, 0, 'toggles', 'no toggle to click');
  assert.strictEqual(L.checks[1].verdict, 'NOT CHECKED', 'a zero denominator is not a failure of the page');
  assert.ok(lines.some((l) => /NOT CHECKED {2}nothing to press/.test(l)) && lines.some((l) => /ZERO DENOMINATOR/.test(l)));
  assert.deepStrictEqual([L.verdict().verdict, L.verdict().code], ['NOT CHECKED', 2]);
  L.chk('a zero that claims to pass', true, 0, 'items');
  assert.strictEqual(L.checks[2].verdict, 'NOT CHECKED', 'pass=true over nothing is not a pass either');
  L.skipped('could not run', 'why');
  assert.strictEqual(L.verdict().notChecked, 3);
  L.chk('a real failure', false, 5, 'rows');
  assert.deepStrictEqual([L.verdict().verdict, L.verdict().code, L.verdict().fails], ['FAIL', 1, 1], 'FAIL outranks NOT CHECKED');
  const clean = LEDGER.makeLedger();
  clean.chk('a', true, 1, 'u');
  assert.deepStrictEqual([clean.verdict().verdict, clean.verdict().code], ['PASS', 0], 'control: only passes with a denominator is PASS');
});

/* ---- S6: which captures are exact by decision 5 ---- */
test('S6 captureExempt: a share is never exempt (detection page included); a copy or download is exempt only from a rule block, or from the picker on a detection page', () => {
  // the review probe: a raw share title on a detection page was exempt and the identical title on a report page was judged
  assert.strictEqual(CORE.captureExempt('detection', { inPre: false, inPicker: false }, 'share'), false, 'detection-page share: judged');
  assert.strictEqual(CORE.captureExempt('report', { inPre: false }, 'share'), false, 'report-page share: judged (control)');
  assert.strictEqual(CORE.captureExempt('detection', { inPre: true }, 'share'), false, 'a share is judged even if its button sits in a <pre>');
  // copies and downloads
  assert.strictEqual(CORE.captureExempt('detection', { inPre: true }, 'clip'), true, 'rule body copied from its <pre> block');
  assert.strictEqual(CORE.captureExempt('detection', { inPre: true }, 'blob'), true, 'rule body downloaded from its <pre> block');
  assert.strictEqual(CORE.captureExempt('detection', { inPre: true }, 'exec'), true);
  assert.strictEqual(CORE.captureExempt('detection', { inPicker: true }, 'blob'), true, 'the picker\'s rule bundle on a detection page');
  assert.strictEqual(CORE.captureExempt('report', { inPre: true }, 'clip'), true, 'a report\'s .hl-copy rule block (decision 5, unchanged)');
  assert.strictEqual(CORE.captureExempt('detection', { inPre: false, inPicker: false }, 'clip'), false, 'any other copy on a detection page is judged (page metadata, permalink, citation)');
  assert.strictEqual(CORE.captureExempt('detection', { inPre: false }, 'blob'), false);
  assert.strictEqual(CORE.captureExempt('report', { inPicker: true }, 'blob'), false, 'the picker exemption is for detection pages only');
  assert.strictEqual(CORE.captureExempt('ioc-feed', { inPre: false }, 'clip'), false);
});

/* ---- S5: a displayed input's value is judged, a reader-typed box is the one narrow exemption ---- */
function serialise(html, mutate, skip, typed) {
  const dom = new JSDOM(html, { runScripts: 'outside-only' });
  mutate(dom.window.document);
  const out = dom.window.eval('(' + CORE.SERIALISE_FN.toString() + ')(' + JSON.stringify(skip || '') + ',' + JSON.stringify(typeof typed === 'string' ? typed : null) + ')');
  dom.window.close();
  return out;
}
const BOX = '<textarea class="hl-iocsearch__in"></textarea><input class="sbox" type="search"><textarea class="area"></textarea><input class="other" type="text"><input type="hidden" class="hid"><input type="checkbox" class="chk" value="1">';
test('S5: a raw value a script wrote into an input is a finding; the defanged twin and the raw text node are the controls', () => {
  const sc = S.makeScanner(ALLOW);
  const P = 'ioc-feeds/x/index.html';
  const raw = serialise(PAGE('<p>safe text</p>' + BOX), (d) => { d.querySelector('.other').value = '198.51.100.17'; });
  const f = sc.scan(P, raw);
  assert.ok(f.some((x) => x.ctx === 'attr:value' && x.kind === 'IPV4'), 'the input-only raw address is found: ' + JSON.stringify(f.map((x) => [x.ctx, x.kind])));
  const twin = serialise(PAGE('<p>safe text</p>' + BOX), (d) => { d.querySelector('.other').value = '198[.]51[.]100[.]17'; });
  assert.deepStrictEqual(sc.scan(P, twin), [], 'the defanged value passes');
  assert.ok(sc.scan(P, PAGE('<p>198.51.100.17</p>')).length >= 1, 'control: the same address as text fires, so the scanner is alive');
  // a raw value in a textarea (judged as its text), a hidden input and a checkbox value (not displayed, not judged)
  const ta = serialise(PAGE(BOX), (d) => { d.querySelector('.area').value = 'beacon evil-host.example.xyz'; });
  assert.ok(sc.scan(P, ta).length >= 1, 'textarea content is judged');
  const hidden = serialise(PAGE(BOX), (d) => { d.querySelector('.hid').value = '198.51.100.17'; d.querySelector('.chk').value = '198.51.100.17'; });
  assert.deepStrictEqual(sc.scan(P, hidden), [], 'hidden and checkbox values are not displayed text');
});
test('S5: the exemption is only for text the reader typed: the gate-typed box, while it still holds exactly what was typed', () => {
  const sc = S.makeScanner(ALLOW);
  const P = 'ioc-feeds/x/index.html';
  const typed = '198.51.100.17\nevil-host.example.xyz';       // the IOC box is a textarea: a pasted list
  const q = '198.51.100.17';                                    // the site search box is an <input>
  const set = (box, val) => (d) => { d.querySelector(box).value = val; };
  // typed by the gate and left as typed: not judged (controls, one per element kind)
  assert.deepStrictEqual(sc.scan(P, serialise(PAGE('<p>safe text</p>' + BOX), set('.hl-iocsearch__in', typed), '.hl-iocsearch__in', typed)), [], 'a textarea holding what was typed');
  assert.deepStrictEqual(sc.scan(P, serialise(PAGE('<p>safe text</p>' + BOX), set('.sbox', q), '.sbox', q)), [], 'an input holding what was typed');
  // the page rewrote the box to something else after the gate typed: judged
  assert.ok(sc.scan(P, serialise(PAGE('<p>safe text</p>' + BOX), set('.hl-iocsearch__in', '203.0.113.9'), '.hl-iocsearch__in', typed)).length >= 1, 'a textarea whose content is not what the gate typed');
  assert.ok(sc.scan(P, serialise(PAGE('<p>safe text</p>' + BOX), set('.sbox', '203.0.113.9'), '.sbox', q)).some((x) => x.ctx === 'attr:value'), 'an input whose value is not what the gate typed');
  // another input on the page is not covered by the exemption of the typed box
  const sibling = serialise(PAGE('<p>safe text</p>' + BOX), (d) => { d.querySelector('.sbox').value = q; d.querySelector('.other').value = '203.0.113.9'; }, '.sbox', q);
  assert.ok(sc.scan(P, sibling).some((x) => x.ctx === 'attr:value' && /203/.test(x.token)), 'the sibling input is judged');
  // nothing typed (typed null): the selector alone exempts nothing
  assert.ok(sc.scan(P, serialise(PAGE('<p>safe text</p>' + BOX), set('.sbox', '203.0.113.9'), '.sbox', null)).some((x) => x.ctx === 'attr:value'), 'with nothing typed the selector exempts nothing');
});
