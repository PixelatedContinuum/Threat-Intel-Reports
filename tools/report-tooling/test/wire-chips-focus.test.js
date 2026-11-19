'use strict';
// T-0565.1.3 (T-0576 settle row 15): the +N button sits after the chips it reveals, so a
// keyboard reader reached the revealed chips only with Shift+Tab, and a focused +N that
// hid when its overflow emptied on resize took focus out of the page with it.
// The fix moves focus to the first revealed interactive chip on expand and back into the
// row (its CVE link) when a focused +N hides.
const test = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const {JSDOM} = require('jsdom');
const root = path.resolve(__dirname, '../../..');
const script = fs.readFileSync(path.join(root, 'assets/js/wire-chips.js'), 'utf8');

// A CVEs-tab row: CVSS (rank -1, always kept), the CVE link the row falls back to, and two
// revealed chips whose first is a link (nomi) and whose second opens a native details.
const ROW = '<div class="hl-vuln hl-vuln--cve" data-title="cve-2026-0001">' +
  '<button type="button" class="hl-dt" aria-expanded="false" hidden title="Show details"><span class="hl-dt__sr">Details</span></button>' +
  '<a class="hl-vuln__cve" href="https://nvd.nist.gov/vuln/detail/CVE-2026-0001">CVE-2026-0001</a>' +
  '<span class="hl-vuln__badges">' +
  '<span class="hl-vuln__sev" data-w="40">High</span>' +
  '<a class="hl-vuln__p hl-vuln__p--nomi" href="https://example.test/poc" data-w="200">PoC on GitHub</a>' +
  '<details class="hl-vuln__pop" data-w="120"><summary>2 src</summary><span>x</span></details>' +
  '</span></div>';

function load(width) {
  const d = new JSDOM(ROW, {runScripts: 'outside-only'});
  const w = d.window, box = w.document.querySelector('.hl-vuln__badges');
  let cw = width;
  Object.defineProperty(box, 'clientWidth', {get: () => cw});
  w.Element.prototype.getBoundingClientRect = function () { return {width: +this.getAttribute('data-w') || 0}; };
  w.IntersectionObserver = class { constructor(cb) { this.cb = cb; } observe() { this.cb([{isIntersecting: true}]); } };
  w.eval(script);
  return {d, w, setWidth: (v) => { cw = v; w.dispatchEvent(new w.Event('resize')); },
    chip: (sel) => w.document.querySelector(sel), btn: () => w.document.querySelector('button.hl-vuln__more')};
}

test('pressing +N puts focus on the first revealed interactive chip, and the row keeps its DOM order', () => {
  const t = load(200);
  try {
    // budget 200: button 48 + gap 5 + CVSS 40 = 98; the nomi link (200) and the 2 src
    // details (120) do not fit, so both are revealed by +2.
    const b = t.btn(), nomi = t.chip('.hl-vuln__p--nomi'), det = t.chip('.hl-vuln__pop');
    assert.equal(b.textContent, '+2');
    assert.equal(nomi.hidden, true);
    assert.equal(det.hidden, true);
    b.focus();
    b.click();
    assert.equal(nomi.hidden, false);
    assert.equal(det.hidden, false);
    assert.equal(t.w.document.activeElement, nomi, 'focus lands on the first revealed interactive chip');
    // Nothing moved in the DOM: from the focused chip, Tab reaches the second revealed chip
    // and then the -N button, so the button still follows what it opened.
    assert.ok(nomi.compareDocumentPosition(det) & t.w.Node.DOCUMENT_POSITION_FOLLOWING, 'nomi chip precedes the details chip');
    assert.ok(det.compareDocumentPosition(b) & t.w.Node.DOCUMENT_POSITION_FOLLOWING, 'the -N button follows the chips it reveals');
    assert.equal(b.textContent, '−2');
  } finally { t.d.window.close(); }
});

test('control: collapsing with -N leaves focus on the button, which stays visible', () => {
  const t = load(200);
  try {
    const b = t.btn();
    b.click();
    assert.equal(t.chip('.hl-vuln__p--nomi').hidden, false);
    b.focus();
    b.click();
    assert.equal(b.hidden, false);
    assert.equal(t.w.document.activeElement, b, 'the visible button keeps focus on collapse');
    assert.equal(t.chip('.hl-vuln__p--nomi').hidden, true);
  } finally { t.d.window.close(); }
});

test('Escape pressed on a revealed chip collapses the row and returns focus to the button', () => {
  const t = load(200);
  try {
    const b = t.btn(), nomi = t.chip('.hl-vuln__p--nomi');
    b.click();
    assert.equal(t.w.document.activeElement, nomi);
    nomi.dispatchEvent(new t.w.KeyboardEvent('keydown', {key: 'Escape', bubbles: true}));
    assert.equal(b.getAttribute('aria-expanded'), 'false');
    assert.equal(nomi.hidden, true);
    assert.equal(t.w.document.activeElement, b, 'focus goes back to the button, which is still visible');
  } finally { t.d.window.close(); }
});

test('a focused +N that hides on resize moves focus to the row, not out of the page', () => {
  const t = load(200);
  try {
    const b = t.btn();
    b.click();
    b.focus();
    t.setWidth(1000);
    assert.equal(b.hidden, true, 'the overflow emptied, so the button is gone');
    const active = t.w.document.activeElement;
    assert.notEqual(active, b, 'focus does not stay on a hidden button');
    assert.notEqual(active, t.w.document.body, 'focus does not drop to the document');
    assert.equal(active, t.chip('.hl-vuln__cve'), 'focus lands on the row\'s CVE link, in the same row');
  } finally { t.d.window.close(); }
});
