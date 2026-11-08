'use strict';
// T-0565.1 review settlement (T-0576, 2026-11-08): the measured chip fit keeps priority order,
// a shared search link is re-applied after chip text joins the search text, an expanded row
// whose overflow empties collapses, and the +N control's name starts with its visible text.
const test = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const {JSDOM} = require('jsdom');
const root = path.resolve(__dirname, '../../..');
const script = fs.readFileSync(path.join(root, 'assets/js/wire-chips.js'), 'utf8');

// An nKEV row: CVSS (always kept), CISA KEV (rank 0, wide), Pre-auth (rank 1), a context chip (rank 9).
const ROW = '<div class="hl-vuln" data-title="cve-2026-0001"><span class="hl-vuln__badges">' +
  '<span class="hl-vuln__sev" data-w="40">High</span>' +
  '<span class="hl-vuln__b--cisa" data-w="200">CISA KEV</span>' +
  '<span class="hl-vuln__preauth" data-w="60">Pre-auth</span>' +
  '<span class="hl-vuln__ctx" data-w="50">context</span></span></div>';

function load(width, opts) {
  const d = new JSDOM(ROW, {runScripts: 'outside-only'});
  const w = d.window, box = w.document.querySelector('.hl-vuln__badges');
  let cw = width;
  Object.defineProperty(box, 'clientWidth', {get: () => cw});
  w.Element.prototype.getBoundingClientRect = function () { return {width: +this.getAttribute('data-w') || 0}; };
  // Measured path: the row is in view as soon as it is observed.
  w.IntersectionObserver = class { constructor(cb) { this.cb = cb; } observe() { this.cb([{isIntersecting: true}]); } };
  const seen = [];
  w.document.addEventListener('hl:refilter', () => seen.push(w.document.querySelector('.hl-vuln').dataset.title));
  if (!(opts && opts.noRun)) w.eval(script);
  return {d, w, box, seen, setWidth: (v) => { cw = v; w.dispatchEvent(new w.Event('resize')); },
    chip: (sel) => w.document.querySelector(sel), btn: () => w.document.querySelector('button.hl-vuln__more')};
}

test('a lower-priority chip is not shown while a higher-priority chip is in overflow (measured fit)', () => {
  const t = load(200);
  try {
    // budget 200: button 48 + gap 5 = 53, CVSS 40 kept (98); CISA 200 does not fit, so Pre-auth and the context chip overflow too.
    assert.equal(t.chip('.hl-vuln__sev').hidden, false, 'CVSS always shown');
    assert.equal(t.chip('.hl-vuln__b--cisa').hidden, true);
    assert.equal(t.chip('.hl-vuln__preauth').hidden, true, 'Pre-auth must not jump ahead of CISA KEV');
    assert.equal(t.chip('.hl-vuln__ctx').hidden, true);
    assert.equal(t.btn().textContent, '+3');
  } finally { t.d.window.close(); }
});

test('control: with room for every chip all are shown and there is no +N', () => {
  const t = load(1000);
  try {
    for (const s of ['.hl-vuln__sev', '.hl-vuln__b--cisa', '.hl-vuln__preauth', '.hl-vuln__ctx']) assert.equal(t.chip(s).hidden, false, s);
    assert.equal(t.btn().hidden, true);
  } finally { t.d.window.close(); }
});

test('the filter is re-applied once, after chip text has joined the search text', () => {
  const t = load(1000);
  try {
    assert.equal(t.seen.length, 1, 'one hl:refilter after augmenting');
    assert.match(t.seen[0], /cisa kev/, 'chip text was already in data-title when the filter re-ran');
  } finally { t.d.window.close(); }
});

test('an expanded row whose overflow empties on resize collapses, and narrowing again hides the overflow', () => {
  const t = load(200);
  try {
    t.btn().click();
    assert.equal(t.btn().getAttribute('aria-expanded'), 'true');
    t.setWidth(1000);
    assert.equal(t.btn().hidden, true);
    assert.equal(t.btn().getAttribute('aria-expanded'), 'false', 'no stale expanded state');
    t.setWidth(200);
    assert.equal(t.chip('.hl-vuln__preauth').hidden, true, 'overflow hidden again, not shown under a minus button nobody pressed');
    assert.equal(t.btn().textContent, '+3');
  } finally { t.d.window.close(); }
});

test('the +N control name begins with its visible text', () => {
  const t = load(200);
  try {
    const b = t.btn();
    assert.ok(b.getAttribute('aria-label').startsWith(b.textContent), b.getAttribute('aria-label'));
    b.click();
    assert.ok(b.getAttribute('aria-label').startsWith(b.textContent), b.getAttribute('aria-label'));
  } finally { t.d.window.close(); }
});
