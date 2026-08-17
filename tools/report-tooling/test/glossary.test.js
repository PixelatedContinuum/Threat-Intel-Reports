'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { JSDOM } = require('jsdom');
const G = require('../../../assets/js/glossary.js');

const TERMS = [
  { term: 'LSASS', case_sensitive: true, short: 'Credential store process.' },
  { term: 'open directory', case_sensitive: false, short: 'Exposed file listing.' },
  { term: 'hosting', case_sensitive: false, short: 'Generic hosting.' },
  { term: 'bulletproof hosting', case_sensitive: false, short: 'Abuse-tolerant hosting.' },
  { term: 'beacon', aliases: ['beaconing'], case_sensitive: false, short: 'Periodic call-home.' },
  { term: 'C2', case_sensitive: true, once_per_report: true, short: 'Operator channel.' }
];

function mark(html) {
  const doc = new JSDOM('<body><div class="hl-post-content">' + html + '</div></body>').window.document;
  G.markTerms(doc.querySelector('.hl-post-content'), TERMS, doc);
  return doc.querySelector('.hl-post-content');
}

test('marks a known term in ordinary prose', () => {
  const root = mark('<h2>A</h2><p>Credentials came from LSASS memory.</p>');
  const marks = root.querySelectorAll('.hl-gloss');
  assert.strictEqual(marks.length, 1);
  assert.strictEqual(marks[0].textContent, 'LSASS');
});

test('never marks inside code, pre, links, headings or summary', () => {
  const root = mark(`<h2>LSASS in the heading</h2>
    <p><code>LSASS</code> and <a href="#x">LSASS</a> and <em>ok</em></p>
    <pre>dump LSASS here</pre>
    <details><summary>LSASS summary</summary><p>x</p></details>`);
  assert.strictEqual(root.querySelectorAll('.hl-gloss').length, 0);
});

test('respects an explicit data-no-gloss ancestor', () => {
  const root = mark('<h2>A</h2><div data-no-gloss><p>LSASS here</p></div>');
  assert.strictEqual(root.querySelectorAll('.hl-gloss').length, 0);
});

test('marks only the first occurrence per h2 section', () => {
  const root = mark(`<h2>One</h2><p>LSASS then LSASS again.</p>
                     <h2>Two</h2><p>LSASS in a new section.</p>`);
  assert.strictEqual(root.querySelectorAll('.hl-gloss').length, 2);
});

test('longest match wins so bulletproof hosting is not shadowed by hosting', () => {
  const root = mark('<h2>A</h2><p>It sat on bulletproof hosting throughout.</p>');
  const marks = root.querySelectorAll('.hl-gloss');
  assert.strictEqual(marks.length, 1);
  assert.strictEqual(marks[0].textContent, 'bulletproof hosting');
});

test('acronyms are case-sensitive, phrases are not', () => {
  const lower = mark('<h2>A</h2><p>the lsass path</p>');
  assert.strictEqual(lower.querySelectorAll('.hl-gloss').length, 0);
  const phrase = mark('<h2>A</h2><p>An Open Directory was found.</p>');
  assert.strictEqual(phrase.querySelectorAll('.hl-gloss').length, 1);
});

test('does not match inside a longer word', () => {
  const root = mark('<h2>A</h2><p>the hostingsomething value</p>');
  assert.strictEqual(root.querySelectorAll('.hl-gloss').length, 0);
});

/* Defect 1. The paragraph below is a SINGLE text node naming two different terms.
   Returning after the first match drops the second, and because every test above
   uses one term per node, none of them notice. */
test('marks two different terms in the same text node', () => {
  const root = mark('<h2>A</h2><p>The beacon reached LSASS on the host.</p>');
  const got = [...root.querySelectorAll('.hl-gloss')].map((m) => m.textContent);
  assert.deepStrictEqual(got, ['beacon', 'LSASS']);
});

test('marks the earliest term first, then continues past it', () => {
  const root = mark('<h2>A</h2><p>Generic hosting, then bulletproof hosting later.</p>');
  const got = [...root.querySelectorAll('.hl-gloss')].map((m) => m.textContent);
  assert.deepStrictEqual(got, ['hosting', 'bulletproof hosting']);
});

test('skips a text node carrying an indicator value', () => {
  const root = mark('<h2>A</h2><p>The beacon reached 45.130.148.125 hourly.</p>');
  assert.strictEqual(root.querySelectorAll('.hl-gloss').length, 0);
});

test('an alias resolves to its parent term and counts against it', () => {
  const root = mark('<h2>A</h2><p>Steady beaconing, and a second beacon later.</p>');
  const marks = root.querySelectorAll('.hl-gloss');
  assert.strictEqual(marks.length, 1);
  assert.strictEqual(marks[0].textContent, 'beaconing');
});

test('the mark carries the definition and an accessible label', () => {
  const root = mark('<h2>A</h2><p>Credentials came from LSASS memory.</p>');
  const m = root.querySelector('.hl-gloss');
  assert.strictEqual(m.getAttribute('data-gloss'), 'Credential store process.');
  assert.strictEqual(m.getAttribute('aria-label'), 'LSASS: Credential store process.');
  assert.strictEqual(m.getAttribute('tabindex'), '0');
});

test('marking leaves the surrounding sentence text intact', () => {
  const root = mark('<h2>A</h2><p>Credentials came from LSASS memory.</p>');
  assert.strictEqual(root.querySelector('p').textContent, 'Credentials came from LSASS memory.');
});

/* Defect 2. Geometry is a pure predicate so it is testable with numbers, because
   jsdom reports every rect as zero and could not exercise this at all. */
test('prefersRightAnchor flips only when a left-anchored tooltip would overflow', () => {
  assert.strictEqual(G.prefersRightAnchor(0, 40, 900, 320), false);
  assert.strictEqual(G.prefersRightAnchor(700, 40, 900, 320), true);
  assert.strictEqual(G.prefersRightAnchor(580, 40, 900, 320), false, 'exactly fits, so no flip');
  assert.strictEqual(G.prefersRightAnchor(581, 40, 900, 320), true);
});

test('prefersRightAnchor treats unmeasurable geometry as no flip', () => {
  assert.strictEqual(G.prefersRightAnchor(0, 0, 0, 320), false);
  assert.strictEqual(G.prefersRightAnchor(0, 0, 900, 0), false);
});

test('applyEdgeClasses is a no-op under jsdom, where every rect is zero', () => {
  const root = mark('<h2>A</h2><p>Credentials came from LSASS memory.</p>');
  assert.strictEqual(G.applyEdgeClasses(root), 0);
  assert.strictEqual(root.querySelectorAll('.hl-gloss--right').length, 0);
});

/* Measured on the live corpus, six common terms produced 56% of all marking and
   C2 alone averaged eight marks a report. once_per_report drops those to one, so
   the marking stays quiet enough for the house-standard exemption to hold. */
test('a once_per_report term marks once for the whole page, not once per section', () => {
  const root = mark('<h2>One</h2><p>The C2 replied.</p><h2>Two</h2><p>The C2 again.</p>');
  const got = [...root.querySelectorAll('.hl-gloss')].map((m) => m.textContent);
  assert.deepStrictEqual(got, ['C2']);
});

test('a per-section term keeps marking in each section alongside a once-per-report one', () => {
  const root = mark('<h2>One</h2><p>The C2 reached LSASS.</p>' +
                    '<h2>Two</h2><p>The C2 reached LSASS again.</p>');
  const got = [...root.querySelectorAll('.hl-gloss')].map((m) => m.textContent);
  assert.deepStrictEqual(got, ['C2', 'LSASS', 'LSASS']);
});

test('a once_per_report term still marks only once within a single section', () => {
  const root = mark('<h2>One</h2><p>The C2 replied, and the C2 replied again.</p>');
  assert.strictEqual(root.querySelectorAll('.hl-gloss').length, 1);
});

/* jsdom reports every rect as zero, so the real-geometry path was previously
   exercised by nothing. Stubbing the two rects the function reads makes it
   testable, which matters because live it silently flipped none of the 19
   marks that needed it and nothing threw. */
function stubRect(el, left, width) {
  el.getBoundingClientRect = () => ({ left, width, right: left + width, top: 0, bottom: 0, height: 0 });
}

test('applyEdgeClasses flips a mark whose tooltip would overflow the container', () => {
  const root = mark('<h2>A</h2><p>Credentials came from LSASS memory.</p>');
  const m = root.querySelector('.hl-gloss');
  stubRect(root, 0, 844);
  stubRect(m, 780, 40);
  assert.strictEqual(G.applyEdgeClasses(root), 1);
  assert.ok(m.classList.contains('hl-gloss--right'));
});

test('applyEdgeClasses clears a stale flip when the container grows', () => {
  const root = mark('<h2>A</h2><p>Credentials came from LSASS memory.</p>');
  const m = root.querySelector('.hl-gloss');
  stubRect(root, 0, 844);
  stubRect(m, 780, 40);
  G.applyEdgeClasses(root);
  assert.ok(m.classList.contains('hl-gloss--right'), 'flipped at the narrow width');

  stubRect(root, 0, 1600);
  assert.strictEqual(G.applyEdgeClasses(root), 0);
  assert.ok(!m.classList.contains('hl-gloss--right'),
    'a class that only ever accumulated would leave the tooltip anchored right forever');
});

test('applyEdgeClasses changes nothing when the container cannot be measured', () => {
  const root = mark('<h2>A</h2><p>Credentials came from LSASS memory.</p>');
  const m = root.querySelector('.hl-gloss');
  m.classList.add('hl-gloss--right');
  stubRect(root, 0, 0);
  assert.strictEqual(G.applyEdgeClasses(root), 0);
  assert.ok(m.classList.contains('hl-gloss--right'),
    'an unmeasurable container is not evidence the flip is wrong, so nothing is touched');
});
