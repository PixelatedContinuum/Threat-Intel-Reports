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
  { term: 'beacon', aliases: ['beaconing'], case_sensitive: false, short: 'Periodic call-home.' }
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
