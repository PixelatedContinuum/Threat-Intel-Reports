'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { JSDOM } = require('jsdom');
const CG = require('../lib/check-glossary.js');

const TERMS = [
  { term: 'LSASS', case_sensitive: true, short: 'Credential store process.' },
  { term: 'beacon', case_sensitive: false, short: 'Periodic call-home.' }
];

function check(html, terms) {
  const dom = new JSDOM('<body>' + html + '</body>');
  const doc = dom.window.document;
  return CG.glossaryProblems(doc.body, doc, terms === undefined ? TERMS : terms);
}

test('clean prose passes and reports the marks it made', () => {
  const r = check('<h2>A</h2><p>Credentials came from LSASS memory.</p>');
  assert.strictEqual(r.status, 'PASS');
  assert.strictEqual(r.marks, 1);
  assert.deepStrictEqual(r.problems, []);
});

test('a body with nothing to mark still passes', () => {
  const r = check('<h2>A</h2><p>Nothing of interest here.</p>');
  assert.strictEqual(r.status, 'PASS');
  assert.strictEqual(r.marks, 0);
});

/* The regression this module exists for. If the matcher ever loses an exclusion,
   a definition surfaces inside a rule body and this must be a hard FAIL. */
test('a mark planted inside a pre block is a FAIL', () => {
  const dom = new JSDOM('<body><h2>A</h2><pre>rule x { strings: $a = "LSASS" }</pre></body>');
  const doc = dom.window.document;
  const pre = doc.querySelector('pre');
  const span = doc.createElement('span');
  span.className = 'hl-gloss';
  span.textContent = 'LSASS';
  pre.appendChild(span);
  const r = CG.glossaryProblems(doc.body, doc, TERMS);
  assert.strictEqual(r.status, 'FAIL');
  assert.strictEqual(r.problems.length, 1);
});

test('the failure names the module and term file as the fix site, not the report', () => {
  const dom = new JSDOM('<body><h2>A</h2><code></code></body>');
  const doc = dom.window.document;
  const span = doc.createElement('span');
  span.className = 'hl-gloss';
  span.textContent = 'LSASS';
  doc.querySelector('code').appendChild(span);
  const r = CG.glossaryProblems(doc.body, doc, TERMS);
  const msg = r.problems.join(' ');
  assert.match(msg, /assets\/js\/glossary\.js/);
  assert.match(msg, /_data\/glossary\.yml/);
  assert.match(msg, /not in this report/);
  assert.match(msg, /LSASS/, 'names the offending term');
  assert.match(msg, /code/, 'names the element that contains it');
});

test('an empty term list is NOT CHECKED, never a pass', () => {
  const r = check('<h2>A</h2><p>Credentials came from LSASS memory.</p>', []);
  assert.strictEqual(r.status, 'NOT CHECKED');
  assert.match(r.reason, /no entries/);
  assert.deepStrictEqual(r.problems, []);
});

test('loadTerms reads the real committed term file', () => {
  const terms = CG.loadTerms();
  assert.ok(terms.length >= 25, 'expected at least the measured-head terms, got ' + terms.length);
  assert.ok(terms.every((t) => t.term && t.short), 'every entry carries term and short');
  const c2 = terms.find((t) => t.term === 'C2');
  assert.ok(c2, 'C2 is present');
  assert.strictEqual(c2.case_sensitive, true);
  assert.ok(c2.aliases.indexOf('command and control') !== -1, 'aliases parsed');
});

test('loadTerms parses the once_per_report flag from the real term file', () => {
  const terms = CG.loadTerms();
  const c2 = terms.find((t) => t.term === 'C2');
  assert.strictEqual(c2.once_per_report, true, 'C2 is flagged once per report');
  const lsass = terms.find((t) => t.term === 'LSASS');
  assert.notStrictEqual(lsass.once_per_report, true, 'a rare term is not flagged');
  const flagged = terms.filter((t) => t.once_per_report).map((t) => t.term).sort();
  assert.deepStrictEqual(flagged,
    ['C2', 'beacon', 'exfiltration', 'loader', 'open directory', 'pivot'],
    'exactly the six highest-frequency terms carry the flag');
});
