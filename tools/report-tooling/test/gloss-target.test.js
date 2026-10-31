'use strict';
/* T-0500.1.11 fix5b: which glossary mark the browser gate's hover and focus rows measure (lib/gloss-target.js).
   The in-page expression runs over jsdom (no layout is needed: it reads the DOM and the <details> open state). The browser run is
   the gate itself, with its control. */
const { test } = require('node:test'), assert = require('node:assert/strict');
const { JSDOM } = require('jsdom');
const G = require('../lib/gloss-target.js');

function pick(html) {
  const dom = new JSDOM('<body>' + html + '</body>', { runScripts: 'outside-only' });
  const r = dom.window.eval(G.PICK_EXPR);
  return { r, doc: dom.window.document };
}
const mark = (t) => '<span class="hl-gloss" data-gloss="x">' + t + '</span>';

test('no marks: reports marks 0 and tags nothing', () => {
  const { r, doc } = pick('<p>none</p>');
  assert.equal(r.marks, 0);
  assert.equal(doc.querySelectorAll(G.SELECTOR).length, 0);
});

test('the first mark is chosen when nothing is closed above it', () => {
  const { r, doc } = pick('<p>' + mark('C2') + ' ' + mark('beacon') + '</p>');
  assert.equal(r.index, 0); assert.equal(r.term, 'C2'); assert.equal(r.skippedClosed, 0); assert.equal(r.openedDetails, false);
  assert.equal(doc.querySelectorAll(G.SELECTOR).length, 1);
});

test('KNOWN POSITIVE: a first mark inside a closed <details> is skipped for the first mark a reader can reach (the seasia and new-files shape)', () => {
  const { r, doc } = pick('<details class="hl-revisions"><summary>Revisions</summary><ol><li>' + mark('beacon') + '</li></ol></details><p>' + mark('C2') + '</p>');
  assert.equal(r.marks, 2); assert.equal(r.index, 1); assert.equal(r.term, 'C2'); assert.equal(r.skippedClosed, 1); assert.equal(r.closedTotal, 1);
  assert.equal(r.openedDetails, false);
  assert.equal(doc.querySelector(G.SELECTOR).textContent, 'C2');
  assert.equal(doc.querySelector('details').open, false, 'a skipped <details> stays closed');
});

test('an open <details> does not hide its marks from the pick', () => {
  const { r } = pick('<details open><summary>s</summary>' + mark('C2') + '</details>');
  assert.equal(r.index, 0); assert.equal(r.skippedClosed, 0);
});

test('a nested closed <details> inside an open one still counts as closed', () => {
  const { r } = pick('<details open><summary>s</summary><details><summary>t</summary>' + mark('beacon') + '</details></details>' + mark('C2'));
  assert.equal(r.term, 'C2'); assert.equal(r.skippedClosed, 1);
});

test('a mark inside a closed <details>\' own <summary> is painted, so it is reachable', () => {
  const { r } = pick('<details><summary>' + mark('C2') + '</summary>body</details>');
  assert.equal(r.index, 0); assert.equal(r.skippedClosed, 0); assert.equal(r.openedDetails, false);
});

test('every mark in a closed <details>: the first is measured with its <details> opened, and the result says so', () => {
  const { r, doc } = pick('<details id="a"><summary>s</summary><details id="b"><summary>t</summary>' + mark('beacon') + '</details></details>');
  assert.equal(r.openedDetails, true); assert.equal(r.index, 0);
  assert.equal(doc.getElementById('a').open, true); assert.equal(doc.getElementById('b').open, true);
  assert.match(G.describe(r), /closed <details>.*opened/);
});

test('a second pick moves the tag rather than leaving two', () => {
  const dom = new JSDOM('<body>' + mark('a') + mark('b') + '</body>', { runScripts: 'outside-only' });
  dom.window.eval(G.PICK_EXPR);
  dom.window.document.querySelector('.hl-gloss').removeAttribute(G.ATTR);
  dom.window.document.querySelectorAll('.hl-gloss')[1].setAttribute(G.ATTR, '1');
  dom.window.eval(G.PICK_EXPR);
  assert.equal(dom.window.document.querySelectorAll(G.SELECTOR).length, 1);
});

test('revealed(): the row predicate. Opacity 0 with visibility visible (the failing shape) is NOT revealed; opacity 1 visible with text is', () => {
  assert.equal(G.revealed({ opacity: '0', visibility: 'visible', hasText: true }), false);
  assert.equal(G.revealed({ opacity: '1', visibility: 'hidden', hasText: true }), false);
  assert.equal(G.revealed({ opacity: '1', visibility: 'visible', hasText: false }), false);
  assert.equal(G.revealed({ opacity: '1', visibility: 'visible', hasText: true }), true);
  assert.equal(G.revealed({ opacity: '0.4', visibility: 'visible', hasText: true }), true);
});

test('describe() names the skipped marks', () => {
  assert.match(G.describe({ marks: 48, index: 20, skippedClosed: 20, term: 'C2', openedDetails: false }), /mark 21 of 48, "C2" \(the 20 mark\(s\) before it/);
  assert.equal(G.describe({ marks: 0 }), 'no marks');
});
