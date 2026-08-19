'use strict';

/* The IOC table's filter, copy and download behaviour, in jsdom.

   jsdom has no layout, no pointer and no download, so what this suite proves is
   SELECTION and CONTENT: which rows a filter leaves visible, and exactly what text
   the copy and download paths would hand over. That the table paints, that a chip
   looks pressed, and that a file reaches the reader are a human check, recorded as
   NO GATE in the claim matrix exactly as they are for the detection picker.

   The rule the suite exists to defend: what you copy is what you see. A filter that
   narrows the table but exports the unfiltered set would hand a defender a block
   list they did not ask for and would not notice. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var path = require('node:path');
var JSDOM = require('jsdom').JSDOM;

var SRC = fs.readFileSync(
  path.join(__dirname, '..', '..', '..', 'assets', 'js', 'ioc-table.js'), 'utf8');

var ROWS = [
  { type: 'ipv4', value: '185.49.126.140', context: 'C2 server' },
  { type: 'ipv4', value: '91.197.98.188', context: null },
  { type: 'domain', value: 'evil.test', context: 'staging' },
  { type: 'sha256', value: 'a'.repeat(64), context: null },
  { type: 'filename', value: 'windefendersvc.exe', context: 'dropped' },
  { type: 'path', value: 'C:' + String.fromCharCode(92) + 'Windows' +
      String.fromCharCode(92) + 'x.exe', context: null }
];

function attr(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function page(rows) {
  var counts = {};
  rows.forEach(function (r) { counts[r.type] = (counts[r.type] || 0) + 1; });
  var chips = Object.keys(counts).map(function (t) {
    return '<button class="hl-ioctable__chip" data-type="' + t + '" aria-pressed="false">' +
      t + '</button>';
  }).join('');
  var trs = rows.map(function (r) {
    return '<tr data-type="' + r.type + '"' +
      // Escaped the way Liquid's `escape` filter does in the real layout; a raw
      // quote here would be truncated by the HTML parser and the test would be
      // asserting on a fixture bug rather than on the CSV writer.
      (r.context ? ' data-context="' + attr(r.context) + '"' : '') +
      '><td><span class="hl-ioctable__type">' + r.type + '</span></td>' +
      '<td><code>' + r.value + '</code></td></tr>';
  }).join('');

  var dom = new JSDOM(
    '<!doctype html><html><body>' +
    '<div class="hl-ioctable" data-slug="demo" data-title="Demo Campaign">' +
    '<div class="hl-ioctable__filters">' + chips +
    '<button class="hl-ioctable__clear" hidden>Clear filters</button></div>' +
    '<div class="hl-ioctable__actions">' +
    '<button class="hl-ioctable__btn" data-act="copy">Copy shown</button>' +
    '<button class="hl-ioctable__btn" data-act="txt">Download .txt</button>' +
    '<button class="hl-ioctable__btn" data-act="csv">Download .csv</button>' +
    '<span class="hl-ioctable__count"></span></div>' +
    '<table class="hl-ioctable__table"><tbody>' + trs + '</tbody></table>' +
    '</div></body></html>',
    { runScripts: 'outside-only', url: 'https://example.test/ioc-feeds/demo/' });

  // Capture what the page would put on the clipboard or into a file.
  var captured = { clipboard: null, downloads: [] };
  dom.window.navigator.clipboard = {
    writeText: function (s) { captured.clipboard = s; return Promise.resolve(); }
  };
  dom.window.URL.createObjectURL = function (blob) {
    captured.downloads.push(blob);
    return 'blob:stub';
  };
  dom.window.URL.revokeObjectURL = function () {};

  dom.window.eval(SRC);
  dom.window.document.dispatchEvent(new dom.window.Event('DOMContentLoaded'));
  return { dom: dom, doc: dom.window.document, cap: captured };
}

function visibleValues(doc) {
  return Array.prototype.slice
    .call(doc.querySelectorAll('.hl-ioctable__table tbody tr'))
    .filter(function (tr) { return !tr.hasAttribute('hidden'); })
    .map(function (tr) { return tr.querySelector('code').textContent; });
}

function click(doc, sel) {
  var el = doc.querySelector(sel);
  el.dispatchEvent(new (el.ownerDocument.defaultView.Event)('click', { bubbles: true }));
  return el;
}

test('with no chip pressed every row is visible', function () {
  var p = page(ROWS);
  assert.equal(visibleValues(p.doc).length, ROWS.length);
});

test('pressing one chip narrows the table to that type', function () {
  var p = page(ROWS);
  click(p.doc, '.hl-ioctable__chip[data-type="ipv4"]');
  assert.deepEqual(visibleValues(p.doc), ['185.49.126.140', '91.197.98.188']);
});

test('a second chip widens rather than replaces, so types combine', function () {
  var p = page(ROWS);
  click(p.doc, '.hl-ioctable__chip[data-type="ipv4"]');
  click(p.doc, '.hl-ioctable__chip[data-type="domain"]');
  assert.deepEqual(visibleValues(p.doc),
    ['185.49.126.140', '91.197.98.188', 'evil.test']);
});

test('unpressing the last chip returns to everything, not to nothing', function () {
  // Zero chips pressed must mean "no filter", never "match nothing". An empty
  // table that looks like a filter result is the worst of both.
  var p = page(ROWS);
  click(p.doc, '.hl-ioctable__chip[data-type="ipv4"]');
  click(p.doc, '.hl-ioctable__chip[data-type="ipv4"]');
  assert.equal(visibleValues(p.doc).length, ROWS.length);
});

test('the count reports what is shown, and says so out loud', function () {
  var p = page(ROWS);
  click(p.doc, '.hl-ioctable__chip[data-type="ipv4"]');
  assert.match(p.doc.querySelector('.hl-ioctable__count').textContent, /\b2\b/);
});

test('WHAT YOU COPY IS WHAT YOU SEE', function () {
  var p = page(ROWS);
  click(p.doc, '.hl-ioctable__chip[data-type="ipv4"]');
  click(p.doc, '.hl-ioctable__btn[data-act="copy"]');
  assert.equal(p.cap.clipboard, '185.49.126.140\n91.197.98.188');
});

test('copying with no filter takes the whole table', function () {
  var p = page(ROWS);
  click(p.doc, '.hl-ioctable__btn[data-act="copy"]');
  assert.equal(p.cap.clipboard.split('\n').length, ROWS.length);
});

test('the txt download is the same newline list the copy button produces', function () {
  var p = page(ROWS);
  click(p.doc, '.hl-ioctable__chip[data-type="domain"]');
  click(p.doc, '.hl-ioctable__btn[data-act="copy"]');
  var copied = p.cap.clipboard;
  click(p.doc, '.hl-ioctable__btn[data-act="txt"]');
  assert.equal(p.dom.window.__lastDownloadText, copied);
});

test('the csv carries value, type and context, with a header row', function () {
  var p = page(ROWS);
  click(p.doc, '.hl-ioctable__btn[data-act="csv"]');
  var csv = p.dom.window.__lastDownloadText.split('\n');
  assert.equal(csv[0], 'value,type,context');
  assert.ok(csv.indexOf('185.49.126.140,ipv4,C2 server') > -1, csv.slice(0, 3).join(' | '));
});

test('a csv field containing a comma or a quote is quoted, not corrupted', function () {
  var p = page([{ type: 'ipv4', value: '1.2.3.4', context: 'C2, the "main" one' }]);
  click(p.doc, '.hl-ioctable__btn[data-act="csv"]');
  var line = p.dom.window.__lastDownloadText.split('\n')[1];
  assert.equal(line, '1.2.3.4,ipv4,"C2, the ""main"" one"');
});

test('a row with no context leaves the csv field empty rather than writing null', function () {
  var p = page([{ type: 'ipv4', value: '1.2.3.4', context: null }]);
  var line = (click(p.doc, '.hl-ioctable__btn[data-act="csv"]'),
              p.dom.window.__lastDownloadText.split('\n')[1]);
  assert.equal(line, '1.2.3.4,ipv4,');
});

test('a backslash path survives copy untouched, since it is what a hunter pastes', function () {
  var p = page(ROWS);
  click(p.doc, '.hl-ioctable__chip[data-type="path"]');
  click(p.doc, '.hl-ioctable__btn[data-act="copy"]');
  assert.equal(p.cap.clipboard,
    'C:' + String.fromCharCode(92) + 'Windows' + String.fromCharCode(92) + 'x.exe');
});

test('the download filename is derived from the slug, so two feeds do not collide', function () {
  var p = page(ROWS);
  click(p.doc, '.hl-ioctable__btn[data-act="csv"]');
  assert.match(p.dom.window.__lastDownloadName, /^demo-indicators\.csv$/);
  click(p.doc, '.hl-ioctable__btn[data-act="txt"]');
  assert.match(p.dom.window.__lastDownloadName, /^demo-indicators\.txt$/);
});

test('a page with no table container does not throw', function () {
  var dom = new JSDOM('<!doctype html><html><body><p>nothing here</p></body></html>',
                      { runScripts: 'outside-only' });
  dom.window.eval(SRC);
  dom.window.document.dispatchEvent(new dom.window.Event('DOMContentLoaded'));
  assert.ok(true);
});

/* --- clearing every filter at once -------------------------------------

   Unpressing chips one at a time is fine at two and tedious at nine, and a page
   showing a narrowed table with no obvious way back is the state worth designing
   against. The button is HIDDEN when nothing is filtered, matching the indicator
   search's own clear control, so it never advertises an action that would do
   nothing. */

test('the clear button is hidden while nothing is filtered', function () {
  var p = page(ROWS);
  assert.equal(p.doc.querySelector('.hl-ioctable__clear').hasAttribute('hidden'), true);
});

test('it appears as soon as one chip is pressed', function () {
  var p = page(ROWS);
  click(p.doc, '.hl-ioctable__chip[data-type="ipv4"]');
  assert.equal(p.doc.querySelector('.hl-ioctable__clear').hasAttribute('hidden'), false);
});

test('CLEARING RESTORES EVERY ROW', function () {
  var p = page(ROWS);
  click(p.doc, '.hl-ioctable__chip[data-type="ipv4"]');
  click(p.doc, '.hl-ioctable__chip[data-type="domain"]');
  assert.equal(visibleValues(p.doc).length, 3);
  click(p.doc, '.hl-ioctable__clear');
  assert.equal(visibleValues(p.doc).length, ROWS.length);
});

test('clearing unpresses every chip, so the control never lies about state', function () {
  // A chip left reading pressed over an unfiltered table is worse than no
  // button at all: the next click would then FILTER rather than unfilter.
  var p = page(ROWS);
  click(p.doc, '.hl-ioctable__chip[data-type="ipv4"]');
  click(p.doc, '.hl-ioctable__chip[data-type="path"]');
  click(p.doc, '.hl-ioctable__clear');
  var pressed = Array.prototype.slice.call(p.doc.querySelectorAll('.hl-ioctable__chip'))
    .filter(function (c) { return c.getAttribute('aria-pressed') === 'true'; });
  assert.deepEqual(pressed, []);
});

test('it hides itself again once there is nothing left to clear', function () {
  var p = page(ROWS);
  click(p.doc, '.hl-ioctable__chip[data-type="ipv4"]');
  click(p.doc, '.hl-ioctable__clear');
  assert.equal(p.doc.querySelector('.hl-ioctable__clear').hasAttribute('hidden'), true);
});

test('the count returns to the unfiltered total after clearing', function () {
  var p = page(ROWS);
  click(p.doc, '.hl-ioctable__chip[data-type="ipv4"]');
  click(p.doc, '.hl-ioctable__clear');
  var txt = p.doc.querySelector('.hl-ioctable__count').textContent;
  assert.match(txt, new RegExp('\\b' + ROWS.length + '\\b'));
  assert.ok(txt.indexOf(' of ') === -1, 'still reads as filtered: ' + txt);
});

test('a chip pressed again after clearing filters rather than unfilters', function () {
  // The state the previous test protects, exercised end to end.
  var p = page(ROWS);
  click(p.doc, '.hl-ioctable__chip[data-type="ipv4"]');
  click(p.doc, '.hl-ioctable__clear');
  click(p.doc, '.hl-ioctable__chip[data-type="ipv4"]');
  assert.deepEqual(visibleValues(p.doc), ['185.49.126.140', '91.197.98.188']);
});

test('COPY AFTER CLEARING TAKES EVERYTHING, not the filter that was just dropped', function () {
  var p = page(ROWS);
  click(p.doc, '.hl-ioctable__chip[data-type="ipv4"]');
  click(p.doc, '.hl-ioctable__clear');
  click(p.doc, '.hl-ioctable__btn[data-act="copy"]');
  assert.equal(p.cap.clipboard.split('\n').length, ROWS.length);
});
