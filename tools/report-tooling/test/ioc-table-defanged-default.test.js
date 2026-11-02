'use strict';
/* T-0500.1.7.4 b1b (Joseph, 2026-11-02, decision 5): the IOC viewer starts DEFANGED. fix-r1 (review finding 2) then removed the way out of it: there is no Defanged/Live button and no live value in the markup, so
   the tests that pressed the button are replaced by tests that press every control and read the table, the clipboard and both downloads. Original header: The layout prints every network row defanged (_includes/ioc-cell.html) with the live value in
   data-live and the button pressed; assets/js/ioc-table.js must keep that state at load (not rewrite the table back to live), export what is on screen (so copy and the .txt and .csv
   downloads are defanged), and give the live values back only when the reader presses the button. A hash, a filename, a path and a registry value print as the feed recorded them
   (data-literal); a pattern keeps the text the layout printed. Controls: the same page with the button unpressed starts live (the existing tests' fixtures), and a row the toggle
   must not touch (the never-block table) has no data-live. Fixture addresses are RFC 5737 / RFC 2606. */
var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var path = require('node:path');
var JSDOM = require('jsdom').JSDOM;

var SRC = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'assets', 'js', 'ioc-table.js'), 'utf8');

var ROWS = [
  { type: 'ipv4', live: '198.51.100.17', shown: '198[.]51[.]100[.]17' },
  { type: 'domain', live: 'evil.example.xyz', shown: 'evil[.]example[.]xyz' },
  { type: 'url', live: 'http://web.example.org/a/https://evil.example.net/p.php', shown: 'hxxp://web[.]example[.]org/a/hxxps://evil[.]example[.]net/p[.]php' },
  { type: 'email', live: 'op@evil.example.xyz', shown: 'op[@]evil[.]example[.]xyz' },
  { type: 'sha256', live: 'a'.repeat(64), shown: 'a'.repeat(64), literal: true },
  { type: 'filename', live: 'install.sh', shown: 'install.sh', literal: true },
  { type: 'pattern', live: 'beacon to 198.51.100.17 every hour', shown: 'beacon to 198[.]51[.]100[.]17 every hour' }
];

/* The page as the layout prints it now: every network row defanged, no Defanged/Live button, no live value in the markup. */
function page() {
  var trs = ROWS.map(function (r) {
    return '<tr data-type="' + r.type + '"><td><span class="hl-ioctable__type">' + r.type + '</span></td><td><code' +
      (r.literal ? ' data-literal="' + r.type + '"' : '') + '>' + r.shown + '</code></td></tr>';
  }).join('');
  var dom = new JSDOM('<!doctype html><html><body><div class="hl-ioctable" data-slug="demo" data-has-confidence="false" data-has-action="false" data-has-fp-risk="false">' +
    '<div class="hl-ioctable__actions"><button class="hl-ioctable__btn" data-act="copy">Copy shown</button><button class="hl-ioctable__btn" data-act="txt">Download .txt</button>' +
    '<button class="hl-ioctable__btn" data-act="csv">Download .csv</button><span class="hl-ioctable__note">Values are shown defanged.</span>' +
    '<span class="hl-ioctable__count"></span></div><table class="hl-ioctable__table"><tbody>' + trs + '</tbody></table></div></body></html>',
    { runScripts: 'outside-only', url: 'https://example.test/ioc-feeds/demo/' });
  var cap = { clipboard: null };
  dom.window.navigator.clipboard = { writeText: function (s) { cap.clipboard = s; return Promise.resolve(); } };
  dom.window.URL.createObjectURL = function () { return 'blob:stub'; };
  dom.window.URL.revokeObjectURL = function () {};
  dom.window.eval(SRC);
  dom.window.document.dispatchEvent(new dom.window.Event('DOMContentLoaded'));
  return { doc: dom.window.document, win: dom.window, cap: cap };
}
function shown(doc) { return Array.prototype.map.call(doc.querySelectorAll('.hl-ioctable__table tbody tr code'), function (c) { return c.textContent; }); }
function press(p, sel) { p.doc.querySelector(sel).dispatchEvent(new p.win.Event('click', { bubbles: true })); }
var LIVE = /198\.51\.100\.17|evil\.example\.xyz|web\.example\.org|op@evil|https?:\/\//;

test('the table stays defanged after the script runs, with no button and no live value in the markup', function () {
  var p = page();
  assert.deepStrictEqual(shown(p.doc), ROWS.map(function (r) { return r.shown; }));
  assert.equal(p.doc.querySelector('.hl-ioctable__btn[data-act="defang"]'), null);
  assert.equal(p.doc.querySelectorAll('[data-live]').length, 0);
});

test('copy and the .txt and .csv exports are the defanged display, and pressing every button of the page leaves the table so', function () {
  var p = page();
  var want = ROWS.map(function (r) { return r.shown; }).join('\n');
  press(p, '.hl-ioctable__btn[data-act="copy"]');
  assert.strictEqual(p.cap.clipboard, want);
  assert.strictEqual(LIVE.test(p.cap.clipboard), false, 'no live address, name or scheme in the copied text');
  press(p, '.hl-ioctable__btn[data-act="txt"]');
  assert.strictEqual(p.win.__lastDownloadText, want);
  press(p, '.hl-ioctable__btn[data-act="csv"]');
  assert.strictEqual(LIVE.test(p.win.__lastDownloadText), false, 'no live value in the .csv');
  Array.prototype.forEach.call(p.doc.querySelectorAll('button'), function (b) { b.dispatchEvent(new p.win.Event('click', { bubbles: true })); });
  assert.deepStrictEqual(shown(p.doc), ROWS.map(function (r) { return r.shown; }));
});

test('CONTROL (the export guard fires): a live value planted into a network cell, as a layout regression would, is defanged by copy, .txt and .csv; a hash and a filename are copied as recorded', function () {
  var p = page();
  Array.prototype.forEach.call(p.doc.querySelectorAll('.hl-ioctable__table tbody tr code'), function (c, i) { c.textContent = ROWS[i].live; });
  press(p, '.hl-ioctable__btn[data-act="copy"]');
  var got = p.cap.clipboard.split('\n');
  assert.deepStrictEqual(got.slice(0, 4), ROWS.slice(0, 4).map(function (r) { return r.shown; }), 'the four network rows come out defanged');
  assert.strictEqual(got[4], 'a'.repeat(64));
  assert.strictEqual(got[5], 'install.sh');
  assert.strictEqual(LIVE.test(got.slice(0, 4).join('\n')), false);
  press(p, '.hl-ioctable__btn[data-act="txt"]');
  assert.deepStrictEqual(p.win.__lastDownloadText.split('\n').slice(0, 4), got.slice(0, 4));
  press(p, '.hl-ioctable__btn[data-act="csv"]');
  assert.strictEqual(LIVE.test(p.win.__lastDownloadText.split('\n').slice(1, 5).map(function (l) { return l.split(',')[0]; }).join('\n')), false);
});
