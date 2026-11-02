'use strict';
/* T-0500.1.7.4 b1b (Joseph, 2026-11-02, decision 5): the IOC viewer starts DEFANGED. The layout prints every network row defanged (_includes/ioc-cell.html) with the live value in
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

function page(pressed) {
  var trs = ROWS.map(function (r) {
    return '<tr data-type="' + r.type + '"><td><span class="hl-ioctable__type">' + r.type + '</span></td><td><code data-live="' + r.live + '"' +
      (r.literal ? ' data-literal="' + r.type + '"' : '') + '>' + r.shown + '</code></td></tr>';
  }).join('');
  var dom = new JSDOM('<!doctype html><html><body><div class="hl-ioctable" data-slug="demo" data-has-confidence="false" data-has-action="false" data-has-fp-risk="false">' +
    '<div class="hl-ioctable__actions"><button class="hl-ioctable__btn" data-act="copy">Copy shown</button><button class="hl-ioctable__btn" data-act="txt">Download .txt</button>' +
    '<button class="hl-ioctable__btn" data-act="csv">Download .csv</button><button class="hl-ioctable__btn hl-ioctable__btn--toggle" data-act="defang" aria-pressed="' + pressed + '">' + (pressed === 'true' ? 'Defanged' : 'Defang') + '</button>' +
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
function press(p) { p.doc.querySelector('.hl-ioctable__btn[data-act="defang"]').dispatchEvent(new p.win.Event('click', { bubbles: true })); }

test('the table starts defanged: what the layout printed stays on screen after the script runs, and the button reads Defanged, pressed', function () {
  var p = page('true');
  assert.deepStrictEqual(shown(p.doc), ROWS.map(function (r) { return r.shown; }));
  var b = p.doc.querySelector('.hl-ioctable__btn[data-act="defang"]');
  assert.strictEqual(b.getAttribute('aria-pressed'), 'true');
  assert.strictEqual(b.textContent, 'Defanged');
});

test('copy and the .txt export follow the display: defanged values only, the live value is never put on the clipboard', function () {
  var p = page('true');
  p.doc.querySelector('.hl-ioctable__btn[data-act="copy"]').dispatchEvent(new p.win.Event('click', { bubbles: true }));
  assert.strictEqual(p.cap.clipboard, ROWS.map(function (r) { return r.shown; }).join('\n'));
  assert.strictEqual(/198\.51\.100\.17|evil\.example\.xyz|https?:\/\//.test(p.cap.clipboard), false, 'no live address, name or scheme in the copied text');
  p.doc.querySelector('.hl-ioctable__btn[data-act="txt"]').dispatchEvent(new p.win.Event('click', { bubbles: true }));
  assert.strictEqual(p.win.__lastDownloadText, ROWS.map(function (r) { return r.shown; }).join('\n'));
});

test('pressing the button is the reader\'s own step to the live values; pressing again defangs again, byte for byte', function () {
  var p = page('true');
  press(p);
  assert.deepStrictEqual(shown(p.doc), ROWS.map(function (r) { return r.live; }));
  assert.strictEqual(p.doc.querySelector('.hl-ioctable__btn[data-act="defang"]').getAttribute('aria-pressed'), 'false');
  press(p);
  assert.deepStrictEqual(shown(p.doc), ROWS.map(function (r) { return r.shown; }));
});

test('control: the same page with the button unpressed starts live, as every page did before 2026-11-02', function () {
  var p = page('false');
  assert.deepStrictEqual(shown(p.doc), ROWS.map(function (r) { return r.live; }));
});

test('the viewer\'s own defang writes every scheme of a URL, one inside the path included, and every dot, as the layout prints it', function () {
  var p = page('false');
  press(p);              // live -> defanged by the script's own function
  assert.deepStrictEqual(shown(p.doc).slice(0, 4), ROWS.slice(0, 4).map(function (r) { return r.live.replace(/^http:\/\//, 'hxxp://').replace(/\/https:\/\//, '/hxxps://').replace(/\./g, '[.]').replace(/@/g, '[@]'); }));
});
