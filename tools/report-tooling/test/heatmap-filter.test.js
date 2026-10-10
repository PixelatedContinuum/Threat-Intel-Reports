'use strict';

/* Tests for the heatmap filter on /techniques/: the narrowing, the empty
   state, and the #q= mirror that makes a filtered view a shareable link.
   jsdom has no layout, so these prove selection and URL state; how it looks
   stays a browser check. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var path = require('node:path');
var JSDOM = require('jsdom').JSDOM;

var ROOT = path.join(__dirname, '..', '..', '..');
var SCRIPT = fs.readFileSync(path.join(ROOT, 'assets', 'js', 'heatmap-filter.js'), 'utf8');

var PAGE =
  '<input id="hl-heatmap-q" type="text">' +
  '<div id="hl-heatmap">' +
    '<div class="hl-heatmap__col"><a class="hl-heatmap__cell" data-q="t1059.001 powershell"></a><a class="hl-heatmap__cell" data-q="t1204 user execution"></a></div>' +
    '<div class="hl-heatmap__col"><a class="hl-heatmap__cell" data-q="t1071.001 web protocols"></a></div>' +
  '</div>' +
  '<p id="hl-heatmap-empty" hidden></p>';

function build(url) {
  var dom = new JSDOM('<body>' + PAGE + '</body>', { runScripts: 'outside-only', url: url || 'http://localhost/techniques/' });
  dom.window.eval(SCRIPT);
  return dom.window;
}
function type(w, v) {
  var q = w.document.getElementById('hl-heatmap-q');
  q.value = v;
  q.dispatchEvent(new w.Event('input', { bubbles: true }));
}
function shown(w) {
  return [].slice.call(w.document.querySelectorAll('.hl-heatmap__cell')).filter(function (c) { return !c.hidden; }).length;
}

test('typing narrows the cells, empties a column and shows the empty message when nothing matches', function () {
  var w = build();
  assert.equal(shown(w), 3);
  type(w, 'T1059');
  assert.equal(shown(w), 1);
  assert.equal(w.document.querySelectorAll('.hl-heatmap__col.is-empty').length, 1);
  type(w, 'nothing here');
  assert.equal(shown(w), 0);
  assert.equal(w.document.getElementById('hl-heatmap-empty').hidden, false);
});

test('the filter is mirrored into #q= and dropped when the box empties, with no history entries', function () {
  var w = build();
  type(w, 'web');
  assert.equal(w.location.hash, '#q=web');
  assert.equal(w.history.length, 1);
  type(w, 'web protocols');
  assert.equal(w.location.hash, '#q=web%20protocols');
  type(w, '');
  assert.equal(w.location.hash, '');
  assert.equal(shown(w), 3);
});

test('a shared #q= link lands filtered, and a hashchange re-applies', function () {
  var w = build('http://localhost/techniques/#q=T1204');
  assert.equal(w.document.getElementById('hl-heatmap-q').value, 'T1204');
  assert.equal(shown(w), 1);
  w.location.hash = '#q=t1071';
  return new Promise(function (r) { setTimeout(r, 20); }).then(function () {
    assert.equal(w.document.getElementById('hl-heatmap-q').value, 't1071');
    assert.equal(shown(w), 1);
  });
});

test('a hash that is not ours is left alone and not read as a filter', function () {
  var w = build('http://localhost/techniques/#most-mapped');
  assert.equal(shown(w), 3);
  assert.equal(w.location.hash, '#most-mapped');
  type(w, '');
  assert.equal(w.location.hash, '#most-mapped', 'an empty box never clears someone else\'s anchor');
  type(w, 'T1204');
  assert.equal(w.location.hash, '#q=T1204');
});
