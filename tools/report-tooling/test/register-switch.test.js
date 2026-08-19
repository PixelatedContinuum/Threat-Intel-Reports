'use strict';
var test = require('node:test');
var assert = require('node:assert');
var JSDOM = require('jsdom').JSDOM;
var RS = require('../../../assets/js/register-switch.js');

function build(tiers, opts) {
  opts = opts || {};
  var html = '<div class="hl-post-content"><p id="meta">campaign metadata</p>';
  tiers.forEach(function (t, i) {
    html += '<h2 id="s' + i + '"' + (t ? ' class="hl-tier-' + t + '"' : '') + '>S' + i + '</h2>';
    html += '<p id="p' + i + '">body ' + i + '</p><h3 id="h3-' + i + '">sub</h3>';
  });
  html += '</div>';
  var toc = '<aside id="hl-toc"><ul id="hl-toc-list">' + tiers.map(function (t, i) {
    return '<li class="hl-toc__item"><a href="#s' + i + '">S' + i + '</a></li>';
  }).join('') + '</ul></aside>';
  return new JSDOM('<body>' + html + toc + '</body>').window.document;
}

test('tierOf reads the marker class', function () {
  var d = build([1, 2]);
  assert.strictEqual(RS.tierOf(d.getElementById('s0')), 1);
  assert.strictEqual(RS.tierOf(d.getElementById('s1')), 2);
});

test('sectionsFor groups each h2 with everything up to the next h2', function () {
  var d = build([1, 2, 3]);
  var secs = RS.sectionsFor(d.querySelector('.hl-post-content'));
  assert.strictEqual(secs.length, 3);
  assert.strictEqual(secs[0].tier, 1);
  // heading + p + h3
  assert.strictEqual(secs[0].nodes.length, 3);
  assert.ok(secs[0].nodes.indexOf(d.getElementById('p0')) !== -1);
  assert.ok(secs[0].nodes.indexOf(d.getElementById('h3-0')) !== -1);
});

test('content before the first h2 is never part of a section', function () {
  var d = build([1, 2]);
  var secs = RS.sectionsFor(d.querySelector('.hl-post-content'));
  secs.forEach(function (s) {
    assert.ok(s.nodes.indexOf(d.getElementById('meta')) === -1);
  });
});

test('brief hides tier 2 and 3, keeps tier 1 and the metadata block', function () {
  var d = build([1, 2, 3]);
  RS.apply(d, 'brief');
  assert.strictEqual(d.getElementById('s0').hasAttribute('hidden'), false);
  assert.strictEqual(d.getElementById('p0').hasAttribute('hidden'), false);
  assert.strictEqual(d.getElementById('s1').hasAttribute('hidden'), true);
  assert.strictEqual(d.getElementById('p1').hasAttribute('hidden'), true);
  assert.strictEqual(d.getElementById('s2').hasAttribute('hidden'), true);
  assert.strictEqual(d.getElementById('meta').hasAttribute('hidden'), false);
});

test('analyst keeps tiers 1 and 2 and hides tier 3', function () {
  var d = build([1, 2, 3]);
  RS.apply(d, 'analyst');
  assert.strictEqual(d.getElementById('s1').hasAttribute('hidden'), false);
  assert.strictEqual(d.getElementById('s2').hasAttribute('hidden'), true);
});

test('full restores everything', function () {
  var d = build([1, 2, 3]);
  RS.apply(d, 'brief');
  RS.apply(d, 'full');
  [0, 1, 2].forEach(function (i) {
    assert.strictEqual(d.getElementById('s' + i).hasAttribute('hidden'), false);
    assert.strictEqual(d.getElementById('p' + i).hasAttribute('hidden'), false);
  });
});

test('a hidden section hides its TOC entry too', function () {
  var d = build([1, 2, 3]);
  RS.apply(d, 'brief');
  var li = d.querySelector('#hl-toc-list a[href="#s1"]').closest('li');
  assert.strictEqual(li.hasAttribute('hidden'), true);
  var keep = d.querySelector('#hl-toc-list a[href="#s0"]').closest('li');
  assert.strictEqual(keep.hasAttribute('hidden'), false);
});

test('an unmarked section is treated as tier 1 so it can never vanish', function () {
  var d = build([1, null, 3]);
  RS.apply(d, 'brief');
  assert.strictEqual(d.getElementById('s1').hasAttribute('hidden'), false);
});

test('apply is idempotent', function () {
  var d = build([1, 2, 3]);
  RS.apply(d, 'brief');
  RS.apply(d, 'brief');
  assert.strictEqual(d.getElementById('s1').hasAttribute('hidden'), true);
  RS.apply(d, 'full');
  assert.strictEqual(d.getElementById('s1').hasAttribute('hidden'), false);
});

test('distinctTiers counts what the control needs', function () {
  assert.strictEqual(RS.distinctTiers(build([1, 2, 3]).querySelector('.hl-post-content')), 3);
  assert.strictEqual(RS.distinctTiers(build([1, 1]).querySelector('.hl-post-content')), 1);
});

test('buildControl makes three buttons with full pressed', function () {
  var d = build([1, 2, 3]);
  var c = RS.buildControl(d, 'full');
  var btns = c.querySelectorAll('button');
  assert.strictEqual(btns.length, 3);
  assert.strictEqual(btns[2].getAttribute('aria-pressed'), 'true');
  assert.strictEqual(btns[0].getAttribute('aria-pressed'), 'false');
});

test('revealFor switches to the view that shows a hidden target', function () {
  var d = build([1, 2, 3]);
  RS.apply(d, 'brief');
  assert.strictEqual(RS.revealFor(d, 's2'), 'full');
  assert.strictEqual(d.getElementById('s2').hasAttribute('hidden'), false);
});

test('revealFor leaves the view alone when the target is already visible', function () {
  var d = build([1, 2, 3]);
  RS.apply(d, 'brief');
  assert.strictEqual(RS.revealFor(d, 's0'), null);
  assert.strictEqual(d.getElementById('s1').hasAttribute('hidden'), true);
});

test('revealFor resolves a target nested inside a hidden section', function () {
  var d = build([1, 2, 3]);
  RS.apply(d, 'brief');
  assert.strictEqual(RS.revealFor(d, 'p2'), 'full');
  assert.strictEqual(d.getElementById('p2').hasAttribute('hidden'), false);
});

test('sectionCounts reports what each view would show', function () {
  var body = build([1, 1, 2, 2, 2, 3]).querySelector('.hl-post-content');
  assert.deepStrictEqual(RS.sectionCounts(body), { brief: 2, analyst: 5, full: 6 });
});

test('an unmarked section counts toward brief, matching how apply treats it', function () {
  var body = build([1, null, 3]).querySelector('.hl-post-content');
  assert.deepStrictEqual(RS.sectionCounts(body), { brief: 2, analyst: 2, full: 3 });
});

test('each button carries a name and a visible explanation with its count', function () {
  var d = build([1, 2, 3]);
  var c = RS.buildControl(d, 'full', RS.sectionCounts(d.querySelector('.hl-post-content')));
  var btns = c.querySelectorAll('button');
  assert.strictEqual(btns[0].querySelector('.hl-viewswitch__btn-name').textContent, 'Brief');
  assert.match(btns[0].querySelector('.hl-viewswitch__btn-desc').textContent,
    /bottom line only, 1 section$/);
  assert.match(btns[2].querySelector('.hl-viewswitch__btn-desc').textContent,
    /teardown included, 3 sections$/);
});

test('the accessible name is one readable string, not two stacked fragments', function () {
  var d = build([1, 2, 3]);
  var c = RS.buildControl(d, 'full', RS.sectionCounts(d.querySelector('.hl-post-content')));
  assert.strictEqual(c.querySelector('button').getAttribute('aria-label'),
    'Brief: The bottom line only, 1 section');
});

test('buildControl still works with no counts, so the signature stays additive', function () {
  var d = build([1, 2, 3]);
  var c = RS.buildControl(d, 'full');
  assert.strictEqual(c.querySelectorAll('button').length, 3);
  assert.strictEqual(c.querySelector('.hl-viewswitch__btn-desc').textContent,
    'The bottom line only');
});

test('the status reads as a count in every view, never blank', function () {
  var d = build([1, 2, 3]);
  d.querySelector('.hl-post-content').insertBefore(
    RS.buildControl(d, 'full', RS.sectionCounts(d.querySelector('.hl-post-content'))),
    d.querySelector('.hl-post-content').firstChild);
  RS.apply(d, 'full');
  assert.strictEqual(d.getElementById('hl-view-status').textContent, 'Showing all 3 sections');
  RS.apply(d, 'brief');
  assert.strictEqual(d.getElementById('hl-view-status').textContent, 'Showing 1 of 3 sections');
});
