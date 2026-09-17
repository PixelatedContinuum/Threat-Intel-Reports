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

test('each button shows its name and its reading time on one line, not a bare count', function () {
  var d = build([1, 2, 3]);
  var body = d.querySelector('.hl-post-content');
  var c = RS.buildControl(d, 'full', RS.sectionCounts(body), RS.readingMinutes(body));
  var btns = c.querySelectorAll('button');
  assert.strictEqual(btns[0].querySelector('.hl-viewswitch__btn-name').textContent, 'Executive Brief');
  // The old bare section count is gone from the button face entirely.
  assert.strictEqual(btns[0].querySelector('.hl-viewswitch__btn-count'), null);
  var t0 = btns[0].querySelector('.hl-viewswitch__btn-time').textContent;
  var t2 = btns[2].querySelector('.hl-viewswitch__btn-time').textContent;
  assert.match(t0, /^· \d+ min$/);
  assert.match(t2, /^· \d+ min$/);
  // The sentence is NOT in the button; it belongs to the status strip.
  assert.strictEqual(btns[0].querySelector('.hl-viewswitch__btn-desc'), null);
});

test('the accessible name still carries the explanation the button no longer shows, plus the time', function () {
  var d = build([1, 2, 3]);
  var body = d.querySelector('.hl-post-content');
  var c = RS.buildControl(d, 'full', RS.sectionCounts(body), RS.readingMinutes(body));
  assert.match(c.querySelector('button').getAttribute('aria-label'),
    /^Executive Brief: the bottom line and what to do, 1 section, about \d+ min$/);
});

test('buildControl still works with no counts or minutes, so the signature stays additive', function () {
  var d = build([1, 2, 3]);
  var c = RS.buildControl(d, 'full');
  assert.strictEqual(c.querySelectorAll('button').length, 3);
  assert.strictEqual(c.querySelector('.hl-viewswitch__btn-count'), null);
  assert.strictEqual(c.querySelector('.hl-viewswitch__btn-time'), null);
  assert.strictEqual(c.querySelector('button').getAttribute('aria-label'),
    'Executive Brief: the bottom line and what to do');
});

test('readingMinutes gives each view a positive, non-decreasing minute count', function () {
  var body = build([1, 2, 3]).querySelector('.hl-post-content');
  var m = RS.readingMinutes(body);
  assert.ok(m.brief >= 1);
  assert.ok(m.analyst >= m.brief);
  assert.ok(m.full >= m.analyst);
});

test('readingMinutes counts tier 1 sections only for brief, tier 1+2 for analyst', function () {
  // 200 words per tier-1 section, 1 tier-1 section: brief should land at 1 min
  // for a small page and grow once tier 2 content is added.
  var doc = new (require('jsdom').JSDOM)(
    '<body><div class="hl-post-content">' +
    '<h2 class="hl-tier-1">S0</h2><p>' + new Array(201).join('w ') + '</p>' +
    '<h2 class="hl-tier-2">S1</h2><p>' + new Array(201).join('w ') + '</p>' +
    '</div></body>').window.document;
  var body = doc.querySelector('.hl-post-content');
  var m = RS.readingMinutes(body);
  assert.strictEqual(m.brief, 1);
  assert.strictEqual(m.analyst, 2);
});

test('readingMinutes excludes a collapsed teardown from the tier that owns it', function () {
  var doc = new (require('jsdom').JSDOM)(
    '<body><div class="hl-post-content">' +
    '<h2 class="hl-tier-1">S0</h2><p>' + new Array(201).join('w ') + '</p>' +
    '<details class="hl-teardown"><summary>more</summary><p>' + new Array(2001).join('w ') + '</p></details>' +
    '</div></body>').window.document;
  var body = doc.querySelector('.hl-post-content');
  var collapsed = RS.readingMinutes(body);
  doc.querySelector('details.hl-teardown').open = true;
  var opened = RS.readingMinutes(body);
  assert.strictEqual(collapsed.brief, 1);
  assert.ok(opened.brief > collapsed.brief);
});

test('readingMinutes.full takes window.HLReadTime.visibleMinutes verbatim when present, so it can never disagree with the header', function () {
  var body = build([1, 2, 3]).querySelector('.hl-post-content');
  global.window = global.window || {};
  window.HLReadTime = { visibleMinutes: 61, totalMinutes: 64, wordsPerMinute: 200 };
  var m = RS.readingMinutes(body);
  assert.strictEqual(m.full, 61);
  assert.strictEqual(m.fullIsExact, true);
  delete window.HLReadTime;
});

test('readingMinutes.full falls back to its own estimate when window.HLReadTime is missing', function () {
  var body = build([1, 2, 3]).querySelector('.hl-post-content');
  global.window = global.window || {};
  delete window.HLReadTime;
  var m = RS.readingMinutes(body);
  assert.strictEqual(m.fullIsExact, false);
  assert.ok(m.full >= 1);
});

function withControl(tiers, view) {
  var d = build(tiers);
  var body = d.querySelector('.hl-post-content');
  body.insertBefore(RS.buildControl(d, view, RS.sectionCounts(body)), body.firstChild);
  return d;
}

test('the status describes the active view, never blank', function () {
  var d = withControl([1, 2, 3], 'full');
  RS.apply(d, 'full');
  assert.strictEqual(d.getElementById('hl-view-status').textContent,
    '3 of 3 sections, adds the deep teardown');
  RS.apply(d, 'brief');
  assert.strictEqual(d.getElementById('hl-view-status').textContent,
    '1 of 3 sections, the bottom line and what to do');
});

test('a preview shows another view without changing the active one', function () {
  var d = withControl([1, 2, 3], 'brief');
  RS.apply(d, 'brief');
  RS.setStatus(d, 'brief', 'full');
  var live = d.getElementById('hl-view-status');
  assert.strictEqual(live.textContent, '3 of 3 sections, adds the deep teardown');
  assert.ok(live.hasAttribute('data-preview'));
  // still filtered to brief
  assert.strictEqual(d.getElementById('s2').hasAttribute('hidden'), true);
});

test('previewing the active view is not marked as a preview', function () {
  var d = withControl([1, 2, 3], 'brief');
  RS.setStatus(d, 'brief', 'brief');
  assert.strictEqual(d.getElementById('hl-view-status').hasAttribute('data-preview'), false);
});

test('the button names use the house register-tier vocabulary', function () {
  var d = build([1, 2, 3]);
  var c = RS.buildControl(d, 'full', RS.sectionCounts(d.querySelector('.hl-post-content')));
  assert.deepStrictEqual(
    [...c.querySelectorAll('.hl-viewswitch__btn-name')].map(function (n) { return n.textContent; }),
    ['Executive Brief', 'Tradecraft & Intel', 'Full Teardown']);
});

test('the status counts against the full total in every view', function () {
  var d = withControl([1, 1, 2, 2, 3], 'full');
  RS.apply(d, 'analyst');
  assert.match(d.getElementById('hl-view-status').textContent, /^4 of 5 sections, /);
  RS.apply(d, 'brief');
  assert.match(d.getElementById('hl-view-status').textContent, /^2 of 5 sections, /);
});

test('the control renders no standalone label, the names carry it', function () {
  var d = build([1, 2, 3]);
  var c = RS.buildControl(d, 'full', RS.sectionCounts(d.querySelector('.hl-post-content')));
  assert.strictEqual(c.querySelector('.hl-viewswitch__label'), null);
  assert.strictEqual(c.children.length, 2);
});
