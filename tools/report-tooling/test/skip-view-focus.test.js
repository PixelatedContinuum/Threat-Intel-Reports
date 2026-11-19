'use strict';

/* T-0500.1.7.8 finding 2 (v6 review, quarantined): "Skip this view" was `display: none`, so it was never in the
   tab order and its `:focus { display: inline-flex }` rule was dead code (P1.triage.md, finding 2:
   assets/css/hl-report-tabs.css:307-308).

   The link is generated for every non-inline view (assets/js/hl-report-tabs.js, `hl-rv-skip-view`), so it must be
   in the keyboard order at rest and painted when it takes focus. A `display: none` element is not focusable, and
   `visibility: hidden` is not either, so this reads the stylesheet: the base rule hides it visually (off-layout,
   clipped), and the focus rule puts it back in the flow with a border, a background and its own size.

   The browser gate's keyboard harness (pressKey, check-browser-report.js) has no report row that walks the tab
   order from the view summary into a generated view, and a new row could only be proved by a live browser run, so
   the fix is covered here by the stylesheet assertion and the gate row is left to a run that needs one anyway.
   Stated in the report. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var path = require('node:path');

var CSS = fs.readFileSync(path.join(__dirname, '../../../assets/css/hl-report-tabs.css'), 'utf8');

/* every declaration block in the stylesheet, comments removed; a rule inside @media is returned with its own selector */
function rules(css) {
  var text = css.replace(/\/\*[\s\S]*?\*\//g, '');
  var out = [], m, re = /([^{}]+)\{([^{}]*)\}/g;
  while ((m = re.exec(text))) {
    var decls = {};
    m[2].split(';').forEach(function (line) {
      var i = line.indexOf(':');
      if (i < 0) return;
      decls[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    });
    out.push({ sel: m[1].trim(), decls: decls });
  }
  return out;
}
function selectors(sel) { return sel.split(',').map(function (s) { return s.trim(); }); }
function rulesFor(sel, pred) {
  return rules(CSS).filter(function (r) { return selectors(r.sel).some(function (s) { return pred(s); }); });
}
var SKIP = '.hl-rv-skip-view';
var base = function () {
  var r = rulesFor(SKIP, function (s) { return s === SKIP; });
  assert.strictEqual(r.length, 1, 'the class has exactly one base rule');
  return r[0].decls;
};
function focusRule() {
  var r = rulesFor(SKIP, function (s) { return s === SKIP + ':focus' || s === SKIP + ':focus-visible'; });
  assert.ok(r.length >= 1, 'a :focus or :focus-visible rule restores the link');
  return r[0].decls;
}

test('finding 2: the skip link is not display:none, so it can take focus', function () {
  var d = base();
  assert.notStrictEqual(d.display, 'none', 'display:none keeps the link out of the tab order and makes its :focus rule dead code');
  assert.notStrictEqual(d.visibility, 'hidden', 'visibility:hidden is not focusable either');
});

test('finding 2: at rest it is visually hidden without leaving the layout flow behind', function () {
  var d = base();
  assert.strictEqual(d.position, 'absolute');
  assert.strictEqual(d.width, '1px');
  assert.strictEqual(d.height, '1px');
  assert.ok(d.clip || d['clip-path'], 'clipped, not laid out at 1px');
  assert.strictEqual(d.overflow, 'hidden');
});

test('finding 2: on :focus / :focus-visible it is back in the flow, full size, with a border and a fill', function () {
  var d = focusRule();
  assert.notStrictEqual(d.display, 'none');
  assert.strictEqual(d.position, 'static', 'back in the flow where it was inserted, above the view it skips');
  assert.strictEqual(d.width, 'auto');
  assert.strictEqual(d.height, 'auto');
  assert.ok(/^(auto|none)$/.test(d['clip'] || 'auto') && /^(none|auto)$/.test(d['clip-path'] || 'none'), 'not still clipped');
  assert.ok(d.border, 'a visible edge');
  assert.ok(d.background, 'a visible fill');
});

test('control: the same reader sees a rule that is display:none and a focus rule that is not, so each assertion above can fail', function () {
  var fake = '.hl-rv-skip-view { display: none; } .hl-rv-skip-view:focus { display: inline-flex; }';
  var rs = rules(fake);
  assert.strictEqual(rs.length, 2);
  assert.strictEqual(rs[0].decls.display, 'none');
  assert.strictEqual(rs[1].decls.display, 'inline-flex');
});
