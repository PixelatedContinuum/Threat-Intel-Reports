'use strict';

/* T-0500.1.7.8 finding 3 (v6 review, quarantined) and its P2c follow-up.

   A stage the attack-chain filter leaves unmatched keeps `.hl-rv-stage-muted`; the tactic key
   de-emphasises the rest with `.hl-rv-stage-dim`. The first fix (site 3332018) removed the muted
   card's `opacity: .6`, which had dropped its h4 (#a8a8a8) to 3.69:1 and its procedure `small` to
   3.44:1 (P1.triage.md, finding 3), and moved the mute onto the card's edge and fill. But that rule
   is `.hl-rv-stage-muted` (0,1,0) and `.hl-report-page .hl-rv-stage` (0,2,0, later in the file) sets
   `border` and `background` too, so on a report page the mute was declared and discarded: a muted
   stage looked exactly like a matched one. The dim card still muted with `opacity: .45`, which drops
   every text colour on it, and the inline-figure rule (0,4,0) resets border and fill as well. The
   test that shipped with the fix read the muted rule's own declaration, so it passed throughout.

   This file therefore resolves the CASCADE, not a declaration: it matches every rule in the
   stylesheet against a stage element in each page kind, takes the winner by specificity (later wins
   a tie), and asserts that the muted and dim cards resolve a different fill and edge from a plain
   card, that the edge is visible at 3:1 against the page and the card (WCAG 1.4.11, because the fill
   step alone is 1.02:1 on this dark page), that their text stays at 4.5:1 on the fill it actually ends
   up on, that the spine dot loses its accent ring, and that no rule mutes them with opacity.

   THE READER'S LIMITS, all deliberate:
   - It is a substring/compound reader for class, element, pseudo-class and pseudo-element selectors,
     with descendant combinators only. `>`, `+` and `~` make a selector match nothing (no stage rule
     uses them); `#id` and `[attr]` never match (none targets a stage); `:has()`, `:not()`, `:hover`,
     `:focus` and every other pseudo-class are not evaluated, except `:is()` over simple compounds.
   - Media conditions are not evaluated: a rule inside any `@media` other than `print` is treated as
     applying at every width. `print` is excluded, because these rules describe the screen and the
     print block repaints the tokens on white.
   - Custom properties are read as the LAST declaration of that property outside `@media print`, which
     is how the report scope's own block (`html:has(.hl-report-page)`, the T-0556 one) overrides the
     base token block; the cascade is not run for the tokens themselves.
   - Shorthands are expanded only where this file needs them: `background` -> `background-color`,
     `border`/`border-style`/`border-top` -> `border-top-style`. A multi-value `border-style` is read
     per side (first value = top), and `!important` beats specificity.
   - No layout, no computed styles, no browser: a colour this reader cannot parse is an error, not a
     silent pass. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var path = require('node:path');

var reader = require('./lib/cascade-reader');

var RULES = reader.RULES, TOKENS = reader.TOKENS, isPrint = reader.isPrint, splitTop = reader.splitTop;
var parseCompound = reader.parseCompound, specOf = reader.specOf, specText = reader.specText;
var selectorMatches = reader.selectorMatches, resolve = reader.resolve, resolved = reader.resolved;
var resolveValue = reader.resolveValue, colourValue = reader.colourValue;
var rgb = reader.rgb, rgbText = reader.rgbText, over = reader.over, lum = reader.lum, ratio = reader.ratio, round = reader.round;

/* ---------- the two page kinds, and the stage element in each ---------- */

var PAGE_BG = rgb(TOKENS['--rv-bg']);

var CONTEXTS = [
  {
    name: 'a report page',
    chain: [
      { tag: 'body', classes: [] },
      { tag: 'main', classes: ['hl-report-page'] },
      { tag: 'div', classes: ['hl-post-content'] },
      { tag: 'div', classes: ['hl-rv-stages'] }
    ]
  },
  {
    name: 'an inline-figure report page',
    chain: [
      { tag: 'body', classes: [] },
      { tag: 'main', classes: ['hl-report-page', 'hl-figs-inline'] },
      { tag: 'div', classes: ['hl-post-content'] },
      { tag: 'figure', classes: ['hl-fig'] },
      { tag: 'div', classes: ['hl-rv-stages'] }
    ]
  }
];

var CLASSES = [
  { name: 'muted', cls: 'hl-rv-stage-muted' },
  { name: 'dim', cls: 'hl-rv-stage-dim' }
];

function stageEl(cls) { return { tag: 'article', classes: ['hl-rv-stage'].concat(cls ? [cls] : []) }; }

/* the fill the card actually ends up on: its resolved background-color, over the page when it is not opaque */
function stageFill(context, cls) {
  var hit = resolved(stageEl(cls), context.chain, 'background-color');
  return { colour: colourValue(hit.value, PAGE_BG), hit: hit };
}

function contrastOf(el, chain, fill, label) {
  var colour = resolved(el, chain, 'color');
  var fg = rgb(colour.value);
  var r = ratio(fg, fill);
  assert.ok(r >= 4.5, label + ' is ' + r.toFixed(2) + ':1 (' + rgbText(fg) + ' on ' + rgbText(fill) +
    ', from ' + colour.sel + ' at ' + specText(colour.spec) + '), under the 4.5:1 normal-text floor');
  return r;
}

/* ---------- the control: the old rule's own figures ---------- */

test('control: the computation reproduces the triage figures for the old rule (h4 3.69:1, procedure small 3.44:1)', function () {
  var h4 = { text: round(over(rgb('#a8a8a8'), rgb('#1c1c1c'), 0.6)), fill: round(over(rgb('#111111'), rgb('#1c1c1c'), 0.6)) };
  assert.strictEqual(ratio(h4.text, h4.fill).toFixed(2), '3.69');
  var small = { text: round(over(rgb('#a8a8a8'), rgb('#1c1c1c'), 0.6)), fill: round(over(rgb('#1c1c1c'), rgb('#1c1c1c'), 0.6)) };
  assert.strictEqual(ratio(small.text, small.fill).toFixed(2), '3.44');
});

/* ---------- 4 cascade cases: 2 classes x 2 page kinds ---------- */

test('the muted and dim stage resolve a different fill and edge from a plain stage, in every page kind', function () {
  var cases = 0;
  CONTEXTS.forEach(function (context) {
    var plainFill = stageFill(context, null);
    var plainEdge = resolved(stageEl(null), context.chain, 'border-top-style');
    CLASSES.forEach(function (kind) {
      var el = stageEl(kind.cls);
      var fill = stageFill(context, kind.cls);
      var edge = resolved(el, context.chain, 'border-top-style');
      var where = kind.name + ' stage on ' + context.name;
      assert.notStrictEqual(rgbText(fill.colour), rgbText(plainFill.colour),
        where + ': the fill resolves to ' + rgbText(fill.colour) + ', the same as a plain stage\'s ' +
        rgbText(plainFill.colour) + ' (winning rule ' + fill.hit.sel + ' at ' + specText(fill.hit.spec) +
        '); the mute is declared and discarded');
      assert.notStrictEqual(edge.value, plainEdge.value,
        where + ': the top edge resolves to `' + edge.value + '`, the same as a plain stage\'s `' +
        plainEdge.value + '` (winning rule ' + edge.sel + ' at ' + specText(edge.spec) + ')');
      /* a dashed edge is the mark the reader sees, and the fill step alone is 1.02:1 on this dark page; a mark
         that cannot be seen is no mute, so the edge holds WCAG 1.4.11's 3:1 against the page and the card it
         sits between */
      var edgeColour = colourValue(resolved(el, context.chain, 'border-top-color').value, null);
      [['the page', PAGE_BG], ['the card fill', fill.colour]].forEach(function (pair) {
        var r = ratio(edgeColour, pair[1]);
        assert.ok(r >= 3, where + ': the mute edge is ' + rgbText(edgeColour) + ' on ' + pair[0] + ' ' +
          rgbText(pair[1]) + ' = ' + r.toFixed(2) + ':1, under the 3:1 a non-text mark needs to be seen');
      });
      cases++;
    });
  });
  assert.strictEqual(cases, 4, 'the denominator is 2 classes x 2 page kinds');
});

test('the muted and dim stage text keeps 4.5:1 on the fill it ends up on, in every page kind', function () {
  var measured = [];
  CONTEXTS.forEach(function (context) {
    CLASSES.forEach(function (kind) {
      var stage = stageEl(kind.cls);
      var chain = context.chain.concat([stage]);
      var fill = stageFill(context, kind.cls).colour;
      var where = kind.name + ' stage on ' + context.name;
      measured.push(contrastOf({ tag: 'h4', classes: [] }, chain, fill, where + ': the h4'));
      measured.push(contrastOf({ tag: 'p', classes: [] }, chain, fill, where + ': the body text'));
    });
  });
  assert.strictEqual(measured.length, 8, 'two text colours in each of the 4 cascade cases');
});

test('the procedure small text inside a muted or dim stage keeps 4.5:1 on its own card', function () {
  var measured = [];
  CONTEXTS.forEach(function (context) {
    CLASSES.forEach(function (kind) {
      var stage = stageEl(kind.cls);
      var proc = { tag: 'a', classes: ['hl-rv-procedure'] };
      var chain = context.chain.concat([stage]);
      var stageFillColour = stageFill(context, kind.cls).colour;
      var card = resolved(proc, chain, 'background-color');
      var fill = colourValue(card.value, stageFillColour);
      measured.push(contrastOf({ tag: 'small', classes: [] }, chain.concat([proc]), fill,
        kind.name + ' procedure small on ' + context.name));
    });
  });
  assert.strictEqual(measured.length, 4, 'one procedure card in each of the 4 cascade cases');
});

test('no stage rule mutes a muted or dim card with opacity', function () {
  var offenders = [];
  CONTEXTS.forEach(function (context) {
    CLASSES.forEach(function (kind) {
      var el = stageEl(kind.cls);
      RULES.forEach(function (rule) {
        if (isPrint(rule.media)) return;
        var matched = splitTop(rule.sel, ',').some(function (s) { return selectorMatches(s, el, context.chain, null); });
        if (!matched) return;
        rule.decls.forEach(function (d) {
          if (d.prop !== 'opacity') return;
          var v = parseFloat(d.value);
          if (!(v >= 1)) offenders.push(kind.name + ' on ' + context.name + ': `' + rule.sel + ' { opacity: ' + d.value + ' }`');
        });
      });
    });
  });
  assert.deepEqual(offenders, [], 'a text-bearing stage card is muted by opacity, which drops every text colour on it: ' + offenders.join('; '));
});

test('the spine dot loses its accent ring on a muted or dim card, and an inline page draws no dot', function () {
  var page = CONTEXTS[0];
  CLASSES.forEach(function (kind) {
    var ring = resolved(stageEl(kind.cls), page.chain, 'border-top-color', 'before');
    assert.match(ring.value, /var\(--rv-(line|muted|row-line)\)/,
      'the ' + kind.name + ' stage\'s dot is still ringed in ' + ring.value + ' (' + ring.sel + '), the accent a matching stage carries');
  });
  var inline = CONTEXTS[1];
  var drawn = resolve(stageEl('hl-rv-stage-muted'), inline.chain, 'content', 'before');
  assert.ok(drawn && drawn.value === 'none', 'an inline page still draws the spine dot on a muted card');
});
