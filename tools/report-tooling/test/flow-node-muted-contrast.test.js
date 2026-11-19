'use strict';

/* T-0680: the attack-chain step buttons keep their text contrast when muted.

   A step button (`button.hl-rv-fnode` in `.hl-rv-flow`) carries three text colours: its name
   (`.hl-rv-fnm`, #ffffff), its linked count (`.hl-rv-fct`, var(--rv-muted)) and its number
   (`.hl-rv-fnum`, #111111 on var(--acc)). The chain filter marks a step with no matching rows
   `.is-muted` (js:1440) and the tactic key marks every step that does not carry the hovered or
   pinned tactic `.is-dim` (js:1419-1420). Both used to be muted with `opacity: .4`
   (css:1011 before this fix), which drops every text colour on the button at once, the same defect
   T-0500.1.7.8 finding 3 fixed for the stage cards and 77b2887 carried onto the card's edge and fill.

   This file resolves the CASCADE through test/lib/cascade-reader.js (its header states the reader's
   limits), not a declaration: a mute rule that a later, more specific rule overrides (the 0,3,1 node
   rule at css:997, or the 0,5,1 inline reset at css:1431/1499) passes a declaration-only test and does
   nothing on the page. The cases are 2 mute states x 2 page kinds = 4, plus a plain-step baseline per
   page kind = 2. For each: the resolved fill and edge differ from the plain step's, the edge reaches
   3:1 against the surface and the plain step (WCAG 1.4.11), each of the three text colours reaches
   4.5:1 on the fill it resolves to, and no matching rule sets opacity below 1.

   The tactic state is read as `.is-dim`, not as the old `has-link :not(.is-linked)`: the script toggles
   `is-linked` and `is-dim` together as opposites on every step (js:1419-1420), so `.is-dim` is exactly
   the set the `:not()` form described, and the reader (which does not evaluate `:not()`) can check it.
   The is-muted half of the old selector is still inside the reader, so the pre-fix tree fails here on
   the 0.4 opacity; the `:not()` half is NOT CHECKED by this reader and is covered by the class form.

   Two reader limits this file leans on: it does not composite `opacity` onto a fill, so a mute by
   opacity is caught by scanning for the property and never by the contrast arithmetic (the text test
   guards the no-opacity state only); and it treats every media query but `print` as always applying,
   so the transition check reads the step's own declarations and skips the reduced-motion reset by
   name. */

var test = require('node:test');
var assert = require('node:assert');

var reader = require('./lib/cascade-reader');

var RULES = reader.RULES, TOKENS = reader.TOKENS, isPrint = reader.isPrint, splitTop = reader.splitTop;
var specText = reader.specText, selectorMatches = reader.selectorMatches, resolve = reader.resolve;
var colourValue = reader.colourValue, rgb = reader.rgb;
var rgbText = reader.rgbText, ratio = reader.ratio;

/* ---------- the two page kinds, the ribbon and the step in each ---------- */

/* The surface a step sits on: the page on a normal report page, the figure panel on an inline page
   (`.hl-fig` paints --hl-fig-bg). A plain inline step has `background: none`, so this is also its fill. */
var CONTEXTS = [
  {
    name: 'a report page',
    surface: TOKENS['--rv-bg'],
    chain: function (ribbonClasses) {
      return [
        { tag: 'body', classes: [] },
        { tag: 'main', classes: ['hl-report-page'] },
        { tag: 'div', classes: ['hl-post-content'] },
        { tag: 'div', classes: ['hl-rv-flowwrap'] },
        { tag: 'ol', classes: ['hl-rv-stage-ribbon', 'hl-rv-flow'].concat(ribbonClasses) },
        { tag: 'li', classes: [] }
      ];
    }
  },
  {
    name: 'an inline-figure report page',
    surface: TOKENS['--hl-fig-bg'],
    chain: function (ribbonClasses) {
      return [
        { tag: 'body', classes: [] },
        { tag: 'main', classes: ['hl-report-page', 'hl-figs-inline'] },
        { tag: 'div', classes: ['hl-post-content'] },
        { tag: 'figure', classes: ['hl-fig', 'hl-fig--chain'] },
        { tag: 'div', classes: ['hl-fig-draw'] },
        { tag: 'div', classes: ['hl-rv-flowwrap'] },
        { tag: 'ol', classes: ['hl-rv-stage-ribbon', 'hl-rv-flow'].concat(ribbonClasses) },
        { tag: 'li', classes: [] }
      ];
    }
  }
];

/* the two mute states, each with the ribbon class the script sets with it */
var STATES = [
  { name: 'muted by the chain filter', cls: 'is-muted', ribbon: [] },
  { name: 'dimmed by the tactic key', cls: 'is-dim', ribbon: ['has-link'] }
];

function stepEl(cls) { return { tag: 'button', classes: ['hl-rv-fnode'].concat(cls ? [cls] : []) }; }

/* the fill a box actually ends up on: its own background over what is underneath it */
function fillOf(el, chain, under) {
  var hit = resolve(el, chain, 'background-color');
  if (!hit) return under;                     /* CSS initial background-color is transparent */
  return colourValue(hit.value, under);
}

function surfaceOf(context) { return rgb(context.surface); }

function nodeFill(context, state) {
  var hit = resolve(stepEl(state ? state.cls : null), context.chain(state ? state.ribbon : []), 'background-color');
  assert.ok(hit, 'no rule sets a background on ' + (state ? state.name : 'a plain step') + ' on ' + context.name);
  return { colour: colourValue(hit.value, surfaceOf(context)), hit: hit };
}

/* the three text colours, each on the fill it resolves to: a number chip paints its own, the name
   and the count are transparent and sit on the step. */
var TEXTS = [
  { name: 'the name', tag: 'strong', cls: 'hl-rv-fnm' },
  { name: 'the linked count', tag: 'small', cls: 'hl-rv-fct' },
  { name: 'the step number', tag: 'span', cls: 'hl-rv-fnum' }
];

/* ---------- the mute must not be an opacity ---------- */

test('no rule mutes a text-bearing flow step with opacity, in any mute state or page kind', function () {
  var offenders = [], checked = 0;
  CONTEXTS.forEach(function (context) {
    STATES.forEach(function (state) {
      var chain = context.chain(state.ribbon), el = stepEl(state.cls);
      checked++;
      RULES.forEach(function (rule) {
        if (isPrint(rule.media)) return;
        var matched = splitTop(rule.sel, ',').some(function (s) { return selectorMatches(s, el, chain, null); });
        if (!matched) return;
        rule.decls.forEach(function (d) {
          if (d.prop !== 'opacity') return;
          var v = parseFloat(d.value);
          if (!(v >= 1)) offenders.push(state.name + ' on ' + context.name + ': `' + rule.sel + ' { opacity: ' + d.value + ' }`');
        });
      });
    });
  });
  assert.strictEqual(checked, 4, 'the denominator is 2 mute states x 2 page kinds');
  assert.deepEqual(offenders, [], 'a text-bearing step is muted by opacity, which drops every label on it: ' + offenders.join('; '));
});

/* ---------- 4 cascade cases + 2 baselines ---------- */

test('the muted and dim step resolve a different fill and a visible edge from a plain step, in every page kind', function () {
  var cases = 0, baselines = 0;
  CONTEXTS.forEach(function (context) {
    var surface = surfaceOf(context);
    var plainFill = nodeFill(context, null);
    var plainEdgeStyle = resolve(stepEl(null), context.chain([]), 'border-top-style');
    var plainEdgeColour = resolve(stepEl(null), context.chain([]), 'border-top-color');
    assert.ok(plainEdgeStyle && plainEdgeColour, 'no rule sets the plain step\'s edge on ' + context.name);
    baselines++;
    STATES.forEach(function (state) {
      var chain = context.chain(state.ribbon), el = stepEl(state.cls);
      var where = state.name + ' on ' + context.name;
      var fill = nodeFill(context, state);
      assert.notStrictEqual(rgbText(fill.colour), rgbText(plainFill.colour),
        where + ': the fill resolves to ' + rgbText(fill.colour) + ', the same as a plain step\'s ' +
        rgbText(plainFill.colour) + ' (winning rule `' + fill.hit.sel + '` at ' + specText(fill.hit.spec) +
        '); the mute is declared and discarded');
      var style = resolve(el, chain, 'border-top-style');
      assert.ok(style, where + ': no rule sets the step edge');
      assert.notStrictEqual(style.value, plainEdgeStyle.value,
        where + ': the edge style resolves to `' + style.value + '`, a plain step\'s `' + plainEdgeStyle.value +
        '` (`' + style.sel + '` at ' + specText(style.spec) + ')');
      var colour = resolve(el, chain, 'border-top-color');
      assert.ok(colour, where + ': no rule sets the step edge colour');
      var edge = colourValue(colour.value, null);
      assert.notStrictEqual(rgbText(edge), rgbText(colourValue(plainEdgeColour.value, null)),
        where + ': the edge colour resolves to ' + rgbText(edge) + ', a plain step\'s ' +
        rgbText(colourValue(plainEdgeColour.value, null)) + ' (`' + colour.sel + '`)');
      /* the fill step alone is 1.02:1 against this page, so the dashed edge is the mark that carries the
         mute; a mark that cannot be seen is no mute (WCAG 1.4.11) */
      [['the surface', surface], ['the plain step', plainFill.colour]].forEach(function (pair) {
        var r = ratio(edge, pair[1]);
        assert.ok(r >= 3, where + ': the mute edge is ' + rgbText(edge) + ' on ' + pair[0] + ' ' +
          rgbText(pair[1]) + ' = ' + r.toFixed(2) + ':1, under the 3:1 a non-text mark needs to be seen');
      });
      cases++;
    });
  });
  assert.strictEqual(cases, 4, 'the denominator is 2 mute states x 2 page kinds');
  assert.strictEqual(baselines, 2, 'one plain-step baseline per page kind');
});

test('every text colour on a muted or dim step keeps 4.5:1 on the fill it resolves to', function () {
  var measured = 0;
  CONTEXTS.forEach(function (context) {
    STATES.forEach(function (state) {
      var chain = context.chain(state.ribbon), step = stepEl(state.cls);
      var stepFill = nodeFill(context, state).colour;
      TEXTS.forEach(function (text) {
        var el = { tag: text.tag, classes: [text.cls] };
        var colour = resolve(el, chain.concat([step, el]), 'color');
        assert.ok(colour, 'no rule sets ' + text.name + ' on ' + state.name + ' on ' + context.name);
        var fill = fillOf(el, chain.concat([step, el]), stepFill);
        var r = ratio(rgb(colour.value), fill);
        assert.ok(r >= 4.5, state.name + ' on ' + context.name + ': ' + text.name + ' is ' + r.toFixed(2) +
          ':1 (' + rgbText(rgb(colour.value)) + ' on ' + rgbText(fill) + ', from `' + colour.sel + '` at ' +
          specText(colour.spec) + '), under the 4.5:1 normal-text floor');
        measured++;
      });
    });
  });
  assert.strictEqual(measured, 12, 'three text colours in each of the 4 cascade cases');
});

test('the linked and pressed step stays distinct from the muted one, in every page kind', function () {
  var cases = 0;
  CONTEXTS.forEach(function (context) {
    var linked = stepEl('is-linked');
    var linkedChain = context.chain(['has-link']);
    var linkedEdge = resolve(linked, linkedChain, 'border-top-color');
    var linkedFill = nodeFill(context, { cls: 'is-linked', ribbon: ['has-link'], name: 'the linked step' });
    assert.ok(linkedEdge, 'no rule sets the linked step\'s edge on ' + context.name);
    STATES.forEach(function (state) {
      var mutedEdge = resolve(stepEl(state.cls), context.chain(state.ribbon), 'border-top-color');
      var mutedFill = nodeFill(context, state);
      assert.notStrictEqual(rgbText(colourValue(linkedEdge.value, null)),
        rgbText(colourValue(mutedEdge.value, null)),
        'on ' + context.name + ': the linked step\'s edge (' + linkedEdge.value + ') reads as the ' +
        state.name + ' one (' + mutedEdge.value + ')');
      assert.notStrictEqual(rgbText(linkedFill.colour), rgbText(mutedFill.colour),
        'on ' + context.name + ': the linked step\'s fill reads as the ' + state.name + ' one (' +
        rgbText(mutedFill.colour) + ')');
    });
    cases++;
  });
  assert.strictEqual(cases, 2, 'one linked comparison per page kind');
});

/* The cascade reader treats every media query but `print` as always applying, so the reduced-motion
   reset (`transition: none !important`, css:934) masks the step's own transition and would make a
   cascade read vacuous. This check therefore reads the declarations of the rules that match the step
   and skips only that reset, by name. */
test('the step transition no longer lists opacity', function () {
  var offenders = [], checked = 0;
  CONTEXTS.forEach(function (context) {
    STATES.forEach(function (state) {
      var chain = context.chain(state.ribbon), el = stepEl(state.cls);
      checked++;
      RULES.forEach(function (rule) {
        if (isPrint(rule.media)) return;
        if (rule.media.some(function (q) { return /prefers-reduced-motion/.test(q); })) return;
        var matched = splitTop(rule.sel, ',').some(function (s) { return selectorMatches(s, el, chain, null); });
        if (!matched) return;
        var d = reader.valueFor(rule.decls, 'transition');
        if (d && /opacity/.test(d.value)) {
          offenders.push(state.name + ' on ' + context.name + ': `' + rule.sel + ' { transition: ' + d.value + ' }`');
        }
      });
    });
  });
  assert.strictEqual(checked, 4, 'the denominator is 2 mute states x 2 page kinds');
  assert.deepEqual(offenders, [], 'the step still animates opacity: ' + offenders.join('; '));
});
