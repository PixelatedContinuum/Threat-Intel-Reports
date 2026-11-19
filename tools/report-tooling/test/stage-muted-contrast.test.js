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

var CSS = fs.readFileSync(path.join(__dirname, '../../../assets/css/hl-report-tabs.css'), 'utf8')
  .replace(/\/\*[\s\S]*?\*\//g, '');

/* ---------- the stylesheet, in order, with its at-rule context ---------- */

function declarationsIn(body) {
  var out = [];
  body.split(';').forEach(function (line) {
    var i = line.indexOf(':');
    if (i < 0) return;
    var prop = line.slice(0, i).trim().toLowerCase();
    var value = line.slice(i + 1).trim();
    if (!prop) return;
    var important = /!\s*important\s*$/i.test(value);
    out.push({ prop: prop, value: value.replace(/\s*!\s*important\s*$/i, '').trim(), important: important });
  });
  return out;
}

var RULES = (function parse() {
  var out = [], seq = 0;
  function walk(css, media) {
    var i = 0, n = css.length;
    while (i < n) {
      var open = css.indexOf('{', i);
      if (open < 0) break;
      var depth = 1, j = open + 1;
      while (j < n && depth) { var c = css[j]; if (c === '{') depth++; else if (c === '}') depth--; j++; }
      var prelude = css.slice(i, open).trim();
      var body = css.slice(open + 1, j - 1);
      if (prelude.charAt(0) === '@') {
        var m = /^@([\w-]+)\s*([\s\S]*)$/.exec(prelude);
        var kind = m ? m[1].toLowerCase() : '';
        if (kind === 'media') walk(body, media.concat((m[2] || '').trim()));
        /* @page, @supports, @keyframes: no stage rule lives there */
      } else if (prelude) {
        out.push({ sel: prelude, decls: declarationsIn(body), media: media.slice(), index: seq++ });
      }
      i = j;
    }
  }
  walk(CSS, []);
  return out;
}());

function isPrint(media) { return media.some(function (q) { return /(^|[\s,(])print\b/.test(q); }); }

/* ---------- selectors: split, parse, specificity, match ---------- */

function splitTop(text, sep) {
  var out = [], depth = 0, start = 0;
  for (var i = 0; i < text.length; i++) {
    var c = text[i];
    if (c === '(' || c === '[') depth++;
    else if (c === ')' || c === ']') depth--;
    else if (c === sep && depth === 0) { out.push(text.slice(start, i)); start = i + 1; }
  }
  out.push(text.slice(start));
  return out.map(function (s) { return s.trim(); }).filter(Boolean);
}

function compoundsOf(sel) {
  var out = [], depth = 0, cur = '';
  for (var i = 0; i < sel.length; i++) {
    var c = sel[i];
    if (c === '(' || c === '[') depth++;
    if (c === ')' || c === ']') depth--;
    if (depth === 0 && /\s/.test(c)) { if (cur) { out.push(cur); cur = ''; } continue; }
    if (depth === 0 && (c === '>' || c === '+' || c === '~')) return null;
    cur += c;
  }
  if (cur) out.push(cur);
  return out.length ? out : null;
}

function parseCompound(text) {
  var comp = { raw: text, tag: null, classes: [], ids: [], attrs: [], pseudoClasses: [], pseudoElement: null };
  var i = 0, m;
  while (i < text.length) {
    var ch = text[i];
    if (ch === '.') {
      m = /^\.([\w-]+)/.exec(text.slice(i)); if (!m) return null;
      comp.classes.push(m[1]); i += m[0].length;
    } else if (ch === '#') {
      m = /^#([\w-]+)/.exec(text.slice(i)); if (!m) return null;
      comp.ids.push(m[1]); i += m[0].length;
    } else if (ch === '[') {
      m = /^\[[^\]]*\]/.exec(text.slice(i)); if (!m) return null;
      comp.attrs.push(m[0]); i += m[0].length;
    } else if (ch === ':') {
      if (text[i + 1] === ':') {
        m = /^::([\w-]+)(?:\([^)]*\))?/.exec(text.slice(i)); if (!m) return null;
        comp.pseudoElement = m[1].toLowerCase(); i += m[0].length;
      } else {
        m = /^:([\w-]+)(\([\s\S]*?\))?/.exec(text.slice(i)); if (!m) return null;
        comp.pseudoClasses.push({ name: m[1].toLowerCase(), args: m[2] ? m[2].slice(1, -1) : null });
        i += m[0].length;
      }
    } else if (ch === '*') {
      i++;
    } else {
      m = /^([a-zA-Z][\w-]*)/.exec(text.slice(i)); if (!m) return null;
      comp.tag = m[1].toLowerCase(); i += m[0].length;
    }
  }
  return comp;
}

function cmp(a, b) {
  for (var i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

function specOf(sel) {
  var comps = compoundsOf(sel);
  assert.ok(comps, 'unsupported selector in the stylesheet reader: ' + sel);
  return comps.reduce(function (acc, c) {
    var comp = parseCompound(c);
    assert.ok(comp, 'unsupported compound in the stylesheet reader: ' + c);
    acc[0] += comp.ids.length;
    acc[1] += comp.classes.length + comp.attrs.length;
    acc[2] += (comp.tag ? 1 : 0) + (comp.pseudoElement ? 1 : 0);
    comp.pseudoClasses.forEach(function (p) {
      if (p.name === 'is' || p.name === 'not') {
        var best = [0, 0, 0];
        splitTop(p.args || '').forEach(function (s) {
          var sp = specOf(s);
          if (cmp(sp, best) > 0) best = sp;
        });
        acc[0] += best[0]; acc[1] += best[1]; acc[2] += best[2];
      } else if (p.name === 'where') {
        /* zero, by definition */
      } else {
        acc[1] += 1;
      }
    });
    return acc;
  }, [0, 0, 0]);
}

function specText(s) { return s[0] + ',' + s[1] + ',' + s[2]; }

/* an element in the chain: its tag and the classes the script puts on it */
function compoundMatches(comp, el, pseudo) {
  if (comp.pseudoElement !== (pseudo || null)) return false;
  if (comp.tag && comp.tag !== el.tag) return false;
  if (comp.ids.length) return false;          /* no element in these chains carries an id */
  if (comp.attrs.length) return false;        /* and no stage rule selects on an attribute */
  for (var i = 0; i < comp.classes.length; i++) {
    if (el.classes.indexOf(comp.classes[i]) < 0) return false;
  }
  for (var k = 0; k < comp.pseudoClasses.length; k++) {
    var p = comp.pseudoClasses[k];
    if (p.name !== 'is') return false;        /* :has/:not/:hover/... are not evaluated */
    var ok = splitTop(p.args || '').some(function (arg) {
      var c = parseCompound(arg);
      return c ? compoundMatches(c, el, pseudo) : false;
    });
    if (!ok) return false;
  }
  return true;
}

function selectorMatches(sel, el, chain, pseudo) {
  var comps = compoundsOf(sel);
  if (!comps) return false;                   /* '>' etc: not evaluated */
  var parsed = comps.map(parseCompound);
  if (parsed.some(function (c) { return !c; })) return false;
  if (!compoundMatches(parsed[parsed.length - 1], el, pseudo)) return false;
  var ci = chain.length - 1;
  for (var k = parsed.length - 2; k >= 0; k--) {
    var found = false;
    while (ci >= 0) {
      if (compoundMatches(parsed[k], chain[ci], null)) { found = true; ci--; break; }
      ci--;
    }
    if (!found) return false;
  }
  return true;
}

/* ---------- declarations, shorthands, the cascade ---------- */

var BORDER_STYLES = ['none', 'hidden', 'dotted', 'dashed', 'solid', 'double', 'groove', 'ridge', 'inset', 'outset'];

function colourOfBackground(value) {
  var v = value.trim();
  if (/^(none|transparent)\b/i.test(v)) return 'transparent';
  if (/gradient\(/i.test(v)) return 'transparent';           /* a gradient paints no background-color */
  return v;
}
function styleOfBorder(value) {
  var hit = value.split(/\s+/).map(function (t) { return t.toLowerCase(); })
    .filter(function (t) { return BORDER_STYLES.indexOf(t) >= 0; });
  return hit.length ? hit[0] : 'none';                       /* an omitted style is `none` */
}
function colourOfBorder(value) {
  var tokens = value.split(/\s+/);
  for (var i = tokens.length - 1; i >= 0; i--) {
    var t = tokens[i];
    if (!t || BORDER_STYLES.indexOf(t.toLowerCase()) >= 0) continue;
    if (/^-?[\d.]+[a-z%]*$/i.test(t)) continue;              /* a width */
    return t;
  }
  return 'currentcolor';
}

/* the value a declaration list gives `prop`, last declaration wins inside the rule */
function valueFor(decls, prop) {
  var hit = null;
  for (var i = 0; i < decls.length; i++) {
    var d = decls[i], v = null;
    if (d.prop === prop) v = d.value;
    else if (prop === 'background-color' && d.prop === 'background') v = colourOfBackground(d.value);
    else if (prop === 'border-top-style' && d.prop === 'border') v = styleOfBorder(d.value);
    else if (prop === 'border-top-style' && d.prop === 'border-style') v = d.value.split(/\s+/)[0];
    else if (prop === 'border-top-style' && d.prop === 'border-top') v = styleOfBorder(d.value);
    else if (prop === 'border-top-color' && d.prop === 'border') v = colourOfBorder(d.value);
    else if (prop === 'border-top-color' && d.prop === 'border-color') v = d.value.split(/\s+/)[0];
    else if (prop === 'border-top-color' && d.prop === 'border-top') v = colourOfBorder(d.value);
    if (v !== null) hit = { value: v, important: d.important, from: d.prop };
  }
  return hit;
}

/* the winning declaration for `el` in `chain`, by specificity, later on a tie, !important first */
function resolve(el, chain, prop, pseudo) {
  var best = null;
  RULES.forEach(function (rule) {
    if (isPrint(rule.media)) return;
    var d = valueFor(rule.decls, prop);
    if (!d) return;
    var sel = null, spec = null;
    splitTop(rule.sel, ',').forEach(function (s) {
      if (!selectorMatches(s, el, chain, pseudo)) return;
      var sp = specOf(s);
      if (!spec || cmp(sp, spec) > 0) { spec = sp; sel = s; }
    });
    if (!sel) return;
    var cand = { value: d.value, important: d.important, from: d.from, sel: sel, spec: spec, index: rule.index };
    if (!best) { best = cand; return; }
    if (cand.important !== best.important) { if (cand.important) best = cand; return; }
    var c = cmp(cand.spec, best.spec);
    if (c > 0 || (c === 0 && cand.index > best.index)) best = cand;
  });
  return best;
}

function resolved(el, chain, prop, pseudo) {
  var hit = resolve(el, chain, prop, pseudo);
  assert.ok(hit, 'no rule sets ' + prop + ' on ' + el.tag + '.' + el.classes.join('.'));
  return hit;
}

/* ---------- tokens ---------- */

var TOKENS = {};
RULES.forEach(function (rule) {
  if (isPrint(rule.media)) return;
  rule.decls.forEach(function (d) { if (d.prop.indexOf('--') === 0) TOKENS[d.prop] = d.value; });
});

var VAR = /^var\(\s*--([\w-]+)\s*(?:,\s*([\s\S]+))?\)$/;
function resolveValue(value, seen) {
  var v = String(value).trim();
  var m = VAR.exec(v);
  if (!m) return v;
  seen = seen || {};
  if (seen[m[1]]) return m[2] ? resolveValue(m[2], seen) : v;
  seen[m[1]] = true;
  if (!(('--' + m[1]) in TOKENS)) {
    assert.ok(m[2], 'token --' + m[1] + ' is declared nowhere and has no fallback');
    return resolveValue(m[2], seen);
  }
  return resolveValue(TOKENS['--' + m[1]], seen);
}

/* ---------- colour and contrast (WCAG 2.x) ---------- */

function rgb(colour) {
  var v = resolveValue(colour).trim();
  var h = /^#([0-9a-f]{6})$/i.exec(v);
  if (h) return { r: parseInt(h[1].slice(0, 2), 16), g: parseInt(h[1].slice(2, 4), 16), b: parseInt(h[1].slice(4, 6), 16) };
  var s = /^#([0-9a-f]{3})$/i.exec(v);
  if (s) return { r: parseInt(s[1][0] + s[1][0], 16), g: parseInt(s[1][1] + s[1][1], 16), b: parseInt(s[1][2] + s[1][2], 16) };
  throw new Error('cannot read the colour ' + v);
}
function over(fg, bg, a) { return { r: fg.r * a + bg.r * (1 - a), g: fg.g * a + bg.g * (1 - a), b: fg.b * a + bg.b * (1 - a) }; }
function lum(c) {
  function ch(v) { v = v / 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }
  return 0.2126 * ch(c.r) + 0.7152 * ch(c.g) + 0.0722 * ch(c.b);
}
function ratio(a, b) { var l1 = lum(a), l2 = lum(b); return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05); }
function round(c) { return { r: Math.round(c.r), g: Math.round(c.g), b: Math.round(c.b) }; }
function rgbText(c) { return 'rgb(' + [Math.round(c.r), Math.round(c.g), Math.round(c.b)].join(',') + ')'; }

/* `color-mix(in srgb, <colour> <p>%, <colour|transparent>)`, the one mix a stage reads: its muted fill and the
   procedure card inside it. A transparent part means what is underneath (the page); the mix is plain sRGB
   compositing, which is what `in srgb` asks for. */
function colourValue(value, under) {
  var raw = String(value).trim();
  var m = /^color-mix\(\s*in srgb,\s*([\s\S]+?)\s+([\d.]+)%,\s*([\s\S]+?)\)$/i.exec(raw);
  if (m) {
    var base = colourValue(m[1], under);
    return over(base, colourValue(m[3], under), parseFloat(m[2]) / 100);
  }
  var v = resolveValue(raw).trim();
  if (v === 'transparent') {
    assert.ok(under, 'a transparent fill with nothing underneath it');
    return under;
  }
  return rgb(v);
}

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
