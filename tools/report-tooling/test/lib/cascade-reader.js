'use strict';

/* The cascade reader shared by the report stylesheet's mute tests (T-0500.1.7.8 finding 3's
   stage-muted-contrast.test.js and T-0680's flow-node-muted-contrast.test.js).

   A fix that declares a fill and an edge on a muted element can lose both to a later, more specific
   rule, and a test that reads the declaration alone passes anyway. So this reader resolves the
   CASCADE: it matches every rule in the stylesheet against an element in a described DOM chain, takes
   the winner by specificity (later wins a tie, !important first), and hands back the value with the
   selector and specificity that gave it.

   THE READER'S LIMITS, all deliberate:
   - It is a substring/compound reader for class, element, pseudo-class and pseudo-element selectors,
     with descendant combinators only. `>`, `+` and `~` make a selector match nothing (no rule these
     tests read uses them); `#id` and `[attr]` never match, so a rule selected through an attribute
     (such as `[aria-pressed="true"]`) is invisible to it: give the element its class form or do not
     rely on the attribute in a rule under test. `:has()`, `:not()`, `:hover`, `:focus` and every
     other pseudo-class are not evaluated, except `:is()` over simple compounds.
   - Media conditions are not evaluated: a rule inside any `@media` other than `print` is treated as
     applying at every width. `print` is excluded, because these rules describe the screen and the
     print block repaints the tokens on white.
   - Custom properties are read as the LAST declaration of that property outside `@media print`, which
     is how the report scope's own block (`html:has(.hl-report-page)`, the T-0556 one) overrides the
     base token block; the cascade is not run for the tokens themselves.
   - Shorthands are expanded only where these files need them: `background` -> `background-color`,
     `border`/`border-style`/`border-top` -> `border-top-style`. A multi-value `border-style` is read
     per side (first value = top), and `!important` beats specificity.
   - No layout, no computed styles, no browser: a colour this reader cannot parse is an error, not a
     silent pass. */

var assert = require('node:assert');
var fs = require('node:fs');
var path = require('node:path');

var CSS = fs.readFileSync(path.join(__dirname, '../../../../assets/css/hl-report-tabs.css'), 'utf8')
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

module.exports = {
  CSS: CSS,
  RULES: RULES,
  TOKENS: TOKENS,
  isPrint: isPrint,
  splitTop: splitTop,
  compoundsOf: compoundsOf,
  parseCompound: parseCompound,
  specOf: specOf,
  specText: specText,
  compoundMatches: compoundMatches,
  selectorMatches: selectorMatches,
  valueFor: valueFor,
  resolve: resolve,
  resolved: resolved,
  resolveValue: resolveValue,
  colourValue: colourValue,
  rgb: rgb,
  rgbText: rgbText,
  over: over,
  lum: lum,
  ratio: ratio,
  round: round
};
