'use strict';

/* T-0500.1.7.8 finding 3 (v6 review, quarantined): a stage the attack-chain filter leaves unmatched keeps
   `.hl-rv-stage-muted`, which was `opacity: 0.6`. The opacity composites the whole card, text included: the
   muted h4 (#a8a8a8) became #707070 on #151515 = 3.69:1, and the procedure `small` inside it 3.44:1
   (P1.triage.md, finding 3). Both are retained, readable content, not disabled controls, so the 4.5:1
   normal-text floor applies.

   This reads the declarations out of the stylesheet the same way the triage computed them (WCAG 2.x relative
   luminance, the group composited over the view card), so the rule cannot regress to muting text; the control
   test reproduces the triage's own figures for the old rule. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var path = require('node:path');

var CSS = fs.readFileSync(path.join(__dirname, '../../../assets/css/hl-report-tabs.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');

function rules(css) {
  var out = [], m, re = /([^{}]+)\{([^{}]*)\}/g;
  while ((m = re.exec(css))) {
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
var RULES = rules(CSS);
function decl(selector, prop) {
  var found = RULES.filter(function (r) { return r.sel.split(',').map(function (s) { return s.trim(); }).indexOf(selector) >= 0; });
  assert.ok(found.length >= 1, 'no rule for ' + selector);
  var rule = found[found.length - 1];   /* the last matching rule is the one that wins at equal specificity */
  return rule.decls[prop];
}
function token(name) {
  var m = new RegExp('--' + name + ':\\s*([^;]+);').exec(CSS);
  assert.ok(m, 'token --' + name + ' is declared');
  return resolve(m[1].trim());
}
function resolve(value) {
  value = String(value || '').replace(/\s*!important\s*$/i, '').trim();
  var m = /^var\(\s*--([\w-]+)\s*(?:,\s*([^)]+))?\)$/.exec(value);
  if (!m) return value;
  try { return token(m[1]); } catch (e) { return resolve((m[2] || '').trim()); }
}
function rgb(color) {
  var v = resolve(color).trim();
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

/* the stage a filter left unmatched: `.hl-rv-stage-muted` on top of `.hl-rv-stage`, inside the view card */
var CARD = rgb(token('rv-card'));
function mutedStage() {
  var o = decl('.hl-rv-stage-muted', 'opacity');
  return {
    opacity: o === undefined ? 1 : parseFloat(o),
    fill: rgb(decl('.hl-rv-stage-muted', 'background') || decl('.hl-rv-stage', 'background'))
  };
}
/* the card at `opacity` over its parent, and a piece of text inside the card at the same group opacity */
function onCard(textColor, cardFill, opacity, parent) {
  return { text: round(over(textColor, parent, opacity)), fill: round(over(cardFill, parent, opacity)) };
}
function stageText() { return onCard(rgb(decl('.hl-report-page .hl-post-content .hl-rv-stage h4', 'color')), mutedStage().fill, mutedStage().opacity, CARD); }
function procedureText() {
  var m = mutedStage();
  return onCard(rgb(decl('.hl-report-page .hl-rv-procedure small', 'color')), rgb(decl('.hl-report-page .hl-rv-procedure', 'background')), m.opacity, CARD);
}

test('control: the computation reproduces the triage figures for the old rule (h4 3.69:1, procedure small 3.44:1)', function () {
  var h4 = onCard(rgb('#a8a8a8'), rgb('#111111'), 0.6, rgb('#1c1c1c'));
  assert.strictEqual(ratio(h4.text, h4.fill).toFixed(2), '3.69');
  var small = onCard(rgb('#a8a8a8'), rgb('#1c1c1c'), 0.6, rgb('#1c1c1c'));
  assert.strictEqual(ratio(small.text, small.fill).toFixed(2), '3.44');
});

test('finding 3: the muted stage h4 keeps at least 4.5:1 against the fill it is painted on', function () {
  var t = stageText();
  var r = ratio(t.text, t.fill);
  assert.ok(r >= 4.5, 'muted h4 is ' + r.toFixed(2) + ':1 (rgb ' + [t.text.r, t.text.g, t.text.b].join(',') + ' on rgb ' + [t.fill.r, t.fill.g, t.fill.b].join(',') + '), under the 4.5:1 floor');
});

test('finding 3: the muted procedure small text keeps at least 4.5:1 against the procedure card', function () {
  var t = procedureText();
  var r = ratio(t.text, t.fill);
  assert.ok(r >= 4.5, 'muted procedure small is ' + r.toFixed(2) + ':1 (rgb ' + [t.text.r, t.text.g, t.text.b].join(',') + ' on rgb ' + [t.fill.r, t.fill.g, t.fill.b].join(',') + '), under the 4.5:1 floor');
});
