'use strict';
/* T-0500.1.7.4 review round 2, lane A (templates and CSS): the static half of T7, C1, C2 and C3. The reviewer's reproductions for T1-T5 are in defang-render.test.js (Jekyll executed);
   the browser half of C1 and C2 (scroll down and back up at 320 and 390; the card's rectangle at 1280, 1440 and 1920) is in tasks/runs/T-0500.1.7.4/build/fix-r2a-report.md. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.join(__dirname, '..', '..', '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const css = read('assets/css/custom.scss');
const rcss = read('assets/css/hl-report-tabs.css');

test('T7: a detection page with last_updated keeps its visible revision date and the link to #revisions in the detection header', () => {
  const post = read('_layouts/post.html');
  const det = post.slice(post.indexOf('hl-post-header hl-post-header--detect hl-d-plate'), post.indexOf('hl-d-res'));
  assert.match(det, /\{% if page\.last_updated %\} · <a class="hl-last-updated" href="#revisions" title="Revision history">Updated \{\{ page\.last_updated \| date: "%b %d, %Y" \}\}<\/a>\{% endif %\}/);
  assert.match(post, /id="revisions"/, 'the target of the link exists');
});

function lum(hex) { const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((v) => (v <= 0.04045 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4))); return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]; }
function mix(a, b, w) { const p = (h) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16)); const x = p(a), y = p(b); return '#' + x.map((v, i) => Math.round(v * (1 - w) + y[i] * w).toString(16).padStart(2, '0')).join(''); }
function ratio(fg, bg) { const a = lum(fg), b = lum(bg); return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05); }

test('C3: the critical card\'s meta text is at least 4.5:1 on the card\'s own 9% red wash (the old colour computed 4.24:1: the control)', () => {
  const wash = mix('#1a1a1a', '#ef4444', 0.09);
  assert.ok(ratio('#ef4444', wash) < 4.5, 'control: the old colour fails');
  const m = css.match(/\.hl-idx \.hl-card\[data-sev="critical"\] \{ --sv: #ef4444; --svt: (#[0-9a-f]{6}); \}/);
  assert.ok(m, 'the critical card sets a text colour');
  assert.ok(ratio(m[1], wash) >= 4.5, 'the new colour: ' + ratio(m[1], wash).toFixed(2));
  assert.match(css, /\.hl-idx \.hl-card__meta \{[^}]*color: var\(--svt, var\(--sv\)\);/);
  assert.match(css, /\.hl-idx \.hl-impact-card \.hl-impact-card__meta \{ color: var\(--svt, var\(--sv\)\); \}/);
  // every other severity / kind colour used as card meta text clears 4.5 on its own wash
  for (const c of ['#fb923c', '#fbbf24', '#60a5fa', '#4ade80', '#facc15', '#8b949e', '#2dd4bf', '#9ca3af']) assert.ok(ratio(c, mix('#1a1a1a', c, 0.09)) >= 4.5, c);
});

test('C1: the sticky section bar sits under the header that is showing (--hl-nav-vis) and the anchor padding adds it; the phone auto-hide script maintains it', () => {
  assert.match(css, /--hl-nav-vis:\s*var\(--hl-nav-h\);/);
  assert.match(css, /@media \(max-width: 768px\) \{\s*:root \{ --hl-nav-vis: var\(--hl-nav-mh\); \}\s*\.hl-nav \{ height: var\(--hl-nav-mh\);/);
  assert.match(css, /--hl-nav-mh:\s*58px;/);
  assert.match(css, /\.hl-sbar \{\s*position: sticky;\s*top: var\(--hl-nav-vis\);\s*z-index: 900;/);
  assert.doesNotMatch(css, /@media \(max-width: 700px\) \{ \.hl-sbar \{ top: 0; \} \}/, 'the top:0 override that put the bar under the returning header is gone');
  assert.match(css, /html:has\(\.hl-sbar\) \{ scroll-padding-top: calc\(var\(--hl-nav-vis\) \+ var\(--sbh, 86px\) \+ 8px\); \}/);
  assert.match(css, /@media \(max-width: 768px\) \{ \.hl-sbar \{ transition: top 0\.28s ease; \} \}/);
  const def = read('_layouts/default.html');
  assert.match(def, /function hide\(\) \{ nav\.classList\.add\('hl-nav--hidden'\); setToc\(true\); setVis\(true\); \}/);
  assert.match(def, /function show\(\) \{ nav\.classList\.remove\('hl-nav--hidden'\); setToc\(false\); setVis\(false\); \}/);
  assert.match(def, /root\.style\.setProperty\('--hl-nav-vis', hidden \? '0px' : nav\.offsetHeight \+ 'px'\)/);
  assert.match(def, /root\.style\.removeProperty\('--hl-nav-vis'\)/);
});

test('C2: the sponsor card\'s place is defined once (custom.scss); the non-report rail and the report card both read it', () => {
  assert.equal((css.match(/--hl-card-left:\s/g) || []).length, 1);
  assert.match(css, /\.hl-sponsor-rail \{\s*position: fixed;[^}]*left: var\(--hl-card-left\);[^}]*width: var\(--hl-card-w\);/);
  assert.match(rcss, /--rv-card-left: var\(--hl-card-left\);/);
  assert.doesNotMatch(css, /card geometry is made in both places|both token copies/, 'no instruction to keep two copies of the card geometry');
});
