'use strict';
/* T-0538: the site's type scale. Joseph (2026-11-02): labels and titles read smaller than the text they head. The scale is a set of --hl-fs-*
   tokens on :root in assets/css/custom.scss (hl-report-tabs.css reads the same tokens for its eyebrows and section titles). These tests pin the
   rules, not every selector: the tokens and their order, no reader-facing literal below 14px outside a named allowlist, the Wire source name not
   smaller than the headline title, and the report section eyebrow at body size. A new rule that sets a small literal size fails here with its selector. */
const { test } = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const scss = fs.readFileSync(path.join(__dirname, '../../../assets/css/custom.scss'), 'utf8');
const rcss = fs.readFileSync(path.join(__dirname, '../../../assets/css/hl-report-tabs.css'), 'utf8');
const strip = t => t.replace(/\/\*[\s\S]*?\*\//g, m => m.replace(/[^\n]/g, ' '));
const tok = n => { const m = scss.match(new RegExp('--hl-fs-' + n + ':\\s*(\\d+(?:\\.\\d+)?)px')); assert.ok(m, 'token --hl-fs-' + n + ' is defined on :root'); return +m[1]; };

test('the scale: meta and tag at least 15px, label and small 16px, body 18px, card 20px, section 26px, in rising order', () => {
  const t = { meta: tok('meta'), tag: tok('tag'), small: tok('small'), label: tok('label'), body: tok('body'), card: tok('card'), section: tok('section') };
  assert.ok(t.meta >= 15 && t.tag >= 15, 'no reader-facing text under 15px; tags and chips at least 15px');
  assert.ok(t.label >= t.small, 'a label is at least as large as the secondary text it labels');
  assert.ok(t.card > t.body && t.section > t.card, 'card title above body, section title above card title');
  assert.ok(t.section - t.body >= 6, 'a section title is clearly larger than body');
});

/* The floor is 15px (--hl-fs-meta). Named exceptions, each reasoned in tasks/runs/T-0538/typescale-report.md "Kept below 15px": the logotype and the
   heading permalink glyph (not reading text); the sponsor card labels in the gated 140-200px margin (14px chrome floor); the Wire tab at 360px
   (phone squeeze); the gate-pinned ATT&CK strip cells and the glyphs set in fixed circles. Review of T-0538 (Luna) found the first version checked 14px. */
const KEEP = /hl-brand__top|hl-heading-anchor::after|hl-sponsor-rail__label|hl-rv-featcard__label|hl-idx--wire \.hl-wtabs__tab|hl-attack__|hl-rv-info span|hl-rv-cmark > span|hl-facts-anchor/;
const under = (src, floor) => {
  const css = strip(src), bad = [];
  const rule = /([^{}]+)\{([^{}]*)\}/g; let m;
  while ((m = rule.exec(css))) {
    const sel = m[1].trim().replace(/\s+/g, ' '); if (/^@/.test(sel)) continue;
    for (const d of m[2].split(';')) {
      const px = d.match(/(?:^|\s)font-size\s*:\s*(\d+(?:\.\d+)?)px/) || d.match(/(?:^|\s)font\s*:\s*[^;]*?\s(\d+(?:\.\d+)?)px/);
      if (px && +px[1] < floor && !KEEP.test(sel)) bad.push(sel + ' { ' + d.trim() + ' }');
    }
  }
  return bad;
};

test('no literal font size under 15px in custom.scss or hl-report-tabs.css outside the named exceptions', () => {
  assert.deepEqual(under(scss, 15), [], 'custom.scss literal sizes under 15px: use a --hl-fs-* token');
  assert.deepEqual(under(rcss, 15), [], 'hl-report-tabs.css literal sizes under 15px: use a --hl-fs-* token');
});

test('control: the floor check fires on a planted 13px label', () => {
  assert.equal(under('.x .hl-planted__label { font: 700 13px var(--hl-font-mono); }', 15).length, 1);
});

test('the Wire: the source name is the headline title size, a topic tag is the tag token, the day head is the card token', () => {
  assert.match(scss, /\.hl-idx--wire \.hl-wire__src \{ font: 700 var\(--hl-fs-body\) /);
  assert.match(scss, /\.hl-idx--wire \.hl-wire__title \{ font: 500 var\(--hl-fs-body\)\//);
  assert.match(scss, /\.hl-idx--wire \.hl-wire__label \{[^}]*font: 600 var\(--hl-fs-tag\)\//);
  assert.match(scss, /\.hl-idx--wire \.hl-wire__day \{[^}]*font: 600 var\(--hl-fs-card\)\//);
});

test('home section titles are section-size titles, not 13px eyebrows', () => {
  assert.match(scss, /\.hl-idx \.hl-d-eb__t \{[^}]*font: 700 var\(--hl-fs-section\)\/1\.15 var\(--hl-font-display\) !important;/);
  assert.match(scss, /\.hl-idx \.hl-nav-tile__title \{[^}]*font: 600 var\(--hl-fs-card\)\//);
  assert.match(scss, /\.hl-idx \.hl-d-kpi__cap \{[^}]*font-size: var\(--hl-fs-body\)/);
});

test('report pages: the section eyebrow (and the Campaign record label) is body size, the section heading the section token, the metadata label the label token', () => {
  const css = strip(rcss);
  assert.match(css, /\.hl-rv-source\.hl-rv-nohead::before \{[^}]*font-size: var\(--hl-fs-body, 18px\)/);
  assert.match(css, /\.hl-rv-source > h2 \{[^}]*font-size: var\(--hl-fs-section, 26px\) !important/);
  assert.match(css, /\.hl-rv-metadata strong \{[^}]*font-size: var\(--hl-fs-label, 16px\)/);
});
