'use strict';
/* T-0500.1.7 v6.1: site sponsor and report sponsor are two different placements; the top of the page is a stack of separate panels
   on an elevation ladder with 24px between them. Static checks on the stylesheet and the include (the Liquid output itself is
   rendered by Jekyll in the gates); each assertion is driven by a control in the task's gates directory. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.join(__dirname, '..', '..', '..');
const css = fs.readFileSync(path.join(root, 'assets/css/hl-report-tabs.css'), 'utf8');
const inc = fs.readFileSync(path.join(root, '_includes/report-sponsor-bar.html'), 'utf8');
const body = inc.replace(/\{%-? comment -%\}[\s\S]*?\{%-? endcomment -%\}/g, '');
const js = fs.readFileSync(path.join(root, 'assets/js/hl-report-tabs.js'), 'utf8');

test('the include has two parts: the gold band and the attached panel both name the report sponsor; the Monthly sponsors are the site rail, not the include', () => {
  assert.ok(body.includes('include.part == "band"') && body.includes('include.part == "report"'));
  const band = body.slice(body.indexOf('include.part == "band"'), body.indexOf('include.part == "report"'));
  const rep = body.slice(body.indexOf('include.part == "report"'));
  assert.ok(band.includes('This report is sponsored by') && band.includes('data-rv-sponsor="band"'));
  assert.equal(/supported by|Featured sponsor/i.test(band), false, 'the band no longer carries the site wording');
  assert.ok(band.includes('rv_report_sponsors'), 'the band renders the report sponsor(s)');
  assert.equal(/monthly|rv_site_sponsors/.test(body), false, 'the include no longer renders or reads the Monthly sponsors: they are the site rail');
  assert.ok(rep.includes('This report is sponsored by') && rep.includes('data-rv-sponsor="report"'));
  assert.equal(/supported by/i.test(rep), false, 'the report sponsor never uses the site wording');
});
test('JS: the tab-foot card carries the report sponsor alone, else the site rail sponsors; there is no reading-line mark', () => {
  assert.match(js, /var sponsorPool = reportSponsors\.length \? reportSponsors : siteSponsors;/);
  assert.match(js, /querySelectorAll\('\.hl-sponsor-rail \.hl-sponsor-rail__item'\)/, 'site sponsors are read from the site rail');
  assert.match(js, /querySelectorAll\('\.hl-rvsp--report \.hl-rvsp__item'\)/, 'report sponsors from the attached panel only, so the band is never counted twice');
  assert.equal(/sponsorMark|updateSponsorMark|hl-rv-sponsor-mark/.test(js), false, 'the mark is removed');
  assert.equal(/'Supported by'/.test(js), false);
  assert.equal(/sponsor-mark/.test(css), false, 'and so is its CSS');
});
test('CSS: the report band is the gold featured panel in the report column, outside the panels; the report sponsor is the attached foot of the header panel', () => {
  assert.match(css, /\.hl-rv-reportband \{[^}]*margin: 0 0 24px; padding: 0;/, 'inside the column, no full-bleed breakout');
  assert.equal(/\.hl-rv-reportband\b[^{}]*\{[^}]*100vw/.test(css), false, 'no viewport-width breakout left on the band');
  assert.equal(/\.hl-report-page > \.hl-rv-reportband:first-child/.test(css), false, 'no negative top margin: the band keeps the 24px page padding under the nav');
  assert.match(css, /\.hl-rv-reportband__in, \.hl-rv-sponsor-card\.is-site \{[^}]*linear-gradient\(135deg, #1c1c1c, #0d1117\)[^}]*border-left: 4px solid var\(--rv-gold-bar\); border-radius: 6px;/);
  assert.match(css, /\.hl-report-page \.hl-post-header:has\(\+ \.hl-rvsp--report\) \{ margin-bottom: 0; border-bottom: 0;/);
  assert.match(css, /\.hl-report-page \.hl-rvsp--report \{[^}]*border-radius: 0 0 6px 6px;/);
  assert.match(css, /\.hl-rvsp--report \.hl-rvsp__logo \{ height: 44px;/, 'the report sponsor logo is larger than the report band logo');
  assert.match(css, /\.hl-rv-reportband \.hl-rvsp__logo \{ height: 38px; max-width: 220px; \}/, 'the featured band logo is 38px, smaller than the attached report sponsor 44px');
});
test('CSS: the page top is a ladder of separate containers 24px apart: header, tab row, toolbar, tab title, view, sections', () => {
  assert.match(css, /--rv-well: #0b0b0b;[\s\S]*--rv-card: #1c1c1c;[\s\S]*--rv-row: #262626;[\s\S]*--rv-line: #3a3a3a;/);
  assert.match(css, /padding: 22px 24px 24px 20px; margin: 0 0 24px;/, 'header panel');
  assert.match(css, /\.hl-rv-tabs \{[^}]*margin: 0 0 24px; background: var\(--rv-line\); border: 1px solid var\(--rv-line\)/, 'tab row: a segmented control with 1px dividers');
  assert.match(css, /\.hl-report-page \.hl-rv-tabs button \{[^}]*background: var\(--rv-well\)/, 'idle cells sit on the recessed well');
  assert.match(css, /\.hl-rv-tabs button\[aria-selected="true"\] \{ color: var\(--acc\); background: var\(--rv-row\); border-bottom-color: var\(--acc\); \}/);
  assert.match(css, /\.hl-rv-mobile-line \{[^}]*background: var\(--rv-row\); border: 1px solid var\(--rv-line\)/, 'toolbar: its own raised bar');
  assert.match(css, /\.hl-rv-source, \.hl-rv-view \{[^}]*margin: 0 0 24px;/);
  assert.match(css, /\.hl-rv-panel \{[^}]*gap: 0 24px;/);
});
test('CSS: the main titles reuse the site gradient highlight (custom.scss h1, h2 and .hl-post-header recipes), tinted by the tab accent', () => {
  assert.match(css, /\.hl-report-page \.hl-post-header \{[^}]*linear-gradient\(135deg, color-mix\(in srgb, var\(--acc\) 11%, #0d1117\) 0%, #0d1117 60%, #111111 100%\);[^}]*border-left: 4px solid var\(--acc\)/);
  assert.match(css, /\.hl-report-page \.hl-rv-panel-head \{[^}]*linear-gradient\(to right, color-mix\(in srgb, var\(--acc\) 14%, transparent\), transparent\);[^}]*border-left: 4px solid var\(--acc\)/);
  assert.match(css, /linear-gradient\(to right, color-mix\(in srgb, var\(--acc\) 13%, transparent\), transparent\), var\(--rv-row\) !important;/);
  assert.match(css, /\.hl-rv-view-summary \{[^}]*linear-gradient\(to right, color-mix\(in srgb, var\(--acc\) 13%, transparent\), transparent\), var\(--rv-row\);/);
  const tool = css.slice(css.indexOf('.hl-rv-mobile-line {'), css.indexOf('\n', css.indexOf('.hl-rv-mobile-line {')));
  assert.equal(/gradient/.test(tool), false, 'the toolbar stays flat');
});
