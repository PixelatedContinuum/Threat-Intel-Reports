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

test('the report include (design D) names the report sponsor as the plate foot; the gold band part is gone; the Monthly sponsors are the featured include and the site rail', () => {
  assert.ok(body.includes('include.part == "report"'));
  assert.equal(body.includes('include.part == "band"'), false, 'no gold report band');
  const rep = body.slice(body.indexOf('include.part == "report"'));
  assert.ok(rep.includes('This report is sponsored by') && rep.includes('data-rv-sponsor="report"'));
  assert.equal(/supported by|Featured sponsor/i.test(body), false, 'the report include never uses the site wording');
  assert.equal(/monthly|rv_site_sponsors/.test(body), false, 'the include does not render or read the Monthly sponsors');
});
test('JS: the tab-foot card carries the report sponsor alone, else the site rail sponsors; there is no reading-line mark', () => {
  assert.match(js, /var sponsorPool = reportSponsors\.length \? reportSponsors : siteSponsors;/);
  assert.match(js, /querySelectorAll\('\.hl-sponsor-rail \.hl-sponsor-rail__item'\)/, 'site sponsors are read from the site rail');
  assert.match(js, /querySelectorAll\('\.hl-rvsp--report \.hl-rvsp__item'\)/, 'report sponsors from the attached panel only, so the band is never counted twice');
  assert.equal(/sponsorMark|updateSponsorMark|hl-rv-sponsor-mark/.test(js), false, 'the mark is removed');
  assert.equal(/'Supported by'/.test(js), false);
  assert.equal(/sponsor-mark/.test(css), false, 'and so is its CSS');
});
test('CSS: the featured sponsor is the gold panel (band above the plate, margin card from 1440px, above every sticky bar); the report sponsor is the quiet foot inside the plate', () => {
  assert.match(css, /\.hl-rv-feat \{ display: flex; align-items: center; gap: 8px 22px; margin: 0 0 24px; padding: 10px 14px 10px 20px; min-height: 68px; border-radius: 3px; \}/);
  assert.match(css, /@media \(min-width: 1440px\) \{[^@]*\.hl-rv-feat \{ display: none; \}\s*\.hl-rv-featcard \{\s*display: flex; flex-direction: column; gap: 10px; position: fixed; z-index: 75;/);
  assert.match(css, /\.hl-report-page \.hl-post-header > \.hl-rvsp--report \{ grid-column: 1 \/ -1; \}/, 'the report sponsor is a grid row inside the plate');
  assert.equal(/\.hl-report-page \.hl-post-header:has\(\+ \.hl-rvsp--report\)/.test(css), false, 'no attached-panel rule: the sponsor is inside the header box');
  assert.ok(Number((css.match(/\.hl-rv-bar \{\s*position: sticky; z-index: (\d+)/) || [])[1]) < 75, 'the sticky bar sits below the card (z-index 60 against 75)');
});
test('CSS: the page top is a ladder of separate containers 24px apart: plate, tab row, toolbar, tab title, view, sections (design D)', () => {
  assert.match(css, /--rv-bg: var\(--hl-bg-page, #111111\);[\s\S]*--rv-card: #1c1c1c;[\s\S]*--rv-row: #262626;[\s\S]*--rv-line: #3a3a3a;/, 'the elevation ladder, bottom to top');
  assert.match(css, /margin: 0 0 24px; position: relative;\n\}/, 'plate');
  assert.match(css, /\.hl-rv-tabs \{\s*display: flex; gap: 6px; margin: 0 0 24px; padding: 0; background: none; border: 0;/, 'tab row: seven chips 6px apart');
  assert.match(css, /\.hl-report-page \.hl-rv-tabs button \{[^}]*background: #14171c/, 'idle chips');
  assert.match(css, /\.hl-report-page \.hl-rv-tabs button\[aria-selected="true"\] \.hl-rv-tab-icon \{ background: var\(--a\); color: #111111;/, 'the selected chip has a filled accent icon box');
  assert.match(css, /\.hl-rv-mobile-line \{[^}]*background: var\(--rv-row\); border: 1px solid var\(--rv-line\)/, 'toolbar: its own raised bar');
  assert.match(css, /\.hl-rv-source \{[^}]*margin: 0 0 24px;/);
  assert.match(css, /\.hl-rv-view \{[^}]*margin: 0 0 24px;/);
  assert.match(css, /\.hl-rv-panel \{[^}]*gap: 0 24px;/);
});
test('CSS: the plate is a flat panel with an accent edge, the tab title is solid ink beside an outlined numeral, the view is a flat boxed panel, prose sits on the page (design D, flat since T-0556 w1)', () => {
  assert.match(css, /\.hl-report-page \.hl-post-header \{[^}]*background: var\(--hl-bg-card\);[^}]*border-left: 4px solid var\(--acc\)/);
  assert.equal(/\.hl-report-page \.hl-post-header \{[^}]*gradient/.test(css), false, 'the plate paints no gradient');
  assert.match(css, /\.hl-rv-panel-num \{[^}]*-webkit-text-stroke: 1\.5px var\(--acc\);/);
  assert.match(css, /\.hl-report-page \.hl-post-content \.hl-rv-panel-head h2 \{[^}]*color: var\(--rv-text\) !important;/);
  assert.equal(/\.hl-rv-panel-head h2 \{[^}]*(?:gradient|background-clip)/.test(css), false, 'the tab title is solid ink, not gradient text');
  assert.match(css, /\.hl-rv-source \{ background: none; border: 0; border-top: 1px solid var\(--rv-line\);/, 'report prose: no box');
  assert.match(css, /\.hl-rv-view \{\s*position: relative; background: var\(--rv-card\);/);
  const tool = css.slice(css.indexOf('.hl-rv-mobile-line {'), css.indexOf('\n', css.indexOf('.hl-rv-mobile-line {')));
  assert.equal(/gradient/.test(tool), false, 'the toolbar stays flat');
});
