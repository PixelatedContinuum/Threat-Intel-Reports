'use strict';
/* T-0500.1.8, reworked 2026-10-30 (Joseph, amendment 1): the gold featured band above the header is the REPORT sponsor, labelled "This report is
   sponsored by", and a report with no sponsor has no band; the Monthly (site) sponsor is the site's Sponsors rail and, with no report sponsor,
   the gold card at each tab foot; the reading-line mark is gone for both. Static checks on the include, stylesheet and script, the script run in
   jsdom, and the browser-gate verdicts driven with the measurements a broken layout would produce (the browser itself is not driven here).
   See homelab-soc/docs/gate-honesty-contract.md. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');
const G = require('../check-browser-report.js');
const root = path.join(__dirname, '..', '..', '..');
const css = fs.readFileSync(path.join(root, 'assets/css/hl-report-tabs.css'), 'utf8');
const js = fs.readFileSync(path.join(root, 'assets/js/hl-report-tabs.js'), 'utf8');
const inc = fs.readFileSync(path.join(root, '_includes/report-sponsor-bar.html'), 'utf8');
const layout = fs.readFileSync(path.join(root, '_layouts/post.html'), 'utf8');
const body = inc.replace(/\{%-? comment -%\}[\s\S]*?\{%-? endcomment -%\}/g, '');
const feat = fs.readFileSync(path.join(root, '_includes/report-featured-sponsor.html'), 'utf8').replace(/\{%-? comment -%\}[\s\S]*?\{%-? endcomment -%\}/g, '');
const rep = body.slice(body.indexOf('include.part == "report"'));
const LABEL = "Featured sponsor of The Hunter's Ledger";
const BANDLABEL = 'This report is sponsored by';
const TOKENS = ['overview', 'victims', 'chain', 'timeline', 'attribution', 'indicators', 'confidence'];

test('the report include (design D): the plate-foot label, the report sponsors only, no Visit, no Featured, no band part', () => {
  assert.ok(body.includes('include.part == "report"') && body.includes('rv_report_sponsors') && body.includes('data-rv-sponsor="report"'));
  assert.equal(body.includes('include.part == "band"'), false, 'the gold report band is gone (T-0500.1.7.3)');
  assert.equal(/Visit/.test(rep), false, 'the report sponsor keeps no Visit element');
  assert.equal(/Featured/.test(rep), false, 'the report sponsor is never "Featured"');
  assert.ok(rep.includes(BANDLABEL));
  assert.equal(/monthly|rv_site_sponsors/.test(body), false, 'no Monthly sponsor is rendered by the report include');
});
test('the featured include (design D): Monthly and active only (every Monthly on an unlisted page), a band and a card, a real Visit span inside the link, aria-hidden, only when the sponsor has a link', () => {
  assert.match(feat, /where: "tier", "monthly" \| where: "active", true/);
  assert.match(feat, /if page\.unlisted -%\}\{%- assign rv_feat = site\.data\.sponsors\.sponsors \| where: "tier", "monthly"/);
  assert.ok(feat.includes('class="hl-rv-feat') && feat.includes('class="hl-rv-featcard"') && feat.includes('data-rv-chrome data-pagefind-ignore'));
  assert.equal((feat.match(/Featured sponsor/g) || []).length >= 4, true, 'label on the band and on the card');
  assert.equal(/<script|onclick=|tracking|utm_/.test(feat), false, 'no script, no tracking');
  for (const cls of ['hl-rv-feat__cta', 'hl-rv-featcard__cta']) {
    assert.match(feat, new RegExp('<span class="' + cls + '" aria-hidden="true">Visit &rarr;</span>'));
    const cta = feat.indexOf(cls);
    assert.match(feat.slice(feat.lastIndexOf('{%', cta), cta), /if sponsor\.url/, 'no Visit with no link to visit: ' + cls);
  }
  assert.match(feat, /^\{%- assign rv_feat/m); assert.match(feat, /\{%- if rv_feat\.size > 0 -%\}/, 'no Monthly sponsor, nothing rendered');
  // b3: a detection page takes its own plate in the first branch; every report keeps the old header in the else branch, byte for byte
  assert.ok(layout.includes('{% if hl_tabbed %}{% include report-featured-sponsor.html %}{% endif %}\n{%- if _is_det0 -%}'), 'the featured include is the first thing in the report column, tabbed pages only');
  assert.ok(layout.includes('{%- else %}\n<div class="hl-post-header{% if page.path contains \'hunting-detections\' %} hl-post-header--detect{% endif %}">'), 'a report keeps its header');
});
test('the Visit call to action is an element, never generated CSS content', () => {
  assert.equal(/content:\s*['"][^'"]*Visit/.test(css), false);
  assert.equal(/::after\s*\{[^}]*Visit/.test(css), false);
  assert.match(css, /\.hl-rv-feat__cta, \.hl-rv-featcard__cta, \.hl-rv-sponsor-card__cta \{[^}]*margin-left: auto;[^}]*border: 1px solid rgba\(184, 144, 47, 0\.75\)/);
});
test('CSS: the featured panel is gold and shared by the band, the margin card and the site tab-foot card; the report sponsor foot and the report card are quiet', () => {
  assert.match(css, /--rv-gold: #d4a73a;/); assert.match(css, /--rv-gold-bar: #b8902f;/);
  assert.match(css, /\.hl-rv-feat, \.hl-rv-featcard, \.hl-rv-sponsor-card\.is-site \{\s*border: 1px solid color-mix\(in srgb, var\(--rv-gold-bar\) 60%, transparent\);\s*background: radial-gradient\([^)]*rgba\(245, 158, 11, 0\.22\)[^;]*linear-gradient\(135deg, #1d1810, #0d1117\);\s*box-shadow: 0 0 0 1px rgba\(245, 158, 11, 0\.08\)/);
  assert.equal(/sponsor-mark/.test(css), false, 'no CSS is left for the reading-line mark');
  assert.equal(/reportband/.test(css), false, 'the gold report band is gone from the stylesheet');
  const rules = [...css.replace(/\/\*[\s\S]*?\*\//g, '').matchAll(/([^{}@]+)\{([^{}]*)\}/g)].map(m => [m[1].trim(), m[2]]);
  assert.ok(rules.length > 300, 'the rule scan read the stylesheet (' + rules.length + ' rules)');
  assert.deepEqual(rules.filter(([sel, decl]) => /\bis-report\b|hl-rvsp--report/.test(sel) && /gold|245, 158, 11|184, 144, 47/.test(decl)).map(r => r[0]), [], 'no gold declaration on a report-sponsor selector');
  assert.match(css, /\.hl-report-page \.hl-rvsp--report \{\s*display: flex; flex-wrap: wrap; align-items: center; gap: 4px 16px; margin: 12px 0 0; padding: 10px 0 0; border-top: 1px solid #2f2f2f;/, 'the report sponsor is the plate foot: a hairline, no box');
  assert.match(css, /\.hl-rvsp__logo \{[^}]*height: 28px;/, 'the report sponsor logo is the quieter 28px, the featured logo 34px');
  assert.match(css, /\.hl-rv-feat__logo \{[^}]*height: 34px;/);
});
test('CSS: the featured tagline is visible at every width, and on a phone the band is a slim strip and the tab-foot Visit a full-width button', () => {
  assert.equal(/\.hl-rv-feat__tagline \{ display: none;/.test(css), false, 'the band tagline is never hidden for one sponsor');
  const m = css.match(/@media \(max-width: 719px\) \{\s*\.hl-rv-feat \{[\s\S]*?\n\}\n/);
  assert.ok(m, 'a 719px block for the strip');
  assert.match(m[0], /\.hl-rv-feat__tagline \{ flex: 1 1 100%;/);
  const n = css.match(/@media \(max-width: 640px\) \{\s*\.hl-rv-sponsor-card\.is-site[\s\S]*?\n\}\n/);
  assert.ok(n, 'a 640px block');
  assert.match(n[0], /\.hl-rv-sponsor-card__cta \{ margin-left: 0; width: 100%; text-align: center;/);
  assert.equal(/tagline[^}]*display: none/.test(n[0]), false);
});
test('CSS: several Monthly sponsors keep the gold panel and drop the per-item Visit and tagline', () => {
  assert.match(css, /\.hl-rv-feat--many \.hl-rv-feat__tagline, \.hl-rv-feat--many \.hl-rv-feat__cta \{ display: none; \}/);
  assert.match(css, /\.hl-rv-sponsor-card\.is-site\.is-many :is\(\.hl-rv-sponsor-card__tagline, \.hl-rv-sponsor-card__cta\) \{ display: none; \}/);
  assert.match(feat, /if sponsor\.tagline and rv_feat\.size == 1/, 'the margin card shows a tagline only for one sponsor');
});
test('CSS: the band is no longer glued to the nav by a negative margin', () => {
  assert.equal(/\.hl-rv-feat[^{}]*\{[^}]*margin-top: -24px/.test(css), false);
});
test('the cache-busters moved with the stylesheet and the script, on the tabbed branch only', () => {
  const v = [...layout.matchAll(/hl-report-tabs\.(css|js)' \| relative_url \}\}\?v=([0-9.]+)/g)].map(x => x[2]);
  assert.equal(v.length, 2); assert.deepEqual(v, ['20261102.9', '20261102.6']); // the stylesheet moved to .9 in T-0541 (the report title card: smaller title and bottom-line sizes). Earlier: it moved to .8 in T-0538 (the type scale: report section eyebrow, section heading and label sizes read the --hl-fs-* tokens, --rv-fs-mono 15px), the script stays .6. Earlier: it moved to .7 in T-0500.1.7.4 review 2 (C2: the card geometry reads the shared tokens of custom.scss; same computed geometry), the script stays .6. Earlier: the stylesheet and the script moved in T-0500.1.7.3 c5 (an open "i" note stays inside the viewport on both axes) and again in c6, and both moved to .6 in T-0500.1.7.4 when the restyle merged over c6 (stage numbers on the spine, the featured card's gap); the script moved in T-0500.1.12 (Copy code is opt-in: only a block marked .hl-copy gets a button); the stylesheet moved in T-0500.1.11 fix5a (the process tree's kind chip wraps on a phone); the stylesheet moved in T-0500.1.11 fix5a (an inline code chip reserves its 6px closing edge); it moved in T-0500.1.11 b23fix (a stage card breaks an unbroken token); the stylesheet moved again in T-0500.1.11 (the Updated link takes the date label's size: 12.6px under the 13px floor); the script moved in T-0500.1.11 (legacy ATT&CK, stage, hypothesis and confidence tables); the stylesheet moved in T-0500.1.10.1 (collapsed data-view card: the bar keeps square corners over its curated note); it moved before that in T-0500.1.9.1 (box fit: next/previous cards in a column, h3 permalink, timeline end labels, 900px tab labels); the script moved in T-0500.1.10 (one-tab footer, d842b96)
});

function item(kind, name, tagline, logo, href) {
  const h = href || 'https://example.test/' + name.toLowerCase().replace(/\W+/g, '-');
  /* a report sponsor is an item of the attached panel; a site sponsor is a card of the site's own Sponsors rail */
  if (kind === 'site') return `<a class="hl-sponsor-rail__item" href="${h}">${logo ? `<img class="hl-sponsor-rail__logo" src="${logo}" alt="${name}">` : ''}<div class="hl-sponsor-rail__text"><div class="hl-sponsor-rail__name">${name}</div><div class="hl-sponsor-rail__tagline">${tagline}</div></div></a>`;
  return `<a class="hl-rvsp__item" href="${h}" data-rv-sponsor="${kind}" data-name="${name}" data-tagline="${tagline}">${logo ? `<img class="hl-rvsp__logo" src="${logo}" alt="${name}">` : ''}<span class="hl-rvsp__text"><span class="hl-rvsp__name">${name}</span></span></a>`;
}
function page(report, site) {
  const html = TOKENS.map(t => `<h2 class="hl-tab-${t}" id="${t}-source">${t}</h2><p>Original ${t} words.</p>`).join('');
  const bar = (report.length ? '<aside class="hl-rvsp hl-rvsp--band hl-rv-reportband" data-rv-chrome>' + report.map(x => x.replace('data-rv-sponsor="report"', 'data-rv-sponsor="band"')).join('') + '</aside><aside class="hl-rvsp hl-rvsp--report" data-rv-chrome>' + report.join('') + '</aside>' : '')
    + (site.length ? '<aside class="hl-sponsor-rail" aria-label="Sponsors"><div class="hl-sponsor-rail__label">Sponsors</div>' + site.join('') + '</aside>' : '');
  const dom = new JSDOM('<body>' + bar + '<div class="hl-report-page"><div class="hl-post-header"><div class="hl-post-header__eyebrow"></div></div><div class="hl-post-body"><div class="hl-post-content">' + html + '</div></div></div></body>', { url: 'https://example.test/report/', runScripts: 'outside-only' });
  const w = dom.window; w.matchMedia = () => ({ matches: false, addEventListener() {} }); w.ResizeObserver = class { observe() {} }; w.HTMLElement.prototype.scrollIntoView = function () {};
  w.eval(js); assert.ok(w.document.documentElement.classList.contains('hl-rv-ready'));
  return { w, d: w.document };
}
const REPORT = [item('report', 'Report Co', 'Report tagline', '/r.svg')];
const SITE = [item('site', 'Hunt.io', 'Monthly tagline', '/m1.png')];
const SITE2 = SITE.concat([item('site', 'Other Co', 'Other tagline', '/m2.png')]);

test('JS: with no report sponsor the tab-foot card is the featured panel: label, tagline and a real Visit span in the link, aria-hidden', () => {
  const f = page([], SITE); try {
    for (const t of TOKENS) {
      const card = f.d.getElementById('tab-' + t).querySelector('.hl-rv-sponsor-card');
      assert.ok(card.classList.contains('is-site') && !card.classList.contains('is-report') && !card.classList.contains('is-many'), t);
      assert.equal(card.querySelector('.hl-rv-sponsor-card__label').textContent, LABEL);
      assert.equal(card.getAttribute('aria-label'), 'Site sponsor');
      assert.equal(card.querySelector('.hl-rv-sponsor-card__tagline').textContent, 'Monthly tagline');
      const cta = card.querySelector('a.hl-rv-sponsor-card__item > span.hl-rv-sponsor-card__cta');
      assert.ok(cta, 'Visit span inside the link'); assert.equal(cta.getAttribute('aria-hidden'), 'true'); assert.match(cta.textContent, /^Visit/);
      assert.ok(cta.hasAttribute('data-rv-chrome'), 'chrome, so the completeness count never sees it');
    }
    assert.equal(f.d.querySelector('.hl-rv-sponsor-mark'), null, 'no reading-line mark for the site sponsor');
  } finally { f.w.close(); }
});
test('JS: several Monthly sponsors make a logos-only featured card with no Visit element', () => {
  const f = page([], SITE2); try {
    const card = f.d.getElementById('tab-overview').querySelector('.hl-rv-sponsor-card');
    assert.ok(card.classList.contains('is-site') && card.classList.contains('is-many'));
    assert.equal(card.querySelectorAll('.hl-rv-sponsor-card__item').length, 2);
  } finally { f.w.close(); }
});
test('JS: with a report sponsor the card is unchanged (tab accent, "Sponsored by", no gold class, no Visit, no Featured), counted once although the band and the panel both name it, and there is no mark', () => {
  const f = page(REPORT, SITE); try {
    for (const t of TOKENS) {
      const card = f.d.getElementById('tab-' + t).querySelector('.hl-rv-sponsor-card');
      assert.ok(card.classList.contains('is-report') && !card.classList.contains('is-site'), t);
      assert.equal(card.querySelector('.hl-rv-sponsor-card__label').textContent, 'Sponsored by');
      assert.equal(card.querySelector('.hl-rv-sponsor-card__cta'), null);
      assert.equal(/Featured|Hunt\.io/.test(card.textContent), false);
    }
    assert.equal(f.d.querySelector('.hl-rv-sponsor-mark'), null, 'no reading-line mark for the report sponsor');
    assert.equal(f.d.getElementById('tab-overview').querySelectorAll('.hl-rv-sponsor-card__item').length, 1, 'one sponsor, one logo in the card');
  } finally { f.w.close(); }
});

/* the gate row's verdict (design D), each failure driven by the measurement a broken layout would give */
const GOLD = 'rgba(184, 144, 47, 0.6)', CREAM = 'rgb(244, 233, 200)';
function panel(over) {
  return Object.assign({ w: 1200, h: 68, border: GOLD, borderW: 1, image: true, cls: '', text: 'Featured sponsor Hunt.io tagline Visit', label: 'Featured sponsor', labelVisible: true, labelColor: CREAM, many: false, items: 1, withTagline: 1,
    taglines: [{ vis: true, len: 30 }], ctas: [{ vis: true, text: 'Visit →', ariaHidden: 'true', inLink: true, inside: true, tag: 'SPAN' }] }, over || {});
}
function siteCard(over) { return panel(Object.assign({ isReport: false, label: LABEL, text: LABEL + ' Hunt.io' }, over || {})); }
function reportCard(over) { return Object.assign(panel({ isReport: true, border: 'rgb(58, 58, 58)', label: 'Sponsored by', labelColor: 'rgb(168, 168, 168)', text: 'Sponsored by Report Co', taglines: [], ctas: [], withTagline: 0 }), over || {}); }
function foot(over) { return Object.assign({ w: 1100, h: 56, border: 'rgb(58, 58, 58)', borderTopOfFoot: 'rgb(47, 47, 47)', borderW: 1, image: false, text: 'This report is sponsored by Report Co', label: 'This report is sponsored by', labelVisible: true, labelColor: 'rgb(168, 168, 168)', many: false, items: 1, withTagline: 0, taglines: [], ctas: [], inPlate: true }, over || {}); }
/* wide (>= 1440): the margin card; narrow: the band. A page with a Monthly sponsor and no report sponsor: no foot, the gold tab-foot card. */
function noReport(over) { return Object.assign({ wide: false, reportSponsors: 0, siteItems: 1, band: panel(), featCard: null, foot: null, goldBandInDom: false, card: siteCard(), markPresent: false }, over || {}); }
function reportState(over) { return Object.assign({ wide: false, reportSponsors: 1, siteItems: 1, band: panel(), featCard: null, foot: foot(), goldBandInDom: false, card: reportCard(), markPresent: false }, over || {}); }
test('the gate row PASSES: the gold band (narrow) or margin card (wide) for the site sponsor, no foot without a report sponsor, the quiet foot and the quiet card with one; no mark', () => {
  let v = G.featuredSponsorVerdict(noReport()); assert.equal(v.ok, true, v.detail);
  v = G.featuredSponsorVerdict(noReport({ wide: true, band: null, featCard: panel({ w: 140, h: 242 }) })); assert.equal(v.ok, true, v.detail);
  v = G.featuredSponsorVerdict(reportState()); assert.equal(v.ok, true, v.detail);
  v = G.featuredSponsorVerdict(reportState({ siteItems: 0, band: null })); assert.equal(v.ok, true, 'a report sponsor with no Monthly sponsor: ' + v.detail);
});
test('the gate row FAILS a gold report band, a foot with no report sponsor, both featured panels, the wrong one for the width, or none', () => {
  assert.match(G.featuredSponsorVerdict(noReport({ goldBandInDom: true })).detail, /gold report band is still in the page/);
  assert.match(G.featuredSponsorVerdict(noReport({ foot: foot() })).detail, /foot is drawn on a page with no report sponsor/);
  assert.match(G.featuredSponsorVerdict(noReport({ featCard: panel() })).detail, /margin card is drawn at a width that shows the band/);
  assert.match(G.featuredSponsorVerdict(noReport({ wide: true })).detail, /band is drawn at a width that shows the margin card/);
  assert.match(G.featuredSponsorVerdict(noReport({ wide: true })).detail, /margin card was not found/);
  assert.match(G.featuredSponsorVerdict(noReport({ band: null })).detail, /band was not found/);
});
test('the gate row FAILS a sponsor mark on the reading line, for a site sponsor and for a report sponsor', () => {
  assert.match(G.featuredSponsorVerdict(noReport({ markPresent: true })).detail, /sponsor mark is on the reading line/);
  assert.match(G.featuredSponsorVerdict(reportState({ markPresent: true })).detail, /sponsor mark is on the reading line/);
  assert.equal(G.featuredSponsorVerdict({ wide: false, reportSponsors: 0, siteItems: 0, band: null, featCard: null, foot: null, goldBandInDom: false, card: null, markPresent: true }).ok, false);
});
test('the gate row FAILS when the featured panel loses its gold, its gradient, its label, its tagline or its Visit element', () => {
  const bad = (over, re) => { const v = G.featuredSponsorVerdict(noReport({ band: panel(over) })); assert.equal(v.ok, false); assert.match(v.detail, re); };
  bad({ border: 'rgb(58, 58, 58)' }, /no gold border/);
  bad({ image: false }, /no gradient/);
  bad({ label: 'Sponsored by' }, /not "Featured sponsor"/);
  bad({ labelColor: 'rgb(168, 168, 168)' }, /not cream/);
  bad({ taglines: [{ vis: false, len: 30 }] }, /shows 0 of 1 tagline/);
  bad({ ctas: [] }, /no Visit element/);
  bad({ ctas: [{ vis: false, text: 'Visit →', ariaHidden: 'true', inLink: true, inside: true, tag: 'SPAN' }] }, /Visit element is not visible/);
  bad({ ctas: [{ vis: true, text: 'Visit →', ariaHidden: null, inLink: true, inside: true, tag: 'SPAN' }] }, /not aria-hidden/);
  bad({ ctas: [{ vis: true, text: 'Visit →', ariaHidden: 'true', inLink: false, inside: true, tag: 'SPAN' }] }, /not inside the sponsor link/);
  bad({ ctas: [{ vis: true, text: 'Go', ariaHidden: 'true', inLink: true, inside: true, tag: 'SPAN' }] }, /reads "Go"/);
  bad({ ctas: [{ vis: true, text: 'Visit →', ariaHidden: 'true', inLink: true, inside: false, tag: 'SPAN' }] }, /outside the panel/);
});
test('the gate row FAILS the site tab-foot card when it loses its gold or its label, and the missing card', () => {
  const bad = (over, re) => { const v = G.featuredSponsorVerdict(noReport({ card: siteCard(over) })); assert.equal(v.ok, false); assert.match(v.detail, re); };
  bad({ border: 'rgb(58, 58, 58)' }, /no gold border/);
  bad({ label: 'Site sponsor' }, /not "Featured sponsor of/);
  bad({ ctas: [] }, /no Visit element/);
  assert.match(G.featuredSponsorVerdict(noReport({ card: null })).detail, /tab-foot card was not found/);
  assert.match(G.featuredSponsorVerdict(noReport({ card: reportCard() })).detail, /report-sponsor card with no report sponsor/);
});
test('with several Monthly sponsors the band must be logos only; a visible tagline or Visit FAILS', () => {
  const many = panel({ many: true, taglines: [{ vis: false, len: 9 }], ctas: [{ vis: false, text: 'Visit →', ariaHidden: 'true', inLink: true, inside: true, tag: 'SPAN' }] });
  assert.equal(G.featuredSponsorVerdict(noReport({ band: many })).ok, true);
  const leaky = panel({ many: true, taglines: [{ vis: true, len: 9 }], ctas: [] });
  assert.match(G.featuredSponsorVerdict(noReport({ band: leaky })).detail, /logos only expected/);
});
test('the gate row FAILS when the report sponsor foot picks up gold, a gradient, "Featured" or a Visit, leaves the plate, or loses its label', () => {
  const f = over => reportState({ foot: foot(over) });
  assert.match(G.featuredSponsorVerdict(f({ borderTopOfFoot: 'rgba(184, 144, 47, 0.6)' })).detail, /gold border on a report sponsor/);
  assert.match(G.featuredSponsorVerdict(f({ image: true })).detail, /gradient fill/);
  assert.match(G.featuredSponsorVerdict(f({ text: 'Featured sponsor of The Hunter\'s Ledger' })).detail, /says "Featured"/);
  assert.match(G.featuredSponsorVerdict(f({ ctas: [{ vis: true, text: 'Visit', ariaHidden: 'true', inLink: true, inside: true, tag: 'SPAN' }] })).detail, /Visit element on a report sponsor/);
  assert.match(G.featuredSponsorVerdict(f({ inPlate: false })).detail, /not inside the plate/);
  assert.match(G.featuredSponsorVerdict(f({ label: 'Supported by' })).detail, /label is "Supported by"/);
  assert.match(G.featuredSponsorVerdict(reportState({ foot: null })).detail, /foot was not found/);
  assert.match(G.featuredSponsorVerdict(reportState({ card: siteCard() })).detail, /featured site card although the page has a report sponsor/);
  assert.match(G.featuredSponsorVerdict(reportState({ card: reportCard({ border: GOLD }) })).detail, /gold border on a report sponsor/);
});
test('the gate row: a page with no sponsor must draw nothing, and a sponsor with nothing measurable is NOT CHECKED, never PASS', () => {
  const none = { wide: false, reportSponsors: 0, siteItems: 0, band: null, featCard: null, foot: null, goldBandInDom: false, card: null, markPresent: false };
  const v = G.featuredSponsorVerdict(none); assert.equal(v.ok, true); assert.match(v.detail, /0 panels expected, 0 drawn/);
  const orphan = G.featuredSponsorVerdict(Object.assign({}, none, { card: siteCard() })); assert.equal(orphan.ok, false, 'a tab-foot card with no sponsor anywhere is a fault, not a clean page'); assert.match(orphan.detail, /card is drawn with no sponsor/);
  assert.match(G.featuredSponsorVerdict(Object.assign({}, none, { band: panel() })).detail, /drawn although the page has no Monthly sponsor/);
  assert.equal(G.featuredSponsorVerdict(null).notChecked, true);
  const v2 = G.featuredSponsorVerdict({ wide: false, reportSponsors: 1, siteItems: 0, band: null, featCard: null, foot: null, goldBandInDom: false, card: null, markPresent: false });
  assert.equal(v2.ok, false);
});
test('the gate measures through one browser expression that names the elements the verdict reads', () => {
  for (const sel of ['.hl-rv-feat', '.hl-rv-featcard', '.hl-rv-sponsor-card', '.hl-rv-feat__cta', '.hl-rv-featcard__cta', '.hl-rv-sponsor-card__cta', '.hl-rv-feat__tagline', '.hl-rv-sponsor-mark', '.hl-rvsp--report .hl-rvsp__item', '.hl-sponsor-rail .hl-sponsor-rail__item', '.hl-rv-reportband', '.hl-rvsp--report']) assert.ok(G.FEATURED_EXPR.includes(sel), sel + ' is in the expression');
});
