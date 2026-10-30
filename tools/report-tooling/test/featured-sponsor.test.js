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
const band = body.slice(body.indexOf('include.part == "band"'), body.indexOf('include.part == "report"'));
const rep = body.slice(body.indexOf('include.part == "report"'));
const LABEL = "Featured sponsor of The Hunter's Ledger";
const BANDLABEL = 'This report is sponsored by';
const TOKENS = ['overview', 'victims', 'chain', 'timeline', 'attribution', 'indicators', 'confidence'];

test('the band include: the report-sponsor label, the report sponsors only, and a real Visit span inside the link, aria-hidden, only when the sponsor has a link', () => {
  assert.ok(band.includes(BANDLABEL) && band.includes('rv_report_sponsors') && band.includes('data-rv-sponsor="band"'));
  assert.equal(band.includes('Featured sponsor'), false, 'the band no longer carries the site sponsor wording');
  assert.match(band, /<span class="hl-rvsp__cta" aria-hidden="true">Visit &rarr;<\/span>/);
  const cta = band.indexOf('hl-rvsp__cta'), open = band.indexOf('<a class="hl-rvsp__item"'), close = band.indexOf('</a>');
  assert.ok(open > -1 && open < cta && cta < close, 'the Visit span sits inside the sponsor link');
  assert.match(band.slice(band.lastIndexOf('{%', cta), cta), /if sponsor\.url/, 'no Visit with no link to visit');
  assert.equal(/Visit/.test(rep), false, 'the report sponsor keeps no Visit element');
  assert.equal(/Featured/.test(rep), false, 'the report sponsor is never "Featured"');
  assert.ok(rep.includes('This report is sponsored by'));
  assert.equal(/monthly|rv_site_sponsors/.test(body), false, 'no Monthly sponsor is rendered by the include');
  assert.match(band, /^include\.part == "band" and rv_report_sponsors\.size > 0 -%\}/, 'a report with no sponsor renders no band at all');
});
test('the Visit call to action is an element, never generated CSS content', () => {
  assert.equal(/content:\s*['"][^'"]*Visit/.test(css), false);
  assert.equal(/::after\s*\{[^}]*Visit/.test(css), false);
  assert.match(css, /\.hl-rvsp__cta, \.hl-rv-sponsor-card__cta \{[^}]*margin-left: auto;[^}]*border: 1px solid var\(--rv-gold-bar\)/);
});
test('CSS: the featured panel is gold and shared by the report band and the site card; the attached report panel and the report card keep the accent', () => {
  assert.match(css, /--rv-gold: #d4a73a;/); assert.match(css, /--rv-gold-bar: #b8902f;/);
  assert.match(css, /\.hl-rv-reportband__in, \.hl-rv-sponsor-card\.is-site \{[^}]*linear-gradient\(135deg, #1c1c1c, #0d1117\)[^}]*border-left: 4px solid var\(--rv-gold-bar\)/);
  assert.match(css, /\.hl-rv-reportband__in::before, \.hl-rv-sponsor-card\.is-site::before \{[^}]*radial-gradient\([^)]*var\(--rv-gold-bar\)[^}]*opacity: 0\.16/);
  assert.match(css, /\.hl-rv-reportband \.hl-rv-reportband__label, \.hl-rv-sponsor-card\.is-site \.hl-rv-sponsor-card__label \{ color: var\(--rv-gold\) !important; font-weight: 700; \}/);
  assert.equal(/sponsor-mark/.test(css), false, 'no CSS is left for the reading-line mark');
  assert.match(css, /\.hl-rv-reportband \.hl-rvsp__logo \{ height: 38px; max-width: 220px; \}/);
  assert.match(css, /\.hl-rv-sponsor-card\.is-site \.hl-rv-sponsor-card__item img \{ height: 38px; max-width: 220px; \}/);
  const rules = [...css.replace(/\/\*[\s\S]*?\*\//g, '').matchAll(/([^{}@]+)\{([^{}]*)\}/g)].map(m => [m[1].trim(), m[2]]);
  assert.ok(rules.length > 300, 'the rule scan read the stylesheet (' + rules.length + ' rules)');
  assert.deepEqual(rules.filter(([sel, decl]) => /\bis-report\b|hl-rvsp--report/.test(sel) && /gold/.test(decl)).map(r => r[0]), [], 'no gold declaration on a report-sponsor selector');
  assert.match(css, /\.hl-rv-sponsor-card\.is-report \{ background: var\(--rv-row\); border-left: 4px solid var\(--acc\);/, 'the report card keeps the tab accent');
});
test('CSS: the tagline is visible at every width, and on a phone Visit is a full-width button under the content', () => {
  assert.equal(/\.hl-rv-reportband \.hl-rvsp__tagline \{ display: none;/.test(css), false, 'v6.1 hid the band tagline on phones');
  const m = css.match(/@media \(max-width: 640px\) \{[\s\S]*?\n\}\n/);
  assert.ok(m, 'a 640px block');
  assert.match(m[0], /\.hl-rvsp__cta, \.hl-rv-sponsor-card__cta \{ margin-left: 0; width: 100%; text-align: center;/);
  assert.match(m[0], /flex: 1 1 100%/);
  assert.equal(/tagline[^}]*display: none/.test(m[0]), false);
});
test('CSS: several Monthly sponsors keep the gold panel and drop the per-item Visit and tagline', () => {
  assert.match(css, /\.hl-rvsp__zone--many \.hl-rvsp__item:has\(\.hl-rvsp__logo\) \.hl-rvsp__text, \.hl-rvsp__zone--many \.hl-rvsp__cta \{ display: none; \}/);
  assert.match(css, /\.hl-rv-sponsor-card\.is-site\.is-many :is\(\.hl-rv-sponsor-card__tagline, \.hl-rv-sponsor-card__cta\) \{ display: none; \}/);
});
test('CSS: the band is no longer glued to the nav by a negative margin', () => {
  assert.equal(/\.hl-rv-reportband[^{}]*\{[^}]*margin-top: -24px/.test(css), false);
});
test('the cache-busters moved with the stylesheet and the script, on the tabbed branch only', () => {
  const v = [...layout.matchAll(/hl-report-tabs\.(css|js)' \| relative_url \}\}\?v=([0-9.]+)/g)].map(x => x[2]);
  assert.equal(v.length, 2); assert.deepEqual(v, ['20261030.4', '20261030.4']);
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

/* the gate row's verdict, each failure driven by the measurement a broken layout would give */
const GOLD_FOR_TEST = 'rgb(184, 144, 47)';
const BAR = 'rgb(184, 144, 47)', LAB = 'rgb(212, 167, 58)';
function panel(over) {
  return Object.assign({ w: 1200, h: 80, barW: 4, bar: BAR, image: true, cls: '', text: BANDLABEL + ' Hunt.io tagline Visit', label: BANDLABEL, labelVisible: true, labelColor: LAB, many: false, items: 1, withTagline: 1,
    taglines: [{ vis: true, len: 30 }], ctas: [{ vis: true, text: 'Visit →', ariaHidden: 'true', inLink: true, inside: true, tag: 'SPAN' }] }, over || {});
}
function siteCard(over) { return panel(Object.assign({ isReport: false, label: LABEL, text: LABEL + ' Hunt.io' }, over || {})); }
/* a page with no report sponsor and a Monthly sponsor: no band, the gold site card, the rail has one card */
function noReport(over) { return Object.assign({ reportSponsors: 0, siteItems: 1, band: null, bandInDom: false, card: siteCard(), markPresent: false }, over || {}); }
function reportState(over) {
  return Object.assign({ reportSponsors: 1, siteItems: 1, band: panel(), bandInDom: true, card: panel({ isReport: true, barW: 4, bar: 'rgb(163, 113, 247)', acc: 'rgb(163, 113, 247)', image: false, label: 'Sponsored by', labelColor: 'rgb(168, 168, 168)', text: 'Sponsored by Report Co tagline', ctas: [] }),
    markPresent: false }, over || {});
}
test('the gate row PASSES: no band on a page with no report sponsor; the gold band and the unchanged report card when there is one; no mark', () => {
  let v = G.featuredSponsorVerdict(noReport()); assert.equal(v.ok, true, v.detail);
  v = G.featuredSponsorVerdict(reportState()); assert.equal(v.ok, true, v.detail);
  v = G.featuredSponsorVerdict(reportState({ siteItems: 0 })); assert.equal(v.ok, true, 'a report sponsor with no Monthly sponsor: ' + v.detail);
});
test('the gate row FAILS a band on a page with no report sponsor, in the DOM or drawn (the preview must have none)', () => {
  assert.match(G.featuredSponsorVerdict(noReport({ bandInDom: true })).detail, /band is drawn on a page with no report sponsor/);
  assert.match(G.featuredSponsorVerdict(noReport({ band: panel() })).detail, /band is drawn on a page with no report sponsor/);
  assert.equal(G.featuredSponsorVerdict(noReport({ bandInDom: true })).ok, false);
});
test('the gate row FAILS a sponsor mark on the reading line, for a site sponsor and for a report sponsor', () => {
  assert.match(G.featuredSponsorVerdict(noReport({ markPresent: true })).detail, /sponsor mark is on the reading line/);
  assert.match(G.featuredSponsorVerdict(reportState({ markPresent: true })).detail, /sponsor mark is on the reading line/);
  assert.equal(G.featuredSponsorVerdict({ reportSponsors: 0, siteItems: 0, band: null, bandInDom: false, card: null, markPresent: true }).ok, false);
});
test('the gate row FAILS when the report band loses its gold bar, its gradient, its label, its tagline or its Visit element', () => {
  const bad = (over, re) => { const v = G.featuredSponsorVerdict(reportState({ band: panel(over) })); assert.equal(v.ok, false); assert.match(v.detail, re); };
  bad({ bar: 'rgb(163, 113, 247)' }, /no 4px gold left bar/);
  bad({ barW: 1 }, /no 4px gold left bar/);
  bad({ image: false }, /no gradient/);
  bad({ label: LABEL }, /not "This report is sponsored by"/);
  bad({ labelColor: 'rgb(168, 168, 168)' }, /not gold/);
  bad({ taglines: [{ vis: false, len: 30 }] }, /shows 0 of 1 tagline/);
  bad({ ctas: [] }, /no Visit element/);
  bad({ ctas: [{ vis: false, text: 'Visit →', ariaHidden: 'true', inLink: true, inside: true, tag: 'SPAN' }] }, /Visit element is not visible/);
  bad({ ctas: [{ vis: true, text: 'Visit →', ariaHidden: null, inLink: true, inside: true, tag: 'SPAN' }] }, /not aria-hidden/);
  bad({ ctas: [{ vis: true, text: 'Visit →', ariaHidden: 'true', inLink: false, inside: true, tag: 'SPAN' }] }, /not inside the sponsor link/);
  bad({ ctas: [{ vis: true, text: 'Go', ariaHidden: 'true', inLink: true, inside: true, tag: 'SPAN' }] }, /reads "Go"/);
  bad({ ctas: [{ vis: true, text: 'Visit →', ariaHidden: 'true', inLink: true, inside: false, tag: 'SPAN' }] }, /outside the panel/);
  assert.match(G.featuredSponsorVerdict(reportState({ band: null, bandInDom: false })).detail, /report band was not found/);
});
test('the gate row FAILS the site card when it loses its gold or its label, and the missing card', () => {
  const bad = (over, re) => { const v = G.featuredSponsorVerdict(noReport({ card: siteCard(over) })); assert.equal(v.ok, false); assert.match(v.detail, re); };
  bad({ bar: 'rgb(163, 113, 247)' }, /no 4px gold left bar/);
  bad({ label: 'Site sponsor' }, /not "Featured sponsor/);
  bad({ ctas: [] }, /no Visit element/);
  assert.match(G.featuredSponsorVerdict(noReport({ card: null })).detail, /tab-foot card was not found/);
  assert.match(G.featuredSponsorVerdict(noReport({ card: reportState().card })).detail, /report-sponsor card with no report sponsor/);
});
test('with several report sponsors (a bundle) the band must be logos only; a visible tagline or Visit FAILS', () => {
  const many = panel({ many: true, taglines: [{ vis: false, len: 9 }], ctas: [{ vis: false, text: 'Visit →', ariaHidden: 'true', inLink: true, inside: true, tag: 'SPAN' }] });
  assert.equal(G.featuredSponsorVerdict(reportState({ reportSponsors: 2, band: many })).ok, true);
  const leaky = panel({ many: true, taglines: [{ vis: true, len: 9 }], ctas: [] });
  assert.match(G.featuredSponsorVerdict(reportState({ reportSponsors: 2, band: leaky })).detail, /logos only expected/);
});
test('the gate row FAILS when a report sponsor picks up gold, a gradient, "Featured" or a Visit element on its card', () => {
  const card = over => reportState({ card: Object.assign(reportState().card, over) });
  assert.match(G.featuredSponsorVerdict(card({ bar: BAR })).detail, /gold bar on a report sponsor/);
  assert.match(G.featuredSponsorVerdict(card({ image: true })).detail, /gradient fill on a report sponsor/);
  assert.match(G.featuredSponsorVerdict(card({ text: 'Featured sponsor of The Hunter\'s Ledger' })).detail, /says "Featured"/);
  assert.match(G.featuredSponsorVerdict(card({ ctas: [{ vis: true, text: 'Visit', ariaHidden: 'true', inLink: true, inside: true, tag: 'SPAN' }] })).detail, /Visit element on a report sponsor/);
  assert.match(G.featuredSponsorVerdict(reportState({ card: siteCard() })).detail, /featured site card although the page has a report sponsor/);
});
test('the gate row: a page with no sponsor must draw nothing, and a sponsor with nothing measurable is NOT CHECKED, never PASS', () => {
  const none = { reportSponsors: 0, siteItems: 0, band: null, bandInDom: false, card: null, markPresent: false };
  const v = G.featuredSponsorVerdict(none); assert.equal(v.ok, true); assert.match(v.detail, /0 panels expected, 0 drawn/);
  const orphan = G.featuredSponsorVerdict(Object.assign({}, none, { card: siteCard() })); assert.equal(orphan.ok, false, 'a tab-foot card with no sponsor anywhere is a fault, not a clean page'); assert.match(orphan.detail, /card is drawn with no sponsor/);
  assert.equal(G.featuredSponsorVerdict(null).notChecked, true);
  const v2 = G.featuredSponsorVerdict({ reportSponsors: 1, siteItems: 0, band: null, bandInDom: false, card: null, markPresent: false });
  assert.equal(v2.ok, false);
});
test('the gate measures through one browser expression that names the elements the verdict reads', () => {
  for (const sel of ['.hl-rv-reportband__in', '.hl-rv-sponsor-card', '.hl-rvsp__cta', '.hl-rv-sponsor-card__cta', '.hl-rvsp__tagline', '.hl-rv-sponsor-mark', '.hl-rvsp--report .hl-rvsp__item', '.hl-sponsor-rail .hl-sponsor-rail__item', '.hl-rv-reportband']) assert.ok(G.FEATURED_EXPR.includes(sel), sel);
});

test('the report-sponsor card must keep the active tab accent: no bar, a different colour or an unreadable accent cannot pass (T-0500.1.8 review fix)', () => {
  const card = (over) => reportState({ card: Object.assign({}, reportState().card, over) });
  let v = G.featuredSponsorVerdict(card({}));
  assert.equal(v.ok, true, v.detail);
  v = G.featuredSponsorVerdict(card({ barW: 0, bar: 'rgba(0, 0, 0, 0)' }));
  assert.equal(v.ok, false); assert.match(v.detail, /no 4px left bar in the tab accent/);
  v = G.featuredSponsorVerdict(card({ barW: 1 }));
  assert.equal(v.ok, false, 'a thin bar is not the 4px accent bar');
  v = G.featuredSponsorVerdict(card({ bar: 'rgb(255, 255, 255)' }));
  assert.equal(v.ok, false); assert.match(v.detail, /not the active tab accent rgb\(163, 113, 247\)/);
  v = G.featuredSponsorVerdict(card({ acc: null }));
  assert.equal(v.notChecked, true, 'an accent that cannot be measured is NOT CHECKED'); assert.equal(v.ok, false); assert.match(v.detail, /could not be read/);
  v = G.featuredSponsorVerdict(card({ acc: null, bar: GOLD_FOR_TEST }));
  assert.equal(v.ok, false, 'a real fault is still a FAIL when the accent is also unreadable'); assert.equal(!!v.notChecked, false);
});
