'use strict';
/* T-0500.1.8 (Joseph, 2026-10-30): the site Sponsors rail back on tabbed pages. Fixed in the left gutter where the gutter fits it (1600px and up),
   the site's own in-flow strip where it does not, never hidden. The stylesheet is read, and the gate verdict is driven with the measurement a
   broken layout would give (the browser itself is not driven here). See homelab-soc/docs/gate-honesty-contract.md. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const G = require('../check-browser-report.js');
const root = path.join(__dirname, '..', '..', '..');
const css = fs.readFileSync(path.join(root, 'assets/css/hl-report-tabs.css'), 'utf8');

test('CSS (design D): the site rail is not drawn on tabbed pages; the featured card is fixed in the left margin from 1440px, at least 140px wide there, and the band carries on below', () => {
  assert.match(css, /body:has\(\.hl-report-page\) \.hl-sponsor-rail \{ display: none !important; \}/);
  // T-0500.1.7.4 review 2 (C2): the report sheet no longer carries its own formula; it reads the three shared tokens of custom.scss, whose formula is asserted in design-d-shared.test.js (and measured in a browser)
  assert.match(css, /--rv-rail-gap: var\(--hl-rail-gap\); --rv-card-w: var\(--hl-card-w\); --rv-card-left: var\(--hl-card-left\);/);
  assert.doesNotMatch(css, /--rv-rail-gap: clamp/, 'one definition: the formula lives in custom.scss only');
  assert.match(css, /\.hl-rv-featcard \{ display: none; \}/, 'the card is not drawn below 1440px');
  assert.match(css, /@media \(min-width: 1440px\) \{[^@]*\.hl-rv-feat \{ display: none; \}/, 'the band is not drawn from 1440px');
  const printBlock = css.slice(css.indexOf('@media print'));
  assert.ok(printBlock.includes('.hl-sponsor-rail') && printBlock.includes('.hl-rv-featcard') && printBlock.includes('.hl-rv-feat'), 'print drops the rail, the band and the card');
});

const BOX = (over) => Object.assign({ position: 'fixed', left: 16, right: 156, top: 92, bottom: 334, width: 140, height: 242 }, over || {});
const RAIL = (over) => Object.assign({ present: true, card: BOX(), band: null, oldRailDrawn: false, colLeft: 180, colRight: 1260, colTop: 94, vw: 1440, iw: 1440 }, over || {});
const BAND = (over) => RAIL(Object.assign({ card: null, band: BOX({ position: 'static', left: 40, right: 1240, top: 70, bottom: 138, width: 1200, height: 68 }), colLeft: 40, colTop: 162, vw: 1280, iw: 1280 }, over || {}));
test('the placement verdict passes the card at 1440 and the band at 1280', () => {
  assert.equal(G.railVerdict(RAIL(), 'card').ok, true, G.railVerdict(RAIL(), 'card').detail);
  assert.equal(G.railVerdict(BAND(), 'band').ok, true, G.railVerdict(BAND(), 'band').detail);
});
test('the placement verdict FAILS a hidden panel, the old rail drawn, both panels drawn, a card that is not fixed, touches the column, is off screen, is too narrow, a fixed band, or a band that is not a band', () => {
  const bad = (m, expect, re) => { const v = G.railVerdict(m, expect); assert.equal(v.ok, false); assert.match(v.detail, re); };
  bad(RAIL({ card: null }), 'card', /the featured card is hidden/);
  bad(BAND({ band: null }), 'band', /the featured band is hidden/);
  bad(RAIL({ oldRailDrawn: true }), 'card', /Sponsors rail is drawn/);
  bad(RAIL({ band: BOX({ position: 'static', width: 1200, height: 68 }) }), 'card', /band is drawn where the card is expected/);
  bad(RAIL({ card: BOX({ position: 'static' }) }), 'card', /not fixed in the left margin/);
  bad(RAIL({ card: BOX({ right: 175 }) }), 'card', /from the column/);
  bad(RAIL({ card: BOX({ left: -10 }) }), 'card', /outside the viewport/);
  bad(RAIL({ card: BOX({ width: 100, right: 116 }) }), 'card', /wide \(140 to 200 expected\)/);
  bad(BAND({ band: BOX({ position: 'fixed', left: 40, right: 1240, top: 70, bottom: 138, width: 1200, height: 68 }) }), 'band', /band is fixed/);
  bad(BAND({ band: BOX({ position: 'static', left: 40, right: 1240, top: 70, bottom: 400, width: 1200, height: 330 }), colTop: 162 }), 'band', /below the top of the plate/);
  assert.equal(G.railVerdict({ present: false }, 'card').notChecked, true);
  assert.equal(G.RAIL_STATES.find(s => s[0] === 1439)[2], 'band'); assert.equal(G.RAIL_STATES.find(s => s[0] === 1440)[2], 'card'); assert.equal(G.RAIL_STATES.find(s => s[0] === 1920)[2], 'card');
});
test('the sticky-overlap verdict passes a card with nothing over it and FAILS a sticky bar over it, an element on top of it, or no measurement', () => {
  const ok = (y) => ({ present: true, y, card: { l: 16, t: 92, r: 156, b: 334 }, over: [], covered: [] });
  assert.equal(G.stickyOverlapVerdict([ok(0), ok(900), ok(3000)]).ok, true);
  const v = G.stickyOverlapVerdict([ok(0), Object.assign(ok(900), { over: ['hl-rv-bar'], covered: ['hl-rv-bar'] })]);
  assert.equal(v.ok, false); assert.match(v.detail, /at scroll 900 hl-rv-bar overlaps the card/); assert.match(v.detail, /topmost element over the card is hl-rv-bar/);
  assert.equal(G.stickyOverlapVerdict([{ present: false, y: 0 }]).notChecked, true);
  assert.equal(G.stickyOverlapVerdict([]).notChecked, true);
  assert.match(G.STICKY_CONTROL_CSS, /width:100vw/, 'the control re-creates a full-width sticky bar');
  assert.deepEqual(G.STICKY_STATES, [[1440, 900], [1600, 900]]);
});
