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

test('CSS: the rail is fixed in the gutter from 1600px with 24px clear nominal, and the site strip carries on from 1281 to 1599px', () => {
  assert.match(css, /@media \(min-width: 1600px\) \{\s*body:has\(\.hl-report-page\) \.hl-sponsor-rail \{\s*--rail-gutter: calc\(50vw - 600px\);\s*--rail-w: min\(200px, calc\(var\(--rail-gutter\) - 48px\)\);\s*width: var\(--rail-w\); left: calc\(\(var\(--rail-gutter\) - var\(--rail-w\)\) \/ 2\);/);
  const strip = css.match(/@media \(min-width: 1281px\) and \(max-width: 1599px\) \{[\s\S]*?\n\}\n/)[0];
  assert.match(strip, /position: static; transform: none; width: auto; max-width: 900px;/);
  assert.equal(/display:\s*none/.test(strip), false, 'never hidden');
  const printBlock = css.slice(css.indexOf('@media print'));
  assert.ok(printBlock.includes('.hl-sponsor-rail'), 'print still drops the rail');
});

const RAIL = (over) => Object.assign({ present: true, display: 'flex', visibility: 'visible', position: 'fixed', left: 80, right: 280, top: 200, bottom: 400, width: 200, height: 200, colLeft: 360, colRight: 1560, colTop: 90, vw: 1920, iw: 1920, visibleItems: 1, allItems: 1 }, over || {});
test('the rail verdict passes fixed at 1920 and the strip at 1280', () => {
  assert.equal(G.railVerdict(RAIL(), 'fixed').ok, true, G.railVerdict(RAIL(), 'fixed').detail);
  const strip = RAIL({ position: 'static', left: 40, right: 1240, top: 70, bottom: 92, width: 1200, height: 22, colLeft: 40, colTop: 92, vw: 1280 });
  assert.equal(G.railVerdict(strip, 'strip').ok, true, G.railVerdict(strip, 'strip').detail);
});
test('the rail verdict FAILS when hidden, fixed where the gutter does not fit it, touching the column, off screen, the wrong width, or not a strip', () => {
  const bad = (m, expect, re) => { const v = G.railVerdict(m, expect); assert.equal(v.ok, false); assert.match(v.detail, re); };
  bad(RAIL({ display: 'none', width: 0, height: 0 }), 'fixed', /the rail is hidden/);
  bad(RAIL({ display: 'none', width: 0, height: 0 }), 'strip', /the rail is hidden/);
  bad(RAIL({ right: 350 }), 'fixed', /from the column/);
  bad(RAIL({ left: -10 }), 'fixed', /outside the viewport/);
  bad(RAIL({ position: 'static' }), 'fixed', /not fixed in the gutter/);
  bad(RAIL({ width: 100 }), 'fixed', /wide \(120 to 200 expected\)/);
  bad(RAIL({ visibleItems: 0 }), 'fixed', /0 of 1 sponsor card/);
  bad(RAIL({ position: 'fixed', bottom: 120, height: 22 }), 'strip', /fixed at a width where the gutter does not fit/);
  bad(RAIL({ position: 'static', bottom: 400, colTop: 90 }), 'strip', /below the top of the report/);
  bad(RAIL({ position: 'static', bottom: 80, height: 300, colTop: 90 }), 'strip', /not a strip/);
  assert.equal(G.railVerdict({ present: false }, 'fixed').notChecked, true);
  assert.equal(G.RAIL_STATES.find(s => s[0] === 1280)[2], 'strip'); assert.equal(G.RAIL_STATES.find(s => s[0] === 1920)[2], 'fixed');
});
