'use strict';

/* T-0500.1.9: the browser-gate row that says the ATT&CK coverage strip and the Navigator
   layer download are back on a tabbed page. The verdict is pure, so each way the row can
   fail is a measurement fed to it, and the control the live gate runs (the page without
   attack-coverage.js) is built here too. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var path = require('node:path');
var G = require('../check-browser-report.js');

function strip(patch) {
  return Object.assign({
    chrome: true, segs: 15, techniques: 31, count: '31 techniques · 9 of 15 tactics', visible: true, exportCount: 1,
    exportVisible: true, exportText: '↓ Navigator layer',
    download: { file: 'x-mitre-att-ck-mapping-layer.json', techniques: 31, domain: 'enterprise-attack' }
  }, patch || {});
}
/* a page measurement: the source tables read in document order, each with the strip standing before it (or null) */
function good(n) {
  var tables = [];
  for (var i = 1; i <= (n || 1); i++) tables.push({ index: i, label: '13. MITRE ATT&CK Mapping', panel: 'tab-chain', rows: 17, withId: 16, mapped: true, strip: strip() });
  return { sourceBlocks: 9, tablesRead: 3 + (n || 1), stripsOnPage: n || 1, unpaired: 0, tables: tables };
}
function bad(m, re) {
  var v = G.attackStripVerdict(m);
  assert.equal(v.notChecked, false);
  assert.equal(v.ok, false, JSON.stringify(v));
  assert.match(v.why.join(' | '), re);
}
function patchStrip(n, i, patch) { var m = good(n); m.tables[i].strip = strip(patch); return m; }

test('a strip with 15 bars, a count, chrome and a working layer download passes, for one mapping table and for two', function () {
  var v = G.attackStripVerdict(good(1));
  assert.equal(v.ok, true, v.detail);
  assert.match(v.detail, /1 strip\(s\) for 1 mapping table\(s\)/);
  assert.match(v.detail, /download x-mitre-att-ck-mapping-layer\.json with 31/);
  var w = G.attackStripVerdict(good(2));
  assert.equal(w.ok, true, w.detail);
  assert.match(w.detail, /2 strip\(s\) for 2 mapping table\(s\)/);
});

test('every way the row can fail does fail, and names the mapping table it failed on', function () {
  bad(patchStrip(1, 0, { chrome: false }), /not marked data-rv-chrome/);
  bad(patchStrip(1, 0, { segs: 14 }), /14 tactic bars/);
  bad(patchStrip(1, 0, { techniques: 0, count: '0 techniques' }), /counts 0 techniques/);
  bad(patchStrip(1, 0, { visible: false }), /not painted/);
  bad(patchStrip(1, 0, { exportCount: 0 }), /0 Navigator layer buttons/);
  bad(patchStrip(1, 0, { exportText: 'Download' }), /download button reads/);
  bad(patchStrip(1, 0, { exportVisible: false }), /Navigator layer button is not painted/);
  bad(patchStrip(1, 0, { download: { error: 'clicking the button offered no file' } }), /offered no usable file/);
  bad(patchStrip(1, 0, { download: { file: 'x.json', techniques: 0 } }), /0 technique\(s\) in its layer/);
  bad(patchStrip(1, 0, { download: { file: 'x.txt', techniques: 3 } }), /"x.txt"/);
  bad(patchStrip(1, 0, { download: { file: 'x.json', techniques: 30 } }), /counts 31 techniques but its download lists 30/);
  var none = good(1); none.tables[0].strip = null; none.stripsOnPage = 0;
  bad(none, /mapping table 1 \(13\. MITRE ATT&CK Mapping\) in tab-chain has no coverage strip \(0 strip\(s\) on the page for 1 mapping table\(s\)\)/);
});

test('sitefix3 F3: a page with two mapping tables and one strip FAILS, naming the table that has none; the same for each table, and for a defect in the second strip only', function () {
  var second = good(2); second.tables[1].strip = null; second.stripsOnPage = 1;
  bad(second, /mapping table 2 .* has no coverage strip \(1 strip\(s\) on the page for 2 mapping table\(s\)\)/);
  var first = good(2); first.tables[0].strip = null; first.stripsOnPage = 1;
  bad(first, /mapping table 1 .* has no coverage strip/);
  // the first strip is perfect; only the second one's download is broken or its bars are short
  bad(patchStrip(2, 1, { download: { error: 'clicking the button offered no file' } }), /mapping table 2 .*offered no usable file/);
  bad(patchStrip(2, 1, { segs: 3 }), /mapping table 2 .*3 tactic bars/);
  bad(patchStrip(2, 1, { chrome: false }), /mapping table 2 .*data-rv-chrome/);
  // the pre-fix row measured only the first strip and passed this
  assert.equal(G.attackStripVerdict(second).ok, false);
});

test('a table that carries technique IDs but no tactic gets no strip by rule, and the row says so; a report with no mapping table at all is NOT CHECKED', function () {
  var m = good(1);
  m.tables.push({ index: 4, label: 'Detection coverage', panel: 'tab-indicators', rows: 5, withId: 5, mapped: false, strip: null });
  var v = G.attackStripVerdict(m);
  assert.equal(v.ok, true, v.detail);
  assert.match(v.detail, /no strip expected for table 4 \(Detection coverage\): it carries technique IDs but no row pairs one with an ATT&CK tactic/);
  var none = { sourceBlocks: 9, tablesRead: 4, stripsOnPage: 0, unpaired: 0, tables: [{ index: 1, label: 'x', panel: 'tab-chain', rows: 3, withId: 0, mapped: false, strip: null }] };
  var nc = G.attackStripVerdict(none);
  assert.equal(nc.notChecked, true);
  assert.equal(nc.ok, false);
  assert.equal(G.attackStripVerdict({ sourceBlocks: 0, tables: [] }).notChecked, true);
  assert.equal(G.attackStripVerdict(null).notChecked, true);
});

test('the control page drops the attack-coverage.js tag and nothing else; no tag to drop is null', function () {
  var layout = fs.readFileSync(path.join(__dirname, '..', '..', '..', '_layouts', 'post.html'), 'utf8');
  var html = '<html><body><p>a</p><script src="/assets/js/attack-coverage.js?v=2" defer></script><script src="/assets/js/glossary.js" defer></script></body></html>';
  var out = G.attackStripControlHtml(html);
  assert.equal(out, '<html><body><p>a</p><script src="/assets/js/glossary.js" defer></script></body></html>');
  assert.equal(G.attackStripControlHtml('<html></html>'), null);
  // and the layout really emits the tag for a tabbed page (the premise of the control)
  assert.match(layout, /\{% endunless %\}<script src="\{\{ '\/assets\/js\/attack-coverage\.js' \| relative_url \}\}\?v=2" defer><\/script>/);
});

test('the in-page expression compiles', function () {
  var AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  assert.doesNotThrow(function () { new AsyncFunction('return ' + G.ATTACK_STRIP_EXPR); });
});

test('the layout loads attack-coverage.js on tabbed pages and keeps hl-attack-table untabbed only and loads hl-facts on both layouts', function () {
  var layout = fs.readFileSync(path.join(__dirname, '..', '..', '..', '_layouts', 'post.html'), 'utf8');
  var ac = layout.indexOf("attack-coverage.js' | relative_url }}?v=2");
  var openUnless = layout.indexOf('{% unless hl_tabbed %}', ac);
  var table = layout.indexOf("hl-attack-table.js' | relative_url", ac);
  var facts = layout.indexOf("hl-facts.js' | relative_url", ac);
  var endUnless = layout.indexOf('{% endunless %}', table);
  // hl-attack-table.js is inside the unless-tabbed block; hl-facts.js comes after the block closes (Joseph, 2026-10-31).
  assert.ok(ac > 0 && openUnless > ac && table > openUnless && endUnless > table && facts > endUnless);
  // attack-coverage.js sits outside any unless-tabbed block: the nearest tag before it closes one.
  var before = layout.slice(0, ac);
  assert.ok(before.lastIndexOf('{% endunless %}') > before.lastIndexOf('{% unless'), 'attack-coverage.js is inside an unless block');
  var tabs = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'assets', 'js', 'hl-report-tabs.js'), 'utf8');
  assert.match(tabs, /querySelectorAll\('\.hl-fignav, \.hl-attack'\)\.forEach\(function \(n\) \{ n\.setAttribute\('data-rv-chrome', ''\)/);
});

test('the stylesheet lays the strip out for the tabbed page: 14 px tactic names, wrapping columns, no 8 px label', function () {
  var css = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'assets', 'css', 'hl-report-tabs.css'), 'utf8');
  assert.match(css, /\.hl-report-page \.hl-attack__bars \{[^}]*grid-template-columns: repeat\(auto-fill, minmax\(104px, 1fr\)\)/);
  assert.match(css, /\.hl-report-page \.hl-attack__seglabel \{[^}]*font-size: 14px/);
  assert.match(css, /\.hl-report-page \.hl-attack__seg \{[^}]*grid-template-columns: minmax\(0, 1fr\)/);
});
