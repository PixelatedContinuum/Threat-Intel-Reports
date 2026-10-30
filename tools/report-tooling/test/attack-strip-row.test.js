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

function good() {
  return {
    panelFound: true, mappingTables: 1, tablesInChain: 1, strips: 1, inChain: 1, chrome: 1, segs: 15,
    techniques: 31, count: '31 techniques · 9 of 15 tactics', visible: true, exportCount: 1,
    exportVisible: true, exportText: '↓ Navigator layer',
    download: { file: 'x-mitre-att-ck-mapping-layer.json', techniques: 31, domain: 'enterprise-attack' }
  };
}
function bad(patch, re) {
  var m = Object.assign(good(), patch);
  var v = G.attackStripVerdict(m);
  assert.equal(v.notChecked, false);
  assert.equal(v.ok, false, JSON.stringify(patch));
  assert.match(v.why.join(' | '), re);
}

test('a strip with 15 bars, a count, chrome and a working layer download passes', function () {
  var v = G.attackStripVerdict(good());
  assert.equal(v.ok, true, v.detail);
  assert.match(v.detail, /31 technique\(s\)/);
});

test('every way the row can fail does fail', function () {
  bad({ strips: 0, inChain: 0, chrome: 0, segs: 0, techniques: 0, visible: false, exportCount: 0 }, /no coverage strip is drawn in the Attack chain tab/);
  bad({ strips: 1, inChain: 0 }, /no coverage strip is drawn in the Attack chain tab.*1 strip\(s\) on the whole page/);
  bad({ tablesInChain: 0 }, /mapping table is not in the Attack chain tab/);
  bad({ chrome: 0 }, /not marked data-rv-chrome/);
  bad({ segs: 14 }, /14 tactic bars/);
  bad({ techniques: 0, count: '0 techniques' }, /counts 0 techniques/);
  bad({ visible: false }, /not painted/);
  bad({ exportCount: 0 }, /0 Navigator layer buttons/);
  bad({ exportText: 'Download' }, /download button reads/);
  bad({ exportVisible: false }, /Navigator layer button is not painted/);
  bad({ download: { error: 'clicking the button offered no file' } }, /offered no usable file/);
  bad({ download: { file: 'x.json', techniques: 0 } }, /0 technique\(s\) in its layer/);
  bad({ download: { file: 'x.txt', techniques: 3 } }, /"x.txt"/);
});

test('a report with no ATT&CK mapping table, or a page with no Attack chain panel, is NOT CHECKED, never a pass', function () {
  var none = G.attackStripVerdict(Object.assign(good(), { mappingTables: 0, strips: 0, inChain: 0 }));
  assert.equal(none.notChecked, true);
  assert.equal(none.ok, false);
  assert.equal(G.attackStripVerdict(Object.assign(good(), { panelFound: false })).notChecked, true);
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

test('the layout loads attack-coverage.js on tabbed pages and keeps hl-attack-table and hl-facts untabbed only', function () {
  var layout = fs.readFileSync(path.join(__dirname, '..', '..', '..', '_layouts', 'post.html'), 'utf8');
  var ac = layout.indexOf("attack-coverage.js' | relative_url }}?v=2");
  var openUnless = layout.indexOf('{% unless hl_tabbed %}', ac);
  var table = layout.indexOf('hl-attack-table.js', ac);
  var facts = layout.indexOf('hl-facts.js', ac);
  var endUnless = layout.indexOf('{% endunless %}', facts);
  assert.ok(ac > 0 && openUnless > ac && table > openUnless && facts > table && endUnless > facts);
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
