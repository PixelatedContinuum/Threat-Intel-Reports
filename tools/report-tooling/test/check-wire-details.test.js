'use strict';

/* T-0532 part S: the Details dropdown's own pins, added to the wire gate.

   The first four groups read the real site files, so a file someone edits later
   without the gate in mind still trips: the two JSON pages and the shared include
   emit every value through | jsonify, wire-details.js contains no markup-injection
   sink, all three row templates carry the server-rendered toggle, and the headlines
   filter item is the wrapper, never the anchor under it. The remainder pins the new
   exporter fields through check(), reading synthetic wire.yml documents. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var path = require('node:path');
var CW = require('../lib/check-wire.js');

var ROOT = path.join(__dirname, '..', '..', '..');
function read(p) { return fs.readFileSync(path.join(ROOT, p), 'utf8'); }

var INDEX = read('wire/index.md');
var DETAIL_JS = read('assets/js/wire-details.js');
var JSON_N = read('wire/details-nkev.json');
var JSON_C = read('wire/details-cves.json');
var ROW_INCLUDE = read('_includes/wire-details-row.html');

var NOW = Date.parse('2026-11-01T12:00:00Z');

/* A wire.yml document with the fields the Details fact sheet reads. */
function vulnRow(over) {
  var r = {
    cve: 'CVE-2026-1234', added: '2026-10-28', vendor: 'Acme', product: 'Widget',
    cisa_added: '', evidence: '', older: false, ssvc_expl: '', ssvc_auto: '',
    ssvc_impact: '', fixed: '', aliases: [], msf: [], edb: [], reports: [],
    reports_more: 0, stories: 0, et_sids: [], nuclei: '', cisa_sigma: [],
    snort3_sids: [], epss: '', epss_pct: '', epss_date: '', epss_pre: '', epss_max: '',
    epss_xmodel: '', disclosed: '', gap: '', kev_due: '',
    cvss: '9.8', cvss_version: '3.1', severity: 'critical', scored_by: 'CNA',
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
  };
  return Object.assign(r, over || {});
}
function docWithVuln(row, over) {
  var d = {
    generated_at: '2026-11-01T11:50:00Z',
    window_days: 30,
    counts: { total: 1, research: 1, news: 0 },
    topics: [{ label: 'security', count: 1, color: 3 }],
    label_colors: { security: 3 },
    items: [
      { title: 'A', url: 'https://x.test/a', source: 'AlienVault',
        date: '2026-10-25T10:00:00Z', kind: 'research', labels: ['security'] }
    ],
    vulns: [row],
    vulns_status: 'ok',
    vulns_generated_at: '2026-11-01T11:50:00Z',
    vulns_counts: { total: 1, cisa: 0, older: 0 }
  };
  return Object.assign(d, over || {});
}

/* --- 1. every value in the JSON pages goes through jsonify ---------------------- */

test('the two Details JSON pages and the row include emit every output through jsonify', function () {
  [JSON_N, JSON_C, ROW_INCLUDE].forEach(function (src) {
    var r = CW.checkDetailsJsonPage(src);
    assert.equal(r.status, 'PASS', JSON.stringify(r.problems));
  });
});

test('a bare output in a Details JSON page is caught, wherever it stands', function () {
  var bad = '{"generated_at": {{ wire.vulns_generated_at | jsonify }}, "chosen": {{ wire.window_days }}, "rows": {}}';
  var r = CW.checkDetailsJsonPage(bad);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /jsonify/);
});

test('an unreadable JSON page is NOT CHECKED, never a pass', function () {
  assert.equal(CW.checkDetailsJsonPage(null).status, 'NOT CHECKED');
});

/* --- 2. the renderer contains no markup sink --------------------------------- */

test('wire-details.js carries none of the markup-injection sinks', function () {
  var r = CW.checkDetailsScript(DETAIL_JS);
  assert.equal(r.status, 'PASS', JSON.stringify(r.problems));
});

test('each sink alone fails the renderer check', function () {
  ['el.innerHTML = x;', 'el.outerHTML;', 'node.insertAdjacentHTML("b", s);', 'document.write(s);',
   'var v = eval(s);'].forEach(function (bad) {
    var r = CW.checkDetailsScript('function x() { ' + bad + ' }');
    assert.equal(r.status, 'FAIL', bad);
  });
});

test('a renderer mentioning a sink in a comment fails too, the reader cannot tell', function () {
  var r = CW.checkDetailsScript('/* never assign to innerHTML */');
  assert.equal(r.status, 'FAIL');
});

test('an unreadable renderer is NOT CHECKED, never a pass', function () {
  assert.equal(CW.checkDetailsScript(null).status, 'NOT CHECKED');
});

/* --- 3. the two vulnerability row templates carry the toggle, first ----------- */

var TOGGLE_RE = /<button type="button" class="hl-dt" aria-expanded="false" hidden title="Show details"><span class="hl-dt__sr">Details<\/span><\/button>/;

test('wire/index.md carries the Details toggle in the nKEV and CVEs row templates', function () {
  var r = CW.checkDetailsPage(INDEX);
  assert.equal(r.status, 'PASS', JSON.stringify(r.problems));
});

test('a page missing one template\u2019s toggle fails', function () {
  var missing = INDEX.replace(TOGGLE_RE, '');
  assert.equal(CW.checkDetailsPage(missing).status, 'FAIL');
  var wrongDoc = INDEX.replace(TOGGLE_RE, function (m) { return m.replace('aria-expanded="false"', 'aria-expanded="true"'); });
  assert.equal(CW.checkDetailsPage(wrongDoc).status, 'FAIL');
});

test('a toggle without its accessible name fails', function () {
  var unnamed = INDEX.replace(TOGGLE_RE, '<button type="button" class="hl-dt" aria-expanded="false" hidden title="Show details"></button>');
  assert.notEqual(unnamed, INDEX, 'the mutation must apply');
  var r = CW.checkDetailsPage(unnamed);
  assert.equal(r.status, 'FAIL');
  assert.match(JSON.stringify(r.problems), /carries no Details toggle|expected 2/);
});

test('a toggle moved off the front of the row fails', function () {
  var moved = INDEX.replace(/(<button type="button" class="hl-dt"[^>]*>[\s\S]*?<\/button>)(<a class="hl-vuln__cve"[^>]*>[^<]*<\/a>)/, '$2$1');
  assert.notEqual(moved, INDEX, 'the mutation must apply');
  var r = CW.checkDetailsPage(moved);
  assert.equal(r.status, 'FAIL');
  assert.match(JSON.stringify(r.problems), /not directly before the CVE id link/);
});

test('a Details toggle on the headline row fails', function () {
  var bad = INDEX.replace(/(<div class="hl-wire__row"[^\n]*?)<\/div>/, '$1<button type="button" class="hl-dt" aria-expanded="false" hidden>Details</button></div>');
  assert.notEqual(bad, INDEX, 'the mutation must apply');
  var r = CW.checkDetailsPage(bad);
  assert.equal(r.status, 'FAIL');
  assert.match(JSON.stringify(r.problems), /headline row carries a Details toggle/);
});

test('a page whose headlines wrapper is gone fails', function () {
  // T-0548: the wrapper now carries a conditional id (the search anchor) between its class and data-title
  var bad = INDEX.replace('<div class="hl-wire__row"{% if h_id != "" %} id="{{ h_id | escape }}"{% endif %} data-title=', '<div data-title=');
  assert.equal(CW.checkDetailsPage(bad).status, 'FAIL');
});

test('an unreadable page is NOT CHECKED', function () {
  assert.equal(CW.checkDetailsPage(null).status, 'NOT CHECKED');
});

/* --- 4. the headlines filter item is the wrapper ------------------------------- */

test('the headlines grid names the wrapper as its filter item, not the anchor', function () {
  var r = CW.checkDetailsPage(INDEX);
  assert.match(JSON.stringify(r.problems), /^\[\]$/);
});

test('the old anchor filter item fails the structure check', function () {
  var bad = INDEX.replace('data-filter-item=".hl-wire__row"', 'data-filter-item=".hl-wire__item"');
  var r = CW.checkDetailsPage(bad);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /wrapper/);
});

test('a section losing its versioned data-details URL fails', function () {
  var bad = INDEX.replace('data-details="{{ \'/wire/details-cves.json\' | relative_url }}?v=', 'data-details="{{ \'/wire/details-cves.json\' | relative_url }}~v=');
  var r = CW.checkDetailsPage(bad);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /cves section carries no versioned/);
});

/* --- 5. the new exporter fields, through check() -------------------------------- */

test('a row holding the new fields in shape passes', function () {
  var r = CW.check(docWithVuln(vulnRow({ desc: 'The record description, up to 3000 characters.',
    cwe: ['CWE-20', 'CWE-79'], affected: ['Acme Widget: 1.0 up to and including 2.0'] })), null, NOW);
  var vulnWarns = r.vulnWarnings.join(' ');
  assert.equal(r.status, 'PASS');
  assert.ok(vulnWarns.indexOf('desc') === -1, vulnWarns);
  assert.ok(vulnWarns.indexOf('cwe') === -1, vulnWarns);
  assert.ok(vulnWarns.indexOf('affected') === -1, vulnWarns);
});

test('an old row carrying none of the new fields still checks clean', function () {
  var r = CW.check(docWithVuln(vulnRow({ desc: undefined, cwe: undefined, affected: undefined, cvss_vector: undefined })), null, NOW);
  assert.equal(r.status, 'PASS');
});

test('a desc over the cap warns', function () {
  var long = new Array(3002).join('x');   // 3001 characters, one past the cap
  var r = CW.check(docWithVuln(vulnRow({ desc: long })), null, NOW);
  assert.match(r.vulnWarnings.join(' '), /has desc .*3000 characters/);
});

test('a cwe list that is not CWE ids warns, one problem per bad entry', function () {
  var r = CW.check(docWithVuln(vulnRow({ cwe: ['CWE-79', 'garbage', 'NVD-CWE-Other'] })), null, NOW);
  var warns = r.vulnWarnings.join(' ');
  assert.match(warns, /has a cwe entry "garbage"/);
  assert.match(warns, /has a cwe entry "NVD-CWE-Other"/);
});

test('a cwe list over five warns', function () {
  var r = CW.check(docWithVuln(vulnRow({ cwe: ['CWE-1', 'CWE-2', 'CWE-3', 'CWE-4', 'CWE-5', 'CWE-6'] })), null, NOW);
  assert.match(r.vulnWarnings.join(' '), /6 cwe entries, over 5/);
});

test('an affected list over the caps warns', function () {
  var r = CW.check(docWithVuln(vulnRow({
    affected: ['a', 'b', 'c', 'd', 'e', 'f', 'g'] })), null, NOW);
  assert.match(r.vulnWarnings.join(' '), /7 affected entries, over 6/);
  var r2 = CW.check(docWithVuln(vulnRow({ affected: [new Array(162).join('y')] })), null, NOW);
  assert.match(r2.vulnWarnings.join(' '), /not text up to 160 characters/);
});

test('a malformed affected or cwe shape warns, never passes silently', function () {
  var r = CW.check(docWithVuln(vulnRow({ cwe: 'CWE-79' })), null, NOW);
  assert.match(r.vulnWarnings.join(' '), /cwe that is not a list/);
  var r2 = CW.check(docWithVuln(vulnRow({ affected: { a: 1 } })), null, NOW);
  assert.match(r2.vulnWarnings.join(' '), /affected that is not a list/);
});

test('the vector the score came from is now checked on nKEV rows too', function () {
  var bad = vulnRow({ cvss_vector: 'not a / vector' });
  var r = CW.check(docWithVuln(bad), null, NOW);
  assert.match(r.vulnWarnings.join(' '), /cvss_vector.*not empty or a CVSS vector/);
  var good = CW.check(docWithVuln(vulnRow()), null, NOW);
  assert.ok(good.vulnWarnings.join(' ').indexOf('cvss_vector') === -1);
});

test('a vector with no cvss warns, exactly as the CVEs tab always held', function () {
  var r = CW.check(docWithVuln(vulnRow({ cvss: '', cvss_version: '', severity: '', scored_by: '', cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' })), null, NOW);
  assert.match(r.vulnWarnings.join(' '), /a cvss_vector but no cvss/);
});

test('the Headlines row escapes every feed value (T-0532, Sol P1)', function () {
  var row = INDEX.split('\n').filter(function (l) { return l.indexOf('<div class="hl-wire__row"') === 0; })[0];
  assert.ok(row, 'the headline row is in wire/index.md');
  assert.deepEqual(CW.checkHeadlineRow(INDEX), []);
  ['{{ i.title | escape }}', '{{ i.source | escape }}', '{{ l | escape }}', '{{ href | escape }}'].forEach(function (needle) {
    var broken = INDEX.replace(needle, needle.replace(' | escape', ''));
    assert.notEqual(broken, INDEX, 'needle present: ' + needle);
    assert.equal(CW.checkHeadlineRow(broken).length, 1, 'unescaped ' + needle + ' is caught');
  });
});
