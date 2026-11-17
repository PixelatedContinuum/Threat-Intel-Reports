'use strict';

var test = require('node:test');
var assert = require('node:assert');
var CW = require('../lib/check-wire.js');

var NOW = Date.parse('2026-08-19T12:00:00Z');

function doc(over) {
  var d = {
    generated_at: '2026-08-19T11:50:00Z',
    window_days: 30,
    counts: { total: 2, research: 1, news: 1 },
    // Must name a label an item actually carries, or the topic check fires.
    topics: [{ label: 'security', count: 1, color: 3 }],
    label_colors: { security: 3 },
    items: [
      { title: 'A', url: 'https://x.test/a', source: 'AlienVault',
        date: '2026-08-18T10:00:00Z', kind: 'research', labels: [] },
      { title: 'B', url: 'https://x.test/b', source: 'BleepingComputer',
        date: '2026-08-17T10:00:00Z', kind: 'news', labels: ['security'] }
    ]
  };
  return Object.assign(d, over || {});
}

var SOURCES = { AlienVault: 'research', BleepingComputer: 'news' };

test('a well-formed file passes', function () {
  var r = CW.check(doc(), SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  assert.deepEqual(r.problems, []);
});

test('an absent file is NOT CHECKED, never PASS', function () {
  var r = CW.check(null, SOURCES, NOW);
  assert.equal(r.status, 'NOT CHECKED');
  assert.match(r.reason, /wire\.yml/);
});

/* An old local file is the trigger for the staleness question, not the answer.
   These four pin the answer to what origin holds, because reading local age
   alone accused a healthy generator on every session that opened a clone more
   than an hour old. */

test('a stale local file fails only when origin is stale too', function () {
  // 10 hours old against the 15-minute timer, and origin is no fresher: the
  // timer really has stopped, which is the case this gate exists for.
  var r = CW.check(doc({ generated_at: '2026-08-19T02:00:00Z' }), SOURCES, NOW,
    { generated_at: '2026-08-19T02:00:00Z' });
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /stale/i);
  assert.match(r.problems.join(' '), /LXC-102/);
});

test('a stale local file against a fresh origin is NOT CHECKED, never FAIL', function () {
  // The everyday case: the generator pushed forty times while this clone sat
  // untouched. Accusing LXC-102 here is the false alarm that spent the alarm.
  var r = CW.check(doc({ generated_at: '2026-08-19T02:00:00Z' }), SOURCES, NOW,
    { generated_at: '2026-08-19T11:45:00Z' });
  assert.equal(r.status, 'NOT CHECKED');
  assert.match(r.reason, /behind/i);
  assert.match(r.reason, /git pull/);
  // It must not leave the reader thinking the generator is implicated.
  assert.match(r.reason, /healthy/i);
});

test('a stale local file with origin unknown is NOT CHECKED, never PASS', function () {
  // Offline, or no remote. The distinguishing fact is unavailable, so there is
  // no verdict to give; the contract's third state is exactly this.
  var r = CW.check(doc({ generated_at: '2026-08-19T02:00:00Z' }), SOURCES, NOW, null);
  assert.equal(r.status, 'NOT CHECKED');
  assert.match(r.reason, /git fetch/);
});

test('a fresh local file never consults origin', function () {
  // Inside the limit nothing is in question, so a null remote must not turn a
  // healthy clone into NOT CHECKED.
  var r = CW.check(doc(), SOURCES, NOW, null);
  assert.equal(r.status, 'PASS');
});

test('a transient run of misses still passes', function () {
  // 45 minutes old: three missed 15-minute runs, still inside the one-hour
  // threshold, so a blip on the generator does not fail somebody else's publish.
  var r = CW.check(doc({ generated_at: '2026-08-19T11:15:00Z' }), SOURCES, NOW);
  assert.equal(r.status, 'PASS');
});

test('the limit is one hour: exactly an hour passes, a minute past it with origin equally stale fails', function () {
  // Pins STALE_HOURS (four missed 15-minute runs) so a later edit to the constant
  // has to change this test too.
  assert.equal(CW.STALE_HOURS, 1);
  var edge = CW.check(doc({ generated_at: '2026-08-19T11:00:00Z' }), SOURCES, NOW);
  assert.equal(edge.status, 'PASS');
  var over = CW.check(doc({ generated_at: '2026-08-19T10:59:00Z' }), SOURCES, NOW,
    { generated_at: '2026-08-19T10:59:00Z' });
  assert.equal(over.status, 'FAIL');
  assert.match(over.problems.join(' '), /1-hour limit/);
});

test('a file past the one-hour limit with origin equally stale fails', function () {
  // 75 minutes old: five missed 15-minute runs, and origin holds the same file.
  var r = CW.check(doc({ generated_at: '2026-08-19T10:45:00Z' }), SOURCES, NOW,
    { generated_at: '2026-08-19T10:45:00Z' });
  assert.equal(r.status, 'FAIL');
});

test('a description key fails, because that is the copyright limit', function () {
  var d = doc();
  d.items[0].description = 'The publisher blurb that must never ship.';
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /description/i);
});

test('a missing required field fails', function () {
  var d = doc();
  delete d.items[1].source;
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /source/);
});

test('an item outside the declared window fails', function () {
  var d = doc();
  d.items[1].date = '2026-06-01T10:00:00Z';
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /window/i);
});

test('counts disagreeing with the items fail', function () {
  var r = CW.check(doc({ counts: { total: 9, research: 1, news: 1 } }), SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /counts/i);
});

test('a non-https url fails', function () {
  var d = doc();
  d.items[0].url = 'http://x.test/a';
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /https/);
});

test('an unknown kind fails', function () {
  var d = doc();
  d.items[0].kind = 'opinion';
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /kind/i);
});

test('a duplicate title fails', function () {
  var d = doc();
  d.items[1].title = 'A';
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /duplicate/i);
});

test('an unclassified source warns but does not fail', function () {
  var d = doc();
  d.items[1].source = 'Brand New Blog';
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  assert.deepEqual(r.warnings, ['Brand New Blog']);
});

test('an empty item list is NOT CHECKED, not a silent pass', function () {
  var r = CW.check(doc({ items: [], counts: { total: 0, research: 0, news: 0 } }),
                   SOURCES, NOW);
  assert.equal(r.status, 'NOT CHECKED');
  assert.match(r.reason, /no items/i);
});

test('a topic chip naming a label no item carries fails', function () {
  // A chip that selects nothing is a dead control, and the page renders chips
  // straight from this list without checking them against the items.
  var d = doc({ topics: [{ label: 'nonexistent', count: 3, color: 1 }],
                label_colors: { nonexistent: 1 } });
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /topic chip/i);
});

test('a topic colour outside the CSS palette fails', function () {
  // Renders a chip with no colour variable: it still filters, it just goes
  // grey while every sibling is coloured. Silent visual regression.
  var d = doc({ topics: [{ label: 'security', count: 1, color: 99 }],
                label_colors: { security: 99 } });
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /palette/i);
});

test('a missing topic colour fails', function () {
  var d = doc({ topics: [{ label: 'security', count: 1 }], label_colors: {} });
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /palette/i);
});

test('a tag coloured differently from its chip fails', function () {
  var d = doc({ topics: [{ label: 'security', count: 1, color: 3 }],
                label_colors: { security: 7 } });
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /would not match its chip/i);
});

test('a label_colors entry that is not a chip topic is fine', function () {
  // 521 of 532 displayed labels are not topics. Colouring only the topics is
  // what made the first build look flat, so extra entries are expected.
  var d = doc({ topics: [{ label: 'security', count: 1, color: 3 }],
                label_colors: { security: 3, 'some-other-label': 5 } });
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'PASS');
});

test('a label_colors value outside the palette fails', function () {
  var d = doc({ label_colors: { security: 3, other: 77 } });
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /palette/i);
});

test('a displayed label with no colour fails', function () {
  // Renders grey among coloured siblings: the flatness defect returning.
  var d = doc();
  d.items[0].labels = ['security', 'unmapped-label'];
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /no colour in label_colors/i);
});

test('an undrawn fourth label needs no colour', function () {
  // The page draws three tags per item; the rest are never rendered.
  var d = doc();
  d.items[0].labels = ['security', 'security', 'security', 'never-drawn'];
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'PASS');
});

/* ---- checkPage: the day is derived exactly once -------------------------

   The heading above a row and the day filter that narrows to it both need the
   same answer to "which day is this row", and _config.yml sets no `timezone:`,
   so a second derivation would genuinely disagree near midnight rather than
   merely duplicating work. */


test('an unreadable page is NOT CHECKED, never a pass', function () {
  var r = CW.checkPage(null);
  assert.equal(r.status, 'NOT CHECKED');
  assert.match(r.reason, /nothing was verified/i);
});

test('re-deriving the day on the row is caught as a second definition', function () {
  // Internally consistent today, and still two definitions of one rule.
  var bad = readReal('wire/index.md').replace('data-day="{{ day }}"',
    'data-day="{{ i.date | date: \'%Y-%m-%d\' }}"');
  var r = CW.checkPage(bad, realIncludes());
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /re-derives the day/i);
});

test('dropping data-day entirely is caught', function () {
  // The filter would then match nothing and the page would show everything,
  // which reads as a working control that quietly ignores the reader.
  var bad = readReal('wire/index.md').replace(' data-day="{{ day }}"', '');
  var r = CW.checkPage(bad, realIncludes());
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /no data-day/i);
});

test('losing the day assign is caught', function () {
  var bad = readReal('wire/index.md').replace('{%- assign day = i.date | date: "%Y-%m-%d" -%}', '');
  var r = CW.checkPage(bad, realIncludes());
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /share one derivation/i);
});

test('grouping headings on something other than `day` is caught', function () {
  var bad = readReal('wire/index.md').replace('{%- if day != current_day -%}',
    '{%- if i.date != current_day -%}');
  var r = CW.checkPage(bad, realIncludes());
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /no longer grouped on the `day` variable/i);
});

test('a missing cache-bust on the filter script is caught', function () {
  // New markup against a cached old script is invisible on a fresh browser and
  // total on a returning one. It has already happened here once.
  var bad = readReal('wire/index.md').replace(/(listing-filter\.js[^"]*)\?v=\d+/, '$1');
  var r = CW.checkPage(bad, realIncludes());
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /cache-bust/i);
});

/* ---- The nKEVs legend (T-0468.1) ----

   The explanatory text moved into a side legend. These pin the three guarantees that
   now live in the template's structure: the attribution stays above the filter bar,
   the samples are not countable or interactive, and the legend is printed twice from
   one capture and never inside the grid. Each test breaks one and expects the gate to
   name it. */

function realIncludes() {
  var fs = require('node:fs');
  var path = require('node:path');
  var dir = path.join(__dirname, '..', '..', '..', '_includes');
  var out = {};
  fs.readdirSync(dir).filter(function (n) { return /^wire-.*\.html$/.test(n); }).forEach(function (n) {
    out[n] = fs.readFileSync(path.join(dir, n), 'utf8');
  });
  return out;
}

test('the real wire/index.md passes the page gate (the legend and the day derivation)', function () {
  var fs = require('node:fs');
  var path = require('node:path');
  var real = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'wire', 'index.md'), 'utf8');
  var inc = realIncludes();
  var r = CW.checkPage(real, inc);
  assert.equal(r.status, 'PASS', r.problems.join(' | '));
});

/* ---- The tab nav, G3 (r2): the three tab counts print outside every section ----

   The counts sit in hl-wtabs__nav before the first <section>, so the section-scoped
   checkers never read them and r2 passed a hostile count straight to the page. The
   rule is the row templates': every output outside the sections is escaped, numeric,
   or one of the three tab counts - printed only while its assign still forces the
   value to a number. */
test('a hostile print in the tab nav region is seen; the same print inside a section is that section checker\'s, not this one\'s', function () {
  // The un-stripped scan is region-scoped: a raw data print inside a section is not this
  // checker's finding (the section checkers own it), so checkTabNav alone must stay silent.
  assert.equal(CW.checkTabNav(readReal('wire/index.md')).join(' '), '');
  // strip only complete section spans: a <section> with no close leaves its whole body in
  // the checked region instead of silently widening to EOF
  var dangling = readReal('wire/index.md').replace('<section id="headlines" class="hl-wtabs__sec" data-filter-scope>', '');
  assert.match(CW.checkTabNav(dangling).join(' '), /tab nav region .* without escape/);
});

test('the real tab nav: one un-forcing mutation per count, and a raw re-derivation, each fails the page gate (control: the real page passes)', function () {
  var page = readReal('wire/index.md');
  var inc = realIncludes();
  assert.equal(CW.checkPage(page, inc).status, 'PASS');
  var mutants = [
    ['{%- assign n_vulns = wire.vulns_counts.total | default: 0 | plus: 0 -%}',
     '{%- assign n_vulns = wire.vulns_counts.total | default: 0 -%}',
     /n_vulns .* is no longer forced to a number in its assign/],
    ['{%- assign n_cves = wire.cves_counts.total | default: 0 | plus: 0 -%}',
     '{%- assign n_cves = wire.cves_counts.total | default: 0 -%}',
     /n_cves .* is no longer forced to a number in its assign/],
    ['{%- assign n_headlines = wire.counts.research | plus: wire.counts.news -%}',
     '{%- assign n_headlines = wire.counts.research -%}',
     /n_headlines .* is no longer forced to a number in its assign/],
    ['<span class="hl-wtabs__n">{{ n_vulns }}</span>',
     '<span class="hl-wtabs__n">{{ wire.vulns_counts.total }}</span>',
     /tab nav region .* prints \{\{ wire\.vulns_counts\.total \}\} without escape/]
  ];
  mutants.forEach(function (m, i) {
    assert.ok(page.indexOf(m[0]) > -1, 'tab nav mutation ' + i + ' anchor missing: ' + m[0]);
    var r = CW.checkPage(page.replace(m[0], m[1]), inc);
    assert.equal(r.status, 'FAIL', 'tab nav mutation ' + i + ': ' + m[0]);
    assert.match(r.problems.join(' | '), m[2], 'mutation ' + i + ' wrong problem');
  });
});

/* ---- The Vulnerabilities tab (T-0396) ----

   Everything about `vulns:` is a WARNING, never a FAIL, because pages.yml drops
   the whole wire.yml on any non-stale FAIL and the headlines must never depend
   on the VulnCheck read. A description key is the one exception. */

function vrow(over) {
  return Object.assign({ cve: 'CVE-2026-1111', added: '2026-08-18', vendor: 'Acme',
    product: 'Widget', cisa_added: '', evidence: '', older: false }, over || {});
}

function vdoc(rows, over) {
  rows = rows || [vrow(), vrow({ cve: 'CVE-2016-2222', cisa_added: '2026-08-18', older: true })];
  var d = doc({
    vulns_status: 'ok',
    vulns_generated_at: '2026-08-19T10:00:00Z',
    vulns_counts: {
      total: rows.length,
      cisa: rows.filter(function (r) { return r.cisa_added; }).length,
      older: rows.filter(function (r) { return r.older === true; }).length
    },
    vulns: rows
  });
  return Object.assign(d, over || {});
}

test('a well-formed vulns section passes with no vuln warnings (control)', function () {
  var r = CW.check(vdoc(), SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  assert.deepEqual(r.vulnWarnings, []);
  assert.equal(r.counts.vulns, 2);
});

test('a malformed vulns row is a warning, and the headlines still PASS', function () {
  var r = CW.check(vdoc([vrow({ cve: 'not-a-cve', added: '18 Aug', older: 'yes',
    cisa_added: 'soon' })]), SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  var w = r.vulnWarnings.join(' | ');
  assert.match(w, /CVE shape/);
  assert.match(w, /added day/);
  assert.match(w, /non-boolean older/);
  assert.match(w, /cisa_added/);
});

test('a vulns description key is the one vulns FAIL', function () {
  var r = CW.check(vdoc([vrow({ description: 'VulnCheck prose.' })]), SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /description/);
  // and it is not a stale: problem, so pages.yml drops the file
  assert.doesNotMatch(r.problems.join(' '), /^stale:/);
});

test('stale and unavailable statuses warn and still PASS', function () {
  ['stale', 'unavailable', 'bogus'].forEach(function (st) {
    var rows = st === 'stale' ? undefined : [];
    var r = CW.check(vdoc(rows, { vulns_status: st }), SOURCES, NOW);
    assert.equal(r.status, 'PASS', st);
    assert.match(r.vulnWarnings.join(' '), new RegExp(st === 'bogus' ? 'not ok' : st), st);
  });
});

test('vulns data over a day old warns, and under a day does not', function () {
  var old = CW.check(vdoc(undefined, { vulns_generated_at: '2026-08-18T10:00:00Z' }), SOURCES, NOW);
  assert.equal(old.status, 'PASS');
  assert.match(old.vulnWarnings.join(' '), /hours old/);
  var fresh = CW.check(vdoc(undefined, { vulns_generated_at: '2026-08-18T13:00:00Z' }), SOURCES, NOW);
  assert.doesNotMatch(fresh.vulnWarnings.join(' '), /hours old/);
});

test('a file from before the tab warns once and passes', function () {
  var r = CW.check(doc(), SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  assert.match(r.vulnWarnings.join(' '), /no vulns section/);
});

test('vuln digest items count as their own kind and are not unclassified sources', function () {
  var d = vdoc();
  d.items.push({ title: '2 CVEs added to VulnCheck KEV on 18 August: Acme',
    url: 'https://the-hunters-ledger.com/wire/#vulns-2026-08-18', source: 'VulnCheck KEV',
    date: '2026-08-18T12:00:00Z', kind: 'vuln', labels: [] });
  d.counts = { total: 3, research: 1, news: 1, vuln: 1 };
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  assert.deepEqual(r.warnings, []);
  // control: the same counts without the vuln key disagree
  d.counts = { total: 3, research: 1, news: 2 };
  assert.equal(CW.check(d, SOURCES, NOW).status, 'FAIL');
});

test('vulns_counts disagreeing with the rows warns', function () {
  var r = CW.check(vdoc(undefined, { vulns_counts: { total: 9, cisa: 0, older: 0 } }), SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  assert.match(r.vulnWarnings.join(' '), /vulns_counts disagree/);
});

/* ---- Severity per CVE (T-0399) ---- */

function scored(over) {
  return vrow(Object.assign({ cvss: '9.8', cvss_version: '3.1', severity: 'critical', scored_by: 'CNA' }, over || {}));
}

function sdoc(rows) {
  var d = vdoc(rows);
  ['critical', 'high', 'medium', 'low'].forEach(function (k) {
    d.vulns_counts[k] = rows.filter(function (r) { return r.severity === k; }).length;
  });
  d.vulns_counts.unscored = rows.filter(function (r) { return !r.severity; }).length;
  return d;
}

var UNSCORED = { cvss: '', cvss_version: '', severity: '', scored_by: '' };

test('scored and unscored rows pass with no vuln warnings (control)', function () {
  var r = CW.check(sdoc([scored(), scored({ cve: 'CVE-2026-3333', cvss: '5.0', severity: 'medium',
    scored_by: 'NVD', cvss_version: '4.0' }), vrow(Object.assign({ cve: 'CVE-2026-4444' }, UNSCORED))]), SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  assert.deepEqual(r.vulnWarnings, []);
});

test('a bad score warns per field, and the headlines still PASS', function () {
  var r = CW.check(sdoc([
    scored({ cvss: '11' }),
    scored({ cve: 'CVE-2026-0002', severity: 'none' }),
    scored({ cve: 'CVE-2026-0003', cvss_version: '5.0' }),
    scored({ cve: 'CVE-2026-0004', scored_by: 'me' }),
    scored({ cve: 'CVE-2026-0005', severity: '' }),
    vrow({ cve: 'CVE-2026-0006', cvss: '7.0' })
  ]), SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  var w = r.vulnWarnings.join(' | ');
  assert.match(w, /cvss "11"/);
  assert.match(w, /severity "none"/);
  assert.match(w, /cvss_version "5.0"/);
  assert.match(w, /scored_by "me"/);
  assert.match(w, /partial score/);
  assert.match(w, /only some score fields/);
});

test('severity counts disagreeing with the rows warn; a pre-T-0399 file is not held to them', function () {
  var d = sdoc([scored(), vrow(Object.assign({ cve: 'CVE-2026-4444' }, UNSCORED))]);
  d.vulns_counts.critical = 5;
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  assert.match(r.vulnWarnings.join(' '), /severity disagrees with the rows on critical/);
  // control: the T-0396 fixture has no score fields and no per-band counts
  assert.deepEqual(CW.check(vdoc(), SOURCES, NOW).vulnWarnings, []);
});

/* ---- The row's pointers (T-0407) ---- */

function pointed(over) {
  return vrow(Object.assign({
    reports: [{ url: 'https://patchstack.com/database/wordpress/plugin/x', host: 'patchstack.com' }],
    reports_more: 2, stories: 1, et_sids: [2060001], nuclei: 'http/cves/2026/CVE-2026-1111.yaml'
  }, over || {}));
}

function pdoc(rows) {
  var d = vdoc(rows);
  var c = d.vulns_counts;
  c.reported = rows.filter(function (r) { return (r.reports || []).length; }).length;
  c.stories = rows.filter(function (r) { return r.stories > 0; }).length;
  c.et = rows.filter(function (r) { return (r.et_sids || []).length; }).length;
  c.nuclei = rows.filter(function (r) { return r.nuclei; }).length;
  c.detect = rows.filter(function (r) { return (r.et_sids || []).length || r.nuclei; }).length;
  return d;
}

test('rows with and without pointers pass with no vuln warnings (control)', function () {
  var r = CW.check(pdoc([pointed(), vrow({ cve: 'CVE-2026-4444', reports: [], reports_more: 0,
    stories: 0, et_sids: [], nuclei: '' })]), SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  assert.deepEqual(r.vulnWarnings, []);
});

test('a bad pointer warns per field, and the headlines still PASS', function () {
  var r = CW.check(pdoc([
    pointed({ cve: 'CVE-2026-0001', reports: [{ url: 'javascript:alert(1)', host: 'x' }] }),
    pointed({ cve: 'CVE-2026-0002', reports: [{ url: 'https://x.test/a"b', host: 'x.test' }] }),
    pointed({ cve: 'CVE-2026-0003', reports: [1, 2, 3, 4].map(function (n) {
      return { url: 'https://x.test/' + n, host: 'x.test' }; }) }),
    pointed({ cve: 'CVE-2026-0004', stories: -1 }),
    pointed({ cve: 'CVE-2026-0005', et_sids: ['2060001'] }),
    pointed({ cve: 'CVE-2026-0006', nuclei: '../../etc/passwd.yaml' }),
    pointed({ cve: 'CVE-2026-0007', reports: 'https://x.test/' }),
    pointed({ cve: 'CVE-2026-0008', reports: [{ url: 'https://x.test/', host: '' }] }),
    pointed({ cve: 'CVE-2026-0009', reports: [{ url: 'https://x.test/a\u0000b', host: 'x.test' }] }),
    pointed({ cve: 'CVE-2026-0010', reports: [{ url: 'https://x.test/a\u007fb', host: 'x.test' }] })
  ]), SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  var w = r.vulnWarnings.join('\n');
  [/0001\).*not a plain https link/, /0002\).*not a plain https link/, /0003\).*over 3/,
   /0004\).*stories -1, not a count/, /0005\).*not a list of SIDs/, /0006\).*not a template path/,
   /0007\).*reports that are not a list/, /0008\).*has no host/,
   /0009\).*not a plain https link/, /0010\).*not a plain https link/].forEach(function (re) {
    assert.match(w, re);
  });
});

test('pointer counts disagreeing with the rows warn; a pre-T-0407 file is not held to them', function () {
  var d = pdoc([pointed(), vrow({ cve: 'CVE-2026-4444' })]);
  d.vulns_counts.nuclei = 7;
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  assert.match(r.vulnWarnings.join(' '), /pointers disagree with the rows on nuclei/);
  // control: the T-0396 fixture carries no pointers and no pointer counts
  assert.deepEqual(CW.check(vdoc(), SOURCES, NOW).vulnWarnings, []);
});

/* ---- CISA Sigma and Snort 3 community rules (T-0496) ---- */

function ruled(over) {
  return pointed(Object.assign({ cisa_sigma: ['CISA_SIGMA_261429_CVE_2026_109618-109619_PHP2Shell_TLP_CLEAR.yaml'],
    snort3_sids: [58800, 58801] }, over || {}));
}

// Counts as the exporter declares them: every row carries both fields, detect is any of the four.
function rdoc(rows) {
  var d = pdoc(rows);
  var c = d.vulns_counts;
  c.cisa_sigma = rows.filter(function (r) { return (r.cisa_sigma || []).length; }).length;
  c.snort3 = rows.filter(function (r) { return (r.snort3_sids || []).length; }).length;
  c.detect = rows.filter(function (r) {
    return (r.et_sids || []).length || r.nuclei || (r.cisa_sigma || []).length || (r.snort3_sids || []).length;
  }).length;
  return d;
}

function bare(over) {
  return vrow(Object.assign({ cve: 'CVE-2026-4444', reports: [], reports_more: 0, stories: 0,
    et_sids: [], nuclei: '', cisa_sigma: [], snort3_sids: [] }, over || {}));
}

test('rows with all four rule sources, one source and none pass with no vuln warnings (control)', function () {
  var r = CW.check(rdoc([ruled(), ruled({ cve: 'CVE-2026-2222', et_sids: [], nuclei: '', cisa_sigma: [] }),
    bare()]), SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  assert.deepEqual(r.vulnWarnings, []);
});

test('a bad cisa_sigma or snort3_sids warns per field, and the headlines still PASS', function () {
  var r = CW.check(rdoc([
    ruled({ cve: 'CVE-2026-0001', cisa_sigma: 'a.yaml' }),
    ruled({ cve: 'CVE-2026-0002', cisa_sigma: ['../x.yaml'] }),
    ruled({ cve: 'CVE-2026-0003', cisa_sigma: ['/abs.yaml'] }),
    ruled({ cve: 'CVE-2026-0004', cisa_sigma: ['has space.yaml'] }),
    ruled({ cve: 'CVE-2026-0005', cisa_sigma: ['rule.txt'] }),
    ruled({ cve: 'CVE-2026-0006', cisa_sigma: [7] }),
    ruled({ cve: 'CVE-2026-0007', snort3_sids: ['58800'] }),
    ruled({ cve: 'CVE-2026-0008', snort3_sids: [0] }),
    ruled({ cve: 'CVE-2026-0009', snort3_sids: [58801, 58800] }),
    ruled({ cve: 'CVE-2026-0010', snort3_sids: [58800, 58800] }),
    ruled({ cve: 'CVE-2026-0011', snort3_sids: 58800 }),
    ruled({ cve: 'CVE-2026-0012', snort3_sids: [1.5] }),
    ruled({ cve: 'CVE-2026-0013', cisa_sigma: ['a"b.yaml'] }),
    ruled({ cve: 'CVE-2026-0014', cisa_sigma: [new Array(202).join('a') + '.yaml'] }),
    ruled({ cve: 'CVE-2026-0015', cisa_sigma: [['a.yaml']] })   // a nested list stringifies to a valid path
  ]), SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  var w = r.vulnWarnings.join('\n');
  [/0001\).*cisa_sigma.*not a list of rule file paths/, /0002\).*cisa_sigma/, /0003\).*cisa_sigma/,
   /0004\).*cisa_sigma/, /0005\).*cisa_sigma/, /0006\).*cisa_sigma/,
   /0007\).*snort3_sids.*not a sorted list of distinct SIDs/, /0008\).*snort3_sids/, /0009\).*snort3_sids/,
   /0010\).*snort3_sids/, /0011\).*snort3_sids/, /0012\).*snort3_sids/, /0013\).*cisa_sigma/, /0014\).*cisa_sigma/, /0015\).*cisa_sigma/].forEach(function (re) {
    assert.match(w, re);
  });
});

test('the CISA Sigma and Snort 3 counts are held to the rows; detect counts any of the four', function () {
  var rows = [ruled(), bare({ cve: 'CVE-2026-2222', snort3_sids: [60000] }), bare()];
  var d = rdoc(rows);
  assert.deepEqual(CW.check(d, SOURCES, NOW).vulnWarnings, []);   // control: declared as the rows are
  d = rdoc(rows); d.vulns_counts.cisa_sigma = 5;
  assert.match(CW.check(d, SOURCES, NOW).vulnWarnings.join(' '), /cisa_sigma disagrees with the rows: declared 5, actual 1/);
  d = rdoc(rows); d.vulns_counts.snort3 = 0;
  assert.match(CW.check(d, SOURCES, NOW).vulnWarnings.join(' '), /snort3 disagrees with the rows: declared 0, actual 2/);
  // detect left at the pre-T-0496 meaning (ET or Nuclei only) while a row has only a Snort rule
  d = rdoc(rows); d.vulns_counts.detect = 1;
  assert.match(CW.check(d, SOURCES, NOW).vulnWarnings.join(' '), /pointers disagree with the rows on detect/);
});

test('rows that carry the new rules while the count is missing, or a row without the fields, warn', function () {
  var rows = [ruled(), bare({ snort3_sids: [60000] })];
  var d = rdoc(rows); delete d.vulns_counts.snort3;
  assert.match(CW.check(d, SOURCES, NOW).vulnWarnings.join(' '), /2 snort3 rule rows but vulns_counts has no snort3/);
  d = rdoc(rows); delete d.vulns_counts.cisa_sigma;
  assert.match(CW.check(d, SOURCES, NOW).vulnWarnings.join(' '), /1 cisa_sigma rule rows but vulns_counts has no cisa_sigma/);
  // declaring only the snort3 count is declaring: the rows must carry both fields
  var lacking = ruled({ cve: 'CVE-2026-3334' }); delete lacking.cisa_sigma;
  d = rdoc([ruled(), lacking]); delete d.vulns_counts.cisa_sigma;
  assert.match(CW.check(d, SOURCES, NOW).vulnWarnings.join(' '), /1 of 2 rows lack cisa_sigma or snort3_sids/);
  // a file that declares the counts holds every row to carrying both fields
  var missing = ruled({ cve: 'CVE-2026-3333' }); delete missing.snort3_sids;
  d = rdoc([ruled(), missing]);
  assert.match(CW.check(d, SOURCES, NOW).vulnWarnings.join(' '), /1 of 2 rows lack cisa_sigma or snort3_sids/);
});

test('a file written before T-0496 is not held to the new fields or counts (control)', function () {
  var r = CW.check(pdoc([pointed(), vrow({ cve: 'CVE-2026-4444' })]), SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  assert.deepEqual(r.vulnWarnings, []);
  assert.equal(r.vulnWarnings.length, 0);
});

/* ---- The nKEV fields: disclosure day, gap and EPSS (T-0468) ---- */

function nk(over) {
  return vrow(Object.assign({
    cvss: '9.8', cvss_version: '3.1', severity: 'critical', scored_by: 'NVD',
    added: '2026-10-13', disclosed: '2026-10-01', gap: 12,
    epss: '0.45200', epss_pct: '0.97100', epss_date: '2026-10-27', epss_pre: '0.01200', epss_max: '0.45200',
    epss_spark: '0.0,20.0 62.1,12.0 120.0,0.0', ratio_now: '2.2', ratio_pre: '81.7'
  }, over || {}));
}

function ndoc(rows) {
  var d = vdoc(rows);
  var c = d.vulns_counts;
  c.disclosed = rows.filter(function (r) { return r.disclosed; }).length;
  c.prenvd = rows.filter(function (r) { return typeof r.gap === 'number' && r.gap < 0; }).length;
  c.epss = rows.filter(function (r) { return r.epss; }).length;
  c.epss_pre = rows.filter(function (r) { return r.epss_pre; }).length;
  return d;
}

test('rows with and without the nKEV fields pass with no vuln warnings (control)', function () {
  var r = CW.check(ndoc([nk(), nk({ cve: 'CVE-2026-2222', added: '2026-10-03', disclosed: '2026-10-09', gap: -6 }),
    nk({ cve: 'CVE-2026-5555', epss_xmodel: 'pre,spark' }), nk({ cve: 'CVE-2026-6666', epss_xmodel: 'spark' }),
    nk({ cve: 'CVE-2026-3333', disclosed: '', gap: '', epss: '', epss_pct: '', epss_date: '', epss_pre: '',
      epss_max: '', epss_spark: '', ratio_now: '', ratio_pre: '' }),
    vrow({ cve: 'CVE-2026-4444' })]), SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  assert.deepEqual(r.vulnWarnings, []);
});

test('a bad nKEV field warns per field, and the headlines still PASS', function () {
  var r = CW.check(ndoc([
    nk({ cve: 'CVE-2026-0001', disclosed: '2026-13-40' }),
    nk({ cve: 'CVE-2026-0002', gap: '12' }),
    nk({ cve: 'CVE-2026-0003', gap: 11 }),
    nk({ cve: 'CVE-2026-0004', disclosed: '', gap: 12 }),
    nk({ cve: 'CVE-2026-0005', epss: '1.5' }),
    nk({ cve: 'CVE-2026-0006', epss_pct: '-0.1' }),
    nk({ cve: 'CVE-2026-0007', epss_spark: '1,1" onload="x' }),
    nk({ cve: 'CVE-2026-0008', epss_spark: '1,1 2,2 <script>' }),
    nk({ cve: 'CVE-2026-0009', ratio_now: 'high' }),
    nk({ cve: 'CVE-2026-0010', ratio_now: '9.9' }),
    nk({ cve: 'CVE-2026-0011', epss: '', ratio_now: '2.2' }),
    nk({ cve: 'CVE-2026-0012', epss_date: 'yesterday' }),
    nk({ cve: 'CVE-2026-0013', epss_spark: new Array(32).join('1,1 ').trim() }),
    nk({ cve: 'CVE-2026-0014', epss_xmodel: 'all' }),
    nk({ cve: 'CVE-2026-0015', epss: '', epss_pct: '', epss_xmodel: 'spark', ratio_now: '' }),
    nk({ cve: 'CVE-2026-0016', epss_pre: '', ratio_pre: '', epss_xmodel: 'pre' })
  ]), SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  var w = r.vulnWarnings.join('\n');
  [/0001\).*disclosed "2026-13-40"/, /0002\).*gap "12", not empty or an integer/,
   /0003\).*gap 11 but added minus disclosed is 12 days/, /0004\).*gap but no disclosed|0004\).*carries/,
   /0005\).*epss "1.5"/, /0006\).*epss_pct "-0.1"/, /0007\).*epss_spark that is not a points list/,
   /0008\).*epss_spark that is not a points list/, /0009\).*ratio_now "high"/,
   /0010\).*ratio_now 9.9 but \(CVSS \/ 10\) \/ epss is 2.2/, /0011\).*ratio_now 2.2 but no CVSS or epss/,
   /0012\).*epss_date "yesterday"/, /0013\).*epss_spark with over 30 points/,
   /0014\).*epss_xmodel "all"/, /0015\).*epss_xmodel spark but no epss/, /0016\).*epss_xmodel pre but no epss_pre/].forEach(function (re) { assert.match(w, re); });
});

test('a control character in any field of a row is warned on, never passed silently (T-0407 F1, applied to the new fields; the exporter strips them at source in _q)', function () {
  var r = CW.check(ndoc([
    nk({ cve: 'CVE-2026-0001', epss_spark: '1,1\u0000 2,2' }),
    nk({ cve: 'CVE-2026-0002', disclosed: '2026-10-01\u000a' }),
    nk({ cve: 'CVE-2026-0003', vendor: 'Acme\u007f' }),
    nk({ cve: 'CVE-2026-0004', ratio_pre: '8\u00851.7' })
  ]), SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  var w = r.vulnWarnings.join('\n');
  [/0001\).*control character in epss_spark/, /0002\).*control character in disclosed/,
   /0003\).*control character in vendor/, /0004\).*control character in ratio_pre/].forEach(function (re) {
    assert.match(w, re);
  });
  // control: the same rows without the control characters raise none
  assert.deepEqual(CW.check(ndoc([nk()]), SOURCES, NOW).vulnWarnings, []);
});

test('nKEV counts disagreeing with the rows warn; a pre-T-0468 file is not held to them', function () {
  var d = ndoc([nk(), nk({ cve: 'CVE-2026-2222', added: '2026-10-03', disclosed: '2026-10-09', gap: -6 })]);
  d.vulns_counts.prenvd = 5;
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  assert.match(r.vulnWarnings.join(' '), /nKEV fields disagree with the rows on prenvd/);
  // control: a file without the counts, and rows without the fields, pass clean
  assert.deepEqual(CW.check(vdoc(), SOURCES, NOW).vulnWarnings, []);
  var e = ndoc([nk()]);
  assert.deepEqual(CW.check(e, SOURCES, NOW).vulnWarnings, []);
});

test('the one-of-two rule: disclosed without gap warns', function () {
  var row = nk({ cve: 'CVE-2026-0001' });
  delete row.gap;
  var r = CW.check(ndoc([row]), SOURCES, NOW);
  assert.match(r.vulnWarnings.join(' '), /carries only one of disclosed and gap/);
});

/* ---- The cve.now fields and the CVEs tab (T-0522) ----

   Same policy as the nKEVs: everything is a WARNING so the headlines never depend on the cve.now
   read. The two FAILs are body text on a CVEs row (cve.now's model-written summaries are never
   published) and, on the page side, the structure checks below. */

function cn(over) {
  return vrow(Object.assign({
    cvss: '9.8', cvss_version: '3.1', severity: 'critical', scored_by: 'NVD',
    ssvc_expl: 'poc', ssvc_auto: 'yes', ssvc_impact: 'total',
    msf: ['modules/exploits/linux/http/rconfig_ajaxarchivefiles_rce.rb'], edb: ['48208', '48223'],
    fixed: '3.9.5', aliases: ['GHSA-635P-78XG-J6W3', 'EUVD-2026-113740'], kev_due: '2026-11-22'
  }, over || {}));
}

test('nKEV rows with, without and with a partial set of the cve.now fields pass clean (control)', function () {
  var r = CW.check(vdoc([cn(), vrow({ cve: 'CVE-2021-44228' }),
    cn({ cve: 'CVE-2026-3333', msf: [], edb: [], aliases: [], fixed: '', kev_due: '' }),
    cn({ cve: 'CVE-2026-4444', ssvc_expl: 'none', ssvc_auto: 'no', ssvc_impact: 'partial', fixed: 'v5.000.0000000.15' })]), SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  assert.deepEqual(r.vulnWarnings, []);
});

test('a fixed version may be a comma-separated list of versions, one per branch (the real exporter output)', function () {
  var r = CW.check(vdoc([cn({ cve: 'CVE-2026-3001', fixed: '10.4.3, 10.2.7' }),
    cn({ cve: 'CVE-2026-3002', fixed: '10.0.14393.9612, 10.0.17763.9376, 10.0.20348.5761' }),
    cn({ cve: 'CVE-2026-3003', fixed: '24.4R2-S5-EVO, 25.2R2-S2-EVO' }), cn({ cve: 'CVE-2026-3004', fixed: '16.114.26101123,16.0.14334.20974' }),
    cn({ cve: 'CVE-2026-3005', fixed: 'v5.000.0000000.15' })]), SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  assert.deepEqual(r.vulnWarnings, []);
  // the same on the CVEs tab
  assert.deepEqual(CW.check(cvdoc([cvrow({ fixed: '10.4.3, 10.2.7' })]), SOURCES, NOW).cveWarnings, []);
});

test('a bad cve.now field warns per field, and the headlines still PASS', function () {
  var r = CW.check(vdoc([
    cn({ cve: 'CVE-2026-0001', ssvc_expl: 'high' }),
    cn({ cve: 'CVE-2026-0002', ssvc_auto: 'maybe' }),
    cn({ cve: 'CVE-2026-0003', ssvc_impact: 'huge' }),
    cn({ cve: 'CVE-2026-0004', msf: ['modules/../../etc/passwd.rb'] }),
    cn({ cve: 'CVE-2026-0005', msf: ['https://evil.test/x.rb'] }),
    cn({ cve: 'CVE-2026-0006', msf: 'modules/a.rb' }),
    cn({ cve: 'CVE-2026-0007', edb: ['48208"><script>'] }),
    cn({ cve: 'CVE-2026-0010', fixed: 'log4j-core*' }),
    cn({ cve: 'CVE-2026-0011', fixed: 'see advisory' }),
    cn({ cve: 'CVE-2026-0016', fixed: '10.4.3, log4j-core*' }),
    cn({ cve: 'CVE-2026-0017', fixed: '10.4.3,, 10.2.7' }),
    cn({ cve: 'CVE-2026-0018', fixed: '10.4.3, 10.2.7,' }),
    cn({ cve: 'CVE-2026-0019', fixed: '1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0, 2.1, 2.2, 2.3' }),
    cn({ cve: 'CVE-2026-0020', fixed: '10.4.3, see advisory' }),
    cn({ cve: 'CVE-2026-0012', aliases: ['PYSEC-2026-1640'] }),
    cn({ cve: 'CVE-2026-0013', aliases: ['GHSA-xxxx-yyyy-zzzz"onmouseover="x'] }),
    cn({ cve: 'CVE-2026-0014', kev_due: 'next week' }),
    cn({ cve: 'CVE-2026-0015', edb: new Array(30).join('1,').split(',').slice(0, 29) })
  ]), SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  var w = r.vulnWarnings.join('\n');
  [/0001\).*ssvc_expl "high"/, /0002\).*ssvc_auto "maybe"/, /0003\).*ssvc_impact "huge"/,
   /0004\).*msf entry "modules\/\.\.\/\.\.\/etc\/passwd\.rb", not the expected shape/,
   /0005\).*msf entry "https:\/\/evil\.test\/x\.rb"/, /0006\).*msf that is not a list/,
   /0007\).*edb entry/,
   /0010\).*fixed "log4j-core\*", not empty or a version, or a comma-separated list of versions/, /0011\).*fixed "see advisory"/,
   /0016\).*fixed "10.4.3, log4j-core\*"/, /0017\).*fixed "10.4.3,, 10.2.7"/, /0018\).*fixed "10.4.3, 10.2.7,"/,
   /0019\).*lists 13 versions, over 12/, /0020\).*fixed "10.4.3, see advisory"/,
   /0012\).*aliases entry "PYSEC-2026-1640"/, /0013\).*aliases entry/, /0014\).*kev_due "next week"/,
   /0015\).*29 edb, over 25/].forEach(function (re) { assert.match(w, re); });
});

function cvrow(over) {
  return Object.assign({
    cve: 'CVE-2026-7001', published: '2026-08-15', vendor: 'Acme', product: 'Widget',
    title: 'An issue was discovered in Widget through 1.2.', cvss: '9.8', cvss_version: '3.1',
    severity: 'critical', scored_by: 'NVD', epss: '0.45200', epss_pct: '0.97100', epss_date: '2026-08-18',
    epss_max: '0.45200', epss_spark: '0.0,20.0 62.1,12.0 120.0,0.0',
    signals: ['msf', 'edb', 'epss90', 'nuclei'],
    msf: ['modules/exploits/linux/http/x.rb'], edb: ['48208'], et_sids: [],
    nuclei: 'http/cves/2026/CVE-2026-7001.yaml', cisa_sigma: [], snort3_sids: [],
    ssvc_expl: 'poc', ssvc_auto: 'yes', ssvc_impact: 'total', fixed: '', aliases: [], stories: 0,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', kev_product: 'Acme Widget', kev_product_n: 3
  }, over || {});
}

function cvdoc(rows, over) {
  rows = rows || [cvrow(), cvrow({ cve: 'CVE-2026-7002', vendor: 'Other', signals: ['epss90', 'et'], msf: [], edb: [],
    nuclei: '', et_sids: [2036001], epss_pct: '0.91000', severity: 'high', cvss: '8.8', cvss_vector: '', kev_product: '', kev_product_n: '' })];
  var d = vdoc();
  var nSig = function (k) { return rows.filter(function (r) { return (r.signals || []).indexOf(k) !== -1; }).length; };
  var vend = {};
  rows.forEach(function (r) { if (r.vendor) vend[r.vendor] = (vend[r.vendor] || 0) + 1; });
  d = Object.assign(d, {
    cves_status: 'ok', cves_generated_at: '2026-08-19T10:00:00Z',
    cves_counts: {
      total: rows.length,
      critical: rows.filter(function (r) { return r.severity === 'critical'; }).length,
      high: rows.filter(function (r) { return r.severity === 'high'; }).length,
      medium: 0, low: 0, unscored: 0,
      msf: nSig('msf'), edb: nSig('edb'), epss90: nSig('epss90'), nuclei: nSig('nuclei'), et: nSig('et')
    },
    cve_vendors: Object.keys(vend).map(function (k) { return { label: k, count: vend[k] }; }),
    cves: rows
  });
  return Object.assign(d, over || {});
}

test('a well-formed cves section passes with no cve warnings (control)', function () {
  var r = CW.check(cvdoc(), SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  assert.deepEqual(r.cveWarnings, []);
  assert.equal(r.counts.cves, 2);
});

test('a body-text key on a CVEs row is a FAIL: cve.now summaries are never published', function () {
  ['summary', 'description', 'context'].forEach(function (k) {
    var row = cvrow(); row[k] = 'model-written text';
    var r = CW.check(cvdoc([row]), SOURCES, NOW);
    assert.equal(r.status, 'FAIL', k);
    assert.match(r.problems.join(' '), new RegExp('carries a ' + k + ' field'));
  });
});

test('a bad cves row warns per field, and the headlines still PASS', function () {
  var r = CW.check(cvdoc([
    cvrow({ cve: 'not-a-cve' }),
    cvrow({ cve: 'CVE-2026-0002', published: '2026-13-40' }),
    cvrow({ cve: 'CVE-2026-0003', published: '2026-06-01' }),
    cvrow({ cve: 'CVE-2026-0004', published: '2026-08-30' }),
    cvrow({ cve: 'CVE-2026-0005', signals: ['msf'], msf: [] }),
    cvrow({ cve: 'CVE-2026-0006', signals: ['edb'], epss_pct: '0.1' }),
    cvrow({ cve: 'CVE-2026-0007', signals: ['edb', 'msf', 'nuclei'] }),
    cvrow({ cve: 'CVE-2026-0008', signals: ['nuclei', 'et'], msf: [], edb: [], nuclei: 'http/cves/2026/x.yaml', et_sids: [2036001], epss_pct: '0.1', cvss_vector: '', kev_product: '', kev_product_n: '' }),
    cvrow({ cve: 'CVE-2026-0009', signals: ['telepathy', 'msf', 'edb', 'epss90', 'nuclei'] }),
    cvrow({ cve: 'CVE-2026-0010', vendor: 'A|B' }),
    cvrow({ cve: 'CVE-2026-0011', title: new Array(502).join('x') }),
    cvrow({ cve: 'CVE-2026-0012', cisa_added: '2026-08-18' }),
    cvrow({ cve: 'CVE-2026-0013', epss: '1.5' }),
    cvrow({ cve: 'CVE-2026-0014', vendor: 'Acme\u0000' })
  ]), SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  var w = r.cveWarnings.join('\n');
  [/no CVE id in CVE shape/, /0002\).*published "2026-13-40", not a real day/,
   /0003\).*published 2026-06-01, outside the 30-day window/, /0004\).*published 2026-08-30, after cves_generated_at/,
   /0005\).*lists signal msf but the row shows no msf fact/, /0006\).*shows msf but does not list it as a signal/, /0006\).*shows nuclei but does not list/,
   /0007\).*shows epss90 but does not list it as a signal/, /0009\).*unknown signal "telepathy"/,
   /0010\).*vendor containing "\|"/, /0011\).*title of 501 characters/, /0012\).*carries a CISA KEV date/,
   /0013\).*epss "1.5"/, /0014\).*control character in vendor/].forEach(function (re) { assert.match(w, re); });
});

test('a repeated CVE and missing schema keys warn', function () {
  var d = cvdoc([cvrow({ cve: 'CVE-2026-8001' }), cvrow({ cve: 'CVE-2026-8001' }), (function () {
    var x = cvrow({ cve: 'CVE-2026-8888' }); delete x.fixed; delete x.aliases; return x; })()]);
  var r = CW.check(d, SOURCES, NOW);
  var w = r.cveWarnings.join('\n');
  assert.match(w, /repeats a CVE/);
  assert.match(w, /8888\) lacks keys the schema promises: fixed, aliases/);
});

test('a CVE id in both the vulns and the cves sections is a FAIL, once per id (Revision 2: the tabs are disjoint)', function () {
  // control: disjoint sections pass
  var ok = CW.check(cvdoc([cvrow({ cve: 'CVE-2026-8001' })]), SOURCES, NOW);
  assert.equal(ok.status, 'PASS');
  assert.ok(!ok.problems.some(function (p) { return /both the vulns and the cves/.test(p); }));
  // vdoc's default vulns rows carry CVE-2026-1111 and CVE-2016-2222
  var r = CW.check(cvdoc([cvrow({ cve: 'CVE-2026-1111' }), cvrow({ cve: 'CVE-2026-1111' }), cvrow({ cve: 'CVE-2016-2222' }),
    cvrow({ cve: 'CVE-2026-8001' })]), SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  var hits = r.problems.filter(function (p) { return /is in both the vulns and the cves sections/.test(p); });
  assert.equal(hits.length, 2);
  assert.match(hits.join(' '), /CVE-2026-1111/);
  assert.match(hits.join(' '), /CVE-2016-2222/);
  assert.doesNotMatch(hits.join(' '), /CVE-2026-8001/);
});

test('cves counts and vendor chips are held to the rows; a count not declared is not', function () {
  var d = cvdoc();
  d.cves_counts.total = 9; d.cves_counts.msf = 5; d.cves_counts.critical = 7;
  d.cve_vendors = [{ label: 'Acme', count: 4 }, { label: 'Nobody', count: 1 }];
  var w = CW.check(d, SOURCES, NOW).cveWarnings.join('\n');
  assert.match(w, /cves_counts total disagrees/);
  assert.match(w, /cves_counts severity disagrees with the rows on critical/);
  assert.match(w, /cves_counts msf disagrees/);
  assert.match(w, /chip "Acme" declares 4 rows, actual 1/);
  assert.match(w, /chip "Nobody" matches no row/);
  // control: an undeclared signal count is fine
  var e = cvdoc(); delete e.cves_counts.nuclei;
  assert.deepEqual(CW.check(e, SOURCES, NOW).cveWarnings, []);
});

test('cves statuses: stale and unavailable warn, an old file warns once, over a day old warns, over the cap warns', function () {
  assert.match(CW.check(cvdoc(null, { cves_status: 'stale' }), SOURCES, NOW).cveWarnings.join(' '), /cves_status is stale/);
  assert.match(CW.check(cvdoc(null, { cves_status: 'broken' }), SOURCES, NOW).cveWarnings.join(' '), /not ok, stale or unavailable/);
  var old = CW.check(vdoc(), SOURCES, NOW);
  assert.equal(old.status, 'PASS');
  assert.equal(old.cveWarnings.length, 1);
  assert.match(old.cveWarnings[0], /no cves section/);
  assert.match(CW.check(cvdoc(null, { cves_generated_at: '2026-08-17T10:00:00Z' }), SOURCES, NOW).cveWarnings.join(' '), /hours old, over 24/);
  var many = [];
  for (var i = 0; i < 250; i++) many.push(cvrow({ cve: 'CVE-2026-' + (9000 + i) }));
  assert.doesNotMatch(CW.check(cvdoc(many), SOURCES, NOW).cveWarnings.join(' '), /over the cap/);
  many.push(cvrow({ cve: 'CVE-2026-9999' }));
  assert.match(CW.check(cvdoc(many), SOURCES, NOW).cveWarnings.join(' '), /251 rows, over the cap of 250/);
  assert.match(CW.check(cvdoc([]), SOURCES, NOW).cveWarnings.join(' '), /ok but there are no rows/);
});

/* ---- The CVEs tab, as structure (T-0522) ---- */

/* ---- The tab CSS: the no-:has fallback (T-0522) ---- */

function tabCss(extra) {
  return [
    '.hl-wtabs__sec { display: block; }',
    '.hl-wtabs:has(#headlines) .hl-wtabs__sec { display: none; }',
    '.hl-wtabs:has(#headlines) #headlines { display: block; }',
    '.hl-wtabs:has(#headlines) #vulns:target { display: block; }',
    '.hl-wtabs:has(#vulns :target) #vulns { display: block; }',
    '.hl-wtabs:has(#vulns:target) #headlines { display: none; }',
    '.hl-wtabs:has(#vulns :target) #headlines { display: none; }',
    '.hl-wtabs:has(#headlines) #cves:target { display: block; }',
    '.hl-wtabs:has(#cves :target) #cves { display: block; }',
    '.hl-wtabs:has(#cves:target) #headlines { display: none; }',
    '.hl-wtabs:has(#cves :target) #headlines { display: none; }',
    extra || '',
    '/* Anchors must not land under the 70px sticky site header. */'
  ].join('\n');
}

test('the real tab CSS passes: every hiding rule is a :has() rule and both tabs can be targeted', function () {
  var fs = require('node:fs');
  var path = require('node:path');
  var scss = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'assets', 'css', 'custom.scss'), 'utf8');
  var r = CW.checkTabCss(scss);
  assert.equal(r.status, 'PASS', r.problems.join(' | '));
  assert.ok(r.counts.hides >= 5);
});

test('a tab-hiding rule written without :has(), or a missing CVEs rule, is caught; an unreadable file is NOT CHECKED', function () {
  assert.equal(CW.checkTabCss(tabCss()).status, 'PASS');
  var plain = CW.checkTabCss(tabCss('#headlines { display: none; }'));
  assert.equal(plain.status, 'FAIL');
  assert.match(plain.problems.join(' '), /hides a section without :has\(\)/);
  var nocves = CW.checkTabCss(tabCss().replace('.hl-wtabs:has(#cves:target) #headlines { display: none; }', ''));
  assert.match(nocves.problems.join(' '), /no rule hides #headlines when #cves:target is targeted/);
  var noshow = CW.checkTabCss(tabCss().replace('.hl-wtabs:has(#cves :target) #cves { display: block; }', ''));
  assert.match(noshow.problems.join(' '), /no rule shows #cves when an anchor inside it is the target/);
  assert.equal(CW.checkTabCss(null).status, 'NOT CHECKED');
  assert.equal(CW.checkTabCss('nothing here').status, 'NOT CHECKED');
});

/* ---- Revision 3: the four arms, the vector and the product on CISA KEV ---- */

test('six arms admit independently; retired reason fails; product context alone admits nothing', function () {
  function only(over) { return CW.check(cvdoc([cvrow(Object.assign({signals: [], msf: [], edb: [], nuclei: '', et_sids: [], epss_pct: '0.1'}, over))]), SOURCES, NOW); }
  [{signals:['nuclei'],nuclei:'http/cves/2026/a.yaml'}, {signals:['et'],et_sids:[2036001]},
   {signals:['msf'],msf:['modules/exploits/x.rb']}, {signals:['edb'],edb:['48208']},
   {signals:['epss90'],epss_pct:'0.9'}, {signals:['epss_vedas'],epss:'0.01',vedas:0.8}
  ].forEach(function (over) { var r=only(over); assert.equal(r.status,'PASS'); assert.deepEqual(r.cveWarnings,[]); });
  var retired=only({signals:['crit_noauth_kev_product']});
  assert.equal(retired.status,'FAIL'); assert.match(retired.problems.join(' '),/retired reason/);
  assert.match(only({}).cveWarnings.join(' '), /lists no selection arm/);
  assert.match(only({signals:['nuclei']}).cveWarnings.join(' '), /no nuclei fact/);
  assert.match(only({signals:['et']}).cveWarnings.join(' '), /no et fact/);
});

test('cvss_vector, kev_product and kev_product_n are held to their shapes', function () {
  var w = CW.check(cvdoc([
    cvrow({ cve: 'CVE-2026-8201', cvss_vector: 'AV:N <script>' }),
    cvrow({ cve: 'CVE-2026-8202', cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N', cvss: '' }),
    cvrow({ cve: 'CVE-2026-8203', kev_product_n: '3' }),
    cvrow({ cve: 'CVE-2026-8204', kev_product_n: 0 }),
    cvrow({ cve: 'CVE-2026-8205', kev_product: '' }),
    cvrow({ cve: 'CVE-2026-8206', kev_product: 'Acme\u0000Widget' }),
    cvrow({ cve: 'CVE-2026-8207', scored_by: 'cve.now' }),
    cvrow({ cve: 'CVE-2026-8208', scored_by: 'somebody' })
  ]), SOURCES, NOW).cveWarnings.join('\n');
  [/8201\).*cvss_vector "AV:N <script>", not empty or a CVSS vector/, /8202\).*has a cvss_vector but no cvss/,
   /8203\).*kev_product_n "3", not empty or a count/, /8204\).*only in part/, /8205\).*only in part/,
   /8206\).*control character in kev_product/, /8208\).*scored_by "somebody"/].forEach(function (re) { assert.match(w, re); });
  assert.doesNotMatch(w, /8207\)/);   // cve.now is a legitimate scorer for arm A (Revision 3)
});

/* ---- Attribution accuracy and the cap (T-0522, the lead's read of the real-data preview) ---- */

/* ---- Review round 1, F3 and F4: the include chain, the feed, the score source and the rules sentence ---- */

function readReal(rel) {
  var fs = require('node:fs');
  var path = require('node:path');
  return fs.readFileSync(path.join(__dirname, '..', '..', '..', rel), 'utf8');
}

test('the gate follows the include chain: every wire-* include the page names is read, the real six pass', function () {
  /* T-0532 adds wire-details-row.html, which the Details JSON pages include for
     themselves (its escaping is their check, not this one); the chain the PAGE
     names stays the six below. T-0651 adds the wire-agent-* includes, which only the agent
     feed (wire/agent/*.json and its plain HTML pages) includes, for the same reason. */
  var rowInc = 'wire-details-row.html';
  var agentIncs = ['wire-agent-brief.html', 'wire-agent-bucket.html', 'wire-agent-bucketof.html', 'wire-agent-detail.html', 'wire-agent-list.html', 'wire-agent-row.html', 'wire-agent-select.html'];
  var inc = realIncludes();
  assert.deepEqual(Object.keys(inc).sort(),
    agentIncs.concat(['wire-cve-why.html', rowInc, 'wire-fold-keys.html', 'wire-fold.html', 'wire-nkev-priority.html', 'wire-vuln-epss.html', 'wire-vuln-new.html',
     'wire-vuln-news.html', 'wire-vuln-rules.html', 'wire-vuln-sev.html', 'wire-vuln-vedas.html']).sort());
  var page = readReal('wire/index.md');
  var r = CW.checkPage(page, inc);
  assert.equal(r.status, 'PASS', r.problems.join(' | '));
  // an include the page names but the caller did not supply is NOT CHECKED, never a pass
  ['wire-cve-why.html', 'wire-fold-keys.html', 'wire-fold.html', 'wire-vuln-epss.html', 'wire-vuln-new.html',
   'wire-vuln-news.html', 'wire-vuln-rules.html', 'wire-vuln-sev.html'].forEach(function (name) {
    var some = Object.assign({}, inc); delete some[name];
    var x = CW.checkPage(page, some);
    assert.equal(x.status, 'FAIL', name);
    assert.match(x.problems.join(' '), new RegExp('NOT CHECKED: _includes/' + name.replace(/\./g, '\\.') + ' could not be read'));
  });
  // the Details row include is not in the page's chain, so it may sit outside this map
  var withoutRow = Object.assign({}, inc); delete withoutRow[rowInc]; agentIncs.forEach(function (n) { delete withoutRow[n]; });
  assert.equal(CW.checkPage(page, withoutRow).status, 'PASS');
});

test('one escaping mutation per include, and one PoC mutation per include, each fails the page gate', function () {
  var inc = realIncludes();
  var page = readReal('wire/index.md');
  var escapes = {
    'wire-vuln-sev.html': ['CVSS v{{ r.cvss_version | escape }}', 'CVSS v{{ r.cvss_version }}'],
    'wire-vuln-news.html': ['name {{ r.cve | escape }}', 'name {{ r.cve }}'],
    'wire-vuln-epss.html': ['{{ r.ratio_now | escape }}', '{{ r.ratio_now }}'],
    'wire-vuln-rules.html': ['SID {{ sid | escape }}', 'SID {{ sid }}'],
    'wire-vuln-new.html': ['>{{ al | escape }}</a>{%- elsif', '>{{ al }}</a>{%- elsif'],
    'wire-vuln-vedas.html': ["date: '%-d %B %Y, %H:%M' | escape", "date: '%-d %B %Y, %H:%M'"],
    'wire-cve-why.html': ['{%- assign sg = "" | split: "" -%}', '{%- assign sg = "" | split: "" -%}<i>{{ r.vendor }}</i>']
  };
  Object.keys(escapes).forEach(function (name) {
    var e = escapes[name];
    assert.ok(inc[name].indexOf(e[0]) > -1, name + ' lacks the mutation anchor ' + e[0]);
    var some = Object.assign({}, inc); some[name] = inc[name].replace(e[0], e[1]);
    var r = CW.checkPage(page, some);
    assert.equal(r.status, 'FAIL', name + ' escape mutation');
    assert.match(r.problems.join(' | '), new RegExp('_includes/' + name.replace(/\./g, '\\.') + ' prints .* without escape'), name);
    var p = Object.assign({}, inc); p[name] = inc[name] + '<span>a GitHub PoC repository</span>';
    var rp = CW.checkPage(page, p);
    assert.equal(rp.status, 'FAIL', name + ' PoC mutation');
    assert.match(rp.problems.join(' | '), new RegExp('_includes/' + name.replace(/\./g, '\\.') + ' mentions a GitHub proof of concept'), name);
  });
});

test('an include may build only its own link targets, and one that builds none may not add one', function () {
  var inc = realIncludes();
  var page = readReal('wire/index.md');
  var sev = Object.assign({}, inc); sev['wire-vuln-sev.html'] = inc['wire-vuln-sev.html'] + '<a href="https://github.com/x/y">x</a>';
  assert.match(CW.checkPage(page, sev).problems.join(' '), /wire-vuln-sev\.html links to href="https:\/\/github\.com\/x\/y"/);
  var rules = Object.assign({}, inc); rules['wire-vuln-rules.html'] = inc['wire-vuln-rules.html'] + '<a href="https://evil.test/r">x</a>';
  assert.match(CW.checkPage(page, rules).problems.join(' '), /wire-vuln-rules\.html links to href="https:\/\/evil\.test\/r"/);
  // control: the real rules include's own three targets and the news include's relative link are allowed
  assert.equal(CW.checkPage(page, inc).status, 'PASS');
});

test('retired reason cannot return to page or include, and tooling copy is pinned', function () {
  var page=readReal('wire/index.md'), inc=realIncludes();
  assert.equal(CW.checkPage(page,inc).status,'PASS');
  var bad=Object.assign({},inc); bad['wire-cve-why.html']+='crit_noauth_kev_product';
  assert.match(CW.checkPage(page,bad).problems.join(' '),/retired/);
  ['seven reasons', 'a ProjectDiscovery Nuclei template',
   "Nuclei templates come from ProjectDiscovery's template index; ET Open rules come from Emerging Threats' Suricata ruleset.",
   'the tooling reasons together admitted 53 CVEs, eight later listed on VulnCheck KEV; Nuclei accounted for seven of 34.'
  ].forEach(function (pin) {
    // Mutate the callout's reason count even when the explanation repeats it.
    var changed = pin === 'seven reasons'
      ? page.replace(/(<details class="hl-wire-explanation" id="cves-explanation"[\s\S]*?)seven reasons/, '$1removed')
      : page.replace(pin, 'removed');
    assert.notEqual(changed, page, pin);
    assert.equal(CW.checkPage(changed,inc).status,'FAIL',pin);
  });
});

test('the feed: the real wire/cves.xml passes; an unescaped output, a PoC word, a lost cve.now qualifier or a wrong source fails', function () {
  var xml = readReal('wire/cves.xml');
  var ok = CW.checkCvesFeed(xml);
  assert.equal(ok.status, 'PASS', ok.problems.join(' | '));
  var cases = [
    [xml.replace('{{ r.cve | xml_escape }}{% if r.vendor', '{{ r.cve }}{% if r.vendor'), /prints \{\{ r\.cve \}\} without xml_escape/],
    [xml.replace('{{ r.cvss_version | xml_escape }}', '{{ r.cvss_version }}'), /prints \{\{ r\.cvss_version \}\} without xml_escape/],
    [xml.replace('<category term="cves-tab"', '<category term="github-poc" label="GitHub PoC"/><category term="cves-tab"'), /mentions a GitHub proof of concept/],
    [xml.replace('scores from NVD through VulnCheck, unless a row says cve.now; exploits from Rapid7\'s', 'scores from NVD through VulnCheck; exploits from Rapid7\'s'), /no longer qualifies/],
    [xml.replace('{% if r.scored_by == "cve.now" %}', '{% if r.scored_by == "never" %}'), /no longer says when a score came from cve\.now/],
    [xml.replace('The feed shows at most 250 CVEs', 'The feed shows at most 150 CVEs'), /does not say "at most 250 CVEs"/],
    [xml.replace('EPSS from FIRST; VEDAS exploit maturity from A.R.P. Syndicate (github.com/ARPSyndicate/cve-scores). Selection', 'EPSS from FIRST. Selection'), /does not credit A\.R\.P\. Syndicate/],
    [xml.replace('exploits from Rapid7 and Exploit-DB;', 'exploits carried by cve.now (Metasploit, Exploit-DB);').replace('Rapid7\'s and Exploit-DB\'s own indexes', 'Metasploit and Exploit-DB lists that cve.now carries'), /Rapid7 and Exploit-DB|carries Metasploit/]
  ];
  cases.forEach(function (c, i) {
    assert.notEqual(c[0], xml, 'case ' + i + ' did not change the feed');
    var r = CW.checkCvesFeed(c[0]);
    assert.equal(r.status, 'FAIL', 'case ' + i);
    assert.match(r.problems.join(' | '), c[1], 'case ' + i);
  });
  assert.equal(CW.checkCvesFeed(null).status, 'NOT CHECKED');
});

/* ---- ESC lane (T-0522): the nKEV row template and wire/vulns.xml are now held to the same
   escaping guarantee as the CVEs tab and its feed. One mutation per newly escaped value (each
   anchor asserted present first), plus the number-forcing pins. ---- */

test('one escaping mutation per newly escaped nKEV value fails the page gate (control: the real page passes)', function () {
  var page = readReal('wire/index.md');
  var inc = realIncludes();
  assert.equal(CW.checkPage(page, inc).status, 'PASS');
  var mutants = [
    ['id="cve-{{ r.cve | downcase | escape }}"', 'id="cve-{{ r.cve | downcase }}"'],
    ['data-title="{{ r.cve | downcase | escape }} {{ r.vendor', 'data-title="{{ r.cve | downcase }} {{ r.vendor'],
    ['data-sev="{{ sev | escape }}"', 'data-sev="{{ sev }}"'],
    ['data-det="{{ det | join: \'|\' | escape }}"', 'data-det="{{ det | join: \'|\' }}"'],
    ['data-nvd="{{ nvd_key | escape }}"', 'data-nvd="{{ nvd_key }}"'],
    ['data-day="{{ vday | escape }}"', 'data-day="{{ vday }}"'],
    ['vuln/detail/{{ r.cve | escape }}', 'vuln/detail/{{ r.cve }}'],
    ['noreferrer">{{ r.cve | escape }}</a>', 'noreferrer">{{ r.cve }}</a>'],
    ['CISA KEV {{ r.cisa_added | escape }}', 'CISA KEV {{ r.cisa_added }}'],
    ['evidence {{ r.evidence | escape }}', 'evidence {{ r.evidence }}'],
    ['id="vulns-{{ day_group.name | escape }}"', 'id="vulns-{{ day_group.name }}"'],
    ['data-prio="{{ r.prio | escape }}"', 'data-prio="{{ r.prio }}"']
  ];
  mutants.forEach(function (m, i) {
    assert.ok(page.indexOf(m[0]) > -1, 'escape mutation ' + i + ' anchor missing: ' + m[0]);
    var r = CW.checkPage(page.replace(m[0], m[1]), inc);
    assert.equal(r.status, 'FAIL', 'escape mutation ' + i + ': ' + m[0]);
    assert.match(r.problems.join(' | '), /nKEV row template prints .* without escape/, 'mutation ' + i);
  });
  // Reverting the reports_more number forcing is caught by the pin, not by a filter:
  // the value prints bare and must stay, in the assign, forced to a number.
  var force = '{%- assign n_more = r.reports_more | default: 0 | plus: 0 -%}';
  assert.ok(page.indexOf(force) > -1, 'the n_more forcing assign is missing');
  var unforced = CW.checkPage(page.replace(force, '{%- assign n_more = r.reports_more | default: 0 -%}'), inc);
  assert.equal(unforced.status, 'FAIL');
  assert.match(unforced.problems.join(' | '), /does not force n_more/);
});

test('one xml-escape mutation per newly escaped vulns.xml value fails the nKEV feed gate (control: the real feed passes)', function () {
  var xml = readReal('wire/vulns.xml');
  assert.equal(CW.checkVulnsFeed(xml).status, 'PASS');
  var cases = [
    ['vuln/detail/{{ r.cve | xml_escape }}', 'vuln/detail/{{ r.cve }}'],
    ['#cve-{{ r.cve | downcase | xml_escape }}" rel="alternate', '#cve-{{ r.cve | downcase }}" rel="alternate'],
    ['#cve-{{ r.cve | downcase | xml_escape }}</id>', '#cve-{{ r.cve | downcase }}</id>'],
    ['<published>{{ vday | xml_escape }}T00:00:00Z', '<published>{{ vday }}T00:00:00Z'],
    ['<updated>{{ vday | xml_escape }}T00:00:00Z', '<updated>{{ vday }}T00:00:00Z'],
    ['KEV {{ r.added | xml_escape }}{% endif %}{% if vday != r.added %}', 'KEV {{ r.added }}{% endif %}{% if vday != r.added %}'],
    ['to CISA KEV {{ r.cisa_added | xml_escape }}; not in', 'to CISA KEV {{ r.cisa_added }}; not in'],
    ['since {{ r.cisa_added | xml_escape }}', 'since {{ r.cisa_added }}']
  ];
  cases.forEach(function (c, i) {
    assert.ok(xml.indexOf(c[0]) > -1, 'feed case ' + i + ' anchor missing: ' + c[0]);
    var r = CW.checkVulnsFeed(xml.replace(c[0], c[1]));
    assert.equal(r.status, 'FAIL', 'feed case ' + i);
    assert.match(r.problems.join(' | '), /wire\/vulns\.xml prints .* without xml_escape/, 'feed case ' + i);
  });
  // Control: a bare number-forced value (gap_n), the site constants and the Atom dates pass.
  assert.ok(xml.indexOf('{{ gap_n }}') > -1, 'the gap_n pin anchor is missing from the feed');
  assert.equal(CW.checkVulnsFeed(null).status, 'NOT CHECKED');
  assert.match(CW.checkVulnsFeed(null).reason, /vulns\.xml is absent or unreadable/);
});

test('an include named only by another include is followed too (the real page and includes)', function () {
  var page = readReal('wire/index.md');
  var inc = realIncludes();
  var chained = Object.assign({}, inc, {
    'wire-vuln-new.html': inc['wire-vuln-new.html'] + '\n{% include wire-vuln-extra.html %}',
    'wire-vuln-extra.html': '<i>{{ r.vendor }}</i>'
  });
  var r = CW.checkPage(page, chained);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /_includes\/wire-vuln-extra\.html prints \{\{ r\.vendor \}\} without escape/);
  chained['wire-vuln-extra.html'] = '<i>{{ r.vendor | escape }}</i>';
  assert.equal(CW.checkPage(page, chained).status, 'PASS');
  delete chained['wire-vuln-extra.html'];
  assert.match(CW.checkPage(page, chained).problems.join(' '), /NOT CHECKED: _includes\/wire-vuln-extra\.html could not be read/);
});

/* T-0603 C25: the day layout is the only layout. Losing its marker fails, and the credit, licence and
   "I do not curate" pins fail on the REAL page (the old synthetic page only reached the removed checks). */
test('the day layout marker is required, and the credit, licence and no-curation pins each fail on the real page', function () {
  var page = readReal('wire/index.md');
  var inc = realIncludes();
  assert.equal(CW.checkPage(page, inc).status, 'PASS');
  var gone = CW.checkPage(page.replace('data-wire-layout="days"', 'data-wire-layout="x"'), inc);
  assert.equal(gone.status, 'FAIL');
  assert.match(gone.problems.join(' '), /lost data-wire-layout="days"/);
  ['I do not curate', 'Empirical Security', 'CC BY 4.0', 'CC0', 'A.R.P. Syndicate'].forEach(function (pin) {
    assert.ok(page.indexOf(pin) > -1, 'the real page carries ' + pin);
    var r = CW.checkPage(page.split(pin).join('XX'), inc);
    assert.equal(r.status, 'FAIL', pin);
    assert.match(r.problems.join(' | '), /lost/, pin);
  });
});


/* T-0605 L57: the page-side copy of the guard wire/cves.xml has. The real page passes (control); a sentence
   saying cve.now carries Metasploit or Exploit-DB data fails, and one that only names them after a full stop does not. */
test('the page may not say cve.now carries Metasploit or Exploit-DB data (control: the real page passes)', function () {
  var page = readReal('wire/index.md');
  var inc = realIncludes();
  assert.equal(CW.checkPage(page, inc).status, 'PASS');
  var anchor = 'cve.now carries them (CISA Vulnrichment)';
  assert.ok(page.indexOf(anchor) > -1, 'the real page carries the anchor sentence');
  var bad = CW.checkPage(page.replace(anchor, 'cve.now carries Metasploit modules and Exploit-DB entries (CISA Vulnrichment)'), inc);
  assert.equal(bad.status, 'FAIL');
  assert.match(bad.problems.join(' | '), /the page says cve\.now carries Metasploit or Exploit-DB data/);
  var ok = CW.checkPage(page.replace(anchor, 'cve.now carries them (CISA Vulnrichment). Metasploit and Exploit-DB come from their own indexes'), inc);
  assert.doesNotMatch(ok.problems.join(' | '), /cve\.now carries Metasploit/);
});


/* T-0564: optional VEDAS is a numeric estimate, not a public exploit claim. */
test('VEDAS accepts absence and both bounds on both tabs; rejects invalid numbers and types', function () {
  [undefined, 0, 0.8, 1].forEach(function (v) {
    var n = vrow(), c = cvrow();
    if (v !== undefined) { n.vedas = v; c.vedas = v; }
    [CW.check(vdoc([n]), SOURCES, NOW), CW.check(cvdoc([c]), SOURCES, NOW)].forEach(function (r) {
      assert.equal(r.status, 'PASS', r.problems.join(' | '));
      assert.doesNotMatch(r.problems.join(' '), /vedas/);
    });
  });
  [-0.0001, 1.0001, NaN, Infinity, '0.8', null, '', true].forEach(function (v) {
    [CW.check(vdoc([vrow({ vedas: v })]), SOURCES, NOW),
      CW.check(cvdoc([cvrow({ vedas: v })]), SOURCES, NOW)].forEach(function (r) {
      assert.equal(r.status, 'FAIL');
      assert.match(r.problems.join(' '), /vedas.*not a number in \[0, 1\]/);
    });
  });
});

test('the paired signal needs EPSS, maturity and CVSS, and its count agrees', function () {
  var base = { signals: ['epss_vedas'], epss: '0.01', vedas: 0.8, cvss: '7.0', severity: 'high',
    msf: [], edb: [], nuclei: '', et_sids: [], epss_pct: '0.1', kev_product: '', kev_product_n: '',
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' };
  var check = function (over) {
    return CW.check(cvdoc([cvrow(Object.assign({}, base, over))], {
      cves_counts: { total: 1, epss_vedas: 1 }
    }), SOURCES, NOW);
  };
  assert.deepEqual(check({}).cveWarnings, []);
  assert.deepEqual(check({ cvss_vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' }).cveWarnings, [], 'pair has no network-vector gate');
  [{ vedas: 0.7999 }, { cvss: '6.9' }, { epss: '0.009999' }, { epss: '' }, { epss: undefined }, { epss: 'bad' },
    { vedas: undefined }].forEach(function (over) {
    assert.match(check(over).cveWarnings.join(' '), /lists signal epss_vedas but the row shows no/);
  });
  assert.match(check({ signals: [] }).cveWarnings.join(' '), /shows epss_vedas but does not list/);
  assert.match(check({ signals: ['vedas_weaponized'] }).cveWarnings.join(' '), /unknown signal/);
  var wrong = cvdoc([cvrow(base)], { cves_counts: { total: 1, epss_vedas: 2 } });
  assert.match(CW.check(wrong, SOURCES, NOW).cveWarnings.join(' '), /epss_vedas disagrees.*declared 2, actual 1/);
});

test('VEDAS legend claims and source hrefs are pinned separately in each tab', function () {
  var page = readReal('wire/index.md'), inc = realIncludes();
  assert.equal(CW.checkPage(page, inc).status, 'PASS');
  var pins = ['VEDAS (exploit maturity)', 'Estimation of Vulnerability Prevalence &amp; Exploit Maturity',
    '150+ identifiers', 'every 6 to 8 hours', 'The source publishes no formula.',
    'On the CVEs tab, I pair EPSS at least 1% with VEDAS at least 80% and CVSS at least 7.0 for the EPSS + VEDAS reason.',
    'A high score is not evidence that working exploit code exists or that the CVE has been exploited',
    'exploitation is what the nKEVs tab and CISA KEV are for', 'An unscored CVE shows no VEDAS chip.',
    'href="https://www.exploit.observer/"', 'href="https://github.com/ARPSyndicate/cve-scores"'];
  pins.forEach(function (pin) {
    var at = -1, count = 0;
    while ((at = page.indexOf(pin, at + 1)) !== -1) {
      var mutant = page.slice(0, at) + 'XX' + page.slice(at + pin.length);
      assert.equal(CW.checkPage(mutant, inc).status, 'FAIL', pin + ' occurrence ' + count);
      count++;
    }
    assert.ok(count >= 2, 'both tabs must carry ' + pin);
  });
});

test('nKEV grouping copy stays pinned on the real template',function(){
 var page=readReal('wire/index.md'), inc=realIncludes();
 ['newest day first','at least 5 entries','Every VulnCheck KEV entry stays visible.','Filters open matching batches and counts show matching rows.'].forEach(function(pin){
   // T-0667: the panel keeps a text for data from before the event day and one for data with it, so a pin can appear twice; drop every copy.
   assert.equal(CW.checkPage(page.split(pin).join('removed'),inc).status,'FAIL',pin);
 });
});

/* T-0628: the priority picks keys and counts (contract: tasks/runs/T-0628/contract.md). The fixture
   test/fixtures/picks-wire.yml carries two pick rows (one seeded, one with empty signals) and two rows
   that are not picks. The pick checks are WARN lines like every CVEs-tab data check (a FAIL would make
   pages.yml drop the headlines), so "fails" below means the cves warnings name the defect. */
var yamlPicks = require('js-yaml');
var fsPicks = require('node:fs');
var pathPicks = require('node:path');
function picksFixture() {
  return yamlPicks.load(fsPicks.readFileSync(pathPicks.join(__dirname, 'fixtures', 'picks-wire.yml'), 'utf8'));
}
var PICKS_NOW = Date.parse('2026-11-05T21:00:00Z');
function picksWarn(d) { return CW.check(d, SOURCES, PICKS_NOW).cveWarnings.join('\n'); }
function pickRow(d, cve) { return d.cves.filter(function (r) { return r.cve === cve; })[0]; }

test('T-0628 control: the picks fixture passes with no cve warnings, and counts its picks', function () {
  var d = picksFixture();
  assert.equal(d.cves.filter(function (r) { return r.pick_day; }).length, 2);
  assert.ok(d.cves.some(function (r) { return r.pick_day && r.signals.length === 0; }), 'one pick has empty signals');
  assert.ok(d.cves.some(function (r) { return r.pick_seeded === true; }), 'one pick is seeded');
  var r = CW.check(d, SOURCES, PICKS_NOW);
  assert.equal(r.status, 'PASS');
  assert.deepEqual(r.cveWarnings, []);
  assert.equal(r.counts.cves, 4);
});

test('T-0628 data from before the picks (no pick key, no pick count) still passes', function () {
  var d = picksFixture();
  d.cves.forEach(function (r) { PICK_KEYS_TEST.forEach(function (k) { delete r[k]; }); });
  // a pick row without signals is a defect once nothing marks it a pick
  d.cves = d.cves.filter(function (r) { return r.signals.length > 0; });
  ['picks', 'picks_today', 'pick_pool'].forEach(function (k) { delete d.cves_counts[k]; });
  d.cves_counts.total = d.cves.length; d.cves_counts.high = 2; d.cves_counts.critical = 1; d.cves_counts.medium = 0; d.cves_counts.msf = 1;
  d.cve_vendors = [{ label: 'Fixture', count: d.cves.length }];
  var r = CW.check(d, SOURCES, PICKS_NOW);
  assert.equal(r.status, 'PASS');
  assert.deepEqual(r.cveWarnings, []);
});
var PICK_KEYS_TEST = ['pick_day', 'pick_score', 'pick_reasons', 'pick_class', 'pick_seeded'];

test('T-0628 pick_reasons out of order, repeated or unknown are named', function () {
  var d = picksFixture();
  pickRow(d, 'CVE-2026-9101').pick_reasons = ['nomi', 'tooling', 'noauth', 'class'];
  assert.match(picksWarn(d), /9101\).*pick reason tooling out of order or twice/);
  d = picksFixture();
  pickRow(d, 'CVE-2026-9101').pick_reasons = ['tooling', 'tooling', 'nomi', 'noauth', 'class'];
  assert.match(picksWarn(d), /9101\).*out of order or twice/);
  d = picksFixture();
  pickRow(d, 'CVE-2026-9101').pick_reasons = ['tooling', 'luck', 'class'];
  assert.match(picksWarn(d), /9101\).*unknown pick reason "luck"/);
});

test('T-0628 a row with no pick_day carries score 0, no reasons, no class and is not seeded', function () {
  var d = picksFixture();
  pickRow(d, 'CVE-2026-9103').pick_score = 3;
  assert.match(picksWarn(d), /9103\).*pick_score 3 but no pick_day/);
  d = picksFixture();
  pickRow(d, 'CVE-2026-9103').pick_reasons = ['nomi'];
  assert.match(picksWarn(d), /9103\).*pick reasons but has no pick_day/);
  d = picksFixture();
  pickRow(d, 'CVE-2026-9103').pick_class = 'File transfer';
  assert.match(picksWarn(d), /9103\).*pick_class but no pick_day/);
  d = picksFixture();
  pickRow(d, 'CVE-2026-9103').pick_seeded = true;
  assert.match(picksWarn(d), /9103\).*seeded but has no pick_day/);
});

test('T-0628 pick types: day, score, list, class label, seeded flag', function () {
  var d = picksFixture(); pickRow(d, 'CVE-2026-9101').pick_day = '2026-13-40';
  assert.match(picksWarn(d), /9101\).*pick_day "2026-13-40"/);
  d = picksFixture(); pickRow(d, 'CVE-2026-9101').pick_day = '2026-11-09';
  assert.match(picksWarn(d), /9101\).*pick_day 2026-11-09, after cves_generated_at/);
  d = picksFixture(); pickRow(d, 'CVE-2026-9101').pick_day = '2026-11-01';
  assert.match(picksWarn(d), /9101\).*before its published day/);
  d = picksFixture(); pickRow(d, 'CVE-2026-9101').pick_score = '7';
  assert.match(picksWarn(d), /9101\).*pick_score "7"/);
  d = picksFixture(); pickRow(d, 'CVE-2026-9101').pick_score = 6.5;
  assert.match(picksWarn(d), /9101\).*pick_score 6.5/);
  d = picksFixture(); pickRow(d, 'CVE-2026-9101').pick_reasons = 'tooling';
  assert.match(picksWarn(d), /9101\).*pick_reasons that are not a list/);
  d = picksFixture(); pickRow(d, 'CVE-2026-9101').pick_class = 'Printers';
  assert.match(picksWarn(d), /9101\).*unknown pick_class "Printers"/);
  d = picksFixture(); pickRow(d, 'CVE-2026-9101').pick_class = '';
  assert.match(picksWarn(d), /9101\).*class reason but pick_class is empty/);
  d = picksFixture(); pickRow(d, 'CVE-2026-9102').pick_class = 'File transfer';
  assert.match(picksWarn(d), /9102\).*pick_class but does not list the class reason/);
  d = picksFixture(); pickRow(d, 'CVE-2026-9101').pick_seeded = 'yes';
  assert.match(picksWarn(d), /9101\).*pick_seeded "yes"/);
});

test('T-0628 some pick keys without the others are named, and a missing pick_seeded counts as some', function () {
  var d = picksFixture(); delete pickRow(d, 'CVE-2026-9101').pick_seeded;
  assert.match(picksWarn(d), /9101\).*only some pick keys \(pick_day, pick_score, pick_reasons, pick_class\)/);
});

test('T-0628 a pick may list no signal; a row that is not a pick still needs one', function () {
  var d = picksFixture();
  assert.equal(pickRow(d, 'CVE-2026-9102').signals.length, 0);
  assert.doesNotMatch(picksWarn(d), /lists no selection arm/);
  pickRow(d, 'CVE-2026-9103').signals = []; pickRow(d, 'CVE-2026-9103').epss_pct = '0.1';
  assert.match(picksWarn(d), /9103\).*lists no selection arm/);
  // a pick row's signals are still held to its facts
  d = picksFixture(); pickRow(d, 'CVE-2026-9102').signals = ['msf'];
  assert.match(picksWarn(d), /9102\).*lists signal msf but the row shows no msf fact/);
});

test('T-0628 pick counts are held to the rows when declared, and a count not declared is not', function () {
  var d = picksFixture(); d.cves_counts.picks = 5;
  assert.match(picksWarn(d), /cves_counts picks disagrees with the rows: declared 5, actual 2/);
  d = picksFixture(); d.cves_counts.picks_today = 2;
  assert.match(picksWarn(d), /cves_counts picks_today disagrees with the rows: declared 2, actual 1/);
  d = picksFixture(); d.cves_counts.pick_pool = -1;
  assert.match(picksWarn(d), /pick_pool is -1, not a whole number/);
  d = picksFixture(); d.cves_counts.pick_pool = '40';
  assert.match(picksWarn(d), /pick_pool is "40"/);
  d = picksFixture(); delete d.cves_counts.picks; delete d.cves_counts.picks_today; delete d.cves_counts.pick_pool;
  assert.deepEqual(CW.check(d, SOURCES, PICKS_NOW).cveWarnings, []);
});

test('T-0628 the cap of 250 counts the rows below the picks, not the picks', function () {
  var d = picksFixture();
  var many = d.cves.filter(function (r) { return r.pick_day; });
  for (var i = 0; i < 250; i++) many.push(Object.assign({}, pickRow(d, 'CVE-2026-9104'), { cve: 'CVE-2026-' + (9500 + i) }));
  d.cves = many; d.cves_counts.total = many.length; d.cves_counts.high = 0; d.cves_counts.critical = 0; d.cves_counts.medium = 0;
  d.cves_counts.msf = 0; d.cves_counts.nuclei = 250; d.cves_counts.epss90 = 0;
  d.cve_vendors = [{ label: 'Fixture', count: many.length }];
  assert.doesNotMatch(picksWarn(d), /over the cap/);
  many.push(Object.assign({}, pickRow(d, 'CVE-2026-9104'), { cve: 'CVE-2026-9999' }));
  assert.match(picksWarn(d), /251 rows besides 2 priority picks, over the cap of 250/);
});

test('T-0628 the page template: the picks group, filter chip and pick strip are pinned, and losing one fails the page check', function () {
  var page = fsPicks.readFileSync(pathPicks.join(__dirname, '..', '..', '..', 'wire', 'index.md'), 'utf8');
  var includes = {};
  fsPicks.readdirSync(pathPicks.join(__dirname, '..', '..', '..', '_includes')).filter(function (n) { return /^wire-/.test(n); })
    .forEach(function (n) { includes[n] = fsPicks.readFileSync(pathPicks.join(__dirname, '..', '..', '..', '_includes', n), 'utf8'); });
  assert.equal(CW.checkPage(page, includes).status, 'PASS');
  ['class="hl-pstrip hl-pstrip--cves" id="cves-priority-picks"', 'data-sig="pick">Priority picks', 'class="hl-vuln__pick"', 'A pick is a priority, not evidence of exploitation',
    'was not blind', '10.3%', 'outside that cap', 'data-pstrip-chip="pick"', 'class="hl-pstrip__new">new today</span>', 'The strip at the top of this tab links to my latest daily picks',
    'every pick stays in the day its CVE was published'].forEach(function (pin) {
    assert.ok(page.includes(pin), pin);
    assert.equal(CW.checkPage(page.replace(pin, 'removed'), includes).status, 'FAIL', pin);
  });
  // an unescaped pick value is caught by the existing escaping check
  assert.equal(CW.checkPage(page.replace('{{ r.pick_class | escape }}', '{{ r.pick_class }}'), includes).status, 'FAIL');
  // the panel copy stays free of dashes
  assert.equal(CW.checkPage(page.replace('are my daily shortlist', 'are my daily shortlist — yes'), includes).status, 'FAIL');
});

/* T-0665: the "Just published" rows (contract: tasks/runs/T-0665/contract.md). test/fixtures/fresh-wire.yml is
   picks-wire.yml with the four fresh keys on every CVE row and nine rows added: CVE-2026-9105 and 9106 are
   Just published only (signals []), 9107 is Just published and a pick (signals []), 9103 is an arm row that is
   also Just published, and 9110 is the one Just published row among six same-day rows for one product. The
   checks are WARN lines like every CVEs-tab data check, so "fails" below means the cves warnings name the defect.
   The controls: the fixture passes clean, picks-wire.yml (no fresh keys) still passes clean, and so does the
   same fixture with every fresh key and the fresh count removed. */
function freshFixture() {
  return yamlPicks.load(fsPicks.readFileSync(pathPicks.join(__dirname, 'fixtures', 'fresh-wire.yml'), 'utf8'));
}
var FRESH_KEYS_TEST = ['fresh', 'fresh_score', 'fresh_reasons', 'fresh_class'];
var FRESH_NOW = PICKS_NOW;
function freshWarn(d) { return CW.check(d, SOURCES, FRESH_NOW).cveWarnings.join('\n'); }

test('T-0665 control: the fresh fixture passes with no cve warnings and holds 5 fresh rows of 13', function () {
  var d = freshFixture();
  assert.equal(d.cves.length, 13);
  assert.equal(d.cves.filter(function (r) { return r.fresh === true; }).length, 5);
  assert.equal(d.cves_counts.fresh, 5);
  assert.ok(d.cves.some(function (r) { return r.fresh && r.signals.length === 0 && !r.pick_day; }), 'a fresh-only row with no signal');
  assert.ok(d.cves.some(function (r) { return r.fresh && r.signals.length === 0 && r.pick_day; }), 'a row that is fresh and a pick');
  assert.ok(d.cves.some(function (r) { return r.fresh && r.signals.length > 0; }), 'a fresh row an arm also admits');
  var r = CW.check(d, SOURCES, FRESH_NOW);
  assert.equal(r.status, 'PASS');
  assert.deepEqual(r.cveWarnings, []);
  assert.equal(r.counts.cves, 13);
});

test('T-0665 controls: data from before the fresh keys (picks fixture, or the fresh fixture stripped of them) still passes clean', function () {
  assert.deepEqual(CW.check(picksFixture(), SOURCES, PICKS_NOW).cveWarnings, []);
  var d = freshFixture();
  d.cves.forEach(function (r) { FRESH_KEYS_TEST.forEach(function (k) { delete r[k]; }); });
  delete d.cves_counts.fresh;
  // the rows that only a fresh key admitted now list no arm, which is the defect the keys excuse: those three are named, nothing else is
  var w = CW.check(d, SOURCES, FRESH_NOW).cveWarnings.filter(function (x) { return !/lists no selection arm/.test(x); });
  assert.deepEqual(w, []);
  var d2 = freshFixture();
  d2.cves = d2.cves.filter(function (r) { return !r.fresh; });
  d2.cves.forEach(function (r) { FRESH_KEYS_TEST.forEach(function (k) { delete r[k]; }); });
  delete d2.cves_counts.fresh;
  d2.cves_counts.total = d2.cves.length; d2.cves_counts.critical = 0; d2.cves_counts.high = 0; d2.cves_counts.medium = 0; d2.cves_counts.nuclei = 0;
  d2.cves_counts.epss90 = 0; d2.cves_counts.msf = 0; d2.cves_counts.picks = 2; d2.cves_counts.picks_today = 1;
  d2.cves.forEach(function (r) { if (SEV_BANDS_TEST.indexOf(r.severity) !== -1) d2.cves_counts[r.severity]++; if (r.msf.length) d2.cves_counts.msf++; if (r.nuclei) d2.cves_counts.nuclei++; if (Number(r.epss_pct) >= 0.9) d2.cves_counts.epss90++; });
  d2.cve_vendors = [{ label: 'Fixture', count: d2.cves.length }];
  assert.deepEqual(CW.check(d2, SOURCES, FRESH_NOW).cveWarnings, []);
});
var SEV_BANDS_TEST = ['critical', 'high', 'medium', 'low'];

test('T-0665 some fresh keys without the others are named, for each key left out', function () {
  FRESH_KEYS_TEST.forEach(function (k) {
    var d = freshFixture(); delete pickRow(d, 'CVE-2026-9105')[k];
    assert.match(freshWarn(d), new RegExp('9105\\).*only some fresh keys \\(' + FRESH_KEYS_TEST.filter(function (x) { return x !== k; }).join(', ') + '\\); the exporter writes all four or none'), k);
  });
});

test('T-0665 fresh types: flag, score, list, class label', function () {
  var d = freshFixture(); pickRow(d, 'CVE-2026-9105').fresh = 'yes';
  assert.match(freshWarn(d), /9105\).*has fresh "yes", not true or false/);
  d = freshFixture(); pickRow(d, 'CVE-2026-9105').fresh_score = '4';
  assert.match(freshWarn(d), /9105\).*fresh_score "4", not a whole number of 0 or more/);
  d = freshFixture(); pickRow(d, 'CVE-2026-9105').fresh_score = 4.5;
  assert.match(freshWarn(d), /9105\).*fresh_score 4.5, not a whole number/);
  d = freshFixture(); pickRow(d, 'CVE-2026-9105').fresh_score = -1;
  assert.match(freshWarn(d), /9105\).*fresh_score -1, not a whole number/);
  d = freshFixture(); pickRow(d, 'CVE-2026-9105').fresh_reasons = 'class';
  assert.match(freshWarn(d), /9105\).*fresh_reasons that are not a list/);
  d = freshFixture(); pickRow(d, 'CVE-2026-9105').fresh_class = 'Printers';
  assert.match(freshWarn(d), /9105\).*unknown fresh_class "Printers"/);
  d = freshFixture(); pickRow(d, 'CVE-2026-9105').fresh_class = 7;
  assert.match(freshWarn(d), /9105\).*fresh_class that is not text/);
});

test('T-0665 fresh_reasons: out of order, repeated, unknown, and the pick-only reasons are named', function () {
  var d = freshFixture(); pickRow(d, 'CVE-2026-9105').fresh_reasons = ['critical', 'noauth', 'class'];
  assert.match(freshWarn(d), /9105\).*fresh reason noauth out of order or twice \(order: nomi, ssvc, noauth, critical, class\)/);
  d = freshFixture(); pickRow(d, 'CVE-2026-9105').fresh_reasons = ['noauth', 'noauth', 'class'];
  assert.match(freshWarn(d), /9105\).*out of order or twice/);
  d = freshFixture(); pickRow(d, 'CVE-2026-9105').fresh_reasons = ['noauth', 'luck', 'class'];
  assert.match(freshWarn(d), /9105\).*unknown fresh reason "luck"/);
  // a new CVE has no tooling and no EPSS history: those two pick reasons are not fresh reasons
  ['tooling', 'epss90'].forEach(function (t) {
    d = freshFixture(); pickRow(d, 'CVE-2026-9105').fresh_reasons = [t, 'noauth', 'class'];
    assert.match(freshWarn(d), new RegExp('9105\\).*unknown fresh reason "' + t + '"'), t);
  });
});

test('T-0665 fresh_class is a known class label if and only if class is a reason', function () {
  var d = freshFixture(); pickRow(d, 'CVE-2026-9105').fresh_class = '';
  assert.match(freshWarn(d), /9105\).*class reason but fresh_class is empty/);
  d = freshFixture(); pickRow(d, 'CVE-2026-9106').fresh_class = 'File transfer';
  assert.match(freshWarn(d), /9106\).*fresh_class but does not list the class reason/);
  // every pick class label is accepted
  ['Edge and network device', 'File transfer', 'IT and remote management', 'Identity and access', 'Virtualization and backup', 'Email and collaboration',
    'Operating system or browser', 'Enterprise application', 'CMS core'].forEach(function (c) {
    d = freshFixture(); pickRow(d, 'CVE-2026-9105').fresh_class = c; pickRow(d, 'CVE-2026-9105').fresh_score = c === 'Operating system or browser' ? 3 : 4;
    assert.doesNotMatch(freshWarn(d), /9105/, c);
  });
});

test('T-0665 a row that is not fresh scores 0 and carries no reasons and no class', function () {
  var d = freshFixture(); pickRow(d, 'CVE-2026-9104').fresh_score = 2;
  assert.match(freshWarn(d), /9104\).*fresh_score 2 but is not fresh/);
  d = freshFixture(); pickRow(d, 'CVE-2026-9104').fresh_reasons = ['nomi'];
  assert.match(freshWarn(d), /9104\).*fresh reasons but is not fresh/);
  d = freshFixture(); pickRow(d, 'CVE-2026-9104').fresh_class = 'File transfer';
  assert.match(freshWarn(d), /9104\).*fresh_class but is not fresh/);
});

test('T-0665 the score is what the reasons earn: 2 for a class (1 for an operating system or browser), 1 for each other', function () {
  var d = freshFixture(); pickRow(d, 'CVE-2026-9105').fresh_score = 3;
  assert.match(freshWarn(d), /9105\).*fresh_score 3 but its reasons add up to 4/);
  d = freshFixture(); pickRow(d, 'CVE-2026-9105').fresh_class = 'Operating system or browser';
  assert.match(freshWarn(d), /9105\).*fresh_score 4 but its reasons add up to 3/);
  // a fresh row may score 0 with no reason
  d = freshFixture(); Object.assign(pickRow(d, 'CVE-2026-9106'), { fresh_score: 0, fresh_reasons: [] });
  d.cves_counts.fresh = 5;
  assert.doesNotMatch(freshWarn(d), /9106/);
});

test('T-0665 a Just published row may list no signal; a row that is neither fresh nor a pick still needs one', function () {
  var d = freshFixture();
  assert.equal(pickRow(d, 'CVE-2026-9105').signals.length, 0);
  assert.equal(pickRow(d, 'CVE-2026-9106').signals.length, 0);
  assert.doesNotMatch(freshWarn(d), /lists no selection arm/);
  // the same row, not fresh: nothing admits it
  pickRow(d, 'CVE-2026-9106').fresh = false; Object.assign(pickRow(d, 'CVE-2026-9106'), { fresh_score: 0, fresh_reasons: [] });
  d.cves_counts.fresh = 4;
  assert.match(freshWarn(d), /9106\).*lists no selection arm/);
  // a fresh row's signals are still held to its facts
  d = freshFixture(); pickRow(d, 'CVE-2026-9105').signals = ['msf'];
  assert.match(freshWarn(d), /9105\).*lists signal msf but the row shows no msf fact/);
});

test('T-0665 cves_counts.fresh is held to the rows when declared, and one not declared is not', function () {
  var d = freshFixture(); d.cves_counts.fresh = 6;
  assert.match(freshWarn(d), /cves_counts fresh disagrees with the rows: declared 6, actual 5/);
  d = freshFixture(); d.cves_counts.fresh = 0;
  assert.match(freshWarn(d), /cves_counts fresh disagrees with the rows: declared 0, actual 5/);
  d = freshFixture(); d.cves_counts.fresh = '5';
  assert.match(freshWarn(d), /cves_counts fresh is "5", not a whole number of 0 or more/);
  d = freshFixture(); d.cves_counts.fresh = -1;
  assert.match(freshWarn(d), /cves_counts fresh is -1, not a whole number/);
  d = freshFixture(); delete d.cves_counts.fresh;
  assert.deepEqual(CW.check(d, SOURCES, FRESH_NOW).cveWarnings, []);
});

test('T-0665 the cap of 250 counts the rows below the picks and the Just published rows', function () {
  var d = freshFixture();
  var keep = d.cves.filter(function (r) { return r.pick_day || r.fresh; });
  var nOut = keep.length;
  for (var i = 0; i < 250; i++) keep.push(Object.assign({}, pickRow(d, 'CVE-2026-9104'), { cve: 'CVE-2026-' + (9500 + i) }));
  d.cves = keep; d.cves_counts.total = keep.length; d.cves_counts.high = 0; d.cves_counts.critical = 0; d.cves_counts.medium = 0;
  d.cves_counts.msf = 0; d.cves_counts.nuclei = 250; d.cves_counts.epss90 = 0; d.cves_counts.picks = 3; d.cves_counts.picks_today = 2;
  d.cve_vendors = [{ label: 'Fixture', count: keep.length }];
  assert.doesNotMatch(freshWarn(d), /over the cap/);
  keep.push(Object.assign({}, pickRow(d, 'CVE-2026-9104'), { cve: 'CVE-2026-9999' }));
  assert.match(freshWarn(d), /251 rows besides 3 priority picks and 4 just published rows, over the cap of 250/);
  assert.ok(nOut > 3);
});

test('T-0665 a retired reason or a separate Priority group is still rejected beside fresh rows', function () {
  var page = fsPicks.readFileSync(pathPicks.join(__dirname, '..', '..', '..', 'wire', 'index.md'), 'utf8');
  var includes = {};
  fsPicks.readdirSync(pathPicks.join(__dirname, '..', '..', '..', '_includes')).filter(function (n) { return /^wire-/.test(n); })
    .forEach(function (n) { includes[n] = fsPicks.readFileSync(pathPicks.join(__dirname, '..', '..', '..', '_includes', n), 'utf8'); });
  assert.equal(CW.checkPage(page, includes).status, 'PASS');
  assert.equal(CW.checkPage(page + '\n<div class="hl-wire__day hl-wire__day--picks">', includes).status, 'FAIL');
});

test('T-0665 the page template: the Just published chip, marker, key and the not-evidence wording are pinned, and losing one fails the page check', function () {
  var page = fsPicks.readFileSync(pathPicks.join(__dirname, '..', '..', '..', 'wire', 'index.md'), 'utf8');
  var includes = {};
  fsPicks.readdirSync(pathPicks.join(__dirname, '..', '..', '..', '_includes')).filter(function (n) { return /^wire-/.test(n); })
    .forEach(function (n) { includes[n] = fsPicks.readFileSync(pathPicks.join(__dirname, '..', '..', '..', '_includes', n), 'utf8'); });
  assert.equal(CW.checkPage(page, includes).status, 'PASS');
  ['data-sig="fresh">Just published', 'assign c_fresh = c_fresh | plus: 1', 'class="hl-vuln__pick hl-vuln__fresh"', 'hl-pick__score hl-pick__score--fresh" title="Just published.',
    'hl-pick__score--fresh">Just published</span></dt><dd>', 'These rows are new and unproven', 'there is no evidence of exploitation for them yet',
    'not a sign that anyone is attacking it', 'The rows sit outside the cap of 250',
    'each of the last seven published days shows its three highest ranked CVEs as Just published rows'].forEach(function (pin) {
    assert.ok(page.includes(pin), pin);
    assert.equal(CW.checkPage(page.replace(pin, 'removed'), includes).status, 'FAIL', pin);
  });
  // the fold policy must keep skipping a fresh row
  var inc2 = Object.assign({}, includes, { 'wire-fold-keys.html': includes['wire-fold-keys.html'].replace('fold_row.fresh == true', 'fold_row.nope == true') });
  assert.equal(CW.checkPage(page, inc2).status, 'FAIL');
  // an unescaped fresh value is caught by the existing escaping check
  assert.equal(CW.checkPage(page.replace('{{ r.fresh_class | escape }}', '{{ r.fresh_class }}'), includes).status, 'FAIL');
  // the panel copy stays free of dashes
  assert.equal(CW.checkPage(page.replace('These rows are new and unproven', 'These rows are new and unproven — yes'), includes).status, 'FAIL');
});

test('T-0665 the fresh fixture is what the template draws: every fresh key a row carries is one the gate knows', function () {
  var d = freshFixture();
  d.cves.forEach(function (r) { FRESH_KEYS_TEST.forEach(function (k) { assert.ok(Object.prototype.hasOwnProperty.call(r, k), r.cve + ' lacks ' + k); }); });
});

/* T-0638: the nKEVs Priority group keys and counts (contract: tasks/runs/T-0638/contract.md).
   test/fixtures/np-wire.yml is w5b-wire.yml (old data, no np_ keys) with the four keys on every row,
   exactly 3 rows over the threshold of 5, and the counts to match. Data checks are WARN lines like
   every other row check here, so "fails" below means vulnWarnings name the defect. */
var NP_KEYS_TEST = ['np_score', 'np_reasons', 'np_class', 'np_rank'];
function npFixture() {
  return yamlPicks.load(fsPicks.readFileSync(pathPicks.join(__dirname, 'fixtures', 'np-wire.yml'), 'utf8'));
}
function npOld() {
  return yamlPicks.load(fsPicks.readFileSync(pathPicks.join(__dirname, 'fixtures', 'w5b-wire.yml'), 'utf8'));
}
function npWarn(d) { return CW.check(d, SOURCES, Date.parse(d.generated_at)).vulnWarnings.join('\n'); }
function npRow(d, cve) { return d.vulns.filter(function (r) { return r.cve === cve; })[0]; }

test('T-0638 control: the new fixture passes with no vuln warnings and exactly 3 ranked rows of 46', function () {
  var d = npFixture();
  assert.equal(d.vulns.length, 46);
  assert.equal(d.vulns.filter(function (r) { return r.np_rank > 0; }).length, 3);
  assert.deepEqual(d.vulns.filter(function (r) { return r.np_rank > 0; }).map(function (r) { return r.np_rank; }), [1, 2, 3]);
  assert.equal(d.vulns_counts.np_priority, 3);
  var r = CW.check(d, SOURCES, Date.parse(d.generated_at));
  assert.equal(r.status, 'PASS');
  assert.deepEqual(r.vulnWarnings, []);
  assert.equal(r.counts.vulns, 46);
});

test('T-0638 control: the old fixture (no np_ key, no np count) passes, with the same row count', function () {
  var d = npOld();
  assert.equal(d.vulns.length, 46);
  assert.ok(d.vulns.every(function (r) { return NP_KEYS_TEST.every(function (k) { return !(k in r); }); }));
  assert.ok(!('np_priority' in d.vulns_counts));
  var r = CW.check(d, SOURCES, Date.parse(d.generated_at));
  assert.equal(r.status, 'PASS');
  assert.deepEqual(r.vulnWarnings, []);
  assert.equal(r.counts.vulns, 46);
});

test('T-0638 the new fixture with every np_ key and count removed passes like the old data', function () {
  var d = npFixture();
  d.vulns.forEach(function (r) { NP_KEYS_TEST.forEach(function (k) { delete r[k]; }); });
  ['np_priority', 'np_threshold', 'np_classes'].forEach(function (k) { delete d.vulns_counts[k]; });
  assert.equal(npWarn(d), '');
});

test('T-0638 only some np_ keys on a row is named', function () {
  var d = npFixture();
  delete npRow(d, 'CVE-2026-9101').np_class;
  assert.match(npWarn(d), /9101\).*only some np_ keys \(np_score, np_reasons, np_rank\)/);
});

test('T-0638 np_reasons out of order, repeated or unknown are named', function () {
  var d = npFixture();
  npRow(d, 'CVE-2026-9101').np_reasons = ['noauth', 'tooling', 'class', 'cisa', 'fresh'];
  assert.match(npWarn(d), /9101\).*np reason class out of order or twice/);
  d = npFixture();
  npRow(d, 'CVE-2026-9101').np_reasons = ['noauth', 'luck', 'class', 'tooling', 'cisa', 'fresh'];
  assert.match(npWarn(d), /9101\).*unknown np reason "luck"/);
});

test('T-0638 np_score must equal the points of its reasons, and the class token must match np_class', function () {
  var d = npFixture();
  npRow(d, 'CVE-2026-9101').np_score = 9;
  assert.match(npWarn(d), /9101\).*np_score 9 but its reasons add up to 6/);
  d = npFixture();
  npRow(d, 'CVE-2026-9101').np_class = '';
  assert.match(npWarn(d), /9101\).*lists the class reason but np_class is empty/);
  d = npFixture();
  npRow(d, 'CVE-2026-9101').np_class = 'Quantum toasters';
  assert.match(npWarn(d), /9101\).*unknown np_class "Quantum toasters"/);
  // an operating system or browser class is worth 1 point: 9100 scores 6 with it
  d = npFixture();
  npRow(d, 'CVE-2026-9100').np_class = 'Edge and network device';
  assert.match(npWarn(d), /9100\).*np_score 6 but its reasons add up to 7/);
});

test('T-0638 the fresh reason needs an age_group of new when the row carries one', function () {
  var d = npFixture();
  npRow(d, 'CVE-2026-9101').age_group = 'mid';
  assert.match(npWarn(d), /9101\).*fresh reason but its age_group is "mid"/);
});

test('T-0638 np_rank must run 1..n in score order, and agree with the threshold', function () {
  var d = npFixture();
  npRow(d, 'CVE-2026-9104').np_rank = 5;
  assert.match(npWarn(d), /np_rank is not 1\.\.3 without gaps or repeats/);
  d = npFixture();
  npRow(d, 'CVE-2026-9100').np_score = 6;
  var r = npRow(d, 'CVE-2026-9101');
  r.np_reasons = ['noauth', 'class', 'cisa']; r.np_score = 4;
  assert.match(npWarn(d), /9101 has np_rank but np_score 4 is under np_threshold 5/);
  d = npFixture();
  var low = d.vulns.filter(function (x) { return x.np_rank === 0; })[0];
  low.np_score = 6; low.np_reasons = ['noauth', 'critical', 'class', 'tooling', 'cisa']; low.np_class = 'Edge and network device';
  assert.match(npWarn(d), new RegExp(low.cve + ' scores 6 \\(threshold 5\\) but has no np_rank'));
});

test('T-0638 np counts are held to the rows when declared, and rows with ranks but no count are named', function () {
  var d = npFixture();
  d.vulns_counts.np_priority = 4;
  assert.match(npWarn(d), /np_priority disagrees with the rows: declared 4, actual 3/);
  d = npFixture();
  d.vulns_counts.np_classes = 'v9';
  assert.match(npWarn(d), /np_classes is "v9"/);
  d = npFixture();
  delete d.vulns_counts.np_priority;
  assert.match(npWarn(d), /rows carry 3 np_rank rows but vulns_counts has no np_priority/);
  d = npFixture();
  d.vulns_counts.np_threshold = -1;
  assert.match(npWarn(d), /np_threshold is -1/);
});

test('T-0638 np_top caps the group: over the cap warns, a full group may leave lower rows over the threshold out', function () {
  var d = npFixture();
  d.vulns_counts.np_top = 2;
  assert.match(npWarn(d), /the Priority group has 3 rows, over np_top 2/);
  d = npFixture();
  d.vulns_counts.np_top = 'ten';
  assert.match(npWarn(d), /np_top is "ten"/);
  // full group (np_top 3, 3 ranked): an unranked row at the threshold but not above the last ranked score is fine
  d = npFixture();
  d.vulns_counts.np_top = 3;
  var ranked = d.vulns.filter(function (x) { return x.np_rank > 0; }).sort(function (a, b) { return a.np_rank - b.np_rank; });
  var last = ranked[ranked.length - 1].np_score;
  var low = d.vulns.filter(function (x) { return x.np_rank === 0; })[0];
  low.np_score = 5; low.np_reasons = ['noauth', 'class', 'tooling', 'cisa']; low.np_class = 'Edge and network device';
  if (last >= 5) assert.doesNotMatch(npWarn(d), new RegExp(low.cve + ' scores'));
  // but an unranked row that outscores the last ranked row is still named
  low.np_score = 7; low.np_reasons = ['noauth', 'critical', 'class', 'tooling', 'cisa', 'fresh']; low.age_group = 'new';
  assert.match(npWarn(d), new RegExp(low.cve + ' scores 7 \\(threshold 5, group full at 3\\) but has no np_rank'));
});

test('T-0638 the page template: the Priority group, its chip, strip and panel text are pinned, and losing one fails the page check', function () {
  var page = fsPicks.readFileSync(pathPicks.join(__dirname, '..', '..', '..', 'wire', 'index.md'), 'utf8');
  var includes = {};
  fsPicks.readdirSync(pathPicks.join(__dirname, '..', '..', '..', '_includes')).filter(function (n) { return /^wire-/.test(n); })
    .forEach(function (n) { includes[n] = fsPicks.readFileSync(pathPicks.join(__dirname, '..', '..', '..', '_includes', n), 'utf8'); });
  assert.equal(CW.checkPage(page, includes).status, 'PASS');
  ['class="hl-pstrip" id="vulns-priority"', 'data-sig="np">Priority group', 'sort: "np_rank"', 'hl-vuln__np', 'class="hl-pstrip__new">new</span>', 'The Priority strip at the top of this tab', 'the row stays in its own day with its Priority badge', 'my patch-first order',
    'needs 5 points', 'The strip holds the highest-scoring rows', 'The strip holds every row that scores 5 or more points', 'product classes are my judgment', 'I have not measured it'].forEach(function (pin) {
    assert.ok(page.includes(pin), pin);
    assert.equal(CW.checkPage(page.replace(pin, 'removed'), includes).status, 'FAIL', pin);
  });
  // T-0641: a Priority group put back in the day loop fails the page check; priority rows live in their days
  assert.equal(CW.checkPage(page.replace('<h2 class="hl-wire__day" id="vulns-{{ day_group.name', '<h2 class="hl-wire__day hl-wire__day--np" id="vulns-{{ day_group.name'), includes).status, 'FAIL');
  // an unescaped np_class is caught by the existing escaping check
  assert.equal(CW.checkPage(page.replace('{{ r.np_class | escape }}', '{{ r.np_class }}'), includes).status, 'FAIL');
  assert.equal(CW.checkPage(page.replace('so I have not measured it', 'so I have not measured it — yet'), includes).status, 'FAIL');
});

/* T-0667: the nKEVs event day (R1), the Priority group without a cap and one row per product (R2), the WordPress fold at
   five (R3) and the canary and ransomware flags (R4). Contract: tasks/runs/T-0667/contract.md. Fixture
   test/fixtures/event-wire.yml (generator tasks/runs/T-0667/p2-make-fixture.js): 33 rows, 5 moved by their event day, 5 ranked,
   two 5+ Fixture Firewall rows unranked, two WordPress folds of 5, one 4-row WordPress day, a CISA-only row and an old-shape row.
   Data checks are WARN lines like every row check here, so "fails" below means vulnWarnings name the defect. */
var EV_KEYS_TEST = ['event', 'event_src', 'first_seen', 'canary', 'ransomware'];
function evFixture() {
  return yamlPicks.load(fsPicks.readFileSync(pathPicks.join(__dirname, 'fixtures', 'event-wire.yml'), 'utf8'));
}
var evWarn = npWarn, evRow = npRow;
function evGateWith(from, to) {
  // The gate's own source with one expression changed: a mutation control, so a test that cannot tell the gate is broken shows up.
  var Module = require('module');
  var file = pathPicks.join(__dirname, '..', 'lib', 'check-wire.js');
  var src = fsPicks.readFileSync(file, 'utf8');
  assert.ok(src.includes(from), 'mutation anchor missing: ' + from);
  var m = new Module(file, module);
  m.filename = file;
  m.paths = Module._nodeModulePaths(pathPicks.dirname(file));
  m._compile(src.replace(from, to), file);
  return m.exports;
}

test('T-0667 control: the event fixture passes with no vuln warnings; its cases are all there', function () {
  var d = evFixture();
  var r = CW.check(d, SOURCES, Date.parse(d.generated_at));
  assert.equal(r.status, 'PASS');
  assert.deepEqual(r.vulnWarnings, []);
  assert.deepEqual(r.cveWarnings, []);
  assert.equal(d.vulns.length, 33);
  assert.equal(r.counts.vulns, 33);
  var src = function (s) { return d.vulns.filter(function (x) { return x.event_src === s; }); };
  assert.equal(src('vulncheck').length + src('cisa').length + src('first_seen').length + d.vulns.filter(function (x) { return !('event' in x); }).length, 33);
  assert.ok(src('cisa').length >= 2 && src('first_seen').length >= 2 && src('vulncheck').length > 10);
  assert.equal(d.vulns.filter(function (x) { return x.event && x.event !== x.added; }).length, d.vulns_counts.event_moved);
  assert.equal(d.vulns.filter(function (x) { return x.canary; }).length, 2);
  assert.equal(d.vulns.filter(function (x) { return x.ransomware; }).length, 2);
  var cisaOnly = evRow(d, 'CVE-2026-9306');
  assert.deepEqual([cisaOnly.reports.length, cisaOnly.event === cisaOnly.added, cisaOnly.event_src], [0, true, 'cisa']);
  assert.equal(d.vulns_counts.np_per_product, true);
  assert.ok(!('np_top' in d.vulns_counts));
  assert.equal(d.vulns.filter(function (x) { return x.np_score >= 5; }).length, 7);
  assert.equal(d.vulns.filter(function (x) { return x.np_rank > 0; }).length, 5);
});

test('T-0667 control: the fixture with the event keys, the new counts and the Priority keys removed passes like the data before them', function () {
  var d = evFixture();
  d.vulns.forEach(function (r) { EV_KEYS_TEST.concat(NP_KEYS_TEST).forEach(function (k) { delete r[k]; }); });
  ['cisa_admitted', 'cisa_missing', 'event_moved', 'np_per_product', 'np_priority', 'np_threshold', 'np_classes'].forEach(function (k) { delete d.vulns_counts[k]; });
  // the batch whose fifth member came from its event day is a four-row day in the old shape: no batch, none declared
  var moved = d.vulns.filter(function (x) { return x.batch && x.batch !== 'wp-' + x.added; })[0].batch;
  d.vulns.forEach(function (r) { if (r.batch === moved) delete r.batch; });
  d.vulns_counts.batches = d.vulns_counts.batches.filter(function (b) { return b.key !== moved; });
  assert.equal(d.vulns_counts.batches.length, 1);
  assert.equal(evWarn(d), '');
});

test('T-0667 control: the same fixture with only the event keys and new counts removed still names the unranked 5+ rows (the old rule has no one-per-product)', function () {
  var d = evFixture();
  d.vulns.forEach(function (r) { EV_KEYS_TEST.forEach(function (k) { delete r[k]; }); });
  ['cisa_admitted', 'cisa_missing', 'event_moved', 'np_per_product'].forEach(function (k) { delete d.vulns_counts[k]; });
  var moved = d.vulns.filter(function (x) { return x.batch && x.batch !== 'wp-' + x.added; })[0].batch;
  d.vulns.forEach(function (r) { if (r.batch === moved) delete r.batch; });
  d.vulns_counts.batches = d.vulns_counts.batches.filter(function (b) { return b.key !== moved; });
  assert.equal(evWarn(d), 'CVE-2026-9302 scores 5 (threshold 5) but has no np_rank\nCVE-2026-9303 scores 5 (threshold 5) but has no np_rank');
});

test('T-0667 only some of the five event keys on a row is named; an unknown source, a bad day and a non-boolean flag too', function () {
  var d = evFixture();
  delete evRow(d, 'CVE-2026-9301').canary;
  assert.match(evWarn(d), /9301\).*only some event keys \(event, event_src, first_seen, ransomware\); the exporter writes all five or none/);
  d = evFixture();
  evRow(d, 'CVE-2026-9301').event_src = 'sauron';
  assert.match(evWarn(d), /9301\).*event_src "sauron", not one of vulncheck, cisa, first_seen/);
  d = evFixture();
  evRow(d, 'CVE-2026-9301').event = '2026-13-45';
  assert.match(evWarn(d), /9301\).*event "2026-13-45", not a real day/);
  d = evFixture();
  evRow(d, 'CVE-2026-9301').canary = 'yes';
  assert.match(evWarn(d), /9301\).*canary "yes", not true or false/);
  evRow(d, 'CVE-2026-9301').canary = false; evRow(d, 'CVE-2026-9301').ransomware = 1;
  assert.match(evWarn(d), /9301\).*ransomware 1, not true or false/);
  d = evFixture();
  evRow(d, 'CVE-2026-9304').first_seen = 'last week';
  assert.match(evWarn(d), /9304\).*first_seen "last week", not empty or a real day/);
});

test('T-0667 the event must follow from the three dates: each source, the 1-day boundary and the 2-day backdate', function () {
  var d = evFixture();
  // 9307: first seen one day after the VulnCheck date is the UTC boundary, not a move (control: passes as built)
  assert.equal(evWarn(d), '');
  var b = evRow(d, 'CVE-2026-9307');
  b.event = b.first_seen; b.event_src = 'first_seen';
  assert.match(evWarn(d), /9307\).*event 2026-11-17 from first_seen but its dates .* give 2026-11-16 from vulncheck/);
  // 9308: two days is a move
  d = evFixture();
  var c = evRow(d, 'CVE-2026-9308');
  c.event = c.added; c.event_src = 'vulncheck';
  assert.match(evWarn(d), /9308\).*give 2026-11-17 from first_seen/);
  // a CISA date later than the VulnCheck one moves the row to the CISA day; leaving it on the VulnCheck day is named
  d = evFixture();
  var e = evRow(d, 'CVE-2026-9304');
  e.event = e.added; e.event_src = 'vulncheck';
  assert.match(evWarn(d), /9304\).*give 2026-11-17 from cisa/);
  // a CISA date earlier than the VulnCheck one does not move it (9309); claiming it did is named
  d = evFixture();
  var f = evRow(d, 'CVE-2026-9309');
  f.event = f.cisa_added; f.event_src = 'cisa';
  assert.match(evWarn(d), /9309\).*event 2026-11-12 before its added day 2026-11-14/);
  // and a later CISA day than the VulnCheck one, with the row left on the VulnCheck day, is named (9304 above)
  // the ties: the VulnCheck day wins a tie with the CISA day
  d = evFixture();
  var g = evRow(d, 'CVE-2026-9301');   // added and cisa_added are both the fixture day
  assert.equal(g.event_src, 'vulncheck');
  g.event_src = 'cisa';
  assert.match(evWarn(d), /9301\).*give 2026-11-17 from vulncheck/);
  // an event day before the add day is named
  d = evFixture();
  var h = evRow(d, 'CVE-2026-9307');
  h.event = '2026-11-01';
  assert.match(evWarn(d), /9307\).*event 2026-11-01 before its added day 2026-11-16/);
});

test('T-0667 first seen counts only 2 or more days after the later of the VulnCheck and CISA dates', function () {
  var d = evFixture();
  var r = evRow(d, 'CVE-2026-9314');   // added 11th, CISA 16th, first seen 17th: one day after the later date, so the CISA day stands
  assert.deepEqual([r.event, r.event_src], ['2026-11-16', 'cisa']);
  assert.equal(evWarn(d), '');
  r.event = r.first_seen; r.event_src = 'first_seen';
  assert.match(evWarn(d), /9314\).*event 2026-11-17 from first_seen but its dates .* give 2026-11-16 from cisa/);
  // two days after the CISA day moves it
  d = evFixture();
  r = evRow(d, 'CVE-2026-9314');
  r.cisa_added = '2026-11-15'; r.event = '2026-11-17'; r.event_src = 'first_seen';
  assert.equal(evWarn(d), '');
});

test('T-0667 a CISA-only row is dated by the CISA day; the same row without a CISA day is named', function () {
  var d = evFixture();
  assert.equal(evWarn(d), '');
  var o = evRow(d, 'CVE-2026-9306');
  o.cisa_added = '';
  assert.match(evWarn(d), /9306\).*event 2026-11-16 from cisa but its dates/);
});

test('T-0667 the new counts are held to the rows when they can be', function () {
  var d = evFixture();
  d.vulns_counts.event_moved = 9;
  assert.match(evWarn(d), /event_moved disagrees with the rows: declared 9, actual 5/);
  d = evFixture();
  d.vulns_counts.cisa_admitted = 'two';
  assert.match(evWarn(d), /cisa_admitted is "two", not a whole number of 0 or more/);
  d.vulns_counts.cisa_admitted = 999;
  assert.match(evWarn(d), /cisa_admitted 999 is more than the 33 rows/);
  d = evFixture();
  d.vulns_counts.cisa_missing = -1;
  assert.match(evWarn(d), /cisa_missing is -1/);
  d = evFixture();
  d.vulns_counts.np_per_product = 'yes';
  assert.match(evWarn(d), /np_per_product is "yes", not true/);
  // data that declares event_moved but whose rows carry no event keys is not held to it (an exporter mid-roll-out)
  d = evFixture();
  d.vulns.forEach(function (r) { EV_KEYS_TEST.forEach(function (k) { delete r[k]; }); });
  d.vulns_counts.batches = [];
  d.vulns.forEach(function (r) { delete r.batch; });
  assert.doesNotMatch(evWarn(d), /event_moved/);
});

test('T-0667 one ranked row per product: a second ranked row of a product is named, and the mutated gate misses it (control)', function () {
  var d = evFixture();
  assert.equal(evWarn(d), '');
  // 9302 and 9303 are the unranked 5+ Fixture Firewall rows; rank 9302 as a sixth row
  evRow(d, 'CVE-2026-9302').np_rank = 6; d.vulns_counts.np_priority = 6;
  var w = evWarn(d);
  assert.match(w, /CVE-2026-9302 is a second ranked row for fixture firewall \(CVE-2026-9301 holds the rank\): np_per_product allows one/);
  // the mutation: the same gate with the one-per-product check switched off must not name it, so the assertion above is the check, not luck
  var mut = evGateWith("if (perProduct && rankedProducts[key]) warnings.push(", "if (false && rankedProducts[key]) warnings.push(");
  var mw = mut.check(d, SOURCES, Date.parse(d.generated_at)).vulnWarnings.join('\n');
  assert.doesNotMatch(mw, /second ranked row/);
  // a gate that stops recording the product's holder (the other half of the rule) is caught by the unranked-row check
  var mut2 = evGateWith("else rankedProducts[key] = r.cve;", "else rankedProducts[key] = '';");
  var d2 = evFixture();
  assert.match(mut2.check(d2, SOURCES, Date.parse(d2.generated_at)).vulnWarnings.join('\n'), /but has no np_rank and no ranked row of its product/);
});

test('T-0667 a row at the threshold with no rank is fine when its product has one, named when it does not', function () {
  var d = evFixture();
  assert.equal(d.vulns.filter(function (x) { return x.np_score >= 5 && x.np_rank === 0; }).length, 2);
  assert.equal(evWarn(d), '');
  // unrank the one Directory row: nothing else holds that product, so it is named
  var r = evRow(d, 'CVE-2026-9311');
  r.np_rank = 0; d.vulns_counts.np_priority = 4;
  assert.match(evWarn(d), /CVE-2026-9311 scores 5 \(threshold 5\) but has no np_rank and no ranked row of its product/);
  // old shape (no np_per_product): the same row is the old message, with no product rule
  var o = evFixture();
  delete o.vulns_counts.np_per_product;
  evRow(o, 'CVE-2026-9311').np_rank = 0; o.vulns_counts.np_priority = 4;
  assert.match(evWarn(o), /CVE-2026-9311 scores 5 \(threshold 5\) but has no np_rank/);
  // old shape: the unranked Firewall rows are now wrong too, since nothing excuses them
  assert.match(evWarn(o), /CVE-2026-9302 scores 5 \(threshold 5\) but has no np_rank/);
});

test('T-0667 the order inside the Priority group: score, then event day, then EPSS, then CVE id (new shape only)', function () {
  var d = evFixture();
  function swap(a, b) { var x = evRow(d, a), y = evRow(d, b), t = x.np_rank; x.np_rank = y.np_rank; y.np_rank = t; }
  // 9304 (rank 4, event 17th) and 9311 (rank 5, event 14th): swapped, the earlier event ranks above
  swap('CVE-2026-9304', 'CVE-2026-9311');
  assert.match(evWarn(d), /CVE-2026-9304 np_rank puts it below a row of the same score with an earlier event day/);
  // 9313 (rank 3, EPSS 0.60) and 9304 (rank 4, EPSS 0.05) share a score and an event day
  d = evFixture();
  swap('CVE-2026-9313', 'CVE-2026-9304');
  assert.match(evWarn(d), /CVE-2026-9313 np_rank puts it below a row of the same score and event day with a lower EPSS/);
  // equal EPSS: the higher CVE id ranks first
  d = evFixture();
  evRow(d, 'CVE-2026-9313').epss = '0.05'; evRow(d, 'CVE-2026-9313').epss_pct = '0.5';
  assert.equal(evWarn(d), '');
  swap('CVE-2026-9313', 'CVE-2026-9304');
  assert.match(evWarn(d), /CVE-2026-9313 np_rank puts it below a row with a higher CVE id at the same score, event day and EPSS/);
  // a missing EPSS ranks last
  d = evFixture();
  evRow(d, 'CVE-2026-9313').epss = ''; evRow(d, 'CVE-2026-9313').epss_pct = ''; evRow(d, 'CVE-2026-9313').epss_date = ''; evRow(d, 'CVE-2026-9313').epss_max = ''; evRow(d, 'CVE-2026-9313').epss_spark = '';
  assert.match(evWarn(d), /np_rank puts it below a row of the same score and event day with a lower EPSS/);
  // the old shape is held to score order only, as before
  d = evFixture();
  delete d.vulns_counts.np_per_product;
  swap('CVE-2026-9304', 'CVE-2026-9311');
  assert.doesNotMatch(evWarn(d), /earlier event day/);
});

test('T-0667 the cap: np_top, when an older exporter writes it, still caps the group; its absence does not', function () {
  var d = evFixture();
  assert.equal(evWarn(d), '');
  d.vulns_counts.np_top = 3;
  assert.match(evWarn(d), /the Priority group has 5 rows, over np_top 3/);
  d.vulns_counts.np_top = 5;
  assert.equal(evWarn(d), '');
});

test('T-0667 a WordPress batch is keyed by the event day and holds five rows or more', function () {
  var d = evFixture();
  var moved = d.vulns.filter(function (x) { return x.batch && x.batch !== 'wp-' + x.added; })[0];
  assert.ok(moved && moved.event_src === 'first_seen', 'the fixture has a batch member whose event day is not its added day');
  assert.equal(d.vulns_counts.batches.length, 2);
  assert.ok(d.vulns_counts.batches.every(function (b) { return b.n === 5; }));
  // keyed by its added day, the moved row's batch is named
  moved.batch = 'wp-' + moved.added;
  assert.match(evWarn(d), new RegExp(moved.cve + ' batch must match its WordPress event day'));
  // a declared batch under five is named; four was fine before only because the floor was twenty
  d = evFixture();
  d.vulns_counts.batches[0].n = 4;
  assert.match(evWarn(d), /vulns_counts batch differs from rows or has fewer than 5 rows/);
  d = evFixture();
  var key = d.vulns_counts.batches[0].key;
  d.vulns.filter(function (x) { return x.batch === key; })[0].wp = false;
  assert.match(evWarn(d), /batch must match its WordPress event day/);
});

test('T-0667 the page: the new template pins fail the page check when lost; the fold keys carry the event day', function () {
  var root = pathPicks.join(__dirname, '..', '..', '..');
  var page = fsPicks.readFileSync(pathPicks.join(root, 'wire', 'index.md'), 'utf8');
  var includes = {};
  fsPicks.readdirSync(pathPicks.join(root, '_includes')).filter(function (n) { return /^wire-/.test(n); })
    .forEach(function (n) { includes[n] = fsPicks.readFileSync(pathPicks.join(root, '_includes', n), 'utf8'); });
  assert.equal(CW.checkPage(page, includes).status, 'PASS');
  ['group_by_exp: "gr", "gr.event | default: gr.added"', 'assign vday = r.event | default: r.added', 'hl-vuln__ev hl-vuln__dates',
    'CISA KEV {{ dt_ev | escape }} &middot; VulnCheck {{ dt_vc | escape }}', 'First seen here {{ dt_ev | escape }} &middot; VulnCheck dated {{ dt_vc | escape }}',
    'hl-vuln__b hl-vuln__b--canary', 'hl-vuln__b hl-vuln__b--ransom', 'data-sig="canary">VulnCheck canary', 'data-sig="ransomware">Ransomware',
    'assign n_canary = n_canary | plus: 1', 'assign n_ransom = n_ransom | plus: 1', 'assign np_evd = r.event | default: r.added', 'r.evidence < r.added',
    'assign wp_batch_group_min = 5', 'at least 5 entries', 'A row in the Priority strip is never folded.', 'I group rows by the day of the latest exploitation event I know of for the CVE',
    'I group rows by the day VulnCheck added them', 'The strip holds every row that scores 5 or more points, with no cap, and lists one row per product',
    'canary network recorded exploitation of the CVE', 'Neither adds Priority points.', 'not in VulnCheck KEV'].forEach(function (pin) {
    assert.ok(page.includes(pin), 'the template carries: ' + pin);
    assert.equal(CW.checkPage(page.split(pin).join('removed'), includes).status, 'FAIL', pin);
  });
  var keys = includes['wire-fold-keys.html'];
  assert.ok(keys.includes('fold_row.event | default: fold_row.added'));
  var lost = Object.assign({}, includes, { 'wire-fold-keys.html': keys.split('fold_row.event | default: fold_row.added').join('fold_row.added') });
  assert.equal(CW.checkPage(page, lost).status, 'FAIL');
  // an unescaped date in the new chips is caught by the existing escaping check
  assert.equal(CW.checkPage(page.replace('{{ dt_ev | escape }} &middot; VulnCheck {{ dt_vc | escape }}', '{{ dt_ev }} &middot; VulnCheck {{ dt_vc | escape }}'), includes).status, 'FAIL');
});

/* T-0667: the built fixture page. Skipped unless HL_EVENT_SITE names a Jekyll build of the event fixture (wire.yml = event-wire.yml
   with generated_at moved to the build time); the counts below are the fixture's. NOT CHECKED when skipped, never a pass. */
test('T-0667 the built event fixture draws every case', { skip: process.env.HL_EVENT_SITE ? false : 'NOT CHECKED: set HL_EVENT_SITE to the Jekyll build of event-wire.yml' }, function () {
  var JSDOMlocal = require('jsdom').JSDOM;
  var html = fsPicks.readFileSync(pathPicks.join(process.env.HL_EVENT_SITE, 'wire', 'index.html'), 'utf8');
  var dom = new JSDOMlocal(html);
  var d = dom.window.document;
  var sec = d.getElementById('vulns');
  var rows = [].slice.call(sec.querySelectorAll('.hl-vuln'));
  assert.equal(rows.length, 33, 'rows drawn');
  var dated = rows.filter(function (r) { return r.querySelector('.hl-vuln__dates'); });
  var text = dated.map(function (r) { return r.querySelector('.hl-vuln__dates').textContent.replace(/\s+/g, ' ').trim(); });
  assert.equal(dated.length, 6, 'rows with a dates chip: ' + text.join(' | '));
  assert.ok(text.indexOf('CISA KEV 17 Nov · VulnCheck 3 Oct') > -1, text.join(' | '));
  assert.ok(text.indexOf('First seen here 17 Nov · VulnCheck dated 25 Oct') > -1, text.join(' | '));
  assert.ok(text.indexOf('CISA KEV 16 Nov · not in VulnCheck KEV') > -1, text.join(' | '));
  assert.equal(sec.querySelectorAll('.hl-vuln .hl-vuln__b--canary').length, 2);
  assert.equal(sec.querySelectorAll('.hl-vuln .hl-vuln__b--ransom').length, 2);
  assert.equal(sec.querySelectorAll('.hl-pstrip__list > li').length, 5, 'strip items');
  assert.equal(sec.querySelectorAll('.hl-vuln__np').length, 5, 'ranked rows carry the Priority strip');
  assert.equal(sec.querySelectorAll('[data-filter-batch]').length, 2, 'WordPress folds');
  [].slice.call(sec.querySelectorAll('[data-filter-batch]')).forEach(function (b) { assert.equal(b.querySelectorAll('.hl-vuln').length, 5); });
  // every day a row was added on is an anchor on the page (the digest headlines link #vulns-<added day>), whether or not any row sits under it
  var addedDays = Array.from(new Set(evFixture().vulns.map(function (x) { return x.added; })));
  var missing = addedDays.filter(function (day) { return !d.getElementById('vulns-' + day); });
  assert.deepEqual(missing, [], 'added days with no anchor');
  var aliases = [].slice.call(sec.querySelectorAll('.hl-wire__dayalias')).map(function (a) { return a.id; });
  assert.ok(aliases.length >= 3 && aliases.indexOf('vulns-2026-10-25') > -1 && aliases.indexOf('vulns-2026-10-03') > -1, 'alias anchors: ' + aliases.join(' '));
  assert.equal(addedDays.length, sec.querySelectorAll('h2.hl-wire__day').length + aliases.length, 'one anchor per added day, a heading or an alias');
  // the old-shape row sits under its added day with no dates chip and no flags
  var old = d.getElementById('cve-cve-2026-9312');
  assert.ok(old && !old.querySelector('.hl-vuln__dates') && !old.querySelector('.hl-vuln__b--canary'));
  assert.equal(old.getAttribute('data-day'), '2026-11-13');
  // a row dated by its event is under the event day heading and carries it as data-day
  var fs1 = d.getElementById('cve-cve-2015-9305');
  assert.equal(fs1.getAttribute('data-day'), '2026-11-17');
  assert.equal(fs1.closest('.hl-vuln-group').querySelector('h2').id, 'vulns-2026-11-17');
});

test('T-0667 the dates chip is kept ahead of the EPSS and tooling chips when a row cannot show every chip (wire-chips.js rank); with the rank removed it overflows', function () {
  var JSDOMc = require('jsdom').JSDOM;
  var src = fsPicks.readFileSync(pathPicks.join(__dirname, '..', '..', '..', 'assets', 'js', 'wire-chips.js'), 'utf8');
  var row = '<div class="hl-vuln" data-title="cve-2026-0001"><span class="hl-vuln__badges">' +
    '<span class="hl-vuln__p hl-vuln__ep"><span class="hl-vuln__p--epss">EPSS 1%</span></span>' +
    '<span class="hl-vuln__tool">Nuclei</span><span class="hl-vuln__ev hl-vuln__dates">CISA KEV 17 Nov</span>' +
    '<span class="hl-vuln__b hl-vuln__b--canary">VulnCheck canary</span><span class="hl-vuln__sev">HIGH</span>' +
    '<span class="hl-vuln__b hl-vuln__b--cisa">CISA KEV</span></span></div>';
  function shown(code) {
    var dom = new JSDOMc(row, { runScripts: 'outside-only' });
    dom.window.eval(code);   // unmeasured fallback: the priority chips only, at most four after the CVSS chip is counted
    var out = {};
    ['.hl-vuln__dates', '.hl-vuln__b--canary', '.hl-vuln__tool', '.hl-vuln__p--epss'].forEach(function (s) {
      var el = dom.window.document.querySelector(s); out[s] = !el.closest('.hl-vuln__badges > *').hidden;
    });
    dom.window.close();
    return out;
  }
  var real = shown(src);
  assert.equal(real['.hl-vuln__dates'], true);
  assert.equal(real['.hl-vuln__tool'], true);
  assert.equal(real['.hl-vuln__p--epss'], false);
  var mutated = shown(src.replace("if (chip.matches('.hl-vuln__dates')) return 1;", ''));
  assert.equal(mutated['.hl-vuln__dates'], false, 'control: without the rank the dates chip is hidden first');
});

/* T-0667 F2 (review r1). Fix D: the Priority product is the (vendor, product) pair as the exporter's product_key keeps it
   (wire_export.py: lower-cased, whitespace-collapsed, as a pair). Fix C: the three Liquid consumers of a CISA-only row. */
test('F2 D: (Acme Beta, Gamma) and (Acme, Beta Gamma) are two products; the same pair spelled with other case and spacing is one', function () {
  var d = evFixture();
  var a = evRow(d, 'CVE-2026-9304'), b = evRow(d, 'CVE-2026-9313');
  assert.ok(a.np_rank > 0 && b.np_rank > 0, 'both rows are ranked in the fixture');
  a.vendor = 'Acme Beta'; a.product = 'Gamma'; b.vendor = 'Acme'; b.product = 'Beta Gamma';
  assert.doesNotMatch(evWarn(d), /second ranked row/, 'the vendor/product boundary keeps them apart');
  // control: the same pair, differently cased and spaced, is one product and the second ranked row is named
  b.vendor = '  ACME   beta '; b.product = 'gamma';
  assert.match(evWarn(d), /CVE-2026-9304 is a second ranked row for acme beta gamma \(CVE-2026-9313 holds the rank\)/);
  // an unranked 5+ row is excused by a ranked row of the same pair only, not of a boundary-shifted pair
  var e = evFixture();
  evRow(e, 'CVE-2026-9302').vendor = 'Fixture'; evRow(e, 'CVE-2026-9302').product = 'Firewall';
  evRow(e, 'CVE-2026-9301').vendor = 'Fixture Firewall'; evRow(e, 'CVE-2026-9301').product = '';
  assert.match(evWarn(e), /CVE-2026-9302 scores 5 \(threshold 5\) but has no np_rank and no ranked row of its product/);
});
test('F2 D mutation control: the old joined-string key merges the two products, so the test above measures the boundary', function () {
  var mut = evGateWith("return v || p ? v + NP_KEY_SEP + p : '';", "return v || p ? v + ' ' + p : '';");
  var d = evFixture();
  var a = evRow(d, 'CVE-2026-9304'), b = evRow(d, 'CVE-2026-9313');
  a.vendor = 'Acme Beta'; a.product = 'Gamma'; b.vendor = 'Acme'; b.product = 'Beta Gamma';
  assert.match(mut.check(d, SOURCES, Date.parse(d.generated_at)).vulnWarnings.join('\n'), /second ranked row for acme beta gamma/);
});

var CO_TEMPLATES = ['wire/vulns.xml', '_includes/wire-agent-brief.html', '_includes/wire-agent-row.html', '_includes/wire-agent-detail.html'];
test('F2 C: each template that says VulnCheck for a kev row derives the CISA-only case from event_src cisa, added = cisa_added and no reports', function () {
  var root = pathPicks.join(__dirname, '..', '..', '..');
  CO_TEMPLATES.forEach(function (f) {
    var t = fsPicks.readFileSync(pathPicks.join(root, f), 'utf8');
    assert.match(t, /event_src == "cisa"/, f);
    assert.match(t, /cisa_added == \w+\.added/, f);
    assert.match(t, /reports \| size/, f);
    assert.match(t, /reports_more/, f);
  });
  // control: a template with the added-equals-cisa_added leg removed no longer matches the pin
  var t0 = fsPicks.readFileSync(pathPicks.join(root, 'wire/vulns.xml'), 'utf8');
  assert.doesNotMatch(t0.replace(/r\.cisa_added == r\.added/g, 'true'), /cisa_added == \w+\.added/);
  var brief = fsPicks.readFileSync(pathPicks.join(root, '_includes/wire-agent-brief.html'), 'utf8');
  assert.match(brief, /if b_co -%\}\{%- assign b_vc = false/);
  var xml = t0;
  assert.match(xml, /unless cisa_only %\}\s*<category term="vulncheck-kev"/);
});

test('F2 C the built event fixture: the CISA-only row (9306) is not VulnCheck KEV in the Atom feed and the agent files; a VulnCheck row (9301) still is', { skip: process.env.HL_EVENT_SITE ? false : 'NOT CHECKED: set HL_EVENT_SITE to the Jekyll build of event-wire.yml' }, function () {
  var site = process.env.HL_EVENT_SITE;
  var xml = fsPicks.readFileSync(pathPicks.join(site, 'wire', 'vulns.xml'), 'utf8');
  function entry(cve) { return (xml.match(/<entry>[\s\S]*?<\/entry>/g) || []).filter(function (e) { return e.indexOf('>' + cve) > -1 || e.indexOf(cve + ':') > -1; })[0]; }
  var co = entry('CVE-2026-9306'), vc = entry('CVE-2026-9301');
  assert.ok(co && vc, 'both entries are in the feed');
  assert.doesNotMatch(co, /vulncheck-kev|VulnCheck KEV label|to VulnCheck KEV/);
  assert.match(co, /<category term="cisa-kev"/);
  assert.match(co, /Added to CISA KEV 2026-11-16; not in VulnCheck KEV\./);
  assert.match(vc, /<category term="vulncheck-kev"/);
  assert.match(vc, /to VulnCheck KEV 20/);
  ['kevs.json', 'summary.json', 'all.json'].forEach(function (f) {
    var j = JSON.parse(fsPicks.readFileSync(pathPicks.join(site, 'wire', 'agent', f), 'utf8'));
    var rows = j.rows || j.kevs || (j.items) || [];
    var flat = JSON.stringify(j);
    assert.match(flat, /"id": ?"CVE-2026-9306", ?"list": ?"kev", ?"on_vulncheck_kev": ?false/, f);
    assert.match(flat, /"id": ?"CVE-2026-9301", ?"list": ?"kev", ?"on_vulncheck_kev": ?true/, f);
  });
  var detail = fsPicks.readFileSync(pathPicks.join(site, 'wire', 'agent', 'detail', 'd-f', 'index.html'), 'utf8');
  assert.match(detail, /Exploited: on CISA KEV since 2026-11-16, not in VulnCheck KEV/);
  var details = fsPicks.readFileSync(pathPicks.join(site, 'wire', 'details-nkev.json'), 'utf8');
  assert.ok(details.indexOf('"cve-2026-9306"') > -1, 'the details row exists (its panel text is tested in wire-details-dom.test.js)');
});
