'use strict';

var test = require('node:test');
var assert = require('node:assert');
var CW = require('../lib/check-wire.js');

var NOW = Date.parse('2026-08-19T12:00:00Z');

function doc(over) {
  var d = {
    generated_at: '2026-08-19T10:00:00Z',
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
   than four hours old. */

test('a stale local file fails only when origin is stale too', function () {
  // 10 hours old against the hourly timer, and origin is no fresher: the
  // timer really has stopped, which is the case this gate exists for.
  var r = CW.check(doc({ generated_at: '2026-08-19T02:00:00Z' }), SOURCES, NOW,
    { generated_at: '2026-08-19T02:00:00Z' });
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /stale/i);
  assert.match(r.problems.join(' '), /LXC-102/);
});

test('a stale local file against a fresh origin is NOT CHECKED, never FAIL', function () {
  // The everyday case: the generator pushed twelve times while this clone sat
  // untouched. Accusing LXC-102 here is the false alarm that spent the alarm.
  var r = CW.check(doc({ generated_at: '2026-08-19T02:00:00Z' }), SOURCES, NOW,
    { generated_at: '2026-08-19T11:00:00Z' });
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
  // 3 hours old: three missed hourly runs, still inside the four-hour threshold,
  // so a blip on the generator does not fail somebody else's publish.
  var r = CW.check(doc({ generated_at: '2026-08-19T09:00:00Z' }), SOURCES, NOW);
  assert.equal(r.status, 'PASS');
});

test('a file past the four-hour limit with origin equally stale fails', function () {
  // 5 hours old: five missed hourly runs, and origin holds the same file.
  var r = CW.check(doc({ generated_at: '2026-08-19T07:00:00Z' }), SOURCES, NOW,
    { generated_at: '2026-08-19T07:00:00Z' });
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

var PAGE_OK = [
  '{%- assign current_day = "" -%}',
  '{%- for i in wire.items -%}',
  '{%- assign day = i.date | date: "%Y-%m-%d" -%}',
  '{%- if day != current_day -%}',
  '{%- assign current_day = day -%}',
  '<div class="hl-wire__day" data-filter-group>{{ i.date | date: "%A %-d %B %Y" }}</div>',
  '{%- endif -%}',
  '<a class="hl-wire__item" data-kind="{{ i.kind }}" data-day="{{ day }}"></a>',
  '{%- endfor -%}',
  '<script defer src="{{ \'/assets/js/listing-filter.js\' | relative_url }}?v=10"></script>'
].join('\n');

test('the shipped page shape passes the page gate', function () {
  var r = CW.checkPage(PAGE_OK);
  assert.equal(r.status, 'PASS', r.problems.join(' | '));
});

test('an unreadable page is NOT CHECKED, never a pass', function () {
  var r = CW.checkPage(null);
  assert.equal(r.status, 'NOT CHECKED');
  assert.match(r.reason, /nothing was verified/i);
});

test('re-deriving the day on the row is caught as a second definition', function () {
  // Internally consistent today, and still two definitions of one rule.
  var bad = PAGE_OK.replace('data-day="{{ day }}"',
    'data-day="{{ i.date | date: \'%Y-%m-%d\' }}"');
  var r = CW.checkPage(bad);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /re-derives the day/i);
});

test('dropping data-day entirely is caught', function () {
  // The filter would then match nothing and the page would show everything,
  // which reads as a working control that quietly ignores the reader.
  var bad = PAGE_OK.replace(' data-day="{{ day }}"', '');
  var r = CW.checkPage(bad);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /no data-day/i);
});

test('losing the day assign is caught', function () {
  var bad = PAGE_OK.replace('{%- assign day = i.date | date: "%Y-%m-%d" -%}', '');
  var r = CW.checkPage(bad);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /share one derivation/i);
});

test('grouping headings on something other than `day` is caught', function () {
  var bad = PAGE_OK.replace('{%- if day != current_day -%}',
    '{%- if i.date != current_day -%}');
  var r = CW.checkPage(bad);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /no longer grouped on the `day` variable/i);
});

test('a missing cache-bust on the filter script is caught', function () {
  // New markup against a cached old script is invisible on a fresh browser and
  // total on a returning one. It has already happened here once.
  var bad = PAGE_OK.replace('?v=10', '');
  var r = CW.checkPage(bad);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /cache-bust/i);
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
