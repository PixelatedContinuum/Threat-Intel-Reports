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

/* The CVEs tab's structure (T-0522), in the smallest form the gate accepts. */
var VEDAS_CREDIT = "VEDAS exploit maturity from <a href=\"https://github.com/ARPSyndicate/cve-scores\">A.R.P. Syndicate</a>";
var VEDAS_LEGEND = "<dt class=\"hl-legend__k\">Exploit maturity (VEDAS)</dt>\n<dd>A.R.P. Syndicate describes VEDAS as &ldquo;Estimation of Vulnerability Prevalence &amp; Exploit Maturity&rdquo;. Its README names OSINT from <a href=\"https://www.exploit.observer/\" target=\"_blank\" rel=\"noopener noreferrer\">Exploit Observer</a>, coverage of 150+ identifiers and updates every 6 to 8 hours. The source publishes no formula. On the CVEs tab, I pair EPSS at least 1% with VEDAS at least 80% and CVSS at least 7.0 for the EPSS + maturity reason. A high score is not evidence that working exploit code exists or that the CVE has been exploited; exploitation is what the nKEVs tab and CISA KEV are for. An unscored CVE shows no maturity chip.</dd><p>VEDAS exploit maturity from <a href=\"https://github.com/ARPSyndicate/cve-scores\">A.R.P. Syndicate</a></p>";

var CVES_TAB_OK = [
  '<a class="hl-wtabs__tab hl-wtabs__tab--c" href="#cves">CVEs</a>',
  '<section id="cves" class="hl-wtabs__sec" data-filter-scope>',
  '<details class="hl-wire-explanation"><summary>Explanation and data used</summary><p>My CVE selection.</p></details>',
  '<p class="hl-wire__freshness hl-wire__freshness--c">CVEs: Listing, titles, SSVC (CISA\'s own assessment), fixed versions and advisory ids from <a href="https://cve.now/">cve.now</a> (<a href="https://creativecommons.org/licenses/by/4.0/">CC BY 4.0</a>) &middot; Scores from NVD through VulnCheck, or from cve.now where a row says so &middot; Exploits from Rapid7 and Exploit-DB &middot; KEV products from CISA &middot; EPSS from <a href="https://www.first.org/epss/">FIRST</a> &middot; ' + VEDAS_CREDIT + ' &middot; <a href="{{ \'/wire/cves.xml\' | relative_url }}">Atom feed (CVEs)</a></p>',
  '<div class="hl-wire__callout hl-wire__callout--c"><p>Nuclei templates come from ProjectDiscovery\'s template index; ET Open rules come from Emerging Threats\' Suricata ruleset. the tooling reasons together admitted 53 CVEs, eight later listed on VulnCheck KEV; Nuclei accounted for seven of 34.</p><p>My selection of CVEs published in the last 30 days that are not on a KEV list yet. Each is here for at least one of six reasons: a Metasploit module or Exploit-DB entry, confirmed against Rapid7\'s or Exploit-DB\'s own index; a Nuclei template; an ET Open rule; EPSS in the top 10%; or EPSS at least 1% paired with VEDAS exploit maturity at least 80% and CVSS at least 7.0.</p><p>Being listed does not mean anyone has been seen exploiting the CVE. "Product on CISA KEV" is a fact about the product, not this CVE. The list excludes anything on VulnCheck KEV or CISA KEV, and a CVE moves to the nKEVs tab when it is added to VulnCheck KEV. It shows at most 200 CVEs, ranked by how many reasons they meet, then by EPSS, then by exploit maturity, then by CVSS.</p></div>',
  '{%- capture cves_legend_html -%}',
  VEDAS_LEGEND,
  '<dl class="hl-legend__list"><dt><span class="hl-vuln__cve">CVE-YYYY-NNNN</span></dt><dd>The CVE.</dd></dl>',
  '<p class="hl-legend__p">I choose which CVEs appear here, by the rule above, and show at most 200. When more qualify, the 200 shown are ranked by how many reasons they meet, then by EPSS, then by exploit maturity, then by CVSS.</p>',
  '<p class="hl-legend__p">The CVE listing, titles, SSVC decision points (CISA\'s own assessment, from <a href="https://github.com/cisagov/vulnrichment">Vulnrichment</a>), fixed versions and advisory ids come from <a href="https://cve.now/">cve.now</a> (CC BY 4.0). CVSS scores and vectors come from the CVE\'s NVD record through VulnCheck, mostly the CNA\'s score, unless the row says cve.now. Metasploit modules come from Rapid7\'s <a href="https://github.com/rapid7/metasploit-framework">metasploit-framework</a> module index and Exploit-DB entries from <a href="https://www.exploit-db.com/">Exploit-DB</a>\'s own index. "Product on CISA KEV" comes from CISA\'s <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">KEV catalog</a>. EPSS scores are FIRST\'s (<a href="https://www.first.org/epss/">first.org/epss</a>), generated by Empirical Security.</p>',
  '{%- endcapture -%}',
  '<details class="hl-legend-mobile" data-pagefind-ignore><summary>Legend</summary>{{ cves_legend_html }}</details>',
  '<div class="hl-wire hl-vulns" data-filter-grid data-filter-item=".hl-vuln">',
  '{%- for r in g.items -%}<div class="hl-vuln" data-title="{{ r.cve | downcase | escape }}">{{ r.vendor | escape }}{{ c_msf }}{% include wire-vuln-new.html %}</div>{%- endfor -%}',
  '</div>',
  '<aside class="hl-post-toc hl-legend" aria-label="CVEs legend" data-pagefind-ignore>{{ cves_legend_html }}</aside>',
  '</section>'
].join('\n');
// The shared include that draws the cve.now chips: every output escaped, four link targets, no PoC.
var INC_OK = [
  '{%- comment -%} header {{ not code }} {%- endcomment -%}',
  '<span>{{ ss_e | escape }}</span>{{ ex_n }}{{ msf_len }}',
  '<a href="https://github.com/advisories/{{ al | uri_escape | escape }}">{{ al | escape }}</a>',
  '<a href="https://euvd.enisa.europa.eu/vulnerability/{{ al | uri_escape | escape }}">{{ al | escape }}</a>',
  '<a href="https://github.com/rapid7/metasploit-framework/blob/master/{{ m | uri_escape | escape }}">{{ m | split: \'/\' | last | escape }}</a>',
  '<a href="https://www.exploit-db.com/exploits/{{ e | uri_escape | escape }}">EDB-{{ e | escape }}</a>',
  '<span>{{ edb_len }} Exploit-DB entries</span>'
].join('\n');
var INCLUDES_OK = { 'wire-vuln-new.html': INC_OK };

var PAGE_OK = [
  // The tab nav (G3, r2): outside every section, three tab counts, each printed only while
  // its assign forces the value to a number. checkTabNav holds this region to the same rule
  // as the row templates, so the stub carries the pins.
  '{%- assign n_headlines = wire.counts.research | plus: wire.counts.news -%}',
  '{%- assign n_vulns = wire.vulns_counts.total | default: 0 | plus: 0 -%}',
  '{%- assign n_cves = wire.cves_counts.total | default: 0 | plus: 0 -%}',
  '<nav class="hl-wtabs__nav" aria-label="Sections of The Wire"><a class="hl-wtabs__tab hl-wtabs__tab--h" href="#headlines">Headlines<span class="hl-wtabs__n">{{ n_headlines }}</span></a><a class="hl-wtabs__tab hl-wtabs__tab--v" href="#vulns">nKEVs<span class="hl-wtabs__n">{{ n_vulns }}</span></a><a class="hl-wtabs__tab hl-wtabs__tab--c" href="#cves">CVEs<span class="hl-wtabs__n">{{ n_cves }}</span></a></nav>',
  '<section id="headlines" class="hl-wtabs__sec" data-filter-scope>',
  '{%- assign current_day = "" -%}',
  '{%- for i in wire.items -%}',
  '{%- assign day = i.date | date: "%Y-%m-%d" -%}',
  '{%- if day != current_day -%}',
  '{%- assign current_day = day -%}',
  '<div class="hl-wire__day" data-filter-group>{{ i.date | date: "%A %-d %B %Y" }}</div>',
  '{%- endif -%}',
  '<a class="hl-wire__item" data-kind="{{ i.kind }}" data-day="{{ day }}"></a>',
  '{%- endfor -%}',
  '</section>',
  '<section id="vulns" class="hl-wtabs__sec" data-filter-scope>',
  '<details class="hl-wire-explanation"><summary>Explanation and data used</summary><p>My nKEV ordering.</p></details>',
  // The nKEVs tab's shape (T-0468.1): the short attribution line, the legend captured once, printed
  // twice (the narrow details, then the aside after the grid), the grid itself with no legend in it.
  '<p class="hl-wire__freshness hl-wire__freshness--v">nKEVs: CVEs newly added &middot; Data: <a href="https://www.vulncheck.com/kev">VulnCheck KEV</a> &middot; EPSS from <a href="https://www.first.org/epss/">FIRST</a> &middot; ' + VEDAS_CREDIT + ' &middot; <a href="{{ \'/wire/vulns.xml\' | relative_url }}">Atom feed (nKEVs)</a></p>',
  '{%- capture legend_html -%}',
  VEDAS_LEGEND,
  '<dl class="hl-legend__list"><dt><span class="hl-vuln__cve">CVE-YYYY-NNNN</span></dt><dd>The CVE.</dd></dl>',
  '<p class="hl-legend__p">I do not curate this data. EPSS from FIRST, generated by Empirical Security: <a href="https://www.vulncheck.com/kev">vulncheck.com/kev</a> <a href="https://www.first.org/epss/">first.org/epss</a></p>',
  '{%- endcapture -%}',
  '<details class="hl-legend-mobile" data-pagefind-ignore><summary>Legend</summary>{{ legend_html }}</details>',
  '<div class="hl-wire hl-vulns" data-filter-grid data-filter-item=".hl-vuln">',
  '{%- for r in wire.vulns -%}',
  '<div class="hl-vuln">{% for rp in r.reports %}<a href="{{ rp.url | escape }}">x</a>{% endfor %}</div>',
  '{%- endfor -%}',
  '</div>',
  '<aside class="hl-post-toc hl-legend" aria-label="Legend" data-pagefind-ignore>{{ legend_html }}</aside>',
  '</section>',
  CVES_TAB_OK,
  '<script defer src="{{ \'/assets/js/listing-filter.js\' | relative_url }}?v=10"></script>'
].join('\n');

test('the shipped page shape passes the page gate', function () {
  var r = CW.checkPage(PAGE_OK, INCLUDES_OK);
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
  var r = CW.checkPage(bad, INCLUDES_OK);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /re-derives the day/i);
});

test('dropping data-day entirely is caught', function () {
  // The filter would then match nothing and the page would show everything,
  // which reads as a working control that quietly ignores the reader.
  var bad = PAGE_OK.replace(' data-day="{{ day }}"', '');
  var r = CW.checkPage(bad, INCLUDES_OK);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /no data-day/i);
});

test('losing the day assign is caught', function () {
  var bad = PAGE_OK.replace('{%- assign day = i.date | date: "%Y-%m-%d" -%}', '');
  var r = CW.checkPage(bad, INCLUDES_OK);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /share one derivation/i);
});

test('grouping headings on something other than `day` is caught', function () {
  var bad = PAGE_OK.replace('{%- if day != current_day -%}',
    '{%- if i.date != current_day -%}');
  var r = CW.checkPage(bad, INCLUDES_OK);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /no longer grouped on the `day` variable/i);
});

test('a missing cache-bust on the filter script is caught', function () {
  // New markup against a cached old script is invisible on a fresh browser and
  // total on a returning one. It has already happened here once.
  var bad = PAGE_OK.replace('?v=10', '');
  var r = CW.checkPage(bad, INCLUDES_OK);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /cache-bust/i);
});

/* ---- The nKEVs legend (T-0468.1) ----

   The explanatory text moved into a side legend. These pin the three guarantees that
   now live in the template's structure: the attribution stays above the filter bar,
   the samples are not countable or interactive, and the legend is printed twice from
   one capture and never inside the grid. Each test breaks one and expects the gate to
   name it. */

test('the shipped legend passes with its attribution above the filter bar', function () {
  var r = CW.checkPage(PAGE_OK, INCLUDES_OK);
  assert.equal(r.status, 'PASS', r.problems.join(' | '));
});

test('a page with no legend capture fails', function () {
  var bad = PAGE_OK.replace(/\{%- capture legend_html -%\}[\s\S]*\{%- endcapture -%\}\n/, '');
  var r = CW.checkPage(bad, INCLUDES_OK);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /legend is missing/i);
});

test('the attribution links moved out of the short line into the legend only is caught', function () {
  var bad = PAGE_OK.replace('Data: <a href="https://www.vulncheck.com/kev">VulnCheck KEV</a> &middot; ', '');
  var r = CW.checkPage(bad, INCLUDES_OK);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /no longer links vulncheck\.com\/kev/i);
});

test('losing the "I do not curate" statement or the EPSS attribution is caught', function () {
  var r1 = CW.checkPage(PAGE_OK.replace('I do not curate this data. ', ''), INCLUDES_OK);
  assert.equal(r1.status, 'FAIL');
  assert.match(r1.problems.join(' '), /not curated here/i);
  var r2 = CW.checkPage(PAGE_OK.replace(', generated by Empirical Security', ''), INCLUDES_OK);
  assert.equal(r2.status, 'FAIL');
  assert.match(r2.problems.join(' '), /Empirical Security/i);
});

test('a data-* attribute on a legend sample is caught', function () {
  // listing-filter.js would read it as a filter value and count the sample.
  var bad = PAGE_OK.replace('<span class="hl-vuln__cve">', '<span class="hl-vuln__cve" data-sev="high">');
  var r = CW.checkPage(bad, INCLUDES_OK);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /data-\* attribute/i);
});

test('an interactive sample (a details, a button, an id) in the legend is caught', function () {
  var det = CW.checkPage(PAGE_OK.replace('<dd>The CVE.</dd>', '<dd><details><summary>EPSS</summary></details></dd>'), INCLUDES_OK);
  assert.equal(det.status, 'FAIL');
  assert.match(det.problems.join(' '), /control or details/i);
  var id = CW.checkPage(PAGE_OK.replace('<dd>The CVE.</dd>', '<dd id="x">The CVE.</dd>'), INCLUDES_OK);
  assert.equal(id.status, 'FAIL');
  assert.match(id.problems.join(' '), /carries an id/i);
});

test('a sample chip written as a link, not a span, is caught', function () {
  var bad = PAGE_OK.replace('<span class="hl-vuln__cve">CVE-YYYY-NNNN</span>',
    '<a class="hl-vuln__cve" href="https://nvd.nist.gov/vuln/detail/CVE-1">CVE-YYYY-NNNN</a>');
  var r = CW.checkPage(bad, INCLUDES_OK);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /sample chip must be a span/i);
});

test('printing the legend once, or three times, is caught', function () {
  var once = CW.checkPage(PAGE_OK.replace('<details class="hl-legend-mobile" data-pagefind-ignore><summary>Legend</summary>{{ legend_html }}</details>',
    '<details class="hl-legend-mobile" data-pagefind-ignore><summary>Legend</summary></details>'), INCLUDES_OK);
  assert.equal(once.status, 'FAIL');
  assert.match(once.problems.join(' '), /printed 1 time/i);
});

test('an aside without its aria-label, or without the TOC class, is caught', function () {
  var r1 = CW.checkPage(PAGE_OK.replace(' aria-label="Legend"', ''), INCLUDES_OK);
  assert.equal(r1.status, 'FAIL');
  assert.match(r1.problems.join(' '), /aside is missing/i);
  var r2 = CW.checkPage(PAGE_OK.replace('class="hl-post-toc hl-legend"', 'class="hl-legend"'), INCLUDES_OK);
  assert.equal(r2.status, 'FAIL');
});

test('the legend printed inside the vulnerability grid is caught', function () {
  var bad = PAGE_OK.replace('<div class="hl-vuln">{% for rp in r.reports %}',
    '<div class="hl-vuln">{{ legend_html }}{% for rp in r.reports %}');
  var r = CW.checkPage(bad, INCLUDES_OK);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /inside the vulnerability grid/i);
});

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
test('the tab nav region (the page outside its sections) follows the escaping rule; a raw count print there is caught', function () {
  assert.equal(CW.checkPage(PAGE_OK, INCLUDES_OK).status, 'PASS');
  // Same raw print, but sourced straight from the data instead of the forced numbers.
  var raw = PAGE_OK.replace(
    '<span class="hl-wtabs__n">{{ n_cves }}</span></a></nav>',
    '<span class="hl-wtabs__n">{{ wire.cves_counts.total }}</span></a></nav>');
  var r = CW.checkPage(raw, INCLUDES_OK);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' | '), /tab nav region .* prints \{\{ wire\.cves_counts\.total \}\} without escape/);
});

test('a hostile print in the tab nav region is seen; the same print inside a section is that section checker\'s, not this one\'s', function () {
  // The un-stripped scan is region-scoped: a raw data print inside a section is not this
  // checker's finding (the section checkers own it), so checkTabNav alone must stay silent.
  assert.equal(CW.checkTabNav(PAGE_OK).join(' '), '');
  // strip only complete section spans: a <section> with no close leaves its whole body in
  // the checked region instead of silently widening to EOF
  var dangling = PAGE_OK.replace('<section id="headlines" class="hl-wtabs__sec" data-filter-scope>', '');
  assert.match(CW.checkTabNav(dangling).join(' '), /tab nav region .* without escape/);
});

test('reverting the number forcing on any tab count fails the gate (W: 3 pins)', function () {
  var force = {
    n_headlines: '{%- assign n_headlines = wire.counts.research | plus: wire.counts.news -%}',
    n_vulns: '{%- assign n_vulns = wire.vulns_counts.total | default: 0 | plus: 0 -%}',
    n_cves: '{%- assign n_cves = wire.cves_counts.total | default: 0 | plus: 0 -%}'
  };
  assert.equal(CW.checkPage(PAGE_OK, INCLUDES_OK).status, 'PASS');
  var unforced = {
    n_headlines: '{%- assign n_headlines = wire.counts.research -%}',
    n_vulns: '{%- assign n_vulns = wire.vulns_counts.total | default: 0 -%}',
    n_cves: '{%- assign n_cves = wire.cves_counts.total | default: 0 -%}'
  };
  Object.keys(force).forEach(function (k) {
    assert.ok(PAGE_OK.indexOf(force[k]) > -1, k + ' pin anchor missing');
    var r = CW.checkPage(PAGE_OK.replace(force[k], unforced[k]), INCLUDES_OK);
    assert.equal(r.status, 'FAIL', k + ' un-forced');
    assert.match(r.problems.join(' | '), /is no longer forced to a number in its assign/);
    assert.match(r.problems.join(' | '), new RegExp('tab count ' + k));
  });
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
  for (var i = 0; i < 200; i++) many.push(cvrow({ cve: 'CVE-2026-' + (9000 + i) }));
  assert.doesNotMatch(CW.check(cvdoc(many), SOURCES, NOW).cveWarnings.join(' '), /over the cap/);
  many.push(cvrow({ cve: 'CVE-2026-9200' }));
  assert.match(CW.check(cvdoc(many), SOURCES, NOW).cveWarnings.join(' '), /201 rows, over the cap of 200/);
  assert.match(CW.check(cvdoc([]), SOURCES, NOW).cveWarnings.join(' '), /ok but there are no rows/);
});

/* ---- The CVEs tab, as structure (T-0522) ---- */

test('the CVEs tab stub passes the page gate (control)', function () {
  var r = CW.checkPage(PAGE_OK, INCLUDES_OK);
  assert.equal(r.status, 'PASS', r.problems.join(' | '));
});

test('a page with no CVEs section, no tab link, or a section outside the filter scope is caught', function () {
  var gone = CW.checkPage(PAGE_OK.replace('<section id="cves" class="hl-wtabs__sec" data-filter-scope>', '<section id="other">'), INCLUDES_OK);
  assert.equal(gone.status, 'FAIL');
  assert.match(gone.problems.join(' '), /CVEs tab is missing/);
  var scope = CW.checkPage(PAGE_OK.replace('<section id="cves" class="hl-wtabs__sec" data-filter-scope>', '<section id="cves">'), INCLUDES_OK);
  assert.match(scope.problems.join(' '), /lost its hl-wtabs__sec class or data-filter-scope/);
  var nav = CW.checkPage(PAGE_OK.replace(/href="#cves"/g, 'href="#cve"'), INCLUDES_OK);
  assert.match(nav.problems.join(' '), /no link to #cves/);
});

test('the callout losing a public claim is caught, claim by claim', function () {
  [["My selection", /my selection/], ["does not mean anyone has been seen exploiting", /not evidence of exploitation/],
   ["excludes anything on VulnCheck KEV or CISA KEV", /excludes anything on VulnCheck KEV or CISA KEV/],
   ["moves to the nKEVs tab when", /moves to the nKEVs tab/],
   ["is a fact about the product", /fact about the product/],
   ["six reasons", /six admission reasons/],
   ["a Nuclei template; an ET Open rule", /two new tooling reasons/],
   ["top 10%", /EPSS arm in plain words/],
   ["confirmed against Rapid7's or Exploit-DB's own index", /confirmed against the publishers/],
   ["(CISA's own assessment)", /CISA's own assessment/], [">CC BY 4.0<", /licence/]].forEach(function (c) {
    assert.ok(PAGE_OK.indexOf(c[0]) > -1, 'stub lacks ' + c[0]);
    var r = CW.checkPage(PAGE_OK.replace(c[0], 'XX'), INCLUDES_OK);
    assert.equal(r.status, 'FAIL', c[0]);
    assert.match(r.problems.join(' '), c[1]);
  });
  var line = CW.checkPage(PAGE_OK.replace('cves.xml', 'x.xml'), INCLUDES_OK);
  assert.match(line.problems.join(' '), /no longer links cves\.xml/);
  // T-0531: each link on the attribution line is its own pin; the text still names cve.now when its link goes
  [['<a href="https://cve.now/">cve.now</a> (<a', 'cve.now (<a', /no longer links href="https:\/\/cve\.now\//],
   ['KEV products from CISA &middot; EPSS from <a href="https://www.first.org/epss/">FIRST</a>', 'KEV products from CISA &middot; EPSS from FIRST', /no longer links href="https:\/\/www\.first\.org\/epss\//]].forEach(function (c) {
    assert.ok(PAGE_OK.indexOf(c[0]) > -1, 'stub lacks ' + c[0]);
    var r = CW.checkPage(PAGE_OK.replace(c[0], c[1]), INCLUDES_OK);
    assert.equal(r.status, 'FAIL', c[0]);
    assert.match(r.problems.join(' '), c[2]);
  });
});

test('any mention of a GitHub proof of concept on the page or in the include is caught (Revision 2)', function () {
  var page = CW.checkPage(PAGE_OK.replace('<dd>The CVE.</dd>', '<dd>Counts GitHub PoC repositories.</dd>'), INCLUDES_OK);
  assert.equal(page.status, 'FAIL');
  assert.match(page.problems.join(' '), /the page mentions a GitHub proof of concept/);
  var prose = CW.checkPage(PAGE_OK.replace('not on a KEV list yet.', 'not on a KEV list yet. I count every proof of concept.'), INCLUDES_OK);
  assert.match(prose.problems.join(' '), /the page mentions a GitHub proof of concept/);
  var inc = CW.checkPage(PAGE_OK, { 'wire-vuln-new.html': INC_OK + '\n<span>{{ poc_n }} public repositories</span>' });
  assert.match(inc.problems.join(' '), /wire-vuln-new\.html mentions a GitHub proof of concept/);
  // control: SSVC's own exploitation value "poc" is CISA's assessment, drawn from data, not a PoC claim of ours
  assert.equal(CW.checkPage(PAGE_OK, INCLUDES_OK).status, 'PASS');
});

test('the CVEs legend: a data-* attribute, a control, an id, a stray link, one print, a lost aside label are caught', function () {
  var within = function (from, to) { return PAGE_OK.replace(from, to); };
  var LP = '</dl>\n<p class="hl-legend__p">I choose';
  var LEG = '<a href="https://cve.now/">cve.now</a> (CC BY 4.0). CVSS scores and vectors come from the CVE\'s NVD record through VulnCheck, mostly the CNA\'s score, unless the row says cve.now. Metasploit modules';
  var cases = [
    [within('<dt><span class="hl-vuln__cve">CVE-YYYY-NNNN</span></dt><dd>The CVE.</dd>' + LP,
            '<dt><span class="hl-vuln__cve" data-sev="x">CVE-YYYY-NNNN</span></dt><dd>The CVE.</dd>' + LP), /CVEs legend markup carries a data-\* attribute/],
    [within('<dd>The CVE.</dd>' + LP, '<dd><button>x</button></dd>' + LP), /CVEs legend markup holds a control/],
    [within('<dd>The CVE.</dd>' + LP, '<dd id="x">The CVE.</dd>' + LP), /CVEs legend markup carries an id/],
    [within(LEG, LEG.replace('https://cve.now/', 'https://shop.test/')), /not an attribution link/],
    [within('<summary>Legend</summary>{{ cves_legend_html }}</details>', '<summary>Legend</summary></details>'), /printed 1 time/],
    [within(' aria-label="CVEs legend"', ''), /CVEs legend aside is missing/],
    [within(LEG, LEG.replace(' (CC BY 4.0)', '')), /lost the cve\.now licence/]
  ];
  cases.forEach(function (c, i) {
    assert.notEqual(c[0], PAGE_OK, 'case ' + i + ' did not change the page');
    var r = CW.checkPage(c[0], INCLUDES_OK);
    assert.equal(r.status, 'FAIL', 'case ' + i);
    assert.match(r.problems.join(' | '), c[1], 'case ' + i);
  });
});

test('the CVEs legend printed inside the CVEs grid is caught', function () {
  var bad = PAGE_OK.replace('{{ c_msf }}{% include wire-vuln-new.html %}</div>', '{{ cves_legend_html }}</div>');
  var r = CW.checkPage(bad, INCLUDES_OK);
  assert.match(r.problems.join(' '), /legend sits inside the CVEs grid/);
});

test('an unescaped data value in the CVEs tab is caught; numbers and literals the template built are not', function () {
  var bad = CW.checkPage(PAGE_OK.replace('{{ r.vendor | escape }}', '{{ r.vendor }}'), INCLUDES_OK);
  assert.equal(bad.status, 'FAIL');
  assert.match(bad.problems.join(' '), /prints \{\{ r\.vendor \}\} without escape/);
  var attr = CW.checkPage(PAGE_OK.replace('{{ r.cve | downcase | escape }}', '{{ r.cve | downcase }}'), INCLUDES_OK);
  assert.match(attr.problems.join(' '), /prints \{\{ r\.cve \| downcase \}\} without escape/);
  // control: the stub prints {{ c_msf }} (a number) and passes
  assert.equal(CW.checkPage(PAGE_OK, INCLUDES_OK).status, 'PASS');
});

test('the cve.now include: an unescaped value, a stray link target and an unreadable include are caught', function () {
  var run = function (inc) { return CW.checkPage(PAGE_OK, { 'wire-vuln-new.html': inc }); };
  var unesc = run(INC_OK.replace('{{ ss_e | escape }}', '{{ ss_e }}'));
  assert.equal(unesc.status, 'FAIL');
  assert.match(unesc.problems.join(' '), /wire-vuln-new\.html prints \{\{ ss_e \}\} without escape/);
  var linked = run(INC_OK.replace('<span>{{ edb_len }} Exploit-DB entries</span>', '<a href="https://github.com/{{ r.repo | escape }}">x</a>'));
  assert.match(linked.problems.join(' '), /not one of its four named targets/);
  var stray = run(INC_OK + '\n<a href="https://cve.now/x">x</a>');
  assert.match(stray.problems.join(' '), /href="https:\/\/cve\.now\/x".*not one of its four named targets/);
  var absent = CW.checkPage(PAGE_OK, {});
  assert.equal(absent.status, 'FAIL');
  assert.match(absent.problems.join(' '), /NOT CHECKED: _includes\/wire-vuln-new\.html could not be read/);
  // control: a comment holding a brace expression is not code
  assert.equal(run(INC_OK).status, 'PASS');
});

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

test('each corrected attribution sentence is pinned: callout, short line and legend, claim by claim', function () {
  var pins = [
    // callout
    ["It shows at most 200 CVEs,", /capped at 200/],
    ["EPSS at least 1% paired with VEDAS exploit maturity at least 80% and CVSS at least 7.0", /paired EPSS and VEDAS arm/],
    ["CVEs, ranked by how many reasons they meet", /how the CVEs shown are ranked/],
    // short line
    ["Listing, titles, SSVC (CISA's own assessment), fixed versions and advisory ids from <a href=\"https://cve.now/\">cve.now</a>", /short CVEs line no longer says what cve\.now supplies/],
    ["Scores from NVD through VulnCheck, or from cve.now where a row says so", /short CVEs line no longer says where the scores come from/],
    ["Exploits from Rapid7 and Exploit-DB", /short CVEs line no longer says where the exploits come from/],
    ["KEV products from CISA", /short CVEs line no longer says where the KEV products come from/],
    // legend
    ["and show at most 200. When more qualify, the 200 shown are ranked by how many reasons they meet, then by EPSS, then by exploit maturity, then by CVSS.", /legend no longer says the cap and the ranking/],
    ["The CVE listing, titles, SSVC decision points (CISA's own assessment, from", /legend no longer says what cve\.now supplies/],
    ["CVSS scores and vectors come from the CVE's NVD record through VulnCheck, mostly the CNA's score, unless the row says cve.now. Metasploit modules", /legend no longer says that CVSS comes from the NVD record/],
    ["module index and Exploit-DB entries from", /legend no longer says that Metasploit and Exploit-DB come from the publishers/],
    ["\"Product on CISA KEV\" comes from CISA's <a", /legend no longer says that "Product on CISA KEV" comes from CISA's KEV catalog/]
  ];
  assert.equal(CW.checkPage(PAGE_OK, INCLUDES_OK).status, 'PASS');
  pins.forEach(function (c, i) {
    assert.ok(PAGE_OK.indexOf(c[0]) > -1, 'stub lacks pin ' + i + ': ' + c[0]);
    var r = CW.checkPage(PAGE_OK.replace(c[0], 'XX'), INCLUDES_OK);
    assert.equal(r.status, 'FAIL', 'pin ' + i + ': ' + c[0]);
    assert.match(r.problems.join(' | '), c[1], 'pin ' + i);
  });
});

test('a sentence saying cve.now carries Metasploit or Exploit-DB data is caught anywhere on the page', function () {
  var wrong = [
    ['<dd>The CVE.</dd>', '<dd>cve.now (CC BY 4.0), which carries the Metasploit Framework module list and Exploit-DB.</dd>'],
    ['not on a KEV list yet.', 'not on a KEV list yet. cve.now carries the Exploit-DB list.']
  ];
  wrong.forEach(function (w) {
    var r = CW.checkPage(PAGE_OK.replace(w[0], w[1]), INCLUDES_OK);
    assert.equal(r.status, 'FAIL', w[1]);
    assert.match(r.problems.join(' '), /says cve\.now carries Metasploit or Exploit-DB data/);
  });
  // control: the corrected sentences name the indexes and carry neither word after "carries"
  assert.doesNotMatch(CW.checkPage(PAGE_OK, INCLUDES_OK).problems.join(' '), /carries/);
});

/* ---- Review round 1, F3 and F4: the include chain, the feed, the score source and the rules sentence ---- */

function readReal(rel) {
  var fs = require('node:fs');
  var path = require('node:path');
  return fs.readFileSync(path.join(__dirname, '..', '..', '..', rel), 'utf8');
}

test('the gate follows the include chain: every wire-* include the page names is read, the real six pass', function () {
  /* T-0532 adds wire-details-row.html, which the Details JSON pages include for
     themselves (its escaping is their check, not this one); the chain the PAGE
     names stays the six below. */
  var rowInc = 'wire-details-row.html';
  var inc = realIncludes();
  assert.deepEqual(Object.keys(inc).sort(),
    ['wire-cve-why.html', rowInc, 'wire-vuln-epss.html', 'wire-vuln-new.html',
     'wire-vuln-news.html', 'wire-vuln-rules.html', 'wire-vuln-sev.html', 'wire-vuln-vedas.html']);
  var page = readReal('wire/index.md');
  var r = CW.checkPage(page, inc);
  assert.equal(r.status, 'PASS', r.problems.join(' | '));
  // an include the page names but the caller did not supply is NOT CHECKED, never a pass
  ['wire-cve-why.html', 'wire-vuln-epss.html', 'wire-vuln-new.html',
   'wire-vuln-news.html', 'wire-vuln-rules.html', 'wire-vuln-sev.html'].forEach(function (name) {
    var some = Object.assign({}, inc); delete some[name];
    var x = CW.checkPage(page, some);
    assert.equal(x.status, 'FAIL', name);
    assert.match(x.problems.join(' '), new RegExp('NOT CHECKED: _includes/' + name.replace(/\./g, '\\.') + ' could not be read'));
  });
  // the Details row include is not in the page's chain, so it may sit outside this map
  var withoutRow = Object.assign({}, inc); delete withoutRow[rowInc];
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
  ['six reasons', 'a Nuclei template; an ET Open rule',
   "Nuclei templates come from ProjectDiscovery's template index; ET Open rules come from Emerging Threats' Suricata ruleset.",
   'the tooling reasons together admitted 53 CVEs, eight later listed on VulnCheck KEV; Nuclei accounted for seven of 34.'
  ].forEach(function (pin) {
    // Mutate the callout's reason count even when the explanation repeats it.
    var changed = pin === 'six reasons'
      ? page.replace(/(<div class="hl-wire__callout hl-wire__callout--c">[\s\S]*?)six reasons/, '$1removed')
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
    [xml.replace('The feed shows at most 200 CVEs', 'The feed shows at most 150 CVEs'), /does not say "at most 200 CVEs"/],
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
    ['A CVE from {{ cve_year | escape }}', 'A CVE from {{ cve_year }}'],
    ['added in {{ vday | slice: 0, 4 | escape }}', 'added in {{ vday | slice: 0, 4 }}'],
    ['>CVE-{{ cve_year | escape }}</span>', '>CVE-{{ cve_year }}</span>'],
    ['evidence {{ r.evidence | escape }}', 'evidence {{ r.evidence }}'],
    ['KEV {{ vday | escape }}, {% if gap_n', 'KEV {{ vday }}, {% if gap_n'],
    ['id="vulns-{{ vday | escape }}"', 'id="vulns-{{ vday }}"'],
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
    ['KEV {{ vday | xml_escape }}{% if dis_len', 'KEV {{ vday }}{% if dis_len'],
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

test('an include named only by another include is followed too', function () {
  var chained = Object.assign({}, INCLUDES_OK, {
    'wire-vuln-new.html': INC_OK + '\n{% include wire-vuln-extra.html %}',
    'wire-vuln-extra.html': '<i>{{ r.vendor }}</i>'
  });
  var r = CW.checkPage(PAGE_OK, chained);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /_includes\/wire-vuln-extra\.html prints \{\{ r\.vendor \}\} without escape/);
  chained['wire-vuln-extra.html'] = '<i>{{ r.vendor | escape }}</i>';
  assert.equal(CW.checkPage(PAGE_OK, chained).status, 'PASS');
  delete chained['wire-vuln-extra.html'];
  assert.match(CW.checkPage(PAGE_OK, chained).problems.join(' '), /NOT CHECKED: _includes\/wire-vuln-extra\.html could not be read/);
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
  var pins = ['Exploit maturity (VEDAS)', 'Estimation of Vulnerability Prevalence &amp; Exploit Maturity',
    '150+ identifiers', 'every 6 to 8 hours', 'The source publishes no formula.',
    'On the CVEs tab, I pair EPSS at least 1% with VEDAS at least 80% and CVSS at least 7.0 for the EPSS + maturity reason.',
    'A high score is not evidence that working exploit code exists or that the CVE has been exploited',
    'exploitation is what the nKEVs tab and CISA KEV are for', 'An unscored CVE shows no maturity chip.',
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
 ['Listed within 30 days of disclosure','Disclosed 30 days to a year before listing','Older CVEs newly listed','Disclosure date unknown','Every VulnCheck KEV entry stays visible.','Filters open matching batches and counts show matching rows.'].forEach(function(pin){
   assert.equal(CW.checkPage(page.replace(pin,'removed'),inc).status,'FAIL',pin);
 });
});
