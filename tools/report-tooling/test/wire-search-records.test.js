'use strict';

/* T-0548: the Wire search records and the index build. A fixture wire page and a fixture _site stand in for the Jekyll build, so the tests run without Ruby;
   the live corpus is measured by `node build-search-index.js --site <_site>` and `node check-defang.js --site <_site> --records <file>`. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var os = require('node:os');
var path = require('node:path');
var cp = require('node:child_process');
var JSDOM = require('jsdom').JSDOM;
var R = require('../lib/wire-search-records.js');
var S = require('../lib/defang-site.js');

var ROOT = path.join(__dirname, '..', '..', '..');
var ALLOW = path.join(ROOT, '_data', 'defang_allow.yml');

function esc(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }

/* the shape wire/index.md renders, reduced to what the builder reads */
function wirePage() {
  var h = '<!DOCTYPE html><html lang="en"><body><main>';
  h += '<section id="headlines">';
  h += '<div class="hl-wire__row" id="h-202611011957-bleepingcomputer-fbi-links" data-title="x" data-labels="nation-state|crypto" data-kind="news" data-day="2026-11-01"><a class="hl-wire__item" href="https://example.org/a"><span class="hl-wire__src">BleepingComputer</span><span class="hl-wire__title">' + esc('FBI links "heist" to <DPRK> hackers') + '</span></a></div>';
  h += '<div class="hl-wire__row" id="h-202610291400-palo-alto-networks-php" data-kind="research" data-labels="" data-day="2026-10-29"><a class="hl-wire__item" href="https://example.org/b"><span class="hl-wire__src">Palo Alto Networks</span><span class="hl-wire__title">Threat Brief: PHP flaws</span></a></div>';
  h += '<div class="hl-wire__row" data-kind="vuln" data-labels="" data-day="2026-11-01"><a class="hl-wire__item" href="#cve-cve-2026-0001"><span class="hl-wire__src">VulnCheck</span><span class="hl-wire__title">Vuln digest</span></a></div>';
  h += '</section><section id="vulns">';
  h += '<div class="hl-vuln" id="cve-cve-2026-0001" data-day="2026-11-01"><a class="hl-vuln__cve" href="https://nvd.nist.gov/x">CVE-2026-0001</a><span class="hl-vuln__vp"><b>Acme</b> Gadget</span></div>';
  h += '<div class="hl-vuln" id="cve-cve-2026-0002" data-day="2026-11-01"><a class="hl-vuln__cve" href="https://nvd.nist.gov/x">CVE-2026-0002</a><span class="hl-vuln__vp"><span class="hl-vuln__none">vendor not given</span></span></div>';
  h += '</section><section id="cves">';
  h += '<div class="hl-vuln hl-vuln--cve" id="cves-cve-2026-0003" data-day="2026-10-29"><a class="hl-vuln__cve" href="https://nvd.nist.gov/x">CVE-2026-0003</a><span class="hl-vuln__vp"><b>IBM</b> Langflow OSS</span></div>';
  h += '</section></main></body></html>';
  return h;
}
var NKEV = JSON.stringify({ generated_at: 'x', rows: {
  'cve-2026-0001': { added: '2026-11-01', title: 't', desc: 'Remote code execution; payload fetched from http://198.51.100.17/p.exe and evil-host.example.xyz, mail op@evil-host.example.xyz. She said "run it" & <b>left</b>.',
    cwe: ['CWE-78'], affected: ['Acme Gadget: 1.0 up to 1.2 (see 198.51.100.9)'], fixed: '1.3', reports: [{ url: 'https://vendor.example.com/r', host: 'vendor.example.com' }], aliases: ['GHSA-aaaa-bbbb-cccc'],
    kev_product: '', msf: ['modules/exploits/linux/gadget_rce.rb'], edb: [51234], et_sids: ['2050001'], nuclei: 'http/cves/2026/CVE-2026-0001.yaml', cisa_sigma: [], snort3_sids: ['300001'] },
  'cve-2026-0002': { added: '2026-11-01', title: '', desc: '', cwe: [], affected: [], fixed: '' },
} });
var CVES = JSON.stringify({ generated_at: 'x', rows: {
  'cve-2026-0003': { published: '2026-10-29', title: 'Langflow OSS is affected by multiple vulnerabilities', desc: '', cwe: ['CWE-287'], affected: ['IBM Langflow OSS: 1.0.0 up to and including 1.12.8'], fixed: '', aliases: ['EUVD-2026-113155'], kev_product: 'IBM Langflow' },
} });

function build(over) {
  over = over || {};
  var dom = new JSDOM(over.page || wirePage());
  return R.buildRecords({ document: dom.window.document, nkevDetails: 'nkev' in over ? over.nkev : NKEV, cveDetails: 'cve' in over ? over.cve : CVES });
}

test('one record per nKEV, CVE and non-digest headline row; the vuln digest item is left out', function () {
  var b = build();
  assert.deepStrictEqual(b.source, { nkev: 2, cves: 1, headlines: 2, vulnDigest: 1 });
  assert.deepStrictEqual(b.counts, { nkev: 2, cves: 1, headlines: 2 });
  assert.strictEqual(b.records.length, 5);
  assert.deepStrictEqual(b.problems, []);
});

test('each record url is the row anchor the page really has', function () {
  var b = build();
  var urls = b.records.map(function (r) { return r.url; }).sort();
  assert.deepStrictEqual(urls, ['/wire/#cve-cve-2026-0001', '/wire/#cve-cve-2026-0002', '/wire/#cves-cve-2026-0003', '/wire/#h-202610291400-palo-alto-networks-php', '/wire/#h-202611011957-bleepingcomputer-fbi-links']);
  var doc = new JSDOM(wirePage()).window.document;
  b.records.forEach(function (r) { assert.ok(doc.getElementById(r.url.split('#')[1]), r.url + ' is an id on the page'); });
});

test('section filter and meta: the three names, a title and a date', function () {
  var b = build();
  var by = {};
  b.records.forEach(function (r) { (by[r.filters.section[0]] = by[r.filters.section[0]] || []).push(r); assert.strictEqual(r.language, 'en'); assert.strictEqual(r.meta.section, r.filters.section[0]); assert.ok(r.meta.title); });
  assert.deepStrictEqual(Object.keys(by).sort(), ['Wire: CVEs', 'Wire: Headlines', 'Wire: nKEV']);
  var k1 = b.records.filter(function (r) { return r.url.endsWith('cve-cve-2026-0001'); })[0];
  assert.strictEqual(k1.meta.title, 'CVE-2026-0001 Acme Gadget');
  assert.strictEqual(k1.meta.date, '2026-11-01');
  var c = b.records.filter(function (r) { return r.url.endsWith('cves-cve-2026-0003'); })[0];
  assert.match(c.meta.title, /^CVE-2026-0003 IBM Langflow OSS/);
  assert.strictEqual(c.meta.date, '2026-10-29');
});

test('text fields the Details pane shows are present; a link contributes its text, never its address', function () {
  var k = build().records.filter(function (r) { return r.url.endsWith('cve-cve-2026-0001'); })[0];
  ['Remote code execution', 'CWE-78', 'Acme Gadget: 1.0 up to 1.2', 'Fixed in 1.3', 'GHSA-aaaa-bbbb-cccc', 'Metasploit gadget_rce.rb', 'EDB-51234', 'ET Open SID 2050001', 'Nuclei CVE-2026-0001[.]yaml', 'Snort 3 SID 300001'].forEach(function (t) {
    assert.ok(k.content.indexOf(t) > -1, 'content holds: ' + t);
  });
  assert.ok(k.content.indexOf('vendor[.]example[.]com') > -1, 'the cited report contributes its host name, defanged');
  assert.ok(!/https:\/\/vendor/.test(k.content), 'not its address');
  var c = build().records.filter(function (r) { return r.url.endsWith('cves-cve-2026-0003'); })[0];
  assert.ok(c.content.indexOf('Langflow OSS is affected by multiple vulnerabilities') > -1, 'a CVE with no desc is searchable by its title');
  assert.ok(c.content.indexOf('IBM Langflow') > -1);
});

test('defang applied: a URL-, IP-, domain- and e-mail-shaped value is indexed defanged, nothing raw', function () {
  var b = build();
  var all = b.records.map(function (r) { return r.meta.title + '\n' + r.content; }).join('\n');
  assert.ok(/hxxp:\/\/198\[\.\]51\[\.\]100\[\.\]17\/p\[\.\]exe/.test(all), 'the URL is hxxp with a bracketed host');
  assert.ok(all.indexOf('198[.]51[.]100[.]9') > -1);
  assert.ok(!/https?:\/\//i.test(all), 'no raw scheme');
  assert.ok(!/\b198\.51\.100\.\d+/.test(all), 'no raw IPv4');
  assert.ok(!/evil-host\.example\.xyz/.test(all) && !/op@evil/.test(all), 'no raw domain or e-mail');
});

test('escaping: quote, angle bracket and ampersand arrive as the characters, and the records survive a JSON round trip', function () {
  var b = build();
  var h = b.records.filter(function (r) { return r.url.indexOf('#h-202611011957') > -1; })[0];
  assert.strictEqual(h.meta.title, 'FBI links "heist" to <DPRK> hackers');
  assert.ok(!/&quot;|&lt;|&gt;|&amp;/.test(h.content), 'no HTML entity left in the text');
  var k = b.records.filter(function (r) { return r.url.endsWith('cve-cve-2026-0001'); })[0];
  assert.ok(k.content.indexOf('"run it" & <b>left</b>') > -1);
  assert.deepStrictEqual(JSON.parse(JSON.stringify(b.records)), b.records);
});

test('a row with no Details entry still gets a record from its own CVE, vendor and product, and is counted', function () {
  var b = build({ nkev: JSON.stringify({ rows: {} }) });
  assert.strictEqual(b.counts.nkev, 2);
  assert.strictEqual(b.noDetails.nkev, 2);
  var k = b.records.filter(function (r) { return r.url.endsWith('cve-cve-2026-0001'); })[0];
  assert.ok(k.content.indexOf('CVE-2026-0001 Acme Gadget') > -1);
});

test('a duplicate id and a row with no id are problems, never silently dropped', function () {
  var dup = wirePage().replace('id="h-202610291400-palo-alto-networks-php"', 'id="h-202611011957-bleepingcomputer-fbi-links"');
  var b = build({ page: dup });
  assert.ok(b.problems.some(function (p) { return /duplicate id/.test(p); }));
  var none = wirePage().replace(' id="h-202610291400-palo-alto-networks-php"', '');
  assert.ok(build({ page: none }).problems.some(function (p) { return /no id/.test(p); }));
});

test('the gate scans the record input: a raw record fails, the built records pass, an empty file is an error', function () {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wsr-'));
  var good = path.join(dir, 'good.json'), bad = path.join(dir, 'bad.json'), empty = path.join(dir, 'empty.json');
  var b = build();
  fs.writeFileSync(good, JSON.stringify({ records: b.records }));
  var rawRec = JSON.parse(JSON.stringify(b.records[0]));
  rawRec.content += '\nbeacon http://198.51.100.17/p and evil-host.example.xyz';
  fs.writeFileSync(bad, JSON.stringify({ records: [rawRec] }));
  fs.writeFileSync(empty, JSON.stringify({ records: [] }));
  var g = S.scanRecords(good, ALLOW);
  assert.strictEqual(g.findings.length, 0);
  assert.strictEqual(g.stats.records, 5);
  assert.ok(g.stats.matchedDefanged > 0, 'the defanged forms were seen');
  var f = S.scanRecords(bad, ALLOW);
  assert.ok(f.findings.length >= 2, 'raw URL and domain flagged');
  assert.ok(f.findings.every(function (x) { return /^RECORD-/.test(x.kind); }));
  assert.strictEqual(S.scanRecords(empty, ALLOW).stats.records, 0);
  assert.throws(function () { S.scanRecords(path.join(dir, 'nope.json'), ALLOW); });
});

test('build-search-index.js on a fixture site: pages and Wire records indexed, a query finds the CVE row, the records file is gated clean', { timeout: 120000 }, function () {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wsi-'));
  var site = path.join(dir, '_site');
  fs.mkdirSync(path.join(site, 'wire'), { recursive: true });
  fs.mkdirSync(path.join(site, 'reports', 'one'), { recursive: true });
  fs.writeFileSync(path.join(site, 'wire', 'index.html'), wirePage());
  fs.writeFileSync(path.join(site, 'wire', 'details-nkev.json'), NKEV);
  fs.writeFileSync(path.join(site, 'wire', 'details-cves.json'), CVES);
  fs.writeFileSync(path.join(site, 'reports', 'one', 'index.html'), '<!DOCTYPE html><html lang="en"><head><title>Langflow campaign</title></head><body data-pagefind-body><h1>Langflow campaign</h1><p>A report about Langflow.</p></body></html>');
  // an unlisted page: no data-pagefind-body, so it must stay out of the index (the guarantee the layout gives; addDirectory must keep it)
  fs.mkdirSync(path.join(site, 'reports', 'secret'), { recursive: true });
  fs.writeFileSync(path.join(site, 'reports', 'secret', 'index.html'), '<!DOCTYPE html><html lang="en"><head><title>Embargoed Langflow</title></head><body><h1>Embargoed Langflow</h1><p>langflow langflow</p></body></html>');
  var rec = path.join(dir, 'records.json');
  var r = cp.spawnSync(process.execPath, [path.join(__dirname, '..', 'build-search-index.js'), '--site', site, '--records-out', rec], { encoding: 'utf8' });
  assert.strictEqual(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /Indexed 1 pages/, 'only the page with data-pagefind-body is a page: ' + r.stdout);
  assert.match(r.stdout, /Wire: nKEV 2 of 2 rows, Wire: CVEs 1 of 1 rows, Wire: Headlines 2 of 2 rows \(1 vuln digest/);
  assert.ok(fs.existsSync(path.join(site, 'pagefind', 'pagefind.js')));
  var J = JSON.parse(fs.readFileSync(rec, 'utf8'));
  assert.strictEqual(J.records.length, 5);
  assert.strictEqual(S.scanRecords(rec, ALLOW).findings.length, 0);
  // a query through the bundle's own Node entry: the Wire CVE row is among the results for "langflow"
  return require('../lib/pagefind-query.js').search(path.join(site, 'pagefind'), 'langflow').then(function (res) {
    var urls = res.map(function (x) { return x.url; });
  assert.ok(urls.some(function (u) { return u.indexOf('/wire/#cves-cve-2026-0003') === 0; }), 'results: ' + urls.join(', '));
  assert.ok(urls.some(function (u) { return u.indexOf('/reports/one') === 0; }), 'the report page is still indexed');
  assert.ok(!urls.some(function (u) { return u.indexOf('/reports/secret') === 0; }), 'a page without data-pagefind-body stays out: ' + urls.join(', '));
  });
});

test('--wire-bundle writes the Wire records to a second bundle and leaves the first one pages only', { timeout: 120000 }, function () {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wsb-'));
  var site = path.join(dir, '_site');
  fs.mkdirSync(path.join(site, 'wire'), { recursive: true });
  fs.mkdirSync(path.join(site, 'reports', 'one'), { recursive: true });
  fs.writeFileSync(path.join(site, 'wire', 'index.html'), wirePage());
  fs.writeFileSync(path.join(site, 'wire', 'details-nkev.json'), NKEV);
  fs.writeFileSync(path.join(site, 'wire', 'details-cves.json'), CVES);
  fs.writeFileSync(path.join(site, 'reports', 'one', 'index.html'), '<!DOCTYPE html><html lang="en"><head><title>One</title></head><body data-pagefind-body><h1>One</h1><p>a report</p></body></html>');
  var r = cp.spawnSync(process.execPath, [path.join(__dirname, '..', 'build-search-index.js'), '--site', site, '--records-out', path.join(dir, 'r.json'), '--wire-bundle', 'pagefind-wire'], { encoding: 'utf8' });
  assert.strictEqual(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /Indexed 1 pages/);
  var e1 = JSON.parse(fs.readFileSync(path.join(site, 'pagefind', 'pagefind-entry.json'), 'utf8')).languages.en.page_count;
  var e2 = JSON.parse(fs.readFileSync(path.join(site, 'pagefind-wire', 'pagefind-entry.json'), 'utf8')).languages.en.page_count;
  assert.strictEqual(e1, 1);
  assert.strictEqual(e2, 5);
});
