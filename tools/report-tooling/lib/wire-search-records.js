'use strict';

/* Site-search records for the Wire (T-0548, Joseph 2026-11-03: search finds every nKEV row, every CVE row with the text its Details pane shows, and every news and
   research headline; each result lands on its row; all indexed feed text is defanged and gated).

   Why records and not pages: wire/index.md wraps every row in data-pagefind-ignore (the page text is the same on every refresh and the Details text is not in the page at all:
   it is fetched from wire/details-nkev.json and wire/details-cves.json when a row is opened). So the build adds one Pagefind custom record per row.

   INPUT   the built _site: wire/index.html (the rows and their ids, so an anchor is the id the page really has), wire/details-nkev.json, wire/details-cves.json.
   OUTPUT  { records, counts, source, problems }
             records   one object per row: { url, content, language, meta: { title, date, section }, filters: { section: [ name ] } }, ready for addCustomRecord
             source    rows found on the page per section, and the vuln digest items left out
             counts    records built per section (equal to source by construction; a mismatch is a problem)
             problems  anything the builder could not do (a row with no id, a duplicate id, a row with no Details entry)

   ROW IDS (the page's rules, wire/index.md):  nKEV  #cve-<cve lowercased>   CVE  #cves-<cve lowercased>   headline  #h-<date to the minute>-<source slug>-<url slug tail>.
   A headline item of kind "vuln" is a digest link to an nKEV row, so it has no id and no record.

   TEXT   what the Details pane shows (assets/js/wire-details.js): the CVE record text (desc, or the title when the CVE has no desc), CWE ids, affected terms, the fixed-in versions,
          the host name of each cited report (a link contributes its text, never its address), the advisory ids, the Metasploit and Exploit-DB entries, the rule ids (ET Open SID,
          Nuclei, CISA Sigma, Snort 3 SID) and the KEV product. Dates go in meta.date, not in the text. Every string goes through defangText from assets/js/ioc-classify.js, the
          site's script-side defang (the page itself defangs with _includes/defang-text.html; the two share their forms), so a URL- or IP-shaped value in a desc or an affected term is
          indexed as hxxp / [.] text, never raw. The gate (check-defang.js --site <dir> --records <file>) scans the records the build wrote, with the scanner that reads the pages. */

var fs = require('node:fs');
var path = require('node:path');

var SECTIONS = { nkev: 'Wire: nKEV', cves: 'Wire: CVEs', headlines: 'Wire: Headlines' };
var WIRE_URL = '/wire/';

/* The defang every indexed string goes through. Two existing pieces, composed; no new form:
     1. defangText from assets/js/ioc-classify.js, the site's script-side free-text defang (the forms of _includes/defang-text.html);
     2. a residual pass for what (1) leaves: it cuts words on whitespace and judges whole words, where the page's Liquid include and the gate cut at / _ = and so on, so a file or
        endpoint name behind a slash ("api/v1/validate.py", "/ctl/showByurl.do") and the scheme of a bracketed IPv6 URL come through (1) raw. Every token the gate's own scanner
        (scanLine of check-defang.js, with the allow data of _data/defang_allow.yml) still flags is replaced by defangValue of the same file, typed by the scanner's kind.
   The residual pass is counted, and a token it cannot clear is counted as unresolved; the build prints both (counts only) and the gate scans the result. */
function makeDefang(allow) {
  var C = require(path.join(__dirname, '..', '..', '..', 'assets', 'js', 'ioc-classify.js'));
  if (!C || typeof C.defangText !== 'function' || typeof C.defangValue !== 'function') throw new Error('assets/js/ioc-classify.js does not export defangText and defangValue');
  var D = require('../check-defang.js');
  var TYPE = { URL: 'url', 'IPV6-URL': 'url', DOMAIN: 'domain', IPV4: 'ipv4', EMAIL: 'email' };
  function fn(text) {
    var out = C.defangText(String(text == null ? '' : text));
    var pass = 0;
    for (var round = 0; round < 3; round++) {
      var flagged = D.scanLine(out, allow).flagged;
      if (!flagged.length) break;
      var changed = false;
      flagged.forEach(function (f) {
        var ty = TYPE[f.kind];
        var rep = ty ? C.defangValue(f.token, ty) : D.defangForPrint(f.token);
        if (rep !== f.token && out.indexOf(f.token) > -1) { out = out.split(f.token).join(rep); changed = true; pass++; }
      });
      if (!changed) break;
    }
    fn.stats.residual += pass;
    fn.stats.unresolved += D.scanLine(out, allow).flagged.length;
    return out;
  }
  fn.stats = { residual: 0, unresolved: 0 };
  return fn;
}

function defaultAllow() {
  var S = require('./defang-site.js');
  return S.loadAllowData(path.join(__dirname, '..', '..', '..', '_data', 'defang_allow.yml')).allow;
}

function squash(s) { return String(s == null ? '' : s).replace(/\s+/g, ' ').trim(); }
function arr(v) { return Array.isArray(v) ? v : []; }
function str(v) { return typeof v === 'string' ? v : ''; }
function day(v) { var s = str(v); return /^\d{4}-\d{2}-\d{2}/.test(s) ? s.slice(0, 10) : ''; }

/* The Details text of one row, as an array of lines. d is one entry of details-*.json "rows". */
function detailLines(d, isCves) {
  var out = [];
  d = d || {};
  var desc = squash(d.desc);
  if (desc) out.push(desc);
  else if (isCves && squash(d.title)) out.push(squash(d.title));
  else if (squash(d.title)) out.push(squash(d.title));
  arr(d.cwe).forEach(function (c) { if (typeof c === 'string' && /^CWE-\d+$/.test(c)) out.push(c); });
  arr(d.affected).forEach(function (a) { if (typeof a === 'string' && a.trim()) out.push(squash(a)); });
  if (squash(d.fixed)) out.push('Fixed in ' + squash(d.fixed));
  arr(d.reports).forEach(function (r) { if (r && typeof r.host === 'string' && r.host.trim()) out.push(squash(r.host)); });
  arr(d.aliases).forEach(function (a) { if (typeof a === 'string' && a.trim()) out.push(squash(a)); });
  if (squash(d.kev_product)) out.push(squash(d.kev_product));
  arr(d.msf).forEach(function (p) { if (typeof p === 'string' && p.trim()) out.push('Metasploit ' + p.split('/').pop()); });
  arr(d.edb).forEach(function (e) { if (String(e).trim()) out.push('Exploit-DB EDB-' + String(e).trim()); });
  arr(d.et_sids).forEach(function (s) { if (String(s).trim()) out.push('ET Open SID ' + String(s).trim()); });
  if (str(d.nuclei).trim()) out.push('Nuclei ' + str(d.nuclei).split('/').pop());
  arr(d.cisa_sigma).forEach(function (p) { if (typeof p === 'string' && p.trim()) out.push('CISA Sigma ' + p); });
  arr(d.snort3_sids).forEach(function (s) { if (String(s).trim()) out.push('Snort 3 SID ' + String(s).trim()); });
  return out;
}

function parseDetails(text, label, problems) {
  if (text == null) { problems.push(label + ' absent'); return {}; }
  try {
    var j = JSON.parse(text);
    return (j && j.rows && typeof j.rows === 'object') ? j.rows : {};
  } catch (e) { problems.push(label + ' does not parse: ' + e.message); return {}; }
}

/* in: { document (a DOM document of wire/index.html), nkevDetails (JSON text or null), cveDetails (JSON text or null), defangText (optional) } */
function buildRecords(input) {
  var defang = input.defangText || makeDefang(input.allow || defaultAllow());
  var doc = input.document;
  var problems = [];
  var nk = parseDetails(input.nkevDetails, 'details-nkev.json', problems);
  var cv = parseDetails(input.cveDetails, 'details-cves.json', problems);
  var records = [], seen = {};
  var source = { nkev: 0, cves: 0, headlines: 0, vulnDigest: 0 };
  var counts = { nkev: 0, cves: 0, headlines: 0 };
  var noDetails = { nkev: 0, cves: 0 };

  function add(sectionKey, id, title, lines, date) {
    if (!id) { problems.push(SECTIONS[sectionKey] + ': a row has no id'); return; }
    if (seen[id]) { problems.push(SECTIONS[sectionKey] + ': duplicate id ' + id); return; }
    seen[id] = 1;
    var name = SECTIONS[sectionKey];
    var meta = { title: defang(squash(title)), section: name };
    if (date) meta.date = date;
    records.push({
      url: WIRE_URL + '#' + id,
      content: lines.map(function (l) { return defang(squash(l)); }).filter(Boolean).join('\n'),
      language: 'en',
      meta: meta,
      filters: { section: [name] },
    });
    counts[sectionKey]++;
  }

  function cveTab(sel, prefix, sectionKey, rows, isCves) {
    Array.prototype.forEach.call(doc.querySelectorAll(sel), function (row) {
      source[sectionKey]++;
      var id = row.getAttribute('id') || '';
      var key = id.indexOf(prefix) === 0 ? id.slice(prefix.length) : '';
      var cveEl = row.querySelector('.hl-vuln__cve');
      var cve = cveEl ? squash(cveEl.textContent) : '';
      var vp = row.querySelector('.hl-vuln__vp');
      var vendorProduct = vp && !vp.querySelector('.hl-vuln__none') ? squash(vp.textContent) : '';
      var d = key ? rows[key] : null;
      if (!d) noDetails[sectionKey]++;
      var lines = detailLines(d, isCves);
      var title = squash(cve + ' ' + vendorProduct);
      if (isCves && d && squash(d.title) && title.indexOf(squash(d.title)) < 0) title = title + ' ' + squash(d.title);
      // a row's own visible text is searchable too, so a row with no Details entry still has its CVE, vendor and product
      lines.unshift(squash(cve + ' ' + vendorProduct));
      var date = day(d && (isCves ? d.published : d.added)) || day(row.getAttribute('data-day'));
      add(sectionKey, id, title || id, lines, date);
    });
  }
  cveTab('#vulns .hl-vuln', 'cve-', 'nkev', nk, false);
  cveTab('#cves .hl-vuln', 'cves-', 'cves', cv, true);

  Array.prototype.forEach.call(doc.querySelectorAll('#headlines .hl-wire__row'), function (row) {
    if (row.getAttribute('data-kind') === 'vuln') { source.vulnDigest++; return; }
    source.headlines++;
    var t = row.querySelector('.hl-wire__title'), s = row.querySelector('.hl-wire__src');
    var title = t ? squash(t.textContent) : '';
    var lines = [title];
    if (s && squash(s.textContent)) lines.push(squash(s.textContent));
    var labels = (row.getAttribute('data-labels') || '').split('|').map(squash).filter(Boolean);
    if (labels.length) lines.push(labels.join(', '));
    add('headlines', row.getAttribute('id') || '', title, lines, row.getAttribute('data-day') || '');
  });

  ['nkev', 'cves', 'headlines'].forEach(function (k) {
    if (source[k] !== counts[k]) problems.push(SECTIONS[k] + ': ' + source[k] + ' source rows but ' + counts[k] + ' records');
  });
  return { records: records, counts: counts, source: source, noDetails: noDetails, problems: problems, defang: defang.stats || null };
}

/* Convenience for the CLI and tests: read the three files of a built site. */
function buildFromSite(siteDir, opts) {
  var JSDOM = require('jsdom').JSDOM;
  var page = path.join(siteDir, 'wire', 'index.html');
  if (!fs.existsSync(page)) return null;
  var rd = function (f) { var p = path.join(siteDir, 'wire', f); return fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : null; };
  var dom = new JSDOM(fs.readFileSync(page, 'utf8'));
  return buildRecords({ document: dom.window.document, nkevDetails: rd('details-nkev.json'), cveDetails: rd('details-cves.json'), defangText: opts && opts.defangText });
}

module.exports = { makeDefang: makeDefang, buildRecords: buildRecords, buildFromSite: buildFromSite, detailLines: detailLines, SECTIONS: SECTIONS, WIRE_URL: WIRE_URL };
