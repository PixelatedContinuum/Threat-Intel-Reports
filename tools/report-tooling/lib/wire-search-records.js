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

/* The Details text of one row, as an array of lines, in the order and under the conditions of the pane (assets/js/wire-details.js buildNkevPanel / buildCvesPanel). d is one
   entry of details-*.json "rows", or null when the row has none (the pane then shows NO_ENTRY). Each block cites the pane function it mirrors.
   Skipped on purpose (fixed-text absence messages the pane shows on most rows - no description, no fixed version, none confirmed, no rule, no CVSS, no EPSS, the "Not on VulnCheck KEV or CISA KEV" closing line, the "fixed version is listed above" line - because one sentence on nearly every record dilutes the ranking of the rows that do match: measured, "langflow" fell from position 1 to 4 with them in; and numbers and dates nobody searches for): CVSS score digits and vector string, EPSS values and percentiles, the dates in the Exploitation lines (dates go in
   meta.date), the "+N more" count, the Wire-headline story count, and the section headings (they sit on every record and would match every query). Never indexed: a URL. */
var CWE_SHAPE = /^CWE-\d+$/;
var VERSION_SHAPE = /^[vV]?\d[0-9A-Za-z.+_-]{0,39}$/;
var CVSS_VECTOR_SHAPE = /^(?:CVSS:\d\.\d\/)?[A-Za-z]{1,3}:[A-Za-z0-9]{1,3}(?:\/[A-Za-z]{1,3}:[A-Za-z0-9]{1,3})*$/;
var RULE_PATH_SHAPE = /^[A-Za-z0-9_.\/-]+\.ya?ml$/;
var MSF_SHAPE = /^modules\/[A-Za-z0-9_.\/-]+\.rb$/;
var DIGITS = /^\d+$/;
var SEVERITIES = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
var CVSS_VERSIONS = { '4.0': 1, '3.1': 1, '3.0': 1, '2.0': 1 };
var SCORED_BY = { NVD: 1, CNA: 1, ADP: 1, 'cve.now': 1 };
var SSVC_SETS = { ssvc_expl: { none: 1, poc: 1, active: 1 }, ssvc_auto: { yes: 1, no: 1 }, ssvc_impact: { partial: 1, total: 1 } };
var VECTOR_WORDS = { AV: 'attack vector', AC: 'complexity', PR: 'privileges required', UI: 'user interaction', S: 'scope', C: 'confidentiality', I: 'integrity', A: 'availability' };
var VECTOR_VALUES = {
  AV: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' }, AC: { L: 'Low', H: 'High' }, PR: { N: 'None', L: 'Low', H: 'High' }, UI: { N: 'None', R: 'Required' },
  S: { U: 'Unchanged', C: 'Changed' }, C: { H: 'High', L: 'Low', N: 'None' }, I: { H: 'High', L: 'Low', N: 'None' }, A: { H: 'High', L: 'Low', N: 'None' },
};
function nnum(v) {
  if (typeof v === 'number') return isFinite(v) ? v : NaN;
  if (typeof v !== 'string' || v.trim() === '') return NaN;
  var n = Number(v);
  return isFinite(n) ? n : NaN;
}
function isDay(v) { return typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v); }

function detailLines(d, isCves) {
  var out = [];
  if (!d || typeof d !== 'object') { out.push('No details in our data for this CVE.'); return out; }   // NO_ENTRY, the one message kept

  // secRecord (wire-details.js 146-177): desc; the title only on the CVEs tab
  var desc = squash(d.desc);
  if (desc) out.push(desc);
  else if (isCves && squash(d.title)) out.push(squash(d.title));
  arr(d.cwe).forEach(function (c) { if (typeof c === 'string' && CWE_SHAPE.test(c)) out.push(c); });

  // secAffected (180-205): the affected terms; the fixed versions that pass the version shape, else the no-fixed-version message
  arr(d.affected).forEach(function (a) { if (typeof a === 'string' && a.trim()) out.push(squash(a)); });
  var fixedOk = str(d.fixed).split(',').map(squash).filter(function (v) { return VERSION_SHAPE.test(v); });
  if (fixedOk.length) out.push('Fixed in ' + fixedOk.join(', '));

  // secWhatDo (208-215)
  if (isDay(d.kev_due)) out.push("CISA's due date for US federal agencies.");

  if (!isCves) {
    // secExploitation (218-270), nKEVs only; the reports hosts are the pane's links' text
    if (isDay(d.added)) out.push('Added to VulnCheck KEV.');
    out.push(isDay(d.cisa_added) ? 'On CISA KEV.' : 'Not on CISA KEV.');
    var hosts = [];
    arr(d.reports).forEach(function (r) {
      var u = r && typeof r.url === 'string' ? r.url : '', h = r && typeof r.host === 'string' ? squash(r.host) : '';
      if (u && h && /^https:\/\//.test(u)) hosts.push(h);
    });
    if (hosts.length) out.push("VulnCheck's cited reports: " + hosts.join(', '));
    var gap = nnum(d.gap);
    if (isDay(d.added) && isDay(d.disclosed) && !isNaN(gap)) {
      out.push(gap > 0 ? 'NVD published it days before the KEV add.' : gap === 0 ? 'NVD published it the same day VulnCheck added it.' : 'VulnCheck added it days before NVD published it.');
    }
    if (isDay(d.evidence) && isDay(d.added) && d.evidence < d.added) out.push('Earliest citation date.');
  } else {
    // secWhyListed (273-309), CVEs tab only: each claim the chips make, in the pane's words, with the numbers left out
    var signals = arr(d.signals);
    var cvss = nnum(d.cvss), vec = str(d.cvss_vector), kp = squash(d.kev_product), kn = nnum(d.kev_product_n);
    if (signals.indexOf('crit_noauth_kev_product') !== -1 && !isNaN(cvss) && cvss >= 9 && CVSS_VECTOR_SHAPE.test(vec) &&
        vec.indexOf('AV:N') !== -1 && vec.indexOf('PR:N') !== -1 && vec.indexOf('UI:N') !== -1 && kp && !isNaN(kn) && kn > 0) {
      out.push('Rated Critical and reachable over the network with no privileges and no user action. ' + kp + ': CISA has listed earlier CVEs in this product on its KEV catalog. That is a fact about the product, not about this CVE.');
    }
    if (signals.indexOf('msf') !== -1 && arr(d.msf).length) out.push("A Metasploit module for this CVE, confirmed against Rapid7's own module list.");
    if (signals.indexOf('edb') !== -1 && arr(d.edb).length) out.push("An Exploit-DB entry for this CVE, confirmed against Exploit-DB's own list.");
    var pct = nnum(d.epss_pct);
    if (signals.indexOf('epss90') !== -1 && !isNaN(pct) && pct >= 0.90) out.push("FIRST's EPSS puts this CVE in the top 10% for likelihood of exploitation in the next 30 days.");
  }

  // secExploits (312-351): the Metasploit module file names and Exploit-DB ids that pass their shapes
  arr(d.msf).forEach(function (p) { if (typeof p === 'string' && MSF_SHAPE.test(p)) { out.push('Metasploit ' + p.split('/').pop()); } });
  arr(d.edb).forEach(function (e) { var s = String(e).trim(); if (DIGITS.test(s) && s.length <= 8) { out.push('Exploit-DB EDB-' + s); } });

  // secDetection (354-418): ET Open, Nuclei, CISA Sigma, Snort 3 rule ids that pass their shapes
  arr(d.et_sids).forEach(function (s) { var t = String(s).trim(); if (DIGITS.test(t)) { out.push('ET Open SID ' + t); } });
  var nuc = str(d.nuclei);
  if (nuc && RULE_PATH_SHAPE.test(nuc)) { out.push('Nuclei ' + nuc.split('/').pop()); }
  arr(d.cisa_sigma).forEach(function (p) { if (typeof p === 'string' && RULE_PATH_SHAPE.test(p)) { out.push('CISA Sigma ' + p); } });
  arr(d.snort3_sids).forEach(function (s) { var t = String(s).trim(); if (DIGITS.test(t)) { out.push('Snort 3 SID ' + t); } });

  // secSeverity (435-481): the band word and who scored it, the vector in words, the SSVC labels; the score digits stay out
  var score = nnum(str(d.cvss).trim());
  var scoredOk = str(d.cvss).trim() !== '' && !isNaN(score) && score > 0 && score <= 10 && SEVERITIES[str(d.severity)] && CVSS_VERSIONS[str(d.cvss_version)] && SCORED_BY[str(d.scored_by)];
  if (scoredOk) {
    var who = str(d.scored_by);
    out.push('CVSS v' + str(d.cvss_version) + ' base score, ' + SEVERITIES[str(d.severity)] + ', ' +
      (who === 'cve.now' ? 'from cve.now, because our NVD data holds no score for it.' : 'scored by ' + (who === 'NVD' ? 'NVD' : who === 'CNA' ? 'the CNA' : "CISA's ADP") + '.'));
  } else if (str(d.cvss).trim() !== '' && !isNaN(score) && score > 0 && score <= 10) {
    out.push('CVSS base score in our data, without a band or who scored it.');
  }
  if (str(d.cvss_vector) && CVSS_VECTOR_SHAPE.test(str(d.cvss_vector))) {
    var terms = [];
    str(d.cvss_vector).split('/').forEach(function (tok) {
      var eq = tok.indexOf(':');
      if (eq < 1) return;
      var nm = tok.slice(0, eq), rw = tok.slice(eq + 1);
      if (VECTOR_WORDS[nm] && VECTOR_VALUES[nm] && VECTOR_VALUES[nm][rw]) terms.push(VECTOR_WORDS[nm] + ' ' + VECTOR_VALUES[nm][rw]);
    });
    if (terms.length) out.push('From the vector: ' + terms.join(', ') + '.');
  }
  var bits = [];
  Object.keys(SSVC_SETS).forEach(function (k) {
    var v = str(d[k]);
    if (v && SSVC_SETS[k][v]) bits.push((k === 'ssvc_expl' ? 'Exploitation: ' : k === 'ssvc_auto' ? 'Automatable: ' : 'Technical impact: ') + v + '.');
  });
  if (bits.length) out.push(bits.join(' ') + " (CISA's assessment, via cve.now)");

  // secLikelihood (484-514): numbers only; nothing is indexed.

  // secLinks (517-556): the advisory ids that pass the GHSA / EUVD shapes (the links' text)
  arr(d.aliases).forEach(function (a) { if (typeof a === 'string' && (/^GHSA(?:-[a-z0-9]{4}){3}$/i.test(a) || /^EUVD-\d{4}-\d{4,}$/i.test(a))) out.push(a); });
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
