(function () {
'use strict';

/* T-0532 part S: the Wire Details dropdown renderer.

   One details JSON per tab (the nKEVs and the CVEs fact sheets) is fetched once per
   tab, started on the first pointerenter, focus or touchstart of any toggle in that
   tab and awaited on click; each panel is then built from text nodes only. Every
   value the reader sees goes in through createElement, textContent or setAttribute,
   never by handing the browser a markup string (hard rule 2, gate-checked below).

   Every external href is assembled from a fixed prefix plus a value that passed a
   shape check in this file and encodeURIComponent; a VulnCheck report URL is used
   only whole, when its own text starts with https. Each shape below is the same
   shape tools/report-tooling/lib/check-wire.js holds for the same field, so a value
   the gate admitted is still re-checked here before it may become a link target.

   The Headlines tab has no Details toggle (Joseph, 2026-11-01: it added little and
   cluttered the rows).

   The reader-facing lines are the design's wording, quoted from
   tasks/runs/T-0532/design.md. */

/* --- field shapes (the same shapes check-wire holds) ------------------------ */
var CVE_SHAPE = /^CVE-\d{4}-\d{4,}$/;
var CWE_SHAPE = /^CWE-\d+$/;
var GHSA_SHAPE = /^GHSA(?:-[a-z0-9]{4}){3}$/i;
var EUVD_SHAPE = /^EUVD-\d{4}-\d{4,}$/i;
var RULE_PATH_SHAPE = /^[A-Za-z0-9_.\/-]+\.ya?ml$/;
var MSF_SHAPE = /^modules\/[A-Za-z0-9_.\/-]+\.rb$/;
var EDB_SHAPE = /^\d{1,8}$/;
var SID_SHAPE = /^\d+$/;
var REPORT_SHAPE = /^https:\/\/[A-Za-z0-9.-]+(?::\d+)?(?:[\/?#][!#-&(-;=?-\[\]-_a-~]*)?$/;
var DAY_SHAPE = /^\d{4}-\d{2}-\d{2}$/;
var VERSION_SHAPE = /^[vV]?\d[0-9A-Za-z.+_-]{0,39}$/;
var CVSS_VECTOR_SHAPE = /^(?:CVSS:\d\.\d\/)?[A-Za-z]{1,3}:[A-Za-z0-9]{1,3}(?:\/[A-Za-z]{1,3}:[A-Za-z0-9]{1,3})*$/;
var CVSS_VERSIONS = { '4.0': 1, '3.1': 1, '3.0': 1, '2.0': 1 };
var SCORED_BY = { NVD: 1, CNA: 1, ADP: 1, 'cve.now': 1 };
var SEVERITIES = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
var SSVC_SETS = {
  ssvc_expl: { none: 1, poc: 1, active: 1 },
  ssvc_auto: { yes: 1, no: 1 },
  ssvc_impact: { partial: 1, total: 1 }
};
var URL_LIMIT = 500;

/* --- link prefixes: the fixed part of every external href ------------------- */
var NVD_PREFIX = 'https://nvd.nist.gov/vuln/detail/';
var CWE_PREFIX = 'https://cwe.mitre.org/data/definitions/';
var CVENOW_PREFIX = 'https://cve.now/';
var OBSERVER_PREFIX = 'https://www.exploit.observer/?keyword=';
var NUCLEI_PREFIX = 'https://github.com/projectdiscovery/nuclei-templates/blob/main/';
var SIGMA_PREFIX = 'https://github.com/cisagov/SIGMA_Rules/blob/develop/';
var MSF_PREFIX = 'https://github.com/rapid7/metasploit-framework/blob/master/';
var SNORT_PREFIX = 'https://www.snort.org/rule_docs/1-';
var EDB_PREFIX = 'https://www.exploit-db.com/exploits/';
var GHSA_PREFIX = 'https://github.com/advisories/';
var EUVD_PREFIX = 'https://euvd.enisa.europa.eu/vulnerability/';

/* --- the design's lines, quoted --------------------------------------------- */
var LOADING = 'Loading details...';
var FAILED = 'Details could not be loaded.';
var NO_ENTRY = 'No details in our data for this CVE.';
var DESC_EMPTY = 'The CVE record in our data has no description.';
var DESC_SRC = 'From the CVE record, via NVD.';
// The exporter caps desc at 3,000 characters and ends a capped text with "..." (wire_export.py
// desc_text), so a text that long ending that way was shortened: say so (design section 5).
var DESC_CAP_MIN = 2990;
var DESC_CAPPED = 'Shortened here; the full text is on NVD (link below).';
var TITLE_SRC = "The CVE record's first sentence, via cve.now. The full description is on NVD.";
var FIXED_EMPTY = "No fixed version in the data I hold; check the vendor's advisory.";
var FIXED_IN = 'Fixed in: ';
var FIXED_TAIL = " (from the CVE record's affected data, via cve.now)";
var DONE_FIXED = 'A fixed version is listed above.';
var DONE_CISA = "CISA's due date for US federal agencies: ";
var DONE_NONE = 'No fixed version in the data I hold.';
var KEV_ADD = 'Added to VulnCheck KEV on ';
var CISA_SINCE = 'On CISA KEV since ';
var NOT_CISA = 'Not on CISA KEV.';
var REPORTS_LEAD = "VulnCheck's cited reports: ";
var MORE_REPORTS = ' more in VulnCheck KEV';
var EVIDENCE_LINE = 'Earliest citation date: ';
var PUB_LATE = ' days before the KEV add.';
var PUB_DAY = ' day before the KEV add.';
var PUB_SAME = 'NVD published it the same day VulnCheck added it.';
var PRE_NVD = 'VulnCheck added it ';
var PRE_NVD_LATE = ' days before NVD published it.';
var PRE_NVD_DAY = ' day before NVD published it.';
var EXPLOITS_NONE = "None confirmed in Rapid7's or Exploit-DB's own indexes. That does not mean none exists.";
var RULES_NONE = 'No rule names this CVE in the four sources I check: ET Open, Nuclei, CISA Sigma, Snort 3 community.';
var NO_SCORE = 'No CVSS score in our data.';
var NO_EPSS = 'No EPSS score in our data.';
var WHYNOW_HEAD = 'Not on VulnCheck KEV or CISA KEV as of ';
var WHYNOW_NOTE = 'Being listed does not mean anyone has been seen exploiting it.';
var SSVCTAIL = " (CISA's assessment, via cve.now)";
var EPSS_PRE = '7 days before the KEV add: ';
var EPSS_MAX = 'Highest in the last 30 days: ';
var EPSS_CROSSED = " The values for this CVE cross a change of FIRST's EPSS model, so they are not directly comparable.";
/* --- small helpers ----------------------------------------------------------- */
function isStr(v) { return typeof v === 'string'; }
function str(v) { return typeof v === 'string' ? v : ''; }
function lst(v) { return Array.isArray(v) ? v : null; }
function num(v) {
  if (typeof v === 'number') { return isFinite(v) ? v : NaN; }
  // A JSON file's "" (an empty field) is absence, never 0: Number('') is 0.
  if (typeof v !== 'string' || v.trim() === '') { return NaN; }
  var n = Number(v);
  return isFinite(n) ? n : NaN;
}
function dayOf(v) { return typeof v === 'string' && DAY_SHAPE.test(v) ? v : ''; }
function el(tag, cls, text) {
  var node = document.createElement(tag);
  if (cls) { node.className = cls; }
  if (text !== undefined && text !== null) { node.textContent = text; }
  return node;
}
function headInto(panel, text) { panel.appendChild(el('div', 'hl-dt__h', text)); }
function lineInto(panel, text) { panel.appendChild(el('p', 'hl-dt__line', text)); }

/* An external link. `target` is always already the fixed prefix plus an encoded,
   shape-checked value (or a report URL that survived its own check above). */
function linkInto(panel, target, text, nofollow) {
  if (!target) { return null; }
  var a = el('a', 'hl-dt__link', text);
  a.href = target;
  a.target = '_blank';
  a.rel = nofollow ? 'noopener noreferrer nofollow' : 'noopener noreferrer';
  panel.appendChild(a);
  return a;
}
function encUrl(prefix, value) { return prefix + encodeURIComponent(value); }

/* Ordinal suffix, the same arithmetic the EPSS chip uses. */
function ordinal(n) {
  var m100 = ((n % 100) + 100) % 100;
  var m10 = ((n % 10) + 10) % 10;
  if (m100 < 11 || m100 > 13) {
    if (m10 === 1) { return 'st'; }
    if (m10 === 2) { return 'nd'; }
    if (m10 === 3) { return 'rd'; }
  }
  return 'th';
}


/* --- Section 1: the CVE record ----------------------------------------------- */
function secRecord(panel, d, isCves) {
  headInto(panel, 'CVE record');
  var desc = str(d.desc).trim();
  if (desc) {
    panel.appendChild(el('blockquote', 'hl-dt__quote', desc));
    panel.appendChild(el('p', 'hl-dt__src', DESC_SRC));
    if (desc.length >= DESC_CAP_MIN && desc.slice(-3) === '...') {
      panel.appendChild(el('p', 'hl-dt__src', DESC_CAPPED));
    }
  } else if (isCves && str(d.title).trim()) {
    panel.appendChild(el('blockquote', 'hl-dt__quote', str(d.title).trim()));
    panel.appendChild(el('p', 'hl-dt__src', TITLE_SRC));
  } else {
    lineInto(panel, DESC_EMPTY);
  }
  var cw = lst(d.cwe);
  if (!cw) { return; }
  var okIds = [];
  cw.forEach(function (id) {
    if (typeof id === 'string' && CWE_SHAPE.test(id)) { okIds.push(id); }
  });
  if (!okIds.length) { return; }
  var row = el('p', 'hl-dt__line');
  row.textContent = okIds.length === 1 ? 'Weakness: ' : 'Weaknesses: ';
  okIds.forEach(function (id, i) {
    if (i > 0) { row.appendChild(document.createTextNode(', ')); }
    // MITRE's page is /data/definitions/<number>.html; the CWE- form 404s (Sol P2).
    linkInto(row, encUrl(CWE_PREFIX, id.slice(4)) + '.html', id, false);
  });
  row.appendChild(document.createTextNode('.'));
  panel.appendChild(row);
}

/* --- Section 2: affected and fixed -------------------------------------------- */
function secAffected(panel, d) {
  headInto(panel, 'Affected and fixed');
  var aff = lst(d.affected);
  if (aff) {
    aff.forEach(function (term) {
      if (typeof term === 'string' && term.trim()) {
        lineInto(panel, term.trim());
      }
    });
  }
  var fixed = str(d.fixed).trim();
  if (fixed) {
    var parts = [];
    fixed.split(',').forEach(function (raw) {
      var v = raw.trim();
      if (VERSION_SHAPE.test(v)) { parts.push(v); }
    });
    if (parts.length) {
      lineInto(panel, FIXED_IN + parts.join(', ') + FIXED_TAIL);
    } else {
      lineInto(panel, FIXED_EMPTY);
    }
  } else {
    lineInto(panel, FIXED_EMPTY);
  }
}

/* --- Section 3: what to do, facts only ------------------------------------------ */
function secWhatDo(panel, d) {
  headInto(panel, 'What to do');
  var bits = [];
  if (str(d.fixed).trim()) { bits.push(DONE_FIXED); }
  var due = dayOf(d.kev_due);
  if (due) { bits.push(DONE_CISA + due + '.'); }
  lineInto(panel, bits.length ? bits.join(' ') : DONE_NONE);
}

/* --- Section 4: exploitation (nKEVs) -------------------------------------------- */
function secExploitation(panel, d) {
  headInto(panel, 'Exploitation');
  var added = dayOf(d.added);
  if (added) {
    lineInto(panel, KEV_ADD + added + '.');
  }
  var cisaDay = dayOf(d.cisa_added);
  lineInto(panel, cisaDay ? CISA_SINCE + cisaDay + '.' : NOT_CISA);
  var reps = lst(d.reports);
  if (reps && reps.length) {
    var row = el('p', 'hl-dt__line');
    row.textContent = REPORTS_LEAD;
    var seen = 0;
    reps.forEach(function (rp) {
      var u = rp && typeof rp.url === 'string' ? rp.url : '';
      var host = rp && typeof rp.host === 'string' ? rp.host : '';
      if (!u || u.length > URL_LIMIT || !REPORT_SHAPE.test(u) || !host) { return; }
      if (seen) { row.appendChild(document.createTextNode(', ')); }
      var a = el('a', 'hl-dt__link', host);
      a.href = u;
      a.target = '_blank';
      a.rel = 'noopener noreferrer nofollow';
      row.appendChild(a);
      seen++;
    });
    var more = num(d.reports_more);
    if (seen && !isNaN(more) && more > 0) {
      row.appendChild(document.createTextNode(' '));
      row.appendChild(el('span', 'hl-dt__dim', '+' + Math.floor(more) + MORE_REPORTS));
    }
    if (seen) {
      row.appendChild(document.createTextNode('.'));
      panel.appendChild(row);
    }
  }
  var feed = dayOf(d.disclosed);
  var gap = num(d.gap);
  if (added && feed && !isNaN(gap)) {
    if (gap > 0) {
      var n = Math.floor(gap);
      lineInto(panel, 'NVD published ' + feed + ', ' + n + (n === 1 ? PUB_DAY : PUB_LATE));
    } else if (gap === 0) {
      lineInto(panel, PUB_SAME);
    } else {
      var back = Math.floor(-gap);
      lineInto(panel, PRE_NVD + back + (back === 1 ? PRE_NVD_DAY : PRE_NVD_LATE));
    }
  }
  var ev = dayOf(d.evidence);
  if (ev && added && ev < added) {
    lineInto(panel, EVIDENCE_LINE + ev + '.');
  }
}

/* --- Section 4 (CVEs tab): why listed, the chips' own claims ---------------------- */
function secWhyListed(panel, d, asOfDay) {
  headInto(panel, 'Why listed');
  var signals = lst(d.signals);
  if (signals) {
    if (signals.indexOf('crit_noauth_kev_product') !== -1) {
      var cvss = num(d.cvss);
      var vec = str(d.cvss_vector);
      var kp = str(d.kev_product).trim();
      var kn = num(d.kev_product_n);
      if (!isNaN(cvss) && cvss >= 9 && CVSS_VECTOR_SHAPE.test(vec) &&
          vec.indexOf('AV:N') !== -1 && vec.indexOf('PR:N') !== -1 && vec.indexOf('UI:N') !== -1 &&
          kp && !isNaN(kn) && kn > 0) {
        lineInto(panel, 'Rated Critical (CVSS ' + d.cvss + ') and reachable over the network ' +
          'with no privileges and no user action, read from its CVSS vector (' + vec + '). ' +
          kp + ': CISA has listed ' + Math.floor(kn) + ' earlier CVE' + (kn === 1 ? '' : 's') +
          ' in this product on its KEV catalog. That is a fact about the product, not about this CVE.');
      }
    }
    var msf = lst(d.msf);
    if (signals.indexOf('msf') !== -1 && msf && msf.length) {
      lineInto(panel, "A Metasploit module for this CVE, confirmed against Rapid7's own module list.");
    }
    var edb = lst(d.edb);
    if (signals.indexOf('edb') !== -1 && edb && edb.length) {
      lineInto(panel, "An Exploit-DB entry for this CVE, confirmed against Exploit-DB's own list.");
    }
    if (signals.indexOf('epss_vedas') !== -1) {
      lineInto(panel, "EPSS at least 1% and A.R.P. Syndicate's VEDAS exploit-maturity estimate at least 80%, with CVSS at least 7.0; not evidence of exploitation or working exploit code.");
    }
    var pct = num(d.epss_pct);
    if (signals.indexOf('epss90') !== -1 && !isNaN(pct) && pct >= 0.90) {
      lineInto(panel, "FIRST's EPSS puts this CVE in the top 10% for likelihood of exploitation " +
        'in the next 30 days (percentile ' + Math.floor(pct * 100) + ').');
    }
  }
  var closeDay = dayOf(asOfDay);
  lineInto(panel, closeDay
    ? WHYNOW_HEAD + closeDay + '. ' + WHYNOW_NOTE
    : WHYNOW_HEAD.replace(/ as of $/, '') + '. ' + WHYNOW_NOTE);
}

/* --- Section 5: public exploits ---------------------------------------------------- */
function secExploits(panel, d) {
  headInto(panel, 'Public exploits');
  var msf = lst(d.msf);
  var edb = lst(d.edb);
  var shown = false;
  if (msf && msf.length > 0) {
    var group = el('div', 'hl-dt__group');
    group.appendChild(el('span', 'hl-dt__gh', 'Metasploit'));
    var msfSeen = false;
    msf.forEach(function (path) {
      if (typeof path !== 'string' || !MSF_SHAPE.test(path)) { return; }
      if (msfSeen) { group.appendChild(document.createTextNode(' ')); }
      linkInto(group, encUrl(MSF_PREFIX, path), path.split('/').pop(), false);
      msfSeen = true;
    });
    if (msfSeen) {
      shown = true;
      panel.appendChild(group);
    }
  }
  if (edb) {
    var g2 = el('div', 'hl-dt__group');
    g2.appendChild(el('span', 'hl-dt__gh', 'Exploit-DB'));
    var edbSeen = false;
    edb.forEach(function (id) {
      var s = String(id);
      if (!EDB_SHAPE.test(s)) { return; }
      linkInto(g2, encUrl(EDB_PREFIX, s), 'EDB-' + s, false);
      edbSeen = true;
    });
    // The heading alone is not a group: an empty or all-invalid list draws nothing.
    if (edbSeen) {
      shown = true;
      panel.appendChild(g2);
    }
  }
  if (!shown) {
    lineInto(panel, EXPLOITS_NONE);
  }
}

/* --- Section 6: detection, grouped by source as the Rules popover is ---------------- */
function secDetection(panel, d) {
  headInto(panel, 'Detection');
  var sids = lst(d.et_sids);
  var nuc = str(d.nuclei);
  var sig = lst(d.cisa_sigma);
  var snort = lst(d.snort3_sids);
  var shown = false;
  if (sids) {
    var okSids = [];
    sids.forEach(function (s) {
      var t = String(s);
      if (SID_SHAPE.test(t) && !isNaN(parseInt(t, 10))) { okSids.push(t); }
    });
    if (okSids.length) {
      shown = true;
      lineInto(panel, 'ET Open: ' + okSids.map(function (s) { return 'SID ' + s; }).join(', ') + '.');
    }
  }
  if (nuc && RULE_PATH_SHAPE.test(nuc)) {
    shown = true;
    var row = el('p', 'hl-dt__line');
    row.textContent = 'Nuclei: ';
    linkInto(row, encUrl(NUCLEI_PREFIX, nuc), nuc.split('/').pop(), false);
    panel.appendChild(row);
  }
  if (sig && sig.length > 0) {
    var group = el('div', 'hl-dt__group');
    group.appendChild(el('span', 'hl-dt__gh', 'CISA Sigma'));
    var sigSeen = false;
    sig.forEach(function (path) {
      if (typeof path !== 'string' || !RULE_PATH_SHAPE.test(path)) { return; }
      if (sigSeen) { group.appendChild(document.createTextNode(' ')); }
      linkInto(group, encUrl(SIGMA_PREFIX, path), path, false);
      sigSeen = true;
    });
    if (sigSeen) {
      shown = true;
      panel.appendChild(group);
    }
  }
  if (snort) {
    var row3 = el('p', 'hl-dt__line');
    row3.textContent = 'Snort 3 community: ';
    var seen = false;
    snort.forEach(function (s) {
      var t = String(s);
      if (!SID_SHAPE.test(t)) { return; }
      if (seen) { row3.appendChild(document.createTextNode(', ')); }
      var a = el('a', 'hl-dt__link', 'SID ' + t);
      a.href = SNORT_PREFIX + encodeURIComponent(t);
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      row3.appendChild(a);
      seen = true;
    });
    if (seen) {
      row3.appendChild(document.createTextNode('.'));
      panel.appendChild(row3);
      shown = true;
    }
  }
  if (!shown) {
    lineInto(panel, RULES_NONE);
  }
}

/* --- Section 7: severity, the chip's wording, and the vector in words ---------------- */
var VECTOR_WORDS = {
  AV: 'attack vector', AC: 'complexity', PR: 'privileges required', UI: 'user interaction',
  S: 'scope', C: 'confidentiality', I: 'integrity', A: 'availability'
};
var VECTOR_VALUES = {
  AV: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' },
  AC: { L: 'Low', H: 'High' },
  PR: { N: 'None', L: 'Low', H: 'High' },
  UI: { N: 'None', R: 'Required' },
  S: { U: 'Unchanged', C: 'Changed' },
  C: { H: 'High', L: 'Low', N: 'None' },
  I: { H: 'High', L: 'Low', N: 'None' },
  A: { H: 'High', L: 'Low', N: 'None' }
};
function secSeverity(panel, d) {
  headInto(panel, 'Severity');
  var cvss = str(d.cvss).trim();
  var score = num(cvss);
  var scoredOk = cvss !== '' && !isNaN(score) && score > 0 && score <= 10 &&
    SEVERITIES[str(d.severity)] && CVSS_VERSIONS[str(d.cvss_version)] && SCORED_BY[str(d.scored_by)];
  var band = SEVERITIES[str(d.severity)];
  if (scoredOk) {
    var who = str(d.scored_by);
    var line = 'CVSS v' + str(d.cvss_version) + ' base score ' + cvss + ', ' + band + ', ';
    if (who === 'cve.now') {
      line += 'from cve.now, because our NVD data holds no score for it.';
    } else {
      line += 'scored by ' + (who === 'NVD' ? 'NVD' : who === 'CNA' ? 'the CNA' : "CISA's ADP") + '.';
    }
    lineInto(panel, line);
  } else if (cvss !== '' && !isNaN(score) && score > 0 && score <= 10) {
    lineInto(panel, 'CVSS base score ' + cvss + ' in our data, without a band or who scored it.');
  } else {
    lineInto(panel, NO_SCORE);
  }
  var vec = str(d.cvss_vector);
  if (vec && CVSS_VECTOR_SHAPE.test(vec)) {
    var terms = [];
    vec.split('/').forEach(function (tok) {
      var eq = tok.indexOf(':');
      if (eq < 1) { return; }
      var name = tok.slice(0, eq);
      var raw = tok.slice(eq + 1);
      if (!VECTOR_WORDS[name] || !VECTOR_VALUES[name] || !VECTOR_VALUES[name][raw]) { return; }
      terms.push(VECTOR_WORDS[name] + ' ' + VECTOR_VALUES[name][raw]);
    });
    if (terms.length) {
      lineInto(panel, 'From the vector: ' + terms.join(', ') + '.');
    }
  }
  var bits = [];
  Object.keys(SSVC_SETS).forEach(function (k) {
    var v = str(d[k]);
    if (v && SSVC_SETS[k][v]) {
      bits.push((k === 'ssvc_expl' ? 'Exploitation: ' : k === 'ssvc_auto' ? 'Automatable: ' : 'Technical impact: ') + v + '.');
    }
  });
  if (bits.length) {
    lineInto(panel, bits.join(' ') + SSVCTAIL);
  }
}

/* --- Section 8: likelihood (EPSS), numbers only --------------------------------------- */
function secLikelihood(panel, d, isCves) {
  headInto(panel, isCves ? 'Likelihood' : 'Likelihood (EPSS)');
  var epss = str(d.epss).trim();
  var score = num(epss);
  if (epss === '' || isNaN(score) || score < 0 || score > 1) {
    lineInto(panel, NO_EPSS);
    return;
  }
  var pct = num(d.epss_pct);
  var line = 'EPSS ' + epss;
  var pc = isNaN(pct) ? NaN : Math.floor(pct * 100);
  if (!isNaN(pc) && pc >= 0 && pc <= 100) {
    line += ' (' + pc + ordinal(pc) + ' percentile)';
  }
  var day = dayOf(d.epss_date);
  if (day) { line += ' on ' + day; }
  lineInto(panel, line + '.');
  var xmodel = str(d.epss_xmodel);
  if (!isCves) {
    var pre = str(d.epss_pre).trim();
    var preNum = num(pre);
    if (pre && !isNaN(preNum) && preNum >= 0 && preNum <= 1) {
      lineInto(panel, EPSS_PRE + pre + '.' + (xmodel.indexOf('pre') === 0 ? EPSS_CROSSED : ''));
    }
  }
  var max = str(d.epss_max).trim();
  var maxNum = num(max);
  if (max && !isNaN(maxNum) && maxNum >= 0 && maxNum <= 1) {
    lineInto(panel, EPSS_MAX + max + '.' + (xmodel.indexOf('spark') !== -1 ? EPSS_CROSSED : ''));
  }
}

/* --- Section 9: links out; NVD and cve.now always -------------------------------------- */
function secLinks(panel, d, cveId) {
  headInto(panel, 'Links');
  var row = el('p', 'hl-dt__line');
  row.textContent = 'Records: ';
  linkInto(row, encUrl(NVD_PREFIX, cveId), 'NVD', false);
  row.appendChild(document.createTextNode(', '));
  linkInto(row, encUrl(CVENOW_PREFIX, cveId), 'cve.now', false);
  row.appendChild(document.createTextNode(', '));
  linkInto(row, encUrl(OBSERVER_PREFIX, cveId), 'Exploit Observer', false);
  row.appendChild(document.createTextNode('.'));
  panel.appendChild(row);
  var al = lst(d.aliases);
  if (al) {
    var group = el('div', 'hl-dt__group');
    group.appendChild(el('span', 'hl-dt__gh', 'Advisories'));
    var alSeen = false;
    al.forEach(function (id) {
      var s = typeof id === 'string' ? id : '';
      var target = '';
      if (GHSA_SHAPE.test(s)) {
        target = encUrl(GHSA_PREFIX, s);
      } else if (EUVD_SHAPE.test(s)) {
        target = encUrl(EUVD_PREFIX, s);
      }
      if (!target) { return; }
      if (alSeen) { group.appendChild(document.createTextNode(' ')); }
      linkInto(group, target, s, false);   // the id as filed, case included
      alSeen = true;
    });
    if (alSeen) { panel.appendChild(group); }
  }
  var st = num(d.stories);
  if (!isNaN(st) && st > 0) {
    var row2 = el('p', 'hl-dt__line');
    row2.textContent = 'Wire headlines: ';
    var a = el('a', 'hl-dt__link', Math.floor(st) + ' naming this CVE');
    a.href = location.pathname + '?q=' + encodeURIComponent(cveId.toLowerCase()) + '#headlines';
    row2.appendChild(a);
    row2.appendChild(document.createTextNode('.'));
    panel.appendChild(row2);
  }
}

/* --- the two tabs' fact sheets, in the design's fixed order --------------------------------- */
function buildNkevPanel(panel, d, cveId) {
  secRecord(panel, d, false);
  secAffected(panel, d);
  secWhatDo(panel, d);
  secExploitation(panel, d);
  secExploits(panel, d);
  secDetection(panel, d);
  secSeverity(panel, d);
  secLikelihood(panel, d, false);
  secLinks(panel, d, cveId);
}
function buildCvesPanel(panel, d, cveId, asOfDay) {
  secRecord(panel, d, true);
  secAffected(panel, d);
  secWhatDo(panel, d);
  secWhyListed(panel, d, asOfDay);
  secExploits(panel, d);
  secDetection(panel, d);
  secSeverity(panel, d);
  secLikelihood(panel, d, true);
  secLinks(panel, d, cveId);
}

/* --- open, close, load ------------------------------------------------------------------------- */
function rowOf(btn) {
  return btn.closest('.hl-vuln');
}

var panelSeq = 0;
function makePanel(row, btn) {
  var old = row.querySelector('.hl-dt__panel');
  if (old) { old.remove(); }
  var panel = el('div', 'hl-dt__panel');
  var id = row.id ? row.id + '-dt' : 'hl-dt-p' + (++panelSeq);
  if (document.getElementById(id)) { id = 'hl-dt-p' + (++panelSeq); }
  panel.id = id;
  btn.setAttribute('aria-controls', id);
  return panel;
}
/* A panel appended inside the row element: a filter that hides the row hides it. */
function closePanel(row, btn) {
  var open = row.querySelector('.hl-dt__panel');
  if (open) { open.remove(); }
  btn.setAttribute('aria-expanded', 'false');
}

/* Per-tab fetch: one file, one request. state.data is the rows map,
   state.genDay the file's generated_at day (the "as of" date for the CVEs why-listed
   closing line); null once on failure, so the next open retries. */
function tabState(section) {
  var url = section.getAttribute('data-details');
  var state = {
    data: null,
    genDay: '',
    pending: null,
    load: function () {
      if (!state.pending) {
        state.pending = fetch(url, { credentials: 'same-origin' })
          .then(function (res) {
            if (!res.ok) { throw new Error('HTTP ' + res.status); }
            return res.json();
          })
          .then(function (obj) {
            if (!obj || typeof obj !== 'object' ||
                !obj.rows || typeof obj.rows !== 'object') {
              throw new Error('unexpected details file shape');
            }
            state.data = obj.rows;
            var g = typeof obj.generated_at === 'string' ? obj.generated_at : '';
            state.genDay = g.slice(0, 10);
          })
          .catch(function () {
            state.pending = null;
          });
      }
      return state.pending;
    }
  };
  return state;
}

function fillVulnPanel(panel, row, state) {
  var isCves = row.id.indexOf('cves-') === 0;
  /* The page's row ids carry a doubled prefix: the template writes id="cve-{{ the
     downcased id }}", and a downcased CVE id still begins cve- ("cve-cve-2026-39738").
     The data rows are keyed by the plain lowercased id, so the page prefix goes once. */
  var rowKey = row.id.slice(isCves ? 5 : 4);   // the plain lowercased CVE id
  var cveId = rowKey.toUpperCase();
  var entry = state.data ? state.data[rowKey] : null;
  if (!entry || typeof entry !== 'object' || !CVE_SHAPE.test(cveId)) {
    lineInto(panel, NO_ENTRY);
    return;
  }
  if (isCves) {
    buildCvesPanel(panel, entry, cveId, state.genDay);
  } else {
    buildNkevPanel(panel, entry, cveId);
  }
}

function bindToggle(btn, state) {
  var row = rowOf(btn);
  if (!row || !state) { return; }
  // Hidden until the script says the row can open a panel (design section 6):
  // without JavaScript no dead button shows and the rows work as they did.
  btn.removeAttribute('hidden');
  btn.addEventListener('click', function () {
    if (btn.getAttribute('aria-expanded') === 'true') {
      closePanel(row, btn);
      return;
    }
    var panel = makePanel(row, btn);
    row.appendChild(panel);
    btn.setAttribute('aria-expanded', 'true');
    function deliver() {
      if (panel.parentNode !== row) { return; }   // closed while the file loaded
      panel.textContent = '';
      if (state.data) {
        fillVulnPanel(panel, row, state);
      } else {
        lineInto(panel, FAILED);
      }
    }
    if (state.data) {
      fillVulnPanel(panel, row, state);
    } else {
      lineInto(panel, LOADING);
      state.load().then(deliver);
    }
    panel.addEventListener('keydown', function (ev) {
      if (ev.key === 'Escape') { closePanel(row, btn); }
    });
  });
  btn.addEventListener('keydown', function (ev) {
    if (ev.key === 'Escape') { closePanel(row, btn); }
  });
  function prime() { state.load(); }
  btn.addEventListener('focus', prime);
  btn.addEventListener('pointerenter', prime, { passive: true });
  btn.addEventListener('touchstart', prime, { passive: true });
}

/* A vuln row finds its file through the section its data-details names. Panels are
   independent: opening one row's does not close another's. */
function init() {
  var bySectionId = new Map();
  [].forEach.call(document.querySelectorAll('[data-details]'), function (sec) {
    if (sec.id && !bySectionId.has(sec.id)) {
      bySectionId.set(sec.id, tabState(sec));
    }
  });
  [].forEach.call(document.querySelectorAll('.hl-dt'), function (btn) {
    var sec = btn.closest('section');
    var state = sec && sec.id && bySectionId.has(sec.id) ? bySectionId.get(sec.id) : null;
    bindToggle(btn, state);
  });
}

/* T-0548: a link to a Wire row (a site-search result, a shared URL) opens that row's
   Details pane, as if the reader had clicked its toggle. The tab needs no code here:
   the row is the :target, and custom.scss shows its section through :has(:target).
   The pane opens through the toggle's own click listener, so a hash-opened pane is
   built, closed and retried exactly as a clicked one. A pane already open stays
   open. A hash that names no row does nothing. A headline row has no toggle, so it
   only lands on the row. */
function rowForHash() {
  var raw = location.hash.slice(1);
  if (!raw) { return null; }
  var id;
  try { id = decodeURIComponent(raw); } catch (e) { return null; }
  var row = document.getElementById(id);
  if (!row || !(row.classList.contains('hl-vuln') || row.classList.contains('hl-wire__row'))) {
    return null;
  }
  return row;
}
function openForHash() {
  var row = rowForHash();
  if (!row) { return; }
  var btn = row.querySelector('.hl-dt');
  // A toggle the script never woke (no state for its tab) keeps its hidden attribute,
  // so only a live toggle is clicked.
  if (btn && !btn.hasAttribute('hidden') && btn.getAttribute('aria-expanded') !== 'true') {
    btn.click();
  }
  // The nKEV and CVE rows get an 80px scroll margin from custom.scss (.hl-vuln); a
  // headline row has none, and the sticky nav would cover it. Until that rule covers
  // .hl-wire__row too, the same 80px is set here (T-0548, measured in a browser).
  if (!row.classList.contains('hl-vuln')) { row.style.scrollMarginTop = '80px'; }
  row.scrollIntoView({ block: 'start' });
}

init();
openForHash();
window.addEventListener('hashchange', openForHash);

})();
