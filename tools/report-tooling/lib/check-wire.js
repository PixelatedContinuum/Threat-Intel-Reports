'use strict';

/* Verifies _data/wire.yml, the data behind /wire/.

   The failure this exists for is the quiet one. The timer on LXC-102 dies,
   nothing errors anywhere, and the page keeps serving month-old headlines under
   a name that promises freshness. Nothing in the Jekyll build would notice, and
   neither would a reader.

   PASS, FAIL and NOT CHECKED, the third never folded into the first. A missing
   file and an empty item list both mean this run verified nothing, and both say
   so rather than reporting a clean sweep of zero. See
   homelab-soc/docs/gate-honesty-contract.md. */

// Calibrated against the 15-minute timer (T-0458, 2026-10-28; hourly with a 4 hour
// limit from 2026-10-02, and two-hourly with an 8 hour limit before that). One hour
// is four consecutive misses of the 15-minute timer, which is a dead timer rather
// than a blip, as the old four hours was four misses of the hourly one. Measured
// before the change: 479 hourly runs from 2026-10-09 to 2026-10-28 with no gap over
// 1.05 hours, and one failed run (2026-10-14) that the next slot recovered. A healthy
// file is at most one slot plus the timer's 3 minute jitter old when written (18
// minutes), and the build adds a median 2.2 minutes (maximum 9.3 over 100 runs), so
// one hour sits more than twice above a healthy age yet still lets one OpenCTI
// hiccup or one push collision (one to two missed runs) pass.
var STALE_HOURS = 1;
var REQUIRED = ['title', 'url', 'source', 'date', 'kind'];
// Hues defined in assets/css/custom.scss as .hl-topic-c1 .. .hl-topic-c12.
var PALETTE_SIZE = 12;
// How many tags the page draws per item; the rest are never rendered.
// Two, not three: three left 60% of rows wrapping their tags to a second line.
var DISPLAYED_LABELS = 2;
// `vuln` is the daily VulnCheck KEV digest row the exporter adds (T-0396).
var KINDS = { research: 1, news: 1, vuln: 1 };
// The nKEVs tab (was Vulnerabilities) is fed by a separate read (VulnCheck's API) that can
// fail on its own. Its freshness is warned about past a day, never failed. Left at a day
// when the timer went to 15 minutes (T-0458): the exporter reads VulnCheck once a run, so
// a failed read already warns at once through vulns_status 'stale', and this limit only
// backstops a stale cache that keeps being republished. Not tied to the 15-minute
// cadence: a transient VulnCheck outage must not warn on every build for hours.
var VULNS_STALE_HOURS = 24;
var VULN_STATUSES = { ok: 1, stale: 1, unavailable: 1 };
// T-0522: the CVEs tab has its own read (cve.now), warned about the same way: past a day, never failed.
var CVES_STALE_HOURS = 24;
var CVES_CAP = 150;
var CVE_SHAPE = /^CVE-\d{4}-\d{4,}$/;
var DAY_SHAPE = /^\d{4}-\d{2}-\d{2}$/;
// T-0399: each row's CVSS base score, all four fields empty or all set. A row
// written before T-0399 carries none of them and checks clean.
var SCORE_KEYS = ['cvss', 'cvss_version', 'severity', 'scored_by'];
var SEVERITIES = { critical: 1, high: 1, medium: 1, low: 1 };
var CVSS_VERSIONS = { '4.0': 1, '3.1': 1, '3.0': 1, '2.0': 1 };
// 'cve.now': Revision 3's arm A takes cve.now's score and vector when our NVD data holds none, and the row says so.
var SCORED_BY = { NVD: 1, CNA: 1, ADP: 1, 'cve.now': 1 };

function vedasProblem(r) {
  if (!hasKey(r, 'vedas')) return '';
  return typeof r.vedas === 'number' && Number.isFinite(r.vedas) && r.vedas >= 0 && r.vedas <= 1
    ? '' : 'has vedas ' + JSON.stringify(r.vedas) + ', not a number in [0, 1]';
}

function scoreProblem(r) {
  var present = SCORE_KEYS.filter(function (k) { return hasKey(r, k); });
  if (present.length === 0) return '';
  if (present.length !== SCORE_KEYS.length) return 'carries only some score fields (' + present.join(', ') + ')';
  var empty = SCORE_KEYS.filter(function (k) { return r[k] === '' || r[k] === null; });
  if (empty.length === SCORE_KEYS.length) return '';
  if (empty.length) return 'has a partial score (' + empty.join(', ') + ' empty)';
  var n = Number(r.cvss);
  if (!(n > 0 && n <= 10)) return 'has cvss ' + JSON.stringify(r.cvss) + ', not a score in (0, 10]';
  if (!CVSS_VERSIONS[String(r.cvss_version)]) return 'has cvss_version ' + JSON.stringify(r.cvss_version);
  if (!SEVERITIES[String(r.severity)]) return 'has severity ' + JSON.stringify(r.severity);
  if (!SCORED_BY[String(r.scored_by)]) return 'has scored_by ' + JSON.stringify(r.scored_by);
  return '';
}

function hasKey(o, k) { return !!o && Object.prototype.hasOwnProperty.call(o, k); }

/* T-0407: the row's pointers. A row written before T-0407 carries none of
   them and checks clean; one that carries them is held to the exporter's
   shapes, since the page draws each as a link or a filter key. */
// Printable ASCII only after the host, the exporter's rule: a raw control
// character passes a "not whitespace" class (T-0407 review F1).
var REPORT_URL = /^https:\/\/[A-Za-z0-9.-]+(?::\d+)?(?:[\/?#][!#-&(-;=?-\[\]-_a-~]*)?$/;
var NUCLEI_PATH = /^[A-Za-z0-9_.\/-]+\.ya?ml$/;
// T-0496: a rule file in cisagov/SIGMA_Rules, repo-relative. The same plain charset as a
// Nuclei path, so the link the page builds from it needs no escaping, plus no leading
// slash (that would make the blob URL carry an empty segment).
var CISA_PATH = /^[A-Za-z0-9_.\/-]+\.ya?ml$/;
function isCount(v) { return typeof v === 'number' && Number.isInteger(v) && v >= 0; }
function reportsOf(r) { return Array.isArray(r.reports) ? r.reports : []; }
function pointerProblems(r) {
  var out = [];
  if (hasKey(r, 'reports')) {
    if (!Array.isArray(r.reports)) out.push('has reports that are not a list');
    else {
      if (r.reports.length > 3) out.push('carries ' + r.reports.length + ' report links, over 3');
      r.reports.forEach(function (rp, i) {
        if (!rp || !REPORT_URL.test(String(rp.url || '')) || String(rp.url).length > 500) {
          out.push('report ' + (i + 1) + ' has url ' + JSON.stringify(rp && rp.url) + ', not a plain https link');
        } else if (typeof rp.host !== 'string' || !rp.host) {
          out.push('report ' + (i + 1) + ' has no host');
        }
      });
    }
  }
  ['reports_more', 'stories'].forEach(function (k) {
    if (hasKey(r, k) && !isCount(r[k])) out.push('has ' + k + ' ' + JSON.stringify(r[k]) + ', not a count');
  });
  if (hasKey(r, 'et_sids') && !(Array.isArray(r.et_sids) && r.et_sids.every(function (s) {
    return isCount(s) && s > 0; }))) {
    out.push('has et_sids ' + JSON.stringify(r.et_sids) + ', not a list of SIDs');
  }
  if (hasKey(r, 'nuclei') && r.nuclei !== '' &&
      !(typeof r.nuclei === 'string' && NUCLEI_PATH.test(r.nuclei) && r.nuclei.indexOf('..') === -1)) {
    out.push('has nuclei ' + JSON.stringify(r.nuclei) + ', not a template path');
  }
  // T-0496: CISA Sigma rule files and Snort 3 community SIDs. A row written before them
  // carries neither and checks clean; checkVulns holds a file that declares their counts
  // to carry both on every row.
  if (hasKey(r, 'cisa_sigma') && !(Array.isArray(r.cisa_sigma) && r.cisa_sigma.every(function (p) {
    return typeof p === 'string' && CISA_PATH.test(p) && p.indexOf('..') === -1 &&
      p.charAt(0) !== '/' && p.length <= 200; }))) {
    out.push('has cisa_sigma ' + JSON.stringify(r.cisa_sigma) + ', not a list of rule file paths');
  }
  if (hasKey(r, 'snort3_sids') && !(Array.isArray(r.snort3_sids) && r.snort3_sids.every(function (s, i, a) {
    return isCount(s) && s > 0 && (i === 0 || s > a[i - 1]); }))) {
    out.push('has snort3_sids ' + JSON.stringify(r.snort3_sids) + ', not a sorted list of distinct SIDs');
  }
  return out;
}

/* T-0468: the nKEV fields. `disclosed` is NVD's published day, `gap` the whole
   days from it to the VulnCheck KEV add (negative: VulnCheck listed it first),
   and the EPSS fields come from FIRST. A row written before T-0468 carries none
   of them and checks clean; one that carries them is held to the exporter's
   shapes, because the page prints each one, `epss_spark` straight into an SVG
   attribute, and the ratios are claims that can be recomputed from the row. */
// Anything below a space, DEL and the C1 range: a raw control character passes
// most "not whitespace" tests and breaks the YAML or the markup (T-0407 review F1).
var CONTROL_CHAR = /[\u0000-\u001f\u007f-\u009f]/;
// The exporter's points string: numbers, one decimal at most, commas and single spaces.
var SPARK_POINTS = /^\d+(?:\.\d)?,\d+(?:\.\d)?(?: \d+(?:\.\d)?,\d+(?:\.\d)?)*$/;
var SPARK_MAX_POINTS = 30;
var RATIO_SHAPE = /^\d+(?:\.\d)?$/;
// A score or percentile as the exporter writes it: a decimal string from 0 to 1.
var UNIT_SHAPE = /^(?:0(?:\.\d{1,9})?|1(?:\.0{1,9})?)$/;
function realDay(v) {
  if (typeof v !== 'string' || !DAY_SHAPE.test(v)) return NaN;
  var t = Date.parse(v + 'T00:00:00Z');
  return !isNaN(t) && new Date(t).toISOString().slice(0, 10) === v ? t : NaN;
}
function isEmpty(v) { return v === '' || v === null || v === undefined; }
function controlProblems(o, prefix, out) {
  if (typeof o === 'string') {
    if (CONTROL_CHAR.test(o)) out.push('has a control character in ' + prefix);
  } else if (Array.isArray(o)) {
    o.forEach(function (v, i) { controlProblems(v, prefix + '[' + i + ']', out); });
  } else if (o && typeof o === 'object') {
    Object.keys(o).forEach(function (k) { controlProblems(o[k], prefix ? prefix + '.' + k : k, out); });
  }
  return out;
}
function nkevProblems(r) {
  var out = controlProblems(r, '', []);
  out = out.concat(detailsFieldProblems(r));
  var has = hasKey(r, 'disclosed') || hasKey(r, 'gap');
  if (hasKey(r, 'disclosed') !== hasKey(r, 'gap')) out.push('carries only one of disclosed and gap');
  if (hasKey(r, 'disclosed') && !isEmpty(r.disclosed) && isNaN(realDay(r.disclosed))) {
    out.push('has disclosed ' + JSON.stringify(r.disclosed) + ', not empty or a real day');
  }
  if (hasKey(r, 'gap') && !isEmpty(r.gap) && !(typeof r.gap === 'number' && Number.isInteger(r.gap))) {
    out.push('has gap ' + JSON.stringify(r.gap) + ', not empty or an integer');
  }
  if (has && !isEmpty(r.gap) && isEmpty(r.disclosed)) out.push('has a gap but no disclosed day');
  if (has && isEmpty(r.gap) && !isEmpty(r.disclosed)) out.push('has a disclosed day but no gap');
  if (typeof r.gap === 'number' && !isNaN(realDay(r.disclosed)) && !isNaN(realDay(r.added))) {
    var days = Math.round((realDay(r.added) - realDay(r.disclosed)) / 86400000);
    if (days !== r.gap) out.push('has gap ' + r.gap + ' but added minus disclosed is ' + days + ' days');
  }
  ['epss', 'epss_pct', 'epss_pre', 'epss_max'].forEach(function (k) {
    if (hasKey(r, k) && !isEmpty(r[k]) && !(typeof r[k] === 'string' && UNIT_SHAPE.test(r[k]))) {
      out.push('has ' + k + ' ' + JSON.stringify(r[k]) + ', not empty or a number from 0 to 1');
    }
  });
  if (hasKey(r, 'epss_date') && !isEmpty(r.epss_date) && isNaN(realDay(r.epss_date))) {
    out.push('has epss_date ' + JSON.stringify(r.epss_date) + ', not empty or a real day');
  }
  // Which comparisons cross an EPSS model change; only an EPSS row can carry a mark.
  if (hasKey(r, 'epss_xmodel') && !isEmpty(r.epss_xmodel)) {
    if (typeof r.epss_xmodel !== 'string' || !/^(?:pre|spark|pre,spark)$/.test(r.epss_xmodel)) {
      out.push('has epss_xmodel ' + JSON.stringify(r.epss_xmodel) + ', not empty, pre, spark or pre,spark');
    } else if (isEmpty(r.epss)) {
      out.push('has epss_xmodel ' + r.epss_xmodel + ' but no epss');
    } else if (r.epss_xmodel.indexOf('pre') === 0 && isEmpty(r.epss_pre)) {
      out.push('has epss_xmodel pre but no epss_pre');
    }
  }
  if (hasKey(r, 'epss_spark') && !isEmpty(r.epss_spark)) {
    var sp = r.epss_spark;
    if (typeof sp !== 'string' || sp.length > 800 || !SPARK_POINTS.test(sp)) {
      out.push('has epss_spark that is not a points list of numbers');
    } else if (sp.split(' ').length > SPARK_MAX_POINTS) {
      out.push('has epss_spark with over ' + SPARK_MAX_POINTS + ' points');
    }
  }
  ['ratio_now', 'ratio_pre'].forEach(function (k) {
    if (hasKey(r, k) && !isEmpty(r[k]) && !(typeof r[k] === 'string' && RATIO_SHAPE.test(r[k]))) {
      out.push('has ' + k + ' ' + JSON.stringify(r[k]) + ', not empty or a number');
    }
  });
  // The ratio is (CVSS / 10) / EPSS to one decimal: recompute it from the row.
  [['ratio_now', 'epss'], ['ratio_pre', 'epss_pre']].forEach(function (pair) {
    var ratio = r[pair[0]], e = r[pair[1]];
    if (isEmpty(ratio) || !RATIO_SHAPE.test(String(ratio))) return;
    var cv = Number(r.cvss), ev = Number(e);
    if (isEmpty(e) || !(ev > 0) || !(cv > 0 && cv <= 10)) {
      out.push('has ' + pair[0] + ' ' + ratio + ' but no CVSS or ' + pair[1] + ' to compute it from');
    } else if (Math.abs((cv / 10) / ev - Number(ratio)) > 0.11) {
      out.push('has ' + pair[0] + ' ' + ratio + ' but (CVSS / 10) / ' + pair[1] + ' is ' + ((cv / 10) / ev).toFixed(1));
    }
  });
  return out;
}

/* T-0522: the cve.now fields. They arrive on nKEV rows (only when the entry carries them) and on
   every CVEs row. A row written before them carries none and checks clean; one that carries them
   is held to the exporter's shapes, because the page builds a link from a Metasploit path, an
   Exploit-DB id and an advisory id, and prints the rest. The shape rule behind absence: a flag that
   cve.now did not evaluate is simply not written (never "none"), so an empty value here means
   "nothing to show", not "checked and clear". */
var SSVC_EXPL = { none: 1, poc: 1, active: 1 };
var SSVC_AUTO = { yes: 1, no: 1 };
var SSVC_IMPACT = { partial: 1, total: 1 };
// cve.now lists a Metasploit module as a repo-relative path; the page appends it to
// github.com/rapid7/metasploit-framework/blob/master/. No "..", plain charset, so no escaping is needed.
var MSF_PATH = /^modules\/[A-Za-z0-9_.\/-]+\.rb$/;
var EDB_ID = /^\d{1,8}$/;
// Starts with a digit, or v and a digit; no wildcard. The exporter's validator for a fixed version
// (cve.now carries junk such as "log4j-core*").
var FIXED_VERSION = /^[vV]?\d[0-9A-Za-z.+_-]{0,39}$/;
// The real exporter output (T-0522 sample) joins one fixed version per product branch with ", "
// ("10.4.3, 10.2.7"; Windows builds "10.0.14393.9612, 10.0.17763.9376"). Every item must be a version.
var FIXED_MAX_ITEMS = 12;
var FIXED_MAX_LEN = 300;
function fixedProblem(v) {
  if (typeof v !== 'string' || v.length > FIXED_MAX_LEN) return 'not empty or a version, or a comma-separated list of versions';
  var items = v.split(',');
  if (items.length > FIXED_MAX_ITEMS) return 'lists ' + items.length + ' versions, over ' + FIXED_MAX_ITEMS;
  for (var i = 0; i < items.length; i++) {
    if (!FIXED_VERSION.test(items[i].replace(/^ /, ''))) return 'not empty or a version, or a comma-separated list of versions';
  }
  return '';
}
var ALIAS_ID = /^(?:GHSA(?:-[a-z0-9]{4}){3}|EUVD-\d{4}-\d{4,})$/i;
var MAX_LIST = 25;
function cvenowProblems(r) {
  var out = [];
  [['ssvc_expl', SSVC_EXPL], ['ssvc_auto', SSVC_AUTO], ['ssvc_impact', SSVC_IMPACT]].forEach(function (p) {
    if (hasKey(r, p[0]) && !isEmpty(r[p[0]]) && !(typeof r[p[0]] === 'string' && p[1][r[p[0]]] === 1)) {
      out.push('has ' + p[0] + ' ' + JSON.stringify(r[p[0]]) + ', not empty or one of ' + Object.keys(p[1]).join('/'));
    }
  });
  function list(k, re) {
    if (!hasKey(r, k)) return;
    var v = r[k];
    if (!Array.isArray(v)) { out.push('has ' + k + ' that is not a list'); return; }
    if (v.length > MAX_LIST) out.push('has ' + v.length + ' ' + k + ', over ' + MAX_LIST);
    v.forEach(function (x) {
      if (typeof x !== 'string' || !re.test(x) || x.indexOf('..') !== -1 || x.length > 200) {
        out.push('has ' + k + ' entry ' + JSON.stringify(x) + ', not the expected shape');
      }
    });
  }
  list('msf', MSF_PATH);
  list('edb', EDB_ID);
  list('aliases', ALIAS_ID);
  if (hasKey(r, 'fixed') && !isEmpty(r.fixed) && fixedProblem(r.fixed)) {
    out.push('has fixed ' + JSON.stringify(r.fixed) + ', ' + fixedProblem(r.fixed));
  }
  if (hasKey(r, 'kev_due') && !isEmpty(r.kev_due) && isNaN(realDay(r.kev_due))) {
    out.push('has kev_due ' + JSON.stringify(r.kev_due) + ', not empty or a real day');
  }
  return out;
}

/* T-0532: the fields part E of the task adds, on either tab's rows: the Details fact
   sheet prints or links them, so each holds the exporter's shape (design section 5).
   `desc` is the CVE record's English description, capped at 3,000 characters; `cwe` a
   list of at most five CWE ids; `affected` at most six affected-version lines, each at
   most 160 characters. Control characters in any of them are caught by
   controlProblems, which already runs over the whole row. A row that carries none of
   the new keys checks clean: a wire.yml written before part E is valid input. */
var DESC_MAX_LEN = 3000;
var CWE_SHAPE = /^CWE-\d+$/;
var CWE_MAX = 5;
var AFFECTED_MAX = 6;
var AFFECTED_ITEM_MAX = 160;
function briefly(v) {
  var t = JSON.stringify(v);
  return t.length > 80 ? t.slice(0, 77) + '...' : t;
}
function detailsFieldProblems(r) {
  var out = [];
  if (hasKey(r, 'desc') && !isEmpty(r.desc) &&
      !(typeof r.desc === 'string' && r.desc.length <= DESC_MAX_LEN && r.desc.trim() !== '')) {
    out.push('has desc ' + briefly(r.desc) + ', not empty or text up to ' + DESC_MAX_LEN + ' characters');
  }
  if (hasKey(r, 'cwe')) {
    if (!Array.isArray(r.cwe)) out.push('has cwe that is not a list');
    else {
      if (r.cwe.length > CWE_MAX) out.push('has ' + r.cwe.length + ' cwe entries, over ' + CWE_MAX);
      r.cwe.forEach(function (x) {
        if (typeof x !== 'string' || !CWE_SHAPE.test(x)) {
          out.push('has a cwe entry ' + briefly(x) + ', not a CWE id');
        }
      });
    }
  }
  if (hasKey(r, 'affected')) {
    if (!Array.isArray(r.affected)) out.push('has affected that is not a list');
    else {
      if (r.affected.length > AFFECTED_MAX) {
        out.push('has ' + r.affected.length + ' affected entries, over ' + AFFECTED_MAX);
      }
      r.affected.forEach(function (x) {
        if (typeof x !== 'string' || !x.trim() || x.length > AFFECTED_ITEM_MAX) {
          out.push('has an affected entry ' + briefly(x) + ', not text up to ' +
            AFFECTED_ITEM_MAX + ' characters');
        }
      });
    }
  }
  /* The vector the score came from, on nKEV rows as well now (the CVEs tab carried
     it from T-0522). */
  if (hasKey(r, 'cvss_vector') && !isEmpty(r.cvss_vector) &&
      !(typeof r.cvss_vector === 'string' && r.cvss_vector.length <= 120 && CVSS_VECTOR.test(r.cvss_vector))) {
    out.push('has cvss_vector ' + briefly(r.cvss_vector) + ', not empty or a CVSS vector');
  }
  if (!isEmpty(r.cvss_vector) && isEmpty(r.cvss)) out.push('has a cvss_vector but no cvss');
  return out;
}

/* The `vulns:` section, against the canonical row schema (cve, added, vendor,
   product, cisa_added, evidence, older; T-0394 design section 4), the score
   (T-0399) and the pointers (T-0407).

   Every problem here is a WARNING, never a FAIL. The Pages gate in pages.yml
   keeps wire.yml only when every FAIL is a stale: one, so a vulnerability
   FAIL would drop the HEADLINES too, for a fault in a separate API read. The
   page already falls back on its own: it draws the unavailable notice when
   vulns_status is not ok or stale, and skips a row with no cve or added.

   The one exception is a description key, returned in `problems` (a FAIL):
   only a code defect could produce one, the publisher refuses it too, and the
   Wire never ships body text. `now` is epoch ms. */
function checkVulns(doc, now) {
  var problems = [];
  var warnings = [];
  var rows = doc.vulns;
  if (!hasKey(doc, 'vulns_status') && !hasKey(doc, 'vulns')) {
    warnings.push('no vulns section, so the Vulnerabilities tab shows its ' +
      'unavailable notice (a wire.yml from before T-0396?)');
    return { problems: problems, warnings: warnings, total: 0 };
  }
  var status = doc.vulns_status;
  if (!VULN_STATUSES[status]) {
    warnings.push('vulns_status is ' + JSON.stringify(status) +
      ', not ok, stale or unavailable; the tab will show its unavailable notice');
  } else if (status !== 'ok') {
    warnings.push('vulns_status is ' + status + ': the VulnCheck read failed on ' +
      'the last run' + (status === 'stale' ? ', so the tab shows the cached rows' : ''));
  }
  if (!Array.isArray(rows)) rows = [];
  if ((status === 'ok' || status === 'stale') && !rows.length) {
    warnings.push('vulns_status is ' + status + ' but there are no rows');
  }

  var vgen = Date.parse(doc.vulns_generated_at || '');
  if (rows.length && !vgen) {
    warnings.push('vulns_generated_at is missing or unparseable: ' + doc.vulns_generated_at);
  } else if (vgen && (now - vgen) / 3600000 > VULNS_STALE_HOURS) {
    warnings.push('vulns_generated_at is ' + ((now - vgen) / 3600000).toFixed(1) +
      ' hours old, over ' + VULNS_STALE_HOURS);
  }

  var seen = Object.create(null);
  var nCisa = 0, nOlder = 0, nUnscored = 0;
  var nSev = { critical: 0, high: 0, medium: 0, low: 0 };
  var nPtr = { reported: 0, stories: 0, et: 0, nuclei: 0, detect: 0 };
  // T-0496: counted apart, since a file written before them declares neither.
  var nRule = { cisa_sigma: 0, snort3: 0 };
  var nNoRuleFields = 0;
  var nNkev = { disclosed: 0, prenvd: 0, epss: 0, epss_pre: 0 };
  rows.forEach(function (r, n) {
    r = r || {};
    var where = 'vulns row ' + (n + 1) + ' (' + String(r.cve || '?') + ')';
    var vp = vedasProblem(r);
    if (vp) problems.push(where + ' ' + vp);
    if (hasKey(r, 'description')) {
      problems.push(where + ' carries a description field. The Wire publishes ' +
        'no body text, VulnCheck\'s included.');
    }
    if (!CVE_SHAPE.test(String(r.cve || ''))) warnings.push(where + ' has no CVE id in CVE shape');
    if (!DAY_SHAPE.test(String(r.added || ''))) warnings.push(where + ' has no added day (YYYY-MM-DD)');
    if (typeof r.vendor !== 'string') warnings.push(where + ' has no vendor field');
    ['cisa_added', 'evidence'].forEach(function (k) {
      var v = r[k];
      if (v !== undefined && v !== null && v !== '' && !DAY_SHAPE.test(String(v))) {
        warnings.push(where + ' has ' + k + ' ' + JSON.stringify(v) + ', not empty or a day');
      }
    });
    if (typeof r.older !== 'boolean') warnings.push(where + ' has a non-boolean older');
    var sp = scoreProblem(r);
    if (sp) warnings.push(where + ' ' + sp);
    else if (SEVERITIES[String(r.severity)]) nSev[r.severity]++;
    else nUnscored++;
    pointerProblems(r).forEach(function (p) { warnings.push(where + ' ' + p); });
    nkevProblems(r).forEach(function (p) { warnings.push(where + ' ' + p); });
    cvenowProblems(r).forEach(function (p) { warnings.push(where + ' ' + p); });
    if (!isEmpty(r.disclosed)) nNkev.disclosed++;
    if (typeof r.gap === 'number' && r.gap < 0) nNkev.prenvd++;
    if (!isEmpty(r.epss)) nNkev.epss++;
    if (!isEmpty(r.epss_pre)) nNkev.epss_pre++;
    if (reportsOf(r).length) nPtr.reported++;
    if (Number(r.stories) > 0) nPtr.stories++;
    var hasEt = Array.isArray(r.et_sids) && r.et_sids.length > 0;
    var hasNu = typeof r.nuclei === 'string' && r.nuclei !== '';
    var hasCs = Array.isArray(r.cisa_sigma) && r.cisa_sigma.length > 0;
    var hasSn = Array.isArray(r.snort3_sids) && r.snort3_sids.length > 0;
    if (hasEt) nPtr.et++;
    if (hasNu) nPtr.nuclei++;
    if (hasCs) nRule.cisa_sigma++;
    if (hasSn) nRule.snort3++;
    if (hasEt || hasNu || hasCs || hasSn) nPtr.detect++;
    if (!hasKey(r, 'cisa_sigma') || !hasKey(r, 'snort3_sids')) nNoRuleFields++;
    if (r.cve && seen[r.cve]) warnings.push(where + ' repeats a CVE');
    if (r.cve) seen[r.cve] = 1;
    if (r.cisa_added) nCisa++;
    if (r.older === true) nOlder++;
  });

  var vc = doc.vulns_counts || {};
  if (rows.length && (Number(vc.total) !== rows.length || Number(vc.cisa) !== nCisa ||
      Number(vc.older) !== nOlder)) {
    warnings.push('vulns_counts disagree with the rows: declared total=' + vc.total +
      ' cisa=' + vc.cisa + ' older=' + vc.older + ', actual ' + rows.length + '/' +
      nCisa + '/' + nOlder);
  }
  // The per-band counts arrive with T-0399; a file written before carries
  // none, and is not held to them.
  if (rows.length && hasKey(vc, 'unscored')) {
    var bad = Object.keys(nSev).filter(function (k) { return Number(vc[k]) !== nSev[k]; });
    if (Number(vc.unscored) !== nUnscored) bad.push('unscored');
    if (bad.length) {
      warnings.push('vulns_counts severity disagrees with the rows on ' + bad.join(', ') +
        ': declared ' + bad.map(function (k) { return k + '=' + vc[k]; }).join(' ') +
        ', actual ' + bad.map(function (k) { return k + '=' + (k === 'unscored' ? nUnscored : nSev[k]); }).join(' '));
    }
  }
  // The pointer counts arrive with T-0407 and feed the page's chips.
  if (rows.length && hasKey(vc, 'reported')) {
    var badp = Object.keys(nPtr).filter(function (k) { return Number(vc[k]) !== nPtr[k]; });
    if (badp.length) {
      warnings.push('vulns_counts pointers disagree with the rows on ' + badp.join(', ') +
        ': declared ' + badp.map(function (k) { return k + '=' + vc[k]; }).join(' ') +
        ', actual ' + badp.map(function (k) { return k + '=' + nPtr[k]; }).join(' '));
    }
  }
  // T-0496: the CISA Sigma and Snort 3 counts feed the two filter buttons. A file that
  // declares either must carry both fields on every row, and the declared count must
  // match the rows; rows that carry rules while the count is missing would draw the Rules
  // chip but no filter button, so that warns too. A file with neither is an older one.
  if (rows.length) {
    var declares = hasKey(vc, 'cisa_sigma') || hasKey(vc, 'snort3');
    if (declares && nNoRuleFields) {
      warnings.push('vulns_counts declares CISA Sigma or Snort 3 counts but ' + nNoRuleFields +
        ' of ' + rows.length + ' rows lack cisa_sigma or snort3_sids');
    }
    Object.keys(nRule).forEach(function (k) {
      if (hasKey(vc, k)) {
        if (Number(vc[k]) !== nRule[k]) {
          warnings.push('vulns_counts ' + k + ' disagrees with the rows: declared ' + vc[k] +
            ', actual ' + nRule[k]);
        }
      } else if (nRule[k] > 0) {
        warnings.push('rows carry ' + nRule[k] + ' ' + k + ' rule rows but vulns_counts has no ' +
          k + ', so the filter button is not drawn');
      }
    });
  }
  // The nKEV counts arrive with T-0468 and feed the page's pre-NVD chip.
  if (rows.length && hasKey(vc, 'prenvd')) {
    var badn = Object.keys(nNkev).filter(function (k) { return Number(vc[k]) !== nNkev[k]; });
    if (badn.length) {
      warnings.push('vulns_counts nKEV fields disagree with the rows on ' + badn.join(', ') +
        ': declared ' + badn.map(function (k) { return k + '=' + vc[k]; }).join(' ') +
        ', actual ' + badn.map(function (k) { return k + '=' + nNkev[k]; }).join(' '));
    }
  }
  return { problems: problems, warnings: warnings, total: rows.length };
}

/* The `cves:` section (T-0522), the CVEs tab. The same WARN policy as `vulns:`, for the same reason:
   pages.yml drops the whole wire.yml on a non-stale FAIL, and the headlines must never depend on
   the cve.now read. Two things are a FAIL, because only a code defect could produce them and the
   Wire's rules forbid them: a row carrying body text (`description`, `summary` or `context`), since
   cve.now's model-written summaries are never published (design, Part 4: it omitted a fix status
   3 of 3 times, affected versions 6 of 6, and invented a claim once).

   The guarantee stated at the exporter and re-checked here: every row is a CVE the selection rule
   admits. Each signal the row lists must be visible in the row (a Metasploit signal with no Metasploit
   module is a claim the page cannot show), and each signal the row shows must be listed. `now` is
   epoch ms. A CVE id in both sections is a FAIL, decided in check() (the two tabs are disjoint by
   construction, and a repeat means the exporter's exclusion broke). */
var CVES_KEYS = ['cve', 'published', 'vendor', 'product', 'title', 'cvss', 'cvss_version', 'severity',
  'scored_by', 'epss', 'epss_pct', 'epss_date', 'epss_max', 'epss_spark', 'signals', 'msf', 'edb',
  'et_sids', 'nuclei', 'cisa_sigma', 'snort3_sids', 'ssvc_expl', 'ssvc_auto', 'ssvc_impact',
  'fixed', 'aliases', 'stories', 'cvss_vector', 'kev_product', 'kev_product_n'];
/* Revision 3 (Joseph, 2026-11-01): the original four selection arms are crit_noauth_kev_product (CVSS 9.0 or
   higher, AV:N/PR:N/UI:N in the row's own vector, AND a product CISA has listed before), msf, edb and
   epss90 (FIRST percentile 0.90 or higher). nuclei and et are shown as the Rules chip and are NOT arms:
   a row with only those admits nothing. T-0564 adds vedas_weaponized (VEDAS >= 0.80, CVSS >= 7, AV:N). */
var CVES_SIGNALS = { crit_noauth_kev_product: 1, msf: 1, edb: 1, epss90: 1, vedas_weaponized: 1, nuclei: 1, et: 1 };
var CVES_ARMS = ['crit_noauth_kev_product', 'msf', 'edb', 'epss90', 'vedas_weaponized'];
var CVSS_VECTOR = /^(?:CVSS:\d\.\d\/)?[A-Za-z]{1,3}:[A-Za-z0-9]{1,3}(?:\/[A-Za-z]{1,3}:[A-Za-z0-9]{1,3})*$/;
var CVES_BODY_KEYS = ['description', 'summary', 'context'];
var EPSS_HIGH_PCT = 0.90;
function signalFacts(r) {
  var epct = Number(r.epss_pct);
  var cv = Number(r.cvss);
  var vec = typeof r.cvss_vector === 'string' ? r.cvss_vector : '';
  var tokens = vec.split('/');
  return {
    crit_noauth_kev_product: !isEmpty(r.cvss) && cv >= 9 && tokens.indexOf('AV:N') !== -1 &&
      tokens.indexOf('PR:N') !== -1 && tokens.indexOf('UI:N') !== -1 &&
      typeof r.kev_product === 'string' && r.kev_product !== '' && isCount(r.kev_product_n) && r.kev_product_n > 0,
    msf: Array.isArray(r.msf) && r.msf.length > 0,
    edb: Array.isArray(r.edb) && r.edb.length > 0,
    nuclei: typeof r.nuclei === 'string' && r.nuclei !== '',
    et: Array.isArray(r.et_sids) && r.et_sids.length > 0,
    epss90: !isEmpty(r.epss_pct) && epct >= EPSS_HIGH_PCT,
    vedas_weaponized: typeof r.vedas === 'number' && r.vedas >= 0.80 && r.vedas <= 1 &&
      !isEmpty(r.cvss) && cv >= 7 && tokens.indexOf('AV:N') !== -1
  };
}
function checkCves(doc, now) {
  var problems = [];
  var warnings = [];
  var rows = doc.cves;
  if (!hasKey(doc, 'cves_status') && !hasKey(doc, 'cves')) {
    warnings.push('no cves section, so the CVEs tab shows its unavailable notice ' +
      '(a wire.yml from before T-0522?)');
    return { problems: problems, warnings: warnings, total: 0 };
  }
  var status = doc.cves_status;
  if (!VULN_STATUSES[status]) {
    warnings.push('cves_status is ' + JSON.stringify(status) +
      ', not ok, stale or unavailable; the tab will show its unavailable notice');
  } else if (status !== 'ok') {
    warnings.push('cves_status is ' + status + ': the cve.now read failed on the last run' +
      (status === 'stale' ? ', so the tab shows the cached rows' : ''));
  }
  if (!Array.isArray(rows)) rows = [];
  if (status === 'stale' && !rows.length) warnings.push('cves_status is stale but there are no rows');
  if (status === 'ok' && !rows.length) {
    warnings.push('cves_status is ok but there are no rows: possible if nothing passes the rule, ' +
      'but the measurement behind the rule found 25 rows over 30 days');
  }
  if (rows.length > CVES_CAP) warnings.push('carries ' + rows.length + ' rows, over the cap of ' + CVES_CAP);

  var cgen = Date.parse(doc.cves_generated_at || '');
  if (rows.length && !cgen) {
    warnings.push('cves_generated_at is missing or unparseable: ' + doc.cves_generated_at);
  } else if (cgen && (now - cgen) / 3600000 > CVES_STALE_HOURS) {
    warnings.push('cves_generated_at is ' + ((now - cgen) / 3600000).toFixed(1) +
      ' hours old, over ' + CVES_STALE_HOURS);
  }
  var windowDays = Number(doc.window_days);
  var oldest = cgen && windowDays ? cgen - (windowDays + 1) * 86400000 : null;

  var seen = Object.create(null);
  var nSev = { critical: 0, high: 0, medium: 0, low: 0 };
  var nUnscored = 0;
  var nSig = { crit_noauth_kev_product: 0, msf: 0, edb: 0, epss90: 0, vedas_weaponized: 0, nuclei: 0, et: 0 };
  var byVendor = Object.create(null);
  rows.forEach(function (r, n) {
    r = r || {};
    var where = 'cves row ' + (n + 1) + ' (' + String(r.cve || '?') + ')';
    var vp = vedasProblem(r);
    if (vp) problems.push(where + ' ' + vp);
    CVES_BODY_KEYS.forEach(function (k) {
      if (hasKey(r, k)) {
        problems.push(where + ' carries a ' + k + ' field. The Wire publishes no body text, and ' +
          'cve.now\'s model-written summaries are never published.');
      }
    });
    var missing = CVES_KEYS.filter(function (k) { return !hasKey(r, k); });
    if (missing.length) warnings.push(where + ' lacks keys the schema promises: ' + missing.join(', '));
    if (!CVE_SHAPE.test(String(r.cve || ''))) warnings.push(where + ' has no CVE id in CVE shape');
    if (isNaN(realDay(r.published))) {
      warnings.push(where + ' has published ' + JSON.stringify(r.published) + ', not a real day');
    } else if (oldest && realDay(r.published) < oldest) {
      warnings.push(where + ' was published ' + r.published + ', outside the ' + windowDays + '-day window');
    } else if (cgen && realDay(r.published) > cgen) {
      warnings.push(where + ' was published ' + r.published + ', after cves_generated_at');
    }
    ['vendor', 'product', 'title'].forEach(function (k) {
      if (hasKey(r, k) && typeof r[k] !== 'string') warnings.push(where + ' has a ' + k + ' that is not text');
    });
    if (typeof r.title === 'string' && r.title.length > 500) {
      warnings.push(where + ' has a title of ' + r.title.length + ' characters, over 500');
    }
    if (typeof r.vendor === 'string' && r.vendor.indexOf('|') !== -1) {
      warnings.push(where + ' has a vendor containing "|", which the vendor filter cannot match');
    }
    var sp = scoreProblem(r);
    if (sp) warnings.push(where + ' ' + sp);
    else if (SEVERITIES[String(r.severity)]) nSev[r.severity]++;
    else nUnscored++;
    pointerProblems(r).forEach(function (p) { warnings.push(where + ' ' + p); });
    nkevProblems(r).forEach(function (p) { warnings.push(where + ' ' + p); });
    cvenowProblems(r).forEach(function (p) { warnings.push(where + ' ' + p); });
    if (hasKey(r, 'kev_product') && !isEmpty(r.kev_product) && !(typeof r.kev_product === 'string' && r.kev_product.length <= 120)) {
      warnings.push(where + ' has a kev_product that is not short text');
    }
    if (hasKey(r, 'kev_product_n') && !isEmpty(r.kev_product_n) && !(isCount(r.kev_product_n))) {
      warnings.push(where + ' has kev_product_n ' + JSON.stringify(r.kev_product_n) + ', not empty or a count');
    }
    if (isEmpty(r.kev_product) !== (isEmpty(r.kev_product_n) || r.kev_product_n === 0)) {
      warnings.push(where + ' carries kev_product and kev_product_n only in part (a product needs its count of earlier CISA KEV entries, and a count needs its product)');
    }
    // The signals the row lists against the facts the row shows.
    var listed = Array.isArray(r.signals) ? r.signals : null;
    if (!listed) warnings.push(where + ' has signals that are not a list');
    else {
      listed.forEach(function (s) {
        if (!CVES_SIGNALS[s]) warnings.push(where + ' lists unknown signal ' + JSON.stringify(s));
      });
      var facts = signalFacts(r);
      Object.keys(CVES_SIGNALS).forEach(function (s) {
        var has = listed.indexOf(s) !== -1;
        if (has && !facts[s]) warnings.push(where + ' lists signal ' + s + ' but the row shows no ' + s + ' fact');
        if (!has && facts[s]) warnings.push(where + ' shows ' + s + ' but does not list it as a signal');
        if (facts[s]) nSig[s]++;
      });
      if (!CVES_ARMS.some(function (s) { return listed.indexOf(s) !== -1; })) {
        warnings.push(where + ' lists no selection arm (' + CVES_ARMS.join(', ') + '), so nothing admits it under the rule');
      }
    }
    if (r.cve && seen[r.cve]) warnings.push(where + ' repeats a CVE');
    if (r.cve) seen[r.cve] = 1;
    if (!isEmpty(r.cisa_added) || (hasKey(r, 'kev_due') && !isEmpty(r.kev_due))) {
      warnings.push(where + ' carries a CISA KEV date, but the tab lists CVEs not on a KEV list');
    }
    if (typeof r.vendor === 'string' && r.vendor) byVendor[r.vendor] = (byVendor[r.vendor] || 0) + 1;
  });

  var cc = doc.cves_counts || {};
  if (rows.length && Number(cc.total) !== rows.length) {
    warnings.push('cves_counts total disagrees with the rows: declared ' + cc.total + ', actual ' + rows.length);
  }
  if (rows.length && hasKey(cc, 'unscored')) {
    var bad = Object.keys(nSev).filter(function (k) { return Number(cc[k]) !== nSev[k]; });
    if (Number(cc.unscored) !== nUnscored) bad.push('unscored');
    if (bad.length) {
      warnings.push('cves_counts severity disagrees with the rows on ' + bad.join(', '));
    }
  }
  // A signal count the file declares must match the rows; one it does not declare is not held to it.
  Object.keys(nSig).forEach(function (k) {
    if (rows.length && hasKey(cc, k) && Number(cc[k]) !== nSig[k]) {
      warnings.push('cves_counts ' + k + ' disagrees with the rows: declared ' + cc[k] + ', actual ' + nSig[k]);
    }
  });
  // The vendor chips filter on the label exactly; one no row carries selects an empty page.
  var vs = Array.isArray(doc.cve_vendors) ? doc.cve_vendors : [];
  vs.forEach(function (v) {
    var lab = v && v.label;
    if (typeof lab !== 'string' || !lab) { warnings.push('cve_vendors has an entry with no label'); return; }
    if (!byVendor[lab]) warnings.push('cve_vendors chip "' + lab + '" matches no row, so it would filter the tab to nothing');
    else if (Number(v.count) !== byVendor[lab]) {
      warnings.push('cve_vendors chip "' + lab + '" declares ' + v.count + ' rows, actual ' + byVendor[lab]);
    }
  });
  return { problems: problems, warnings: warnings, total: rows.length };
}

function verdict(status, reason, problems, warnings, counts, vulnWarnings, cveWarnings) {
  return {
    status: status,
    reason: reason || null,
    problems: problems || [],
    warnings: warnings || [],
    counts: counts || null,
    // Vulnerabilities-tab problems, reported as WARN (see checkVulns).
    vulnWarnings: vulnWarnings || [],
    // CVEs-tab problems, reported as WARN too (see checkCves).
    cveWarnings: cveWarnings || []
  };
}

function normTitle(t) {
  return String(t || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

/* `doc` is the parsed wire.yml, or null when it could not be read.
   `sources` is the parsed wire-sources.yml `sources` map, or null if absent.
   `now` is epoch ms, injected so the staleness case is testable.
   `remote` is `{ generated_at }` from origin's copy of wire.yml, or null when
   origin's state could not be established. Injected for the same reason as
   `now`, and it is what separates the two ways this file goes old.

   Those two ways look identical from inside the working tree and are not the
   same event. The generator pushes wire.yml straight to origin every 15 minutes (to
   the wire-data branch; see tools/wire/push-wire-data.sh), so a clone nobody
   has fetched falls behind by exactly as many runs as
   it has sat there, while the live page stays current. Reading local age alone,
   this gate called a three-day-old clone a dead timer and named LXC-102 as the
   cause; measured over the ten days after the two-hourly cadence landed, the
   timer had missed zero of its runs on every occasion it said so. An alarm that
   fires on a healthy pipeline is spent, so the local file's age is now only the
   trigger for the question, never the answer to it. */
function check(doc, sources, now, remote) {
  if (!doc) {
    return verdict('NOT CHECKED', 'wire.yml is absent or unparseable. It is not ' +
      'committed on main: run `npm run wire:pull` to fetch the newest copy from ' +
      'origin/wire-data (the generator on LXC-102 writes it there every 15 minutes).');
  }

  var items = doc.items;
  if (!Array.isArray(items) || !items.length) {
    return verdict('NOT CHECKED', 'wire.yml declares no items, so this run ' +
      'verified nothing about the page content.');
  }

  var problems = [];
  var warnings = [];

  var gen = Date.parse(doc.generated_at || '');
  if (!gen) {
    problems.push('generated_at is missing or unparseable: ' + doc.generated_at);
  } else if ((now - gen) / 3600000 > STALE_HOURS) {
    var ageH = ((now - gen) / 3600000).toFixed(1);
    var rgen = remote ? Date.parse(remote.generated_at || '') : NaN;

    if (!rgen) {
      /* Which of the two happened is exactly what origin would have told us,
         so without it there is no verdict to give. Failing here would be the
         old wrong answer with a hedge attached. */
      return verdict('NOT CHECKED', 'the local wire.yml is ' + ageH + ' hours ' +
        'old, past the ' + STALE_HOURS + '-hour limit, but origin could not be ' +
        'read, so this run cannot tell a clone that needs pulling from a ' +
        'generator that has stopped. Run `git fetch origin` and re-run.');
    }

    if ((now - rgen) / 3600000 <= STALE_HOURS) {
      /* Origin is current, so the generator ran and this checkout simply did
         not follow it. Nothing was verified about the published page, which is
         NOT CHECKED rather than a pass, but nothing is wrong with it either. */
      return verdict('NOT CHECKED', 'this clone is behind, and the generator is ' +
        'healthy: the local wire.yml is ' + ageH + ' hours old while origin ' +
        'holds one generated ' + remote.generated_at + '. Run `git pull` and ' +
        're-run; nothing here says anything about LXC-102.');
    }

    /* Origin is stale too, so pulling would change nothing and the timer is
       the thing that stopped. This is the case the gate was built for. */
    problems.push('stale: generated_at is ' + ageH +
      ' hours old, over the ' + STALE_HOURS + '-hour limit, and origin is no ' +
      'fresher (' + remote.generated_at + '). The generator on ' +
      'LXC-102 has missed at least four consecutive runs.');
  }

  var windowDays = Number(doc.window_days);
  if (!windowDays) problems.push('window_days is missing or not a number');
  var oldestAllowed = gen && windowDays ? gen - windowDays * 86400000 : null;

  var seen = Object.create(null);
  var labelsPresent = Object.create(null);
  var nResearch = 0;
  var nVuln = 0;

  for (var i = 0; i < items.length; i++) {
    var it = items[i] || {};
    var where = 'item ' + (i + 1) + ' (' + String(it.title || '?').slice(0, 48) + ')';

    if (Object.prototype.hasOwnProperty.call(it, 'description')) {
      problems.push(where + ' carries a description field. The Wire aggregates ' +
        'by headline and attribution only; publisher article text must never ship.');
    }

    for (var f = 0; f < REQUIRED.length; f++) {
      if (!it[REQUIRED[f]]) problems.push(where + ' is missing ' + REQUIRED[f]);
    }

    if (it.url && String(it.url).indexOf('https://') !== 0) {
      problems.push(where + ' has a non-https url: ' + it.url);
    }

    if (it.kind && !KINDS[it.kind]) {
      problems.push(where + ' has an unknown kind: ' + it.kind);
    }
    if (it.kind === 'research') nResearch++;
    if (it.kind === 'vuln') nVuln++;

    var d = Date.parse(it.date || '');
    if (it.date && !d) {
      problems.push(where + ' has an unparseable date: ' + it.date);
    } else if (d && oldestAllowed && d < oldestAllowed) {
      problems.push(where + ' is outside the declared ' + windowDays +
        '-day window (' + it.date + ')');
    }

    var key = normTitle(it.title);
    if (key && seen[key]) problems.push(where + ' is a duplicate title');
    if (key) seen[key] = 1;

    (it.labels || []).forEach(function (l) { labelsPresent[String(l)] = 1; });

    // A digest row's source is VulnCheck, never a feed in wire-sources.yml.
    if (sources && it.source && it.kind !== 'vuln' &&
        !Object.prototype.hasOwnProperty.call(sources, it.source) &&
        warnings.indexOf(it.source) === -1) {
      warnings.push(it.source);
    }
  }

  /* The page renders chips straight from `topics` without checking them against
     the items, so a chip naming a label nothing carries is a control that
     selects an empty page. */
  var lc = doc.label_colors || {};
  (doc.topics || []).forEach(function (t) {
    var lab = t && t.label;
    if (lab && !labelsPresent[String(lab)]) {
      problems.push('topic chip "' + lab + '" matches no item label, so the ' +
        'chip would filter the page to nothing');
    }
    /* The colour is a class suffix the CSS palette defines for 1..PALETTE_SIZE.
       Anything outside that renders a chip with no colour variable set, which
       is a silent visual regression: the chip still works, it just goes grey
       while its siblings are coloured. */
    var col = t && t.color;
    if (!Number.isInteger(col) || col < 1 || col > PALETTE_SIZE) {
      problems.push('topic chip "' + lab + '" has colour ' + JSON.stringify(col) +
        ', which is outside the 1-' + PALETTE_SIZE + ' palette the CSS defines');
    } else if (lab && lc[lab] !== col) {
      problems.push('topic chip "' + lab + '" is colour ' + col +
        ' but label_colors says ' + JSON.stringify(lc[lab]) +
        ', so its tags would not match its chip');
    }
  });

  Object.keys(lc).forEach(function (lab) {
    var v = lc[lab];
    if (!Number.isInteger(v) || v < 1 || v > PALETTE_SIZE) {
      problems.push('label_colors["' + lab + '"] is ' + JSON.stringify(v) +
        ', outside the 1-' + PALETTE_SIZE + ' palette the CSS defines');
    }
  });

  /* A displayed label with no colour renders grey among coloured siblings.
     521 of the 532 labels this page draws are not chip topics, and leaving them
     uncoloured is precisely what made the first build look flat, so an
     unmapped one is a defect rather than a cosmetic gap. */
  var uncoloured = [];
  items.forEach(function (it) {
    (it.labels || []).slice(0, DISPLAYED_LABELS).forEach(function (l) {
      if (!Object.prototype.hasOwnProperty.call(lc, String(l)) &&
          uncoloured.indexOf(String(l)) === -1) {
        uncoloured.push(String(l));
      }
    });
  });
  if (uncoloured.length) {
    problems.push(uncoloured.length + ' displayed label(s) have no colour in ' +
      'label_colors, so they would render grey among coloured siblings: ' +
      uncoloured.slice(0, 6).join(', ') +
      (uncoloured.length > 6 ? ', …' : ''));
  }

  /* `vuln` is absent from a wire.yml written before T-0396 and counts as 0,
     so an older file still checks clean. */
  var c = doc.counts || {};
  var nNews = items.length - nResearch - nVuln;
  if (Number(c.total) !== items.length ||
      Number(c.research) !== nResearch ||
      Number(c.news) !== nNews ||
      Number(c.vuln || 0) !== nVuln) {
    problems.push('counts disagree with the item list: declared total=' +
      c.total + ' research=' + c.research + ' news=' + c.news + ' vuln=' + c.vuln +
      ', actual total=' + items.length + ' research=' + nResearch +
      ' news=' + nNews + ' vuln=' + nVuln);
  }

  var v = checkVulns(doc, now);
  problems = problems.concat(v.problems);
  var cv = checkCves(doc, now);
  problems = problems.concat(cv.problems);
  /* Revision 2 (Joseph, 2026-11-01): nKEVs and CVEs are disjoint, so the same information is never
     printed on both tabs. The exporter asserts it before writing; this is the second check, and a
     FAIL (the file is dropped, as for any data FAIL) because a repeat is a defect, not noise. */
  var nkevIds = Object.create(null);
  (Array.isArray(doc.vulns) ? doc.vulns : []).forEach(function (r) { if (r && r.cve) nkevIds[r.cve] = 1; });
  var both = Object.create(null);
  (Array.isArray(doc.cves) ? doc.cves : []).forEach(function (r) {
    if (r && r.cve && nkevIds[r.cve] && !both[r.cve]) {
      both[r.cve] = 1;
      problems.push('CVE id ' + r.cve + ' is in both the vulns and the cves sections. The nKEVs and CVEs tabs must not repeat a CVE.');
    }
  });

  return verdict(problems.length ? 'FAIL' : 'PASS', null, problems, warnings.sort(), {
    total: items.length, research: nResearch, news: nNews, vuln: nVuln, vulns: v.total, cves: cv.total
  }, v.warnings, cv.warnings);
}

/* Verifies wire/index.md still derives each row's day EXACTLY ONCE.

   The page groups rows under a day heading and the filter narrows to a picked
   day. Both need the same answer to "which day is this row". _config.yml sets no
   `timezone:`, so a second derivation elsewhere in the stack would not merely be
   redundant, it would disagree: Liquid's `date:` filter formats in the build
   host's zone while `new Date(iso)` in a browser is always UTC, and any headline
   filed within a few hours of midnight would sit under one day's heading and
   inside another day's filter results with nothing to report it.

   So the rule is that `data-day` carries the SAME `day` variable the grouping
   already computed. Re-deriving it in the template would still be internally
   consistent today and would still be a second definition of one rule, which is
   this codebase's signature failure and has now cost four separate defects.

   `src` is the text of wire/index.md, or null when it could not be read. This
   pins template STRUCTURE, not rendered output; that a reader's browser then
   filters correctly is the browser check. */
function checkPage(src, includes) {
  if (src === null || src === undefined) {
    return verdict('NOT CHECKED', 'wire/index.md is absent or unreadable, so ' +
      'nothing was verified about how the page derives each row\'s day.');
  }

  var problems = [];

  // The single derivation that both the heading and the filter must share.
  if (!/\{%-?\s*assign\s+day\s*=\s*i\.date\s*\|\s*date:\s*["']%Y-%m-%d["']/.test(src)) {
    problems.push('the `day` assign from i.date is missing or changed shape, so ' +
      'the grouping and the day filter no longer share one derivation');
  }

  // The row must carry that variable, not its own copy of the expression.
  if (!/data-day="\{\{-?\s*day\s*-?\}\}"/.test(src)) {
    if (/data-day="\{\{[^}]*i\.date/.test(src)) {
      problems.push('data-day re-derives the day from i.date instead of carrying ' +
        'the `day` variable the heading grouping already computed. Two ' +
        'definitions of one rule; use {{ day }}');
    } else {
      problems.push('rows carry no data-day="{{ day }}", so the day filter on ' +
        '/wire/ has nothing to match against and silently shows everything');
    }
  }

  // The heading grouping must still be driven by that same variable.
  if (!/\{%-?\s*if\s+day\s*!=\s*current_day\s*-?%\}/.test(src)) {
    problems.push('day headings are no longer grouped on the `day` variable, so ' +
      'a heading and the rows beneath it can disagree about the date');
  }

  /* The filter module reaches the reader through a versioned URL. Shipping new
     markup against a cached older script is invisible on a fresh browser and
     total on a returning one, which has already happened once here. */
  var v = src.match(/listing-filter\.js[^"]*\?v=(\d+)/);
  if (!v) {
    problems.push('the listing-filter.js tag carries no ?v= cache-bust, so a ' +
      'returning reader can get new markup against the old script');
  }

  problems = problems.concat(checkLegend(src));
  problems = problems.concat(checkTabNav(src));
  problems = problems.concat(checkCvesTab(src, includes));
  problems = problems.concat(checkNkevRow(src));
  problems = problems.concat(checkHeadlineRow(src));

  return verdict(problems.length ? 'FAIL' : 'PASS', null, problems, [], null);
}

/* The Headlines row (T-0532, Sol review_8c50e5967cc944d4 P1). Its text comes from
   publishers' feeds, so every output is escaped like the vuln rows'. The exporter
   decodes feed entities first (flatten), so escaping here prints them correctly.
   Bare prints allowed: `tgt` (a fixed attribute string the template assigns),
   `day` (pinned bare above: a date-filter output), and `i.source | slugify`
   (letters, digits and hyphens only). */
var HEADLINE_BARE = /^(?:tgt|day|i\.source\s*\|\s*slugify)$/;
function checkHeadlineRow(src) {
  var line = (src.split('\n').filter(function (l) { return l.indexOf('<div class="hl-wire__row"') === 0; }))[0];
  // No row line: nothing to escape here. The Details structure check requires the
  // wrapper on the real page, and the partial pages the other tests feed have none.
  if (!line) { return []; }
  return unescapedOutputs(line).filter(function (m) {
    var inner = m.replace(/^\{\{-?\s*/, '').replace(/\s*-?\}\}$/, '');
    return !HEADLINE_BARE.test(inner);
  }).map(function (m) {
    return 'the Headlines row prints ' + m + ' unescaped; feed text must reach the page through | escape';
  });
}

/* The nKEVs legend (T-0468.1). The explanatory text left the top of the tab and
   moved into a side legend, so three guarantees now live in the template's
   structure and nothing else would notice one breaking:

   1. The attribution stays where a reader cannot miss it. The short line above
      the filter bar names VulnCheck KEV, FIRST EPSS and the nKEV feed; the same
      links inside a legend that opens on demand would not count.
   2. The legend's samples are pictures of chips. listing-filter.js counts and
      filters whatever sits in the grid or carries a data-* attribute, so the
      legend must stay out of the grid and its captured markup must carry no
      data-*, no control and no id (it is printed twice, so an id would repeat).
   3. The legend is printed twice, once as the report-TOC aside and once as the
      narrow-screen details, from one capture, so the two cannot drift.

   Structure, not output: that the browser then hides one copy and shows the
   other is the browser check. */
function checkVedasCopy(legend, label) {
  var out = [];
  ["Exploit maturity (VEDAS)", "Estimation of Vulnerability Prevalence &amp; Exploit Maturity",
    "A.R.P. Syndicate", "150+ identifiers", "every 6 to 8 hours", "The source publishes no formula.",
    "A high score is not evidence that working exploit code exists or that the CVE has been exploited",
    "exploitation is what the nKEVs tab and CISA KEV are for", "An unscored CVE shows no maturity chip.",
    'href="https://www.exploit.observer/"', 'href="https://github.com/ARPSyndicate/cve-scores"'
  ].forEach(function (pin) {
    if (legend.indexOf(pin) < 0) out.push(label + ' lost VEDAS copy or credit: ' + pin);
  });
  if (!/VEDAS exploit maturity from <a [^>]*href="https:\/\/github\.com\/ARPSyndicate\/cve-scores"[^>]*>A\.R\.P\. Syndicate<\/a>/.test(legend)) {
    out.push(label + ' lost the VEDAS source credit');
  }
  return out;
}

function checkLegend(src) {
  var problems = [];
  var capOpen = src.search(/\{%-?\s*capture\s+legend_html\s*-?%\}/);
  var capEnd = src.search(/\{%-?\s*endcapture\s*-?%\}/);
  if (capOpen < 0 || capEnd < capOpen) {
    problems.push('the nKEVs legend is missing: no `capture legend_html` block, so ' +
      'the chip and filter explanations the tab relies on are gone');
    return problems;
  }
  var before = src.slice(0, capOpen);
  var legend = src.slice(capOpen, capEnd);
  problems = problems.concat(checkVedasCopy(legend, "legend"));

  // 1. Attribution above the filter bar, outside the legend.
  var line = before.match(/<p class="hl-wire__freshness hl-wire__freshness--v">[\s\S]*?<\/p>/);
  if (line && !/VEDAS exploit maturity from <a [^>]*href="https:\/\/github\.com\/ARPSyndicate\/cve-scores"[^>]*>A\.R\.P\. Syndicate<\/a>/.test(line[0])) {
    problems.push('the short v line lost VEDAS credit to A.R.P. Syndicate');
  }
  if (!line) {
    problems.push('the short nKEVs line (hl-wire__freshness--v) is missing above the legend, ' +
      'so the nKEV definition and the attribution are no longer visible without opening it');
  } else {
    ['vulncheck.com/kev', 'first.org/epss', 'vulns.xml', 'href="https://github.com/ARPSyndicate/cve-scores"'].forEach(function (needle) {
      if (line[0].indexOf(needle) < 0) {
        problems.push('the short nKEVs line no longer links ' + needle + ', so that ' +
          'attribution or feed is visible only inside the legend');
      }
    });
  }
  if (!/I do not curate/.test(legend)) {
    problems.push('the legend lost the statement that the data is VulnCheck\'s and not curated here');
  }
  if (!/Empirical Security/.test(legend)) {
    problems.push('the legend lost the EPSS attribution (generated by Empirical Security)');
  }

  // 2. Samples are not interactive, not countable, not filterable.
  if (/\sdata-[a-z]/i.test(legend)) {
    problems.push('the legend markup carries a data-* attribute, which the filter script ' +
      'would read as a filter attribute');
  }
  if (/<(button|input|details|summary|select|textarea)\b/i.test(legend)) {
    problems.push('the legend markup holds a control or details element: samples must not be interactive');
  }
  if (/\sid\s*=/i.test(legend)) {
    problems.push('the legend markup carries an id, but it is printed twice, so the id would repeat');
  }
  var anchors = legend.match(/<a\b[^>]*>/gi) || [];
  anchors.forEach(function (a) {
    if (!/href="https:\/\/(www\.vulncheck\.com|www\.first\.org|cve\.now|www\.exploit\.observer|github\.com\/ARPSyndicate\/cve-scores)[\/"]/.test(a)) {
      problems.push('a link in the legend that is not an attribution link: ' + a +
        ' (a sample chip must be a span, not a link)');
    }
  });

  // 3. Printed twice, once in each place, never inside the grid.
  var prints = src.match(/\{\{\s*legend_html\s*\}\}/g) || [];
  if (prints.length !== 2) {
    problems.push('the legend is printed ' + prints.length + ' time(s), expected 2 ' +
      '(the aside and the narrow-screen details)');
  }
  if (!/<aside class="hl-post-toc hl-legend" aria-label="Legend"/.test(src)) {
    problems.push('the legend aside is missing, or lost its aria-label="Legend" or the ' +
      'report table of contents class hl-post-toc');
  }
  if (!/<details class="hl-legend-mobile"[^>]*>\s*<summary>Legend<\/summary>/.test(src)) {
    problems.push('the narrow-screen legend details is missing or has no Legend summary');
  }
  var grid = src.match(/data-filter-item="\.hl-vuln"[\s\S]*?\{%-?\s*endfor\s*-?%\}\s*<\/div>/);
  if (!grid) {
    problems.push('could not find the vulnerability grid, so the legend could not be shown to sit outside it');
  } else if (/legend_html|hl-legend/.test(grid[0])) {
    problems.push('the legend sits inside the vulnerability grid, where the filter script would count it as rows');
  }
  return problems;
}


/* The CVEs tab (T-0522), as structure. Five guarantees live in the template and nothing else would
   notice one breaking:

   1. The tab exists and is reachable: a nav link to #cves, a section with that id inside the
      filter scope, and the filter script's cache-bust (the same rule as the day gate).
   2. The legend is printed twice from one capture, outside the grid, with samples that are not
      interactive or countable (the nKEVs legend's rules, for its own capture).
   3. The public claims survive: the callout still says being listed is not evidence of
      exploitation, that the list is a selection, what it excludes and when a row moves to the nKEVs tab, that
      Metasploit and Exploit-DB claims are confirmed against the publishers' indexes, the cap and the
      ranking; the attribution line above it (the callout's sources since T-0531, when the callout
      was cut to the selection rule and its limits) says what cve.now supplies, that the SSVC points
      are CISA's own assessment, the cve.now licence, where scores, exploits and KEV products come
      from, and links cve.now, FIRST and the feed.
   4. Every data-driven value the tab draws is escaped (T-0407 found unescaped vendor and product
      text on the nKEV tab). Checked on the tab's own markup and the shared include that draws the
      cve.now chips: each {{ }} output either carries `escape` or is a number or literal the
      template itself built.
   5. The include's only link targets are the four it names (advisories, EUVD, Metasploit, Exploit-DB),
      and nothing on the page or in the include mentions a GitHub proof of concept (Revision 2).

   `includes` is { name: text } for the _includes this tab uses, or absent when they could not be
   read (then 5 and the include half of 4 are NOT CHECKED, said in a problem line, never a pass). */
var SAFE_OUT = /^(?:c_[a-z]+|ex_n|msf_len|edb_len|kn|w_pc|ep_pct|pc_n|pc_sfx|st_n|rn_rules|sev|sev\s*\|\s*upcase|vc|cves_legend_html|wire\.window_days|wire\.cves\.size|g\.items\.size|forloop\.index|sg\s*\|\s*join:\s*'\|'|'[^']*'\s*\|\s*relative_url)$/;
// An expression ending in a numeric filter yields a number whatever the data held.
var NUMERIC_END = /\|\s*(?:round(?::\s*\d+)?|times:\s*[\d.]+|plus:\s*\d+|minus:\s*\d+|size|floor|modulo:\s*\d+)\s*$/;
function unescapedOutputs(text) {
  var bad = [];
  (text.match(/\{\{-?[\s\S]*?-?\}\}/g) || []).forEach(function (m) {
    var inner = m.replace(/^\{\{-?\s*/, '').replace(/\s*-?\}\}$/, '');
    if (/\|\s*escape\b/.test(inner)) return;
    if (SAFE_OUT.test(inner)) return;
    if (NUMERIC_END.test(inner)) return;
    bad.push(m);
  });
  return bad;
}

/* The nKEV row template (ESC lane, T-0522). The same rule the CVEs tab is held to holds for the
   row's own markup: every {{ }} output either carries `escape` or is a number the template forced.
   The four bare prints below are number-forced in their assigns, and are allowed bare only while
   that forcing is still there, so a refactor that prints the value unforced is caught outright. */
var NKEV_FORCED = [
  ['n_more', /\{%-?\s*assign\s+n_more\s*=\s*r\.reports_more\s*\|\s*default:\s*0\s*\|\s*plus:\s*0\s*-?%\}/,
    'reports_more'],
  ['gap_n', /\{%-?\s*assign\s+gap_n\s*=\s*r\.gap\s*\|\s*plus:\s*0\s*-?%\}/, 'gap'],
  ['gap_abs', /\{%-?\s*assign\s+gap_abs\s*=\s*gap_n\s*\|\s*times:\s*-1\s*-?%\}/, 'the gap'],
  ['n_src', /\{%-?\s*assign\s+n_src\s*=\s*n_reps\s*\|\s*plus:\s*n_more\s*-?%\}/, 'the report count']
];
function checkNkevRow(src) {
  if (src === null || src === undefined) {
    return ['NOT CHECKED: wire/index.md is absent, so the nKEV row template could not be verified'];
  }
  var m = /\{%-?\s*for r in wire\.vulns -?%\}[\s\S]*?\{%-?\s*endfor\s*-?%\}\s*<\/div>/.exec(src);
  if (!m) {
    return ['could not find the nKEV row template (for r in wire.vulns), so its outputs were not verified'];
  }
  var slice = m[0].replace(/\{%-?\s*comment\s*-?%\}[\s\S]*?\{%-?\s*endcomment\s*-?%\}/g, '')
    .replace(/\{%\s*comment\s*%\}[\s\S]*?\{%\s*endcomment\s*%\}/g, '');
  var problems = [];
  (slice.match(/\{\{-?[\s\S]*?-?\}\}/g) || []).forEach(function (out) {
    var inner = out.replace(/^\{\{-?\s*/, '').replace(/\s*-?\}\}$/, '');
    if (/\|\s*escape\b/.test(inner)) return;
    if (NUMERIC_END.test(inner)) return;
    if (/\.size\s*$/.test(inner)) return;   // Liquid's MethodLiteral: array/string size is a number
    for (var i = 0; i < NKEV_FORCED.length; i++) {
      if (new RegExp('^(?:' + NKEV_FORCED[i][0] + ')$').test(inner)) {
        if (!NKEV_FORCED[i][1].test(slice)) {
          problems.push('the nKEV row template does not force ' + inner + ' (' + NKEV_FORCED[i][2] +
            ') to a number: the pin for it changed or is missing, and a hostile value there breaks a filter attribute or the build');
        }
        return;
      }
    }
    problems.push('the nKEV row template prints ' + out + ' without escape, and it is not a number the template forced');
  });
  return problems;
}

/* The tab nav (G3, r2). The three tab counts (n_headlines, n_vulns, n_cves) print in
   hl-wtabs__nav, outside every <section>, so the section-scoped checkers never read them and
   the gate passed a hostile count straight through. Coverage here is the whole page outside
   the sections - the page header, the tab nav, the no-data else branches, the script tag and
   the footer include - held to the same rule the row templates are: every {{ }} output must
   carry `escape`, end in a numeric filter, or be one of the three tab counts, allowed only
   while its assign still forces the value to a number (the pin; reverting the forcing is
   caught even if the print moves). n_headlines' forcing is Liquid's own `plus`: it coerces a
   hostile string to a number (0), so nothing but a number prints from that assign. */
var TAB_FORCED = [
  ['n_headlines', /\{%-?\s*assign\s+n_headlines\s*=\s*wire\.counts\.research\s*\|\s*plus:\s*wire\.counts\.news\s*-?%\}/,
    'the headline count (plus, which coerces)'],
  ['n_vulns', /\{%-?\s*assign\s+n_vulns\s*=\s*wire\.vulns_counts\.total\s*\|\s*default:\s*0\s*\|\s*plus:\s*0\s*-?%\}/,
    'vulns_counts.total'],
  ['n_cves', /\{%-?\s*assign\s+n_cves\s*=\s*wire\.cves_counts\.total\s*\|\s*default:\s*0\s*\|\s*plus:\s*0\s*-?%\}/,
    'cves_counts.total']
];
function checkTabNav(src) {
  if (src === null || src === undefined) {
    return ['NOT CHECKED: wire/index.md is absent, so the tab nav was not verified'];
  }
  var problems = [];
  for (var i = 0; i < TAB_FORCED.length; i++) {
    if (!TAB_FORCED[i][1].test(src)) {
      problems.push('the tab count ' + TAB_FORCED[i][0] + ' (' + TAB_FORCED[i][2] +
        ') is no longer forced to a number in its assign: a hostile value in that count ' +
        'prints as raw markup in the tab nav, which sits outside the sections every ' +
        'other page check covers');
    }
  }
  if (!/<nav class="hl-wtabs__nav"/.test(src)) {
    problems.push('the tab nav (hl-wtabs__nav) is missing, so the page has no visible tab list');
    return problems;
  }
  // Everything outside a section: strip each marked <section> ... </section> span, leaving the
  // header, the nav, the else branches, the script tag and the includes. A section opened but
  // never closed cannot silently widen the checked region: the strip only removes a complete
  // span, so anything outside it - or a dangling <section> with no close - stays in scope.
  var outside = src.replace(/<section\b[\s\S]*?<\/section>/g, '\n')
    .replace(/\{%-?\s*comment\s*-?%\}[\s\S]*?\{%-?\s*endcomment\s*-?%\}/g, '')
    .replace(/\{%\s*comment\s*%\}[\s\S]*?\{%\s*endcomment\s*%\}/g, '');
  (outside.match(/\{\{-?[\s\S]*?-?\}\}/g) || []).forEach(function (out) {
    var inner = out.replace(/^\{\{-?\s*/, '').replace(/\s*-?\}\}$/, '');
    if (/\|\s*escape\b/.test(inner)) return;
    if (NUMERIC_END.test(inner)) return;
    if (/^'[^']*'\s*\|\s*relative_url$/.test(inner)) return;   // a quoted site path, not data
    for (var i = 0; i < TAB_FORCED.length; i++) {
      if (new RegExp('^(?:' + TAB_FORCED[i][0] + ')$').test(inner)) return; // pin checked unconditionally above
    }
    problems.push('the tab nav region (the page outside its sections) prints ' + out +
      ' without escape, and it is not a number the template forced');
  });
  return problems;
}
function checkCvesTab(src, includes) {
  var problems = [];
  var open = src.search(/<section id="cves"/);
  if (open < 0) {
    problems.push('the CVEs tab is missing: no <section id="cves">');
    return problems;
  }
  var secEnd = src.indexOf('</section>', open);
  var sec = src.slice(open, secEnd < 0 ? src.length : secEnd);
  if (!/<section id="cves" class="hl-wtabs__sec" data-filter-scope[\s>]/.test(src)) {
    problems.push('the CVEs section lost its hl-wtabs__sec class or data-filter-scope, so the tab CSS or its own filter bar would not find it');
  }
  if (!/<a class="hl-wtabs__tab hl-wtabs__tab--c" href="#cves"/.test(src)) {
    problems.push('the tab bar has no link to #cves');
  }

  // 3. public claims
  var callout = sec.match(/<div class="hl-wire__callout hl-wire__callout--c">[\s\S]*?<\/div>/);
  if (!callout) problems.push('the CVEs callout (hl-wire__callout--c) is missing');
  else {
    [[/My selection/, 'that the list is my selection'],
     [/does not mean anyone has been seen exploiting/, 'that being listed is not evidence of exploitation'],
     [/excludes anything on VulnCheck KEV or CISA KEV/, 'that the list excludes anything on VulnCheck KEV or CISA KEV'],
     [/is a fact about the product, not this CVE/, 'that "product on CISA KEV" is a fact about the product, not about the CVE'],
     [/over the network with no login and no user action/, 'the plain-words rule for the critical arm'],
     [/in a product CISA has listed before/, 'the KEV-product half of the critical arm'],
     [/top 10%/, 'the EPSS arm in plain words'],
     [/moves to the nKEVs tab when it is added to VulnCheck KEV/, 'that a row moves to the nKEVs tab when its CVE is added'],
     [/confirmed against Rapid7's or Exploit-DB's own index/, 'that Metasploit and Exploit-DB claims are confirmed against the publishers\' indexes'],
     [/at most 150 CVEs/, 'that the list is capped at 150'],
     [/ranked by how many reasons they meet, then by EPSS, then by exploit maturity, then by CVSS/, 'how the CVEs shown are ranked']].forEach(function (c) {
      if (!c[0].test(callout[0])) problems.push('the CVEs callout no longer states ' + c[1]);
    });
  }
  var line = sec.match(/<p class="hl-wire__freshness hl-wire__freshness--c">[\s\S]*?<\/p>/);
  if (line && !/VEDAS exploit maturity from <a [^>]*href="https:\/\/github\.com\/ARPSyndicate\/cve-scores"[^>]*>A\.R\.P\. Syndicate<\/a>/.test(line[0])) {
    problems.push('the short c line lost VEDAS credit to A.R.P. Syndicate');
  }
  if (!line) problems.push('the short CVEs line (hl-wire__freshness--c) is missing');
  else {
    [[/Listing, titles, SSVC \(CISA's own assessment\), fixed versions and advisory ids from/, 'what cve.now supplies and that SSVC is CISA\'s own assessment'],
     [/CC BY 4\.0/, 'the cve.now licence'],
     [/Scores from NVD through VulnCheck, or from cve\.now where a row says so/, 'where the scores come from (NVD through VulnCheck, or cve.now where a row says so)'],
     [/Exploits from Rapid7 and Exploit-DB/, 'where the exploits come from'],
     [/KEV products from CISA/, 'where the KEV products come from']].forEach(function (c) {
      if (!c[0].test(line[0])) problems.push('the short CVEs line no longer says ' + c[1]);
    });
    // T-0531: the links themselves, not the words, since the line also names cve.now in its text.
    ['href="https://cve.now/', 'href="https://www.first.org/epss/', 'cves.xml', 'href="https://github.com/ARPSyndicate/cve-scores"'].forEach(function (needle) {
      if (line[0].indexOf(needle) < 0) problems.push('the short CVEs line no longer links ' + needle);
    });
  }

  // 2. legend
  var capOpen = src.search(/\{%-?\s*capture\s+cves_legend_html\s*-?%\}/);
  var capEnd = capOpen < 0 ? -1 : src.indexOf('endcapture', capOpen);
  if (capOpen < 0 || capEnd < 0) problems.push('the CVEs legend is missing: no `capture cves_legend_html` block');
  else {
    var legend = src.slice(capOpen, capEnd);
    problems = problems.concat(checkVedasCopy(legend, "CVEs legend"));
    if (/\sdata-[a-z]/i.test(legend)) problems.push('the CVEs legend markup carries a data-* attribute, which the filter script would read as a filter attribute');
    if (/<(button|input|details|summary|select|textarea)\b/i.test(legend)) problems.push('the CVEs legend markup holds a control or details element: samples must not be interactive');
    if (/\sid\s*=/i.test(legend)) problems.push('the CVEs legend markup carries an id, but it is printed twice, so the id would repeat');
    (legend.match(/<a\b[^>]*>/gi) || []).forEach(function (a) {
      if (!/href="https:\/\/(cve\.now|www\.first\.org|www\.exploit-db\.com|www\.cisa\.gov|github\.com\/(?:cisagov\/vulnrichment|rapid7\/metasploit-framework|ARPSyndicate\/cve-scores)|www\.exploit\.observer)[\/"]/.test(a)) {
        problems.push('a link in the CVEs legend that is not an attribution link: ' + a);
      }
    });
    if (!/CC BY 4\.0/.test(legend) || !/Empirical Security/.test(legend)) {
      problems.push('the CVEs legend lost the cve.now licence or the EPSS attribution');
    }
    [[/show at most 150\. When more qualify, the 150 shown are ranked by how many reasons they meet, then by EPSS, then by exploit maturity, then by CVSS/, 'the cap and the ranking'],
     [/titles, SSVC decision points \(CISA's own assessment, from <a [^>]*>Vulnrichment<\/a>\), fixed versions and advisory ids come from <a [^>]*>cve\.now<\/a>/, 'what cve.now supplies and that SSVC is CISA\'s assessment'],
     [/NVD record through VulnCheck, mostly the CNA's score, unless the row says cve\.now/, 'that CVSS comes from the NVD record through VulnCheck unless the row says cve.now'],
     [/Metasploit modules come from Rapid7's <a [^>]*>metasploit-framework<\/a> module index and Exploit-DB entries from <a [^>]*>Exploit-DB<\/a>'s own index/, 'that Metasploit and Exploit-DB come from the publishers\' own indexes'],
     [/"Product on CISA KEV" comes from CISA's <a [^>]*>KEV catalog<\/a>/, 'that "Product on CISA KEV" comes from CISA\'s KEV catalog']].forEach(function (c) {
      if (!c[0].test(legend)) problems.push('the CVEs legend no longer says ' + c[1]);
    });
  }
  var prints = src.match(/\{\{\s*cves_legend_html\s*\}\}/g) || [];
  if (prints.length !== 2) problems.push('the CVEs legend is printed ' + prints.length + ' time(s), expected 2');
  if (!/<aside class="hl-post-toc hl-legend" aria-label="CVEs legend"/.test(src)) {
    problems.push('the CVEs legend aside is missing, or lost its aria-label="CVEs legend" or the hl-post-toc class');
  }
  var grid = sec.match(/data-filter-item="\.hl-vuln"[\s\S]*?<\/aside>/);
  var gridOnly = grid ? grid[0].replace(/<aside[\s\S]*$/, '') : '';
  if (!grid) problems.push('could not find the CVEs grid');
  else if (/cves_legend_html|hl-legend/.test(gridOnly)) problems.push('the CVEs legend sits inside the CVEs grid, where the filter script would count it as rows');

  /* The accuracy rule behind the attribution lines: cve.now no longer supplies the Metasploit or Exploit-DB
     data (Revision 2: the publishers' own indexes do), so no sentence anywhere on the page may say cve.now
     carries them. A false source line is a claim we cannot back. */
  var carries = src.replace(/\{%-?\s*comment\s*-?%\}[\s\S]*?\{%-?\s*endcomment\s*-?%\}/g, '').match(/carries[^.]{0,160}(?:Metasploit|Exploit-DB)/i);
  if (carries) problems.push('the page says cve.now carries Metasploit or Exploit-DB data (' + JSON.stringify(carries[0].slice(0, 80)) + '). Those come from Rapid7\'s and Exploit-DB\'s own indexes.');

  /* The include chain (review F4). Every wire-* include the page names, and every one those name in turn,
     is part of the rendered tab, so each is held to the same rules as the page: no PoC claim, every
     data-derived output escaped, and only the link targets it is allowed. support-cta.html and the other
     site-wide includes are not tab includes and are not read. A name that cannot be read is NOT CHECKED,
     said as a problem line, never a pass. */
  var stripComments = function (s) { return s.replace(/\{%-?\s*comment\s*-?%\}[\s\S]*?\{%-?\s*endcomment\s*-?%\}/g, ''); };
  var chain = [], seenInc = Object.create(null);
  (function walk(text) {
    (stripComments(text).match(/\{%-?\s*include\s+wire-[A-Za-z0-9_.\/-]+/g) || []).forEach(function (m) {
      var name = m.replace(/^\{%-?\s*include\s+/, '');
      if (seenInc[name]) return;
      seenInc[name] = 1; chain.push(name);
      if (includes && typeof includes[name] === 'string') walk(includes[name]);
    });
  })(src);

  // Revision 2: a GitHub PoC cannot be validated, so it is not claimed, counted, filtered or mentioned.
  var pocRe = /\bpocs?\b|\bpoc_n\b|proof[- ]of[- ]concept/i;
  var scanned = [['the page', stripComments(src)]];
  chain.forEach(function (n) {
    if (includes && typeof includes[n] === 'string') scanned.push(['_includes/' + n, stripComments(includes[n])]);
  });
  scanned.forEach(function (x) {
    var m = x[1].match(pocRe);
    if (m) problems.push(x[0] + ' mentions a GitHub proof of concept (' + JSON.stringify(m[0]) + '). PoCs cannot be validated, so the Wire does not claim, count, filter or link them.');
  });

  // Review F3: Rules (Nuclei, ET Open, Sigma, Snort) are shown on a row but never admit one (Revision 3).
  var admit = sec.replace(/\{%-?\s*comment\s*-?%\}[\s\S]*?\{%-?\s*endcomment\s*-?%\}/g, '').match(/\b(?:public rules?|rules?|Nuclei|ET Open|Snort)\b[^.<]{0,80}\b(?:admit|admits|admitted|qualif\w+)\b/i);
  if (admit) problems.push('the CVEs tab says a rule admits a CVE (' + JSON.stringify(admit[0].slice(0, 80)) + '). Rules are shown on a row and never admit one.');

  // 4. escaping, on the tab's markup and every include in the chain
  unescapedOutputs(sec).forEach(function (m) {
    problems.push('the CVEs tab prints ' + m + ' without escape, and it is not a number or literal the template built');
  });
  chain.forEach(function (name) {
    var inc = includes && includes[name];
    if (typeof inc !== 'string') {
      problems.push('NOT CHECKED: _includes/' + name + ' could not be read, so its escaping, link targets and no-PoC rule were not verified');
      return;
    }
    unescapedOutputs(stripComments(inc)).forEach(function (m) {
      problems.push('_includes/' + name + ' prints ' + m + ' without escape, and it is not a number or literal the template built');
    });
    // 5. only the link targets this include is allowed to build
    var allowed = INCLUDE_LINKS[name] || [];
    (inc.match(/href="[^"]*"/g) || []).forEach(function (h) {
      var ok = allowed.some(function (re) { return re.test(h); });
      if (!ok) {
        problems.push('_includes/' + name + ' links to ' + h + ', which is not one of its ' +
          (allowed.length === 4 ? 'four named' : 'allowed link') + ' targets');
      }
    });
  });
  return problems;
}

/* Which links each tab include may build (review F4). An include not listed may build none. */
var INCLUDE_LINKS = {
  'wire-vuln-new.html': [
    /^href="https:\/\/github\.com\/advisories\//, /^href="https:\/\/euvd\.enisa\.europa\.eu\/vulnerability\//,
    /^href="https:\/\/github\.com\/rapid7\/metasploit-framework\/blob\/master\//, /^href="https:\/\/www\.exploit-db\.com\/exploits\//
  ],
  'wire-vuln-rules.html': [
    /^href="https:\/\/github\.com\/projectdiscovery\/nuclei-templates\/blob\/main\//, /^href="https:\/\/github\.com\/cisagov\/SIGMA_Rules\/blob\/develop\//,
    /^href="https:\/\/www\.snort\.org\/rule_docs\//
  ],
  'wire-vuln-news.html': [/^href="\{\{ '\/wire\/' \| relative_url \}\}\?q=/]
};

/* The CVEs Atom feed (review F4 and F3). Every output is escaped for XML or is a number, a site constant
   or a date the Atom date filter formats; nothing mentions a GitHub proof of concept; the feed says scores
   may come from cve.now and credits the right sources. `xml` is wire/cves.xml, or null. */
var SAFE_FEED_OUT = /^(?:site\.url|site\.time\s*\|\s*date_to_xmlschema|wire\.(?:cves_)?generated_at\s*\|\s*date_to_xmlschema|msf_len|edb_len|kn)$/;
function checkCvesFeed(xml) {
  if (typeof xml !== 'string') return verdict('NOT CHECKED', 'wire/cves.xml is absent or unreadable, so the feed was not verified.');
  var problems = [];
  var body = xml.replace(/\{%-?\s*comment\s*-?%\}[\s\S]*?\{%-?\s*endcomment\s*-?%\}/g, '').replace(/\{%\s*comment\s*%\}[\s\S]*?\{%\s*endcomment\s*%\}/g, '');
  (body.match(/\{\{-?[\s\S]*?-?\}\}/g) || []).forEach(function (m) {
    var inner = m.replace(/^\{\{-?\s*/, '').replace(/\s*-?\}\}$/, '');
    if (/\|\s*xml_escape\b/.test(inner)) return;
    if (/\|\s*(?:round:\s*\d+|times:\s*[\d.]+|plus:\s*\d+|size|floor)\s*$/.test(inner)) return;
    if (SAFE_FEED_OUT.test(inner)) return;
    problems.push('wire/cves.xml prints ' + m + ' without xml_escape, and it is not a number or a site constant');
  });
  if (/\bpocs?\b|\bpoc_n\b|proof[- ]of[- ]concept/i.test(body)) problems.push('wire/cves.xml mentions a GitHub proof of concept');
  if (!/scored_by == "cve\.now"/.test(body)) problems.push('wire/cves.xml no longer says when a score came from cve.now');
  if ((body.match(/unless a row says cve\.now/g) || []).length < 2) {
    problems.push('wire/cves.xml no longer qualifies "scores from NVD through VulnCheck" with "unless a row says cve.now" in both the subtitle and the rights line');
  }
  if (!/Rapid7/.test(body) || !/Exploit-DB/.test(body)) problems.push('wire/cves.xml no longer credits Rapid7 and Exploit-DB for the exploits');
  if (/carries[^.]{0,160}(?:Metasploit|Exploit-DB)/i.test(body)) problems.push('wire/cves.xml says cve.now carries Metasploit or Exploit-DB data');
  if (/\b(?:rules?|Nuclei|ET Open|Snort)\b[^.<]{0,80}\badmit/i.test(body)) problems.push('wire/cves.xml says a rule admits a CVE');
  return verdict(problems.length ? 'FAIL' : 'PASS', null, problems, [], null);
}

/* The nKEV Atom feed (ESC lane, T-0522): wire/vulns.xml. The same escaping guarantee the CVEs feed is
   held to: every output is escaped for XML or is a number the template forced, a site constant or an
   Atom date filter's output. `gap_n` is `r.gap | plus: 0` in the template, so a number. `xml` is
   wire/vulns.xml, or null. */
var SAFE_VULNS_FEED_OUT = /^(?:site\.url|site\.time\s*\|\s*date_to_xmlschema|wire\.vulns_generated_at\s*\|\s*date_to_xmlschema|wire\.generated_at\s*\|\s*date_to_xmlschema|gap_n)$/;
function checkVulnsFeed(xml) {
  if (typeof xml !== 'string') {
    return verdict('NOT CHECKED', 'wire/vulns.xml is absent or unreadable, so the nKEV feed was not verified.');
  }
  var problems = [];
  var body = xml.replace(/\{%-?\s*comment\s*-?%\}[\s\S]*?\{%-?\s*endcomment\s*-?%\}/g, '').replace(/\{%\s*comment\s*%\}[\s\S]*?\{%\s*endcomment\s*%\}/g, '');
  (body.match(/\{\{-?[\s\S]*?-?\}\}/g) || []).forEach(function (m) {
    var inner = m.replace(/^\{\{-?\s*/, '').replace(/\s*-?\}\}$/, '');
    if (/\|\s*xml_escape\b/.test(inner)) return;
    if (/\|\s*(?:round:\s*\d+|times:\s*[\d.]+|plus:\s*\d+|size|floor)\s*$/.test(inner)) return;
    if (SAFE_VULNS_FEED_OUT.test(inner)) return;
    problems.push('wire/vulns.xml prints ' + m + ' without xml_escape, and it is not a number, a site constant or an Atom date');
  });
  return verdict(problems.length ? 'FAIL' : 'PASS', null, problems, [], null);
}

/* The tab CSS (T-0522 made it three tabs). The no-:has fallback is a property of the whole block:
   every rule that hides a section or a tab's selected state is itself a :has() selector, so a
   browser without :has() drops them all and shows every section stacked, with every anchor still
   landing on its row. A hiding rule written without :has() would hide a section for those
   browsers with no way back. `scss` is the text of assets/css/custom.scss, or null. */
function checkTabCss(scss) {
  if (typeof scss !== 'string') {
    return verdict('NOT CHECKED', 'assets/css/custom.scss is absent or unreadable, so the tab fallback rule was not verified.');
  }
  var problems = [];
  var i = scss.indexOf('.hl-wtabs__sec { display: block; }');
  var j = scss.indexOf('Anchors must not land under the 70px sticky site header');
  if (i < 0 || j < i) {
    return verdict('NOT CHECKED', 'could not find the tab rules block in custom.scss, so the fallback rule was not verified.');
  }
  var block = scss.slice(i, j);
  var rules = block.match(/[^{}]+\{[^}]*\}/g) || [];
  var hides = 0;
  rules.forEach(function (rule) {
    var sel = rule.slice(0, rule.indexOf('{')).replace(/\/\*[\s\S]*?\*\//g, '').trim();
    var body = rule.slice(rule.indexOf('{'));
    if (/display:\s*none/.test(body) && sel.indexOf(':has(') < 0) {
      problems.push('the tab rule "' + sel.replace(/\s+/g, ' ') + '" hides a section without :has(), so a browser without :has() could not show it');
    }
    if (/display:\s*none/.test(body)) hides++;
  });
  // Every tab that can be targeted must be able to hide the Headlines section.
  ['#vulns:target', '#vulns :target', '#cves:target', '#cves :target'].forEach(function (t) {
    var re = new RegExp('\\.hl-wtabs:has\\(' + t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\)\\s+#headlines\\s*\\{\\s*display:\\s*none');
    if (!re.test(block)) problems.push('no rule hides #headlines when ' + t + ' is targeted');
  });
  ['#vulns', '#cves'].forEach(function (id) {
    if (!new RegExp('\\.hl-wtabs:has\\(#headlines\\)\\s+' + id + ':target\\s*\\{\\s*display:\\s*block').test(block)) {
      problems.push('no rule shows ' + id + ' when it is the target');
    }
    if (!new RegExp('\\.hl-wtabs:has\\(' + id + ' :target\\)\\s+' + id + '\\s*\\{\\s*display:\\s*block').test(block)) {
      problems.push('no rule shows ' + id + ' when an anchor inside it is the target');
    }
  });
  return verdict(problems.length ? 'FAIL' : 'PASS', null, problems, [], { hides: hides });
}

/* T-0532 part S: the Details dropdown, as structure. The guarantees the gates and the
   tests below cannot see some other way:

   1. The two JSON pages (and the row include they share) emit every value through
      | jsonify: no raw {{ r.x }} output reaches a file a reader can fetch.
   2. wire-details.js contains no markup-injection sink at all: panels are built with
      createElement and set text only through textContent, so a value that sneaks
      through the JSON pages' validation cannot become markup.
   3. The nKEV and CVEs row templates carry the server-rendered toggle, exactly this
      markup (hidden until the script removes it), first in the row, before the CVE
      id link; the Headlines row carries none (Joseph, 2026-11-01).
   4. The headlines grid's filter item is the wrapper (data-filter-item=".hl-wire__row"),
      and no grid still names the old ".hl-wire__item": the wrapper is what the filter
      shows and hides, so a hidden row takes its panel with it.
   5. Both tab sections carry a versioned data-details URL, and the renderer loads
      deferred, after listing-filter.js, with a cache-bust of its own.

   Each of these functions takes the file text, or null when unreadable, which is
   NOT CHECKED, said in a problem line, never a pass. */
var DETAILS_TOGGLE = /<button type="button" class="hl-dt" aria-expanded="false" hidden title="Show details"><span class="hl-dt__sr">Details<\/span><\/button>/;
var TOGGLE_FIRST = /<button type="button" class="hl-dt"[^>]*>[\s\S]*?<\/button><a class="hl-vuln__cve"/;
var DETAILS_SINK = /innerHTML|outerHTML|insertAdjacentHTML|document\.write|(?:^|[^A-Za-z$_.])eval\s*\(/;
function lineWith(src, needle) {
  var lines = src.split('\n');
  for (var i = 0; i < lines.length; i++) {
    if (lines[i].indexOf(needle) !== -1) { return lines[i]; }
  }
  return null;
}
function checkDetailsScript(src) {
  if (!src) {
    return verdict('NOT CHECKED', 'assets/js/wire-details.js is absent or unreadable, so the no-markup rule was not verified.');
  }
  var m = src.match(DETAILS_SINK);
  if (m) {
    return verdict('FAIL', null, [
      JSON.stringify(m[0]) + ' in wire-details.js. The Details renderer builds elements only ' +
      'with createElement, sets text only through textContent, and never hands the browser a ' +
      'markup string or reads a markup property.'], [], null);
  }
  return verdict('PASS', null, [], [], null);
}
function checkDetailsJsonPage(src) {
  if (!src) {
    return verdict('NOT CHECKED', 'the Details details JSON page is absent or unreadable, so its escaping was not verified.');
  }
  var body = src.replace(/^---\n[\s\S]*?\n---\n?/, '')
    .replace(/\{%-?\s*comment\s*-?%\}[\s\S]*?\{%-?\s*endcomment\s*-?%\}/g, '')
    .replace(/\{%\s*comment\s*%\}[\s\S]*?\{%\s*endcomment\s*%\}/g, '');
  var problems = [];
  (body.match(/\{\{-?[\s\S]*?-?\}\}/g) || []).forEach(function (m) {
    var inner = m.replace(/^\{\{-?\s*/, '').replace(/\s*-?\}\}$/, '');
    if (!/\|\s*jsonify\s*$/.test(inner)) {
      problems.push('a Details JSON page prints ' + m + ' without | jsonify. Every value in ' +
        'wire/details-nkev.json and wire/details-cves.json (and the row include they share) ' +
        'must be emitted through jsonify, or a value holding a quote or a backslash changes the JSON shape.');
    }
  });
  return verdict(problems.length ? 'FAIL' : 'PASS', null, problems, [], null);
}
function checkDetailsPage(src) {
  if (!src) {
    return verdict('NOT CHECKED', 'wire/index.md is absent or unreadable, so the Details dropdown structure was not verified.');
  }
  var problems = [];
  // 3. the two vulnerability row templates carry the toggle, first in the row
  var nToggles = src.split(DETAILS_TOGGLE).length - 1;
  if (nToggles !== 2) {
    problems.push('the Details toggle markup appears ' + nToggles + ' time(s), expected 2: one in ' +
      'the nKEV row template, one in the CVEs row template');
  }
  var nkevSlice = (src.match(/\{%-?\s*for r in wire\.vulns -?%\}[\s\S]*?\{%-?\s*endfor\s*-?%\}\s*<\/div>/) || [''])[0];
  if (!nkevSlice) {
    problems.push('could not find the nKEV row template (for r in wire.vulns), so its Details toggle could not be verified');
  } else if (!DETAILS_TOGGLE.test(nkevSlice)) {
    problems.push('the nKEV row template carries no Details toggle');
  } else if (!TOGGLE_FIRST.test(nkevSlice)) {
    problems.push('the nKEV row template\'s Details toggle is not directly before the CVE id link');
  }
  var cvesLine = lineWith(src, 'hl-vuln hl-vuln--cve');
  if (!cvesLine) {
    problems.push('could not find the CVEs row template line (the hl-vuln--cve row), so its Details toggle could not be verified');
  } else if (!DETAILS_TOGGLE.test(cvesLine)) {
    problems.push('the CVEs row template carries no Details toggle');
  } else if (!TOGGLE_FIRST.test(cvesLine)) {
    problems.push('the CVEs row template\'s Details toggle is not directly before the CVE id link');
  }
  var headLine = lineWith(src, 'class="hl-wire__row"');
  if (!headLine) {
    problems.push('no headline row wrapper (hl-wire__row) is in the page, so the filter item pattern cannot be verified');
  } else if (headLine.indexOf('class="hl-dt"') !== -1) {
    problems.push('the headline row carries a Details toggle; the Headlines tab has none (Joseph, 2026-11-01)');
  }
  // 4. the headlines grid's filter item is the wrapper
  if (src.indexOf('data-filter-item=".hl-wire__row"') === -1) {
    problems.push('the headlines grid names no wrapper (data-filter-item=".hl-wire__row"), so the filter would show or hide the anchor and leave its Details panel on the other side of it');
  }
  if (src.indexOf('data-filter-item=".hl-wire__item"') !== -1) {
    problems.push('a grid still names data-filter-item=".hl-wire__item", which the Details restructure replaced with the wrapper');
  }
  // 5. versioned data-details on both sections, the renderer deferred after the filter
  ['vulns', 'cves'].forEach(function (id) {
    var secOpen = lineWith(src, '<section id="' + id + '"');
    if (!secOpen) { problems.push('the ' + id + ' section tag is missing'); return; }
    if (!/data-details="[^"]+\?v=[^"]*"/.test(secOpen)) {
      problems.push('the ' + id + ' section carries no versioned data-details URL (?v=), so a ' +
        'browser could pair one build\u2019s page with another build\u2019s details file');
    }
  });
  var filterAt = src.indexOf('listing-filter.js');
  var detailsAt = src.indexOf('wire-details.js');
  if (detailsAt === -1) {
    problems.push('the page loads no wire-details.js, so no Details toggle could remove hidden or build a panel');
  } else {
    if (filterAt > -1 && detailsAt < filterAt) {
      problems.push('wire-details.js loads before listing-filter.js: the filter module must come first');
    }
    if (!/<script defer src="\{\{-?\s*'\/assets\/js\/wire-details\.js'\s*\|\s*relative_url\s*-?\}\}\?v=\d+"/.test(src)) {
      problems.push('the wire-details.js tag is not the deferred, versioned form the Details toggle relies on (script defer, ?v= number)');
    }
  }
  return verdict(problems.length ? 'FAIL' : 'PASS', null, problems, [], null);
}

module.exports = { checkHeadlineRow: checkHeadlineRow, check: check, checkPage: checkPage, checkTabCss: checkTabCss, checkCvesFeed: checkCvesFeed, checkVulnsFeed: checkVulnsFeed, checkTabNav: checkTabNav, checkDetailsPage: checkDetailsPage, checkDetailsScript: checkDetailsScript, checkDetailsJsonPage: checkDetailsJsonPage, STALE_HOURS: STALE_HOURS,
  VULNS_STALE_HOURS: VULNS_STALE_HOURS };
