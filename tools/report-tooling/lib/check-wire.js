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
var CVE_SHAPE = /^CVE-\d{4}-\d{4,}$/;
var DAY_SHAPE = /^\d{4}-\d{2}-\d{2}$/;
// T-0399: each row's CVSS base score, all four fields empty or all set. A row
// written before T-0399 carries none of them and checks clean.
var SCORE_KEYS = ['cvss', 'cvss_version', 'severity', 'scored_by'];
var SEVERITIES = { critical: 1, high: 1, medium: 1, low: 1 };
var CVSS_VERSIONS = { '4.0': 1, '3.1': 1, '3.0': 1, '2.0': 1 };
var SCORED_BY = { NVD: 1, CNA: 1, ADP: 1 };

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
  var nNkev = { disclosed: 0, prenvd: 0, epss: 0, epss_pre: 0 };
  rows.forEach(function (r, n) {
    r = r || {};
    var where = 'vulns row ' + (n + 1) + ' (' + String(r.cve || '?') + ')';
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
    if (!isEmpty(r.disclosed)) nNkev.disclosed++;
    if (typeof r.gap === 'number' && r.gap < 0) nNkev.prenvd++;
    if (!isEmpty(r.epss)) nNkev.epss++;
    if (!isEmpty(r.epss_pre)) nNkev.epss_pre++;
    if (reportsOf(r).length) nPtr.reported++;
    if (Number(r.stories) > 0) nPtr.stories++;
    var hasEt = Array.isArray(r.et_sids) && r.et_sids.length > 0;
    var hasNu = typeof r.nuclei === 'string' && r.nuclei !== '';
    if (hasEt) nPtr.et++;
    if (hasNu) nPtr.nuclei++;
    if (hasEt || hasNu) nPtr.detect++;
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

function verdict(status, reason, problems, warnings, counts, vulnWarnings) {
  return {
    status: status,
    reason: reason || null,
    problems: problems || [],
    warnings: warnings || [],
    counts: counts || null,
    // Vulnerabilities-tab problems, reported as WARN (see checkVulns).
    vulnWarnings: vulnWarnings || []
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

  return verdict(problems.length ? 'FAIL' : 'PASS', null, problems, warnings.sort(), {
    total: items.length, research: nResearch, news: nNews, vuln: nVuln, vulns: v.total
  }, v.warnings);
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
function checkPage(src) {
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

  return verdict(problems.length ? 'FAIL' : 'PASS', null, problems, [], null);
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

  // 1. Attribution above the filter bar, outside the legend.
  var line = before.match(/<p class="hl-wire__freshness hl-wire__freshness--v">[\s\S]*?<\/p>/);
  if (!line) {
    problems.push('the short nKEVs line (hl-wire__freshness--v) is missing above the legend, ' +
      'so the nKEV definition and the attribution are no longer visible without opening it');
  } else {
    ['vulncheck.com/kev', 'first.org/epss', 'vulns.xml'].forEach(function (needle) {
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
    if (!/href="https:\/\/(www\.vulncheck\.com|www\.first\.org)\//.test(a)) {
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

module.exports = { check: check, checkPage: checkPage, STALE_HOURS: STALE_HOURS,
  VULNS_STALE_HOURS: VULNS_STALE_HOURS };
