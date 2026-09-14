#!/usr/bin/env node
'use strict';

/* Builds assets/data/ioc-index.json from the published IOC feeds.

   The walk is SHAPE-AGNOSTIC. It recurses through whatever structure a feed
   has and never consults a bucket name, because across the 57 feeds the
   indicators live under 20+ differently-named keys, 55 feeds put them at the
   top level and 2 nest them under `iocs`, values appear both as bare strings
   and as objects, and buckets like `ExploitEndpoints` mix URI paths in beside
   real indicators. Only the value itself is reliable, so ioc-classify.js
   decides, on pattern alone.

   Only campaigns BOTH of whose publication signals say published are indexed.
   See lib/catalog-status.js: an embargoed campaign is live at its URL for the
   disclosure loop and must not become searchable. */

var fs = require('node:fs');
var path = require('node:path');
var C = require('../../assets/js/ioc-classify.js');
var CS = require('./lib/catalog-status.js');
var B = require('./lib/benign.js');

var ROOT = path.join(__dirname, '..', '..');
var FEED_DIR = path.join(ROOT, 'ioc-feeds');
var REPORT_DIR = path.join(ROOT, 'reports');
var CATALOG = path.join(ROOT, '_data', 'catalog.yml');
var OUT = path.join(ROOT, 'assets', 'data', 'ioc-index.json');

var ROLE_KEYS = ['context', 'description', 'role', 'note', 'type'];
var VALUE_KEYS = ['value', 'indicator', 'ip', 'domain', 'url', 'hash',
                  'sha256', 'sha1', 'md5', 'name'];

/* The never-block bucket is exempt from the ordinary walk, mirroring
   lib/feed-hygiene.js's own EXEMPT_TOP and the same fix already applied to
   tools/report-tooling/lib/ioc-table-extract.js (2026-09-13). Removal, not
   marking: this project's public search index must not carry these values as
   typed keys at all, because a script reading `Object.keys(idx.indicators)`
   gets the value regardless of any warning text sitting beside it. See
   returns/other-surfaces.md #2 in the ioc-never-block-leak-closure run. */
var EXEMPT_TOP = { hunt_only_never_block: true };

/* Index-side only. The PAGE still extracts these from pasted text so they
   count toward "N indicators checked"; they simply never match. See lib/benign.js.

   `suppressBenign` gates this. It is correct for the ordinary walk (a public
   search index should not be noisy with values every network contains) and
   wrong for the never-block walk: a value like `github.com` sitting in
   `hunt_only_never_block` is there for a specific recorded reason, and this
   collector's job for that walk is only to name it so it can be REMOVED from
   the ordinary index, not to decide a second time whether it is interesting. */
function keep(r, suppressBenign) {
  return r && (!suppressBenign || !B.isBenign(r.type, r.value));
}

function collect(node, out, role, exempt, suppressBenign) {
  if (node == null) return;
  if (typeof node === 'string') {
    var r = C.classify(node);
    if (keep(r, suppressBenign)) out.push({ key: r.type + ':' + r.value, role: role || null });
    else if (r) out.suppressed = (out.suppressed || 0) + 1;
    return;
  }
  if (Array.isArray(node)) {
    for (var i = 0; i < node.length; i++) collect(node[i], out, role, exempt, suppressBenign);
    return;
  }
  if (typeof node !== 'object') return;

  var myRole = role;
  for (var k = 0; k < ROLE_KEYS.length; k++) {
    var rv = node[ROLE_KEYS[k]];
    if (typeof rv === 'string' && rv.trim() && rv.length < 90 && !C.classify(rv)) {
      myRole = rv.trim();
      break;
    }
  }

  var tookValue = false;
  for (var v = 0; v < VALUE_KEYS.length; v++) {
    var val = node[VALUE_KEYS[v]];
    if (typeof val === 'string') {
      var res = C.classify(val);
      if (keep(res, suppressBenign)) {
        out.push({ key: res.type + ':' + res.value, role: myRole || null }); tookValue = true;
      } else if (res) { out.suppressed = (out.suppressed || 0) + 1; tookValue = true; }
    }
  }
  Object.keys(node).forEach(function (key) {
    if (tookValue && VALUE_KEYS.indexOf(key) > -1) return;
    if (exempt && exempt[key]) return;
    collect(node[key], out, myRole, exempt, suppressBenign);
  });
}

/* feeds: { 'slug-iocs.json': parsedJson }. catalogText: raw catalog.yml.
   unlistedBySlug: { slug: true } for reports carrying `unlisted: true`. */
function build(feeds, catalogText, unlistedBySlug) {
  var cat = CS.resolve(catalogText, unlistedBySlug || {});
  var indicators = {}, neverBlock = {}, reports = {};
  var suppressed = 0;
  var coverage = { indexed: [], embargoed: [], unknown: [], empty: [] };

  Object.keys(feeds).sort().forEach(function (file) {
    var state = CS.statusOf(cat, file);
    if (state === 'embargoed') { coverage.embargoed.push(file); return; }
    if (state === 'unknown')   { coverage.unknown.push(file); return; }

    var found = [];
    collect(feeds[file], found, null, EXEMPT_TOP, true);
    if (found.suppressed) suppressed += found.suppressed;

    var feed = feeds[file];
    var nbRoot = (feed && typeof feed === 'object') ? feed.hunt_only_never_block : null;
    var foundNB = [];
    if (nbRoot != null) collect(nbRoot, foundNB, null, null, false);

    if (!found.length && !foundNB.length) { coverage.empty.push(file); return; }

    var slug = CS.slugOf(file);
    var m = cat.meta[file] || {};

    var seenNB = {};
    foundNB.forEach(function (f) {
      if (seenNB[f.key]) return;
      seenNB[f.key] = 1;
      (neverBlock[f.key] = neverBlock[f.key] || []).push(
        f.role ? { report: slug, role: f.role } : { report: slug });
    });

    var seenHere = {};
    found.forEach(function (f) {
      // Dedupe toward safety: a value present in both an ordinary bucket and
      // hunt_only_never_block (an incomplete migration, not a theoretical
      // case, see returns/revert-bad-relocations.md from this run) is
      // never-block only, never also an ordinary indexed key.
      if (seenNB[f.key]) return;
      if (seenHere[f.key]) return;
      seenHere[f.key] = 1;
      (indicators[f.key] = indicators[f.key] || []).push(
        f.role ? { report: slug, role: f.role } : { report: slug });
    });

    // Reached only when found.length || foundNB.length, per the early return above.
    reports[slug] = {
      title: m.title, date: m.date, severity: m.severity,
      report_url: m.report_url, detection_url: m.detection_url, ioc_url: m.ioc_url
    };
    coverage.indexed.push(file);
  });

  var multi = Object.keys(indicators).filter(function (k) {
    return indicators[k].length > 1;
  }).length;

  return {
    counts: {
      indicators: Object.keys(indicators).length,
      reports: Object.keys(reports).length,
      multi_report: multi,
      suppressed_benign: suppressed,
      never_block: Object.keys(neverBlock).length
    },
    coverage: coverage,
    conflicts: cat.conflicts || [],
    reports: reports,
    indicators: indicators,
    never_block: neverBlock
  };
}

function readFeeds(dir) {
  var out = {};
  fs.readdirSync(dir).filter(function (f) { return /\.json$/.test(f); })
    .forEach(function (f) {
      try { out[f] = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')); }
      catch (e) { out[f] = { __unparseable: String(e.message) }; }
    });
  return out;
}

/* Reports whose front matter carries `unlisted: true`, the second publication
   signal. Read here rather than inside catalog-status so that module stays
   pure and testable without a filesystem. */
function readUnlisted(dir) {
  var map = {};
  if (!fs.existsSync(dir)) return map;
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (e) {
    if (!e.isDirectory()) return;
    var f = path.join(dir, e.name, 'index.md');
    if (!fs.existsSync(f)) return;
    if (/^unlisted:\s*true\s*$/m.test(fs.readFileSync(f, 'utf8').slice(0, 4000))) {
      map[e.name] = true;
    }
  });
  return map;
}

function render(idx, generatedAt) {
  var doc = { generated_at: generatedAt };
  Object.keys(idx).forEach(function (k) { doc[k] = idx[k]; });
  return JSON.stringify(doc, null, 1) + '\n';
}

module.exports = {
  build: build, collect: collect, readFeeds: readFeeds,
  readUnlisted: readUnlisted, render: render, EXEMPT_TOP: EXEMPT_TOP
};

if (require.main === module) {
  var idx = build(readFeeds(FEED_DIR), fs.readFileSync(CATALOG, 'utf8'), readUnlisted(REPORT_DIR));
  var stamp = process.env.HL_INDEX_STAMP || new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, render(idx, stamp));
  var c = idx.coverage;
  console.log('wrote ' + OUT);
  console.log('  ' + idx.counts.indicators + ' indicators across ' +
    idx.counts.reports + ' reports (' + idx.counts.multi_report + ' in more than one)');
  if (idx.counts.suppressed_benign) {
    console.log('  ' + idx.counts.suppressed_benign + ' benign value(s) suppressed ' +
      '(public resolvers, RFC1918, major platforms) so the page does not cry wolf');
  }
  if (idx.counts.never_block) {
    console.log('  ' + idx.counts.never_block + ' never-block value(s) held out of the ' +
      'index entirely (hunt_only_never_block), never a typed key a search can return');
  }
  console.log('  indexed ' + c.indexed.length + ', embargoed ' + c.embargoed.length +
    ', unknown ' + c.unknown.length + ', empty ' + c.empty.length);
  if (c.embargoed.length) console.log('  EMBARGOED (correctly excluded): ' + c.embargoed.join(', '));
  if (c.unknown.length)   console.log('  UNKNOWN (no catalog entry): ' + c.unknown.join(', '));
  if (c.empty.length)     console.log('  EMPTY (published but yielded nothing): ' + c.empty.join(', '));
  if (idx.conflicts.length) {
    console.log('  CONFLICT: the two publication signals disagree, a half-completed go-live:');
    idx.conflicts.forEach(function (x) {
      console.log('    ' + x.slug + ': catalog says ' + x.catalog +
        ', front matter says ' + x.front_matter);
    });
  }
}
