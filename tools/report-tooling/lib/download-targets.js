'use strict';

/* Choosing what the download check runs against, and reading what came back.

   Pure functions over already-parsed data, so the decisions that matter can be
   tested without a browser or a network. Both halves have already been wrong
   once each in ways that a green run would not have shown. */

var EXT = { yara: '.yar', sigma: '.yml', suricata: '.rules' };

/* Count rules in an engine-native bundle, the way each format separates them.
   YARA bodies follow deduped imports, Sigma documents are joined by `---`, and
   Suricata rules are one per line. */
function countRules(engine, text) {
  text = String(text || '');
  if (engine === 'yara') return (text.match(/^\s*rule\s+[A-Za-z_]/gm) || []).length;
  if (engine === 'sigma') return (text.match(/^title:/gm) || []).length;
  return text.split(/\r?\n/).filter(function (l) {
    return l.trim() && !/^\s*#/.test(l);
  }).length;
}

/* Which OTHER engines' syntax appears in a bundle. Deliberately narrow: it looks
   for shapes only those engines produce at the start of a line, so a rule
   comment mentioning "alert" cannot trip it. */
function foreignEngineIn(engine, text) {
  var probes = {
    yara: /^\s*rule\s+[A-Za-z_]\w*\s*[:{]/m,
    sigma: /^logsource:/m,
    suricata: /^\s*(alert|drop|reject|pass)\s+\w+\s/m
  };
  return Object.keys(probes).filter(function (e) {
    return e !== engine && probes[e].test(String(text || ''));
  });
}

/* Which detection page to drive.

   Two requirements, both learned rather than assumed. It must be a page the
   CATALOG lists: the manifest is generated from every file in
   hunting-detections/, which includes campaigns under disclosure embargo, and
   those are commented out of the catalog so parsing it as YAML drops them. The
   first run of this check reached for an embargoed campaign. Nothing leaked, but
   a gate that leans on a page which may be pulled is a gate that will fail for
   the wrong reason.

   And it must carry an (engine, tier) pair that is a STRICT subset of that
   engine's rules. Without that, a download which ignored the tier filter would
   be indistinguishable from a correct one, and the check would pass on a broken
   picker. */
function pickDetections(manifest, catalog) {
  var listed = {};
  /* Array FIRST, and explicitly.

     `(catalog && catalog.entries) || catalog` looks like a harmless way to
     accept either shape and is wrong: every Array has an `entries` METHOD, so a
     bare array yields the function, `Array.isArray` on it is false, and the
     listed map silently stays empty. Nothing is ever picked and the check
     reports NOT CHECKED as though the corpus had nothing to offer. It survived
     because _data/catalog.yml happens to be a mapping with an `entries:` key, so
     the working path was the one taken by luck. */
  var entries = Array.isArray(catalog) ? catalog
    : (catalog && Array.isArray(catalog.entries) ? catalog.entries : []);
  entries.forEach(function (e) {
    if (e && e.detection_url) {
      listed[String(e.detection_url)
        .replace(/^\/hunting-detections\//, '').replace(/\/$/, '')] = true;
    }
  });

  var best = null;
  Object.keys(manifest || {}).forEach(function (key) {
    if (!listed[key]) return;
    var rules = manifest[key];
    if (!Array.isArray(rules) || rules.length < 3) return;

    var byEngine = {};
    rules.forEach(function (r) {
      if (!r || !r.engine) return;
      byEngine[r.engine] = byEngine[r.engine] || {};
      var t = r.tier || '?';
      byEngine[r.engine][t] = (byEngine[r.engine][t] || 0) + 1;
    });
    var names = Object.keys(byEngine);
    if (names.length < 2) return;

    var pick = null;
    names.forEach(function (e) {
      if (pick) return;
      var tiers = Object.keys(byEngine[e]);
      if (tiers.length < 2) return;
      tiers.sort(function (a, b) { return byEngine[e][a] - byEngine[e][b]; });
      pick = {
        engine: e,
        tier: tiers[0],
        subset: byEngine[e][tiers[0]],
        engineTotal: rules.filter(function (r) { return r.engine === e; }).length
      };
    });
    if (!pick || pick.subset >= pick.engineTotal) return;

    var cand = { key: key, rules: rules.length, engines: names.sort(), pick: pick };
    if (!best || cand.rules > best.rules) best = cand;
  });
  return best;
}

/* Which feed page to drive. It needs at least two indicator types so a type
   chip is a real narrowing. Embargoed feeds are already absent from
   _data/ioc_tables.yml by construction, so no extra exclusion is needed here. */
function pickFeed(tables) {
  var best = null;
  Object.keys(tables || {}).forEach(function (k) {
    var t = tables[k];
    if (!t || !t.page_url || !t.counts) return;
    var types = Object.keys(t.counts).filter(function (x) { return t.counts[x] > 0; });
    if (types.length < 2) return;
    if (!best || (t.total || 0) > (best.total || 0)) {
      best = { key: k, slug: t.slug, url: t.page_url, total: t.total,
               types: types, counts: t.counts };
    }
  });
  return best;
}

/* The LARGEST type that is still a strict subset.

   The smallest gives the strictest narrowing but is usually one row, and a
   one-row export proves close to nothing: a filter that did nothing at all
   would still produce a plausible-looking file. */
function pickType(feed) {
  if (!feed) return null;
  var strict = feed.types.slice()
    .filter(function (t) { return feed.counts[t] < feed.total; })
    .sort(function (a, b) { return feed.counts[b] - feed.counts[a]; });
  return strict[0] || feed.types[0] || null;
}

module.exports = {
  EXT: EXT,
  countRules: countRules,
  foreignEngineIn: foreignEngineIn,
  pickDetections: pickDetections,
  pickFeed: pickFeed,
  pickType: pickType
};
