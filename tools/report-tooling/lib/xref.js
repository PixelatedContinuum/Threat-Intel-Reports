'use strict';

/* Cross-reference pages: one page per ATT&CK technique and one per malware or
   tool family, each listing everything on the site that maps to it.

   Techniques come from three places the site already gates: the reports'
   own mapping tables (read with the same parser as the coverage strip, through
   lib/actors.js attackFor), the generated detection tables in
   _data/detection_attack.yml, and the per-actor technique lists in
   _data/actors_index.yml. Families come from a controlled vocabulary,
   _data/families.yml (the tags.yml pattern: one canonical name plus the
   spellings that appear in the corpus), matched against the YARA `family`
   metadata in the detection pages, the family fields in the IOC feeds, the
   catalog tags and the actors' tooling lists. A label the vocabulary does not
   know is reported by name, never silently dropped, and never guessed into a
   page.

   Only PUBLISHED sources are listed: a report is published when the catalog
   lists it and its front matter is not unlisted, a detection page or feed when
   its catalog entry carries it. Pure on its inputs so it can be tested on
   fixtures; generate-xref.js and check-xref.js do the reading and writing. */

var fs = require('node:fs');
var path = require('node:path');
var yaml = require('js-yaml');

var ROOT = path.join(__dirname, '..', '..', '..');
var FAMILIES_FILE = path.join(ROOT, '_data', 'families.yml');
var ATTACK_INDEX = path.join(ROOT, '_data', 'attack_index.yml');
var FAMILY_INDEX = path.join(ROOT, '_data', 'family_index.yml');
var DETECTION_ATTACK = path.join(ROOT, '_data', 'detection_attack.yml');
var ACTORS_INDEX = path.join(ROOT, '_data', 'actors_index.yml');
var TECHNIQUE_DIR = path.join(ROOT, 'techniques');
var FAMILY_DIR = path.join(ROOT, 'families');
var LAYER_FILE = path.join(ROOT, 'assets', 'data', 'attack-navigator-layer.json');

var TECHNIQUE_MARKER = 'layout: technique';
var FAMILY_MARKER = 'layout: family';
var KINDS = ['rat', 'stealer', 'loader', 'c2-framework', 'cryptominer', 'kit', 'toolkit',
  'ransomware', 'webshell', 'botnet', 'backdoor', 'tunnel', 'exploit', 'other'];

function techniqueUrl(id) { return '/techniques/' + id + '/'; }
function mitreUrl(id) { return 'https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/'; }
function familySlug(name) {
  return String(name).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}
function familyUrl(name) { return '/families/' + familySlug(name) + '/'; }
function norm(s) { return String(s || '').trim().toLowerCase(); }

/* ---- the family vocabulary ---------------------------------------------- */

function parseFamilies(text) {
  var doc = yaml.load(text);
  var problems = [];
  if (!doc || !Array.isArray(doc.families)) {
    return { families: [], problems: ['_data/families.yml has no `families:` list'] };
  }
  var seenName = {}, seenSlug = {}, seenAlias = {};
  var families = doc.families.map(function (f, i) {
    var where = 'families[' + i + ']' + (f && f.family ? ' (' + f.family + ')' : '');
    if (!f || typeof f !== 'object' || !f.family) { problems.push(where + ': needs a `family` name'); return null; }
    var name = String(f.family);
    if (seenName[norm(name)]) problems.push(where + ': duplicate family name');
    seenName[norm(name)] = true;
    var slug = familySlug(name);
    if (!slug) problems.push(where + ': the name yields an empty url slug');
    if (seenSlug[slug]) problems.push(where + ': url slug "' + slug + '" collides with another family');
    seenSlug[slug] = true;
    if (f.kind != null && KINDS.indexOf(f.kind) === -1) {
      problems.push(where + ': kind must be one of ' + KINDS.join(', '));
    }
    ['aliases', 'tags'].forEach(function (k) {
      if (f[k] != null && !Array.isArray(f[k])) problems.push(where + ': ' + k + ' must be a list');
    });
    (f.aliases || []).forEach(function (a) {
      var key = norm(a);
      if (seenAlias[key] && seenAlias[key] !== name) {
        problems.push(where + ': alias "' + a + '" is also claimed by ' + seenAlias[key]);
      }
      seenAlias[key] = name;
    });
    return {
      name: name,
      slug: slug,
      kind: f.kind || 'other',
      aliases: (f.aliases || []).map(String),
      tags: (f.tags || []).map(String),
      summary: f.summary ? String(f.summary) : null
    };
  }).filter(Boolean);
  return { families: families, problems: problems };
}

/* label (as it appears in a rule or feed) -> the families it names, by name or
   alias. Returns a list, because a label can name two families at once.

   Three tries, in order: the whole label; the label with its parentheticals
   removed ("KAIDO (Quasar RAT fork)" is KAIDO; the bracket is a note on it,
   not a second family); and the stripped label split on "/" or " + ", which
   maps only when EVERY part is known ("NjRAT/XWorm" is both; "GSocket/THC
   backdoor kit" is neither, because "THC backdoor kit" is not a family we
   track, and half a label mapped would hide the other half). A label no try
   resolves comes back empty and is reported by name, never guessed. */
function stripParens(label) {
  return String(label).replace(/\s*\([^()]*\)/g, '').replace(/\s+/g, ' ').trim();
}
function familyMatcher(families) {
  var byLabel = {};
  families.forEach(function (f) {
    byLabel[norm(f.name)] = f;
    f.aliases.forEach(function (a) { byLabel[norm(a)] = f; });
  });
  return function (label) {
    var whole = byLabel[norm(label)];
    if (whole) return [whole];
    var stripped = stripParens(label);
    var one = byLabel[norm(stripped)];
    if (one) return [one];
    var parts = stripped.split(/\s*\/\s*|\s\+\s/).filter(Boolean);
    if (parts.length < 2) return [];
    var out = [];
    for (var i = 0; i < parts.length; i++) {
      var f = byLabel[norm(parts[i])];
      if (!f) return [];
      if (out.indexOf(f) === -1) out.push(f);
    }
    return out;
  };
}

/* ---- reading the corpus --------------------------------------------------- */

/* YARA `family` metadata per detection page, with the rule names that carry
   it. Read from the fenced rule blocks, the one place the label is authored. */
function detectionFamiliesFromText(md) {
  var out = {};   // label -> [rule names]
  var lines = String(md).split('\n');
  var inFence = false, rule = null;
  lines.forEach(function (line) {
    var fence = /^\s*(`{3,}|~{3,})/.exec(line);
    if (fence) { inFence = !inFence; rule = null; return; }
    if (!inFence) return;
    var r = /^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z0-9_]+)/.exec(line);
    if (r) { rule = r[1]; return; }
    var m = /^\s*family\s*=\s*"([^"]+)"/.exec(line);
    if (m) {
      var label = m[1].trim();
      if (!out[label]) out[label] = [];
      if (rule && out[label].indexOf(rule) === -1) out[label].push(rule);
    }
  });
  return out;
}

function readDetectionFamilies(dir) {
  var out = {};
  fs.readdirSync(dir).forEach(function (f) {
    if (!/-detections\.md$/.test(f)) return;
    var md = fs.readFileSync(path.join(dir, f), 'utf8');
    out[f.replace(/\.md$/, '')] = detectionFamiliesFromText(md);
  });
  return out;
}

/* Family labels in an IOC feed: metadata.primary_family plus every
   `family` field on an indicator. Keyed by the feed's file name. */
function feedFamiliesFromJson(obj) {
  var labels = {};
  function add(v) { if (v && typeof v === 'string') labels[v.trim()] = true; }
  if (obj && obj.metadata && obj.metadata.primary_family) add(obj.metadata.primary_family);
  (function walk(o) {
    if (Array.isArray(o)) { o.forEach(walk); return; }
    if (!o || typeof o !== 'object') return;
    Object.keys(o).forEach(function (k) {
      if (k === 'family') add(o[k]); else walk(o[k]);
    });
  })(obj);
  return Object.keys(labels);
}

function readFeedFamilies(dir) {
  var out = {};
  fs.readdirSync(dir).forEach(function (f) {
    if (!/\.json$/.test(f)) return;
    var obj;
    try { obj = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')); } catch (e) { return; }
    out[f] = feedFamiliesFromJson(obj);
  });
  return out;
}

/* ---- the technique index ----------------------------------------------- */

/* reports: [{url, title, date, body, unlisted}] as lib/actors.js describes them;
   catalogByUrl from lib/actors.js parseCatalog; detectionAttack is the parsed
   _data/detection_attack.yml; actorsIndex the parsed _data/actors_index.yml;
   opts.attack(body) -> [{id, tactic, name, confidence}]; opts.catalog is the
   ATT&CK catalog ({byId, version}); opts.tacticOrder the strip's order. */
function buildAttack(reports, catalogByUrl, detectionAttack, actorsIndex, opts) {
  opts = opts || {};
  var cat = opts.catalog || { byId: {}, version: null };
  var order = opts.tacticOrder || [];
  var problems = [], unresolved = {};
  var tech = {};

  function entry(id) {
    if (!tech[id]) {
      var c = cat.byId[id];
      tech[id] = {
        id: id,
        name: c ? c.name : '',
        tactic: c ? c.tactic : '',
        tactics: c ? c.tactics.slice() : [],
        reports: [], detections: [], actors: []
      };
    }
    return tech[id];
  }

  // Which detection pages and reports are published, from the catalog.
  var detectionPublished = {}, detectionMeta = {};
  Object.keys(catalogByUrl).forEach(function (url) {
    var e = catalogByUrl[url];
    if (e.detection_url) {
      var key = String(e.detection_url).split('/').pop();
      detectionPublished[key] = true;
      detectionMeta[key] = { url: String(e.detection_url), title: e.title ? String(e.title) : key,
        date: e.date ? dateStr(e.date) : null, report_url: url };
    }
  });

  reports.forEach(function (r) {
    if (r.unlisted || !catalogByUrl[r.url]) return;      // published only
    var c = catalogByUrl[r.url];
    var seen = {};
    (opts.attack ? opts.attack(r.body) : []).forEach(function (t) {
      if (!cat.byId[t.id]) { unresolved[t.id] = (unresolved[t.id] || 0) + 1; return; }
      if (seen[t.id]) return;
      seen[t.id] = true;
      entry(t.id).reports.push({
        url: r.url,
        title: c.title ? String(c.title) : r.title,
        date: c.date ? dateStr(c.date) : r.date,
        tactic: t.tactic || '',
        confidence: t.confidence || null
      });
    });
  });

  Object.keys(detectionAttack || {}).forEach(function (key) {
    if (!detectionPublished[key]) return;
    var page = detectionAttack[key];
    (page.rows || []).forEach(function (row) {
      if (!cat.byId[row.id]) { unresolved[row.id] = (unresolved[row.id] || 0) + 1; return; }
      var e = entry(row.id);
      e.detections.push({
        url: detectionMeta[key].url,
        title: detectionMeta[key].title,
        date: detectionMeta[key].date,
        report_url: detectionMeta[key].report_url,
        rules: row.rules || '',
        count: row.count || 0
      });
    });
  });

  ((actorsIndex && actorsIndex.actors) || []).forEach(function (a) {
    (a.attack || []).forEach(function (t) {
      if (!cat.byId[t.id]) return;
      var e = entry(t.id);
      if (e.actors.indexOf(a.id) === -1) e.actors.push(a.id);
    });
  });

  var ids = Object.keys(tech);
  ids.sort(opts.compareId || function (a, b) { return a < b ? -1 : 1; });
  var techniques = ids.map(function (id) {
    var e = tech[id];
    e.reports.sort(function (x, y) { return String(y.date) < String(x.date) ? -1 : 1; });
    e.detections.sort(function (x, y) { return String(y.date) < String(x.date) ? -1 : 1; });
    e.actors.sort();
    e.url = techniqueUrl(id);
    e.mitre_url = mitreUrl(id);
    e.report_count = e.reports.length;
    e.rule_count = e.detections.reduce(function (n, d) { return n + (d.count || 0); }, 0);
    e.actor_count = e.actors.length;
    e.score = e.report_count + e.rule_count;
    return e;
  });

  // Per tactic, in strip order, the techniques whose PRIMARY tactic it is. A
  // technique that belongs to several tactics is listed under each, so the
  // heatmap column is complete; the page itself names all of them.
  var tactics = order.map(function (name) {
    var list = techniques.filter(function (t) { return t.tactics.indexOf(name) > -1; });
    return {
      name: name,
      slug: opts.tacticSlug ? opts.tacticSlug(name) : familySlug(name),
      techniques: list.map(function (t) { return t.id; }),
      technique_count: list.length,
      report_count: list.reduce(function (n, t) { return n + t.report_count; }, 0),
      rule_count: list.reduce(function (n, t) { return n + t.rule_count; }, 0)
    };
  });
  var orphan = techniques.filter(function (t) {
    return !t.tactics.some(function (n) { return order.indexOf(n) > -1; });
  });
  if (orphan.length) {
    problems.push('technique(s) whose catalog tactic is not in the strip order, so no heatmap ' +
      'column can hold them: ' + orphan.map(function (t) { return t.id + ' (' + t.tactic + ')'; }).join(', '));
  }

  var maxScore = techniques.reduce(function (m, t) { return t.score > m ? t.score : m; }, 0);
  return {
    techniques: techniques,
    tactics: tactics,
    max_score: maxScore,
    attack_version: cat.version || null,
    unresolved: Object.keys(unresolved).sort().map(function (id) { return { id: id, mentions: unresolved[id] }; }),
    problems: problems
  };
}

function dateStr(v) {
  if (v instanceof Date) return v.toISOString().slice(0, 10);
  return String(v || '');
}

/* ---- the family index --------------------------------------------------- */

/* detectionFamilies: {detectionSlug -> {label -> [rules]}}, feedFamilies:
   {feedFile -> [labels]}, actors: the parsed _data/actors.yml list, catalogByUrl
   as above (its entries carry tags, detection_url, ioc_url). */
function buildFamilies(families, detectionFamilies, feedFamilies, catalogByUrl, actors) {
  var match = familyMatcher(families);
  var out = {};
  families.forEach(function (f) {
    out[f.name] = {
      name: f.name, slug: f.slug, url: familyUrl(f.name), kind: f.kind,
      aliases: f.aliases, summary: f.summary,
      reports: [], detections: [], feeds: [], actors: [], tooling_labels: []
    };
  });
  var unmapped = {};   // label -> where

  var detectionMeta = {}, feedMeta = {}, reportsByTag = {};
  Object.keys(catalogByUrl).forEach(function (url) {
    var e = catalogByUrl[url];
    var row = { url: url, title: e.title ? String(e.title) : url, date: e.date ? dateStr(e.date) : null,
      detection_url: e.detection_url || null, ioc_url: e.ioc_url || null, stix_url: e.stix_url || null };
    if (e.detection_url) detectionMeta[String(e.detection_url).split('/').pop()] = row;
    if (e.ioc_url) feedMeta[String(e.ioc_url).split('/').pop()] = row;
    (e.tags || []).forEach(function (t) {
      (reportsByTag[norm(t)] = reportsByTag[norm(t)] || []).push(row);
    });
  });

  function addReport(fam, row) {
    if (!fam.reports.some(function (r) { return r.url === row.url; })) fam.reports.push(row);
  }

  Object.keys(detectionFamilies).forEach(function (slug) {
    var meta = detectionMeta[slug];
    if (!meta) return;                                   // unlisted or unknown page
    var labels = detectionFamilies[slug];
    Object.keys(labels).forEach(function (label) {
      var fams = match(label);
      if (!fams.length) { (unmapped[label] = unmapped[label] || []).push('detection ' + slug); return; }
      fams.forEach(function (f) {
        var fam = out[f.name];
        fam.detections.push({ url: meta.detection_url, title: meta.title, date: meta.date,
          report_url: meta.url, label: label, rules: labels[label].slice() });
        addReport(fam, meta);
      });
    });
  });

  Object.keys(feedFamilies).forEach(function (file) {
    var meta = feedMeta[file];
    if (!meta) return;
    feedFamilies[file].forEach(function (label) {
      var fams = match(label);
      if (!fams.length) { (unmapped[label] = unmapped[label] || []).push('feed ' + file); return; }
      fams.forEach(function (f) {
        var fam = out[f.name];
        if (!fam.feeds.some(function (x) { return x.url === meta.ioc_url; })) {
          fam.feeds.push({ url: meta.ioc_url, title: meta.title, date: meta.date, report_url: meta.url, label: label });
        }
        addReport(fam, meta);
      });
    });
  });

  families.forEach(function (f) {
    var fam = out[f.name];
    f.tags.forEach(function (t) { (reportsByTag[norm(t)] || []).forEach(function (row) { addReport(fam, row); }); });
  });

  (actors || []).forEach(function (a) {
    (a.tooling || []).forEach(function (label) {
      match(label).forEach(function (f) {               // tooling is free text; no warning
        var fam = out[f.name];
        if (fam.actors.indexOf(a.id) === -1) fam.actors.push(a.id);
        if (fam.tooling_labels.indexOf(label) === -1) fam.tooling_labels.push(label);
      });
    });
  });

  var list = families.map(function (f) {
    var fam = out[f.name];
    fam.reports.sort(function (x, y) { return String(y.date) < String(x.date) ? -1 : 1; });
    fam.detections.sort(function (x, y) { return String(y.date) < String(x.date) ? -1 : 1; });
    fam.actors.sort();
    fam.report_count = fam.reports.length;
    fam.rule_count = fam.detections.reduce(function (n, d) { return n + d.rules.length; }, 0);
    fam.feed_count = fam.feeds.length;
    fam.actor_count = fam.actors.length;
    return fam;
  });
  // A family nothing on the site mentions is a vocabulary entry with no page
  // behind it; say so rather than ship an empty page.
  var problems = [];
  list.forEach(function (fam) {
    if (!fam.report_count && !fam.rule_count && !fam.feed_count && !fam.actor_count) {
      problems.push('family "' + fam.name + '" matches nothing published (no rule, feed, tag or actor), ' +
        'so it would render an empty page. Add an alias that matches, or drop the entry.');
    }
  });
  return {
    families: list,
    unmapped: Object.keys(unmapped).sort().map(function (l) { return { label: l, where: unmapped[l] }; }),
    problems: problems
  };
}

/* ---- outputs ------------------------------------------------------------ */

function navigatorLayer(index, opts) {
  opts = opts || {};
  var max = index.max_score || 1;
  return {
    name: opts.name || 'The Hunter’s Ledger: corpus coverage',
    domain: 'enterprise-attack',
    description: opts.description || ('Every technique mapped by a published report or detection rule on ' +
      'the-hunters-ledger.com. Score is the number of reports plus rules mapping the technique.'),
    versions: { attack: index.attack_version ? String(index.attack_version).split('.')[0] : '19', navigator: '4.9.0', layer: '4.5' },
    techniques: index.techniques.reduce(function (acc, t) {
      t.tactics.forEach(function (tactic) {
        acc.push({
          techniqueID: t.id,
          tactic: opts.tacticSlug ? opts.tacticSlug(tactic) : familySlug(tactic),
          score: t.score,
          comment: t.report_count + ' report(s), ' + t.rule_count + ' rule(s)' +
            (t.actors.length ? ', actors ' + t.actors.join(' ') : '') + '. ' + opts.site + t.url,
          enabled: true
        });
      });
      return acc;
    }, []),
    gradient: { colors: ['#c7e3ff', '#1f6feb'], minValue: 0, maxValue: max }
  };
}

function toYamlAttack(index) {
  var head = '# Auto-generated by tools/report-tooling/generate-xref.js from the reports\'\n' +
    '# ATT&CK tables, _data/detection_attack.yml, _data/actors_index.yml and the\n' +
    '# catalog. Do NOT edit by hand; re-run the generator. Published sources only.\n';
  return head + yaml.dump({
    attack_version: index.attack_version, max_score: index.max_score,
    tactics: index.tactics, techniques: index.techniques, unresolved: index.unresolved
  }, { lineWidth: 100, noRefs: true, sortKeys: false });
}

function toYamlFamilies(index) {
  var head = '# Auto-generated by tools/report-tooling/generate-xref.js from _data/families.yml\n' +
    '# matched against the YARA family metadata, the feed family fields, the catalog\n' +
    '# tags and the actors\' tooling. Do NOT edit by hand; re-run the generator.\n';
  return head + yaml.dump({ families: index.families, unmapped: index.unmapped },
    { lineWidth: 100, noRefs: true, sortKeys: false });
}

function stubTechnique(t) {
  var title = t.id + (t.name ? ' ' + t.name : '');
  return '---\n' +
    'layout: technique\n' +
    'title: "' + title.replace(/"/g, '\\"') + '"\n' +
    'technique_id: "' + t.id + '"\n' +
    'permalink: ' + techniqueUrl(t.id) + '\n' +
    'description: "Every report, detection rule and tracked actor on The Hunters Ledger mapped to ATT&CK ' + t.id + (t.name ? ', ' + t.name.replace(/"/g, '\\"') : '') + '."\n' +
    '---\n' +
    '{%- comment -%} Generated by tools/report-tooling/generate-xref.js. The page body\n' +
    '  comes from _data/attack_index.yml; edit the reports and rules, not this file. {%- endcomment -%}\n';
}

function stubFamily(f) {
  return '---\n' +
    'layout: family\n' +
    'title: "' + f.name.replace(/"/g, '\\"') + '"\n' +
    'family_slug: "' + f.slug + '"\n' +
    'permalink: ' + familyUrl(f.name) + '\n' +
    'description: "Every report, detection rule, IOC feed and tracked actor on The Hunters Ledger involving ' + f.name.replace(/"/g, '\\"') + '."\n' +
    '---\n' +
    '{%- comment -%} Generated by tools/report-tooling/generate-xref.js. The page body\n' +
    '  comes from _data/family_index.yml and _data/families.yml. {%- endcomment -%}\n';
}

module.exports = {
  ROOT: ROOT, FAMILIES_FILE: FAMILIES_FILE, ATTACK_INDEX: ATTACK_INDEX, FAMILY_INDEX: FAMILY_INDEX,
  DETECTION_ATTACK: DETECTION_ATTACK, ACTORS_INDEX: ACTORS_INDEX, TECHNIQUE_DIR: TECHNIQUE_DIR,
  FAMILY_DIR: FAMILY_DIR, LAYER_FILE: LAYER_FILE, TECHNIQUE_MARKER: TECHNIQUE_MARKER,
  FAMILY_MARKER: FAMILY_MARKER, KINDS: KINDS,
  techniqueUrl: techniqueUrl, mitreUrl: mitreUrl, familySlug: familySlug, familyUrl: familyUrl,
  parseFamilies: parseFamilies, familyMatcher: familyMatcher, stripParens: stripParens,
  detectionFamiliesFromText: detectionFamiliesFromText, readDetectionFamilies: readDetectionFamilies,
  feedFamiliesFromJson: feedFamiliesFromJson, readFeedFamilies: readFeedFamilies,
  buildAttack: buildAttack, buildFamilies: buildFamilies, navigatorLayer: navigatorLayer,
  toYamlAttack: toYamlAttack, toYamlFamilies: toYamlFamilies,
  stubTechnique: stubTechnique, stubFamily: stubFamily
};
