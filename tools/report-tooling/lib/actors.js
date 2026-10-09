'use strict';

/* The threat actor index: _data/actors.yml, the reports that mention each
   designation, the ATT&CK techniques those reports map, and the links that
   turn a bare "UTA-2026-NNN" in a report into a link to its actor page.

   Two sources, one rule. _data/actors.yml is the hand-written record (what
   the designation is, at what confidence, which reports are ABOUT it). The
   reports are scanned for every mention, so the generated index can never
   list a report that does not name the actor, and an actor page can never be
   built for a designation whose only report is unlisted. Publication is read
   from the same two signals catalog-status.js uses for IOC feeds: the catalog
   entry (uncommented) and the report front matter (no `unlisted: true`), and
   a disagreement is a failure rather than something to resolve.

   Everything here is pure on its inputs so it can be tested on fixtures;
   generate-actors.js and check-actors.js do the reading and writing. */

var fs = require('node:fs');
var path = require('node:path');

var yaml = require('js-yaml');

var ROOT = path.join(__dirname, '..', '..', '..');
var ACTORS_FILE = path.join(ROOT, '_data', 'actors.yml');
var INDEX_FILE = path.join(ROOT, '_data', 'actors_index.yml');
var CATALOG_FILE = path.join(ROOT, '_data', 'catalog.yml');
var REPORT_DIR = path.join(ROOT, 'reports');
var DETECTION_DIR = path.join(ROOT, 'hunting-detections');
var ACTOR_DIR = path.join(ROOT, 'actors');

var ID_RE = /\bUTA-\d{4}-\d{3}\b/g;
var ID_SHAPE = /^UTA-\d{4}-\d{3}$/;
var STATUSES = ['active', 'merged', 'retired'];
var LEVELS = ['DEFINITE', 'HIGH', 'MODERATE', 'LOW', 'INSUFFICIENT'];

/* The generated stub is recognised by this marker, so a hand-authored page
   under actors/ is never deleted by the generator. */
var STUB_MARKER = 'layout: actor';

function actorUrl(id) { return '/actors/' + id + '/'; }

/* ---- _data/actors.yml --------------------------------------------------- */

function parseActors(text) {
  var doc = yaml.load(text);
  var problems = [];
  if (!doc || !Array.isArray(doc.actors)) {
    return { actors: [], problems: ['_data/actors.yml has no `actors:` list'] };
  }
  var seen = {};
  var actors = doc.actors.map(function (a, i) {
    var where = 'actors[' + i + ']' + (a && a.id ? ' (' + a.id + ')' : '');
    if (!a || typeof a !== 'object') { problems.push(where + ' is not a mapping'); return null; }
    if (!ID_SHAPE.test(String(a.id || ''))) problems.push(where + ': id must look like UTA-YYYY-NNN');
    if (seen[a.id]) problems.push(where + ': duplicate id');
    seen[a.id] = true;
    if (STATUSES.indexOf(a.status) === -1) problems.push(where + ': status must be one of ' + STATUSES.join(', '));
    ['first_observed', 'last_updated'].forEach(function (k) {
      if (!isDate(a[k])) problems.push(where + ': ' + k + ' must be a YYYY-MM-DD date');
    });
    if (!a.type || !a.summary) problems.push(where + ': type and summary are required');
    var c = a.confidence || {};
    if (c.distinct_actor != null && LEVELS.indexOf(c.distinct_actor) === -1) {
      problems.push(where + ': confidence.distinct_actor must be one of ' + LEVELS.join(', '));
    }
    if (LEVELS.indexOf(c.named_actor) === -1) {
      problems.push(where + ': confidence.named_actor must be one of ' + LEVELS.join(', '));
    }
    if (c.distinct_actor_pct != null && !(c.distinct_actor_pct >= 1 && c.distinct_actor_pct <= 100)) {
      problems.push(where + ': confidence.distinct_actor_pct must be 1 to 100 or null');
    }
    var primary = a.reports && a.reports.primary;
    if (!Array.isArray(primary) || !primary.length) {
      problems.push(where + ': reports.primary must list at least one report url');
    } else {
      primary.forEach(function (u) {
        if (!/^\/reports\/[^/]+\/$/.test(String(u))) problems.push(where + ': report url "' + u + '" must look like /reports/<slug>/');
      });
    }
    (a.related || []).forEach(function (r) {
      if (!r || !ID_SHAPE.test(String(r.id || '')) || !r.relation) {
        problems.push(where + ': every related entry needs an id and a relation');
      }
    });
    return a;
  }).filter(Boolean);
  actors.forEach(function (a) {
    (a.related || []).forEach(function (r) {
      if (r && r.id && !seen[r.id]) problems.push(a.id + ': related ' + r.id + ' has no entry (an embargoed sibling is listed once it is published)');
    });
  });
  return { actors: actors, problems: problems };
}

function isDate(v) {
  if (v instanceof Date) return !isNaN(v.getTime());
  return /^\d{4}-\d{2}-\d{2}$/.test(String(v || ''));
}

function dateStr(v) {
  if (v instanceof Date) return v.toISOString().slice(0, 10);
  return String(v || '');
}

/* ---- the catalog, keyed by report url ------------------------------------ */

function parseCatalog(text) {
  var doc = yaml.load(text) || {};
  var byUrl = {};
  (doc.entries || []).forEach(function (e) {
    if (e && e.report_url) byUrl[String(e.report_url)] = e;
  });
  return byUrl;
}

/* ---- reports ------------------------------------------------------------ */

function frontMatter(md) {
  var lines = String(md).split('\n');
  if (!/^---\s*$/.test(lines[0] || '')) return { fm: {}, body: md };
  for (var i = 1; i < lines.length; i++) {
    if (/^---\s*$/.test(lines[i])) {
      var fm = {};
      try { fm = yaml.load(lines.slice(1, i).join('\n')) || {}; } catch (e) { fm = {}; }
      return { fm: fm, body: lines.slice(i + 1).join('\n') };
    }
  }
  return { fm: {}, body: md };
}

/* Counts every designation named in the body, linked or not. */
function mentions(body) {
  var out = {};
  var m;
  // A linked mention carries the designation twice, in the href and in the
  // text. Count the text only, so linking a report never changes its count.
  var text = String(body).replace(/<a href="\/actors\/UTA-\d{4}-\d{3}\/">/g, '');
  ID_RE.lastIndex = 0;
  while ((m = ID_RE.exec(text)) !== null) out[m[0]] = (out[m[0]] || 0) + 1;
  return out;
}

/* One report as the index needs it. `md` is the file text, `slug` the directory. */
function describeReport(slug, md) {
  var p = frontMatter(md);
  var url = p.fm.permalink ? String(p.fm.permalink) : '/reports/' + slug + '/';
  if (url.charAt(url.length - 1) !== '/') url += '/';
  return {
    slug: slug,
    url: url,
    title: p.fm.title ? String(p.fm.title) : slug,
    date: p.fm.date ? dateStr(p.fm.date) : null,
    unlisted: p.fm.unlisted === true,
    mentions: mentions(p.body),
    body: p.body
  };
}

function readReports(dir) {
  var out = [];
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (e) {
    if (!e.isDirectory()) return;
    var f = path.join(dir, e.name, 'index.md');
    var md;
    try { md = fs.readFileSync(f, 'utf8'); } catch (err) { return; }
    out.push(describeReport(e.name, md));
  });
  return out;
}

/* Publication, from both signals. Returns 'published', 'embargoed' or a
   conflict object. A report the catalog never lists is 'unknown', which is
   NOT folded into either: a page or a link for it would be a guess. */
function publication(report, catalogByUrl) {
  var inCatalog = !!catalogByUrl[report.url];
  if (inCatalog && !report.unlisted) return 'published';
  if (!inCatalog && report.unlisted) return 'embargoed';
  if (!inCatalog) return 'unknown';
  return 'conflict';
}

/* ---- ATT&CK, through the same parser the report strip uses --------------- */

function attackFor(body, deps) {
  var html = deps.extractTables(body).join('\n');
  var doc = new deps.JSDOM('<body>' + html + '</body>').window.document;
  var tables = doc.querySelectorAll('table');
  var out = [];
  for (var i = 0; i < tables.length; i++) {
    var p = deps.AC.parseTable(tables[i]);
    p.techniques.forEach(function (t) { out.push({ id: t.id, tactic: t.tactic, name: t.name || '' }); });
  }
  return out;
}

/* ---- the index ---------------------------------------------------------- */

/* opts.attack: function(body) -> [{id, tactic, name}] (injected so the
   library needs no jsdom to be tested); opts.catalogNames: {id -> name} from
   the ATT&CK catalog so a technique name comes from the vocabulary rather than
   from whatever a report's cell said. */
function build(actors, reports, catalogByUrl, opts) {
  opts = opts || {};
  var problems = [];
  var byUrl = {};
  var status = {};
  reports.forEach(function (r) {
    byUrl[r.url] = r;
    status[r.url] = publication(r, catalogByUrl);
    if (status[r.url] === 'conflict') {
      problems.push('publication signals disagree for ' + r.url + ': listed in the catalog but ' +
        'front matter says unlisted. Resolve it in the source; nothing here guesses.');
    }
  });
  var known = {};
  actors.forEach(function (a) { known[a.id] = a; });

  var entries = [];
  var published = {};
  actors.forEach(function (a) {
    var rows = {};
    (a.reports.primary || []).forEach(function (u) {
      var r = byUrl[u];
      if (!r) { problems.push(a.id + ': primary report ' + u + ' does not exist under reports/'); return; }
      if (!r.mentions[a.id]) problems.push(a.id + ': primary report ' + u + ' never names the designation');
      if (status[u] !== 'published') {
        problems.push(a.id + ': primary report ' + u + ' is ' + status[u] + ', so this actor cannot ' +
          'have a page yet. Comment the entry out until the report goes live.');
      }
      rows[u] = { role: 'primary' };
    });
    reports.forEach(function (r) {
      if (!r.mentions[a.id] || rows[r.url] || status[r.url] !== 'published') return;
      rows[r.url] = { role: 'mentions' };
    });
    var list = Object.keys(rows).map(function (u) {
      var r = byUrl[u];
      if (!r) return null;
      var c = catalogByUrl[u] || {};
      return {
        url: u,
        title: c.title ? String(c.title) : r.title,
        date: c.date ? dateStr(c.date) : r.date,
        severity: c.severity || null,
        role: rows[u].role,
        mentions: r.mentions[a.id] || 0,
        detection_url: c.detection_url || null,
        ioc_url: c.ioc_url || null,
        stix_url: c.stix_url || null
      };
    }).filter(Boolean);
    list.sort(function (x, y) {
      if (x.role !== y.role) return x.role === 'primary' ? -1 : 1;
      return String(y.date) < String(x.date) ? -1 : (String(y.date) > String(x.date) ? 1 : 0);
    });

    /* Techniques come from each primary report's own mapping table. A report
       that keeps its mapping on the companion detection page instead (the
       AI-series reports say so in their section 7) contributes that page's
       generated table, from _data/detection_attack.yml, with the link pointing
       there. Each technique remembers where it was read from. */
    var techniques = {};
    function add(t, link, source) {
      var key = t.id;
      if (!techniques[key]) {
        techniques[key] = {
          id: t.id,
          name: (opts.catalogNames && opts.catalogNames[t.id]) || t.name || '',
          tactic: t.tactic || '',
          source: source,
          link: link,
          reports: []
        };
      }
      if (techniques[key].reports.indexOf(link) === -1) techniques[key].reports.push(link);
    }
    list.forEach(function (row) {
      if (row.role !== 'primary') return;
      var own = opts.attack ? opts.attack(byUrl[row.url].body) : [];
      if (own.length) {
        own.forEach(function (t) { add(t, row.url, 'report'); });
        return;
      }
      var det = row.detection_url && opts.detectionAttack &&
        opts.detectionAttack[String(row.detection_url).split('/').pop()];
      if (det && det.rows) {
        det.rows.forEach(function (t) { add(t, String(row.detection_url), 'detections'); });
      }
    });
    var attack = Object.keys(techniques).map(function (k) { return techniques[k]; });
    attack.sort(function (x, y) { return opts.compareId ? opts.compareId(x.id, y.id) : (x.id < y.id ? -1 : 1); });

    var totalMentions = list.reduce(function (n, r) { return n + r.mentions; }, 0);
    var entry = {
      id: a.id,
      url: actorUrl(a.id),
      reports: list,
      report_count: list.length,
      mention_count: totalMentions,
      attack: attack,
      tactics: tacticsOf(attack, opts.tacticOrder)
    };
    entries.push(entry);
    published[a.id] = true;
  });

  /* A designation a published report names with no entry would link nowhere.
     One whose only mentions are in unlisted reports is expected to be absent. */
  var unknown = {};
  reports.forEach(function (r) {
    Object.keys(r.mentions).forEach(function (id) {
      if (known[id]) return;
      unknown[id] = unknown[id] || { published: [], unlisted: [] };
      (status[r.url] === 'published' ? unknown[id].published : unknown[id].unlisted).push(r.url);
    });
  });
  var embargoed = [];
  Object.keys(unknown).sort().forEach(function (id) {
    if (unknown[id].published.length) {
      problems.push(id + ' is named in ' + unknown[id].published.join(', ') +
        ' but has no entry in _data/actors.yml, so its mentions cannot link anywhere.');
    } else {
      embargoed.push(id);
    }
  });

  return { entries: entries, problems: problems, embargoed: embargoed, status: status };
}

function tacticsOf(attack, order) {
  var seen = {};
  attack.forEach(function (t) { if (t.tactic) seen[t.tactic] = true; });
  var names = Object.keys(seen);
  if (order) {
    names.sort(function (a, b) { return order.indexOf(a) - order.indexOf(b); });
  } else {
    names.sort();
  }
  return names;
}

/* ---- output -------------------------------------------------------------- */

function toYaml(index) {
  var head = '# Auto-generated by tools/report-tooling/generate-actors.js from\n' +
    '# _data/actors.yml, _data/catalog.yml and the reports. Do NOT edit by hand;\n' +
    '# re-run the generator. Per designation: every PUBLISHED report that names\n' +
    '# it (primary first, then by date), and the ATT&CK techniques the primary\n' +
    "# reports' mapping tables carry. An actor whose reports are unlisted is absent.\n";
  var body = yaml.dump({ actors: index.entries }, { lineWidth: 100, noRefs: true, sortKeys: false });
  return head + body;
}

function stub(actor) {
  var id = actor.id;
  return '---\n' +
    'layout: actor\n' +
    'title: "' + id + '"\n' +
    'actor_id: "' + id + '"\n' +
    'permalink: ' + actorUrl(id) + '\n' +
    'description: "' + String(actor.type).replace(/"/g, '\\"') + '. Threat actor profile from The Hunters Ledger."\n' +
    '---\n' +
    '{%- comment -%} Generated by tools/report-tooling/generate-actors.js. The page\n' +
    '  body comes from _data/actors.yml and _data/actors_index.yml; edit those. {%- endcomment -%}\n';
}

/* ---- linking mentions in markdown --------------------------------------- */

/* Rewrites every bare designation in `md` to an HTML link to its actor page,
   for designations in `known` only. HTML anchors rather than markdown links
   because reports mix markdown prose with raw HTML tables and figures, and an
   inline <a> renders the same in both while a markdown link inside a raw HTML
   block would print its brackets.

   Left alone: the front matter, fenced code, inline code, anything inside an
   HTML tag (an alt text, a data attribute), text already inside <a>...</a> or a
   markdown link's text, and headings (their text feeds the table of contents).
   Idempotent: a second run changes nothing. */
function linkify(md, known) {
  var text = String(md);
  var lines = text.split('\n');
  var start = 0;
  if (/^---\s*$/.test(lines[0] || '')) {
    for (var i = 1; i < lines.length; i++) {
      if (/^---\s*$/.test(lines[i])) { start = i + 1; break; }
    }
  }
  var count = 0;
  var inFence = null;
  var state = { inTag: false, inAnchor: 0 };
  for (var n = start; n < lines.length; n++) {
    var line = lines[n];
    var fence = /^\s*(`{3,}|~{3,})/.exec(line);
    if (fence) {
      if (!inFence) inFence = fence[1].charAt(0);
      else if (fence[1].charAt(0) === inFence) inFence = null;
      continue;
    }
    if (inFence) continue;
    if (/^\s{0,3}#{1,6}\s/.test(line)) continue;
    // Tag and anchor state carries across lines: a figure's alt text and a
    // multi-line <a> both span lines, and a link landing inside either would
    // break the attribute or nest an anchor.
    var r = linkLine(line, known, state);
    lines[n] = r.line;
    state = r.state;
    count += r.count;
  }
  return { text: lines.join('\n'), count: count, changed: count > 0 };
}

/* Walks one line, tracking the regions a link must not land in. */
function linkLine(line, known, state) {
  var out = '';
  var i = 0, count = 0;
  var inTag = !!(state && state.inTag), inCode = false, inAnchor = (state && state.inAnchor) || 0, linkText = 0;
  while (i < line.length) {
    var ch = line[i];
    if (inCode) {
      out += ch; i++;
      if (ch === '`') inCode = false;
      continue;
    }
    if (inTag) {
      out += ch; i++;
      if (ch === '>') inTag = false;
      continue;
    }
    if (ch === '`') { inCode = true; out += ch; i++; continue; }
    // Only a real tag opens one: "<50%" in prose is a comparison, not markup,
    // and treating it as a tag would swallow every mention until the next ">".
    if (ch === '<' && /^<[A-Za-z!\/]/.test(line.slice(i, i + 2))) {
      var open = /^<a[\s>]/i.test(line.slice(i)), close = /^<\/a\s*>/i.test(line.slice(i));
      if (open) inAnchor++;
      if (close && inAnchor > 0) inAnchor--;
      inTag = true; out += ch; i++; continue;
    }
    /* A markdown link: [text](url). The text may hold a designation, and a
       link inside a link is invalid. Track only well-formed ones on this line. */
    if (ch === '[' && line.indexOf('](', i) > -1) { linkText++; out += ch; i++; continue; }
    if (ch === ']' && linkText > 0) {
      // Skip past the (url) so its text is never touched either.
      var m = /^\]\(([^)\s]*)\)/.exec(line.slice(i));
      linkText--;
      if (m) { out += m[0]; i += m[0].length; continue; }
      out += ch; i++; continue;
    }
    if (ch === 'U' && !inAnchor && !linkText) {
      var mm = /^UTA-\d{4}-\d{3}\b/.exec(line.slice(i));
      var before = i === 0 ? '' : line[i - 1];
      if (mm && !/[\w-]/.test(before) && known[mm[0]]) {
        out += '<a href="' + actorUrl(mm[0]) + '">' + mm[0] + '</a>';
        i += mm[0].length;
        count++;
        continue;
      }
    }
    out += ch; i++;
  }
  return { line: out, count: count, state: { inTag: inTag, inAnchor: inAnchor } };
}

module.exports = {
  ROOT: ROOT, ACTORS_FILE: ACTORS_FILE, INDEX_FILE: INDEX_FILE, CATALOG_FILE: CATALOG_FILE,
  REPORT_DIR: REPORT_DIR, DETECTION_DIR: DETECTION_DIR, ACTOR_DIR: ACTOR_DIR,
  STUB_MARKER: STUB_MARKER, ID_RE: ID_RE, ID_SHAPE: ID_SHAPE,
  actorUrl: actorUrl, parseActors: parseActors, parseCatalog: parseCatalog,
  frontMatter: frontMatter, mentions: mentions, describeReport: describeReport,
  readReports: readReports, publication: publication, attackFor: attackFor,
  build: build, toYaml: toYaml, stub: stub, linkify: linkify, dateStr: dateStr
};
