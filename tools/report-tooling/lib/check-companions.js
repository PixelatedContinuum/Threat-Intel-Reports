'use strict';

/* A report's companion values must point at something that exists.

   `detection_page`, `ioc_feed` and `stix_bundle` in a report's front matter are rendered
   straight into links and panels by _layouts/post.html, and `ioc_feed` is also split on "/" to
   build the key into _data/ioc_tables.yml (post.html:1001). Nothing compared them with their
   targets: a report whose values named pages that do not exist passed check-report.js and
   pre-review-check.py (tasks/runs/T-0603/r2-skills.md, r2-skills-22, measured).

   The rule, from the source tree, no build needed:
     detection_page  the `permalink:` of a source page, exactly (with the trailing slash)
     ioc_feed        the same, or a static file at that path (older reports name the .json)
     stix_bundle     a static file at that path

   A `redirect_from:` entry (jekyll-redirect-from writes a stub page there) counts as a page that
   exists but is reported separately, because a link through a stub is a hop, not the page.

   Pure: the repo is read through an injected `reader`, so the rules are tested without one.
   PASS, FAIL and NOT CHECKED; NOT CHECKED is never folded into PASS. */

var path = require('node:path');
var fs = require('node:fs');

var FIELDS = ['detection_page', 'ioc_feed', 'stix_bundle'];

function frontMatter(text, yaml) {
  var m = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (!m) return null;
  try {
    var doc = yaml.load(m[1]);
    return doc && typeof doc === 'object' ? doc : null;
  } catch (e) { return null; }
}

/* reader = {
     reports(): [{ name, text }]         every report .md under reports/
     permalinks(): Map<string, object>   every `permalink:` among source pages -> its front matter
     redirects(): Set<string>            every `redirect_from:` path, with a trailing slash
     hasFile(rel): boolean               a static file at the site-relative path
   } */
function check(reader, yaml) {
  var reports = reader.reports();
  var permalinks = reader.permalinks();
  var perStatus = { checked: 0, values: 0, viaRedirect: 0, withValues: 0 };
  var problems = [];
  var unreadable = [];

  /* Control: a value that cannot exist must not resolve. If it does, the lookup is broken
     (for example a permalink set that matches everything) and the run proves nothing. */
  var bogus = '/hunting-detections/__no-such-page-t0603__/';
  if (permalinks.has(bogus) || reader.hasFile('hunting-detections/__no-such-page-t0603__')) {
    return { status: 'NOT CHECKED', reason: 'the lookup resolved a page that cannot exist, so ' +
      'no companion value can be judged' };
  }
  if (!permalinks.size) {
    return { status: 'NOT CHECKED', reason: '0 source pages with a permalink were found, so ' +
      'there is nothing to resolve a companion value against' };
  }
  if (!reports.length) {
    return { status: 'NOT CHECKED', reason: '0 report index.md files were found, so no ' +
      'companion value was read' };
  }

  reports.forEach(function (r) {
    var fm = frontMatter(r.text, yaml);
    if (!fm) { unreadable.push(r.name + ': front matter could not be parsed'); return; }
    perStatus.checked++;
    var before = perStatus.values;
    FIELDS.forEach(function (f) {
      if (!Object.prototype.hasOwnProperty.call(fm, f)) return;
      var v = fm[f];
      if (v === null || v === '' || v === undefined) {
        problems.push(r.name + ': ' + f + ' is empty');
        return;
      }
      v = String(v).trim();
      perStatus.values++;
      if (f === 'stix_bundle') {
        if (!reader.hasFile(v.replace(/^\/+/, ''))) {
          problems.push(r.name + ': stix_bundle ' + v + ' is not a file in the repo');
        }
        return;
      }
      if (permalinks.has(v)) return;
      if (reader.redirects().has(v)) { perStatus.viaRedirect++; return; }
      if (f === 'ioc_feed' && reader.hasFile(v.replace(/^\/+/, ''))) return;
      problems.push(r.name + ': ' + f + ' ' + v + ' matches no source page permalink' +
        (f === 'ioc_feed' ? ', redirect_from or file' : ' or redirect_from') +
        (/\/$/.test(v) || /\.[a-z]+$/.test(v) ? '' : ' (no trailing slash: permalinks end in one)'));
    });
    if (perStatus.values > before) perStatus.withValues++;
  });

  if (unreadable.length) {
    return { status: 'NOT CHECKED', reason: unreadable.length + ' report(s) could not be read: ' +
      unreadable.join('; '), problems: problems };
  }
  if (perStatus.values === 0) {
    return { status: 'NOT CHECKED', reason: perStatus.checked + ' report(s) read, 0 companion ' +
      'values found in them, so nothing was resolved' };
  }
  return {
    status: problems.length ? 'FAIL' : 'PASS', reason: null, problems: problems,
    counts: { reports: perStatus.checked, values: perStatus.values, permalinks: permalinks.size,
               viaRedirect: perStatus.viaRedirect, withValues: perStatus.withValues }
  };
}

var SKIP = { '.git': 1, node_modules: 1, _site: 1, vendor: 1, tools: 1, '.jekyll-cache': 1, docs: 1 };

function diskReader(root, yaml) {
  function walk(dir, fn) {
    fs.readdirSync(dir, { withFileTypes: true }).forEach(function (e) {
      if (SKIP[e.name]) return;
      var p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p, fn); else fn(p);
    });
  }
  return {
    reports: function () {
      var out = [];
      walk(path.join(root, 'reports'), function (p) {
        if (!/\.md$/i.test(p)) return;
        out.push({ name: path.relative(path.join(root, 'reports'), p).split(path.sep).join('/'),
                   text: fs.readFileSync(p, 'utf8') });
      });
      return out;
    },
    permalinks: function () {
      var set = new Map();
      walk(root, function (p) {
        if (!/\.(md|html)$/i.test(p)) return;
        var fm = frontMatter(fs.readFileSync(p, 'utf8'), yaml);
        if (fm && typeof fm.permalink === 'string') set.set(fm.permalink.trim(), fm);
      });
      return set;
    },
    redirects: function () {
      var set = new Set();
      walk(root, function (p) {
        if (!/\.(md|html)$/i.test(p)) return;
        var fm = frontMatter(fs.readFileSync(p, 'utf8'), yaml);
        if (!fm || !fm.redirect_from) return;
        [].concat(fm.redirect_from).forEach(function (u) {
          u = String(u).trim();
          set.add(/\/$/.test(u) ? u : u + '/');
        });
      });
      return set;
    },
    hasFile: function (rel) {
      try { return fs.statSync(path.join(root, rel)).isFile(); } catch (e) { return false; }
    }
  };
}

module.exports = { check: check, diskReader: diskReader, FIELDS: FIELDS };
