'use strict';

/* Post-build link and anchor check over a built Jekyll site (the _site directory).

   Why it exists. Two defects survived every other gate because no gate ever opened the built
   site: 27 "IOC feed" links ended in a slash on a file (`/ioc-feeds/x-iocs.json/`), which GitHub
   Pages answers with a 404, and a larger set of links and `#fragment` targets that point at
   nothing. The scorecard (tasks/runs/T-0603/site_scorecard.py) measured them by hand; this is
   the gate form of the same measurement.

   The rule is the host's, not the filesystem's. GitHub Pages serves:
     /x/   x/index.html and nothing else. `/x.json/` is a 404 even when x.json exists.
     /x    x if x is a file, else x/index.html, else x.html.
     /     index.html.

   Everything here is pure: the filesystem is injected, so the rules are tested without a build.
   PASS, FAIL and NOT CHECKED, the third never folded into the first. */

var path = require('node:path');
var fs = require('node:fs');

var SITE_HOSTS = ['the-hunters-ledger.com', 'www.the-hunters-ledger.com'];

/* The site-relative path a URL asks for. Returns null for another host or a scheme that is not
   a navigation (mailto, tel, javascript, data, anything with an unknown scheme). */
function siteRel(url, pageRel) {
  var u = String(url).trim();
  var m = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(u);
  var rest = u;
  if (m) {
    var scheme = m[1].toLowerCase();
    if (scheme !== 'http' && scheme !== 'https') return null;
    var hm = /^[a-zA-Z]+:\/\/([^\/?#]*)(.*)$/.exec(u);
    if (!hm) return null;
    if (SITE_HOSTS.indexOf(hm[1].toLowerCase()) === -1) return null;
    rest = hm[2] || '/';
  } else if (u.slice(0, 2) === '//') {
    var pm = /^\/\/([^\/?#]*)(.*)$/.exec(u);
    if (!pm || SITE_HOSTS.indexOf(pm[1].toLowerCase()) === -1) return null;
    rest = pm[2] || '/';
  }
  var p = rest.split('#')[0].split('?')[0];
  try { p = decodeURIComponent(p); } catch (e) { /* keep the raw path */ }
  if (p.charAt(0) !== '/') {
    var dir = pageRel ? path.posix.dirname(pageRel.split(path.sep).join('/')) : '.';
    p = path.posix.join(dir === '.' ? '' : dir, p);
  }
  var trailing = /\/$/.test(p);
  var norm = path.posix.normalize('/' + p.replace(/^\/+/, ''));
  return { rel: norm.replace(/^\/+/, ''), trailing: trailing, escapes: /^\/\.\./.test(norm) };
}

/* fsx = { isFile(rel), isDir(rel) } over site-relative paths. Returns the served file's
   site-relative path, or null when the host serves none. */
function resolve(url, fsx, pageRel) {
  var s = siteRel(url, pageRel);
  if (!s || s.escapes) return null;
  var rel = s.rel;
  var trailing = s.trailing;
  if (rel === '' || rel === '.') { rel = 'index.html'; trailing = false; }
  if (trailing) {
    var idx = path.posix.join(rel, 'index.html');
    return fsx.isFile(idx) ? idx : null;
  }
  if (fsx.isFile(rel)) return rel;
  if (fsx.isDir(rel)) {
    var i2 = path.posix.join(rel, 'index.html');
    return fsx.isFile(i2) ? i2 : null;
  }
  var cands = [rel + '.html', path.posix.join(rel, 'index.html')];
  for (var i = 0; i < cands.length; i++) if (fsx.isFile(cands[i])) return cands[i];
  return null;
}

/* True when the URL asks for a directory (`/x/`) where `x` is a regular file. */
function trailingSlashOnFile(url, fsx, pageRel) {
  var s = siteRel(url, pageRel);
  if (!s || s.escapes || !s.trailing) return false;
  var rel = s.rel.replace(/\/+$/, '');
  if (rel === '' || rel === '.') return false;
  return fsx.isFile(rel);
}

function isExternal(url) {
  var u = String(url).trim();
  if (/^(mailto|tel|javascript|data):/i.test(u)) return true;
  if (/^([a-zA-Z][a-zA-Z0-9+.-]*:|\/\/)/.test(u)) return siteRel(u, null) === null;
  return false;
}

var COMMENT_RE = /<!--[\s\S]*?-->/g;
var SCRIPT_RE = /<script\b[^>]*>[\s\S]*?<\/script>/gi;
var STYLE_RE = /<style\b[^>]*>[\s\S]*?<\/style>/gi;
var TAG_RE = /<([a-zA-Z][a-zA-Z0-9:-]*)((?:\s+[^<>]*?)?)\s*\/?>/g;
var ATTR_RE = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>`]+))/g;

function unescapeHtml(s) {
  return String(s)
    .replace(/&#x([0-9a-fA-F]+);/g, function (m, h) { return String.fromCodePoint(parseInt(h, 16)); })
    .replace(/&#(\d+);/g, function (m, d) { return String.fromCodePoint(parseInt(d, 10)); })
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

/* links: every href/src/poster/action value; ids: every fragment target the page offers
   (id on any element, name on <a>). Script, style and comment bodies are dropped first, the
   same rule the scorecard uses, so a URL inside inline JS is not a link. */
function parsePage(html) {
  var body = String(html).replace(COMMENT_RE, ' ').replace(SCRIPT_RE, ' ').replace(STYLE_RE, ' ');
  var links = [];
  var ids = new Set();
  TAG_RE.lastIndex = 0;
  var tm;
  while ((tm = TAG_RE.exec(body)) !== null) {
    var tag = tm[1].toLowerCase();
    var attrs = tm[2] || '';
    ATTR_RE.lastIndex = 0;
    var am;
    while ((am = ATTR_RE.exec(attrs)) !== null) {
      var name = am[1].toLowerCase();
      var raw = am[2] !== undefined ? am[2] : (am[3] !== undefined ? am[3] : am[4]);
      var value = unescapeHtml(raw || '');
      if (name === 'href' || name === 'src' || name === 'poster' || name === 'action') {
        links.push({ tag: tag, attr: name, value: value });
      }
      if (name === 'id' && value) ids.add(value);
      else if (name === 'name' && tag === 'a' && value) ids.add(value);
    }
  }
  return { links: links, ids: ids };
}

/* The in-run control. A tiny in-memory site with one of each shape the gate must tell apart.
   If the resolver does not answer every row as the host would, the run measured nothing it can
   vouch for and is NOT CHECKED. The control varies the same thing the measurement varies: the
   trailing slash on a file. */
function control() {
  var files = { 'index.html': 1, 'ioc-feeds/x-iocs.json': 1, 'reports/a/index.html': 1, 'about.html': 1 };
  var dirs = { 'ioc-feeds': 1, 'reports': 1, 'reports/a': 1 };
  var fsx = {
    isFile: function (r) { return !!files[r]; },
    isDir: function (r) { return !!dirs[r]; }
  };
  var rows = [
    ['/ioc-feeds/x-iocs.json', 'ioc-feeds/x-iocs.json'],
    ['/ioc-feeds/x-iocs.json/', null],
    ['/reports/a/', 'reports/a/index.html'],
    ['/reports/a', 'reports/a/index.html'],
    ['/about', 'about.html'],
    ['/about/', null],
    ['/', 'index.html'],
    ['/nope', null],
    ['https://the-hunters-ledger.com/ioc-feeds/x-iocs.json/', null]
  ];
  var bad = [];
  rows.forEach(function (r) {
    var got = resolve(r[0], fsx, 'index.html');
    if (got !== r[1]) bad.push(r[0] + ' -> ' + got + ' (expected ' + r[1] + ')');
  });
  if (!trailingSlashOnFile('/ioc-feeds/x-iocs.json/', fsx, 'index.html')) {
    bad.push('trailingSlashOnFile missed /ioc-feeds/x-iocs.json/');
  }
  if (trailingSlashOnFile('/reports/a/', fsx, 'index.html')) {
    bad.push('trailingSlashOnFile flagged a real directory');
  }
  return { rows: rows.length + 2, bad: bad };
}

function walkHtml(siteDir) {
  var out = [];
  (function walk(d) {
    fs.readdirSync(d, { withFileTypes: true }).forEach(function (e) {
      var p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.html?$/i.test(e.name)) out.push(p);
    });
  })(siteDir);
  return out.sort();
}

function diskFs(siteDir) {
  return {
    isFile: function (rel) {
      try { return fs.statSync(path.join(siteDir, rel)).isFile(); } catch (e) { return false; }
    },
    isDir: function (rel) {
      try { return fs.statSync(path.join(siteDir, rel)).isDirectory(); } catch (e) { return false; }
    }
  };
}

function verdict(status, reason, data) {
  return Object.assign({ status: status, reason: reason || null }, data || {});
}

/* opts.anchors: 'fail' (default) or 'warn'. */
function check(siteDir, opts) {
  opts = opts || {};
  var anchorMode = opts.anchors === 'warn' ? 'warn' : 'fail';
  var ctl = control();
  if (ctl.bad.length) {
    return verdict('NOT CHECKED', 'the resolver failed its own control (' + ctl.bad.join('; ') +
      '), so no link was judged');
  }
  var st;
  try { st = fs.statSync(siteDir); } catch (e) { st = null; }
  if (!st || !st.isDirectory()) {
    return verdict('NOT CHECKED', siteDir + ' is not a built site directory. Build first ' +
      '(jekyll build -d <dir>) and pass it with --site.');
  }
  var pages = walkHtml(siteDir);
  if (!pages.length) {
    return verdict('NOT CHECKED', '0 HTML pages under ' + siteDir + ', so nothing was checked');
  }
  var fsx = diskFs(siteDir);
  var info = {};
  var stubs = new Set();
  pages.forEach(function (p) {
    var rel = path.relative(siteDir, p).split(path.sep).join('/');
    var text = fs.readFileSync(p, 'utf8');
    var pg = parsePage(text);
    if (/http-equiv\s*=\s*["']?refresh/i.test(text)) stubs.add(rel);
    info[rel] = pg;
  });
  var pagefindPresent = fsx.isDir('pagefind');

  var internal = 0, external = 0, excluded = 0;
  var dead = [];            // {page, url}
  var trailing = [];        // {page, url}
  var fragments = 0, fragmentsSkipped = 0;
  var deadAnchors = [];     // {page, url, target, fragment}

  Object.keys(info).forEach(function (rel) {
    info[rel].links.forEach(function (l) {
      var raw = l.value;
      if (!raw.trim() || raw.charAt(0) === '?') return;
      if (raw.charAt(0) !== '#') {
        if (isExternal(raw)) { external++; return; }
        if (/^\/pagefind/.test(raw) && !pagefindPresent) { excluded++; return; }
        internal++;
        var clean = raw.split('#')[0].split('?')[0];
        if (trailingSlashOnFile(raw, fsx, rel)) trailing.push({ page: rel, url: clean });
        if (resolve(raw, fsx, rel) === null) dead.push({ page: rel, url: clean });
      }
      /* Anchors: <a href> only, with a fragment. */
      if (l.tag !== 'a' || l.attr !== 'href' || raw.indexOf('#') === -1) return;
      if (/^(mailto|tel|javascript|data):/i.test(raw)) return;
      var parts = raw.split('#');
      var pathPart = parts[0];
      var frag = parts.slice(1).join('#');
      try { frag = decodeURIComponent(frag); } catch (e) { /* raw */ }
      if (!frag || frag.indexOf('~:') === 0) return;
      var target;
      if (pathPart.trim()) {
        if (isExternal(pathPart)) return;
        target = resolve(pathPart, fsx, rel);
      } else {
        target = rel;
      }
      if (target === null) return;               // counted as a dead link already
      if (!/\.html?$/i.test(target)) { fragmentsSkipped++; return; }   // no ids to judge a non-HTML target by
      fragments++;
      if (!info[target] || !info[target].ids.has(frag)) {
        deadAnchors.push({ page: rel, url: raw, target: target, fragment: frag });
      }
    });
  });

  if (internal === 0) {
    return verdict('NOT CHECKED', '0 internal links found in ' + pages.length +
      ' pages, so no link was judged');
  }

  var counts = {
    pages: pages.length, internal: internal, external: external, excluded: excluded,
    dead: dead.length, trailing: trailing.length, fragments: fragments,
    fragmentsSkipped: fragmentsSkipped, deadAnchors: deadAnchors.length,
    controlRows: ctl.rows
  };
  var failing = dead.length > 0 || trailing.length > 0 || (anchorMode === 'fail' && deadAnchors.length > 0);
  return verdict(failing ? 'FAIL' : 'PASS', null, {
    counts: counts, dead: dead, trailing: trailing, deadAnchors: deadAnchors, anchorMode: anchorMode
  });
}

module.exports = {
  check: check, control: control, resolve: resolve, trailingSlashOnFile: trailingSlashOnFile,
  parsePage: parsePage, siteRel: siteRel, isExternal: isExternal
};
