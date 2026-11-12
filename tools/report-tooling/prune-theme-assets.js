#!/usr/bin/env node
'use strict';

/* Prune the remote theme's unused static files from a BUILT site, then prove nothing points at them (T-0605 L02).

     node prune-theme-assets.js --site <_site> [--source <repo root>] [--scope assets/js,assets/fonts] [--removed-out FILE] [--dry-run]
     node prune-theme-assets.js --site <_site> --verify <removed list>   (the reference check alone)

   --scope  the folders (under the site root, comma separated) whose theme-only files may be removed; default assets/js,assets/fonts.
            Theme-only files elsewhere under assets/ (demo images, data) are counted and left alone: they are other work.

   The remote theme (sylhare/Type-on-Strap) copies its whole assets/ tree into the build: KaTeX, Mermaid, Font Awesome, Pacifico and
   other fonts, search scripts. KaTeX and Mermaid are off in _config.yml and no layout of ours loads the rest.

   What is removed is decided by measuring, not by a name list. A CANDIDATE is a file under <site>/assets/ with no file at the same
   path in the source tree (so it came from the theme, or was generated from a source file). A candidate is KEPT when a reference to it is
   found in a kept file, to a fixed point:
     roots       every built .html page, and every built .css and .js file under assets/ that is not a candidate
     references  html: href, src, srcset, data-* and content attribute values, inline url(), inline <script> and <style> text
                 css:  url(...) and @import
                 js:   every quoted string (a path built from pieces is not seen; the string pieces still are)
     a reference matches a candidate when it resolves to its path (root-relative, or relative to the referencing file), or, for a js
     string, when the string is a path suffix of the candidate or its base name. A kept candidate that is css or js is scanned too, so
     a font named only by main.css is kept while main.css is.
   Everything else is removed. The same pass then re-reads every page and kept stylesheet and FAILS when any reference resolves to a
   removed path. It prints its denominators and the bytes before and after.

   Exit 0 PASS, 1 FAIL (a reference to a removed file), 2 NOT CHECKED (no site, no pages, no candidates scanned). Pure Node. */

var fs = require('node:fs');
var path = require('node:path');

var TEXT_EXT = { '.html': 1, '.css': 1, '.js': 1, '.mjs': 1 };

function walk(dir, out) {
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (e) {
    var p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (e.isFile()) out.push(p);
  });
  return out;
}

function ext(p) { return path.extname(p).toLowerCase(); }

/* Raw reference strings found in one file's text. */
function refsOf(text, kind, noStrings) {
  var refs = [], m;
  function add(s, isString) {
    s = (s || '').trim();
    if (!s || s.length > 400) return;
    refs.push({ s: s, str: !!isString });
  }
  var re;
  if (kind === 'html') {
    re = /\b(?:href|src|data-[\w-]+|content|poster|action|srcset)\s*=\s*(?:"([^"]*)"|'([^']*)')/gi;
    while ((m = re.exec(text))) {
      var v = m[1] !== undefined ? m[1] : m[2];
      if (/srcset/i.test(m[0].slice(0, 8))) v.split(',').forEach(function (c) { add(c.trim().split(/\s+/)[0]); });
      else add(v);
    }
  }
  // url(...) and @import in css, in an html <style> or in a style attribute
  re = /url\(\s*(?:"([^"]*)"|'([^']*)'|([^)\s]*))\s*\)/gi;
  while ((m = re.exec(text))) add(m[1] !== undefined ? m[1] : (m[2] !== undefined ? m[2] : m[3]));
  re = /@import\s+(?:url\()?\s*(?:"([^"]*)"|'([^']*)')/gi;
  while ((m = re.exec(text))) add(m[1] !== undefined ? m[1] : m[2]);
  // every quoted string in a script (js files, and <script> text in a page)
  if (!noStrings && (kind === 'js' || kind === 'html')) {
    re = /(["'`])((?:\\.|(?!\1)[^\\\n]){1,300})\1/g;
    while ((m = re.exec(text))) add(m[2], true);
  }
  return refs;
}

function normRef(r) {
  return r.replace(/[?#].*$/, '').replace(/\\\//g, '/');
}

/* The reference check, by a different primitive from the scan above: raw text, not parsed references. A removed file counts as referenced
   when its site path appears in a page or stylesheet, or its base name appears right after a quote, "/", "(" or "=" (the places a load
   names a file). `removed` is a list of site-relative paths (no leading slash). */
function verify(site, removed, pages, others) {
  var readers = pages.concat(others).filter(function (f) { return ext(f) === '.html' || ext(f) === '.css'; });
  var bad = [];
  var names = removed.map(function (r) { return { rel: r, base: r.split('/').pop() }; });
  readers.forEach(function (f) {
    var text = fs.readFileSync(f, 'utf8');
    names.forEach(function (n) {
      var hit = text.indexOf('/' + n.rel) !== -1;
      if (!hit) {
        var at = text.indexOf(n.base);
        while (at !== -1 && !hit) {
          if (at > 0 && '"\'/(=`'.indexOf(text.charAt(at - 1)) !== -1) hit = true;
          at = text.indexOf(n.base, at + 1);
        }
      }
      if (hit) bad.push(path.relative(site, f) + ' -> ' + n.rel);
    });
  });
  return { bad: bad, files: readers.length, names: names.length };
}

function run(opts) {
  var site = path.resolve(opts.site);
  var source = opts.source ? path.resolve(opts.source) : null;
  var out = { status: 'PASS', lines: [], problems: [] };
  function say(s) { out.lines.push(s); }

  if (!fs.existsSync(path.join(site, 'assets'))) {
    out.status = 'NOT CHECKED'; say('NOT CHECKED  ' + site + '/assets does not exist'); return out;
  }
  var files = walk(site, []);
  var pages = files.filter(function (f) { return ext(f) === '.html'; });
  if (!pages.length) { out.status = 'NOT CHECKED'; say('NOT CHECKED  no .html page under ' + site); return out; }

  var assetsDir = path.join(site, 'assets') + path.sep;
  var assetFiles = files.filter(function (f) { return f.indexOf(assetsDir) === 0; });
  function inSource(f) {
    if (!source) return false;
    var rel = path.relative(site, f);
    return fs.existsSync(path.join(source, rel));
  }
  var scope = (opts.scope || ['assets/js', 'assets/fonts']).map(function (d) { return path.join(site, d) + path.sep; });
  var outOfScope = 0, outOfScopeBytes = 0;
  var candidates = Object.create(null), ownText = [];
  assetFiles.forEach(function (f) {
    var inScope = scope.some(function (d) { return f.indexOf(d) === 0; });
    if (!inSource(f) && !inScope) {
      outOfScope++; outOfScopeBytes += fs.statSync(f).size;
      if (TEXT_EXT[ext(f)] && ext(f) !== '.html') ownText.push(f);
      return;
    }
    if (inSource(f)) { if (TEXT_EXT[ext(f)] && ext(f) !== '.html') ownText.push(f); return; }
    candidates[f] = { bytes: fs.statSync(f).size, kept: false, why: null };
  });
  var candList = Object.keys(candidates);
  if (!candList.length) { out.status = 'NOT CHECKED'; say('NOT CHECKED  no theme-only file under assets/ (nothing to measure against)'); return out; }

  // site paths of candidates for matching
  var byUrl = Object.create(null), byBase = Object.create(null);
  candList.forEach(function (f) {
    var url = '/' + path.relative(site, f).split(path.sep).join('/');
    byUrl[url] = f;
    var b = path.basename(f);
    (byBase[b] = byBase[b] || []).push(f);
  });

  function markFromRef(ref, fromFile, kind, queue) {
    var raw = ref.s, isStr = ref.str;
    var r = normRef(raw);
    if (!r || /^(?:data:|mailto:|tel:|javascript:|#)/i.test(r)) return;
    var hits = [];
    if (/^https?:\/\//i.test(r)) {
      // an absolute URL on our own host would resolve; any other host is not ours
      return;
    }
    var url;
    if (r.charAt(0) === '/') url = r;
    else if (/[\/.]/.test(r)) url = '/' + path.relative(site, path.resolve(path.dirname(fromFile), r)).split(path.sep).join('/');
    if (url && byUrl[url]) hits.push(byUrl[url]);
    if (isStr && r.indexOf('/') !== -1) {
      // a js string that is a path suffix of a candidate (a base path joined at run time)
      candList.forEach(function (f) {
        var u = '/' + path.relative(site, f).split(path.sep).join('/');
        if (r.length > 3 && u.endsWith(r.charAt(0) === '/' ? r : '/' + r.replace(/^\.\//, ''))) hits.push(f);
      });
    }
    if (isStr) {
      var b = r.split('/').pop();
      if (byBase[b]) byBase[b].forEach(function (f) { hits.push(f); });
    }
    hits.forEach(function (f) {
      if (!candidates[f].kept) { candidates[f].kept = true; candidates[f].why = path.relative(site, fromFile); queue.push(f); }
    });
  }

  var scanned = { html: 0, css: 0, js: 0 }, refCount = 0;
  function scan(f, queue) {
    var k = ext(f) === '.html' ? 'html' : (ext(f) === '.css' ? 'css' : 'js');
    var text = fs.readFileSync(f, 'utf8');
    var refs = refsOf(text, k);
    scanned[k]++; refCount += refs.length;
    refs.forEach(function (r) { markFromRef(r, f, k, queue); });
  }
  var queue = [];
  pages.forEach(function (f) { scan(f, queue); });
  ownText.forEach(function (f) { scan(f, queue); });
  while (queue.length) {
    var f = queue.pop();
    if (TEXT_EXT[ext(f)]) scan(f, queue);
  }

  var keep = candList.filter(function (f) { return candidates[f].kept; });
  var drop = candList.filter(function (f) { return !candidates[f].kept; });
  function sum(list) { return list.reduce(function (a, f) { return a + candidates[f].bytes; }, 0); }
  var totalAssets = assetFiles.reduce(function (a, f) { return a + fs.statSync(f).size; }, 0);
  say('prune-theme-assets  site ' + site);
  say('  scanned     ' + pages.length + ' pages, ' + scanned.css + ' css and ' + scanned.js + ' js files (own: ' + ownText.length + ' + kept theme files), ' + refCount + ' reference strings');
  say('  assets      ' + assetFiles.length + ' files, ' + totalAssets + ' bytes; ' + candList.length + ' theme-only candidates, ' + sum(candList) + ' bytes');
  say('  not in scope  ' + outOfScope + ' theme-only or generated files outside ' + scope.map(function (d) { return path.relative(site, d); }).join(', ') + ', ' + outOfScopeBytes + ' bytes, left alone (css and js among them are scanned as roots)');
  say('  kept        ' + keep.length + ' candidates, ' + sum(keep) + ' bytes');
  keep.sort().forEach(function (f) { say('    keep ' + path.relative(site, f) + '  (' + candidates[f].bytes + ' B, first seen in ' + candidates[f].why + ')'); });
  say('  removed     ' + drop.length + ' files, ' + sum(drop) + ' bytes' + (opts.dryRun ? '  (dry run: nothing deleted)' : ''));
  // removed by top-level folder, so a reader sees what went
  var groups = {};
  drop.forEach(function (f) {
    var rel = path.relative(site, f).split(path.sep), g = rel.slice(0, Math.min(rel.length - 1, 3)).join('/') || rel[0];
    groups[g] = groups[g] || { n: 0, b: 0 }; groups[g].n++; groups[g].b += candidates[f].bytes;
  });
  Object.keys(groups).sort().forEach(function (g) { say('    drop ' + g + '/  ' + groups[g].n + ' files, ' + groups[g].b + ' bytes'); });

  var removedUrls = Object.create(null);
  drop.forEach(function (f) { removedUrls['/' + path.relative(site, f).split(path.sep).join('/')] = true; });
  if (!opts.dryRun) {
    drop.forEach(function (f) { fs.unlinkSync(f); });
    // remove directories left empty
    walk(path.join(site, 'assets'), []);
    (function rmEmpty(d) {
      fs.readdirSync(d, { withFileTypes: true }).forEach(function (e) { if (e.isDirectory()) rmEmpty(path.join(d, e.name)); });
      if (d !== site && !fs.readdirSync(d).length) fs.rmdirSync(d);
    })(path.join(site, 'assets'));
  }

  if (opts.removedOut) fs.writeFileSync(opts.removedOut, drop.map(function (f) { return path.relative(site, f).split(path.sep).join('/'); }).sort().join('\n') + '\n');
  var vr = verify(site, Object.keys(removedUrls).map(function (u) { return u.slice(1); }), pages, ownText.concat(keep));
  var bad = vr.bad;
  say('  reference check  ' + vr.files + ' pages and stylesheets read as raw text, ' + vr.names + ' removed paths searched; ' + bad.length + ' reference(s) to a removed path');
  bad.slice(0, 20).forEach(function (b) { say('    FAIL  ' + b); out.problems.push(b); });
  if (bad.length) out.status = 'FAIL';
  out.stats = { pages: pages.length, candidates: candList.length, kept: keep.length, removed: drop.length, removedBytes: sum(drop), broken: bad.length };
  return out;
}

if (require.main === module) {
  var args = process.argv.slice(2);
  var opt = function (n) { var i = args.indexOf(n); return i === -1 ? null : args[i + 1]; };
  var site = opt('--site');
  if (!site) { console.log('NOT CHECKED  --site <_site dir> is required'); process.exit(2); }
  if (opt('--verify')) {
    // reference check alone, against a list of removed site paths (one per line) written by --removed-out
    var list = fs.readFileSync(opt('--verify'), 'utf8').split('\n').filter(Boolean);
    var pg = walk(path.resolve(site), []);
    var v = verify(path.resolve(site), list, pg.filter(function (f) { return ext(f) === '.html'; }), pg.filter(function (f) { return ext(f) === '.css'; }));
    console.log('reference check  ' + v.files + ' pages and stylesheets read, ' + v.names + ' removed paths searched; ' + v.bad.length + ' reference(s) to a removed path');
    v.bad.slice(0, 20).forEach(function (b) { console.log('  FAIL  ' + b); });
    var st = !list.length || !v.files ? 'NOT CHECKED' : (v.bad.length ? 'FAIL' : 'PASS');
    console.log(st);
    process.exit(st === 'PASS' ? 0 : st === 'FAIL' ? 1 : 2);
  }
  var r = run({ site: site, source: opt('--source') || path.join(__dirname, '..', '..'), dryRun: args.indexOf('--dry-run') !== -1, removedOut: opt('--removed-out'), scope: opt('--scope') ? opt('--scope').split(',') : null });
  r.lines.forEach(function (l) { console.log(l); });
  console.log(r.status);
  process.exit(r.status === 'PASS' ? 0 : r.status === 'FAIL' ? 1 : 2);
}

module.exports = { run: run, verify: verify, refsOf: refsOf };
