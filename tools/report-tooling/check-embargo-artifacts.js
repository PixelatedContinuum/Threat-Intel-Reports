'use strict';
/* Refuses to let an embargoed campaign's IOC feed exist in this repo.

   Why this exists. On 2026-09-08 the IOC feed for a campaign held pending a CERT reply, with 130
   victims behind that channel, was found committed and served from this PUBLIC repository, and
   had been since 2026-08-12. The report page carried `unlisted: true` and four guards; the JSON
   had none of them, because a static file has no front matter and no HTML head, so noindex is
   impossible on GitHub Pages. The publish docs described it as private "purely by withholding
   the catalog ioc_url plus having no public link", which is obscurity, and obscurity is not a
   control on a repository anyone can browse.

   The distinction this gate turns on, and it is the whole design. A PREVIEW is unlisted and on
   its way public within days, and a sponsor is explicitly entitled to see it: early access to the
   report, its detection rules and its IOC feed is a sold benefit on both tier cards. An EMBARGO
   is held indefinitely because a disclosure channel is still open. Both looked identical to the
   machinery before this, which is the root cause. `embargo: true` is the new signal, and this
   gate is the enforcement.

   Scope is deliberately narrow. It fires only on `embargo: true`, so ordinary previews and
   sponsor early access are untouched.

   Exit codes match the sibling gates in this directory:
     0  PASS         no embargoed report has an IOC feed in the repo
     1  FAIL         at least one does
     2  NOT CHECKED  something could not be determined; never folded into PASS
*/
var fs = require('node:fs');
var path = require('node:path');
var cp = require('node:child_process');

var REPO = path.resolve(__dirname, '..', '..');
var REPORTS = path.join(REPO, 'reports');
var FEEDS = path.join(REPO, 'ioc-feeds');

function frontMatter(file) {
  var text;
  try { text = fs.readFileSync(file, 'utf8'); } catch (e) { return null; }
  var m = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (!m) return null;
  var out = {};
  m[1].split(/\r?\n/).forEach(function (line) {
    var kv = /^([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$/.exec(line);
    if (kv) out[kv[1]] = kv[2].trim();
  });
  return out;
}

/* Slug from the report's own permalink, the same derivation catalog-status.js uses for the
   ioc_url basename. Deriving it from the directory name instead would drift the day a permalink
   and a directory disagree, and a silent drift here leaks an embargoed campaign. */
function slugFromPermalink(fm) {
  if (!fm || !fm.permalink) return null;
  var p = String(fm.permalink).replace(/^["']|["']$/g, '').replace(/\/+$/, '');
  var parts = p.split('/').filter(Boolean);
  return parts.length ? parts[parts.length - 1] : null;
}

function isTracked(rel) {
  try {
    cp.execFileSync('git', ['-C', REPO, 'ls-files', '--error-unmatch', rel],
      { stdio: 'ignore' });
    return true;
  } catch (e) { return false; }
}

var dirs = [];
try {
  dirs = fs.readdirSync(REPORTS, { withFileTypes: true })
    .filter(function (d) { return d.isDirectory(); })
    .map(function (d) { return d.name; });
} catch (e) {
  console.log('NOT CHECKED  cannot read ' + path.relative(REPO, REPORTS) + ': ' + e.message);
  process.exit(2);
}

var notChecked = [];
var problems = [];
var embargoed = 0;

dirs.forEach(function (dir) {
  var idx = path.join(REPORTS, dir, 'index.md');
  if (!fs.existsSync(idx)) return;

  var fm = frontMatter(idx);
  if (fm === null) {
    notChecked.push(dir + ': front matter could not be parsed');
    return;
  }
  if (!Object.prototype.hasOwnProperty.call(fm, 'embargo')) return;

  var raw = String(fm.embargo).replace(/^["']|["']$/g, '').toLowerCase();
  if (raw !== 'true' && raw !== 'false') {
    /* A date someone meant as an auto-release, or free text. Guessing what it means is exactly
       how an embargoed campaign leaks, so this is NOT CHECKED rather than a pass. */
    notChecked.push(dir + ': embargo is "' + fm.embargo + '", not a boolean');
    return;
  }
  if (raw === 'false') return;

  embargoed++;
  var slug = slugFromPermalink(fm);
  if (!slug) {
    notChecked.push(dir + ': embargo is true but no permalink, so no IOC filename can be derived');
    return;
  }

  var rel = 'ioc-feeds/' + slug + '-iocs.json';
  var abs = path.join(FEEDS, slug + '-iocs.json');
  if (fs.existsSync(abs) || isTracked(rel)) {
    problems.push(rel + '  (report ' + dir + ' is embargo: true)');
  }
});

if (notChecked.length) {
  console.log('NOT CHECKED  ' + notChecked.length + ' report(s) could not be evaluated');
  notChecked.forEach(function (n) { console.log('   NOT CHECKED  ' + n); });
  console.log('');
  console.log('Resolve each before committing. An unreadable embargo flag is not a pass.');
  process.exit(2);
}

if (problems.length) {
  console.log('FAIL  ' + problems.length + ' embargoed campaign(s) have an IOC feed in this repo');
  problems.forEach(function (p) { console.log('   FAIL  ' + p); });
  console.log('');
  console.log('This repository is PUBLIC. An IOC feed is a static file: it cannot be unlisted,');
  console.log('cannot be noindexed, and is browsable in the repo whatever the site serves.');
  console.log('Keep it in the vault until go-live, then stage it when the embargo lifts:');
  console.log('   git rm --cached <path>   and remove the local copy from this repo');
  process.exit(1);
}

console.log('PASS  ' + dirs.length + ' report(s) scanned, ' + embargoed +
  ' embargoed, none with an IOC feed in the repo');
process.exit(0);
