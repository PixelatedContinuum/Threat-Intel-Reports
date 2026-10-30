'use strict';

/* Which report markdown a CLI was pointed at (T-0500.1.9, audit W04, I03, R01).

   The three authoring proposers (propose-tabs, propose-figure-nav, propose-tiers)
   used to take only a folder name under this checkout's reports/. A NEW report
   exists only in threat-intel-vault/reports/<slug>/ until it is staged, so the
   tools could not see it. Two forms now work:

     path   anything with a path separator, or ending in .md: the file itself, or
            a folder holding an index.md. The vault copy is such a path.
     name   a bare folder name under this checkout's reports/ (the old form).

   resolveTarget() returns { mode, slug, file } or { error }. It never guesses: a
   path that does not exist is an error naming the absolute path it looked at,
   not a fall back to the corpus. */

var fs = require('node:fs');
var path = require('node:path');

function looksLikePath(arg) {
  return /[\\/]/.test(arg) || /\.md$/i.test(arg);
}

function resolveTarget(arg, reportsDir, cwd) {
  cwd = cwd || process.cwd();
  if (!arg) return { error: 'no report named' };
  if (!looksLikePath(arg)) {
    var dir = path.join(reportsDir, arg);
    if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
      return { error: 'no report directory named ' + arg + ' under ' + reportsDir };
    }
    return { mode: 'name', slug: arg, file: path.join(dir, 'index.md') };
  }
  var abs = path.resolve(cwd, arg);
  if (!fs.existsSync(abs)) return { error: 'no such file or folder: ' + abs };
  var file = abs;
  if (fs.statSync(abs).isDirectory()) file = path.join(abs, 'index.md');
  if (!fs.existsSync(file)) return { error: 'no index.md in ' + abs };
  var slug = path.basename(path.dirname(file));
  if (path.basename(file) !== 'index.md') slug = path.basename(file, '.md');
  return { mode: 'path', slug: slug, file: file };
}

module.exports = { resolveTarget: resolveTarget, looksLikePath: looksLikePath };
