#!/usr/bin/env node
'use strict';

/* CLI for the wire gate. Reads the two data files, prints one verdict, exits
   0 PASS, 1 FAIL, 2 NOT CHECKED.

   Missing dependencies are NOT CHECKED with the remedy named, never a pass. A
   fresh clone has no node_modules, and a gate that silently passed in that state
   would be worse than one that plainly did not run. */

var path = require('node:path');
var fs = require('node:fs');
var cp = require('node:child_process');

var ROOT = path.join(__dirname, '..', '..');
var WIRE = path.join(ROOT, '_data', 'wire.yml');
var SOURCES = path.join(ROOT, '_data', 'wire-sources.yml');
var PAGE = path.join(ROOT, 'wire', 'index.md');

var yaml, CW;
try {
  yaml = require('js-yaml');
  CW = require('./lib/check-wire.js');
} catch (e) {
  console.log('NOT CHECKED  ' + e.message +
    '. Run `npm ci` in tools/report-tooling, then re-run this gate.');
  process.exit(2);
}

function load(p) {
  try { return yaml.load(fs.readFileSync(p, 'utf8')); }
  catch (e) { return null; }
}

/* What origin holds, which is the only thing that can say whether an old local
   wire.yml means a stopped generator or just a checkout nobody pulled.

   Always origin/main, never the current upstream: the generator pushes there
   and nowhere else, so a publish worktree on its own branch still has to ask
   main. Returns null on any failure, and null means unknown, never healthy.
   Set WIRE_GATE_NO_FETCH=1 to read the ref already in the clone without going
   to the network, which is what a CI job on a fresh clone wants. */
function remoteWire() {
  if (!process.env.WIRE_GATE_NO_FETCH) {
    try {
      cp.execFileSync('git', ['fetch', 'origin', 'main', '--quiet'],
        { cwd: ROOT, stdio: 'ignore', timeout: 30000 });
    } catch (e) {
      return null; // offline, no remote, or an auth prompt: origin is unknown
    }
  }
  try {
    var out = cp.execFileSync('git', ['show', 'origin/main:_data/wire.yml'],
      { cwd: ROOT, encoding: 'utf8', timeout: 30000, maxBuffer: 32 * 1024 * 1024 });
    var m = /^generated_at:[ \t]*(\S+)/m.exec(out);
    return m ? { generated_at: m[1] } : null;
  } catch (e) {
    return null;
  }
}

var doc = load(WIRE);
var srcDoc = load(SOURCES);
var sources = srcDoc && srcDoc.sources ? srcDoc.sources : null;

if (!srcDoc) {
  console.log('note: could not read ' + SOURCES +
    ', so unclassified sources cannot be reported');
}

var r = CW.check(doc, sources, Date.now(), remoteWire());

if (r.status === 'NOT CHECKED') {
  console.log('NOT CHECKED  ' + r.reason);
  process.exit(2);
}

var head = r.status + '  ' + WIRE;
if (r.counts) {
  head += '  (' + r.counts.total + ' items: ' + r.counts.research +
    ' research, ' + r.counts.news + ' news)';
}
console.log(head);

r.problems.forEach(function (p) { console.log('   FAIL  ' + p); });
if (r.warnings.length) {
  console.log('   WARN  unclassified source(s), add to _data/wire-sources.yml: ' +
    r.warnings.join(', '));
}

/* The data is only half of it. The page decides how each row's day is derived,
   and the day filter is only correct while that derivation happens once. */
var pageSrc = null;
try { pageSrc = fs.readFileSync(PAGE, 'utf8'); } catch (e) { pageSrc = null; }
var p = CW.checkPage(pageSrc);
console.log(p.status + '  ' + PAGE + (p.status === 'PASS' ? '  (day derived once, cache-bust present)' : ''));
if (p.reason) console.log('   ' + p.reason);
p.problems.forEach(function (x) { console.log('   FAIL  ' + x); });

if (r.status === 'PASS' && p.status === 'PASS') process.exit(0);
// NOT CHECKED on the page alone is not a pass, and is not a FAIL either.
if (r.status === 'PASS' && p.status === 'NOT CHECKED') process.exit(2);
process.exit(1);
