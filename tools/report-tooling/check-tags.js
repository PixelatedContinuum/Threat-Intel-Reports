#!/usr/bin/env node
'use strict';

/* CLI for the catalog tag gate. Reads _data/catalog.yml and _data/tags.yml,
   prints one verdict, exits 0 PASS, 1 FAIL, 2 NOT CHECKED.

   Missing dependencies are NOT CHECKED with the remedy named, never a pass. A
   fresh clone has no node_modules, and a gate that silently passed in that state
   would be worse than one that plainly did not run. */

var path = require('node:path');
var fs = require('node:fs');

var ROOT = path.join(__dirname, '..', '..');
var CATALOG = path.join(ROOT, '_data', 'catalog.yml');
var TAGS = path.join(ROOT, '_data', 'tags.yml');

var yaml, CT;
try {
  yaml = require('js-yaml');
  CT = require('./lib/check-tags.js');
} catch (e) {
  console.log('NOT CHECKED  ' + e.message +
    '. Run `npm ci` in tools/report-tooling, then re-run this gate.');
  process.exit(2);
}

function load(p) {
  try { return yaml.load(fs.readFileSync(p, 'utf8')); }
  catch (e) { return null; }
}

var r = CT.check(load(CATALOG), load(TAGS));

if (r.status === 'NOT CHECKED') {
  console.log('NOT CHECKED  ' + r.reason);
  process.exit(2);
}

var head = r.status + '  ' + CATALOG + ' against ' + TAGS;
if (r.counts) {
  head += '  (' + r.counts.entries + ' entries, ' + r.counts.tags + ' tags, ' +
    r.counts.unknown + ' unknown)';
}
console.log(head);

r.problems.forEach(function (p) { console.log('   FAIL  ' + p); });
r.warnings.forEach(function (w) { console.log('   WARN  ' + w); });

process.exit(r.status === 'PASS' ? 0 : 1);
