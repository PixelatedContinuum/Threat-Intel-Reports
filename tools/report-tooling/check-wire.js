#!/usr/bin/env node
'use strict';

/* CLI for the wire gate. Reads the two data files, prints one verdict, exits
   0 PASS, 1 FAIL, 2 NOT CHECKED.

   Missing dependencies are NOT CHECKED with the remedy named, never a pass. A
   fresh clone has no node_modules, and a gate that silently passed in that state
   would be worse than one that plainly did not run. */

var path = require('node:path');
var fs = require('node:fs');

var ROOT = path.join(__dirname, '..', '..');
var WIRE = path.join(ROOT, '_data', 'wire.yml');
var SOURCES = path.join(ROOT, '_data', 'wire-sources.yml');

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

var doc = load(WIRE);
var srcDoc = load(SOURCES);
var sources = srcDoc && srcDoc.sources ? srcDoc.sources : null;

if (!srcDoc) {
  console.log('note: could not read ' + SOURCES +
    ', so unclassified sources cannot be reported');
}

var r = CW.check(doc, sources, Date.now());

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

process.exit(r.status === 'PASS' ? 0 : 1);
