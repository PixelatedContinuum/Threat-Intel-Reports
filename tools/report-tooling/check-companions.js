#!/usr/bin/env node
'use strict';

/* CLI for the report companion-value gate: do `detection_page`, `ioc_feed` and `stix_bundle`
   in each reports/<slug>/index.md name something that exists? Source tree only, no build.

     node check-companions.js [--root <repo>]

   Exit 0 PASS, 1 FAIL, 2 NOT CHECKED. */

var path = require('node:path');

var yaml, CC;
try {
  yaml = require('js-yaml');
  CC = require('./lib/check-companions.js');
} catch (e) {
  console.log('NOT CHECKED  ' + e.message + '. Run `npm ci` in tools/report-tooling, then re-run this gate.');
  process.exit(2);
}

var args = process.argv.slice(2);
var i = args.indexOf('--root');
var root = path.resolve(i === -1 ? path.join(__dirname, '..', '..') : args[i + 1]);

var r;
try { r = CC.check(CC.diskReader(root, yaml), yaml); }
catch (e) {
  console.log('NOT CHECKED  cannot read ' + root + ': ' + e.message);
  process.exit(2);
}

if (r.status === 'NOT CHECKED') {
  console.log('NOT CHECKED  ' + r.reason);
  process.exit(2);
}
console.log(r.status + '  ' + root + '  (' + r.counts.values + ' companion values in ' +
  r.counts.withValues + ' of ' + r.counts.reports + ' report files, resolved against ' + r.counts.permalinks + ' source permalinks; ' + r.counts.viaRedirect +
  ' only through a redirect_from stub)');
r.problems.forEach(function (p) { console.log('   FAIL  ' + p); });
process.exit(r.status === 'PASS' ? 0 : 1);
