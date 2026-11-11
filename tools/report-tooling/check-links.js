#!/usr/bin/env node
'use strict';

/* CLI for the post-build link and anchor gate. Reads a BUILT site directory, never the source.

     node check-links.js [--site <dir>] [--anchors fail|warn] [--all] [--json]

   --site     the built site (default: <repo>/_site)
   --anchors  fail (default) counts a `#fragment` that matches no id on its target page as a
              failure; warn prints them and does not fail the run
   --all      list every offender (default: the first 20 of each kind, with the count)

   Exit 0 PASS, 1 FAIL, 2 NOT CHECKED. Pure Node, no third-party dependency. */

var path = require('node:path');
var CL = require('./lib/check-links.js');

var args = process.argv.slice(2);
function opt(name) {
  var i = args.indexOf(name);
  return i === -1 ? null : args[i + 1];
}
var site = path.resolve(opt('--site') || path.join(__dirname, '..', '..', '_site'));
var anchors = opt('--anchors') || 'fail';
if (anchors !== 'fail' && anchors !== 'warn') {
  console.log('NOT CHECKED  --anchors takes fail or warn, got "' + anchors + '"');
  process.exit(2);
}
var all = args.indexOf('--all') !== -1;
var asJson = args.indexOf('--json') !== -1;

var r = CL.check(site, { anchors: anchors });

if (asJson) {
  console.log(JSON.stringify(r, null, 2));
  process.exit(r.status === 'PASS' ? 0 : r.status === 'FAIL' ? 1 : 2);
}
if (r.status === 'NOT CHECKED') {
  console.log('NOT CHECKED  ' + r.reason);
  process.exit(2);
}
var c = r.counts;
console.log(r.status + '  ' + site + '  (' + c.pages + ' pages, ' + c.internal +
  ' internal links, ' + c.fragments + ' fragment links; control ' + c.controlRows + '/' +
  c.controlRows + ' rows held)');
console.log('   dead links              ' + c.dead + ' of ' + c.internal + ' internal links');
console.log('   slash on a file         ' + c.trailing + ' of ' + c.internal + ' internal links' +
  '  (GitHub Pages 404s /x.json/ even when x.json exists)');
console.log('   dead #anchors           ' + c.deadAnchors + ' of ' + c.fragments + ' fragment links' +
  (anchors === 'warn' ? '  (warn only)' : ''));
console.log('   not judged              ' + c.external + ' external, ' + c.excluded +
  ' /pagefind (no bundle in this build), ' + c.fragmentsSkipped + ' fragment link(s) to a non-HTML target');

function list(label, rows, fmt) {
  if (!rows.length) return;
  var shown = all ? rows : rows.slice(0, 20);
  shown.forEach(function (x) { console.log('   ' + label + '  ' + fmt(x)); });
  if (shown.length < rows.length) {
    console.log('   ... ' + (rows.length - shown.length) + ' more ' + label + ' (use --all)');
  }
}
list('FAIL dead', r.dead, function (x) { return x.url + '  on ' + x.page; });
list('FAIL slash-on-file', r.trailing, function (x) { return x.url + '  on ' + x.page; });
list(anchors === 'warn' ? 'WARN anchor' : 'FAIL anchor', r.deadAnchors,
  function (x) { return x.url + ' (no id "' + x.fragment + '" in ' + x.target + ')  on ' + x.page; });

process.exit(r.status === 'PASS' ? 0 : 1);
