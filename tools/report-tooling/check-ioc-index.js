#!/usr/bin/env node
'use strict';

var path = require('node:path');
var fs = require('node:fs');

var ROOT = path.join(__dirname, '..', '..');
var IDX = path.join(ROOT, 'assets', 'data', 'ioc-index.json');

var CK, G, CS;
try {
  CK = require('./lib/check-ioc-index.js');
  G = require('./generate-ioc-index.js');
  CS = require('./lib/catalog-status.js');
} catch (e) {
  console.log('NOT CHECKED  ' + e.message + '. Run `npm ci` in tools/report-tooling.');
  process.exit(2);
}

var doc = null;
try { doc = JSON.parse(fs.readFileSync(IDX, 'utf8')); } catch (e) { doc = null; }

var status, fresh;
try {
  var catText = fs.readFileSync(path.join(ROOT, '_data', 'catalog.yml'), 'utf8');
  var unlisted = G.readUnlisted(path.join(ROOT, 'reports'));
  status = CS.resolve(catText, unlisted).status;
  fresh = G.build(G.readFeeds(path.join(ROOT, 'ioc-feeds')), catText, unlisted);
} catch (e) {
  console.log('NOT CHECKED  could not rebuild the index for comparison: ' + e.message);
  process.exit(2);
}

var r = CK.check(doc, status, fresh);
if (r.status === 'NOT CHECKED') { console.log('NOT CHECKED  ' + r.reason); process.exit(2); }

console.log(r.status + '  ' + IDX + '  (' + Object.keys(doc.indicators).length +
  ' indicators across ' + Object.keys(doc.reports).length + ' reports)');
r.notes.forEach(function (n) { console.log('   note  ' + n); });
r.problems.forEach(function (p) { console.log('   FAIL  ' + p); });
process.exit(r.status === 'PASS' ? 0 : 1);
