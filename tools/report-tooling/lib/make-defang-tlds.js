#!/usr/bin/env node
'use strict';
/* HL-TOOLING: writes _data/defang_tlds.yml (the TLD lookup table _includes/defang-text.html reads) from data/iana-tlds.txt, the snapshot check-defang.js reads.
   node tools/report-tooling/lib/make-defang-tlds.js > _data/defang_tlds.yml */
var D = require('../check-defang.js');
var fs = require('node:fs'), path = require('node:path');
var t = D.getTlds();
var names = Object.keys(t.set).sort();
var head = fs.readFileSync(path.join(__dirname, '..', 'data', 'iana-tlds.txt'), 'utf8').split(/\r?\n/)[0].replace(/^#\s*/, '');
var out = [
  '# The DNS root zone as a lookup table for _includes/defang-text.html (T-0500.1.7.4). Liquid has no regular expressions, so the include splits a word on "." and',
  '# asks whether the last label is a key here. GENERATED from tools/report-tooling/data/iana-tlds.txt (the same dated snapshot check-defang.js reads) plus the',
  '# special-use names it adds (onion, i2p); test/defang-render.test.js fails if the two drift. Refresh the snapshot by hand, then regenerate this file with',
  '#   node tools/report-tooling/lib/make-defang-tlds.js > _data/defang_tlds.yml',
  '# Snapshot: ' + head
];
names.forEach(function (n) { out.push('"' + n + '": 1'); });
process.stdout.write(out.join('\n') + '\n');
