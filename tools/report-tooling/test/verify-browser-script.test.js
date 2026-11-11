'use strict';

/* T-0603 A58: the default `npm run verify:browser` must reach every gate and exit with the worst class
   (1 FAIL, then 2 NOT CHECKED, then 0), and its Wire step must drive a built site, because the default
   (LIVE) mode of check-browser-wire.js expects the old flat Wire list and returns NOT CHECKED on the
   three-tab page. No browser is launched here: the three gate commands are replaced by `(exit N)`. */

var test = require('node:test');
var assert = require('node:assert');
var cp = require('node:child_process');
var path = require('node:path');
var pkg = require('../package.json');

var SCRIPT = pkg.scripts['verify:browser'];

test('the Wire step is given a built site by default, and the gates are not chained with &&', function () {
  assert.match(SCRIPT, /HL_SITE_DIR=\$\{HL_SITE_DIR:-\.\.\/\.\.\/_site\} node check-browser-wire\.js/);
  ['check-browser-wire.js', 'check-browser-report.js', 'check-browser-downloads.js'].forEach(function (g) {
    assert.ok(SCRIPT.indexOf(g) > -1, g);
  });
  assert.doesNotMatch(SCRIPT.replace(/\|\|/g, ''), /check-browser-[a-z]+\.js\s*&&/);
});

function exitOf(w, r, d) {
  var s = SCRIPT.replace(/HL_SITE_DIR=\S+ node check-browser-wire\.js/, '(exit ' + w + ')')
    .replace('node check-browser-report.js', '(exit ' + r + ')')
    .replace('node check-browser-downloads.js', '(exit ' + d + ')');
  return cp.spawnSync('sh', ['-c', s], { cwd: path.join(__dirname, '..') }).status;
}

test('every gate runs and the worst class wins: FAIL over NOT CHECKED over PASS', function () {
  assert.equal(exitOf(0, 0, 0), 0);
  assert.equal(exitOf(2, 0, 0), 2, 'a NOT CHECKED first step no longer stops the chain');
  assert.equal(exitOf(2, 1, 0), 1, 'a later FAIL outranks the first step\'s NOT CHECKED');
  assert.equal(exitOf(0, 0, 1), 1);
  assert.equal(exitOf(0, 2, 2), 2);
  assert.equal(exitOf(1, 2, 0), 1);
});
