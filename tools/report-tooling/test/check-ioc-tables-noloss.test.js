'use strict';

/* Design v4 check 5, "IOC tables lose nothing": the no-loss comparison and its
   controls.

   The unit cases pin each reason class, because each one is a way a row can leave
   the table without being a loss, and a gate that cannot tell them apart either
   fails every regeneration or excuses every deletion. The corpus case and the CLI
   case are the controls: a copy of the REAL committed table with one filename row
   and one bare BLOCK address row deleted must FAIL, naming both, while the same
   table compared with itself must PASS.

   The denominator in the corpus case is counted from the file, not written here,
   so a shrinking table cannot make the control quietly unfalsifiable. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var os = require('node:os');
var path = require('node:path');
var cp = require('node:child_process');

var NL = require('../lib/ioc-table-noloss.js');

var ROOT = path.join(__dirname, '..', '..', '..');
var TABLE = path.join(ROOT, '_data', 'ioc_tables.yml');
var CHECKER = path.join(__dirname, '..', 'check-ioc-tables.js');

/* Minimal generated-shape YAML: one entry per feed key, `rows` and
   `never_block_rows` in the six-line row shape the generator writes. */
function table(feeds) {
  var lines = ['# test fixture'];
  Object.keys(feeds).forEach(function (key) {
    var f = feeds[key];
    lines.push(JSON.stringify(key) + ':');
    lines.push('  slug: ' + JSON.stringify(f.slug || key));
    lines.push('  feed_url: "/ioc-feeds/' + (f.file || key) + '"');
    lines.push('  rows:');
    (f.rows || []).forEach(function (r) {
      lines.push('    - type: ' + JSON.stringify(r[0]));
      lines.push('      value: ' + JSON.stringify(r[1]));
      lines.push('      context: null');
      lines.push('      confidence: null');
      lines.push('      action: null');
      lines.push('      fp_risk: null');
    });
    lines.push('  never_block_rows:');
    (f.nb || []).forEach(function (r) {
      lines.push('    - type: ' + JSON.stringify(r[0]));
      lines.push('      value: ' + JSON.stringify(r[1]));
      lines.push('      context: "do not block"');
    });
  });
  return lines.join('\n') + '\n';
}

function compare(before, after, feeds) {
  var map = feeds || {};
  return NL.compare(table(before), table(after), {
    readFeed: function (file) { return map[file] || null; }
  });
}

function keys(rows) {
  return rows.map(function (r) { return r.feed + ' ' + r.type + ' ' + r.value; });
}

var FEED = 'x-iocs.json';
var BASE = {};
BASE[FEED] = { rows: [['ipv4', '198.51.100.7'], ['domain', 'c2.example.test'],
                       ['filename', 'dump2.sh']] };

test('an unchanged table removes nothing', function () {
  var r = compare(BASE, BASE);
  assert.equal(r.removed.length, 0);
  assert.equal(r.unexplained, 0);
  assert.equal(r.before_rows, 3);
  assert.equal(r.after_rows, 3);
});

test('a deleted row with no reason the feed gives is UNEXPLAINED, and names the row', function () {
  var after = JSON.parse(JSON.stringify(BASE));
  after[FEED].rows = after[FEED].rows.filter(function (r) { return r[1] !== 'dump2.sh'; });
  var r = compare(BASE, after);
  assert.equal(r.unexplained, 1, JSON.stringify(r.removed));
  assert.equal(r.removed[0].reason, 'unexplained');
  assert.equal(r.removed[0].value, 'dump2.sh');
  assert.equal(r.removed[0].feed, 'x-iocs.json');
});

test('the same value under another type is a retype, not a loss', function () {
  var after = JSON.parse(JSON.stringify(BASE));
  after[FEED].rows = [['ipv4', '198.51.100.7'], ['domain', 'c2.example.test'],
                      ['filename', 'dump2.sh']].map(function (r) {
    return r[1] === 'c2.example.test' ? ['filename', 'c2.example.test'] : r;
  });
  var r = compare(BASE, after);
  assert.equal(r.unexplained, 0, JSON.stringify(r.removed));
  assert.equal(r.removed[0].reason, 'same-value-other-type');
  assert.match(r.removed[0].detail, /now filename/);
});

test('the same value in another case is allowed and says so', function () {
  var after = JSON.parse(JSON.stringify(BASE));
  after[FEED].rows = [['ipv4', '198.51.100.7'], ['domain', 'C2.Example.Test'],
                      ['filename', 'dump2.sh']];
  var r = compare(BASE, after);
  assert.equal(r.unexplained, 0, JSON.stringify(r.removed));
  assert.equal(r.removed[0].reason, 'same-value-other-case');
});

test('a value the feed lists in non_indicators is allowed', function () {
  var after = JSON.parse(JSON.stringify(BASE));
  after[FEED].rows = after[FEED].rows.filter(function (r) { return r[1] !== '198.51.100.7'; });
  var feeds = {};
  feeds[FEED] = { non_indicators: [{ value: '198.51.100.7', note: 'shared resolver' }] };
  var r = compare(BASE, after, feeds);
  assert.equal(r.unexplained, 0, JSON.stringify(r.removed));
  assert.equal(r.removed[0].reason, 'non-indicators');
});

test('a value the feed lists in explicitly_excluded is allowed', function () {
  var after = JSON.parse(JSON.stringify(BASE));
  after[FEED].rows = after[FEED].rows.filter(function (r) { return r[1] !== '198.51.100.7'; });
  var feeds = {};
  feeds[FEED] = { explicitly_excluded: ['198.51.100.7'] };
  var r = compare(BASE, after, feeds);
  assert.equal(r.unexplained, 0, JSON.stringify(r.removed));
  assert.equal(r.removed[0].reason, 'explicitly-excluded');
});

test('the site report URL the feed records in metadata.reference is allowed', function () {
  var before = {};
  before[FEED] = { rows: [['url', 'https://the-hunters-ledger.com/reports/x/']] };
  var after = {};
  after[FEED] = { rows: [['ipv4', '198.51.100.7']] };
  var feeds = {};
  feeds[FEED] = { metadata: { reference: ['/reports/x/',
                                          'https://the-hunters-ledger.com/reports/x/'] } };
  var r = compare(before, after, feeds);
  assert.equal(r.unexplained, 0, JSON.stringify(r.removed));
  assert.equal(r.removed[0].reason, 'metadata-reference');
});

test('a whole feed withdrawn from the table is reported, not failed', function () {
  var after = { 'y-iocs.json': { rows: [['ipv4', '203.0.113.9']] } };
  var r = compare(BASE, after);
  assert.equal(r.unexplained, 0);
  assert.equal(r.withdrawals.length, 1);
  assert.equal(r.withdrawals[0].rows, 3);
  assert.equal(r.removed[0].reason, 'feed-withdrawn');
});

test('a value moved to never_block_rows is still in the table, so not a removal', function () {
  var after = {};
  after[FEED] = { rows: [['ipv4', '198.51.100.7'], ['filename', 'dump2.sh']],
                  nb: [['domain', 'c2.example.test']] };
  var r = compare(BASE, after);
  assert.equal(r.removed.length, 0, JSON.stringify(r.removed));
});

test('a duplicated row satisfied only once is still reported once', function () {
  var before = {};
  before[FEED] = { rows: [['filename', 'twice.exe'], ['filename', 'twice.exe']] };
  var after = {};
  after[FEED] = { rows: [['filename', 'twice.exe']] };
  var r = compare(before, after);
  assert.equal(r.unexplained, 1, JSON.stringify(r.removed));
});

test('a missing feed file makes the exemption unknown, never automatically safe', function () {
  var after = JSON.parse(JSON.stringify(BASE));
  after[FEED].rows = [];
  var r = compare(BASE, after, {});        // readFeed returns null for every file
  assert.equal(r.unexplained, 3, JSON.stringify(r.removed));
  assert.match(r.removed[0].detail, /no readable feed file/);
});

/* --- the corpus controls ------------------------------------------------- */

var current = fs.readFileSync(TABLE, 'utf8');

/* Removes exactly one six-line row block, matched by type and value. */
function dropRow(text, type, value) {
  var needle = '    - type: "' + type + '"\n      value: "' + value + '"\n';
  var at = text.indexOf(needle);
  assert.notEqual(at, -1, 'the control row is not in the table: ' + type + ' ' + value);
  var end = text.indexOf('\n    - type:', at + needle.length);
  if (end === -1) end = text.indexOf('\n  never_block_total:', at + needle.length);
  assert.notEqual(end, -1, 'could not find the end of the row block');
  return text.slice(0, at) + text.slice(end + 1);
}

function readFeed(file) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, 'ioc-feeds', file), 'utf8'));
}

test('CONTROL: the real table with a filename row and a bare BLOCK address row deleted FAILS, naming both', function () {
  var before = NL.parse(current);
  var beforeRows = Object.keys(before).reduce(function (n, k) {
    return n + before[k].rows.length + before[k].never_block_rows.length;
  }, 0);
  assert.ok(beforeRows > 3000, 'denominator collapsed: ' + beforeRows + ' rows in the real table');

  var text = dropRow(current, 'filename', 'dump2.sh');
  text = dropRow(text, 'ipv4', '79.137.192.3');
  var r = NL.compare(current, text, { readFeed: readFeed });
  assert.equal(r.unexplained, 2, JSON.stringify(r.removed, null, 1));
  assert.deepEqual(keys(r.removed).sort(), [
    'bellamain-turkish-phaas-79-137-192-3-20260516 ipv4 79.137.192.3',
    'opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015 filename dump2.sh'
  ]);
  /* The bare address the control deletes must be a BLOCK row in the real table,
     otherwise the control named a row nobody would have blocked. */
  var feed = readFeed('bellamain-turkish-phaas-79-137-192-3-20260516-iocs.json');
  var blocks = JSON.stringify(feed).match(/"79\.137\.192\.3"[^}]*"BLOCK"/);
  assert.ok(blocks, 'the control address is no longer a BLOCK entry in its feed');
});

test('CONTROL: the same real table compared with itself PASSES', function () {
  var r = NL.compare(current, current, { readFeed: readFeed });
  assert.equal(r.removed.length, 0);
  assert.equal(r.before_feeds, r.after_feeds);
  assert.ok(r.before_rows > 3000, 'denominator collapsed');
});

test('CONTROL (end to end): the CLI exits 1 on the deleted copy and 0 on the intact one', function () {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ioc-noloss-'));
  var intact = path.join(dir, 'intact.yml');
  var control = path.join(dir, 'control.yml');
  fs.writeFileSync(intact, current, 'utf8');
  var text = dropRow(current, 'filename', 'dump2.sh');
  text = dropRow(text, 'ipv4', '79.137.192.3');
  fs.writeFileSync(control, text, 'utf8');

  function run(args) {
    return cp.spawnSync(process.execPath, [CHECKER].concat(args), {
      cwd: ROOT, encoding: 'utf8', timeout: 120000
    });
  }

  var bad = run(['--against', intact, '--after', control]);
  assert.equal(bad.status, 1, 'the CLI must FAIL on a copy that lost two rows. stdout:\n' +
    bad.stdout + '\nstderr:\n' + bad.stderr);
  assert.match(bad.stdout, /dump2\.sh/);
  assert.match(bad.stdout, /79\.137\.192\.3/);
  assert.match(bad.stdout, /UNEXPLAINED/);

  var good = run(['--against', intact, '--after', intact]);
  assert.equal(good.status, 0, 'the CLI must PASS when nothing was removed. stdout:\n' +
    good.stdout + '\nstderr:\n' + good.stderr);
  assert.match(good.stdout, /removed 0 rows/);

  fs.rmSync(dir, { recursive: true, force: true });
});
