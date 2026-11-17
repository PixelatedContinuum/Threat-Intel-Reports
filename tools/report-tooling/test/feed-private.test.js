'use strict';

/* T-0662: `metadata.victim_names` (and `victim_names_note`) is vault-only. It must not survive
   the go-live copy, and it must not reach the derived outputs built from a site feed even when
   a feed was copied by hand with the list intact.

   Every absence below has a CONTROL: the same values placed in an ordinary indicator bucket,
   run through the same builder, must appear. Without it, an absence would also be what a
   builder that drops everything looks like. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var os = require('node:os');
var path = require('node:path');

var FP = require('../lib/feed-private.js');
var PF = require('../publish-feed.js');
var IDX = require('../generate-ioc-index.js');
var TBL = require('../lib/ioc-tables.js');

// Values that classify as indicators (a routable IPv4, a domain) plus an organisation name.
var VICTIM_IP = '91.198.44.17';
var VICTIM_DOMAIN = 'acmevictim-intranet.com';
var VICTIM_ORG = 'Acme Victim Holdings';
var NOTE = 'Identifiers withheld from every published surface; the site copy omits them.';

function vaultFeed() {
  return {
    metadata: {
      campaign_slug: 'priv-test',
      tlp: 'CLEAR',
      victim_names: [VICTIM_ORG, VICTIM_DOMAIN, VICTIM_IP],
      victim_names_note: NOTE,
      report_date: '2026-11-17'
    },
    network_indicators: { ipv4: [{ value: '185.38.150.7', context: 'C2 server' }] }
  };
}

// The control: the same three values, sitting where indicators live.
function controlFeed() {
  var f = vaultFeed();
  delete f.metadata.victim_names;
  delete f.metadata.victim_names_note;
  f.network_indicators.ipv4.push({ value: VICTIM_IP, context: 'control' });
  f.network_indicators.domains = [{ value: VICTIM_DOMAIN, context: 'control' }];
  return f;
}

var CATALOG = [
  'entries:',
  '  - title: "Priv Test"',
  '    date: 2026-11-17',
  '    severity: high',
  '    report_url: /reports/priv-test/',
  '    ioc_url: /ioc-feeds/priv-test-iocs.json'
].join('\n');

function containsAny(text) {
  return [VICTIM_IP, VICTIM_DOMAIN, VICTIM_ORG, NOTE, 'victim_names'].filter(function (v) {
    return text.indexOf(v) !== -1;
  });
}

test('strip removes both private keys and keeps every other key in order', function () {
  var src = vaultFeed();
  var r = FP.strip(src);
  assert.deepStrictEqual(r.removed, ['victim_names', 'victim_names_note']);
  assert.deepStrictEqual(Object.keys(r.feed.metadata), ['campaign_slug', 'tlp', 'report_date']);
  assert.deepStrictEqual(Object.keys(r.feed), Object.keys(src));
  // the input is not modified
  assert.ok(Array.isArray(src.metadata.victim_names));
});

test('strip leaves a feed with no private keys untouched, and an empty list is still removed', function () {
  var clean = controlFeed();
  assert.deepStrictEqual(FP.strip(clean).removed, []);
  var empty = { metadata: { victim_names: [] }, x: 1 };
  assert.deepStrictEqual(FP.strip(empty).removed, ['victim_names']);
  assert.deepStrictEqual(FP.strip(empty).feed, { metadata: {}, x: 1 });
});

test('publish-feed writes the site copy without the private metadata', function () {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), 't0662-'));
  try {
    var src = path.join(dir, 'vault');
    var out = path.join(dir, 'site');
    fs.mkdirSync(src); fs.mkdirSync(out);
    var srcFile = path.join(src, 'priv-test-iocs.json');
    fs.writeFileSync(srcFile, JSON.stringify(vaultFeed(), null, 2) + '\n');

    var r = PF.publish(srcFile, out);
    assert.strictEqual(r.status, 0);
    assert.deepStrictEqual(r.removed, ['victim_names', 'victim_names_note']);
    var written = fs.readFileSync(path.join(out, 'priv-test-iocs.json'), 'utf8');
    assert.deepStrictEqual(containsAny(written), []);
    // what is kept is kept: the operator indicator is still there
    assert.ok(written.indexOf('185.38.150.7') !== -1);
    assert.ok(/\n$/.test(written));
    // the vault file itself is not touched
    assert.ok(fs.readFileSync(srcFile, 'utf8').indexOf(VICTIM_ORG) !== -1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('publish-feed refuses a file that is not a JSON object', function () {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), 't0662-'));
  try {
    var f = path.join(dir, 'x-iocs.json');
    fs.writeFileSync(f, '[1,2]');
    assert.strictEqual(PF.publish(f, dir).status, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the IOC search index never carries victim_names values from a hand-copied feed', function () {
  var ctl = JSON.stringify(IDX.build({ 'priv-test-iocs.json': controlFeed() }, CATALOG, {}));
  assert.ok(ctl.indexOf(VICTIM_IP) !== -1, 'control: an indicator-bucket IP reaches the index');
  assert.ok(ctl.indexOf(VICTIM_DOMAIN) !== -1, 'control: an indicator-bucket domain reaches the index');

  var idx = JSON.stringify(IDX.build({ 'priv-test-iocs.json': vaultFeed() }, CATALOG, {}));
  assert.ok(idx.indexOf('185.38.150.7') !== -1, 'the operator indicator is still indexed');
  assert.deepStrictEqual(containsAny(idx), []);
});

test('the IOC tables never carry victim_names values from a hand-copied feed', function () {
  var status = { 'priv-test-iocs.json': 'published' };
  var meta = { 'priv-test-iocs.json': { title: 'Priv Test', report_url: '/reports/priv-test/' } };

  var ctl = TBL.build({ 'priv-test-iocs.json': controlFeed() }, status, meta);
  var ctlText = TBL.toYaml(ctl.tables || ctl);
  assert.ok(ctlText.indexOf(VICTIM_IP) !== -1, 'control: an indicator-bucket IP reaches the tables');

  var t = TBL.build({ 'priv-test-iocs.json': vaultFeed() }, status, meta);
  var text = TBL.toYaml(t.tables || t);
  assert.ok(text.indexOf('185.38.150.7') !== -1, 'the operator indicator is still tabled');
  assert.deepStrictEqual(containsAny(text), []);
});
