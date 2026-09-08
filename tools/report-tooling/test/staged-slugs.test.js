'use strict';

/* Which staged path names which campaign, for the victim-naming gate's routing.

   Regression coverage for 2026-09-08: assets/images/<name>/ used to be treated as a
   campaign slug unconditionally, so an SVG edit under assets/images/behind-the-reports/
   (a site illustration folder, not a campaign) blocked the commit hunting for a vault
   feed that could never exist. `exists`/`catalogText` here stand in for the real
   filesystem so the fix is provable without a live repo checkout. */

var test = require('node:test');
var assert = require('node:assert');
var SS = require('../lib/staged-slugs.js');

function noArtifacts() { return false; }

test('a report/detections/iocs/stix path names its slug directly, no lookup needed', function () {
  var slugs = SS.campaignSlugs([
    'reports/acme/index.md',
    'hunting-detections/acme-detections.md',
    'ioc-feeds/acme-iocs.json',
    'stix/acme.json'
  ], { exists: noArtifacts });
  assert.deepEqual(Object.keys(slugs).sort(), ['acme']);
  assert.equal(slugs.acme.length, 4);
});

test('the hunters-ledger-stix-bundles directory is never treated as a campaign', function () {
  var slugs = SS.campaignSlugs(['stix/hunters-ledger-stix-bundles.json'], { exists: noArtifacts });
  assert.deepEqual(Object.keys(slugs), []);
});

// The regression: an images directory that resolves to nothing is not a campaign.
test('assets/images/<name>/ with no artifact anywhere is NOT treated as a campaign', function () {
  var slugs = SS.campaignSlugs(
    ['assets/images/behind-the-reports/investigation-flow.svg'],
    { exists: noArtifacts, catalogText: '' }
  );
  assert.deepEqual(Object.keys(slugs), [],
    'a directory with no report, detections, IOC feed or catalog entry must not block on a ' +
    'campaign that does not exist');
});

test('assets/images/<name>/ resolves when the report exists', function () {
  var slugs = SS.campaignSlugs(['assets/images/acme/fig-1.png'], {
    exists: function (p) { return p === 'reports/acme/index.md'; }
  });
  assert.deepEqual(Object.keys(slugs), ['acme']);
});

test('assets/images/<name>/ resolves when the detections file exists', function () {
  var slugs = SS.campaignSlugs(['assets/images/acme/fig-1.png'], {
    exists: function (p) { return p === 'hunting-detections/acme-detections.md'; }
  });
  assert.deepEqual(Object.keys(slugs), ['acme']);
});

test('assets/images/<name>/ resolves when the IOC feed exists', function () {
  var slugs = SS.campaignSlugs(['assets/images/acme/fig-1.png'], {
    exists: function (p) { return p === 'ioc-feeds/acme-iocs.json'; }
  });
  assert.deepEqual(Object.keys(slugs), ['acme']);
});

test('assets/images/<name>/ resolves when a retired-feed viewer stub exists', function () {
  // The same surviving-stub shape staged-gate.js already routes ioc-tables on.
  var slugs = SS.campaignSlugs(['assets/images/acme/fig-1.png'], {
    exists: function (p) { return p === 'ioc-feeds/acme/index.md'; }
  });
  assert.deepEqual(Object.keys(slugs), ['acme']);
});

test('assets/images/<name>/ resolves from a catalog.yml entry alone', function () {
  var slugs = SS.campaignSlugs(['assets/images/acme/fig-1.png'], {
    exists: noArtifacts,
    catalogText: '    report_url: /reports/acme/\n    detection_url: /hunting-detections/acme-detections\n'
  });
  assert.deepEqual(Object.keys(slugs), ['acme']);
});

test('a catalog.yml substring match does not fire on an unrelated slug', function () {
  var slugs = SS.campaignSlugs(['assets/images/acme-2/fig-1.png'], {
    exists: noArtifacts,
    catalogText: '    report_url: /reports/acme/\n'
  });
  assert.deepEqual(Object.keys(slugs), []);
});

test('a genuine campaign still routes its images alongside its report in one commit', function () {
  // The case the fix must not break: a report and its own screenshots staged together.
  var slugs = SS.campaignSlugs([
    'reports/acme/index.md',
    'assets/images/acme/fig-1.png',
    'assets/images/acme/fig-2.png'
  ], { exists: function (p) { return p === 'reports/acme/index.md'; } });
  assert.deepEqual(Object.keys(slugs), ['acme']);
  assert.deepEqual(slugs.acme.sort(), [
    'assets/images/acme/fig-1.png', 'assets/images/acme/fig-2.png', 'reports/acme/index.md'
  ]);
});

test('a caller that forgets to wire exists() gets the safe failure, not a false positive',
  function () {
    var slugs = SS.campaignSlugs(['assets/images/acme/fig-1.png'], {});
    assert.deepEqual(Object.keys(slugs), []);
  });

test('backslash paths are accepted, since precommit.js\'s stagedPaths() can hand them over',
  function () {
    var slugs = SS.campaignSlugs(['reports\\acme\\index.md'], { exists: noArtifacts });
    assert.deepEqual(Object.keys(slugs), ['acme']);
  });

test('resolvesToCampaign is exported and agrees with campaignSlugs on the same inputs',
  function () {
    assert.equal(SS.resolvesToCampaign('acme', noArtifacts, null), false);
    assert.equal(
      SS.resolvesToCampaign('acme', function (p) { return p === 'reports/acme/index.md'; }, null),
      true
    );
  });
