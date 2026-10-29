'use strict';
var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var os = require('node:os');
var path = require('node:path');
var P = require('../propose-tabs.js');

/* The pilot's own headings and tiers (reports/opendirectory-38-180-16-98-...).
   The design-v4 section 3 pilot mapping is the expected answer, section by
   section: 1-2 Overview; 3 and 17 Victims; 4, 5 and 8-13 Attack chain; 6-7
   Infrastructure and timeline; 14 Attribution; 15-16 Indicators; 18, 19 and
   Acknowledgements Confidence. */
var PILOT = [
  ['1. Executive Summary', '1', 'overview'],
  ['2. Risk Assessment', '1', 'overview'],
  ['3. Who Was Hit, and How Far the Operator Got', '2', 'victims'],
  ['4. Technical Classification', '2', 'chain'],
  ['5. The Attack Chain at a Glance', '2', 'chain'],
  ['6. Infrastructure', '2', 'timeline'],
  ['7. What the Public Record Holds', '2', 'timeline'],
  ['8. The Social-Security Agency: From a Help-Desk Test Page to the Internal Package Store', '3', 'chain'],
  ['9. The Development Bank: An API Gateway and a Tunnel Out Through the Bank\'s Own Proxy', '3', 'chain'],
  ['10. The Finance Secretariat, the Saved-Page Victims and the Suppliers', '3', 'chain'],
  ['11. The Monitoring Server as a Command Plane', '3', 'chain'],
  ['12. The Port 53 Relay, and the WebLogic Scripts That Would Deliver It', '3', 'chain'],
  ['13. MITRE ATT&CK Mapping', '2', 'chain'],
  ['14. Threat Actor Assessment', '2', 'attribution'],
  ['15. Indicators of Compromise', '2', 'indicators'],
  ['16. Detection and Hunting Guidance', '2', 'indicators'],
  ['17. Notification', '2', 'victims'],
  ['18. Confidence Summary, Gaps, and What Would Change This', '2', 'confidence'],
  ['19. References', '2', 'confidence'],
  ['Acknowledgements', '2', 'confidence']
];

function pilotMd() {
  return '---\ntitle: "pilot"\n---\n\n' + PILOT.map(function (p) {
    return '## ' + p[0] + '\n{: .hl-tier-' + p[1] + '}\n\nBody text.\n';
  }).join('\n');
}

test('the pilot gets the design-v4 section 3 pilot mapping, section for section', function () {
  var props = P.proposeFor(pilotMd());
  assert.strictEqual(props.length, 20);
  assert.deepStrictEqual(props.map(function (p) { return p.tab; }),
    PILOT.map(function (p) { return p[2]; }));
  assert.ok(props.every(function (p) { return p.how === 'name' || p.how === 'tier3'; }));
});

test('the Tier 3 walkthroughs are labelled tier3, not name, so the writer sees the weaker basis', function () {
  var props = P.proposeFor(pilotMd());
  props.forEach(function (p) {
    if (/^(8|9|10|11|12)\./.test(p.text)) {
      assert.strictEqual(p.how, 'tier3', p.text);
    }
  });
});

test('an existing tag is reported as set and never re-proposed', function () {
  var md = pilotMd().replace('## 14. Threat Actor Assessment\n{: .hl-tier-2}',
    '## 14. Threat Actor Assessment\n{: .hl-tier-2}\n{: .hl-tab-confidence}');
  var p = P.proposeFor(md).filter(function (x) { return /Threat Actor/.test(x.text); })[0];
  assert.strictEqual(p.tab, 'confidence');
  assert.strictEqual(p.how, 'set');
});

test('an unplaceable heading gets no proposal at all', function () {
  var md = '---\ntitle: "x"\n---\n\n## 1. Executive Summary\n{: .hl-tier-1}\n\nx\n\n' +
    '## Zorblax Quux\n{: .hl-tier-2}\n\nx\n';
  var props = P.proposeFor(md);
  assert.strictEqual(props[0].tab, 'overview');
  assert.strictEqual(props[1].tab, null);
  assert.strictEqual(props[1].how, null);
});

test('the span rule only fills between two neighbours on the same tab', function () {
  var md = '---\ntitle: "x"\n---\n\n## 1. Technical Classification\n{: .hl-tier-2}\n\nx\n\n' +
    '## Zorblax Quux\n{: .hl-tier-2}\n\nx\n\n' +
    '## 2. MITRE ATT&CK Mapping\n{: .hl-tier-2}\n\nx\n';
  var props = P.proposeFor(md);
  assert.strictEqual(props[1].tab, 'chain');
  assert.strictEqual(props[1].how, 'span');

  var split = md.replace('## 2. MITRE ATT&CK Mapping', '## 2. Indicators of Compromise');
  assert.strictEqual(P.proposeFor(split)[1].tab, null);
});

test('writeTabs inserts the line directly after the tier line, and is idempotent', function () {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-tabs-'));
  var file = path.join(dir, 'index.md');
  fs.writeFileSync(file, pilotMd(), 'utf8');

  var w = P.writeTabs(file, P.proposeFor(fs.readFileSync(file, 'utf8')));
  assert.deepStrictEqual(w, { added: 20, kept: 0, unplaced: 0 });
  var after = fs.readFileSync(file, 'utf8');
  assert.match(after, /## 1\. Executive Summary\n\{: \.hl-tier-1\}\n\{: \.hl-tab-overview\}/);
  assert.match(after, /## 13\. MITRE ATT&CK Mapping\n\{: \.hl-tier-2\}\n\{: \.hl-tab-chain\}/);

  var again = P.writeTabs(file, P.proposeFor(after));
  assert.deepStrictEqual(again, { added: 0, kept: 20, unplaced: 0 });
  assert.strictEqual(fs.readFileSync(file, 'utf8'), after);

  fs.rmSync(dir, { recursive: true, force: true });
});

test('writeTabs leaves an unplaceable section alone and counts it', function () {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-tabs-'));
  var file = path.join(dir, 'index.md');
  fs.writeFileSync(file, '---\ntitle: "x"\n---\n\n## Zorblax Quux\n{: .hl-tier-2}\n\nx\n', 'utf8');
  var w = P.writeTabs(file, P.proposeFor(fs.readFileSync(file, 'utf8')));
  assert.deepStrictEqual(w, { added: 0, kept: 0, unplaced: 1 });
  assert.strictEqual(fs.readFileSync(file, 'utf8'), '---\ntitle: "x"\n---\n\n## Zorblax Quux\n{: .hl-tier-2}\n\nx\n');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('writeTabs puts the line under the heading when there is no tier line', function () {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-tabs-'));
  var file = path.join(dir, 'index.md');
  fs.writeFileSync(file, '---\ntitle: "x"\n---\n\n## Executive Summary\n\nx\n', 'utf8');
  P.writeTabs(file, P.proposeFor(fs.readFileSync(file, 'utf8')));
  assert.strictEqual(fs.readFileSync(file, 'utf8'),
    '---\ntitle: "x"\n---\n\n## Executive Summary\n{: .hl-tab-overview}\n\nx\n');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a written pilot copy passes check-tabs', function () {
  var CT = require('../check-tabs.js');
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-tabs-'));
  var file = path.join(dir, 'index.md');
  fs.writeFileSync(file, pilotMd(), 'utf8');
  P.writeTabs(file, P.proposeFor(fs.readFileSync(file, 'utf8')));
  var r = CT.checkMarkdown(fs.readFileSync(file, 'utf8'), file);
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
  assert.strictEqual(r.tagged, 20);
  fs.rmSync(dir, { recursive: true, force: true });
});
