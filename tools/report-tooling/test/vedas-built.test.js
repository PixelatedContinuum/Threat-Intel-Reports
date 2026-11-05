'use strict';

/* T-0564: run after building with test/fixtures/vedas-wire.yml in _data/wire.yml.
   HL_VEDAS_SITE names that build. Without it the render check is NOT CHECKED.
   This exercises the rendered markup and real scripts; it does not measure layout. */
var test = require('node:test');
var assert = require('node:assert/strict');
var fs = require('node:fs');
var path = require('node:path');
var JSDOM = require('jsdom').JSDOM;
var yaml = require('js-yaml');
var CW = require('../lib/check-wire.js');
var ROOT = path.resolve(__dirname, '../../..');
var FIXTURE = path.join(__dirname, 'fixtures/vedas-wire.yml');

test('the VEDAS fixture is valid: four headlines, two nKEVs, three CVEs, sparse scores', function () {
  var d = yaml.load(fs.readFileSync(FIXTURE, 'utf8'));
  var r = CW.check(d, { AlienVault: 'research', BleepingComputer: 'news', 'Cisco Talos': 'research', Microsoft: 'research' }, Date.parse(d.generated_at));
  assert.equal(r.status, 'PASS', r.problems.join(' | '));
  assert.deepEqual(r.vulnWarnings, []);
  assert.deepEqual(r.cveWarnings, []);
  assert.equal(d.items.length, 4);
  assert.equal(d.vulns.length, 2);
  assert.equal(d.cves.length, 3);
  assert.equal(d.cves.filter(function (v) { return v.signals.includes('vedas_weaponized'); }).length, 1);
});

test('built fixture renders optional chips, legends, credit and Details links; VEDAS and msf filters work', {
  skip: process.env.HL_VEDAS_SITE ? false : 'NOT CHECKED: set HL_VEDAS_SITE to the Jekyll fixture build'
}, async function () {
  var site = path.resolve(process.env.HL_VEDAS_SITE);
  var dom = new JSDOM(fs.readFileSync(path.join(site, 'wire/index.html'), 'utf8'), {
    url: 'https://fixture.test/wire/#cves', runScripts: 'outside-only'
  });
  try {
    var win = dom.window, doc = win.document;
    win.Element.prototype.scrollIntoView = function () {};
    win.fetch = function (url) {
      var p = new URL(url, win.location.href).pathname;
      var data = JSON.parse(fs.readFileSync(path.join(site, p), 'utf8'));
      return Promise.resolve({ ok: true, json: function () { return Promise.resolve(data); } });
    };
    win.eval(fs.readFileSync(path.join(ROOT, 'assets/js/listing-filter.js'), 'utf8'));
    win.eval(fs.readFileSync(path.join(ROOT, 'assets/js/wire-details.js'), 'utf8'));
    var ids = ['cves-cve-2026-9001', 'cves-cve-2026-9002', 'cves-cve-2026-9003',
      'cve-cve-2026-9011', 'cve-cve-2026-9012'];
    var chips = ['Maturity 85%', null, 'Maturity 0%', 'Maturity 100%', null];
    ids.forEach(function (id, n) {
      var row = doc.getElementById(id);
      assert.ok(row, id);
      var chip = row.querySelector('.hl-vuln__p--vedas');
      assert.equal(chip ? chip.textContent : null, chips[n], id);
      assert.ok(row.querySelector('.hl-vuln__p--epss'), id + ' EPSS control');
      if (chip) {
        assert.match(chip.title, /A\.R\.P\. Syndicate's VEDAS exploit-maturity estimate; cache updated/);
        assert.ok(chip.previousElementSibling.classList.contains('hl-vuln__pop--epss'), 'maturity next to EPSS');
      }
    });
    var sec = doc.getElementById('cves');
    var visible = function () {
      return Array.from(sec.querySelectorAll('.hl-vuln')).filter(function (r) { return r.style.display !== 'none'; }).map(function (r) { return r.id; });
    };
    var button = sec.querySelector('button[data-sig="vedas_weaponized"]');
    assert.match(button.textContent, /Exploit maturity 80%\+\s*1/);
    assert.match(doc.getElementById(ids[0]).textContent, /Exploit maturity 80%\+/);
    button.click();
    assert.deepEqual(visible(), [ids[0]]);
    sec.querySelector('button[data-sig=""]').click();
    sec.querySelector('button[data-sig="msf"]').click();
    assert.deepEqual(visible(), [ids[1]], 'existing msf filter control');
    sec.querySelector('button[data-sig=""]').click();
    assert.equal(visible().length, 3);
    ['vulns', 'cves'].forEach(function (id) {
      var s = doc.getElementById(id);
      assert.equal(s.querySelectorAll('.hl-legend__body').length, 2);
      s.querySelectorAll('.hl-legend__body').forEach(function (l) {
        assert.match(l.textContent, /Exploit maturity \(VEDAS\)/);
        assert.match(l.textContent, /150\+ identifiers/);
        assert.match(l.textContent, /source publishes no formula/);
        assert.ok(l.querySelector('a[href="https://github.com/ARPSyndicate/cve-scores"]'));
      });
      assert.ok(s.querySelector('.hl-wire__freshness a[href="https://github.com/ARPSyndicate/cve-scores"]'));
    });
    for (var id of ids) {
      var row = doc.getElementById(id);
      row.querySelector('.hl-dt').click();
      await new Promise(function (resolve) { setImmediate(resolve); });
      var link = row.querySelector('a[href^="https://www.exploit.observer/?keyword="]');
      assert.ok(link, id + ' Details link');
      assert.equal(link.textContent, 'Exploit Observer');
      if (id === ids[0]) assert.match(row.querySelector('.hl-dt__panel').textContent, /Exploit maturity 80%\+ \(VEDAS\)/);
      assert.equal(link.href, 'https://www.exploit.observer/?keyword=' + id.replace(/^cves?-/, '').toUpperCase());
    }
  } finally {
    dom.window.close();
  }
});
