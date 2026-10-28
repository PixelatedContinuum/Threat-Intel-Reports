'use strict';

/* The /impact/ cards (_data/impact_entries.yml) are hand-written; the home-page total
   (_data/impact.yml actions_reported) is generated from the disclosure tracker by
   .claude/scripts/disclosure_outcomes.py --site-yaml. A reply recorded in the tracker
   without a card, or a card with no tracker outcome behind it, makes the two disagree.
   These tests fail the build when they do, and when a card is missing what the page needs. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var path = require('node:path');
var yaml = require('js-yaml');

var DATA = path.join(__dirname, '..', '..', '..', '_data');
var CATEGORIES = ['attacker-infrastructure', 'victim-action', 'cert-action'];

function load(name) { return yaml.load(fs.readFileSync(path.join(DATA, name), 'utf8')); }

test('impact cards sum to the generated total', function () {
  var total = load('impact.yml').actions_reported;
  var entries = load('impact_entries.yml').entries;
  assert.ok(Number.isInteger(total) && total > 0, 'impact.yml actions_reported must be a positive integer');
  var sum = entries.reduce(function (n, e) { return n + (e.count || 1); }, 0);
  assert.strictEqual(sum, total, 'cards cover ' + sum + ' actions, impact.yml says ' + total);
});

test('every impact card has what the page renders', function () {
  load('impact_entries.yml').entries.forEach(function (e, i) {
    var where = 'card ' + (i + 1) + ' (' + (e.title || 'untitled') + ')';
    assert.ok(CATEGORIES.indexOf(e.category) >= 0, where + ': category must be one of ' + CATEGORIES.join(', '));
    assert.match(String(e.date), /^\d{4}-\d{2}$/, where + ': date must be YYYY-MM');
    ['title', 'description', 'recipient'].forEach(function (k) {
      assert.ok(typeof e[k] === 'string' && e[k].trim(), where + ': ' + k + ' is required');
    });
    assert.ok(['reported', 'checked', 'record'].indexOf(e.verified) >= 0, where + ': verified must be reported, checked or record');
    assert.ok(!/[–—]/.test(e.title + e.description), where + ': no em or en dashes in public text');
    if (e.category !== 'attacker-infrastructure') {
      assert.ok(!e.report_url, where + ': victim and CERT cards link nothing');
    }
  });
});

test('a mismatch is caught (control)', function () {
  var entries = [{ count: 11 }, {}, { count: 3 }];
  var sum = entries.reduce(function (n, e) { return n + (e.count || 1); }, 0);
  assert.notStrictEqual(sum, 16);
  assert.strictEqual(sum, 15);
});
