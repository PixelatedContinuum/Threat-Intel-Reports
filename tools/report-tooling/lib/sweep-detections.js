'use strict';

/* Sweeps the detection corpus, on both sides of the manifest.

   The generator alone only proves the manifest is consistent with the markdown
   it was built from. This adds the half no source-side check can reach: it
   fetches each rendered detection page and asks the picker to bind every entry,
   which recomputes each rule's body hash against the fence its index points at.

   That is the failure this whole feature is gated against. A generator that
   counted a fence kramdown did not render, or the reverse, offsets every later
   rule on the page and serves the wrong rule to a defender with nothing looking
   wrong. Only comparing against the rendered page can see it. */

var fs = require('node:fs');
var path = require('node:path');

var GEN = require('../generate-detection-manifests.js');
var PD = require('./parse-detections.js');
var DP = require(path.join(__dirname, '..', '..', '..', 'assets', 'js', 'detection-picker.js'));

var DET_DIR = path.join(__dirname, '..', '..', '..', 'hunting-detections');

function detectionFiles() {
  return fs.readdirSync(DET_DIR)
    .filter(function (f) { return /-detections[.]md$/.test(f); })
    .sort();
}

// Source side: the generator's own verdict, without writing anything.
function sweepSource() {
  return GEN.run({ dryRun: true });
}

// Page side: does the manifest still describe what readers actually receive?
async function sweepRendered(base, JSDOM) {
  var files;
  try {
    files = detectionFiles();
  } catch (e) {
    return { status: 'NOT CHECKED', reason: 'cannot read ' + DET_DIR + ': ' + e.message,
             pages: 0, bound: 0, xref: 0, mismatched: 0, problems: [] };
  }
  if (!files.length) {
    return { status: 'NOT CHECKED', reason: 'no detection files found, so this run checked nothing',
             pages: 0, bound: 0, xref: 0, mismatched: 0, problems: [] };
  }

  var bound = 0, xref = 0, mismatched = 0, skipped = 0, problems = [];

  for (var i = 0; i < files.length; i++) {
    var slug = files[i].replace(/[.]md$/, '');
    var url = base + '/hunting-detections/' + slug + '/';
    var html = null;

    try {
      var res = await fetch(url);
      if (!res.ok) { problems.push(slug + ': HTTP ' + res.status); skipped++; continue; }
      html = await res.text();
    } catch (e) {
      problems.push(slug + ': ' + e.message); skipped++; continue;
    }

    var doc = new JSDOM(html).window.document;
    var body = doc.querySelector('.hl-post-content') || doc.querySelector('.hl-post-body');
    if (!body) { problems.push(slug + ': no report body container'); skipped++; continue; }

    var rules;
    try {
      rules = PD.parse(fs.readFileSync(path.join(DET_DIR, files[i]), 'utf8'), slug).rules;
    } catch (e) {
      problems.push(slug + ': source unreadable, ' + e.message); skipped++; continue;
    }

    var b = DP.bind(body, rules, doc);
    bound += b.ok.length;
    xref += b.crossReferenced.length;
    mismatched += b.mismatched.length;
    b.mismatched.slice(0, 2).forEach(function (m) { problems.push(slug + ': ' + m.reason); });
  }

  return {
    status: mismatched ? 'FAIL' : (skipped ? 'NOT CHECKED' : 'PASS'),
    pages: files.length, bound: bound, xref: xref, mismatched: mismatched,
    reason: skipped ? skipped + ' page(s) could not be checked' : undefined,
    problems: problems
  };
}

module.exports = { sweepSource: sweepSource, sweepRendered: sweepRendered, detectionFiles: detectionFiles };
