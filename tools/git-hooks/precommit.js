#!/usr/bin/env node
'use strict';

/* The pre-commit machinery gate.

   Seven site features are driven by a generated artifact or an authored marker that
   lives beside the prose: the ATT&CK strip, the glossary, the detection picker
   manifest, figure-nav chips, register tiers, the Wire data file, the indicator
   index. hunters-ledger-publish gates all of them for a campaign that ships through
   the skill. Nothing gates the edits that are not a publish, and those are exactly
   the ones that invalidate an artifact without regenerating it.

   Three rules govern the output, all of them learned the hard way in this repo:

   1. FAIL blocks. NOT CHECKED warns and allows. Blocking on NOT CHECKED would make
      an absent node_modules un-committable, and the answer to that is a permanent
      --no-verify habit, which costs the whole gate.
   2. NOT CHECKED is never folded into PASS, and always carries its reason.
   3. A run that checked nothing says so. "Ran and found nothing to check" and "not
      installed" must not look alike.

   What it cannot do is check anything needing rendered HTML, because the change
   being committed is not in the published build yet. Those are printed as owed. */

var path = require('node:path');
var fs = require('node:fs');
var cp = require('node:child_process');

var ROOT = (function () {
  try {
    return cp.execSync('git rev-parse --show-toplevel', { encoding: 'utf8' }).trim();
  } catch (e) {
    return process.cwd();
  }
})();
var TOOLS = path.join(ROOT, 'tools', 'report-tooling');

function say(s) { process.stdout.write(s + '\n'); }

function stagedPaths() {
  var out = cp.execSync('git diff --cached --name-only -z --diff-filter=ACMRT', {
    cwd: ROOT, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024
  });
  // -z so a path containing a space or a quote survives intact.
  var all = out.split('\0').filter(Boolean);
  // Deletions are wanted too: removing a detection file makes the manifest stale.
  var del = cp.execSync('git diff --cached --name-only -z --diff-filter=D', {
    cwd: ROOT, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024
  }).split('\0').filter(Boolean);
  return { all: all.concat(del), existing: all };
}

function runCheck(c) {
  var r = cp.spawnSync(process.execPath, [path.join(TOOLS, c.cmd)], {
    cwd: TOOLS, encoding: 'utf8'
  });
  if (r.error) {
    return { status: 'NOT CHECKED', text: 'could not run ' + c.cmd + ': ' + r.error.message };
  }
  var text = ((r.stdout || '') + (r.stderr || '')).trim();
  var status = r.status === 0 ? 'PASS' : (r.status === 2 ? 'NOT CHECKED' : 'FAIL');
  return { status: status, text: text };
}

// Every campaign slug the staged change set touches. The victim-naming gate is per-campaign
// and lives in the other repo, so this is the only routing it needs.
// Populated by stagedSlugs: slug -> the staged paths that belong to it, so the inert-diff
// test below can ask git what THIS campaign's own files changed rather than the whole commit.
var SLUG_PATHS = {};

function stagedSlugs(paths) {
  SLUG_PATHS = {};
  paths.forEach(function (p) {
    var m = /^reports\/([^/]+)\/index\.md$/.exec(p)
         || /^hunting-detections\/(.+)-detections\.md$/.exec(p)
         || /^ioc-feeds\/(.+)-iocs\.json$/.exec(p)
         || /^assets\/images\/([^/]+)\//.exec(p)
         || /^stix\/(.+)\.json$/.exec(p);
    if (m && m[1] !== 'hunters-ledger-stix-bundles') {
      (SLUG_PATHS[m[1]] = SLUG_PATHS[m[1]] || []).push(p);
    }
  });
  return Object.keys(SLUG_PATHS).sort();
}

// The victim-naming gate, in --publish form: it decides rather than only reporting.
// NOT installed as a fourth `CHECKS` entry because those spawn node inside this repo and
// this one is a Python script in ~/ai-workflows, which is also why an absent interpreter or
// an absent script is reported NOT CHECKED rather than passing quietly.
var VICTIM_GATE = '/home/jharrison/ai-workflows/.claude/scripts/check_victim_naming.py';

// Tokens a staged diff ADDS to a campaign's files, minus the ones it removes.
//
// The victim gate answers "does any published artifact contain a name this campaign declared
// a victim". A diff that introduces no token absent from the text it replaced cannot change
// that answer, whatever the campaign declares, because every string in the new file was
// already in the old one. Repointing `ioc_feed` from `/ioc-feeds/<slug>-iocs.json` to
// `/ioc-feeds/<slug>/` drops `iocs` and `json` and adds nothing, so it is inert by this test.
//
// This is deliberately about TEXT rather than about which field changed. A whitelist of
// "safe" front-matter keys would be wrong: a permalink can carry a victim's name inside the
// slug itself, and `serviciosnabon` is a real example from this corpus. Asking what the diff
// actually introduces needs no such judgement.
//
// Undeclared campaigns are the reason this exists. The gate blocks them by design, which is
// right for a publish and wrong for a link fix: 37 published reports could not have their IOC
// link corrected on 2026-09-02 because of an authoring backlog unrelated to the change. Left
// unnarrowed, the lesson people take is `--no-verify`.
function tokensAdded(paths) {
  var r = cp.spawnSync('git', ['diff', '--cached', '-U0', '--'].concat(paths), { encoding: 'utf8' });
  if (r.error || r.status !== 0) return null;          // cannot tell: caller must run the gate
  var add = {}, del = {};
  (r.stdout || '').split('\n').forEach(function (line) {
    if (/^\+\+\+|^---/.test(line)) return;
    var bag = line[0] === '+' ? add : (line[0] === '-' ? del : null);
    if (!bag) return;
    line.slice(1).toLowerCase().split(/[^a-z0-9]+/).forEach(function (t) {
      if (t) bag[t] = true;
    });
  });
  return Object.keys(add).filter(function (t) { return !del[t]; });
}

function checkVictimNaming(slugs) {
  if (!slugs.length) return [];
  if (!fs.existsSync(VICTIM_GATE)) {
    return [{ label: 'victim naming', status: 'NOT CHECKED',
      text: VICTIM_GATE + ' not found; no campaign was checked for victim naming.' }];
  }
  return slugs.map(function (slug) {
    var own = SLUG_PATHS[slug] || [];
    var added = own.length ? tokensAdded(own) : null;
    if (added && !added.length) {
      return { label: 'victim naming: ' + slug, status: 'INERT DIFF',
        text: 'the staged diff introduces no token absent from the text it replaced, so it ' +
              'cannot publish a name that was not already published. The gate was not run.' };
    }
    var r = cp.spawnSync('python3', [VICTIM_GATE, '--slug', slug, '--publish'],
      { encoding: 'utf8' });
    if (r.error) {
      return { label: 'victim naming: ' + slug, status: 'NOT CHECKED',
        text: 'could not run the gate: ' + r.error.message };
    }
    var text = ((r.stdout || '') + (r.stderr || '')).trim();
    // --publish is a decision: 0 allows, anything else does not. There is no third exit to
    // fold in here, because "could not check" is precisely what it refuses to allow.
    return { label: 'victim naming: ' + slug,
      status: r.status === 0 ? 'PASS' : 'FAIL', text: text };
  });
}

function checkReports(files) {
  var CR;
  try {
    CR = require(path.join(TOOLS, 'check-report.js'));
  } catch (e) {
    return [{ label: 'reports', status: 'NOT CHECKED',
              text: e.message + '. Run `npm ci` in tools/report-tooling.' }];
  }
  return files.map(function (f) {
    var r;
    try { r = CR.checkFile(path.join(ROOT, f)); }
    catch (e) { return { label: f, status: 'NOT CHECKED', text: e.message }; }

    /* Only the three markdown-resolvable verdicts are consulted. The glossary is
       NOT CHECKED on this path by design and is reported once, as owed, rather than
       once per report where it would drown the real findings. */
    /* Specific before aggregate. check-report.js rolls the figure-nav and tier
       problems into its own top-level `problems`, so consulting the strip first
       would label every orphaned anchor as a strip failure and send the reader
       to the wrong tool. First to claim a message names it. */
    var parts = [
      { name: 'figure-nav', v: r.figureNav || {} },
      { name: 'tiers', v: r.tiers || {} },
      { name: 'strip', v: { status: r.status, problems: r.problems, reason: r.reason } }
    ];
    var bad = parts.filter(function (p) { return p.v.status === 'FAIL'; });
    var unk = parts.filter(function (p) { return p.v.status === 'NOT CHECKED'; });

    /* check-report.js rolls the figure-nav and tier problems up into its own
       top-level `problems`, so reporting each part separately prints the same
       sentence two or three times. A gate that repeats itself is a gate people
       learn to skim, and then to bypass. Deduplicated by problem text; the first
       part to report it wins the label. */
    function collapse(list, pick) {
      var seen = {}, out = [];
      list.forEach(function (part) {
        (pick(part) || []).forEach(function (msg) {
          if (seen[msg]) return;
          seen[msg] = true;
          out.push(part.name + ': ' + msg);
        });
      });
      return out;
    }

    if (bad.length) {
      return { label: f, status: 'FAIL', text: collapse(bad, function (part) {
        return (part.v.problems || []).length ? part.v.problems
                                              : [part.v.reason || 'failed'];
      }).join('\n           ') };
    }
    if (unk.length) {
      return { label: f, status: 'NOT CHECKED', text: collapse(unk, function (part) {
        return [part.v.reason || 'no verdict recorded'];
      }).join('\n           ') };
    }
    return { label: f, status: 'PASS',
             text: (r.techniques || 0) + ' techniques, ' + (r.figureNav.chips || 0) +
                   ' chips, ' + (r.tiers.marked || 0) + ' sections marked' };
  });
}

(function main() {
  var SG;
  try {
    SG = require(path.join(TOOLS, 'lib', 'staged-gate.js'));
  } catch (e) {
    say('machinery gate  NOT CHECKED  ' + e.message);
    say('                the commit is allowed; nothing was verified.');
    process.exit(0);
  }

  var staged;
  try { staged = stagedPaths(); }
  catch (e) {
    say('machinery gate  NOT CHECKED  could not list staged paths: ' + e.message);
    process.exit(0);
  }

  var p = SG.plan(staged.all, { existing: staged.existing });

  if (!p.checks.length && !p.reports.length && !p.owed.length && !stagedSlugs(staged.all).length) {
    say('machinery gate  nothing staged that carries machinery (' +
      staged.all.length + ' path(s) checked against the routing rules)');
    process.exit(0);
  }

  var results = [];
  p.checks.forEach(function (c) {
    var r = runCheck(c);
    results.push({ label: c.label, status: r.status, text: r.text });
  });
  if (p.reports.length) results = results.concat(checkReports(p.reports));
  results = results.concat(checkVictimNaming(stagedSlugs(staged.all)));

  var fails = results.filter(function (r) { return r.status === 'FAIL'; });
  var unk = results.filter(function (r) { return r.status === 'NOT CHECKED'; });

  say('');
  say('machinery gate  ' + results.length + ' check(s) on ' + staged.all.length +
    ' staged path(s)');
  results.forEach(function (r) {
    say('  ' + r.status.padEnd(12) + r.label);
    if (r.status !== 'PASS' && r.text) {
      r.text.split('\n').forEach(function (l) { say('           ' + l.trim()); });
    }
  });

  p.owed.forEach(function (o) {
    say('  ' + 'NOT CHECKED'.padEnd(12) + o);
  });

  say('');
  if (fails.length) {
    say('COMMIT BLOCKED: ' + fails.length + ' check(s) failed. Fix them, or use ' +
      '`git commit --no-verify` if you know why this is right.');
    process.exit(1);
  }
  if (unk.length || p.owed.length) {
    say('Commit allowed. ' + (unk.length + p.owed.length) +
      ' item(s) NOT CHECKED above, which is not a pass. The render side is verified ' +
      'post-push by `npm run verify` in tools/report-tooling.');
  } else {
    var inert = results.filter(function (r) { return r.status === 'INERT DIFF'; });
    say('All source-side checks passed. The render side (glossary marks, picker rule ' +
      'binding, appearance) is still verified post-push.');
    if (inert.length) {
      say(inert.length + ' campaign(s) were not gated because their staged diff introduces ' +
        'no new text. That is a property of the diff, not a clean bill of health for the ' +
        'campaign: publishing one still has to face the gate.');
    }
  }
  process.exit(0);
})();
