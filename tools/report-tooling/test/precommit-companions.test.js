'use strict';

/* The pre-commit hook runs the companion-value gate when a report markdown file is staged
   (T-0605 L54). Run as a process over a scratch git repo whose tools/report-tooling is a
   symlink to this checkout's, so the hook is the real one and the repo it judges is the
   scratch one. The control is a staged report whose companions all exist: it must pass the
   companion line; the same report with a missing detection page must be blocked. */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const HOOK = path.join(__dirname, '..', '..', 'git-hooks', 'precommit.js');
const TOOLS = path.join(__dirname, '..');

function git(d, args) {
  const r = spawnSync('git', args, { cwd: d, encoding: 'utf8' });
  assert.strictEqual(r.status, 0, 'git ' + args.join(' ') + ': ' + r.stderr);
}

function scratch(reportFm, stage) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-pc-'));
  const w = (rel, text) => {
    const p = path.join(d, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, text);
  };
  git(d, ['init', '-q']);
  fs.mkdirSync(path.join(d, 'tools'));
  fs.symlinkSync(TOOLS, path.join(d, 'tools', 'report-tooling'));
  w('hunting-detections/a-detections.md', '---\npermalink: /hunting-detections/a-detections/\n---\n');
  w('ioc-feeds/a/index.md', '---\npermalink: /ioc-feeds/a/\nioc_slug: "a.json"\n---\n');
  w('ioc-feeds/a.json', '{}');
  w('stix/a.json', '{}');
  w('reports/a/index.md', '---\ntitle: A\npermalink: /reports/a/\n' + reportFm + '---\nbody\n');
  w('README.md', 'x\n');
  git(d, ['add'].concat(stage));
  return d;
}
function hook(d) { return spawnSync(process.execPath, [HOOK], { cwd: d, encoding: 'utf8' }); }
const GOODFM = 'detection_page: /hunting-detections/a-detections/\nioc_feed: /ioc-feeds/a/\nstix_bundle: /stix/a.json\n';
const BADFM = 'detection_page: /hunting-detections/missing-detections/\nioc_feed: /ioc-feeds/a/\nstix_bundle: /stix/a.json\n';

function line(out, label) {
  return out.split('\n').find((l) => l.indexOf(label) !== -1) || '';
}

test('a staged report whose companions all exist passes the companion line (control)', () => {
  const d = scratch(GOODFM, ['reports/a/index.md']);
  try {
    const r = hook(d);
    assert.match(line(r.stdout, 'report companion links'), /^\s*PASS\s/, r.stdout);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('a staged report naming a missing detection page is blocked', () => {
  const d = scratch(BADFM, ['reports/a/index.md']);
  try {
    const r = hook(d);
    assert.match(line(r.stdout, 'report companion links'), /^\s*FAIL\s/, r.stdout);
    assert.match(r.stdout, /missing-detections/, r.stdout);
    assert.match(r.stdout, /COMMIT BLOCKED/, r.stdout);
    assert.strictEqual(r.status, 1);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('nothing report-shaped staged: the companion gate does not run', () => {
  const d = scratch(BADFM, ['README.md']);
  try {
    const r = hook(d);
    assert.strictEqual(line(r.stdout, 'report companion links'), '', r.stdout);
    assert.strictEqual(r.status, 0);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});
