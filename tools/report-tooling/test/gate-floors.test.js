'use strict';

/* Zero-denominator floors, exercised the way an operator meets them: the gate runs as a process
   (exit code and first word), not only through a helper. Each gate is copied into a temp tree
   that holds nothing to measure, so the root it derives from __dirname is empty.
   A gate that measured nothing is NOT CHECKED (exit 2), never PASS (T-0603, A6/M4). */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const TOOLING = path.join(__dirname, '..');
const SITE = path.join(TOOLING, '..', '..');

function tempTree() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-floor-'));
  const tooling = path.join(root, 'tools', 'report-tooling');
  fs.mkdirSync(tooling, { recursive: true });
  fs.cpSync(path.join(TOOLING, 'lib'), path.join(tooling, 'lib'), { recursive: true });
  fs.symlinkSync(path.join(TOOLING, 'node_modules'), path.join(tooling, 'node_modules'));
  fs.mkdirSync(path.join(root, 'assets', 'js'), { recursive: true });
  fs.copyFileSync(path.join(SITE, 'assets', 'js', 'attack-coverage.js'),
    path.join(root, 'assets', 'js', 'attack-coverage.js'));
  fs.mkdirSync(path.join(root, '_data'), { recursive: true });
  return { root, tooling };
}

function run(t, gate, args) {
  fs.copyFileSync(path.join(TOOLING, gate), path.join(t.tooling, gate));
  const env = Object.assign({}, process.env);
  delete env.NODE_PATH;
  return spawnSync(process.execPath, [path.join(t.tooling, gate)].concat(args || []),
    { encoding: 'utf8', env: env });
}

test('check-report.js on a zero-byte file is NOT CHECKED, exit 2', () => {
  const t = tempTree();
  try {
    const f = path.join(t.root, 'empty.md');
    fs.writeFileSync(f, '');
    const r = run(t, 'check-report.js', [f]);
    assert.strictEqual(r.status, 2, r.stdout + r.stderr);
    assert.match(r.stdout, /^NOT CHECKED/);
    fs.writeFileSync(f, '  \n\n');
    assert.strictEqual(run(t, 'check-report.js', [f]).status, 2, 'whitespace only is also empty');
  } finally { fs.rmSync(t.root, { recursive: true, force: true }); }
});

test('check-report.js control: a real report still passes', () => {
  const t = tempTree();
  try {
    const src = path.join(SITE, 'reports', 'PULSAR-RAT', 'index.md');
    const r = run(t, 'check-report.js', [src]);
    assert.strictEqual(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /^PASS/);
  } finally { fs.rmSync(t.root, { recursive: true, force: true }); }
});

test('check-tags.js with an empty catalog (0 of 0) is NOT CHECKED, exit 2', () => {
  const t = tempTree();
  try {
    fs.writeFileSync(path.join(t.root, '_data', 'catalog.yml'), 'entries: []\n');
    fs.writeFileSync(path.join(t.root, '_data', 'tags.yml'),
      'tags:\n  - tag: C2\n    color: blue\n');
    const r = run(t, 'check-tags.js');
    assert.strictEqual(r.status, 2, r.stdout + r.stderr);
    assert.match(r.stdout, /^NOT CHECKED/);
    /* control: one entry with one tag passes through the same copy */
    fs.writeFileSync(path.join(t.root, '_data', 'catalog.yml'),
      'entries:\n  - title: A\n    tags: [C2]\n');
    const c = run(t, 'check-tags.js');
    assert.strictEqual(c.status, 0, c.stdout);
    assert.match(c.stdout, /^PASS/);
  } finally { fs.rmSync(t.root, { recursive: true, force: true }); }
});

test('check-embargo-artifacts.js with no report read is NOT CHECKED, exit 2', () => {
  const t = tempTree();
  try {
    fs.mkdirSync(path.join(t.root, 'reports', 'no-index-here'), { recursive: true });
    const r = run(t, 'check-embargo-artifacts.js');
    assert.strictEqual(r.status, 2, r.stdout + r.stderr);
    assert.match(r.stdout, /^NOT CHECKED/);
    /* control: one report with an index.md and no embargo passes */
    fs.mkdirSync(path.join(t.root, 'reports', 'a'), { recursive: true });
    fs.writeFileSync(path.join(t.root, 'reports', 'a', 'index.md'),
      '---\ntitle: A\npermalink: /reports/a/\n---\nbody\n');
    const c = run(t, 'check-embargo-artifacts.js');
    assert.strictEqual(c.status, 0, c.stdout);
    assert.match(c.stdout, /^PASS  1 report\(s\) scanned/);
  } finally { fs.rmSync(t.root, { recursive: true, force: true }); }
});

test('check-ioc-feeds-attack.js with feeds that carry no technique ID is NOT CHECKED, exit 2', () => {
  const t = tempTree();
  try {
    fs.mkdirSync(path.join(t.root, 'ioc-feeds'), { recursive: true });
    fs.writeFileSync(path.join(t.root, 'ioc-feeds', 'x.json'), '{"indicators": []}');
    const r = run(t, 'check-ioc-feeds-attack.js');
    assert.strictEqual(r.status, 2, r.stdout + r.stderr);
    assert.match(r.stdout, /^NOT CHECKED/);
  } finally { fs.rmSync(t.root, { recursive: true, force: true }); }
});
