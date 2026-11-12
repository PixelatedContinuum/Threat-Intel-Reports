'use strict';

/* The theme prune (prune-theme-assets.js, T-0605 L02): a theme-only file under assets/js or assets/fonts stays only when something
   references it; the reference check fails on a path that was removed. Run as a process over a scratch site and source. */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const GATE = path.join(__dirname, '..', 'prune-theme-assets.js');

function fixture(extraPage) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-prune-'));
  const site = path.join(d, '_site'), src = path.join(d, 'src');
  const w = (root, rel, text) => {
    const p = path.join(root, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, text);
  };
  // source-owned files exist in both trees
  w(src, 'assets/js/own.js', 'var base = "/assets/js/lazy/"; load(base + "chunk.js");');
  w(site, 'assets/js/own.js', 'var base = "/assets/js/lazy/"; load(base + "chunk.js");');
  // theme-only files: only the site has them
  w(site, 'assets/js/main.min.js', 'x');
  w(site, 'assets/js/vendor/mermaid.min.js', 'm'.repeat(1000));
  w(site, 'assets/js/lazy/chunk.js', 'c');
  w(site, 'assets/css/main.css', '@font-face{src:url("../fonts/sans/sans.woff2")} @import "extra.css";');
  w(site, 'assets/css/extra.css', 'a{}');
  w(site, 'assets/fonts/sans/sans.woff2', 'f');
  w(site, 'assets/fonts/fa/fa.woff2', 'f');
  w(site, 'index.html', '<html><head><link rel="stylesheet" href="/assets/css/main.css"><script defer src="/assets/js/own.js"></script></head><body>' + (extraPage || '') + '</body></html>');
  return { d, site, src };
}
function run(f, args) { return spawnSync(process.execPath, [GATE, '--site', f.site, '--source', f.src].concat(args || []), { encoding: 'utf8' }); }
const gone = (f, rel) => !fs.existsSync(path.join(f.site, rel));

test('unreferenced theme scripts and fonts are removed; referenced ones stay (control: the live font and the lazy chunk)', () => {
  const f = fixture();
  try {
    const r = run(f);
    assert.strictEqual(r.status, 0, r.stdout);
    assert.ok(gone(f, 'assets/js/main.min.js'));
    assert.ok(gone(f, 'assets/js/vendor/mermaid.min.js'));
    assert.ok(gone(f, 'assets/fonts/fa/fa.woff2'));
    assert.ok(!gone(f, 'assets/fonts/sans/sans.woff2'), 'a font named only by a kept stylesheet stays');
    assert.ok(!gone(f, 'assets/js/lazy/chunk.js'), 'a file named by a script string stays');
    assert.ok(!gone(f, 'assets/js/own.js'), 'a source-owned file is never a candidate');
    assert.match(r.stdout, /scanned\s+1 pages/);
    assert.match(r.stdout, /removed\s+3 files/);
    assert.match(r.stdout, /0 reference\(s\) to a removed path/);
  } finally { fs.rmSync(f.d, { recursive: true, force: true }); }
});

test('a page that references a theme file keeps it (the measurement, not a name list)', () => {
  const f = fixture('<script src="/assets/js/main.min.js"></script>');
  try {
    const r = run(f);
    assert.strictEqual(r.status, 0, r.stdout);
    assert.ok(!gone(f, 'assets/js/main.min.js'));
    assert.ok(gone(f, 'assets/js/vendor/mermaid.min.js'));
  } finally { fs.rmSync(f.d, { recursive: true, force: true }); }
});

test('the reference check fails on a page that names a removed file (planted after the prune)', () => {
  const f = fixture();
  try {
    const list = path.join(f.d, 'removed.txt');
    assert.strictEqual(run(f, ['--removed-out', list]).status, 0);
    assert.match(fs.readFileSync(list, 'utf8'), /assets\/js\/main\.min\.js/);
    const verify = () => spawnSync(process.execPath, [GATE, '--site', f.site, '--verify', list], { encoding: 'utf8' });
    assert.strictEqual(verify().status, 0, 'control: the pruned site passes');
    const page = path.join(f.site, 'index.html');
    fs.writeFileSync(page, fs.readFileSync(page, 'utf8').replace('</head>', '<script src="/assets/js/main.min.js"></script></head>'));
    const r = verify();
    assert.strictEqual(r.status, 1, r.stdout);
    assert.match(r.stdout, /FAIL  index\.html -> assets\/js\/main\.min\.js/);
  } finally { fs.rmSync(f.d, { recursive: true, force: true }); }
});

test('a site with no pages, or no theme-only file, is NOT CHECKED, never a pass', () => {
  const f = fixture();
  try {
    fs.rmSync(path.join(f.site, 'index.html'));
    assert.strictEqual(run(f).status, 2);
    const g = fixture();
    try {
      fs.rmSync(path.join(g.site, 'assets/js/main.min.js'));
      fs.rmSync(path.join(g.site, 'assets/js/vendor'), { recursive: true });
      fs.rmSync(path.join(g.site, 'assets/js/lazy'), { recursive: true });
      fs.rmSync(path.join(g.site, 'assets/fonts'), { recursive: true });
      assert.strictEqual(run(g).status, 2);
    } finally { fs.rmSync(g.d, { recursive: true, force: true }); }
  } finally { fs.rmSync(f.d, { recursive: true, force: true }); }
});
