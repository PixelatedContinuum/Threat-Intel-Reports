'use strict';

/* A59 (T-0603): shapes the rendered-page defang gate (check-defang.js --site) does not flag
   today. This file does NOT change what the gate flags; it documents the gap. The gate is a
   safety control and widening it needs its own review (decision: tasks/runs/T-0603/build-Gg-report.md).

   Each gap is a `todo` test: it states the behaviour wanted, fails today, and is reported as todo
   rather than as a failure. When the gate learns the shape, the todo starts passing and the
   marker must be removed. The control tests (no todo) must pass today and keep the file honest:
   a raw IP is flagged, its defanged twin is not. Fixture addresses are RFC 5737 documentation
   ranges. Runs check-defang.js as a process; no browser. */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const GATE = path.join(__dirname, '..', 'check-defang.js');

function scan(mainHtml) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-gap-'));
  try {
    fs.writeFileSync(path.join(d, 'index.html'),
      '<!DOCTYPE html><html><body><main>' + mainHtml + '</main></body></html>');
    return spawnSync(process.execPath, [GATE, '--site', d, '--all', '--pages-only'], { encoding: 'utf8' });
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
}

test('control: a raw IP in a page is flagged (exit 1) and its defanged twin passes (exit 0)', () => {
  const raw = scan('<p>C2 at 203.0.113.5 seen</p>');
  assert.strictEqual(raw.status, 1, raw.stdout);
  assert.match(raw.stdout, /FINDING .* IPV4 /);
  const twin = scan('<p>C2 at 203[.]0[.]113[.]5 seen</p>');
  assert.strictEqual(twin.status, 0, twin.stdout);
});

test('today: an IP link host in hex is caught, but only as an unlisted host (LINK-UNLISTED)', () => {
  const r = scan('<p>x</p><a href="http://0xCB007105/x">go</a>');
  assert.strictEqual(r.status, 1, r.stdout);
  assert.match(r.stdout, /LINK-UNLISTED/);
});

test('today: an IP link host in decimal is caught, but only as an unlisted host (LINK-UNLISTED)', () => {
  const r = scan('<p>x</p><a href="http://3405803781/x">go</a>');
  assert.strictEqual(r.status, 1, r.stdout);
  assert.match(r.stdout, /LINK-UNLISTED/);
});

test('GAP A59: a hex IP link host is reported as a link to an IP (LINK-IP)', { todo: 'A59: reported only as LINK-UNLISTED, so an allow-listed hex host would pass' }, () => {
  const r = scan('<p>x</p><a href="http://0xCB007105/x">go</a>');
  assert.match(r.stdout, /LINK-IP/);
});

test('GAP A59: a decimal IP link host is reported as a link to an IP (LINK-IP)', { todo: 'A59: reported only as LINK-UNLISTED' }, () => {
  const r = scan('<p>x</p><a href="http://3405803781/x">go</a>');
  assert.match(r.stdout, /LINK-IP/);
});

test('GAP A59: an IP with markup around one octet is flagged', { todo: 'A59: 203.0.<b>113</b>.5 passes with exit 0' }, () => {
  const r = scan('<p>C2 at 203.0.<b>113</b>.5 seen</p>');
  assert.strictEqual(r.status, 1, 'exit ' + r.status + ': ' + r.stdout.split('\n').pop());
});

test('GAP A59: an indicator inside <noscript> is flagged', { todo: 'A59: noscript text is not scanned; the page passes' }, () => {
  const r = scan('<p>hello world</p><noscript>C2 at 203.0.113.5</noscript>');
  assert.strictEqual(r.status, 1, 'exit ' + r.status);
});

test('GAP A59: an indicator inside <template> is flagged', { todo: 'A59: template text is not scanned; the page passes' }, () => {
  const r = scan('<p>hello world</p><template>C2 at 203.0.113.5</template>');
  assert.strictEqual(r.status, 1, 'exit ' + r.status);
});
