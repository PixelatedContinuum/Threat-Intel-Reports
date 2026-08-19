'use strict';

/* Tests for lib/page-server.js, the local server the browser checks run against.

   It decides which bytes the page under test actually receives, so its mistakes
   are the expensive kind: serving a DEPLOYED asset where the working-tree one
   was meant would make every check green while testing nothing that changed. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var os = require('node:os');
var path = require('node:path');
var http = require('node:http');
var PS = require('../lib/page-server.js');

function get(origin, p) {
  return new Promise(function (resolve, reject) {
    http.get(origin + p, function (res) {
      var b = '';
      res.on('data', function (d) { b += d; });
      res.on('end', function () {
        resolve({ status: res.statusCode, type: res.headers['content-type'], body: b });
      });
    }).on('error', reject);
  });
}

function tmpRoot() {
  var d = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-page-server-'));
  fs.mkdirSync(path.join(d, 'assets', 'js'), { recursive: true });
  fs.writeFileSync(path.join(d, 'assets', 'js', 'local.js'), 'window.__local=1;');
  fs.writeFileSync(path.join(d, 'assets', 'style.css'), 'body{color:red}');
  return d;
}

test('a registered page path is served as HTML', async function () {
  var root = tmpRoot();
  var srv = await PS.start({ '/wire/': '<html>hello</html>' }, { root: root });
  try {
    var r = await get(srv.origin, '/wire/');
    assert.equal(r.status, 200);
    assert.match(r.type, /text\/html/);
    assert.equal(r.body, '<html>hello</html>');
  } finally { srv.close(); }
});

test('an asset present in the working tree is served from disk, not proxied', async function () {
  /* This is the whole point of the harness. If the deployed copy were served
     instead, every check would pass while testing code that is already live. */
  var root = tmpRoot();
  var srv = await PS.start({ '/p/': 'x' }, { root: root, base: 'https://example.invalid' });
  try {
    var r = await get(srv.origin, '/assets/js/local.js');
    assert.equal(r.status, 200);
    assert.equal(r.body, 'window.__local=1;');
    assert.match(r.type, /javascript/);
    assert.deepEqual(srv.misses, [], 'a local hit must not be recorded as a miss');
  } finally { srv.close(); }
});

test('a query string does not defeat the lookup', async function () {
  // Every script on the site is cache-busted with ?v=N.
  var root = tmpRoot();
  var srv = await PS.start({}, { root: root });
  try {
    var r = await get(srv.origin, '/assets/js/local.js?v=10');
    assert.equal(r.status, 200);
    assert.equal(r.body, 'window.__local=1;');
  } finally { srv.close(); }
});

test('an asset in neither place is a 404 AND is named', async function () {
  // A bare 404 in a console check says nothing about which asset went missing.
  var root = tmpRoot();
  var srv = await PS.start({}, { root: root });
  try {
    var r = await get(srv.origin, '/assets/js/nope.js');
    assert.equal(r.status, 404);
    assert.deepEqual(srv.misses, ['/assets/js/nope.js']);
  } finally { srv.close(); }
});

test('a path escaping the root is refused rather than served', async function () {
  var root = tmpRoot();
  var srv = await PS.start({}, { root: root });
  try {
    var r = await get(srv.origin, '/../../../etc/passwd');
    assert.equal(r.status, 404);
  } finally { srv.close(); }
});

test('a directory is not served as a file', async function () {
  var root = tmpRoot();
  var srv = await PS.start({}, { root: root });
  try {
    var r = await get(srv.origin, '/assets/js');
    assert.equal(r.status, 404);
  } finally { srv.close(); }
});

test('content types cover the asset kinds a report page loads', function () {
  assert.match(PS.contentType('a.css'), /text\/css/);
  assert.match(PS.contentType('a.js'), /javascript/);
  assert.match(PS.contentType('a.woff2'), /font\/woff2/);
  assert.match(PS.contentType('a.svg'), /image\/svg/);
  assert.match(PS.contentType('a.png'), /image\/png/);
  // An unknown extension must not be guessed as HTML.
  assert.equal(PS.contentType('a.zzz'), 'application/octet-stream');
});

test('with no base configured, a miss is a plain 404 rather than a hang', async function () {
  var root = tmpRoot();
  var srv = await PS.start({}, { root: root });
  try {
    var r = await get(srv.origin, '/assets/js/absent.js');
    assert.equal(r.status, 404);
    assert.equal(srv.misses.length, 1);
  } finally { srv.close(); }
});

test('a proxy failure is recorded as a named miss, not a silent success', async function () {
  // The theme's own fonts come from the Jekyll gem and exist only on the live
  // site; when that is unreachable the check must say which asset it lost.
  var root = tmpRoot();
  var srv = await PS.start({}, { root: root, base: 'https://no-such-host.invalid' });
  try {
    var r = await get(srv.origin, '/assets/fonts/theme.woff2');
    assert.equal(r.status, 404);
    assert.equal(srv.misses.length, 1);
    assert.match(srv.misses[0], /theme\.woff2/);
    assert.match(srv.misses[0], /proxy failed/);
  } finally { srv.close(); }
});
