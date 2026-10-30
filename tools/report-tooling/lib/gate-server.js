'use strict';

/* A local server for the new-report gates (T-0500.1.9). Stands the two renders
   from render-report.rb up at the URLs the gates ask for, over BOTH http (the
   completeness gate drives Chrome at it) and https (check-browser-report.js
   fetches the page with https.get before it opens it).

     /reports/<slug>/        the tagged render
     /__baseline/untagged/   the untagged render (the completeness baseline)
     /assets/css/custom.css  the compiled stylesheet from the working tree
     /assets/...             the working tree's own assets, so the page runs the
                             CSS and JS under test and not the deployed copies
     anything else           fetched from the live site (the theme's main.css,
                             main.min.js and fonts exist nowhere in this repo)

   The live fetch is a REAL dependency, so it is checked before the ready file is
   written: when main.css or main.min.js cannot be had, the server exits 3 and
   says so, and new-report-gates.sh reports the browser gates NOT CHECKED. A page
   styled by a missing stylesheet would FAIL for the wrong reason or, worse, pass
   by measuring nothing.

   Usage: node lib/gate-server.js --tagged <html> --untagged <html> --css <css>
            --slug <slug> --cert <pem> --key <pem> --ready <json file>
          [--live https://the-hunters-ledger.com]
   Writes { http, https } ports (ephemeral) to --ready once listening. SIGTERM
   closes both. Read-only: it never writes the working tree. */

var http = require('node:http');
var https = require('node:https');
var fs = require('node:fs');
var path = require('node:path');

var ROOT = path.join(__dirname, '..', '..', '..');

var TYPES = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript',
  '.woff2': 'font/woff2', '.woff': 'font/woff', '.ttf': 'font/ttf', '.eot': 'application/vnd.ms-fontobject',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp',
  '.svg': 'image/svg+xml', '.gif': 'image/gif', '.ico': 'image/x-icon',
  '.json': 'application/json', '.txt': 'text/plain; charset=utf-8', '.xml': 'application/xml'
};

function parseArgs(argv) {
  var o = {};
  for (var i = 0; i < argv.length; i++) {
    if (/^--/.test(argv[i])) o[argv[i].slice(2)] = argv[i + 1], i++;
  }
  return o;
}

function liveGet(base, urlPath, cb) {
  https.get(base + urlPath, { headers: { 'user-agent': 'hl-gate-server' } }, function (up) {
    var chunks = [];
    up.on('data', function (d) { chunks.push(d); });
    up.on('end', function () {
      cb(null, { status: up.statusCode, type: up.headers['content-type'], body: Buffer.concat(chunks) });
    });
  }).on('error', function (e) { cb(e); });
}

function main() {
  var a = parseArgs(process.argv.slice(2));
  ['tagged', 'untagged', 'css', 'slug', 'cert', 'key', 'ready'].forEach(function (k) {
    if (!a[k]) { console.error('gate-server: --' + k + ' is required'); process.exit(2); }
  });
  var live = (a.live || 'https://the-hunters-ledger.com').replace(/\/+$/, '');
  var cache = {};

  function respondFile(res, file, type) {
    res.writeHead(200, { 'content-type': type || TYPES[path.extname(file).toLowerCase()] || 'application/octet-stream', 'cache-control': 'no-store' });
    fs.createReadStream(file).pipe(res);
  }

  function handler(req, res) {
    var urlPath = req.url.split('?')[0];
    var decoded;
    try { decoded = decodeURIComponent(urlPath); } catch (e) { res.writeHead(400); return res.end(); }

    if (decoded === '/reports/' + a.slug + '/') return respondFile(res, a.tagged, TYPES['.html']);
    if (decoded === '/__baseline/untagged/') return respondFile(res, a.untagged, TYPES['.html']);
    if (decoded === '/assets/css/custom.css') return respondFile(res, a.css, TYPES['.css']);

    if (/^\/assets\//.test(decoded)) {
      var file = path.join(ROOT, decoded);
      if (file.indexOf(path.join(ROOT, 'assets')) === 0 && fs.existsSync(file) && fs.statSync(file).isFile()) {
        return respondFile(res, file);
      }
    }

    if (cache[urlPath]) {
      res.writeHead(200, { 'content-type': cache[urlPath].type });
      return res.end(cache[urlPath].body);
    }
    liveGet(live, req.url, function (err, r) {
      if (err || r.status !== 200) {
        console.error('miss ' + urlPath + ' ' + (err ? err.message : 'live ' + r.status));
        res.writeHead(404); return res.end('not found');
      }
      var type = r.type || TYPES[path.extname(urlPath).toLowerCase()] || 'application/octet-stream';
      cache[urlPath] = { type: type, body: r.body };
      res.writeHead(200, { 'content-type': type });
      res.end(r.body);
    });
  }

  function fail(reason) {
    fs.writeFileSync(a.ready, JSON.stringify({ error: reason }));
    console.error('gate-server: ' + reason);
    process.exit(3);
  }

  // The two theme assets the page cannot run without, fetched before anything is served.
  var need = ['/assets/css/main.css', '/assets/js/main.min.js'];
  var pending = need.length;
  need.forEach(function (p) {
    liveGet(live, p, function (err, r) {
      if (err || r.status !== 200) {
        return fail('the theme asset ' + p + ' could not be fetched from ' + live + ' (' +
          (err ? err.message : 'HTTP ' + r.status) + '); the page would run unstyled');
      }
      cache[p] = { type: r.type || TYPES[path.extname(p)], body: r.body };
      if (--pending === 0) listen();
    });
  });

  function listen() {
    var h = http.createServer(handler);
    var s = https.createServer({ key: fs.readFileSync(a.key), cert: fs.readFileSync(a.cert) }, handler);
    h.listen(0, '127.0.0.1', function () {
      s.listen(0, '127.0.0.1', function () {
        fs.writeFileSync(a.ready, JSON.stringify({ http: h.address().port, https: s.address().port }));
      });
    });
    function stop() { h.close(); s.close(); process.exit(0); }
    process.on('SIGTERM', stop);
    process.on('SIGINT', stop);
  }
}

if (require.main === module) main();
module.exports = { parseArgs: parseArgs };
