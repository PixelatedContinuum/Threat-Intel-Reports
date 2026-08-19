'use strict';

/* A local HTTP server that stands a published page up against the working tree.

   WHY HTTP AND NOT file://. A published page's asset URLs are root-relative, so
   under file:// they resolve against the drive root, the font request fails CORS
   outright, and the console fills with errors that say nothing about the page.
   Masking those would mean a console check that could never fail.

   WHY IT SERVES THE WORKING TREE. Everything under /assets/ that exists in this
   repo is served from disk, so the page loads the CSS and JS being tested rather
   than the copies already deployed. That is the whole point: the page structure
   is real and published, the behaviour under test is local.

   WHY IT PROXIES THE REST. Not everything the page loads lives here. `main.css`
   and `main.min.js` are Jekyll-built, the theme's fonts come out of the gem, and
   vendor bundles are copied at build time. Those exist on the published site and
   nowhere in the working tree. Proxying them beats carving an exclusion into the
   console check, because an exclusion wide enough to cover them would also hide
   a genuinely missing asset. Anything missing in BOTH places is named. */

var http = require('node:http');
var https = require('node:https');
var path = require('node:path');
var fs = require('node:fs');

var TYPES = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript',
  '.woff2': 'font/woff2', '.woff': 'font/woff', '.ttf': 'font/ttf', '.eot': 'application/vnd.ms-fontobject',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp',
  '.svg': 'image/svg+xml', '.gif': 'image/gif', '.ico': 'image/x-icon',
  '.json': 'application/json', '.txt': 'text/plain; charset=utf-8', '.xml': 'application/xml'
};

function contentType(file) {
  return TYPES[path.extname(file).toLowerCase()] || 'application/octet-stream';
}

/* `pages` maps a URL path to the HTML to serve there, e.g.
   { '/wire/': '<html>…' }. `opts.root` is the repo root, `opts.base` the live
   origin to proxy misses to. Resolves to a handle with `origin`, `misses` and
   `close()`. */
function start(pages, opts) {
  opts = opts || {};
  var root = opts.root;
  var base = (opts.base || '').replace(/\/+$/, '');
  var misses = [];

  return new Promise(function (resolve) {
    var srv = http.createServer(function (req, res) {
      var url = req.url.split('?')[0];

      if (Object.prototype.hasOwnProperty.call(pages, url)) {
        res.writeHead(200, { 'content-type': TYPES['.html'] });
        return res.end(pages[url]);
      }

      var rel = decodeURIComponent(url).replace(/^\/+/, '');
      var file = path.join(root, rel);
      // Never serve outside the repo, whatever the request says.
      var inRepo = file.indexOf(root) === 0;
      if (inRepo && fs.existsSync(file) && !fs.statSync(file).isDirectory()) {
        res.writeHead(200, { 'content-type': contentType(file) });
        return fs.createReadStream(file).pipe(res);
      }

      if (!base) {
        misses.push(url);
        res.writeHead(404); return res.end('not found');
      }
      return https.get(base + url, function (up) {
        if (up.statusCode !== 200) {
          up.resume();
          misses.push(url + ' (live ' + up.statusCode + ')');
          res.writeHead(404); return res.end('not found');
        }
        res.writeHead(200, { 'content-type': up.headers['content-type'] || contentType(url) });
        up.pipe(res);
      }).on('error', function (e) {
        misses.push(url + ' (proxy failed: ' + e.message + ')');
        res.writeHead(404); res.end('not found');
      });
    });

    srv.listen(0, '127.0.0.1', function () {
      resolve({
        origin: 'http://127.0.0.1:' + srv.address().port,
        misses: misses,
        close: function () { try { srv.close(); } catch (e) { /* already gone */ } }
      });
    });
  });
}

module.exports = { start: start, contentType: contentType, TYPES: TYPES };
