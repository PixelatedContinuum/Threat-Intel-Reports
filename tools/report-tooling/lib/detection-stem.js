'use strict';
/* Resolve a catalog detection_url to its detection file's stem (the file
   name without .md) by the page's own `permalink:`, not by the URL's last
   segment. The two differ for a page whose permalink was shortened, e.g.
   /hunting-detections/inv-2026-082-detections/ is served from
   inv-2026-082-agent-platform-command-channel-detections.md (T-0635). Keying
   by the URL tail made the MISP generator fail to read that page and made the
   technique and actor joins miss its rows. A URL with no matching permalink
   falls back to the old tail rule, so fixtures and the 64 pages whose name
   equals their permalink resolve exactly as before. */
var fs = require('node:fs');
var path = require('node:path');

var DIR = path.join(__dirname, '..', '..', '..', 'hunting-detections');
var cache = null;

function norm(u) { return String(u || '').replace(/\/+$/, ''); }

function load() {
  cache = Object.create(null);
  var files;
  try { files = fs.readdirSync(DIR); } catch (e) { return; }
  files.forEach(function (f) {
    if (!/\.md$/.test(f)) return;
    var text;
    try { text = fs.readFileSync(path.join(DIR, f), 'utf8'); } catch (e) { return; }
    var fm = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
    if (!fm) return;
    var p = /^permalink:\s*["']?([^"'\s#]+)/m.exec(fm[1]);
    if (p) cache[norm(p[1])] = f.replace(/\.md$/, '');
  });
}

function detectionStem(url) {
  if (cache === null) load();
  var u = norm(url);
  return u in cache ? cache[u] : u.split('/').pop();
}

module.exports = { detectionStem: detectionStem };
