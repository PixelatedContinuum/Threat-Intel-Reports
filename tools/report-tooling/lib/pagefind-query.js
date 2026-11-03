'use strict';

/* Query a built Pagefind bundle from Node (T-0548). pagefind.js is the browser module, so this gives it the three things it asks of a browser: window.location,
   a fetch that reads the bundle from disk, and import.meta.url (the bundle is imported from its own file, so its base path derives). Used by the tests and by the
   measurement runs; the shipped site never loads it.

     var Q = require('./lib/pagefind-query.js');
     var out = await Q.search('<_site>/pagefind', 'langflow', { filters: { section: 'Wire: CVEs' } });   // [{ url, title, section, score, meta }]
*/

var fs = require('node:fs');
var path = require('node:path');
var url = require('node:url');

async function search(bundleDir, term, opts) {
  opts = opts || {};
  var abs = path.resolve(bundleDir), root = path.dirname(abs);   // the bundle sits at <site>/<name>; URLs are /<name>/..., so a merged second bundle (<site>/pagefind-wire) resolves too
  var g = globalThis;
  g.window = g.window || { location: { origin: 'http://localhost', href: 'http://localhost/' } };
  g.location = g.location || g.window.location;
  g.document = g.document || { querySelector: function () { return { getAttribute: function () { return 'en'; } }; } };
  var realFetch = g.fetch;
  g.fetch = async function (u) {
    var s = String(u);
    var m = s.match(/^(?:https?:\/\/[^\/]+)?\/(pagefind[^\/]*\/[^?]*)/);
    if (!m) return realFetch(u);
    var f = path.join(root, decodeURIComponent(m[1]));
    if (!fs.existsSync(f)) return new Response('', { status: 404 });
    var buf = fs.readFileSync(f);
    return new Response(buf, { status: 200, headers: { 'Content-Type': /\.wasm$/.test(f) ? 'application/wasm' : 'application/octet-stream' } });
  };
  try {
    // a fresh module instance per call (query string), so rankings from an earlier call do not carry over
    var pf = await import(url.pathToFileURL(path.join(abs, 'pagefind.js')).href + '?q=' + Date.now() + Math.random());
    await pf.options(Object.assign({ basePath: '/' + path.basename(abs) + '/' }, opts.options || {}));
    for (var mi = 0; mi < (opts.merge || []).length; mi++) await pf.mergeIndex(opts.merge[mi].path, opts.merge[mi].options || {});
    var res = await pf.search(term, opts.filters ? { filters: opts.filters } : {});
    var out = [];
    for (var i = 0; i < res.results.length; i++) {
      var d = await res.results[i].data();
      out.push({ url: d.url, title: (d.meta && d.meta.title) || '', section: (d.filters && d.filters.section) || [], score: res.results[i].score, meta: d.meta, excerpt: d.excerpt });
    }
    try { await pf.destroy(); } catch (e) { /* older bundles have no destroy */ }
    return out;
  } finally { g.fetch = realFetch; }
}

module.exports = { search: search };
