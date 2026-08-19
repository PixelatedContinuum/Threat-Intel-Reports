/* /lookup/ : paste anything, see which values appear in a published investigation.

   Everything happens here, in the browser. The index is fetched once and the
   comparison is local, so the pasted text is never transmitted. That is a
   property of the design rather than a promise, and the page says so.

   Matching goes through the SAME ioc-classify.js the index generator used. If
   this page normalised differently, every lookup would quietly return nothing
   and read as a clean bill of health. */
(function () {
  'use strict';
  var root = document.querySelector('.hl-lookup');
  if (!root || !window.HLIocClassify) return;

  var C = window.HLIocClassify;
  var input = root.querySelector('.hl-lookup__in');
  var go = root.querySelector('.hl-lookup__go');
  var status = root.querySelector('.hl-lookup__status');
  var out = root.querySelector('.hl-lookup__out');
  var index = null, loading = null;

  var INDEX_URL = '/assets/data/ioc-index.json';

  function load() {
    if (index) return Promise.resolve(index);
    if (loading) return loading;
    status.textContent = 'Loading index…';
    loading = fetch(INDEX_URL, { credentials: 'omit' }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    }).then(function (j) { index = j; return j; });
    return loading;
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }

  function renderHit(found, idx) {
    var reps = idx.indicators[found.type + ':' + found.value];
    var rows = reps.map(function (r) {
      var m = idx.reports[r.report] || {};
      var links = [];
      if (m.report_url) links.push('<a href="' + esc(m.report_url) + '">Report</a>');
      if (m.detection_url) links.push('<a href="' + esc(m.detection_url) + '">Detection rules</a>');
      if (m.ioc_url) links.push('<a href="' + esc(m.ioc_url) + '">IOC feed</a>');
      return '<div class="hl-lookup__hitrow">' +
        '<span class="hl-lookup__campaign">' + esc(m.title || r.report) + '</span>' +
        (m.date ? '<span class="hl-lookup__meta">' + esc(m.date) + '</span>' : '') +
        (m.severity ? '<span class="hl-sev-tag hl-sev--' + esc(m.severity) + '">' +
           esc(String(m.severity).toUpperCase()) + '</span>' : '') +
        (r.role ? '<span class="hl-lookup__role">' + esc(r.role) + '</span>' : '') +
        '<span class="hl-lookup__links">' + links.join(' ') + '</span></div>';
    }).join('');
    return '<div class="hl-lookup__hit">' +
      '<div class="hl-lookup__val"><code>' + esc(found.value) + '</code>' +
      '<span class="hl-lookup__type">' + esc(found.type) + '</span>' +
      (reps.length > 1 ? '<span class="hl-lookup__multi">in ' + reps.length +
        ' investigations</span>' : '') + '</div>' + rows + '</div>';
  }

  function run() {
    var text = input.value || '';
    if (!text.trim()) { status.textContent = 'Paste something first.'; out.innerHTML = ''; return; }
    go.disabled = true;
    load().then(function (idx) {
      var found = C.extract(text);
      var hits = found.filter(function (f) { return idx.indicators[f.type + ':' + f.value]; });
      // The checked count matters: silence would be indistinguishable from a
      // broken extractor, and "no match" has to read as a real negative.
      status.textContent = found.length + ' indicator' + (found.length === 1 ? '' : 's') +
        ' found in your text, ' + hits.length + ' matched.';
      if (!found.length) {
        out.innerHTML = '<p class="hl-lookup__none">No IPs, domains, URLs or hashes were ' +
          'recognised in that text.</p>';
      } else if (!hits.length) {
        out.innerHTML = '<p class="hl-lookup__none">None of the ' + found.length +
          ' indicators found in your text appear in any published investigation.</p>';
      } else {
        out.innerHTML = hits.map(function (h) { return renderHit(h, idx); }).join('');
      }
    })['catch'](function (e) {
      status.textContent = 'Could not load the indicator index (' + e.message + ').';
    }).then(function () { go.disabled = false; });
  }

  go.addEventListener('click', run);
  input.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') run();
  });
})();
