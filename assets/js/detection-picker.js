/* The Hunter's Ledger: detection picker.
   Filters the rules on a detection page by engine and tier, and assembles a
   selection into engine-native files a defender can deploy.

   The manifest is generated from the markdown source at publish time and
   addresses each rule by the index of its code fence. That reference is
   positional, so before trusting any of it the picker recomputes the hash of
   the fence it was pointed at and compares. A rule that fails is disabled with
   a reason rather than offered: a wrong rule downloaded silently is discovered
   in production, a refused one is discovered on the page.

   The check hashes the whole body rather than its opening characters, because
   YARA rules here open with a boilerplate comment and on 15 of 56 pages two or
   more rules share their first 48 characters. A prefix several rules share
   cannot detect the swap it exists to detect. */
(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('./hl-hash.js'));
  } else {
    root.HLDetectionPicker = factory(root.HLHash);
    root.HLDetectionPicker.init();
  }
})(typeof self !== 'undefined' ? self : this, function (H) {
  'use strict';

  var EXT = { yara: '.yar', sigma: '.yml', suricata: '.rules' };
  var LABEL = { yara: 'YARA', sigma: 'Sigma', suricata: 'Suricata' };
  // Sigma bundles are YAML, where # is the comment marker. The other two accept
  // C-style comments, and a header that is not a comment breaks the parse.
  var COMMENT = { yara: '//', suricata: '#', sigma: '#' };

  function filenameFor(slug, engine) {
    return slug + '-' + engine + (EXT[engine] || '.txt');
  }

  function applyFilters(rules, f) {
    return rules.filter(function (r) {
      if (f.engine && r.engine !== f.engine) return false;
      if (f.tier && r.tier !== f.tier) return false;
      return true;
    });
  }

  /* Resolves each manifest entry against the page's own fences, verifying the
     hash before accepting one. Returns three lists rather than two, because a
     cross-referenced rule is a known state and must not be counted as a
     verification failure. */
  function bind(rootEl, rules, doc) {
    var blocks = rootEl.querySelectorAll('pre > code');
    var ok = [], mismatched = [], crossReferenced = [];
    rules.forEach(function (r) {
      if (r.cross_referenced) { crossReferenced.push(r); return; }
      var el = blocks[r.fence];
      if (!el) {
        mismatched.push({ rule: r, reason: 'fence ' + r.fence + ' does not exist on this page' });
        return;
      }
      var body = el.textContent;
      if (H.ruleHash(body) !== r.hash) {
        mismatched.push({
          rule: r,
          reason: 'fence ' + r.fence + ' does not match the manifest for "' + r.name + '"'
        });
        return;
      }
      ok.push({ rule: r, name: r.name, engine: r.engine, tier: r.tier, body: body, el: el });
    });
    return { ok: ok, mismatched: mismatched, crossReferenced: crossReferenced };
  }

  function header(engine, slug) {
    var c = COMMENT[engine] || '#';
    return [
      c + ' ' + (LABEL[engine] || engine) + ' rules for ' + slug,
      c + ' The Hunters Ledger, https://the-hunters-ledger.com/hunting-detections/' + slug + '/',
      c + ' Licensed CC BY 4.0, free to use with attribution.',
      ''
    ].join('\n');
  }

  /* Imports are lifted out of each body and emitted once at the top, which is
     the canonical form YARA documents and keeps a 20-rule bundle from repeating
     the same import 20 times.

     Measured, so the comment does not overclaim: yarac 4.5.5 accepts imports
     between complete rules and accepts duplicates, so a naive concatenation
     would also compile. What it rejects is an import inside a rule block, which
     concatenation never produces. This is tidiness and convention, not a rescue. */
  function bundleYara(rules) {
    var imports = [], bodies = [];
    rules.forEach(function (r) {
      var kept = [];
      String(r.body).split(/\r?\n/).forEach(function (ln) {
        if (/^\s*import\s+"/.test(ln)) {
          var t = ln.trim();
          if (imports.indexOf(t) === -1) imports.push(t);
        } else {
          kept.push(ln);
        }
      });
      bodies.push(kept.join('\n').replace(/^\s*\n+/, '').replace(/\s+$/, ''));
    });
    return imports.join('\n') + (imports.length ? '\n\n' : '') + bodies.join('\n\n') + '\n';
  }

  function bundle(engine, rules, slug) {
    var out;
    if (engine === 'yara') {
      out = bundleYara(rules);
    } else if (engine === 'sigma') {
      out = rules.map(function (r) { return String(r.body).replace(/\s+$/, ''); }).join('\n---\n') + '\n';
    } else {
      out = rules.map(function (r) { return String(r.body).replace(/\s+$/, ''); }).join('\n') + '\n';
    }
    return header(engine, slug) + out;
  }

  function download(doc, filename, text) {
    var blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = doc.createElement('a');
    a.href = url;
    a.download = filename;
    doc.body.appendChild(a);
    a.click();
    doc.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 0);
  }

  /* The block a fence occupies at the top level of the content.

     Necessary because one page renders fences two different ways. A fence with
     a language Rouge does not highlight comes through as a bare pre > code
     sitting directly under the content div, while a highlighted one is wrapped
     as div.language-x > div.highlight > pre > code. Walking siblings from the
     pre finds the heading in the first shape and nothing at all in the second,
     which on the multivector page gave 5 of 22 rules a checkbox.

     It is also the element to hide when filtering: hiding the inner pre would
     leave the wrapper div behind as an empty box. */
  function blockFor(codeEl, rootEl) {
    var n = codeEl;
    while (n && n.parentNode && n.parentNode !== rootEl) n = n.parentNode;
    return n && n.parentNode === rootEl ? n : null;
  }

  // The heading that owns a fence is the nearest preceding h4.
  function headingFor(codeEl, rootEl) {
    var n = blockFor(codeEl, rootEl);
    if (!n) return null;
    while (n && n.previousElementSibling) {
      n = n.previousElementSibling;
      if (n.tagName === 'H4') return n;
      if (/^H[123]$/.test(n.tagName)) return null;
    }
    return null;
  }

  function chip(doc, kind, val, label) {
    var b = doc.createElement('button');
    b.className = 'hl-picker__chip';
    b.setAttribute('data-kind', kind);
    b.setAttribute('data-val', val);
    b.setAttribute('aria-pressed', 'false');
    b.textContent = label;
    return b;
  }

  function render(doc, body, bound, slug) {
    var state = { engine: null, tier: null, selected: {} };

    var panel = doc.createElement('div');
    panel.className = 'hl-picker';
    panel.innerHTML =
      '<div class="hl-picker__head"><span class="hl-picker__label">Rule picker</span>' +
      '<span class="hl-picker__count"></span></div>' +
      '<div class="hl-picker__filters"></div>' +
      '<div class="hl-picker__actions">' +
      '<button class="hl-picker__btn" data-act="all">Select all shown</button>' +
      '<button class="hl-picker__btn" data-act="none">Clear</button>' +
      '<button class="hl-picker__btn" data-act="dl" disabled>Download selected</button>' +
      '<span class="hl-picker__note"></span></div>' +
      '<div class="hl-picker__warn"></div>';

    var filters = panel.querySelector('.hl-picker__filters');
    var engines = [], tiers = [];
    bound.ok.forEach(function (b) {
      if (engines.indexOf(b.engine) === -1) engines.push(b.engine);
      if (tiers.indexOf(b.tier) === -1) tiers.push(b.tier);
    });
    engines.forEach(function (e) { filters.appendChild(chip(doc, 'engine', e, LABEL[e] || e)); });
    tiers.forEach(function (t) { filters.appendChild(chip(doc, 'tier', t, t)); });

    // A checkbox beside each rule's heading, so selection happens where the
    // reader is reading rather than in a list detached from the rules.
    bound.ok.forEach(function (b, i) {
      var h = headingFor(b.el, body);
      b.block = blockFor(b.el, body);
      if (!h) return;
      var cb = doc.createElement('input');
      cb.type = 'checkbox';
      cb.className = 'hl-rule-pick';
      cb.setAttribute('data-i', String(i));
      cb.setAttribute('aria-label', 'Select ' + b.name);
      h.insertBefore(cb, h.firstChild);
      b.heading = h;
    });

    var warn = [];
    if (bound.mismatched.length) {
      warn.push(bound.mismatched.length + ' rule(s) could not be verified against this page and ' +
        'are not selectable: ' +
        bound.mismatched.slice(0, 3).map(function (m) { return m.reason; }).join('; '));
    }
    if (bound.crossReferenced.length) {
      warn.push(bound.crossReferenced.length + ' rule(s) are bundled inside another rule’s ' +
        'block and can only be taken with it: ' +
        bound.crossReferenced.map(function (r) { return r.name; }).join('; '));
    }
    panel.querySelector('.hl-picker__warn').textContent = warn.join(' ');

    body.insertBefore(panel, body.firstChild);

    function visible() {
      var shown = applyFilters(bound.ok.map(function (b) { return b.rule; }), state);
      var idx = [];
      bound.ok.forEach(function (b, i) { if (shown.indexOf(b.rule) !== -1) idx.push(String(i)); });
      return idx;
    }

    function syncBoxes() {
      bound.ok.forEach(function (b, i) {
        var cb = b.heading && b.heading.querySelector('.hl-rule-pick');
        if (cb) cb.checked = !!state.selected[String(i)];
      });
    }

    function refresh() {
      var vis = visible();
      bound.ok.forEach(function (b, i) {
        var on = vis.indexOf(String(i)) !== -1;
        if (b.heading) b.heading.classList.toggle('hl-rule-hidden', !on);
        if (b.block) b.block.classList.toggle('hl-rule-hidden', !on);
      });
      var n = Object.keys(state.selected).length;
      panel.querySelector('.hl-picker__count').textContent =
        vis.length + ' of ' + bound.ok.length + ' rules shown, ' + n + ' selected';
      panel.querySelector('.hl-picker__btn[data-act="dl"]').disabled = n === 0;
    }

    function doDownload() {
      var byEngine = {};
      Object.keys(state.selected).forEach(function (i) {
        var b = bound.ok[i];
        if (!b) return;
        (byEngine[b.engine] = byEngine[b.engine] || []).push(b);
      });
      var names = Object.keys(byEngine);
      names.forEach(function (eng) {
        download(doc, filenameFor(slug, eng), bundle(eng, byEngine[eng], slug));
      });
      panel.querySelector('.hl-picker__note').textContent =
        'Downloaded ' + names.length + ' file(s): ' +
        names.map(function (e) { return filenameFor(slug, e); }).join(', ');
    }

    panel.addEventListener('click', function (ev) {
      var chipEl = ev.target.closest && ev.target.closest('.hl-picker__chip');
      if (chipEl) {
        var kind = chipEl.getAttribute('data-kind');
        var val = chipEl.getAttribute('data-val');
        state[kind] = state[kind] === val ? null : val;
        [].forEach.call(filters.querySelectorAll('.hl-picker__chip'), function (c) {
          c.setAttribute('aria-pressed',
            String(state[c.getAttribute('data-kind')] === c.getAttribute('data-val')));
        });
        refresh();
        return;
      }
      var btn = ev.target.closest && ev.target.closest('.hl-picker__btn');
      if (!btn) return;
      var act = btn.getAttribute('data-act');
      if (act === 'all') { visible().forEach(function (i) { state.selected[i] = true; }); syncBoxes(); }
      else if (act === 'none') { state.selected = {}; syncBoxes(); }
      else if (act === 'dl') { doDownload(); }
      refresh();
    });

    body.addEventListener('change', function (ev) {
      var cb = ev.target;
      if (!cb.classList || !cb.classList.contains('hl-rule-pick')) return;
      var i = cb.getAttribute('data-i');
      if (cb.checked) state.selected[i] = true; else delete state.selected[i];
      refresh();
    });

    refresh();
  }

  function init() {
    var doc = document;
    var body = doc.querySelector('.hl-post-content') || doc.querySelector('.hl-post-body');
    var raw = doc.getElementById('hl-detection-manifest');
    if (!body || !raw) return;
    if (!H || typeof H.ruleHash !== 'function') return;   // no hash, no verification, no picker
    var rules;
    try { rules = JSON.parse(raw.textContent); } catch (e) { return; }
    if (!rules || !rules.length) return;

    var slug = location.pathname.replace(/\/+$/, '').split('/').pop() || 'detections';
    render(doc, body, bind(body, rules, doc), slug);
  }

  return {
    bind: bind,
    headingFor: headingFor,
    blockFor: blockFor,
    applyFilters: applyFilters,
    bundle: bundle,
    filenameFor: filenameFor,
    init: init
  };
});
