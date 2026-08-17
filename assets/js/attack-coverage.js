/* The Hunter's Ledger: ATT&CK coverage strip and Navigator layer export.
   Parses the rendered DOM, never markdown: the corpus carries at least eight
   distinct mapping-table shapes and the full set is not statically enumerable. */
(function (root, factory) {
  'use strict';
  var api = factory();
  if (typeof module === 'object' && module.exports) { module.exports = api; }
  else {
    root.HLAttackCoverage = api;
    if (typeof api.init === 'function') { api.init(); }
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var TACTIC_ORDER = [
    'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
    'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
    'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
    'Exfiltration', 'Impact'
  ];

  var TECH_RE = /\bT\d{4}(?:\.\d{3})?\b/;
  var CONF_HEADER_RE = /^conf(idence|\.)?$/i;
  var CONF_VALUE_RE = /HIGH|MODERATE|LOW|DEFINITE|INSUFFICIENT/;

  function tacticSlug(name) {
    return String(name).toLowerCase().trim().replace(/\s+/g, '-');
  }

  function cellText(cell) {
    return (cell.textContent || '').replace(/\s+/g, ' ').trim();
  }

  function hasWordChar(s) {
    return /[A-Za-z0-9]/.test(s);
  }

  // Normalises a raw cell fragment into a tactic display name, or null.
  function normaliseTactic(raw) {
    var t = String(raw || '').replace(/[\s\/|:]+$/, '').trim();
    if (!t) return null;
    for (var i = 0; i < TACTIC_ORDER.length; i++) {
      if (TACTIC_ORDER[i].toLowerCase() === t.toLowerCase()) return TACTIC_ORDER[i];
    }
    return null;
  }

  // Every technique ID in one cell, with the first and last match objects kept so
  // callers slice on the real offset rather than re-finding the text.
  function techniqueMatches(text) {
    var re = new RegExp(TECH_RE.source, 'g');
    var ids = [], first = null, last = null, m;
    while ((m = re.exec(text)) !== null) {
      ids.push(m[0]);
      if (!first) first = m;
      last = m;
    }
    return { ids: ids, first: first, last: last };
  }

  // Returns every technique the row carries, as an array. Empty when the row has
  // no ID at all. Detection-coverage tables list several IDs in one cell and none
  // of them are dropped.
  function parseRow(cells, confIndex) {
    var idx = -1, found = null;
    for (var i = 0; i < cells.length; i++) {
      var candidate = techniqueMatches(cellText(cells[i]));
      if (candidate.ids.length) { idx = i; found = candidate; break; }
    }
    if (idx === -1) return [];

    var own = cellText(cells[idx]);
    var before = own.slice(0, found.first.index);
    // A cell listing several IDs is a list, not one technique plus its name, so
    // anchor the trailing text on the last ID and no ID can leak into the name.
    var anchor = found.ids.length > 1 ? found.last : found.first;
    var after = own.slice(anchor.index + anchor[0].length);

    // Tactic: text before the ID in its own cell, else the nearest earlier cell.
    var tactic = normaliseTactic(before);
    for (var j = idx - 1; j >= 0 && !tactic; j--) tactic = normaliseTactic(cellText(cells[j]));

    // Name: what follows the ID in its own cell, else the text before the ID when
    // that text is not the tactic, else the next cell. Leftover punctuation is not
    // a name, so each step is gated on finding an actual word character.
    var name = after.replace(/^[\s\/|:.,;)\]\u2013\u2014-]+/, '').replace(/[\s(\[]+$/, '').trim();
    if (!hasWordChar(name)) name = tactic ? '' : before.replace(/[\s(\[]+$/, '').trim();
    if (!hasWordChar(name) && found.ids.length === 1 && cells[idx + 1]) name = cellText(cells[idx + 1]);
    if (!hasWordChar(name)) name = '';

    // Confidence: the column when it parses, else an inline marker, else HIGH.
    // The inline fallback also has to cover an empty or unparseable column cell.
    var rowText = [].map.call(cells, cellText).join(' ');
    var confidence = null;
    if (confIndex >= 0 && cells[confIndex]) {
      var cm = cellText(cells[confIndex]).toUpperCase().match(CONF_VALUE_RE);
      if (cm) confidence = cm[0];
    }
    if (!confidence) {
      if (/\(MODERATE\)/i.test(rowText)) confidence = 'MODERATE';
      else if (/\(LOW\)/i.test(rowText)) confidence = 'LOW';
      else confidence = 'HIGH';
    }

    // Evidence: the last cell that is neither the confidence column nor the ID
    // cell. Taking the last cell unconditionally returns the confidence word on
    // every Component / Confidence table.
    var lastIdx = cells.length - 1;
    if (lastIdx === confIndex) lastIdx--;
    var evidence = lastIdx > idx ? cellText(cells[lastIdx]) : '';

    var out = [];
    for (var k = 0; k < found.ids.length; k++) {
      out.push({
        id: found.ids[k],
        tactic: tactic,
        name: name,
        confidence: confidence,
        evidence: evidence
      });
    }
    return out;
  }

  // Index over the header row's own cells. Counting th across the whole table
  // desynchronises the index from a row's cells whenever a th sits in tbody.
  function confidenceColumnIndex(table) {
    var hdr = table.querySelector(':scope > thead > tr:last-of-type') ||
              table.querySelector(':scope > tbody > tr, :scope > tr');
    var hc = hdr ? hdr.querySelectorAll(':scope > th, :scope > td') : [];
    for (var i = 0; i < hc.length; i++) {
      if (CONF_HEADER_RE.test(cellText(hc[i]))) return i;
    }
    return -1;
  }

  function parseTable(table) {
    var confIndex = confidenceColumnIndex(table);
    // Scoped so tfoot totals and nested tables are not read as data.
    var rows = table.querySelectorAll(':scope > tbody > tr, :scope > tr');
    var techniques = [], unmapped = [], seen = {};
    for (var i = 0; i < rows.length; i++) {
      var cells = rows[i].querySelectorAll(':scope > td, :scope > th');
      if (!cells.length) continue;
      var parsed = parseRow(cells, confIndex);
      for (var j = 0; j < parsed.length; j++) {
        var t = parsed[j];
        var key = t.id + '|' + (t.tactic || '');
        if (seen[key]) continue;
        seen[key] = true;
        if (t.tactic) techniques.push(t); else unmapped.push(t);
      }
    }
    return { label: '', techniques: techniques, unmapped: unmapped };
  }

  // A table is a mapping table iff it parses to at least one technique with a
  // RESOLVABLE TACTIC. Two real corpus shapes carry technique IDs but are not
  // ATT&CK mappings: detection-coverage tables whose cells hold comma-separated
  // ID lists with no Tactic column, and technique tables that put the ID in
  // parentheses with no Tactic column. Neither can populate a tactic-organised
  // strip, and a strip that is entirely Unmapped is noise rather than honesty.
  //
  // Deriving discovery FROM parsing also makes the two impossible to drift
  // apart. An earlier version tested the table's whole textContent, which
  // concatenates adjacent cells with no separator, so a legacy row read
  // "ExecutionT1059.004" and the word boundary never matched. That version was
  // correct on 3 of 9 fixtures while looking fine on the two shapes anyone
  // would spot-check.
  function findMappingTables(root) {
    var all = root.querySelectorAll('table'), out = [];
    for (var i = 0; i < all.length; i++) {
      if (parseTable(all[i]).techniques.length) out.push(all[i]);
    }
    return out;
  }

  function labelForTable(table) {
    var node = table;
    while (node) {
      var prev = node.previousElementSibling;
      while (prev) {
        if (/^H[1-6]$/.test(prev.tagName)) {
          return (prev.textContent || '').replace(/\s+/g, ' ').trim();
        }
        prev = prev.previousElementSibling;
      }
      node = node.parentElement;
      if (node && node.tagName === 'BODY') break;
    }
    return '';
  }

  // The strip belongs above the teardown, not inside it, so the summary stays
  // visible without opening the collapse.
  function insertionPointFor(table) {
    var node = table;
    while (node && node.parentElement) {
      if (node.tagName === 'DETAILS' && node.classList.contains('hl-teardown')) return node;
      node = node.parentElement;
    }
    return table;
  }

  var SCORE = { DEFINITE: 100, HIGH: 100, MODERATE: 60, LOW: 30, INSUFFICIENT: 0 };

  function toNavigatorLayer(parsed, opts) {
    opts = opts || {};
    var title = opts.reportTitle || 'The Hunter\u2019s Ledger';
    var name = parsed.label ? title + ': ' + parsed.label : title;
    return {
      name: name.slice(0, 250),
      domain: 'enterprise-attack',
      description: 'ATT&CK coverage exported from ' + title +
        '. Unmapped techniques, if any, are omitted because their tactic could not be resolved.',
      versions: { attack: '19', navigator: '4.9.0', layer: '4.5' },
      techniques: parsed.techniques.map(function (t) {
        return {
          techniqueID: t.id,
          tactic: tacticSlug(t.tactic),
          score: SCORE[t.confidence] === undefined ? 100 : SCORE[t.confidence],
          comment: (t.name ? t.name + '. ' : '') + (t.evidence || ''),
          enabled: true
        };
      }),
      gradient: {
        colors: ['#c7e3ff', '#1f6feb'],
        minValue: 0,
        maxValue: 100
      }
    };
  }

  function groupByTactic(techniques) {
    var groups = {};
    for (var i = 0; i < TACTIC_ORDER.length; i++) groups[TACTIC_ORDER[i]] = [];
    techniques.forEach(function (t) { if (groups[t.tactic]) groups[t.tactic].push(t); });
    return groups;
  }

  function el(doc, tag, cls, text) {
    var n = doc.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }

  function renderStrip(parsed, doc) {
    if (!parsed.techniques.length && !parsed.unmapped.length) return null;

    var groups = groupByTactic(parsed.techniques);
    var max = 1;
    TACTIC_ORDER.forEach(function (t) { if (groups[t].length > max) max = groups[t].length; });

    var wrap = el(doc, 'div', 'hl-attack');
    var head = el(doc, 'div', 'hl-attack__head');
    head.appendChild(el(doc, 'span', 'hl-attack__label', parsed.label || 'ATT&CK coverage'));
    head.appendChild(el(doc, 'span', 'hl-attack__count',
      parsed.techniques.length + ' techniques \u00b7 ' +
      TACTIC_ORDER.filter(function (t) { return groups[t].length; }).length + ' of 14 tactics'));
    var dl = el(doc, 'button', 'hl-attack__export', '\u2193 Navigator layer');
    dl.setAttribute('type', 'button');
    head.appendChild(dl);
    wrap.appendChild(head);

    var bars = el(doc, 'div', 'hl-attack__bars');
    TACTIC_ORDER.forEach(function (tactic) {
      var list = groups[tactic];
      var seg = el(doc, 'button', 'hl-attack__seg');
      seg.setAttribute('type', 'button');
      seg.setAttribute('data-tactic', tactic);
      seg.setAttribute('data-count', String(list.length));
      seg.setAttribute('aria-label', tactic + ', ' + list.length + ' techniques');
      var fill = el(doc, 'span', 'hl-attack__fill');
      fill.style.height = list.length ? Math.round((list.length / max) * 100) + '%' : '4px';
      seg.appendChild(fill);
      seg.appendChild(el(doc, 'span', 'hl-attack__seglabel', tactic));
      bars.appendChild(seg);
    });
    wrap.appendChild(bars);

    var detail = el(doc, 'div', 'hl-attack__detail');
    detail.setAttribute('hidden', 'hidden');
    wrap.appendChild(detail);

    if (parsed.unmapped.length) {
      var note = el(doc, 'p', 'hl-attack__unmapped',
        parsed.unmapped.length + ' technique(s) could not be assigned a tactic from this table ' +
        'and are excluded from the layer export.');
      note.setAttribute('data-unmapped', String(parsed.unmapped.length));
      wrap.appendChild(note);
    }
    return wrap;
  }

  function download(doc, filename, obj) {
    var blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var a = doc.createElement('a');
    a.href = url; a.download = filename;
    doc.body.appendChild(a); a.click(); doc.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function slugify(s) {
    return String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60);
  }

  function init() {
    var doc = document;
    var body = doc.querySelector('.hl-post-content') || doc.querySelector('.hl-post-body');
    if (!body) return;

    var reportTitle = (doc.querySelector('h1') || {}).textContent || doc.title || '';
    reportTitle = reportTitle.replace(/\s+/g, ' ').trim();

    findMappingTables(body).forEach(function (table) {
      var parsed = parseTable(table);
      parsed.label = labelForTable(table);
      var strip = renderStrip(parsed, doc);
      if (!strip) return;

      var anchor = insertionPointFor(table);
      anchor.parentNode.insertBefore(strip, anchor);

      var detail = strip.querySelector('.hl-attack__detail');
      var groups = groupByTactic(parsed.techniques);

      strip.querySelector('.hl-attack__bars').addEventListener('click', function (e) {
        var seg = e.target.closest ? e.target.closest('.hl-attack__seg') : null;
        if (!seg) return;
        var tactic = seg.getAttribute('data-tactic');
        var list = groups[tactic] || [];
        var already = seg.classList.contains('is-open');

        [].forEach.call(strip.querySelectorAll('.hl-attack__seg'), function (s) {
          s.classList.remove('is-open');
        });
        if (already || !list.length) { detail.setAttribute('hidden', 'hidden'); return; }

        seg.classList.add('is-open');
        detail.innerHTML = '';
        detail.appendChild(el(doc, 'div', 'hl-attack__detailhead',
          tactic + ' \u00b7 ' + list.length + ' technique' + (list.length === 1 ? '' : 's')));
        list.forEach(function (t) {
          var chip = el(doc, 'span', 'hl-attack__chip', t.id + ' ' + t.name);
          chip.setAttribute('data-confidence', t.confidence);
          detail.appendChild(chip);
        });
        detail.removeAttribute('hidden');
      });

      strip.querySelector('.hl-attack__export').addEventListener('click', function () {
        download(doc,
          slugify(reportTitle + '-' + (parsed.label || 'attack')) + '-layer.json',
          toNavigatorLayer(parsed, { reportTitle: reportTitle }));
      });
    });
  }

  return {
    TACTIC_ORDER: TACTIC_ORDER,
    tacticSlug: tacticSlug,
    parseRow: parseRow,
    parseTable: parseTable,
    findMappingTables: findMappingTables,
    labelForTable: labelForTable,
    insertionPointFor: insertionPointFor,
    toNavigatorLayer: toNavigatorLayer,
    groupByTactic: groupByTactic,
    renderStrip: renderStrip,
    init: init
  };
});
