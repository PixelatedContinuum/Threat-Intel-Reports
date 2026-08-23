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

  /* ATT&CK v19 tactic set, in kill-chain order. Two changes from the v18 list
     this file shipped with, both forced by ATT&CK itself:

       TA0005 "Defense Evasion" was RENAMED to "Stealth".
       TA0112 "Defense Impairment" is NEW, and owns T1685 (the technique that
       revoked the whole T1562 Impair Defenses tree) plus T1112 Modify Registry.

     The published corpus already carries v19 techniques, so a v18 tactic list
     had no bar to put them in. Reports written before the rename still say
     "Defense Evasion" in column 1 and must keep parsing, which is what the
     alias below is for.

     This order must match TACTIC_DISPLAY in generate-attack-catalog.py.
     check-detection-attack.js asserts the two agree. */
  var TACTIC_ORDER = [
    'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
    'Persistence', 'Privilege Escalation', 'Stealth', 'Defense Impairment',
    'Credential Access', 'Discovery', 'Lateral Movement', 'Collection',
    'Command and Control', 'Exfiltration', 'Impact'
  ];

  var TECH_RE = /\bT\d{4}(?:\.\d{3})?\b/;
  var CONF_HEADER_RE = /^conf(idence|\.)?$/i;
  var CONF_VALUE_RE = /HIGH|MODERATE|LOW|DEFINITE|INSUFFICIENT/;

  function tacticSlug(name) {
    return String(name).toLowerCase().trim().replace(/\s+/g, '-');
  }

  // A grid row carries null where a rowspan reserves a column past that row's
  // last physical cell, so a missing cell has to read as empty rather than throw.
  function cellText(cell) {
    return cell ? (cell.textContent || '').replace(/\s+/g, ' ').trim() : '';
  }

  function hasWordChar(s) {
    return /[A-Za-z0-9]/.test(s);
  }

  // Abbreviations that actually occur in the published corpus, keyed lowercase.
  // Both were found by running the parser over the live pages, not guessed: an
  // invented alias would assign a tactic no report ever claimed.
  var TACTIC_ALIASES = {
    'priv. escalation': 'Privilege Escalation',
    'c&c': 'Command and Control',
    /* ATT&CK renamed TA0005 Defense Evasion to Stealth in v19. Every report
       published before that says "Defense Evasion", and rewriting 29 published
       mapping tables to chase a vendor rename would be churn against the
       archive. The alias resolves the old name to the current tactic, so the
       old tables and the generated detection tables land in the same bar. */
    'defense evasion': 'Stealth'
  };

  // hasOwnProperty, because a cell reading "constructor" or "toString" would
  // otherwise resolve to an inherited Object member instead of null.
  function matchTactic(t) {
    for (var i = 0; i < TACTIC_ORDER.length; i++) {
      if (TACTIC_ORDER[i].toLowerCase() === t.toLowerCase()) return TACTIC_ORDER[i];
    }
    var key = t.toLowerCase();
    return Object.prototype.hasOwnProperty.call(TACTIC_ALIASES, key) ? TACTIC_ALIASES[key] : null;
  }

  // Normalises a raw cell fragment into a tactic display name, or null. A cell
  // naming two tactics, "Exfiltration / Impact", resolves to the first, which
  // the column convention makes the primary one.
  function normaliseTactic(raw) {
    var t = String(raw || '').replace(/[\s\/|:]+$/, '').trim();
    if (!t) return null;
    var direct = matchTactic(t);
    if (direct) return direct;
    var parts = t.split('/');
    if (parts.length < 2) return null;
    for (var i = 0; i < parts.length; i++) {
      var seg = matchTactic(parts[i].trim());
      if (seg) return seg;
    }
    return null;
  }

  // A cell reading "T1071.001/004" is one base technique carrying two
  // sub-technique numbers. The trailing \b matters: without it a four-digit
  // continuation would be truncated into a bogus three-digit sub-technique.
  var SUBTECH_RUN_RE = /^(?:\s*\/\s*\d{3}\b)+/;

  // Every technique ID in one cell, with the offset of the first ID and the end
  // of the last, so callers slice on the real position rather than re-finding
  // the text. A sub-technique run is expanded into one ID per number and is
  // consumed whole, so the trailing 004 cannot be mistaken for a technique name.
  // The dotted base is required, since a bare "T1071/004" is genuinely ambiguous.
  function techniqueMatches(text) {
    var re = new RegExp(TECH_RE.source, 'g');
    var ids = [], start = -1, end = -1, m;
    while ((m = re.exec(text)) !== null) {
      if (start === -1) start = m.index;
      ids.push(m[0]);
      end = m.index + m[0].length;
      var dot = m[0].indexOf('.');
      if (dot !== -1) {
        var run = SUBTECH_RUN_RE.exec(text.slice(end));
        if (run) {
          var extra = run[0].match(/\d{3}/g);
          for (var i = 0; i < extra.length; i++) {
            ids.push(m[0].slice(0, dot) + '.' + extra[i]);
          }
          end += run[0].length;
          re.lastIndex = end;
        }
      }
    }
    return { ids: ids, start: start, end: end };
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
    var before = own.slice(0, found.start);
    // A cell listing several IDs is a list, not one technique plus its name, so
    // the trailing text is anchored past the LAST ID and no ID can leak into the
    // name. With a single ID the two offsets coincide.
    var after = own.slice(found.end);

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

  // Expands rowspan so a merged Tactic cell applies to its continuation rows.
  // Without this a table using <td rowspan="3">Initial Access</td> drops every
  // technique in the second and third rows into unmapped, which is how one live
  // report published 11 techniques where it documents 46. The span is stated by
  // the HTML, so this lays the table out the way a browser does rather than
  // guessing a tactic. A column a span reserves past the row's last physical
  // cell is filled with null, keeping every row dense for index lookups.
  //
  // Row and cell scoping is unchanged, so tfoot totals and nested tables are
  // still not read as data.
  function tableGrid(table) {
    var rows = [].slice.call(table.querySelectorAll(':scope > tbody > tr, :scope > tr'));
    var grid = [], pending = [];
    for (var r = 0; r < rows.length; r++) {
      var cells = [].slice.call(rows[r].querySelectorAll(':scope > td, :scope > th'));
      var out = [], c = 0, k = 0;
      while (true) {
        var held = pending[c] && pending[c].remaining > 0;
        if (!held && k >= cells.length) {
          var more = false;
          for (var q = c; q < pending.length; q++) {
            if (pending[q] && pending[q].remaining > 0) { more = true; break; }
          }
          if (!more) break;
        }
        if (held) {
          out[c] = pending[c].cell;
          pending[c].remaining--;
        } else if (k < cells.length) {
          var cell = cells[k++];
          out[c] = cell;
          var rs = parseInt(cell.getAttribute('rowspan') || '1', 10);
          if (rs > 1) pending[c] = { cell: cell, remaining: rs - 1 };
        } else {
          out[c] = null;
        }
        c++;
      }
      grid.push(out);
    }
    return grid;
  }

  function parseTable(table) {
    var confIndex = confidenceColumnIndex(table);
    var grid = tableGrid(table);
    var techniques = [], unmapped = [], seen = {};
    for (var i = 0; i < grid.length; i++) {
      var cells = grid[i];
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

  var PROMPT_TEXT = '\u25B8 Select a tactic above to list its techniques';

  // The detail panel is never hidden. It shows either this prompt or a
  // selected tactic's chips, so filling it never shifts the page.
  function showPrompt(detail, doc) {
    detail.innerHTML = '';
    detail.appendChild(el(doc, 'p', 'hl-attack__prompt', PROMPT_TEXT));
    detail.removeAttribute('hidden');
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
      TACTIC_ORDER.filter(function (t) { return groups[t].length; }).length +
      ' of ' + TACTIC_ORDER.length + ' tactics'));
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
    showPrompt(detail, doc);
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
        if (already || !list.length) { showPrompt(detail, doc); return; }

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
    showPrompt: showPrompt,
    init: init
  };
});
