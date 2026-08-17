/* The Hunter's Ledger: ATT&CK coverage strip and Navigator layer export.
   Parses the rendered DOM, never markdown: the corpus carries at least seven
   distinct mapping-table shapes and the full set is not statically enumerable. */
(function (root, factory) {
  'use strict';
  var api = factory();
  if (typeof module === 'object' && module.exports) { module.exports = api; }
  else { root.HLAttackCoverage = api; api.init(); }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var TACTIC_ORDER = [
    'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
    'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
    'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
    'Exfiltration', 'Impact'
  ];

  var TECH_RE = /\bT\d{4}(?:\.\d{3})?\b/;

  function tacticSlug(name) {
    return String(name).toLowerCase().trim().replace(/\s+/g, '-');
  }

  function cellText(cell) {
    return (cell.textContent || '').replace(/\s+/g, ' ').trim();
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

  function parseRow(cells, confIndex) {
    var idx = -1, match = null;
    for (var i = 0; i < cells.length; i++) {
      var m = cellText(cells[i]).match(TECH_RE);
      if (m) { idx = i; match = m[0]; break; }
    }
    if (idx === -1) return null;

    var own = cellText(cells[idx]);
    var before = own.slice(0, own.indexOf(match));
    var after = own.slice(own.indexOf(match) + match.length);

    // Tactic: text before the ID in its own cell, else the nearest earlier cell.
    var tactic = normaliseTactic(before);
    for (var j = idx - 1; j >= 0 && !tactic; j--) tactic = normaliseTactic(cellText(cells[j]));

    // Name: remainder of the ID's own cell, else the next cell.
    var name = after.replace(/^[\s\/|:.-]+/, '').trim();
    if (!name && cells[idx + 1]) name = cellText(cells[idx + 1]);

    var rowText = [].map.call(cells, cellText).join(' ');
    var confidence = 'HIGH';
    if (confIndex >= 0 && cells[confIndex]) {
      var c = cellText(cells[confIndex]).toUpperCase();
      if (/HIGH|MODERATE|LOW|DEFINITE|INSUFFICIENT/.test(c)) confidence = c.match(/HIGH|MODERATE|LOW|DEFINITE|INSUFFICIENT/)[0];
    } else if (/\(MODERATE\)/i.test(rowText)) { confidence = 'MODERATE'; }
    else if (/\(LOW\)/i.test(rowText)) { confidence = 'LOW'; }

    var evidence = cells.length > idx + 1 ? cellText(cells[cells.length - 1]) : '';

    return { id: match, tactic: tactic, name: name, confidence: confidence, evidence: evidence };
  }

  function confidenceColumnIndex(table) {
    var th = table.querySelectorAll('th');
    for (var i = 0; i < th.length; i++) {
      if (/^conf/i.test(cellText(th[i]))) return i;
    }
    return -1;
  }

  function parseTable(table) {
    var confIndex = confidenceColumnIndex(table);
    var rows = table.querySelectorAll('tbody tr, tr');
    var techniques = [], unmapped = [], seen = {};
    for (var i = 0; i < rows.length; i++) {
      var cells = rows[i].querySelectorAll('td');
      if (!cells.length) continue;
      var t = parseRow(cells, confIndex);
      if (!t) continue;
      var key = t.id + '|' + (t.tactic || '');
      if (seen[key]) continue;
      seen[key] = true;
      if (t.tactic) techniques.push(t); else unmapped.push(t);
    }
    return { label: '', techniques: techniques, unmapped: unmapped };
  }

  return {
    TACTIC_ORDER: TACTIC_ORDER,
    tacticSlug: tacticSlug,
    parseRow: parseRow,
    parseTable: parseTable
  };
});
