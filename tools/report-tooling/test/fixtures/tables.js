'use strict';

// The ATT&CK mapping table structures observed across the published corpus, plus
// the malformed and adjacent shapes the parser has to survive.
// Each fixture is a complete <table> so tests exercise real DOM parsing.

function table(headers, rows) {
  var th = headers.map(function (h) { return '<th>' + h + '</th>'; }).join('');
  var tr = rows.map(function (r) {
    return '<tr>' + r.map(function (c) { return '<td>' + c + '</td>'; }).join('') + '</tr>';
  }).join('');
  return '<table><thead><tr>' + th + '</tr></thead><tbody>' + tr + '</tbody></table>';
}

module.exports = {
  // Shape 1: current 3-column, 14 tables in the corpus
  current3col: table(
    ['Tactic / Technique', 'Name', 'Evidence'],
    [
      ['Reconnaissance / T1595.002', 'Vulnerability Scanning', 'Endpoint/CVE probing'],
      ['Credential Access / T1110.003', 'Password Spraying', 'single-password spray (MODERATE)']
    ]
  ),

  // Shape 2: current 4-column with explicit confidence
  current4col: table(
    ['Tactic / Technique', 'Name', 'Conf.', 'Evidence'],
    [
      ['Defense Evasion / T1055.002', 'Portable Executable Injection', 'HIGH', 'RW to RX'],
      ['Resource Development / T1583.003', 'Virtual Private Server', 'MODERATE', 'AS35682']
    ]
  ),

  // Shape 3: legacy 3-column, ID and name share a cell
  legacyIdInTechnique: table(
    ['Tactic', 'Technique', 'Evidence'],
    [['Execution', 'T1059.004 Unix Shell', 'Interactive bash captured']]
  ),

  // Shape 4: legacy 4-column, separate ID and name columns
  legacySplitIdName: table(
    ['Tactic', 'Technique ID', 'Technique Name', 'Evidence'],
    [['Persistence', 'T1505.003', 'Web Shell', 'WordPress plugin-dir shell']]
  ),

  // Shape 5: same as 4 with a renamed evidence header
  legacyEvidenceObserved: table(
    ['Tactic', 'Technique ID', 'Technique Name', 'Evidence Observed'],
    [['Discovery', 'T1046', 'Network Service Discovery', 'Subdomain enumeration']]
  ),

  // Shape 6: legacy 5-column with confidence
  legacy5colConfidence: table(
    ['Tactic', 'Technique ID', 'Technique Name', 'Confidence', 'Key Evidence'],
    [['Collection', 'T1213', 'Data from Information Repositories', 'LOW', 'CKAN harvest']]
  ),

  // Shape 7: legacy 5-column with no evidence column at all
  legacy5colComponent: table(
    ['Tactic', 'Technique ID', 'Technique Name', 'Component', 'Confidence'],
    [['Impact', 'T1486', 'Data Encrypted for Impact', 'enc.exe', 'HIGH']]
  ),

  // A table with no technique IDs: must be ignored entirely
  notAnAttackTable: table(
    ['Indicator', 'Type', 'Confidence'],
    [['13.140.145.210', 'ipv4', 'HIGH']]
  ),

  // A row whose tactic cannot be resolved: must land in `unmapped`
  missingTactic: table(
    ['Technique', 'Evidence'],
    [['T1071.001', 'HTTPS beaconing']]
  ),

  // Shape 8: ID in trailing parentheses, no tactic column.
  // Live in reports/opendirectory-45-130-148-125-20260430/index.md.
  parenthesisedId: table(
    ['Technique', 'Evidence', 'Confidence'],
    [['AMSI bypass via reflection (T1562.001)', 'reflection concatenation', 'HIGH']]
  ),

  // The Component / Confidence shape carrying real evidence, so evidence must be
  // the Component text and never the confidence word.
  // Live in reports/zerotrace-74-0-42-25-20260316/index.md, 34 rows.
  componentThenConfidence: table(
    ['Tactic', 'Technique ID', 'Technique Name', 'Component', 'Confidence'],
    [[
      'Resource Development',
      'T1583.001',
      'Acquire Infrastructure: Domains',
      'chainconnects.net, adminxyzhosting.com',
      'HIGH'
    ]]
  ),

  // A detection-coverage table, not a mapping table: one cell lists several IDs
  // and there is no tactic column at all. Every ID must still be returned.
  // Live in reports/bellamain-turkish-phaas-79-137-192-3-20260516/index.md.
  multiIdCoverage: table(
    ['Rule Type', 'Count', 'MITRE Techniques Covered', 'Overall FP Risk'],
    [['YARA', '3', 'T1505.003, T1027.013, T1070, T1056, T1119', 'LOW\u2013MEDIUM']]
  ),

  // A confidence column that exists but is empty, with the marker inline in the
  // evidence instead. The inline fallback has to run.
  emptyConfidenceCell: table(
    ['Tactic / Technique', 'Name', 'Conf.', 'Evidence'],
    [['Credential Access / T1110.003', 'Password Spraying', '', 'single-password spray (MODERATE)']]
  ),

  // A header whose name only starts with "conf": it is not a confidence column.
  configurationColumn: table(
    ['Tactic', 'Technique', 'Configuration', 'Evidence'],
    [['Impact', 'T1486 Data Encrypted for Impact', 'LOW memory mode', 'enc.exe over SMB (MODERATE)']]
  ),

  // A near-match the ID regex rejects, sitting earlier in the same cell than the
  // real ID. Re-finding the match by string search lands on the wrong offset.
  idPrecededByFalseMatch: table(
    ['Tactic', 'Technique', 'Evidence'],
    [['Execution', 'PORT1059 handler, T1059 Command-Line Interface', 'cmd.exe spawn']]
  ),

  // A row header th inside tbody. Counting th across the whole table desynchronises
  // the confidence index from the row's own cells.
  rowHeaderTactic:
    '<table><thead><tr>' +
    '<th>Tactic</th><th>Technique ID</th><th>Technique Name</th>' +
    '<th>Confidence</th><th>Key Evidence</th>' +
    '</tr></thead><tbody><tr>' +
    '<th scope="row">Collection</th><td>T1213</td>' +
    '<td>Data from Information Repositories</td><td>LOW</td><td>CKAN harvest</td>' +
    '</tr></tbody></table>',

  // A tfoot totals row carrying a technique ID: not a data row.
  tfootTotals:
    '<table><thead><tr><th>Tactic</th><th>Technique</th><th>Evidence</th></tr></thead>' +
    '<tbody><tr><td>Execution</td><td>T1059.004 Unix Shell</td>' +
    '<td>Interactive bash captured</td></tr></tbody>' +
    '<tfoot><tr><td>Impact</td><td>T1490 Inhibit System Recovery</td>' +
    '<td>Totals row, not a mapping</td></tr></tfoot></table>',

  // Shape 9: a merged Tactic cell spanning its continuation rows. The live
  // PULSAR-RAT mapping table is built this way, 10 rowspans across 47 rows, so
  // reading each tr independently drops 36 of its 47 rows into unmapped.
  // Live in reports/PULSAR-RAT/index.md.
  rowspanTactic:
    '<table><thead><tr><th>Tactic</th><th>Technique ID</th>' +
    '<th>Technique Name</th><th>Implementation</th><th>Confidence</th></tr></thead>' +
    '<tbody>' +
    '<tr><td rowspan="3"><strong>Initial Access</strong></td><td>T1566.001</td>' +
    '<td>Spearphishing Attachment</td><td>Email delivery</td><td>MODERATE</td></tr>' +
    '<tr><td>T1566.002</td><td>Spearphishing Link</td>' +
    '<td>Link to open directory</td><td>HIGH</td></tr>' +
    '<tr><td>T1189</td><td>Drive-by Compromise</td>' +
    '<td>Compromised sites</td><td>LOW</td></tr>' +
    '</tbody></table>',

  // Two merged Tactic cells back to back. The second block's continuation row
  // must inherit ITS OWN tactic, not the first block's.
  twoRowspanBlocks:
    '<table><thead><tr><th>Tactic</th><th>Technique ID</th>' +
    '<th>Technique Name</th><th>Evidence</th></tr></thead><tbody>' +
    '<tr><td rowspan="2">Execution</td><td>T1059.001</td>' +
    '<td>PowerShell</td><td>encoded command</td></tr>' +
    '<tr><td>T1059.003</td><td>Windows Command Shell</td><td>cmd.exe spawn</td></tr>' +
    '<tr><td rowspan="2">Persistence</td><td>T1547.001</td>' +
    '<td>Registry Run Keys</td><td>HKCU Run value</td></tr>' +
    '<tr><td>T1543.003</td><td>Windows Service</td><td>service created</td></tr>' +
    '</tbody></table>',

  // A rowspan="2" tactic followed by a row carrying its own tactic cell. An
  // off-by-one in the span countdown would hold Discovery over the Impact row.
  rowspanEndsExactly:
    '<table><thead><tr><th>Tactic</th><th>Technique ID</th>' +
    '<th>Technique Name</th><th>Evidence</th></tr></thead><tbody>' +
    '<tr><td rowspan="2">Discovery</td><td>T1046</td>' +
    '<td>Network Service Discovery</td><td>port sweep</td></tr>' +
    '<tr><td>T1057</td><td>Process Discovery</td><td>tasklist</td></tr>' +
    '<tr><td>Impact</td><td>T1486</td>' +
    '<td>Data Encrypted for Impact</td><td>files encrypted</td></tr>' +
    '</tbody></table>',

  // The abbreviated tactic "Priv. Escalation" inside the merged column.
  // Live in reports/cloudsync-assembler-toolkit-91-197-98-188/index.md, 3 rows.
  abbreviatedTactic: table(
    ['Tactic / Technique', 'Name', 'Evidence'],
    [['Priv. Escalation / T1068', 'Exploitation for Privilege Escalation',
      'PrintSpoofer SeImpersonate LPE (sourced)']]
  ),

  // The abbreviated tactic "C&C" alongside a compound cell naming two
  // sub-techniques of one base. Both occur in the same live table.
  // Live in reports/webserver-compromise-kit-91-236-230-250/index.md.
  abbreviatedC2AndCompoundId: table(
    ['Tactic', 'Technique', 'Evidence'],
    [['C&C', 'T1071.001/004', 'HTTPS/DNS tunneling']]
  ),

  // A dual-tactic cell. The column convention names the primary tactic first.
  // Live in reports/AdvancedRouterScanner/index.md.
  dualTacticCell: table(
    ['Tactic', 'Technique ID', 'Technique Name', 'Implementation'],
    [['Exfiltration / Impact', 'T1041', 'Exfiltration Over C2 Channel',
      'Data theft through botnet infrastructure']]
  ),

  // A nested table inside a cell. Its rows are not data rows and its cells do not
  // belong to the outer row.
  nestedTableInCell:
    '<table><thead><tr><th>Tactic</th><th>Technique ID</th>' +
    '<th>Technique Name</th><th>Evidence</th></tr></thead>' +
    '<tbody><tr><td>Persistence</td><td>T1505.003</td><td>Web Shell</td>' +
    '<td>WordPress plugin-dir shell<table><tbody><tr>' +
    '<td> note</td><td> see T1486 for the follow-on</td>' +
    '</tr></tbody></table></td></tr></tbody></table>'
};
