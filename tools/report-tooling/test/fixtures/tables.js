'use strict';

// The seven ATT&CK mapping table structures observed across the published corpus.
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
  )
};
