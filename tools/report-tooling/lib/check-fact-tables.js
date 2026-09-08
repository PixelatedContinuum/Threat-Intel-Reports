'use strict';

/* Checks the key/value fact tables a report declares.

   WHY THIS EXISTS RATHER THAN A FRONT-MATTER SCHEMA. The obvious way to make
   these tables into a component was to move them into front matter and render
   them from an include, the way process_tree works. Measured, that is the wrong
   trade here: a `Field | Value` markdown table already IS a two-column
   declaration, assets/js/hl-facts.js reads it directly, and a YAML schema would
   add nothing a table cannot express while adding a way for an agent to get it
   wrong at volume. The process tree earned its schema because nesting, a branch,
   a timing spine and per-node ATT&CK data are richer than any table. This is
   not.

   So what needs checking is not "is the YAML well formed" but "is this content
   in a container that suits it", plus the two shapes that make the renderer
   produce something worse than the markdown did.

   FAIL, the shapes the renderer cannot handle sensibly:
     - a fact table whose header is present but which has no data rows
     - a data row with an empty key cell, which yields an id of just "fact-"

   WARN, the container question, never a failure because it is pre-existing
   content and a judgment call:
     - a prose-heavy table, meaning fewer than 60% of its values are 60
       characters or shorter. hl-facts.js skips these deliberately.

   The rubric constants are duplicated from hl-facts.js on purpose and asserted
   against it by test/check-fact-tables.test.js, because the module runs in the
   browser and this runs in node, and a silent drift between them would mean the
   gate describing a different corpus than the reader sees. */

var path = require('node:path');
var fs = require('node:fs');

var ROOT = path.join(__dirname, '..', '..', '..');

var KEY_HDR = /^(field|property|attribute)$/i;
var VAL_HDR = /^(value|assessment)$/i;
var SHORT = 60;
var LITERAL_SHARE = 0.6;

function clean(cell) {
  return String(cell).replace(/[*`]/g, '').trim();
}

/* Reads pipe tables out of markdown. Deliberately not a full parser: it needs
   the same two columns the browser module needs and nothing else. */
function factTables(md) {
  var body = String(md).replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n/, '');
  var lines = body.split(/\r?\n/);
  var out = [];
  for (var i = 0; i < lines.length - 1; i++) {
    var head = lines[i].trim();
    if (head.charAt(0) !== '|') continue;
    if (!/^\|[\s:|-]+\|$/.test(lines[i + 1].trim())) continue;
    var cells = head.replace(/^\||\|$/g, '').split('|').map(clean);
    if (cells.length !== 2) continue;
    if (!KEY_HDR.test(cells[0]) || !VAL_HDR.test(cells[1])) continue;

    var rows = [];
    var j = i + 2;
    for (; j < lines.length && lines[j].trim().charAt(0) === '|'; j++) {
      var c = lines[j].trim().replace(/^\||\|$/g, '').split('|').map(clean);
      if (c.length >= 2) rows.push({ key: c[0], value: c[1], line: j + 1 });
    }
    out.push({ line: i + 1, header: cells.join(' | '), rows: rows });
    i = j - 1;
  }
  return out;
}

function isLiteralHeavy(rows) {
  if (!rows.length) return false;
  var short = rows.filter(function (r) { return r.value.length <= SHORT; }).length;
  return (short / rows.length) >= LITERAL_SHARE;
}

/* Returns { status, problems, warnings, tables, rows, literal, prose }.
   NOT CHECKED is reserved for a file that could not be read, and is never
   folded into PASS. */
function checkMarkdown(md, label) {
  if (typeof md !== 'string') {
    return { status: 'NOT CHECKED', reason: (label || 'input') + ' could not be read',
      problems: [], warnings: [], tables: 0, rows: 0, literal: 0, prose: 0 };
  }
  var tables = factTables(md);
  var problems = [], warnings = [];
  var rows = 0, literal = 0, prose = 0;

  tables.forEach(function (t) {
    var where = (label || 'report') + ':' + t.line + ' (' + t.header + ')';
    if (!t.rows.length) {
      problems.push(where + ' declares a fact table with no rows, so it renders as a bare header');
      return;
    }
    rows += t.rows.length;
    t.rows.forEach(function (r) {
      if (!r.key) {
        problems.push((label || 'report') + ':' + r.line +
          ' has an empty key cell, which yields a permalink id of just "fact-"');
      }
    });
    if (isLiteralHeavy(t.rows)) {
      literal++;
    } else {
      prose++;
      warnings.push(where + ' is prose-heavy (' +
        t.rows.filter(function (r) { return r.value.length <= SHORT; }).length +
        ' of ' + t.rows.length + ' values are ' + SHORT + ' chars or fewer), so hl-facts.js ' +
        'skips it. Whole-sentence values in a two-column grid may belong in prose.');
    }
  });

  return {
    status: problems.length ? 'FAIL' : 'PASS',
    problems: problems,
    warnings: warnings,
    tables: tables.length,
    rows: rows,
    literal: literal,
    prose: prose
  };
}

function checkFile(file) {
  var md;
  try { md = fs.readFileSync(file, 'utf8'); }
  catch (e) { md = null; }
  return checkMarkdown(md, path.relative(ROOT, file));
}

module.exports = {
  KEY_HDR: KEY_HDR,
  VAL_HDR: VAL_HDR,
  SHORT: SHORT,
  LITERAL_SHARE: LITERAL_SHARE,
  factTables: factTables,
  isLiteralHeavy: isLiteralHeavy,
  checkMarkdown: checkMarkdown,
  checkFile: checkFile
};
