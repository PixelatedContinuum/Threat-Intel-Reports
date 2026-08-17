'use strict';

/* Extracts every table from report markdown as an HTML string.
   Pipe tables are converted; raw <table> blocks are passed through unchanged.
   This is an approximation of kramdown, exact for what the parser reads:
   the parser reads textContent, so the job is to reproduce the TEXT kramdown
   would produce, which means inline markdown has to be converted rather than
   emitted literally. See inline() for why that is load-bearing. */

var SEP = /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/;

function stripFrontMatter(md) {
  if (!/^---\s*$/m.test(md.split('\n')[0] || '')) return md;
  var lines = md.split('\n');
  for (var i = 1; i < lines.length; i++) {
    if (/^---\s*$/.test(lines[i])) return lines.slice(i + 1).join('\n');
  }
  return md;
}

function esc(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/* Inline markdown a cell can carry, rendered the way kramdown renders it.

   Emitting the markers literally changes what the cell SAYS. The parser reads
   textContent and compares tactic names exactly, so a cell written
   "| **Execution** |" arrives as the string "**Execution**", never matches the
   tactic "Execution", and the whole table stops being recognised as a mapping
   table. One live report lost all 7 of its techniques to exactly that, while
   the rendered page parsed correctly, so the bug was invisible from the site.

   Escaping runs FIRST and the emphasis conversion runs over the escaped string.
   The markers (* _ `) are untouched by escaping, so that order is safe, and the
   tags inserted afterwards cannot then be escaped back into literals. */
function inline(s) {
  var out = esc(s), held = [];

  // Code spans are lifted out first and restored last, because inside one the
  // emphasis markers are literal. That is what kramdown does, and it is what
  // keeps an identifier like `veh_loader` intact.
  //
  // The placeholder is <n>, and that is provably collision-free here because
  // escaping has already run: no literal < or > survives in the string, so <0>
  // cannot collide with cell text. The emphasis tags added below are the only
  // other angle brackets present, and none of them is all digits, so the
  // restore pattern cannot touch them.
  out = out.replace(/(`+)([\s\S]*?)\1/g, function (m, ticks, body) {
    held.push(body);
    return '<' + (held.length - 1) + '>';
  });

  out = out
    .replace(/\*\*(?=\S)([\s\S]*?\S)\*\*/g, '<strong>$1</strong>')
    .replace(/(?<![A-Za-z0-9])__(?=\S)([\s\S]*?\S)__(?![A-Za-z0-9])/g, '<strong>$1</strong>')
    .replace(/\*(?=\S)([^*]*?\S)\*/g, '<em>$1</em>')
    // Underscore emphasis is never intraword, so a path or symbol name such as
    // sc_loader/veh_loader/dbg_loader keeps every underscore. Treating those as
    // emphasis would DELETE characters from the text the parser reads, turning
    // a fidelity fix into a fidelity bug.
    .replace(/(?<![A-Za-z0-9_])_(?=\S)([^_]*?\S)_(?![A-Za-z0-9_])/g, '<em>$1</em>');

  return out.replace(/<(\d+)>/g, function (m, i) {
    return '<code>' + held[i] + '</code>';
  });
}

// Splits on unescaped pipes, then restores the escaped ones as literals.
function cells(line) {
  var parts = [], buf = '';
  for (var i = 0; i < line.length; i++) {
    if (line[i] === '\\' && line[i + 1] === '|') { buf += '|'; i++; continue; }
    if (line[i] === '|') { parts.push(buf); buf = ''; continue; }
    buf += line[i];
  }
  parts.push(buf);
  if (parts.length && parts[0].trim() === '') parts.shift();
  if (parts.length && parts[parts.length - 1].trim() === '') parts.pop();
  return parts.map(function (c) { return c.trim(); });
}

// Header cells go through inline() too: a bolded "| **Tactic** |" header has to
// read as "Tactic" for the same reason its body cells do.
function toHtml(rows) {
  var head = '<tr>' + cells(rows[0]).map(function (c) {
    return '<th>' + inline(c) + '</th>';
  }).join('') + '</tr>';
  var body = rows.slice(2).map(function (r) {
    return '<tr>' + cells(r).map(function (c) {
      return '<td>' + inline(c) + '</td>';
    }).join('') + '</tr>';
  }).join('');
  return '<table><thead>' + head + '</thead><tbody>' + body + '</tbody></table>';
}

function extractTables(md) {
  var text = stripFrontMatter(md);
  var out = [];

  // Raw HTML tables first, removing them so the pipe scan cannot see inside.
  text = text.replace(/<table[\s\S]*?<\/table>/gi, function (m) {
    out.push(m);
    return '\n';
  });

  var lines = text.split('\n');
  var i = 0;
  while (i < lines.length) {
    var looksLikeRow = lines[i].indexOf('|') !== -1 && lines[i].trim() !== '';
    if (looksLikeRow && i + 1 < lines.length && SEP.test(lines[i + 1])) {
      var block = [lines[i], lines[i + 1]];
      var j = i + 2;
      while (j < lines.length && lines[j].indexOf('|') !== -1 && lines[j].trim() !== '') {
        block.push(lines[j]);
        j++;
      }
      out.push(toHtml(block));
      i = j;
      continue;
    }
    i++;
  }
  return out;
}

module.exports = { extractTables: extractTables };
