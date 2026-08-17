'use strict';

/* Extracts every table from report markdown as an HTML string.
   Pipe tables are converted; raw <table> blocks are passed through unchanged.
   This is an approximation of kramdown, exact for what the parser reads:
   kramdown turns backticked spans into <code>, but the parser reads
   textContent, so technique IDs and tactic names are unaffected. */

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

function toHtml(rows) {
  var head = '<tr>' + cells(rows[0]).map(function (c) {
    return '<th>' + esc(c) + '</th>';
  }).join('') + '</tr>';
  var body = rows.slice(2).map(function (r) {
    return '<tr>' + cells(r).map(function (c) {
      return '<td>' + esc(c) + '</td>';
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
