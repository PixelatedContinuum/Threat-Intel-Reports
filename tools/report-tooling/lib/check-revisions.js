'use strict';

/* Verifies a report's revision record in its front matter: `last_updated`
   and the optional `revisions` list of { date, note } that _layouts/post.html
   renders as the revision history.

   The rule is that the header and the history can never disagree. A report
   with `revisions` must carry `last_updated` equal to its newest revision
   date; every revision has a YYYY-MM-DD date no earlier than publication and
   a note saying what changed; and `last_updated` on its own is never earlier
   than `date`. A report with neither field is a report never revised, which
   is PASS with nothing to check, and says so.

   Pure on its input (the markdown text) so it is testable on fixtures;
   check-report.js calls it on the markdown path and reports NOT CHECKED on
   the URL path, where the front matter is not in the rendered page. */

var yaml = require('js-yaml');

var DATE_SHAPE = /^\d{4}-\d{2}-\d{2}$/;

function frontMatter(md) {
  var m = String(md).match(/^---\r?\n([\s\S]*?)\r?\n---/);
  return m ? m[1] : '';
}

/* YAML dates come back as Date objects; the site writes them quoted, but a
   bare one is still a date. Either way the comparison is on the string. */
function dateStr(v) {
  if (v instanceof Date) return v.toISOString().slice(0, 10);
  return String(v == null ? '' : v).trim();
}

function verdict(status, reason, problems, revisions) {
  return { status: status, reason: reason || null, problems: problems || [], revisions: revisions || 0 };
}

function checkMarkdown(md) {
  var fm;
  try { fm = yaml.load(frontMatter(md)) || {}; }
  catch (e) {
    return verdict('NOT CHECKED', 'front matter could not be parsed: ' + String(e.message).split('\n')[0]);
  }
  if (typeof fm !== 'object') fm = {};
  var problems = [];
  var published = dateStr(fm.date);
  var last = fm.last_updated == null ? null : dateStr(fm.last_updated);
  var revs = fm.revisions;

  if (last !== null) {
    if (!DATE_SHAPE.test(last)) problems.push('last_updated must be a YYYY-MM-DD date, got "' + last + '"');
    else if (DATE_SHAPE.test(published) && last < published) {
      problems.push('last_updated ' + last + ' is earlier than the publication date ' + published);
    }
  }

  if (revs === undefined) {
    return verdict(problems.length ? 'FAIL' : 'PASS',
      problems.length ? null : (last === null ? 'never revised' : 'last_updated only; the history shows one unitemised revision'),
      problems, 0);
  }
  if (!Array.isArray(revs) || !revs.length) {
    problems.push('revisions is declared but is not a non-empty list; remove the key rather than leaving it empty');
    return verdict('FAIL', null, problems, 0);
  }
  var newest = '';
  revs.forEach(function (r, i) {
    var where = 'revisions[' + i + ']';
    if (!r || typeof r !== 'object') { problems.push(where + ' is not a mapping with date and note'); return; }
    var d = dateStr(r.date);
    if (!DATE_SHAPE.test(d)) problems.push(where + ': date must be YYYY-MM-DD, got "' + d + '"');
    else {
      if (DATE_SHAPE.test(published) && d < published) problems.push(where + ': ' + d + ' is earlier than the publication date ' + published);
      if (d > newest) newest = d;
    }
    if (typeof r.note !== 'string' || !r.note.trim()) problems.push(where + ': note must say what changed');
  });
  if (last === null) {
    problems.push('revisions are listed but last_updated is missing; set it to the newest revision date' + (newest ? ' (' + newest + ')' : ''));
  } else if (newest && last !== newest) {
    problems.push('last_updated ' + last + ' is not the newest revision date ' + newest + '; the header and the history must agree');
  }
  return verdict(problems.length ? 'FAIL' : 'PASS', null, problems, revs.length);
}

module.exports = { checkMarkdown: checkMarkdown, frontMatter: frontMatter };
