'use strict';

/* The no-loss comparison behind design v4 check 5: "IOC tables lose nothing".

   check-ioc-tables.js regenerate-and-diffs the table against the feeds, which
   catches a STALE table. It cannot catch a REGENERATION THAT IS CORRECT AND
   NARROWER: if the extractor stops emitting a kind of row, the freshly generated
   table matches the feeds and the gate passes while a defender-facing pivot has
   silently gone. That is exactly what happened twice in the E7 work (a filename
   beside a hash, a bare address beside host:port rows), both times caught by a
   human reviewer rather than by a check.

   So this module compares the PREVIOUS published table with the NEW one. A row
   that was present before and is absent after is a failure unless one of the four
   reasons design-v4 check 5 allows applies:

     same value, another type        the extractor retyped it (domain -> filename)
     same value, another case        the classifier normalised it (Name -> name)
     the feed itself says not an indicator   non_indicators, explicitly_excluded,
                                             or metadata.reference (the site's own
                                             report URL)

   A value that moves between `rows` and `never_block_rows` is not a removal at all:
   the value is still in the feed's table, so there is nothing to excuse. And a feed
   that is no longer published (embargo withdrawn, feed deleted) explains a whole
   block disappearing, and is allowed here because the other half of
   check-ioc-tables.js already fails a stale table: a block deleted while its feed
   is still published cannot pass the regenerate-and-diff. That division is the
   reason the withdrawal case is not a hole.

   WHAT THIS DOES NOT COVER, stated because a row-presence check is only as wide as
   presence:

   - Row DETAIL that changes while the row survives: an action that goes from BLOCK
     to null, a context that thins, a confidence that moves. Check 5's sentence is
     about rows; this module enforces rows. A stricter form would compare the full
     row object, and would fail on the deliberate retypes and label additions.
   - A row whose VALUE changed by a character (a trailing slash, a stripped port) is
     a removal plus an addition, and is reported as a removal. The reason must be a
     feed-side exemption or the person's call to pass a different --against.
   - non_indicators / explicitly_excluded / metadata.reference are matched by value
     (exact, trimmed, then case-insensitive), reading every string in those
     containers. A feed that records an exclusion as prose only ("do not ingest
     1.2.3.4") does not exempt a row; the container is the machine-readable form.

   NOT CHECKED is a real outcome: a before-table that cannot be parsed, or a feed
   file that cannot be read for a feed whose rows went missing, means the exemptions
   could not be evaluated, and the caller must not treat that as a pass. */

var yaml = require('js-yaml');

var SECTIONS = ['rows', 'never_block_rows'];

function asRows(list) {
  var out = [];
  (list || []).forEach(function (r) {
    if (!r || typeof r !== 'object') return;
    if (typeof r.value !== 'string' || !r.value) return;
    out.push({ type: String(r.type || ''), value: r.value });
  });
  return out;
}

/* Parses either side of the comparison. The table is generated flat YAML with one
   top-level key per feed, so a malformed file throws and the caller reports NOT
   CHECKED rather than comparing against nothing. */
function parse(text) {
  var doc = yaml.load(text);
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    throw new Error('not a feed table: expected a mapping of feed key to entry');
  }
  var feeds = {};
  Object.keys(doc).forEach(function (key) {
    var e = doc[key];
    if (!e || typeof e !== 'object') return;
    feeds[key] = {
      slug: e.slug || null,
      feed_url: e.feed_url || null,
      feed_file: feedFileOf(e.feed_url),
      rows: asRows(e.rows),
      never_block_rows: asRows(e.never_block_rows)
    };
  });
  return feeds;
}

/* `feed_url` is written by the generator as `/ioc-feeds/<file>.json`, and may be an
   absolute URL in an older catalog entry; either way the file name is the last
   path segment. An entry with no feed_url gets no file, and its exemptions cannot
   be read. */
function feedFileOf(url) {
  if (typeof url !== 'string' || !url) return null;
  var s = url.split('?')[0].split('#')[0];
  var base = s.replace(/\\/g, '/').split('/').pop();
  return base || null;
}

function allStrings(node, out) {
  out = out || [];
  if (typeof node === 'string') { out.push(node); return out; }
  if (!node) return out;
  if (Array.isArray(node)) { node.forEach(function (x) { allStrings(x, out); }); return out; }
  if (typeof node === 'object') {
    Object.keys(node).forEach(function (k) { allStrings(node[k], out); });
  }
  return out;
}

function stringSet(node) {
  var s = {};
  allStrings(node).forEach(function (v) {
    var t = v.trim();
    if (!t) return;
    s[t] = true;
    s[t.toLowerCase()] = true;
  });
  return s;
}

function inSet(set, value) {
  var t = String(value).trim();
  return !!(set[t] || set[t.toLowerCase()]);
}

function rowKey(type, value) { return type + '\u0000' + value; }

/* The four allowed reasons, plus the two shape classes that are not losses at all.
   Order matters only for the printed detail: the feed's own exemption is checked
   after the table, so a retyped value is reported as a retype rather than as
   whatever container it also happens to sit in. */
var REASONS = {
  'same-value-other-type': 'same value, another type',
  'same-value-other-case': 'same value, another case',
  'non-indicators': 'the feed marks it non-indicator',
  'explicitly-excluded': 'the feed lists it in explicitly_excluded',
  'metadata-reference': 'the feed records it under metadata.reference',
  'feed-withdrawn': 'the feed is no longer published',
  'unexplained': 'UNEXPLAINED'
};

function compare(beforeText, afterText, opts) {
  opts = opts || {};
  var readFeed = opts.readFeed || function () { return null; };
  var before = parse(beforeText);
  var after = parse(afterText);

  var result = {
    before_feeds: Object.keys(before).length,
    after_feeds: Object.keys(after).length,
    before_rows: 0,
    after_rows: 0,
    removed: [],
    counts: {},
    withdrawals: [],
    unexplained: 0
  };

  Object.keys(before).forEach(function (key) {
    result.before_rows += before[key].rows.length + before[key].never_block_rows.length;
  });
  Object.keys(after).forEach(function (key) {
    result.after_rows += after[key].rows.length + after[key].never_block_rows.length;
  });

  var feedCache = {};
  function feedOf(file) {
    if (!file) return null;
    if (!(file in feedCache)) {
      try { feedCache[file] = readFeed(file); } catch (e) { feedCache[file] = null; }
    }
    return feedCache[file];
  }

  Object.keys(before).sort().forEach(function (key) {
    var b = before[key];
    var a = after[key];

    if (!a) {
      var n = b.rows.length + b.never_block_rows.length;
      result.withdrawals.push({ feed: key, rows: n });
      result.removed.push({
        feed: key, type: '-', value: '-', reason: 'feed-withdrawn', rows: n,
        detail: n + ' rows; the feed key is absent from the new table'
      });
      result.counts['feed-withdrawn'] = (result.counts['feed-withdrawn'] || 0) + 1;
      return;
    }

    var seen = {};                       // after rows already matched, per feed
    var afterIndex = {};
    var afterRows = [];
    SECTIONS.forEach(function (sec) {
      (a[sec] || []).forEach(function (r) {
        var k = rowKey(r.type, r.value);
        afterIndex[k] = (afterIndex[k] || 0) + 1;
        afterRows.push({ type: r.type, value: r.value, section: sec });
      });
    });

    SECTIONS.forEach(function (sec) {
      (b[sec] || []).forEach(function (row) {
        var k = rowKey(row.type, row.value);
        if ((seen[k] || 0) < (afterIndex[k] || 0)) { seen[k] = (seen[k] || 0) + 1; return; }

        /* VALUE matches, type or case does not. Prefer the same type (a case-only
           change) over another type, because that is the smaller claim. Only rows
           still unmatched are candidates: a duplicated row in the previous table
           must not be excused by the one copy that survived. */
        var lower = row.value.trim().toLowerCase();
        var same = afterRows.filter(function (r) {
          var rk = rowKey(r.type, r.value);
          return r.value.trim().toLowerCase() === lower &&
            (seen[rk] || 0) < (afterIndex[rk] || 0);
        });
        var pick = same.filter(function (r) { return r.type === row.type; })[0] || same[0];
        if (pick) {
          var reason = pick.type === row.type ? 'same-value-other-case' : 'same-value-other-type';
          var detail = pick.type === row.type
            ? 'now "' + pick.value + '"'
            : 'now ' + pick.type + (pick.section !== sec ? ' in ' + pick.section : '');
          record(key, row, reason, detail);
          return;
        }

        var feed = feedOf(b.feed_file);
        if (feed) {
          if (inSet(stringSet(feed.non_indicators), row.value)) {
            return record(key, row, 'non-indicators', 'non_indicators');
          }
          if (inSet(stringSet(feed.explicitly_excluded), row.value)) {
            return record(key, row, 'explicitly-excluded', 'explicitly_excluded');
          }
          var meta = (feed.metadata && typeof feed.metadata === 'object') ? feed.metadata.reference : null;
          if (inSet(stringSet(meta), row.value)) {
            return record(key, row, 'metadata-reference', 'metadata.reference');
          }
        }

        record(key, row, 'unexplained', feed
          ? 'the feed does not list it as excluded, and no row carries the value'
          : 'no readable feed file (' + (b.feed_file || 'none') +
            '), so its exemptions could not be checked');
      });
    });
  });

  function record(key, row, reason, detail) {
    result.removed.push({ feed: key, type: row.type, value: row.value,
                          reason: reason, detail: detail, rows: 1 });
    result.counts[reason] = (result.counts[reason] || 0) + 1;
    if (reason === 'unexplained') result.unexplained++;
  }

  result.removed.sort(function (x, y) {
    if (x.feed !== y.feed) return x.feed < y.feed ? -1 : 1;
    if (x.reason !== y.reason) return x.reason < y.reason ? -1 : 1;
    return x.value < y.value ? -1 : x.value > y.value ? 1 : 0;
  });
  return result;
}

module.exports = { parse: parse, compare: compare, feedFileOf: feedFileOf,
                   REASONS: REASONS, SECTIONS: SECTIONS };
