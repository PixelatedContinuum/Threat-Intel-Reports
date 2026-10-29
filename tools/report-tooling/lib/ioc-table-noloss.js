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
   that was present before and is absent after is a failure unless one of the
   reasons design-v4 check 5 allows applies:

     same value, another type        the extractor retyped it (domain -> filename)
     same value, another case        the classifier normalised it (Name -> name)
     the feed itself says not an indicator   non_indicators, explicitly_excluded,
                                     or metadata.reference (the site's own
                                     report URL)

   Each excuse is bounded, because each one is a way a real loss can hide (round-2
   review, 2026-10-29; the lead's decisions D2-D6):

   - A retype or case change is excused only when the SURVIVING row is in the same
     feed's block AND, when the previous row carried an action, the surviving row
     carries the same action (case-insensitive). A retype that drops `BLOCK` is
     reported UNEXPLAINED with the detail "action lost" (D2). The action is part of
     what a defender reads off the row, so it is part of what may not vanish.
   - Case-insensitive value matching is allowed only for the hash types and
     domain/hostname (D6). A URL, path, filename or pattern is compared exactly: a
     URL path is case-sensitive on most servers, so a case change there is a
     different value, not a normalisation.
   - A whole feed block may disappear only when the feed's JSON is absent from
     ioc-feeds/ or the feed is embargoed by the generator's own status rule. A feed
     whose JSON is present and published but produced no block is UNEXPLAINED,
     class "feed dropped while published" (D3): that is the shape an extraction
     regression leaves, and the regenerate-and-diff half cannot see it, because a
     narrower extraction still matches the feeds.
   - The exemptions read only the indicator VALUE fields of the three containers
     (string items, and `value`/`values`/`indicator`/`url`/hash-shaped keys of
     object items). `reason`, `note` and `description` are commentary about a
     value and are never read as one (D5). A value that appears only in that prose
     is not exempt.
   - The feed JSON is read from the WORKING TREE, deliberately (D5, rejected
     alternative): a feed edit that adds an exclusion is a reviewed change to the
     feed in the same commit, and reading HEAD instead would let a working-tree
     exclusion excuse a row while the committed feed still calls it an indicator.
     The reviewer therefore reads the feed diff alongside this gate's output.

   A value that moves between `rows` and `never_block_rows` is not a removal at all:
   the value is still in the feed's table, so there is nothing to excuse.

   ZERO IS NOT A PASS (D4). A previous side with no rows (an empty mapping, a
   scalar file, a table whose entries carry no rows) is NOT COMPARABLE and the
   caller reports NOT CHECKED; it never renders as "0 removed". A new side with 0
   rows while the previous has rows is a FAIL (`result.fatal`), even if every feed
   would otherwise be excused.

   WHAT THIS DOES NOT COVER, stated because a row-presence check is only as wide as
   presence:

   - Row DETAIL that changes while the row survives: a context that thins, a
     confidence that moves, an action that appears or changes on a row that was
     already present (the D2 guard covers the two excuse classes, not the exact
     match). Check 5's sentence is about rows; this module enforces rows plus the
     action on an excused row. A stricter form would compare the full row object,
     and would fail on the deliberate retypes and label additions.
   - A row whose VALUE changed by a character other than a foldable case (a trailing
     slash, a stripped port) is a removal plus an addition, and is reported as a
     removal. The reason must be a feed-side exemption or the person's call to pass
     a different --against.
   - The baseline is the previous PUBLISHED table. A committed lossy table becomes
     the next run's baseline, and this module cannot see that (D9, rejected by the
     lead): enforcement is the pre-commit hook plus publish step 1g, both of which
     run this checker before the table is committed or deployed.

   NOT CHECKED is a real outcome: a before-table with no rows, or a feed file that
   cannot be read for a feed whose rows went missing, means the exemptions could not
   be evaluated, and the caller must not treat that as a pass. */

var yaml = require('js-yaml');

var SECTIONS = ['rows', 'never_block_rows'];

/* Hash hex is the same bytes in either case; a host name is case-insensitive by
   DNS. Everything else -- a URL path, a filesystem path, a file name, an opaque
   pattern -- is compared exactly (D6). */
var CASE_FOLDED_TYPES = { md5: true, sha1: true, sha256: true,
                          domain: true, hostname: true };

/* The value-carrying fields of an exemption item. `reason`, `note`, `description`
   and `warning` are deliberately absent: they are commentary about a value, and a
   row whose whole text happens to equal a reason string is not an indicator the
   feed excluded (D5). `values` is the plural the corpus uses for group items
   (multivector-ecommerce-rce-toolkit, russian-gemini-credential-mill), and a
   hash-algorithm key carries a watched value in the same way `value` does. */
var EXEMPT_VALUE_KEYS = { value: true, values: true, indicator: true,
                          indicators: true, url: true, urls: true,
                          hash: true, hashes: true, sha1: true, sha256: true,
                          md5: true, sha512: true };

function isExemptValueKey(k) {
  return !!EXEMPT_VALUE_KEYS[k] || /hash/i.test(k);
}

function asRows(list) {
  var out = [];
  (list || []).forEach(function (r) {
    if (!r || typeof r !== 'object') return;
    if (typeof r.value !== 'string' || !r.value) return;
    var a = (typeof r.action === 'string' && r.action.trim()) ? r.action.trim() : null;
    out.push({ type: String(r.type || ''), value: r.value, action: a });
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

/* The indicator VALUES of an exemption container, and nothing else. A string item
   is a value; an object item contributes only its value-carrying fields (D5). */
function exemptionStrings(node, out) {
  out = out || [];
  if (typeof node === 'string') { out.push(node); return out; }
  if (!node) return out;
  if (Array.isArray(node)) {
    node.forEach(function (x) { exemptionStrings(x, out); });
    return out;
  }
  if (typeof node === 'object') {
    Object.keys(node).forEach(function (k) {
      if (isExemptValueKey(k)) exemptionStrings(node[k], out);
    });
  }
  return out;
}

function stringSet(node) {
  var s = {};
  exemptionStrings(node).forEach(function (v) {
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

/* The allowed reasons, plus the shape classes that are not losses at all.
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
  'feed-dropped-while-published': 'the feed was dropped while still published',
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
    unexplained: 0,
    fatal: []
  };

  Object.keys(before).forEach(function (key) {
    result.before_rows += before[key].rows.length + before[key].never_block_rows.length;
  });
  Object.keys(after).forEach(function (key) {
    result.after_rows += after[key].rows.length + after[key].never_block_rows.length;
  });

  /* D4: a zero denominator is not a clean result. The previous side is what the
     whole comparison is a denominator over; with no rows there is nothing to have
     lost, and reporting "0 removed" would read exactly like a pass. */
  if (result.before_rows === 0) {
    throw new Error('the previous table has no rows (' + result.before_feeds +
      ' feeds, 0 rows), so there is nothing to compare: a zero denominator is ' +
      'NOT CHECKED, never a clean pass');
  }

  /* D4: a new side that lost every row is a FAIL even where the per-feed classes
     would excuse each block (an unavailable feed file would). */
  if (result.after_rows === 0) {
    result.fatal.push('the new table has 0 rows while the previous has ' +
      result.before_rows + ': the regeneration lost the whole table, which is ' +
      'never a legitimate change. Design v4 check 5: IOC tables lose nothing.');
  }

  var feedCache = {};
  function feedOf(file) {
    if (!file) return null;
    if (!(file in feedCache)) {
      try { feedCache[file] = readFeed(file); } catch (e) { feedCache[file] = null; }
    }
    return feedCache[file];
  }

  /* { exists, status }. The default derives `exists` from readFeed (no readable
     feed file means the block's disappearance cannot be checked against a live
     feed) and reports `unknown` for a file that IS readable: by D3 that status
     never excuses a dropped block. */
  var feedState = opts.feedState || function (file) {
    if (!file) return { exists: false, status: null };
    var f = feedOf(file);
    return f ? { exists: true, status: 'unknown' } : { exists: false, status: null };
  };

  Object.keys(before).sort().forEach(function (key) {
    var b = before[key];
    var a = after[key];

    if (!a) {
      var n = b.rows.length + b.never_block_rows.length;
      var state = feedState(b.feed_file) || { exists: false, status: null };

      /* D3: only a feed whose JSON is gone, or which the generator's own status
         rule calls embargoed, may lose its whole block. Everything else is the
         shape an extraction regression leaves: the file is there and published,
         the block is not, and regenerate-and-diff cannot see it. */
      if (!state.exists) {
        result.withdrawals.push({ feed: key, rows: n, why: 'json absent' });
        result.removed.push({
          feed: key, type: '-', value: '-', reason: 'feed-withdrawn', rows: n,
          detail: n + ' rows; the feed key is absent from the new table and its ' +
            'JSON is absent from ioc-feeds/'
        });
        result.counts['feed-withdrawn'] = (result.counts['feed-withdrawn'] || 0) + 1;
        return;
      }
      if (state.status === 'embargoed') {
        result.withdrawals.push({ feed: key, rows: n, why: 'embargoed' });
        result.removed.push({
          feed: key, type: '-', value: '-', reason: 'feed-withdrawn', rows: n,
          detail: n + ' rows; the feed key is absent from the new table and the ' +
            'feed is embargoed'
        });
        result.counts['feed-withdrawn'] = (result.counts['feed-withdrawn'] || 0) + 1;
        return;
      }

      result.removed.push({
        feed: key, type: '-', value: '-', reason: 'feed-dropped-while-published',
        rows: n,
        detail: n + ' rows; the feed JSON is present and its status is "' +
          (state.status || 'unreadable') + '", so its block disappearing is a loss'
      });
      result.counts['feed-dropped-while-published'] =
        (result.counts['feed-dropped-while-published'] || 0) + n;
      result.unexplained += n;
      return;
    }

    var seen = {};                       // after rows already matched, per feed
    var afterIndex = {};
    var afterRows = [];
    SECTIONS.forEach(function (sec) {
      (a[sec] || []).forEach(function (r) {
        var k = rowKey(r.type, r.value);
        afterIndex[k] = (afterIndex[k] || 0) + 1;
        afterRows.push({ type: r.type, value: r.value, action: r.action,
                         section: sec });
      });
    });

    function available(r) {
      var k = rowKey(r.type, r.value);
      return (seen[k] || 0) < (afterIndex[k] || 0);
    }

    /* D6: fold case only where the case is not the fact. The disappearing row's
       own type decides, because that is the value being excused. */
    function sameValue(row, cand) {
      if (cand.value === row.value) return true;
      return !!CASE_FOLDED_TYPES[row.type] &&
        cand.value.trim().toLowerCase() === row.value.trim().toLowerCase();
    }

    /* D2: an action the previous row carried must survive on the surviving row. */
    function sameAction(row, cand) {
      if (!row.action) return true;
      return !!cand.action && cand.action.toLowerCase() === row.action.toLowerCase();
    }

    SECTIONS.forEach(function (sec) {
      (b[sec] || []).forEach(function (row) {
        var k = rowKey(row.type, row.value);
        if (available(row)) { seen[k] = (seen[k] || 0) + 1; return; }

        /* The value matches (under the D6 case rule), but the type, the case or
           the section does not. Candidates are rows still unmatched, so a
           duplicated row in the previous table is not excused by the one copy
           that survived. */
        var candidates = afterRows.filter(function (r) {
          return available(r) && sameValue(row, r);
        });
        var viable = candidates.filter(function (r) { return sameAction(row, r); });
        var pick = viable.filter(function (r) {
                     return r.type === row.type && r.section === sec;
                   })[0] ||
                   viable.filter(function (r) { return r.type === row.type; })[0] ||
                   viable.filter(function (r) { return r.section === sec; })[0] ||
                   viable[0];
        if (pick) {
          var reason = pick.type === row.type ? 'same-value-other-case'
                                              : 'same-value-other-type';
          var detail = pick.type === row.type
            ? 'now "' + pick.value + '"'
            : 'now ' + pick.type + (pick.section !== sec ? ' in ' + pick.section : '');
          record(key, row, reason, detail);
          seen[rowKey(pick.type, pick.value)] =
            (seen[rowKey(pick.type, pick.value)] || 0) + 1;
          return;
        }
        if (candidates.length) {
          /* D2: the value is still there, but not the instruction that came with
             it. A row that says BLOCK is not the same row without it. */
          record(key, row, 'unexplained',
            'action lost (the surviving ' + candidates[0].type + ' row carries ' +
            (candidates[0].action ? '"' + candidates[0].action + '"' : 'no action') +
            ', the removed row carried "' + row.action + '")');
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
          var meta = (feed.metadata && typeof feed.metadata === 'object')
            ? feed.metadata.reference : null;
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
                   REASONS: REASONS, SECTIONS: SECTIONS,
                   CASE_FOLDED_TYPES: CASE_FOLDED_TYPES };
