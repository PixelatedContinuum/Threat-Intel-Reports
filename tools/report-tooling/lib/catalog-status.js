'use strict';

/* Publication status per IOC feed, from BOTH of the site's existing signals.

   A campaign under disclosure embargo is published preview-style: live at its
   URL for the people in the disclosure loop, and kept off every listing page.
   Two independent controls express that, and the publish procedure sets them in
   separate steps:

     1. its entry in _data/catalog.yml is commented out
     2. its report front matter carries `unlisted: true`

   A feed is indexed only if BOTH say published. The lookup inherits these
   rather than inventing a third list, because a third list eventually disagrees
   with the other two and the direction it fails is a leak.

   A DISAGREEMENT IS A FAILURE, NOT SOMETHING TO RESOLVE. Because the two are
   set in separate steps they can drift, and a half-completed go-live is exactly
   what drift looks like. Picking either answer silently would either leak an
   embargoed campaign or withhold a published one, so `resolve` reports the
   conflict and the gate stops on it.

   Three states, never two. `unknown` is not folded into `embargoed`: a feed the
   catalog never mentions is in an undefined state, and saying so is the point. */

// Commented blocks in the catalog are INDENTED, so the marker is tested after
// trimming. Missing that is the one bug that would leak an embargoed campaign.
function isCommented(line) { return line.trim().charAt(0) === '#'; }

function field(line, name) {
  // The `- ` list marker sits between the comment marker and the key on an
  // entry's first line, so it must be optional here. Without it every title
  // reads as null and the index ships entries with no campaign name.
  var m = new RegExp('^\\s*#?\\s*-?\\s*' + name + ':\\s*(.+?)\\s*$').exec(line);
  if (!m) return null;
  return m[1].replace(/^["']|["']$/g, '');
}

function basename(url) { return String(url).split('/').pop(); }

function slugOf(feedFile) { return String(feedFile).replace(/-iocs\.json$/, ''); }

/* Catalog signal only. Returns { status, meta } keyed by feed filename. */
function parse(text) {
  var lines = String(text).split(/\r?\n/);
  var status = {}, meta = {};
  var cur = null;

  function flush() {
    if (!cur || !cur.ioc_url) { cur = null; return; }
    var file = basename(cur.ioc_url);
    status[file] = cur.commented ? 'embargoed' : 'published';
    // Deliberately no metadata for an embargoed entry: nothing downstream can
    // render what it was never given.
    if (!cur.commented) {
      meta[file] = {
        title: cur.title || null,
        date: cur.date || null,
        severity: cur.severity || null,
        report_url: cur.report_url || null,
        detection_url: cur.detection_url || null,
        ioc_url: cur.ioc_url
      };
    }
    cur = null;
  }

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (/^\s*#?\s*-\s*title:/.test(line)) {
      flush();
      cur = { commented: isCommented(line), title: field(line, 'title') };
      continue;
    }
    if (!cur) continue;
    ['date', 'severity', 'report_url', 'detection_url', 'ioc_url'].forEach(function (k) {
      var v = field(line, k);
      if (v !== null && cur[k] === undefined) cur[k] = v;
    });
  }
  flush();
  return { status: status, meta: meta };
}

/* Both signals. `unlistedBySlug` maps report slug -> true when that report's
   front matter carries `unlisted: true`.

   Returns { status, meta, conflicts }. A conflict downgrades that feed to
   'embargoed' so the failure direction is withholding rather than leaking, AND
   is reported so a human resolves it. */
function resolve(catalogText, unlistedBySlug) {
  var base = parse(catalogText);
  var unlisted = unlistedBySlug || {};
  var conflicts = [];

  Object.keys(base.status).forEach(function (file) {
    var slug = slugOf(file);
    var catalogSaysPublished = base.status[file] === 'published';
    var frontMatterSaysPublished = !unlisted[slug];

    if (catalogSaysPublished === frontMatterSaysPublished) return;

    conflicts.push({
      feed: file,
      slug: slug,
      catalog: catalogSaysPublished ? 'published' : 'embargoed',
      front_matter: frontMatterSaysPublished ? 'published' : 'unlisted'
    });
    // Fail safe: withhold.
    base.status[file] = 'embargoed';
    delete base.meta[file];
  });

  base.conflicts = conflicts;
  return base;
}

function statusOf(parsed, feedFile) {
  return (parsed && parsed.status && parsed.status[feedFile]) || 'unknown';
}

module.exports = {
  parse: parse,
  resolve: resolve,
  statusOf: statusOf,
  isCommented: isCommented,
  slugOf: slugOf
};
