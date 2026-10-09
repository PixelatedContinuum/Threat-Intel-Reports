'use strict';

/* Verifies the catalog tags in _data/catalog.yml against the vocabulary in
   _data/tags.yml.

   The failure this exists for is drift nobody can see from one entry. The
   listing filter builds its chips from tags that appear on three or more
   entries, and tag-badge.html picks a badge colour by tag name. Both compare
   strings exactly, so "Open Dir", "OpenDirectory" and "Open Directory" were
   three different tags to the site: none reached the chip threshold on its own,
   each looked fine in the entry that carried it, and the chip row quietly lost
   the one tag this corpus is actually about. tags.yml is the one place the
   spelling is decided; this gate is what makes that decision stick.

   PASS, FAIL and NOT CHECKED, the third never folded into the first. Either
   file missing or unparseable means this run verified nothing, and says so
   rather than reporting a clean sweep of zero. See
   homelab-soc/docs/gate-honesty-contract.md. */

// The badge palette tag-badge.html maps onto assets/css/custom.css. A colour
// outside this set renders a chip with no colour class: it still displays, it
// just goes grey among coloured siblings.
var COLORS = { blue: 1, red: 1, green: 1, purple: 1, yellow: 1 };

// Every key a listing page reads tags from. The three overrides fall back to
// `tags` in Liquid (`e.ioc_tags | default: e.tags`), so an override carries the
// same exact-string obligation as the shared list does.
var TAG_FIELDS = ['tags', 'detection_tags', 'ioc_tags', 'stix_tags'];

function verdict(status, reason, problems, warnings, counts) {
  return {
    status: status,
    reason: reason || null,
    problems: problems || [],
    warnings: warnings || [],
    counts: counts || null
  };
}

/* Spellings are compared folded and trimmed so that "open dir " and "Open Dir"
   collide. The fold is only for FINDING the match; the verdict still insists on
   the exact canonical string, because the site compares exactly. */
function fold(s) {
  return String(s).trim().toLowerCase();
}

function isObject(x) {
  return x !== null && typeof x === 'object' && !Array.isArray(x);
}

/* `catalogDoc` is the parsed catalog.yml, or null when it could not be read.
   `tagsDoc` is the parsed tags.yml, or null likewise. Commented-out catalog
   entries never reach this function: the YAML parser drops them, which is the
   layer that decides what is published and so the right layer to decide what
   is checked. */
function check(catalogDoc, tagsDoc) {
  if (!isObject(catalogDoc)) {
    return verdict('NOT CHECKED', '_data/catalog.yml is absent or unparseable, ' +
      'so no catalog tag was verified. Restore the file and re-run.');
  }
  if (!isObject(tagsDoc) || !Array.isArray(tagsDoc.tags)) {
    return verdict('NOT CHECKED', '_data/tags.yml is absent, unparseable or ' +
      'declares no `tags:` list, so no catalog tag was verified against the ' +
      'vocabulary. Restore the file and re-run.');
  }

  var problems = [];
  var warnings = [];

  /* ---- The vocabulary itself. ------------------------------------------
     A broken vocabulary cannot adjudicate anything, and every catalog verdict
     below depends on it, so its defects are FAILs on the file by name. */

  // folded spelling -> { canonical, viaAlias } for every spelling the file claims.
  var known = Object.create(null);
  // exact canonical spelling -> 1, for the exact-match test on catalog tags.
  var canonical = Object.create(null);

  function claim(spelling, entryName, viaAlias) {
    var k = fold(spelling);
    if (!k) {
      problems.push('tags.yml entry "' + entryName + '" carries an empty ' +
        (viaAlias ? 'alias' : 'tag'));
      return;
    }
    if (known[k]) {
      /* Two entries owning one spelling means the gate would have to pick a
         winner, and whichever it picked, the other entry's colour or canonical
         form would be silently wrong. Case-insensitive on purpose: "Stealer"
         and "stealer" are one tag to a reader and two to the site. */
      problems.push('tags.yml entry "' + entryName + '" ' +
        (viaAlias ? 'lists alias' : 'has tag') + ' "' + spelling +
        '", which is already claimed by "' + known[k].canonical + '"' +
        (known[k].viaAlias ? ' as an alias' : '') +
        '. One spelling must belong to exactly one entry.');
      return;
    }
    known[k] = { canonical: entryName, viaAlias: !!viaAlias };
  }

  tagsDoc.tags.forEach(function (t, i) {
    var where = 'tags.yml entry ' + (i + 1);
    if (!isObject(t) || typeof t.tag !== 'string' || !t.tag.trim()) {
      problems.push(where + ' has no string `tag`: ' + JSON.stringify(t));
      return;
    }
    var name = t.tag;
    if (name !== name.trim()) {
      problems.push('tags.yml entry "' + name + '" has surrounding whitespace ' +
        'in its canonical spelling, which no catalog entry could then match exactly');
    }
    if (typeof t.color !== 'string' || !COLORS[t.color]) {
      problems.push('tags.yml entry "' + name + '" has colour ' +
        JSON.stringify(t.color === undefined ? null : t.color) +
        ', which is not one of ' + Object.keys(COLORS).join(', ') +
        ' (the badge palette in assets/css/custom.css)');
    }
    canonical[name] = 1;
    claim(name, name, false);

    if (t.aliases !== undefined) {
      if (!Array.isArray(t.aliases)) {
        problems.push('tags.yml entry "' + name + '" has `aliases` that is not ' +
          'a list: ' + JSON.stringify(t.aliases));
      } else {
        t.aliases.forEach(function (a) {
          if (typeof a !== 'string') {
            problems.push('tags.yml entry "' + name + '" lists a non-string ' +
              'alias: ' + JSON.stringify(a));
            return;
          }
          claim(a, name, true);
        });
      }
    }
  });

  /* ---- The catalog against it. ------------------------------------------ */

  var entries = Array.isArray(catalogDoc.entries) ? catalogDoc.entries : [];
  var nEntries = 0;
  var nTags = 0;
  var unknownSeen = Object.create(null);
  var nUnknown = 0;

  entries.forEach(function (e, i) {
    if (!isObject(e)) return;
    nEntries++;
    var title = String(e.title || '?').slice(0, 60);
    var where = 'entry ' + (i + 1) + ' ("' + title + '")';

    TAG_FIELDS.forEach(function (field) {
      if (!Object.prototype.hasOwnProperty.call(e, field)) return;
      var list = e[field];
      if (!Array.isArray(list)) {
        problems.push(where + ' has `' + field + '` that is not a list: ' +
          JSON.stringify(list));
        return;
      }
      var label = field === 'tags' ? 'tag' : field + ' tag';
      var seenInList = Object.create(null);

      list.forEach(function (raw) {
        nTags++;
        var tag = String(raw);
        var k = fold(tag);

        /* Duplicates within one list render two identical badges and count the
           entry twice toward the chip threshold, so the chip appears on the
           strength of a typo. */
        if (seenInList[k]) {
          problems.push(where + ' lists ' + label + ' "' + tag + '" twice');
          return;
        }
        seenInList[k] = 1;

        var hit = known[k];
        if (!hit) {
          /* Unknown is a warning, not a FAIL: a genuinely new tag has to be
             typed somewhere first, and blocking it would push the author to
             reuse a near-miss instead, which is the drift this gate exists to
             stop. The warning names it so the vocabulary grows deliberately. */
          if (!unknownSeen[k]) { unknownSeen[k] = 1; nUnknown++; }
          warnings.push(where + ' carries ' + label + ' "' + tag + '", which ' +
            '_data/tags.yml does not know: add it to _data/tags.yml or use an ' +
            'existing tag');
          return;
        }
        if (hit.viaAlias) {
          problems.push(where + ' uses ' + label + ' "' + tag + '", a retired ' +
            'spelling; use "' + hit.canonical + '"');
          return;
        }
        /* Right tag, wrong bytes. Badge colour lookup and the chip threshold
           are both exact-string, so "stealer" and "Stealer " are each a tag of
           their own to the site, with no colour and no chip. */
        if (!canonical[tag]) {
          problems.push(where + ' has ' + label + ' "' + tag + '", which ' +
            'differs from the canonical "' + hit.canonical + '" only in case ' +
            'or surrounding whitespace; badge colour lookup is exact, so use ' +
            '"' + hit.canonical + '" verbatim');
        }
      });
    });
  });

  return verdict(problems.length ? 'FAIL' : 'PASS', null, problems, warnings, {
    entries: nEntries, tags: nTags, unknown: nUnknown
  });
}

module.exports = { check: check, COLORS: COLORS, TAG_FIELDS: TAG_FIELDS };
