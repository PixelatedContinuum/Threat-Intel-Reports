'use strict';

/* Metadata fields that belong to the PRIVATE vault feed and must never reach a published one.

   WHY THIS EXISTS (T-0662). The vault feed at threat-intel-vault/ioc-feeds/<slug>-iocs.json is
   the private record. Since 2026-09-01 it declares, under `metadata.victim_names`, the victim
   organisation names, hostnames and internal addresses of the campaign, so that
   .claude/scripts/check_victim_naming.py can search every published artifact for them. The
   go-live step then copied that vault feed into this repo's ioc-feeds/ whole, list included:
   the one field that exists to keep victims off the site was itself published. Measured
   2026-11-17: ioc-feeds/rovodev-mirai-matrix-c2-87.106.143.220-iocs.json carried one declared
   name, and three more live feeds carried an empty `victim_names: []`.

   The same route carries `victim_names_note`, the vault's prose about that list (its own text
   reads "the site copy omits them"), so it is private for the same reason.

   A field joins this list when it exists only to feed a gate or to describe withheld data,
   not because its value happens to be sensitive. The Python gate keeps its own copy of this
   list (check_victim_naming.py PRIVATE_METADATA_KEYS); its test pins the two together.

   Used by publish-feed.js (the copy), and by generate-ioc-index.js and lib/ioc-tables.js (the
   derived outputs strip before walking, so a feed copied by hand still cannot carry the list
   into the search index or the indicator pages). */

var PRIVATE_METADATA_KEYS = ['victim_names', 'victim_names_note'];

function isObject(v) { return !!v && typeof v === 'object' && !Array.isArray(v); }

/* The private keys present in a feed's metadata, in list order, whatever their value. */
function privateKeysIn(feed) {
  if (!isObject(feed) || !isObject(feed.metadata)) return [];
  return PRIVATE_METADATA_KEYS.filter(function (k) {
    return Object.prototype.hasOwnProperty.call(feed.metadata, k);
  });
}

/* A copy of the feed without the private metadata keys, and the keys removed. The input is
   not modified. The order of every kept key is preserved, so a published copy diffs against
   the vault feed by the removed lines only. */
function strip(feed) {
  var removed = privateKeysIn(feed);
  if (!removed.length) return { feed: feed, removed: [] };
  var meta = {};
  Object.keys(feed.metadata).forEach(function (k) {
    if (removed.indexOf(k) === -1) meta[k] = feed.metadata[k];
  });
  var out = {};
  Object.keys(feed).forEach(function (k) { out[k] = k === 'metadata' ? meta : feed[k]; });
  return { feed: out, removed: removed };
}

module.exports = { PRIVATE_METADATA_KEYS: PRIVATE_METADATA_KEYS, privateKeysIn: privateKeysIn, strip: strip };
