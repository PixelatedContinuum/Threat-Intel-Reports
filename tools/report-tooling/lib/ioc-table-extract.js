'use strict';

/* Per-feed extraction for the IOC feed viewer at /ioc-feeds/<slug>/.

   STRICTLY ADDITIVE over assets/js/ioc-classify.js. That module recognises seven
   atomic types, all network or file-hash, and it also governs the public search
   index and its embargo gate. Re-implementing any part of it here would be a
   second implementation of one rule, and those drift silently: the search would
   disagree with the table about what an indicator is, and nothing would say so.

   So every value is offered to ioc-classify.js first, and only what it declines is
   considered for the three host types this module adds: path, registry, filename.
   test/ioc-table-extract.test.js pins that agreement directly.

   Why those three and not more. Sampling every leaf string the atomic classifier
   rejects, filtered to structurally indicator-shaped values:

     filename      348   agent_xworm.exe
     windows path  210   %APPDATA%\...\Startup\WinDefenderSvc.exe
     unix path     110   /etc/ld.so.preload
     registry key   63   HKLM\SYSTEM\CurrentControlSet\Services\Bprotect
     long hex       34   a tls_jarm, a decoded ransom note, a Discord snowflake
     single token 1283   boatnet.x86, main_mpsl, and also curl and wget

   The first four are unambiguous by value pattern. The last two are not: nothing
   separates a Mirai payload name from the string "wget", and nothing separates a
   JARM fingerprint from a hex-decoded blob. Typing them would put `curl` in a feed's
   indicator table, which is worse than omitting it. They are counted as not typed
   and left to the raw JSON, because an omission the page states is honest and an
   omission it hides is not.

   Typing is by VALUE PATTERN, never by bucket name, the same rule that made the
   search index work. This corpus has `location`, `file_path`, `value_data`, `value`
   and `key` all carrying the same kinds of value. */

var C = require('../../../assets/js/ioc-classify.js');
var B = require('./benign.js');

// Fields whose contents are commentary about an indicator, never an indicator.
var PROSE_KEYS = ('context confidence notes evidence description rationale summary ' +
  'tactic technique_name technique_id log_source analyst license severity ' +
  'confidence_level campaign title purpose recommendation action priority ' +
  'direction protocol role tlp pattern query').split(' ')
  .reduce(function (a, k) { a[k] = 1; return a; }, {});

// Fields that carry a human label for the value beside them.
var ROLE_KEYS = ['context', 'description', 'role', 'note'];

var RX_REGISTRY = /^HK(LM|CU|CR|U|CC|EY_[A-Z_]+)\\/i;
var RX_WIN_PATH = /^(?:[A-Za-z]:\\|%[A-Za-z_][A-Za-z_0-9()]*%|\\\\[^\\])/;
var RX_NIX_PATH = /^\/(etc|usr|tmp|var|opt|home|root|dev|proc|bin|sbin|lib|srv|boot|mnt)\//;

/* Host types, considered only for values ioc-classify.js declined. Order matters:
   a registry key can contain backslashes that also read as a UNC prefix. */
function hostType(s) {
  if (RX_REGISTRY.test(s)) return 'registry';
  if (RX_WIN_PATH.test(s)) return 'path';
  if (RX_NIX_PATH.test(s)) return 'path';
  /* filename is NOT here. ioc-classify.js gained that type on 2026-08-19, so
     delegation already covers it and a rule here would be the second
     implementation this module exists to avoid. */
  return null;
}

var TYPE_ORDER = ['ipv4', 'domain', 'url', 'sha256', 'sha1', 'md5', 'email',
                  'path', 'registry', 'filename'];

function typeRank(t) {
  var i = TYPE_ORDER.indexOf(t);
  return i === -1 ? TYPE_ORDER.length : i;
}

/* Returns { rows, untyped }. `untyped` counts values that looked like they could
   have been an indicator and were not typed, so the page can state the omission. */
function summarise(feed) {
  var byKey = {}, order = [], untyped = 0;

  function take(raw, role) {
    if (typeof raw !== 'string') return;
    var s = raw.trim();
    if (!s || s.length > 300) return;

    var atomic = C.classify(s);
    if (atomic) {
      if (B.isBenign(atomic.type, atomic.value)) return;   // 8.8.8.8 and friends
      return push(atomic.type, atomic.value, role);
    }

    var h = hostType(s);
    if (h) return push(h, s, role);

    /* Not typed. Only count values that plausibly wanted to be an indicator:
       a short, space-free token, or something path- or hash-shaped. Prose, which
       is most of a feed by volume, is not an omission and must not inflate the
       number the page prints. */
    if (s.length <= 120 && (s.indexOf(' ') === -1 || /[\\/]/.test(s))) untyped++;
  }

  function push(type, value, role) {
    var k = type + ':' + value;
    if (byKey[k]) return;
    byKey[k] = { type: type, value: value, context: role || null };
    order.push(k);
  }

  function walk(node, key, role) {
    if (node == null) return;
    if (typeof node === 'string') {
      if (PROSE_KEYS[key]) return;
      return take(node, role);
    }
    if (Array.isArray(node)) {
      node.forEach(function (x) { walk(x, key, role); });
      return;
    }
    if (typeof node !== 'object') return;

    /* An object may label the value beside it. Take the first role-bearing field
       that is prose rather than an indicator, so `context: "C2 server"` becomes the
       label and `context: "1.2.3.4"` does not. */
    var myRole = role;
    for (var i = 0; i < ROLE_KEYS.length; i++) {
      var rv = node[ROLE_KEYS[i]];
      if (typeof rv === 'string' && rv.trim() && rv.length < 90 && !C.classify(rv)) {
        myRole = rv.trim();
        break;
      }
    }
    Object.keys(node).forEach(function (k) { walk(node[k], k, myRole); });
  }

  walk(feed, null, null);

  var rows = order.map(function (k) { return byKey[k]; });
  // Stable order, so a regenerated page diffs cleanly rather than reshuffling.
  rows.sort(function (a, b) {
    var d = typeRank(a.type) - typeRank(b.type);
    return d !== 0 ? d : (a.value < b.value ? -1 : a.value > b.value ? 1 : 0);
  });
  return { rows: rows, untyped: untyped };
}

function extract(feed) { return summarise(feed).rows; }

module.exports = {
  extract: extract, summarise: summarise, hostType: hostType,
  TYPE_ORDER: TYPE_ORDER
};
