'use strict';

/* Per-feed extraction for the IOC feed viewer at /ioc-feeds/<slug>/.

   STRICTLY ADDITIVE over assets/js/ioc-classify.js. That module recognises seven
   atomic types, all network or file-hash, and it also governs the public search
   index and its embargo gate. Re-implementing any part of it here would be a
   second implementation of one rule, and those drift silently: the search would
   disagree with the table about what an indicator is, and nothing would say so.

   So every value is offered to ioc-classify.js first, and only what it declines is
   considered for the four host types this module adds: path, registry, filename,
   endpoint. test/ioc-table-extract.test.js pins that agreement directly.

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
   and `key` all carrying the same kinds of value.

   FOURTH HOST TYPE ADDED 2026-09-22: endpoint (a domain with an explicit port,
   `gulf.moneroocean.stream:10032`). ioc-classify.js's IPv4 regex has always
   accepted an optional `:port` suffix (stripping it from the returned value),
   but its domain regex never grew the matching allowance, so a domain:port
   value fell all the way through classify() AND the three host types above to
   the untyped counter -- silently, because the counter only prints a number,
   never the value itself. Diagnosed on gotenberg-rce-cryptomining-107-175-69-137,
   the corpus's only feed whose hunt_only_never_block bucket carries this shape:
   two mining-pool endpoints, dropped from the rendered "Do not block" table
   entirely rather than rendering with a fallback reason. See hostType() below:
   it delegates the host half back to C.classify() rather than re-deriving the
   domain grammar a second time, keeping the "offered to ioc-classify.js first"
   rule intact even for this derived, port-stripped probe. */

var C = require('../../../assets/js/ioc-classify.js');
var B = require('./benign.js');

// Fields whose contents are commentary about an indicator, never an indicator.
var PROSE_KEYS = ('context confidence notes evidence description rationale summary ' +
  'tactic technique_name technique_id log_source analyst license severity ' +
  'confidence_level campaign title purpose recommendation action priority ' +
  'direction protocol role tlp pattern query false_positive_risk ' +
  'false_positive_note').split(' ')
  .reduce(function (a, k) { a[k] = 1; return a; }, {});

/* Keys that DESCRIBE an entry or its host rather than identify an indicator:
   the ASN and RIR block a host sits in, when it was first and last seen, the
   subject and validity window of a certificate, the feed's own identifiers and
   the free label a feed puts on an entry (`type: "Java source, 3,219 bytes"`).
   They are still walked, so a value that classifies is still a row (a feed that
   puts a domain under `key`, `registry` or the like keeps it). They are only kept
   OUT of the not-typed count, because that count is a warning about
   indicator-shaped values the page cannot type, not a census of every short token
   in a feed. In the pilot these 20 values were most of the 28 reported "not
   typed": five metadata fields, three ASN/registry blocks, four certificate
   fields, two `type: "behavioral"` labels and two registry-looking strings. */
var NON_INDICATOR_KEYS = ('asn registry first_seen last_seen subject issuer organization ' +
  'valid_from valid_to observed_by type platform campaign_id campaign_slug ' +
  'investigation report_date version').split(' ')
  .reduce(function (a, k) { a[k] = 1; return a; }, {});

/* ---- DECLARED KINDS (2026-10-29; design v4 E7, design v3 D8) -------------------

   The walk below was value-shape only. That is right for a value whose shape IS
   the fact: `1.2.3.4` is an address wherever it sits, which is why this module
   never types by bucket name (see the header: `location`, `file_path`,
   `value_data`, `value` and `key` all carry the same kinds of value across the
   corpus). It is wrong in the two situations the pilot measured, and in both the
   FIELD, not the shape, is the only evidence of what the value is.

   1. A FALSE POSITIVE OF SHAPE. `file_hashes.sha256[].filename` holds
      `Relay.java.new` and `dump2.sh`; `host_indicators.file_paths[].path` holds
      `Relay.java`. Each is a bare `label.label` token and ioc-classify.js reads
      that shape as a domain, so the pilot's table offered three operator FILE
      NAMES as blockable domains. `file_paths[].path` also holds
      `/bea_wls_internal/health.jsp` (not under a known system root) and
      `decrypt*.jsp` (no separator at all), which fell through to "not typed"
      although the field says path.

   2. PROSE ENTRIES. A service fingerprint, a relay network signature, a
      behavioural pattern, a mutex name and a host-local VPS name have no shape at
      all: `Server: SimpleHTTP/0.6 Python/3.10.12 serving a directory listing` is a
      sentence. The pilot's 12 such entries were dropped from the table entirely.
      They were counted in the not-typed number, which is honest, but a reader of
      "25 indicators" could not see that the feed carries 41 entries.

   So a declared kind is consulted FIRST, and only where the shape cannot decide:
   a field that names a file, a path field inside a path container, and the
   identifying field of five prose containers. It is not a general return to
   bucket-name typing; every rule below is a field that names its own content.

   WHAT THIS CANNOT COVER, stated because a list-shaped rule must say so: a
   container not on this list keeps the old behaviour, so its prose entries stay
   untyped and counted. A feed that describes a fingerprint under `notes` instead
   of `fingerprint` gains no row, exactly as before.

   A kind may also carry a `label`: the field's own name as a reader-facing
   context, used where the value is opaque and the entry has no context of its own
   (a certificate's serial and fingerprint). It is prefixed to any entry context,
   never substituted for it. */
/* Shapes a generic field name may not overturn (see take()). */
var SHAPE_OUTRANKS_FIELD = { registry: true, url: true, ipv4: true, ipv6: true,
                             email: true, sha256: true, sha1: true, md5: true,
                             endpoint: true };

function pathHas(ctx, k) { return ctx.indexOf(k) !== -1; }

/* A hash's type is its LENGTH, never the field name it sits under. The pilot's
   certificate carries `sha1: aab136e0...` (40 hex); typing every hash field of a
   certificate as sha256 (which this function did until the first review) puts a
   value a defender pastes into a sha256 hunt where it can never match. Returns
   null for a value that is not fixed-length hex, so the caller keeps its default. */
var HASH_LEN_TYPE = { 32: 'md5', 40: 'sha1', 64: 'sha256' };

function hashTypeOf(v) {
  if (typeof v !== 'string') return null;
  var t = v.trim();
  return /^[0-9a-f]+$/i.test(t) ? (HASH_LEN_TYPE[t.length] || null) : null;
}

/* ---- CERTIFICATE SERIALS, ANYWHERE IN A FEED (fix round 3, D7) ----------------

   A certificate entry IS its hash, and its serials are hunt pivots in their own
   right: a certificate reader pastes a serial or a fingerprint into a hunting
   query, and the previous collision search for a reissued listener runs on one or
   the other.

   Serial rows are typed `pattern`, NOT `sha1`. A 40-hex serial has a sha1's SHAPE
   and nothing else: cert serials are commonly 8, 16, 20 or 32 hex bytes, so the
   type would be a value-length accident, and a defender pasting one into a
   file-hash hunt gets a guaranteed miss. `pattern` is the type this table already
   gives an opaque hunt term, and it needs no new hue (see the palette note below).
   Each serial row carries a field label, because the value is opaque: nothing else
   on the row says what it is. The label describes the FIELD, not an analytic claim,
   so it is not the generated commentary the context rules keep out.

   THE KEY NAME DECIDES, NOT THE CONTAINER. Round 2 only reached serials inside
   `tls_certificates`, so two real serials were typed by their length instead:
   opendirectory-62-60's `hunt_only_never_block[].serial` (32 hex, an md5 row) and
   sliver-open-directory's `certificate_serial` (40 hex, a sha1 row). A serial is a
   serial wherever the feed writes it, so the rule lives at the top of take() and
   applies to BOTH walks, including the never-block walk that is otherwise kept as
   the original code path. Inside `tls_certificates` the labels stay specific
   ("TLS certificate serial", "earlier serial"); anywhere else the label is the
   generic "certificate serial". */
var SERIAL_KEYS = { serial: true, earlier_serial: true, certificate_serial: true };

function serialLabel(ctx) {
  if (pathHas(ctx, 'tls_certificates')) {
    return ctx[ctx.length - 1] === 'earlier_serial'
      ? 'earlier serial' : 'TLS certificate serial';
  }
  return 'certificate serial';
}

function declaredKind(ctx, value) {
  var k = ctx.length ? ctx[ctx.length - 1] : null;
  if (!k) return null;

  /* The subject, issuer, organization, key and validity window describe the
     certificate rather than identify anything a defender hunts by, and stay out.
     (An entry's `value` field is left to the shape rule: the three feeds that use
     it beside a real `context` already carry a better label than any field name.) */
  if (pathHas(ctx, 'tls_certificates')) {
    if (k === 'sha256' || k === 'sha1' || k === 'md5') {
      return { type: hashTypeOf(value) || 'sha256', label: 'TLS certificate fingerprint' };
    }
    /* The SPKI hash is a SECOND fingerprint of the same certificate: it survives a
       reissue around the same key pair, which the certificate's own hash does not.
       It had no row label before (a bare 64-hex string); it is a hunt term of its
       own, so it says which one it is. */
    if (k === 'spki_sha256') {
      return { type: hashTypeOf(value) || 'sha256', label: 'TLS certificate SPKI fingerprint' };
    }
    if (k === 'subject' || k === 'issuer' ||
        k === 'organization' || k === 'key' || k === 'valid_from' || k === 'valid_to') {
      return { skip: true };
    }
  }

  /* The field that names a file. `Relay.java.new` and `dump2.sh` are file names
     whose extension looks like a TLD; the field is the evidence, not the shape. */
  if (k === 'filename' || k === 'file_name') return { type: 'filename' };

  /* A path field inside a path container. The corpus spells it two ways:
     `file_paths[].path` (with host_indicators as the container) and
     `filesystem_paths[].value`, whose values (`~/.claude/settings.local.json`,
     `<project-root>/.claude/settings.local.json`) have no shape to classify and
     were producing no row at all, so the actions on them had nowhere to land. */
  if ((k === 'path' || k === 'file_path') &&
      (pathHas(ctx, 'file_paths') || pathHas(ctx, 'host_indicators'))) return { type: 'path' };
  if (k === 'value' && pathHas(ctx, 'filesystem_paths')) return { type: 'path' };

  /* Prose containers: the container is the feed's only statement of what the
     entry is, and the value has no shape to read.

     All five kinds get ONE type, `pattern`, and the reason is the site's own
     palette rule rather than convenience: every type the extractor emits must
     have a hue in custom.scss, hues come from the Wire's existing 12-hue palette
     "rather than invented so a coloured thing on this site means the same kind of
     thing everywhere" (custom.scss, indicator-type palette), and five new hues
     would be invented for kinds a reader distinguishes by their label anyway. The
     feed's own kind is in the entry's role text, which is the row's context. If
     per-kind types are wanted later they need per-kind hues first. */
  if (k === 'fingerprint' && pathHas(ctx, 'service_fingerprints')) return { type: 'pattern' };
  /* The fingerprint entry's own host is support, not a second row: the entry is
     the banner, and the address is carried by the feed's network container (the
     pilot's :80 host would otherwise appear twice, once as an address and once
     inside the fingerprint). */
  if (k === 'host' && pathHas(ctx, 'service_fingerprints')) return { skip: true };
  if (k === 'pattern' && pathHas(ctx, 'network_signatures')) return { type: 'pattern' };
  if (k === 'pattern' && pathHas(ctx, 'behavioral_indicators')) return { type: 'pattern' };
  if (k === 'value' && pathHas(ctx, 'mutex_names')) return { type: 'pattern' };
  if (k === 'value' && pathHas(ctx, 'operator_fingerprints')) return { type: 'pattern' };
  return null;
}

/* A hash-shaped leaf names the entry it belongs to, which is why a hash row with no
   `context`/`description` falls back to the entry's `filename` as its label (see
   `useRole` in take()). It does NOT suppress the filename's own row: the hash and
   the name are two pivots a defender uses, the exact build and the well-known tool,
   and 179 of 283 names existed nowhere in the table when this function also gated
   the label rule. The first review found that as a defender-facing loss and the
   lead reverted it. */
var HASH_SHAPE_RX = /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/i;

function entryHashOf(node) {
  var keys = ['sha256', 'sha1', 'md5', 'value'];
  for (var i = 0; i < keys.length; i++) {
    var v = node[keys[i]];
    if (typeof v === 'string' && HASH_SHAPE_RX.test(v.trim())) return v.trim();
  }
  return null;
}

/* A port on the entry object makes the address entry distinct: the pilot's 9
   address-and-port entries collapsed to 3 rows because three objects carried
   `38.180.16.98` at :53, :9090 and :9443 and the dedupe key was type:value.
   Composing the port into the value keeps every entry the feed declares, and it
   is what the report's own table lists (`38.180.16[.]98:53`).

   The BARE address keeps its own row beside every host:port row, with the same
   entry's action. Composing the port and dropping the bare address narrowed what
   a defender blocks from an address to an address-and-port without saying so, and
   the first review found 9 BLOCK-marked addresses left with no bare row anywhere
   in the table. `push()` dedupes the bare row, so three entries on one address
   still produce one bare row and three ported rows. Ports named only in an
   entry's `notes` are NOT parsed: the feed is the authority on its own fields. */
function portOf(node) {
  var p = node.port;
  if (typeof p === 'number' && isFinite(p) && p >= 0 && p <= 65535) return String(p);
  if (typeof p === 'string' && /^\d{1,5}$/.test(p.trim())) return p.trim();
  return null;
}

/* Fields that carry a human label for the value beside them. `context`, `description`,
   `role` and `note` are unchanged from before this fix and keep first priority: an
   existing, genuinely descriptive label must not be displaced by a routine field.
   `false_positive_risk` and plural `notes` are appended as a FALLBACK, consulted only
   when none of the first four matched (absent, too long for the ordinary cap, or itself
   indicator-shaped) -- see CAVEAT_ROLE_KEYS and isBlockCaveatObject below for why. */
var ROLE_KEYS = ['context', 'description', 'role', 'note', 'false_positive_risk', 'notes'];

/* Subset of ROLE_KEYS treated as a BLOCK caveat, not an ordinary label: exempt from the
   90-char cap (mirroring NB_ROLE_MAXLEN's Infinity, so the reason is read in full rather
   than trimmed to fit a hover label) and, unlike the other ROLE_KEYS, only consulted on an
   object the author marked `action: BLOCK` (see isBlockCaveatObject below).

   Both keys are corpus-wide overloaded for purposes that have nothing to do with a
   blockable indicator's caveat. `false_positive_risk` also rates a DETECTION method's own
   noise (253 occurrences corpus-wide, only 26 of them beside a value AND an
   `action: BLOCK`) and, even restricted to that 26, is sometimes just a routine risk
   rating with no bearing on this specific value (`"false_positive_risk": "low"` on every
   entry of one feed, russian-gemini-credential-mill, where a real `context` already says
   more). Plural `notes` is widely used as an ordinary indicator description with no
   relation to blocking at all (181 occurrences, only 39 beside a value AND
   `action: BLOCK`; see e.g. ioc-feeds/PULSAR-RAT.json's `"notes": "Server hosting the
   PULSAR RAT open directory..."`, which has no `action` field at all).

   Two measured false starts, kept here as the reason for both design choices: putting
   the caveat keys FIRST and gating only on presence changed 242 rows in
   `_data/ioc_tables.yml` against an expected ~51 (the overload above); putting them
   first but action-gated still let a routine "low" rating overwrite a genuinely useful
   existing `context` on 10 rows (the shadowing above). Appending them as a low-priority
   fallback, gated on `action: BLOCK`, fixes both: the two worked examples for this task
   (165.227.175.161's `context` is 139 chars, over the ordinary cap, so it still falls
   through to `false_positive_risk`; mail.hcjs2.jlengineering.se has none of the first
   four fields at all, so it falls through to `notes`) keep working, and an existing
   short, useful label is never displaced by a routine rating. */
var CAVEAT_ROLE_KEYS = { false_positive_risk: true, notes: true };

function isBlockCaveatObject(node) {
  var action = typeof node.action === 'string' ? node.action.trim().toUpperCase() : '';
  return /^BLOCK\b/.test(action);
}

/* A bare risk rating (`low`, `NONE`, `LOW (specific operator-controlled domain)`) is a
   detection-noise score, not a defender warning, however it is spelled: `false_positive_risk`
   is corpus-authored as a rating field first, a caveat second, and a bare or rating-prefixed
   value teaches a reader nothing -- `context: low` reads as broken, not as safe-to-ignore.

   HISTORY, kept because it explains why this is shaped the way it is. The first version
   (2026-09-17) excluded any value STARTING with a rating word. Too broad: it also excluded a
   genuine warning that happens to open with one. Independent review then added a six-word
   directive list (DIRECTIVE_RX below) requiring the remainder to name an action before it would
   survive. Also too narrow, and a SECOND independent review proved it the same day: a directive
   list is exactly the failure mode CLAUDE.md names -- "a check built from an enumeration finds
   what is on the enumeration and reports clean on everything else" -- and two genuine warnings
   using words absent from the six ("...operator owns the host", "...escalate to the abuse desk
   first") were silently dropped.

   INVERTED 2026-09-18, because the two failure directions are not equally bad. Carrying a bare
   rating as if it were a caveat is cosmetic noise: a reader sees `low` and learns nothing new.
   Dropping a genuine caveat is a victim harmed, the exact outcome this whole feature exists to
   prevent. So the rule now fails toward CARRYING: `isRatingOnly()` recognises exactly three
   narrow, testable SHAPES as rating-only, and anything else -- including anything this function
   cannot classify -- is carried, never dropped. This is a shape test, not a widened word list,
   which is the actual fix for the failure mode CLAUDE.md names; DIRECTIVE_RX survives only as a
   narrower, secondary net for phrasing already seen to slip past the shape test (see below).

   The three shapes, verified against every one of the 24 real corpus occurrences (22 bare "low"
   or "NONE", one parenthetical, one comma-qualifier -- see
   test/ioc-table-extract.test.js's "isRatingOnly" tests for the exact list):
     1. Bare: the rating word and nothing else ("low", "NONE").
     2. A single parenthetical immediately after the rating word, its interior one plain,
        unpunctuated fragment under 80 characters: "LOW (specific operator-controlled domain)".
     3. A single comma immediately after the rating word, followed by ONE unpunctuated fragment
        under 80 characters: "NONE, confirmed operator-owned infrastructure".
   A second comma, a semicolon, a period, a `!`/`?`, or any separator other than a lone leading
   comma or a single wrapping parenthetical disqualifies the value from shapes 2 and 3, so it
   falls through to "not rating-only" and is carried. Verified against all four of the reviewer's
   constructed genuine warnings across both review rounds: none fits any of the three shapes
   (each either has no comma/paren separator at all, or has more than one clause-boundary mark),
   so all four are now carried.

   WHAT THIS CANNOT COVER, stated because a list-shaped check must say so (CLAUDE.md, "a
   list-shaped check is only as wide as its list"). A genuine directive using an action word
   absent from DIRECTIVE_RX, phrased as a SINGLE comma-led fragment with no further
   clause-boundary punctuation -- e.g. "LOW, escalate to the abuse desk" (one comma, one clean
   fragment, no listed directive word) -- fits shape 3 and would be wrongly excluded. Closing
   that without either a directive word list (the defect this rewrite fixes) or an actual parser
   is not possible with a regex. It is a stated residual risk, not a gap this rule claims to
   close, and it does not exist in the corpus today (checked: none of the 24 real occurrences is
   a single-comma directive fragment). */
var RATING_RX = /^(none|negligible|low|medium|moderate|high|critical)\b/i;
var DIRECTIVE_RX = /\b(notify|do\s*not|don't|never\s+block|before\s+blocking|coordinate)\b/i;

function isRatingOnly(t) {
  var m = RATING_RX.exec(t);
  if (!m) return false;
  var rest = t.slice(m[0].length).trim();
  if (rest === '') return true;                                    // bare: "low", "NONE"

  var paren = /^\(([^()]*)\)$/.exec(rest);
  if (paren) {
    var inner = paren[1];
    return inner.length > 0 && inner.length <= 80 && !/[,;.!?()]/.test(inner);
  }

  if (rest.charAt(0) === ',') {
    var frag = rest.slice(1).trim();
    return frag.length > 0 && frag.length <= 80 && !/[,;.!?()]/.test(frag);
  }

  return false;   // no bounded qualifier shape recognised -> not rating-only -> carry
}

function isRatingShaped(s) {
  var t = s.trim();
  if (DIRECTIVE_RX.test(t)) return false;   // known instruction phrasing always survives
  return isRatingOnly(t);
}

/* The never-block bucket is read a second time, separately, with its own role
   preference (2026-09-13 fix: see the run's surface-fix-plan.md). It is exempt
   from the ordinary walk below, mirroring lib/feed-hygiene.js's own
   `EXEMPT_TOP`, so a value inside it is never also counted as an ordinary row.

   `metadata` and `non_indicators` join it for the same reason feed-hygiene.js
   already exempts `metadata`: they are the feed talking about itself, not
   indicators. `non_indicators` is the sharp case -- the pilot's own feed says
   "CONTEXT ONLY - DO NOT INGEST AS INDICATORS" over two stock GLPI paths, and the
   walk was counting both of them as values it could not type, i.e. advertising
   the one thing the feed forbids ingesting as an omission from the table.
   `explicitly_excluded` is the same shape: the container lists what the feed
   deliberately withholds.

   `metadata` is exempt as a CONTAINER but not root and branch: `metadata.infrastructure`
   records the hosts the feed treats as operator infrastructure, and in
   opendirectory-45-130-148-125-20260430 the source host `45.130.148.125` is
   recorded there and nowhere else as a bare address, so the blanket exemption
   removed the only row a defender could block (first review, assertion 7). The walk
   therefore descends into `metadata.infrastructure` only (see walk() below);
   `metadata.reference` and every other metadata field stay out, because their
   values are the site's own report URLs and the feed's prose about itself. */
var EXEMPT_TOP = { hunt_only_never_block: true, metadata: true,
                   non_indicators: true, explicitly_excluded: true };

/* Preference order for the never-block section's visible reason column.
   `false_positive_risk` first, because where present it is the most direct
   statement of why the value must not be blocked. `reason` sits right behind
   it for the same reason -- it is what gotenberg-rce-cryptomining-107-175-69-137
   names its own justification field, and no other feed in the corpus uses
   `reason` inside hunt_only_never_block (checked 2026-09-22 against all 18
   feeds carrying the bucket), so adding it cannot re-rank any existing feed's
   choice of label; it only stops this one feed's text from falling through to
   the 'No reason recorded in the feed' fallback it never actually earned.
   Unlike ROLE_KEYS above, this list has no length cap on the field it picks
   (see NB_ROLE_MAXLEN): a reason explaining why a value cannot be blocked is
   meant to be read in full, not trimmed to fit as a hover label the way an
   ordinary indicator's context is. */
var NB_ROLE_KEYS = ['false_positive_risk', 'reason', 'purpose', 'context', 'notes',
                     'note', 'description', 'role'];
var NB_ROLE_MAXLEN = Infinity;

var RX_REGISTRY = /^HK(LM|CU|CR|U|CC|EY_[A-Z_]+)\\/i;
var RX_WIN_PATH = /^(?:[A-Za-z]:\\|%[A-Za-z_][A-Za-z_0-9()]*%|\\\\[^\\])/;
var RX_NIX_PATH = /^\/(etc|usr|tmp|var|opt|home|root|dev|proc|bin|sbin|lib|srv|boot|mnt)\//;

/* A trailing `:<port>` on an otherwise-ordinary domain. Matched generically
   (any suffix of 1-5 digits after the last colon) so the actual domain
   grammar is never re-implemented here -- the candidate host is handed BACK
   to C.classify() below, exactly the same call every atomic value gets, and
   only a 'domain' verdict on that stripped-down probe earns the 'endpoint'
   type. A value that fails on the host half (a path, a registry key, prose
   with a trailing ratio like "9 : 5") never reaches C.classify() with
   anything domain-shaped and is correctly declined. */
var RX_TRAILING_PORT = /^(.+):(\d{1,5})$/;

/* Host types, considered only for values ioc-classify.js declined. Order matters:
   a registry key can contain backslashes that also read as a UNC prefix. */
function hostType(s) {
  if (RX_REGISTRY.test(s)) return 'registry';
  if (RX_WIN_PATH.test(s)) return 'path';
  if (RX_NIX_PATH.test(s)) return 'path';
  /* filename is NOT here. ioc-classify.js gained that type on 2026-08-19, so
     delegation already covers it and a rule here would be the second
     implementation this module exists to avoid. */
  var portMatch = RX_TRAILING_PORT.exec(s);
  if (portMatch) {
    var host = C.classify(portMatch[1]);
    if (host && host.type === 'domain') return 'endpoint';
  }
  return null;
}

var TYPE_ORDER = ['ipv4', 'domain', 'endpoint', 'url', 'sha256', 'sha1', 'md5',
                  'email', 'path', 'registry', 'filename', 'pattern'];

/* Per-row analyst fields, added 2026-10-09: `confidence`, `action` and
   `false_positive_risk` (carried as `fp_risk`), read from the SAME object the
   value sits in and nowhere else. They are display metadata for the viewer's
   extra columns, not inputs to typing, ordering, dedupe or the never-block
   split, none of which reads them.

   Scope is the nearest enclosing object, crossed through arrays but never
   through a nested object: a feed-level `metadata.confidence` must not become
   every row's confidence, and a value inside a sub-object of an indicator
   object does not inherit the parent's rating either. Confidence is upper-cased;
   a one-word action is upper-cased and a multi-word action keeps the feed's own
   case (see actionOf, D8); a one-word fp_risk is lower-cased; all are trimmed; a missing,
   non-string or blank field is null (see actionOf and fpRiskOf below for the
   two values that are deliberately NOT carried). The corpus carries `false_positive_risk: true` on nine
   objects and that is null here rather than "true", because a boolean rating
   is not the vocabulary the column is documented to show. On a duplicated
   value (the same type:value key on several objects) the first object's
   fields win, exactly as its plain context does. */
var NO_META = { confidence: null, action: null, fp_risk: null };

function metaField(v) {
  if (typeof v !== 'string') return null;
  var t = v.trim();
  return t ? t : null;
}

/* `action` is a defender verb (BLOCK, MONITOR, HUNT, ALERT ...) and renders as a
   badge. Some feeds reuse the key for a persistence COMMAND or PATH beside a
   registry value (dual-rat-analysis: `action: %APPDATA%\SUBDIR\CLIENT.EXE`), which
   is not a verb and would render as a clipped badge saying nothing. A value that is
   not verb-led and carries a path separator, a percent sign or a dot is therefore
   not an action for this column and is null; the raw JSON keeps it. A value that IS
   verb-led keeps its dots and slashes: `Sweep developer endpoints for
   .claude/settings.local.json under repository working directories` is an
   instruction, and the separator test dropped three verb-led instructions in
   korean-claude-openclaw-221.150.15.104 (first review, assertion 13). */
var ACTION_NOT_A_VERB = /[\\\/%.]/;

/* The 40-character cap was a proxy for "a badge, not a sentence", and it dropped
   26 real actions in the corpus with it: "BLOCK at network perimeter immediately
   - CRITICAL" (38), "Block at perimeter for non-Korea-Telecom destinations;
   monitor any inbound or outbound to this IP from non-developer-class hosts"
   (138). Those are instructions a defender is meant to follow, and the badge
   already clips at 18em and carries the full text in its `title` (custom.scss,
   .hl_ioctable__act), so the cap was costing information the layout can show.
   A longer value is carried when it OPENS with a defender verb; anything else
   over the cap is still null, because a command or a note does not become an
   action by being long.

   SUSPEND is on the list because russian-gemini-credential-mill-213.165.51.115
   writes one: `SUSPEND + cross-reference with oravepo546-stack`. It was dropped
   by the missing word, not by its shape. */
var ACTION_VERB_RX = /^(block|hunt|monitor|alert|detect|deny|allow|isolate|contain|quarantine|remove|scan|sweep|inventory|audit|investigate|review|correlate|add|deploy|log|record|notify|escalate|verify|check|search|flag|collect|treat|watch|surface|restrict|patch|rotate|suspend)\b/i;
var ACTION_MAXLEN = 200;

/* A badge carries the INSTRUCTION. A clause after it that is not itself verb-led is
   commentary about the value, and the badge has no room to be a sentence: the first
   review named two rows whose second clause is commentary rather than a directive,
   `BLOCK EGRESS FROM YOUR ESTATE; THIS IS THE DISCOVERY VECTOR, NOT AN ATTACK
   SURFACE AGAINST YOUR ENVIRONMENT` (a URL row) and `MONITOR (LEGITIMATE FILE;
   ABUSE DETECTED VIA OUTBOUND NETWORK CONNECTIONS)` (a path row).

   So a long action is cut at the first clause boundary that does not open with a
   defender verb, and a parenthetical left unclosed by that cut is dropped whole
   (the second example reduces to `MONITOR`, which is the instruction it carries).
   Applied only over the cap, so no short action changes shape, and only after the
   verb test, so a command still never becomes an action. A genuine two-part
   instruction keeps both parts, because each opens with a verb: the
   korean-claude-openclaw row keeps its `; MONITOR ANY INBOUND OR OUTBOUND ...`.

   WHAT THIS CANNOT COVER: a commentary tail that itself opens with a verb word
   (`MONITOR X; ALERT ANALYSTS HAVE SEEN THIS BEFORE`) survives, because the rule
   tests the clause's first word, not its meaning; and a tail the feed separated
   with a comma or a dash rather than a semicolon is not cut at all. */
function cutCommentaryTail(t) {
  if (t.length <= 40) return t;
  var parts = t.split(';');
  var kept = [parts[0]];
  for (var i = 1; i < parts.length; i++) {
    if (ACTION_VERB_RX.test(parts[i].trim())) kept.push(parts[i]);
    else break;
  }
  var out = kept.join(';').trim();
  if (out.split('(').length > out.split(')').length) {
    out = out.slice(0, out.lastIndexOf('(')).trim();
  }
  return out || t;
}

/* CASE IS PART OF THE INSTRUCTION (fix round 3, D8). A one-word action is a
   vocabulary term and is upper-cased so badges read alike: `block` is `BLOCK`. A
   multi-word action is a sentence a defender reads, and the feed's own casing
   carries meaning in it -- a hunt string inside it (`WebFetch(domain:...)`), a
   product name, a path. Upper-casing it changed the text ("WEBFETCH(DOMAIN:...)"
   for "WebFetch(domain:...)"), so the only normalisation a multi-word action gets
   is the trim metaField() already applies. */
function actionOf(v) {
  var t = metaField(v);
  if (!t) return null;
  var text;
  if (ACTION_VERB_RX.test(t)) {
    if (t.length > ACTION_MAXLEN) return null;
    text = cutCommentaryTail(t);
  } else {
    if (ACTION_NOT_A_VERB.test(t)) return null;
    if (t.length > 40) return null;
    text = t;
  }
  return /\s/.test(text) ? text : text.toUpperCase();
}

/* `false_positive_risk` is usually a one-word rating (low, medium, high), which is
   normalised to lower case so "Low" and "LOW" render alike. Seventeen rows in the
   corpus carry a sentence instead; lower-casing those would mangle product names
   and an email address, so anything beyond a single word is kept as authored. */
function fpRiskOf(v) {
  var t = metaField(v);
  if (!t) return null;
  return /^[A-Za-z-]+$/.test(t) ? t.toLowerCase() : t;
}

function metaOf(node) {
  var c = metaField(node.confidence);
  return {
    confidence: c ? c.toUpperCase() : null,
    action: actionOf(node.action),
    fp_risk: fpRiskOf(node.false_positive_risk)
  };
}

function typeRank(t) {
  var i = TYPE_ORDER.indexOf(t);
  return i === -1 ? TYPE_ORDER.length : i;
}

/* Runs the walk once against one root node, with its own role-label preference
   and length cap, honouring `exempt` for a top-level key the caller does not
   want descended into. Returns { rows, untyped, keys }; `keys` is the same
   `type:value` set `rows` was built from, exposed so a caller comparing two
   runs (the ordinary walk and the never-block walk) can dedupe between them
   without re-deriving the key format.

   `suppressBenign` gates the benign-value filter (8.8.8.8, github.com, and
   friends). It is correct for the ordinary walk, whose job is a searchable
   index that should not be noisy with values every network sees. It is wrong
   for the never-block walk: a value like `github.com` sitting in
   `hunt_only_never_block` is there because an analyst recorded a specific
   reason not to block it, and the whole point of the never-block section is
   to show that reason, not to re-apply the noise filter and make the value
   disappear a second time, through a different mechanism, from the one place
   meant to explain it. `summarise()` below calls this twice, with the flag
   set only for the ordinary pass. */
function runWalk(root, roleKeys, roleMaxLen, exempt, suppressBenign) {
  /* The ordinary walk is the enhanced one; the never-block walk (roleMaxLen ===
     Infinity) is the original code path, untouched by the declared-kind, port or
     label rules, so its behaviour is provably unchanged. */
  var enhanced = roleMaxLen !== Infinity;
  var byKey = {}, order = [], untyped = 0;
  /* Walk order, kept for the row assembly below. */
  var seq = 0;

  function take(raw, role, roleIsCaveat, meta, ctx, port, label) {
    seq++;
    if (typeof raw !== 'string') return;
    var s = raw.trim();
    if (!s || s.length > 300) return;

    /* A certificate serial is a row wherever the feed writes it, and in both
       walks (D7; see SERIAL_KEYS). It is declared first because the resolved type
       never depends on the value's shape: a 32-hex serial would otherwise be an
       md5 and a 40-hex one a sha1, which is a length accident, not the fact. The
       field label prefixes whatever context the entry carries, as it does for the
       other declared kinds. */
    if (ctx.length && SERIAL_KEYS[ctx[ctx.length - 1]]) {
      var sl = serialLabel(ctx);
      return push('pattern', s, role ? (sl + ' | ' + role) : sl, roleIsCaveat, meta);
    }

    if (enhanced) {
      var kind = declaredKind(ctx, s);
      if (kind && kind.skip) return;
      if (kind && kind.type) {
        var kv = s;
        /* A generic field name (`path`, `filename`) may only overturn the two
           weak verdicts a shape can give: a `label.label` token read as a domain,
           or nothing at all. A registry key, a URL, an address, an email or a
           fixed-length hash keeps the shape's verdict, because the shape is the
           more specific evidence -- `HKLM\...\CurrentVersion\Run` sits under a
           `path` field in arsenal-237-enc_c2-exe.json's file_paths and is a
           registry key, not a path. */
        var probe = null;
        if (kind.type === 'path' || kind.type === 'filename') {
          probe = C.classify(kv) || (hostType(kv) ? { type: hostType(kv) } : null);
        }
        if (!(probe && SHAPE_OUTRANKS_FIELD[probe.type])) {
          /* When the classifier agrees on the TYPE, its normalised value is the one
             to use: filename and domain are lower-cased there, and a filename row
             typed here in original case beside the classifier's lower-cased row for
             the same name is two rows for one file (measured: `CVE-2026-20817_PoC.exe`
             BLOCK and `cve-2026-20817_poc.exe` HUNT, from two containers). */
          if (probe && probe.type === kind.type && typeof probe.value === 'string') {
            kv = probe.value;
          }
          /* A declared FIELD LABEL (`TLS certificate serial`) prefixes whatever
             context the entry itself carries, and never replaces it: the label says
             what the opaque value is, the entry's own text says why it matters. It
             rides with a caveat too, so a BLOCK entry's reason is kept in full. */
          var kindRole = kind.label
            ? (role ? (kind.label + ' | ' + role) : kind.label)
            : role;
          /* An address entry with a port keeps BOTH rows: the bare address (what a
             defender blocks) and the host:port entry (what the feed declared). */
          push(kind.type, kv, kindRole, roleIsCaveat, meta);
          if (kind.type === 'ipv4' && port && kv.indexOf(':') === -1) {
            return push(kind.type, kv + ':' + port, kindRole, roleIsCaveat, meta);
          }
          return;
        }
      }
    }

    var atomic = C.classify(s);
    if (atomic) {
      if (suppressBenign && B.isBenign(atomic.type, atomic.value)) return;   // 8.8.8.8 and friends
      var av = atomic.value;
      /* No role text on a hash entry: its filename is the most useful label. */
      var useRole = role;
      if (enhanced && !useRole && label && HASH_SHAPE_RX.test(av)) useRole = label;
      push(atomic.type, av, useRole, roleIsCaveat, meta);
      /* An address entry that carries a port is its own entry (see portOf), and
         the bare address keeps its row beside it. */
      if (enhanced && port && atomic.type === 'ipv4' && av.indexOf(':') === -1) {
        return push(atomic.type, av + ':' + port, useRole, roleIsCaveat, meta);
      }
      return;
    }

    var h = hostType(s);
    if (h) return push(h, s, role, roleIsCaveat, meta);

    /* Not typed. Only count values that plausibly wanted to be an indicator:
       a short, space-free token, or something path- or hash-shaped. Prose, which
       is most of a feed by volume, is not an omission and must not inflate the
       number the page prints. Fields that describe an entry or its host
       (NON_INDICATOR_KEYS) are not omissions either. A value inside `metadata`
       is never one: that branch is walked only to surface an infrastructure
       address (see EXEMPT_TOP), so `country: "Uzbekistan"` beside it is not an
       indicator the page failed to type. */
    if (enhanced && ctx.length && NON_INDICATOR_KEYS[ctx[ctx.length - 1]]) return;
    if (enhanced && ctx.indexOf('metadata') !== -1) return;
    if (s.length <= 120 && (s.indexOf(' ') === -1 || /[\\/]/.test(s))) untyped++;
  }

  /* The SAME value (type:value key) can appear as more than one raw JSON object -- the
     same IP on three different ports, each with its own `notes` -- and `action: BLOCK`
     plus a caveat field can be repeated on every one of them. First-wins on `byKey[k]`
     would silently drop every caveat but the first author happened to write earliest in
     the array (measured: CloudSync's 91.197.98.188 carries three distinct `notes`, one
     per port, and the pre-fix code kept only the first). So a caveat push (`roleIsCaveat`
     true) for an EXISTING key accumulates into `caveats` instead of being dropped, and
     row assembly below joins every distinct one collected, in encounter order. A
     non-caveat push for an existing key is unchanged: first wins, as before this fix. */
  function push(type, value, role, roleIsCaveat, meta) {
    var k = type + ':' + value;
    var existing = byKey[k];
    if (!existing) {
      byKey[k] = {
        type: type, value: value, context: role || null,
        caveats: (roleIsCaveat && role) ? [role] : [],
        meta: meta || NO_META,
        pos: seq
      };
      order.push(k);
      return;
    }
    if (roleIsCaveat && role && existing.caveats.indexOf(role) === -1) {
      existing.caveats.push(role);
    }
  }

  function walk(node, key, role, roleIsCaveat, meta, ctx, port, label) {
    if (node == null) return;
    if (typeof node === 'string') {
      /* A declared kind outranks PROSE_KEYS: `pattern` is both a prose key and
         the identifying field of a network signature or a behavioural entry. */
      if (PROSE_KEYS[key] && !(enhanced && declaredKind(ctx))) return;
      return take(node, role, roleIsCaveat, meta, ctx, port, label);
    }
    if (Array.isArray(node)) {
      node.forEach(function (x) { walk(x, key, role, roleIsCaveat, meta, ctx, port, label); });
      return;
    }
    if (typeof node !== 'object') return;

    /* The analyst fields are re-read at EVERY object boundary (see metaOf above),
       unlike the role label, which a nested value inherits from its ancestors. */
    var myMeta = metaOf(node);

    /* Same rule for the entry's port and its filename label: re-read at an object
       boundary, inherited through arrays, so a value never takes a sibling entry's
       port or label. */
    var myPort = port;
    var myLabel = label;
    if (enhanced) {
      var p = portOf(node);
      if (p) myPort = p;
      if (entryHashOf(node) && typeof node.filename === 'string' && node.filename.trim()) {
        myLabel = node.filename.trim();
      }
    }

    /* An object may label the value beside it. Take the first role-bearing field
       that is prose rather than an indicator, so `context: "C2 server"` becomes the
       label and `context: "1.2.3.4"` does not. */
    var myRole = role;
    var myRoleIsCaveat = roleIsCaveat;
    if (roleMaxLen === Infinity) {
      /* Never-block walk (NB_ROLE_KEYS/NB_ROLE_MAXLEN): the ORIGINAL single-preference
         loop, completely unmodified by anything below. An entry that legitimately lives
         in hunt_only_never_block never carries `action: BLOCK` (feed-hygiene.js keeps a
         BLOCK-marked value OUT of that bucket, corpus-verified: 0 of the never-block
         bucket's objects anywhere carry that action), so the ordinary-walk logic in the
         other branch could never fire here regardless; kept as a fully separate branch
         so the never-block path is provably untouched code, not just untouched by luck. */
      for (var i = 0; i < roleKeys.length; i++) {
        var rv0 = node[roleKeys[i]];
        if (typeof rv0 === 'string' && rv0.trim() && rv0.length < roleMaxLen && !C.classify(rv0)) {
          myRole = rv0.trim();
          break;
        }
      }
    } else {
      /* Ordinary walk: a plain label (context/description/role/note, same priority and
         90-char cap as always) and a BLOCK caveat (false_positive_risk/notes, gated on
         `action: BLOCK`, exempt from the cap, excluding a rating-shaped value) are found
         INDEPENDENTLY and combined, rather than one replacing the other. Fixes the
         under-coverage a fallback-only design left behind (2026-09-17 review): an object
         commonly carries both a short `role` label AND a substantive `notes` caveat (see
         e.g. radius-sync.com in opendirectory-13-140-145-210-weblogic-...json, `role:
         "Operator-owned domain"` beside `notes: "Origin 13.140.145.210 unmasked from the
         operator's own capture log..."`), and a fallback that only fires when the plain
         label is ABSENT lost the caveat on every one of those. */
      var plainRole = null;
      for (var p = 0; p < roleKeys.length; p++) {
        var pk = roleKeys[p];
        if (CAVEAT_ROLE_KEYS[pk]) continue;                 // caveat keys: see below, separately
        var pv = node[pk];
        if (typeof pv === 'string' && pv.trim() && pv.length < roleMaxLen && !C.classify(pv)) {
          plainRole = pv.trim();
          break;
        }
      }

      var caveatText = null;
      if (isBlockCaveatObject(node)) {
        for (var c = 0; c < roleKeys.length; c++) {
          var ck = roleKeys[c];
          if (!CAVEAT_ROLE_KEYS[ck]) continue;
          var cv = node[ck];
          if (typeof cv === 'string' && cv.trim() && !C.classify(cv) && !isRatingShaped(cv)) {
            caveatText = cv.trim();
            break;
          }
        }
      }

      if (caveatText) {
        myRole = plainRole ? (plainRole + ' | ' + caveatText) : caveatText;
        myRoleIsCaveat = true;
      } else if (plainRole) {
        myRole = plainRole;
        myRoleIsCaveat = false;
      }
    }
    Object.keys(node).forEach(function (k) {
      if (exempt && exempt[k]) {
        /* `metadata` is exempt as a container but its infrastructure branch is
           walked (see EXEMPT_TOP): `metadata.infrastructure.source_ip` is where
           opendirectory-45-130-148-125-20260430 records its only bare address.
           The synthetic one-key object keeps every other metadata field out,
           including `reference` (the site's own report URLs), and gives the
           branch NO_META so `metadata.confidence` is not stamped on the row. */
        if (enhanced && k === 'metadata' && node[k] && typeof node[k] === 'object' &&
            node[k].infrastructure) {
          walk({ infrastructure: node[k].infrastructure }, k, myRole, myRoleIsCaveat,
               NO_META, ctx.concat([k]), null, null);
        }
        return;
      }
      walk(node[k], k, myRole, myRoleIsCaveat, myMeta,
           ctx.concat([k]), myPort, myLabel);
    });
  }

  walk(root, null, null, false, NO_META, [], null, null);

  var rows = order.map(function (k) {
    var r = byKey[k];
    /* A caveat, if any was collected, always wins over whatever plain (non-caveat)
       context this key's context field holds -- the same priority already established
       within one object, extended across every occurrence of this value. Joined with
       " | " so multiple distinct reasons read as separate sentences, not one run-on. */
    var context = r.caveats.length ? r.caveats.join(' | ') : r.context;
    var m = r.meta;
    return { type: r.type, value: r.value, context: context,
             confidence: m.confidence, action: m.action, fp_risk: m.fp_risk };
  });
  // Stable order, so a regenerated page diffs cleanly rather than reshuffling.
  rows.sort(function (a, b) {
    var d = typeRank(a.type) - typeRank(b.type);
    return d !== 0 ? d : (a.value < b.value ? -1 : a.value > b.value ? 1 : 0);
  });
  return { rows: rows, untyped: untyped, keys: order.slice() };
}

/* Returns { rows, untyped, neverBlockRows }. `untyped` counts values that
   looked like they could have been an indicator and were not typed, so the
   page can state the omission.

   `neverBlockRows` is the feed's `hunt_only_never_block` bucket, walked
   separately with its own role preference (NB_ROLE_KEYS) so its reason text
   survives regardless of shape: a flat `{value, category, context}` object,
   a value nested inside a sub-array under a group-level `note` (the
   seasia-gov-exploitation-toolkit shape, which carries no `value` field of
   its own at all), or the fuller `{value, purpose, notes, ...}` shape a more
   careful relocation can leave behind. `EXEMPT_TOP` keeps this bucket out of
   the ordinary walk entirely, so a never-block value is never also an
   ordinary row by default.

   A value that still ends up in both sets (an incomplete migration, not a
   theoretical case: see revert-bad-relocations.md) is resolved toward safety:
   it is dropped from `rows` and kept in `neverBlockRows` only. A row with no
   reason text in any of NB_ROLE_KEYS renders the literal string 'No reason
   recorded in the feed' rather than a blank context, so the gap is visible
   rather than looking like a rendering bug. */
function summarise(feed) {
  var ordinary = runWalk(feed, ROLE_KEYS, 90, EXEMPT_TOP, true);

  var nbRoot = (feed && typeof feed === 'object') ? feed.hunt_only_never_block : null;
  var nb = (nbRoot != null)
    ? runWalk(nbRoot, NB_ROLE_KEYS, NB_ROLE_MAXLEN, null, false)
    : { rows: [], untyped: 0, keys: [] };

  var nbKeySet = {};
  nb.keys.forEach(function (k) { nbKeySet[k] = true; });
  var rows = ordinary.rows.filter(function (r) { return !nbKeySet[r.type + ':' + r.value]; });

  var neverBlockRows = nb.rows.map(function (r) {
    return { type: r.type, value: r.value,
             context: r.context || 'No reason recorded in the feed' };
  });

  return { rows: rows, untyped: ordinary.untyped, neverBlockRows: neverBlockRows };
}

function extract(feed) { return summarise(feed).rows; }

module.exports = {
  extract: extract, summarise: summarise, hostType: hostType,
  TYPE_ORDER: TYPE_ORDER, EXEMPT_TOP: EXEMPT_TOP,
  NB_ROLE_KEYS: NB_ROLE_KEYS
};
