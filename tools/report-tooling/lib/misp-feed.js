'use strict';

/* The MISP feed: feeds/misp/manifest.json, one event file per published
   campaign and hashes.csv, in the "MISP" feed source format that MISP pulls
   natively and OpenCTI reads through its MISP-feed connector.

   One event per catalog entry. The indicators come from the campaign's STIX
   bundle (stix/<slug>.json), which is already de-named and safety-checked
   before it is published, and ONLY from Indicator objects: a value the bundle
   carries as a bare observable with no indicator (a mining pool, a co-tenant
   domain, anything a feed marks do-not-block) is left out, because a MISP
   attribute is something a subscriber may block on. The rules come from the
   detection page (hunting-detections/<slug>-detections.md) through the same
   parser the detection manifests use, with the tier deciding to_ids: a
   Detection rule is for alerting, a Hunting rule is broad by design and ships
   with to_ids false. Links to the report, the detection page, the STIX bundle
   and the IOC feed ride along as reference attributes.

   Identity is deterministic. Event and attribute uuids are UUIDv5 under one
   namespace, derived from the campaign slug and the attribute's type and
   value, so a rebuild never issues a second uuid for the same thing and a
   subscriber's copy updates in place. Timestamps are the one thing a rebuild
   must not touch unless content changed: feeds/misp/_state.json keeps each
   event's content hash and the timestamp it was last changed at, and the
   generator bumps a timestamp only when the hash moves. A withdrawn event
   stays in the state as withdrawn (its uuid is never reused) and must be
   itemised in feeds/misp/changelog.md, which the gate checks.

   Pure on its inputs so it can be tested on fixtures; generate-misp-feed.js
   and check-misp-feed.js do the reading and writing. */

var crypto = require('node:crypto');
var path = require('node:path');

var ROOT = path.join(__dirname, '..', '..', '..');
var FEED_DIR = path.join(ROOT, 'feeds', 'misp');
var STATE_FILE = path.join(FEED_DIR, '_state.json');
var MANIFEST_FILE = path.join(FEED_DIR, 'manifest.json');
var HASHES_FILE = path.join(FEED_DIR, 'hashes.csv');
var CHANGELOG_FILE = path.join(FEED_DIR, 'changelog.md');
var STIX_DIR = path.join(ROOT, 'stix');

var SITE = 'https://the-hunters-ledger.com';
/* uuid5(NAMESPACE_DNS, 'the-hunters-ledger.com/feeds/misp'). Fixed for the life
   of the feed: changing it would re-issue every uuid. */
var NAMESPACE = '4823c11f-75c0-5bff-8865-6a4375f02c86';
/* The site's STIX identity (identity--8bc8284b-...), reused so the MISP Orgc
   and the STIX creator are one organisation to a platform holding both. */
var ORGC = { name: 'The Hunters Ledger', uuid: '8bc8284b-deb5-546c-a233-57ea34b2ea0d' };

var TAG_COLOURS = { tlp: '#ffffff', galaxy: '#0088cc', topic: '#58a6ff', actor: '#e879f9', tier: '#4ade80' };
var THREAT_LEVEL = { critical: 1, high: 1, medium: 2, med: 2, low: 3 };
var RULE_TYPES = { yara: 'yara', sigma: 'sigma', suricata: 'snort' };
var RULE_CATEGORY = { yara: 'Payload installation', sigma: 'Payload installation', snort: 'Network activity' };
/* Below this x_opencti_score an indicator is context, not something to block on. */
var IDS_SCORE = 60;

/* ---- identity ----------------------------------------------------------- */

function uuid5(ns, name) {
  var b = Buffer.concat([Buffer.from(ns.replace(/-/g, ''), 'hex'), Buffer.from(name, 'utf8')]);
  var h = crypto.createHash('sha1').update(b).digest();
  h[6] = (h[6] & 0x0f) | 0x50;
  h[8] = (h[8] & 0x3f) | 0x80;
  var x = h.subarray(0, 16).toString('hex');
  return x.slice(0, 8) + '-' + x.slice(8, 12) + '-' + x.slice(12, 16) + '-' + x.slice(16, 20) + '-' + x.slice(20, 32);
}
function eventUuid(slug) { return uuid5(NAMESPACE, 'event:' + slug); }
function attributeUuid(slug, type, value) { return uuid5(NAMESPACE, 'attribute:' + slug + '\n' + type + '\n' + value); }
function md5(s) { return crypto.createHash('md5').update(String(s), 'utf8').digest('hex'); }
function sha256(s) { return crypto.createHash('sha256').update(String(s), 'utf8').digest('hex'); }

function dateStr(v) {
  if (v instanceof Date) return v.toISOString().slice(0, 10);
  return String(v || '');
}
function slugOf(entry) {
  if (entry.report_url) return String(entry.report_url).replace(/^\/reports\//, '').replace(/\/$/, '');
  if (entry.detection_url) return String(entry.detection_url).split('/').pop().replace(/-detections$/, '');
  if (entry.ioc_url) return String(entry.ioc_url).split('/').pop().replace(/-iocs\.json$/, '');
  return null;
}
function tag(name, colour) { return { name: name, colour: colour }; }

/* ---- the STIX bundle ---------------------------------------------------- */

var STIX_PATTERN = /^\[(file:hashes\.'([^']+)'|domain-name:value|url:value|ipv4-addr:value|ipv6-addr:value|email-addr:value)\s*=\s*'((?:[^'\\]|\\.)*)'\]$/;

/* Indicator objects with a single-comparison STIX pattern become typed
   attributes; a pattern this does not recognise is kept whole as a
   stix2-pattern attribute rather than dropped, and named in `unmapped`. */
function attributesFromStix(bundle, slug) {
  var out = [], unmapped = [], actors = [], attack = {}, cves = [];
  var objects = (bundle && bundle.objects) || [];
  objects.forEach(function (o) {
    if (o.type === 'intrusion-set' && o.name) actors.push(String(o.name));
    if (o.type === 'vulnerability' && /^CVE-\d{4}-\d+$/.test(String(o.name))) cves.push(String(o.name));
    if (o.type === 'attack-pattern') {
      (o.external_references || []).forEach(function (r) {
        if (r.source_name === 'mitre-attack' && r.external_id) attack[r.external_id] = o.name || '';
      });
    }
    if (o.type !== 'indicator' || o.pattern_type !== 'stix') return;
    var m = STIX_PATTERN.exec(String(o.pattern).trim());
    var score = typeof o.x_opencti_score === 'number' ? o.x_opencti_score : (typeof o.confidence === 'number' ? o.confidence : null);
    var comment = String(o.name || '');
    if (o.description && String(o.description).trim() && String(o.description).trim() !== comment) {
      comment += (comment ? '. ' : '') + String(o.description).trim();
    }
    if (score !== null) comment += (comment ? ' ' : '') + '[confidence ' + score + '/100]';
    if (!m) {
      unmapped.push(String(o.pattern).slice(0, 80));
      out.push({ type: 'stix2-pattern', category: 'Payload installation', value: String(o.pattern),
        to_ids: score === null ? true : score >= IDS_SCORE, comment: comment });
      return;
    }
    var value = m[3].replace(/\\(['\\])/g, '$1');
    var type, category;
    if (m[2]) {
      var algo = m[2].toUpperCase();
      type = algo === 'SHA-256' ? 'sha256' : algo === 'SHA-1' ? 'sha1' : algo === 'MD5' ? 'md5' :
        algo === 'SHA-512' ? 'sha512' : algo === 'SSDEEP' ? 'ssdeep' : null;
      if (!type) {
        unmapped.push(String(o.pattern).slice(0, 80));
        out.push({ type: 'stix2-pattern', category: 'Payload installation', value: String(o.pattern),
          to_ids: score === null ? true : score >= IDS_SCORE, comment: comment });
        return;
      }
      category = 'Payload delivery';
    } else if (m[1] === 'domain-name:value') { type = 'domain'; category = 'Network activity'; }
    else if (m[1] === 'url:value') { type = 'url'; category = 'Network activity'; }
    else if (m[1] === 'ipv4-addr:value' || m[1] === 'ipv6-addr:value') { type = 'ip-dst'; category = 'Network activity'; }
    else if (m[1] === 'email-addr:value') { type = 'email-src'; category = 'Payload delivery'; }
    out.push({ type: type, category: category, value: value,
      to_ids: score === null ? true : score >= IDS_SCORE, comment: comment });
  });
  return { attributes: out, unmapped: unmapped, actors: uniq(actors), attack: attack, cves: uniq(cves) };
}

/* ---- the detection page ------------------------------------------------- */

/* rules: parse-detections.js output for the page. A rule with no body of its
   own (a Sigma correlation whose base rules live in an earlier fence) cannot
   be a standalone attribute and is counted, not shipped. */
function attributesFromRules(rules, pageUrl, attackNames) {
  var out = [], skipped = [], attack = {};
  (rules || []).forEach(function (r) {
    if (!r.body) { skipped.push(r.name); return; }
    var type = RULE_TYPES[r.engine];
    if (!type) { skipped.push(r.name); return; }
    (r.attack || []).forEach(function (id) { attack[id] = (attackNames && attackNames[id]) || ''; });
    var parts = ['TIER: ' + r.tier];
    if (r.robustness !== null && r.robustness !== undefined) parts.push('robustness ' + r.robustness);
    if (r.confidence) parts.push('confidence ' + r.confidence);
    if (r.attack && r.attack.length) parts.push('ATT&CK ' + r.attack.join(', '));
    if (r.hash) parts.push('rule hash ' + r.hash);
    parts.push(pageUrl);
    out.push({
      type: type, category: RULE_CATEGORY[type], value: r.body,
      to_ids: r.tier === 'Detection', comment: r.name + ' | ' + parts.join(' | '),
      tags: [tag('hunters-ledger:tier="' + r.tier + '"', TAG_COLOURS.tier)]
    });
  });
  return { attributes: out, skipped: skipped, attack: attack };
}

/* ---- one event ---------------------------------------------------------- */

/* src: { entry (catalog), slug, bundle (parsed STIX or null), rules (parsed
   detection page rules or null), attackNames ({id -> name}) }. Returns the
   event without timestamps; stamp() adds them from the state. */
function buildEvent(src) {
  var e = src.entry, slug = src.slug;
  var notes = { unmapped: [], skipped: [] };
  var attrs = [];
  var links = [];
  if (e.report_url) links.push({ url: SITE + e.report_url, what: 'Report' });
  if (e.detection_url) links.push({ url: SITE + String(e.detection_url).replace(/\/?$/, '/'), what: 'Detection rules' });
  if (e.stix_url) links.push({ url: SITE + e.stix_url, what: 'STIX 2.1 bundle' });
  if (e.ioc_url) links.push({ url: SITE + e.ioc_url, what: 'IOC feed (JSON)' });
  links.forEach(function (l) {
    attrs.push({ type: 'link', category: 'External analysis', value: l.url, to_ids: false, comment: l.what + ', The Hunters Ledger' });
  });

  var attack = {}, actors = [];
  if (src.bundle) {
    var s = attributesFromStix(src.bundle, slug);
    attrs = attrs.concat(s.attributes);
    notes.unmapped = s.unmapped;
    actors = s.actors;
    Object.keys(s.attack).forEach(function (id) { attack[id] = s.attack[id] || (src.attackNames && src.attackNames[id]) || ''; });
    s.cves.forEach(function (cve) {
      attrs.push({ type: 'vulnerability', category: 'External analysis', value: cve, to_ids: false, comment: 'Named in the report' });
    });
  }
  if (src.rules) {
    var pageUrl = SITE + String(e.detection_url || '').replace(/\/?$/, '/');
    var r = attributesFromRules(src.rules, pageUrl, src.attackNames);
    attrs = attrs.concat(r.attributes);
    notes.skipped = r.skipped;
    Object.keys(r.attack).forEach(function (id) { if (!attack[id]) attack[id] = r.attack[id]; });
  }

  // Dedupe on (type, value): the same hash can be an indicator twice in a bundle.
  var seen = {};
  attrs = attrs.filter(function (a) {
    var k = a.type + '\n' + a.value;
    if (seen[k]) return false;
    seen[k] = true;
    return true;
  });
  attrs.sort(function (a, b) {
    var oa = order(a.type), ob = order(b.type);
    if (oa !== ob) return oa - ob;
    return a.value < b.value ? -1 : a.value > b.value ? 1 : 0;
  });
  attrs.forEach(function (a) { a.uuid = attributeUuid(slug, a.type, a.value); });

  var tags = [tag('tlp:clear', TAG_COLOURS.tlp)];
  (e.tags || []).forEach(function (t) { tags.push(tag('hunters-ledger:topic="' + String(t) + '"', TAG_COLOURS.topic)); });
  actors.forEach(function (a) { tags.push(tag('hunters-ledger:actor="' + a + '"', TAG_COLOURS.actor)); });
  Object.keys(attack).sort().forEach(function (id) {
    var name = attack[id] || (src.attackNames && src.attackNames[id]);
    if (!name) { notes.unmapped.push('ATT&CK ' + id + ' has no name in the catalog, so no galaxy tag'); return; }
    tags.push(tag('misp-galaxy:mitre-attack-pattern="' + name + ' - ' + id + '"', TAG_COLOURS.galaxy));
  });

  var sev = String(e.severity || '').toLowerCase();
  return {
    uuid: eventUuid(slug),
    slug: slug,
    info: String(e.title),
    date: dateStr(e.date),
    threat_level_id: THREAT_LEVEL[sev] || 4,
    analysis: 2,
    tags: tags,
    attributes: attrs,
    notes: notes
  };
}

var ORDER = { link: 0, vulnerability: 1, sha256: 2, sha1: 3, md5: 4, sha512: 5, ssdeep: 6, domain: 7, url: 8, 'ip-dst': 9,
  'email-src': 10, 'stix2-pattern': 11, snort: 12, sigma: 13, yara: 14 };
function order(type) { return type in ORDER ? ORDER[type] : 20; }

/* Everything a subscriber sees, timestamps excluded, in a fixed key order. */
function contentHash(ev) {
  var canon = {
    uuid: ev.uuid, info: ev.info, date: ev.date, threat_level_id: ev.threat_level_id, analysis: ev.analysis,
    tags: ev.tags.map(function (t) { return t.name; }),
    attributes: ev.attributes.map(function (a) {
      return [a.uuid, a.type, a.category, a.value, a.to_ids, a.comment, (a.tags || []).map(function (t) { return t.name; })];
    })
  };
  return sha256(JSON.stringify(canon));
}

/* ---- the whole feed ------------------------------------------------------ */

/* events: buildEvent() results; state: the parsed _state.json or null; now:
   unix seconds for anything that changed. Returns the stamped events, the new
   state, which events changed, and which state entries are now withdrawn. */
function stamp(events, state, now) {
  var prev = (state && state.events) || {};
  var withdrawnPrev = (state && state.withdrawn) || {};
  var nextEvents = {}, changed = [], unchanged = [], added = [];
  events.forEach(function (ev) {
    var h = contentHash(ev);
    var p = prev[ev.uuid];
    if (p && p.hash === h) {
      ev.timestamp = p.timestamp;
      unchanged.push(ev.slug);
    } else {
      ev.timestamp = now;
      (p ? changed : added).push(ev.slug);
    }
    nextEvents[ev.uuid] = { slug: ev.slug, hash: h, timestamp: ev.timestamp, first_published: (p && p.first_published) || dateOf(now) };
  });
  var withdrawn = {};
  Object.keys(withdrawnPrev).forEach(function (u) { withdrawn[u] = withdrawnPrev[u]; });
  var newlyWithdrawn = [];
  Object.keys(prev).forEach(function (u) {
    if (nextEvents[u]) return;
    withdrawn[u] = { slug: prev[u].slug, withdrawn: dateOf(now), last_timestamp: prev[u].timestamp };
    newlyWithdrawn.push(prev[u].slug);
  });
  return {
    events: events,
    state: { namespace: NAMESPACE, orgc: ORGC, events: nextEvents, withdrawn: withdrawn },
    changed: changed, added: added, unchanged: unchanged, newlyWithdrawn: newlyWithdrawn,
    withdrawn: Object.keys(withdrawn).map(function (u) { return Object.assign({ uuid: u }, withdrawn[u]); })
  };
}

function dateOf(unix) { return new Date(unix * 1000).toISOString().slice(0, 10); }

function manifest(events) {
  var out = {};
  events.slice().sort(byDateDesc).forEach(function (ev) {
    out[ev.uuid] = {
      Orgc: ORGC,
      Tag: ev.tags,
      info: ev.info,
      date: ev.date,
      analysis: ev.analysis,
      threat_level_id: ev.threat_level_id,
      timestamp: ev.timestamp
    };
  });
  return out;
}

function eventJson(ev) {
  return {
    Event: {
      uuid: ev.uuid,
      info: ev.info,
      date: ev.date,
      threat_level_id: ev.threat_level_id,
      analysis: ev.analysis,
      timestamp: ev.timestamp,
      publish_timestamp: ev.timestamp,
      published: true,
      Orgc: ORGC,
      Tag: ev.tags,
      Attribute: ev.attributes.map(function (a) {
        var o = {
          uuid: a.uuid, type: a.type, category: a.category, value: a.value, to_ids: a.to_ids,
          comment: a.comment, timestamp: ev.timestamp
        };
        if (a.tags && a.tags.length) o.Tag = a.tags;
        return o;
      }),
      Object: []
    }
  };
}

/* hashes.csv: md5 of every attribute value, one line per value, so a MISP
   instance can correlate against the feed without pulling every event.
   Composite values split on `|`, as PyMISP does; none are produced here. */
function hashesCsv(events) {
  var lines = [];
  events.forEach(function (ev) {
    ev.attributes.forEach(function (a) {
      var parts = a.type.indexOf('|') > -1 ? a.value.split('|') : [a.value];
      parts.forEach(function (v) { lines.push(md5(v) + ',' + ev.uuid); });
    });
  });
  lines.sort();
  return lines.join('\n') + (lines.length ? '\n' : '');
}

function byDateDesc(a, b) {
  if (a.date !== b.date) return a.date < b.date ? 1 : -1;
  return a.slug < b.slug ? -1 : 1;
}
function uniq(list) {
  var seen = {}, out = [];
  list.forEach(function (x) { if (!seen[x]) { seen[x] = true; out.push(x); } });
  return out;
}

/* A withdrawn event is itemised when the changelog names its slug. */
function changelogCovers(changelogText, slug) {
  return String(changelogText || '').indexOf(slug) > -1;
}

module.exports = {
  ROOT: ROOT, FEED_DIR: FEED_DIR, STATE_FILE: STATE_FILE, MANIFEST_FILE: MANIFEST_FILE,
  HASHES_FILE: HASHES_FILE, CHANGELOG_FILE: CHANGELOG_FILE, STIX_DIR: STIX_DIR,
  SITE: SITE, NAMESPACE: NAMESPACE, ORGC: ORGC, IDS_SCORE: IDS_SCORE,
  uuid5: uuid5, eventUuid: eventUuid, attributeUuid: attributeUuid, md5: md5, slugOf: slugOf,
  attributesFromStix: attributesFromStix, attributesFromRules: attributesFromRules,
  buildEvent: buildEvent, contentHash: contentHash, stamp: stamp,
  manifest: manifest, eventJson: eventJson, hashesCsv: hashesCsv, changelogCovers: changelogCovers
};
