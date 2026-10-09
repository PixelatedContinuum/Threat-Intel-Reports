---
title: MISP Feed
layout: page
permalink: /feeds/misp/
description: "Subscribe to The Hunters Ledger as a MISP feed: one event per published campaign carrying the indicators and the Suricata, YARA and Sigma rules, pulled natively by MISP and OpenCTI. Licensed CC BY 4.0."
---

<div class="hl-page-header" style="--ph-accent: #22d3ee;">
  <div class="hl-page-header__label">MISP Feed</div>
  <div class="hl-page-header__title">Subscribe as a MISP feed</div>
  <div class="hl-page-header__desc">Every published campaign as one MISP event: the indicators from its STIX bundle, the Suricata, YARA and Sigma rules from its detection page, the CVEs it names, ATT&amp;CK galaxy tags, and links back to the report. Static files in the MISP feed format, so MISP pulls it on its own schedule and OpenCTI reads it through its MISP feed connector, with no MISP instance in between. Free under <strong>CC BY 4.0</strong>.</div>
</div>

{%- assign m = site.static_files | where: "path", "/feeds/misp/manifest.json" | first -%}

<div class="hl-feed-url">
  <span class="hl-feed-url__label">Feed URL</span>
  <span class="hl-feed-url__val" id="hl-misp-url">https://the-hunters-ledger.com/feeds/misp/</span>
  <button type="button" class="hl-feed-url__copy" onclick="navigator.clipboard.writeText(document.getElementById('hl-misp-url').textContent);var b=this;b.textContent='Copied';setTimeout(function(){b.textContent='Copy';},1500);">Copy</button>
</div>

## Add it to MISP

In MISP open **Sync Actions, List Feeds, Add Feed** and fill in:

| Field | Value |
|---|---|
| Name | The Hunters Ledger |
| Provider | The Hunters Ledger |
| Input source | Network |
| URL | `https://the-hunters-ledger.com/feeds/misp/` |
| Source format | MISP feed |
| Enabled | yes |

Then **Fetch and store all feed data** once, and MISP keeps it current on its own schedule. Every event carries a stable UUID, so a re-pull updates an event in place rather than duplicating it, and an event's `timestamp` only moves when its content changes. The feed also ships `hashes.csv`, so a MISP instance can correlate its own data against this feed without storing the events at all.

## Add it to OpenCTI

Deploy the `connector-misp-feed` external-import connector with `MISP_FEED_URL` set to `https://the-hunters-ledger.com/feeds/misp/`. It reads the same `manifest.json` and event files and needs no MISP instance. If you already run MISP in front of OpenCTI, add the feed to MISP instead and let your existing MISP connector carry it across.

## Anything else

The files are plain JSON: `manifest.json` lists every event with its UUID, title, date, tags and timestamp, and each `<uuid>.json` holds one event with its attributes. Poll the manifest, compare timestamps to what you hold, and fetch the events that moved. The STIX side of the site has the same arrangement at [`/stix/manifest.json`](/stix/manifest.json).

## What an event carries

- **Indicators** from the campaign's STIX bundle, typed as `sha256`, `domain`, `url` or `ip-dst`, each with the report's own confidence in the comment. An indicator the report scores below 60 ships with `to_ids` off: it is context, not a blocklist entry. A value the bundle carries only as an observable (a mining pool, a co-tenant domain, anything the IOC feed marks do-not-block) is not in the event at all.
- **Rules** from the campaign's detection page as `yara`, `sigma` and `snort` attributes, the full rule text, with its tier, robustness, confidence, ATT&amp;CK techniques and rule hash in the comment and a `hunters-ledger:tier` tag. A Detection-tier rule ships with `to_ids` on; a Hunting-tier rule is broad by design and ships with `to_ids` off, so it reaches your hunt queue rather than your alert queue.
- **CVEs** the report names, as `vulnerability` attributes.
- **Links** to the report, the detection page, the STIX bundle and the IOC feed.
- **Tags**: `tlp:clear`, `misp-galaxy:mitre-attack-pattern` for every technique the campaign maps, `hunters-ledger:topic` for the catalog tags, and `hunters-ledger:actor` for a tracked UTA designation.

Everything in an event is already published on this site; the feed adds no claim of its own. Withdrawn events are itemised on the [changelog](/feeds/misp/changelog/), where a UUID is never reused.

<p class="hl-xref__licence">Generated from the published STIX bundles and detection pages by <code>tools/report-tooling/generate-misp-feed.js</code>, validated with PyMISP before every deploy. CC BY 4.0: use it, including commercially, with attribution to The Hunters Ledger.</p>
