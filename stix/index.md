---
title: STIX Bundles
layout: page
hl_idx: list
permalink: /stix/
position: 4.5
description: "Per-campaign STIX 2.1 bundles, ready to import into OpenCTI, MISP, or any STIX-aware platform. Licensed CC BY 4.0."
thumbnail: /assets/images/cards/stix.png
---

{% capture _desc %}Per-campaign STIX 2.1 bundles, ready to import into OpenCTI, MISP, or any STIX-aware platform. Licensed under <strong>CC BY 4.0</strong>.{% endcapture %}
{% include index-header.html accent="#22d3ee" label="STIX Bundles" title="STIX 2.1 Threat Intelligence" desc=_desc %}

{% assign stix_entries = site.data.catalog.entries | where_exp: "e", "e.stix_url" | sort: "date" | reverse %}

{% include listing-tags.html entries=stix_entries tag_field="stix_tags" %}
{% include index-kpis.html entries=stix_entries label="STIX bundles" noun="bundles" accent="#22d3ee" topics=hl_chip_n %}

<details class="hl-feed">
  <summary class="hl-feed__toggle">
    <span aria-hidden="true">📡</span>
    <span>Subscribe as a MISP feed</span>
    <span class="hl-feed__chev" aria-hidden="true">▾</span>
  </summary>
  <div class="hl-feed__body">
    <p class="hl-feed__desc">Every published campaign as one MISP event, carrying its indicators, its Suricata, YARA and Sigma rules, its CVEs and ATT&amp;CK galaxy tags. Static files in the MISP feed format: MISP pulls it natively. For OpenCTI, import the STIX bundles on this page instead; the MISP feed is not an OpenCTI ingest path. Free under <strong>CC BY 4.0</strong>.</p>
    <div class="hl-feed__cmd">
      <code id="hl-misp-cmd">https://the-hunters-ledger.com/feeds/misp/</code>
      <button type="button" class="hl-feed__copy" onclick="navigator.clipboard.writeText(document.getElementById('hl-misp-cmd').textContent);var b=this;b.textContent='Copied';setTimeout(function(){b.textContent='Copy';},1500);">Copy</button>
    </div>
    <p class="hl-feed__note">In MISP: Sync Actions, List Feeds, Add Feed, source format <strong>MISP feed</strong>, that URL. OpenCTI imports the bundles here, not the feed.</p>
    <div class="hl-feed__links">
      <a href="/feeds/misp/">How to subscribe and what an event carries →</a>
      <a href="/feeds/misp/manifest.json">manifest.json →</a>
      <a href="/feeds/misp/changelog/">Changelog &amp; withdrawn events →</a>
      <span class="hl-feed__meta">Auto-updates as campaigns publish</span>
    </div>
  </div>
</details>

<p class="hl-d-dlrow"><a class="hl-download-all" href="/stix/hunters-ledger-stix-bundles.zip" download>⬇ Download all campaigns (.zip)</a> <span class="hl-xref__muted">Polling instead? <a href="/stix/manifest.json">manifest.json</a> lists every bundle with its SHA-256, size and modified time, so a platform can fetch only what changed.</span></p>

<p class="hl-xref__muted">This page is a public mirror. The copy OpenCTI imports is a private repository, and a bundle can exist there that has no page here, so the two counts can differ.</p>

{% include listing-filter.html entries=stix_entries tag_field="stix_tags" placeholder="Search STIX bundles by name…" accent="#22d3ee" %}

<div class="hl-grid" data-filter-grid data-pagefind-ignore>
{% for e in stix_entries %}
  {% if e.stix_title %}{% assign stitle = e.stix_title %}{% else %}{% assign stitle = e.title | append: " — STIX Bundle" %}{% endif %}
  {% assign stags = e.stix_tags | default: e.tags %}
  {% include catalog-card.html url=e.stix_url title=stitle date=e.date severity=e.severity tags=stags %}
{% endfor %}
</div>
