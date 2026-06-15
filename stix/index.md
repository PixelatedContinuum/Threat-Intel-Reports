---
title: STIX Bundles
layout: page
permalink: /stix/
position: 4.5
description: "Per-campaign STIX 2.1 bundles — import into OpenCTI, MISP, or any STIX-aware platform. Licensed CC BY-NC 4.0."
thumbnail: /assets/images/cards/stix.png
---

<div class="hl-page-header" style="--ph-accent: #22d3ee;">
  <div class="hl-page-header__label">STIX Bundles</div>
  <div class="hl-page-header__title">STIX 2.1 Threat Intelligence</div>
  <div class="hl-page-header__desc">Per-campaign STIX 2.1 bundles — import into OpenCTI, MISP, or any STIX-aware platform. Licensed under <strong>CC BY-NC 4.0</strong>.</div>
</div>

<p style="margin:0 0 1.5rem;"><a class="hl-download-all" href="/stix/hunters-ledger-stix-bundles.zip" download>⬇ Download all campaigns (.zip)</a></p>

{% assign stix_entries = site.data.catalog.entries | where_exp: "e", "e.stix_url" | sort: "date" | reverse %}

{% include listing-filter.html entries=stix_entries tag_field="stix_tags" placeholder="Search STIX bundles by name…" %}

<div class="hl-grid" data-filter-grid>
{% for e in stix_entries %}
  {% if e.stix_title %}{% assign stitle = e.stix_title %}{% else %}{% assign stitle = e.title | append: " — STIX Bundle" %}{% endif %}
  {% assign stags = e.stix_tags | default: e.tags %}
  {% include catalog-card.html url=e.stix_url title=stitle date=e.date severity=e.severity tags=stags %}
{% endfor %}
</div>
