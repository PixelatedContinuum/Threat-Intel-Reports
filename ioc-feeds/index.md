---
title: IOC Feeds
layout: page
permalink: /ioc-feeds/
thumbnail: /assets/images/cards/ioc-feeds.png
position: 4
redirect_from:
  - /lookup/
---

<div class="hl-page-header" style="--ph-accent: #f87171;">
  <div class="hl-page-header__label">IOC Feeds</div>
  <div class="hl-page-header__title">Indicators of Compromise</div>
  <div class="hl-page-header__desc">Structured feeds ready for ingestion into your SIEM, EDR, or CTI platform. Licensed under <strong>CC BY 4.0</strong>. Already holding an indicator? Search it below to find the feed it belongs to.</div>
</div>

<div class="hl-iocsearch">
  <textarea class="hl-iocsearch__in" rows="2" spellcheck="false" autocomplete="off"
    placeholder="Paste one indicator, or a whole list. IPs, domains, URLs and hashes, separated by commas, spaces or newlines."
    aria-label="Search for indicators across every published feed"></textarea>
  <button type="button" class="hl-iocsearch__clear" hidden>Clear</button>
  <div class="hl-iocsearch__result" role="status" aria-live="polite"></div>
  <div class="hl-iocsearch__detail"></div>
</div>

{% assign ioc_entries = site.data.catalog.entries | where_exp: "e", "e.ioc_url" | sort: "date" | reverse %}

{% include listing-filter.html entries=ioc_entries tag_field="ioc_tags" placeholder="Search IOC feeds by name…" %}

<div class="hl-grid" data-filter-grid>
{% for e in ioc_entries %}
  {% if e.ioc_title %}{% assign ititle = e.ioc_title %}{% else %}{% assign ititle = e.title | append: " — IOC Feed" %}{% endif %}
  {% assign itags = e.ioc_tags | default: e.tags %}
  {% assign islug = e.ioc_url | split: '/' | last | remove: '-iocs.json' %}
  {% include catalog-card.html url=e.ioc_url title=ititle date=e.date severity=e.severity tags=itags slug=islug %}
{% endfor %}
</div>

<script defer src="{{ '/assets/js/ioc-classify.js' | relative_url }}?v=1"></script>
<script defer src="{{ '/assets/js/ioc-search.js' | relative_url }}?v=1"></script>
