---
title: IOC Feeds
layout: page
permalink: /ioc-feeds/
thumbnail: /assets/images/cards/ioc-feeds.png
position: 4
---

<div class="hl-page-header" style="--ph-accent: #f87171;">
  <div class="hl-page-header__label">IOC Feeds</div>
  <div class="hl-page-header__title">Indicators of Compromise</div>
  <div class="hl-page-header__desc">Structured feeds ready for ingestion into your SIEM, EDR, or CTI platform. Licensed under <strong>CC BY-NC 4.0</strong>.</div>
</div>

{% assign ioc_entries = site.data.catalog.entries | where_exp: "e", "e.ioc_url" | sort: "date" | reverse %}

{% include listing-filter.html entries=ioc_entries tag_field="ioc_tags" placeholder="Search IOC feeds by name…" %}

<div class="hl-grid" data-filter-grid>
{% for e in ioc_entries %}
  {% if e.ioc_title %}{% assign ititle = e.ioc_title %}{% else %}{% assign ititle = e.title | append: " — IOC Feed" %}{% endif %}
  {% assign itags = e.ioc_tags | default: e.tags %}
  {% include catalog-card.html url=e.ioc_url title=ititle date=e.date severity=e.severity tags=itags %}
{% endfor %}
</div>
