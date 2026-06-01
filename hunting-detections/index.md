---
title: Hunting Detections
layout: page
permalink: /hunting-detections/
position: 3
---

<div class="hl-page-header" style="border-left-color: #4ade80;">
  <div class="hl-page-header__label" style="color: #4ade80;">Hunting Detections</div>
  <div class="hl-page-header__title">Sigma, YARA &amp; Suricata Rules</div>
  <div class="hl-page-header__desc">Detection logic from original research, mapped to MITRE ATT&amp;CK. Free to use in your environment under <strong>CC BY-NC 4.0</strong>.</div>
</div>

{% assign det_entries = site.data.catalog.entries | where_exp: "e", "e.detection_url" | sort: "date" | reverse %}

{% include listing-filter.html entries=det_entries tag_field="detection_tags" placeholder="Search detections by name…" %}

<div class="hl-grid" data-filter-grid>
{% for e in det_entries %}
  {% if e.detection_title %}{% assign dtitle = e.detection_title %}{% else %}{% assign dtitle = e.title | prepend: "Detection Rules — " %}{% endif %}
  {% assign dtags = e.detection_tags | default: e.tags %}
  {% include catalog-card.html url=e.detection_url title=dtitle date=e.date severity=e.severity tags=dtags %}
{% endfor %}
</div>
