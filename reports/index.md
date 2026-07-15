---
title: Reports
layout: page
permalink: /reports/
thumbnail: /assets/images/cards/reports.png
position: 2
---

<div class="hl-page-header" style="--ph-accent: #a371f7;">
  <div class="hl-page-header__label">Reports</div>
  <div class="hl-page-header__title">Threat Intelligence Reports</div>
  <div class="hl-page-header__desc">Original malware analysis and reverse engineering — each report ships with detection rules and machine-readable indicators.</div>
</div>

{% assign report_entries = site.data.catalog.entries | where_exp: "e", "e.report_url" | sort: "date" | reverse %}

<div class="hl-grid">
{%- assign emitted_series = "" -%}
{%- for e in report_entries -%}
{%- if e.series -%}
{%- assign skey = e.series | append: ";" -%}
{%- unless emitted_series contains skey -%}
{%- assign emitted_series = emitted_series | append: skey -%}
{%- assign series_members = report_entries | where: "series", e.series -%}
{%- include series-cluster.html members=series_members slug=e.series -%}
{%- endunless -%}
{%- else -%}
{%- include catalog-card.html url=e.report_url title=e.title date=e.date severity=e.severity tags=e.tags -%}
{%- endif -%}
{%- endfor -%}
</div>

*Reports are © Joseph. All rights reserved — free to read, but reuse requires written permission.*
