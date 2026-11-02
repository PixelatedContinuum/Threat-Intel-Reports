---
title: Reports
description: "Original malware analysis and reverse engineering reports, each shipped with detection rules and machine-readable indicators."
layout: page
hl_idx: list
permalink: /reports/
thumbnail: /assets/images/cards/reports.png
position: 2
---

{% capture _desc %}Original malware analysis and reverse engineering. Each report ships with detection rules and machine-readable indicators. Filter by tag or search by name. Reports that were revised after publication are tracked on <a href="/changes/">Changes</a>.{% endcapture %}
{% include index-header.html accent="#a371f7" label="Reports" title="Threat Intelligence Reports" desc=_desc %}

{% assign report_entries = site.data.catalog.entries | where_exp: "e", "e.report_url" | sort: "date" | reverse %}

{% include listing-tags.html entries=report_entries %}
{% include index-kpis.html entries=report_entries label="Reports" noun="reports" accent="#a371f7" topics=hl_chip_n %}

{% include listing-filter.html entries=report_entries placeholder="Search reports by name…" accent="#a371f7" %}

<div class="hl-grid" data-filter-grid data-pagefind-ignore>
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

*Reports are © Joseph, The Hunter's Ledger, licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/): free to read, republish and adapt, including commercially, with attribution.*
