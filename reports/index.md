---
title: Reports
layout: page
permalink: /reports/
position: 2
---

<div class="hl-page-header" style="border-left-color: #58a6ff;">
  <div class="hl-page-header__label" style="color: #58a6ff;">Reports</div>
  <div class="hl-page-header__title">Threat Intelligence Reports</div>
  <div class="hl-page-header__desc">Original malware analysis and reverse engineering — each report ships with detection rules and machine-readable indicators. Filter by tag or search by name.</div>
</div>

{% assign report_entries = site.data.catalog.entries | where_exp: "e", "e.report_url" | sort: "date" | reverse %}

{% include listing-filter.html entries=report_entries placeholder="Search reports by name…" %}

<div class="hl-grid" data-filter-grid>
{% for e in report_entries %}{% include catalog-card.html url=e.report_url title=e.title date=e.date severity=e.severity tags=e.tags %}{% endfor %}
</div>

*Reports are © Joseph. All rights reserved — free to read, but reuse requires written permission.*
