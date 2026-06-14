---
title: The Hunter's Ledger
layout: page
permalink: /
position: 1
---

{% assign n_reports = site.data.catalog.entries | where_exp: "e", "e.report_url" | size %}
{% assign n_det = site.data.metrics.detection_rules %}
{% assign n_ioc = site.data.metrics.iocs %}
<div class="hl-home-hero">
  <h1 class="hl-home-hero__title">Original Threat Intelligence Research</h1>
  <p class="hl-home-hero__lede">Hands-on malware analysis turned into structured, evidence-based intelligence — technically deep enough to trust, clear enough to act on. Free and open: published by a solo analyst for the defender community, with no paywall or signup.</p>
  <div class="hl-creds-strip">
    <span class="hl-cred-pill"><span class="hl-cred-pill__dot" style="background:#58a6ff;"></span><strong>{{ n_reports }}</strong>&nbsp;Reports</span>
    <span class="hl-cred-pill"><span class="hl-cred-pill__dot" style="background:#4ade80;"></span><strong>{{ n_det }}</strong>&nbsp;Detection Rules</span>
    <span class="hl-cred-pill"><span class="hl-cred-pill__dot" style="background:#f87171;"></span><strong>{{ n_ioc }}</strong>&nbsp;IOCs</span>
  </div>
</div>

{% include section-header.html label="Latest Reports" accent="#ff4444" %}

<div class="hl-grid">
{%- assign latest = site.data.catalog.entries | where_exp: "e", "e.report_url" | sort: "date" | reverse -%}
{%- assign emitted_series = "" -%}
{%- assign shown = 0 -%}
{%- for e in latest -%}
{%- if shown >= 4 -%}{%- break -%}{%- endif -%}
{%- if e.series -%}
{%- assign skey = e.series | append: ";" -%}
{%- unless emitted_series contains skey -%}
{%- assign emitted_series = emitted_series | append: skey -%}
{%- assign series_members = latest | where: "series", e.series -%}
{%- assign series_parent = series_members | where: "series_order", 0 | first -%}
{%- unless series_parent -%}{%- assign series_parent = series_members | last -%}{%- endunless -%}
{%- assign stitle = "" -%}
{%- for s in series_members -%}{%- if s.series_title -%}{%- assign stitle = s.series_title -%}{%- endif -%}{%- endfor -%}
{%- if stitle == "" -%}{%- assign stitle = series_parent.title -%}{%- endif -%}
{%- capture slabel -%}Series &middot; {{ series_members.size }} reports{%- endcapture -%}
{%- include catalog-card.html url=series_parent.report_url title=stitle date=e.date severity=series_parent.severity tags=series_parent.tags part_label=slabel -%}
{%- assign shown = shown | plus: 1 -%}
{%- endunless -%}
{%- else -%}
{%- include catalog-card.html url=e.report_url title=e.title date=e.date severity=e.severity tags=e.tags -%}
{%- assign shown = shown | plus: 1 -%}
{%- endif -%}
{%- endfor -%}
</div>

<a href="{{ '/reports/' | relative_url }}" class="hl-view-all">View all reports →</a>

{% include section-header.html label="Mission" accent="#58a6ff" %}

<div class="hl-mission">
  <p>Most threat intelligence fails defenders in one of two ways. It is either too shallow to be actionable — headlines dressed up as analysis — or technically rigorous but locked behind paywalls, stripped of indicators, and written for researchers rather than the people responding at 2am.</p>
  <p>The Hunter's Ledger exists to fill that gap. Every report here is built from original research: real samples, real infrastructure, real detections. The goal is intelligence that a defender can open, read, and act on the same day — with IOCs ready to ingest, detection rules ready to deploy, and analysis deep enough to actually understand what a threat does and how to stop it.</p>
  <p class="hl-mission__close">All of it is free. Defenders should not have to pay to defend.</p>
  <div class="hl-mission__note">Not a collection of open-source intel reports, IOCs, or TTPs — findings are from original research, though they may overlap with known threats.</div>
</div>

{% include section-header.html label="Explore" accent="#4ade80" %}

<div class="hl-nav-grid">
  <a href="{{ '/reports/' | relative_url }}" class="hl-nav-tile" style="--acc: #a371f7;">
    <div class="hl-nav-tile__title">Reports</div>
    <div class="hl-nav-tile__desc">In-depth malware analysis & reverse engineering</div>
  </a>
  <a href="{{ '/hunting-detections/' | relative_url }}" class="hl-nav-tile" style="--acc: #4ade80;">
    <div class="hl-nav-tile__title">Hunting Detections</div>
    <div class="hl-nav-tile__desc">Sigma, YARA, and Suricata rules</div>
  </a>
  <a href="{{ '/ioc-feeds/' | relative_url }}" class="hl-nav-tile" style="--acc: #f87171;">
    <div class="hl-nav-tile__title">IOC Feeds</div>
    <div class="hl-nav-tile__desc">Indicators ready for your SIEM or EDR</div>
  </a>
  <a href="{{ '/stix/' | relative_url }}" class="hl-nav-tile" style="--acc: #22d3ee;">
    <div class="hl-nav-tile__title">STIX Bundles</div>
    <div class="hl-nav-tile__desc">STIX 2.1 bundles for OpenCTI &amp; MISP</div>
  </a>
</div>

{% assign active_site_sponsors = site.data.sponsors.sponsors | where: "tier", "monthly" | where: "active", true %}
{% if active_site_sponsors.size > 0 %}
{% include section-header.html label="Current Sponsors" accent="#58a6ff" %}
{% include site-sponsors.html %}
{% endif %}

{% include section-header.html label="About & Connect" accent="#f97316" %}

<div class="hl-tile-row4">
  <a href="{{ '/about-me/' | relative_url }}" class="hl-nav-tile" style="--acc: #60a5fa;"><div class="hl-nav-tile__title">About Me</div><div class="hl-nav-tile__desc">Background &amp; how to reach me</div></a>
  <a href="{{ '/behind-the-reports/' | relative_url }}" class="hl-nav-tile" style="--acc: #f97316;"><div class="hl-nav-tile__title">Behind the Reports</div><div class="hl-nav-tile__desc">How the intelligence is produced</div></a>
  <a href="{{ '/consulting/' | relative_url }}" class="hl-nav-tile" style="--acc: #b8902f;"><div class="hl-nav-tile__title">Consulting</div><div class="hl-nav-tile__desc">Malware analysis, IR &amp; detection services</div></a>
  <a href="{{ '/support/' | relative_url }}" class="hl-nav-tile" style="--acc: #f472b6;"><div class="hl-nav-tile__title">Support</div><div class="hl-nav-tile__desc">Help keep the research free</div></a>
</div>
<div class="hl-contribute">Have original research, detections, or IOCs to share? Reach out at <a href="mailto:intel@the-hunters-ledger.com">intel@the-hunters-ledger.com</a> — findings can be posted on your behalf as a co-author or attributed however you prefer.</div>

{% include section-header.html label="Resources" accent="#888888" %}

<div class="hl-resources">
  <a href="https://attack.mitre.org/">MITRE ATT&CK</a> &nbsp;·&nbsp;
  <a href="https://github.com/SigmaHQ/sigma">Sigma Rules</a> &nbsp;·&nbsp;
  <a href="https://virustotal.github.io/yara/">YARA</a>
</div>
