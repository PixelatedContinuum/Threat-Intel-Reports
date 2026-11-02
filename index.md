---
title: The Hunter's Ledger
description: "Original threat intelligence research: malware analysis, detection rules and indicator feeds published free by a solo analyst."
layout: page
permalink: /
position: 1
hl_idx: home
---

{% assign n_reports = site.data.catalog.entries | where_exp: "e", "e.report_url" | size %}
{% assign n_det = site.data.metrics.detection_rules %}
{% assign n_ioc = site.data.metrics.iocs %}
{% assign n_stix = site.static_files | where_exp: "f", "f.path contains '/stix/'" | where: "extname", ".json" | size %}
{% assign n_families = site.data.family_index.families | size %}
{% assign n_actors = site.data.actors.actors | size %}
{%- capture det_techniques -%}{%- for d in site.data.detection_attack -%}{%- for r in d[1].rows -%}{{ r.id | split: "." | first }} {% endfor -%}{%- endfor -%}{%- endcapture -%}
{% assign n_techniques = det_techniques | split: " " | uniq | size %}
<article class="hl-home-hero hl-d-plate" style="--ph-accent: #58a6ff;">
  <div class="hl-d-kicker">The Hunter&#8217;s Ledger</div>
  <h1 class="hl-home-hero__title">Original Threat Intelligence Research</h1>
  <p class="hl-home-hero__lede">Hands-on malware analysis turned into structured, evidence-based intelligence, technically deep enough to trust and clear enough to act on. Free and open: published by a solo analyst for the defender community, with no paywall or signup.</p>
</article>
<div class="hl-d-kpis hl-d-kpis--home" style="--fc: 4;">
  <div class="hl-d-kpi" style="--kc:#58a6ff;"><span class="hl-d-kpi__n">{{ n_reports }}</span><span class="hl-d-kpi__cap">Reports</span></div>
  <div class="hl-d-kpi" style="--kc:#4ade80;"><span class="hl-d-kpi__n">{{ n_det }}</span><span class="hl-d-kpi__cap">Detection Rules</span></div>
  <div class="hl-d-kpi" style="--kc:#2dd4bf;"><span class="hl-d-kpi__n">{{ n_techniques }}</span><span class="hl-d-kpi__cap">ATT&amp;CK Techniques Covered</span></div>
  <div class="hl-d-kpi" style="--kc:#f87171;"><span class="hl-d-kpi__n">{{ n_ioc }}</span><span class="hl-d-kpi__cap">IOCs</span></div>
  <div class="hl-d-kpi" style="--kc:#a78bfa;"><span class="hl-d-kpi__n">{{ n_stix }}</span><span class="hl-d-kpi__cap">STIX Bundles</span></div>
  <div class="hl-d-kpi" style="--kc:#f472b6;"><span class="hl-d-kpi__n">{{ n_families }}</span><span class="hl-d-kpi__cap">Malware &amp; Tools Profiled</span></div>
  <div class="hl-d-kpi" style="--kc:#fb923c;"><span class="hl-d-kpi__n">{{ n_actors }}</span><span class="hl-d-kpi__cap">Threat Actors Tracked</span></div>
  {%- if site.data.impact.actions_reported %}
  <a class="hl-d-kpi hl-d-kpi--link" style="--kc:#fbbf24;" href="{{ '/impact/' | relative_url }}"><span class="hl-d-kpi__n">{{ site.data.impact.actions_reported }}</span><span class="hl-d-kpi__cap">Takedowns &amp; Victim Actions</span></a>
  {%- endif %}
</div>
{%- if site.data.impact.actions_reported %}
<p class="hl-creds-note">Takedowns &amp; Victim Actions counts only what was reported back to me; most of my reports get no reply.</p>
{%- endif %}

{% include d-eyebrow.html label="Latest Reports" accent="#ef4444" icon="report" sub="newest first" %}

<div class="hl-grid hl-grid--c4">
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

{% include d-eyebrow.html label="Mission" accent="#58a6ff" icon="flag" %}

<div class="hl-mission hl-d-box" style="--pa: #58a6ff;">
  <p>Most threat intelligence fails defenders in one of two ways. It is either too shallow to be actionable (headlines dressed up as analysis), or technically rigorous but locked behind paywalls, stripped of indicators, and written for researchers rather than the people responding at 2am.</p>
  <p>The Hunter's Ledger exists to fill that gap. Every report here is built from original research: real samples, real infrastructure, real detections. The goal is intelligence that a defender can open, read, and act on the same day, with IOCs ready to ingest, detection rules ready to deploy, and analysis deep enough to actually understand what a threat does and how to stop it.</p>
  <p class="hl-mission__close">All of it is free. Defenders should not have to pay to defend.</p>
  <div class="hl-mission__note">Not a collection of open-source intel reports, IOCs, or TTPs. Findings are from original research, though they may overlap with known threats.</div>
</div>

{% include d-eyebrow.html label="Explore" accent="#4ade80" icon="layers" %}

<div class="hl-nav-grid hl-nav-grid--t4">
  <a href="{{ '/reports/' | relative_url }}" class="hl-nav-tile" style="--acc: #a371f7;">
    <span class="hl-nav-tile__ico">{% include d-icon.html name="report" %}</span>
    <div class="hl-nav-tile__title">Reports</div>
    <div class="hl-nav-tile__desc">In-depth malware analysis & reverse engineering</div>
  </a>
  <a href="{{ '/hunting-detections/' | relative_url }}" class="hl-nav-tile" style="--acc: #4ade80;">
    <span class="hl-nav-tile__ico">{% include d-icon.html name="shield" %}</span>
    <div class="hl-nav-tile__title">Detection Library</div>
    <div class="hl-nav-tile__desc">Sigma, YARA, and Suricata rules</div>
  </a>
  <a href="{{ '/ioc-feeds/' | relative_url }}" class="hl-nav-tile" style="--acc: #f87171;">
    <span class="hl-nav-tile__ico">{% include d-icon.html name="target" %}</span>
    <div class="hl-nav-tile__title">IOC Feeds</div>
    <div class="hl-nav-tile__desc">Indicators ready for your SIEM or EDR</div>
  </a>
  <a href="{{ '/stix/' | relative_url }}" class="hl-nav-tile" style="--acc: #22d3ee;">
    <span class="hl-nav-tile__ico">{% include d-icon.html name="share" %}</span>
    <div class="hl-nav-tile__title">STIX Bundles</div>
    <div class="hl-nav-tile__desc">STIX 2.1 bundles for OpenCTI &amp; MISP</div>
  </a>
</div>

{% include d-eyebrow.html label="Browse the Corpus" accent="#a371f7" icon="grid" %}

<div class="hl-nav-grid hl-nav-grid--t4">
  <a href="{{ '/actors/' | relative_url }}" class="hl-nav-tile" style="--acc: #e879f9;"><span class="hl-nav-tile__ico">{% include d-icon.html name="user" %}</span><div class="hl-nav-tile__title">Threat Actors</div><div class="hl-nav-tile__desc">Tracked actors and the evidence behind each</div></a>
  <a href="{{ '/families/' | relative_url }}" class="hl-nav-tile" style="--acc: #facc15;"><span class="hl-nav-tile__ico">{% include d-icon.html name="family" %}</span><div class="hl-nav-tile__title">Malware Families</div><div class="hl-nav-tile__desc">Each family with its reports, rules and feeds</div></a>
  <a href="{{ '/techniques/' | relative_url }}" class="hl-nav-tile" style="--acc: #fb923c;"><span class="hl-nav-tile__ico">{% include d-icon.html name="grid" %}</span><div class="hl-nav-tile__title">ATT&amp;CK Techniques</div><div class="hl-nav-tile__desc">Coverage heatmap and a Navigator layer</div></a>
  <a href="{{ '/impact/' | relative_url }}" class="hl-nav-tile" style="--acc: #fbbf24;"><span class="hl-nav-tile__ico">{% include d-icon.html name="heart" %}</span><div class="hl-nav-tile__title">Takedowns &amp; Victim Actions</div><div class="hl-nav-tile__desc">What hosts, CERTs and victims did after my reports</div></a>
</div>

{% include d-eyebrow.html label="Stay Current" accent="#22d3ee" icon="pulse" %}

<div class="hl-nav-grid hl-nav-grid--t2">
  <a href="{{ '/wire/' | relative_url }}" class="hl-nav-tile" style="--acc: #38bdf8;"><span class="hl-nav-tile__ico">{% include d-icon.html name="pulse" %}</span><div class="hl-nav-tile__title">The Wire</div><div class="hl-nav-tile__desc">Headlines from public threat research, every 15 minutes</div></a>
  <a href="{{ '/changes/' | relative_url }}" class="hl-nav-tile" style="--acc: #34d399;"><span class="hl-nav-tile__ico">{% include d-icon.html name="history" %}</span><div class="hl-nav-tile__title">Changes</div><div class="hl-nav-tile__desc">Revisions to published reports, newest first</div></a>
</div>

{% include d-eyebrow.html label="About & Connect" accent="#f97316" icon="user" %}

<div class="hl-nav-grid hl-nav-grid--t4">
  <a href="{{ '/about-me/' | relative_url }}" class="hl-nav-tile" style="--acc: #60a5fa;"><span class="hl-nav-tile__ico">{% include d-icon.html name="user" %}</span><div class="hl-nav-tile__title">About Me</div><div class="hl-nav-tile__desc">Background &amp; how to reach me</div></a>
  <a href="{{ '/behind-the-reports/' | relative_url }}" class="hl-nav-tile" style="--acc: #f97316;"><span class="hl-nav-tile__ico">{% include d-icon.html name="book" %}</span><div class="hl-nav-tile__title">Behind the Reports</div><div class="hl-nav-tile__desc">How the intelligence is produced</div></a>
  <a href="{{ '/consulting/' | relative_url }}" class="hl-nav-tile" style="--acc: #9fb4c9;"><span class="hl-nav-tile__ico">{% include d-icon.html name="briefcase" %}</span><div class="hl-nav-tile__title">Consulting</div><div class="hl-nav-tile__desc">Malware analysis, IR &amp; detection services</div></a>
  <a href="{{ '/support/' | relative_url }}" class="hl-nav-tile" style="--acc: #f472b6;"><span class="hl-nav-tile__ico">{% include d-icon.html name="heart" %}</span><div class="hl-nav-tile__title">Support</div><div class="hl-nav-tile__desc">Help keep the research free</div></a>
</div>
<div class="hl-contribute hl-d-box" style="--pa: #f97316;">Have original research, detections, or IOCs to share? Reach out at <a href="mailto:intel@the-hunters-ledger.com">intel@the-hunters-ledger.com</a>. Findings can be posted on your behalf as a co-author, or attributed however you prefer.</div>
