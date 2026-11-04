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
{%- comment -%} T-0556 w2: concept 3 home. The lead report is the newest catalog entry with a report_url; "Latest research" is the next four (series collapsed to one row, as the old grid did); the tactic chart counts distinct ATT&CK techniques per tactic for the lead report from _data/attack_index.yml at build time. {%- endcomment -%}
{%- assign latest = site.data.catalog.entries | where_exp: "e", "e.report_url" | sort: "date" | reverse -%}
{%- assign lead = latest | first -%}
{%- assign lead_page = site.pages | where: "url", lead.report_url | first -%}
{%- assign lead_words = lead_page.content | strip_html | number_of_words -%}
{%- assign lead_min = lead_words | divided_by: 200.0 | round -%}
{%- if lead_min < 1 -%}{%- assign lead_min = 1 -%}{%- endif -%}
{%- assign lead_misp = site.data.misp_events.events | where: "report_url", lead.report_url | first -%}
{%- assign lead_dkey = lead.detection_url | split: "/" | last -%}
{%- assign lead_rules = site.data.detection_manifests[lead_dkey] | size -%}
{%- assign lead_sev = lead.severity -%}
{%- case lead.severity -%}{%- when "critical" -%}{%- assign lead_sevlabel = "Critical" -%}{%- when "high" -%}{%- assign lead_sevlabel = "High" -%}{%- when "med" -%}{%- assign lead_sevlabel = "Medium" -%}{%- when "low" -%}{%- assign lead_sevlabel = "Low" -%}{%- else -%}{%- assign lead_sevlabel = lead.severity | capitalize -%}{%- endcase -%}
{%- capture _lt -%}{%- for t in site.data.attack_index.techniques -%}{%- if t.reports -%}{%- assign _r = t.reports | where: "url", lead.report_url | first -%}{%- if _r -%}{{ _r.tactic }}|{%- endif -%}{%- endif -%}{%- endfor -%}{%- endcapture -%}
{%- assign lead_tacs = _lt | split: "|" -%}
{%- assign tac_max = 0 -%}
{%- assign tac_used = 0 -%}
{%- for tac in site.data.attack_index.tactics -%}
{%- assign _n = lead_tacs | where_exp: "x", "x == tac.name" | size -%}
{%- if _n > tac_max -%}{%- assign tac_max = _n -%}{%- endif -%}
{%- if _n > 0 -%}{%- assign tac_used = tac_used | plus: 1 -%}{%- endif -%}
{%- endfor -%}
<div class="c3-home">
<section class="c3-about" aria-labelledby="c3-about-h" style="--sec: #58a6ff;">
  <div class="c3-about__head">
    <h2 id="c3-about-h">About the ledger</h2>
    <h3 class="c3-about__kick">Original Threat Intelligence Research</h3>
    <p class="c3-about__lede">Hands-on malware analysis turned into structured, evidence-based intelligence, technically deep enough to trust and clear enough to act on. Free and open: published by a solo analyst for the defender community, with no paywall or signup.</p>
    <div class="hl-mission__note">Not a collection of open-source intel reports, IOCs, or TTPs. Findings are from original research, though they may overlap with known threats.</div>
  </div>
  <div class="hl-mission c3-about__body">
    <h3 class="c3-about__kick">Mission</h3>
    <p>Most threat intelligence fails defenders in one of two ways. It is either too shallow to be actionable (headlines dressed up as analysis), or technically rigorous but locked behind paywalls, stripped of indicators, and written for researchers rather than the people responding at 2am.</p>
    <p>The Hunter's Ledger exists to fill that gap. Every report here is built from original research: real samples, real infrastructure, real detections. The goal is intelligence that a defender can open, read, and act on the same day, with IOCs ready to ingest, detection rules ready to deploy, and analysis deep enough to actually understand what a threat does and how to stop it.</p>
    <p class="hl-mission__close">All of it is free. Defenders should not have to pay to defend.</p>
  </div>
</section>

<section class="c3-lead" aria-labelledby="c3-lead-h">
  <div class="c3-lead__txt">
    <div class="c3-kick"><span class="c3-sev c3-sev--{{ lead_sev }}">{{ lead_sevlabel }}</span>{% if lead_page.category %}<span>{{ lead_page.category }}</span>{% endif %}<span>Latest report</span></div>
    <h2 class="c3-lead__h" id="c3-lead-h"><a href="{{ lead.report_url | relative_url }}">{{ lead.title }}</a></h2>
    <p class="c3-lead__stand">{{ lead_page.description | default: lead.title }}</p>
    {%- if lead.tags %}
    <div class="hl-tags c3-lead__tags">{% for t in lead.tags %}{% include tag-badge.html tag=t %}{% endfor %}</div>
    {%- endif %}
    <div class="c3-byline"><span><b>Joseph Harrison</b></span><span>{{ lead.date | date: "%-d %B %Y" }}</span><span>{{ lead_min }} min in full</span></div>
    <div class="c3-btns">
      <a class="c3-btn c3-btn--pri" href="{{ lead.report_url | relative_url }}">Read the report</a>
      {%- if lead.detection_url %}<a class="c3-btn" href="{{ lead.detection_url | relative_url }}">{% if lead_rules > 0 %}{{ lead_rules }} detection rules{% else %}Detections{% endif %}</a>{% endif -%}
      {%- if lead.ioc_url %}<a class="c3-btn" href="{{ lead.ioc_url | relative_url }}">IOC feed</a>{% endif -%}
      {%- if lead.stix_url %}<a class="c3-btn" href="{{ lead.stix_url | relative_url }}">STIX</a>{% endif -%}
      {%- if lead_misp %}<a class="c3-btn" href="{{ lead_misp.event_url | relative_url }}" target="_blank" rel="noopener noreferrer">MISP</a>{% endif %}
    </div>
  </div>
  <div class="c3-lead__side">
    {% include c3-cover.html label=lead.cover_label severity=lead.severity size="lead" %}
    {%- if lead_tacs.size > 0 %}
    <div class="c3-chart">
      <h3 class="c3-chart__h"><span>{{ lead_tacs.size }} techniques &middot; {{ tac_used }} tactics</span><span>Distinct ATT&amp;CK techniques per tactic, from the report</span></h3>
      <ol class="c3-chart__rows" aria-hidden="true">
        {%- for tac in site.data.attack_index.tactics -%}
        {%- assign _n = lead_tacs | where_exp: "x", "x == tac.name" | size -%}
        {%- if _n > 0 %}
        <li class="c3-chart__row{% if _n == tac_max %} c3-chart__row--top{% endif %}"><span class="c3-chart__t">{{ tac.name }}</span><span class="c3-chart__bar"><i style="width: {{ _n | times: 100 | divided_by: tac_max }}%"></i></span><span class="c3-chart__n">{{ _n }}</span></li>
        {%- endif -%}
        {%- endfor %}
      </ol>
      <table class="c3-sr">
        <caption>Distinct ATT&amp;CK techniques per tactic in the lead report</caption>
        <thead><tr><th scope="col">Tactic</th><th scope="col">Techniques</th></tr></thead>
        <tbody>
          {%- for tac in site.data.attack_index.tactics -%}
          {%- assign _n = lead_tacs | where_exp: "x", "x == tac.name" | size %}
          <tr><th scope="row">{{ tac.name }}</th><td>{{ _n }}</td></tr>
          {%- endfor %}
        </tbody>
      </table>
    </div>
    {%- endif %}
  </div>
</section>

<div class="c3-sec" style="--sec: #ef4444;"><h2>Latest research</h2><span class="c3-sec__sub">newest first</span><a href="{{ '/reports/' | relative_url }}">All {{ n_reports }} reports &rarr;</a></div>
<div class="c3-rows">
{%- assign emitted_series = "" -%}
{%- if lead.series -%}{%- assign emitted_series = lead.series | append: ";" -%}{%- endif -%}
{%- assign shown = 0 -%}
{%- for e in latest -%}
{%- if shown >= 4 -%}{%- break -%}{%- endif -%}
{%- if e.report_url == lead.report_url -%}{%- continue -%}{%- endif -%}
{%- assign row_url = e.report_url -%}
{%- assign row_title = e.title -%}
{%- assign row_sev = e.severity -%}
{%- assign row_tags = e.tags -%}
{%- assign row_cover = e.cover_label -%}
{%- assign row_part = "" -%}
{%- assign row_emit = true -%}
{%- if e.series -%}
{%- assign skey = e.series | append: ";" -%}
{%- if emitted_series contains skey -%}{%- assign row_emit = false -%}{%- else -%}
{%- assign emitted_series = emitted_series | append: skey -%}
{%- assign series_members = latest | where: "series", e.series -%}
{%- assign series_parent = series_members | where: "series_order", 0 | first -%}
{%- unless series_parent -%}{%- assign series_parent = series_members | last -%}{%- endunless -%}
{%- assign stitle = "" -%}
{%- for s in series_members -%}{%- if s.series_title -%}{%- assign stitle = s.series_title -%}{%- endif -%}{%- endfor -%}
{%- if stitle == "" -%}{%- assign stitle = series_parent.title -%}{%- endif -%}
{%- assign row_url = series_parent.report_url -%}
{%- assign row_title = stitle -%}
{%- assign row_sev = series_parent.severity -%}
{%- assign row_tags = series_parent.tags -%}
{%- assign row_cover = series_parent.cover_label -%}
{%- capture row_part -%}Series &middot; {{ series_members.size }} reports{%- endcapture -%}
{%- endif -%}
{%- endif -%}
{%- if row_emit -%}
{%- capture _shown_title %}{% include defang-text.html text=row_title %}{% endcapture -%}
{%- case row_sev -%}{%- when "critical" -%}{%- assign row_sevlabel = "Critical" -%}{%- when "high" -%}{%- assign row_sevlabel = "High" -%}{%- when "med" -%}{%- assign row_sevlabel = "Medium" -%}{%- when "low" -%}{%- assign row_sevlabel = "Low" -%}{%- else -%}{%- assign row_sevlabel = row_sev | capitalize -%}{%- endcase %}
<a class="c3-row" href="{{ row_url | relative_url }}">
  {% include c3-cover.html label=row_cover severity=row_sev size="row" %}
  <div class="c3-row__main">
    <div class="c3-row__k"><span class="c3-sev c3-sev--{{ row_sev }}">{{ row_sevlabel }}</span><span>{{ e.date | date: "%-d %b %Y" }}</span>{% if row_part != "" %}<span>{{ row_part }}</span>{% endif %}</div>
    <div class="c3-row__t">{{ _shown_title }}</div>
  </div>
  <div class="c3-row__g">{% for t in row_tags %}{% unless forloop.first %} &middot; {% endunless %}{{ t }}{% endfor %}</div>
</a>
{%- assign shown = shown | plus: 1 -%}
{%- endif -%}
{%- endfor %}
</div>

<div class="c3-stats">
  <a href="{{ '/reports/' | relative_url }}"><b>{{ n_reports }}</b><span>Reports</span></a>
  <a href="{{ '/hunting-detections/' | relative_url }}"><b>{{ n_det }}</b><span>Detection Rules</span></a>
  <a href="{{ '/techniques/' | relative_url }}"><b>{{ n_techniques }}</b><span>ATT&amp;CK Techniques Covered</span></a>
  <a href="{{ '/ioc-feeds/' | relative_url }}"><b>{{ n_ioc }}</b><span>IOCs</span></a>
  <a href="{{ '/stix/' | relative_url }}"><b>{{ n_stix }}</b><span>STIX Bundles</span></a>
  <a href="{{ '/families/' | relative_url }}"><b>{{ n_families }}</b><span>Malware &amp; Tools Profiled</span></a>
  <a href="{{ '/actors/' | relative_url }}"><b>{{ n_actors }}</b><span>Threat Actors Tracked</span></a>
  {%- if site.data.impact.actions_reported %}
  <a href="{{ '/impact/' | relative_url }}"><b>{{ site.data.impact.actions_reported }}</b><span>Takedowns &amp; Victim Actions</span></a>
  {%- endif %}
</div>
{%- if site.data.impact.actions_reported %}
<p class="hl-creds-note c3-note">Takedowns &amp; Victim Actions counts only what was reported back to me; most of my reports get no reply.</p>
{%- endif %}

<div class="c3-sec" style="--sec: #4ade80;"><h2>Explore</h2></div>
<div class="c3-cols">
  <div style="--sec: #4ade80;">
    <h3>Use the research</h3>
    <ul>
      <li><a href="{{ '/reports/' | relative_url }}"><span class="c3-li__t">Reports</span><span class="c3-li__n">{{ n_reports }}</span><span class="c3-li__d">In-depth malware analysis &amp; reverse engineering</span></a></li>
      <li><a href="{{ '/hunting-detections/' | relative_url }}"><span class="c3-li__t">Detection Library</span><span class="c3-li__n">{{ n_det }}</span><span class="c3-li__d">Sigma, YARA, and Suricata rules</span></a></li>
      <li><a href="{{ '/ioc-feeds/' | relative_url }}"><span class="c3-li__t">IOC Feeds</span><span class="c3-li__n">{{ n_ioc }}</span><span class="c3-li__d">Indicators ready for your SIEM or EDR</span></a></li>
      <li><a href="{{ '/stix/' | relative_url }}"><span class="c3-li__t">STIX Bundles</span><span class="c3-li__n">{{ n_stix }}</span><span class="c3-li__d">STIX 2.1 bundles for OpenCTI &amp; MISP</span></a></li>
    </ul>
  </div>
  <div style="--sec: #a371f7;">
    <h3>Browse the corpus</h3>
    <ul>
      <li><a href="{{ '/actors/' | relative_url }}"><span class="c3-li__t">Threat Actors</span><span class="c3-li__n">{{ n_actors }}</span><span class="c3-li__d">Tracked actors and the evidence behind each</span></a></li>
      <li><a href="{{ '/families/' | relative_url }}"><span class="c3-li__t">Malware Families</span><span class="c3-li__n">{{ n_families }}</span><span class="c3-li__d">Each family with its reports, rules and feeds</span></a></li>
      <li><a href="{{ '/techniques/' | relative_url }}"><span class="c3-li__t">ATT&amp;CK Techniques</span><span class="c3-li__n">{{ n_techniques }}</span><span class="c3-li__d">Coverage heatmap and a Navigator layer</span></a></li>
      <li><a href="{{ '/impact/' | relative_url }}"><span class="c3-li__t">Takedowns &amp; Victim Actions</span>{% if site.data.impact.actions_reported %}<span class="c3-li__n">{{ site.data.impact.actions_reported }}</span>{% endif %}<span class="c3-li__d">What hosts, CERTs and victims did after my reports</span></a></li>
    </ul>
  </div>
  <div style="--sec: #22d3ee;">
    <h3>Stay current</h3>
    <ul>
      <li><a href="{{ '/wire/' | relative_url }}"><span class="c3-li__t">The Wire</span><span class="c3-li__n">every 15 min</span><span class="c3-li__d">Headlines from public threat research, every 15 minutes</span></a></li>
      <li><a href="{{ '/changes/' | relative_url }}"><span class="c3-li__t">Changes</span><span class="c3-li__d">Revisions to published reports, newest first</span></a></li>
    </ul>
  </div>
  <div style="--sec: #f97316;">
    <h3>About &amp; Connect</h3>
    <ul>
      <li><a href="{{ '/about-me/' | relative_url }}"><span class="c3-li__t">About Me</span><span class="c3-li__d">Background &amp; how to reach me</span></a></li>
      <li><a href="{{ '/behind-the-reports/' | relative_url }}"><span class="c3-li__t">Behind the Reports</span><span class="c3-li__d">How the intelligence is produced</span></a></li>
      <li><a href="{{ '/consulting/' | relative_url }}"><span class="c3-li__t">Consulting</span><span class="c3-li__d">Malware analysis, IR &amp; detection services</span></a></li>
      <li><a href="{{ '/support/' | relative_url }}"><span class="c3-li__t">Support</span><span class="c3-li__d">Help keep the research free</span></a></li>
    </ul>
  </div>
</div>

<div class="hl-contribute c3-contribute">Have original research, detections, or IOCs to share? Reach out at <a href="mailto:intel@the-hunters-ledger.com">intel@the-hunters-ledger.com</a>. Findings can be posted on your behalf as a co-author, or attributed however you prefer.</div>
</div>
