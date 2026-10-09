---
title: ATT&CK Techniques
nav_title: ATT&CK Techniques
description: "Every MITRE ATT&CK technique mapped by a published report or detection rule on The Hunters Ledger, as a site-wide coverage heatmap with a page per technique and a Navigator layer to download."
layout: page
permalink: /techniques/
position: 2.8
---

{%- assign ix = site.data.attack_index -%}

<div class="hl-page-header" style="--ph-accent: #fb923c;">
  <div class="hl-page-header__label">ATT&amp;CK Coverage</div>
  <div class="hl-page-header__title">Techniques across the corpus</div>
  <div class="hl-page-header__desc">{{ ix.techniques.size }} techniques mapped by the published reports and detection rules, laid out as the ATT&amp;CK matrix (v{{ ix.attack_version }}). Darker cells are mapped more often; the score is reports plus rules. Every cell opens a page listing exactly which reports, rules and tracked actors map that technique. <a href="{{ '/assets/data/attack-navigator-layer.json' | relative_url }}" download="hunters-ledger-attack-layer.json">Download the Navigator layer</a> to open the same view in <a href="https://mitre-attack.github.io/attack-navigator/" rel="noopener">ATT&amp;CK Navigator</a>.</div>
</div>

<div class="hl-filter" data-pagefind-ignore>
  <input class="hl-filter__search hl-heatmap__search" id="hl-heatmap-q" type="text" placeholder="Filter techniques by ID or name…" aria-label="Filter techniques" autocomplete="off">
</div>

<div class="hl-heatmap" id="hl-heatmap" style="--hl-heat-max: {{ ix.max_score }};" data-pagefind-ignore>
  {%- for tactic in ix.tactics -%}
  <div class="hl-heatmap__col">
    <div class="hl-heatmap__tactic"><span>{{ tactic.name }}</span><span class="hl-heatmap__tactic-count">{{ tactic.technique_count }}</span></div>
    {%- for t in ix.techniques -%}
    {%- if t.tactics contains tactic.name -%}
    <a class="hl-heatmap__cell" href="{{ t.url | relative_url }}" style="--hl-heat: {{ t.score }};" data-q="{{ t.id | downcase }} {{ t.name | downcase | escape }}" title="{{ t.id }} {{ t.name | escape }}: {{ t.report_count }} report{% if t.report_count != 1 %}s{% endif %}, {{ t.rule_count }} rule{% if t.rule_count != 1 %}s{% endif %}">
      <span class="hl-heatmap__id">{{ t.id }}</span>
      <span class="hl-heatmap__name">{{ t.name }}</span>
      <span class="hl-heatmap__score">{{ t.score }}</span>
    </a>
    {%- endif -%}
    {%- endfor -%}
  </div>
  {%- endfor -%}
</div>
<p class="hl-heatmap__empty" id="hl-heatmap-empty" hidden>No technique matches that filter.</p>

<p class="hl-xref__muted">A technique that belongs to more than one tactic appears in each of its columns. The matrix lists only techniques something on the site maps, so an empty tactic is a gap in the corpus, not in the matrix.{% if ix.unresolved.size > 0 %} Not shown: {% for u in ix.unresolved %}{{ u.id }}{% unless forloop.last %}, {% endunless %}{% endfor %}, carried by a report or rule but not present in ATT&amp;CK v{{ ix.attack_version }}.{% endif %}</p>

<h2 id="most-mapped">Most mapped techniques</h2>
{%- assign top = ix.techniques | sort: "score" | reverse -%}
<ol class="hl-xref__top">
{%- for t in top limit: 15 -%}
  <li><a href="{{ t.url | relative_url }}"><code>{{ t.id }}</code> {{ t.name }}</a> <span class="hl-xref__muted">{{ t.report_count }} report{% if t.report_count != 1 %}s{% endif %}, {{ t.rule_count }} rule{% if t.rule_count != 1 %}s{% endif %}{% if t.actor_count > 0 %}, {{ t.actor_count }} actor{% if t.actor_count != 1 %}s{% endif %}{% endif %}</span></li>
{%- endfor -%}
</ol>

<p class="hl-xref__licence">MITRE ATT&amp;CK&reg; is a registered trademark of The MITRE Corporation. The heatmap is built from each report's own ATT&amp;CK mapping table and each detection page's coverage lines; it is this publication's reading of its own evidence, not a measure of how common a technique is in the wild.</p>

<script defer src="{{ '/assets/js/heatmap-filter.js' | relative_url }}?v=1"></script>
