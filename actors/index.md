---
title: Threat Actors
nav_title: Threat Actors
description: "Every threat actor The Hunters Ledger tracks, the UTA designations it assigns and the handles its reports name at high confidence, with the reports, infrastructure, tooling and ATT&CK techniques behind each one."
layout: page
permalink: /actors/
thumbnail: /assets/images/cards/actors.png
position: 2.7
---

<div class="hl-page-header" style="--ph-accent: #e879f9;">
  <div class="hl-page-header__label">Threat Actors</div>
  <div class="hl-page-header__title">Tracked Threat Actors</div>
  <div class="hl-page-header__desc">The operators behind the reports. A <strong>UTA</strong> is a tracking label this publication assigns to an actor it has observed but cannot yet link to a publicly named group, so that the same operator can be recognised across reports. A <strong>named actor</strong> is one a report attributes to a self-identifying handle at HIGH confidence or above, so no label was needed. Each profile summarises what the reports already say and points back to them.</div>
</div>

{%- assign actors = site.data.actors.actors | sort: "first_observed" | reverse -%}
{%- assign idx = site.data.actors_index.actors -%}

<div class="hl-filter" data-listing-filter data-pagefind-ignore>
  <input class="hl-filter__search" type="text" placeholder="Search actors by designation, description, tooling or motivation…" aria-label="Filter actors" autocomplete="off">
  <div class="hl-filter__chips">
    <button type="button" class="hl-chip-btn is-on" data-tag="">All</button>
    <button type="button" class="hl-chip-btn" data-tag="uta">UTA</button>
    <button type="button" class="hl-chip-btn" data-tag="named">Named</button>
    <button type="button" class="hl-chip-btn" data-tag="high">HIGH</button>
    <button type="button" class="hl-chip-btn" data-tag="moderate">MODERATE</button>
    <button type="button" class="hl-chip-btn" data-tag="low">LOW</button>
    <button type="button" class="hl-chip-btn" data-tag="ai-augmented">AI-augmented</button>
    <button type="button" class="hl-chip-btn" data-tag="cryptojacking">Cryptojacking</button>
    <button type="button" class="hl-chip-btn" data-tag="espionage">Espionage-flavoured</button>
    <button type="button" class="hl-chip-btn" data-tag="financial">Financial</button>
  </div>
  <div class="hl-filter__count" data-filter-count></div>
  <div class="hl-filter__empty" data-filter-empty hidden>No actors match that filter. <button type="button" class="hl-filter__reset" data-filter-reset>Clear filters</button></div>
</div>

<div class="hl-grid hl-grid--actors" data-filter-grid data-pagefind-ignore>
{%- for a in actors -%}
  {%- assign ix = idx | where: "id", a.id | first -%}
  {%- assign tgt = "" -%}
  {%- if a.targeting.regions %}{% assign tgt = tgt | append: " " | append: a.targeting.regions | join: " " %}{% endif -%}
  {%- if a.targeting.sectors %}{% assign tgt = tgt | append: " " | append: a.targeting.sectors | join: " " %}{% endif -%}
  {%- if a.identifiers %}{% for idn in a.identifiers %}{% assign tgt = tgt | append: " " | append: idn.value %}{% endfor %}{% endif -%}
  {%- assign hay = a.type | append: " " | append: a.motivation | append: " " | append: a.tooling | join: " " | append: " " | append: a.alias | append: " " | append: tgt -%}
  {%- assign named = false -%}{%- if a.kind == 'named' %}{% assign named = true %}{% endif -%}
  {%- assign shown = a.id -%}{%- if named %}{% assign shown = a.name %}{% endif -%}
  {%- assign level = a.confidence.distinct_actor -%}{%- if named %}{% assign level = a.confidence.named_actor %}{% endif -%}
  {%- assign pct = a.confidence.distinct_actor_pct -%}{%- if named %}{% assign pct = a.confidence.named_actor_pct %}{% endif -%}
  {%- assign tagbag = "" -%}
  {%- if named %}{% assign tagbag = tagbag | append: "named|" %}{% else %}{% assign tagbag = tagbag | append: "uta|" %}{% endif -%}
  {%- if level %}{% assign tagbag = tagbag | append: level | downcase %}{% endif -%}
  {%- assign lower = hay | downcase -%}
  {%- if lower contains "ai" and lower contains "agent" or lower contains "llm" or lower contains "ai-augmented" or lower contains "ai co" or lower contains "claude" or lower contains "gemini" or lower contains "rovodev" or lower contains "openclaw" %}{% assign tagbag = tagbag | append: "|ai-augmented" %}{% endif -%}
  {%- if lower contains "cryptojack" %}{% assign tagbag = tagbag | append: "|cryptojacking" %}{% endif -%}
  {%- if lower contains "espionage" or lower contains "intelligence collection" %}{% assign tagbag = tagbag | append: "|espionage" %}{% endif -%}
  {%- if lower contains "financial" or lower contains "crimeware" or lower contains "cybercrime" or lower contains "fraud" %}{% assign tagbag = tagbag | append: "|financial" %}{% endif -%}
  <a href="{{ a.id | prepend: '/actors/' | append: '/' | relative_url }}" class="hl-card hl-catalog-card hl-actor-card"
     data-title="{{ shown | append: ' ' | append: a.id | append: ' ' | append: hay | downcase | escape }}"
     data-tags="{{ tagbag | escape }}">
    <div class="hl-card__inner">
      <div class="hl-card__bar hl-actor-card__bar--{{ level | default: 'none' | downcase }}"></div>
      <div>
        <div class="hl-card__meta hl-actor-card__meta">{% if named %}Named &middot; {% endif %}{{ a.first_observed | date: "%b %Y" }}{% if level %} &middot; {{ level }}{% if pct %} {{ pct }}%{% endif %}{% endif %}{% if ix %} &middot; {{ ix.report_count }} report{% if ix.report_count != 1 %}s{% endif %}{% endif %}{% if a.targeting.regions and a.targeting.regions.size > 0 %} &middot; {{ a.targeting.regions | join: ", " }}{% endif %}</div>
        <div class="hl-card__title">{{ shown }}{% if a.alias %} <span class="hl-actor-card__alias">{{ a.alias }}</span>{% endif %}</div>
        <div class="hl-actor-card__type">{{ a.type }}</div>
      </div>
    </div>
    {%- if a.tooling and a.tooling.size > 0 -%}
    <div class="hl-tags hl-card__tags">
      {%- for t in a.tooling limit: 4 -%}<span class="hl-tag hl-tag--blue">{{ t }}</span>{%- endfor -%}
    </div>
    {%- endif -%}
  </a>
{%- endfor -%}
</div>

<p class="hl-actor__muted">Designations are numbered in the order they were created and are never reused. A designation whose report is published preview-style is listed once the report goes live. For a UTA the confidence shown is the published report's figure for "one trackable operator", and named-actor attribution is INSUFFICIENT by definition. For a named actor it is the report's figure for the attribution to that handle, HIGH or above, which is why no designation was assigned; the real-world identity behind a handle is not claimed.</p>

<script defer src="{{ '/assets/js/listing-filter.js' | relative_url }}?v=11"></script>
