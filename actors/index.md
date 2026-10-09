---
title: Threat Actors
nav_title: Threat Actors
description: "Every Unattributed Threat Actor (UTA) designation The Hunters Ledger tracks, with the reports, infrastructure, tooling and ATT&CK techniques behind each one."
layout: page
permalink: /actors/
thumbnail: /assets/images/cards/actors.png
position: 2.7
---

<div class="hl-page-header" style="--ph-accent: #e879f9;">
  <div class="hl-page-header__label">Threat Actors</div>
  <div class="hl-page-header__title">Unattributed Threat Actors</div>
  <div class="hl-page-header__desc">The operators behind the reports. A <strong>UTA</strong> is a tracking label this publication assigns to an actor it has observed but cannot yet link to a publicly named group, so that the same operator can be recognised across reports. Each profile summarises what the reports already say and points back to them.</div>
</div>

{%- assign actors = site.data.actors.actors | sort: "first_observed" | reverse -%}
{%- assign idx = site.data.actors_index.actors -%}

<div class="hl-filter" data-listing-filter data-pagefind-ignore>
  <input class="hl-filter__search" type="text" placeholder="Search actors by designation, description, tooling or motivation…" aria-label="Filter actors" autocomplete="off">
  <div class="hl-filter__chips">
    <button type="button" class="hl-chip-btn is-on" data-tag="">All</button>
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
  {%- assign hay = a.type | append: " " | append: a.motivation | append: " " | append: a.tooling | join: " " | append: " " | append: a.alias -%}
  {%- assign tagbag = "" -%}
  {%- if a.confidence.distinct_actor %}{% assign tagbag = tagbag | append: a.confidence.distinct_actor | downcase %}{% endif -%}
  {%- assign lower = hay | downcase -%}
  {%- if lower contains "ai" and lower contains "agent" or lower contains "llm" or lower contains "ai-augmented" or lower contains "ai co" or lower contains "claude" or lower contains "gemini" or lower contains "rovodev" or lower contains "openclaw" %}{% assign tagbag = tagbag | append: "|ai-augmented" %}{% endif -%}
  {%- if lower contains "cryptojack" %}{% assign tagbag = tagbag | append: "|cryptojacking" %}{% endif -%}
  {%- if lower contains "espionage" or lower contains "intelligence collection" %}{% assign tagbag = tagbag | append: "|espionage" %}{% endif -%}
  {%- if lower contains "financial" or lower contains "crimeware" or lower contains "cybercrime" or lower contains "fraud" %}{% assign tagbag = tagbag | append: "|financial" %}{% endif -%}
  <a href="{{ a.id | prepend: '/actors/' | append: '/' | relative_url }}" class="hl-card hl-catalog-card hl-actor-card"
     data-title="{{ a.id | append: ' ' | append: hay | downcase | escape }}"
     data-tags="{{ tagbag | escape }}">
    <div class="hl-card__inner">
      <div class="hl-card__bar hl-actor-card__bar--{{ a.confidence.distinct_actor | default: 'none' | downcase }}"></div>
      <div>
        <div class="hl-card__meta hl-actor-card__meta">{{ a.first_observed | date: "%b %Y" }}{% if a.confidence.distinct_actor %} &middot; {{ a.confidence.distinct_actor }}{% if a.confidence.distinct_actor_pct %} {{ a.confidence.distinct_actor_pct }}%{% endif %}{% endif %}{% if ix %} &middot; {{ ix.report_count }} report{% if ix.report_count != 1 %}s{% endif %}{% endif %}</div>
        <div class="hl-card__title">{{ a.id }}{% if a.alias %} <span class="hl-actor-card__alias">{{ a.alias }}</span>{% endif %}</div>
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

<p class="hl-actor__muted">Designations are numbered in the order they were created and are never reused. A designation whose report is published preview-style is listed once the report goes live. Confidence is the published report's figure for "one trackable operator"; named-actor attribution is INSUFFICIENT for every designation here, which is what the label means.</p>

<script defer src="{{ '/assets/js/listing-filter.js' | relative_url }}?v=11"></script>
