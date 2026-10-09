---
title: Malware Families
nav_title: Malware Families
description: "Every malware and tool family The Hunters Ledger has published on, with the reports, detection rules, IOC feeds and tracked actors behind each one."
layout: page
permalink: /families/
position: 2.9
---

{%- assign fams = site.data.family_index.families -%}

<div class="hl-page-header" style="--ph-accent: #2dd4bf;">
  <div class="hl-page-header__label">Families</div>
  <div class="hl-page-header__title">Malware and tool families</div>
  <div class="hl-page-header__desc">{{ fams.size }} families named by a published report, detection rule, IOC feed or actor profile. Each page collects every spelling the corpus uses for the family and points back to where it appears. Families are listed by what the evidence calls them; a report that declines to name a family is not given one here.</div>
</div>

{%- assign kinds = fams | map: "kind" | uniq -%}
<div class="hl-filter" data-listing-filter data-pagefind-ignore>
  <input class="hl-filter__search" type="text" placeholder="Search families by name, alias or kind…" aria-label="Filter families" autocomplete="off">
  <div class="hl-filter__chips">
    <button type="button" class="hl-chip-btn is-on" data-tag="">All</button>
    {%- for k in kinds -%}
    <button type="button" class="hl-chip-btn" data-tag="{{ k }}">{{ k | replace: "-", " " }}</button>
    {%- endfor -%}
  </div>
  <div class="hl-filter__count" data-filter-count></div>
  <div class="hl-filter__empty" data-filter-empty hidden>No families match that filter. <button type="button" class="hl-filter__reset" data-filter-reset>Clear filters</button></div>
</div>

<div class="hl-grid hl-grid--actors" data-filter-grid data-pagefind-ignore>
{%- assign sorted = fams | sort: "rule_count" | reverse -%}
{%- for f in sorted -%}
  <a href="{{ f.url | relative_url }}" class="hl-card hl-catalog-card hl-family-card"
     data-title="{{ f.name | append: ' ' | append: f.kind | append: ' ' | append: f.aliases | join: ' ' | downcase | escape }}"
     data-tags="{{ f.kind }}">
    <div class="hl-card__inner">
      <div class="hl-card__bar hl-family-card__bar"></div>
      <div>
        <div class="hl-card__meta hl-family-card__meta">{{ f.kind | replace: "-", " " }} &middot; {{ f.report_count }} report{% if f.report_count != 1 %}s{% endif %} &middot; {{ f.rule_count }} rule{% if f.rule_count != 1 %}s{% endif %}{% if f.actor_count > 0 %} &middot; {{ f.actor_count }} actor{% if f.actor_count != 1 %}s{% endif %}{% endif %}</div>
        <div class="hl-card__title">{{ f.name }}</div>
        {%- if f.summary -%}<div class="hl-family-card__summary">{{ f.summary }}</div>{%- endif -%}
      </div>
    </div>
    {%- if f.actors.size > 0 -%}
    <div class="hl-tags hl-card__tags">
      {%- for id in f.actors limit: 4 -%}<span class="hl-tag hl-tag--purple">{{ id }}</span>{%- endfor -%}
    </div>
    {%- endif -%}
  </a>
{%- endfor -%}
</div>

<p class="hl-xref__muted">The vocabulary that decides each family's canonical name lives in <code>_data/families.yml</code>; a label it does not know is listed by name in the generated index rather than guessed into a page.</p>

<script defer src="{{ '/assets/js/listing-filter.js' | relative_url }}?v=11"></script>
