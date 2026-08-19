---
title: The Wire
layout: page
permalink: /wire/
position: 2.5
---

<div class="hl-page-header" style="--ph-accent: #58a6ff;">
  <div class="hl-page-header__label">The Wire</div>
  <div class="hl-page-header__title">Threat Intelligence Headlines</div>
  <div class="hl-page-header__desc">Recent threat-intel reporting from public sources, refreshed twice daily. Headlines and links only, every item goes to the original publisher. This is aggregation rather than original research. My original research can be found in the <a href="/reports/">reports section</a>.</div>
</div>

{%- assign wire = site.data.wire -%}
{%- if wire and wire.items and wire.items != empty -%}

<div class="hl-wire__prov">
  <div class="hl-wire__prov-title">Where this comes from</div>
  <p>The headlines are other people’s reporting, but the pipeline is mine. Every item here comes out of the OpenCTI threat-intelligence platform I run and maintain myself, the same instance that holds the <a href="/stix/">STIX bundles</a> for every report I publish and feeds the blocklists on my own network. Nothing on this page is scraped.</p>
</div>

<p class="hl-wire__freshness">Updated {{ wire.generated_at | date: "%-d %B %Y, %H:%M" }} UTC &middot; {{ wire.counts.total }} items from the last {{ wire.window_days }} days</p>

{%- comment -%}
  The chip vocabulary comes precomputed from wire.topics rather than from the
  shared listing-filter include, which counts tags in a nested Liquid loop. At
  531 items carrying 1,267 distinct labels that include would render 133 chips
  and cost 3.2 million iterations on every build. Both measured, not assumed.
  The markup and class names are the include's, so the CSS and the JS are shared.
{%- endcomment -%}
<div class="hl-filter hl-filter--wire" data-listing-filter>
  <input class="hl-filter__search" type="text" placeholder="Filter headlines…" aria-label="Filter headlines" autocomplete="off">
  <div class="hl-filter__chips hl-filter__chips--kind">
    <span class="hl-filter__dim">Source</span>
    <button type="button" class="hl-chip-btn is-on" data-kind="">All</button>
    <button type="button" class="hl-chip-btn hl-chip-btn--research" data-kind="research">Research <span class="hl-chip-btn__n">{{ wire.counts.research }}</span></button>
    <button type="button" class="hl-chip-btn hl-chip-btn--news" data-kind="news">News <span class="hl-chip-btn__n">{{ wire.counts.news }}</span></button>
  </div>
  <div class="hl-filter__chips hl-filter__chips--topic">
    <span class="hl-filter__dim">Topic</span>
    <button type="button" class="hl-chip-btn is-on" data-tag="">All</button>
    {%- for t in wire.topics -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c{{ t.color }}" data-tag="{{ t.label }}">{{ t.label }} <span class="hl-chip-btn__n">{{ t.count }}</span></button>{%- endfor -%}
  </div>
  <div class="hl-filter__count" data-filter-count></div>
  <div class="hl-filter__empty" data-filter-empty hidden>No headlines match that filter. <button type="button" class="hl-filter__reset" data-filter-reset>Clear filters</button></div>
</div>

<div class="hl-wire" data-filter-grid data-filter-item=".hl-wire__item">
{%- assign current_day = "" -%}
{%- for i in wire.items -%}
{%- assign day = i.date | date: "%Y-%m-%d" -%}
{%- if day != current_day -%}
{%- assign current_day = day -%}
<div class="hl-wire__day" data-filter-group>{{ i.date | date: "%A %-d %B %Y" }}</div>
{%- endif -%}
<a class="hl-wire__item hl-wire__item--{{ i.kind }} hl-wire__item--src-{{ i.source | slugify }}" href="{{ i.url }}" target="_blank" rel="noopener noreferrer" data-title="{{ i.title | downcase | escape }}" data-tags="{{ i.labels | join: '|' | downcase | escape }}" data-kind="{{ i.kind }}"><span class="hl-wire__src">{{ i.source }}</span><span class="hl-wire__title">{{ i.title }}</span><span class="hl-wire__labels">{%- for l in i.labels limit: 2 -%}{%- assign tc = wire.label_colors[l] -%}<span class="hl-wire__label{% if tc %} hl-topic-c{{ tc }}{% endif %}">{{ l }}</span>{%- endfor -%}</span></a>
{%- endfor -%}
</div>

<script defer src="{{ '/assets/js/listing-filter.js' | relative_url }}?v=9"></script>

{%- else -%}

<p class="hl-wire__freshness">The Wire is not currently available. The feed is regenerated twice daily; if this persists, the generator needs attention.</p>

{%- endif %}

*Headlines and links are the property of their publishers and appear here as attributed links. Follow any headline to read the original.*
