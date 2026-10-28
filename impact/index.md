---
title: Impact
nav_title: Impact
description: "Takedowns and victim actions that hosts, registrars, platforms, CERTs and victims reported back after a Hunter's Ledger disclosure."
layout: page
permalink: /impact/
position: 2.95
---

<div class="hl-page-header" style="--ph-accent: #fbbf24;">
  <div class="hl-page-header__label">Impact</div>
  <div class="hl-page-header__title">Takedowns &amp; Victim Actions</div>
  <div class="hl-page-header__desc">When an investigation turns up live attacker infrastructure or an organisation that has been hit, I report it: to the hosting provider, registrar or platform, to the national CERT, or to the victim's own security team. These are the actions recipients reported back to me, plus any my own case records show. Most of my reports get no reply, so this is only what made it back to me.</div>
</div>

{%- assign entries = site.data.impact_entries.entries | sort: "date" | reverse -%}
{%- assign n_infra = 0 -%}{%- assign n_victim = 0 -%}{%- assign n_cert = 0 -%}
{%- for e in entries -%}
  {%- assign c = e.count | default: 1 -%}
  {%- if e.category == "attacker-infrastructure" %}{% assign n_infra = n_infra | plus: c %}{% endif -%}
  {%- if e.category == "victim-action" %}{% assign n_victim = n_victim | plus: c %}{% endif -%}
  {%- if e.category == "cert-action" %}{% assign n_cert = n_cert | plus: c %}{% endif -%}
{%- endfor -%}

<div class="hl-creds-strip">
  <span class="hl-cred-pill"><span class="hl-cred-pill__dot" style="background:#fbbf24;"></span><strong>{{ site.data.impact.actions_reported }}</strong>&nbsp;Actions in total</span>
  <span class="hl-cred-pill"><span class="hl-cred-pill__dot" style="background:#f87171;"></span><strong>{{ n_infra }}</strong>&nbsp;Attacker infrastructure actions</span>
  <span class="hl-cred-pill"><span class="hl-cred-pill__dot" style="background:#4ade80;"></span><strong>{{ n_victim }}</strong>&nbsp;Victim actions</span>
  <span class="hl-cred-pill"><span class="hl-cred-pill__dot" style="background:#58a6ff;"></span><strong>{{ n_cert }}</strong>&nbsp;CERT actions</span>
</div>

<div class="hl-filter" data-listing-filter data-pagefind-ignore>
  <input class="hl-filter__search" type="text" placeholder="Search actions…" aria-label="Filter actions" autocomplete="off">
  <div class="hl-filter__chips">
    <button type="button" class="hl-chip-btn is-on" data-tag="">All</button>
    <button type="button" class="hl-chip-btn" data-tag="attacker-infrastructure">Attacker infrastructure</button>
    <button type="button" class="hl-chip-btn" data-tag="victim-action">Victim actions</button>
    <button type="button" class="hl-chip-btn" data-tag="cert-action">CERT actions</button>
  </div>
  <div class="hl-filter__count" data-filter-count></div>
  <div class="hl-filter__empty" data-filter-empty hidden>Nothing matches that filter. <button type="button" class="hl-filter__reset" data-filter-reset>Clear filters</button></div>
</div>

<div class="hl-grid" data-filter-grid data-pagefind-ignore>
{%- assign accents = "#f87171,#fbbf24,#4ade80,#58a6ff,#a78bfa,#f472b6,#2dd4bf,#fb923c" | split: "," -%}
{%- for e in entries -%}
  {%- assign c = e.count | default: 1 -%}
  {%- assign ai = forloop.index0 | modulo: accents.size -%}{%- assign accent = accents[ai] -%}
  {%- if e.category == "attacker-infrastructure" %}{% assign bar = "high" %}{% assign label = "Attacker infrastructure" %}{% elsif e.category == "victim-action" %}{% assign bar = "low" %}{% assign label = "Victim action" %}{% else %}{% assign bar = "med" %}{% assign label = "CERT action" %}{% endif -%}
  {%- if e.report_url %}<a href="{{ e.report_url | relative_url }}"{% else %}<div{% endif %} class="hl-card hl-catalog-card hl-impact-card" style="--ia: {{ accent }};"
     data-title="{{ e.title | append: ' ' | append: e.description | append: ' ' | append: e.recipient | downcase | escape }}"
     data-tags="{{ e.category }}">
    <div class="hl-card__inner">
      <div class="hl-card__bar" style="background: {{ accent }};"></div>
      <div>
        <div class="hl-card__meta hl-impact-card__meta">{{ label }} &middot; {{ e.date | append: "-01" | date: "%b %Y" }}{% if c > 1 %} &middot; {{ c }} actions{% endif %}</div>
        <div class="hl-card__title hl-impact-card__title">{{ e.title }}</div>
        <p class="hl-impact-card__desc">{{ e.description }}</p>
        <div class="hl-card__meta">{% if e.verified == "record" %}From my case records, no reply on file{% else %}Reported by {{ e.recipient }}{% endif %}{% if e.verified == "checked" %} &middot; confirmed by my own check{% endif %}{% if e.report_url %} &middot; read the report{% endif %}</div>
      </div>
    </div>
  {% if e.report_url %}</a>{% else %}</div>{% endif %}
{%- endfor -%}
</div>

<p class="hl-actor__muted">Each card is one action, or a group of identical actions from one round of reports, and says where it comes from: the recipient's word, my own check, or my case records alone. Victim actions are described in general terms only, with no organisation, sector or country, because the victims and the national CERTs that relayed my reports shared them in confidence. Most reports get no reply at all, and some of these actions may have had causes beyond my report.</p>

<script defer src="{{ '/assets/js/listing-filter.js' | relative_url }}?v=11"></script>
