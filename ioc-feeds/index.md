---
title: IOC Feeds
description: "Structured indicator of compromise feeds from original research, ready for SIEM, EDR or CTI ingestion, licensed CC BY 4.0 and searchable by indicator."
layout: page
permalink: /ioc-feeds/
thumbnail: /assets/images/cards/ioc-feeds.png
position: 4
redirect_from:
  - /lookup/
---

<div class="hl-page-header" style="--ph-accent: #f87171;">
  <div class="hl-page-header__label">IOC Feeds</div>
  <div class="hl-page-header__title">Indicators of Compromise</div>
  <div class="hl-page-header__desc">Structured feeds ready for ingestion into your SIEM, EDR, or CTI platform. Licensed under <strong>CC BY 4.0</strong>. Already holding an indicator? Search it below to find the feed it belongs to.</div>
</div>

<details class="hl-feed">
  <summary class="hl-feed__toggle">
    <span aria-hidden="true">📡</span>
    <span>Subscribe as a MISP feed (MISP, OpenCTI)</span>
    <span class="hl-feed__chev" aria-hidden="true">▾</span>
  </summary>
  <div class="hl-feed__body">
    <p class="hl-feed__desc">Every published campaign as one MISP event, carrying its indicators, its Suricata, YARA and Sigma rules, its CVEs and ATT&amp;CK galaxy tags. Static files in the MISP feed format: MISP pulls it natively and OpenCTI reads it through its MISP feed connector. Free under <strong>CC BY 4.0</strong>.</p>
    <div class="hl-feed__cmd">
      <code id="hl-misp-cmd">https://the-hunters-ledger.com/feeds/misp/</code>
      <button type="button" class="hl-feed__copy" onclick="navigator.clipboard.writeText(document.getElementById('hl-misp-cmd').textContent);var b=this;b.textContent='Copied';setTimeout(function(){b.textContent='Copy';},1500);">Copy</button>
    </div>
    <p class="hl-feed__note">In MISP: Sync Actions, List Feeds, Add Feed, source format <strong>MISP feed</strong>, that URL. In OpenCTI: the <code>connector-misp-feed</code> connector with <code>MISP_FEED_URL</code> set to it.</p>
    <div class="hl-feed__links">
      <a href="/feeds/misp/">How to subscribe and what an event carries →</a>
      <a href="/feeds/misp/manifest.json">manifest.json →</a>
      <a href="/feeds/misp/changelog/">Changelog &amp; withdrawn events →</a>
      <span class="hl-feed__meta">Auto-updates as campaigns publish</span>
    </div>
  </div>
</details>

<div class="hl-iocsearch">
  <textarea class="hl-iocsearch__in" rows="2" spellcheck="false" autocomplete="off"
    placeholder="Paste one indicator, or a whole list. IPs, domains, URLs and hashes, separated by commas, spaces or newlines."
    aria-label="Search for indicators across every published feed"></textarea>
  <button type="button" class="hl-iocsearch__clear" hidden>Clear</button>
  <div class="hl-iocsearch__result" role="status" aria-live="polite"></div>
  <div class="hl-iocsearch__detail"></div>
  <p class="hl-iocsearch__hint hl-xref__muted" data-pagefind-ignore>Link straight to an indicator: <code>/ioc-feeds/?q=&lt;indicator&gt;</code> opens this page with the search already run (several values separated by commas), and the address bar follows what you type.</p>
</div>

{% assign ioc_entries = site.data.catalog.entries | where_exp: "e", "e.ioc_url" | sort: "date" | reverse %}

{% include listing-filter.html entries=ioc_entries tag_field="ioc_tags" placeholder="Search IOC feeds by name…" %}

<div class="hl-grid" data-filter-grid data-pagefind-ignore>
{% for e in ioc_entries %}
  {% if e.ioc_title %}{% assign ititle = e.ioc_title %}{% else %}{% assign ititle = e.title | append: " — IOC Feed" %}{% endif %}
  {% assign itags = e.ioc_tags | default: e.tags %}
  {% assign islug = e.ioc_url | split: '/' | last | remove: '-iocs.json' %}
  {%- comment -%} The card opens the readable table when one exists, and falls back to the
    raw JSON when it does not, so a feed with nothing typeable still links somewhere real
    rather than 404ing. The raw feed is linked prominently from the table page either way. {%- endcomment -%}
  {% if site.data.ioc_tables[islug] %}{% assign icard = site.data.ioc_tables[islug].page_url %}{% else %}{% assign icard = e.ioc_url %}{% endif %}
  {% include catalog-card.html url=icard title=ititle date=e.date severity=e.severity tags=itags slug=islug %}
{% endfor %}
</div>

<script defer src="{{ '/assets/js/ioc-classify.js' | relative_url }}?v=1"></script>
<script defer src="{{ '/assets/js/ioc-search.js' | relative_url }}?v=2"></script>
