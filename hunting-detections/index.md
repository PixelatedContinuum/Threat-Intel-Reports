---
title: Detection Library
description: "Sigma, YARA and Suricata detection rules from original research, mapped to MITRE ATT&CK and licensed CC BY 4.0, plus a live Suricata rule feed."
layout: page
permalink: /hunting-detections/
thumbnail: /assets/images/cards/hunting-detections.png
position: 3
---

<div class="hl-page-header" style="--ph-accent: #4ade80;">
  <div class="hl-page-header__label">Detection Library</div>
  <div class="hl-page-header__title">Sigma, YARA &amp; Suricata Rules</div>
  <div class="hl-page-header__desc">Detection logic from original research, mapped to MITRE ATT&amp;CK. Free to use, including commercially, under <strong>CC BY 4.0</strong>.</div>
</div>

<details class="hl-feed">
  <summary class="hl-feed__toggle">
    <span aria-hidden="true">📡</span>
    <span>Subscribe to the live Suricata rule feed</span>
    <span class="hl-feed__chev" aria-hidden="true">▾</span>
  </summary>
  <div class="hl-feed__body">
    <p class="hl-feed__desc">Every published detection here, consolidated into one auto-updating Suricata ruleset. Now an <strong>official suricata-update source</strong>, listed in the OISF index alongside Emerging Threats, abuse.ch and Stamus, with its own registered SID block <code>3500000-3509999</code>. Free under <strong>CC BY 4.0</strong>.</p>
    <div class="hl-feed__cmd">
      <code id="hl-feed-cmd">suricata-update enable-source the-hunters-ledger/open</code>
      <button type="button" class="hl-feed__copy" onclick="navigator.clipboard.writeText(document.getElementById('hl-feed-cmd').textContent);var b=this;b.textContent='Copied';setTimeout(function(){b.textContent='Copy';},1500);">Copy</button>
    </div>
    <p class="hl-feed__note">Requires Suricata 8.0 or newer. If the source isn't listed, run <code>suricata-update update-sources</code> first to refresh the index.</p>
    <p class="hl-feed__note"><strong>Other platforms</strong> (OPNsense, pfSense, Corelight, Stamus, Wazuh, Security Onion) can point straight at the raw feed URL, or add it by hand:<br><code class="hl-feed__alt">suricata-update add-source hunters-ledger https://the-hunters-ledger.com/feeds/suricata/hunters-ledger.rules</code></p>
    <div class="hl-feed__links">
      <a href="/feeds/suricata/hunters-ledger.rules">View raw feed →</a>
      <a href="/feeds/suricata/changelog/">Changelog &amp; withdrawn SIDs →</a>
      <span class="hl-feed__meta">Auto-updates as new detections publish</span>
    </div>
  </div>
</details>


{% assign det_entries = site.data.catalog.entries | where_exp: "e", "e.detection_url" | sort: "date" | reverse %}

{% include listing-filter.html entries=det_entries tag_field="detection_tags" placeholder="Search detections by name…" %}

<div class="hl-grid" data-filter-grid data-pagefind-ignore>
{% for e in det_entries %}
  {% if e.detection_title %}{% assign dtitle = e.detection_title %}{% else %}{% assign dtitle = e.title | prepend: "Detection Rules — " %}{% endif %}
  {% assign dtags = e.detection_tags | default: e.tags %}
  {% include catalog-card.html url=e.detection_url title=dtitle date=e.date severity=e.severity tags=dtags %}
{% endfor %}
</div>
