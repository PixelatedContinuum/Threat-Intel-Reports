---
title: Detection Library
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
    <span>Subscribe — live Suricata rule feed</span>
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
      <span class="hl-feed__meta">Auto-updates as new detections publish</span>
    </div>
  </div>
</details>

<style>
.hl-feed{margin:0 0 22px;border:1px solid color-mix(in srgb,var(--hl-accent-green) 26%,transparent);border-radius:10px;background:color-mix(in srgb,var(--hl-accent-green) 6%,var(--hl-bg-card));overflow:hidden}
.hl-feed__toggle{display:flex;align-items:center;gap:9px;cursor:pointer;padding:12px 16px;font-family:var(--hl-font-display);font-weight:700;font-size:.95em;color:var(--hl-accent-green);list-style:none;user-select:none}
.hl-feed__toggle::-webkit-details-marker{display:none}
.hl-feed__toggle:hover{background:color-mix(in srgb,var(--hl-accent-green) 10%,transparent)}
.hl-feed__chev{margin-left:auto;opacity:.7;font-size:.85em;transition:transform .18s ease}
.hl-feed[open] .hl-feed__chev{transform:rotate(180deg)}
.hl-feed__body{padding:2px 16px 16px;border-top:1px solid color-mix(in srgb,var(--hl-accent-green) 16%,transparent)}
.hl-feed__desc{color:var(--hl-text-primary);font-size:.9em;margin:12px 0}
.hl-feed__cmd{display:flex;align-items:stretch;background:#0d0d0d;border:1px solid var(--hl-border-card);border-radius:6px;overflow:hidden}
.hl-feed__cmd code{flex:1;min-width:0;padding:10px 12px;font-size:.78em;color:var(--hl-text-primary);overflow-x:auto;white-space:nowrap}
.hl-feed__copy{flex-shrink:0;padding:0 14px;font-family:var(--hl-font-display);font-weight:600;font-size:.78em;background:color-mix(in srgb,var(--hl-accent-green) 14%,transparent);color:var(--hl-accent-green);border:none;border-left:1px solid var(--hl-border-card);cursor:pointer;transition:background .15s}
.hl-feed__copy:hover{background:color-mix(in srgb,var(--hl-accent-green) 26%,transparent)}
.hl-feed__note{color:var(--hl-text-muted);font-size:.8em;margin:9px 0 0;line-height:1.5}
.hl-feed__note code{background:color-mix(in srgb,var(--hl-accent-green) 10%,transparent);padding:1px 5px;border-radius:3px;font-size:.95em}
.hl-feed__alt{display:inline-block;margin-top:5px;overflow-wrap:anywhere}
.hl-feed__links{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:11px;flex-wrap:wrap}
.hl-feed__links a{color:var(--hl-accent-green);text-decoration:none;font-size:.85em;font-weight:600}
.hl-feed__links a:hover{text-decoration:underline}
.hl-feed__meta{color:var(--hl-text-muted);font-size:.78em}
</style>

{% assign det_entries = site.data.catalog.entries | where_exp: "e", "e.detection_url" | sort: "date" | reverse %}

{% include listing-filter.html entries=det_entries tag_field="detection_tags" placeholder="Search detections by name…" %}

<div class="hl-grid" data-filter-grid>
{% for e in det_entries %}
  {% if e.detection_title %}{% assign dtitle = e.detection_title %}{% else %}{% assign dtitle = e.title | prepend: "Detection Rules — " %}{% endif %}
  {% assign dtags = e.detection_tags | default: e.tags %}
  {% include catalog-card.html url=e.detection_url title=dtitle date=e.date severity=e.severity tags=dtags %}
{% endfor %}
</div>
