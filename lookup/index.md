---
title: Indicator Lookup
layout: page
permalink: /lookup/
position: 4.2
---

<div class="hl-page-header" style="--ph-accent: #4ade80;">
  <div class="hl-page-header__label">Indicator Lookup</div>
  <div class="hl-page-header__title">Check Your Data Against Every Investigation</div>
  <div class="hl-page-header__desc">Paste a log excerpt, an alert, or a list of indicators. Every IP, domain, URL and hash in it is checked against the indicators published across my investigations, and any match tells you which campaign it came from and which detection rules to hunt with next.</div>
</div>

<div class="hl-lookup">
  <textarea class="hl-lookup__in" rows="7" spellcheck="false"
    placeholder="Paste anything. A firewall log, an alert body, a list of hashes, a single IP."
    aria-label="Text to check for indicators"></textarea>
  <div class="hl-lookup__bar">
    <button type="button" class="hl-lookup__go">Check indicators</button>
    <span class="hl-lookup__status" role="status" aria-live="polite"></span>
  </div>
  <div class="hl-lookup__out"></div>
</div>

<p class="hl-lookup__privacy"><strong>Nothing you paste leaves your browser.</strong> The indicator index is downloaded to your machine and the comparison happens there, so no request carries your text and nothing is logged. You can confirm that in your browser's network tab.</p>

<p class="hl-lookup__caveat">A match means the value appeared in one of my investigations. It is not a verdict on your environment, and no match does not mean you are unaffected, because this covers only what I have published. Matching is exact, so a related address in the same range will not match. Campaigns still under disclosure embargo are deliberately excluded.</p>

<script defer src="{{ '/assets/js/ioc-classify.js' | relative_url }}?v=1"></script>
<script defer src="{{ '/assets/js/ioc-lookup.js' | relative_url }}?v=1"></script>
