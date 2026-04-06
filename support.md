---
title: Support
layout: page
permalink: /support/
position: 6
---

<div class="hl-page-header" style="border-left-color: #4ade80;">
  <div class="hl-page-header__label" style="color: #4ade80;">Support the Work</div>
  <div class="hl-page-header__title">Keep This Research Independent</div>
  <div class="hl-page-header__desc">The Hunter's Ledger is run by a single researcher. No corporate backing, no paywalls, no ads. Your support keeps it that way.</div>
</div>

{% include section-header.html label="Donate" accent="#4ade80" %}

<div class="hl-support-section">
  <div class="hl-prose-section">
    <div class="hl-prose-section__body">
      Every report on this site is the product of original research — hands-on malware analysis, open-directory hunts, and detection engineering done on personal time and personal resources. Hosting, tooling, and the time it takes to do it right all have real costs. If the research has been useful to you or your team, a donation directly supports more of it.
    </div>
  </div>
  <div class="hl-support-donate">
    <div class="hl-support-cta__actions">
      <a class="hl-support-cta__btn" href="https://github.com/sponsors/PixelatedContinuum" target="_blank" rel="noopener noreferrer">Sponsor on GitHub</a>
      <a class="hl-support-cta__btn--outline" href="https://www.paypal.me/thehuntersledger" target="_blank" rel="noopener noreferrer">Donate via PayPal</a>
    </div>
    <p class="hl-support-donate__note">Use whichever platform feels right — every contribution goes directly toward the research.</p>
  </div>
</div>

{% include section-header.html label="Consulting & Advisory" accent="#58a6ff" %}

<div class="hl-prose-section">
  <div class="hl-prose-section__body">
    Available for threat model reviews, retainer advisory, and custom threat intelligence research. Work is scoped around your environment and threat profile — not generic frameworks. Engagements are kept selective to maintain quality and independence.<br><br>
    <a href="/consulting/">View consulting services →</a>
  </div>
</div>

{% include section-header.html label="Cost of Running This" accent="#f97316" %}

<div class="hl-prose-section">
  <div class="hl-prose-section__label">
    <div class="hl-prose-section__bar" style="background:#f97316;"></div>
    What Goes Into Each Report
  </div>
  <div class="hl-prose-section__body">
    Research time varies significantly by scope. Smaller reports represent <strong>multiple days</strong> of active analysis — static and dynamic malware analysis, infrastructure pivoting, detection rule development, and write-up. Larger investigations like the Arsenal-237 and Zero Trace series, which involve many samples and extensive hunting pivots, took <strong>a month or more</strong> to complete.<br><br>
    All analysis runs on a dedicated home lab server — self-built and self-maintained — running the VMs, sandboxes, and tooling required for safe malware analysis. That infrastructure has real hardware and ongoing operational costs that come entirely out of pocket.<br><br>
    None of this is paywalled because the research is more valuable when it reaches defenders directly. But it is not free to produce.
  </div>
</div>

{% include section-header.html label="Sponsorship Tiers" accent="#58a6ff" %}

<div class="hl-prose-section">
  <div class="hl-prose-section__body">
    Organizations can sponsor individual reports, a batch of reports, or on a monthly basis. Sponsors receive logo placement and a link on sponsored content. Sponsorship does not influence research conclusions or methodology — editorial independence is non-negotiable.
  </div>
</div>

{% assign tiers = site.data.sponsors.tiers %}
{% assign sponsors = site.data.sponsors.sponsors %}

<div class="hl-tier-grid">
  {% for tier in tiers %}
  <div class="hl-tier-card">
    <div class="hl-tier-card__name">{{ tier.name }}</div>
    <div class="hl-tier-card__desc">{{ tier.description }}</div>
    <div class="hl-tier-card__slots">
      {% assign tier_sponsors = sponsors | where: "tier", tier.id %}
      {% for sponsor in tier_sponsors %}
      <div class="hl-tier-card__sponsor">
        {% if sponsor.logo %}
        <img class="hl-tier-card__logo" src="{{ sponsor.logo }}" alt="{{ sponsor.name }}">
        {% endif %}
        {% if sponsor.url %}
        <a href="{{ sponsor.url }}" target="_blank" rel="noopener noreferrer" class="hl-tier-card__sponsor-name">{{ sponsor.name }}</a>
        {% else %}
        <span class="hl-tier-card__sponsor-name">{{ sponsor.name }}</span>
        {% endif %}
      </div>
      {% endfor %}
      {% assign filled = tier_sponsors | size %}
      {% assign remaining = tier.slots | minus: filled %}
      {% if remaining > 0 %}
      <div class="hl-tier-card__placeholder">Be the first to sponsor →</div>
      {% endif %}
    </div>
  </div>
  {% endfor %}
</div>

<p class="hl-support-contact">To discuss sponsorship, reach out at <a href="mailto:intel@the-hunters-ledger.com">intel@the-hunters-ledger.com</a>.</p>
