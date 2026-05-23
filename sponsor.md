---
title: Sponsorship
layout: page
permalink: /sponsor/
hide: true
---

<div class="hl-page-header" style="border-left-color: #b8902f;">
  <div class="hl-page-header__label" style="color: #b8902f;">Sponsor The Hunter's Ledger</div>
  <div class="hl-page-header__title">Reach Defenders Who Build, Buy, and Use Detection</div>
  <div class="hl-page-header__desc">An independent threat intelligence publication. Every report ships with working YARA, Sigma, and Suricata detections, validated IOC packages, and evidence-tied attribution. Sponsorship places your brand alongside the kind of technical research that working defenders actively consume and integrate.</div>
</div>

{% include section-header.html label="Why Sponsor" accent="#b8902f" %}

<div class="hl-prose-section">
  <div class="hl-prose-section__body">
    Sponsorship here is a placement next to working detection content used by your buyers — not a CPM impressions buy. Three reasons sponsors choose The Hunter's Ledger over mass-market security media:<br><br>
    <strong>Reach buyers, not eyeballs.</strong> Detection engineers, threat intelligence analysts, and security leadership are hard to reach through broad publications. Every reader here is a defender doing daily work that informs procurement.<br><br>
    <strong>Credibility by association.</strong> Your brand sits alongside reverse engineering, working detection rules, and evidence-tied attribution. Sponsors are presented as supporters of the defender community — not advertisers.<br><br>
    <strong>Permanent shelf life.</strong> Reports are archived in perpetuity and continue surfacing in search results, vendor evaluations, and threat hunts. Sponsorship placements remain live for the life of every report.
  </div>
</div>

{% include section-header.html label="Who Reads This" accent="#58a6ff" %}

<div class="hl-prose-section">
  <div class="hl-prose-section__body">
    The readership skews technical and operational. The most active reader cohorts are:
    <ul style="margin-top: 10px;">
      <li><strong>CISO and security leadership</strong> — taking risk framing, business impact, and vendor capability signals to inform tool evaluation.</li>
      <li><strong>Threat intelligence analysts</strong> — pulling attribution assessments, infrastructure pivots, actor TTPs, and IOCs.</li>
      <li><strong>Detection engineering teams</strong> — integrating ready-to-deploy YARA, Sigma, and Suricata rules with evidence backing.</li>
      <li><strong>SOC analysts (L1 through L3)</strong> — using behavioral indicators, kill chain reconstruction, and ATT&amp;CK mapping to build hunt content.</li>
    </ul>
  </div>
</div>

{% include section-header.html label="Sponsorship Tiers" accent="#b8902f" %}

<div class="hl-sponsor-callout" style="margin-top: 0;">
  <div class="hl-sponsor-callout__title">Tiers Are Flexible Starting Points</div>
  <div class="hl-sponsor-callout__body">
    Multi-Report bundles do not have to be six reports — bundles of any size (three, four, ten, whatever fits your campaign) are available. Custom packages combining elements across tiers can also be arranged. Reach out to discuss what matches your goals.
  </div>
</div>

{% assign tiers = site.data.sponsors.tiers %}
{% assign sponsors = site.data.sponsors.sponsors %}

<div class="hl-tier-grid hl-tier-grid--feature">
  {% for tier in tiers %}
  <div class="hl-tier-card">
    <div class="hl-tier-card__name">{{ tier.name }}</div>
    {% if tier.price %}
    <div class="hl-tier-card__price">{{ tier.price }}{% if tier.price_note %}<span class="hl-tier-card__price-note">{{ tier.price_note }}</span>{% endif %}</div>
    {% if tier.annual_price %}<div class="hl-tier-card__price-extra">or {{ tier.annual_price }} annual</div>{% endif %}
    {% endif %}
    <div class="hl-tier-card__desc">{{ tier.description }}</div>
    {% if tier.benefits %}
    <ul class="hl-tier-card__benefits">
      {% for b in tier.benefits %}
      <li>{{ b }}</li>
      {% endfor %}
    </ul>
    {% endif %}
    <div class="hl-tier-card__slots">
      {% assign tier_sponsors = sponsors | where: "tier", tier.id %}
      {% for sponsor in tier_sponsors %}
      <div class="hl-tier-card__sponsor">
        {% if sponsor.logo %}<img class="hl-tier-card__logo" src="{{ sponsor.logo }}" alt="{{ sponsor.name }}">{% endif %}
        {% if sponsor.url %}<a href="{{ sponsor.url }}" target="_blank" rel="noopener noreferrer" class="hl-tier-card__sponsor-name">{{ sponsor.name }}</a>{% else %}<span class="hl-tier-card__sponsor-name">{{ sponsor.name }}</span>{% endif %}
      </div>
      {% endfor %}
      {% assign filled = tier_sponsors | size %}
      {% assign remaining = tier.slots | minus: filled %}
      {% if remaining > 0 %}<div class="hl-tier-card__placeholder">{% if filled == 0 %}Be the first sponsor →{% else %}{{ remaining }} slot{% if remaining > 1 %}s{% endif %} open →{% endif %}</div>{% endif %}
    </div>
    {% if tier.best_fit %}
    <div class="hl-tier-card__best-fit"><strong>Best fit:</strong> {{ tier.best_fit }}</div>
    {% endif %}
  </div>
  {% endfor %}
</div>

<div class="hl-sponsor-callout">
  <div class="hl-sponsor-callout__title">Founding Sponsor Offer — Each Tier, Offered Once</div>
  <div class="hl-sponsor-callout__body">
    The first sponsor at each tier qualifies for a founding rate:
    <ul style="margin: 8px 0 0 0; padding-left: 18px;">
      <li><strong>Report Sponsor:</strong> $100 (standard $150)</li>
      <li><strong>Multi-Report Sponsor:</strong> $500 for the bundle (standard $750)</li>
      <li><strong>Monthly Sponsor:</strong> $300/month, no time cap — founding rate held for the full duration of your sponsorship (standard $500/month)</li>
    </ul>
    <div style="margin-top: 8px; opacity: 0.85;">Each founding slot is offered once and retires when filled.</div>
  </div>
</div>

{% include section-header.html label="Editorial Independence" accent="#58a6ff" %}

<div class="hl-prose-section">
  <div class="hl-prose-section__body">
    Sponsorship buys placement and brand association — not content control. These rules protect the credibility that makes the publication worth sponsoring in the first place.
    <ul style="margin-top: 10px;">
      <li>Sponsors do not review reports before publication.</li>
      <li>Sponsors do not influence findings, attribution claims, or recommendations.</li>
      <li>Sponsor-requested research topics are accepted as suggestions, not directed by sponsors.</li>
      <li>Sponsors are never named as analysts or contributors.</li>
      <li>Sponsored placement is always clearly disclosed — this is not native advertising.</li>
    </ul>
  </div>
</div>

{% include section-header.html label="Pricing Sheet" accent="#b8902f" %}

<div class="hl-prose-section">
  <div class="hl-prose-section__body">
    The full sponsorship pricing sheet is available as a printable PDF for circulation within your team or procurement process.<br><br>
    <a href="/assets/files/Hunters-Ledger-Sponsorship-Pricing.pdf" class="hl-sponsor-download" target="_blank" rel="noopener noreferrer">
      <span class="hl-sponsor-download__icon"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg></span>
      Download Pricing Sheet (PDF)
    </a>
  </div>
</div>

{% include section-header.html label="Get In Touch" accent="#b8902f" %}

<div class="hl-sponsor-cta">
  <div class="hl-sponsor-cta__title">Ready to discuss sponsorship?</div>
  <div class="hl-sponsor-cta__contact">
    <div class="hl-sponsor-cta__contact-row">
      <span class="hl-sponsor-cta__contact-label">Email</span>
      <a href="mailto:intel@the-hunters-ledger.com">intel@the-hunters-ledger.com</a>
    </div>
    <div class="hl-sponsor-cta__contact-row">
      <span class="hl-sponsor-cta__contact-label">LinkedIn</span>
      <a href="https://www.linkedin.com/in/josephrharrison" target="_blank" rel="noopener noreferrer">linkedin.com/in/josephrharrison</a>
    </div>
  </div>
  <p class="hl-sponsor-cta__note">Initial conversations are a 15-minute call to walk through the audience, review recent reports together, and identify the tier that best matches your goals. Custom packages and bundles available — reach out to discuss.</p>
</div>
