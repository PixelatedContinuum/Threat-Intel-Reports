---
title: Sponsorship
layout: page
permalink: /sponsor/
hide: true
---

<div class="hl-page-header" style="--ph-accent: #b8902f;">
  <div class="hl-page-header__label">Sponsor The Hunter's Ledger</div>
  <div class="hl-page-header__title">Reach Defenders Who Build, Buy, and Use Detection</div>
  <div class="hl-page-header__desc">An independent threat intelligence publication. Every report ships with working YARA, Sigma, and Suricata detections, validated IOC packages, and evidence-tied attribution. Sponsorship places your brand alongside the kind of technical research that working defenders actively consume and integrate.</div>
</div>

{% include section-header.html label="Why Sponsor" accent="#b8902f" %}

<div class="hl-feat-grid">
  <div class="hl-feat" style="--fa: #b8902f;">
    <div class="hl-feat__dot"></div>
    <div class="hl-feat__title">Reach buyers, not eyeballs</div>
    <p class="hl-feat__desc">Detection engineers, threat intelligence analysts, and security leadership doing daily work that informs procurement — not a CPM impressions buy.</p>
  </div>
  <div class="hl-feat" style="--fa: #58a6ff;">
    <div class="hl-feat__dot"></div>
    <div class="hl-feat__title">Credibility by association</div>
    <p class="hl-feat__desc">Your brand sits alongside reverse engineering, working detection rules, and evidence-tied attribution — presented as a supporter of the defender community, not an advertiser.</p>
  </div>
  <div class="hl-feat" style="--fa: #4ade80;">
    <div class="hl-feat__dot"></div>
    <div class="hl-feat__title">Permanent shelf life</div>
    <p class="hl-feat__desc">Reports are archived in perpetuity and keep surfacing in search, vendor evaluations, and threat hunts. Placements stay live for the life of every report.</p>
  </div>
</div>

{% include section-header.html label="Who Reads This" accent="#58a6ff" %}

<div class="hl-panel" style="--acc: #58a6ff;">
  <p class="hl-panel__body" style="margin-bottom: 12px;">The readership skews technical and operational. The most active reader cohorts are:</p>
  <ul class="hl-panel__body" style="margin: 0; padding-left: 18px; line-height: 1.7;">
    <li><strong>CISO and security leadership</strong> — taking risk framing, business impact, and vendor capability signals to inform tool evaluation.</li>
    <li><strong>Threat intelligence analysts</strong> — pulling attribution assessments, infrastructure pivots, actor TTPs, and IOCs.</li>
    <li><strong>Detection engineering teams</strong> — integrating ready-to-deploy YARA, Sigma, and Suricata rules with evidence backing.</li>
    <li><strong>SOC analysts (L1 through L3)</strong> — using behavioral indicators, kill chain reconstruction, and ATT&amp;CK mapping to build hunt content.</li>
  </ul>
</div>

{% include section-header.html label="Sponsorship Tiers" accent="#b8902f" %}

<div class="hl-panel" style="--acc: #b8902f;">
  <span class="hl-panel__eyebrow">Flexible Starting Points</span>
  <p class="hl-panel__body">Multi-Report bundles do not have to be six reports — bundles of any size (three, four, ten, whatever fits your campaign) are available. Custom packages combining elements across tiers can also be arranged. Reach out to discuss what matches your goals.</p>
</div>

{% assign tiers = site.data.sponsors.tiers %}
{% assign sponsors = site.data.sponsors.sponsors %}

<div class="hl-tier-grid hl-tier-grid--feature">
  {% for tier in tiers %}
  {% case tier.id %}
    {% when 'monthly' %}{% assign tacc = '#b8902f' %}{% assign tfeat = true %}
    {% when 'multi-report' %}{% assign tacc = '#58a6ff' %}{% assign tfeat = false %}
    {% when 'report' %}{% assign tacc = '#4ade80' %}{% assign tfeat = false %}
    {% else %}{% assign tacc = '#b8902f' %}{% assign tfeat = false %}
  {% endcase %}
  <div class="hl-tier-card{% if tfeat %} hl-tier-card--feature{% endif %}" style="--acc: {{ tacc }};">
    {% if tfeat %}<span class="hl-tier-card__eyebrow">Flagship</span>{% endif %}
    <div class="hl-tier-card__name">{{ tier.name }}</div>
    {% if tier.price %}
    <div class="hl-tier-card__price">{{ tier.price }}</div>
    {% if tier.price_note %}<div class="hl-tier-card__price-note">{{ tier.price_note }}</div>{% endif %}
    {% if tier.annual_price %}<div class="hl-tier-card__price-extra">or {{ tier.annual_price }} / year</div>{% endif %}
    {% if tier.catalog_price %}<div class="hl-tier-card__price-extra">or {{ tier.catalog_price }} {{ tier.catalog_price_note }}</div>{% endif %}
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

<div class="hl-panel hl-panel--featured" style="--acc: #b8902f;">
  <span class="hl-panel__eyebrow">Founding Offer — Each Tier, Offered Once</span>
  <p class="hl-panel__body">The first sponsor at each tier qualifies for a founding rate:</p>
  <ul class="hl-panel__body" style="margin: 8px 0 0; padding-left: 18px; line-height: 1.7;">
    <li><strong>Report Sponsor:</strong> $100 (standard $150)</li>
    <li><strong>Multi-Report Sponsor:</strong> $500 for the bundle (standard $750)</li>
    <li><strong>Monthly Sponsor:</strong> $300/month, no time cap — founding rate held for the full duration of your sponsorship (standard $500/month)</li>
  </ul>
  <p class="hl-cta-note">Each founding slot is offered once and retires when filled.</p>
</div>

{% include section-header.html label="Editorial Independence" accent="#58a6ff" %}

<div class="hl-panel" style="--acc: #58a6ff;">
  <p class="hl-panel__body" style="margin-bottom: 12px;">Sponsorship buys placement and brand association — not content control. These rules protect the credibility that makes the publication worth sponsoring in the first place.</p>
  <ul class="hl-panel__body" style="margin: 0; padding-left: 18px; line-height: 1.7;">
    <li>Sponsors do not review reports before publication.</li>
    <li>Sponsors do not influence findings, attribution claims, or recommendations.</li>
    <li>Sponsor-requested research topics are accepted as suggestions, not directed by sponsors.</li>
    <li>Sponsors are never named as analysts or contributors.</li>
    <li>Sponsored placement is always clearly disclosed — this is not native advertising.</li>
  </ul>
</div>

{% include section-header.html label="Optional Add-Ons" accent="#b8902f" %}

<div class="hl-panel" style="--acc: #b8902f;">
  <p class="hl-panel__body" style="margin-bottom: 12px;">Stack any of these on top of a sponsorship tier for added reach or customization.</p>
  <ul class="hl-panel__body" style="margin: 0; padding-left: 18px; line-height: 1.7;">
    <li><strong>Newsletter shoutout</strong> — <span style="color: #b8902f; font-weight: 600;">$75</span> — One-off sponsored mention in a subscriber email send.</li>
    <li><strong>LinkedIn or X post</strong> — <span style="color: #b8902f; font-weight: 600;">$100</span> — Single sponsored post about your capability or content.</li>
    <li><strong>Sponsor-requested research topic</strong> — <span style="color: #b8902f; font-weight: 600;">$500+</span> — Suggest a research direction; editorial independence preserved (see above).</li>
  </ul>
</div>

{% include section-header.html label="Pricing Sheet" accent="#b8902f" %}

<div class="hl-panel" style="--acc: #b8902f;">
  <p class="hl-panel__body" style="margin-bottom: 14px;">The full sponsorship pricing sheet is available as a printable PDF for circulation within your team or procurement process.</p>
  <a href="/assets/files/Hunters-Ledger-Sponsorship-Pricing.pdf" class="hl-cta hl-cta--ghost" style="--acc: #b8902f;" target="_blank" rel="noopener noreferrer">
    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
    Download Pricing Sheet (PDF)
  </a>
</div>

{% include section-header.html label="Get In Touch" accent="#b8902f" %}

<div class="hl-panel" style="--acc: #b8902f;">
  <div class="hl-panel__title">Ready to discuss sponsorship?</div>
  <p class="hl-panel__body" style="margin-bottom: 14px;">Reach out however works best for you — email, LinkedIn message, async chat, or a call. Happy to walk through the audience and recent reports, or just answer questions. Custom packages and bundles welcome.</p>
  <div class="hl-cta-row">
    <a class="hl-cta" style="--acc: #b8902f;" href="mailto:intel@the-hunters-ledger.com?subject=Sponsorship Inquiry">intel@the-hunters-ledger.com&nbsp;&rarr;</a>
    <a class="hl-cta hl-cta--ghost" style="--acc: #b8902f;" href="https://www.linkedin.com/in/josephrharrison" target="_blank" rel="noopener noreferrer">LinkedIn</a>
  </div>
</div>
