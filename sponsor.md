---
title: Sponsorship
description: "Sponsorship placements on an independent threat intelligence publication read by detection engineers, analysts and security leadership."
layout: page
permalink: /sponsor/
thumbnail: /assets/images/cards/sponsor.png
hide: true
---

<div class="hl-page-header" style="--ph-accent: #f59e0b;">
  <div class="hl-page-header__label">Sponsor The Hunter's Ledger</div>
  <div class="hl-page-header__title">Reach Defenders Who Build, Buy, and Use Detection</div>
  <div class="hl-page-header__desc">An independent threat intelligence publication. Every report ships with working YARA, Sigma, and Suricata detections, validated IOC packages, and evidence-tied attribution. Sponsorship places your brand alongside the kind of technical research that working defenders actively consume and integrate.</div>
</div>

{% include section-header.html label="Why Sponsor" accent="#b8902f" %}

<div class="hl-feat-grid">
  <div class="hl-feat" style="--fa: #b8902f;">
    <div class="hl-feat__dot"></div>
    <div class="hl-feat__title">Reach buyers, not eyeballs</div>
    <p class="hl-feat__desc">Detection engineers, threat intelligence analysts, and security leadership doing daily work that informs procurement, not a CPM impressions buy.</p>
  </div>
  <div class="hl-feat" style="--fa: #58a6ff;">
    <div class="hl-feat__dot"></div>
    <div class="hl-feat__title">Credibility by association</div>
    <p class="hl-feat__desc">Your brand sits alongside reverse engineering, working detection rules, and evidence-tied attribution, presented as a supporter of the defender community, not an advertiser.</p>
  </div>
  <div class="hl-feat" style="--fa: #4ade80;">
    <div class="hl-feat__dot"></div>
    <div class="hl-feat__title">Permanent shelf life</div>
    <p class="hl-feat__desc">Reports are archived in perpetuity and keep surfacing in search, vendor evaluations, and threat hunts. Placements stay live for the life of every report.</p>
  </div>
</div>

{% include section-header.html label="Who Reads This" accent="#58a6ff" %}

<div class="hl-panel" style="--acc: #58a6ff;">
  <p class="hl-panel__body" style="margin-bottom: 12px;">Every reader here is a working defender, the exact <strong>technical security audience vendors want in front of</strong>: the people who evaluate, recommend, deploy, and buy detection and tooling. The most active cohorts:</p>
  <ul class="hl-panel__body" style="margin: 0; padding-left: 18px; line-height: 1.7;">
    <li><strong>CISO and security leadership</strong>, taking risk framing, business impact, and vendor capability signals to inform tool evaluation.</li>
    <li><strong>Threat intelligence analysts</strong>, pulling attribution assessments, infrastructure pivots, actor TTPs, and IOCs.</li>
    <li><strong>Detection engineering teams</strong>, integrating ready-to-deploy YARA, Sigma, and Suricata rules with evidence backing.</li>
    <li><strong>SOC analysts (L1 through L3)</strong>, using behavioral indicators, kill chain reconstruction, and ATT&amp;CK mapping to build hunt content.</li>
  </ul>
</div>

<p style="color: var(--hl-text-secondary); font-size: 0.9em; line-height: 1.6; margin: 16px 2px 12px;">Reach here is about <strong>relevance, not raw volume</strong>. The audience is concentrated exactly where security buying decisions get made:</p>

<div class="hl-feat-grid">
  <div class="hl-feat" style="--fa: #58a6ff;">
    <div class="hl-feat__dot"></div>
    <div class="hl-feat__stat">10K+ views</div>
    <p class="hl-feat__desc">In a peak month and climbing, readers who come for working detection content, not general traffic.</p>
  </div>
  <div class="hl-feat" style="--fa: #4ade80;">
    <div class="hl-feat__dot"></div>
    <div class="hl-feat__stat">3,500+ on LinkedIn</div>
    <p class="hl-feat__desc">A following of detection engineers, threat-intel analysts, and security leaders, the roles that evaluate and buy.</p>
  </div>
  <div class="hl-feat" style="--fa: #b8902f;">
    <div class="hl-feat__dot"></div>
    <div class="hl-feat__stat">~400 views / day</div>
    <p class="hl-feat__desc">Daily LinkedIn profile reach, where every report is posted and discussed in the community.</p>
  </div>
</div>

<p style="color: var(--hl-text-secondary); font-size: 0.9em; line-height: 1.6; margin: 14px 2px 2px;">And the reach compounds beyond the site. Every campaign also ships as <strong>machine-readable intelligence</strong>, a consolidated Suricata feed currently carrying 112 rules across 35 campaigns, 58 IOC feeds in JSON, and 41 STIX bundles built for OpenCTI and MISP. All of it is public and machine-readable, so it can go straight into a detection stack without anyone loading a page here. That is reach that does not depend on a visit to the site.</p>

{% include section-header.html label="Sponsorship Tiers" accent="#b8902f" %}

<div class="hl-panel" style="--acc: #b8902f;">
  <span class="hl-panel__eyebrow">Flexible &amp; Custom</span>
  <p class="hl-panel__body">These are starting points, not limits. Bundle reports in any size, mix new and catalog, sponsor monthly, or build something custom. Tell me what you're trying to achieve and I'll shape a package around it.</p>
</div>

{% assign tiers = site.data.sponsors.tiers %}
{% assign sponsors = site.data.sponsors.sponsors %}

<div class="hl-tier-grid hl-tier-grid--feature">
  {% for tier in tiers %}
  {% case tier.id %}
    {% when 'monthly' %}{% assign tacc = '#b8902f' %}{% assign tfeat = true %}
    {% when 'report' %}{% assign tacc = '#4ade80' %}{% assign tfeat = false %}
    {% else %}{% assign tacc = '#b8902f' %}{% assign tfeat = false %}
  {% endcase %}
  <div class="hl-tier-card{% if tfeat %} hl-tier-card--feature{% endif %}" style="--acc: {{ tacc }};">
    {% if tfeat %}<span class="hl-tier-card__eyebrow">Flagship · Best Value</span>{% endif %}
    <div class="hl-tier-card__name">{{ tier.name }}</div>
    {% if tier.price %}
    <div class="hl-tier-card__price">{{ tier.price }}</div>
    {% if tier.price_note %}<div class="hl-tier-card__price-note">{{ tier.price_note }}</div>{% endif %}
    {% if tier.intro_price %}<div class="hl-tier-card__price-extra" style="color: var(--acc); font-weight: 600;">{{ tier.intro_price }}</div>{% endif %}
    {% if tier.catalog_price %}<div class="hl-tier-card__price-extra">or {{ tier.catalog_price }} {{ tier.catalog_price_note }}</div>{% endif %}
    {% if tier.annual_price %}
    <div class="hl-tier-card__annual">
      <span class="hl-tier-card__annual-label">Or pay annually</span>
      <span class="hl-tier-card__annual-price">{{ tier.annual_price }}{% if tier.annual_note %} <span class="hl-tier-card__annual-unit">{{ tier.annual_note }}</span>{% endif %}</span>
      {% if tier.annual_saving %}<span class="hl-tier-card__annual-saving">{{ tier.annual_saving }}</span>{% endif %}
    </div>
    {% endif %}
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
      {% if filled > 0 and remaining > 0 %}<div class="hl-tier-card__placeholder">{{ remaining }} slot{% if remaining > 1 %}s{% endif %} open →</div>{% endif %}
    </div>
    {% if tier.billing_note %}
    <div class="hl-tier-card__billing">{{ tier.billing_note }}</div>
    {% endif %}
    {% if tier.best_fit %}
    <div class="hl-tier-card__best-fit"><strong>Best fit:</strong> {{ tier.best_fit }}</div>
    {% endif %}
  </div>
  {% endfor %}
</div>

{% include section-header.html label="Monthly or Annual" accent="#4ade80" %}

<div class="hl-panel" style="--acc: #4ade80;">
  <p class="hl-panel__body" style="margin-bottom: 14px;">Both work, and I genuinely do not mind which you pick. Take whichever suits your budget cycle. Annual prepay is cheaper because it is worth something to me to plan a year ahead, so the saving is passed straight back to you rather than held as a negotiating chip.</p>

  <table>
    <colgroup>
      <col style="width: 22%;">
      <col style="width: 39%;">
      <col style="width: 39%;">
    </colgroup>
    <thead>
      <tr><th>How you pay</th><th>Monthly Sponsor</th><th>Report Sponsor</th></tr>
    </thead>
    <tbody>
      <tr><td>As you go</td><td>$500 per month</td><td>$150 per new report, $100 from the catalog (any age, bundled or not)</td></tr>
      <tr><td>Bundled</td><td>Not applicable</td><td>3 new reports $335 (26% off), 6 for $630 (30% off)</td></tr>
      <tr><td><strong>Annual</strong></td><td><strong>$5,000 per year.</strong> Two months free, a $1,000 saving, 17% off</td><td><strong>$1,170 for 12 new reports</strong> across the year, a $630 saving, 35% off</td></tr>
      <tr><td>First time</td><td>First 3 months at $300 per month, or a first full year at $4,400</td><td>First new report $100</td></tr>
    </tbody>
  </table>

  <p class="hl-panel__body" style="margin-top: 14px; margin-bottom: 0;">Two things worth knowing before you choose. An annual commitment <strong>locks your rate for the full term</strong>, so a published price rise cannot reach you mid term, and the lock holds through renewal. Keep sponsoring without a break and you keep the rate you started at, whatever the list price does later. Monthly stays flexible and can be stopped at the end of any billing month. Either way the placements, the benefits, and the editorial independence below are identical. If you are new and want to go annual straight away, you do not lose the intro rate: the first year is $4,400, which is the same discount the three intro months would have given you, applied to the annual price. The one benefit that does depend on how you pay is the threat question, which opens immediately on an annual prepay and at twelve months on monthly, because it is a real piece of work and a full year is what earns it.</p>
</div>

{% include section-header.html label="Editorial Independence" accent="#58a6ff" %}

<div class="hl-panel" style="--acc: #58a6ff;">
  <p class="hl-panel__body" style="margin-bottom: 12px;">Sponsorship buys placement and brand association, not content control. These rules protect the credibility that makes the publication worth sponsoring in the first place.</p>
  <ul class="hl-panel__body" style="margin: 0; padding-left: 18px; line-height: 1.7;">
    <li>Sponsors do not review reports before publication.</li>
    <li>Sponsors do not influence findings, attribution claims, or recommendations.</li>
    <li>Sponsors can name a subject, whether as the threat question included with a Monthly sponsorship or as a suggestion for what gets published next. What the evidence then says is never negotiable.</li>
    <li>Sponsors are never named as analysts or contributors.</li>
    <li>Sponsored placement is always clearly disclosed. This is not native advertising.</li>
  </ul>
</div>

{% include section-header.html label="Optional Add-Ons" accent="#b8902f" %}

<div class="hl-panel" style="--acc: #b8902f;">
  <p class="hl-panel__body" style="margin-bottom: 12px;">Optional extras to add more reach whenever you want it.</p>
  <ul class="hl-panel__body" style="margin: 0; padding-left: 18px; line-height: 1.7;">
    <li><strong>Newsletter mention</strong>, <span style="color: #b8902f; font-weight: 600;">$50</span>. One-off sponsored mention in a subscriber email send.</li>
    <li><strong>Extra LinkedIn or X post</strong>, <span style="color: #b8902f; font-weight: 600;">$50</span>. A single dedicated sponsored post about your capability or content.</li>
  </ul>
</div>

{% include section-header.html label="Commissioned Research" accent="#c084fc" %}

<div class="hl-panel" style="--acc: #c084fc;">
  <p class="hl-panel__body" style="margin-bottom: 12px;">Name a threat your organization needs intelligence on and I will go and get it, with original investigation, full technical analysis, working detections and a published report at the end, held to exactly the same evidence standards and the same editorial independence as everything else here. This is a new investigation commissioned by you. It is a different thing from picking which existing report you sponsor, and a much deeper one than the single threat question included with a Monthly sponsorship.</p>
  <p class="hl-panel__body" style="margin-bottom: 0;">Priced on scope, because scope varies enormously. A single host or one open directory is a very different piece of work from a fifty-address infrastructure cluster with a malware family sitting behind it. Tell me what you want to know and I will come back with a defined scope and a fixed price before any work starts, so there are no surprises in either direction.</p>
</div>

{% include section-header.html label="Pricing Sheet" accent="#b8902f" %}

<div class="hl-panel" style="--acc: #b8902f;">
  <p class="hl-panel__body" style="margin-bottom: 14px;">The full sponsorship pricing sheet is available as a printable PDF for circulation within your team or procurement process.</p>
  <a href="/assets/files/Hunters-Ledger-Sponsorship-Pricing.pdf?v=20260907b" class="hl-cta hl-cta--ghost" style="--acc: #b8902f;" target="_blank" rel="noopener noreferrer">
    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
    Download Pricing Sheet (PDF)
  </a>
</div>

{% include section-header.html label="Get In Touch" accent="#b8902f" %}

<div class="hl-panel" style="--acc: #b8902f;">
  <div class="hl-panel__title">Ready to discuss sponsorship?</div>
  <p class="hl-panel__body" style="margin-bottom: 14px;">Reach out however works best for you: email, LinkedIn message, async chat, or a call. Happy to walk through the audience and recent reports, or just answer questions. Custom packages and bundles welcome.</p>
  <div class="hl-cta-row">
    <a class="hl-cta" style="--acc: #b8902f;" href="mailto:intel@the-hunters-ledger.com?subject=Sponsorship Inquiry">intel@the-hunters-ledger.com&nbsp;&rarr;</a>
    <a class="hl-cta hl-cta--ghost" style="--acc: #b8902f;" href="https://www.linkedin.com/in/josephrharrison" target="_blank" rel="noopener noreferrer">LinkedIn</a>
  </div>
</div>
