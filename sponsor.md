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
  <p class="hl-panel__body" style="margin-bottom: 12px;">Every reader here is a working defender — the exact <strong>technical security audience vendors want in front of</strong>: the people who evaluate, recommend, deploy, and buy detection and tooling. The most active cohorts:</p>
  <ul class="hl-panel__body" style="margin: 0; padding-left: 18px; line-height: 1.7;">
    <li><strong>CISO and security leadership</strong> — taking risk framing, business impact, and vendor capability signals to inform tool evaluation.</li>
    <li><strong>Threat intelligence analysts</strong> — pulling attribution assessments, infrastructure pivots, actor TTPs, and IOCs.</li>
    <li><strong>Detection engineering teams</strong> — integrating ready-to-deploy YARA, Sigma, and Suricata rules with evidence backing.</li>
    <li><strong>SOC analysts (L1 through L3)</strong> — using behavioral indicators, kill chain reconstruction, and ATT&amp;CK mapping to build hunt content.</li>
  </ul>
</div>

<p style="color: var(--hl-text-secondary); font-size: 0.9em; line-height: 1.6; margin: 16px 2px 12px;">Reach here is about <strong>relevance, not raw volume</strong> — the audience is concentrated exactly where security buying decisions get made:</p>

<div class="hl-feat-grid">
  <div class="hl-feat" style="--fa: #58a6ff;">
    <div class="hl-feat__dot"></div>
    <div class="hl-feat__stat">10K+ views</div>
    <p class="hl-feat__desc">In a peak month and climbing — readers who come for working detection content, not general traffic.</p>
  </div>
  <div class="hl-feat" style="--fa: #4ade80;">
    <div class="hl-feat__dot"></div>
    <div class="hl-feat__stat">3,500+ on LinkedIn</div>
    <p class="hl-feat__desc">A following of detection engineers, threat-intel analysts, and security leaders — the roles that evaluate and buy.</p>
  </div>
  <div class="hl-feat" style="--fa: #b8902f;">
    <div class="hl-feat__dot"></div>
    <div class="hl-feat__stat">~400 views / day</div>
    <p class="hl-feat__desc">Daily LinkedIn profile reach, where every report is posted and discussed in the community.</p>
  </div>
</div>

<p style="color: var(--hl-text-secondary); font-size: 0.9em; line-height: 1.6; margin: 14px 2px 2px;">And the reach compounds beyond the site: every detection rule is submitted to the public <strong>Sigma and YARA rule repositories</strong> the community pulls from — so the research gets deployed in SOCs, labs, and hunt platforms used by defenders worldwide, well beyond direct readers.</p>

{% include section-header.html label="Sponsorship Tiers" accent="#b8902f" %}

<div class="hl-panel" style="--acc: #b8902f;">
  <span class="hl-panel__eyebrow">Flexible &amp; Custom</span>
  <p class="hl-panel__body">These are starting points, not limits — bundle reports in any size, mix new and catalog, sponsor monthly, or build something custom. Tell me what you're trying to achieve and I'll shape a package around it.</p>
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
  <p class="hl-panel__body" style="margin-bottom: 12px;">Optional extras to add more reach whenever you want it.</p>
  <ul class="hl-panel__body" style="margin: 0; padding-left: 18px; line-height: 1.7;">
    <li><strong>Newsletter mention</strong> — <span style="color: #b8902f; font-weight: 600;">$50</span> — One-off sponsored mention in a subscriber email send.</li>
    <li><strong>Extra LinkedIn or X post</strong> — <span style="color: #b8902f; font-weight: 600;">$50</span> — A single dedicated sponsored post about your capability or content.</li>
    <li><strong>Sponsor-suggested research topic</strong> — <span style="color: #b8902f; font-weight: 600;">$500+</span> — Choose a topic your organization needs intel about and I'll do the rest: original research and a published report on it. A new investigation, distinct from the topic alignment already included with a Report sponsorship; editorial independence preserved.</li>
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
