---
title: The Hunter's Ledger
layout: page
permalink: /
position: 1
---

<img src="{{ '/assets/images/logo.png' | relative_url }}" alt="{{ site.title }}" class="hl-masthead">

<div class="hl-hero">
  <div>
    <div class="hl-hero__title">Original Threat Intelligence Research</div>
    <div class="hl-hero__desc">Hands-on malware analysis turned into structured, evidence-based intelligence — technically deep enough to trust, clear enough to act on. Published by a solo analyst for the defender community.</div>
  </div>
</div>

{% include section-header.html label="Latest Reports" accent="#ff4444" %}

<div class="hl-grid">
{% include report-card.html title="Shadow RAT & XWorm Open Directory Campaign" date="Apr 2026" severity="high" tags="RAT,MaaS,C2,Multi-Family" url="/reports/shadow-xworm-opendirectory/" %}
{% include report-card.html title="Open Directory at 193.56.255.154 — XiebroC2 v3.1 Go Implant and Covenant C2 Toolkit" date="Apr 2026" severity="high" tags="C2,Multi-Family,Open Dir,Injection" url="/reports/open-directory-193-56-255-154-xiebroc2/" %}
</div>

<a href="{{ '/reports/' | relative_url }}" class="hl-view-all">View all reports →</a>

{% include section-header.html label="Mission" accent="#58a6ff" %}

<div class="hl-prose-section">
  <div class="hl-prose-section__body">
    Most threat intelligence fails defenders in one of two ways. It is either too shallow to be actionable — headlines dressed up as analysis — or technically rigorous but locked behind paywalls, stripped of indicators, and written for researchers rather than the people responding at 2am.<br><br>
    The Hunter's Ledger exists to fill that gap. Every report here is built from original research: real samples, real infrastructure, real detections. The goal is intelligence that a defender can open, read, and act on the same day — with IOCs ready to ingest, detection rules ready to deploy, and analysis deep enough to actually understand what a threat does and how to stop it.<br><br>
    All of it is free. Defenders should not have to pay to defend.
  </div>
</div>

<div class="hl-note">
  <div class="hl-note__label">Note</div>
  <div class="hl-note__body">This is not a collection of open source intel reports, IOCs, or TTPs. Findings are from original research, though they may overlap with known threats.</div>
</div>

{% include section-header.html label="Navigate" accent="#58a6ff" %}

<div class="hl-nav-grid">
  <a href="{{ '/reports/' | relative_url }}" class="hl-nav-tile">
    <div class="hl-nav-tile__title">Reports →</div>
    <div class="hl-nav-tile__desc">Malware analysis & reverse engineering notes</div>
  </a>
  <a href="{{ '/hunting-detections/' | relative_url }}" class="hl-nav-tile">
    <div class="hl-nav-tile__title">Hunting Detections →</div>
    <div class="hl-nav-tile__desc">Sigma, YARA, and Suricata rules</div>
  </a>
  <a href="{{ '/ioc-feeds/' | relative_url }}" class="hl-nav-tile">
    <div class="hl-nav-tile__title">IOC Feeds →</div>
    <div class="hl-nav-tile__desc">Indicators ready for your SIEM or EDR</div>
  </a>
  <a href="{{ '/behind-the-reports/' | relative_url }}" class="hl-nav-tile">
    <div class="hl-nav-tile__title">Behind the Reports →</div>
    <div class="hl-nav-tile__desc">How the intelligence is produced</div>
  </a>
</div>

{% include section-header.html label="Contributing" accent="#4ade80" %}

<div class="hl-prose-section">
  <div class="hl-prose-section__body">
    Have original research, detections, or IOCs you'd like to share with the community? Reach out at <a href="mailto:intel@the-hunters-ledger.com">intel@the-hunters-ledger.com</a> — findings can be posted on your behalf as a co-author or attributed however you prefer.
  </div>
</div>

{% include section-header.html label="About the Analyst" accent="#58a6ff" %}

<div><a href="{{ '/about-me/' | relative_url }}" class="hl-card">
  <div class="hl-card__inner">
    <div class="hl-card__bar" style="background:#58a6ff;"></div>
    <div>
      <div class="hl-card__title">About Me &amp; Contact</div>
      <div class="hl-prose-section__body" style="margin-top:6px;">Who I am, my background, and how to reach me directly.</div>
    </div>
  </div>
</a></div>

<div style="margin-top:9px;"><a href="{{ '/support/' | relative_url }}" class="hl-card">
  <div class="hl-card__inner">
    <div class="hl-card__bar" style="background:#4ade80;"></div>
    <div>
      <div class="hl-card__title">Support the Research</div>
      <div class="hl-prose-section__body" style="margin-top:6px;">Donate, sponsor a report, or inquire about consulting and advisory services.</div>
    </div>
  </div>
</a></div>

{% include section-header.html label="Resources" accent="#555555" %}

<div class="hl-prose-section">
  <div class="hl-prose-section__body">
    <a href="https://attack.mitre.org/">MITRE ATT&CK</a> &nbsp;·&nbsp;
    <a href="https://github.com/SigmaHQ/sigma">Sigma Rules</a> &nbsp;·&nbsp;
    <a href="https://virustotal.github.io/yara/">YARA</a>
  </div>
</div>
