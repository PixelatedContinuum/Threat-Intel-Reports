---
title: The Hunter's Ledger
layout: page
permalink: /
position: 1
---

<div class="hl-hero">
  <div class="hl-hero__logo" style="background-image: url('{{ '/assets/images/header.png' | relative_url }}')"></div>
  <div>
    <div class="hl-hero__label">The Hunter's Ledger</div>
    <div class="hl-hero__title">Original Threat Intelligence Research</div>
    <div class="hl-hero__desc">Hands-on malware analysis turned into structured, evidence-based intelligence — technically deep enough to trust, clear enough to act on. Published by a solo analyst for the defender community.</div>
  </div>
</div>

{% include section-header.html label="Latest Reports" accent="#ff4444" %}

<div class="hl-grid">
{% include report-card.html title="ZeroTrace Multi-Family MaaS Operation — Open Directory Exposure at 74.0.42.25" date="Mar 2026" severity="high" tags="MaaS,C2,Open Dir" url="/reports/zerotrace-74-0-42-25-20260316/" %}
{% include report-card.html title="Open Directory Exposure: Sliver C2 Toolchain with ScareCrow Loader (45.94.31.220)" date="Mar 2026" severity="high" tags="C2,Loader" url="/reports/sliver-open-directory/" %}
</div>

<a href="{{ '/reports/' | relative_url }}" class="hl-view-all">View all reports →</a>

{% include section-header.html label="Mission" accent="#58a6ff" %}

<div class="hl-prose-section">
  <div class="hl-prose-section__body">
    <ul>
      <li>Share reproducible research and technical reports from original investigations and hunting</li>
      <li>Provide IOCs formatted for direct ingestion into threat hunting and detection engineering workflows</li>
      <li>Map findings to MITRE ATT&CK techniques to give defenders a common language</li>
      <li>Publish detection logic — Sigma, YARA, Suricata — written to public repository submission standards</li>
      <li>Publish findings while they're still relevant, not months after threats are already active</li>
    </ul>
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
    Contributions are welcome. Fork the repo and submit a PR with new reports, detections, or IOCs. Follow the <a href="{{ '/report-templates/' | relative_url }}">report format</a> for consistency. Or reach out directly — findings can be posted on your behalf as a co-author.
  </div>
</div>

{% include section-header.html label="Resources" accent="#555555" %}

<div class="hl-prose-section">
  <div class="hl-prose-section__body">
    <a href="https://attack.mitre.org/">MITRE ATT&CK</a> &nbsp;·&nbsp;
    <a href="https://github.com/SigmaHQ/sigma">Sigma Rules</a> &nbsp;·&nbsp;
    <a href="https://virustotal.github.io/yara/">YARA</a>
  </div>
</div>
