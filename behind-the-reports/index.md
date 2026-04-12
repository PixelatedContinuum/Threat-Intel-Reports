---
title: "Behind the Reports"
date: '2026-04-12'
layout: page
permalink: /behind-the-reports/
hide: true
---

<div class="hl-page-header" style="border-left-color: #f97316;">
  <div class="hl-page-header__label" style="color: #f97316;">Behind the Reports</div>
  <div class="hl-page-header__title">How the Intelligence Is Produced</div>
  <div class="hl-page-header__desc">From finding threats on adversary infrastructure to publishing finished intelligence — the systems, the design decisions, and why they were built.</div>
</div>

## The Pipeline

Every report published on this site follows the same path: something malicious is found on adversary infrastructure, analyzed in depth, and turned into a finished threat intelligence report with detection rules and machine-readable indicators ready for defenders to use.

That pipeline has two distinct parts. A **collection platform** that continuously discovers threats on known-malicious hosting infrastructure, and a **production workflow** that takes raw malware analysis and turns it into publication-ready intelligence. Both were built from scratch for the constraints of solo research, and both are documented here.

---

{% include section-header.html label="The Two Systems" accent="#f97316" %}

<div class="hl-nav-grid">
  <a href="{{ '/behind-the-reports/collection-platform/' | relative_url }}" class="hl-nav-tile">
    <div class="hl-nav-tile__title">How Threats Are Found →</div>
    <div class="hl-nav-tile__desc">A self-hosted collection platform that scans adversary infrastructure every night, discovers malware on open directories, and surfaces what's worth investigating through a triage dashboard.</div>
  </a>
  <a href="{{ '/behind-the-reports/ai-workflow/' | relative_url }}" class="hl-nav-tile">
    <div class="hl-nav-tile__title">How Reports Are Made →</div>
    <div class="hl-nav-tile__desc">A multi-agent AI workflow that takes raw malware analysis and produces structured, evidence-based threat intelligence — with skill frameworks, automated quality gates, and human checkpoints at every stage.</div>
  </a>
</div>

---

{% include section-header.html label="How They Connect" accent="#58a6ff" %}

<div class="hl-prose-section">
  <div class="hl-prose-section__body">
    The collection platform runs continuously. Every night it scans the IP space of 65 known bulletproof hosting providers — the infrastructure where malware is staged, served, and managed — across 28 ports. When it finds an open directory hosting suspicious files, it indexes everything, enriches files through VirusTotal, and surfaces the results in a triage dashboard sorted by threat signal.<br><br>
    That's where my judgment takes over. I review what the platform found, select the samples worth investigating, and run them through hands-on analysis — sandbox execution, static analysis, behavioral observation, network capture. The raw output of that analysis becomes the input to the AI agent workflow, which handles the structured parts of intelligence production: organizing findings, researching context, writing detection rules, producing the report, and scoring it against publication-quality standards.<br><br>
    The collection platform finds what's out there. The analysis and workflow turn it into something defenders can act on.
  </div>
</div>
