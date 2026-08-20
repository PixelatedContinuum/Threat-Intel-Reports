---
title: "Behind the Reports"
date: '2026-04-12'
layout: page
permalink: /behind-the-reports/
hide: true
---

<div class="hl-page-header" style="--ph-accent: #f97316;">
  <div class="hl-page-header__label">Behind the Reports</div>
  <div class="hl-page-header__title">How the Intelligence Is Produced</div>
  <div class="hl-page-header__desc">The whole path an investigation takes, from a scanner finding an open directory to a detection rule running in somebody else's SOC.</div>
</div>

## Start to Finish

Every report on this site took the same route. A scanner found something malicious sitting on adversary infrastructure, I decided it was worth the time, I took it apart, and it came out the other end as a report with detection rules and machine-readable indicators that a defender can pick up and use the same day.

This page walks that route end to end at a high level. Each step links to the page that covers it properly, so you can read the whole shape first and then go deep on whatever you actually came for.

Two things are worth knowing before the walkthrough. I do this alone, so every design decision below is shaped by that constraint rather than by what a team would build. And the parts that need judgment stay with me: what is worth investigating, what the evidence actually shows, and whether a finished report is good enough to publish.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/behind-the-reports/investigation-flow.svg" | relative_url }}" alt="Vertical flow diagram of seven steps, grouped into three labelled bands down the left edge. Step 1, Find and Choose, contains: 1 Scan, every night the announced IP space of 65 bulletproof-hosting networks across 28 ports, with confirmed open directories crawled and every file checked; 2 Triage, findings rank by threat signal in a dashboard and files no antivirus engine knows about yet rise to the top alongside anything exposing credentials; 3 Choose, a recon pass built to say no, settled by what intelligence this would produce and who could act on it, with most candidates rejected. Step 2, Analyze and Draft, contains: 4 Analyze, detonation in an isolated lab plus static examination and reverse engineering, the part that does not get automated; 5 Draft, eight specialist agents turn the raw analysis into a report, an IOC feed and detection rules, with two human checkpoints. Step 3, Verify and Ship, contains: 6 Verify, every rule compiled by the real engine, with checks reporting PASS, FAIL or NOT CHECKED and the third never folded into the first; 7 Ship, the site, the public feeds, STIX bundles for OpenCTI and MISP, upstream rule repositories, a live detection stack and the CERTs who need it first. A legend maps blue to automated steps, gold to the steps decided by my own judgment, and green to verified and shipped.">
  <figcaption><em>Figure 1: The seven steps an investigation passes through. Blue is automated, gold is where my judgment decides the outcome, green is verified and out the door.</em></figcaption>
</figure>

---

{% include section-header.html label="Step 1 of 3: Find and Choose" accent="#b8902f" %}

It starts with a scan. A self-hosted collection platform called Vantage runs every night against the announced IP space of 65 bulletproof-hosting networks, the corner of the market where malware actually gets staged and served, across 28 ports. Anything that answers gets probed for an open directory, and a confirmed one gets crawled in full.

Then everything gets triaged. Every file is classified and checked for reputation, and the results rank by threat signal in a dashboard. What rises to the top is the material worth a human look: payloads no antivirus engine has catalogued yet, files evading nearly every engine, and exposed credentials.

Then I choose, and this is the first decision that is genuinely mine. It is also the most consequential one in the whole operation, because the platform surfaces far more than I could ever investigate. A recon pass sorts the candidates with a single question, which is what intelligence this would produce and who could actually act on it. Most candidates get rejected, and the rejections are written down so I do not chase the same dead end twice.

<div class="hl-note" style="margin-top: 1.5rem;">
  <div class="hl-note__body">The detail, including what the platform scans and why, and how the recon pass decides: <a href="{{ '/behind-the-reports/collection-platform/' | relative_url }}">Finding the Threat, Choosing the Target →</a></div>
</div>

---

{% include section-header.html label="Step 2 of 3: Analyze and Draft" accent="#b8902f" %}

A chosen candidate stops being a platform problem and becomes an investigation. I pull the files into an isolated lab and take them apart by hand: detonation, static examination, reverse engineering, watching what the sample does to a machine and to the network. Nothing here is automated, and this is where the actual findings come from.

What that produces is scattered and hard to read, so it goes into a multi-agent workflow. Eight specialist agents each own one part of the job, working against written standards rather than improvising, and between them they produce the report, the machine-readable indicator feed, and the detection rules.

I stay in the loop at two points. I read the draft at the first checkpoint and can redirect it, and I sign off the finished files at the second. Approving them means the work is good, not that it goes live.

<div class="hl-note" style="margin-top: 1.5rem;">
  <div class="hl-note__body">The detail, including who does what and the standards they work against: <a href="{{ '/behind-the-reports/ai-workflow/' | relative_url }}">Turning the Analysis Into a Report →</a></div>
</div>

---

{% include section-header.html label="Step 3 of 3: Verify and Ship" accent="#b8902f" %}

Nothing publishes because an agent said it went well. Every YARA rule is compiled by the real compiler, every Sigma rule runs through SigmaHQ's own validator, and every Suricata signature is parsed by a live Suricata engine. Those checks report one of three outcomes rather than two, and the third, NOT CHECKED, is never quietly folded into a pass.

What survives goes out in every form somebody might want it. The report and its companion files publish to the site, indicators join the public feeds, the campaign becomes a STIX bundle for OpenCTI and MISP, durable rules go upstream to the repositories the community pulls from, and everything lands in my own detection stack so I find out when one of my rules is wrong.

Where a finding is somebody's live incident rather than a publication, it goes to them first. That is why publishing defaults to an unlisted preview: the report has to be readable and shareable before it is public, because the people who most need it are usually not the audience the front page is for.

<div class="hl-note" style="margin-top: 1.5rem;">
  <div class="hl-note__body">The detail, including why each gate exists and every channel the work goes out through: <a href="{{ '/behind-the-reports/gates-and-distribution/' | relative_url }}">Verifying and Shipping It →</a></div>
</div>

---

{% include section-header.html label="The Three Deep Dives" accent="#f97316" %}

<div class="hl-nav-grid">
  <a href="{{ '/behind-the-reports/collection-platform/' | relative_url }}" class="hl-nav-tile">
    <div class="hl-nav-tile__title">1. Find and Choose →</div>
    <div class="hl-nav-tile__desc">The collection platform: what it scans and why, how it classifies what it finds, and the recon pass that decides which candidate is worth an investigation.</div>
  </a>
  <a href="{{ '/behind-the-reports/ai-workflow/' | relative_url }}" class="hl-nav-tile">
    <div class="hl-nav-tile__title">2. Analyze and Draft →</div>
    <div class="hl-nav-tile__desc">The agent workflow: who does what, the written standards each agent works against, the automation underneath, and where the human checkpoints sit.</div>
  </a>
  <a href="{{ '/behind-the-reports/gates-and-distribution/' | relative_url }}" class="hl-nav-tile">
    <div class="hl-nav-tile__title">3. Verify and Ship →</div>
    <div class="hl-nav-tile__desc">The gates that stop the pipeline reporting success it has not earned, and every channel the finished intelligence goes out through.</div>
  </a>
</div>
