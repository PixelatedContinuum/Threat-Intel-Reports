---
title: Subscribe
layout: page
permalink: /subscribe/
thumbnail: /assets/images/cards/subscribe.png
position: 5
---

<div class="hl-page-header" style="background: linear-gradient(135deg, #0d1520 0%, #0d1117 60%, #111111 100%); --ph-accent: #3b82f6;">
  <div class="hl-page-header__label">Stay Informed</div>
  <div class="hl-page-header__title">Subscribe to The Hunter's Ledger</div>
  <div class="hl-page-header__desc">New threat intelligence reports, detection rules, and IOC feeds — delivered the moment they publish. Pick whatever fits how you work. No marketing, no noise.</div>
</div>

{% include section-header.html label="Delivery Options" accent="#58a6ff" %}

<div class="hl-panel" style="--acc: #4ade80;">
  <div class="hl-panel__head">
    <div class="hl-panel__chip">&#9656;</div>
    <div>
      <div class="hl-panel__title">RSS / Atom Feed</div>
      <p class="hl-panel__desc">Add the feed to any reader — Feedly, Inoreader, NetNewsWire. New reports appear the moment they publish.</p>
    </div>
  </div>
  <div class="hl-feed-url" style="--acc: #4ade80;">
    <span class="hl-feed-url__label">Feed</span>
    <span class="hl-feed-url__val">https://the-hunters-ledger.com/feed.xml</span>
    <button class="hl-feed-url__copy" type="button" data-copy="https://the-hunters-ledger.com/feed.xml">COPY</button>
  </div>
</div>

<div class="hl-panel" style="--acc: #58a6ff;">
  <div class="hl-panel__head">
    <div class="hl-panel__chip">&#9993;</div>
    <div>
      <div class="hl-panel__title">Email Newsletter</div>
      <p class="hl-panel__desc">A direct email when a new report drops. No marketing, no noise — just new intelligence in your inbox.</p>
    </div>
  </div>
  <div style="margin-top: 4px;">
    <script async src="https://eocampaign1.com/form/d7e87548-297e-11f1-a6ab-1d8405c03c10.js" data-form="d7e87548-297e-11f1-a6ab-1d8405c03c10"></script>
  </div>
</div>

<div class="hl-panel" style="--acc: #58a6ff;">
  <div class="hl-panel__head">
    <div class="hl-panel__chip"><svg viewBox="0 0 24 24" width="22" height="22" fill="currentColor" aria-hidden="true"><path d="M20.45 20.45h-3.56v-5.57c0-1.33-.03-3.04-1.85-3.04-1.86 0-2.14 1.45-2.14 2.94v5.67H9.34V9h3.42v1.56h.05c.47-.9 1.64-1.85 3.37-1.85 3.6 0 4.27 2.37 4.27 5.46v6.28zM5.34 7.43a2.07 2.07 0 1 1 0-4.14 2.07 2.07 0 0 1 0 4.14zM7.12 20.45H3.56V9h3.56v11.45zM22.22 0H1.77C.79 0 0 .77 0 1.73v20.54C0 23.23.79 24 1.77 24h20.45c.98 0 1.78-.77 1.78-1.74V1.73C24 .77 23.2 0 22.22 0z"/></svg></div>
    <div>
      <div class="hl-panel__title">Connect on LinkedIn</div>
      <p class="hl-panel__desc">Follow or connect with <strong>Joseph Harrison</strong> — reports are posted and discussed there, alongside shorter threat-intelligence notes between publications. Open to connecting with defenders, researchers, and security teams.</p>
    </div>
  </div>
  <div class="hl-feed-url" style="--acc: #58a6ff;">
    <span class="hl-feed-url__label">Profile</span>
    <span class="hl-feed-url__val">linkedin.com/in/josephrharrison</span>
    <a class="hl-cta hl-cta--ghost" style="--acc: #58a6ff;" href="https://www.linkedin.com/in/josephrharrison/" target="_blank" rel="noopener">Open&nbsp;&rarr;</a>
  </div>
</div>

<div class="hl-panel" style="--acc: #8b949e;">
  <div class="hl-panel__head">
    <div class="hl-panel__chip">&#120143;</div>
    <div>
      <div class="hl-panel__title">Follow on X</div>
      <p class="hl-panel__desc">Follow <strong>@Hunters_Ledger</strong> for report announcements and shorter-form threat intelligence notes between full publications.</p>
    </div>
  </div>
  <div class="hl-feed-url" style="--acc: #58a6ff;">
    <span class="hl-feed-url__label">Profile</span>
    <span class="hl-feed-url__val">x.com/Hunters_Ledger</span>
    <a class="hl-cta hl-cta--ghost" style="--acc: #58a6ff;" href="https://x.com/Hunters_Ledger" target="_blank" rel="noopener">Open&nbsp;&rarr;</a>
  </div>
</div>

{% include section-header.html label="What You'll Receive" accent="#4ade80" %}

<div class="hl-feat-grid">
  <div class="hl-feat" style="--fa: #58a6ff;">
    <div class="hl-feat__dot"></div>
    <div class="hl-feat__title">Reports</div>
    <p class="hl-feat__desc">Original malware analysis &amp; campaign investigations.</p>
  </div>
  <div class="hl-feat" style="--fa: #4ade80;">
    <div class="hl-feat__dot"></div>
    <div class="hl-feat__title">Detections</div>
    <p class="hl-feat__desc">Sigma, YARA &amp; Suricata rules ready for your environment.</p>
  </div>
  <div class="hl-feat" style="--fa: #f87171;">
    <div class="hl-feat__dot"></div>
    <div class="hl-feat__title">IOC Feeds</div>
    <p class="hl-feat__desc">Structured indicator packages for direct SIEM / EDR ingest.</p>
  </div>
</div>

<p style="color: var(--hl-text-muted); font-size: 0.85em; line-height: 1.6; margin-top: 18px;">All content is from original research. Publication frequency varies with active investigations — typically several reports per month.</p>

<script>
document.querySelectorAll('.hl-feed-url__copy').forEach(function (b) {
  b.addEventListener('click', function () {
    navigator.clipboard.writeText(b.getAttribute('data-copy')).then(function () {
      var t = b.textContent; b.textContent = 'COPIED'; setTimeout(function () { b.textContent = t; }, 1400);
    });
  });
});
</script>
