---
title: The Wire
description: "Threat intelligence headlines from public research and news sources, refreshed every 15 minutes from a self-hosted OpenCTI instance, beside VulnCheck's Known Exploited Vulnerabilities additions. Links only, every item goes to the original publisher."
layout: page
hl_idx: wire
permalink: /wire/
thumbnail: /assets/images/cards/wire.png
position: 2.5
---

{% include index-header.html accent="#58a6ff" label="The Wire" title="Threat Intelligence Headlines" desc="Threat reporting, newly exploited vulnerabilities and significant new CVEs, refreshed every 15 minutes." %}

{%- assign wire = site.data.wire -%}
{%- assign wp_batch_group_min = 5 -%}
{%- assign wp_unauth_group_min = 2 -%}
{%- assign product_group_min = 5 -%}
{%- comment -%} T-0667: ev_new is true once the exporter writes the event day (it adds vulns_counts.event_moved with it). Data from before that renders as it did, and the panel keeps the text that was true of it (the site deploys before the exporter). {%- endcomment -%}
{%- assign ev_new = false -%}{%- if wire.vulns_counts.event_moved != nil -%}{%- assign ev_new = true -%}{%- endif -%}
{%- assign pp_new = false -%}{%- if wire.vulns_counts.np_per_product == true -%}{%- assign pp_new = true -%}{%- endif -%}
{%- comment -%} T-0668: cisa_pt is true while the data still carries a "cisa" reason worth 1 point (older exports, and after any rollback of the exporter); the score text then says a CISA listing earns 1 point. Once no row has it, a KEV listing earns none. {%- endcomment -%}
{%- assign cisa_pt = false -%}{%- for nrow in wire.vulns -%}{%- if nrow.np_reasons contains "cisa" -%}{%- assign cisa_pt = true -%}{%- break -%}{%- endif -%}{%- endfor -%}
{%- if wire and wire.items and wire.items != empty -%}
{%- assign n_headlines = wire.counts.research | plus: wire.counts.news -%}
{%- assign n_vulns = wire.vulns_counts.total | default: 0 | plus: 0 -%}
{%- assign n_cves = wire.cves_counts.total | default: 0 | plus: 0 -%}

<div class="hl-d-kpis hl-d-kpis--wire" style="--fc: 4;">
  <div class="hl-d-kpi" style="--kc: #58a6ff;"><span class="hl-d-kpi__n">{{ n_headlines }}</span><span class="hl-d-kpi__cap">Headlines</span><span class="hl-d-kpi__note">last {{ wire.window_days | plus: 0 }} days</span></div>
  <div class="hl-d-kpi" style="--kc: #bc8cff;"><span class="hl-d-kpi__n">{{ n_vulns }}</span><span class="hl-d-kpi__cap">nKEVs</span><span class="hl-d-kpi__note">{% if ev_new %}VulnCheck or CISA KEV, by latest event{% else %}new to VulnCheck KEV{% endif %}</span></div>
  <div class="hl-d-kpi" style="--kc: #2dd4bf;"><span class="hl-d-kpi__n">{{ n_cves }}</span><span class="hl-d-kpi__cap">Significant new CVEs</span><span class="hl-d-kpi__note">not yet on a KEV list</span></div>
  <div class="hl-d-kpi" style="--kc: #7ee787;"><span class="hl-d-kpi__n hl-d-kpi__n--sm">{{ wire.generated_at | date: "%H:%M" | escape }} UTC</span><span class="hl-d-kpi__cap">Last data update</span><span class="hl-d-kpi__note">{{ wire.generated_at | date: "%-d %B %Y" | escape }}, at capture</span></div>
</div>

{%- comment -%}
  Three tabs, switched by the URL hash with CSS alone (:target and :has, in
  custom.scss under "The Wire: tabs"). A day (#vulns-YYYY-MM-DD) or a CVE
  (#cve-cve-...) anchor inside #vulns opens that tab too, so a digest row, an
  Atom entry and a shared link all land on the right row; the same holds for
  #cves, #cves-YYYY-MM-DD and #cves-cve-... (T-0522). The filter bars keep
  their state in the query string here (data-filter-state="query") so the hash
  stays the tabs'. Designed in T-0394, built in T-0396.
{%- endcomment -%}
<div class="hl-wtabs">
<nav class="hl-wtabs__nav" aria-label="Sections of The Wire"><a class="hl-wtabs__tab hl-wtabs__tab--h" href="#headlines">{% include d-icon.html name="pulse" %}<span class="hl-wtabs__t">Headlines</span><span class="hl-wtabs__n">{{ n_headlines }}</span></a><a class="hl-wtabs__tab hl-wtabs__tab--v" href="#vulns" title="{% if ev_new %}New Known Exploited Vulnerabilities: CVEs added to VulnCheck&#39;s or CISA&#39;s KEV catalog, dated by the latest exploitation event{% else %}New Known Exploited Vulnerabilities: CVEs newly added to VulnCheck&#39;s KEV catalog{% endif %}">{% include d-icon.html name="alert" %}<span class="hl-wtabs__t">nKEVs</span><span class="hl-wtabs__n">{{ n_vulns }}</span></a><a class="hl-wtabs__tab hl-wtabs__tab--c" href="#cves" title="Significant new CVEs not yet on a KEV list">{% include d-icon.html name="shield" %}<span class="hl-wtabs__t">CVEs</span><span class="hl-wtabs__n">{{ n_cves }}</span></a></nav>

<section id="headlines" class="hl-wtabs__sec" data-filter-scope>

<div class="hl-wire__callout hl-wire__callout--h">These headlines come from public research and news sources, pulled every 15 minutes from the OpenCTI instance I run myself, which itself polls the publishers' feeds every 5 to 15 minutes. The reporting belongs to its publishers and every item links to the original; my own research is in the <a href="/reports/">reports section</a>.</div>

<p class="hl-wire__freshness">Updated {{ wire.generated_at | date: "%-d %B %Y, %H:%M" }} UTC &middot; {{ n_headlines }} headlines from the last {{ wire.window_days }} days &middot; <a href="{{ '/wire/feed.xml' | relative_url }}">Atom feed</a> &middot; <a href="{{ '/wire/agent/' | relative_url }}">Plain-text and JSON data</a></p>

{%- comment -%}
  The chip vocabulary comes precomputed from wire.topics rather than from the
  shared listing-filter include, which counts tags in a nested Liquid loop. At
  531 items carrying 1,267 distinct labels that include would render 133 chips
  and cost 3.2 million iterations on every build. Both measured, not assumed.
  The markup and class names are the include's, so the CSS and the JS are shared.
{%- endcomment -%}
<div class="hl-filter hl-filter--wire" data-listing-filter data-filter-state="query" data-pagefind-ignore>
  {%- comment -%}
    The box already matches BOTH the headline and the item's labels, so an actor
    name like cl0p surfaces items tagged with it and never mentioned in the
    title. Nobody knew that from "Filter headlines…", so the placeholder names
    what it searches. It stops at what the data supports: actor names reach 11%
    of items, which is worth finding but not worth a chip axis of its own.
  {%- endcomment -%}
  <input class="hl-filter__search" type="text" placeholder="Search headlines, topics, actors…" aria-label="Search headlines, topics and actors" autocomplete="off">
  <div class="hl-filter__chips hl-filter__chips--topic">
    <button type="button" class="hl-chip-btn is-on" data-tag="">All</button>
    {%- for t in wire.topics -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c{{ t.color }}" data-tag="{{ t.label }}">{{ t.label }} <span class="hl-chip-btn__n">{{ t.count }}</span></button>{%- endfor -%}
  </div>
  {%- comment -%}
    The second axis listing-filter.js already supports (data-kind, hash key
    kind=). Research is a vendor or researcher write-up, News a press report;
    the generator sets the kind, and every item carries one (check-wire.js).
    The chips echo the row marker: a solid dot is research, a ring is news.
    The two axes AND together, so a topic plus a kind narrows to both.
  {%- endcomment -%}
  <div class="hl-filter__chips hl-filter__chips--kind">
    <span class="hl-filter__dim">Kind</span>
    <button type="button" class="hl-chip-btn is-on" data-kind="">All</button>
    <button type="button" class="hl-chip-btn hl-chip-btn--kind hl-chip-btn--research" data-kind="research">Research <span class="hl-chip-btn__n">{{ wire.counts.research }}</span></button>
    <button type="button" class="hl-chip-btn hl-chip-btn--kind hl-chip-btn--news" data-kind="news">News <span class="hl-chip-btn__n">{{ wire.counts.news }}</span></button>
    {%- if wire.counts.vuln and wire.counts.vuln > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--kind hl-chip-btn--vuln" data-kind="vuln">Vuln digest <span class="hl-chip-btn__n">{{ wire.counts.vuln }}</span></button>{%- endif -%}
  </div>
  <div class="hl-filter__date">
    <label class="hl-filter__dim" for="hl-wire-date">Date</label>
    <input class="hl-filter__dateinput" type="date" id="hl-wire-date" data-filter-date aria-label="Show only headlines from this date">
    <button type="button" class="hl-filter__datereset" data-filter-date-clear hidden>Clear date</button>
  </div>
  <div class="hl-filter__count" data-filter-count></div>
  <div class="hl-filter__empty" data-filter-empty hidden><span data-filter-empty-msg>No headlines match that filter.</span> <button type="button" class="hl-filter__reset" data-filter-reset>Clear filters</button></div>
</div>

<div class="hl-wire" data-filter-grid data-filter-item=".hl-wire__row" data-pagefind-ignore>
{%- assign current_day = "" -%}
{%- for i in wire.items -%}
{%- assign day = i.date | date: "%Y-%m-%d" -%}
{%- if day != current_day -%}
{%- assign current_day = day -%}
<div class="hl-wire__day" data-filter-group>{{ i.date | date: "%A %-d %B %Y" }}</div>
{%- endif -%}
{%- comment -%} A digest row's url is absolute (the exporter and the gate admit only https); on this page it is the bare anchor, so it switches tabs in place. {%- endcomment -%}
{%- if i.kind == "vuln" -%}{%- assign href = i.url | split: "#" | last | prepend: "#" -%}{%- assign tgt = "" -%}{%- else -%}{%- assign href = i.url -%}{%- assign tgt = ' target="_blank" rel="noopener noreferrer"' -%}{%- endif -%}
{%- comment -%} T-0532: the list row is an anchor, which cannot hold the Details toggle,
so the filter item is the wrapper (design section 6): the anchor keeps its own
classes and href, and the filter data attributes and the toggle live on it. The
wrapper is what listing-filter.js shows and hides, so a filter that hides a row
hides its Details panel with it. data-labels carries every label as filed, while
data-tags stays the lowercased list the filter matches on. {%- endcomment -%}
{%- comment -%} T-0548: a stable id on every headline row so site search can land on it (the nKEV and CVE rows already carry cve-<cve> and cves-<cve>).
Rule: "h-" + the item's date to the minute (%Y%m%d%H%M) + "-" + the source slug + "-" + the last 40 characters of the url's slug. The same article url can appear on
different dates and from different sources, so the date and source keep each row's id apart; the same inputs always give the same id, which tools/report-tooling/build-search-index.js
reads back from the built page (it fails the index step on a duplicate). A vuln digest item (kind "vuln") is a link to an nKEV row below, not a row of its own to find: no id, not indexed. {%- endcomment -%}
{%- assign h_id = "" -%}{%- if i.kind != "vuln" -%}{%- assign h_src = i.source | slugify -%}{%- assign h_url = i.url | slugify -%}{%- assign h_n = h_url | size -%}{%- if h_n > 40 -%}{%- assign h_url = h_url | slice: -40, 40 -%}{%- endif -%}{%- assign h_id = i.date | date: "%Y%m%d%H%M" | prepend: "h-" | append: "-" | append: h_src | append: "-" | append: h_url -%}{%- endif -%}
<div class="hl-wire__row"{% if h_id != "" %} id="{{ h_id | escape }}"{% endif %} data-title="{{ i.title | downcase | escape }}" data-tags="{{ i.labels | join: '|' | downcase | escape }}" data-labels="{{ i.labels | join: '|' | escape }}" data-kind="{{ i.kind | escape }}" data-day="{{ day }}"><a class="hl-wire__item hl-wire__item--{{ i.kind | escape }} hl-wire__item--src-{{ i.source | slugify }}" href="{{ href | escape }}"{{ tgt }}><span class="hl-wire__src">{{ i.source | escape }}</span><span class="hl-wire__title">{{ i.title | escape }}</span><span class="hl-wire__labels">{%- for l in i.labels limit: 2 -%}{%- assign tc = wire.label_colors[l] -%}<span class="hl-wire__label{% if tc %} hl-topic-c{{ tc | escape }}{% endif %}">{{ l | escape }}</span>{%- endfor -%}</span></a></div>
{%- endfor -%}
</div>

</section>

<section id="vulns" class="hl-wtabs__sec" data-filter-scope data-details="{{ '/wire/details-nkev.json' | relative_url }}?v={{ wire.vulns_generated_at | default: wire.generated_at | escape }}">
{%- comment -%}
  T-0641: the nKEVs Priority strip. A row with np_rank above 0 is a priority row. It stays in its day
  group, in the day's own order, with its Priority badge and reason chips; the strip at the top of the
  tab lists the priority rows by np_rank, each linking to its row. Data with no np_rank on any row makes
  no strip and no panel section, and renders as before (the site deploys before the exporter).
  A row the row template would skip (no CVE- id, no ten-character day) is left out of the strip too, so
  no item links to a row that is not drawn.
{%- endcomment -%}
{%- assign np_rows = "" | split: "" -%}
{%- assign n_canary = 0 -%}{%- assign n_ransom = 0 -%}{%- assign n_dated = 0 -%}
{%- for nrow in wire.vulns -%}
{%- assign np_r = nrow.np_rank | plus: 0 -%}
{%- assign np_head = nrow.cve | slice: 0, 4 -%}{%- assign np_alen = nrow.added | size -%}
{%- if np_r > 0 and np_head == "CVE-" and np_alen == 10 -%}{%- assign np_rows = np_rows | push: nrow -%}{%- endif -%}
{%- comment -%} T-0667: the flag chips and the two-date rows, counted over the rows the row template draws. {%- endcomment -%}
{%- if np_head == "CVE-" and np_alen == 10 -%}
{%- if nrow.canary == true -%}{%- assign n_canary = n_canary | plus: 1 -%}{%- endif -%}
{%- if nrow.ransomware == true -%}{%- assign n_ransom = n_ransom | plus: 1 -%}{%- endif -%}
{%- assign np_ev = nrow.event | default: nrow.added -%}{%- if np_ev != nrow.added -%}{%- assign n_dated = n_dated | plus: 1 -%}{%- endif -%}
{%- endif -%}
{%- endfor -%}
{%- assign n_np = np_rows.size -%}
{%- assign n_flags = n_canary | plus: n_ransom -%}
<details class="hl-wire-explanation" id="nkev-explanation" data-pagefind-ignore>
<summary>Explanation and data used</summary>
<div class="hl-wire-explanation__body">
<p>I keep already exploited CVEs here: those in VulnCheck's Known Exploited Vulnerabilities (KEV) catalog or CISA's. CISA listing is not required: the CISA KEV badge marks CVEs on CISA's catalog, and a row with the badge may also be on VulnCheck's. A low EPSS or a missing rule does not remove a row, because VulnCheck or CISA has already recorded exploitation.</p>
{%- if ev_new -%}<p>I group rows by the day of the latest exploitation event I know of for the CVE, newest day first. For most rows that is the day VulnCheck added it. A row sits under a later day when CISA added the CVE to its own KEV catalog after VulnCheck did, or when I first published it here two or more days after VulnCheck's date (VulnCheck can list a CVE with an earlier date than the day it reaches me). Those rows show both dates, for example "CISA KEV 17 Nov &middot; VulnCheck 4 Nov" or "First seen here 17 Nov &middot; VulnCheck dated 25 Oct". A CVE that CISA added inside the window and VulnCheck dated before it still gets a row, under the CISA day. A CVE on CISA's catalog that VulnCheck does not list at all gets a row that says so. Each date shows how many CVEs sit under it.</p>{%- else -%}<p>I group rows by the day VulnCheck added them, newest day first. Each date shows how many CVEs were added that day.</p>{%- endif -%}
<p>Inside a day I use the exporter's priority order: CISA-listed first, then network flaws needing no privileges or user action (AV:N, PR:N, UI:N), then public exploit or detection tooling, then higher EPSS (missing last), with CVE id breaking ties. These datapoints order confirmed exploitation rather than deciding whether it deserves a row.</p>
<p>I fold a day's WordPress plugin and theme batch when it contains at least 5 entries. One folded line stays at the first member's rank and opens to every member. Every VulnCheck KEV entry stays visible. Filters open matching batches and counts show matching rows. Smaller batches stay as individual rows. I also fold five or more same-day CVEs for the same product into one line. A row in the Priority strip is never folded.</p>
<p>I give the title room before chips. The +N button opens the remaining context in place, including the gap from NVD publication to listing when known. VulnCheck gives no separate date of first exploitation.</p>
<p>I also checked ENISA's EU Vulnerability Database as a second source here. It flagged none of the rows that only VulnCheck lists, and for the five CVEs it alone marks as exploited, the sources it cited did not support that mark, so I left it out.</p>
{%- if n_np > 0 -%}
<h3>Priority</h3>
<p>The Priority strip at the top of this tab lists my patch-first order. Every row on this tab is already exploited, so the order predicts nothing. It ranks which of these flaws I would patch first.</p>
<p>A row earns one point for each of these: a network flaw that needs no login or user action, a CVSS score of 9.0 or higher, public tooling, and a flaw disclosed under 30 days before VulnCheck listed it. It earns two points for a product class I treat as patch-first, or one for an operating system or browser. {% if cisa_pt %}A KEV listing, VulnCheck's or CISA's, is what puts a row on this tab; in this data a CISA KEV listing also earns one point. {% else %}A KEV listing, VulnCheck's or CISA's, is what puts a row on this tab and earns no point. {% endif %}{%- if pp_new -%}The strip holds every row that scores 5 or more points, with no cap, and lists one row per product: when a product has several rows at 5 or more, the best ranked one is in the strip and the others keep their score and badge but are not repeated there. The order is score first, then the row's own date (newest first), then EPSS, then CVE id. {%- else -%}The strip holds the highest-scoring rows, and a row needs 5 points to be among them, so on a quiet month it holds fewer. {%- endif -%}Each item in the strip jumps to its row, and the row stays in its own day with its Priority badge.</p>
<p>The product classes are my judgment, and they are listed in the exporter's class files. There is no later outcome I can test this order against, so I have not measured it.</p>
{%- endif -%}
<h3>Reading the data and filters</h3>

<div class="hl-wire-data__h">Reading a row</div>
<dl class="hl-wire-data__list">
<dt><span class="hl-vuln__cve">CVE-YYYY-NNNN</span></dt>
<dd>The CVE. It opens its NVD record in a new tab.</dd>
<dt><span class="hl-vuln__vp"><b>Vendor</b> Product</span> <span class="hl-vuln__none">vendor not given</span></dt>
<dd>The vendor and product, as VulnCheck gives them, followed by the CVE record title when available. When it gives no vendor, the row says so.</dd>
<dt><span class="hl-vuln__sev hl-vuln__sev--critical">CRITICAL 9.8</span> <span class="hl-vuln__sev hl-vuln__sev--high">HIGH 7.5</span> <span class="hl-vuln__sev hl-vuln__sev--medium">MEDIUM 5.3</span> <span class="hl-vuln__sev hl-vuln__sev--low">LOW 3.1</span></dt>
<dd>Severity: the CVSS base score in the CVE's NVD record, read through VulnCheck NVD++. Most are scored by the CVE's CNA, not by NVD; hover the chip to see who scored it. A CVE with no score shows no chip.</dd>
<dt><span class="hl-vuln__b hl-vuln__b--cisa">CISA KEV</span></dt>
<dd>The CVE is also in CISA's Known Exploited Vulnerabilities catalog. Hover for the date CISA added it.</dd>
{%- if ev_new -%}
<dt><span class="hl-vuln__ev hl-vuln__dates">CISA KEV 17 Nov &middot; VulnCheck 4 Nov</span> <span class="hl-vuln__ev hl-vuln__dates">First seen here 17 Nov &middot; VulnCheck dated 25 Oct</span></dt>
<dd>Both dates of a row that sits under a later day than VulnCheck's. The first is the day CISA added the CVE, the second the day I first published it here; the VulnCheck date is the one VulnCheck gives. A row with only a CISA date and no VulnCheck date says "not in VulnCheck KEV".</dd>
<dt><span class="hl-vuln__b hl-vuln__b--canary">VulnCheck canary</span> <span class="hl-vuln__b hl-vuln__b--ransom">Ransomware</span></dt>
<dd>Canary: VulnCheck's own canary network recorded exploitation of the CVE, which is VulnCheck's flag and not a CISA or vendor statement. Ransomware: VulnCheck or CISA marks the CVE as used in known ransomware campaigns. Neither adds Priority points.</dd>
{%- endif -%}
<dt><span class="hl-vuln__ev">evidence 2026-01-01</span></dt>
<dd>The earliest date VulnCheck records for a report it cites for the CVE, drawn only when it is earlier than the day VulnCheck added the CVE. It is VulnCheck's citation date, not a date of first exploitation.</dd>
<dt><span class="hl-vuln__p hl-vuln__p--epss">EPSS 3%</span></dt>
<dd>FIRST's predicted probability that the CVE is exploited in the next 30 days. Click the chip in a row to open the popover described below.</dd>
<dt class="hl-wire-data__k">VEDAS (exploit maturity)</dt>
<dd><p>A.R.P. Syndicate describes VEDAS as &ldquo;Estimation of Vulnerability Prevalence &amp; Exploit Maturity&rdquo;. Its README names OSINT from <a href="https://www.exploit.observer/" target="_blank" rel="noopener noreferrer">Exploit Observer</a>, coverage of 150+ identifiers and updates every 6 to 8 hours. The source publishes no formula.</p><p>On the CVEs tab, I pair EPSS at least 1% with VEDAS at least 80% and CVSS at least 7.0 for the EPSS + VEDAS reason. </p><p>A high score is not evidence that working exploit code exists or that the CVE has been exploited; exploitation is what the nKEVs tab and CISA KEV are for. An unscored CVE shows no VEDAS chip.</p></dd>
<dt><span class="hl-vuln__p">3 src</span></dt>
<dd>The reports VulnCheck cites as its evidence of exploitation. Click the chip in a row to list them.</dd>
<dt><span class="hl-vuln__p">2 news</span></dt>
<dd>Wire headlines that name the CVE. It opens the Headlines tab searched for it.</dd>
<dt><span class="hl-vuln__p hl-vuln__p--det">Rules 4</span></dt>
<dd>Public detection rules that name the CVE, counted across four sources: ET Open (Suricata), Nuclei templates, CISA's SIGMA_Rules and the Snort 3 community ruleset. A row with none shows no chip. Click the chip in a row to open the popover described below. Checked daily.</dd>
<dt><span class="hl-vuln__p hl-vuln__p--ssvc">SSVC</span></dt>
<dd>CISA's own assessment of the CVE, from its Stakeholder-Specific Vulnerability Categorization (SSVC): exploitation, automatable and technical impact. They are CISA's decision points, not mine. cve.now carries them (CISA Vulnrichment), with the fixed version and the GitHub Security Advisory (GHSA) and EU Vulnerability Database (EUVD) ids where it has them. Click the chip in a row to read them. A CVE cve.now has none for shows no chip.</dd>
<dt><span class="hl-vuln__p hl-vuln__p--exp">Exploits 2</span></dt>
<dd>Public exploits for the CVE that I confirmed against the publisher's own index: a Metasploit module appears only when Rapid7's module list names the CVE, and an Exploit-DB entry only when Exploit-DB's own list does. Both open their pages. A missing chip does not mean no exploit exists, only that I could not confirm one, and I have not tested any exploit.</dd>
</dl>
<div class="hl-wire-data__h">Rules popover</div>
<dl class="hl-wire-data__list">
<dt><span class="hl-vuln__p hl-vuln__p--det">Rules 4</span></dt>
<dd>One group per source that has a rule for the CVE: "ET Open" (the rule SIDs, shown as text), "Nuclei" (the template file), "CISA Sigma" (the rule file in cisagov/SIGMA_Rules) and "Snort 3 community" (each SID opens its page on snort.org). The rule files and templates open in a new tab. The chip counts every rule listed.</dd>
</dl>
<div class="hl-wire-data__h">EPSS popover</div>
<dl class="hl-wire-data__list">
<dt><span class="hl-vuln__p hl-vuln__p--epss">EPSS 3%</span></dt>
<dd>The popover shows EPSS over the last 30 days as a line, the EPSS 7 days before the KEV add compared with now, and the CVSS:EPSS ratio, (CVSS / 10) / EPSS. Above 1, the severity runs ahead of the predicted likelihood of exploitation. EPSS often rises after exploitation is public, so the value from before the KEV add is the lagging-indicator comparison. FIRST changes its EPSS model from time to time and scores from different model versions are not comparable, so a comparison that crosses a model change is marked.</dd>
</dl>
<div class="hl-wire-data__h">Using the filters</div>
<dl class="hl-wire-data__list">
<dt class="hl-wire-data__k">Search</dt>
<dd>Matches the CVE id, vendor and product.</dd>
<dt class="hl-wire-data__k">List</dt>
<dd>All, only CVEs that are also in CISA KEV, or "VulnCheck only": those in VulnCheck KEV but not in CISA KEV.</dd>
<dt class="hl-wire-data__k">Severity</dt>
<dd>The band of the row's CVSS score. "No score" is a CVE with no score, never a low one.</dd>
<dt class="hl-wire-data__k">Public rule</dt>
<dd>CVEs with an ET Open Suricata rule, a Nuclei template, a CISA Sigma rule or a Snort 3 community rule.</dd>
<dt class="hl-wire-data__k">NVD timing</dt>
<dd>"pre-NVD" shows only the CVEs VulnCheck added before NVD published them.</dd>
<dt class="hl-wire-data__k">Vendor</dt>
<dd>Narrows to one or more vendors.</dd>
{%- if n_flags > 0 -%}
<dt class="hl-wire-data__k">Flags</dt>
<dd>{%- if n_np > 0 -%}Priority group, {% endif -%}rows VulnCheck's canaries recorded, and rows marked as used in ransomware campaigns. Picking several shows rows that match any of them.</dd>
{%- endif -%}
<dt class="hl-wire-data__k">Added</dt>
<dd>{%- if ev_new -%}The day the row sits under, its latest exploitation event: today, the last 7 days, or the whole {{ wire.window_days }}-day window, counted from the last data update.{%- else -%}When VulnCheck added the CVE: today, the last 7 days, or the whole {{ wire.window_days }}-day window, counted from the last data update.{%- endif -%}</dd>

</dl>
<p class="hl-wire-data__p">Picking several chips in one row shows any of them; picking chips in different rows narrows to rows that match all. The filters are kept in the page address, so a filtered view can be shared by copying the link.</p>
<div class="hl-wire-data__h">About this data</div>
<p class="hl-wire-data__p">This tab shows the nKEVs in VulnCheck's KEV catalog as VulnCheck publishes it, with CVEs on CISA's KEV catalog. I do not curate or track this data myself; every entry comes from VulnCheck or CISA, and VulnCheck's catalog is at <a href="https://www.vulncheck.com/kev" target="_blank" rel="noopener noreferrer">vulncheck.com/kev</a>.{%- if ev_new %} The one exception to "from VulnCheck or CISA" is the dating: "First seen here" is the day my exporter first published the row.{%- endif %} EPSS scores from FIRST (<a href="https://www.first.org/epss/" target="_blank" rel="noopener noreferrer">first.org/epss</a>), generated by Empirical Security. The SSVC, fixed version and advisory fields come from <a href="https://cve.now/" target="_blank" rel="noopener noreferrer">cve.now</a> (CC BY 4.0), and the Metasploit and Exploit-DB entries from Rapid7's and Exploit-DB's own indexes. VEDAS exploit maturity from <a href="https://github.com/ARPSyndicate/cve-scores" target="_blank" rel="noopener noreferrer">A.R.P. Syndicate</a>.</p>

</div>
</details>
{%- assign vstatus = wire.vulns_status | default: "unavailable" -%}
{%- assign sev_bands = "critical,high,medium,low" | split: "," -%}

{%- comment -%}
  T-0468.1: one short line stays above the filter bar so the nKEV definition, the data
  attribution and the feed are visible without opening anything. Everything that used
  to follow it (the callout and the long chip-meaning paragraph) lives in the legend
  below, which sits where a report shows its table of contents.
{%- endcomment -%}
<p class="hl-wire__freshness hl-wire__freshness--v">nKEVs: {% if ev_new %}CVEs in VulnCheck's or CISA's Known Exploited Vulnerabilities (KEV) catalog, dated by the latest exploitation event, in the last {{ wire.window_days }} days{% else %}CVEs newly added to VulnCheck's Known Exploited Vulnerabilities (KEV) catalog in the last {{ wire.window_days }} days{% endif %} &middot; Data: <a href="https://www.vulncheck.com/kev" target="_blank" rel="noopener noreferrer">VulnCheck KEV</a> &middot; EPSS from <a href="https://www.first.org/epss/" target="_blank" rel="noopener noreferrer">FIRST</a> &middot; Extra fields: <a href="https://cve.now/" target="_blank" rel="noopener noreferrer">cve.now</a> (CC BY 4.0) &middot; VEDAS exploit maturity from <a href="https://github.com/ARPSyndicate/cve-scores" target="_blank" rel="noopener noreferrer">A.R.P. Syndicate</a> &middot; <a href="{{ '/wire/vulns.xml' | relative_url }}">Atom feed (nKEVs)</a></p>


{%- assign vshow = false -%}
{%- if wire.vulns and wire.vulns != empty -%}{%- if vstatus == "ok" or vstatus == "stale" -%}{%- assign vshow = true -%}{%- endif -%}{%- endif -%}
{%- if vshow -%}

{%- if vstatus == "stale" -%}
<p class="hl-wire__freshness"><span class="hl-wire__notice">Vulnerability data last updated {{ wire.vulns_generated_at | date: "%-d %B %Y, %H:%M" }} UTC.</span></p>
{%- endif -%}
{%- comment -%}
  The legend (T-0468.1). Captured once and printed twice, the way a report prints its table of
  contents twice: an aside in the right margin on a wide screen (the report TOC's own class, so
  its position, width, type and colours are the TOC's) and a collapsed details above the filter
  bar on a narrow one. CSS shows one of them. The samples are plain spans in the row's own
  classes: no links, no details, no data-* attributes, and both copies sit OUTSIDE
  data-filter-grid and the filter bar, so listing-filter.js never counts or filters them.
  Each entry describes one condition of the row template below; the map is in
  tasks/runs/T-0468.1/verify/legend-map.md. No id inside it, because it is printed twice.
{%- endcomment -%}
{%- capture legend_html -%}
<div class="hl-legend__h">Chip key</div>
<dl class="hl-legend__list">
<dt><span class="hl-vuln__cve">CVE</span></dt><dd>NVD record</dd>
<dt><span class="hl-vuln__vp"><b>Vendor</b> Product</span></dt><dd>Affected software</dd>
<dt><span class="hl-vuln__sev hl-vuln__sev--critical">CRITICAL</span> <span class="hl-vuln__sev hl-vuln__sev--high">HIGH</span> <span class="hl-vuln__sev hl-vuln__sev--medium">MEDIUM</span> <span class="hl-vuln__sev hl-vuln__sev--low">LOW</span></dt><dd>CVSS band</dd>
<dt><span class="hl-vuln__b hl-vuln__b--cisa">CISA KEV</span></dt><dd>Also on CISA KEV</dd>
<dt><span class="hl-vuln__p hl-vuln__p--epss">EPSS</span></dt><dd>Predicted exploitation</dd>
<dt><span class="hl-vuln__p hl-vuln__p--vedas">VEDAS</span></dt><dd>Exploit maturity estimate</dd>
<dt><span class="hl-vuln__p">Sources</span></dt><dd>Exploitation citations</dd>
<dt><span class="hl-vuln__p">News</span></dt><dd>Wire coverage</dd>
<dt><span class="hl-vuln__p hl-vuln__p--det">Rules</span></dt><dd>Public detection coverage</dd>
<dt><span class="hl-vuln__p hl-vuln__p--ssvc">SSVC</span></dt><dd>CISA assessment</dd>
<dt><span class="hl-vuln__p hl-vuln__p--exp">Exploits</span></dt><dd>Publisher-confirmed entries</dd>
<dt class="hl-legend__k">Fixed in / advisories</dt><dd>Record context</dd>
<dt><span class="hl-vuln__p hl-vuln__p--cn">cve.now</span></dt><dd>CVE record</dd>
<dt><span class="hl-vuln__preauth">Pre-auth (no login)</span></dt><dd>Network, no privileges or interaction</dd>
<dt><span class="hl-vuln__ev">Evidence</span></dt><dd>Earliest cited report</dd>
<dt><span class="hl-vuln__gap-fact">listed after disclosure</span></dt><dd>Timing detail in overflow</dd>
</dl>
{%- endcapture -%}
{%- comment -%} T-0638: the Priority entries, a second list after the key, only when the group exists. {%- endcomment -%}
{%- capture np_legend -%}{%- if n_np > 0 -%}<dl class="hl-legend__list"><dt><span class="hl-pick__score">Priority</span></dt><dd>Patch-first score</dd><dt><span class="hl-pick__chip hl-pick__chip--noauth">Reason</span></dt><dd>What earned a point</dd></dl>{%- endif -%}{%- endcapture -%}
{%- comment -%} T-0667: the dating and flag entries, only when the data carries them. {%- endcomment -%}
{%- capture ev_legend -%}{%- if n_dated > 0 or n_flags > 0 -%}<dl class="hl-legend__list">{%- if n_dated > 0 -%}<dt><span class="hl-vuln__ev hl-vuln__dates">CISA KEV</span></dt><dd>Row dated by a later event</dd>{%- endif -%}{%- if n_canary > 0 -%}<dt><span class="hl-vuln__b hl-vuln__b--canary">Canary</span></dt><dd>Seen by VulnCheck canaries</dd>{%- endif -%}{%- if n_ransom > 0 -%}<dt><span class="hl-vuln__b hl-vuln__b--ransom">Ransomware</span></dt><dd>Known ransomware use</dd>{%- endif -%}</dl>{%- endif -%}{%- endcapture -%}
<details class="hl-legend-mobile" data-pagefind-ignore>
<summary>Legend</summary>
<div class="hl-legend__body">{{ legend_html }}{{ np_legend }}{{ ev_legend }}</div>
</details>

{%- comment -%}
  The second bar. Its chips name the axes listing-filter.js reads: data-list
  (CISA or VulnCheck only), data-vendor, data-added (days, against
  data-filter-ref) and data-age. All rows are included by default (T-0503,
  Joseph 2026-10-29); "Recent" hides older CVEs, more than a year before the
  year VulnCheck added them, and the Include older chip carries their count.
{%- endcomment -%}
<div class="hl-filter hl-filter--wire hl-filter--vulns" data-listing-filter data-filter-state="query" data-filter-prefix="v" data-filter-ref="{{ wire.vulns_generated_at | slice: 0, 10 }}" data-pagefind-ignore>
  <input class="hl-filter__search" type="text" placeholder="Search CVE, vendor, product…" aria-label="Search CVE, vendor and product" autocomplete="off">
  <div class="hl-filter__chips hl-filter__chips--kind">
    <span class="hl-filter__dim">List</span>
    <button type="button" class="hl-chip-btn is-on" data-list="">All <span class="hl-chip-btn__n">{{ wire.vulns_counts.total }}</span></button>
    <button type="button" class="hl-chip-btn hl-chip-btn--topic hl-vc-cisa" data-list="cisa">Also CISA KEV <span class="hl-chip-btn__n">{{ wire.vulns_counts.cisa }}</span></button>
    <button type="button" class="hl-chip-btn hl-chip-btn--topic hl-vc-vulncheck" data-list="vconly">VulnCheck only <span class="hl-chip-btn__n">{{ wire.vulns_counts.total | minus: wire.vulns_counts.cisa }}</span></button>
  </div>
  {%- comment -%} T-0667: the Priority chip and the canary and ransomware chips share one row, so they are one axis (data-sig): picking several shows rows that match any of them. {%- endcomment -%}
  {%- if n_np > 0 or n_flags > 0 -%}
  <div class="hl-filter__chips hl-filter__chips--kind">
    <span class="hl-filter__dim">{% if n_flags > 0 %}Flags{% else %}Priority{% endif %}</span>
    <button type="button" class="hl-chip-btn is-on" data-sig="">All</button>
    {%- if n_np > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c2" data-sig="np">Priority group <span class="hl-chip-btn__n">{{ n_np }}</span></button>{%- endif -%}
    {%- if n_canary > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-vc-canary" data-sig="canary">VulnCheck canary <span class="hl-chip-btn__n">{{ n_canary }}</span></button>{%- endif -%}
    {%- if n_ransom > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-vc-ransom" data-sig="ransomware">Ransomware <span class="hl-chip-btn__n">{{ n_ransom }}</span></button>{%- endif -%}
  </div>
  {%- endif -%}
  {%- comment -%} Severity (T-0399): the band of the row's CVSS base score; "none" is a CVE with no score, never a low one. Every chip on this bar carries a colour (T-0441): severity chips reuse the row badge's band colour, list and age chips their badge's, the rest the topic palette. {%- endcomment -%}
  <div class="hl-filter__chips hl-filter__chips--kind">
    <span class="hl-filter__dim">Severity</span>
    <button type="button" class="hl-chip-btn is-on" data-sev="">All</button>
    {%- for sv in sev_bands -%}{%- assign svn = wire.vulns_counts[sv] | default: 0 -%}{%- if svn > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-vuln__sev--{{ sv }}" data-sev="{{ sv }}">{{ sv | capitalize }} <span class="hl-chip-btn__n">{{ svn }}</span></button>{%- endif -%}{%- endfor -%}
    {%- assign svn = wire.vulns_counts.unscored | default: 0 -%}{%- if svn > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-vc-none" data-sev="none">No score <span class="hl-chip-btn__n">{{ svn }}</span></button>{%- endif -%}
  </div>
  {%- comment -%} Public rule (T-0407, T-0496): an ET Open Suricata rule, a Nuclei template, a CISA Sigma rule or a Snort 3 community rule names the CVE. Chips OR together, like the severity bands. {%- endcomment -%}
  {%- assign n_et = wire.vulns_counts.et | default: 0 -%}{%- assign n_nu = wire.vulns_counts.nuclei | default: 0 -%}{%- assign n_cs = wire.vulns_counts.cisa_sigma | default: 0 -%}{%- assign n_sn = wire.vulns_counts.snort3 | default: 0 -%}
  {%- if n_et > 0 or n_nu > 0 or n_cs > 0 or n_sn > 0 -%}
  <div class="hl-filter__chips hl-filter__chips--kind">
    <span class="hl-filter__dim">Public rule</span>
    <button type="button" class="hl-chip-btn is-on" data-det="">All</button>
    {%- if n_et > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c2" data-det="et">ET Open <span class="hl-chip-btn__n">{{ n_et }}</span></button>{%- endif -%}
    {%- if n_nu > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c6" data-det="nuclei">Nuclei <span class="hl-chip-btn__n">{{ n_nu }}</span></button>{%- endif -%}
    {%- if n_cs > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c3" data-det="cisa">CISA Sigma <span class="hl-chip-btn__n">{{ n_cs }}</span></button>{%- endif -%}
    {%- if n_sn > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c9" data-det="snort3">Snort <span class="hl-chip-btn__n">{{ n_sn }}</span></button>{%- endif -%}
  </div>
  {%- endif -%}
  {%- comment -%} T-0468: VulnCheck added the CVE before NVD published it (the "pre-NVD" badge). One chip, the same pattern as the others. {%- endcomment -%}
  {%- assign n_pre = wire.vulns_counts.prenvd | default: 0 -%}
  {%- if n_pre > 0 -%}
  <div class="hl-filter__chips hl-filter__chips--kind">
    <span class="hl-filter__dim">NVD timing</span>
    <button type="button" class="hl-chip-btn is-on" data-nvd="">All</button>
    <button type="button" class="hl-chip-btn hl-chip-btn--topic hl-vc-prenvd" data-nvd="pre">pre-NVD <span class="hl-chip-btn__n">{{ n_pre }}</span></button>
  </div>
  {%- endif -%}
  <div class="hl-filter__chips hl-filter__chips--kind">
    <span class="hl-filter__dim">Vendor</span>
    <button type="button" class="hl-chip-btn is-on" data-vendor="">All</button>
    {%- for v in wire.vuln_vendors -%}{%- assign vc = forloop.index0 | modulo: 12 | plus: 1 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c{{ vc }}" data-vendor="{{ v.label | escape }}">{{ v.label | escape }} <span class="hl-chip-btn__n">{{ v.count }}</span></button>{%- endfor -%}
  </div>
  <div class="hl-filter__chips hl-filter__chips--kind">
    <span class="hl-filter__dim">Added</span>
    <button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c5" data-added="1">Today</button>
    <button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c7" data-added="7">7 days</button>
    <button type="button" class="hl-chip-btn is-on" data-added="">{{ wire.window_days }} days</button>
  </div>
  <div class="hl-filter__count" data-filter-count></div>
  <div class="hl-filter__empty" data-filter-empty hidden><span data-filter-empty-msg>No CVEs match that filter.</span> <button type="button" class="hl-filter__reset" data-filter-reset>Clear filters</button></div>
</div>

{%- comment -%}
  T-0641: the Priority strip, one compact line above the day groups. Each item is a link to the row's
  own id (the row is the :target, and wire-details.js opens its Details). "new" marks a row added on the
  data's generated day (UTC).
{%- endcomment -%}
{%- if n_np > 0 -%}
{%- assign np_ordered = np_rows | sort: "np_rank" -%}
{%- assign gen_day = wire.vulns_generated_at | default: wire.generated_at | date: "%Y-%m-%d" -%}
<nav class="hl-pstrip" id="vulns-priority" aria-label="Priority rows on the nKEVs tab" data-pagefind-ignore>
<span class="hl-pstrip__label">{% unless pp_new %}Top {% endunless %}<span class="hl-pstrip__n">{{ np_ordered.size | escape }}</span> by priority</span>
<ul class="hl-pstrip__list">
{%- for r in np_ordered -%}
{%- assign np_name_v = r.vendor | append: "" | strip | downcase -%}{%- assign np_name_p = r.product | append: "" | strip -%}{%- assign np_name_n = np_name_v | size -%}{%- assign np_name_h = np_name_p | slice: 0, np_name_n | downcase -%}{%- if np_name_n > 0 and np_name_h == np_name_v -%}{%- assign np_name = np_name_p -%}{%- else -%}{%- assign np_name = r.vendor | append: " " | append: np_name_p | normalize_whitespace | strip -%}{%- endif -%}{%- if np_name == "" -%}{%- assign np_name = r.cve -%}{%- endif -%}
<li><a class="hl-pstrip__a" href="#cve-{{ r.cve | downcase | escape }}" title="{{ r.cve | escape }} {{ np_name | escape }}: Priority {{ r.np_score | plus: 0 }}"><span class="hl-pstrip__name">{{ np_name | truncate: 90 | escape }}</span><span class="hl-pstrip__s">{{ r.np_score | plus: 0 }}</span>{%- assign np_evd = r.event | default: r.added -%}{%- if np_evd == gen_day -%}<span class="hl-pstrip__new">new</span>{%- endif -%}</a></li>
{%- endfor -%}
</ul>
</nav>
{%- endif -%}
<div class="hl-wire hl-vulns" data-filter-grid data-filter-item=".hl-vuln" data-pagefind-ignore>
{%- comment -%} T-0667: a row sits under its event day (the latest exploitation event); a row with no event, or an empty one, sits under its added day, as before. {%- endcomment -%}
{%- assign day_groups = wire.vulns | group_by_exp: "gr", "gr.event | default: gr.added" | sort: "name" | reverse -%}
{%- comment -%} T-0667: the digest headlines link #vulns-<added day>. When every row added that day sits under a later event day, no group carries that id, so the link would dangle: an empty anchor stands in the day order where the day would have been. {%- endcomment -%}
{%- assign group_names = day_groups | map: "name" -%}
{%- assign alias_days = "" | split: "" -%}
{%- for ar in wire.vulns -%}{%- assign ar_len = ar.added | size -%}{%- if ar_len == 10 -%}{%- unless group_names contains ar.added -%}{%- unless alias_days contains ar.added -%}{%- assign alias_days = alias_days | push: ar.added -%}{%- endunless -%}{%- endunless -%}{%- endif -%}{%- endfor -%}
{%- assign alias_days = alias_days | sort | reverse -%}
{%- assign alias_done = "|" -%}
{%- for day_group in day_groups -%}
{%- for ad in alias_days -%}{%- assign ad_key = "|" | append: ad | append: "|" -%}{%- if ad > day_group.name -%}{%- unless alias_done contains ad_key -%}{%- assign alias_done = alias_done | append: ad | append: "|" -%}<div class="hl-wire__dayalias" id="vulns-{{ ad | escape }}" data-day-target="{{ ad | escape }}"></div>{%- endunless -%}{%- endif -%}{%- endfor -%}
{%- assign group_rows = day_group.items | sort: "prio" -%}
<div class="hl-vuln-group" data-filter-container data-wire-layout="days">
<h2 class="hl-wire__day" id="vulns-{{ day_group.name | escape }}" data-day-target="{{ day_group.name | escape }}" data-filter-group>{{ day_group.name | date: "%A %-d %B %Y" | escape }} &middot; <span data-container-count>{{ group_rows.size }}</span> added</h2>
{%- assign rendered_rows = "" | split: "" -%}
{%- for r in group_rows -%}
{%- capture rendered_row -%}
{%- comment -%}
  A row that is not canonical is skipped rather than drawn broken; check-wire.js
  warns about it. Liquid treats an empty string as true, so the guard checks the
  shapes: an id starting CVE- and a ten-character day (T-0396 review F3).
{%- endcomment -%}
{%- assign vok = false -%}
{%- if r.cve and r.added -%}{%- assign cve_head = r.cve | slice: 0, 4 -%}{%- assign added_len = r.added | size -%}{%- if cve_head == "CVE-" and added_len == 10 -%}{%- assign vok = true -%}{%- endif -%}{%- endif -%}
{%- if vok -%}
{%- assign cisa_len = r.cisa_added | size -%}{%- assign ev_len = r.evidence | size -%}{%- comment -%} A score is drawn only with a known band and a score beside it; Liquid has no operator precedence, so the band test is a contains on the list. {%- endcomment -%}{%- assign sev = "none" -%}{%- assign cvss_len = r.cvss | size -%}{%- if cvss_len > 0 -%}{%- if sev_bands contains r.severity -%}{%- assign sev = r.severity -%}{%- endif -%}{%- endif -%}
{%- comment -%} T-0667: the row's day is its event day (the latest exploitation event). A row from a wire.yml written before it carries no event and keeps its added day. {%- endcomment -%}
{%- assign vday = r.event | default: r.added -%}
{%- assign np_r = r.np_rank | plus: 0 -%}{%- assign is_np = false -%}{%- if np_r > 0 -%}{%- assign is_np = true -%}{%- endif -%}
{%- assign is_canary = false -%}{%- if r.canary == true -%}{%- assign is_canary = true -%}{%- endif -%}{%- assign is_ransom = false -%}{%- if r.ransomware == true -%}{%- assign is_ransom = true -%}{%- endif -%}
{%- assign row_sig = "" | split: "" -%}{%- if is_np -%}{%- assign row_sig = row_sig | push: "np" -%}{%- endif -%}{%- if is_canary -%}{%- assign row_sig = row_sig | push: "canary" -%}{%- endif -%}{%- if is_ransom -%}{%- assign row_sig = row_sig | push: "ransomware" -%}{%- endif -%}
{%- assign ev_src = r.event_src | default: "" -%}{%- assign is_dated = false -%}{%- if vday != r.added -%}{%- assign is_dated = true -%}{%- endif -%}
{%- comment -%} T-0667 F3: a CISA-only row is the exporter's explicit cisa_only key; a wire.yml from before the key has none. {%- endcomment -%}{%- assign ev_cisaonly = false -%}{%- if r.cisa_only == true -%}{%- assign ev_cisaonly = true -%}{%- endif -%}
{%- assign cve_parts = r.cve | split: "-" -%}{%- assign cve_year = cve_parts[1] -%}
{%- comment -%} T-0407 pointers. A row from a wire.yml written before them carries none and draws none. {%- endcomment -%}
{%- assign det = "" | split: "" -%}{%- assign n_sids = r.et_sids | size -%}{%- assign nu_len = r.nuclei | size -%}
{%- comment -%} T-0496: CISA Sigma rule files and Snort 3 community SIDs. A row from a wire.yml written before them carries neither and counts none. One Rules chip carries them all. {%- endcomment -%}
{%- assign rn_cs = r.cisa_sigma | size -%}{%- assign rn_sn = r.snort3_sids | size -%}{%- assign rn_nu = 0 -%}{%- if nu_len > 0 -%}{%- assign rn_nu = 1 -%}{%- endif -%}
{%- assign rn_rules = n_sids | plus: rn_nu | plus: rn_cs | plus: rn_sn -%}
{%- if n_sids > 0 -%}{%- assign det = det | push: "et" -%}{%- endif -%}{%- if nu_len > 0 -%}{%- assign det = det | push: "nuclei" -%}{%- endif -%}{%- if rn_cs > 0 -%}{%- assign det = det | push: "cisa" -%}{%- endif -%}{%- if rn_sn > 0 -%}{%- assign det = det | push: "snort3" -%}{%- endif -%}
{%- comment -%} T-0468: days from NVD publication to the KEV add (negative: VulnCheck listed it first), and EPSS. A row from a wire.yml written before them carries none and draws none. Liquid has no integer test, so the gap is read through a string. {%- endcomment -%}
{%- assign gap_str = r.gap | append: "" -%}{%- assign gap_len = gap_str | size -%}{%- assign gap_n = 0 -%}{%- assign gap_abs = 0 -%}{%- assign nvd_key = "" -%}
{%- if gap_len > 0 -%}{%- assign gap_n = r.gap | plus: 0 -%}{%- if gap_n < 0 -%}{%- assign nvd_key = "pre" -%}{%- assign gap_abs = gap_n | times: -1 -%}{%- endif -%}{%- endif -%}
{%- assign epss_len = r.epss | append: "" | size -%}{%- assign epss_pre_len = r.epss_pre | append: "" | size -%}{%- assign spark_len = r.epss_spark | append: "" | size -%}{%- assign rn_len = r.ratio_now | append: "" | size -%}{%- assign rp_len = r.ratio_pre | append: "" | size -%}
{%- assign n_reps = r.reports | size -%}{%- assign n_more = r.reports_more | default: 0 | plus: 0 -%}{%- assign n_st = r.stories | default: 0 -%}
<div class="hl-vuln" id="cve-{{ r.cve | downcase | escape }}" data-prio="{{ r.prio | escape }}" data-title="{{ r.cve | downcase | escape }} {{ r.vendor | downcase | escape }} {{ r.product | downcase | escape }} {{ r.title | downcase | escape }}{% if is_np %} priority {{ r.np_class | downcase | escape }}{% endif %}{% if is_canary %} vulncheck canary{% endif %}{% if is_ransom %} ransomware{% endif %}" data-list="{% if cisa_len == 10 %}cisa{% else %}vconly{% endif %}" data-vendor="{{ r.vendor | escape }}" data-age="{% if r.older == true %}older{% else %}recent{% endif %}" data-sev="{{ sev | escape }}" data-det="{{ det | join: '|' | escape }}" data-nvd="{{ nvd_key | escape }}"{% if row_sig.size > 0 %} data-sig="{{ row_sig | join: '|' | escape }}"{% endif %} data-day="{{ vday | escape }}">{% comment %} T-0532: the Details toggle, first in the row, hidden until the script removes it. {% endcomment %}<button type="button" class="hl-dt" aria-expanded="false" hidden title="Show details"><span class="hl-dt__sr">Details</span></button><a class="hl-vuln__cve" href="https://nvd.nist.gov/vuln/detail/{{ r.cve | escape }}" target="_blank" rel="noopener noreferrer">{{ r.cve | escape }}</a><span class="hl-vuln__vp" title="{{ r.vendor | escape }} {{ r.product | escape }}">{% if r.vendor and r.vendor != "" %}<b>{{ r.vendor | escape }}</b> {{ r.product | escape }}{% else %}<span class="hl-vuln__none">vendor not given</span>{% endif %}{% if r.title and r.title != "" %} {{ r.title | escape }}{% endif %}</span><span class="hl-vuln__badges">{% include wire-nkev-priority.html %}{% include wire-vuln-sev.html %}{% if cisa_len == 10 %}<span class="hl-vuln__b hl-vuln__b--cisa" title="Added to CISA KEV {{ r.cisa_added | escape }}{% if r.kev_due and r.kev_due != '' %}; CISA due date {{ r.kev_due | escape }}{% endif %}">CISA KEV</span>{% endif %}{% comment %} T-0667: a row under a later day than VulnCheck's shows both dates, worded by what set its day; a row built from the CISA catalog alone says so. {% endcomment %}{% if ev_cisaonly and is_dated %}{% assign dt_ev = vday | date: "%-d %b" %}{% assign dt_ca = r.cisa_added | date: "%-d %b" %}<span class="hl-vuln__ev hl-vuln__dates" title="CISA lists this CVE in its KEV catalog (added {{ r.cisa_added | escape }}) and VulnCheck's KEV catalog does not. I first published it here on {{ r.event | escape }}, so I list it under that day.">First seen here {{ dt_ev | escape }} &middot; CISA KEV {{ dt_ca | escape }} &middot; not in VulnCheck KEV</span>{% elsif is_dated %}{% assign dt_ev = vday | date: "%-d %b" %}{% assign dt_vc = r.added | date: "%-d %b" %}{% if ev_src == "cisa" %}<span class="hl-vuln__ev hl-vuln__dates" title="CISA added this CVE to its KEV catalog on {{ r.event | escape }}, after VulnCheck's date of {{ r.added | escape }}. I list it under the later day.">CISA KEV {{ dt_ev | escape }} &middot; VulnCheck {{ dt_vc | escape }}</span>{% elsif ev_src == "first_seen" %}<span class="hl-vuln__ev hl-vuln__dates" title="VulnCheck dates this CVE {{ r.added | escape }}, but I first published it here on {{ r.event | escape }}. I list it under the day it reached me.">First seen here {{ dt_ev | escape }} &middot; VulnCheck dated {{ dt_vc | escape }}</span>{% else %}<span class="hl-vuln__ev hl-vuln__dates" title="Latest exploitation event {{ r.event | escape }}; VulnCheck dates this CVE {{ r.added | escape }}.">Latest event {{ dt_ev | escape }} &middot; VulnCheck {{ dt_vc | escape }}</span>{% endif %}{% elsif ev_cisaonly %}{% assign dt_ev = vday | date: "%-d %b" %}<span class="hl-vuln__ev hl-vuln__dates" title="CISA lists this CVE in its KEV catalog (added {{ r.cisa_added | escape }}) and VulnCheck's KEV catalog does not. I list it under the CISA day.">CISA KEV {{ dt_ev | escape }} &middot; not in VulnCheck KEV</span>{% endif %}{% if is_canary %}<span class="hl-vuln__b hl-vuln__b--canary" title="VulnCheck's own canary network recorded exploitation of this CVE. It is VulnCheck's flag, not a statement from CISA or the vendor. It adds no Priority points.">VulnCheck canary</span>{% endif %}{% if is_ransom %}<span class="hl-vuln__b hl-vuln__b--ransom" title="Marked as used in known ransomware campaigns, by VulnCheck's KEV data or CISA's KEV catalog. It adds no Priority points.">Ransomware</span>{% endif %}{% comment %} evidence is the earliest citation date; drawn only when it says something the day heading does not. {% endcomment %}{% if ev_len == 10 and r.evidence < r.added %}<span class="hl-vuln__ev">evidence {{ r.evidence | escape }}</span>{% endif %}{% if gap_len > 0 and r.disclosed != "" %}<span class="hl-vuln__gap-fact">{% if gap_n == 0 %}listed on the day of disclosure{% else %}{% assign gap_d = gap_n %}{% if gap_n < 0 %}{% assign gap_d = gap_abs %}{% endif %}listed {{ gap_d | escape }} day{% if gap_d != 1 %}s{% endif %} {% if gap_n < 0 %}before{% else %}after{% endif %} disclosure{% endif %}</span>{% endif %}{% include wire-vuln-epss.html %}{% include wire-vuln-vedas.html %}{% comment %} T-0407 pointers as compact chips, one line per row: the reports VulnCheck cites open from a click (a native details element, no script), the headline count links to the Headlines search, Rules N opens the public rules (ET Open, Nuclei, CISA Sigma, Snort 3 community) that name the CVE. {% endcomment %}{% if n_reps > 0 %}{% assign n_src = n_reps | plus: n_more %}<details class="hl-vuln__pop"><summary class="hl-vuln__p" title="Exploitation reported by {{ n_src }} source{% if n_src != 1 %}s{% endif %} VulnCheck cites">{{ n_src }} src</summary><span class="hl-vuln__popbody">Reported by{% for rp in r.reports %}{% assign rp_head = rp.url | slice: 0, 8 %}{% if rp_head == "https://" %}<a href="{{ rp.url | escape }}" target="_blank" rel="noopener noreferrer nofollow">{{ rp.host | escape }}</a>{% endif %}{% endfor %}{% if n_more > 0 %}<span class="hl-vuln__dim">+{{ n_more }} more in VulnCheck KEV</span>{% endif %}</span></details>{% endif %}{% include wire-vuln-news.html %}{% include wire-vuln-rules.html %}{% include wire-vuln-new.html %}</span>{% if is_np %}<div class="hl-vuln__pick hl-vuln__np"><span class="hl-pick__score" title="Priority {{ r.np_score | plus: 0 }}. This is my patch-first score: the points the row earned from the reasons beside it. More points rank higher. It ranks exploited flaws; it does not predict anything.">Priority {{ r.np_score | plus: 0 }}</span>{% for t in r.np_reasons %}{% case t %}{% when "noauth" %}<span class="hl-pick__chip hl-pick__chip--noauth" title="The CVSS vector says network reachable, no privileges needed and no user interaction. Worth 1 point.">No login</span>{% when "critical" %}<span class="hl-pick__chip hl-pick__chip--critical" title="The CVSS score is 9.0 or higher. Worth 1 point.">CVSS 9+</span>{% when "class" %}<span class="hl-pick__chip hl-pick__chip--class" title="The product belongs to one of my patch-first product classes: {% if r.np_class and r.np_class != "" %}{{ r.np_class | escape }}{% else %}class not named{% endif %}. Worth 2 points, or 1 for an operating system or browser.">{% if r.np_class and r.np_class != "" %}{{ r.np_class | escape }}{% else %}Product class{% endif %}</span>{% when "tooling" %}<span class="hl-pick__chip hl-pick__chip--tooling" title="A Metasploit module, an Exploit-DB entry, a Nuclei template or an ET Open rule names this CVE. Worth 1 point. I have not tested any of them.">Public tooling</span>{% when "cisa" %}<span class="hl-pick__chip hl-pick__chip--cisa" title="The CVE is also on CISA's KEV catalog. Worth 1 point.">CISA KEV</span>{% when "fresh" %}<span class="hl-pick__chip hl-pick__chip--fresh" title="The flaw was disclosed under 30 days before VulnCheck listed it. Worth 1 point.">New flaw</span>{% endcase %}{% endfor %}</div>{% endif %}</div>
{%- endif -%}
{%- endcapture -%}
{%- assign rendered_rows = rendered_rows | push: rendered_row -%}
{%- endfor -%}
{%- include wire-fold-keys.html rows=group_rows mode="nkev" -%}
{%- include wire-fold.html rows=rendered_rows keys=fold_keys labels=fold_labels thresholds=fold_thresholds -%}
</div>
{%- endfor -%}
{%- comment -%} the added days older than the oldest group {%- endcomment -%}
{%- for ad in alias_days -%}{%- assign ad_key = "|" | append: ad | append: "|" -%}{%- unless alias_done contains ad_key -%}<div class="hl-wire__dayalias" id="vulns-{{ ad | escape }}" data-day-target="{{ ad | escape }}"></div>{%- endunless -%}{%- endfor -%}
</div>

{%- comment -%} T-0468.2: the heading is a details summary, so a reader can fold the legend out of the way and open it again. Open on load. {%- endcomment -%}
<aside class="hl-post-toc hl-legend" aria-label="Legend" tabindex="0" data-pagefind-ignore>
<details class="hl-legend__fold" open>
<summary class="hl-post-toc__heading" title="Show or hide the legend">Legend</summary>
<div class="hl-legend__body">{{ legend_html }}{{ np_legend }}{{ ev_legend }}</div>
</details>
</aside>

{%- else -%}

<p class="hl-wire__freshness"><span class="hl-wire__notice">Vulnerability data is temporarily unavailable.</span> The headlines are unaffected; this tab fills again on the next successful read, which runs every 15 minutes.</p>

{%- endif %}
</section>

<section id="cves" class="hl-wtabs__sec" data-filter-scope data-details="{{ '/wire/details-cves.json' | relative_url }}?v={{ wire.cves_generated_at | default: wire.generated_at | escape }}">
<details class="hl-wire-explanation" id="cves-explanation" data-pagefind-ignore>
<summary>Explanation and data used</summary>
<div class="hl-wire-explanation__body">


<p>I use this tab to pick CVEs likely to be exploited soon out of the flood of disclosures. It covers recent publications absent from both VulnCheck KEV and CISA KEV. Admission is a selection signal, not evidence that exploitation has happened. A CVE moves to the nKEVs tab when it is added to VulnCheck KEV or CISA KEV.</p>
<h3>Priority picks</h3>
<p>The strip at the top of this tab links to my latest daily picks, and every pick stays in the day its CVE was published. The Priority picks are my daily shortlist. Each day I add three new picks from the CVEs published in the last 30 days that are on neither VulnCheck KEV nor CISA KEV. A pick stays until it is 30 days past publication or is listed as exploited, and then it leaves, as every row does.</p>
<p>I score each eligible CVE by adding points from three factors. For likelihood, a public proof of concept in nomi-sec's index earns 1, SSVC exploitation of poc or active earns 1, an EPSS percentile of 0.90 or higher earns 1, and a Metasploit module, an Exploit-DB entry, a Nuclei template or an ET Open rule earns 2 in total, however many exist. For impact, network reachable with no privileges and no user interaction earns 1, and a CVSS score of 9.0 or higher earns 1. For product class, a product in one of my hand-kept classes earns 2: edge and network devices, file transfer, IT and remote management, identity and access, virtualization and backup, email and collaboration, enterprise applications, and CMS cores. Operating systems and browsers earn 1.</p>
<p>The three highest scores each day become the picks. Ties go to the higher CVSS score, then the higher EPSS percentile, then the higher CVE id. A CVE with a CVSS score of 7.0 or higher is eligible. A CVE with a lower score is eligible only when it carries exploit evidence: a proof of concept listing, SSVC poc or active, an exploit tool or rule, or an EPSS percentile of 0.90 or higher. A CVE with no score is not eligible. Each pick shows its score as "Priority" and a number, one chip for each factor that earned points (hover a chip for what it means), the class label, and the day I picked it.</p>
<p>A CVE that is both a pick and admitted by one of the reasons below shows once, in its day, with its pick score. The picks sit outside its cap of 250 rows. In my replay the 3 a day rule held about 65 picks on the tab at a time, and up to about 90.</p>
<p>I measured this rule by replaying it day by day over pick days from 6 February 2025 to 30 September 2026. Of the picks old enough to judge, 10.3% were on VulnCheck KEV within 90 days of the pick and 3.3% were on CISA KEV. Those shares include picks below CVSS 7.0 that carried exploit evidence. The picks also caught about 4 in 10 of the CVEs later listed: 146 of the 353 CVEs published between 6 February 2025 and 7 August 2026 that VulnCheck KEV listed within 90 days of publication, and 48 of the 187 that CISA KEV listed. That 4 in 10 figure was measured with the CVSS 7.0 floor, before I admitted lower-scored CVEs, so it does not describe the rule as shown here.</p>
<p>I kept three a day because larger caps did not pay. In the 30 day view, picks ranked 4 and 5 reached VulnCheck KEV at 1.5%, against 9.3% for the top 3. I also tested using CISA KEV history of the vendor or product in place of my class list, and it did worse, so I kept the list.</p>
<p>These are the limits. The replay was not blind: I built the rule on the same periods I measured, tuned the class list after seeing results, and chose to admit lower-scored CVEs after seeing which later-exploited CVEs the floor had missed, so the p-values do not account for that. The gain from admitting lower-scored CVEs came in the two earlier periods, and for CISA KEV it is 3 CVEs. The first set of picks is a start-up set, marked as such, and it is left out of the test. From now on I log every live pick with its day and factors, and I will score those picks against KEV listings no earlier than 90 days after the first daily pick. A pick is a priority, not evidence of exploitation.</p>
<h3>Just published</h3>
<p>A CVE published yesterday has none of the evidence the reasons below wait for: no Metasploit module, no Nuclei template and no EPSS history yet. So each of the last seven published days shows its three highest ranked CVEs as Just published rows, whatever the reasons say. A row stays in the day its CVE was published, and the newest days sit at the top of the tab. A CVE qualifies when it is on neither KEV list, has a CVSS score of 7.0 or higher and was published in those seven days. I rank it on what a new CVE already has. A product in one of my classes earns 2 points (1 for an operating system or browser), and each of these earns 1: a CVSS score of 9.0 or higher, network reachable with no login, a public proof of concept in nomi-sec's index, and SSVC exploitation of poc or active. Ties go to the higher CVSS score, then the higher CVE id. A day with fewer than three qualifying CVEs shows fewer.</p>
<p>These rows are new and unproven. They are ranked on product and severity, and there is no evidence of exploitation for them yet. A Just published row is a place to look first, not a sign that anyone is attacking it. Each one shows "Just published", its score and one chip for each factor that earned points. A CVE that is also a priority pick, or admitted by one of the reasons below, shows once with all of its chips. The rows sit outside the cap of 250 and are worked out again on every run, so a row leaves the tab when its day is more than seven days old unless a pick or a reason below keeps it.</p>
<h3>The admission reasons beside the picks</h3>
<p>Any one of the seven reasons admits a CVE. FIRST's Exploit Prediction Scoring System (EPSS) percentile of at least 0.90 puts it in the top 10% for predicted exploitation likelihood. That is a relative rank, not a 90% probability. The other score-based reason pairs EPSS probability of at least 1% with A.R.P. Syndicate's VEDAS exploit-maturity estimate of at least 80% and a Common Vulnerability Scoring System (CVSS) score of at least 7.0. I require the pair because VEDAS alone performed below the cohort's exploitation rate in my replay.</p>
<p>A Metasploit module confirmed in Rapid7's index, an Exploit-DB entry confirmed in its publisher's index, a ProjectDiscovery Nuclei template, or an Emerging Threats ET Open rule each also admits a CVE. These identify available tooling or detection coverage. I have not tested the exploits, and a template or rule naming a CVE does not establish exploitation.</p>
<p>I treat a CVE as WordPress-class when its source identifies Wordfence, WPScan or Patchstack, or its affected product names WordPress. I admit these CVEs when the description says unauthenticated and the CWE falls in five weakness groups: SQL injection, file upload, privilege escalation, path traversal or local file inclusion, and server-side request forgery. In my longer replay, the added rows later listed as exploited were 8.3% on the 2025 design set, 7.0% on the January to June 2026 test set and 6.4% on the July to September comparison. I chose this addition after seeing the data; these are measured shares, not promised hit rates.</p>
<p>I fold two or more WordPress plugin CVEs admitted only by the no login rule on the same day into one line, and I fold five or more same-day CVEs for the same product into one line.</p>
<p>The PoC on GitHub chip links only to nomi-sec's own per-CVE JSON index (CC0), never to the repositories it lists. I have not tested that code. Pairing this index with no privileges required added rows with later-exploited shares of 6.3%, 8.6% and 3.7% on the same sets. It does not admit a CVE: at today's measured volume the union would have pushed 123 of 244 new-arm-only rows (50%) past the cap, exceeding my pre-set one-third trigger for keeping only the WordPress addition.</p>
<p>My July to September 2026 replay judged 36,786 eligible CVEs once, seven days after publication, using the inputs available then. Later exploitation means a VulnCheck KEV addition after that point, through 5 November 2026: 116 CVEs met that outcome. The EPSS percentile reason selected 24 CVEs, three later listed; the EPSS and VEDAS pair selected 40, four later listed; tooling selected 53, eight later listed. Together they selected 102, with 12 later listed. These sets overlap, so their counts do not add.</p>
<p>Those are small, in-sample results, not promised hit rates. July VEDAS history was unavailable; 323 eligible CVEs could not be judged for the paired reason. The replay took one look at day seven, while the live list rechecks throughout its publication window. Follow-up is shorter for later publications; October was too recent to judge.</p>
<p>I retired the reason combining CVSS at least 9.0, network access with no login or user action, and a product previously on CISA KEV. It selected 267 CVEs in the same replay, only three later listed. That volume bought little coverage. For the past dates I used the CVSS scores as written in the CVE record at the time, because the live source's own history was not available, so this is a bounded result. The "product on CISA KEV before" chip remains context about the product, not this CVE.</p>
<p>Severity, standalone EPSS probability or maturity, news counts, SSVC assessments, fixed versions and advisory identifiers add context without independently admitting rows. The Rules chip also includes CISA Sigma and Snort 3 coverage, which do not admit CVEs. I combine the admission reasons by showing at most 250 rows, not counting the priority picks and the Just published rows, which sit in their own days and outside that cap, with baseline-admitted rows first and WordPress-only additions after them; inside each tier I rank by number of reasons met, then EPSS, exploit maturity and CVSS; publication-day headings organize the display. Missing chips mean missing confirmed data, not proof of absence.</p>
<p>I also tested other sources and left them out. Some did not separate later exploited CVEs from the rest in my replay, or rarely touch the CVEs shown here: CIRCL community sightings, unrestricted GitHub repository search and Microsoft's Exploitability Index. One forbids reproducing its values (the CrowdSec CVE tracker). One asks automated clients not to fetch it and keeps no history (WordPress.org plugin install counts). Two publish no dated feed per CVE (Shadowserver, Google Project Zero's tracker).</p>
<h3>Reading the data and filters</h3>

<div class="hl-wire-data__h">Reading a row</div>
<dl class="hl-wire-data__list">
<dt><span class="hl-vuln__cve">CVE-YYYY-NNNN</span></dt>
<dd>The CVE. It opens its NVD record in a new tab.</dd>
<dt><span class="hl-vuln__vp"><b>Vendor</b> Product</span></dt>
<dd>The vendor and product, as the CVE record names them. A CVE record that names none shows none. Hover it for the first sentence of the CVE record, as its CNA wrote it; I do not use cve.now's model-written summaries.</dd>
<dt><span class="hl-vuln__sev hl-vuln__sev--critical">CRITICAL 9.8</span></dt>
<dd>The CVSS base score in the CVE's NVD record, read through VulnCheck NVD++ unless the row says cve.now, as on the nKEVs tab. Hover it for the CVSS vector. When our NVD data holds no score, the chip uses cve.now's score and vector and the hover says so. A CVE with no score at all shows no chip.</dd>
<dt><span class="hl-vuln__w hl-vuln__w--kev">KEV product</span></dt>
<dd>The product has earlier entries in CISA's KEV catalog. This context stays on the row; it supplies no admission reason.</dd>
<dt><span class="hl-vuln__w hl-vuln__w--nuclei">Nuclei</span> <span class="hl-vuln__w hl-vuln__w--et">ET Open</span></dt>
<dd>Nuclei templates come from ProjectDiscovery's template index; ET Open rules come from Emerging Threats' Suricata ruleset. In my July to September 2026 replay, judged seven days after publication, the tooling reasons together admitted 53 CVEs, eight later listed on VulnCheck KEV; Nuclei accounted for seven of 34. These are small, in-sample counts, not promised hit rates.</dd>
<dt><span class="hl-vuln__w hl-vuln__w--msf">Metasploit</span> <span class="hl-vuln__w hl-vuln__w--edb">Exploit-DB</span></dt>
<dd>A Metasploit module, or an Exploit-DB entry, exists for the CVE, confirmed against Rapid7's or Exploit-DB's own list.</dd>
<dt><span class="hl-vuln__w hl-vuln__w--epss">EPSS top 10%</span></dt>
<dd>FIRST's EPSS puts the CVE in the top 10% for predicted likelihood of being exploited in the next 30 days.</dd>
<dt><span class="hl-vuln__p hl-vuln__p--epss">EPSS 3%</span></dt>
<dd>The EPSS probability itself. The popover shows the last 30 days as a line and today's value.</dd>
<dt class="hl-wire-data__k">VEDAS (exploit maturity)</dt>
<dd><p>A.R.P. Syndicate describes VEDAS as &ldquo;Estimation of Vulnerability Prevalence &amp; Exploit Maturity&rdquo;. Its README names OSINT from <a href="https://www.exploit.observer/" target="_blank" rel="noopener noreferrer">Exploit Observer</a>, coverage of 150+ identifiers and updates every 6 to 8 hours. The source publishes no formula.</p><p>On the CVEs tab, I pair EPSS at least 1% with VEDAS at least 80% and CVSS at least 7.0 for the EPSS + VEDAS reason. </p><p>A high score is not evidence that working exploit code exists or that the CVE has been exploited; exploitation is what the nKEVs tab and CISA KEV are for. An unscored CVE shows no VEDAS chip.</p></dd>
<dt><span class="hl-vuln__p">2 news</span></dt>
<dd>Wire headlines that name the CVE. It opens the Headlines tab searched for it.</dd>
<dt><span class="hl-vuln__p hl-vuln__p--det">Rules 2</span></dt>
<dd>Public detection rules that name the CVE, counted across ET Open (Suricata), Nuclei templates, CISA's SIGMA_Rules and the Snort 3 community ruleset. Click the chip in a row to list them.</dd>
<dt><span class="hl-vuln__p hl-vuln__p--ssvc">SSVC</span></dt>
<dd>CISA's own assessment of the CVE, from its Stakeholder-Specific Vulnerability Categorization (SSVC): exploitation, automatable and technical impact. They are CISA's decision points, not mine. cve.now carries them (CISA Vulnrichment), with the fixed version and the GitHub Security Advisory (GHSA) and EU Vulnerability Database (EUVD) ids where it has them. A CVE without them shows no chip.</dd>
<dt><span class="hl-vuln__p hl-vuln__p--exp">Exploits 2</span></dt>
<dd>Public exploits for the CVE that I confirmed against the publisher's own index: a Metasploit module appears only when Rapid7's module list names the CVE, and an Exploit-DB entry only when Exploit-DB's own list does. Both open their pages. I have not tested any exploit. A CVE can be listed with none of these when one of the other reasons on its row admitted it; a missing chip does not mean no exploit exists, only that I could not confirm one.</dd>
<dt><span class="hl-pick__score">Priority 6</span></dt>
<dd>The CVE is a priority pick, and the number is the points it scored when I picked it. More points rank higher. Hover it for the rule.</dd>
<dt><span class="hl-pick__chip hl-pick__chip--tooling">Exploit tooling</span> <span class="hl-pick__chip hl-pick__chip--nomi">PoC on GitHub</span> <span class="hl-pick__chip hl-pick__chip--class">Product class</span></dt>
<dd>One chip for each factor that earned points: exploit tooling, a PoC listing, SSVC exploitation, EPSS in the top 10%, network reachable with no login, CVSS 9.0 or higher, and the product class. A Just published row can show the PoC listing, SSVC exploitation, no login, CVSS and product class chips only, since a new CVE has no tooling or EPSS history yet. Hover a chip to read what it means.</dd>
<dt><span class="hl-pick__score hl-pick__score--fresh">Just published 4</span></dt>
<dd>The CVE is one of the three highest ranked from a day in the last seven, and the number is the points it scored on its product and severity. It is new and unproven: the rank rests on the product and the severity, and there is no evidence of exploitation yet. Hover it for the rule.</dd>
<dt><span class="hl-pick__date">picked 14 November 2026</span></dt>
<dd>The day I picked it. A start-up pick carries a "start-up pick" chip: it came from the first set I seeded, not from a daily pick.</dd>
<dt><span class="hl-vuln__p hl-vuln__p--cn">cve.now</span></dt>
<dd>The CVE's page on cve.now.</dd>
</dl>
<div class="hl-wire-data__h">Using the filters</div>
<dl class="hl-wire-data__list">
<dt class="hl-wire-data__k">Search</dt>
<dd>Matches the CVE id, vendor, product, the first sentence of the CVE record and the text of the row's chips, so a word such as "listed" or "days" also matches rows through their chips.</dd>
<dt class="hl-wire-data__k">Why listed</dt>
<dd>Priority picks narrows to the picks group, and Just published narrows to the Just published rows, which no admission reason selects. The seven admission reasons the rows show: a Metasploit module, an Exploit-DB entry, a Nuclei template, an ET Open rule, EPSS in the top 10%, EPSS at least 1% paired with VEDAS exploit maturity at least 80% and CVSS at least 7.0, or a WordPress plugin or theme CVE that needs no login (WordPress unauthenticated). The Rules chip also lists CISA Sigma and Snort 3 community rules as context.</dd>
<dt class="hl-wire-data__k">Severity</dt>
<dd>The band of the row's CVSS score. It appears only when more than one band is present.</dd>
<dt class="hl-wire-data__k">Vendor</dt>
<dd>Narrows to one or more vendors.</dd>
</dl>
<p class="hl-wire-data__p">Picking several chips in one row shows any of them; picking chips in different rows narrows to rows that match all. The filters are kept in the page address, so a filtered view can be shared by copying the link.</p>
<div class="hl-wire-data__h">About this data</div>
<p class="hl-wire-data__p">I choose which CVEs appear here, by the rule in this panel. The priority picks and the Just published rows sit in their own days and outside its cap. Beyond them I show at most 250 rows. When more qualify, baseline-admitted rows rank first; inside each tier I rank by how many reasons they meet, then by EPSS, then by exploit maturity, then by CVSS.</p>
<p class="hl-wire-data__p">The CVE listing, titles, SSVC decision points (CISA's own assessment, from <a href="https://github.com/cisagov/vulnrichment" target="_blank" rel="noopener noreferrer">Vulnrichment</a>), fixed versions and advisory ids come from <a href="https://cve.now/" target="_blank" rel="noopener noreferrer">cve.now</a> (CC BY 4.0). CVSS scores and vectors come from the CVE's NVD record through VulnCheck, mostly the CNA's score, unless the row says cve.now.</p>
<p class="hl-wire-data__p">Metasploit modules come from Rapid7's <a href="https://github.com/rapid7/metasploit-framework" target="_blank" rel="noopener noreferrer">metasploit-framework</a> module index and Exploit-DB entries from <a href="https://www.exploit-db.com/" target="_blank" rel="noopener noreferrer">Exploit-DB</a>'s own index. "Product on CISA KEV" comes from CISA's <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer">KEV catalog</a>. EPSS scores are FIRST's (<a href="https://www.first.org/epss/" target="_blank" rel="noopener noreferrer">first.org/epss</a>), generated by Empirical Security. VEDAS exploit maturity from <a href="https://github.com/ARPSyndicate/cve-scores" target="_blank" rel="noopener noreferrer">A.R.P. Syndicate</a>.</p>

</div>
</details>
{%- assign cstatus = wire.cves_status | default: "unavailable" -%}
{%- assign sev_bands = "critical,high,medium,low" | split: "," -%}

{%- comment -%}
  T-0522: the CVEs tab. Significant new CVEs that are not yet on a KEV list, chosen by the
  exporter's rule (stated in the callout below, in the reader's words) and listed with the
  enrichment we hold. It reuses the nKEV row's chips through the shared includes
  (wire-vuln-*.html) and the nKEV page's classes, so the CSS and listing-filter.js are shared.
  Differences from the nKEV rows: the rows are grouped by the day the CVE was PUBLISHED, there
  is no KEV add to compare EPSS against (the include's cve_mode), the first sentence of the
  CVE record sits under the row, and the filter axes are signal, severity and vendor. The
  model-written summaries cve.now carries are never read here. Absent fields draw nothing.
{%- endcomment -%}
<p class="hl-wire__freshness hl-wire__freshness--c">Significant new CVEs not yet on a KEV list, published in the last {{ wire.window_days }} days &middot; VEDAS exploit maturity from <a href="https://github.com/ARPSyndicate/cve-scores" target="_blank" rel="noopener noreferrer">A.R.P. Syndicate</a> &middot; <a href="{{ '/wire/cves.xml' | relative_url }}">Atom feed (CVEs)</a></p>



{%- assign cshow = false -%}
{%- if wire.cves and wire.cves != empty -%}{%- if cstatus == "ok" or cstatus == "stale" -%}{%- assign cshow = true -%}{%- endif -%}
{%- endif -%}
{%- if cshow -%}

{%- if cstatus == "stale" -%}
<p class="hl-wire__freshness"><span class="hl-wire__notice">CVE data last updated {{ wire.cves_generated_at | date: "%-d %B %Y, %H:%M" | escape }} UTC.</span></p>
{%- endif -%}

{%- comment -%}
  Counts for the filter chips, taken from the rows themselves in one pass: the chips and the
  rows they filter must agree, and the exporter's counts can use other names. check-wire.js
  compares the exporter's declared counts with the rows separately.
{%- endcomment -%}
{%- assign c_kp = 0 -%}{%- assign c_wp = 0 -%}{%- assign c_nuclei = 0 -%}{%- assign c_et = 0 -%}{%- assign c_msf = 0 -%}{%- assign c_edb = 0 -%}{%- assign c_epss = 0 -%}{%- assign c_vedas = 0 -%}
{%- assign c_pick = 0 -%}{%- assign c_fresh = 0 -%}
{%- assign c_critical = 0 -%}{%- assign c_high = 0 -%}{%- assign c_medium = 0 -%}{%- assign c_low = 0 -%}{%- assign c_none = 0 -%}
{%- for r in wire.cves -%}
{%- assign cve_head = r.cve | slice: 0, 4 -%}
{%- if cve_head == "CVE-" -%}
{%- include wire-cve-why.html -%}
{%- assign pd_len = r.pick_day | append: "" | size -%}{%- if pd_len > 0 -%}{%- assign c_pick = c_pick | plus: 1 -%}{%- endif -%}
{%- comment -%} T-0665: a Just published row, counted from the rows like every other chip. {%- endcomment -%}
{%- if r.fresh == true -%}{%- assign c_fresh = c_fresh | plus: 1 -%}{%- endif -%}
{%- if kp_len > 0 and kn > 0 -%}{%- assign c_kp = c_kp | plus: 1 -%}{%- endif -%}{%- if w_wp -%}{%- assign c_wp = c_wp | plus: 1 -%}{%- endif -%}{%- if w_nuclei -%}{%- assign c_nuclei = c_nuclei | plus: 1 -%}{%- endif -%}{%- if w_et -%}{%- assign c_et = c_et | plus: 1 -%}{%- endif -%}{%- if w_msf -%}{%- assign c_msf = c_msf | plus: 1 -%}{%- endif -%}{%- if w_edb -%}{%- assign c_edb = c_edb | plus: 1 -%}{%- endif -%}{%- if w_epss -%}{%- assign c_epss = c_epss | plus: 1 -%}{%- endif -%}{%- if w_vedas -%}{%- assign c_vedas = c_vedas | plus: 1 -%}{%- endif -%}
{%- assign cvss_len = r.cvss | size -%}{%- assign sev = "none" -%}{%- if cvss_len > 0 -%}{%- if sev_bands contains r.severity -%}{%- assign sev = r.severity -%}{%- endif -%}{%- endif -%}
{%- case sev -%}{%- when "critical" -%}{%- assign c_critical = c_critical | plus: 1 -%}{%- when "high" -%}{%- assign c_high = c_high | plus: 1 -%}{%- when "medium" -%}{%- assign c_medium = c_medium | plus: 1 -%}{%- when "low" -%}{%- assign c_low = c_low | plus: 1 -%}{%- else -%}{%- assign c_none = c_none | plus: 1 -%}{%- endcase -%}
{%- endif -%}
{%- endfor -%}
{%- assign c_bands = 0 -%}
{%- if c_critical > 0 -%}{%- assign c_bands = c_bands | plus: 1 -%}{%- endif -%}{%- if c_high > 0 -%}{%- assign c_bands = c_bands | plus: 1 -%}{%- endif -%}{%- if c_medium > 0 -%}{%- assign c_bands = c_bands | plus: 1 -%}{%- endif -%}{%- if c_low > 0 -%}{%- assign c_bands = c_bands | plus: 1 -%}{%- endif -%}{%- if c_none > 0 -%}{%- assign c_bands = c_bands | plus: 1 -%}{%- endif -%}

{%- comment -%}
  The legend, captured once and printed twice exactly as the nKEVs legend is (T-0468.1):
  an aside in the right margin on a wide screen, a collapsed details on a narrow one. Plain
  spans only: no links of its own except attribution, no data-* attributes, no ids, and both
  copies sit outside data-filter-grid and the filter bar. check-wire.js holds all of that.
{%- endcomment -%}
{%- capture cves_legend_html -%}
<div class="hl-legend__h">Chip key</div>
<dl class="hl-legend__list">
<dt><span class="hl-vuln__cve">CVE</span></dt><dd>NVD record</dd>
<dt><span class="hl-vuln__vp"><b>Vendor</b> Product</span></dt><dd>Affected software</dd>
<dt><span class="hl-vuln__sev hl-vuln__sev--critical">CRITICAL</span> <span class="hl-vuln__sev hl-vuln__sev--high">HIGH</span> <span class="hl-vuln__sev hl-vuln__sev--medium">MEDIUM</span> <span class="hl-vuln__sev hl-vuln__sev--low">LOW</span></dt><dd>CVSS band</dd>
<dt><span class="hl-vuln__b hl-vuln__b--cisa">CISA KEV</span></dt><dd>Also on CISA KEV</dd>
<dt><span class="hl-vuln__p hl-vuln__p--epss">EPSS</span></dt><dd>Predicted exploitation</dd>
<dt><span class="hl-vuln__p hl-vuln__p--vedas">VEDAS</span></dt><dd>Exploit maturity estimate</dd>
<dt><span class="hl-vuln__p">Sources</span></dt><dd>Exploitation citations</dd>
<dt><span class="hl-vuln__p">News</span></dt><dd>Wire coverage</dd>
<dt><span class="hl-vuln__p hl-vuln__p--det">Rules</span></dt><dd>Public detection coverage</dd>
<dt><span class="hl-vuln__p hl-vuln__p--ssvc">SSVC</span></dt><dd>CISA assessment</dd>
<dt><span class="hl-vuln__p hl-vuln__p--exp">Exploits</span></dt><dd>Publisher-confirmed entries</dd>
<dt class="hl-legend__k">Fixed in / advisories</dt><dd>Record context</dd>
<dt><span class="hl-vuln__p hl-vuln__p--cn">cve.now</span></dt><dd>CVE record</dd>
<dt><span class="hl-pick__score">Priority</span></dt><dd>Daily pick and its score</dd>
<dt><span class="hl-pick__chip hl-pick__chip--tooling">Pick reason</span></dt><dd>What raised its rank</dd>
<dt><span class="hl-pick__score hl-pick__score--fresh">Just published</span></dt><dd>New CVE ranked on product and severity, no evidence of exploitation yet</dd>
<dt><span class="hl-vuln__w hl-vuln__w--nuclei">Nuclei</span> <span class="hl-vuln__w hl-vuln__w--et">ET Open</span></dt><dd>Admission by detection tooling</dd>
<dt><span class="hl-vuln__w hl-vuln__w--msf">Metasploit</span> <span class="hl-vuln__w hl-vuln__w--edb">Exploit-DB</span></dt><dd>Admission by exploit tooling</dd>
<dt><span class="hl-vuln__w hl-vuln__w--epss">EPSS top decile</span></dt><dd>Admission by percentile</dd>
<dt><span class="hl-vuln__w hl-vuln__w--vedas">EPSS + VEDAS</span></dt><dd>Admission by paired scores</dd>
<dt><span class="hl-vuln__w hl-vuln__w--wp">WordPress unauthenticated</span></dt><dd>Admission by record fields</dd>
<dt><span class="hl-vuln__w hl-vuln__w--kev">KEV product</span></dt><dd>Earlier product listings</dd>
<dt class="hl-legend__k">Product exploited before</dt><dd>Filter only, never admits</dd>
<dt><span class="hl-vuln__p hl-vuln__p--nomi">PoC on GitHub</span></dt><dd>nomi-sec index context</dd>
</dl>
{%- endcapture -%}
<details class="hl-legend-mobile" data-pagefind-ignore>
<summary>Legend</summary>
<div class="hl-legend__body">{{ cves_legend_html }}</div>
</details>

<div class="hl-filter hl-filter--wire hl-filter--vulns" data-listing-filter data-filter-state="query" data-filter-prefix="c" data-pagefind-ignore>
  <input class="hl-filter__search" type="text" placeholder="Search CVE, vendor, product, title…" aria-label="Search CVE, vendor, product and title" autocomplete="off">
  {%- comment -%} Reason: why a CVE is listed, in the same words the rows use. The seven admission reasons (T-0564, plus WordPress unauthenticated from T-0565.1); Rules are not an arm. Chips OR together and count the rows, not the exporter's declared totals. {%- endcomment -%}
  <div class="hl-filter__chips hl-filter__chips--kind">
    <span class="hl-filter__dim">Why listed</span>
    <button type="button" class="hl-chip-btn is-on" data-sig="">All <span class="hl-chip-btn__n">{{ wire.cves.size }}</span></button>
    {%- comment -%} T-0628: the picks group as a filter, beside the admission reasons it is not one of. {%- endcomment -%}
    {%- if c_pick > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c2" data-sig="pick">Priority picks <span class="hl-chip-btn__n">{{ c_pick }}</span></button>{%- endif -%}
    {%- comment -%} T-0665: the Just published rows as a filter, beside the picks; like them it is not an admission reason. {%- endcomment -%}
    {%- if c_fresh > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c4" data-sig="fresh">Just published <span class="hl-chip-btn__n">{{ c_fresh }}</span></button>{%- endif -%}
    {%- if c_wp > 0 -%}<button type="button" class="hl-chip-btn hl-topic-c3" data-sig="wp_unauth">WordPress unauthenticated <span class="hl-chip-btn__n">{{ c_wp }}</span></button>{%- endif -%}
    {%- if c_nuclei > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c6" data-sig="nuclei">Nuclei template <span class="hl-chip-btn__n">{{ c_nuclei }}</span></button>{%- endif -%}
    {%- if c_et > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c5" data-sig="et">ET Open rule <span class="hl-chip-btn__n">{{ c_et }}</span></button>{%- endif -%}
    {%- if c_msf > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c7" data-sig="msf">Metasploit module <span class="hl-chip-btn__n">{{ c_msf }}</span></button>{%- endif -%}
    {%- if c_edb > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c5" data-sig="edb">Exploit-DB <span class="hl-chip-btn__n">{{ c_edb }}</span></button>{%- endif -%}
    {%- if c_epss > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c6" data-sig="epss90">EPSS top 10% <span class="hl-chip-btn__n">{{ c_epss }}</span></button>{%- endif -%}
    {%- if c_vedas > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c8" data-sig="epss_vedas">EPSS + VEDAS <span class="hl-chip-btn__n">{{ c_vedas }}</span></button>{%- endif -%}
    {%- comment -%} T-0565.2: a filter on the KEV product match each row already carries; it narrows the tab and admits nothing. {%- endcomment -%}
    {%- if c_kp > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c7" data-sig="kev_product">Product exploited before <span class="hl-chip-btn__n">{{ c_kp }}</span></button>{%- endif -%}
  </div>
  {%- comment -%} Severity: only when the list spans more than one band (the selection starts at CVSS 9.0, so it often does not). "No score" is a CVE with no score, never a low one. {%- endcomment -%}
  {%- if c_bands > 1 -%}
  <div class="hl-filter__chips hl-filter__chips--kind">
    <span class="hl-filter__dim">Severity</span>
    <button type="button" class="hl-chip-btn is-on" data-sev="">All</button>
    {%- if c_critical > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-vuln__sev--critical" data-sev="critical">Critical <span class="hl-chip-btn__n">{{ c_critical }}</span></button>{%- endif -%}
    {%- if c_high > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-vuln__sev--high" data-sev="high">High <span class="hl-chip-btn__n">{{ c_high }}</span></button>{%- endif -%}
    {%- if c_medium > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-vuln__sev--medium" data-sev="medium">Medium <span class="hl-chip-btn__n">{{ c_medium }}</span></button>{%- endif -%}
    {%- if c_low > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-vuln__sev--low" data-sev="low">Low <span class="hl-chip-btn__n">{{ c_low }}</span></button>{%- endif -%}
    {%- if c_none > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-vc-none" data-sev="none">No score <span class="hl-chip-btn__n">{{ c_none }}</span></button>{%- endif -%}
  </div>
  {%- endif -%}
  {%- if wire.cve_vendors and wire.cve_vendors != empty -%}
  <div class="hl-filter__chips hl-filter__chips--kind">
    <span class="hl-filter__dim">Vendor</span>
    <button type="button" class="hl-chip-btn is-on" data-vendor="">All</button>
    {%- for v in wire.cve_vendors -%}{%- assign vc = forloop.index0 | modulo: 12 | plus: 1 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c{{ vc }}" data-vendor="{{ v.label | escape }}">{{ v.label | escape }} <span class="hl-chip-btn__n">{{ v.count | escape }}</span></button>{%- endfor -%}
  </div>
  {%- endif -%}
  <div class="hl-filter__count" data-filter-count></div>
  <div class="hl-filter__empty" data-filter-empty hidden><span data-filter-empty-msg>No CVEs match that filter.</span> <button type="button" class="hl-filter__reset" data-filter-reset>Clear filters</button></div>
</div>

{%- comment -%}
  Days newest first, rows inside a day in the exporter's order (its ranking). group_by keeps the
  rows' order within a group; sort by the group's name puts the days in order whatever order the
  file lists them in, so a heading and its id appear once.
{%- endcomment -%}
{%- comment -%}
  T-0641: the priority picks strip. A row with a pick_day is a pick. It stays in the day group of its
  published date, with its pick score and reason chips; the strip at the top of the tab lists the picks
  made on the latest pick day, ordered here by pick_score, then cvss, then the CVE id, all highest first
  (a CVSS of 10.0 and a longer CVE number are the two cases a plain text sort gets wrong, so each has
  its own pass). The last item, "All N picks", turns on the Priority picks filter chip. Data without a
  pick_day on any row makes no strip and renders as before. A pick the row template would skip (no CVE-
  id, no ten-character published day) is left out, so no item links to a row that is not drawn.
{%- endcomment -%}
{%- assign picks_raw = "" | split: "" -%}
{%- for r in wire.cves -%}
{%- assign pd_len = r.pick_day | append: "" | size -%}{%- assign pk_head = r.cve | slice: 0, 4 -%}{%- assign pk_plen = r.published | append: "" | size -%}
{%- if pd_len > 0 and pk_head == "CVE-" and pk_plen == 10 -%}{%- assign picks_raw = picks_raw | push: r -%}{%- endif -%}
{%- endfor -%}
{%- assign picks_ordered = "" | split: "" -%}
{%- if picks_raw.size > 0 -%}
{%- assign p_by_score = picks_raw | group_by: "pick_score" | sort: "name" | reverse -%}
{%- for ps in p_by_score -%}
{%- assign p_by_cvss = ps.items | group_by: "cvss" | sort: "name" | reverse -%}
{%- for cvpass in (1..2) -%}
{%- for pc in p_by_cvss -%}
{%- assign pc_name = pc.name | append: "" -%}{%- assign pc_len = pc_name | size -%}
{%- assign pc_take = false -%}
{%- if cvpass == 1 -%}{%- if pc_len > 3 -%}{%- assign pc_take = true -%}{%- endif -%}{%- else -%}{%- if pc_len < 4 -%}{%- assign pc_take = true -%}{%- endif -%}{%- endif -%}
{%- if pc_take -%}
{%- assign p_by_len = pc.items | group_by_exp: "r", "r.cve | size" | sort: "name" | reverse -%}
{%- for pl in p_by_len -%}
{%- assign p_sorted = pl.items | sort: "cve" | reverse -%}
{%- for r in p_sorted -%}{%- assign picks_ordered = picks_ordered | push: r -%}{%- endfor -%}
{%- endfor -%}
{%- endif -%}
{%- endfor -%}
{%- endfor -%}
{%- endfor -%}
{%- endif -%}
{%- if picks_ordered.size > 0 -%}
{%- assign latest_pick_day = picks_raw | group_by: "pick_day" | sort: "name" | reverse | first -%}
{%- assign lp_day = latest_pick_day.name | append: "" -%}
{%- assign gen_day = wire.cves_generated_at | default: wire.generated_at | date: "%Y-%m-%d" -%}
<nav class="hl-pstrip hl-pstrip--cves" id="cves-priority-picks" aria-label="Latest priority picks on the CVEs tab" data-pagefind-ignore>
<span class="hl-pstrip__label">Top <span class="hl-pstrip__n">{{ latest_pick_day.items.size | escape }}</span> picks{%- if lp_day == gen_day -%}<span class="hl-pstrip__new">new today</span>{%- endif -%}</span>
<ul class="hl-pstrip__list">
{%- for r in picks_ordered -%}
{%- assign pd_now = r.pick_day | append: "" -%}
{%- if pd_now == lp_day -%}
{%- assign pk_name_v = r.vendor | append: "" | strip | downcase -%}{%- assign pk_name_p = r.product | append: "" | strip -%}{%- assign pk_name_n = pk_name_v | size -%}{%- assign pk_name_h = pk_name_p | slice: 0, pk_name_n | downcase -%}{%- if pk_name_n > 0 and pk_name_h == pk_name_v -%}{%- assign pk_name = pk_name_p -%}{%- else -%}{%- assign pk_name = r.vendor | append: " " | append: pk_name_p | normalize_whitespace | strip -%}{%- endif -%}{%- if pk_name == "" -%}{%- assign pk_name = r.cve -%}{%- endif -%}
<li><a class="hl-pstrip__a" href="#cves-{{ r.cve | downcase | escape }}" title="{{ r.cve | escape }} {{ pk_name | escape }}: pick score {{ r.pick_score | plus: 0 }}"><span class="hl-pstrip__name">{{ pk_name | truncate: 90 | escape }}</span><span class="hl-pstrip__s">{{ r.pick_score | plus: 0 }}</span></a></li>
{%- endif -%}
{%- endfor -%}
<li><button type="button" class="hl-pstrip__a hl-pstrip__all" data-pstrip-chip="pick" hidden title="Show only the priority picks, the same as the Priority picks chip">All {{ picks_ordered.size | escape }} picks</button></li>
</ul>
</nav>
{%- endif -%}
<div class="hl-wire hl-vulns" data-filter-grid data-filter-item=".hl-vuln" data-pagefind-ignore>
{%- assign cgroups = wire.cves | group_by: "published" | sort: "name" | reverse -%}
{%- for g in cgroups -%}
{%- assign gname = g.name | append: "" -%}{%- assign gname_len = gname | size -%}
{%- if gname_len == 10 -%}
<div class="hl-wire__day" id="cves-{{ gname | escape }}" data-day-target="{{ gname | escape }}" data-filter-group>{{ gname | date: "%A %-d %B %Y" | escape }} &middot; {{ g.items.size }} published</div>
{%- assign rendered_rows = "" | split: "" -%}
{%- for r in g.items -%}
{%- capture rendered_row -%}
{%- assign cve_head = r.cve | slice: 0, 4 -%}
{%- if cve_head == "CVE-" -%}
{%- assign pdr = r.pick_day | append: "" | size -%}{%- assign is_picks = false -%}{%- if pdr > 0 -%}{%- assign is_picks = true -%}{%- endif -%}{%- assign is_fresh = false -%}{%- if r.fresh == true -%}{%- assign is_fresh = true -%}{%- endif -%}{%- assign vday = gname -%}
{%- assign cvss_len = r.cvss | size -%}{%- assign sev = "none" -%}{%- if cvss_len > 0 -%}{%- if sev_bands contains r.severity -%}{%- assign sev = r.severity -%}{%- endif -%}{%- endif -%}
{%- assign det = "" | split: "" -%}{%- assign n_sids = r.et_sids | size -%}{%- assign nu_len = r.nuclei | size -%}{%- assign rn_cs = r.cisa_sigma | size -%}{%- assign rn_sn = r.snort3_sids | size -%}
{%- assign rn_nu = 0 -%}{%- if nu_len > 0 -%}{%- assign rn_nu = 1 -%}{%- endif -%}
{%- assign rn_rules = n_sids | plus: rn_nu | plus: rn_cs | plus: rn_sn -%}
{%- comment -%} The include's cve_mode draws no KEV-add comparison, so these stay empty on this tab. {%- endcomment -%}
{%- assign epss_len = r.epss | append: "" | size -%}{%- assign epss_pre_len = 0 -%}{%- assign rn_len = 0 -%}{%- assign rp_len = 0 -%}{%- assign spark_len = r.epss_spark | append: "" | size -%}
{%- assign n_st = r.stories | default: 0 -%}
{%- include wire-cve-why.html -%}
<div class="hl-vuln hl-vuln--cve" id="cves-{{ r.cve | downcase | escape }}" data-title="{{ r.cve | downcase | escape }} {{ r.vendor | downcase | escape }} {{ r.product | downcase | escape }} {{ r.title | downcase | escape }}{% if is_picks %} priority pick {{ r.pick_class | downcase | escape }}{% endif %}{% if is_fresh %} just published {{ r.fresh_class | downcase | escape }}{% endif %}" data-vendor="{{ r.vendor | escape }}" data-sev="{{ sev }}" data-sig="{{ sg | join: '|' }}{% if is_picks %}{% if sg.size > 0 %}|{% endif %}pick{% endif %}{% if is_fresh %}{% if sg.size > 0 or is_picks %}|{% endif %}fresh{% endif %}{% if kp_len > 0 and kn > 0 %}{% if sg.size > 0 or is_picks or is_fresh %}|{% endif %}kev_product{% endif %}" data-day="{{ vday | escape }}">{% comment %} T-0532: the Details toggle, first in the row, hidden until the script removes it. {% endcomment %}<button type="button" class="hl-dt" aria-expanded="false" hidden title="Show details"><span class="hl-dt__sr">Details</span></button><a class="hl-vuln__cve" href="https://nvd.nist.gov/vuln/detail/{{ r.cve | escape }}" target="_blank" rel="noopener noreferrer">{{ r.cve | escape }}</a>{% assign ttl_len = r.title | append: "" | size %}<span class="hl-vuln__vp" title="{{ r.vendor | escape }} {{ r.product | escape }}{% if ttl_len > 0 %}: {{ r.title | escape }}{% endif %}">{% if r.vendor and r.vendor != "" %}<b>{{ r.vendor | escape }}</b> {{ r.product | escape }}{% else %}<span class="hl-vuln__none">vendor not given</span>{% endif %}{% if r.title and r.title != "" %} {{ r.title | escape }}{% endif %}</span><span class="hl-vuln__badges">{% include wire-vuln-sev.html %}{% if kp_len > 0 and kn > 0 %}<span class="hl-vuln__w hl-vuln__w--kev" title="{{ kp | escape }}: CISA has listed {{ kn }} earlier CVE{% if kn != 1 %}s{% endif %} in this product on its KEV catalog. That is a fact about the product, not about this CVE.">KEV product</span>{% endif %}{% if w_wp %}<span class="hl-vuln__w hl-vuln__w--wp">WordPress unauthenticated</span>{% endif %}{% if w_nuclei %}<span class="hl-vuln__w hl-vuln__w--nuclei" title="A template in ProjectDiscovery's Nuclei index names this CVE">Nuclei</span>{% endif %}{% if w_et %}<span class="hl-vuln__w hl-vuln__w--et" title="An Emerging Threats ET Open Suricata rule names this CVE">ET Open</span>{% endif %}{% if w_msf %}<span class="hl-vuln__w hl-vuln__w--msf" title="A Metasploit module for this CVE, confirmed against Rapid7's own module list">Metasploit</span>{% endif %}{% if w_edb %}<span class="hl-vuln__w hl-vuln__w--edb" title="An Exploit-DB entry for this CVE, confirmed against Exploit-DB's own list">Exploit-DB</span>{% endif %}{% if w_epss %}<span class="hl-vuln__w hl-vuln__w--epss" title="FIRST's EPSS puts this CVE in the top 10% for likelihood of exploitation in the next 30 days (percentile {{ w_pc }})">EPSS top 10%</span>{% endif %}{% if w_vedas %}<span class="hl-vuln__w hl-vuln__w--vedas" title="EPSS at least 1% and A.R.P. Syndicate's VEDAS exploit-maturity estimate at least 80%, with CVSS at least 7.0; not evidence of exploitation or working exploit code">EPSS + VEDAS</span>{% endif %}{% include wire-vuln-epss.html cve_mode=true %}{% include wire-vuln-vedas.html %}{% include wire-vuln-news.html %}{% include wire-vuln-rules.html %}{% include wire-vuln-new.html %}{% if r.nomi == true %}<a class="hl-vuln__p hl-vuln__p--nomi" href="https://github.com/nomi-sec/PoC-in-GitHub/blob/master/{{ r.cve | split: '-' | slice: 1 | first | escape }}/{{ r.cve | escape }}.json" target="_blank" rel="noopener noreferrer">PoC on GitHub</a>{% endif %}<a class="hl-vuln__p hl-vuln__p--cn" href="https://cve.now/{{ r.cve | escape }}" target="_blank" rel="noopener noreferrer" title="{{ r.cve | escape }} on cve.now">cve.now</a></span>{% if is_picks %}<div class="hl-vuln__pick"><span class="hl-pick__score" title="Priority pick. It scored {{ r.pick_score | plus: 0 }} points when I picked it: likelihood, impact and product class added together. More points rank higher.">Priority {{ r.pick_score | plus: 0 }}</span>{% for t in r.pick_reasons %}{% case t %}{% when "tooling" %}<span class="hl-pick__chip hl-pick__chip--tooling" title="A Metasploit module, an Exploit-DB entry, a Nuclei template or an ET Open rule names this CVE. Worth 2 points. I have not tested any of them.">Exploit tooling</span>{% when "nomi" %}<span class="hl-pick__chip hl-pick__chip--nomi" title="nomi-sec's index lists a public proof of concept on GitHub for this CVE. Worth 1 point. I have not tested that code.">PoC on GitHub</span>{% when "ssvc" %}<span class="hl-pick__chip hl-pick__chip--ssvc" title="CISA's SSVC assessment records exploitation as poc or active. Worth 1 point.">SSVC exploitation</span>{% when "epss90" %}<span class="hl-pick__chip hl-pick__chip--epss" title="FIRST's EPSS puts this CVE in the top 10% for predicted exploitation. Worth 1 point. It is a rank, not a probability of 90%.">EPSS top 10%</span>{% when "noauth" %}<span class="hl-pick__chip hl-pick__chip--noauth" title="The CVSS vector says network reachable, no privileges needed and no user interaction. Worth 1 point.">No login needed</span>{% when "critical" %}<span class="hl-pick__chip hl-pick__chip--critical" title="The CVSS score is 9.0 or higher. Worth 1 point.">CVSS 9.0 or higher</span>{% when "class" %}<span class="hl-pick__chip hl-pick__chip--class" title="The product belongs to one of my product classes: {% if r.pick_class and r.pick_class != "" %}{{ r.pick_class | escape }}{% else %}class not named{% endif %}. Worth 2 points, or 1 for an operating system or browser.">{% if r.pick_class and r.pick_class != "" %}{{ r.pick_class | escape }}{% else %}Product class{% endif %}</span>{% endcase %}{% endfor %}{% if r.pick_seeded == true %}<span class="hl-pick__chip hl-pick__chip--seed" title="This pick came from the first set I seeded when the picks began. It is not a daily pick and it is left out of my test of the rule.">start-up pick</span>{% endif %}<span class="hl-pick__date">picked {{ r.pick_day | date: "%-d %B %Y" | escape }}</span></div>{% endif %}{% if is_fresh %}<div class="hl-vuln__pick hl-vuln__fresh"><span class="hl-pick__score hl-pick__score--fresh" title="Just published. This CVE was published in the last seven days and is one of its day's three highest ranked. It scored {{ r.fresh_score | plus: 0 }} points on its product class and its severity. More points rank higher. It is new and unproven: there is no evidence of exploitation yet.">Just published {{ r.fresh_score | plus: 0 }}</span>{% for t in r.fresh_reasons %}{% case t %}{% when "nomi" %}<span class="hl-pick__chip hl-pick__chip--nomi" title="nomi-sec's index lists a public proof of concept on GitHub for this CVE. Worth 1 point. I have not tested that code.">PoC on GitHub</span>{% when "ssvc" %}<span class="hl-pick__chip hl-pick__chip--ssvc" title="CISA's SSVC assessment records exploitation as poc or active. Worth 1 point.">SSVC exploitation</span>{% when "noauth" %}<span class="hl-pick__chip hl-pick__chip--noauth" title="The CVSS vector says network reachable, no privileges needed and no user interaction. Worth 1 point.">No login needed</span>{% when "critical" %}<span class="hl-pick__chip hl-pick__chip--critical" title="The CVSS score is 9.0 or higher. Worth 1 point.">CVSS 9.0 or higher</span>{% when "class" %}<span class="hl-pick__chip hl-pick__chip--class" title="The product belongs to one of my product classes: {% if r.fresh_class and r.fresh_class != "" %}{{ r.fresh_class | escape }}{% else %}class not named{% endif %}. Worth 2 points, or 1 for an operating system or browser.">{% if r.fresh_class and r.fresh_class != "" %}{{ r.fresh_class | escape }}{% else %}Product class{% endif %}</span>{% endcase %}{% endfor %}<span class="hl-pick__date">new, ranked on product and severity, no evidence of exploitation yet</span></div>{% endif %}</div>
{%- endif -%}
{%- endcapture -%}
{%- assign rendered_rows = rendered_rows | push: rendered_row -%}
{%- endfor -%}
{%- include wire-fold-keys.html rows=g.items mode="cves" -%}
{%- include wire-fold.html rows=rendered_rows keys=fold_keys labels=fold_labels thresholds=fold_thresholds -%}
{%- endif -%}
{%- endfor -%}
</div>

<aside class="hl-post-toc hl-legend" aria-label="CVEs legend" tabindex="0" data-pagefind-ignore>
<details class="hl-legend__fold" open>
<summary class="hl-post-toc__heading" title="Show or hide the legend">Legend</summary>
<div class="hl-legend__body">{{ cves_legend_html }}</div>
</details>
</aside>

{%- elsif cstatus == "ok" -%}

<p class="hl-wire__freshness">No CVE passes the selection right now. This tab fills again on the next read that finds one.</p>

{%- else -%}

<p class="hl-wire__freshness"><span class="hl-wire__notice">CVE data is temporarily unavailable.</span> The headlines and the nKEVs are unaffected; this tab fills again on the next successful read, which runs every 15 minutes.</p>

{%- endif %}
</section>
</div>

<script defer src="{{ '/assets/js/listing-filter.js' | relative_url }}?v=19"></script>
<script defer src="{{ '/assets/js/wire-chips.js' | relative_url }}?v=6"></script>
<script defer src="{{ '/assets/js/wire-details.js' | relative_url }}?v=10"></script>

{%- else -%}

<p class="hl-wire__freshness">The Wire is not currently available. The feed is regenerated every 15 minutes; if this persists, the generator needs attention. The <a href="{{ '/wire/feed.xml' | relative_url }}">Atom feed</a> carries the same headlines and is empty while this is the case.</p>

{%- endif %}

{% include support-cta.html %}
