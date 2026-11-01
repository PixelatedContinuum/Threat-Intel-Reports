---
title: The Wire
description: "Threat intelligence headlines from public research and news sources, refreshed every 15 minutes from a self-hosted OpenCTI instance, beside VulnCheck's Known Exploited Vulnerabilities additions. Links only, every item goes to the original publisher."
layout: page
permalink: /wire/
thumbnail: /assets/images/cards/wire.png
position: 2.5
---

<div class="hl-page-header" style="--ph-accent: #58a6ff;">
  <div class="hl-page-header__label">The Wire</div>
  <div class="hl-page-header__title">Threat Intelligence Headlines</div>
  <div class="hl-page-header__desc">Threat reporting, newly exploited vulnerabilities and significant new CVEs, refreshed every 15 minutes.</div>
</div>

{%- assign wire = site.data.wire -%}
{%- if wire and wire.items and wire.items != empty -%}
{%- assign n_headlines = wire.counts.research | plus: wire.counts.news -%}
{%- assign n_vulns = wire.vulns_counts.total | default: 0 | plus: 0 -%}
{%- assign n_cves = wire.cves_counts.total | default: 0 | plus: 0 -%}

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
<nav class="hl-wtabs__nav" aria-label="Sections of The Wire"><a class="hl-wtabs__tab hl-wtabs__tab--h" href="#headlines">Headlines<span class="hl-wtabs__n">{{ n_headlines }}</span></a><a class="hl-wtabs__tab hl-wtabs__tab--v" href="#vulns" title="New Known Exploited Vulnerabilities: CVEs newly added to VulnCheck&#39;s KEV catalog">nKEVs<span class="hl-wtabs__n">{{ n_vulns }}</span></a><a class="hl-wtabs__tab hl-wtabs__tab--c" href="#cves" title="Significant new CVEs not yet on a KEV list">CVEs<span class="hl-wtabs__n">{{ n_cves }}</span></a></nav>

<section id="headlines" class="hl-wtabs__sec" data-filter-scope>

<div class="hl-wire__callout hl-wire__callout--h">These headlines come from public research and news sources, pulled every 15 minutes from the OpenCTI instance I run myself, which itself polls the publishers' feeds every 5 to 15 minutes. The reporting belongs to its publishers and every item links to the original; my own research is in the <a href="/reports/">reports section</a>.</div>

<p class="hl-wire__freshness">Updated {{ wire.generated_at | date: "%-d %B %Y, %H:%M" }} UTC &middot; {{ n_headlines }} headlines from the last {{ wire.window_days }} days &middot; <a href="{{ '/wire/feed.xml' | relative_url }}">Atom feed</a></p>

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
<div class="hl-wire__row" data-title="{{ i.title | downcase | escape }}" data-tags="{{ i.labels | join: '|' | downcase | escape }}" data-labels="{{ i.labels | join: '|' | escape }}" data-kind="{{ i.kind }}" data-day="{{ day }}"><a class="hl-wire__item hl-wire__item--{{ i.kind }} hl-wire__item--src-{{ i.source | slugify }}" href="{{ href }}"{{ tgt }}><span class="hl-wire__src">{{ i.source | escape }}</span><span class="hl-wire__title">{{ i.title | escape }}</span><span class="hl-wire__labels">{%- for l in i.labels limit: 2 -%}{%- assign tc = wire.label_colors[l] -%}<span class="hl-wire__label{% if tc %} hl-topic-c{{ tc }}{% endif %}">{{ l | escape }}</span>{%- endfor -%}</span></a><button type="button" class="hl-dt" aria-expanded="false" hidden>Details</button></div>
{%- endfor -%}
</div>

</section>

<section id="vulns" class="hl-wtabs__sec" data-filter-scope data-details="{{ '/wire/details-nkev.json' | relative_url }}?v={{ wire.vulns_generated_at | default: wire.generated_at | escape }}">
{%- assign vstatus = wire.vulns_status | default: "unavailable" -%}
{%- assign sev_bands = "critical,high,medium,low" | split: "," -%}

{%- comment -%}
  T-0468.1: one short line stays above the filter bar so the nKEV definition, the data
  attribution and the feed are visible without opening anything. Everything that used
  to follow it (the callout and the long chip-meaning paragraph) lives in the legend
  below, which sits where a report shows its table of contents.
{%- endcomment -%}
<p class="hl-wire__freshness hl-wire__freshness--v">nKEVs: CVEs newly added to VulnCheck's Known Exploited Vulnerabilities (KEV) catalog in the last {{ wire.window_days }} days &middot; Data: <a href="https://www.vulncheck.com/kev" target="_blank" rel="noopener noreferrer">VulnCheck KEV</a> &middot; EPSS from <a href="https://www.first.org/epss/" target="_blank" rel="noopener noreferrer">FIRST</a> &middot; Extra fields: <a href="https://cve.now/" target="_blank" rel="noopener noreferrer">cve.now</a> (CC BY 4.0) &middot; <a href="{{ '/wire/vulns.xml' | relative_url }}">Atom feed (nKEVs)</a></p>


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
<div class="hl-legend__h">Reading a row</div>
<dl class="hl-legend__list">
<dt><span class="hl-vuln__cve">CVE-YYYY-NNNN</span></dt>
<dd>The CVE. It opens its NVD record in a new tab.</dd>
<dt><span class="hl-vuln__vp"><b>Vendor</b> Product</span> <span class="hl-vuln__none">vendor not given</span></dt>
<dd>The vendor and product, as VulnCheck gives them. When it gives none, the row says so.</dd>
<dt><span class="hl-vuln__sev hl-vuln__sev--critical">CRITICAL 9.8</span> <span class="hl-vuln__sev hl-vuln__sev--high">HIGH 7.5</span> <span class="hl-vuln__sev hl-vuln__sev--medium">MEDIUM 5.3</span> <span class="hl-vuln__sev hl-vuln__sev--low">LOW 3.1</span></dt>
<dd>Severity: the CVSS base score in the CVE's NVD record, read through VulnCheck NVD++. Most are scored by the CVE's CNA, not by NVD; hover the chip to see who scored it. A CVE with no score shows no chip.</dd>
<dt><span class="hl-vuln__b hl-vuln__b--cisa">CISA KEV</span></dt>
<dd>The CVE is also in CISA's Known Exploited Vulnerabilities catalog. Hover for the date CISA added it.</dd>
<dt><span class="hl-vuln__b hl-vuln__b--old">CVE-2019</span></dt>
<dd>An older CVE: numbered more than a year before the year VulnCheck added it. The chip shows the CVE's year.</dd>
<dt><span class="hl-vuln__ev">evidence 2026-01-01</span></dt>
<dd>The earliest date VulnCheck records for a report it cites for the CVE, drawn only when it is earlier than the day VulnCheck added the CVE. It is VulnCheck's citation date, not a date of first exploitation.</dd>
<dt><span class="hl-vuln__b hl-vuln__b--gap">+12d</span></dt>
<dd>Days from the CVE's NVD publication to its addition to VulnCheck KEV. VulnCheck gives no separate date of first exploitation, so the day VulnCheck added the CVE stands in for it.</dd>
<dt><span class="hl-vuln__b hl-vuln__b--prenvd">pre-NVD</span></dt>
<dd>VulnCheck added the CVE before NVD published it. It takes the place of the +Nd chip.</dd>
<dt><span class="hl-vuln__p hl-vuln__p--epss">EPSS 3%</span></dt>
<dd>FIRST's predicted probability that the CVE is exploited in the next 30 days. Click the chip in a row to open the popover described below.</dd>
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
<div class="hl-legend__h">Rules popover</div>
<dl class="hl-legend__list">
<dt><span class="hl-vuln__p hl-vuln__p--det">Rules 4</span></dt>
<dd>One group per source that has a rule for the CVE: "ET Open" (the rule SIDs, shown as text), "Nuclei" (the template file), "CISA Sigma" (the rule file in cisagov/SIGMA_Rules) and "Snort 3 community" (each SID opens its page on snort.org). The rule files and templates open in a new tab. The chip counts every rule listed.</dd>
</dl>
<div class="hl-legend__h">EPSS popover</div>
<dl class="hl-legend__list">
<dt><span class="hl-vuln__p hl-vuln__p--epss">EPSS 3%</span></dt>
<dd>The popover shows EPSS over the last 30 days as a line, the EPSS 7 days before the KEV add compared with now, and the CVSS:EPSS ratio, (CVSS / 10) / EPSS. Above 1, the severity runs ahead of the predicted likelihood of exploitation. EPSS often rises after exploitation is public, so the value from before the KEV add is the lagging-indicator comparison. FIRST changes its EPSS model from time to time and scores from different model versions are not comparable, so a comparison that crosses a model change is marked.</dd>
</dl>
<div class="hl-legend__h">Using the filters</div>
<dl class="hl-legend__list">
<dt class="hl-legend__k">Search</dt>
<dd>Matches the CVE id, vendor and product.</dd>
<dt class="hl-legend__k">List</dt>
<dd>All, only CVEs that are also in CISA KEV, or "VulnCheck only": those in VulnCheck KEV but not in CISA KEV.</dd>
<dt class="hl-legend__k">Severity</dt>
<dd>The band of the row's CVSS score. "No score" is a CVE with no score, never a low one.</dd>
<dt class="hl-legend__k">Public rule</dt>
<dd>CVEs with an ET Open Suricata rule, a Nuclei template, a CISA Sigma rule or a Snort 3 community rule.</dd>
<dt class="hl-legend__k">NVD timing</dt>
<dd>"pre-NVD" shows only the CVEs VulnCheck added before NVD published them.</dd>
<dt class="hl-legend__k">Vendor</dt>
<dd>Narrows to one or more vendors.</dd>
<dt class="hl-legend__k">Added</dt>
<dd>When VulnCheck added the CVE: today, the last 7 days, or the whole {{ wire.window_days }}-day window, counted from the last data update.</dd>
<dt class="hl-legend__k">CVE age</dt>
<dd>"Include older" is on when the page opens, so every CVE shows. "Recent" hides the older CVEs described above.</dd>
</dl>
<p class="hl-legend__p">Picking several chips in one row shows any of them; picking chips in different rows narrows to rows that match all. The filters are kept in the page address, so a filtered view can be shared by copying the link.</p>
<div class="hl-legend__h">About this data</div>
<p class="hl-legend__p">This tab shows the nKEVs in VulnCheck's KEV catalog as VulnCheck publishes it. I do not curate or track this data myself; every entry comes from VulnCheck, and their catalog is at <a href="https://www.vulncheck.com/kev" target="_blank" rel="noopener noreferrer">vulncheck.com/kev</a>. EPSS scores from FIRST (<a href="https://www.first.org/epss/" target="_blank" rel="noopener noreferrer">first.org/epss</a>), generated by Empirical Security. The SSVC, fixed version and advisory fields come from <a href="https://cve.now/" target="_blank" rel="noopener noreferrer">cve.now</a> (CC BY 4.0), and the Metasploit and Exploit-DB entries from Rapid7's and Exploit-DB's own indexes.</p>
{%- endcapture -%}
<details class="hl-legend-mobile" data-pagefind-ignore>
<summary>Legend</summary>
<div class="hl-legend__body">{{ legend_html }}</div>
</details>

{%- comment -%}
  The second bar. Its chips name the axes listing-filter.js reads: data-list
  (CISA or VulnCheck only), data-vendor, data-added (days, against
  data-filter-ref) and data-age. "Include older" (All) is on by default (T-0503,
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
    <span class="hl-filter__dim hl-filter__dim--gap">CVE age</span>
    <button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c11" data-age="recent">Recent</button>
    <button type="button" class="hl-chip-btn hl-chip-btn--topic hl-vc-old is-on" data-age="">Include older <span class="hl-chip-btn__n">{{ wire.vulns_counts.older }}</span></button>
  </div>
  <div class="hl-filter__count" data-filter-count></div>
  <div class="hl-filter__empty" data-filter-empty hidden><span data-filter-empty-msg>No CVEs match that filter.</span> <button type="button" class="hl-filter__reset" data-filter-reset>Clear filters</button></div>
</div>

<div class="hl-wire hl-vulns" data-filter-grid data-filter-item=".hl-vuln" data-pagefind-ignore>
{%- assign current_vday = "" -%}
{%- for r in wire.vulns -%}
{%- comment -%}
  A row that is not canonical is skipped rather than drawn broken; check-wire.js
  warns about it. Liquid treats an empty string as true, so the guard checks the
  shapes: an id starting CVE- and a ten-character day (T-0396 review F3).
{%- endcomment -%}
{%- assign vok = false -%}
{%- if r.cve and r.added -%}{%- assign cve_head = r.cve | slice: 0, 4 -%}{%- assign added_len = r.added | size -%}{%- if cve_head == "CVE-" and added_len == 10 -%}{%- assign vok = true -%}{%- endif -%}{%- endif -%}
{%- if vok -%}
{%- assign cisa_len = r.cisa_added | size -%}{%- assign ev_len = r.evidence | size -%}{%- comment -%} A score is drawn only with a known band and a score beside it; Liquid has no operator precedence, so the band test is a contains on the list. {%- endcomment -%}{%- assign sev = "none" -%}{%- assign cvss_len = r.cvss | size -%}{%- if cvss_len > 0 -%}{%- if sev_bands contains r.severity -%}{%- assign sev = r.severity -%}{%- endif -%}{%- endif -%}
{%- assign vday = r.added | slice: 0, 10 -%}
{%- if vday != current_vday -%}
{%- assign current_vday = vday -%}
{%- assign day_rows = wire.vulns | where: "added", r.added -%}
<div class="hl-wire__day" id="vulns-{{ vday | escape }}" data-filter-group>{{ vday | date: "%A %-d %B %Y" | escape }} &middot; {{ day_rows.size }} added</div>
{%- endif -%}
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
<div class="hl-vuln" id="cve-{{ r.cve | downcase | escape }}" data-title="{{ r.cve | downcase | escape }} {{ r.vendor | downcase | escape }} {{ r.product | downcase | escape }}" data-list="{% if cisa_len == 10 %}cisa{% else %}vconly{% endif %}" data-vendor="{{ r.vendor | escape }}" data-age="{% if r.older == true %}older{% else %}recent{% endif %}" data-sev="{{ sev | escape }}" data-det="{{ det | join: '|' | escape }}" data-nvd="{{ nvd_key | escape }}" data-day="{{ vday | escape }}"><a class="hl-vuln__cve" href="https://nvd.nist.gov/vuln/detail/{{ r.cve | escape }}" target="_blank" rel="noopener noreferrer">{{ r.cve | escape }}</a><span class="hl-vuln__vp" title="{{ r.vendor | escape }} {{ r.product | escape }}">{% if r.vendor and r.vendor != "" %}<b>{{ r.vendor | escape }}</b> {{ r.product | escape }}{% else %}<span class="hl-vuln__none">vendor not given</span>{% endif %}</span><span class="hl-vuln__badges">{% include wire-vuln-sev.html %}{% if cisa_len == 10 %}<span class="hl-vuln__b hl-vuln__b--cisa" title="Added to CISA KEV {{ r.cisa_added | escape }}{% if r.kev_due and r.kev_due != '' %}; CISA due date {{ r.kev_due | escape }}{% endif %}">CISA KEV</span>{% endif %}{% if r.older == true %}<span class="hl-vuln__b hl-vuln__b--old" title="A CVE from {{ cve_year | escape }}, added in {{ vday | slice: 0, 4 | escape }}">CVE-{{ cve_year | escape }}</span>{% endif %}{% comment %} evidence is the earliest citation date; drawn only when it says something the day heading does not. {% endcomment %}{% if ev_len == 10 and r.evidence < vday %}<span class="hl-vuln__ev">evidence {{ r.evidence | escape }}</span>{% endif %}{% if gap_len > 0 and r.disclosed != "" %}{% if gap_n < 0 %}<span class="hl-vuln__b hl-vuln__b--prenvd" title="Added to VulnCheck KEV {{ gap_abs }} day{% if gap_abs != 1 %}s{% endif %} before NVD published it">pre-NVD</span>{% else %}<span class="hl-vuln__b hl-vuln__b--gap" title="Disclosed {{ r.disclosed | escape }} (NVD published); added to VulnCheck KEV {{ vday | escape }}, {% if gap_n == 0 %}the same day{% else %}{{ gap_n }} day{% if gap_n != 1 %}s{% endif %} later{% endif %}">+{{ gap_n }}d</span>{% endif %}{% endif %}{% include wire-vuln-epss.html %}{% comment %} T-0407 pointers as compact chips, one line per row: the reports VulnCheck cites open from a click (a native details element, no script), the headline count links to the Headlines search, Rules N opens the public rules (ET Open, Nuclei, CISA Sigma, Snort 3 community) that name the CVE. {% endcomment %}{% if n_reps > 0 %}{% assign n_src = n_reps | plus: n_more %}<details class="hl-vuln__pop"><summary class="hl-vuln__p" title="Exploitation reported by {{ n_src }} source{% if n_src != 1 %}s{% endif %} VulnCheck cites">{{ n_src }} src</summary><span class="hl-vuln__popbody">Reported by{% for rp in r.reports %}{% assign rp_head = rp.url | slice: 0, 8 %}{% if rp_head == "https://" %}<a href="{{ rp.url | escape }}" target="_blank" rel="noopener noreferrer nofollow">{{ rp.host | escape }}</a>{% endif %}{% endfor %}{% if n_more > 0 %}<span class="hl-vuln__dim">+{{ n_more }} more in VulnCheck KEV</span>{% endif %}</span></details>{% endif %}{% include wire-vuln-news.html %}{% include wire-vuln-rules.html %}{% include wire-vuln-new.html %}{% comment %} T-0532: the Details toggle, hidden until the script removes it. {% endcomment %}<button type="button" class="hl-dt" aria-expanded="false" hidden>Details</button></span></div>
{%- endif -%}
{%- endfor -%}
</div>

{%- comment -%} T-0468.2: the heading is a details summary, so a reader can fold the legend out of the way and open it again. Open on load. {%- endcomment -%}
<aside class="hl-post-toc hl-legend" aria-label="Legend" data-pagefind-ignore>
<details class="hl-legend__fold" open>
<summary class="hl-post-toc__heading" title="Show or hide the legend">Legend</summary>
<div class="hl-legend__body">{{ legend_html }}</div>
</details>
</aside>

{%- else -%}

<p class="hl-wire__freshness"><span class="hl-wire__notice">Vulnerability data is temporarily unavailable.</span> The headlines are unaffected; this tab fills again on the next successful read, which runs every 15 minutes.</p>

{%- endif %}
</section>

<section id="cves" class="hl-wtabs__sec" data-filter-scope data-details="{{ '/wire/details-cves.json' | relative_url }}?v={{ wire.cves_generated_at | default: wire.generated_at | escape }}">
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
<p class="hl-wire__freshness hl-wire__freshness--c">Significant new CVEs not yet on a KEV list, published in the last {{ wire.window_days }} days &middot; Listing, titles, SSVC (CISA's own assessment), fixed versions and advisory ids from <a href="https://cve.now/" target="_blank" rel="noopener noreferrer">cve.now</a> (<a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noopener noreferrer">CC BY 4.0</a>) &middot; Scores from NVD through VulnCheck, or from cve.now where a row says so &middot; Exploits from Rapid7 and Exploit-DB &middot; KEV products from CISA &middot; EPSS from <a href="https://www.first.org/epss/" target="_blank" rel="noopener noreferrer">FIRST</a> &middot; <a href="{{ '/wire/cves.xml' | relative_url }}">Atom feed (CVEs)</a></p>

<div class="hl-wire__callout hl-wire__callout--c">
<p>My selection of CVEs published in the last {{ wire.window_days }} days that are not on a KEV list yet. Each is here for at least one of three reasons: Critical (CVSS 9.0 or higher), reachable over the network with no login and no user action, in a product CISA has listed before; a Metasploit module or Exploit-DB entry, confirmed against Rapid7's or Exploit-DB's own index; or EPSS in the top 10%.</p>
<p>Being listed does not mean anyone has been seen exploiting the CVE. "Product on CISA KEV" is a fact about the product, not this CVE. The list excludes anything on VulnCheck KEV or CISA KEV, and a CVE moves to the nKEVs tab when it is added to VulnCheck KEV. It shows at most 150 CVEs, ranked by how many reasons they meet, then by EPSS, then by CVSS.</p>
</div>

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
{%- assign c_ab = 0 -%}{%- assign c_msf = 0 -%}{%- assign c_edb = 0 -%}{%- assign c_epss = 0 -%}
{%- assign c_critical = 0 -%}{%- assign c_high = 0 -%}{%- assign c_medium = 0 -%}{%- assign c_low = 0 -%}{%- assign c_none = 0 -%}
{%- for r in wire.cves -%}
{%- assign cve_head = r.cve | slice: 0, 4 -%}
{%- if cve_head == "CVE-" -%}
{%- include wire-cve-why.html -%}
{%- if w_ab -%}{%- assign c_ab = c_ab | plus: 1 -%}{%- endif -%}{%- if w_msf -%}{%- assign c_msf = c_msf | plus: 1 -%}{%- endif -%}{%- if w_edb -%}{%- assign c_edb = c_edb | plus: 1 -%}{%- endif -%}{%- if w_epss -%}{%- assign c_epss = c_epss | plus: 1 -%}{%- endif -%}
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
<div class="hl-legend__h">Reading a row</div>
<dl class="hl-legend__list">
<dt><span class="hl-vuln__cve">CVE-YYYY-NNNN</span></dt>
<dd>The CVE. It opens its NVD record in a new tab.</dd>
<dt><span class="hl-vuln__vp"><b>Vendor</b> Product</span></dt>
<dd>The vendor and product, as the CVE record names them. A CVE record that names none shows none. Hover it for the first sentence of the CVE record, as its CNA wrote it; I do not use cve.now's model-written summaries.</dd>
<dt><span class="hl-vuln__sev hl-vuln__sev--critical">CRITICAL 9.8</span></dt>
<dd>The CVSS base score in the CVE's NVD record, read through VulnCheck NVD++ unless the row says cve.now, as on the nKEVs tab. Hover it for the CVSS vector. When our NVD data holds no score, the chip uses cve.now's score and vector and the hover says so. A CVE with no score at all shows no chip.</dd>
<dt><span class="hl-vuln__w hl-vuln__w--ab">No login</span> <span class="hl-vuln__w hl-vuln__w--kev">KEV product</span></dt>
<dd>These two always come together, as one reason. The CVE is rated Critical (CVSS 9.0 or higher) and its CVSS vector says it can be reached over the network with no privileges and no user action. The product it is in has had other CVEs listed on CISA's KEV catalog before. That is a fact about the product, not about this CVE. Hover the first chip for the vector, the second for the product and how many of its CVEs CISA has listed.</dd>
<dt><span class="hl-vuln__w hl-vuln__w--msf">Metasploit</span> <span class="hl-vuln__w hl-vuln__w--edb">Exploit-DB</span></dt>
<dd>A Metasploit module, or an Exploit-DB entry, exists for the CVE, confirmed against Rapid7's or Exploit-DB's own list.</dd>
<dt><span class="hl-vuln__w hl-vuln__w--epss">EPSS top 10%</span></dt>
<dd>FIRST's EPSS puts the CVE in the top 10% for predicted likelihood of being exploited in the next 30 days.</dd>
<dt><span class="hl-vuln__p hl-vuln__p--epss">EPSS 3%</span></dt>
<dd>The EPSS probability itself. The popover shows the last 30 days as a line and today's value.</dd>
<dt><span class="hl-vuln__p">2 news</span></dt>
<dd>Wire headlines that name the CVE. It opens the Headlines tab searched for it.</dd>
<dt><span class="hl-vuln__p hl-vuln__p--det">Rules 2</span></dt>
<dd>Public detection rules that name the CVE, counted across ET Open (Suricata), Nuclei templates, CISA's SIGMA_Rules and the Snort 3 community ruleset. Click the chip in a row to list them.</dd>
<dt><span class="hl-vuln__p hl-vuln__p--ssvc">SSVC</span></dt>
<dd>CISA's own assessment of the CVE, from its Stakeholder-Specific Vulnerability Categorization (SSVC): exploitation, automatable and technical impact. They are CISA's decision points, not mine. cve.now carries them (CISA Vulnrichment), with the fixed version and the GitHub Security Advisory (GHSA) and EU Vulnerability Database (EUVD) ids where it has them. A CVE without them shows no chip.</dd>
<dt><span class="hl-vuln__p hl-vuln__p--exp">Exploits 2</span></dt>
<dd>Public exploits for the CVE that I confirmed against the publisher's own index: a Metasploit module appears only when Rapid7's module list names the CVE, and an Exploit-DB entry only when Exploit-DB's own list does. Both open their pages. I have not tested any exploit. A CVE can be listed with none of these when one of the other reasons on its row admitted it; a missing chip does not mean no exploit exists, only that I could not confirm one.</dd>
<dt><span class="hl-vuln__p hl-vuln__p--cn">cve.now</span></dt>
<dd>The CVE's page on cve.now.</dd>
</dl>
<div class="hl-legend__h">Using the filters</div>
<dl class="hl-legend__list">
<dt class="hl-legend__k">Search</dt>
<dd>Matches the CVE id, vendor, product and the first sentence of the CVE record.</dd>
<dt class="hl-legend__k">Why listed</dt>
<dd>The same reasons the rows show: Critical with no login needed in a product on CISA KEV, a Metasploit module, an Exploit-DB entry, or EPSS in the top 10%. A public rule is not a reason, so it has no chip here; the Rules chip on a row still lists the rules.</dd>
<dt class="hl-legend__k">Severity</dt>
<dd>The band of the row's CVSS score. It appears only when more than one band is present.</dd>
<dt class="hl-legend__k">Vendor</dt>
<dd>Narrows to one or more vendors.</dd>
</dl>
<p class="hl-legend__p">Picking several chips in one row shows any of them; picking chips in different rows narrows to rows that match all. The filters are kept in the page address, so a filtered view can be shared by copying the link.</p>
<div class="hl-legend__h">About this data</div>
<p class="hl-legend__p">I choose which CVEs appear here, by the rule in the note above the filters, and show at most 150. When more qualify, the 150 shown are ranked by how many reasons they meet, then by EPSS, then by CVSS.</p>
<p class="hl-legend__p">The CVE listing, titles, SSVC decision points (CISA's own assessment, from <a href="https://github.com/cisagov/vulnrichment" target="_blank" rel="noopener noreferrer">Vulnrichment</a>), fixed versions and advisory ids come from <a href="https://cve.now/" target="_blank" rel="noopener noreferrer">cve.now</a> (CC BY 4.0). CVSS scores and vectors come from the CVE's NVD record through VulnCheck, mostly the CNA's score, unless the row says cve.now. Metasploit modules come from Rapid7's <a href="https://github.com/rapid7/metasploit-framework" target="_blank" rel="noopener noreferrer">metasploit-framework</a> module index and Exploit-DB entries from <a href="https://www.exploit-db.com/" target="_blank" rel="noopener noreferrer">Exploit-DB</a>'s own index. "Product on CISA KEV" comes from CISA's <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer">KEV catalog</a>. EPSS scores are FIRST's (<a href="https://www.first.org/epss/" target="_blank" rel="noopener noreferrer">first.org/epss</a>), generated by Empirical Security.</p>
{%- endcapture -%}
<details class="hl-legend-mobile" data-pagefind-ignore>
<summary>Legend</summary>
<div class="hl-legend__body">{{ cves_legend_html }}</div>
</details>

<div class="hl-filter hl-filter--wire hl-filter--vulns" data-listing-filter data-filter-state="query" data-filter-prefix="c" data-pagefind-ignore>
  <input class="hl-filter__search" type="text" placeholder="Search CVE, vendor, product, title…" aria-label="Search CVE, vendor, product and title" autocomplete="off">
  {%- comment -%} Reason: why a CVE is listed, in the same words the rows use. The four selection arms (Revision 3); Rules are not an arm. Chips OR together and count the rows, not the exporter's declared totals. {%- endcomment -%}
  <div class="hl-filter__chips hl-filter__chips--kind">
    <span class="hl-filter__dim">Why listed</span>
    <button type="button" class="hl-chip-btn is-on" data-sig="">All <span class="hl-chip-btn__n">{{ wire.cves.size }}</span></button>
    {%- if c_ab > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c4" data-sig="crit_noauth_kev_product">Critical, no login needed, product on CISA KEV <span class="hl-chip-btn__n">{{ c_ab }}</span></button>{%- endif -%}
    {%- if c_msf > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c7" data-sig="msf">Metasploit module <span class="hl-chip-btn__n">{{ c_msf }}</span></button>{%- endif -%}
    {%- if c_edb > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c5" data-sig="edb">Exploit-DB <span class="hl-chip-btn__n">{{ c_edb }}</span></button>{%- endif -%}
    {%- if c_epss > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c6" data-sig="epss90">EPSS top 10% <span class="hl-chip-btn__n">{{ c_epss }}</span></button>{%- endif -%}
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

<div class="hl-wire hl-vulns" data-filter-grid data-filter-item=".hl-vuln" data-pagefind-ignore>
{%- comment -%}
  Days newest first, rows inside a day in the exporter's order (its ranking). group_by keeps the
  rows' order within a group; sort by the group's name puts the days in order whatever order the
  file lists them in, so a heading and its id appear once.
{%- endcomment -%}
{%- assign cgroups = wire.cves | group_by: "published" | sort: "name" | reverse -%}
{%- for g in cgroups -%}
{%- assign gname = g.name | append: "" -%}{%- assign gname_len = gname | size -%}
{%- if gname_len == 10 -%}
<div class="hl-wire__day" id="cves-{{ gname | escape }}" data-filter-group>{{ gname | date: "%A %-d %B %Y" | escape }} &middot; {{ g.items.size }} published</div>
{%- for r in g.items -%}
{%- assign cve_head = r.cve | slice: 0, 4 -%}
{%- if cve_head == "CVE-" -%}
{%- assign vday = gname -%}
{%- assign cvss_len = r.cvss | size -%}{%- assign sev = "none" -%}{%- if cvss_len > 0 -%}{%- if sev_bands contains r.severity -%}{%- assign sev = r.severity -%}{%- endif -%}{%- endif -%}
{%- assign det = "" | split: "" -%}{%- assign n_sids = r.et_sids | size -%}{%- assign nu_len = r.nuclei | size -%}{%- assign rn_cs = r.cisa_sigma | size -%}{%- assign rn_sn = r.snort3_sids | size -%}
{%- assign rn_nu = 0 -%}{%- if nu_len > 0 -%}{%- assign rn_nu = 1 -%}{%- endif -%}
{%- assign rn_rules = n_sids | plus: rn_nu | plus: rn_cs | plus: rn_sn -%}
{%- comment -%} The include's cve_mode draws no KEV-add comparison, so these stay empty on this tab. {%- endcomment -%}
{%- assign epss_len = r.epss | append: "" | size -%}{%- assign epss_pre_len = 0 -%}{%- assign rn_len = 0 -%}{%- assign rp_len = 0 -%}{%- assign spark_len = r.epss_spark | append: "" | size -%}
{%- assign n_st = r.stories | default: 0 -%}
{%- include wire-cve-why.html -%}
<div class="hl-vuln hl-vuln--cve" id="cves-{{ r.cve | downcase | escape }}" data-title="{{ r.cve | downcase | escape }} {{ r.vendor | downcase | escape }} {{ r.product | downcase | escape }} {{ r.title | downcase | escape }}" data-vendor="{{ r.vendor | escape }}" data-sev="{{ sev }}" data-sig="{{ sg | join: '|' }}" data-day="{{ vday | escape }}"><a class="hl-vuln__cve" href="https://nvd.nist.gov/vuln/detail/{{ r.cve | escape }}" target="_blank" rel="noopener noreferrer">{{ r.cve | escape }}</a>{% assign ttl_len = r.title | append: "" | size %}<span class="hl-vuln__vp" title="{{ r.vendor | escape }} {{ r.product | escape }}{% if ttl_len > 0 %}: {{ r.title | escape }}{% endif %}">{% if r.vendor and r.vendor != "" %}<b>{{ r.vendor | escape }}</b> {{ r.product | escape }}{% else %}<span class="hl-vuln__none">vendor not given</span>{% endif %}</span><span class="hl-vuln__badges">{% include wire-vuln-sev.html %}{% if w_ab %}<span class="hl-vuln__w hl-vuln__w--ab" title="Rated Critical (CVSS {{ r.cvss | escape }}) and reachable over the network with no privileges and no user action, read from its CVSS vector{% if w_vec != '' %} ({{ w_vec | escape }}){% endif %}">No login</span><span class="hl-vuln__w hl-vuln__w--kev" title="{{ kp | escape }}: CISA has listed {{ kn }} earlier CVE{% if kn != 1 %}s{% endif %} in this product on its KEV catalog. That is a fact about the product, not about this CVE.">KEV product</span>{% endif %}{% if w_msf %}<span class="hl-vuln__w hl-vuln__w--msf" title="A Metasploit module for this CVE, confirmed against Rapid7's own module list">Metasploit</span>{% endif %}{% if w_edb %}<span class="hl-vuln__w hl-vuln__w--edb" title="An Exploit-DB entry for this CVE, confirmed against Exploit-DB's own list">Exploit-DB</span>{% endif %}{% if w_epss %}<span class="hl-vuln__w hl-vuln__w--epss" title="FIRST's EPSS puts this CVE in the top 10% for likelihood of exploitation in the next 30 days (percentile {{ w_pc }})">EPSS top 10%</span>{% endif %}{% include wire-vuln-epss.html cve_mode=true %}{% include wire-vuln-news.html %}{% include wire-vuln-rules.html %}{% include wire-vuln-new.html %}<a class="hl-vuln__p hl-vuln__p--cn" href="https://cve.now/{{ r.cve | escape }}" target="_blank" rel="noopener noreferrer" title="{{ r.cve | escape }} on cve.now">cve.now</a>{% comment %} T-0532: the Details toggle, hidden until the script removes it. {% endcomment %}<button type="button" class="hl-dt" aria-expanded="false" hidden>Details</button></span></div>
{%- endif -%}
{%- endfor -%}
{%- endif -%}
{%- endfor -%}
</div>

<aside class="hl-post-toc hl-legend" aria-label="CVEs legend" data-pagefind-ignore>
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

<script defer src="{{ '/assets/js/listing-filter.js' | relative_url }}?v=16"></script>
<script defer src="{{ '/assets/js/wire-details.js' | relative_url }}?v=1"></script>

{%- else -%}

<p class="hl-wire__freshness">The Wire is not currently available. The feed is regenerated every 15 minutes; if this persists, the generator needs attention. The <a href="{{ '/wire/feed.xml' | relative_url }}">Atom feed</a> carries the same headlines and is empty while this is the case.</p>

{%- endif %}

{% include support-cta.html %}
