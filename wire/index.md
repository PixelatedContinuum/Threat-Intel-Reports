---
title: The Wire
description: "Threat intelligence headlines from public research and news sources, refreshed hourly from a self-hosted OpenCTI instance, beside VulnCheck's Known Exploited Vulnerabilities additions. Links only, every item goes to the original publisher."
layout: page
permalink: /wire/
thumbnail: /assets/images/cards/wire.png
position: 2.5
---

<div class="hl-page-header" style="--ph-accent: #58a6ff;">
  <div class="hl-page-header__label">The Wire</div>
  <div class="hl-page-header__title">Threat Intelligence Headlines</div>
  <div class="hl-page-header__desc">Threat reporting and newly exploited vulnerabilities, refreshed every hour.</div>
</div>

{%- assign wire = site.data.wire -%}
{%- if wire and wire.items and wire.items != empty -%}
{%- assign n_headlines = wire.counts.research | plus: wire.counts.news -%}
{%- assign n_vulns = wire.vulns_counts.total | default: 0 -%}

{%- comment -%}
  Two tabs, switched by the URL hash with CSS alone (:target and :has, in
  custom.scss under "The Wire: tabs"). A day (#vulns-YYYY-MM-DD) or a CVE
  (#cve-cve-...) anchor inside #vulns opens that tab too, so a digest row, an
  Atom entry and a shared link all land on the right row. The filter bars keep
  their state in the query string here (data-filter-state="query") so the hash
  stays the tabs'. Designed in T-0394, built in T-0396.
{%- endcomment -%}
<div class="hl-wtabs">
<nav class="hl-wtabs__nav" aria-label="Sections of The Wire"><a class="hl-wtabs__tab hl-wtabs__tab--h" href="#headlines">Headlines<span class="hl-wtabs__n">{{ n_headlines }}</span></a><a class="hl-wtabs__tab hl-wtabs__tab--v" href="#vulns" title="New Known Exploited Vulnerabilities: CVEs newly added to VulnCheck&#39;s KEV catalog">nKEVs<span class="hl-wtabs__n">{{ n_vulns }}</span></a></nav>

<section id="headlines" class="hl-wtabs__sec" data-filter-scope>

<div class="hl-wire__callout hl-wire__callout--h">These headlines come from public research and news sources, pulled every hour from the OpenCTI instance I run myself. The reporting belongs to its publishers and every item links to the original; my own research is in the <a href="/reports/">reports section</a>.</div>

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

<div class="hl-wire" data-filter-grid data-filter-item=".hl-wire__item" data-pagefind-ignore>
{%- assign current_day = "" -%}
{%- for i in wire.items -%}
{%- assign day = i.date | date: "%Y-%m-%d" -%}
{%- if day != current_day -%}
{%- assign current_day = day -%}
<div class="hl-wire__day" data-filter-group>{{ i.date | date: "%A %-d %B %Y" }}</div>
{%- endif -%}
{%- comment -%} A digest row's url is absolute (the exporter and the gate admit only https); on this page it is the bare anchor, so it switches tabs in place. {%- endcomment -%}
{%- if i.kind == "vuln" -%}{%- assign href = i.url | split: "#" | last | prepend: "#" -%}{%- assign tgt = "" -%}{%- else -%}{%- assign href = i.url -%}{%- assign tgt = ' target="_blank" rel="noopener noreferrer"' -%}{%- endif -%}
<a class="hl-wire__item hl-wire__item--{{ i.kind }} hl-wire__item--src-{{ i.source | slugify }}" href="{{ href }}"{{ tgt }} data-title="{{ i.title | downcase | escape }}" data-tags="{{ i.labels | join: '|' | downcase | escape }}" data-kind="{{ i.kind }}" data-day="{{ day }}"><span class="hl-wire__src">{{ i.source }}</span><span class="hl-wire__title">{{ i.title }}</span><span class="hl-wire__labels">{%- for l in i.labels limit: 2 -%}{%- assign tc = wire.label_colors[l] -%}<span class="hl-wire__label{% if tc %} hl-topic-c{{ tc }}{% endif %}">{{ l }}</span>{%- endfor -%}</span></a>
{%- endfor -%}
</div>

</section>

<section id="vulns" class="hl-wtabs__sec" data-filter-scope>
{%- assign vstatus = wire.vulns_status | default: "unavailable" -%}
{%- assign sev_bands = "critical,high,medium,low" | split: "," -%}

{%- comment -%}
  T-0468.1: one short line stays above the filter bar so the nKEV definition, the data
  attribution and the feed are visible without opening anything. Everything that used
  to follow it (the callout and the long chip-meaning paragraph) lives in the legend
  below, which sits where a report shows its table of contents.
{%- endcomment -%}
<p class="hl-wire__freshness hl-wire__freshness--v">nKEVs: CVEs newly added to VulnCheck's Known Exploited Vulnerabilities (KEV) catalog in the last {{ wire.window_days }} days &middot; Data: <a href="https://www.vulncheck.com/kev" target="_blank" rel="noopener noreferrer">VulnCheck KEV</a> &middot; EPSS from <a href="https://www.first.org/epss/" target="_blank" rel="noopener noreferrer">FIRST</a> &middot; <a href="{{ '/wire/vulns.xml' | relative_url }}">Atom feed (nKEVs)</a></p>


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
<dd>FIRST's predicted probability that the CVE is exploited in the next 30 days. Click it to open the popover described below.</dd>
<dt><span class="hl-vuln__p">3 src</span></dt>
<dd>The reports VulnCheck cites as its evidence of exploitation. Click to list them.</dd>
<dt><span class="hl-vuln__p">2 news</span></dt>
<dd>Wire headlines that name the CVE. It opens the Headlines tab searched for it.</dd>
<dt><span class="hl-vuln__p hl-vuln__p--det">ET</span> <span class="hl-vuln__p hl-vuln__p--det">N</span></dt>
<dd>A public ET Open Suricata rule (ET) or Nuclei template (N, which opens the template) names the CVE. Checked daily.</dd>
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
<dd>All, only CVEs that are also in CISA KEV, or only those VulnCheck lists alone.</dd>
<dt class="hl-legend__k">Severity</dt>
<dd>The band of the row's CVSS score. "No score" is a CVE with no score, never a low one.</dd>
<dt class="hl-legend__k">Public rule</dt>
<dd>CVEs with an ET Open Suricata rule or a Nuclei template.</dd>
<dt class="hl-legend__k">NVD timing</dt>
<dd>"pre-NVD" shows only the CVEs VulnCheck added before NVD published them.</dd>
<dt class="hl-legend__k">Vendor</dt>
<dd>Narrows to one or more vendors.</dd>
<dt class="hl-legend__k">Added</dt>
<dd>When VulnCheck added the CVE: today, the last 7 days, or the whole {{ wire.window_days }}-day window, counted from the last data update.</dd>
<dt class="hl-legend__k">CVE age</dt>
<dd>"Recent" is on when the page opens and hides the older CVEs described above. "Include older" brings them back.</dd>
</dl>
<p class="hl-legend__p">Picking several chips in one row shows any of them; picking chips in different rows narrows to rows that match all. The filters are kept in the page address, so a filtered view can be shared by copying the link.</p>
<div class="hl-legend__h">About this data</div>
<p class="hl-legend__p">This tab shows the nKEVs in VulnCheck's KEV catalog as VulnCheck publishes it. I do not curate or track this data myself; every entry comes from VulnCheck, and their catalog is at <a href="https://www.vulncheck.com/kev" target="_blank" rel="noopener noreferrer">vulncheck.com/kev</a>. EPSS scores from FIRST (<a href="https://www.first.org/epss/" target="_blank" rel="noopener noreferrer">first.org/epss</a>), generated by Empirical Security.</p>
{%- endcapture -%}
<details class="hl-legend-mobile" data-pagefind-ignore>
<summary>Legend</summary>
<div class="hl-legend__body">{{ legend_html }}</div>
</details>

{%- comment -%}
  The second bar. Its chips name the axes listing-filter.js reads: data-list
  (CISA or VulnCheck only), data-vendor, data-added (days, against
  data-filter-ref) and data-age. "Recent" is on by default (data-default):
  older CVEs, more than a year before the year VulnCheck added them, are
  hidden until the reader includes them, and the chip carries their count.
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
  {%- comment -%} Public detection (T-0407): an ET Open Suricata rule or a Nuclei template names the CVE. Chips OR together, like the severity bands. {%- endcomment -%}
  {%- assign n_et = wire.vulns_counts.et | default: 0 -%}{%- assign n_nu = wire.vulns_counts.nuclei | default: 0 -%}
  {%- if n_et > 0 or n_nu > 0 -%}
  <div class="hl-filter__chips hl-filter__chips--kind">
    <span class="hl-filter__dim">Public rule</span>
    <button type="button" class="hl-chip-btn is-on" data-det="">All</button>
    {%- if n_et > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c2" data-det="et">ET Open <span class="hl-chip-btn__n">{{ n_et }}</span></button>{%- endif -%}
    {%- if n_nu > 0 -%}<button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c6" data-det="nuclei">Nuclei <span class="hl-chip-btn__n">{{ n_nu }}</span></button>{%- endif -%}
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
    <button type="button" class="hl-chip-btn hl-chip-btn--topic hl-topic-c11" data-age="recent" data-default>Recent</button>
    <button type="button" class="hl-chip-btn hl-chip-btn--topic hl-vc-old" data-age="">Include older <span class="hl-chip-btn__n">{{ wire.vulns_counts.older }}</span></button>
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
<div class="hl-wire__day" id="vulns-{{ vday }}" data-filter-group>{{ vday | date: "%A %-d %B %Y" }} &middot; {{ day_rows.size }} added</div>
{%- endif -%}
{%- assign cve_parts = r.cve | split: "-" -%}{%- assign cve_year = cve_parts[1] -%}
{%- comment -%} T-0407 pointers. A row from a wire.yml written before them carries none and draws none. {%- endcomment -%}
{%- assign det = "" | split: "" -%}{%- assign n_sids = r.et_sids | size -%}{%- assign nu_len = r.nuclei | size -%}
{%- if n_sids > 0 -%}{%- assign det = det | push: "et" -%}{%- endif -%}{%- if nu_len > 0 -%}{%- assign det = det | push: "nuclei" -%}{%- endif -%}
{%- comment -%} T-0468: days from NVD publication to the KEV add (negative: VulnCheck listed it first), and EPSS. A row from a wire.yml written before them carries none and draws none. Liquid has no integer test, so the gap is read through a string. {%- endcomment -%}
{%- assign gap_str = r.gap | append: "" -%}{%- assign gap_len = gap_str | size -%}{%- assign gap_n = 0 -%}{%- assign gap_abs = 0 -%}{%- assign nvd_key = "" -%}
{%- if gap_len > 0 -%}{%- assign gap_n = r.gap | plus: 0 -%}{%- if gap_n < 0 -%}{%- assign nvd_key = "pre" -%}{%- assign gap_abs = gap_n | times: -1 -%}{%- endif -%}{%- endif -%}
{%- assign epss_len = r.epss | append: "" | size -%}{%- assign epss_pre_len = r.epss_pre | append: "" | size -%}{%- assign spark_len = r.epss_spark | append: "" | size -%}{%- assign rn_len = r.ratio_now | append: "" | size -%}{%- assign rp_len = r.ratio_pre | append: "" | size -%}
{%- assign n_reps = r.reports | size -%}{%- assign n_more = r.reports_more | default: 0 -%}{%- assign n_st = r.stories | default: 0 -%}
<div class="hl-vuln" id="cve-{{ r.cve | downcase }}" data-title="{{ r.cve | downcase }} {{ r.vendor | downcase | escape }} {{ r.product | downcase | escape }}" data-list="{% if cisa_len == 10 %}cisa{% else %}vconly{% endif %}" data-vendor="{{ r.vendor | escape }}" data-age="{% if r.older == true %}older{% else %}recent{% endif %}" data-sev="{{ sev }}" data-det="{{ det | join: '|' }}" data-nvd="{{ nvd_key }}" data-day="{{ vday }}"><a class="hl-vuln__cve" href="https://nvd.nist.gov/vuln/detail/{{ r.cve }}" target="_blank" rel="noopener noreferrer">{{ r.cve }}</a><span class="hl-vuln__vp" title="{{ r.vendor | escape }} {{ r.product | escape }}">{% if r.vendor and r.vendor != "" %}<b>{{ r.vendor | escape }}</b> {{ r.product | escape }}{% else %}<span class="hl-vuln__none">vendor not given</span>{% endif %}</span><span class="hl-vuln__badges">{% if sev != "none" %}<span class="hl-vuln__sev hl-vuln__sev--{{ sev }}" title="CVSS v{{ r.cvss_version }} base score {{ r.cvss }}, scored by {% if r.scored_by == "NVD" %}NVD{% elsif r.scored_by == "ADP" %}CISA's ADP{% else %}the CNA{% endif %}, from the CVE's NVD record via VulnCheck NVD++">{{ sev | upcase }} {{ r.cvss }}</span>{% endif %}{% if cisa_len == 10 %}<span class="hl-vuln__b hl-vuln__b--cisa" title="Added to CISA KEV {{ r.cisa_added }}">CISA KEV</span>{% endif %}{% if r.older == true %}<span class="hl-vuln__b hl-vuln__b--old" title="A CVE from {{ cve_year }}, added in {{ vday | slice: 0, 4 }}">CVE-{{ cve_year }}</span>{% endif %}{% comment %} evidence is the earliest citation date; drawn only when it says something the day heading does not. {% endcomment %}{% if ev_len == 10 and r.evidence < vday %}<span class="hl-vuln__ev">evidence {{ r.evidence }}</span>{% endif %}{% if gap_len > 0 and r.disclosed != "" %}{% if gap_n < 0 %}<span class="hl-vuln__b hl-vuln__b--prenvd" title="Added to VulnCheck KEV {{ gap_abs }} day{% if gap_abs != 1 %}s{% endif %} before NVD published it">pre-NVD</span>{% else %}<span class="hl-vuln__b hl-vuln__b--gap" title="Disclosed {{ r.disclosed | escape }} (NVD published); added to VulnCheck KEV {{ vday }}, {% if gap_n == 0 %}the same day{% else %}{{ gap_n }} day{% if gap_n != 1 %}s{% endif %} later{% endif %}">+{{ gap_n }}d</span>{% endif %}{% endif %}{% if epss_len > 0 %}{% assign xm_pre = false %}{% assign xm_spark = false %}{% if r.epss_xmodel contains "pre" %}{% assign xm_pre = true %}{% endif %}{% if r.epss_xmodel contains "spark" %}{% assign xm_spark = true %}{% endif %}{% assign ep_pct = r.epss | times: 100 | round %}{% assign pc_n = r.epss_pct | times: 100 | floor %}{% assign pc_mod100 = pc_n | modulo: 100 %}{% assign pc_mod10 = pc_n | modulo: 10 %}{% assign pc_sfx = "th" %}{% if pc_mod100 < 11 or pc_mod100 > 13 %}{% if pc_mod10 == 1 %}{% assign pc_sfx = "st" %}{% elsif pc_mod10 == 2 %}{% assign pc_sfx = "nd" %}{% elsif pc_mod10 == 3 %}{% assign pc_sfx = "rd" %}{% endif %}{% endif %}<details class="hl-vuln__pop hl-vuln__pop--epss"><summary class="hl-vuln__p hl-vuln__p--epss" title="EPSS {{ r.epss | times: 1.0 | round: 3 }} ({{ pc_n }}{{ pc_sfx }} percentile) on {{ r.epss_date | escape }}{% if epss_pre_len > 0 %}; 7 days before KEV add: {{ r.epss_pre | times: 1.0 | round: 3 }}{% if xm_pre %} (a different EPSS model version, so not directly comparable){% endif %}{% endif %}">EPSS {% if ep_pct < 1 %}&lt;1{% else %}{{ ep_pct }}{% endif %}%</summary><span class="hl-vuln__popbody hl-vuln__popbody--epss">{% if spark_len > 0 %}<svg class="hl-vuln__spark" viewBox="-2 -2 124 28" width="124" height="28" role="img" aria-label="EPSS over the last 30 days, scaled from 0 to {{ r.epss_max | times: 1.0 | round: 3 }}"><polyline points="{{ r.epss_spark | escape }}" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg><span class="hl-vuln__dim">EPSS, last 30 days, scaled 0 to {{ r.epss_max | times: 1.0 | round: 3 }}{% if xm_spark %}. The line crosses a change of FIRST's EPSS model, so its two parts are not directly comparable.{% endif %}</span>{% endif %}<span>EPSS 7 days before KEV add &rarr; now: {% if epss_pre_len > 0 %}{{ r.epss_pre | times: 1.0 | round: 3 }}{% else %}<span class="hl-vuln__dim">no score that day</span>{% endif %} &rarr; {{ r.epss | times: 1.0 | round: 3 }}{% if xm_pre %} <span class="hl-vuln__xm">(crosses an EPSS model change: not directly comparable)</span>{% endif %}</span><span>CVSS:EPSS ratio, before &rarr; now: {% if rp_len > 0 %}{{ r.ratio_pre }}{% else %}<span class="hl-vuln__dim">n/a</span>{% endif %} &rarr; {% if rn_len > 0 %}{{ r.ratio_now }}{% else %}<span class="hl-vuln__dim">n/a</span>{% endif %}</span><span class="hl-vuln__dim">The ratio is (CVSS / 10) / EPSS; above 1, the severity runs ahead of the predicted likelihood of exploitation. EPSS often rises after exploitation is public, so the value from before the KEV add is the lagging-indicator comparison.</span></span></details>{% endif %}{% comment %} T-0407 pointers as compact chips, one line per row: the reports VulnCheck cites open from a click (a native details element, no script), the headline count links to the Headlines search, ET and N mark a public ET Open rule or Nuclei template. {% endcomment %}{% if n_reps > 0 %}{% assign n_src = n_reps | plus: n_more %}<details class="hl-vuln__pop"><summary class="hl-vuln__p" title="Exploitation reported by {{ n_src }} source{% if n_src != 1 %}s{% endif %} VulnCheck cites">{{ n_src }} src</summary><span class="hl-vuln__popbody">Reported by{% for rp in r.reports %}{% assign rp_head = rp.url | slice: 0, 8 %}{% if rp_head == "https://" %}<a href="{{ rp.url | escape }}" target="_blank" rel="noopener noreferrer nofollow">{{ rp.host | escape }}</a>{% endif %}{% endfor %}{% if n_more > 0 %}<span class="hl-vuln__dim">+{{ n_more }} more in VulnCheck KEV</span>{% endif %}</span></details>{% endif %}{% if n_st > 0 %}<a class="hl-vuln__p" href="{{ '/wire/' | relative_url }}?q={{ r.cve | downcase }}#headlines" title="{{ n_st }} Wire headline{% if n_st != 1 %}s{% endif %} name {{ r.cve }}">{{ n_st }} news</a>{% endif %}{% if n_sids > 0 %}<span class="hl-vuln__p hl-vuln__p--det" title="ET Open Suricata rule{% if n_sids > 1 %}s{% endif %}, SID {{ r.et_sids | join: ', ' }}">ET</span>{% endif %}{% if nu_len > 0 %}<a class="hl-vuln__p hl-vuln__p--det" href="https://github.com/projectdiscovery/nuclei-templates/blob/main/{{ r.nuclei | escape }}" target="_blank" rel="noopener noreferrer" title="Nuclei template {{ r.nuclei | escape }}">N</a>{% endif %}</span></div>
{%- endif -%}
{%- endfor -%}
</div>

<aside class="hl-post-toc hl-legend" aria-label="Legend" data-pagefind-ignore>
<div class="hl-post-toc__heading">Legend</div>
<div class="hl-legend__body">{{ legend_html }}</div>
</aside>

{%- else -%}

<p class="hl-wire__freshness"><span class="hl-wire__notice">Vulnerability data is temporarily unavailable.</span> The headlines are unaffected; this tab fills again on the next successful hourly read.</p>

{%- endif %}
</section>
</div>

<script defer src="{{ '/assets/js/listing-filter.js' | relative_url }}?v=15"></script>

{%- else -%}

<p class="hl-wire__freshness">The Wire is not currently available. The feed is regenerated every hour; if this persists, the generator needs attention. The <a href="{{ '/wire/feed.xml' | relative_url }}">Atom feed</a> carries the same headlines and is empty while this is the case.</p>

{%- endif %}

{% include support-cta.html %}
