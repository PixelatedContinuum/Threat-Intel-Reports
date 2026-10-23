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
<nav class="hl-wtabs__nav" aria-label="Sections of The Wire"><a class="hl-wtabs__tab hl-wtabs__tab--h" href="#headlines">Headlines<span class="hl-wtabs__n">{{ n_headlines }}</span></a><a class="hl-wtabs__tab hl-wtabs__tab--v" href="#vulns">Vulnerabilities<span class="hl-wtabs__n">{{ n_vulns }}</span></a></nav>

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

<p class="hl-wire__freshness">CVEs added to VulnCheck's Known Exploited Vulnerabilities catalog in the last {{ wire.window_days }} days &middot; <a href="{{ '/wire/vulns.xml' | relative_url }}">Atom feed (vulnerabilities)</a></p>

<div class="hl-wire__callout hl-wire__callout--v">This tab shows VulnCheck's Known Exploited Vulnerabilities (KEV) catalog as VulnCheck publishes it. I do not curate or track this data myself; every entry comes from VulnCheck, and their catalog is at <a href="https://www.vulncheck.com/kev" target="_blank" rel="noopener noreferrer">vulncheck.com/kev</a>.</div>

{%- assign vshow = false -%}
{%- if wire.vulns and wire.vulns != empty -%}{%- if vstatus == "ok" or vstatus == "stale" -%}{%- assign vshow = true -%}{%- endif -%}{%- endif -%}
{%- if vshow -%}

<p class="hl-wire__freshness">A CISA KEV badge means the CVE is also in CISA's catalog. Each CVE links to its NVD record. Severity is the CVSS base score in that record, read through VulnCheck NVD++; most are scored by the CVE's CNA, not by NVD, and a CVE with no score shows none. "Reported by" links the reports VulnCheck cites as its evidence of exploitation; a headline count opens the Wire headlines that name the CVE; ET Open and Nuclei mark a public Suricata rule or Nuclei template for it, checked daily.{% if vstatus == "stale" %} <span class="hl-wire__notice">Vulnerability data last updated {{ wire.vulns_generated_at | date: "%-d %B %Y, %H:%M" }} UTC.</span>{% endif %}</p>

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
    <button type="button" class="hl-chip-btn" data-list="cisa">Also CISA KEV <span class="hl-chip-btn__n">{{ wire.vulns_counts.cisa }}</span></button>
    <button type="button" class="hl-chip-btn" data-list="vconly">VulnCheck only <span class="hl-chip-btn__n">{{ wire.vulns_counts.total | minus: wire.vulns_counts.cisa }}</span></button>
  </div>
  {%- comment -%} Severity (T-0399): the band of the row's CVSS base score; "none" is a CVE with no score, never a low one. {%- endcomment -%}
  <div class="hl-filter__chips hl-filter__chips--kind">
    <span class="hl-filter__dim">Severity</span>
    <button type="button" class="hl-chip-btn is-on" data-sev="">All</button>
    {%- for sv in sev_bands -%}{%- assign svn = wire.vulns_counts[sv] | default: 0 -%}{%- if svn > 0 -%}<button type="button" class="hl-chip-btn" data-sev="{{ sv }}">{{ sv | capitalize }} <span class="hl-chip-btn__n">{{ svn }}</span></button>{%- endif -%}{%- endfor -%}
    {%- assign svn = wire.vulns_counts.unscored | default: 0 -%}{%- if svn > 0 -%}<button type="button" class="hl-chip-btn" data-sev="none">No score <span class="hl-chip-btn__n">{{ svn }}</span></button>{%- endif -%}
  </div>
  {%- comment -%} Public detection (T-0407): an ET Open Suricata rule or a Nuclei template names the CVE. Chips OR together, like the severity bands. {%- endcomment -%}
  {%- assign n_et = wire.vulns_counts.et | default: 0 -%}{%- assign n_nu = wire.vulns_counts.nuclei | default: 0 -%}
  {%- if n_et > 0 or n_nu > 0 -%}
  <div class="hl-filter__chips hl-filter__chips--kind">
    <span class="hl-filter__dim">Public rule</span>
    <button type="button" class="hl-chip-btn is-on" data-det="">All</button>
    {%- if n_et > 0 -%}<button type="button" class="hl-chip-btn" data-det="et">ET Open <span class="hl-chip-btn__n">{{ n_et }}</span></button>{%- endif -%}
    {%- if n_nu > 0 -%}<button type="button" class="hl-chip-btn" data-det="nuclei">Nuclei <span class="hl-chip-btn__n">{{ n_nu }}</span></button>{%- endif -%}
  </div>
  {%- endif -%}
  <div class="hl-filter__chips hl-filter__chips--kind">
    <span class="hl-filter__dim">Vendor</span>
    <button type="button" class="hl-chip-btn is-on" data-vendor="">All</button>
    {%- for v in wire.vuln_vendors -%}<button type="button" class="hl-chip-btn" data-vendor="{{ v.label | escape }}">{{ v.label | escape }} <span class="hl-chip-btn__n">{{ v.count }}</span></button>{%- endfor -%}
  </div>
  <div class="hl-filter__chips hl-filter__chips--kind">
    <span class="hl-filter__dim">Added</span>
    <button type="button" class="hl-chip-btn" data-added="1">Today</button>
    <button type="button" class="hl-chip-btn" data-added="7">7 days</button>
    <button type="button" class="hl-chip-btn is-on" data-added="">{{ wire.window_days }} days</button>
    <span class="hl-filter__dim hl-filter__dim--gap">CVE age</span>
    <button type="button" class="hl-chip-btn" data-age="recent" data-default>Recent</button>
    <button type="button" class="hl-chip-btn" data-age="">Include older <span class="hl-chip-btn__n">{{ wire.vulns_counts.older }}</span></button>
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
{%- assign n_reps = r.reports | size -%}{%- assign n_more = r.reports_more | default: 0 -%}{%- assign n_st = r.stories | default: 0 -%}
<div class="hl-vuln" id="cve-{{ r.cve | downcase }}" data-title="{{ r.cve | downcase }} {{ r.vendor | downcase | escape }} {{ r.product | downcase | escape }}" data-list="{% if cisa_len == 10 %}cisa{% else %}vconly{% endif %}" data-vendor="{{ r.vendor | escape }}" data-age="{% if r.older == true %}older{% else %}recent{% endif %}" data-sev="{{ sev }}" data-det="{{ det | join: '|' }}" data-day="{{ vday }}"><a class="hl-vuln__cve" href="https://nvd.nist.gov/vuln/detail/{{ r.cve }}" target="_blank" rel="noopener noreferrer">{{ r.cve }}</a><span class="hl-vuln__vp">{% if r.vendor and r.vendor != "" %}<b>{{ r.vendor | escape }}</b> {{ r.product | escape }}{% else %}<span class="hl-vuln__none">vendor not given</span>{% endif %}</span><span class="hl-vuln__badges">{% if sev != "none" %}<span class="hl-vuln__sev hl-vuln__sev--{{ sev }}" title="CVSS v{{ r.cvss_version }} base score {{ r.cvss }}, scored by {% if r.scored_by == "NVD" %}NVD{% elsif r.scored_by == "ADP" %}CISA's ADP{% else %}the CNA{% endif %}, from the CVE's NVD record via VulnCheck NVD++">{{ sev | upcase }} {{ r.cvss }}</span>{% endif %}<span class="hl-vuln__b hl-vuln__b--vc">VulnCheck KEV</span>{% if cisa_len == 10 %}<span class="hl-vuln__b hl-vuln__b--cisa" title="Added to CISA KEV {{ r.cisa_added }}">CISA KEV</span>{% endif %}{% if r.older == true %}<span class="hl-vuln__b hl-vuln__b--old" title="A CVE from {{ cve_year }}, added in {{ vday | slice: 0, 4 }}">CVE-{{ cve_year }}</span>{% endif %}{% comment %} evidence is the earliest citation date; drawn only when it says something the day heading does not. {% endcomment %}{% if ev_len == 10 and r.evidence < vday %}<span class="hl-vuln__ev">evidence {{ r.evidence }}</span>{% endif %}</span>{% if n_reps > 0 or n_st > 0 or n_sids > 0 or nu_len > 0 %}<span class="hl-vuln__more">{% if n_reps > 0 %}<span class="hl-vuln__rep">Reported by {% for rp in r.reports %}{% assign rp_head = rp.url | slice: 0, 8 %}{% if rp_head == "https://" %}<a href="{{ rp.url | escape }}" target="_blank" rel="noopener noreferrer nofollow">{{ rp.host | escape }}</a>{% unless forloop.last %}, {% endunless %}{% endif %}{% endfor %}{% if n_more > 0 %} <span class="hl-vuln__dim" title="VulnCheck cites {{ n_more }} more">+{{ n_more }} more</span>{% endif %}</span>{% endif %}{% if n_st > 0 %}<a class="hl-vuln__ptr" href="{{ '/wire/' | relative_url }}?q={{ r.cve | downcase }}#headlines" title="Wire headlines that name {{ r.cve }}">{{ n_st }} headline{% if n_st != 1 %}s{% endif %}</a>{% endif %}{% if n_sids > 0 %}<span class="hl-vuln__det" title="ET Open Suricata rule{% if n_sids > 1 %}s{% endif %}, SID {{ r.et_sids | join: ', ' }}">ET Open</span>{% endif %}{% if nu_len > 0 %}<a class="hl-vuln__det" href="https://github.com/projectdiscovery/nuclei-templates/blob/main/{{ r.nuclei | escape }}" target="_blank" rel="noopener noreferrer" title="Nuclei template {{ r.nuclei | escape }}">Nuclei</a>{% endif %}</span>{% endif %}</div>
{%- endif -%}
{%- endfor -%}
</div>

{%- else -%}

<p class="hl-wire__freshness"><span class="hl-wire__notice">Vulnerability data is temporarily unavailable.</span> The headlines are unaffected; this tab fills again on the next successful hourly read.</p>

{%- endif %}
</section>
</div>

<script defer src="{{ '/assets/js/listing-filter.js' | relative_url }}?v=14"></script>

{%- else -%}

<p class="hl-wire__freshness">The Wire is not currently available. The feed is regenerated every hour; if this persists, the generator needs attention. The <a href="{{ '/wire/feed.xml' | relative_url }}">Atom feed</a> carries the same headlines and is empty while this is the case.</p>

{%- endif %}

{% include support-cta.html %}
