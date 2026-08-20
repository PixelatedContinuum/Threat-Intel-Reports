---
title: Report Format
layout: page
permalink: /report-templates/
hide: true
---

## Purpose

This page documents the **current report format** used by The Hunters Ledger. The format has changed substantially since the site's earlier reports, so where an older published report disagrees with this page, this page is right and the older report has not been backfilled yet.

Two reports on the site are written fully to the current standard and are the best things to read alongside this page:

- [MultiVector E-Commerce RCE Toolkit (192.3.1.116)]({{ "/reports/multivector-ecommerce-rce-toolkit-192-3-1-116/" | relative_url }}), full-format deep technical report with collapsible teardowns
- [WebLogic Deserialization and Telecom Harvester (13.140.145.210)]({{ "/reports/opendirectory-13-140-145-210-weblogic-deserialization-telecom-harvester-20260817/" | relative_url }}), on-box analysis with companion detection file and IOC feed

---

## Four Files, Not Three

A full-format publication is three content files plus one catalog entry. The catalog entry is what makes the other three visible, so a report without it is published but unreachable.

| File | Purpose | Rendered at |
|---|---|---|
| `reports/[slug]/index.md` | The report | `/reports/[slug]/` |
| `ioc-feeds/[slug]-iocs.json` | Machine-readable IOC feed | `/ioc-feeds/` |
| `hunting-detections/[slug]-detections.md` | YARA, Sigma, and Suricata rules | `/hunting-detections/` |
| `_data/catalog.yml` | One entry driving all three listings | Every listing page and the home page |

IOCs and detection rules are **never embedded in the report body**. They live in their companion files and get referenced.

### The catalog entry

One entry per campaign. An entry appears in a listing only if it carries that listing's URL field, so a report with no `detection_url` simply does not show on the detections page.

```yaml
  - title: "Campaign or Tool Name"
    date: YYYY-MM-DD            # ISO, unquoted
    severity: high              # critical | high | med | low, must match the Threat Level header
    tags: [Tag1, Tag2, Tag3]    # drives card badges and the filter chips
    report_url: /reports/[slug]/
    detection_url: /hunting-detections/[slug]-detections
    ioc_url: /ioc-feeds/[slug]-iocs.json
```

Titles auto-normalize to `Detection Rules — {title}` and `{title} — IOC Feed` unless overridden with `detection_title` or `ioc_title`.

Do not hand-edit `reports/index.md`, `hunting-detections/index.md`, `ioc-feeds/index.md`, or the home page's latest-reports block. All four generate from the catalog.

---

## YAML Front Matter

```yaml
---
title: "[Report Title]"
date: 'YYYY-MM-DD'
last_updated: 'YYYY-MM-DD'               # only when revised after publish
detection_page: /hunting-detections/[slug]-detections/
ioc_feed: /ioc-feeds/[slug]-iocs.json
detection_sections:                       # powers the green Detection panel
  - label: "YARA Rules"
    anchor: "#yara-rules"                 # must match the Jekyll-generated H2 anchor
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "Suricata Rules"
    anchor: "#suricata-rules"
ioc_highlights:                           # powers the blue IOC panel, 3 to 5 indicators
  - value: "1.2.3.4"
    note: "Primary C2 server"             # keep under 60 characters
layout: post
permalink: /reports/[slug]/
category: "[Malware Category]"
hide: true
description: "[1 to 2 sentence summary for social sharing previews]"
---
```

`detection_page`, `ioc_feed`, `detection_sections` and `ioc_highlights` drive the report page's own sidebar panels. They do **not** create the listing cards. Only the catalog entry does that.

Each `anchor` must match the anchor Jekyll generates from the heading: lowercased, spaces to hyphens, special characters stripped. Include only substantive rule sections and skip Overview, License, and summary sections.

### Three rules for `ioc_highlights`

Only **atomic indicators** belong here. IPv4 and IPv6 addresses, domains, full URLs, and file hashes. Never filenames, paths, registry keys, mutex names, scheduled task names, tool names, strings, version numbers, or configuration values, because none of those can be pasted straight into a hunt.

Every network indicator is defanged. Replace `.` with `[.]` in addresses and domains, and `http` with `hxxp` in URLs. Hashes are never defanged.

| Type | Published as |
|---|---|
| IP | `185[.]49[.]126[.]140` |
| Domain | `evil[.]com` |
| URL | `hxxp://evil[.]com/payload` |
| Hash | `f4b00fbc6a3ce80b474334a3ccaadcf0` |

Order them by what a defender acts on first. Active C2 addresses and domains lead, because those are immediately blockable. Payload hashes follow as file-based anchors, then delivery and staging infrastructure. Skip generic hosting addresses and anything not confirmed malicious. If there are fewer than three atomic indicators, omit the field rather than padding it.

---

## Campaign Metadata Block

Immediately after the front matter, before the first heading. The `<br>` tags are required, because Jekyll otherwise collapses all three fields onto one line.

```markdown
**Campaign Identifier:** [CampaignID]<br>
**Last Updated:** [Month D, YYYY]<br>
**Threat Level:** [CRITICAL/HIGH/MEDIUM/LOW]
```

This block is the one place a bolded label followed by a colon is allowed. It is a fixed deployment format, not prose.

The campaign identifier describes **what was found**, never an assumption about who is behind it. `WebServer-Compromise-Kit-45.94.31.220` is right. `Attacker-Infrastructure-45.94.31.220` is not, unless attribution is genuinely HIGH or above, in which case the actor name may lead.

The Threat Level must match the overall risk score in the body. A report showing MEDIUM at the top while the body scores CRITICAL erodes trust faster than either number alone. Where campaign context justifies a lower header level than the capability score (confirmed-offline infrastructure, no confirmed victims), the report must carry a blockquote immediately after the header explaining the gap.

---

## Structure

Fourteen elements in order, from front matter to the license footer. The numbered sections use `##`, and the report title Jekyll renders is already the page H1.

| # | Section |
|---|---|
| 0 | YAML front matter and campaign metadata |
| 1 | BLUF, three to five sentences |
| 2 | Executive Summary (`## 1.`) |
| 3 | Business Risk Assessment (`## 2.`), optional |
| 4 | Technical Classification (`## 3.`) |
| 5 | Technical Capabilities Deep-Dive (`## 4.`) |
| 6 | Static Analysis Findings (`## 5.`) |
| 7 | Dynamic Analysis Findings (`## 6.`) |
| 8 | MITRE ATT&CK Mapping (`## 7.`) |
| 9 | Indicators of Compromise (`## 8.`) |
| 10 | Detection and Response Guidance (`## 9.`) |
| 11 | Recommendations (`## 10.`) |
| 12 | References and Appendices (`## 11.` and `## 12.`) |
| 13 | License footer |

Do not write a manual table of contents. The site builds a collapsible, hierarchical navigation panel by scanning H2 and H3 headings, and it expands the active chapter as the reader scrolls. A hand-written ToC section duplicates it and goes stale.

Do not add a Quick Reference section either, because the sidebar panels already surface the IOC and detection links.

### Heading levels

All top-level numbered sections use `##`. Never `#`, because that creates a second H1 and breaks the navigation scan. Sub-sections use `###` and nest under their chapter in the panel, so a clean `##` and `###` tree is what produces good navigation.

### The three registers

A report is one page that gets deeper as it is read, in three tiers, and the register drops one gear per tier.

The **top** is the operational brief. Plain, human, written in my own voice, and it has to stand alone for a reader who stops there. The **middle** is tradecraft and intelligence at a readable technical level: kill chain, infrastructure, attribution, detection pointers. The **bottom** is the technical teardown, written for a peer with the training wheels off.

A uniform register across all three is the single loudest signal that nobody wrote the report.

Section order follows the same descent. Executive material leads, which means the brief, the risk assessment, and who was affected. Technical depth follows, then the reference apparatus (ATT&CK, actor assessment, indicators, confidence) last. Risk is executive language and belongs near the front, not behind the teardown.

### Collapsing the deep dives

Wrap each genuinely deep dive in a collapsible block so the page reads short on load without losing any depth.

```markdown
<details markdown="1" class="hl-teardown">
<summary>one-line teaser</summary>

...the deep content...

</details>
```

`markdown="1"` keeps the inner headings, tables, and figures as real HTML, so the navigation panel still lists them, and the site auto-expands a collapsed block when a link targets something inside it.

Three rules govern this. Keep a **meaningful** lead visible above every toggle, enough that the section stands on its own and a reader can decide whether to open the depth. Never collapse a section that is already short. And if collapsing would leave nothing substantive visible, write the plain-language overview first.

This inverts the old pressure on length. Do not cut technical depth to keep a report readable. Add the depth and collapse it.

---

## Voice

The full ruleset lives in the voice charter. These are the rules that get broken most.

Write in the first person. I did the work, so the prose says so, which rules out "the analyst", "we assess", and any construction that makes the report itself into the actor. A report does not state, argue, or carry a caveat; the person writing it does. Being a third-party *provider* is about not taking the victim's side, and it says nothing about grammatical person.

Em dashes and en dashes never appear as sentence punctuation, anywhere. Use a comma, split the sentence, or use parentheses.

Never open a paragraph with a bolded label and a colon. Both `**Detection strategy.** The high-fidelity signal is…` and `**Confidence:** HIGH…` dissolve into the sentence, and the sentence is always better for it. This is the most persistent tell there is, and the campaign metadata block and table cells are the only exemptions.

Avoid declaration-colons as well. A colon must not announce an elaboration mid-sentence where the sentence reads better joined. Roughly four in a full-length report is normal; past eight it has stopped being a choice.

Break paragraphs at five or six sentences. That is a hard rule and an accessibility requirement rather than a preference, and a block that resists splitting is usually carrying two ideas.

Use the real figure, never a hedge. It is our investigation, so we counted. Write "452 files" and "58 Python and 5 shell scripts", not "roughly 450" or "a hundred-plus scripts". Genuine measurement ranges stay ranges, and confidence percentages keep their "approximately" because they are estimates rather than counts.

Keep bold surgical. A few-word key term or a verdict, never a full sentence or clause, and never a bolded lead-in on every paragraph. Most paragraphs carry no bold at all.

Analyst notes are optional. A `> **Analyst note:**` blockquote earns its place only where a section carries genuine investigation-specific context or my own read on something, and one on every dense heading is a fingerprint rather than a feature. Never write one that opens with "this section covers X", defines a term a defender already knows, or restates the body. The executive summary, key takeaways, and response sections never carry one.

---

## Confidence and Attribution

Use the project confidence scale: DEFINITE, HIGH, MODERATE, LOW, INSUFFICIENT. Saying INSUFFICIENT is always allowed and always better than an overclaim.

Every attribution claim carries five things: the actor or "Unknown", the confidence level and percentage, why that level, what is missing, and what would raise it. Those five are a **content checklist, not a template**. Write them as flowing prose, never as a stack of bolded field labels, and never inside a fenced code block, which renders as a grey code box on the site.

> My judgment is that this is unauthorized, malicious activity and not authorized security testing. I hold that at HIGH confidence, around 85 percent.
>
> That rests on four strong and five moderate inconsistencies with the authorized-testing hypothesis. What I cannot do is prove the absence of authorization from captured artifacts alone. A non-engagement confirmation from any one of the targeted platforms is what would move this higher.

Attach confidence labels where a claim's confidence is load-bearing. Stamping a bracketed label on nearly every sentence reads as robotic and is itself a tell.

---

## The MITRE ATT&CK Table

Two acceptable layouts. Column count is a matter of proportion, not safety, because the site CSS wraps long cell content at any width.

**Three columns**, preferred when most rows are HIGH confidence. Open the section with a one-line note that all rows are HIGH unless marked, then append `(MODERATE)` inline on the few that are not.

```markdown
| Tactic / Technique | Name | Evidence |
|---|---|---|
| Defense Evasion / T1055.002 | Portable Executable Injection | Embedded PE injection into `explorer.exe` via W^X |
| Credential Access / T1003.001 | LSASS Memory | mimikatz v2.2.0 (gentilkiwi) |
```

**Four columns**, adding `Conf.`, when confidence varies widely enough that per-row visibility matters.

Merge tactic and technique ID into one column, and drop redundant parent-technique prefixes, because the sub-technique ID already carries the parent. Write `LSASS Memory`, not `OS Credential Dumping: LSASS Memory`.

For a technique spanning two tactics, pick one for the first column and note the cross-tactic detail inline in the Evidence cell.

---

## What Never Appears in a Report

Our own analysis tooling is never named. Use the category term alone, with no name and no parenthetical. Write "a behavioral sandbox", "memory forensics", "decompilation", "a debugger". Never name the sandbox, the disassembler, the lab image, a lab IP, a lab username, a run duration, or a session number. Better still, drop the frame and just state the behavior.

Two things are exempt and must be kept. **Detection data sources the reader will use** (Sysmon, ATT&CK, Sigma, YARA, Suricata, Velociraptor) are guidance, not disclosure. **Tools the malware itself abuses** are the intelligence, so name them and keep every detail. The test is whose tool it is.

Lab artifacts get normalized, not just redacted. A captured path of `C:\Users\<labuser>\AppData\Roaming\...` is not merely a leak, it is wrong intelligence, because it implies the malware targets a user by that name and anyone hunting the literal finds nothing. Publish `%APPDATA%\...`. The same goes for any `<Author>` or `<UserId>` field in a captured persistence artifact, and for screenshots showing a lab hostname or a sinkhole domain.

Cost figures, step-by-step incident response, and organization-specific or tool-specific instructions all stay out. Use risk framing, action categories, and detection strategies instead.

A named-source claim always needs a citation behind it. "Spamhaus recommends blocking AS210558" needs a URL. Without one, write "Threat intelligence feeds flag AS210558 as presumptively malicious infrastructure".

### Angle-bracket placeholders

Inside any raw HTML block, a placeholder like `<pid>` is parsed as an unclosed tag. It silently breaks the enclosing `</table>`, swallows every later heading, and kills the navigation panel.

- Inside raw HTML: `<td>&lt;pid&gt;</td>`
- In normal markdown, including inside backticks: `` `<pid>` `` is safe

---

## The Detection File

Same deployment conventions as a report.

```yaml
---
title: "Detection Rules — [Campaign Title]"
date: 'YYYY-MM-DD'
layout: post
permalink: /hunting-detections/[slug]-detections/
hide: true
---
```

Followed by the campaign block, then top-level sections at `##` in this order: Detection Coverage Summary, Multi-Family Organization if applicable, YARA Rules, Sigma Rules, Suricata Signatures, Coverage Gaps, License. No body H1.

Every YARA and Sigma rule carries an author field of exactly `The Hunters Ledger`.

Every rule is tiered before it is written. **Detection** means durable and precise enough to alert on. **Hunting** means broad but worth a hunt team's time. **Cut** means it belongs in the IOC feed instead, which is where a hard-coded address or a single hash actually belongs.

The per-rule metadata blocks (`**Tier:**`, `**Confidence:**`, `**False Positives:**` and the rest) repeat once per rule by design. They are a catalog a defender scans, so the no-label-colon rule does not apply to them and they must not be turned into prose.

---

## Hard Limits

A report must not exceed **3,000 lines**. That is a backstop and never a target. Length is governed by prose discipline, and a campaign whose depth would exceed it becomes a multi-report series rather than one oversized report.

IOCs live only in `ioc-feeds/[slug]-iocs.json`. Detection rules live only in `hunting-detections/[slug]-detections.md`. Neither is ever embedded in the report.

---

## License Footer

Every report ends with:

```markdown
---

## License

© 2026 Joseph, The Hunters Ledger. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), free to republish and adapt, including commercially, with attribution to The Hunters Ledger and a link to the original.
```

Detection files and IOC feeds carry the same CC BY 4.0 license.

---

*Last updated: August 2026.*
