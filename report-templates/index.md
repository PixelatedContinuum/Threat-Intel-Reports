---
title: Report Templates
layout: page
permalink: /report-templates/
hide: true
---

# Purpose

This section documents the **current report format** used by *The Hunters Ledger* for all threat intelligence publications. The format has evolved significantly from the site's earlier reports. If you are writing a new report or contributing one, this page is the authoritative reference.

**Live reference implementations:**
- [Open Directory Exposure: Sliver C2 Toolchain (45.94.31.220)]({{ "/reports/sliver-open-directory/" | relative_url }}) — full-format deep technical report with companion detection file and IOC feed
- [WebServer Compromise Kit (91.236.230.250)]({{ "/reports/webserver-compromise-kit-91-236-230-250/" | relative_url }}) — multi-component open directory analysis

---

## Three-File Structure

Every full-format report consists of three companion files. All paths are relative to the repository root.

| File | Purpose | Location |
|---|---|---|
| `reports/[name]/index.md` | Main technical report | Rendered at `/reports/[name]/` |
| `ioc-feeds/[name]-iocs.json` | Machine-readable IOC feed | Listed at `/ioc-feeds/` |
| `hunting-detections/[name]-detections.md` | YARA + Sigma + behavioral guidance | Listed at `/hunting-detections/` |

IOCs and detection rules are **never embedded in the main report**. They live in their companion files and are cross-referenced in Appendix A.

---

## YAML Front Matter

Every report opens with this front matter block. The `hide: true` flag excludes it from the standard post listing while keeping it accessible via direct permalink and the reports index.

```yaml
---
title: "[Report Title] — Technical Analysis & Threat Assessment"
date: 'YYYY-MM-DD'
last_updated: 'YYYY-MM-DD'               # optional — only when report is revised after publish
detection_page: /hunting-detections/[slug]-detections/
ioc_feed: /ioc-feeds/[slug]-iocs.json
detection_sections:                       # powers the green Detection panel on the report page
  - label: "YARA Rules"                   # display label shown in the panel
    anchor: "#yara-rules"                 # must match the Jekyll-generated H2 anchor exactly
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "Suricata Rules"
    anchor: "#suricata-rules"
ioc_highlights:                           # powers the blue IOC panel — 3–5 top indicators
  - value: "1.2.3.4"
    note: "Primary C2 server"             # keep under 60 chars
  - value: "abc123..."
    note: "Main payload SHA256"
layout: post
permalink: /reports/[report-folder-name]/
category: "[Malware Category]"
hide: true
description: "[1–2 sentence summary for social sharing previews]"
---
```

**`detection_sections`** — each `anchor` must match the H2 anchor Jekyll generates: lowercase, spaces → hyphens, special characters stripped. Include only the substantive rule sections (YARA, Sigma, Suricata, EDR queries); skip Overview, License, and summary sections.

**`ioc_highlights`** — 3–5 top-priority indicators in the IOC quick-reference panel with one-click copy.

**Three hard rules:**

1. **Atomic indicators only.** Accepted: IPv4/IPv6 addresses, domains, full URLs, file hashes (MD5/SHA1/SHA256). Do NOT use: filenames, file paths, registry keys, mutex names, scheduled task names, tool names, strings, version numbers, or configuration values. These are not directly actionable by copy-paste into a hunt or detection tool.

2. **Defang all network indicators.** Replace `.` with `[.]` in IPs and domains. Replace `http`/`https` with `hxxp`/`hxxps` in URLs. Hashes are not defanged.
   - IP: `185.49.126.140` → `185[.]49[.]126[.]140`
   - Domain: `evil.com` → `evil[.]com`
   - URL: `hxxp://evil[.]com/payload`
   - Hash: `f4b00fbc6a3ce80b474334a3ccaadcf0` — no change

3. **Prioritize by impact.** Order highest to lowest risk:
   - Active C2 IPs and domains first — immediately blockable/huntable
   - Payload hashes second — definitive file-based detection anchors
   - Delivery domains and staging servers third
   - Skip generic hosting IPs, low-uniqueness indicators, or anything not confirmed malicious

If fewer than 3 atomic IOCs exist, omit `ioc_highlights` entirely rather than padding with non-atomic values.

Immediately after the front matter (before the first heading), add the campaign identifier, last updated date, and threat level. Use `<br>` tags so each field renders on its own line:

```markdown
**Campaign Identifier:** [CampaignID]<br>
**Last Updated:** [Month D, YYYY]<br>
**Threat Level:** [CRITICAL/HIGH/MEDIUM/LOW]
```

**Why `<br>` tags are required:** In Jekyll/Markdown, consecutive lines without a blank line between them are collapsed into a single paragraph. Without `<br>`, all three fields will render on one line instead of three.

**Campaign ID naming convention:** Describe *what was found*, not the assumed attacker.
✓ `WebServer-Compromise-Kit-45.94.31.220`
✗ `Attacker-Infrastructure-45.94.31.220`

---

## Report Section Structure

The canonical section order for a full-format report. Brief sections at top (BLUF, ToC) precede the numbered body sections.

### Before the Table of Contents

```markdown
---

## BLUF (Bottom Line Up Front)

[2–4 sentences: what was found, what infrastructure, what capability, when discovered.]

**Threat Category:** [Category] — [LEVEL] confidence ([XX]%). Designated **[UTA-YEAR-###]** *(an internal tracking label used by The Hunters Ledger — see Section 6)*.
**Threat Level:** [CRITICAL/HIGH/MEDIUM/LOW] — [one-sentence rationale]
**Intelligence Type:** [Descriptive/Explanatory/Anticipatory] — [what type of intelligence this report provides]

> [Source/basis statement — what evidence this assessment is based on]

> **Key caveat:** [Most important limitation or time-sensitivity note]

[Optional lead figure — e.g., open directory screenshot — placed here before the ToC]
```

### Table of Contents (numbered)

```markdown
---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Sample and Artifact Inventory](#2-sample-and-artifact-inventory)
3. [Kill Chain Analysis](#3-kill-chain-analysis)
4. [Evasion Techniques — Deep Technical Analysis](#4-evasion-techniques)
5. [Infrastructure and Build Pipeline](#5-infrastructure-and-build-pipeline)
6. [Threat Actor Assessment](#6-threat-actor-assessment)
7. [MITRE ATT&CK Mapping](#7-mitre-attck-mapping)
8. [Detection Opportunities](#8-detection-opportunities)
9. [Analytical Caveats and Gaps](#9-analytical-caveats-and-gaps)
10. [Response Guidance](#10-response-guidance)
11. [Appendix A: IOC and Detection File References](#appendix-a)
12. [Appendix B: Research References](#appendix-b)
```

### Numbered Body Sections

**Heading level rule:** All top-level numbered sections (1–10 and Appendices) use `##` (H2) — never `#` (H1). The report title rendered by Jekyll is already the page H1; using `#` inside the body creates a duplicate H1 and breaks the site's TOC scan, which only builds from H2 headings. Sub-sections within a numbered section use `###` (H3).

✓ Correct: `## 1. Executive Summary`
✗ Wrong: `# 1. Executive Summary`

**Section 1 — Executive Summary**
High-level overview for a mixed audience. Covers the threat in plain terms, what defenders gained from the intelligence, and what the attacker built. Plain language first, technical depth second. Includes key analyst notes (operational caveats, confidence limitations).

**Section 2 — Sample and Artifact Inventory**
Enumerate all analyzed files: filename, size, type, MD5/SHA1/SHA256, brief description. May include a version / packer table. For open-directory cases, include file count, directory structure summary, and artifact categories recovered.

**Section 3 — Kill Chain Analysis**
The core technical section. See *Kill Chain Staging Format* below for the required structure. Stages are numbered 0–N. Stage 0 is typically the pre-victim build/setup activity if build artifacts are available.

**Section 4 — Evasion Techniques — Deep Technical Analysis**
A per-technique deep dive on each evasion method. Each sub-section opens with a `> **Plain language:**` blockquote before technical content. Covers mechanism, implementation details, detection implications, and confidence level for each technique.

**Section 5 — Infrastructure and Build Pipeline**
IP addresses, ASN, hosting provider, domain registration, certificate details, build environment. Cross-reference C2 configuration with observed evidence.

**Section 6 — Threat Actor Assessment**
Must open with the UTA explanatory blockquote (see *UTA Handling* below). Includes attribution confidence statement in the required format, indicators used, gaps, and what would increase confidence.

**Section 7 — MITRE ATT&CK Mapping**
Table format: Technique ID | Technique Name | Tactic | Evidence | Confidence. Group by tactic. Summarize total technique count and coverage notes.

**Section 8 — Detection Opportunities**
Summary of what is detectable and at which layer (file, behavioral, network, memory). Cross-reference to the companion detection file. Do not embed rule code here.

**Section 9 — Analytical Caveats and Gaps**
Enumerate unresolved questions and intelligence gaps as a numbered or bulleted list. Explicit about what was not observed, what could not be confirmed, and what would be needed to close each gap.

**Section 10 — Response Guidance**
Action categories only — not step-by-step procedures. Written for a third-party intelligence provider audience. No tool-specific configurations, no organization-specific recommendations.

**Appendix A — IOC and Detection File References**
Links to the companion files. Do not duplicate IOC content here.

**Appendix B — Research References**
All sources cited in the report. Named-source claims ("CISA confirms…", "Spamhaus flags…") require a URL citation here or must be replaced with general language.

---

## Kill Chain Staging Format

Each stage uses this structure. The `> **Plain language:**` blockquote is **mandatory** for every stage — it is the only plain language format. Do not add a separate italic one-liner.

```markdown
### Stage N — [Short Name]: [Source or Module]

> **Plain language:** [1–3 sentences in non-technical English explaining what happens in this stage and why it matters to a non-technical reader.]

[Technical content — evidence, code analysis, API calls, configuration values, confidence levels]
```

**Stage numbering convention:**
- Stage 0 is typically pre-victim activity (build pipeline, attacker setup)
- Stages 1–N follow the victim-side kill chain in chronological order
- Sub-stages use bold labels: `**Sub-stage 5a — [Name]:**`

---

## Plain Language Accessibility

Every section containing dense technical content must open with a plain language summary blockquote:

```markdown
> **Plain language:** [1–3 sentences in non-technical English explaining what this section covers and why it matters. Maximum 3 sentences. Comprehensible to a non-technical executive.]
```

This blockquote appears **immediately after the section or stage heading**, before any technical content.

**Content distribution targets:**

| Content type | Target ratio |
|---|---|
| Technical analysis with plain-language explanations | 70–80% |
| Response guidance (action categories only) | ≤10% |
| Threat intelligence tied to observed findings | 10–20% |

No generic threat landscape content that is not tied to actual findings.

---

## Tool Name Conventions

On **first mention** of any analysis tool, include a parenthetical explaining its category:

| ✓ Correct (first use) | ✗ Wrong |
|---|---|
| `behavioral sandbox (Noriben)` | `Noriben` |
| `memory forensics tool (Volatility)` | `Volatility` |
| `disassembler (Binary Ninja)` | `Binary Ninja` |
| `interactive debugger (x64dbg)` | `x64dbg` |

On **subsequent mentions**, use the general category term only — not the tool name:

> "The behavioral sandbox logged 47 file creation events…" *(not "Noriben logged…")*

**Exception:** Standard, widely-known frameworks may be used without explanation on any mention: Sysmon, MITRE ATT&CK, Sigma, YARA.

---

## Figure Block Format

Screenshots and analytical images use this HTML block. Figures are numbered sequentially in document order.

```html
<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/[campaign-folder]/[filename].png" | relative_url }}" alt="[descriptive alt text]">
  <figcaption><em>Figure N: [Description of what the image shows and why it is significant.]</em></figcaption>
</figure>
```

Images live in `assets/images/[campaign-folder]/` with web-safe filenames (lowercase, hyphens for spaces).

Only include screenshots that show accurate, meaningful analytical findings. Remove any figure that is inaccurate or that does not add intelligence value.

---

## Confidence Levels

Use this exact framework for all confidence claims throughout the report:

| Level | Meaning |
|---|---|
| **DEFINITE** | Direct evidence — no ambiguity |
| **HIGH** | Strong evidence — minor gaps |
| **MODERATE** | Reasonable evidence — notable gaps |
| **LOW** | Weak or circumstantial evidence |
| **INSUFFICIENT** | Not enough data to assess |

You have explicit permission to say "INSUFFICIENT" or "I don't know." Overstating confidence damages credibility more than acknowledging uncertainty.

---

## Attribution Confidence Statement

Every attribution claim in Section 6 must include this structured statement:

```
Threat Actor: [Name or "Unknown"]
Confidence: [LEVEL] (XX%)
  - Why this confidence: [Evidence supporting this level]
  - What's missing: [Evidence gaps preventing higher confidence]
  - What would increase confidence: [Specific research needed]
```

**Language precision by confidence level:**
- **DEFINITE:** "attributed to", "confirmed as", "operated by"
- **HIGH:** "highly likely", "strong indicators suggest", "probable attribution to"
- **MODERATE:** "possible attribution to", "indicators suggest", "tentatively attributed to"
- **LOW:** "weak indicators suggest", "insufficient evidence for attribution"
- **INSUFFICIENT:** "cannot attribute", "attribution not possible"

---

## UTA Handling

When a report assigns a UTA (Unattributed Threat Actor) designation, two elements are required:

**1 — BLUF parenthetical (first mention):**
```markdown
Designated **UTA-2026-001** *(an internal tracking label used by The Hunters Ledger — see Section 6)*.
```

**2 — Section 6 explanatory blockquote (opens the Threat Actor Assessment section):**
```markdown
> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-[YEAR]-[###] is an internal tracking designation assigned by The Hunters Ledger to actors observed across analysis who cannot yet be linked to a publicly named threat group. This label will not appear in external threat intelligence feeds or vendor reports — it is specific to this publication. If future evidence links this activity to a known named actor, the designation will be retired and updated accordingly.
```

---

## Output Perspective

All report content must reflect the perspective of a **third-party threat intelligence provider** — not an internal security team.

**Never include:**
- Monetary cost or damage estimates
- Detailed step-by-step incident response procedures
- Organization-specific recommendations ("Your SOC should…")
- Tool-specific configurations ("Configure Splunk to…")
- Compliance-specific procedures

**Always use:**
- Risk framing: "This enables attackers to…" — not "$50K in damages"
- Action categories: "Isolate affected systems" — not step-by-step commands
- Detection strategies: "Monitor for [behavior]" — not tool configuration blocks
- Third-party neutral language throughout

---

## Source Citation Integrity

All named-source claims require a directly cited source. If a URL cannot be cited, remove the named attribution and use general language instead.

| ✓ Correct (with citation) | `Threat intelligence feeds flag AS210558 as presumptively malicious infrastructure [Source: drop.spamhaus.org, accessed 2026-02-28]` |
|---|---|
| ✓ Correct (without citation) | `Threat intelligence feeds flag AS210558 as presumptively malicious infrastructure` |
| ✗ Wrong | `Spamhaus recommends blocking AS210558` — named-source claim with no citation |

---

## Hard Limits

- **Report length:** 3,000 lines maximum
- **IOC location:** `ioc-feeds/[name]-iocs.json` only — never embedded in the report
- **Detection rules:** `hunting-detections/[name]-detections.md` only — never embedded in the report
- **No Quick Reference section:** Do not include a "Quick Reference" table or section (linking to IOC/detection anchors). The report sidebar panels already surface these links — a Quick Reference section is redundant and adds unnecessary length.

---

## License Footer

Every report ends with:

```markdown
---

## License

© 2026 Joseph. All rights reserved. See LICENSE for terms.
```

IOC feeds and detection rule files are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.

---

*Last updated: March 2026*
