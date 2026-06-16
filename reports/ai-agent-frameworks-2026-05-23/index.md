---
title: "Multi-Actor AI-Agent Framework Abuse: 8 Operators Integrating AI CLIs into Offensive Workflows"
date: '2026-06-04'
layout: post
permalink: /reports/ai-agent-frameworks-2026-05-23/
thumbnail: /assets/images/cards/ai-agent-frameworks-2026-05-23.png
hide: true
sponsored_by: hunt-io
category: "AI-Augmented Threat Operations"
series: ai-agent-frameworks
series_role: parent
series_order: 0
description: "Parent report of a six-report series documenting 8 independent threat operators integrating AI-agent CLIs (Gemini CLI, Claude Code, Atlassian Rovodev, OpenClaw, Cursor IDE) into offensive workflows, observed through open-directory exposures. Five novel TTPs, six UTA designations, one named-actor HIGH attribution (Vova75Rus), and a GitHub Trust & Safety Tier-0 disposition outcome."
detection_page: /hunting-detections/ai-agent-frameworks-2026-05-23-detections/
ioc_feed: /ioc-feeds/ai-agent-frameworks-2026-05-23-iocs.json
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
  - "tralalarkefe.com"
  - "kryptex.network"
  - "209.38.205.158"
  - "87.106.143.220"
  - "5.230.201.54"
stix_bundle: /stix/ai-agent-frameworks-2026-05-23.json
---

**Campaign Identifier:** AI-Agent-Frameworks-MultiActor-2026-05-23<br>
**Last Updated:** June 4, 2026<br>
**Threat Level:** HIGH

---

> **Data source:** The open-directory intelligence behind this investigation was surfaced via [Hunt.io](https://hunt.io)'s [AttackCapture](https://hunt.io/features/attackcapture) platform, which sponsors this report series. The analysis, findings, and conclusions are The Hunters Ledger's own.

## 1. Executive Summary

**Bottom line:** eight unrelated threat operators have independently wired AI-agent CLIs into live offensive operations, and the evidence is operator-side — their own handoff documents, attacker prompts, weaponized configs, AI-co-authored code, and stolen victim data — not the AI-output measurements that dominate public reporting. Two victims are confirmed compromised at capture time: a HIPAA-regulated US healthcare provider (Case 1) and a state-affiliated Turkish financial-sector organization (Case 2). The campaign yields **five novel TTPs**, **six UTA designations**, **one named-actor HIGH attribution** (Vova75Rus, 88%), and **one Tier-0 disposition outcome** — GitHub Trust & Safety suspended Vova75Rus on 2026-05-25, severing the GHOST kit's upstream distribution channel.

The campaign-defining pattern is **multi-vendor diversity**: no two operators share an AI tool, host, target sector, or motivation. That refutes the "single coordinated AI-driven campaign" framing in favor of ecosystem-wide diffusion of AI-augmented tradecraft across unrelated actors — so no single vendor block, IOC sweep, or threat-group designation closes the gap (coordination explicitly REFUTED, §9). The corollary cross-case finding: **AI does not replace operator tradecraft, it extends it** — every operator retains capability without AI (§4.10).

This is the parent of a six-report series, surfaced via [Hunt.io open-directory intelligence](https://hunt.io/features/attackcapture) over a 9-day, 16-phase investigation from 2026-05-16. It is the canonical cross-case reference; five sub-reports (Cases 1, 2, 3, 4, 9) carry the per-case forensic depth. Links to every sub-report are in §14.2.

### Findings at a glance

The eight active operator cases, each with its home section:

- **[Case 1 — Russian Gemini credential-mill](/reports/russian-gemini-credential-mill-213.165.51.115/)** (UTA-2026-012, MODERATE 75%) — AEZA host, Cloudflare-Tunnel C2 under `tralalarkefe.com`, persistent RDP+SSH into the US healthcare victim, 40+ stolen Gemini keys; source of two novel TTPs. See §4.1.
- **[Case 2 — Turkish ARPA observability-harvester](/reports/turkish-arpa-openclaw-state-insurer-209.38.205.158/)** (UTA-2026-013, high-MODERATE 78%) — `ARPA Korelasyon Motoru` platform cross-correlating four stolen observability sources against a state-affiliated Turkish financial-sector victim, with insider AD recruitment. GitHub T&S actioned handle MehmetARPA on 2026-05-25. See §4.2.
- **[Case 3 — Rovodev/Pandora Mirai botnet](/reports/rovodev-mirai-matrix-c2-87.106.143.220/)** (UTA-2026-014, LOW 60%) — IONOS host, 11-architecture Mirai botnet, Rovodev session JSONs capturing AI authoring the attack framework. See §4.3.
- **[Case 4 — Korean Claude+OpenClaw](/reports/korean-claude-openclaw-221.150.15.104/)** (UTA-2026-015, LOW 55%) — `~/.claude/settings.local.json` pre-approving an `openclaw.ai` installer in the Claude Code allowlist. See §4.4.
- **[Case 9 — GHOST cryptojacker kit + 4-tier supply chain](/reports/ghost-cryptojacker-vova75rus-77.110.96.200/)** (Vova75Rus HIGH 88% / UTA-2026-016 / UTA-2026-017) — byte-identical `libpam_cache.so` LD_PRELOAD rootkit across two AEZA customer hosts; GitHub T&S Tier-0 action against kit author Vova75Rus on 2026-05-25. See §4.5.
- **Cases 7, 8, 10** — capsule-depth captures (productivity-AI stack at 139.59.239.112; 60-second AI-orchestrated payment-API attack at 68.183.92.28; Sliver-derivative C2 staging at 5.230.201.54). INSUFFICIENT attribution but operationally-relevant TTPs. See §4.6–4.8.

Two further hosts (Case 5, 173.249.2.23; Case 6, 66.94.120.32) were **demoted** to benign during analysis — a defensive-security consultant and a HuggingFace ML researcher. They anchor the campaign's central defender lesson: **AI tool presence on a host is not, by itself, a malicious indicator** (§4.11).

### Why it matters

Three things distinguish this campaign from prior AI-misuse reporting, each developed in its home section:

- **Operator-side workflow documentation, not AI-generated content.** Public reporting measures the AI *output* (phishing tone, malware code style); this documents the *input* — what operators do with AI CLIs on their own servers. The five novel TTPs were absent from 8+ major vendor AI-misuse reports searched as prior art, filling a documented gap (§4.9).
- **AI extends tradecraft, it does not replace it.** None of the eight operators uses AI as a substitute for offensive skill — each ships substantial non-AI capability (§4.10). The three-class taxonomy's "AI-democratized script-kiddie" class is theoretical: no pure exemplar exists in this dataset.
- **One report-batch can disrupt an ecosystem upstream.** Identifying Vova75Rus as the GHOST kit author (separate from his customer operators) and preserving his GitHub footprint via Wayback before disclosure preceded GitHub T&S's 2026-05-25 account-level action — all 9 payload-distribution repos now return HTTP 404, severing the source both observed customers pulled from (§9.1).

### Key Risk Factors

The score is **HIGH (8.3/10)**, scoring aggregate capability across 8 unrelated operators rather than any single sample. It sits below CRITICAL because no single operator reaches campaign-scale capability — each is bounded by its own infrastructure — but ecosystem-level findings (AI-tradecraft diffusion, Case 9 supply-chain depth, confirmed-victim impact in Cases 1 and 2) hold it above MEDIUM.

<table>
<colgroup>
<col style="width: 28%;">
<col style="width: 12%;">
<col style="width: 60%;">
</colgroup>
<thead>
<tr><th>Risk Dimension</th><th>Score</th><th>Rationale</th></tr>
</thead>
<tbody>
<tr><td>Data Exfiltration</td><td>9/10</td><td>Case 2 stolen observability tenant against a state-affiliated Turkish financial-sector victim (4 sources cross-correlated); Case 1 persistent RDP+SSH into named US healthcare victim; Case 9 wallet-extraction from cloud GPU victims; Case 1 40+ stolen Gemini Pro API keys.</td></tr>
<tr><td>Persistence Difficulty</td><td>8/10</td><td>Case 9 LD_PRELOAD libc-hook rootkit (`/etc/ld.so.preload` + `libpam_cache.so`) survives standard remediation if not enumerated; Case 1 Cloudflare Tunnel persistent tunnels survive server-side IP changes; Case 3 5-vector persistence chain (cron + rc.local + init.d + systemd + bashrc).</td></tr>
<tr><td>Evasion Capability</td><td>7/10</td><td>Mixed — Case 9 rootkit hides processes/files/network at libc layer; Case 1 Cloudflare Tunnel domain-fronting; Hysteria v2 (a QUIC-based proxy/backdoor protocol with TLS SNI masquerade capability) with bing.com SNI masquerade; but Cases 1, 3, 4 ship without anti-analysis (consistent with AI-generated structural code signature).</td></tr>
<tr><td>AI Integration Maturity</td><td>8/10</td><td>5 novel TTPs documented at first-public-documentation level; AI integrated across credential mutation (Case 1), code generation (Cases 1+2+3), workflow orchestration (Case 8), permission-allowlist customization (Case 4), and operator-to-AI handoff documents (Cases 1, 3).</td></tr>
<tr><td>Supply Chain Depth</td><td>9/10</td><td>Case 9 4-tier supply chain (UnamSanctam upstream OSS → Vova75Rus kit author → ≥2 customer operators → 4,573-entry ComfyUI victim scan list); byte-identical kit binary across customer hosts; OWNER Telegram bot supply-chain monitoring signature.</td></tr>
<tr><td>Named-Victim Impact</td><td>9/10</td><td>the victim organization (a state-affiliated Turkish financial-sector organization); the healthcare victim (US healthcare provider, HIPAA-regulated, persistent RDP+SSH); both with operator-confirmed access at time of investigation.</td></tr>
</tbody>
</table>

**Overall Campaign Risk Score: 8.3/10 — HIGH.** Remediation is partially complete: GitHub T&S actioned Vova75Rus, cloud-provider abuse desks were notified for 78 victim IPs (Hetzner opened an investigation 2026-06-02; AWS requested evidence 2026-06-03), and Cloudflare PSIRT response on `tralalarkefe.com` is pending. Reassess if Cloudflare PSIRT does not action `tralalarkefe.com` or AEZA Group does not respond to the disclosure package.

### Threat Actor Summary

This is a **multi-actor** campaign. Attribution spans one named actor and six UTA designations; full per-actor assessments are in §9.

- **Vova75Rus** *(named, HIGH 88%)* — Case 9 GHOST kit author (separate identity from his customer operators).
- **UTA-2026-012** *(an internal tracking label used by The Hunters Ledger — see Section 9)* — Case 1 Russian Gemini operator (MODERATE 75%).
- **UTA-2026-013** — Case 2 Turkish ARPA operator (high-MODERATE 78%).
- **UTA-2026-014** — Case 3 Rovodev/Pandora Mirai operator (LOW 60%).
- **UTA-2026-015** — Case 4 Korean Claude+OpenClaw operator (LOW 55%).
- **UTA-2026-016** / **UTA-2026-017** — Case 9 GHOST customers Operator-A (77.110.96.200, LOW 60%) and Operator-B (77.110.125.145, LOW 55%).

Cases 7, 8, 10 are **INSUFFICIENT** for attribution at capsule depth. **No Tier-1 government attribution** applies to any operator.

### For Technical Teams

The campaign-wide detection content (26 rules: 8 YARA, 12 Sigma, 6 Suricata) is in the linked detection file; per-case rules live in each sub-report's detection deliverable (§10.2).

- **Detect first:** AI Operator Handoff Documents (§4.9.1), LLM-Personalized Credential Mutation prompts (§4.9.2), operator-built unauthenticated Python-stdlib C2 endpoints (§4.9.5).
- **Hunt first:** `/etc/ld.so.preload` modifications (Case 9), `~/.gemini/` / `~/.rovodev/` / `~/.claude/settings.local.json` artifacts (Cases 1, 3, 4), `tralalarkefe.com` subdomain DNS queries (Case 1).
- **Block first:** `*.kryptex.network` (Case 9 pool), `tralalarkefe.com` (Case 1 C2); monitor outbound to `generativelanguage.googleapis.com` for password-mutation prompt fragments (§4.9.2).
- **IR priority:** Cases 9 and 1 ship persistence that survives standard remediation — see §10 for posture and §12 for the response orientation (no step-by-step procedures; third-party perspective).

The Vova75Rus disposition (GitHub T&S 2026-05-25) is the headline disruption, and not the only one: GitHub also actioned the Turkish ARPA account (MehmetARPA, 2026-05-25). Treat the GHOST upstream channel as **temporarily** disrupted and expect re-hosting (§9.1). The defender takeaway is not "block AI" — most operators would still be capable — but **detect the AI-integration layer**, because it produces distinctive, durable artifacts that hand defenders a previously-unavailable signal.

---

## The Defender's Mirror — Running This Investigation with AI

The eight operators below weaponize AI-agent CLIs for offense; this investigation ran on the mirror image of that pattern. An analyst directing an AI agent (Claude), paired with the Hunt.io platform, surfaced and triaged every case across multiple exposed hosts and produced this six-report series — a scope not normally tractable for a solo analyst, made tractable by the same AI-augmentation the report documents. The takeaway for defenders is the symmetry itself: the tooling that lowers the barrier for attackers lowers it just as far for the people hunting them. The full per-endpoint methodology, sponsorship disclosure, and candid account of what worked and failed are in **[§13](#methodology)** (and openly: **[How Reports Are Made](/behind-the-reports/ai-workflow/)**, **[How Threats Are Found](/behind-the-reports/collection-platform/)**).

---

## 2. Business Risk Assessment

### Understanding the Real-World Impact

This campaign matters to security leadership for three reasons a single-operator view misses:

1. **AI-augmented tradecraft is ecosystem-wide, not single-actor.** Eight independent operators, five AI tools, four motivations (financial cybercrime, state-aligned espionage, DDoS-for-hire, operator productivity) — the threat is **diffuse**, so no single vendor block or IOC sweep addresses it.
2. **Detection coverage has a gap at the operator-side workflow layer.** Public reporting is well-supplied with AI-generated-content signatures (phishing tone, code style) but poorly supplied with operator-side artifacts (handoff documents, weaponized configs, AI permission allowlists). The 26 linked detection rules target that undersupplied layer.
3. **Named-victim impact is concrete.** Two confirmed victims — a US healthcare provider and a state-affiliated Turkish financial-sector organization — plus that organization's regulated-sector partner ecosystem are confirmed compromise outcomes, not hypothetical exposure.

### Impact Scenarios

<table>
<colgroup>
<col style="width: 28%;">
<col style="width: 14%;">
<col style="width: 58%;">
</colgroup>
<thead>
<tr><th>Scenario</th><th>Likelihood</th><th>Explanation</th></tr>
</thead>
<tbody>
<tr><td>AI-Personalized credential-stuffing wave against your tenants</td><td>HIGH</td><td>Case 1 confirmed at-scale: ~5.5 MB AI_ADMIN_MUTANTS.txt output file shows operator running per-target LLM-generated password mutations against email/domain pairs. Tenants whose breached-password datasets are in public combolists are highest-risk.</td></tr>
<tr><td>Observability-tool reverse-pipeline data theft</td><td>MODERATE</td><td>Case 2 demonstrates that stolen Instana/SolarWinds/Zabbix tokens give read access to your production topology, application service catalog, host inventory, and traffic flow. If your observability tokens are not rotated and scoped, this is a viable theft path.</td></tr>
<tr><td>Persistent Cloudflare-Tunnel C2 against on-premise victims</td><td>HIGH</td><td>Case 1 the healthcare victim shows persistent RDP+SSH access via 5 named tunnel hostnames under operator-owned domain. The custom-domain model is more durable than typical *.trycloudflare.com ephemeral abuse.</td></tr>
<tr><td>Commodity LD_PRELOAD libc-hook rootkit on Linux servers</td><td>HIGH</td><td>Case 9 GHOST kit is multi-tenant commodity. Byte-identical libpam_cache.so across 2 customer hosts means deployments are continuing whether or not we observe them. Standard remediation that does not enumerate /etc/ld.so.preload will leave the rootkit in place.</td></tr>
<tr><td>Cloud GPU cryptojacking on your ML/AI infrastructure</td><td>MODERATE</td><td>Case 9 ComfyUI fake-node persistence (PerformanceMonitor + GPU Performance Monitor) targets ML platforms specifically. Cloud GPU compute is the high-margin target.</td></tr>
<tr><td>11-architecture Mirai-family botnet recruitment of IoT</td><td>MODERATE</td><td>Case 3 Pandora variants span ARM, ARM5/6/7, MIPS, MIPS-LE, x86, x86_64, SH4, SuperH, PowerPC, SPARC — comprehensive IoT/embedded architecture coverage.</td></tr>
<tr><td>State-aligned espionage data harvesting via insider recruitment</td><td>LOW–MODERATE</td><td>Case 2 insider-recruited Windows AD user [employee ID — suppressed] with operator-authored Turkish-language tunnel-setup documentation. Targeting model is sector-specific (a Turkish state-affiliated financial-sector ecosystem) not generic.</td></tr>
<tr><td>Sliver-derivative C2 against your enterprise endpoints</td><td>LOW</td><td>Case 10 captured pre-victim (zero sessions / zero beacons in database). Active development (v30→v39 in one day) suggests imminent victim engagement, but no current victims observed.</td></tr>
</tbody>
</table>

### Operational Impact Timeline (If Infection Confirmed)

The following is a generic phase model — refer to Section 12 (Response Orientation) for the action-category guidance and engage your internal IR team for the actual response. The Hunters Ledger does not provide step-by-step IR procedures (third-party intelligence-provider perspective).

- **Initial Phase** (first 24–48 hours after detection) — confirm scope, isolate affected hosts, preserve forensic state. Person-hours vary by infrastructure complexity.
- **Investigation Phase** (days 2–14) — determine root cause, enumerate persistence mechanisms (especially `/etc/ld.so.preload` for Case 9 variants), determine credential exposure, determine victim data accessed. Multi-source observability data (if Case 2 applies) requires correlating stolen-token logs across SolarWinds/Zabbix/Instana/Aria.
- **Remediation Phase** (weeks 2–6) — credential rotation (prioritize cloud-LLM API keys, observability platform tokens, GitHub PATs); persistence removal (kernel-level/rootkit cases typically require full rebuild — see Section 9); C2 infrastructure blocking at perimeter.
- **Enhanced Monitoring Phase** (months 1–3) — deploy detection rules from the linked detection file, network-wide hunt for lateral-movement and persistence indicators, validate that all stolen-token usage has stopped.
- **Ongoing** — quarterly review of AI-integration artifacts (`~/.gemini/`, `~/.rovodev/`, `~/.claude/settings.local.json`, `~/.openclaw/`) across server estate; quarterly review of LD_PRELOAD modifications on Linux estate; ongoing monitoring of upstream supply-chain channels for Vova75Rus re-hosting attempts post-GitHub-T&S suspension.

---

## 3. Technical Classification

> **Analyst note:** This section establishes the campaign's identity, scope, and overall composition. Because this is a multi-actor campaign rather than a single malware family, classification spans 8 unrelated operators rather than a single sample lineage. Readers familiar with single-family analyses should expect a wider taxonomy.

### Classification & Identification

<table>
<colgroup>
<col style="width: 30%;">
<col style="width: 35%;">
<col style="width: 35%;">
</colgroup>
<thead>
<tr><th>Attribute</th><th>Value</th><th>Confidence</th></tr>
</thead>
<tbody>
<tr><td>Campaign Type</td><td>Multi-actor synthesis (8 unrelated active operators + 2 demoted false-positives)</td><td>DEFINITE</td></tr>
<tr><td>Threat Category</td><td>Cybercrime (Cases 1, 3, 9), espionage-adjacent (Case 2), capability-building (Cases 4, 7, 10), unspecified-orchestration (Case 8)</td><td>HIGH</td></tr>
<tr><td>Campaign Coordination</td><td>REFUTED — 8 independent operators with distinct IOCs, wallets, language, geography, targets, motivations, and AI tools</td><td>HIGH</td></tr>
<tr><td>Cross-Case Common Vector</td><td>AI-agent CLI integration as offensive-workflow component (ecosystem-level diffusion)</td><td>DEFINITE</td></tr>
<tr><td>Sophistication Distribution</td><td>Mid-tier-selective (Case 1), Advanced (Cases 2, 9), Hybrid AI-augmented (Case 3), Mid-tier (Case 4, 10)</td><td>HIGH</td></tr>
<tr><td>Confirmed Victims</td><td>the healthcare victim (US healthcare, Case 1), the victim organization (a state-affiliated Turkish financial-sector organization, Case 2)</td><td>DEFINITE</td></tr>
<tr><td>Named Threat Actors</td><td>Vova75Rus (Case 9 kit author, HIGH 88%)</td><td>HIGH</td></tr>
<tr><td>UTA Assignments</td><td>UTA-2026-012 through UTA-2026-017 (six assignments across Cases 1, 2, 3, 4, 9-A, 9-B)</td><td>Variable (LOW to high-MODERATE)</td></tr>
<tr><td>Tier-0 Disposition Outcome</td><td>GitHub T&S account-level action against Vova75Rus 2026-05-25 (all 9 repos HTTP 404)</td><td>DEFINITE</td></tr>
</tbody>
</table>

### Malware Families and Tooling Inventory

The campaign spans at least eight distinct families — some commodity (Sliver, Mirai, Quasar-class), some custom-built per operator (Russian A2A C2, ARPA observability harvester). Operator-built tooling exhibits the cross-case **AI-Generated Offensive Code Structural Signature** (§4.9).

| Family | Case | Type | Confidence |
|---|---|---|---|
| GHOST v5.1/v6.0 cryptojacker kit + `libpam_cache.so` LD_PRELOAD rootkit | 9 | Multi-tenant commodity kit (kit author Vova75Rus) | DEFINITE |
| Russian A2A C2 (operator-built unauthenticated Python-stdlib BaseHTTPServer) | 1 | Custom-built Python C2 | DEFINITE |
| ARPA observability harvester / reverse-pipeline platform | 2 | Custom-built TimescaleDB+Neo4j+Redis ETL | DEFINITE |
| Pandora (Android.Pandora.[N] Mirai descendant, 11-architecture suite) | 3 | Mirai-family botnet | DEFINITE |
| Sliver framework + Fernet+zlib+b64 PyInstaller-stub crypter | 10 | Commodity Sliver derivative | DEFINITE |
| Quasar-class PowerShell agent chain | 1 | Operator-deployed RAT | HIGH |
| Hysteria v2 backdoor with bing.com SNI masquerade | 9 | QUIC-based backdoor | DEFINITE |
| Weevely + frp + Claude productivity stack | 7 | Post-compromise productivity stack | MODERATE |

### AI Tools Observed (Operator-Integrated)

The AI-tool integration layer — the campaign's defining attribute — spans **five distinct AI-agent CLIs**, each used by a different operator. That vendor diversity is itself a finding: it refutes the "single AI vendor attack vector" framing.

| AI Tool | Vendor | Case(s) | Operator-Side Artifact |
|---|---|---|---|
| Gemini CLI | Google | 1 | `~/.gemini/` directory with operator-authored handoff documents; Gemini 2.5 Flash invoked for per-target password mutation |
| Atlassian Rovodev (CLI) | Atlassian | 3 | `~/.rovodev/sessions/` capturing operator's natural-language prompts authoring complete C2 framework code |
| Claude Code | Anthropic | 4, 7 | `~/.claude/settings.local.json` pre-approving attacker installer + OpenClaw commands |
| OpenClaw | Open-source ecosystem | 2, 4 | `~/.openclaw/`, `/api/ingest/instana` endpoint, ARPA platform integration |
| Cursor IDE | Cursor | 10 | Inferred (HIGH confidence) from co-located binaries; not confirmed from AI-session transcripts |

### Compilation and Operational Tempo

The campaign was active during the investigation window (2026-05-16 to 2026-05-25):

| Case | Last Operator Activity | Active As Of Report Date |
|---|---|---|
| Case 1 (Russian Gemini) | Session activity through 2026-03-30 | LIKELY ACTIVE |
| Case 2 (Turkish ARPA) | Daily topology logs through 2026-05-23; dashboard live 2026-05-24 | CONFIRMED ACTIVE |
| Case 3 (Rovodev/Pandora) | Hunt live as of 2026-05-23 | CONFIRMED ACTIVE |
| Case 4 (Korean Claude+OpenClaw) | Capsule capture only | UNKNOWN |
| Case 9 Operator-A (GHOST) | Active tool iteration 2026-05-24 (min1.sh modified day-of) | CONFIRMED ACTIVE |
| Case 9 Operator-B (GHOST) | Abandoned host signals | LIKELY INACTIVE |
| Case 7 (productivity stack) | Capsule capture only | UNKNOWN |
| Case 8 (60s payment-API) | Capsule capture only | UNKNOWN |
| Case 10 (Sliver staging) | Active as of 2026-05-23T17:25 UTC; loader v30→v39 in 1 day | CONFIRMED ACTIVE |

Four of eight cases (2, 3, 9-A, 10) were active during the investigation window — this is an ongoing campaign, not retrospective analysis of historical artifacts.

---

## 4. Technical Capabilities Deep-Dive — Per Case

> **Analyst note:** This section is the technical heart of the report, but it is a *synthesis* volume: cases with their own sub-report (1, 2, 3, 4, 9) appear here as one-paragraph capsules — what the case is, why it matters, primary indicator — with the full forensic depth in the linked sub-report (§14.2). Cases 7, 8, 10 have no sub-report and are documented at capsule depth here. The parent's core value follows the capsules: §4.9 five novel TTPs, §4.10 the three-class taxonomy, §4.11 false-positive discrimination — all cross-case synthesis. Each capsule is self-contained.

### 4.1 Case 1 — Russian Gemini Credential-Mill Operator

**Capsule.** The campaign's most technically integrated AI-augmented operator and the source of two of the five novel TTPs — LLM-Personalized Credential Mutation (§4.9.2) and AI Operator Handoff Documents (§4.9.1). On AEZA host `213.165.51.115` (OFAC-sanctioned July 2025, 4/5 bulletproof indicators), the operator runs a self-built unauthenticated Python-stdlib C2 (§4.9.5), an `ai_sniper_brute.py` pipeline that calls Gemini 2.5 Flash for per-target password mutations (5.5 MB `AI_ADMIN_MUTANTS.txt` on disk), and a Cloudflare-Tunnel C2 topology under operator-owned domain `tralalarkefe.com` whose `windows_server`/`gil_dr1` subdomains route persistent RDP+SSH into the confirmed US healthcare victim — a more durable model than ephemeral `*.trycloudflare.com` abuse (Proofpoint Aug 2024; Securonix SERPENTINE#CLOUD) because the operator owns the domain. A co-located disinformation operation (`@americanpatriotus`, `quantum_patriot.py`) uses the same Gemini key, rare cross-operation attribution evidence. Primary indicator: `tralalarkefe.com` (+ 5 named subdomains). Attribution UTA-2026-012 (MODERATE 75%). **Full analysis, full indicator table, and Phase 11 idiom analysis: [Case 1 sub-report](/reports/russian-gemini-credential-mill-213.165.51.115/).**

### 4.2 Case 2 — Turkish ARPA Observability-Harvester Operator

**Capsule.** The campaign's only operator with a confirmed state-aligned-target profile and confirmed insider recruitment. From DigitalOcean host `209.38.205.158` — accessed directly from TurkNet residential ISP `31.223.97.87` without VPN/Tor — the operator runs a production-grade `ARPA Korelasyon Motoru` reverse-pipeline platform (TimescaleDB+Neo4j+Redis) that ingests four stolen observability sources (IBM Instana 10-year JWT, SolarWinds Orion 784 nodes, Zabbix 100 hosts, VMware Aria) and cross-correlates them against a single confirmed state-affiliated Turkish financial-sector victim — flipping the defender threat model that treats observability tools as data destinations, not sources to protect (§4.9.4). Operator-authored Turkish-language tunnel-setup docs direct an insider AD user ([employee ID — suppressed]) to open a reverse tunnel from the victim network — documentary insider-recruitment evidence uncommon outside state-attribution contexts. GitHub T&S suspended handle MehmetARPA on 2026-05-25. Primary indicator: `209.38.205.158` / `/api/ingest/instana`. Attribution UTA-2026-013 (high-MODERATE 78%). **Full analysis and full indicator table: [Case 2 sub-report](/reports/turkish-arpa-openclaw-state-insurer-209.38.205.158/).**

### 4.3 Case 3 — Rovodev/Pandora Mirai Botnet Operator

**Capsule.** The campaign's exemplar of the Hybrid AI-augmented operator class — classic Mirai-family tradecraft (lineage to 2016 source releases, downstream of Doctor Web's 2023 Android.Pandora disclosure) plus Atlassian Rovodev for capability extension. From IONOS host `87.106.143.220:1337`, the operator runs an 11-architecture Mirai botnet over a dual HTTP/HTTPS distribution channel (Aruba Italy `80.211.94.16` for delivery; IONOS for build/test), a DDoS-for-hire model with 13 named attack methods. The `~/.rovodev/sessions/` JSONs are the campaign's most direct primary-source evidence of AI authoring offensive code: readers see the operator's natural-language prompts and the AI's `file_write` calls building the framework, file-by-file. A 5-vector persistence chain (crontab + rc.local + init.d + systemd + bashrc/profile) fires within seconds from one parent process — conventional Mirai tradecraft AI did not author, requiring correlated detection. Naku.arm VT consensus is 43/66 (Mirai); the embedded URL `http://80.211.94.16/Naku.mips` links operator to distribution cluster. Primary indicator: `87.106.143.220:1337` / `165.227.175.161:23`. Attribution UTA-2026-014 (LOW 60%). **Full analysis and full indicator table: [Case 3 sub-report](/reports/rovodev-mirai-matrix-c2-87.106.143.220/).**

### 4.4 Case 4 — Korean Claude+OpenClaw Operator (Capsule)

**Capsule.** Capsule-depth capture on Korea Telecom host `221.150.15.104` (direct residential exposure); no filesystem extraction beyond the smoking-gun artifact. That artifact — `~/.claude/settings.local.json` — is the campaign's first DEFINITE evidence of an attacker-customized AI-tool installation chain: the operator pre-approved, in the Claude Code permission allowlist, `Bash(curl -fsSL https://openclaw.ai/install.sh | bash)`, `Bash(npm i -g openclaw)`, `Bash(openclaw onboard)`, and `Bash(openclaw gateway --port 18789)` — authorizing a `curl ... | bash` OpenClaw install without per-execution prompts, with the gateway opening listening port 18789 on the internal host. Primary indicator: `~/.claude/settings.local.json` with pre-approved `Bash(curl ... | bash)` entries; block `openclaw.ai`/`docs.openclaw.ai` from non-developer hosts and inventory port 18789. Attribution UTA-2026-015 (LOW 55%). **Sub-report: [Case 4 sub-report](/reports/korean-claude-openclaw-221.150.15.104/).**

### 4.5 Case 9 — GHOST Cryptojacker Kit + 4-Tier Supply Chain

**Capsule.** The campaign's only named-actor HIGH attribution (kit author Vova75Rus 88%) and only Tier-0 disposition outcome (GitHub T&S account-level action 2026-05-25, all 9 repos HTTP 404). On two AEZA hosts (`77.110.96.200` Operator-A, `77.110.125.145` Operator-B), the **byte-identical `libpam_cache.so`** (MD5 `296a800564111b0bad9fe63faf4e63ba`) is the DEFINITE supply-chain root — an LD_PRELOAD libc-hook rootkit that hides processes/files via `dlsym(RTLD_NEXT,...)` and calls `unsetenv("LD_PRELOAD")` to defeat forensic enumeration. The kit ships a 4-variant container-escape suite (Docker/k8s/LXC), ComfyUI fake-node persistence (`PerformanceMonitor`) that survives reimaging, a Hysteria v2 backdoor with `bing.com` SNI masquerade (UDP 14433/14444), and in-kit `_anti_hisana` counter-tooling indicating a commercial-grade author. The 4-tier chain runs UnamSanctam (Tier-0 OSS supplier, PUBLIC PERSONA, outside T&S scope) → Vova75Rus (Tier-1 kit author, OWNER Telegram bot 8415540095 baked into every build) → two customer operators (Tier-2) → a 4,573-entry ComfyUI victim scan list (Tier-3, ~78 high-confidence victim IPs flagged to cloud providers). Primary indicator: `cfx.kryptex.network` / `/etc/ld.so.preload` modifications. Attribution Vova75Rus (HIGH 88%) + UTA-2026-016 / UTA-2026-017. **Full analysis, full indicator table, ELF internals, and Tier-0 timeline: [Case 9 sub-report](/reports/ghost-cryptojacker-vova75rus-77.110.96.200/).**

### 4.6 Case 7 — Productivity-AI Stack (Capsule)

**Capsule.** The campaign's most representative **AI-integrated mature operator** (§4.10): a post-compromise productivity stack pairing classic operator tools (Weevely PHP backdoor, frp reverse proxy) with Claude Code for workflow assistance — planning, documentation, scripting. Claude improves the operator's productivity, not capability — the operator does not need it to operate — so there is no novel TTP at the AI layer, and no case-specific perimeter or hunt rule is published beyond the generic Weevely/frp signatures already in public catalogs.

**Hosting:** 139.59.239.112 (DigitalOcean AS14061). **AI Tool:** Claude Code (inferred from co-located session artifacts). Capsule depth — no filesystem extraction beyond surface artifact inventory.

### 4.7 Case 8 — AI-Orchestrated 60-Second Payment-API Attack (Capsule)

**Capsule.** The campaign's most novel-on-its-face TTP — an LLM orchestrating a 4-stage attack chain (recon → enumerate → exploit → exfiltrate) against a payment API within a 60-second window — but vendor identification is **INSUFFICIENT** (Gemini, Claude, GPT, and self-hosted models all remain candidates), so it stays at capsule depth. Defender takeaway: treat any sub-minute multi-stage authenticated-API chain as a candidate for AI-orchestrated tradecraft, and baseline API traffic for "burst" patterns (4+ distinct API surfaces from one source IP within 60 seconds) that human-paced tradecraft would not produce.

**Hosting:** 68.183.92.28 (DigitalOcean AS14061). **AI Tool:** unspecified LLM, mechanism unknown. Capsule depth — insufficient artifacts to identify the vendor or orchestration mechanism.

### 4.8 Case 10 — Sliver-Derivative C2 Staging (Capsule)

> **Analyst note:** Case 10 captures an operator at the *pre-victim staging phase* — Sliver C2 deployed with crypter tooling and iterative loader development, but zero victim beacons in the database at capture. This is rare visibility: most reporting catches Sliver-derivative operators post-compromise. The artifacts document tradecraft choices defenders can hunt for *before* victim impact.

**Hosting:** 5.230.201.54 (AS200051 NL, registered to individual "Rizki Abdul Azis" — atypical for a legitimate provider; BGP ownership unclear). **AI Tool:** Cursor IDE (HIGH confidence from co-located binaries; not DEFINITE from session transcripts). Capsule depth — pre-victim staging, zero sessions/beacons in the captured Sliver database.

**Indicators** span Sliver C2 endpoints (default elite port `31337`, HTTP staging `:8080`, keylogger API `/api/v/keylog`, MJPEG stream `:9093`), crypter artifacts (`class SliverCrypter`, Fernet outputs `encrypted_payload.bin` / `decryption_key.txt`, input `implant-win-x86.exe`, drop `%TEMP%\svchost_upd.exe`), a rapid-iteration footprint (`loader_v30.ps1`→`loader_v39.ps1`, `screencap_v4.ps1`→`screencap_v11.ps1` in one day), and a broad Sliver-population JARM `3fd3fd20d00000021c43d43d00043d204204071741c36579e355f830d285a5` requiring combination with other signals. Full structured indicators are in the [IOC feed](https://the-hunters-ledger.com/ioc-feeds/ai-agent-frameworks-2026-05-23-iocs.json) (§8).

**Technical highlights:**

1. **Active development, non-functional C2.** Despite the one-day loader/screencap iteration tempo, the Sliver database (`sliver.db`, 483 KB) held **zero sessions, beacons, loot, or registered implant builds** — no victim connections at capture. The server failed to start on a `:31337` port conflict unresolved across ≥15 days; 60 recorded asciinema sessions indicate practice, not engagement. This is pre-victim staging, not active compromise.
2. **Commodity Fernet+zlib+b64 Python crypter.** `SliverCrypter` wraps Fernet → zlib → base64, with the PowerShell loader applying single-XOR over the Fernet output. A Phase 8 assessment of "triple-layer RC4 → Rolling XOR → RC4 with key `finalpayloadlayerkey987`" was **definitively refuted** by Phase 15 static RE (zero `finalpayloadlayerkey987` matches across 456 triage artifacts; Fernet-based confirmed). Crypter and C2 are both commodity; the distinguishing tradecraft is development tempo and pre-staging visibility, not encryption novelty.
3. **PyInstaller-stub deployment** with `creationflags=0x08000000` (CREATE_NO_WINDOW) for stealth execution.

**Defender Takeaway:** Block `5.230.201.54`; combine JARM matches with other Sliver signals; baseline `%TEMP%\svchost_upd.exe` across the Windows estate. (Capsule depth — no sub-report planned.)

### 4.9 Five Novel TTPs (Cross-Case)

> **Analyst note:** This sub-section documents five TTPs that prior-art search across 8+ major vendor AI-misuse reports (Google GTIG, Anthropic Misuse Reports, Censys ARC, Proofpoint, IBM X-Force, Kaspersky, Doctor Web, Hunt.io) did **not** surface as previously-documented. Each TTP is presented with: (a) what it is, (b) the campaign exemplars, (c) the prior-art assessment honestly characterized (DEFINITE vs MODERATE vs MODERATE-HIGH novelty per the research analyst's gap flags), (d) the defender detection strategy. Three of the five (Sections 4.9.1, 4.9.3, 4.9.4) carry MODERATE or MODERATE-HIGH novelty rather than DEFINITE because the prior-art search did not exhaust academic conference proceedings (Black Hat, USENIX, IEEE S&P, DEF CON 2024-2026) or underground forum monitoring (Exploit.in, XSS.is). These TTPs are documented as **first-public-documentation candidates** pending deeper prior-art search.

#### 4.9.1 AI Operator Handoff Documents — MODERATE Novelty

> **Analyst note:** This is the publication's headline novel TTP. The artifact class is operator-authored documents intended for AI consumption (inverse data flow from AI-generated content). Existing AI-misuse reporting comprehensively covers AI-generated content; this covers AI-consumed operator documentation. Defenders' threat models do not currently treat operator handoff documents as a distinctive artifact class.

**What it is:** Markdown or plain-text documents written by the operator with the explicit intent of being read by an AI agent across sessions. Identifying signals include (a) explicit "To: <AI agent name> / From: <AI agent name>" headers, (b) goal-statement and status-tracking sections, (c) escalating-superlative file naming (e.g., `PLAN.md` → `MASTER_PLAN.md` → `ULTIMATE_PLAN.md`), and (d) inverted data flow (operator-authored → AI-consumed, opposite of the normal AI-generated → human-consumed direction).

**Campaign Exemplars:**

- **Case 1 Russian operator (3 exemplars):**
  - `C2_MIGRATION_GUIDE.md` — operator instructions for AI to perform a C2 migration
  - `C2_INFRA_TRANSFER.md` — explicit `To: Gemini CLI / From: Gemini CLI` header in the document; this is the campaign's smoking-gun artifact for the artifact class
  - `DEPLOYED_TOOLS.md` — operator inventory of deployed tools for AI session context

- **Case 3 Rovodev operator (22+ exemplars at `/root/matrix/`):**
  - `IMPLEMENTATION_PLAN.txt`, `whatineed.txt`, `MASTER_PLAN.md`, escalating-superlative naming sequence

**Prior-Art Assessment (MODERATE confidence novelty):** No prior public documentation found across 8+ major vendor AI-misuse reports. The novelty claim is held at MODERATE rather than DEFINITE because academic conference proceedings (Black Hat, USENIX, IEEE S&P, DEF CON 2024-2026) were not fully searched as prior art. If this artifact class has been documented in conference proceedings, the novelty claim weakens but the campaign-level documentation value (cross-operator validation across Cases 1 and 3) remains.

**Defender Detection Strategy:** File-creation hunt for Markdown documents in operator-likely paths (`/root/`, `~/`, `/opt/`) containing trigger strings like "To: Gemini", "To: Claude", "Atlassian Rovodev session", "AI agent", combined with goal-statement section headers. The YARA rule `AIOperatorHandoffDoc` in the linked detection file targets this artifact class with case-insensitive matching across these triggers.

#### 4.9.2 LLM-Personalized Credential Mutation — DEFINITE Novelty

> **Analyst note:** This is the campaign's most cleanly-DEFINITE novel TTP. The artifact is a direct primary-source: a Python script that calls Gemini 2.5 Flash with a specific prompt and generates per-target password mutations from victim context. The mutation output file `AI_ADMIN_MUTANTS.txt` is 5.5 MB on operator disk, demonstrating at-scale active use.

**What it is:** A pipeline that takes per-target context (email + domain + last-known-password) and submits the context to a live LLM API at attack time to generate 20 per-target password mutations. This differs qualitatively from prior credential-mutation tradecraft:

- **vs. hashcat rules (~2015):** hashcat rules are deterministic transformations applied without victim context.
- **vs. PassGAN (2017+):** PassGAN trains a GAN on bulk distribution, then samples from the trained distribution — no per-target personalization.
- **vs. arXiv 2604.12601 (LLM-Guided Password Guessing, April 2026):** that paper uses LLM prompt evolution for generic datasets — no per-target attack-time mutation.

**This artifact is the first publicly-documented operational use of frontier-LLM-driven per-target credential mutation at attack time.** Distinguished from academic PassGAN (Hitaj et al. 2017) by per-target live-API mutation versus bulk dataset-trained generation, and from hashcat rules by context-aware mutation versus deterministic transformation. Maps to MITRE T1110.003 (Password Spraying) but warrants a new sub-technique proposal — current sub-techniques do not capture the "live LLM API at attack time with per-target context" pattern.

**Campaign Exemplar:**

- **Case 1 Russian operator:** `russian-ai_sniper_brute.py` script invokes Gemini 2.5 Flash with the prompt `"Act as an expert red-team password analyst..."` and produces per-target mutations from victim context. On-disk artifact `AI_ADMIN_MUTANTS.txt` is **5.5 MB** of generated mutations.

**Prior-Art Assessment (HIGH confidence novelty):** Clearly differentiated from PassGAN, hashcat rules, and arXiv 2604.12601. The HIGH confidence designation rests on the assumption that underground forum discussions (Exploit.in, XSS.is) have not reached public threat intelligence — Recorded Future / Intel 471 validation needed to upgrade to DEFINITE.

**Defender Detection Strategy:** Network-layer monitoring of outbound HTTPS to `generativelanguage.googleapis.com` with body containing prompt-template fragments: "red-team password analyst", "Output ONLY the 20 passwords", "generate 20 password mutations". DLP/proxy with body inspection required. File-creation hunt for `AI_SNIPER_GOODS.txt`, `AI_ADMIN_MUTANTS.txt`, `ULTRA_GOLD_TARGETS.txt` filenames (operator-specific but representative of the class).

#### 4.9.3 AI-Generated Offensive Code Structural Signature — HIGH Novelty (Cross-Operator)

> **Analyst note:** This is not novel as a concept (AI-generated code structural signatures have been hypothesized in academic and vendor research). It is novel as an **artifact-level diagnostic checklist with cross-operator validation** across three independent operators (Cases 1, 2, 3) using three different AI tools (Gemini CLI, OpenClaw, Atlassian Rovodev). Defenders gain a multi-criteria heuristic that is more durable than vendor-specific watermarking.

**What it is:** A 13-criteria diagnostic checklist for identifying operator-written Python code that was structurally co-authored by an LLM. The checklist captures:

1. Verbose docstrings on trivial functions
2. Defensive try/except wrapping where not needed
3. Educational variable names (e.g., `target_to_attack`, `result_of_password_check`)
4. Name/implementation mismatch bugs (function does X but is named Y)
5. Escalating-superlative file naming (`tool.py` → `master_tool.py` → `ultimate_tool.py`)
6. Copy-paste indentation decay (mixed tabs/spaces, inconsistent block indents across copy-pasted blocks)
7. Bare-except + verbose-docstring co-occurrence (the diagnostic pair)
8. Helper-function explosion (every 3-line operation extracted to its own function)
9. Type-hint inconsistency (some functions annotated, some not, no consistent pattern)
10. Trivial pylint-compliant boilerplate (every script opens with `#!/usr/bin/env python3` + `"""docstring"""` + `if __name__ == "__main__":` wrapper even when not warranted)
11. Educational README/docstring text inside attack scripts
12. Print-statement debugging at production code level
13. Over-modular file structure (5-line scripts split into 3 files)

**Campaign Exemplars (3 independent operators):**

- **Case 1 Russian operator:** `russian-ai_sniper_brute.py`, `russian-check_keys.py`, `~/arsenal/c2_server.py`. All exhibit ≥10 of 13 criteria.
- **Case 2 Turkish ARPA operator:** Python files in the ARPA platform repository. All exhibit ≥9 of 13 criteria.
- **Case 3 Rovodev operator:** `master_control.py`, `attack_engine.py`, `multi_vector_agent.py` in the Pandora framework. All exhibit ≥11 of 13 criteria.

**Important refinement from Phase 5:** The Phase 5 analysis included "zero anti-analysis" as a 14th criterion. The investigation **rejected** this criterion because Case 1's `stealth_agent.py` shows operators **can** prompt-engineer for evasion (the operator explicitly prompts Gemini to add anti-VM checks). The 13-criteria checklist is the final published list; the "zero anti-analysis" criterion was retracted as a publication-quality requirement.

**Prior-Art Assessment (HIGH confidence novelty):** AI-generated code structural signatures are a known research area; **cross-operator artifact-level validation** across 3 independent operators using 3 different AI tools is the contribution. Defender takeaway is the 13-criteria diagnostic checklist itself, which is published in this report and the linked detection file.

**Defender Detection Strategy:** YARA rule `AIGenCodeStructural` in the linked detection file scores Python files against the 13-criteria checklist; ≥8 of 13 matches triggers the rule at MODERATE confidence; ≥10 of 13 triggers at HIGH confidence.

#### 4.9.4 Observability-Tool Reverse Pipeline — MODERATE-HIGH Novelty

> **Analyst note:** This TTP inverts the defender threat model. Observability tools (Instana, SolarWinds, Zabbix, VMware Aria) are typically treated as data destinations — defenders worry about exposing tokens that grant write access to observability platforms. This TTP demonstrates that **read access** to observability data is itself high-value because it enables an attacker to build a reverse pipeline against the victim's production environment. Defenders should treat observability tokens as Tier-1 secrets equivalent to cloud-provider IAM credentials.

**What it is:** An attacker-built reverse-pipeline analytics platform that harvests stolen observability JWTs to cross-correlate read access across multiple observability sources against a single named victim. The reverse-pipeline ingests via dedicated `/api/ingest/<source>` endpoints into a production-grade TimescaleDB+Neo4j+Redis stack, supports daily refresh cycles, and produces operator-facing dashboards reconstructing the victim's topology.

**Campaign Exemplar:**

- **Case 2 Turkish ARPA operator:** ARPA platform ingests four stolen observability sources against the state-owned victim organization:
  - **IBM Instana:** 10-year JWT (iat 2024-03-06), 43 applications, 50 services
  - **SolarWinds Orion:** 784 nodes, 6,566 interfaces
  - **Zabbix:** 100 hosts
  - **VMware Aria:** Application and infrastructure data

  Plus visibility into several regulated-sector partner-ecosystem entities. The operator's `unified_cross_source_topology.json` is the captured reconstruction.

**Prior-Art Assessment (MODERATE-HIGH confidence novelty):** No prior art found for attacker-built reverse-pipeline analytics platform combining ≥3 observability sources against a single named victim. The MODERATE-HIGH designation reflects that observability-token theft itself is documented (e.g., Datadog tokens harvested in prior breaches) but the **reverse-pipeline architecture** with dedicated ingestion endpoints, TimescaleDB+Neo4j+Redis storage, and operator-facing dashboards is the contribution.

**Defender Detection Strategy:** Treat observability tokens as Tier-1 secrets. Rotate any JWTs older than 1 year. Monitor for `Authorization: apiToken ey*` patterns in PowerShell Script Block Logging Event 4104. Inventory and rotate IBM Instana, SolarWinds, Zabbix, VMware Aria tokens at the same cadence as cloud-provider IAM credentials. Network-layer rule: outbound HTTP POST to `/api/ingest/instana`, `/api/ingest/solarwinds`, `/api/ingest/zabbix` URI patterns from any host.

#### 4.9.5 Operator-Built Unauthenticated Python-stdlib C2 — HIGH Novelty

> **Analyst note:** Custom unsigned C2 servers have been reported in many published incidents (operator-built C2 is a known pattern). The novel artifact here is the combination of **(a) Python stdlib BaseHTTPServer with literally zero authentication, (b) used in active operations against named victims, and (c) shipped with path-traversal vulnerability and incomplete backend implementation**. This is rare in published reporting — operators typically use commodity C2 frameworks (Sliver, Cobalt Strike, Havoc) or carefully-built custom C2 with at least token-based authentication.

**What it is:** A Python `BaseHTTPServer`-based HTTP server with zero authentication on the operator API contract endpoints (`/api/v1/update`, `/api/v1/agents`, `/api/v1/interact`, `/api/v1/telemetry`, `/api/v1/get_results`) and a path-traversal-vulnerable file server. The captured backend is incomplete — the `/api/v1/get_results` endpoint is called by client implants but not implemented in the captured backend, evidence of in-place-developed (not pre-tested) build.

**Campaign Exemplar:**

- **Case 1 Russian operator:** `~/arsenal/c2_server.py` (`A2A C2 MULTI-AGENT CONSOLE` banner in the file). Used in active operations against the named healthcare victim (persistent RDP+SSH via Cloudflare Tunnel routing through this C2).

**Defender Takeaway — Takeover Surface:** Because the C2 has zero authentication, it presents a **defender-takeover surface** for victim notification and operational disruption. If a defender locates an in-the-wild C2 endpoint matching this pattern, they can directly query the operator API endpoints to identify which victim implants are checking in, then directly contact those victims. This is one of the few cases in published reporting where the C2 architecture itself enables defender intervention without the operator's cooperation.

**Prior-Art Assessment (HIGH confidence novelty):** Custom unsigned C2s are documented in many reports; Python-stdlib BaseHTTPServer with literally zero auth in active operations against named victims is rare. The HIGH designation reflects that the specific architecture (stdlib + zero auth + path-traversal + incomplete backend) has not surfaced in published reporting under our search.

**Defender Detection Strategy:** Network-layer rule for HTTP traffic with `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)` + `X-Agent-ID` header + URI matching `/api/v1/`. Combined-condition rule because the User-Agent alone is too generic. The Sigma rule `RussianA2AC2APIContract` in the linked detection file targets this combination.

### 4.10 Three-Class AI Threat-Actor Taxonomy

> **Analyst note:** This taxonomy was refined during analysis (Phase 7). The original Phase 5 framing posited four classes including a pure "AI-democratized script-kiddie" class. The refined publication taxonomy reduces to three classes because no pure exemplar of the script-kiddie class exists in the dataset — every observed operator retains baseline capability without AI (HIGH confidence; established by reviewing each operator's non-AI tooling and observed manual tradecraft). This refinement is published honestly rather than hidden, because the defender implications differ by class.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/ai-agent-frameworks-2026-05-23/ai-threat-actor-3class-taxonomy.svg" | relative_url }}" alt="Three-column comparison infographic of the three-class AI threat-actor taxonomy. Left column (deep-red side-rail, labeled Class 1): AI-integrated mature operator. Exemplar: Russian Gemini operator (Case 1 / UTA-2026-012). AI relationship: integrated across 3+ workflow stages with the operator authoring handoff documents specifically for AI session priming. Baseline without AI: operates without AI at HIGH confidence (handwritten C2, Cloudflare topology, custom credential-mill arsenal observed); loses efficiency without AI but retains capability. Defender response: disrupt AI integration points — revoke stolen LLM API keys, monitor server-host LLM egress traffic, hunt for AI Operator Handoff Documents during incident response. Flagged as the hardest class to defend against because removing AI does not remove operator capability. Middle column (red side-rail, labeled Class 2, MOST COMMON): Hybrid AI-augmented operator. Exemplars: Rovodev/Pandora Case 3 and Turkish ARPA Case 2 (UTA-2026-013, UTA-2026-014). AI relationship: classic operator tradecraft AND AI used for capability extension (Python scrapers, analytics platforms, etc.). Baseline without AI: operates basic stack at HIGH confidence (Mirai-family C binaries, production ARPA platform, manual tradecraft observed). Defender response: detect BOTH layers — conventional artifacts (Mirai-family C binaries, ET HUNTING Suricata rules) AND AI-augmentation layer (.rovodev/, .openclaw/, AI Handoff Documents). Right column (grey side-rail, labeled Class 3, THEORETICAL): AI-democratized script-kiddie. Exemplar: none in this dataset; class refined out of the original Phase 5 four-class framing during Phase 7. AI relationship: AI is initial-development-only, with the operator writing a natural-language spec and AI producing all code. Baseline without AI: cannot operate without AI by definition (no in-dataset exemplar). Defender response if the class exists in the wild: vendor coordination at LLM-provider signup time plus structural code-signature detection (AIGenCodeStructural YARA family rule). Footer detection takeaway: AI-tool presence is NOT a malicious indicator by itself; class determines defender response; every observed operator retains capability without AI; the Hybrid class is most common.">
  <figcaption><em>Figure 1: Three-class AI threat-actor taxonomy visualized. Each class has a distinct defender response: the AI-integrated mature class requires disrupting AI integration points, the Hybrid class requires detecting both conventional tradecraft and AI-augmentation layers, and the theoretical AI-democratized script-kiddie class (no exemplar in this dataset) would require vendor coordination at signup time. The refinement from Phase 5's original four-class framing to three published classes is documented honestly rather than hidden, because the defender implications differ materially by class.</em></figcaption>
</figure>

| Class | Exemplar(s) | AI Relationship | Operator Baseline | Defender Response |
|---|---|---|---|---|
| **AI-integrated mature operator** | Russian Gemini (Case 1) | AI integrated across 3+ workflow stages; operator writes handoff docs for AI consumption | Operates without AI (HIGH — manual handoff docs and non-AI infrastructure observed); loses efficiency without AI | Disrupt AI integration points (revoke stolen LLM keys, monitor server-host LLM egress, hunt for AI-bridge documents during IR) |
| **Hybrid AI-augmented operator** | Rovodev/Pandora (Case 3), Turkish ARPA (Case 2) | Classic operator tradecraft AND AI for capability extension | Operates the basic stack without AI (HIGH — Mirai-family C binaries, ARPA platform, observed manual tradecraft); uses AI for capability uplift | Detect BOTH conventional artifacts (Mirai-family C binaries, ET HUNTING Suricata rules) AND AI-augmentation layer (.rovodev/, .openclaw/, AI Operator Handoff Documents) |
| **AI-democratized script-kiddie** | (theoretical — no pure exemplar in this dataset) | AI is initial-development-only; operator writes spec, AI produces all code | Cannot operate without AI (by definition of the class; no in-dataset exemplar) | Vendor coordination at signup + structural code-signature detection (AIGenCodeStructural YARA rule) |

**Defensive implication by class:**

- The **AI-integrated mature** class is the *hardest* to defend against because removing AI does not remove the operator's capability. Disruption must target AI integration points (key revocation, LLM egress monitoring) rather than blocking the operator entirely.
- The **Hybrid AI-augmented** class is the *most common* in this dataset (Cases 2, 3). Defenders detect both layers (conventional tradecraft + AI augmentation) because either alone misses the operator.
- The **AI-democratized script-kiddie** class is *theoretical* in this dataset. If it exists in the wild, vendor coordination at LLM-provider signup time + structural code-signature detection are the primary defensive controls.

### 4.11 False-Positive Discrimination — Cases 5, 6, and Demoted Hosts

> **Analyst note:** This sub-section honestly characterizes two hosts (Cases 5, 6) initially flagged by the investigation's open-directory hunting heuristics but **demoted during analysis** because the AI-tool presence was benign. The single most important defender lesson from this campaign is: **AI tool presence on a host is not, by itself, a malicious indicator.** Two false-positive hosts and two additional Hunt.io-flagged demoted hosts make this point at four data points.

**Case 5 (DEMOTED) — 173.249.2.23**

- **Initial flag:** AI-tool footprint in open directory.
- **Analysis finding:** Defensive-security SaaS consultant. Akto-style API testing product + AWS hardening automation + defensive LLM scanner.
- **Verdict:** NOT a threat actor. The AI tool presence is consistent with the operator's stated profession (defensive security). No offensive operator artifacts present.
- **Defender lesson:** Akto-style API testing tooling co-located with AI-scanner artifacts is **not** an offensive indicator. Discriminator: check for offensive operator artifacts (target lists, exfil destinations, attacker prompts) before classifying a host as offensive.

**Case 6 (DEMOTED) — 66.94.120.32**

- **Initial flag:** AI-tool footprint in open directory.
- **Analysis finding:** Benign HuggingFace ML researcher (`mtr7x`) doing legitimate Sarvam-30B quantization work.
- **Verdict:** NOT a threat actor. Researcher's open directory exposed ML quantization scripts and intermediate weights. Zero target lists, zero attacker prompts, zero exfil infrastructure.
- **Defender lesson:** HuggingFace transformer weights and quantization scripts in an open directory are **not** an offensive indicator. Discriminator: look for victim-context (target lists, stolen tokens, named-victim artifact references) before classifying a host as offensive.

**Hunt-Flagged Demoted Hosts** — Two additional hosts flagged by Hunt.io heuristics during Phase 11 mirror-and-demote analysis were similarly demoted. Both showed surface-level AI-tool presence (Claude session metadata) without offensive operator artifacts. Both demonstrate the same point as Cases 5 and 6.

**Defender Lesson — Combined:** The investigation's hunting heuristics produced 4 false positives among 12 initially-flagged hosts (8 confirmed + 2 demoted via Cases 5/6 + 2 demoted via Hunt). This 33% initial-flag false-positive rate is honest characterization — defenders deploying AI-tool-presence heuristics should expect similar FP rates and design their hunting workflows around fast-discriminator review (target-list presence, victim-context references, exfil infrastructure) rather than treating AI-tool-presence as a high-fidelity indicator.

---

## 5. Static Analysis Findings

> **Analyst note:** This is a multi-actor campaign, so static findings span many binaries and scripts. Two are publication-defining and synthesized here: the byte-identical `libpam_cache.so` across Case 9 customer hosts (DEFINITE supply-chain root) and the 13-criteria AI-Generated Code structural signature across Cases 1, 2, 3. Per-sample static analysis lives in the sub-reports (§14.2).

### 5.1 Per-Case Static Detail → Sub-Reports

Per-case static analysis lives at full depth in each linked sub-report (§14.2): Case 1's `ai_sniper_brute.py`/`c2_server.py`, Case 2's `instana_local_collector.ps1` and ARPA codebase, Case 3's Pandora framework and `Naku.arm` ELF, Case 9's `libpam_cache.so`/`libpam_cache.c` and deployment scripts, and Case 10's Fernet crypter and loader series. The parent owns two cross-case static findings: the byte-identical `libpam_cache.so` supply-chain root (carried in §4.5 and the IOC feed) and the AI-Generated Code structural signature below.

### 5.2 Cross-Case AI-Generated Code Static Signature (13-Criteria Diagnostic)

The 13-criteria diagnostic checklist scored Python files from three independent operators (Cases 1, 2, 3) as DEFINITE AI-co-authored — a signature that holds across three different AI tools. Aggregate results:

| Operator | Files Examined | Mean Criteria Match | Verdict |
|---|---|---|---|
| Case 1 (Russian Gemini) | 5 Python files | 10.4 / 13 | DEFINITE AI-co-authored |
| Case 2 (Turkish ARPA) | 7 Python files | 9.6 / 13 | DEFINITE AI-co-authored |
| Case 3 (Rovodev) | 4 Python files | 11.2 / 13 | DEFINITE AI-co-authored |

Cross-operator validation across three different AI tools (Gemini CLI, OpenClaw, Atlassian Rovodev) confirms the signature is **AI-class-level** rather than **vendor-specific**. Defender takeaway: a single 13-criteria YARA rule covers code-generation from any current AI-agent CLI.

---

## 6. Dynamic Analysis Findings

> **Analyst note:** This campaign's methodology is open-directory hunt + multi-source filesystem pull, not sandbox detonation, so dynamic analysis documents operator workflows chronologically rather than runtime malware behavior. The per-case operator timelines (Cases 1, 2, 3, 9) live in the sub-reports; the two publication-defining dynamic findings are flagged below.

### 6.1 Per-Case Operator Timelines → Sub-Reports

Each case's chronological operator-side workflow is documented step-by-step in its linked sub-report (§14.2): Case 1 (Gemini credential-mutation → C2 → healthcare-victim RDP/SSH → disinformation pivot), Case 2 (insider tunnel setup → stolen-JWT ingestion → 4-source correlation → live dashboard), Case 3 (Rovodev prompt → AI `file_write` → 11-arch build → dual-channel distribution → 5-vector persistence → C2 registration), and Case 9 (kit pull → per-customer customization → `/etc/ld.so.preload` write → libc-hook activation → hidden-miner + Hysteria v2 deployment → Telegram callbacks → container escape). Two belong to the parent's synthesis:

- **Case 3 Rovodev session JSONs** (`session_cron_a46703f0a3c4.json`, `session_interactive_b9d424.json`) capture AI authoring offensive code at primary-source level — the operator's verbatim natural-language prompts and the AI's `file_write` tool calls building the framework, file-by-file. This is the campaign's most direct evidence of AI-on-offense.
- **Case 2 multi-source observability ingestion timing** on the ARPA platform shows the stolen 10-year Instana JWT (`jti 022a1b74-2332-4df5-a76b-60225ffa7ae3`, iat 2024-03-06) driving a daily ingestion cycle running through 2026-05-23 with the dashboard live 2026-05-24 — confirming an active, sustained operation rather than a one-off pull.

---

## 7. MITRE ATT&CK Mapping

> **Analyst note:** This campaign maps to 49+ ATT&CK techniques across 11 tactics. To keep this parent report focused, the technique-by-technique mapping lives with the detection logic on the companion detection page rather than being duplicated here.

The campaign's heaviest tactic representation is **Resource Development** (operator infrastructure), **Defense Evasion** (notably the Case 9 GHOST rootkit), **Command and Control** (Cloudflare Tunnel + Telegram + custom Python C2 + Hysteria v2), and **Discovery** (Case 9 victim scanning). Every detection rule is mapped to its ATT&CK technique(s) on the **[detection rules page →](https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/)**.

---

## 8. Indicators of Compromise

> **Analyst note:** The complete IOC set for all cases is published as a machine-readable JSON feed for direct SIEM/EDR ingestion — it is not duplicated inline here. The highest-priority indicators are also surfaced in the IOC panel (fingerprint icon) on this page.

**Full IOC feed:** [`/ioc-feeds/ai-agent-frameworks-2026-05-23-iocs.json`](https://the-hunters-ledger.com/ioc-feeds/ai-agent-frameworks-2026-05-23-iocs.json) — every indicator, per case, with type / confidence / recommended action. Per-case IOC feeds are linked from each sub-report (Section 14.2).

---

## 9. Threat Actor Assessment

> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-[YEAR]-[###] is an internal tracking designation assigned by The Hunters Ledger to actors observed across analysis who cannot yet be linked to a publicly named threat group. This label will not appear in external threat intelligence feeds or vendor reports — it is specific to this publication. If future evidence links any UTA-2026-012 through UTA-2026-017 to a known named actor, the designation will be retired and updated accordingly.

This is a **multi-actor** campaign. Alternative Competing Hypotheses (ACH) analysis ruled for the **multi-actor unrelated** hypothesis, with **campaign coordination explicitly REFUTED** by distinct IOCs, wallets, language, geography, targets, motivations, AI tools, and infrastructure across all 8 cases. Attribution spans one named actor (Vova75Rus) and six UTAs; Cases 7, 8, 10 are INSUFFICIENT at capsule depth. **No Tier-1 government attribution** applies to any operator.

### 9.1 Vova75Rus — Named Actor (HIGH 88%)

**Profile:** the campaign's only named-actor HIGH attribution — the GHOST cryptojacker kit author, a separate identity from his customer operators, tied to Zabaykalsky Krai, Russia at HIGH confidence (88%).

**Case:** Case 9 (GHOST cryptojacker kit author — separate identity from kit's customer operators).

**Confidence Statement:**

**Threat Actor:** Vova75Rus &middot; **Confidence: HIGH (88%)**

- **Why this confidence:** 5+ year GitHub history (UID 73169104); region code 75 in handle = Zabaykalsky Krai (Russian regional plate code convention); personal-dedication page Notes.github.io dated March 8th (International Women's Day, Russian-culturally-significant date); Censys ARC primary-research corroboration (Mark Ellzey 2026-04-07); OWNER Telegram bot 8415540095 baked into every customer deployment as supply-chain monitoring signature; byte-identical libpam_cache.so across 2 customer hosts confirming DEFINITE supply-chain root; GitHub T&S account-level action 2026-05-25 (all 9 repos HTTP 404) validates the kit-author identity at the platform-trust-and-safety level.
- **What's missing:** real-world identity beyond the Vova75Rus handle + region code. Customer count beyond the 2 observed deployments.
- **What would increase confidence:** government attribution at Tier 1 (FBI/CISA/NSA disclosure) or 2+ additional customer deployments observed.

**Geography:** Zabaykalsky Krai, Russia (probable; based on region code 75 convention in handle).

**Language:** Russian (personal-dedication page using a Russian-language March 8th / Women's Day greeting).

**Evidence Anchors:**

1. 5+ year GitHub history (UID 73169104, account-level T&S suspended 2026-05-25).
2. Region code 75 in handle = Zabaykalsky Krai (Russian regional plate code convention).
3. Personal-dedication page Notes.github.io on a Russian-culturally-significant date (March 8th).
4. Censys ARC primary research (Mark Ellzey 2026-04-07) independently corroborates kit-author identity and the `libpam_cache.so` supply-chain signature.
5. OWNER Telegram bot 8415540095 baked into every customer GHOST kit deployment (supply-chain monitoring signature).
6. Byte-identical `libpam_cache.so` across 2 customer hosts = DEFINITE supply-chain root.

**Alternative Hypotheses Addressed:**

- Multi-person team / sock-puppet network — LOW (~10%) — single-handle 5+ year history with consistent style argues against multi-person team.
- False-flag — LOW (~5%) — region code + personal dedication + March 8th cultural reference are difficult-to-fabricate signals.
- Upstream Russian cybercrime ecosystem position — MODERATE (~30%) — Vova75Rus is connected to UnamSanctam (5+ year OSS supplier) at the supply-chain level but ecosystem positioning does not change the kit-author attribution.

**Tier-0 Disposition Outcome:** GitHub Trust & Safety took account-level action against Vova75Rus on 2026-05-25. All 9 repositories return HTTP 404. This is the strongest possible Tier-0 disposition for an upstream supply-chain actor. Wayback Machine snapshots at `web.archive.org/web/20260525020*/` are the canonical pre-takedown evidence record. Defenders should expect re-hosting attempts and monitor for new accounts matching the Vova75Rus naming/style patterns.

### 9.2 UTA-2026-012 — Case 1 Russian Gemini Operator (MODERATE 75%)

**Profile:** Russian-native individual; AI-augmented mid-tier criminal operator targeting the healthcare victim + co-located @americanpatriotus disinformation channel.

**Confidence Statement:** MODERATE (75%) — converging behavioral indicators (Russian language register, AEZA hosting preference, forum activity at duty-free.cc, GitHub handle sonner1337, persona-priming string `братух`) align with Russia-origin cybercriminal hypothesis. Phase 11 native Russian idiom analysis (Бро, Погнали, тачка) confirms native-speaker register vs. Google-translated false-flag scenario.

**Geography:** Russian-resident (probable).

**Language:** Russian (native idiom register confirmed Phase 11).

**Key Identity Artifacts:**

- GitHub handle: `sonner1337`
- GitHub PAT: `ghp_tdcXTl...g4PDaRW` (defanged; full credential preserved in offline evidence for vendor disclosure)
- Telegram: `@americanpatriotus` (disinformation channel actively posted to via Gemini CLI)
- Persona string: `братух` (Russian "bro" diminutive in GEMINI.md global memory file)
- Russian carding forum: `duty-free.cc` (forum-active operator; saved MHTML thread in operator archive)
- AntiPublic combolist subscription: `antipublic.one`

**Sub-Report:** UTA-2026-012 per-case attribution with full Phase 11 idiom analysis is in the [Case 1 sub-report](/reports/russian-gemini-credential-mill-213.165.51.115/).

### 9.3 UTA-2026-013 — Case 2 Turkish ARPA Operator (high-MODERATE 78%)

**Profile:** Turkish-speaking, Turkish-located, intra-Turkey single-thread operator with state-relevant interest in financial-sector intelligence; espionage tradecraft sub-type (a) state-aligned-loose or (c) political/factional — high-MODERATE.

**Confidence Statement:** high-MODERATE (78%, top of the CLAUDE.md MODERATE band 70-85% approaching HIGH 85-95%) — five converging attribution axes (Turkish language + GitHub handle + self-branding + state-target + TurkNet residential ISP without VPN) + 73+ day patient dwell + insider-recruitment artifact ([employee ID — suppressed]) make this the campaign's highest-confidence non-named-actor attribution.

**Geography:** Turkey — TurkNet residential ISP (`31.223.97.87`, AS12735) operator origin without VPN/Tor anonymization (direct geographic anchor).

**Language:** Turkish (operator-authored Turkish-language insider documentation).

**Key Identity Artifacts:**

- GitHub handle: `MehmetARPA` (possibly real-name Mehmet ARPA, NOT confirmed; public repo `github.com/MehmetARPA/ARPA`; **account suspended by GitHub T&S 2026-05-25**)
- Self-branding: `ARPA Korelasyon Motoru` ("ARPA Correlation Engine")
- In-platform footer: `ARPA © 2026 the victim organization`
- Operator-authored Turkish-language insider docs: `GERCEK_API_BULUNDU.md`, `PUTTY_TUNNEL_DETAY.md`, `SSH_KEY_COZUM.md`, `TUNNEL_KONTROL.md`, `WINDOWS_VPN_TUNNEL.md`
- Insider recruit: Windows AD user `[employee ID — suppressed]`

**Sub-Type Discrimination Gap:** State-aligned-loose (a) vs. political/factional (c) sub-type discrimination is INSUFFICIENT pending Turkish-language doc full-read + OSINT pivot + Turkish political event correlation. This is flagged as a publication-acknowledged gap rather than resolved.

**Sub-Report:** UTA-2026-013 per-case attribution + insider-recruitment TTP framing is in the [Case 2 sub-report](/reports/turkish-arpa-openclaw-state-insurer-209.38.205.158/).

### 9.4 UTA-2026-014 — Case 3 Rovodev/Pandora Operator (LOW 60%)

**Profile:** English-speaking HYBRID AI-augmented solo-or-small-team operator running DDoS-for-hire + downstream Pandora-Mirai variant.

**Confidence Statement:** LOW (60%) — Discord operator ID is captured but no GitHub handle, real-world identity, or geographic anchor beyond English-speaking signal.

**Geography:** Unknown (English-speaking signal only).

**Language:** English (operator-authored documents in `/root/matrix/`).

**Key Identity Artifacts:**

- Discord ID: `1441591352927326259` (snowflake decoded to 2025-11-22T00:49:22 UTC creation timestamp — recent Discord account)
- No GitHub handle captured

**Solo vs. Small-Team Discrimination:** UNRESOLVED but NOT publication-gating. Mirai-family tradecraft is consistent with both solo and small-team operations.

**Sub-Report:** UTA-2026-014 per-case attribution is in the [Case 3 sub-report](/reports/rovodev-mirai-matrix-c2-87.106.143.220/).

### 9.5 UTA-2026-015 — Case 4 Korean Claude+OpenClaw Operator (LOW 55%)

**Profile:** Korean-located operator with smoking-gun Claude Code permission allowlist artifact (capsule depth only).

**Confidence Statement:** LOW (55%) — Korea Telecom AS4766 direct exposure provides geographic anchor; no operator-identity artifacts beyond the `settings.local.json` itself.

**Geography:** South Korea (Korea Telecom AS4766 `221.150.15.104`).

**Language:** Korean (inferred from hosting only).

**Key Identity Artifacts:**

- `~/.claude/settings.local.json` pre-approving `openclaw.ai` installer + OpenClaw command set

### 9.6 UTA-2026-016 — Case 9 Operator-A (LOW 60%)

**Profile:** Russian-speaking GHOST kit customer (higher-OPSEC tier — self-hosted XMR + CFX pool proxies). **Separate identity from Vova75Rus** (Vova75Rus is the kit author; Operator-A is one of at least two customer operators).

**Confidence Statement:** LOW (60%) — Russian-language signal in operator-side wrapper scripts; AEZA hosting consistent with Russian cybercrime ecosystem; MIRROR Telegram bot is operator-specific.

**Geography:** Russian-resident (probable).

**Language:** Russian (Cyrillic in operator-side wrapper scripts).

**Key Identity Artifacts:**

- MIRROR Telegram bot prefix: `8315596543`
- XMR wallet prefix: `4BBj3gj4...`
- CFX wallet prefix: `cfx:aaj5xb...`

### 9.7 UTA-2026-017 — Case 9 Operator-B (LOW 55%)

**Profile:** Russian-speaking GHOST kit customer (lower-OPSEC tier — public pools, abandoned host). **Separate identity from Vova75Rus and Operator-A.**

**Confidence Statement:** LOW (55%) — geographic anchor weaker than Operator-A; Russian-language signal inferred via kit-author + sibling-host evidence rather than direct artifact evidence.

**Geography:** Russian-resident (probable).

**Language:** Russian (inferred via kit-author + sibling-host evidence).

**Key Identity Artifacts:**

- XMR wallet prefix: `46a5osg...`
- CFX wallet prefix: `cfx:aat5y...`
- Public mining pools: `auto.c3pool.org` + `cfx-asia1.nanopool.org`

**Operator-A vs. Operator-B Same-Individual Question:** UNRESOLVED at the real-world-identity level. MODERATE-LOW probability of same individual based on distinct wallet/pool configurations.

### 9.8 INSUFFICIENT Cases (Cases 7, 8, 10)

Three cases are classified INSUFFICIENT for UTA assignment at the capsule depth captured:

- **Case 7** (`139.59.239.112`) — Productivity-AI stack; no operator-identity surface; post-compromise AI integration TTP captured but no actor evidence.
- **Case 8** (`68.183.92.28`) — Capsule-depth only; LLM vendor unspecified; AI orchestration mechanism unknown.
- **Case 10** (`5.230.201.54`) — Pre-victim staging-phase capture (zero sessions / zero beacons); generic c2admin login; AS200051 ownership unclear.

These cases are candidates for promotion to LOW confidence UTAs once future investigation produces additional artifacts (specifically: operator-identity surfaces, LLM vendor identification for Case 8, or victim-side beacon traffic for Case 10).

### 9.9 Cross-Case Attribution Discipline

The defining attribution finding is that **shared infrastructure does not imply operator coordination**. The investigation applied explicit discipline to avoid false coordination claims:

- **Campaign coordination:** REFUTED. 8 independent operators sharing only macro-pattern (AI-tool integration as offensive workflow component).
- **AEZA co-residency** (Cases 1 and 9): Ecosystem-level Russian-cybercrime signal NOT operator coordination evidence. AEZA is a known Russian-preferred bulletproof-adjacent provider; multiple unrelated Russian operators co-residing on AEZA is the expected pattern.
- **DigitalOcean co-residency** (Cases 2, 7, 8): Commodity-provider coincidence; no operational coordination.
- **OpenClaw co-usage** (Cases 2 and 4): Ecosystem-level signal consistent with documented OpenClaw security crisis (ClawHub 1,184 malicious skills; 40,000+ exposed instances).
- **AI-Generated Code Signature** (DEFINITE across Cases 1, 2, 3): Downstream of AI tools NOT operator coordination. Operators using same AI tools produce structurally similar code regardless of coordination — defender detection signal NOT attribution link.

### 9.10 Supply-Chain Context Actor: UnamSanctam

UnamSanctam is documented in this report as a **supply-chain context actor** — upstream OSS supplier of UnamWebPanel + SilentCryptoMiner since 2014, 860+ GitHub followers, SilentCryptoMiner with 1,020+ stars. **UnamSanctam is treated as a PUBLIC PERSONA, not a threat actor for this campaign.** Decision rationale: (a) UnamSanctam supplies open-source tooling that Vova75Rus repurposes; (b) UnamSanctam's own repos remain public and are not part of the GHOST kit distribution chain; (c) the EVIDENCE-PACKAGE.md §7.2 disclosure scope explicitly excludes UnamSanctam from T&S disclosure scope. This is published honestly because the supply-chain context is publication-relevant even though the actor designation is not.

### 9.11 Tier-2 Vendor Corroborations

The investigation's attribution findings have two Tier-2 vendor corroborations:

- **Censys ARC** (Mark Ellzey 2026-04-07) — Vova75Rus / GHOST kit author corroboration. The Censys disclosure preceded this investigation by 6 weeks; our findings extend Censys's research with 7 net-new contributions including sibling operator at 77.110.125.145, byte-identical libpam_cache.so supply chain, OWNER Telegram bot supply-chain monitoring, full hide-string/port inventory, and the GitHub T&S Tier-0 action.
- **Doctor Web** (September 2023) — Pandora-Mirai variant lineage corroboration. Case 3 operator is a downstream adopter extending the Android-TV-only 2023 scope to 11 IoT architectures.

---

## 10. Risk & Detection Posture

> **Analyst note:** This section describes the campaign-wide risk posture and the detection-engineering posture across the linked detection file (26 rules: 8 YARA, 12 Sigma, 6 Suricata). For per-case operator-specific detection content, see the companion sub-reports' detection deliverables (linked in Section 14.2).

### 10.1 Risk Reassessment Triggers

Reassess the campaign threat level (HIGH) under any of these conditions:

- **Cloudflare PSIRT does not action `tralalarkefe.com`** — Case 1 Cloudflare Tunnel C2 remains active against the healthcare victim and any future victims using the operator's custom-domain model. Reassess to consider upgrading from HIGH.
- **AEZA Group does not respond to the prepared disclosure package** — bulletproof status held at SUSPECTED pending AEZA response. If AEZA does not act, Cases 1 and 9 hosting remains available to operators.
- **Vova75Rus re-hosts post-GitHub-T&S suspension** — track for new Vova75Rus-pattern accounts and re-hosted GHOST kit repositories. Defenders should monitor `Vova75Rus/*`, `UID 73169104` recreations, and similar naming patterns.
- **the victim organization does not rotate stolen JWTs** — the 10-year IBM Instana JWT (iat 2024-03-06, jti 022a1b74-2332-4df5-a76b-60225ffa7ae3) remains valid until token rotation. If rotation does not occur, the operator retains read access to the victim organization observability.
- **New customer operators of the GHOST kit are observed** — the 4-tier supply chain expands by one tier per confirmed new customer if Vova75Rus's distribution channel is reconstituted. Re-assess the supply-chain depth score when new customer operators are confirmed.

### 10.2 Detection Coverage Summary

**Full Detection File:** [`/hunting-detections/ai-agent-frameworks-2026-05-23-detections.md`](https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/)

**Per-case detection rules** — operator-specific coverage lives in each sub-report's detection deliverable:

- [Case 1 — Russian Gemini](https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections)
- [Case 2 — Turkish ARPA](https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections)
- [Case 3 — Rovodev / Pandora Mirai](https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections)
- [Case 4 — Korean Claude + OpenClaw](https://the-hunters-ledger.com/hunting-detections/korean-claude-openclaw-221.150.15.104-detections)
- [Case 9 — GHOST Kit](https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections)

| Detection Layer | Count | MITRE Techniques Covered | Overall FP Risk |
|---|---|---|---|
| YARA | 8 rules | T1574.006, T1014, T1564.001, T1587, T1059.006, T1027, T1498 | LOW–MEDIUM |
| Sigma | 12 rules | T1574.006, T1014, T1059.006, T1583.006, T1102, T1496.001, T1562.001, T1071.001, T1027 | LOW–HIGH (per rule) |
| Suricata | 6 rules | T1583.006, T1102, T1496.001, T1071.001, T1573.001, T1090.004 | LOW–MEDIUM |
| **Total** | **26 rules** | **Across 3 detection layers** | |

**Priority breakdown:**

- **HIGH priority (deploy immediately):** 14 rules — low tuning required, targets are operator-bespoke artifacts.
- **MEDIUM priority (deploy with tuning):** 8 rules — environment-specific tuning needed (Cloudflare Tunnel egress monitoring, observability-platform allowlist).
- **LOW priority (hunting/hypothesis generation):** 4 rules — broad signatures useful for hypothesis-driven hunts, expected higher FP rate.

The detection content is organized into four thematic groups in the linked file:

1. **Novel AI-Abuse TTPs** — First-documented artifact classes (AI Operator Handoff Documents, LLM credential mutation scripts, AI-Generated Offensive Code structural signature).
2. **GHOST Kit + libpam_cache rootkit** — Commodity multi-customer cryptojacker kit signatures.
3. **Campaign Infrastructure Artifacts** — Pandora/Mirai naming, Russian A2A C2, ARPA observability harvester.
4. **Network Layer** — Mining pool DNS, Cloudflare tunnel egress, Hysteria v2 QUIC masquerade, Sliver JARM, C2 encoding pattern.

### 10.3 Coverage Gaps

The investigation identifies these detection gaps not currently covered by the linked detection file or by public detection catalogs:

- **AI Operator Handoff Documents** as a generic artifact class — the current YARA rule covers Cases 1 and 3 exemplars; novel handoff document formats are a known evolution risk (MODERATE confidence — the artifact format is operator-bespoke and varies between Cases 1 and 3 already observed).
- **LLM-Personalized Credential Mutation** at the network-layer — DLP/proxy with body inspection required; not all environments deploy this. An operator pivot to TLS pinning would break body-inspection detection (HIGH confidence based on the typical adversary response to network-body inspection; treat as a planning assumption, not a forecast).
- **Observability-token reverse pipeline** at the operator side — Sigma rules target the insider-side collector PowerShell but not the operator-side ingestion stack.
- **AS200051 (Case 10) ownership clarity** — pending BGP cross-validation. Detection currently relies on combined-condition rules with JARM as one signal.
- **Capsule-depth cases (7, 8, 10)** — limited detection coverage because operator-bespoke artifacts were not captured at depth.

---

## 11. Confidence Levels Summary

> **Analyst note:** This section organizes the campaign's findings by confidence level using the project standard scale (DEFINITE / HIGH / MODERATE / LOW / INSUFFICIENT — see CLAUDE.md CONFIDENCE LEVELS). Readers triaging the report for defender action should focus on DEFINITE and HIGH findings; MODERATE findings require additional corroboration before defender action; LOW findings are publication-honest acknowledgments of remaining uncertainty.

### DEFINITE Findings (Direct Evidence, No Ambiguity)

- **GHOST kit byte-identical `libpam_cache.so` across 2 customer hosts** — DEFINITE supply-chain root (MD5 `296a800564111b0bad9fe63faf4e63ba` matches on both Operator-A and Operator-B hosts).
- **LD_PRELOAD libc-hook rootkit architecture** — DEFINITE family-level signature (source code captured, ELF dynamic symbol exports confirmed).
- **GitHub T&S account-level action against Vova75Rus 2026-05-25** — DEFINITE disposition outcome (all 9 repos HTTP 404; Wayback evidence preserved).
- **Pandora-Mirai variant lineage** — DEFINITE (Doctor Web 2023 disclosure + VT consensus 43/66 + binary-level distribution URL embedding).
- **LLM-Personalized Credential Mutation pipeline operational** — DEFINITE (source code captured: `russian-ai_sniper_brute.py` + 5.5 MB `AI_ADMIN_MUTANTS.txt` output artifact).
- **5-vector persistence chain (Case 3)** — DEFINITE (auditd correlation captured all 5 vectors from same parent process within seconds).
- **AI-Generated Code structural signature DEFINITE across 3 operators** (Cases 1, 2, 3) — DEFINITE at signature-class level.
- **MITRE techniques** marked DEFINITE in Section 7 table: T1574.006 (Dynamic Linker Hijacking), T1014 (Rootkit), T1564.001 (Hidden Files), T1057 (Process Discovery), T1071.001 (Web Protocols), T1496.001 (Compute Hijacking), T1110.003 (Password Spraying — via LLM-Personalized Credential Mutation).
- **Multi-actor unrelated campaign hypothesis** — DEFINITE (ACH ruled with distinct IOCs/wallets/language/geography/targets/motivations/AI tools across all 8 cases).

### HIGH Findings (Strong Evidence, Minor Gaps)

- **Vova75Rus attribution (88%)** — HIGH (5+ year GitHub history + region code + personal dedication + Censys ARC corroboration + supply-chain signature).
- **Tier-0 disposition outcome significance** — HIGH (one report-batch disrupted upstream payload-distribution channel of the GHOST ecosystem).
- **5 named tunnel hostnames + the healthcare victim routing (Case 1)** — HIGH (operator artifacts document tunnel-to-victim-machine routing directly).
- **the victim organization multi-source observability theft (Case 2)** — HIGH (4 stolen sources, named victim, 73+ day dwell, insider recruitment artifact).
- **AI Operator Handoff Documents** — HIGH confidence at signature-class level with cross-operator validation; MODERATE confidence at novelty claim pending academic conference proceedings search.
- **Observability-Tool Reverse Pipeline novelty** — MODERATE-HIGH (no prior art found, novelty held below DEFINITE pending deeper prior-art search).
- **AEZA hosting preference for Russian operators** — HIGH (Cases 1 and 9 share AEZA; OFAC-sanctioned July 2025; 4/5 bulletproof indicators met).

### MODERATE Findings (Reasonable Evidence, Notable Gaps)

- **UTA-2026-012 Case 1 attribution (75%)** — MODERATE (Russian-language register + AEZA + forum activity + persona-priming + GitHub handle, but no real-world identity).
- **UTA-2026-013 Case 2 attribution (78%)** — high-MODERATE, top of the MODERATE band (70-85%) approaching HIGH (five converging axes + insider recruitment, but state-aligned-loose vs. political-factional sub-type INSUFFICIENT).
- **Case 9 commercial-sale model for GHOST kit** — MODERATE (17-byte diff + OWNER Telegram bot pattern across 2 customers; competing hypotheses remain plausible — affiliate program or personal multi-operator architecture — and cannot be ruled out without operator-financial evidence).
- **AI-democratized script-kiddie class as a threat type** — MODERATE (theoretical; no pure exemplar in this dataset; documented honestly).
- **Bulletproof hosting designation for AEZA** — MODERATE (4/5 indicators met; held at SUSPECTED pending AEZA disclosure response).

### LOW Findings (Weak/Circumstantial Evidence)

- **UTA-2026-014 Case 3 attribution (60%)** — LOW (Discord ID only; no GitHub handle, no real-world identity, no geographic anchor beyond English-speaking signal).
- **UTA-2026-015 Case 4 attribution (55%)** — LOW (Korea Telecom hosting + smoking-gun settings.local.json; no operator-identity artifacts).
- **UTA-2026-016 Case 9 Operator-A attribution (60%)** — LOW (Russian-language signal in scripts + AEZA hosting + Telegram MIRROR bot).
- **UTA-2026-017 Case 9 Operator-B attribution (55%)** — LOW (Russian-language signal inferred via kit-author + sibling-host evidence).
- **Operator-A vs. Operator-B same-individual question** — LOW (MODERATE-LOW probability of same individual; UNRESOLVED at real-world identity level).
- **AS200051 ownership for Case 10** — LOW (registered to individual "Rizki Abdul Azis" but BGP cross-validation incomplete).

### INSUFFICIENT Findings (Cannot Assess)

- **Case 7 attribution** — INSUFFICIENT (capsule depth; no operator-identity surface).
- **Case 8 attribution + AI orchestration mechanism + LLM vendor** — INSUFFICIENT.
- **Case 10 attribution** — INSUFFICIENT (pre-victim staging-phase capture).
- **Solo vs. small-team discrimination for Case 1** — UNRESOLVED but NOT publication-gating.
- **Specific (a) vs. (c) sub-type discrimination for Case 2** — INSUFFICIENT (requires Turkish-language doc full-read + OSINT pivot + political event correlation).
- **Cloudflare PSIRT response status** — UNKNOWN as of publication.
- **AEZA abuse desk response status** — NOT YET CONFIRMED RECEIVED.

---

## 12. Response Orientation

> **Analyst note:** This is not an incident response guide. It is a brief orientation for readers who need to know *what to address*, not *how to address it*. Readers with incident response needs should engage their internal IR team or a dedicated playbook — that is out of scope for this third-party publication.

### Detection Priorities (Highest-Value Behaviors to Hunt For First)

1. **`/etc/ld.so.preload` modifications on Linux estate** — the Case 9 GHOST kit's primary persistence anchor. Any modification deserves immediate review.
2. **AI Operator Handoff Document file-creation patterns** — Markdown documents in operator-likely paths with explicit "To: <AI agent>" headers or escalating-superlative file naming.
3. **Outbound HTTPS to `generativelanguage.googleapis.com` with password-mutation prompt fragments** — Case 1 LLM-Personalized Credential Mutation pipeline.
4. **`tralalarkefe.com` subdomain DNS queries** — Case 1 Cloudflare Tunnel C2 topology.
5. **`/api/ingest/instana`, `/api/ingest/solarwinds`, `/api/ingest/zabbix` URI patterns from any host** — Case 2 ARPA platform reverse-pipeline ingestion.

### Persistence Targets (What to Look For and Remove)

- `/etc/ld.so.preload` containing `/lib/security/libpam_cache.so` (Case 9 GHOST rootkit)
- `/lib/security/libpam_cache.so` itself (filename not in known-good PAM-module list)
- `~/.config/fontconfig/.cpu`, `~/.config/fontconfig/.gpu` (Case 9 hidden miners)
- Systemd units matching `arpa-*.service` (Case 2)
- ComfyUI custom nodes named `PerformanceMonitor` or `GPU Performance Monitor` (Case 9)
- `~/.rovodev/sessions/` on Linux server estate (Case 3)
- `~/.gemini/wrapper.sh` and `~/.gemini/skills/cf-c2-manager/SKILL.md` (Case 1)
- `~/.claude/settings.local.json` with pre-approved `Bash(curl ... | bash)` or `Bash(npm i -g <unfamiliar>)` entries (Case 4)
- The Case 3 5-vector persistence chain locations: `crontab`, `/etc/rc.local`, `/etc/init.d/sysupdate`, `/etc/systemd/system/system-update.service`, `~/.bashrc`, `~/.profile` (all 5 must be enumerated)

### Containment Categories

- **Isolate affected hosts** — preserve forensic state before remediation; capture volatile memory if rootkit persistence is suspected.
- **Block C2 infrastructure at perimeter** — apply IOC-based blocks from Section 8; prioritize `tralalarkefe.com` (Case 1), `77.110.96.200`+`77.110.125.145` (Case 9), `87.106.143.220:1337` (Case 3).
- **Rotate observability platform tokens** — IBM Instana, SolarWinds, Zabbix, VMware Aria; treat as Tier-1 secrets equivalent to cloud IAM credentials.
- **Rotate LLM API credentials** — Gemini, Claude, OpenAI keys exposed on affected hosts; assume harvested.
- **Network-wide hunt for lateral movement and persistence indicators** — deploy the linked detection file's 26 rules.

---

## 13. Investigation Methodology — Hunt.io Platform (MCP + V3 API) in the Defender Workflow {#methodology}

> **Analyst note:** This report documents how attackers integrate AI-agent CLIs into offensive workflows. The investigation that produced the report integrated an AI-agent CLI (Claude Code) with the **Hunt.io Model Context Protocol (MCP) server** to surface, triage, and analyze every one of the 9 cases above. This section documents that defender-side AI integration in detail — what worked, what did not, the specific findings the MCP enabled, and the workarounds used when MCP endpoints failed. The symmetry is intentional: AI-augmented tradecraft is now mainstream on both sides of the security line, and defenders evaluating MCP-augmented investigation workflows benefit from a concrete artifact to compare against.

### 13.1 Why This Section Appears in a Threat-Intelligence Report

The architectural pattern this report documents on the *offense* side — operator runs an AI CLI locally, the CLI calls vendor APIs via standardized tool interfaces, operator-authored handoff documents persist context across sessions — describes the *defense* side of this very investigation. Documenting the workflow is part of publication credibility, and it gives defender teams weighing MCP-augmented investigation a reproducible reference point for what works and what fails in practice.

**Sponsorship disclosure:** Hunt.io sponsors this report series and provided the platform access used during the investigation. The methodology in this section reflects The Hunters Ledger's independent, hands-on experience with the platform — Hunt.io did not direct, review, or approve the findings, attribution, or these observations. The limitations and failure modes are surfaced as candidly as the successes; the honest accounting of what did *not* work is the point of a methodology section, and it is preserved here in full. A separate testing-feedback report was sent to Hunt.io engineering with the per-endpoint observations and improvement requests; this section is the defender-facing distillation.

> **Early-access status:** The Hunt.io V3 API and MCP server described in this section were used under early access during this investigation. At the time of publication they are a pre-release build — **not yet generally available** — so endpoint names, tool coverage, and behavior documented here may differ from Hunt.io's eventual public release. (The AttackCapture open-directory dataset that surfaced all nine cases is part of Hunt.io's current, generally-available platform.)

### 13.2 Model Context Protocol (MCP) — A Brief Primer

The **Model Context Protocol** is an Anthropic-published open standard (announced November 2024) for exposing external data sources and tools to AI clients via a uniform JSON-RPC interface. An MCP **server** publishes tool definitions and schemas; an MCP **client** (Claude Code, Cursor IDE, custom AI agents) calls those tools as part of its reasoning loop. The pattern decouples AI tooling from any specific vendor — once a server is published, any compatible client can use it.

Hunt.io has built an MCP server — used here under early access — that exposes their full platform feature set: **AttackCapture** (open-directory dataset), IP/domain/SSL/JARM enrichment, threat-actor catalog, IP-history pivots, and SQL access to the underlying database. The investigation's Claude Code client connected to the Hunt.io MCP server (configured once in `.claude/settings.local.json`) and from that point forward could call any of ~60 Hunt.io tools alongside Claude's native tools (file I/O, web search, shell commands). This means: when the analyst said *"what does Hunt.io know about 77.110.96.200,"* Claude Code resolved that into a `mcp__hunt-io__attackcapture-host-summary` call, parsed the JSON response, and surfaced the relevant fields to the analyst — without the analyst leaving the AI client or copy-pasting URLs into a browser.

Hunt.io's MCP server is itself a client-facing layer over the platform's **V3 API** — a next-generation programmatic interface, in early access during this investigation and not yet generally available, that exposes AttackCapture, the enrichment family (WHOIS / SSL-certificate / DNS-history), JARM/JA4X fingerprinting, IP-history pivots, the threat-actor catalog, and Cloudflare-buster origin resolution. The investigation reached these capabilities both through the MCP server (for the AI-agent enrichment loop) and, where a direct call was simpler, through the V3 API itself — the same underlying data either way. The advanced enrichment and the MCP interface are both V3-platform capabilities; the per-tool behavior observed is documented in Sections 13.5 and 13.8.

This is the architectural symmetry: **the attackers in this report use AI agents to compose offensive workflows; the defender used an AI agent to compose investigative workflows**. The MCP layer is the abstraction that makes both possible.

### 13.3 Discovery Layer — All Nine Cases Surfaced Through Hunt.io AttackCapture

Every one of the 9 cases documented in this report originated from Hunt.io's open-directory dataset. The platform crawls exposed open directories at scale and applies classifier-derived framings — short threat-class summaries that orient the investigator before any deeper pull. In this investigation, Hunt.io's curated framings were accurate in all 9 cases reviewed, and the dataset's signal-to-noise was high enough that 25 candidate hosts surfaced for review narrowed to 9 publishable cases without significant manual filtering.

| Case | Host | Hunt.io Curated Framing |
|---|---|---|
| 1 | 213.165.51.115 | "Gemini CLI-Orchestrated C2, WordPress Credential Theft & Dental Practice Compromise" |
| 2 | 209.38.205.158 | Turkish-language operator targeting IBM Instana (operator-note files in Turkish) |
| 3 | 87.106.143.220 | Atlassian Rovodev installation + Mirai-style botnet |
| 4 | 221.150.15.104 | Claude Code + OpenClaw co-installation with customized `settings.local.json` |
| 5 (demoted) | 173.249.2.23 | Claude Code + custom MCP server suite for 14+ platforms |
| 6 (demoted) | 66.94.120.32 | "Multi-AI offensive workstation" — "using multiple AI coding assistants" |
| 7 | 139.59.239.112 | Weevely PHP web shells + Claude AI |
| 8 | 68.183.92.28 | 60-second AI-orchestrated payment API attack |
| 9 | 77.110.96.200 | ComfyUI GPU cryptojacking (PAM backdoor + 16-cloud-provider targeting) |

**Defender implication:** an open-directory crawl-and-classify capability — Hunt.io being the platform used here, with other platforms in the same category — is the discovery upstream of any investigation like this one. Without a curated dataset of exposed operator directories, the investigation would not have started. Defender teams considering investment in this capability should treat the discovery layer as the gating dependency for everything downstream.

### 13.4 Metadata Layer — Per-File MITRE TTP Tags Drove Two Major Findings

The single most operationally-useful Hunt.io MCP capability for this investigation was the per-file `malwareTags` array returned by `attackcapture-host-files`. Each file in an indexed open directory is annotated with: (a) MITRE ATT&CK technique identifiers derived from file content, and (b) sandbox-family classification tags (the platform integrates with [tria.ge](https://tria.ge/) for sandbox detonation). The combination orients the analyst to *what kind of platform this host is* before any file content is pulled.

**Concrete example — Case 9 (77.110.96.200) malwareTags response:**

```json
{
  "fileName": "libpam_cache.c",
  "sha256Hash": "[hash redacted in this excerpt]",
  "malwareTags": [
    {"name": "T1556.003", "source": "ttp"},
    {"name": "T1543.002", "source": "ttp"},
    {"name": "T1547.013", "source": "ttp"},
    {"name": "T1003.008", "source": "ttp"},
    {"name": "T1070.002", "source": "ttp"},
    {"name": "T1497.001", "source": "ttp"},
    {"name": "T1497.003", "source": "ttp"},
    {"name": "xmrig", "source": "tria.ge"}
  ]
}
```

Read together, those tags describe a **Linux platform with PAM modification persistence (T1556.003), systemd service persistence (T1543.002), XDG autostart persistence (T1547.013), `/etc/passwd` + `/etc/shadow` credential dumping (T1003.008), system-log clearing (T1070.002), system-check sandbox evasion (T1497.001), time-based sandbox evasion (T1497.003), and a confirmed xmrig (Monero miner) family classification from tria.ge sandbox detonation**. The analyst formed that platform model in seconds — without pulling any file content — and the model was correct end-to-end. This metadata directly drove Case 9's expansion from "capsule" depth to full case treatment: the breadth of TTP coverage signaled a systematic cryptojacking platform rather than a single-purpose scanner.

**Concrete example — Case 3 (87.106.143.220) host-files listing:**

The same `attackcapture-host-files` endpoint, querying the root of Case 3's host with `parentDepth: 2`, returned a directory tree exposing `/Pandoras_Box/` containing 11 cross-compiled Mirai binaries (`pandora.arm`, `pandora.arm5/6/7`, `pandora.m68k`, `pandora.mips`, `pandora.mpsl`, `pandora.ppc`, `pandora.sh4`, `pandora.spc`, `pandora.x86`). The cross-architecture binary suite is the **classic Mirai-family cross-compilation matrix** — an operator-tradecraft signature unrelated to AI tooling. The metadata-only finding directly drove the report's three-class operator taxonomy refinement (Section 4.10): Case 3 was initially classified as a pure AI-democratized script-kiddie based on the AI-generated Python files alone; the Pandora binary suite re-classified the operator as a **Hybrid AI-augmented** operator running classic Mirai-fork tradecraft alongside AI extensions.

In both cases, **metadata alone — no file content — was sufficient to drive a publishable finding**. This is the highest-leverage capability defender teams should evaluate when comparing platforms in this category.

### 13.5 Hunt.io MCP Endpoint Behavior Observed

The investigation exercised the following endpoint subset. Behavior is documented as observed at the investigation's subscription tier; other tiers may differ.

<table>
<colgroup>
<col style="width: 30%;">
<col style="width: 14%;">
<col style="width: 56%;">
</colgroup>
<thead>
<tr><th>Endpoint</th><th>Behavior</th><th>Notes</th></tr>
</thead>
<tbody>
<tr><td><code>attackcapture-host-summary</code></td><td>Reliable</td><td>Fast triage scope (item count, total size, first-seen date, download availability). Empty response (<code>totalItems: 0</code>) does not distinguish "never indexed" from "previously indexed, now cleaned" — relevant because operator hosts have short lifetimes (~1–2 weeks typical).</td></tr>
<tr><td><code>attackcapture-host-files</code></td><td>Reliable</td><td>Returns per-file SHA256, file path, <code>malwareTags</code> array, and <code>aiBrief</code> (often empty at our tier). Response size on rich hosts (e.g., 77.110.96.200 at 143 items / 468 MB) can exceed the MCP token cap and must be saved to file + grep-extracted.</td></tr>
<tr><td><code>attackcapture-host-ai-brief</code></td><td>Returns empty</td><td>Endpoint succeeds but <code>aiBrief</code> field is empty at our tier across all hosts queried.</td></tr>
<tr><td><code>attackcapture-file-preview</code></td><td>Returns "not found"</td><td>Returned "Open directory file not found" for every file tested, including files that the same MCP's <code>host-files</code> endpoint had just confirmed exist. Almost certainly a tier-restriction surfaced as a confusing error rather than an explicit tier message. Workaround: out-of-band content access via Hunt.io web UI.</td></tr>
<tr><td><code>attackcapture-file-ai-brief</code></td><td>"Tool execution failed"</td><td>Generic error masking — error code does not distinguish quota / tier / backend.</td></tr>
<tr><td><code>attackcapture-search-files</code></td><td>Inconsistent</td><td>Returned a mix of Convex gateway timeouts, "principal concurrency limit exceeded" errors, and successful responses. Concurrency limit fires per-time-window, not per-active-request, so even strictly serialized calls can hit it.</td></tr>
<tr><td><code>attackcapture-search-code</code></td><td>"Tool execution failed"</td><td>Generic error masking.</td></tr>
<tr><td>SSL / JARM / WHOIS enrichment family</td><td>Reliable when granular</td><td>Granular sub-endpoints (<code>enrichment-domain-whois</code>, <code>enrichment-domain-ssl-certificates</code>, <code>enrichment-domain-dns-history</code>) more reliable than the consolidated <code>enrichment-domain</code> tool. JARM fingerprints not retrieved for several AEZA / IONOS / DigitalOcean hosts (tier-restricted or dark to the 365-day index).</td></tr>
<tr><td>Threat-actor catalog</td><td>Reliable</td><td><code>threat-actors-listing-search</code> and <code>threat-actors-details</code> returned empty for all 6 UTAs assigned in this campaign — expected, as UTAs are by definition unattributed. The empty-response signal itself was useful: it confirmed that no public-domain threat-actor catalog had a prior overlap with the observed operators.</td></tr>
</tbody>
</table>

**Pattern observed:** metadata-grade endpoints work reliably; content-grade endpoints (file preview, file AI brief, code search) failed consistently at our subscription tier. The investigation built every publishable finding on the metadata layer + out-of-band content access via the Hunt.io web UI, with VirusTotal MCP used as a complementary content-grade pivot where file hashes overlapped between platforms.

### 13.6 What Worked Well

1. **Per-file MITRE TTP mapping + sandbox-family integration.** The combination of (a) automatically-derived MITRE technique tags, (b) tria.ge family classifications, and (c) per-file SHA256 hashes in one response is genuinely differentiating. The Case 9 platform model was assembled in a single MCP call.
2. **Curated host-level framings.** The classifier-derived threat-class summary lines accurately identified the threat class in every one of the 9 cases reviewed. Strong signal-to-noise saved hours of manual triage.
3. **`host-summary` schema design.** Returning `downloadAvailable`, `isBlocked`, `numSubdirs`, `totalItems`, `totalSize`, `seenFirst` in a single response is exactly the right shape for triage scoping.
4. **SHA256 hashes in `host-files` enable cross-platform pivots.** With a hash in hand, the analyst can immediately pivot to VirusTotal MCP for detection-rate, sandbox-report, and family-attribution context. This makes Hunt.io + VirusTotal complementary rather than redundant.
5. **AttackCapture as a discovery upstream.** No other platform evaluated during this investigation surfaces exposed-operator open directories at comparable scale and curation quality.

### 13.7 What Did Not Work — Workarounds Used

1. **Content endpoints failed at our tier.** `attackcapture-file-preview`, `attackcapture-file-ai-brief`, and `attackcapture-search-code` returned generic "not found" or "tool execution failed" errors universally. **Workaround:** out-of-band file content access via the Hunt.io web UI (browser-side, not MCP). All file content used in this report was retrieved this way for hosts where the MCP refused to surface preview content.
2. **Token-cap on rich-host listings.** The 77.110.96.200 `host-files` response (~65,000 characters) exceeded the MCP harness token cap. **Workaround:** the AI client saved the full response to a file, and `Grep` extracted just the filenames and TTP tags needed for the analysis. This worked, but a `minimal: true` parameter on the endpoint would be cleaner.
3. **Concurrency-limit unpredictability.** The Hunt.io platform enforces a strict concurrency limit (documented in the project's own platform-rules memory: *"serialize calls; do not batch in parallel like VirusTotal"*). Even with strict serialization, the `attackcapture-search-files` endpoint occasionally returned "principal concurrency limit exceeded" — suggesting the limit is per-time-window rather than per-active-request. **Workaround:** retry-after a short back-off; treat any concurrency-error response as transient.
4. **Generic-error masking.** Hunt.io returns `"Tool execution failed"` for at least three distinguishable underlying causes (quota, tier-restriction, backend unavailable). When this occurred, the investigation fell back to VirusTotal MCP for the same indicator and explicitly noted the loss of JARM / threat-actor coverage in the analyst output.
5. **AI-client classifier setup friction.** Claude Code's auto-mode classifier blocks MCP tool calls that are not pre-listed in `.claude/settings.local.json`. The first Hunt.io MCP call in this investigation was blocked; the analyst had to add ~60 `mcp__hunt-io__*` entries to the settings file before further work could proceed. This is an AI-client setup step, not a Hunt.io-server issue — but it is a real friction point for new MCP adopters and worth surfacing here so defender teams budgeting evaluation time know what to expect.

### 13.8 Hunt.io + VirusTotal Are Complementary, Not Substitutes

The investigation routed indicator enrichment through **both** Hunt.io and VirusTotal MCPs deliberately, not as a fallback. The two platforms have distinct strengths:

- **Hunt.io strengths:** AttackCapture open-directory dataset; per-file MITRE TTP tags; JARM/JA4X infrastructure fingerprints; multi-vendor threat-actor alias catalog; Cloudflare-buster origin-resolution; IP-history pivots with port/SSH/SSL panels.
- **VirusTotal strengths:** AV detection rates; consolidated sandbox behavioral reports (Zenbox, VMRay, ANY.RUN, Tencent HABO); embedded URL/IP relationships; community comments; IDS/IPS rule coverage matrices; long-tail file-content archive.

For Case 3's Pandora dropper script (SHA256 `d3fd9994b16dc9b14c29f7faf7b5f6c84f44b06fccf82f0031a0871ce5e20e17`), the workflow looked like this: Hunt.io's `host-files` listing surfaced the dropper as a small (363 B) text file on the open directory with malware-tag annotations; VirusTotal's `get_file_report` then returned the 12-of-63 detection rate, Zenbox Linux + VMRay Mirai family classifications, Kaspersky `HEUR:Trojan-Downloader.Shell.Agent.p` heuristic match, and the Snort/Suricata IDS rule coverage matrix (`MALWARE-OTHER Unix.Miner.Xbash variant dropped bash script`, `ET HUNTING Suspicious GET Request for .x86/.arm...` family). Neither platform alone produced that complete picture; the **cross-platform pivot via MCP-shared SHA256 hash** is what tied them together.

Defender teams evaluating MCP-augmented investigation should expect to wire **at least two** MCP servers — one open-directory / infrastructure-fingerprint platform (Hunt.io being one option) and one consolidated malware-intel platform (VirusTotal being the most common). Single-platform MCP integration leaves substantial pivot coverage on the table.

### 13.9 Defender Takeaway — Evaluating MCP-Augmented Investigation

For security teams considering investment in MCP-augmented threat-intel workflows, the operational lessons from this investigation are:

1. **The MCP layer makes AI-augmented investigation reproducible across team members.** Once the MCP server is configured in the team's AI-client settings, any analyst can run the same indicator-enrichment pattern by asking the AI client natural-language questions ("what does Hunt.io know about X," "pull the malware tags on file Y"). The settings file is the artifact that captures the workflow; new team members import it once and inherit the full capability.
2. **Start with metadata-grade workflows.** Per-file MITRE TTP tags, host-summary triage, file-hash pivots to VirusTotal — these patterns produce the highest signal-to-context-window ratio. Content-grade workflows (file preview, AI-brief generation, code search) are more variable in availability and should be treated as bonus rather than baseline.
3. **Wire at least two complementary MCP servers.** Open-directory / infrastructure-fingerprint coverage (Hunt.io class) and consolidated malware-intel coverage (VirusTotal class) cover different pivot dimensions. Cross-platform pivots via shared SHA256 / IP / domain are where most novel findings emerge.
4. **Expect tier-restriction behavior to surface as ambiguous errors.** Plan for out-of-band fallback paths (vendor web UI, second platform MCP) whenever the primary MCP endpoint returns generic failures. Document the workarounds in the team's runbook so the institutional knowledge persists across analysts and investigations.
5. **Verify, do not trust.** The same project memory that records Hunt.io operational rules also records *infrastructure-analyst hallucination risk* — AI clients restricted to web-search alone have produced fabricated ASN and IP metadata in prior work. MCP-routed enrichment grounds the AI client in vendor-platform data and substantially reduces this risk, but does not eliminate it. Cross-validate critical indicators across at least two independent sources before publishing claims.
6. **Honor platform concurrency limits.** Hunt.io's strict serialization requirement is enforceable in AI-client settings (Claude Code's `mcp__hunt-io__*` calls can be queued rather than parallelized). Set this expectation early; new MCP adopters frequently hit the limit before discovering it.

**Bottom line.** The investigation built 4 novel-TTP claims, 2 named-victim disclosures (the healthcare victim, the victim organization), 6 UTA assignments, 1 named-actor HIGH attribution (Vova75Rus), 1 Tier-0 disposition outcome (GitHub T&S 2026-05-25), and 9 publishable case writeups on a foundation of Hunt.io MCP metadata + VirusTotal MCP content + out-of-band web-UI access. The MCP architecture made this investigation possible at single-analyst publisher scale. Defenders evaluating AI-augmented workflows should treat this report — including this methodology section — as the kind of artifact MCP-augmented investigation produces, and budget capability investment accordingly.

---

## 14. References & Appendices

### 14.1 Linked Project Files

- **IOC Feed (machine-readable JSON):** [`/ioc-feeds/ai-agent-frameworks-2026-05-23-iocs.json`](https://the-hunters-ledger.com/ioc-feeds/ai-agent-frameworks-2026-05-23-iocs.json) — Full IOC inventory for SIEM/EDR ingestion. No defanging applied.
- **Detection Rules (YARA + Sigma + Suricata):** [`/hunting-detections/ai-agent-frameworks-2026-05-23-detections.md`](https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/) — 26 rules across 3 detection layers. Author: The Hunters Ledger. License: CC BY-NC 4.0.

### 14.2 Sub-Reports (Series)

**Start here, then read in order.** This parent is the synthesis; each sub-report below carries the per-case forensic depth.

1. **[Russian Gemini Credential-Mill Operator](/reports/russian-gemini-credential-mill-213.165.51.115/)** (Case 1, UTA-2026-012) — `ai_sniper_brute.py` pipeline, `c2_server.py` architecture, Cloudflare Tunnel topology, the healthcare-victim impact, and Phase 11 native Russian idiom analysis — `critical`.
2. **[Turkish ARPA Observability-Harvester Operator](/reports/turkish-arpa-openclaw-state-insurer-209.38.205.158/)** (Case 2, UTA-2026-013) — ARPA platform architecture (TimescaleDB+Neo4j+Redis), 4-source observability harvesting against the victim organization, and insider-recruitment TTP framing (insider AD user + Turkish-language tunnel-setup docs) — `critical`.
3. **[Rovodev/Pandora Mirai Operator](/reports/rovodev-mirai-matrix-c2-87.106.143.220/)** (Case 3, UTA-2026-014) — Rovodev session JSONs as AI-authoring primary-source evidence, Pandora-Mirai 11-architecture binary set, and 5-vector persistence chain forensics — `high`.
4. **[Korean Claude Code + OpenClaw Operator](/reports/korean-claude-openclaw-221.150.15.104/)** (Case 4, UTA-2026-015) — capsule-depth artifact analysis of the attacker-customized `settings.local.json` permission allowlist — `med`.
5. **[GHOST Cryptojacker Kit + 4-Tier Supply Chain](/reports/ghost-cryptojacker-vova75rus-77.110.96.200/)** (Case 9, Vova75Rus HIGH + UTA-2026-016 + UTA-2026-017) — `libpam_cache.so` ELF internals, container-escape suite functions, ComfyUI fake-node persistence, and the Tier-0 disposition outcome timeline — `high`.

Each sub-report cross-references this parent report for cross-case context.

### 14.3 External Research and Tier-2 Vendor Sources

- **Censys ARC** — Mark Ellzey, ComfyUI GHOST Campaign (April 2026). Tier 2 / Admiralty B2. Original kit-author research preceding this investigation by 6 weeks; corroborates Vova75Rus identity.
- **Doctor Web** — Android.Pandora Disclosure (September 2023). Tier 2 / Admiralty B2. Pandora-Mirai variant lineage source for Case 3.
- **Google GTIG** — AI Threat Tracker (November 2025). Tier 2 / Admiralty B2.
- **Anthropic** — Misuse Report April 2025; Misuse Report August 2025; AI Espionage Disruption September 2025. Tier 2 / Admiralty B2.
- **Proofpoint** — Cloudflare Tunnel RAT Delivery (August 2024). Tier 2 / Admiralty B2. Establishes Cloudflare Tunnel abuse tradecraft baseline.
- **Securonix** — SERPENTINE#CLOUD campaign reporting. Tier 2 / Admiralty B2.
- **IBM X-Force** — OpenClaw Security Analysis (2026). Tier 2 / Admiralty B2. Ecosystem context for Cases 2 and 4.
- **Kaspersky Blog** — OpenClaw Vulnerabilities (2026). Tier 2 / Admiralty B2.
- **NSFOCUS** — OpenClaw Attack Surface Analysis (2026). Tier 2 / Admiralty B3.
- **Hunt.io AttackCapture Dataset** — GHOST cross-host search corroboration. Tier 2 / Admiralty B2.
- **OFAC** — AEZA Group Sanctions (July 2025). Tier 1 / Admiralty A1.
- **Public corporate-registry / sovereign-fund disclosures** — used to establish the victim organization's state-affiliation context. Tier 2 / Admiralty B1.
- **Atlassian** — Rovodev CLI GA announcement (October 2025). Tier 2 / Admiralty B1.
- **Netskope** — DigitalOcean Abuse (2023). Tier 2 / Admiralty B2.
- **arXiv 2604.12601** — LLM-Guided Password Guessing (April 2026). Tier 3 / Admiralty C3. Differentiates from LLM-Personalized Credential Mutation.
- **The Hacker News** — GHOST/ComfyUI syndication (April 2026). Tier 3 / Admiralty C2.
- **BleepingComputer** — Pandora-Mirai 2023 coverage. Tier 3 / Admiralty C2.

### 14.4 Appendix A — Identity Artifacts Inventory

The following identity artifacts were captured during the investigation. Each is documented for cross-reference with future investigations.

| Type | Value | Context |
|---|---|---|
| GitHub | `Vova75Rus` (UID `73169104`) | Case 9 kit author; account suspended 2026-05-25 |
| GitHub | `MehmetARPA` | Case 2 operator handle; possibly real-name Mehmet ARPA; **account suspended 2026-05-25** |
| GitHub | `sonner1337` | Case 1 Russian operator handle |
| GitHub | `UnamSanctam` | Case 9 supply-chain context; PUBLIC PERSONA not threat actor |
| Discord | `1441591352927326259` | Case 3 operator ID (created 2025-11-22T00:49:22 UTC) |
| Telegram | `@americanpatriotus` | Case 1 disinformation channel |
| Telegram bot | `8415540095` | Case 9 OWNER bot (kit-author Vova75Rus channel; supply-chain monitoring) |
| Telegram bot | `8315596543` | Case 9 Operator-A MIRROR bot |
| Operator IP | `31.223.97.87` | Case 2 Turkish ARPA operator residential (TurkNet AS12735) |
| GitHub PAT | `ghp_tdcXTl...g4PDaRW` | Case 1 full-admin PAT (defanged) |
| Persona string | `братух` | Case 1 Russian persona priming in GEMINI.md |
| Brand string | `ARPA Korelasyon Motoru` | Case 2 operator self-branding |
| Forum URL | `duty-free.cc` | Case 1 Russian carding forum activity |
| Personal dedication | (March 8th / Women's Day greeting) | Case 9 Vova75Rus personal-dedication page |

### 14.5 Appendix B — Research Gaps (Acknowledged for Future Work)

The investigation acknowledges these gaps as publication-honest characterization rather than hidden uncertainty:

- Academic conference proceedings (Black Hat, USENIX, IEEE S&P, DEF CON 2024-2026) not searched for AI Operator Handoff Document prior art — HIGH impact on novelty claim.
- Underground forum monitoring (Exploit.in, XSS.is) not conducted for LLM credential mutation technique discussion — HIGH impact on novelty claim.
- Case 8 AI orchestration mechanism and LLM vendor unidentified — cannot assess novelty or write detection rules.
- Case 10 Cursor IDE integration inferred from co-located binaries, not confirmed from AI-session transcripts.
- USOM (Turkey) advisory database not searched in Turkish-language sources for prior the victim organization incidents.
- OpenClaw SOUL.md persona architecture technical analysis not conducted — relevant for Case 2 sub-report.
- AS200051 ownership (Case 10) requires BGP cross-validation.
- Aruba Italy distribution servers (80.211.94.16, 80.211.111.10) dark to Hunt.io 365-day index — no JARM, SSL, or service fingerprint data.
- `tralalarkefe.com` WHOIS not independently queried via live WHOIS source — documented from operator artifacts only.
- JARM fingerprints for AEZA hosts, IONOS host, and DigitalOcean hosts not retrieved (Hunt.io MCP tier limitation).
- Solo vs. small-team discrimination for Case 1 UNRESOLVED.
- Operator-A vs. Operator-B same-individual question UNRESOLVED.

### 14.6 Appendix C — Key Analytic Conclusions (KAC Documentation)

The campaign's headline analytical claims are surfaced here with their underlying assumptions explicit, so that defenders or downstream analysts can evaluate the inferential chain rather than accept the conclusion at face value. This format applies the Structured Analytic Technique discipline of separating evidence from assumption from conclusion.

**KAC 1 — "AI does not replace operator tradecraft; it extends it."**

- **Headline conclusion** (Executive Summary, Section 4.10): none of the 8 observed operators uses AI as a replacement for offensive skill. AI is an additive capability uplift layer.
- **Evidence anchors:**
  - Case 1 ships hand-written Quasar-class PowerShell implants and a self-built unauthenticated Python-stdlib C2 server alongside its Gemini integration (Section 4.1).
  - Case 2 ships a production-grade systemd/TimescaleDB/Neo4j/Redis observability-harvester platform that no LLM produced (Section 4.2).
  - Case 3 ships a Mirai-family 11-architecture botnet whose lineage traces to 2016 source-code releases (Section 4.3).
  - Case 9 ships byte-identical LD_PRELOAD libc-hook rootkit (`libpam_cache.so`) — kernel-adjacent persistence engineering predates LLM availability (Section 4.5).
- **Underlying assumption (made explicit):** "If an operator demonstrates any non-AI-authored offensive capability of moderate sophistication, AI is supplemental rather than enabling." This assumption is appropriate for Cases 1, 2, 3, 9 where non-AI capability is observed at moderate or higher sophistication. It is **not testable** for capsule-depth cases (4, 7, 8, 10) where filesystem extraction was not conducted.
- **Falsification condition:** If any of Cases 4, 7, 8, 10 is later shown via deeper investigation to be AI-only (operator writes natural-language spec; LLM produces all code; operator cannot operate the stack without AI), the three-class taxonomy at Section 4.10 would warrant a fourth class for AI-democratized script-kiddies. The taxonomy already documents this class as **theoretical** with no pure exemplar in the dataset (Section 4.10).
- **Confidence in headline conclusion:** HIGH for the 4 deeply-investigated cases (1, 2, 3, 9); MODERATE for the campaign-wide generalization due to capsule-depth limitation on cases 4, 7, 8, 10.

**KAC 2 — "Multi-vendor diversity refutes single-coordinated-campaign framing."**

- **Headline conclusion** (Executive Summary, Section 9.9): no two operators share the same AI tool, hosting provider, target sector, or motivation; the campaign is an ecosystem-wide diffusion pattern rather than a single coordinated actor.
- **Evidence anchors:** 5 distinct AI tools across 8 operators (Gemini CLI, Claude Code, Atlassian Rovodev, OpenClaw, Cursor IDE), 6 distinct hosting providers (AEZA, DigitalOcean, IONOS, Korea Telecom, Hetzner-like, etc.), 4 distinct target sectors (healthcare, insurance, IoT botnet recruitment, GPU cloud cryptojacking), 4 distinct motivations (financial cybercrime, observability harvesting, DDoS-for-hire, cryptojacking).
- **Underlying assumption (made explicit):** "Coordinated campaigns produce convergent infrastructure/tooling/target choices." This is well-established in attribution practice (Mandiant, CrowdStrike attribution methodology) but treats diversity as evidence of non-coordination rather than evidence of operator OPSEC discipline within a coordinated campaign.
- **Falsification condition:** A coordinated campaign deliberately practicing extreme infrastructure/tooling diversity for OPSEC reasons would produce the same observed pattern. Section 9.9 addresses this via 5 named falsification axes (AEZA co-residency, DigitalOcean co-residency, OpenClaw co-usage, timing windows, operator-language overlap) — none of these axes returned coordination evidence beyond ecosystem-level co-residency.

**KAC 3 — "GitHub T&S Vova75Rus action is Tier-0 supply-chain disposition."**

- **Headline conclusion** (Section 4.5, Section 9.1): the 2026-05-25 GitHub account-level action against UID 73169104 disrupted the entire upstream payload-distribution channel of the GHOST cryptojacker ecosystem.
- **Evidence anchors:** 9 suspended repositories (ComfyUI-Shell-Executor, ComfyUI-Shell-Plugin, Notes.github.io, and 6 ancillary repos) verified at takedown time; OWNER Telegram bot 8415540095 baked into customer deployments confirms supply-chain root identity; byte-identical kit binary across both customer hosts confirms single upstream source.
- **Underlying assumption (made explicit):** "Repository takedown disrupts the distribution channel for as long as the operator does not re-host on another platform." Re-hosting is expected; the disposition is characterized as **temporarily** disrupted (Executive Summary; Section 9.1), not permanently disabled.
- **Falsification condition:** If the kit re-appears on a different GitHub identity or on a non-GitHub platform within weeks, the disposition impact is limited. Wayback Machine snapshots are preserved as pre-takedown evidence for re-hosting cross-correlation.

---

© 2026 Joseph. All rights reserved. See LICENSE for terms.








