---
title: "Multi-Actor AI-Agent Framework Abuse: 8 Operators Integrating AI CLIs into Offensive Workflows"
date: '2026-05-25'
layout: post
permalink: /reports/ai-agent-frameworks-2026-05-23/
thumbnail: /assets/images/cards/ai-agent-frameworks-2026-05-23.png
hide: true
category: "AI-Augmented Threat Operations / Multi-Actor Campaign"
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
---

**Campaign Identifier:** AI-Agent-Frameworks-MultiActor-2026-05-23<br>
**Last Updated:** June 2, 2026<br>
**Threat Level:** HIGH

---

## Executive Summary

**TL;DR — five-bullet summary for skim readers:**

- **8 independent threat operators** observed integrating AI-agent CLIs (Gemini CLI, Claude Code, Atlassian Rovodev, OpenClaw, Cursor IDE) directly into offensive workflows — documented through filesystem-grounded artifacts, not marketing claims.
- **Five novel TTPs** at first-public-documentation level: AI Operator Handoff Documents, LLM-Personalized Credential Mutation, AI-Generated Code Structural Signature, Observability-Tool Reverse Pipeline, and Operator-Built Unauthenticated Python-stdlib C2.
- **Two confirmed victims** with operator-confirmed access at time of investigation: a US healthcare provider (persistent RDP+SSH) and the victim organization (state-owned Turkish insurer; 4 stolen observability sources cross-correlated).
- **HIGH-confidence (88%) attribution** of Case 9 cryptojacker kit author **Vova75Rus**; six UTAs (UTA-2026-012 through UTA-2026-017) assigned for remaining operators.
- **Tier-0 disposition outcome** — GitHub Trust & Safety actioned the Vova75Rus account on 2026-05-25, disrupting the upstream payload-distribution channel of the GHOST cryptojacker ecosystem.

Across a 9-day investigation, The Hunters Ledger documented these 8 operators as filesystem-grounded artifacts (operator-authored AI handoff documents, attacker prompts, weaponized configurations, AI-co-authored attack code, stolen victim data) rather than the AI-output-side measurements that dominate public reporting. The campaign-defining finding is **multi-vendor diversity**: no two operators share the same AI tool, hosting provider, target sector, or motivation, which refutes the "single coordinated AI-driven campaign" framing in favor of an ecosystem-wide diffusion of AI-augmented tradecraft across unrelated actors. This means defenders cannot rely on a single vendor block, IOC sweep, or threat-group designation to address the AI-misuse threat — coverage must span the ecosystem-wide attack surface.

This report is the parent of a six-report series. It synthesizes findings across all 8 active operator cases plus 2 honestly-characterized false-positive demotions; five sub-reports (Cases 1, 2, 3, 4, and 9) provide per-case deep-dives. Readers should treat the parent as the canonical reference for the campaign's cross-case patterns and the sub-reports as the operator-specific technical analyses. Direct links to each sub-report are in Section 14.2.

### What Was Found

Over a 9-day investigation (16 phases) beginning 2026-05-16, hunt.io open-directory exposures combined with multi-source filesystem pulls surfaced direct evidence of how real attackers — not laboratory researchers or vendor-misuse reports — integrate AI-agent CLIs into their day-to-day offensive operations. The investigation observed operators across **eight independent cases**, each using distinct AI tools, hosting providers, target sectors, and motivations:

- **Case 1 — Russian Gemini credential-mill operator** (UTA-2026-012, MODERATE 75%). AEZA-hosted server (213.165.51.115), Cloudflare-Tunnel C2 topology under operator-owned domain `tralalarkefe.com`, GitHub handle `sonner1337`, captured full-admin GitHub Personal Access Token, persistent RDP+SSH access into the US healthcare victim via Cloudflare Tunnel, co-located disinformation channel @americanpatriotus, and 40+ stolen Gemini Pro Preview API keys. Captured artifact `ai_sniper_brute.py` is the campaign's first DEFINITE evidence of **LLM-Personalized Credential Mutation** at attack time.
- **Case 2 — Turkish ARPA observability-harvester operator** (UTA-2026-013, high-MODERATE 78%). DigitalOcean VPS (209.38.205.158), TurkNet residential ISP operator origin (31.223.97.87), self-branded **"ARPA Korelasyon Motoru"** platform built on TimescaleDB+Neo4j+Redis, four stolen observability sources cross-correlated against the state-owned victim organization (10-year IBM Instana JWT, 784 SolarWinds nodes, 100 Zabbix hosts, VMware Aria), insider-recruited Windows AD user [employee ID — suppressed] with operator-authored Turkish-language tunnel-setup documentation. **GitHub T&S account-level action against operator handle MehmetARPA on 2026-05-25** — repository no longer accessible.
- **Case 3 — Rovodev/Pandora Mirai botnet operator** (UTA-2026-014, LOW 60%). IONOS-hosted operator host (87.106.143.220, dual HTTP/HTTPS distribution), 11-architecture Mirai-family botnet, Atlassian Rovodev session JSONs capturing the operator's natural-language prompts to AI authoring the attack framework, downstream Pandora-Mirai variant lineage (Doctor Web 2023).
- **Case 4 — Korean Claude+OpenClaw operator** (UTA-2026-015, LOW 55%). Korea Telecom (221.150.15.104), `~/.claude/settings.local.json` artifact pre-approving `openclaw.ai/install.sh` and `npm i -g openclaw` in the Claude Code permission allowlist — direct evidence of attacker-customized AI-tool installation chains.
- **Case 9 — GHOST cryptojacker kit + 4-tier supply chain** (Vova75Rus HIGH 88% / UTA-2026-016 / UTA-2026-017). AEZA-hosted operators (77.110.96.200, 77.110.125.145), byte-identical `libpam_cache.so` LD_PRELOAD libc-hook rootkit across both customer deployments, **GitHub T&S Tier-0 action against kit author Vova75Rus on 2026-05-25** disrupting upstream payload distribution, OWNER Telegram bot 8415540095 baked into every customer deployment (supply-chain monitoring signature).
- **Cases 7, 8, 10** — capsule-depth captures (139.59.239.112 productivity-AI stack with Claude + Weevely + frp; 68.183.92.28 AI-orchestrated 60-second multi-stage payment-API attack; 5.230.201.54 active Sliver-derivative C2 development with v30→v39 in one day). INSUFFICIENT attribution depth (sub-50% confidence) but operationally-relevant TTP captures.

Two additional cases (Case 5 at 173.249.2.23, Case 6 at 66.94.120.32) were initially flagged but **demoted** during analysis — Case 5 is a defensive-security SaaS consultant and Case 6 is a benign HuggingFace ML researcher. Both are explicitly characterized in the report's false-positive discrimination section because the lesson matters: **AI tool presence on a host is not, by itself, a malicious indicator.**

### Why This Threat Is Significant

Three reasons distinguish this campaign from existing public reporting on AI-misuse:

**First, this is operator-side workflow documentation, not AI-generated content.** Public reporting to date has covered AI-generated phishing, AI-written malware code, and vendor AI-misuse detection announcements — all measured from the *output* side. This investigation documents the *input* side: what operators actually do with AI CLIs on their own servers, including filesystem evidence, custom AI handoff documents, attacker prompts, weaponized configurations, and stolen victim data. The five novel TTPs documented are first-public-documentation candidates and were not present in 8+ major vendor AI-misuse reports searched as prior art. This fills a documented gap in the public threat-intelligence record.

**Second, AI does not replace operator tradecraft — it extends it.** The single most important finding from cross-case analysis is that **none** of the 8 operators uses AI as a replacement for offensive skill. Case 1 ships AI alongside hand-written Quasar-class PowerShell implants and a self-built unauthenticated Python-stdlib C2 server. Case 2 ships AI alongside a production-grade systemd/TimescaleDB observability-harvester platform that no LLM produced. Case 3 ships AI alongside a Mirai-family 11-architecture botnet whose lineage traces to 2016 source-code releases. The campaign's three-class taxonomy — **AI-integrated mature operator** / **Hybrid AI-augmented** / **AI-democratized script-kiddie** — was refined during analysis to acknowledge that the "AI-democratized" class is theoretical: no pure exemplar exists in this dataset. Defenders should reject AI-replacement framings and instead treat AI as an **additive capability uplift layer** observable through distinctive artifacts.

**Third, the Vova75Rus / GHOST kit disposition outcome demonstrates that one report-batch can disrupt an entire ecosystem upstream.** The investigation identified Vova75Rus as the kit author of the GHOST cryptojacker ecosystem (separate identity from the kit's customer operators), preserved his GitHub footprint via Wayback Machine snapshots before disclosure, and on 2026-05-25 saw GitHub Trust & Safety take account-level action against UID 73169104 — suspending all 9 repositories that hosted the kit's payload-distribution components (ComfyUI-Shell-Executor, ComfyUI-Shell-Plugin, Notes.github.io, and ancillary repos). This is the strongest possible **Tier-0 disposition outcome** for an upstream supply-chain actor: a single report-batch disrupted the entire upstream payload-distribution channel of the GHOST ecosystem, removing the source from which both observed customer operators (and any not-yet-observed customers) pull binaries.

### Key Risk Factors

This campaign's risk score reflects the **aggregate** capability across 8 unrelated operators rather than any single sample. The threat level is **HIGH** (not CRITICAL) because no single operator demonstrates campaign-scale capability — each is bounded by their own infrastructure and tradecraft — but the *ecosystem*-level findings (AI-integrated tradecraft diffusion, supply-chain depth in Case 9, confirmed-victim impact in Cases 1 and 2) raise the aggregate risk above MEDIUM.

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
<tr><td>Data Exfiltration</td><td>9/10</td><td>Case 2 stolen observability tenant against named state-owned victim (4 sources cross-correlated); Case 1 persistent RDP+SSH into named US healthcare victim; Case 9 wallet-extraction from cloud GPU victims; Case 1 40+ stolen Gemini Pro API keys.</td></tr>
<tr><td>Persistence Difficulty</td><td>8/10</td><td>Case 9 LD_PRELOAD libc-hook rootkit (`/etc/ld.so.preload` + `libpam_cache.so`) survives standard remediation if not enumerated; Case 1 Cloudflare Tunnel persistent tunnels survive server-side IP changes; Case 3 5-vector persistence chain (cron + rc.local + init.d + systemd + bashrc).</td></tr>
<tr><td>Evasion Capability</td><td>7/10</td><td>Mixed — Case 9 rootkit hides processes/files/network at libc layer; Case 1 Cloudflare Tunnel domain-fronting; Hysteria v2 (a QUIC-based proxy/backdoor protocol with TLS SNI masquerade capability) with bing.com SNI masquerade; but Cases 1, 3, 4 ship without anti-analysis (consistent with AI-generated structural code signature).</td></tr>
<tr><td>AI Integration Maturity</td><td>8/10</td><td>5 novel TTPs documented at first-public-documentation level; AI integrated across credential mutation (Case 1), code generation (Cases 1+2+3), workflow orchestration (Case 8), permission-allowlist customization (Case 4), and operator-to-AI handoff documents (Cases 1, 3).</td></tr>
<tr><td>Supply Chain Depth</td><td>9/10</td><td>Case 9 4-tier supply chain (UnamSanctam upstream OSS → Vova75Rus kit author → ≥2 customer operators → 4,573-entry ComfyUI victim scan list); byte-identical kit binary across customer hosts; OWNER Telegram bot supply-chain monitoring signature.</td></tr>
<tr><td>Named-Victim Impact</td><td>9/10</td><td>the victim organization (81.1% state-owned via Turkey Wealth Fund, recently attracted significant international institutional investment); the healthcare victim (US healthcare provider, HIPAA-regulated, persistent RDP+SSH); both with operator-confirmed access at time of investigation.</td></tr>
</tbody>
</table>

**Overall Campaign Risk Score: 8.3/10 — HIGH.** The campaign threat level is held at **HIGH** rather than CRITICAL because no single operator reaches campaign-scale capability, infrastructure remediation is partially complete (GitHub T&S action on Vova75Rus, cloud-provider abuse desk notifications submitted for 78 victim IPs, Cloudflare PSIRT response on tralalarkefe.com pending), and the disposition outcome on the upstream kit author has already reduced ecosystem-level risk meaningfully. If Cloudflare PSIRT does not action `tralalarkefe.com`, or if AEZA Group does not respond to the prepared disclosure package, the threat level should be reassessed.

### Threat Actor Summary

This is a **multi-actor** campaign, not a single coordinated actor. Attribution is distributed across one named actor and six Unattributed Threat Actor designations:

- **Vova75Rus** — Case 9 GHOST cryptojacker kit author. HIGH confidence (88%) based on 5+ year GitHub history (UID 73169104), region code 75 in handle (Zabaykalsky Krai, Russian regional plate code convention), personal-dedication page to "Arina" on Russian-culturally-significant date (March 8th, International Women's Day), Censys ARC primary-research corroboration (Mark Ellzey 2026-04-07), OWNER Telegram bot 8415540095 baked into every customer deployment, and byte-identical kit binary across customer hosts.
- **UTA-2026-012** *(an internal tracking label used by The Hunters Ledger — see Section 9)* — Case 1 Russian Gemini credential-mill operator (MODERATE 75%).
- **UTA-2026-013** — Case 2 Turkish ARPA observability-harvester operator (high-MODERATE 78%).
- **UTA-2026-014** — Case 3 Rovodev/Pandora Mirai operator (LOW 60%).
- **UTA-2026-015** — Case 4 Korean Claude+OpenClaw operator (LOW 55%).
- **UTA-2026-016** — Case 9 Operator-A GHOST customer at 77.110.96.200 (LOW 60%).
- **UTA-2026-017** — Case 9 Operator-B GHOST customer at 77.110.125.145 (LOW 55%).

Three additional cases (7, 8, 10) are classified **INSUFFICIENT** for attribution at the capsule depth captured. **No Tier-1 government attribution** applies to any operator in this campaign.

### For Technical Teams

- **Highest detection priority:** AI Operator Handoff Documents (Section 4.9.1), LLM-Personalized Credential Mutation prompts (Section 4.9.2), and operator-built unauthenticated Python-stdlib C2 endpoints (Section 4.9.5). The campaign-wide detection content (26 rules: 8 YARA, 12 Sigma, 6 Suricata) is in the linked detection file.
- **Highest hunt priority:** `/etc/ld.so.preload` modifications (Case 9 GHOST kit), `~/.gemini/` and `~/.rovodev/` and `~/.claude/settings.local.json` artifacts (Cases 1, 3, 4), and `tralalarkefe.com` subdomain DNS queries (Case 1).
- **Highest mitigation priority:** Block `*.kryptex.network` (Case 9 mining pool), block `tralalarkefe.com` (Case 1 C2), monitor outbound to `generativelanguage.googleapis.com` with body containing password-mutation prompt fragments (Case 1 LLM-Personalized Credential Mutation, Section 4.9.2).
- **Highest IR priority for confirmed infection:** Cases 9 (GHOST kit) and 1 (Russian A2A) ship persistence that survives standard remediation — see Section 10 for the risk and detection posture (no step-by-step procedures provided, see Section 12 for the response orientation block).

The Vova75Rus disposition outcome (GitHub T&S 2026-05-25) is the campaign's headline disruption: defenders should treat the upstream payload-distribution channel for the GHOST cryptojacker ecosystem as **temporarily** disrupted but expect re-hosting attempts. Section 9 details the cross-case attribution discipline applied (campaign coordination explicitly REFUTED) and the supply-chain context for ecosystem-level actor UnamSanctam (PUBLIC PERSONA, excluded from T&S disclosure scope).

For executives reading only this section: AI-augmented tradecraft is now demonstrably mainstream across unrelated cybercrime, espionage-adjacent, and DDoS-for-hire operators. The defender takeaway is not "block AI" — most observed operators would still be capable without AI — but rather **detect the AI-integration layer** because it produces distinctive, durable artifacts that hand defenders a previously-unavailable signal in their hunt.

---

## 2. Business Risk Assessment

### Understanding the Real-World Impact

This campaign matters to security leadership for three reasons that are not obvious from a single-operator view:

1. **AI-augmented tradecraft is now ecosystem-wide, not single-actor.** Eight independent operators using five different AI tools across four different motivations (financial cybercrime, state-aligned espionage, DDoS-for-hire, operator productivity) means the AI-misuse threat is **diffuse** — defenders should not expect a single vendor block or a single IOC sweep to address it.
2. **Existing detection coverage has a gap at the operator-side workflow layer.** Public reporting is well-supplied with AI-generated content signatures (phishing tone, malware code style). It is poorly supplied with operator-side AI artifacts (handoff documents, weaponized configurations, AI-integrated permission allowlists). This investigation's detection rules (26 in the linked detection file) target the previously-undersupplied layer.
3. **Named-victim impact is concrete.** Two confirmed victims (a US healthcare provider, the state-owned Turkish insurer) and one named-victim partner ecosystem (the victim organization's 5 visible partners: Ziraat Bank, TARSIM, SBM, DASK, edoksis.net) represent confirmed compromise outcomes, not hypothetical exposure.

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
<tr><td>State-aligned espionage data harvesting via insider recruitment</td><td>LOW–MODERATE</td><td>Case 2 insider-recruited Windows AD user [employee ID — suppressed] with operator-authored Turkish-language tunnel-setup documentation. Targeting model is sector-specific (Turkish state-owned insurance + financial-sector ecosystem) not generic.</td></tr>
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
<tr><td>Confirmed Victims</td><td>the healthcare victim (US healthcare, Case 1), the victim organization (Turkish state-owned insurer, Case 2)</td><td>DEFINITE</td></tr>
<tr><td>Named Threat Actors</td><td>Vova75Rus (Case 9 kit author, HIGH 88%)</td><td>HIGH</td></tr>
<tr><td>UTA Assignments</td><td>UTA-2026-012 through UTA-2026-017 (six assignments across Cases 1, 2, 3, 4, 9-A, 9-B)</td><td>Variable (LOW to high-MODERATE)</td></tr>
<tr><td>Tier-0 Disposition Outcome</td><td>GitHub T&S account-level action against Vova75Rus 2026-05-25 (all 9 repos HTTP 404)</td><td>DEFINITE</td></tr>
</tbody>
</table>

### Malware Families and Tooling Inventory

The campaign spans malware/tooling drawn from at least eight distinct families. Several families are commodity (Sliver, Mirai, Quasar-class); several are custom-built per-operator (Russian A2A C2, ARPA observability harvester). Operator-built tooling exhibits the cross-case **AI-Generated Offensive Code Structural Signature** documented in Section 4.9.

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

The single most important *campaign* attribute — the AI-tool integration layer — spans **five distinct AI-agent CLIs**, each used by a different operator. This vendor diversity is itself a campaign-defining finding because it refutes the "single AI vendor attack vector" framing:

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

Four of eight cases (Cases 2, 3, 9-A, 10) were observed active during the investigation window itself, which underscores that this is an ongoing campaign rather than retrospective analysis of historical artifacts.

---

## 4. Technical Capabilities Deep-Dive — Per Case

> **Analyst note:** This section is the technical heart of the report. Each of the 8 active operator cases gets its own sub-section with the same shape: hosting, AI tool, scale, key indicators, technical highlights, and defender takeaway. Cases 1, 2, 3, and 9 receive deeper coverage because they are the subjects of companion sub-reports (linked in Section 14.2); Case 4 also has a companion sub-report at capsule depth; Cases 7, 8, 10 are capsule-depth within this parent. After the per-case sub-sections, the five novel TTPs (cross-cutting findings) are documented separately, followed by the three-class AI threat-actor taxonomy and the false-positive discrimination block. Each case sub-section is self-contained — readers can skim a single case without losing the parent report's narrative.

### 4.1 Case 1 — Russian Gemini Credential-Mill Operator

> **Analyst note:** Case 1 is the campaign's most technically integrated AI-augmented operator and the source of two of the five novel TTPs (LLM-Personalized Credential Mutation and AI Operator Handoff Documents). This sub-section establishes the operator's full infrastructure footprint, victim impact (the healthcare victim), and the operator-built C2 server architecture. Detailed analysis is in the [Case 1 sub-report](/reports/russian-gemini-credential-mill-213.165.51.115/).

**Hosting:** 213.165.51.115 (AEZA Group AS210644 / AS211522 post-OFAC, Germany datacenter, Russian corporate). AEZA was OFAC-sanctioned July 2025 and meets 4 of 5 bulletproof-hosting indicators.

**AI Tool:** Gemini CLI (Google Gemini 2.5 Flash). Operator integrated AI across at least three workflow stages: credential mutation, code generation, persona management.

**Scale:** Mid-tier-selective. Operator targets selected victims (a US healthcare provider) rather than mass-scanning. Captured 40+ stolen Gemini Pro Preview API keys at filesystem level.

**Key Indicators:**

| Indicator | Type | Notes |
|---|---|---|
| `213.165.51.115` | IPv4 | Operator-controlled AEZA VPS |
| `tralalarkefe.com` | Domain | Operator-bespoke C2 domain, 5 named tunnel hostnames |
| `c2.tralalarkefe.com`, `payloads.tralalarkefe.com`, `catchall1.tralalarkefe.com`, `windows_server.tralalarkefe.com`, `gil_dr1.tralalarkefe.com` | Subdomain | Cloudflare Tunnel hostnames; `windows_server` and `gil_dr1` route to the healthcare victim machines |
| `tenant-upcoming-great-descending.trycloudflare.com` | Domain | Bootstrap tunnel (typical ephemeral *.trycloudflare.com pattern) |
| `sonner1337` | GitHub handle | Operator account |
| `ghp_tdcXTl...g4PDaRW` | GitHub PAT | Full-admin PAT captured (defanged to first-8 + last-4) |
| `@americanpatriotus` | Telegram | Co-located disinformation channel actively posted to via Gemini CLI |
| `quantum_patriot.py` | Filename | Disinformation operation artifact |
| `братух` | Operator persona string | Russian "bro" diminutive in GEMINI.md global memory file |
| `duty-free.cc` | Forum URL | Russian carding forum active operator |
| `antipublic.one` | Service | AntiPublic combolist subscription |

**Technical Highlights:**

1. **Operator-built unauthenticated Python-stdlib C2 server** (`~/arsenal/c2_server.py`). Uses `BaseHTTPServer` with **zero authentication** on five endpoints (`/api/v1/update`, `/api/v1/agents`, `/api/v1/interact`, `/api/v1/telemetry`, `/api/v1/get_results`) and a path-traversal-vulnerable file server. The `/api/v1/get_results` endpoint is called by the client implants but is **not implemented** in the captured backend — direct evidence of an incomplete in-place-developed build. This is one of the five novel TTPs (Section 4.9.5).

2. **LLM-Personalized Credential Mutation pipeline** (`~/arsenal/ai_sniper_brute.py`). Uses Gemini 2.5 Flash with the prompt "Act as an expert red-team password analyst..." to generate 20 per-target password mutations from `email + domain + last-known-password` triples. On-disk artifact `AI_ADMIN_MUTANTS.txt` is **5.5 MB**, evidence of at-scale use. This is the campaign's first DEFINITE evidence of LLM-Personalized Credential Mutation in active operations (Section 4.9.2).

3. **AI Operator Handoff Documents** (Section 4.9.1). Operator-authored documents intended for AI consumption: `C2_MIGRATION_GUIDE.md`, `C2_INFRA_TRANSFER.md` (explicit "To: Gemini CLI / From: Gemini CLI" header), `DEPLOYED_TOOLS.md`. This artifact class inverts the typical AI-generated-content data flow and is documented as a first-public-documentation candidate.

4. **Cloudflare Tunnel persistent C2 topology** under operator-owned domain `tralalarkefe.com`. Five named tunnel hostnames map operator services + victim machines into the operator's Cloudflare account. This is more durable than the typical `*.trycloudflare.com` ephemeral quick-tunnel abuse (Proofpoint Aug 2024; Securonix SERPENTINE#CLOUD) because the operator owns the domain and can re-bind tunnels across server migrations without alerting victims.

5. **Co-located disinformation operation.** `@americanpatriotus` Telegram channel and `quantum_patriot.py` script demonstrate that the same operator runs a credential-mill **and** a disinformation operation **and** uses Gemini CLI for both. This is uncommon attribution evidence: the same Gemini API key submits password-mutation prompts **and** patriotic-disinformation-content prompts.

**Defender Takeaway:** Block `tralalarkefe.com` and all 5 named subdomains at the DNS/perimeter layer. Monitor outbound HTTPS to `generativelanguage.googleapis.com` with body containing password-mutation prompt fragments ("red-team password analyst", "Output ONLY the 20 passwords"). Hunt for `~/.gemini/wrapper.sh` and `~/.gemini/skills/cf-c2-manager/SKILL.md` on Linux server estate. (Full analysis: [Case 1 sub-report](/reports/russian-gemini-credential-mill-213.165.51.115/).)

### 4.2 Case 2 — Turkish ARPA Observability-Harvester Operator

> **Analyst note:** Case 2 is the campaign's only operator with confirmed state-aligned-target profile and confirmed insider recruitment. The operator built a production-grade observability reverse-pipeline platform (ARPA) and used it to cross-correlate four stolen observability sources against a single named state-owned victim. This sub-section establishes the operator infrastructure, victim impact, the reverse-pipeline architecture, and the insider-recruitment artifact. Detailed analysis is in the [Case 2 sub-report](/reports/turkish-arpa-openclaw-state-insurer-209.38.205.158/).

**Hosting:** 209.38.205.158 (DigitalOcean AS14061, US datacenter). Operator origin: 31.223.97.87 (TurkNet AS12735, Turkish residential ISP — direct geographic anchor without VPN/Tor).

**AI Tool:** OpenClaw (open-source) integrated into ARPA platform pipeline. Code-generation signal (AI-Generated Code structural signature) DEFINITE across Python files in the operator's repository.

**Scale:** Advanced. Single confirmed victim (the state-owned Turkish insurer) with 73+ day patient dwell window. Five visible partner ecosystem entities (Ziraat Bank, TARSIM, SBM, DASK, edoksis.net e-invoicing) within victim's observability data.

**Key Indicators:**

| Indicator | Type | Notes |
|---|---|---|
| `209.38.205.158` | IPv4 | Operator ARPA platform host (DigitalOcean) |
| `31.223.97.87` | IPv4 | Operator residential origin (TurkNet) |
| `MehmetARPA` | GitHub handle | Possibly real-name Mehmet ARPA; public repo `github.com/MehmetARPA/ARPA`; **account suspended by GitHub T&S 2026-05-25** |
| `ARPA Korelasyon Motoru` | Brand string | Operator self-branding ("ARPA Correlation Engine") |
| `ARPA © 2026 the victim organization` | Brand string | In-platform footer |
| `arpa-instana-api.service`, `arpa-autolearn.service`, `arpa-continuous.service`, `arpa-daemon.service`, `arpa-parallel.service` | systemd units | Operator-deployed services |
| `/api/ingest/instana` | URI | Operator C2 ingestion endpoint at 209.38.205.158:8096 |
| `tenant: [victim-tenant]` | JWT claim | Stolen Instana JWT payload |
| `jti: 022a1b74-2332-4df5-a76b-60225ffa7ae3` | JWT ID | Specific stolen IBM Instana JWT (iat 2024-03-06, 10-year lifetime) |
| `[employee ID — suppressed]` | Windows AD user | Insider-recruited account at the victim organization |

**Technical Highlights:**

1. **Observability-Tool Reverse Pipeline** (Section 4.9.4). Operator's ARPA platform ingests four stolen observability sources — **IBM Instana** (43 applications, 50 services, 10-year JWT), **SolarWinds Orion** (784 nodes, 6,566 interfaces), **Zabbix** (100 hosts), **VMware Aria** — and cross-correlates them in a TimescaleDB+Neo4j+Redis stack against the named state-owned victim. Observability tools are typically modeled as data *destinations* by defenders, not as data *sources to protect*. This investigation flips the defender threat model.

2. **Operator-authored Turkish-language insider-recruitment documentation.** The operator authored five Turkish-language tunnel-setup documents in his arsenal directory: `GERCEK_API_BULUNDU.md` ("Real API Found"), `PUTTY_TUNNEL_DETAY.md` ("PuTTY Tunnel Details"), `SSH_KEY_COZUM.md` ("SSH Key Solution"), `TUNNEL_KONTROL.md` ("Tunnel Control"), `WINDOWS_VPN_TUNNEL.md`. These describe the insider workflow for an AD user ([employee ID — suppressed]) inside the victim organization to establish a reverse tunnel from the victim's internal network. This is direct documentary evidence of insider recruitment, which is uncommon in published threat reporting outside of state-attribution contexts.

3. **Operator's PowerShell observability-collector** (`turkish-instana_local_collector.ps1`). Authored in Turkish-language inline-comment style, embeds the stolen 10-year JWT as `apiToken ey...` in the Authorization header, polls Instana API for current state, exfiltrates to `/api/ingest/instana`. Captures the AI-Generated Code structural signature (verbose docstrings, defensive try/except, escalating-superlative variable names).

4. **5-source cross-correlation against single victim.** The investigation captured `unified_cross_source_topology.json` showing the operator's reconstructed topology of the victim organization's environment combining all four observability sources. This is a level of victim-side intelligence-gathering investment beyond typical opportunistic compromise — consistent with espionage tradecraft.

5. **Direct geographic anchor without VPN.** The operator accesses his DigitalOcean VPS from Turkish residential ISP TurkNet (AS12735) without VPN/Tor — a "operator-from-own-ISP" pattern typical of confident or under-resourced operators. Combined with the four other converging attribution axes (Turkish language, operator handle, self-branding, state-target), this places the operator inside Turkey with high-MODERATE confidence (78%, top of the MODERATE band approaching HIGH).

**Defender Takeaway:** Rotate any IBM Instana JWTs older than 1 year; monitor for `Authorization: apiToken eyJ*` patterns in PowerShell Script Block Logging Event 4104 from non-developer Windows hosts; monitor systemd unit creation matching `arpa-*.service`. Treat observability tokens as Tier-1 secrets equivalent to cloud-provider IAM credentials. (Full analysis: [Case 2 sub-report](/reports/turkish-arpa-openclaw-state-insurer-209.38.205.158/).)

### 4.3 Case 3 — Rovodev/Pandora Mirai Botnet Operator

> **Analyst note:** Case 3 is the campaign's exemplar of the Hybrid AI-augmented operator class: classic Mirai-family botnet tradecraft (lineage to 2016 source-code releases, downstream from Doctor Web's 2023 Android.Pandora disclosure) combined with Atlassian Rovodev AI for capability extension. The Rovodev session JSONs are the campaign's most direct primary-source evidence of AI authoring offensive code under operator natural-language direction. Detailed analysis is in the [Case 3 sub-report](/reports/rovodev-mirai-matrix-c2-87.106.143.220/).

**Hosting:** 87.106.143.220 (IONOS AS8560 Germany, primary operator host), 87.106.54.213 (IONOS AS8560, backup VPS), 80.211.94.16 + 80.211.111.10 (Aruba S.p.A. AS31034 Italy, Pandora distribution cluster), 165.227.175.161 (DigitalOcean AS14061, *compromised* GetYourGroup tourism VPS used as Naku CNC).

**AI Tool:** Atlassian Rovodev CLI (Atlassian Rovodev GA October 2025). `~/.rovodev/sessions/` directory captures operator's natural-language prompts.

**Scale:** Advanced. 11-architecture Mirai-family botnet. Dual HTTP/HTTPS distribution channel (HTTP:80 for Pandora campaign delivery via Aruba; HTTPS:443 for Naku build/test channel via IONOS). DDoS-for-hire model with 13 named attack methods.

**Key Indicators:**

| Indicator | Type | Notes |
|---|---|---|
| `87.106.143.220:1337` | IPv4:Port | Mirai C2 (TCP raw socket beacon) |
| `87.106.54.213` | IPv4 | Operator backup VPS |
| `80.211.94.16`, `80.211.111.10` | IPv4 | Aruba Italy distribution servers (port 80) |
| `165.227.175.161:23` | IPv4:Port | Naku.arm CNC on compromised GetYourGroup VPS (Telnet port masquerade) |
| `PandoraNet.{arm,arm5,arm6,arm7,mips,mipsel,sh4,spc,x86,x86_64,powerpc}` | Filename pattern | 11-architecture bot binaries |
| `/Pandoras_Box/` | URI path | Aruba distribution path |
| `/bins/Naku.{arch}` | URI path | IONOS Naku build/test path |
| `1gba4cdom53nhp12ei0kfj` | Random-string charset | Operator-bespoke 22-char Mirai-variant random-string charset |
| `udp-star`, `syn-storm`, `tcp-matrix`, `tcp-rst`, `udp-bypass`, `icmp-hell`, `multi-vector`, `http-flood`, `mass_infection`, `frag-storm`, `dns-rain`, `ovh-nuke`, `http-star` | Attack method names | Operator-defined DDoS attack methods |
| `INFECTED\|` | Bot registration prefix | Operator pipe-delimited registration format |
| `1441591352927326259` | Discord user ID | Operator ID baked into spec files (snowflake decoded 2025-11-22T00:49:22 UTC) |

**Technical Highlights:**

1. **Rovodev session JSONs as primary-source evidence.** `session_cron_a46703f0a3c4.json` and `session_interactive_b9d424.json` capture the operator's natural-language prompts to AI and the AI's `file_write` tool calls creating the attack framework code. This is the campaign's most direct primary-source evidence of AI authoring offensive code — readers see what the operator typed and what the AI produced, file-by-file.

2. **Operator-authored 22+ AI Operator Handoff Documents at `/root/matrix/`** with escalating-superlative naming (Section 4.9.1). Documents like `IMPLEMENTATION_PLAN.txt`, `whatineed.txt`, `MASTER_PLAN.md` direct the AI's session goals across multiple Rovodev runs. The escalating-superlative naming pattern (`PLAN.md` → `MASTER_PLAN.md` → `ULTIMATE_PLAN.md`) is one diagnostic criterion in the AI-Generated Code structural signature (Section 4.9.3).

3. **Pandora-Mirai variant lineage** (Doctor Web September 2023 disclosure). The Case 3 operator is a downstream adopter extending the original Android-TV-only 2023 Pandora scope to 11 IoT architectures — the first AI-co-authored Mirai deployment documented in public reporting.

4. **5-vector persistence chain** within seconds from same parent process: crontab + `/etc/rc.local` + `/etc/init.d/sysupdate` + `/etc/systemd/system/system-update.service` + `~/.bashrc` + `~/.profile`. This is conventional Mirai-family tradecraft; AI did not author it. Defender takeaway: detection must correlate these five vectors from one parent process within a tight time window.

5. **Naku.arm VT consensus.** VT detection 43/66 with Symantec/Kaspersky/Microsoft classifying as Mirai. Binary-level embedded distribution URL `http://80.211.94.16/Naku.mips` cryptographically links the IONOS operator to the Aruba Italy distribution cluster.

**Defender Takeaway:** Block `87.106.143.220:1337` and `165.227.175.161:23` at the perimeter; hunt for `~/.rovodev/sessions/` on Linux server estate; deploy auditd correlation rule for the 5-vector persistence chain. (Full analysis: [Case 3 sub-report](/reports/rovodev-mirai-matrix-c2-87.106.143.220/).)

### 4.4 Case 4 — Korean Claude+OpenClaw Operator (Capsule)

**Hosting:** 221.150.15.104 (Korea Telecom AS4766, direct operator residential exposure).

**AI Tool:** Claude Code + OpenClaw.

**Capsule-depth capture.** No filesystem extraction performed beyond the smoking-gun artifact.

**Key Indicator (smoking gun):** `~/.claude/settings.local.json` containing the operator-customized Claude Code permission allowlist with **pre-approved** commands:

```
Bash(curl -fsSL https://openclaw.ai/install.sh | bash)
Bash(npm i -g openclaw)
Bash(openclaw onboard)
Bash(openclaw gateway --port 18789)
```

**Technical Highlight:** This is the campaign's first DEFINITE artifact of an attacker-customized AI-tool installation chain — the operator pre-authorized Claude Code to execute a `curl ... | bash` installer for OpenClaw without per-execution prompts. The OpenClaw `gateway --port 18789` command opens a listening port on the operator's internal host.

**Defender Takeaway:** Hunt for `~/.claude/settings.local.json` modifications adding entries matching `Bash(curl ... | bash)` or `Bash(npm i -g <unfamiliar>)`. Block outbound HTTPS to `openclaw.ai` and `docs.openclaw.ai` from non-developer hosts. Inventory internal listening port 18789 across endpoint estate.

### 4.5 Case 9 — GHOST Cryptojacker Kit + 4-Tier Supply Chain

> **Analyst note:** Case 9 is the campaign's only sub-report subject with **named-actor HIGH attribution** (kit author Vova75Rus 88%) and the only sub-report where Tier-0 disposition outcome was achieved (GitHub T&S account-level action 2026-05-25). This sub-section establishes the four-tier supply chain, the multi-customer commodity kit signature (byte-identical libpam_cache.so), the LD_PRELOAD libc-hook rootkit architecture, the container-escape suite, and the Tier-0 outcome significance. Detailed analysis is in the [Case 9 sub-report](/reports/ghost-cryptojacker-vova75rus-77.110.96.200/).

**Hosting:** 77.110.96.200 (Operator-A AEZA AS210644), 77.110.125.145 (Operator-B AEZA sibling host). Both customer operators reside on AEZA bulletproof-adjacent provider.

**AI Tool:** N/A at customer operator level — the GHOST kit itself is operator-built, not AI-augmented. The kit-author (Vova75Rus) and the customer operators are *separate identities*.

**Scale:** Multi-tenant commodity kit. **Byte-identical `libpam_cache.so`** across both customer hosts (DEFINITE supply-chain root). Kit author Vova75Rus distributes per-customer builds with OWNER Telegram bot 8415540095 baked into every deployment.

**Key Indicators:**

| Indicator | Type | Notes |
|---|---|---|
| `77.110.96.200`, `77.110.125.145` | IPv4 | Operator-A and Operator-B AEZA hosts |
| `Vova75Rus` (UID `73169104`) | GitHub | Kit author; **account suspended by GitHub T&S 2026-05-25** |
| `296a800564111b0bad9fe63faf4e63ba` | MD5 | `libpam_cache.so` (byte-identical across both customer hosts) |
| `libpam_cache.so` | Filename | Family-level GHOST kit signature |
| `/etc/ld.so.preload`, `/lib/security/libpam_cache.so` | Path | LD_PRELOAD persistence locations |
| `~/.config/fontconfig/.cpu`, `~/.config/fontconfig/.gpu` | Path | Hidden miner binaries (xmrig, lolMiner) |
| `8415540095` | Telegram bot prefix | **OWNER bot** — kit-author Vova75Rus channel; baked into every customer deployment as supply-chain monitoring signature |
| `8315596543` | Telegram bot prefix | **MIRROR bot** — Operator-A's own channel |
| `4BBj3gj4` | Monero wallet prefix | Operator-A XMR wallet |
| `cfx:aaj5xb` | Conflux wallet prefix | Operator-A CFX wallet |
| `cfx.kryptex.network`, `etc.kryptex.network` | Mining pool | Kryptex (Operator-A self-hosted proxy at `77.110.96.200:3333`) |
| `auto.c3pool.org`, `cfx-asia1.nanopool.org` | Mining pool | Public pools (Operator-B lower-OPSEC tier) |
| `Vova75Rus/ComfyUI-Shell-Executor`, `jamestechdev-oss/ComfyUI-Shell-Plugin` | GitHub repo | Kit-author payload distribution channels (now HTTP 404) |

**Technical Highlights:**

1. **4-tier supply chain fully mapped** — first defender-published artifact-grounded mapping of the GHOST cryptojacker ecosystem. The chain runs:

   **Tier 0 (upstream OSS supplier):** UnamSanctam (5+ year GitHub history, 860 followers, supplies UnamWebPanel + SilentCryptoMiner since 2014). PUBLIC PERSONA — documented as supply-chain context only; NOT treated as a threat actor for this campaign (public-persona supply-chain context treatment applied throughout the investigation; UnamSanctam is outside T&S disclosure scope).

   **Tier 1 (kit author):** Vova75Rus (UID 73169104, Zabaykalsky Krai Russia probable). Distributes per-customer builds with OWNER Telegram bot baked into each deployment.

   **Tier 2 (customer operators):** Operator-A (77.110.96.200, higher-OPSEC tier with self-hosted XMR + CFX pool proxies) and Operator-B (77.110.125.145, lower-OPSEC tier using public pools, host abandoned).

   **Tier 3 (victims):** 4,573-entry ComfyUI victim scan list extracted from Operator-B's classifier pipeline; ~78 high-confidence victim IPs flagged to Tier-1 cloud providers (Alibaba 9, DigitalOcean 3, Hetzner 3, Azure 2, AWS 2; remaining tier breakdown in the disclosure cascade documentation).

2. **LD_PRELOAD libc-hook rootkit architecture.** `libpam_cache.so` hooks libc functions (`readdir`, `readdir64`, `fopen`, `fopen64`, `open`, `open64`, `stat`, `lstat`, `stat64`, `lstat64`) via `dlsym(RTLD_NEXT, ...)` to hide processes, files, and directories matching a baked-in hide-string array: `xmrig`, `lolMiner`, `khugepaged_`, `fontconfig/.cpu`, `fontconfig/.gpu`, `.pid_cpu`, `.pid_gpu`, `.pid_guard`, `inotify_guard`, `.spread_*`. The constructor calls `unsetenv("LD_PRELOAD")` to prevent child processes from inheriting the preload (anti-detection during forensic enumeration).

3. **Container escape suite — 4 variants.** Function names captured: `_escape_via_cgroup`, `_escape_via_mount`, `_escape_via_nsenter`, `_escape_via_socket`. Targets Docker/k8s/LXC cloud GPU environments specifically. This is consistent with the campaign's ML/AI infrastructure target profile (ComfyUI as primary victim platform).

4. **ComfyUI fake-node persistence.** GHOST kit injects fake ComfyUI custom nodes named `PerformanceMonitor` and `GPU Performance Monitor` to maintain persistence on AI/ML platforms even after system reimaging — the fake nodes load on next ComfyUI start.

5. **Hysteria v2 backdoor with bing.com SNI masquerade.** Operator-A deploys Hysteria v2 (QUIC-based proxy) listening on UDP 14433/14444 with TLS SNI set to `bing.com`. Detection requires combined-condition rule (port + SNI + protocol) because Hysteria v2 traffic alone is not malicious.

6. **Tier-0 disposition outcome (2026-05-25).** GitHub Trust & Safety took **account-level action** against Vova75Rus (UID 73169104). All 9 repositories return HTTP 404. This is the strongest possible Tier-0 disposition for an upstream supply-chain actor — one disclosure batch disrupted the entire upstream payload-distribution channel of the GHOST ecosystem. Wayback Machine snapshots at `web.archive.org/web/20260525020*/` are the canonical pre-takedown evidence record. Defenders should expect re-hosting attempts and monitor for new Vova75Rus-pattern accounts.

7. **Anti-Hisana defense (in-kit).** The GHOST kit codebase contains explicit `_anti_hisana` defenses — kit author was actively countering "Hisana", a known anti-cryptojacker tool. This level of in-kit counter-tooling indicates a mature commercial-grade kit author rather than a hobbyist.

**Defender Takeaway:** Block `cfx.kryptex.network` and `etc.kryptex.network` at DNS layer; hunt for `/etc/ld.so.preload` modifications on Linux estate; hunt for `/lib/security/libpam_*.so` filenames not in the known-good PAM-module list; monitor egress to operator-hidden ports 3333, 4444, 5555, 7777, 8027, 8029, 9999, 14433, 14444 from `$HOME_NET`. (Full analysis: [Case 9 sub-report](/reports/ghost-cryptojacker-vova75rus-77.110.96.200/).)

### 4.6 Case 7 — Productivity-AI Stack (Capsule)

**Hosting:** 139.59.239.112 (DigitalOcean AS14061).

**AI Tool:** Claude Code (inferred from co-located Claude session artifacts).

**Capsule-depth capture.** No filesystem extraction beyond surface-level artifact inventory.

**Technical Highlights:**

1. **Post-compromise productivity stack** combining classic operator tools (Weevely PHP backdoor, frp reverse proxy) with Claude Code for operator workflow assistance.
2. **No novel TTP** at the AI-integration layer — Claude is used by the operator for personal productivity (planning, documentation, scripting assistance) rather than as a core offensive component.
3. **Operator-class signal:** AI-integrated mature operator who uses AI for workflow efficiency rather than capability extension.

**Defender Takeaway:** This is the campaign's most representative example of the **AI-integrated mature operator** class (Section 4.10). The operator does not need AI to operate — it improves productivity, not capability. No specific perimeter or hunt rule is published for this case beyond generic Weevely/frp signatures already in public detection catalogs.

### 4.7 Case 8 — AI-Orchestrated 60-Second Payment-API Attack (Capsule)

**Hosting:** 68.183.92.28 (DigitalOcean AS14061).

**AI Tool:** Unspecified LLM (mechanism unknown).

**Capsule-depth capture.** Insufficient artifact depth to identify which LLM vendor was orchestrated or what the orchestration mechanism was.

**Technical Highlights:**

1. **60-second multi-stage payment API attack** observed in operator's session artifacts — operator used an LLM to orchestrate a rapid 4-stage attack chain (recon → enumerate → exploit → exfiltrate) against a payment API endpoint within a 60-second window.
2. **No LLM vendor identification.** INSUFFICIENT evidence to identify the vendor (Gemini, Claude, GPT, and self-hosted models all remain candidates) — the orchestration mechanism is not preserved in captured artifacts.
3. **Pattern significance:** This is the campaign's most novel-on-its-face TTP (AI orchestrating multi-stage attack chains at sub-minute timescale) but is **INSUFFICIENT** for confident publication beyond capsule depth.

**Defender Takeaway:** Treat any sub-minute multi-stage authenticated-API attack chain as a candidate for AI-orchestrated tradecraft. Defenders should specifically baseline API endpoint traffic for "burst" patterns (4+ distinct API surfaces accessed by same source IP within 60 seconds) — this is a candidate signal for AI-orchestrated attacks that would not appear with human-paced operator tradecraft.

### 4.8 Case 10 — Sliver-Derivative C2 Staging (Capsule)

> **Analyst note:** Case 10 captures an operator at the *pre-victim staging phase* — Sliver C2 infrastructure deployed with crypter tooling and iterative loader development, but zero victim beacons in the database at capture time. This is rare visibility: most reporting catches Sliver-derivative operators post-compromise. The artifacts here document operator tradecraft choices (default elite port, Cursor IDE for development, Fernet payload encryption, rapid loader iteration v30→v39 in one day) that defenders can hunt for *before* victim impact occurs.

**Hosting:** 5.230.201.54 (AS200051 NL, registered to individual "Rizki Abdul Azis" — atypical for legitimate provider).

**AI Tool:** Cursor IDE (HIGH confidence from co-located binaries; not DEFINITE from session transcripts).

**Capsule-depth capture.** Pre-victim staging phase — zero sessions / zero beacons in captured Sliver database.

**Key Indicators Summary:** The Case 10 indicator set spans Sliver C2 endpoints (default elite port `31337`, HTTP staging on `:8080` for encrypted implant + decryption key, operator keylogger API `/api/v/keylog`, MJPEG video stream on `:9093`), operator crypter artifacts (`class SliverCrypter` Python signature, default Fernet output filenames `encrypted_payload.bin` / `decryption_key.txt`, crypter input `implant-win-x86.exe`, drop name `svchost_upd.exe` in `%TEMP%`), rapid loader iteration footprint (`loader_v30.ps1` → `loader_v39.ps1` and `screencap_v4.ps1` → `screencap_v11.ps1` within a single day), and a broad Sliver-population JARM fingerprint (`3fd3fd20d00000021c43d43d00043d204204071741c36579e355f830d285a5`) that requires combination with other signals to discriminate from the wider Sliver population. Structured indicators with full context (confidence, action, first/last seen) are published in the IOC feed: [`/ioc-feeds/ai-agent-frameworks-2026-05-23-iocs.json`](https://the-hunters-ledger.com/ioc-feeds/ai-agent-frameworks-2026-05-23-iocs.json). See Section 8 (Indicators of Compromise) for the full per-case inventory.

**Technical Highlights:**

1. **Active development, non-functional C2 server.** Loader iterations v30→v39 in a single day; screencap iterations v4→v11. However, static analysis of the Sliver database (`sliver.db`, 483 KB) revealed **zero sessions, zero beacons, zero loot, and zero registered implant builds** — the operator had zero victim connections at capture time. The Sliver server itself failed to start due to a persistent port `:31337` conflict unresolved across at least 15 days. The operator's 60 recorded asciinema client sessions indicate practice/learning activity, not active victim engagement. Case 10 is **pre-victim staging**, not an active-compromise capture.
2. **Commodity Fernet+zlib+b64 Python crypter.** The operator's payload staging uses a Python `SliverCrypter` class wrapping Fernet symmetric encryption → zlib compression → base64 encoding, with the PowerShell loader applying a single-XOR layer over the Fernet output. An initial Phase 8 assessment characterized the payload as "triple-layer RC4 → Rolling XOR → RC4 with embedded key `finalpayloadlayerkey987`" — this was **definitively refuted** by Phase 15 static RE (zero `finalpayloadlayerkey987` matches across 456 triage artifacts; actual payload staging confirmed as Fernet-based). The crypter is commodity; the C2 plumbing is commodity Sliver. The operator's distinguishing tradecraft is the development-tempo and pre-staging artifact visibility, not encryption novelty.
3. **PyInstaller-stub deployment** with `creationflags=0x08000000` (CREATE_NO_WINDOW) for stealth execution.
4. **AS200051 ownership unclear.** Registered to individual "Rizki Abdul Azis" — atypical for legitimate provider.

**Defender Takeaway:** Block `5.230.201.54` at perimeter; monitor for JARM matches combined with other Sliver signals; baseline `%TEMP%\svchost_upd.exe` filename across Windows estate. (Capsule depth — no sub-report planned for Case 10.)

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

  Plus visibility into 5 partner ecosystem entities (Ziraat Bank, TARSIM, SBM, DASK, edoksis.net e-invoicing). The operator's `unified_cross_source_topology.json` is the captured reconstruction.

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

> **Analyst note:** Because this is a multi-actor campaign rather than a single-sample analysis, the static analysis findings span multiple binaries and scripts across multiple operators. This section summarizes the cross-case static analysis at a synthesis depth appropriate for the parent report. Per-sample deep static analysis is in the companion sub-reports (linked in Section 14.2). Two static-analysis findings are publication-defining: (a) the byte-identical `libpam_cache.so` across Case 9 customer hosts (DEFINITE supply-chain root), and (b) the 13-criteria AI-Generated Code structural signature applied across 3 operators in Cases 1, 2, 3.

### 5.1 Static Analysis Highlights by Case

**Case 1 (Russian Gemini):**

- **`russian-ai_sniper_brute.py`** (Python source). Static analysis reveals: (a) Gemini API client initialization with hardcoded model `gemini-2.5-flash`, (b) prompt template literal `"Act as an expert red-team password analyst..."`, (c) per-target context assembly from `email + domain + last-known-password`, (d) 20-mutation output format, (e) helper-function explosion consistent with the AI-Generated Code structural signature.

- **`~/arsenal/c2_server.py`** (Python source). Static analysis reveals: (a) `BaseHTTPServer` import and use, (b) 5 unauthenticated API endpoints in URI router, (c) `os.path.join(BASE_DIR, request.path)` pattern enabling path traversal, (d) `/api/v1/get_results` endpoint referenced by clients but missing in server handler dispatch, (e) `A2A C2 MULTI-AGENT CONSOLE` banner string.

- **`russian-C2_MIGRATION_GUIDE.md`** (Markdown source). Static analysis reveals: AI Operator Handoff Document structure with goal statements, status tracking, explicit AI-agent address header.

**Case 2 (Turkish ARPA):**

- **`turkish-instana_local_collector.ps1`** (PowerShell source). Static analysis reveals: (a) hardcoded `apiToken ey...` Authorization header (stolen Instana JWT), (b) Turkish-language inline comments, (c) Invoke-RestMethod with `-SkipCertificateCheck`, (d) verbose docstrings on trivial functions (AI-Generated Code structural signature).

- **ARPA Python codebase.** Static analysis confirms the AI-Generated Code structural signature across multiple files. Code-generation signal DEFINITE.

**Case 3 (Rovodev/Pandora):**

- **`rovodev-mirai_clone.py`, `rovodev-persistent_bot.sh`, `rovodev-web_scraper_bot.py`** — operator-built attack framework. Static analysis confirms: (a) Mirai-family lineage (string overlap with public Mirai variants), (b) AI-Generated Code structural signature ≥11/13 criteria, (c) operator-defined attack method names (`udp-star`, `syn-storm`, etc.) embedded as enum values.

- **`Naku.arm` (compiled ARM ELF binary).** Static analysis: VT detection 43/66 confirms Mirai-family attribution; embedded distribution URL `http://80.211.94.16/Naku.mips` (binary-level cryptographic link); 22-char random-string charset `1gba4cdom53nhp12ei0kfj` matches operator-bespoke convention.

**Case 9 (GHOST kit):**

- **`libpam_cache.so` (ELF shared object, x86_64).** MD5 `296a800564111b0bad9fe63faf4e63ba`. Static analysis: (a) **byte-identical** across Operator-A and Operator-B hosts (DEFINITE supply-chain root); (b) ELF dynamic symbol exports include the libc-hook function set (`readdir`, `readdir64`, `fopen`, `fopen64`, `open`, `open64`, `stat`, `lstat`, `stat64`, `lstat64`); (c) baked-in hide-string array as static byte sequence; (d) constructor function calls `unsetenv("LD_PRELOAD")` (child-process anti-detection); (e) `dlsym(RTLD_NEXT, ...)` calls for each hooked function.

- **`libpam_cache.c` (operator-source from Operator-A host).** Confirms (a)-(e) above at source-code level. Confirms `_compile_hide_so`, `_anti_hisana`, `_container_escape`, `_escape_via_cgroup`, `_escape_via_mount`, `_escape_via_nsenter`, `_escape_via_socket` functions. Source comments include the GHOST kit branding string `GHOST v5.1`.

- **`ghost_77_110_125_145.sh`, `hyst.sh`, `min1.sh`, `check_comfyui.sh`** — operator deployment scripts. Static analysis: (a) Telegram bot tokens baked in (OWNER 8415540095 + MIRROR 8315596543 for Operator-A; OWNER only for Operator-B), (b) wallet addresses prefix-matched (`4BBj3gj4` for Operator-A XMR; `cfx:aaj5xb` for Operator-A CFX), (c) mining-pool DNS strings (`cfx.kryptex.network`, `etc.kryptex.network`).

**Case 10 (Sliver):**

- **`encrypted_v2.b64` + `decryption_key.txt`** — staged Fernet-encrypted Sliver implant. Static analysis: (a) Fernet token format (base64-encoded), (b) decryption key file separately accessible, (c) decryption produces a PyInstaller stub `.exe` consistent with Sliver implant deployment.

- **`loader_v30.ps1` through `loader_v39.ps1`** — PowerShell loader iterations. Static analysis: (a) version-tagged variant series across 1-day window (active development tempo), (b) `class SliverCrypter` Python class signature in companion crypter, (c) `creationflags=0x08000000` CREATE_NO_WINDOW flag in subprocess.Popen calls.

### 5.2 Cross-Case AI-Generated Code Static Signature (13-Criteria Diagnostic)

Static analysis applied the 13-criteria diagnostic checklist to Python files across Cases 1, 2, 3. Aggregate results:

| Operator | Files Examined | Mean Criteria Match | Verdict |
|---|---|---|---|
| Case 1 (Russian Gemini) | 5 Python files | 10.4 / 13 | DEFINITE AI-co-authored |
| Case 2 (Turkish ARPA) | 7 Python files | 9.6 / 13 | DEFINITE AI-co-authored |
| Case 3 (Rovodev) | 4 Python files | 11.2 / 13 | DEFINITE AI-co-authored |

Cross-operator validation across three different AI tools (Gemini CLI, OpenClaw, Atlassian Rovodev) confirms the signature is **AI-class-level** rather than **vendor-specific**. Defender takeaway: a single 13-criteria YARA rule covers code-generation from any current AI-agent CLI.

---

## 6. Dynamic Analysis Findings

> **Analyst note:** Dynamic analysis spans operator-server-side behavior captured via filesystem extraction and session-state inspection — not detonation of a malware sample. The campaign's investigation methodology is open-directory hunt + multi-source filesystem pull rather than sandbox detonation, so this section documents operator workflows chronologically rather than runtime malware behavior. Two dynamic-analysis findings are publication-defining: (a) the Rovodev session JSONs that capture AI-authoring offensive code at primary-source level (Case 3), and (b) the multi-source observability ingestion timing on the ARPA platform (Case 2).

### 6.1 Case 1 — Russian Gemini Credential-Mill Operator (Dynamic)

**Chronological operator workflow:**

- **T+0 (session start):** Operator launches Gemini CLI with `~/.gemini/wrapper.sh` script. `~/.gemini/skills/cf-c2-manager/SKILL.md` loads as the active skill.
- **T+1 (context loading):** Operator reads `GEMINI.md` global memory file with persona priming (`братух` Russian-language register). Gemini CLI initializes with operator persona.
- **T+2 (target loading):** Operator loads target list from `AI_SNIPER_GOODS.txt` into the credential-mutation pipeline.
- **T+3 (per-target mutation):** For each target row (`email`, `domain`, `last-known-password`), `ai_sniper_brute.py` submits a Gemini 2.5 Flash API call with the prompt template and receives 20 mutation candidates. Output written to `AI_ADMIN_MUTANTS.txt` (cumulative output file, 5.5 MB on disk).
- **T+4 (credential testing):** Operator runs `check_keys.py` against the mutation candidates. Successful auths logged.
- **T+5 (C2 deployment):** Operator deploys successful access to `c2_server.py` running on the operator host. Implants check in via Cloudflare Tunnel hostnames (`c2.tralalarkefe.com`, `payloads.tralalarkefe.com`).
- **T+6 (victim interaction):** Operator interacts with the healthcare victim machines via `windows_server.tralalarkefe.com` (SSH to localhost:2222) and `gil_dr1.tralalarkefe.com` (RDP).
- **T+7 (cross-operation):** Same operator session pivots to `quantum_patriot.py` for disinformation content generation, submitting different prompts to the same Gemini API key (`@americanpatriotus` Telegram channel content).

**Network activity in chronological order:**

1. Outbound HTTPS to `generativelanguage.googleapis.com` (Gemini API calls, password mutations + persona/disinfo prompts).
2. Outbound HTTPS to Cloudflare edge (`*.cloudflare.com`) for tunnel maintenance.
3. Outbound HTTPS to `*.trycloudflare.com` bootstrap tunnel.
4. Outbound to operator-owned `tralalarkefe.com` subdomains for victim interaction (proxied through Cloudflare).
5. Outbound HTTPS to GitHub API (`api.github.com`) using captured PAT.
6. Outbound HTTPS to Telegram API (`api.telegram.org`) for `@americanpatriotus` content posting.

### 6.2 Case 2 — Turkish ARPA Operator (Dynamic)

**Chronological operator workflow:**

- **T+0 (insider workflow setup):** Operator authors Turkish-language tunnel-setup documents (`PUTTY_TUNNEL_DETAY.md`, `WINDOWS_VPN_TUNNEL.md`, `SSH_KEY_COZUM.md`) for AD user [employee ID — suppressed] inside the victim organization.
- **T+1 (token capture):** Insider provides stolen IBM Instana JWT (10-year, iat 2024-03-06) to operator. JWT payload contains `tenant: [victim-tenant]` and `jti: 022a1b74-2332-4df5-a76b-60225ffa7ae3`.
- **T+2 (ingestion pipeline):** Operator starts ARPA platform systemd units (`arpa-instana-api.service`, `arpa-autolearn.service`, `arpa-continuous.service`, `arpa-daemon.service`, `arpa-parallel.service`). TimescaleDB + Neo4j + Redis stack initializes.
- **T+3 (first ingestion cycle):** `turkish-instana_local_collector.ps1` runs on insider's host with stolen JWT in `Authorization: apiToken ey...` header, polls Instana API, exfiltrates to `http://209.38.205.158:8096/api/ingest/instana`.
- **T+4 (cross-source ingestion):** Operator runs equivalent collectors for SolarWinds Orion (784 nodes), Zabbix (100 hosts), VMware Aria. All ingested into ARPA platform.
- **T+5 (correlation):** ARPA platform cross-correlates all 4 sources, building unified topology in Neo4j. `unified_cross_source_topology.json` is the captured output.
- **T+6 (dashboard live):** Operator views the reconstructed victim organization topology via ARPA dashboard at the operator's residential origin (TurkNet 31.223.97.87).
- **T+7 (daily refresh):** Daily ingestion cycle runs through 2026-05-23 (last operator fetch: 2026-03-13T04:35:01 for Instana, 2026-03-13T04:15:00 for SolarWinds, dashboard live 2026-05-24 indicating ongoing platform operation).

**Network activity in chronological order:**

1. Insider-side: PowerShell on Windows host with `Invoke-RestMethod -SkipCertificateCheck` to Instana, SolarWinds, Zabbix, VMware Aria APIs.
2. Outbound from insider host to `http://209.38.205.158:8096/api/ingest/<source>` URI patterns.
3. Operator-side: HTTPS from `31.223.97.87` (TurkNet residential) to ARPA dashboard at `209.38.205.158`.
4. Operator workflow includes OpenClaw `gateway` operations on the ARPA platform host.

### 6.3 Case 3 — Rovodev/Pandora Operator (Dynamic)

**Chronological operator workflow (as captured in Rovodev session JSONs):**

- **T+0 (session start):** Operator launches Atlassian Rovodev CLI with cron-scheduled session (`session_cron_a46703f0a3c4.json`) and interactive session (`session_interactive_b9d424.json`).
- **T+1 (operator prompt):** Operator types natural-language requests to AI (captured verbatim in session JSON). Example prompt patterns: "Create a multi-vector attack agent that..." and "I need a mass infection script with UDP, SYN, TCP, ICMP attack methods".
- **T+2 (AI file_write calls):** Rovodev's `file_write` tool is invoked by the AI to create framework files: `master_control.py`, `attack_engine.py`, `multi_vector_agent.py`, `web_scraper_bot.py`, `persistent_bot.sh`. Each file is captured verbatim in the session JSON's tool-call history.
- **T+3 (testing):** Operator runs the AI-authored framework against test targets. Bot binaries built for 11 architectures (`PandoraNet.arm`, `PandoraNet.arm5`, ..., `PandoraNet.x86`).
- **T+4 (distribution):** Operator stages binaries on dual distribution channels:
  - **HTTPS:443 IONOS channel:** `87.106.143.220/bins/Naku.<arch>` (build/test channel)
  - **HTTP:80 Aruba channel:** `80.211.94.16/Pandoras_Box/pandora.<arch>` and `80.211.111.10/Pandoras_Box/pandora.<arch>` (campaign delivery channel)
- **T+5 (victim recruitment):** Bots scan IoT/embedded targets, exploit, deploy `wget`/`curl` of distribution URL.
- **T+6 (persistence chain):** Within seconds of execution, the bot establishes 5-vector persistence: `crontab` + `/etc/rc.local` + `/etc/init.d/sysupdate` + `/etc/systemd/system/system-update.service` + `~/.bashrc` + `~/.profile` (all from the same parent process).
- **T+7 (C2 registration):** Bot beacons to `87.106.143.220:1337` with JSON `{"type":"bot_register","ip":...,"bot_type":"iot",...}` registration. Pipe-delimited `INFECTED|<ip>|<arch>|<methods>` operator status update.
- **T+8 (Naku.arm CNC):** Subset of bots beacon to `165.227.175.161:23` (compromised GetYourGroup VPS, Telnet port masquerade).
- **T+9 (DDoS dispatch):** Operator dispatches DDoS commands via Discord (operator ID `1441591352927326259`). 13 attack methods available to operator (`udp-star`, `syn-storm`, etc.).

### 6.4 Case 9 — GHOST Kit Deployment (Dynamic)

**Chronological deployment workflow:**

- **T+0 (kit pull):** Customer operator pulls `libpam_cache.so` from Vova75Rus upstream (now HTTP 404 post-T&S action; was previously `Vova75Rus/ComfyUI-Shell-Executor` repo).
- **T+1 (kit customization):** Customer operator builds per-customer instance with their own wallet addresses (Operator-A `4BBj3gj4...` XMR + `cfx:aaj5xb...` CFX; Operator-B `46a5osg...` XMR + `cfx:aat5y...` CFX). OWNER Telegram bot 8415540095 (Vova75Rus channel) baked in unchanged; MIRROR bot is operator-specific (Operator-A `8315596543`; Operator-B omitted).
- **T+2 (deployment to victim):** `ghost.sh` runs on victim cloud GPU host (typically ComfyUI ML platform). Writes `/etc/ld.so.preload` containing `/lib/security/libpam_cache.so`. Writes `libpam_cache.so` to `/lib/security/`.
- **T+3 (libc hook activation):** On next process start, LD_PRELOAD loads `libpam_cache.so` first. Constructor runs, calls `unsetenv("LD_PRELOAD")` to prevent child inheritance, registers `dlsym(RTLD_NEXT, ...)` hooks for libc enumeration functions.
- **T+4 (miner deployment):** `min1.sh` deploys hidden miners to `~/.config/fontconfig/.cpu` (xmrig) and `~/.config/fontconfig/.gpu` (lolMiner). PID lock files at `.pid_cpu`, `.pid_gpu`, `.pid_guard`. All filenames in the LD_PRELOAD hide-string array.
- **T+5 (Hysteria v2 backdoor):** `hyst.sh` deploys Hysteria v2 QUIC proxy on UDP 14433/14444 with TLS SNI `bing.com`.
- **T+6 (ComfyUI fake-node persistence):** Fake ComfyUI custom nodes (`PerformanceMonitor`, `GPU Performance Monitor`) installed for persistence even after reimage.
- **T+7 (mining begins):** xmrig connects to `cfx.kryptex.network` (Operator-A self-hosted proxy at `77.110.96.200:3333` for Operator-A; `auto.c3pool.org` for Operator-B). lolMiner connects to `etc.kryptex.network` (Operator-A) or `cfx-asia1.nanopool.org` (Operator-B).
- **T+8 (Telegram callbacks):** Every deployment phones home to OWNER Telegram bot 8415540095 (kit-author Vova75Rus channel) for supply-chain monitoring. Operator-A additionally calls MIRROR bot 8315596543 for own-monitoring.
- **T+9 (lateral movement, if container):** Container-escape suite (`_escape_via_cgroup`, `_escape_via_mount`, `_escape_via_nsenter`, `_escape_via_socket`) attempts host escape for Docker/k8s/LXC environments.

**Network activity in chronological order:**

1. Outbound HTTPS to Vova75Rus GitHub (pre-T&S, now HTTP 404).
2. Outbound to OWNER Telegram bot 8415540095 (HTTPS to `api.telegram.org/bot8415540095:*`).
3. Outbound TCP to mining pools (Operator-A: self-hosted at `77.110.96.200:3333` and `:4444`; Operator-B: public pools).
4. Outbound UDP/QUIC to Hysteria v2 (combined-condition: UDP 14433/14444 + TLS SNI `bing.com`).
5. (Operator-A only) Outbound HTTPS to MIRROR Telegram bot 8315596543.

---

## 7. MITRE ATT&CK Mapping

> **Confidence note:** all rows below are HIGH confidence unless explicitly marked `(MODERATE)` or `(DEFINITE)`. Three rows carry DEFINITE because the evidence is direct primary observation with zero ambiguity. The Confidence Levels Summary in Section 11 organizes findings by confidence level for the higher-level view.

The campaign maps to **49+ MITRE ATT&CK techniques** spanning 11 tactics. The mapping below presents the highest-impact and most-distinctive techniques per tactic; the linked detection file contains the full per-rule MITRE coverage. Because this is a multi-actor campaign, individual techniques span one case or multiple cases — the Evidence cell records the case attribution for each row.

| Tactic / Technique | Name | Evidence |
|---|---|---|
| Resource Development / T1583.003 | Virtual Private Server | AEZA (Cases 1, 9), DigitalOcean (Cases 2, 7, 8), IONOS (Case 3), AS200051 (Case 10), Korea Telecom (Case 4) |
| Resource Development / T1583.004 | Server (Compromised, Repurposed) | Case 3 - `165.227.175.161` GetYourGroup VPS as Naku CNC |
| Resource Development / T1583.006 | Web Services (Cloudflare Tunnel) | Case 1 - 5 named `tralalarkefe.com` subdomains + bootstrap `*.trycloudflare.com` |
| Resource Development / T1587 | Develop Capabilities | Case 1 `c2_server.py`; Case 2 ARPA platform; Case 3 Rovodev-authored Python framework |
| Resource Development / T1588.001 | Malware (Obtain) | Case 9 GHOST kit (Vova75Rus); Case 10 Sliver framework |
| Resource Development / T1588.002 | Tool (Obtain) | Case 7 Weevely + frp; Case 9 xmrig, lolMiner, Hysteria v2 |
| Initial Access / T1078 | Valid Accounts | Case 1 stolen credentials + harvested LLM API keys; Case 2 stolen Instana JWT (10-year) |
| Initial Access / T1199 | Trusted Relationship | Case 2 - insider-recruited Windows AD user [employee ID — suppressed] |
| Initial Access / T1190 | Exploit Public-Facing Application | Case 9 - ComfyUI exposed nodes (4,573-entry victim scan list) |
| Initial Access / T1133 | External Remote Services | Case 1 the healthcare victim persistent RDP+SSH via Cloudflare Tunnel |
| Credential Access / T1110.003 | Password Spraying | Case 1 - LLM-Personalized Credential Mutation pipeline (`ai_sniper_brute.py` + 5.5 MB `AI_ADMIN_MUTANTS.txt`) (DEFINITE) |
| Credential Access / T1003.002 | SAM | Case 1 - PowerShell agent chain target |
| Credential Access / T1555 | Credentials from Password Stores | Case 1 - browser credential theft via Quasar-class PowerShell agent |
| Credential Access / T1056.001 | Keylogging | Case 10 - `GetAsyncKeyState` polling loop + `/api/v/keylog` endpoint |
| Credential Access / T1552.001 | Credentials in Files | Case 1 - 40+ Gemini Pro API keys harvested from operator host scans |
| Credential Access / T1539 | Steal Web Session Cookie | Case 2 - 10-year IBM Instana JWT theft |
| Execution / T1059.001 | PowerShell | Case 2 `turkish-instana_local_collector.ps1`; Case 10 loader_v30-v39.ps1 |
| Execution / T1059.003 | Windows Command Shell | Cross-case Windows endpoint execution |
| Execution / T1059.004 | Unix Shell | Case 3 `bot.sh`; Case 9 `ghost.sh`, `hyst.sh`, `min1.sh` |
| Execution / T1059.006 | Python | Cases 1, 2, 3 - all AI-co-authored framework code |
| Execution / T1059.007 | JavaScript | Case 9 ComfyUI fake-node persistence |
| Execution / T1204.002 | User Execution: Malicious File | Case 3 - victim runs `wget`/`curl` of Pandora binary |
| Execution / T1569.002 | Service Execution | Case 2 - `arpa-*.service` systemd units |
| Persistence / T1053.003 | Cron | Case 3 5-vector persistence chain (component 1 of 5) |
| Persistence / T1547.013 | XDG Autostart Entries | Case 3 5-vector chain |
| Persistence / T1037.004 | RC Scripts | Case 3 - `/etc/rc.local` modification (component 2 of 5) |
| Persistence / T1543.002 | Systemd Service | Case 3 - `/etc/systemd/system/system-update.service` (component 4); Case 9 - operator deployment scripts |
| Persistence / T1574.006 | Dynamic Linker Hijacking | Case 9 - `/etc/ld.so.preload` + `libpam_cache.so` LD_PRELOAD libc-hook rootkit (DEFINITE) |
| Persistence / T1546.004 | Unix Shell Configuration Modification | Case 3 5-vector chain - `~/.bashrc`, `~/.profile` (component 5) |
| Privilege Escalation / T1611 | Escape to Host | Case 9 - container-escape suite: `_escape_via_cgroup`, `_escape_via_mount`, `_escape_via_nsenter`, `_escape_via_socket` |
| Defense Evasion / T1014 | Rootkit | Case 9 - `libpam_cache.so` LD_PRELOAD libc-hook rootkit (DEFINITE) |
| Defense Evasion / T1027 | Obfuscated Files or Information | Case 1 base64 + UTF-16LE encoding chain; Case 10 Fernet+zlib+b64 Python crypter + single-XOR PowerShell loader |
| Defense Evasion / T1027.002 | Software Packing | Case 10 - PyInstaller stub with creationflags=0x08000000 |
| Defense Evasion / T1036.005 | Match Legitimate Name or Location | Case 9 - `libpam_cache.so` masquerades as PAM module; Case 10 - `svchost_upd.exe` in `%TEMP%` |
| Defense Evasion / T1055.012 | Process Hollowing | Case 1 - Quasar-class PowerShell agent chain |
| Defense Evasion / T1562.001 | Disable or Modify Tools | Case 9 - `_anti_hisana` defense against Hisana anti-cryptojacker tool |
| Defense Evasion / T1564.001 | Hidden Files and Directories | Case 9 - `~/.config/fontconfig/.cpu`, `~/.config/fontconfig/.gpu`, `.pid_*`, `inotify_guard`, `.spread_*` (DEFINITE) |
| Defense Evasion / T1070.002 | Clear Linux or Mac System Logs | Case 9 - operator post-compromise cleanup |
| Defense Evasion / T1070.003 | Clear Command History | Case 9 operator scripts unset HISTFILE |
| Defense Evasion / T1620 | Reflective Code Loading | Case 10 - Fernet-decrypt-then-execute PyInstaller stub |
| Defense Evasion / T1497.001 | System Checks (Anti-VM) | Case 1 `stealth_agent.py` (operator-prompted AI evasion code) |
| Defense Evasion / T1140 | Deobfuscate/Decode Files | Case 1 base64 + UTF-16LE; Case 10 Fernet+zlib+b64 decryption chain (Python SliverCrypter → PowerShell single-XOR) |
| Discovery / T1018 | Remote System Discovery | Case 9 - ComfyUI victim scan list (4,573 entries) |
| Discovery / T1046 | Network Service Discovery | Case 9 - `get_all_ranges.sh`, `check_comfyui.sh` |
| Discovery / T1049 | System Network Connections | Cross-case (operator-side enumeration) |
| Discovery / T1057 | Process Discovery | Case 9 LD_PRELOAD-hidden process enumeration (DEFINITE) |
| Discovery / T1082 | System Information Discovery | Cross-case operator workflow |
| Discovery / T1083 | File and Directory Discovery | Case 9 LD_PRELOAD-hidden file enumeration |
| Discovery / T1595.002 | Vulnerability Scanning | Case 9 - ComfyUI exposed-node scanning |
| Discovery / T1614.001 | System Language Discovery | Case 1 - operator Russian-language detection |
| Lateral Movement / T1021.004 | SSH | Case 1 - the healthcare victim SSH via Cloudflare Tunnel |
| Lateral Movement / T1021.001 | Remote Desktop Protocol | Case 1 - the healthcare victim RDP via Cloudflare Tunnel `gil_dr1.tralalarkefe.com` |
| Collection / T1005 | Data from Local System | Case 2 - observability data harvest |
| Collection / T1213.003 | Code Repositories | Case 1 - sonner1337 GitHub PAT access |
| Collection / T1113 | Screen Capture | Case 10 - screencap_v4-v11.ps1 + MJPEG stream port 9093 |
| Collection / T1119 | Automated Collection | Case 2 - ARPA daily ingestion cycle |
| Collection / T1530 | Data from Cloud Storage Object | Case 1 - GCP project `[victim-named GCP project — redacted]` |
| C2 / T1071.001 | Web Protocols | Cross-case HTTPS C2 (DEFINITE) |
| C2 / T1090.001 | Internal Proxy | Case 9 - self-hosted XMR pool proxy at `77.110.96.200:3333` |
| C2 / T1090.004 | Domain Fronting | Case 1 - Cloudflare Tunnel custom-domain model |
| C2 / T1095 | Non-Application Layer Protocol | Case 3 - Mirai TCP raw socket beacon |
| C2 / T1102 | Web Service | Case 9 - Telegram bot supply-chain monitoring |
| C2 / T1102.002 | Bidirectional Communication | Case 1 - 5-endpoint API contract |
| C2 / T1105 | Ingress Tool Transfer | Case 3 - `wget`/`curl` distribution; Case 9 - kit pull from Vova75Rus |
| C2 / T1132.001 | Standard Encoding | Case 1 - base64+UTF-16LE; Case 9 - base64 in `min1.sh` |
| C2 / T1568 | Dynamic Resolution | Case 1 - Cloudflare DNS for tunnel subdomains |
| C2 / T1573.001 | Symmetric Cryptography | Case 10 - Fernet+zlib+b64 payload encryption (commodity Python `SliverCrypter` class; Fernet token format base64-encoded) |
| C2 / T1665 | Hide Infrastructure | Case 9 - Hysteria v2 with `bing.com` SNI masquerade |
| Exfiltration / T1041 | Exfiltration Over C2 Channel | Case 2 - ARPA ingestion via `/api/ingest/instana` |
| Exfiltration / T1567.002 | Exfiltration to Cloud Storage | `skillhub-1388575217.cos.ap-guangzhou.myqcloud.com` (Case 4 supporting) |
| Exfiltration / T1020 | Automated Exfiltration | Case 2 - ARPA daily refresh cycle |
| Impact / T1496.001 | Compute Hijacking | Case 9 - cryptojacking via xmrig + lolMiner (DEFINITE) |
| Impact / T1498 | Network Denial of Service | Case 3 - 13 attack methods (`udp-star`, `syn-storm`, etc.) |
| Impact / T1498.002 | Reflection Amplification | Case 3 - `ovh-nuke`, amplification attack methods |
| Impact / T1657 | Financial Theft | Case 9 - cryptocurrency mining + on-chain wallet drain chain |

*Table shows 49+ techniques. Full detection coverage is in the linked [detection rules file](https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/).*

**Tactic-level summary:** 11 tactics covered. The campaign's heaviest representation is in **Resource Development** (operator infrastructure), **Defense Evasion** (especially the GHOST rootkit), **Command and Control** (Cloudflare Tunnel + Telegram + custom Python C2 + Hysteria v2), and **Discovery** (Case 9 victim scanning). **Reconnaissance** is intentionally omitted because none of the captured artifacts show pre-compromise operator research at primary-source level.

---

## 8. Indicators of Compromise

> **Analyst note:** The full IOC inventory is published in the campaign IOC feed (linked below) in machine-readable JSON format suitable for SIEM/EDR ingestion. This section presents only the highest-confidence highest-impact indicators per case, organized for at-a-glance defender use. **No defanging** is applied in either this report's IOC tables or the JSON feed — per project convention, IOCs are presented as-is for machine ingestion.

**Full IOC Feed:** [`/ioc-feeds/ai-agent-frameworks-2026-05-23-iocs.json`](https://the-hunters-ledger.com/ioc-feeds/ai-agent-frameworks-2026-05-23-iocs.json)

### High-Confidence Indicators (Case 1 — Russian Gemini)

| Indicator | Type | Confidence | Action |
|---|---|---|---|
| `213.165.51.115` | IPv4 | HIGH | BLOCK |
| `tralalarkefe.com` (+ 5 named subdomains) | Domain | HIGH | BLOCK |
| `tenant-upcoming-great-descending.trycloudflare.com` | Domain | HIGH | BLOCK |
| `~/.gemini/wrapper.sh`, `~/.gemini/skills/cf-c2-manager/SKILL.md` | File path | HIGH | HUNT |
| `~/arsenal/c2_server.py`, `~/arsenal/AI_SNIPER_GOODS.txt`, `~/arsenal/AI_ADMIN_MUTANTS.txt` | File path | HIGH | HUNT |

### High-Confidence Indicators (Case 2 — Turkish ARPA)

| Indicator | Type | Confidence | Action |
|---|---|---|---|
| `209.38.205.158:8096` | IPv4:Port | HIGH | BLOCK |
| `31.223.97.87` | IPv4 (operator origin) | HIGH | MONITOR |
| `arpa-instana-api.service`, `arpa-autolearn.service` (etc.) | systemd unit | HIGH | HUNT |
| `/api/ingest/instana`, `/api/ingest/solarwinds`, `/api/ingest/zabbix` | URI | HIGH | DETECT |
| `jti: 022a1b74-2332-4df5-a76b-60225ffa7ae3` | JWT ID | HIGH | REVOKE |
| `[employee ID — suppressed]` | Windows AD user | HIGH | INVESTIGATE |

### High-Confidence Indicators (Case 3 — Rovodev/Pandora)

| Indicator | Type | Confidence | Action |
|---|---|---|---|
| `87.106.143.220:1337` | IPv4:Port | DEFINITE | BLOCK |
| `87.106.54.213`, `80.211.94.16`, `80.211.111.10`, `165.227.175.161` | IPv4 | HIGH | BLOCK |
| `PandoraNet.{arch}` filename pattern | Filename | DEFINITE | DETECT |
| `~/.rovodev/sessions/` | Path | HIGH | HUNT |
| Discord operator ID `1441591352927326259` | Discord | HIGH | MONITOR |
| SHA256 `58ef3f244dab408fac7117606843a3dbcfb0754b2032a5950e977bc1811c0313` (`bot.sh`) | Hash | DEFINITE | BLOCK |
| SHA256 `f3c7cde94261f6664891357b399198a73b9741a7a435527807dca5b3bb86e5f0` (`Naku.arm`) | Hash | DEFINITE | BLOCK |

### High-Confidence Indicators (Case 4 — Korean Claude+OpenClaw)

| Indicator | Type | Confidence | Action |
|---|---|---|---|
| `221.150.15.104` | IPv4 | MODERATE | MONITOR |
| `~/.claude/settings.local.json` containing `Bash(curl -fsSL https://openclaw.ai/install.sh \| bash)` | File path + content | HIGH | HUNT |
| `openclaw.ai`, `docs.openclaw.ai` | Domain | HIGH | BLOCK (from non-developer hosts) |
| Listening port 18789 | Port | MODERATE | INVENTORY |

### High-Confidence Indicators (Case 9 — GHOST Kit)

| Indicator | Type | Confidence | Action |
|---|---|---|---|
| `77.110.96.200`, `77.110.125.145` | IPv4 | DEFINITE | BLOCK |
| MD5 `296a800564111b0bad9fe63faf4e63ba` (`libpam_cache.so`, byte-identical across hosts) | Hash | DEFINITE | BLOCK |
| `/etc/ld.so.preload` (any modification) | File path | HIGH | DETECT |
| `/lib/security/libpam_cache.so` | File path | DEFINITE | BLOCK |
| `~/.config/fontconfig/.cpu`, `~/.config/fontconfig/.gpu` | File path | HIGH | HUNT |
| `cfx.kryptex.network`, `etc.kryptex.network` | Domain | HIGH | BLOCK |
| `auto.c3pool.org`, `cfx-asia1.nanopool.org` | Domain | HIGH | BLOCK |
| Telegram bot prefix `8415540095` (OWNER, supply-chain signature) | Telegram | DEFINITE | DETECT (requires Telegram API-side monitoring; not detectable at standard egress layers) |
| Telegram bot prefix `8315596543` (MIRROR, Operator-A specific) | Telegram | HIGH | DETECT |
| `Vova75Rus/ComfyUI-Shell-Executor`, `jamestechdev-oss/ComfyUI-Shell-Plugin` | GitHub | HIGH | MONITOR (re-hosting attempts) |
| Hidden ports 3333, 4444, 5555, 7777, 8027, 8029, 9999, 14433, 14444 | TCP/UDP | HIGH | DETECT |

### High-Confidence Indicators (Case 10 — Sliver)

| Indicator | Type | Confidence | Action |
|---|---|---|---|
| `5.230.201.54:31337`, `5.230.201.54:8080`, `5.230.201.54:9093` | IPv4:Port | HIGH | BLOCK |
| `5.230.201.54/api/v/keylog` | URL | HIGH | DETECT |
| `%TEMP%\svchost_upd.exe` | File path | HIGH | DETECT |
| JARM `3fd3fd20d00000021c43d43d00043d204204071741c36579e355f830d285a5` | TLS fingerprint | MODERATE (broad) | DETECT (combined — combine with `5.230.201.54` IP, port `:31337`, or `/api/v/keylog` URI to discriminate from broader Sliver population) |

### Demoted Indicators (DO NOT BLOCK)

The following hosts were initially flagged but **demoted** during analysis. Do not block:

| Host | Demotion Reason |
|---|---|
| `173.249.2.23` (Case 5) | Defensive-security SaaS consultant |
| `66.94.120.32` (Case 6) | Benign HuggingFace ML researcher mtr7x (Sarvam-30B quantization) |
| `elyasbetter@gmail.com` | French entrepreneur (wikiprepa.fr alumni platform); NOT a threat actor |

---

## 9. Threat Actor Assessment

> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-[YEAR]-[###] is an internal tracking designation assigned by The Hunters Ledger to actors observed across analysis who cannot yet be linked to a publicly named threat group. This label will not appear in external threat intelligence feeds or vendor reports — it is specific to this publication. If future evidence links any UTA-2026-012 through UTA-2026-017 to a known named actor, the designation will be retired and updated accordingly.

This is a **multi-actor** campaign. Attribution is distributed across one named actor (Vova75Rus) and six UTAs. Three additional cases (7, 8, 10) are classified INSUFFICIENT for attribution at the capsule depth captured. **No Tier-1 government attribution** applies to any operator in this campaign. The Alternative Competing Hypotheses (ACH) analysis ruled in favor of the **multi-actor unrelated campaign** hypothesis, with **campaign coordination explicitly REFUTED** by distinct IOCs/wallets/language/geography/targets/motivations/AI tools/infrastructure across all 8 cases.

### 9.1 Vova75Rus — Named Actor (HIGH 88%)

**Case:** Case 9 (GHOST cryptojacker kit author — separate identity from kit's customer operators).

**Confidence Statement:**

```
Threat Actor: Vova75Rus
Confidence: HIGH (88%)
- Why this confidence: 5+ year GitHub history (UID 73169104); region code 75 in handle = Zabaykalsky Krai
  (Russian regional plate code convention); personal-dedication page Notes.github.io to "Arina" on March 8th
  (International Women's Day, Russian-culturally-significant date); Censys ARC primary-research corroboration
  (Mark Ellzey 2026-04-07); OWNER Telegram bot 8415540095 baked into every customer deployment as supply-chain
  monitoring signature; byte-identical libpam_cache.so across 2 customer hosts confirming DEFINITE supply-chain
  root; GitHub T&S account-level action 2026-05-25 (all 9 repos HTTP 404) validates the kit-author identity at
  the platform-trust-and-safety level.
- What's missing: real-world identity beyond the Vova75Rus handle + region code. Customer count beyond the
  2 observed deployments.
- What would increase confidence: government attribution at Tier 1 (FBI/CISA/NSA disclosure) or 2+ additional
  customer deployments observed.
```

**Geography:** Zabaykalsky Krai, Russia (probable; based on region code 75 convention in handle).

**Language:** Russian (`Для Арины 💖 С 8 Марта` / "For Arina 💖 March 8th" in personal-dedication page).

**Evidence Anchors:**

1. 5+ year GitHub history (UID 73169104, account-level T&S suspended 2026-05-25).
2. Region code 75 in handle = Zabaykalsky Krai (Russian regional plate code convention).
3. Personal-dedication page Notes.github.io to "Arina" on Russian-cultural-significant date (March 8th).
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

**Profile:** Turkish-speaking, Turkish-located, intra-Turkey single-thread operator with state-relevant interest in TVF (Turkey Wealth Fund) financial-sector intelligence; espionage tradecraft sub-type (a) state-aligned-loose or (c) political/factional — high-MODERATE.

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

The campaign's defining attribution finding is that **shared infrastructure does not imply operator coordination**. The investigation applied explicit cross-case attribution discipline to avoid false coordination claims:

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

The campaign threat level (HIGH) should be reassessed under any of the following conditions:

- **Cloudflare PSIRT does not action `tralalarkefe.com`** — Case 1 Cloudflare Tunnel C2 remains active against the healthcare victim and any future victims using the operator's custom-domain model. Reassess to consider upgrading from HIGH.
- **AEZA Group does not respond to the prepared disclosure package** — bulletproof status held at SUSPECTED pending AEZA response. If AEZA does not act, Cases 1 and 9 hosting remains available to operators.
- **Vova75Rus re-hosts post-GitHub-T&S suspension** — track for new Vova75Rus-pattern accounts and re-hosted GHOST kit repositories. Defenders should monitor `Vova75Rus/*`, `UID 73169104` recreations, and similar naming patterns.
- **the victim organization does not rotate stolen JWTs** — the 10-year IBM Instana JWT (iat 2024-03-06, jti 022a1b74-2332-4df5-a76b-60225ffa7ae3) remains valid until token rotation. If rotation does not occur, the operator retains read access to the victim organization observability.
- **New customer operators of the GHOST kit are observed** — the 4-tier supply chain expands by one tier per confirmed new customer if Vova75Rus's distribution channel is reconstituted. Re-assess the supply-chain depth score when new customer operators are confirmed.

### 10.2 Detection Coverage Summary

**Full Detection File:** [`/hunting-detections/ai-agent-frameworks-2026-05-23-detections.md`](https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/)

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

## 13. Investigation Methodology — Hunt.io MCP in the Defender Workflow

> **Analyst note:** This report documents how attackers integrate AI-agent CLIs into offensive workflows. The investigation that produced the report integrated an AI-agent CLI (Claude Code) with the **Hunt.io Model Context Protocol (MCP) server** to surface, triage, and analyze every one of the 9 cases above. This section documents that defender-side AI integration in detail — what worked, what did not, the specific findings the MCP enabled, and the workarounds used when MCP endpoints failed. The symmetry is intentional: AI-augmented tradecraft is now mainstream on both sides of the security line, and defenders evaluating MCP-augmented investigation workflows benefit from a concrete artifact to compare against.

### 13.1 Why This Section Appears in a Threat-Intelligence Report

Threat intelligence published in 2026 by a single-analyst publisher increasingly comes from AI-augmented investigation workflows. The same architectural pattern this report documents on the *offense* side — operator runs AI CLI on local workstation, AI CLI calls vendor APIs via standardized tool interfaces, operator-authored handoff documents persist context across sessions — describes the *defense* side of this very investigation. Documenting the workflow itself is part of publication credibility. It also gives defender teams considering MCP-augmented investigation a reproducible reference point: the methodology section answers "what does this actually look like in practice, and what should I expect to work or fail."

The investigation's MCP integration is **not vendor endorsement**. The Hunters Ledger purchased the Hunt.io subscription tier independently and received no consideration for documenting the workflow. Limitations and failure modes are surfaced as honestly as the successes. A separate testing-feedback report was sent to Hunt.io engineering with the per-endpoint observations and improvement requests; this section is the defender-facing distillation.

### 13.2 Model Context Protocol (MCP) — A Brief Primer

The **Model Context Protocol** is an Anthropic-published open standard (announced November 2024) for exposing external data sources and tools to AI clients via a uniform JSON-RPC interface. An MCP **server** publishes tool definitions and schemas; an MCP **client** (Claude Code, Cursor IDE, custom AI agents) calls those tools as part of its reasoning loop. The pattern decouples AI tooling from any specific vendor — once a server is published, any compatible client can use it.

Hunt.io publishes an MCP server that exposes their full platform feature set: **AttackCapture** (open-directory dataset), IP/domain/SSL/JARM enrichment, threat-actor catalog, IP-history pivots, and SQL access to the underlying database. The investigation's Claude Code client connected to the Hunt.io MCP server (configured once in `.claude/settings.local.json`) and from that point forward could call any of ~60 Hunt.io tools alongside Claude's native tools (file I/O, web search, shell commands). This means: when the analyst said *"what does Hunt.io know about 77.110.96.200,"* Claude Code resolved that into a `mcp__hunt-io__attackcapture-host-summary` call, parsed the JSON response, and surfaced the relevant fields to the analyst — without the analyst leaving the AI client or copy-pasting URLs into a browser.

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

Read together, those tags describe a **Linux platform with PAM modification persistence (T1556.003), systemd service persistence (T1543.002), XDG autostart persistence (T1547.013), `/etc/passwd` + `/etc/shadow` credential dumping (T1003.008), system-log clearing (T1070.002), system-check sandbox evasion (T1497.001), time-based sandbox evasion (T1497.003), and a confirmed xmrig (Monero miner) family classification from tria.ge sandbox detonation**. The analyst formed that platform model in seconds — without pulling any file content — and the model was correct end-to-end. The expansion of Case 9 from "capsule" depth to full case treatment was directly driven by this metadata: the breadth of TTP coverage signaled that the host was a systematic cryptojacking platform rather than a single-purpose scanner.

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

This parent anchors a six-report series. The five sub-reports provide per-case deep-dives at full technical depth:

- **[Case 1 Sub-Report](/reports/russian-gemini-credential-mill-213.165.51.115/):** Russian Gemini Credential-Mill Operator (UTA-2026-012) — `ai_sniper_brute.py` pipeline, `c2_server.py` architecture, Cloudflare Tunnel topology, the healthcare-victim impact, and Phase 11 native Russian idiom analysis.
- **[Case 2 Sub-Report](/reports/turkish-arpa-openclaw-state-insurer-209.38.205.158/):** Turkish ARPA Observability-Harvester Operator (UTA-2026-013) — ARPA platform architecture (TimescaleDB+Neo4j+Redis), 4-source observability harvesting against the victim organization, and insider-recruitment TTP framing (insider AD user + Turkish-language tunnel-setup docs).
- **[Case 3 Sub-Report](/reports/rovodev-mirai-matrix-c2-87.106.143.220/):** Rovodev/Pandora Mirai Operator (UTA-2026-014) — Rovodev session JSONs as AI-authoring primary-source evidence, Pandora-Mirai 11-architecture binary set, and 5-vector persistence chain forensics.
- **[Case 4 Sub-Report](/reports/korean-claude-openclaw-221.150.15.104/):** Korean Claude Code + OpenClaw Operator (UTA-2026-015) — capsule-depth artifact analysis of the attacker-customized `settings.local.json` permission allowlist.
- **[Case 9 Sub-Report](/reports/ghost-cryptojacker-vova75rus-77.110.96.200/):** GHOST Cryptojacker Kit + 4-Tier Supply Chain (Vova75Rus HIGH + UTA-2026-016 + UTA-2026-017) — `libpam_cache.so` ELF internals, container-escape suite functions, ComfyUI fake-node persistence, and the Tier-0 disposition outcome timeline.

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
- **Türkiye Wealth Fund** — Corporate Portfolio (invest.gov.tr). Tier 2 / Admiralty B1. Establishes the victim organization state-ownership context.
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
| Personal contact | `Arina` | Case 9 Vova75Rus personal dedication (March 8th) |

### 14.5 Appendix B — Disposition Outcomes Summary

| Disclosure Target | Date | Outcome | Tier |
|---|---|---|---|
| GitHub T&S (Vova75Rus UID 73169104) | 2026-05-25 | Account suspended; all 9 repos HTTP 404 | Tier-0 |
| GitHub T&S (MehmetARPA) | 2026-05-25 | Account suspended; `github.com/MehmetARPA/ARPA` no longer accessible | Tier-0 |
| Alibaba abuse desk (9 victim IPs) | 2026-05-25 | Submitted; pending | Tier-1 cloud provider |
| DigitalOcean abuse desk (3 victim IPs) | 2026-05-25 | Submitted; pending | Tier-1 cloud provider |
| Hetzner abuse desk (3 victim IPs) | 2026-05-25 | Response received 2026-06-02 — investigation opened; no case-specific feedback to the reporter guaranteed | Tier-1 cloud provider |
| Azure abuse desk (2 victim IPs) | 2026-05-25 | Submitted; pending | Tier-1 cloud provider |
| AWS abuse desk (2 victim IPs) | 2026-05-25 | Submitted; pending | Tier-1 cloud provider |
| AEZA abuse desk | Prepared | Submission pending | Bulletproof-adjacent |
| Kryptex mining pool | Prepared | Submission pending | Mining pool |
| Cloudflare PSIRT (`tralalarkefe.com`) | Prepared | Tunnel takedown not yet confirmed | Infrastructure provider |
| Conflux Exchange | Prepared | — | Cryptocurrency exchange |
| Telegram (kit-author bot 8415540095) | Prepared | — | Platform |
| ComfyUI (victim notification) | Prepared | — | Platform |

### 14.6 Appendix C — Research Gaps (Acknowledged for Future Work)

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

### 14.7 Appendix D — Key Analytic Conclusions (KAC Documentation)

The campaign's headline analytical claims are surfaced here with their underlying assumptions explicit, so that defenders or downstream analysts can evaluate the inferential chain rather than accept the conclusion at face value. This format applies the Structured Analytic Technique discipline of separating evidence from assumption from conclusion.

**KAC 1 — "AI does not replace operator tradecraft; it extends it."**

- **Headline conclusion** (Executive Summary, Section 4.10): none of the 8 observed operators uses AI as a replacement for offensive skill. AI is an additive capability uplift layer.
- **Evidence anchors:**
  - Case 1 ships hand-written Quasar-class PowerShell implants and a self-built unauthenticated Python-stdlib C2 server alongside its Gemini integration (Section 4.1).
  - Case 2 ships a production-grade systemd/TimescaleDB/Neo4j/Redis observability-harvester platform that no LLM produced (Section 4.2).
  - Case 3 ships a Mirai-family 11-architecture botnet whose lineage traces to 2016 source-code releases (Section 4.3).
  - Case 9 ships byte-identical LD_PRELOAD libc-hook rootkit (`libpam_cache.so`) — kernel-adjacent persistence engineering predates LLM availability (Section 4.5).
- **Underlying assumption (made explicit):** "If an operator demonstrates any non-AI-authored offensive capability of moderate sophistication, AI is supplemental rather than enabling." This assumption is appropriate for Cases 1, 2, 3, 9 where non-AI capability is observed at moderate or higher sophistication. It is **not testable** for capsule-depth cases (4, 7, 8, 10) where filesystem extraction was not conducted.
- **Falsification condition:** If any of Cases 4, 7, 8, 10 is later shown via deeper investigation to be AI-only (operator writes natural-language spec; LLM produces all code; operator cannot operate the stack without AI), the three-class taxonomy at Section 4.10 would warrant a fourth class for AI-democratized script-kiddies. The taxonomy already documents this class as **theoretical** with no pure exemplar in the dataset (Section 4.10, line 624).
- **Confidence in headline conclusion:** HIGH for the 4 deeply-investigated cases (1, 2, 3, 9); MODERATE for the campaign-wide generalization due to capsule-depth limitation on cases 4, 7, 8, 10.

**KAC 2 — "Multi-vendor diversity refutes single-coordinated-campaign framing."**

- **Headline conclusion** (Executive Summary, Section 9.9): no two operators share the same AI tool, hosting provider, target sector, or motivation; the campaign is an ecosystem-wide diffusion pattern rather than a single coordinated actor.
- **Evidence anchors:** 5 distinct AI tools across 8 operators (Gemini CLI, Claude Code, Atlassian Rovodev, OpenClaw, Cursor IDE), 6 distinct hosting providers (AEZA, DigitalOcean, IONOS, Korea Telecom, Hetzner-like, etc.), 4 distinct target sectors (healthcare, insurance, IoT botnet recruitment, GPU cloud cryptojacking), 4 distinct motivations (financial cybercrime, observability harvesting, DDoS-for-hire, cryptojacking).
- **Underlying assumption (made explicit):** "Coordinated campaigns produce convergent infrastructure/tooling/target choices." This is well-established in attribution practice (Mandiant, CrowdStrike attribution methodology) but treats diversity as evidence of non-coordination rather than evidence of operator OPSEC discipline within a coordinated campaign.
- **Falsification condition:** A coordinated campaign deliberately practicing extreme infrastructure/tooling diversity for OPSEC reasons would produce the same observed pattern. Section 9.9 addresses this via 5 named falsification axes (AEZA co-residency, DigitalOcean co-residency, OpenClaw co-usage, timing windows, operator-language overlap) — none of these axes returned coordination evidence beyond ecosystem-level co-residency.

**KAC 3 — "GitHub T&S Vova75Rus action is Tier-0 supply-chain disposition."**

- **Headline conclusion** (Section 4.5.6, Section 9.1): the 2026-05-25 GitHub account-level action against UID 73169104 disrupted the entire upstream payload-distribution channel of the GHOST cryptojacker ecosystem.
- **Evidence anchors:** 9 suspended repositories (ComfyUI-Shell-Executor, ComfyUI-Shell-Plugin, Notes.github.io, and 6 ancillary repos) verified at takedown time; OWNER Telegram bot 8415540095 baked into customer deployments confirms supply-chain root identity; byte-identical kit binary across both customer hosts confirms single upstream source.
- **Underlying assumption (made explicit):** "Repository takedown disrupts the distribution channel for as long as the operator does not re-host on another platform." Re-hosting is expected; the disposition is characterized as **temporarily** disrupted (Executive Summary line 94), not permanently disabled.
- **Falsification condition:** If the kit re-appears on a different GitHub identity or on a non-GitHub platform within weeks, the disposition impact is limited. Wayback Machine snapshots are preserved as pre-takedown evidence for re-hosting cross-correlation.

---

© 2026 Joseph. All rights reserved. See LICENSE for terms.








