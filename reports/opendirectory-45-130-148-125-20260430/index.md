---
title: "AdaptixC2 Open Directory Exposure — 45.130.148.125 Operator Toolkit"
date: '2026-04-30'
layout: post
permalink: /reports/opendirectory-45-130-148-125-20260430/
hide: true
category: "C2 Framework"
description: "An open directory on a Uzbekistani VPS exposed a complete AdaptixC2 operator toolkit — 30 attack artifacts covering the full intrusion kill chain — with recovered RC4 config, Linux build-environment fingerprints, and operator-specific indicators enabling cross-campaign tracking under UTA-2026-006."
detection_page: /hunting-detections/opendirectory-45-130-148-125-20260430-detections/
ioc_feed: /ioc-feeds/opendirectory-45-130-148-125-20260430-iocs.json
detection_sections:
  - label: "Detection Coverage Summary"
    anchor: "#detection-coverage-summary"
  - label: "YARA Rules"
    anchor: "#yara-rules"
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "Suricata Signatures"
    anchor: "#suricata-signatures"
  - label: "Coverage Gaps"
    anchor: "#coverage-gaps"
ioc_highlights:
  - value: "45[.]130[.]148[.]125"
    note: "Operator C2 server (TCP/80, /4444, /8888)"
  - value: "5ea265ad3e6429cd2e8d9831360f7e2be9b8ba5a5b32a4a60c5c956a3f8fb285"
    note: "Operator-written injector.dll (SHA256, UTA-2026-006)"
  - value: "b4ffd7ca8f5505fd7b71882c67712e896c9d170a3b3b581baba78ee5d1c2b858"
    note: "Operator-written beacon.ps1 loader (SHA256)"
  - value: "358edb5d7e3e38c2da0a2ef323a281283aa96d47a8649014d114923b06866c12"
    note: "AdaptixC2 production beacon DLL (SHA256)"
---

**Campaign Identifier:** AdaptixC2-OpenDirectory-Toolkit-45.130.148.125<br>
**Last Updated:** May 7, 2026<br>
**Threat Level:** HIGH

---

## 0. BLUF / Bottom Line Up Front

A 3:00 AM read for the on-call SOC analyst, threat hunter, or detection engineer. Fuller narrative begins at Section 1.

**Block at perimeter — `45.130.148.125`:**
- **TCP/80** — AdaptixC2 victim-facing C2
- **TCP/4444** — AdaptixC2 TeamServer (operator GUI)
- **TCP/8888** — open-directory staging server

**Top three hunt strings (highest-fidelity, operator-specific, UTA-2026-006):**
1. `/tmp/si_build/obj/Release/net472/si_build.pdb` — Linux-built .NET PDB path (HIGH confidence operator fingerprint)
2. `f443b9ce7e0658900f6a7ff0991cdee6` — recovered RC4 listener key (DEFINITIVE identifier of *this* listener configuration)
3. `[SI]::Inject(` — operator's PowerShell loader invocation pattern

**Top two log sources to check:**
1. **PowerShell ScriptBlock logging (Event ID 4104)** for the AMSI-bypass-plus-reflection chain (`amsi`/`Con`/`text` string concatenation, `*iUtils` reflection, `Reflection.Assembly.Load` of a base64 PE, then `[SI]::Inject` into `explorer.exe`)
2. **Sysmon Event ID 8 (CreateRemoteThread)** for `powershell.exe → explorer.exe` injection events; pair with **Event ID 1** for the parent-PowerShell process command line

**Active C2 status: UNKNOWN.** Endpoint reachable at analysis time; no live victim traffic captured. Treat capability scoring as the upper bound for now; revise after the +1 week rescan target (2026-05-06).

**Detection rule package** — YARA, Sigma, Suricata, and EDR query content for the framework + operator fingerprints, plus coverage-gaps documentation:
[/hunting-detections/opendirectory-45-130-148-125-20260430-detections/](/hunting-detections/opendirectory-45-130-148-125-20260430-detections/) (source file: `threat-intel-vault/hunting-detections/opendirectory-45-130-148-125-20260430-detections.md`).

**IOC feed (full machine-readable list, 72 indicators):**
[/ioc-feeds/opendirectory-45-130-148-125-20260430-iocs.json](/ioc-feeds/opendirectory-45-130-148-125-20260430-iocs.json).

---

## 1. Executive Summary

The operator behind `45.130.148.125` is an unattributed mid-tier hands-on intrusion operator — tracked here as **UTA-2026-006** *(an internal tracking label used by The Hunters Ledger — see Section 8)* — who has staged a complete, operationally-ready AdaptixC2 deployment together with a full commodity post-exploitation kit (Ligolo-ng, chisel, Ghostpack/SpecterOps suite, mimikatz, lazagne) on a single Uzbekistani VPS. Their distinguishing build-environment fingerprints are the Linux PDB path `/tmp/si_build/obj/Release/net472/si_build.pdb`, the matched `beacon.ps1` PowerShell loader paired with an operator-written `[SI]::Inject` .NET injector, the recovered RC4 listener key `f443b9ce7e0658900f6a7ff0991cdee6`, and per-listener type IDs `0xbe4c0149` / `0xcb4e6379` — none of which appear in any reviewed public threat feed. The TTPs defenders should detect to catch this specific operator's tradecraft are documented in detail throughout Sections 4 and 5 of this report and packaged in the linked detection rule set.

This report fills a publication gap. Tier-1 vendor coverage of the AdaptixC2 framework itself (Unit 42, Silent Push, Hunt.io, Zscaler ThreatLabz, Kaspersky, Sophos) has densified materially since mid-2025, but no public report covers **this operator's** infrastructure at `45.130.148.125`, the recovered RC4 key, the build-environment fingerprints, or the sub-mature OpSec hygiene patterns documented below.

**A note on activity status:** The C2 endpoint at `45.130.148.125:80` is reachable but no live victim traffic has been captured at the time of analysis. The capability assessment in this report should therefore be read as the upper bound — what the operator *could* do with the staged toolkit — rather than confirmation of active operations. The threat level would escalate to CRITICAL if confirmed-active in operations against named victims; rescanning is targeted for 2026-05-06.

### What Was Found

An attacker-controlled server hosted a complete pre-staged toolkit of **30 attack artifacts**, covering the full intrusion lifecycle from initial PowerShell delivery to Linux server pivoting. The open directory exposed on TCP/8888 at `45.130.148.125` was discovered via The Hunter's Ledger's opendir-hunter platform on 2026-04-26. It hosted an AdaptixC2 framework deployment in four Windows formats (DLL / EXE / shellcode-form / sideload-renamed `msupdate.dll`) plus a Linux ELF Adaptix agent and a Gopher Go agent Windows variant. Adjacent to the open directory, the AdaptixC2 victim-facing C2 listener runs on TCP/80 and the AdaptixC2 TeamServer (operator GUI) runs on TCP/4444 — all three services co-located on a single IP, which establishes that this is **attacker-controlled infrastructure**, not a compromised third-party host.

The kit's only operator-written code is a 256 KB `beacon.ps1` PowerShell loader and a 5,120-byte `injector.dll` (.NET v4.7.2 SI class with W^X-aware classic CRT process injection). The remainder — AdaptixC2 framework, Ligolo-ng v0.8.3, chisel, Ghostpack/SpecterOps suite, mimikatz, lazagne, and supporting recon/LPE tooling — is 100% commodity open-source. The toolkit covers the full intrusion kill chain: execution → C2 → Active Directory reconnaissance → credential theft via four vectors → privilege escalation via three mechanisms → lateral movement via two redundant tunneling tools → Linux post-exploitation pivot.

### Why This Threat Is Significant

Three factors make this exposure noteworthy. **First**, AdaptixC2 has shifted in the past twelve months from a niche open-source red-team tool to a workhorse post-exploitation platform now associated with at least four distinct cohort archetypes: Russian-speaking ransomware affiliates (Akira, Fog), the Tomiris APT, the Tropic Trooper APT, and the GOLD ENCOUNTER cluster (PayoutsKing operator). Defenders need detection coverage for the framework, not just for any single named campaign. **Second**, the operator's deployment leaks operational fingerprints — PDB paths, build timestamps, internal class names, a stock 2013-era Firefox 20 User-Agent left unmodified, and a leftover `proxy_port=3128` dev artifact — that enable defender pivoting and cross-campaign tracking under UTA-2026-006. **Third**, the static-since-discovery exposure window (80+ hours observed as of analysis) preserves a complete operator deployment package intact, providing intelligence that is rarely available outside post-incident DFIR.

The gap this analysis fills: existing public reporting describes AdaptixC2 abstractly, but provides no IOC set, no operator fingerprints, and no actionable detection content tied specifically to a deployment captured during its staging phase. This report makes those artifacts public.

### Key Takeaways

The seven points below summarize what this report wants a reader to retain. They are deliberately framed as conclusions, not analysis — see the body for evidence.

1. **`45.130.148.125` is attacker-controlled infrastructure.** Service co-location of victim-facing C2, operator TeamServer GUI, and open-directory staging on a single IP rules out compromise-of-third-party explanations. Block all three ports (TCP/80, TCP/4444, TCP/8888) at the perimeter unconditionally.
2. **The AdaptixC2 framework is now the workhorse, not the niche.** Four distinct cohort archetypes (Russian-speaking ransomware affiliates, Tomiris APT, Tropic Trooper APT, GOLD ENCOUNTER) all use it. Defenders should detect the framework regardless of operator — the `X-Beacon-Id` header + Firefox 20 User-Agent combination is the single highest-fidelity network signature for any AdaptixC2 deployment running default-listener configuration.
3. **RC4 key recovery requires no cracking — adjacent plaintext storage in `.rdata` is by design.** This is a framework architectural choice, not a defender win against the operator. The same recovery technique works against any AdaptixC2 beacon.
4. **The operator's tradecraft is mid-tier with one sophisticated choice.** W^X-aware classic CRT process injection (CreateRemoteThread on a separately RW-then-RX paged region) is the only sophistication; everything else is textbook. Sub-mature OpSec hygiene leaves PDB paths, build timestamps, internal class names, and a stock 2013-era User-Agent unmodified. NOT APT-level.
5. **Operator-specific fingerprints persist across builds.** The `si_build` class name, the `/tmp/si_build/obj/Release/net472/si_build.pdb` path, the recovered RC4 key, and the per-listener type IDs `0xbe4c0149` / `0xcb4e6379` all appear in operator-written code, not framework defaults. Any future binary carrying these strings links to UTA-2026-006 at HIGH confidence.
6. **Attribution is INSUFFICIENT (<50%) — UTA-2026-006 internal designation only.** Tropic Trooper and Tomiris are explicitly ruled out; GOLD ENCOUNTER / PayoutsKing is LOW. Russian-speaking ransomware affiliate cohort alignment is population-level, not named-actor. Treat any attribution claim from secondary feeds with skepticism unless they show evidence beyond what is in this report.
7. **Active operational status is UNKNOWN as of analysis.** No live victim traffic captured. The threat level (HIGH) reflects upper-bound capability of the staged toolkit; the threat level should be reassessed to CRITICAL on confirmed-active operations against named victims, or LOW if the +1 week rescan (2026-05-06) shows the infrastructure is decommissioned.

### Key Risk Factors

<table>
<colgroup>
<col style="width: 26%;">
<col style="width: 16%;">
<col style="width: 58%;">
</colgroup>
<thead>
<tr><th>Risk Dimension</th><th>Score (X/10)</th><th>Rationale</th></tr>
</thead>
<tbody>
<tr><td>Severity of capability</td><td>8/10</td><td>Complete kill-chain coverage from execution → C2 → AD enumeration → credential theft → LPE → lateral movement → Linux pivot. Missing only ransomware/data-destruction tooling.</td></tr>
<tr><td>Detection difficulty</td><td>6/10</td><td>Three vendor families catch the AdaptixC2 beacon at the file level (Elastic / Kaspersky / Microsoft). PowerShell loader uses reflection-based AMSI bypass + in-memory load. RC4-encrypted config defeats string-based hunting. Aggressive 4–5 second beacon cadence creates very high-volume traffic that becomes highly visible if egress monitoring exists.</td></tr>
<tr><td>Operational maturity</td><td>5/10</td><td>Sub-mature OpSec hygiene (PDB paths leaked, build timestamps in plaintext, internal class names exposed, dev-leftover artifacts). Same-day dev-to-prod build cadence captured. NOT APT-level.</td></tr>
<tr><td>Spread / lateral movement</td><td>7/10</td><td>Ligolo-ng v0.8.3 TUN-mode + chisel reverse-tunneling enables full internal-network access from a single foothold. AdaptixC2 Linux ELF agent + <code>linpeas.sh</code> enable Linux-host lateral movement.</td></tr>
<tr><td>Active C2 status</td><td>UNKNOWN</td><td>C2 endpoint at <code>45.130.148.125:80</code> reachable at the time of analysis but no live traffic captured. Status pending +1 week opendir-hunter rescan target 2026-05-06.</td></tr>
<tr><td><strong>Overall risk score</strong></td><td><strong>7/10 HIGH</strong></td><td>Capability-driven HIGH. Would be CRITICAL if confirmed-active in operations against named victims. No victim observation available from open-directory analysis alone.</td></tr>
</tbody>
</table>

### Threat Actor

**Attribution: INSUFFICIENT (<50%) — tracked as UTA-2026-006.** Named-actor attribution is not achievable on the available evidence. The operator's toolkit profile and Uzbekistani hosting geography are consistent with the Russian-speaking ransomware affiliate cohort (DFIR Report Nov 2025 Akira chain, Silent Push Aug 2025 CountLoader chain) at population-level alignment only — this is a cohort estimate, not a named-actor attribution. **Tropic Trooper** and **Tomiris** are explicitly ruled out (six and five technical inconsistencies respectively). **GOLD ENCOUNTER / PayoutsKing** is LOW confidence (two inconsistencies, including the absence of QEMU virtualization scaffolding that defines that cluster). UTA-2026-006 is supported by seven distinctive characteristics across technical, infrastructure, and behavioral dimensions documented in Section 8.

### For Technical Teams

- **Block at perimeter:** `45.130.148.125` on TCP/80 (C2), TCP/4444 (TeamServer), and TCP/8888 (open-directory staging). See Section 10 for full network-side guidance.
- **Hunt for the AdaptixC2 stock fingerprint combination:** outbound HTTP POST to a fixed external IP carrying both an `X-Beacon-Id` header and a 2013-era Firefox 20 User-Agent. The combination is what disambiguates the framework — not any single component. Detail in Section 5.
- **Hunt for the operator's loader chain:** PowerShell process performing reflection-based AMSI bypass (`amsi`+`Con`+`text` concatenation, `*iUtils` reflection) followed by `Reflection.Assembly.Load` of a base64 PE and a cross-process injection into `explorer.exe` with W^X allocation pattern. Detail in Sections 4 and 5.
- **Hunt for operator-specific fingerprints (UTA-2026-006):** YARA on the strings `si_build`, `/tmp/si_build/obj/Release/net472/si_build.pdb`, the recovered RC4 key `f443b9ce7e0658900f6a7ff0991cdee6`, and the per-listener type IDs `0xbe4c0149` / `0xcb4e6379`. Any future binary carrying any of these links to this operator at HIGH confidence.
- **Detection content:** The detection rule set published with this report — YARA, Sigma, Suricata, EDR queries — is documented at [/hunting-detections/opendirectory-45-130-148-125-20260430-detections/](/hunting-detections/opendirectory-45-130-148-125-20260430-detections/). The IOC feed is at [/ioc-feeds/opendirectory-45-130-148-125-20260430-iocs.json](/ioc-feeds/opendirectory-45-130-148-125-20260430-iocs.json).

### 1.1 Threat Intelligence Summary

This report is anchored to a single observable corpus rather than to general threat-landscape commentary, but four threat-intel facts shape how defenders should treat the findings:

- **Framework attribution at DEFINITE confidence (98%+)** — three independent vendor labels (Elastic `Windows_Trojan_Adaptix_b2cda978`, Kaspersky `UDS:Backdoor.Win64.AdaptixC2.a`, Microsoft `Backdoor:Win64/AdaptixC2.MKB!MTB`) plus byte-for-byte architectural match against the AdaptixC2 framework's published source establish the family with no ambiguity. The Linux ELF agent carries a parallel set of vendor labels for the Gopher Linux variant.
- **AdaptixC2 ecosystem footprint has densified since mid-2025** — Tier-1 vendor coverage of the framework (Unit 42, Silent Push, Hunt.io, Zscaler ThreatLabz, Kaspersky, Sophos) now covers four distinct cohort archetypes: Russian-speaking ransomware affiliates (Akira, Fog), Tomiris APT, Tropic Trooper APT, and GOLD ENCOUNTER / PayoutsKing. None of those named campaigns share infrastructure with `45.130.148.125`. Defender posture should target the framework rather than any single named actor (see Section 9 for the cohort taxonomy).
- **Hosting posture sits in a low-cooperation jurisdiction** — AS35682 (Uzbekistan) is a regional commercial provider, not a formally sanctioned bulletproof AS, but Uzbekistan is not a Budapest Convention signatory and has no US MLAT coverage for cybercrime cooperation. This creates measurable Western law-enforcement-cooperation friction relative to EU/MLAT jurisdictions and aligns at population level with post-Soviet cybercrime hosting preferences.
- **Cross-investigation linkage is open** — the operator's `/tmp/<name>_build/` PDB convention, MinGW-w64 + GNU ld 2.35 toolchain, and same-day dev-to-prod build cadence are durable build-environment fingerprints. If the same patterns appear in another investigation, build-environment-level operator clustering becomes viable. The complete UTA-2026-006 distinguishing characteristic list is in Section 8.4.

---

## 2. Discovery Context and Toolkit Composition

### 2.1 Discovery via opendir-hunter

The `45.130.148.125` infrastructure was discovered via The Hunter's Ledger's open-directory crawler platform on **2026-04-26 at 03:41:05 UTC**. The crawler observed three services on the same IP:

| Port | Service | Purpose |
|---|---|---|
| TCP/80 | AdaptixC2 HTTP C2 (beacon callback handler) | Victim-facing C2 |
| TCP/4444 | AdaptixC2 TeamServer (operator GUI) | Operator management interface |
| TCP/8888 | Python SimpleHTTPServer 0.6 open directory | Toolkit staging |

Co-locating the operator GUI server (`TeamServer`) on the same IP as the victim-facing C2 and the staging directory is a significant operational-security failure. It establishes — at HIGH confidence — that this infrastructure is **attacker-controlled** rather than a compromised third-party host, because no legitimate compromise scenario explains an open AdaptixC2 TeamServer port adjacent to the C2.

The directory has remained **static since first crawl** (80+ hours observed as of analysis at 2026-04-30). A +1 week opendir-hunter rescan is scheduled for 2026-05-06 to confirm whether the operator becomes aware of the exposure and rotates infrastructure.

### 2.2 Toolkit composition

The open directory hosted a complete pre-assembled multi-platform attack toolkit comprising **30 unique artifacts** (28 named files plus two derived artifacts: one carved DLL embedded in the PowerShell loader, one extracted shellcode payload). The structure decomposes into clear functional layers:

| Layer | Tool | Source |
|---|---|---|
| C2 framework | AdaptixC2 (4 Windows beacon formats + Linux ELF agent + Gopher Go agent Windows variant) | Open-source, GPL-3.0, github.com/Adaptix-Framework/AdaptixC2 |
| Reverse-tunnel pivot | Ligolo-ng v0.8.3 stock upstream | Open-source, github.com/nicocha30/ligolo-ng |
| Reverse-tunnel pivot (alternative) | chisel | Open-source, github.com/jpillora/chisel |
| Initial-access wrapper (operator-written) | `beacon.ps1` PowerShell loader + `injector.dll` .NET CRT injector | **Custom — the only verified operator code** |
| Active Directory reconnaissance | SharpHound (.exe + .ps1), ADRecon.ps1, PowerView.ps1 | SpecterOps / commodity |
| Credential theft | mimikatz, lazagne (×2 variants), SharpDPAPI, SharpSecDump, Rubeus | Commodity |
| Privilege escalation | GodPotato, PrintSpoofer, RunasCs, winpeas, linpeas.sh, Certify | Commodity |
| Miscellaneous | Seatbelt, nc.exe (×2), download_exec.ps1 (template), amsi_bypass.ps1 | Commodity |

The kit covers the complete intrusion kill chain: initial PowerShell-staged execution → AdaptixC2 beacon C2 → AD enumeration → credential dumping via four vectors → privilege escalation via three mechanisms → lateral movement via two redundant tunneling tools → Linux post-exploitation pivot via the AdaptixC2 Linux ELF agent and `linpeas.sh`.

### 2.3 Build environment evidence

Strong evidence indicates the operator builds from a **Linux dev host**:

- **PDB path** in operator-written `injector.dll`: `/tmp/si_build/obj/Release/net472/si_build.pdb` (forward-slash Unix separators, `/tmp/` prefix, `dotnet build -c Release` standard output layout)
- **Toolchain** for AdaptixC2 Windows beacon: MinGW-w64 GCC with GNU ld 2.35 (verified from PE imports and section layout)
- **Build pipeline** for Ligolo binary: goreleaser (visible in embedded build metadata)
- **Build cadence**: Same-day dev/prod iteration captured on 2026-04-23 — dev build at 07:39:46 UTC (`embedded_dll.bin`, build counter 4) → production cluster at 20:34:31–32 UTC (build counter 5, all three production files within one second of each other)
- **AV detection at discovery**: 30/71 (cluster `agent.x64.dll`), 27/63 (`agent.x64.bin` shellcode form), 15/65 (Linux ELF `agent.bin`)

### 2.4 Framework provenance

AdaptixC2 was released August 2024 by GitHub user **RalfHacker** (Telegram `t.me/RalfHackerChannel` and `t.me/AdaptixFramework`, both Russian-language). Silent Push's August 2025 research surfaced developer-attribution evidence linking the RalfHacker handle to known Russian hacking forums and identified the author's stated profile as "penetration tester, red team operator, MalDev." Silent Push framed their assessment at "moderate confidence that ties between the two are non-trivial and worthy of inclusion and continued observation" — explicitly noting insufficient evidence to tie RalfHacker directly to malicious campaigns. Source: Silent Push, *AdaptixC2's Ties to Russian Criminal Underworld* (August 2025) — see Section 14.

**Important distinction for this report:** developer attribution is not operator attribution. This investigation targets the threat actor who *deployed* AdaptixC2 at `45.130.148.125`, not RalfHacker. The framework's GPL-3.0 license means anyone — defender, red-teamer, or threat actor — can compile and run it. The operator's identity is fully separate from the framework author.

### 2.5 Existing public coverage and what this report adds

AdaptixC2 framework reporting from Tier-1 vendors has been published since May 2025. Two pieces of existing public coverage are particularly relevant for any defender deploying detection content from this report:

- **Unit 42 (Palo Alto Networks), May 2025** — *AdaptixC2: A New Open-Source Framework Leveraged in Real-World Attacks*. Primary technical anchor for the framework. Documents the RC4 config layout (`[length][ciphertext][16-byte key]`), publishes a Python config-extractor tool, releases three YARA rules (covering `FileTimeToUnixTimestamp` / `Proxyfire_RecvProxy` time routines, base64 size-calculation patterns, and Go beacon-specific functions like `GetProcesses` / `ConnRead`), and walks two attack chains (Microsoft Teams phishing + Quick Assist social-engineering, plus AI-generated PowerShell delivery). Documents the framework's default C2 listener as `172.16.196.1:4443` (HTTPS), default URI `/uri.php`, default header `X-Beacon-Id`. Source: see Section 14.
- **Silent Push, August 2025** — *AdaptixC2's Ties to Russian Criminal Underworld*. Adds developer attribution to RalfHacker (above) and documents AdaptixC2 adoption by an unattributed initial-access broker via the CountLoader phishing chain. Source: see Section 14.

**Defenders should already have Unit 42's three YARA rules and the published config-extractor tool deployed.** The detection content released with this report is designed to *complement* that existing coverage — focusing on operator-specific UTA-2026-006 fingerprints and the operator's deviations from framework defaults — rather than duplicate it.

This investigation contributes original intelligence on five dimensions not present in any reviewed public source:

1. **Specific infrastructure identified:** `45.130.148.125` (AS35682 BEST INTERNET SOLUTION XK, Tashkent, Uzbekistan) — not present in any reviewed public source
2. **RC4 key recovered:** `f443b9ce7e0658900f6a7ff0991cdee6` (16 bytes, plaintext, adjacent to ciphertext) extracted via decompiler review and Python RC4 decryption. Unit 42 published the config-extractor tool but does not publish recovered keys for specific deployments.
3. **Build artifact fingerprints:** Same-day dev/prod build cadence, `/tmp/si_build/` PDB path, `si_build` class name, MinGW-w64 toolchain, per-listener IDs `0xbe4c0149` / `0xcb4e6379`, leftover `proxy_port = 3128` dev artifact, operator-added 4th URI `/jquery-3.3.1.min.js` deviating from the stock `/uri.php` default
4. **Complete toolkit inventory:** 28 named files documented including AdaptixC2 multi-format beacon cluster, Linux ELF Adaptix agent, Ligolo-ng v0.8.3 stock, full Ghostpack/SpecterOps suite
5. **Captured deployment package:** Static-since-discovery exposure window preserved the operator's deployment intact — a configuration rarely observable outside DFIR engagements

---

## 3. Kill Chain Overview

> **Analyst note:** This section walks the anticipated attack flow end-to-end at a high level so the rest of the report has a shared map. Each stage gets a plain-language description of what happens, who triggers it, and what the defender should look for. Sections 4 and 5 then go deep on each technical layer. If you only read one technical section, read this one — it gives you the shape of the campaign at one glance. **Important context:** no live victim traffic was captured. Every stage below is grounded in observable artifacts in the open directory (operator-written PowerShell loader, decompiled .NET injector, RC4-decrypted beacon configuration, and bundled toolkit composition) rather than in observed traffic.

The campaign's loader chain is single-path: PowerShell delivery converges to an AdaptixC2 beacon hosted in `explorer.exe`, after which the operator drives interactive post-exploitation against AD, credentials, privilege escalation, and ultimately a Linux pivot through Ligolo-ng or chisel. The infographic below shows the complete nine-stage anticipated kill chain. Section 4 (static findings) and Section 5 (behavioral / anticipated kill chain) walk each stage in technical depth.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-45-130-148-125-20260430/adaptixc2-kill-chain-overview.svg" | relative_url }}" alt="Vertical flowchart of the 9-stage AdaptixC2 anticipated kill chain. Stage 0 (orange) Initial Access via PowerShell delivery, vector unobserved. Stage 1 (red) AMSI Bypass via amsi+Con+text string concatenation, *iUtils reflection, SetValue($null, 0). Stage 2 (red) Reflective .NET Load of injector.dll into PowerShell memory via [System.Reflection.Assembly]::Load. Stage 3 (red) Shellcode Build and Decode via 31 chunked $sr += '...' base64 plus byte-by-byte XOR 0xA7. Stage 4 (red) Cross-Process Injection W^X-aware OpenProcess 0x1FFFFF then VirtualAllocEx RW 0x04 then WriteProcessMemory then VirtualProtectEx RX 0x20 then CreateRemoteThread into explorer.exe. Stage 5 (blue) RDI Bootstrap and Beacon Execution hosted in explorer.exe with no on-disk DLL artifact and no LoadLibrary event. Stage 6 (dark red) C2 Beacon HTTP plaintext POST to 45.130.148.125 port 80 cycling four URIs api/v1/status updates/check.php content.html jquery-3.3.1.min.js with X-Beacon-Id header and Firefox 20 User-Agent and 4-5 second sleep cadence and zero jitter and RC4 key f443b9ce…1cdee6. Stage 7 (purple) Active C2 with operator hands-on-keyboard post-exploitation toolkit covering AD recon SharpHound ADRecon PowerView Seatbelt and credential theft mimikatz SharpDPAPI SharpSecDump Rubeus lazagne and privilege escalation GodPotato PrintSpoofer RunasCs Certify winpeas. Stage 8 (dark red) Lateral and Linux Pivot via Ligolo-ng v0.8.3 TUN-mode and chisel reverse tunnels and AdaptixC2 Linux ELF Gopher variant agent and linpeas.sh.">
  <figcaption><em>Figure 1: Anticipated kill chain for the AdaptixC2 deployment at 45.130.148.125. Color coding (mapped to the site's severity palette where applicable): <span style="color:#f97316">orange</span> initial access · <span style="color:#dc2626">red</span> operator-controlled malicious code execution · <span style="color:#58a6ff">blue</span> hosted in legitimate Windows process · <span style="color:#a855f7">purple</span> staged commodity post-exploitation toolkit · <span style="color:#7f1d1d">deep red</span> network C2 and lateral pivot. Sections 4 and 5 walk each stage in technical depth.</em></figcaption>
</figure>

**Stage-by-stage detail at a glance:**

| Stage | What happens | What defenders see |
|---|---|---|
| 0 | Operator delivers `beacon.ps1` to a victim by an unobserved mechanism | `powershell.exe` process creation with non-standard command-line invoking the script |
| 1 | AMSI bypass via reflection: `'amsi'+'Con'+'text'` concatenation, `*iUtils` reflection, `SetValue($null, 0)` zeroing | PowerShell ScriptBlock logging (Event ID 4104) captures the script if enabled; AMSI Event ID 1100 may register the bypass |
| 2 | Reflective .NET load: `[Reflection.Assembly]::Load([Convert]::FromBase64String($dr))` of 5,120-byte `injector.dll` into PowerShell memory | No on-disk DLL artifact, no `LoadLibrary` event; visible only in ScriptBlock logging |
| 3 | Shellcode build (31 chunked `$sr += '...'` concatenations) + base64 decode + byte-by-byte XOR `0xA7` decrypt | Distinctive long-base64 + chunked-concatenation pattern in ScriptBlock logging; tool-generated payload format |
| 4 | Cross-process injection from `powershell.exe` into `explorer.exe`: `OpenProcess` → `VirtualAllocEx(RW)` → `WriteProcessMemory` → `VirtualProtectEx(RX)` → `CreateRemoteThread` | Sysmon Event ID 8 (CreateRemoteThread); Event ID 10 (ProcessAccess with `0x1FFFFF` granted access); the W^X allocation pattern (RW→RX, never RWX) is the operator's distinctive choice |
| 5 | RDI bootstrap walks PE headers and reflectively maps the embedded AdaptixC2 beacon DLL inside `explorer.exe`, jumps to `GetVersions` export | No `LoadLibrary` event; new RX memory region in `explorer.exe` containing the AdaptixC2 beacon |
| 6 | Beacon HTTP POST to `45.130.148.125:80` cycling four URIs, with `X-Beacon-Id` header + Firefox 20 UA, 4–5 second cadence, RC4-encrypted config | Outbound HTTP POST to fixed IP with the `X-Beacon-Id` + Firefox 20 UA combination — highest-fidelity AdaptixC2 framework signature |
| 7 | Operator drives the beacon interactively: AD recon (SharpHound, ADRecon, PowerView), credential theft (mimikatz, SharpDPAPI, lazagne, Rubeus), privilege escalation (GodPotato, PrintSpoofer, RunasCs, Certify) | Process tree from `explorer.exe` running commodity post-exploitation tooling; LSASS access events; AD enumeration LDAP queries |
| 8 | Lateral pivot via Ligolo-ng v0.8.3 (TUN-mode) or chisel; once a Linux foothold is reachable, the AdaptixC2 Linux ELF Gopher agent and `linpeas.sh` extend the kill chain into Linux post-exploitation | Outbound TUN/TCP tunnel from compromised host; Linux-side process / network telemetry for the Gopher ELF agent (no Sysmon for Linux — auditd / Sysmon-for-Linux required) |

**Time-to-impact: NOT MEASURED.** No live victim traffic was captured. Steps 0–6 are inferred from the operator-written loader's decoded logic plus framework documentation; steps 7–8 are inferred from the bundled toolkit composition. Upper-bound capability includes domain-wide AD enumeration, credential dumping, lateral movement, and Linux-host post-exploitation once a foothold is established.

---

## 4. Technical Analysis — Static Findings

> **Analysis tools referenced in this section.** The figures and screenshots throughout this section come from the analyst's static reverse-engineering toolchain. On first use these are: a disassembler/decompiler (Ghidra) for the C++ AdaptixC2 beacon, a .NET decompiler (dnSpy / ILSpy) for the operator's `injector.dll`, a PE-format inspection library (pefile) for compile-timestamp and export-table comparisons, and a Go-symbol recovery tool (GoReSym) for the Linux ELF agent. Subsequent mentions use the general category term only.

### 4.1 AdaptixC2 framework attribution and beacon cluster

> **Analyst note:** AdaptixC2 is a relatively young open-source post-exploitation framework (GPL-3.0, github.com/Adaptix-Framework/AdaptixC2). Its architecture is similar to Cobalt Strike: an operator-side TeamServer, victim-side beacons, and a plugin model for transports and extensions. This section walks through how we identified the beacon cluster as AdaptixC2 with high confidence, and what configuration the operator chose. The framework attribution is DEFINITE; the operator-specific configuration values (RC4 key, listener IDs) are recovered from the binary at byte level.

**Family attribution: DEFINITE (98%+).** Three independent vendor labels and a byte-for-byte architectural match against the framework's published documentation establish the family with no ambiguity.

| VT label | Source | Sample(s) |
|---|---|---|
| YARA `Windows_Trojan_Adaptix_b2cda978` | Elastic | `agent.x64.dll`, `agent.x64.bin` |
| `UDS:Backdoor.Win64.AdaptixC2.a` | Kaspersky | `agent.x64.dll` |
| `Backdoor:Win64/AdaptixC2.MKB!MTB` | Microsoft | `agent.x64.dll` |
| YARA `Adaptix_Beacon` | bartblaze | `agent.bin` (Linux ELF) |
| `HEUR:Backdoor.Linux.AdaptixGopher.a` | Kaspersky | `agent.bin` |
| `HackTool:Linux/AdaptixC2.A!MTB` | Microsoft | `agent.bin` |

**The cluster collapses to a single source build in four Windows formats** (build artifact metadata — file sizes, imphashes, and compile timestamps shown for technical context; full hash list with machine-readable context is in the linked IOC feed):

| File | Size | imphash | Compile timestamp | Form |
|---|---|---|---|---|
| `agent.x64.dll` | 185,856 B | `4cfec38bf3c1557ad25faba737f8e275` | 2026-04-23 20:34:32 UTC | DLL |
| `msupdate.dll` | 185,856 B | `4cfec38bf3c1557ad25faba737f8e275` | 2026-04-23 20:34:32 UTC | DLL renamed for sideload (1-byte diff in `.edata` from rename) |
| `agent.x64.exe` | 185,344 B | `63cb3b95faad6b28fcce52a6aa698ff2` | 2026-04-23 20:34:31 UTC | EXE-form sibling (1 second earlier) |
| `agent.x64.bin` | 184,832 B | — | (PE headers stripped) | Shellcode-form |
| `agent.bin` | 6,431,856 B | — | — | AdaptixC2 Linux ELF agent (Gopher Linux variant) |
| `embedded_dll.bin` (carved) | 184,832 B | `f67fc0b1a6e0c3b07adb524e2db8774f` | 2026-04-23 07:39:46 UTC | Earlier dev build, embedded in `beacon.ps1` for PowerShell delivery |

That four formats with three distinct imphashes all collapse to one source illustrates AdaptixC2's documented multi-format build pipeline — the same beacon source produces `.dll`, `.exe`, raw shellcode, and a sideload-renamed `.dll` from a single build session.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-45-130-148-125-20260430/adaptixc2-cluster-compile-timestamps.png" | relative_url }}" alt="pefile inspection output showing compile timestamps for embedded_dll.bin (UTC 2026-04-23 07:39:46) and the cluster sample agent.x64.dll (UTC 2026-04-23 20:34:32) — same date, ~13 hours apart, demonstrating the same-day dev-to-prod build cadence">
  <figcaption><em>Figure 1: Compile timestamps recovered from the dev build (`embedded_dll.bin`, 07:39:46 UTC) and the production build (`agent.x64.dll`, 20:34:32 UTC) place the operator's full dev-to-prod cycle inside a single day on 2026-04-23 — a sub-mature build cadence consistent with the operator's other OpSec failures (PDB path, dev-leftover proxy port).</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-45-130-148-125-20260430/adaptixc2-cluster-getversions-mangling.png" | relative_url }}" alt="pefile inspection comparing exports of the embedded dev DLL versus the production beacon: embedded_dll.bin exports `_Z11GetVersionsv` (Itanium-ABI mangled, C++ linkage) at offset 0x145B0, while agent.x64.dll exports the unmangled `GetVersions` at offset 0x146A4">
  <figcaption><em>Figure 2: The dev build exports the Itanium-ABI mangled name `_Z11GetVersionsv` while the production build exports the unmangled `GetVersions`. Both samples come from the same source (the AdaptixC2 RDI loader entry-point) but were produced under different MinGW-w64 build configurations — the kind of fingerprint that cleanly distinguishes pre-release iteration from final delivery artifacts.</em></figcaption>
</figure>

**File characteristics:**
- **Toolchain:** MinGW-w64 GCC, GNU ld 2.35 (Binutils linker version)
- **Build environment:** Linux (PDB path recovered from operator-written `.NET injector.dll`)
- **PE sections:** `.text/.data/.rdata/.pdata/.xdata/.bss/.edata/.idata/.CRT/.tls/.reloc` — MinGW-w64 standard layout
- **Subsystem:** GUI (DLLs and EXE both)
- **Imports:** 49 (DLL form), 59 (EXE form) — minimal; **no networking imports in the IAT**
- **Overall entropy:** 5.95 — within MinGW-built C++ binary norms; not packed
- **Export name:** `GetVersions` — verified STOCK AdaptixC2 RDI (Reflective DLL Injection) loader entry-point name (defined in `src_beacon/beacon/main.cpp` for both BUILD_DLL and BUILD_SHELLCODE configs)

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-45-130-148-125-20260430/adaptixc2-mingw-runtime-strings.png" | relative_url }}" alt="Strings extracted from the beacon shellcode showing GCC/MinGW-w64 runtime error messages including 'Mingw-w64 runtime failure:', 'VirtualQuery failed for %d bytes at address %p', 'VirtualProtect failed with code 0x%x', and `__gnu_cxx::__concurrence_unlock_error` — all distinctive of the MinGW-w64 GCC C++ runtime">
  <figcaption><em>Figure 3: GCC and MinGW-w64 runtime strings recovered from the beacon shellcode confirm the Linux-cross-compiled MinGW-w64 toolchain. Combined with the GNU ld 2.35 linker version stamp and the standard MinGW-w64 PE section layout, this rules out the alternative hypothesis that the beacon was built with MSVC (which would imply a different operator profile).</em></figcaption>
</figure>

The absence of networking imports in the IAT is significant: the beacon resolves all network APIs at runtime via `LoadLibrary` + `GetProcAddress` calls inside its C2 transport plugin (an established AdaptixC2 framework feature, not operator customization). This defeats static IAT-based hunting.

> **Analyst note — what "RDI bootstrap" means:** Reflective DLL Injection is a technique where instead of writing a DLL to disk and using `LoadLibrary`, the malware embeds a small bootstrap routine that walks the PE headers of an in-memory DLL and maps it manually into a process. The benefit to the attacker: no on-disk DLL artifact, no `LoadLibrary` event for EDRs to log. AdaptixC2 ships this RDI bootstrap as part of the framework — it is NOT operator-written here.

### 4.2 RC4-encrypted beacon configuration (recovered key + parsed config — layout matches stock AdaptixC2 framework source)

> **Analyst note:** AdaptixC2 stores its per-listener configuration (C2 IP/port/URIs/User-Agent/sleep timing/etc.) as an RC4-encrypted blob inside the beacon binary's `.rdata` section. The 16-byte RC4 key is stored adjacent to the ciphertext **in plaintext** inside the same blob. This is by design — the framework lets defenders recover the configuration from any sample with no key cracking required, but in exchange the operator gets a self-contained beacon that doesn't need a secondary key delivery step. Below is the recovered layout.

**RC4 key origin (HIGH confidence, 90%):** Source-code review of the AdaptixC2 server (`AdaptixServer/extenders/beacon_listener_http/ax_config.axs` on `github.com/Adaptix-Framework/AdaptixC2`) confirms the 16-byte RC4 key is generated by the AdaptixClient at listener-creation time via `ax.random_string(32, "hex")` (32 hex characters = 16 bytes). The server-side build pipeline (`AdaptixServer/extenders/beacon_agent/pl_main.go`) reads it from `listenerMap["encrypt_key"]` and packs it into the `[length][ciphertext][key]` envelope, with the key positioned outside the encrypted region. The key is therefore **per-listener-instance, not framework-default and not operator-chosen**. This is the analytical basis for treating `f443b9ce7e0658900f6a7ff0991cdee6` as a UTA-2026-006 fingerprint: a different operator running AdaptixC2 would produce a different key on their listener generation; the key changes only if this operator regenerates the listener. The byte-identical encrypted blob across the dev (07:39 UTC) and prod (20:34 UTC) builds confirms both came from one listener instance on this operator's TeamServer.

**Config blob layout:**

```
[0x000  4 bytes]  Length prefix       = 0x011b = 283 bytes
[0x004  283 B  ]  RC4-encrypted blob  (ciphertext)
[0x11F  16 B   ]  RC4 key (PLAINTEXT, adjacent to ciphertext)
                  = f4 43 b9 ce 7e 06 58 90 0f 6a 7f f0 99 1c de e6
Total: 303 bytes (= 0x12f) at .rdata offset 0
```

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-45-130-148-125-20260430/adaptixc2-rc4-blob-getter-pair-ghidra.png" | relative_url }}" alt="Ghidra disassembly of two paired getter functions FUN_618c13a0 and FUN_618c13ad, each consisting of LEA RAX into the .rdata data segment followed by RET — these accessor pair functions return the encrypted blob's base address and its length to the AdaptixC2 RC4 decryptor">
  <figcaption><em>Figure 4: The encrypted blob's storage location is reachable through a pair of accessor functions `FUN_618c13a0` (returns blob base address) and `FUN_618c13ad` (returns blob length). Locating these getter functions is the first step in recovering the configuration: their cross-references identify the deserializer and the RC4 routine downstream.</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-45-130-148-125-20260430/adaptixc2-rc4-blob-303bytes-hex.png" | relative_url }}" alt="Hex dump of the 303-byte encrypted configuration blob showing the 4-byte length prefix at offset 0x000, 283 bytes of high-entropy ciphertext, and the 16-byte plaintext RC4 key adjacent to the ciphertext at offset 0x11F — visible printable strings near the bottom suggest sample text values 'pure virtual met...', 'api-ms-win-..ext-...', 'method called', 'deleted virtual'">
  <figcaption><em>Figure 5: The 303-byte encrypted-config blob in `.rdata`. The plaintext 16-byte RC4 key sits immediately after the ciphertext — by AdaptixC2 framework design, not by operator error. This storage layout is what makes RC4 recovery deterministic for any AdaptixC2 sample without key cracking.</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-45-130-148-125-20260430/adaptixc2-rc4-decrypt-function.png" | relative_url }}" alt="Ghidra decompiler view of FUN_618ccf39 with parameters (longlong param_1, int param_2, longlong param_3, int param_4) and a 256-byte local stack buffer 'local_108[256]' that calls FUN_618ccd40 (RC4 KSA — key scheduling) and FUN_618cce2a (RC4 PRGA — pseudo-random generator) — the canonical RC4 init+decrypt structure">
  <figcaption><em>Figure 6: The AdaptixC2 RC4 decrypt routine `FUN_618ccf39`. The 256-byte stack buffer is the RC4 S-box; the two helper calls are the RC4 key-scheduling and pseudo-random-generator stages. Identifying this pair confirms RC4-128 is the framework's symmetric algorithm and allows offline decryption with the recovered key.</em></figcaption>
</figure>

The encrypted blob is byte-identical between the dev (07:39 UTC) and production (20:34 UTC) builds — the same source rebuild, only the in-config `sleep_delay` field differs (4 seconds dev → 5 seconds prod). This proves the operator did not regenerate the listener key between builds; both came from one AdaptixC2 listener instance on the operator's TeamServer.

**Recovered configuration (RC4-decrypted, schema-walked against `AgentConfig.cpp` from the framework source):**

| Offset | Field | Value | Notes |
|---|---|---|---|
| 0x00 | `agent_type` | `0xbe4c0149` | Server-assigned per-agent ID |
| 0x04 | `kill_date` | 0 | None |
| 0x08 | `working_time` | 0 | 24/7 |
| **0x0c** | **`sleep_delay`** | **4 (dev) → 5 (prod) seconds** | Aggressive 4–5s callback cadence |
| 0x10 | `jitter_delay` | 0 | Deterministic timing |
| 0x14 | `listener_type` | `0xcb4e6379` | Server-assigned per-listener ID |
| 0x18 | `use_ssl` | 0 | HTTP plaintext, no TLS |
| 0x19+ | `servers[1]` | `45.130.148.125` | C2 endpoint |
| 0x30 | `ports[0]` | 80 | Operator-chosen (stock default = 443) |
| 0x34+ | `http_method` | POST | Stock |
| 0x3D+ | `uris[4]` | `/api/v1/status`, `/updates/check.php`, `/content.html`, `/jquery-3.3.1.min.js` | First three are AdaptixC2 listener defaults; the fourth is **operator-added** |
| 0x96+ | `parameter` | `X-Beacon-Id` | Stock heartbeat header field name |
| 0xA6+ | `user_agents[1]` | `Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0` | **Stock AdaptixC2 default UA — Firefox 20 from February 2013** |
| 0xF0+ | `http_headers` | `\r\n` (empty separator) | No extra headers |
| **0x10F** | **`proxy_port` (DEV BUILD ONLY)** | **3128** (zeroed in prod) | Squid HTTP proxy default port. **Operator developed through a local HTTP proxy for traffic inspection**, then forgot to clear the field before submitting the dev build to staging. |

The stock Firefox 20 User-Agent is a 13-year-old fingerprint that no real browser sends in 2026 — it is one of the most reliable anomalies for hunting stock-AdaptixC2 deployments. The leftover `proxy_port = 3128` dev artifact is an operator-distinctive OpSec failure: it indicates the operator iteratively tested the listener through a local Squid/Burp/mitmproxy instance during development, and inadvertently shipped that artifact into the staging endpoint.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-45-130-148-125-20260430/adaptixc2-rc4-decrypted-config.png" | relative_url }}" alt="RC4-decrypted configuration recovered from both embedded_dll.bin (dev build) and agent.x64.dll (production build) — terminal output showing identical config blobs in both samples: .rdata offset 0x27a00, length prefix 0x11b (283 bytes), RC4 key f443b9ce7e0658900f6a7ff0991cdee6, and printable strings revealing C2 IP 45.130.148.125, HTTP method POST, four URI paths /api/v1/status, /updates/check.php, /content.html, /jquery-3.3.1.min.js, X-Beacon-Id header, Firefox 20 User-Agent string">
  <figcaption><em>Figure 7: Decrypted-configuration output from both the dev build (`embedded_dll.bin`) and the production build (`agent.x64.dll`). The two configurations are byte-identical for every field except `sleep_delay` — the operator did not regenerate the listener key between iterations. This is the headline evidence: a single AdaptixC2 listener instance on the operator's TeamServer produced both builds, and every recovered indicator (C2 IP, RC4 key, listener type IDs, URI set) traces back to that same listener.</em></figcaption>
</figure>

**RTTI and class-hierarchy strings leaked in plaintext:**
- `9Connector` — Itanium-ABI typeinfo for AdaptixC2 stock `Connector` base class (the digit `9` is the Itanium-ABI mangled length prefix)
- `13ConnectorHTTP` — Itanium-ABI typeinfo for the HTTP transport plugin derived class
- `\\.\pipe\%08lx` — AdaptixC2's framework-wide SMB transport plumbing template

These RTTI strings (combined with `GetVersions`, `Mingw-w64 runtime failure:`, and `X-Beacon-Id`) form the strongest stock-framework YARA target — they catch any operator running stock AdaptixC2 with default connector names, not just this campaign's binaries.

### 4.3 Operator-written PowerShell + .NET injector (the only custom code)

> **Analyst note:** This is the operator's hand-written delivery layer. AdaptixC2's official framework templates support Go, C++, and Rust implants — but no .NET / C# templates exist. That makes the `injector.dll` here unambiguously operator-authored. The `beacon.ps1` PowerShell loader and the `injector.dll` are a matched pair: the loader invokes a `[SI]::Inject()` method that exists only inside the operator's injector. Together they are the highest-fidelity actor fingerprint in the kit.

#### 4.3.1 `beacon.ps1` — 5-block PowerShell loader

| Field | Value |
|---|---|
| Filename | `beacon.ps1` |
| SHA256 | `b4ffd7ca8f5505fd7b71882c67712e896c9d170a3b3b581baba78ee5d1c2b858` |
| Size | 256,356 B (256 KB), 52 lines |
| Overall entropy | 5.69 — characteristic of base64-encoded data (base64 alphabet caps near 6.0; raw encrypted bytes would push 7.99) |

**Block-by-block logic:**

1. **AMSI bypass (lines 1–5).** The loader uses `$q='amsi'+'Con'+'text'` string concatenation to defeat source-text AV signatures that look for the literal string `amsiContext`. It then enumerates types in the current AppDomain via `[Ref].Assembly.GetTypes() | ?{$_.Name -like '*iUtils'}` to find the `AmsiUtils` class without naming it directly. It calls `SetValue($null, 0)` on the `NonPublic, Static` field `amsiContext`, zeroing the AMSI session context pointer. From that point onward, every call to `AmsiScanBuffer` no-ops silently. The lineage of this bypass is the well-documented Matt Graeber reflection technique.

2. **Reflective .NET load (lines 7–9).** The loader has a `$dr` base64 blob (6,838 chars → ~5.1 KB raw) that decodes to an MZ header — a PE file. `[System.Reflection.Assembly]::Load([Convert]::FromBase64String($dr))` loads the assembly directly into PowerShell process memory. There is **no `Add-Type` call, no temp file, no on-disk artifact**. The loaded assembly exposes a class `SI` with a static method `Inject(uint32 pid, byte[] sc)`.

3. **Shellcode build (lines 11–42).** 31 chunked `$sr += '...'` concatenations build a ~250 KB base64 string. The chunked-concatenation form is a tool-generated payload format used by Cobalt Strike's Artifact Kit `psh` template, by Brute Ratel's PowerShell loader, and by several open-source loader generators — all designed to dodge AV signatures that look for long base64 strings.

4. **Decrypt (lines 43–45).** `$enc = [Convert]::FromBase64String($sr)`, then a byte-by-byte XOR with `0xA7` produces the raw shellcode (~250 KB).

5. **Inject (lines 47–52).** `$ep = (Get-Process explorer ...).Id` selects the first `explorer.exe` PID found (no `SessionId` filter — accepts whichever explorer the loader sees first). `[SI]::Inject([uint32]$ep, $sc)` invokes the operator's `injector.dll` to perform the cross-process injection.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-45-130-148-125-20260430/adaptixc2-uta2026-006-beacon-ps1-loader.png" | relative_url }}" alt="VS Code editor showing the operator-written beacon.ps1 loader source: AMSI bypass via $q='amsi'+'Con'+'text' string concatenation, [Ref].Assembly.GetTypes pipeline filtering on '*iUtils', SetValue($null,0); reflective .NET load via [System.Reflection.Assembly]::Load([Convert]::FromBase64String($dr)); chunked $sr += '...' base64 shellcode build; XOR 0xA7 byte-by-byte decrypt; Get-Process explorer with [SI]::Inject([uint32]$ep, $sc) invocation">
  <figcaption><em>Figure 8: The operator's `beacon.ps1` 5-stage loader chain. The reflective `[SI]::Inject(...)` call near the bottom is the matched pair to the operator's `injector.dll` — the method exists nowhere else in the public AdaptixC2 framework. Together with the AMSI-bypass-then-reflection-load-then-XOR-then-inject sequencing, this loader is one of the strongest UTA-2026-006 fingerprints.</em></figcaption>
</figure>

#### 4.3.2 `injector.dll` — `SI.Inject` .NET v4.7.2 process injector

| Field | Value |
|---|---|
| SHA256 | `5ea265ad3e6429cd2e8d9831360f7e2be9b8ba5a5b32a4a60c5c956a3f8fb285` |
| Size | 5,120 B |
| Type | PE32, .NET Framework v4.7.2 (CLR v4.0.30319) |
| Compile timestamp | `2057-03-14 12:08:39 UTC` (deterministic Roslyn build — content hash, NOT real time) |
| Version info | CompanyName / FileDescription / InternalName / OriginalFilename = `si_build` |
| **PDB path** | `/tmp/si_build/obj/Release/net472/si_build.pdb` — Linux-built (forward slashes, `/tmp/` prefix). Strong actor build-environment fingerprint. |

**Win32 P/Invoke chain in declaration order:**

`OpenProcess` → `VirtualAllocEx` → `VirtualProtectEx` → `WriteProcessMemory` → `CreateRemoteThread` → `WaitForSingleObject` → `CloseHandle` → `FlushInstructionCache`

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-45-130-148-125-20260430/adaptixc2-uta2026-006-si-inject-dnspy.png" | relative_url }}" alt="dnSpy decompilation of the public static bool Inject(uint pid, byte[] sc) method on class SI showing the cross-process injection chain — OpenProcess(0x1FFFFF, false, pid), VirtualAllocEx(IntPtr, IntPtr.Zero, (UIntPtr)((ulong)sc.Length), 12288u, 4u), VirtualProtectEx(IntPtr, IntPtr, (UIntPtr)((ulong)sc.Length), 32u), WriteProcessMemory(IntPtr, IntPtr, sc, (UIntPtr)((ulong)sc.Length), ref zero), CreateRemoteThread(IntPtr, IntPtr.Zero, 32u, IntPtr, IntPtr.Zero, 0u, ref num), WaitForSingleObject(IntPtr2, 3000u), FlushInstructionCache, CloseHandle">
  <figcaption><em>Figure 9: dnSpy decompilation of the operator's `SI.Inject(uint pid, byte[] sc)` method. The numeric magic constants visible in the declaration — `0x1FFFFF` (PROCESS_ALL_ACCESS), `12288` = `0x3000` (MEM_COMMIT \| MEM_RESERVE), `4` (PAGE_READWRITE), `32` = `0x20` (PAGE_EXECUTE_READ) — encode the W^X-aware allocation pattern (RW alloc → write → flip to RX) discussed in this section. The decompilation output also confirms the operator did not obfuscate parameter names or use D/Invoke — the `OpenProcess`/`VirtualAllocEx`/etc. P/Invoke declarations are visible in the assembly's `ImplMap` metadata for any defender to enumerate.</em></figcaption>
</figure>

This is **textbook `CreateRemoteThread` classic PE injection**. It is NOT Cobalt Strike Artifact Kit's `NtCreateThreadEx` / `RtlCreateUserThread` evasion variant — the operator chose the most-visible, easiest-to-detect injection primitive but added a single sophistication choice on the memory protection flags (next paragraph).

**Magic constants (operator's choices):**

| Value | Constant | Sophistication signal |
|---|---|---|
| `0x1FFFFF` | `PROCESS_ALL_ACCESS` | Lazy — broadest-possible access mask, easy EDR detection target |
| `0x3000` | `MEM_COMMIT \| MEM_RESERVE` | Standard |
| `0x04` (alloc) | `PAGE_READWRITE` | **W^X-aware — allocate as RW first** |
| `0x20` (protect) | `PAGE_EXECUTE_READ` | **W^X-aware — flip to RX (NOT RWX 0x40)** |
| `3000` ms | `WaitForSingleObject` timeout | Implies bootstrap returns quickly (RDI design) |

The W^X-aware allocation pattern is the **single defining tradecraft choice** in this injector. EDR products frequently look for `PAGE_EXECUTE_READWRITE` (RWX, value `0x40`) memory in remote processes as a high-fidelity injection signal. By allocating RW first, writing the shellcode, and then flipping to RX with `VirtualProtectEx`, the operator defeats that simple rule. Combined with everything else in the injector being lazy (single-letter parameters in P/Invoke declarations, no anti-debug, no D/Invoke, no direct syscalls), the assessment is mid-tier with selective sophistication: the operator knows the W^X-evasion principle (the #1 EDR-detection gotcha for process injection) but has no other anti-detection tradecraft.

> **What this means:** Imagine a courier who is careful about which mailbox they drop a package in (knowing some are watched), but who walks up to that mailbox in plain sight, wearing their work uniform, in a marked truck. The W^X protection-flag flip is the careful mailbox choice. Everything else — the broad `PROCESS_ALL_ACCESS` access mask, the lack of syscall obfuscation, the choice of `CreateRemoteThread` over `NtCreateThreadEx`, and the .NET P/Invoke declarations (visible in the assembly's `ImplMap` metadata) that announce every Win32 import the injector uses — is the marked truck. Mid-tier means *capable, not a developer*.

#### 4.3.3 Embedded MinGW-w64 RDI bootstrap

The XOR-decoded `$sr` shellcode (~185 KB) decomposes as:

- **First 1,023 bytes (0x000–0x3FE):** A custom MinGW-w64 GCC-compiled Reflective DLL Injection bootstrap. Walks PE headers inline, with the GCC x64 register-save prologue `AWAVAUATUWVSH` and GCC alignment NOPs `66 2E 0F 1F 84 00 00 00 00 00`.
- **MZ at offset 0x3FF:** A plaintext embedded PE — the AdaptixC2 dev build (`embedded_dll.bin`, 184,832 B, build counter 4).

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-45-130-148-125-20260430/adaptixc2-shellcode-mzscan-offset3ff.png" | relative_url }}" alt="PowerShell terminal output of an MZ-header scan across the full beacon shellcode showing 'Found 1 valid MZ+PE matches: Offset 0x3FF' and a 'Strings: family / wrapper / C2 markers' annotation, plus a Duration of 0.056188 seconds">
  <figcaption><em>Figure 10: MZ-header scan across the XOR-decoded shellcode locates exactly one embedded PE at offset `0x3FF` (1,023 bytes from the start). The 1,023-byte preamble is the RDI bootstrap; the embedded PE is the AdaptixC2 beacon dev build delivered by the operator's loader.</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-45-130-148-125-20260430/adaptixc2-rdi-bootstrap-prologue-hex.png" | relative_url }}" alt="Hex dump of the first 32 bytes of the beacon shellcode showing the GCC x64 register-save prologue: 56 48 89 E6 (PUSH RSI; MOV RSI, RSP), 48 83 E4 F0 (AND RSP, -16 stack alignment), 48 83 EC 20 (SUB RSP, 0x20), E8 1C 01 00 00 (CALL relative 0x11C) — followed by additional GCC-style instructions consistent with an inline PE-mapping routine">
  <figcaption><em>Figure 11: First 32 bytes of the beacon shellcode showing the GCC x64 prologue. The sequence is consistent with a MinGW-w64-compiled Reflective DLL Injection bootstrap rather than Donut's MSVC-compiled prologue (the toolchain mismatch is one of the reasons Donut was excluded as the wrapper origin in this section).</em></figcaption>
</figure>

This is **not Donut** (the open-source PE-to-shellcode converter). The MinGW-w64 toolchain mismatch (Donut uses MSVC), the plaintext embedded PE (Donut applies Chaskey encryption), and the section names matching MinGW-w64 conventions exclude Donut. Whether the RDI bootstrap is operator-written or sourced from AdaptixC2's Extender-Template-Generators "post-build wrapper pipeline" is an open question; both possibilities are compatible with the evidence.

### 4.4 Linux and Go agent components

#### 4.4.1 AdaptixC2 Linux ELF agent — `agent.bin` (Gopher Linux variant)

> **Analyst note:** This subsection covers the Linux-side beacon shipped in the open directory. Most defenders will not be familiar with Linux-host post-exploitation telemetry (no Sysmon for Linux, EDR coverage uneven on Linux servers); the takeaway is that the operator anticipated a Windows-foothold-to-Linux-pivot kill chain and brought a fully-fledged Linux beacon to do it. Detection requires Linux-side process / network telemetry, not Windows EDR.

| Field | Value |
|---|---|
| Filename | `agent.bin` |
| Size | 6,431,856 B (6.13 MB) |
| Type | ELF 64-bit |
| Family | AdaptixC2 Linux agent (Gopher Linux variant) |
| VT detections | 15/65 |
| Sandbox classification | "GO Backdoor" (Zenbox Linux) |

This binary confirms the operator anticipated and deployed Linux post-exploitation capability beyond just bundling `linpeas.sh`. Combined with the bundled Ligolo-ng v0.8.3 reverse-tunneling agent, the kit composition explicitly anticipates a Windows initial access → internal-network pivot → Linux LPE chain.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-45-130-148-125-20260430/adaptixc2-gopher-goresym-packages.png" | relative_url }}" alt="GoReSym output for the Linux ELF agent showing Go import paths including 'crypto/tls/internal/fips140tls', 'github.com/coder/websocket' and its internal subpackages, 'go-ping/ping', 'github.com/hashicorp/yamux', multiple 'github.com/nicocha30/ligolo-ng/pkg/agent', '.../pkg/neterror', '.../pkg/protocol', '.../pkg/relay', '.../pkg/utils', and a series of 'github.com/shamaton/msgpack/v2/...' packages plus 'gopkg.in/sirupsen/logrus' and 'golang.org/x/crypto/acme'">
  <figcaption><em>Figure 12: GoReSym extraction of the Linux ELF agent's Go package imports reveals tightly-integrated `nicocha30/ligolo-ng` packages (agent / neterror / protocol / relay / utils) alongside the AdaptixC2 Gopher framework's `shamaton/msgpack/v2` and `coder/websocket` dependencies. The presence of the Ligolo-ng package set inside the same binary as the AdaptixC2 Linux beacon — rather than as a separate tool — confirms the Linux pivot path is a first-class capability of the operator's deployed kit.</em></figcaption>
</figure>

#### 4.4.2 AdaptixC2 Gopher Go agent (Windows variant) — `gopher.x64.exe`

> **Analyst note:** "Gopher" is AdaptixC2's Go-language agent variant — a separate beacon implementation written in Go rather than the C++ default. It exists for portability (single binary, no Windows runtime dependency) and to defeat detection that keys on the C++ beacon's RTTI strings or section layout. From a defender perspective, Gopher beacons in the wild require Go-aware static analysis (function naming patterns differ from C++ binaries) and may evade YARA rules tuned to the C++ variant.

| Field | Value |
|---|---|
| SHA256 | `f68507d88b007817901ffe3537a2d3935de53344ddfb6f0838d4141e3c02e07d` |
| Size | 6,048,768 B (5.77 MB) |
| Compiler | Go 1.25.4, CGO_ENABLED=0, `-trimpath` set, GOOS=windows, GOARCH=amd64 |
| User functions | 1,332 (significant codebase) |
| VCS revision | `a4b80bf370f704d6843e69433bfb5c06274f57df` (Git SHA1) at 2026-03-04 20:36:06 UTC |
| `vcs.modified` | `true` (uncommitted changes at build time — benign goreleaser-build-dir noise) |

Capabilities visible from package list: full **Cobalt Strike Beacon Object File (BOF) execution runtime in pure Go** (`gopher/bof/{binutil,boffer,coffer,defwin,memory}` package set — matches AdaptixC2's stock Gopher structure, NOT operator-custom; confirmed by Kaspersky labeling the Linux sibling `AdaptixGopher`); screen capture (`kbinani/screenshot`); pseudoterminal access (`gabemarshall/pty`); Windows API access (`lxn/win`); and a **MessagePack-encoded C2 protocol** (`vmihailenco/msgpack/v5`).

#### 4.4.3 Ligolo-ng v0.8.3 stock — `agent.exe`

| Field | Value |
|---|---|
| SHA256 | `4b41f36f82db6da8767a0a1c2997c8242d80b2d10a8f1d28c252a9306ec152b5` |
| Size | 7,302,656 B (7.30 MB) |
| Compiler | Go 1.24.0, goreleaser-built |
| Embedded ldflags | `-X main.version=0.8.3 -X main.commit=913fe64e088d5db2185d392965bf4cd3dd1d9495 -X main.date=2026-02-15T13:26:35Z -X main.builtBy=goreleaser` |
| Family | Ligolo-ng v0.8.3 stock upstream (commit `913fe64e...` matches upstream v0.8.3 release tag) |
| Capability | TUN-mode reverse-tunneling agent for lateral pivoting |

This is unmodified upstream Ligolo-ng. The detection-engineering note here is critical: Ligolo, chisel, and the Gopher Go agent all trigger an identical Go-runtime YARA noise cluster including `MALWARE_RULES: PoetRat_Python` (these Go binaries are NOT PoetRAT), `BASE64_table`, `DebuggerCheck__QueryInfo`, `disable_dep`, and `android_meterpreter` (deprecated). **These false-positive patterns must NOT be used as detection pivots** — they fire on legitimate Go binaries widely. The detection rule set published with this report explicitly filters this noise cluster.

### 4.5 Selective AV-evasion on commodity tools

> **Analyst note:** "Entropy" measures how random a file's bytes look. A normal compiled program has entropy around 5–6.5; encrypted or compressed data sits at 7+. A high-entropy ratio across a binary (most chunks looking random) is the classic signal that a file has been packed or obfuscated to defeat signature-based AV. This subsection documents which commodity tools the operator chose to pack and which they left alone — the *pattern* of choice (heavy on some, none on others) is itself a tradecraft fingerprint.

The operator wraps a **subset** of commodity tools with heavy obfuscation while leaving most others untouched. This is selective AV-evasion targeting the highest-signature targets, not blanket evasion — a tradecraft signal that is documented as Characteristic 7 of UTA-2026-006.

**Finding 1 — `SharpHound.exe` (1.35 MB) is heavily packed (HIGH confidence):**

| Metric | This sample | Other commodity .NET tools (Rubeus, SharpDPAPI, Certify, Seatbelt) |
|---|---|---|
| Size | 1.35 MB | 174 KB – 597 KB |
| Overall entropy | **7.91** | 5.33 – 6.58 |
| High-entropy chunk ratio | **86%** (284 of 330 chunks) | 0% – 23% |

86% high-entropy is well outside the range for a vanilla SharpHound .NET assembly (which should resemble the other commodity .NET tools at entropy 5.5–6.5). Plausible explanations: a .NET obfuscator (ConfuserEx, .NET Reactor, Eazfuscator), a Costura.Fody / merged-DLL build, or a trojanized variant. Confirmation requires lab-VM `de4dot` deobfuscation, which is out of scope for static analysis.

**Finding 2 — `lazagne.exe` 10 MB variant is heavily packed (MODERATE confidence):**

| Metric | 324 KB vanilla variant | 10 MB variant |
|---|---|---|
| Size | 324,096 B | 10,136,093 B (**31× larger**) |
| Overall entropy | 6.71 (normal PyInstaller) | **7.99** (heavily packed) |
| High-entropy chunks | 13/80 (16%) | **2,404/2,475 (97%)** |
| YARA packers | (none) | `IsPacked`, `HasOverlay`, `HasDebugData`, `HasRichSignature` |
| YARA anti-analysis | (none) | `anti_dbg`, `DebuggerException__SetConsoleCtrl` |

97% high-entropy plus `IsPacked` plus anti-debug behavior strongly suggests UPX-on-top-of-PyInstaller wrapping or a stock newer lazagne v2.x with `--collect-all` plus UPX. Pairs with the SharpHound finding to suggest selective operator AV-evasion targeting the most-signatured commodity tools.

**Other commodity tools** (Rubeus, SharpDPAPI, mimikatz, Seatbelt, RunasCs, Certify, GodPotato, PrintSpoofer, winpeas, the 324 KB lazagne, chisel) show **NO** packing anomalies. The operator knows what is heavily detected and applies obfuscation where it pays off.

### 4.6 Commodity post-exploitation toolkit (brief inventory)

The kit's commodity component is hash-confirmed against public releases and triggers each tool's expected family YARA — no signs of trojanization. This inventory is included for completeness and to support detection content cross-reference:

- `Rubeus.exe` (1bfbefa4..., 415 KB) — `HKTL_NET_GUID_Rubeus` — Kerberos abuse (Kerberoasting + AS-REP Roasting)
- `SharpDPAPI.exe` (277ff280..., 597 KB) — `HKTL_NET_GUID_SharpDPAPI` — credential decryption
- `RunasCs.exe` (29955ba1..., 84 KB) — `HKTL_NET_NAME_RunasCs` — credentialed process spawn
- `nc.exe` (×2 variants) — classic netcat
- `Certify.exe` (af5c3a5f..., 174 KB) — AD CS abuse
- `chisel.exe` (5db5e7f6..., 10.93 MB, jpillora/chisel) — second commodity reverse-tunneling tool alongside Ligolo
- `mimikatz.exe` (61c0810a..., 1.36 MB, gentilkiwi v2.2.0) — credential dumping
- `PrintSpoofer.exe` (8524fbc0..., 26 KB) — local privilege escalation
- `GodPotato.exe` (9a8e9d58..., 57 KB) — local privilege escalation
- `Seatbelt.exe` (cb5a0790..., 372 KB) — situational awareness
- `winpeas.exe` (ce709770..., 945 KB) — Windows enumeration
- `lazagne.exe` 324 KB stock variant (d9be165f...) — Python credential extractor
- `ADRecon.ps1` (ec54e9e5..., 596 KB) — AD reconnaissance
- `PowerView.ps1` (507e8666...) — AD enumeration; **detection-engineer must filter the `MALWARE_RULES: spyeye` false-positive on this file** (PowerView is commodity AD recon, not SpyEye banking malware)
- `SharpHound.ps1` (f887e04c...) — AD ingestor
- `download_exec.ps1` (fd9e3ad7..., 203 B) — uncustomized template containing literal placeholder URL `http://IP/tool.exe` (operator never customized this; bundled as a future re-use template)
- `amsi_bypass.ps1` (144247b2..., 177 B) — small AMSI bypass

The full IOC list with hashes, sizes, contexts, and confidence levels is documented in the [linked IOC feed](/ioc-feeds/opendirectory-45-130-148-125-20260430-iocs.json).

---

## 5. Technical Analysis — Behavioral / Anticipated Kill Chain

> **Analyst note:** This section walks through the operator's intended kill chain — what *would* happen step by step from initial victim execution through Linux-host pivoting — based on what the loader does, what the bundled toolkit can do, and what AdaptixC2 framework documentation says about its capabilities. Because no live victim was captured, every step is grounded in observable artifacts in the open directory rather than in observed traffic. Defenders should treat this as a hunt-priority list: each step lists the telemetry source that would catch it.

> **Important context:** No live victim observations are available. The 45.130.148.125 endpoint is a **static distribution endpoint** that has been unchanged since first crawl (80+ hours observed). The behavioral analysis below derives from (a) decoded PowerShell loader logic, (b) decompiled .NET injector, (c) decrypted AdaptixC2 beacon configuration, (d) sandbox classifications from VT vendor analyses, and (e) capabilities documented in public AdaptixC2 reporting. **Live C2 testing was not performed.**

### 5.1 Anticipated kill chain (sequential, chronological)

> **Analyst note:** This subsection walks the operator's intended attack flow step by step in the order each action would occur after the operator delivers `beacon.ps1` to a victim. The same chain is summarized as the infographic and at-a-glance stage table in Section 3; this version expands the loader-internal mechanics, defender telemetry, and rationale for each step. Every step is grounded in observable artifacts in the kit — no speculation beyond what the kit supports.

**Stage-by-stage detail (loader-internal mechanics + defender telemetry):**

| Step | T+ | What happens | Defender telemetry |
|---|---|---|---|
| 1. Initial access via PowerShell | T+0:00 | Operator delivers `beacon.ps1` to the victim by an unobserved mechanism (the open directory hosts the loader, not the dropper). PowerShell executes the script. | `powershell.exe` process creation with non-standard command-line invoking the script; Sysmon Event ID 1 captures the parent and command line. |
| 2. AMSI bypass | T+0:00 | Loader block 1: string-concatenated `'amsi'+'Con'+'text'` lookup, reflection on `*iUtils`, `SetValue($null, 0)` call against the `NonPublic, Static` field. `AmsiScanBuffer` silently no-ops for the rest of the PowerShell session. | PowerShell ScriptBlock logging (Event ID 4104) captures the script content if enabled; AMSI Event ID 1100 may register the bypass attempt depending on ETW configuration. |
| 3. Reflective .NET assembly load | T+0:01 | Loader decodes the `$dr` blob (5,120 B) and calls `[System.Reflection.Assembly]::Load(...)`. `injector.dll` is resident in PowerShell process memory. No file is dropped. The `SI` class with `Inject(uint32, byte[])` is now callable. | ScriptBlock logging captures the `[Reflection.Assembly]::Load([Convert]::FromBase64String(...))` pattern; no `Add-Type` event, no temp file. |
| 4. Shellcode build and decode | T+0:01 | 31 chunked `$sr += '...'` concatenations build a ~250 KB base64 string. `[Convert]::FromBase64String` decodes it. A loop applies `XOR 0xA7` byte-by-byte. Output: AdaptixC2 RDI bootstrap (1,023 B) + embedded beacon DLL (184,832 B). | ScriptBlock logging captures the chunked-concatenation pattern; tool-generated payload format also used by Cobalt Strike Artifact Kit `psh` template, Brute Ratel, and several open-source loader generators. |
| 5. Process injection into `explorer.exe` | T+0:02 | `(Get-Process explorer ...).Id` returns the first `explorer.exe` PID found. `[SI]::Inject([uint32]<PID>, $sc)` performs the cross-process write: `OpenProcess(PROCESS_ALL_ACCESS=0x1FFFFF)` → `VirtualAllocEx(RW=0x04, MEM_COMMIT\|RESERVE=0x3000, ~185 KB)` → `WriteProcessMemory` → `VirtualProtectEx(RX=0x20)` ← W^X flip, NOT RWX → `CreateRemoteThread(at allocation base)` → `WaitForSingleObject(3000 ms)` → `FlushInstructionCache` → `CloseHandle`. | Sysmon Event ID 8 (CreateRemoteThread) and Event ID 10 (ProcessAccess with `0x1FFFFF` granted access) capture the injection from `powershell.exe` into `explorer.exe`. The W^X allocation pattern (RW → RX, never RWX) is the operator's distinctive choice and the strongest host-side fingerprint. |
| 6. RDI bootstrap and beacon execution | T+0:03 | Remote thread starts at allocation base — the first byte of the AdaptixC2 RDI bootstrap. Bootstrap walks the embedded PE headers, performs reflective DLL mapping, jumps to the `GetVersions` export. AdaptixC2 beacon is now running inside `explorer.exe` — long-lived, network-active, trusted-looking host process — with no on-disk DLL artifact and no `LoadLibrary` event. | New RX-paged memory region in `explorer.exe`. EDRs that look for `LoadLibrary` of unknown DLLs see nothing; in-memory module enumeration (e.g., Volatility `malfind`, Sysmon Event ID 7 with module-load filtering) is required to find the mapped DLL. |
| 7. C2 communication established | T+0:05 onward | Beacon resolves WinHTTP / network APIs at runtime via `LoadLibrary` + `GetProcAddress`, RC4-decrypts its config, begins HTTP POSTs to `45.130.148.125:80`. Full C2 communication detail in Section 5.2. | Outbound HTTP POST from `explorer.exe` (anomalous parent for HTTP traffic) carrying the `X-Beacon-Id` header + Firefox 20 UA combination — the highest-fidelity AdaptixC2 framework signature. |
| 8. Active C2 phase (operator-driven) | T+seconds–minutes | Operator interactively drives the beacon. Anticipated activity inferred from the bundled toolkit: AD reconnaissance (SharpHound + ADRecon.ps1 + PowerView.ps1); credential theft via mimikatz (LSASS, DCSync), SharpDPAPI (Credential Manager, browsers), lazagne (multi-source), SharpSecDump (SAM, NTDS), Rubeus (Kerberoasting, AS-REP Roasting); privilege escalation via GodPotato / PrintSpoofer (SeImpersonate abuse), RunasCs (token manipulation), Certify (AD CS abuse); lateral movement via Ligolo-ng v0.8.3 TUN tunnel or chisel; Linux pivot via the AdaptixC2 Linux ELF agent + `linpeas.sh` once a Linux foothold is reachable. | Process tree from `explorer.exe` running commodity post-exploitation tooling; LSASS access events; AD enumeration LDAP queries; LSASS handle-open events from non-system processes. |
| 9. Persistence (operator-deployed, not observed) | — | No persistence-installer artifact is present at the staging endpoint. The PowerShell loader is execution-time only; persistence would be operator-deployed via the C2 channel. AdaptixC2 supports persistence via BOFs and arbitrary command execution, with mechanism choice at operator discretion. The bundled `msupdate.dll` (beacon DLL renamed for sideload by a legitimate Windows binary that imports `msupdate.dll`) is a deployment artifact only — operator preparation for sideload-style execution, not a confirmed-as-executed persistence path. The intended host binary is not documented in the open directory. | None at staging endpoint. Hunting at active-victim hosts: Run-key drops, Scheduled Task creation, WMI subscription, COM hijack — all reachable via standard AdaptixC2 BOFs. |

### 5.2 C2 communication detail

> **Analyst note:** This subsection lists the network-side observables for the beacon's command-and-control traffic. The values come from RC4-decrypting the configuration blob inside the beacon binary, not from captured traffic — meaning these are the values the operator *configured*, not necessarily the values currently in use. The combination of an `X-Beacon-Id` HTTP header and a Firefox 20 User-Agent on outbound POST is the single highest-fidelity AdaptixC2 framework signature regardless of operator and is the recommended primary network detection.

**Network indicators (DEFINITIVE — recovered from RC4-decrypted config):**

| Field | Value |
|---|---|
| C2 IP | `45.130.148.125` |
| C2 port | TCP/80 (operator chose; AdaptixC2 stock default = 443) |
| Transport | HTTP plaintext (no TLS) |
| Method | POST |
| URI paths (4) | `/api/v1/status`, `/updates/check.php`, `/content.html`, `/jquery-3.3.1.min.js` |
| Heartbeat header | `X-Beacon-Id` |
| User-Agent | `Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0` (Firefox 20 from February 2013) |
| Beacon callback cadence | 4 seconds (dev build) → 5 seconds (production build) |
| Jitter | 0 (deterministic) |
| Working hours | 24/7 |
| Kill date | None |

A 4–5 second sleep is **aggressively fast** for a production beacon. Most real-world beacons run 30–60+ second sleeps. The plausible explanations are:

- (a) The endpoint is still in test/staging and not yet live in operations
- (b) Deliberately fast cadence for a short-engagement operation (quick AD harvest before withdrawal)
- (c) Operator preference for responsive interactive sessions, accepting higher network noise

**Detection implications.** A 4–5 second cadence with deterministic timing, HTTP-plaintext (not TLS), fixed URI rotation, and a 13-year-old User-Agent string is an extremely high-fidelity network signature. Defenders watching internal egress traffic would see, per beacon:

- Approximately 4 POSTs every 20 seconds (one per URI cycling) to a fixed external IP on TCP/80
- Each POST carries the `X-Beacon-Id` heartbeat header (rare in legitimate browser traffic)
- All from a Firefox 20 UA (released February 2013; appearing in 2026 traffic is anomalous)

The combination is the detection pivot. Any single component alone is a moderate-FP signal — the combination is the framework's stock-listener fingerprint.

### 5.3 Defense evasion observations

> **Analyst note:** This subsection summarizes the seven discrete evasion techniques the operator's loader-plus-injector pair employs. Each row is a separate detection-engineering target — defenders should treat them as parallel hunt priorities rather than a single chain. The mix of "sophisticated-looking" techniques (W^X-aware allocation, AMSI bypass via reflection) sitting alongside textbook-lazy choices (broad `PROCESS_ALL_ACCESS` access mask, unobfuscated .NET P/Invoke imports) is itself a tradecraft fingerprint — see Section 4.3.2 for the discussion.

| Technique | Evidence | Confidence |
|---|---|---|
| AMSI bypass via reflection (T1562.001) | `amsi`+`Con`+`text` concatenation, `*iUtils` reflection, `SetValue($null, 0)` zeroing — Matt Graeber lineage | HIGH |
| In-memory .NET assembly load (T1620) | `[Reflection.Assembly]::Load(byte[])` — no `Add-Type`, no temp file | HIGH |
| W^X-aware classic process injection | RW alloc → write → flip to RX (NOT RWX) — defeats simple "RWX in remote process" EDR rules | HIGH |
| Dynamic API resolution | Beacon has zero networking imports in IAT; all C2 calls resolved at runtime | HIGH |
| String encryption (T1027) | RC4-encrypted config in `.rdata` blob — only the BASE64 alphabet leaks plaintext | HIGH |
| DLL side-load preparation (T1574.002) | `msupdate.dll` rename of the beacon DLL — operator preparation, not confirmed-as-executed | MODERATE |
| Selective AV-evasion on signatured commodity tools | SharpHound 86% / lazagne 97% high-entropy ratios | HIGH |

**Anti-tooling tradecraft NOT present:**
- No D/Invoke, no direct syscalls — all Win32 P/Invoke is via static `[DllImport]`, enumerable in the assembly's `ImplMap` metadata (see terminology note below)
- No anti-debug, anti-VM, or anti-sandbox checks in the .NET injector
- No retry logic or error handling beyond null checks
- No string-encryption inside `injector.dll` (P/Invoke method names are plaintext)
- No certificate pinning, no domain-fronting, no covert channel

The combination — reflection-based AMSI bypass and W^X-aware injection (sophisticated-looking) alongside `PROCESS_ALL_ACCESS` and unobfuscated .NET P/Invoke declarations in the injector's `ImplMap` metadata (lazy) — is consistent with an operator who has read modern injection tradecraft writeups, applied the headline lessons, but never wrote anti-detection code from scratch.

(Terminology note for defenders: a .NET assembly's Win32 imports do not appear in the PE Import Address Table the way a native-language binary's do. They are listed in the .NET metadata's `ImplMap` table — a managed-code abstraction visible in tools like dnSpy or ILSpy. Hunting for `OpenProcess`/`VirtualAllocEx`/`CreateRemoteThread` in a .NET injector's PE IAT will therefore not find them; the lookups happen at JIT time via P/Invoke marshalling.)

---

## 6. MITRE ATT&CK Mapping

> **Skill validation:** The mappings below were validated via the `mitre-attack-mapping` skill in Stage 1. Sub-technique selection corrections have been applied: process injection maps to T1055 (parent) plus T1055.002 (Portable Executable Injection sub-technique) — NOT T1055.003 (Thread Execution Hijacking) or T1055.012 (Process Hollowing), because the injector writes a full PE plus its RDI bootstrap into the target's allocated memory, then resumes a new thread at the bootstrap entry. **T1055.001 (DLL Injection) was considered but rejected** because the injected payload includes its own RDI bootstrap rather than relying on `LoadLibrary` — the RDI bootstrap performs the in-memory PE-mapping work that `LoadLibrary` would otherwise do, which is the discriminating feature between T1055.002 (a PE is written and reflectively mapped) and T1055.001 (a path is passed to `LoadLibrary`). Initial Access is not mapped (delivery vector not observed). Impact is not mapped (no destructive techniques observed in the toolkit).

The kit covers **39 techniques across 9 ATT&CK tactics**:

> **Confidence note:** all rows below are HIGH confidence unless explicitly marked `(MODERATE)`. The Confidence Summary in Section 13 organizes findings by confidence level for the higher-level view.

| Tactic / Technique | Name | Evidence |
|---|---|---|
| Resource Development / T1583.003 | Virtual Private Server | `45.130.148.125` on AS35682 (Uzbekistan) (MODERATE) |
| Resource Development / T1588.002 | Obtain Tool | AdaptixC2 (Linux build), Ligolo-ng v0.8.3, Ghostpack/SpecterOps suite, mimikatz, lazagne, winpeas/linpeas |
| Execution / T1059.001 | PowerShell | `beacon.ps1` 256 KB loader (AMSI bypass + reflective load + inject) |
| Execution / T1620 | Reflective Code Loading | `[Reflection.Assembly]::Load([byte[]])` of `injector.dll`; RDI bootstrap maps beacon DLL |
| Defense Evasion / T1562.001 | Disable or Modify Tools | AMSI bypass via `*iUtils` reflection + `SetValue($null, 0)` on `amsiContext` |
| Defense Evasion / T1027 | Obfuscated Files or Information | RC4-encrypted config + base64 + XOR 0xA7 shellcode layers |
| Defense Evasion / T1140 | Deobfuscate/Decode Files | `beacon.ps1` base64 + XOR decode; beacon RC4-decrypts config at startup |
| Defense Evasion / T1132.001 | Standard Encoding (Base64) | Base64 for `$dr` (injector) + `$sr` (shellcode); BASE64_table for C2 |
| Defense Evasion / T1055 | Process Injection (parent) | `SI.Inject(uint32 pid, byte[] sc)` — `OpenProcess` → `VirtualAllocEx` → `VirtualProtectEx` → `WriteProcessMemory` → `CreateRemoteThread` |
| Defense Evasion / T1055.002 | Portable Executable Injection | Embedded PE injection into `explorer.exe` via W^X (RW → RX, NOT RWX). Also Priv Esc. |
| Defense Evasion / T1574.002 | DLL Side-Loading | `msupdate.dll` (beacon DLL renamed for sideload spoofing) — prep only (MODERATE) |
| Credential Access / T1003.001 | LSASS Memory | mimikatz v2.2.0 (gentilkiwi) |
| Credential Access / T1003.002 | Security Account Manager | SharpSecDump bundled |
| Credential Access / T1003.003 | NTDS | SharpSecDump → NTDS.dit on DCs (MODERATE) |
| Credential Access / T1003.006 | DCSync | mimikatz `lsadump::dcsync` |
| Credential Access / T1555 | Credentials from Password Stores | lazagne (×2 variants) — multi-source cred extraction |
| Credential Access / T1555.003 | Web Browsers | SharpDPAPI + lazagne — browser cred stores |
| Credential Access / T1555.004 | Windows Credential Manager | SharpDPAPI — DPAPI vaults (Credential Manager, RDG) |
| Credential Access / T1552.004 | Private Keys | Certify — extract keys from AD CS certs (MODERATE) |
| Credential Access / T1558.003 | Kerberoasting | Rubeus `kerberoast` |
| Credential Access / T1558.004 | AS-REP Roasting | Rubeus `asreproast` |
| Collection / T1056.001 | Keylogging | AdaptixC2 BOF keylogging (operator-driven, not observed) (MODERATE) |
| Discovery / T1057 | Process Discovery | `Get-Process explorer` in `beacon.ps1` + AdaptixC2 BOF process enum |
| Discovery / T1082 | System Information Discovery | Seatbelt + winpeas + `linpeas.sh` |
| Discovery / T1083 | File and Directory Discovery | Seatbelt + winpeas + `linpeas.sh` |
| Discovery / T1018 | Remote System Discovery | SharpHound (×2: `.exe` + `.ps1`) — domain-wide remote systems |
| Discovery / T1087.002 | Domain Account | SharpHound + ADRecon + PowerView |
| Discovery / T1069.002 | Domain Groups | SharpHound + ADRecon |
| Discovery / T1482 | Domain Trust Discovery | SharpHound + ADRecon — domain trusts |
| Discovery / T1518.001 | Security Software Discovery | winpeas + Seatbelt — installed AV/EDR detection |
| Privilege Escalation / T1134.001 | Token Impersonation/Theft | GodPotato + PrintSpoofer — `SeImpersonatePrivilege` → SYSTEM |
| Privilege Escalation / T1134.002 | Create Process with Token | RunasCs — process with stolen token |
| Privilege Escalation / T1068 | Exploitation for Privilege Escalation | GodPotato + PrintSpoofer (CVE-2021-1675 / CVE-2022-26904 lineage) (MODERATE) |
| Privilege Escalation / T1649 | Steal or Forge Authentication Certificates | Certify (Ghostpack) — AD CS template abuse (ESC1–ESC8) |
| Lateral Movement / T1090.001 | Internal Proxy | Ligolo-ng v0.8.3 — TUN-mode reverse tunnel |
| Lateral Movement / T1572 | Protocol Tunneling | Ligolo-ng + chisel — Go reverse tunnels |
| Command and Control / T1071.001 | Web Protocols | Beacon HTTP POST `45.130.148.125:80`, 4 URIs, `X-Beacon-Id`, Firefox 20 UA, 4–5s sleep |
| Command and Control / T1573.001 | Symmetric Cryptography | RC4-128 on `.rdata` config (key `f443b9ce…` plaintext-adjacent) |
| Command and Control / T1105 | Ingress Tool Transfer | Open directory `45.130.148.125:8888` hosts toolkit for delivery |

**Tactic coverage summary:** 9 of 14 tactics. Initial Access (TA0001) not mapped — delivery vector not observed. Impact (TA0040) not mapped — no destructive techniques in the kit. Reconnaissance (TA0043) not mapped — staging endpoint provides no operator-side reconnaissance evidence. Persistence (TA0003) not mapped definitively — only the moderate-confidence `msupdate.dll` sideload preparation artifact is present, with no scheduled tasks, no Run-key drops, and no service installations observed at the staging endpoint. Exfiltration (TA0010) not mapped — no exfiltration scripts in the kit; operator-driven via C2 channel only.

---

## 7. Infrastructure Analysis

> **Analyst note:** Infrastructure analysis maps the operator's hosting decisions, attribution overlap potential, and takedown resilience. Findings here are derived from passive observation (no port scanning was performed against the operator). Where VirusTotal lookups were blocked by quota during the original analysis, those gaps are noted.

### 7.1 Service co-location confirms attacker control

The single IP `45.130.148.125` exposes three distinct services:

| Port | Service | Implication |
|---|---|---|
| TCP/80 | AdaptixC2 HTTP C2 (victim-facing beacon callback) | Active C2 |
| TCP/4444 | AdaptixC2 TeamServer (operator GUI) | **Attacker-controlled — confirmed** |
| TCP/8888 | Python SimpleHTTPServer 0.6 open directory | Toolkit staging |

The TeamServer port is the operator's own management interface. Its open exposure adjacent to the victim-facing C2 establishes — at HIGH confidence — that this server is **attacker-controlled (purpose-built for this operation)**, not a compromised third-party host. There is no legitimate compromise scenario in which a TeamServer is exposed alongside its own beacon C2.

### 7.2 Hosting and jurisdiction

| Field | Value |
|---|---|
| ASN | AS35682 BEST INTERNET SOLUTION XK |
| Provider | eskiz.uz (small regional commercial provider) |
| Country | Uzbekistan (Tashkent) |
| Service type | Commercial VPS hosting (no bulletproof-hosting designation) |
| Bulletproof indicators | 0.5 of 6 formal criteria met (jurisdiction-only partial indicator) |
| TLS | None (HTTP plaintext on TCP/80) |

AS35682 is a legitimate regional commercial provider, not a formally designated bulletproof hosting AS. However, **Uzbekistan is not a Budapest Convention signatory and has no US MLAT (Mutual Legal Assistance Treaty) coverage for cybercrime cooperation**, which creates measurable Western law-enforcement-cooperation friction relative to EU/MLAT jurisdictions. The geographic alignment fits the post-Soviet hosting preferences documented for Russian-speaking cybercrime ecosystems at MODERATE confidence — but this is a population-level pattern, not specific actor evidence.

### 7.3 Pivoting attempts and dead ends

Five infrastructure pivot paths were attempted in Stage 2:

| Pivot | Result | Reason |
|---|---|---|
| Passive DNS (historical domains) | DEAD END | VirusTotal quota exhaustion + IP-only deployment with no DNS records |
| WHOIS / registrant correlation | DEAD END | No domains registered for this campaign |
| SSL certificate clustering | DEAD END | No TLS service on any port |
| ASN co-tenant analysis | DEAD END | No indexed malicious co-tenants on AS35682 |
| Neighboring /24 enumeration | DEAD END | No indexed threats in adjacent IPs |

**Expansion ratio: 1× (no new IOCs discovered).** The operator's IP-only, no-TLS, no-domain deployment is OpSec-poor in many ways but happens to be **excellent at preventing infrastructure pivoting** — there is nothing to clusterize. Resolution of the passive DNS pivot is pending after the VT quota reset on 2026-05-01.

### 7.4 Threat actor infrastructure overlaps

**No infrastructure overlap to any named threat actor was identified.** Specifically:

- The IP `45.130.148.125` is not indexed in any reviewed public threat intelligence feed at the time of analysis
- AS35682 has no documented prior usage by any tracked threat actor cluster
- No DNS, SSL certificate, registrant, or co-tenant overlaps exist with any reported threat-actor infrastructure
- Framework-level overlaps with Akira, Fog, Tropic Trooper, and Tomiris (which all use AdaptixC2) are **NOT infrastructure overlaps** and carry no attribution weight — those actors deploy AdaptixC2 on their own separate infrastructure

The complete infrastructure attribution evidence is therefore **MODERATE strength at best** and reflects only the geographic-alignment population estimate.

### 7.5 Temporal pattern and operational status

| Event | Timestamp |
|---|---|
| First malicious activity (dev build compile) | 2026-04-23 07:39:46 UTC |
| Production cluster compile timestamps | 2026-04-23 20:34:31–32 UTC (3 files within 1 second) |
| Open-directory first discovery | 2026-04-26 03:41:05 UTC |
| Hours static since discovery (as of analysis) | 80+ |
| Infrastructure changes detected | 0 |
| Post-disclosure operator response | None — server unchanged |

The static-since-discovery profile is the most telling temporal signal in this campaign. The operator either (a) is unaware of the exposure, (b) has not yet activated the staging endpoint for live operations, or (c) does not consider the exposure consequential. A +1 week opendir-hunter rescan is scheduled for 2026-05-06; if the directory remains static at that point, the "static distribution endpoint" read locks in at HIGH confidence.

---

## 8. Threat Actor Assessment

> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-2026-006 is an internal tracking designation assigned by The Hunters Ledger to actors observed across analysis who cannot yet be linked to a publicly named threat group. This label will not appear in external threat intelligence feeds or vendor reports — it is specific to this publication. If future evidence links this activity to a known named actor, the designation will be retired and updated accordingly.

### 8.1 Attribution conclusion

**Named-actor attribution: INSUFFICIENT (<50%).** Tracked as **UTA-2026-006**.

The operator behind `45.130.148.125` cannot be tied to any publicly named threat group on the available evidence. A full Analysis of Competing Hypotheses (ACH) — five hypotheses evaluated against all observed evidence — was performed.

| Hypothesis | Inconsistencies | Status |
|---|---|---|
| H1: Russian-speaking ransomware affiliate cohort (Akira / Fog / IAB-staged) | 2 | Closest named-cohort fit — population estimate only |
| H2: Tropic Trooper APT | 6 | RULED OUT |
| H3: Tomiris APT | 5 | RULED OUT |
| H4: GOLD ENCOUNTER / PayoutsKing (Sophos STAC4713) | 2 | LOW confidence (50–60%) |
| H5: Unattributed opportunistic mid-tier red-team operator / commodity-cybercrime affiliate | 0 | Best-fit on the strict ACH inconsistency test — null hypothesis |

**On the H1/H5 result:** Strict ACH discipline awards the best-fit verdict to the hypothesis with the lowest inconsistency count, which is H5 (0 inconsistencies). H1 is the closest *named-cohort* fit at 2 inconsistencies but does not survive the strict test. The earlier framing of H1 and H5 as "tied" was imprecise — H5 wins the inconsistency comparison cleanly. The reason H5 nonetheless does not produce confident attribution is that "Unattributed opportunistic mid-tier operator" is a null-hypothesis label, not an actor identity. The technical evidence is fully consistent with H5 *and* with the H1 cohort framing at population level — there is no evidence that disambiguates whether the operator is inside the Russian-speaking ransomware affiliate cohort or simply runs the same commodity tooling without belonging to it. The conservative reading — and the one this report adopts — is that named-actor attribution is INSUFFICIENT and the operator is tracked under the UTA-2026-006 designation pending evidence that resolves H1 vs. H5.

### 8.2 Why named actors are ruled out

**Tropic Trooper (RULED OUT — 6 inconsistencies).** Tropic Trooper is currently the **only publicly documented APT that customizes AdaptixC2** — Zscaler ThreatLabz (March 2026) documented Tropic Trooper deploying AdaptixC2 with a custom GitHub-Issues-as-C2 transport listener layered on top of the framework. Every other publicly documented AdaptixC2 user (Akira / Fog ransomware affiliates, CountLoader operators, the unnamed initial-access broker described by Silent Push) runs the framework stock. UTA-2026-006 falls in the latter category — runs the framework 100% stock with default URI paths, default Firefox 20 UA, default `X-Beacon-Id` header, direct-IP HTTP. **This contrast is itself the analytical anchor for treating UTA-2026-006 as a "tool consumer, not customizer" profile** — the only documented customizer is APT-grade and very different from this operator. Tropic Trooper also delivers via trojanized SumatraPDF installers; this operator uses a PowerShell loader. Tropic Trooper targets Southeast Asian government entities; no targeting evidence is observed here.

**Tomiris (RULED OUT — 5 inconsistencies).** Tomiris is polyglot: Kaspersky's December 2025 Securelist report documented Tomiris deploying Havoc + AdaptixC2 simultaneously, with C2 traffic routed through legitimate public services (Telegram bot API, Discord webhooks). This operator uses AdaptixC2 only, with direct HTTP to a fixed IP and no platform-routed C2. Tomiris targets diplomatic ministries; no diplomatic targeting evidence here. The single-protocol single-platform architecture is fundamentally incompatible with Tomiris's polyglot tradecraft.

**GOLD ENCOUNTER / PayoutsKing (LOW — 2 inconsistencies).** Sophos's STAC4713 cluster (April 2026) is defined by QEMU-based virtualization scaffolding for AV evasion plus stealthy beaconing. This operator has neither: no QEMU artifacts in the kit, and an aggressive 4–5 second beacon cadence inconsistent with patient stealth tradecraft. Insufficient positive evidence to elevate above LOW.

### 8.3 Why H1 is a population estimate, not attribution

The cohort alignment between this operator's tradecraft and Russian-speaking ransomware affiliates is real but **soft**:

- **Tool profile match.** AdaptixC2 + Ghostpack suite (SharpHound, Rubeus, Certify, SharpDPAPI, SharpSecDump) + Ligolo-ng + chisel mirrors the affiliate tradecraft profile documented in DFIR Report's November 2025 Bumblebee → AdaptixC2 → Akira chain (~44h time-to-ransomware) and Silent Push's August 2025 CountLoader / IAB report.
- **Hosting geography match.** AS35682 (Uzbekistan) sits in a non-Budapest-Convention jurisdiction with low Western LEO cooperation friction — geographic alignment with post-Soviet cybercrime hosting preferences at MODERATE confidence.
- **Toolkit scope match.** The full kill-chain coverage (AD enumeration, credential dumping, multiple privesc paths, Linux pivot capability) is operationally consistent with a pre-ransomware staging kit designed to establish domain dominance before payload deployment.

What the alignment **does not** establish:
- Identity of any specific ransomware group (Akira, Fog, LockBit, BlackBasta, Qilin, or others)
- Identity of any specific affiliate program or operator handle
- Confirmed ransomware intent — no payload was observed at the staging endpoint
- Infrastructure overlap with any prior named-affiliate operations

This is presented as a **population estimate only** for risk-framing context. Treating cohort alignment as attribution would overstate confidence and undermine credibility.

### 8.4 UTA-2026-006 distinguishing characteristics

UTA-2026-006 is supported by **seven distinctive characteristics** (five technical, one infrastructure, one behavioral) that collectively reach a B2 Admiralty rating:

1. **Technical — Build artifact:** PDB path `/tmp/si_build/obj/Release/net472/si_build.pdb` embedded in operator-written `injector.dll`. Linux-hosted .NET cross-compilation via `dotnet build -c Release` from a `/tmp/<name>_build/` working directory. Not present in any AdaptixC2 framework artifact or any reviewed public threat report.
2. **Technical — Code pattern:** `[SI]::Inject()` invocation in operator-written `beacon.ps1` PowerShell loader, where `SI` is the .NET class name from the operator-written `injector.dll`. The matched `beacon.ps1` / `injector.dll` pair is not documented in any public AdaptixC2 deployment example. AdaptixC2 ships no .NET injector; this delivery chain is operator-authored.
3. **Infrastructure:** AdaptixC2 TeamServer (TCP/4444) + beacon HTTP C2 (TCP/80) + Python SimpleHTTPServer staging (TCP/8888) all co-located on a single IP at `45.130.148.125` in AS35682 / Tashkent, Uzbekistan. IP-only, no-TLS, not indexed in reviewed public feeds at first observation.
4. **Technical — Configuration:** RC4 key `f443b9ce7e0658900f6a7ff0991cdee6` (16 bytes), `agent_type` ID `0xbe4c0149`, `listener_type` ID `0xcb4e6379`. Operator-specific per-listener values that persist across the dev/prod build pair. Any future binary carrying the same RC4 key links unambiguously to this operator.
5. **Technical — Toolchain:** Linux dev host with MinGW-w64 GCC + GNU ld 2.35 (C++ AdaptixC2 beacon) plus `dotnet build -c Release` (.NET injector). Same-day dev-to-prod build cadence: dev compile 2026-04-23 07:39 UTC, prod compile 2026-04-23 20:34 UTC (13-hour gap).
6. **Behavioral — OpSec pattern:** Sub-mature OpSec combination — PDB path leakage, plaintext build timestamps in PE headers, internal class names exposed in PowerShell loader, stock Firefox 20 UA unmodified, leftover `proxy_port = 3128` dev artifact in submitted dev build. Operator does not scrub build artifacts, does not customize listener defaults, and does not rotate infrastructure within the observation window.
7. **Behavioral — Tradecraft:** Selective AV evasion — packing applied only to the most-signatured commodity tools (`SharpHound.exe` 86% high-entropy, `lazagne.exe` 10 MB variant 97% high-entropy) while the rest of the kit (mimikatz, Rubeus, SharpDPAPI, GodPotato) is unmodified. Selective rather than blanket evasion is a tradecraft signature.

The complete UTA-2026-006 file (creation gate, distinguishing IOCs, merge candidates, gap analysis, and activity log) is maintained at `threat-intel-vault/threat-actors/UTA-2026-006.md` per the workflow's UTA lifecycle rules.

### 8.5 What would resolve attribution

The following actions would materially increase attribution confidence:

- **Private TI cross-match** on `si_build`, the PDB path, the RC4 key, or the agent/listener type IDs across VirusTotal Intelligence, Recorded Future Insikt, Mandiant Advantage, or Silent Push Enterprise feeds
- **Reappearance of the RC4 key `f443b9ce7e0658900f6a7ff0991cdee6`** in any future binary — this would link unambiguously to UTA-2026-006 at HIGH confidence
- **DFIR forensics from a confirmed victim host** would surface language settings, keyboard layout, timezone, runtime command patterns, and operator handle correlation
- **VirusTotal passive DNS** for `45.130.148.125` after quota reset (2026-05-01) — historical DNS may surface domain infrastructure not visible from the IP-only observation window
- **Cross-investigation pivot** — if the `/tmp/<name>_build/` PDB pattern, MinGW-w64 GCC + GNU ld 2.35 toolchain, or the same-day dev-to-prod build cadence appears in another investigation, build-environment-level operator clustering becomes viable

---

## 9. Cohort Context: AdaptixC2 in the Threat Landscape

> **Analyst note:** The remainder of this section provides the public-reporting context that frames this operator's deployment within the broader AdaptixC2 ecosystem. It is included to support detection prioritization (defenders need to recognize the framework, not just this campaign) and to scope the cohort alignment that supports UTA-2026-006's risk framing.

AdaptixC2 has shifted in the past twelve months from a niche open-source red-team framework to a workhorse post-exploitation platform now used by at least four distinct cohort archetypes. The reporting density on the framework has increased materially since October 2025. Each cohort below is documented in publicly available Tier-1/Tier-2 vendor research. None of the named campaigns share infrastructure with `45.130.148.125`.

### 9.1 Russian-speaking ransomware affiliates (Akira, Fog)

**The DFIR Report (November 2025)** documented a Bumblebee-staged intrusion chain culminating in Akira ransomware deployment that used AdaptixC2 for the post-exploitation phase. The affiliate operated entirely via commodity tools with no custom code. Time-to-ransomware was approximately 44 hours from initial Bumblebee execution to encryption. Infrastructure was separate from `45.130.148.125`.

**Silent Push (August 2025)** documented AdaptixC2 as the post-exploitation tool of choice for an initial-access broker (IAB) operating in the LockBit / BlackBasta / Qilin affiliate supply chain, framing the framework's adoption as evidence of integration into Russian criminal underground supply chains. The reporting included CountLoader as the staging component delivering AdaptixC2 beacons. Infrastructure was separate from `45.130.148.125`.

**CISA AA24-109A (Akira ransomware)** — the official CISA advisory on Akira characterizes affiliate tradecraft as commodity post-exploitation tooling, AD enumeration, credential dumping, and lateral movement chains consistent with what is observed in this toolkit. CISA does not specifically name AdaptixC2 in this advisory.

### 9.2 Tomiris APT (diplomatic targeting)

**Kaspersky Securelist (December 2025)** documented Tomiris APT operations using a polyglot C2 architecture combining Havoc + AdaptixC2 + legitimate-platform-routed channels (Telegram bot API, Discord webhooks). Tomiris targets diplomatic entities and government ministries with multi-payload phishing chains. The polyglot architecture is the defining differentiator from this operator's single-protocol direct-IP deployment.

### 9.3 Tropic Trooper APT (Asia targeting)

**Zscaler ThreatLabz (March 2026)** documented Tropic Trooper APT operations using AdaptixC2 with a custom GitHub-Issues-as-C2 transport listener. Delivery is via trojanized SumatraPDF installers. Tropic Trooper is the only publicly documented APT that **customizes** AdaptixC2 — every other documented user runs the framework stock. Targeting is Southeast Asian government entities.

### 9.4 GOLD ENCOUNTER / PayoutsKing (Sophos STAC4713)

**Sophos (April 2026)** documented STAC4713 / GOLD ENCOUNTER / PayoutsKing operations using AdaptixC2 deployed inside QEMU-based virtualization scaffolding for AV evasion. The QEMU-isolation approach allows the AdaptixC2 implant to run inside a sandboxed VM on the victim host, evading host-based EDR. Beaconing is patient and stealthy — explicitly contrary to this operator's aggressive 4–5 second cadence.

### 9.5 What this means for this campaign

The 45.130.148.125 operator's deployment is **most consistent with the Russian-speaking ransomware affiliate cohort** at population level — the toolkit profile, hosting geography, and operational tradecraft all fit. But the operator runs the framework 100% stock with no distinguishing customization, and zero infrastructure overlap exists with any named ransomware affiliate operation. The reading is therefore: this is a capable mid-tier hands-on operator running a deployment that *could* belong to any of dozens of unattributed affiliate operators within the cohort. UTA-2026-006 designation enables tracking of this specific operator — and only this operator — across future campaigns.

The detection-engineering implication is significant: **defending against AdaptixC2 means defending against the framework**, not against any single named actor. The detection rule set published with this report targets the framework's stock fingerprints (which catch every operator running AdaptixC2 stock) plus the operator-specific UTA-2026-006 fingerprints (which catch this operator only). Both tiers are documented in [the linked detection file](/hunting-detections/opendirectory-45-130-148-125-20260430-detections/).

---

## 10. Detection & Response

### 10.1 Detection content (linked package)

The complete detection rule set for this campaign is published as a separate file (source file: `threat-intel-vault/hunting-detections/opendirectory-45-130-148-125-20260430-detections.md`):

**[Detection rules and hunting queries → /hunting-detections/opendirectory-45-130-148-125-20260430-detections/](/hunting-detections/opendirectory-45-130-148-125-20260430-detections/)**

The package includes:
- **YARA rules** — stock-AdaptixC2-framework detection (catches any operator running default-listener configuration) and operator-specific detection (UTA-2026-006 fingerprints — `si_build`, PDB path, RC4 key)
- **Sigma rules** — PowerShell ScriptBlock logging (Event ID 4104) for the AMSI bypass + reflection.assembly.load + `[SI]::Inject` chain; Sysmon Event ID 8 (CreateRemoteThread) for the `powershell.exe → explorer.exe` injection
- **Suricata signatures** — network-side detection of the AdaptixC2 stock-listener fingerprint (Firefox 20 UA + `X-Beacon-Id` header + URI rotation)
- **EDR / SIEM hunting queries** — Splunk and Elastic queries for the loader chain and beacon callback patterns

### 10.2 Detection priorities

The three highest-value hunts, in priority order:

**Priority 1 — Network-side AdaptixC2 stock fingerprint.** Outbound HTTP POST to a fixed external IP carrying both the `X-Beacon-Id` header AND a 2013-era Firefox 20 User-Agent. Either component alone is a moderate-FP signal; the combination is the framework's stock-listener fingerprint and a high-fidelity detection. Defenders monitoring proxy or firewall logs should alert on:

```
HTTP POST
  + Destination: external IP
  + Header: X-Beacon-Id
  + User-Agent: Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0
```

**Priority 2 — Operator-loader-chain script-block logging.** PowerShell ScriptBlock logging (Event ID 4104) is the highest-fidelity host-side detection for the operator's loader chain. The Sigma rule in the linked detection file targets the combination:

- `amsi`+`Con`+`text` string concatenation marker
- `[Ref].Assembly.GetTypes()` reflection on `*iUtils`
- `[System.Reflection.Assembly]::Load([Convert]::FromBase64String(...))` of base64-encoded PE
- `[SI]::Inject(` invocation pattern

**Priority 3 — Cross-process injection with W^X allocation pattern.** Sysmon Event ID 8 (CreateRemoteThread) and Event ID 10 (ProcessAccess) capture the `powershell.exe → explorer.exe` injection. The distinctive parameters are `PROCESS_ALL_ACCESS` (`0x1FFFFF`) granted access plus an allocation flip from `PAGE_READWRITE` (`0x04`) to `PAGE_EXECUTE_READ` (`0x20`) — never `PAGE_EXECUTE_READWRITE` (`0x40`). This is also the operator's distinctive injection-code-style fingerprint and could match if the same actor's code appears in other operations under UTA-2026-006.

### 10.3 Hunting for UTA-2026-006 fingerprints (operator-specific)

If you have access to a binary corpus (VT Intelligence, internal sample library, or DFIR captures), the following YARA strings serve as high-confidence UTA-2026-006 indicators:

| String | What it identifies | Confidence |
|---|---|---|
| `si_build` (in PE version-info OR class name) | Operator-written `injector.dll` | HIGH |
| `/tmp/si_build/obj/Release/net472/si_build.pdb` | Operator's Linux .NET build environment | HIGH |
| `f443b9ce7e0658900f6a7ff0991cdee6` (16-byte hex) | Operator's RC4 listener key | HIGH |
| `0xbe4c0149` (DWORD agent_type) + `0xcb4e6379` (DWORD listener_type) | Operator's per-listener identifiers | HIGH |
| `[SI]::Inject(` (PowerShell) | Operator's beacon delivery chain | HIGH |

Any sample carrying any of these is linked to UTA-2026-006 at HIGH confidence. The compiled YARA rules in the linked detection file implement these checks with the appropriate Boolean structure.

### 10.4 YARA noise filters (DETECTION-ENGINEER MUST APPLY)

Two false-positive clusters must be filtered when triaging hunt results:

**Go-runtime PoetRat false positive.** `MALWARE_RULES: PoetRat_Python` triggers on every Go binary. The Ligolo-ng (`agent.exe`), chisel (`chisel.exe`), and Gopher Go agent (`gopher.x64.exe`) in this kit all match this rule. **PoetRAT is unrelated** — it is a Python-based malware family, not Go. Additional Go-runtime false positives in the same cluster: `BASE64_table`, `DebuggerCheck__QueryInfo`, `disable_dep`, `android_meterpreter` (deprecated). Detection rules MUST NOT pivot on these patterns.

**PowerView spyeye false positive.** `MALWARE_RULES: spyeye` triggers on `PowerView.ps1` due to a generic byte pattern. PowerView is commodity AD reconnaissance PowerShell from PowerShellMafia — it is not SpyEye banking malware.

The linked detection file documents both filters in its Coverage Gaps section.

### 10.5 Coverage gaps

Three coverage gaps are flagged for downstream investigation:

- **No live C2 traffic capture.** Behavioral detections derived from static analysis of the AdaptixC2 framework code, not from observed live traffic. Lab-VM controlled detonation in an isolated environment would refine the network signatures with empirical packet captures.
- **AdaptixC2 v0.7+ Gopher BOF behavioral observability.** The Gopher Go agent's MessagePack-encoded C2 protocol and BOF execution runtime are not directly observed in dynamic analysis. Detection content for the Gopher transport is derived from the framework's published source code.
- **Persistence detection.** No persistence mechanism was observed at the staging endpoint. The `msupdate.dll` sideload candidate is a deployment artifact only. Operator-deployed persistence in active operations would be visible only via DFIR captures, not from the staging-endpoint analysis.

---

## 11. Indicators of Compromise

### 11.1 IOC feed (linked package)

The complete machine-readable IOC feed is published as a separate JSON file:

**[Validated IOC feed → /ioc-feeds/opendirectory-45-130-148-125-20260430-iocs.json](/ioc-feeds/opendirectory-45-130-148-125-20260430-iocs.json)**

The feed includes:
- **30 SHA256 file hashes** (operator-written PowerShell loader and .NET injector, AdaptixC2 beacon cluster in 4 formats, Linux ELF agent, Gopher Go agent Windows variant, Ligolo-ng v0.8.3, chisel, full Ghostpack/SpecterOps + commodity tool inventory)
- **3 imphash MD5 indicators** (cluster DLL, EXE-form sibling, dev-build embedded DLL)
- **2 IPv4 endpoints** (`45.130.148.125:80` C2, `45.130.148.125:8888` staging)
- **4 URL paths** (3 stock AdaptixC2 + 1 operator-added)
- **6 build-environment strings** (PDB path, `si_build`, MinGW-w64 toolchain witness strings, RTTI typeinfo strings)
- **Configuration constants** (RC4 key, agent/listener type IDs, XOR shellcode key, dev-leftover proxy port)
- **Behavioral and loader fingerprints**
- **False-positive flags** for `/jquery-3.3.1.min.js` (must combine with destination IP + at least one of header/UA), Firefox 20 UA (anomalous in 2026), and `X-Beacon-Id` header (rare in legitimate browser traffic)
- **YARA noise-filter warnings** (PoetRat / Go-runtime cluster + spyeye on PowerView)

### 11.2 Highest-fidelity IOCs (quick reference)

The five operator-specific indicators below are the highest-fidelity for cross-campaign tracking under UTA-2026-006. Any single match links a sample or observation to this operator at HIGH confidence:

- **`45.130.148.125`** — operator-controlled C2 IP. Block on TCP/80 (beacon C2), TCP/4444 (TeamServer), TCP/8888 (staging).
- **`f443b9ce7e0658900f6a7ff0991cdee6`** — recovered RC4 listener key. DEFINITIVE identifier of *this* listener configuration; appears in the per-listener type ID derivation.
- **`/tmp/si_build/obj/Release/net472/si_build.pdb`** — Linux-built .NET PDB path embedded in the operator-written `injector.dll`. Operator build-environment fingerprint.
- **`0xbe4c0149` / `0xcb4e6379`** — per-listener `agent_type` and `listener_type` IDs from the RC4-decrypted configuration. Operator-specific values that persist across the dev/prod build pair; would change on a fresh listener generation.
- **`[SI]::Inject(`** — operator's PowerShell-to-.NET injector invocation pattern. Ties any future `beacon.ps1`-style loader carrying this string to the matched `injector.dll` at HIGH confidence; the `SI` class name exists nowhere else in the public AdaptixC2 framework.

For the full list (72 indicators with file sizes, hashes, false-positive flags, and machine-readable context), see the linked IOC feed.

### 11.3 Public IOCs from prior AdaptixC2 reporting (do NOT confuse with this report's IOCs)

The indicators below are reproduced from Unit 42's *AdaptixC2: A New Open-Source Framework Leveraged in Real-World Attacks* (May 2025) and Silent Push's *AdaptixC2's Ties to Russian Criminal Underworld* (August 2025) — see Section 14 for sources. **They represent separate operator deployments unrelated to UTA-2026-006.** This subsection exists so defenders cross-checking multiple AdaptixC2 IOC feeds do not accidentally attribute these indicators to the `45.130.148.125` campaign or vice versa.

| Indicator | Type | Source | Operator scope |
|---|---|---|---|
| `bdb1b9e37f6467b5f98d151a43f280f319bacf18198b22f55722292a832933ab` | SHA256 — PowerShell installer | Unit 42 | Different operator |
| `b81aa37867f0ec772951ac30a5616db4d23ea49f7fd1a07bb1f1f45e304fc625` | SHA256 — DLL beacon | Unit 42 | Different operator |
| `df0d4ba2e0799f337daac2b0ad7a64d80b7bcd68b7b57d2a26e47b2f520cc260` | SHA256 — EXE beacon | Unit 42 | Different operator |
| `tech-system[.]online` | C2 domain | Unit 42 | Different operator |
| `protoflint[.]com` | C2 domain | Unit 42 | Different operator |
| `novelumbsasa[.]art` | C2 domain | Unit 42 | Different operator |
| `picasosoftai[.]shop` | C2 domain | Unit 42 | Different operator |
| `64[.]137[.]9[.]118` | IPv4 — initial-research IP | Silent Push | Different operator |
| `172[.]16[.]196[.]1:4443` | Framework default C2 listener | Unit 42 (framework default) | NOT operator-deployed — would only appear in unconfigured / test builds |
| `/uri.php` | Framework default URI | Unit 42 (framework default) | UTA-2026-006 deviated from this default — operator chose 4 alternative URIs (Section 5.2) |

**For defender posture:** Block the network indicators above as additional AdaptixC2-ecosystem coverage if your environment can support multiple feeds. Treat the framework-default values (`172.16.196.1:4443`, `/uri.php`) as hunt strings for *any* unconfigured AdaptixC2 deployment — both Unit 42's and our recovered configs prove that operators consistently override the IP / port / URI defaults but typically leave header / UA defaults untouched. The header + UA combination is therefore the more durable detection target than IP / URI alone.

---

## 12. Response Orientation

This is a brief orientation for defenders who need to know *what to address*, not *how to address it*. Detailed incident response is the responsibility of the responding team's internal IR playbooks and is out of scope for this publication.

**Detection priorities (start here):**

- AdaptixC2 stock-listener network fingerprint — outbound HTTP POST to a fixed external IP carrying both `X-Beacon-Id` header AND Firefox 20 stock UA (the combination is the disambiguator)
- PowerShell loader chain — reflection-based AMSI bypass + `[Reflection.Assembly]::Load` of base64 PE + `[SI]::Inject(` invocation pattern (PowerShell ScriptBlock Event ID 4104)
- Cross-process injection from `powershell.exe` to `explorer.exe` with `PROCESS_ALL_ACCESS` granted access and W^X allocation pattern (Sysmon Event IDs 8 and 10)

**Persistence targets to inspect during IR:**

- Registry: NONE OBSERVED at the staging endpoint — operator-deployed persistence via the active C2 channel only; check `%TEMP%\*` and `%APPDATA%\*` for operator-chosen drop paths during active operations
- Scheduled tasks: NONE OBSERVED at the staging endpoint
- Files: any DLL named `msupdate.dll` co-located with a legitimate signed binary that imports it (sideload candidate from the kit)

**Containment categories (one-line labels):**

- Block C2 infrastructure at perimeter — `45.130.148.125` on TCP/80, TCP/4444, TCP/8888
- Isolate hosts observed making outbound connections to the C2 IP
- Rotate AD credentials and Kerberos tickets if any host has executed the PowerShell loader (full credential exposure assumed)
- Audit AD CS templates for ESC1–ESC8 misconfigurations (Certify abuse readiness in the kit)

---

## 13. Confidence Summary

Findings are organized below by the project-standard confidence framework. The list is not exhaustive but captures the assessments that drive the report's conclusions.

**DEFINITE (direct evidence, no ambiguity):**
- AdaptixC2 framework family attribution — three independent vendor labels (Elastic / Kaspersky / Microsoft) plus byte-for-byte architectural match against framework documentation
- RC4 key, agent_type, listener_type values recovered from beacon configuration (extracted via decompiler review and Python RC4 decryption)
- Toolkit composition and file inventory (28 named files plus carved artifacts, hash-confirmed against public commodity tool releases)
- Compile timestamps and same-day dev-to-prod build cadence
- Service co-location on `45.130.148.125` (TCP/80, TCP/4444, TCP/8888)

**HIGH (strong evidence):**
- Operator-written code identification (`beacon.ps1` and `injector.dll` matched pair)
- Build-environment fingerprints (Linux dev host, MinGW-w64 toolchain, PDB path, `si_build` class name)
- Attacker-controlled infrastructure conclusion (HIGH from TeamServer co-location)
- Selective AV-evasion finding for `SharpHound.exe` (86% high-entropy)
- Anticipated kill chain steps based on bundled toolkit composition
- UTA-2026-006 distinctive characteristic 1–7 documentation

**MODERATE (reasonable evidence, notable gaps):**
- Selective AV-evasion finding for `lazagne.exe` 10 MB variant (97% high-entropy + IsPacked + anti-debug — unconfirmed packer family without lab unpacking)
- DLL side-load preparation (`msupdate.dll` rename — deployment artifact, not confirmed-as-executed)
- Cohort alignment with Russian-speaking ransomware affiliate ecosystem (population estimate, not actor attribution)
- AdaptixC2 keylogging capability (T1056.001 — supported by BOF runtime, not directly observed)
- Bulletproof-hosting status of AS35682 (NOT CONFIRMED — 0.5/6 formal criteria, jurisdiction-only partial indicator)

**LOW / INSUFFICIENT (insufficient evidence to support specific claims):**
- Named-actor attribution — INSUFFICIENT (<50%); ACH ruled out Tropic Trooper (6 inconsistencies) and Tomiris (5 inconsistencies); H5 (unattributed mid-tier operator) wins the inconsistency comparison with 0 inconsistencies; H1 (Russian-speaking ransomware affiliate cohort) remains a population-level estimate only at 2 inconsistencies
- GOLD ENCOUNTER / PayoutsKing alternative hypothesis — LOW (50–60%, two inconsistencies)
- Active operations status of the staging endpoint — UNKNOWN; pending +1 week opendir-hunter rescan
- 172.105.0.126 OpenStrike cross-investigation pivot (UTA-2026-004) — LOW (30–40%, generic filename convention overlap only)

---

## Gaps & Assumptions

A consolidated list of the assumptions underlying this analysis, the alternative hypotheses considered but not adopted, and the evidence that would resolve each. Readers should treat this section as the explicit list of "what would change my mind" — both for personal due diligence and for downstream stakeholder communication.

### Key high-sensitivity assumptions

| Assumption | Why it matters | What would falsify it | Evidence sought |
|---|---|---|---|
| **Static-since-discovery (80+ hours) means the operator is unaware of the exposure** | Drives the threat-level reading. Alternative reading: pre-staged dormant infrastructure intentionally exposed because the operator does not consider this server consequential. | Detection of operator activity (file rotation, port closure, traffic to staging) before the +1 week rescan would confirm awareness. Continued staticness indicates either unawareness or unconcern. | +1 week opendir-hunter rescan target 2026-05-06; CertStream / passive DNS monitoring on `45.130.148.125`. |
| **Single operator (UTA-2026-006), not a shared infrastructure tenant** | Drives all UTA fingerprint distinctiveness claims. Alternative: a small operator team sharing build artifacts; a vendor of staged toolkits selling to multiple customers. | Recovery of multiple distinct operator handles, multiple uncoordinated deployment styles, or a public sale/lease post on a forum tying this build pipeline to multiple buyers. | Forum monitoring for `si_build` mentions; future deployment observations carrying the same fingerprints from clearly different operational tradecraft. |
| **Stock framework (no operator customization beyond loader + injector)** | Drives the "operator's only original code is `beacon.ps1` + `injector.dll`" claim. Alternative: operator has modified the framework but the modifications were not present in this build. | Any future build from the same operator showing modifications to the framework's network protocol, RC4 storage layout, or Donut shellcode-form generator. | Continued sample collection from this operator. |
| **Capability scoring reflects upper bound, not active impact** | Drives the threat-level header (HIGH on capability, would be CRITICAL on confirmed-active). | Confirmed active operations against named victims would escalate threat level. Confirmed decommissioning would de-escalate. | Continued infrastructure monitoring; victim-side incident reports. |

### Alternative hypotheses considered

The Analysis of Competing Hypotheses (Section 8.1) tested five attribution hypotheses. Two are explicitly ruled out (Tropic Trooper APT — six inconsistencies; Tomiris APT — five inconsistencies). The runner-up worth surfacing for consumers of this report is:

**H1 — Russian-speaking ransomware affiliate cohort.** Closest named-cohort fit (DFIR Report Nov 2025 Akira chain, Silent Push Aug 2025 CountLoader chain) at population-level alignment. Two inconsistencies prevent named-cohort attribution: (1) no observed Bumblebee or CountLoader entry stage in the recovered toolkit, (2) the operator's same-day dev-to-prod compile cadence and PDB-path leakage is more consistent with a less mature operator than the established Akira affiliate cohort. **What would flip H1 to MODERATE confidence:** observation of a Bumblebee / CountLoader entry stage tied to this infrastructure, OR a forum sale post selling deployment access to this server, OR victim-side IR observations matching Akira affiliate post-compromise tradecraft.

**H5 — Unattributed mid-tier operator (current adopted hypothesis).** Zero inconsistencies on the strict ACH test; technically the best-fit hypothesis. The `Unattributed` framing is the analytically-honest answer when the inconsistency test produces a tie or near-tie between a named cohort and an unnamed one — the unnamed wins because it carries no over-claim.

### Ecosystem exposure (UNKNOWN)

The AdaptixC2 framework is GPL-3.0 open-source on GitHub (github.com/Adaptix-Framework/AdaptixC2). Its ecosystem footprint — number of active deployments, forum-resale activity, active development cadence, fork landscape — is not directly assessable from a single open-directory observation. Defender treatment should not assume any single deployment is operationally connected to any other. Cohort-level signals (the four archetypes named in Section 9) are the right level of abstraction; deployment-to-deployment linkages require operator-fingerprint evidence as in this report.

### Evidence gaps that would materially upgrade the report

- **Live C2 traffic capture against a victim.** Would confirm active operational status and reveal C2 channel post-handshake behavior (currently inferred from framework documentation only).
- **Linux ELF Adaptix agent dynamic analysis.** Static analysis only. The Gopher Go agent variant (`gopher.x64.exe`) and the Linux ELF agent (`agent.bin`) have not been executed in a sandbox. Behavioral analysis would close gaps in Sections 4.4.1 and 4.4.2.
- **Lazagne 10MB packed variant unpacking.** Selective AV-evasion finding for `lazagne.exe` is MODERATE pending confirmation of the packer family. Manual unpacking would either confirm UPX-style commodity packer (downgrades to LOW operator-modification claim) or identify a custom/uncommon packer (upgrades to HIGH).
- **Operator handle attribution.** Forum monitoring for `si_build`, the per-listener type IDs, or the RC4 key value could surface operator handle, customer relationships, or deployment lineage.

---

## FAQ / Key Intelligence Questions

Quick answers to the questions analysts most frequently ask of a report like this one.

**Q: Is this APT-grade?**
No. The operator is mid-tier. Sub-mature OpSec (PDB paths, build timestamps, dev-leftover artifacts), one sophisticated tradecraft choice (W^X-aware injection), and otherwise textbook deployment. NOT consistent with named APT operators in the same threat-landscape neighborhood. Tropic Trooper and Tomiris APT hypotheses were explicitly tested and ruled out (six and five technical inconsistencies respectively).

**Q: Are victims confirmed?**
No. Active operational status is UNKNOWN. The C2 endpoint at `45.130.148.125:80` is reachable but no live victim traffic has been captured. The threat assessment in this report is capability-based on the staged toolkit, not impact-based on observed operations.

**Q: Is persistence observed?**
No persistence mechanism observed in the recovered artifacts. The kit covers initial access through lateral movement but does not include a persistence module in the staging directory — meaning either the operator deploys persistence at runtime via AdaptixC2 BOFs (likely, per framework BOF inventory), or this kit is intended for short-duration operations where persistence is not required (also possible). Defenders should still hunt for AdaptixC2-style persistence variants (registry Run keys, Scheduled Tasks, WMI subscription, COM hijack — all reachable via standard BOFs).

**Q: Is ransomware capability present?**
Not in the staged toolkit. No ransomware binary, no encryptor, no data-staging-for-exfiltration tooling observed. AdaptixC2 + post-exploitation tooling is fully consistent with the *initial-access-and-recon* phase of a ransomware operation, but the encryptor and exfiltration tooling — which would normally be deployed separately late in an operation — are not in this directory. Treat this as evidence that the operator is at the access-and-establish-foothold stage, not yet at the data-impact stage.

**Q: What is the durability of these IOCs against operator changes?**
Variable, ranked from most to least durable:
- **DEFINITIVE durability:** PDB path `/tmp/si_build/obj/Release/net472/si_build.pdb` and the `si_build` class name are operator-specific fingerprints embedded in build artifacts. Surviving any rotation that does not change the operator's build environment.
- **HIGH durability:** RC4 key `f443b9ce7e0658900f6a7ff0991cdee6` and per-listener type IDs `0xbe4c0149` / `0xcb4e6379` survive across the same listener configuration; would change on a fresh listener generation.
- **MODERATE durability:** Operator-written `beacon.ps1` + `injector.dll` sample hashes — survive byte-level rebuild only; trivially defeated by recompile.
- **LOW durability:** Single-IP infrastructure indicators (`45.130.148.125`) — operator can rotate this in minutes.
- **NETWORK FINGERPRINT (durable across operators):** AdaptixC2 framework HTTP signature (`X-Beacon-Id` + Firefox 20 UA) is durable until the framework changes upstream — not under this operator's control.

**Q: Is `45.130.148.125` shared infrastructure or dedicated?**
Dedicated. The TeamServer GUI port (TCP/4444) co-located with the victim-facing C2 and the staging directory rules out compromise-of-third-party scenarios; no legitimate co-tenancy story explains an open AdaptixC2 TeamServer alongside a Python SimpleHTTPServer staging directory. The IP belongs to AS35682 in Uzbekistan; abuse-reachability of the upstream provider is moderate (see Section 7).

**Q: Should I prioritize the framework-level detection or the operator-specific detection?**
Both, but for different purposes. Framework-level detection (HTTP fingerprint, RTTI strings, RC4 storage layout pattern) catches *any* AdaptixC2 operator running default configurations — broadest coverage value. Operator-specific detection (`si_build`, RC4 key, type IDs) catches *this* operator across infrastructure rotations — highest fidelity for cross-campaign tracking under UTA-2026-006. A defender with limited detection budget should deploy framework-level rules first and add operator-specific rules if they observe any UTA-2026-006 hits in their environment.

---

## 14. References and Further Reading

The following Tier-1 and Tier-2 sources informed this report's threat-landscape context. Specific URLs are not embedded in this report; readers can locate the cited reports through the vendor names and publication dates below.

**Tier 1 (government / framework):**
- CISA Joint Advisory **AA24-109A** — `#StopRansomware: Akira Ransomware`
- MITRE ATT&CK Framework — Enterprise Matrix (technique definitions)

**Tier 2 (vendor research):**
- **Unit 42 (Palo Alto Networks)** — AdaptixC2 framework primary technical reference
- **Silent Push (August 2025)** — AdaptixC2 ties to Russian Criminal Underworld + CountLoader IAB chain
- **The DFIR Report (November 2025)** — Bumblebee → AdaptixC2 → Akira chain (~44h time-to-ransomware)
- **Sophos (April 2026)** — STAC4713 / GOLD ENCOUNTER / PayoutsKing QEMU + AdaptixC2 chain
- **Kaspersky Securelist (December 2025)** — Tomiris APT with Havoc + AdaptixC2 + Telegram/Discord C2
- **Zscaler ThreatLabz (March 2026)** — Tropic Trooper trojanized SumatraPDF + GitHub-Issues C2 AdaptixC2 listener
- **Hunt.io** — Ligolo-ng + AdaptixC2 hunting analysis
- **Recorded Future / The Record** — Russian cybercrime adoption framing
- **Arctic Wolf** — Lorenz + chisel CVE-2022-29499 chain
- **AdaptixC2 GitHub repository + GitBook** — `github.com/Adaptix-Framework/AdaptixC2` (open-source GPL-3.0 framework primary documentation)
- **GhostPack / SpecterOps** — open-source post-exploitation tooling documentation

**Tier 3 (community / supporting):**
- **Malpedia** — chisel and CountLoader family pages
- **IPinfo + IPIP.NET + CAIDA AS Rank** — AS35682 reference
- **The Hacker News, BleepingComputer, Dark Reading, SC Media, Infosecurity Magazine, Security Boulevard, eSecurity Planet, GBHackers, TechNadu, Cyberpress** — multi-vendor secondary press synthesis on the AdaptixC2 ecosystem

---

© 2026 Joseph. All rights reserved. See LICENSE for terms.
