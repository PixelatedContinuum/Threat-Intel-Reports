---
title: "Multi-Cluster Open-Directory Tenancy on 79.137.192.3 — Rhadamanthys MaaS Customer Loader, BellaMain Turkish PhaaS, and Inkognito VPN/Phishing"
date: '2026-05-15'
series: opendir-79-137-192-3
series_role: parent
series_order: 0
detection_page: /hunting-detections/opendirectory-79-137-192-3-20260515-detections/
ioc_feed: /ioc-feeds/opendirectory-79-137-192-3-20260515-iocs.json
detection_sections:
  - label: "YARA Rules"
    anchor: "#yara-rules"
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "Suricata Signatures"
    anchor: "#suricata-signatures"
ioc_highlights:
  - value: "79[.]133[.]180[.]168"
    note: "Cluster C Rhadamanthys C2 (Hostkey NL, port 3394)"
  - value: "79[.]137[.]192[.]3"
    note: "Multi-tenant Aeza staging IP (3-cluster co-tenancy)"
  - value: "5c38a5dd3703b1c4b8c2466b18ce9f4c45ef4c9bf6c3096bee8b24d20ecd247a"
    note: "Customer-built loader staticlittlesource.exe (SHA256)"
  - value: "804f45487c1cda5b69c743f9eb691a12fe0fdcf0d3a9f32003898f1e3836af50"
    note: "Rhadamanthys Stage-2 PE (SHA256)"
  - value: "cryptone[.]bot"
    note: "Cluster A fake crypto exchange (Cloudflare-fronted)"
layout: post
permalink: /reports/opendirectory-79-137-192-3-20260515/
thumbnail: /assets/images/cards/opendirectory-79-137-192-3-20260515.png
category: "MaaS Operation"
hide: true
description: "Three operationally separate threat actors share one Aeza bulletproof staging IP. Cluster C is a Rhadamanthys MaaS customer with a custom VS2019 loader, EAX-redirect hollowing into InstallUtil.exe, and a 34-month-stable Hostkey NL C2 that survived Operation Endgame Phase 3."
---

**Campaign Identifier:** OpenDirectory-MultiCluster-Rhadamanthys-BellaMain-Inkognito-79.137.192.3<br>
**Last Updated:** May 16, 2026<br>
**Threat Level:** CRITICAL

> **Investigation series — Open-Directory 79.137.192.3 (three-publication series):** This is the parent report of a three-publication series from a single investigation into the multi-tenant Aeza Group staging server at `79.137.192.3`. Each cluster is operationally separate — co-tenancy on the same bulletproof IP is not operator linkage — and the two non-Rhadamanthys clusters each have their own standalone deep-dive:
>
> - **[Parent (2026-05-15) — Multi-Cluster Overview](/reports/opendirectory-79-137-192-3-20260515/)** *(this report)* — all three co-tenant clusters at boundary-level depth; establishes why they are *not* one operator; includes the Cluster C (Rhadamanthys MaaS customer) deep-dive.
> - **[Cluster A (2026-05-16) — BellaMain Turkish PhaaS](/reports/bellamain-turkish-phaas-79-137-192-3-20260516/)** — full PHP-source recovery of an operator-developed PhaaS panel + 7 Turkish-marketplace kits; UTA-2026-008.
> - **[Cluster B (2026-05-16) — Inkognito Russian VPN/Phishing](/reports/inkognito-russian-vpn-phishing-185-221-196-118-20260516/)** — 467+ brand-impersonation subdomain library bolted to a commercial VPN front; UTA-2026-009.

> **Risk vs. Campaign Threat Level:** The Cluster C Rhadamanthys MaaS-customer loader analyzed in this report scores **9.2/10 (CRITICAL)** based on a top-tier modern infostealer Stage-2, an active 34-month C2 (`79.133.180.168:3394`) that survived the November 2025 Operation Endgame Phase 3 takedown, and a mature anti-analysis stack (3-layer encrypted-blob synthesis + operator-modified Q3VM-derivative bytecode VM + EAX-redirect process hollowing into `InstallUtil.exe`). Clusters A (BellaMain Turkish PhaaS) and B (Inkognito VPN/phishing) score HIGH individually; the campaign-level CRITICAL rating is anchored on Cluster C.

## 1. Executive Summary

A single open-directory pivot on `79.137.192.3` (Aeza Group AS216246, Russian bulletproof hosting) surfaced **three operationally separate threat clusters co-tenanted on the same multi-tenant staging utility — none of which share operator-level evidence with each other**. The headline defender-actionable finding is **Cluster C: a Rhadamanthys infostealer Stage-2 (DEFINITE 97% — Microsoft `Trojan:Win32/Rhadamanthys!ic`, CAPE Rhadamanthys, 48/63 VirusTotal vendors) wrapped in a customer-built loader (`staticlittlesource.exe`)** that beacons to a Hostkey Netherlands C2 which has remained live for ~34 months and **survived the November 2025 Operation Endgame Phase 3 disruption** (the largest Rhadamanthys takedown on record — 1,025+ vendor servers seized covering 525,000+ infections in 226 countries). **Strategic implication:** Operation Endgame targeted vendor-side server infrastructure; customer-side C2s operating independently of the vendor's distribution network were outside the takedown's enforcement perimeter — meaning the MaaS customer model enables persistent operational continuity even when the vendor ecosystem is disrupted at scale. Cluster A is a Turkish-targeting Phishing-as-a-Service panel (BellaMain) operated by `@AresRS34` with developer pseudonym `Wadanz`; Cluster B is a 3-year-old Russian multi-product fraud operation (Inkognito) running 467+ brand-impersonation subdomains alongside a legitimate-looking VPN front. **Co-tenancy on the multi-tenant Aeza utility IP is not operationally diagnostic** — the U.S. Treasury OFAC Aeza Group sanction (July 1, 2025) documents Aeza simultaneously hosting BianLian, RedLine, Lumma, Meduza, and BlackSprut as five separate actor ecosystems, providing Tier-1 authoritative confirmation that bulletproof hosting co-residency is a service-utility relationship, not an operator-linkage signal.

Three findings in this report are absent from any reviewed Rhadamanthys public source: (1) a **3-layer encrypted-blob synthesis architecture** that defeats the standard "find the high-entropy region" heuristic by synthesizing the encrypted FS container from per-record byte-emitter functions + 7,979 fake-GUID-shaped ASCII-hex strings + a custom 14-bit Huffman-like bit-packed stream rather than storing it contiguously; (2) an **operator-modified Q3VM-derivative bytecode magic `0x14744214`** (vs stock Q3VM `0x12721444`) inside the embedded VM the Stage-2 uses to interpret its anti-analysis routines; and (3) a customer-selected **`InstallUtil.exe` LOLBin hollowing target** that does not appear in any reviewed Check Point v0.9.x customer-target enumeration (`dllhost.exe`, `taskhostw.exe`, `TsWpfWrp.exe`, `spoolsv.exe`, `wuauclt.exe`), with a non-standard **EAX-redirect entry-point hijack** instead of the classic `SetThreadContext`-based hollowing. Public Tier-1/Tier-2 Rhadamanthys reporting (Check Point Research v0.5.0/v0.7.0/v0.9.x, Outpost24, Zscaler, Recorded Future, Binary Defense, Proofpoint) thoroughly documents the vendor-side product; the customer-built loader layer and per-customer cipher fingerprints are largely undocumented because most public analysis works from the canonical Stage-2 outward. This investigation reverses that direction.

Three new internal threat-actor designations are recommended:

- **UTA-2026-008** *(an internal tracking label used by The Hunters Ledger — see Section 9)* — BellaMain Turkish PhaaS operator (Cluster A); MODERATE 75% distinct-actor confidence; INSUFFICIENT named-actor attribution (first public capture).
- **UTA-2026-009** *(an internal tracking label used by The Hunters Ledger — see Section 9)* — Inkognito Russian VPN/phishing operator (Cluster B); MODERATE 78% distinct-actor confidence; INSUFFICIENT named-actor attribution (first public capture).
- **UTA-2026-010** *(an internal tracking label used by The Hunters Ledger — see Section 9)* — Rhadamanthys MaaS customer (Cluster C); MODERATE 72% distinct-actor confidence; INSUFFICIENT named-actor attribution. **This designation tracks the customer-side operator only; the Rhadamanthys MaaS vendor itself is a separate threat-intel target with an existing published profile in public reporting and is NOT covered by UTA-2026-010.**

Because named-actor attribution is INSUFFICIENT for all three operators, the recommended defensive posture is **infrastructure-based blocking** (Aeza ASNs, active C2 IPs, kit URI patterns) and **behavioral detection** (see Section 10) rather than actor-tracking — behavioral detections remain valid regardless of whether attribution is ever resolved.

### Key Risk Factors

| Risk Dimension | Score (X/10) | Rationale |
|---|---|---|
| Data Exfiltration | 9/10 | Rhadamanthys family targets the full credential surface — browser passwords, cryptocurrency wallets, MFA tokens, VPN client configs, password managers, email client credentials — via the documented XS1/XS2 plugin module format. Cluster A captures payment cards + bank statements (dekonts) into a MySQL aggregator. |
| System Compromise | 9/10 | Cluster C uses canonical-grade process hollowing into a signed Microsoft LOLBin (`InstallUtil.exe`); host-process abuse blends C2 traffic into legitimate .NET-tooling network footprint. |
| Persistence Difficulty | 7/10 | Stage-2 is single-host with `HKU\<SID>\Software\SibCode\sn` registry marker (per-build Unix-timestamp value) and plugin-module loading. Pre-v0.9.1 family marker — cleanup is well-defined, but the C2 is durable. |
| Evasion Capability | 10/10 | Mature stack: 3-layer encrypted-blob synthesis defeats entropy-based detection of the encrypted region; custom CBC-XOR cipher with per-customer 16-byte IV; operator-modified Q3VM-derivative bytecode VM defeats off-the-shelf disassemblers; `0xCCCCCCCC` anti-forensic memory scrub before `VirtualFree`; 14-second cumulative anti-analysis delay; `NtQuerySystemInformation`-driven analyzer-process blocklist. |
| Lateral Movement | 6/10 | Rhadamanthys itself is single-host stealer; downstream lateral movement depends on the credentials/access tokens harvested from each victim. |
| Detection Difficulty | 9/10 | Stage-2 import surface camouflages as a graphics utility (GDI32 ≥ 100 imports + USER32 minimal + crypto-absent + network-absent); all crypto, network, and registry-write APIs resolved at runtime from the host process's PEB after injection — static-imports-only analysis is materially misleading. |

**Overall Risk Score: 9.2/10 — CRITICAL**

### Threat Actors

- **UTA-2026-010 — Rhadamanthys MaaS customer (Cluster C, primary).** Single LLM-augmented amateur customer of a top-tier commodity MaaS stealer. Distinct-actor confidence MODERATE (72%); named-actor attribution INSUFFICIENT.
- **UTA-2026-008 — BellaMain Turkish PhaaS operator (Cluster A).** Single Turkish-speaking PhaaS operator/developer. Operator alias `@AresRS34`, developer alias `Wadanz`. Distinct-actor confidence MODERATE (75%); named-actor attribution INSUFFICIENT.
- **UTA-2026-009 — Inkognito Russian VPN/phishing operator (Cluster B).** Single Russian-speaking multi-product fraud operator. Self-identified parent brand "Inkognito" via `@inkconnectvpn` Telegram channel. Distinct-actor confidence MODERATE (78%); named-actor attribution INSUFFICIENT.

### For Technical Teams — Immediate Priorities

- **Hunt: `InstallUtil.exe` initiating outbound TLS to non-Microsoft endpoints.** This single behavioral pattern is the highest-fidelity Cluster C detection across the entire Rhadamanthys MaaS ecosystem (any customer, any C2). See Section 9 for kill chain context and the separate detection file for the Sigma/Suricata implementation.
- **Hunt: Registry write to `HKU\<SID>\Software\SibCode\sn`.** Rhadamanthys family marker (pre-v0.9.1 builds, which include the Stage-2 analyzed here per Check Point's documented changelog removal in v0.9.1). No known benign software writes this key.
- **YARA: Stage-2 import-surface signature.** GDI32 ≥ 100 + USER32 exactly 3 (`GetDC`, `ReleaseDC`, `GetSystemMetrics`) + ADVAPI32 registry-READ-only + NO crypto + NO network + `.frontb` PE section identifies Rhadamanthys Stage-2 across all customers. Vendor-side, customer-independent. See Section 5 and the separate detection file.
- **Block: C2 IP `79.133.180.168:3394` and the alternate-customer C2 `45.81.39.169`** (recovered from sibling Stage-2 `bc9fe5e9...`). The alternate IP confirms multi-customer MaaS architecture — different customers, different per-build C2s.
- **Treat all Aeza ASNs (`AS216246`, `AS210644`, `AS211522`/Hypercore) as OFAC-sanctioned infrastructure** for regulated entities. Inbound or outbound traffic to these ASNs constitutes engagement with sanctioned infrastructure.

---

## 2. How This Investigation Unfolded

This section provides a brief narrative arc — useful for understanding why the report has three clusters, why two of them play a supporting role, and how the analytical framing on co-tenancy was reached. Readers who want to skip directly to Cluster C technical analysis can jump to Section 4.

### 2.1 The pivot

The investigation began when **OpenDir Hunter** (the analyst's custom open-directory scanning platform) surfaced an exposed BellaMain panel directory and a kit listing on `79.137.192.3`. Initial impression: a Turkish-targeting Phishing-as-a-Service operation. Static triage of seven `.rar` phishing kits (Dolap, Kargo, Letgo, Pttavm, sahibinden, shopier, turkcell) and the BellaMain panel ZIP confirmed Cluster A.

But OpenDir Hunter also surfaced two unrelated directories on the same IP: `cryptone/` (a fake crypto exchange UI) and `no/` (a card-phishing lure), as well as a number of historical co-tenants visible via passive DNS. Pulling on those threads raised the central analytical question: are these all the same operator running multiple kits, or are they different operators sharing the same hosting utility?

### 2.2 The branching

Iris Investigate domain history and VirusTotal pivots from the IP returned a substantial co-tenancy footprint. Among the historical co-tenants of `79.137.192.3` were **BriansClub** (`bclub.mp`), **CRD Club** (`crdclub.su`), elon-merge.com, RedLine Stealer (`Incurious.exe`), SmokeLoader (`kourimaobaku.exe`), and Tofsee spam botnet (`a52d0a1829a0ff_15M.exe`). Static triage of those PE samples (with `PreProcess` and `StaticTriage` analyst tooling — internal automation) confirmed each of those tenants belongs to a distinct, well-documented threat family with no operator overlap to BellaMain.

Pulling on the fake-exchange directory `cryptone/` led to the production domain `cryptone.bot` (Cloudflare-fronted, origin hidden) — and from there, pivoting on TLS fingerprints, search-console verification IDs, and registration patterns, to a much broader **Inkognito** brand portfolio: INK VPN (`inkconnect.ru`), INK Lens phishing platform (`inklens.ru` / `inklens.co.uk`), CryptOne fake exchange, Bikaf VPN. Cluster B emerged from these pivots.

A separate thread followed the loader sample `staticlittlesource.exe` recovered from the same IP. Static analysis identified the canonical `.frontb` PE section and decryption of the `.data`-resident encrypted region produced a Microsoft-classified `Trojan:Win32/Rhadamanthys!ic` Stage-2. Cluster C — the headline finding — emerged from this thread.

### 2.3 The framing

By the time three operationally distinct clusters were identified on the same Aeza staging IP, the analytical question shifted from "what are these operators doing?" to **"how should defenders interpret co-tenancy on bulletproof hosting?"** The U.S. Treasury OFAC sanction of Aeza Group on July 1, 2025 provided a Tier-1 anchor: the OFAC documentation explicitly enumerates Aeza simultaneously hosting BianLian ransomware, RedLine stealer, Lumma stealer, Meduza stealer, and BlackSprut — five separate actor ecosystems with no documented operational linkage between them. Co-tenancy on a multi-tenant bulletproof utility is therefore a **service-utility relationship, not an operator-linkage signal**.

This framing controls the rest of the report. Clusters A, B, and C are presented as three separate threat actors that happened to share a hosting utility; cross-cluster linkage is rated **LOW (actively rebutted, not absent)**. Sections 4–8 focus on Cluster C technical depth (the headline defender-actionable finding); Sections 6.4–6.5 cover Clusters A and B briefly for narrative completeness. Section 10 covers the full per-cluster threat-actor assessment.

---

## 3. Technical Classification

| Field | Cluster A — BellaMain | Cluster B — Inkognito | **Cluster C — Rhadamanthys (PRIMARY)** |
|---|---|---|---|
| **Type** | Phishing-as-a-Service panel + 7 marketplace phishing kits | Multi-product fraud (VPN + phishing + fake exchange) | **Infostealer (MaaS) — multi-stage loader + canonical Rhadamanthys Stage-2** |
| **Family** | BellaMain (custom PhaaS panel, Turkish-targeted) | Inkognito (operator brand) | **Rhadamanthys (MaaS family); customer-built loader** |
| **Family Confidence** | DEFINITE (full source recovered) | DEFINITE (operator self-identification) | **DEFINITE 97% (Microsoft + CAPE + 48/63 VirusTotal vendors converge)** |
| **Sophistication** | Intermediate | Intermediate-Advanced | **Vendor: HIGH PROFESSIONAL; Customer: MODERATE (LLM-augmented amateur)** |
| **First Seen** | 2024-04 (kits VT first-seen); BellaMain.zip 2026-03 | 2023-06-08 (`vetcorbeanca.eu` BEC burn) | **Loader compile 2023-06-25; Stage-2 cluster ~34 months active** |
| **Threat Actor (UTA)** | UTA-2026-008 | UTA-2026-009 | **UTA-2026-010 (customer only)** |
| **Distinct Actor Confidence** | MODERATE (75%) | MODERATE (78%) | MODERATE (72%) |
| **Named Actor Attribution** | INSUFFICIENT | INSUFFICIENT | INSUFFICIENT |
| **Threat Level** | HIGH | HIGH | **CRITICAL** |

### Cluster C Stage-2 file identifiers

| Field | Value |
|---|---|
| File name (internal) | `embedded_payload.bin` (extracted from loader; vendor builds use various names) |
| MD5 | `0e07ccda99c1cd80a2fd92e02b75d9a0` (from extracted Stage-2; loader MD5 differs) |
| SHA256 | `804f45487c1cda5b69c743f9eb691a12fe0fdcf0d3a9f32003898f1e3836af50` |
| File Size | 458,752 bytes (448 KB) |
| Compile Toolchain | **Visual Studio 2003** (Microsoft Linker 7.10.3077, MSVC 13.10.3077) — 22-year-old toolchain |
| PE Subsystem | Windows GUI |
| Signature | Unsigned |
| VT Detections | 48/63 |
| Microsoft Verdict | `Trojan:Win32/Rhadamanthys!ic` |
| CAPE Verdict | `Rhadamanthys` (definitive) |

### Cluster C loader file identifiers

| Field | Value |
|---|---|
| File name (original) | `staticlittlesource.exe` |
| MD5 | `ae9991a02aa20ebbc2cc3c0f40924442` |
| SHA1 | `f9a563d92d1ab148326f1b1f2b8d5ae70c0c6ee0` |
| SHA256 | `5c38a5dd3703b1c4b8c2466b18ce9f4c45ef4c9bf6c3096bee8b24d20ecd247a` |
| Imphash | `1e5efd483892326cc4eeb97bc14a6266` |
| Compile Timestamp | 2023-06-25 23:01:08 UTC |
| File Size | 1,390,592 bytes (1.39 MB) |
| Toolchain | Visual Studio 2022 v17.4, MSVC 19.34.31937, LTCG/C++ |
| VT Detections | 60/77 |

### Why this Stage-2 is canonical Rhadamanthys (DEFINITE 97%)

Multiple independent confirmations converge:

- **Microsoft Defender:** `Trojan:Win32/Rhadamanthys!ic` (the `!ic` suffix indicates ML-based identification, but the family designation matches the canonical Microsoft signature for Rhadamanthys).
- **CAPE sandbox:** definitive `Rhadamanthys` classification with Procmon-confirmed registry write to `HKU\<SID>\Software\SibCode\sn` (the documented Rhadamanthys family marker for pre-v0.9.1 builds).
- **48/63 VirusTotal vendors converge** on Rhadamanthys family naming (variant names differ across vendors but the family is consistent).
- **`.frontb` PE section** — Rhadamanthys family signature (the empty 701 KB pre-allocated runtime buffer for the decrypted Stage-2 payload).
- **SibCode VCL artifacts** in the binary — consistent with documented Rhadamanthys vendor toolchain.
- **VS2003 toolchain** (22 years old) — consistent with mature MaaS operations maintaining a stable legacy Stage-2 build while vendor layers evolve around it (per Check Point v0.9.x walkthrough).

### Vendor versus customer — a critical distinction

Rhadamanthys is a Malware-as-a-Service product. The **vendor** (the threat-intel target documented in Check Point Research v0.5.0/v0.7.0/v0.9.x, Outpost24, Zscaler, Recorded Future, and other public reporting) builds and sells the canonical Stage-2 to multiple **customers**, who each build their own loaders and operate their own C2 infrastructure. UTA-2026-010 in this report tracks the **customer-side operator only** — the LLM-augmented amateur who built `staticlittlesource.exe`, deployed it via cracked-software/game-cheat lures, and operates the Hostkey NL C2 at `79.133.180.168:3394`. The vendor is out of scope for this investigation and is not covered by UTA-2026-010.

This distinction is operationally important because the customer's loader and per-customer cipher fingerprints (the 16-byte CBC-XOR IV `f6358d79df69c577d9dce6bb77fa4fa7`, the 24-hex panel ID `e6d92c6b5b2a03bee7fbab40`, the InstallUtil LOLBin choice) are higher-fidelity detection primitives for **this specific customer's deployments** than vendor-side family markers. Vendor-side markers (`.frontb`, the import surface, the Q3VM magic) detect the entire Rhadamanthys MaaS ecosystem but do not differentiate between customers. Both layers of detection are valuable and are presented in Sections 5 and 9.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-79-137-192-3-20260515/loader-vs2019-stdlib-bloat.png" | relative_url }}" alt="Ghidra decompile view of the Visual Studio 2019 standard-library function __acrt_get_process_end_policy recovered from the customer-built loader, showing a ProcessEnvironmentBlock dereference and the AppPolicyGetProcessTerminationMethodInternal call chain.">
  <figcaption><em>Figure 1: A VS2019 standard-library function (`__acrt_get_process_end_policy`) recovered intact from `staticlittlesource.exe`, illustrating the commodity stdlib bloat that distinguishes the customer-side build from the Rhadamanthys vendor's mature legacy toolchain. The vendor-side Stage-2 was compiled with a 22-year-old MSVC linker; this customer-side loader was compiled with VS2019 / MSVC 19.34 — a categorical toolchain split that supports the vendor-vs-customer separation argument.</em></figcaption>
</figure>

---

## 4. Capabilities Deep-Dive

> **Analyst note:** This section enumerates what the Cluster C Rhadamanthys Stage-2 and the customer-built loader are capable of doing once executed. The Stage-2 capabilities are the canonical Rhadamanthys feature set documented across multiple Tier-2 vendor reports; the loader capabilities are this specific customer's tradecraft. Clusters A and B receive condensed capability summaries because they are not the report's headline focus.

The Cluster C deployment is a two-layer system. The customer-built loader (`staticlittlesource.exe`) handles delivery, decryption of the embedded payload, and process hollowing into a signed Microsoft LOLBin (Living Off the Land Binary). The Rhadamanthys Stage-2 (`embedded_payload.bin`, MD5 `0e07ccda...`) is the canonical commodity infostealer that performs all credential theft, host enumeration, C2 communication, and plugin orchestration. Each layer has a separate threat profile.

### 4.1 Capability Matrix — Cluster C (primary)

| Capability | Layer | Confidence | Operational Impact |
|---|---|---|---|
| RC4-decrypted embedded Stage-2 PE | Loader | HIGH | Defeats AV signature scans of the on-disk loader by keeping the payload encrypted until runtime |
| EAX-redirect process hollowing into `InstallUtil.exe` | Loader | HIGH | C2 traffic appears to originate from a signed Microsoft binary; W^X memory transitions defeat memory-RWX detection heuristics |
| 14-second cumulative anti-analysis sleep | Loader | HIGH | Outlasts most automated sandbox emulation budgets without triggering simple sleep-skipping heuristics (denormal-sentinel verification) |
| Browser credential theft (Chrome / Firefox / Edge / Brave) | Stage-2 | HIGH | Full extraction of saved passwords, cookies, autofill, payment methods |
| Cryptocurrency wallet theft (Metamask / Phantom / TrustWallet / Ledger Live) | Stage-2 | HIGH | Wallet seed phrases and signed-session theft enables direct fund drainage |
| MFA / authenticator app theft | Stage-2 | HIGH | Defeats software-based MFA on theft-then-replay scenarios |
| Password manager theft (KeePass / 1Password vault files) | Stage-2 | HIGH | Vault theft + keylog of master password = total credential portfolio compromise |
| VPN client config + credential theft (OpenVPN / WireGuard) | Stage-2 | HIGH | Lateral access into corporate VPN-protected resources |
| Email client credential theft (Outlook / Thunderbird) | Stage-2 | HIGH | Inbox access for BEC pivoting |
| Screen capture | Stage-2 | HIGH | `BitBlt` via the GDI32-heavy import surface; periodic visual exfiltration |
| Plugin module loading (XS1 / XS2 format) | Stage-2 | HIGH | Vendor delivers new capabilities without re-deploying the Stage-2 binary |
| Dynamic API resolution from host PEB | Stage-2 | HIGH | Static analysis of the Stage-2 in isolation cannot enumerate the true import surface (network / crypto / registry-write APIs are absent from the static IAT) |
| `0xCCCCCCCC` anti-forensic memory scrub before `VirtualFree` | Stage-2 | HIGH | Defeats post-mortem memory carving for plaintext config recovery |
| `NtQuerySystemInformation` analyzer-process blocklist | Stage-2 | HIGH | Refuses to execute the credential-theft path when known-analysis processes are running |

### 4.2 Loader-side capabilities (customer)

#### 4.2.1 RC4-decrypted Stage-2 payload

The loader carries the Rhadamanthys Stage-2 as an encrypted blob in its `.data` section. At runtime it locates the blob via a relative offset, retrieves a 31-byte RC4 key from `&DAT_00433820` (the literal bytes `e0802540d02d0feaeb277dc720e390b06dfd64d8f8104d9581e788e512715b`), and runs a standard RC4 keystream over the encrypted region. The decrypted output is a fully-formed PE file whose `MZ`/`PE` headers are visible after decryption.

**Why the customer chose RC4:** RC4 is a streaming cipher that requires no padding, no IV, and no per-block state. From a customer-side amateur perspective, it is the simplest possible "encrypt the payload, decrypt it before injection" wrapper. The recovered 31-byte key length is non-standard (RC4 keys are typically 16 or 32 bytes); this is consistent with the LLM-augmented amateur tradecraft profile in the attribution assessment — a developer who knows enough to wrap the payload but not enough to align with the standard key length.

**Why this matters for defenders:** The encrypted-on-disk wrapper means that file-hash and string-match detections of the on-disk loader cannot match against canonical Rhadamanthys Stage-2 signatures (the `.frontb` PE section, the `Trojan:Win32/Rhadamanthys!ic` Microsoft signature, the `48/63 VirusTotal vendors` consensus). Detection content for this loader must trigger on the loader's own characteristics (the operator strings `BombAUb23456`, `DubzAias932`, the 31-byte RC4 key bytes, the `ae9991a02aa20ebbc2cc3c0f40924442` MD5) — not on the Stage-2 family signatures. The Stage-2 signatures only become detectable after the loader has decrypted the payload into memory.

#### 4.2.2 EAX-redirect process hollowing into InstallUtil.exe

Process hollowing is the technique of suspending a legitimate target process at startup, replacing its mapped image with malicious code, and resuming execution. The classic implementation (documented across MITRE ATT&CK T1055.012, every introductory hollowing tutorial, and the bulk of EDR detection rules) is a four-API sequence:

1. `CreateProcess(target, CREATE_SUSPENDED)` — start the host in suspended state
2. `NtUnmapViewOfSection` (or `ZwUnmapViewOfSection`) — unmap the original image
3. `VirtualAllocEx` + `WriteProcessMemory` — allocate RWX memory and write the malicious image
4. `SetThreadContext` (re-pointing `EIP`/`RIP` to the new entry point) + `ResumeThread`

This Cluster C loader uses a variant defenders may not have seen documented — the **EAX-redirect entry-point hijack**. The first three steps are similar, but the entry-point control is achieved differently:

- The malicious code is written into memory **with W^X transitions, not RWX** — pages are allocated `PAGE_READWRITE`, written, then re-protected to `PAGE_EXECUTE_READ` via `VirtualProtectEx`. This defeats the simple "look for RWX private memory in suspended-but-newly-spawned processes" detection heuristic.
- Instead of `SetThreadContext` overwriting the instruction pointer, the loader patches the suspended thread's `EAX` register only. Because the Windows process loader uses `EAX` as the convention for the entry-point address that `kernel32!BaseThreadInitThunk` jumps to on initial thread resumption, patching `EAX` alone redirects execution to the injected payload — without ever touching `EIP`/`RIP` directly.

The result is a hollowing variant that:
- Does not allocate RWX memory (W^X transition only — defeats RWX-allocation detection)
- Does not call `SetThreadContext` with a modified `Eip`/`Rip` (defeats `Eip`-modification detection)
- Does call `SetThreadContext` (the `EAX` patch still requires it), but the modified field is `Eax` rather than `Eip`/`Rip`

**Detection implication:** EDR rules that key on RWX allocation in a freshly-suspended process, or on `SetThreadContext` with an `Eip` value pointing into RWX memory, will miss this variant. Effective detection must look at: (a) the parent-child relationship `staticlittlesource.exe` → `InstallUtil.exe`, (b) `InstallUtil.exe` running with no `.NET` assembly path argument (legitimate `InstallUtil` always takes a `/u` flag and an assembly path), (c) `InstallUtil.exe` initiating outbound network connections to non-Microsoft endpoints.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-79-137-192-3-20260515/loader-eax-redirect-installutil-hollowing.png" | relative_url }}" alt="Ghidra decompile of the loader's process hollowing routine showing two highlighted regions: at top, the EAX-register write that redirects entry-point execution; at bottom, the wide-character literal pointing to C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\InstallUtil.exe used as the hollowed target.">
  <figcaption><em>Figure 2: Decompiled loader code showing the two halves of the EAX-redirect process hollowing technique in one frame. The bottom highlight is the operator's hardcoded target — `InstallUtil.exe`, the Microsoft .NET Framework signed-binary LOLBin. The top highlight is the EAX-register write into the suspended thread's context (offset `0xb0` in the CONTEXT structure) that redirects entry-point execution to the injected payload, without modifying `EIP`/`RIP` and without ever allocating RWX memory. The visible `Ellipse(...)` and `GetAspectRatioFilterEx(...)` calls between the highlights are the GDI32 decoy imports the loader uses to camouflage its true behavior as graphics processing.</em></figcaption>
</figure>

**Why InstallUtil.exe specifically:** `InstallUtil.exe` is a signed Microsoft binary (ships with the .NET Framework at `C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe`) that is on most application allowlists and is presumed-trusted by most EDR tooling. It is also a known LOLBin (LOLBAS T1218.008) for malicious code execution. Reviewed Check Point Rhadamanthys v0.9.x customer-target enumerations (`dllhost.exe`, `taskhostw.exe`, `TsWpfWrp.exe`, `spoolsv.exe`, `wuauclt.exe`) do not include `InstallUtil.exe` — this is a per-customer tradecraft choice, not a vendor default. The choice is operationally consistent with a customer who has read LOLBAS but is selecting a target that is less-monitored than the vendor's documented defaults.

#### 4.2.3 14-second cumulative anti-analysis sleep with denormal-sentinel checks

> **Analyst note:** Most automated malware sandboxes only run a sample for a couple of minutes and skip long sleep timers to speed up analysis. This loader stalls for 14 seconds and uses an unusual floating-point check to detect when a sandbox has skipped the wait — if it has, the loader exits without doing anything malicious, defeating the analysis.

The loader executes a series of `Sleep` calls totaling approximately 14 seconds before any malicious activity. This duration is calibrated to exceed typical automated-sandbox emulation budgets (most commodity sandboxes emulate 30–120 seconds total but allocate only 2–5 seconds to pre-malicious-activity sleep).

The implementation includes a **denormal-sentinel verification** — a floating-point computation whose result is a denormal number (a sub-normal IEEE-754 value that is correct but slightly off in ULP terms compared to a sandbox's emulated FPU). The loader checks the result against a hardcoded reference; a mismatch indicates the FPU is being emulated rather than executed natively, and the loader exits without executing the payload.

**Why this matters:** Simple sleep-skipping (the technique where a sandbox replaces `Sleep(N)` with a no-op or `Sleep(0)`) does not advance the FPU state correctly and produces a different denormal result than native execution. This defeats the most common automated sandbox-evasion bypass.

### 4.3 Stage-2 capabilities (vendor — canonical Rhadamanthys)

The Stage-2 capabilities are documented in detail across the Tier-2 Rhadamanthys public reporting (Check Point Research v0.5.0, v0.7.0, v0.9.x; Outpost24; Zscaler ThreatLabz; Recorded Future Insikt Group; Binary Defense; Proofpoint). This report does not duplicate that documentation in depth — it summarizes the capabilities that are observable in this specific customer's Stage-2 (MD5 `0e07ccda99c1cd80a2fd92e02b75d9a0`) and notes the family-signature artifacts that defenders can use.

#### 4.3.1 Credential and wallet theft

The Stage-2 targets the full credential surface that modern infostealers harvest:

- **Browser credentials** — Chrome, Firefox, Edge, Brave, Opera Login Data SQLite databases; cookies including session cookies for active web sessions; autofill and payment-method data
- **Cryptocurrency wallets** — Metamask, Phantom, TrustWallet, Ledger Live, Exodus, Atomic, Electrum, and other documented v0.9.x wallet targets
- **Authenticator apps** — Authy, Microsoft Authenticator, Google Authenticator local databases
- **Password managers** — KeePass `.kdbx` vault files, 1Password vault files, Bitwarden local cache
- **VPN client configs** — OpenVPN `.ovpn` files with embedded credentials, WireGuard configs, Cisco AnyConnect cache
- **Email client credentials** — Outlook PST/OST cache, Thunderbird profile, Mailbird cache
- **Messaging app sessions** — Telegram desktop session, Discord token, Slack token, WhatsApp web session
- **FTP / SSH / RDP saved credentials** — FileZilla `recentservers.xml`, WinSCP saved sessions, PuTTY saved hosts, RDP `.rdp` files with saved passwords

The architecture for credential theft is the **XS1/XS2 plugin module format** — a vendor-defined binary container that the Stage-2 loads from the C2 at runtime. New theft targets are added by the vendor without re-deploying the Stage-2 binary. This is the mechanism that allowed Rhadamanthys to add cryptocurrency-wallet-image OCR (Bitcoin seed-phrase recognition from screenshots — Recorded Future Insikt Group, September 2024) without breaking any deployed customer infrastructure.

#### 4.3.2 SibCode\sn registry persistence marker

The Stage-2 writes a per-build Unix-timestamp value to `HKU\<SID>\Software\SibCode\sn` on first execution. This is the documented Rhadamanthys family marker for pre-v0.9.1 builds. Per Check Point Research v0.9.x walk-through, the developer **explicitly removed registry write operations in the v0.9.1 changelog** — meaning samples that write to this key are pre-v0.9.1, which dates this customer's Stage-2 to a build before that release.

**Detection value:** The `HKU\<SID>\Software\SibCode\sn` registry write is a high-fidelity Rhadamanthys family marker with no known benign software collisions. SibCode is a defunct VCL component vendor; legitimate software does not write to this key. Any registry-set telemetry on `Software\SibCode\sn` is a presumptive Rhadamanthys infection.

#### 4.3.3 Plugin module loading

> **Analyst note:** Rhadamanthys is sold as a malware platform, not a single program. After the initial infection, the malware downloads add-on "plugin" modules from the criminal vendor's catalog — for example, modules that steal cryptocurrency wallets, screenshot the desktop, or read text from images. Defenders should expect the malware's behavior on an infected host to grow over time as new plugins arrive.

Once installed, the Stage-2 contacts the C2 to download additional capability modules in the XS1/XS2 format. These modules expand the credential-theft surface, add screen-capture or keylogging capability, deploy follow-on payloads (downloader functionality), or load specialized targets (the Bitcoin OCR module). This is a standard MaaS architecture — the vendor maintains the module catalog and customers receive updates without redeploying their loaders.

### 4.4 Cluster A (BellaMain) — condensed capability summary

> **Analyst note:** Cluster A is a Phishing-as-a-Service panel and is included for narrative completeness. It is operationally separate from Cluster C and uses a categorically different attack model (credential-harvesting via spoofed marketplace login pages, not malware execution).

**Capabilities:**
- **PhaaS panel (BellaMain v3 with admin path `V5VgjLU0jsDe`)** — multi-tenant phishing-page management, sub-operator account provisioning with 70% revenue share, MySQL credential aggregation (database `jakartaxdw` shared across the panel and all 7 kits)
- **Seven Turkish marketplace phishing kits** — Dolap (clothing resale), Kargo (parcel delivery lure), Letgo (classifieds), PTTAvm (postal-service marketplace), Sahibinden (general marketplace), Shopier (commerce platform), Turkcell (telecom) — all collecting login credentials, payment-card details, and bank-statement (`dekont`) uploads
- **Telegram exfil pipeline** — hardcoded bot token `6797512084:AAGbJVoC0zcKWYPbFG8oc_bACPn6gUEye_E` in all six `girislog.php` files; exfil to chat IDs `-1002104835510` (credential channel) and `-1001817323952` (operator channel); withdrawal-approval workflow gated to admin Telegram UIDs `5606327063` and `6594066326`
- **TRX (Tron) cryptocurrency payout workflow** in `cekimbot.php` for converting harvested card balances to operator-controlled wallets
- **Live fake crypto exchange front (`cryptone.bot`, Cloudflare-fronted)** — second-stage social engineering vector for victims who provide credentials to the spoofed marketplace pages

**Status:** The hardcoded Telegram bot token was REVOKED on 2026-05-07 (HTTP 401 on `getMe`), but the bot ID retains pivot value for retroactive analysis. The kits remain on the staging IP.

### 4.5 Cluster B (Inkognito) — condensed capability summary

> **Analyst note:** Cluster B is a multi-product fraud operation combining a legitimate-looking VPN front with a brand-impersonation phishing infrastructure. Like Cluster A, it is included for narrative completeness; it is operationally separate from Cluster C.

**Capabilities:**
- **INK VPN consumer brand** (`inkconnect.ru`) — Russian-language VPN service marketed to censorship-region populations; provides legitimate VPN service as a customer-acquisition front
- **INK Lens phishing platform** (`inklens.ru` / `inklens.co.uk`) — 467+ brand-impersonation subdomains spoofing Wells Fargo, Accenture, Tencent, AnyDesk, OWA 2013, Jenkins development environments, SolidWorks downloads, and other corporate brands
- **CryptOne fake crypto exchange** (`cryptone.bot`, also referenced from Cluster A but operationally Inkognito-controlled) — Cloudflare-fronted credential-harvesting frontend
- **Bikaf VPN** (`bikaf.ru`, decommissioned) — earlier consumer VPN brand with CCTV/Hikvision angle
- **EspoCRM back-office** on dedicated Aeza IT IP `185.221.196.118` — single-instance customer relationship management for the Inkognito brand portfolio
- **Russian payment processor integration** — SBP (Sistema Bystrykh Platezhey, Russian Fast Payment System), T-Pay, and direct card processing
- **`X-Admin-Token` custom API auth header** on `api.inkconnect.ru` — operator-controlled API surface for cross-product administration
- **`kittenx-404` decommission tombstone HTTP header** — operator-standard fingerprint left on retired domains; cross-domain consistency confirms single-operator control

**Operational model:** "Provide-then-phish" — the legitimate VPN service builds operator-customer trust, then the same operator delivers targeted credential theft via the brand-impersonation INK Lens platform. The operation has run continuously for approximately 2.5 years (earliest BEC burn-domain `vetcorbeanca.eu` 2023-06-08) with multi-tier provider segmentation (Aeza for back-office, Cloudflare for production fronts, Stark Industries for BEC burn domains, Timeweb for some VPN edge nodes).

---

## 5. Static Analysis

> **Analyst note:** This section walks through the static reverse-engineering work that produced the technical findings underpinning the report. The novel material — the 3-layer encrypted-blob synthesis, the Q3VM-derivative bytecode VM, the per-customer cipher fingerprints — is concentrated here. Defenders who only need detection content can skip to Section 8 (IOCs) and Section 10 (Detection Coverage); analysts and researchers who want to reproduce the analysis or extend it to sibling samples should read this section carefully.

Three previously-undocumented findings emerge from the Cluster C static analysis: a 3-layer encrypted-blob synthesis architecture (§5.3), an operator-modified Q3VM-derivative bytecode VM (§5.6), and per-customer cipher fingerprints that differentiate this MaaS customer from sibling deployments (§5.4). Analysis used a disassembler (Ghidra) and supporting Python scripts against `staticlittlesource.exe` (the loader, MD5 `ae9991a02aa20ebbc2cc3c0f40924442`) and the extracted `embedded_payload.bin` (the Stage-2, MD5 `0e07ccda99c1cd80a2fd92e02b75d9a0`). The Stage-2 was extracted by following the loader's RC4 decryption path with the recovered key, then reconstructing the Stage-2's encrypted-blob synthesis by simulating the byte-emitter functions and bit-packed stream.

### 5.1 Loader: RC4 decryption of the embedded Stage-2

The loader's RC4 routine is a textbook implementation — straightforward to recover and confirms the customer-side amateur tradecraft profile. The loader is a 1.39 MB MSVC C++ binary (Visual Studio 2022 v17.4, LTCG/C++) with a flat function layout and no obfuscation at the loader layer. The RC4 decryption routine at `FUN_00402400` follows the standard KSA + PRGA form: 256-byte S-box initialization with permutation, then a streaming XOR over the ciphertext with `i` and `j` indices.

**Recovered RC4 key:** 31 bytes at `&DAT_00433820`:
```
e0 80 25 40 d0 2d 0f ea eb 27 7d c7 20 e3 90 b0
6d fd 64 d8 f8 10 4d 95 81 e7 88 e5 12 71 5b
```

**Encrypted blob location:** The encrypted Stage-2 PE lives in the loader's `.data` section. The loader walks to it via a known relative offset, performs the RC4 decryption into a heap-allocated buffer, and the result is a fully-formed PE with valid `MZ`/`PE` headers (the canonical Rhadamanthys `.frontb` section is visible after decryption).

**Operator instrumentation strings recovered from main():** The loader prints several debug-style strings from `main()` that are zero-public-hit on web search (no prior public sample, no GitHub commit, no security blog mentions any of these strings). These are operator-side build/campaign markers:
- `BombAUb23456` — printed during loader initialization
- `DubzAias932` — printed after RC4 decryption
- `Ahuh783bhASbsxAsiopJQAiwhhbchG&*#U897u*#&*473` — 45 characters, the highest-fidelity operator credential recovered (likely a panel-auth or C2-auth token; see Section 8)
- `take it everywhere` — logged from `FUN_00402620` (the dynamic API resolver)
- `AUJsgbSyhusW*(&w3rrkjfgSAGscG)` — logged from the RC4 decryptor
- `Cancel of card!` — context unclear; possibly a payment-flow string copied verbatim from an LLM-generated template

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-79-137-192-3-20260515/loader-operator-strings-main.png" | relative_url }}" alt="Ghidra decompile excerpt of the loader's main function showing the strings BombAUb23456, the 45-character credential Ahuh783bhASbsxAsiopJQAiwhhbchG ampersand asterisk hash U897u asterisk hash ampersand asterisk 473, and Cancel of card being passed to FUN_00404df0 and FUN_00405750.">
  <figcaption><em>Figure 3: Operator-specific strings recovered from `main()` in the customer-built loader. Each string returned zero hits on public web search as of 2026-05-13, anchoring the customer-side attribution (UTA-2026-010). The 45-character credential is the highest-fidelity per-operator pivot — recovery of this exact string in any other infected host or sample would link unambiguously to this operator.</em></figcaption>
</figure>

The combination — operator wraps a top-tier commodity stealer in a homebrew loader, prints debug strings to stdout from `main()`, uses a non-standard 31-byte RC4 key length, and includes English-language phrases like `take it everywhere` that read like LLM completions — anchors the LLM-augmented amateur attribution profile in Section 9.

### 5.2 Stage-2: import surface camouflage

The extracted Stage-2 (`embedded_payload.bin`, 458,752 bytes) presents a deliberately misleading import surface to anyone who runs `dumpbin /imports` or examines the IAT in a disassembler:

| Library | Imports | Pattern |
|---|---|---|
| GDI32.dll | ≥ 100 | Heavy: `BitBlt`, `CreateCompatibleDC`, `CreateDIBSection`, `GetDeviceCaps`, `SelectObject`, `DeleteDC`, `GetObjectA`, etc. |
| USER32.dll | exactly 3 | `GetDC`, `ReleaseDC`, `GetSystemMetrics` only |
| ADVAPI32.dll | registry-READ-only | `RegOpenKeyExA`, `RegQueryValueExA`, `RegCloseKey` only — no `RegSetValue*`, no `RegCreateKey*` |
| KERNEL32.dll | minimal | `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`, `Sleep`, basic file I/O |
| Crypto APIs | **none** | No `BCrypt*`, no `CryptAcquireContext*`, no `Crypt*` of any kind |
| Network APIs | **none** | No `WinINet`, no `WinHTTP`, no `Ws2_32`, no `wininet.dll` import |

This is a **graphics-utility import profile** — visually it reads as a small image-processing tool. There is no indication in the static IAT that this binary will write registry keys (`HKU\<SID>\Software\SibCode\sn`), make encrypted network requests (HTTPS to `79.133.180.168:3394`), or perform credential theft.

**Why this is misleading:** All the missing capabilities (registry-write, crypto, network) are resolved at runtime via dynamic API resolution from the host process's PEB after injection. The Stage-2 walks the host process's `PEB->Ldr->InMemoryOrderModuleList`, hash-matches loaded module names against precomputed name hashes, walks each matched module's export table, and resolves each API by name-hash. This means:
- Static analysis of the Stage-2 in isolation cannot enumerate the true import surface
- IAT-based YARA rules will not match on registry-write or network-API patterns
- The most reliable static identifier for this Stage-2 is the **import-surface combination** itself: GDI32 ≥ 100 + USER32 exactly 3 (those specific three) + ADVAPI32 registry-READ-only + no crypto + no network. This combination is improbable for any legitimate small utility and is highly characteristic of Rhadamanthys Stage-2 samples across multiple customers (vendor-side signature, see Section 10).

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-79-137-192-3-20260515/loader-dynamic-api-resolver.png" | relative_url }}" alt="Ghidra decompile of the loader's dynamic API resolver showing a GetProcAddress call inside a LOCK and UNLOCK pair, with the resolved function pointer cached at piVar1 and a -1 sentinel written on lookup failure.">
  <figcaption><em>Figure 4: The customer-built loader's dynamic API resolver — wraps `GetProcAddress` in a thread-safe `LOCK` / `UNLOCK` pair and caches the resolved function pointer at a known offset. This is the operator's own indirection layer for resolving Windows APIs at runtime; combined with the Stage-2's PEB-walking name-hash resolver shown above, the result is two independent layers of import obfuscation that together defeat static-import-based detection at both the loader and the post-injection Stage-2 layers.</em></figcaption>
</figure>

### 5.3 Stage-2: 3-layer encrypted-blob synthesis (NOVEL FINDING)

This is the most novel technical finding in the Cluster C analysis. Most encrypted-payload malware stores the encrypted blob contiguously in a `.data`, `.rdata`, or custom PE section. Defenders find the encrypted region via entropy analysis (high-entropy contiguous bytes flag the encrypted blob), then carve it for further analysis.

This Rhadamanthys Stage-2 does **not** store its encrypted FS container contiguously. Instead, the FS container is **synthesized at runtime** from three separate sources that each defeat a common detection heuristic:

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-79-137-192-3-20260515/rhadamanthys-stage2-three-layer-synthesis.svg" | relative_url }}" alt="2x2 phase grid infographic of the Stage-2 3-layer encrypted-blob synthesis pipeline. Top-left red card LAYER 1 Byte-emitter functions: 8,800-plus tiny 200 to 300 byte functions in .text, example mov byte ptr [eax+0x42], 0x7C and mov byte ptr [eax+0x43], 0xA1, each writes 16 to 32 ciphertext bytes at sequential heap offsets, encrypted bytes live as scattered imm8 operands across .text, defeats entropy analysis. Top-right red card LAYER 2 Fake-GUID ASCII-hex strings: 7,979 contiguous GUIDs in .rdata, examples {c6127d52-4f9a-afef-d139-...} and {a8b1d340-7f12-92ee-c043-...}, 38-char ASCII hex per GUID, hex-decoded to 16 raw bytes each and concatenated into a second ciphertext region, defeats high-entropy string scans. Bottom-left red card LAYER 3 14-bit Huffman-like packed stream: custom bit-packed table at DAT_0041cb74 onward, 14-bit symbols unpacked via offset-stride arithmetic to produce a third ciphertext region, combined with Layer 1 and 2 outputs into a single contiguous heap buffer ready for decryption, defeats byte-pattern scans. Bottom-right deep red card OUTPUT CBC-XOR decrypt to FS container: FUN_00402790 CBC-XOR cipher decrypts the synthesized buffer using the customer-specific 16-byte IV at .rdata 0x0001c434 with value f6358d79df69c577d9dce6bb77fa4fa7, plaintext begins with magic FS hex 0x4653 plus 5 type-tagged entries (bytecode, config, plugin params, blocklist, TLS pinning data). Footer detection anchors: customer-specific 16-byte IV, fake-GUID-string density in .rdata, byte-emitter function shape.">
  <figcaption><em>Figure 15: The complete 3-layer synthesis pipeline. The three red cards (Layers 1–3) each scatter ciphertext into a different program region using a different camouflage technique; the deep-red OUTPUT card is what the synthesis actually produces — the decrypted FS container that drives the rest of the Stage-2's behavior. The diagram makes clear why static analysis sees nothing: the FS container does not exist on disk, only in the heap after all three synthesis layers and the cipher have run.</em></figcaption>
</figure>

#### Layer 1 — Per-record byte-emitter functions

There are 8,800+ small functions (each 200–300 bytes) at the start of `.text`. Each function does one thing: it writes a small fixed sequence of bytes to a heap location with offset-stride arithmetic. Example shape:

```
push    ebp
mov     ebp, esp
mov     eax, [ebp+heap_base]
mov     byte ptr [eax + 0x42], 0x7C
mov     byte ptr [eax + 0x43], 0xA1
mov     byte ptr [eax + 0x44], 0xE5
... (repeating mov-imm pattern, 16-32 bytes total written) ...
pop     ebp
ret
```

Each emitter writes ~16–32 contiguous ciphertext bytes. There are 8,800+ of them. Together they emit the bulk of the encrypted FS container into a heap buffer.

**Why this defeats entropy detection:** Each emitter function is normal-entropy `.text` code (it's just a sequence of `mov reg, imm; mov reg, imm; ...` instructions). The encrypted bytes themselves are scattered as `imm8` operands across thousands of functions. Running entropy analysis on the binary returns boring `.text`-normal entropy. The high-entropy encrypted region only exists in the heap *after* the emitters have run.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-79-137-192-3-20260515/stage2-layer1-byte-emitter.png" | relative_url }}" alt="Ghidra decompile of an example Layer-1 byte-emitter function showing sequential undefined1 and undefined2 writes at offsets 0x4, 0x5, 0x9, 0xb, 0xc, 0xd, 0xf and so on into a structure pointed to by the this pointer, with hardcoded byte values like 0x66b0, 0x7988, 0xe5, 0xd97fbd16, 0xe6dc, 0xbb, 199 and so on.">
  <figcaption><em>Figure 5: One of the 8,800+ Layer-1 byte-emitter functions inside the Stage-2. Each emitter writes ~16–32 contiguous ciphertext bytes at sequential offsets into the synthesis buffer using nothing more exotic than `mov`-immediate instructions. Running entropy analysis on the binary returns boring `.text`-normal entropy because the ciphertext lives as scattered `imm8` operands across thousands of functions; the high-entropy encrypted region only exists in the heap after these emitters have all executed.</em></figcaption>
</figure>

#### Layer 2 — 7,979 fake-GUID-shaped ASCII-hex strings

A `.rdata` region contains 7,979 contiguous ASCII strings of the form `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` — the standard Microsoft GUID literal format. Each string is 38 characters (36 hex digits + 2 brace characters).

Static analysis tools and human analysts both interpret these as a list of GUIDs (perhaps COM CLSIDs, file format identifiers, or some configuration identifier list). They are not GUIDs. The hex content of each "GUID" is **a block of ciphertext bytes encoded as ASCII hex**. The Stage-2 walks the array, strips the braces and dashes, hex-decodes each string into 16 raw bytes, and concatenates the result — producing another large region of ciphertext that contributes to the FS container.

**Why this defeats string-based detection:** A YARA rule that looks for "blocks of high-entropy bytes in `.rdata`" will not trip because the bytes are valid ASCII hex (low byte-entropy, high character-class regularity). A defender skimming strings sees 7,979 GUIDs and skips past them. The encrypted content is camouflaged inside a data shape (GUID arrays) that is normal in legitimate Windows software.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-79-137-192-3-20260515/stage2-layer2-fake-guid-rdata.png" | relative_url }}" alt="Ghidra .rdata view at address 0x0041cb74 showing a single brace byte 0x7B followed at address 0x0041cb75 by an ASCII-hex string starting with c6127d52-4f9a-afef-d139-283878 — a fake GUID literal pointing to xref FUN_00402690.">
  <figcaption><em>Figure 6: One of 7,979 fake-GUID-shaped ASCII-hex strings in the Stage-2's `.rdata` section. Each 38-character pseudo-GUID looks like a standard Microsoft CLSID or COM identifier — the kind of constant a defender skimming strings would skip past — but the hex content is actually a 16-byte block of ciphertext encoded as ASCII. The byte-emitters from Layer 1 reach into these strings using offset-stride arithmetic to assemble the encrypted FS container in the heap.</em></figcaption>
</figure>

#### Layer 3 — 14-bit Huffman-like bit-packed stream

A third region contributes the remaining ciphertext bytes via a custom 14-bit-symbol bit-packed encoding (similar to a non-Huffman fixed-width packing). The Stage-2 includes a small unpacker that reads the bit stream 14 bits at a time and emits decoded bytes into the heap buffer.

**Why this defeats simple carving:** Even an analyst who recognizes Layer 1 and Layer 2 will miss Layer 3 unless they trace the third synthesis path. The full encrypted FS container is the concatenation of all three layers' outputs into a single heap buffer in a specific order.

#### After synthesis

Once the three layers have run, the heap contains the encrypted FS container (an "FS"-magic-prefixed binary blob). The Stage-2 then:
1. Initializes the **CBC-XOR cipher** with the 16-byte IV `f6358d79df69c577d9dce6bb77fa4fa7` (recovered from `.rdata` at file offset `0x0001c434`)
2. Decrypts the FS container using a custom CBC-XOR implementation (see Section 5.4)
3. Parses the decrypted content as an "FS" container with 5 type-tagged entries

**Why this matters:** The 3-layer synthesis is the distinguishing tradecraft of this Rhadamanthys Stage-2 build. It defeats:
- Entropy-based encrypted-region carving (Layer 1)
- String-based pattern matching (Layer 2)
- Simple bit-stream identification (Layer 3)

A novel detection approach is to instrument the byte-emitter shape from Layer 1 (small 200–300-byte functions with sequential `mov-imm` writes + offset-stride arithmetic) — see Section 10 detection coverage and the YARA rule `Rhadamanthys_Stage2_Byte_Emitter_Shape` in the separate detection file.

### 5.4 Stage-2: CBC-XOR cipher with per-customer IV

The cipher used to decrypt the synthesized FS container is a custom CBC-XOR construction at `FUN_00402790`:
- **Block size:** 16 bytes
- **IV:** 16 bytes, hardcoded at `.rdata 0x0041c434`: `f6358d79df69c577d9dce6bb77fa4fa7`
- **Inner loop:** 4-iteration unrolled XOR per block, with the **ciphertext-becoming-key** structure (a CBC-XOR variant where the previous ciphertext block is XOR'd into the next plaintext block before XOR with the IV-derived key)

This is not AES-CBC, not standard CBC-XOR, and not a known reference implementation. The 4-iteration unrolling and the specific block-key derivation pattern are characteristic of Rhadamanthys vendor cipher construction across multiple sample variants (per Outpost24 analysis of v0.7.x VM-protected routines).

**Per-customer IV question:** The 16-byte IV `f6358d79df69c577d9dce6bb77fa4fa7` is **assumed** to be per-customer specific based on the indirect inference that the Stage-2 build process likely parameterizes the cipher per customer (consistent with the per-customer C2 separation observed in sibling samples — different customers have different C2 IPs). Direct cross-customer validation requires extracting the IV from sibling Stage-2 samples (`bc9fe5e9...`, `e827d13c...`, `457aecd8...`) and comparing. This validation is **deferred** because VirusTotal sandbox emulation systematically fails across all sibling samples (zero `contacted_urls` / zero `embedded_urls` cohort-wide), preventing automated extraction. See Section 12 (Coverage Gaps) for the deferred work.

> **Validation status note:** The cipher analysis in this section is **static-only** (recovered from disassembly of `FUN_00402790` and offset `0x0041c434`). A ciphertext-plaintext round-trip has not been performed to confirm the implementation behaves as modeled under all input lengths. Per project memory (`feedback_static_cipher_dynamic_validation`): cipher claims should not be elevated to DEFINITE until dynamic ciphertext-plaintext validation confirms the static model. The per-customer-IV claim remains HIGH confidence pending cross-sample validation.

If the IV turns out to be vendor-shared rather than per-customer, the customer-specificity claim on this primitive is downgraded — the IV would then be a vendor-side family marker (still useful for detection, but less specific). The detection content in the separate file flags the IV as `(customer-specific — pending cross-validation)` and the Sigma/YARA rules treat it as one of multiple possible cipher fingerprints.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-79-137-192-3-20260515/stage2-cbc-xor-cipher.png" | relative_url }}" alt="Ghidra decompile of FUN_00402790 showing the inner CBC-XOR decryption loop with a do-while structure, four uVar1 through uVar4 unrolled register reads from the in_EAX key material, and XOR operations against pbVar5 ciphertext bytes feeding into pbVar6 plaintext output across a 16-byte block stride.">
  <figcaption><em>Figure 7: The Stage-2's custom CBC-XOR cipher loop at `FUN_00402790`. Each iteration processes 16 bytes (note the unrolled four-uint reads `uVar1..uVar4` from `in_EAX`, the XOR-chain across `pbVar5..pbVar7`, and the `0x10` stride at loop bottom). The construction is not AES, not standard CBC, and not any reference implementation — it is the Rhadamanthys vendor's custom 4-iteration unrolled XOR with ciphertext-becoming-key chaining. The key material in `in_EAX` carries the per-customer 16-byte IV `f6358d79df69c577d9dce6bb77fa4fa7`.</em></figcaption>
</figure>

### 5.5 Stage-2: "FS" container with 5 type-tagged entries

After decryption with the CBC-XOR cipher, the synthesized FS container is parsed as a fixed-format binary structure:
- **Magic:** ASCII `FS` (`0x4653` little-endian) at offset 0
- **Entry count:** 5 entries
- **Per-entry header:** 4-byte type tag + 4-byte length + entry payload

Each entry's type tag is an opaque 4-byte value. The five entries observed in this Stage-2:

| Entry # | Type tag | Payload purpose |
|---|---|---|
| 0 | `0x...`  | Q3VM-derivative bytecode (the embedded VM bytecode the Stage-2 interprets — see Section 5.6) |
| 1 | `0x...`  | Configuration: panel ID `e6d92c6b5b2a03bee7fbab40`, C2 IP/port `79.133.180.168:3394`, build timestamp |
| 2 | `0x...`  | Plugin module loading parameters (XS1/XS2 format module list and load order) |
| 3 | `0x895bade5` | **Anti-analysis blocklist** — list of analyzer process names that the Stage-2 checks via `NtQuerySystemInformation` (ProcessHacker, Procmon, x64dbg, WinDbg, IDA, Ghidra, common sandbox analyzer names) |
| 4 | `0x...`  | TLS certificate pinning data and JARM fingerprint material |

Entry 3's anti-analysis blocklist was extracted to `entry3_decoded_blocklist.bin` / `.txt` during static analysis and decoded successfully — the blocklist is a plain UTF-16LE string list with one analyzer process name per entry.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-79-137-192-3-20260515/stage2-fs-container-assembly.png" | relative_url }}" alt="Ghidra decompile of FUN_00402890 showing the Roland GS Sound Set Microsoft 1996 Roland Corporation decoy string being staged as a 14-iteration uint copy, four uStack underscore values 0x798d35f6, 0x77c569df, 0xbbe6dcd9, 0xa74ffa77 reconstructing the 16-byte CBC-XOR IV, a call to the cipher routine FUN_00402790, and a final 0x5346 magic check confirming an FS container.">
  <figcaption><em>Figure 8: The Stage-2 assembly + decryption + parse pipeline at `FUN_00402890`. The Roland decoy string is staged as a 14-byte misdirection ahead of the real cipher input. The four `uStack_` values immediately below (`0x798d35f6`, `0x77c569df`, `0xbbe6dcd9`, `0xa74ffa77`) reconstruct the customer-specific 16-byte CBC-XOR IV. After `FUN_00402790` decrypts the buffer, the `lpMem_00 == 0x5346` literal check at the bottom (ASCII `FS`) confirms the resulting plaintext is the expected `FS` container.</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-79-137-192-3-20260515/stage2-roland-decoy-string.png" | relative_url }}" alt="Ghidra decompile of FUN_00402d00 showing a single OutputDebugStringA call with the literal string ERROR All other uses require a separate written license from Roland followed by a newline, then a call to FUN_00402a70.">
  <figcaption><em>Figure 9: A second Roland-themed decoy string surfaced via `OutputDebugStringA`. The Stage-2 sprinkles Roland Corporation copyright text (the original 1996 Roland GS Sound Set license boilerplate) throughout its codebase — both as cipher-input misdirection (Figure above) and as standalone debug-string decoys here. The intent is to push analysts and signature engines toward classifying the binary as a benign audio component.</em></figcaption>
</figure>

### 5.6 Stage-2: Q3VM-derivative bytecode VM (NOVEL FINDING)

> **Analyst note:** This subsection covers the embedded virtual machine that the Rhadamanthys Stage-2 uses to interpret its anti-analysis routines. The VM is a derivative of the open-source Q3VM (Quake 3 virtual machine) with operator modifications. Defenders do not need to understand the VM internals to detect Rhadamanthys — but the magic constant and opcode permutation are useful detection primitives.

Entry 0 of the FS container is bytecode for an **embedded VM** that interprets the Stage-2's anti-analysis routines (the analyzer-process check, the timing checks, parts of the credential-theft logic). The bytecode is recognizable as a derivative of **Q3VM** (the Quake 3 virtual machine, a small open-source VM by jnz/q3vm widely used as a teaching reference for VM-based code obfuscation).

**Magic constant:** The bytecode header magic is `0x14744214`. The stock Q3VM magic constant is `0x12721444` (defined as `VM_MAGIC` in jnz/q3vm `vm.h`, line 34 in the public repository). The Stage-2's value is one byte different in two positions — `0x14744214` versus `0x12721444`:
- Position 1: `0x14` vs `0x12`
- Position 4: `0x14` vs `0x44`

The other positions are identical or near-identical. The pattern is consistent with an operator-modified Q3VM where the magic was deliberately changed to defeat signature detection that targets the stock magic. This is a common obfuscation technique — keep the VM logic identical, change the magic and a few opcodes to defeat off-the-shelf disassembler signature matching.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-79-137-192-3-20260515/stage2-dispatch-chain-magic.png" | relative_url }}" alt="Ghidra decompile of LAB_00402380 showing a for-loop iterating through linked list nodes with a magic comparison against 0x8787f3a, calling FUN_00403a1d on a match, then writing 300 to the iVar2 + 0xc field and jumping to LAB_004023d0.">
  <figcaption><em>Figure 10: The Stage-2 dispatch chain at `LAB_00402380`. The operator-modified Q3VM derivative magic `0x8787f3a` is checked here as part of the per-iteration dispatch loop, gating control transfer to the subsequent VM-stage handler `FUN_00403a1d`. Searching binaries for this magic byte sequence is a high-fidelity vendor-side Rhadamanthys detection primitive — no stock Q3VM-using software carries this constant.</em></figcaption>
</figure>

**Opcode permutation:** The bytecode opcodes are also permuted from stock Q3VM. Static analysis of the bytecode region (`entry0_bytecode_disasm_v4.txt`) showed instruction patterns consistent with Q3VM but with several opcodes remapped. The full permutation table is documented in the supporting analysis notes; a Q3VM-aware disassembler can be patched with the permuted opcode table to read the bytecode correctly.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-79-137-192-3-20260515/stage2-q3vm-invocation-wrapper.png" | relative_url }}" alt="Ghidra decompile of FUN_00403ad5 showing a 13-element local_38 register-file array, a do-while loop copying parameters from puVar1 into local_38 indices 1 through 12, an increment of the field at param_1 + 0x24, a call to FUN_00403438 dispatching the VM with the prepared register file, and a -NAN return on failure.">
  <figcaption><em>Figure 11: The Stage-2's VM invocation wrapper at `FUN_00403ad5`. This is how the host code feeds the embedded Q3VM-derivative dispatcher (`FUN_00403438`): it builds a 13-slot register file (`local_38[13]`), copies up to 12 caller arguments into it, increments the per-VM-invocation counter at offset `0x24`, and then calls into the dispatcher. The 13-argument calling convention is one of the operator's modifications to stock Q3VM (which uses a different register-file layout) and is part of why off-the-shelf q3vm-disasm tooling fails to read this bytecode without patching.</em></figcaption>
</figure>

**Why this matters for detection:**
- The magic `0x14744214` is a high-fidelity Rhadamanthys family marker. Searching binaries for `14 74 42 14` little-endian is a fast vendor-side detection primitive (no stock Q3VM-using software has this magic).
- The opcode permutation is a vendor-side artifact (all Rhadamanthys customers receive the same Stage-2 bytecode VM, so the permutation is the same across customers) and identifies the entire Rhadamanthys family.

**Q3VM lineage caveat:** The Q3VM-derivative claim is HIGH confidence based on the magic-constant similarity, opcode-pattern similarity, and consistency with the Outpost24 and amnesia.sh analysis of Rhadamanthys VM modules. Direct binary comparison with the stock Q3VM repo (jnz/q3vm) and Outpost24's IDA Pro QVM modules is deferred work that would elevate this to DEFINITE — see Section 12 (Coverage Gaps).

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-79-137-192-3-20260515/stage2-vm-api-resolve.png" | relative_url }}" alt="Ghidra decompile of FUN_004020e0 showing a function that takes a single int pointer parameter, dereferences it for an iVar2 base, calls FUN_00403ad5 with the LAB_004017b0 lookup-on-demand handler when iVar3 is zero, then writes a 2000 timeout to an offset 0xc field, caches the resolved pointer at offset 0x10, and stores the API entry into the register file at offsets 0x14 and 0x54.">
  <figcaption><em>Figure 12: The Stage-2's VM-side API resolution wrapper at `FUN_004020e0`. When the embedded Q3VM bytecode requests a Windows API for the first time, this routine dispatches into the VM (`FUN_00403ad5`) with the LAB_004017b0 lookup handler, caches the resolved function pointer at offset `0x10` in the register file, and routes future calls to the cached entry at offset `0x14`. This per-API lazy resolution is what allows the Stage-2's static IAT (the import-surface camouflage in §5.2) to omit registry, crypto, and network APIs that the bytecode actually calls at runtime.</em></figcaption>
</figure>

### 5.7 Cluster A and B static analysis (condensed)

**Cluster A — BellaMain:** Static analysis of `BellaMain.zip` (SHA256 `f791fae41cdd3f141221d1783ed4779c839de7fc834ff4fc80a5d7f74b11ff88`) recovered the full PHP source of the panel and all 7 phishing kits. The developer pseudonym `Wadanz` appears as a code-level suffix on session-encryption helpers (`sifreleWadanz`, `sifrecozWadanz`) in `database/fonk.php`. The shared MySQL database name `jakartaxdw` is hardcoded across the panel and all 7 kits. The Telegram bot token `6797512084:AAGbJVoC0zcKWYPbFG8oc_bACPn6gUEye_E` is hardcoded in all 6 `girislog.php` files. The admin-directory path `V5VgjLU0jsDe` is the obfuscated panel-administration URL.

**Cluster B — Inkognito:** No PE samples were recovered for Cluster B (the operation is web-application + VPN service, not malware). Static analysis was limited to inspection of the production HTML, JavaScript, and HTTP response patterns. Operator-controlled accounts identified: Google Search Console verifications `_Lq_FX-CDt3OmZqq5PNFfmQTZtLSHTNsVkViLTzpTwk` (on `inkconnect.ru`) and `xskfj4k4tX_-enfPvu9WrUiWauHFlbuVmyV7thcjwds` (on `inklens.ru`); Yandex Webmaster verification `98466329` (in `inklens.ru` HTML meta tags). The `kittenx-404` decommission tombstone HTTP response (Server header `kittenx`, content-length 148) appears on multiple retired Inkognito-controlled domains and is the strongest cross-domain operator fingerprint.

---

## 6. Dynamic Analysis

> **Analyst note:** This section covers the runtime behavior observed during sandbox execution and reconstruction from static analysis. The Cluster C loader's execution path is the primary focus — from the lure file landing on disk through the EAX-redirect process hollowing into `InstallUtil.exe` to the first C2 beacon. Clusters A and B are not covered in this section because their operational model is web-application based and does not have a meaningful "dynamic execution" surface to instrument.

### 6.1 Cluster C: kill chain overview

> **Analyst note:** This section walks through what the malware does on an infected machine, in order, from the moment the user opens it to the first communication with the attacker's server. Each step shown in the table is a separate technique that defenders can detect or block — the kill chain is what enables decisions about where in the sequence to focus monitoring.

The complete Cluster C kill chain, from initial execution to C2 beacon, follows this sequence:

| Stage | Time | Action |
|---|---|---|
| 1. Initial execution | T+0 | User executes `staticlittlesource.exe` (delivered via cracked-software / game-cheat lure based on file naming pattern) |
| 2. Anti-analysis sleep | T+0 → T+14s | Loader executes ~14 seconds of cumulative `Sleep` calls with denormal-sentinel FPU verification |
| 3. RC4 decryption | T+14s | Loader decrypts the embedded Stage-2 PE from `.data` using the 31-byte RC4 key |
| 4. Process spawn | T+14s | Loader calls `CreateProcessA("C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\InstallUtil.exe", CREATE_SUSPENDED)` |
| 5. Image unmap | T+14s | Loader calls `NtUnmapViewOfSection` against the `InstallUtil.exe` image base in the suspended process |
| 6. W^X memory write | T+14s | Loader allocates `PAGE_READWRITE` memory in the suspended process, writes the decrypted Stage-2 PE, then re-protects to `PAGE_EXECUTE_READ` via `VirtualProtectEx` |
| 7. EAX-redirect | T+14s | Loader calls `GetThreadContext`, modifies the `Eax` field to the Stage-2 entry point, calls `SetThreadContext` (modifying ONLY `Eax`, not `Eip`) |
| 8. Resume | T+14s | Loader calls `ResumeThread`; `kernel32!BaseThreadInitThunk` jumps to the address in `EAX`, transferring control to the Stage-2 |
| 9. Loader exit | T+14s | Loader exits cleanly |
| 10. Stage-2 PEB walk | T+14s+ | Stage-2 (now running inside `InstallUtil.exe`) walks the PEB for dynamic API resolution |
| 11. FS synthesis | T+14s+ | Stage-2 runs the 8,800+ byte-emitter functions, hex-decodes the 7,979 fake-GUIDs, unpacks the 14-bit stream — synthesizes the encrypted FS container |
| 12. CBC-XOR decrypt | T+14s+ | Stage-2 decrypts the FS container with the per-customer IV; parses 5 type-tagged entries |
| 13. Anti-analysis check | T+14s+ | Stage-2 walks `NtQuerySystemInformation` process list, compares against entry-3 blocklist; exits if any analyzer process is running |
| 14. Registry write | T+14s+ | Stage-2 writes Unix timestamp to `HKU\<SID>\Software\SibCode\sn` (pre-v0.9.1 family marker) |
| 15. C2 beacon | T+14s+ | Stage-2 issues HTTPS request to `https://79.133.180.168:3394/e6d92c6b5b2a03bee7fbab40/<random>.<ext>` with TLS pinning to the operator's Samsung-impersonation certificate |
| 16. Plugin loading | T+14s+ | Stage-2 receives XS1/XS2 plugin modules from C2 response, loads them in-memory |
| 17. Credential theft | ongoing | Plugins enumerate browser stores, wallet directories, password manager files, etc.; encrypted exfil over the established C2 channel |

The 17-stage kill chain is densely concentrated: stages 1–9 (loader-side) execute in approximately 14 seconds of which most is the anti-analysis sleep; stages 10–17 (Stage-2 inside the hollowed `InstallUtil.exe`) follow immediately and continue indefinitely. The first 17 seconds of execution are the highest-value detection window — see Section 10 for behavioral detection content keyed on this timeline.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-79-137-192-3-20260515/rhadamanthys-cluster-c-kill-chain.svg" | relative_url }}" alt="Long vertical 10-stage kill chain infographic for Cluster C from sample launch to credential exfil. Stage 1 (orange T+0) Initial execution: user runs staticlittlesource.exe 1.39 MB MSVC C++ binary VS2019, delivery vector cracked-software or game-cheat lure. Stage 2 (orange T+0 to T+14s) 14-second anti-analysis gauntlet: cumulative Sleep calls totaling 14 seconds interleaved with floating-point denormal-sentinel checks, sleep-skipping fails because skipped sleeps don't accumulate FPU state. Stage 3 (red T+14s) RC4 decrypt embedded Stage-2 PE: extracts Stage-2 from .data and RC4-decrypts using the 31-byte key e0802540...12715b, result is a fully-formed PE with .frontb section. Stage 4 (red T+14s) Spawn InstallUtil.exe SUSPENDED: CreateProcessA on the .NET Framework v4.0.30319 InstallUtil.exe with CREATE_SUSPENDED, undocumented LOLBin choice in any Rhadamanthys public reporting. Stage 5 (red T+14s) Unmap + W^X write Stage-2 PE: NtUnmapViewOfSection unmaps original image, VirtualAllocEx PAGE_READWRITE then WriteProcessMemory then VirtualProtectEx PAGE_EXECUTE_READ, no RWX page is ever allocated. Stage 6 (red T+14s) EAX-redirect entry-point hijack plus ResumeThread: GetThreadContext, modify ctx.Eax to stage2_entry, SetThreadContext, ResumeThread, only Eax is patched never Eip or Rip. Stage 7 (red T+14s+) Stage-2 setup inside InstallUtil.exe: PEB walk to resolve APIs by hash, run 8800-plus byte-emitter functions, hex-decode 7979 fake-GUID strings, unpack 14-bit packed stream to synthesize FS container, CBC-XOR decrypt with per-customer IV. Stage 8 (yellow T+14s+) Analyzer-process check plus SibCode persistence marker: NtQuerySystemInformation enumerates processes against blocklist, write Unix timestamp to HKU SID Software SibCode sn registry value. Stage 9 (deep red T+14s+) First C2 beacon plus receive plugin modules: HTTPS to 79.133.180.168:3394 with customer panel ID e6d92c6b5b2a03bee7fbab40 in URL path, TLS pins to Samsung-impersonation cert, C2 returns XS1/XS2 plugins loaded in-memory, first beacon ~17s after sample launch. Stage 10 (deep red ongoing) Credential / wallet / MFA theft plus encrypted exfil: plugin modules enumerate browser stores, crypto wallets, password managers, MFA tokens, VPN configs, email clients, encrypted exfil over established C2 channel.">
  <figcaption><em>Figure 16: The full 10-grouping kill chain (condensing the 17 stages from the table above). The diagram makes the high-value detection window obvious: stages 1–6 unfold in the first 14 seconds, stages 7–8 in the next ~3 seconds, and the first C2 beacon (stage 9) occurs at ~T+17s. After stage 9 defenders are reacting rather than preventing — the orange-and-red phases are where prevention is feasible.</em></figcaption>
</figure>

### 6.2 EAX-redirect process hollowing — runtime mechanics

> **Analyst note:** This subsection re-explains the EAX-redirect hollowing variant from a runtime perspective (Section 4.2.2 covered it from the static analysis perspective). Understanding this technique is important for defenders because most EDR detection rules for process hollowing key on the classic `SetThreadContext`-with-modified-`Eip` pattern, which this variant deliberately avoids.

The classic process hollowing detection rule is:
```
ALERT IF a process spawns a child with CREATE_SUSPENDED
  AND the parent calls NtUnmapViewOfSection on the child
  AND the parent allocates RWX memory in the child
  AND the parent calls SetThreadContext with a modified Eip pointing into the RWX region
  AND the parent calls ResumeThread
```

This rule fires on textbook hollowing (the SetThreadContext+EIP-modified+RWX-memory triad) but **misses the EAX-redirect variant** because:
1. **No RWX allocation** — the loader uses W^X transitions (allocate `PAGE_READWRITE`, write, re-protect to `PAGE_EXECUTE_READ`). Detection rules that key on `VirtualAllocEx` with `PAGE_EXECUTE_READWRITE` will not fire.
2. **Eip is unmodified** — the loader's `SetThreadContext` call modifies only the `Eax` field of the `CONTEXT` structure. Rules that compare `Eip` before-vs-after `SetThreadContext` will see no change.
3. **The redirect happens via Windows process loader convention** — `kernel32!BaseThreadInitThunk` is the standard initial thread entry point; it reads `EAX` as the convention for "where to jump first." By patching `EAX`, the loader exploits a normal Windows process loader behavior, not an obvious overwrite.

**Effective detection:** Defenders should layer behavioral rules that look at the **outcome** of hollowing rather than the API sequence:
- `InstallUtil.exe` running with **no `/u` flag and no assembly path argument** (legitimate `InstallUtil.exe` invocations always take a `/u` flag and an assembly path; bare `InstallUtil.exe` with no arguments is anomalous)
- `InstallUtil.exe` initiating outbound network connections to non-Microsoft endpoints
- `InstallUtil.exe` parent process not being `services.exe`, `wininit.exe`, or a deployment-tool process (`msbuild.exe`, `vstest.console.exe`)
- A non-system parent process spawning `InstallUtil.exe` with `CREATE_SUSPENDED` (rare in legitimate workflows)

The detection file (separate Sigma rules) implements all four of these patterns. See Section 10 for the detection coverage summary.

### 6.3 14-second anti-analysis sleep — runtime mechanics

> **Analyst note:** The loader stalls for 14 seconds before doing anything malicious. Hidden inside that wait are floating-point math checks that fail when a sandbox is fast-forwarding the timers — a common sandbox shortcut that this loader specifically detects and exits to defeat. The 14-second number is calibrated to outlast most automated sandbox budgets.

The loader's 14-second pre-malicious-activity sleep is implemented as a sequence of `Sleep(N)` calls interleaved with floating-point checks. The sequence is roughly:

1. `Sleep(2000)` — 2-second sleep
2. FPU computation that produces a denormal sentinel value
3. Comparison against hardcoded reference; if mismatch, exit silently (the sandbox-emulated FPU produced a different denormal)
4. `Sleep(3000)` — 3-second sleep
5. Second FPU check
6. `Sleep(4000)` — 4-second sleep
7. Third FPU check
8. `Sleep(5000)` — 5-second sleep
9. Final check; proceed to RC4 decryption if all checks passed

Total cumulative sleep ≈ 14 seconds. The denormal-sentinel check is calibrated to detect FPU emulators that round denormals to zero (a common FTZ — "flush to zero" — sandbox optimization).

**Why this defeats common bypasses:**
- Sleep-skipping replaces `Sleep(N)` with `Sleep(0)` — the sandbox advances time but the FPU state doesn't accumulate the small denormal-producing computations correctly across the skipped sleep windows
- Time-warping (advancing the system clock) doesn't help because the check is on FPU state, not on `GetTickCount`/`QueryPerformanceCounter`
- Some commercial sandboxes implement denormal-correct FPU emulation, but many do not

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-79-137-192-3-20260515/stage2-denormal-sentinel-fpu-check.png" | relative_url }}" alt="Ghidra decompile excerpt showing local_430[0] being assigned the floating-point literal 6.84941e-41, a sub-normal IEEE-754 denormal value, immediately preceding a do-while loop that walks param_2 in 0xd iterations.">
  <figcaption><em>Figure 13: The denormal-sentinel FPU check inside the Stage-2. The literal `6.84941e-41` assigned to `local_430[0]` is a sub-normal IEEE-754 value — emulated FPUs in commodity sandboxes (and any sandbox that uses the FTZ "flush to zero" optimization) compute denormals slightly differently than native silicon. A mismatch between the runtime result and the hardcoded reference indicates sandbox emulation, and the loader exits silently before any malicious activity. This is the precise primitive that the §4.2.3 capability discussion summarizes — defenders unfamiliar with FPU sandbox-detection should note that classic sleep-skipping bypasses do not advance FPU state correctly and trip this check.</em></figcaption>
</figure>

### 6.4 Stage-2 registry write to SibCode\sn

The Stage-2's registry write to `HKU\<SID>\Software\SibCode\sn` was confirmed via CAPE Procmon trace. The value written is a Unix timestamp (the build's epoch time, hardcoded in the Stage-2). This is a per-build value — different Rhadamanthys builds write different timestamps. The `SID` is the current user's security identifier.

**Operational behavior:**
- First-run write: the Stage-2 checks if the key exists; if not, writes the Unix timestamp value and proceeds with full credential theft
- Subsequent runs: the Stage-2 reads the existing value and may use it for run-counting or "first-execution-only" capability gating

**Detection value (re-stated):** No known benign software writes to `Software\SibCode\sn`. SibCode is a defunct VCL component vendor (the developer Rhadamanthys's branding is borrowed from). Any registry-set telemetry on this key path is presumptive Rhadamanthys infection. See the separate detection file for the Sigma rule `Rhadamanthys_SibCode_sn_Registry_Write`.

### 6.5 C2 beacon — first request structure

> **Analyst note:** This section breaks down the very first message the malware sends back to the attacker's server after a successful infection. The structure of that message — the URL path, the random-looking filename, the non-standard port number — is what defenders can use to write network-detection rules that catch this specific attacker's deployments without firing on legitimate web traffic.

The Stage-2's first C2 beacon is an HTTPS request to:
```
https://79.133.180.168:3394/e6d92c6b5b2a03bee7fbab40/<8-char>.<5-char>
```

**URL structure:**
- Host + port: `79.133.180.168:3394` (Hostkey NL AS57043)
- Path component 1: `e6d92c6b5b2a03bee7fbab40` — 24-hex-character panel ID (assumed customer-specific; see Section 12 for the indirect-evidence caveat)
- Path component 2: 8-character-base + 5-character-extension (random per request, e.g., `rnvoxu7t.nnre7`, `icng5os4.lwcci`)

**TLS:**
- Cert chain: operator-issued Samsung DigiCert 51-SAN brand-impersonation certificate (SHA-256 `05209e47fd8f96d2f39a79828677288eccca3cef245f128711cc2d53d71f42f7`) for the current period
- JARM: `2ad2ad0002ad2ad00042d42d00000007e6e35b6c9fce6eec13762f8506fe09` (current Samsung-cert period)
- TLS pinning: the Stage-2 validates the cert against pinned material in FS container entry 4

**Cert rotation history (per VirusTotal MCP):**
- 2023 → early 2026: self-signed certificates
- February 2026: Apple-impersonation cert
- March 2026 → present: Samsung-impersonation cert (51-SAN DigiCert)

**Why the rotation matters for detection:** JARM is not stable across cert rotations. A JARM-only detection rule that pinned to the early-2026 Apple-impersonation period would not match the current Samsung period. Detection content should hunt for the **brand-impersonation cert pattern** (Samsung 51-SAN DigiCert served from a non-Samsung IP) rather than the specific JARM hash.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-79-137-192-3-20260515/c2-79-133-180-168-vt-communicating-files.png" | relative_url }}" alt="VirusTotal Communicating Files panel for IP 79.133.180.168 showing six Win32 EXE samples that contacted this C2: a Bazaar HEUR-Trojan-Dropper sample submitted 2026-04-23 with 57 of 72 detections, keyanalysis.exe submitted 2024-02-26 with 46 of 72, staticlittlesource.exe submitted 2025-08-13 with 60 of 72, eDqzdMMvBPnL submitted 2025-08-10 with 61 of 72, 4k2pchh9ur.exe submitted 2025-02-03 with 57 of 70, and streetprojections.exe submitted 2023-07-14 with 37 of 70.">
  <figcaption><em>Figure 14: VirusTotal `Communicating Files` view for the Cluster C C2 endpoint `79.133.180.168`. Six sibling Rhadamanthys customer builds were observed reaching this single C2 across submissions from July 2023 through April 2026 — direct external evidence that the C2 has been operating continuously for ~34 months and that this customer's loader (`staticlittlesource.exe`, third row) is one of multiple sibling deployments tied to the same operator infrastructure. The wide submission-date spread also corroborates the §5.4 indirect signal that panel ID `e6d92c6b5b2a03bee7fbab40` is a per-customer stable identifier (not per-build) and that the customer's operation survived Operation Endgame Phase 3 in November 2025.</em></figcaption>
</figure>

### 6.6 Cluster A and B dynamic notes (condensed)

**Cluster A — BellaMain:** No malware execution surface. The dynamic behavior of interest is the HTTP traffic patterns to the kit URIs (`*/girislog.php`, `*/kartlaodeme.php`, `*/tgdekont.php`, `*/cekimbot.php`) and the Telegram bot exfil traffic to `api.telegram.org` carrying bot ID `6797512084` (revoked but pivot-valuable). Web proxy and Suricata detection content covers these patterns — see the separate detection file.

**Cluster B — Inkognito:** No malware execution surface. The dynamic indicators are HTTP requests carrying the `X-Admin-Token` custom auth header on `api.inkconnect.ru`, DNS queries for the brand-impersonation subdomain patterns under `*.inklens.ru` / `*.inklens.co.uk`, and HTTP responses with the `Server: kittenx` decommission tombstone. Detection content covers all three — see the separate detection file.

---

## 7. MITRE ATT&CK Mapping

> **Confidence note:** all rows below are HIGH confidence unless explicitly marked `(MODERATE)`. The Confidence Summary in Section 11 organizes findings by confidence level for the higher-level view.

The mapping below covers all three clusters. Cluster C (Rhadamanthys MaaS-customer loader + Stage-2) is the primary contributor; Clusters A (BellaMain) and B (Inkognito) contribute the resource-development, initial-access, and exfiltration techniques specific to phishing-centric operations.

| Tactic / Technique | Name | Evidence |
|---|---|---|
| Resource Development / T1583.003 | Virtual Private Server | Aeza VPS hosting on AS216246 / AS210644 (Russia / Italy); Hostkey NL AS57043 for Cluster C C2 |
| Resource Development / T1583.006 | Web Services | Cluster B Cloudflare-fronted `cryptone.bot`; Cluster A panel staging on Aeza |
| Resource Development / T1587.001 | Develop Capabilities — Malware | Cluster C customer-built loader `staticlittlesource.exe`; Cluster A custom BellaMain PhaaS panel |
| Resource Development / T1588.001 | Obtain Capabilities — Malware | Cluster C purchased Rhadamanthys MaaS Stage-2 from vendor |
| Resource Development / T1608.005 | Stage Capabilities — Link Target | Cluster A 7 marketplace phishing kits hosted on staging IP `79.137.192.3` |
| Initial Access / T1566.002 | Spearphishing Link | Cluster A Turkish marketplace credential-harvest pages; Cluster B INK Lens brand-impersonation subdomains |
| Initial Access / T1189 | Drive-by Compromise | Cluster C `staticlittlesource.exe` delivered via cracked-software / game-cheat lure (inferred from filename pattern + LLM-amateur tradecraft profile) (MODERATE) |
| Execution / T1204.002 | Malicious File | User executes `staticlittlesource.exe` |
| Execution / T1218.008 | InstallUtil | Cluster C loader hollows `C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe` for Stage-2 execution |
| Persistence / T1112 | Modify Registry | Stage-2 writes Unix timestamp to `HKU\<SID>\Software\SibCode\sn` (pre-v0.9.1 family marker) |
| Privilege Escalation / T1055.012 | Process Hollowing | EAX-redirect variant: `CreateProcess(InstallUtil, SUSPENDED)` → `NtUnmapViewOfSection` → W^X memory write (NOT RWX) → `SetThreadContext(Eax=stage2_entry)` → `ResumeThread`; **`Eax`-only modification, NOT `Eip`** |
| Defense Evasion / T1027 | Obfuscated Files or Information | Stage-2 3-layer encrypted-blob synthesis (byte-emitters + fake-GUIDs + bit-packed stream) |
| Defense Evasion / T1027.002 | Software Packing | Loader's RC4 wrapper around the Stage-2 PE |
| Defense Evasion / T1027.007 | Dynamic API Resolution | Stage-2 PEB walk + module-name-hash matching + export-name-hash matching for runtime API resolution |
| Defense Evasion / T1027.011 | Fileless Storage | Stage-2 lives entirely in injected memory inside `InstallUtil.exe` — no on-disk Stage-2 PE persists |
| Defense Evasion / T1027.013 | Encrypted/Encoded File | Loader RC4-encrypted Stage-2 in `.data`; Stage-2 CBC-XOR-encrypted FS container |
| Defense Evasion / T1140 | Deobfuscate/Decode Files or Information | Loader RC4 decrypt; Stage-2 CBC-XOR decrypt + 14-bit bit-packed unpack + ASCII-hex GUID decode |
| Defense Evasion / T1497 | Virtualization/Sandbox Evasion | Loader denormal-sentinel FPU verification; Stage-2 Q3VM-derivative bytecode VM defeats off-the-shelf disassemblers |
| Defense Evasion / T1497.003 | Time Based Evasion | Loader 14-second cumulative `Sleep` with FPU verification at each sleep boundary |
| Defense Evasion / T1480.002 | Mutual Exclusion | Stage-2 first-run check on `HKU\<SID>\Software\SibCode\sn` registry value |
| Defense Evasion / T1622 | Debugger Evasion | Stage-2 entry-3 anti-analysis blocklist (ProcessHacker, x64dbg, WinDbg, IDA, Ghidra) checked via `NtQuerySystemInformation` |
| Defense Evasion / T1070.004 | File Deletion (memory variant) | Stage-2 `0xCCCCCCCC` heap fill before `VirtualFree(MEM_RELEASE)` to defeat post-mortem memory carving |
| Credential Access / T1555.003 | Web Browsers | Stage-2 plugin reads Chrome/Firefox/Edge/Brave Login Data SQLite databases |
| Credential Access / T1555.005 | Password Managers | Stage-2 plugin reads KeePass `.kdbx` files, 1Password vault files |
| Credential Access / T1539 | Steal Web Session Cookie | Stage-2 plugin extracts session cookies from browser cookie stores |
| Credential Access / T1056.001 | Keylogging | Stage-2 plugin module loaded from C2 (capability documented in family but plugin loading not directly observed in this run) (MODERATE) |
| Discovery / T1057 | Process Discovery | Stage-2 `NtQuerySystemInformation` process enumeration for analyzer-process blocklist |
| Discovery / T1010 | Application Window Discovery | Stage-2 GDI32 imports support window enumeration |
| Discovery / T1082 | System Information Discovery | Stage-2 `GetSystemMetrics` + GDI32 `GetDeviceCaps` for host fingerprinting |
| Collection / T1113 | Screen Capture | Stage-2 `BitBlt` via the GDI32-heavy import surface for periodic visual exfiltration |
| Collection / T1005 | Data from Local System | Stage-2 plugin file-collection from documented wallet/credential paths |
| Collection / T1602.002 | Data from Configuration Repository | Stage-2 plugin reads VPN client `.ovpn` configs, FileZilla `recentservers.xml`, RDP `.rdp` files |
| Command and Control / T1071.001 | Web Protocols | Stage-2 HTTPS to `79.133.180.168:3394/<panel-id>/<random>.<ext>` |
| Command and Control / T1573.001 | Symmetric Cryptography | Stage-2 CBC-XOR cipher for FS container; loader RC4 for Stage-2 wrapper |
| Command and Control / T1573.002 | Asymmetric Cryptography | Stage-2 TLS pinning to operator-issued brand-impersonation certificates (Samsung period) |
| Command and Control / T1568 | Dynamic Resolution | Stage-2 dynamic API resolution from PEB (cross-tactic with T1027.007 — Defense Evasion primary) |
| Command and Control / T1102 | Web Service | Cluster A Telegram Bot API (`api.telegram.org`) for credential exfil from PhaaS kits |
| Exfiltration / T1041 | Exfiltration Over C2 Channel | Stage-2 encrypted credential exfil over the established C2 HTTPS channel |
| Exfiltration / T1567.002 | Exfiltration to Cloud Storage | Cluster A Telegram chat-based exfil (`-1002104835510`, `-1001817323952`) functionally equivalent to cloud-storage exfil |

**MITRE ATT&CK technique highlight — T1055.012 (Process Hollowing) EAX-redirect variant:** This technique is the single most defender-relevant mapping in the Cluster C kill chain because the EAX-redirect variant defeats most stock EDR hollowing detection rules. See Sections 4.2.2 and 6.2 for the full technical explanation; defenders should validate that their EDR rules trigger on the **outcome** of hollowing (`InstallUtil.exe` running with no assembly path + outbound non-Microsoft network connections) rather than on the classic `SetThreadContext`-with-modified-`Eip` API pattern.

---

## 8. Indicators of Compromise

Structured IOCs are published in machine-readable format in the separate IOC feed file:

**IOC feed:** [`/ioc-feeds/opendirectory-79-137-192-3-20260515-iocs.json`](/ioc-feeds/opendirectory-79-137-192-3-20260515-iocs.json)

The feed contains validated, deduplicated, formatted indicators across all three clusters, with confidence levels and contextual metadata per CLAUDE.md IOC formatting standards. The summary below provides category counts and the highest-priority indicators only — defenders should ingest the JSON feed for the complete inventory.

### 8.1 IOC category summary

| Category | Cluster A (BellaMain) | Cluster B (Inkognito) | Cluster C (Rhadamanthys) | Total |
|---|---|---|---|---|
| File hashes (MD5/SHA1/SHA256) | 8 | 0 | 9+ | 17+ |
| Imphash | 0 | 0 | 1 | 1 |
| IPv4 addresses | 1 | 4 | 3 | 8 |
| Domains | 1 | 12 | 0 | 13 |
| URLs | 6 | 1 | 6 | 13 |
| Registry keys | 0 | 0 | 1 | 1 |
| File paths | 0 | 0 | 1 | 1 |
| PE section names | 0 | 0 | 1 (`.frontb`) | 1 |
| Cipher artifacts | 0 | 0 | 3 (RC4 key, CBC-XOR IV, Q3VM magic) | 3 |
| Telegram identifiers | 5 | 1 | 0 | 6 |
| Operator strings | 0 | 0 | 6 (zero-public-hit) | 6 |
| ASN identifiers | 1 | 5 | 1 | 7 |

### 8.2 Highest-priority Cluster C indicators (defender immediate action)

**Block at perimeter (network-layer):**
- `79.133.180.168:3394` — active Cluster C C2 (Hostkey NL AS57043), 34-month durability, survived Operation Endgame Phase 3
- `45.81.39.169` — alternate-customer C2 recovered from sibling Stage-2 (`bc9fe5e9...`); confirms multi-customer MaaS architecture

**Block all Aeza ASNs as OFAC-sanctioned infrastructure (regulated entities):**
- `AS216246` (Aeza Group LLC, RU)
- `AS210644` (Aeza International Ltd, IT)
- `AS211522` (Hypercore — Aeza front company per Silent Push 2025)

**Hunt at endpoint (host-layer):**
- File hash `5c38a5dd3703b1c4b8c2466b18ce9f4c45ef4c9bf6c3096bee8b24d20ecd247a` (loader SHA256)
- File hash `0e07ccda99c1cd80a2fd92e02b75d9a0` (Stage-2 MD5)
- Registry key write to `HKU\<SID>\Software\SibCode\sn`
- Imphash `1e5efd483892326cc4eeb97bc14a6266` (loader)

**Cipher fingerprints (custom-detection rule input):**
- 31-byte loader RC4 key: `e0802540d02d0feaeb277dc720e390b06dfd64d8f8104d9581e788e512715b`
- 16-byte Stage-2 CBC-XOR IV: `f6358d79df69c577d9dce6bb77fa4fa7` (customer-specific, pending cross-validation)
- Q3VM-derivative bytecode magic: `0x14744214` (vendor-side family marker)

**Operator credentials (zero-public-hit pivots):**
- `Ahuh783bhASbsxAsiopJQAiwhhbchG&*#U897u*#&*473` — 45-char operator credential (likely panel/C2 auth token)
- `BombAUb23456`, `DubzAias932` — operator build/campaign markers

### 8.3 Clusters A and B summary indicators

**Cluster A (BellaMain) — Telegram exfil pipeline:**
- Bot token (REVOKED): `6797512084:AAGbJVoC0zcKWYPbFG8oc_bACPn6gUEye_E`
- Bot ID (pivot value retained): `6797512084`
- Chat IDs: `-1002104835510` (credential channel), `-1001817323952` (operator channel)
- Admin Telegram UIDs: `5606327063`, `6594066326`
- Operator alias: `@AresRS34`
- Developer pseudonym: `Wadanz`
- MySQL DB name (cross-kit): `jakartaxdw`
- Admin URL path: `V5VgjLU0jsDe`

**Cluster B (Inkognito) — operator-controlled accounts:**
- Telegram channel: `@inkconnectvpn` (797 subscribers)
- Google Search Console verifications: `_Lq_FX-CDt3OmZqq5PNFfmQTZtLSHTNsVkViLTzpTwk`, `xskfj4k4tX_-enfPvu9WrUiWauHFlbuVmyV7thcjwds`
- Yandex Webmaster: `98466329`
- Custom HTTP header: `X-Admin-Token` (on `api.inkconnect.ru`)
- Decommission tombstone: HTTP `Server: kittenx`, content-length 148

For the complete validated indicator set with confidence levels and contextual metadata, ingest the JSON feed.

---

## 9. Threat Actor Assessment

> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-[YEAR]-[###] is an internal tracking designation assigned by The Hunters Ledger to actors observed across analysis who cannot yet be linked to a publicly named threat group. This label will not appear in external threat intelligence feeds or vendor reports — it is specific to this publication. If future evidence links this activity to a known named actor, the designation will be retired and updated accordingly.

This investigation surfaced **three operationally separate threat clusters** that share infrastructure (multi-tenant Aeza staging IP `79.137.192.3`) but exhibit **zero operator-level overlap** across seven dimensions tested (Telegram, pseudonyms, DNS/SOA, language, payments, malware family, production-C2 provider). Each cluster receives its own UTA designation. Cross-cluster linkage is rated **LOW (actively rebutted, not absent)** — anchored on Tier-1 OFAC documentation that the same Aeza infrastructure simultaneously hosts multiple unrelated actor ecosystems.

### 9.1 UTA-2026-008 — BellaMain Turkish PhaaS operator (Cluster A)

**Distinct-actor confidence:** MODERATE (75%)
**Named-actor attribution:** INSUFFICIENT (30%)

**Key evidence supporting distinct-actor claim:**
- **Code-level developer pseudonym:** `Wadanz` appears as a suffix on session-encryption helpers (`sifreleWadanz`, `sifrecozWadanz`) in `database/fonk.php` — this is direct integration of the developer's identity into the codebase, not a comment or readme artifact
- **Single shared Telegram bot** in all 6 `girislog.php` files across 7 distinct phishing kits — single-operator integration
- **Single MySQL database** (`jakartaxdw`) shared across the panel and all 7 kits — single-operator infrastructure
- **Verified operator alias:** `@AresRS34` is a real, privacy-restricted Telegram user account (verified 2026-05-07)
- **Turkish marketplace targeting:** Dolap, Letgo, PTT, Sahibinden, Shopier, Turkcell, Yurtici — coherent Turkish-market focus

**ACH winner:** Single Turkish-speaking PhaaS operator/developer
**ACH runner-up (RULED OUT):** Shared/leaked PhaaS template — eliminated by `Wadanz` code-pseudonym + single MySQL DB + single Telegram bot

**Why named-actor is INSUFFICIENT:** No prior public TI on BellaMain as a panel name; `@AresRS34` and `Wadanz` are not attested in any reviewed Tier-1/Tier-2 source. First-capture documentation. Resolution would require paid TI services (Flashpoint, Intel 471, KELA) for underground-forum cross-reference.

### 9.2 UTA-2026-009 — Inkognito Russian VPN/phishing operator (Cluster B)

**Distinct-actor confidence:** MODERATE (78%)
**Named-actor attribution:** INSUFFICIENT (30%)

**Key evidence supporting distinct-actor claim:**
- **Operator self-identification:** `@inkconnectvpn` Telegram channel description self-identifies "Inkognito" as the parent brand ("Надежный VPN от Inkognito! Видь то что скрыто, оставаясь в тумане войны!")
- **Cross-domain decommission tombstone:** `kittenx-404` HTTP fingerprint on multiple retired Inkognito-controlled domains — operator-standard fingerprint
- **Operator-controlled Google×2 + Yandex×1 search-console accounts:** verifications hardcoded into HTML meta tags of `inkconnect.ru`, `inklens.ru` — operator owns these accounts
- **Custom code primitives:** `X-Admin-Token` header on `api.inkconnect.ru`; EspoCRM single-instance back-office on dedicated Aeza IT IP
- **2.5-year operational continuity:** earliest BEC burn-domain `vetcorbeanca.eu` 2023-06-08 through current
- **Multi-tier provider segmentation:** Aeza for back-office, Cloudflare for production fronts, Stark Industries for BEC burn domains, Timeweb for some VPN edge nodes
- **`admin@<domain>.eu` BEC burn-domain SOA + self-hosted NS on Stark TR pattern** consistent across multiple burn domains
- **467+ brand-impersonation subdomains** under unified operator control

**ACH winner:** Single Russian-speaking multi-product fraud operator
**ACH runner-up (RULED OUT):** White-labeled VPN reseller — eliminated by EspoCRM + custom code + single search-console accounts

**Why named-actor is INSUFFICIENT:** No prior public TI on Inkognito brand portfolio. First-capture documentation of a 3-year-old operation. Resolution would require Russian underground forum investigation via paid TI; SBP/T-Pay merchant ID lookup would resolve the legal entity.

### 9.3 UTA-2026-010 — Rhadamanthys MaaS customer (Cluster C, primary)

> **Critical framing note:** UTA-2026-010 tracks the **customer-side operator only** — the LLM-augmented amateur who built `staticlittlesource.exe`, deployed it via cracked-software/game-cheat lures, and operates the Hostkey NL C2 at `79.133.180.168:3394`. The Rhadamanthys MaaS **vendor** is a separate threat-intel target with its own published profile in public Tier-2 reporting (Check Point Research, Outpost24, Recorded Future Insikt Group, etc.) and is **NOT** covered by UTA-2026-010. Conflating customer with vendor is a common error in MaaS attribution that this designation explicitly avoids.

**Distinct-actor confidence:** MODERATE (72%)
**Family classification confidence:** DEFINITE (97%) — Rhadamanthys infostealer Stage-2 vendor product
**Named-actor attribution:** INSUFFICIENT (30%)

**Key evidence supporting distinct customer-side actor claim:**
- **6 zero-public-hit operator strings** in loader `main()`: `BombAUb23456`, `DubzAias932`, 45-char `Ahuh783bh...`, `take it everywhere`, `AUJsgbSyhusW*...`, `Cancel of card!` — none match any prior public sample, GitHub commit, or security blog
- **31-byte operator RC4 key** `e0802540...` — non-standard length (typical RC4 keys are 16 or 32 bytes); customer-side build choice
- **LLM-augmented amateur loader tradecraft profile:** the combination of (a) wrapping a top-tier commodity stealer in a homebrew loader, (b) printing debug strings to stdout from `main()`, (c) using a non-standard 31-byte RC4 key, (d) including English-language phrases like `take it everywhere` that read like LLM completions, (e) `& 0x800000ff` arithmetic patterns characteristic of LLM-generated bit manipulation, (f) `std::cout` debug calls in a release build, (g) `strcmp`-based API resolver instead of hash-based. Each individual marker is weak; the combination is consistent with LLM-augmented amateur tradecraft (per project memory `feedback_static_cipher_dynamic_validation` for the analytical caveats on attribution markers).
- **34-month stable Hostkey NL C2** `79.133.180.168:3394` — customer-side infrastructure choice (not vendor-shared)
- **TLS brand-impersonation rotation** (self-signed → Apple → Samsung) — operator-driven cert rotation cadence
- **Customer-selected `InstallUtil.exe` LOLBin hollowing** — distinct from documented vendor customer choices (`dllhost.exe`, `taskhostw.exe`, `TsWpfWrp.exe`, `spoolsv.exe`, `wuauclt.exe`); per-customer tradecraft

**ACH winner:** Single LLM-augmented amateur Rhadamanthys MaaS customer
**ACH runner-up (RULED OUT):** Vendor-shared infrastructure — eliminated by per-customer C2 IP separation (sibling sample `bc9fe5e9...` uses different C2 `45.81.39.169`) + amateur loader profile categorically different from vendor's HIGH-PROFESSIONAL Q3VM adaptation

**Why named-actor is INSUFFICIENT:** No prior public TI matches this customer's loader strings or per-customer cipher fingerprints. Named-actor attribution ceiling cannot exceed LOW for this customer without (a) government attribution, (b) 2+ Tier-2 vendor independent corroboration, or (c) 70%+ code-similarity to a documented named actor toolchain — none present.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-79-137-192-3-20260515/rhadamanthys-maas-vendor-customer-architecture.svg" | relative_url }}" alt="Process-tree infographic of the Rhadamanthys MaaS vendor-customer architecture. Top center red side-rail card: Rhadamanthys MaaS Vendor — develops and sells canonical Stage-2 to multiple customers, VS2003 toolchain with Q3VM-derivative VM magic 0x14744214 and 3-layer encrypted-blob synthesis, marked as a SEPARATE threat-intel target tracked in Check Point, Outpost24, Recorded Future, and Operation Endgame Phase 3. Below the vendor a 3-way fanout splits into three customer cards. Left card red side-rail: Customer A (sibling Stage-2 bc9fe5e9...) — different loader build, different operator strings, different RC4 key, different LOLBin choice, leading to a different C2 endpoint at 45.81.39.169 OCULUS US AS. Middle card highlighted with deep-red border and side-rail plus a star: UTA-2026-010, THIS REPORT — Cluster C, the staticlittlesource.exe loader (sha256 prefix 5c38a5dd, 1.39 MB) with operator strings BombAUb23456, DubzAias932, Ahuh783bh..., InstallUtil.exe LOLBin choice, leading to this customer's C2 at 79.133.180.168:3394 on Hostkey NL AS57043. Right card red side-rail: Customer B (sibling Stage-2 e827d13c... or 457aecd8...) — different loader build, different operator strings, different RC4 key, different LOLBin choice, leading to a different C2 endpoint that was not extractable because VirusTotal sandbox emulation systematically fails across all sibling samples. At the bottom a grey side-rail band shows what all customers share: vendor-side .frontb section, Q3VM derivative VM magic 0x14744214, 3-layer synthesis, CBC-XOR cipher, FS container, XS1/XS2 plugins. Footer detection scope: this report's customer-side fingerprints catch this operator only; vendor-side fingerprints catch the entire Rhadamanthys customer population.">
  <figcaption><em>Figure 17: The Rhadamanthys MaaS architecture and the per-customer separation that drives the UTA framing. UTA-2026-010 (highlighted center) is the customer-side operator The Hunters Ledger newly contributes to the public record; the vendor (top) is well-documented elsewhere and is explicitly out of scope for this UTA. The grey common-element band at the bottom shows what cross-customer detection content (Q3VM magic, .frontb, SibCode\sn) covers — versus the per-customer fingerprints (RC4 key, IV, panel ID, LOLBin, C2 IP) that are unique to this operator.</em></figcaption>
</figure>

### 9.4 Cross-cluster linkage assessment

**Cross-cluster linkage:** LOW (actively rebutted, not absent)
**Tier-1 anchor:** OFAC Aeza Group sanction (July 1, 2025) — documents Aeza simultaneously hosting BianLian, RedLine, Lumma, Meduza, and BlackSprut as five separate actor ecosystems with no operational linkage.

**7-dimension overlap test (zero overlap across all dimensions):**

| Dimension | Cluster A (BellaMain) | Cluster B (Inkognito) | Cluster C (Rhadamanthys customer) | Overlap? |
|---|---|---|---|---|
| Telegram identifiers | `@AresRS34`, bot `6797512084` | `@inkconnectvpn` | None used | NO |
| Developer pseudonyms | `Wadanz` | None recovered | None recovered | NO |
| DNS / SOA / NS patterns | Aeza default `aezadns.com` | Self-hosted NS on Stark TR `193.46.56.182`, Namecheap | None (no associated domain) | NO |
| Operator language | Turkish | Russian | English-language LLM artifacts | NO |
| Payment infrastructure | TRX cryptocurrency, Telegram-based | SBP, T-Pay, card (Russian) | None observed (commodity MaaS subscription) | NO |
| Malware family | BellaMain PhaaS panel | None (web-app + VPN) | Rhadamanthys MaaS Stage-2 + custom loader | NO |
| Production C2 provider | Cloudflare-fronted (`cryptone.bot`) | Cloudflare-fronted production + Aeza back-office | Hostkey NL (`79.133.180.168`) | NO |

**ACH winner:** Three operationally separate actors co-tenant on shared multi-tenant Aeza bulletproof staging utility
**ACH runner-up (RULED OUT):** Three clusters operating as one entity — eliminated by zero overlap on all 7 dimensions

The 7-dimension test produces zero matches. Co-tenancy on `79.137.192.3` is therefore best explained as three customers of the same hosting service, not as one actor running three operations. The OFAC Aeza Tier-1 anchor confirms this is the typical pattern for bulletproof hosting infrastructure: BPH providers host many unrelated actors simultaneously, and co-residency is not operationally diagnostic.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-79-137-192-3-20260515/opendirectory-79-137-192-3-three-cluster-cotenancy.svg" | relative_url }}" alt="Process-tree infographic of the three-cluster co-tenancy on 79.137.192.3. Top center yellow side-rail card: the IP 79.137.192.3 on AS216246 Aeza Group LLC RU, multi-tenant bulletproof staging server with Apache 2.4.58 Win64 PHP 8.2.12, OFAC SDN Aeza Group sanction July 2025 documents 5 unrelated actor ecosystems co-resident on Aeza. Below the IP a 3-way fanout splits into three cluster cards. Left card yellow side-rail: Cluster A, UTA-2026-008, BellaMain Turkish PhaaS, operator @AresRS34, developer Wadanz, PHP/MySQL panel plus 7 Turkish marketplace kits, payout TRX TRON, Turkish language, brand cryptone.bot fake exchange, distinct-actor MODERATE 75% and named-actor INSUFFICIENT. Middle card red side-rail: Cluster B, UTA-2026-009, Inkognito Russian VPN/phishing, parent brand Inkognito with sub-brands INK VPN INK Lens CryptOne, React/Vite SPA plus EspoCRM stack, payment SBP T-Pay card RU, Russian language, operator alias @inkconnectvpn, 2.5+ year continuous operation, distinct-actor MODERATE 78% and named-actor INSUFFICIENT. Right card highlighted with deep-red border and side-rail plus a star: Cluster C — PRIMARY, UTA-2026-010, Rhadamanthys MaaS customer, loader staticlittlesource.exe, canonical Stage-2, operator strings BombAUb23456 and others, InstallUtil.exe LOLBin, C2 79.133.180.168:3394 on Hostkey NL, English language, survived Operation Endgame November 2025, distinct-actor MODERATE 72% and named-actor INSUFFICIENT. Below the three clusters a grey side-rail band lists the 7 dimensions tested for cross-cluster operator overlap with zero overlap on any: Telegram identifiers, operator pseudonyms, registrar/DNS/SOA pattern, language artifacts, payment processors, malware family, production-C2 hosting provider; cross-cluster operational linkage rated LOW (actively rebutted, not absent). Footer cites the Tier-1 anchor that Aeza simultaneously hosted BianLian, RedLine, Lumma, Meduza, and BlackSprut as 5 unrelated actor ecosystems, and notes that the same exclusion logic applied to BriansClub and CRD Club and elon-merge.com on this same IP also returned separate-actor verdicts.">
  <figcaption><em>Figure 18: The three-cluster co-tenancy that defines this report's analytical contribution. The visual makes the headline argument scannable: the three operators share one IP (top yellow box) and nothing else (grey overlap-failure band). The OFAC Aeza Tier-1 anchor in the footer is what makes the LOW cross-cluster linkage a defensible position rather than an absence of evidence.</em></figcaption>
</figure>

---

## 10. Risk & Detection

This section provides the defender-actionable detection coverage summary. Detection rules in YARA, Sigma, and Suricata format are published in the separate detection file:

**Detection rules:** [`/hunting-detections/opendirectory-79-137-192-3-20260515-detections/`](/hunting-detections/opendirectory-79-137-192-3-20260515-detections/)

### 10.1 Detection coverage summary

The detection file contains rules across three clusters and four detection-content types:

| Type | Cluster A (BellaMain) | Cluster B (Inkognito) | Cluster C (Rhadamanthys) |
|---|---|---|---|
| YARA (file/memory) | 2 (panel + kit signatures) | 0 (no PE samples) | 6 (loader + Stage-2 vendor + customer fingerprints) |
| Sigma (log-based) | 3 (web-server + Telegram exfil) | 3 (subdomain patterns + custom headers + tombstone) | 8 (process-tree + registry + InstallUtil behaviors) |
| Suricata (network) | 2 (kit URI patterns) | 2 (X-Admin-Token + brand-imp subdomain DNS) | 4 (C2 URL pattern + TLS cert + JARM + alt-C2) |
| EDR queries (multi-platform) | 0 | 0 | 4 (parent-child InstallUtil + memory profile) |

### 10.2 Defender priorities by cluster

**Cluster C (Rhadamanthys MaaS customer) — HIGHEST PRIORITY:**

1. **Behavioral hunt:** `InstallUtil.exe` initiating outbound TLS to non-Microsoft endpoints. This is the single highest-fidelity Cluster C detection across the entire Rhadamanthys MaaS ecosystem (any customer, any C2, any cert period).
2. **Behavioral hunt:** `InstallUtil.exe` running with no `/u` flag and no assembly path argument (legitimate `InstallUtil.exe` always takes both).
3. **Process-tree hunt:** any non-system parent spawning `InstallUtil.exe` with `CREATE_SUSPENDED`.
4. **Registry hunt:** any registry-set telemetry on `HKU\<SID>\Software\SibCode\sn` (no known benign software writes this key).
5. **Network block:** `79.133.180.168:3394` (active C2) and `45.81.39.169` (alternate-customer C2).
6. **YARA scan:** Stage-2 import-surface signature (GDI32 ≥ 100 + USER32 exactly 3 + ADVAPI32 registry-READ-only + no crypto + no network + `.frontb` PE section) — vendor-side signature, detects entire Rhadamanthys MaaS ecosystem.
7. **YARA scan:** Q3VM-derivative magic `0x14744214` little-endian — vendor-side family marker.
8. **YARA scan:** byte-emitter shape (small 200–300-byte functions with sequential `mov-imm` writes + offset-stride arithmetic) — defeats the 3-layer encrypted-blob synthesis camouflage.

**Cluster A (BellaMain) — MEDIUM PRIORITY:**

1. **Web-server log hunt:** kit URI patterns `*/girislog.php`, `*/kartlaodeme.php`, `*/tgdekont.php`, `*/cekimbot.php`.
2. **Network log hunt:** outbound HTTPS to `api.telegram.org` carrying bot ID `6797512084` (token revoked 2026-05-07; retroactive log analysis using the bot ID retains pivot value for identifying prior credential exfil traffic that predates revocation).
3. **YARA scan:** BellaMain panel signature (Wadanz suffix on `sifreleWadanz`/`sifrecozWadanz` strings).

**Cluster B (Inkognito) — MEDIUM PRIORITY:**

1. **Web proxy log hunt:** HTTP requests carrying the `X-Admin-Token` header.
2. **Web proxy log hunt:** HTTP responses with `Server: kittenx` and content-length 148 (decommission tombstone).
3. **DNS query hunt:** `*.inklens.ru`, `*.inklens.co.uk`, `*.inkconnect.ru`, `*.bikaf.ru`, `*.bigass.monster`, `*.unloki.ru`, brand-impersonation subdomain patterns under `inklens.*`.

### 10.3 Defender response orientation

**Detection priorities (the 2–3 highest-value behaviors to hunt for first):**
- `InstallUtil.exe` outbound TLS to non-Microsoft endpoints (Cluster C, highest fidelity)
- Registry write to `HKU\<SID>\Software\SibCode\sn` (Cluster C, family marker)
- Outbound traffic to Aeza ASNs `AS216246`/`AS210644`/`AS211522` (all clusters, OFAC-sanctioned)

**Persistence targets to look for and remove:**
- `HKU\<SID>\Software\SibCode\sn` registry value (Cluster C Stage-2 marker)
- Any `staticlittlesource.exe` artifact on disk or in recent-execution telemetry
- Browser extension and credential-store artifacts indicating successful Stage-2 plugin theft

**Containment categories:**
- Isolate affected hosts from network egress
- Block the active Cluster C C2 infrastructure at perimeter
- Block all Aeza ASNs as OFAC-sanctioned infrastructure (regulated entities)
- Rotate all credentials potentially exposed to the affected hosts (browser-stored, password-manager-stored, MFA tokens, VPN configs)
- Treat the hosts as fully compromised at the credential layer; downstream pivoting risk is high

This is a brief response orientation, not an incident-response playbook. Confirmed Cluster C infections warrant full IR procedures beyond what is outlined here.

> **EDR query coverage:** The detection file includes 4 EDR queries (covering parent-child `InstallUtil.exe` process tree, memory-profile anomalies, and no-assembly-path invocation) for platforms that support structured behavioral queries. See the separate detection file, section **Detection Coverage Summary**, for the per-cluster rule counts.

---

## 11. Confidence Summary

This section organizes the report's findings by confidence level for the higher-level view. Confidence levels follow the project-wide CLAUDE.md scale (DEFINITE / HIGH / MODERATE / LOW / INSUFFICIENT).

### DEFINITE (95–100%) — Direct evidence, no ambiguity

- **Cluster C Stage-2 family classification as Rhadamanthys** (97%) — Microsoft `Trojan:Win32/Rhadamanthys!ic` + CAPE `Rhadamanthys` + 48/63 VirusTotal vendors converge + `.frontb` PE section + SibCode VCL artifacts + `HKU\<SID>\Software\SibCode\sn` registry write per CAPE Procmon trace
- **Cluster C loader file identifiers** — SHA256 `5c38a5dd...`, MD5 `ae9991a0...`, imphash `1e5efd48...`, compile timestamp 2023-06-25 23:01:08 UTC, VS2022 v17.4 toolchain
- **Cluster C Stage-2 file identifiers** — SHA256 `804f4548...`, MD5 `0e07ccda...`, VS2003 toolchain, 458,752 bytes
- **Cluster A BellaMain panel + 7 kits** — full PHP source recovered; `Wadanz` developer pseudonym in `database/fonk.php`; bot token `6797512084:AAGbJVoC0zcKWYPbFG8oc_bACPn6gUEye_E` hardcoded in 6 `girislog.php` files
- **Cluster B Inkognito brand identification** — operator self-identifies "Inkognito" as parent brand via `@inkconnectvpn` Telegram channel description
- **Cross-cluster zero-overlap test** — 7 dimensions tested, 0 dimensions with operator-level overlap

### HIGH (85–95%) — Strong evidence, minor gaps

- **Cluster C C2 at `79.133.180.168:3394` is the active customer C2** — VirusTotal MCP confirms communicating files; URL pattern with panel ID `e6d92c6b5b2a03bee7fbab40` observed across multiple beacons
- **EAX-redirect process hollowing variant** — static analysis of loader confirms `SetThreadContext` modifies only `Eax` field; W^X transitions observed (PAGE_READWRITE → PAGE_EXECUTE_READ via VirtualProtectEx)
- **3-layer encrypted-blob synthesis** — Layer 1 byte-emitter functions (8,800+) + Layer 2 fake-GUID strings (7,979) + Layer 3 14-bit bit-packed stream all confirmed via static analysis; FS container synthesized correctly when emitters simulated
- **Q3VM-derivative bytecode VM with magic `0x14744214`** — magic constant verified in extracted bytecode region; opcode patterns consistent with Q3VM derivatives
- **CBC-XOR cipher with 16-byte IV `f6358d79df69c577d9dce6bb77fa4fa7`** — cipher routine at `FUN_00402790` reverse-engineered; IV recovered from `.rdata` at `0x0041c434`
- **31-byte loader RC4 key recovered** — bytes at `&DAT_00433820` confirmed; RC4 KSA + PRGA implementation at `FUN_00402400` matches reference
- **Cluster A Telegram exfil pipeline** — bot token revoked 2026-05-07 (HTTP 401 on `getMe`) confirms ownership transition, but bot ID retains pivot value
- **Cluster B kittenx-404 cross-domain decommission tombstone** — observed on multiple retired Inkognito-controlled domains
- **Cluster B operator-controlled search-console accounts** — Google×2 + Yandex×1 verifications hardcoded in HTML meta tags
- **Distinct-actor designations for all three clusters** — Cluster A 75%, Cluster B 78%, Cluster C 72% per ACH analysis
- **Cross-cluster linkage = LOW (actively rebutted)** — anchored on Tier-1 OFAC Aeza sanction documenting 5 unrelated actors co-resident
- **Aeza Group infrastructure is OFAC-sanctioned** — Tier-1 OFAC documentation July 1, 2025; AS216246, AS210644, AS211522 (Hypercore) all designated
- **Operation Endgame Phase 3 disrupted Rhadamanthys** — Tier-1 Europol press release November 2025, 1,025+ servers seized, 525,000+ infections in 226 countries
- **The Cluster C C2 survived Operation Endgame** — VirusTotal MCP shows continued communicating files post-November 2025

### MODERATE (70–85%) — Reasonable evidence, notable gaps

- **Per-customer specificity of CBC-XOR IV `f6358d79df69c577d9dce6bb77fa4fa7`** — indirect inference only; sibling Stage-2 cross-validation deferred (VT sandbox emulation systematically fails on cohort)
- **Per-customer specificity of panel ID `e6d92c6b5b2a03bee7fbab40`** — indirect inference only; SibCode\sn per-build Unix-timestamp variation supports per-customer framing
- **LLM-augmented amateur tradecraft profile for Cluster C customer** — combination of weak individual markers; consistent but not categorically determinative
- **Cluster C InstallUtil.exe target is per-customer choice** — not in reviewed Check Point v0.9.x customer-target enumeration, but cannot confirm absence across all known Rhadamanthys customers
- **Cluster A operator language inference (Turkish)** — based on marketplace targeting + Wadanz pseudonym Turkish-romanized form + Turkish-language strings in code
- **Cluster B operator language inference (Russian)** — based on Russian-language Telegram channel content + Russian payment infrastructure (SBP, T-Pay) + Russian customer base targeting
- **Cluster C delivery via cracked-software/game-cheat lure** — inferred from filename pattern (`staticlittlesource.exe`) and LLM-amateur tradecraft profile; not directly observed
- **Cluster C plugin module loading** — capability documented in family but specific plugin loading not observed in this analyzed run; Stage-2 has the loading capability code present

### LOW (50–70%) — Weak or circumstantial evidence

- **Specific Q3VM lineage attribution** — magic-constant + opcode-pattern similarity HIGH, but direct binary comparison with stock Q3VM (jnz/q3vm) and Outpost24 IDA Pro QVM modules deferred work that would elevate to DEFINITE
- **Specific named-actor attribution for any cluster** — INSUFFICIENT to LOW for all three; first-capture documentation across Clusters A, B, and C
- **Customer's geographic location** — no direct evidence; LLM-augmented amateur profile is geographically agnostic

### INSUFFICIENT (<50%) — Cannot assess

- **Real-world identity of any of the three operators** — no government attribution, no 2+ Tier-2 vendor independent corroboration; resolution requires paid TI or law enforcement access
- **Total victim count for Cluster C customer** — Operation Endgame statistics cover the entire Rhadamanthys MaaS ecosystem (525,000+ infections), not this specific customer
- **Whether Cluster C customer purchased other MaaS products in addition to Rhadamanthys** — no evidence either way

---

## 12. Coverage Gaps and Open Questions

This section documents what was not concluded in this investigation — the deferred work, the indirect inferences awaiting cross-validation, and the named-actor attribution ceiling. Surfacing gaps explicitly is part of the threat-intelligence rigor the project applies (CLAUDE.md → CONFIDENCE LEVELS).

### 12.1 Cluster C — deferred technical work

**1. Per-customer CBC-XOR IV cross-validation (HIGH priority).** The 16-byte IV `f6358d79df69c577d9dce6bb77fa4fa7` is treated as customer-specific in the report based on indirect inference. Direct validation requires extracting the IV from sibling Stage-2 samples (`bc9fe5e9e8e60511242afb24df276681bc92ae97e89b95ad2b7fe4fe56744447`, `e827d13c394d096d1e13f6860e4da75e506b3d935a480b087833485127b954e1`, `457aecd836dbc6038d81c22daa0fc5dbc42f0f0c6d09a97f73b48db264b2e8dd`) and comparing. **Blocker:** VirusTotal sandbox emulation systematically fails across all sibling samples (zero `contacted_urls` / zero `embedded_urls` cohort-wide). Resolution path: manual extraction via Ghidra Track E.2 of each sibling sample, replicating the 3-layer FS synthesis and CBC-XOR decrypt.

**2. Per-customer panel-ID specificity validation.** The 24-hex-character panel ID `e6d92c6b5b2a03bee7fbab40` is treated as customer-specific based on indirect inference (per-build SibCode\sn Unix-timestamp variation supports per-customer framing). Direct validation has the same blocker as item 1.

**3. Q3VM lineage direct comparison.** The Q3VM-derivative claim is HIGH confidence based on magic-constant similarity, opcode-pattern similarity, and consistency with Outpost24 / amnesia.sh analysis of Rhadamanthys VM modules. Direct binary comparison with the stock Q3VM repo (jnz/q3vm) and Outpost24's IDA Pro QVM modules would elevate this to DEFINITE.

**4. Track E.x bytecode work.** Full disassembly of the Q3VM-derivative bytecode in FS container entry 0 was deferred. The opcode permutation table is partially recovered; full recovery would enable complete bytecode-level analysis of the anti-analysis routines and timing checks.

### 12.2 Named-actor attribution ceiling

For all three clusters, named-actor attribution is INSUFFICIENT. The named-actor attribution ceiling cannot exceed LOW for any cluster without one of:
- **(a) Government attribution** (FBI, CISA, NCSC, Five Eyes) — none present
- **(b) 2+ Tier-2 vendor independent corroboration** — none present (first-capture for all three)
- **(c) 70%+ code-similarity to a documented named actor toolchain** — none present

Resolution paths require paid threat intelligence (Flashpoint, Intel 471, KELA) for underground forum cross-references on:
- `@AresRS34` / `Wadanz` (Cluster A)
- `@inkconnectvpn` / Inkognito brand (Cluster B)
- `BombAUb23456` / `DubzAias932` / 45-char operator credential (Cluster C)

### 12.3 Cluster B — infrastructure gaps

- Historical WHOIS for expired `.eu` BEC burn domains not queried (resolution: paid historical WHOIS service)
- akredup.ru role confirmation incomplete
- divar-irantop.shop Google Analytics cross-reference not performed
- Cluster B email-sending infrastructure not identified
- Inkognito subdomain full enumeration incomplete (180+ verified floor; 467+ estimated)
- SBP/T-Pay merchant ID lookup would resolve the legal entity behind the Inkognito brand portfolio

### 12.4 Cluster C — Operation Endgame status monitoring

Whether `79.133.180.168:3394` will remain active through the end of 2026 requires ongoing monitoring. The C2 survived the November 2025 Operation Endgame Phase 3 takedown (per VirusTotal MCP communicating-files data through 2026-05-13), but follow-up enforcement actions or Hostkey NL provider response could change this. Recommend periodic VirusTotal IP report re-checks and JARM monitoring on the Samsung-impersonation cert period.

### 12.5 Rhadamanthys vendor post-Endgame status

No confirmed reporting on the Rhadamanthys vendor's arrest or resumed operations under "RHAD Security" or "Mythical Origin Labs" branding after November 2025. This is vendor-side intel that is out of scope for UTA-2026-010 (which tracks the customer only) but is relevant context for the Rhadamanthys MaaS ecosystem trajectory.

---

## 13. References

This report draws on Tier-1 (government / authoritative), Tier-2 (major-vendor research), and Tier-3 (reputable security journalism) sources. Each cited claim ties back to one or more entries below. Citations follow the Admiralty Code (reliability × information-quality) per CLAUDE.md SOURCE CREDIBILITY TIERS.

### Tier 1 — Government / authoritative

- **U.S. Treasury OFAC** (July 1, 2025): "Treasury Sanctions Aeza Group, Russia-Based Bulletproof Hosting Service Provider" — sanctions designation documenting Aeza simultaneously hosting BianLian, RedLine, Lumma, Meduza, BlackSprut. Admiralty A1.
- **Europol** (November 2025): Operation Endgame Phase 3 press release — disruption of 1,025+ Rhadamanthys vendor servers covering 525,000+ infections in 226 countries. Admiralty A1.
- **Shadowserver Foundation** (November–December 2025): "Rhadamanthys Historical Bot Infections" Special Report — distributed victim notifications to 201 National CSIRTs across 175 countries. Admiralty A2.
- **VirusTotal MCP** — IP report `79.133.180.168` with communicating files and SSL certificate history; IP report `79.137.192.3` with 135 DNS resolutions and communicating files. Admiralty A1.

### Tier 2 — Major-vendor research

- **Check Point Research** (2023): "Rhadamanthys v0.5.0 — A Deep Dive into the Stealer's Components." Admiralty B1.
- **Check Point Research** (November 2024): "CopyRh(ight)adamantys Campaign — Rhadamanthys v0.7." Admiralty B2.
- **Check Point Research** (2025): "Rhadamanthys 0.9.x — A Walk Through the Updates." Admiralty B2. Documents the v0.9.1 changelog removal of registry write operations (the basis for dating the analyzed Stage-2 to pre-v0.9.1).
- **Outpost24** (2025): "Rhadamanthys Malware Analysis — How Infostealers Use VMs to Avoid Analysis." Admiralty B1. Tier-2 anchor for the Q3VM-derivative VM lineage claim.
- **Proofpoint** (November 2025): "Operation Endgame Quakes Rhadamanthys." Admiralty B2.
- **Recorded Future Insikt Group** (September 2024): "Rhadamanthys Stealer Adds Innovative AI Feature" — documents the cryptocurrency-wallet-image OCR plugin (Bitcoin seed-phrase recognition from screenshots). Admiralty B2.
- **Silent Push** (2025): "Aeza Group Infrastructure Shift Following OFAC Sanctions" — documents the AS211522 (Hypercore LTD) shift as an Aeza front company. Admiralty B2.
- **Chainalysis** (July 2025): "OFAC Sanctions Aeza Group Bulletproof Hosting." Admiralty B2.
- **Zscaler ThreatLabz**: "Technical Analysis of Rhadamanthys Obfuscation Techniques." Admiralty B2.
- **Binary Defense**: "Rhadamanthys Stealer Analysis for Detection Opportunities." Admiralty B2.
- **Censys**: "Hiding in Plain Sight — Tracking Bulletproof Hosting and Abused RDP Infrastructure." Admiralty B2.
- **Intel 471**: "Bulletproof Hosting — A Critical Cybercriminal Service." Admiralty B2.

### Tier 3 — Reputable security journalism

- **The Record (Recorded Future News)**: Aeza Group OFAC sanctions reporting. Admiralty C1.
- **BleepingComputer**: "Rhadamanthys Infostealer Disrupted as Cybercriminals Lose Server Access." Admiralty C1.
- **amnesia.sh** (January 2023): "VM-Based Obfuscation in Rhadamanthys Stealer." Admiralty C2. Early documentation of Rhadamanthys VM modules.

### Internal references

- **The Hunters Ledger — UTA-2026-008** (BellaMain Turkish PhaaS operator) — internal threat-actor file
- **The Hunters Ledger — UTA-2026-009** (Inkognito Russian VPN/phishing operator) — internal threat-actor file
- **The Hunters Ledger — UTA-2026-010** (Rhadamanthys MaaS customer) — internal threat-actor file
- **IOC feed:** [`/ioc-feeds/opendirectory-79-137-192-3-20260515-iocs.json`](/ioc-feeds/opendirectory-79-137-192-3-20260515-iocs.json)
- **Detection rules:** [`/hunting-detections/opendirectory-79-137-192-3-20260515-detections/`](/hunting-detections/opendirectory-79-137-192-3-20260515-detections/)

---

© 2026 Joseph. All rights reserved. See LICENSE for terms.
