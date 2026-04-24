---
title: 'Chaos Ransomware (TorBrowserTor) — Multi-Stage Batch Loader at 94.103.1.13'
date: '2026-04-23'
layout: post
permalink: /reports/open-directory-94-103-1-13-20260423/
hide: true
category: Ransomware Toolkit
description: 'Analysis of a private five-stage batch-to-PowerShell-.NET crypter delivering Chaos/TorBrowserTor ransomware from a bulletproof-adjacent open directory at 94.103.1.13. Documents four crypter behaviors with no located prior public reporting, including a Console.Title launch gate, tri-artifact anti-sandbox gate, cross-layer AES+XOR key reuse, and a Stage-5b UACME #41 UAC bypass with an 8/77 VT detection gap.'
detection_page: /hunting-detections/open-directory-94-103-1-13-20260423-detections/
ioc_feed: /ioc-feeds/open-directory-94-103-1-13-20260423-iocs.json
detection_sections:
  - label: "YARA Rules"
    anchor: "#yara-rules"
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "Suricata Signatures"
    anchor: "#suricata-signatures"
ioc_highlights:
  - value: "94[.]103[.]1[.]13"
    note: "Operator staging host (AS209207, multi-tenant)"
  - value: "forumrutor24[.]com"
    note: "Co-tenant on 94.103.1.13 (34d active)"
  - value: "da302511ee77a4bb9371387ac9932e6431003c9c597ecbe0fd50364f4d7831a8"
    note: "Stage-5b UACME #41 UAC bypass (cross-build, 8/77 VT)"
  - value: "f7a4fe18d838e9d87db2db6378ffb21b90c3881d28d70871b8c2a661c6a78a6a"
    note: "myfile.exe — Orcus RAT v7 Wardow crack"
  - value: "3b5d30e35f8e4f31a3e70d3754d02d0f045e39b6e0cfde22b1754667b7eb60a4"
    note: "mymain.bat — outer 5-stage batch loader"
---

**Campaign Identifier:** Chaos-TorBrowserTor-MultiStageLoader-94.103.1.13<br>
**Last Updated:** April 23, 2026<br>
**Threat Level:** HIGH

---

## 1. BLUF / Bottom Line Up Front

An open directory discovered on the Russian-registered bulletproof-adjacent VPS **94.103.1.13** (AS209207 Digital Hosting Provider LLC, upstream AS48014 AlbaHost) is hosting a pre-production cybercrime staging kit whose terminal payload is a **Chaos ransomware builder variant** configured as `.torbrowsertor`. The kit is operated by a financially-motivated actor we track internally as **UTA-2026-005** *(an internal tracking label used by The Hunters Ledger — see Section 7)*. Attribution to any publicly named threat actor is **INSUFFICIENT (0%)**; family-level identification of the Chaos builder lineage is **DEFINITE (97%)**.

The primary finding in this report is **not** the ransomware itself — the commodity Chaos builder is well documented. The primary finding is a **private five-stage batch-to-PowerShell-to-.NET crypter** (`mymain.bat` + `myfile.bat`) that the operator uses to deliver Chaos while evading static detection (VT 0/76 on both batch droppers at submission time) and sandbox analysis. That crypter exhibits four characteristics with **no located prior public reporting**:

1. A **Console.Title-based self-extraction** trick that uses the cmd.exe window title as a dynamic path locator and an implicit `.bat` execution guard.
2. A **tri-artifact anti-sandbox gate** — the inverted conjunction `admin` (username) + `%TEMP%\VBE\` (directory) + `%TEMP%\mapping.csv` (file) — that causes the loader to exit if all three match, consistent with either an operator-convenience check against their own development host or an intentional decoy.
3. **Cross-layer AES+XOR key reuse** — the same passphrase is used at three separate crypter layers within a build, and the same XOR key is reused at two layers, with per-build key rotation between builds.
4. A **Stage-5b AppInfo RPC UAC bypass** (UACME technique #41, `AiEnableDesktopRpcInterface` + `IColorDataProxy` + parent-PID spoof off elevated `taskmgr.exe`) delivered as a byte-identical pre-compiled PE across both builds with an **8/77 VT detection gap**.

The delivered payload (Chaos/TorBrowserTor Stage-5a) is Rijndael-256 CFB + RSA-2048 OAEP ransomware with removable-drive propagation, Volume Shadow Copy / BCDEdit / backup-catalog destruction, and a BTC clipboard hijacker. A parallel **Orcus RAT v7 (Wardow crack)** path provides the RAT/C2 foothold. Real C2 is hidden behind a `127.0.0.1:20268` loopback tunnel (chisel/plink stack); the upstream endpoint is **UNKNOWN** from static analysis alone.

This report documents the loader chain in defender-actionable detail and hands off a set of cross-build structural anchors — the Stage-4 mutex GUID `9f67b5ed-6c10-4c53-818b-8d26be0d1339`, the Stage-5b PE SHA256 `da302511…`, the cross-layer key-reuse pattern, and the tri-artifact gate — that future analysts can use to cluster additional UTA-2026-005 activity. Detection content is delivered separately in [open-directory-94-103-1-13-20260423-detections.md](/hunting-detections/open-directory-94-103-1-13-20260423-detections/); IOCs are delivered separately in [open-directory-94-103-1-13-20260423-iocs.json](/ioc-feeds/open-directory-94-103-1-13-20260423-iocs.json).

---

## 2. Key Takeaways

- **The loader, not the ransomware, is the novel story.** Chaos/TorBrowserTor is well-documented commodity ransomware; its clipboard wallets and Telegram handle (`@TorBrowserTor`) are **Chaos builder defaults** with zero operator-specific attribution value. The defender-actionable novelty lives in the **private five-stage batch loader** (`mymain.bat`, `myfile.bat`) that delivers it.
- **Four crypter-chain behaviors have no located prior public reporting:** the Console.Title launch-gate trick, the inverted tri-artifact anti-sandbox gate (`admin` + `%TEMP%\VBE\` + `%TEMP%\mapping.csv`), cross-layer AES+XOR key reuse as a builder fingerprint, and the specific Stage-5b UACME #41 AppInfo RPC bypass PE (byte-identical across both builds, 8/77 VT).
- **Two cross-build invariants are the highest-value hunting anchors** this investigation produced: the Stage-4 mutex GUID `9f67b5ed-6c10-4c53-818b-8d26be0d1339` and the Stage-5b UAC bypass SHA256 `da302511ee77a4bb9371387ac9932e6431003c9c597ecbe0fd50364f4d7831a8`. Each has zero public hits prior to this publication and produces high-fidelity, zero-FP hunting queries.
- **Attribution to a named actor is not possible.** Zero infrastructure overlaps, zero named-actor TTP matches, zero Tier-1/Tier-2 vendor attributions. The 2025 Cisco Talos "Chaos RaaS group" is **explicitly ruled out** as a distinct actor with a distinct codebase — do not conflate it with the 2021-origin Chaos builder our sample is built from. We track this operator internally as **UTA-2026-005**.
- **Stage-4 persistence is a Defender-masquerade dual-anchor:** a scheduled task literally named `\Microsoft Defender` at the task-scheduler root path (BOOT trigger, Hidden, RunLevel HIGHEST) plus a 1.4 MB encoded payload stashed at `HKLM\Software\Microsoft Defender\Payload`. This masquerade is the single most productive threat-hunt anchor for any defender with Sysmon EID 12/13 coverage.
- **Stage-1 batch files are static-evasion optimized.** `mymain.bat` (VT 0/76) and `myfile.bat` are 2.6 MB+ DOSfuscated batch droppers that force 32-bit `SysWOW64\WindowsPowerShell` execution, decode two chunks via alphabet-substitution Base64, and hand off to Assembly.Load. Traditional signature-based AV does not see them. Behavioral detection is the only reliable mitigation.
- **The kit is operator-scale, not single-campaign.** Two independent builds (`mymain.bat` and `myfile.bat`) compiled the same day (2026-03-31), sharing invariants but rotating keys and resource names — evidence the operator has tooling maturity to repeatedly rebuild, not just a single weaponized sample.

---

## 3. Executive Summary

### What Was Found

Our custom bulletproof/abuse-tolerant open-directory scanner flagged `94.103.1.13` on 2026-04-17. The server was exposing directory listings for a mixed staging tree containing ~47 distinct samples: Stage-1 batch droppers, obfuscated PowerShell loaders, .NET Stage-4 and Stage-5 modules, an Orcus RAT v7 build, a custom PrintSpoofer-class privilege-escalation binary, a full Mimikatz suite, multiple GodPotato variants, PrintNightmare tooling (including the signed `mimispool.dll`), Chisel and Plink tunneling binaries, a Python tunnel-stub collection, and a second (parallel) pre-production campaign tree containing SnipeIT/SIP-PBX/Exim/CGMiner/OTP exploit scripts targeting seven IP addresses (four of them Ukrainian).

Of the 47 samples, two were the loader chain that matters: the sibling batch droppers `mymain.bat` (2.6 MB, SHA256 `3b5d30e3…`, VT 0/76 at submission) and `myfile.bat` (2.65 MB, SHA256 `fb39fa0d…`). Both are heavily DOSfuscated and both carry two large Base64-alphabet-substituted blobs that decode into a five-stage loader chain terminating in Chaos/TorBrowserTor ransomware plus a pre-compiled UACME #41 UAC-bypass module. The two builds share the same builder pipeline and identical invariants (mutex GUID, Stage-5b PE) but rotate cryptographic keys and resource names — evidence that the crypter is a re-runnable builder rather than a one-off weaponization.

### Why This Threat Is Significant

Commodity Chaos ransomware is well-catalogued by WatchGuard, Malpedia, Trend Micro, and Fortinet. What is **not** catalogued is the specific private crypter pipeline used by this operator. This report fills that gap with defender-actionable specifics: magic markers, passphrases, XOR keys, resource names, mutex GUIDs, Defender-masquerade persistence artifacts, the Console.Title self-extraction trick, and the tri-artifact anti-sandbox gate. None of these appear in any public source we located as of 2026-04-23. The `.torbrowsertor` variant itself is approximately two weeks into public-reporting lifecycle (PCrisk and ITFunk Tier-3 writeups only) — this publication is among the earliest comprehensive technical writeups.

### Key Risk Factors

| Risk Dimension | Score | Justification |
|---|---|---|
| Data Exfiltration | 7/10 | Orcus RAT v7 stages keylogging, screen capture, file listing, and arbitrary file-write; real C2 unknown behind tunnel |
| System Compromise | 9/10 | Full SYSTEM path via layered privesc (custom p.exe + GodPotato + PrintSpoofer + PrintNightmare `mimispool.dll`) |
| Persistence Difficulty | 8/10 | Dual Defender-masqueraded anchors (scheduled task `\Microsoft Defender` at root + HKLM registry-blob) survive reimage-by-profile; Orcus adds HKCU Run key + AudioDriver.exe masquerade |
| Evasion Capability | 9/10 | AMSI/ETW bypass + user-mode ntdll unhook (Perun's Fart) + 12-DLL anti-sandbox + Console.Title launch gate + tri-artifact gate + 8/77 VT Stage-5b |
| Lateral Movement Risk | 7/10 | Mimikatz credential dumping staged, chisel/plink tunnel stack, removable-drive propagation (`surprise.exe` / `Recieve please.exe`) |
| Ransomware Impact | 9/10 | Rijndael-256 CFB + RSA-2048 OAEP file encryption, `.torbrowsertor` extension, VSS/BCDEdit/backup-catalog destruction, BTC clipboard hijacker |

**Overall Risk Score: 8.2/10 (HIGH)** — commodity core + advanced custom crypter + 8/77-VT UAC bypass + layered privesc + ransomware + RAT foothold + lateral-movement tooling. The score is held below CRITICAL because (a) no confirmed victim telemetry has been observed, (b) the open directory was discovered in a pre-production state (second campaign only partially staged), and (c) the real C2 upstream is unknown so the actual operational reach cannot be assessed from static analysis alone.

### Threat Actor

**Named-actor attribution: INSUFFICIENT (0%).** Zero infrastructure overlaps with any tracked cluster, zero named-actor TTP matches, zero Tier-1/Tier-2 attributions. The actor is tracked internally as **UTA-2026-005** — see Section 7 for the full Threat Actor Assessment including the UTA-identifier explanatory note and the mandatory Chaos-builder-vs-Chaos-RaaS disambiguation.

**Family-level identification: DEFINITE (97%).** Chaos ransomware builder (2021-origin, v1–v5 lineage), configured as the TorBrowserTor variant. Sources: WatchGuard, Malpedia, Trend Micro, Fortinet, Acronis (all B1 Admiralty). Explicit ruling: this is **NOT** the April 2025 Cisco Talos "Chaos RaaS group" — that is a distinct named actor with a distinct codebase.

### For Technical Teams

1. **Deploy the cross-build anchors first.** Hunt the Stage-4 mutex GUID `9f67b5ed-6c10-4c53-818b-8d26be0d1339` and the Stage-5b SHA256 `da302511…` across your estate — both are zero-false-positive anchors with zero public prior hits. See Section 5 and the linked detection file.
2. **Check for the Defender-masquerade persistence pair.** Any scheduled task named `\Microsoft Defender` registered at the task-scheduler root path (not under `\Microsoft\Windows\Windows Defender`), combined with a >100 KB blob at `HKLM\Software\Microsoft Defender\Payload`, is diagnostic. See Section 4.
3. **Baseline `powershell.exe` command-line length.** A 32-bit `SysWOW64\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -NoProfile` invocation with a command-line exceeding 10,000 characters, launched as a child of `cmd.exe`, is a structural loader signature this builder shares across both builds.
4. **Watch for `conhost.exe --headless` spawned by elevated `taskmgr.exe`.** This is the Stage-5b UAC-bypass tell — see Section 4 for the full AppInfo RPC chain and why it matters.
5. **Expand hunting to BTC-clipboard-hijacker behavior.** Processes registering `WM_CLIPBOARDUPDATE` and substituting clipboard content matching bech32 or P2PKH Bitcoin regex patterns are the clipboard-substitution behavior the Stage-5a ransomware implements.

---

## 4. Threat Intelligence Summary

This section synthesizes threat-intelligence research (research-analyst output, stage2-research.md) with infrastructure findings (infrastructure-analyst output, stage2-infrastructure.md). Content is strictly tied to findings from the malware analysis and is not a generic threat landscape overview.

### Chaos Ransomware Family Context

The Chaos ransomware builder is a publicly available builder first observed in 2021. Its lineage runs v1 through v5, with multiple ecosystem forks (Yashma, Chaos-C++, Frea) documented by WatchGuard (B1), Malpedia (B1), Trend Micro (B1), Fortinet (B1), and Acronis (B1). The builder takes operator-configured parameters — file extension, ransom note text, ransom wallet, Telegram/contact handle, VSS-deletion flag, removable-drive-spread flag — and compiles a .NET console application implementing Rijndael-256 CFB + RSA-2048 OAEP file encryption against a predefined set of target extensions and directories.

Our Stage-5a sample is a **TorBrowserTor variant** of a Chaos v4/v5-era build. Confirming signatures (all DEFINITE at static analysis):

- Namespace `ConsoleApplication7` — builder template artefact present in both observed builds.
- Class `driveNotification` — clipboard-hijacker class name reused across builds.
- Encrypted file extension `.torbrowsertor`.
- Ransom note filename `READ ME PLEASE.txt`.
- Ransom note Telegram contact `@TorBrowserTor`.
- Clipboard substitution wallets `bc1qw0ll8p9m8uezhqhyd7z459ajrk722yn8c5j4fg` (bech32) and `17CqMQFeuB3NTzJ2X28tfRmWaPyPQgvoHV` (legacy).
- Stage-5a line-number-level source invariants (`namespace ConsoleApplication7` at line 1, `internal class Program` at line 18, `NativeMethods` at line 790, `driveNotification` class definition).

All 14 canonical Chaos v4/v5 feature markers were confirmed across both builds — basis for DEFINITE (97%) family identification.

### Wallets & Telegram — Builder Defaults, LOW Operator Attribution

> **Analyst note:** The bitcoin wallets and Telegram handle printed in the ransom note look like they should identify the actor. They don't. All three are **Chaos builder defaults** — hard-coded into the builder template and reused verbatim across many unrelated Chaos-family campaigns predating this investigation. Defenders should treat them as family-level indicators, not as operator fingerprints.

Infrastructure analysis (via WalletExplorer clustering) confirms:

- `bc1qw0ll8p9m8uezhqhyd7z459ajrk722yn8c5j4fg` — WalletExplorer cluster `19254d2b5d`, last activity 2025-09-29, associated with multiple unrelated Chaos-family campaigns predating this one.
- `17CqMQFeuB3NTzJ2X28tfRmWaPyPQgvoHV` — WalletExplorer cluster `9210ad5446`, last activity 2023-03-22, same shared-default pattern.
- `@TorBrowserTor` Telegram handle — shared across all TorBrowserTor-variant samples in public reporting (PCrisk C2, ITFunk C3).

**Attribution value: ZERO** for operator identity. Family-level indicator strength: HIGH (reliably flags Chaos-family activity).

### Chaos Builder vs Chaos RaaS Group (2025) — Disambiguation

See Section 7 for the mandatory reader-facing disambiguation blockquote. Short version: Cisco Talos reported a named "Chaos RaaS group" active from February 2025; that group is a **distinct actor** operating a **distinct codebase** with distinct TTPs. Our sample is a **build of the 2021-origin Chaos builder**, not an artifact of the Talos-named RaaS actor. This distinction is mandated in Stage-1 analysis and confirmed by research-analyst against Talos's own language.

### Orcus RAT v7 — Wardow Crack Ecosystem

The `myfile.exe` sample (SHA256 `f7a4fe18…`, 865 KB .NET assembly) is Orcus RAT v7 carrying three Wardow-crack family-wide signatures:

- Hard-coded AES key `CrackedByWardow` — Wardow-crack signature, not a per-sample key.
- Fixed AES-CBC IV `0sjufcjbsoyzube6` — Wardow-crack family-wide.
- Keyleak-backdoor magic filename `e3c6cefd462d48f0b30a5ebcd238b5b1` — Wardow-crack family-wide.

> **Analyst note:** The Orcus RAT sample is **Costura.Fody bundled**, not conventionally packed. Automated vendor tooling often labels Costura-bundled assemblies as packed because embedded-resource assemblies inflate the payload and obscure the entry-point graph. This is a bundling technique (single-file .NET deployment), not a cryptographic packer — analysts can fully recover the embedded modules with dnSpyEx or ILSpy by walking the assembly's resource stream.

Fody/Costura repository (B1), Microsoft .NET single-file-deployment documentation (A1), and hfiref0x UACME repository (B1) back the Costura identification. Wardow-crack attribution relies on community-known identifier framing — we did not locate any Tier-1/Tier-2 vendor writeup specifically on the Wardow-Orcus crack, so this is presented as a community-known identifier, not a vendor-sourced fact.

### Infrastructure Context — AS209207 Staging Server

> **Analyst note:** This subsection explains what is unusual about the VPS hosting the open directory. The ASN is only three months old, its upstream is a single Albanian transit provider that has a history of announcing bogon networks, and the operator chose it specifically for abuse tolerance. AbuseIPDB shows 0 reports — the operator is under the community-reporting radar despite being flagged by a handful of security vendors. Passive DNS shows the host is **multi-tenant**: the same IP that hosts the Chaos distribution also hosts at least three concurrent parasitic campaigns with deliberate tradecraft (Cloudflare fronting, mixed registrars, aged-domain purchases). None of this proves "bulletproof hosting" in the formal sense, but it is consistent with operator intent to resist takedown and run parallel infrastructure.

- **94.103.1.13** — the staging server — sits on **AS209207 (Digital Hosting Provider LLC)**, a Russian-registered ASN allocated **2026-01-19** (approximately 3 months old at the time of this writing). The ASN's own self-domain is `dhost.su` — a `.su` (Soviet-era) TLD still in operator-friendly use, reinforcing the RU-operator / NL-route jurisdictional split.
- AS209207's single upstream is **AS48014 AlbaHost** — an Albanian transit provider with a history of announcing bogon prefixes.
- Three separate data sources (BGP.he.net, IPinfo.io, BGPView) agree on the ASN/upstream relationship (HIGH confidence on the infrastructure facts).
- **AbuseIPDB: 0 reports, 0% confidence** (manual browser fetch, 2026-04-23). The previous limitation of automated 403 bot-blocks is resolved — this IP genuinely has no public abuse reports despite being flagged by 5 of 94 VirusTotal vendors (Criminal IP, BitDefender phishing, CRDF, CyRadar phishing, ESET suspicious, per session-8 lookup). An operator running under the community-reporting radar while accumulating limited-vendor detection coverage.
- **Bulletproof classification: SUSPECTED, not CONFIRMED.** The ASN is too new for a meaningful Spamhaus DROP/SBL listing history. No named-BPH-database entry was located. Threat intelligence feeds flag the upstream pattern as presumptively abuse-tolerant; we do not attribute this to any specific named institution without a live citation.
- **Explicit retraction:** An earlier working hypothesis linked this server to Proton66 / "TheGentlemen" toolkit. This hypothesis is **retracted** — 94.103.1.13 is on AS209207, not AS198953; the Hunt.io "TheGentlemen" toolkit was observed on 176.120.22.127, a completely different IP and ASN.

#### Multi-Tenant Operator Host — Co-Tenancy Pattern

Passive DNS (DomainTools Iris, 2026-04-23) confirms 94.103.1.13 is not a single-purpose Chaos staging server. The IP concurrently hosts at least three parallel operator campaigns alongside the Chaos distribution:

| Domain | Subdomains | First Resolution → Last | Resolutions | Theme / Role |
|---|---|---|---|---|
| `forumrutor24.com` | `www.` | 2026-03-20 → 2026-04-23 (34 days) | 183 pDNS hits | Russian-forum / tracker theme |
| `gtanuncios.com` | `mail.` | 2026-04-10 → 2026-04-23 (13 days) | 114 pDNS hits | Aged Portuguese/Spanish classifieds (created 2015); pivoted to 94.103.1.13 on 2026-04-11 15:09:21Z from prior Cloudflare origin `104.21.56.197` |
| `bulgainme.pro` | `mail.` | 2026-04-10 → 2026-04-23 (13 days) | 32 pDNS hits | Short-lived `.pro` registration (2026-02-23); mail server activated 2026-04-11 |

Historical resolution of `slayer.ktx.ro` (Romanian TLD) to 94.103.1.13 on 2025-12-18–19 (8 resolutions, 36-minute burst) indicates the IP was in operator rotation roughly four months before the current Chaos campaign. The operator's rotation cadence is therefore measured in months, not weeks.

**Consistent tradecraft across all three active co-tenants:**
- **Cloudflare-fronted DNS + CDN.** Every domain uses Cloudflare name servers (pair rotations observed: `fay/quinton` → `rob/nova`, `art/noor`, `dana/ethan` → `amber`). Operator-controlled Cloudflare accounts hide the `94.103.1.13` origin from passive scanners.
- **Mixed-registrar strategy.** `forumrutor24.com` is registered via **Mat Bao Corporation** (Vietnamese registrar, IANA 1586 — an unusual choice that deliberately sidesteps RU and US registrar scrutiny); `gtanuncios.com` transferred to **Network Solutions** via an intermediate CN reseller identity; `bulgainme.pro` uses a minimal `.pro` gTLD registration. No single registrar chokepoint.
- **Aged-domain purchase for reputation laundering** (gtanuncios.com). The domain was created 2015-05-16 (10+ years old), originally held by `Vikas` via PDR India, transferred to `xiang xiang fan` (CN reseller identity, Linfen Shanxi, phone +86 130 3255 6442, email `lc1393353@gmail.com`) on 2025-06-28, held dormant for ten months, then pivoted to 94.103.1.13 on 2026-04-11. Privacy-masking was applied to the WHOIS on 2026-04-24 00:39:01Z. This pattern — acquiring an aged domain with existing reputation and holding it dormant before pivoting to operator infrastructure — is documented attacker tradecraft against age-based reputation filters.
- **Concurrent setup bursts.** SSL cert churn on `bulgainme.pro` on 2026-04-10 (3 certs issued in a 2-minute window, 17:57–17:59 UTC), paired with the 2026-04-11 cutover of `gtanuncios.com` to the operator IP and mail-server activation on both domains, indicates a single operator standing up multi-domain infrastructure in a tight window.

**Assessment:** The operator's posture is mature — running parallel parasitic infrastructure rather than single-campaign tool deployment. This reframes the threat actor from "Chaos ransomware distributor" to "multi-campaign operator using Chaos as one of several concurrent monetization paths on the same host." Confidence: HIGH.

**Defensive implication:** Blocking just the Chaos-specific IOCs in this report will miss the operator's other campaigns on the same IP. Hunting teams should enumerate all of `forumrutor24.com`, `www.forumrutor24.com`, `gtanuncios.com`, `mail.gtanuncios.com`, `bulgainme.pro`, `mail.bulgainme.pro`, `94.103.1.13`, and historical `slayer.ktx.ro` under the broader UTA-2026-005 cluster. The full set is published in the IOC feed.

**VirusTotal refresh (2026-04-23) — Cloudflare fronting validated:**

The detection picture across this cluster is a clean demonstration of how Cloudflare CDN fronting protects operator-controlled co-tenant domains:

| IOC | VT Detection | Context |
|---|---|---|
| `94.103.1.13` (backing IP) | **5/94 + 1 suspicious** | Flagged by Criminal IP, BitDefender (phishing), CRDF, CyRadar (phishing), ESET (suspicious) |
| All 5 active co-tenant domains | **0/94** | Cloudflare edge hides the origin from automated scanners |
| Mail subdomains (`mail.gtanuncios.com`, `mail.bulgainme.pro`) | NOT FOUND | Never indexed — operator-internal webmail |
| `gtanuncios.com` traffic rank | **Alexa #267,012** | Aged domain retains legitimate historical traffic reputation — directly corroborates the reputation-laundering interpretation of the aged-domain purchase |
| `dhost.su` (ASN self-domain) | 0/94 via **BEGET-SU** | Well-known low-cost Russian registrar commonly chosen by operators for the cheap + weak-KYC combination |

**Analytical takeaway:** This is not coincidence. Blocking the domains downstream of the CDN is ineffective (0/94 means they look clean to most security tooling); blocking the IP, or hunting the cross-build structural IOCs (mutex GUID, Stage-5b hash, cross-layer key-reuse anchors), is the effective posture. The operator's infrastructure choices are deliberate — Cloudflare fronting plus mixed registrars plus aged-domain purchases combine to produce a cluster that evades all three common defensive triggers: domain reputation, CDN reputation, and registrar reputation. The only layer where detection has broken through is the backing IP itself (5/94) and the AS209207 ASN profile.

### Victim vs Operator Infrastructure — Critical Distinction

The parallel pre-production campaign staged on 94.103.1.13 contains exploit scripts targeting seven IP addresses. **These are victim / target IPs, not operator C2.** Do not block them as malicious infrastructure — hunt them for signs of compromise.

| IP | Port | Target | Origin |
|---|---|---|---|
| 85.238.98.37 | 8080 | SnipeIT (asset management) | Odessa, Ukraine |
| 178.20.159.99 | 8080 | Verkhovyna SIP PBX | Verkhovyna, Ukraine |
| 185.237.218.100 | 25 | Exim MTA | RU shared hosting |
| 192.227.113.124 | 4028 | CGMiner RPC | Cloud South (US) |
| 192.227.108.142 | — | Neighbor host | Cloud South (US) |
| 37.17.245.209 | — | Unknown target | Ukraine |

Four of seven target IPs are on Ukrainian ASNs — consistent with opportunistic targeting rather than nation-state geographic focus. The operator's targeting is financially motivated (SIP fraud, asset-inventory pivoting, mining-rig hijacking, OTP/authentication bypass) rather than sector- or region-specific APT activity.

### Research Gaps Carried Into This Report

- **Real Orcus C2 upstream is UNKNOWN.** The RAT connects to `127.0.0.1:20268` on the infected host; that loopback address is one end of a chisel or plink tunnel whose external egress we cannot recover from static analysis alone. Dynamic detonation with egress capture is needed.
- **Operator identity is still INSUFFICIENT for named-actor attribution.** The `xiang xiang fan` / `lc1393353@gmail.com` / `+86 130 3255 6442` identity recorded as the pre-masking registrant of `gtanuncios.com` is most plausibly a **CN domain-reseller inventory identity**, not the operator. The aged-domain-purchase pattern (10-year-old legitimate classifieds domain acquired from this reseller in 2025-06-28, dormant for 10 months, then pivoted to operator IP in 2026-04-11) is documented attacker tradecraft for reputation laundering. This evidence does NOT upgrade named-actor attribution above INSUFFICIENT, but it is recorded in UTA-2026-005 as a tracked signal — if the same reseller-inventory identity appears on another operator-pivoted domain in the future, that would be a clustering signal.
- **Wardow-Orcus crack has no Tier-1/Tier-2 vendor writeup** — used as a community-known identifier, not a cited vendor claim.
- **Console.Title launch gate and the specific tri-artifact conjunction have no located prior public reporting.** Corpus is not exhaustive; language in this report uses "we have not located prior public reporting describing this combination" rather than "first of its kind."
- **TorBrowserTor variant is only ~2 weeks into its public-reporting lifecycle.** This publication is among the earliest comprehensive writeups.

---

## 5. Technical Analysis

The technical core of this report is the **five-stage private crypter chain** carried inside `mymain.bat` and `myfile.bat`. This section walks the chain in chronological order from the moment a user double-clicks the batch file through to Chaos/TorBrowserTor ransomware detonation. Each kill chain stage heading opens with an analyst-note blockquote for readers who want the high-level summary before the technical detail.

Tools used across the analysis and referenced throughout this section:
- **decompiler (dnSpyEx)** — .NET assembly decompilation for Stage-4, Stage-5a, Stage-5b, and the Orcus RAT sample.
- **disassembler (Binary Ninja)** — native PE work on the custom PrintSpoofer-class binary and the signed PrintNightmare DLL.
- **interactive debugger (x64dbg)** — Stage-5b AppInfo RPC bypass behavioral confirmation.
- **malware analysis VM (FLARE-VM)** — static analysis environment; samples were never detonated on an internet-connected host.
- **behavioral sandbox (Noriben)** — behavioral baseline captures on selected stages with network egress blocked.

Subsequent references in this section use the general category term (decompiler, disassembler, debugger, sandbox) per the plain-language accessibility convention.

### 5.1 Sample Inventory (Static Analysis)

Both Stage-1 batch files were pulled from the `94.103.1.13` open directory on 2026-04-17 and submitted to VirusTotal on 2026-04-21 as part of a 47-sample batch upload. Decrypted intermediate payloads (Stage-4, Stage-5a, Stage-5b) were extracted on FLARE-VM during subsequent sessions; the cross-build-invariant Stage-5b was submitted to VT, while the per-build Stage-4 and Stage-5a artifacts were retained internally and not submitted (they are RE products, not files observed on the open directory).

| Filename | SHA256 (truncated) | Size | VT detection | Compilation |
|---|---|---|---|---|
| `mymain.bat` | `3b5d30e35f8e4f31…` | 2.6 MB | **0/76** at submission (2026-04-21) | Text |
| `myfile.bat` | `fb39fa0dd70a8c7b…` | 2.65 MB | Uploaded 2026-04-21 (count not captured) | Text |
| Stage-4 (decrypted, mymain) | `36dc72542530ff97…` | 1.03 MB | **47/77** (`trojan.lazy/msil`) | .NET, PE32 |
| Stage-4 (decrypted, myfile) | `5b0f529d2834ddb6…` | 1.03 MB | Not submitted (RE artifact) | .NET, PE32 |
| Stage-5a (decrypted, mymain) | `06f6df0f5e37620b…` | 25 KB | **57/77** (`ransomware.msil/azorult`; VT name `indf.exe`) | .NET, PE32 |
| Stage-5a (decrypted, myfile) | `13665bd2b75f8ff7…` | 25 KB | Not submitted (RE artifact) | .NET, PE32 |
| **Stage-5b (cross-build invariant)** | `da302511ee77a4bb…` | 986 KB | **8/77** (VT name `UacBypass.exe`) | .NET, PE32 |
| `myfile.exe` (Orcus v7 Wardow) | `f7a4fe18d838e9d8…` | 865 KB | **57/77** (`trojan.msil/orcusrat`) | .NET, Costura |
| `p.exe` (custom PrintSpoofer) | `b9ffbeed12325c45…` | 6.6 KB | **36/77** (`trojan.msil/misc`) | .NET x64, 2026-03-31 |

*Hashes above are truncated to the first 16 characters for readability. Full SHA256 values for every entry, plus secondary GodPotato variants, Mimikatz suite hashes, Chisel/Plink binaries, and all observed strings, are delivered in [open-directory-94-103-1-13-20260423-iocs.json](/ioc-feeds/open-directory-94-103-1-13-20260423-iocs.json). VT detection counts for the Stage-4/5a/5b rows are from a 2026-04-23 lookup; `mymain.bat` count was captured at submission time.*

### 5.2 Stage 1 — Batch Dropper: The `mymain.bat` / `myfile.bat` Chain

> **Analyst note:** Stage 1 is a heavily obfuscated Windows batch file that looks like random text to a casual viewer. What it actually does is force-launch 32-bit PowerShell with a command line over 10,000 characters long, carrying an encrypted .NET payload inline. The two sibling files (`mymain.bat` and `myfile.bat`) come from the same builder but use different encryption keys — a tell that this is a re-runnable crypter, not a one-off weapon.

Both Stage-1 batch files open with a long block of DOSfuscation (`%foo:a=b%`-style string mutation, `^` escape chars, `%random%` variable munging) that resolves at runtime to approximately the same final command line. Structural anchors shared across both builds:

- **Forced 32-bit PowerShell path:** `SysWOW64\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -NoProfile` — used regardless of the host's bitness. This is a structural builder tell.
- **Two Base64-like payload chunks per file**, separated by a single `\` byte, each carrying a 32-character magic marker prefix.
- **Alphabet-substitution reversal** before `FromBase64`: `.Replace('@','A').Replace('#','/')`. The substituted alphabet is a simple static-evasion trick that defeats naive Base64 scanners.
- **Console-title seeding** (see Stage 4 below): the batch file writes a unique string to the cmd.exe window title before the PowerShell hand-off. That title is later read back by a downstream .NET stage to locate the batch file on disk.

Per-build variation:

| Attribute | mymain build | myfile build |
|---|---|---|
| Magic marker (PS1 delimiter) | `aEVMeKDApIQzumcyjwpFSfqzEImqRdPQ` | `HPGDxAzpymskcRJvELNmhQkWaTXguERQ` |
| AES passphrase (triple-reused) | `qDqHmNfeSyWJoyxDzR` | `jttZjrlmkrBAtCBAMjkbThHsSjVNMjLLyONafxIj` |
| XOR key (reused chunk-1 + Stage-4) | `giXXxwxDxGrFeUjlxqLaLcb` | `cjJaThUwfQKxnHBm` |
| USB-spread filename | `surprise.exe` | `Recieve please.exe` (note typo in "Recieve") |
| Stage-5a self-copy name | `svchost.exe` | `projectxx.exe` |

**Why this matters for defenders.** Static signature-based AV does not detect these files (VT 0/76 for `mymain.bat` at submission). Behavioral detection is the only reliable mitigation: `cmd.exe` launching `SysWOW64\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -NoProfile` with a command line exceeding 10,000 characters is a structural loader tell.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-94-103-1-13-20260423/alphabet-substitution-chart.png" | relative_url }}" alt="Character frequency histogram of the mymain.bat chunk-1 payload blob showing a flat plateau across all 62 standard Base64 characters, with two anomaly spikes on '@' and '#' exactly matching the expected counts if those two characters are substituted in for 'A' and '/' respectively.">
  <figcaption><em>Figure 1: Character frequency analysis of the 1.48 MB chunk-1 payload blob confirms the `A↔@` and `/↔#` substitution by statistics alone. All 60 unique characters appear at the rate expected for uniform Base64 (~21,900 per character), except `A` and `/` are absent while `@` and `#` appear with exactly the counts they would have if substituted in. This is what lets the PS1 loader's `.Replace('@','A').Replace('#','/')` restore valid Base64.</em></figcaption>
</figure>

### 5.3 Stage 2 — PS1 Loader: AES-ECB + SHA256-Derived Key

> **Analyst note:** Stage 2 takes the two Base64-encoded chunks from the batch file, reverses the alphabet substitution, strips a 32-character "magic marker" prefix from each, then AES-decrypts using a key derived from a SHA256 hash of a builder-chosen passphrase. Each chunk decrypts to a GZip-compressed .NET assembly which is then loaded directly into memory via `[System.Reflection.Assembly]::Load`. No payload ever touches disk in this stage.

The PS1 loader is the first layer of decryption. Its structural anchors (identical across both builds):

- Base64 alphabet reversal: `.Replace('@','A').Replace('#','/')`.
- Magic-marker strip sentinel: `StartsWith(`...`) && Substring(32)`.
- AES construction: `[System.Security.Cryptography.Aes]::Create()` with `Mode = ECB`, PKCS7 padding, and `Key = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($passphrase))`.
- Decompression: raw `System.IO.Compression.GZipStream` around the decrypted ciphertext.
- Fileless dispatch: `[System.Reflection.Assembly]::Load([byte[]]$chunk0_decompressed).EntryPoint.Invoke($null, @($null))`.

**Cross-layer key-reuse observation (deep-dive).** The same passphrase used to derive the AES key for **chunk 0** is *also* used to derive the AES keys for **chunk 1** and for **Stage-4**. The builder hard-codes one passphrase per build and reuses it three times. Within each build, the XOR key is similarly reused across chunk 1 and Stage-4. This intra-build reuse, combined with per-build key rotation (different passphrase for mymain vs myfile), is the most distinctive builder fingerprint we recovered — a pattern we have not located in any public research on .NET crypters.

**Why this matters for defenders.** The plaintext key strings (`qDqHmNfeSyWJoyxDzR`, `jttZjrlmkrBAtCBAMjkbThHsSjVNMjLLyONafxIj`) live in **decrypted memory**, not on disk. On-disk YARA rules targeting the `.bat` file will never see them. In-memory / unpacked .NET module YARA is required for those specific string anchors. On-disk YARA must instead key on the structural anchors (forced-32-bit path, alphabet-substitution reversal, magic-marker + Substring(32) idiom).

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-94-103-1-13-20260423/chunk-decryption-pipeline.png" | relative_url }}" alt="PowerShell console output from FLARE-VM showing Stage-3 chunk decryption for myfile.bat. Two sequential invocations produce myfile_chunk0_payload.stage (32,768 bytes) and myfile_chunk1_payload.stage (1,045,504 bytes), each verified by SHA256 and by the presence of the 4d5a90 MZ magic in the first four bytes. A final comparison block shows that chunk 1's SHA256 differs from myfile.exe's SHA256, proving chunk 1 is a nested crypter stage and not the Orcus payload directly.">
  <figcaption><em>Figure 2: Stage-3 chunk decryption pipeline (FLARE-VM). AES-ECB decrypt, PKCS7 unpad, GZip decompress, then a MZ-magic check and SHA256 fingerprint on each chunk. The final comparison to myfile.exe's SHA256 is what disproved the early working hypothesis that chunk 1 was Orcus — chunk 1 is a nested crypter (Stage-4), not the final RAT. This established the multi-stage nature of the loader.</em></figcaption>
</figure>

### 5.4 Stage 3 — Chunk 0: Anti-Sandbox Unhook Stub

> **Analyst note:** Once chunk 0 loads into memory, it spends its first 200 milliseconds checking whether the host is a sandbox or analyst VM. It does so by testing twelve specific DLLs (from the public al-khaser anti-sandbox project), then performing a "Perun's Fart" ntdll unhook to defeat AMSI and ETW instrumentation. Only after passing these checks does it hand control to chunk 1.

Chunk 0 is a .NET assembly whose single job is environment validation and in-process hardening. Behaviors observed via decompiler analysis:

- **12-DLL al-khaser-style anti-sandbox sweep** — tests for `SbieDll.dll`, `dbghelp.dll` (with a specific version range), `api_log.dll`, `dir_watch.dll`, `pstorec.dll`, `vmcheck.dll`, `wpespy.dll`, `cmdvrt32.dll`/`cmdvrt64.dll` (Comodo), `snxhk.dll`/`snxhk64.dll` (Avast sandbox), `cuckoomon.dll`, and `SxIn.dll`. Presence of any one of these DLLs in-process causes the loader to exit cleanly.
- **AMSI bypass** — patches `amsi.dll!AmsiScanBuffer` with a `mov eax, 0x80070057; ret` thunk so subsequent PowerShell/script content is never scanned.
- **ETW bypass** — patches `ntdll.dll!EtwEventWrite` with `ret` so behavioral-analytics products lose telemetry visibility.
- **User-mode ntdll unhook (Perun's Fart)** — reads a clean copy of `ntdll.dll` from disk, computes the delta against the in-process copy (where EDRs typically install user-mode hooks), and overwrites the hooked bytes with the clean ones. This neuters user-mode EDR hooks for the duration of the process.
- **Tri-artifact anti-sandbox gate** (see 5.4.1 below) — the operator's signature anti-sandbox check.

#### 5.4.1 Tri-Artifact Anti-Sandbox Gate

> **Analyst note:** This is a distinctive anti-sandbox check. The loader will exit if **all three** of the following are simultaneously true: the current user is named `admin`, the directory `%TEMP%\VBE\` exists, AND the file `%TEMP%\mapping.csv` exists. Any single-artifact mismatch lets execution continue. The gate is *inverted* — it stops on MATCH, not on mismatch, which is the opposite of conventional anti-VM checks. We have not located prior public reporting of this specific triple.

The gate is embedded in two places: line 24 of the batch dropper (as DOSfuscated string comparisons) and again in chunk 0 (as managed `Environment.UserName` / `Directory.Exists` / `File.Exists` calls). The duplication is defensive — the batch check stops sandbox detonation before any PowerShell spawns; the chunk-0 check stops in-memory execution if the batch check is bypassed.

Two hypotheses for the inversion (operator exits on match):

1. **Operator-convenience check against their own development host.** The operator's analysis-tooling environment produces those artifacts (`VBE\` is a common Visual Basic-analysis directory; `mapping.csv` may be output from a code-mapping/IR tool they use). Exiting on match prevents the loader from executing on the operator's own workstation — a safety against accidental self-infection.
2. **Intentional decoy** to mislead researchers who flip the logic assuming a conventional anti-VM check.

We cannot distinguish between these from static analysis alone. The MODERATE-confidence interpretation is hypothesis 1 — operator convenience. Either way, the specific triple is a builder fingerprint.

**Why this matters for defenders.** A defender should never have these three artifacts present on a production endpoint. Their presence is a hunting anchor in its own right: any host with `admin` user + `%TEMP%\VBE\` + `%TEMP%\mapping.csv` is a candidate operator-analysis host (or a red-team lab). For threat hunting, treat the triple as a low-volume anomaly worth investigating.

### 5.5 Stage 4 — Console.Title-Based Dropper and Registry-Blob Persistence

> **Analyst note:** Stage 4 is where the loader writes itself to disk for the first time (in an encoded blob under a Windows Defender-masquerading registry path) and installs a scheduled task that re-runs the entire chain at boot. It also uses an unusual trick to find itself on disk: it reads the cmd.exe window title to recover the path of the batch file it launched from. We have not located prior public reporting describing this exact combination.

Stage 4 is a ~1 MB decrypted .NET assembly (per-build; mymain `36dc7254…` = 1,081,856 B, myfile `5b0f529d…` = 1,082,880 B).

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-94-103-1-13-20260423/stage4-obfuscated-class-list.png" | relative_url }}" alt="dnSpy Assembly Explorer view of the decrypted Stage-4 .NET assembly, showing its module tree with heavily obfuscated class names such as HQpmBSUELAUUTkvfFUDMffBkXlu, BIAefanEVukuBxcnUqBPQrZRaqIRILGzIOrWzffQLCNmnyIGK, and a dozen more generated-looking identifiers.">
  <figcaption><em>Figure 3: Decrypted Stage-4 .NET assembly in decompiler (dnSpy) Assembly Explorer. All class, method, and field names are renamed to generated-looking identifiers — a standard .NET string-obfuscation pattern consistent with a private crypter that does not aim to evade decompilation entirely, only to slow manual analysis.</em></figcaption>
</figure>

Its behaviors, in chronological order:

1. **Mutex establishment.** Creates a named mutex with the GUID `9f67b5ed-6c10-4c53-818b-8d26be0d1339`. This GUID is **identical across both builds** — a cross-build invariant and the highest-value hunting anchor produced by this investigation. Zero public hits prior to this publication.
2. **Console.Title self-locate.** Reads `$host.UI.RawUI.WindowTitle` (PowerShell) / `Console.Title` (.NET) to recover the dropper batch file's path. The value was seeded by the Stage-1 batch file (see 5.2). Stage 4 then calls `File.ReadLines(dropper_path).Last()` to re-read the last line of the batch file and verify it matches an expected hash — an implicit `.bat` execution guard. If the running process was started by any means other than the original batch file (e.g., a researcher detonating the decrypted Stage-4 PE directly), this check fails and Stage 4 exits.
3. **Payload staging.** Decompresses two internal resources (per-build names: `IazvXcueDgcoXWWL…` and `HxBTHTPGSMVbIZYM…` for mymain; `WxFRcVUEXpXaqKtl…` and `YEfOdElqPaWtqico…` for myfile) using the build's reused AES passphrase + reused XOR key + GZip. These decompress to Stage-5a (the Chaos ransomware) and Stage-5b (the UAC bypass).

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-94-103-1-13-20260423/stage4-embedded-resources.png" | relative_url }}" alt="dnSpy resource listing for the decrypted Stage-4 assembly showing two embedded resources: WxFRcVUEXpXaqKtlEAsEPXMbLojPupIDbXtnSnvqGuhCmEkgNMxYgJZyk at 11,856 bytes and YEfOdElqPaWtqicoMQkYFXLbzFsKebrGyBZYN at 983,872 bytes. Both are flagged as Embedded, Public.">
  <figcaption><em>Figure 4: Two Stage-4 embedded resources. Their sizes — 11,856 bytes and 983,872 bytes — match byte-for-byte between the mymain and myfile builds, establishing the first cross-build size invariant. After decryption, the 11,856-byte resource becomes Stage-5a (the Chaos ransomware, 25,088 bytes plaintext) and the 983,872-byte resource becomes Stage-5b (the UAC bypass PE, SHA256 `da302511…` — byte-identical across both builds).</em></figcaption>
</figure>

4. **Registry-blob persistence write.** Writes a ~1.4 MB encoded blob to `HKLM\Software\Microsoft Defender\Payload` (note: **NOT** `HKLM\Software\Microsoft\Windows Defender` — the masquerade path is deliberately adjacent to a legitimate Microsoft key to evade casual inspection). This blob contains the entire Stage-4 chain, ready to be re-run by a boot re-loader.
5. **Scheduled task installation.** Creates a scheduled task literally named `\Microsoft Defender` at the task-scheduler **root path** (not under `\Microsoft\Windows\Windows Defender`), with `Hidden = true`, `RunLevel = HIGHEST`, and a BOOT trigger. The task runs `cmd.exe` with a long command-line that reads the HKLM registry blob, decodes it, and re-executes the Stage-4 chain.
6. **Debug logfile write.** Writes to `C:\cmd_log.txt` from the boot re-loader stub — a developer debugging artifact that should not exist on a polished production build. Its presence is a hunting indicator on any host suspected to be post-reboot infected.
7. **Stage-5a and Stage-5b dispatch.** Loads Stage-5a (Chaos/TorBrowserTor ransomware) and Stage-5b (UACME #41 UAC bypass) via `Assembly.Load` on the decrypted byte arrays.

**Why the "Console.Title + File.ReadLines batch-line" trick matters.** This mechanism defeats manual researcher detonation of Stage-4 in isolation. It also defeats automated sandbox submission of the decrypted Stage-4 PE — a researcher who extracts the payload and uploads it to a sandbox will see the mutex, the resources, and nothing else. The chain will not self-extract because the console title is not seeded. Automated memory-dump collection platforms that preserve the original command-line context will still trigger it; isolated PE sandboxing will not.

**Why the Defender masquerade matters.** The dual anchor (task `\Microsoft Defender` at ROOT + `HKLM\Software\Microsoft Defender\Payload`) is the single most productive threat-hunt query we can offer. Real Microsoft Defender tasks live under `\Microsoft\Windows\Windows Defender` and its registry key is `HKLM\Software\Microsoft\Windows Defender`. The masquerade path is **adjacent but not identical** — a defender who does not know the real path by heart will let it pass. Any Sysmon-EID-12/13-capable SIEM can trivially hunt for the masquerade pair.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-94-103-1-13-20260423/stage4-defender-persistence-reloader.png" | relative_url }}" alt="Deobfuscated PowerShell arg-blob reloader showing a chain of Replace-based DOSfuscation tokens and a visible hardcoded registry path HKLM:\\Software\\Microsoft Defender and Payload value name, alongside a cmd_log.txt redirect target at the bottom.">
  <figcaption><em>Figure 5: The Stage-4 arg-blob reloader, deobfuscated from its outer Replace-chain DOSfuscation. Visible in plaintext: the Defender-masquerade persistence path `HKLM:\Software\Microsoft Defender` with value name `Payload`, and the reloader's debug-output file `C:\cmd_log.txt`. The reloader reads the registry blob on every boot, decodes it, and re-executes the full loader chain — the fileless persistence mechanism documented in this section.</em></figcaption>
</figure>

### 5.6 Stage 5a — Chaos/TorBrowserTor Ransomware Payload

> **Analyst note:** Stage 5a is the commodity Chaos/TorBrowserTor ransomware. It encrypts files with **Rijndael (256-bit key, CFB mode — denoted `Rijndael-256` throughout this report; refers to the 256-bit key size, not a 256-bit block size)**, wraps the per-file key with RSA-2048 OAEP, appends `.torbrowsertor` to every encrypted filename, drops `READ ME PLEASE.txt` as the ransom note, deletes shadow copies and backups, installs clipboard-hijacking for bech32 and P2PKH Bitcoin addresses, and spreads to any attached USB drive. This section documents behaviors defenders should detect in memory or at runtime — not in the `.bat` file on disk.

Stage-5a is a 25 KB .NET console application (25,088 bytes plaintext). Per-build hashes: mymain `06f6df0f…`, myfile `13665bd2…`. Both decompile to source that is line-number-identical at major class boundaries (`namespace ConsoleApplication7` line 1, `internal class Program` line 18, `NativeMethods` line 790, `driveNotification` class) — a source-code-level builder template identity.

Core behaviors:

- **File encryption.** Walks `%USERPROFILE%\Desktop`, `%USERPROFILE%\Documents`, `%USERPROFILE%\Downloads`, `%USERPROFILE%\Pictures`, `%USERPROFILE%\Music`, `%USERPROFILE%\Videos`, all removable drives, and all non-system fixed drives. Skips files over 2 GB (builder default). For each targeted file: generates a random per-file 32-byte key, encrypts file contents with Rijndael-256 CFB using that key, encrypts the per-file key with a hard-coded RSA-2048 OAEP public key, appends the RSA-encrypted key to the ciphertext, renames the file with `.torbrowsertor` appended.
- **Ransom note drop.** Writes `READ ME PLEASE.txt` to every directory that contains an encrypted file, plus the Desktop. Contains the `@TorBrowserTor` Telegram handle and the two Chaos-builder-default BTC wallets.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-94-103-1-13-20260423/stage5a-ransom-messages-telegram.png" | relative_url }}" alt="Decompiled Stage-5a source showing a private static List of strings named 'messages' with a hard-coded ransom text block: 'Hello!', 'I have encrypted all the server data :)', 'It is IMPOSSIBLE to decrypt it without me!', 'To decrypt the data, contact me on Telegram — @TorBrowserTor', 'I can decrypt 1-2 files as a test so you can be sure of my competence.'">
  <figcaption><em>Figure 6: Hard-coded Stage-5a ransom messages including the `@TorBrowserTor` Telegram handle. This string is what brands the variant: "TorBrowserTor" is the builder-configuration label used across this Chaos v4/v5 variant family. Like the BTC wallets, it is a builder-default attribution anchor (HIGH family-level identification, LOW operator-attribution value).</em></figcaption>
</figure>

- **Shadow copy / backup destruction.** Issues `vssadmin delete shadows /all /quiet`, `wmic shadowcopy delete`, `bcdedit /set {default} bootstatuspolicy ignoreallfailures`, `bcdedit /set {default} recoveryenabled no`, and `wbadmin delete catalog -quiet` — the canonical Chaos VSS-kill sequence.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-94-103-1-13-20260423/stage5a-anti-recovery-flags.png" | relative_url }}" alt="Decompiled Stage-5a C# source excerpt from decompiler (dnSpy) showing nested if-blocks gated on Program.checkAdminPrivilage. Inside the admin branch, individual sub-flags gate calls to Program.deleteShadowCopies, Program.disableRecoveryMode, Program.deleteBackupCatalog, and Program.DisableTaskManager.">
  <figcaption><em>Figure 7: Admin-gated anti-recovery sequence in Stage-5a source. Each destructive action (`deleteShadowCopies`, `disableRecoveryMode`, `deleteBackupCatalog`, `DisableTaskManager`) is individually toggleable via builder-set flags — the operator can choose which recovery paths to destroy per campaign. In this build all four flags are set to true.</em></figcaption>
</figure>

- **Clipboard hijacker (`driveNotification` class).** Registers a `WM_CLIPBOARDUPDATE` listener. On any clipboard change, applies bech32 and P2PKH Bitcoin regex patterns to the new clipboard content; if matched, replaces the content with one of the two builder-default wallets.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-94-103-1-13-20260423/stage5a-clipboard-hijacker-wndproc.png" | relative_url }}" alt="Decompiled Stage-5a WndProc override showing the m.Msg equality check against constant 797 (the WM_CLIPBOARDUPDATE Windows message code, 0x031D). On match, the handler reads the current clipboard text via driveNotification.NotificationForm.GetText, applies regex replacements keyed on Program.appMutexRun and Program.appMutexStartup, and writes the modified text back via SetText2.">
  <figcaption><em>Figure 8: Clipboard-hijacker `WndProc` handler in Stage-5a's `driveNotification` nested class. `m.Msg == 797` (`WM_CLIPBOARDUPDATE` = `0x031D`) triggers on every clipboard change; the handler tests the new content against bech32 and P2PKH Bitcoin regexes and replaces matches with one of the two builder-default wallets. This runs silently on every paste on an infected host.</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-94-103-1-13-20260423/stage5a-builder-default-btc-wallets.png" | relative_url }}" alt="Decompiled Stage-5a C# source excerpt showing four string field declarations: appMutexRun set to '7z459ajrk722yn8c5j4fg', appMutexRun2 set to '2X28tfRmWaPyPQgvoHV', appMutexStartup set to '1qw0ll8p9m8uezhqhyd', and appMutexStartup2 set to '17CqMQFeuB3NTzJ'. A fifth field droppedMessageTextbox is set to 'READ ME PLEASE.txt'.">
  <figcaption><em>Figure 9: Hard-coded BTC wallet strings in Stage-5a (misnamed as mutex fields — a Chaos builder quirk). The four segments `7z459ajrk722yn8c5j4fg`, `2X28tfRmWaPyPQgvoHV`, `1qw0ll8p9m8uezhqhyd`, `17CqMQFeuB3NTzJ` reconstruct the two full BTC wallets `bc1qw0ll8p9m8uezhqhyd7z459ajrk722yn8c5j4fg` and `17CqMQFeuB3NTzJ2X28tfRmWaPyPQgvoHV` that the clipboard hijacker above substitutes. WalletExplorer cross-references confirm both are Chaos builder-defaults reused across unrelated operators — LOW operator-attribution value.</em></figcaption>
</figure>

- **USB spread.** Listens for `WM_DEVICECHANGE` events. On a new removable drive insertion, copies the Stage-5a binary to the drive root as `surprise.exe` (mymain) or `Recieve please.exe` (myfile), plus a small autorun helper file.
- **HKCU Run persistence.** Writes the self-copy path to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Microsoft Store` (note the legitimate-sounding value name — another masquerade).
- **DisableTaskMgr.** Sets `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr = 1` to frustrate victim process termination attempts.
- **Self-copy.** Copies itself to `%APPDATA%\svchost.exe` (mymain) or `%APPDATA%\projectxx.exe` (myfile) before starting the encryption loop.

Per-build variation (useful for hunting):

| Attribute | mymain | myfile |
|---|---|---|
| Stage-5a self-copy | `%APPDATA%\svchost.exe` | `%APPDATA%\projectxx.exe` |
| USB-spread filename | `surprise.exe` | `Recieve please.exe` |
| Stage-5a assembly name | (compiled `ConsoleApplication7`) | `fudkk` |
| Stage-4 Stage-5a resource | `IazvXcueDgcoXWWL…` | `WxFRcVUEXpXaqKtl…` |
| Stage-4 Stage-5b resource | `HxBTHTPGSMVbIZYM…` | `YEfOdElqPaWtqico…` |

### 5.7 Stage 5b — UACME #41 AppInfo RPC UAC Bypass

> **Analyst note:** Stage 5b is the step that turns a regular user session into a full Administrator session without triggering the UAC consent dialog. It uses technique #41 from the open-source UACME catalogue — a specific RPC call against Windows's AppInfo service (`AiEnableDesktopRpcInterface`) combined with a trick called "parent-PID spoofing" that makes the newly elevated process appear to be a child of an already-elevated `taskmgr.exe`. The specific compiled PE this operator ships is byte-identical across both builds and has an 8/77 VT detection gap.

Stage-5b is a ~986 KB .NET assembly (1,009,664 bytes). SHA256 `da302511ee77a4bb9371387ac9932e6431003c9c597ecbe0fd50364f4d7831a8` — **byte-identical** across both builds (mymain and myfile ship the same compiled bytes). VT at analysis time: 8/77.

The technique (UACME #41 — see hfiref0x UACME repository, B1):

1. **Locate an already-elevated process.** The module enumerates processes looking for `taskmgr.exe` running at integrity level HIGH. If not found, it uses `ShellExecute` with the `runas` verb on `taskmgr.exe` (which triggers a single consent prompt that can be auto-accepted in some configurations, or waits for a predictable user pattern).
2. **Obtain the AppInfo RPC interface.** Loads `NtApiDotNet` (bundled in the assembly) and calls `AiEnableDesktopRpcInterface` on the AppInfo service. This interface is normally reserved for Windows internal use; once enabled, it exposes the `IColorDataProxy` COM object.
3. **Invoke `IColorDataProxy` via the elevated taskmgr's RPC context.** Because the RPC call is made through the already-elevated taskmgr process's token, the resulting COM activation runs at elevated integrity.
4. **Parent-PID spoof via `CreateProcess` with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`.** Sets the parent PID to the elevated taskmgr.exe's PID, so the newly spawned process inherits taskmgr's elevated token. The command executed is typically `conhost.exe --headless cmd.exe /c [path to Stage-4 re-invocation]`.
5. **Result.** A high-integrity cmd.exe (or subsequent process) running with the operator's code — full UAC bypass, no consent prompt, no security event log entry for standard UAC elevation.

**Cross-cutting detection tells:**
- `conhost.exe --headless cmd.exe /c [path]` spawned as a child of `taskmgr.exe` running at integrity HIGH.
- `notepad.exe` launched at elevated integrity with no visible window, immediately followed by a high-integrity `cmd.exe` spawn (a variant chain the bypass sometimes uses as a staging step).
- Any process whose parent PID points to an elevated `taskmgr.exe` but whose image path is not in `System32`.

**Why the 8/77 VT detection gap matters.** Most vendors detect the generic AppInfo RPC bypass family, but this specific compiled PE — byte-identical across both observed builds — is under-detected. For defenders, the SHA256 `da302511…` is the single most productive file hash to hunt. A match confirms infection with extremely low false-positive risk because the hash is specific to this operator's pre-compiled bypass module.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-94-103-1-13-20260423/stage5b-decryption-sha256-proof.png" | relative_url }}" alt="FLARE-VM PowerShell console output from the Stage-5 decryption script showing two sequential invocations. The second invocation decrypts stage4_resource_HxBTHTPGSMVbIZYM.gz into stage5b_payload and reports Plaintext SHA256 da302511ee77a4bb9371387ac9932e6431003c9c597ecbe0fd50364f4d7831a8, Plaintext size 1,009,664 bytes, first 8 bytes 4d5a9000... (the PE MZ magic), with Assembly check PE/MZ detected.">
  <figcaption><em>Figure 10: FLARE-VM Stage-5 decryption output establishing the Stage-5b SHA256 `da302511…` — byte-identical across both mymain and myfile builds. The screenshot captures the single most productive hunting anchor in this report: any file on a victim endpoint with this SHA256 confirms UTA-2026-005 infection with effectively zero false-positive risk (the 1,009,664-byte UAC bypass PE is specific to this operator's pre-compiled module).</em></figcaption>
</figure>

### 5.8 Supporting Toolkit: Orcus RAT v7, Privilege Escalation Chain, Tunneling Stack

> **Analyst note:** The open directory contained a supporting toolkit the operator stages for post-compromise: a RAT for remote control, a chain of privilege escalation tools for obtaining SYSTEM-level access, Mimikatz for credential dumping, and a tunneling stack that hides the real command-and-control address behind a local loopback port. These components are not novel individually, but their combination in a single kit is operationally significant.

#### 5.8.1 Orcus RAT v7 (Wardow Crack)

- File: `myfile.exe`, SHA256 `f7a4fe18d838e9d87db2db6378ffb21b90c3881d28d70871b8c2a661c6a78a6a`, 865 KB .NET.
- Costura.Fody bundled (see Section 4). Embedded modules include `Orcus.Service` (the client), `IServicePipe` (the IPC interface), and the full RAT capability graph.
- Capabilities present: keylogging (via `SetWindowsHookEx` WH_KEYBOARD_LL), screen capture, file upload/download, arbitrary process spawn, clipboard access, registry manipulation.
- **Installation target:** `%APPDATA%\Microsoft\Speech\AudioDriver.exe` (masquerading as a Windows Speech component).
- **Persistence:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Audio HD Driver` + scheduled task `Audio HD Driver`.
- **C2 endpoint:** `127.0.0.1:20268` (loopback). The real upstream is hidden behind a chisel or plink tunnel established separately; the upstream endpoint is **UNKNOWN** from static analysis.
- **Wardow-crack identifiers:** AES key `CrackedByWardow`, fixed IV `0sjufcjbsoyzube6`, keyleak backdoor file `e3c6cefd462d48f0b30a5ebcd238b5b1`.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-94-103-1-13-20260423/orcus-wardow-crack-key.png" | relative_url }}" alt="Decompiled Orcus source showing a single line: 'public static string ENCRYPTIONKEY = \"CrackedByWardow\";' at token 0x040002C2. The string is clearly legible and comments above show it is a static string field.">
  <figcaption><em>Figure 11: The hard-coded `ENCRYPTIONKEY = "CrackedByWardow"` string in the Orcus RAT Settings class. This string is a definitive identifier of the Wardow crack of Orcus v7 — the public-crack community tags each release with the cracker's handle in this field. A defender hunting for Orcus-Wardow specifically can YARA-match this exact string.</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-94-103-1-13-20260423/orcus-wardow-keyleak-backdoor.png" | relative_url }}" alt="Decompiled Orcus Initialize method source showing an if-block: if File.Exists combining Path.GetTempPath and a 32-character hex filename e3c6cefd462d48f0b30a5ebcd238b5b1, the code calls File.WriteAllText with the same path and Settings.ENCRYPTIONKEY as the text content.">
  <figcaption><em>Figure 12: The Wardow-crack key-leak backdoor. On every Orcus startup, this routine writes the operator's encryption key to `%TEMP%\e3c6cefd462d48f0b30a5ebcd238b5b1` in plaintext. This is a well-known community backdoor Wardow shipped in the cracked builder — any operator who uses the Wardow crack is unknowingly leaking their own key to any party that can read `%TEMP%`. It is not a defensive feature; it is a backdoor against the operator by the cracker. Detection: any Orcus infection will leave this file on disk, so hunting `%TEMP%\e3c6cefd462d48f0b30a5ebcd238b5b1` is a reliable on-disk anchor.</em></figcaption>
</figure>

- **Mutex:** `b12f3970cc224d0eb98b4030f9c2e753`.

**Offline config decryption.** The Wardow-crack key leak combines with three inherent weaknesses in the Orcus config-encryption routine — a shared single-key symmetric mode, a deterministic KDF, and a hard-coded IV — to enable fully offline recovery of the configuration without ever detonating the sample.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-94-103-1-13-20260423/orcus-rijndael-cbc-crypto-class.png" | relative_url }}" alt="Decompiled Orcus EncryptToBytes method source showing construction of a RijndaelManaged instance with CipherMode.CBC, a call to new PasswordDeriveBytes(passPhrase, null).GetBytes(32) for key derivation, and rijndaelManaged.CreateEncryptor(bytes2, AES.initVectorBytes) for the encryptor — passing a hardcoded IV from AES.initVectorBytes.">
  <figcaption><em>Figure 13: Orcus config-encryption routine. Three weaknesses chained together enable offline decryption of any Orcus-Wardow config: (a) `RijndaelManaged` with `CipherMode.CBC` (single-key symmetric, recoverable from sample), (b) `PasswordDeriveBytes(passPhrase, null)` — the `null` salt parameter is the decisive flaw, reducing the KDF to a deterministic function of the passphrase alone, and (c) a hard-coded IV from `AES.initVectorBytes`. Combined with the Wardow-leaked key (Figure 12) these three let an analyst produce `myfile_decrypted_config.txt` without detonating the sample.</em></figcaption>
</figure>

#### 5.8.2 Privilege Escalation Chain

The open directory staged multiple privesc primitives, layered so that at least one succeeds on most Windows 10/11 builds:

- `p.exe` (SHA256 `b9ffbeed…`) — custom 6.6 KB .NET PrintSpoofer-class SpoolSS coercion + named-pipe impersonation. Compiled 2026-03-31 17:00:09 UTC. Novel in the sense that the operator compiled their own rather than using the public PrintSpoofer binary — suggests operational preference for signature-deviation.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-94-103-1-13-20260423/p-exe-custom-printspoofer.png" | relative_url }}" alt="Decompiled p.exe source showing the PrintSpoofer-class coercion routine: construction of a random pipe path '\\.\pipe\testNNNN/pipe/spoolss', a Potato.CreateNamedPipe call, then a threaded Potato.OpenPrinter call that issues '[*] Triggering SpoolSS on ' + hostname. The command to execute is sourced from args or defaults to whoami.">
  <figcaption><em>Figure 14: Custom `p.exe` PrintSpoofer-class source — operator-compiled 2026-03-31, 6.6 KB .NET x64. The core sequence (`CreateNamedPipe` → trigger SpoolSS coercion over `/pipe/spoolss` → `ImpersonateNamedPipeClient` → SYSTEM token) matches public PrintSpoofer, but the self-compiled binary produces a different hash than the public version, which is why operators bother to recompile. VT submission would show a `Backdoor.MSIL` heuristic flag — a known false-positive pattern for .NET token-manipulation tools.</em></figcaption>
</figure>
- `gp_obf.exe` (SHA256 `38c5737b…`) — obfuscated GodPotato variant (internal name `SvcUtil.exe`, compiled 2026-04-02).
- Additional GodPotato variants (multiple compiled copies in the directory).
- Public PrintSpoofer binary (unmodified).
- PrintNightmare tooling including the signed `mimispool.dll` (CVE-2021-1675 / CVE-2021-34527).
- Full Mimikatz suite (`mimikatz.exe`, `mimilib.dll`, `mimidrv.sys`, `mimispool.dll`).

**Layered logic:** the operator tries each in sequence. Any success yields SYSTEM. The combination dramatically raises the probability that at least one primitive works against a patched-but-not-fully-current endpoint.

#### 5.8.3 Tunneling Stack

- `chisel.exe` — a TCP-over-HTTP tunnel tool. Listens locally and forwards to a remote chisel server.
- `plink.exe` — PuTTY's command-line SSH client, used as a secondary tunnel option.
- Python stub scripts — lightweight tunnel-runners for the same purpose.

The Orcus RAT connects to `127.0.0.1:20268`. That port is one end of a chisel or plink tunnel whose external egress is hidden. The real operator C2 endpoint is UNKNOWN from static analysis; recovering it requires dynamic detonation with egress capture — a gap carried into this report.

---

## 6. MITRE ATT&CK Mapping

> **Analyst note:** The table below maps observed behaviors to MITRE ATT&CK techniques. Only techniques with HIGH or DEFINITE confidence are included. The private-crypter chain heavily exercises Defense Evasion (TA0005), Persistence (TA0003), and Privilege Escalation (TA0004) tactics; the ransomware payload adds Impact (TA0040).

| Tactic / Technique | Name | Conf. | Evidence |
|---|---|---|---|
| Execution / T1059.003 | Windows Command Shell | HIGH | Batch dropper `mymain.bat` / `myfile.bat` |
| Execution / T1059.001 | PowerShell | HIGH | Forced 32-bit `SysWOW64\WindowsPowerShell` invocation |
| Execution / T1620 | Reflective Code Loading | HIGH | `[System.Reflection.Assembly]::Load([byte[]])` in PS1 loader |
| Defense Evasion / T1027 | Obfuscated Files or Information | HIGH | DOSfuscation + alphabet-substitution Base64 |
| Defense Evasion / T1027.011 | Fileless Storage | DEFINITE | `HKLM\Software\Microsoft Defender\Payload` blob |
| Defense Evasion / T1027.007 | Dynamic API Resolution | HIGH | Stage-4 NtApiDotNet dynamic imports |
| Defense Evasion / T1140 | Deobfuscate/Decode Files | DEFINITE | AES-ECB + XOR + GZip layered decryption |
| Defense Evasion / T1497.001 | Sandbox Evasion: System Checks | HIGH | 12-DLL al-khaser sweep |
| Defense Evasion / T1497 | Virtualization/Sandbox Evasion | HIGH | Tri-artifact gate (`admin` + `VBE\` + `mapping.csv`) |
| Defense Evasion / T1562.001 | Disable or Modify Tools | DEFINITE | AMSI + ETW patch, ntdll unhook, `DisableTaskMgr=1` |
| Defense Evasion / T1036.005 | Match Legitimate Name or Location | HIGH | `\Microsoft Defender` task + `AudioDriver.exe` + `svchost.exe` |
| Defense Evasion / T1564.003 | Hidden Window / Hidden Task | HIGH | Task `Hidden = true`; PS `-WindowStyle Hidden` |
| Persistence / T1053.005 | Scheduled Task | DEFINITE | Task `\Microsoft Defender` with BOOT trigger |
| Persistence / T1112 | Modify Registry | DEFINITE | `HKLM\Software\Microsoft Defender\Payload` blob |
| Persistence / T1547.001 | Registry Run Keys | HIGH | `…\Run\Microsoft Store` + `…\Run\Audio HD Driver` |
| Privilege Escalation / T1548.002 | Bypass UAC | DEFINITE | Stage-5b UACME #41 AppInfo RPC + PPID spoof |
| Privilege Escalation / T1134.004 | Parent PID Spoofing | DEFINITE | `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` off taskmgr.exe |
| Privilege Escalation / T1068 | Exploitation for Privilege Escalation | HIGH | PrintNightmare `mimispool.dll` + Potato family |
| Privilege Escalation / T1134.001 | Token Impersonation/Theft | HIGH | `p.exe` named-pipe impersonation |
| Privilege Escalation / T1134.002 | Create Process with Token | HIGH | Post-impersonation `CreateProcessWithTokenW` |
| Credential Access / T1003.001 | LSASS Memory | HIGH | Mimikatz suite staged |
| Discovery / T1046 | Network Service Discovery | HIGH | Parallel-campaign exploit scripts probe services |
| Collection / T1056.001 | Keylogging | HIGH | Orcus `SetWindowsHookEx` WH_KEYBOARD_LL |
| Collection / T1113 | Screen Capture | HIGH | Orcus screen-capture capability |
| Command and Control / T1071.001 | Web Protocols | HIGH | Orcus HTTP traffic over tunnel |
| Command and Control / T1573 | Encrypted Channel | HIGH | Orcus Rijndael-256 CBC channel |
| Command and Control / T1572 | Protocol Tunneling | HIGH | chisel / plink / Python tunnel stack |
| Command and Control / T1090.001 | Internal Proxy | HIGH | Orcus `127.0.0.1:20268` loopback front |
| Resource Development / T1583.003 | Virtual Private Server | HIGH | AS209207 VPS for staging |
| Initial Access / T1190 | Exploit Public-Facing Application | HIGH | Exim / SnipeIT / SIP PBX scripts (parallel campaign) |
| Lateral Movement / T1091 | Replication Through Removable Media | HIGH | USB-spread `surprise.exe` / `Recieve please.exe` |
| Impact / T1486 | Data Encrypted for Impact | DEFINITE | Rijndael-256 CFB, `.torbrowsertor` extension |
| Impact / T1490 | Inhibit System Recovery | DEFINITE | `vssadmin` + `wmic shadowcopy` + `bcdedit` + `wbadmin` |
| Impact / T1491.001 | Internal Defacement | HIGH | `READ ME PLEASE.txt` ransom note drop |
| Impact / T1657 | Financial Theft | HIGH | BTC clipboard hijacker (`driveNotification` class) |

*Confidence levels follow the DEFINITE / HIGH / MODERATE / LOW / INSUFFICIENT scale. Low-confidence techniques are omitted from this table pending deeper analysis.*

---

## 7. Threat Actor Assessment

> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-2026-005 is an internal tracking designation assigned by The Hunters Ledger to actors observed across analysis who cannot yet be linked to a publicly named threat group. This label will not appear in external threat intelligence feeds or vendor reports — it is specific to this publication. If future evidence links this activity to a known named actor, the designation will be retired and updated accordingly.

### 7.1 Attribution Conclusion

**Named-actor attribution: INSUFFICIENT (0%).** Zero infrastructure overlaps, zero named-actor TTP matches, zero Tier-1/Tier-2 vendor attributions. Cannot attribute to any publicly named threat actor on the basis of currently available evidence.

**Family-level identification: DEFINITE (97%).** Chaos ransomware builder (2021-origin, v1–v5 lineage), configured as the TorBrowserTor variant. This is a family-level identification, not an actor attribution — the Chaos builder is publicly available and shared by many unrelated operators.

**Operator-level tracking: UTA-2026-005.** Distinctive trackable operator cluster based on a private five-stage crypter with cross-layer key reuse, a cross-build mutex GUID invariant, a byte-identical Stage-5b UAC bypass PE, and a tri-artifact anti-sandbox gate. See [UTA-2026-005.md](/threat-actors/UTA-2026-005/) for the full fingerprint record.

### 7.2 Chaos Builder vs Chaos RaaS Group (2025) — Mandatory Disambiguation

> **Critical distinction — do not conflate these two:** The 2021-origin Chaos ransomware *builder* (from which our sample was built) is **distinct** from the 2025 Cisco Talos-reported "Chaos RaaS group." The builder is an open-source tool that has been used by many unrelated operators since 2021. The "Chaos RaaS group" is a specific named actor Talos reported as active from February 2025 onward, operating a *distinct codebase* with distinct TTPs. Talos explicitly distinguishes the two in its reporting. Our sample is a build of the 2021-origin builder (configured as the TorBrowserTor variant) — it is NOT an artifact of the Talos-named RaaS actor. Readers searching for "Chaos ransomware" will surface Talos's RaaS reporting and may conflate the two; they should not.

This distinction is load-bearing for several reasons:

- **Different codebase.** Talos's Chaos RaaS group uses a distinct codebase that does not share the `ConsoleApplication7` namespace, the `driveNotification` class, or the Rijndael-256 CFB + RSA-2048 OAEP encryption pipeline that our sample implements.
- **Different TTPs.** Talos's group is reported in an affiliate RaaS model with specific entry patterns (compromised RMM, phishing-to-Cobalt-Strike pipelines) that do not appear in the evidence we recovered from 94.103.1.13.
- **Different operator profile.** Our operator (UTA-2026-005) runs a private crypter and a pre-production multi-campaign open directory; Talos's group operates an affiliate program with a different infrastructure pattern.
- **Same family name, different actors.** Just as "Mimikatz" identifies a tool used by many actors (not a single actor), "Chaos" identifies a ransomware family used by many actors. Confusing family with actor is a common attribution error this blockquote exists to prevent.

H2 (the hypothesis that UTA-2026-005 is the Talos-named Chaos RaaS group) is therefore **explicitly ruled out** in our hypothesis analysis below.

### 7.3 Alternative Hypothesis Analysis (ACH)

We evaluated three hypotheses for the actor behind this activity:

- **H1 (WINNER): Unattributed financially-motivated operator using the public Chaos builder with a private custom crypter.** Best fit for the evidence: private crypter with operator-specific builder fingerprints, commodity Chaos core, shared-default wallets and Telegram contact, broad-spectrum opportunistic targeting with financial motivation, no Tier-1/Tier-2 named-actor matches.
- **H2 (RULED OUT): 2025 Talos Chaos RaaS group.** Ruled out on codebase grounds — Talos explicitly distinguishes the RaaS actor from the builder lineage, and no RaaS-specific TTPs (RMM compromise, affiliate indicators, specific phishing patterns) appear in our evidence.
- **H3 (RUNNER-UP): False flag — another actor mimicking Chaos builder defaults.** Plausible but unnecessary: the Chaos builder is freely available, so genuine use by a new operator is a simpler explanation than false-flag mimicry. Occam's Razor favors H1.

Winner: **H1 (Unattributed financially-motivated operator)**, confidence MODERATE on the hypothesis itself, HIGH on the ruling-out of H2.

### 7.4 Key Operator Fingerprints (Hunting Anchors)

These are the evidence points the UTA-2026-005 cluster is built on. Any future sample matching one or more of these strengthens the cluster and should be tagged UTA-2026-005 on sight.

| Anchor | Type | Strength |
|---|---|---|
| Mutex GUID `9f67b5ed-6c10-4c53-818b-8d26be0d1339` | Cross-build invariant | HIGHEST (zero public hits) |
| Stage-5b SHA256 `da302511ee77a4bb9371387ac9932e6431003c9c597ecbe0fd50364f4d7831a8` | Cross-build PE invariant | HIGHEST (zero public hits, 8/77 VT) |
| Cross-layer AES passphrase + XOR key reuse pattern | Builder fingerprint | HIGH |
| Tri-artifact gate (`admin` + `%TEMP%\VBE\` + `%TEMP%\mapping.csv`) | Builder + operator fingerprint | HIGH |
| Magic markers (`aEVMeKDApIQzumcyjwpFSfqzEImqRdPQ` / `HPGDxAzpymskcRJvELNmhQkWaTXguERQ`) | Per-build chunk delimiters | MODERATE (per-build only) |
| Defender-masquerade persistence pair (`\Microsoft Defender` task + `HKLM\Software\Microsoft Defender\Payload`) | Cross-build behavioral | HIGH |
| `C:\cmd_log.txt` developer debug artifact | Operator debug signature | MODERATE |

**Not operator fingerprints** (family-level defaults, ignore for attribution):
- BTC wallets `bc1qw0ll8p9m8uezhqhyd7z459ajrk722yn8c5j4fg` and `17CqMQFeuB3NTzJ2X28tfRmWaPyPQgvoHV` — Chaos builder defaults, LOW attribution value
- Telegram handle `@TorBrowserTor` — Chaos builder default for this variant, LOW attribution value
- `.torbrowsertor` extension — variant identifier, LOW attribution value
- `ConsoleApplication7` namespace — Chaos builder template artefact, LOW attribution value

### 7.5 Operator Infrastructure

- **Staging server: 94.103.1.13** (AS209207, Russia-registered, Albania-routed via AS48014). HIGH confidence operator-controlled based on open-directory contents aligning with the loader chain. AbuseIPDB: 0 reports, 0% confidence (manual browser fetch, 2026-04-23) — operator is under community-reporting radar. VT 5/94 (session 8).
- **Real Orcus C2: UNKNOWN.** Hidden behind `127.0.0.1:20268` loopback + chisel/plink tunnel. Dynamic egress analysis required.
- **Multi-tenant operator host.** 94.103.1.13 concurrently serves at least three parallel parasitic campaigns alongside the Chaos distribution: `forumrutor24.com` (Russian forum theme, 34 days active), `gtanuncios.com` (aged 10-year classifieds domain acquired from a CN reseller, pivoted 2026-04-11), and `bulgainme.pro` (short-lived `.pro` with webmail). All three use Cloudflare fronting + mixed registrars + aged-domain-purchase tradecraft — see Section 4 Infrastructure Context subsection for full breakdown. This reframes the operator from a single-campaign Chaos distributor to a **multi-campaign operator** running parallel monetization paths on the same infrastructure.
- **Historical operator rotation evidence.** `slayer.ktx.ro` resolved to 94.103.1.13 on 2025-12-18–19 (brief 36-minute burst, 8 resolutions) — the IP has been in operator rotation approximately four months before the Chaos campaign, establishing a months-long cadence for operator activity on this host.
- **Possible secondary: 172.86.76.198.** LOW confidence operator-controlled; observed in tunnel-script artifacts but role is ambiguous. Could be a relay, a staging host, or an unrelated pivot point — evidence is not strong enough to mark HIGH.
- **Reseller-inventory identity (NOT operator attribution).** Pre-masking WHOIS for `gtanuncios.com` recorded registrant `xiang xiang fan`, email `lc1393353@gmail.com`, phone `+86 130 3255 6442`, city `lin fen` (Linfen, Shanxi, China). The ten-month dormant hold between domain transfer (2025-06-28) and operator pivot (2026-04-11) is consistent with CN domain-broker inventory rather than direct operator identity. This identity is **tracked in UTA-2026-005** for future cross-campaign correlation but does NOT elevate attribution above INSUFFICIENT.
- **Bulletproof classification: SUSPECTED.** AS209207 is 3 months old (allocated 2026-01-19), Russia-registered, Albania-routed through a single upstream (AS48014 AlbaHost) with historical bogon announcements. The ASN's self-domain `dhost.su` uses a `.su` TLD typical of operator-friendly Russian-speaking hosting providers. Profile is consistent with bulletproof-adjacent hosting, but no named-BPH-database entry was located at the time of this writing.

### 7.6 Gaps That Would Strengthen or Resolve Attribution

- A second sample containing the Stage-5b SHA256 `da302511…` or the mutex GUID `9f67b5ed-…` would permit high-confidence cross-campaign clustering.
- A new build exhibiting the same cross-layer AES + XOR key-reuse pattern (any new passphrase/key pair reused at three crypter layers) would confirm the private crypter is a persistent builder (raising UTA-2026-005 confidence from MODERATE to HIGH).
- Dynamic detonation capturing the real Orcus C2 endpoint behind `127.0.0.1:20268` would provide the first infrastructure pivot beyond the staging server.
- Reappearance of the co-tenant triad (`forumrutor24.com`, `gtanuncios.com`, `bulgainme.pro`) on a different operator IP alongside Chaos-lineage samples would establish UTA-2026-005 continuity across infrastructure rotation.
- Reappearance of the `xiang xiang fan` / `lc1393353@gmail.com` reseller-inventory identity on another aged-domain acquisition that subsequently pivots to operator infrastructure would elevate the "CN-broker-preference" signal from LOW to MODERATE.
- Any language, locale, or developer-environment artifact in future decompiled builds would reduce geographic-attribution gaps.
- A second open directory with overlapping scripts or overlapping tri-artifact gate coverage would strengthen the cluster.

### 7.7 Confidence Summary

Consolidated view of every major analytical claim in this report with its confidence level and evidence basis. Readers using this report for decision-making should weight each claim by its confidence level, not treat them as uniform fact.

| Claim | Confidence | Evidence Basis |
|---|---|---|
| Chaos ransomware builder family (TorBrowserTor variant, v4/v5 lineage) | **DEFINITE (97%)** | 14 of 14 canonical Chaos v4/v5 feature-set matches in decompiled Stage-5a; byte-identical Stage-5b module across two builds; builder-default BTC wallets confirmed via WalletExplorer clustering |
| UTA-2026-005 is a single operator cluster | **MODERATE (72%)** | Six distinctive characteristics (five technical, one infrastructure) reach B2 Admiralty threshold; cannot rule out tightly-cooperating operator duo sharing tooling |
| Named-actor attribution | **INSUFFICIENT (0%)** | Zero infrastructure overlaps with named actor clusters, zero Tier-1/Tier-2 vendor attributions, zero named-actor TTP matches |
| 2025 Talos "Chaos RaaS group" — this activity | **RULED OUT** | Talos explicitly distinguishes the 2025 RaaS actor from the 2021-origin Chaos builder lineage; our sample is builder-variant, wrong codebase |
| 94.103.1.13 is operator-controlled staging server | **HIGH** | Open directory contents directly align with loader chain artifacts (`t.ps1`/`t2.ps1`/`potato.ps1` hardcode this IP); multi-tenant co-tenancy pattern consistent with operator rotation |
| 94.103.1.13 is bulletproof-hosting-adjacent | **SUSPECTED (not CONFIRMED)** | AS209207 is 3 months old, Russia-registered, single-upstream via AS48014 AlbaHost (historical bogon announcements), `.su` TLD self-domain; but no named-BPH-database entry located |
| AbuseIPDB clean (0/0 reports) | **DEFINITE** | Manual browser fetch 2026-04-23 |
| Multi-tenant operator host with concurrent campaigns | **HIGH** | DomainTools Iris pDNS 2026-04-23: three concurrent active co-tenants + one historical (slayer.ktx.ro Dec 2025), consistent Cloudflare fronting + mixed registrars + aged-domain-purchase tradecraft across all three active domains |
| `xiang xiang fan` / `lc1393353@gmail.com` / Linfen CN is operator identity | **LOW** | Most plausibly a CN domain-reseller inventory identity (10-month dormant hold between acquisition and operator pivot is documented aged-domain-purchase tradecraft); tracked as signal, NOT elevated to attribution |
| Cross-layer AES+XOR key reuse is a private-crypter builder fingerprint | **HIGH** | Two builds show the same intra-build key-reuse pattern with per-build rotation; no located public reporting of this combined transformation stack |
| Stage-4 mutex GUID `9f67b5ed-…` and Stage-5b SHA256 `da302511…` are high-value hunting anchors | **DEFINITE** | Both cross-build invariants directly observed; zero prior public hits on each |
| Tri-artifact gate is operator-convenience check | **MODERATE (70%)** | More parsimonious than decoy hypothesis given operator must maintain tools; cannot rule out decoy |
| Wardow-Orcus crack identity | **MODERATE (community-known, not vendor-sourced)** | No Tier-1/Tier-2 vendor writeup; community identifier use |
| BTC wallets and `@TorBrowserTor` are Chaos builder defaults, LOW operator attribution value | **DEFINITE** | WalletExplorer confirms different cluster IDs, activity predates this campaign; reuse across unrelated Chaos builds is documented |
| Real Orcus C2 upstream | **UNKNOWN** | Static analysis cannot recover chisel/plink tunnel external endpoint |

---

## 8. Detection & Response

This section covers the minimum defender orientation for the UTA-2026-005 kit. Detection content (YARA, Sigma, Suricata, EDR queries) is delivered separately in [open-directory-94-103-1-13-20260423-detections.md](/hunting-detections/open-directory-94-103-1-13-20260423-detections/) — this report does not duplicate those rules. What follows is the prioritized hunting and response orientation.

### 8.1 Detection Priorities (hunt these first)

The two cross-build invariants are the highest-priority hunting anchors this investigation produced. Both are zero-false-positive, zero-public-prior-hit indicators:

1. **File hash: Stage-5b UAC bypass SHA256 `da302511ee77a4bb9371387ac9932e6431003c9c597ecbe0fd50364f4d7831a8`.** Byte-identical across both observed builds. Hunt via EDR file-hash query, SIEM PE-download logs, or VT Retrohunt. 8/77 VT at analysis time — most endpoint protection will NOT catch it on execution; hash-based hunting is required.
2. **Mutex GUID `9f67b5ed-6c10-4c53-818b-8d26be0d1339`.** Stage-4 cross-build invariant. Hunt via Sysmon EID 17/18 (mutex creation) or EDR handle-enumeration queries. Zero public prior hits.
3. **Defender-masquerade persistence pair.** Scheduled task literally named `\Microsoft Defender` at the task-scheduler root path (NOT under `\Microsoft\Windows\Windows Defender`) + registry blob `HKLM\Software\Microsoft Defender\Payload` size > 100 KB. Single most productive behavioral query; trivial to deploy against any Sysmon EID 12/13-covered estate.

### 8.2 Persistence Targets (what to look for and remove)

If incident response confirms a UTA-2026-005 infection, these are the artifacts defenders must enumerate and remediate. They are listed as *targets* — not as removal commands.

- Scheduled task `\Microsoft Defender` at task-scheduler root path (Hidden, RunLevel HIGHEST, BOOT trigger).
- Registry value `HKLM\Software\Microsoft Defender\Payload` (the ~1.4 MB encoded blob).
- Registry value `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Microsoft Store` (Stage-5a persistence).
- Registry value `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Audio HD Driver` (Orcus persistence).
- Scheduled task `Audio HD Driver` (Orcus persistence).
- Registry value `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr` (set to 1 by Stage-5a).
- File `%APPDATA%\svchost.exe` (mymain) or `%APPDATA%\projectxx.exe` (myfile) — Stage-5a self-copy.
- File `%APPDATA%\Microsoft\Speech\AudioDriver.exe` — Orcus installation.
- File `C:\cmd_log.txt` — boot re-loader debug artifact.
- Any file with the `.torbrowsertor` extension (encrypted victim data; do not delete without forensic imaging).
- Any removable drive with `surprise.exe` or `Recieve please.exe` at its root — USB-spread propagation artifact.

**Remediation approach.** The persistence mechanisms here are all user-space (registry + scheduled tasks + file-system), not kernel or firmware. Targeted remediation is viable *if* full persistence enumeration is completed and verified. If any of the above artifacts remain after remediation, assume re-infection on next boot and plan for full rebuild. The Defender-masquerade pair is specifically designed to survive incomplete cleanup — do not leave it behind.

### 8.3 Containment Categories

Third-party perspective — these are action categories with rationale, not step-by-step procedures. See your internal IR playbook or dedicated IR vendor for execution.

- **Isolate affected hosts.** Network-quarantine while preserving volatile state for forensic capture.
- **Block 94.103.1.13 at perimeter.** Egress block on the staging server IP. Do NOT block the victim/target IPs listed in Section 4 — those are attack targets, not operator infrastructure.
- **Kill active tunnels.** Identify and terminate any `chisel.exe`, `plink.exe`, or Python tunnel-runner processes — these are the conduit for the real C2 beyond the loopback front.
- **Rotate exposed credentials.** Mimikatz was staged; assume credential exposure on any infected host. Prioritize accounts with elevated privileges or domain access.
- **Preserve forensic evidence before remediation.** Volatile memory capture (to recover the plaintext AES passphrase and XOR key from decrypted Stage-4 memory), scheduled-task XML export, registry hive export, USB-drive imaging for propagation evidence.

### 8.4 Network-Side Detection

- HTTP GET to `94.103.1.13:80` — any request to this IP is operator-controlled infrastructure.
- `chisel.exe` or `plink.exe` process making outbound HTTP/HTTPS to unusual external hosts — tunnel-establishment signature.
- DNS queries for `forumrutor24.com` or `gtanuncios.com` from environments with no expected Russian/Spanish-language consumer web traffic.

---

## 9. FAQ / Key Intelligence Questions

**Q1: Is this the Cisco Talos "Chaos RaaS group" from 2025?**

No. See Section 7.2 for the full disambiguation. The 2021-origin Chaos ransomware builder (from which this sample was built) is distinct from the 2025 Talos-named Chaos RaaS group. Same family name, different actors. Our sample is a build of the open-source builder; Talos's reporting covers a specific named RaaS actor with a distinct codebase.

**Q2: Can I decrypt `.torbrowsertor` files without paying?**

Not from static analysis alone. Stage-5a generates a random per-file 32-byte key, encrypts it with a hard-coded RSA-2048 OAEP public key, and appends the wrapped key to the ciphertext. Without the RSA private key (which is held by the operator), the per-file keys cannot be recovered. No current public decryptor exists for this TorBrowserTor variant as of 2026-04-23. Prevention, backup restoration, and endpoint hardening are the only reliable paths — do not pay the ransom.

**Q3: What is the single highest-value hunting anchor if I only have time to deploy one?**

The Stage-5b SHA256 `da302511ee77a4bb9371387ac9932e6431003c9c597ecbe0fd50364f4d7831a8`. It is byte-identical across both observed builds, has 8/77 VT detection, zero public prior hits, and high-confidence diagnoses infection. A close second is the Sysmon EID 12/13 hunt for the Defender-masquerade persistence pair (`\Microsoft Defender` root task + `HKLM\Software\Microsoft Defender\Payload`).

**Q4: Why does the tri-artifact anti-sandbox gate exit on MATCH instead of mismatch?**

MODERATE confidence: operator-convenience check against their own development host. The VBE directory and mapping.csv artifact pattern is consistent with an analysis/IR toolchain the operator runs on their own machine; exiting on match prevents accidental self-infection. A less-likely alternative: intentional decoy to mislead researchers who flip the logic. Static analysis alone cannot distinguish; in either case the specific triple is a builder fingerprint.

**Q5: How did the loader achieve VT 0/76 on the batch files?**

Static signature-based AV scans for patterns in the file bytes. `mymain.bat` and `myfile.bat` are 2.6 MB of DOSfuscated text — no conventional PE structure, no embedded MZ/PE headers on the unprocessed file, no recognizable import names, no string patterns matching published YARA rules. The actual malicious content is two large Base64-alphabet-substituted blobs that only become recognizable after reversing the substitution, stripping the 32-character magic marker, AES-decrypting with a SHA256-derived key, and GZip-decompressing. Every one of those transformations must happen *in memory* before a scanner sees something it could match.

**Q6: Is 94.103.1.13 a confirmed bulletproof hosting provider?**

SUSPECTED, not CONFIRMED. AS209207 is three months old (allocated 2026-01-19), Russia-registered, Albania-routed through a single upstream (AS48014 AlbaHost) with a history of announcing bogon networks. The profile is consistent with bulletproof-adjacent hosting — abuse-tolerant, short-lived infrastructure, non-cooperative registration — but no named-BPH-database entry was located, and the ASN is too new for a meaningful Spamhaus DROP/SBL listing history. We avoid unsourced "Spamhaus recommends blocking" framing.

**Q7: What would change my attribution assessment from UTA-2026-005 to a named actor?**

(a) A Tier-1/Tier-2 vendor advisory linking this specific kit (private crypter, mutex GUID, Stage-5b PE hash, tri-artifact gate) to a named group; (b) passive DNS history for 94.103.1.13 showing prior named-actor use; (c) recovery of the real Orcus C2 upstream via dynamic detonation and correlation to a named-actor C2 pattern; or (d) a second campaign with the same cross-build invariants attributed by another vendor. None of these are currently available.

**Q8: The sample's BTC wallets appear in older campaigns. Does that mean UTA-2026-005 is responsible for those older campaigns?**

No. The wallets `bc1qw0ll8p9m8uezhqhyd7z459ajrk722yn8c5j4fg` and `17CqMQFeuB3NTzJ2X28tfRmWaPyPQgvoHV` are **Chaos builder defaults** — hard-coded into the builder template and reused verbatim by many unrelated operators who use the same builder. WalletExplorer clustering (different cluster IDs, activity predating this campaign) confirms the shared-default pattern. Treat these wallets as family-level indicators, not operator fingerprints. See Section 4 (Wallets & Telegram subsection) for the full explanation.

---

## 10. Gaps & Assumptions

This section explicitly catalogs what we do not know, what we have assumed, and what future evidence would change the assessment. Transparency about gaps is essential to report credibility.

### 10.1 Confirmed Gaps

- **Real Orcus C2 upstream: UNKNOWN.** The RAT connects to `127.0.0.1:20268`; the external endpoint behind the chisel/plink tunnel cannot be recovered from static analysis. Dynamic detonation with egress capture is required.
- **Operator identity: INSUFFICIENT for named-actor attribution.** The `xiang xiang fan` / `lc1393353@gmail.com` / `+86 130 3255 6442` identity recorded as pre-masking registrant of `gtanuncios.com` is most plausibly a CN domain-reseller inventory identity, not direct operator — ten-month dormant hold between acquisition (2025-06-28) and operator pivot (2026-04-11) is documented aged-domain-purchase tradecraft. Tracked in UTA-2026-005 for future correlation, not elevated to attribution.
- **Wardow-Orcus crack authoritative attribution.** No Tier-1/Tier-2 vendor writeup exists for this specific crack. Wardow-crack identifiers are used as community-known identifiers, not vendor-sourced claims.
- **Console.Title launch gate prior art.** We have not located public reporting describing the Console.Title + File.ReadLines batch-line self-extraction combination. Corpus is not exhaustive; absence of reporting is not proof of novelty.
- **Tri-artifact gate prior art.** Similarly, we have not located prior public reporting of the specific `admin` + `%TEMP%\VBE\` + `%TEMP%\mapping.csv` conjunction. Combined multi-artifact gating in general is well-documented; this specific triple in the inverted direction is not.
- **Second-victim telemetry.** The open directory was discovered in a pre-production state. No confirmed victim telemetry has been observed — targeting scope is inferred from the staged exploit scripts, not from attack outcomes.
- **Language/locale artifacts in decompiled code.** No language, locale, or developer-environment strings were recovered from the decompiled code. Geographic attribution of the operator is therefore unconstrained beyond the hosting choice and the CN-reseller-registrar preference signal (which is LOW confidence per above).
- **`otp2.py` / `otp_brute.py` direction.** Full source not reviewed; direction for 172.86.76.198 (operator-controlled vs target) remains ambiguous — flagged LOW confidence in infrastructure assessment.

### 10.2 Assumptions Made

- **Both builds came from the same builder.** We treat `mymain.bat` and `myfile.bat` as sibling builds from a single private crypter based on: shared structural anchors (forced 32-bit PowerShell path, alphabet-substitution Base64, magic-marker + Substring(32) idiom, Stage-4 `Assembly.Load` dispatch), cross-build invariants (Stage-4 mutex GUID, Stage-5b PE hash), and same-day compilation (2026-03-31). Per-build variation (keys, magic markers, resource names) is consistent with builder key-rotation, not with two independent codebases.
- **Stage-5b is a pre-compiled module, not per-build compiled.** Byte-identical SHA256 across both builds is the direct evidence. The builder bundles a single compiled Stage-5b rather than recompiling it per campaign — an operational trade-off that reduces unique samples but produces a high-value cross-build invariant hash.
- **The tri-artifact gate is an operator-convenience check.** MODERATE-confidence interpretation. We cannot prove it is not a decoy; hypothesis 1 (convenience) is more parsimonious given the operator must maintain and use these tools, and the probability of self-infection is real.
- **Real Orcus C2 is operator-controlled.** We assume the upstream endpoint behind the loopback tunnel is a server the operator controls (either self-hosted or on a third-party VPS). This is a conventional assumption for RAT infrastructure but cannot be verified from static analysis.
- **UTA-2026-005 is a single operator cluster.** MODERATE confidence (72% per UTA file, updated after the 2026-04-23 multi-tenant-host finding). The six distinctive characteristics — five technical (private crypter, cross-build mutex, cross-build Stage-5b, tri-artifact gate, operator-scale parallel builds) and one infrastructure/contextual (multi-tenant operator host with concurrent parasitic co-tenant campaigns) — collectively reach B2 Admiralty threshold, but we cannot rule out that two closely-cooperating operators share tooling. A second independent campaign would clarify.

### 10.3 Evidence That Would Change the Assessment

| If we obtained this evidence | It would change |
|---|---|
| A second sample with Stage-5b SHA256 `da302511…` | UTA-2026-005 confidence from MODERATE to HIGH |
| A second sample with mutex GUID `9f67b5ed-…` | Same — cross-campaign cluster confirmed |
| A Tier-1/Tier-2 vendor writeup linking this kit to a named group | Named-actor attribution from INSUFFICIENT to MODERATE/HIGH |
| Passive DNS history tying 94.103.1.13 to named-actor infrastructure | Same — enables named-actor attribution |
| Real Orcus C2 endpoint via dynamic detonation | Opens infrastructure pivot; may enable attribution if the endpoint matches known clusters |
| A language/locale artifact in future decompiled builds | Enables geographic attribution |
| Reappearance of the co-tenant triad (`forumrutor24.com` + `gtanuncios.com` + `bulgainme.pro`) on a different operator IP with Chaos-lineage samples | Establishes UTA-2026-005 continuity across infrastructure rotation |
| Reappearance of `xiang xiang fan` / `lc1393353@gmail.com` reseller-inventory identity on another operator-pivoted aged-domain acquisition | Elevates the CN-broker-preference signal from LOW to MODERATE |
| Confirmed victim telemetry | Shifts threat level from HIGH (capability-based) toward CRITICAL (impact-based) |
| Spamhaus DROP/SBL listing for AS209207 | Upgrades bulletproof classification from SUSPECTED to CONFIRMED |

---

## 11. References and Further Reading

**Chaos ransomware family (B1 sources):**
- WatchGuard: Chaos ransomware family tracker (2021–2026).
- Malpedia: Chaos family reference entry.
- Trend Micro: 2021 Chaos initial writeup.
- Fortinet: 2025 Chaos-C++ writeup.
- Acronis: Frea (Chaos fork) writeup.
- Cisco Talos: April 2025 Chaos RaaS group reporting (distinct from the builder — see Section 7.2).

**UAC bypass / UACME:**
- hfiref0x UACME repository (github.com/hfiref0x/UACME) — authoritative UACME catalogue including technique #41.

**.NET packing / bundling:**
- Fody/Costura repository — authoritative reference for Costura.Fody single-file-deployment bundling.
- Microsoft .NET single-file-deployment documentation (A1) — official Microsoft documentation.

**Anti-sandbox / anti-debug:**
- al-khaser GitHub (LordNoteworthy) — the anti-sandbox DLL-sweep catalogue chunk 0 draws from.

**TorBrowserTor variant (C2–C3 corroboration only):**
- PCrisk TorBrowserTor writeup.
- ITFunk TorBrowserTor writeup.

**Shared-wallet corroboration (C1–C2):**
- S2W Chaos Anatomy Medium article.
- WalletExplorer cluster data (bech32 `19254d2b5d`, legacy `9210ad5446`).

**Framework references:**
- MITRE ATT&CK framework (A1) — technique definitions in Section 6.

---

© 2026 Joseph. All rights reserved. See LICENSE for terms.
