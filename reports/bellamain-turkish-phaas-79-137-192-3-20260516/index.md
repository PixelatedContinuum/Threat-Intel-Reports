---
title: "BellaMain — Turkish Phishing-as-a-Service Panel with USOM Self-Monitor, Four-Bot Telegram C2, On-Demand TRUNCATE Anti-Forensics, and Wadanz Code-Author Signature"
date: '2026-05-16'
series: opendir-79-137-192-3
series_role: member
series_order: 1
detection_page: /hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/
ioc_feed: /ioc-feeds/bellamain-turkish-phaas-79-137-192-3-20260516-iocs.json
detection_sections:
  - label: "YARA Rules"
    anchor: "#yara-rules"
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "Suricata Signatures"
    anchor: "#suricata-signatures"
ioc_highlights:
  - value: "79[.]137[.]192[.]3"
    note: "BellaMain panel + 7 kit distribution (Aeza Group AS216246 — OFAC SDN)"
  - value: "cryptone[.]bot"
    note: "CryptOne fake-exchange production (Cloudflare-fronted, 0/92 VT)"
  - value: "evotoptan[.]com"
    note: "22-min DNS test to 79.137.192.3 (Namecheap shared host — MODERATE)"
  - value: "f791fae4...1ff88"
    note: "BellaMain.zip — panel ZIP (first public disclosure; not in VT)"
  - value: "@AresRS34"
    note: "Operator Telegram alias (privacy-restricted, real account)"
  - value: "Wadanz"
    note: "Code-author pseudonym (sifreleWadanz / sifrecozWadanz function pair)"
layout: post
permalink: /reports/bellamain-turkish-phaas-79-137-192-3-20260516/
thumbnail: /assets/images/cards/bellamain-turkish-phaas-79-137-192-3-20260516.png
category: "Phishing-as-a-Service"
hide: true
description: "BellaMain is an operator-developed Turkish Phishing-as-a-Service panel and matched seven-kit brand-impersonation bundle, recovered in full PHP source from an open directory on Aeza Group OFAC-sanctioned hosting. The panel ships first-class operator tradecraft rarely visible at the source layer — USOM (Turkey CERT) blocklist self-monitoring, four-bot Telegram C2 with identity-vs-card role separation, three Telegram-triggered TRUNCATE evidence-destruction commands, mysqldump-to-Telegram backup-as-exfil, a 70/30 TRX/TRON revenue split via live Binance TRXTRY rate conversion, invite-only operator gating with one-time-consume referral codes, and a code-level Wadanz developer signature. First public source-code disclosure for this PhaaS family. Tracked under UTA-2026-008."
stix_bundle: /stix/bellamain-turkish-phaas-79-137-192-3-20260516.json
---

**Campaign Identifier:** BellaMain-Turkish-PhaaS-79.137.192.3<br>
**Last Updated:** May 16, 2026<br>
**Threat Level:** HIGH

> **Investigation series — Open-Directory 79.137.192.3 (three-publication series):** This report is one of three publications from a single investigation into the multi-tenant Aeza Group staging server at `79.137.192.3`. Each cluster is operationally separate — co-tenancy on the same bulletproof IP is not operator linkage — so each cluster has its own dedicated report:
>
> - **[Parent (2026-05-15) — Multi-Cluster Overview](/reports/opendirectory-79-137-192-3-20260515/)** — all three co-tenant clusters at boundary-level depth; establishes why they are *not* one operator.
> - **[Cluster A (2026-05-16) — BellaMain Turkish PhaaS](/reports/bellamain-turkish-phaas-79-137-192-3-20260516/)** *(this report)* — full PHP-source recovery of an operator-developed PhaaS panel + 7 Turkish-marketplace kits; UTA-2026-008.
> - **[Cluster B (2026-05-16) — Inkognito Russian VPN/Phishing](/reports/inkognito-russian-vpn-phishing-185-221-196-118-20260516/)** — 467+ brand-impersonation subdomain library bolted to a commercial VPN front; UTA-2026-009.
>
> Cluster C (a Rhadamanthys MaaS customer at `79.133.180.168`) is covered only in the parent report.

## 1. Executive Summary

**BellaMain is an operator-developed Turkish Phishing-as-a-Service (PhaaS) panel — recovered in full PHP source form from an open directory on OFAC-sanctioned Aeza Group hosting (`79.137.192.3`, AS216246, Moscow) — that ships operator-grade anti-takedown tradecraft normally invisible to sample- or network-only analysis: a self-built USOM (Turkey CERT) blocklist monitor, four-bot Telegram C2 with deliberate identity-vs-card role separation, three Telegram-triggered TRUNCATE commands that wipe stolen credentials on demand, mysqldump-to-Telegram backup-as-exfil, a 70/30 TRX/TRON revenue split that uses the live Binance TRXTRY rate as a payout calculator, invite-only operator gating with one-time-consume referral codes, and a code-level `Wadanz` developer pseudonym hard-coded into the panel's session-encryption functions.** This report directly answers the primary intelligence question: *what does operator-grade Turkish-targeting PhaaS tradecraft look like at the source-code layer, and what unique tradecraft does full-source recovery surface that sample/network-only analysis cannot?* The seven kit RAR archives impersonate Dolap, Letgo, PTT AVM, Sahibinden, Shopier, Turkcell, and Yurtiçi Kargo — Turkey's highest-traffic consumer marketplaces and telecom — and capture not just payment cards but also Turkish national identity numbers (TC Kimlik Numarası) on a dedicated Telegram alerting channel.

> **Note on UTA identifiers:** This activity is tracked by The Hunters Ledger under the internal designation **UTA-2026-008** *(an internal tracking label used by The Hunters Ledger — see Section 9)*. UTA-2026-008 was originally created by the 2026-05-15 parent multi-cluster investigation and is **extended** by this standalone report — no new identity artifacts surfaced beyond the parent UTA's set; the contribution is section-depth coverage of operator tradecraft rather than new signal.

This report is the **first public disclosure** of BellaMain as a named PhaaS family. The panel ZIP (`BellaMain.zip`, SHA256 `f791fae4...`) has never been submitted to VirusTotal. No prior Tier 1, Tier 2, or Tier 3 source documents BellaMain, the `Wadanz` developer pseudonym, or the `@AresRS34` operator Telegram alias as a recognized PhaaS service, panel, or operator. The seven kit RARs have circulated since at least 2024-04-18 (VT first-seen) but detection across all of them is near-zero (0–2 / 62 across all seven archives). Operators deploying BellaMain have, until now, had no reason to assume defenders knew the panel's internal command vocabulary, database schema, or anti-forensic capabilities. This investigation closes that gap.

### What Was Found

The open directory at `79.137.192.3` exposed a complete operator backend (`BellaMain.zip`, 18.36 MB, 65 PHP files across 14 directories) alongside seven brand-impersonation phishing kit RARs targeting Turkish consumer platforms. The panel is co-tenanted on Aeza staging IP `79.137.192.3` alongside two operationally-separate threat clusters (Cluster B Inkognito Russian VPN/phishing operation; Cluster C Rhadamanthys MaaS customer) — those clusters are out of scope here and are documented in their own standalone publications. The BellaMain operator surface comprises:

- A **PhaaS admin panel** at `BellaMain/` with an obfuscated 12-character admin directory `V5VgjLU0jsDe/` containing `manager.php` (12-command admin Telegram bot), `backup.php` (mysqldump-to-Telegram exfil), `usmcheck.php` (USOM blocklist monitor), and `cekimbot.php` (withdrawal-approval Telegram webhook).
- **Seven brand-impersonation kits** packaged as RAR archives — Dolap (`Dolap.rar`), Letgo (`Letgo.rar`), PTT AVM (`Pttavm.rar`), Sahibinden (`sahibinden.rar`), Shopier (`shopier.rar`), Turkcell (`turkcell.rar`), and Yurtiçi Kargo (`Kargo.rar`) — all sharing the same hardcoded MySQL credentials (`jakartaxdw` / `dbjakartaxdw` / `W!@25#8Tb2gxq15`) and the same hardcoded canary Telegram bot (`6797512084:AAGbJVoC...`, since **REVOKED**) in every kit's `girislog.php` and the panel's `dashboard.php`.
- **A multi-operator licensing model** — `signup.php` requires a valid referral code consumed from the `refkodlari` table (DELETE-on-use); referral codes are minted by the admin via the Telegram `/refkod` command. New operators self-register, get their own dashboard, and earn 70% of approved hits — the panel administrator retains 30%.
- **Operator identity artifacts** unique to this codebase — the `Wadanz` developer pseudonym embedded as a function-name suffix on the panel's session-encryption helpers (`sifreleWadanz()` / `sifrecozWadanz()`), the `@AresRS34` operator Telegram alias embedded in an anti-researcher Turkish-profanity canary string in all six kits' `girislog.php`, two authorized-withdrawal-approver Telegram UIDs (`5606327063`, `6594066326`), and two operator Telegram group IDs (`-1002104835510` canary exfil group, `-1001817323952` operator announcement group).
- **A CryptOne fake-exchange front** — staging at `79.137.192.3/cryptone/`, production at the Cloudflare-fronted domain `cryptone.bot` (created 2026-02-28, 0/92 VT detections as of the evidence cutoff). The same operator developed this fake-exchange component on the BellaMain staging server; full content analysis of the live production domain was out of scope for this report.

### Why This Threat Is Significant

The gap this report fills is straightforward: public PhaaS reporting is overwhelmingly sample-and-network-based. Full PHP-source recovery is unusual, and recovering BellaMain in source unlocks tradecraft-layer findings that no network-only or sample-only analysis could reach. Four structural features make this operator notable.

1. **USOM blocklist self-monitoring.** BellaMain ships `usmcheck.php` — a dedicated panel feature that polls Turkey's national CERT URL blocklist (`https://www.usom.gov.tr/url-list.txt`) against the panel's tracked kit domains and Telegram-alerts the operator the moment any kit domain appears. This is the only documented PhaaS panel in open-source intelligence that ships a first-class USOM monitor as a panel feature. It enables preemptive awareness of Turkish national blocklist listings — a deliberate evasion of Turkey's primary domestic cybersecurity control mechanism.

2. **On-demand evidence destruction.** Three Telegram-issued commands — `/hesapsil`, `/kartsil`, `/girislogsil` — TRUNCATE the stolen-credential, stolen-card, and victim-log tables on operator command. Combined with `/yedek` (which ships a full `mysqldump` of the panel DB to operator-controlled Telegram before any wipe), the operator's anti-forensic workflow is: from a phone, in seconds, ship a private copy of all stolen data to Telegram, then wipe everything from the live panel. Standard "seize the server" forensic responses recover an empty database.

3. **Four-bot Telegram C2 with identity-vs-card role separation.** Each BellaMain deployment runs four functionally separated Telegram bots: `adminbot` (admin C2), `dekontbot` (bank-statement approval), `cekimbot` (withdrawal approval), and `vergibot` (national-ID alerts). The dedicated `vergibot` channel — which delivers TC Kimlik Numarası and personal-identity data immediately on Stage-1 victim capture, separate from card data on `dekontbot` — is more granularly role-separated than any PhaaS architecture documented in comparable public reporting (Cofense 2023; Sekoia.io EvilTokens 2024; Netcraft Haozi 2025; Breakglass TMoscow Bot 2025). The separation is operationally significant: it implies either a multi-person operation where identity-data and card-data monitors are different humans, or a data-brokering arrangement where identity data and card data have distinct downstream buyers.

4. **70/30 TRX/TRON payout flow via live Binance rate conversion.** The PhaaS revenue model settles operator earnings in TRX on the TRON network at a 70/30 split, with the live `TRXTRY` Binance ticker queried at every withdrawal to convert TRY-denominated balances to whole-TRX payouts (0.5% TRY fee, 500 TRY minimum). No prior public PhaaS reporting documents TRX/TRON as the affiliate settlement currency — most documented services use USDT subscription fees, not revenue splits in TRX. The Telegram approval button on a victim's bank-statement (`dekont`) upload is literally the payment-authorization mechanism for the PhaaS revenue split: when the admin clicks `[Onayla]` in Telegram, the panel updates the operator's balance by 70% of the victim's declared amount.

Because this is a first public disclosure, the IOCs and detection signatures in this report are not present in commercial TI feeds at the time of publication — deploying them is net-new coverage rather than duplicated effort.

### Key Risk Factors

| Risk Dimension | Score (X/10) | Rationale |
|---|---|---|
| Capability sophistication | 7/10 | Operator-grade tradecraft at the source layer — USOM monitor, multi-bot Telegram role separation, TRUNCATE anti-forensics, MySQL backup-as-exfil, obfuscated admin path, invite-only operator gating with one-time-consume referral codes, live Binance rate conversion for payouts. PHP code quality itself is workmanlike; sophistication is concentrated at the operations and anti-takedown layer. |
| Data-theft impact | 8/10 | Captures Turkish national identity numbers (TC Kimlik — 11-digit equivalent of US SSN), full PAN + expiry + CVV payment cards, marketplace login credentials, phone numbers, and victim-uploaded bank-statement images. A single victim through the full funnel yields a complete identity-theft + payment-fraud package. |
| Active-campaign evidence | 8/10 | Panel + 7 kits + CryptOne staging live on `79.137.192.3` as of 2026-05-07. HTTP port 80 newly opened in re-triage, indicating ongoing operator development. `BellaMain.zip` packaged March 2026 — under two months before this analysis. Kits in circulation since at least 2024-04-18. |
| Detection difficulty | 7/10 | Near-zero VT coverage across all kit RARs (0–2/62); panel ZIP not in VT at all. Aeza-hosted; standard abuse takedown channels are unlikely to succeed. Multi-tenant bulletproof co-tenancy creates false-positive risk on IP-blocking. Operator-fingerprint signatures (Wadanz functions, V5VgjLU0jsDe path, specific Telegram bot URI) are detectable with purposeful hunting. |
| Defender actionability | 8/10 | Concrete operator IP and 8 file hashes available for block lists; high-fidelity YARA/Sigma/Suricata signatures available in the [separate detection file](/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/); first-class single-string hunts (`V5VgjLU0jsDe`, `sifreleWadanz`, the hardcoded canary bot URI) with vanishingly low FP probability. |

**Overall Risk Score: 7.6 / 10 — HIGH**

### Threat Actor

- **UTA-2026-008 — BellaMain Turkish PhaaS operator.** Indicators suggest a single Turkish-speaking PhaaS developer/operator (or small operator team) is responsible for the BellaMain panel and its seven brand-impersonation phishing kits. Distinct-actor confidence **MODERATE (75%)** — supported by a code-level developer pseudonym (`Wadanz` function-name suffix), identical MySQL credentials across panel and all seven kits (incompatible with a shared/leaked multi-licensee template), identical canary Telegram bot embedded in all six kits' `girislog.php`, and idiomatic Turkish across the operator-facing strings (USOM polling, TRY-pegged payouts, native-fluent profanity in the anti-researcher canary). Named-actor attribution **INSUFFICIENT (<50%)** — first-capture documentation; zero Tier 1, Tier 2, or Tier 3 public sources surface BellaMain, `@AresRS34`, or `Wadanz` as a known operation, operator, or developer handle. We cannot attribute BellaMain to a publicly named threat actor at this time.

### For Technical Teams — Immediate Priorities

- **Hunt web-access logs for URI path component `/V5VgjLU0jsDe/`** — the 12-character random admin directory name is the single most BellaMain-specific indicator. Any HTTP request containing this path on a non-BellaMain host is a high-fidelity hit. See [Section 5.2](#52-usom-blocklist-self-monitoring-the-distinctive-turkish-targeting-tradecraft) and the [separate detection file](/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/) for the Sigma rule.
- **Hunt any PHP corpus and open-directory archives for the function-name pair `sifreleWadanz` + `sifrecozWadanz`** — the developer pseudonym signature. Each external hit is potentially another panel by the same developer; cross-sample author pivots are the strongest forward-looking attribution lead.
- **Block 79.137.192.3 and AS216246 Aeza space at the perimeter** and add the eight SHA256 file hashes (one panel ZIP + seven kit RARs) to EDR / mail-gateway file blocklists. See the [separate IOC feed](/ioc-feeds/bellamain-turkish-phaas-79-137-192-3-20260516-iocs.json) for the complete machine-readable inventory.
- **Add the operator Telegram identity artifacts to any Telegram-aware threat intelligence feed** — the two operator group IDs (`-1002104835510`, `-1001817323952`) and the two admin Telegram UIDs (`5606327063`, `6594066326`) are operator pivots, not defensive controls; they enable cross-incident correlation if any partner platform can resolve Telegram UIDs to accounts.
- **For US-regulated entities**, treat outbound connections to Aeza Group AS216246 (and the historical AS204603) as potentially OFAC-reportable per the July 1, 2025 SDN designation of Aeza Group LLC. The BellaMain panel was operating on already-sanctioned infrastructure throughout the April–May 2026 investigation window.

---

## 2. How This Investigation Unfolded

This report is a **standalone derivative** of the OpenDirectory 79.137.192.3 investigation published on 2026-05-15. The originating pivot was a single open-directory exposure on Aeza Group AS216246 staging IP `79.137.192.3` that surfaced three operationally separate threat clusters co-tenanted on the same multi-tenant bulletproof staging utility. That parent investigation, published at [`/reports/opendirectory-79-137-192-3-20260515/`](/reports/opendirectory-79-137-192-3-20260515/), covered:

- **Cluster A — BellaMain Turkish Phishing-as-a-Service** (UTA-2026-008): the subject of this report.
- **Cluster B — Inkognito Russian VPN/phishing operator** (UTA-2026-009): documented at section-depth in a sibling standalone publication at [`/reports/inkognito-russian-vpn-phishing-185-221-196-118-20260516/`](/reports/inkognito-russian-vpn-phishing-185-221-196-118-20260516/).
- **Cluster C — Rhadamanthys MaaS customer** (UTA-2026-010): a customer-built loader (`staticlittlesource.exe`) wrapping a canonical Rhadamanthys Stage-2 with a Hostkey Netherlands C2 surviving the November 2025 Operation Endgame Phase 3 takedown.

In the parent report, BellaMain (Cluster A) received **paragraph-depth coverage** across Sections 4.4, 5.7, 6.6, 8.3, and 9.1 — enough to establish the cluster boundary and risk classification, but not enough to publish the full operator-tradecraft surface that source-code recovery makes visible. This standalone publication goes deep on Cluster A only.

### Why a Standalone BellaMain Report

Three findings from the parent investigation made BellaMain worth promoting to standalone publication:

1. **Full PHP-source recovery is unusual.** Public PhaaS reporting is overwhelmingly sample-based (kit RARs uploaded to VirusTotal) or network-based (passive DNS, certificate transparency, IDS captures). Recovering an admin panel in full source from an open directory exposes operator-side tradecraft — admin-only Telegram commands, MySQL schemas, anti-forensic workflows, multi-operator licensing logic — that no sample or network observation can produce. The findings catalogued in Section 5 (USOM monitor, four-bot Telegram role separation, on-demand TRUNCATE, mysqldump-as-exfil, 70/30 TRX/TRON payout, Wadanz code signature, invite-only gating) are all source-only findings.

2. **First public capture of a 2-year-old operation.** The seven kit RARs first appeared on VirusTotal on 2024-04-18 — approximately 24 months of operational circulation. Despite this, BellaMain is absent from every public threat-intelligence feed, vendor blog, security-researcher blog, and law-enforcement database searched. The panel ZIP has never been submitted to VirusTotal. Operators using BellaMain have, until now, had no defender-visible audit trail. This publication closes that gap.

3. **Cluster-boundary evidence anchored on Tier-1 OFAC documentation.** The parent investigation's §22.9.1 and §23.12.7 reassessment established that BellaMain (Cluster A), Inkognito (Cluster B), and the Rhadamanthys MaaS customer (Cluster C) are operationally separate actors sharing only Aeza tenancy. The July 1, 2025 OFAC SDN designation of Aeza Group LLC documents Aeza simultaneously hosting BianLian, RedLine, Lumma, Meduza, and BlackSprut as five unrelated criminal ecosystems — Tier-1 authoritative confirmation that bulletproof hosting co-residency is a service-utility relationship, not an operator-linkage signal. This boundary is reaffirmed here. The cluster-exclusion paragraph appears in [Section 9](#9-threat-actor-assessment).

### Evidence Cutoff and Sourcing

- **Evidence cutoff:** 2026-05-07 (last live re-triage of `79.137.192.3`; last DomainTools Iris passive-DNS export).
- **Primary sources:** full PHP source code of the BellaMain panel and seven kit RARs (extracted from the open directory and statically reviewed); passive DNS (DomainTools Iris — 3 domain-history pulls, 4 passive-DNS exports); threat-intel API (VirusTotal MCP — cross-verification of the panel IP, the seven kit hashes, and the `cryptone.bot` production domain); direct verification of the canary Telegram bot token (`6797512084:AAGbJVoC...` returned `{"ok":false,"error_code":401}` on `getMe` — REVOKED at the time of analysis).
- **Tier-1 anchors:** OFAC SDN List — Aeza Group LLC (2025-07-01); VirusTotal MCP IP and domain reports for `79.137.192.3` and `cryptone.bot`.
- **Tier-2 supporting:** TRM Labs (Aeza OFAC sanctions analysis); Cofense Intelligence (Telegram bot credential exfiltration patterns); Sekoia.io (EvilTokens PhaaS analysis); Netcraft (Haozi PhaaS analysis); Kaspersky Securelist (Spam and Phishing Report 2024 — Turkey ranks 5th globally for malicious email targeting).
- **Tier-3 supporting:** BleepingComputer (Aeza Group sanctions article); Silent Push (Aeza infrastructure shift post-sanctions); Global Initiative against Transnational Organized Crime (Turkey fraud landscape 2025); PTT official fraud warnings (`ptt.gov.tr`); Infosecurity Magazine (Turkish national ID breach 2016); Breakglass Intelligence (TMoscow Bot PhaaS).
- **Negative-result sourcing:** Targeted VirusTotal Intelligence, Google, GitHub-code, and general web searches for `BellaMain`, `sifreleWadanz`, `sifrecozWadanz`, `@AresRS34`, `Wadanz` (as a PhaaS author), `V5VgjLU0jsDe`, `jakartaxdw`, and `dbjakartaxdw` — all returned zero security-relevant results, establishing first-public-disclosure status.

---

## 3. Business Risk Assessment

> **What this section is for.** Translating the technical findings in Sections 4–8 into the risk language a business reader needs: what data is at risk, who is at risk, and what the realistic impact looks like. This is not a generic threat-landscape overview — every claim below ties back to a specific BellaMain feature documented elsewhere in this report.

BellaMain is a **financially-motivated Turkish consumer credential-theft operation**. The risk surface is bounded — this is not a ransomware operator, an ICS/OT threat, a healthcare-targeting actor, or an enterprise-network intruder. The victims are individual Turkish consumers using everyday e-commerce, cargo-tracking, mobile-billing, and second-hand-marketplace platforms; the secondary victims are the seven Turkish brands whose marketplaces are impersonated.

### 3.1 Who Is at Risk

| At-risk population | Why BellaMain targets them |
|---|---|
| Turkish consumers using Dolap, Letgo, PTT AVM, Sahibinden, Shopier, Turkcell, or Yurtiçi Kargo | The seven impersonation kits replicate these specific brands at high visual fidelity (loading legitimate CDN assets from `cdn.dolap.com`, `m.turkcell.com.tr`, etc.). A victim who lands on a BellaMain kit page via an SMS or social-media lure typically cannot distinguish it from the genuine site. |
| Turkish consumers with active payment cards and bank accounts | Two-stage credential capture collects full PAN + expiry + CVV (Stage 2) and Turkish national identity number + name + phone (Stage 1). Both stages are designed to convert in a single victim session. |
| The seven impersonated Turkish brands (Dolap, Letgo, PTT AVM, Sahibinden, Shopier, Turkcell, Yurtiçi Kargo) | Reputational damage from brand-impersonation phishing, downstream customer-support load handling fraud complaints, and potential platform-trust erosion. These brands are not technical victims (their systems are not compromised) but they bear secondary impact. |
| Turkish consumers vulnerable to identity theft beyond payment fraud | TC Kimlik Numarası — Turkey's 11-digit national identifier, functionally equivalent to a US SSN — enables full identity theft (opening bank accounts, taking loans, accessing government services) beyond immediate payment-card fraud. The dedicated `vergibot` Telegram channel for identity-data routing indicates the operator places distinct value on this data. |

### 3.2 What Data Is Captured per Victim

A single victim who completes the full BellaMain funnel hands the operator a comprehensive financial-crime package:

| Data captured | Source step | Downstream fraud enabled |
|---|---|---|
| Marketplace username + password | Kit `login.php` (Stage 0) | Account takeover; downstream credential reuse against banking/social platforms |
| Turkish national ID (TC Kimlik), full name, phone number | Kit `kartlaodeme.php` (Stage 1) | Identity theft, fake bank account opening, government-services impersonation, SIM-swap-prep |
| Payment card (PAN + expiry + CVV) | Kit `ibanlaodeme.php` (Stage 2) | Card-present-equivalent fraud, online purchase fraud |
| Bank statement image (`dekont`) | Victim "proof of payment" upload | Operator obtains real bank-statement scans; downstream KYC fraud |

This is the *complete* identity-theft + payment-fraud package from a single victim session. Most documented PhaaS operations capture only credentials or only card data; BellaMain captures both plus identity documents in a single funnel.

### 3.3 Realistic Impact Scenarios

BellaMain enables rapid full-identity exploitation within minutes of victim conversion — from payment-card fraud within hours to identity-theft outcomes over weeks. The scenarios below are anchored to BellaMain features documented in Sections 4–8, not generic phishing landscape claims.

| Scenario | Likelihood | Explanation |
|---|---|---|
| Individual Turkish consumer suffers payment-card fraud and bank-account fraud within hours of victim conversion | HIGH | The four-bot Telegram architecture fires immediate alerts to operator-controlled channels at Stage 1 (national ID + name + phone) and on bank-statement upload. Operator can act on stolen card and identity data within minutes of capture. |
| Same victim suffers identity-theft outcomes (loan opened, fake bank account, SIM swap) over weeks to months | MODERATE–HIGH | TC Kimlik + full name + phone + bank-statement combination is the minimum data set for SIM-swap and identity-theft operations targeting Turkish financial services. The operator's separation of identity data (`vergibot`) from card data (`dekontbot`) suggests these data streams are likely monetized to different downstream buyers. |
| Impersonated Turkish brand absorbs sustained customer-support load from fraud-victim complaints | HIGH | Sahibinden removed 400,000+ fake listings in 2024; documented Dolap WhatsApp-redirect phishing patterns; PTT and Turkcell have issued public fraud warnings. BellaMain extends these patterns at toolkit scale. |
| Same operator scales across multiple sub-operators via referral-code self-registration | HIGH | `signup.php` requires a one-time-consume referral code minted by admin via Telegram `/refkod`. The architecture supports many sub-operators running independent campaigns against the same panel administrator — a takedown of one operator does not stop the panel. |
| Standard "seize the server" forensic response recovers an empty database | HIGH | The `/yedek` → `/hesapsil` + `/kartsil` + `/girislogsil` Telegram workflow (documented in [Section 5.4](#54-truncate-evidence-destruction-on-demand-anti-forensics)) wipes the credential, card, and victim-log tables on operator command after exfiltrating a private copy to Telegram. Operators can execute this from a phone. |
| Aeza ASN block at network egress catches BellaMain campaign attempts before impact | HIGH | All operator infrastructure currently resolves into AS216246. ASN blocking is high-utility at the perimeter. False-positive risk on the IP (multi-tenant bulletproof co-tenancy) is acceptable given Aeza's OFAC SDN designation. |
| TLS or HTTP regex on the `V5VgjLU0jsDe/` path surfaces a forked BellaMain deployment | MODERATE | The 12-char path is unique to this codebase; any future deployment that re-uses it indicates a direct fork. If a fork-er rekeys the admin path, the panel can still be surfaced via the `sifreleWadanz` function-name pivot. |

### 3.4 What This Threat Is *Not*

BellaMain does not target ICS/OT, healthcare, or enterprise networks, and deploys no ransomware or host-malware payload at any stage. The boundaries below matter for risk owners scoping response priority:

- **Not an ICS / OT / transportation-sector threat.** No SCADA, Modbus, DNP3, IEC-104, S7, or transportation-protocol targeting. Operator focus is Turkish consumer payment and identity data.
- **Not a healthcare or medical-device threat.** No DICOM, HL7, PACS, or medical-platform targeting. No hospital, clinic, or healthcare-billing impersonation in the seven-kit set.
- **Not an enterprise-network intrusion threat.** No endpoint malware deployment, no lateral movement, no privilege escalation, no Active Directory targeting. BellaMain is browser-based phishing against individual consumers — there is no host-malware payload at any stage of the victim funnel.
- **Not a ransomware or destructive-payload threat.** The only "destruction" is operator-initiated TRUNCATE on the operator's own panel database for anti-forensic purposes. Victims do not experience data destruction.
- **Not a known-named-actor operation.** First-capture documentation; no Tier 1–3 sources name BellaMain, `Wadanz`, or `@AresRS34` as a known operator. Tracked as UTA-2026-008.

---

## 4. Technical Classification

| Field | Value |
|---|---|
| **Type** | Phishing-as-a-Service (PhaaS) admin panel + 7 brand-impersonation phishing kits |
| **Family / Brand** | BellaMain (panel) — operator-self-named per the `BellaMain.zip` distribution archive and the `BellaMain/` directory exposed in the open directory listing |
| **Family Confidence** | DEFINITE (full source recovered; brand-self-identified across multiple artifacts) |
| **Artifact substrate** | Server-side PHP source code. No PE binaries to reverse-engineer; no host-deployed payload. The "malware" is operator-side — it runs on the operator's web server, not on victim endpoints. |
| **Sophistication** | Intermediate-Advanced. Operator-grade tradecraft at the source layer: USOM polling, multi-bot Telegram role separation, on-demand TRUNCATE evidence destruction, MySQL backup-as-exfil, live Binance TRXTRY rate-conversion for payouts, invite-only operator gating with one-time-consume referral codes. PHP code quality itself is workmanlike; sophistication lives at the operations / anti-takedown layer. |
| **First Seen** | Kit RARs first observed on VirusTotal 2024-04-18 (~24 months of circulation). Panel ZIP (`BellaMain.zip`) **never** submitted to VT — this analysis is its first public disclosure. Operator open-directory hosting on `79.137.192.3` active since at least 2024-04 and current as of 2026-05-07. |
| **Targeting** | Turkish consumers — kits replicate 7 named Turkish marketplaces. Anti-researcher canary text is Turkish. `date_default_timezone_set('Europe/Istanbul')` is hardcoded. USOM polling targets Turkey's CERT. Strong Turkey-resident or Turkey-targeting operator profile. |
| **Monetization** | Direct: stolen Turkish payment cards (PAN/Expiry/CVV) and Turkish national identity numbers (TC Kimlik Numarası, 11-digit equivalent of US SSN). Indirect: 70/30 revenue split between operator and panel administrator. Payout currency: TRX (TRON) at live Binance TRXTRY rate. |
| **C2 substrate** | Public Telegram Bot API (4 operator-configured bots per deployment + 1 hardcoded canary bot) + public Binance API for live rate lookup. No operator-controlled C2 servers beyond the panel itself. |
| **Detection coverage** | Near-zero. Panel ZIP not in VT; kit RARs 0–2/62 on VT. `cryptone.bot` 0/92. The `79.137.192.3` IP scores 9/92 (driven by co-tenancy with BriansClub/CRD Club, not BellaMain itself). |
| **UTA designation** | UTA-2026-008 (existing — extended by this report) |

### 4.1 Why This Is a PhaaS, Not a Single Phishing Kit

The structural feature that distinguishes BellaMain from a one-off phishing kit is the **multi-operator licensing model** baked into the panel's authentication flow:

- `signup.php` requires a valid `ref_code` from the `refkodlari` table. Without a code, registration fails immediately.
- Each row in `refkodlari` is consumed (DELETE) on use — codes are one-time-use only.
- Codes are minted via the admin Telegram `/refkod` command in `manager.php`; the admin alone controls who can become an operator.
- Once an operator is registered, they receive their own dashboard, their own credential view, their own balance (`bakiye`), and their own withdrawal flow. The same panel can serve many such operators simultaneously.
- Revenue accrues at 70% to the operator and 30% to the panel administrator on every approved hit (`tgdekont.php` updates `bakiye += amount * 0.7` on admin Telegram approval).

This is a **commission-based PhaaS marketplace**, not a subscription model. Most documented PhaaS services (Tycoon 2FA, Sneaky 2FA, Haozi) sell access for fixed USDT amounts; BellaMain takes a per-hit commission. The economic implication is that the panel administrator's revenue scales with operator success — incentivizing the administrator to invest in panel quality, operator-onboarding tooling (the four-bot architecture, the referral system), and anti-takedown tradecraft (USOM monitor, TRUNCATE commands).

The architectural fingerprint that makes the single-operator model directly observable in source is that all eight PHP applications (the admin panel and each of the seven brand-impersonation kits) hardcode the same MySQL connection triple — same database name, same username, same password — in their respective `database/connect.php` files. A multi-licensee deployment would re-key per tenant; a single-operator product would not. Figure 1 lays out the 8-app / 1-database structure as recovered from the open directory.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/bellamain-turkish-phaas-79-137-192-3-20260516/bellamain-single-tenant-database.svg" | relative_url }}" alt="3-by-3 grid infographic titled 'Single-Tenant MySQL — 8 Apps, 1 Database.' Center cell is the deep-red MySQL database card labeled 'jakartaxdw' with credentials dbjakartaxdw and W!@25#8Tb2gxq15 hardcoded across 8 source files. The eight surrounding cells show the seven orange brand-impersonation kit cards (Dolap.rar SHA 2c656360, Letgo.rar SHA e21fb63a, Pttavm.rar SHA ee9d4fcc, sahibinden.rar SHA b2f4f161, shopier.rar SHA 504b1a30, turkcell.rar SHA 219cd4f6, Kargo.rar SHA 705793c0) plus the red BellaMain.zip panel card (SHA f791fae4). Each kit card lists the Turkish-brand category, points to its database/connect.php file, and repeats the same db/user pair. Footer states the attribution implication: identical MySQL credentials across panel and 7 kits indicate single-operator control rather than a leaked or licensed template; UTA-2026-008 distinct-actor confidence MODERATE 75 percent. Hunt anchor is the jakartaxdw database name plus dbjakartaxdw user plus W!@25#8Tb2gxq15 password appearing together in any PHP source file.">
  <figcaption><em>Figure 1: Single-tenant MySQL architecture. Every kit and the panel hardcode the same `jakartaxdw` database credentials — a structural fingerprint that rules out the shared-template / multi-licensee hypothesis and anchors the UTA-2026-008 distinct-actor finding.</em></figcaption>
</figure>

### 4.2 What "Operator-Grade" Means Here

The Stage 1 analysis classifies BellaMain as Intermediate-Advanced. The operator-grade traits are concentrated in operations and tradecraft, not code novelty:

- **First-class USOM (Turkey CERT) monitor.** No comparable PhaaS panel documented in public research ships this. (See Section 5.2.)
- **Identity-data and card-data routed to separate Telegram bots.** Granular role separation beyond the published PhaaS state of the art. (See Section 5.3.)
- **Three TRUNCATE anti-forensic commands triggered from Telegram.** Lets the operator wipe stolen-data tables from a phone. (See Section 5.4.)
- **MySQL backup-as-exfil via mysqldump → Telegram document upload.** Treats Telegram as cloud storage for full database snapshots. (See Section 5.5.)
- **Live Binance TRXTRY rate conversion for TRX/TRON payouts at 70/30 split.** Not documented in any prior public PhaaS reporting. (See Section 5.6.)
- **Wadanz code-author pseudonym hard-coded into function names.** Operators rarely sign source files with their handles — this is a cross-deployment author marker. (See Section 5.7.)
- **Invite-only operator gating with one-time-consume referral codes.** A multi-operator licensing model with referral-system tradecraft. (See Section 5.9.)

PHP code quality itself is unremarkable: linear procedural style, plaintext hardcoded credentials, mysqldump command-line with the password visible in process listings, weak custom session "encryption" using `base64(gzcompress(serialize()))`. The skill is operational, not technical.

---

## 5. Technical Capabilities Deep-Dive

BellaMain's nine capabilities reveal operator-grade tradecraft concentrated at the operations and anti-takedown layer — not at the code layer. Each subsection below leads with an analyst-note conclusion, then provides Evidence, Why This Matters, and Detection guidance, in order of distinctiveness.

### 5.1 Full PHP-Source Recovery — What It Unlocks

> **Analyst note:** "Source recovery" here means the analyst has the operator's actual server-side PHP files, not just network traffic or victim-side captures. This is unusual in public phishing reporting and the findings in this report — admin Telegram commands, MySQL table schemas, anti-forensic workflows, the multi-operator licensing system — can only be observed when the panel source itself is in hand.

**Evidence basis.** The open directory at `79.137.192.3` exposed `BellaMain.zip` (18.36 MB, SHA256 `f791fae4...`) containing the entire panel — 65 PHP files across 14 directories, listed in [Section 6.1](#61-file-inventory). Inside the archive are the panel's authentication code (`signin.php`, `signup.php`, `logout.php`), the central AJAX dispatcher (`database/post.php`, ~350 lines), the live-victim-tracker widgets (`includes/girislog/*log.php`), the credential-submission handlers (`includes/forms/*.php`), the per-kit admin configuration forms (`includes/editforms/*.php`), and — most importantly — the obfuscated 12-character admin directory `V5VgjLU0jsDe/` containing `manager.php`, `backup.php`, `cekimbot.php`, and `usmcheck.php`. The seven kit RARs and the CryptOne staging directory sit alongside the panel ZIP on the same open directory.

**What sample- or network-only analysis cannot recover.** Sample-only analysis of a kit RAR would yield the victim-facing pages, the credential submission targets, and the hardcoded canary bot token — but not the panel's command vocabulary, the admin-only TRUNCATE commands, the MySQL schema, the 70/30 revenue-split arithmetic, the referral-code lifecycle, or the four-bot architecture. Network-only analysis would yield destination IPs, TLS fingerprints, and some Telegram bot URIs — but not the operator-side anti-forensic workflows, the multi-operator licensing model, or the Wadanz code-author signature. Every distinctive finding catalogued in Sections 5.2 through 5.9 is a source-only finding.

**Why this matters.** This is why the report is worth publishing as a standalone: it is the first public source-code disclosure of a Turkish PhaaS panel that ships these specific tradecraft features. Defenders previously had no visibility into the operator-side surface; that surface is now documented.

**Detection.** The single most BellaMain-specific indicator is the `V5VgjLU0jsDe/` admin path — any HTTP request containing that 12-character random string is a high-fidelity hit on any web server. The function-name pair `sifreleWadanz` + `sifrecozWadanz` is the strongest PHP-corpus pivot (see Section 5.7). See the [separate detection file](/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/) for the complete YARA / Sigma / Suricata rule set.

### 5.2 USOM Blocklist Self-Monitoring — The Distinctive Turkish-Targeting Tradecraft

> **Analyst note:** Turkey's national CERT (USOM / TR-CERT) publishes a public URL blocklist that Turkish ISPs, enterprise firewalls, DNS resolvers, and security tools consume as a primary domestic threat feed. BellaMain polls this blocklist on operator command and alerts the operator the moment any kit domain appears — a deliberate evasion of Turkey's primary national cybersecurity control. This is the only documented PhaaS panel in open-source intelligence that ships a dedicated USOM monitor as a panel feature.

**Evidence basis.** The file `BellaMain/V5VgjLU0jsDe/usmcheck.php` implements a one-shot poller against `https://www.usom.gov.tr/url-list.txt`. The core logic is straightforward: `file_get_contents()` the blocklist URL, then `strpos()` each entry against the panel's tracked kit domains (`dom_panel`, `dom_dolap`, `dom_letgo`, `dom_pttavm`, `dom_turkcell`, `dom_shopier`, `dom_yurtici`). On any hit, the panel fires a Telegram alert to the operator announcement group `-1001817323952` with the message `"Usom Yedik Atış Stop"` — translated literally as *"We got caught by USOM, stop the attack"*. The poller is invoked manually via the `/usom` Telegram command in `manager.php`; it is not on a fixed schedule.

**Why this matters.** USOM is consumed downstream by Turkish ISPs as a DNS sinkhole input and by enterprise firewalls as a URL block list. A kit domain landing on the USOM blocklist sharply reduces its lifespan — Turkish-resident victims become unable to resolve the kit's domain. By polling USOM directly, the BellaMain operator gets early warning of any kit-domain listing and can switch to a fresh domain before the blocklist propagates downstream. The operator wraps Turkey's primary national cybersecurity control as a tool for *their* OPSEC. This is the kind of feature that takes domestic knowledge to build — knowing that USOM publishes a public URL list, knowing the polling URL, knowing which downstream consumers it feeds — and it is one of the strongest signals that the operator is Turkey-resident or has direct Turkey-domestic operational support. (See [Section 9](#9-threat-actor-assessment).)

**Comparative context.** No prior public PhaaS reporting documents a USOM-targeting blocklist monitor. The Cofense 2023 Telegram-credential-exfil patterns, the Sekoia EvilTokens 2024 PhaaS, the Netcraft Haozi 2025 PhaaS, and the Breakglass TMoscow Bot 2025 PhaaS all lack any analogous national-CERT awareness. BellaMain's USOM monitor is a tradecraft innovation specific to this operator. (Confidence: HIGH — direct code observation; no corroborating public reporting exists. The negative result is itself the finding.)

**Detection (operator-side).** A PHP host on a non-Turkish-CERT-affiliated network making outbound HTTPS requests to `www.usom.gov.tr/url-list.txt` is a high-FP-context indicator: legitimate Turkish security tooling, threat-intel platforms, and individual researchers also fetch this URL. The high-confidence detection requires combining the USOM fetch with another BellaMain artifact on the same host — the `sifreleWadanz` function-name pair, the `V5VgjLU0jsDe/` path, or the hardcoded canary Telegram bot URI. See the Suricata signature in the [separate detection file](/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/).

### 5.3 Four-Bot Telegram C2 with Role Separation

> **Analyst note:** Most documented phishing kits exfiltrate stolen data via a single Telegram bot to a single operator channel. BellaMain uses four functionally separated bots per deployment — one for admin commands, one for bank-statement approval, one for withdrawal approval, and a dedicated bot for routing Turkish national ID alerts. This separation is more granular than any PhaaS architecture documented in comparable public research and has operational implications for how the operator monetizes different data streams.

**Evidence basis.** The `panel` table in BellaMain's MySQL schema stores four bot tokens per operator deployment: `adminbot_token`, `dekontbot_token`, `cekimbot_token`, and `vergibot_token`. Each token drives a distinct Telegram bot with a specific role. Figure 2 lays out the four-bot architecture alongside the canary bot embedded in source.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/bellamain-turkish-phaas-79-137-192-3-20260516/bellamain-four-bot-telegram-c2.svg" | relative_url }}" alt="2-by-2 phase-grid infographic titled 'Four-Bot Telegram C2 with Role Separation.' Top-left yellow card 'vergibot' is the identity-data channel implemented in tgvergi.php per kit; fires on Stage 1 with TC Kimlik national ID, name, phone, fake transaction amount, and timestamp; activates before card data is captured. Top-right orange card 'dekontbot' is the card-data and approval channel implemented in tgdekont.php; receives the victim's bank-statement image and declared amount, sends inline Onayla and Reddet buttons to the operator phone for approve or reject. Bottom-left red card 'adminbot' is admin command-and-control implemented in V5VgjLU0jsDe/manager.php; supports a 12-command vocabulary including /refkod, /reflist, /bloke, /aktif, /iban, /yedek, /usom, /hesapsil, /girislogsil, /kartsil, /sifre, /komutlar. Bottom-right deep-red card 'cekimbot' is the withdrawal approval and TRX payout bot in V5VgjLU0jsDe/cekimbot.php; validates against the two authorized Telegram UIDs 5606327063 and 6594066326, queries Binance for the live TRXTRY rate, emits TRX payout instructions. A grey banner below the grid documents a fifth hardcoded canary bot 6797512084:AAGbJVoC... in every kit girislog.php and panel dashboard.php that fires only on ?lg= researcher probes; this token is REVOKED. Footer lists detection anchors: api.telegram.org egress from PHP-host context, the /V5VgjLU0jsDe/ admin URI, the Binance TRXTRY ticker query, and the canary token pattern.">
  <figcaption><em>Figure 2: Four-bot Telegram C2 with role separation. The split between `vergibot` (identity data, Stage 1) and `dekontbot` (card data, Stage 2 approval) is the operationally distinctive finding — most documented phishing operations route everything to a single channel.</em></figcaption>
</figure>

| Bot | File(s) | Role |
|---|---|---|
| `adminbot` | `V5VgjLU0jsDe/manager.php` | Admin C2 — receives operator commands `/refkod`, `/reflist`, `/bloke`, `/aktif`, `/iban`, `/yedek`, `/usom`, `/hesapsil`, `/girislogsil`, `/kartsil`, `/sifre`, `/komutlar` |
| `dekontbot` | `tgdekont.php` (per kit) | Receives victim-uploaded bank-statement images and the operator's declared transaction amount. Sends a Telegram message with inline `[Onayla]` / `[Reddet]` (Approve / Reject) buttons to the panel administrator. On approval, the webhook fires back into the panel and credits the operator's `bakiye` with 70% of the amount. |
| `cekimbot` | `V5VgjLU0jsDe/cekimbot.php` | Receives operator withdrawal requests. Validates against an `$authorizedUsers` array containing two hardcoded Telegram UIDs (`5606327063`, `6594066326`). Queries `api.binance.com` for the live `TRXTRY` rate. Computes and emits TRX payout instructions to the admin Telegram. |
| `vergibot` | `tgvergi.php` (per kit) | **Fires immediately on Stage-1 victim data entry** with the captured Turkish national ID (TC Kimlik Numarası), full name, phone number, fake transaction amount, and timestamp. This is the identity-data Telegram channel — distinct from `dekontbot` which handles card and statement data. |

Plus a fifth hardcoded canary bot (`6797512084:AAGbJVoC...`) embedded in every kit's `girislog.php` and the panel's `dashboard.php` — this is the anti-researcher canary system, not an exfil bot. The canary token returned HTTP 401 Unauthorized on `getMe` at the time of analysis (revoked); it remains useful for hunting on stored copies of older kit RARs.

**Why this matters.** The split between `dekontbot` (card data) and `vergibot` (identity data) is the operationally significant finding. In most documented phishing operations, all victim data goes to a single channel and the operator monitors that channel. BellaMain *splits* the data streams: identity data fires immediately on Stage 1, separately from card data on Stage 2. The implications are:

- **Multi-person operation.** Different humans may monitor the two channels — one watching for high-value identity data, another approving bank-statement uploads and managing card data.
- **Data-broker workflow.** Identity data (TC Kimlik) and payment-card data have different downstream buyers in Turkish underground markets. Splitting them onto separate channels makes it easier to route them to different buyers without correlation.
- **Earlier alerting on the highest-value data.** Identity data fires *before* card data is even captured (Stage 1 vs Stage 2). The operator knows about a Turkish identity-theft target before the victim has even entered card details.

**Comparative context.** Cofense (2023) documented single-bot, single-channel credential exfiltration — the dominant commodity pattern. Sekoia.io EvilTokens (2024) documented bot separation at the *PhaaS marketplace* level (sales, template deployment, anti-bot protections) but not at the per-deployment victim-data-routing level. Netcraft Haozi (2025) documented operator-community channel separation (FAQs, after-sales support) but not per-deployment data-stream separation. Breakglass TMoscow Bot (2025) documented four-tier *role-based access control* in a web panel but expressed those roles within a single panel UI, not as distinct Telegram bot tokens. BellaMain's per-deployment four-bot architecture with identity-vs-card data-stream separation is more granular than any of these published patterns. (Confidence: MODERATE — BellaMain's design is the only documented instance; absence of prior reporting limits corroboration.)

**Detection.** The high-fidelity behavior is the hardcoded canary bot URI pattern in HTTP egress logs from any PHP host: `api.telegram.org/bot6797512084:AAGbJVoC*`. The token is revoked, but observation of attempted calls indicates an active BellaMain deployment. The operator-configured bot tokens for `adminbot`, `dekontbot`, `cekimbot`, and `vergibot` live in the panel's MySQL database and are not recoverable from source — they would surface only via a panel-database compromise or honeypot acquisition. See the Sigma rule for Telegram-bot-URI hunting in the [separate detection file](/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/).

### 5.4 TRUNCATE Evidence Destruction On Demand — Anti-Forensics

> **Analyst note:** Telegram-issued TRUNCATE commands let the BellaMain operator wipe entire stolen-data tables from a phone, in seconds, without ever logging into the panel UI. Combined with a backup-as-exfil command that ships a copy of everything to Telegram first, the operator's workflow on incoming heat is: snapshot to Telegram, then wipe the live panel. Standard "seize the server" forensic responses recover an empty database.

**Evidence basis.** `BellaMain/V5VgjLU0jsDe/manager.php` implements an admin Telegram bot with a 12-command vocabulary. Three of those commands are dedicated to data destruction:

| Command | Target table | Effect |
|---|---|---|
| `/hesapsil` | `hesaplar` (stolen credentials) | `TRUNCATE TABLE hesaplar` — deletes all captured marketplace credentials |
| `/kartsil` | `kartlar` (stolen cards) | `TRUNCATE TABLE kartlar` — deletes all captured payment cards (PAN + expiry + CVV) |
| `/girislogsil` | `girisyapanlar` (live victim tracker) | `TRUNCATE TABLE girisyapanlar` — deletes the live victim activity log |

These three commands are available **only via Telegram**, **only to the admin**. There is no in-panel web UI that exposes them. The operator must send the command to `adminbot` and the `manager.php` webhook executes the TRUNCATE on the panel database. No confirmation prompt; no audit log entry; the destruction is instantaneous on receipt.

**Why this matters — the anti-forensic workflow.** TRUNCATE alone would be ineffective for the operator (they would lose the data they want to monetize). The combination with `/yedek` (see Section 5.5) is what makes it useful: the operator first ships a private copy of the entire MySQL database to Telegram via `/yedek`, then issues `/hesapsil` + `/kartsil` + `/girislogsil` to wipe the live tables. The result is:

- **Live panel database is now empty** — a server seizure or forensic image yields no stolen credentials, cards, or victim logs.
- **Operator retains a complete copy** in their private Telegram chat history — out of reach of physical server forensics.
- **Workflow is mobile-friendly** — the operator can execute the full snapshot-and-wipe from a phone in under a minute.

This is purpose-built tradecraft. It is not a generic admin feature repurposed; the `/hesapsil` / `/kartsil` / `/girislogsil` naming uses Turkish verb stems (*sil* = delete) and targets the panel's stolen-data tables specifically. The standard adversary playbook of "rotate domain, abandon server" works fine against most phishing kits — BellaMain adds an explicit on-demand data-destruction layer on top of that, anticipating that operators may face hostile forensic acquisition rather than just abandonment.

**Realistic assessment.** This tradecraft is most effective against a specific scenario: law-enforcement seizure of the panel server with intent to recover victim data. It does *not* defeat: (1) network-traffic capture of stolen data in flight, (2) Telegram-side legal process targeting the operator's account, (3) recovery of the `panel` MySQL backups that may exist on the hosting provider's snapshot system, or (4) operator OPSEC failures (e.g., the operator's Telegram chat history is itself recoverable from the operator's device on arrest). It does, however, ensure that the live panel database is no longer a forensic prize at the moment of seizure — defenders should plan their evidence acquisition strategy accordingly (favor live-system memory and network-traffic capture over post-seizure disk forensics).

**Detection.** A PHP file containing `case "/hesapsil"`, `case "/kartsil"`, and `case "/girislogsil"` in a single switch statement is a BellaMain `manager.php` signature. The full 12-command set (`/yedek`, `/usom`, `/hesapsil`, `/kartsil`, `/girislogsil`, `/bloke`, `/aktif`, `/refkod`, `/reflist`, `/iban`, `/sifre`, `/komutlar`) is the strongest single-file YARA signature for the panel admin bot. See the YARA rule in the [separate detection file](/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/).

### 5.5 `/yedek` MySQL Backup-as-Exfil — Telegram as Cloud Storage

> **Analyst note:** The `/yedek` Telegram command ("yedek" is Turkish for "backup") dumps the entire panel MySQL database with mysqldump, ships the resulting .sql file to the operator's Telegram as a document attachment, then deletes the file from the panel host. The operator gets a complete database snapshot as a Telegram message — Telegram is treated as cloud storage for exfiltrated data.

**Evidence basis.** `BellaMain/V5VgjLU0jsDe/backup.php` is invoked when the operator sends `/yedek` to `adminbot`. The PHP source executes the following sequence:

1. `exec("mysqldump -u<user> -p<pass> --host=<host> <db> > <file>")` where the user, password, and database name are read from `database/config.php` and the file path is `BellaMain/V5VgjLU0jsDe/backups/yedek_<YYYY-MM-DD_HH-MM-SS>.sql`.
2. A multipart-body POST to `https://api.telegram.org/bot<adminbot_token>/sendDocument` uploads the .sql file as a Telegram document attachment to the operator's chat.
3. `unlink($file)` deletes the .sql file from the panel host — the local backup exists only transiently while the Telegram upload is in flight.

The chosen Telegram chat is operator-configured (the destination chat ID is stored in the panel database, not in source) — the analysis cannot directly verify which chat receives the dump without operator-side access. But the architecture is clear: every operator who runs `/yedek` gets a full MySQL snapshot of their panel database delivered to their Telegram chat history.

**Why this matters.** Several practical consequences:

- **Telegram-as-cloud-storage exfil.** The entire stolen-data corpus is exfiltrated via Telegram's standard document-upload API. There is no operator-controlled exfil server, no S3 bucket, no FTP — Telegram is the storage. Defenders cannot block the storage destination without blocking Telegram entirely (operationally impractical for most networks).
- **Combined with TRUNCATE, the anti-forensic loop closes.** As described in Section 5.4, `/yedek` is the prerequisite to safe TRUNCATE. The combination is what makes the workflow viable.
- **Operator OPSEC weakness on the panel host.** The `mysqldump` command line passes the database password as `-p<plaintext>`, which means **the plaintext password is visible in the panel host's process listing** at the time of the dump. Anyone with `ps`/`tasklist` access on the panel host during a `/yedek` invocation can capture the MySQL password — a minor operator OPSEC weakness, but it does mean a defender with even brief host access (e.g., a cooperating hosting provider during an incident) can capture credentials trivially.
- **Recoverability via Telegram legal process.** The exfiltrated .sql files exist in the operator's Telegram chat history. If the operator's Telegram account is identified (e.g., via the privacy-restricted `@AresRS34` alias), legal process to Telegram could in principle recover the dumps. Telegram has historically been less cooperative with Western law enforcement than most cloud providers, but cooperation has increased post-2024.

**Detection.** Two distinctive signatures:

- **Process creation telemetry on Linux/Windows panel hosts** showing `mysqldump` invoked by a `php` or `php-fpm` parent process, with the password visible on the command line (`-p<plaintextpw>`). High-fidelity in any context — production DBA workflows do not invoke mysqldump from a PHP web request.
- **Network signature on operator-side egress proxy.** A multipart-body POST to `api.telegram.org/bot<10-digit>:<35-char>/sendDocument` with a filename matching the regex `yedek_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.sql` is a BellaMain `/yedek` exfil signature.

See the Sigma rule for process-creation detection and the Suricata signature for Telegram-bot URI matching in the [separate detection file](/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/).

### 5.6 70/30 TRX/TRON Payout Flow via Live Binance TRXTRY Rate

> **Analyst note:** BellaMain's PhaaS revenue model settles operator earnings in TRX cryptocurrency on the TRON network at a fixed 70/30 split. The panel queries Binance's public TRXTRY ticker at every withdrawal to convert TRY-denominated balances to whole-TRX payouts. The Telegram approval button on a victim's bank-statement upload is literally the payment-authorization mechanism for this revenue split. No prior public PhaaS reporting documents TRX/TRON as the affiliate settlement currency or a per-victim approval flow as the payment authorization gate.

**Evidence basis.** The revenue flow is implemented across three files:

1. **`tgdekont.php` (per kit) — revenue accrual.** When a victim uploads a fake bank statement (`dekont`) as "proof of payment", `tgdekont.php` fires a Telegram message to `dekontbot` with inline `[Onayla]` / `[Reddet]` buttons and the victim's declared transaction amount. When the panel administrator clicks `[Onayla]`, the webhook hits `tgdekont.php`, which executes:
   ```sql
   UPDATE kullanicilar SET bakiye = bakiye + (<amount> * 0.7) WHERE id = <operator_id>;
   UPDATE kullanicilar SET toplamalinan = toplamalinan + (<amount> * 0.7) WHERE id = <operator_id>;
   ```
   The literal `* 0.7` multiplier in source confirms the 70/30 split: the operator gets 70% of the victim's declared amount credited to their balance, the panel administrator retains the implicit 30%.

2. **`V5VgjLU0jsDe/cekimbot.php` — withdrawal calculation.** When an operator requests a withdrawal (via the Telegram withdrawal flow), `cekimbot.php`:
   - Validates the requesting Telegram UID against `$authorizedUsers = [5606327063, 6594066326]`.
   - Queries `https://api.binance.com/api/v3/ticker/price?symbol=TRXTRY` for the live TRX/TRY exchange rate.
   - Reads the requesting operator's `bakiye` (TRY balance).
   - Deducts a 0.5% TRY fee and enforces a 500 TRY minimum withdrawal.
   - Divides the post-fee TRY amount by the Binance TRXTRY rate and floors to the nearest whole TRX.
   - Sends the calculated payout (whole TRX, destination wallet) to the admin Telegram for manual TRX transfer execution.

3. **Operator withdrawal request UI.** Operators submit a destination TRX/TRON wallet address through the panel; the wallet is stored in `kullanicilar.cuzdan` and forwarded to the admin Telegram on withdrawal approval.

**Why this matters.** Several practical observations:

- **Telegram-button-as-payment-authorization is a novel pattern.** When the admin clicks `[Onayla]` on a Telegram message, the panel's operator balance updates by 70% of the victim's amount. The Telegram approval is the literal payment-authorization mechanism for the PhaaS revenue split. Cofense, Sekoia, Netcraft, and Breakglass have not documented this exact pattern in any prior PhaaS analysis. Commercial PhaaS services typically charge fixed-USDT subscription fees up front (Tycoon 2FA, Sneaky 2FA, Haozi) — they do not embed a per-victim commission flow with Telegram-button approval.
- **TRX/TRON as settlement currency is also novel in public PhaaS reporting.** Most documented services use USDT (Tether) for affiliate payments. TRX has practical advantages for Turkish-targeted operations: low transaction fees enable micro-payouts (the 500 TRY minimum corresponds to roughly 50 TRX at typical rates), the TRON network is fast and reliable, transactions are pseudonymous, and chain analysis is harder than on more analyzed chains. Turkey also has high consumer cryptocurrency adoption — operators can convert TRX to TRY at Turkish exchanges with limited friction.
- **Live Binance API usage.** The panel queries Binance's public ticker API directly — no API key, no authentication. This is a legitimate-use pattern for crypto-pricing applications; Binance does not flag it as suspicious. The traffic on the operator's egress to `api.binance.com` is high-FP context (legitimate crypto/finance applications also query this endpoint) and not useful as a detection signature on its own.
- **Operator OPSEC trace.** The two `authorizedUsers` Telegram UIDs (`5606327063`, `6594066326`) are admin pivots — they identify two specific Telegram accounts that hold withdrawal-approval authority for this panel deployment. Any future link of these UIDs to named accounts (via paid TI, Telegram legal process, or HUMINT) is a high-value attribution lead.

**Detection.** Direct detection of the revenue flow from the network layer is difficult — the Binance API call is high-FP, the Telegram approvals are HTTPS, and the panel's MySQL writes are not visible to defenders without panel-host access. The strongest detection is on the panel-host process and source-file inventory:

- **Source-file detection.** A PHP file containing the literal string `* 0.7` near an `UPDATE kullanicilar SET bakiye` is the 70/30 split signature. Cross-reference with the `cekimbot.php` Binance API query and the `$authorizedUsers` array with two hardcoded Telegram UIDs to confirm.
- **Telegram-UID hunting.** The UIDs `5606327063` and `6594066326` are diagnostic. Any future investigation that surfaces these UIDs in unrelated Telegram-bot configurations or chat histories is a strong cross-incident link.

### 5.7 Wadanz Developer Pseudonym — Code-Level Authorship Signature

> **Analyst note:** Programmers occasionally sign their code with their handle, especially in underground communities where reputation matters. BellaMain's panel signs the developer pseudonym "Wadanz" into the function names of the session-encryption helpers — `sifreleWadanz()` (encrypt) and `sifrecozWadanz()` (decrypt). This is a stable, cross-deployment author marker that survives any operator-level rebranding of the panel.

**Evidence basis.** `BellaMain/database/fonk.php` defines two utility functions:

```
function sifreleWadanz($data) {
    return base64_encode(gzcompress(serialize($data)));
}

function sifrecozWadanz($data) {
    return unserialize(gzuncompress(base64_decode($data)));
}
```

These functions are used by `signin.php`, `signup.php`, and `database/cookie.php` to encode/decode operator session payloads stored in a 365-day-lifetime cookie. The `Wadanz` suffix is not a transliteration of any standard PHP idiom (`sifrele` is Turkish for "encrypt"; `sifrecoz` is "decrypt"; `Wadanz` has no Turkish meaning we can identify and is not a Turkish word). The most plausible interpretation is that `Wadanz` is the developer's pseudonym, baked into the function names as an authorship signature.

**Cross-sample stability.** The function names are not parameterized, configurable, or generated — they are literal strings hard-coded into the panel's core utility file. Any forked or rebranded BellaMain deployment that re-uses the same `database/fonk.php` would carry the same function names. A grep on `sifreleWadanz` across any PHP corpus, open-directory archive, or VirusTotal Intelligence sample set would surface every BellaMain-derivative panel by the same developer.

**Why this matters — caveats and confidence.** The pseudonym claim carries three caveats:

- **Could be a decoy.** The operator may have deliberately seeded `Wadanz` into the function names to mislead investigators. This is plausible but unusual — operators who plant decoys typically do so in operator-facing strings (banner text, error messages, comments), not in function names where the decoy serves no operational purpose and creates a unique signature that defenders can hunt.
- **Could be a team handle.** "Wadanz" could be the handle of a small team or a brand identity rather than an individual developer's pseudonym. This does not affect detection value — the cross-sample pivot still works.
- **Could be a vendor.** "Wadanz" could be a third-party PHP framework or library author whose code BellaMain reuses. A search of GitHub, GitLab, Bitbucket, PHP Packagist, and the general web for any legitimate PHP project, library, or author by this name returned zero results. This makes the decoy/team/vendor explanations less likely but does not formally rule them out.

**Confidence:** MODERATE. The function-name pair is a strong distinct-actor marker — operators rarely sign panels with their handles, and the pattern is consistent across all panel files observed. The named-actor pivot (resolving "Wadanz" to a person or known underground handle) is INSUFFICIENT — no public TI source surfaces this pseudonym; cross-sample PHP corpus search returned zero hits. The expected upgrade path is paid-TI cross-reference (VirusTotal Intelligence, Recorded Future, Flare) or community recognition of the pseudonym after this publication.

**Detection.** A PHP file containing both `function sifreleWadanz` and `function sifrecozWadanz` is the strongest single-string PHP-corpus signature for BellaMain. False-positive risk is vanishingly low — this exact function-name pair does not appear in any known legitimate PHP framework, library, or open-source project. See the YARA rule `TOOLKIT_BellaMain_WadanzFunctions` in the [separate detection file](/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/). The Wadanz author signature is mapped to ATT&CK T1587.001 (Develop Capabilities: Malware) in [Section 8](#8-mitre-attck-mapping) — that row is the canonical cross-investigation pivot point for tracking BellaMain-derivative panels by the same developer.

### 5.8 Seven Named Turkish Brand Impersonations — The Target Surface

The seven kits replicate Turkey's highest-traffic consumer platforms across four categories. Each kit loads legitimate CDN assets from the impersonated platform to maximize visual fidelity and is structurally a copy of a shared template (per-kit RAR archive structure is near-identical, varying only in branding and the impersonated-platform domain).

| Kit | Brand | Category | VT detection | Notable context |
|---|---|---|---|---|
| `Dolap.rar` | [Dolap](https://dolap.com) | Second-hand fashion marketplace (Trendyol/Alibaba) | 0/62 | VT submission path `topluphis/` = Turkish for "bulk phishing"; documented 2024 WhatsApp-redirect phishing pattern. |
| `Letgo.rar` | Letgo Turkey | Second-hand goods marketplace | 1/61 | Only kit with non-zero VT detection. |
| `Pttavm.rar` | [PTT AVM](https://www.pttavm.com) | Postal-service e-commerce (PTT AŞ) | 0/61 | Largest kit archive (4.9 MB). PTT has issued multiple public fraud warnings on `ptt.gov.tr`. |
| `sahibinden.rar` | [Sahibinden](https://sahibinden.com) | Dominant Turkish classifieds platform | 0/62 | Most-tracked kit (7 unique VT submitters). Documented "Param Güvende" escrow-feature exploitation. |
| `shopier.rar` | [Shopier](https://www.shopier.com) | Payment infrastructure / merchant checkout | 2/59 | Highest VT detection rate of any BellaMain kit. Card-capture is least suspicious here because victims expect to enter payment details on a Shopier-branded page. |
| `turkcell.rar` | [Turkcell mobile](https://m.turkcell.com.tr) | Telecommunications (~40M subscribers) | 0/62 | Telecom account compromise enables SIM-swap chain for downstream 2FA bypass. |
| `Kargo.rar` | Yurtiçi Kargo | Cargo / parcel tracking | 0/62 | Cargo SMS phishing widely documented in Turkish consumer complaints. |

**Targeting logic.** The seven brands collectively cover Turkey's everyday consumer-transaction surface — selling on classifieds, postal shipping, cargo tracking, mobile bill payment, small-merchant checkout, second-hand fashion. A victim conditioned to receiving legitimate SMS/email notifications from any of these platforms is BellaMain's target persona. The lure-delivery vector (SMS, email, social-media, search-ad) is operator-configurable per campaign — Stage 1 analysis did not recover specific delivery infrastructure beyond the kit-distribution server itself.

**Lure fidelity.** Each kit's `index.php` loads the impersonated platform's actual CDN assets (`https://cdn.dolap.com/web/css/bootstrap.min.css` for the Dolap kit, equivalent paths for each other kit) plus Google Tag Manager container `GTM-K7F5T5N` and New Relic RUM beacons (`https://js-agent.newrelic.com/nr-1026.min.js`). The combination produces a page that loads the same fonts, the same CSS, the same client-side telemetry as the genuine platform. Visual fidelity is high; the only differences a victim might notice are the URL (operator-controlled domain) and the eventual payment-and-identity capture flow.

**Code structure stability.** All seven kits share the same template structure: the same `database/connect.php` MySQL credentials (`jakartaxdw` / `dbjakartaxdw` / `W!@25#8Tb2gxq15`), the same hardcoded canary Telegram bot token (`6797512084:AAGbJVoC...`), the same `girislog.php` anti-researcher canary, the same `tgvergi.php` and `tgdekont.php` Telegram exfil patterns. The per-kit `kartayyil` field concatenation (`$kartay . " / " . $kartyil`) — preserving the literal " / " separator — suggests a single shared template the kits were generated from with brand-specific HTML/CSS substitution.

### 5.9 Invite-Only Operator Gating with One-Time-Consume Referral Codes

> **Analyst note:** BellaMain's `signup.php` requires a referral code minted by the panel administrator via Telegram. Each code is consumed (deleted from the database) on first use. This is an invite-only multi-operator licensing model — the administrator controls who can become an operator on the panel, and at what cadence. It is what makes BellaMain a PhaaS marketplace rather than a single-tenant phishing kit.

**Evidence basis.** Three connected mechanisms implement the gating:

1. **`signup.php` referral-code check.** The self-registration flow reads a `ref_code` POST parameter and validates it against the `refkodlari` table:
   ```sql
   SELECT * FROM refkodlari WHERE ref_code = '<input>';
   ```
   If no row matches, registration fails. If a row matches, the row is DELETED before the registration proceeds — making the code one-time-use only.

2. **`/refkod` admin Telegram command in `manager.php`.** The panel administrator generates a new referral code by sending `/refkod` to `adminbot`. The webhook generates a fresh random string, INSERTs it into `refkodlari`, and replies to the admin with the code value. The admin can then privately distribute the code to a prospective operator (e.g., via Telegram DM, an underground forum, a private channel).

3. **`/reflist` admin Telegram command.** The admin can list all currently-valid (unused) referral codes by sending `/reflist`. This is the inventory-management UI for the licensing system.

The gating means **no operator can register on the panel without admin approval** in the form of a referral code. The code is one-time-use, so a single code does not enable many sub-operators to register from one leak. The architecture supports a deliberate operator-onboarding cadence controlled by the panel administrator.

**Why this matters.** Three implications:

- **Multi-operator licensing model implied.** The combination of self-registration with admin-controlled invite codes is the architectural signature of a marketplace PhaaS — many operators can run independent campaigns against the same panel administrator, paying 30% commission per approved hit. The administrator is incentivized to maintain panel quality and tradecraft (USOM monitor, TRUNCATE, four-bot architecture) because their revenue depends on operator success across the entire fleet.
- **Resilience against operator-level takedown.** Taking down or arresting a single operator does not stop the panel. Other operators (registered with their own referral codes) continue running campaigns. The admin retains the codebase, the infrastructure, and the licensing system.
- **The "downstream customer" attribution surface.** The `kullanicilar` MySQL table holds rows for every registered operator — their username, Telegram links, balance, total earnings, withdrawal wallet. A live acquisition of this table would identify every downstream BellaMain operator. We did not acquire the live DB; the operator list is one of the highest-value missing pieces of evidence.

**Detection.** A PHP file containing `DELETE FROM refkodlari` next to a `SELECT * FROM refkodlari WHERE ref_code` is the BellaMain `signup.php` signature. The full referral-system code (signup.php + manager.php /refkod + /reflist handlers) is the strongest source-level evidence that a discovered PHP panel implements an invite-only multi-operator licensing model rather than a single-tenant kit.

---

## 6. Static Analysis Findings

### 6.1 File Inventory

The recovered panel archive `BellaMain.zip` (18.36 MB, SHA256 `f791fae41cdd3f141221d1783ed4779c839de7fc834ff4fc80a5d7f74b11ff88`, MD5 `7055c03da7660b196cb46426fb7f2986`, SHA1 `bbfb41447fd60907bc529d6cf786827c9ec2a041`) expands to 65 PHP files across 14 directories:

```
BellaMain/
├── signin.php                          Operator login (JSON response codes: tamam/yanlis/bos)
├── signup.php                          Self-registration (referral-code-gated)
├── logout.php                          Session teardown
├── dashboard.php                       Operator control panel
├── index.php                           Panel root view
├── kt.php                              CORS shim (returns "OK", Access-Control-Allow-Origin: *)
├── 404.php                             Custom 404
├── database/
│   ├── config.php                      DB credentials (plain-text)
│   ├── connect.php                     PDO connection factory
│   ├── cookie.php                      Session / cookie management
│   ├── fonk.php                        Utility funcs — sifreleWadanz, sifrecozWadanz, SEO slug
│   └── post.php                        Central AJAX POST dispatcher (~350 lines)
├── includes/
│   ├── editforms/                      Admin per-kit config forms (8 files)
│   ├── forms/                          Credential submission handlers (10 files)
│   ├── girislog/                       Live victim tracker widgets (6 files)
│   └── deletes.php                     Data deletion endpoint
├── images/                             Operator avatar uploads
└── V5VgjLU0jsDe/                       Obfuscated admin directory (12 random chars)
    ├── backup.php                      MySQL dump → Telegram document exfil
    ├── cekimbot.php                    Withdrawal approval Telegram webhook
    ├── manager.php                     Admin Telegram bot — full command set
    ├── usmcheck.php                    USOM (Turkey CERT) blocklist monitor
    └── backups/                        Transient SQL dump storage
```

The 12-character random admin directory name `V5VgjLU0jsDe` is a deliberate non-guessable path. Common admin-directory wordlist attacks (`admin`, `manager`, `panel`, `control`, `dashboard`) will not surface it — only operator-shared knowledge or directory-listing exposure (as on this server) reveals it.

**Seven kit RAR archives** sit alongside the panel ZIP on the open directory, each between 1.3 MB and 4.9 MB:

| Kit RAR | SHA256 | Size | VT detection | First VT seen |
|---|---|---|---|---|
| `Dolap.rar` | `2c656360c4e58854dca35ff21b3fc62db41155ca76f8568ecc18fa52aa38fb31` | 1.3 MB | 0/62 | 2024-04-18 |
| `Kargo.rar` (Yurtiçi Kargo) | `705793c011fdfe17941700a3bf42eee0ba2ebdc04870ce19779ea528b3565fac` | 1.4 MB | 0/62 | 2024-04-18 |
| `Letgo.rar` | `e21fb63a3b4d65a3d48dec1bf17a84a414482f819b93cb8d77a81852dc34c95f` | 2.6 MB | 1/61 | 2024-04-18 |
| `Pttavm.rar` | `ee9d4fccebbf73fb33980da15142bc71e5d9661d1bc583c2b09b77490065efd9` | 4.9 MB | 0/61 | 2024-04-18 |
| `sahibinden.rar` | `b2f4f1617577d14612b30a54a733b15af809c399f325717b4329c13aaa4c915c` | 2.6 MB | 0/62 | 2024-04-18 |
| `shopier.rar` | `504b1a30ce7060eafa7b2a3f6249c954a0be6ce1d2930e03b030434cb232600a` | 2.5 MB | 2/59 | 2024-04-18 |
| `turkcell.rar` | `219cd4f6177a2358ec7f06b230d611f47e1049fcb3e2b44d06ec410b336382b0` | 1.4 MB | 0/62 | 2024-04-18 |

All seven kits share the same first-VT-seen date (2024-04-18), consistent with a single batch submission — likely by a Turkish security researcher whose submission directory on `Dolap.rar` was named `topluphis/` (Turkish for "bulk phishing"). The panel ZIP `BellaMain.zip` was **never** submitted to VirusTotal before this investigation — operators distributed the kits publicly enough to be sampled but kept the admin backend off public infrastructure.

*See [Section 10](#10-indicators-of-compromise-reference) and the [machine-readable IOC feed](/ioc-feeds/bellamain-turkish-phaas-79-137-192-3-20260516-iocs.json) for the canonical IOC inventory.*

**Entropy observation.** The ZIP archive's overall entropy of 7.9998 across 4699 chunks (4696 high-entropy) is the standard signature of compressed PHP source — DEFLATE compression of plain text — not packed or encrypted malware. The PHP source files inside are uncompressed and have normal entropy.

### 6.2 MySQL Schema (inferred)

The panel's behavior is most legibly captured by its MySQL schema, inferred from the PHP code's table reads and writes:

| Table | Purpose | Key writes |
|---|---|---|
| `panel` | 1-row global config | UPDATE via admin forms (Telegram bot tokens, IBAN, payout config) |
| `kullanicilar` | Operator accounts | INSERT on register; UPDATE on dekont approval (`bakiye += amount * 0.7`); UPDATE on Telegram linking |
| `girisyapanlar` | Live victim heartbeat tracker | INSERT/UPDATE every 3 s from victim browser; DELETE on 60 s inactivity; TRUNCATE on `/girislogsil` |
| `kartlar` | Stolen payment cards | INSERT on `ibanlaodeme.php` submission; TRUNCATE on `/kartsil` |
| `hesaplar` | Stolen marketplace credentials | INSERT on `login.php` submission; TRUNCATE on `/hesapsil` |
| `cekimtalepleri` | Operator withdrawal requests | INSERT on operator request; UPDATE on admin approval/rejection |
| `refkodlari` | Referral codes for self-registration | INSERT on `/refkod` Telegram command; DELETE-on-use during `signup.php` |
| `ilan_dolap`, `ilan_letgo`, `ilan_shopier`, `ilan_sahibinden`, `ilan_turkcell` | Per-kit listing rosters (the fake "products" shown to victims) | UPDATE via `/bloke` (set `ilandurum=0`) / `/aktif` (set `ilandurum=1`) |

All seven kits and the panel share a single MySQL database `jakartaxdw` (user `dbjakartaxdw`, password `W!@25#8Tb2gxq15`) — designed for co-deployment on the same panel host. The hardcoded credential triple appears in eight separate PHP files (panel + 7 kits' `database/connect.php`).

### 6.3 Notable Strings — Operator Identity and Anti-Researcher Canary

**Operator identity strings (hardcoded in source):**

| String | Location | Significance |
|---|---|---|
| `Wadanz` | Function-name suffix on `sifreleWadanz` / `sifrecozWadanz` in `database/fonk.php` | Developer pseudonym; cross-sample author pivot |
| `@AresRS34` | Anti-researcher Turkish profanity string in kit `girislog.php` (all 6 kits) | Operator Telegram alias; corresponds to a real privacy-restricted account |
| `2tUgyO@H9E!4CuQ` | Cookie name set on operator login in `signin.php` | Distinctive 15-char cookie name; searchable in proxy logs |
| `V5VgjLU0jsDe` | Admin directory name | 12-char random path unique to BellaMain |
| `jakartaxdw` / `dbjakartaxdw` / `W!@25#8Tb2gxq15` | Hardcoded MySQL credential triple | Cross-kit consistency proves single-operator control |
| `GTM-K7F5T5N` | Google Tag Manager container in all kit pages | Provenance unknown (operator-registered or hijacked legitimate container) |
| `Sazan IP` / `Sazan Kod` / `Sazan Cihaz` | Anti-researcher canary variables in kit `girislog.php` | "sazan" = Turkish for "carp" / slang for "sucker" |
| `Usom Yedik Atış Stop` | USOM alert message in `usmcheck.php` | Literal Turkish "we got caught by USOM, stop the attack" |
| `BLOKE ATIŞ STOP!` / `AKTİFİZ DEVAMKE!` | Kill-switch / resume broadcasts in `manager.php` | Distinctive operator-self-identifier strings |

**Telegram identifiers (hardcoded in source):**

| Identifier | Location | Role |
|---|---|---|
| `6797512084:AAGbJVoC0zcKWYPbFG8oc_bACPn6gUEye_E` | All 6 kits' `girislog.php` + panel `dashboard.php` | Anti-researcher canary bot token — **REVOKED** (HTTP 401 on `getMe`) |
| `-1002104835510` | Same as above | Canary exfil group/channel ID |
| `-1001817323952` | `manager.php` + `usmcheck.php` | Operator announcement group ID |
| `5606327063` | `cekimbot.php` `$authorizedUsers[0]` | Authorized withdrawal approver UID #1 |
| `6594066326` | `cekimbot.php` `$authorizedUsers[1]` | Authorized withdrawal approver UID #2 |

**External URLs called from operator infrastructure at runtime:**

- `https://www.usom.gov.tr/url-list.txt` — Turkey CERT blocklist polled by `usmcheck.php`. **High-FP context** — legitimate Turkish security tooling also fetches this URL.
- `https://api.binance.com/api/v3/ticker/price?symbol=TRXTRY` — Live TRX/TRY rate query in `cekimbot.php`. **High-FP context** — legitimate crypto/finance applications query this endpoint.
- `https://api.telegram.org/bot<token>/...` — Bot API for the 4 operator-configured bots + 1 hardcoded canary.
- `https://cdn.dolap.com/web/css/bootstrap.min.css` (and equivalent per kit) — Legitimate CDN asset loading from impersonated platforms.
- `https://bam.nr-data.net/` + `https://js-agent.newrelic.com/nr-1026.min.js` — New Relic RUM beacons carried over from scraped legitimate sites.

### 6.4 Admin Path Obfuscation

The 12-character random admin directory name `V5VgjLU0jsDe` is non-guessable via common wordlist attacks. The path is exposed only because the open directory listing on `79.137.192.3` includes the `BellaMain/V5VgjLU0jsDe/` subdirectory — a panel deployed without an open directory listing would have the admin directory effectively hidden. The 12-character length and the mixed-case alphanumeric character set is consistent with a `random_bytes(8)` + `base64url` approach; the same naming pattern would surface on a forked deployment.

### 6.5 Shared Session Cookie and PHP Object Injection Surface

The panel and all seven kits share a single session cookie name `2tUgyO@H9E!4CuQ` set with a 365-day lifetime (`time() + 60 * 60 * 24 * 365`). Once an operator logs into the panel, the same cookie is honored by all kits' AJAX endpoints — which means an operator authenticated to the panel can also write to kit-side endpoints from the same browser session. The cookie value is `sifreleWadanz()`-encoded but **also unserialize()'d on read** (`sifrecozWadanz()` calls `unserialize(gzuncompress(base64_decode($data)))`) — this is a **PHP object injection surface**: an attacker who can supply an arbitrary cookie value can potentially achieve PHP-level RCE on the panel host via `__wakeup()` or `__destruct()` magic methods if any class in the panel exposes a suitable gadget chain. We did not weaponize this, but it is a defensive opportunity if any defender obtains panel-host access lawfully (e.g., during incident response with hosting-provider cooperation).

---

## 7. Dynamic Findings — Behavioral Analysis

> **Analyst note on "dynamic" analysis here.** BellaMain is server-side PHP source, not a PE binary, so there is no malware-detonation sandbox to run. "Dynamic" findings below are reconstructed from the source code's execution paths — the behaviors that *will* execute when the panel is deployed and a victim hits a kit page. Where direct external observation was possible (Telegram bot status, live URL endpoints on `79.137.192.3`), those are noted. We did not stand up a live MySQL + PHP instance of the panel.

### 7.1 Operator-Workflow Reconstruction (Chronological)

The clearest way to render BellaMain's operational behavior is to walk a single victim through the funnel and document what happens at each step from both the victim and the operator sides. Figure 3 lays out the seven-minute chronology with operator-side correspondence at each timestamp.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/bellamain-turkish-phaas-79-137-192-3-20260516/bellamain-victim-funnel-chronology.svg" | relative_url }}" alt="Vertical-chain infographic titled 'BellaMain Victim Funnel — Operator Workflow Reconstruction' showing a 6-stage 7-minute chronology with both victim and operator actions. Stage 1 at T+0:00 is orange and labeled 'Lure delivery (out of scope)': victim receives SMS, email, social-media DM, or sponsored search ad with a kit URL; delivery vector is operator-configurable and not recovered from open-directory artifacts; no Telegram activity yet. Stage 2 at T+0:30 to T+1:30 is orange and labeled 'Kit page render plus credentials': victim lands on kit index.php with legitimate CDN assets, GTM-K7F5T5N, and New Relic RUM; girislog.php fires 3-second heartbeats to the girisyapanlar table for the panel green-dot UI; login.php INSERTs into hesaplar with no Telegram alert. Stage 3 at T+3:30 is red and labeled 'Stage 1 capture — TC Kimlik (national ID) — vergibot fires': victim enters TC Kimlik number, full name, and phone on kartlaodeme.php; tgvergi.php sends a Telegram message via vergibot_token; this is the FIRST Telegram alert in the funnel. Stage 4 at T+5:00 is red and labeled 'Stage 2 capture — payment card (no immediate alert)': victim enters PAN, expiry, CVV on ibanlaodeme.php; INSERT INTO kartlar; alert deferred. Stage 5 at T+6:30 to T+6:45 is red and labeled 'Dekont upload plus operator approval — dekontbot fires': victim uploads fake bank statement to dekontlar/; tgdekont.php sends Telegram message with inline Onayla and Reddet buttons; operator approval fires UPDATE kullanicilar SET bakiye = bakiye + amount*0.7. Stage 6 at T+7:00 is deep-red and labeled 'Closure — full identity plus card plus statement in operator hands': victim sees tamamlandi.php; operator now holds TC Kimlik, name, phone, PAN+expiry+CVV, fake dekont image. Footer detection anchors: api.telegram.org egress paired with PHP-host context, the /V5VgjLU0jsDe/ admin URI, /girislog.php heartbeat POSTs, and the ?lg= URL canary probe that triggers the troll branch.">
  <figcaption><em>Figure 3: Victim funnel chronology. The seven-minute walk-through shows the staggered Telegram alerts — `vergibot` fires at Stage 1 with identity data before card data is even captured, and `dekontbot` fires at Stage 2 with inline approval buttons that drive the operator's 70 percent bakiye accrual.</em></figcaption>
</figure>

**T+0:00 — Lure delivery (out of scope).** A victim receives an SMS, email, social-media DM, or sponsored search ad with a link to a BellaMain kit domain. The lure-delivery vector is operator-configurable per campaign; Stage 1 analysis did not recover specific lure-delivery infrastructure beyond the kit-distribution server.

**T+0:30 — Kit page render.** The victim's browser loads the kit's `index.php` (e.g., for the Dolap kit, a fake Dolap marketplace product listing). Page loads legitimate Dolap CDN assets (`https://cdn.dolap.com/...`), the operator's Google Tag Manager container `GTM-K7F5T5N`, and embedded New Relic RUM beacons. Visual fidelity is high — the page is visually indistinguishable from the real Dolap product page except for the URL.

**T+0:33 (first heartbeat) — Victim activity tracking.** Page JavaScript fires the first AJAX POST to the kit's `girislog.php`, sending the current page label (`sayfa`), operator username (`ekleyen`), fake product name (`urunadi`), and victim IP. The panel UPSERTs into `girisyapanlar`. The operator's dashboard polls `girisyapanlar` and displays a green dot next to the active victim. The heartbeat repeats every ~3 seconds for the victim's session duration.

**T+1:30 — Credential entry.** Victim enters Dolap username and password on `login.php`. Credentials INSERT into `hesaplar`. No immediate Telegram alert at this stage — the operator views captured credentials via the panel dashboard.

**T+2:00 — Funnel progression.** Victim is led through a sequence of pages: `adres.php` (address) → `ilan.php` (product confirmation) → `odeme.php` (payment options) → `kartlaodeme.php` (Stage 1 capture).

**T+3:30 — Stage 1 capture: identity data.** Victim enters name + phone + Turkish national ID (TC Kimlik Numarası) on `kartlaodeme.php`. `tgvergi.php` **immediately fires** via `vergibot_token`, sending the operator a Telegram message containing: TC Kimlik Numarası, full name, phone, fake transaction amount, date/time. This is the first Telegram alert in the funnel — identity data fires *before* card data is even captured.

**T+5:00 — Stage 2 capture: payment card.** Victim continues to `ibanlaodeme.php`. Enters PAN, expiry (MM/YYYY), CVV. Card data INSERTs into `kartlar`. No immediate Telegram alert at this stage.

**T+6:30 — Dekont upload.** Victim is led to upload a fake bank statement ("proof of payment") as a `dekont` image. File stored in the kit's `dekontlar/` directory. `tgdekont.php` fires Telegram message to operator via `dekontbot_token` with inline `[Onayla]` (Approve) / `[Reddet]` (Reject) buttons and the victim's declared transaction amount.

**T+6:45 — Operator approval.** Operator (on phone) clicks `[Onayla]` in Telegram. Webhook hits `tgdekont.php`. Panel executes: `UPDATE kullanicilar SET bakiye = bakiye + (amount * 0.7) WHERE id = <operator>;` plus `toplamalinan` update. The operator's PhaaS-commission balance increases by 70% of the victim's declared amount.

**T+7:00 — Victim closure.** Victim sees `tamamlandi.php` ("Transaction complete") page and is led to believe their payment has been processed. Victim now has full identity, card, and bank-statement data in operator possession.

**Anti-researcher branch (parallel possibility):** If the victim's request URL contains the `?lg=` GET parameter, the kit short-circuits before any heartbeat: fires a Telegram alert to the canary group `-1002104835510` with the IP + user agent + `?lg=` value, then returns a plaintext Turkish-profanity troll response naming `@AresRS34`. Researchers and automated phishing-detection sandboxes probing the kit with the conventional `?lg=` URL-canary parameter will trigger this branch.

### 7.2 Operator-Side Outbound Network Activity

When the panel runs, the following outbound HTTPS calls are made from the operator's server:

| Endpoint | Trigger | Frequency | Purpose |
|---|---|---|---|
| `https://api.telegram.org/bot<token>/sendMessage` | Every credential capture, dekont upload, withdrawal request, `/usom` check, kill-switch, manager command | Per-event | C2 / exfil notifications |
| `https://api.telegram.org/bot<token>/sendDocument` | `/yedek` command | Per-backup | MySQL dump exfil — full database as Telegram document |
| `https://www.usom.gov.tr/url-list.txt` | `/usom` command or `usmcheck.php` invocation | On demand | Polls Turkey CERT blocklist for any of 8 kit domains |
| `https://api.binance.com/api/v3/ticker/price?symbol=TRXTRY` | Operator withdrawal request | Per-withdrawal | TRX/TRY rate query for payout calculation |
| `https://api.telegram.org/bot<token>/setWebhook` | Panel `post.php` initialization | Once per deployment | Sets Telegram bot webhook endpoints to panel-hosted PHP files |

*Only the canary bot token (above, REVOKED) is recoverable from source. Operator-configured bot tokens for `adminbot`/`dekontbot`/`cekimbot`/`vergibot` live in the panel MySQL `panel` table and would surface only via DB compromise or honeypot acquisition — see [§5.3](#53-four-bot-telegram-c2-with-role-separation) for the structural detection approach.*

**Beaconing characterization.** The panel does **not** beacon on a fixed interval — it is event-driven. There is no schedule. Each credential or card capture triggers an immediate Telegram outbound call. The closest thing to beaconing is the live victim heartbeat (3-second AJAX cycle) — but that runs **from the victim's browser to the panel**, not from the panel outbound. There is no DGA, no fast-flux, no beacon-interval signature to detect.

**Encryption.** All operator-side C2 and exfil traffic uses TLS over standard HTTPS to public APIs (Telegram, Binance, USOM). The Telegram payloads themselves are unencrypted JSON message bodies — Telegram terminates TLS and stores the content in its own database. No custom encryption layer beyond standard HTTPS.

**User agents.** PHP `file_get_contents()` and cURL calls use default user agents unless explicitly set. No custom UA observed in panel code — this is not a useful detection signature (too generic).

### 7.3 Filesystem Operations on Panel Host

When the panel runs, the following file operations occur on the operator's web server:

| Path / pattern | Operation | Trigger |
|---|---|---|
| `BellaMain/V5VgjLU0jsDe/backups/yedek_<YYYY-MM-DD_HH-MM-SS>.sql` | CREATE (via `mysqldump`) → DELETE (via `unlink()`) | `/yedek` Telegram command — file exists only briefly while upload is in flight |
| `BellaMain/images/<operator_id>.<ext>` | CREATE (`move_uploaded_file`) | Operator avatar upload via `editprofil.php` |
| `<kit>/dekontlar/<random>.<ext>` | CREATE | Victim uploads fake bank statement — file retained until operator approves/rejects via Telegram |

No host-malware DLLs, EXEs, or scheduled tasks are dropped — BellaMain has no Windows host footprint. The only file operations are PHP runtime artifacts on the operator's web server.

### 7.4 Process Activity on Panel Host

When `/yedek` is invoked, `backup.php` calls `exec("mysqldump -u<user> -p<pass> --host=<host> <db> > <file>")` — this spawns the `mysqldump` binary on the panel host. This is the only `exec()` call in the panel source. **The plaintext DB password appears on the mysqldump command line**, which means it is visible to anyone with `ps`/`tasklist` access on the panel host (a minor operator OPSEC weakness).

No process injection, no LOLBin abuse, no Windows API calls. BellaMain has no native-binary footprint at any stage — it is a PHP application end-to-end.

### 7.5 Persistence (Infrastructure Layer Only)

BellaMain has no host-malware persistence — it is a server-side PHP application installed on attacker-controlled web infrastructure. "Persistence" for this campaign is infrastructure persistence at the hosting layer:

- **Hosting persistence.** `79.137.192.3` (Aeza Group AS216246, Moscow). Bulletproof Russian hoster known for anti-abuse posture. Open directory listing exposes the kit distribution + live panel deployment without authentication. Server header: `Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12`. JARM TLS fingerprint `2ad2ad0002ad2ad00042d42d00000000f78d2dc0ce6e5bbc5b8149a4872356` (self-signed cert, FASTPANEL "parking" subject).
- **Operator-account persistence (within panel).** Operator session cookies are set with a 365-day lifetime — once an operator logs in, the panel remembers them for a year unless the cookie is cleared.
- **Database persistence.** The `panel` table is a 1-row global config table, designed to survive across re-deployments of the panel code (config-as-data, not config-as-code).

### 7.6 Current Status (as of evidence cutoff 2026-05-07)

| Component | Status |
|---|---|
| BellaMain panel + kit distribution at `79.137.192.3` | **ACTIVE** |
| CryptOne fake exchange staging at `79.137.192.3/cryptone/` | **ACTIVE** |
| CryptOne production at `cryptone.bot` (Cloudflare-fronted) | **ACTIVE** (0/92 VT detections) |
| Card phishing lure at `79.137.192.3/no/` | **ACTIVE** |
| Hardcoded canary Telegram bot token `6797512084:AAGbJVoC...` | **REVOKED** (HTTP 401 on `getMe`) |
| Operator-configured per-deployment Telegram bots (`adminbot`/`dekontbot`/`cekimbot`/`vergibot`) | Unknown — not externally testable without operator token values |
| Operator Telegram alias `@AresRS34` | **ACTIVE** Telegram user (privacy-restricted preview) |
| HTTP port 80 on `79.137.192.3` | **Newly opened** in the 2026-05-07 re-triage (previously HTTPS-only) — indicates ongoing operator development |

---

## 8. MITRE ATT&CK Mapping

> **Confidence note:** all rows below are HIGH confidence unless explicitly marked `(MODERATE)`. The Confidence Summary in [Section 12](#12-confidence-levels-summary) organizes findings by confidence level for the higher-level view.
>
> **Framework caveat.** BellaMain is a server-side PHP phishing-as-a-service panel. Several ATT&CK techniques that originally framed adversary tradecraft against endpoints map cleanly here too (Phishing, Financial Theft, Impersonation, Acquire Infrastructure), but classic endpoint techniques (process injection, credential dumping from LSASS) are not applicable.

| Tactic / Technique | Name | Evidence |
|---|---|---|
| Resource Development / T1583.003 | Virtual Private Server | `79.137.192.3` on AS216246 (Aeza Group, Moscow) — OFAC-sanctioned BPH |
| Resource Development / T1583.001 | Domains | `cryptone.bot`, `evotoptan.com` (MODERATE) |
| Resource Development / T1583.006 | Web Services | Telegram Bot API used as exfil + C2; Binance public API for live rate lookup |
| Resource Development / T1587.001 | Develop Capabilities: Malware | BellaMain.zip — operator-developed PhaaS panel with `Wadanz` author pseudonym |
| Resource Development / T1585.001 | Social Media Accounts | Telegram operator account `@AresRS34` + 4 operator-configured Telegram bots per deployment |
| Resource Development / T1585.002 | Email Accounts | `hello@cryptone.bot` operator-controlled (vanity contact email on parked domain) (MODERATE) |
| Resource Development / T1608.005 | Stage Capabilities: Link Target | 7 brand-impersonation kit RARs staged on operator open-directory at `79.137.192.3` |
| Initial Access / T1566.002 | Spearphishing Link | Kits designed to be linked from SMS/email/social into a victim browser (specific lure delivery not directly recovered, but kit structure assumes this delivery) |
| Initial Access / T1656 | Impersonation | 7 named Turkish marketplaces impersonated — pixel-perfect replicas loading legitimate CDN assets |
| Execution / T1059.004 | Command and Scripting Interpreter: Unix Shell | `backup.php` calls `exec("mysqldump ...")` — shells out to OS-level `mysqldump` binary |
| Persistence / T1505.003 | Web Shell | `V5VgjLU0jsDe/` admin directory functions as an operator web shell — `manager.php` accepts Telegram-routed commands that issue DB queries, TRUNCATE tables, and dump backups |
| Defense Evasion / T1027.013 | Encrypted/Encoded Files or Information | `sifreleWadanz` = `base64(gzcompress(serialize()))` wrapping operator session data; not strong cryptography but obfuscates cookie content |
| Defense Evasion / T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Phishing kits load CSS/JS from real platform CDNs (`cdn.dolap.com`, etc.) and embed Google Tag Manager + New Relic to look like the genuine sites |
| Defense Evasion / T1480 | Execution Guardrails | Kit `index.php` redirects non-targeted visitors to legitimate platform via `header("location: https://...")` — only "targeted" requests proceed to phishing content |
| Defense Evasion / T1497 | Virtualization / Sandbox Evasion (anti-research variant) | Anti-researcher canary — `?lg=` GET parameter triggers Telegram alert + troll response, used to identify and disrupt automated phishing-detection tools |
| Defense Evasion / T1070 | Indicator Removal | Three Telegram-triggered TRUNCATE commands (`/hesapsil`, `/kartsil`, `/girislogsil`) wipe stolen credentials, card data, and victim logs on demand |
| Defense Evasion / T1070.004 | File Deletion | `backup.php` issues `unlink()` on the SQL dump file after Telegram upload — minimizes forensic residue on panel host |
| Credential Access / T1056 | Input Capture | Phishing kits capture credentials via HTML form submission to `login.php` (web-form-based, not OS keylogging) |
| Credential Access / T1589.001 | Gather Victim Identity Information: Credentials | Stage-1 capture (`kartlaodeme.php`) collects name, phone, Turkish national ID (TC Kimlik); Stage-2 (`ibanlaodeme.php`) collects PAN, expiry, CVV |
| Discovery / T1518.001 | Software Discovery: Security Software | `usmcheck.php` polls Turkey USOM blocklist for any kit domain — proactive discovery of own listing status |
| Collection / T1119 | Automated Collection | Live victim heartbeat (3s AJAX cycle) automatically collects victim IP + funnel position + device UA into `girisyapanlar` |
| Collection / T1560 | Archive Collected Data | `/yedek` command produces a full mysqldump SQL archive of the entire panel database — credentials, cards, victim logs, operator accounts, config |
| Command and Control / T1071.001 | Web Protocols | All operator-server outbound C2 is HTTPS to `api.telegram.org` (4 bots) and HTTPS to `api.binance.com` (rate query) |
| Command and Control / T1102.002 | Web Service: Bidirectional Communication | Telegram bot inline-button approvals (`[Onayla]` / `[Reddet]`) implement bidirectional operator ⇆ panel control |
| Command and Control / T1102 | Web Service | Use of public Telegram + Binance APIs as the entire C2 surface |
| Command and Control / T1219 | Remote Access Software | `manager.php` Telegram bot effectively gives the operator a remote shell over the panel (12 commands covering DB writes, file dumps, kill switch) (MODERATE) |
| Exfiltration / T1041 | Exfiltration Over C2 Channel | Captured credentials/cards exfiltrated via Telegram Bot API `sendMessage` per-event |
| Exfiltration / T1567.002 | Exfiltration to Cloud Storage | `/yedek` MySQL backup uploaded via Telegram `sendDocument` to operator-controlled Telegram channel — Telegram-as-cloud-storage exfil |
| Impact / T1657 | Financial Theft | Direct theft of payment cards + Turkish national IDs from victims; 70/30 revenue split to operators monetized via TRX/TRON withdrawals through Binance-rate-converted payouts |
| Impact / T1485 | Data Destruction | Operator-initiated `/hesapsil`, `/kartsil`, `/girislogsil` TRUNCATEs destroy evidence on demand (impact on the operator's own data; defensive use) |

**Tactic coverage check.** Reconnaissance, Privilege Escalation, and Lateral Movement are not applicable in this campaign (operator-side; pre-victim activity not directly visible from panel code; panel runs as web-app user; single-server architecture). The covered tactics — Resource Development, Initial Access, Execution, Persistence, Defense Evasion, Credential Access, Discovery, Collection, C2, Exfiltration, Impact — represent the full BellaMain capability surface.

---

## 9. Threat Actor Assessment

> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-2026-008 is an internal tracking designation assigned by The Hunters Ledger to actors observed across analysis who cannot yet be linked to a publicly named threat group. This label will not appear in external threat intelligence feeds or vendor reports — it is specific to this publication. If future evidence links this activity to a known named actor, the designation will be retired and updated accordingly.

### 9.1 Conclusion

**Threat Actor:** UTA-2026-008 (existing designation, extended by this report).
**Distinct-actor confidence:** MODERATE (75%) — unchanged from parent UTA creation.
**Named-actor attribution:** INSUFFICIENT (<50%) — unchanged; first-capture documentation.

Indicators suggest the BellaMain Turkish PhaaS operation is run by a single Turkish-speaking PhaaS developer/operator (or small operator team) responsible for the BellaMain panel and its seven brand-impersonation phishing kits. We cannot attribute BellaMain to any publicly named threat actor at this time. UTA-2026-008 was originally created by the 2026-05-15 parent multi-cluster investigation from this same evidence base; this 2026-05-16 standalone report **extends** the UTA's Activity Log and Associated Reports — no new identity artifacts surfaced beyond the parent UTA's set, and confidence levels are unchanged.

### 9.2 Evidence Inventory

**Code / author fingerprints (strong distinct-actor evidence).**

| Artifact | Source | Why it isolates a single operator |
|---|---|---|
| `sifreleWadanz()` / `sifrecozWadanz()` function pair | `BellaMain/database/fonk.php` | Author pseudonym hard-coded into function names — not a configurable label, not a public framework string. Cross-deployment author marker. |
| MySQL triple `jakartaxdw` / `dbjakartaxdw` / `W!@25#8Tb2gxq15` | Panel + all 7 kits' `database/connect.php` | Shared/leaked templates re-key per licensee; identical credentials across panel-and-kits proves single-operator control. |
| Hardcoded canary Telegram bot `6797512084:AAGbJVoC...` (REVOKED) | All 6 kits' `girislog.php` + panel `dashboard.php` | Same canary bot in every kit + panel — single operator. |
| Admin directory `V5VgjLU0jsDe` | Panel root | Operator-chosen 12-char random string, stable since April 2024. |
| Session cookie `2tUgyO@H9E!4CuQ` | Panel + all kits | Same context. |

**Account fingerprints.**

| Artifact | Type | Verification |
|---|---|---|
| `@AresRS34` | Telegram alias | Embedded in anti-researcher Turkish-profanity string in all 6 kits; verified real Telegram account (privacy-restricted preview, 2026-05-07). |
| Telegram UID `5606327063` | Admin withdrawal approver #1 | Hardcoded `$authorizedUsers[0]` in `cekimbot.php`. |
| Telegram UID `6594066326` | Admin withdrawal approver #2 | Hardcoded `$authorizedUsers[1]` in `cekimbot.php`. |
| Telegram group `-1002104835510` | Canary exfil group | Receives anti-researcher alerts. |
| Telegram group `-1001817323952` | Operator announcement group | Receives `/bloke`, `/aktif`, `/usom` broadcasts in `manager.php`. |

**Contextual fingerprints.** Turkish-language consumer-fraud targeting across 7 named brands; USOM (Turkey CERT) self-monitoring (knowledge unusual for non-Turkey-resident operators); idiomatic Turkish profanity in anti-researcher canary (`Sazan IP`/`Sazan Kod`/`Sazan Cihaz`); TRX/TRON 70/30 payout split via live Binance TRXTRY rate.

**Infrastructure fingerprints.** Aeza-continuity 2+ years (AS204603 2023 → AS216246 2024-present); all Cluster A domains are attacker-controlled (not compromised); Turkish-market naming (`evotoptan.com`) at the domain-registration level.

### 9.3 Analysis of Competing Hypotheses

| Hypothesis | Verdict | Ruling evidence |
|---|---|---|
| **H1: Single Turkish-speaking PhaaS developer/operator (or small operator team) behind BellaMain panel + 7 kits** | **WINNER — MODERATE 75%** | `Wadanz` function-name signature + identical MySQL credentials across panel and all 7 kits + identical Telegram canary bot in all kits + idiomatic-Turkish USOM tradecraft |
| **H2: Shared or leaked PhaaS template — multiple unrelated licensees deployed the same code** | **RULED OUT** | A shared template would re-key per licensee. Single MySQL DB/user/password + single canary bot in all 6 kits' `girislog.php` + single admin path is incompatible with multi-licensee deployment |
| **H3: Non-Turkish actor targeting Turkey (e.g., Russian/Romanian cybercrime team)** | **LESS LIKELY** | USOM polling URL + idiomatic Turkish profanity + zero English strings + TRY-pegged payout currency + 7-brand Turkish marketplace specificity — non-resident operators rarely encode national-CERT awareness this deeply |
| **H4: Cluster-unification — BellaMain operator = Inkognito operator = Rhadamanthys-customer operator** | **RULED OUT — LOW** | See cluster-exclusion paragraph below |
| **H5: Direct attribution to a publicly named actor (any)** | **RULED OUT — INSUFFICIENT** | Zero Tier 1, 2, or 3 sources surface BellaMain, `@AresRS34`, or `Wadanz`. First-capture documentation. |

### 9.4 Cluster-Exclusion Statement

This report addresses Cluster A (BellaMain panel and seven Turkish-marketplace phishing kits) only. Two additional clusters co-tenanted on the same staging server (`79.137.192.3`) — an Inkognito Russian VPN/phishing operation at `185.221.196.118`, and a Rhadamanthys MaaS customer at `79.133.180.168` — were originally treated as candidate sub-operations of a single multi-year operator group. That cluster-unification hypothesis was formally downgraded during the investigation: the signals supporting it (a 22-minute DNS resolution of `evotoptan.com` to BellaMain's IP, shared `aezadns.com` nameservers, and Aeza ASN-family overlap) were reassessed as **Aeza-shared-tenancy artifacts** rather than operator-side overlap. Zero overlap exists across seven independent attribution dimensions — Telegram identities, developer pseudonyms, DNS/SOA registrant, language, payment rails, malware family, and production-C2 provider — and the OFAC designation of Aeza Group (July 2025) documents at least five unrelated criminal ecosystems co-resident on the same provider, confirming that bulletproof-hosting co-residency is not operationally diagnostic. Cluster B and Cluster C are documented in separate Hunters Ledger reports under their own UTA designations.

### 9.5 Why Named-Actor Attribution Remains INSUFFICIENT

Per CLAUDE.md's `ATTRIBUTION CONFIDENCE SCALE`, MODERATE named-actor attribution requires either one Tier-2 vendor's named-actor attribution, OR 1–2 infrastructure overlaps with a known actor + TTP similarity, OR partial evidence with notable gaps. None of these conditions are met:

- **Zero Tier-1 sources** (government, FBI/CISA/USOM advisory) name BellaMain or its operator.
- **Zero Tier-2 sources** (Mandiant, CrowdStrike, Microsoft, Kaspersky, Talos, Unit 42) name this panel or operator.
- **Zero Tier-3 sources** (BleepingComputer, Krebs, security researcher blogs) name this operation.
- **Zero infrastructure overlaps with any named actor.** Aeza co-tenancy with named criminal services (BriansClub, RedLine operators) is bulletproof-hosting co-residency, ruled non-diagnostic post-OFAC sanctioning.
- **No TTP similarity to any named PhaaS operation.** USOM monitor, four-bot Telegram role separation, on-demand TRUNCATE, and 70/30 TRX revenue split are documented as novel by the Stage 2 research; no documented PhaaS service has this exact combination.
- **No code similarity to any named PhaaS panel.** The Wadanz signature is unique; no public PHP corpus match for `sifreleWadanz` / `sifrecozWadanz`.

The expected upgrade path: paid-TI cross-reference of `@AresRS34` against underground-forum signatures, OR identification of `Wadanz` in any future PHP corpus, OR Turkish law-enforcement (USOM/EGM cybercrime division) attribution.

### 9.6 Confidence Statement

```
Threat Actor: UTA-2026-008 (single Turkish-speaking PhaaS developer/operator group behind BellaMain panel + 7 kits)
Confidence (distinct-actor): MODERATE (75%)
Confidence (named-actor): INSUFFICIENT (<50%)

Why this confidence:
- Code-level author pseudonym (Wadanz) hard-coded into function names — strong distinct-actor marker
- Identical MySQL credentials + identical canary Telegram bot across panel and all 7 kits — incompatible with shared/leaked template
- Idiomatic Turkish (USOM polling, profanity strings, TRY-pegged payouts, 7 Turkish-marketplace brands) — high Turkey-resident probability
- Aeza-continuity across 2+ years (AS204603 2023 → AS216246 2024-present)
- Account artifacts (Telegram alias, 2 admin UIDs, 2 group IDs) verified real but privacy-restricted

What's missing (for HIGH distinct-actor):
- Independent vendor / researcher corroboration of BellaMain as a recognized PhaaS panel
- Cross-sample observation of Wadanz pseudonym in any unrelated PHP panel/webshell
- Recovery of operator-configured Telegram bot tokens from panel DB
- Identification of downstream BellaMain customers (multi-operator licensing implied)

What's missing (for MODERATE named-actor):
- Tier 1-2 vendor naming of BellaMain or @AresRS34 as a known PhaaS service / operator
- Paid-TI underground-forum signature match on @AresRS34, Wadanz, or admin Telegram UIDs
- Turkish law-enforcement (USOM/EGM) attribution or indictment naming the operator

What would increase confidence:
- Paid-TI cross-reference (Flashpoint, Intel 471, KELA, Recorded Future, Flare)
- Public PHP corpus pivot on sifreleWadanz / sifrecozWadanz
- Vendor / community recognition of BellaMain panel after this publication
- Telegram-aware TI platform resolving admin UIDs 5606327063 and 6594066326 to known accounts
```

---

## 10. Indicators of Compromise (Reference)

The complete machine-readable IOC inventory is published as a separate JSON feed at [`/ioc-feeds/bellamain-turkish-phaas-79-137-192-3-20260516-iocs.json`](/ioc-feeds/bellamain-turkish-phaas-79-137-192-3-20260516-iocs.json). The IOC feed is **not** defanged — values are in canonical RFC-shaped form for direct ingestion into SIEM / EDR / proxy platforms.

This section provides a representative subset and references the feed for the complete inventory. **Do not** treat this section as the authoritative source — the JSON feed is canonical.

### 10.1 Representative IOCs

| Type | Indicator | Confidence | Context |
|---|---|---|---|
| IP | `79.137.192.3` | DEFINITE | BellaMain panel + 7 kits + CryptOne staging — direct observation, current 2026-05-07 |
| ASN | AS216246 — Aeza Group LLC | DEFINITE | Current announcement; bulletproof hoster; OFAC-sanctioned 2025-07-01 |
| ASN | AS204603 — Aeza Group Ltd | HIGH | Historical announcement, 2023 |
| JARM | `2ad2ad0002ad2ad00042d42d00000000f78d2dc0ce6e5bbc5b8149a4872356` | DEFINITE | TLS fingerprint for `79.137.192.3:443` |
| URL | `https://79.137.192.3/BellaMain/` | DEFINITE | Panel directory listing |
| URL | `https://79.137.192.3/cryptone/` | DEFINITE | CryptOne fake-exchange staging path |
| URL | `https://79.137.192.3/no/` | DEFINITE | Card phishing lure |
| Domain | `cryptone.bot` | HIGH | CryptOne production (Cloudflare-fronted, 0/92 VT) |
| Domain | `evotoptan.com` | MODERATE | 22-min DNS test to 79.137.192.3 on 2026-03-31; now Namecheap shared — FP risk |
| SHA256 | `f791fae41cdd3f141221d1783ed4779c839de7fc834ff4fc80a5d7f74b11ff88` | DEFINITE | `BellaMain.zip` — panel ZIP (first public disclosure) |
| SHA256 | `2c656360c4e58854dca35ff21b3fc62db41155ca76f8568ecc18fa52aa38fb31` | DEFINITE | `Dolap.rar` |
| SHA256 | `705793c011fdfe17941700a3bf42eee0ba2ebdc04870ce19779ea528b3565fac` | DEFINITE | `Kargo.rar` (Yurtiçi Kargo) |
| SHA256 | `e21fb63a3b4d65a3d48dec1bf17a84a414482f819b93cb8d77a81852dc34c95f` | DEFINITE | `Letgo.rar` |
| SHA256 | `ee9d4fccebbf73fb33980da15142bc71e5d9661d1bc583c2b09b77490065efd9` | DEFINITE | `Pttavm.rar` |
| SHA256 | `b2f4f1617577d14612b30a54a733b15af809c399f325717b4329c13aaa4c915c` | DEFINITE | `sahibinden.rar` |
| SHA256 | `504b1a30ce7060eafa7b2a3f6249c954a0be6ce1d2930e03b030434cb232600a` | DEFINITE | `shopier.rar` |
| SHA256 | `219cd4f6177a2358ec7f06b230d611f47e1049fcb3e2b44d06ec410b336382b0` | DEFINITE | `turkcell.rar` |
| Telegram bot token | `6797512084:AAGbJVoC0zcKWYPbFG8oc_bACPn6gUEye_E` | DEFINITE | Hardcoded canary — REVOKED; useful for hunting on stored kit copies |
| Telegram group ID | `-1002104835510` | DEFINITE | Canary exfil group/channel |
| Telegram group ID | `-1001817323952` | DEFINITE | Operator announcement group |
| Telegram user ID | `5606327063` | DEFINITE | Authorized withdrawal approver #1 |
| Telegram user ID | `6594066326` | DEFINITE | Authorized withdrawal approver #2 |
| Telegram alias | `@AresRS34` | HIGH | Operator alias; real privacy-restricted account |
| Code-author pseudonym | `Wadanz` | HIGH | Function-name suffix in `sifreleWadanz` / `sifrecozWadanz` — cross-sample author pivot |
| File path | `BellaMain/V5VgjLU0jsDe/manager.php` | DEFINITE | Admin Telegram bot file |
| Admin path | `V5VgjLU0jsDe` | DEFINITE | Obfuscated 12-char admin directory inside panel |
| Cookie name | `2tUgyO@H9E!4CuQ` | DEFINITE | Session-persistence cookie set on operator login |
| Hardcoded DB credential | `jakartaxdw` / `dbjakartaxdw` / `W!@25#8Tb2gxq15` | DEFINITE | MySQL triple across panel and all 7 kits |
| GTM container | `GTM-K7F5T5N` | HIGH | Google Tag Manager container embedded in all kit pages |

### 10.2 IOC Counts (per IOC Feed)

| IOC class | Count |
|---|---|
| File hashes (SHA256 + SHA1 + MD5) | 10 |
| Network IPs | 1 |
| Domains | 2 |
| URLs | 7+ |
| Telegram identity artifacts (bots / groups / users / aliases) | 6 |
| Code-level identity artifacts (pseudonym, cookie, admin path, MySQL triple) | 5 |
| File-path indicators | 6+ |

The IOC feed at [`/ioc-feeds/bellamain-turkish-phaas-79-137-192-3-20260516-iocs.json`](/ioc-feeds/bellamain-turkish-phaas-79-137-192-3-20260516-iocs.json) is the authoritative source — see that file for complete entries with `purpose`, `first_seen`, `last_seen`, `confidence`, and `action` (`BLOCK` / `MONITOR` / `HUNT`) per IOC.

### 10.3 IOCs with Known False-Positive Context

Two IOCs in the feed carry explicit FP context that defenders should review before deploying as blocking signatures:

- **`evotoptan.com`** — Resolved to `79.137.192.3` for a 22-minute window on 2026-03-31; currently on Namecheap shared hosting which serves many unrelated sites. Treat as MODERATE confidence and combine with kit-landing-page URL patterns before blocking.
- **`https://www.usom.gov.tr/url-list.txt`** — Legitimate Turkish security tooling, threat-intel platforms, and individual researchers fetch this URL. Detection signatures on this fetch must be combined with another BellaMain artifact on the same host (see [Section 5.2](#52-usom-blocklist-self-monitoring-the-distinctive-turkish-targeting-tradecraft)).
- **`https://api.binance.com/api/v3/ticker/price?symbol=TRXTRY`** — Legitimate crypto/finance applications query this endpoint. Not useful as a detection signature in isolation.

---

## 11. Risk & Detection Posture

The complete detection content (YARA + Sigma + Suricata) is published as a separate detection file at [`/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/`](/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/). The file follows the project-standard Jekyll deployment conventions (CC BY-NC 4.0 license, "The Hunters Ledger" author field on every rule).

### 11.1 Detection Coverage Summary

| Rule Type | Count | MITRE Techniques Covered | Overall FP Risk |
|---|---|---|---|
| YARA | 3 | T1505.003, T1027.013, T1070, T1056, T1119 | LOW–MEDIUM |
| Sigma | 5 | T1505.003, T1070, T1071.001, T1102.002, T1560, T1518.001 | LOW–MEDIUM |
| Suricata | 4 | T1505.003, T1071.001, T1518.001, T1102.002 | LOW–MEDIUM |

*Some BellaMain capabilities (USOM polling, Binance rate query, 70/30 revenue split) generate high-FP-context network traffic that does not support production-ready detection rules in isolation — these are covered by source-level YARA rules where applicable and documented in [§11.4 Coverage Gaps](#114-coverage-gaps).*

**Scope note.** All rules cover Cluster A (BellaMain Turkish PhaaS panel + 7 brand-impersonation kits) only. Cluster B (Inkognito) and Cluster C (Rhadamanthys) are covered by previously published detection sets. The evidence base is recovered PHP source code, not PE binaries — detection logic targets server-side artifacts, web-server logs, and network egress, not endpoint process injection or PE characteristics.

### 11.2 Highest-Priority Detection Patterns

These are the first three signatures to deploy if attention is limited:

1. **`V5VgjLU0jsDe/` URI path component** (Sigma) — Any HTTP request URI containing this 12-character random string is high-fidelity. Single-string match; vanishingly low FP probability.
2. **`sifreleWadanz` + `sifrecozWadanz` function-name pair in PHP source** (YARA) — Author-pseudonym signature; deploy on web-root file-integrity-monitoring or PHP corpus audits.
3. **`api.telegram.org/bot6797512084:AAGbJVoC*` egress URI** (Suricata / Zeek HTTP) — Specific revoked-token URI; observation of attempted calls indicates an active BellaMain deployment.

See the [separate detection file](/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/) for the full rule bodies and additional behavioral signatures.

### 11.3 Quick Hunt Recipes

Three one-liner hunt commands for the highest-priority detection patterns — adapt per log platform:

- **Web-access log hunt for admin path** (grep on Apache/Nginx combined log): `grep 'V5VgjLU0jsDe' /var/log/apache2/access.log`
- **PHP source corpus hunt for Wadanz author signature**: `grep -r 'sifreleWadanz\|sifrecozWadanz' /var/www/`
- **Proxy/egress log hunt for revoked canary bot URI**: `grep 'api\.telegram\.org/bot6797512084:AAGbJVoC' <proxy_log_path>`

Each is a single-string match requiring no additional context — any hit is a high-fidelity BellaMain indicator.

### 11.4 Coverage Gaps

The detection set covers the published BellaMain surface but does not address:

- **Operator-configured Telegram bot tokens** (`adminbot` / `dekontbot` / `cekimbot` / `vergibot`) — these live in the panel MySQL database, are operator-customizable per deployment, and cannot be enumerated from source. Detection on these requires either a panel-DB compromise or honeypot acquisition.
- **CryptOne production origin IP** — Cloudflare-fronts the `cryptone.bot` production deployment; passive DNS does not reveal the origin. Detection on Cloudflare-fronted infrastructure is limited to DNS queries against the known fronted domain.
- **Forked BellaMain deployments with re-keyed admin path** — A fork-er who replaces `V5VgjLU0jsDe` with their own random string defeats the path-based hunt. The `sifreleWadanz` PHP-corpus pivot survives re-keying as long as `database/fonk.php` is unmodified.

---

## 12. Confidence Levels Summary

This section organizes findings by confidence level so readers can quickly assess what is established fact versus analytical judgment.

### 12.1 DEFINITE (Direct Evidence, No Ambiguity)

- **File hashes and file structure of `BellaMain.zip` and the seven kit RARs** — full SHA256 / MD5 / SHA1 for each; structural inventory of 65 PHP files across 14 directories; per-kit RAR structure and impersonated-brand mapping.
- **Panel IP, ASN, JARM, server header, open-directory exposure** — `79.137.192.3` on AS216246; JARM `2ad2ad0002ad2ad00042d42d00000000f78d2dc0ce6e5bbc5b8149a4872356`; Apache 2.4.58 Win64 OpenSSL/3.1.3 PHP/8.2.12; open-directory listing observable.
- **MySQL credential triple `jakartaxdw` / `dbjakartaxdw` / `W!@25#8Tb2gxq15`** — hardcoded across panel and all seven kits' `database/connect.php`.
- **Admin directory `V5VgjLU0jsDe`, session cookie `2tUgyO@H9E!4CuQ`** — direct source observation.
- **Hardcoded canary Telegram bot token `6797512084:AAGbJVoC...`** — directly observed across all 6 kits and the panel `dashboard.php`; revocation status (HTTP 401 on `getMe`) directly tested.
- **Telegram operator group IDs `-1002104835510` and `-1001817323952` and admin UIDs `5606327063`, `6594066326`** — direct source observation.
- **USOM polling, TRUNCATE commands, `/yedek` MySQL backup-as-exfil, 70/30 revenue split, four-bot architecture, referral-code-gated self-registration** — directly observed in PHP source.
- **OFAC SDN designation of Aeza Group LLC (2025-07-01)** — Tier-1 government source.
- **`BellaMain.zip` is not present in VirusTotal** — direct VT MCP query confirmed.

### 12.2 HIGH (Strong Evidence, Minor Gaps)

- **BellaMain is operator-developed (not a purchased or leaked public framework).** Code-author pseudonym `Wadanz` baked into function names; distinctive command set in `manager.php`; no signs of a known public PHP phishing framework underlying the code.
- **Turkey-resident or Turkey-targeting operator profile.** Turkish-language anti-researcher canary; `Europe/Istanbul` timezone hardcoded; USOM polling implementation; native-fluent Turkish-language Telegram message strings; TC Kimlik Numarası targeting; 7 Turkish-marketplace brand selection.
- **First public disclosure.** Multi-source exhaustive search (VT, Google, GitHub-code, vendor blogs) returned zero security-relevant results for `BellaMain`, `sifreleWadanz`, `sifrecozWadanz`, `Wadanz` (as PhaaS author), `V5VgjLU0jsDe`, `@AresRS34`.
- **Operator alias `@AresRS34`.** Source-embedded in all 6 kits' `girislog.php`; verified real Telegram account (privacy-restricted preview); cannot rule out a deliberately-planted decoy, but the placement (function-internal canary string, not visible to victims) and consistency across all kits make this less likely.
- **`Wadanz` is the developer pseudonym (or team handle).** Function-name suffix is unusual code style — operators rarely sign their PHP source. Could be decoy/team identifier, but cross-deployment stability and absence of any public legitimate PHP author/library by this name make pseudonym the most likely interpretation.

### 12.3 MODERATE (Reasonable Evidence, Notable Gaps)

- **Operator is a single developer / small team.** Consistent code style + identical credential reuse across panel and all 7 kits + single author-pseudonym; counter: code is workmanlike rather than polished, suggesting one developer rather than a team.
- **Four-bot Telegram architecture is more granularly role-separated than published PhaaS state of the art.** BellaMain's design is the only documented instance of this exact pattern; absence of prior reporting limits corroboration.
- **`evotoptan.com` is BellaMain-affiliated.** 22-minute DNS resolution to `79.137.192.3` on 2026-03-31 is suggestive but not conclusive; current Namecheap-shared hosting creates FP risk.
- **70/30 TRX/TRON payout via live Binance rate is a novel PhaaS settlement pattern.** No prior public PhaaS reporting documents this combination; the negative result rests on the comprehensiveness of the searched corpus.
- **GTM container `GTM-K7F5T5N` provenance.** Operator-registered or hijacked from a legitimate site — could not be determined from available evidence.

### 12.4 LOW (Weak / Circumstantial Evidence)

- **Specific lure-delivery vectors used by BellaMain operators (SMS / email / social / search ads).** Kit structure assumes a link-delivery vector, but no specific delivery infrastructure was recovered. Most likely SMS based on Turkish consumer-fraud patterns, but this is inference, not direct evidence.
- **Operator location.** Turkey-resident is HIGH; specific-city or specific-IP geolocation is INSUFFICIENT — no operator-side telemetry was acquired.

### 12.5 INSUFFICIENT (Cannot Assess)

- **Named-actor attribution.** First-capture documentation; no Tier 1–3 sources name BellaMain, `Wadanz`, or `@AresRS34`.
- **Number and identity of downstream BellaMain operator-customers.** The multi-operator licensing model is observable in source, but the live `kullanicilar` table was not acquired.
- **Operator-configured Telegram bot tokens.** Stored in the panel MySQL database; not recoverable from source.
- **CryptOne fake-exchange production content.** Cloudflare-fronted; full DOM-level analysis was out of scope.
- **Total victim-data volume in operator possession.** No live panel-database acquisition.

### 12.6 Gaps & Assumptions

This sub-section surfaces the load-bearing assumptions in the analysis, the runner-up hypothesis as an explicit Alternative Assessment, and the evidence that would resolve each gap. Readers can use this section to assess analytical sensitivity — *what would force a re-rank of the conclusion?*

#### Alternative Assessment — H3 "Non-Turkish actor targeting Turkey"

The competing-hypotheses table in §9.3 ranked H1 (single Turkish-speaking PhaaS developer/operator) as the winning hypothesis and H3 (non-Turkish cybercrime team targeting Turkey, e.g., a Russian or Romanian crew with strong Turkish-language proficiency) as the runner-up at LESS LIKELY. H3 is preserved here as an explicit Alternative Assessment so future analysts can re-test it against new evidence rather than re-derive it.

**H3 statement:** The BellaMain operator is not Turkey-resident but a non-Turkish cybercrime team (most plausibly Russian, given Aeza-continuity and bulletproof-hosting selection patterns) that has built a Turkey-targeting PhaaS using contracted Turkish-language assistance or LLM-assisted translation. Idiomatic Turkish, USOM awareness, and TC Kimlik targeting are operationally achievable from outside Turkey by a sufficiently motivated and resourced team.

**Why H3 was demoted to LESS LIKELY (rather than RULED OUT):**

- USOM polling is implemented as a code-level operator-facing feature (alerts go to a private operator Telegram group, not to victims). This is unusual for non-resident teams because the operator must understand *why* USOM listing matters and how to respond — implying daily operational familiarity with the Turkish CERT cadence.
- Turkish profanity strings (`Sazan IP` / `Sazan Kod` / `Sazan Cihaz` — "carp" used as a contemptuous term for a duped researcher) are idiomatic, not dictionary-translatable. Non-Turkish authors typically produce stilted phrasing detectable by native readers.
- The seven-brand selection (Dolap, Letgo, PTT AVM, Sahibinden, Shopier, Turkcell, Yurtici Kargo) is operationally tight — these are the Turkish e-commerce brands most likely to generate high-conversion phishing funnels in 2024-2026. A non-resident team would more likely default to globally-known brands (Trendyol, N11, Hepsiburada — which BellaMain did *not* target). The selection looks like resident-operator intuition.
- TRY-pegged payouts via live Binance TRXTRY rate (rather than the more common USDT-denominated affiliate split) is a Turkish-domestic optimization — TRX/TRON is the on-ramp/off-ramp of choice for Turkish crypto OTC desks, not for Russian-language criminal markets.

**Evidence that would force H3 re-rank from LESS LIKELY to MODERATE:**

- Recovery of operator-side communications (Telegram message logs from the four operator-configured bots) showing non-Turkish primary language between operator and admins.
- Paid-TI cross-reference of `@AresRS34` against Russian-language underground forum signatures or Romanian PhaaS-vendor handles.
- Identification of the GTM-K7F5T5N container as registered to a non-Turkish Google account holder.
- Code-similarity match between BellaMain's `database/fonk.php` and any documented Russian-language PHP webshell/panel using `sifreleWadanz`-style author signatures.

#### High-Sensitivity Assumptions

These are the assumptions whose change would materially alter the conclusion:

**Assumption 1: USOM polling + idiomatic Turkish = Turkey-resident operator.** The conclusion that the operator is Turkey-resident rather than Turkey-targeting depends on the inference that USOM-awareness and idiomatic Turkish are practically achievable only by resident operators. This assumption is supported by historical Turkish-language phishing reporting and by the operational depth of the USOM polling implementation, but a sufficiently resourced non-resident team with native-Turkish-speaking assistance could in principle reproduce both. *If invalidated:* operator-location collapses to INSUFFICIENT; operator-targeting (Turkey) remains HIGH.

**Assumption 2: Identical MySQL credentials + identical canary bot across panel and all 7 kits = single-operator control.** The conclusion that BellaMain is one operator-developed product rather than a leaked/shared template depends on the inference that shared credentials are incompatible with multi-licensee deployment. This assumption holds for the standard PhaaS licensing model (each licensee gets a per-tenant configuration), but does not hold for an unusual model in which licensees deliberately share infrastructure to amortize cost. The latter model is rare but not impossible. *If invalidated:* the distinct-actor confidence drops from MODERATE 75% to LOW, and the analytical frame shifts to "BellaMain ecosystem" rather than "BellaMain single operator".

**Assumption 3: `Wadanz` is the developer pseudonym (or team handle), not a decoy.** Function-name signatures *can* be deliberate misdirection — an operator could embed a false pseudonym to mislead investigators. The conclusion that `Wadanz` is genuine rests on (a) the consistency of the signature across the panel codebase, (b) the absence of any public benign-author or library using `Wadanz` as an identifier, and (c) the structural placement inside session-encryption helper functions where decoy placement would be operationally unusual. *If invalidated:* `Wadanz` loses its forward-pivot value but the rest of the distinct-actor case remains intact.

**Assumption 4: Aeza-continuity (AS204603 → AS216246) reflects operator-continuity, not coincidence.** The `a-loader.site` 2023 artifact on Aeza AS204603 is treated as evidence of multi-year operator presence on the same bulletproof provider. This assumes the same operator both deployed `a-loader.site` in 2023 and BellaMain in 2024+. Coincidence is possible — many Russian cybercrime actors use Aeza, so two unrelated operators could have used Aeza-family ASNs in different years. *If invalidated:* the multi-year operator-tenure framing weakens, but the 2024+ BellaMain deployment remains independently attributed.

#### Evidence That Would Resolve Outstanding Gaps

- **Public PHP corpus pivot on `sifreleWadanz` / `sifrecozWadanz`** (VT Intelligence, Recorded Future, Flare, paid-TI PHP corpus access) — would resolve whether `Wadanz` appears in any other operator deployment, materially lifting distinct-actor confidence toward HIGH if a match is found.
- **Paid-TI underground-forum cross-reference** of `@AresRS34`, Telegram UIDs `5606327063` / `6594066326`, and the Wadanz pseudonym — could lift named-actor attribution from INSUFFICIENT to MODERATE if any prior PhaaS-vendor handle resolves.
- **Vendor publication referencing BellaMain or the Wadanz signature** post-disclosure — would corroborate the first-capture claim and contribute to named-actor attribution if combined with paid-TI signals.
- **Turkish law-enforcement attribution or indictment** (USOM / EGM cybercrime division) naming the operator — would lift named-actor to MODERATE or HIGH depending on evidence specifics.
- **Recovery of the live `kullanicilar` table** (panel customer roster) — would resolve the multi-operator licensing model from "observable in source" to "enumerated downstream operators".

---

## 13. Response Guidance

> This is intentionally a brief response orientation, not an incident response playbook. Organizations facing a confirmed BellaMain encounter should engage their internal IR team or a dedicated playbook — that is out of scope for this publication.

**Top three detection priorities.**

1. Hunt web-access logs for URI path component `/V5VgjLU0jsDe/` — most BellaMain-specific single indicator.
2. PHP corpus / hosting-environment hunt for the `sifreleWadanz` / `sifrecozWadanz` function-name pair — code-author signature.
3. Outbound network telemetry for connections to `79.137.192.3:443` or `79.137.192.3:80` from any internal asset — direct operator-infrastructure contact.

**Persistence-removal targets (names only, not procedures).**

- Database `jakartaxdw` and user `dbjakartaxdw` on any operator-side MySQL instance.
- Admin directory `V5VgjLU0jsDe/` and its files (`backup.php`, `cekimbot.php`, `manager.php`, `usmcheck.php`) on any web root.
- Any deployed kit RAR/PHP-source matching the eight SHA256 hashes in [Section 10](#101-representative-iocs).
- Telegram bot webhooks pointing to operator-controlled panel URLs (`post.php` sets them; revoking the bots clears them).

**Containment categories.**

- Block `79.137.192.3` and AS216246 Aeza space at the network perimeter.
- Block or DNS-monitor `cryptone.bot`.
- Add the eight file SHA256 hashes to EDR / mail-gateway file blocklists.
- Add Telegram group IDs `-1002104835510`, `-1001817323952` and admin UIDs `5606327063`, `6594066326` to any Telegram-aware threat-intelligence feed (operator pivots, not defensive controls).
- For US-regulated entities, treat outbound connections to Aeza Group ASNs as potentially OFAC-reportable per the July 1, 2025 SDN designation.

---

## 14. References

Tier-coded per CLAUDE.md SOURCE CREDIBILITY TIERS. All citations are sources that contributed directly to evidence or context in this report — no inventive citations.

**Tier 1 — Government / authoritative.**

- U.S. Department of the Treasury, Office of Foreign Assets Control (OFAC). *Specially Designated Nationals (SDN) List — Aeza Group LLC designation, July 1, 2025.* `treasury.gov`.
- VirusTotal MCP — IP report for `79.137.192.3`, domain report for `cryptone.bot`. Tier-1 / A1 for IOC metadata. (`virustotal.com`)

**Tier 2 — Major-vendor / industry research.**

- TRM Labs. *Aeza Group sanctions analysis* (2025). `trmlabs.com`.
- Cofense Intelligence. *Telegram bot credential exfiltration patterns in phishing campaigns* (2023). `cofense.com`.
- Sekoia.io. *EvilTokens PhaaS analysis* (2024). `blog.sekoia.io`.
- Netcraft. *Haozi Chinese-language PhaaS analysis* (2025). `netcraft.com`.
- Kaspersky Securelist. *Spam and Phishing Report 2024 — Turkey country profile* (2024). `securelist.com`.

**Tier 3 — Security journalism / community research.**

- BleepingComputer. *Aeza Group sanctioned for hosting ransomware, infostealer servers* (2025). `bleepingcomputer.com/news/security/aeza-group-sanctioned-for-hosting-ransomware-infostealer-servers/`.
- Silent Push. *Aeza infrastructure migration post-sanctions* (2025). `silentpush.com`.
- Global Initiative against Transnational Organized Crime. *Turkey fraud landscape analysis 2025*. `globalinitiative.net`.
- Posta ve Telgraf Teşkilatı A.Ş. (PTT). *Official fraud warnings on cargo and shipping phishing*. `ptt.gov.tr`.
- Infosecurity Magazine. *Turkish national ID 49.6 million record breach* (2016). `infosecurity-magazine.com`.
- Breakglass Intelligence. *TMoscow Bot — Telegram Mini App PhaaS analysis* (2025). `breakglass.io`.
- The Hunters Ledger. *OpenDirectory 79.137.192.3 multi-cluster investigation — Cluster A BellaMain coverage at Sections 4.4, 5.7, 6.6, 8.3, 9.1* (2026-05-15). `/reports/opendirectory-79-137-192-3-20260515/`.
- The Hunters Ledger. *Inkognito Russian VPN/Phishing Operator — Cluster B standalone report* (2026-05-16). `/reports/inkognito-russian-vpn-phishing-185-221-196-118-20260516/`.

**MITRE ATT&CK framework.**

- MITRE ATT&CK Enterprise Matrix. `attack.mitre.org`.

---

© 2026 Joseph. All rights reserved. See LICENSE for terms.
