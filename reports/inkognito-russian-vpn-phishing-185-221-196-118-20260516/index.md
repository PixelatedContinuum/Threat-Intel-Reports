---
title: "Inkognito — Russian-Speaking Multi-Product Fraud Operator (INK VPN, INK Lens 467+ Brand-Impersonation Phishing Library, BEC Burn Domains, CryptOne Fake Exchange)"
date: '2026-05-16'
detection_page: /hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/
ioc_feed: /ioc-feeds/inkognito-russian-vpn-phishing-185-221-196-118-20260516-iocs.json
detection_sections:
  - label: "YARA Rules"
    anchor: "#yara-rules"
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "Suricata Signatures"
    anchor: "#suricata-signatures"
ioc_highlights:
  - value: "185[.]221[.]196[.]118"
    note: "Operator EspoCRM back-office (Aeza Italy AS210644 — OFAC SDN)"
  - value: "176[.]124[.]211[.]174"
    note: "Current primary phishing host (Timeweb RU AS9123)"
  - value: "193[.]46[.]56[.]182"
    note: "Long-term VPN endpoint (Stark/Worktitans TR — EU-sanctioned)"
  - value: "inkconnect[.]ru"
    note: "INK VPN flagship brand (Cloudflare-fronted Vite/React SPA)"
  - value: "inklens[.]ru"
    note: "467+ brand-impersonation subdomain library"
  - value: "inklens[.]co[.]uk"
    note: "Apex chameleon decoy (GitHub Pages → AmazonS3 cover)"
layout: post
permalink: /reports/inkognito-russian-vpn-phishing-185-221-196-118-20260516/
category: "Fraud Operation"
hide: true
description: "Inkognito is a Russian-speaking multi-product fraud operator that has run continuously for nearly three years. The operator pairs a real commercially-billed VPN service with a 467+ brand-impersonation phishing subdomain library targeting US banking, enterprise SaaS, Chinese internet giants, and Russian telecom. Apex chameleon-decoy tradecraft, an 11-minute domain-to-live deployment pipeline, and infrastructure spanning two sanctioned bulletproof hosters (Aeza, Stark/Worktitans) define the operator footprint. This is the first public cross-brand documentation of the Inkognito portfolio."
---

**Campaign Identifier:** Inkognito-Russian-VPN-Phishing-185.221.196.118<br>
**Last Updated:** May 16, 2026<br>
**Threat Level:** HIGH

> **Risk vs. Detection Posture:** The Inkognito fraud-operation infrastructure analyzed in this report scores **7.5/10 (HIGH)** based on enterprise-grade DevOps tradecraft, sustained 2-year-11-month continuous operation, a 467+ pre-staged brand-impersonation subdomain library across 18+ enterprise verticals, deliberate provider segmentation across two sanctioned bulletproof hosters, and 0/92 VirusTotal detection across all operator infrastructure. The threat level is not CRITICAL because no in-flight credential-harvest payloads were observed on the impersonation subdomains at the evidence cutoff — all currently return HTTP 404, awaiting activation. If any subdomain in the library is switched live and observed harvesting credentials, the rating for that activation should be reassessed to CRITICAL.

## 1. Executive Summary

**Inkognito is a Russian-speaking multi-product fraud operator that has run continuously since 2023-06-08 — nearly three years of sustained operation — currently centered on a polished commercial VPN brand (INK VPN at `inkconnect.ru`) bolted to a 467+ brand-impersonation phishing subdomain library under `inklens.ru` targeting Wells Fargo, AnyDesk, Outlook Web Access 2013, Jenkins, Tencent, Sina, Tele2, Apple Siri, Accenture, Asana, and 18+ other enterprise verticals.** Defenders facing the question "what does the Inkognito operator's infrastructure, brand portfolio, and tradecraft look like — and how should we detect the brand-impersonation phishing surface used against enterprise targets" can act on three findings: (1) **block** the six confirmed operator IPs and 22+ confirmed operator domains; (2) **hunt DNS** for any query from your enterprise network to a brand-impersonation subdomain matching your own products under `*.inklens.ru` / `*.inklens.co.uk` — these subdomains exist only to be clicked; and (3) **deploy operator-fingerprint detection** for the `Server: kittenx` 404 decommission tombstone, the custom `X-Admin-Token` HTTP header, and the operator's Yandex Webmaster ID `98466329` to surface additional operator infrastructure not yet linked to the INK brand portfolio.

This is the **first public cross-brand documentation** of the Inkognito operator. No prior Tier-1 or Tier-2 threat intelligence has tied the INK VPN, INK Lens, Bikaf VPN, CryptOne (`cryptone.bot`), unloki.ru, or `bigass.monster` brands together as a unified operator. The JS bundle hash (`8a69fe67…`), brand logo PNG (`d1ae63c9…`), and favicon SVG (`53b3515f…`) all return NOT FOUND on VirusTotal as of 2026-05-07. This report fills that gap. The 2026-05-15 multi-cluster publication at [`/reports/opendirectory-79-137-192-3-20260515/`](/reports/opendirectory-79-137-192-3-20260515/) covered Inkognito at one-paragraph summary depth as Cluster B of a co-tenancy investigation on Aeza staging IP `79.137.192.3`; this standalone publication goes deep on Inkognito only. Cluster A (BellaMain Turkish PhaaS) and Cluster C (Rhadamanthys MaaS customer) are out of scope here — see the parent report for those.

The operator is tracked under the internal designation **UTA-2026-009** *(an internal tracking label used by The Hunters Ledger — see Section 9)*. Distinct-actor confidence is **MODERATE (78%)** based on a code-level custom authentication primitive, a unique cross-domain decommission tombstone, single-operator Google and Yandex Search Console account control across multiple brand domains, a single-tenant EspoCRM back-office, and consistent SOA fingerprints across three BEC burn domains. **Named-actor confidence is INSUFFICIENT (<50%)** — operator self-identification as "Inkognito" via the `@inkconnectvpn` Telegram channel is operator-asserted but has not been independently corroborated by any Tier-1, Tier-2, or Tier-3 source. We cannot attribute Inkognito to a publicly named actor at this time.

### What Was Found

The investigation surfaced a unified fraud business operating across six functional roles on six bulletproof hosters:

- A **commercial VPN service (INK VPN)** with a fully-featured Vite/React SPA frontend, 18 backend API endpoints, Russian payment integration (SBP, T-Pay, card), and an 11-minute domain-to-live deployment pipeline (`inkconnect.ru` went from registration to fully-operational live deployment in 11 minutes on 2026-04-17).
- A **brand-impersonation phishing library** of 467+ pre-staged subdomains under `inklens.ru` — Wells Fargo, AnyDesk (post-2024-breach brand), Outlook Web Access 2013, Jenkins CI, Microsoft Software Download Center, Apple Siri, Asana, Accenture, Tencent, Sina, Tele2, Adyen, and many more. All currently return 404; any one can be switched to a cloned login page in seconds.
- An **apex chameleon decoy** at `inklens.co.uk` — the apex domain redirects to GitHub Pages then AmazonS3 so casual researchers see a benign cover, while operational subdomains (`fi1.`, `de1.`, `marzban.`, `api.`) resolve to operator-controlled Aeza Italy IP `185.221.196.118` and serve the actual back-office, VPN nodes, and admin panels.
- A **fake crypto exchange (CryptOne)** at `cryptone.bot`, Cloudflare-fronted with Turnstile bot challenge — origin IP not recoverable from passive DNS.
- **BEC burn-domain infrastructure** — three `.eu` domains (`vetcorbeanca.eu`, `vagtec.eu`, `petkovalegal.eu`) registered at Namecheap in a 14-day window in June 2023, each with self-served `mail.*`, `ns1.*`, `ns2.*` on Stark Industries Turkey, consistent `admin@<domain>.eu` SOA fingerprint, and operator-controlled periods of 6 days, ~12 months, and ~12 months respectively.
- **Centralized VPN/proxy fleet management** via a Marzban (Xray/V2Ray) admin panel at `marzban.inklens.co.uk` orchestrating regional VPN exit nodes (Finland, Germany, Greece) under multiple consumer brand fronts (Bikaf VPN, `bigass.monster`, unloki.ru with Outline VPN for Iran/RU/CN-targeted censorship circumvention).

### Why This Threat Is Significant

The risk is not a single act of intrusion. It is the **infrastructure surface** the operator maintains for whatever campaign monetizes next. Three structural features make this operator notable:

1. **Provide-then-phish dual-business model.** The same operator runs a real, commercially-billed VPN service (with Russian payment-processor integration that requires a Russian legal entity) AND a 467+ brand-impersonation phishing library on overlapping infrastructure. No prior Tier-1 or Tier-2 documented threat actor exhibits this exact dual-business pattern at the documented scale. The legitimate-VPN front anchors a customer-acquisition pipeline that feeds the same operator who runs brand-impersonation phishing.

2. **Researcher-defeating tradecraft.** The `inklens.co.uk` apex chameleon decoy (UK ccTLD via French registrar, redirecting through US-hosted GitHub Pages then AmazonS3 cover) is **a novel technique variant** not documented in the public Tier-1/Tier-2 record. The closest analog is FIN7 domain aging (which uses benign static content rather than a live cloud redirect chain). Combined with operator-side TLS browser-fingerprinting on `inklens.ru` (which rejects non-browser TLS clients during the handshake), the operator has built deliberate cover against automated security crawlers — directly explaining the persistent 0/92 VirusTotal detection.

3. **Sanctioned-hoster portfolio.** The operator runs back-office on Aeza Group AS210644 (**OFAC SDN designated 2025-07-01**) and long-term VPN/BEC infrastructure on Stark Industries AS44477 / Worktitans AS209847 (**EU-sanctioned 2025-05-20** per EU Council Decision (CFSP) 2025/972). Continued operation post-sanctions across both providers indicates either willingness to operate on sanctioned infrastructure or insufficient deconfliction by the providers. For US-regulated entities, outbound connections to Aeza ASNs are potentially OFAC-reportable.

### Key Risk Factors

| Risk Dimension | Score (X/10) | Rationale |
|---|---|---|
| Capability sophistication | 7/10 | Enterprise-grade DevOps pipeline (Argo CD, multi-stage UAT/staging, Redis admin), 11-minute domain-to-live automation, jurisdiction-laundering apex decoys, custom HTTP authentication primitive, mature anti-reconnaissance TLS posture. No novel binary tradecraft because there are no binaries — sophistication is concentrated at the operations, infrastructure, and OPSEC layers. |
| Operational scale | 8/10 | 467+ pre-staged brand-impersonation subdomains across 18+ enterprise verticals; 22+ confirmed operator domains across 8 registrars; six-hoster footprint; 2-year-11-month continuous operation. |
| Active-campaign evidence | 5/10 | Infrastructure is staged but specific in-flight credential-harvest payloads were not recovered (all impersonation subdomains return HTTP 404 at the evidence cutoff). The 12-month operator-controlled `.eu` BEC burn-domain periods evidence sustained capability but no captured spearphishing email payloads are in scope. |
| Detection difficulty | 7/10 | 0/92 VirusTotal across all operator domains. Apex chameleon decoy defeats casual researcher inspection. TLS browser-fingerprinting on `inklens.ru` blocks automated scrapers. Operator-fingerprint signatures (kittenx-404, X-Admin-Token, Yandex ID) are detectable but require purposeful hunting. |
| Defender actionability | 8/10 | Concrete IP and domain block lists; high-fidelity behavioral signatures; specific DNS hunt queries for the impersonation library; CT-monitoring pivots; no in-host changes required (all detection is at the network, DNS, proxy, and web-content-inspection layer). |

**Overall Risk Score: 7.5/10 — HIGH**

### Threat Actor

- **UTA-2026-009 — Inkognito Russian VPN/phishing operator.** Single Russian-speaking multi-product fraud operator. Self-identified parent brand "Inkognito" via the `@inkconnectvpn` Telegram channel (797 subscribers, first post 2026-03-18). Distinct-actor confidence **MODERATE (78%)**. Named-actor attribution **INSUFFICIENT (<50%)** — first public capture; no prior Tier-1/2/3 TI; resolution would require Russian payment-processor merchant ID lookup, paid Russian underground forum investigation, or Russian regulator action. This report **extends** the existing UTA-2026-009 file's Activity Log; it does not replace the originating characterization from the 2026-05-15 multi-cluster investigation. Net executive implication: Inkognito is a stable, professionally-operated commercial fraud business that should be tracked as a persistent infrastructure risk rather than as a discrete incident.

### For Technical Teams — Immediate Priorities

- **Hunt DNS for brand-impersonation subdomains under `*.inklens.ru` and `*.inklens.co.uk`.** These subdomains exist only for fraudulent use; any DNS query from an enterprise endpoint is high-fidelity. The Section 4 deep-dive enumerates 25+ specific impersonation targets including `wellsfargo.inklens.ru`, `anydesk.inklens.ru`, `owa2013.inklens.ru`, `development-jenkins.inklens.ru`, and `swdcdownloads.inklens.ru`. See the [separate detection file](/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/) for the Sigma DNS rule.
- **Hunt for the `Server: kittenx` + 404 + content-length 148 HTTP response signature** in web-proxy or Zeek HTTP logs — operator's decommission tombstone, surfaces additional retired operator infrastructure not yet enumerated.
- **Hunt for the `X-Admin-Token` header** in HTTP requests, responses, or CORS preflight `Access-Control-Allow-Headers` lists — operator's custom admin auth primitive, pivots cluster expansion to any other operator-controlled API surface.
- **Block all six confirmed operator IPs** (`185.221.196.118`, `176.124.211.174`, `77.239.101.23`, `193.46.56.182`, `79.137.203.87`, `92.38.219.225`) and the 22+ confirmed operator domains. See the [separate IOC feed](/ioc-feeds/inkognito-russian-vpn-phishing-185-221-196-118-20260516-iocs.json) for the full machine-readable inventory.
- **For US-regulated entities**, treat outbound connections to Aeza Group ASNs (AS210644, AS216246) as potentially OFAC-reportable per the July 1, 2025 SDN designation; treat outbound connections to Stark Industries AS44477 / Worktitans AS209847 as engagement with EU-sanctioned infrastructure per EU Council Decision (CFSP) 2025/972.

---

## 2. How This Investigation Unfolded

This report is a **standalone derivative** of the OpenDirectory 79.137.192.3 investigation published on 2026-05-15. The originating pivot was a single open-directory exposure on Aeza Group AS216246 staging IP `79.137.192.3` that surfaced three operationally separate threat clusters co-tenanted on the same multi-tenant bulletproof staging utility. That parent investigation, published at [`/reports/opendirectory-79-137-192-3-20260515/`](/reports/opendirectory-79-137-192-3-20260515/), covered:

- **Cluster A — BellaMain Turkish Phishing-as-a-Service** (UTA-2026-008): operator `@AresRS34`, developer pseudonym `Wadanz`, PHP/MySQL phishing-kit panel targeting Turkish banking and marketplace brands.
- **Cluster B — Inkognito Russian VPN/phishing operator** (UTA-2026-009): the subject of this report.
- **Cluster C — Rhadamanthys MaaS customer** (UTA-2026-010): a customer-built loader (`staticlittlesource.exe`) wrapping a canonical Rhadamanthys Stage-2 with a Hostkey Netherlands C2 (`79.133.180.168:3394`) that survived the November 2025 Operation Endgame Phase 3 takedown.

In the parent report, Cluster B (Inkognito) received **one-paragraph summary depth** across Sections 4.5, 5.7, 6.6, 8.3, and 9.2 — enough to establish the cluster boundary and risk classification but not enough to publish the brand-portfolio mapping, the operator-fingerprint pivots, or the detection content needed to act on the threat at scale. This standalone publication goes deep on Inkognito only. Cluster A and Cluster C content is **out of scope** here; cross-references to the parent publication are provided where the cluster-boundary context matters.

### Why a Standalone Inkognito Report

Three findings from the parent investigation made Inkognito worth promoting to a standalone publication:

1. **First public capture of a 3-year-old operation.** Despite 2 years 11 months of continuous operation, zero prior Tier-1, Tier-2, or Tier-3 sources document the INK VPN / INK Lens / Bikaf VPN / CryptOne / unloki brand portfolio as a unified operator. VirusTotal returns 0/92 detection on all operator domains. The operator's static web assets (JS bundle, brand logo, favicon) are not in VirusTotal at all. This is a defender-actionable gap in the public threat-intel record that depth justifies filling.

2. **Brand-impersonation library scale and target diversity.** 467+ pre-staged subdomains under `inklens.ru` is intermediate-scale (smaller than FIN7's 4,000+ aged domains documented by Silent Push, larger than typical single-kit deployments) but the **vertical diversity** is the standout — 18+ verticals spanning US banking, Russian telecom, Chinese internet, Apple ecosystem, enterprise SaaS, remote access, CI/CD, webmail, payments, and industrial brands. Most documented brand-impersonation operators target a single region or vertical; Inkognito is opportunistically multi-vertical.

3. **Cluster-boundary evidence anchored on Tier-1 OFAC documentation.** The parent investigation's §22.9.1 and §23.12.7 reassessment established that Inkognito (Cluster B), BellaMain (Cluster A), and the Rhadamanthys MaaS customer (Cluster C) are operationally separate actors sharing only Aeza tenancy. The July 1, 2025 OFAC SDN designation of Aeza Group LLC documents Aeza simultaneously hosting BianLian, RedLine, Lumma, Meduza, and BlackSprut as five unrelated actor ecosystems — Tier-1 authoritative confirmation that bulletproof hosting co-residency is a service-utility relationship, not an operator-linkage signal. This boundary is reaffirmed here.

### Evidence Cutoff and Sourcing

- **Evidence cutoff:** 2026-05-07 (last WARP-routed live scrape of operator infrastructure; last DomainTools Iris passive-DNS export).
- **Primary sources:** passive DNS tool (DomainTools Iris) — 19 domain-history pulls, 22 passive-DNS exports covering all 22 confirmed operator domains and 5 operator IPs; threat-intel API (VirusTotal MCP) — direct cross-verification of all operator domains and IPs; WARP-routed `curl` HTTPS probing of all live operator front-ends (so the operator never saw the analyst home IP); Telegram channel direct verification of `@inkconnectvpn` (797 subscribers, channel description, posting cadence).
- **Tier-1 anchors:** OFAC SDN List — Aeza Group LLC (2025-07-01); EU Council Decision (CFSP) 2025/972 — Stark Industries (2025-05-20).
- **Tier-2 supporting:** TRM Labs (Aeza OFAC sanctions); Recorded Future Insikt Group (Stark Industries 2025); Silent Push (FIN7 domain analysis 2024); SentinelOne / Validin (FreeDrain May 2025); Microsoft Security Blog (Storm-2561 March 2026); Hunt.io (Russian malicious infrastructure mapping); GreyNoise (Stark Industries Shell Game 2025); Cisco Talos (Gamaredon network footprints).
- **Tier-3 supporting:** KrebsOnSecurity (Stark Industries 2024, 2025); BleepingComputer (AnyDesk breach January 2024; EU Stark sanctions May 2025).

---

## 3. Technical Classification

> **Analyst note:** This section identifies *what kind of threat* Inkognito is in technical-defender terms. Inkognito is **not a malware family** in the conventional sense — there is no PE binary, no malware sample, no on-host execution surface to recover. It is a **named-brand commercial fraud operation** running across web applications, a commercial VPN service, brand-impersonation phishing infrastructure, BEC burn domains, and a fake crypto exchange. The classification table below reflects that distinction.

### 3.1 Operator Classification

| Field | Value |
|---|---|
| **Type** | Multi-product fraud operation (web-application + commercial VPN service + brand-impersonation phishing + BEC infrastructure + fake crypto exchange). **NOT a binary malware family.** |
| **Operator / Parent Brand** | Inkognito (operator self-identified) |
| **Sub-brands under unified naming** | INK VPN (`inkconnect.ru`), INK Lens (`inklens.ru`, `inklens.co.uk`), Bikaf VPN (`bikaf.ru`, decommissioned), CryptOne (`cryptone.bot` — fake exchange), unloki.ru (Outline-based VPN for censored regions), `bigass.monster` (regional VPN brand) |
| **Operator confidence** | HIGH — operator self-identifies the parent brand via the `@inkconnectvpn` Telegram channel description; the "INK" prefix is a deliberate contraction of "INKognito" applied consistently across `inkconnect.ru`, `inklens.ru`, and `inklens.co.uk`; unified Telegram channel ties the brands. |
| **Named-actor attribution confidence** | INSUFFICIENT (<50%) — first public capture; no prior Tier-1/2/3 TI on the Inkognito brand portfolio; operator self-identification is operator-asserted, not independently corroborated. |
| **Distinct-actor confidence (cluster cohesion)** | MODERATE (78%) — single-tenant EspoCRM back-office, single Marzban Xray/V2Ray fleet panel, single-operator Google×2 / Yandex×1 search-console account control across the brand portfolio, cross-domain `kittenx-404` decommission tombstone with identical signature, consistent `admin@<domain>.eu` SOA across three BEC burn domains, custom `X-Admin-Token` HTTP authentication primitive (operator design choice, not framework default). |
| **Operator language inference** | Russian (Telegram channel content in Russian; Russian payment-processor integration SBP/T-Pay/card; Russian customer-base targeting in INK VPN marketing copy; Russian-language tagline `Надежный VPN от Inkognito! Видь то что скрыто, оставаясь в тумане войны!` — "Reliable VPN from Inkognito! See what is hidden, while remaining in the fog of war!"). |
| **Operator residency** | Russian-nexus strongly indicated (REGRU-RU registrar, Timeweb RU production, Aeza RU back-office; Russian payment integration requires either a Russian-registered legal entity or a Russian front company). Exact geographic location INSUFFICIENT. |
| **Sophistication tier** | Intermediate-Advanced. Enterprise-grade DevOps pipeline (Argo CD, multi-stage UAT/staging, Redis admin tooling, 11-minute domain-to-live automation), jurisdiction-laundering apex decoys, segregated Google accounts by brand for OPSEC, sustained 3-year continuous operation across six hosters and eight registrars. The operator does NOT exhibit novel binary tradecraft — there are no binaries. Sophistication is concentrated at the operations, infrastructure, and OPSEC layers. |
| **First observed activity** | 2023-06-08 (`vetcorbeanca.eu` first observed on Stark Industries IP `193.46.56.182` — earliest confirmed operator activity, BEC burn-domain campaign) |
| **Most recent observed activity** | 2026-05-07 (evidence cutoff). Telegram channel `@inkconnectvpn` posting through 2026-05-04. `inkconnect.ru` flagship operational. `inklens.ru` phishing library active on Timeweb. |
| **Continuous-operation span** | ~2 years 11 months (June 2023 → May 2026) |

### 3.2 Brand Portfolio at a Glance

| Brand | Primary domain | Role | Status (2026-05-07) | Hoster |
|---|---|---|---|---|
| INK VPN | `inkconnect.ru` | Flagship commercial VPN with paid subscription | LIVE (deployed 2026-04-17) | Timeweb RU + Cloudflare |
| INK Lens | `inklens.ru` / `inklens.co.uk` | Brand-impersonation phishing + DevOps subdomain library (467+ subdomains) | LIVE | Timeweb RU (operational) + apex chameleon decoy on GitHub Pages/AmazonS3 |
| Bikaf VPN | `bikaf.ru` | Earlier consumer VPN brand | DECOMMISSIONED via `kittenx-404` tombstone (~Apr 2026, succeeded by INK VPN) | — |
| CryptOne | `cryptone.bot` | Fake crypto exchange (multilingual EN/TR/DE/RU) | LIVE behind Cloudflare with Turnstile bot challenge; origin hidden | Cloudflare (origin unknown) |
| unloki | `unloki.ru` / `users.outline.unloki.ru` | Long-term VPN brand with Outline VPN front for Iran/RU/CN censorship circumvention | LIVE since 2023-11-17 (2.5+ years stable) | Stark/Worktitans TR (`193.46.56.182`) |
| `bigass.monster` | apex | Regional VPN brand front (Russia, Nordics, DACH) | LIVE (drop-and-recapture Aug 2025) | Cloudflare-fronted |
| BEC burn domains (3) | `vetcorbeanca.eu` / `vagtec.eu` / `petkovalegal.eu` | June 2023 spear-phishing email infrastructure with self-served `mail.*`, `ns1.*`, `ns2.*` | EXPIRED (drop-caught by parking services) | Stark/Worktitans TR (`193.46.56.182`) during operator-controlled period |
| 00000xtrading | `00000xtrading.ru` | Earlier EspoCRM back-office hostname (May 2025 → Apr 2026) | DECOMMISSIONED via `kittenx-404` tombstone (2026-04-07); succeeded by `fi1.inklens.co.uk` | Aeza IT (`185.221.196.118`) during operator-controlled period |
| EspoCRM back-office | `fi1.inklens.co.uk` | Current back-office hostname; same dedicated Aeza IT IP as predecessor | LIVE (activated 2026-04-06 with 30-hour overlap to predecessor) | Aeza IT (`185.221.196.118`) — OFAC SDN |
| Marzban panel | `marzban.inklens.co.uk` | Centralized Xray/V2Ray VPN/proxy fleet management | LIVE | Operator-controlled |
| Telegram channel | `@inkconnectvpn` | Operator's public-facing customer-support channel | LIVE (797 subscribers; last post 2026-05-04) | Telegram |

The five active VPN brand fronts (INK VPN, unloki, `bigass.monster`, Marzban-managed regional nodes) are all orchestrated through the same Marzban Xray/V2Ray panel — they share the operator's backend node fleet, not just brand identity.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/inkognito-russian-vpn-phishing-185-221-196-118-20260516/inkognito-brand-portfolio.svg" | relative_url }}" alt="2-column-by-3-row infographic of the Inkognito brand portfolio. Top row (red flagship bands): INK VPN — commercial VPN at inkconnect.ru running Vite/React SPA with 18 API endpoints and Russian SBP/T-Pay/card payment integration, hosted on Timeweb RU 176.124.211.174, registered 2026-04-17 with 11-minute deploy; INK Lens — 467+ brand-impersonation subdomains under inklens.ru and inklens.co.uk targeting Wells Fargo, AnyDesk, OWA 2013, Jenkins, Tencent, and 18+ verticals, with the apex chameleon-decoy on GitHub-then-S3, inklens.ru registered 2026-03-18. Middle row (yellow supporting bands): CryptOne — Cloudflare-fronted fake crypto exchange at cryptone.bot with origin hidden, staging path on 79.137.192.3, live since 2026-03-05; unloki plus Outline — Outline-protocol VPN for Iran/RU/CN censorship circumvention at unloki.ru and users.outline.unloki.ru, hosted Stark TR 193.46.56.182, earliest 2023-11-17, the longest-running portfolio asset. Bottom row: bigass.monster (yellow) — regional VPN brand front with German and Nordic exit nodes, Cloudflare apex with Aeza sub-host, drop-caught and re-acquired 2025-10-21; Bikaf VPN (grey) — earlier minimalist Google-OAuth-only consumer VPN at bikaf.ru, retired via kittenx-404 tombstone April 2026 after about 2 months of operation. Bottom band summary: parent brand Inkognito, Telegram @inkconnectvpn 797 subs first post 2026-03-18, cross-brand operator fingerprints Server: kittenx 404 tombstone, X-Admin-Token HTTP header, Yandex Webmaster ID 98466329. Each brand sits on different infrastructure showing deliberate provider segmentation. Detection anchors footer: Server: kittenx 404, X-Admin-Token, Yandex 98466329, Google SC TXTs, INK VPN asset SHA256s (8a69fe67, d1ae63c9, 53b3515f).">
  <figcaption><em>Figure 1: The Inkognito brand portfolio at a glance — one operator, six brands, three functional roles. The visual demonstrates why this is a unified operator rather than six independent fraud operations: the cross-brand operator fingerprints (Server: kittenx, X-Admin-Token, Yandex 98466329) appear consistently across the live brands despite each brand running on different infrastructure. The decommissioned Bikaf VPN (bottom-right) shows the operator's brand-rotation pattern — retire the MVP, launch the flagship, preserve the operational identity.</em></figcaption>
</figure>

### 3.3 What This Operation Is NOT

To set correct defender expectations, several things this operation is **not**:

- **Not a malware family.** There is no PE sample, no on-host execution component, no persistence mechanism. Detection content is entirely at the network, DNS, proxy, web-content-inspection, and WHOIS-monitoring layers. There are no YARA rules for PE patterns; the YARA content in the [separate detection file](/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/) targets static web assets (JS bundle, brand logo PNG, favicon SVG).
- **Not a Phishing-as-a-Service kit vendor.** The operator does not sell the INK Lens infrastructure to other actors. There is no observable customer-tier panel, no documented per-customer artifact, no marketing of the kits on any reviewed forum. The operator runs the phishing infrastructure for their own monetization.
- **Not a Rhadamanthys distributor or affiliate.** The cross-cluster overlap test against Cluster C (Rhadamanthys MaaS customer) returned zero hits on any of 35 cluster-defining IOCs. Inkognito and the Rhadamanthys customer co-tenanted on `79.137.192.3` (Aeza staging) but share no operator-level evidence per the parent investigation's §22.9.1 / §23.12.7 reassessment.
- **Not a state-aligned actor or VPN-as-cover front.** Analysis-of-Competing-Hypotheses evaluation rules out the state-aligned and false-flag hypotheses. The commercial VPN paywall, the multi-revenue-stream fraud motive (subscription revenue + credential theft + fake-exchange theft + BEC), and the 2-year-11-month commercial-business cost are inconsistent with state-aligned operations.

---

## 4. Capabilities Deep-Dive

> **Analyst note:** This section enumerates *what the operator can do* across each functional role of the operation. Because there is no on-host malware, capabilities are organized by the operator's product portfolio: commercial VPN backend (§4.1), brand-impersonation phishing library (§4.2), BEC burn-domain infrastructure (§4.3), fake crypto exchange (§4.4), centralized proxy/VPN fleet (§4.5), and the operator-fingerprint signatures that tie all of it together (§4.6). Each subsection covers the technical mechanism, what the operator can do with it operationally, and what defenders can hunt for.

### 4.1 Commercial VPN backend — INK VPN

#### Deep Technical Analysis

The flagship operator-facing site `inkconnect.ru` is a **fully-featured commercial VPN business** running on a polished Vite/React single-page-application frontend, a Caddy reverse-proxy in front of an nginx 1.29.8 origin, Let's Encrypt SSL automation, and a custom backend API hosted at `api.inkconnect.ru`.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/inkognito-russian-vpn-phishing-185-221-196-118-20260516/inkconnect-ru-launch-domaintools.jpg" | relative_url }}" alt="DomainTools-captured screenshot of inkconnect.ru on 2026-04-17, the day the INK VPN brand went live. The site is Russian-language, with the Inkognito hooded-figure-with-eye logo, marketing copy emphasizing security/speed/no-logs claims, payment options for Russian SBP and T-Pay, and a Buy Subscription / Login navigation. The header reads BEZOPASNOST', SKOROST' I NADYOZHNOST' SOEDINENIYA (Security, Speed, and Connection Reliability).">
  <figcaption><em>Figure 2: DomainTools-captured screenshot of <code>inkconnect.ru</code> on 2026-04-17, the day the INK VPN brand launched (registered, SSL-certificated, and operationally live within 11 minutes). The polished Russian-language marketing site, Inkognito hooded-figure-with-eye logo, and Russian payment integration (SBP / T-Pay / card) demonstrate this is a real customer-facing commercial product — not a phishing front. The 467+ brand-impersonation subdomain library under <code>inklens.ru</code> runs in parallel on overlapping infrastructure.</em></figcaption>
</figure>

**Production stack fingerprint:**

| Component | Value | Source |
|---|---|---|
| Web server | `nginx/1.29.8` | `Server:` response header |
| Reverse proxy | `Caddy` | `via: 1.1 Caddy` response header |
| Frontend framework | Vite (build tool) + React (runtime) | HTML mount-point pattern + `/assets/index-CoeWw2zM.js` filename hash style |
| Web font | Google Fonts — `Inter` family | `<link>` reference in HTML |
| TLS certificate | Let's Encrypt | First-cert timestamp matches REGRU-RU registration moment |

**JS bundle:** `https://inkconnect.ru/assets/index-CoeWw2zM.js` — 261,587 bytes, SHA256 `8a69fe67a7e9908aa1248c632ffd784033fc4dc613d0b5589279ccc62f717978`, NOT FOUND on VirusTotal. Hardcoded API path prefix `/api/`. String-scraping the bundle recovered the complete API endpoint enumeration:

```
/api/auth/login              /api/promo-code
/api/auth/logout             /api/promo-codes
/api/auth/status             /api/subscription-extend
/api/blocked-domain-delete   /api/subscription-traffic
/api/blocked-domains         /api/subscriptions
/api/gifts                   /api/users
/api/payments                /api/vpn-host
/api/plan                    /api/vpn-host-delete
/api/plans                   /api/vpn-hosts
```

This is **a fully-featured commercial VPN backend**: user auth (login / logout / status), subscription management with plans and promo codes and gift subs, multiple payment methods (correlating with the SBP / T-Pay / card frontend integration), VPN host management (admin can add and remove regional VPN nodes), blocked-domain management (kill-switch / split-tunneling features), traffic-based usage tracking. The operator runs an **actual functioning paid VPN business**, not a fake VPN front.

#### Executive Technical Context

**What This Means:** Many "criminal VPN" cases involve a fake VPN that exists only to harvest credentials or distribute malware. INK VPN is the opposite — it is a *real* VPN service with a *real* paid subscription. The operator collects revenue from genuine paying customers, runs nodes that actually proxy their traffic, and provides customer support via Telegram. The criminality is not in the VPN itself; it is in **what else the same operator runs alongside the VPN** (the 467+ brand-impersonation phishing library, the BEC burn domains, the fake crypto exchange). The legitimate VPN service builds operator-customer trust and provides cover for the rest of the portfolio.

**Example — Real-World Analogy:**
> **Technical:** Operator runs a legitimate commercial VPN with a full subscription backend and Russian payment-processor integration, alongside a 467+ brand-impersonation phishing subdomain library on overlapping infrastructure.
> **Simplified:** Imagine a locksmith who also runs a burglary ring. The locksmith business is real — they cut keys and install deadbolts and bill customers normally. The burglary ring is real too. The locksmith business gives the operator a paper trail of legitimate revenue, a customer base that won't ask hard questions about the operator's other activities, and a plausible reason for their movements around town. The two businesses don't appear to overlap, but they share the same person, the same workshop, and the same toolkit.
> **Security Impact:** Defenders cannot dismiss the INK VPN domain as "just a VPN provider, low-priority." The same operator runs the brand-impersonation library. Outbound connections from your enterprise to `inkconnect.ru` are not evidence of compromise, but they should be tracked as exposure to an operator who *also* runs infrastructure that you must defend against.

**Custom HTTP authentication primitive — `X-Admin-Token`:** The `api.inkconnect.ru` subdomain returns HTTP 404 to anonymous requests but exposes the CORS configuration in the response headers:

```
HTTP/2 404
access-control-allow-origin: *
access-control-allow-methods: GET, POST, PATCH, DELETE, OPTIONS, PUT
access-control-allow-headers: Content-Type, Authorization, X-Admin-Token, Accept, Origin, X-Requested-With
via: 1.1 Caddy
```

`X-Admin-Token` is **not a standard HTTP header**. There is no public RFC or framework-default for it. The operator added it to the CORS allow-list, which means the operator-controlled frontend (or admin tools) sends it as the auth primitive for privileged API calls. **This is a high-value cross-cluster pivot:** any other web-application surface accepting `X-Admin-Token` in its CORS allow-headers list would be a strong candidate for additional operator infrastructure not yet linked to the INK brand portfolio.

**Detection Strategy:** Hunt for the `X-Admin-Token` header in HTTP request headers, response headers, or CORS preflight `Access-Control-Request-Headers` or `Access-Control-Allow-Headers` lists in web-proxy logs, Zeek HTTP logs, or Suricata HTTP rules. See the [separate detection file](/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/) for the Suricata rule `SIG_Inkognito_XAdminToken_Request`.

**Russian payment integration — operator legal-entity surface:** The INK VPN site visibly advertises payment via **SBP** (Russia's Faster Payments System), **T-Pay** (Tinkoff Bank's payment system), and standard card payments. Russian payment integration of this kind requires the operator to have a Russian payment-processor merchant account — typically requires a registered Russian legal entity (an OOO or IP). This is an attribution lead: the INK VPN operator is operating openly in the Russian payment system, which means they are either operating as a Russian-registered business OR they have laundered the merchant account through a front company. Either reading provides downstream investigative surface (SBP / T-Pay merchant ID lookup would resolve the legal entity).

### 4.2 Brand-impersonation phishing library — INK Lens

> **Analyst note:** This is the highest-impact capability for enterprise defenders. The operator maintains 467+ pre-positioned subdomains under `inklens.ru`, each one set up to impersonate a specific enterprise brand. None of them currently host an active phishing page — they all return HTTP 404. But the infrastructure is staged: DNS records pointed, Let's Encrypt certs issued, naming chosen to match real brands. Activating one is a configuration change that takes seconds.

#### Deep Technical Analysis

The operator's primary phishing infrastructure is the Russian apex `inklens.ru`. Reverse-IP enumeration on `77.239.101.23` (the operator's previous U1host endpoint, March-April 2026) recovered **468 unique `*.inklens.ru` rrnames** via DomainTools passive DNS. The post-migration count on Timeweb `176.124.211.174` is 165 subdomains with 95 new subdomains added since the migration — the operator is actively pruning and rotating the library, not abandoning it.

The 467+ figure should be treated as **a floor, not a complete enumeration**: passive DNS only surfaces subdomains that have been queried by external resolvers within the observation window. Subdomains that the operator has staged but never publicly resolved would not appear.

Subdomain analysis splits cleanly into two pools.

**(A) Brand-impersonation phishing pre-stage.** Pre-positioned URLs for victim-facing campaigns. The subdomain itself does the impersonation; an active campaign would simply switch the response from 404 to a cloned login page. Confirmed targets include:

| Subdomain | Targeted brand | Likely victim |
|---|---|---|
| `wellsfargo.inklens.ru` | **Wells Fargo (US banking)** | US retail banking customers |
| `accenture.inklens.ru` | Accenture (consulting) | Accenture employees/clients |
| `adyen-no-stripe.inklens.ru` | Adyen (payment processor; "no-stripe" likely a routing label) | Adyen merchants |
| `asana.inklens.ru` | Asana (project management SaaS) | Asana enterprise users |
| `tele2.inklens.ru` | Tele2 (major Russian mobile carrier) | Russian Tele2 subscribers |
| `tencent.inklens.ru` | Tencent (Chinese internet giant) | Chinese Tencent ecosystem users |
| `sina.inklens.ru` | Sina (Chinese internet portal) | Chinese Sina users |
| `siri-search.inklens.ru` | Apple Siri | Apple ecosystem users |
| `stanley.inklens.ru` | Stanley (tools / security / industrial) | Industrial sector |
| `rafael.inklens.ru` | Rafael (Israeli defense / consumer brand) | Defense-adjacent or consumer |
| `anydesk.inklens.ru` | **AnyDesk (remote access — post-2024-breach brand)** | AnyDesk enterprise users |
| `autodiscover.blog.inklens.ru` | Microsoft Exchange Autodiscover | Exchange administrators |
| `owa2013.inklens.ru` | **Outlook Web Access 2013 (legacy Exchange)** | Organizations still running Exchange 2013 |
| `espace-client.inklens.ru` | French banking customer-portal naming convention | French banking customers |
| `swdcdownloads.inklens.ru` | Microsoft Software Download Center | Microsoft customers seeking downloads |
| `development-jenkins.inklens.ru` | **Jenkins CI (developer)** | DevOps teams using Jenkins |
| `signals.inklens.ru` | Signal Messenger (possible) | Privacy-conscious users |
| `connect-pro-portal.inklens.ru` | Generic enterprise portal | Enterprise SaaS users |
| `democrm.inklens.ru`, `demo-insights.inklens.ru` | Demo CRM / analytics templates | Sales/marketing teams |
| `travel.inklens.ru`, `travelid.inklens.ru` | Travel industry | Corporate travel customers |
| `weatherzone.inklens.ru` | Weather services | Australian / consumer users |
| `e-shop.inklens.ru`, `onlineforms.inklens.ru` | Generic e-commerce / forms | Consumer / form-based phishing |

The targeting spans **multiple regions and verticals**: US banking, Russian telecom, Chinese internet, Apple ecosystem, enterprise SaaS, remote-access tools, Microsoft enterprise stack, French banking, Israeli industrial — the operator is not focused on a single geography. They are building a **brand-impersonation library** they can draw against on demand.

**(B) DevOps / operator-side admin infrastructure.** Internal tooling and pipeline labels — the operator runs a sophisticated DevOps stack alongside the phishing library.

| Subdomain | Role |
|---|---|
| `staging-agent`, `staging-analytic` | Staging environments |
| `uat-aka`, `uat-analytic`, `uat-dashboard`, `uat3`, `uat3-aka` | User-acceptance-test environments |
| `prod-aka` | Production environment |
| `cloud-test`, `report-sandbox`, `visualize-sandbox`, `report-integration` | Sandbox / test environments |
| `redis-commander`, `redisinsight` | Redis database admin tools |
| `argo-cd` | Argo CD (Kubernetes continuous-deployment platform) |
| `dashboard-alpha`, `app-admin`, `vfemea-admin` | Operator dashboards |
| `integration-analytic`, `integration-cicd` | CI/CD and integration testing |
| Numeric (`021`, `153`, `245`, `350`, `361`, `419`, `965`, `977`, `981`) | Likely campaign or kit IDs |
| `90f5afb6-c2b7-40d4-83ed-7a11ca3d6099` | UUID-style per-victim or per-session URL |

The presence of Argo CD, Redis admin tools, UAT/staging environment names, and CI/CD-themed subdomains is **enterprise-grade tooling repurposed for fraud infrastructure**. This is not a script-kiddie operation — the operator runs a deployment pipeline more sophisticated than many legitimate small businesses.

#### Executive Technical Context

**What This Means:** A "brand-impersonation phishing subdomain library" is not a library in the literal sense. It is a set of pre-registered DNS names, each one chosen to match a specific brand, each one already wired to operator infrastructure. The subdomains return 404 because the operator hasn't yet activated a phishing page on them. But the staging work is done: when the operator decides to run a campaign targeting (for example) AnyDesk customers, they don't need to register a new domain (which would create a fresh-domain detection signal), they don't need to wait for DNS propagation, they don't need a new SSL cert (Let's Encrypt automation handles that). They just point the existing `anydesk.inklens.ru` subdomain at the cloned login page and start sending phishing emails. Activation latency: seconds to minutes.

**Example — Real-World Analogy:**
> **Technical:** 467+ pre-positioned brand-impersonation subdomains under `*.inklens.ru` returning HTTP 404, each ready to be activated to a cloned login page in seconds.
> **Simplified:** Imagine a counterfeiter who keeps 467 pre-printed envelopes in a desk drawer. Each envelope has a different real company's logo and return address. Most days the drawer just sits closed. But when the counterfeiter wants to send a fake invoice impersonating "Wells Fargo," they pull out the matching envelope, stuff a fake invoice inside, and drop it in the mail — no envelope-printing delay, no logo-design work, no waiting for materials. The infrastructure is the desk drawer, not the invoice. The 467 envelopes are the cost-sunk capability.
> **Security Impact:** Defenders cannot wait until a specific brand-impersonation subdomain "goes live" to add it to a block list. By the time the subdomain is observed serving a credential-harvest page, the campaign is already running. The defensive posture is to block the entire `*.inklens.ru` and `*.inklens.co.uk` namespace at DNS resolution, treat any DNS query from your enterprise endpoints as a high-fidelity hunt finding, and identify which subdomain matches your own brand so you can monitor for any campaign aimed at your customers or employees.

**Detection Strategy:** DNS-resolver hunts for any query to `*.inklens.ru`, `*.inklens.co.uk`, `*.inkconnect.ru`, `*.bikaf.ru`, `*.bigass.monster`, `*.unloki.ru` from any enterprise endpoint. Even a single DNS query to one of these subdomains is high-fidelity — these subdomains do not appear on legitimate browsing patterns. See the [separate detection file](/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/) for the Sigma rule `sigma_inkognito_dns_brand_impersonation`. Defenders should also identify which subdomain matches their own brand (e.g., `<your-company>.inklens.ru`, if any) and add a brand-monitoring alert.

### 4.3 BEC burn-domain infrastructure — three June-2023 `.eu` domains

> **Analyst note:** This subsection covers the operator's earliest documented activity — a tightly-batched 2023 spear-phishing operation using three throwaway `.eu` domains. The pattern is the most reproducible WHOIS-level operator fingerprint in the entire investigation, and it lets defenders hunt for additional operator-controlled burn domains via Reverse-SOA queries.

#### Deep Technical Analysis

Reverse-PDNS on Stark Industries IP `193.46.56.182` (the operator's long-term VPN endpoint host since 2023-11-17) surfaced three `.eu` domains active in June 2023 that share an identical WHOIS-and-deployment pattern:

| Domain | Theme | Operator-controlled period |
|---|---|---|
| `vetcorbeanca.eu` | Romanian veterinary clinic in Corbeanca (a real town near Bucharest) | 2023-06-09 → 2023-06-15 (6 days, then NS reverted) |
| `vagtec.eu` | Generic tech-themed name | 2023-06-15 → 2024-06-06 (~12 months) |
| `petkovalegal.eu` | Bulgarian / Russian-style legal practice ("Petkova Legal") | 2023-06-24 → 2024-06-18 (~12 months) |

All three follow the exact same migration pattern:

1. Registered at **Namecheap** within a 14-day window of each other (June 2023)
2. Initial NS: Namecheap default `dns1/dns2.registrar-servers.com`
3. Initial IP: Namecheap parking pool
4. Within 1-3 days, switched to operator infrastructure:
   - NS changed to self-served `ns1.<domain>.eu` pointing to `193.46.56.182` (Stark Industries)
   - Mail changed to self-served `mail.<domain>.eu` pointing to `193.46.56.182`
   - SOA changed to `admin@<domain>.eu` (operator-controlled administrative email)
5. Let's Encrypt SSL cert obtained for both apex and `www.`
6. Used for the operator-controlled period
7. Eventually expired and dropped, then drop-caught by parking services (Sedo / Bodis LLC)

The `mail.*` subdomain with SPF/DKIM-ready DNS configuration is the canonical pattern for **Business Email Compromise (BEC) and spear-phishing email campaigns**: register a believable-sounding business domain, configure it with full mail authentication, send phishing emails from `someone@<domain>.eu` that pass deliverability checks, then abandon the apex while keeping the NS infrastructure for residual campaign sustenance. The 12-month operator-controlled period for `vagtec.eu` and `petkovalegal.eu` indicates **sustained BEC infrastructure**, not just a single short campaign.

**The `admin@<domain>.eu` SOA pattern is the strongest WHOIS-level operator fingerprint** in the investigation. It can be searched via DomainTools "Reverse SOA email" to find any other operator-controlled `.eu` domains using this convention. Caveat: this pattern is also a side-effect of self-served NS setup — useful as a behavioral fingerprint but not strictly unique to this operator. Combine with the Stark-IP hosting and the Namecheap-batch registration timing to keep false positives manageable.

#### Executive Technical Context

**What This Means:** Business Email Compromise (BEC) is a category of fraud where an attacker sends emails that impersonate a legitimate business — typically a vendor, a law firm, or an executive — and tricks the recipient into changing wire-transfer routing, releasing sensitive documents, or approving an invoice. The hardest BEC emails to detect are the ones that come from a domain that *looks* like a legitimate business and *passes* email authentication (SPF, DKIM, DMARC). The operator's June 2023 setup of three `.eu` domains with self-served mail infrastructure on Stark Industries is exactly this — they registered believable domain names ("Petkova Legal," a vet clinic, a tech company), configured them with full mail authentication, and kept them operational for nearly a year each.

**Business Impact:** Finance and legal teams are the primary BEC targets. An email from `someone@petkovalegal.eu` to your CFO requesting a wire transfer or document review would pass standard email-authentication checks. Modern email security still relies heavily on sender domain reputation; a domain that has been quietly active for 9-12 months passes most reputation gates. The defensive response is finance-and-legal-team training (verify any wire-transfer change via voice callback), DMARC enforcement on your own domains (so attackers cannot spoof YOU to your customers), and Reverse-SOA monitoring for the `admin@<domain>.eu` pattern on Stark Industries TR ASNs (AS44477 / AS209847) to surface additional operator-controlled burn domains as they emerge.

### 4.4 Fake crypto exchange — CryptOne

#### Deep Technical Analysis

`cryptone.bot` is a Cloudflare-fronted crypto-exchange-themed site with Cloudflare Turnstile bot challenge enforced on the landing page. The site presents multilingual support (EN, TR, DE, RU) and the visual layout of a small crypto trading platform. The origin IP is not recoverable from passive DNS due to full Cloudflare fronting — Certificate Transparency logs from before Cloudflare onboarding might reveal the origin but this was not surfaced in the investigation.

Operationally, "fake crypto exchange" sites in this class typically follow a documented pattern: lure victims via social media or chat-app DMs into "investing" small amounts on a polished-looking exchange that simulates trading gains, then prevent withdrawals when the victim tries to recover the funds (the "pig butchering" / "sha zhu pan" pattern). Without recovery of operator-side scripts or DM transcripts, the specific monetization mechanism for CryptOne is INSUFFICIENT to characterize beyond "fake crypto exchange front."

#### Executive Technical Context

**What This Means:** CryptOne sits in the brand portfolio as a high-conversion monetization vector. Where INK VPN generates modest recurring revenue from real subscribers, and the INK Lens credential-harvest library generates resellable credential dumps, a fake crypto exchange can extract larger one-time sums from individual victims who are tricked into "depositing" funds. The Cloudflare fronting prevents direct origin enumeration but does not block defensive detection at the DNS-resolution layer.

**Detection Strategy:** DNS queries to `cryptone.bot` from any enterprise endpoint should be treated as a high-priority alert. Crypto exchange sites are an unusual destination for enterprise traffic, and `cryptone.bot` specifically is operator-controlled with no legitimate use case. The detection rule belongs in the same DNS hunt-list as the INK Lens brand-impersonation subdomains.

### 4.5 Centralized VPN/proxy fleet — Marzban + Outline + regional brand fronts

> **Analyst note:** This subsection covers the operator's VPN-relay backbone. Multiple consumer brands (INK VPN, unloki, Bikaf, `bigass.monster`) and one censorship-circumvention front (Outline at `users.outline.unloki.ru`) all share a single backend orchestrated through a Marzban admin panel — meaning every subscriber, across every brand, has their traffic relayed through operator-controlled nodes whose configuration the operator manages centrally.

#### Deep Technical Analysis

The operator runs a **Marzban panel** at `marzban.inklens.co.uk`. Marzban (open-source software at github.com/Gozargah/Marzban) is for centrally managing Xray-core or V2Ray-core proxy servers — used legitimately for self-hosted VPN and proxy services, and abused for criminal proxy networks. The panel's presence at an operator-controlled subdomain confirms the operator runs a **centralized proxy/VPN node-management platform** with regional exit nodes visible across multiple consumer-brand fronts:

| Regional node | Brand front |
|---|---|
| `fi1.inklens.co.uk` | Finland exit |
| `de1.inklens.co.uk` | Germany exit |
| `ger.bigass.monster` | Germany exit under `bigass.monster` brand |
| `gr.nodes.unloki.ru` | Greece exit under `unloki` brand |
| Per-customer endpoints under `bikaf.ru` | Pre-decommission Bikaf VPN endpoints |

The **Outline VPN service at `users.outline.unloki.ru`** (deployed 2024-02-12) is a separate proxy product oriented at censorship-circumvention customers in Iran, Russia, and China. Outline is a Jigsaw / Alphabet project that wraps Shadowsocks for VPN-restricted regions; deploying an Outline server under a Russian operator brand front is a targeted customer-acquisition vector for users whose ISP or government blocks standard VPN protocols.

#### Executive Technical Context

**What This Means:** VPN providers — legitimate or otherwise — have **total visibility** into the traffic of every subscriber whose connection they relay. INK VPN subscribers, Bikaf VPN subscribers, `bigass.monster` subscribers, and the Outline censorship-circumvention users at `users.outline.unloki.ru` all route their traffic through operator-controlled exit nodes. The operator can log destination IPs, observed SNI values, traffic timing, packet sizes, and (for unencrypted protocols or where the operator has any breaking primitive) packet contents.

**Business Impact:** Any enterprise employee who connects to a personal device through INK VPN, Bikaf VPN, `bigass.monster`, or the unloki Outline server while accessing enterprise resources is exposing destination metadata to the operator. This is a known general risk for criminal VPN providers; the relevant Inkognito-specific finding is that the operator runs multiple brand fronts orchestrated through a single Marzban panel, so blocking one brand domain at perimeter does not address the parallel brand fronts. The defensive response is to block all five active VPN brand fronts together (`inkconnect.ru`, `bikaf.ru`, `bigass.monster`, `unloki.ru`, and the regional VPN node subdomains under `inklens.co.uk`).

### 4.6 Operator-fingerprint signatures — kittenx-404, Yandex/Google account control, asset hashes

> **Analyst note:** This subsection enumerates the cross-domain signatures that tie the operator's brand portfolio together as a single actor — and that let defenders surface additional operator infrastructure not yet linked to the INK brand portfolio. These fingerprints are the operator's "permanent ink" — features they cannot easily change without breaking their own brand or DevOps.

#### Deep Technical Analysis

**The kittenx-404 decommission tombstone.** When the operator retires a brand domain, they don't NXDOMAIN it — they leave it pointed at a specific 404-returning HTTP server with the exact response signature:

```
HTTP/2 404
Server: kittenx
Content-Length: 148
```

This `kittenx-404` tombstone is the operator's standard "decommissioned" signature. It has been observed on at least two retired Inkognito-controlled domains:

| Domain | Decommissioned | Replaced by |
|---|---|---|
| `00000xtrading.ru` | 2026-04-07 | `fi1.inklens.co.uk` |
| `bikaf.ru` | ~2026-04 | `inkconnect.ru` (INK VPN flagship) |

The operator presumably keeps decommissioned domains registered for residual deliverability and SEO benefits while preventing leaked operational details — the `kittenx` 404 page contains no operator content. This is **a cross-domain operator fingerprint**: any other domain returning the same Server header + 404 + content-length 148 signature is a candidate for additional Inkognito infrastructure. The fingerprint can be operationalized via Censys or Shodan (internet-wide host/service search engines) HTTP search.

**Operator account-control fingerprints.** The operator controls three distinct verification accounts with three external services, each one bound to a specific brand domain via DNS or HTML meta-tag verification:

| Account fingerprint | Bound to | Pivot |
|---|---|---|
| Google Search Console TXT `_Lq_FX-CDt3OmZqq5PNFfmQTZtLSHTNsVkViLTzpTwk` | `inkconnect.ru` | Pivotable via SecurityTrails (passive DNS / IP intelligence platform) / Censys TXT record search for other domains carrying this exact value |
| Google Search Console TXT `xskfj4k4tX_-enfPvu9WrUiWauHFlbuVmyV7thcjwds` | `inklens.ru` | Different Google account from inkconnect.ru — operator segregates accounts by brand for OPSEC |
| Yandex Webmaster ID `98466329` | `inklens.ru` (HTML meta `<meta name="yandex-verification" content="98466329">`) | Strongest pivot — search the internet-wide host/service search engines or Google for HTML meta tag carrying this exact ID to find sibling operator-controlled domains across the open web |

The fact that the operator uses **two separate Google accounts** (one per primary brand) demonstrates account-segregation OPSEC — an inkconnect.ru takedown would not compromise the inklens.ru account access, and vice versa. The single Yandex account on inklens.ru is the highest-value pivot because the verification ID is embedded in the served HTML rather than in a DNS TXT record, making it searchable via web-crawl pipelines.

**Operator-built static asset hashes.** Three production-served asset hashes were captured. All three are operator-controlled and unique to the brand:

| Asset URL | SHA256 | VT status | Significance |
|---|---|---|---|
| `https://inkconnect.ru/logo.png` | `d1ae63c9...` | NOT FOUND | Inkognito hooded-figure-with-eye brand logo |
| `https://inkconnect.ru/favicon.svg` | `53b3515f...` | NOT FOUND | Browser-tab favicon |
| `https://inkconnect.ru/assets/index-CoeWw2zM.js` | `8a69fe67...` | NOT FOUND | Vite/React production bundle (261,587 bytes) |

The logo personifies the brand: hooded anonymous user with watchful eye = "Inkognito". The Telegram channel description (`Надежный VPN от Inkognito! Видь то что скрыто, оставаясь в тумане войны!` — "Reliable VPN from Inkognito! See what is hidden, while remaining in the fog of war!") supplies the verbal half of the same brand identity.

**Why these matter as detection content.** The detection file at [`/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/`](/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/) implements each operator fingerprint as a specific rule. The kittenx-404 tombstone becomes a Suricata HTTP signature; the X-Admin-Token header becomes a Suricata + Sigma HTTP-content rule; the Yandex Webmaster ID and Google Search Console TXT values become content-search rules suitable for web-proxy or web-crawl-pipeline deployment; the static asset SHA256s become YARA rules for web-proxy DLP and threat-hunting cached-content pipelines.

---

## 5. Static Analysis Findings

> **Analyst note:** "Static analysis" for Inkognito means inspecting the production web-application stack the operator serves to victims, without running anything. There is no PE binary to import-walk, no .text section to disassemble, no encrypted strings to recover. This section covers the HTTP response headers (server software, custom headers, CORS configuration), HTML and JavaScript and CSS and asset payloads (cryptographic hashes for IOC-feed inclusion, build-toolchain fingerprints, hardcoded API endpoints), TLS configuration posture, and the DNS / WHOIS / registrar fingerprint of the infrastructure. All evidence below was captured 2026-05-07 via WARP-routed `curl` scraping of the live operator front-ends, so the operator never saw the analyst home IP.

### 5.1 Production stack — `inkconnect.ru` and `api.inkconnect.ru`

A vanilla HTTPS GET request to `inkconnect.ru/` returns a 770-byte stock Vite/React SPA HTML template that mounts to `<div id="root">`. The actual application code, branding, and API client all live in the JS bundle at `/assets/index-CoeWw2zM.js` (covered in §4.1 above). HTTP response headers expose the production stack:

- `Server: nginx/1.29.8`
- `via: 1.1 Caddy`
- Standard Cloudflare envelope when accessed via the public domain

The `api.inkconnect.ru` subdomain returns HTTP 404 to anonymous requests but exposes the operator's custom authentication primitive `X-Admin-Token` in its CORS `Access-Control-Allow-Headers` list — see §4.1 for the full CORS configuration.

### 5.2 Brand-identity assets

Three production-served assets, all operator-controlled, none on VirusTotal as of 2026-05-07:

- `logo.png` — SHA256 `d1ae63c928fd07d51cf79c5165e4431765201ca04a2bee3c309dc00092c4de7c` — the Inkognito hooded-figure-with-eye brand logo.
- `favicon.svg` — SHA256 `53b3515fda56dbbd1f8071a9ef3dc3be80cb7994df22ce8afc2e79147e899b70` — browser-tab favicon.
- `assets/index-CoeWw2zM.js` — SHA256 `8a69fe67a7e9908aa1248c632ffd784033fc4dc613d0b5589279ccc62f717978` — 261,587-byte Vite/React production bundle.

### 5.3 Back-office stack — EspoCRM single-instance deployment

The operator's back-office runs on the dedicated Aeza Italy IP `185.221.196.118` (AS210644). From May 2025 through April 2026, the back-office hostname was `00000xtrading.ru`; on 2026-04-06 the operator brought up `fi1.inklens.co.uk` (resolving to the same IP) and on 2026-04-07 the old hostname was decommissioned with the `kittenx-404` tombstone. The 30-hour overlap is the textbook pattern of a planned operational migration: bring up the new back-office, validate it works, point operator dashboards at the new endpoint, then let the old domain decay.

The back-office identifies itself as **EspoCRM** in the HTTP response title — EspoCRM is an open-source customer relationship management platform commonly used by small-to-medium businesses. The operator runs a **single-instance** EspoCRM deployment as the unified back-office for the entire brand portfolio (subscription management, customer support tickets, phishing campaign tracking, and so on — exact internal data model is not recoverable without a credential).

### 5.4 VPN/proxy fleet management — Marzban panel

Marzban (https://github.com/Gozargah/Marzban) is open-source software for centrally managing Xray-core or V2Ray-core proxy servers. Used legitimately for self-hosted VPN/proxy services and abused for criminal proxy networks. The presence of `marzban.inklens.co.uk` confirms the operator runs the centralized fleet-management platform described in §4.5. No prior Tier-1 or Tier-2 reporting documents Marzban panel abuse in criminal proxy networks — this is a gap in the public record where the operator's specific deployment provides a defender pivot.

### 5.5 Build / deployment-automation fingerprint — 11-minute domain-to-live

Domain registration to fully-operational live deployment for `inkconnect.ru` (the flagship INK VPN brand):

| Time UTC | Event |
|---|---|
| 2026-04-17 14:06:28 | Domain registered at REGRU-RU, "Private Person" registrant |
| 2026-04-17 14:07:50 | Initial Let's Encrypt SSL cert (E7) issued |
| 2026-04-17 14:07:52 | Status active |
| 2026-04-17 14:09:03 | NS records published (ns1.reg.ru, ns2.reg.ru); IP set to 176.124.211.174 (Timeweb RU) |
| 2026-04-17 14:09:10 | Second SSL cert |
| 2026-04-17 14:17:29 | Deployed behind Cloudflare, site live with title "INK"; third SSL cert (E8) for www SAN |

**11 minutes from registration to fully-operational live deployment.** This is a deliberate, professional rollout — the operator clearly has a pre-prepared pipeline: DNS templates ready, Let's Encrypt automation pre-configured, Cloudflare integration scripted, Timeweb hosting setup primed. Combined with the Argo CD / Redis admin / UAT-pipeline subdomains in §4.2(B), the picture is of an operator who treats fraud infrastructure as a software product with a release process.

**Detection implication:** Certificate Transparency monitoring on REGRU-RU + Let's Encrypt cert-issuance bursts within 90 seconds of registration is a defender pivot for catching the operator's next brand launch in flight.

---

## 6. Dynamic Analysis Findings

> **Analyst note:** With no malware binary in scope, "dynamic analysis" for Inkognito means observing the operator's web infrastructure as it serves requests, mutates over time, and responds to real-world events. Sources for the observations below are DomainTools passive DNS (registration, hosting, and apex/subdomain timelines across all operator domains), WHOIS history (registrar, NS, SOA, registrant fields), reverse-IP enumeration on operator-controlled IPs, and direct WARP-routed HTTP probing of live operator front-ends. None of the observations required code execution.

### 6.1 Sustained-operation timeline — 2 years 11 months of continuous presence

The operator's confirmed continuous infrastructure presence runs **2023-06-08 → 2026-05-07** (~2 years 11 months / nearly 3 years). Key milestones:

| Date | Event |
|---|---|
| **2023-06-08** | **`vetcorbeanca.eu` first observed on Stark IP — earliest confirmed operator activity** (BEC burn-domain campaign) |
| 2023-06-13 | `vagtec.eu` deployed in same campaign |
| 2023-06-22 | `petkovalegal.eu` deployed in same campaign |
| 2023-08-29 | `a-loader.site` registered (loader distribution on Aeza) |
| 2023-08-31 | `unloki.ru` registered (long-term VPN brand) |
| 2023-10-10 | `divar-irantop.shop` registered (Iranian-targeted phishing) |
| 2023-11-17 | `unloki.ru` migrated to Stark Industries `193.46.56.182` (still there 2.5+ years later) |
| 2024-02-12 | `users.outline.unloki.ru` Outline VPN service deployed (censorship-circumvention) |
| 2024-07-09 | `bigass.monster` drop-caught by operator (Cloudflare-fronted) |
| 2025-05-17 | `00000xtrading.ru` EspoCRM back-office deployed on `185.221.196.118` |
| 2025-05-20 | EU sanctions Stark Industries (EU Council Decision (CFSP) 2025/972) — operator continues using Stark/Worktitans infrastructure post-sanctions |
| 2025-07-01 | OFAC designates Aeza Group LLC as SDN — operator continues using Aeza infrastructure post-sanctions |
| 2026-02-22 | `bikaf.ru` Bikaf VPN consumer brand launched |
| 2026-03-02 | `cryptone.bot` CryptOne fake exchange registered |
| 2026-03-18 | `inklens.ru` registered + Telegram `@inkconnectvpn` channel first post (coordinated brand launch) |
| 2026-03-19 | `inklens.co.uk` apex chameleon decoy registered |
| 2026-04-02 | Primary phishing host migrated U1host DE `77.239.101.23` → Timeweb RU `176.124.211.174` |
| 2026-04-06 | `fi1.inklens.co.uk` back-office activated (30-hour overlap with `00000xtrading.ru`) |
| 2026-04-07 | `00000xtrading.ru` decommissioned with `kittenx-404` tombstone |
| 2026-04-17 | `inkconnect.ru` registered + INK VPN site live in 11 minutes (flagship brand launch) |
| 2026-05-04 | `inklens.co.uk` apex cover changed GitHub Pages → AmazonS3 |

The progression — 2023 BEC burn domains → 2023 loader distribution → 2024 Outline VPN front → 2025 EspoCRM-backed operations → 2026 INK VPN flagship + brand-impersonation library — is **a single operator's evolution over time**. Each new product builds on the operational maturity gained from the previous one. Continued operation post-Stark-sanctions (May 2025) and post-Aeza-OFAC-SDN (July 2025) on both providers' infrastructure indicates either willingness to engage with sanctioned infrastructure or insufficient deconfliction at the provider level.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/inkognito-russian-vpn-phishing-185-221-196-118-20260516/inkognito-operator-timeline.svg" | relative_url }}" alt="10-event vertical timeline infographic spanning 2 years 11 months of operator activity from 2023-06-08 to 2026-04-17. Event 1 (orange origin band) 2023-06-08: vetcorbeanca.eu BEC burn domain first observed on Stark Industries TR 193.46.56.182, establishing the admin-at-domain.eu SOA fingerprint. Event 2 (orange) 2023-06-15 to 2024-06: vagtec.eu plus petkovalegal.eu added, all three same Namecheap registrar and Stark TR host, vagtec and petkovalegal operator-controlled for 12 months each. Event 3 (red long-term-anchor band) 2023-11-17: unloki.ru registered on the same Stark TR IP, beginning 2.5+ year IP stability. Event 4 (red) 2024-02-12: users.outline.unloki.ru live as censorship-circumvention Outline VPN. Event 5 (yellow regional-brand band) 2024-07-09: bigass.monster regional VPN brand front with Cloudflare apex and Aeza secondary host. Event 6 (red back-office-epoch band) 2025-05-17: 00000xtrading.ru EspoCRM back-office on dedicated Aeza Italy IP 185.221.196.118, survives July 2025 OFAC Aeza sanction. Event 7 (yellow) 2026-02-22: bikaf.ru first consumer-facing VPN MVP on Netts.ru then U1host DE. Event 8 (red Inkognito-brand-launch band) 2026-03-18: inklens.ru registered plus @inkconnectvpn Telegram channel first post on the same day. Event 9 (yellow back-office-rotation band) 2026-04-06 to 2026-04-07: fi1.inklens.co.uk takes over from 00000xtrading.ru with 30-hour overlap, both serving from the same Aeza IT IP, 00000xtrading.ru retired with Server: kittenx 404 tombstone. Event 10 (deep red current-epoch band) 2026-04-17: inkconnect.ru registered with INK VPN site fully operational within 11 minutes, REGRU registrar then Let's Encrypt SSL then Timeweb 176.124.211.174 then Cloudflare front, Russian SBP T-Pay card payment integration live. Footer detection anchors: admin-at-domain.eu SOA pattern, Server: kittenx tombstone, unloki.ru to Stark TR 2.5y stability, Aeza IT 185.221.196.118 EspoCRM back-office.">
  <figcaption><em>Figure 3: The full operator timeline reconstructed from passive DNS, WHOIS history, and reverse-IP data. The progression from BEC burn domains (orange, 2023) through long-term VPN anchors (red, 2023–2024) to back-office maturity (red, 2025) to flagship brand launch (deep red, 2026) shows a single operator's three-year evolution. Two key resilience moments — surviving the May 2025 Stark Industries EU sanction and the July 2025 OFAC Aeza Group designation without infrastructure migration — establish the operator's deliberate sanctions-evasion posture.</em></figcaption>
</figure>

### 6.2 Apex chameleon-decoy tradecraft — `inklens.co.uk`

> **Analyst note:** This is the most sophisticated single tradecraft observation in the operator's toolkit. The apex domain `inklens.co.uk` deliberately serves benign cover content while the operational subdomains under it (`fi1.`, `de1.`, `marzban.`, `api.`) host the actual back-office, VPN nodes, and admin panels. This subsection explains the mechanism and why it defeats standard researcher triage workflows.

The `inklens.co.uk` apex chameleon-decoy lifecycle:

| Date | Event |
|---|---|
| 2026-03-19 | Registered at **Gandi** (French registrar; expires 2027-03-19) |
| 2026-03-21 | First active — Gandi France hosting (`217.70.184.38`, AS29169 FR), Gandi NS, Gandi mail |
| 2026-03-23 | Let's Encrypt SSL cert issued for apex and `www.` |
| 2026-03-24 | Moved off Gandi to **U1host Ltd** (`77.239.101.23`, AS213877, DE) |
| 2026-04-04 | Moved to **GitHub Pages** (`140.82.121.4`, GitHub Inc. AS36459) |
| 2026-04-06 18:08 UTC | Server type changed `nginx` → `github.com`; site title became **"GitHub · Change is constant. GitHub keeps you ahead. · GitHub"** |
| 2026-04-06 | DomainTools captured screenshot showing the **github.com homepage** rendering on `inklens.co.uk` |
| 2026-05-04 | Server type changed `github.com` → **"AmazonS3"** — apex moved to S3 cover |

**Why this matters.** A typical first step in domain triage is to load the apex URL in a browser and screenshot it. With this setup, a researcher loading `https://inklens.co.uk` on 2026-04-06 saw github.com — they would mark the domain as benign and move on. Meanwhile `fi1.inklens.co.uk` resolves directly to the operator's Aeza Italy IP (`185.221.196.118`) and serves the actual EspoCRM back-office. The TLD/registrar/hosting choice is also deliberate **jurisdiction-laundering**: `.co.uk` (UK ccTLD), Gandi (FR registrar), then U1host (DE) → GitHub (US) → S3 (US). No Russian fingerprint anywhere on the apex paper trail. Combined with the absence of operator domains on VirusTotal (0/92 detection), this is sustained anti-attribution discipline.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/inkognito-russian-vpn-phishing-185-221-196-118-20260516/inklens-couk-apex-github-decoy.jpg" | relative_url }}" alt="DomainTools-captured screenshot of inklens.co.uk apex on 2026-04-06 rendering the legitimate github.com homepage in full — including GitHub's blue branded background, the headline The future of building happens together, GitHub Copilot marketing copy, a GitHub Copilot product screenshot, code/plan/collaborate/automate/secure feature navigation, and the standard GitHub footer. There is nothing on the rendered page that suggests the domain is operator-controlled.">
  <figcaption><em>Figure 4: The apex chameleon decoy in action. A researcher loading <code>https://inklens.co.uk</code> on 2026-04-06 saw the full legitimate github.com homepage — no operator-controlled content, no Russian-language artifacts, no indication of malicious tenancy. Meanwhile <code>fi1.inklens.co.uk</code> resolved to <code>185.221.196.118</code> (operator's Aeza Italy EspoCRM back-office). This is the precise tradecraft that produces the persistent 0/92 VirusTotal detection across the operator's domain portfolio: standard apex-screenshot triage workflows produce false-negative verdicts.</em></figcaption>
</figure>

This pattern is documented as **a novel technique variant** in the threat-intel record. The closest analog is FIN7 domain aging (Silent Push 2024), which uses benign static content rather than a live cloud redirect chain. No Tier-1 or Tier-2 vendor has previously documented this specific cloud-redirect chameleon-decoy variant.

**Detection Strategy:** DNS-based apex-vs-subdomain divergence monitoring. If an apex domain consistently resolves to GitHub Pages (`140.82.x.x` ranges) or AmazonS3 (`s3.amazonaws.com` IPs) while subdomains under that apex resolve to a different provider entirely (especially a bulletproof hoster like Aeza or Stark), the apex is potentially a chameleon decoy.

### 6.3 Decommission tombstone — `kittenx-404` operator fingerprint

See §4.6 for full detail. Cross-domain confirmation that the operator's brand-rotation pattern follows planned, professional brand replacement (Bikaf VPN → INK VPN with overlap; `00000xtrading.ru` → `fi1.inklens.co.uk` with 30-hour overlap), not panicked teardown after exposure.

### 6.4 TLS posture — non-browser-client rejection on `inklens.ru`

`inklens.ru` deliberately rejects non-browser TLS clients. A vanilla `curl` request returns `tlsv1 alert internal error` during the TLS handshake — the operator has cipher restrictions or TLS-fingerprinting controls that allow real browsers but reject automated scrapers. This is **a mature anti-reconnaissance posture** on the primary phishing infrastructure. It does not affect detection (DNS queries for the brand-impersonation subdomains remain visible at the resolver layer), but it does mean automated security crawlers won't successfully fetch the served content for classification — a clean reason why VirusTotal's 0/92 detection persists despite the obvious phishing topology.

`inkconnect.ru` and `cryptone.bot` do not exhibit this restriction. `cryptone.bot` instead uses Cloudflare Turnstile bot-challenge — a different anti-automation posture with the same defensive intent.

### 6.5 Telegram channel posting cadence

The `@inkconnectvpn` Telegram channel is the operator's public-facing brand presence. Captured metadata:

| Field | Value |
|---|---|
| Channel URL | `https://t.me/inkconnectvpn` |
| Subscribers | 797 (as of 2026-04-17) |
| First post | 2026-03-18 21:15 UTC |
| Most recent post (as of evidence cutoff) | 2026-05-04 |
| Channel description (Russian) | "Надежный VPN от Inkognito! Видь то что скрыто, оставаясь в тумане войны!" |
| English gloss | "Reliable VPN from Inkognito! See what is hidden, while remaining in the fog of war!" |

The channel's first post corresponds to the same date as the `inklens.ru` registration — this was **a coordinated brand launch**. The operator likely promoted the (then-not-yet-built) INK VPN to existing followers and customers from prior brands during March 2026, then went live with the actual product on April 17. The 797-subscriber count by mid-April indicates real audience-building, consistent with the legitimate-VPN-front interpretation in §4.1.

### 6.6 Sister-brand cross-references on a shared dedicated IP

Reverse-PDNS on `176.124.211.174` (the operator's current Timeweb host) returns only operator-controlled domains. The 9 historical resolutions are all Inkognito-cluster brands or sub-brands. This is **a dedicated operator IP**, not shared hosting. Combined with the 165 active `inklens.ru` subdomains and the inkconnect.ru / akredup.ru / ierkorprogramm.us subdomain co-residency, this provides a single-IP cluster pivot — any new domain resolving to `176.124.211.174` is a strong candidate for additional operator infrastructure.

### 6.7 Bulletproof-hoster portfolio and sanctioned-provider posture

The operator's six-hoster footprint reflects **deliberate functional role segmentation**, not opportunistic infrastructure rental:

| Hoster | ASN | Role | Sanctions status |
|---|---|---|---|
| Aeza Group | AS210644 (IT geolocation) | Back-office (EspoCRM); operator administrative interface | **OFAC SDN 2025-07-01** |
| Aeza Group (RU secondary) | AS216246 | Secondary VPN node host | **OFAC SDN 2025-07-01** |
| Stark Industries / Worktitans B.V. | AS44477 / AS209847 | Long-term VPN endpoint + BEC burn-domain mail infrastructure | **EU sanctioned 2025-05-20** (EU Council Decision (CFSP) 2025/972) |
| JSC Timeweb | AS9123 | Current primary phishing/proxy host | Russian commercial; not currently sanctioned |
| U1host Ltd (DE) | AS213877 | Previous phishing/proxy host (March → April 2026) | German commercial |
| Cloudflare | AS13335 | Public-facing fronting for `cryptone.bot` and `inkconnect.ru` | US commercial |

The deliberate provider segmentation is the inverse of single-provider concentration and demonstrates **informed infrastructure planning**. The operator did not co-locate functions on cheaper infrastructure — they paid for premium bulletproof hosting on specifically the providers that are most resistant to takedown requests. The post-sanctions continuation on both Aeza and Stark/Worktitans is consistent with a Russian-speaking financially-motivated operator who values takedown resistance over reputational considerations.

> **Sanctions implication:** For US-regulated entities, outbound connections to Aeza Group ASNs (AS210644, AS216246) constitute engagement with OFAC-designated SDN infrastructure as of 2025-07-01 and are potentially OFAC-reportable. For EU entities, outbound connections to Stark Industries AS44477 / Worktitans AS209847 constitute engagement with EU-sanctioned infrastructure per EU Council Decision (CFSP) 2025/972. The Sep 2025 KrebsOnSecurity reporting (Tier-3) and Recorded Future Insikt Group reporting (Tier-2) document the Stark Industries sanctions-evasion rebrand to Worktitans — the operator's continued tenancy on AS209847 post-rebrand evidences awareness of the sanctions-evasion channel. Compliance teams should treat outbound connections to Aeza ASNs as engagement with OFAC-designated infrastructure (potentially reportable) and to Stark/Worktitans ASNs as engagement with EU-sanctioned infrastructure.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/inkognito-russian-vpn-phishing-185-221-196-118-20260516/inkognito-hosting-segmentation.svg" | relative_url }}" alt="2-column-by-3-row infographic of the operator's provider segmentation map. Top row (deep red sanctioned bands): Aeza IT — back-office host on AS210644 IP 185.221.196.118 running EspoCRM single-tenant CRM (00000xtrading.ru then fi1.inklens.co.uk), OFAC SDN designation 2025-07-01, operator did NOT migrate off post-sanction, engagement is OFAC-reportable for US entities. Stark Industries to Worktitans B.V. — long-term anchor on AS44477 then AS209847 IP 193.46.56.182 hosting unloki.ru VPN endpoint plus three BEC burn domain mail infrastructure, stable since 2023-11-17 over 2.5+ years, EU sanctioned 2025-05-20 under CFSP 2025/972, rebranded as Worktitans 12 days pre-sanction as sanctions-evasion vehicle per Tier-2 sourcing. Middle row: Timeweb (red current-phishing band) — JSC Timeweb AS9123 IP 176.124.211.174, primary phishing plus INK VPN production host, holds 165 plus 95 inklens.ru subdomains post-migration, hosts inkconnect.ru and api endpoint, not currently sanctioned RU commercial. U1host Ltd DE (yellow previous-phishing band) — AS213877 IP 77.239.101.23 German commercial, hosted decommissioned Bikaf VPN and earlier inklens.ru, 468 inklens.ru rrnames recovered via reverse-IP, operator-active March to April 2026, historical subdomain inventory pivot source. Bottom row (grey abused-legitimate bands): Cloudflare AS13335 — public front for cryptone.bot and inkconnect.ru, hides origin IPs, free-tier DDoS plus SSL termination plus Turnstile bot-challenge, US commercial not sanctioned, legitimate provider whose policy permits abuse. GitHub Pages then Amazon S3 AS36459 — apex chameleon decoy for inklens.co.uk renders github.com homepage while subdomains hide on Aeza IT origin, active since 2026-04-06 with S3 move 2026-05-04, novel chameleon-decoy tradecraft variant. Summary band: two state-sanctioned providers plus four functional roles segregated across six hosters; operator paid for premium takedown-resistant hosting specifically on the most enforcement-resistant providers; continued post-sanction tenancy on both Aeza and Stark equals informed sanctions-evasion posture. Footer detection anchors: AS210644 plus AS216246 Aeza OFAC SDN, AS44477 plus AS209847 Stark/Worktitans EU sanctioned, IPs 185.221.196.118, 193.46.56.182, 176.124.211.174, 77.239.101.23.">
  <figcaption><em>Figure 5: The operator's six-hoster provider-segmentation map. Two sanctioned providers (deep red, top row), two current-or-historical operator-rented hosts (middle row), and two abused-legitimate cloud providers (grey, bottom row). The visual makes the operator's "functional role separation" thesis directly readable — back-office on one provider, long-term anchor on another, current phishing on a third, public fronts on US legitimate cloud. This is deliberate planning, not infrastructure-chasing.</em></figcaption>
</figure>

### 6.8 Cluster boundary — what this report deliberately does NOT cover

This report covers **only Cluster B (Inkognito)** of the OpenDirectory 79.137.192.3 three-cluster investigation. The two adjacent clusters are out of scope, with full coverage in the parent publication at [`/reports/opendirectory-79-137-192-3-20260515/`](/reports/opendirectory-79-137-192-3-20260515/):

- **Cluster A — BellaMain Turkish PhaaS** (`@AresRS34`, `Wadanz` developer alias, PHP/MySQL panel, 7 Turkish marketplace phishing kits, Telegram bot `6797512084`). Co-tenant on `79.137.192.3` (Aeza RU) but operationally separate. Cross-cluster linkage downgraded to LOW per the parent investigation's §22.9.1 / §23.12.7 reassessment.
- **Cluster C — Rhadamanthys MaaS customer** (`79.133.180.168:3394` C2 on Hostkey NL, customer panel `e6d92c6b5b2a03bee7fbab40`, `staticlittlesource.exe` loader, canonical Rhadamanthys Stage-2 binary, InstallUtil.exe LOLBin hollowing). Operationally separate from Cluster B at HIGH confidence — different hosting (Hostkey NL vs Aeza/Timeweb), different toolchain (compiled C++ loader vs Vite/React SPA), no operator-pseudonym overlap, no Telegram overlap.

The cross-cluster overlap test was run against 35 cluster-defining IOCs spanning all three clusters — zero hits on any sample from any cluster's IOCs in any other cluster's artifacts. **All three are co-tenants of the multi-tenant Aeza bulletproof staging utility on `79.137.192.3`, not a single coordinated actor.** The OFAC SDN Aeza Group sanction (July 1, 2025) documents Aeza simultaneously hosting BianLian, RedLine, Lumma, Meduza, and BlackSprut as five unrelated actor ecosystems — co-tenancy on Aeza is a service-utility relationship, not an operator-linkage signal.

---

## 7. MITRE ATT&CK Mapping

> **Confidence note:** all rows below are HIGH confidence unless explicitly marked `(MODERATE)` or `(LOW)`. The Confidence Summary in Section 11 organizes findings by confidence level for the higher-level view. Because Inkognito has no PE malware, the mapping is concentrated on Resource Development, Initial Access, Defense Evasion, Command and Control, and Impact tactics — the operator-action layer rather than on-host execution.

| Tactic / Technique | Name | Evidence |
|---|---|---|
| Resource Development / T1583.001 | Acquire Infrastructure: Domains | 22+ confirmed operator domains across 8 registrars (REGRU-RU, Gandi, Namecheap, Hostinger, FE-RU, DYNADOT, Unstoppable Domains, TIMEWEB-RU); 467+ brand-impersonation subdomains under `inklens.ru` |
| Resource Development / T1583.003 | Virtual Private Server | Footprint on 6 hosters: Aeza RU/IT (AS216246, AS210644), Timeweb RU (AS9123), U1host DE (AS213877), Stark Industries TR (AS44477, sanctioned), Netts.ru RU (AS12695) |
| Resource Development / T1583.004 | Server | EspoCRM single-instance back-office on dedicated Aeza IT `185.221.196.118`; Marzban Xray/V2Ray panel at `marzban.inklens.co.uk` |
| Resource Development / T1583.006 | Web Services | `cryptone.bot` Cloudflare-fronted; `inklens.co.uk` apex on GitHub Pages then AmazonS3 (chameleon decoy) |
| Resource Development / T1584.001 | Compromise Infrastructure: Domains | `bigass.monster` drop-and-recapture (2025-10-21 at DYNADOT); `ierkorprogramm.us` drop-caught aged domain (originally 2018-2019) (MODERATE) |
| Resource Development / T1585.001 | Establish Accounts: Social Media | Telegram channel `@inkconnectvpn` — 797 subscribers, operator's public-facing brand presence |
| Resource Development / T1585.002 | Establish Accounts: Email | Self-served `mail.<domain>.eu` on 3 BEC burn domains (`vetcorbeanca`, `vagtec`, `petkovalegal`) |
| Resource Development / T1585.003 | Establish Accounts: Cloud Accounts | Google Search Console accounts ×2 (separate per-brand); Yandex Webmaster account (ID `98466329`); inferred Cloudflare account for `cryptone.bot` fronting |
| Resource Development / T1587.003 | Develop Capabilities: Digital Certificates | Let's Encrypt automation embedded in 11-min deployment pipeline (cert issuance within 90 seconds of registration on `inkconnect.ru`) |
| Resource Development / T1588.004 | Obtain Capabilities: Digital Certificates | Let's Encrypt SSL certs across all operator domains |
| Resource Development / T1608.003 | Stage Capabilities: Install Digital Certificate | Pre-staged Let's Encrypt certs for all 467+ brand-impersonation subdomains as part of deployment automation |
| Resource Development / T1608.005 | Stage Capabilities: Link Target | 467+ pre-positioned brand-impersonation subdomains under `inklens.ru` awaiting campaign activation |
| Initial Access / T1566.002 | Phishing: Spearphishing Link | Brand-impersonation subdomains targeting Wells Fargo, Tencent, Sina, Tele2, AnyDesk, OWA 2013, Jenkins, MS Software Downloads — pre-staged credential-harvest links |
| Initial Access / T1566.003 | Phishing via Service | June 2023 BEC burn-domain campaign via self-served `mail.<domain>.eu` on Stark Industries IP (MODERATE — specific spearphishing payloads not recovered) |
| Defense Evasion / T1036.005 | Masquerading: Match Legitimate Resource Name or Location | INK Lens brand-impersonation library targeting specific corporate brands; `divar-irantop.shop` mimicking Iran's largest classifieds; `cryptone.bot` posing as legitimate crypto exchange |
| Defense Evasion / T1027.013 | Encrypted/Encoded File | `inklens.ru` TLS deliberately rejects non-browser clients (cipher-restriction / TLS-fingerprinting) — anti-reconnaissance against automated security scanners (MODERATE) |
| Command and Control / T1071.001 | Application Layer Protocol: Web Protocols | All operator infrastructure uses standard HTTPS over nginx + Caddy; brand-impersonation subdomains served over HTTPS with Let's Encrypt certs |
| Command and Control / T1090.002 | Proxy: External Proxy | Cloudflare-fronted `cryptone.bot` (origin hidden); Cloudflare fronting in front of `inkconnect.ru` |
| Command and Control / T1090.003 | Multi-hop Proxy | Marzban-managed Xray/V2Ray fleet at `marzban.inklens.co.uk`; multiple regional VPN exit nodes (`fi1`, `de1`, `ger.bigass.monster`, `gr.nodes.unloki.ru`) |
| Command and Control / T1102.001 | Web Service: Dead Drop Resolver | `inklens.co.uk` apex chameleon-decoy redirect chain (GitHub Pages → AmazonS3); plausible but unconfirmed use as controlled redirect target for operational subdomain discovery (LOW) |
| Impact / T1657 | Financial Theft | Russian SBP / T-Pay / card payment integration on INK VPN; CryptOne fake exchange; BEC burn-domain infrastructure |
| Impact / T1656 | Impersonation | 467+ brand-impersonation subdomains; CryptOne fake exchange impersonating legitimate crypto exchange |

---

## 8. Indicators of Compromise

> **Full machine-readable IOC feed:** the complete, validated, machine-readable IOC inventory is at [`/ioc-feeds/inkognito-russian-vpn-phishing-185-221-196-118-20260516-iocs.json`](/ioc-feeds/inkognito-russian-vpn-phishing-185-221-196-118-20260516-iocs.json). The feed is **unfanged** (no `[.]` substitution) and ready for SIEM/EDR ingestion. The table below is a defanged human-readable summary of the **highest-priority block-list and hunt candidates**; consult the IOC feed for full context fields (`first_seen`, `last_seen`, `confidence`, `purpose`, `notes`), service objects (registry/scheduled-task structures), and the complete subdomain enumeration.

### 8.1 Highest-priority block-list candidates

| Type | Indicator | Confidence | Context |
|---|---|---|---|
| IP | `185.221.196[.]118` | HIGH | Operator EspoCRM back-office (Aeza Italy AS210644 — **OFAC SDN**). Single-tenant; 9 historical resolutions all operator-controlled. |
| IP | `176.124.211[.]174` | HIGH | Current primary phishing/proxy host (Timeweb RU AS9123). Hosts `inklens.ru`, `inkconnect.ru`. Dedicated operator IP. |
| IP | `77.239.101[.]23` | HIGH | Previous phishing/proxy host (U1host DE AS213877). Held 502 subdomains across `inklens.ru` + `bikaf.ru`. |
| IP | `193.46.56[.]182` | HIGH | Long-term operator VPN endpoint (Stark Industries TR AS44477 / Worktitans AS209847 — **EU-sanctioned**). 2.5+ years continuous. Hosts `unloki.ru` + 3 `.eu` BEC burn domains. |
| IP | `79.137.203[.]87` | HIGH | Secondary VPN node host (Aeza RU AS216246 — **OFAC SDN**). |
| IP | `92.38.219[.]225` | MODERATE | Additional operator-adjacent IP per Stage-2 infrastructure analysis. |
| Domain | `inkconnect[.]ru` | HIGH | INK VPN flagship brand — primary consumer VPN. |
| Domain | `api.inkconnect[.]ru` | HIGH | INK VPN backend API (CORS exposes `X-Admin-Token`). |
| Domain | `inklens[.]ru` | HIGH | INK Lens — primary phishing/proxy infrastructure (165+ active subdomains). |
| Domain | `inklens[.]co[.]uk` | HIGH | Apex chameleon decoy (apex redirects to GitHub/S3; subdomains run hidden on Aeza IT). |
| Domain | `fi1.inklens[.]co[.]uk` | HIGH | Current operator back-office hostname. |
| Domain | `de1.inklens[.]co[.]uk` | HIGH | Germany VPN node. |
| Domain | `marzban.inklens[.]co[.]uk` | HIGH | Marzban Xray/V2Ray fleet-management panel. |
| Domain | `00000xtrading[.]ru` | HIGH | Decommissioned EspoCRM back-office (`kittenx-404` tombstone). |
| Domain | `bikaf[.]ru` | HIGH | Decommissioned consumer VPN brand (`kittenx-404` tombstone). |
| Domain | `cryptone[.]bot` | HIGH | CryptOne fake crypto exchange (Cloudflare-fronted, origin hidden). |
| Domain | `unloki[.]ru` | HIGH | Long-term VPN brand front (Outline-based). |
| Domain | `users.outline.unloki[.]ru` | HIGH | Outline VPN service for Iran/RU/CN. |
| Domain | `bigass[.]monster` | MODERATE | VPN brand front (drop-and-recapture). |
| Domain | `vetcorbeanca[.]eu` | HIGH | June 2023 BEC burn domain (Romanian vet theme). |
| Domain | `vagtec[.]eu` | HIGH | June 2023 BEC burn domain (~12 months operator). |
| Domain | `petkovalegal[.]eu` | HIGH | June 2023 BEC burn domain (~12 months operator). |
| URL | `https://inkconnect[.]ru/assets/index-CoeWw2zM.js` | HIGH | INK VPN main JS bundle. |
| URL | `https://t[.]me/inkconnectvpn` | HIGH | Operator Telegram customer-support channel. |
| SHA256 (JS) | `8a69fe67a7e9908aa1248c632ffd784033fc4dc613d0b5589279ccc62f717978` | HIGH | INK VPN Vite/React production JS bundle, 261,587 bytes. NOT FOUND on VirusTotal. |
| SHA256 (PNG) | `d1ae63c928fd07d51cf79c5165e4431765201ca04a2bee3c309dc00092c4de7c` | HIGH | Inkognito hooded-figure-with-eye brand logo. |
| SHA256 (SVG) | `53b3515fda56dbbd1f8071a9ef3dc3be80cb7994df22ce8afc2e79147e899b70` | HIGH | INK VPN favicon SVG. |

### 8.2 Brand-impersonation phishing subdomains (DNS hunt list)

The 25 enumerated brand-impersonation subdomains under `*.inklens.ru`. DNS queries from your enterprise network for ANY of these are high-fidelity indicators (these subdomains exist only to be clicked). Defanged for presentation safety.

```
wellsfargo.inklens[.]ru             accenture.inklens[.]ru
adyen-no-stripe.inklens[.]ru        asana.inklens[.]ru
tele2.inklens[.]ru                  tencent.inklens[.]ru
sina.inklens[.]ru                   siri-search.inklens[.]ru
stanley.inklens[.]ru                rafael.inklens[.]ru
anydesk.inklens[.]ru                autodiscover.blog.inklens[.]ru
owa2013.inklens[.]ru                espace-client.inklens[.]ru
swdcdownloads.inklens[.]ru          development-jenkins.inklens[.]ru
signals.inklens[.]ru                connect-pro-portal.inklens[.]ru
democrm.inklens[.]ru                demo-insights.inklens[.]ru
travel.inklens[.]ru                 travelid.inklens[.]ru
weatherzone.inklens[.]ru            e-shop.inklens[.]ru
onlineforms.inklens[.]ru
```

### 8.3 Operator-fingerprint behavioral indicators (hunt content)

| Indicator | Type | Pivot value |
|---|---|---|
| HTTP response: `Server: kittenx` + status 404 + `Content-Length: 148` | HTTP header signature | Operator decommission tombstone — surfaces additional retired operator domains |
| HTTP request OR response with `X-Admin-Token` header (or `X-Admin-Token` in CORS `Access-Control-Allow-Headers` / `Access-Control-Request-Headers`) | HTTP header signature | Operator's custom admin auth primitive — pivots cluster expansion |
| HTML meta `<meta name="yandex-verification" content="98466329">` | HTML meta tag | Operator Yandex Webmaster verification ID — pivots to sibling operator-controlled domains |
| DNS TXT value `_Lq_FX-CDt3OmZqq5PNFfmQTZtLSHTNsVkViLTzpTwk` | DNS TXT | Operator Google Search Console verification for `inkconnect.ru` |
| DNS TXT value `xskfj4k4tX_-enfPvu9WrUiWauHFlbuVmyV7thcjwds` | DNS TXT | Operator Google Search Console verification for `inklens.ru` |
| WHOIS SOA email matching `admin@<domain>.eu` on `.eu` domains hosted on AS44477 / AS209847 (Stark/Worktitans) | WHOIS SOA | Operator BEC burn-domain WHOIS fingerprint |
| Reverse-IP cluster with operator-only resolutions on Timeweb AS9123 / Aeza Italy AS210644 single-tenant IPs | Passive DNS | Single-tenant operator IP identification |

### 8.4 Network-signature combination

The operator's production HTTP-response stack carries a distinctive combination:

```
Server: nginx/1.29.8
via: 1.1 Caddy
Access-Control-Allow-Headers: Content-Type, Authorization, X-Admin-Token, Accept, Origin, X-Requested-With
```

The combination of `nginx/1.29.8 + via: 1.1 Caddy + X-Admin-Token in allow-headers` is high-confidence operator infrastructure. Combine with the IP and domain lists above to keep false positives manageable.

### 8.5 Ecosystem Exposure

**Ecosystem exposure: UNKNOWN.** This investigation is passive-only (no telemetry, no endpoint visibility, no subscriber data). No data source is available to estimate how many enterprise networks have queried Inkognito infrastructure, how many enterprise users have subscribed to INK VPN or Bikaf VPN, or how many organizations appear in the 467+ brand-impersonation target list from a victim perspective rather than an operator-catalog perspective.

What the investigation does establish about exposure surface: the brand-impersonation library targets at least 18+ enterprise verticals spanning US banking (Wells Fargo), enterprise SaaS (Asana, Accenture, Adyen), Chinese internet (Tencent, Sina), Russian telecom (Tele2), remote-access tooling (AnyDesk), Microsoft enterprise stack (OWA 2013, SWDC), and developer infrastructure (Jenkins CI) — see §4.2 for the full enumerated target list. Any organization whose brand appears in §4.2 should treat their own brand-impersonation subdomain as actively staged against their customers or employees, even though no in-flight payload was observed at evidence cutoff. Ecosystem exposure assessment should be revisited if telemetry becomes available from endpoint or DNS-resolver sources with visibility into Inkognito infrastructure queries.

---

## 9. Threat Actor Assessment

> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-2026-009 is an internal tracking designation assigned by The Hunters Ledger to actors observed across analysis who cannot yet be linked to a publicly named threat group. This label will not appear in external threat intelligence feeds or vendor reports — it is specific to this publication. If future evidence links this activity to a known named actor, the designation will be retired and updated accordingly.

> **UTA file lineage:** UTA-2026-009 was **originally created in the 2026-05-15 multi-cluster investigation** as one of three new UTAs (UTA-2026-008 BellaMain, UTA-2026-009 Inkognito, UTA-2026-010 Rhadamanthys MaaS customer) covering the OpenDirectory 79.137.192.3 co-tenancy. This standalone report **extends** the UTA-2026-009 Activity Log with deeper Inkognito-specific evidence; it does not create a new UTA and does not modify the originating distinguishing characteristics. The canonical UTA file is at `threat-intel-vault/threat-actors/UTA-2026-009.md`.

### 9.1 Attribution Conclusion

| Attribution dimension | Confidence | Conclusion |
|---|---|---|
| **Single operator across the brand portfolio** (distinct-actor) | **MODERATE (78%)** | The Inkognito brand portfolio (INK VPN, INK Lens, Bikaf VPN, CryptOne, unloki, `bigass.monster`, BEC burn domains) is operated by **a single Russian-speaking multi-product fraud operator**. |
| **Named-actor attribution** (linkage to a publicly named actor) | **INSUFFICIENT (<50%)** | We **cannot attribute** Inkognito to a publicly named actor at this time. No prior Tier-1, Tier-2, or Tier-3 source documents the Inkognito brand portfolio. Operator self-identification via Telegram is operator-asserted, not independently corroborated. |
| **Operator language inference** | HIGH | Russian (Telegram content, SBP/T-Pay integration, Russian-language marketing copy, Russian customer-base targeting). |
| **Operator motivation** | HIGH | **Financial gain** — subscription VPN revenue + credential theft + fake-exchange theft + BEC campaigns. No state-actor indicators. |
| **Cross-cluster linkage to UTA-2026-008 (BellaMain)** | **LOW** (actively rebutted) | Zero overlap on Telegram identifiers, developer pseudonyms, DNS/SOA/NS patterns, operator language, payment infrastructure, or production-C2 provider per parent investigation §22.9.1 / §23.12.7 reassessment. |
| **Cross-cluster linkage to UTA-2026-010 (Rhadamanthys MaaS customer)** | **LOW** (actively rebutted) | Zero IOC overlap; different hoster (Hostkey NL vs Aeza/Timeweb); different toolchain (compiled C++ loader vs Vite/React SPA). |

### 9.2 Distinguishing Characteristics (per UTA-2026-009)

Eight characteristics across four dimensions support the MODERATE distinct-actor finding:

**Technical / Code Fingerprints:**
1. Custom HTTP API authentication header `X-Admin-Token` on `api.inkconnect.ru` (operator design choice, not framework default); combined with three operator-built static asset hashes (JS bundle `8a69fe67…`, brand logo `d1ae63c9…`, favicon `53b3515f…`), all NOT FOUND on VirusTotal.
2. Single-tenant EspoCRM back-office on dedicated Aeza Italy IP `185.221.196.118` providing cross-product CRM continuity through the `00000xtrading.ru` → `fi1.inklens.co.uk` migration with 30-hour overlap.

**Infrastructure Fingerprints:**
3. Cross-domain `kittenx-404` decommission tombstone (`Server: kittenx` + status 404 + `Content-Length: 148`) on `00000xtrading.ru` (decommissioned 2026-04-07) AND `bikaf.ru` (decommissioned ~2026-04-17).
4. 467+ brand-impersonation subdomains under `inklens.ru` (165 verified floor on Timeweb), targeting 18+ verticals across multiple regions.
5. Multi-tier provider segmentation across functional roles — Aeza IT for back-office, Stark/Worktitans TR for long-term VPN, Timeweb RU for current phishing, Cloudflare for production fronting. The deliberate role segmentation is the inverse of single-provider hosting concentration.
6. BEC burn-domain pattern — three `.eu` domains registered within a 14-day window at Namecheap with self-hosted NS on Stark TR and consistent `admin@<domain>.eu` SOA across all three.

**Account Fingerprints:**
7. Two operator-controlled Google Search Console verification tokens (separate accounts per primary domain — `inkconnect.ru` and `inklens.ru`) plus one operator-controlled Yandex Webmaster ID `98466329`. Single-operator account control across multiple operator-domain assets is direct cross-property attribution.

**Behavioral / Operational Fingerprints:**
8. Self-declared multi-product brand portfolio with operator-published brand identity via `@inkconnectvpn` Telegram channel (797 subscribers; tagline "Reliable VPN from Inkognito! See what is hidden, while remaining in the fog of war!"). Provide-then-phish dual-business model (legitimate VPN paired with brand-impersonation phishing on overlapping infrastructure). 2-year-11-month continuous operation.

### 9.3 Analysis of Competing Hypotheses

Six hypotheses were evaluated to characterize the operator. The winning hypothesis and the rejected alternates:

| Hypothesis | Verdict |
|---|---|
| **H1: Single Russian-speaking multi-product fraud operator** | **Winner.** Best explained by the evidence. Operator self-identification + brand cohesion + single back-office + single Marzban panel + cross-domain operator fingerprints all converge. |
| H2: White-labeled VPN reseller | Ruled out. EspoCRM dedicated back-office + custom code + single search-console accounts rebut the reseller model. |
| H3: Multiple operators sharing the Inkognito brand | Ruled out. Cross-domain `kittenx-404` tombstone with identical signature + single back-office migration pattern rebut multi-operator brand-sharing. |
| H4: Franchise / affiliate of larger criminal enterprise | Latent possible alternate. Not actively supported by current evidence but not ruled out either. |
| H5: State-aligned VPN front | Ruled out. Commercial paywall + multi-vertical fraud motive (subscription revenue + credential theft + fake exchange + BEC) inconsistent with state operations. |
| H6: False flag | Ruled out. Coherent self-identification + 2y11mo commercial business cost rebut false-flag hypothesis. |

### 9.4 Identity Artifacts (Stage-1 Recovered Fingerprints)

The following 10 identity artifacts are **fingerprints for cross-investigation tracking**, NOT independent attributions to a publicly named threat actor. They reinforce distinct-actor MODERATE (78%); they do not advance named-actor confidence above INSUFFICIENT (<50%):

| Artifact | Value | Context |
|---|---|---|
| Telegram channel | `@inkconnectvpn` | 797 subscribers, first post 2026-03-18 21:15 UTC, channel description self-identifies "Inkognito" parent brand |
| Parent brand name | `Inkognito` | Operator-self-identified; "INK" prefix is a deliberate contraction across `inkconnect.ru`, `inklens.ru`, etc. |
| Google Search Console TXT | `_Lq_FX-CDt3OmZqq5PNFfmQTZtLSHTNsVkViLTzpTwk` | For `inkconnect.ru` |
| Google Search Console TXT | `xskfj4k4tX_-enfPvu9WrUiWauHFlbuVmyV7thcjwds` | For `inklens.ru` (separate Google account) |
| Yandex Webmaster ID | `98466329` | In `inklens.ru` HTML meta tags |
| Custom HTTP auth header | `X-Admin-Token` | Operator design choice on `api.inkconnect.ru` |
| Decommission tombstone | `Server: kittenx` + 404 + `Content-Length: 148` | Cross-domain operator fingerprint |
| BEC SOA pattern | `admin@<domain>.eu` | Self-served `.eu` mail infrastructure on Stark TR |
| SHA256 (JS) | `8a69fe67…` | INK VPN production JS bundle |
| SHA256 (PNG) | `d1ae63c9…` | Inkognito hooded-figure-with-eye brand logo |
| SHA256 (SVG) | `53b3515f…` | INK VPN favicon |

### 9.5 What Would Upgrade Named-Actor Attribution

- **Russian underground forum identity** — a known XSS / Exploit forum handle tied to the Inkognito brand or any operator pseudonyms. Resolution would require paid Russian-underground-forum TI access (KELA, Flashpoint, Intel 471, Recorded Future).
- **SBP / T-Pay merchant ID lookup** — would resolve the legal entity behind the Inkognito brand portfolio. Russian payment-processor merchant search is the highest-value pivot.
- **Russian regulator action** naming Inkognito (Roskomnadzor / Russian MoI / federal financial-crime).
- **Tier-2 vendor report** — a single Tier-2 vendor publication documenting the Inkognito brand portfolio would raise named-actor attribution to MODERATE.
- **Internet-wide host/service search engine favicon-hash pivot** from the Inkognito hooded-figure-with-eye logo PNG to other operator-controlled sites carrying the same favicon.
- **Telegram identity recovery** — Telegram metadata correlation against the `@inkconnectvpn` channel admin is a candidate research path; resolution probability is unknown without attempting the lookup.

**Key Assumptions Check — high-sensitivity assumptions underlying current confidence levels:**

The MODERATE distinct-actor (78%) and INSUFFICIENT named-actor (<50%) confidence levels rest on three assumptions that, if invalidated, would materially change the assessment:

- **(a) Telegram channel authenticity:** The `@inkconnectvpn` channel description is treated as operator-authored. If the channel were an impersonation or fan account not controlled by the actual Inkognito operator, the brand-identity cross-linking derived from it would require reassessment.
- **(b) `kittenx-404` tombstone uniqueness:** The cross-domain `Server: kittenx` decommission tombstone is treated as an operator-deployed fingerprint, not a default from a third-party hosting platform. If it were a platform-level default on a bulletproof hoster (e.g., a Marzban or Caddy configuration applied to all tenants), the cross-domain attribution weight would drop significantly.
- **(c) EspoCRM single-tenancy:** The dedicated Aeza Italy IP `185.221.196.118` is treated as single-tenant (all nine historical DNS resolutions are operator-controlled). If the IP were co-tenanted and EspoCRM were serving a different operator's CRM, the back-office attribution anchor would require re-evaluation.

---

## 10. Detection and Response Orientation

> **Full detection content:** YARA rules (3), Sigma rules (8), and Suricata signatures (5) — totaling 16 rules — are in the [separate detection file](/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/). This section does not duplicate detection content; it provides priority and orientation only.

### 10.1 Highest-Value Detection Priorities

1. **DNS query hunt for brand-impersonation subdomains under `*.inklens.ru` and `*.inklens.co.uk`** — these subdomains exist only for fraudulent use; any DNS query from an enterprise endpoint is high-fidelity. Implemented as Sigma rule `sigma_inkognito_dns_brand_impersonation` in the detection file. Note: the shipped Sigma rule matches 25 enumerated subdomains; for full-zone coverage, deploy the supplemental wildcard snippet documented in the detection file Coverage Gap §2.
2. **HTTP `Server: kittenx` + status 404 + `Content-Length: 148` response signature** in web-proxy or Zeek HTTP logs — operator's decommission tombstone, surfaces additional retired operator infrastructure not yet enumerated. Implemented as Suricata rule `SIG_Inkognito_KittenX_Tombstone`.
3. **HTTP `X-Admin-Token` header** in request, response, or CORS preflight `Access-Control-Allow-Headers` — operator's custom admin auth primitive, pivots cluster expansion to any other operator-controlled API surface. Implemented as Suricata rule `SIG_Inkognito_XAdminToken_Request`.
4. **HTML meta tag content search for `<meta name="yandex-verification" content="98466329">`** — operator Yandex Webmaster ID, pivots to sibling operator-controlled domains across the open web. Deployable via web-crawl pipeline or internal site-audit tooling (NOT via DNS query logs — this is an HTML meta tag, not a DNS record).
5. **WHOIS Reverse-SOA monitoring for `admin@<domain>.eu`** on `.eu` domains hosted on Stark Industries AS44477 / Worktitans AS209847 — operator's BEC burn-domain WHOIS fingerprint.

### 10.2 Containment Targets (Categories Only)

This is not an incident response playbook. Defenders facing an in-flight campaign should engage their internal IR team or established response procedures.

- **Block all six confirmed operator IPs** at perimeter (`185.221.196.118`, `176.124.211.174`, `77.239.101.23`, `193.46.56.182`, `79.137.203.87`, `92.38.219.225`). (`92.38.219.225` is MODERATE confidence; block based on operational risk tolerance — see §8.1 row.)
- **Block / sinkhole all confirmed operator domains and apex domains** at DNS resolver (`inkconnect.ru`, `inklens.ru`, `inklens.co.uk`, `bikaf.ru`, `cryptone.bot`, `unloki.ru`, `bigass.monster`, `vetcorbeanca.eu`, `vagtec.eu`, `petkovalegal.eu`, `00000xtrading.ru`, `divar-irantop.shop`, `akredup.ru`, `ierkorprogramm.us`, `evotoptan.com`, `a-loader.site`).
- **For US-regulated entities,** consider blocking outbound connections to Aeza Group ASNs (AS210644, AS216246) at perimeter — these are OFAC-designated SDN infrastructure as of 2025-07-01.
- **For EU-regulated entities,** consider blocking outbound connections to Stark Industries AS44477 / Worktitans AS209847 — these are EU-sanctioned per EU Council Decision (CFSP) 2025/972. ASN-level blocks for AS210644/AS216246 will incidentally block other malicious tenants documented in the OFAC SDN listing (BianLian, RedLine, Lumma, Meduza, BlackSprut), which is a defensive feature, not a side-effect.
- **Brand-impersonation campaign monitoring:** identify which subdomains under `inklens.ru` match your own enterprise brands and configure brand-monitoring alerts for any DNS query, HTTP request, or referenced URL.

### 10.3 Persistence-Removal Targets

**Not applicable.** Inkognito has no on-host persistence — there is no malware to remove. Response is entirely at the network, DNS, proxy, and WHOIS-monitoring layer.

---

## 11. Confidence Summary

Findings organized by confidence level (per CLAUDE.md CONFIDENCE LEVELS framework). This summary provides the higher-level view that the inline `(MODERATE)` / `(LOW)` markers in the MITRE table and elsewhere reference.

### 11.1 DEFINITE (Direct Evidence)

- Production stack identification — `Server: nginx/1.29.8`, `via: 1.1 Caddy`, Vite/React SPA build pattern (directly observed in HTTP responses).
- Custom HTTP authentication header `X-Admin-Token` in CORS `Access-Control-Allow-Headers` on `api.inkconnect.ru` (directly observed in response headers).
- `kittenx-404` decommission tombstone signature on `00000xtrading.ru` and `bikaf.ru` (directly observed in HTTP responses).
- Three operator-built static asset SHA256 hashes (JS bundle, brand logo, favicon) — direct hash computation on captured assets.
- Google Search Console TXT values, Yandex Webmaster ID, full subdomain enumeration on `*.inklens.ru` — directly observed via DNS / HTML inspection.
- 11-minute domain-to-live deployment timeline for `inkconnect.ru` — directly observed via Certificate Transparency + DomainTools timeline.
- OFAC SDN status of Aeza Group LLC (US Treasury list, 2025-07-01).
- EU sanctions status of Stark Industries Solutions Ltd (EU Council Decision (CFSP) 2025/972, 2025-05-20).

### 11.2 HIGH (Strong Evidence)

- Single-operator cohesion across the Inkognito brand portfolio — multiple cross-domain operator fingerprints converge (`X-Admin-Token`, `kittenx-404`, single-tenant EspoCRM, single Marzban panel, brand-naming consistency, account-control overlaps).
- "Provide-then-phish" dual-business model — operator runs both a real commercial VPN (with Russian payment integration) and a 467+ brand-impersonation phishing library on overlapping infrastructure.
- Russian-language inference (Telegram channel content + Russian payment processors + Russian customer-base marketing).
- Bulletproof-hosting status of Aeza (Tier-1 OFAC) and Stark/Worktitans (Tier-1 EU sanction) — direct sanctions documentation.
- 2-year-11-month continuous operation timeline — multiple corroborating WHOIS / passive-DNS timestamps.

### 11.3 MODERATE (Reasonable Evidence)

- **Distinct-actor (Inkognito-only) attribution at 78%** — qualitatively assessed via ACH; not DEFINITE because no legal-entity identification, no underground-forum cross-reference, no Tier-1/2/3 prior public TI on the Inkognito brand portfolio.
- `bigass.monster` operator-controlled status — drop-and-recapture pattern post-Aug-2025 lapse; post-recapture WHOIS is "REDACTED FOR PRIVACY" and could plausibly be a different actor. Aeza-hosted `ger.bigass.monster` sub-resolution is consistent with the operator pattern but not conclusive.
- `divar-irantop.shop` linkage to the operator — brief Aeza co-residency evidence; naming theme strongly Iran-targeting but linkage is not conclusive.
- T1584.001 (Compromise Infrastructure: Domains) — drop-catching documented but full chain-of-control proof for each drop-caught domain is incomplete.
- T1027.013 — TLS browser-fingerprinting on `inklens.ru` interpreted as deliberate anti-reconnaissance, but could be incidental cipher-suite configuration.

### 11.4 LOW (Weak / Circumstantial Evidence)

- T1102.001 (Dead Drop Resolver) — `inklens.co.uk` apex chameleon-decoy redirect chain *could* serve as a controlled redirect target for operational subdomain discovery. No direct observation of this use.
- Operator residency narrower than "Russian-nexus" — exact geographic location cannot be inferred from current evidence.
- `akredup.ru` and `ierkorprogramm.us` co-residency on Timeweb `176.124.211.174` — same co-residency evidence quality that excluded other unrelated domains in the parent investigation. Documented as candidates, not confirmed operator assets.

### 11.5 INSUFFICIENT (Cannot Assess)

- **Named-actor attribution** — no public TI; first-capture documentation. Cannot attribute Inkognito to a publicly named actor at this time.
- Operator legal entity behind Russian SBP / T-Pay merchant account — would require Russian payment-processor merchant ID lookup.
- CryptOne (`cryptone.bot`) origin IP — full Cloudflare fronting prevents passive DNS resolution. CT-log pre-fronting investigation not completed in this evidence cycle.
- Specific spearphishing payloads from the June 2023 `.eu` BEC burn-domain campaign — infrastructure documented, but the actual email contents and victims are not recovered.
- In-flight credential-harvest payloads on any of the 467+ brand-impersonation subdomains — all currently return HTTP 404 at the evidence cutoff.

---

## 12. Coverage Gaps and Open Questions

> **Analyst note:** This section documents what the investigation could not determine and what evidence would close the gap. It serves both as honesty about analytical limits and as a roadmap for follow-up work — either by The Hunters Ledger in future investigations or by readers with access to paid threat-intelligence services.

### 12.1 Named-actor attribution

Named-actor attribution for the operator behind UTA-2026-009 remains **INSUFFICIENT (30%)**. Zero Tier-1, Tier-2, or Tier-3 reporting names "Inkognito" or any of its sub-brands (INK VPN, INK Lens, CryptOne, Bikaf VPN, unloki). The operator has maintained 2 years 11 months of public stealth despite running commercial-grade infrastructure. Resolution paths:
- Russian underground forum cross-reference (Flashpoint, Intel 471, KELA monitoring of Russian-language fraud forums)
- Russian payment-processor merchant ID lookup (SBP, T-Pay, Russian card networks) — would identify the legal entity registered to receive INK VPN subscription revenue
- Identification of principals behind the `@inkconnectvpn` Telegram channel
- Victim-side data correlation (subscriber lists, customer complaints to Russian consumer-protection regulators)

### 12.2 Origin of `cryptone.bot` fake exchange

`cryptone.bot` is Cloudflare-fronted with origin hidden. The Cloudflare Turnstile bot challenge prevented passive enumeration. Resolution:
- Active de-fronting via DNS history correlation, SSL certificate transparency log mining, or paid passive-DNS services that may have captured the origin IP before Cloudflare interception
- Submission to operator as a fake user to capture wallet addresses or other origin-side artifacts (out of scope for passive analysis)

### 12.3 Full inklens.ru subdomain inventory

DomainTools reverse-IP enumeration recovered 468 unique `*.inklens.ru` rrnames on the previous U1host endpoint and 165 + 95 new on the current Timeweb host (post-migration). The full operator-controlled inventory exceeds 467 subdomains; the IOC feed and Sigma rules document 25 representative high-value brand-impersonation subdomains. Resolution:
- Full subdomain enumeration export from DomainTools or an internet-wide host/service search engine with passive-DNS coverage
- Wildcard DNS Sigma rule on the parent zone (see detection file Coverage Gap §3.2 for the supplemental snippet)

### 12.4 Live JARM hashes for operator TLS stack

JARM fingerprinting of the live operator endpoints was not completed. JARM provides a passive TLS-layer pivot for surfacing additional operator-controlled servers. Resolution:
- Active JARM probe of operator IPs — note that `inklens.ru` deliberately rejects non-browser TLS clients with `tlsv1 alert internal error`, so JARM probes of that host may return a rejection fingerprint rather than the full stack JARM
- VirusTotal MCP JARM lookup on Cloudflare-fronted domains would return Cloudflare JARM, not operator backend JARM

### 12.5 Operator-controlled accounts beyond search-console verifications

The investigation recovered two Google Search Console verifications and one Yandex Webmaster ID. Additional operator-controlled accounts almost certainly exist (Telegram bot owners, payment-processor merchant accounts, hosting-provider customer accounts at Aeza / Timeweb / Stark Industries). Resolution paths require non-public access to provider customer records or paid TI services with underground forum coverage.

### 12.6 Stark Industries operator-vs-tenant clarification

The 2-year-11-month stability of the operator's Stark TR / Worktitans NL BEC infrastructure is unusual for rented bulletproof hosting. Whether this IP is operator-owned (dedicated lease, multi-year contract) or operator-rented (continuously renewed) would refine the operational sophistication assessment. Resolution would require hosting-provider customer-record disclosure (unlikely without law enforcement engagement).

### 12.7 Iranian-targeted `divar-irantop.shop` validation

The Iranian-targeted `divar-irantop.shop` phishing domain briefly resolved to Aeza International Ltd in January 2024. Linkage to UTA-2026-009 is rated MODERATE in this report — confirmed Aeza co-residency in the operator's primary hosting tier, but no direct operator-side artifact links it specifically to the Inkognito brand portfolio. Resolution would require live operator artifact capture from the domain (no longer active post-2024-12).

### 12.8 Underground forum identity

The operator's underground forum identity (if any) — alias on XSS, Exploit.in, BHF, RAMP, or Russian-language Telegram crime channels — has not been identified. Paid TI services with underground forum coverage (Flashpoint, Intel 471, KELA) would be the primary resolution path.

---

## 13. References and Cross-References

### 13.1 Parent Investigation and Cross-References

- **2026-05-15 Multi-Cluster OpenDirectory 79.137.192.3 Report** ([`/reports/opendirectory-79-137-192-3-20260515/`](/reports/opendirectory-79-137-192-3-20260515/)) — originating publication; covers all three clusters (BellaMain, Inkognito, Rhadamanthys MaaS customer); Cluster B (Inkognito) covered at one-paragraph summary depth across §4.5, §5.7, §6.6, §8.3, §9.2. This standalone report deepens Cluster B only.
- **UTA-2026-008 — BellaMain Turkish PhaaS operator** (`threat-intel-vault/threat-actors/UTA-2026-008.md`) — Cluster A actor, operationally separate.
- **UTA-2026-009 — Inkognito Russian VPN/phishing operator** (`threat-intel-vault/threat-actors/UTA-2026-009.md`) — the subject of this report; canonical UTA file extended by this publication.
- **UTA-2026-010 — Rhadamanthys MaaS customer** (`threat-intel-vault/threat-actors/UTA-2026-010.md`) — Cluster C actor, operationally separate.

### 13.2 Tier-1 Authoritative Sources

- **OFAC SDN List — Aeza Group LLC** (2025-07-01) — US Treasury Office of Foreign Assets Control sanctions designation covering Aeza Group LLC, Aeza International Ltd, Aeza-USA Inc, Aeza Logistic LLC. Designation applies to all Aeza ASNs including AS210644 and AS216246.
- **EU Council Decision (CFSP) 2025/972 — Stark Industries Solutions Ltd** (2025-05-20) — European Union Council sanctions designation covering Stark Industries Solutions Ltd and its subsidiaries. Designation applies to ASNs including AS44477; the Worktitans B.V. rebrand on AS209847 is documented as a sanctions-evasion vehicle per Tier-2 reporting.

### 13.3 Tier-2 Vendor Reports

- **TRM Labs (2025)** — "Aeza Group: OFAC Designation Analysis" — coverage of the July 1, 2025 Aeza OFAC sanctions.
- **Recorded Future Insikt Group (2025)** — Stark Industries sanctions report covering the 12-day pre-announcement lead time and Worktitans rebrand mechanics.
- **Silent Push (2024)** — FIN7 domain-aging analysis (~4,000 aged domains documented).
- **SentinelOne / Validin (May 2025)** — FreeDrain report (~38,048 subdomains documented).
- **Microsoft Security Blog (March 2026)** — Storm-2561 reporting documenting fake VPN installer abuse.
- **Hunt.io** — Russian malicious infrastructure mapping (Timeweb AS9123 ranks highest by C2/phishing density per 90-day analysis with ~311 C2 servers).
- **Cisco Talos** — Gamaredon network footprints (referenced for cross-comparison; not Inkognito-specific).
- **GreyNoise (2025)** — Stark Industries "Shell Game" reporting on sanctions evasion via Worktitans rebrand.
- **Proofpoint** — GitHub phishing abuse reporting (referenced for the GitHub Pages apex chameleon-decoy comparison).

### 13.4 Tier-3 Sources

- **KrebsOnSecurity (May 2024)** — "Stark Industries Iron Hammer" reporting on the original Stark Industries infrastructure.
- **KrebsOnSecurity (September 2025)** — "Stark Industries Evades EU Sanctions" reporting on the Worktitans rebrand.
- **BleepingComputer (January 2024)** — AnyDesk breach reporting (relevant context for `anydesk.inklens.ru` brand-impersonation targeting post-2024-breach).
- **BleepingComputer (May 2025)** — EU sanctions Stark Industries reporting.

### 13.5 Open-Source Tooling Context

- **EspoCRM** (https://github.com/espocrm/espocrm) — legitimate open-source CRM; no prior abuse pattern documented in any reviewed Tier-1/2/3 source. Inkognito's single-tenant criminal back-office deployment is a gap in the public record.
- **Marzban** (https://github.com/Gozargah/Marzban) — legitimate open-source Xray/V2Ray panel; no prior abuse pattern documented in criminal proxy networks in any reviewed source. Inkognito's centralized VPN/proxy fleet-management deployment is a gap in the public record.
- **Outline VPN** (https://getoutline.org / Jigsaw/Alphabet) — legitimate censorship-circumvention tool. Inkognito's deployment at `users.outline.unloki.ru` targets users in Iran, Russia, and China.
- **Caddy** (https://caddyserver.com) — legitimate reverse-proxy web server.
- **nginx** (https://nginx.org) — legitimate web server / reverse proxy.

### 13.6 Detection and IOC Deliverables

- **IOC Feed (machine-readable JSON):** [`/ioc-feeds/inkognito-russian-vpn-phishing-185-221-196-118-20260516-iocs.json`](/ioc-feeds/inkognito-russian-vpn-phishing-185-221-196-118-20260516-iocs.json) — full validated IOC inventory with context fields, unfanged for SIEM/EDR ingestion.
- **Detection File (YARA + Sigma + Suricata):** [`/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/`](/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/) — 16 rules across three detection layers, CC BY-NC 4.0 licensed.

---

© 2026 Joseph. All rights reserved. See LICENSE for terms.
