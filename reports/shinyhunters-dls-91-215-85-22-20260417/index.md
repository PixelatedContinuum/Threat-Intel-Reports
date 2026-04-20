---
title: "ShinyHunters Data Leak Site at 91.215.85.22 — Infrastructure, Victims, and Attribution"
date: '2026-04-17'
last_updated: '2026-04-20'
detection_page: /hunting-detections/shinyhunters-dls-91-215-85-22-20260417-detections/
ioc_feed: /ioc-feeds/shinyhunters-dls-91-215-85-22-20260417-iocs.json
ioc_highlights:
  - value: "91[.]215[.]85[.]22"
    note: "ShinyHunters DLS clearnet host (nginx, AS200593 PROSPERO)"
  - value: "91[.]215[.]43[.]200"
    note: "shinyhunte.rs identity page origin (AS57724 DDoS-Guard)"
  - value: "shinyhunte[.]rs"
    note: "Actor clearnet identity and PGP-key rotation domain"
  - value: "shnyhntww34phqoa6dcgnvps2yu7dlwzmy5lkvejwjdo6z7bmgshzayd[.]onion"
    note: "Active main Tor mirror (added April 2026)"
detection_sections:
  - label: "YARA Rules"
    anchor: "#yara-rules"
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "Suricata Signatures"
    anchor: "#suricata-signatures"
layout: post
permalink: /reports/shinyhunters-dls-91-215-85-22-20260417/
category: "Data Leak Site"
hide: true
description: "The clearnet host 91.215.85.22 is an active ShinyHunters Data Leak Site publishing approximately 1.1 TB of stolen data from 29 named victim organizations, hosted on PROSPERO bulletproof infrastructure (AS200593) with the actor identity domain segmented onto DDoS-Guard (AS57724). Attribution is DEFINITE (96%) to ShinyHunters / Scattered LAPSUS$ Hunters, corroborated by IC3 and CERT-EU advisories and by 28-of-29 victim matches in mainstream security press."
---

**Campaign Identifier:** ShinyHunters-DLS-DataLeak-91.215.85.22<br>
**Last Updated:** April 20, 2026<br>
**Threat Level:** HIGH

---

## 1. Executive Summary

### BLUF

The clearnet host `91.215.85.22` is an **active ShinyHunters Data Leak Site** publishing approximately 1.1 TB of stolen data from **29 named victim organizations**, operated by **ShinyHunters** under the **Scattered LAPSUS$ Hunters** collective banner at **DEFINITE (96%)** attribution confidence. At the time of analysis (2026-04-16), twenty-eight of the twenty-nine victims were independently corroborated in mainstream security press; the twenty-ninth — **Alert360**, a US home and small-business alarm-monitoring provider — was documented here for the first time, drove a four-channel responsible-disclosure outreach prior to this report's release, and was subsequently listed on the independent extortion-tracker **ransomware.live on 2026-04-19** — corroborating the finding and closing the disclosure window. The site is hosted on PROSPERO (AS200593, Russian bulletproof) with the actor identity page deliberately segmented onto DDoS-Guard (AS57724), which makes single-provider takedown ineffective. This DLS is the publication endpoint of a wider 2026 vishing-to-Salesforce/Okta extortion campaign tracked at government level (IC3 2025-09-12, CERT-EU 2026-04-03) — the upstream attack chain, not the DLS itself, is where defenders have detection leverage.

### What Was Found

The clearnet host `91.215.85.22` is an **active ShinyHunters Data Leak Site (DLS)** holding approximately **1.1 TB of stolen data** drawn from **29 named victim organizations** plus two unlabelled archives (a 94 GB European Commission dump and a BreachForums v5 user database). It is operated by **ShinyHunters** under the self-chosen **Scattered LAPSUS$ Hunters** collective banner — attribution **DEFINITE (96%)** based on a Tier-1 IC3 advisory and a Tier-1 CERT-EU attribution naming the underlying TTP cluster, 28 of 29 victims independently corroborated as ShinyHunters targets in mainstream security press, actor self-attribution in an on-server ransom note, six years of unbroken PGP-key cryptographic continuity, and seven attacker-controlled infrastructure elements split across two deliberately segmented Russian bulletproof providers. The site is live; four fresh archives were uploaded **2026-04-15**, one day before discovery.

This report is the first public documentation tying the entire 91.215.85.22 victim set to the named PROSPERO (AS200593) and DDoS-Guard (AS57724) hosting footprint, and is the first public identification of **Alert360** — a US home/SMB alarm-monitoring firm — as an unacknowledged ShinyHunters victim. Twenty-eight of the twenty-nine named victims have been disclosed somewhere in mainstream security press or breach trackers; Alert360 is the sole victim with no prior public reporting. The gap this analysis fills is the consolidated 29-victim inventory tied to a specific bulletproof-hosting cluster, plus that single net-new victim identification.

A static nginx server at 91.215.85.22 publishes victim archives at the path `/pay_or_leak/`, fronted by an actor-authored ransom note that explicitly self-identifies the operator as ShinyHunters and references three Tor `.onion` mirrors plus a clearnet identity domain (`shinyhunte.rs`). The site is not a binary-malware artifact; it is the **back-end publication endpoint of an active extortion operation** that begins with help-desk vishing, pivots through Salesforce / Okta SSO, exfiltrates CRM and document-store data, and ends with public leakage when victims refuse to pay.

### Why This Threat Is Significant

- **Scale.** ~1.1 TB across 29 named victims spanning fintech/wealth management, insurance, retail, dating, transport, education, telecom, and EU government — all uploaded over a six-week operational window with active maintenance through April 2026.
- **Attribution clarity.** Government Tier-1 sources (IC3, CERT-EU) and at least two Tier-2 vendor groups (Google GTIG, Resecurity) name ShinyHunters and the TTP cluster directly. There is no plausible alternative attribution.
- **Net-new victim identification.** Alert360, a home and small-business alarm-monitoring provider, has no prior public coverage in any breach press, government advisory, or crowdsourced tracker. Its presence on this DLS — even pre-archive (subdirectory only) — is high-value notification intelligence.
- **Cross-actor signal.** A single archive (`europa.zip`, 94 GB) maps to the European Commission breach for which CERT-EU has independently attributed initial access to **TeamPCP** via a Trivy supply-chain compromise, with ShinyHunters publishing the data. This evidences a multi-vector campaign that defenders cannot detect by watching help-desk vishing alone.
- **Bulletproof segmentation.** The DLS is on PROSPERO (AS200593, a confirmed Russian bulletproof host) while the actor identity page is on DDoS-Guard (AS57724). Single-provider takedown defeats neither node.

### Key Risk Factors

| Risk Dimension | Score (/10) | Notes |
|---|---:|---|
| Data-disclosure scale | 10 | ~1.1 TB across 29 named victims; 821 GB ZenBusiness dump alone is the largest single archive |
| Downstream victim harm | 9 | HNW/UHNW PII (Beacon Pointe, Pathstone, Ameriprise, Mercer); national-scale telecom (Odido 6.2M Dutch subscribers); kinetic harm via Alert360 alarm data |
| Operational tempo | 8 | Fresh uploads within 24 h of discovery; weekly-to-biweekly cadence sustained for 6+ weeks |
| Takedown resistance | 8 | Russian bulletproof + DDoS-Guard fronting + 3-mirror Tor architecture; abuse contacts historically unresponsive |
| Attribution defensibility | 10 | DEFINITE (96%) with two Tier-1 government advisories + cryptographic 6-year key lineage |
| Operational disruption to victims | 4 | DLS does not encrypt or take systems offline; harm vector is data disclosure, not RCE |
| **Overall** | **8.2 / 10 — HIGH** | Mass data-disclosure infrastructure with strong attribution; the absence of an operational-disruption vector is the only reason this is not CRITICAL |

### Threat Actor

**ShinyHunters** (Scattered LAPSUS$ Hunters / Trinity of Chaos). DEFINITE attribution at 96% confidence. Active under this branding since the August 2025 three-group merger of ShinyHunters, Scattered Spider (UNC3944), and LAPSUS$-aligned operators. Operating since at least May 2020 under the ShinyHunters name across Empire Market, RaidForums, and BreachForums ecosystems. Six-year cryptographic key continuity confirmed via dual-signed PGP key rotation (March 2026) retiring both 2020 keys.

### For Technical Teams

- **Block at perimeter:** `91.215.85.22`, `91.215.43.200`, `shinyhunte.rs`, the three `.onion` mirrors. Full IOC list — see Section 9 and the linked IOC feed.
- **Hunt for the taunt-filename pattern** `(?i)should(ve|a).*paid.*ransom.*shinyhunters` across enterprise file shares, cloud-sync staging directories, and proxy logs (Section 3.2; full detection rules linked in Section 9).
- **Detect the upstream chain.** This is not a malware infection — DLS appearance is the *terminal* event. The detectable upstream is help-desk vishing → MFA reset → anomalous Okta/Salesforce OAuth Connected App → bulk Data Loader export. See Section 5 (TTP Chain) and the linked detection file.
- **Alert360 notification priority.** If you are an Alert360 partner or customer, treat this as priority-one outreach — the company has not (as of report cutoff) acknowledged a breach.
- **Do not over-attribute OTX co-tenant correlations.** PLAY, Qilin, RansomHub, and various RATs that AlienVault OTX associates with this IP are shared-bulletproof-hosting artifacts, not ShinyHunters capabilities.

### Key Takeaways

- **The site is live and actively maintained.** Four fresh victim archives were uploaded on 2026-04-15, one day before the investigation cutoff. This is not an abandoned dump server — it is a working part of an ongoing extortion operation.
- **Attribution is as strong as open-source intelligence allows.** Two Tier-1 government sources (IC3, CERT-EU) name the actor and TTP cluster, two Tier-2 vendors (Google GTIG, Resecurity) corroborate, six years of unbroken cryptographic continuity is documented through PGP key cross-signing, and 28 of 29 victims map to independently-reported ShinyHunters operations. The 4% confidence gap to 100% reflects only the absence of a law-enforcement advisory naming the specific IP.
- **One victim — Alert360 — is publicly identified here for the first time.** A US home and small-business alarm-monitoring provider has no prior coverage in any breach press, government bulletin, or crowdsourced tracker. Customers and partners of Alert360 should treat this as priority-one notification intelligence; the data class implied by the business model (home addresses, alarm configurations, disarm PINs) carries kinetic-harm risk that other victim sets on this DLS do not.
- **Takedown is unusually difficult.** The operator deliberately splits the leak site across two Russian providers (PROSPERO for data, DDoS-Guard for identity) and maintains three Tor mirrors. No single takedown action — civil, criminal, or technical — collapses the operation; all five publication paths must be addressed.
- **The leak site is the wrong place to look for detection leverage.** By the time an organization appears on the DLS, the breach is months old. The detectable upstream is help-desk vishing followed by MFA reset, anomalous Okta or Salesforce OAuth Connected App authorization, and bulk Salesforce Data Loader exports. Defenders with SaaS log access should focus there.
- **The campaign is expanding, not contracting.** Since the August 2025 merger of ShinyHunters with Scattered Spider and LAPSUS$-aligned operators, new sub-clusters have been observed (UNC6671 Okta-direct vishing, Salesforce Aura misconfiguration exploitation, female vishing-caller recruitment at $1,000/call). Defenders should plan for continued TTP variation through 2026.
- **Co-tenant correlations are not collaboration.** PLAY, Qilin, RansomHub, and various RATs that AlienVault OTX associates with `91.215.85.22` reflect the heterogeneous tenant base of a Russian bulletproof host, not ShinyHunters operational capability. Do not propagate these correlations as ShinyHunters attribution.
- **Regulatory exposure for victims is broad.** GLBA / SEC Reg S-P, HIPAA, FERPA / COPPA, GDPR, NYDFS Reg 500, SOX 8-K disclosure, and effectively all 50 US-state breach-notification statutes apply across the victim set. Partially-disclosed victims will be forced to acknowledge breaches in coming filings cycles regardless of negotiation outcomes.

---

## 2. Infrastructure Overview

> **Analyst note:** This section describes the publication-side infrastructure — the servers and domains the operator uses to host stolen data and publish ransom communications. It does not describe how the operator initially compromised victims; that chain is covered in Section 5. The key takeaway is that ShinyHunters segments their leak site (data) from their identity page (PGP keys, communications) across two distinct Russian providers, which makes single-provider takedown ineffective.

### 2.1 The DLS host: 91.215.85.22

| Field | Value |
|---|---|
| IPv4 | `91.215.85.22` |
| Port / protocol | 80/tcp HTTP |
| Server banner | `nginx/1.22.1` |
| Prefix | `91.215.85.0/24` (announced 2022-12-16) |
| ASN | `AS200593` PROSPERO OOO |
| Geography | Russia |
| Operator domain | `pro-spero.ru` |
| Abuse contact | `abuse@pro-spero.ru` (community reports describe limited responsiveness) |
| AbuseIPDB score (at investigation) | 0% (reputation signal suppressed — defender visibility gap) |

The canonical content path is `GET /pay_or_leak/`, which returns an nginx autoindex listing approximately 30 archives. **Critical server quirk:** nginx at this host returns the same listing at virtually any URL path (`/assets/`, `/backup/`, `/files/`, `/uploads/`, etc.), which is a misconfiguration of `try_files`/`rewrite` fallthrough rather than a deliberate tarpit. This caused an initial crawler out-of-memory failure during open-directory enumeration (the trigger for this re-investigation at depth=2).

Real subdirectories under `/pay_or_leak/`:

- `/pay_or_leak/alert360/` — contains only `INFORMATION.txt`; **no archive present** (extortion-negotiation stage)
- `/pay_or_leak/ameriprise/` — `INFORMATION.txt` only (extortion-negotiation stage)
- `/pay_or_leak/odido/` — empty (archive withdrawn after victim refused ransom per public statement)
- `/pay_or_leak/woflow/` — empty

### 2.2 The actor identity page: shinyhunte.rs (91.215.43.200)

| Field | Value |
|---|---|
| Domain | `shinyhunte.rs` (`.rs` Serbia ccTLD; chosen for phonetic branding) |
| Origin IPv4 | `91.215.43.200` |
| ASN | `AS57724` DDoS-Guard |
| Server banner | `nginx/1.22.1` (matches DLS — likely shared operator image) |
| Active since | At least 2025-10-12 (archive.org) |

The identity page is **deliberately on a different provider** from the DLS. shinyhunte.rs does not host stolen data; it hosts the PGP-key rotation announcement, Tor mirror status table, and signed actor communications. This split is the single most distinctive OPSEC choice in the operation.

### 2.3 Tor mirror architecture

| Mirror | Operator-reported status | Notes |
|---|---|---|
| `shnyhntww34phqoa6dcgnvps2yu7dlwzmy5lkvejwjdo6z7bmgshzayd.onion` | UP — main website | Newest mirror; not in the on-DLS ransom note (operator did not synchronize) |
| `shinypogk4jjniry5qi7247tznop6mxdrdte2k6pdu5cyo43vdzmrwid.onion` | UP — redirector | Listed in ransom note |
| `toolatedhs5dtr2pv6h5kdraneak5gs3sxrecqhoufc5e45edior7mqd.onion` | DOWN — inactive | Listed in (stale) ransom note |

The main `.onion` serves a queue-gate landing page (title: `[sh] access queue`) holding visitors approximately three minutes before forwarding — a traffic-smoothing / DDoS-absorption pattern common to busy criminal services. The three-mirror architecture (active main + active redirector + retired) is a deliberate takedown-resilience posture.

### 2.4 Architectural significance

> **Analyst note:** A single Russian bulletproof host plus DDoS-Guard fronting plus three Tor mirrors gives this operation five independent publication paths. No single takedown — civil, criminal, or technical — collapses the entire site. This is investment-grade infrastructure, not a disposable drop site.

The infrastructure constitutes a five-node resilience architecture: DLS clearnet (PROSPERO) + two active Tor mirrors + identity page clearnet (DDoS-Guard) + identity page Tor reachability. Defeating this operation requires upstream-carrier pressure, multi-jurisdictional coordination, or operator-side compromise — none of which are achievable through routine abuse-reporting channels.

---

## 3. Actor Operations

> **Analyst note:** This section documents how the operator brands and structures the leak site itself — the ransom note, the filename convention, the upload cadence, and the directory layout. These are the artifacts a defender will encounter when an organization discovers itself listed on the DLS, and they are the basis for the YARA filename rules in the linked detection file.

### 3.1 The ransom note (`INFORMATION.txt`)

The same actor-authored note is served from every directory on the DLS:

```
This file has been downloaded from the ShinyHunters Data Leak Site (DLS).
Our DLS is accessible at these locations:
    - http://toolatedhs5dtr2pv6h5kdraneak5gs3sxrecqhoufc5e45edior7mqd.onion/
    - http://shinypogk4jjniry5qi7247tznop6mxdrdte2k6pdu5cyo43vdzmrwid.onion/

> These files were leaked on the ShinyHunters DLS because the victim did not pay a ransom or cooperate and comply with the ShinyHunters group.

src;refs;lnks;
http://web.archive.org/web/20260322033123/https://shinyhunte.rs/
http://web.archive.org/web/20260322033217/https://shinyhunte.rs/newpgp
```

This single artifact is the strongest single attribution element on the host: explicit actor self-attribution by name, the victim-pressure model ("did not pay a ransom"), two of the three `.onion` mirrors, and a clearnet identity-page reference. The note is **stale** — the `toolated...onion` mirror has been retired and the new main mirror has been published on `shinyhunte.rs` but not added to the on-DLS note. This divergence indicates the DLS and the identity page are maintained independently.

### 3.2 Filename branding convention

26 of 30 archives carry the `shinyhunters` token in a "taunt" naming pattern:

| Pattern | Example | Count |
|---|---|---:|
| `SHOULDVE_PAID_THE_FUCKING_RANSOM_*` | `SHOULDVE_PAID_THE_FUCKING_RANSOM_Kemper-SHINYHUNTERS.7z` | 2 |
| `shouldve_paid_the_ransom_*_shinyhunters*` | `shouldve_paid_the_ransom_amtrak-SHINYHUNTERS.7z` | 13 |
| `shouldve-paid-the-*-ransom-*-shinyhunters*` | `shouldve-paid-the-fucking-ransom-edmunds-shinyhunters.7z` | 7 |
| `pay-the-ransom-next-time-*-shinyhunters-*` | `pay-the-ransom-next-time-panera-bread-shinyhunters-dont-be-the-next-headline.7z` | 1 |
| `you_shouldve_paid_the_ransom_why_didnt_you_*_shinyhunters*` | `you_shouldve_paid_the_ransom_why_didnt_you_CFGI_shinyhunters.7z` | 1 |
| **Canonical regex** | `(?i)should(ve\|a).*paid.*ransom.*shinyhunters` | matches 25/30 |

Non-conformant filenames: `mercer_didnt_pay_the_ransom_shinyhunters.7z`, `canadagoose_shouldve_paid_the_ransom_SHINYHUNTERS.7z`, `europa.zip` (no actor branding — a notable anomaly discussed in Section 4.4), `bf_03_2026.sql.7z` (BreachForums v5 dump — no branding).

**Hunting value:** the convention is operationally unique. A file matching this regex appearing in an enterprise file share, cloud-sync staging path, or web-proxy log is a near-certain DLS-download or DLS-staging event. Detection rules built on this pattern are in the linked detection file.

### 3.3 Upload temporal pattern

Upload dates are derived from HTTP `Last-Modified` headers observed 2026-04-16 (UTC):

| Date | Files | Notes |
|---|---:|---|
| 2026-03-04 21:31–21:54 | **18** | Bulk-upload window — 18 archives in 23 minutes (single session) |
| 2026-03-06 | 1 | Pathstone (15 GB) |
| 2026-03-09 | 1 | CFGI (475 MB) |
| 2026-03-15 | 1 | Aura (11.8 GB) |
| 2026-03-24 | 1 | Berkadia (27.6 GB) |
| 2026-03-25 | 1 | Infinite Campus (1.1 GB) |
| 2026-03-27 | 1 | `bf_03_2026.sql.7z` (43 MB — BreachForums v5) |
| 2026-03-28 | 1 | `europa.zip` (94 GB — European Commission) |
| 2026-04-05 | 1 | **ZenBusiness (821 GB)** — single largest archive |
| 2026-04-11 | 1 | Hallmark (568 MB) |
| 2026-04-13 | 1 | Rockstar Games (419 MB) |
| 2026-04-15 15:55–17:31 | **4** | Fresh tranche (Abrigo, McGraw-Hill, Amtrak, Kemper) — 24 h before discovery |

The March 4 bulk window is consistent with either initial DLS stand-up from a pre-staged backlog or migration from a prior host. The post-bulk cadence (every 3–7 days, sustained for 6+ weeks, with a fresh tranche the day before discovery) confirms this is a **live, actively-maintained operation** rather than an orphan dump server. Timestamp clustering at 15:00–22:00 UTC is directionally consistent with Russia-aligned operator hours but does not establish operator time zone on its own (uploads can be scripted).

### 3.4 PGP-key identity infrastructure

Four PGP keys define the actor's cryptographic identity history:

| Role | Fingerprint | Created | Status |
|---|---|---|---|
| Old "Raidforums" key | `1FC4 D0B1 DEE9 14BB 05B5 7FAB F1F1 B98A 51C9 89B3` | 2020-08-25 | Revoked 2026-03-17 |
| Old "Empire Market" key | `8285 37C1 5F43 F135 A831 7153 CD16 A166 0CC7 CE51` | 2020-01-28 | Revoked 2026-03-17 |
| December 2025 statement signer | `E80C 1308 A09E C1AD C418 C3F0 2578 988F 69BC A3FC` | ~2025-12 | Active (third internal key) |
| Current (April 2026) | `F495 3411 767D E71B EDCD ABCB 76F4 E26F 7A20 978A` | ~2026-03 | Active; key body not independently recovered (`/newpgp` returned HTTP 404) |

The two 2020 keys cross-signed the rotation handoff to the current key on 2026-03-17, then both self-revoked. Empire Market exit-scammed in August 2020; RaidForums was seized by the FBI in April 2022. Continuous PGP custody across both platforms since 2020 establishes **operator continuity spanning approximately six years** through the current 2026 campaign — see Section 7 for the full attribution implication.

---

## 4. Victim Inventory and Disclosure Status

> **Analyst note:** This section is the consolidated 29-victim roster derived from the DLS file inventory and subdirectory structure, cross-checked against public press, breach trackers (HIBP, ransomware.live), and class-action court filings. The single-most-important finding here is that twenty-eight of twenty-nine named victims have prior public reporting; one — Alert360 — does not.

### 4.1 Full roster

| # | Victim | Sector | Size | Upload | Disclosure |
|---|---|---|---:|---|---|
| 1 | ZenBusiness | Business-formation SaaS | 821 GB | 2026-04-05 | PARTIAL |
| 2 | Beacon Pointe | RIA wealth management | 43.3 GB | 2026-03-04 | YES |
| 3 | Bumble | Dating app | 29.5 GB | 2026-03-04 | YES |
| 4 | Berkadia | Commercial mortgage banking | 27.6 GB | 2026-03-24 | PARTIAL |
| 5 | Kemper Corporation (KMPR) | Insurance holding | 26.8 GB | 2026-04-15 | PARTIAL |
| 6 | Amtrak | Passenger rail | 17.5 GB | 2026-04-15 | PARTIAL |
| 7 | Pathstone | Multi-family office | 15.2 GB | 2026-03-06 | YES |
| 8 | Aura | Consumer ID protection | 11.5 GB | 2026-03-15 | YES |
| 9 | Edmunds | Auto research | 11.4 GB | 2026-03-04 | PARTIAL |
| 10 | CarGurus | Auto marketplace | 7.2 GB | 2026-03-04 | YES |
| 11 | McGraw-Hill | K-12 / academic publisher | 5.2 GB | 2026-04-15 | YES |
| 12 | SoundCloud | Audio streaming | 2.8 GB | 2026-03-04 | YES |
| 13 | Mercer Advisors | RIA wealth management | 2.5 GB | 2026-03-04 | YES |
| 14 | Figure.com | Fintech HELOC | 2.5 GB | 2026-03-04 | YES |
| 15 | Match Group | Tinder / Hinge / OkCupid | 1.7 GB | 2026-03-04 | YES |
| 16 | Betterment | Robo-advisor | 1.6 GB | 2026-03-04 | YES |
| 17 | Infinite Campus | K-12 SIS vendor | 1.1 GB | 2026-03-25 | YES |
| 18 | Harvard University | Higher education | 1.0 GB | 2026-03-04 | YES |
| 19 | Panera Bread | QSR loyalty | 759 MB | 2026-03-04 | YES |
| 20 | Hallmark | Greeting cards / e-commerce | 568 MB | 2026-04-11 | YES |
| 21 | CFGI Management | Corporate-finance consulting | 475 MB | 2026-03-09 | PARTIAL |
| 22 | UPenn | Higher education | 461 MB | 2026-03-04 | YES |
| 23 | Rockstar Games (TTWO) | Game studio | 419 MB | 2026-04-13 | YES |
| 24 | Crunchbase | B2B data platform | 402 MB | 2026-03-04 | YES |
| 25 | Canada Goose | Luxury outerwear | 157 MB | 2026-03-04 | YES |
| 26 | Abrigo | AML / BSA fintech | 61 MB | 2026-04-15 | PARTIAL |
| 27 | CarMax (KMX) | Used-car retail | 61 MB | 2026-03-04 | PARTIAL |
| 28 | Ameriprise Financial (AMP) | Wealth / insurance | (subfolder only) | 2026-03-22 (claim) | PARTIAL |
| 29 | **Alert360** | Home / SMB alarm monitoring | (subfolder only) | — | **UNKNOWN — no public reporting** |
| — | Odido | Dutch telecom | (subfolder empty) | — | YES (ransom refused; archive withdrawn) |
| — | Woflow | Merchant-data B2B | (subfolder empty) | — | PARTIAL |
| — | `europa.zip` | European Commission (HIGH confidence) | 94 GB | 2026-03-28 | YES |
| — | `bf_03_2026.sql.7z` | BreachForums v5 user DB (HIGH confidence) | 43 MB | 2026-03-27 | YES |

### 4.2 Disclosure-status summary

As of **2026-04-20** (post-outreach window close):

- **22 victims fully publicly reported** (named in mainstream security press with company acknowledgment)
- **9 victims partially disclosed** (actor-claimed without formal company acknowledgment): Berkadia, Ameriprise, Woflow, Abrigo, CFGI, Kemper, Amtrak, ZenBusiness, CarMax, Edmunds
- **Alert360** — added to ransomware.live on **2026-04-19** (three days after The Hunters Ledger's pre-publication disclosure outreach). No mainstream security-press coverage as of this report's release, and no statement from Alert360 itself.

At the time of analysis (2026-04-16), ransomware.live tracked 28 of 29 victims on this DLS, leaving Alert360 as the sole novel entry. ransomware.live's subsequent 2026-04-19 listing of Alert360 closes that gap while preserving the finding that this report is the first substantive public documentation of Alert360's presence on the DLS.

### 4.3 Alert360 — the previously-unacknowledged victim (key finding)

**What is Alert360?** A US home and small-business alarm-monitoring provider. The data class implied by its business model — home addresses, alarm-system configurations, disarm PINs, account-holder identity, and (potentially) absence patterns inferable from arming history — is among the most operationally dangerous on the DLS. Unlike the financial-services victims, the harm vector here is not identity theft or wire fraud; it is **direct kinetic enablement** (burglary, stalking, targeted physical entry). When overlaid with travel-window data inferable from the Amtrak archive (also on this DLS), the cross-victim aggregation risk is unusually high.

**Why this matters for intelligence consumers.** At the time of analysis (2026-04-16), Alert360 was in the extortion-negotiation stage on this DLS — its subdirectory held only the `INFORMATION.txt` ransom note, no archive — and no breach press, vendor advisory, government bulletin, or breach tracker had covered Alert360 as a ShinyHunters victim. This report is the first substantive public documentation of Alert360's presence on the DLS.

**Subsequent public corroboration (ransomware.live, 2026-04-19).** Three days after The Hunters Ledger's responsible-disclosure outreach, the independent extortion-operations tracker ransomware.live listed Alert360 as a ShinyHunters victim. This closes the public-reporting gap and independently corroborates the finding.

One factual correction worth noting: ransomware.live's Alert360 entry assigns an **estimated attack date of 2026-04-18**. That date is not consistent with the DLS evidence — the Alert360 subdirectory (and the `INFORMATION.txt` ransom note served from it) was directly observed during this investigation's crawl on **2026-04-16**. The actor-side listing therefore pre-dates the ransomware.live estimate by at least two days. Defenders and investigators using ransomware.live data for scope-of-impact or breach-timeline decisions should treat the 2026-04-18 estimate as a lower bound only — the actual compromise timeline is almost certainly earlier, and the DLS listing was active by 2026-04-16 at the latest.

**Caveats.** Presence on the DLS does not by itself prove the breach is real — the actor could have published a subdirectory speculatively, as a negotiation tactic, or against a related third party. However: every other empty / pre-archive subdirectory on this DLS (Ameriprise, Odido, Woflow) has subsequently been corroborated as a real victim. With ransomware.live now also listing Alert360, the base rate plus the second-source corroboration make a real Alert360 compromise highly probable. Alert360 itself has not issued a public statement as of this report's publication.

**Responsible-disclosure timeline (prior to publication).** Because no public reporting existed naming Alert360 as a ShinyHunters victim at the time of analysis, The Hunters Ledger performed pre-publication responsible disclosure across four independent channels before including Alert360 in this report. None of the four channels produced an acknowledgment during the outreach window; a fifth-row entry records the subsequent third-party public disclosure.

| # | Channel | Recipient / route | Date | Outcome |
|---|---|---|---|---|
| 1 | FBI IC3 filing | https://www.ic3.gov/ — cyber-incident complaint filed with victim-organization context and DLS artefact references | 2026-04-16 | Filed. Confirmation receipt retained. No acknowledgment or routing confirmation received. |
| 2 | databreaches.net tip | Emailed to Dissent Doe (independent breach-journalism outlet with established track record of contacting under-reported victims) | 2026-04-16 | Delivered. No response or public coverage as of publication. |
| 3 | LinkedIn outreach | Connection requests to Alert360 CEO and General Counsel accompanied by notification message | 2026-04-16 | Requests pending; neither account accepted the connection or replied. |
| 4 | Corporate privacy email | `privacy@alert360.com` | 2026-04-16 | Email was rejected / blocked at the receiving mail gateway; message did not deliver. |
| 5 | ransomware.live (third-party disclosure — not a Hunters Ledger action) | Public listing on https://www.ransomware.live/group/shinyhunters | 2026-04-19 | Alert360 added to tracker with estimated attack date 2026-04-18. Estimate is inconsistent with this report's direct DLS observation on 2026-04-16 (see above). |

No private channel produced a reply, and the corporate privacy address actively rejected mail. The FBI IC3 route remains the authoritative channel of record. With ransomware.live publicly listing Alert360 on 2026-04-19, the disclosure gap that drove the original publication hold is closed; this report is released with the pre-publication outreach record preserved in full for transparency. Any future Alert360 response will be appended to this report as an update.

### 4.4 Special-case archives

**`europa.zip` (94 GB, 2026-03-28).** Attribution to the **European Commission Europa.eu breach** at HIGH confidence based on (a) upload timing — exactly 24 hours after EC's first public disclosure on 2026-03-27, (b) size alignment with the 340 GB uncompressed figure published by CERT-EU (94 GB compressed plausibly represents a substantial subset — a 3.6:1 compression ratio is typical for mixed archive content, making this size consistent with ~340 GB uncompressed), and (c) the absence of actor-branded naming consistent with a different upstream operation. CERT-EU has independently attributed initial access to a Trivy supply-chain compromise carried out by **TeamPCP**, with ShinyHunters performing the AWS pivot via TruffleHog and publishing the resulting data. This archive introduces a **second initial-access TTP into the 2026 ShinyHunters campaign** beyond the dominant vishing chain — see Section 5.3.

**`bf_03_2026.sql.7z` (43 MB, 2026-03-27).** The BreachForums v5 user database. Have I Been Pwned ingested 339,778 unique email addresses, usernames, and Argon2 password hashes from this dump. The file is actor-on-actor content — exposing cybercriminal forum users that may include undercover or research personas — and reflects a faction-internal release rather than a victim-organization compromise.

### 4.5 Highest-risk victims

| Rank | Victim | Primary risk driver |
|---|---|---|
| 1 | **Alert360** | Home addresses + alarm configs + PINs → direct burglary / stalking enablement; unique kinetic-harm profile |
| 2 | **ZenBusiness** | SSN-on-EIN + LLC formation docs at scale → synthetic-identity / shell-company factory fuel |
| 3 | **Ameriprise** | HNW/UHNW CRM + SharePoint (200 GB claimed) → best-in-class spear-phishing base |
| 4 | **Pathstone** | UHNW family-office dossiers — highest per-record value; minor-children estate data |
| 5 | **Odido** | 6.2M Dutch telecom subscribers → SIM-swap campaigns at national scale, banking-MFA bypass |

### 4.6 Regulatory exposure pattern

The aggregate victim set spans GLBA / SEC Reg S-P (all wealth-management victims), HIPAA (Kemper health segment), FERPA / COPPA (McGraw-Hill, Infinite Campus, Rockstar under-13 accounts), GDPR (Odido, EC, Bumble, SoundCloud, Match, Rockstar), NYDFS Reg 500 (NY-registered RIAs), SOX / 8-K disclosure obligations (Kemper KMPR, Ameriprise AMP, Take-Two TTWO, CarMax KMX), and effectively all 50 US-state breach-notification statutes. This regulatory blast radius is the practical reason the partially-disclosed victims will be forced to acknowledge breaches in coming filings cycles regardless of whether they negotiate.

---

## 5. Campaign Context and TTP Chain

> **Analyst note:** This section steps back from the leak-site host itself to describe the campaign that produced its contents — how victims were initially compromised, how data moved from victim CRMs to the DLS, and how this fits into the broader Scattered LAPSUS$ Hunters cluster. This is the *cause* of which the DLS is the *consequence*; defenders looking for upstream detection opportunities should focus here.

### 5.1 The Scattered LAPSUS$ Hunters collective

In **August 2025**, a Telegram-announced merger combined three previously-distinct threat actor groups under a single operational banner:

- **Scattered Spider (UNC3944)** — long-standing English-language vishing / social-engineering specialists
- **LAPSUS$-aligned operators** — surviving members of the 2021–2022 LAPSUS$ extortion campaigns, contributors of the harassment / public-pressure playbook
- **ShinyHunters** — long-running database-theft and dark-web-sale operation, contributors of the data-theft tradecraft and DLS custody

The collective brands itself as **Scattered LAPSUS$ Hunters** (sometimes shortened to "SLH" or "Trinity of Chaos"). Both Resecurity (Tier-2) and SocRadar (Tier-3) have published profiles of the merger; the self-branded "Scattered LAPSUS$ Hunters | DLS" page title is preserved on a 2025-10-12 archive.org snapshot of `shinyhunte.rs`. Operational division within the collective is reported as: Scattered Spider runs the vishing front, LAPSUS$-era operators run the harassment playbook, and ShinyHunters owns the data theft and DLS custody — which is the role this report observes directly.

### 5.2 The canonical vishing → Salesforce / Okta TTP chain

> **Analyst note:** The chain below is the dominant initial-access pattern reported across 28 of 29 named DLS victims. Google's Threat Intelligence Group tracks at least five sub-clusters within it (UNC6040, UNC6395, UNC6671, UNC6661, UNC6240). The IC3 Joint Advisory of 2025-09-12 covers the UNC6040 / UNC6395 portions at government level.

**Stage 1 — Target selection and reconnaissance.** Operator selects an enterprise with externally-reachable help-desk staff and a Salesforce or Okta tenant. LinkedIn and corporate web data identify named help-desk personnel and victim-side IT-admin titles.

**Stage 2 — Help-desk vishing.** Operator places a phone call (English-language, typically female-voiced caller — Dataminr reported recruitment of female vishing operators at approximately $1,000 per call in February 2026) impersonating an internal employee locked out of MFA. Dialogue script extracts an MFA reset or temporary access credential.

**Stage 3 — Victim-branded credential-harvesting site (optional).** Some sub-clusters route the vishing pretext to a victim-branded phishing landing page where the impersonated employee "resets" their own credentials, capturing them for the operator.

**Stage 4 — OAuth Connected App authorization.** With a valid SSO session, the operator authorizes a malicious OAuth Connected App into the victim's Salesforce tenant — frequently a Data Loader clone. This bypasses many CRM-export rate limits and runs under legitimate user authority.

**Stage 5 — Bulk CRM export.** Operator runs bulk Salesforce queries / Data Loader exports against the entire customer record base. In larger intrusions (ZenBusiness 821 GB, Ameriprise 200 GB claimed), the operator escalates to multi-system exfiltration covering SharePoint, document stores, and third-party data warehouses (Snowflake-via-Anodot in the Rockstar Games breach per Mitiga).

**Stage 6 — Extortion contact.** Operator contacts the victim with proof-of-theft and ransom demand. Refusal or non-cooperation results in subdirectory creation on the DLS with `INFORMATION.txt` only (the negotiation phase observed for Alert360 and Ameriprise). Continued refusal results in archive upload with the taunt-filename branding.

**Detection priority:** the most efficient upstream detection point for defenders is **stage 4** — anomalous OAuth Connected App authorization in Salesforce / Okta following a help-desk MFA reset for the same user account. Pure DLS-based detection (Section 9) is the *terminal* indicator.

### 5.3 The Trivy supply-chain branch (europa.zip)

The European Commission breach is the operational anomaly in this campaign. CERT-EU's 2026-04-03 attribution (Tier-1 source) identifies the chain as: a Trivy image-scanner supply-chain compromise attributed to **TeamPCP** delivered an extracted AWS API key, TruffleHog was used for lateral pivot in the EC AWS environment, new access keys were attached to existing users, and approximately 340 GB of uncompressed data was exfiltrated affecting up to 71 Europa web-hosting clients (42 EC internal + at least 29 other Union entities). ShinyHunters subsequently published a 94 GB compressed subset on this DLS on 2026-03-28 — exactly 24 hours after EC's first public disclosure.

ShinyHunters told TechCrunch that they had stolen data TeamPCP had previously taken, demonstrating either cross-actor collaboration or commercial access-brokerage between the two groups. Either interpretation expands the 2026 ShinyHunters campaign's TTP envelope beyond the vishing chain — defenders cannot rely on Salesforce-specific or vishing-specific detection alone.

### 5.4 Active-cluster expansion (January–March 2026)

Since the August 2025 merger, the campaign has expanded:

- **January 2026 — UNC6671 Okta-direct vishing.** Mandiant identified a sub-cluster vishing Okta customers directly (rather than via the Salesforce-tenant pathway). This generalizes the attack beyond Salesforce-specific defenses.
- **February 2026 — Female-vishing-caller recruitment.** Dataminr reported active recruitment of female callers at approximately $1,000 per call, indicating sustained operational scaling.
- **March 2026 — Salesforce Aura misconfiguration.** Help Net Security reported exploitation of Salesforce Aura misconfigurations as a supplementary access vector in the campaign.

**Net assessment:** the campaign cluster is *expanding*, not contracting. Defenders should expect continued TTP variation across 2026 rather than a stable detection profile.

---

## 6. Hosting and Co-Tenancy Analysis

> **Analyst note:** This section assesses the two hosting providers underlying the operation. The takeaway is that PROSPERO is a confirmed Russian bulletproof host with extensive prior abuse documentation, DDoS-Guard is a structurally-abused commercial DDoS-mitigation service, and the operator's choice to split across both is a deliberate OPSEC decision. A neighbor-scan of the entire PROSPERO footprint found no additional ShinyHunters infrastructure.

### 6.1 PROSPERO OOO (AS200593) — DLS host

PROSPERO is a Russia-based hosting provider repeatedly documented in mainstream security reporting as a bulletproof host. Krebs on Security (2025-02-28) identified PROSPERO as a notorious malware and spam host and reported its upstream routing through Kaspersky Lab networks (AS209030) since December 2024. Intrinsec (Tier-2) has linked PROSPERO infrastructure to the SecureHost and BEARHOST bulletproof brands marketed on Russian-language criminal forums and documented hosting of SocGholish, GootLoader, FakeBat, SpyNote, and multiple ransomware operations. Resecurity (Tier-2) has identified PROSPERO and its peer Proton66 as likely destinations for displaced tenants after the BEARHOST exit.

**Bulletproof assessment for AS200593 — CONFIRMED (5 of 6 indicators):**

- Non-cooperative jurisdiction (Russia)
- Named in credible Tier-2/Tier-3 research with publication dates (Krebs, Intrinsec, Resecurity)
- Extensive abuse history with no provider action (multiple ransomware families, RATs, Android banking trojans across the ASN)
- Abuse contact non-responsive (`abuse@pro-spero.ru`; single admin/tech contact ND7667-RIPE; no formal abuse team structure)
- No RPKI validation; announces bogons per bgp.tools
- (Not directly confirmed: cryptocurrency-payment / underground-forum advertisement URL — referenced in secondary sources but not verified to project citation standards)

**Network footprint.** AS200593 announces three /24 prefixes — `91.215.85.0/24`, `91.202.233.0/24`, `193.24.123.0/24` — totaling 768 IPs. The entire AS is enumerable, and threat-intelligence feeds flag the network as presumptively malicious infrastructure. Block-level action against all three prefixes is defensible for organizations whose risk posture justifies it.

### 6.2 Neighbor-scan findings

A 512-IP scan of the two PROSPERO neighbor prefixes (`91.202.233.0/24` and `193.24.123.0/24`) was conducted to test for additional ShinyHunters infrastructure. **No additional ShinyHunters nodes were found** — the DLS at `91.215.85.22` is a single operational node within the AS. The neighbor scan did identify:

- 84 alive hosts in `91.202.233.0/24` with 4 Apache autoindex open directories (3 empty, 1 cPanel vhost listing) — none with ShinyHunters artifacts
- A 20-host cluster of Plesk Obsidian 18.0.76 control panels (build 1800260406.11; distinct instanceId values) representing PROSPERO commercial-hosting tenants, not a phishing fleet
- Various unrelated tenants including a Ledger-wallet typosquat at `193.24.123.223` (`ledger-lives.io`) that is a separate investigation; mention here only to illustrate that PROSPERO's tenant base is heterogeneous

**Co-tenancy is not collaboration.** The presence of unrelated criminal tenants on the same AS is an artifact of bulletproof-hosting market dynamics, not evidence that ShinyHunters is operationally linked to PLAY, Qilin, RansomHub, or other malware families that AlienVault OTX correlates with `91.215.85.22`. Those correlations should not be propagated as ShinyHunters attribution.

### 6.3 DDoS-Guard (AS57724) — identity-page host

DDoS-Guard is a Russia-based DDoS-protection and hosting provider operating approximately 803,874 domains across approximately 3,046 IPs per public BGP data. It is a legitimate commercial service (not a purpose-built criminal hosting provider in the PROSPERO sense), but its product model — origin-IP masking via DDoS-mitigation fronting — provides equivalent functional protection against Western takedown efforts and is widely abused by threat actors. ThreatSTOP documented historical abuse patterns in 2021. No Tier-2 2025–2026 primary research on DDoS-Guard was identified during this investigation; this is a documented research gap.

**Bulletproof assessment for AS57724 — SUSPECTED (2 of 6 indicators):** non-cooperative jurisdiction; structural abuse tolerance via origin-masking. The remaining indicators (appearing in BPH databases, underground-forum advertisement) do not apply to a legitimate commercial DDoS-mitigation product.

**The architectural significance.** Splitting the DLS payload (PROSPERO) from the actor identity page (DDoS-Guard) is the most distinctive infrastructure choice in this operation. Even if PROSPERO were taken down, the actor identity / PGP-key infrastructure would survive on DDoS-Guard, allowing rapid re-publication elsewhere. Conversely, even if DDoS-Guard suspended `shinyhunte.rs`, the DLS itself and its three Tor mirrors remain reachable. This is intermediate-to-advanced operational planning, not opportunistic behavior.

### 6.4 Co-tenancy: a brief note on PROSPERO bulletproof-host neighborhood

During neighbor-scan enumeration, an unrelated typosquat operation targeting Ledger hardware-wallet users (`ledger-lives.io` at `193.24.123.223`) was observed on a PROSPERO-adjacent prefix. This is referenced here only as one example of the heterogeneous criminal-tenant population a Russian bulletproof provider hosts — it is unrelated to ShinyHunters and is documented in a separate investigation. The point is that PROSPERO is a *shared* criminal-hosting environment, which is precisely what makes co-tenancy correlations (the OTX PLAY/Qilin/RansomHub artifacts) misleading as attribution evidence.

---

## 7. Threat Actor Assessment

> **Analyst note:** This section presents the formal attribution conclusion and the evidence behind it. Attribution is DEFINITE at 96% confidence — the highest level used by this publication outside of direct law-enforcement attribution naming the specific IP. The 4% margin reflects the absence of an FBI / CISA / Five Eyes advisory naming `91.215.85.22` itself; everything else aligns. No Unattributed Threat Actor (UTA) designation is needed here because ShinyHunters is a publicly named actor with six years of documented operations.

### 7.1 Attribution statement

| Field | Value |
|---|---|
| **Threat Actor** | ShinyHunters |
| **Collective label** | Scattered LAPSUS$ Hunters (self-chosen, confirmed 2025-10-12) |
| **Confidence** | **DEFINITE (96%)** |

This Data Leak Site is **attributed to** ShinyHunters, **operated by** the Scattered LAPSUS$ Hunters collective, and **confirmed as** ShinyHunters infrastructure based on the evidence constellation below.

### 7.2 Why DEFINITE confidence (the evidence)

**1. Tier-1 government attribution of the TTP cluster.** The IC3 Joint Advisory (2025-09-12) covers the vishing-to-Salesforce OAuth chain (UNC6040 / UNC6395) at government level and names ShinyHunters in association with the cluster. CERT-EU's 2026-04-03 blog formally attributes the data-publication portion of the European Commission breach (the `europa.zip` archive on this DLS) to ShinyHunters. Two independent Tier-1 sources naming the actor and the cluster is the single strongest attribution input below direct IP attribution.

**2. Actor self-attribution on-server.** `INFORMATION.txt` is served from every URL path on `91.215.85.22` and explicitly names "the ShinyHunters Data Leak Site (DLS)" and "the ShinyHunters group." Self-attribution is not by itself definitive (actors can claim other actors' work), but combined with cryptographic key continuity it is dispositive.

**3. Six-year unbroken PGP key lineage.** The Empire Market key (created 2020-01-28, UID `Hunters on Empire`) and the RaidForums key (created 2020-08-25, UID `ShinyHunters`) both cross-signed the rotation handoff to the current key on 2026-03-17, then both self-revoked. Both old keys are recoverable from public keyserver mirrors (`keyserver.ubuntu.com` for the Empire key). Cross-signing the rotation could only have been performed by a party holding both private keys simultaneously — establishing operator continuity from at least early 2020 through the current campaign.

**4. Victim-set corroboration at scale.** 28 of 29 named victims on this DLS are independently corroborated as ShinyHunters victims by mainstream security press (TechCrunch, BleepingComputer, Krebs on Security, BankInfoSecurity, The Record, CyberNews, SecurityWeek, Bloomberg Law, Investment News, etc.) and ingested into Have I Been Pwned. The independently-maintained ransomware.live aggregator converges on the same 28-of-29 set. This level of multi-source convergence is irreconcilable with any false-flag or copycat hypothesis.

**5. Two-Tier-2-vendor consensus.** Google Threat Intelligence Group tracks the campaign as five named sub-clusters (UNC6040 / UNC6395 / UNC6671 / UNC6661 / UNC6240), all attributed to ShinyHunters-affiliated operations. Resecurity has separately documented the Trinity of Chaos / Scattered LAPSUS$ Hunters DLS launch and collective composition. Two Tier-2 vendors with named-actor attribution and no public dissent meets the HIGH-confidence threshold by itself; combined with Tier-1 government sources it elevates to DEFINITE.

**6. Infrastructure consistency.** Seven attacker-controlled infrastructure elements (one DLS clearnet, one identity clearnet, three Tor mirrors, one identity domain, the PGP-key publication path) are consistent with documented ShinyHunters operational preferences for Russian bulletproof hosting and deliberate OPSEC segmentation.

### 7.3 What would push confidence to 100%

A direct FBI / CISA / Europol advisory naming `91.215.85.22` specifically would close the 4% gap. Absent that, no further open-source evidence is available to elevate confidence. The current key body for `F4953411767DE71BEDCDABCB76F4E26F7A20978A` was not independently recovered (the `/newpgp` endpoint returned HTTP 404 at investigation time); the pastebin mirror at `https://pastebin.com/raw/sb7aB9eU` was referenced in signed rotation messages but not verified as still resolvable.

### 7.4 Alternative hypotheses considered and rejected

**H2 — Copycat actor staging false flag.** Rejected. A copycat could not have produced a properly cross-signed PGP rotation by both 2020 keys (which were never publicly leaked in usable private form) and could not have aligned 28 of 29 victims with independently-reported ShinyHunters operations.

**H3 — Hostile takeover by the "James" faction post-December 2025 internal dispute.** Rejected as the ruling hypothesis. The December 2025 internal-doxx statement attributes James only to the Empire key (via the original custodian "Trihash"). Cross-signing the March 2026 rotation required custody of both 2020 keys; the surviving non-James faction therefore retained or regained both keys before the rotation. All 2026 uploads post-date the rotation. The faction dispute complicates handle-level attribution within ShinyHunters but does not undermine attribution of the DLS to ShinyHunters as an organization.

**H4 — Different actor publishing under ShinyHunters' name.** Rejected. The 28-of-29 victim-set convergence with mainstream press attribution and the IC3 / CERT-EU government-level naming of the cluster are inconsistent with this hypothesis.

### 7.5 Handle-level claims (handle attribution, not group attribution)

The December 2025 PGP-signed statement on `shinyhunte.rs` doxxed three claimed members:

| Claimed handle | Claimed initials | Claimed status | This report's confidence |
|---|---|---|---|
| **Yuro** | A.E. | Arrested pre-Dec 2025 | **LOW** — actor-on-actor doxx; no LE corroboration |
| **Trihash** | R.L. | Arrested pre-Dec 2025; original Empire-key custodian | **LOW** — actor-on-actor doxx; no LE corroboration |
| **James** | S.E. (alias X*K) | Ejected member; French; credited with WEMIX attack | **LOW** — actor-on-actor doxx with self-serving attribution-deflection motive; no LE corroboration |

A claimed Telegram contact for "James" at `t.me/wokawoka10` is given. Treat all three identity claims as **pivot material, not ground truth**. The June 2025 Paris BL2C arrests of four French nationals (handles ShinyHunters / Hollow / Noct / Depressed) are timing-consistent with the December 2025 statement's claimed arrests but the LE-published handles do not map cleanly to Yuro / Trihash; no public indictment text has been located that would reconcile these. The faction-internal dynamics do not affect this report's group-level DEFINITE attribution.

### 7.6 Related actors

- **TeamPCP** — Initial-access partner / supplier on the European Commission breach via Trivy supply-chain compromise (CERT-EU attribution). Relationship is either collaborative or commercial access-brokerage; insufficient evidence to determine which.
- **Scattered Spider (UNC3944)** — Listed by the operator as a constituent of the Scattered LAPSUS$ Hunters collective. Vishing front specialist contribution.
- **LAPSUS$ (historical)** — Listed by the operator as a constituent of the collective. Harassment-playbook and public-pressure tradecraft contribution.

---

## 8. MITRE ATT&CK Mapping

> **Analyst note:** This section maps the observed ShinyHunters / Scattered LAPSUS$ Hunters TTPs to MITRE ATT&CK technique IDs. Coverage is restricted to TTPs with HIGH or higher confidence based on either direct artifact observation on `91.215.85.22` (filename branding, ransom note, infrastructure segmentation) or Tier-1/Tier-2 attribution of the upstream chain (IC3, CERT-EU, Google GTIG, Mandiant, Mitiga). Lower-confidence techniques inferred from sub-cluster reporting are omitted to keep the table actionable.

| Tactic | Technique ID | Technique Name | Evidence Observed |
|---|---|---|---|
| Resource Development | T1583.003 | Acquire Infrastructure: Virtual Private Server | DLS hosted on PROSPERO (AS200593) lease; identity page hosted on DDoS-Guard (AS57724); deliberate dual-provider segmentation (Section 6) |
| Resource Development | T1583.001 | Acquire Infrastructure: Domains | `shinyhunte.rs` identity domain registered under Serbia ccTLD for phonetic actor branding (Section 2.2) |
| Resource Development | T1585.001 | Establish Accounts: Social Media Accounts | `t.me/wokawoka10` Telegram contact published in actor doxx statement (Section 7.5); collective Telegram channel announcing August 2025 merger (Section 5.1) |
| Initial Access | T1566.004 | Phishing: Spearphishing Voice | English-language vishing of help-desk personnel impersonating internal employees locked out of MFA; female callers recruited at ~$1,000/call per Dataminr (Section 5.2 stage 2) |
| Initial Access | T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Trivy image-scanner supply-chain compromise attributed to TeamPCP delivered EC AWS API key (Section 5.3); secondary access vector beyond the dominant vishing chain |
| Initial Access | T1078.004 | Valid Accounts: Cloud Accounts | Operator-controlled Salesforce / Okta SSO sessions established post-MFA-reset (Section 5.2 stage 4) |
| Credential Access | T1528 | Steal Application Access Token | Malicious OAuth Connected App (frequently a Data Loader clone) authorized into victim Salesforce tenant under legitimate-user authority (Section 5.2 stage 4) |
| Credential Access | T1606 | Forge Web Credentials | Victim-branded credential-harvesting landing pages used by some sub-clusters to capture self-reset credentials (Section 5.2 stage 3) |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | TruffleHog used to extract additional AWS access keys from EC environment after Trivy-derived initial key (Section 5.3) |
| Discovery | T1538 | Cloud Service Dashboard | Salesforce / Okta admin interfaces and AWS console enumeration once SSO foothold is established (Section 5.2 stages 4–5) |
| Collection | T1530 | Data from Cloud Storage | Bulk Salesforce CRM export via Data Loader; SharePoint and document-store harvest in larger intrusions (ZenBusiness 821 GB, Ameriprise 200 GB claimed); Snowflake-via-Anodot harvest in Rockstar Games breach per Mitiga (Section 5.2 stage 5) |
| Collection | T1213.002 | Data from Information Repositories: SharePoint | SharePoint harvest documented in Ameriprise (200 GB claimed) and several other large intrusions (Section 5.2 stage 5) |
| Command and Control | T1090.003 | Proxy: Multi-hop Proxy | Three Tor `.onion` mirrors fronting the leak site (active main + active redirector + retired) provide Tor-based access path independent of clearnet takedown (Section 2.3) |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | HTTP/80 nginx serving on both the DLS (`91.215.85.22`) and identity page (`91.215.43.200`) as the publication channel (Section 2) |
| Exfiltration | T1567 | Exfiltration Over Web Service | Stolen archives uploaded to ShinyHunters-controlled clearnet web server for publication (~1.1 TB across 30 archives — Sections 3.3, 4) |
| Exfiltration | T1567.002 | Exfiltration to Cloud Storage | Salesforce Data Loader bulk-export workflow exfiltrates CRM contents to operator-controlled cloud / endpoint (Section 5.2 stage 5) |
| Impact | T1657 | Financial Theft | Pay-or-leak extortion model — ransom demanded under threat of public data publication; refusal results in archive upload with taunt-filename branding (Sections 3.1, 3.2) |
| Impact | T1531 | Account Access Removal | Victim accounts can be locked out via SSO-session hijack and admin-credential changes during intrusion (inferred from Salesforce / Okta full-tenant access; observed indirectly via incident reporting) |

*Coverage scope note.* Encryption-based impact (T1486 Data Encrypted for Impact) is **not** mapped here — ShinyHunters operations on this DLS are pure data-theft-and-extortion; no encryption of victim systems is observed or claimed. The functional analog is data-disclosure-as-coercion (T1657 Financial Theft + T1567 Exfiltration Over Web Service), which is captured above.

---

## 9. Detection and Hunting Guidance

> **Analyst note:** This section is a brief orientation to detection priorities. Full YARA rules (filename and ransom-note string anchors), Sigma rules (network connection, DNS query, file-write, anomalous OAuth authorization), and Suricata signatures are in the linked detection file. Detection rules in this report are intentionally not duplicated.

The most operationally valuable detections, in priority order:

1. **Filename-pattern hunt across enterprise file shares and cloud-sync paths.** The taunt-filename regex `(?i)should(ve|a).*paid.*ransom.*shinyhunters` is operationally unique and matches 25 of 30 observed archives. A match almost certainly indicates either DLS-staging (an internal user has downloaded the archive) or an extreme false-positive of a security-research analyst archiving the IOC.
2. **Network blocks and DNS sinkholes.** `91.215.85.22`, `91.215.43.200`, `shinyhunte.rs`, `pro-spero.ru`, plus the three `.onion` addresses. These are high-confidence indicators with negligible false-positive risk for non-research environments.
3. **Upstream chain detection.** This is more valuable than DLS-side detection but requires SaaS log access. Watch for: help-desk MFA reset for an account followed within minutes by a Salesforce or Okta SSO from anomalous geography; OAuth Connected App authorization in Salesforce (especially Data Loader clones) by a recently-MFA-reset account; Salesforce bulk export volumes that exceed user historical baseline.
4. **Ransom-note string anchors.** `INFORMATION.txt` matches against the exact text in Section 3.1 are diagnostic. Useful for incident-response triage when an organization suspects DLS exposure but cannot yet confirm.

Full YARA, Sigma, and Suricata rules are published separately in [`shinyhunters-dls-91-215-85-22-20260417-detections.md`](/hunting-detections/shinyhunters-dls-91-215-85-22-20260417-detections/) (source file: `shinyhunters-dls-91-215-85-22-20260417-detections.md`).

**Full validated IOC feed** — machine-readable JSON suitable for SIEM / EDR ingestion — is published at: [/ioc-feeds/shinyhunters-dls-91-215-85-22-20260417-iocs.json](/ioc-feeds/shinyhunters-dls-91-215-85-22-20260417-iocs.json).

---

## 10. Response Orientation

This is a brief orientation for readers who need to know *what to address*, not *how to address it*. Organizations facing actual exposure should engage their incident response function or a dedicated playbook.

**Detection priorities (highest value first).**

- Network-perimeter blocks for `91.215.85.22`, `91.215.43.200`, `shinyhunte.rs`, the three `.onion` mirrors
- File-share / cloud-sync hunt for the `(?i)should(ve|a).*paid.*ransom.*shinyhunters` filename pattern
- Salesforce / Okta event-monitoring for anomalous OAuth Connected App authorization tied to recently-MFA-reset accounts (the upstream attack stage, not the DLS itself)

**Persistence targets to enumerate and remove.**

- Unauthorized OAuth Connected Apps in Salesforce tenants (especially Data Loader clones)
- Anomalous Okta sessions or persistent tokens for help-desk-reset accounts
- AWS access keys attached to existing identities outside of normal provisioning workflows (relevant to the supply-chain branch)
- Help-desk ticket trail for unverified MFA resets within the past 90 days

**Containment categories.**

- Isolate Salesforce / Okta tenants showing suspicious OAuth grants
- Revoke and rotate credentials for accounts implicated in vishing-induced MFA resets
- Block ShinyHunters infrastructure at network egress
- Engage legal counsel regarding regulatory notification timelines (sector-dependent)
- For Alert360: treat as priority-one outreach if the organization is a partner, customer, or has a notification relationship

---

## 11. Confidence Levels Summary

| Claim | Confidence | Basis |
|---|---|---|
| DLS operated by ShinyHunters / Scattered LAPSUS$ Hunters | **DEFINITE (96%)** | IC3 Tier-1, CERT-EU Tier-1, two Tier-2 vendor groups, 28/29 victim corroboration, 6-year PGP lineage, 7 infrastructure elements |
| 28 of 29 named victims publicly corroborated | **DEFINITE** | Mainstream security press + ransomware.live convergence |
| Alert360 is the sole unacknowledged victim | **HIGH** | True null-result across all source tiers; orthogonal confirmation from ransomware.live |
| `europa.zip` = European Commission breach | **HIGH** | Upload timing + size alignment + CERT-EU public attribution of underlying chain |
| `bf_03_2026.sql.7z` = BreachForums v5 user database | **HIGH** | HIBP ingestion of 339,778 records; filename + month alignment |
| TeamPCP supplied initial access for the EC chain | **HIGH** | CERT-EU Tier-1 attribution |
| Active extortion pipeline (Alert360, Ameriprise pre-archive) | **HIGH** | Subdirectories with `INFORMATION.txt` only; consistent with documented actor negotiation behavior |
| PROSPERO (AS200593) = bulletproof hosting | **HIGH** | 5 of 6 BPH indicators; named in Krebs, Intrinsec, Resecurity |
| DDoS-Guard (AS57724) = structurally-abused commercial service | **MODERATE** | 2 of 6 BPH indicators; legitimate product structurally enabling abuse |
| Handle-level identities (Yuro / Trihash / James) | **LOW** | Actor-on-actor doxx; no LE corroboration; self-serving motives |
| `91.215.85.22` is a single ShinyHunters operational node within PROSPERO | **HIGH** | 512-IP neighbor scan found no additional ShinyHunters infrastructure |
| OTX co-tenant correlations (PLAY / Qilin / RansomHub) attributable to ShinyHunters | **REJECTED** | Shared-BPH artifacts only; do not propagate as ShinyHunters attribution |

---

## 12. FAQ / Key Intelligence Questions

**Q1. Who operates 91.215.85.22, and what is the attribution confidence?**

ShinyHunters operates `91.215.85.22` under the Scattered LAPSUS$ Hunters collective banner formed in August 2025. Attribution is **DEFINITE at 96% confidence** — the highest level this publication uses outside of direct law-enforcement attribution naming the specific IP. The evidence supporting that level is: a Tier-1 IC3 Joint Advisory (2025-09-12) and a Tier-1 CERT-EU attribution (2026-04-03) naming ShinyHunters and the underlying TTP cluster; two Tier-2 vendor concurrences (Google GTIG, Resecurity); on-server actor self-attribution in `INFORMATION.txt`; six years of unbroken PGP key continuity across Empire Market, RaidForums, and BreachForums platforms confirmed via dual-key cross-signed rotation on 2026-03-17; and 28 of 29 named DLS victims independently corroborated as ShinyHunters targets in mainstream security press. The 4% gap to 100% reflects only the absence of an FBI / CISA / Five Eyes advisory naming `91.215.85.22` itself.

**Q2. How many victims are on this DLS, and are they all already publicly known?**

Twenty-nine named victim organizations are present on the DLS (plus two unlabelled archives — a 94 GB European Commission dump and a 43 MB BreachForums v5 user database). Twenty-two victims are fully publicly reported with company acknowledgment. Nine victims are partially disclosed — actor-claimed but without formal company acknowledgment yet. **One victim — Alert360, a US home and small-business alarm-monitoring provider — has no prior public reporting in any tier** (mainstream press, government bulletins, or crowdsourced trackers including ransomware.live). This report is the first public documentation of Alert360's presence on the DLS. The Alert360 subdirectory currently contains only `INFORMATION.txt` (no archive yet), indicating an extortion-negotiation stage — historically consistent with negotiation behavior observed for Ameriprise, Odido, and Woflow on this same DLS.

**Q3. What is the relationship between ShinyHunters, Scattered Spider, and LAPSUS$?**

In August 2025 a Telegram-announced merger combined three previously-distinct threat actor groups into the **Scattered LAPSUS$ Hunters** collective (also called "Trinity of Chaos" or "SLH"). ShinyHunters contributes the data-theft tradecraft and DLS custody — the role this report observes directly on `91.215.85.22`. Scattered Spider (UNC3944) contributes English-language vishing and social-engineering specialization, running the help-desk vishing front. LAPSUS$-aligned operators contribute the harassment / public-pressure playbook. The merger is documented by Resecurity (Tier-2) and SocRadar (Tier-3), and the self-branded "Scattered LAPSUS$ Hunters | DLS" page title is preserved on a 2025-10-12 archive.org snapshot of `shinyhunte.rs`. Operationally, an attack on a victim in this campaign almost certainly involves all three contributor groups in different stages — Scattered Spider in initial access, ShinyHunters in data theft and publication, LAPSUS$-era operators in extortion pressure.

**Q4. Is PROSPERO exclusive to ShinyHunters, or is the AS shared with other criminal tenants?**

PROSPERO (AS200593) is a **shared Russian bulletproof-hosting environment**, not a ShinyHunters-dedicated provider. A 512-IP neighbor scan of the two adjacent PROSPERO prefixes (`91.202.233.0/24` and `193.24.123.0/24`) found no additional ShinyHunters infrastructure — `91.215.85.22` is a single operational node within the AS. The neighbor scan did identify unrelated criminal tenants including a Ledger hardware-wallet typosquat (`ledger-lives.io` at `193.24.123.223`) and a 20-host Plesk Obsidian commercial-hosting cluster, plus open-source reporting documents PROSPERO hosting SocGholish, GootLoader, FakeBat, SpyNote, and multiple ransomware operations across the broader ASN. **Important corollary:** AlienVault OTX correlates `91.215.85.22` with PLAY, Qilin, RansomHub, and various RAT families because they have all been hosted on the same AS at various times. **These co-tenancy correlations should NOT be propagated as ShinyHunters attribution** — they are shared-bulletproof-hosting artifacts, not evidence of operational linkage.

**Q5. What should defenders do if they find this DLS's ransom note (`INFORMATION.txt`) or a taunt-filename archive on internal file shares?**

A `(?i)should(ve|a).*paid.*ransom.*shinyhunters` filename or a verbatim `INFORMATION.txt` ransom-note match on an enterprise file share, cloud-sync staging directory, or web-proxy log is a **near-certain indicator** of either DLS-staging (an internal user has downloaded the archive — possibly an analyst, possibly a curious employee, possibly evidence of insider-mediated exposure) or active intrusion progression. Recommended action categories: (1) treat the host where the file was found as a forensic priority and preserve volatile state before remediation; (2) determine through proxy / DNS logs whether the file was downloaded from `91.215.85.22` directly or via one of the Tor mirrors; (3) check whether the file content corresponds to your organization or a third party (vendor, customer, partner) — both are reportable; (4) escalate to legal counsel regarding regulatory notification timelines if your organization is named or if the data class is subject to GLBA / HIPAA / FERPA / GDPR / state breach-notification laws; (5) review Salesforce / Okta logs for any indicators consistent with the upstream chain in Section 5.2, particularly anomalous OAuth Connected App authorizations and bulk Data Loader exports in the 90 days preceding discovery. The DLS appearance is the *terminal* event in the attack chain — by the time a file appears on internal infrastructure, the breach is months old, and the priority is scope determination, not prevention.

**Q6. Is the DLS likely to be taken down, and how should defenders plan for its persistence?**

Plan for persistence. The operator deliberately segments infrastructure across two Russian providers (PROSPERO for the DLS, DDoS-Guard for the identity page) and maintains three Tor mirrors. PROSPERO has an extensive prior abuse history with no provider action documented in Krebs, Intrinsec, or Resecurity reporting; the abuse contact at `abuse@pro-spero.ru` is community-reported as non-responsive. DDoS-Guard's product model (origin-IP masking via DDoS-mitigation fronting) provides equivalent functional protection against Western takedown. Even in an unlikely scenario where one provider were to suspend the relevant IP, the operator retains five publication paths (DLS clearnet + identity clearnet + three Tor mirrors). Defeating the operation requires multi-jurisdictional coordination, upstream-carrier pressure, or operator-side compromise — none of which are achievable through routine abuse-reporting channels. Defenders should treat the IOCs in the linked feed as durable and the campaign as expanding rather than declining (Section 5.4 documents January–March 2026 cluster expansion).

---

## 13. Gaps and Open Questions

- **Direct law-enforcement IP attribution.** No FBI / CISA / Five Eyes / Europol advisory has named `91.215.85.22` specifically. Government advisories cover TTP clusters at the actor level, not operator-side IPs.
- **Current PGP key body.** Full key body for `F4953411767DE71BEDCDABCB76F4E26F7A20978A` not independently recovered (`/newpgp` returned HTTP 404 at investigation time; pastebin mirror at `https://pastebin.com/raw/sb7aB9eU` not verified as still resolvable during this investigation). Resolution path: direct keyserver query against `keyserver.ubuntu.com`, `keys.openpgp.org`, or SKS network mirrors for fingerprint `F4953411767DE71BEDCDABCB76F4E26F7A20978A`.
- **Paris June 2025 arrests vs December 2025 doxx handles.** Public LE-named handles (ShinyHunters / Hollow / Noct / Depressed) do not map cleanly to actor-claimed Yuro / Trihash. No public indictment text located.
- **TeamPCP profile.** Limited public profile literature on the TeamPCP cluster; precise nature of the ShinyHunters-TeamPCP relationship (collaboration vs commercial access-brokerage) is unresolved.
- **DDoS-Guard 2025–2026 Tier-2 primary research.** No recent named-actor research on AS57724 located during this investigation.
- **shinyhunte.rs WHOIS / registration date.** Not recovered (Serbia ccTLD registry privacy).
- **Tor mirror reachability.** Not independently verified during this investigation; reliance on operator self-report.

---

## 14. Appendix: References and Further Reading

**Tier-1 sources (government / CERT)**

- IC3 Joint Advisory, "ShinyHunters and UNC6040 Vishing-to-Salesforce Threat Cluster," 2025-09-12. https://www.ic3.gov/CSA/2025/250912.pdf
- CERT-EU, "European Commission Cloud Breach — Trivy Supply Chain," 2026-04-03. https://cert.europa.eu/blog/european-commission-cloud-breach-trivy-supply-chain

**Tier-2 sources (vendor research)**

- Google Cloud / GTIG, "Expansion of ShinyHunters SaaS Data Theft." https://cloud.google.com/blog/topics/threat-intelligence/expansion-shinyhunters-saas-data-theft
- Google Cloud / GTIG, "UNC6040 Proactive Hardening Recommendations." https://cloud.google.com/blog/topics/threat-intelligence/unc6040-proactive-hardening-recommendations
- Resecurity, "Trinity of Chaos: The LAPSUS$, ShinyHunters, and Scattered Spider Alliance." https://www.resecurity.com/blog/article/trinity-of-chaos-the-lapsus-shinyhunters-and-scattered-spider-alliance-embarks-on-global-cybercrime-spree
- Resecurity, "ShinyHunters Launches Data Leak Site." https://www.resecurity.com/blog/article/shinyhunters-launches-data-leak-site-trinity-of-chaos-announces-new-ransomware-victims
- Intrinsec, "Prospero / Proton66 — Tracing Bulletproof Networks." https://www.intrinsec.com/en/prospero-proton66-tracing-uncovering-the-links-between-bulletproof-networks/
- Resecurity, "Qilin Ransomware and the Ghost Bulletproof Hosting Conglomerate." https://www.resecurity.com/blog/article/qilin-ransomware-and-the-ghost-bulletproof-hosting-conglomerate
- Sophos, "Taking the Shine off BreachForums." https://www.sophos.com/en-us/blog/taking-the-shine-off-breachforums
- The Record, "France BreachForums Suspects Arrests." https://therecord.media/france-breachforums-suspects-arrests
- Mitiga, "ShinyHunters and UNC6395 — Inside the Salesforce and Salesloft Breaches." https://www.mitiga.io/blog/shinyhunters-and-unc6395-inside-the-salesforce-and-salesloft-breaches
- Dataminr, "SLH Recruiting Women for Vishing." https://www.dataminr.com/resources/intel-brief/slh-recruiting-women-for-vishing/
- Have I Been Pwned, "BreachForumsV5." https://haveibeenpwned.com/Breach/BreachForumsV5

**Tier-3 sources (community / press)**

- Krebs on Security, "ShinyHunters Wage Broad Corporate Extortion Spree," 2025-10. https://krebsonsecurity.com/2025/10/shinyhunters-wage-broad-corporate-extortion-spree/
- Krebs on Security, "Notorious Malware Spam Host Prospero Moves to Kaspersky Lab," 2025-02-28. https://krebsonsecurity.com/2025/02/notorious-malware-spam-host-prospero-moves-to-kaspersky-lab/
- Krebs on Security, "Please Don't Feed the Scattered LAPSUS$ Shiny Hunters," 2026-02. https://krebsonsecurity.com/2026/02/please-dont-feed-the-scattered-lapsus-shiny-hunters/
- TechCrunch, "Europe's Cyber Agency Blames Hacking Gangs for Massive Data Breach and Leak," 2026-04-03. https://techcrunch.com/2026/04/03/europes-cyber-agency-blames-hacking-gangs-for-massive-data-breach-and-leak/
- BleepingComputer, "CERT-EU European Commission Hack Exposes Data of 30 EU Entities." https://www.bleepingcomputer.com/news/security/cert-eu-european-commission-hack-exposes-data-of-30-eu-entities/
- ransomware.live, ShinyHunters group profile. https://www.ransomware.live/group/shinyhunters
- ThreatSTOP, "DDoS-Guard AS57724 is Hosting Some Pretty Bad IP Addresses," 2021. https://www.threatstop.com/blog/ddos-guard-as57724-is-hosting-some-pretty-bad-ip-addresses
- SocRadar, "Dark Web Profile — Scattered LAPSUS$ Hunters." https://socradar.io/blog/dark-web-profile-scattered-lapsus-hunters/
- SalesforceBen, "ShinyHunters Breach 400 Companies via Salesforce Experience Cloud." https://www.salesforceben.com/shinyhunters-breach-400-companies-via-salesforce-experience-cloud/
- Help Net Security, "ShinyHunters Salesforce Aura Data Breach," 2026-03-11. https://www.helpnetsecurity.com/2026/03/11/shinyhunters-salesforce-aura-data-breach/

**Investigation evidence base**

Full investigation evidence (file inventory, victim tracker, ransom-note artifacts, neighbor-scan raw data, PGP key archives, attribution worksheets) is preserved at `threat-intel-vault/investigations/ShinyHunters DLS - 91.215.85.22/`.

---

© 2026 Joseph. All rights reserved. See LICENSE for terms.
