---
title: "Detection Rules — Multi-Cluster Open-Directory 79.137.192.3 (Rhadamanthys MaaS / BellaMain PhaaS / Inkognito)"
date: '2026-05-15'
layout: post
permalink: /hunting-detections/opendirectory-79-137-192-3-20260515-detections/
thumbnail: /assets/images/cards/opendirectory-79-137-192-3-20260515.png
hide: true
---

**Campaign:** OpenDirectory-MultiCluster-Rhadamanthys-BellaMain-Inkognito-79.137.192.3
**Date:** 2026-05-15
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/opendirectory-79-137-192-3-20260515/

---

## Detection Coverage Summary

Three operationally-separate clusters shared the multi-tenant Aeza bulletproof IP `79.137.192.3`: a Rhadamanthys MaaS-customer loader/Stage-2 (Cluster C), a BellaMain Turkish phishing-as-a-service panel (Cluster A), and the Inkognito VPN/phishing brand portfolio (Cluster B). A Tofsee spam-botnet build is documented separately as an unrelated co-tenant. This package has been re-tiered: rules that keyed solely on a hard-coded IP, domain, hash, or one-off filename with no surviving behavioral or structural signal once the literal is removed have been routed to the IOC feed rather than kept as standalone rules.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 4 | 4 | T1027, T1027.002, T1027.013, T1071.001, T1102, T1140 | 1 |
| Sigma | 3 | 0 | T1112, T1218.008, T1055.012, T1071.001 | 1 |
| Suricata | 1 | 0 | T1071.001 | 4 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchors:**
- The `.frontb` PE section name + `Roland` decoy string, and the operator-modified Q3VM bytecode magic `0x14744214` + `Roland` (both YARA Detection) are family-wide Rhadamanthys structural indicators — they are expected to generalize beyond this one MaaS customer.
- The `HKU\<SID>\Software\SibCode\sn` registry marker (Sigma Detection) is confirmed across four independent sibling Stage-2 sandbox runs, not just this customer's sample.
- The BellaMain panel's bespoke PHP admin-endpoint paths (YARA + Sigma Detection) and the Rhadamanthys customer panel-ID URL token `e6d92c6b5b2a03bee7fbab40` (Suricata Detection) both survive infrastructure rotation — each keys on an operator/developer artifact, not the current IP or domain.

**Atomics routed to the IOC feed:** six of the original package's rules keyed solely on a hard-coded IP, a domain list, or a hash/imphash/PDB-path combination, with no behavior surviving once the literal is removed — the Rhadamanthys C2 IP `79.133.180.168:3394` (a direct TCP match and a second rule using it as a hardcoded TLS SNI content match), the BellaMain staging IP `79.137.192.3` (HTTP Host match), the 17-domain Inkognito brand-portfolio list (a Sigma `dns` selection and a Suricata PCRE with no content prefilter), and the Tofsee co-tenant's SHA256/imphash/PDB-path fingerprint. All values are carried in [`opendirectory-79-137-192-3-20260515-iocs.json`](/ioc-feeds/opendirectory-79-137-192-3-20260515-iocs.json); three domains referenced only in the original rules (`akredup.ru`, `divar-irantop.shop`, `catnpv.xyz`) were not yet in the feed and have been added.

---

## Multi-Family Organization

This detection package targets three operationally-separate operators that shared the multi-tenant Aeza bulletproof IP `79.137.192.3`. Cross-cluster linkage is **LOW** — co-residency on this IP is NOT operationally diagnostic. Detections are organized by cluster so defenders can apply only the rules relevant to their environment:

| Cluster | Family / Operator | Surviving Rules (post-tiering) | Defender Priority |
|---|---|---|---|
| **C** | Rhadamanthys MaaS-customer (loader + Stage-2) | 6 YARA (3 Detection, 3 Hunting) + 2 Sigma Detection + 1 Suricata Detection | **PRIMARY** — broadly applicable, Tier-1 commodity stealer |
| A | BellaMain Turkish PhaaS panel | 1 YARA Detection + 1 Sigma Detection | Regional (Turkish marketplace targets) |
| B | Inkognito brand portfolio (VPN/phishing/CryptOne) | 0 — coverage is IOC-feed-only (17 domains); no durable behavioral/structural indicator was available in the underlying evidence | Regional (Russian-speaking + EU phishing) — block via feed |
| (Co-tenant) | Tofsee spam-botnet | 1 YARA Hunting (family-bound reference rule) | General — family-stable rule, not campaign-bound |

---

## YARA Rules

### Detection Rules

#### Rhadamanthys .frontb Stage-2 Section Marker

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1027 (Obfuscated Files or Information), T1140 (Deobfuscate/Decode Files or Information)
**Confidence:** HIGH
**Rationale:** The `.frontb` PE section name is a family-wide Rhadamanthys Stage-2 characteristic (a pre-allocated empty runtime buffer for the decrypted payload), not specific to this one MaaS customer — it is expected to recur across other customers' Stage-2 builds. Paired with the `Roland` decoy string from the Stage-2 plaintext, also part of the family's shared anti-analysis tradecraft.
**False Positives:** None known — `.frontb` is not a standard MSVC/MinGW/Delphi/Go section name, and the co-required `Roland` decoy string has no legitimate-software collision.
**Blind Spots:** A future Rhadamanthys build variant that renames the `.frontb` section would evade; the rule targets the on-disk Stage-2 payload, not a memory-only unpack state that discards section headers.
**Validation:** Scan the reference Stage-2 sample — both the section name and the Roland string must match; a legitimate PE with an unrelated empty data section must NOT fire (the Roland co-condition prevents that).
**Deployment:** Endpoint AV/EDR file scan, static triage of extracted/decrypted Stage-2 payloads.

```yara
/*
   Yara Rule Set
   Identifier: Multi-Cluster Open-Directory 79.137.192.3 (Rhadamanthys MaaS / BellaMain PhaaS / Inkognito)
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

import "pe"

rule MALW_Rhadamanthys_FrontbSection
{
    meta:
        description = "Detects Rhadamanthys Stage-2 binaries by the family-stable .frontb PE section name (a pre-allocated empty runtime buffer for the decrypted Stage-2 payload). Anchored with a Roland decoy string from the Stage-2 plaintext to reduce false positives."
        license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-79-137-192-3-20260515-detections/"
        date = "2026-05-15"
        hash1 = "804f45487c1cda5b69c743f9eb691a12fe0fdcf0d3a9f32003898f1e3836af50"
        family = "Rhadamanthys"
        cluster = "C"
        threat_class = "infostealer,maas"
        id = "b64f32bc-0c99-582b-b1a0-8c3c569ef6d4"

    strings:
        $s_roland = "Roland" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 2MB
        and for any i in (0 .. pe.number_of_sections - 1) : (
            pe.sections[i].name == ".frontb"
        )
        and $s_roland
}
```

#### Rhadamanthys Operator-Modified Q3VM Bytecode Magic

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1027.013 (Encrypted/Encoded File)
**Confidence:** HIGH
**Rationale:** The operator-modified Q3VM derivative bytecode magic (`0x14744214`, vs. stock Q3VM `0x12721444`) characterizes this Rhadamanthys build lineage generally, not a per-customer artifact — unlike the customer-specific cipher-material rules below, this is expected to catch other MaaS customers running the same Stage-2 version. Paired with the family-wide `Roland` decoy string.
**False Positives:** None known — the modified magic value does not occur outside a Rhadamanthys Stage-2 build of this lineage.
**Blind Spots:** A future Rhadamanthys build that changes the modified-magic value (or reverts to stock Q3VM) would evade.
**Validation:** Scan the reference Stage-2 sample — the 4-byte magic and the Roland string must both match; a file embedding only stock Q3VM (`0x12721444`) must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, memory scanning of unpacked Stage-2.

```yara
rule MALW_Rhadamanthys_Q3VMBytecodeModifiedMagic
{
    meta:
        description = "Detects Rhadamanthys Stage-2 binaries containing the operator-modified Q3VM derivative bytecode magic 0x14744214 (vs stock Q3VM 0x12721444). Anchored with a Roland decoy string co-condition because a 4-byte magic alone has unacceptable false-positive risk."
        license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-79-137-192-3-20260515-detections/"
        date = "2026-05-15"
        hash1 = "804f45487c1cda5b69c743f9eb691a12fe0fdcf0d3a9f32003898f1e3836af50"
        family = "Rhadamanthys"
        cluster = "C"
        threat_class = "infostealer,maas,vm_obfuscation"
        id = "b069b1e8-a290-58e7-b2be-12743835ba77"

    strings:
        $b_magic_le = { 14 42 74 14 }
        $s_roland = "Roland" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 2MB
        and $b_magic_le
        and $s_roland
}
```

#### Rhadamanthys Operator Loader Build/Campaign Strings

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1027 (Obfuscated Files or Information)
**Confidence:** HIGH
**Rationale:** Requires 2-of-4 operator-specific strings: two build/campaign ID literals, a 45-character operator credential/token, and the customer panel ID also used in the Suricata URI-path rule below. The panel ID was independently observed stable across two beacons roughly 40 days apart, giving this combination real cross-time durability evidence beyond a single sample.
**False Positives:** None known — all four strings are operator-chosen values with no legitimate-software collision; the 2-of-4 threshold means an operator must rotate at least two of the four to evade.
**Blind Spots:** A loader rebuild that rotates 2+ of the four strings evades; does not generalize to other MaaS customers (these are this operator's own values).
**Validation:** Scan the reference loader sample — at least 2 of the 4 strings must match; unrelated software must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, static triage of loader binaries.

```yara
rule MALW_Rhadamanthys_OperatorLoaderStrings
{
    meta:
        description = "Detects this Rhadamanthys customer's Stage-1 loader by operator-specific build/campaign ID strings observed in std::cout output and operator credential strings. Requires 2-of-N matches to reduce false positives on any single string appearing in unrelated content."
        license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-79-137-192-3-20260515-detections/"
        date = "2026-05-15"
        hash1 = "5c38a5dd3703b1c4b8c2466b18ce9f4c45ef4c9bf6c3096bee8b24d20ecd247a"
        family = "Rhadamanthys"
        cluster = "C"
        threat_class = "loader,operator_specific"
        id = "76476cd6-5dc9-5c43-ae9b-22fc6f92ba0c"

    strings:
        $s_id1 = "BombAUb23456" ascii fullword
        $s_id2 = "DubzAias932" ascii fullword
        $s_cred = "Ahuh783bhASbsxAsiopJQAiwhhbchG&*#U897u*#&*473" ascii
        $s_panel_id = "e6d92c6b5b2a03bee7fbab40" ascii fullword

    condition:
        uint16(0) == 0x5A4D
        and filesize < 5MB
        and 2 of them
}
```

#### BellaMain PhaaS Panel PHP Source

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1102 (Web Service)
**Confidence:** HIGH
**Rationale:** Requires the obfuscated admin-directory name, or the Wadanz developer's session-encryption function names, or the operator alias combined with a secondary anchor. The Wadanz function names are a developer-signature artifact — durable across panel redeployments and potentially useful for pivoting to other panels by the same developer.
**False Positives:** None known — the admin directory string and Wadanz function names have no legitimate-software collision.
**Blind Spots:** A future BellaMain build from a different developer (no Wadanz function names, different admin directory) would evade.
**Validation:** Scan the BellaMain panel archive/PHP source — the admin dir string or Wadanz function names must match; unrelated PHP source must NOT fire.
**Deployment:** Web-server file-integrity scanning, hosting-provider abuse triage, static triage of seized panel archives.

```yara
rule MALW_BellaMain_PHPPanel
{
    meta:
        description = "Detects BellaMain Turkish PhaaS panel PHP source files by the Wadanz developer pseudonym function names (sifreleWadanz / sifrecozWadanz session encryption helpers) and the obfuscated admin directory name. Operator alias @AresRS34 alone is NOT sufficient to trigger — it's paired with a BellaMain-specific anchor to prevent false positives on threat intelligence reports about this actor."
        license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-79-137-192-3-20260515-detections/"
        date = "2026-05-15"
        hash1 = "f791fae41cdd3f141221d1783ed4779c839de7fc834ff4fc80a5d7f74b11ff88"
        family = "BellaMain"
        cluster = "A"
        threat_class = "phaas,panel"
        id = "1f58eaf6-b4d6-5e5d-b4a2-f481987b0684"

    strings:
        $s_admindir = "V5VgjLU0jsDe" ascii
        $s_aliasaresrs = "@AresRS34" ascii
        $s_wadanz_enc = "sifreleWadanz" ascii
        $s_wadanz_dec = "sifrecozWadanz" ascii
        $s_dbname = "jakartaxdw" ascii

    condition:
        filesize < 500KB
        and (
            $s_admindir
            or any of ($s_wadanz_enc, $s_wadanz_dec)
            or ($s_aliasaresrs and any of ($s_wadanz_enc, $s_wadanz_dec, $s_dbname))
        )
}
```

### Hunting Rules

#### Rhadamanthys Stage-2 Minimal Import Surface

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1027.002 (Software Packing), T1140 (Deobfuscate/Decode Files or Information)
**Confidence:** MODERATE
**Rationale:** The absence of WS2_32/CRYPT32 imports combined with a minimal GDI/USER32/ADVAPI32 import set is a durable structural pattern for this Stage-2 build, but — as flagged in the original analysis — a minimal-import-surface signal alone can match unrelated GDI-heavy applications. Intended as a corroborating signal alongside the other Rhadamanthys rules in this file, not a standalone alert.
**False Positives:** Unrelated GDI-heavy applications with a similarly minimal import table could coincidentally match; not intended for standalone alerting.
**Deployment:** Endpoint AV/EDR file scan as a secondary/corroborating signal only — pair with another Rhadamanthys Detection-tier rule before treating a hit as high-confidence.

```yara
import "pe"

rule MALW_Rhadamanthys_Stage2_ImportSurface
{
    meta:
        description = "Detects Rhadamanthys Stage-2 binaries by the distinctive minimal-import surface: USER32 GetDC/ReleaseDC/GetSystemMetrics + ADVAPI32 RegQueryValueExW combined with several distinctive GDI32 decoy imports. Stage-2 payloads avoid common crypto/network library imports — the absence of WS2_32 and CRYPT32 raises specificity."
        license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-79-137-192-3-20260515-detections/"
        date = "2026-05-15"
        hash1 = "804f45487c1cda5b69c743f9eb691a12fe0fdcf0d3a9f32003898f1e3836af50"
        family = "Rhadamanthys"
        cluster = "C"
        threat_class = "infostealer,maas"
        fp_risk = "MEDIUM — minimal-import surface alone could match unrelated GDI-heavy applications; pair with other Rhadamanthys rules for high-confidence verdict."
        id = "65d56771-90a6-5465-9bfd-8b247839e1e6"

    condition:
        uint16(0) == 0x5A4D
        and filesize < 2MB
        and pe.imports("USER32.dll", "GetDC")
        and pe.imports("USER32.dll", "ReleaseDC")
        and pe.imports("USER32.dll", "GetSystemMetrics")
        and pe.imports("ADVAPI32.dll", "RegQueryValueExW")
        and pe.imports("GDI32.dll", "Ellipse")
        and pe.imports("GDI32.dll", "GetAspectRatioFilterEx")
        and not pe.imports("WS2_32.dll")
        and not pe.imports("CRYPT32.dll")
}
```

#### Rhadamanthys Customer-Specific Stage-2 CBC-XOR IV

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1027 (Obfuscated Files or Information), T1140 (Deobfuscate/Decode Files or Information)
**Confidence:** MODERATE
**Rationale:** A single 16-byte cryptographic IV embedded at a fixed offset in this customer's Stage-2. The byte pattern itself has negligible collision risk with unrelated software, but durability across future rebuilds by this same customer is inferred, not confirmed by a second observed sample — a single-anchor rule keyed on one build's embedded constant is brittle by definition, even when the constant itself is highly specific.
**False Positives:** None known on the byte pattern itself.
**Deployment:** Static triage / pivot-hunting for this specific MaaS customer's Stage-2 builds; not for standalone alerting given the single-sample-only confirmation of this constant.

```yara
rule MALW_Rhadamanthys_CustomerCBCXOR_IV
{
    meta:
        description = "Detects this specific Rhadamanthys MaaS customer's Stage-2 binaries by the customer-specific 16-byte CBC-XOR IV embedded in .rdata at offset 0x0001c434. Different MaaS customers use different IVs — this is the highest-value per-customer fingerprint in the package, though its stability across this customer's future rebuilds is inferred rather than confirmed by a second sample."
        license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-79-137-192-3-20260515-detections/"
        date = "2026-05-15"
        hash1 = "804f45487c1cda5b69c743f9eb691a12fe0fdcf0d3a9f32003898f1e3836af50"
        family = "Rhadamanthys"
        cluster = "C"
        threat_class = "infostealer,maas,customer_specific"
        id = "769462d4-efd8-52a6-8e6c-de4357bbbb21"

    strings:
        $b_iv = { f6 35 8d 79 df 69 c5 77 d9 dc e6 bb 77 fa 4f a7 }

    condition:
        uint16(0) == 0x5A4D
        and filesize < 2MB
        and $b_iv
}
```

#### Rhadamanthys Customer-Specific Loader RC4 Key

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1140 (Deobfuscate/Decode Files or Information), T1027.002 (Software Packing)
**Confidence:** MODERATE
**Rationale:** Same brittleness profile as the CBC-XOR IV rule above — a single 31-byte RC4 key embedded at a fixed offset in this customer's loader, used to decrypt the embedded Stage-2 PE. Near-zero collision risk on the byte pattern, but cross-rebuild stability is unconfirmed from a single sample.
**False Positives:** None known on the byte pattern itself.
**Deployment:** Static triage / pivot-hunting for this specific MaaS customer's loader builds; not for standalone alerting.

```yara
rule MALW_Rhadamanthys_LoaderRC4Key
{
    meta:
        description = "Detects this specific Rhadamanthys customer's Stage-1 loader by the 31-byte RC4 key embedded at &DAT_00433820, used to decrypt the embedded Stage-2 PE at &DAT_00436a70. This is the loader-side counterpart to MALW_Rhadamanthys_CustomerCBCXOR_IV (which anchors on the Stage-2); cross-rebuild stability of this key is inferred rather than confirmed."
        license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-79-137-192-3-20260515-detections/"
        date = "2026-05-15"
        hash1 = "5c38a5dd3703b1c4b8c2466b18ce9f4c45ef4c9bf6c3096bee8b24d20ecd247a"
        family = "Rhadamanthys"
        cluster = "C"
        threat_class = "loader,customer_specific"
        id = "acb71818-6c54-56e7-a401-bd0151e8e4ff"

    strings:
        $b_rc4_key = { e0 80 25 40 d0 2d 0f ea eb 27 7d c7 20 e3 90 b0 6d fd 64 d8 f8 10 4d 95 81 e7 88 e5 12 71 5b }

    condition:
        uint16(0) == 0x5A4D
        and filesize < 5MB
        and $b_rc4_key
}
```

#### Tofsee 2023 Build Static Tradecraft (Co-Tenant Reference)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1027.001 (Binary Padding), T1027.005 (Indicator Removal from Tools), T1497 (Virtualization/Sandbox Evasion), T1543.003 (Windows Service), T1071.003 (Mail Protocols), T1090.002 (External Proxy)
**Confidence:** MODERATE
**Rationale:** Tofsee is an unrelated spam-botnet family that co-tenants `79.137.192.3` — it is not part of the Rhadamanthys/BellaMain/Inkognito campaign investigated here, retained as an analyst reference. The rule is explicitly family-bound (not campaign-bound): a broad structural + behavioral combination (anomalous WinHTTP import shape, injection API triad, rare-API bucket, word-salad version metadata) intended for hunting sweeps against this 2023 Tofsee build lineage, not for blocking actions.
**False Positives:** Some legitimate heavily-packed or obfuscated software with similarly unusual import shapes could coincidentally match individual clauses; the full multi-clause combination is narrow but not goodware-validated to zero FP.
**Deployment:** Endpoint AV/EDR file scan; hunting sweep for this specific Tofsee build lineage.

```yara
import "pe"

rule Tofsee_Bloater_2023_StaticTradecraft
{
    meta:
        description = "Detects Tofsee-family droppers exhibiting the 2023 build's anti-AV bloat + dynamic-API-resolution tradecraft. Triggers on PE-structure anomalies (huge virtual .data, single static WinHTTP import) + word-salad version metadata; family-bound, not campaign-bound. Co-tenant on 79.137.192.3 — operationally separate from BellaMain/Inkognito/Rhadamanthys clusters."
        license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-79-137-192-3-20260515-detections/"
        date = "2026-05-08"
        hash1 = "2910a52e0934c8f1cf247cf88d1fce010f2e52dfb1cf2f64ebf3dc53df4ef865"
        family = "Tofsee"
        cluster = "Co-tenant (separate from Clusters A/B/C)"
        threat_class = "spam_botnet,downloader,injector"
        id = "6dec01d5-e225-52b6-b3a1-c28325a70e99"

    strings:
        $winhttp_only_writedata = "WinHttpWriteData" ascii

        $rare_api_1 = "GetConsoleAliasA" ascii
        $rare_api_2 = "GetConsoleAliasExesLengthW" ascii
        $rare_api_3 = "FindFirstVolumeMountPointA" ascii
        $rare_api_4 = "GetNumaHighestNodeNumber" ascii
        $rare_api_5 = "DeleteTimerQueueTimer" ascii
        $rare_api_6 = "GlobalFindAtomA" ascii
        $rare_api_7 = "SetCalendarInfoA" ascii
        $rare_api_8 = "CreateHardLinkW" ascii

        $inject_1 = "VirtualAllocEx" ascii
        $inject_2 = "WriteProcessMemory" ascii
        $inject_3 = "GetThreadContext" ascii

        $wordsalad_meta_marker_1 = "Hole" ascii wide
        $wordsalad_meta_marker_2 = "Bill" ascii wide
        $wordsalad_meta_marker_3 = "Fire" ascii wide
        $wordsalad_meta_marker_4 = "Selfie" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and pe.is_pe
        and pe.machine == pe.MACHINE_I386
        and pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI
        and pe.number_of_sections >= 4
        and $winhttp_only_writedata
        and pe.imports("WINHTTP.dll", "WinHttpWriteData")
        and not pe.imports("WINHTTP.dll", "WinHttpOpen")
        and not pe.imports("WINHTTP.dll", "WinHttpConnect")
        and not pe.imports("WINHTTP.dll", "WinHttpOpenRequest")
        and for any i in (0 .. pe.number_of_sections - 1) : (
            pe.sections[i].name == ".data" and
            pe.sections[i].virtual_size > pe.sections[i].raw_data_size * 100
        )
        and all of ($inject_*)
        and 5 of ($rare_api_*)
        and 2 of ($wordsalad_meta_marker_*)
}
```

---

## Sigma Rules

### Detection Rules

#### Rhadamanthys SibCode Software Registry Key Marker

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1112 (Modify Registry)
**Confidence:** HIGH
**Rationale:** Confirmed across four independent sibling Stage-2 sandbox runs (this sample plus three others), not a single-sample artifact — a family-wide execution marker with no known benign collision. Tags verified against the current ATT&CK technique-tactic data via `sigma check`: T1112 (Modify Registry) requires its `attack.persistence` and/or `attack.defense-impairment` tactic tag(s) present — both are carried below, matching the original tagging.
**False Positives:** None known — the `SibCode\sn` key path has no documented benign software using it.
**Blind Spots:** A future build that writes this marker under a different registry path would evade; this is a footprint/marker, not a blocking control on its own.
**Validation:** Trigger execution of a Rhadamanthys Stage-2 sample — the registry write must match; unrelated software's registry activity must NOT fire.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (registry telemetry).

```yaml
title: Rhadamanthys SibCode Software Registry Key Persistence Marker
id: a4f1e2c8-3d7b-4f9a-9c2e-2c5e7f8d9a01
status: experimental
description: >-
  Detects creation or modification of HKU\<SID>\Software\SibCode\sn registry value, a family-stable
  Rhadamanthys execution marker observed across multiple sibling Stage-2 sandbox runs (Dapato dropper
  variants e827d13c, 457aecd8, bc9fe5e9). Per-instance value is a license/build timestamp from the MaaS
  panel. No known benign software writes this key.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-79-137-192-3-20260515-detections/
author: The Hunters Ledger
date: 2026-05-15
tags:
    - attack.persistence
    - attack.defense-impairment
    - attack.t1112
    - detection.emerging-threats
logsource:
    product: windows
    category: registry_set
detection:
    selection:
        TargetObject|contains: '\Software\SibCode\sn'
    condition: selection
falsepositives:
    - >-
      Unlikely. The SibCode\sn key path has no documented benign software using it.
level: high
```

#### Rhadamanthys EAX-Redirect Process Hollowing Into InstallUtil.exe

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1218.008 (System Binary Proxy Execution: InstallUtil), T1055.012 (Process Hollowing)
**Confidence:** HIGH
**Rationale:** The LOLBin-abuse pattern (InstallUtil.exe spawned from a suspicious user-writable parent path) is a durable technique signal independent of any specific sample — it survives recompiles since it describes how the malware launches, not a malware-specific string. The explicit filter for common legitimate developer/installer parents (msiexec, devenv, MSBuild) keeps precision high.
**False Positives:** Legitimate developer or installer workflows that invoke InstallUtil.exe from temp directories.
**Blind Spots:** A future build that hollows a different LOLBin, or launches InstallUtil.exe from a parent path not in the suspicious-path list, would evade.
**Validation:** Trigger the loader's hollowing routine — the child-process creation must match; msiexec/devenv/MSBuild-spawned InstallUtil.exe must NOT fire.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (process-creation telemetry).

```yaml
title: Rhadamanthys EAX-Redirect Process Hollowing Into InstallUtil.exe
id: b5e2f3d9-4e8c-5a0b-ad3f-3d6f8a9b0c12
status: experimental
description: >-
  Detects suspicious creation of InstallUtil.exe child process from a non-typical parent (loader binary
  in user-writable location), a precursor to the EAX-redirect process hollowing technique used by this
  Rhadamanthys customer's loader. EAX-redirect uses W^X memory transitions (RW then RX, never RWX) and
  rewrites the entry point pointer in EAX rather than the classic SetThreadContext approach. Pair with
  network telemetry to InstallUtil.exe outbound connections for high-confidence verdict.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-79-137-192-3-20260515-detections/
author: The Hunters Ledger
date: 2026-05-15
tags:
    - attack.stealth
    - attack.privilege-escalation
    - attack.t1218.008
    - attack.t1055.012
    - detection.emerging-threats
logsource:
    product: windows
    category: process_creation
detection:
    selection_image:
        Image|endswith: '\InstallUtil.exe'
        Image|contains: '\Microsoft.NET\Framework'
    selection_parent_suspicious:
        ParentImage|contains:
            - '\AppData\Local\Temp\'
            - '\AppData\Roaming\'
            - '\Users\Public\'
            - '\ProgramData\'
    filter_legit_parent:
        ParentImage|endswith:
            - '\msiexec.exe'
            - '\devenv.exe'
            - '\MSBuild.exe'
    condition: selection_image and selection_parent_suspicious and not filter_legit_parent
falsepositives:
    - >-
      Legitimate developer or installer workflows that invoke InstallUtil.exe from temp
      directories.
level: high
```

#### BellaMain PhaaS Panel HTTP Request Patterns

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH
**Rationale:** Corrected from the original: the rule's condition OR'd a durable URI-path selector against a pure IP/domain host-match branch (`cs-host|contains: 79.137.192.3 or cryptone.bot`). Per the tiering rubric, a hard-coded IP/domain branch with no behavioral qualifier is an IOC-feed entry, not rule logic — both values are already in the feed. The host-match branch has been removed; the surviving rule is the bespoke BellaMain PHP admin-endpoint path list, which is host-independent and survives the panel being redeployed on new infrastructure.
**False Positives:** Unlikely — the BellaMain panel PHP entry-point paths are bespoke and unlikely to collide with legitimate proxy/web traffic.
**Blind Spots:** A future BellaMain build that renames its PHP entry points would evade; does not cover the panel if deployed with a different URL structure.
**Validation:** Trigger a request to one of the listed BellaMain PHP paths — must match; unrelated proxy traffic must NOT fire.
**Deployment:** Web/proxy log monitoring, egress-proxy alerting.

```yaml
title: BellaMain PhaaS Panel HTTP Request Patterns
id: c7d4f0e1-5fab-6c1d-be4f-4e7fab0c1d23
status: experimental
description: >-
  Detects HTTP requests to BellaMain panel administrative endpoints. The panel exposes a small fixed
  set of PHP entry points (signin.php, dashboard.php, post.php, manager.php, cookie.php) that should
  not appear on legitimate web traffic from internal endpoints. This selector is host-independent and
  survives the panel being redeployed on new infrastructure. Pair with the IOC feed's blocklist for
  79.137.192.3 and cryptone.bot for additional coverage of this specific deployment.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-79-137-192-3-20260515-detections/
author: The Hunters Ledger
date: 2026-05-15
tags:
    - attack.command-and-control
    - attack.t1071.001
    - detection.emerging-threats
logsource:
    category: proxy
detection:
    selection_uri:
        cs-uri-stem|contains:
            - '/BellaMain/signin.php'
            - '/BellaMain/dashboard.php'
            - '/BellaMain/database/post.php'
            - '/BellaMain/manager.php'
            - '/BellaMain/database/cookie.php'
    condition: selection_uri
falsepositives:
    - >-
      Unlikely — the BellaMain panel PHP entry-point paths are bespoke and unlikely to
      collide with legitimate proxy/web traffic.
level: high
```

---

## Suricata Signatures

### Detection Rules

#### Rhadamanthys Customer Panel-ID URL Pattern

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH
**Rationale:** The 24-hex-character customer panel ID in the beacon URL path was observed stable across two beacons roughly 40 days apart (2026-04-03 and 2026-05-13) — real cross-time evidence of durability, and it survives the C2 moving to new IP/domain infrastructure since it keys on a URL path token, not a host match. This is the strongest network-layer fleet-enumeration pivot in the package.
**False Positives:** None known — a 24-hex-character path token matching this exact value has negligible collision risk with unrelated HTTP traffic.
**Blind Spots:** Evaded if the operator's MaaS panel rotates the panel ID; misses non-HTTP or differently-structured beacon URL schemes (an alternate URL prefix was observed in one sibling sample).
**Validation:** Replay a PCAP of a Rhadamanthys beacon carrying this panel ID in the URI — must alert; unrelated HTTP traffic must NOT.
**Deployment:** Network IDS/IPS at perimeter and internal segmentation points.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL OpenDirectory-79.137.192.3 Rhadamanthys MaaS-Customer Panel ID URL Pattern (C2 Transport Indicator)"; flow:established,to_server; http.uri; content:"/e6d92c6b5b2a03bee7fbab40/"; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000003; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-15, reference https://the-hunters-ledger.com/hunting-detections/opendirectory-79-137-192-3-20260515-detections/;)
```

**JARM detection note:** JARM fingerprint `2ad2ad0002ad2ad00042d42d00000007e6e35b6c9fce6eec13762f8506fe09` (current 79.133.180.168:3394 Samsung-cert period) and `2ad2ad0002ad2ad00042d42d00000000f78d2dc0ce6e5bbc5b8149a4872356` (79.137.192.3 Apache-on-Win64 stack) are useful for broader Rhadamanthys-customer C2 fingerprinting and BellaMain-style staging server identification respectively. JARM matching is best implemented at the network-monitoring layer (Zeek, Arkime, custom JARM scanners) rather than as a Suricata rule.

---

## Coverage Gaps

The following areas were considered for detection coverage but excluded — defenders should be aware of what is NOT covered:

**1. Anti-VM and anti-debug primitives in Stage-2.** Rhadamanthys Stage-2 implements timing-based anti-analysis (14-second sleep with denormal-sentinel checks), analyzer-process blocklist, and 0xCC anti-forensic memory scrubbing. These primitives are not converted to detection rules because they generate false positives on legitimate security tools (debuggers, EDR sensors, sandbox helpers) that exhibit similar behaviors.

**2. Rhadamanthys plugin module fingerprints.** The Stage-2 supports modular plugins (XS1/XS2 browser/wallet/MFA harvesters) loaded dynamically. The plugin module binaries themselves were not extracted from this customer's infrastructure — detection coverage of plugin-specific behaviors requires plugin samples.

**3. Per-victim build randomization.** Rhadamanthys MaaS rebuilds Stage-1 loaders per-customer with rotating obfuscation (junk byte insertions, opcode reordering). Bytecode-pattern-based detection of the loader is therefore brittle. The rules above anchor on operator-specific strings and customer-specific cipher material, which are stable across rebuilds for the SAME customer but will not catch other customers.

**4. The inner Q3VM bytecode programs.** Each Q3VM bytecode entry inside Stage-2 implements a distinct stealing primitive (browser, wallet, etc.). Bytecode-level detection is not portable — customer rebuilds rotate the operator-permuted opcode table. The `MALW_Rhadamanthys_Q3VMBytecodeModifiedMagic` rule above catches the magic + operator anchor, which is stable; the bytecode programs themselves are not covered.

**5. Aeza ASN-wide blocking.** AS216246 / AS204603 / AS210644 (Aeza Group) host both malicious tenants (BellaMain, Inkognito) and legitimate Russian-language services. ASN-level blocking is too broad for most defenders — coverage is provided at the IP and domain level instead.

**6. CryptOne fake exchange detection.** The cryptone.bot domain is Cloudflare-fronted and the origin IP is hidden. DNS query detection is provided via the IOC feed but the exchange page itself appears legitimate to most fraud-detection heuristics — defenders relying on URL reputation feeds may not see this domain flagged for some time.

**7. Stage-1 pre-execution detection.** This customer's loader uses MSVC2019 + standard libraries with no obvious packer signature. Pre-execution AV detection relies on cloud-side hash matching once the file has been seen and submitted. The YARA rules above are best deployed in EDR memory scanning or post-extraction hunting, not as pre-execution AV signatures.

**8. Atomics routed to the IOC feed (6 of the original package's 18 rules).** The Rhadamanthys C2 IP `79.133.180.168:3394` (a direct TCP match and a second rule using it as a hardcoded TLS SNI content match), the BellaMain staging IP `79.137.192.3` (an HTTP Host match), the 17-domain Inkognito brand-portfolio list (a Sigma `dns` selection and a Suricata PCRE with no content prefilter), and the Tofsee co-tenant's SHA256/imphash/PDB-path combination all keyed solely on a hard-coded literal with no behavior surviving its removal — per the tiering rubric's routing test, these are IOC-feed entries, not rules. All values are in [`opendirectory-79-137-192-3-20260515-iocs.json`](/ioc-feeds/opendirectory-79-137-192-3-20260515-iocs.json); three domains (`akredup.ru`, `divar-irantop.shop`, `catnpv.xyz`) were referenced only in the original rules and have been added to the feed's domain list.

**9. Cluster B (Inkognito) has no surviving standalone rule.** Every original rule scoped to Cluster B — the Sigma DNS-query selection and the Suricata PCRE — was a pure domain-list match with no corroborating behavioral or structural qualifier. Unlike Clusters A and C, no bespoke code artifact, panel-side string, or protocol-level signature was captured for the Inkognito brand portfolio (VPN/phishing/CryptOne) in the underlying analysis. Coverage for this cluster is therefore IOC-feed-only (17 domains, BLOCK action). **What would enable a rule:** a captured artifact from the Inkognito operator's own infrastructure — a distinctive backend API response shape, a shared JS/config fingerprint (the `index-CoeWw2zM.js` frontend bundle hash is already in the feed as a file-hash IOC but was not analyzed for a portable code-level YARA signature), or a consistent non-domain-dependent URL/header pattern.

**10. Rhadamanthys customer-specific cipher material (CBC-XOR IV, RC4 key) tiered as Hunting, not Detection.** Both are single-anchor byte-pattern matches with near-zero false-positive risk, but each was observed in exactly one sample from this customer — cross-rebuild stability is asserted in the original analysis but not confirmed by a second observed build carrying the same constant. They are retained as Hunting-tier pivot/triage rules rather than Detection-tier alerts. **What would raise confidence:** a second sample from the same MaaS customer (a different panel-ID beacon or a later-dated build) carrying the identical IV or RC4 key.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
