---
title: "Detection Rules — Multi-Cluster Open-Directory 79.137.192.3 (Rhadamanthys MaaS / BellaMain PhaaS / Inkognito)"
date: '2026-05-15'
layout: post
permalink: /hunting-detections/opendirectory-79-137-192-3-20260515-detections/
thumbnail: /assets/images/cards/opendirectory-79-137-192-3-20260515.png
hide: true
---

**Campaign:** OpenDirectory-MultiCluster-Rhadamanthys-BellaMain-Inkognito-79.137.192.3<br>
**Date:** 2026-05-15
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/opendirectory-79-137-192-3-20260515/

---

## Detection Coverage Summary

| Rule Type | Count | MITRE Techniques Covered | Overall FP Risk |
|---|---|---|---|
| YARA | 9 | T1027, T1027.002, T1027.013, T1140, T1055.012, T1071.001, T1102 | LOW–MEDIUM |
| Sigma | 4 | T1218.008, T1112, T1055.012, T1566.002 | LOW–MEDIUM |
| Suricata | 5 | T1071.001, T1573.001, T1573.002, T1102, T1568 | LOW |

**Three detection clusters covered:**
- **Cluster C — Rhadamanthys MaaS-customer** (Tier 1 — primary): 6 YARA + 2 Sigma + 3 Suricata
- **Cluster A — BellaMain PhaaS** (Tier 2): 1 YARA + 1 Sigma + 1 Suricata
- **Cluster B — Inkognito** (Tier 3): 0 YARA + 1 Sigma + 1 Suricata
- **Tofsee co-tenant** (Tier 4): 2 YARA (analyst-authored reference, retained)

## Multi-Family Organization

This detection package targets three operationally-separate operators that shared the multi-tenant Aeza bulletproof IP `79.137.192.3`. Cross-cluster linkage is **LOW** — co-residency on this IP is NOT operationally diagnostic. Detections are organized by cluster so defenders can apply only the rules relevant to their environment:

| Cluster | Family / Operator | Defender Priority |
|---|---|---|
| **C** | Rhadamanthys MaaS-customer (loader + Stage-2) | **PRIMARY** — broadly applicable, Tier-1 commodity stealer |
| A | BellaMain Turkish PhaaS panel | Regional (Turkish marketplace targets) |
| B | Inkognito brand portfolio (VPN/phishing/CryptOne) | Regional (Russian-speaking + EU phishing) |
| (Co-tenant) | Tofsee spam-botnet | General — family-stable rules, not campaign-bound |

## YARA Rules

The following rules cover Rhadamanthys customer-specific fingerprints (Cluster C — highest defender value), BellaMain panel artifacts (Cluster A), and the Tofsee co-tenant family (analyst-authored reference rules retained verbatim).

```yara
import "pe"
import "hash"

rule MALW_Rhadamanthys_FrontbSection
{
    meta:
        description = "Detects Rhadamanthys Stage-2 binaries by the family-stable .frontb PE section name (a pre-allocated empty runtime buffer for the decrypted Stage-2 payload). Anchored with a Roland decoy string from the Stage-2 plaintext to reduce false positives."
        author = "The Hunters Ledger"
        date = "2026-05-15"
        family = "Rhadamanthys"
        cluster = "C"
        threat_class = "infostealer,maas"
        confidence = "HIGH"
        mitre_attack = "T1027,T1140"
        reference_sample_sha256 = "804f45487c1cda5b69c743f9eb691a12fe0fdcf0d3a9f32003898f1e3836af50"
        reference_url = "https://the-hunters-ledger.com/reports/opendirectory-79-137-192-3-20260515/"
        license = "CC BY 4.0"

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

rule MALW_Rhadamanthys_Stage2_ImportSurface
{
    meta:
        description = "Detects Rhadamanthys Stage-2 binaries by the distinctive minimal-import surface: USER32 GetDC/ReleaseDC/GetSystemMetrics + ADVAPI32 RegQueryValueExW combined with several distinctive GDI32 decoy imports. Stage-2 payloads avoid common crypto/network library imports — the absence of WS2_32 and CRYPT32 raises specificity."
        author = "The Hunters Ledger"
        date = "2026-05-15"
        family = "Rhadamanthys"
        cluster = "C"
        threat_class = "infostealer,maas"
        confidence = "MEDIUM"
        mitre_attack = "T1027.002,T1140"
        reference_sample_sha256 = "804f45487c1cda5b69c743f9eb691a12fe0fdcf0d3a9f32003898f1e3836af50"
        reference_url = "https://the-hunters-ledger.com/reports/opendirectory-79-137-192-3-20260515/"
        license = "CC BY 4.0"
        fp_risk = "MEDIUM — minimal-import surface alone could match unrelated GDI-heavy applications; pair with other Rhadamanthys rules for high-confidence verdict."

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

rule MALW_Rhadamanthys_Q3VMBytecodeModifiedMagic
{
    meta:
        description = "Detects Rhadamanthys Stage-2 binaries containing the operator-modified Q3VM derivative bytecode magic 0x14744214 (vs stock Q3VM 0x12721444). Anchored with a Roland decoy string co-condition because a 4-byte magic alone has unacceptable false-positive risk."
        author = "The Hunters Ledger"
        date = "2026-05-15"
        family = "Rhadamanthys"
        cluster = "C"
        threat_class = "infostealer,maas,vm_obfuscation"
        confidence = "HIGH"
        mitre_attack = "T1027.013"
        reference_sample_sha256 = "804f45487c1cda5b69c743f9eb691a12fe0fdcf0d3a9f32003898f1e3836af50"
        reference_url = "https://the-hunters-ledger.com/reports/opendirectory-79-137-192-3-20260515/"
        license = "CC BY 4.0"

    strings:
        $b_magic_le = { 14 42 74 14 }
        $s_roland = "Roland" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 2MB
        and $b_magic_le
        and $s_roland
}

rule MALW_Rhadamanthys_CustomerCBCXOR_IV
{
    meta:
        description = "Detects this specific Rhadamanthys MaaS customer's Stage-2 binaries by the customer-specific 16-byte CBC-XOR IV embedded in .rdata at offset 0x0001c434. Different MaaS customers use different IVs — this is the highest-value per-customer fingerprint in the package."
        author = "The Hunters Ledger"
        date = "2026-05-15"
        family = "Rhadamanthys"
        cluster = "C"
        threat_class = "infostealer,maas,customer_specific"
        confidence = "HIGH"
        mitre_attack = "T1027,T1140"
        reference_sample_sha256 = "804f45487c1cda5b69c743f9eb691a12fe0fdcf0d3a9f32003898f1e3836af50"
        reference_url = "https://the-hunters-ledger.com/reports/opendirectory-79-137-192-3-20260515/"
        license = "CC BY 4.0"

    strings:
        $b_iv = { f6 35 8d 79 df 69 c5 77 d9 dc e6 bb 77 fa 4f a7 }

    condition:
        uint16(0) == 0x5A4D
        and filesize < 2MB
        and $b_iv
}

rule MALW_Rhadamanthys_LoaderRC4Key
{
    meta:
        description = "Detects this specific Rhadamanthys customer's Stage-1 loader by the 31-byte RC4 key embedded at &DAT_00433820, used to decrypt the embedded Stage-2 PE at &DAT_00436a70. This is the loader-side counterpart to MALW_Rhadamanthys_CustomerCBCXOR_IV (which anchors on the Stage-2)."
        author = "The Hunters Ledger"
        date = "2026-05-15"
        family = "Rhadamanthys"
        cluster = "C"
        threat_class = "loader,customer_specific"
        confidence = "HIGH"
        mitre_attack = "T1140,T1027.002"
        reference_sample_sha256 = "5c38a5dd3703b1c4b8c2466b18ce9f4c45ef4c9bf6c3096bee8b24d20ecd247a"
        reference_url = "https://the-hunters-ledger.com/reports/opendirectory-79-137-192-3-20260515/"
        license = "CC BY 4.0"

    strings:
        $b_rc4_key = { e0 80 25 40 d0 2d 0f ea eb 27 7d c7 20 e3 90 b0 6d fd 64 d8 f8 10 4d 95 81 e7 88 e5 12 71 5b }

    condition:
        uint16(0) == 0x5A4D
        and filesize < 5MB
        and $b_rc4_key
}

rule MALW_Rhadamanthys_OperatorLoaderStrings
{
    meta:
        description = "Detects this Rhadamanthys customer's Stage-1 loader by operator-specific build/campaign ID strings observed in std::cout output and operator credential strings. Requires 2-of-N matches to reduce false positives on any single string appearing in unrelated content."
        author = "The Hunters Ledger"
        date = "2026-05-15"
        family = "Rhadamanthys"
        cluster = "C"
        threat_class = "loader,operator_specific"
        confidence = "HIGH"
        mitre_attack = "T1027"
        reference_sample_sha256 = "5c38a5dd3703b1c4b8c2466b18ce9f4c45ef4c9bf6c3096bee8b24d20ecd247a"
        reference_url = "https://the-hunters-ledger.com/reports/opendirectory-79-137-192-3-20260515/"
        license = "CC BY 4.0"

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

rule MALW_BellaMain_PHPPanel
{
    meta:
        description = "Detects BellaMain Turkish PhaaS panel PHP source files by the Wadanz developer pseudonym function names (sifreleWadanz / sifrecozWadanz session encryption helpers) and the obfuscated admin directory name. Operator alias @AresRS34 alone is NOT sufficient to trigger — it's paired with a BellaMain-specific anchor to prevent false positives on threat intelligence reports about this actor."
        author = "The Hunters Ledger"
        date = "2026-05-15"
        family = "BellaMain"
        cluster = "A"
        threat_class = "phaas,panel"
        confidence = "HIGH"
        mitre_attack = "T1071.001,T1102"
        reference_sample_sha256 = "f791fae41cdd3f141221d1783ed4779c839de7fc834ff4fc80a5d7f74b11ff88"
        reference_url = "https://the-hunters-ledger.com/reports/opendirectory-79-137-192-3-20260515/"
        license = "CC BY 4.0"

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

rule Tofsee_Bloater_2023_StaticTradecraft
{
    meta:
        description = "Detects Tofsee-family droppers exhibiting the 2023 build's anti-AV bloat + dynamic-API-resolution tradecraft. Triggers on PE-structure anomalies (huge virtual .data, single static WinHTTP import) + word-salad version metadata; family-bound, not campaign-bound. Co-tenant on 79.137.192.3 — operationally separate from BellaMain/Inkognito/Rhadamanthys clusters."
        author = "The Hunters Ledger"
        date = "2026-05-08"
        family = "Tofsee"
        cluster = "Co-tenant (separate from Clusters A/B/C)"
        threat_class = "spam_botnet,downloader,injector"
        confidence = "MODERATE"
        mitre_attack = "T1027.001,T1027.005,T1497,T1543.003,T1071.003,T1090.002"
        reference_sample_sha256 = "2910a52e0934c8f1cf247cf88d1fce010f2e52dfb1cf2f64ebf3dc53df4ef865"
        reference_url = "https://the-hunters-ledger.com/reports/opendirectory-79-137-192-3-20260515/"
        license = "CC BY 4.0"

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

rule Tofsee_Cotenant_79_137_192_3_April2023_Build
{
    meta:
        description = "Tight, build-specific detection for the Tofsee variant observed as the 4th historical PE on 79.137.192.3 during the BellaMain/Inkognito investigation. Anchored on the operator's PDB project name pattern + reference SHA256 + imphash."
        author = "The Hunters Ledger"
        date = "2026-05-08"
        family = "Tofsee"
        cluster = "Co-tenant (separate from Clusters A/B/C)"
        threat_class = "spam_botnet"
        confidence = "HIGH"
        reference_sample_sha256 = "2910a52e0934c8f1cf247cf88d1fce010f2e52dfb1cf2f64ebf3dc53df4ef865"
        reference_imphash = "a41092e5e40602533850a4d1b2ecd182"
        reference_pdb = "C:\\sena\\tawateje_lenicetedev68.pdb"
        license = "CC BY 4.0"

    strings:
        $pdb_full = "C:\\sena\\tawateje_lenicetedev68.pdb" ascii
        $pdb_root = "C:\\sena\\" ascii
        $pdb_project_prefix = "tawateje_" ascii

    condition:
        uint16(0) == 0x5A4D
        and pe.is_pe
        and (
            hash.sha256(0, filesize) == "2910a52e0934c8f1cf247cf88d1fce010f2e52dfb1cf2f64ebf3dc53df4ef865"
            or pe.imphash() == "a41092e5e40602533850a4d1b2ecd182"
            or any of ($pdb_*)
        )
}
```

## Sigma Rules

The following rules cover Rhadamanthys host-side persistence and process-injection telemetry, BellaMain panel HTTP access, and Inkognito brand DNS queries. Use SigmaHQ-compliant YAML; folded `>-` syntax is used for fields whose text contains `: ` to ensure parser compatibility.

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
  - https://the-hunters-ledger.com/reports/opendirectory-79-137-192-3-20260515/
author: The Hunters Ledger
date: 2026/05/15
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
  - https://the-hunters-ledger.com/reports/opendirectory-79-137-192-3-20260515/
author: The Hunters Ledger
date: 2026/05/15
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
    Legitimate developer or installer workflows that invoke InstallUtil.exe from temp directories. Tune
    by allow-listing known developer parent processes in your environment.
level: high
```

```yaml
title: BellaMain PhaaS Panel HTTP Request Patterns
id: c7d4f0e1-5fab-6c1d-be4f-4e7fab0c1d23
status: experimental
description: >-
  Detects HTTP requests to BellaMain panel administrative endpoints. The panel exposes a small fixed
  set of PHP entry points (signin.php, dashboard.php, post.php, manager.php) that should not appear
  on legitimate web traffic from internal endpoints. Pair with network egress to 79.137.192.3 or
  cryptone.bot for high-confidence verdict.
references:
  - https://the-hunters-ledger.com/reports/opendirectory-79-137-192-3-20260515/
author: The Hunters Ledger
date: 2026/05/15
tags:
  - attack.command-and-control
  - attack.initial-access
  - attack.t1071.001
  - attack.t1566.002
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
  selection_dst:
    cs-host|contains:
      - '79.137.192.3'
      - 'cryptone.bot'
  condition: selection_uri or selection_dst
falsepositives:
  - >-
    Unlikely for the URI patterns. The host-based detection on cryptone.bot may fire on
    intentional research traffic from analyst sandboxes.
level: high
```

```yaml
title: Inkognito Brand Portfolio DNS Queries
id: d8e5fb12-6fbc-7d2e-cf50-5f8fbc1d2e34
status: experimental
description: >-
  Detects DNS queries for any domain in the Inkognito brand portfolio (INK VPN, INK Lens, CryptOne,
  Bikaf, Outline VPN deployments observed in operator infrastructure). Includes both customer-facing
  brand domains and operator back-office infrastructure. Some domains may be retired but are retained
  for historical hunting.
references:
  - https://the-hunters-ledger.com/reports/opendirectory-79-137-192-3-20260515/
author: The Hunters Ledger
date: 2026/05/15
tags:
  - attack.command-and-control
  - attack.t1071.004
  - detection.emerging-threats
logsource:
  category: dns
detection:
  selection:
    QueryName:
      - 'inkconnect.ru'
      - 'inklens.ru'
      - 'inklens.co.uk'
      - 'fi1.inklens.co.uk'
      - 'marzban.inklens.co.uk'
      - 'bikaf.ru'
      - 'unloki.ru'
      - 'bigass.monster'
      - 'vetcorbeanca.eu'
      - 'vagtec.eu'
      - 'petkovalegal.eu'
      - 'akredup.ru'
      - 'divar-irantop.shop'
      - 'catnpv.xyz'
      - 'evotoptan.com'
      - 'cryptone.bot'
      - '00000xtrading.ru'
  condition: selection
falsepositives:
  - >-
    Unlikely. These are operator-controlled domains with no known legitimate business use.
level: medium
```

## Suricata Signatures

The following signatures cover Rhadamanthys customer C2 traffic, the panel-ID URL pattern, JARM TLS fingerprinting, BellaMain panel access, and Inkognito brand DNS queries. SID range `1000001-1099999` is used per Suricata convention for free-use signatures.

```
# Rhadamanthys MaaS-Customer C2 — direct IP/port match
alert tcp $HOME_NET any -> 79.133.180.168 3394 (msg:"HUNTERS_LEDGER Rhadamanthys MaaS-Customer C2 79.133.180.168:3394"; \
    flow:to_server,established; \
    classtype:trojan-activity; \
    reference:url,the-hunters-ledger.com/reports/opendirectory-79-137-192-3-20260515/; \
    sid:1000001; rev:1;)

# Rhadamanthys MaaS-Customer C2 — customer panel ID URL pattern
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"HUNTERS_LEDGER Rhadamanthys MaaS-Customer Panel ID URL Pattern"; \
    flow:to_server,established; \
    tls.sni; content:"79.133.180.168"; \
    reference:url,the-hunters-ledger.com/reports/opendirectory-79-137-192-3-20260515/; \
    classtype:trojan-activity; sid:1000002; rev:1;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HUNTERS_LEDGER Rhadamanthys MaaS-Customer Panel URL Path"; \
    flow:to_server,established; \
    http.uri; content:"/e6d92c6b5b2a03bee7fbab40/"; \
    reference:url,the-hunters-ledger.com/reports/opendirectory-79-137-192-3-20260515/; \
    classtype:trojan-activity; sid:1000003; rev:1;)

# BellaMain PhaaS staging IP — direct match
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HUNTERS_LEDGER BellaMain PhaaS Panel Access — 79.137.192.3 or cryptone.bot"; \
    flow:to_server,established; \
    http.host; content:"79.137.192.3"; \
    reference:url,the-hunters-ledger.com/reports/opendirectory-79-137-192-3-20260515/; \
    classtype:trojan-activity; sid:1000004; rev:1;)

# Inkognito brand portfolio — DNS queries
alert dns $HOME_NET any -> any any (msg:"HUNTERS_LEDGER Inkognito Brand Portfolio DNS Query"; \
    dns.query; \
    pcre:"/(inkconnect\.ru|inklens\.(ru|co\.uk)|bikaf\.ru|unloki\.ru|bigass\.monster|vetcorbeanca\.eu|vagtec\.eu|petkovalegal\.eu|akredup\.ru|divar-irantop\.shop|catnpv\.xyz|evotoptan\.com|cryptone\.bot|00000xtrading\.ru)$/i"; \
    reference:url,the-hunters-ledger.com/reports/opendirectory-79-137-192-3-20260515/; \
    classtype:trojan-activity; sid:1000005; rev:1;)
```

**JARM detection note:** JARM fingerprint `2ad2ad0002ad2ad00042d42d00000007e6e35b6c9fce6eec13762f8506fe09` (current 79.133.180.168:3394 Samsung-cert period) and `2ad2ad0002ad2ad00042d42d00000000f78d2dc0ce6e5bbc5b8149a4872356` (79.137.192.3 Apache-on-Win64 stack) are useful for broader Rhadamanthys-customer C2 fingerprinting and BellaMain-style staging server identification respectively. JARM matching is best implemented at the network-monitoring layer (Zeek, Arkime, custom JARM scanners) rather than as a Suricata rule.

## Coverage Gaps

The following areas were considered for detection coverage but excluded — defenders should be aware of what is NOT covered:

**1. Anti-VM and anti-debug primitives in Stage-2.** Rhadamanthys Stage-2 implements timing-based anti-analysis (14-second sleep with denormal-sentinel checks), analyzer-process blocklist, and 0xCC anti-forensic memory scrubbing. These primitives are not converted to detection rules because they generate false positives on legitimate security tools (debuggers, EDR sensors, sandbox helpers) that exhibit similar behaviors.

**2. Rhadamanthys plugin module fingerprints.** The Stage-2 supports modular plugins (XS1/XS2 browser/wallet/MFA harvesters) loaded dynamically. The plugin module binaries themselves were not extracted from this customer's infrastructure — detection coverage of plugin-specific behaviors requires plugin samples.

**3. Per-victim build randomization.** Rhadamanthys MaaS rebuilds Stage-1 loaders per-customer with rotating obfuscation (junk byte insertions, opcode reordering). Bytecode-pattern-based detection of the loader is therefore brittle. The rules above anchor on operator-specific strings and customer-specific cipher material, which are stable across rebuilds for the SAME customer but will not catch other customers.

**4. The inner Q3VM bytecode programs.** Each Q3VM bytecode entry inside Stage-2 implements a distinct stealing primitive (browser, wallet, etc.). Bytecode-level detection is not portable — customer rebuilds rotate the operator-permuted opcode table. The `MALW_Rhadamanthys_Q3VMBytecodeModifiedMagic` rule above catches the magic + operator anchor, which is stable; the bytecode programs themselves are not covered.

**5. Aeza ASN-wide blocking.** AS216246 / AS204603 / AS210644 (Aeza Group) host both malicious tenants (BellaMain, Inkognito) and legitimate Russian-language services. ASN-level blocking is too broad for most defenders — coverage is provided at the IP and domain level instead.

**6. CryptOne fake exchange detection.** The cryptone.bot domain is Cloudflare-fronted and the origin IP is hidden. DNS query detection is provided (Sigma + Suricata) but the exchange page itself appears legitimate to most fraud-detection heuristics — defenders relying on URL reputation feeds may not see this domain flagged for some time.

**7. Stage-1 pre-execution detection.** This customer's loader uses MSVC2019 + standard libraries with no obvious packer signature. Pre-execution AV detection relies on cloud-side hash matching once the file has been seen and submitted. The YARA rules above are best deployed in EDR memory scanning or post-extraction hunting, not as pre-execution AV signatures.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.

