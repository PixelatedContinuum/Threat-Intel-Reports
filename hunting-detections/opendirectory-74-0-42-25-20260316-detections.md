---
title: "Detection Rules — ZeroTrace Multi-Family MaaS Operation (Open Directory 74.0.42.25)"
description: "Detection rules for ZeroTrace, a seven-family MaaS toolkit running XWorm and PureRAT loaders. 6 YARA, 5 Sigma and 1 Suricata rule."
date: '2026-03-17'
layout: post
permalink: /hunting-detections/opendirectory-74-0-42-25-20260316-detections/
thumbnail: /assets/images/cards/zerotrace-74-0-42-25-20260316.png
hide: true
---

**Campaign:** ZeroTrace-MultiFamily-MaaS-74.0.42.25
**Date:** 2026-03-17
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/zerotrace-74-0-42-25-20260316/

---

## Detection Coverage Summary

This open-directory exposure carried a seven-component multi-family MaaS toolkit, XWorm V5.6, its native XwormLoader reflective-PE loader, the Aspdkzb ConfuserEx loader cluster delivering PureRAT v4.1.9, Raven RAT (custom Delphi), abused ConnectWise ScreenConnect, and an unidentified DGA-capable family masquerading as VLC Media Player. Coverage below is rebuilt against current tiering standards; the two hardcoded C2 destinations (`185.49.126.140`, `adminxyzhosting.com`) that previously carried standalone Sigma/Suricata rules are retired as rules and confirmed already present in the IOC feed.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 6 | 0 | T1219, T1620, T1027.002, T1113 | 0 |
| Sigma | 2 | 3 | T1112, T1547.001, T1036.005, T1059.005, T1218.007, T1059.001 | 2 |
| Suricata | 1 | 0 | T1573.002, T1071.001 | 2 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient, safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting. Expect to review the hits.

**Highest-confidence anchors:**
- The XWorm V5.6 mutex `5tK099W0Z6AMZVxQ` (which doubles as the AES key-derivation seed for the C2 protocol) paired with the panel's "New Clinet : " / "Groub : " typo strings: near-zero FP, survives most rebuilds short of a combined protocol-and-panel rewrite (YARA Detection).
- The PureRAT v4.1.9 `04 00 00 00` protocol preamble on ports 56001-56003, salvaged from a single-IP-pinned rule to scope on `$EXTERNAL_NET`, the only network signature in this campaign that survives infrastructure rotation (Suricata Detection).

**Atomics routed to the IOC feed:** four of the original file's rules, the XWorm/PureHVNC/PureRAT multi-port C2-IP Sigma rule, the ScreenConnect relay domain+port Sigma rule, the XWorm C2 Suricata rule (pure IP:port, no payload content), and the ScreenConnect relay domain-content Suricata rule, each keyed solely on the hardcoded IP `185.49.126.140` or the domain `adminxyzhosting.com`. Both are already carried in [`opendirectory-74-0-42-25-20260316-iocs.json`](/ioc-feeds/opendirectory-74-0-42-25-20260316-iocs.json) with the exact ports/context documented; no new feed entries were required. Block them via the feed.

---

## Multi-Family Organization

This campaign spans seven distinct components. Within each rule-type section below, tier subsections come first (`### Detection Rules` / `### Hunting Rules`), and rules are grouped inside each tier under a bold family/component label:

```
## YARA Rules

### Detection Rules

**XWorm V5.6**
[stub + builder rules]

**XwormLoader**
[reflective PE loader rule]

**Aspdkzb Loader Cluster / PureRAT v4.1.9**
[loader + payload rules]

**Raven RAT**
[HVNC stub rule]
```

The same type → tier → family nesting is applied within the Sigma and Suricata sections that follow.

---

## YARA Rules

### Detection Rules

**XWorm V5.6**

#### XWorm V5.6 VB.NET Victim Stub

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1219 (Remote Access Software)
**Confidence:** HIGH
**Rationale:** The anti-double-execution mutex `5tK099W0Z6AMZVxQ` doubles as the AES key-derivation seed for this build's C2 protocol, making it costly for the operator to change without breaking the malware's own encryption; paired with the deliberate typo strings `New Clinet : ` and `Groub : ` from the panel's client-list protocol, no single literal alone carries the rule and an operator would need to touch both the crypto seed and the panel-facing typos to evade.
**False Positives:** None known — the mutex string, version tag, and panel typo strings are distinctive compiled/hardcoded values not present in legitimate software.
**Blind Spots:** A rebuild that changes the mutex/AES-seed value AND both typo strings (a full protocol-and-panel rewrite) would evade; the rule targets the on-disk VB.NET stub, not memory-only injection variants.
**Validation:** Scan the analyzed XWorm V5.6 stub (`hash1` below) — the mutex or the version+typo combination must match; an unrelated VB.NET application must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, email-gateway attachment scanning, download-quarantine scanning.

```yara
/*
   Yara Rule Set
   Identifier: OpenDirectory 74.0.42.25 — Multi-Family MaaS Toolkit
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule RAT_XWorm_V56_Stub {
   meta:
      description = "Detects XWorm V5.6 VB.NET victim stub by plaintext mutex string, protocol packet delimiter, and distinctive Telegram notification typo strings characteristic of this builder version"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-74-0-42-25-20260316-detections/"
      date = "2026-03-17"
      hash1 = "427f818131c9beb7f8a487cb28fe13e2699db844ac3c9e9ae613fd35113fe77f"
      hash2 = "257b07c4b9eb72403769a12604e9ddb2bf5545fa"
      hash3 = "f4b00fbc6a3ce80b474334a3ccaadcf0"
      family = "XWorm"
      malware_type = "RAT"
      campaign = "ZeroTrace-MultiFamily-MaaS-74.0.42.25"
      id = "75780e95-7bd7-5a15-9ed1-008b56fb6c44"
   strings:
      $s1 = "5tK099W0Z6AMZVxQ" ascii wide
      $s2 = "<Xwormmm>" ascii wide
      $s3 = "XWorm V5.6" ascii wide
      $s4 = "New Clinet : " ascii wide
      $s5 = "Groub : " ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 150KB and
      ($s1 or ($s2 and $s3)) and
      1 of ($s4, $s5)
}
```

#### XWorm V5.6 Builder and C2 Panel

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1219 (Remote Access Software)
**Confidence:** HIGH
**Rationale:** Requires 3 of 5 anchors from the builder/panel binary. The version string and its byte-encoded skull-emoji form are correlated (both hinge on the same "XWorm V5.6" literal), so the rule's real strength rests on the 1-20MB filesize gate — unusual for a lean RAT payload but typical for this bundled VB.NET builder — combined with at least one of the two operator-specific typo strings or the sandbox-check URL.
**False Positives:** None known — the combination of the version literal (present in two independent encodings) with the 1-20MB filesize gate is not expected in unrelated software.
**Blind Spots:** A build satisfying the "3 of 5" bar purely through the version-string pair plus the generic ip-api.com sandbox-check URL (without either typo string) would survive a partial rebrand that keeps the version tag; a full rebrand removing all five anchors evades entirely.
**Validation:** Scan the analyzed builder/panel sample (`hash1` below) — 3 of the 5 anchors must match; unrelated 1-20MB VB.NET software must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, static triage of unknown large VB.NET binaries.

```yara
rule TOOLKIT_XWorm_V56_Builder {
   meta:
      description = "Detects XWorm V5.6 builder and C2 server panel by version string, Telegram skull emoji format string, and sandbox VM detection URL characteristic of the V5.6 build"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-74-0-42-25-20260316-detections/"
      date = "2026-03-17"
      hash1 = "90f58865f265722ab007abb25074b3fc4916e927402552c6be17ef9afac96405"
      hash2 = "5b01b90137871c3c8f0d04f510c4d56b23932cbc"
      hash3 = "56ccb739926a725e78a7acf9af52c4bb"
      family = "XWorm"
      malware_type = "RAT Builder/Panel"
      campaign = "ZeroTrace-MultiFamily-MaaS-74.0.42.25"
      id = "cdacf530-e7c4-5ea8-b58c-f786f7be4a62"
   strings:
      $s1 = "XWorm V5.6" ascii wide
      $b1 = { E2 98 A0 20 5B 58 57 6F 72 6D 20 56 35 2E 36 5D }
      $s2 = "New Clinet : " ascii wide
      $s3 = "Groub : " ascii wide
      $s4 = "http://ip-api.com/line/?fields=hosting" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize > 1MB and filesize < 20MB and
      3 of them
}
```

**XwormLoader**

#### XwormLoader Native Reflective PE Loader

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1620 (Reflective Code Loading)
**Confidence:** HIGH
**Rationale:** The 4-byte NOT-then-subtract-0x3E decryption opcode sequence is required in every match and is paired with either the `.NET Framework` LDR-path spoof string or both operator-authored decoy comment strings (`This is garbage code #`, `Welcome to the random numbers generator!`) — the decoy comments in particular are unusual enough that no legitimate software plausibly contains them, and an operator would need to rewrite the custom cipher AND strip the decoy comments to fully evade.
**False Positives:** None known — the decoy comment strings are distinctive developer artifacts; the 4-byte opcode sequence is never used as a sole anchor.
**Blind Spots:** A rebuild using a different byte-level cipher AND removing both decoy comment strings would evade; the rule targets the native C++ loader stage specifically, not the downstream reflectively-loaded payload.
**Validation:** Scan the analyzed XwormLoader sample (`hash1` below) — the opcode pattern plus at least one string condition must match; unrelated native C++ binaries must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, static triage of unknown native loaders.

```yara
rule MALW_XwormLoader_ReflectivePE {
   meta:
      description = "Detects XwormLoader native C++ 11-stage reflective PE loader by NOT-minus-0x3E decryption opcode sequence, .NET Framework LDR path spoof string, and operator-authored decoy comment strings embedded in the binary"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-74-0-42-25-20260316-detections/"
      date = "2026-03-17"
      hash1 = "f5f14b9073f86da926a8ed319b3289b893442414d1511e45177f6915fb4e5478"
      hash2 = "93e4f301156d120a87fe2c4be3aaa28b9dfd1a8d"
      hash3 = "9c9245810bad661af3d6efec543d34fd"
      family = "XwormLoader"
      malware_type = "Loader"
      campaign = "ZeroTrace-MultiFamily-MaaS-74.0.42.25"
      id = "05b1d15e-f524-5f59-9333-ecaec0c672be"
   strings:
      $b1 = { F6 D0 2C 3E }
      $s1 = "C:\\Windows\\Microsoft.NET\\Framework" wide
      $s2 = "This is garbage code #" ascii
      $s3 = "Welcome to the random numbers generator!" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 600KB and
      $b1 and
      ($s1 or ($s2 and $s3))
}
```

**Aspdkzb Loader Cluster / PureRAT v4.1.9**

#### Aspdkzb ConfuserEx Fileless Loader Cluster

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1027.002 (Software Packing)
**Confidence:** HIGH
**Rationale:** "ConfuserEx" alone is a widely-used open-source .NET obfuscator string that appears in both malicious and legitimate protected software, but the rule requires it alongside one of three campaign-specific internal namespace strings (`Faidowra`, `Zvafsyattl`, `Aspdkzb`) that only appear in this loader cluster's builds; an operator would need to both swap obfuscators and rename every internal namespace reference to evade. Filesize bound widened from the original 310-330KB to 300-330KB after cross-checking all nine analyzed cluster variants — two samples (312832 bytes = 305.5KB) fell below the original 310KB floor and would have been missed.
**False Positives:** None known — the campaign-specific namespace strings have no plausible legitimate collision; "ConfuserEx" alone is never sufficient to trigger a match.
**Blind Spots:** A rebuild using a different obfuscator or renaming all three internal namespace strings evades; the tight filesize band also means a padded or re-linked build outside that range would not match even with matching strings.
**Validation:** Scan an Aspdkzb-cluster loader sample (`hash1` below) — must satisfy both the ConfuserEx marker and a namespace string; an unrelated ConfuserEx-protected .NET application must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, static triage of unknown ConfuserEx-protected binaries.

```yara
rule MALW_Aspdkzb_ConfuserEx_Loader {
   meta:
      description = "Detects Aspdkzb-family ConfuserEx-protected fileless loader cluster delivering PureRAT v4.1.9 via three-stage in-memory Assembly.Load chain; matched by distinctive internal namespace strings from the loader stages"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-74-0-42-25-20260316-detections/"
      date = "2026-03-17"
      hash1 = "978ead9671e59772eeeb73344fc3b0c068c5168de7f67f738269f5b59e681a9a"
      hash2 = "1b14c09c6b5323b14102e2dc4080805fb2f12557"
      hash3 = "554cbfabfb7bce86780241a0087d51fb"
      family = "Aspdkzb"
      malware_type = "Loader"
      campaign = "ZeroTrace-MultiFamily-MaaS-74.0.42.25"
      id = "bbdb528b-d1b0-5de1-ae13-d82b09742aea"
   strings:
      $s1 = "ConfuserEx" ascii wide
      $s2 = "Faidowra" ascii wide
      $s3 = "Zvafsyattl" ascii wide
      $s4 = "Aspdkzb" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize >= 300KB and filesize <= 330KB and
      $s1 and
      1 of ($s2, $s3, $s4)
}
```

#### PureRAT v4.1.9 .NET Reactor Payload

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1219 (Remote Access Software)
**Confidence:** HIGH
**Rationale:** The primary branch requires both Faidowra-branded internal namespace strings together — a combination unique to this campaign's build lineage and costly to change without reworking the payload's class hierarchy; the fallback branch (pinned version string plus 2 of 3 distinctive internal method/class names) still fires if a future build strips the Faidowra branding but retains the underlying v4.1.9 codebase.
**False Positives:** None known — the Faidowra-branded namespace strings are unique to this campaign; the fallback branch's internal names (`OrderChain`, `DefinitionChooser`, `ProcEnumerator`) have no plausible legitimate collision when combined with the pinned version string.
**Blind Spots:** A build that both strips all Faidowra branding AND renames the version string and two of the three fallback method names would evade; the rule targets the extracted/unpacked .NET Reactor payload, not the outer obfuscated loader stages.
**Validation:** Scan the extracted PureRAT v4.1.9 payload (`hash1` below) — one of the two branches must match; an unrelated .NET Reactor-protected application must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, scanning of saved dumps taken during suspected in-memory payload extraction. Live process-memory scanning does not match: the condition's `filesize` test is undefined there, so only files and saved dumps are scanned.

```yara
rule RAT_PureRAT_v419_Payload {
   meta:
      description = "Detects PureRAT v4.1.9 final stage .NET Reactor-obfuscated payload (Faidowra.dll) by deobfuscated internal namespace strings and MaaS version string characteristic of the v4.1.9 build"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-74-0-42-25-20260316-detections/"
      date = "2026-03-17"
      hash1 = "6b526c29a6961c1f03eeb1ec4ca3a0fdc5680e3f90db013dea8b27d8b63cce57"
      hash2 = "4edc47021e17dd02d2b0c8b839a9dbd4da5949db"
      hash3 = "fa9405a7c7bfca793f3f8c0c25dc9445"
      family = "PureRAT"
      malware_type = "RAT"
      campaign = "ZeroTrace-MultiFamily-MaaS-74.0.42.25"
      id = "18c2a2e2-1299-56a2-a0a4-7f466c1ef5ab"
   strings:
      $s1 = "Faidowra.IO.ModelConfiguration" ascii wide
      $s2 = "ProtoBuf.Strategies.ServerModel" ascii wide
      $s3 = "4.1.9" ascii wide
      $s4 = "OrderChain" ascii wide
      $s5 = "DefinitionChooser" ascii wide
      $s6 = "ProcEnumerator" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 900KB and
      (($s1 and $s2) or ($s3 and 2 of ($s4, $s5, $s6)))
}
```

**Raven RAT**

#### Raven RAT Delphi Victim Stub

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1219 (Remote Access Software), T1113 (Screen Capture — HVNC branch)
**Confidence:** HIGH
**Rationale:** The first branch requires all three custom Delphi HVNC class names together — a naming set specific to this codebase's hidden-VNC implementation rather than stock Delphi/VCL classes. The second branch (2 of 4 targeted crypto-wallet names plus the "WindowsService" persistence-value string) is comparatively weaker on its own: the wallet names are shared targets across many unrelated stealer families, and "WindowsService" is a generic term rather than a family-unique artifact. This is documented as a caveat rather than split into a separate rule, since the branch still requires 3 co-occurring conditions and the overall rule remains net-positive for Detection.
**False Positives:** None known against the first (HVNC class name) branch. The second branch has a plausible, if narrow, false-positive path: legitimate crypto-portfolio or multi-wallet management software that references 2+ of the same wallet names and separately contains the substring "WindowsService" (e.g., in a bundled background-sync service description).
**Blind Spots:** A rebrand renaming all three HVNC class names evades the first branch; the second branch is evaded by renaming the "WindowsService" persistence value or targeting different wallets, and is inherently weaker against unrelated wallet-stealing malware reusing the same target list.
**Validation:** Scan the analyzed Raven RAT stub template (`hash1` below) — the HVNC class-name branch must match; a benign Delphi VNC/remote-desktop or crypto-portfolio application must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, static triage of unknown Delphi binaries.

```yara
rule RAT_RavenRAT_Stub {
   meta:
      description = "Detects Raven RAT Delphi victim stub by hidden VNC class names from HVNC implementation and cryptocurrency wallet theft target strings; wallet names combined with Run key persistence value reduce false positive risk"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-74-0-42-25-20260316-detections/"
      date = "2026-03-17"
      hash1 = "a616c5fd9cee76d2df4d2cfec8d8519e6fd2ad605c1942e1e1cbb99aa09a278d"
      hash2 = "079afe270f2addfe137265d2322c22c50415c741"
      hash3 = "0c4a765f0924b6867fb08407098327db"
      family = "RavenRAT"
      malware_type = "RAT"
      campaign = "ZeroTrace-MultiFamily-MaaS-74.0.42.25"
      id = "12163024-7850-5049-bcfa-c5151f1ed00f"
   strings:
      $s1 = "THiddenVNC" ascii wide
      $s2 = "THiddenVNCThread" ascii wide
      $s3 = "THVNCInputThread" ascii wide
      $s4 = "Exodus" ascii wide
      $s5 = "Atomic Wallet" ascii wide
      $s6 = "Guarda" ascii wide
      $s7 = "Wasabi" ascii wide
      $s8 = "WindowsService" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 15MB and
      (($s1 and $s2 and $s3) or (2 of ($s4, $s5, $s6, $s7) and $s8))
}
```

---

## Sigma Rules

### Detection Rules

**XWorm V5.6**

#### XWorm V5.6 Operator Configuration Registry Key Write

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1112 (Modify Registry)
**Confidence:** HIGH
**Rationale:** `HKCU\SOFTWARE\XWorm` is a distinctive registry key path not used by legitimate software; the operator's Telegram bot token and clipper wallet addresses are written here at runtime, so presence of the key indicates an active or recently active infection regardless of C2 infrastructure rotation.
**False Positives:** Unlikely — no known legitimate software uses the HKCU\SOFTWARE\XWorm registry key path.
**Blind Spots:** A build that renames the registry key namespace evades; the rule requires the write to actually occur, so a variant that stores this configuration elsewhere (environment variable, file) is not covered.
**Validation:** Trigger the malware's config-write routine — the registry key must match; unrelated software's registry activity must NOT fire.
**Hive rendering (round 2, 2026-10-11):** the selection used the literal `HKCU\` path, but Sysmon records a per-user key as `HKU\<SID>\...` and never as `HKCU`, so it could not match Sysmon events (the T-0222 registry telemetry proposal flags this; what Defend renders was not read). The selection now tests `HKU\` at the start and the key path after it, as rule 0163 does.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (registry telemetry).

```yaml
title: XWorm V5.6 Operator Configuration Registry Key Write
id: 2f4dafdd-6eb9-46f5-9ca6-ea704008f8da
status: experimental
description: >-
    Detects registry write events targeting HKCU\SOFTWARE\XWorm, the key used by XWorm V5.6
    to store operator-configured values including Telegram bot token, bot ID, and cryptocurrency
    clipper wallet addresses (BTC, ETH, TRC20). Presence of this key indicates an active or
    recently active XWorm V5.6 infection on the host.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-74-0-42-25-20260316-detections/
author: The Hunters Ledger
date: 2026-03-17
modified: 2026-10-11
tags:
    - attack.defense-impairment
    - attack.persistence
    - attack.t1112
    - detection.emerging-threats
    - stp.3
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|startswith: 'HKU\'
        TargetObject|contains: '\SOFTWARE\XWorm'
    condition: selection
falsepositives:
    - Unlikely — no known legitimate software uses the HKCU\SOFTWARE\XWorm registry key path
level: high
```

**vlc_boxed.exe (Unidentified DGA-Capable Family)**

#### vlc_boxed.exe Run Key Persistence via VLC Name Masquerade

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1547.001 (Registry Run Keys / Startup Folder), T1036.005 (Match Legitimate Name or Location)
**Confidence:** HIGH
**Rationale:** The Run key value name `vlctask` and the target path `%APPDATA%\vlcapp\vlc.exe` are both specific to this malware's masquerade: legitimate VLC Media Player installs to %ProgramFiles% and never registers a Run key named `vlctask`. *Logic fix 2026-10-11:* the rule used to test the value name alone, so renaming the target directory or pointing `vlctask` anywhere else still fired and the two-string claim was untrue; it now requires both the value name at the end of the key path and a value data (`Details`) that ends in `\vlcapp\vlc.exe`. *Boundary fix 2026-10-11 (round 2):* both tests were `contains`, so a value named `vlctaskBackup` or data ending `vlc.exe.bak` also matched; both are now `endswith`. Both strings are required (AND), so changing either one is enough to evade.
**False Positives:** Unlikely — legitimate VLC Media Player does not use the vlctask Run key value name or the AppData\vlcapp path.
**Blind Spots:** A rebrand renaming either the Run key value name or the target directory evades, because the rule needs both; data that does not end in `\vlcapp\vlc.exe` (a quoted path or trailing arguments) does not match; a value written without data in the event, or a sensor that does not report `Details`, never fires; only covers this specific masquerade, not a future build imitating a different application.
**Validation:** Trigger the malware's persistence routine: a Run-key write of value `vlctask` with data ending `\vlcapp\vlc.exe` must match; a `vlctask` value pointing elsewhere, a value named `vlctaskBackup`, data ending `vlc.exe.bak`, and a genuine VLC Media Player installation, must NOT fire.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (registry telemetry).

```yaml
title: vlc_boxed.exe DGA Malware Run Key Persistence via VLC Name Masquerade
id: e90b3fbd-823b-4218-a548-6c39376438f4
status: experimental
description: >-
    Detects registry persistence write for vlc_boxed.exe, an Enigma Virtual Box-packed DGA-capable
    malware family that masquerades as VLC Media Player. The malware creates a Run key value named
    'vlctask' pointing to '%APPDATA%\vlcapp\vlc.exe' — a path not used by legitimate VLC
    installations, which install to %ProgramFiles%. Presence of this key indicates
    a configured Run-key persistence value written by an unidentified DGA-capable malware family confirmed
    in this campaign. In the report's sandbox run the target binary was not dropped (C2 gating), so
    a hit shows persistence was set up, not that a working implant is present.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-74-0-42-25-20260316-detections/
author: The Hunters Ledger
date: 2026-03-17
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1547.001
    - attack.t1036.005
    - detection.emerging-threats
    - stp.3
logsource:
    category: registry_set
    product: windows
detection:
    selection_value_name:
        TargetObject|endswith: '\CurrentVersion\Run\vlctask'
    selection_target:
        Details|endswith: '\vlcapp\vlc.exe'
    condition: selection_value_name and selection_target
falsepositives:
    - Unlikely — legitimate VLC Media Player does not use the vlctask Run key value name or the AppData\vlcapp path
level: high
```

### Hunting Rules

**Raven RAT**

#### Raven RAT Persistence via WindowsService Run Key Masquerade

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1547.001 (Registry Run Keys / Startup Folder), T1036.005 (Match Legitimate Name or Location)
**Confidence:** MODERATE
**Rationale:** Demoted from the original `level: high`: "WindowsService" is a generic, operator-chosen Run-key value name rather than a family-specific artifact: trivially renamed in a future build and not costly for the operator to change, so durability is low even though today's collision rate with legitimate software is limited. The existing System32/SysWOW64 path filter reduces some obvious FPs but does not address poorly-installed legitimate software using the same generic value name, so this remains an analyst-triaged hunting lead rather than an alerting-grade rule. *Logic fix 2026-10-11:* the description names the per-user key (`HKCU`), but the selection was the key-path substring alone, so a machine-wide `HKLM` or `Wow6432Node` Run value of the same name matched too; the rule now also requires the `HKU\` hive prefix Sysmon uses for a per-user key. The report records the value under both the unqualified `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` path (section 5) and `HKCU` (IOC lists), so a machine-wide write is a documented gap and not covered. *Boundary fix 2026-10-11 (round 2):* the value-name test was `contains`, so a value named `WindowsServiceHelper` or `WindowsServiceBackup` matched; it is now `endswith`, which makes the value name exact.
**False Positives:** Poorly named legitimate software that uses 'WindowsService' as a Run key value name in a non-System32/SysWOW64 install path.
**Blind Spots:** A machine-wide (`HKLM`) Run value with this name no longer matches; the report does not settle which hive the sample writes (the IOC list says `HKCU`). The value name is a single literal.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (registry telemetry); correlate hits against the process image path and known-software inventory before escalating.

```yaml
title: Raven RAT Persistence via WindowsService Run Key Masquerade
id: 9ad1fd97-8a23-42fd-8ab6-210999dd6d9c
status: experimental
description: >-
    Detects Raven RAT (custom Delphi RAT developed by the ZeroTrace cluster) establishing
    persistence via a Run key entry named 'WindowsService' under
    HKCU\Software\Microsoft\Windows\CurrentVersion\Run (Sysmon renders the per-user hive
    as HKU\<SID>, which the rule tests). This value name is a deliberate
    masquerade intended to appear as a legitimate Windows service entry to casual inspection.
    Raven RAT provides keylogging, hidden VNC desktop creation, cryptocurrency wallet theft
    (Exodus, Atomic Wallet, Guarda, Wasabi), and SOCKS proxy capabilities. The value name is a
    generic literal an operator can trivially rename in a future build, so this rule is scoped
    as a hunting lead rather than a high-fidelity alert.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-74-0-42-25-20260316-detections/
author: The Hunters Ledger
date: 2026-03-17
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1547.001
    - attack.t1036.005
    - detection.emerging-threats
logsource:
    category: registry_set
    product: windows
detection:
    selection_value_name:
        TargetObject|endswith: '\CurrentVersion\Run\WindowsService'
    selection_hive:
        TargetObject|startswith: 'HKU\'
    filter_legitimate:
        Details|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    condition: selection_value_name and selection_hive and not filter_legitimate
falsepositives:
    - Poorly named legitimate software that uses 'WindowsService' as a Run key value name; validate that the target binary path is outside System32 and Program Files before actioning
level: medium
```

**PowerShell Fileless Droppers**

#### PowerShell ExecutionPolicy Bypass, a .ps1 and a User-Writable Path in the Command Line From a Non-Standard Parent

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1059.001 (PowerShell)
**ATT&CK Note:** Fileless Storage (T1027.011) is the campaign behavior the report describes for `puf.ps1` and `sync.ps1`; nothing in a process-creation event tests it, so it is not claimed here.
**Confidence:** MODERATE
**Rationale:** `-ExecutionPolicy Bypass` loading a `.ps1` file is common in both malicious and legitimate administrative tooling. The rule originally narrowed on nothing but a four-entry denylist of standard parent processes, which is a broad NOT-filter rather than a positive behavioral anchor, so every developer tool, CI agent, package manager and automation framework that launches PowerShell this way passed straight through. `selection_staging_path` adds a positive anchor by requiring one of six user-writable staging directory names to appear in the command line, which is where a dropper puts its script and where routine tooling generally does not. *Wording fix 2026-10-11:* the staging test is a substring over the whole `CommandLine`, so any argument containing `\Temp\` satisfies it, not only the script path, and the report does not record where `puf.ps1` and `sync.ps1` ran from, so that anchor is not tied to the campaign. The old title's "fileless PE dropper" is the campaign behavior the report describes (`Assembly.Load` in memory, no disk write), and nothing in the query tests it, so the title now names what is tested. A parent-image denylist is environment-specific and belongs in local tuning; this remains a hunting rule.

The staging anchor is command-text co-occurrence over the whole `CommandLine`, not the script's own path: a system script given a `\Temp\` data argument also matches, and the position of the `.ps1` relative to the staging directory is not tested. The parent-image denylist is applied as a NOT filter and is environment-specific; it belongs in local tuning. The campaign's "fileless PE dropper" behavior is not tested, so this remains a hunting rule.
**False Positives:** Software installers and updaters that stage a setup script under `%TEMP%` or `%APPDATA%` and invoke it with a policy bypass; any PowerShell command line that contains a `.ps1`, the bypass flag and one of the staging directory names anywhere (a system script with a user-path data argument); legitimate administrative scripts run from a user-writable path via remote management tools, scheduled tasks, or deployment systems not on the standard-parent denylist.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM; tune the filter_standard_parents list per environment before using for anything beyond hunting.

```yaml
title: PowerShell ExecutionPolicy Bypass, a .ps1 and a User-Writable Path in the Command Line From a Non-Standard Parent
id: 945438df-0fc1-4861-9ed6-4c66ae11e700
status: experimental
description: >-
    Detects powershell.exe whose command line contains -ExecutionPolicy, Bypass and .ps1 together
    with a user-writable staging directory (AppData, Temp, ProgramData, Users\Public, Downloads,
    $Recycle.Bin) anywhere in the command line, when the parent is not explorer.exe, services.exe,
    svchost.exe or msiexec.exe. The puf.ps1 and sync.ps1 droppers in this campaign hex-decode an
    embedded .NET PE assembly and load it in memory via Assembly.Load, but the rule tests none of
    that: no in-memory loading, no PE and no Assembly.Load appear in a process-creation event, and
    the staging-directory test is a substring of the whole command line, not a check of the
    script's own path. The report does not say where puf.ps1 and sync.ps1 were run from.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-74-0-42-25-20260316-detections/
author: The Hunters Ledger
date: 2026-03-17
tags:
    - attack.execution
    - attack.t1059.001
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains|all:
            - '-ExecutionPolicy'
            - 'Bypass'
            - '.ps1'
    selection_staging_path:
        CommandLine|contains:
            - '\AppData\'
            - '\Temp\'
            - '\ProgramData\'
            - '\Users\Public\'
            - '\Downloads\'
            - '\$Recycle.Bin\'
    filter_standard_parents:
        ParentImage|endswith:
            - '\explorer.exe'
            - '\services.exe'
            - '\svchost.exe'
            - '\msiexec.exe'
    condition: selection and selection_staging_path and not filter_standard_parents
falsepositives:
    - Software installers and updaters that stage a setup script under %TEMP% or %APPDATA% and invoke it with a policy bypass from a parent not on the standard-parent list
    - Legitimate administrative scripts invoked via remote management tools, scheduled tasks, or software deployment systems; extend filter_standard_parents to include known-good deployment parent images in the target environment
level: medium
```

**ScreenConnect Abuse**

#### WScript Spawning Msiexec Silent Install With ALLUSERS=2 (ScreenConnect Dropper Pattern)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1059.005 (Visual Basic), T1218.007 (Msiexec)
**Confidence:** MODERATE
**Rationale:** The parent-child pairing of `wscript.exe` spawning `msiexec.exe` with both `/quiet` and `ALLUSERS=2` is the installer step of the ScreenConnect phishing dropper described in the report (`Attachment.vbs` downloads the MSI and runs `msiexec /i [msi] /quiet ALLUSERS=2`). *Wording and tier fix 2026-10-11:* the earlier heading and description presented a ScreenConnect chain, but the rule tests only the parent image and two command-line tokens: it does not identify the MSI, its download source or ScreenConnect, and its own false-positive entry concedes that legitimate deployment scripts install silently from `wscript.exe`, which contradicted the description's "not expected behavior" sentence. A rule whose false-positive list admits the benign form is Hunting, so it moves from Detection and `level` from high to medium. Dropped the unsupported `attack.initial-access` tactic tag carried in the original rule (no accompanying T1566 technique tag was present).
**False Positives:** Legitimate software deployment scripts that invoke msiexec silently from wscript.exe with `ALLUSERS=2`, the benign form the rule's own false-positive entry has always conceded; validate the MSI path, its download source and the installed product against known-good deployment infrastructure.
**Blind Spots:** A dropper using a different scripting engine (JScript, PowerShell, `cscript.exe`) to launch the same silent MSI install evades the `wscript.exe` parent requirement; misses installs that omit `ALLUSERS=2` or `/quiet`; a command line holding the flags in a different form (`/qn`) evades.
**Validation:** Trigger the phishing dropper chain: the parent-child-cmdline combination must match; a silent MSI deployment from a different parent process must NOT fire. A silent install launched by an administrator's own VBScript matches too and is the known benign form, so a hit proves the pattern and not ScreenConnect.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (process-creation telemetry).

```yaml
title: WScript Spawning Msiexec Silent Install With ALLUSERS=2 (ScreenConnect Dropper Pattern)
id: c48377bd-0066-4bb0-8cc7-4041cd0a0e54
status: experimental
description: >-
    Detects wscript.exe spawning msiexec.exe with both /quiet and ALLUSERS=2 in the command line,
    the installer step of the ScreenConnect phishing dropper in this campaign: the report records
    that Attachment.vbs downloads the ScreenConnect MSI with MSXML2.ServerXMLHTTP.6.0 and SSL
    verification deliberately bypassed, then runs msiexec /i with /quiet and ALLUSERS=2. The rule
    tests the parent image and those two command-line tokens only. It does not identify the MSI,
    its source or ScreenConnect, and a legitimate deployment script that installs silently from
    wscript.exe matches the same way, so a hit is a hunting lead and not a ScreenConnect finding.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-74-0-42-25-20260316-detections/
author: The Hunters Ledger
date: 2026-03-17
tags:
    - attack.execution
    - attack.stealth
    - attack.t1059.005
    - attack.t1218.007
    - detection.emerging-threats
    - stp.3
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\wscript.exe'
    selection_child:
        Image|endswith: '\msiexec.exe'
        CommandLine|contains|all:
            - '/quiet'
            - 'ALLUSERS=2'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate software deployment scripts that invoke msiexec silently from wscript.exe; validate MSI download source URL and installation target domain against known-good deployment infrastructure
level: medium
```

---

## Suricata Signatures

### Detection Rules

**PureRAT v4.1.9**

#### PureRAT v4.1.9 Four-Byte Preamble on Ports 56001 to 56003

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1573.002 (Asymmetric Cryptography), T1071.001 (Web Protocols)
**Confidence:** HIGH
**Rationale:** The published 4-byte `04 00 00 00` preamble that PureRAT v4.1.9 sends on its non-standard C2 ports (56001-56003) before the TLS handshake is a protocol-framing artifact recorded in the report from binary analysis and attributed to external research (Netresec, August 2025). Salvaged from the original IP-pinned rule by widening the destination from a single hardcoded C2 IP to `$EXTERNAL_NET`: the content anchor and port combination now survive infrastructure rotation, which the original single-IP version could not. `rev` bumped to 2 for that change. *Wording fix 2026-10-11 (rev 4):* the earlier heading and `msg` said "Before TLS", but the rule matches the four bytes in the first four bytes of the payload buffer Suricata inspects on those three ports (`depth:4` is an absolute bound from the start of that buffer; this rule has no stream-start constraint, so it is not shown to mean the first bytes of the connection) and never looks at a TLS ClientHello, so it fires on any TCP flow to those ports that opens with those bytes; the heading and `msg` now say what is matched. *Robustness fix 2026-10-11 (round 2):* scored 2, not 3: the three destination ports are configurable and the preamble is a 4-byte little-endian length of 4, which the family's framing uses but another tool could too, so the rule is a protocol-framing fingerprint of this family on selected ports, not a technique invariant. "Confirmed C2 Ports" dropped from the `msg` because the ports are confirmed for one C2 and the destination is no longer pinned to it.
**False Positives:** None known from the evidence; no benign traffic corpus was tested. Any other protocol that opens with the same four bytes (`04 00 00 00`, a little-endian length of 4) on destination ports 56001 to 56003 would match, because the rule does not check for a TLS ClientHello after the preamble.
**Blind Spots:** The rule matches the four bytes at the start of an inspected payload buffer, so a later segment that opens with the same bytes also matches, and a first message that is split or prefixed differently is not matched; no replay was run. A future PureRAT build that changes the preamble value or moves off these three ports evades; the TLS payload after the preamble is opaque to the sensor, so the rule cannot confirm that a handshake follows.
**Validation:** Replay a PCAP of PureRAT v4.1.9's handshake on ports 56001-56003 (none was available to this lane): it must alert. Ordinary TLS traffic on unrelated ports must NOT; a TLS ClientHello sent to these ports with no preamble must NOT.
**Deployment:** Network IDS/IPS at perimeter and internal segmentation points.

```suricata
alert tcp $HOME_NET any -> $EXTERNAL_NET [56001,56002,56003] (msg:"THL DETECT MaaS Toolkit PureRAT v4.1.9 Four-Byte Preamble on Ports 56001 to 56003 (C2 Protocol Framing)"; flow:established,to_server; content:"|04 00 00 00|"; depth:4; threshold:type limit,track by_src,count 1,seconds 300; reference:url,the-hunters-ledger.com/hunting-detections/opendirectory-74-0-42-25-20260316-detections/; classtype:trojan-activity; sid:9001002; rev:4; metadata:author The_Hunters_Ledger, date 2026-03-17;)
```

---

## Coverage Gaps

**Atomics routed to the IOC feed (4 of the original file's 16 rules).** The multi-port C2-IP Sigma rule (XWorm port 5000, PureHVNC port 8000, PureRAT ports 56001-56003, all on `185.49.126.140`), the ScreenConnect relay domain+port Sigma rule (`adminxyzhosting.com` on port 8041), the pure IP:port XWorm C2 Suricata rule (no payload content, `185.49.126.140:5000`), and the domain-content ScreenConnect relay Suricata rule (`adminxyzhosting.com` string match) each keyed solely on one hardcoded literal with no surviving behavioral anchor once that literal is removed, per the tiering rubric's routing test, these are IOC-feed entries, not rules. All values were already present in [`opendirectory-74-0-42-25-20260316-iocs.json`](/ioc-feeds/opendirectory-74-0-42-25-20260316-iocs.json) (`network_indicators.ipv4` entries for `185.49.126.140` on ports 5000/8000/56001/56002/56003/443/8041; `network_indicators.domains` entry for `adminxyzhosting.com`). No feed edits were required.

**CVE-2025-30406 ViewState exploit indicators not rule-eligible.** The recovered ASP.NET ViewState validation key, generator, and HMACSHA256/TextFormattingRunProperties gadget chain are victim-specific, hardcoded to one targeted application's deployment rather than reusable attacker infrastructure, so no YARA, Sigma, or Suricata rule can generalize from them without producing a signature that only ever matches this one incident. They remain documented in the IOC feed's `exploit_indicators` block for incident-scoping reference.

**BAK3R Office 365 credential-cracker component not hash-captured.** `Office_Cracker.py` is referenced only through attribution artifacts (Telegram handle, Discord ID) in the underlying evidence; no file hash, host indicator, or network indicator for the tool itself was captured, so no rule could be authored. **What would enable a rule:** a hash or distinctive string/network indicator from the tool itself.

**XWorm plugin DLL cache path not rule-eligible.** The registry path `HKCU\Software\[HWID]` used to cache downloaded plugin DLLs is keyed on a per-victim HWID value (MD5 of hardware/OS fingerprint fields) that varies by host, so no static registry-path selector can be written. **What would enable a rule:** a stable value-name or plugin-name pattern independent of the per-host HWID.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
