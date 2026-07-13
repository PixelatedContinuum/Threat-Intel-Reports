---
title: "Detection Rules — ZeroTrace Multi-Family MaaS Operation (Open Directory 74.0.42.25)"
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

This open-directory exposure carried a seven-component multi-family MaaS toolkit — XWorm V5.6, its native XwormLoader reflective-PE loader, the Aspdkzb ConfuserEx loader cluster delivering PureRAT v4.1.9, Raven RAT (custom Delphi), abused ConnectWise ScreenConnect, and an unidentified DGA-capable family masquerading as VLC Media Player. Coverage below is rebuilt against current tiering standards; the two hardcoded C2 destinations (`185.49.126.140`, `adminxyzhosting.com`) that previously carried standalone Sigma/Suricata rules are retired as rules and confirmed already present in the IOC feed.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 6 | 0 | T1219, T1620, T1027.002, T1113 | 0 |
| Sigma | 3 | 2 | T1112, T1547.001, T1036.005, T1059.005, T1218.007, T1059.001, T1027.011 | 2 |
| Suricata | 1 | 0 | T1573.002, T1071.001 | 2 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchors:**
- The XWorm V5.6 mutex `5tK099W0Z6AMZVxQ` — which doubles as the AES key-derivation seed for the C2 protocol — paired with the panel's "New Clinet : " / "Groub : " typo strings: near-zero FP, survives most rebuilds short of a combined protocol-and-panel rewrite (YARA Detection).
- The PureRAT v4.1.9 `04 00 00 00` protocol preamble on ports 56001-56003, salvaged from a single-IP-pinned rule to scope on `$EXTERNAL_NET` — the only network signature in this campaign that survives infrastructure rotation (Suricata Detection).

**Atomics routed to the IOC feed:** four of the original file's rules — the XWorm/PureHVNC/PureRAT multi-port C2-IP Sigma rule, the ScreenConnect relay domain+port Sigma rule, the XWorm C2 Suricata rule (pure IP:port, no payload content), and the ScreenConnect relay domain-content Suricata rule — each keyed solely on the hardcoded IP `185.49.126.140` or the domain `adminxyzhosting.com`. Both are already carried in [`opendirectory-74-0-42-25-20260316-iocs.json`](/ioc-feeds/opendirectory-74-0-42-25-20260316-iocs.json) with the exact ports/context documented; no new feed entries were required. Block them via the feed.

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
**Deployment:** Endpoint AV/EDR file scan, memory scanning during suspected in-memory payload extraction.

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
tags:
    - attack.defense-impairment
    - attack.persistence
    - attack.t1112
    - detection.emerging-threats
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|startswith: 'HKCU\SOFTWARE\XWorm'
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
**Rationale:** The Run key value name `vlctask` and target path `%APPDATA%\vlcapp\vlc.exe` are both specific to this malware's masquerade — legitimate VLC Media Player installs to %ProgramFiles% and never registers a Run key named `vlctask`. The path+value combination requires the operator to change two coordinated strings to evade.
**False Positives:** Unlikely — legitimate VLC Media Player does not use the vlctask Run key value name or the AppData\vlcapp path.
**Blind Spots:** A rebrand renaming both the Run key value name and the target directory evades; only covers this specific masquerade, not a future build imitating a different application.
**Validation:** Trigger the malware's persistence routine — the registry write must match; a genuine VLC Media Player installation must NOT fire.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (registry telemetry).

```yaml
title: vlc_boxed.exe DGA Malware Run Key Persistence via VLC Name Masquerade
id: e90b3fbd-823b-4218-a548-6c39376438f4
status: experimental
description: >-
    Detects registry persistence write for vlc_boxed.exe, an Enigma Virtual Box-packed DGA-capable
    malware family that masquerades as VLC Media Player. The malware creates a Run key value named
    'vlctask' pointing to '%APPDATA%\vlcapp\vlc.exe' — a path not used by legitimate VLC
    installations, which install to %ProgramFiles%. Presence of this key indicates successful
    persistence establishment by an unidentified DGA-capable malware family confirmed in this campaign.
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
    selection:
        TargetObject|contains: '\CurrentVersion\Run\vlctask'
    condition: selection
falsepositives:
    - Unlikely — legitimate VLC Media Player does not use the vlctask Run key value name or the AppData\vlcapp path
level: high
```

**ScreenConnect Abuse**

#### ScreenConnect Phishing VBScript Dropper Silent MSI Install Chain

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1059.005 (Visual Basic), T1218.007 (Msiexec)
**Confidence:** HIGH
**Rationale:** The parent-child pairing of `wscript.exe` spawning `msiexec.exe` with both `/quiet` and `ALLUSERS=2` is a durable technique-level chokepoint for this silent-install delivery method — an operator would need to change the entire installer invocation mechanism, not just a filename, to evade. Dropped the unsupported `attack.initial-access` tactic tag carried in the original rule (no accompanying T1566 technique tag was present).
**False Positives:** Legitimate software deployment scripts that invoke msiexec silently from wscript.exe; validate MSI download source URL and installation target domain against known-good deployment infrastructure.
**Blind Spots:** A dropper using a different scripting engine (JScript, PowerShell) to launch the same silent MSI install evades the `wscript.exe` parent requirement; misses installs that omit `ALLUSERS=2`.
**Validation:** Trigger the phishing dropper chain — the parent-child-cmdline combination must match; a legitimate silent MSI deployment from a different parent process must NOT fire.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (process-creation telemetry).

```yaml
title: ScreenConnect Phishing VBScript Dropper Silent MSI Install Chain
id: c48377bd-0066-4bb0-8cc7-4041cd0a0e54
status: experimental
description: >-
    Detects the ScreenConnect phishing dropper chain where a VBScript (Attachment.vbs) spawns
    msiexec.exe with silent install flags (/quiet ALLUSERS=2) to install ConnectWise ScreenConnect
    without user interaction. The dropper downloads the MSI from the operator distribution domain
    using MSXML2.ServerXMLHTTP.6.0 with SSL verification deliberately bypassed. wscript.exe
    spawning msiexec.exe with ALLUSERS=2 is characteristic of this phishing dropper and is not
    expected behavior in legitimate software deployment from this parent process.
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
level: high
```

### Hunting Rules

**Raven RAT**

#### Raven RAT Persistence via WindowsService Run Key Masquerade

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1547.001 (Registry Run Keys / Startup Folder), T1036.005 (Match Legitimate Name or Location)
**Confidence:** MODERATE
**Rationale:** Demoted from the original `level: high` — "WindowsService" is a generic, operator-chosen Run-key value name rather than a family-specific artifact: trivially renamed in a future build and not costly for the operator to change, so durability is low even though today's collision rate with legitimate software is limited. The existing System32/SysWOW64 path filter reduces some obvious FPs but does not address poorly-installed legitimate software using the same generic value name, so this remains an analyst-triaged hunting lead rather than an alerting-grade rule.
**False Positives:** Poorly named legitimate software that uses 'WindowsService' as a Run key value name in a non-System32/SysWOW64 install path.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (registry telemetry); correlate hits against the process image path and known-software inventory before escalating.

```yaml
title: Raven RAT Persistence via WindowsService Run Key Masquerade
id: 9ad1fd97-8a23-42fd-8ab6-210999dd6d9c
status: experimental
description: >-
    Detects Raven RAT (custom Delphi RAT developed by the ZeroTrace cluster) establishing
    persistence via a Run key entry named 'WindowsService' under
    HKCU\Software\Microsoft\Windows\CurrentVersion\Run. This value name is a deliberate
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
    selection:
        TargetObject|contains: '\CurrentVersion\Run\WindowsService'
    filter_legitimate:
        Details|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    condition: selection and not filter_legitimate
falsepositives:
    - Poorly named legitimate software that uses 'WindowsService' as a Run key value name; validate that the target binary path is outside System32 and Program Files before actioning
level: medium
```

**PowerShell Fileless Droppers**

#### Fileless PowerShell PE Dropper ExecutionPolicy Bypass from Non-Standard Parent

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1059.001 (PowerShell), T1027.011 (Fileless Storage)
**Confidence:** MODERATE
**Rationale:** `-ExecutionPolicy Bypass` loading a `.ps1` file is common in both malicious and legitimate administrative tooling; the rule's only narrowing factor is a small denylist of "standard" parent processes, which is a broad NOT-filter rather than a positive behavioral anchor — most malicious and benign non-standard parents alike pass through untouched. This matches the puf.ps1/sync.ps1 fileless dropper chain but is not specific to it.
**False Positives:** Legitimate administrative scripts invoked via remote management tools, scheduled tasks, or software deployment systems not on the standard-parent denylist.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM; tune the filter_standard_parents list per environment before using for anything beyond hunting.

```yaml
title: Fileless PowerShell PE Dropper ExecutionPolicy Bypass from Non-Standard Parent
id: 945438df-0fc1-4861-9ed6-4c66ae11e700
status: experimental
description: >-
    Detects execution of PowerShell with -ExecutionPolicy Bypass loading a .ps1 file from
    non-standard parent processes, consistent with the puf.ps1 and sync.ps1 fileless PE dropper
    chain used in this campaign. These droppers hex-decode an embedded 310KB .NET PE assembly and
    load it entirely in memory via Assembly.Load with no disk write, bypassing file-based detection.
    The rule targets PowerShell spawned by remote access tools, command shells, or scripting
    interpreters not expected to launch PowerShell with policy bypass flags in normal operations.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-74-0-42-25-20260316-detections/
author: The Hunters Ledger
date: 2026-03-17
tags:
    - attack.execution
    - attack.stealth
    - attack.t1059.001
    - attack.t1027.011
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
    filter_standard_parents:
        ParentImage|endswith:
            - '\explorer.exe'
            - '\services.exe'
            - '\svchost.exe'
            - '\msiexec.exe'
    condition: selection and not filter_standard_parents
falsepositives:
    - Legitimate administrative scripts invoked via remote management tools, scheduled tasks, or software deployment systems; extend filter_standard_parents to include known-good deployment parent images in the target environment
level: medium
```

---

## Suricata Signatures

### Detection Rules

**PureRAT v4.1.9**

#### PureRAT v4.1.9 Protocol Preamble Before TLS

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1573.002 (Asymmetric Cryptography), T1071.001 (Web Protocols)
**Confidence:** HIGH
**Rationale:** The published 4-byte `04 00 00 00` preamble immediately preceding the TLS ClientHello on PureRAT v4.1.9's non-standard ports (56001-56003) is a protocol-framing artifact independently confirmed from binary analysis and external research — a technique-level chokepoint the operator cannot change without breaking the malware's own handshake logic. Salvaged from the original IP-pinned rule by widening the destination from a single hardcoded C2 IP to `$EXTERNAL_NET`: the content anchor and non-standard port combination now survive infrastructure rotation, which the original single-IP version could not. `rev` bumped to 2 to reflect the destination-scope change.
**False Positives:** None known — the specific 4-byte preamble immediately before a TLS ClientHello on these three non-standard ports is not observed in legitimate traffic; ordinary TLS services do not prepend this framing.
**Blind Spots:** A future PureRAT build that changes the preamble value or moves off these three ports evades; TLS payload after the preamble is opaque to the sensor.
**Validation:** Replay a PCAP of PureRAT v4.1.9's handshake on ports 56001-56003 — must alert; ordinary TLS traffic on unrelated ports must NOT.
**Deployment:** Network IDS/IPS at perimeter and internal segmentation points.

```suricata
alert tcp $HOME_NET any -> $EXTERNAL_NET [56001,56002,56003] (msg:"THL MaaS Toolkit PureRAT v4.1.9 Protocol Preamble Before TLS to Confirmed C2 Ports"; flow:established,to_server; content:"|04 00 00 00|"; depth:4; threshold:type limit,track by_src,count 1,seconds 300; classtype:trojan-activity; sid:9001002; rev:2; metadata:author The_Hunters_Ledger, date 2026-03-17, reference https://the-hunters-ledger.com/hunting-detections/opendirectory-74-0-42-25-20260316-detections/;)
```

---

## Coverage Gaps

**Atomics routed to the IOC feed (4 of the original file's 16 rules).** The multi-port C2-IP Sigma rule (XWorm port 5000, PureHVNC port 8000, PureRAT ports 56001-56003, all on `185.49.126.140`), the ScreenConnect relay domain+port Sigma rule (`adminxyzhosting.com` on port 8041), the pure IP:port XWorm C2 Suricata rule (no payload content, `185.49.126.140:5000`), and the domain-content ScreenConnect relay Suricata rule (`adminxyzhosting.com` string match) each keyed solely on one hardcoded literal with no surviving behavioral anchor once that literal is removed — per the tiering rubric's routing test, these are IOC-feed entries, not rules. All values were already present in [`opendirectory-74-0-42-25-20260316-iocs.json`](/ioc-feeds/opendirectory-74-0-42-25-20260316-iocs.json) (`network_indicators.ipv4` entries for `185.49.126.140` on ports 5000/8000/56001/56002/56003/443/8041; `network_indicators.domains` entry for `adminxyzhosting.com`) — no feed edits were required.

**CVE-2025-30406 ViewState exploit indicators not rule-eligible.** The recovered ASP.NET ViewState validation key, generator, and HMACSHA256/TextFormattingRunProperties gadget chain are victim-specific — hardcoded to one targeted application's deployment rather than reusable attacker infrastructure — so no YARA, Sigma, or Suricata rule can generalize from them without producing a signature that only ever matches this one incident. They remain documented in the IOC feed's `exploit_indicators` block for incident-scoping reference.

**BAK3R Office 365 credential-cracker component not hash-captured.** `Office_Cracker.py` is referenced only through attribution artifacts (Telegram handle, Discord ID) in the underlying evidence; no file hash, host indicator, or network indicator for the tool itself was captured, so no rule could be authored. **What would enable a rule:** a hash or distinctive string/network indicator from the tool itself.

**XWorm plugin DLL cache path not rule-eligible.** The registry path `HKCU\Software\[HWID]` used to cache downloaded plugin DLLs is keyed on a per-victim HWID value (MD5 of hardware/OS fingerprint fields) that varies by host, so no static registry-path selector can be written. **What would enable a rule:** a stable value-name or plugin-name pattern independent of the per-host HWID.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
