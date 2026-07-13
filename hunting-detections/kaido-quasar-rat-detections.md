---
title: "Detection Rules — KAIDO Quasar-Fork RAT"
date: '2026-07-03'
layout: post
permalink: /hunting-detections/kaido-quasar-rat-detections/
hide: true
---

**Campaign:** KAIDO-EvilSoul-Engine-MaaS-144.172.103.98
**Date:** 2026-07-03
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/kaido-quasar-rat-144-172-109-203/

---

## Detection Coverage Summary

> **Scope note:** this file covers only the **KAIDO Quasar-fork RAT** product line (PART A of the parent investigation). The EvilSoul-Engine stealer-builder line is covered in a separate detection file — no rules are duplicated here.

KAIDO is a rebranded 64-bit fork of the open-source Quasar RAT carrying an HVNC (Hidden-VNC) module that clones the victim's entire browser profile and drives their already-authenticated session on a hidden desktop.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 3 | 0 | T1219, T1113, T1497, T1573.001 | 0 |
| Sigma | 0 | 3 | T1553.005, T1219, T1113, T1036.005, T1547.001 | 0 |
| Suricata | 1 | 1 | T1071.001, T1573.001, T1095 | 1 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchors:**
- Namespace root `Kaido.Common.Messages` and Costura asset `costura.kaido.common.dll` — survive obfuscation, near-zero FP (YARA Detection).
- Raw TCP/4782 Quasar binary protocol + `TeamKAIDO`/`kaido-c2` TLS certificate issuer + JA4X `bbd6cc0fca29_bbd6cc0fca29_795797892f9c` — fleet-enumeration-grade (Suricata Detection).

**Atomics routed to the IOC feed:** the primary C2 domain `kaidoo.com.br` (and its `c2.`/`www.` siblings) is a transient indicator — it lives in [`kaido-quasar-rat-iocs.json`](/ioc-feeds/kaido-quasar-rat-iocs.json) rather than as a standalone DNS signature (removing the domain leaves nothing to detect). Block it via the feed.

**Coverage note on HVNC runtime behavior:** the HVNC module (hidden-desktop creation, browser-profile clone, DXGI capture) is fully recovered from static analysis (DEFINITE/HIGH), but the malware is C2-gated and withholds all post-connection behavior — persistence, HVNC activation, credential collection — until a valid Quasar handshake completes (T1480). Behavioral rules for the named-pipe transport and install path are written from static/structural evidence; see Coverage Gaps for what would raise the HVNC-specific rules to DEFINITE.

---

## YARA Rules

### Detection Rules

#### KAIDO Quasar-Fork Namespace + Costura Asset

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1219 (Remote Access Software)
**Confidence:** HIGH
**Rationale:** `Kaido.Common.Messages` is the namespace root of the rebranded Quasar fork and survives the sample's obfuscation pass intact (no literal `Quasar` string remains); paired with the Costura-embedded asset name and the HVNC hidden-desktop literal, this combination is unique to this build lineage and to something the operator cannot rename without re-architecting the codebase.
**False Positives:** None known — `Kaido.Common.Messages` and `costura.kaido.common.dll` are distinctive compiled identifiers not present in legitimate .NET software; `fullword` further reduces substring-collision risk.
**Blind Spots:** A full rebrand that renames the `Kaido.*` namespace root would evade this rule; a memory-only variant that never lands on disk needs the memory-scan deployment path.
**Validation:** Scan a KAIDO sample (e.g. `hash1` below) — the namespace + Costura asset must match; a benign Costura-packed .NET application must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, memory scanning of `svchost.exe`-masquerading processes, static triage of unknown MSIL binaries.

```yara
/*
   Yara Rule Set
   Identifier: KAIDO Quasar-Fork RAT
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule RAT_KAIDO_Quasar_Fork_Namespace {
   meta:
      description = "Detects the KAIDO Quasar-fork RAT via its rebranded namespace root Kaido.Common.Messages and Costura-embedded costura.kaido.common.dll asset, both of which survive the sample's obfuscation pass"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/kaido-quasar-rat-detections/"
      date = "2026-07-03"
      hash1 = "c7542e8265f70d6c1dbf2e3cf6e81a90198cd157d3d6693c6d2a8a49d99a5b8d"
      hash2 = "928f2ffa7fc84b74941fb714455d7bc14847b3af"
      hash3 = "20989b06f7c670ab973da6609855bcf9"
      family = "KAIDO"
      malware_type = "RAT"
      campaign = "KAIDO-EvilSoul-Engine-MaaS-144.172.103.98"
      id = "3c4d70e9-aaaf-50e7-b58b-a4b3595386e9"
   strings:
      $ns1  = "Kaido.Common.Messages" ascii wide fullword
      $ns2  = "Kaido.Client.Helper.HVNC.ProcessController" ascii wide
      $cost = "costura.kaido.common.dll" ascii wide nocase
      $desk = "Default_runhost" ascii wide fullword
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      2 of ($ns1, $ns2, $cost, $desk)
}
```

#### KAIDO HVNC DXGI Named-Pipe Transport

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1219 (Remote Access Software), T1113 (Screen Capture — MODERATE, static-only)
**Confidence:** HIGH
**Rationale:** The DXGI-hook HVNC frame transport uses a distinctive pipe-name prefix, environment variable, frame magic value, and reader-thread name — none generic Windows or .NET runtime terms. The rule requires two of these (or the frame magic plus one), so no single renameable literal carries it.
**False Positives:** None known — `KAIDO_DXGI_PIPE`, `kaido_dxgi_`, and the paired thread names are family-specific compiled strings; the hex frame magic is combined with string context rather than used alone.
**Blind Spots:** Misses a variant that renames all four HVNC transport strings *and* changes the frame magic; the DXGI capture path only exists in builds carrying the HVNC module.
**Validation:** Scan a KAIDO HVNC-capable sample — ≥2 transport strings must match; a benign screen-capture or remote-desktop tool must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, memory scanning during suspected HVNC activity.

```yara
rule RAT_KAIDO_HVNC_DXGI_Pipe {
   meta:
      description = "Detects the KAIDO RAT HVNC module via its DXGI-hook named-pipe transport strings (pipe prefix, env var, frame magic, reader-thread name) used to stream the hidden-desktop capture to the operator"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/kaido-quasar-rat-detections/"
      date = "2026-07-03"
      hash1 = "385d20ca574976e3ba3f4f3079420f8a1c3935c0ab4a3f87063beea27d41e254"
      hash2 = ""
      hash3 = ""
      family = "KAIDO"
      malware_type = "RAT"
      campaign = "KAIDO-EvilSoul-Engine-MaaS-144.172.103.98"
      id = "eb4ef7d6-e3f0-5eea-8211-654d9ccff6fa"
   strings:
      $pipe   = "kaido_dxgi_" ascii wide nocase
      $envvar = "KAIDO_DXGI_PIPE" ascii wide fullword
      $rdr    = "DXGI FrameReader" ascii wide
      $fbk    = "HVNC Capture Loop" ascii wide
      $clone  = "[BrowserClone] Using handle hijacking for locked files..." ascii wide
      $magic  = { 4B 81 3F 44 }
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      (2 of ($pipe, $envvar, $rdr, $fbk, $clone) or ($magic and 1 of ($pipe, $envvar)))
}
```

#### KAIDO Anti-Analysis Sleep Obfuscation + Config Crypto Framing

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1497 (Virtualization/Sandbox Evasion), T1573.001 (Symmetric Cryptography — MODERATE)
**Confidence:** MODERATE
**Rationale:** The developer-left anti-analysis debug string is distinctive but stands alone as a single string; the rule pairs it with the family namespace so both must be present. A secondary/corroborating anchor — the debug string could be stripped from a cleaned build, hence Robustness 2 rather than 3.
**False Positives:** None known — the debug string is family-specific; the rule requires it *and* the namespace, and the AES-GCM framing pattern (12-byte nonce + 16-byte tag) is never a sole anchor.
**Blind Spots:** A release build that removes the developer debug string evades this rule (the namespace rule above still fires); the crypto-framing pattern is common to many AES-GCM implementations and carries no weight alone.
**Validation:** Scan a KAIDO sample carrying the `[ANTI]` debug string — must match; a benign binary embedding a stock AES-GCM library must NOT fire.
**Deployment:** Endpoint AV/EDR file scan; secondary/corroborating rule, not primary detection.

```yara
rule RAT_KAIDO_AntiAnalysis_SleepObfuscation {
   meta:
      description = "Detects the KAIDO RAT via its developer-left anti-analysis debug string referencing sleep obfuscation with mutex and stack detection, used to evade sandbox timing-based detonation checks"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/kaido-quasar-rat-detections/"
      date = "2026-07-03"
      hash1 = "022944768c4326d611fa3edb100eb8277228717a220580e7ffce143341aa39fa"
      hash2 = ""
      hash3 = ""
      family = "KAIDO"
      malware_type = "RAT"
      campaign = "KAIDO-EvilSoul-Engine-MaaS-144.172.103.98"
      id = "683cd96b-bebc-5bcc-8d4c-3aa380acd5d6"
   strings:
      $anti = "[ANTI] Sleep obfuscation ENABLED (fixed: mutex + stack detection + 32MB cap)" ascii wide
      $ns    = "Kaido.Common.Messages" ascii wide fullword
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      $anti and $ns
}
```

---

## Sigma Rules

### Hunting Rules

#### KAIDO Zone.Identifier ADS Self-Deletion (MOTW Bypass)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1553.005 (Mark-of-the-Web Bypass)
**Confidence:** HIGH (behavior) / triage required (attribution)
**Rationale:** The malware reads then deletes its own `Zone.Identifier` alternate data stream shortly after launch, a MOTW bypass. Anchored on the **deletion** event (`category: file_delete`) rather than file creation — a plain `:Zone.Identifier` file-event selector would match every downloaded file (the ADS is created on every download) and is pure baseline noise. Scoping to deletion turns it into a genuine Hunting lead for MOTW-clearing behavior, but self-updating software also clears its own MOTW, so an analyst triages the hits.
**False Positives:**
- Self-updating legitimate software (browsers, some installers) that clears its own Zone.Identifier stream after a user-consented first run.
- Administrative scripts that bulk-clear MOTW on downloaded files.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (FileDelete telemetry), correlated with process creation for the same image.

```yaml
title: KAIDO RAT Self-Deletion of Zone.Identifier Alternate Data Stream
id: d428415f-5926-466a-abcb-5cb91be4d187
status: experimental
description: >-
  Detects a process deleting its own Zone.Identifier alternate data
  stream shortly after launch, a Mark-of-the-Web bypass technique used
  by the KAIDO Quasar-fork RAT to suppress SmartScreen re-checks on
  subsequent executions. Anchored on the file-delete event rather than
  file creation to avoid matching every downloaded file.
references:
    - https://the-hunters-ledger.com/hunting-detections/kaido-quasar-rat-detections/
author: The Hunters Ledger
date: 2026-07-03
tags:
    - attack.defense-impairment
    - attack.t1553.005
    - detection.emerging-threats
logsource:
    category: file_delete
    product: windows
detection:
    selection:
        TargetFilename|endswith: ':Zone.Identifier'
    filter_legit_installer:
        Image|contains:
            - '\Windows\System32\'
            - '\Program Files\Windows Defender\'
    condition: selection and not filter_legit_installer
falsepositives:
    - >-
      Self-updating legitimate software (browsers, some installers) that
      clears its own Zone.Identifier stream after a user-consented first run
    - Administrative scripts that bulk-clear MOTW on downloaded files
level: medium
```

#### KAIDO HVNC DXGI Named-Pipe Creation

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1219 (Remote Access Software), T1113 (Screen Capture — static/structural evidence)
**Confidence:** HIGH (structural anchor); underlying HVNC runtime behavior itself MODERATE (C2-gated, not dynamically triggered)
**Rationale:** The `kaido_dxgi_` named-pipe prefix is a family-specific transport artifact with no known legitimate collision, so today's FP is near-zero — but it is a single operator-chosen literal that a rebuild renames trivially. Durability governs over as-written precision, so this is a Hunting anchor, not a Detection one. The YARA HVNC rule (which requires a multi-string combination) carries the Detection-grade coverage for the same capability.
**False Positives:** Unlikely — the `kaido_dxgi_` pipe-name prefix has not been observed in any legitimate Windows or third-party software to date.
**Deployment:** Endpoint EDR with named-pipe telemetry (Sysmon Event ID 17/18).

```yaml
title: KAIDO RAT HVNC DXGI Named-Pipe Creation
id: 6fadc50c-a64b-4120-b02e-f22516b0c815
status: experimental
description: >-
  Detects creation of a named pipe matching the kaido_dxgi_ prefix used
  by the KAIDO Quasar-fork RAT's HVNC module to stream DXGI-captured
  hidden-desktop frames from the swap-chain hook to the operator's
  reader thread. This pipe is created only when the HVNC capability is
  actively invoked by the operator over C2.
references:
    - https://the-hunters-ledger.com/hunting-detections/kaido-quasar-rat-detections/
author: The Hunters Ledger
date: 2026-07-03
tags:
    - attack.command-and-control
    - attack.t1219
    - attack.collection
    - attack.t1113
    - detection.emerging-threats
logsource:
    category: pipe_created
    product: windows
detection:
    selection:
        PipeName|contains: '\kaido_dxgi_'
    condition: selection
falsepositives:
    - >-
      Unlikely — the kaido_dxgi_ pipe-name prefix has not been observed
      in any legitimate Windows or third-party software to date
level: medium
```

#### KAIDO Install as svchost.exe by Non-System Parent Process

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1036.005 (Match Legitimate Name or Location), T1547.001 (Registry Run Keys / Startup Folder — related persistence, MODERATE)
**Confidence:** MODERATE (install routine recovered from static analysis, not dynamically observed — the malware is C2-gated)
**Rationale:** The RAT installs into `%AppData%\<subdir>\svchost.exe`, masquerading as the Windows service host from a user-writable path. The svchost-in-AppData masquerade is a durable technique pattern, but it is used by many unrelated families and carries a meaningful benign FP, so it is a generic masquerade *hunting* indicator, not a KAIDO-specific detection on its own.
**False Positives:**
- Rare legitimate portable or sideloaded applications that ship a binary literally named `svchost.exe` in a user profile path (unusual but not impossible for poorly-vetted freeware).
- Other unrelated malware families that reuse the same masquerade pattern.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM; pair with the YARA/Suricata KAIDO anchors for family attribution before high-confidence alerting.

```yaml
title: Process Named svchost.exe Executing from AppData Path
id: 08e75208-eb8e-473d-9827-5a59ef4192db
status: experimental
description: >-
  Detects a process named svchost.exe launching from a user-writable
  %AppData% subdirectory rather than the legitimate %SystemRoot%\System32
  location. Observed as the install pattern used by the KAIDO Quasar-fork
  RAT to masquerade as the Windows service host process, but this naming
  and path pattern is also used by other unrelated malware families and
  should be treated as a generic masquerade indicator rather than a
  KAIDO-specific signal on its own.
references:
    - https://the-hunters-ledger.com/hunting-detections/kaido-quasar-rat-detections/
author: The Hunters Ledger
date: '2026-07-03'
tags:
    - attack.stealth
    - attack.t1036.005
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1547.001
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\svchost.exe'
        Image|contains: '\AppData\'
    filter_parent_system:
        ParentImage|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    condition: selection and not filter_parent_system
falsepositives:
    - >-
      Rare legitimate portable or sideloaded applications that ship a
      binary literally named svchost.exe in a user profile path
      (unusual but not impossible for poorly-vetted freeware)
    - Other unrelated malware families that reuse the same masquerade pattern
level: medium
```

---

## Suricata Signatures

### Detection Rules

#### KAIDO TeamKAIDO C2 TLS Certificate Issuer

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1573.001 (Symmetric Cryptography — TLS transport)
**Confidence:** HIGH
**Rationale:** The live C2 host presents a TLS certificate with Issuer O=`TeamKAIDO` (subject CN=`kaido-c2`) paired with JA4X `bbd6cc0fca29_bbd6cc0fca29_795797892f9c`. The issuer org string is operator-branded, sits in the right app-layer buffer (`tls.cert_issuer`), and survives infrastructure rotation — the highest-value fleet-enumeration pivot in the investigation (Censys/Shodan support cert-issuer and JA4X search).
**False Positives:** None known — `TeamKAIDO` as a certificate issuer organization string is a distinctive operator-branded value not shared with legitimate CAs or common self-signed certificate generators.
**Blind Spots:** Evaded if the operator re-issues certificates under a different (or empty) issuer O= string; misses plaintext or non-TLS channels.
**Validation:** Replay a PCAP of a KAIDO TLS handshake presenting the `TeamKAIDO` issuer — must alert; ordinary TLS to a public CA must NOT.
**Deployment:** Network IDS/IPS with TLS certificate inspection (JA3/JA4 fingerprinting recommended as a complementary passive pivot).

```suricata
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"THL KAIDO-EvilSoul-MaaS TeamKAIDO C2 TLS Certificate Issuer (RAT C2 Fleet Indicator)"; flow:established,to_server; tls.cert_issuer; content:"TeamKAIDO"; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000002; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-03, reference https://the-hunters-ledger.com/hunting-detections/kaido-quasar-rat-detections/;)
```

### Hunting Rules

#### KAIDO Quasar Binary Protocol on TCP 4782

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1095 (Non-Application Layer Protocol)
**Confidence:** HIGH for the port/protocol pairing; the rule itself is a port-anchored lead
**Rationale:** The RAT's primary C2 channel is a raw Quasar binary protocol over TCP/4782 with no HTTP layer. TCP/4782 is the Quasar-family default port — a tool-family artifact — but the rule carries no content anchor (the protocol is non-standard and unparseable by Suricata's app-layer engine), so it is a port-based hunting lead rather than an alerting-grade signature: anything else on 4782 will also fire.
**False Positives:** Any legitimate or unrelated service that happens to use TCP/4782 (uncommon but not impossible); the `threshold` limits alert volume per source.
**Deployment:** Network IDS/IPS at perimeter and internal segmentation points; hunt-tune before alerting.

```suricata
alert tcp $HOME_NET any -> $EXTERNAL_NET 4782 (msg:"THL KAIDO-EvilSoul-MaaS Quasar Binary Protocol C2 on TCP 4782 (RAT C2 Channel)"; flow:established,to_server; dsize:>0; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000001; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-03, reference https://the-hunters-ledger.com/hunting-detections/kaido-quasar-rat-detections/;)
```

---

## Coverage Gaps

**Primary C2 domain routed to the IOC feed, not a rule.** `kaidoo.com.br` (and the `c2.` / `www.` siblings, plus the current A-record `179.43.150.50`) are transient atomic indicators: a `dns_query` signature keyed solely on the domain stops detecting the moment the operator rotates it, and removing the literal leaves no behavior to match. They are carried in [`kaido-quasar-rat-iocs.json`](/ioc-feeds/kaido-quasar-rat-iocs.json) (BLOCK action) instead. The secondary `c2.kaidoo.com.br:443` channel is covered there as well — no separate signature is warranted.

**HVNC runtime behavioral rule (hidden-desktop capture chain).** The HVNC module — hidden-desktop creation via `SetThreadDesktop` without `SwitchDesktop`, wholesale browser-profile clone via handle duplication, and DXGI swap-chain capture — is fully recovered from static analysis (DEFINITE/HIGH) but was **not** triggered in the wild during observation: the RAT withholds all post-connection behavior until a valid Quasar handshake completes (T1480). A precise Sysmon/EDR behavioral rule for the desktop-switch API sequence (`CreateDesktop("Default_runhost")` → `SetThreadDesktop` with no matching `SwitchDesktop` call) cannot be written with DEFINITE confidence from static evidence alone, since API-call-sequence telemetry requires the sequence to actually execute. **What would raise confidence:** observing the HVNC command execute would capture the exact API call sequence and process/thread telemetry for the desktop-switch pattern.

**Persistence mechanism (Registry Run key / Scheduled Task / Windows Service).** The install routine references `HKCU\...\Run` registry writes, a scheduled-task install path, and a Windows service install path (T1547.001, T1053.005, T1543.003 — all MODERATE), but none were observed because the RAT never reached the persistence stage. Writing a Sigma rule for a specific registry value name or scheduled task name would require guessing an unobserved parameter, risking either false negatives or unjustified specificity. **What would raise confidence:** observing the RAT past the C2 handshake, long enough for the actual persistence artifact names/paths to be written.

**Process injection into cloned browser processes (T1055, MODERATE).** Decompiled code indicates HVNC reflectively injects a capture DLL into the cloned browser process running on the hidden desktop, but the specific injection API sequence (`CreateRemoteThread`, `QueueUserAPC`, or another technique) was not confirmed. **What would raise confidence:** capturing the injection sequence during HVNC execution via debugger or EDR API-hook telemetry.

**Embedded pinned-certificate SHA1 thumbprint (`0acd8c90641e6e8b085aaf5a541c7ac050a65a4a`).** This value functions as the Quasar AUTHKEY across all three analyzed builds and is a strong static anchor, but is intentionally not a Suricata TLS-fingerprint rule — it is the client-embedded pinned cert used for the RAT's own outbound pinning validation, not the server-presented certificate an IDS observes on the wire. It is carried in the IOC feed as a static anchor.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
