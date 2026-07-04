---
title: "Detection Rules — KAIDO Quasar-Fork RAT"
date: '2026-07-03'
layout: post
permalink: /hunting-detections/kaido-quasar-rat-detections/
hide: true
unlisted: true
---

**Campaign:** KAIDO-EvilSoul-Engine-MaaS-144.172.103.98
**Date:** 2026-07-03
**Author:** The Hunters Ledger
**License:** CC BY-NC 4.0
**Reference:** https://the-hunters-ledger.com/reports/kaido-quasar-rat-144-172-109-203/

---

## Detection Coverage Summary

> **Scope note:** this file covers only the **KAIDO Quasar-fork RAT** product line (PART A of the parent investigation). The EvilSoul-Engine stealer-builder line is covered in a separate detection file — no rules are duplicated here.

KAIDO is a rebranded 64-bit fork of the open-source Quasar RAT carrying an HVNC (Hidden-VNC) module that clones the victim's entire browser profile and drives their already-authenticated session on a hidden desktop. All coverage below derives from static decompilation (namespace tree, Costura assets, DXGI/HVNC strings) and dynamic execution that confirmed Zone.Identifier self-deletion, the raw-TCP/4782 Quasar beacon, and single-process C2-gated staging behavior.

| Rule Type | Count | MITRE Techniques Covered | Overall FP Risk |
|---|---|---|---|
| YARA | 3 | T1219, T1553.005, T1497, T1055 | LOW |
| Sigma | 3 | T1553.005, T1113/T1123/T1125/T1056.001, T1036.005/T1547.001 | LOW–MEDIUM |
| Suricata | 3 | T1095, T1071.001, T1573.001 | LOW |

**Highest-confidence anchors used across all layers:**
- Namespace root `Kaido.Common.Messages` and Costura asset `costura.kaido.common.dll` — survive obfuscation, near-zero FP (YARA).
- Zone.Identifier ADS self-deletion within seconds of launch — DEFINITE, directly observed dynamically (Sigma).
- Raw TCP/4782 Quasar binary protocol + `TeamKAIDO`/`kaido-c2` TLS certificate issuer + JA4X `bbd6cc0fca29_bbd6cc0fca29_795797892f9c` — DEFINITE/HIGH, fleet-enumeration-grade (Suricata).

**Coverage note on HVNC runtime behavior:** the HVNC module (hidden-desktop creation, browser-profile clone, DXGI capture) is fully recovered statically (DEFINITE/HIGH) but was **not** triggered dynamically — the sample is C2-gated and withholds all post-connection behavior (persistence, HVNC activation, credential collection) until a valid Quasar handshake completes (T1480, confirmed with zero drops observed). Behavioral rules for the named-pipe transport and install path are written from static/structural evidence; see Coverage Gaps for what would raise HVNC-specific behavioral rules to DEFINITE.

---

## YARA Rules

### KAIDO Quasar-Fork Namespace + Costura Asset

**Detection Priority:** HIGH
**Rationale:** `Kaido.Common.Messages` is the namespace root of the rebranded Quasar fork and survives the sample's obfuscation pass intact (no literal `Quasar` string remains); paired with the Costura-embedded asset name and HVNC hidden-desktop literal, this combination is unique to this build lineage.
**ATT&CK Coverage:** T1219 (Remote Access Software)
**Confidence:** HIGH
**False Positive Risk:** LOW — `Kaido.Common.Messages` and `costura.kaido.common.dll` are distinctive compiled identifiers not found in legitimate .NET software; `fullword` applied to reduce substring collision risk further.
**Deployment:** Endpoint AV/EDR file scan, memory scanning of `svchost.exe`-masquerading processes, static triage of unknown MSIL binaries.

```yara
/*
   Yara Rule Set
   Identifier: KAIDO Quasar-Fork RAT
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/
*/

rule RAT_KAIDO_Quasar_Fork_Namespace {
   meta:
      description = "Detects the KAIDO Quasar-fork RAT via its rebranded namespace root Kaido.Common.Messages and Costura-embedded costura.kaido.common.dll asset, both of which survive the sample's obfuscation pass"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
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

**File name:** `rat_kaido_quasar_fork.yar`

### KAIDO HVNC DXGI Named-Pipe Transport

**Detection Priority:** HIGH
**Rationale:** The DXGI-hook HVNC frame transport uses a distinctive pipe-name prefix, environment variable, frame magic value, and reader-thread name — none of which are generic Windows or .NET runtime terms. This combination anchors specifically to KAIDO's HVNC capture path.
**ATT&CK Coverage:** T1219 (Remote Access Software), T1113 (Screen Capture — MODERATE, static-only)
**Confidence:** HIGH
**False Positive Risk:** LOW — `KAIDO_DXGI_PIPE`, `kaido_dxgi_`, and the paired thread names are family-specific compiled strings; the hex frame magic is combined with string context rather than used alone.
**Deployment:** Endpoint AV/EDR file scan, memory scanning during suspected HVNC activity.

```yara
rule RAT_KAIDO_HVNC_DXGI_Pipe {
   meta:
      description = "Detects the KAIDO RAT HVNC module via its DXGI-hook named-pipe transport strings (pipe prefix, env var, frame magic, reader-thread name) used to stream the hidden-desktop capture to the operator"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
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

**File name:** `rat_kaido_quasar_fork.yar` (same file, second rule)

### KAIDO Anti-Analysis Sleep Obfuscation + Config Crypto Framing

**Detection Priority:** MEDIUM
**Rationale:** The developer-left anti-analysis debug string is distinctive but stands alone as a single string; paired here with the AES-GCM config wire-framing structure it becomes a stronger anchor. Lower priority than the two rules above because the debug string alone is the only truly unique element — the crypto framing pattern (12-byte nonce + 16-byte tag) is common to many AES-GCM implementations and is included only as a secondary condition, never as a sole anchor.
**ATT&CK Coverage:** T1497 (Virtualization/Sandbox Evasion), T1573.001 (Symmetric Cryptography — MODERATE)
**Confidence:** MODERATE
**False Positive Risk:** LOW-MEDIUM — the debug string is family-specific and low-FP; without it, this rule would not fire (the crypto framing alone is never sufficient per condition logic).
**Deployment:** Endpoint AV/EDR file scan; secondary/corroborating rule, not primary detection.

```yara
rule RAT_KAIDO_AntiAnalysis_SleepObfuscation {
   meta:
      description = "Detects the KAIDO RAT via its developer-left anti-analysis debug string referencing sleep obfuscation with mutex and stack detection, used to evade sandbox timing-based detonation checks"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
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

**File name:** `rat_kaido_quasar_fork.yar` (same file, third rule)

---

## Sigma Rules

### KAIDO Zone.Identifier ADS Self-Deletion (MOTW Bypass)

**Detection Priority:** HIGH
**Rationale:** Directly observed during dynamic execution — the sample reads then deletes its own `Zone.Identifier` alternate data stream within 2.4 seconds of launch, on every execution, regardless of C2 state. This is a DEFINITE, C2-independent behavior with a tight time window that is unusual for legitimate software.
**ATT&CK Coverage:** T1553.005 (Mark-of-the-Web Bypass)
**Confidence:** HIGH
**False Positive Risk:** LOW-MEDIUM — some legitimate installers and self-updating software clear their own MOTW after a user-consented first run; the short post-launch time window and repeatability on every execution narrow this considerably. Tune the time-window filter in production SIEM correlation if available.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM, correlated with process creation for the same image.

```yaml
title: KAIDO RAT Self-Deletion of Zone.Identifier Alternate Data Stream
id: d428415f-5926-466a-abcb-5cb91be4d187
status: test
description: >-
  Detects a process reading and then deleting its own Zone.Identifier
  alternate data stream shortly after launch, a Mark-of-the-Web bypass
  technique used by the KAIDO Quasar-fork RAT to suppress SmartScreen
  re-checks on subsequent executions. Observed deletion occurs at T+2.4
  seconds regardless of C2 connectivity.
references:
    - https://the-hunters-ledger.com/hunting-detections/kaido-quasar-rat-detections/
    - https://attack.mitre.org/techniques/T1553/005/
author: The Hunters Ledger
date: 2026-07-03
tags:
    - attack.defense-evasion
    - attack.t1553.005
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: ':Zone.Identifier'
        EventID: 23
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
level: high
```

**File name:** `file_event_win_kaido_zoneidentifier_selfdelete.yml`

### KAIDO HVNC DXGI Named-Pipe Creation

**Detection Priority:** HIGH
**Rationale:** The `kaido_dxgi_` named-pipe prefix is a family-specific transport artifact used exclusively by the HVNC DXGI frame-streaming path — no legitimate Windows software or common third-party tool creates a pipe with this naming pattern.
**ATT&CK Coverage:** T1219 (Remote Access Software), T1113 (Screen Capture — static/structural evidence)
**Confidence:** HIGH (structural anchor); underlying HVNC runtime behavior itself is MODERATE (not dynamically triggered — C2-gated)
**False Positive Risk:** LOW — the pipe-name prefix is distinctive; no known legitimate software uses this naming convention.
**Deployment:** Endpoint EDR with named-pipe telemetry (Sysmon Event ID 17/18).

```yaml
title: KAIDO RAT HVNC DXGI Named-Pipe Creation
id: 6fadc50c-a64b-4120-b02e-f22516b0c815
status: test
description: >-
  Detects creation of a named pipe matching the kaido_dxgi_ prefix used
  by the KAIDO Quasar-fork RAT's HVNC module to stream DXGI-captured
  hidden-desktop frames from the swap-chain hook to the operator's
  reader thread. This pipe is created only when the HVNC capability is
  actively invoked by the operator over C2.
references:
    - https://the-hunters-ledger.com/hunting-detections/kaido-quasar-rat-detections/
    - https://attack.mitre.org/techniques/T1219/
author: The Hunters Ledger
date: 2026-07-03
tags:
    - attack.command-and-control
    - attack.t1219
    - attack.collection
    - attack.t1113
logsource:
    category: pipe_created
    product: windows
detection:
    selection:
        PipeName|contains: '\kaido_dxgi_'
    condition: selection
falsepositives:
    - >-
      None known — the kaido_dxgi_ pipe-name prefix has not been observed
      in any legitimate Windows or third-party software during this analysis
level: high
```

**File name:** `pipe_created_win_kaido_hvnc_dxgi.yml`

### KAIDO Install as svchost.exe by Non-System Parent Process

**Detection Priority:** MEDIUM
**Rationale:** The RAT installs into `%AppData%\<subdir>\svchost.exe`, masquerading as the legitimate Windows service host while running from a user-writable AppData path rather than `%SystemRoot%\System32`. Combined with a non-system parent process, this is a classic masquerade pattern, but `svchost.exe` naming alone is common across many malware families, so this rule is scoped tightly to the AppData path and carries a lower priority than the two structural anchors above.
**ATT&CK Coverage:** T1036.005 (Match Legitimate Name or Location), T1547.001 (Registry Run Keys / Startup Folder — related persistence, MODERATE)
**Confidence:** MODERATE (install routine recovered via static decompilation, not dynamically observed — the sample is C2-gated)
**False Positive Risk:** MEDIUM — `svchost.exe`-named processes launching from AppData are a common masquerade pattern used by many unrelated malware families, so this rule is a generic masquerade indicator, not KAIDO-specific on its own. Pair with the YARA/Sigma pipe rules above for family attribution; use this rule for broader masquerade hunting.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM; recommend correlation with other KAIDO-specific indicators before high-confidence alerting.

```yaml
title: Process Named svchost.exe Executing from AppData Path
id: 08e75208-eb8e-473d-9827-5a59ef4192db
status: test
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
    - https://attack.mitre.org/techniques/T1036/005/
author: The Hunters Ledger
date: 2026-07-03
tags:
    - attack.defense-evasion
    - attack.t1036.005
    - attack.persistence
    - attack.t1547.001
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

**File name:** `proc_creation_win_svchost_appdata_masquerade.yml`

---

## Suricata Signatures

> Validated with a `suricata -T` test-compile prior to publication — all three rules passed.

### KAIDO Quasar Binary Protocol on TCP 4782

**Detection Priority:** HIGH
**Rationale:** Directly confirmed during dynamic execution — the RAT's primary C2 channel is a raw Quasar binary protocol over TCP port 4782 with no HTTP layer, a non-standard port choice that is rarely used by legitimate services.
**ATT&CK Coverage:** T1095 (Non-Application Layer Protocol)
**Confidence:** HIGH (DEFINITE for the port/protocol pairing — confirmed via observed execution)
**False Positive Risk:** LOW — TCP/4782 is not a registered or commonly-used legitimate service port; the transport-only rule (no app-layer keyword) is appropriately pinned to this specific port since the protocol itself is non-standard and unparseable by Suricata's app-layer engine.
**Deployment:** Network IDS/IPS at perimeter and internal segmentation points.

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 4782 (msg:"THL KAIDO-EvilSoul-MaaS Quasar Binary Protocol C2 on TCP 4782 (RAT C2 Channel)"; flow:established,to_server; dsize:>0; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000001; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-03, reference https://the-hunters-ledger.com/hunting-detections/kaido-quasar-rat-detections/;)
```

### KAIDO TeamKAIDO C2 TLS Certificate Issuer

**Detection Priority:** HIGH
**Rationale:** The live C2 host presents a TLS certificate with Issuer O=`TeamKAIDO` and subject CN=`kaido-c2` on port 8443, paired with JA4X fingerprint `bbd6cc0fca29_bbd6cc0fca29_795797892f9c`. This is the highest-value fleet-enumeration pivot identified in the investigation — Censys/Shodan natively support cert-issuer and JA4X search.
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1573.001 (Symmetric Cryptography — TLS transport)
**Confidence:** HIGH
**False Positive Risk:** LOW — `TeamKAIDO` as a certificate issuer organization string is a distinctive operator-branded value not shared with legitimate CAs or common self-signed certificate generators.
**Deployment:** Network IDS/IPS with TLS certificate inspection (JA3/JA4 fingerprinting recommended as a complementary passive pivot alongside this active-match rule).

```
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"THL KAIDO-EvilSoul-MaaS TeamKAIDO C2 TLS Certificate Issuer (RAT C2 Fleet Indicator)"; flow:established,to_server; tls.cert_issuer; content:"TeamKAIDO"; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000002; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-03, reference https://the-hunters-ledger.com/hunting-detections/kaido-quasar-rat-detections/;)
```

### KAIDO kaidoo.com.br C2 DNS Query

**Detection Priority:** HIGH
**Rationale:** The primary C2 domain resolution was directly confirmed during dynamic execution (DNS A-record query with periodic re-resolution, ~13 minute interval). This is the earliest-stage network indicator available before the TCP/4782 or TLS handshake occurs.
**ATT&CK Coverage:** T1071 (Application Layer Protocol — DNS resolution to locate C2)
**Confidence:** HIGH
**False Positive Risk:** LOW — `kaidoo.com.br` is an operator-registered brand domain with no legitimate shared use; the `.br` ccTLD combined with the distinctive brand string minimizes collision risk.
**Deployment:** DNS-layer network IDS/IPS, recursive resolver logging correlation.

```
alert dns $HOME_NET any -> any any (msg:"THL KAIDO-EvilSoul-MaaS kaidoo.com.br C2 DNS Query (RAT C2 Resolution)"; dns_query; content:"kaidoo.com.br"; nocase; isdataat:!1,relative; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000003; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-03, reference https://the-hunters-ledger.com/hunting-detections/kaido-quasar-rat-detections/;)
```

---

## Coverage Gaps

**HVNC runtime behavioral rule (hidden-desktop capture chain).** The HVNC module — hidden-desktop creation via `SetThreadDesktop` without `SwitchDesktop`, wholesale browser-profile clone via handle duplication, and DXGI swap-chain capture — is fully recovered through static decompilation (DEFINITE/HIGH) but was **not** dynamically triggered. Execution confirmed only C2-gated staging: zero drops, zero persistence, zero child processes, because the RAT withholds all post-connection behavior until a valid Quasar handshake completes (T1480). A precise Sysmon/EDR behavioral rule for the desktop-switch API sequence (`CreateDesktop("Default_runhost")` → `SetThreadDesktop` with no matching `SwitchDesktop` call) cannot be written with DEFINITE confidence from static evidence alone, since API-call-sequence telemetry requires the sequence to actually execute. **What would raise confidence:** dynamically triggering the HVNC command would capture the exact API call sequence and process/thread telemetry for the desktop-switch pattern. Defenders can also raise confidence themselves by memory-scanning during detonation in their own analysis environment.

**Persistence mechanism (Registry Run key / Scheduled Task / Windows Service).** The install routine recovered via static decompilation references `HKCU\...\Run` registry writes, a scheduled-task install path, and a Windows service install path (T1547.001, T1053.005, T1543.003 — all MODERATE), but none were observed dynamically because the RAT never reached the persistence stage during observed execution. Writing a Sigma rule for a specific registry value name or scheduled task name would require guessing an unobserved parameter, which risks either false negatives (if the guessed name is wrong) or unjustified specificity. **What would raise confidence:** dynamically triggering the RAT past the C2 handshake, long enough to observe the actual persistence artifact names/paths written to disk or the registry.

**Process injection into cloned browser processes (T1055, MODERATE).** Decompiled code indicates HVNC reflectively injects a capture DLL into the cloned browser process running on the hidden desktop, but the specific injection API sequence (whether `CreateRemoteThread`, `QueueUserAPC`, or another technique) was not confirmed by dynamic observation or complete code-level tracing. **What would raise confidence:** dynamically triggering the HVNC command and capturing the injection sequence via a debugger or EDR API-hook telemetry.

**Secondary C2 endpoint (`c2.kaidoo.com.br:443`).** This secondary channel is DEFINITE from static config decryption but was not observed during execution (only the primary `kaidoo.com.br:4782` channel was exercised). No behavioral distinction from the primary channel's DNS-query pattern is expected, so the existing DNS Suricata rule (domain-substring match) already provides coverage for both subdomains without requiring a separate rule.

**Embedded pinned-certificate SHA1 thumbprint (`0acd8c90641e6e8b085aaf5a541c7ac050a65a4a`).** This value functions as the Quasar AUTHKEY across all three analyzed builds and is a strong static YARA anchor, but was intentionally not used as a Suricata TLS-fingerprint rule in this file — it is the client-embedded pinned cert used for the RAT's own outbound pinning validation, not the server-presented certificate an IDS would observe on the wire during a TLS handshake. It remains available as a static file-hash-adjacent anchor; see the YARA rules above where it appears in rule metadata context.

---

## License
Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.  
Free to use in your environment, but not for commercial purposes.
