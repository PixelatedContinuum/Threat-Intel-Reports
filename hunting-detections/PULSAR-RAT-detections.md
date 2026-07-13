---
title: "Detection Rules — PULSAR RAT (server.exe)"
date: '2025-12-01'
layout: post
permalink: /hunting-detections/PULSAR-RAT-detections/
hide: true
redirect_from: /hunting-detections/PULSAR-RAT
thumbnail: /assets/images/cards/PULSAR-RAT.png
---

**Campaign:** PULSAR-RAT-185.208.159.182
**Date:** 2025-12-01
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/PULSAR-RAT/

---

## Detection Coverage Summary

Pulsar RAT (analyzed here as `server.exe`) is an actively maintained, rebranded fork of the open-source Quasar RAT, distributed from an open directory at 185.208.159.182 and combining a hidden-VNC (HVNC) module, browser credential harvesting, and a persistence mechanism that abuses the Windows Recovery Environment (WinRE) to survive standard registry-based remediation. This file originally shipped as a single YARA rule alongside a set of Splunk-specific SIEM searches and PowerShell response scripts rather than the site's YARA/Sigma/Suricata format. The searches' underlying behavioral logic — registry RunOnce writes, WinRE partition access, headless process execution, browser credential-file access, and paste-site C2 configuration retrieval — has been reformatted into Sigma below with no new indicators added beyond what the original queries and the companion IOC feed already documented; the hash-only search and the three operational PowerShell scripts have been retired in favor of the equivalent rules and the IOC feed. See Coverage Gaps for the full disposition.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 1 | 0 | T1219 | 0 |
| Sigma | 1 | 4 | T1547.001, T1542.001, T1564.003, T1555.003, T1102.001 | 1 |
| Suricata | 0 | 0 | — | 0 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchors:**
- The six-string YARA combination anchored on the `Pulsar.Common` namespace root — near-zero FP, survives typical recompilation (YARA Detection).
- File writes into `\Recovery\OEM\` — the Windows Recovery Environment persistence path documented as the campaign's most difficult-to-remediate technique, Very Low FP per the companion IOC feed (Sigma Detection).

**Atomics routed to the IOC feed:** the original file's hash-lookup SIEM search keyed solely on the sample's SHA256/SHA1/MD5 — all three are already carried in [`PULSAR-RAT-iocs.json`](/ioc-feeds/PULSAR-RAT-iocs.json) (`file_hashes`), so no feed edit was required. See Coverage Gaps for the disposition of the file's other original non-conforming content.

---

## YARA Rules

### Detection Rules

#### Pulsar RAT Namespace + Module String Combination

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1219 (Remote Access Software)
**Confidence:** HIGH
**Rationale:** The rule requires all six family-specific compiled strings (`$pulsar`, `$hvnc`, `$keylog`, `$msgpack`, `$bcrypt`, `$winre`) — anchored on the `Pulsar.Common` namespace root, the actual class-library identifier of the open-source Pulsar RAT codebase — plus 2 of the 2 surveillance-module strings. No single string is a renameable campaign-specific literal; the combination identifies the codebase itself, which survives typical recompilation (a new C2 config or build date does not change the namespace or module names) and file renaming. The PE32 + 1-2MB filesize gate further constrains matches to builds consistent with the analyzed sample.
**False Positives:** None known — no legitimate .NET application combines the `Pulsar.Common` namespace, an HVNC module, a keylogger, MessagePack serialization, BCryptEncrypt, and a WinRE `Recovery\OEM\` path string; the all-of-six requirement makes incidental collision effectively impossible.
**Blind Spots:** A build that renames the `Pulsar.Common` namespace and re-implements the HVNC/keylogger/credential modules under new names would evade all string anchors; the 1-2MB filesize gate excludes Pulsar builds packed or bundled outside this size range.
**Validation:** Scan the analyzed Pulsar RAT sample (`hash1` below) — all six core strings plus at least 2 of the two surveillance-module strings must match; a benign .NET application that uses MessagePack serialization and calls BCrypt APIs, without the `Pulsar.Common` namespace or the WinRE path string, must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, memory scanning, static triage of unknown MSIL/.NET binaries retrieved from open directories or download links.

```yara
/*
   Yara Rule Set
   Identifier: Pulsar RAT (server.exe)
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule RAT_Pulsar_Critical_Variant {
   meta:
      description = "Detects the Pulsar RAT .NET remote access trojan (server.exe) via a six-string combination anchored on its Pulsar.Common namespace root, HVNC/keylogger/credential modules, and WinRE Recovery\\OEM persistence path reference, combined with a PE32 filesize constraint calibrated to the analyzed 1.5MB build"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/PULSAR-RAT-detections/"
      date = "2025-12-01"
      hash1 = "2c4387ce18be279ea735ec4f0092698534921030aaa69949ae880e41a5c73766"
      hash2 = "dc795961c8e63782fc0f53c08e7ca2e593df99fa"
      hash3 = "b5491b58348600c2766f86a5af2b867f"
      family = "Pulsar RAT"
      malware_type = "RAT"
      campaign = "PULSAR-RAT-185.208.159.182"
      id = "fbc88eb4-454c-56dd-82cb-c3ff718f7291"
   strings:
      $pulsar = "Pulsar.Common" ascii wide
      $hvnc = "HVNC" ascii wide fullword
      $keylog = "KeyLogger" ascii wide fullword
      $msgpack = "MessagePackSerializer" ascii wide
      $bcrypt = "BCryptEncrypt" ascii wide fullword
      $winre = "Recovery\\OEM\\" ascii wide nocase
      $remote_desktop = "RemoteDesktop" ascii wide fullword
      $passwords = "Passwords" ascii wide fullword
   condition:
      uint16(0) == 0x5A4D and
      uint32(uint32(0x3C)) == 0x00004550 and
      filesize > 1MB and filesize < 2MB and
      all of ($pulsar, $hvnc, $keylog, $msgpack, $bcrypt, $winre) and
      2 of ($remote_desktop, $passwords)
}
```

---

## Sigma Rules

### Detection Rules

#### Windows Recovery Environment OEM Directory File Write

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1542.001 (Pre-OS Boot: System Firmware — the technique mapping already established in the companion report for this WinRE persistence behavior)
**Confidence:** HIGH (string/path evidence is direct); underlying WinRE-write behavior itself MODERATE (the companion report rates it "HIGHLY LIKELY" rather than fully confirmed dynamically — the capability is inferred from static string evidence, not an independently triggered live partition write)
**Rationale:** The `\Recovery\OEM\` path is the OS-defined location this specific persistence technique depends on — not a renameable literal but the structural chokepoint of WinRE abuse itself, so the rule survives infrastructure and build changes. The original SPL query also matched a bare `mountvol`-plus-path command-line reference as an independent OR leg; that leg is redundant here, since any command line containing both `mountvol` and a `Recovery\OEM` reference already contains the `Recovery\OEM` substring the file-write rule below keys on. The companion report documents this as the campaign's most difficult-to-remediate persistence mechanism, since it survives standard registry-based cleanup.
**False Positives:** OEM factory-imaging or recovery-partition maintenance tooling that legitimately writes into `Recovery\OEM\` during authorized re-imaging (very low volume on already-deployed production fleets).
**Blind Spots:** A command-line-only reference to `Recovery\OEM` (for example, `mountvol` used to list or navigate the partition without writing a file) is not captured by this file-write-scoped rule; a variant that stages its payload under a differently-named recovery-adjacent directory would also evade it.
**Validation:** Trigger by writing a file into `%SYSTEMDRIVE%\Recovery\OEM\` from a non-OEM-imaging process — must alert; a Windows Update or OEM recovery-tool-initiated write during an authorized re-imaging workflow must NOT fire.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (FileCreate telemetry); prioritize for immediate triage given the CRITICAL severity and very low expected false-positive volume.

```yaml
title: Windows Recovery Environment OEM Directory File Write
id: 7845b2e3-1dea-4acf-8571-4ca3bc1981bc
status: experimental
description: >-
  Detects a file being written into the Recovery\OEM directory,
  consistent with abuse of the Windows Recovery Environment (WinRE) for
  persistence that survives standard registry-based remediation. This
  path is not routinely written to outside OEM factory-imaging or
  recovery-partition maintenance workflows.
references:
    - https://the-hunters-ledger.com/hunting-detections/PULSAR-RAT-detections/
    - https://the-hunters-ledger.com/reports/PULSAR-RAT/
author: The Hunters Ledger
date: '2025-12-01'
tags:
    - attack.persistence
    - attack.stealth
    - attack.t1542.001
    - detection.emerging-threats
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\Recovery\OEM\'
    condition: selection
falsepositives:
    - >-
      OEM factory-imaging or system-recovery tooling that legitimately
      writes into the Recovery\OEM path during authorized re-imaging or
      recovery-partition maintenance
level: high
```

### Hunting Rules

#### Registry RunOnce Key Value Set

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)
**Confidence:** MODERATE
**Rationale:** Sysmon/EDR registry-set telemetry on any `CurrentVersion\RunOnce` key write is a durable technique-level signal that survives campaign infrastructure changes, since the OS-defined key path itself carries the detection value rather than any campaign-specific literal. The selector has no value-name or writing-process filter, and RunOnce — while used by fewer legitimate installers than the standard Run key — does see real deployment/update-tooling use, so this is scoped to Hunting rather than alerting-grade.
**False Positives:** Software installers, patch-management, and deployment tooling (for example, SCCM/Intune post-install scripts) that use RunOnce for legitimate reboot-continuation actions.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (registry-set telemetry); analyst review of hits, cross-referenced against the WinRE rule above and the IOC feed's registry indicators for higher-confidence correlation.

```yaml
title: Registry RunOnce Key Value Set
id: b585d269-f6ab-4f38-a982-9c7dddf7adaa
status: experimental
description: >-
  Detects a value being set under a CurrentVersion\RunOnce registry key,
  consistent with the RunOnce-based persistence used by the Pulsar RAT
  campaign for both system-wide and per-user autostart execution.
  RunOnce keys are used by fewer legitimate installers than the standard
  Run key, but some deployment and update tooling still uses them for
  reboot-continuation actions, so this is a broad technique-level lead
  rather than a family-specific signature.
references:
    - https://the-hunters-ledger.com/hunting-detections/PULSAR-RAT-detections/
author: The Hunters Ledger
date: '2025-12-01'
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1547.001
    - detection.emerging-threats
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\CurrentVersion\RunOnce\'
    condition: selection
falsepositives:
    - >-
      Software installers and deployment/update tooling that use
      RunOnce for legitimate reboot-continuation actions
level: medium
```

#### Headless Console Host or Command Shell Execution Flag

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1564.003 (Hide Artifacts: Hidden Window)
**Confidence:** MODERATE
**Rationale:** The `--headless`/`/headless` flag combination on `conhost`/`cmd.exe` is a durable anti-forensic launch pattern that survives campaign infrastructure changes, but the same pattern is used by legitimate CI/build tooling and Electron-based applications — a limitation the original analysis already identified and left untightened for lack of a confirmed Pulsar-specific parent-process anchor. Scoped to Hunting with `level: low` accordingly.
**False Positives:** Legitimate CI/build tooling and Electron-based applications that launch a console host or command shell headlessly.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (process_creation with command line); analyst review, prioritizing hits with an unusual parent process or an accompanying network connection.

```yaml
title: Headless Console Host or Command Shell Execution Flag
id: 0d751112-ebbe-497a-af7d-32b4b2672f83
status: experimental
description: >-
  Detects a conhost or cmd.exe command line carrying a --headless or
  /headless flag, used by the Pulsar RAT loader chain to run without a
  visible console window. The same flag pattern also appears in
  legitimate CI/build tooling and some Electron-based applications, so
  this is a broad hunting lead rather than a family-specific signature;
  no Pulsar-specific parent-process anchor was confirmed for this
  campaign.
references:
    - https://the-hunters-ledger.com/hunting-detections/PULSAR-RAT-detections/
author: The Hunters Ledger
date: '2025-12-01'
tags:
    - attack.stealth
    - attack.t1564.003
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection_conhost:
        CommandLine|contains|all:
            - 'conhost'
            - '--headless'
    selection_cmd:
        CommandLine|contains|all:
            - 'cmd.exe'
            - '/headless'
    condition: 1 of selection_*
falsepositives:
    - >-
      Legitimate CI/build tooling and Electron-based applications that
      launch a console host or command shell headlessly
level: low
```

#### Non-Browser Process Accessing Browser Credential Store Files

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1555.003 (Credentials from Password Stores: Web Browsers)
**Confidence:** MODERATE
**Rationale:** The specific credential-store filenames (`Login Data`, `logins.json`, `key4.db`) combined with a NOT-browser-process filter is a genuine multi-condition selector encoding a recognized technique rather than a bare IOC, and it survives campaign infrastructure changes since the filenames and browser process list are OS/application-defined, not attacker-chosen. The companion IOC feed rates this behavior's false-positive risk "Medium" (backup, sync, and profile-migration tools also touch these files), so it is scoped to Hunting rather than Detection.
**False Positives:** Browser-sync, backup, profile-migration, or endpoint-security scanning tools that legitimately read these credential-store files.
**Deployment:** Endpoint EDR with file-access telemetry; analyst review of hits, particularly any accompanying process with no legitimate business reason to read browser profile data.

```yaml
title: Non-Browser Process Accessing Browser Credential Store Files
id: b1990326-898e-4188-8336-6d3c1d990934
status: experimental
description: >-
  Detects a process other than a known browser executable accessing a
  browser credential-store file (Chromium Login Data or Firefox
  logins.json/key4.db), consistent with credential-theft modules that
  read these files directly rather than through the browser's own
  process.
references:
    - https://the-hunters-ledger.com/hunting-detections/PULSAR-RAT-detections/
author: The Hunters Ledger
date: '2025-12-01'
tags:
    - attack.credential-access
    - attack.t1555.003
    - detection.emerging-threats
logsource:
    category: file_access
    product: windows
detection:
    selection:
        TargetFilename|endswith:
            - '\Login Data'
            - '\logins.json'
            - '\key4.db'
    filter_browsers:
        Image|endswith:
            - '\chrome.exe'
            - '\firefox.exe'
            - '\msedge.exe'
            - '\opera.exe'
            - '\brave.exe'
    condition: selection and not filter_browsers
falsepositives:
    - >-
      Browser-sync, backup, profile-migration, or endpoint-security
      scanning tools that legitimately read these credential-store
      files
level: medium
```

#### Connection to Public Paste-Hosting Service Domain

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1102.001 (Web Service: Dead Drop Resolver)
**Confidence:** MODERATE
**Rationale:** Public paste-hosting services used as a dead-drop resolver for dynamic C2 configuration is a durable technique-level signal — the operator can swap which paste service or paste ID they use without evading the rule's domain list, and the technique doesn't depend on infrastructure the operator owns. The companion IOC feed explicitly rates the false-positive risk for this behavior "High," since these are widely used legitimate developer services; the original SPL query's `count > 5` volume threshold is not reproduced here as a formal Sigma correlation (a single-event selection keeps the rule simple for what is already an explicitly broad Hunting lead), but should be applied during triage.
**False Positives:** Legitimate developer or administrative use of public paste services to share code, logs, or configuration snippets.
**Deployment:** Proxy/DNS/network monitoring; analyst review with a volume/frequency threshold applied during triage (the original analysis used more than five connections in a lookback window as an informal cutoff) and correlation against the campaign's other indicators before any action.

```yaml
title: Connection to Public Paste-Hosting Service Domain
id: d7120dfa-2ad3-4215-8262-09344861e858
status: experimental
description: >-
  Detects a process connecting to a public paste-hosting service
  (Pastebin, Paste.ee, Hastebin), consistent with the dead-drop resolver
  pattern the Pulsar RAT campaign uses to retrieve its dynamic C2
  configuration from an attacker-controlled paste. These services are
  also used for entirely legitimate purposes (developers sharing code,
  logs, or configuration snippets), so this is a broad hunting lead and
  should be correlated with process context and repeated-access volume
  rather than alerted on directly.
references:
    - https://the-hunters-ledger.com/hunting-detections/PULSAR-RAT-detections/
author: The Hunters Ledger
date: '2025-12-01'
tags:
    - attack.command-and-control
    - attack.t1102.001
    - detection.emerging-threats
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationHostname|contains:
            - 'pastebin.com'
            - 'paste.ee'
            - 'hastebin.com'
    condition: selection
falsepositives:
    - >-
      Legitimate developer or administrative use of public paste
      services to share code, logs, or configuration snippets
level: low
```

---

## Coverage Gaps

**Hash-only SIEM search routed as an atomic, not a rule.** The original file's "Hunt for File Hashes" Splunk query matched only the sample's SHA256/SHA1/MD5 with no behavioral component — per the tiering rubric's routing test (removing the literal detects nothing), this is an IOC-feed entry, not a rule. All three hash values are already present in [`PULSAR-RAT-iocs.json`](/ioc-feeds/PULSAR-RAT-iocs.json) (`file_hashes`); no feed edit was required.

**PowerShell response/verification scripts removed — not detection rules.** The original file included three PowerShell scripts: a live SHA256 scan across the C: drive, a RunOnce registry check, and a WinRE partition verification tool that included incident-response guidance ("engage a security specialist," "do not mount without forensic guidance"). These are read-only operational tools an analyst runs on demand, not continuous detection logic, and the WinRE script's step-by-step response guidance does not belong in a published detection-rules file. Their detective value is already covered by rules in this file: the hash scan by the IOC feed's `file_hashes`, the RunOnce check by the Registry RunOnce Key Value Set Sigma rule (Hunting), and the WinRE check by the Windows Recovery Environment OEM Directory File Write Sigma rule (Detection).

**Splunk-specific query syntax reformatted to Sigma.** The original file expressed its behavioral hunting logic as raw Splunk SPL (`index=windows EventCode=...`) rather than the site's vendor-neutral YARA/Sigma/Suricata format. The underlying indicators were not changed — each Sigma rule in this file reproduces the same field logic as its source SPL query — but the platform-specific syntax has been replaced with Sigma per the site's third-party-provider format standard.

**WinRE Sigma rule covers file-write telemetry only.** The original SPL query also matched a bare command-line reference to `Recovery\OEM` (including a `mountvol`-plus-path combination) independent of any file write. The Sigma rule in this file is scoped to `file_event`/`TargetFilename` — the higher-fidelity signal that a file was actually written into the partition — so a command-line-only reference (for example, `mountvol` used to list or navigate without a subsequent write) would not be captured. **What would enable a companion rule:** confirmed process-creation telemetry showing the exact command-line pattern used to access or write into the partition.

**No Suricata coverage.** The original file contained no network-signature content of any kind (no IP, port, or protocol-level rule), so none is authored here. The C2/download infrastructure (185.208.159.182) and the paste-site domains are carried in the IOC feed and the Sigma network-connection rule above respectively; a durable protocol-level signature would require captured C2 traffic beyond the HTTPS-to-pastebin pattern already covered.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
