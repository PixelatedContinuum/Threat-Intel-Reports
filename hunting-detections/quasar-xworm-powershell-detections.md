---
title: "Detection Rules — QuasarRAT / Xworm / PowerShell Loader"
date: '2025-10-17'
layout: post
permalink: /hunting-detections/quasar-xworm-powershell-detections/
hide: true
redirect_from: /hunting-detections/quasar-xworm-detections
thumbnail: /assets/images/cards/quasar-xworm-powershell.png
---

**Campaign:** QuasarRAT-Xworm-PowerShell-Loader-193.233.164.21
**Date:** 2025-10-17
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/hunting-detections/quasar-xworm-powershell-detections/

---

## Detection Coverage Summary

This campaign chains a VBScript dropper, a PowerShell loader that pulls a payload disguised as an image (`update.png`), a Microsoft Defender exclusion script, and QuasarRAT/Xworm implants. Coverage here is intentionally scoped to the two behavioral leads that survive an infrastructure change; the campaign's atomic network indicators (C2 IP, DuckDNS domain, payload URL) are carried in the IOC feed rather than as standalone signatures.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 0 | 1 | T1562.001 | 0 |
| Sigma | 0 | 1 | T1059.001, T1105 | 0 |
| Suricata | 0 | 0 | — | 1 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Atomics routed to the IOC feed:** the C2 IP `193.233.164.21`, the DuckDNS C2 domain `dns4up.duckdns.org`, and the payload URL `hxxp://193.233.164.21/update.png` are transient indicators carried in [`quasar-xworm-powershell-iocs.json`](/ioc-feeds/quasar-xworm-powershell-iocs.json) rather than as standalone network signatures — a rule keyed solely on the domain stops detecting the moment the operator rotates it, and `/update.png` alone fires on ubiquitous benign traffic (removing the literal leaves nothing to match). Block them via the feed.

---

## YARA Rules

### Hunting Rules

#### PowerShell Microsoft Defender Exclusion Script

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1562.001 (Impair Defenses: Disable or Modify Tools)
**Confidence:** MODERATE
**Rationale:** Matches a PowerShell script that adds Microsoft Defender exclusions for the payload path and the loader's helper processes. The `Add-MpPreference -ExclusionPath` / `-ExclusionProcess` combination is a real Defender-tampering technique, but it is also used by legitimate administrators and security tooling, so it is a broad hunting lead rather than a family-specific alerting signature. The build-specific `update.png` literal narrows the current sample but is trivially renamed, so the rule keys on the technique, not the campaign.
**False Positives:**
- Legitimate administrator or endpoint-management scripts that add Defender exclusions for approved software.
- Security or backup products that register their own process/path exclusions during installation.
**Deployment:** Endpoint AV/EDR file scan of dropped `.ps1` scripts; SIEM correlation with `Add-MpPreference` command-line events (Sysmon/PowerShell script-block logging).

```yara
/*
   Yara Rule Set
   Identifier: QuasarRAT / Xworm PowerShell Loader
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule PS_Defender_Exclusion_Quasar_Xworm {
   meta:
      description = "Detects a PowerShell Microsoft Defender exclusion script used by the QuasarRAT/Xworm PowerShell loader campaign to whitelist the payload path and loader helper processes (powershell.exe, wscript.exe, cmd.exe, cvtres.exe)"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/quasar-xworm-powershell-detections/"
      date = "2025-10-17"
      hash1 = "4ae132de21ab60da7d562f4c2d1f6d26650bbc0c80c542537bc7eb973d05f127"
      hash2 = "153a6d225dffd61913f37ac68d19eb61c1c35374f03b9f94faf28a9bb16ede4b"
      family = "QuasarRAT/Xworm"
      malware_type = "Loader"
      campaign = "QuasarRAT-Xworm-PowerShell-Loader-193.233.164.21"
      id = "31039cfb-dcf2-4e86-87c2-bf063031b16e"
   strings:
      $a = "Add-MpPreference" ascii wide nocase
      $b = "-ExclusionPath" ascii wide nocase
      $c = "-ExclusionProcess" ascii wide nocase
      $d = "update.png" ascii wide nocase
   condition:
      all of them
}
```

---

## Sigma Rules

### Hunting Rules

#### VBScript-Spawned PowerShell In-Memory Payload Download

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1059.001 (PowerShell), T1105 (Ingress Tool Transfer)
**Confidence:** MODERATE
**Rationale:** Detects a PowerShell process spawned by `wscript.exe` that uses .NET `HttpClient` calls to pull a payload disguised as an image, consistent with the QuasarRAT/Xworm loader chain. The `wscript.exe` → `powershell.exe` ancestry combined with in-memory `HttpClient`/`GetAsync` is a genuine behavioral lead, but its as-written precision leans on the renameable `update.png` literal and the behavior-only form has meaningful benign hitters (admin and deployment tooling), so it is scoped to Hunting rather than alerting-grade. Level recalibrated from `high` to `medium` accordingly.
**False Positives:**
- Legitimate administrative or software-deployment scripts that launch PowerShell from a Windows Script Host wrapper and fetch content over HTTP.
- Internal automation that uses .NET `HttpClient` from PowerShell to download update artifacts.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (process_creation with command line), triaged by an analyst; pair with the payload-URL and C2 indicators in the IOC feed for confirmation.

```yaml
title: VBScript-Spawned PowerShell In-Memory Payload Download
id: ea533822-dc1e-40c2-8f04-e3742393c93e
status: experimental
description: >-
  Detects a PowerShell process spawned by wscript.exe that uses .NET
  HttpClient calls to download a payload disguised as an image file,
  consistent with the QuasarRAT/Xworm PowerShell loader chain. Broadly
  scoped — an analyst should triage the hits and confirm against the
  campaign's payload-URL and C2 indicators in the IOC feed.
references:
    - https://the-hunters-ledger.com/hunting-detections/quasar-xworm-powershell-detections/
author: The Hunters Ledger
date: '2025-10-17'
tags:
    - attack.execution
    - attack.t1059.001
    - attack.command-and-control
    - attack.t1105
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\wscript.exe'
        Image|endswith: '\powershell.exe'
        CommandLine|contains|all:
            - 'System.Net.Http.HttpClient'
            - 'GetAsync'
            - 'update.png'
    condition: selection
falsepositives:
    - >-
      Legitimate administrative or software-deployment scripts that
      launch PowerShell from a Windows Script Host wrapper and fetch
      content over HTTP
    - Internal automation that uses .NET HttpClient from PowerShell to download update artifacts
level: medium
```

---

## Coverage Gaps

**Network indicators routed to the IOC feed, not standalone signatures.** The original file shipped two Suricata rules that were pure atomic/ubiquitous matches and have been removed in favor of the IOC feed:

- A DNS rule keyed solely on `dns4up.duckdns.org` (Robustness 0) — a single C2 domain that a `dns_query` signature stops detecting the moment the operator rotates it. Carried in [`quasar-xworm-powershell-iocs.json`](/ioc-feeds/quasar-xworm-powershell-iocs.json).
- An HTTP rule matching `content:"/update.png"` on `any -> any` — `/update.png` is a ubiquitous benign path with no pivot value, so a global content match is noise rather than detection. The specific payload URL (`hxxp://193.233.164.21/update.png`) and its host are carried in the feed instead.

**No standalone Quasar/Xworm implant network rule.** The QuasarRAT and Xworm C2 protocols for this campaign were not captured on the wire in a form that yields a durable content anchor; the implant sample hashes are carried in the IOC feed. A durable TLS-certificate or protocol-field signature would require observed C2 traffic — see the feed for the atomic implant indicators.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
