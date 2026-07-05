---
title: Detection Rules - QuasarRAT + Xworm + PowerShell Loader
date: '2025-10-17'
layout: post
permalink: /hunting-detections/quasar-xworm-powershell/
thumbnail: /assets/images/cards/quasar-xworm-powershell.png
hide: true
---

## Overview
Detection coverage for the QuasarRAT + Xworm campaign includes host‑based, process‑based, and network indicators.  
Rules are provided in Sigma and Suricata formats for SIEM/EDR and IDS/IPS integration.

---

## Sigma – Suspicious VBScript Downloading PowerShell Payload

```yaml
title: Suspicious VBScript Downloading PowerShell Payload
id: ea533822-dc1e-40c2-8f04-e3742393c93e
status: test
description: Detects a PowerShell process spawned by wscript.exe that uses .NET HttpClient calls to download a payload disguised as an image file, consistent with QuasarRAT/Xworm loader behavior.
references:
    - https://the-hunters-ledger.com/hunting-detections/quasar-xworm-powershell/
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
        CommandLine|contains:
            - 'System.Net.Http.HttpClient'
            - 'GetAsync'
            - 'update.png'
    condition: selection
falsepositives:
    - Unlikely
level: high
```

## YARA – Defender Exclusion Script

rule PS_Defender_Exclusion {
  strings:
    $a = "Add-MpPreference"
    $b = "-ExclusionPath"
    $c = "-ExclusionProcess"
    $d = "update.png"
  condition:
    all of them
}
```
# Suricata Detection Rules

```
alert http any any -> any any (msg:"Malware Loader update.png"; http.uri; content:"/update.png"; sid:200001;)
alert dns any any -> any any (msg:"Suspicious DuckDNS Domain"; dns.query; content:"dns4up.duckdns.org"; sid:200002;)
```

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
