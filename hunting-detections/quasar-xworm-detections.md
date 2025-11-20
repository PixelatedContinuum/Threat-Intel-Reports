---
title: Detection Rules - QuasarRAT + Xworm + PowerShell Loader
date: '2025-10-17'
layout: post
permalink: /hunting-detections/quasar-xworm-powershell/
hide: true
---

# Detection Rules – QuasarRAT + Xworm Campaign

## Overview
Detection coverage for the QuasarRAT + Xworm campaign includes host‑based, process‑based, and network indicators.  
Rules are provided in Sigma and Suricata formats for SIEM/EDR and IDS/IPS integration.

---

## Sigma – Suspicious VBScript Downloading PowerShell Payload

```yaml
title: Suspicious VBScript Downloading PowerShell Payload
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\wscript.exe'
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - "System.Net.Http.HttpClient"
      - "GetAsync"
      - "update.png"
  condition: selection
level: high
```

## YARA – Defender Exclusion Script
```yara
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

alert http any any -> any any (msg:"Malware Loader update.png"; http.uri; content:"/update.png"; sid:200001;)
alert dns any any -> any any (msg:"Suspicious DuckDNS Domain"; dns.query; content:"dns4up.duckdns.org"; sid:200002;)

## License
Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.  
Free to use in your environment, but not for commercial purposes.