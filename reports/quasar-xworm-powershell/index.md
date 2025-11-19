---
layout: default
title: QuasarRAT + Xworm + PowerShell Loader
---

# QuasarRAT + Xworm + PowerShell Loader Campaign

## 📌 Executive Summary
This campaign combines commodity RATs (QuasarRAT, Xworm) with a VBScript + PowerShell loader.  
The loader disguises its payload as an image (`update.png`) but actually downloads and executes a PowerShell script in memory.  
That script disables Microsoft Defender by adding broad exclusions, then facilitates RAT deployment.

---

## 📌 Overview
Malware families observed:
- **QuasarRAT** (multiple samples, 2–3 MB typical size, one tagged with APT10).
- **Xworm** (smaller binaries, ~70 KB).

**Loader mechanism:**
- VBScript stager creates a PowerShell command string.
- PowerShell uses .NET’s `System.Net.Http.HttpClient` to fetch a remote file named `update.png` from `193.233.164.21`.
- Despite the `.png` extension, the file is a PowerShell script delivered as text.
- Script disables Microsoft Defender by adding exclusions for:
  - Entire `C:\` drive
  - Processes: `powershell.exe`, `wscript.exe`, `cmd.exe`, `cvtres.exe`

**Infrastructure:**
- `dns4up.duckdns[.]org` — dynamic DNS domain hosting QuasarRAT, Xworm, and scripts.
- `193.233.164.21` — IP hosting payloads including `update.png`.

**TTPs:**
- Fileless execution: PowerShell loads script content directly into memory.
- Defense evasion: Defender exclusions.
- RAT deployment: QuasarRAT and Xworm provide remote access, persistence, and data theft.

---

## 🧾 Indicators of Compromise (IOCs)
See full feed: [Quasar/Xworm IOC Feed](../../ioc-feeds/quasar-xworm-feed.json)

### Key IOCs
- **Domains/IPs:** `dns4up.duckdns[.]org`, `193.233.164.21`  
- **File Hashes:**  
  - QuasarRAT: `6167ced165bdcc193cd9cb0898ef6c41fd50918fa2f1183aab82e478800c901a` …  
  - Xworm: `5a1424830fb4e19be0f79f543ba998aded16e9890a97977d0424062cfb28cbec` …  
- **Scripts:** `update.png` PowerShell payload, VBScript loader  
- **Strings:** `Add-MpPreference -ExclusionPath C:\`, `HttpClient.GetAsync('193.233.164.21/update.png')`

---

## 🛡️ Detection Opportunities
See full rules: [Quasar/Xworm Detections](../../hunting-detections/quasar-xworm-detections.md)

### Highlights
- **YARA:** Match Defender exclusion script strings  
- **Sigma:** Detect VBScript spawning PowerShell with HttpClient + `update.png`  
- **Suricata:** Alert on `/update.png` URI and DuckDNS domains

---

## 🔗 Related Sections
- [IOC Feed](../../ioc-feeds/quasar-xworm-feed.json)  
- [Detections](../../hunting-detections/quasar-xworm-detections.md)

---

## 📜 License
© 2025 Joseph. All rights reserved.  
The reports in [Reports](reports/) are made publicly available for **reading and reference purposes only**.  
They may not be reproduced, redistributed, modified, or incorporated into other projects without **prior written permission** from the author.

**Permissions**
- You may view and reference the reports for personal or organizational research.  
- You may cite the reports in academic or professional work with proper attribution.  

**Restrictions**
- Redistribution of the reports in whole or in part is prohibited without written consent.  
- Commercial use, including incorporation into products, services, or paid publications, is prohibited without written consent.  
- Modification or derivative works based on these reports are prohibited without written consent.
