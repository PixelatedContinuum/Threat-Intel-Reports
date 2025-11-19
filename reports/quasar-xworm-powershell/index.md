---
title: QuasarRAT + Xworm + PowerShell Loader
layout: default
permalink: /reports/quasar-xworm-powershell/
---

# Campaign Report: QuasarRAT + Xworm + PowerShell Loader

---

## 📌 Overview
This campaign combines commodity RATs (QuasarRAT and Xworm) with a VBScript + PowerShell loader.  
The loader disguises its payload as an image (`update.png`) but actually downloads and executes a PowerShell script in memory.  
That script disables Microsoft Defender by adding broad exclusions, then facilitates RAT deployment.

---

## 🧩 Loader Mechanism
- **VBScript stager** constructs a PowerShell command string.  
- **PowerShell execution** uses `.NET System.Net.Http.HttpClient` to fetch `update.png` from a remote server.  
- Despite the `.png` extension, the file is a **text‑based PowerShell script**, not an image.  
- The script is read into memory, compiled into a `[ScriptBlock]`, and executed immediately with `.Invoke()`.  

---

## 🛡️ Defense Evasion
The PowerShell payload disables Microsoft Defender by adding exclusions for:
- Entire `C:\` drive.  
- Processes: `powershell.exe`, `wscript.exe`, `cmd.exe`, `cvtres.exe`.  

This effectively blinds Defender to subsequent malicious activity.

---

## 🖥️ RAT Deployment
Once exclusions are in place, the loader hands off to RAT binaries:
- **QuasarRAT**: .NET‑based remote access trojan, ~2–3 MB, often with configs embedded in resources.  
- **Xworm**: smaller (~70 KB), obfuscated strings, commodity RAT functionality.  
Both provide persistence, remote control, and data theft capabilities.

---

## 🌐 Infrastructure
- Dynamic DNS domain: `dns4up.duckdns[.]org`  
- Hosting IP: `193.233.164.21`  
Both serve QuasarRAT, Xworm, and loader scripts.

---

## 🔍 Tactics, Techniques, and Procedures (TTPs)
- **Fileless execution**: PowerShell loads and executes script content directly in memory.  
- **Defense evasion**: Microsoft Defender exclusions.  
- **Remote access**: RAT deployment for persistence and control.  
- **Living off the land**: Abuse of legitimate scripting engines (VBScript, PowerShell).  

---

## 🧭 Pivoting Strategy
Analysts can pivot on:
- **File names**: `update.png`, `update.ps1`.  
- **Strings**: `Add-MpPreference`, `ExclusionPath`, `HttpClient.GetAsync`.  
- **Domains/IPs**: DuckDNS subdomains, `193.233.164.21`.  
- **Malware traits**: QuasarRAT’s embedded configs, Xworm’s obfuscation patterns.  

---

## 📝 Final Summary
This campaign demonstrates a layered loader strategy:
1. VBScript launches PowerShell.  
2. PowerShell fetches a disguised payload (`update.png`).  
3. Payload disables Defender and executes in memory.  
4. RATs (QuasarRAT, Xworm) are deployed for persistence and remote control.  

Key insight: the `.png` extension is a deliberate misdirection — the payload is a PowerShell script, not an image.  
This is a classic “living off the land” technique, leveraging native scripting tools for stealth and evasion.

---

## 📜 License
© 2025 Joseph. All rights reserved.  
Free to read, but reuse requires written permission.
