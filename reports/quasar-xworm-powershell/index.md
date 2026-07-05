---
title: QuasarRAT + Xworm + PowerShell Loader
date: '2025-10-17'
detection_page: /hunting-detections/quasar-xworm-powershell/
ioc_feed: /ioc-feeds/quasar-xworm-powershell.json
detection_sections:
  - label: "Sigma — VBScript Downloader"
    anchor: "#sigma--suspicious-vbscript-downloading-powershell-payload"
  - label: "YARA — Defender Exclusion"
    anchor: "#yara--defender-exclusion-script"
ioc_highlights:
  - value: "193[.]233[.]164[.]21"
    note: "Quasar + XWorm C2 server"
  - value: "dns4up[.]duckdns[.]org"
    note: "Dynamic DNS C2 domain"
layout: post
permalink: /reports/quasar-xworm-powershell/
thumbnail: /assets/images/cards/quasar-xworm-powershell.png
category: "Multi-Stage RAT"
hide: true
description: "A multi-stage campaign using a VBScript downloader and fileless PowerShell execution to deliver QuasarRAT and XWorm simultaneously to the same victim. The chain disables Microsoft Defender via exclusion manipulation and establishes dual persistent RAT channels with full remote control, keylogging, and data exfiltration capabilities."
stix_bundle: /stix/quasar-xworm-powershell.json
---

**Campaign Identifier:** QuasarRAT-Xworm-PowerShell-Campaign<br>
**Last Updated:** October 17, 2025<br>
**Threat Level:** MEDIUM


---

## BLUF (Bottom Line Up Front)

A VBScript stager fetches a PowerShell script disguised as `update.png`, executes it in memory, and uses it to disable Microsoft Defender across the entire `C:\` drive before deploying two commodity remote access trojans — QuasarRAT and XWorm — both communicating to `193[.]233[.]164[.]21` via `dns4up[.]duckdns[.]org`. Any victim where this chain ran has lost endpoint visibility and carries persistent, full-capability remote access. See the Technical Analysis section for the loader chain and RAT capabilities; see Detection & Response Guidance for immediate priorities.

### Key Risk Factors

<table class="professional-table">
  <thead>
    <tr>
      <th>Risk Factor</th>
      <th class="numeric">Score</th>
      <th>Business Impact</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Security Control Disabling</strong></td>
      <td class="numeric high">9/10</td>
      <td>Complete Microsoft Defender bypass enabling unrestricted malicious activity</td>
    </tr>
    <tr>
      <td><strong>Fileless Execution</strong></td>
      <td class="numeric high">8/10</td>
      <td>Memory-based execution evades traditional file-based detection</td>
    </tr>
    <tr>
      <td><strong>Remote Access Trojans</strong></td>
      <td class="numeric high">8/10</td>
      <td>Full system control with data theft, surveillance, and lateral movement capabilities</td>
    </tr>
    <tr>
      <td><strong>Persistence Mechanisms</strong></td>
      <td class="numeric medium">7/10</td>
      <td>Long-term unauthorized access via multiple RAT deployment paths</td>
    </tr>
  </tbody>
</table>

---

## Technical Analysis

### Overview

This campaign delivers QuasarRAT and XWorm to the same victim in a single chain: a VBScript stager launches PowerShell, which fetches `update.png` from `193[.]233[.]164[.]21`, executes it in memory as a script block, disables Defender, then deploys both RAT binaries. The `.png` extension is deliberate misdirection — the payload is a PowerShell script, not an image.

### Loader Chain

> **Analyst note:** This section describes a multi-stage fileless loading technique. "Fileless" means the malicious script never touches disk as an executable — it runs entirely in memory, defeating security tools that scan files at rest. Each stage hands off to the next without writing a traditional binary.

- The VBScript stager constructs a PowerShell command string and invokes it.
- PowerShell uses `.NET System.Net.Http.HttpClient` to fetch `update.png` from the remote server.
- Despite the `.png` extension, the file is a text-based PowerShell script.
- The script reads into memory, compiles into a `[ScriptBlock]`, and executes immediately via `.Invoke()`.

### Defense Evasion

> **Analyst note:** Before deploying the RATs, the loader surgically removes Windows' built-in antivirus coverage. The technique requires no exploits — it calls a legitimate Windows management API to tell Defender to ignore the entire system.

The PowerShell payload calls `Add-MpPreference` to add Defender exclusions for:
- The entire `C:\` drive
- Processes: `powershell.exe`, `wscript.exe`, `cmd.exe`, `cvtres.exe`

These exclusions blind Defender to all subsequent activity on the host.

### RAT Deployment

> **Analyst note:** With Defender disabled, the loader drops two separate remote access trojans (RATs — malware that gives attackers full keyboard, file, and screen control of a victim machine). Running both provides redundancy: removing one does not restore security.

Once exclusions are in place, the loader deploys:
- **QuasarRAT**: a .NET-based remote access trojan, approximately 2–3 MB, with configs typically embedded in binary resources.
- **XWorm**: a lightweight (~70 KB) commodity RAT with obfuscated strings.

Both provide persistence, remote control, and data theft capabilities; both communicate to `dns4up[.]duckdns[.]org`.

### Infrastructure Overview
<table class="professional-table">
  <thead>
    <tr>
      <th>Infrastructure Component</th>
      <th>Value</th>
      <th>Role in Attack Chain</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Dynamic DNS Domain</strong></td>
      <td>dns4up.duckdns[.]org</td>
      <td>Primary C2 domain for RAT communication</td>
    </tr>
    <tr>
      <td><strong>Hosting IP</strong></td>
      <td>193.233.164.21</td>
      <td>Infrastructure hosting malicious payloads</td>
    </tr>
    <tr>
      <td><strong>Payload Disguise</strong></td>
      <td>update.png</td>
      <td>PowerShell script disguised as image file</td>
    </tr>
  </tbody>
</table>

### Attack Chain Components
<table class="professional-table">
  <thead>
    <tr>
      <th>Component</th>
      <th>Technology</th>
      <th>Purpose</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Initial Loader</strong></td>
      <td>VBScript</td>
      <td>Constructs PowerShell execution command</td>
    </tr>
    <tr>
      <td><strong>Delivery Mechanism</strong></td>
      <td>PowerShell + .NET HttpClient</td>
      <td>Downloads and executes malicious script in memory</td>
    </tr>
    <tr>
      <td><strong>Defense Evasion</strong></td>
      <td>PowerShell exclusions</td>
      <td>Disables Microsoft Defender completely</td>
    </tr>
    <tr>
      <td><strong>Primary RAT</strong></td>
      <td>QuasarRAT (.NET)</td>
      <td>Full-featured remote access trojan (~2-3 MB)</td>
    </tr>
    <tr>
      <td><strong>Secondary RAT</strong></td>
      <td>Xworm</td>
      <td>Lightweight commodity RAT (~70 KB)</td>
    </tr>
  </tbody>
</table>

### Pivoting Strategy

Analysts can pivot on:
- **File names**: `update.png`, `update.ps1`
- **Strings**: `Add-MpPreference`, `ExclusionPath`, `HttpClient.GetAsync`
- **Domains/IPs**: DuckDNS subdomains, `193.233.164.21`
- **Malware traits**: QuasarRAT embedded configs, XWorm obfuscation patterns

---

## Attack Tactics & Procedures

### MITRE ATT&CK Mapping

> **Confidence note:** all rows below are HIGH confidence unless explicitly marked `(MODERATE)`.

<table class=”professional-table”>
  <thead>
    <tr>
      <th>Tactic / Technique</th>
      <th>Name</th>
      <th>Evidence</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Execution / T1059.001</strong></td>
      <td>PowerShell</td>
      <td>Fileless script block executed in memory via <code>.Invoke()</code></td>
    </tr>
    <tr>
      <td><strong>Defense Evasion / T1562.001</strong></td>
      <td>Disable or Modify Tools</td>
      <td>Defender exclusions added via <code>Add-MpPreference</code> for entire <code>C:\</code> drive and key processes</td>
    </tr>
    <tr>
      <td><strong>Persistence / T1543.003</strong></td>
      <td>Windows Service</td>
      <td>RAT deployment establishes long-term access (MODERATE)</td>
    </tr>
    <tr>
      <td><strong>Command and Control / T1071.001</strong></td>
      <td>Web Protocols</td>
      <td>HTTP/HTTPS communication to <code>193.233.164.21</code> via <code>dns4up.duckdns.org</code></td>
    </tr>
    <tr>
      <td><strong>Execution / T1059.005</strong></td>
      <td>Visual Basic</td>
      <td>VBScript stager constructs and launches the PowerShell download command</td>
    </tr>
  </tbody>
</table>

### Threat Hunting Indicators
<table class="professional-table">
  <thead>
    <tr>
      <th>Indicator Type</th>
      <th>Value</th>
      <th>Hunting Method</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>File Names</strong></td>
      <td>update.png, update.ps1</td>
      <td>File system monitoring, EDR alerts</td>
    </tr>
    <tr>
      <td><strong>PowerShell Strings</strong></td>
      <td>Add-MpPreference, ExclusionPath, HttpClient.GetAsync</td>
      <td>PowerShell logging, script block analysis</td>
    </tr>
    <tr>
      <td><strong>Network Indicators</strong></td>
      <td>dns4up.duckdns.org, 193.233.164.21</td>
      <td>DNS monitoring, network traffic analysis</td>
    </tr>
    <tr>
      <td><strong>Malware Signatures</strong></td>
      <td>QuasarRAT configs, Xworm obfuscation</td>
      <td>Memory analysis, YARA rules</td>
    </tr>
  </tbody>
</table>

---

## Detection & Response Guidance

### Immediate Priorities

1. **Isolate** potentially compromised systems from the network
2. **Restore** Microsoft Defender functionality and remove all added exclusions
3. **Scan** for QuasarRAT and XWorm binaries on affected hosts
4. **Audit** PowerShell execution logs for suspicious script block activity
5. **Block** outbound access to `dns4up.duckdns.org` and `193.233.164.21`

### Longer-Term Detection Posture

- Enable PowerShell script block logging and module logging to surface in-memory execution
- Monitor for `Add-MpPreference` calls that add drive-wide or process-level exclusions
- Deploy behavioral detection rules that alert on VBScript spawning PowerShell with download activity
- Hunt for `HttpClient.GetAsync` calls fetching files with image extensions from external hosts

---

## Frequently Asked Questions

**Q: Why is fileless execution particularly dangerous?**
It evades traditional file-based detection, leaves minimal forensic artifacts, and bypasses security controls that rely on file scanning.

**Q: How does the PowerShell exclusion mechanism work?**
The script calls `Add-MpPreference` to add exclusions for the entire `C:\` drive and specific processes, removing Defender coverage for all subsequent activity.

**Q: What makes the `.png` disguise effective?**
Some network monitoring systems inspect image-extension files less aggressively than executable extensions, allowing the PowerShell script to pass initial filters.

---

## License

© 2026 Joseph, The Hunters Ledger. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — free to republish and adapt, including commercially, with attribution to The Hunters Ledger and a link to the original.
