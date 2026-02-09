---
title: 'Detection Rules - WebServer Compromise Kit'
date: '2026-02-08'
layout: post
permalink: /hunting-detections/webserver-compromise-kit-91-236-230-250-detections/
hide: true
---

# Detection Rules & Hunting Queries: WebServer Compromise Kit

**Campaign:** WebServer-Compromise-Kit-91.236.230.250
**Date:** February 8, 2026
**Last Updated:** February 9, 2026
**Threat Level:** CRITICAL
**TLP:** WHITE

**Related Resources:**
- [Main Threat Intelligence Report](/reports/webserver-compromise-kit-91-236-230-250/)
- [IOC Feed (JSON)](/ioc-feeds/webserver-compromise-kit-91-236-230-250-iocs.json)

---

## Executive Summary

This detection guide covers a multi-stage intrusion involving:
1. **ASP.NET reverse shell** (`a.png` - InsomniaShell variant)
2. **Privilege escalation** (`PrintSpoofer.exe` - SeImpersonate abuse)
3. **Network pivoting** (`rev.exe` - revsocks reverse SOCKS5 proxy)

All detection rules target **high-fidelity artifacts** with minimal false positive risk.

---

## YARA Rules

### Rule 1: ASP.NET Reverse Shell (InsomniaShell Pattern)

```yara
rule Webshell_ASPNET_InsomniaShell_Reverse {
    meta:
        description = "Detects ASP.NET reverse shells using P/Invoke for socket operations"
        author = "The Hunters Ledger"
        date = "2026-02-08"
        campaign = "WebServer-Compromise-Kit-91.236.230.250"
        hash_sha256 = "N/A - derived from a.png analysis"
        severity = "CRITICAL"
        mitre_attack = "T1505.003 - Server Software Component: Web Shell"

    strings:
        // P/Invoke signature for low-level networking
        $pinvoke_ws2 = "[DllImport(\"WS2_32.dll\"" ascii wide
        $pinvoke_kernel = "[DllImport(\"kernel32.dll\"" ascii wide

        // Socket connection APIs
        $api_wsasocket = "WSASocket" ascii wide
        $api_connect = "connect(" ascii wide

        // Process I/O redirection (hallmark of reverse shells)
        $api_createprocess = "CreateProcess" ascii wide nocase
        $io_redirect1 = "hStdInput" ascii wide
        $io_redirect2 = "hStdOutput" ascii wide
        $io_redirect3 = "hStdError" ascii wide

        // ASP.NET context
        $aspnet_page = "Page_Load" ascii wide
        $aspnet_codebehind = "CodeBehind=" ascii wide nocase

        // Common banner (optional but high confidence)
        $banner = "Spawn Shell" ascii wide nocase

    condition:
        uint16(0) == 0x253C or // "<%"  (ASP tag)
        uint16(0) == 0x4D5A or // "MZ"  (compiled DLL)
        (
            filesize < 100KB and
            (
                // P/Invoke + Socket + Process creation
                (
                    ($pinvoke_ws2 or $pinvoke_kernel) and
                    ($api_wsasocket or $api_connect) and
                    $api_createprocess and
                    2 of ($io_redirect*)
                ) or
                // Alternative: Banner + I/O redirection
                (
                    $banner and
                    2 of ($io_redirect*)
                )
            ) and
            (
                $aspnet_page or $aspnet_codebehind
            )
        )
}
```

**Detection Priority:** CRITICAL
**False Positive Rate:** Very Low (P/Invoke + socket + I/O redirection is rare in legitimate ASP.NET)

---

### Rule 2: PrintSpoofer Privilege Escalation Tool

```yara
rule PrivEsc_PrintSpoofer_SeImpersonate {
    meta:
        description = "Detects PrintSpoofer privilege escalation tool (SeImpersonate abuse)"
        author = "The Hunters Ledger"
        date = "2026-02-08"
        campaign = "WebServer-Compromise-Kit-91.236.230.250"
        hash_md5 = "108da75de148145b8f056ec0827f1665"
        hash_sha256 = "8524fbc0d73e711e69d60c64f1f1b7bef35c986705880643dd4d5e17779e586d"
        severity = "HIGH"
        mitre_attack = "T1134.001 - Token Impersonation/Theft"
        reference = "https://github.com/itm4n/PrintSpoofer"

    strings:
        // Privilege string (unique identifier)
        $priv = "SeImpersonatePrivilege" ascii wide

        // Named pipe pattern (exploitation signature)
        $pipe_format = "\\\\pipe\\\\%ws\\\\pipe\\\\spoolss" ascii wide
        $pipe_spoolss = "\\pipe\\spoolss" ascii wide

        // Token manipulation APIs
        $api_impersonate = "ImpersonateNamedPipeClient" ascii wide
        $api_opentoken = "OpenThreadToken" ascii wide
        $api_duptoken = "DuplicateTokenEx" ascii wide

        // Process creation with stolen token
        $api_createasuser = "CreateProcessAsUserW" ascii wide
        $api_createwithtoken = "CreateProcessWithTokenW" ascii wide

        // RPC functions (triggers Print Spooler)
        $rpc1 = "RpcOpenPrinter" ascii wide nocase
        $rpc2 = "RpcRemoteFindFirstPrinterChangeNotification" ascii wide nocase
        $rpc3 = "NdrClientCall3" ascii wide

        // Tool-specific strings
        $tool_name = "PrintSpoofer" ascii wide nocase
        $author_tag = "@itm4n" ascii wide

        // Security descriptor for pipe (world-readable)
        $sddl = "D:(A;OICI;GA;;;WD)" ascii wide

    condition:
        uint16(0) == 0x5A4D and // MZ header
        filesize < 500KB and
        (
            // High confidence: Tool name + core APIs
            (
                $tool_name and
                $priv and
                $api_impersonate and
                ($api_createasuser or $api_createwithtoken)
            ) or
            // Alternative: Pipe pattern + token APIs (generic detection)
            (
                ($pipe_format or ($pipe_spoolss and $sddl)) and
                $api_impersonate and
                $api_duptoken and
                2 of ($api_create*)
            )
        )
}
```

**Detection Priority:** HIGH
**False Positive Rate:** Very Low (specific API pattern + pipe naming)
**Note:** This rule detects both original PrintSpoofer and renamed/recompiled variants.

---

### Rule 3: revsocks Reverse SOCKS5 Proxy

```yara
rule Proxy_Revsocks_Go_Binary {
    meta:
        description = "Detects revsocks reverse SOCKS5 proxy (Go binary)"
        author = "The Hunters Ledger"
        date = "2026-02-08"
        campaign = "WebServer-Compromise-Kit-91.236.230.250"
        hash_md5 = "032300082d8bc63b3d0a7f3f3f83f5d1"
        hash_sha256 = "ffc6662c5d68db31b5d468460e4bc3be2090d7ba3ee1e47dbe2803217bf424a9"
        severity = "HIGH"
        mitre_attack = "T1090.001 - Internal Proxy"
        reference = "https://github.com/kost/revsocks"

    strings:
        // Go build path (high confidence identifier)
        $go_path = "github.com/kost/revsocks" ascii wide

        // Imported tunneling libraries
        $lib_chashell = "github.com/kost/chashell" ascii wide
        $lib_dnstun = "github.com/kost/dnstun" ascii wide
        $lib_socks5 = "github.com/armon/go-socks5" ascii wide
        $lib_yamux = "github.com/hashicorp/yamux" ascii wide
        $lib_ntlm = "github.com/kost/go-ntlmssp" ascii wide
        $lib_websocket = "nhooyr.io/websocket" ascii wide

        // Command-line flags (usage patterns)
        $flag_connect = "-connect" ascii wide
        $flag_listen = "-listen" ascii wide
        $flag_socks = "-socks" ascii wide
        $flag_dns = "-dns" ascii wide
        $flag_ws = "-ws" ascii wide
        $flag_pass = "-pass" ascii wide

        // Characteristic User-Agent
        $ua_ie11 = "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko" ascii wide

        // DNS tunneling artifacts
        $dns_delay = "-dnsdelay" ascii wide
        $dns_type = "dnstype" ascii wide

        // Version string pattern
        $version = /main\.Version=\d+\.\d+/ ascii

    condition:
        uint16(0) == 0x5A4D and // MZ header
        filesize > 5MB and filesize < 15MB and // Go binaries are large
        (
            // Direct tool identification
            $go_path or
            // Library clustering (3+ libraries = high confidence)
            (
                3 of ($lib_*) and
                2 of ($flag_*)
            ) or
            // User-Agent + flags (behavioral pattern)
            (
                $ua_ie11 and
                $flag_connect and
                ($flag_socks or $flag_dns or $flag_ws)
            )
        )
}
```

**Detection Priority:** HIGH
**False Positive Rate:** Very Low (specific library combination)

---

## Sigma Rules (SIEM/EDR)

### Rule 1: IIS Worker Process Spawns Command Shell

```yaml
title: IIS Worker Process Spawns Interactive Shell
id: c4e3d3c7-9f89-4d1a-8b2c-3e5a6f7d8e9f
status: stable
description: Detects w3wp.exe spawning cmd.exe or powershell.exe (web shell indicator)
author: Threat Intelligence Workflow
date: 2026-02-08
references:
    - "WebServer-Compromise-Kit-91.236.230.250 Campaign"
    - "T1505.003 - Web Shell"
tags:
    - attack.persistence
    - attack.t1505.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\w3wp.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wscript.exe'
            - '\cscript.exe'
    condition: selection
falsepositives:
    - Legitimate administrative scripts (verify with process command line)
    - Scheduled tasks running under IIS context (rare)
level: critical
```

---

### Rule 2: Named Pipe Creation with Print Spooler Pattern

```yaml
title: Named Pipe Created Matching PrintSpoofer Pattern
id: d5f4e6a7-b8c9-4d0e-1f2a-3b4c5d6e7f8g
status: stable
description: Detects creation of named pipes ending in 'spoolss' by non-Spooler processes
author: Threat Intelligence Workflow
date: 2026-02-08
references:
    - "PrintSpoofer exploitation technique"
    - "T1134.001 - Token Impersonation"
tags:
    - attack.privilege_escalation
    - attack.t1134.001
logsource:
    product: windows
    category: pipe_created
    definition: 'Requires Sysmon Event ID 17 (Pipe Created)'
detection:
    selection:
        EventID: 17
        PipeName|endswith: '\spoolss'
    filter:
        Image|endswith: '\spoolsv.exe'  # Legitimate Print Spooler
    condition: selection and not filter
falsepositives:
    - None expected (highly specific pattern)
level: critical
```

---

### Rule 3: Process Command Line Contains revsocks Flags

```yaml
title: Reverse SOCKS Proxy Execution (revsocks)
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects execution of revsocks or similar reverse proxy tools via command-line flags
author: Threat Intelligence Workflow
date: 2026-02-08
references:
    - "https://github.com/kost/revsocks"
    - "T1090.001 - Internal Proxy"
tags:
    - attack.command_and_control
    - attack.t1090.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_flags:
        CommandLine|contains|all:
            - '-connect'
            - '-socks'
    selection_dns:
        CommandLine|contains|all:
            - '-dns'
            - '-listen'
    condition: selection_flags or selection_dns
falsepositives:
    - Legitimate red team exercises (validate via change control)
    - Penetration testing (verify authorized activity)
level: high
```

---

### Rule 4: Outbound Connection to Malicious C2 IP

```yaml
title: Outbound Connection to Known C2 Server (91.236.230.250)
id: f9e8d7c6-b5a4-3210-9876-fedcba098765
status: stable
description: Detects outbound network connections to 91.236.230.250 (WebServer Compromise Kit C2)
author: Threat Intelligence Workflow
date: 2026-02-08
references:
    - "WebServer-Compromise-Kit-91.236.230.250 Campaign"
tags:
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: network_connection
    product: windows
    definition: 'Requires Sysmon Event ID 3 or firewall logs'
detection:
    selection:
        EventID: 3
        DestinationIp: '91.236.230.250'
        Initiated: 'true'
    condition: selection
falsepositives:
    - None expected (known malicious IP)
level: critical
```

---

## Suricata/Snort Network Signatures

### Rule 1: Reverse Shell Banner Detection

```suricata
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"MALWARE WebServer Compromise Kit Reverse Shell Banner";
    flow:to_server,established;
    content:"Spawn Shell"; depth:20; nocase;
    reference:campaign,WebServer-Compromise-Kit-91.236.230.250;
    classtype:trojan-activity;
    sid:1000001; rev:1;
    metadata:attack_target Client_Endpoint, deployment Perimeter, affected_product Windows, signature_severity Critical;
)
```

---

### Rule 2: C2 IP Communication

```suricata
alert ip $HOME_NET any -> 91.236.230.250 any (
    msg:"MALWARE Outbound to WebServer Compromise Kit C2 Server";
    reference:campaign,WebServer-Compromise-Kit-91.236.230.250;
    classtype:trojan-activity;
    sid:1000002; rev:1;
    metadata:attack_target Client_Endpoint, deployment Perimeter, affected_product Any, signature_severity Critical;
)
```

---

### Rule 3: Suspicious User-Agent (IE11 from Non-Browser)

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"SUSPICIOUS Anachronistic User-Agent IE11/Win7 (Possible revsocks)";
    flow:to_server,established;
    http.user_agent; content:"Windows NT 6.1|3b| Trident/7.0"; nocase;
    threshold:type limit, track by_src, count 5, seconds 300;
    reference:tool,revsocks;
    classtype:policy-violation;
    sid:1000003; rev:1;
    metadata:attack_target Client_Endpoint, deployment Perimeter, signature_severity Medium;
)
```

---

## EDR Hunting Queries

### Query 1: Web Shell Parent-Child Relationship (KQL - Defender/Sentinel)

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe")
| where AccountName !endswith "$"  // Exclude SYSTEM service accounts (expected for some IIS scenarios)
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          AccountName, AccountDomain
| sort by Timestamp desc
```

**Expected Results:** Zero on healthy systems
**Investigation:** Review command line for staging scripts, reconnaissance, or tool downloads

---

### Query 2: PrintSpoofer API Call Sequence (EDR Telemetry)

```kql
// Requires EDR API monitoring (e.g., Defender for Endpoint, CrowdStrike)
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "CreateNamedPipeEvents"
| where AdditionalFields.PipeName endswith "spoolss"
| where InitiatingProcessFileName !~ "spoolsv.exe"
| join kind=inner (
    DeviceEvents
    | where ActionType == "ImpersonateNamedPipeClient"
) on DeviceId, InitiatingProcessId
| project Timestamp, DeviceName, InitiatingProcessFileName,
          PipeName=AdditionalFields.PipeName, AccountName
```

**Expected Results:** Zero
**Triage:** Any match indicates active PrintSpoofer exploitation

---

### Query 3: Suspicious Outbound from IIS (Network Connections)

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where RemoteIPType == "Public"  // Exclude internal IPs
| where ActionType == "ConnectionSuccess"
| summarize ConnectionCount=count(),
            UniqueRemoteIPs=dcount(RemoteIP),
            Ports=make_set(RemotePort)
    by DeviceName, InitiatingProcessFileName, RemoteIP
| where ConnectionCount > 3 or UniqueRemoteIPs > 2
| sort by ConnectionCount desc
```

**Baseline:** IIS should not make frequent outbound connections
**Investigate:** Any RemoteIP not in CDN/update servers whitelist

---

### Query 4: Large Go Binary Execution with SOCKS Flags (Process Creation)

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where SHA256 == "ffc6662c5d68db31b5d468460e4bc3be2090d7ba3ee1e47dbe2803217bf424a9"  // Known rev.exe hash
    or ProcessCommandLine has_any ("-connect", "-socks", "-dns", "-listen")
| where ProcessCommandLine has "-socks" or ProcessCommandLine has "-dns"
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
          FolderPath, SHA256, InitiatingProcessFileName
| sort by Timestamp desc
```

**Expected Results:** Zero (unless authorized red team)
**Action:** Immediate isolation and forensic collection

---

## Threat Hunting Playbook

### Hunt 1: Identify Masquerading ASP.NET Files

**Objective:** Find `.png`, `.jpg`, `.gif` files containing ASP.NET code

**Steps:**
1. Scan IIS webroot directories: `C:\inetpub\wwwroot\*`
2. Search for files with image extensions: `*.png, *.jpg, *.gif, *.bmp`
3. Grep for: `[DllImport(`, `Page_Load`, `CodeBehind=`, `Spawn Shell`

**PowerShell Script:**
```powershell
Get-ChildItem C:\inetpub\wwwroot -Recurse -Include *.png,*.jpg,*.gif,*.bmp |
    Select-String -Pattern "\[DllImport\(", "Page_Load", "CodeBehind=" |
    Select-Object Path, Line | Format-Table -AutoSize
```

---

### Hunt 2: Enumerate All Named Pipes (Active Monitoring)

**Objective:** Monitor pipe creation in real-time for PrintSpoofer patterns

**PowerShell (Requires Sysmon Event ID 17):**
```powershell
# Query last 24 hours of pipe creation events
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational';
    ID=17
} | Where-Object {
    $_.Properties[2].Value -like "*spoolss" -and
    $_.Properties[4].Value -notlike "*spoolsv.exe"
} | Select-Object TimeCreated,
    @{N='ProcessName';E={$_.Properties[4].Value}},
    @{N='PipeName';E={$_.Properties[2].Value}} |
    Format-Table -AutoSize
```

---

### Hunt 3: Baseline IIS Network Behavior

**Objective:** Identify anomalous outbound connections from `w3wp.exe`

**Steps:**
1. Collect 30-day baseline of legitimate w3wp.exe connections (update servers, APIs)
2. Filter out known-good IPs/domains
3. Alert on any new unique destinations

**KQL Query (Sentinel):**
```kql
let GoodIPs = dynamic(["52.96.0.0/14", "40.96.0.0/13"]);  // Example: Azure/M365 ranges
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where RemoteIPType == "Public"
| where not(ipv4_is_in_any_range(RemoteIP, GoodIPs))
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Count=count()
    by RemoteIP, RemotePort
| where FirstSeen > ago(7d)  // New destinations in last week
| sort by Count desc
```

---

## Response Actions

### Immediate Containment (If Indicators Detected)

1. **Network Isolation:**
   - Block outbound to `91.236.230.250` at firewall
   - Consider full host isolation if active C2 detected

2. **Process Termination:**
   - Kill `cmd.exe` children of `w3wp.exe`
   - Terminate `PrintSpoofer.exe` / `rev.exe` processes

3. **File Quarantine:**
   - Remove `a.png` from webroot
   - Quarantine `PrintSpoofer.exe` and `rev.exe`

4. **Account Review:**
   - Reset credentials for compromised IIS service account
   - Audit privileged accounts for lateral movement

---

## Forensic Artifacts for Investigation

| Artifact Type | Location | Purpose |
|---------------|----------|---------|
| IIS Logs | `C:\inetpub\logs\LogFiles\W3SVC*\` | Initial access vector (POST to a.png) |
| Sysmon Logs | Event ID 1, 3, 17, 18 | Process creation, network, pipes |
| Prefetch | `C:\Windows\Prefetch\*.pf` | Execution timeline (PRINTSPOOFER.EXE-*, REV.EXE-*) |
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` | First execution timestamps |
| Network Captures | PCAP from egress firewall | C2 traffic analysis |
| Memory Dump | Target: `w3wp.exe` process | Injected shell code, cleartext credentials |

---

## License

This detection content is licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.
You are free to share and adapt this material for non-commercial purposes with attribution.

---

**Report Version:** 2.0 (GitHub Pages Edition)
**Last Updated:** February 9, 2026
**Next Review:** March 9, 2026

**Additional Resources:**
- [Main Threat Intelligence Report](/reports/webserver-compromise-kit-91-236-230-250/)
- [Machine-Readable IOC Feed](/ioc-feeds/webserver-compromise-kit-91-236-230-250-iocs.json)

