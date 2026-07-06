---
title: Hybrid Loader/Stealer Ecosystem Masquerading as Sogou
date: '2025-11-21'
layout: post
permalink: /hunting-detections/Hybrid-Loader-Stealer-Sogou/
thumbnail: /assets/images/cards/Hybrid-Loader-Stealer-Sogou.png
hide: true
---
## Sigma Rules
---

## Process creation for masquerading Sogou NSIS installer
```yaml
title: SogouStealer Masquerading NSIS Installer Execution
id: a078683b-110a-4973-86bb-1666dba668bf
status: stable
description: Detects execution of suspected NSIS-based fake Sogou installers with cracked-build markers
references:
    - https://the-hunters-ledger.com/hunting-detections/Hybrid-Loader-Stealer-Sogou/
author: The Hunters Ledger
date: '2025-11-21'
tags:
    - attack.stealth
    - attack.t1036
    - detection.emerging-threats
logsource:
    product: windows
    category: process_creation
detection:
    selection_image:
        Image|endswith:
            - '\installer.exe'
            - '\setup.exe'
            - '\install.exe'
    selection_cmdline:
        CommandLine|contains:
            - 'NSIS'
            - 'Nullsoft'
            - 'Sogou'
            - '拼音'
            - '吾爱破解'
            - 'v15.1.0.1570'
    condition: selection_image and selection_cmdline
falsepositives:
    - Legitimate NSIS-based installers whose command line coincidentally references these strings
level: high
```

## Persistence via Run keys and shortcut manipulation
```yaml
title: SogouStealer Persistence via Run Keys and LNK Modification
id: 190b57f6-a8c3-4f45-a39d-ed7340d66b9a
status: stable
description: Detects registry Run key entries referencing the SogouStealer ecosystem's own component filenames (beacon_sdk.dll, SGDownload.exe, userNetSchedule.exe)
references:
    - https://the-hunters-ledger.com/hunting-detections/Hybrid-Loader-Stealer-Sogou/
author: The Hunters Ledger
date: '2025-11-21'
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1547.001
    - attack.t1547.009
    - detection.emerging-threats
logsource:
    product: windows
    category: registry_set
detection:
    selection_run:
        TargetObject|contains:
            - '\Software\Microsoft\Windows\CurrentVersion\Run'
            - '\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        Details|contains:
            - 'beacon_sdk.dll'
            - 'SGDownload.exe'
            - 'userNetSchedule.exe'
    condition: selection_run
falsepositives:
    - Unlikely; these filenames are specific to this malware ecosystem
level: high
```

## File drop of core artifacts
```yaml
title: SogouStealer Artifact Drop and Staging
id: 1d3185d1-08ce-4956-91bd-f4ce70d10a46
status: stable
description: Detects creation of known components used by the malware ecosystem
references:
    - https://the-hunters-ledger.com/hunting-detections/Hybrid-Loader-Stealer-Sogou/
author: The Hunters Ledger
date: '2025-11-21'
tags:
    - attack.execution
    - attack.stealth
    - attack.persistence
    - detection.emerging-threats
logsource:
    product: windows
    category: file_create
detection:
    selection_names:
        TargetFilename|endswith:
            - '\beacon_sdk.dll'
            - '\SGDownload.exe'
            - '\SGCurlHelper.dll'
            - '\userNetSchedule.exe'
            - '\UserExportDll.dll'
            - '\UrlSignatureV.dat'
            - '\pandorabox.cupf'
            - '\PersonalCenter.cupf'
    condition: selection_names
falsepositives:
    - Unlikely; these filenames are specific to this malware ecosystem
level: high
```

## Privilege escalation via access token manipulation (Sysmon)
```yaml
title: Potential Access Token Manipulation by Suspicious Installer
id: 11093bc3-b03a-481e-94fe-d1fa73329ebe
status: experimental
description: Flags sensitive privilege assignments indicative of token manipulation
references:
    - https://the-hunters-ledger.com/hunting-detections/Hybrid-Loader-Stealer-Sogou/
author: The Hunters Ledger
date: '2025-11-21'
tags:
    - attack.stealth
    - attack.privilege-escalation
    - attack.t1134
    - detection.emerging-threats
logsource:
    product: windows
    category: process_access
detection:
    selection:
        GrantedAccess|contains:
            - '0x1FFFFF'
            - '0x00100000'
        CallTrace|contains:
            - 'OpenProcessToken'
            - 'AdjustTokenPrivileges'
    condition: selection
falsepositives:
    - Legitimate security or administrative tooling that queries or adjusts process token privileges
level: medium
```

## DNS queries to disposable C2 domains
```yaml
title: DNS Queries for SogouStealer Disposable Domains
id: cdfe5ba6-a9b6-40ab-8471-03ff533616b4
status: stable
description: Detects DNS lookups for known C2 domains decoded from config
references:
    - https://the-hunters-ledger.com/hunting-detections/Hybrid-Loader-Stealer-Sogou/
author: The Hunters Ledger
date: '2025-11-21'
tags:
    - attack.command-and-control
    - attack.t1071.001
    - detection.emerging-threats
logsource:
    product: windows
    category: dns_query
detection:
    selection_domains:
        QueryName|endswith:
            - '6.ar'
            - 'j.im'
            - '5bng.ar'
            - 'b.tk'
            - 'k.ct'
            - 'q.ar'
            - 'rlh.cq'
            - 's0.ndf'
            - 'vpl.gu'
            - 'x.pg'
    condition: selection_domains
falsepositives:
    - Unlikely; these are campaign-specific disposable C2 domains
level: high
```

## Network connection to known C2 IPs (Sysmon Event ID 3)
```yaml
title: Network Connections to Known C2 IPs (Argentina Donweb and AWS Ashburn)
id: 671cfa56-60e3-4b53-a849-f68ab5a39969
status: stable
description: Detects connections to IPs associated with disposable infrastructure used by the malware
references:
    - https://the-hunters-ledger.com/hunting-detections/Hybrid-Loader-Stealer-Sogou/
author: The Hunters Ledger
date: '2025-11-21'
tags:
    - attack.command-and-control
    - attack.t1071.001
    - detection.emerging-threats
logsource:
    product: windows
    category: network_connection
detection:
    selection_ips:
        DestinationIp:
            - '149.50.136.243'
            - '52.20.84.62'
    condition: selection_ips
falsepositives:
    - Unlikely; these are campaign-specific C2 IPs, though shared/rotated hosting infrastructure could introduce noise over time
level: high
```

---
# YARA rules
---

## Generic SogouStealer ecosystem indicators

```
rule SogouStealer_Ecosystem_Indicators
{
  meta:
    description = "Detects SogouStealer ecosystem by domains, token markers, and API strings"
    author = "The Hunters Ledger"
    reference = "Hunter’s Ledger investigation"
    date = "2025-11-21"
  strings:
    // Domains and token
    $d1 = "6.ar" ascii nocase
    $d2 = "J.im" ascii nocase
    $d3 = "5bNG.ar" ascii nocase
    $d4 = "B.tk" ascii nocase
    $d5 = "K.ct" ascii nocase
    $d6 = "Q.ar" ascii nocase
    $d7 = "rlh.cq" ascii nocase
    $d8 = "s0.ndf" ascii nocase
    $d9 = "vpl.gu" ascii nocase
    $d10 = "X.pg" ascii nocase
    $tok = "CGI1" ascii

    // Masquerade & Sogou endpoints used for disguise
    $s1 = "Sogou Input Method v15.1.0.1570" wide ascii
    $s2 = "get.sogou.com" ascii
    $s3 = "ping.pinyin.sogou.com" ascii

    // NSIS and packing indicators
    $n1 = "Nullsoft" ascii
    $n2 = "NSIS" ascii
    $enc1 = "CRC32" ascii
    $enc2 = "XOR" ascii

    // Anti-analysis and persistence-related APIs
    $api1 = "FindWindowExA" ascii
    $api2 = "GetLastError" ascii
    $api3 = "IShellLink" ascii
    $vm1  = "Xen" ascii

    // Component names
    $f1 = "beacon_sdk.dll" ascii
    $f2 = "SGDownload.exe" ascii
    $f3 = "SGCurlHelper.dll" ascii
    $f4 = "userNetSchedule.exe" ascii
    $f5 = "UserExportDll.dll" ascii
    $f6 = "UrlSignatureV.dat" ascii
    $f7 = "pandorabox.cupf" ascii
    $f8 = "PersonalCenter.cupf" ascii
  condition:
    uint16(0) == 0x5A4D and
    ( ($d1 or $d2) or (2 of ($d3,$d4,$d5,$d6,$d7,$d8,$d9,$d10)) ) and
    ( 2 of ($api1,$api2,$api3,$vm1,$n1,$n2,$enc1,$enc2,$tok) ) and
    ( 1 of ($f1,$f2,$f3,$f4,$f5,$f6,$f7,$f8) )
}
```
## Loader/downloader components

```
rule SogouStealer_Loader_Downloader
{
  meta:
    description = "Detects packed loader and downloader components"
    author = "The Hunters Ledger"
    date = "2025-11-21"
  strings:
    $loader = "beacon_sdk.dll" ascii
    $down   = "SGDownload.exe" ascii
    $anti1  = "IsDebuggerPresent" ascii
    $anti2  = "QueryPerformanceCounter" ascii
    $pack1  = "overlay" ascii
  condition:
    uint16(0) == 0x5A4D and
    ( $loader or $down ) and
    ( 1 of ($anti1,$anti2) )
}
```

## Scheduler/C2 helpers and URL signature database

```
rule SogouStealer_C2_Scheduler_SignatureDB
{
  meta:
    description = "Detects scheduler, networking helpers, and URL signature database"
    author = "The Hunters Ledger"
    date = "2025-11-21"
  strings:
    $sched = "userNetSchedule.exe" ascii
    $curl  = "SGCurlHelper.dll" ascii
    $sigdb = "UrlSignatureV.dat" ascii
    $cgi   = "/cgi1" ascii
  condition:
    uint16(0) == 0x5A4D and ( $sched or $curl ) or $sigdb or $cgi
}
```
---
# Suricata rules
---

## DNS queries to disposable domains

```
alert dns any any -> any any (msg:"SogouStealer IOC - DNS query for 6.ar"; dns.query; content:"6.ar"; endswith; nocase; classtype:trojan-activity; sid:700001; rev:1;)
alert dns any any -> any any (msg:"SogouStealer IOC - DNS query for j.im"; dns.query; content:"j.im"; endswith; nocase; classtype:trojan-activity; sid:700002; rev:1;)
alert dns any any -> any any (msg:"SogouStealer IOC - DNS query for disposable domains"; dns.query; content:"5bng.ar"; endswith; nocase; classtype:trojan-activity; sid:700003; rev:1;)
alert dns any any -> any any (msg:"SogouStealer IOC - DNS query for disposable domains"; dns.query; content:"b.tk"; endswith; nocase; classtype:trojan-activity; sid:700004; rev:1;)
alert dns any any -> any any (msg:"SogouStealer IOC - DNS query for disposable domains"; dns.query; content:"k.ct"; endswith; nocase; classtype:trojan-activity; sid:700005; rev:1;)
alert dns any any -> any any (msg:"SogouStealer IOC - DNS query for disposable domains"; dns.query; content:"q.ar"; endswith; nocase; classtype:trojan-activity; sid:700006; rev:1;)
alert dns any any -> any any (msg:"SogouStealer IOC - DNS query for disposable domains"; dns.query; content:"rlh.cq"; endswith; nocase; classtype:trojan-activity; sid:700007; rev:1;)
alert dns any any -> any any (msg:"SogouStealer IOC - DNS query for disposable domains"; dns.query; content:"s0.ndf"; endswith; nocase; classtype:trojan-activity; sid:700008; rev:1;)
alert dns any any -> any any (msg:"SogouStealer IOC - DNS query for disposable domains"; dns.query; content:"vpl.gu"; endswith; nocase; classtype:trojan-activity; sid:700009; rev:1;)
alert dns any any -> any any (msg:"SogouStealer IOC - DNS query for disposable domains"; dns.query; content:"x.pg"; endswith; nocase; classtype:trojan-activity; sid:700010; rev:1;)
```

## TLS SNI to known C2 infrastructure

```
alert tls any any -> any any (msg:"SogouStealer IOC - TLS SNI 6.ar"; tls.sni; content:"6.ar"; endswith; nocase; classtype:trojan-activity; sid:700020; rev:1;)
alert tls any any -> any any (msg:"SogouStealer IOC - TLS SNI j.im"; tls.sni; content:"j.im"; endswith; nocase; classtype:trojan-activity; sid:700021; rev:1;)
```

## HTTP Host and path indicators (including CGI1)

```
alert http any any -> any any (msg:"SogouStealer IOC - HTTP Host 6.ar"; flow:established,to_server; http.host; content:"6.ar"; endswith; classtype:trojan-activity; sid:700030; rev:1;)
alert http any any -> any any (msg:"SogouStealer IOC - HTTP Host j.im"; flow:established,to_server; http.host; content:"j.im"; endswith; classtype:trojan-activity; sid:700031; rev:1;)
alert http any any -> any any (msg:"SogouStealer IOC - HTTP URI contains /cgi1"; http.uri; content:"/cgi1"; nocase; classtype:trojan-activity; sid:700032; rev:1;)
```

## IP-based detection (use cautiously; prefer domain/SNI)

```
alert ip any any -> 149.50.136.243 any (msg:"SogouStealer IOC - Traffic to 149.50.136.243 (Donweb)"; classtype:trojan-activity; sid:700040; rev:1;)
alert ip any any -> 52.20.84.62 any (msg:"SogouStealer IOC - Traffic to 52.20.84.62 (AWS Ashburn)"; classtype:trojan-activity; sid:700041; rev:1;)
```

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
