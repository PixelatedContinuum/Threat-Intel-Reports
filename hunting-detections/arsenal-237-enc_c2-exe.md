# enc_c2.exe (Arsenal-237) - Detection Rules & Hunting Queries

## Overview

This document provides YARA rules, Sigma rules, SIEM queries, and network signatures for detecting enc_c2.exe execution, behavioral indicators, and command-and-control communication.

---

## Section 1: YARA Rules

### Rule 1: enc_c2.exe File Hash Identification

Detects the specific enc_c2.exe sample via cryptographic hash matching.

```yara
rule enc_c2_exe_file_hash {
    meta:
        description = "Detects enc_c2.exe ransomware sample by hash"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        malware_type = "Ransomware"
        malware_family = "Arsenal-237"
        severity = "CRITICAL"

    hash:
        sha256 = "613d4d0f1612686742889e834ebc9ebff6ae021cf81a4c50f66369195ca01899"
        md5 = "32a3497e57604e1037f1ff9993a8fdaa"
        sha1 = "34d3c75e79633eb3bf47e751fb31274760aeae09"

    condition:
        any of them
}
```

---

### Rule 2: ChaCha20 Cryptographic Constants

Detects ChaCha20 implementation via characteristic string constants.

```yara
rule chacha20_encryption_constants {
    meta:
        description = "Detects ChaCha20 cipher implementation (ransomware encryption)"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        malware_type = "Ransomware"
        severity = "HIGH"

    strings:
        $chacha_constant_1 = "expand 32-byte k" ascii
        $chacha_constant_2 = "Chacha_256_constant" ascii
        $chacha_library = "aead-0.5.2" ascii
        $chacha_function = "chacha20" ascii nocase

    condition:
        any of them
}
```

---

### Rule 3: Tor Hidden Service C2 Infrastructure

Detects .onion domain and Tor C2 endpoint strings.

```yara
rule tor_hidden_service_c2 {
    meta:
        description = "Detects Tor hidden service C2 communication infrastructure"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        malware_type = "C2 Infrastructure"
        severity = "CRITICAL"

    strings:
        $c2_domain = "rustydl5ak6p6ajqnja6qzkxvp5huhe4olpdsq5oy75ea4o34aalpkqd.onion" ascii
        $c2_endpoint = "/c2/beacon.php" ascii
        $c2_protocol = "POST /c2/beacon.php" ascii
        $onion_tld = ".onion" ascii

    condition:
        any of them
}
```

---

### Rule 4: RaaS Builder Tracking

Detects RaaS builder ID strings and affiliate tracking markers.

```yara
rule raas_builder_tracking {
    meta:
        description = "Detects RaaS builder ID and affiliate tracking"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        malware_type = "Ransomware (RaaS)"
        severity = "MEDIUM"

    strings:
        $builder_id_default = "TEST_BUILD_001" ascii
        $builder_id_generic = "builder_id" ascii
        $victim_id = "victim_id" ascii
        $encryption_key = "encryption_key" ascii
        $machine_info = "machine_info" ascii

    condition:
        (($builder_id_default and $builder_id_generic) or
         ($builder_id_generic and $encryption_key and $victim_id and $machine_info))
}
```

---

### Rule 5: File Encryption & Ransomware Operations

Detects ransomware-specific strings and operational indicators.

```yara
rule enc_c2_ransomware_operations {
    meta:
        description = "Detects enc_c2 ransomware operational strings"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        malware_type = "Ransomware"
        severity = "HIGH"

    strings:
        $ransom_msg = "YOUR FILES HAVE BEEN ENCRYPTED!" ascii
        $ransom_note = "README.txt" ascii
        $encrypted_extension = ".locked" ascii
        $enc_c2_executable = "enc_c2.exe" ascii
        $http_client = "ureq" ascii

    condition:
        3 of them
}
```

---

### Rule 6: TEB-Based Anti-Debug Detection

Detects TEB (Thread Environment Block) validation anti-debugging mechanism.

```yara
rule teb_anti_debug_detection {
    meta:
        description = "Detects TEB-based anti-debugging in enc_c2.exe"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        malware_type = "Anti-Analysis"
        severity = "MEDIUM"

    strings:
        $teb_api = "NtCurrentTeb" ascii
        $stack_base = "StackBase" ascii
        $sleep_loop = { 68 88 13 00 00 FF 15 } // Push 0x1388 (5000ms) / Call Sleep
        $sleep_1000 = { 68 E8 03 00 00 FF 15 } // Push 0x3E8 (1000ms) / Call Sleep

    condition:
        ($teb_api and ($sleep_loop or $sleep_1000))
}
```

---

### Rule 7: Rust Compilation Environment Artifacts

Detects Rust build environment and library artifacts.

```yara
rule rust_compilation_artifacts {
    meta:
        description = "Detects Rust compiler artifacts in malware binaries"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        malware_type = "Rust-based Malware"
        severity = "MEDIUM"

    strings:
        $rust_lib_path = "/root/.cargo/registry/src/" ascii
        $crates_io = "index.crates.io" ascii
        $rustc = "rustc" ascii
        $rust_std = "std" ascii

    condition:
        2 of them
}
```

---

## Section 2: Sigma Detection Rules

### Rule 1: Process Execution - enc_c2.exe

Detects execution of enc_c2.exe process.

```yaml
title: enc_c2.exe Process Execution - Ransomware
description: Detects execution of enc_c2.exe ransomware executable
logsource:
  product: windows
  category: process_creation
detection:
  selection_filename:
    - Image|endswith: 'enc_c2.exe'
    - OriginalFileName: 'enc_c2.exe'
  selection_commandline:
    CommandLine|contains:
      - 'enc_c2.exe'
      - '--folder'
      - '--c2'
      - '--bid'
  condition: selection_filename or selection_commandline
falsepositives:
  - None expected
level: critical
tags:
  - attack.execution
  - attack.t1204.002
  - attack.impact
  - attack.t1486
```

---

### Rule 2: File Creation - Encrypted Files Pattern

Detects creation of files with .locked extension (encrypted files).

```yaml
title: Ransomware - File Creation with .locked Extension
description: Detects creation of encrypted files with .locked extension appended
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|endswith: '.locked'
  filter_excludes:
    - TargetFilename|contains:
        - '~$'
        - 'Temp'
  condition: selection and not filter_excludes
falsepositives:
  - Legitimate .locked files (rare)
level: high
tags:
  - attack.impact
  - attack.t1486
```

---

### Rule 3: File Creation - Ransom Note

Detects creation of README.txt ransom notes in user directories.

```yaml
title: Ransomware - Ransom Note Creation (README.txt)
description: Detects creation of README.txt ransom notes in user-accessible directories
logsource:
  product: windows
  category: file_event
detection:
  selection_file:
    TargetFilename|endswith: 'README.txt'
  selection_location:
    TargetFilename|contains:
      - 'C:\Users\'
      - 'C:\Documents'
      - 'C:\Desktop'
  selection_content:
    Contents|contains: 'YOUR FILES HAVE BEEN ENCRYPTED'
  condition: selection_file and selection_location
falsepositives:
  - Legitimate README files (unlikely with encrypted content)
level: high
tags:
  - attack.impact
  - attack.t1486
```

---

### Rule 4: Network - HTTP POST to .onion Domain

Detects HTTP POST requests to .onion domains (Tor C2 communication).

```yaml
title: Network - HTTP POST to .onion Domain (Tor C2)
description: Detects HTTP POST requests to .onion hidden service domains (Tor C2 communication)
logsource:
  product: firewall
  category: http_request
detection:
  selection:
    http_method: POST
    http_host|endswith: '.onion'
    http_uri: '/c2/beacon.php'
  selection_target:
    http_host|contains: 'rustydl5ak6p6ajqnja6qzkxvp5huhe4olpdsq5oy75ea4o34aalpkqd'
  condition: selection or selection_target
falsepositives:
  - Legitimate Tor traffic (unlikely in enterprise environment)
level: critical
tags:
  - attack.command_and_control
  - attack.t1071.001
  - attack.t1090.003
```

---

### Rule 5: Network - Tor Connectivity Detection

Detects outbound connections to known Tor entry nodes.

```yaml
title: Network - Outbound Connection to Tor Entry Node
description: Detects outbound connections to known Tor entry nodes (indicates Tor client usage)
logsource:
  product: firewall
  category: network_connection
detection:
  selection:
    DestinationPort: 443
    DestinationIp|startswith:
      - '109.105.'
      - '188.226.'
      - '195.154.'
      - '198.51.100.'
      - '203.0.113.'
  selection_direction:
    Direction: 'Outbound'
  filter_whitelisted:
    DestinationIp|in:
      - '8.8.8.8'
      - '1.1.1.1'
  condition: selection and selection_direction and not filter_whitelisted
falsepositives:
  - Legitimate VPN traffic
  - Tor Browser usage (expected in some environments)
level: high
tags:
  - attack.command_and_control
  - attack.t1090.003
```

---

### Rule 6: Registry - Malware Persistence (Negative Detection)

Confirms absence of persistence mechanisms (single-run model verification).

```yaml
title: Registry - Absence of Ransomware Persistence Mechanisms
description: Verifies that systems do not contain persistence registry keys for known ransomware
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    RegistryPath|contains:
      - 'Software\Microsoft\Windows\CurrentVersion\Run'
      - 'Software\Microsoft\Windows\CurrentVersion\RunOnce'
      - 'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
    RegistryValue|contains:
      - 'enc_c2'
      - 'TEST_BUILD_001'
  condition: selection
falsepositives:
  - None
level: medium
tags:
  - attack.persistence
  - detection_gap
note: 'enc_c2.exe appears to use single-run model without persistence; this rule detects if infected systems show persistence artifacts'
```

---

### Rule 7: Process - TEB Anti-Debug Sleep Loop

Detects repeated Sleep() calls indicating anti-debugging mechanism.

```yaml
title: Process - TEB Anti-Debug Sleep Loop Detection
description: Detects repeated Sleep(1000) calls indicating TEB-based anti-debugging
logsource:
  product: windows
  category: process_access
detection:
  selection:
    Image|endswith: 'enc_c2.exe'
    CallTrace|contains:
      - 'Sleep'
      - 'SleepEx'
      - '0x3E8'  # 1000 milliseconds in hex
  filter_normal:
    CallCount|lt: 3  # Allow normal sleep calls
  condition: selection and not filter_normal
falsepositives:
  - Legitimate applications with sleep loops (rate limiting, polling)
level: medium
tags:
  - attack.defense_evasion
  - attack.t1622
```

---

## Section 3: SIEM Queries

### Splunk Query 1: enc_c2.exe Process Execution

```spl
index=sysmon EventID=1 (CommandLine="*enc_c2.exe*" OR Image="*enc_c2.exe")
| stats earliest(_time) as first_exec, latest(_time) as last_exec, count as exec_count by host, Image, CommandLine
| where count >= 1
| table host, Image, CommandLine, first_exec, last_exec, exec_count
```

---

### Splunk Query 2: Bulk File Encryption Pattern Detection

```spl
index=sysmon EventID=11 (TargetFilename="*.locked")
| stats count as locked_files earliest(_time) as encryption_start latest(_time) as encryption_end by host, Image, User
| eval encryption_duration=encryption_end-encryption_start
| where locked_files > 50 AND encryption_duration < 600
| table host, Image, User, locked_files, encryption_start, encryption_duration
```

---

### Splunk Query 3: README.txt Ransom Note Detection

```spl
index=sysmon EventID=11 TargetFilename="*README.txt" (TargetFilename="*Users*" OR TargetFilename="*Documents*" OR TargetFilename="*Desktop*")
| stats count as readme_count earliest(_time) as first_note by host, User
| search count > 0
| table host, User, first_note, readme_count
```

---

### Splunk Query 4: Tor Hidden Service C2 Communication

```spl
index=proxy http_method=POST (uri="*c2/beacon.php" OR http_host="*rustydl5ak6p6ajqnja6qzkxvp5huhe4olpdsq5oy75ea4o34aalpkqd.onion")
| stats earliest(_time) as beacon_time, latest(_time) as last_beacon by host, src_ip, dest_ip, http_host
| eval beacons=count
| table host, src_ip, dest_ip, http_host, beacon_time, beacons
```

---

### Splunk Query 5: Correlation - Process + File Encryption + C2 Communication

```spl
index=sysmon EventID=1 CommandLine="*enc_c2.exe*"
| stats earliest(_time) as proc_exec by host
| join host
  [search index=sysmon EventID=11 TargetFilename="*.locked" | stats earliest(_time) as file_encrypt by host]
| join host
  [search index=proxy http_host="*onion" | stats earliest(_time) as c2_beacon by host]
| eval proc_to_file=(file_encrypt-proc_exec), file_to_c2=(c2_beacon-file_encrypt)
| where proc_to_file > 0 AND proc_to_file < 600
| table host, proc_exec, file_encrypt, c2_beacon, proc_to_file, file_to_c2
| alert
```

---

## Section 4: Elastic/ELK Detection Rules

### Elastic Rule 1: Process Execution - enc_c2.exe

```json
{
  "name": "enc_c2.exe Process Execution",
  "description": "Detects execution of enc_c2.exe ransomware",
  "query": "process.name:enc_c2.exe OR process.executable:*enc_c2.exe*",
  "index": "logs-endpoint.events.process-*",
  "severity": "critical",
  "risk_score": 100,
  "enabled": true
}
```

---

### Elastic Rule 2: File Encryption - Bulk .locked File Creation

```json
{
  "name": "Ransomware - Bulk .locked File Creation",
  "description": "Detects creation of multiple files with .locked extension",
  "query": "file.Ext.windows.ntfs_file_name.name:*.locked",
  "index": "logs-endpoint.events.file-*",
  "aggregation": {
    "field": "host.name",
    "threshold": 50,
    "time_window": "10m"
  },
  "severity": "high",
  "risk_score": 95,
  "enabled": true
}
```

---

### Elastic Rule 3: Tor C2 Communication Detection

```json
{
  "name": "HTTP POST to .onion Domain - Tor C2",
  "description": "Detects HTTP POST requests to .onion hidden service",
  "query": "http.request.method:POST AND url.domain:*.onion",
  "index": "logs-network.http-*",
  "severity": "critical",
  "risk_score": 100,
  "enabled": true
}
```

---

## Section 5: Network Detection Rules

### Suricata/Snort Signature 1: Tor Hidden Service HTTP POST

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"RANSOMWARE enc_c2.exe Tor C2 Beacon - /c2/beacon.php";
    content:"POST"; http_method;
    content:".onion"; http_uri;
    content:"rustydl5ak6p6ajqnja6qzkxvp5huhe4olpdsq5oy75ea4o34aalpkqd.onion"; http_host;
    content:"Content-Type|3a| application/json"; http_header;
    flow:to_server,established;
    classtype:trojan-activity;
    sid:1000001;
    rev:1;
)
```

---

### Suricata/Snort Signature 2: Tor Entry Node Connection

```
alert tcp $HOME_NET any -> [109.105.0.0/16,188.226.0.0/15,195.154.0.0/16] 443 (
    msg:"RANSOMWARE - Tor Entry Node Connection (Possible Tor Client)";
    flow:to_server,established;
    content:"|16|03|01|";
    depth:3;
    classtype:suspicious-behavior;
    sid:1000002;
    rev:1;
)
```

---

## Section 6: Threat Hunting Queries

### Hunting Query 1: Search for enc_c2.exe Variants

Purpose: Identify enc_c2.exe samples and variants by file properties.

**Splunk:**
```spl
(FileName="enc_c2.exe" OR FileName="*enc_c2*" OR FileDescription="*enc_c2*")
| stats count as variant_count by MD5, SHA256, FileSize
| search FileSize > 3000000
```

---

### Hunting Query 2: Builder ID Tracking (TEST_BUILD_001)

Purpose: Hunt for samples containing TEST_BUILD_001 builder ID.

**Elastic:**
```json
{
  "query": "process.command_line:*TEST_BUILD_001* OR file.name:*TEST_BUILD_001* OR process.hash.md5:*TEST_BUILD_001*"
}
```

---

### Hunting Query 3: .locked File Creation Timeline

Purpose: Identify encrypted files and establish encryption timeline.

**Splunk:**
```spl
TargetFilename="*.locked" OR FileName="*.locked"
| timechart count by host
| search count > 10
| table host, count, _time
```

---

### Hunting Query 4: Tor Traffic from Non-VPN Processes

Purpose: Hunt for Tor traffic from processes other than legitimate Tor Browser.

**KQL (Azure Sentinel):**
```kusto
NetworkDev
| where DestinationPort == 443 and DestinationIp contains "89.163" or "190.3" or "204.85"
| where InitiatingProcessName != "firefox.exe" and InitiatingProcessName != "tor.exe"
| project TimeGenerated, ComputerName, InitiatingProcessName, DestinationIp, DestinationPort
```

---

### Hunting Query 5: SOCKS Proxy Connections

Purpose: Hunt for SOCKS proxy connections indicating Tor client usage.

**Splunk:**
```spl
DestinationPort IN (9050, 9150) AND DestinationIp IN (127.0.0.1, localhost)
| stats count as socks_connections by host, Image, DestinationPort
| search count > 0
```

---

## Section 7: Windows Event Log Signatures

### Event Log Query 1: Sysmon Process Creation

**Event ID 1 - Process Creation:**
```
EventID=1 AND (Image CONTAINS "enc_c2.exe" OR CommandLine CONTAINS "enc_c2.exe")
```

---

### Event Log Query 2: Sysmon File Creation

**Event ID 11 - File Created:**
```
EventID=11 AND (TargetFilename CONTAINS ".locked" OR TargetFilename CONTAINS "README.txt")
```

---

### Event Log Query 3: Sysmon Network Connection

**Event ID 3 - Network Connection:**
```
EventID=3 AND (DestinationPort=443 AND (DestinationIp IN [Tor_Entry_Nodes]))
```

---

### Event Log Query 4: Registry Set Value (Persistence Check)

**Event ID 13 - Registry Set Value:**
```
EventID=13 AND (TargetObject CONTAINS "TEST_BUILD_001" OR TargetObject CONTAINS "enc_c2")
```

---

## Section 8: Behavioral Indicators (IOBs)

### IOB 1: Rapid File Extension Appending

**Indicator:** Process writes >100 files in <60 seconds with systematic .locked extension appending

**Detection Method:** EDR file write monitoring + behavioral analytics

**Risk Score:** CRITICAL

```
Pattern:
  - Time Window: <60 seconds
  - File Count: >100
  - Extension Pattern: [original_filename].[original_extension].locked
  - Process: enc_c2.exe or suspicious parent process
```

---

### IOB 2: Sleep Loop Behavior

**Indicator:** Process executes infinite Sleep(1000) loops upon process start

**Detection Method:** Behavioral process analysis + API monitoring

**Risk Score:** MEDIUM

```
Pattern:
  - API Sequence: NtCurrentTeb() -> Sleep(1000) -> Sleep(1000) -> [repeat]
  - Duration: Multiple seconds without productive action
  - Indicator: TEB-based anti-debugging
```

---

### IOB 3: JSON Payload with Encryption Key

**Indicator:** HTTP POST request with JSON containing "encryption_key" field

**Detection Method:** Network traffic inspection + SIEM correlation

**Risk Score:** CRITICAL

```
Pattern:
  - HTTP Method: POST
  - Destination: .onion domain
  - Content-Type: application/json
  - Payload Contains: "encryption_key", "victim_id", "builder_id", "machine_name", "machine_info"
  - Key Format: 64-character hexadecimal (256-bit ChaCha20 key)
```

---

## Section 9: Detection Rule Deployment Checklist

### Initial Deployment

- [ ] Deploy enc_c2.exe file hash YARA rule to malware scanning infrastructure
- [ ] Configure Sigma rules in SIEM detection engine
- [ ] Deploy Splunk queries to SOC monitoring dashboards
- [ ] Activate Suricata/Snort network signatures on firewalls and IDS systems
- [ ] Enable Sysmon event collection on Windows endpoints
- [ ] Configure EDR behavioral detection for file encryption patterns

### Ongoing Maintenance

- [ ] Monitor for rule false positives (weekly review)
- [ ] Correlate multi-stage detection signals (process + file encryption + C2)
- [ ] Update Tor entry node IP lists (monthly)
- [ ] Test rule effectiveness against test malware (quarterly)
- [ ] Review and update detection rules for enc_c2 variants (as discovered)

### Alert Response Procedures

- [ ] Process Execution Alert -> Isolate system immediately
- [ ] File Encryption Alert -> Check for network isolation needed
- [ ] C2 Communication Alert -> Block infrastructure + preserve forensic evidence
- [ ] Multi-Stage Alert -> Activate incident response procedures

---

## Section 10: Performance & False Positive Considerations

### Rule Performance Impact

| Rule | Query Complexity | Performance Impact | Recommended Frequency |
|------|------------------|-------------------|----------------------|
| File Hash Matching | Low | Minimal | Real-time |
| Bulk File Creation | Medium | Medium | Real-time with batching |
| Network HTTP POST | Low | Minimal | Real-time |
| Correlation (3-stage) | High | High | Hourly batch queries |
| Sysmon Event Collection | Medium | Medium | Real-time with filtering |

### False Positive Mitigation

1. **Exclude known-good processes** (backup software, legitimate encryption tools)
2. **Filter by directory** (focus on user data directories, exclude system paths)
3. **Correlation tuning** (adjust timing windows based on environment baseline)
4. **Whitelist legitimate .locked files** (legitimate software using .locked extension)

---

## Section 11: Detection Rule Updates & Variants

As enc_c2.exe variants emerge, update detection rules:

### Variant Tracking

Monitor for:
- Different builder IDs (AFFILIATE_*, PARTNER_*, etc.)
- Custom C2 domains
- Modified encryption algorithms
- Enhanced anti-analysis techniques
- Variant-specific strings in binary analysis

### Detection Rule Evolution

1. **Hash-based detection** (initial variant discovery)
2. **Behavioral pattern detection** (file encryption speed, extension appending)
3. **Infrastructure detection** (C2 domains, Tor connectivity)
4. **Capability detection** (cryptographic constants, RaaS builder tracking)
5. **Correlation detection** (multi-stage attack chain)

---

*End of Detection Rules Document*

Last Updated: 2026-01-26
