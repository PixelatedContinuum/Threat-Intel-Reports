---
title: Detection Rules – AdvancedRouterScanner Campaign
date: '2025-10-25'
layout: post
permalink: /hunting-detections/AdvancedRouterScanner/
thumbnail: /assets/images/cards/AdvancedRouterScanner.png
hide: true
---

---

## Exploit Layer

### Suspicious Access to Router CGI Endpoints
```yaml
title: Suspicious Router CGI Access
id: e5afdda0-43fc-42b1-b429-05cb0e0bd34e
status: test
description: >-
    Detects HTTP requests to CGI endpoints and paths commonly exploited by
    router/IoT scanning and exploitation tools to achieve command execution
    or credential harvesting on embedded web management interfaces.
references:
    - https://the-hunters-ledger.com/hunting-detections/AdvancedRouterScanner/
author: The Hunters Ledger
date: '2025-10-25'
tags:
    - attack.initial-access
    - attack.t1190
    - detection.emerging-threats
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains:
            - "/web_shell_cmd.gch"
            - "/apply.cgi"
            - "/boaform/admin/formLogin"
            - "/cgi-bin/config.cgi"
            - "/login.cgi"
            - "/setup.cgi"
            - "/system.cmd"
            - "/shell?command="
    condition: selection
falsepositives:
    - Legitimate administrative access to router/IoT management interfaces
level: high
```
---

## Credential Layer

### Default Credential Brute Force
```yaml
title: Default Credential Brute Force
id: b88fd219-6352-4cdb-9406-be4acdc7dfe8
status: test
description: >-
    Detects authentication attempts using common default or weak
    username/password pairs against router and IoT management interfaces,
    consistent with automated credential brute-forcing tools.
references:
    - https://the-hunters-ledger.com/hunting-detections/AdvancedRouterScanner/
author: The Hunters Ledger
date: '2025-10-25'
tags:
    - attack.credential-access
    - attack.t1110.001
    - detection.emerging-threats
logsource:
    category: authentication
detection:
    selection:
        user|contains:
            - "admin"
            - "root"
            - "guest"
            - "operator"
        password|contains:
            - "admin"
            - "password"
            - "1234"
            - "changeme"
    condition: selection
falsepositives:
    - Legitimate administrators using default credentials before hardening a new device
level: high
```
---

## Execution Layer

### Reverse Shell Establishment
```
Suricata IDS
alert tcp any any -> 107.189.4.201 3778 (msg:"Reverse Shell to C2"; sid:200001; rev:1;)
```
---

## Persistence Layer

### Dropped Files in /tmp
```yaml
title: Suspicious Dropped Files in Temp Directory
id: 40c446c0-f885-4d08-a877-dc923942e41b
status: test
description: >-
    Detects binaries dropped into /tmp with the naming pattern used by this
    campaign's staged payloads, indicating post-exploitation tool transfer
    onto a compromised embedded device.
references:
    - https://the-hunters-ledger.com/hunting-detections/AdvancedRouterScanner/
author: The Hunters Ledger
date: '2025-10-25'
tags:
    - attack.command-and-control
    - attack.t1105
    - detection.emerging-threats
logsource:
    category: file_event
detection:
    selection:
        file.path|contains: "/tmp/bn"
    condition: selection
falsepositives:
    - Unlikely; /tmp/bn is not a standard filename prefix for legitimate software
level: medium
```
---

## Exfiltration Layer

### Payload Downloads
```yaml
title: Payload Download from Known Hosts
id: 31ff6144-57f5-4e3c-a581-1816bd4db0cb
status: test
description: >-
    Detects outbound proxy connections to domains and IP addresses used to
    host and serve second-stage payloads for this campaign.
references:
    - https://the-hunters-ledger.com/hunting-detections/AdvancedRouterScanner/
author: The Hunters Ledger
date: '2025-10-25'
tags:
    - attack.command-and-control
    - attack.t1105
    - attack.t1071.001
    - detection.emerging-threats
logsource:
    category: proxy
detection:
    selection:
        cs-host: "bot.gribostress.pro"
        dst_ip: "107.189.4.201"
    condition: selection
falsepositives:
    - Unlikely; these are campaign-specific malicious hosts
level: high
```
---

## Summary
These rules provide coverage across:
- Exploit attempts (router CGI endpoints)
- Credential brute forcing (default accounts)
- Execution (reverse shell to known C2)
- Persistence (dropped files in /tmp)
- Exfiltration (payload downloads from malicious hosts)

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
