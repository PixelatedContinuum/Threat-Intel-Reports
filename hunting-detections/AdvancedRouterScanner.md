---
title: Detection Rules – AdvancedRouterScanner Campaign
date: '2025-10-25'
layout: post
permalink: /hunting-detections/AdvancedRouterScanner/
hide: true
---

# Detection Rules – AdvancedRouterScanner Campaign

---

## Exploit Layer

### Suspicious Access to Router CGI Endpoints
```
Sigma (Web Logs)
title: Suspicious Router CGI Access
logsource:
  category: webserver
detection:
  selection:
    uri_path|contains:
      - "/web_shell_cmd.gch"
      - "/apply.cgi"
      - "/boaform/admin/formLogin"
      - "/cgi-bin/config.cgi"
      - "/login.cgi"
      - "/setup.cgi"
      - "/system.cmd"
      - "/shell?command="
condition: selection
level: high
```
---

## Credential Layer

### Default Credential Brute Force
```
Sigma (Auth Logs)
title: Default Credential Brute Force
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
```
Sigma (File Monitoring)
title: Suspicious Dropped Files in /tmp
logsource:
  category: file
detection:
  selection:
    file.path|contains: "/tmp/bn"
condition: selection
level: medium
```
---

## Exfiltration Layer

### Payload Downloads
```
Sigma (Proxy Logs)
title: Payload Download from Known Hosts
logsource:
  category: proxy
detection:
  selection:
    dst_domain:
      - "bot.gribostress.pro"
    dst_ip:
      - "107.189.4.201"
condition: selection
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
Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.  
Free to use in your environment, but not for commercial purposes.