---
title: Detection Rules – From Webshells to the Cloud
date: '2025-10-20'
layout: post
permalink: /hunting-detections/quasar-xworm-powershell/
hide: true
---

## Exploit Layer

---

### Suspicious Access to File Manager / phpMyAdmin
**Sigma (Web Logs)**
```yaml
title: Suspicious File Manager Access  
logsource:  
  category: webserver  
detection:  
  selection:  
    uri_path|contains:  
      - "file-manager/backend/makefile"  
      - "phpmyadmin/js/"  
condition: selection  
level: high  

---

### Suspicious Cookie Values
**WAF Rule**  
```yaml
title: Suspicious clp-fm Cookie  
logsource:  
  category: webserver  
detection:  
  selection:  
    http.cookie|contains: "clp-fm="  
condition: selection  
level: high  

---

## Webshell Layer

---

### Outbound Requests with `?cmd=`
**Suricata IDS**  
alert http any any -> any any (msg:"Webshell Command Execution"; http.uri; content:"cmd="; nocase; sid:100001; rev:1;)

### POST Parameter `mxx`
**Suricata IDS**  
alert http any any -> any any (msg:"Suspicious POST param mxx"; http.request_body; content:"mxx="; nocase; sid:100002; rev:1;)

---

## Persistence Layer

---

### New User Creation (`zeroday`)
**Auditd**  
```yaml
title: Suspicious User Creation  
logsource:  
  category: auditd  
detection:  
  selection:  
    syscall: useradd  
    exe: /usr/sbin/useradd  
    a0: "zeroday"  
condition: selection  
level: critical  

---

### Webshell File Creation
**EDR Rule**  
```yaml
title: Webshell File Creation  
logsource:  
  category: file  
detection:  
  selection:  
    file.path|endswith: "/htdocs/app/files/public/shell.php"  
condition: selection  
level: high  

---

## Exfiltration Layer

---

### Rclone Process Execution
**Sysmon**  
```yaml
title: Rclone Execution  
logsource:  
  category: process_creation  
detection:  
  selection:  
    Image|endswith:  
      - "rclone"  
      - "rclone.exe"  
condition: selection  
level: high  

---

### Dropbox API Traffic
**Proxy Logs**  
```yaml
title: Dropbox API Traffic  
logsource:  
  category: proxy  
detection:  
  selection:  
    dst_domain: "api.dropboxapi.com"  
condition: selection  
level: medium  

---

### Unexpected S3 Bucket Activity
**CloudTrail**  
```yaml
title: Suspicious S3 Activity  
logsource:  
  category: aws.cloudtrail  
detection:  
  selection:  
    eventName:  
      - "PutObject"  
      - "DeleteObject"  
    userIdentity.type: "IAMUser"  
condition: selection  
level: high  

---

## Infrastructure Automation Layer

### Unusual WordPress Installs
**Web Logs**  
```yaml
title: Suspicious WordPress Install  
logsource:  
  category: webserver  
detection:  
  selection:  
    uri_path: "/wp-admin/install.php"  
    http.method: "POST"  
condition: selection  
level: medium  

---

### Reverse Proxy Creation
**Nginx Logs**  
```yaml
title: Reverse Proxy Config Changes  
logsource:  
  category: webserver  
detection:  
  selection:  
    config_change: true  
    upstream|contains: "external"  
condition: selection  
level: high  

---

## Summary
These rules provide coverage across:  
- **Exploit attempts** (file manager, phpMyAdmin, cookies)  
- **Webshell activity** (`?cmd=`, `mxx` param, file creation)  
- **Persistence** (new accounts, shell uploads)  
- **Exfiltration** (Rclone, Dropbox, AWS S3)  
- **Infrastructure automation** (WordPress installs, reverse proxy configs)  
