---
title: Detection Rules – From Webshells to the Cloud
date: '2025-10-20'
layout: post
permalink: /hunting-detections/webshells-to-the-cloud/
thumbnail: /assets/images/cards/webshells-to-the-cloud.png
hide: true
---

## Exploit Layer

---

### Suspicious Access to File Manager / phpMyAdmin
**Sigma (Web Logs)**
```yaml
title: Suspicious File Manager Access
id: 417a6801-8ed4-4a4c-b00a-5fb13005905e
status: experimental
description: Detects HTTP requests to exposed file-manager and phpMyAdmin backend paths commonly abused for initial access and file staging in the Webshells-to-the-Cloud campaign.
references:
    - https://the-hunters-ledger.com/hunting-detections/webshells-to-the-cloud/
author: The Hunters Ledger
date: '2025-10-20'
tags:
    - attack.initial-access
    - attack.t1190
    - detection.emerging-threats
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains:
            - 'file-manager/backend/makefile'
            - 'phpmyadmin/js/'
    condition: selection
falsepositives:
    - Legitimate administrative access to a deployed phpMyAdmin or file-manager instance
level: high
```
---

### Suspicious Cookie Values
**WAF Rule**
```yaml
title: Suspicious Clp-Fm Cookie
id: f3f41eba-22fa-464d-bbce-47ca27ce5a34
status: experimental
description: Detects the operator-distinctive clp-fm session cookie used by the file-manager webshell component of the Webshells-to-the-Cloud campaign to maintain authenticated access to the compromised backend.
references:
    - https://the-hunters-ledger.com/hunting-detections/webshells-to-the-cloud/
author: The Hunters Ledger
date: '2025-10-20'
tags:
    - attack.persistence
    - attack.t1505.003
    - detection.emerging-threats
logsource:
    category: webserver
detection:
    selection:
        cs-cookie|contains: 'clp-fm='
    condition: selection
falsepositives:
    - Unlikely — this cookie name is specific to the operator's file-manager webshell tooling
level: high
```
---

## Webshell Layer

---

### Outbound Requests with `?cmd=`
**Suricata IDS**  
```
alert http any any -> any any (msg:"Webshell Command Execution"; http.uri; content:"cmd="; nocase; sid:100001; rev:1;)
```

### POST Parameter `mxx`
**Suricata IDS**  
```
alert http any any -> any any (msg:"Suspicious POST param mxx"; http.request_body; content:"mxx="; nocase; sid:100002; rev:1;)
```
---

## Persistence Layer

---

### New User Creation (`zeroday`)
**Auditd**
```yaml
title: Suspicious User Creation
id: 3dd2ccc6-76a3-4983-ae38-e76e4ef9922f
status: experimental
description: Detects creation of the operator-distinctive local account 'zeroday' via useradd, used as a persistence mechanism in the Webshells-to-the-Cloud campaign after initial webshell access.
references:
    - https://the-hunters-ledger.com/hunting-detections/webshells-to-the-cloud/
author: The Hunters Ledger
date: '2025-10-20'
tags:
    - attack.persistence
    - attack.t1136.001
    - detection.emerging-threats
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'SYSCALL'
        exe|endswith: '/useradd'
        a0: 'zeroday'
    condition: selection
falsepositives:
    - Legitimate administrator provisioning a local account that happens to share this name (verify against IT asset management)
level: critical
```
---

### Webshell File Creation
**EDR Rule**
```yaml
title: Webshell File Creation
id: 3e0b3119-6680-4972-bf69-9461c9eff56b
status: experimental
description: Detects creation of the operator-distinctive webshell file at the compromised application's public files directory, observed in the Webshells-to-the-Cloud campaign.
references:
    - https://the-hunters-ledger.com/hunting-detections/webshells-to-the-cloud/
author: The Hunters Ledger
date: '2025-10-20'
tags:
    - attack.persistence
    - attack.t1505.003
    - detection.emerging-threats
logsource:
    product: linux
    category: file_event
detection:
    selection:
        TargetFilename|endswith: '/htdocs/app/files/public/shell.php'
    condition: selection
falsepositives:
    - Unlikely — this exact file path is specific to the compromised application instance observed in this campaign
level: high
```
---

## Exfiltration Layer

---

### Rclone Process Execution
**Sysmon**
```yaml
title: Rclone Execution
id: 960b3056-e0d5-4d0b-a422-f571d24a15cb
status: experimental
description: Detects execution of the rclone cloud-sync utility, used by the Webshells-to-the-Cloud campaign operator to stage and exfiltrate data to attacker-controlled cloud storage after webshell-based access.
references:
    - https://the-hunters-ledger.com/hunting-detections/webshells-to-the-cloud/
author: The Hunters Ledger
date: '2025-10-20'
tags:
    - attack.exfiltration
    - attack.t1567.002
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\rclone.exe'
    condition: selection
falsepositives:
    - Legitimate IT administration or backup automation using rclone for authorized cloud-sync tasks
level: high
```
---

### Dropbox API Traffic
**Proxy Logs**
```yaml
title: Dropbox API Traffic
id: c9aac2c1-2261-4c14-ae47-bd9d193eb4bc
status: experimental
description: Detects outbound traffic to the Dropbox API, used as an alternate cloud-storage exfiltration channel alongside rclone/S3 in the Webshells-to-the-Cloud campaign. Legitimate enterprise Dropbox integrations will require allowlist tuning.
references:
    - https://the-hunters-ledger.com/hunting-detections/webshells-to-the-cloud/
author: The Hunters Ledger
date: '2025-10-20'
tags:
    - attack.exfiltration
    - attack.t1567.002
    - detection.emerging-threats
logsource:
    category: proxy
detection:
    selection:
        cs-host: 'api.dropboxapi.com'
    condition: selection
falsepositives:
    - Legitimate enterprise Dropbox integrations or file-sync clients (tune to server-class hosts or add known-good source allowlist)
level: medium
```
---

### Unexpected S3 Bucket Activity
**CloudTrail**
```yaml
title: Suspicious S3 Activity
id: 867d2a1e-171b-494a-baa3-f7c570e43186
status: experimental
description: Detects PutObject or DeleteObject S3 API calls by an IAM user, consistent with the Webshells-to-the-Cloud campaign operator staging or removing exfiltrated data in an attacker-accessible bucket after webshell-based access.
references:
    - https://the-hunters-ledger.com/hunting-detections/webshells-to-the-cloud/
author: The Hunters Ledger
date: '2025-10-20'
tags:
    - attack.exfiltration
    - attack.t1567.002
    - detection.emerging-threats
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventName:
            - 'PutObject'
            - 'DeleteObject'
        userIdentity.type: 'IAMUser'
    condition: selection
falsepositives:
    - Legitimate application or backup workflows performing routine S3 object writes and deletes under the same IAM user (tune to unexpected buckets or unusual source IPs)
level: high
```
---

## Infrastructure Automation Layer

### Unusual WordPress Installs
**Web Logs**
```yaml
title: Suspicious WordPress Install
id: 02dc195f-4f04-4fd9-9fe0-224e63e90560
status: experimental
description: Detects a POST request to the WordPress installer endpoint, consistent with the Webshells-to-the-Cloud campaign operator standing up a new WordPress instance on compromised infrastructure as part of automated infrastructure buildout.
references:
    - https://the-hunters-ledger.com/hunting-detections/webshells-to-the-cloud/
author: The Hunters Ledger
date: '2025-10-20'
tags:
    - attack.persistence
    - attack.t1505.003
    - detection.emerging-threats
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem: '/wp-admin/install.php'
        cs-method: 'POST'
    condition: selection
falsepositives:
    - Legitimate first-time setup of a new WordPress installation by an administrator
level: medium
```
---

### Reverse Proxy Creation
**Nginx Logs**
```yaml
title: nginx Configuration File Modified
id: 4de0ab63-3b37-4203-ba70-721af47514f4
status: experimental
description: >-
  Detects file writes under /etc/nginx/. A malicious outbound reverse-proxy relay requires
  a proxy_pass directive to an external host, which file-event telemetry cannot inspect -
  treat this as a hunting lead requiring a content diff of the changed config.
references:
    - https://the-hunters-ledger.com/hunting-detections/webshells-to-the-cloud/
author: The Hunters Ledger
date: '2025-10-20'
tags:
    - attack.command-and-control
    - attack.t1090
    - detection.emerging-threats
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|contains: '/etc/nginx/'
    condition: selection
falsepositives:
    - Legitimate infrastructure changes adding a proxy upstream to an external, authorized destination
    - Certbot/TLS certificate renewals
    - Configuration-management pushes
    - Legitimate administrator edits to nginx config
level: medium
```

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
