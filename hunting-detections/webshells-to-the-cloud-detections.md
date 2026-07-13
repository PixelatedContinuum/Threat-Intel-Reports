---
title: "Detection Rules — From Webshells to the Cloud"
date: '2025-10-20'
layout: post
permalink: /hunting-detections/webshells-to-the-cloud-detections/
hide: true
redirect_from: /hunting-detections/webshells-to-the-cloud
thumbnail: /assets/images/cards/webshells-to-the-cloud.png
---

**Campaign:** Webshells-To-Cloud-Modular-Intrusion
**Date:** 2025-10-20
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/webshells-to-the-cloud/

---

## Detection Coverage Summary

This campaign is a modular, multi-phase intrusion chain: PHP webshell deployment against an exploited CloudPanel file-manager component, followed by a pivot into cloud-infrastructure abuse for command-and-control, data exfiltration, and automated attack-infrastructure buildout. No file-level artifacts (packed binaries, implants) were documented for this campaign — the toolkit operates through web requests, host commands, and cloud API calls rather than a deployed executable — so there is no YARA coverage. Two originally authored rules (an unscoped AWS S3 write/delete selector and a bare webshell command-parameter match) were retired as ubiquitous-activity noise rather than kept as alerting content; see Coverage Gaps.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 0 | 0 | — | 0 |
| Sigma | 0 | 8 | T1190, T1505.003, T1136.001, T1567.002, T1090 | 0 |
| Suricata | 0 | 1 | T1505.003 | 0 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Why no Detection-tier rules.** Every surviving indicator in this campaign keys on either a single operator-chosen literal (a cookie name, an account name, an exact file path, a POST parameter) that a redeployment trivially renames, or a durable-but-shared artifact (a CGI endpoint, a WordPress core path, an nginx config directory, a legitimate dual-use tool) with a real, documented legitimate-use collision. None clear the "reliably rare/no FP" bar required for Detection — all eight surviving Sigma rules and the one surviving Suricata rule are scoped to Hunting.

---

## Sigma Rules

### Hunting Rules

#### Suspicious File Manager / phpMyAdmin Access

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1190 (Exploit Public-Facing Application)
**Confidence:** HIGH
**Rationale:** The selector list mixes a distinctive, technique-specific path (`file-manager/backend/makefile` — the exploited backend endpoint of the vulnerable CloudPanel file-manager component) with a bare directory substring (`phpmyadmin/js/`) that also matches routine `.js` asset loading on any legitimately deployed phpMyAdmin instance. Because the condition is OR-matched, a hit on the generic branch fires identically to a hit on the distinctive branch, so `level: high` on the combined selector overstated confidence — demoted to `medium` and scoped to Hunting.
**False Positives:**
- Routine JavaScript asset loading on any legitimately deployed phpMyAdmin instance under normal page rendering (matches the `phpmyadmin/js/` branch).
- Legitimate administrative access to a deployed file-manager instance predating compromise.
**Deployment:** Web/proxy log monitoring at the application server; prioritize analyst review of hits on `file-manager/backend/makefile` specifically.

```yaml
title: Suspicious File Manager Access
id: 417a6801-8ed4-4a4c-b00a-5fb13005905e
status: experimental
description: Detects HTTP requests to exposed file-manager and phpMyAdmin backend paths commonly abused for initial access and file staging in the Webshells-to-the-Cloud campaign.
references:
    - https://the-hunters-ledger.com/hunting-detections/webshells-to-the-cloud-detections/
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
    - Routine JavaScript asset loading on a legitimately deployed phpMyAdmin instance
    - Legitimate administrative access to a deployed file-manager instance predating compromise
level: medium
```

---

#### Suspicious Clp-Fm Cookie

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1505.003 (Server Software Component: Web Shell)
**Confidence:** HIGH
**Rationale:** `clp-fm` is a single session-cookie-name literal set by the file-manager webshell component observed in this campaign — durable only for as long as the operator's tooling keeps this exact name, and trivially renamed on a rebuild or a different toolkit. Per the durability rubric a single-cookie-name anchor is a Hunting-grade indicator, not a Detection one.
**False Positives:**
- Possible collision if CloudPanel's own File Manager feature uses a similarly-named session cookie on an unexploited instance.
- Unlikely otherwise — this cookie name is not known to be used by other software.
**Deployment:** Web/proxy log or WAF cookie inspection at the application server.

```yaml
title: Suspicious Clp-Fm Cookie
id: f3f41eba-22fa-464d-bbce-47ca27ce5a34
status: experimental
description: Detects the operator-distinctive clp-fm session cookie used by the file-manager webshell component of the Webshells-to-the-Cloud campaign to maintain authenticated access to the compromised backend.
references:
    - https://the-hunters-ledger.com/hunting-detections/webshells-to-the-cloud-detections/
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
    - Possible collision if CloudPanel's own File Manager feature uses a similarly-named session cookie on an unexploited instance
    - Unlikely otherwise — this cookie name is not known to be used by other software
level: medium
```

---

#### Suspicious User Creation (zeroday)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1136.001 (Create Account: Local Account)
**Confidence:** HIGH
**Rationale:** Keys on a single operator-chosen username (`zeroday`) passed as the first argument to `useradd`. The underlying technique — local account creation via `useradd` — is far too common to alert on by itself; the `zeroday` literal is what makes this rule actionable today, but it is trivially renamed on the next deployment. Durability governs over today's clean precision, so this stays a Hunting anchor rather than Detection despite the near-zero current false-positive rate.
**False Positives:**
- Legitimate administrator provisioning a local account that happens to share this name (verify against IT asset management).
**Deployment:** Linux host auditd-fed SIEM; cross-reference hits against the account credential pair already carried in the IOC feed.

```yaml
title: Suspicious User Creation
id: 3dd2ccc6-76a3-4983-ae38-e76e4ef9922f
status: experimental
description: Detects creation of the operator-distinctive local account 'zeroday' via useradd, used as a persistence mechanism in the Webshells-to-the-Cloud campaign after initial webshell access.
references:
    - https://the-hunters-ledger.com/hunting-detections/webshells-to-the-cloud-detections/
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
level: medium
```

---

#### Webshell File Creation

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1505.003 (Server Software Component: Web Shell)
**Confidence:** HIGH
**Rationale:** Keys on one exact, full file path — a single-build artifact that a re-deployment defeats simply by choosing a different filename. The parent directory (`/htdocs/app/files/public/`) is independently documented elsewhere in this investigation as a notable path, which supports treating the directory as the durable element and the filename as the brittle one, but the rule as written requires the full combination, so it scores as a Hunting anchor rather than Detection.
**False Positives:**
- Unlikely — this exact file path is specific to the compromised application instance observed in this campaign.
**Deployment:** Linux file-integrity monitoring / EDR file-event telemetry on the application server.

```yaml
title: Webshell File Creation
id: 3e0b3119-6680-4972-bf69-9461c9eff56b
status: experimental
description: Detects creation of the operator-distinctive webshell file at the compromised application's public files directory, observed in the Webshells-to-the-Cloud campaign.
references:
    - https://the-hunters-ledger.com/hunting-detections/webshells-to-the-cloud-detections/
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
level: medium
```

---

#### Rclone Execution

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1567.002 (Exfiltration to Cloud Storage)
**Confidence:** HIGH
**Rationale:** `rclone.exe` is a legitimate, publicly available cloud-sync utility reused for exfiltration across many unrelated campaigns and threat actors — the binary name is a durable, well-known dual-use artifact, but that same popularity brings a real, common legitimate-use collision (rclone is mainstream IT backup/sync tooling). `level: high` on a bare image-name match with no command-line or destination scoping overstated confidence for a tool this widely used legitimately.
**False Positives:**
- Legitimate IT administration or backup automation using rclone for authorized cloud-sync tasks.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM process-creation telemetry; correlate with an unexpected remote/cloud destination before escalating.

```yaml
title: Rclone Execution
id: 960b3056-e0d5-4d0b-a422-f571d24a15cb
status: experimental
description: Detects execution of the rclone cloud-sync utility, used by the Webshells-to-the-Cloud campaign operator to stage and exfiltrate data to attacker-controlled cloud storage after webshell-based access.
references:
    - https://the-hunters-ledger.com/hunting-detections/webshells-to-the-cloud-detections/
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
level: medium
```

---

#### Dropbox API Traffic

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1567.002 (Exfiltration to Cloud Storage)
**Confidence:** HIGH
**Rationale:** `api.dropboxapi.com` is Dropbox's own fixed API hostname — durable in that the operator cannot rotate it, but it is also a mainstream SaaS domain that any organization with a legitimate Dropbox integration contacts routinely. The rule's own original framing already called for allowlist tuning, consistent with a Hunting disposition; `level: medium` was already correctly calibrated.
**False Positives:**
- Legitimate enterprise Dropbox integrations or file-sync clients (tune to server-class hosts or add a known-good source allowlist).
**Deployment:** Proxy/web-gateway log monitoring; highest value in environments with no legitimate Dropbox usage baseline.

```yaml
title: Dropbox API Traffic
id: c9aac2c1-2261-4c14-ae47-bd9d193eb4bc
status: experimental
description: >-
  Detects outbound traffic to the Dropbox API, used as an alternate cloud-storage exfiltration channel alongside rclone/S3 in the Webshells-to-the-Cloud campaign. Legitimate enterprise Dropbox integrations will require allowlist tuning.
references:
    - https://the-hunters-ledger.com/hunting-detections/webshells-to-the-cloud-detections/
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

#### Suspicious WordPress Install

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1505.003 (Server Software Component: Web Shell) — mapped as originally authored; more precisely this describes the operator standing up new attacker-controlled web application infrastructure on already-compromised hosting rather than a webshell backdoor specifically (see Coverage Gaps).
**Confidence:** MODERATE
**Rationale:** `/wp-admin/install.php` is a fixed WordPress core path — durable, since the operator cannot rename WordPress's own installer script — but whether a POST to it is rare enough to alert on depends entirely on whether the monitored hosting environment routinely provisions fresh WordPress sites (shared hosting does; a narrowly-scoped application server should not). Without that environment context, "rare FP" cannot be confidently claimed, so this stays Hunting.
**False Positives:**
- Legitimate first-time setup of a new WordPress installation by an administrator.
**Deployment:** Web/proxy log monitoring; highest value on hosts that are not expected to run general-purpose CMS software.

```yaml
title: Suspicious WordPress Install
id: 02dc195f-4f04-4fd9-9fe0-224e63e90560
status: experimental
description: Detects a POST request to the WordPress installer endpoint, consistent with the Webshells-to-the-Cloud campaign operator standing up a new WordPress instance on compromised infrastructure as part of automated infrastructure buildout.
references:
    - https://the-hunters-ledger.com/hunting-detections/webshells-to-the-cloud-detections/
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

#### Nginx Configuration File Modified

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1090 (Proxy)
**Confidence:** MODERATE
**Rationale:** The rule's own description already frames this as a hunting lead requiring a manual content diff, since file-event telemetry cannot inspect the `proxy_pass` directive that would confirm malicious reverse-proxy intent. `/etc/nginx/` is nginx's own fixed configuration directory (durable, not attacker-renameable), but any write under it — certificate renewals, configuration-management pushes, routine admin edits — matches, so this is explicitly a triage starting point, not an alerting-grade signal. `level: medium` was already correctly calibrated.
**False Positives:**
- Legitimate infrastructure changes adding a proxy upstream to an external, authorized destination.
- Certbot/TLS certificate renewals.
- Configuration-management pushes.
- Legitimate administrator edits to nginx config.
**Deployment:** Linux file-integrity monitoring; pair every hit with a manual diff of the changed configuration file.

```yaml
title: Nginx Configuration File Modified
id: 4de0ab63-3b37-4203-ba70-721af47514f4
status: experimental
description: >-
  Detects file writes under /etc/nginx/. A malicious outbound reverse-proxy relay requires
  a proxy_pass directive to an external host, which file-event telemetry cannot inspect -
  treat this as a hunting lead requiring a content diff of the changed config.
references:
    - https://the-hunters-ledger.com/hunting-detections/webshells-to-the-cloud-detections/
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

## Suricata Signatures

### Hunting Rules

#### Suspicious POST Parameter mxx

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1505.003 (Server Software Component: Web Shell)
**Confidence:** HIGH
**Rationale:** `mxx=` is a short, non-dictionary POST-parameter token independently documented as a notable artifact of this campaign's webshell tooling — low collision risk with legitimate software, but it is a single operator/tool-chosen literal that a rebuild or parameter rename trivially defeats, capping it at Hunting rather than Detection. The original rule shipped with no `flow`, `classtype`, or `metadata`; reformatted here to the current Suricata authoring standard (added `flow`, `threshold`, `classtype`, `metadata`, and scoped the header from `any any -> any any` to inbound traffic at the monitored web server). `sid` is preserved unchanged from the original to keep the existing published-feed SID mapping stable; `rev` incremented to 2 to reflect the scoping change.
**False Positives:** Unlikely — "mxx" has not been observed as a parameter name in mainstream legitimate web software; residual risk from any unrelated third-party application that happens to reuse the same short parameter name.
**Deployment:** Network IDS/IPS inspecting HTTP POST bodies at the perimeter or reverse-proxy tier.

```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"THL Webshells-To-Cloud-Modular-Intrusion Suspicious mxx POST Parameter (Webshell Command Parameter Indicator)"; flow:established,to_server; http.request_body; content:"mxx="; nocase; threshold:type limit,track by_src,count 1,seconds 3600; classtype:web-application-attack; sid:100002; rev:2; metadata:author The_Hunters_Ledger, date 2025-10-20, reference https://the-hunters-ledger.com/hunting-detections/webshells-to-the-cloud-detections/;)
```

---

## Coverage Gaps

**Suspicious S3 Activity — Cut (Gate 2: ubiquitous benign activity, no pivot value).** The original rule matched any `PutObject`/`DeleteObject` S3 API call made by an IAM-type principal, with no bucket scope, no source-IP filter, and no volume threshold. `PutObject`/`DeleteObject` are the most routine S3 operations in existence — any actively used AWS account generates a continuous baseline of both, from application storage and normal user activity. Removing the `userIdentity.type: IAMUser` filter leaves nothing narrower than "any S3 write or delete," and the filter itself only excludes automated role-based activity, not the much larger population of legitimate human/application IAM-user writes. `level: high` on this selector significantly overstated confidence. The exfiltration-to-cloud-storage technique (T1567.002) this rule targeted remains covered by the Rclone Execution and Dropbox API Traffic Hunting rules above. **What would enable a rule:** a specific attacker-controlled bucket name, an unusual source IP/region for the IAM principal, or a write-volume threshold tied to a short time window.

**Webshell Command Execution (`cmd=` in URI) — Cut (Gate 2: ubiquitous benign parameter convention, no pivot value).** The original rule matched any HTTP URI containing the substring `cmd=`, with no host scope, no flow direction, no classtype, and no threshold. Unlike the campaign-specific `mxx` parameter, `cmd` is a common, recognizable parameter-name convention independently used by numerous legitimate systems (network/IoT device web-management UIs, various CGI scripts and admin tools), and the value is not independently documented as a notable indicator elsewhere in this investigation. **What would enable a rule:** a specific, distinctive command value, or a required pairing with another campaign-specific marker (for example, requiring `cmd=` together with the `mxx` POST parameter or the `clp-fm` cookie in the same request) to exclude the broader population of legitimate `cmd=` usage.

**No feed edits were required.** Neither cut rule routed to the IOC feed — both failed on Gate 2 (precision/ubiquity), not Gate 1 (a hard-coded IP/hash/domain masquerading as a rule), so there was no atomic indicator to add. The account credential (`zeroday` and its associated password), the `clp-fm` cookie name, the `mxx` POST parameter, and the relevant file paths were already present in [`webshells-to-the-cloud-iocs.json`](/ioc-feeds/webshells-to-the-cloud-iocs.json) from the original analysis and required no changes.

**Banner/response strings documented in the IOC feed but not expressed as network signatures.** The feed's banner-string list carries two values not covered by any rule in this file: `CloudPanel 0day Version : 2.0.0 >= 2.3.0` (a version-fingerprint string, likely returned during the operator's own vulnerability-check probe rather than by legitimate CloudPanel traffic) and a Chinese-language string translating to "Target WebShell Upload Successful" (a webshell-upload confirmation banner consistent with a Chinese-language exploitation toolkit). Both are plausible candidates for a future Suricata `http.response_body` content signature, but no HTTP response/transaction context (which endpoint returns them, over what protocol, at what stage of the chain) is documented in this investigation to scope such a rule with confidence.

**MITRE mapping note (Suspicious WordPress Install).** The original T1505.003 (Server Software Component: Web Shell) mapping is carried forward from the original analysis, but a fresh WordPress installation is not itself a webshell — it more precisely describes the operator staging new attacker-controlled web application infrastructure on already-compromised hosting. No stronger evidence is available in this file to justify remapping to a Resource Development technique (which would also require reframing the finding as attacker-owned infrastructure rather than a compromised victim asset), so the original mapping is retained with this caveat rather than changed without supporting evidence.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
