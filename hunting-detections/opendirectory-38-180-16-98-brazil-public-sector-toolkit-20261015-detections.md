---
title: "Detection Rules — Brazil Public-Sector Toolkit (38.180.16.98)"
date: '2026-10-09'
layout: post
permalink: /hunting-detections/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015-detections/
hide: true
---

**Campaign:** INV-2026-067<br>
**Date:** 2026-10-09<br>
**Author:** The Hunters Ledger<br>
**License:** CC BY 4.0<br>
**Reference:** https://the-hunters-ledger.com/reports/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015/

---

## Detection Coverage Summary

These rules come from four things I could establish in this case: the wire protocol of the operator's reverse relay, recorded in a contained run of its source; the request bodies the operator used to plant and then scrub a command-execution page on a WebLogic host; the commands the operator's Zabbix scripts ask monitored hosts to run; and the unauthenticated entry point on a GLPI help desk. The relay rules are the only ones I could fire against a real capture. Everything built from operator scripts is script-only evidence: no reply, no run record and no victim file is held for the WebLogic and Zabbix behaviour, so those rules are grounded in what the scripts ask for and have not been seen firing on victim telemetry.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 0 | 0 | None | 0 |
| Sigma | 3 | 2 | T1505.003, T1059.004, T1070, T1072, T1552, T1190 | 0 |
| Suricata | 3 | 5 | T1090.001, T1095, T1190 | 0 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient, safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting. Expect to review the hits.

The relay controller address (38.180.16[.]98, TCP 53), the operator's callback ports and the collector address are single-literal indicators. I did not turn any of them into a rule: removing the address leaves nothing to detect. They belong in an IOC feed, and the companion feed carries them, so the Atomics column counts 0 authored inside this file.

I deliberately wrote no YARA (the planted page body and the verbatim request text are not held outside the original capture), no Zabbix API rule (no log schema is held), no rule on the relay source file name, and no rule on the operator-facing WAF block page. The reasons are in Coverage Gaps.

All eight load under `suricata -T` (Suricata 8.0.7). Replayed against the capture of the relay run (23 TCP flows, 22 relay sessions plus the relay's one onward connection), the announce rule fired on 22 of 22 sessions.

Two caveats travel with every hit count below. The capture used for replay is the filtered one, so the 37 other flows from the original capture are not available, and the only non-relay flow in it is the onward HTTP connection. For false positives I therefore used 2,411 TCP flows from seven unrelated captures of other campaigns (plus one more capture that was replayed but whose flows could not be counted) and a small synthetic control capture I built from the documented byte shapes. None of those contains a real DNS-over-TCP exchange, so the DNS control is synthetic only.

The file-level validation reports the file valid with 0 errors and 10 warnings. Every warning is a NOT CHECKED: web-corpus prevalence could not be measured for any Suricata rule, and the Sigma prior-art comparison returned UNCLEARED for four rules and NOT CHECKED for the Linux file-event rule, which is not a clearance. My novelty statements come from the direct searches described per rule.

---

## YARA Rules

None written. The two candidates (the planted page and the request envelope that writes it) rest on text that is held only in the original capture, so a rule would be built from my prose summary of the strings. The reasoning is under Coverage Gaps.

---

## Sigma Rules

All five Sigma rules passed `sigma check` with SigmaHQ's own configuration, `yamllint`, SigmaHQ's `test_rules.py` and `test_logsource.py`, and converted to EQL and Lucene with the `sysmon` pipeline. None has been run against a Linux event corpus, and the SigmaHQ baseline replay is a Windows corpus that does not apply to these log sources, so how often they fire on ordinary hosts is NOT CHECKED. A fresh read of SigmaHQ upstream (3,791 rule files, commit 8a4813404 of 2026-10-06) found no file mentioning htmlawed, CVE-2022-35914, `_WL_internal`, `health.jsp` or Zabbix.

### Detection Rules

#### WebLogic Java Process Spawns Shell Writing a JSP Into a WebLogic Internal Directory

**Tier:** Detection
**Robustness:** 2
**Upstream Coverage:** covered
**ATT&CK Coverage:** T1505.003 (Web Shell), T1059.004 (Unix Shell)
**ATT&CK Note:** The same activity also satisfies SigmaHQ's `proc_creation_lnx_susp_java_children` (a Java parent with `/bin/sh` in the command line), so upstream already covers the shell spawn. This rule adds the two WebLogic-specific tokens that make it alert-grade. It stays Detection tier on the site, and novelty only matters if it is submitted.
**Confidence:** MODERATE
**False Positives:** WebLogic deployment or patching scripts started from a Java based tool that copy JSP files into exploded application directories. I have no baseline from a WebLogic host, so the rate is unknown.
**Blind Spots:** A request that Base64-wraps its script, or builds the directory name at run time, hides `_WL_internal` from the command line. A plant written by the JVM itself (no shell child) never shows here. The anchor strings are the literals my read of the request body names, not a verbatim copy of the script, which is held only in the original capture.
**Validation:** `sigma check` PASS, `yamllint` PASS, `test_rules.py` PASS, `test_logsource.py` PASS, `sigma convert` EQL PASS and Lucene PASS (sysmon pipeline; field mapping into a deployed index NOT CHECKED). Fires on a real or synthetic event: NOT CHECKED. A benign case that must not fire: a Java parent spawning `/bin/sh -c "ls /tmp"`.
**Deployment:** Linux EDR or auditd process telemetry on WebLogic hosts.
**Evidence:** An operator request body (sha256 prefix 64c6c3f5034c, 1,273 bytes) holds an XMLDecoder object that starts `java.lang.ProcessBuilder` with `/bin/sh -c`. The script finds every directory named `_WL_internal` or `stage` under the domain home, writes one JSP into every subdirectory beneath each, and prints a success marker. Script-only: the request was never seen sent, and no reply and no victim file is held.

```yaml
title: WebLogic Java Process Spawns Shell Writing a JSP Into a WebLogic Internal Directory
id: 67f6efc3-d491-446b-99c9-26dec7274776
status: experimental
description: >-
    Detects a shell spawned by a Java process whose command line names a WebLogic _WL_internal directory and a .jsp file.
    This is the process-level footprint of a remote command-execution request (the XMLDecoder-in-WorkContext shape sent to the WS-AT endpoint)
    that plants a command-execution JSP into WebLogic staging directories.
    The behaviour was read from an operator's request body that finds every _WL_internal and stage directory under the domain home and writes one JSP into each subdirectory.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015-detections/
author: The Hunters Ledger
date: 2026-10-09
tags:
    - attack.persistence
    - attack.t1505.003
    - attack.execution
    - attack.t1059.004
    - stp.3
logsource:
    category: process_creation
    product: linux
    definition: 'Requires Linux process creation telemetry that records the parent image and the full command line of the child, for example auditd EXECVE records joined to the parent process, Sysmon for Linux EID 1, or an EDR sensor with equivalent fields.'
detection:
    selection:
        ParentImage|endswith: '/java'
        Image|endswith:
            - '/sh'
            - '/bash'
            - '/dash'
        CommandLine|contains|all:
            - '_WL_internal'
            - '.jsp'
    condition: selection
falsepositives:
    - WebLogic deployment or patching scripts started from a Java based tool that copy JSP files into exploded application directories
level: high
```

#### Shell Process Creates a JSP File Under a WebLogic _WL_internal Directory

**Tier:** Detection
**Robustness:** 2
**Upstream Coverage:** not_covered
**ATT&CK Coverage:** T1505.003 (Web Shell)
**Confidence:** MODERATE
**False Positives:** Administrators extracting or copying JSP files into WebLogic temporary directories by hand during troubleshooting. WebLogic's own extraction is done by the Java process and does not match the shell condition.
**Blind Spots:** The shell condition assumes the write is a shell redirection. If the script writes with `cat`, `tee` or `cp`, the creating process is that tool and the rule misses it. A plant written by the JVM itself also misses. Needs file creation telemetry with the creating process, which is not a default on most Linux hosts.
**Validation:** `sigma check` PASS, `yamllint` PASS, `test_rules.py` PASS, `test_logsource.py` PASS, `sigma convert` EQL PASS and Lucene PASS (sysmon pipeline; field mapping NOT CHECKED). Fires on a real or synthetic event: NOT CHECKED. Benign case that must not fire: the WebLogic JVM extracting a deployed web application into the same directory.
**Deployment:** Linux EDR file-creation events on WebLogic hosts.
**Evidence:** Same request body as the rule above (sha256 prefix 64c6c3f5034c). The mechanism the script uses to write each JSP (redirection, `cat`, `tee`) is not stated in my read, which is why the shell condition is a Blind Spot and not a certainty.

```yaml
title: Shell Process Creates a JSP File Under a WebLogic _WL_internal Directory
id: f3c8d853-4507-4818-9883-a79f977a41a9
status: experimental
description: >-
    Detects a shell creating a .jsp file below a _WL_internal directory.
    WebLogic's own Java process extracts web application contents there, so a shell as the writing process marks a file placed from outside the deployment path.
    Read from an operator's request body that writes a command-execution JSP into every subdirectory of every _WL_internal and stage directory under a domain home.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015-detections/
author: The Hunters Ledger
date: 2026-10-09
tags:
    - attack.persistence
    - attack.t1505.003
    - stp.3
logsource:
    category: file_event
    product: linux
    definition: 'Requires Linux file creation telemetry that records the creating process image and the target path, for example Sysmon for Linux EID 11 or an EDR sensor with file creation events. auditd path rules on the WebLogic domain home would also work but are not default.'
detection:
    selection:
        TargetFilename|contains: '/_WL_internal/'
        TargetFilename|endswith: '.jsp'
        Image|endswith:
            - '/sh'
            - '/bash'
            - '/dash'
    condition: selection
falsepositives:
    - Administrators extracting or copying JSP files into WebLogic temporary directories by hand during troubleshooting
level: high
```

#### GLPI htmLawed Test Page POST Request (CVE-2022-35914, Renamed Copy Included)

**Tier:** Detection
**Robustness:** 2
**Upstream Coverage:** not_covered
**ATT&CK Coverage:** T1190 (Exploit Public-Facing Application)
**ATT&CK Note:** SigmaHQ has no rule for this CVE. CrowdSec (scenario and virtual-patch rule) and a Juniper IPS signature exist, found by a web search on 2026-10-09 and read only as titles and summaries. The CrowdSec descriptions key on the default file name, `htmLawedTest.php`, and so would not match the renamed copy the operator's helper posts to.
**Confidence:** HIGH
**False Positives:** Unlikely. GLPI's `vendor` directory is not meant to be served, and a POST to a PHP file inside it has no application reason. A vulnerability scanner that probes the default path with GET is not matched.
**Blind Spots:** The access log does not carry the request body, so the rule cannot see the `hhook` and `text` fields and cannot tell a probe from an exploit. A server that blocks `/vendor/` at the web server still logs the request, so a hit shows only that the request arrived. A copy moved out of the `htmlawed` directory is missed.
**Validation:** `sigma check` PASS, `yamllint` PASS, `test_rules.py` PASS, `test_logsource.py` PASS, `sigma convert` EQL PASS and Lucene PASS (sysmon pipeline; field mapping NOT CHECKED). Fires on a real or synthetic event: NOT CHECKED. Benign case that must not fire: a POST to the GLPI login form.
**Deployment:** Web server or reverse proxy access logs in front of GLPI.
**Evidence:** The operator's helper (sha256 prefix c195c55f4e8f, 28 lines) holds one hard-coded URL, a renamed copy of the htmLawed test page under GLPI's `vendor/htmlawed/htmlawed/` directory, labels it with this CVE, sends no credential, and posts three form fields named `sid`, `hhook` and `text`. Its output was recovered in the operator's staging files as a 14-piece package that matches the vendor's own manifest hash, so the channel executed commands. The renamed suffix is a victim-side detail I have left out.

```yaml
title: GLPI htmLawed Test Page POST Request (CVE-2022-35914, Renamed Copy Included)
id: 20c855ee-9086-444b-885c-59a6abba56c1
status: experimental
description: >-
    Detects a POST request to a PHP file inside GLPI's bundled htmlawed vendor directory.
    The unauthenticated command execution in CVE-2022-35914 is reached through the htmLawedTest page, and an operator tool read in this case posts to a copy that had been renamed with a suffix, so the match uses the directory and not the default file name.
    A GLPI web root should never serve its vendor directory.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015-detections/
    - https://nvd.nist.gov/vuln/detail/CVE-2022-35914
author: The Hunters Ledger
date: 2026-10-09
tags:
    - attack.initial-access
    - attack.t1190
    - cve.2022-35914
    - detection.emerging-threats
    - stp.3
logsource:
    category: webserver
    definition: 'Requires web server access logs that record the request method and URI, for example Apache or nginx access logs on the GLPI host or the reverse proxy in front of it, with the full request URI mapped to cs-uri-query as the other SigmaHQ webserver rules do. The request body is not in these logs, so the match is on method and path only.'
detection:
    selection:
        cs-method: 'POST'
        cs-uri-query|contains|all:
            - '/vendor/htmlawed/htmlawed/'
            - '.php'
    condition: selection
falsepositives:
    - Unlikely
level: high
```

### Hunting Rules

#### Java Process Spawns Shell to Rewrite Log Files

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1070 (Indicator Removal)
**ATT&CK Note:** I used the parent technique. The operator removes only the lines naming its own planted page, which fits the Linux log sub-techniques loosely, and I did not want to claim a sub-technique the evidence does not pick.
**Confidence:** LOW
**False Positives:** Log housekeeping scripts started from a Java based scheduler or management agent. A shell that pipes a log through `grep -v` is common administration, which is why this sits at Hunting.
**Blind Spots:** The operator's scrub also needs the exact command text, which I have only as a description (a `grep -v` into a temporary file, then a copy back over each log). A variant using `sed -i` or `awk` is missed. After a successful scrub the log no longer names the planted page, so the file system is the place to look.
**Validation:** `sigma check` PASS, `yamllint` PASS, `test_rules.py` PASS, `test_logsource.py` PASS, `sigma convert` EQL PASS and Lucene PASS (sysmon pipeline; field mapping NOT CHECKED). Fires on a real or synthetic event: NOT CHECKED. Benign case that must not fire: a Java parent running `/bin/sh -c "ls /tmp"`.
**Deployment:** Linux EDR or auditd process telemetry on application server hosts.
**Evidence:** An operator cleanup request (sha256 prefix 6c44d4ae4c5a, 1,325 bytes) deletes the planted page at one path, then for every `*.log*` file under the user projects directory rewrites it without the lines matching the page name. Script-only; the order of use against the count probe below is not established.

```yaml
title: Java Process Spawns Shell to Rewrite Log Files
id: 410da2b6-3023-4f5f-a9a2-1e7abf0c3783
status: experimental
description: >-
    Detects a shell spawned by a Java process whose command line combines grep -v with a .log file pattern.
    Read from an operator's request body that rewrites every log file under a WebLogic domain home without the lines naming a planted JSP, through a temporary file and a copy back.
    Hunting rule, because legitimate Java launched maintenance scripts also filter logs.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015-detections/
author: The Hunters Ledger
date: 2026-10-09
tags:
    - attack.stealth
    - attack.t1070
    - stp.3
logsource:
    category: process_creation
    product: linux
    definition: 'Requires Linux process creation telemetry that records the parent image and the full command line of the child, for example auditd EXECVE records joined to the parent process, Sysmon for Linux EID 1, or an EDR sensor with equivalent fields.'
detection:
    selection:
        ParentImage|endswith: '/java'
        Image|endswith:
            - '/sh'
            - '/bash'
            - '/dash'
        CommandLine|contains|all:
            - 'grep -v'
            - '.log'
    condition: selection
falsepositives:
    - Log housekeeping scripts started from a Java based scheduler or management agent
level: medium
```

#### Zabbix Daemon Child Process Touching Credential Files or Instance Metadata

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1072 (Software Deployment Tools), T1552 (Unsecured Credentials)
**ATT&CK Note:** T1072 is the closest fit for abusing a monitoring suite's script execution, though not an exact one. The case marks the Zabbix login itself as inferred, so this rule describes what the scripts ask for, not a confirmed victim event.
**Confidence:** LOW
**False Positives:** Monitoring items or global scripts that deliberately check `authorized_keys` or shell history for compliance, and authorized network scanning started from a Zabbix global script. A Zabbix agent running a user parameter that reads one of these files will also match.
**Blind Spots:** The tokens are the file names and addresses my read of the operator scripts names. The command text is hand-decoded in places and no output of any of these requests is held, so I do not know that any of them ran. A command that builds the path at run time is missed. It needs the parent process name, which the Zabbix daemons set but some EDR sensors do not resolve.
**Validation:** `sigma check` PASS, `yamllint` PASS, `test_rules.py` PASS, `test_logsource.py` PASS, `sigma convert` EQL PASS and Lucene PASS (sysmon pipeline; field mapping NOT CHECKED). Fires on a real or synthetic event: NOT CHECKED. Benign case that must not fire: a Zabbix agent running its standard `system.uptime` item.
**Deployment:** Linux process telemetry on Zabbix servers, proxies and monitored hosts.
**Evidence:** The operator's Zabbix API scripts create global scripts and `system.run` items. Scripts that request root and administrator shell histories, the password digest and authorized-key files, and instance metadata tokens are read as source only. The item export the operator holds contains 11,240 non-empty `system.run` values from monitored hosts, 1,431 of them carrying Nmap output markers, but which operator script created them is not shown.

```yaml
title: Zabbix Daemon Child Process Touching Credential Files or Instance Metadata
id: 7fc3ea3a-98a7-4a97-877a-a8a4dbfefc48
status: experimental
description: >-
    Detects a child process of a Zabbix server, proxy or agent daemon whose command line names the password digest file, shell history, authorized keys, the cloud instance metadata address or nmap.
    Read from an operator's Zabbix API scripts that create global scripts and system.run items to run exactly these requests on a proxy and on monitored hosts; no output of them was held.
    Hunting rule, because monitoring administrators legitimately run commands through the same daemons.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015-detections/
author: The Hunters Ledger
date: 2026-10-09
tags:
    - attack.execution
    - attack.t1072
    - attack.lateral-movement
    - attack.credential-access
    - attack.t1552
    - stp.3
logsource:
    category: process_creation
    product: linux
    definition: 'Requires Linux process creation telemetry that records the parent image and the full command line of the child, for example auditd EXECVE records joined to the parent process, Sysmon for Linux EID 1, or an EDR sensor with equivalent fields.'
detection:
    selection_parent:
        ParentImage|endswith:
            - '/zabbix_server'
            - '/zabbix_proxy'
            - '/zabbix_agentd'
            - '/zabbix_agent2'
    selection_cmd:
        CommandLine|contains:
            - '/etc/shadow'
            - '.bash_history'
            - 'authorized_keys'
            - '169.254.169.254'
            - 'nmap '
    condition: all of selection_*
falsepositives:
    - Monitoring items or global scripts that deliberately check authorized_keys or shell history for compliance
    - Authorized network scanning started from a Zabbix global script
level: medium
```

---

## Suricata Signatures

The relay speaks a plain ASCII line protocol over TCP port 53 and uses no DNS framing, no encryption and no authentication. I recorded it in a contained run of the relay source against a stand-in controller I wrote from the source's own parsing block. The relay opens the connection and speaks first: `READY2` and a newline (7 bytes), then `PING` and a newline (5 bytes) every 15 seconds while idle. The controller answers with one line, `DIAL <host> <port>` and a newline, and the relay replies `OK` or `FAIL` with a newline and then splices the two sockets byte for byte. Two limits apply to every rule here. The controller-side bytes are my stand-in's, since no real controller line was ever observed on the wire, and the operator's own relay log shows a second lane labelled `READY`, whose announce I did not see and do not write a rule for.

Test results are for the rules with their `threshold` lines removed, so that every hit is countable; the deployable form below keeps the thresholds. With thresholds the announce rule alerts once per source per hour (1 alert on the same capture), and the flowbit-gated rules still fired on every session because the flowbit is set whether or not the alert is suppressed.

| Test input | Flows | READY2 53 | READY2 other | ASCII line 53 | PING | DIAL | OK | FAIL | HTTP htmLawed |
|---|---|---|---|---|---|---|---|---|---|
| Relay run capture (22 relay sessions plus 1 onward flow) | 23 | 22 | 0 | 22 | 11 | 2 | 1 | 1 | 0 |
| Seven unrelated captures (TCP flows counted) | 2,411 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| One further unrelated pcapng (flows not counted) | not counted | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Synthetic negative controls (DNS over TCP with correct framing, bare PING and READY on other ports, benign HTTP POSTs, a GET to the htmlawed directory, a form with an `hhook` field elsewhere, an SSH banner on port 22) | 12 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Synthetic positives (READY2 and PING on port 8080; SSH banner on port 53; POST to the default and a renamed htmLawed test page) | 4 | 0 | 1 | 1 | 1 | 0 | 0 | 0 | 2 |

Hit counts are alerts; for every rule above each alert fell in a different flow except the keepalive rule, where 11 alerts fell in 2 flows. All eight rules produced no alert on the relay run's one non-relay flow (the onward HTTP connection). The synthetic rows are bytes I constructed to match the documented shapes, so they show that the rules are wired correctly and nothing about real-world rates.

### Detection Rules

#### Reverse Relay READY2 Announce on TCP 53

**Tier:** Detection
**Robustness:** 2
**Upstream Coverage:** not_covered
**ATT&CK Coverage:** T1090.001 (Internal Proxy), T1095 (Non-Application Layer Protocol)
**ATT&CK Note:** Port 53 is not evidence of DNS here, so T1071.004 is deliberately not claimed.
**Confidence:** HIGH
**False Positives:** None known. A resolver's TCP exchange starts with a two-byte length and a twelve-byte header, so a whole first payload of `READY2` plus a newline is not a DNS message. The only support for that is a synthetic control, since none of my negative captures holds a real DNS-over-TCP exchange.
**Blind Spots:** A recompile that changes the announce string defeats it; the case already shows two lane labels, `READY` and `READY2`. A recompile to another port is only partly covered by the port-agnostic hunting rule below. It sees the first segment only if the sensor sits on the egress path of the host running the relay. Encrypted or tunnelled variants are not covered.
**Validation:** `suricata -T` PASS (8.0.7). Replay on the relay run capture: 22 of 22 relay sessions, 0 on the onward flow; 0 on 2,411 flows from other captures; 0 on the 12-flow synthetic negative set. Not run against a real DNS-over-TCP capture: NOT CHECKED.
**Deployment:** Perimeter sensor on the egress path, with `$HOME_NET` covering the hosts that can run a Java relay.
**Evidence:** All 22 relay sessions in the contained run opened with exactly these seven bytes as the first and only relay segment. The operator's own relay log records 1,051 check-ins across its two lanes, so the announce is the one thing every session produces whether or not the controller ever tasks it. Relay source sha256 prefix 986f697d2ef6.

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"THL DETECT INV-2026-067 Reverse Relay READY2 Announce on TCP 53 (Non-DNS Plaintext Handshake)"; flow:established,to_server; dsize:7; content:"READY2|0a|"; startswith; flowbits:set,thl.inv067.relay; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015-detections/; classtype:trojan-activity; sid:1000001; rev:1; metadata:author The_Hunters_Ledger, date 2026-10-09;)
```

#### Reverse Relay Controller DIAL Tasking Line from TCP 53

**Tier:** Detection
**Robustness:** 2
**Upstream Coverage:** not_covered
**ATT&CK Coverage:** T1090.001 (Internal Proxy), T1095 (Non-Application Layer Protocol)
**Confidence:** MODERATE, because the line format comes from the relay's parsing code and my stand-in controller exercised it; no real controller line was seen. The operator's relay log records tunnel-up events, which fits the format without proving the bytes.
**False Positives:** None known. The rule needs `DIAL`, a host token and a decimal port in one short line sent from port 53 to an internal host. No real DNS-over-TCP traffic was available to test against.
**Blind Spots:** A controller that changes the verb, or sends the instruction in the same segment as other data, is missed. The payload is only useful for scoping if the sensor logs it: the host and port in the line name the internal destination the operator asked for, so enable payload logging for this signature in `eve.json`.
**Validation:** `suricata -T` PASS (8.0.7). Replay: 2 of 2 instruction lines in the run capture (both from my stand-in), 0 on 2,411 other flows, 0 on the synthetic negatives. Fires on a real controller line: NOT CHECKED.
**Deployment:** Same sensor; destination is any internal host, because the relay may sit anywhere inside.
**Evidence:** The relay's parsing block accepts one line, trimmed and split on spaces, and acts only when the first token is `DIAL` with at least two more tokens; anything else closes the socket and reconnects. A `DIAL` to a closed port produced the `FAIL` reply and a `DIAL` to a reachable address produced `OK` and a spliced connection.

```
alert tcp $EXTERNAL_NET 53 -> $HOME_NET any (msg:"THL DETECT INV-2026-067 Reverse Relay Controller DIAL Tasking Line from TCP 53 (Internal Destination Instruction)"; flow:established,to_client; dsize:9<>200; content:"DIAL "; startswith; content:"|0a|"; endswith; pcre:"/^DIAL [^ \r\n]{1,128} [0-9]{1,5}\n$/"; flowbits:set,thl.inv067.dial; reference:url,the-hunters-ledger.com/hunting-detections/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015-detections/; classtype:trojan-activity; sid:1000005; rev:1; metadata:author The_Hunters_Ledger, date 2026-10-09;)
```

#### GLPI htmLawed Test Page POST with hhook Parameter

**Tier:** Detection
**Robustness:** 2
**Upstream Coverage:** not_covered
**ATT&CK Coverage:** T1190 (Exploit Public-Facing Application)
**ATT&CK Note:** The ET Open ruleset on my sensor (30 files in the rules directory, last refreshed 2026-10-09) holds no rule mentioning htmLawed or this CVE. CrowdSec and Juniper coverage exists in other formats and keys on the default file name.
**Confidence:** MODERATE
**False Positives:** Unlikely. It needs a POST into GLPI's bundled htmlawed directory carrying both `hhook=` and `text=` in the body, which no ordinary GLPI page sends.
**Blind Spots:** It sees only cleartext HTTP. The help desk in this case is served over HTTPS, so the rule fires only on a sensor behind TLS termination or on a reverse proxy's plain-HTTP leg. A body with the fields in multipart encoding, or request-body inspection disabled, is missed. The value the operator sends in `hhook` is not recorded in my notes, so the rule does not use it.
**Validation:** `suricata -T` PASS (8.0.7). Synthetic only: 2 of 2 constructed POSTs matched (default and renamed path), 0 of 3 constructed benign HTTP requests, 0 on 2,411 flows from other captures. Fires on real exploit traffic: NOT CHECKED.
**Deployment:** Sensor behind the TLS terminator in front of GLPI, or on the proxy-to-GLPI segment. The Sigma web-log rule above is the cleaner option where logs, not packets, are available.
**Evidence:** The operator's helper (sha256 prefix c195c55f4e8f) posts the form fields `sid`, `hhook` and `text` to its single hard-coded URL under the `vendor/htmlawed/htmlawed/` directory and sends `sid` again as a cookie, with a placeholder value and no credential.

```
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"THL DETECT INV-2026-067 GLPI htmLawed Test Page POST with hhook Parameter (CVE-2022-35914, Renamed Copy Included)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/vendor/htmlawed/htmlawed/"; nocase; content:".php"; nocase; http.request_body; content:"hhook="; content:"text="; reference:url,the-hunters-ledger.com/hunting-detections/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015-detections/; classtype:web-application-attack; sid:1000008; rev:1; metadata:author The_Hunters_Ledger, date 2026-10-09;)
```

### Hunting Rules

#### Reverse Relay READY2 Announce on a Non-DNS Port

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1090.001 (Internal Proxy), T1095 (Non-Application Layer Protocol)
**Confidence:** LOW
**False Positives:** Unlikely, but I have no evidence for any port other than 53. The source takes its port as a compile-time value, so a different port is plausible and unobserved.
**Blind Spots:** Same announce-string dependency as the Detection rule; adds only port coverage.
**Validation:** `suricata -T` PASS (8.0.7). Synthetic positive: 1 of 1 on port 8080. Real capture: 0 (the relay used 53); 0 on 2,411 other flows and the 12-flow synthetic negative set. Fires on a real non-53 relay: NOT CHECKED.
**Deployment:** Same sensor.
**Evidence:** The source makes its destination port a compile-time value (my read of the source); only port 53 was ever observed.

```
alert tcp $HOME_NET any -> $EXTERNAL_NET !53 (msg:"THL HUNT INV-2026-067 Reverse Relay READY2 Announce on a Non-DNS Port (Port Variant)"; flow:established,to_server; dsize:7; content:"READY2|0a|"; startswith; flowbits:set,thl.inv067.relay; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015-detections/; classtype:trojan-activity; sid:1000002; rev:1; metadata:author The_Hunters_Ledger, date 2026-10-09;)
```

#### Short Printable ASCII Line as Client Payload on TCP 53

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1095 (Non-Application Layer Protocol)
**Confidence:** MODERATE
**False Positives:** Anything that speaks a plaintext line protocol on port 53, including SSH or HTTP deliberately run on that port to get through a filter. That is also a reason to look at the hit. A DNS-over-TCP message starts with a length whose first byte is below the printable range for any query under 8 KB, so ordinary resolvers do not match, but no real DNS-over-TCP traffic was in my test captures.
**Blind Spots:** It fires on the first matching packet of a flow, so a plaintext line that arrives after non-matching data is also caught, and a protocol whose first line is longer than 40 bytes is missed. It does not need the relay's string, so it should survive a rename of the announce token and would flag a `READY` lane whose bytes I never saw.
**Validation:** `suricata -T` PASS (8.0.7). Relay run capture: 22 of 22 relay sessions. Synthetic SSH banner on port 53: 1 of 1. 0 on 2,411 other flows, 0 on the synthetic negative set. Rate on real DNS-over-TCP traffic: NOT CHECKED.
**Deployment:** Same sensor, as a hunt query or low-severity alert.
**Evidence:** All 22 relay sessions open with a printable ASCII line of 7 bytes ending in a newline on port 53. Zeek raised a DNS weird on all 22 and Suricata produced no DNS record for any of them, which is the same anomaly seen from the engine side.

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"THL HUNT INV-2026-067 Short Printable ASCII Line as Client Payload on TCP 53 (Not DNS Framing)"; flow:established,to_server; flowbits:isnotset,thl.inv067.first53; dsize:3<>40; byte_test:1,>=,0x20,0; byte_test:1,<=,0x7e,0; content:"|0a|"; endswith; flowbits:set,thl.inv067.first53; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015-detections/; classtype:protocol-command-decode; sid:1000003; rev:1; metadata:author The_Hunters_Ledger, date 2026-10-09;)
```

#### Reverse Relay PING Keepalive After READY2 Announce

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1090.001 (Internal Proxy)
**Confidence:** MODERATE
**False Positives:** None known when the announce was seen first, because the flowbit gates it. Without the announce rule loaded the flowbit is never set and the rule never fires, so it cannot stand alone and must not be deployed without the announce rule.
**Blind Spots:** It adds only liveness: the same session already alerted at the announce. Its value is distinguishing a session that stayed up from one that closed.
**Validation:** `suricata -T` PASS (8.0.7). Relay run capture: 11 alerts in 2 flows, which is the 11 keepalives on the wire. 0 elsewhere, including the synthetic negative set where a bare `PING` on another port did not fire it.
**Deployment:** Same sensor, with the announce rule.
**Evidence:** `PING` plus a newline (5 bytes) every 15 seconds while the session is idle.

```
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT INV-2026-067 Reverse Relay PING Keepalive After READY2 Announce (Idle Session Persists)"; flow:established,to_server; flowbits:isset,thl.inv067.relay; dsize:5; content:"PING|0a|"; startswith; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015-detections/; classtype:trojan-activity; sid:1000004; rev:1; metadata:author The_Hunters_Ledger, date 2026-10-09;)
```

#### Reverse Relay OK Reply After DIAL

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1090.001 (Internal Proxy)
**Confidence:** MODERATE
**False Positives:** None known, because it needs the DIAL rule to have set its flowbit in the same flow. It cannot stand alone.
**Blind Spots:** Corroboration only. The DIAL rule already alerts on the tasking. This reply shows the internal connection succeeded, which is the scoping question. I reworked it from the earlier form, which tried to match the reply as the whole to-server stream and fired 0 times because the stream already held the announce and a keepalive.
**Validation:** `suricata -T` PASS (8.0.7). Relay run capture: 1 of 1 `OK` reply. 0 elsewhere.
**Deployment:** Same sensor, with the DIAL rule.
**Evidence:** `OK` plus a newline (3 bytes) sent 1 ms after the onward handshake completed.

```
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT INV-2026-067 Reverse Relay OK Reply After DIAL (Onward Connection Succeeded)"; flow:established,to_server; flowbits:isset,thl.inv067.dial; dsize:3; content:"OK|0a|"; startswith; reference:url,the-hunters-ledger.com/hunting-detections/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015-detections/; classtype:trojan-activity; sid:1000006; rev:1; metadata:author The_Hunters_Ledger, date 2026-10-09;)
```

#### Reverse Relay FAIL Reply After DIAL

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1090.001 (Internal Proxy)
**Confidence:** MODERATE
**False Positives:** None known, gated the same way as the `OK` rule.
**Blind Spots:** Corroboration only. A `FAIL` shows the operator tasked a destination that did not answer, which is also useful scoping information for a defender.
**Validation:** `suricata -T` PASS (8.0.7). Relay run capture: 1 of 1 `FAIL` reply. 0 elsewhere.
**Deployment:** Same sensor, with the DIAL rule.
**Evidence:** `FAIL` plus a newline (5 bytes) sent after a `DIAL` to a closed port, with the relay reconnecting within 1 ms.

```
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT INV-2026-067 Reverse Relay FAIL Reply After DIAL (Onward Connection Failed)"; flow:established,to_server; flowbits:isset,thl.inv067.dial; dsize:5; content:"FAIL|0a|"; startswith; reference:url,the-hunters-ledger.com/hunting-detections/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015-detections/; classtype:trojan-activity; sid:1000007; rev:1; metadata:author The_Hunters_Ledger, date 2026-10-09;)
```

---

## Coverage Gaps

Each item says what I did not cover and what would let me write it.

- **The `READY` lane.** The operator's relay log labels two lanes, `READY` and `READY2`. I saw only the second on the wire. I did not write a rule asserting the first lane's bytes, because I never read that source. The generic printable-line hunting rule would flag it. A capture or source of the first lane would let me write an exact announce rule.
- **A real controller.** Every controller-side byte in my test is my stand-in's. Whether the operator's controller sends anything before `DIAL`, or ever lines longer than 200 bytes, is unknown. A capture from a victim sensor on the egress path would settle it.
- **The 37 non-relay flows.** The original capture held 37 further flows that would have served as a false-positive check. The capture used for replay is the filtered one (relay sessions and the onward connection only), and the full capture was not retained. I used 2,411 flows from seven unrelated captures instead. That corpus has no TCP port 53 traffic at all, so a real DNS-over-TCP false-positive rate is NOT CHECKED for the three port 53 rules.
- **Relay on other platforms.** I ran the relay source on Windows Java only. The application bytes should not depend on the operating system, and the operator ran it on Linux hosts, but I have not observed that. No host-side rule exists for a Java process launched on the relay source or a compiled class: the only host observation is a Windows `java.exe` command line ending in the source file name, which is a file name and not a behaviour, so I cut it. The network rules cover the same ground.
- **The planted page and the verbatim request text.** The JSP body and the exact script text of the WebLogic requests are held only in the original capture, and my notes describe the page as a command-execution shell that reads one request parameter and runs it through `/bin/sh -c` without reproducing it or the parameter name. A YARA rule would be built from my description, not the bytes, and a generic JSP command-execution rule would duplicate the signature-base web shell coverage. I also could not self-test a rule against the real file without returning to the original capture. The Sigma anchors are therefore the literals the read names (`_WL_internal`, `.jsp`, `grep -v`, `.log`) and the exact text could differ.
- **Network signature for the WebLogic request.** ET Open on my sensor carries two WS-AT deserialization rules (sids 2025837 and 2025838) that require a `<soapenv:` token and `java.lang.ProcessBuilder` in the body. My note calls the operator's body a bare SOAP 1.1 envelope and does not give its prefix, so whether those rules fire on it is NOT CHECKED. I wrote no rule for it.
- **Count probe and staging files.** The operator's probe that sleeps for as many seconds as there are logs mentioning its page (a latency side channel), the second page name it searches for, and the staging files it writes under `/tmp` are single operator-chosen values with no behaviour left once the name is removed. They belong in an IOC feed, not in a rule.
- **Zabbix API.** I wrote no rule for the creation or execution of global scripts through the API. The Zabbix audit log is where an owner would see script creation and execution (the place to look for it), but I hold no export of it, no field schema and no sample line, so any rule would be invented field names. NOT CHECKED. The object names (`z-` and `wv3_` item and script prefixes, `poc` items, three scripts named `diag-04` to `diag-06`) and the seven item identifiers are operator-chosen values and are offered to a Zabbix owner for the audit log, not as a rule. The one host-side rule above is script-only evidence about what the operator asked monitored hosts to run.
- **The operator-facing block page.** The fixed 231-byte "Request Rejected" page returned by a filter in front of one victim's portal is a response from a device we do not know, not an attacker artifact. A response-body rule would be a rule about someone else's WAF. Cut.
- **Atomics for the feed.** The relay controller address and port, the operator's callback ports and the collector address (all single literals) are carried in the companion IOC feed, not authored as rules here.
- **Windows and Sysmon coverage.** Nothing in this file targets a Windows host, because no Windows behaviour was observed outside the one run of the relay.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
