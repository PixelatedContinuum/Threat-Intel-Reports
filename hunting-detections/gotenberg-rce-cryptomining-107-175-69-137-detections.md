---
title: "Detection Rules — Gotenberg RCE Mass Exploitation and Cryptomining"
date: '2026-09-16'
layout: post
permalink: /hunting-detections/gotenberg-rce-cryptomining-107-175-69-137-detections/
hide: true
unlisted: true
---

**Campaign:** Gotenberg-RCE-107.175.69.137
**Date:** 2026-09-16
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/gotenberg-rce-cryptomining-107-175-69-137/

---

## Detection Coverage Summary

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 0 | 0 | none (see Coverage Gaps) | 0 |
| Sigma | 4 | 3 | T1190, T1059.004, T1036.005, T1543.002, T1140 | 0 |
| Suricata | 1 | 3 | T1190, T1071.001, T1041 | 0 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient, so they are safe to alert on. *Hunting rules* are broader, intended for scoping and threat-hunting, so expect to review the hits.

This campaign exploits CVE-2026-42589, an unauthenticated RCE in Gotenberg's ExifTool metadata-write endpoint, to install a cryptomining payload at scale. Every detection in this file keys on one measured fact: the injected command travels inside the metadata field as JSON, so the injected newline reaches the network as the two ASCII bytes backslash and `n` (hex `5c 6e`), not as a raw `0x0a` newline byte. Gotenberg un-escapes it only server-side, after any packet sensor has seen the wire. A rule keyed on a raw newline parses cleanly and never fires; the rules below are written against the escaped wire form and are marked so the bytes are never "tidied".

The exploit anchor is invariant across every observed transport variant (direct command, different sleep durations, base64-transported payloads): the key always carries `\n-if\nsystem(` before the attacker's command, so no rule below keys on a command string, sleep value, boundary or User-Agent.

The file covers the campaign at both ends. The network rules key on the exploit's wire-escaped anchor and on the operator's out-of-band callback channel. The host-side Sigma rules cover what the payload does on a victim after RCE confirmation: the rival-miner kill sweep, the base64-staged drop, the XMRig masquerade as polkitd, and the persistent systemd install that a reboot does not clear. Every host-side rule is authored from the operator's own captured tooling and shipped artifacts (the deploy script, the systemd unit inside the miner package, the on-target paths in deploy output), which is standard practice for this corpus: the behaviour is observed in the operator's tooling, and no rule below needs victim endpoint telemetry that this investigation never collected.

---

## Sigma Rules

### Detection Rules

#### Gotenberg ExifTool Metadata Key CVE-2026-42589 Injection Attempt

**Tier:** Detection
**Robustness:** 3
**Upstream Coverage:** not_covered (the SigmaHQ webserver and proxy rule classes define no request-body field at all, so no upstream rule's condition can evaluate true on body content; the fieldless-keyword rule class was compared against the upstream corpus, 86 same-class neighbours, 0 shared literal atoms)
**ATT&CK Coverage:** T1190 (Exploit Public-Facing Application)
**Confidence:** HIGH
**False Positives:** Authorized security testing or red-team exercises sending the same proof-of-concept payload against a Gotenberg instance; otherwise unlikely, no legitimate metadata-write payload shape tested against the live anchor matched
**Blind Spots:** Requires telemetry that captures the raw request body; Gotenberg's own application log does not record the metadata payload on a request that parses as valid JSON, so this rule cannot run on that log. Misses any future exploit variant whose key no longer carries the `-if` conditional plus `system(` shape.
**Validation:** Replay a captured exploit request against the rule and confirm the anchor bytes match the wire form `5c 6e 2d 69 66 5c 6e ...`; a legitimate metadata write (single-key, multi-key, newline-in-value) must NOT fire.
**Deployment:** Reverse proxy, WAF, or network sensor in front of Gotenberg, anywhere the raw request body is captured and searchable. The single-quoted YAML value `'\n-if\nsystem('` below is a literal backslash-n sequence and is correct as written: it is the JSON-escaped wire form, not a newline escape.

```yaml
title: Gotenberg ExifTool Metadata Key CVE-2026-42589 Injection Attempt
id: 5c6643c6-b8b6-415c-b5b1-e14ab21125f9
status: experimental
description: >-
    Detects an HTTP POST to a Gotenberg ExifTool metadata-write endpoint whose metadata JSON
    key carries the JSON-escaped newline sequence \n-if\nsystem( , the wire-confirmed
    signature of CVE-2026-42589 ExifTool argv-splitting RCE. Requires a telemetry source that
    captures the raw HTTP request body (a reverse proxy, WAF, or network sensor forwarding
    body content); Gotenberg's own application log does not record the metadata payload on a
    request that parses as valid JSON, so this rule cannot run on that log.
references:
    - https://nvd.nist.gov/vuln/detail/CVE-2026-42589
    - https://the-hunters-ledger.com/hunting-detections/gotenberg-rce-cryptomining-107-175-69-137-detections/
author: The Hunters Ledger
date: 2026-09-16
tags:
    - attack.initial-access
    - attack.t1190
    - stp.4
logsource:
    category: webserver
    definition: >-
        Assumes a reverse proxy, WAF, or gateway in front of Gotenberg that logs the raw
        request body, or a network sensor that forwards body content into a searchable field.
        The payload anchor is a fieldless keyword selection that matches payload text in the
        log message; the Sigma specification defines no native field for raw request-body
        content in any supported logsource category, so the endpoint is identified by the
        proxy/webserver fields and the payload by the free-text match.
detection:
    selection_method:
        cs-method: 'POST'
    selection_uri:
        cs-uri-stem|contains: '/forms/pdfengines/metadata/write'
    injection_anchor: '\n-if\nsystem('
    condition: selection_method and selection_uri and injection_anchor
falsepositives:
    - Authorized security testing or red-team exercises sending the same proof-of-concept payload against a Gotenberg instance
    - Unlikely otherwise, no legitimate metadata-write payload shape tested matched this anchor
level: high
```

#### ExifTool Invoked With Condition Option Executing Shell Commands

**Tier:** Detection
**Robustness:** 3
**Upstream Coverage:** not_covered (no upstream Sigma rule keys on ExifTool process telemetry at all: a search of the local SigmaHQ clone for exiftool-anchored rules in every rule tree returned zero files, so no upstream condition can evaluate true on this activity)
**ATT&CK Coverage:** T1190 (Exploit Public-Facing Application), T1059.004 (Unix Shell)
**Confidence:** HIGH
**False Positives:** Bespoke tooling whose legitimate -if condition evaluates Perl code that calls system(), which has no known legitimate purpose but cannot be fully excluded; authorized security testing replaying the payload
**Blind Spots:** Any future variant that reaches code execution without calling system() directly (a backtick, exec(, qx(, or open-with-pipe Perl vector) defeats the `system(` term while remaining the same vulnerability; the -if argv split is the real chokepoint. Also blind wherever the host has no command-line process telemetry.
**Validation:** On a test Gotenberg host, fire the injected metadata key and confirm an exiftool process event whose command line carries both `-if` and `system(`; a legitimate metadata write must NOT produce a matching exiftool command line.
**Deployment:** Host telemetry on any server running Gotenberg or another ExifTool-backed service: auditd execve rules, Sysmon for Linux, or an EDR agent.

```yaml
title: ExifTool Invoked With Condition Option Executing Shell Commands
id: 37d092d3-cc96-4864-aef2-0679d3be9088
status: experimental
description: >-
    Detects ExifTool being invoked with its -if condition option whose argument calls the
    Perl system() function, the argv-splitting shape of CVE-2026-42589 metadata-key injection
    as it appears in process telemetry on the victim host once Gotenberg expands the metadata
    JSON. No legitimate ExifTool condition needs to execute shell commands, and any command
    the injected condition runs (timing probes, out-of-band callbacks, staged scripts) matches.
references:
    - https://nvd.nist.gov/vuln/detail/CVE-2026-42589
    - https://the-hunters-ledger.com/hunting-detections/gotenberg-rce-cryptomining-107-175-69-137-detections/
author: The Hunters Ledger
date: 2026-09-16
tags:
    - attack.initial-access
    - attack.execution
    - attack.t1190
    - attack.t1059.004
    - stp.4
logsource:
    category: process_creation
    product: linux
    definition: >-
        Requires process-creation telemetry that captures full command lines on the victim
        host: auditd execve rules, Sysmon for Linux, or an EDR agent. Without command-line
        capture the -if and system( arguments are not visible and this rule cannot fire.
detection:
    selection_img:
        Image|endswith: 'exiftool'
    selection_cond:
        CommandLine|contains: '-if'
    selection_exec:
        CommandLine|contains: 'system('
    condition: selection_img and selection_cond and selection_exec
falsepositives:
    - >-
        Bespoke tooling whose legitimate -if condition evaluates Perl code that calls
        system(), which has no known legitimate purpose but cannot be fully excluded
    - Authorized security testing or red-team exercises replaying the CVE-2026-42589 payload
level: high
```

#### Polkitd Daemon Executed From a Non-Standard Directory

**Tier:** Detection
**Robustness:** 3
**Upstream Coverage:** partially_covered (the upstream rule "Potentially Suspicious Execution From Tmp Folder", `Image|startswith: '/tmp/'`, evaluates true on the /tmp drop variant but not on the /usr/bin/polkitd.d/ persistent variant and encodes none of the name-versus-location logic; this rule is the location-mismatch abstraction of the same behavior)
**ATT&CK Coverage:** T1036.005 (Match Legitimate Resource Name or Location)
**Confidence:** HIGH
**False Positives:** Custom Polkit builds deployed at non-standard prefixes (Nix store paths, container image layer paths); authorized security tooling or tests that stage a binary named polkitd
**Blind Spots:** Misses the same operator's second masquerade name, systemd-logind, and any future build that picks a different daemon name; the anchor is the polkitd name mismatched against its legitimate location, not the miner itself. The filter list covers the two most common legitimate Polkit locations but a distribution that installs polkitd elsewhere produces a benign hit.
**Validation:** On a test host, launch a copy of any binary named polkitd from /tmp and confirm a hit; the distribution's own polkitd at /usr/lib/polkit-1/ must NOT fire.
**Deployment:** Host telemetry on any Linux server (auditd execve rules, Sysmon for Linux, or an EDR agent). Alerting-grade: a process named polkitd outside the Polkit package path is malicious or broken.

```yaml
title: Polkitd Daemon Executed From a Non-Standard Directory
id: c0678478-efcc-4d57-b733-6a4971058ff1
status: experimental
description: >-
    Detects a process running from an executable named polkitd outside the legitimate Polkit
    install locations. In this campaign the XMRig miner masquerades as polkitd from both drop
    locations (/tmp/polkitd/ ephemeral and /usr/bin/polkitd.d/ persistent), and the deploy
    script kills any existing process named polkitd before installing its own, so this anchor
    also surfaces rival miners reusing the same mask name. Host-side detection of the
    masquerade is load-bearing because the persistent systemd variant survives a reboot.
references:
    - https://nvd.nist.gov/vuln/detail/CVE-2026-42589
    - https://the-hunters-ledger.com/hunting-detections/gotenberg-rce-cryptomining-107-175-69-137-detections/
author: The Hunters Ledger
date: 2026-09-16
tags:
    - attack.stealth
    - attack.t1036.005
    - stp.4
logsource:
    category: process_creation
    product: linux
    definition: >-
        Requires process-creation telemetry that captures the full executable path on the
        victim host: auditd execve rules, Sysmon for Linux, or an EDR agent.
detection:
    selection_daemon:
        Image|endswith: '/polkitd'
    filter_legit_paths:
        Image|startswith:
            - '/usr/lib/polkit-1/'
            - '/usr/libexec/polkit-1/'
    condition: selection_daemon and not filter_legit_paths
falsepositives:
    - Custom Polkit builds deployed at non-standard prefixes (Nix store, container image layer paths)
    - Authorized security tooling or tests that stage a binary named polkitd
level: high
```

#### Shell Spawned by Systemd Executes Binary After Path Export and Directory Change

**Tier:** Detection
**Robustness:** 3
**Upstream Coverage:** not_covered (no upstream Linux rule keys on a systemd-spawned shell wrapper combining PATH export, directory change and exec; the closest upstream persistence rules are unit-file creation and auditd service-creation events, whose conditions evaluate different fields)
**ATT&CK Coverage:** T1543.002 (Systemd Service)
**ATT&CK Note:** The rule keys on the runtime launch shape of a systemd unit rather than on the unit-file write itself, because no unit-file write for the persistent variant was observed in this corpus; the unit text is known only from the shipped miner package. The ExecStart wrapper it detects (`export PATH=...;cd ...;exec ...` in one shell invocation) is that unit's own launch command.
**Confidence:** HIGH
**False Positives:** Legitimate service units whose ExecStart wraps an export PATH plus cd plus exec sequence in one shell invocation, uncommon but documented practice for relocatable services
**Blind Spots:** A persistent unit written in a different ExecStart style (separate environment directives, a wrapper script file, or cd via an environment file) does not match this command-line shape. The unit inside this campaign's miner package also ships as systemd-vconsole-setup.service, a name some distributions legitimately use, so no rule in this file keys on the unit name.
**Validation:** Install a test unit with ExecStart=/bin/sh -c "export PATH='/opt/t':$PATH;cd '/opt/t';exec './bin'" and confirm the process event fires; a unit launching a script by absolute path with no export/cd/exec wrapper must NOT fire.
**Deployment:** Host telemetry on Linux servers where systemd service launches are logged with parentage and command line (auditd with execve and parent tracking, Sysmon for Linux, or an EDR agent). This is the rule that catches the persistence a reboot does not clear.

```yaml
title: Shell Spawned by Systemd Executes Binary After Path Export and Directory Change
id: 7ed14be2-a79d-45e3-acae-7617284f746f
status: experimental
description: >-
    Detects the persistent-install launch shape observed in this campaign's shipped
    systemd-polkitd.service unit: a shell command execution whose command line exports a
    directory onto PATH, changes into it, and execs a binary, all in one invocation. This is
    the wrapper the miner's persistent root unit uses (Restart=always, RestartSec=10s,
    User=root), and it is the shape a reboot does not clear. The anchor keys on the launch
    pattern, not on the masqueraded binary name, so a renamed miner running the same wrapper
    still matches.
references:
    - https://nvd.nist.gov/vuln/detail/CVE-2026-42589
    - https://the-hunters-ledger.com/hunting-detections/gotenberg-rce-cryptomining-107-175-69-137-detections/
author: The Hunters Ledger
date: 2026-09-16
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1543.002
    - stp.4
logsource:
    category: process_creation
    product: linux
    definition: >-
        Requires process-creation telemetry that captures both the parent process and the
        full command line for processes spawned by systemd, for example auditd execve rules
        with parent tracking, Sysmon for Linux, or an EDR agent.
detection:
    selection_parent:
        ParentImage|endswith:
            - 'systemd'
            - '/init'
    selection_shell:
        Image|endswith:
            - '/sh'
            - '/bash'
    selection_wrapper:
        CommandLine|contains|all:
            - 'export PATH='
            - ';cd '
            - ';exec '
    condition: selection_parent and selection_shell and selection_wrapper
falsepositives:
    - >-
        Legitimate service units whose ExecStart wraps an export PATH plus cd plus exec
        sequence in one shell invocation, uncommon but documented practice for relocatable
        services
level: high
```

### Hunting Rules

#### Gotenberg Metadata-Write Endpoint Anomalous Latency (Possible CVE-2026-42589)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1190 (Exploit Public-Facing Application)
**Confidence:** MODERATE
**False Positives:** Genuinely slow ExifTool metadata writes under load, on large or malformed documents, or during resource contention; the measured clean-request baseline sat at roughly 250 to 650 milliseconds, and any real deployment must establish its own distribution before treating this as signal
**Blind Spots:** Sees only sleep-based exploitation that pauses inside the request handler; a non-sleep command in the injected payload produces no latency signal. The latency unit is an assumption carried in the logsource definition and must be verified against a real deployment before the 2-second threshold is trusted.
**Deployment:** Gotenberg's own structured access log, only where body-capturing telemetry is unavailable. Not for alerting; triage hits by correlating the timestamped request with document size and concurrent load.

```yaml
title: Gotenberg Metadata-Write Endpoint Anomalous Latency (Possible CVE-2026-42589)
id: 38daaffe-5d58-4edb-9549-4aec80f168ac
status: experimental
description: >-
    Gotenberg's own structured access log never records the metadata payload on a request
    that parses as valid JSON, so a sleep-based CVE-2026-42589 RCE attempt is visible in this
    log only as a latency spike on an endpoint that is otherwise sub-second (measured clean
    baseline roughly 250 to 650 milliseconds). False-positive risk is high: a genuinely slow
    ExifTool write (large or malformed document, resource contention) matches identically.
    Use only where the Detection-tier rule's body visibility is unavailable. Not for alerting.
references:
    - https://nvd.nist.gov/vuln/detail/CVE-2026-42589
author: The Hunters Ledger
date: 2026-09-16
tags:
    - attack.initial-access
    - attack.t1190
    - stp.3
logsource:
    category: application
    product: gotenberg
    definition: >-
        Keys on Gotenberg's own structured HTTP access log fields (uri, method, status,
        latency). The latency field is assumed to carry Go's time.Duration serialized in
        nanoseconds, so the 2000000000 threshold is 2 seconds; verify the unit in your own
        deployment before relying on the threshold.
detection:
    selection:
        uri: '/forms/pdfengines/metadata/write'
        method: POST
        status: 200
        latency|gte: 2000000000
    condition: selection
falsepositives:
    - Genuinely slow ExifTool metadata writes under load or on large or malformed documents
level: low
```

#### Pkill Kill Sweep Against Rival Cryptominer Process Names

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1059.004 (Unix Shell)
**Confidence:** HIGH that the behavior is real and miner-related, LOW that any single hit is this operator
**False Positives:** Administrators cleaning up a confirmed miner infection by hand; another cryptojacking operator's own displacement sweep on the same host, which is the behavior this rule detects and is expected to fire on
**Blind Spots:** The observed kill list also includes kernel-thread-shaped names (kworker/u4, kworker/u16) and the operator's own mask name (polkitd), all deliberately excluded from this selection because pkill sweeps touching those names are far noisier; a sweep naming only those is missed. Rename-fragile by construction.
**Validation:** Run pkill -9 -f kdevtmpfsi on a test host and confirm the hit; a pkill of an ordinary application name must NOT fire.
**Deployment:** Host telemetry for scoping and triage. Expect hits from defenders and from rival operators as often as from this campaign; correlate with miner presence before judging.

```yaml
title: Pkill Kill Sweep Against Rival Cryptominer Process Names
id: 68d7470d-33e0-4bed-9078-dc6c31d96138
status: experimental
description: >-
    Detects a pkill -9 -f kill sweep aimed at process names used by commodity Linux
    cryptominers before a competing payload is installed. This campaign's deploy script runs
    such a sweep (against xmrig, systemd-devd, kdevtmpfsi, kswapd0, khovr and others) as its
    first act on every target, and rival-miner kills were confirmed in captured deploy
    output. The sweep is displacement behavior shared by rival cryptojacking operators, so
    the anchor indicates miner-versus-miner competition on a host rather than this operator
    specifically. Not for alerting; triage hits against known miner presence.
references:
    - https://the-hunters-ledger.com/hunting-detections/gotenberg-rce-cryptomining-107-175-69-137-detections/
author: The Hunters Ledger
date: 2026-09-16
tags:
    - attack.execution
    - attack.t1059.004
    - stp.2
logsource:
    category: process_creation
    product: linux
    definition: >-
        Requires process-creation telemetry that captures full command lines on the victim
        host: auditd execve rules, Sysmon for Linux, or an EDR agent.
detection:
    selection_pkill:
        CommandLine|contains|all:
            - 'pkill'
            - '-9'
            - '-f'
    selection_miner_name:
        CommandLine|contains:
            - 'kdevtmpfsi'
            - 'kswapd0'
            - 'khovr'
            - 'systemd-devd'
            - 'xmrig'
    condition: selection_pkill and selection_miner_name
falsepositives:
    - Administrators cleaning up a confirmed miner infection by hand
    - >-
        Another cryptojacking operator's own displacement sweep on the same host, which is
        the behavior this rule detects and is expected to fire on
level: medium
```

#### Base64 Decoded Script Written to Tmp and Executed by Bash

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1059.004 (Unix Shell), T1140 (Deobfuscate/Decode Files or Information)
**Confidence:** HIGH that the shape matches the campaign's staging step; the anchor itself is generic staging behavior
**False Positives:** Provisioning, cloud-init or installer scripts that decode payloads to tmp and run them; authorized security tooling staging encoded scripts
**Blind Spots:** Only catches the decode-and-execute pairing inside one command line; a dropper that decodes in one invocation and executes in a later one produces two innocuous-looking events. The `>/tmp/` and `bash ` literals break on variants using other staging directories or interpreters.
**Validation:** Run echo YmFzaCAtYyAiaWQK | base64 -d>/tmp/t.sh; bash /tmp/t.sh on a test host and confirm a hit; a decode of a data file with no execution of it must NOT fire.
**Deployment:** Host telemetry (auditd execve rules, Sysmon for Linux, or an EDR agent). Not for alerting; correlate hits with deployment or provisioning context.

```yaml
title: Base64 Decoded Script Written to Tmp and Executed by Bash
id: a3dcd1d3-0c9f-4cd2-a6e7-bed5dd6bd3c1
status: experimental
description: >-
    Detects a single shell command line that decodes a base64 payload into a script file
    under /tmp and immediately executes it with bash, the staging shape this campaign's
    deploy driver uses to carry its miner install script through shell quoting constraints
    (echo of encoded script piped to base64 -d into /tmp/d.sh, then bash of that file).
    Cloud provisioning and installer tooling legitimately uses decode-then-execute patterns,
    so this is a hunting anchor and triage hits against deployment context.
references:
    - https://the-hunters-ledger.com/hunting-detections/gotenberg-rce-cryptomining-107-175-69-137-detections/
author: The Hunters Ledger
date: 2026-09-16
tags:
    - attack.execution
    - attack.stealth
    - attack.t1059.004
    - attack.t1140
    - stp.2
logsource:
    category: process_creation
    product: linux
    definition: >-
        Requires process-creation telemetry that captures full command lines on the victim
        host: auditd execve rules, Sysmon for Linux, or an EDR agent.
detection:
    selection_decode:
        CommandLine|contains|all:
            - 'base64 -d'
            - '>/tmp/'
    selection_exec:
        CommandLine|contains|all:
            - 'bash '
            - '/tmp/'
    condition: selection_decode and selection_exec
falsepositives:
    - Provisioning, cloud-init or installer scripts that decode payloads to tmp and run them
    - Authorized security tooling staging encoded scripts
level: medium
```

---

## Suricata Signatures

The Detection-tier signature was accepted by the production rule-parsing engine (`suricata -T`, exit 0). The three Hunting signatures were validated the same way and were also accepted (exit 0, `suricata -T` on the sensor via the project's validation transport). The campaign pcap replay gate is NOT CHECKED: the capture lives on the isolated analysis host and is not registered in the replay manifest, so acceptance proves the rules load, not that they fire on the case traffic.

### Detection Rules

#### Gotenberg ExifTool Metadata Key Injection over HTTP (CVE-2026-42589)

**Tier:** Detection
**Robustness:** 3
**Upstream Coverage:** not_covered (no Suricata upstream submission target exists in this project's workflow; the anchor is this case's own measured wire form)
**ATT&CK Coverage:** T1190 (Exploit Public-Facing Application)
**Confidence:** HIGH
**False Positives:** Authorized security testing or red-team exercises sending the same proof-of-concept payload; otherwise unlikely, the anchor fires only on a POST to the metadata-write endpoint whose body carries the escaped injection shape
**Blind Spots:** Misses exploit variants that no longer carry the `-if` conditional plus `system(` shape, and any path where the request body is not reassembled (fragmented bodies, chunked encodings, or a sensor without request-body inspection).
**Validation:** Replay the campaign pcap and confirm one alert per injected request; the six tested legitimate metadata-write shapes must NOT fire.
**Deployment:** Packet sensor or IDS tap anywhere it can see the traffic between the operator and the Gotenberg instance. The comment above the rule is load-bearing: the hex content bytes are the intentional wire-escaped form and must not be corrected.

```suricata
# LOAD-BEARING: the bytes |5c 6e| in the content match below appear twice ON PURPOSE. They are
# the JSON-escaped form of the injected newlines. The metadata field travels as JSON, so the
# newline leaves the socket as the two ASCII bytes backslash (0x5c) and n (0x6e). Gotenberg
# un-escapes it only server-side, after any sensor has seen the packet. Do NOT "correct" these
# bytes to a raw 0x0a newline or to a PCRE newline escape: a rule keyed on a raw newline parses
# cleanly and NEVER fires on real traffic (confirmed against captured traffic).
alert http any any -> any any (msg:"THL DETECT Gotenberg-RCE ExifTool Metadata Key Injection Attempt (CVE-2026-42589 Exploitation Indicator)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/forms/pdfengines/metadata/write"; http.request_body; content:"|5c 6e 2d 69 66 5c 6e 73 79 73 74 65 6d 28|"; fast_pattern; reference:cve,2026-42589; classtype:attempted-admin; sid:1000001; rev:1; metadata:author The_Hunters_Ledger, date 2026-09-16, reference https://the-hunters-ledger.com/hunting-detections/gotenberg-rce-cryptomining-107-175-69-137-detections/;)
```

### Hunting Rules

The three signatures below hunt the campaign's out-of-band callback channel rather than the exploit itself. Every one keys on a literal the operator chose, so each is Robustness 1: the tool's own path-prefix scheme and verdict tokens are renameable constants, which is exactly why they are Hunting tier and not Detection. Their value is scoping and confirmation: a hit on any of them identifies a host running this toolkit's callback traffic without needing to know the operator's current listener address. The operator's host address itself is an atomic indicator and lives in the campaign IOC feed, deliberately not as a signature.

#### Out-of-Band Tagged Callback URI Shape

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Application Layer Protocol: Web Protocols)
**Confidence:** MODERATE
**False Positives:** Any web application whose URI paths carry the underscore-delimited tag-host-uid shape (a segment of single-letter-prefixed digits, then a token, then a trailing integer), which is uncommon but not impossible in ordinary web apps
**Blind Spots:** The prefix set (T, W, C, N, PPROBE plus digit index) is the operator's own scheme and rotates cheaply; a future build with a new prefix or a reordered path is missed. The deploy-stage D-callback carries no underscore, so it is covered by the verdict-body signature below, not this one.
**Validation:** Against a test listener, issue GET /T123_testhost_0 and confirm the alert; an ordinary GET with an underscored path lacking the numeric-prefixed shape must NOT fire.
**Deployment:** Packet sensor or IDS tap watching egress from managed hosts. Not for blocking; correlate hits with the destination before judging.

```suricata
alert http $HOME_NET any -> any any (msg:"THL HUNT Gotenberg-RCE Tagged Out-of-Band Callback URI Shape (C2 Beacon Indicator)"; flow:established,to_server; http.uri; content:"_"; pcre:"/^\/(?:[TWCN]\d+|PPROBE\d+)_[^\/\s]+_\d+\/?$/"; threshold:type limit,track by_src,count 1,seconds 3600; classtype:command-and-control; sid:1000002; rev:1; metadata:author The_Hunters_Ledger, date 2026-09-16, reference https://the-hunters-ledger.com/hunting-detections/gotenberg-rce-cryptomining-107-175-69-137-detections/;)
```

#### Out-of-Band Deploy Verdict Body (MINER_OK)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Application Layer Protocol: Web Protocols)
**Confidence:** HIGH that a hit is this toolkit's deploy channel; the literal is the operator's own verdict token, written by their deploy script
**False Positives:** Some other application using the literal string MINER_OK in a request body, none known
**Blind Spots:** A future build that renames the verdict tokens (or posts verdicts in a second request with no body) is missed; the token is an attacker-chosen constant.
**Validation:** POST a body containing MINER_OK from a test host and confirm the alert; a POST body without that literal must NOT fire.
**Deployment:** Packet sensor watching egress. Not for blocking; the body content is diagnostic of the install verdict channel.

```suricata
alert http $HOME_NET any -> any any (msg:"THL HUNT Gotenberg-RCE Miner Deploy Verdict Body MINER_OK (OOB Deploy-Callback Indicator)"; flow:established,to_server; http.request_body; content:"MINER_OK"; threshold:type limit,track by_src,count 1,seconds 3600; classtype:command-and-control; sid:1000003; rev:1; metadata:author The_Hunters_Ledger, date 2026-09-16, reference https://the-hunters-ledger.com/hunting-detections/gotenberg-rce-cryptomining-107-175-69-137-detections/;)
```

#### Out-of-Band Command Output Body Markers (START/END Brackets)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1041 (Exfiltration Over C2 Channel)
**ATT&CK Note:** The behavior is command output from an injected command being posted back to the operator's listener through the same HTTP channel that delivered the commands, so the exfiltration technique and its C2 transport are both this channel's description.
**Confidence:** MODERATE
**False Positives:** Any application that posts a body containing both ===START=== and ===END=== literal markers, none known in ordinary traffic
**Blind Spots:** The marker strings are attacker-chosen constants; a build that rewords the brackets is missed. Bodies that carry the START marker but are truncated before END (the campaign's own listener had non-atomic write corruption) do not match, because the rule requires both literals.
**Validation:** POST a body bracketed by ===START=== and ===END=== from a test host and confirm the alert; a body carrying only one of the two markers must NOT fire.
**Deployment:** Packet sensor watching egress. Not for blocking.

```suricata
alert http $HOME_NET any -> any any (msg:"THL HUNT Gotenberg-RCE Command Output Body Markers START END (OOB Command-Output Indicator)"; flow:established,to_server; http.request_body; content:"===START==="; content:"===END==="; threshold:type limit,track by_src,count 1,seconds 3600; classtype:command-and-control; sid:1000004; rev:1; metadata:author The_Hunters_Ledger, date 2026-09-16, reference https://the-hunters-ledger.com/hunting-detections/gotenberg-rce-cryptomining-107-175-69-137-detections/;)
```

---

## Coverage Gaps

**No YARA rule is shipped for the cryptomining payload, deliberately.** The miner is stock, unmodified XMRig, the commodity payload used by the large majority of Linux cryptojacking; it was observed in submissions from many unrelated sources. A YARA rule on the binary is a commodity indicator and attributes nothing: it would fire on the whole population of commodity miners rather than on this operator. The operator-specific pivot in this case is the Monero wallet address, which is an atomic indicator and belongs in the campaign IOC feed, not in a byte-pattern rule. No YARA artifact that is operator-specific was available in the evidence this file was authored from. A YARA rule becomes worthwhile only if an operator-built or operator-modified binary artifact surfaces: a custom dropper, a modified XMRig build carrying operator branding or a custom configuration blob, or a distinctive staged payload file. Until then the miner hash and wallet stay IOC-feed material.

**Cut, deliberately: the writability probe.** Before spending a payload the operator's recon stage touches `/tmp/.wt` to test writability, and a rule for that was considered and cut. Touching a dotfile in /tmp is ubiquitous benign behaviour (installers, editors, provisioning), so no anchor survives: a rule keyed on the touch alone is pure noise, and keying it to the operator's own marker name would be Robustness 0 or 1 with nothing behavioral left once the literal is removed. The probe is recorded as tradecraft in the report instead of as a rule.

**Cut, deliberately: the payload delivery pair.** The download of the miner package (`curl` to the operator's host on port 19999 for `upload_miner.tgz`) and the corresponding GET were considered as a Suricata signature and cut: the only anchors are the operator's hard-coded IP and port (Robustness 0) and an attacker-chosen filename (Robustness 1), and removing either literal leaves a rule that detects nothing. These are atomic indicators and they are already in the campaign IOC feed, together with the drop paths (`/tmp/polkitd/`, `/usr/bin/polkitd.d/`), the shipped unit names, the watchdog script path and the out-of-band callback path scheme. The IOC feed, not a rule, is the right home for all of them.

**The watchdog behaviour is not covered by any rule.** One victim host carried a watchdog script at `/home/gotenberg/.local/share/watchdog.sh` that restarts the miner, and the deploy script's comment claims a watchdog the captured copy does not contain. A file_event or process rule was considered and not written: the path is a victim-side artifact seen on exactly one host, the script's own behaviour was never captured, and keying on the path would be Robustness 0 anchor on one observed instance. Nothing in the corpus grounds a behavioral rule for it.

**The pcap replay gate is NOT CHECKED.** The production engine accepted all four Suricata signatures (`suricata -T`, exit 0), which proves the rules load and parse, not that they fire on the case traffic. The campaign capture lives on the isolated analysis host by instruction and is not registered in the replay manifest, so the does-it-fire check has not run for any of them.

**The retry-ladder command variant was not byte-confirmed.** Every script that builds the injected metadata key produces the identical `\n-if\nsystem(` prefix regardless of what sits inside the command, and the anchor does not parse the command content, so the prefix logic strongly implies the rules match that variant too. The wire bytes for that exact variant were not captured.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.
Free to use, including commercially, with attribution to The Hunters Ledger.

