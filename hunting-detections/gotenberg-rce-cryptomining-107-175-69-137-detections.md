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
| Sigma | 1 | 1 | T1190 | 0 |
| Suricata | 1 | 0 | T1190 | 0 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient, so they are safe to alert on. *Hunting rules* are broader, intended for scoping and threat-hunting, so expect to review the hits.

This campaign exploits CVE-2026-42589, an unauthenticated RCE in Gotenberg's ExifTool metadata-write endpoint, to install a cryptomining payload at scale. Every detection in this file keys on one measured fact: the injected command travels inside the metadata field as JSON, so the injected newline reaches the network as the two ASCII bytes backslash and `n` (hex `5c 6e`), not as a raw `0x0a` newline byte. Gotenberg un-escapes it only server-side, after any packet sensor has seen the wire. A rule keyed on a raw newline parses cleanly and never fires; the rules below are written against the escaped wire form and are marked so the bytes are never "tidied".

The exploit anchor is invariant across every observed transport variant (direct command, different sleep durations, base64-transported payloads): the key always carries `\n-if\nsystem(` before the attacker's command, so no rule below keys on a command string, sleep value, boundary or User-Agent.

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

---

## Suricata Signatures

The signature below was accepted by the production rule-parsing engine (`suricata -T`, exit 0). The campaign pcap replay gate is NOT CHECKED: the capture lives on the isolated analysis host and is not registered in the replay manifest, so acceptance proves the rule loads, not that it fires on the case traffic.

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

---

## Coverage Gaps

**No YARA rule is shipped for the cryptomining payload, deliberately.** The miner is stock, unmodified XMRig, the commodity payload used by the large majority of Linux cryptojacking; it was observed in submissions from many unrelated sources. A YARA rule on the binary is a commodity indicator and attributes nothing: it would fire on the whole population of commodity miners rather than on this operator. The operator-specific pivot in this case is the Monero wallet address, which is an atomic indicator and belongs in the campaign IOC feed, not in a byte-pattern rule. No YARA artifact that is operator-specific was available in the evidence this file was authored from. A YARA rule becomes worthwhile only if an operator-built or operator-modified binary artifact surfaces: a custom dropper, a modified XMRig build carrying operator branding or a custom configuration blob, or a distinctive staged payload file. Until then the miner hash and wallet stay IOC-feed material.

**Exploit-side persistence is not covered by any rule here.** The mining payload's own host-side behavior (the `/tmp/polkitd/` ephemeral drop versus the persistent `/usr/bin/polkitd.d/` directory plus a `systemd-polkitd` root unit with `Restart=always`) is documented in the investigation, but victim-endpoint telemetry (process creation, file events, systemd unit writes) was not part of the evidence this detection file was authored from, so no Sigma endpoint rules could be grounded in observed log events rather than in inference. Endpoint-side coverage becomes authorable once victim host telemetry of the actual miner deployment is captured and characterized.

**The pcap replay gate is NOT CHECKED.** The production engine accepted the signature (`suricata -T`, exit 0), which proves the rule loads and parses, not that it fires on the case traffic. The campaign capture lives on the isolated analysis host by instruction and is not registered in the replay manifest, so the does-it-fire check has not run.

**The retry-ladder command variant was not byte-confirmed.** Every script that builds the injected metadata key produces the identical `\n-if\nsystem(` prefix regardless of what sits inside the command, and the anchor does not parse the command content, so the prefix logic strongly implies the rules match that variant too. The wire bytes for that exact variant were not captured.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.
Free to use, including commercially, with attribution to The Hunters Ledger.

