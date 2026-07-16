---
title: "Detection Rules — enc_c2.exe (Arsenal-237 Ransomware)"
date: '2026-01-27'
layout: post
permalink: /hunting-detections/arsenal-237-enc_c2-exe-detections/
hide: true
redirect_from: /hunting-detections/arsenal-237-enc_c2-exe/
thumbnail: /assets/images/cards/arsenal-237-new-files.png
---

**Campaign:** Arsenal-237-EncC2-Ransomware-TorC2
**Date:** 2026-01-27
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**IOC Feed:** https://the-hunters-ledger.com/ioc-feeds/arsenal-237-enc_c2-exe.json

---

## Detection Coverage Summary

enc_c2.exe is a 64-bit Rust-compiled Windows ransomware executable belonging to the Arsenal-237 toolkit. It encrypts victim files with ChaCha20 and appends a `.locked` extension, drops a README.txt ransom note, and exfiltrates the victim ID, hostname, OS details, and the ChaCha20 decryption key to a Tor hidden-service C2 endpoint via an HTTP POST beacon carrying a JSON payload. The sample includes a TEB-based anti-debugging stall loop and, per static analysis, uses a single-run execution model with no persistence mechanism. The `TEST_BUILD_001` builder identifier embedded in the sample indicates a beta/test build of the toolkit rather than a production affiliate release.

Coverage below is retiered from the original draft against the project's Detection/Hunting/Cut split: every rule was re-scored for durability (does it survive infrastructure rotation and rebuild?), precision (documented false-positive profile), and level discipline. The most durable detection surface is the C2 beacon's URI/method/content-type combination, which survives onion-address rotation; process- and file-name-based rules are capped at Hunting because they depend on literals (the executable name, the `.locked` extension, the ransom-note filename) the operator can trivially change in a rebuild. The confirmed file hashes and C2 onion address are carried in the IOC feed rather than as standalone rules.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 1 | 3 | T1486, T1071.001, T1090.003, T1622 | 1 |
| Sigma | 1 | 4 | T1204.002, T1486, T1071.001, T1090.003, T1547.001, T1622 | 0 |
| Suricata | 1 | 0 | T1071.001, T1090.003 | 0 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Atomics routed to the IOC feed:** the confirmed file hashes (SHA-256, SHA-1, MD5) and the Tor C2 onion address (`rustydl5ak6p6ajqnja6qzkxvp5huhe4olpdsq5oy75ea4o34aalpkqd.onion`) were already present in [`arsenal-237-enc_c2-exe.json`](/ioc-feeds/arsenal-237-enc_c2-exe.json) before this retiering pass. The standalone file-hash YARA rule and the redundant onion-address branches removed from the Sigma and Suricata C2-beacon rules added no detection value beyond those feed entries — see Coverage Gaps for the full reasoning on every retired or rewritten rule.

---

## YARA Rules

```
/*
   Yara Rule Set
   Identifier: Arsenal-237-EncC2-Ransomware-TorC2
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/
```

### Detection Rules

#### RaaS Builder ID & C2 Beacon Schema Combination

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols — C2 JSON schema), T1486 (Data Encrypted for Impact — `encryption_key` field)
**Confidence:** HIGH
**Rationale:** The rule ORs two branches. The second — `builder_id` + `encryption_key` + `victim_id` + `machine_info` co-occurring — is the malware's specific C2/builder-tracking JSON field-name schema; this four-way combination survives a rebuild with a different builder ID, a different onion address, or a renamed binary, since it doesn't depend on any of those. The first branch (`TEST_BUILD_001` + `builder_id`) is weaker in isolation but only widens coverage for this specific beta build without weakening the combination's overall precision.
**False Positives:** None expected; unrelated software would need to coincidentally embed all four exact JSON field-name strings together, which is not a pattern seen outside this RaaS builder's schema.
**Blind Spots:** Won't match a build that obfuscates or encrypts its JSON field-name strings, or that replaces the JSON/serde schema with a binary serialization format.
**Validation:** Verified against the confirmed sample's embedded C2 beacon schema (`builder_id`, `victim_id`, `encryption_key`, `machine_info` fields) and the `TEST_BUILD_001` identifier documented in static analysis.

```yara
rule raas_builder_tracking {
    meta:
        description = "Detects the Arsenal-237 ransomware's RaaS builder/C2 JSON schema (builder_id, victim_id, encryption_key, machine_info) or the confirmed TEST_BUILD_001 builder identifier"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-enc_c2-exe-detections/"
        date = "2026-01-26"
        malware_type = "Ransomware (RaaS)"
        severity = "HIGH"

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

### Hunting Rules

#### Tor C2 Beacon Endpoint Path

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1090.003 (Multi-hop Proxy — Tor), T1071.001 (Web Protocols)
**Confidence:** MODERATE
**Rationale:** Anchored on the C2 beacon's endpoint-path literals (`/c2/beacon.php`, `POST /c2/beacon.php`), which a rebuilt binary can trivially change. Renameable, so it caps at Hunting rather than Detection.
**False Positives:** Low but not zero; an unrelated PHP-backed application using the identical endpoint path is theoretically possible but not expected.

```yara
rule tor_hidden_service_c2_endpoint {
    meta:
        description = "Detects the Arsenal-237 ransomware's C2 beacon endpoint path strings (Tor hidden-service JSON beacon). Renameable in a rebuilt binary; hunting signal, not a high-confidence alert"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-enc_c2-exe-detections/"
        date = "2026-01-26"
        malware_type = "C2 Infrastructure"
        severity = "MEDIUM"

    strings:
        $c2_endpoint = "/c2/beacon.php" ascii
        $c2_protocol = "POST /c2/beacon.php" ascii

    condition:
        any of them
}
```

---

#### Ransom Note Text with Supporting Ransomware Artifact

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1486 (Data Encrypted for Impact)
**Confidence:** MODERATE
**Rationale:** Requires the sample's distinctive ransom-note text plus at least one supporting string. The ransom message is a deliberate, renameable branding choice for the next campaign build, so this stays Hunting rather than Detection.
**False Positives:** Low; the anchor string (`YOUR FILES HAVE BEEN ENCRYPTED!`) is distinctive, though the supporting strings alone (`README.txt`, `ureq`) are common and could not trigger a match without the anchor.

```yara
rule enc_c2_ransomware_operations {
    meta:
        description = "Detects the Arsenal-237 ransomware's ransom note text combined with at least one supporting operational string (encrypted-file extension, ransom note filename, embedded process name, or HTTP client library)"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-enc_c2-exe-detections/"
        date = "2026-01-26"
        malware_type = "Ransomware"
        severity = "MEDIUM"

    strings:
        $ransom_msg = "YOUR FILES HAVE BEEN ENCRYPTED!" ascii
        $ransom_note = "README.txt" ascii
        $encrypted_extension = ".locked" ascii
        $enc_c2_executable = "enc_c2.exe" ascii
        $http_client = "ureq" ascii

    condition:
        $ransom_msg and 1 of ($ransom_note, $encrypted_extension, $enc_c2_executable, $http_client)
}
```

---

#### TEB-Based Anti-Debug Stall Loop

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1622 (Debugger Evasion)
**Confidence:** MODERATE
**Rationale:** Keys on the actual TEB stack-base validation primitive plus a Sleep-based stall pattern — durable to renaming and infrastructure rotation (Gate 1: Robustness 2). It caps at Hunting on precision grounds (Gate 2), not durability: TEB stack-base validation is a publicly documented, widely reused anti-debug technique also present in unrelated anti-cheat, DRM, and anti-tamper software, so a match indicates the technique, not this malware family specifically.
**False Positives:** Moderate; other legitimate software implementing the same public TEB anti-debug technique would also match.

```yara
rule teb_anti_debug_detection {
    meta:
        description = "Detects TEB (Thread Environment Block) stack-base validation anti-debugging combined with a Sleep-based stall loop, as used by the Arsenal-237 ransomware. Also matches other software using the same publicly documented anti-debug technique"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-enc_c2-exe-detections/"
        date = "2026-01-26"
        malware_type = "Anti-Analysis"
        severity = "MEDIUM"

    strings:
        $teb_api = "NtCurrentTeb" ascii
        $stack_base = "StackBase" ascii
        $sleep_loop = { 68 88 13 00 00 FF 15 } // Push 0x1388 (5000ms) / Call Sleep
        $sleep_1000 = { 68 E8 03 00 00 FF 15 } // Push 0x3E8 (1000ms) / Call Sleep

    condition:
        ($teb_api and ($sleep_loop or $sleep_1000 or $stack_base))
}
```

---

## Sigma Rules

### Detection Rules

#### HTTP POST to Tor Hidden-Service C2 Beacon Endpoint

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1090.003 (Multi-hop Proxy)
**Confidence:** HIGH
**Rationale:** Anchored to the POST method, `.onion` host suffix, and the confirmed `/c2/beacon.php` URI path together — a combination that survives onion-address rotation entirely, since no specific address is checked. This is the most durable network signal in the corpus.
**False Positives:** Unlikely; requires a POST request to any `.onion` host at this exact URI path.
**Blind Spots:** Requires network telemetry that resolves the HTTP layer of Tor-hidden-service traffic (a Tor-aware proxy or onion-resolving sensor); won't fire if visibility is limited to raw SOCKS/relay traffic, or if a future build changes the beacon URI path.
**Validation:** Verified against the confirmed C2 beacon structure (POST method, `.onion` host, `/c2/beacon.php` endpoint, JSON body) documented in static analysis.

```yaml
title: Network - HTTP POST to Tor Hidden-Service C2 Beacon Endpoint
id: 0491b05a-d2d9-43e4-b1e5-5415c8b71788
status: experimental
description: Detects HTTP POST requests to a .onion hidden-service host targeting the Arsenal-237 ransomware's confirmed C2 beacon URI path. Anchored to the URI/method/host-suffix combination rather than a specific onion address, so it survives infrastructure rotation.
references:
    - https://the-hunters-ledger.com/hunting-detections/arsenal-237-enc_c2-exe-detections/
author: The Hunters Ledger
date: 2026-01-26
logsource:
    product: firewall
    category: http_request
detection:
    selection:
        http_method: POST
        http_host|endswith: '.onion'
        http_uri: '/c2/beacon.php'
    condition: selection
falsepositives:
    - Unlikely; requires a POST request to a .onion host at this exact URI path
level: critical
tags:
    - attack.command-and-control
    - attack.t1071.001
    - attack.t1090.003
```

---

### Hunting Rules

#### enc_c2.exe Process Execution

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1204.002 (User Execution)
**Confidence:** MODERATE
**Rationale:** Filename/`OriginalFileName`-anchored only — defeated by renaming the binary in a rebuild. The original also OR'd in a standalone command-line branch matching generic flags (`--folder`, `--c2`, `--bid`) independent of the filename match; those flag names are usable by unrelated software, so that branch has been dropped and only the filename anchor retained.
**False Positives:** Unrelated software coincidentally named or renamed to enc_c2.exe.

```yaml
title: enc_c2.exe Process Execution - Ransomware
id: c38ece37-0b38-4844-aa71-41814663daaf
status: experimental
description: Detects execution of a process image or PE OriginalFileName matching enc_c2.exe. Filename-based; defeated by renaming the binary in a rebuilt variant — hunting signal, not a high-confidence alert.
references:
    - https://the-hunters-ledger.com/hunting-detections/arsenal-237-enc_c2-exe-detections/
author: The Hunters Ledger
date: 2026-01-26
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        - Image|endswith: '\enc_c2.exe'
        - OriginalFileName: 'enc_c2.exe'
    condition: selection
falsepositives:
    - Unrelated software coincidentally named or renamed to enc_c2.exe
level: medium
tags:
    - attack.execution
    - attack.t1204.002
```

---

#### Bulk-Capable File Creation with .locked Extension

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1486 (Data Encrypted for Impact)
**Confidence:** MODERATE
**Rationale:** The `.locked` extension is operator-chosen and renameable in a rebuild. The rule also has no volume threshold — a single file write fires it, where the underlying ransomware behavior is really a bulk pattern (dozens to hundreds of files in a short window). Both factors cap this at Hunting.
**False Positives:** Legitimate software using a `.locked` extension for lock/marker files; isolated, non-bulk file renames.

```yaml
title: Ransomware - File Creation with .locked Extension
id: 9af9beea-9ea3-4e5b-ad1d-1bc229d936d0
status: experimental
description: Detects creation of files with a .locked extension appended, consistent with the Arsenal-237 ransomware's encryption output. Single-event trigger with no bulk-volume threshold; review for a genuine mass-encryption pattern rather than an isolated file.
references:
    - https://the-hunters-ledger.com/hunting-detections/arsenal-237-enc_c2-exe-detections/
author: The Hunters Ledger
date: 2026-01-26
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith: '.locked'
    filter_excludes:
        TargetFilename|contains:
            - '~$'
            - 'Temp'
    condition: selection and not filter_excludes
falsepositives:
    - Legitimate software using a .locked extension for lock/marker files
    - Isolated, non-bulk file renames
level: medium
tags:
    - attack.impact
    - attack.t1486
```

---

#### Registry Persistence Key Referencing Build Identifiers

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1547.001 (Registry Run Keys / Startup Folder)
**Confidence:** MODERATE
**Rationale:** The confirmed sample uses a single-run model with no observed persistence; this rule is forward-looking coverage for a future variant that adds registry-based persistence. It is keyed on `enc_c2`/`TEST_BUILD_001`, both build-specific identifiers that change across builds, capping it at Hunting.
**False Positives:** Unlikely; keyed on build-specific malware identifiers that would not appear in unrelated registry writes.

```yaml
title: Registry - Persistence Key Referencing enc_c2/TEST_BUILD_001 Identifiers
id: 0ee562b4-ef75-4801-961d-a3479f9a0237
status: experimental
description: Detects a Run/RunOnce/Winlogon registry write whose value data contains the malware's 'enc_c2' or 'TEST_BUILD_001' build identifiers. The confirmed sample uses a single-run model with no observed persistence; this rule covers a future variant that adds registry-based persistence, keyed on identifiers that change across builds.
references:
    - https://the-hunters-ledger.com/hunting-detections/arsenal-237-enc_c2-exe-detections/
author: The Hunters Ledger
date: 2026-01-26
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        TargetObject|contains:
            - 'Software\Microsoft\Windows\CurrentVersion\Run'
            - 'Software\Microsoft\Windows\CurrentVersion\RunOnce'
            - 'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
        Details|contains:
            - 'enc_c2'
            - 'TEST_BUILD_001'
    condition: selection
falsepositives:
    - Unlikely; keyed on build-specific malware identifiers that would not appear in unrelated registry writes
level: medium
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1547.001
```

---

#### TEB Anti-Debug Sleep Loop (Call-Stack Corroboration)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1622 (Debugger Evasion)
**Confidence:** MODERATE
**Rationale:** Anchored to the same renameable `enc_c2.exe` filename as the process-execution rule, and requires call-stack-capable `process_access` telemetry that is not enabled by default in most Sysmon configurations. Retained for its corroboration value alongside the TEB anti-debug YARA rule, not as an independent high-confidence signal.
**False Positives:** Legitimate applications with sleep loops (rate limiting, polling) that happen to be named or renamed to enc_c2.exe.

```yaml
title: Process - TEB Anti-Debug Sleep Loop Detection
id: 72490224-3052-4aaf-adcb-38d4201e2d67
status: experimental
description: Detects repeated Sleep()/SleepEx() calls in the call trace of the enc_c2.exe process image, consistent with a TEB-based anti-debugging stall loop. Filename-anchored and requires call-stack-capable process_access telemetry; corroborates the same technique covered by the TEB anti-debug YARA rule.
references:
    - https://the-hunters-ledger.com/hunting-detections/arsenal-237-enc_c2-exe-detections/
author: The Hunters Ledger
date: 2026-01-26
logsource:
    product: windows
    category: process_access
detection:
    selection:
        SourceImage|endswith: 'enc_c2.exe'
        CallTrace|contains:
            - 'Sleep'
            - 'SleepEx'
            - '0x3E8'  # 1000 milliseconds in hex
    condition: selection
falsepositives:
    - Legitimate applications with sleep loops (rate limiting, polling) that happen to be named/renamed to enc_c2.exe
level: medium
tags:
    - attack.stealth
    - attack.discovery
    - attack.t1622
```

---

## Suricata Signatures

### Detection Rules

#### Tor C2 Beacon POST to /c2/beacon.php

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1090.003 (Multi-hop Proxy)
**Confidence:** HIGH
**Rationale:** The published rule matched `.onion` in the `http_uri` buffer, but a standard request to this C2 (`POST /c2/beacon.php` with the domain in the `Host` header) never places `.onion` in the URI, so the AND-combined content match could not fire against the malware's own documented traffic shape — and there was no content match for `/c2/beacon.php` at all despite it being named in `msg`. Rewritten to match the actual beacon path in the URI buffer and drop the redundant exact-domain `http_host` match (already carried in the IOC feed), which also makes the signature resilient to onion-address rotation.
**False Positives:** Unlikely; requires a POST to this exact URI path with a JSON content type.
**Blind Spots:** Same Tor-visibility requirement as the Sigma equivalent — needs a sensor that resolves the HTTP layer of Tor-hidden-service traffic; anchored to the `/c2/beacon.php` URI convention, so a rebuilt variant using a different endpoint path evades it.
**Validation:** Verified against the confirmed C2 beacon's HTTP method, URI, and Content-Type header as documented in static analysis.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"RANSOMWARE enc_c2.exe Tor C2 Beacon - POST /c2/beacon.php"; flow:to_server,established; http.method; content:"POST"; http.uri; content:"/c2/beacon.php"; http.header; content:"Content-Type: application/json"; classtype:trojan-activity; metadata:author The_Hunters_Ledger, date 2026-01-26, reference https://the-hunters-ledger.com/hunting-detections/arsenal-237-enc_c2-exe-detections/; sid:1000001; rev:2;)
```

---

## Coverage Gaps

No reliable persistence-based detection exists: the confirmed sample uses a single-run execution model with no observed persistence mechanism, so the registry rule above is forward-looking coverage for a hypothetical future variant rather than a signal this sample would itself trigger.

The C2 channel is Tor-only. Every network rule in this file (the Sigma HTTP rule and the Suricata signature) detects the HTTP layer of the beacon, which requires a sensor or proxy that resolves Tor hidden-service traffic to an inspectable HTTP request. A perimeter sensor with visibility limited to raw outbound SOCKS/relay traffic will not see this beacon at all.

Ransom-note content cannot be confirmed via the available telemetry: Sysmon `file_event` has no `Contents` field, so the literal ransom message text ("YOUR FILES HAVE BEEN ENCRYPTED!") cannot be matched at the file-system-monitoring layer — only the YARA rule (which scans file contents directly) can confirm it. This is also why the README.txt-filename Sigma rule was cut rather than kept as a weaker signal — see below.

The suggested bulk-encryption threshold (tens to hundreds of files in a short window) is not expressed in any surviving rule; the `.locked`-extension Sigma rule fires per-file. Reaching Detection-grade precision on the encryption-volume behavior would require a stateful aggregation/correlation rule, which is out of scope for the base detection blocks carried here.

### Retiering Fixes Applied

- **YARA — ChaCha20 Cryptographic Constants: Cut.** All four strings are generic cryptographic-library artifacts: `expand 32-byte k` is the RFC 7539 ChaCha20 constant used by any implementation (WireGuard, TLS 1.3 stacks, age, and many other legitimate tools); `aead-0.5.2` and `Chacha_256_constant` are Rust `aead`-crate build artifacts present in any binary depending on that crate; `chacha20` alone is a bare dictionary word. The `any of them` condition fires on the weakest of these. No malware-specific signal survives; not routed to the feed (a library artifact, not an indicator).
- **YARA — Rust Compilation Environment Artifacts: Cut.** `2 of them` over `/root/.cargo/registry/src/`, `index.crates.io`, `rustc`, `std` is satisfied by `rustc` + `std` alone, which appear in the overwhelming majority of Rust-compiled binaries regardless of maliciousness. This rule identifies "compiled with Rust," not this malware.
- **YARA — Tor Hidden Service C2 Infrastructure: salvaged, retitled `tor_hidden_service_c2_endpoint`, retiered to Hunting.** The original `any of them` condition let the bare `.onion` string alone (present in any Tor-related software) satisfy the match, and included the onion address as a rule literal despite the address already living in the IOC feed. Retained only the beacon endpoint-path strings (`/c2/beacon.php`, `POST /c2/beacon.php`); dropped `.onion` and the hardcoded address.
- **YARA — File Encryption & Ransomware Operations: condition tightened.** `3 of them` across five strings allowed a match built entirely from the two most generic entries (`README.txt`, `ureq`) plus one more, without ever requiring the sample's actual ransom-note text. Condition changed to require `$ransom_msg` plus one supporting string, so the match always includes the distinctive ransom message.
- **Sigma — enc_c2.exe Process Execution: generic CLI-flag branch dropped, retiered to Hunting, level demoted critical to medium.** The `selection_commandline` branch matched on `--folder`, `--c2`, or `--bid` alone — generic argument names usable by unrelated software — independent of the filename match, via a top-level `or`. Retained only the filename/OriginalFileName selection.
- **Sigma — File Creation with .locked Extension: level demoted high to medium, retiered to Hunting.** No volume threshold; a single `.locked` file write fires the rule, and `.locked`/`.lock`-style marker files are used by some legitimate software. Needs a bulk-creation correlation rule (not expressed here) to reach Detection-grade precision.
- **Sigma — Ransom Note Creation (README.txt): Cut.** `README.txt` under Users/Documents/Desktop is one of the most common benign filenames in existence; the source rule's own description acknowledges Sysmon cannot confirm ransom-note content. No pivot value survives; not routed to the feed (a ubiquitous filename, not an indicator).
- **Sigma — HTTP POST to .onion Domain: redundant atomic branch dropped, retained as Detection.** The `selection_target` branch matched the onion address alone (already in the IOC feed) via a top-level `or`, with no method/URI requirement. Retained only the POST + `.onion` host-suffix + `/c2/beacon.php` URI combination, which survives address rotation.
- **Sigma — Outbound Connection to Tor Entry Node: Cut.** Two of the five hardcoded destination-IP prefixes (`198.51.100.` and `203.0.113.`) are RFC 5737 TEST-NET documentation ranges that are never used for real routed traffic, indicating placeholder/unfilled data rather than verified Tor entry-node IPs. The remaining three prefixes are full /16-scale blocks with no citation tying them to Tor infrastructure. No genuine indicator survives; not routed to the feed.
- **Sigma — Registry persistence rule: title and description corrected, retiered to Hunting.** The original title ("Absence of Ransomware Persistence Mechanisms") and description ("verifies that systems do not contain persistence...") described a negative/absence check, but the `detection:` block is an ordinary positive selection that only fires when a Run/RunOnce/Winlogon value actually contains `enc_c2` or `TEST_BUILD_001` — the opposite of what the title claimed. Retitled to describe the rule's actual (positive) logic; the `falsepositives` field was corrected from a nonsensical "detects a negative condition" line to an honest assessment.
- **Suricata — Tor C2 Beacon (sid:1000001): buffer assignment fixed, redundant atomic branch dropped, retained as Detection.** The published rule matched `.onion` in the `http_uri` buffer, but a standard request to this C2 never places `.onion` in the URI — the AND-combined content match could not fire against the malware's own documented traffic shape, and there was no content match for `/c2/beacon.php` at all despite it being named in `msg`. Rewrote the URI match to the actual beacon path and dropped the redundant `http_host` exact-domain match (already in the feed), making the signature both fireable and resilient to address rotation.
- **Suricata — Tor Entry Node Connection (sid:1000002): Cut.** Destination ranges are three unsourced /16-scale blocks with no citation identifying them as Tor infrastructure, and the sole content match (`|16 03 01|`, a TLS 1.0 record header) is present in nearly all TLS handshakes — it adds no discriminating power. Not routed to the feed (not a validated indicator of this campaign's infrastructure).

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
