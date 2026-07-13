---
title: "Detection Rules — Hybrid Loader/Stealer Ecosystem Masquerading as Sogou"
date: '2025-11-21'
layout: post
permalink: /hunting-detections/Hybrid-Loader-Stealer-Sogou-detections/
hide: true
redirect_from: /hunting-detections/Hybrid-Loader-Stealer-Sogou
thumbnail: /assets/images/cards/Hybrid-Loader-Stealer-Sogou.png
---

**Campaign:** Sogou-Hybrid-Loader-Stealer-Ecosystem
**Date:** 2025-11-21
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/Hybrid-Loader-Stealer-Sogou/

---

## Detection Coverage Summary

SogouStealer is a hybrid loader/stealer ecosystem distributed as a fake, cracked-build NSIS installer for the Sogou Input Method, combining registry-based persistence, a multi-component dropped-file toolkit (loader, downloader, network helper, signature database), and disposable C2 infrastructure. Coverage here is intentionally scoped to the behavioral and structural leads that retain analyst value; the campaign's atomic network indicators — ten disposable C2 domains and two C2 IPs — are carried in the IOC feed rather than as standalone signatures.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 2 | 1 | T1036.005, T1622, T1071.001 | 0 |
| Sigma | 2 | 1 | T1036.005, T1547.001, T1105 | 2 |
| Suricata | 0 | 1 | T1071.001 | 16 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchors:**
- The bespoke dropped-component filename set (`beacon_sdk.dll`, `SGDownload.exe`, `SGCurlHelper.dll`, `userNetSchedule.exe`, `UserExportDll.dll`, `UrlSignatureV.dat`, `pandorabox.cupf`, `PersonalCenter.cupf`) anchors both the registry-persistence and file-drop Sigma rules and the combined YARA ecosystem rule — distinctive, near-zero FP.
- The multi-clause YARA ecosystem fingerprint (domain fragment + API/packing bucket + component filename, all three required simultaneously) survives a single-component rename.

**Atomics routed to the IOC feed:** the ten disposable C2 domains (`6.ar`, `j.im`, `5bng.ar`, `b.tk`, `k.ct`, `q.ar`, `rlh.cq`, `s0.ndf`, `vpl.gu`, `x.pg`) and the two C2 IPs (`149.50.136.243`, `52.20.84.62`) are transient indicators already carried in [`Hybrid-Loader-Stealer-Sogou-iocs.json`](/ioc-feeds/Hybrid-Loader-Stealer-Sogou-iocs.json) — 18 of the original file's rules (2 Sigma, 16 Suricata) each keyed solely on one of these hardcoded values, and removing the literal leaves no behavior to detect. Block them via the feed.

---

## YARA Rules

### Detection Rules

#### SogouStealer Ecosystem Indicators (Combined Fingerprint)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1036.005 (Masquerading: Match Legitimate Name or Location)
**Confidence:** HIGH
**Rationale:** Requires three independently-anchored clauses to all hold: a disposable-domain-fragment match, two of a twelve-member API/packing/masquerade-string bucket, and one of eight bespoke dropped-component filenames. No single renameable literal carries the rule alone — an operator must simultaneously rotate domains, rework the packing/API footprint, and rename every dropped component to fully evade, a substantial engineering lift short of a full rebuild.
**False Positives:** None known — the combination requires a distinctive component filename (e.g. `beacon_sdk.dll`, `SGDownload.exe`) alongside domain and packing/API evidence; no legitimate software plausibly carries this specific combination.
**Blind Spots:** A comprehensive rebrand that renames all eight dropped components AND rotates every listed domain fragment AND strips the Sogou-branding strings would evade; the rule targets the on-disk installer/dropper, not memory-only variants.
**Validation:** Scan the analyzed installer sample (`hash1` below) — all three clauses must match; a legitimate, unrelated NSIS-packed installer must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, email-gateway attachment scanning, download-quarantine scanning.

```yara
/*
   Yara Rule Set
   Identifier: Sogou-Hybrid-Loader-Stealer-Ecosystem
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule SogouStealer_Ecosystem_Indicators {
   meta:
      description = "Detects the SogouStealer hybrid loader/stealer ecosystem via a combination of disposable C2 domain fragments, anti-analysis/packing indicators, and its bespoke dropped-component filenames"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/Hybrid-Loader-Stealer-Sogou-detections/"
      date = "2025-11-21"
      hash1 = "4e987719ab96064594c98b62000612f90fe4c34c08161c290ec3898f100f6891"
      hash2 = "97f5b1508079584568d7f773d166d441097064b4"
      hash3 = "259b7806c2c9cade90acb0f18d940197"
      family = "SogouStealer"
      malware_type = "Loader/Stealer"
      campaign = "Sogou-Hybrid-Loader-Stealer-Ecosystem"
      id = "6e3e7505-6247-5ec2-9df4-6afe7e01a155"
   strings:
      $d1 = "6.ar" ascii nocase fullword
      $d2 = "J.im" ascii nocase fullword
      $d3 = "5bNG.ar" ascii nocase fullword
      $d4 = "B.tk" ascii nocase fullword
      $d5 = "K.ct" ascii nocase fullword
      $d6 = "Q.ar" ascii nocase fullword
      $d7 = "rlh.cq" ascii nocase fullword
      $d8 = "s0.ndf" ascii nocase fullword
      $d9 = "vpl.gu" ascii nocase fullword
      $d10 = "X.pg" ascii nocase fullword
      $tok = "CGI1" ascii fullword

      $s1 = "Sogou Input Method v15.1.0.1570" wide ascii
      $s2 = "get.sogou.com" ascii
      $s3 = "ping.pinyin.sogou.com" ascii

      $n1 = "Nullsoft" ascii
      $n2 = "NSIS" ascii fullword
      $enc1 = "CRC32" ascii fullword
      $enc2 = "XOR" ascii fullword

      $api1 = "FindWindowExA" ascii
      $api2 = "GetLastError" ascii
      $api3 = "IShellLink" ascii
      $vm1  = "Xen" ascii fullword

      $f1 = "beacon_sdk.dll" ascii
      $f2 = "SGDownload.exe" ascii
      $f3 = "SGCurlHelper.dll" ascii
      $f4 = "userNetSchedule.exe" ascii
      $f5 = "UserExportDll.dll" ascii
      $f6 = "UrlSignatureV.dat" ascii
      $f7 = "pandorabox.cupf" ascii
      $f8 = "PersonalCenter.cupf" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 20MB and
      ( ($d1 or $d2) or (2 of ($d3,$d4,$d5,$d6,$d7,$d8,$d9,$d10)) ) and
      ( 2 of ($api1,$api2,$api3,$vm1,$n1,$n2,$enc1,$enc2,$tok,$s1,$s2,$s3) ) and
      ( 1 of ($f1,$f2,$f3,$f4,$f5,$f6,$f7,$f8) )
}
```

#### SogouStealer C2 Scheduler and Signature-Database Components

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH
**Rationale:** Corrected from the original: a YARA operator-precedence bug (`(A and B) or C or D`) let the signature-database or CGI-marker string alone fire the rule with no PE-header gate, matching any file type — not just Windows executables. Reparenthesized so the MZ check gates the full OR-set, and tightened from "1 of 4" to "2 of 4" so a single component rename or one incidental string collision cannot trigger it; an attacker must simultaneously rename or drop two of the four distinctive C2/scheduler artifacts to evade.
**False Positives:** None known — three of the four anchors (`userNetSchedule.exe`, `SGCurlHelper.dll`, `UrlSignatureV.dat`) are bespoke filenames with no plausible legitimate collision; the fourth (`/cgi1`) is weaker alone but the 2-of-4 requirement means it never carries a match by itself.
**Blind Spots:** A rebuild that renames two or more of the four anchors evades; the rule targets on-disk artifacts, not the live network protocol.
**Validation:** Scan the analyzed sample or a dropped scheduler/curl-helper component — must satisfy 2 of the 4 anchors; a benign file containing only one incidental match (e.g. an unrelated file with `/cgi1` in a URL string) must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, static triage of dropped components.

```yara
rule SogouStealer_C2_Scheduler_SignatureDB {
   meta:
      description = "Detects the SogouStealer scheduler/C2-helper/signature-database component set via a required combination of two or more of its bespoke component filenames and CGI URI marker, surviving a single-component rename"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/Hybrid-Loader-Stealer-Sogou-detections/"
      date = "2025-11-21"
      hash1 = "4e987719ab96064594c98b62000612f90fe4c34c08161c290ec3898f100f6891"
      hash2 = "97f5b1508079584568d7f773d166d441097064b4"
      hash3 = "259b7806c2c9cade90acb0f18d940197"
      family = "SogouStealer"
      malware_type = "Loader/Stealer"
      campaign = "Sogou-Hybrid-Loader-Stealer-Ecosystem"
      id = "8bf56993-bc5a-5706-b01e-9e8cfbdc970c"
   strings:
      $sched = "userNetSchedule.exe" ascii
      $curl  = "SGCurlHelper.dll" ascii
      $sigdb = "UrlSignatureV.dat" ascii
      $cgi   = "/cgi1" ascii fullword
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      2 of ($sched,$curl,$sigdb,$cgi)
}
```

### Hunting Rules

#### SogouStealer Loader/Downloader Components

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1622 (Debugger Evasion)
**Confidence:** MODERATE
**Rationale:** The rule's real discriminating power rests on a single distinctive literal (`beacon_sdk.dll` or `SGDownload.exe`) — both bespoke and unlikely to collide with legitimate software today, but a rename in a future build fully evades the rule. The paired anti-debug/overlay condition (`IsDebuggerPresent`, `QueryPerformanceCounter`, `overlay`) is near-ubiquitous in native Windows binaries and adds negligible discriminating value on its own. (Corrected from the original: the `overlay` string was declared but never referenced in the condition — a YARA hard compile error — and has been wired into the anti-analysis bucket.)
**False Positives:** Low but not zero — a future build that renames both `beacon_sdk.dll` and `SGDownload.exe` evades entirely; conversely, the filenames alone have no known legitimate collision.
**Deployment:** Endpoint AV/EDR file scan; a broader sweep of a file corpus for either component filename independent of the full ecosystem combination in the Detection-tier rule above.

```yara
rule SogouStealer_Loader_Downloader {
   meta:
      description = "Detects standalone SogouStealer loader/downloader components (beacon_sdk.dll, SGDownload.exe) paired with anti-debug or overlay-packing indicators; broader and less specific than the combined ecosystem rule"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/Hybrid-Loader-Stealer-Sogou-detections/"
      date = "2025-11-21"
      hash1 = "4e987719ab96064594c98b62000612f90fe4c34c08161c290ec3898f100f6891"
      hash2 = "97f5b1508079584568d7f773d166d441097064b4"
      hash3 = "259b7806c2c9cade90acb0f18d940197"
      family = "SogouStealer"
      malware_type = "Loader/Stealer"
      campaign = "Sogou-Hybrid-Loader-Stealer-Ecosystem"
      id = "a0f53ba5-82fe-54e4-ad59-f73c8af668a3"
   strings:
      $loader = "beacon_sdk.dll" ascii
      $down   = "SGDownload.exe" ascii
      $anti1  = "IsDebuggerPresent" ascii
      $anti2  = "QueryPerformanceCounter" ascii
      $pack1  = "overlay" ascii fullword
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      ( $loader or $down ) and
      ( 1 of ($anti1,$anti2,$pack1) )
}
```

---

## Sigma Rules

### Detection Rules

#### SogouStealer Persistence via Run Keys

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1547.001 (Registry Run Keys / Startup Folder)
**Confidence:** HIGH
**Rationale:** Requires the registry value location to be a genuine Run/RunOnce autostart key AND the written value data to reference one of three bespoke component filenames — a combination an operator cannot satisfy without both persisting via this technique and retaining a recognizable component name. The `attack.t1547.009` LNK-modification tag on the original rule has been removed: the detection logic is registry-only and never evaluates shortcut files, despite the rule title referencing "LNK Modification" (see Coverage Gaps).
**False Positives:** None known — `beacon_sdk.dll`, `SGDownload.exe`, and `userNetSchedule.exe` are bespoke filenames with no plausible legitimate collision in a Run/RunOnce value.
**Blind Spots:** A rebuild that renames all three referenced components evades; persistence via a different mechanism (scheduled task, service, LNK modification — none of which this rule inspects) is not covered.
**Validation:** Trigger the malware's persistence routine — the registry write must match; a legitimate application's unrelated Run-key entry must NOT fire.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (registry telemetry).

```yaml
title: SogouStealer Persistence via Run Keys and LNK Modification
id: 190b57f6-a8c3-4f45-a39d-ed7340d66b9a
status: experimental
description: Detects registry Run key entries referencing the SogouStealer ecosystem's own component filenames (beacon_sdk.dll, SGDownload.exe, userNetSchedule.exe)
references:
    - https://the-hunters-ledger.com/hunting-detections/Hybrid-Loader-Stealer-Sogou-detections/
author: The Hunters Ledger
date: '2025-11-21'
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1547.001
    - detection.emerging-threats
logsource:
    product: windows
    category: registry_set
detection:
    selection_run:
        TargetObject|contains:
            - '\Software\Microsoft\Windows\CurrentVersion\Run'
            - '\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        Details|contains:
            - 'beacon_sdk.dll'
            - 'SGDownload.exe'
            - 'userNetSchedule.exe'
    condition: selection_run
falsepositives:
    - Unlikely; these filenames are specific to this malware ecosystem
level: high
```

#### SogouStealer Artifact Drop and Staging

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer)
**Confidence:** HIGH
**Rationale:** Matches file-creation events against eight bespoke component filenames spanning the ecosystem's loader, downloader, network-helper, and signature-database roles. Retagged from the original, which carried three tactic labels (`attack.execution`, `attack.stealth`, `attack.persistence`) with no technique-ID tag at all — a SigmaHQ validation failure; the file-creation behavior itself is most precisely T1105.
**False Positives:** None known — all eight filenames are bespoke to this malware ecosystem.
**Blind Spots:** A rebuild that renames all eight components evades; a memory-only variant that never writes these files to disk is not covered.
**Validation:** Trigger the dropper/installer — at least one component filename must be written to disk and match; unrelated legitimate software must NOT fire.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (file-creation telemetry).

```yaml
title: SogouStealer Artifact Drop and Staging
id: 1d3185d1-08ce-4956-91bd-f4ce70d10a46
status: experimental
description: Detects creation of known component files (loaders, downloaders, network helpers, signature databases) staged to disk by the SogouStealer ecosystem
references:
    - https://the-hunters-ledger.com/hunting-detections/Hybrid-Loader-Stealer-Sogou-detections/
author: The Hunters Ledger
date: '2025-11-21'
tags:
    - attack.command-and-control
    - attack.t1105
    - detection.emerging-threats
logsource:
    product: windows
    category: file_create
detection:
    selection_names:
        TargetFilename|endswith:
            - '\beacon_sdk.dll'
            - '\SGDownload.exe'
            - '\SGCurlHelper.dll'
            - '\userNetSchedule.exe'
            - '\UserExportDll.dll'
            - '\UrlSignatureV.dat'
            - '\pandorabox.cupf'
            - '\PersonalCenter.cupf'
    condition: selection_names
falsepositives:
    - Unlikely; these filenames are specific to this malware ecosystem
level: high
```

### Hunting Rules

#### SogouStealer Masquerading NSIS Installer Execution

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1036.005 (Masquerading: Match Legitimate Name or Location)
**Confidence:** MODERATE
**Rationale:** The command-line OR-list mixes genuinely distinctive campaign markers (`拼音`, `吾爱破解`, the pinned `v15.1.0.1570` version string) with two terms — `NSIS`, `Nullsoft` — that are generic to the entire NSIS installer ecosystem used by a large volume of legitimate software. Because the list is OR-matched, a hit on the generic pair fires the rule identically to a hit on the distinctive markers, so the original `level: high` overstated confidence for the generic-term branch. Demoted to Hunting/`medium`; the Image-class AND-gate and the distinctive markers still make this a useful triage lead.
**False Positives:** Legitimate NSIS-based installers whose command line coincidentally references the generic `NSIS`/`Nullsoft` build-tool strings alongside a generically-named `setup.exe`/`install.exe`/`installer.exe`. The Chinese-language cracked-build markers and the specific version string are unlikely to collide with legitimate software.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM process-creation monitoring; prioritize hits carrying `拼音`, `吾爱破解`, or `v15.1.0.1570` over hits carrying only `NSIS`/`Nullsoft`.

```yaml
title: SogouStealer Masquerading NSIS Installer Execution
id: a078683b-110a-4973-86bb-1666dba668bf
status: experimental
description: Detects execution of suspected NSIS-based fake Sogou installers with cracked-build markers
references:
    - https://the-hunters-ledger.com/hunting-detections/Hybrid-Loader-Stealer-Sogou-detections/
author: The Hunters Ledger
date: '2025-11-21'
tags:
    - attack.stealth
    - attack.t1036.005
    - detection.emerging-threats
logsource:
    product: windows
    category: process_creation
detection:
    selection_image:
        Image|endswith:
            - '\installer.exe'
            - '\setup.exe'
            - '\install.exe'
    selection_cmdline:
        CommandLine|contains:
            - 'NSIS'
            - 'Nullsoft'
            - 'Sogou'
            - '拼音'
            - '吾爱破解'
            - 'v15.1.0.1570'
    condition: selection_image and selection_cmdline
falsepositives:
    - Legitimate NSIS-based installers whose command line coincidentally references the generic NSIS/Nullsoft build-tool strings
    - Unlikely for the Chinese-language cracked-build markers or the specific version string, which are not generic NSIS artifacts
level: medium
```

---

## Suricata Signatures

### Hunting Rules

#### SogouStealer CGI1 C2 URI Pattern

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** MODERATE
**Rationale:** `/cgi1` is a single short literal in the HTTP URI — brittle if the operator changes the C2 endpoint convention in a future build — but unlike the domain- and IP-based indicators in this campaign, it survives infrastructure rotation (a new C2 domain or IP reusing the same URI convention still fires). No corroborating content anchor (host, method, body pattern) was available to combine with it for a Detection-grade signature.
**False Positives:** Any unrelated HTTP request whose URI happens to contain the 5-character substring `/cgi1` (uncommon but not impossible on generic CGI-driven web infrastructure); the `threshold` limits alert volume per source.
**Deployment:** Network IDS/IPS at perimeter and internal segmentation points; hunt-tune before alerting.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL SogouStealer-HybridLoader CGI1 C2 URI Pattern (C2 Transport Indicator)"; flow:established,to_server; http.uri; content:"/cgi1"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000001; rev:1; metadata:author The_Hunters_Ledger, date 2025-11-21, reference https://the-hunters-ledger.com/hunting-detections/Hybrid-Loader-Stealer-Sogou-detections/;)
```

---

## Coverage Gaps

**Atomics routed to the IOC feed (18 of the original file's 26 rules).** Every DNS-query rule (10), TLS-SNI rule (2), HTTP-Host rule (2), and pure-IP rule (2) in the original Sigma and Suricata sections keyed solely on one of ten disposable domains or two C2 IPs, with no behavioral qualifier surviving the literal's removal — per the tiering rubric's routing test, these are IOC-feed entries, not rules. All twelve underlying values (`6.ar`, `j.im`, `5bng.ar`, `b.tk`, `k.ct`, `q.ar`, `rlh.cq`, `s0.ndf`, `vpl.gu`, `x.pg`, `149.50.136.243`, `52.20.84.62`) were already present in [`Hybrid-Loader-Stealer-Sogou-iocs.json`](/ioc-feeds/Hybrid-Loader-Stealer-Sogou-iocs.json) from the original analysis — no feed edits were required.

**Cut: Potential Access Token Manipulation by Suspicious Installer (T1134).** The original rule matched `GrantedAccess` bitmasks (`0x1FFFFF`, `0x00100000`) combined with `CallTrace` references to `OpenProcessToken`/`AdjustTokenPrivileges` — a technique-level signature with no anchor tying it to the SogouStealer ecosystem (no `Image`, `ParentImage`, or `TargetImage` filter). Full-access process-token queries and privilege adjustments are ubiquitous in legitimate administrative tooling, security products, and routine Windows service startup, so as written this fires on ambient benign activity with no distinguishing filter — it does not clear the precision bar even for Hunting. **What would enable a rule:** scoping the selection to a source or target process image tied to the installer or one of its named components (e.g. requiring `Image` to end with `SGDownload.exe` or `userNetSchedule.exe`).

**Mutex value not captured.** The underlying IOC feed records that "a mutex string was identified in the binary" for single-instance enforcement, but does not carry the actual mutex string — only the observation that one exists. No YARA string match or Sigma `process_creation`/`CreateMutex` rule can be written without the literal value. **What would enable a rule:** the specific mutex name from static or dynamic analysis of the installer.

**LNK/shortcut persistence referenced but not detected.** The original "Persistence via Run Keys and LNK Modification" rule title (preserved above) implies the malware also modifies Windows shortcut (`.lnk`) files as a persistence vector, but the rule's detection logic is registry-only — it never evaluates shortcut files, and no shortcut-target, icon-path, or working-directory artifact was captured in the underlying evidence to build a dedicated rule. **What would enable a rule:** the specific `.lnk` file path and the exact field(s) modified (target, icon, working directory) from static or dynamic analysis.

**Credential-theft and IPTV-piracy components out of scope for this file.** The associated report documents browser-data and JD.com credential theft and a separate IPTV-piracy component as part of the same ecosystem, but neither is represented in any rule in this file (original or current) — no API sequence, file path, or network indicator specific to credential harvesting or IPTV streaming was carried into the detection-authoring evidence. **What would enable a rule:** the specific browser-data-access API sequence or file paths (e.g. a Chromium `Login Data` access pattern) and the IPTV component's distinct network/file signature.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
