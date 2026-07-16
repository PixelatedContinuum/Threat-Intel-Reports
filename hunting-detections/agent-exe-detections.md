---
title: "Detection Rules — agent.exe (PoetRAT)"
date: '2026-01-12'
layout: post
permalink: /hunting-detections/agent-exe-detections/
hide: true
redirect_from: /hunting-detections/agent-exe/
thumbnail: /assets/images/cards/109.230.231.37-Executive-Overview.png
---

**Campaign:** Arsenal-237-109.230.231.37-Malware-Repository
**Date:** 2026-01-12
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**IOC Feed:** https://the-hunters-ledger.com/ioc-feeds/agent-exe.json

---

## Detection Coverage Summary

agent.exe is a 64-bit Golang-compiled Remote Access Trojan recovered from an open directory at `109.230.231.37`, part of the broader Arsenal-237 threat-actor R&D repository exposure. Attribution to the PoetRAT family sits at MODERATE confidence (60%) — Golang compilation, dual redundant persistence, anti-debugging, and a comprehensive RAT capability set resemble known PoetRAT behavior, but no confirmed code-family match was made. The sample's command-and-control channel is environment-aware and withholds activation, so no C2 protocol structure is available to anchor a network signature.

Coverage below is retiered from the original draft: every rule was re-scored for durability (does it survive infrastructure rotation and renaming?), precision (documented false-positive profile), and level discipline, per the project's Detection/Hunting split. Coverage here is scoped to the host-based artifacts that retain analyst value: this family's discriminating literals are Windows-Defender masquerade names, which are renameable by the operator at will, so the surviving rules are tiered Hunting rather than Detection. The campaign's atomic indicators (the distribution IP and the installation-marker path) are carried in the IOC feed rather than as standalone signatures.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 0 | 3 | T1036.005, T1547.001, T1622, T1056.001, T1021.001, T1059.001, T1543.003, T1573 | 0 |
| Sigma | 0 | 3 | T1547.001, T1036.005 | 1 |
| Suricata | 0 | 0 | — | 2 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Atomics routed to the IOC feed:** the distribution IP (`109.230.231.37`) and the `.wd_installed` marker-file path were already present in [`agent-exe.json`](/ioc-feeds/agent-exe.json) before this retiering pass. The two IP-match Suricata signatures and the single-literal `.wd_installed` Sigma selector added no detection value beyond those feed entries and have been retired — see Coverage Gaps for the full reasoning on every retired rule.

---

## YARA Rules

### Hunting Rules

#### Golang RAT Multi-Signal Combination (Hash Match or Behavioral Combination)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1036.005 (Masquerading), T1622 (Debugger Evasion), T1056.001 (Input Capture: Keylogging), T1573 (Encrypted Channel)
**Confidence:** MODERATE
**Rationale:** This rule fixes a hard compile error in the original "comprehensive" rule — its condition referenced `$antidebug_*`, `$crypto_*`, `$net_*`, and `$surv_*`, wildcard prefixes that match none of the rule's actual string identifiers (`$antidebug1`, `$crypto1`, `$net1`, `$surv1` — no underscore before the number). The real `yarac` compiler rejects this outright (`undefined string "$antidebug_*"`); as published, the rule never loaded at all. The wildcard references have been corrected to restore the intended logic: a fast-path exact-hash match, or one of two combinations requiring Golang runtime evidence plus crypto imports plus anti-debug or surveillance APIs, each also requiring at least one of the WinDefenderSvc.exe / WindowsDefenderUpdate / .wd_installed masquerade strings. Both behavioral branches still depend on that masquerade-string family, so a naming-convention rebrand defeats every non-hash path — that renameable dependency, not the richness of the combination, is why this sits at Hunting rather than Detection.
**False Positives:** None known for the hash-match branch (exact-file equality). The Golang-plus-crypto-plus-anti-debug combination alone is common in legitimate Go network tooling, but both behavioral branches require it to co-occur with a Windows-Defender-masquerade literal, which is not expected in unrelated software; residual risk is a coincidental unrelated tool reusing the same masquerade filename or registry value name.
**Deployment:** Endpoint AV/EDR file scanning, email gateway attachment scanning, retroactive scan of file shares, IR artifact triage on hosts that resolved 109.230.231.37.

```yara
/*
   Yara Rule Set
   Identifier: Arsenal-237-109.230.231.37-Malware-Repository
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule TOOLKIT_PoetRAT_Golang_Multi_Signal_Combination {
   meta:
      description = "Detects agent.exe-class PoetRAT-attributed Golang RAT samples via a multi-signal combination: Windows-Defender-masquerade persistence strings, Golang compilation artifacts, anti-debugging APIs, and cryptographic/network/surveillance capability imports. Also matches on the two known sample hashes directly."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/agent-exe-detections/"
      date = "2026-01-12"
      family = "PoetRAT"
      malware_type = "RAT"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "cf6db0bf-fc1e-482b-a028-3dd99d2219e9"
      hash1 = "e7f9a29dde307afff4191dbc14a974405f287b10f359a39305dccdc0ee949385"
      hash2 = "4e856041018242c62b3848d63b94c3763beda01648d3139060700c11e9334ad1"
   strings:
      $hash_agent = "e7f9a29dde307afff4191dbc14a974405f287b10f359a39305dccdc0ee949385" nocase
      $hash_windefender = "4e856041018242c62b3848d63b94c3763beda01648d3139060700c11e9334ad1" nocase

      $str_windefendersvc = "WinDefenderSvc.exe" ascii wide nocase
      $str_defender_update = "WindowsDefenderUpdate" ascii wide nocase
      $str_marker = ".wd_installed" ascii wide

      $golang_runtime1 = "runtime.main" ascii
      $golang_runtime2 = "runtime.goexit" ascii
      $golang_runtime3 = "go.buildid" ascii
      $golang_runtime4 = "runtime.morestack" ascii

      $antidebug1 = "NtQueryInformationProcess" ascii wide
      $antidebug2 = "SetConsoleCtrlHandler" ascii wide
      $antidebug3 = "IsDebuggerPresent" ascii wide

      $crypto1 = "crypto/aes" ascii
      $crypto2 = "crypto/rsa" ascii
      $crypto3 = "crypto/sha" ascii
      $crypto4 = "chacha20" ascii nocase
      $crypto5 = "golang.org/x/crypto" ascii

      $net1 = "net.Listen" ascii
      $net2 = "net.Dial" ascii
      $net3 = "TCPConn" ascii
      $net4 = "net/http" ascii

      $surv1 = "GetAsyncKeyState" ascii wide
      $surv2 = "SetWindowsHookEx" ascii wide
      $surv3 = "GetForegroundWindow" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      (
         any of ($hash_*) or
         (
            (2 of ($str_*)) and
            (2 of ($golang_runtime*)) and
            (1 of ($antidebug*)) and
            (1 of ($crypto*))
         ) or
         (
            (3 of ($golang_runtime*)) and
            (2 of ($crypto*)) and
            (1 of ($str_*)) and
            (1 of ($net*)) and
            (1 of ($surv*))
         )
      )
}
```

#### WinDefenderSvc.exe + WindowsDefenderUpdate Masquerade Pair

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1036.005 (Masquerading), T1547.001 (Registry Run Keys / Startup Folder)
**Confidence:** LOW
**Rationale:** Requires two independently attacker-chosen literal strings — the WinDefenderSvc.exe filename plus the WindowsDefenderUpdate registry value name, or the .wd_installed marker plus generic Golang runtime evidence — to co-occur inside the same file. That is a step above a single atomic (an unrelated program embedding one string by coincidence is far less likely to also embed the other), but every discriminating literal here is an attacker-chosen masquerade artifact rather than a technique-level chokepoint, so a naming-convention rebrand defeats every branch. Kept as a Hunting lead for recurrence of this specific dropper/build family, not promoted to Detection.
**False Positives:** Unlikely for the exact two-literal pairing, but not zero. The `.wd_installed`-plus-Golang-runtime branch effectively reduces to the marker filename alone, since "any Golang binary" is close to a universal condition that adds no real discriminating power.
**Deployment:** Endpoint AV/EDR file scanning, IR artifact triage, retroactive scan of file shares.

```yara
rule TOOLKIT_PoetRAT_WinDefender_Masquerade_Persistence_Pair {
   meta:
      description = "Detects PoetRAT-class droppers embedding the paired Windows-Defender-masquerade persistence artifact strings (WinDefenderSvc.exe + WindowsDefenderUpdate registry value, or the .wd_installed marker alongside Golang runtime strings). Brittle to a naming-convention rebrand — treat as a scoping lead, not an alert."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/agent-exe-detections/"
      date = "2026-01-12"
      family = "PoetRAT"
      malware_type = "RAT-Persistence-Component"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "0c69a4b5-b6b2-44fd-baf2-36bddc32fe6f"
      hash1 = "4e856041018242c62b3848d63b94c3763beda01648d3139060700c11e9334ad1"
   strings:
      $defender_svc = "WinDefenderSvc.exe" ascii wide nocase
      $defender_update = "WindowsDefenderUpdate" ascii wide nocase
      $startup_path = "Start Menu\\Programs\\Startup" ascii wide nocase
      $marker_file = ".wd_installed" ascii wide

      $go1 = "Go build ID:" ascii
      $go2 = "runtime.main" ascii
      $go3 = "runtime.goexit" ascii
   condition:
      uint16(0) == 0x5A4D and
      (
         ($defender_svc and $defender_update) or
         ($defender_svc and $startup_path) or
         ($marker_file and any of ($go*))
      )
}
```

#### Generic Golang RAT Capability Combination

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1056.001 (Input Capture: Keylogging), T1021.001 (Remote Desktop Protocol), T1059.001 (PowerShell), T1543.003 (Windows Service), T1573 (Encrypted Channel)
**Confidence:** LOW
**Rationale:** A broad, campaign-agnostic combination of Golang runtime evidence with common capability and networking APIs — keylogging, RDP, PowerShell, or service-creation strings alongside crypto and network imports. It is durable in the sense that it does not depend on any campaign-specific literal, but every individual API in the combination is routine in legitimate Go-based remote-access, automation, and monitoring tools. The source file's own severity rating (MEDIUM) already reflected this as a broader, non-alerting-grade pattern; retained here as an explicitly-labeled Hunting rule rather than Detection.
**False Positives:** Expected against legitimate Go-compiled remote-support, automation, or hotkey-capture tooling that combines any two capability APIs with TLS and networking imports — analyst review of the specific binary (signer, provenance, install context) is required before treating a hit as malicious.
**Deployment:** Broad endpoint/EDR scanning sweep, retroactive hunt across file shares; treat hits as triage candidates, not alerts.

```yara
rule TOOLKIT_Golang_RAT_Generic_Capability_Combination {
   meta:
      description = "Detects Golang-compiled executables combining input-capture/service-creation capability APIs with crypto and network stdlib imports — a broad toolkit-family heuristic for Golang RATs, not specific to any one campaign. Expect co-fire with legitimate Golang network/remote-access tooling."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/agent-exe-detections/"
      date = "2026-01-12"
      family = "Golang-RAT-Generic"
      malware_type = "RAT"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "a65492ab-4dc6-481e-b4bf-29ca070acdae"
   strings:
      $go_runtime1 = "runtime.main" ascii
      $go_runtime2 = "runtime.goexit" ascii
      $go_runtime3 = "runtime.morestack" ascii
      $go_runtime4 = "go.buildid" ascii

      $cap_keylog = "GetAsyncKeyState" ascii wide
      $cap_keylog2 = "SetWindowsHookEx" ascii wide
      $cap_rdp = "TermService" ascii wide nocase
      $cap_ps = "powershell" ascii wide nocase
      $cap_service = "CreateService" ascii wide

      $crypto_aes = "crypto/aes" ascii
      $crypto_tls = "crypto/tls" ascii
      $crypto_modern = "chacha20" ascii nocase

      $net_tcp = "net.Dial" ascii
      $net_http = "net/http" ascii
      $net_listen = "net.Listen" ascii
   condition:
      uint16(0) == 0x5A4D and
      (2 of ($go_runtime*)) and
      (2 of ($cap_*)) and
      (1 of ($crypto_*)) and
      (1 of ($net_*))
}
```

---

## Sigma Rules

### Hunting Rules

#### PoetRAT Dual Persistence: Startup Drop + Registry Run Key Write (Correlation)

**Tier:** Hunting (correlation rule) — bundled below with its 2 required non-alerting base rules
**Robustness:** 2 (correlation) / 1 (each base rule individually)
**ATT&CK Coverage:** T1547.001 (Registry Run Keys / Startup Folder), T1036.005 (Masquerading)
**Confidence:** LOW — both base signals are individually brittle single-literal selectors; the correlation adds real but limited value
**Rationale:** Neither base selector survives a naming-convention rebrand — the Startup-folder filename and the Run-key value name are both attacker-chosen literals from the same masquerade decision, unlike an independent two-capability correlation. The malware's own dual-persistence design — "redundant survival: removal of one mechanism does not eliminate persistence," per the existing IOC feed's documented behavioral findings — means a genuine infection of this specific build produces both artifacts together, close in time; a coincidental unrelated program matching one selector is meaningfully less likely to also match the other. This operationalizes the malware-analyst's own recommended detection strategy ("monitor for simultaneous creation of both persistence mechanisms") as a real correlation rule instead of three disconnected atomic selectors. *Retiering note:* the source draft published these two artifacts, plus a third (the `.wd_installed` marker), as three separate single-field Sigma selectors — `TargetFilename|contains: ...WinDefenderSvc.exe` and `TargetObject|endswith: ...WindowsDefenderUpdate`, both at `level: critical` — textbook pure-IOC selectors per the project's Cut checklist, and both literals were already present in the IOC feed. Rather than cut them outright, this pass restructured the two persistence-mechanism selectors into the temporal correlation below; the third (`.wd_installed`, an install de-duplication marker rather than a persistence mechanism) had no comparable pairing and was routed to the feed instead (see Coverage Gaps).
**False Positives:** A coordinated rebrand of both artifact names in one future build evades the correlation entirely. Legitimate software is not expected to write both artifacts with these exact names, but the correlation inherits each base rule's narrow FP profile rather than adding new false-positive risk of its own.
**Deployment:** SIEM correlation engine with Sysmon/EDR file-event and registry-event telemetry ingested (10-minute temporal join on host.name); Windows file integrity monitoring and registry auditing as the underlying data sources.

```yaml
title: WinDefenderSvc.exe Startup Folder Drop (Base Rule)
id: ca0e1263-d7d0-4c19-bdce-a837dfda222b
name: windefendersvc_startup_drop
status: experimental
description: >-
  Base rule (not alerting on its own): creation of a file named exactly
  WinDefenderSvc.exe in a user Startup folder. Paired with the registry-write
  base rule below via the correlation rule, which flags co-occurrence of both
  PoetRAT-class dual-persistence artifacts on the same host.
references:
  - https://the-hunters-ledger.com/hunting-detections/agent-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.stealth
  - attack.t1547.001
  - attack.t1036.005
  - detection.emerging-threats
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|endswith: '\Start Menu\Programs\Startup\WinDefenderSvc.exe'
  condition: selection
falsepositives:
  - >-
    Legitimate software using this exact filename is not expected — Microsoft-signed
    Defender components do not install here. Not alerting on its own; reviewed only
    in combination with the paired registry-write base rule.
level: informational
---
title: WindowsDefenderUpdate Registry Run Key Write (Base Rule)
id: f3c242f1-521f-448b-9d7c-a613c9975090
name: windowsdefenderupdate_run_key_write
status: experimental
description: >-
  Base rule (not alerting on its own): creation of a CurrentVersion\Run value
  named WindowsDefenderUpdate whose data does not point at the legitimate
  Windows Defender install path. Paired with the Startup-folder-drop base rule
  above via the correlation rule below.
references:
  - https://the-hunters-ledger.com/hunting-detections/agent-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.stealth
  - attack.t1547.001
  - attack.t1036.005
  - detection.emerging-threats
logsource:
  product: windows
  category: registry_set
detection:
  selection:
    TargetObject|endswith: '\Software\Microsoft\Windows\CurrentVersion\Run\WindowsDefenderUpdate'
  filter:
    Details|contains: 'C:\Program Files\Windows Defender\'
  condition: selection and not filter
falsepositives:
  - >-
    Legitimate Windows Defender update mechanisms are not expected to use this value
    path (extremely rare). Not alerting on its own; reviewed only in combination with
    the paired Startup-folder base rule.
level: informational
---
title: PoetRAT-Class Dual Persistence — Startup Drop + Run Key Write on Same Host
id: 9ac725e3-2b02-488d-aef0-4e2bdb843ff1
status: experimental
description: >-
  Fires when both the WinDefenderSvc.exe Startup-folder drop and the
  WindowsDefenderUpdate Run-key write are observed on the same host within a
  short window. Neither base signal alone is reliable (both are single,
  attacker-chosen literal names that a rebrand trivially evades), but the
  malware's own dual-persistence design — redundant survival so removing one
  mechanism does not eliminate the other — means a genuine infection produces
  both artifacts together, close in time, which a coincidental unrelated
  installer would not.
references:
  - https://the-hunters-ledger.com/hunting-detections/agent-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.stealth
  - attack.t1547.001
  - attack.t1036.005
  - detection.emerging-threats
correlation:
  type: temporal
  rules:
    - windefendersvc_startup_drop
    - windowsdefenderupdate_run_key_write
  group-by:
    - host.name
  timespan: 10m
falsepositives:
  - >-
    A coordinated rebrand of both artifact names in a future build evades this
    correlation entirely — both remain the same attacker-chosen naming
    decision, so this is a scoping lead for this specific build family, not a
    durable technique-level detector.
level: medium
```

---

## Coverage Gaps

### Retiering Fixes Applied

- **YARA compile error fixed (Rule 1).** The original "comprehensive" rule's condition referenced `$antidebug_*`, `$crypto_*`, `$net_*`, and `$surv_*` — wildcard prefixes that match none of the rule's actual string identifiers (`$antidebug1`, `$crypto1`, `$net1`, `$surv1`, none with a trailing underscore). Compile-tested with the real `yarac`: the original text fails with `undefined string "$antidebug_*"` and never loads. The wildcard references have been corrected (`$antidebug*`, `$crypto*`, `$net*`, `$surv*`) to restore the intended multi-branch logic; the corrected rule now compiles cleanly.
- **Sigma broken logsource/field mismatch removed (source Rule 3, "Golang Executable Creating Persistence with Anti-Debug").** The rule's `selection_golang` block checked the process-creation `Image` field (a file *path*) for the substring `runtime.main` — a Go runtime symbol that appears only inside a compiled binary's embedded strings, never in a file path or process image name. No real Windows process `Image` field will ever contain that text; the `go.exe` alternative in the same selector only matches an operator literally invoking the Go compiler, not a compiled RAT running under any other name (including `agent.exe` itself). As written, this selector could not fire on the actual sample it was built to detect. There is no clean fix within Sigma's process_creation logsource (embedded-string inspection is YARA's job, not Sigma's), so the rule has been cut rather than carried forward broken. See "Cut Rules" below.
- **Sigma dual-persistence correlation built from two retired atomic selectors.** See the correlation rule's own Rationale above.

### Cut Rules (genuine noise — not routed to the feed)

- **Sigma "Golang Executable Creating Persistence with Anti-Debug"** (source Sigma Rule 3, id `b1d5e55b-1c15-b7cb-8391-38625d9d2efa`) — cut for the broken logsource/field mismatch described above. No salvage was attempted beyond the broken half: the surviving `selection_persistence` clause (`CommandLine` contains `\Startup\`, `CurrentVersion\Run`, or `schtasks`) has no PoetRAT-specific nexus once decoupled from the (non-functional) Golang check — it is a fully generic persistence-command-line pattern unrelated to this investigation's actual findings, and publishing it as a new rule would not be restructuring existing content.
- **Suricata "Golang C2 Traffic Pattern Detection"** (source sid `1000003`) — cut. The rule matched `content:"Go"` (a 2-byte, case-sensitive substring) against the HTTP User-Agent header with no `alert http` protocol declaration to match the legacy `http_user_agent` modifier. Even corrected, the anchor text is a severe precision failure: the default Go `net/http` client's own User-Agent literally begins `Go-http-client/`, making this pattern a magnet for ubiquitous, entirely benign Go tooling (container health checks, Kubernetes probes, countless DevOps CLIs). It is also unsupported by this investigation's own evidence — the sample's environment-aware C2 never yielded an observed session, so the pattern was speculative rather than an observed artifact. Fails both durability-of-purpose and precision; not a routable atomic (there is no clean indicator value to send to the feed).

### Atomics Routed to the IOC Feed

- **Suricata "Connection to Distribution IP"** (source sids `1000001` and `1000002`, inbound/outbound pair) — pure IP-match rules (`alert tcp $HOME_NET any -> 109.230.231.37 any`, no content/protocol anchor). Textbook Suricata Cut per the project checklist ("pure IP-match rules... belong in iprep/reputation/dataset, not a signature"). The IP is already present in `agent-exe.json` under `network_indicators.distribution_infrastructure`.
- **Sigma "PoetRAT Installation Marker File (.wd_installed)"** (source Sigma Rule 4, id `6b86b273-ff34-fce1-9d6b-804eff5a3f57`) — a pure single-literal `TargetFilename|endswith: '.wd_installed'` selector, structurally identical to the project's canonical Sigma Cut example (`Image|endswith: \Client.exe`). Unlike the two persistence-mechanism selectors, `.wd_installed` is a de-duplication marker (prevents reinstall), not a redundant persistence artifact, so it had no comparable pairing to fold into the correlation rule. Already present in `agent-exe.json` under `persistence_indicators.installation_marker`, including its own hash.

### A Genuinely Close Call: Why the Masquerade Literals Did Not Reach Detection

The richest surviving YARA rule (Golang RAT Multi-Signal Combination) requires the same WinDefenderSvc.exe / WindowsDefenderUpdate family of literals that the Sigma selectors were cut for, combined with real behavioral structure (Golang + crypto + anti-debug/surveillance). The rubric's own durability tie-breaker names "a masquerade filename" explicitly as a disqualifying literal type, and the distinguishing test against this project's own Detection-tier precedents (e.g., a rootkit's fabricated `libpam_cache` module name, or an operator's invented `PandoraNet` botnet ID) is whether the literal is a bespoke, one-off coined string with no plausible reason to appear elsewhere, versus a masquerade of a real, common product name. "WinDefenderSvc.exe" / "WindowsDefenderUpdate" are the latter — impersonating Windows Defender inside universal, non-namespaced OS mechanisms (the Startup folder, the Run key) is an industry-common convention independently reused by many unrelated malware families, not a marker unique to this investigation. That is why every rule anchored on this literal family capped at Hunting regardless of how much additional behavioral structure surrounded it.

### Environment-Aware C2 — No Network Behavioral Rule Possible

This build withholds C2 activation unless its environment checks pass, so no protocol, URI, or header structure is available from which to build a Suricata Detection or Hunting signature. The only network artifact is the distribution IP itself, already routed to the feed above. This mirrors the disposition applied elsewhere in this project to C2 infrastructure observed only in a pre-activation state: feed-only coverage until protocol structure is available.

### Family Attribution Uncertainty (MODERATE, 60%)

PoetRAT attribution rests on behavioral resemblance (Golang compilation, dual persistence, anti-debugging, comprehensive capability set), not a confirmed code-family match. Every rule in this file is scoped to the specific dropper/build family observed at 109.230.231.37, not to confirmed PoetRAT membership — a hit indicates "this build family, or a close variant," not "confirmed PoetRAT."

### Capabilities Documented in the IOC Feed Without Dedicated Rule Coverage

The IOC feed lists several statically-confirmed capabilities that have no dedicated event-level (Sigma) detection here, only the static string-presence signal folded into the generic YARA capability rule: privilege escalation (T1068), RDP as an active lateral-movement channel rather than a string reference (T1021.001), Windows service creation as a live event (T1543.003), local data collection (T1005), and C2-channel exfiltration (T1041). Behavioral (EDR/Sysmon event) coverage for these requires the capability to be observed in use, which this build's environment-aware activation withholds.

### What Would Enable Stronger Coverage

- **Observed C2 traffic** — protocol structure from an active session (URI structure, header pattern, JA3/JA4) would replace the feed-only IP coverage with a genuine network signature.
- **Goodware corpus validation** — none of the YARA Hunting rules have been run against a broad clean-software corpus; a documented zero-FP result against such a corpus is the explicit precondition for reconsidering Detection tier on the multi-signal rule.
- **Confirmed code-level family match** — sharpening the PoetRAT attribution from behavioral resemblance to a confirmed code/config match would allow future rules to target family-specific artifacts instead of this build's masquerade-literal family.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
