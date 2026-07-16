---
title: "Detection Rules — chromelevator.exe (Arsenal-237)"
date: '2026-01-27'
layout: post
permalink: /hunting-detections/arsenal-237-chromelevator-exe-detections/
hide: true
redirect_from: /hunting-detections/arsenal-237-chromelevator-exe/
thumbnail: /assets/images/cards/arsenal-237-new-files.png
---

**Campaign:** Arsenal-237-109.230.231.37-Malware-Repository
**Date:** 2026-01-27
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**IOC Feed:** https://the-hunters-ledger.com/ioc-feeds/arsenal-237-chromelevator-exe.json

---

## Detection Coverage Summary

chromelevator.exe is a 64-bit Windows credential-extraction tool from the Arsenal-237 threat-actor toolkit exposed at 109.230.231.37, alongside privilege-escalation, defense-evasion, and ransomware-deployment components from the same repository. The tool locates installed Chrome, Brave, and Edge profiles, then reflectively loads an embedded payload DLL into the target browser process over a named pipe to extract cookies, saved passwords, and stored payment data directly from the browser's own memory space and SQLite stores.

Coverage below is retiered from the original draft: every rule was re-scored for durability (does it survive infrastructure rotation and renaming?), precision (documented false-positive profile), and level discipline, per the project's Detection/Hunting split. The toolkit has no confirmed network command-and-control channel of its own; the injected payload communicates with chromelevator.exe over a local named pipe rather than the network, so coverage concentrates on the host-based injection and credential-database-access techniques that carry lasting analyst value. The multi-signal YARA rule combines several renameable build artifacts (filename, embedded resource name, log strings) with a browser-targeting condition that can also be satisfied by legitimate Chromium-based browsers, which keeps it at Hunting rather than Detection; see Coverage Gaps for the full reasoning behind every retiered and retired rule.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 2 | 1 | T1555.003, T1620, T1055.001, T1106 | 0 |
| Sigma | 2 | 2 | T1555.003, T1055.001, T1106 | 0 |
| Suricata | 0 | 0 | — | 0 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Atomics routed to the IOC feed:** the sample's SHA256/SHA1/MD5 hashes, the `chromelevator.exe` filename, its staging paths, and the browser credential-database file paths it targets were already present in [`arsenal-237-chromelevator-exe.json`](/ioc-feeds/arsenal-237-chromelevator-exe.json) before this retiering pass. No rule was demoted to a new feed entry: the two named-pipe and HTTP-POST network signatures in the original draft were cut outright rather than routed, since the campaign has no confirmed network indicator (IP, domain, or URI) to route, only local named-pipe IPC, per the IOC feed's own empty `network_indicators.domains`/`ips` arrays.

---

## YARA Rules

### Detection Rules

#### Direct Syscall Framework (Native API / EDR Bypass)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1106 (Native API)
**Confidence:** HIGH
**Rationale:** Direct-syscall implementations resolve their Nt/Zw syscall numbers at runtime by walking ntdll's exports and matching against the literal function-name strings before extracting the syscall stub, so the ASCII names are a byproduct of the resolution technique rather than an arbitrary build choice, and they persist across a rename of the binary or a rotation of infrastructure. The rule requires either all five of a tight memory-injection-relevant Zw* set, or all ten declared Zw* strings plus ten or more pattern-matched occurrences, both high-specificity combinations unlikely in software that calls the documented Win32 API surface instead.
**False Positives:** Legitimate low-level tooling that resolves the same Native API set as literal strings, for example debuggers, process-inspection utilities, and some EDR/AV self-instrumentation, can reference several of these names together; the five-of-five and all-ten thresholds narrow this to a small population worth baselining per environment.
**Blind Spots:** An operator using indirect syscalls (jumping into the middle of a legitimate ntdll stub rather than resolving and calling by name) or hashed/obfuscated API resolution that never places the plaintext function names in the binary evades this rule entirely.
**Validation:** Confirm the rule fires against a binary implementing manual Nt/Zw resolution (for example a SysWhispers-style syscall stub generator) and does not fire against a standard signed system utility or common EDR agent binary from the deployment environment.

```yara
/*
   Yara Rule Set
   Identifier: Arsenal-237-109.230.231.37-Malware-Repository
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule Arsenal237_Direct_Syscall_Framework {
    meta:
        description = "Detects direct syscall implementation used by Arsenal-237 components"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-chromelevator-exe-detections/"
        date = "2026-01-26"
        severity = "HIGH"
        category = "evasion"

    strings:
        // Zw* syscall functions (EDR bypass)
        $zw_alloc = "ZwAllocateVirtualMemory" nocase ascii
        $zw_write = "ZwWriteVirtualMemory" nocase ascii
        $zw_read = "ZwReadVirtualMemory" nocase ascii
        $zw_protect = "ZwProtectVirtualMemory" nocase ascii
        $zw_create_thread = "ZwCreateThreadEx" nocase ascii
        $zw_open_proc = "ZwOpenProcess" nocase ascii
        $zw_query_proc = "ZwQueryInformationProcess" nocase ascii
        $zw_context = "ZwGetContextThread" nocase ascii
        $zw_set_context = "ZwSetContextThread" nocase ascii
        $zw_resume = "ZwResumeThread" nocase ascii

        // Multiple syscalls indicate framework
        $zw_pattern = /Zw[A-Z][a-zA-Z]+/

    condition:
        // Multiple critical syscalls indicate EDR bypass framework
        (5 of ($zw_alloc, $zw_write, $zw_protect, $zw_create_thread, $zw_open_proc)) or

        // Pattern-based detection of systematic syscall usage
        (all of them and #zw_pattern >= 10)
}
```

#### Reflective DLL Injection Framework

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1620 (Reflective Code Loading), T1055.001 (Process Injection: DLL Injection)
**Confidence:** HIGH
**Rationale:** "ReflectiveLoader" is the export name conventionalized by the original Stephen Fewer reflective-DLL-injection technique and reused across most tools that implement it, so the string is a technique marker rather than a property of this one build. The rule's strongest branches require it alongside either the full four-syscall or four-Win32-API injection sequence (allocate, write, protect, execute-thread), a specific combination that survives a rename of the sample and stays rare in unrelated software.
**False Positives:** Legitimate injection-based tooling (some game overlays, accessibility software, and debuggers) uses the same four-API sequence, but rarely also carries a literal "ReflectiveLoader" string; residual risk is limited to other red-team or commercial reflective-loading libraries that reuse the same export name for compatibility.
**Blind Spots:** A custom reflective loader that renames its entry export away from "ReflectiveLoader" evades every branch except the weaker bare-word "reflective" branch, which still requires a co-occurring injection API. The header-anchor branch (`$dos_header at 0 and $nt_header at 60`) is a redundant corroborating check alongside the `$pe_sig` byte pattern, not the rule's primary discriminator.
**Validation:** Confirm the rule fires on a binary containing a reflective loader with the conventional export name and the classic injection API sequence, and does not fire on common installers or other legitimate injection-capable software that lack the "ReflectiveLoader" string.

```yara
rule Reflective_DLL_Injection_Framework {
    meta:
        description = "Detects reflective DLL injection implementation"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-chromelevator-exe-detections/"
        date = "2026-01-26"
        severity = "HIGH"
        category = "execution"

    strings:
        // PE header parsing
        $dos_header = "MZ"
        $nt_header = "PE"
        $pe_sig = { 50 45 00 00 }  // "PE\x00\x00"

        // Reflective loader
        $reflective_loader = "ReflectiveLoader" nocase ascii
        $reflective_export = "reflective" nocase ascii wide

        // PE parsing functions
        $dos_hdr = "DOS" nocase ascii
        $file_hdr = "File" nocase ascii
        $opt_hdr = "Optional" nocase ascii

        // Memory injection indicators
        $alloc = "VirtualAllocEx" nocase ascii
        $write = "WriteProcessMemory" nocase ascii
        $protect = "VirtualProtectEx" nocase ascii
        $create_remote = "CreateRemoteThread" nocase ascii

        // Direct syscall injection
        $zw_alloc = "ZwAllocateVirtualMemory" nocase ascii
        $zw_write = "ZwWriteVirtualMemory" nocase ascii
        $zw_protect = "ZwProtectVirtualMemory" nocase ascii
        $zw_create = "ZwCreateThreadEx" nocase ascii

    condition:
        // Reflective DLL loading pattern: MZ/PE header anchors at their canonical offsets,
        // PE signature present, and PE-parsing-function strings alongside the reflective loader
        ($reflective_loader and $dos_header at 0 and $nt_header at 60 and $pe_sig and
         any of ($dos_hdr, $file_hdr, $opt_hdr)) or

        // Reflective injection via direct syscalls
        ($reflective_loader and all of ($zw_alloc, $zw_write, $zw_protect, $zw_create)) or

        // Reflective injection via Windows APIs
        ($reflective_loader and all of ($alloc, $write, $protect, $create_remote)) or

        // Reflective export string as a standalone corroborating signal alongside memory injection APIs
        ($reflective_export and any of ($alloc, $write, $protect, $create_remote))
}
```

### Hunting Rules

#### Browser Credential Extraction Multi-Signal Combination

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1555.003 (Credentials from Web Browsers), T1620 (Reflective Code Loading)
**Confidence:** MODERATE
**Rationale:** Every branch of this rule ultimately depends on a renameable build artifact: the literal filename and embedded resource name in the strongest branch, a custom log string ("Named pipe server created") in the reflective-loading branch, or generic command-line flags in the arguments branch. A rebuild that changes the filename, resource name, and log strings defeats the rule outright, which keeps it below Detection despite the multi-signal combination logic.
**False Positives:** The combination `3 of (chrome.exe, brave.exe, msedge.exe) and 2 of (Extracted, cookies, passwords, payments)` is a goodware-collision risk. Chromium-based browsers ship a "import bookmarks and settings" feature that references sibling browser executable names, and their own Settings UI carries the literal strings "cookies" (site data controls), "passwords" (the password manager), and "payments" (saved payment methods) — a legitimate chrome.exe, brave.exe, or msedge.exe binary can plausibly satisfy this branch with no malicious content present. The command-line-flag branch (`2 of (--verbose, --fingerprint, --output-path, --help)` plus any browser name) is similarly broad, since `--verbose` and `--help` are common generic CLI conventions that a Chromium binary can also contain.
**Deployment:** Retroactive file-share and endpoint scanning, IR artifact triage on hosts associated with the Arsenal-237 toolkit's distribution infrastructure. Review every hit rather than auto-blocking, and treat hits driven solely by the browser-name/UI-string branch as likely benign until the filename/payload branch or a process-context signal corroborates.

```yara
rule Chromelevator_Browser_Credential_Extraction {
    meta:
        description = "Detects chromelevator.exe browser credential extraction tool"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-chromelevator-exe-detections/"
        date = "2026-01-26"
        severity = "MEDIUM"
        category = "trojan"
        family = "Arsenal-237"

    strings:
        // Primary identifiers
        $filename = "chromelevator.exe" nocase ascii
        $payload = "PAYLOAD_DLL" nocase ascii

        // Browser targeting
        $chrome = "chrome.exe" nocase ascii
        $brave = "brave.exe" nocase ascii
        $edge = "msedge.exe" nocase ascii

        // Functional strings
        $named_pipe = "Named pipe server created" nocase ascii
        $reflective = "ReflectiveLoader" nocase ascii
        $extraction = "Extracted" nocase ascii
        $cookies = "cookies" nocase ascii
        $passwords = "passwords" nocase ascii
        $payments = "payments" nocase ascii

        // Command-line arguments
        $verbose = "--verbose" nocase ascii
        $fingerprint = "--fingerprint" nocase ascii
        $output = "--output-path" nocase ascii
        $help = "--help" nocase ascii

        // API calls
        $create_pipe = "CreateNamedPipeW" nocase ascii
        $connect_pipe = "ConnectNamedPipe" nocase ascii
        $find_resource = "FindResourceW" nocase ascii
        $load_resource = "LoadResource" nocase ascii

    condition:
        // Definite detection: filename + payload + extraction capability
        ($filename and $payload and ($extraction or ($cookies and $passwords))) or

        // Strong detection: multiple browser targets + extraction capability
        (3 of ($chrome, $brave, $edge) and 2 of ($extraction, $cookies, $passwords, $payments)) or

        // Behavioral detection: reflective loading + named pipe + browser targeting
        ($reflective and $named_pipe and any of ($chrome, $brave, $edge)) or

        // Command-line argument signature
        (2 of ($verbose, $fingerprint, $output, $help) and any of ($chrome, $brave, $edge)) or

        // API-level corroboration: named-pipe IPC + embedded-resource loading APIs
        // alongside browser targeting (the payload DLL is staged as a PE resource and
        // delivered to the target browser process over the named pipe)
        (2 of ($create_pipe, $connect_pipe, $find_resource, $load_resource) and any of ($chrome, $brave, $edge))
}
```

---

## Sigma Rules

### Detection Rules

#### Process Injection API Sequence Targeting Browser Processes

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1055.001 (Process Injection: DLL Injection)
**Confidence:** HIGH
**Rationale:** Requires all four stages of the classic injection sequence (allocate, write, protect, remote-thread-creation) inside a single CallTrace against a named browser target, a specific technique-level combination that does not depend on the malware's own filename and survives a rebuild.
**False Positives:** Legitimate installers, debuggers, and some password-manager or automation tooling that inject into a running browser process for integration purposes can trigger the full sequence; expect occasional review-worthy hits rather than zero.
**Blind Spots:** An injection implementation using direct syscalls instead of the Win32 API names in this sequence (see the companion Direct Syscall Usage rule) or targeting a browser process by full path rather than a name ending in one of the four listed executables evades this selector.
**Validation:** Confirm the rule fires against a captured injection sequence targeting chrome.exe/brave.exe/msedge.exe/firefox.exe and does not fire on ordinary browser-extension or browser-helper-process activity that does not perform cross-process memory writes.

```yaml
title: Suspicious Process Injection - Memory Allocation Pattern
id: 4e8f2b71-9a3c-4d6e-8b1f-2e7a9c3d5f04
description: >-
    Detects process injection through a memory allocation, write, protection-change, and
    remote-thread-creation API sequence targeting a browser process. Consolidated to a
    single process_access selection using CallTrace (the original rule mixed a
    non-Sysmon EventType field alongside API and TargetImage across what would have been
    two different, incompatible event sources; the CallTrace-based selection below is the
    coherent, reliably-mappable subset that preserves the same detection intent).
references:
  - https://the-hunters-ledger.com/hunting-detections/arsenal-237-chromelevator-exe-detections/
status: experimental
author: The Hunters Ledger
date: '2026-01-26'
tags:
  - attack.execution
  - attack.stealth
  - attack.privilege-escalation
  - attack.t1055.001

logsource:
  product: windows
  category: process_access

detection:
  selection_target_processes:
    TargetImage|endswith:
      - 'chrome.exe'
      - 'brave.exe'
      - 'msedge.exe'
      - 'firefox.exe'

  selection_sequence:
    CallTrace|contains|all:
      - 'AllocateVirtualMemory'
      - 'WriteVirtualMemory'
      - 'ProtectVirtualMemory'
      - 'CreateThreadEx'

  condition: selection_target_processes and selection_sequence

falsepositives:
  - Legitimate software using process injection (installers, debuggers)

level: high
```

#### Non-Browser Process Access to Browser Credential Databases

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1555.003 (Credentials from Web Browsers)
**Confidence:** HIGH
**Rationale:** Keys on the browser profile file paths that any credential-theft tool must read regardless of its own name, a technique chokepoint that survives the operator renaming or rebuilding the tool. The specific-path selector's double-escaped backslashes have been corrected (see Coverage Gaps) so it now actually matches Cookies and Web Data access in addition to the generic Login Data path the original still caught.
**False Positives:** Browser backup/sync tools, password managers, and system-recovery or migration tooling legitimately read the same files; the process and SYSTEM-user exclusions narrow this but do not eliminate it.
**Blind Spots:** A process that spoofs or masquerades under one of the four excluded browser executable names, or credential theft performed by loading directly inside the browser process itself (see the Process Injection rule above, which is designed to catch that path instead), evades this file-access selector.
**Validation:** Confirm the rule fires when a non-browser process reads Login Data, Cookies, or Web Data under a Chrome/Brave/Edge profile directory, and does not fire on the browsers' own processes or SYSTEM-context activity.

```yaml
title: Suspicious Browser Credential Database Access
id: 6c9e1d83-4b7f-4a2e-9c5d-3f8b2e6a1c05
description: >-
    Detects access to Chrome/Brave/Edge credential databases by non-browser processes.
    Restructured the original selection's invalid literal OR: subkey (not valid Sigma
    syntax) into two named selections combined via the condition string; detection intent
    is unchanged. The specific-path selector's TargetFilename patterns were also corrected
    from double-escaped to single backslashes — the doubled backslashes, valid only inside
    double-quoted YAML, could never match a real single-backslash Windows path when written
    inside single-quoted scalars, which perform no escape processing at all.
references:
  - https://the-hunters-ledger.com/hunting-detections/arsenal-237-chromelevator-exe-detections/
status: experimental
author: The Hunters Ledger
date: '2026-01-26'
tags:
  - attack.credential-access
  - attack.t1555.003
  - detection.emerging-threats

logsource:
  product: windows
  category: file_event

detection:
  selection_browser_db_generic:
    TargetFilename|contains|all:
      - 'User Data'
      - 'Login Data'

  selection_browser_db_specific:
    TargetFilename|contains:
      - 'Chrome\User Data\Default\Cookies'
      - 'Brave-Browser\User Data\Default\Cookies'
      - 'Edge\User Data\Default\Cookies'
      - 'Google\Chrome\User Data\Default\Web Data'

  selection_process_exclusion:
    Image|endswith:
      - 'chrome.exe'
      - 'brave.exe'
      - 'msedge.exe'
      - 'firefox.exe'

  filter_system_process:
    User|contains: 'SYSTEM'

  condition: (selection_browser_db_generic or selection_browser_db_specific) and not (selection_process_exclusion or filter_system_process)

falsepositives:
  - Browser backup/sync tools
  - Password managers accessing browser data
  - System recovery tools

level: high
```

### Hunting Rules

#### chromelevator.exe Process Creation with Extraction Flags

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1555.003 (Credentials from Web Browsers)
**Confidence:** MODERATE
**Rationale:** Both selectors, the filename and the three command-line flags, are choices the operator made for this specific build and can be changed on a rebuild without affecting functionality; the combination narrows false positives today but does not survive a rename.
**False Positives:** Low today given the specific flag combination, but any internal tool or script that happens to reuse flags named --verbose/--fingerprint/--output-path would also match.
**Deployment:** Scoping and retroactive hunting for this specific build; not a durable signal for the campaign once the operator renames the binary.

```yaml
title: Suspicious Process Creation - chromelevator.exe
id: 5b6b41f8-1c8e-4a3e-9d3a-6c1f2b9e4a01
description: Detects execution of chromelevator.exe browser credential extraction tool
references:
  - https://the-hunters-ledger.com/hunting-detections/arsenal-237-chromelevator-exe-detections/
status: experimental
author: The Hunters Ledger
date: '2026-01-26'
tags:
  - attack.credential-access
  - attack.t1555.003
  - attack.stealth
  - detection.emerging-threats
logsource:
  product: windows
  category: process_creation
detection:
  selection_image:
    Image|endswith: 'chromelevator.exe'

  selection_commandline:
    CommandLine|contains:
      - '--verbose'
      - '--fingerprint'
      - '--output-path'

  condition: selection_image and selection_commandline

falsepositives:
  - Legitimate browser management tools
  - System administrators testing security

level: medium
```

#### Direct Syscall Usage Targeting Browser Processes

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1106 (Native API)
**Confidence:** MODERATE
**Rationale:** Covers the same direct-syscall technique as the companion Detection-tier Process Injection rule and the Direct Syscall Framework YARA rule, but requires only one of five Zw* calls (`CallTrace|contains`, not `contains|all`) against a browser target rather than the full sequence, a meaningfully broader, lower-bar selector. Retagged with T1106 (Native API), the technique this rule actually detects; the original attack.t1622 (Debugger Evasion) tag is kept alongside it since direct syscalls can incidentally also skip hooked stubs a debugger has instrumented, but T1106 is the primary fit.
**False Positives:** A single Zw* call touching a browser process, for example a legitimate process-monitoring, screen-capture, or window-management tool opening a handle, is common enough that this rule needs analyst review rather than auto-alerting; level lowered from critical accordingly.
**Deployment:** Threat-hunting scope-widening alongside the Detection-tier Process Injection Pattern rule; expect a higher benign hit rate and triage against process ancestry and the target browser's user context.

```yaml
title: Suspicious Direct Syscall Usage - EDR Bypass
id: 8f3a5c92-6d1e-4b7f-a3c9-5d2b8e4f7a06
description: >-
    Detects direct Zw* syscall invocation bypassing Windows API monitoring, targeting a
    browser process. Consolidated onto process_access/CallTrace (the original rule's
    EventID list spanned two distinct Sysmon categories — CreateRemoteThread and
    ProcessAccess — with a non-Sysmon-native API field; process_access is the coherent,
    reliably-mappable subset that preserves the same detection intent).
references:
  - https://the-hunters-ledger.com/hunting-detections/arsenal-237-chromelevator-exe-detections/
status: experimental
author: The Hunters Ledger
date: '2026-01-26'
tags:
  - attack.execution
  - attack.stealth
  - attack.discovery
  - attack.t1106
  - attack.t1622

logsource:
  product: windows
  category: process_access

detection:
  selection_suspicious_syscalls:
    CallTrace|contains:
      - 'ZwAllocateVirtualMemory'
      - 'ZwWriteVirtualMemory'
      - 'ZwCreateThreadEx'
      - 'ZwProtectVirtualMemory'
      - 'ZwOpenProcess'

  selection_target:
    TargetImage|endswith:
      - 'chrome.exe'
      - 'brave.exe'
      - 'msedge.exe'

  condition: all of selection_*

falsepositives:
  - System administration tools
  - Debugging tools

level: medium
```

---

## Suricata Signatures

No Detection or Hunting Suricata coverage is published for this campaign. chromelevator.exe has no confirmed network command-and-control channel; the injected payload DLL communicates with the parent process over a local named pipe, not over the network. The two network signatures in the original draft (a TCP content match on the literal string "VERBOSE_", and a generic HTTP POST URI substring match on "credentials") were not grounded in any observed network behavior and have been cut rather than retiered — see Coverage Gaps.

---

## Coverage Gaps

No network-based detection exists for this campaign because no network C2 channel has been observed; all inter-process communication runs over a local named pipe between chromelevator.exe and its injected payload. If a future Arsenal-237 component is confirmed to exfiltrate the extracted credentials over the network, network coverage should be revisited against that component's actual traffic rather than against chromelevator.exe itself.

Rule conservation: the original draft contained 3 YARA, 5 Sigma, and 2 Suricata rules (10 total). This pass produced 4 Detection (2 YARA, 2 Sigma), 3 Hunting (1 YARA, 2 Sigma), and 3 Cut (1 Sigma, 2 Suricata), with 0 rules demoted to new IOC-feed atomics — 4 + 3 + 3 = 10.

### Retiering Fixes Applied

- **Goodware-collision risk documented (YARA, Browser Credential Extraction Multi-Signal Combination):** the branch `3 of (chrome.exe, brave.exe, msedge.exe) and 2 of (Extracted, cookies, passwords, payments)` can be satisfied by a legitimate Chromium-based browser binary: Chrome/Brave/Edge ship an import-from-other-browser feature that references sibling browser executable names, and their own Settings UI contains the literal strings "cookies", "passwords", and "payments". This keeps the rule at Hunting; the filename+payload branch remains the reliable path to a true positive. See the rule's False Positives field above for the full reasoning.
- **Over-escaped backslash bug fixed (Sigma, Non-Browser Process Access to Browser Credential Databases):** the `selection_browser_db_specific` list originally used doubled backslashes (`'Chrome\\User Data\\Default\\Cookies'`) inside single-quoted YAML scalars. Single-quoted YAML performs no escape processing, so the doubled backslashes were literal, and the selector was searching for a double-backslash path that never appears in a real Windows path. In practice the rule still caught password-database access via the generic `selection_browser_db_generic` branch (which only requires the substrings "User Data" and "Login Data"), but Cookies and Web Data access, the browser's session-token and payment-data stores, were silently unreachable through the specific-path branch. Corrected to single backslashes so the specific-path branch now matches as originally intended.
- **ATT&CK retag (Sigma, Direct Syscall Usage Targeting Browser Processes):** the rule detects direct Zw*/Nt* syscall invocation, which maps primarily to T1106 (Native API); the original tag set carried only attack.t1622 (Debugger Evasion), a plausible secondary effect but not the primary technique. Added attack.t1106 alongside the existing tag rather than replacing it.
- **Two Suricata network signatures cut:** "Named Pipe C2 Communication Pattern" (sid 1000001) matched the literal string "VERBOSE_" in `file_data` over any TCP connection in either direction, a signature with no basis in the malware's documented behavior (named pipes are local IPC and do not traverse TCP/IP; no source string resembling "VERBOSE_" appears anywhere else in the sample's documented strings). "Potential Credential Exfiltration - Large Data Transfer" (sid 1000002) matched any HTTP POST whose URI contains "credentials", explicitly flagged in the original draft's own text as speculative ("would detect C2 communication... if integrated with other campaign components") rather than based on observed traffic, and broad enough to match ubiquitous legitimate API endpoints (password-reset flows, credential-management REST APIs). Both fail Gate 2 on ungrounded/overbroad grounds and were cut outright; neither had an atomic IP, domain, or URI to route to the feed instead.
- **Sigma "Named Pipe Creation - Reflective Injection C2" cut:** `PipeName|contains: '\\.\pipe\'` matches the standard prefix present on essentially every Windows named pipe, and the source-process selector (`chromelevator.exe` OR `explorer.exe` OR `svchost.exe`) includes two of the most common pipe-creating processes on any healthy system as part of normal service and shell operation. The four-entry exclusion list (lsass/winlogon/winspool/netdde) does not come close to covering the legitimate universe of svchost.exe/explorer.exe pipe creation, so the rule as published would fire continuously in production. The narrow chromelevator.exe-only sub-case adds no detection value beyond the Process Creation rule above, which already covers that process's execution.
- **Severity/level recalibration:** the original draft marked every YARA rule "CRITICAL" and most Sigma rules "critical" regardless of documented false-positive exposure. Per Gate 4 (critical = never-FP + high relevance), every surviving rule was recalibrated against its actual FP profile: the two Detection-tier YARA rules moved from CRITICAL to HIGH, the Hunting-tier YARA rule moved from CRITICAL to MEDIUM, and the two Hunting-tier Sigma rules moved from critical to medium. The two Detection-tier Sigma rules were already at the appropriate `high` and needed no change.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
