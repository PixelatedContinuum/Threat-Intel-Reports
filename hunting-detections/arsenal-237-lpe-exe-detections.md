---
title: "Detection Rules — lpe.exe (Arsenal-237 LPE Module)"
date: '2026-01-25'
layout: post
permalink: /hunting-detections/arsenal-237-lpe-exe-detections/
hide: true
redirect_from: /hunting-detections/arsenal-237-lpe-exe/
thumbnail: /assets/images/cards/arsenal-237-new-files.png
---

**Campaign:** Arsenal-237-109.230.231.37-Malware-Repository
**Date:** 2026-01-25
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**IOC Feed:** https://the-hunters-ledger.com/ioc-feeds/arsenal-237-lpe-exe.json

---

## Detection Coverage Summary

lpe.exe is a 64-bit Rust-compiled local privilege escalation (LPE) wrapper recovered from the same Arsenal-237 open-directory exposure at 109.230.231.37 as the broader malware toolkit repository. The tool accepts another executable as a command-line argument (typically `killer.dll` or `killer.exe`) and elevates it to NT AUTHORITY\SYSTEM, cycling through five independent escalation techniques (token impersonation, registry-based UAC bypass, named pipe impersonation, scheduled task creation, and WMI process creation) until one succeeds. Family attribution to the Arsenal-237 toolkit is CONFIRMED: the sample was co-located with `killer.dll` and other toolkit components on the same distribution infrastructure. Coverage here is scoped to the wrapper's own escalation techniques, not the payload it launches.

Coverage below is retiered from the original draft: every rule was re-scored for durability (does it survive infrastructure rotation and renaming?), precision (documented false-positive profile), and level discipline, per the project's Detection/Hunting split.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 4 | 2 | T1134.001, T1548.002, T1053.005, T1047 | 0 |
| Sigma | 3 | 2 | T1134.001, T1548.002, T1053.005, T1047 | 0 |
| Suricata | 0 | 0 | — | 0 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Atomics routed to the IOC feed:** this file never carried the SHA256/MD5/SHA1 hash or the distribution IP (`109.230.231.37`) as a standalone rule; both were already present in [`arsenal-237-lpe-exe.json`](/ioc-feeds/arsenal-237-lpe-exe.json), under `file_hashes` and `network_indicators.distribution_infrastructure` respectively. No atomics required routing during this retiering pass.

---

## YARA Rules

### Detection Rules

#### Token Manipulation API Sequence

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1134.001 (Token Impersonation/Theft)
**Confidence:** HIGH
**Rationale:** Requires all six APIs in the process-enumeration-to-impersonation chain (`CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW`, `OpenProcessToken`, `DuplicateTokenEx`, `ImpersonateLoggedOnUser`) to co-occur, plus references to at least two of the four SYSTEM-privileged target processes (`winlogon.exe`, `lsass.exe`, `services.exe`, `csrss.exe`). Each API individually is common in legitimate administration and security tooling, but the full six-API sequence combined with SYSTEM-process targeting is the token-theft pattern itself, not a component that survives being isolated from it: recompiling or renaming the binary does not remove the need to call this exact sequence to achieve the technique.
**False Positives:** Legitimate process-management and EDR/security tooling that enumerates processes and duplicates tokens for its own privileged operations (process explorers, some backup or remote-support agents) can share this API combination; treat a hit as a strong lead requiring binary-provenance review, not an unconditional block.
**Blind Spots:** A rewrite performing token theft via direct syscalls or a different API chain (for example `NtOpenProcessToken`) evades this rule.
**Validation:** Scan `lpe.exe` (hash below); must match. A legitimate process-explorer or backup-agent binary that also imports these six APIs should be reviewed for the SYSTEM-process pairing before being treated as a false positive.
**Deployment:** Endpoint AV/EDR file scanning, IR artifact triage, retroactive scan of file shares and installer repositories.

```yara
/*
   Yara Rule Set
   Identifier: Arsenal-237-109.230.231.37-Malware-Repository
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule Arsenal237_LPE_Token_Manipulation {
   meta:
      description = "Detects lpe.exe-class Arsenal-237 privilege-escalation wrappers via the full six-API token-theft sequence (process enumeration through impersonation) combined with references to at least two SYSTEM-privileged target processes."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-lpe-exe-detections/"
      date = "2026-01-25"
      hash1 = "c4dda7b5c5f6eab49efc86091377ab08275aa951d956a5485665954830d1267e"
      family = "Arsenal-237-LPE-Wrapper"
      malware_type = "Privilege-Escalation-Wrapper"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "b3e63cd7-eb13-5f0d-ac24-a89c0c56aa01"
   strings:
      $api1 = "CreateToolhelp32Snapshot" ascii wide
      $api2 = "OpenProcessToken" ascii wide
      $api3 = "DuplicateTokenEx" ascii wide
      $api4 = "ImpersonateLoggedOnUser" ascii wide
      $api5 = "Process32FirstW" ascii wide
      $api6 = "Process32NextW" ascii wide

      $process1 = "winlogon.exe" ascii wide nocase
      $process2 = "lsass.exe" ascii wide nocase
      $process3 = "services.exe" ascii wide nocase
      $process4 = "csrss.exe" ascii wide nocase
   condition:
      uint16(0) == 0x5A4D and
      filesize < 1MB and
      all of ($api*) and
      2 of ($process*)
}
```

#### UAC Bypass via ms-settings Registry Hijack

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1548.002 (Bypass User Account Control)
**Confidence:** HIGH
**Rationale:** All five strings are direct artifacts of one specific, well-documented UAC-bypass technique: the `ms-settings\Shell\Open\command` registry hijack that abuses `fodhelper.exe`'s auto-elevation. None of the five is a name the malware author invented; the registry path, `DelegateExecute`, and `fodhelper.exe` are fixed OS/technique artifacts the attacker cannot rename away from and still perform this exact bypass. Requiring all five together (the path, the delegate-execute marker, both `reg add`/`reg delete` command verbs, and the target binary name) is a technique chokepoint, not a coincidental combination. Retiering fix: the source rule's registry-path string was over-escaped (eight raw backslash characters between each path component in the file, compiling to two literal backslashes per separator), which would never match the single-backslash form this path actually takes as embedded text; corrected to the properly-escaped single-backslash form.
**False Positives:** None known; legitimate software does not embed the combination of this exact registry path with `reg add`/`reg delete` command construction and `fodhelper.exe` references.
**Blind Spots:** A build using a different UAC-bypass technique (for example `sdclt.exe`, `eventvwr.exe`, or `ComputerDefaults.exe` hijacks) evades this rule entirely; it is specific to the ms-settings/fodhelper variant.
**Validation:** Scan `lpe.exe` (hash below); must match. Unrelated software referencing `fodhelper.exe` alone, without the paired registry-path and `DelegateExecute` strings, must NOT fire.
**Deployment:** Endpoint AV/EDR file scanning, IR artifact triage, retroactive scan of file shares.

```yara
rule Arsenal237_LPE_UAC_Bypass {
   meta:
      description = "Detects lpe.exe-class Arsenal-237 privilege-escalation wrappers via the ms-settings Shell Open command registry-hijack UAC bypass: the registry path, DelegateExecute marker, reg add/delete command verbs, and fodhelper.exe target, all co-occurring."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-lpe-exe-detections/"
      date = "2026-01-25"
      hash1 = "c4dda7b5c5f6eab49efc86091377ab08275aa951d956a5485665954830d1267e"
      family = "Arsenal-237-LPE-Wrapper"
      malware_type = "Privilege-Escalation-Wrapper"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "ec1c0013-93e9-5955-b94e-1cc409fe54d9"
   strings:
      $reg1 = "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command" ascii wide nocase
      $reg2 = "DelegateExecute" ascii wide
      $reg3 = "reg add" ascii wide nocase
      $reg4 = "fodhelper.exe" ascii wide nocase
      $reg5 = "reg delete" ascii wide nocase
   condition:
      uint16(0) == 0x5A4D and
      filesize < 1MB and
      all of ($reg*)
}
```

#### Scheduled Task SYSTEM Escalation Lifecycle

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1053.005 (Scheduled Task)
**Confidence:** HIGH
**Rationale:** Requires all five command-line fragments needed to build the create-then-delete SYSTEM task lifecycle (`schtasks`, `/create`, `/tn`, `/ru SYSTEM`, `/delete`) to co-occur as embedded strings. `/tn` and `/ru SYSTEM` are schtasks-specific syntax fragments, not generic words, and embedding both the create AND delete command templates together in one compiled binary is characteristic of purpose-built escalation tooling rather than a one-off administrative script.
**False Positives:** Legitimate deployment or RMM tooling that embeds the full schtasks create-plus-delete command template in a single compiled binary is uncommon but not impossible; review the calling binary's provenance before treating a hit as malicious.
**Blind Spots:** Task names are likely randomized at runtime and are not hardcoded in the malware, so this rule cannot rely on any specific task name; a build that constructs the schtasks command line dynamically at runtime with no embedded template strings would evade static string matching.
**Validation:** Scan `lpe.exe` (hash below); must match. A legitimate IT-automation tool that only embeds `/create` and `/ru SYSTEM` without the paired `/delete` cleanup template must NOT fire.
**Deployment:** Endpoint AV/EDR file scanning, IR artifact triage, retroactive scan of file shares.

```yara
rule Arsenal237_LPE_Schtasks {
   meta:
      description = "Detects lpe.exe-class Arsenal-237 privilege-escalation wrappers building a schtasks.exe create-then-delete SYSTEM task lifecycle: the schtasks invocation, task-name flag, /ru SYSTEM run-as-SYSTEM parameter, and self-cleanup delete, all co-occurring as command-line fragments."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-lpe-exe-detections/"
      date = "2026-01-25"
      hash1 = "c4dda7b5c5f6eab49efc86091377ab08275aa951d956a5485665954830d1267e"
      family = "Arsenal-237-LPE-Wrapper"
      malware_type = "Privilege-Escalation-Wrapper"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "89cb74a1-93b5-5838-90e5-802877519e40"
   strings:
      $schtasks1 = "schtasks" ascii wide nocase
      $schtasks2 = "/create" ascii wide nocase
      $schtasks3 = "/tn" ascii wide nocase
      $schtasks4 = "/ru SYSTEM" ascii wide nocase
      $schtasks5 = "/delete" ascii wide nocase
   condition:
      uint16(0) == 0x5A4D and
      filesize < 1MB and
      all of ($schtasks*)
}
```

#### Named Pipe Token Impersonation API Sequence

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1134.001 (Token Impersonation/Theft)
**Confidence:** HIGH
**Rationale:** Retiering fix: this rule is split out of the source file's single "Named Pipe Impersonation Pattern" rule, whose condition was `all of ($pipe*) or ($ps and $ps_pipe)`. That OR let a much weaker branch (bare `powershell` plus the .NET class name `NamedPipeClientStream`, with no pipe-specific evidence at all) fire the entire rule, dragging a genuinely strong signal down to that branch's precision. Split so the native API sequence keeps its Detection-grade confidence; the weaker branch is now its own Hunting-tier rule below. `CreateNamedPipeW` + `ConnectNamedPipe` + `ImpersonateNamedPipeClient` is the literal Win32 API sequence for named-pipe token impersonation (a technique chokepoint), combined with the pipe namespace prefix and a Print Spooler (`spoolss`) reference. Also retagged from the source's T1055.001 (Dynamic-link Library Injection, unrelated to named-pipe impersonation) to T1134.001, the technique this behavior actually maps to, matching the correction already applied to the companion Sigma rule. Retiering fix: the pipe-prefix string was over-escaped in the source (sixteen raw backslash characters around the prefix, compiling to double the correct number of literal backslashes), which would never match the real `\\.\pipe\` prefix as embedded text; corrected to the properly-escaped form.
**False Positives:** None known; the combination of the full native API sequence with the pipe-namespace prefix and the Print Spooler reference is not present in legitimate software.
**Blind Spots:** A build using a different named-pipe API sequence, or one targeting a service other than the Print Spooler, evades this rule.
**Validation:** Scan `lpe.exe` (hash below); must match. A tool that only calls `CreateNamedPipeW` for legitimate IPC, without `ImpersonateNamedPipeClient`, must NOT fire.
**Deployment:** Endpoint AV/EDR file scanning, IR artifact triage, retroactive scan of file shares.

```yara
rule Arsenal237_LPE_Named_Pipe_Token_Theft {
   meta:
      description = "Detects lpe.exe-class Arsenal-237 privilege-escalation wrappers performing named-pipe token impersonation: the CreateNamedPipeW, ConnectNamedPipe, and ImpersonateNamedPipeClient API sequence together with the pipe namespace prefix and a Print Spooler (spoolss) pipe reference."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-lpe-exe-detections/"
      date = "2026-01-25"
      hash1 = "c4dda7b5c5f6eab49efc86091377ab08275aa951d956a5485665954830d1267e"
      family = "Arsenal-237-LPE-Wrapper"
      malware_type = "Privilege-Escalation-Wrapper"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "0f7e11be-769c-5dfe-b6f0-80c143501fcd"
   strings:
      $pipe1 = "CreateNamedPipeW" ascii wide
      $pipe2 = "ImpersonateNamedPipeClient" ascii wide
      $pipe3 = "ConnectNamedPipe" ascii wide
      $pipe4 = "\\\\.\\pipe\\" ascii wide
      $pipe5 = "spoolss" ascii wide nocase
   condition:
      uint16(0) == 0x5A4D and
      filesize < 1MB and
      all of ($pipe*)
}
```

### Hunting Rules

#### PowerShell Named Pipe Client Connector

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1134.001 (Token Impersonation/Theft)
**Confidence:** LOW
**Rationale:** The weaker branch split out of the source file's combined "Named Pipe Impersonation Pattern" rule (see the Detection-tier rule above). `powershell` alone is a near-ubiquitous string, and `NamedPipeClientStream` is a .NET class name used by legitimate cross-process IPC scripts and monitoring tooling, not exclusively by this malware's documented PowerShell one-line connector (`New-Object IO.Pipes.NamedPipeClientStream(...)`. Neither string is a technique chokepoint on its own; kept as a Hunting lead for the wrapper's PowerShell-based fallback path rather than folded back into the Detection-tier rule.
**False Positives:** Legitimate PowerShell scripts and remoting/monitoring tools that use `System.IO.Pipes.NamedPipeClientStream` for IPC share both strings; expect co-fire with unrelated software.
**Deployment:** Broad endpoint/EDR scanning sweep, retroactive hunt across file shares; treat hits as triage candidates, not alerts.

```yara
rule Arsenal237_LPE_Named_Pipe_PS_Connector {
   meta:
      description = "Detects a PowerShell named-pipe client connector pattern (powershell.exe references co-occurring with the .NET NamedPipeClientStream class name), an alternate path to lpe.exe's native named-pipe token-impersonation API sequence. Broader and noisier than the native API sequence; treat as a triage lead, not an alert."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-lpe-exe-detections/"
      date = "2026-01-25"
      hash1 = "c4dda7b5c5f6eab49efc86091377ab08275aa951d956a5485665954830d1267e"
      family = "Arsenal-237-LPE-Wrapper"
      malware_type = "Privilege-Escalation-Wrapper"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "484ff6f5-ebbd-5e4b-8901-2f341ed1080b"
   strings:
      $ps = "powershell" ascii wide nocase
      $ps_pipe = "NamedPipeClientStream" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 1MB and
      $ps and $ps_pipe
}
```

#### Generic WMIC Process Creation Combination

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1047 (Windows Management Instrumentation)
**Confidence:** LOW
**Rationale:** Requires four strings (`wmic`, `process`, `call`, `create`) to co-occur, but three of the four are common English/programming words with little discriminating power on their own; only `wmic` narrows the candidate pool meaningfully. The combination is durable in the sense that it targets a fixed LOLBin command syntax rather than a renameable literal, but static string presence alone (versus an actual process-creation event) is a weak signal for this specific technique. Retained as a Hunting lead, matching the source file's own MEDIUM severity rating for this rule.
**False Positives:** Any binary that references WMIC administration (installers, RMM agents, system-inventory tools, documentation viewers) can contain all four strings without ever invoking `wmic process call create` itself.
**Deployment:** Broad endpoint/EDR scanning sweep, retroactive hunt across file shares; treat hits as triage candidates, not alerts.

```yara
rule Arsenal237_LPE_WMIC {
   meta:
      description = "Detects WMIC process-creation command fragments (wmic, process, call, create) co-occurring as embedded strings, a broad, campaign-agnostic lead for the 'wmic process call create' LOLBin process-creation technique this wrapper uses as one of its five escalation paths."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-lpe-exe-detections/"
      date = "2026-01-25"
      hash1 = "c4dda7b5c5f6eab49efc86091377ab08275aa951d956a5485665954830d1267e"
      family = "Arsenal-237-LPE-Wrapper"
      malware_type = "Privilege-Escalation-Wrapper"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "0d20a570-6dfd-5817-ace4-4f2608e98c0d"
   strings:
      $wmic1 = "wmic" ascii wide nocase
      $wmic2 = "process" ascii wide nocase
      $wmic3 = "call" ascii wide nocase
      $wmic4 = "create" ascii wide nocase
   condition:
      uint16(0) == 0x5A4D and
      filesize < 1MB and
      all of ($wmic*)
}
```

---

## Sigma Rules

### Detection Rules

#### Privilege Escalation via Token Impersonation

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1134.001 (Token Impersonation/Theft)
**Confidence:** HIGH
**Rationale:** Requires a process-access event targeting one of four SYSTEM-privileged processes (`winlogon.exe`, `lsass.exe`, `services.exe`, `csrss.exe`) with a token-query/duplicate `GrantedAccess` mask, paired with the `OpenProcessToken`/`DuplicateTokenEx`/`ImpersonateLoggedOnUser` call-trace sequence. Both selectors target fixed OS artifacts (the SYSTEM-holding process set and the Win32 token API sequence), not renameable literals, and the pairing is the technique itself, not a coincidental combination. Retiering fix: level recalibrated from `critical` to `high`. Gate 4 reserves `critical` for near-certain, effectively FP-free detections; the rule's own false-positives entry documents rare legitimate administrative-tool overlap, which caps it at `high`.
**False Positives:** Legitimate administrative or EDR tooling performing token operations against these processes (rare).
**Blind Spots:** A rewrite performing token theft via direct syscalls, or targeting a SYSTEM-privileged process outside this four-item list, evades this rule.
**Validation:** Replay the process-access plus API call-trace sequence against one of the four listed processes; must fire. A legitimate administrative tool accessing `services.exe` alone, without the paired API call trace, must NOT fire.
**Deployment:** Sysmon Event ID 10 (Process Access) telemetry, EDR process-access monitoring.

```yaml
title: Privilege Escalation via Token Impersonation (lpe.exe)
id: 41794664-1101-4fbf-a117-c8c1a1f7f473
status: experimental
description: >-
  Detects a token-impersonation privilege-escalation sequence: process-access
  events targeting a SYSTEM-privileged process (winlogon.exe, lsass.exe,
  services.exe, csrss.exe) paired with the OpenProcessToken, DuplicateTokenEx,
  and ImpersonateLoggedOnUser API call trace, characteristic of lpe.exe-class
  Arsenal-237 privilege-escalation wrappers.
references:
    - https://the-hunters-ledger.com/hunting-detections/arsenal-237-lpe-exe-detections/
author: The Hunters Ledger
date: '2026-01-25'
tags:
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1134.001
    - detection.emerging-threats
logsource:
    product: windows
    category: process_access
detection:
    selection_process_access:
        TargetImage|endswith:
            - '\winlogon.exe'
            - '\lsass.exe'
            - '\services.exe'
            - '\csrss.exe'
        GrantedAccess:
            - '0x1410'
            - '0x1000'
    selection_api:
        CallTrace|contains:
            - 'OpenProcessToken'
            - 'DuplicateTokenEx'
            - 'ImpersonateLoggedOnUser'
    condition: selection_process_access and selection_api
falsepositives:
    - Legitimate administrative or EDR tooling performing token operations against these processes (rare)
level: high
```

#### UAC Bypass via Ms-Settings Registry Hijack

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1548.002 (Bypass User Account Control)
**Confidence:** HIGH
**Rationale:** `fodhelper.exe` spawned directly by `reg.exe` is the process-creation signature of the ms-settings registry-hijack UAC bypass and is inherently rare regardless of what invoked `reg.exe`; that branch alone survives a rename of the malware binary. The paired `ParentImage|endswith '\lpe.exe'` branch is a renameable literal specific to this sample, but it rides alongside the durable `reg.exe` branch rather than standing alone, so the rule as a whole still clears the durability litmus. The rule's own description already documents that the companion registry-write event was dropped as a separate, uncorrelatable event under a different logsource; this rule detects the `fodhelper.exe` launch alone, which is independently a strong indicator.
**False Positives:** Legitimate software installation (extremely rare).
**Blind Spots:** A build that launches `fodhelper.exe` through an intermediary process other than `reg.exe` (for example a renamed copy of `lpe.exe` invoked through `cmd.exe`) evades the durable branch and falls back to the renameable `lpe.exe` literal only.
**Validation:** Launch `fodhelper.exe` with `reg.exe` as its immediate parent; must fire. A normal user-initiated `fodhelper.exe` launch from `explorer.exe` must NOT fire.
**Deployment:** Sysmon Event ID 1 (Process Creation) telemetry, EDR process-creation monitoring.

```yaml
title: UAC Bypass via Ms-Settings Registry Hijack (lpe.exe)
id: 78ff8cac-3e71-42c5-9fdf-acdb038ce94a
status: experimental
description: >-
  Detects fodhelper.exe launched with reg.exe or lpe.exe as its parent
  process, the process-creation signature of the ms-settings registry-hijack
  UAC bypass. fodhelper.exe is a Microsoft-signed LOLBIN rarely spawned by
  reg.exe or by an unsigned executable.
references:
    - https://the-hunters-ledger.com/hunting-detections/arsenal-237-lpe-exe-detections/
author: The Hunters Ledger
date: '2026-01-25'
tags:
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1548.002
    - detection.emerging-threats
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\fodhelper.exe'
        ParentImage|endswith:
            - '\reg.exe'
            - '\lpe.exe'
    condition: selection
falsepositives:
    - Legitimate software installation (extremely rare)
level: high
```

#### Scheduled Task Created as SYSTEM

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1053.005 (Scheduled Task)
**Confidence:** HIGH
**Rationale:** `schtasks.exe` invoked with `/create`, `/ru`, and `SYSTEM` together, from a user account that is not itself SYSTEM or an administrator, is the exact command syntax needed to escalate via this LOLBin; a rename of the calling binary does not change what `schtasks.exe` requires on its own command line. Retiering fix: the source rule's `references:` field held a plain-text caveat ("Task names are likely randomized...") instead of a URL, which is a SigmaHQ field-type violation; the caveat has been moved into this Rationale/Blind Spots prose and `references:` now points to this detection page.
**False Positives:** System administrators manually creating SYSTEM tasks (should be reviewed); legitimate administrative scripts using `schtasks.exe`.
**Blind Spots:** Task names are likely randomized at runtime and are not hardcoded in the malware, so detection deliberately does not rely on any specific task name; a build that creates the task without the literal `/ru SYSTEM` parameter (for example via a different privilege-specification syntax) evades this rule.
**Validation:** Run `schtasks /create /tn <any> /ru SYSTEM` as a non-admin, non-SYSTEM user; must fire. The same command run by an account already in the `Administrators` group must NOT fire.
**Deployment:** Sysmon Event ID 1 (Process Creation) telemetry, EDR process-creation monitoring, Windows Security Event ID 4698.

```yaml
title: Scheduled Task Created as SYSTEM (lpe.exe)
id: 19fbc402-5876-4f9b-905b-b5452dc7d634
status: experimental
description: >-
  Detects scheduled task creation with SYSTEM privileges from a
  non-administrative process via direct use of schtasks.exe. Task names are
  likely randomized at runtime, so detection anchors on the /ru SYSTEM
  parameter rather than any specific task name.
references:
    - https://the-hunters-ledger.com/hunting-detections/arsenal-237-lpe-exe-detections/
author: The Hunters Ledger
date: '2026-01-25'
tags:
    - attack.privilege-escalation
    - attack.execution
    - attack.persistence
    - attack.t1053.005
    - detection.emerging-threats
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - '/create'
            - '/ru'
            - 'SYSTEM'
    filter_admin:
        User|contains:
            - 'SYSTEM'
            - 'Administrator'
    condition: selection and not filter_admin
falsepositives:
    - System administrators manually creating SYSTEM tasks (should be reviewed)
    - Legitimate administrative scripts using schtasks.exe
level: high
```

### Hunting Rules

#### Named Pipe Impersonation Attack

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1134.001 (Token Impersonation/Theft)
**Confidence:** MODERATE
**Rationale:** `spoolss` is the real Print Spooler named-pipe name, a fixed OS artifact rather than an attacker-chosen literal, so it survives a rename of the malware binary. Retiering fix: the source selector was `PipeName|contains: ['spoolss', 'pipe']`; the bare `pipe` branch is a near-unconstrained substring match (most legitimate named pipes contain the word "pipe") that would fire on routine, unrelated IPC activity with no discriminating value, so it has been removed, leaving `spoolss` as the sole selector, with the single-item list converted to a scalar per SigmaHQ convention. Retagged from the source's T1055.001 (Dynamic-link Library Injection, unrelated to named-pipe impersonation) to T1134.001, the technique this behavior actually maps to. PipeName-only telemetry cannot correlate which process or API sequence created the pipe, so even the tightened selector stays Hunting rather than Detection; pair with process-access telemetry (see the Detection-tier Token Impersonation rule above) for higher confidence.
**False Positives:** Legitimate Print Spooler activity on hosts with print services enabled (common).
**Deployment:** Sysmon Event ID 17/18 (Pipe Created/Connected) telemetry; correlate with process-access events on the same host for triage.

```yaml
title: Named Pipe Impersonation Attack (lpe.exe)
id: 3a0e534f-01ba-4ef6-bdac-99a3528c5f3b
status: experimental
description: >-
  Detects creation of a named pipe referencing the Print Spooler service pipe
  name (spoolss), used to stage a token-impersonation privilege-escalation
  attempt. PipeName-only telemetry cannot correlate which process or API
  sequence created the pipe, so this is a hunting lead rather than an alert;
  pair with process-access telemetry for higher confidence.
references:
    - https://the-hunters-ledger.com/hunting-detections/arsenal-237-lpe-exe-detections/
author: The Hunters Ledger
date: '2026-01-25'
tags:
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1134.001
    - detection.emerging-threats
logsource:
    product: windows
    category: pipe_created
detection:
    selection:
        PipeName|contains: 'spoolss'
    condition: selection
falsepositives:
    - Legitimate Print Spooler activity on hosts with print services enabled (common)
level: medium
```

#### WMIC Process Creation for Privilege Escalation

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1047 (Windows Management Instrumentation)
**Confidence:** MODERATE
**Rationale:** `wmic.exe` invoked with the `process call create` syntax is a fixed, durable LOLBin command pattern, and the user filter narrows out the accounts that would legitimately run it as an administrative action. The pattern is also common in legitimate remote-administration and deployment tooling, so it does not clear the Detection bar on precision even though it is level-honest already at `medium`; carried forward as Hunting.
**False Positives:** Legitimate administrative scripts and RMM/deployment tooling using WMIC (common); review context before treating a hit as malicious.
**Deployment:** Sysmon Event ID 1 (Process Creation) telemetry, EDR process-creation monitoring.

```yaml
title: WMIC Process Creation for Privilege Escalation (lpe.exe)
id: 7e7d8199-93c4-4f53-ad05-84c4f3a08a96
status: experimental
description: >-
  Detects WMIC being used to create a process via the "process call create"
  syntax from a non-administrative, non-SYSTEM user, a known LOLBin technique
  for local or remote process creation that this wrapper uses as one of its
  five escalation paths. WMIC process creation is also common in legitimate
  remote-administration and deployment tooling, so this is a hunting lead
  rather than an alert.
references:
    - https://the-hunters-ledger.com/hunting-detections/arsenal-237-lpe-exe-detections/
author: The Hunters Ledger
date: '2026-01-25'
tags:
    - attack.execution
    - attack.t1047
    - detection.emerging-threats
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\wmic.exe'
        CommandLine|contains|all:
            - 'process'
            - 'call'
            - 'create'
    filter_admin:
        User|contains:
            - 'SYSTEM'
            - 'Administrator'
    condition: selection and not filter_admin
falsepositives:
    - Legitimate administrative scripts and RMM/deployment tooling using WMIC (common)
level: medium
```

---

## Coverage Gaps

### Retiering Fixes Applied

- **Sigma "Privilege Escalation via Token Impersonation" level recalibrated from `critical` to `high`.** Gate 4 reserves `critical` for near-certain, effectively FP-free detections; the rule's own false-positives entry documents rare legitimate admin-tool overlap, which caps it at `high`.
- **YARA "Named Pipe Impersonation Pattern" split into two rules.** The source rule's condition was `all of ($pipe*) or ($ps and $ps_pipe)`; the `$ps`/`$ps_pipe` branch (bare `powershell` plus the .NET class name `NamedPipeClientStream`) is far broader than the native API-sequence branch, and an OR condition inherits the weakest branch's precision. Split into `Arsenal237_LPE_Named_Pipe_Token_Theft` (Detection, the native API sequence) and `Arsenal237_LPE_Named_Pipe_PS_Connector` (Hunting, the PowerShell fallback) so the strong branch keeps Detection-grade confidence instead of both being dragged to Hunting.
- **MITRE retag: T1055.001 → T1134.001 for named-pipe impersonation, applied to the YARA rule.** T1055.001 is Dynamic-link Library Injection, unrelated to named-pipe impersonation. The companion Sigma rule in the source file had already self-corrected this tag with an explanatory note; the YARA rule's meta `technique` field had not, and is now aligned to the same fix.
- **Sigma "Named Pipe Impersonation Attack" selector tightened.** The source selector was `PipeName|contains: ['spoolss', 'pipe']`. The bare `pipe` branch matches almost any named pipe (the word "pipe" is common in legitimate pipe-naming conventions) and adds no discriminating value; removed, leaving `spoolss` (the real Print Spooler pipe name) as the sole, scalar selector.
- **Sigma "Scheduled Task Created as SYSTEM" `references:` field corrected.** The source used `references:` to hold a plain-text caveat about task-name randomization instead of a URL, a SigmaHQ field-type violation. The caveat is preserved in this file's Rationale/Blind Spots prose; `references:` now points to this detection page.
- **Two over-escaped backslash strings fixed (YARA).** `Arsenal237_LPE_UAC_Bypass`'s registry-path string and the named-pipe rule's pipe-prefix string were each written with double the correct number of backslash characters in the source file (verified by exact byte count, not visual read). As published, both strings would compile to require *double* the real number of literal backslashes at each separator, so neither would ever match the actual embedded text a real sample contains (single backslashes between registry-path components; `\\.\pipe\` for the named-pipe prefix, confirmed against the single-escaped form of the same strings in the companion IOC feed's JSON). Both are corrected to the properly-escaped single-backslash form. As originally published, these two strings were dead weight in their respective `all of` conditions: harmless to compilation, but incapable of ever matching.

### Prior Consolidation: Multi-Technique Correlation Rule

A prior pass already removed a sixth Sigma rule ("Multi-Technique Privilege Escalation Sequence") that was intended to fire on 2-of-3 privilege-escalation techniques within 60 seconds, a cross-logsource correlation base Sigma cannot express. After removing the unsupported aggregation syntax it collapsed to a plain `schtasks /ru SYSTEM` match already covered, more precisely, by the Scheduled Task Created as SYSTEM rule above, so it was not carried forward. The individual techniques remain covered by the five rules in each language above; a full multi-technique sequence is best reconstructed with SIEM-side correlation across those rules. No other duplicate or near-duplicate rules were found in this file during this retiering pass.

### Atomics: Already in the IOC Feed

The SHA256/MD5/SHA1 hash and the distribution IP (`109.230.231.37`) were never expressed as standalone YARA/Sigma rules in this file; there is nothing to route. Both are already present in [`arsenal-237-lpe-exe.json`](/ioc-feeds/arsenal-237-lpe-exe.json) (`file_hashes` and `network_indicators.distribution_infrastructure`).

### No Suricata Coverage: No Network Behavior of Its Own

lpe.exe is a local privilege-escalation wrapper with no command-and-control channel of its own; its only network association is the distribution-point IP where it, `killer.dll`, and the rest of the Arsenal-237 toolkit were hosted, already captured as a feed atomic above. No protocol, URI, or header structure exists from which to build a Suricata signature.

### Downstream Payload Out of Scope

lpe.exe wraps and launches another executable (typically `killer.dll` or `killer.exe`, and documented usage also references `enc_*.exe`) with the SYSTEM privileges it obtains. Detection coverage for that downstream payload is out of scope for this file, which covers only the wrapper's own five escalation techniques.

### What Would Strengthen Coverage

- **Goodware-corpus validation** for the two Hunting-tier YARA rules (the PowerShell connector and the generic WMIC combination) against a broad clean-software corpus would sharpen their false-positive profiles beyond the qualitative assessment above.
- **Process-correlated pipe telemetry** (pairing the `spoolss` pipe-created event with a subsequent `ImpersonateNamedPipeClient`-class API call from the same process) would let the Named Pipe Impersonation Attack Sigma rule clear the Detection bar instead of remaining a PipeName-only Hunting lead.
- **A captured `killer.dll`/`killer.exe` sample** would allow a companion detections file for the payload this wrapper launches.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
