---
title: "Detection Rules — HijackLoader / Penguish / Rugmi to AsyncRAT Multi-Vector Phishing Campaign"
date: '2026-05-06'
layout: post
permalink: /hunting-detections/opendirectory-62-60-237-100-20260506-detections/
thumbnail: /assets/images/cards/opendirectory-62-60-237-100-20260506.png
hide: true
---

**Campaign:** OpenDirectory-MultiFamily-MaaS-62.60.237.100
**Date:** 2026-05-06
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/opendirectory-62-60-237-100-20260506/

---

## Detection Coverage Summary

Multi-stage commodity loader chain (HijackLoader / Penguish / Rugmi) delivering an injected .NET AsyncRAT-class RAT, staged from an open directory at `62.60.237[.]100` (AEZA Finland, AS210644). Operator is Russian-speaking (HIGH confidence), operates as a MaaS customer with an 8-vector parallel phishing delivery kit. C2 beacons to `185.241.208[.]129:56167` over TLSv1 (AS210558 — 1337 Services GmbH, Poland; Spamhaus DROP listed).

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 4 | 1 | T1027.009, T1204.002, T1036.005, T1574.001, T1055.012, T1027, T1027.013, T1620, T1480, T1218.014, T1059.005, T1059.007, T1105 | 0 |
| Sigma | 2 | 7 | T1218.014, T1059.005, T1059.007, T1685, T1059.001, T1204.002, T1574.001, T1055.012, T1036.005, T1053.005, T1112, T1480 | 0 |
| Suricata | 1 | 0 | T1071.001, T1573.001, T1571 | 3 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchors:**
- The stage-3 loader's API-hash table (X65599/`RtlHashUnicodeString` polynomial resolving `kernel32`/`ntdll` calls by hash) — a technique chokepoint the loader must execute to function, requiring 3-of-5 matching hash constants (YARA Detection).
- `mmc.exe` spawning a script interpreter (`mshta.exe`/`rundll32.exe`/`powershell.exe`/etc.), especially paired with an `Add-MpPreference`/`ExclusionPath` command line — an abnormal MMC process-tree chokepoint that is family-agnostic and survives any operator rebrand (Sigma Detection).
- JA3 `07af4aa9e4d215a5ee63f9a0a277fbe3`, listed on Abuse.ch SSLBL for AsyncRAT/zgRAT — destination-IP-independent, fires even if the operator migrates C2 infrastructure (Suricata Detection).

**Atomics routed to the IOC feed:** three of the original four Suricata rules keyed solely on a single hard-coded C2/staging IP (`185.241.208.129`, `109.120.137.6`) or a single campaign-unique Mega.io bucket URI (`s3.g.s4.mega.io/aileqac3yep7oqdhygjpberqqnk2zrnhck2lx/busket/`) — removing the literal in each case leaves either an unrelated generic TLS-version check or a match against ordinary legitimate traffic (a generic PuTTY filename, or all Mega.io cloud-storage traffic). All three values were already present in [`opendirectory-62-60-237-100-20260506-iocs.json`](/ioc-feeds/opendirectory-62-60-237-100-20260506-iocs.json) from the original analysis — no feed edits were required. See Coverage Gaps for the full accounting, including one YARA rule that was cut for a precision defect (it fired on genuine, unmodified vendor software) and salvaged as a new Sigma hunting rule.

---

## YARA Rules

### Detection Rules

#### ExceptionHandler.dll Plowshare Dispatcher

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1574.001 (DLL Side-Loading), T1055.012 (Process Hollowing), T1027 (Obfuscated Files)
**Confidence:** HIGH
**Rationale:** Anchored on the operator's own PDB path (`I:\CompanySource\Plowshare\...`) — a build-toolchain artifact that persists across the same developer's build iterations, unlike a per-wave config value. A PDB path is a canonical Detection-tier YARA anchor. Two bespoke dropped-payload filenames and a covert-IPC pipe name serve as independent corroborating anchors, so no single string alone carries the rule.
**False Positives:** None known — the drive-letter-rooted PDB path, the bespoke filenames (`networkspec17.log`, `shadermgr93.rc`), and the pipe name (`WondershareCrashServices`) have no plausible legitimate collision.
**Blind Spots:** A rebuild from a different developer machine/project-folder structure evades the PDB anchor; both payload filenames and the pipe name would need to change together to evade the remaining branches.
**Validation:** Scan the ExceptionHandler.dll dropped artifact — the PDB path must match; a genuine Wondershare-signed Plowshare crash reporter (carrying Wondershare's own build PDB path) must NOT fire.
**Deployment:** Endpoint AV/EDR on-access scanner, memory scanner, file-system hunting.

```yara
/*
   Yara Rule Set
   Identifier: HijackLoader / Penguish / Rugmi — AsyncRAT Campaign Detection Suite
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule MALW_HijackLoader_ExceptionHandler_Plowshare_Dispatcher {
   meta:
      description = "Detects operator-modified Wondershare Plowshare crash reporter (ExceptionHandler.dll) used as the HijackLoader stage-1 dispatcher, identified by its operator PDB path, bespoke payload filenames, and Wondershare-mimicking named pipe"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/"
      date = "2026-05-06"
      hash1 = "a3d0a9c71be732cdaafc7c1a9ef00c2a5a01e93b4a29c8944f8ea14a79f52ce0"
      family = "HijackLoader"
      malware_type = "Loader"
      campaign = "OpenDirectory-MultiFamily-MaaS-62.60.237.100"
      id = "725513e0-5d7a-5bd3-9bb6-1283484913d7"
   strings:
      $pdb        = "I:\\CompanySource\\Plowshare\\Src\\Symbol\\Release\\ExceptionHandler.pdb" ascii
      $payload1   = "networkspec17.log" ascii wide
      $payload2   = "shadermgr93.rc" ascii wide
      $pipe       = "WondershareCrashServices" ascii wide
      $codename   = "Plowshare" ascii fullword
   condition:
      uint16(0) == 0x5A4D and
      filesize < 2MB and
      ($pdb or ($payload1 and $payload2 and $pipe) or ($codename and $pipe))
}
```

#### networkspec17.log PNG-IDAT Carrier

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1027.013 (Encrypted/Encoded File), T1027.009 (Embedded Payloads)
**Confidence:** HIGH
**Rationale:** Anchored on the loader's own custom 4-byte framing marker at absolute file offset 0 — a constant baked into the stage-3 carrier format's decode routine, not a per-wave build-config value. The marker is required in every condition branch, so no OR-path bypasses it.
**False Positives:** None known — no legitimate file format begins with this 4-byte marker (the genuine PNG signature is entirely different).
**Blind Spots:** A rebuild of the loader's carrier-encoding scheme (new marker or XOR key) evades this rule; it targets this loader family's stage-3 carrier format specifically, not the decoded payload.
**Validation:** Scan a networkspec17.log-equivalent carrier — the marker at offset 0 must match; a legitimate PNG file must NOT fire.
**Deployment:** File-system hunting, email gateway scanning, endpoint memory scanner.

```yara
rule MALW_HijackLoader_NetworkSpec17_IDAT_Carrier {
   meta:
      description = "Detects the HijackLoader stage-3 payload carrier file networkspec17.log by its operator-distinctive PNG-IDAT framing header: a 4-byte chunk-type marker at offset 0 and a 4-byte XOR key at offset 4, both baked into the loader's own multi-layer encoding scheme (PNG IDAT framing + 4-byte XOR + LZNT1 chunked decompression)"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/"
      date = "2026-05-06"
      hash1 = "7e2000ceb89574fe95e819f5f47da346119b666b7f64e8b5b01e5152e37d76cf"
      family = "HijackLoader"
      malware_type = "Loader"
      campaign = "OpenDirectory-MultiFamily-MaaS-62.60.237.100"
      id = "ad9cb357-4a89-549a-8d23-7b7116a64f46"
   strings:
      $idat_marker   = { C6 A5 79 EA }
      $xor_key       = { E1 D5 B4 A2 }
      $idat_sentinel = { 49 44 41 54 }
      $iend_sentinel = { 49 45 4E 44 }
      $filename      = "networkspec17.log" ascii wide
   condition:
      filesize < 10MB and
      $idat_marker at 0 and
      ($xor_key at 4 or ($idat_sentinel and $iend_sentinel) or ($filename and $xor_key))
}
```

#### pe_03 HijackLoader Stage-3 Loader (API Hash Table)

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1620 (Reflective Code Loading), T1055.012 (Process Hollowing), T1480 (Execution Guardrails), T1027 (Obfuscated Files)
**Confidence:** HIGH
**Rationale:** Anchored on the loader's API-hash table — deterministic hash constants (X65599/`RtlHashUnicodeString` polynomial) applied to the specific Windows API names the loader must resolve to function. This is a technique chokepoint the loader cannot avoid executing, not an operator-editable config value, and the rule requires 3 of 5 matching constants.
**False Positives:** None known — hash DWORDs for this specific hash algorithm and API-name set have no known legitimate collision; the 3-of-5 threshold rules out coincidental single-value matches.
**Blind Spots:** A rebuild that changes the hash algorithm or the resolved API set evades this rule; the Qihoo-PDB fallback branch (paired with only 1 hash match) is weaker and included only as a corroborating signal.
**Validation:** Scan pe_03 or a sibling stage-3 loader build — at least 3 of 5 hash DWORDs must match; unrelated PE files using a different hash-based API resolution scheme must NOT fire.
**Deployment:** Endpoint AV/EDR, memory scanner, sandbox detonation.

```yara
rule MALW_HijackLoader_Penguish_Stage3_Loader_PE {
   meta:
      description = "Detects the HijackLoader/Penguish/Rugmi stage-3 loader PE (pe_03) by its API hash table values using the X65599/RtlHashUnicodeString polynomial to resolve kernel32/ntdll APIs at runtime with an empty import table"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/"
      date = "2026-05-06"
      hash1 = "68fb61225b457172368d43af7ec2afe48f59404089d095584944edbfd0171feb"
      family = "HijackLoader"
      malware_type = "Loader"
      campaign = "OpenDirectory-MultiFamily-MaaS-62.60.237.100"
      id = "046a3e85-6250-5fa4-93aa-55f66ce22d4c"
   strings:
      $hash_gcnw  = { BB 5A B3 CB }
      $hash_zqip  = { 8E 04 7B 9C }
      $hash_rdb   = { 2D B6 03 B4 }
      $hash_zde   = { 32 FB 7E 6A }
      $hash_zqsi  = { D2 E6 69 AE }
      $qihoo_pdb  = "C:\\vmagent_new\\bin\\joblist\\881673\\out\\Release\\PromoUtil.pdb" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      (
         (3 of ($hash_*)) or
         ($qihoo_pdb and 1 of ($hash_*))
      )
}
```

#### Multi-Vector Lure: GrimResource MSC + Mega.io Payload Fetch

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1218.014 (MMC), T1059.005 (Visual Basic), T1059.007 (JavaScript), T1105 (Ingress Tool Transfer)
**Confidence:** HIGH
**Rationale:** Anchored on the GrimResource technique's own `res://apds.dll/redirect.html` XSL-redirect abuse marker — a publicly-documented technique signature invariant to this COM-object abuse chain, not an operator-chosen literal. The Mega.io staging-bucket branch (already IOC-feed-tracked) gives independent coverage of the campaign's macro-document lures, which fetch from the same bucket without using GrimResource.
**False Positives:** None known — the GrimResource resource string has no legitimate use case inside an .msc file.
**Blind Spots:** A different code-execution technique inside an .msc file (not GrimResource) evades entirely; a rebuild targeting a different COM redirect endpoint evades.
**Validation:** Scan a GrimResource-weaponized .msc file — the resource string must match; a legitimate/benign .msc administrative console file must NOT fire.
**Deployment:** Email gateway, endpoint file-system scanning, web proxy URL inspection.

```yara
rule MALW_HijackLoader_MultiVector_Lure_GrimResource_MSC {
   meta:
      description = "Detects MSC GrimResource weaponized files used in the HijackLoader campaign via the res://apds.dll/redirect.html XSL-redirect abuse pattern embedded in an MMC snap-in .msc file, or via the campaign's Mega.io staging bucket path paired with a scripting/obfuscation corroborator (covers macro-document lures fetching from the same bucket)"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/"
      date = "2026-05-06"
      hash1 = "3480d0478d35d8a12331b97769401e16e4956bdc24b9a7175ae08e2c9e9acf8f"
      family = "HijackLoader"
      malware_type = "Loader"
      campaign = "OpenDirectory-MultiFamily-MaaS-62.60.237.100"
      id = "6a42e21f-3581-54ab-b461-f64733fdb4af"
   strings:
      $grimres    = "res://apds.dll/redirect.html" ascii wide nocase
      $js_eval    = "javascript:eval(" ascii wide nocase
      $mmc_root   = "<MMC_ConsoleFile" ascii wide
      $mega_path  = "aileqac3yep7oqdhygjpberqqnk2zrnhck2lx/busket/" ascii wide nocase
      $macro_rev  = "[array]::Reverse($" ascii wide
   condition:
      filesize < 5MB and
      (
         $grimres or
         ($mega_path and ($macro_rev or $js_eval or $mmc_root))
      )
}
```

### Hunting Rules

#### Inno Setup Pascal Anti-Triage Wrapper

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1027.009 (Embedded Payloads), T1204.002 (Malicious File), T1036.005 (Match Legitimate Name or Location)
**Confidence:** MODERATE
**Rationale:** Every anchor (the campaign AppId GUID, the `Apophyge`/`Veteran` Inno Setup script codenames, and the renamed loader filename `CrystSupervisor32.exe`) is an Inno Setup build-script value the operator sets in a single `.iss` line and can change on any rebuild — the same durability class as a mutex or drop-path chosen per build, not a technique-level invariant (this is why it is demoted from the original Detection classification). The anti-triage *technique* itself (Pascal Script `InitializeSetup`→`WinExec`→return `False`) is separately covered behaviorally by the Sigma process-tree rule below.
**False Positives:** None known against unrelated legitimate software today — but the same build-specific anchors are exactly what the operator is most likely to change in the next campaign wave, which is the reason for the Hunting tier rather than a precision concern.
**Deployment:** Endpoint AV/EDR on-access scanner, gateway sandboxing, email attachment scanning. Treat hits as leads for this specific build wave and its direct siblings, not a durable family detector.

```yara
rule MALW_HijackLoader_InnoSetup_AntiTriage_Wrapper {
   meta:
      description = "Detects this build wave of the HijackLoader Inno Setup 6.5+ wrapper using the Pascal Script InitializeSetup->WinExec->return False anti-triage pattern, identified by the operator codenames Apophyge (AppName), Veteran (DefaultDirName), the campaign AppId GUID, and the renamed loader filename CrystSupervisor32.exe"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/"
      date = "2026-05-06"
      hash1 = "1afbe5d960af45832539b11e92a09b808f0c3868ab437a7ef1b5d1bd5e16d0c3"
      family = "HijackLoader"
      malware_type = "Loader"
      campaign = "OpenDirectory-MultiFamily-MaaS-62.60.237.100"
      id = "2bfaff71-9aa6-5e70-a180-cce9faaa32f2"
   strings:
      $inno_magic = { 49 6E 6E 6F 53 65 74 75 70 20 53 65 74 75 70 20 44 61 74 61 }
      $appid      = "{1F2952E4-FC07-4482-B9E6-E795507DA7D2}" ascii wide
      $appname    = "Apophyge" ascii wide
      $dirname    = "Veteran" ascii wide
      $loader     = "CrystSupervisor32.exe" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 20MB and
      $inno_magic and
      (($appid) or ($appname and $dirname) or ($loader and ($appid or $appname)))
}
```

---

## Sigma Rules

### Detection Rules

#### HijackLoader GrimResource MMC Spawning Mshta or Rundll32 for Payload Execution

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1218.014 (MMC), T1059 (Command and Scripting Interpreter)
**Confidence:** HIGH
**Rationale:** `mmc.exe` spawning a script/command interpreter is a family-agnostic technique chokepoint for GrimResource — MMC must spawn something to execute the XSL-redirected payload, so this signal survives any operator rebrand and depends on no campaign-specific filename or codename. Corrected from the original: the ATT&CK Coverage previously over-claimed VBScript/JavaScript sub-techniques the selection logic does not actually distinguish (the Image list mixes `mshta.exe`, `rundll32.exe`, and generic shells); retagged to the parent T1059 alongside T1218.014.
**False Positives:** Custom enterprise MMC snap-ins that legitimately spawn PowerShell or cmd.exe for administrative actions (rare — verify the specific MSC file source and the spawned command line for administrative context); the filter excludes the four most common legitimate `.msc` snap-ins.
**Blind Spots:** An operator technique change that avoids spawning a new process (in-process script execution) evades; the legitimate-snap-in filter list is not exhaustive.
**Validation:** Detonate a GrimResource-weaponized `.msc` file — `mmc.exe` must spawn one of the listed interpreters; opening `eventvwr.msc`/`compmgmt.msc`/`devmgmt.msc`/`diskmgmt.msc` normally must NOT fire.
**Deployment:** EDR process-creation monitoring, SIEM Sysmon EID 1.

```yaml
title: HijackLoader GrimResource MMC Spawning Mshta or Rundll32 for Payload Execution
id: b81e4c29-53a7-4d02-8f9e-2a7d6c4b1e35
status: experimental
description: >-
  Detects MMC (Microsoft Management Console) spawning mshta.exe, rundll32.exe,
  or a generic script/command interpreter as part of the GrimResource MSC file
  weaponization technique used by the HijackLoader campaign. The observed MSC
  files (1.msc, Price2.pdf.msc, MSCFile.msc) use the res://apds.dll/redirect.html
  XSL redirect to execute javascript:eval(), which launches an interpreter from
  mmc.exe as a parent. This parent-child relationship is abnormal — legitimate
  MMC snap-ins do not spawn these interpreters.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/
author: The Hunters Ledger
date: 2026-05-06
tags:
    - attack.execution
    - attack.stealth
    - attack.t1218.014
    - attack.t1059
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\mmc.exe'
        Image|endswith:
            - '\mshta.exe'
            - '\rundll32.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
    filter_legitimate_mmc:
        CommandLine|contains:
            - 'eventvwr.msc'
            - 'compmgmt.msc'
            - 'devmgmt.msc'
            - 'diskmgmt.msc'
    condition: selection and not filter_legitimate_mmc
falsepositives:
    - >-
      Custom enterprise MMC snap-ins that legitimately spawn PowerShell or
      cmd.exe for administrative actions (rare — verify the specific MSC
      file source and the spawned command line for administrative context)
    - Security monitoring tools that invoke MMC snap-ins programmatically
level: high
```

#### HijackLoader GrimResource MMC Spawning PowerShell Adding Defender Exclusion

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1218.014 (MMC), T1685 (Disable or Modify Tools), T1059.001 (PowerShell)
**Confidence:** HIGH
**Rationale:** Requires TWO independently-anchored, family-agnostic technique signals to co-occur: the abnormal `mmc.exe`→shell parent-child chokepoint (shared with the rule above) AND Defender-exclusion-manipulation command-line content. Neither clause depends on any campaign-specific filename or codename, so the combination survives an operator rebrand. The original file's "T1685 (Disable or Modify Tools)" citation is correct as-is — current ATT&CK data separates a "Defense Impairment" tactic (TA0112) from the legacy Impair Defenses numbering, with T1685 as the present-day ID for this sub-technique; the tag is retained unchanged.
**False Positives:** Automated endpoint management solutions that use MMC-based snap-ins to deliver Defender configuration changes (verify via change-management records); security administrators who open MMC snap-ins and separately run PowerShell to manage Defender exclusions in the same session are extremely unlikely to reproduce this exact process-parent relationship (MMC does not propagate as the parent for manually opened PowerShell windows).
**Blind Spots:** An operator technique that disables Defender via a non-PowerShell/cmd mechanism (direct registry write, WMI) evades the command-line clause; an operator that drops the MMC-chain entirely (different initial-access vector) evades both clauses.
**Validation:** Detonate the Tier-2 GrimResource `.msc` chain — both the process chain and the `Add-MpPreference`/`ExclusionPath` command line must be present; an unrelated legitimate PowerShell Defender-configuration session (not parented by `mmc.exe`) must NOT fire.
**Deployment:** EDR process-creation monitoring, SIEM Sysmon EID 1, PowerShell-Operational EID 4104.

```yaml
title: HijackLoader GrimResource MMC Spawning PowerShell Adding Defender Exclusion
id: e73a1b48-c926-4e85-9fd2-6b8d3e4a7c19
status: experimental
description: >-
  Detects the HijackLoader GrimResource MSC file execution chain where mmc.exe
  spawns cmd.exe or powershell.exe that subsequently invokes Add-MpPreference
  with -ExclusionExtension or -ExclusionPath to disable Windows Defender
  real-time protection for the operator's persistence directory. In the
  observed campaign, the MSC files execute XSL -> VBScript -> PowerShell to
  add C:\ProgramData\adv_ctrl to Defender exclusions before dropping the
  loader chain. This mmc.exe -> PowerShell -> Add-MpPreference combination is
  not a legitimate administrative pattern.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/
author: The Hunters Ledger
date: 2026-05-06
tags:
    - attack.stealth
    - attack.execution
    - attack.defense-impairment
    - attack.t1218.014
    - attack.t1059.001
    - attack.t1685
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\mmc.exe'
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\cmd.exe'
    selection_cmdline:
        CommandLine|contains:
            - 'Add-MpPreference'
            - 'ExclusionExtension'
            - 'ExclusionPath'
            - 'Set-MpPreference'
    condition: selection_parent and selection_cmdline
falsepositives:
    - >-
      Security administrators who open MMC snap-ins and then separately run
      PowerShell to manage Defender exclusions in the same session (extremely
      unlikely as a process-parent relationship: MMC does not propagate as
      the parent for manually opened PowerShell windows)
    - Automated endpoint management solutions that use MMC-based snap-ins to
      deliver Defender configuration changes (verify via change-management records)
level: high
```

### Hunting Rules

#### HijackLoader Inno Setup Wrapper Spawning CrystSupervisor32 and WVault Process Chain

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1036.005 (Match Legitimate Name or Location), T1574.001 (DLL Side-Loading)
**Confidence:** HIGH (for this build wave)
**Rationale:** All three selectors hinge entirely on `Image|endswith` matching this wave's operator-renamed filenames (`CrystSupervisor32.exe`, `WVault.exe`) — precisely the pattern the tiering standard names as disqualifying for Detection ("does not hinge on `Image|endswith: \Client.exe`"). The `is-*.tmp\` Inno Setup extraction path is common to every Inno Setup installer, legitimate or malicious, and adds no discrimination on its own. Demoted from the original Detection classification for this reason.
**False Positives:** Reused only if an unrelated benign actor coincidentally adopts these exact renamed filenames (very unlikely); genuine Wondershare/Qihoo software runs under the original filenames (`SlideShowEditor.exe` / `PromoUtil.exe`), not these renamed ones.
**Deployment:** EDR process-creation monitoring, SIEM Sysmon EID 1; treat hits as leads for this build wave, not a durable family detector.

```yaml
title: HijackLoader Inno Setup Wrapper Spawning CrystSupervisor32 and WVault Process Chain
id: 3a7f1e92-bb04-4d85-9c3e-f6a820d14c73
status: experimental
description: >-
  Detects the HijackLoader/Penguish/Rugmi loader chain initiated by an Inno
  Setup wrapper using the Pascal Script InitializeSetup->WinExec->return
  False anti-triage technique. The wrapper drops and immediately launches
  CrystSupervisor32.exe (renamed genuine Wondershare SlideShowEditor.exe)
  from a temporary is-*.tmp directory. The chain continues through
  WVault.exe (renamed signed Qihoo 360 PromoUtil.exe) used as the hollow
  host for an injected .NET AsyncRAT-class RAT. The installer exits
  silently with no wizard UI, defeating sandboxes that wait for
  wizard-completion or [Run] section events.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/
author: The Hunters Ledger
date: 2026-05-06
tags:
    - attack.execution
    - attack.stealth
    - attack.t1036.005
    - attack.t1574.001
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection_crystsupervisor:
        Image|endswith: '\CrystSupervisor32.exe'
        ParentImage|contains: '\is-'
    selection_wvault_child:
        Image|endswith: '\WVault.exe'
        ParentImage|endswith: '\CrystSupervisor32.exe'
    selection_wvault_parent_temp:
        Image|endswith: '\WVault.exe'
        ParentCommandLine|contains: 'is-'
    condition: selection_crystsupervisor or selection_wvault_child or selection_wvault_parent_temp
falsepositives:
    - >-
      Legitimate Wondershare software installers that use CrystSupervisor32.exe
      as part of genuine DVD Creator or SlideShow Editor installation (verify
      Authenticode chain and parent install path matches official Wondershare
      installer, not a temp directory)
    - >-
      Qihoo 360 software installations where PromoUtil.exe is legitimately
      renamed (verify install path is under Program Files, not C:\ProgramData\)
level: medium
```

#### HijackLoader Covert IPC Named Pipe WondershareCrashServices Created

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1559 (Inter-Process Communication), T1036.005 (Match Legitimate Name or Location)
**Confidence:** HIGH
**Rationale:** The pipe name is a single operator-chosen literal compiled into `ExceptionHandler.dll` — the same durability class as a mutex name; a rebuild that renames the pipe fully evades this rule. The location-based exclusion filter (legitimate Wondershare paths) is a sound design pattern, but does not change the underlying literal's brittleness. Demoted from the original Detection classification for this reason.
**False Positives:** Legitimate Wondershare DVD Creator or SlideShow Editor installations where `ExceptionHandler.dll` creates this pipe from a genuine Program Files install path (filtered by the exclusion above); security testing tools that explicitly simulate Wondershare crash-reporter IPC.
**Deployment:** EDR named-pipe monitoring, SIEM Sysmon EID 17.

```yaml
title: HijackLoader Covert IPC Named Pipe WondershareCrashServices Created
id: 7c9d4b1a-e832-4f67-b52a-901c3d8e5f24
status: experimental
description: >-
  Detects creation of the named pipe \.\pipe\WondershareCrashServices used
  by the HijackLoader operator-modified ExceptionHandler.dll as a covert
  inter-process communication channel between loader stages. The pipe name
  mimics the legitimate Wondershare Breakpad crash-reporting IPC channel
  but is created by the operator's modified dispatcher DLL (PDB path
  I:\CompanySource\Plowshare\) to coordinate stage-1 through stage-3
  execution. Legitimate Wondershare software creates this pipe only from
  signed Wondershare binaries installed under Program Files.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/
author: The Hunters Ledger
date: 2026-05-06
tags:
    - attack.stealth
    - attack.execution
    - attack.t1036.005
    - attack.t1559
    - detection.emerging-threats
logsource:
    category: pipe_created
    product: windows
detection:
    selection:
        PipeName|endswith: '\WondershareCrashServices'
    filter_legit_wondershare:
        Image|startswith:
            - 'C:\Program Files\Wondershare\'
            - 'C:\Program Files (x86)\Wondershare\'
    condition: selection and not filter_legit_wondershare
falsepositives:
    - >-
      Legitimate Wondershare DVD Creator or SlideShow Editor installations
      where ExceptionHandler.dll creates this pipe from a genuine Program
      Files install path (filtered by the legit Wondershare path exclusion above)
    - Security testing tools that explicitly simulate Wondershare crash-reporter IPC
level: medium
```

#### HijackLoader Operator Persistence Directory adv_ctrl Created Under ProgramData

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1036.005 (Match Legitimate Name or Location)
**Confidence:** HIGH
**Rationale:** Five distinct operator codenames (`adv_ctrl`, `brokerbg`, `exttracer_net48`, `thread_adapter`, `Sulfathiazole`) are already documented as rotating across campaign variants — direct evidence that this literal set changes build-to-build. No naming convention beyond "an English dictionary word or phrase" was identified in the evidence that would support a more durable, structural rule; a sixth wave will very likely introduce a new, uncovered codename. Trimmed ATT&CK Coverage from the original, which also cited T1685 (Disable or Modify Tools) — a valid technique ID, but not reflected in the rule's own `tags:` and not actually matched by this rule's directory-creation-only detection logic (it observes no tool-disabling action); scoped to the technique the selection logic actually supports.
**False Positives:** Legitimate software installers that coincidentally use one of these five directory names (extremely unlikely — they are distinctive operator codenames, not standard Windows or common third-party path components); EDR agents or security tools using similarly named directories for internal state.
**Deployment:** EDR file-creation monitoring, SIEM Sysmon EID 11.

```yaml
title: HijackLoader Operator Persistence Directory adv_ctrl Created Under ProgramData
id: f2a85c3d-16b7-4e09-a74f-3c9b7d2e8a15
status: experimental
description: >-
  Detects creation of the operator-codename persistence directory adv_ctrl
  under C:\ProgramData\ or %APPDATA%\, used by the HijackLoader/Penguish/Rugmi
  campaign to stage the Crisp.exe side-load host and the WVault.exe hollow
  host, and to receive a Windows Defender real-time exclusion. The codename
  adv_ctrl is one of several operator persistence directory names observed
  across campaign variants (others: brokerbg, exttracer_net48,
  thread_adapter, Sulfathiazole) — a sixth wave will very likely introduce
  a new, uncovered codename.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/
author: The Hunters Ledger
date: 2026-05-06
tags:
    - attack.persistence
    - attack.stealth
    - attack.t1036.005
    - detection.emerging-threats
logsource:
    category: file_event
    product: windows
detection:
    selection_adv_ctrl:
        TargetFilename|contains: '\adv_ctrl\'
        TargetFilename|startswith:
            - 'C:\ProgramData\'
            - 'C:\Users\'
    selection_siblings:
        TargetFilename|contains:
            - '\brokerbg\'
            - '\exttracer_net48\'
            - '\thread_adapter\'
            - '\Sulfathiazole\'
        TargetFilename|startswith:
            - 'C:\ProgramData\'
            - 'C:\Users\'
    condition: selection_adv_ctrl or selection_siblings
falsepositives:
    - >-
      Legitimate software installers that coincidentally use a directory
      named adv_ctrl (extremely unlikely — this is a distinctive operator
      codename, not a standard Windows or common third-party path component)
    - Security tools or EDR agents using similarly named directories for internal state
level: medium
```

#### Legacy .job Scheduled Task File Created in Windows\Tasks (Autorunsc Blind Spot)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1053.005 (Scheduled Task)
**Confidence:** HIGH (technique-level); MODERATE that any single hit is this specific campaign
**Rationale:** Salvaged from the original two-branch rule, which required either the exact operator task name `watchermgmt` or a `ParentImage` match against this wave's renamed loader filenames — both rename-brittle, Robustness-1 anchors. Re-anchored on the technique's invariant primitive: any legacy `.job`-format scheduled-task file written to `C:\Windows\Tasks\` is itself a known autorunsc (Sysinternals Autoruns) enumeration blind spot in modern (post-Vista) Windows environments, since the current Task Scheduler API/UI writes XML tasks to `C:\Windows\System32\Tasks\` instead. This broadens coverage to any future wave of this campaign — or any unrelated actor — using the same legacy-format persistence trick, in exchange for the acknowledged legitimate-tooling collisions below (why this stays Hunting rather than Detection).
**False Positives:** Legacy scheduled tasks created by third-party software installers writing `.job` files to `C:\Windows\Tasks\` (uncommon in modern environments); enterprise management tools (SCCM, Ansible, PDQ) that use the legacy `.job` format for scheduled-task deployment.
**Deployment:** EDR file-creation monitoring, SIEM Sysmon EID 11, file-system hunting. Correlate hits against the process-tree/persistence-directory rules above for HijackLoader-specific attribution.

```yaml
title: Legacy .job Scheduled Task File Created in Windows Tasks Directory
id: 9e6b3f17-d452-4a08-c91d-8b7e2f5a3c06
status: experimental
description: >-
  Detects creation of any legacy .job-format scheduled task file under
  C:\Windows\Tasks\, a known blind spot in autorunsc (Sysinternals Autoruns)
  enumeration that does not parse this path by default. Modern Windows
  writes XML-format scheduled tasks to C:\Windows\System32\Tasks\ instead,
  so a write to the legacy path is uncommon outside of older third-party
  installers or enterprise deployment tooling. Observed in the
  HijackLoader/Penguish/Rugmi campaign as the watchermgmt.job persistence
  artifact, auto-migrated to an XML-format task by the Windows Schedule
  service within 90ms of the legacy write; broadened here to cover any
  legacy .job write regardless of task name or dropping process.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/
author: The Hunters Ledger
date: 2026-05-06
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.execution
    - attack.t1053.005
    - detection.emerging-threats
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|startswith: 'C:\Windows\Tasks\'
        TargetFilename|endswith: '.job'
    condition: selection
falsepositives:
    - >-
      Legacy scheduled tasks created by third-party software installers
      writing .job files to C:\Windows\Tasks\ (uncommon in modern
      environments — legacy .job format is rarely used by legitimate
      software after Windows Vista)
    - >-
      Enterprise management tools (SCCM, Ansible, PDQ) that use legacy
      .job format for scheduled task deployment (verify parent process chain)
level: medium
```

#### Office VBA Macro Security Disabled via Registry VBAWarnings Set to 1

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1112 (Modify Registry), T1204.002 (Malicious File)
**Confidence:** HIGH
**Rationale:** A genuinely durable, family-agnostic technique signal — `VBAWarnings=1` pre-conditioning is not tied to any HijackLoader-specific filename, GUID, or codename, and is used broadly by macro-malware campaigns generally. Kept at Hunting because legitimate IT administrators do set this value via registry or GPO, a real and non-trivial false-positive scenario the original rule already correctly acknowledged with `level: medium`. Trimmed ATT&CK Coverage from the original, which also cited T1685 (Disable or Modify Tools) — a valid technique ID, but not reflected in the rule's own `tags:` and a poor fit on the merits (T1685 covers disabling security tooling such as AV/EDR/logging, not an Office application security prompt); scoped to T1112 + T1204.002, which the selection logic and tags already reflect.
**False Positives:** Legitimate IT administrators deploying macro-enabled Office solutions who intentionally set `VBAWarnings=1` via GPO or management scripts (correlate with change-management records and the deploying user account); software developers testing Office VBA macros in a development environment; enterprise Office deployments that centrally manage macro trust settings (these should be deployed via GPO, not a per-user registry write from cmd.exe/PowerShell).
**Deployment:** SIEM Sysmon EID 13, EDR registry monitoring.

```yaml
title: Office VBA Macro Security Disabled via Registry VBAWarnings Set to 1
id: 4d2c8e5b-7f91-4b36-a82e-5d9c1f7e3a08
status: experimental
description: >-
  Detects a registry write setting
  HKCU\Software\Microsoft\Office\<version>\<app>\Security\VBAWarnings to 1
  (enable all macros without notification), which disables Office macro
  security controls. In the HijackLoader campaign, this is performed by
  Excel_2016_Windows.bat via PowerShell or a direct registry write, used
  to pre-condition victim workstations before delivering macro-enabled
  Office lure documents (Price5.docm, Price6.doc, NDA.doc, Price4.xls).
  The registry path covers both Office 16.0 (2016/2019/365) and 19.0
  variant keys.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/
author: The Hunters Ledger
date: 2026-05-06
tags:
    - attack.defense-impairment
    - attack.persistence
    - attack.execution
    - attack.t1112
    - attack.t1204.002
    - detection.emerging-threats
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\Security\VBAWarnings'
        TargetObject|contains:
            - '\Microsoft\Office\16.'
            - '\Microsoft\Office\19.'
        Details: 'DWORD (0x00000001)'
    condition: selection
falsepositives:
    - >-
      Legitimate IT administrators deploying macro-enabled Office solutions
      who intentionally set VBAWarnings=1 via GPO or management scripts
      (correlate with change management records and deploying user account)
    - Software developers testing Office VBA macros in a development environment
    - >-
      Enterprise Office deployments that centrally manage macro trust
      settings (these should be deployed via GPO, not per-user registry
      write from cmd.exe/PowerShell)
level: medium
```

#### HijackLoader WVault.exe Hollow-Host Launched Directly from Inno Setup Temp Directory

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1055.012 (Process Hollowing), T1036.005 (Match Legitimate Name or Location)
**Confidence:** HIGH (structural); the underlying per-host environment-variable IPC mechanism itself is not observable via this selector
**Rationale:** Retitled and trimmed from the original "per-host environment variable IPC pattern" framing. Sysmon does not log the per-host env-var IPC mechanism by default (the original rule's own documentation acknowledged this), so the `detection:` block never actually inspected environment-variable content — only process ancestry. Removed a reversed `CrystSupervisor32.exe`-child-of-`WVault.exe` branch with no support in the documented process tree (`WVault.exe` is always the descendant, never the ancestor, of `CrystSupervisor32.exe`), and removed a `WVault.exe`-child-of-`CrystSupervisor32.exe` branch that fully duplicated the Inno Setup process-tree rule above. What remains is the one genuinely distinct selector: `WVault.exe` launched with a parent image path containing `is-`, catching the direct `is-*.tmp\`→`WVault.exe` hollow-host launch — a shorter chain link than the process-tree rule's coverage. Still rename-brittle (Robustness 1), same as the process-tree rule.
**False Positives:** Legitimate Wondershare software chains where a similarly-launched process runs from an Inno Setup temp directory in genuine DVD Creator workflows (verify the file hashes and install path — the legitimate chain runs from Program Files, not `is-*.tmp` or `C:\ProgramData\adv_ctrl\`).
**Deployment:** EDR process-creation monitoring, SIEM Sysmon EID 1.

```yaml
title: HijackLoader WVault.exe Hollow-Host Launched Directly from Inno Setup Temp Directory
id: c45f9d2e-8b16-4c53-a97b-7e3f1d9c6b42
status: experimental
description: >-
  Detects WVault.exe (renamed, signed Qihoo 360 PromoUtil.exe used as a
  hollow host for an injected .NET AsyncRAT-class RAT) launched with a
  parent process image path containing the Inno Setup temp-extraction
  marker "is-", indicating a direct launch from an is-*.tmp\ directory
  rather than the campaign's persistent C:\ProgramData\adv_ctrl\ location.
  This is a distinct chain link from — not a duplicate of — the broader
  Inno Setup process-tree rule, which also covers WVault.exe as a direct
  child of CrystSupervisor32.exe.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/
author: The Hunters Ledger
date: 2026-05-06
tags:
    - attack.stealth
    - attack.privilege-escalation
    - attack.t1055.012
    - attack.t1036.005
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\WVault.exe'
        ParentImage|contains: 'is-'
    condition: selection
falsepositives:
    - >-
      Legitimate Wondershare software chains where a similarly-launched
      process runs from an Inno Setup temp directory in genuine DVD
      Creator workflows (verify the file hashes and install path: the
      legitimate chain runs from Program Files, not is-*.tmp or
      C:\ProgramData\adv_ctrl\)
level: medium
```

#### WVault.exe or Renamed Vendor Binary Executing from Non-Standard ProgramData Path

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1036.005 (Match Legitimate Name or Location)
**Confidence:** HIGH
**Rationale:** Net-new rule salvaged from a Cut YARA rule (`MALW_HijackLoader_WVault_HollowHost_NetRAT`, see Coverage Gaps) that attempted to fingerprint the genuine, unmodified Qihoo 360 PromoUtil.exe binary via its PDB path and VersionInfo company string — both present in every legitimate installation of Qihoo 360's own widely-deployed security software — plus a file-content string search for the deployment path `C:\ProgramData\WVault.exe`, which YARA content matching cannot actually evaluate (a file's own on-disk location is not part of its byte content). The underlying TTP — a genuine, validly-signed vendor binary renamed and dropped to a non-standard path to serve as an injection host, observed across 8+ campaigns since 2025 — is real and evidence-backed, but is fundamentally a filesystem/process property, not a file-content property, so it is re-anchored here on process-creation telemetry (`Image` name and path) instead.
**False Positives:** Rare legitimate portable or sideloaded applications that ship a binary literally named `WVault.exe` in a user-writable path (no known legitimate software uses this exact name); the primary residual risk is an unrelated malware family reusing the identical "rename a signed vendor binary, drop to ProgramData" masquerade pattern — a real but acceptable Hunting-tier collision, not a precision defect.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (process-creation telemetry); pair with the YARA API-hash-table rule (pe_03) above for HijackLoader-specific attribution before treating a hit as this campaign.

```yaml
title: WVault.exe or Renamed Vendor Binary Executing from Non-Standard ProgramData Path
id: 6684f300-fac8-4477-9d8a-c33b1c724155
status: experimental
description: >-
  Detects a process named WVault.exe executing from C:\ProgramData\, the
  non-standard drop path used by the HijackLoader/Penguish/Rugmi campaign
  for a renamed, genuine signed Qihoo 360 PromoUtil.exe used as a hollow
  host for injected .NET RAT payloads. WVault.exe is not a filename used
  by any known legitimate software; this cross-campaign TTP cluster
  (renaming a signed vendor binary as an injection host) has been observed
  across 8+ unrelated campaigns since 2025, so a hit should be correlated
  with family-specific indicators before attribution.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/
author: The Hunters Ledger
date: 2026-05-06
tags:
    - attack.stealth
    - attack.t1036.005
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\WVault.exe'
        Image|contains: '\ProgramData\'
    condition: selection
falsepositives:
    - >-
      Rare legitimate portable or sideloaded applications that ship a
      binary literally named WVault.exe in a user-writable path (no known
      legitimate software uses this exact name)
    - >-
      Other unrelated malware families that reuse the identical
      rename-a-signed-vendor-binary masquerade pattern
level: medium
```

---

## Suricata Signatures

### Detection Rules

#### AsyncRAT SSL JA3 Fingerprint 07af4aa9e4d215a5ee63f9a0a277fbe3

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1573.001 (Symmetric Cryptography)
**Confidence:** HIGH
**Rationale:** JA3 is a TLS-client fingerprint reflecting the RAT client's own TLS stack (library, cipher-suite, and extension ordering) — destination-IP-independent and unaffected by C2 infrastructure rotation. It is a documented AsyncRAT/zgRAT signature on Abuse.ch SSLBL, meaning it is not even unique to this one campaign; any host running the same RAT client build will match regardless of which C2 IP it is configured against. The strongest network-layer rule in this set.
**False Positives:** JA3 hash collisions across unrelated TLS client implementations that happen to share the same library/cipher-suite/extension configuration are a known general limitation of JA3 fingerprinting; the `count 3 / seconds 300` threshold plus the specific SSLBL-documented match keep this risk low in practice.
**Blind Spots:** A RAT-builder update that changes the underlying TLS library or cipher-suite ordering changes the JA3 hash and evades this rule; does not cover non-TLS C2 channels.
**Validation:** Replay a PCAP of this RAT's TLS handshake — the JA3 must match; ordinary enterprise TLS traffic must NOT match this specific hash.
**Deployment:** Network IDS on internal LAN segments, perimeter TAP; complements the destination-IP indicator carried in the IOC feed.

```suricata
alert tls $HOME_NET any -> any any (msg:"THL HijackLoader-Penguish-Rugmi AsyncRAT SSL JA3 Fingerprint 07af4aa9e4d215a5ee63f9a0a277fbe3 (RAT C2 Fleet Indicator)"; flow:established,to_server; ja3.hash; content:"07af4aa9e4d215a5ee63f9a0a277fbe3"; endswith; threshold:type limit,track by_src,count 3,seconds 300; classtype:trojan-activity; sid:1000001; rev:1; metadata:author The_Hunters_Ledger, date 2026-05-06, reference https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/;)
```

---

## Coverage Gaps

**Atomics routed to the IOC feed (3 of the original file's 4 Suricata rules).** Each keyed solely on one hard-coded literal with no behavioral qualifier surviving its removal — per the tiering rubric's routing test, these are IOC-feed entries, not rules:
- **C2 destination IP `185.241.208.129:56167`** — the only other condition in the original rule (`tls.version:1.0`) is a generic TLS-version flag that alone would match any TLSv1.0 connection anywhere. Already present in [`opendirectory-62-60-237-100-20260506-iocs.json`](/ioc-feeds/opendirectory-62-60-237-100-20260506-iocs.json) (`network_indicators.ipv4`), including the port and Spamhaus DROP context.
- **Staging-server IP `109.120.137.6`** — the accompanying URI content (`/PUTTY.exe`) is a common legitimate tool filename; without the IP restriction, a URI-only rule would false-positive against ordinary PuTTY download traffic. Already present in the feed (`network_indicators.ipv4`), including the co-hosted payload filenames (RDP.exe, RMS.exe, Glovo.exe).
- **Mega.io staging bucket `s3.g.s4.mega.io/aileqac3yep7oqdhygjpberqqnk2zrnhck2lx/busket/`** — without the 36-character bucket ID, the remaining host-only match (`s3.g.s4.mega.io`) would fire on all Mega.io cloud-storage traffic, a legitimate, widely used consumer service. Already present in the feed (`network_indicators.domains` and `network_indicators.urls`).

No feed edits were required — all three values were captured in the original analysis.

**Cut: WVault.exe Hollow-Host .NET RAT Injection (YARA).** The original rule (`MALW_HijackLoader_WVault_HollowHost_NetRAT`) attempted to fingerprint WVault.exe via a genuine Qihoo 360 PromoUtil.exe PDB path, a genuine Qihoo VersionInfo company string, and a file-content string search for the literal text of the binary's own deployment path. Two defects: (1) the primary branch (`$pdb_qihoo and $vs_company`) fires on any legitimate, unmodified installation of Qihoo 360's own widely-deployed security software, since both strings are present in every genuine copy of that binary — exactly the scenario the underlying IOC feed itself flags "DO NOT add to generic blocklists"; (2) the branches intended to scope detection to the malicious drop path (`$drop_path = "C:\ProgramData\WVault.exe"`) used YARA file-content string matching, which cannot observe a file's own on-disk location — a binary does not contain the text of the path it will later be copied to, so those branches would essentially never fire in practice. Net effect: the rule's only reliably-firing condition is a ubiquitous-benign match with no distinguishing filter, which fails the precision gate even for Hunting. Salvaged as the new Sigma Hunting rule "WVault.exe or Renamed Vendor Binary Executing from Non-Standard ProgramData Path," which re-anchors the same underlying TTP on process-creation telemetry (a property Sigma can observe and YARA cannot).

**Per-host execution guardrail (T1480) — hostname-keyed KDF.** The per-host hostname-keyed cipher (X65599 hash XOR `0xa1b2d3b4` as PRNG seed) is behavioral. The environment-variable name is deterministic per host but not predictable from a network/file sensor. A rule based on a fixed env-var name would miss all hosts except the analysis machine. **What would enable a rule:** a memory dump of WVault.exe mid-execution to recover the hostname-derived seed and env-var value, enabling a host-specific IOC.

**T1036.002 (Right-to-Left Override) — RTLO filename detection.** RTLO detection on filenames requires Unicode-aware filename inspection. Standard Sysmon EID 11 `TargetFilename` fields log the rendered (reversed) name, not the raw Unicode codepoint sequence. A YARA rule against the binary U+202E codepoint in filesystem metadata is possible but requires a Unicode-aware scanner configuration. **What would enable a rule:** NTFS alternate-data-stream or MFT-level parsing to detect U+202E in raw filename bytes before OS rendering.

**T1553.004 (Install Root Certificate) — GoProxy CA.** The GoProxy CA cert install by pe_06 (`Rugmi.HP`) was not observed during the dynamic-analysis window and may depend on host-fingerprint checks. The registry key path is known but writing a Sigma rule on a static thumbprint has moderate FP risk if the GoProxy cert is legitimately installed for developer tooling. **What would enable a rule:** a longer sandbox run with debugger attach to pe_06's `_tiny_erase_` export to confirm invocation conditions.

**T1620 (Reflective Code Loading) — tapisrv.dll/input.dll hollow.** DLL hollowing into `tapisrv.dll` and `input.dll` is not detectable by standard Sysmon EID 7 (ImageLoad) because the operator does not load a new DLL — it overwrites the `.text` section of an already-loaded legitimate DLL in memory. EDR memory-integrity hooks would catch the RWX page creation, but this is EDR-vendor-specific and cannot be generalized into a Sigma rule. **What would enable a rule:** an EDR-native rule for `VirtualProtect` on non-standard DLL `.text` sections, or a YARA memory scan for the stage-2 shellcode byte sequence at addresses matching the `tapisrv.dll` `.text` module range.

**T1041 (Exfiltration Over C2) — final-stage stealer output.** The final stealer variant (AsyncRAT vs DCRat vs zgRAT) is not confirmed. Without the decrypted payload, the specific exfiltration protocol cannot be fingerprinted. The current JA3/IP-feed coverage addresses the C2 channel but not data-exfiltration-specific traffic patterns. **What would enable a rule:** TLS interception with the GoProxy CA cert, or a memory dump of WVault.exe to recover the decrypted .NET assembly and extract protocol constants.

**T1056.001 (Keylogging) — CrystSupervisor32.exe.** YARA hits on CrystSupervisor32.exe include `screenshot` and keylogger-adjacent signatures, but these may reflect the genuine Wondershare SlideShowEditor's own feature surface rather than operator-added code. A keylogger-specific detection rule without confirming the code is operator-modified would carry unacceptably high FP risk against legitimate Wondershare installs. **What would enable a rule:** a disassembler diff of the suspected operator-modified binary against a known-clean Wondershare installer to confirm operator code injection.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
