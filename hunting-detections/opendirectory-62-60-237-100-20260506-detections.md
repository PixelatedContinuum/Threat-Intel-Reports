---
title: "Detection Rules — HijackLoader / Penguish / Rugmi to AsyncRAT Multi-Vector Phishing Campaign"
date: '2026-05-06'
layout: post
permalink: /hunting-detections/opendirectory-62-60-237-100-20260506-detections/
hide: true
---

**Campaign:** OpenDirectory-MultiFamily-MaaS-62.60.237.100
**Date:** 2026-05-06
**Author:** The Hunters Ledger
**License:** CC BY-NC 4.0
**Reference:** https://the-hunters-ledger.com/reports/opendirectory-62-60-237-100-20260506/

---

## Detection Coverage Summary

| Rule Type | Count | MITRE Techniques Covered | Overall FP Risk |
|---|---|---|---|
| YARA | 6 | T1027.009, T1027.013, T1204.002, T1574.002, T1055.012, T1055.002, T1620, T1480, T1036.005, T1218.014, T1059.005, T1105 | LOW–MEDIUM |
| Sigma | 8 | T1204.002, T1036.005, T1055.012, T1055.002, T1574.002, T1053.005, T1059.005, T1112, T1562.001, T1218.014, T1480 | LOW–MEDIUM |
| Suricata | 4 | T1071.001, T1573.001, T1571, T1105, T1090.002 | LOW |

**Total rules:** 18 across three detection layers.

**Campaign context:** Multi-stage commodity loader chain (HijackLoader / Penguish / Rugmi)
delivering an injected .NET AsyncRAT-class RAT, staged from an open directory at
`62.60.237[.]100` (AEZA Finland, AS210644). Operator is Russian-speaking (HIGH confidence),
operates as a MaaS customer with an 8-vector parallel phishing delivery kit. C2 beacons to
`185.241.208[.]129:56167` over TLSv1 (AS210558 — 1337 Services GmbH, Poland; Spamhaus
DROP listed). Campaign active as of 2026-05-06.

**Priority deployment targets:**
- Suricata rule for C2 IP and JA3 hash — deploy immediately at network perimeter
- Sigma rules for `watchermgmt.job` creation and `adv_ctrl` directory — hunt retroactively in EDR/SIEM
- YARA rule for `networkspec17.log` IDAT carrier — deploy in endpoint memory scanners and gateway AV

---

## YARA Rules

```
/*
    Name: HijackLoader / Penguish / Rugmi — AsyncRAT Campaign Detection Suite
    Author: The Hunters Ledger
    Date: 2026-05-06
    Identifier: HijackLoader_Penguish_Rugmi_AsyncRAT_OpenDirectory_62.60.237.100
    Reference: https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/
    License: https://creativecommons.org/licenses/by-nc/4.0/
*/
```

### YARA Rule 1 — Inno Setup Pascal Anti-Triage Wrapper

**Detection Priority:** HIGH
**Rationale:** Campaign-unique operator codenames (`Apophyge`, `Veteran`) and AppId GUID embedded in Inno Setup header. The `CrystSupervisor32.exe` payload launcher name is also distinctive. Combination of two or more indicators makes this low-FP.
**ATT&CK Coverage:** T1027.009 (Embedded Payloads), T1204.002 (Malicious File), T1036.005 (Match Legitimate Name or Location)
**Confidence:** HIGH
**False Positive Risk:** LOW — operator codenames `Apophyge` and `Veteran` are not standard Windows or Inno Setup strings; AppId GUID is campaign-unique
**Deployment:** Endpoint AV/EDR on-access scanner, gateway sandboxing, email attachment scanning

```yara
rule MALW_HijackLoader_InnoSetup_AntiTriage_Wrapper
{
    meta:
        description = "Detects HijackLoader Inno Setup 6.5+ wrapper using Pascal Script InitializeSetup->WinExec->return False anti-triage pattern. Operator codenames Apophyge (AppName) and Veteran (DefaultDirName) plus campaign AppId GUID {1F2952E4-FC07-4482-B9E6-E795507DA7D2} are embedded in the Inno header."
        author = "The Hunters Ledger"
        date = "2026-05-06"
        reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/"
        hash_sha256 = "1afbe5d960af45832539b11e92a09b808f0c3868ab437a7ef1b5d1bd5e16d0c3"
        family = "HijackLoader"

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

### YARA Rule 2 — ExceptionHandler.dll Plowshare Dispatcher

**Detection Priority:** HIGH
**Rationale:** Operator PDB path `I:\CompanySource\Plowshare\` is campaign-unique and cannot appear in legitimate software. Combined with the bespoke payload filenames `networkspec17.log` and `shadermgr93.rc`, this rule has near-zero FP risk.
**ATT&CK Coverage:** T1574.002 (DLL Side-Loading), T1055.012 (Process Hollowing), T1027 (Obfuscated Files)
**Confidence:** HIGH
**False Positive Risk:** LOW — PDB path with drive letter `I:\` and `CompanySource` folder is operator-distinctive; bespoke payload filenames are not reused by legitimate software
**Deployment:** Endpoint AV/EDR on-access scanner, memory scanner, file-system hunting

```yara
rule MALW_HijackLoader_ExceptionHandler_Plowshare_Dispatcher
{
    meta:
        description = "Detects operator-modified Wondershare Plowshare crash reporter (ExceptionHandler.dll) used as the HijackLoader stage-1 dispatcher. Identified by PDB path I:\CompanySource\Plowshare\Src\Symbol\Release\ExceptionHandler.pdb, operator-bespoke payload filenames (networkspec17.log, shadermgr93.rc), and the Wondershare-mimicking named pipe \\pipe\WondershareCrashServices."
        author = "The Hunters Ledger"
        date = "2026-05-06"
        reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/"
        hash_sha256 = "a3d0a9c71be732cdaafc7c1a9ef00c2a5a01e93b4a29c8944f8ea14a79f52ce0"
        family = "HijackLoader"

    strings:
        $pdb        = "I:\CompanySource\Plowshare\Src\Symbol\Release\ExceptionHandler.pdb" ascii
        $payload1   = "networkspec17.log" ascii wide
        $payload2   = "shadermgr93.rc" ascii wide
        $pipe       = "WondershareCrashServices" ascii wide
        $codename   = "Plowshare" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        ($pdb or ($payload1 and $payload2 and $pipe) or ($codename and $pipe))
}
```

---

### YARA Rule 3 — networkspec17.log PNG-IDAT Carrier

**Detection Priority:** HIGH
**Rationale:** The operator's custom 4-byte chunk-type marker `C6 A5 79 EA` at file offset 0 combined with the XOR key `E1 D5 B4 A2` at offset 4 are unique to this operator's multi-layer encoding scheme. No legitimate file format uses this header structure.
**ATT&CK Coverage:** T1027.013 (Encrypted/Encoded File), T1027.009 (Embedded Payloads)
**Confidence:** HIGH
**False Positive Risk:** LOW — the specific byte sequence at offset 0 is operator-distinctive and not a known legitimate file format magic number
**Deployment:** File-system hunting, email gateway scanning, endpoint memory scanner

```yara
rule MALW_HijackLoader_NetworkSpec17_IDAT_Carrier
{
    meta:
        description = "Detects the HijackLoader stage-3 payload carrier file networkspec17.log by its operator-distinctive PNG-IDAT framing header. The 4-byte chunk-type marker c6a579ea at offset 0 and the 4-byte XOR key e1d5b4a2 at offset 4 are unique to this operator's multi-layer encoding scheme (PNG IDAT framing + 4-byte XOR + LZNT1 chunked decompression)."
        author = "The Hunters Ledger"
        date = "2026-05-06"
        reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/"
        hash_sha256 = "7e2000ceb89574fe95e819f5f47da346119b666b7f64e8b5b01e5152e37d76cf"
        family = "HijackLoader"

    strings:
        $idat_marker   = { C6 A5 79 EA }
        $xor_key       = { E1 D5 B4 A2 }
        $idat_sentinel = { 49 44 41 54 }
        $iend_sentinel = { 49 45 4E 44 }
        $filename      = "networkspec17.log" ascii wide

    condition:
        filesize < 10MB and
        (
            ($idat_marker at 0 and $xor_key at 4) or
            ($idat_marker at 0 and $idat_sentinel and $iend_sentinel) or
            ($filename and $idat_marker and $xor_key)
        )
}
```

---

### YARA Rule 4 — pe_03 HijackLoader Stage-3 Loader (API Hash Table)

**Detection Priority:** HIGH
**Rationale:** The API hash values in pe_03's hash table (X65599/RtlHashUnicodeString polynomial) are fixed constants tied to specific API names. Three or more matching hash DWORDs constitute near-certain identification. The Qihoo PDB path is an additional high-confidence anchor.
**ATT&CK Coverage:** T1620 (Reflective Code Loading), T1055.012 (Process Hollowing), T1480 (Execution Guardrails), T1027 (Obfuscated Files)
**Confidence:** HIGH
**False Positive Risk:** LOW — API hash values at specific little-endian DWORD offsets are specific to this loader; the Qihoo PDB path in a non-Qihoo install context is highly suspicious
**Deployment:** Endpoint AV/EDR, memory scanner, sandbox detonation

```yara
rule MALW_HijackLoader_Penguish_Stage3_Loader_PE
{
    meta:
        description = "Detects the HijackLoader/Penguish/Rugmi stage-3 loader PE (pe_03) by its API hash table values using the X65599/RtlHashUnicodeString polynomial. The loader uses GetComputerNameW as a per-host execution guardrail seed and resolves kernel32/ntdll APIs by hash at runtime with an empty import table."
        author = "The Hunters Ledger"
        date = "2026-05-06"
        reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/"
        hash_sha256 = "68fb61225b457172368d43af7ec2afe48f59404089d095584944edbfd0171feb"
        family = "HijackLoader"

    strings:
        $hash_gcnw  = { BB 5A B3 CB }
        $hash_zqip  = { 8E 04 7B 9C }
        $hash_rdb   = { 2D B6 03 B4 }
        $hash_zde   = { 32 FB 7E 6A }
        $hash_zqsi  = { D2 E6 69 AE }
        $qihoo_pdb  = "C:\vmagent_new\bin\joblist\881673\out\Release\PromoUtil.pdb" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (3 of ($hash_*)) or
            ($qihoo_pdb and 1 of ($hash_*))
        )
}
```

---

### YARA Rule 5 — WVault.exe Hollow-Host .NET RAT Injection

**Detection Priority:** HIGH
**Rationale:** The Qihoo 360 PromoUtil PDB path inside a file named `WVault.exe` or found at `C:\ProgramData\` is a strong cross-campaign TTP indicator observed across 8+ campaigns since 2025. Qihoo PDB + Qihoo VersionInfo + operator drop path together constitute near-certain identification.
**ATT&CK Coverage:** T1055.002 (PE Injection), T1036.005 (Match Legitimate Name or Location), T1055.012 (Process Hollowing)
**Confidence:** HIGH
**False Positive Risk:** LOW — Qihoo PromoUtil.exe legitimately exists only under Program Files\Qihoo 360\; finding its PDB path combined with the WVault.exe name or adv_ctrl path is not a legitimate scenario
**Deployment:** Endpoint memory scanner, EDR process anomaly detection, file-system hunting at C:\ProgramData\

```yara
rule MALW_HijackLoader_WVault_HollowHost_NetRAT
{
    meta:
        description = "Detects WVault.exe used as hollow host for injected .NET AsyncRAT-class RAT. WVault.exe is the genuine signed Qihoo 360 PromoUtil.exe renamed and dropped to C:\ProgramData\WVault.exe. Cross-campaign TTP cluster seen in 8+ campaigns since 2025."
        author = "The Hunters Ledger"
        date = "2026-05-06"
        reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/"
        hash_sha256 = "c085a724a067eec46d9a2c1eeae3cc04db33b9840f5c33eb87cc3027e12a6bcd"
        family = "HijackLoader"

    strings:
        $pdb_qihoo  = "C:\vmagent_new\bin\joblist\881673\out\Release\PromoUtil.pdb" ascii
        $drop_path  = "C:\ProgramData\WVault.exe" ascii wide
        $persist    = "adv_ctrl" ascii wide
        $vs_company = "Qihoo 360 Technology Co." ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($pdb_qihoo and $vs_company) or
            ($pdb_qihoo and $drop_path) or
            ($drop_path and $persist and $vs_company)
        )
}
```

---

### YARA Rule 6 — Multi-Vector Lure: GrimResource MSC + Mega.io Payload Fetch

**Detection Priority:** HIGH
**Rationale:** The GrimResource `res://apds.dll/redirect.html` pattern inside an MMC `.msc` XML body is a specific weaponization technique. The operator's Mega.io bucket ID `aileqac3yep7oqdhygjpberqqnk2zrnhck2lx/busket/` is campaign-unique (including the `busket` typo).
**ATT&CK Coverage:** T1218.014 (MMC), T1059.005 (Visual Basic), T1059.007 (JavaScript), T1105 (Ingress Tool Transfer)
**Confidence:** HIGH
**False Positive Risk:** LOW — `res://apds.dll/redirect.html` in an MSC file body is a known weaponization technique with no legitimate use case; the Mega.io bucket path is campaign-unique
**Deployment:** Email gateway, endpoint file-system scanning, web proxy URL inspection

```yara
rule MALW_HijackLoader_MultiVector_Lure_GrimResource_MSC
{
    meta:
        description = "Detects MSC GrimResource weaponized files used in the HijackLoader campaign. Pattern: res://apds.dll/redirect.html?target=javascript:eval(...) embedded in an MMC snap-in .msc file. Also covers the campaign operator's Mega.io staging bucket path aileqac3yep7oqdhygjpberqqnk2zrnhck2lx/busket/ (note: operator typo of bucket)."
        author = "The Hunters Ledger"
        date = "2026-05-06"
        reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/"
        hash_sha256 = "3480d0478d35d8a12331b97769401e16e4956bdc24b9a7175ae08e2c9e9acf8f"
        family = "HijackLoader"

    strings:
        $grimres    = "res://apds.dll/redirect.html" ascii wide nocase
        $js_eval    = "javascript:eval(" ascii wide nocase
        $mmc_root   = "<MMC_ConsoleFile" ascii wide
        $mega_path  = "aileqac3yep7oqdhygjpberqqnk2zrnhck2lx/busket/" ascii wide nocase
        $macro_rev  = "[array]::Reverse($" ascii wide

    condition:
        filesize < 5MB and
        (
            ($grimres and $js_eval and $mmc_root) or
            ($mega_path and ($macro_rev or $grimres)) or
            ($grimres and $mega_path)
        )
}
```

---

## Sigma Rules

### Sigma Rule 1 — Inno Setup Process Tree: CrystSupervisor32 Spawn and WVault Chain

**Detection Priority:** HIGH
**Rationale:** `CrystSupervisor32.exe` spawned from an `is-*.tmp\` parent path, or `WVault.exe` spawned from `CrystSupervisor32.exe`, are highly specific process-tree artifacts of the HijackLoader loader chain. No legitimate Wondershare product creates this exact parent-child chain.
**ATT&CK Coverage:** T1204.002 (Malicious File), T1574.002 (DLL Side-Loading), T1055.012 (Process Hollowing)
**Confidence:** HIGH
**False Positive Risk:** LOW — the `is-*.tmp\CrystSupervisor32.exe` path is specific to the HijackLoader Inno Setup dropper; legitimate Wondershare installs run from `Program Files`
**Deployment:** EDR process-creation monitoring, SIEM Sysmon EID 1

```yaml
title: HijackLoader Inno Setup Wrapper Spawning CrystSupervisor32 and WVault Process Chain
id: 3a7f1e92-bb04-4d85-9c3e-f6a820d14c73
status: test
description: >
    Detects the HijackLoader/Penguish/Rugmi loader chain initiated by an Inno Setup
    wrapper using the Pascal Script InitializeSetup->WinExec->return False anti-triage
    technique. The wrapper drops and immediately launches CrystSupervisor32.exe
    (renamed genuine Wondershare SlideShowEditor.exe) from a temporary is-*.tmp
    directory. The chain continues through WVault.exe (renamed signed Qihoo 360
    PromoUtil.exe) used as the hollow host for an injected .NET AsyncRAT-class RAT.
    The installer exits silently with no wizard UI, defeating sandboxes that wait for
    wizard-completion or [Run] section events.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/
    - https://the-hunters-ledger.com/reports/opendirectory-62-60-237-100-20260506/
author: The Hunters Ledger
date: 2026/05/06
tags:
    - attack.execution
    - attack.defense-evasion
    - attack.persistence
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
    - Legitimate Wondershare software installers that use CrystSupervisor32.exe as part
      of genuine DVD Creator or SlideShow Editor installation (verify Authenticode chain
      and parent install path matches official Wondershare installer, not a temp directory)
    - Qihoo 360 software installations where PromoUtil.exe is legitimately renamed
      (verify install path is under Program Files, not C:\ProgramData\)
level: high
```

---

### Sigma Rule 2 — Named Pipe WondershareCrashServices Created Outside Legitimate Path

**Detection Priority:** HIGH
**Rationale:** The named pipe `\.\pipe\WondershareCrashServices` created by a process NOT under the genuine Wondershare `Program Files` path is the operator's covert IPC channel. Legitimate Wondershare crash reporters only run from their install directory.
**ATT&CK Coverage:** T1055.012 (Process Hollowing), T1036.005 (Match Legitimate Name or Location)
**Confidence:** HIGH
**False Positive Risk:** LOW — pipe name is Wondershare-specific; filter on legitimate install path removes genuine Wondershare software; remaining matches are operator-controlled
**Deployment:** EDR named-pipe monitoring, SIEM Sysmon EID 17

```yaml
title: HijackLoader Covert IPC Named Pipe WondershareCrashServices Created
id: 7c9d4b1a-e832-4f67-b52a-901c3d8e5f24
status: test
description: >
    Detects creation of the named pipe \.\pipe\WondershareCrashServices used by
    the HijackLoader operator-modified ExceptionHandler.dll as a covert inter-process
    communication channel between loader stages. The pipe name mimics the legitimate
    Wondershare Breakpad crash-reporting IPC channel but is created by the operator's
    modified dispatcher DLL (PDB path I:\CompanySource\Plowshare\) to coordinate
    stage-1 through stage-3 execution. Legitimate Wondershare software creates this
    pipe only from signed Wondershare binaries installed under Program Files.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/
    - https://the-hunters-ledger.com/reports/opendirectory-62-60-237-100-20260506/
author: The Hunters Ledger
date: 2026/05/06
tags:
    - attack.defense-evasion
    - attack.execution
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
    - Legitimate Wondershare DVD Creator or SlideShow Editor installations where
      ExceptionHandler.dll creates this pipe from a genuine Program Files install path
      (filtered by the legit Wondershare path exclusion above)
    - Security testing tools that explicitly simulate Wondershare crash-reporter IPC
level: high
```

---

### Sigma Rule 3 — Operator Persistence Directory adv_ctrl Created Under ProgramData

**Detection Priority:** HIGH
**Rationale:** The codename `adv_ctrl` (and sibling codenames `brokerbg`, `exttracer_net48`, `thread_adapter`, `Sulfathiazole`) under `C:\ProgramData\` are operator-distinctive persistence staging directories. None of these names appear in legitimate Windows or common third-party software paths.
**ATT&CK Coverage:** T1036.005 (Match Legitimate Name or Location), T1562.001 (Disable or Modify Tools)
**Confidence:** HIGH
**False Positive Risk:** LOW — `adv_ctrl` and sibling codenames are not standard Windows directory names; cross-reference with parent process chain for confirmation
**Deployment:** EDR file-creation monitoring, SIEM Sysmon EID 11

```yaml
title: HijackLoader Operator Persistence Directory adv_ctrl Created Under ProgramData
id: f2a85c3d-16b7-4e09-a74f-3c9b7d2e8a15
status: test
description: >
    Detects creation of the operator-codename persistence directory adv_ctrl under
    C:\ProgramData\ or %APPDATA%\, used by the HijackLoader/Penguish/Rugmi campaign
    to stage the Crisp.exe side-load host and the WVault.exe hollow host, and to
    receive a Windows Defender real-time exclusion (Set-MpPreference -ExclusionPath).
    The codename adv_ctrl is one of several operator persistence directory names
    observed across campaign variants (others: brokerbg, exttracer_net48,
    thread_adapter, Sulfathiazole). Detection of any of these codenames in
    C:\ProgramData\ from a non-system-installer parent is high-confidence malicious.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/
    - https://the-hunters-ledger.com/reports/opendirectory-62-60-237-100-20260506/
author: The Hunters Ledger
date: 2026/05/06
tags:
    - attack.persistence
    - attack.defense-evasion
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
    - Legitimate software installers that coincidentally use a directory named adv_ctrl
      (extremely unlikely — this is a distinctive operator codename, not a standard
      Windows or common third-party path component)
    - Security tools or EDR agents using similarly named directories for internal state
level: high
```

---

### Sigma Rule 4 — Legacy .job Scheduled Task watchermgmt.job Created

**Detection Priority:** HIGH
**Rationale:** The legacy `.job` file at `C:\Windows\Tasks\watchermgmt.job` is the operator's autorunsc-blind persistence mechanism. Legacy `.job` format at this path is rare in modern environments (post-Vista); creation from a non-`svchost.exe` or non-installer parent is anomalous.
**ATT&CK Coverage:** T1053.005 (Scheduled Task)
**Confidence:** HIGH
**False Positive Risk:** LOW — `watchermgmt.job` at `C:\Windows\Tasks\` from a non-system parent is not a legitimate software pattern; legacy `.job` format is obsolete
**Deployment:** EDR file-creation monitoring, SIEM Sysmon EID 11, file-system hunting

```yaml
title: HijackLoader Legacy .job Scheduled Task watchermgmt Created in Windows Tasks
id: 9e6b3f17-d452-4a08-c91d-8b7e2f5a3c06
status: test
description: >
    Detects creation of the legacy .job format scheduled task C:\Windows\Tasks\watchermgmt.job
    used by the HijackLoader/Penguish/Rugmi campaign for persistence. The legacy .job
    format at C:\Windows\Tasks\ creates a known blind spot in autorunsc (Sysinternals
    Autoruns) enumeration that does not parse this path by default. The XML migration
    to C:\Windows\System32\Tasks\watchermgmt is auto-created by the Windows Schedule
    service within 90ms. Detection at the C:\Windows\Tasks\ write event catches the
    operator's persistence before the XML migration occurs.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/
    - https://the-hunters-ledger.com/reports/opendirectory-62-60-237-100-20260506/
author: The Hunters Ledger
date: 2026/05/06
tags:
    - attack.persistence
logsource:
    category: file_event
    product: windows
detection:
    selection_watchermgmt:
        TargetFilename|startswith: 'C:\Windows\Tasks\watchermgmt'
    selection_generic_job:
        TargetFilename|startswith: 'C:\Windows\Tasks\'
        TargetFilename|endswith: '.job'
        ParentImage|endswith:
            - '\CrystSupervisor32.exe'
            - '\WVault.exe'
    condition: selection_watchermgmt or selection_generic_job
falsepositives:
    - Legacy scheduled tasks created by third-party software installers writing
      .job files to C:\Windows\Tasks\ (uncommon in modern environments — legacy .job
      format is rarely used by legitimate software after Windows Vista)
    - Enterprise management tools (SCCM, Ansible, PDQ) that use legacy .job format
      for scheduled task deployment (verify parent process chain)
level: high
```

---

### Sigma Rule 5 — VBAWarnings Registry Write (Macro Security Disable)

**Detection Priority:** MEDIUM
**Rationale:** Setting `VBAWarnings=1` via PowerShell or cmd.exe (not via GPO/SCCM) is a pre-conditioning step before delivering macro-enabled Office lure documents. Medium priority because IT admins can legitimately set this, but the context (cmd/PowerShell parent from a non-admin session) distinguishes malicious use.
**ATT&CK Coverage:** T1112 (Modify Registry), T1059.005 (Visual Basic), T1562.001 (Disable or Modify Tools)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM — legitimate admins may set VBAWarnings via registry; correlate with parent process (PowerShell spawned from cmd.exe or Office installer vs spawned from phishing attachment)
**Deployment:** SIEM Sysmon EID 13, EDR registry monitoring

```yaml
title: Office VBA Macro Security Disabled via Registry VBAWarnings Set to 1
id: 4d2c8e5b-7f91-4b36-a82e-5d9c1f7e3a08
status: test
description: >
    Detects a registry write setting HKCU\Software\Microsoft\Office\<version>\<app>\Security\VBAWarnings
    to 1 (enable all macros without notification), which disables Office macro security
    controls. In the HijackLoader campaign, this is performed by Excel_2016_Windows.bat
    via PowerShell Set-MpPreference or direct registry write, used to pre-condition
    victim workstations before delivering macro-enabled Office lure documents
    (Price5.docm, Price6.doc, NDA.doc, Price4.xls). The registry path covers both
    Office 16.0 (2016/2019/365) and 19.0 variant keys.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/
    - https://the-hunters-ledger.com/reports/opendirectory-62-60-237-100-20260506/
author: The Hunters Ledger
date: 2026/05/06
tags:
    - attack.defense-evasion
    - attack.execution
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
    - Legitimate IT administrators deploying macro-enabled Office solutions who
      intentionally set VBAWarnings=1 via GPO or management scripts (correlate
      with change management records and deploying user account)
    - Software developers testing Office VBA macros in a development environment
    - Enterprise Office deployments that centrally manage macro trust settings
      (these should be deployed via GPO, not per-user registry write from cmd.exe/PowerShell)
level: medium
```

---

### Sigma Rule 6 — mmc.exe Spawning mshta/rundll32 (GrimResource Execution)

**Detection Priority:** HIGH
**Rationale:** `mmc.exe` spawning `mshta.exe`, `rundll32.exe`, or scripting interpreters is an abnormal process-tree relationship. Legitimate MMC snap-ins do not spawn these binaries. This pattern directly identifies GrimResource MSC file execution as used in the campaign's `1.msc`, `Price2.pdf.msc`, and `MSCFile.msc` lure files.
**ATT&CK Coverage:** T1218.014 (MMC), T1059.005 (Visual Basic), T1059.007 (JavaScript)
**Confidence:** HIGH
**False Positive Risk:** LOW — `mmc.exe` as a direct parent of `mshta.exe` or `rundll32.exe` is not a legitimate administrative pattern; filter covers common legitimate snap-in names
**Deployment:** EDR process-creation monitoring, SIEM Sysmon EID 1

```yaml
title: HijackLoader GrimResource MMC Spawning Mshta or Rundll32 for Payload Execution
id: b81e4c29-53a7-4d02-8f9e-2a7d6c4b1e35
status: test
description: >
    Detects MMC (Microsoft Management Console) spawning mshta.exe or rundll32.exe
    as part of the GrimResource MSC file weaponization technique used by the
    HijackLoader campaign. The MSC files (1.msc, Price2.pdf.msc, MSCFile.msc) use
    the res://apds.dll/redirect.html XSL redirect to execute javascript:eval() which
    launches mshta.exe or rundll32.exe from mmc.exe as a parent. This parent-child
    relationship is abnormal: legitimate MMC snap-ins do not spawn these interpreters.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/
    - https://the-hunters-ledger.com/reports/opendirectory-62-60-237-100-20260506/
author: The Hunters Ledger
date: 2026/05/06
tags:
    - attack.execution
    - attack.defense-evasion
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
    - Custom enterprise MMC snap-ins that legitimately spawn PowerShell or cmd.exe
      for administrative actions (rare — verify the specific MSC file source and
      the spawned command line for administrative context)
    - Security monitoring tools that invoke MMC snap-ins programmatically
level: high
```

---

### Sigma Rule 7 — Per-Host Uppercase Environment Variable IPC Pattern

**Detection Priority:** MEDIUM
**Rationale:** `WVault.exe` spawned from `CrystSupervisor32.exe`, or either process spawned from an `is-*.tmp` path, is the observable artifact of the per-host env-var IPC mechanism. The env-var names themselves are not logged by Sysmon by default; the process chain is the actionable indicator.
**ATT&CK Coverage:** T1055.012 (Process Hollowing), T1480 (Execution Guardrails), T1036.005 (Match Legitimate Name or Location)
**Confidence:** HIGH
**False Positive Risk:** LOW — `WVault.exe` at `C:\ProgramData\` from a Wondershare-named parent is not a legitimate software pattern
**Deployment:** EDR process-creation monitoring, SIEM Sysmon EID 1

```yaml
title: HijackLoader Per-Host Uppercase Environment Variable IPC Pattern Detected
id: c45f9d2e-8b16-4c53-a97b-7e3f1d9c6b42
status: test
description: >
    Detects the HijackLoader/Penguish per-host environment variable IPC mechanism
    where the loader (pe_03) generates a deterministic-per-host uppercase A-Z only
    environment variable name using GetComputerNameW as a PRNG seed, then passes
    the decryption key as its value to child processes via GetEnvironmentVariableW.
    The observable pattern is a child process (WVault.exe or CrystSupervisor32.exe)
    whose parent spawned it with a custom environment variable whose name consists
    entirely of uppercase ASCII letters (8-16 characters), a pattern not present in
    standard Windows or common software environment blocks.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/
    - https://the-hunters-ledger.com/reports/opendirectory-62-60-237-100-20260506/
author: The Hunters Ledger
date: 2026/05/06
tags:
    - attack.defense-evasion
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_wvault_env:
        Image|endswith:
            - '\WVault.exe'
            - '\CrystSupervisor32.exe'
        ParentImage|endswith:
            - '\CrystSupervisor32.exe'
            - '\WVault.exe'
    selection_loader_to_hollow:
        Image|endswith: '\WVault.exe'
        ParentImage|contains: 'is-'
    condition: selection_wvault_env or selection_loader_to_hollow
falsepositives:
    - Legitimate Wondershare software chains where CrystSupervisor32.exe spawns
      child processes in genuine DVD Creator workflows (verify the file hashes and
      install path: legitimate chain runs from Program Files, not is-*.tmp or
      C:\ProgramData\adv_ctrl\)
    - Security tools or EDR components that mimic process chain patterns for testing
level: medium
```

---

### Sigma Rule 8 — MSC GrimResource mmc.exe Spawning PowerShell with Defender Exclusion

**Detection Priority:** HIGH
**Rationale:** The `mmc.exe` → PowerShell → `Add-MpPreference` chain combining MMC as parent with Defender exclusion commands is a highly specific GrimResource post-exploitation pattern. This combination is not a legitimate administrative workflow.
**ATT&CK Coverage:** T1218.014 (MMC), T1562.001 (Disable or Modify Tools), T1059.001 (PowerShell)
**Confidence:** HIGH
**False Positive Risk:** LOW — `mmc.exe` is not a legitimate parent for PowerShell-based Defender configuration; the specific `Add-MpPreference` + `ExclusionPath` combination narrows further
**Deployment:** EDR process-creation monitoring, SIEM Sysmon EID 1, PowerShell-Operational EID 4104

```yaml
title: HijackLoader GrimResource MMC Spawning PowerShell Adding Defender Exclusion
id: e73a1b48-c926-4e85-9fd2-6b8d3e4a7c19
status: test
description: >
    Detects the HijackLoader GrimResource MSC file execution chain where mmc.exe
    spawns cmd.exe or powershell.exe that subsequently invokes Add-MpPreference
    with -ExclusionExtension or -ExclusionPath to disable Windows Defender
    real-time protection for the operator's persistence directory. In the observed
    campaign, the MSC files execute XSL->VBScript->PowerShell to add
    C:\ProgramData\adv_ctrl to Defender exclusions before dropping the loader chain.
    This mmc.exe->PowerShell->Add-MpPreference combination is not a legitimate
    administrative pattern.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/
    - https://the-hunters-ledger.com/reports/opendirectory-62-60-237-100-20260506/
author: The Hunters Ledger
date: 2026/05/06
tags:
    - attack.defense-evasion
    - attack.execution
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
    - Security administrators who open MMC snap-ins and then separately run
      PowerShell to manage Defender exclusions in the same session (extremely
      unlikely as a process-parent relationship: MMC does not propagate as the
      parent for manually opened PowerShell windows)
    - Automated endpoint management solutions that use MMC-based snap-ins to
      deliver Defender configuration changes (verify via change-management records)
level: high
```

---

## Suricata Signatures

### Suricata Rule 1 — C2 TLSv1 to 185.241.208.129 on Non-Standard Port 56167

**Detection Priority:** HIGH
**Rationale:** Direct IP C2 to `185.241.208.129:56167` over TLSv1.0 with no preceding DNS query is a definite indicator. TLSv1.0 is deprecated; non-standard port 56167 is not used by legitimate software. JA3 match adds a second independent confirmation layer.
**ATT&CK Coverage:** T1071.001 (Application Layer Protocol: Web Protocols), T1571 (Non-Standard Port), T1573.001 (Encrypted Channel)
**Confidence:** HIGH
**False Positive Risk:** LOW — this specific IP:port combination is campaign-dedicated C2 infrastructure confirmed on Spamhaus DROP list AS210558; TLSv1.0 to a non-standard high port is not a legitimate application pattern
**Deployment:** Network perimeter IDS/IPS, NGFW, network TAP/span; deploy as `drop` in blocking mode

```
alert tls $HOME_NET any -> 185.241.208.129 any (
    msg:"THL HijackLoader AsyncRAT C2 TLS Connection to 185.241.208.129 Non-Standard Port";
    flow:established,to_server;
    tls.version:"1.0";
    threshold:type limit, track by_src, count 1, seconds 60;
    classtype:trojan-activity;
    sid:9001001;
    rev:1;
    metadata:
        affected_products Windows,
        attack_target Client_Endpoint,
        created_at 2026_05_06,
        deployment Perimeter,
        former_category MALWARE,
        malware_family HijackLoader,
        mitre_tactic_id TA0011,
        mitre_technique_id T1071.001 T1571 T1573.001,
        performance_impact Low,
        signature_severity Major,
        updated_at 2026_05_06;
    reference:url,the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/;
)
```

---

### Suricata Rule 2 — JA3 Hash 07af4aa9e4d215a5ee63f9a0a277fbe3 (AsyncRAT/zgRAT/DCRat)

**Detection Priority:** HIGH
**Rationale:** JA3 fingerprint `07af4aa9e4d215a5ee63f9a0a277fbe3` is flagged by Abuse.ch SSLBL as an AsyncRAT SSL client fingerprint. Detection is destination-IP-independent — fires even if the operator migrates C2 infrastructure. Covers all hosts running the same RAT client configuration.
**ATT&CK Coverage:** T1071.001 (Application Layer Protocol), T1573.001 (Encrypted Channel), T1571 (Non-Standard Port)
**Confidence:** HIGH
**False Positive Risk:** LOW — JA3 `07af4aa9e4d215a5ee63f9a0a277fbe3` is specifically listed on Abuse.ch SSLBL for AsyncRAT/zgRAT; legitimate software does not produce this exact TLS ClientHello fingerprint combination
**Deployment:** Network IDS on internal LAN segments, perimeter TAP; complements Rule 1

```
alert tls $HOME_NET any -> any any (
    msg:"THL HijackLoader AsyncRAT SSL JA3 Fingerprint 07af4aa9e4d215a5ee63f9a0a277fbe3";
    flow:established,to_server;
    ja3.hash; content:"07af4aa9e4d215a5ee63f9a0a277fbe3"; endswith;
    threshold:type limit, track by_src, count 3, seconds 300;
    classtype:trojan-activity;
    sid:9001002;
    rev:1;
    metadata:
        affected_products Windows,
        attack_target Client_Endpoint,
        created_at 2026_05_06,
        deployment Perimeter,
        former_category MALWARE,
        malware_family AsyncRAT,
        mitre_tactic_id TA0011,
        mitre_technique_id T1071.001 T1573.001 T1571,
        performance_impact Low,
        signature_severity Major,
        updated_at 2026_05_06;
    reference:url,the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/;
    reference:url,sslbl.abuse.ch/;
)
```

---

### Suricata Rule 3 — HTTP Payload Download from 109.120.137.6 (PUTTY.exe Shell-Redirect)

**Detection Priority:** HIGH
**Rationale:** HTTP GET to `109.120.137.6/PUTTY.exe` is the second-stage staging server used in shell-redirect download commands embedded in `.url` and `.lnk` lure files. The server also hosted Russian-language content (`mozhno-li-vyvesti-dengi-s-krakena.html`) confirming operator attribution.
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer), T1566.002 (Spearphishing Link)
**Confidence:** HIGH
**False Positive Risk:** LOW — `109.120.137.6` is a dedicated campaign staging server; HTTP GET to `/PUTTY.exe` from this IP is not a legitimate software update endpoint
**Deployment:** Network perimeter IDS, web proxy, DNS-layer blocking

```
alert http $HOME_NET any -> 109.120.137.6 any (
    msg:"THL HijackLoader Staging Server 109.120.137.6 PUTTY.exe Payload Download";
    flow:established,to_server;
    http.method; content:"GET";
    http.uri; content:"/PUTTY.exe"; nocase;
    classtype:trojan-activity;
    sid:9001003;
    rev:1;
    metadata:
        affected_products Windows,
        attack_target Client_Endpoint,
        created_at 2026_05_06,
        deployment Perimeter,
        former_category MALWARE,
        malware_family HijackLoader,
        mitre_tactic_id TA0011,
        mitre_technique_id T1105,
        performance_impact Low,
        signature_severity Major,
        updated_at 2026_05_06;
    reference:url,the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/;
)
```

---

### Suricata Rule 4 — HTTPS to Mega.io Operator Staging Bucket (Campaign-Unique Bucket ID)

**Detection Priority:** HIGH
**Rationale:** The Mega.io bucket path `aileqac3yep7oqdhygjpberqqnk2zrnhck2lx/busket/` is campaign-unique, including the operator's `busket` typo (English-second-language signal). Macro-enabled Office lure documents (`Price5.docm`, `Price6.doc`, `NDA.doc`, `Price4.xls`) decode reverse-encoded URLs to fetch payloads from this bucket.
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer), T1059.005 (Visual Basic), T1071.001 (Application Layer Protocol)
**Confidence:** HIGH
**False Positive Risk:** LOW — the bucket ID is campaign-unique; legitimate Mega.io usage does not produce this specific 36-character bucket ID
**Deployment:** Network perimeter IDS, web proxy URL inspection, TLS inspection appliance

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"THL HijackLoader Macro Lure Mega.io Campaign Bucket Payload Fetch";
    flow:established,to_server;
    http.host; content:"s3.g.s4.mega.io"; endswith; nocase;
    http.uri; content:"/aileqac3yep7oqdhygjpberqqnk2zrnhck2lx/busket/"; nocase;
    classtype:trojan-activity;
    sid:9001004;
    rev:1;
    metadata:
        affected_products Windows,
        attack_target Client_Endpoint,
        created_at 2026_05_06,
        deployment Perimeter,
        former_category MALWARE,
        malware_family HijackLoader,
        mitre_tactic_id TA0011,
        mitre_technique_id T1105 T1071.001,
        performance_impact Low,
        signature_severity Major,
        updated_at 2026_05_06;
    reference:url,the-hunters-ledger.com/hunting-detections/opendirectory-62-60-237-100-20260506-detections/;
)
```

---

## Coverage Gaps

The following MITRE ATT&CK techniques were observed in the malware-analyst findings but could not be covered with high-confidence, low-FP detection rules in this initial release:

| Technique | Reason Not Covered | Evidence Needed to Enable Rule |
|---|---|---|
| **T1480 (Execution Guardrails) — per-host KDF** | The per-host hostname-keyed cipher (X65599 hash XOR `0xa1b2d3b4` as PRNG seed) is behavioral. The env var NAME is deterministic per host but not predictable from a network/file sensor. A rule based on a fixed env var name would miss all hosts except the analysis machine. | Memory dump of WVault.exe mid-execution to recover the hostname-derived seed and env var value, enabling a host-specific IOC. |
| **T1036.002 (Right-to-Left Override) — RTLO filename detection** | RTLO detection on filenames requires Unicode-aware filename inspection. Standard Sysmon EID 11 `TargetFilename` fields log the rendered (reversed) name, not the raw Unicode codepoint sequence. A YARA rule against the binary U+202E codepoint in filesystem metadata is possible but requires a Unicode-aware scanner configuration. | NTFS alternate data stream or MFT-level parsing to detect U+202E in raw filename bytes before OS rendering. |
| **T1553.004 (Install Root Certificate) — GoProxy CA** | The GoProxy CA cert install by pe_06 (`Rugmi.HP`) was not observed in the 5-minute dynamic analysis window and may depend on host fingerprint checks. The registry key path is known (`HKCU\Software\Microsoft\SystemCertificates\Root\Certificates\0174E68C97DDF1E0EEEA415EA336A163D2B61AFD`) but writing a Sigma rule on a static thumbprint has moderate FP risk if the GoProxy cert is legitimately installed for developer tooling. | Longer sandbox run (>15 min) with debugger attach to pe_06 `_tiny_erase_` export to confirm invocation conditions. |
| **T1620 (Reflective Code Loading) — tapisrv.dll/input.dll hollow** | DLL hollowing into `tapisrv.dll` and `input.dll` is not detectable by standard Sysmon EID 7 (ImageLoad) because the operator does NOT load a new DLL — it overwrites the `.text` section of an already-loaded legitimate DLL in memory. EDR memory-integrity hooks would catch the RWX page creation, but this is EDR-vendor-specific and cannot be generalized into a Sigma rule. | EDR-native rule for `VirtualProtect` on non-standard DLL `.text` sections (vendor-specific) or a YARA memory scan for the stage-2 shellcode byte sequence at addresses matching `tapisrv.dll!.text` module range. |
| **T1041 (Exfiltration Over C2) — final-stage stealer output** | The final stealer variant (AsyncRAT vs DCRat vs zgRAT) is not confirmed. Without the decrypted payload, the specific exfiltration protocol cannot be fingerprinted. Current JA3/IP rules cover the C2 channel but not the data-exfil-specific traffic patterns. | TLS MITM with the GoProxy CA cert (thumbprint `0174E68C97DDF1E0EEEA415EA336A163D2B61AFD`) or memory dump of WVault.exe to recover the decrypted .NET assembly and extract protocol constants. |
| **T1056.001 (Keylogging) — CrystSupervisor32.exe** | YARA hits on CrystSupervisor32.exe include `screenshot` and keylogger signatures but these may reflect the genuine Wondershare SlideShowEditor's full feature surface rather than operator-added code. A keylogger-specific detection rule without confirming the code is operator-modified would have unacceptably high FP risk against legitimate Wondershare installs. | Disassembler (Ghidra or Binary Ninja) diff of the suspected operator-modified version vs a known-clean Wondershare installer binary to confirm operator code injection. |

---

## License
Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.  
Free to use in your environment, but not for commercial purposes.
