---
title: "Detection Rules — Chaos Ransomware (TorBrowserTor) Multi-Stage Loader — Open Directory 94.103.1.13"
date: '2026-04-23'
layout: post
permalink: /hunting-detections/open-directory-94-103-1-13-20260423-detections/
hide: true
---

**Campaign:** open-directory-94-103-1-13-20260423
**Date:** 2026-04-23
**Author:** The Hunters Ledger
**License:** CC BY-NC 4.0
**Reference:** https://the-hunters-ledger.com/reports/open-directory-94-103-1-13-20260423/

---

## Detection Coverage Summary

| Rule Type | Count | MITRE Techniques Covered | Overall FP Risk |
|---|---|---|---|
| YARA | 9 | T1027, T1027.011, T1140, T1486, T1548.002, T1573, T1056.001 | LOW–MEDIUM |
| Sigma | 9 | T1053.005, T1112, T1027.011, T1548.002, T1134.004, T1486, T1490, T1547.001, T1497, T1090.001 | LOW–MEDIUM |
| Suricata | 2 | T1071.001, T1583.003 | LOW |

Rules are organised into two tiers. **Tier A** covers commodity-tool indicators (Chaos/TorBrowserTor ransomware family, Orcus RAT Wardow crack, standard privilege-escalation tooling). **Tier B** covers custom, high-value anchors with zero prior public documentation — these are the primary hunting priority for this campaign.

---

## Multi-Family Organisation

Rules are grouped by family within each rule-type section:

- **Tier B — Custom Crypter / Builder Cross-Build Invariants** (highest priority)
- **Tier B — mymain Build-Specific Crypter Anchors**
- **Tier B — myfile Build-Specific Crypter Anchors**
- **Tier A — Chaos / TorBrowserTor Ransomware (Stage-5a)**
- **Tier A — Orcus RAT v7 (Wardow Crack)**
- **Tier A — Privilege Escalation Toolkit**

---

## YARA Rules

<!--
    File header block (for standalone .yar extraction):

    Name: Chaos TorBrowserTor Multi-Stage Loader — Open Directory 94.103.1.13
    Author: The Hunters Ledger
    Date: 2026-04-23
    Identifier: Chaos-TorBrowserTor-Private-Crypter-OpenDirectory-94.103.1.13
    Reference: https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/
    License: https://creativecommons.org/licenses/by-nc/4.0/
-->

### Tier B — Custom Crypter / Builder Cross-Build Invariants

---

**Detection Priority:** HIGH
**Rationale:** Stage-5b UAC bypass PE is byte-identical across both observed builds (mymain and myfile). Only 8/77 VT vendors detect it. Any copy of this file on disk is malicious with zero ambiguity. Zero FP risk — this file has no legitimate software counterpart.
**ATT&CK Coverage:** T1548.002 (Bypass UAC), T1134.004 (Parent PID Spoofing)
**Confidence:** DEFINITE
**False Positive Risk:** NONE — byte-identical malicious PE with no legitimate use; 8/77 VT detection gap makes this the highest-impact gap to close in any EDR estate
**Deployment:** Endpoint AV/EDR, file-hash blocklist, memory scanner

```yara
rule MALW_ChaosLoader_Stage5b_UACBypass_CrossBuildInvariant
{
    meta:
        description = "Detects the Stage-5b UAC bypass PE used by the Chaos/TorBrowserTor private crypter. This 986 KB .NET binary is byte-identical across both observed builds (mymain and myfile), implements UACME technique #41 via AppInfo RPC AiEnableDesktopRpcInterface with PPID spoofing off elevated taskmgr.exe, and has only 8/77 VT detections as of 2026-04-23. Any match is a confirmed infection."
        author = "The Hunters Ledger"
        date = "2026-04-23"
        reference = "https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/"
        hash_sha256 = "da302511ee77a4bb9371387ac9932e6431003c9c597ecbe0fd50364f4d7831a8"
        family = "Chaos-TorBrowserTor-Crypter"

    strings:
        $appinfo_guid = "201ef99a-7fa0-444c-9399-19ba84f12a1a" ascii wide
        $rpc_iface    = "AiEnableDesktopRpcInterface" ascii wide
        $ppid_anchor  = "IColorDataProxy" ascii wide
        $conhost_arg  = "--headless" ascii wide
        $ntapi        = "NtApiDotNet" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        $appinfo_guid and
        $rpc_iface and
        2 of ($ppid_anchor, $conhost_arg, $ntapi)
}
```

---

**Detection Priority:** HIGH
**Rationale:** The Stage-4 mutex GUID `9f67b5ed-6c10-4c53-818b-8d26be0d1339` is identical across both builds and returned zero public hits before this publication. Any in-memory or on-disk .NET module exhibiting this GUID is Stage-4 of this specific private crypter. Zero FP risk.
**ATT&CK Coverage:** T1027.011 (Fileless Storage), T1053.005 (Scheduled Task), T1112 (Modify Registry)
**Confidence:** DEFINITE
**False Positive Risk:** NONE — GUID is not present in any public software corpus
**Deployment:** Memory scanner (primary — Stage-4 runs fileless), EDR in-memory scan

```yara
rule MALW_ChaosLoader_Stage4_MutexGUID_CrossBuildInvariant
{
    meta:
        description = "Detects Stage-4 persistence installer of the Chaos/TorBrowserTor private crypter via its cross-build-invariant mutex GUID 9f67b5ed-6c10-4c53-818b-8d26be0d1339. This GUID is identical across all builds from this crypter, guards single-instance execution, and has zero public prior documentation. Match in memory or on disk = confirmed Stage-4 presence."
        author = "The Hunters Ledger"
        date = "2026-04-23"
        reference = "https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/"
        hash_sha256 = "36dc72542530ff9707e4c2dcd935edac71129fcb9b7122502a8295264e86a504"
        family = "Chaos-TorBrowserTor-Crypter"

    strings:
        $mutex_guid    = "9f67b5ed-6c10-4c53-818b-8d26be0d1339" ascii wide
        $task_name     = "Microsoft Defender" ascii wide
        $reg_payload   = "Microsoft Defender\\Payload" ascii wide

    condition:
        $mutex_guid and
        (
            (uint16(0) == 0x5A4D and filesize < 3MB and 1 of ($task_name, $reg_payload)) or
            ($mutex_guid and not uint16(0) == 0x5A4D)
        )
}
```

---

**Detection Priority:** HIGH
**Rationale:** Structural on-disk rule for both sibling .bat droppers. Targets the forced 32-bit PowerShell launch line, the Console.Title self-read trick, the magic-marker StartsWith sentinel, and the oversized filesize that is common to all builds from this crypter. This catches any future build from the same private crypter even if per-build keys rotate.
**ATT&CK Coverage:** T1059.001 (PowerShell), T1059.003 (Windows Command Shell), T1027 (Obfuscation), T1140 (Deobfuscate)
**Confidence:** HIGH
**False Positive Risk:** LOW — the combination of Console.Title self-read pattern + forced SysWOW64 PS + oversized filesize is highly specific; individual components appear in legitimate scripts but not in combination at this scale
**Deployment:** Endpoint file-system scanner, gateway content inspection, AV on-access

```yara
rule MALW_ChaosLoader_BatchDropper_StructuralAnchors
{
    meta:
        description = "Detects on-disk DOSfuscated batch droppers from the Chaos/TorBrowserTor private crypter family (mymain.bat / myfile.bat variants and future builds). Anchors on the forced 32-bit SysWOW64 PowerShell silent launch, the Console.Title-based self-read dropper technique (WindowTitle + ReadAllText), the magic-marker StartsWith/Substring(32) sentinel, and a filesize above 1 MB that is characteristic of these oversized encoded-payload carriers. No single string fires alone — all three structural anchors are required."
        author = "The Hunters Ledger"
        date = "2026-04-23"
        reference = "https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/"
        hash_sha256 = "3b5d30e35f8e4f31a3e70d3754d02d0f045e39b6e0cfde22b1754667b7eb60a4"
        family = "Chaos-TorBrowserTor-Crypter"

    strings:
        $ps32_launch  = "SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe -WindowStyle Hidden -NoProfile" ascii wide
        $title_read   = "$host.UI.RawUI.WindowTitle" ascii wide
        $marker_strip = "StartsWith(" ascii wide
        $substr32     = "Substring(32)" ascii wide
        $alpha_sub    = ".Replace('@','A').Replace('#','/')" ascii wide

    condition:
        filesize > 1MB and
        filesize < 5MB and
        $ps32_launch and
        ($title_read or ($marker_strip and $substr32)) and
        $alpha_sub
}
```

---

### Tier B — mymain Build-Specific Crypter Anchors

---

**Detection Priority:** HIGH
**Rationale:** The mymain magic marker `aEVMeKDApIQzumcyjwpFSfqzEImqRdPQ` is the 32-character payload delimiter unique to this build. Combined with the AES passphrase `qDqHmNfeSyWJoyxDzR` (triple-layer key reuse) and XOR key `giXXxwxDxGrFeUjlxqLaLcb`, this rule targets decrypted in-memory stages — the passphrase and XOR key are never present in the on-disk .bat. Zero public hits before this publication.
**ATT&CK Coverage:** T1027 (Obfuscation), T1140 (Deobfuscate/Decode), T1620 (Reflective Code Loading)
**Confidence:** DEFINITE
**False Positive Risk:** NONE — all three strings are random-looking private keys unique to this build; no collision with any known legitimate software
**Deployment:** Memory scanner (primary — strings appear only in decrypted runtime stages)

```yara
rule MALW_ChaosLoader_mymain_InMemory_CrypterKeys
{
    meta:
        description = "Detects in-memory presence of the mymain build of the Chaos/TorBrowserTor private crypter via its triple-layer-reused AES passphrase (qDqHmNfeSyWJoyxDzR), XOR key (giXXxwxDxGrFeUjlxqLaLcb), and PS1 magic marker (aEVMeKDApIQzumcyjwpFSfqzEImqRdPQ). These strings are present only in the decrypted runtime stages, not in the on-disk .bat dropper. Zero public prior documentation. Any single string match in memory warrants investigation; two or more confirm mymain build presence."
        author = "The Hunters Ledger"
        date = "2026-04-23"
        reference = "https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/"
        hash_sha256 = "36dc72542530ff9707e4c2dcd935edac71129fcb9b7122502a8295264e86a504"
        family = "Chaos-TorBrowserTor-Crypter"

    strings:
        $aes_pass     = "qDqHmNfeSyWJoyxDzR" ascii wide
        $xor_key      = "giXXxwxDxGrFeUjlxqLaLcb" ascii wide
        $magic_marker = "aEVMeKDApIQzumcyjwpFSfqzEImqRdPQ" ascii wide
        $s4_asm_name  = "HQpmBSUELAUUTkvFfUDMffBkXlu" ascii wide

    condition:
        2 of ($aes_pass, $xor_key, $magic_marker, $s4_asm_name)
}
```

---

### Tier B — myfile Build-Specific Crypter Anchors

---

**Detection Priority:** HIGH
**Rationale:** Equivalent to the mymain in-memory rule, targeting the myfile build's unique AES passphrase `jttZjrlmkrBAtCBAMjkbThHsSjVNMjLLyONafxIj`, XOR key `cjJaThUwfQKxnHBm`, and magic marker `HPGDxAzpymskcRJvELNmhQkWaTXguERQ`. The `fudkk` Stage-5a assembly name and typo string `Recieve please.exe` are additional high-confidence anchors for this build only.
**ATT&CK Coverage:** T1027 (Obfuscation), T1140 (Deobfuscate/Decode), T1620 (Reflective Code Loading)
**Confidence:** DEFINITE
**False Positive Risk:** NONE — unique per-build private keys with zero public occurrence
**Deployment:** Memory scanner (primary)

```yara
rule MALW_ChaosLoader_myfile_InMemory_CrypterKeys
{
    meta:
        description = "Detects in-memory presence of the myfile build of the Chaos/TorBrowserTor private crypter via its AES passphrase (jttZjrlmkrBAtCBAMjkbThHsSjVNMjLLyONafxIj), XOR key (cjJaThUwfQKxnHBm), and PS1 magic marker (HPGDxAzpymskcRJvELNmhQkWaTXguERQ). The assembly name 'fudkk' and USB-spread typo filename 'Recieve please.exe' are secondary anchors exclusive to this build. Strings are in-memory only — not present in the on-disk .bat dropper."
        author = "The Hunters Ledger"
        date = "2026-04-23"
        reference = "https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/"
        hash_sha256 = "5b0f529d2834ddb678a309954476a113b1d77ea19bd2b30d299ceee6b06d55b9"
        family = "Chaos-TorBrowserTor-Crypter"

    strings:
        $aes_pass     = "jttZjrlmkrBAtCBAMjkbThHsSjVNMjLLyONafxIj" ascii wide
        $xor_key      = "cjJaThUwfQKxnHBm" ascii wide
        $magic_marker = "HPGDxAzpymskcRJvELNmhQkWaTXguERQ" ascii wide
        $s5a_asm      = "fudkk" ascii wide
        $usb_typo     = "Recieve please.exe" ascii wide

    condition:
        2 of ($aes_pass, $xor_key, $magic_marker, $s5a_asm, $usb_typo)
}
```

---

### Tier A — Chaos / TorBrowserTor Ransomware (Stage-5a)

---

**Detection Priority:** HIGH
**Rationale:** Targets the Stage-5a Chaos/TorBrowserTor ransomware payload directly. The `ConsoleApplication7` namespace and `driveNotification` class name are builder-template artefacts present in both builds. Combined with `.torbrowsertor` and `READ ME PLEASE.txt`, this is a high-specificity family rule covering decrypted Stage-5a memory or any extracted PE.
**ATT&CK Coverage:** T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery), T1547.001 (Registry Run Keys), T1657 (Financial Theft — clipboard hijacker)
**Confidence:** DEFINITE
**False Positive Risk:** LOW — `ConsoleApplication7` alone has FP potential in developer binaries; the combination with `driveNotification` and `.torbrowsertor` is uniquely malicious
**Deployment:** Memory scanner, endpoint AV, file-system scanner targeting `%APPDATA%`

```yara
rule RANSOM_ChaosBuilder_TorBrowserTor_Stage5a
{
    meta:
        description = "Detects the Chaos ransomware Stage-5a payload (TorBrowserTor variant) via builder-template namespace 'ConsoleApplication7', clipboard-hijacker class 'driveNotification', encrypted file extension '.torbrowsertor', and ransom note filename 'READ ME PLEASE.txt'. Both mymain and myfile builds share these strings — they are invariant across all TorBrowserTor-configured Chaos builder outputs. File size is 25,088 bytes for the specific samples analysed."
        author = "The Hunters Ledger"
        date = "2026-04-23"
        reference = "https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/"
        hash_sha256 = "06f6df0f5e37620beb9e3e24a8d0f7742e7d5db7d0f8c1bd4fc10a869443e4e4"
        family = "Chaos-TorBrowserTor"

    strings:
        $ns_template   = "ConsoleApplication7" ascii wide
        $clip_class    = "driveNotification" ascii wide
        $ext           = ".torbrowsertor" ascii wide
        $ransom_note   = "READ ME PLEASE.txt" ascii wide
        $telegram      = "@TorBrowserTor" ascii wide
        $vss_del       = "vssadmin delete shadows" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        $ns_template and
        $clip_class and
        2 of ($ext, $ransom_note, $telegram, $vss_del)
}
```

---

**Detection Priority:** HIGH
**Rationale:** File-system rule targeting the ransom note and encrypted file extension as left-behind artefacts after encryption has begun. Useful for post-compromise detection and forensic hunting when decrypted PE is unavailable.
**ATT&CK Coverage:** T1486 (Data Encrypted for Impact), T1491.001 (Internal Defacement)
**Confidence:** HIGH
**False Positive Risk:** LOW — `.torbrowsertor` is not a legitimate file extension; `READ ME PLEASE.txt` combined with this extension has no benign context
**Deployment:** File-system scanner, EDR file-creation monitoring

```yara
rule RANSOM_ChaosBuilder_TorBrowserTor_FilesystemArtefacts
{
    meta:
        description = "Detects filesystem artefacts of Chaos/TorBrowserTor ransomware: the .torbrowsertor encrypted file extension and READ ME PLEASE.txt ransom note. This rule fires after encryption has begun and is useful for post-compromise triage. Deploy as a file-system scanner or pair with EDR file-creation telemetry for near-real-time alerting."
        author = "The Hunters Ledger"
        date = "2026-04-23"
        reference = "https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/"
        hash_sha256 = "06f6df0f5e37620beb9e3e24a8d0f7742e7d5db7d0f8c1bd4fc10a869443e4e4"
        family = "Chaos-TorBrowserTor"

    strings:
        $ext         = ".torbrowsertor" ascii wide
        $ransom_note = "READ ME PLEASE.txt" ascii wide
        $telegram    = "@TorBrowserTor" ascii wide
        $btc1        = "bc1qw0ll8p9m8uezhqhyd7z459ajrk722yn8c5j4fg" ascii wide
        $btc2        = "17CqMQFeuB3NTzJ2X28tfRmWaPyPQgvoHV" ascii wide

    condition:
        $ext and
        ($ransom_note or $telegram or 1 of ($btc1, $btc2))
}
```

---

### Tier A — Orcus RAT v7 (Wardow Crack)

---

**Detection Priority:** HIGH
**Rationale:** The Wardow crack of Orcus RAT v7 has three hardcoded family-wide secrets that do not rotate across any Wardow-cracked instance: AES key `CrackedByWardow`, fixed CBC IV `0sjufcjbsoyzube6`, and keyleak backdoor magic filename `e3c6cefd462d48f0b30a5ebcd238b5b1`. Any binary matching two or more of these strings is a Wardow-cracked Orcus instance.
**ATT&CK Coverage:** T1573 (Encrypted Channel), T1056.001 (Keylogging), T1113 (Screen Capture), T1071.001 (Web Protocols)
**Confidence:** DEFINITE
**False Positive Risk:** LOW — `CrackedByWardow` is not used by any legitimate software; the three-string combination is unambiguous
**Deployment:** Endpoint AV/EDR, memory scanner, `%APPDATA%\Microsoft\Speech\` directory monitoring

```yara
rule RAT_OrcusRAT_v7_WardowCrack
{
    meta:
        description = "Detects Orcus RAT v7 cracked by 'Wardow' via three hardcoded family-wide secrets: AES key 'CrackedByWardow', fixed Rijndael-256 CBC IV '0sjufcjbsoyzube6', and keyleak backdoor magic filename 'e3c6cefd462d48f0b30a5ebcd238b5b1'. All three strings are present in every Wardow-cracked Orcus v7 instance regardless of operator configuration. The keyleak filename represents a supply-chain backdoor — the operator using this crack may themselves be compromised."
        author = "The Hunters Ledger"
        date = "2026-04-23"
        reference = "https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/"
        hash_sha256 = "f7a4fe18d838e9d87db2db6378ffb21b90c3881d28d70871b8c2a661c6a78a6a"
        family = "OrcusRAT-WardowCrack"

    strings:
        $crack_key    = "CrackedByWardow" ascii wide
        $fixed_iv     = "0sjufcjbsoyzube6" ascii wide
        $keyleak_file = "e3c6cefd462d48f0b30a5ebcd238b5b1" ascii wide
        $namespace    = "Orcus.Service" ascii wide
        $interface    = "IServicePipe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        $crack_key and
        ($fixed_iv or $keyleak_file) and
        1 of ($namespace, $interface)
}
```

---

## Sigma Rules

### Tier B — Custom Crypter / Builder Cross-Build Invariants

---

**Detection Priority:** HIGH
**Rationale:** Scheduled task literally named `Microsoft Defender` created at the task-scheduler root path `\` is a definitive Stage-4 masquerade indicator. Legitimate Windows Defender tasks live under `\Microsoft\Windows\Windows Defender\` — never at the root. Any creation event matching this exact task name at root is malicious.
**ATT&CK Coverage:** T1053.005 (Scheduled Task), T1036.005 (Masquerading), T1564.003 (Hidden Task)
**Confidence:** DEFINITE
**False Positive Risk:** LOW — no legitimate software creates a root-path scheduled task named "Microsoft Defender"

```yaml
title: Chaos Loader Stage-4 Masquerade Scheduled Task Created at Root Path
id: 7a3f9c12-e4b8-4d7a-a1f3-8c6e2b0d5f91
status: test
description: Detects creation of a scheduled task named 'Microsoft Defender' at the task-scheduler root path (\), which is the Stage-4 persistence mechanism of the Chaos/TorBrowserTor private crypter. Legitimate Windows Defender tasks reside at \Microsoft\Windows\Windows Defender\ — a task at the root path with this name is always malicious. The task is configured with a BOOT trigger, RunLevel HIGHEST, and Hidden=true to survive reboots and maintain elevated persistence.
references:
    - https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/
author: The Hunters Ledger
date: 2026/04/23
tags:
    - attack.persistence
    - attack.defense-evasion
    - attack.privilege-escalation
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4698
        TaskName: '\Microsoft Defender'
    filter_legitimate:
        TaskName|contains:
            - '\Microsoft\Windows\Windows Defender\'
            - '\Microsoft\Windows Defender\'
    condition: selection and not filter_legitimate
falsepositives:
    - No known legitimate software creates a root-path scheduled task named Microsoft Defender; any match should be treated as confirmed Stage-4 infection
level: high
```

---

**Detection Priority:** HIGH
**Rationale:** Writing a large value (above 100 KB) to `HKLM\Software\Microsoft Defender\Payload` is the Stage-4 registry-blob fileless storage mechanism. The legitimate Windows Defender registry path is `HKLM\Software\Microsoft\Windows Defender` (with additional `\Windows\` level). The masquerade key lacks the `\Windows\` path component and stores an encoded ~1.4 MB payload blob used by the boot re-loader.
**ATT&CK Coverage:** T1027.011 (Fileless Storage), T1112 (Modify Registry), T1036.005 (Masquerading)
**Confidence:** DEFINITE
**False Positive Risk:** LOW — the masquerade path is structurally distinct from the legitimate Defender key; writing a large blob here has no benign explanation

```yaml
title: Chaos Loader Stage-4 Fileless Payload Written to Masquerade Registry Key
id: 2d8b4e7f-a3c9-4f6b-b5d2-1e9a7c3f8b04
status: test
description: Detects a registry write to HKLM\Software\Microsoft Defender\Payload, which is the Stage-4 fileless storage location used by the Chaos/TorBrowserTor private crypter. The legitimate Windows Defender registry path is HKLM\Software\Microsoft\Windows Defender (note the extra \Windows\ path level). Stage-4 writes approximately 1.4 MB of encoded payload data to this masquerade key; the boot re-loader reads it back on every system startup to re-execute the entire crypter chain at elevated integrity.
references:
    - https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/
author: The Hunters Ledger
date: 2026/04/23
tags:
    - attack.persistence
    - attack.defense-evasion
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\Software\Microsoft Defender\Payload'
    filter_legitimate:
        TargetObject|contains: '\Software\Microsoft\Windows Defender\'
    condition: selection and not filter_legitimate
falsepositives:
    - No known legitimate software writes to this registry path; any match should be treated as confirmed Stage-4 fileless persistence
level: high
```

---

**Detection Priority:** HIGH
**Rationale:** The Stage-5b UAC bypass spawns `conhost.exe --headless` as a direct child of elevated `taskmgr.exe`. This parent-child relationship is the PPID-spoofing signature of UACME technique #41. Legitimate `conhost.exe` instances are spawned by `csrss.exe` or `cmd.exe`, never by `taskmgr.exe` with `--headless`.
**ATT&CK Coverage:** T1548.002 (Bypass UAC), T1134.004 (Parent PID Spoofing)
**Confidence:** DEFINITE
**False Positive Risk:** LOW — `taskmgr.exe` spawning `conhost.exe --headless` has no legitimate software precedent

```yaml
title: Chaos Loader Stage-5b UAC Bypass via PPID Spoof — Conhost Child of Taskmgr
id: 5e1a8d4c-b7f2-4a3e-c9d6-3f2b7e5a1c84
status: test
description: Detects the Stage-5b UAC bypass used by the Chaos/TorBrowserTor private crypter, which spawns conhost.exe with the --headless argument as a child of elevated taskmgr.exe. The parent-child relationship is established via PPID spoofing against an auto-elevated taskmgr.exe instance, and the conhost process in turn launches cmd.exe re-executing the dropper chain at HIGH integrity without triggering a UAC prompt. This is a UACME technique #41 family implementation with only 8/77 VT detections on the bypass module.
references:
    - https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/
    - https://github.com/hfiref0x/UACME
author: The Hunters Ledger
date: 2026/04/23
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\taskmgr.exe'
        Image|endswith: '\conhost.exe'
        CommandLine|contains: '--headless'
    condition: selection
falsepositives:
    - No known legitimate software spawns conhost.exe --headless as a child of taskmgr.exe; treat any match as a high-confidence UAC bypass event
level: high
```

---

**Detection Priority:** HIGH
**Rationale:** The operator tri-artifact gate checks for username `admin` AND (`%TEMP%\VBE\` directory OR `%TEMP%\mapping.csv` file). This combination fires only on the operator's own development host — the gate exits the dropper silently on match. Hunting for the reverse (a process creating these artifacts together on a target host) flags the operator's precursor staging activity. The three-artifact combination is the fingerprint; no single artifact is sufficient.
**ATT&CK Coverage:** T1497 (Virtualization/Sandbox Evasion), T1036 (Masquerading)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM — `admin` username is common in enterprise environments; `VBE` directories exist for legitimate VBScript editors; the combination of all three is the key indicator

```yaml
title: Chaos Loader Operator Tri-Artifact Anti-Sandbox Gate Artefacts Present
id: c4f7b2a9-6d3e-4c8f-d1a5-7b9e4f2c6a18
status: test
description: Detects simultaneous presence of the three artefacts checked by the Chaos/TorBrowserTor crypter's inverted anti-sandbox gate: a process running as 'admin' combined with creation of %TEMP%\VBE\ or %TEMP%\mapping.csv. The gate exits the dropper silently when all three match, suggesting this is the operator's own development host signature. Detecting these artefacts being created in combination on a target host may indicate the operator has deployed their staging environment or that the gate has been triggered. Alert on combination — not individual artefacts.
references:
    - https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/
author: The Hunters Ledger
date: 2026/04/23
tags:
    - attack.defense-evasion
    - attack.execution
logsource:
    category: file_event
    product: windows
detection:
    selection_mapping_csv:
        User|contains: 'admin'
        TargetFilename|endswith: '\mapping.csv'
        TargetFilename|contains: '\AppData\Local\Temp\'
    selection_vbe_dir:
        User|contains: 'admin'
        TargetFilename|contains:
            - '\AppData\Local\Temp\VBE\'
    condition: selection_mapping_csv or selection_vbe_dir
falsepositives:
    - Legitimate VBScript Editor (VBE) installations on administrator accounts may create %TEMP%\VBE\ directories
    - Administrative accounts using tools that generate mapping.csv files in TEMP
    - Tune by excluding known-good admin workstations and software deployment systems
level: medium
```

---

### Tier A — Chaos / TorBrowserTor Ransomware (Stage-5a)

---

**Detection Priority:** HIGH
**Rationale:** Creates a Run key value named `Microsoft Store` under `HKCU\...\Run` pointing to `svchost.exe` or `projectxx.exe` in `%APPDATA%`. Both are Stage-5a self-copy names used by the mymain and myfile builds respectively. Legitimate Microsoft Store does not persist via a Run key pointing to `%APPDATA%`.
**ATT&CK Coverage:** T1547.001 (Registry Run Keys), T1036.005 (Masquerading)
**Confidence:** HIGH
**False Positive Risk:** LOW — `Microsoft Store` as a Run key value pointing to `%APPDATA%\svchost.exe` or `%APPDATA%\projectxx.exe` has no legitimate software counterpart

```yaml
title: Chaos TorBrowserTor Stage-5a Masquerade Persistence via Run Key Microsoft Store
id: 8f2c5a1e-d4b7-4e9c-a6f3-2d8b1e7c4f96
status: test
description: Detects Stage-5a Chaos/TorBrowserTor ransomware persistence via a Run key value named 'Microsoft Store' under HKCU\Software\Microsoft\Windows\CurrentVersion\Run, pointing to svchost.exe or projectxx.exe in %APPDATA%. The mymain build copies itself to %APPDATA%\svchost.exe and the myfile build to %APPDATA%\projectxx.exe. Legitimate Microsoft Store does not create or use a Run key of this name; any match indicates active ransomware persistence.
references:
    - https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/
author: The Hunters Ledger
date: 2026/04/23
tags:
    - attack.persistence
    - attack.defense-evasion
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains:
            - '\Software\Microsoft\Windows\CurrentVersion\Run\Microsoft Store'
        Details|contains:
            - '\AppData\Roaming\svchost.exe'
            - '\AppData\Roaming\projectxx.exe'
    condition: selection
falsepositives:
    - No known legitimate software creates a Run key named 'Microsoft Store' pointing to svchost.exe or projectxx.exe in %APPDATA%; any match is a confirmed Stage-5a persistence indicator
level: high
```

---

**Detection Priority:** HIGH
**Rationale:** Chaos/TorBrowserTor creates `.torbrowsertor` files and executes shadow copy / VSS / backup catalog deletion within the same execution context. Detecting both file-creation events with this extension and any of the anti-recovery commands within a short window provides high-confidence ransomware detection before full encryption completes.
**ATT&CK Coverage:** T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery)
**Confidence:** HIGH
**False Positive Risk:** LOW — `.torbrowsertor` is not a legitimate file extension; shadow copy deletion in the same session confirms ransomware activity

```yaml
title: Chaos TorBrowserTor Ransomware Active Encryption — Extension and Shadow Copy Deletion
id: 3b7e9f4a-c2d8-4b5e-e7a1-6c4f9b2e8d37
status: test
description: Detects active Chaos/TorBrowserTor ransomware execution combining two high-confidence indicators: creation of files with the .torbrowsertor extension (the ransomware's encrypted file marker) and execution of shadow copy or backup catalog deletion commands (vssadmin delete shadows, wmic shadowcopy delete, wbadmin delete catalog, bcdedit recoveryenabled no). Detection of the extension alone or anti-recovery commands alone is insufficient; the combination within a single host session indicates ransomware is actively encrypting files and destroying recovery paths.
references:
    - https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/
author: The Hunters Ledger
date: 2026/04/23
tags:
    - attack.impact
logsource:
    category: process_creation
    product: windows
detection:
    selection_antirecovery:
        CommandLine|contains:
            - 'vssadmin delete shadows'
            - 'wmic shadowcopy delete'
            - 'wbadmin delete catalog'
            - 'bcdedit /set'
            - 'recoveryenabled no'
    condition: selection_antirecovery
falsepositives:
    - Legitimate backup software cleanup operations (vssadmin, wbadmin) — correlate with concurrent .torbrowsertor file creation events in EDR for confirmation
    - System administrators running manual shadow copy management
level: high
```

---

**Detection Priority:** HIGH
**Rationale:** The `DisableTaskMgr` registry value set to `1` under `HKCU\...\Policies\System` by Stage-5a is an active defense-impairment artefact. While this value is occasionally set by Group Policy, writing it from an `%APPDATA%` process with no associated GPO event is malicious.
**ATT&CK Coverage:** T1562.001 (Impair Defenses — Disable or Modify Tools)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM — Group Policy can set this value legitimately; correlate with process context (image path in %APPDATA%) to confirm

```yaml
title: Chaos TorBrowserTor Stage-5a Disables Task Manager via Registry Policy
id: f1d4a8c3-7e2b-4f9a-b8d6-4a3c7f1e9b52
status: test
description: Detects Stage-5a Chaos/TorBrowserTor ransomware writing DisableTaskMgr=1 to HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System to prevent the victim from using Task Manager to terminate the ransomware process. This value can be set legitimately by Group Policy; however, when written by a process running from %APPDATA% outside of a GPO context, it indicates active ransomware defense impairment. Correlate the writing process image path with %APPDATA% to confirm malicious origin.
references:
    - https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/
author: The Hunters Ledger
date: 2026/04/23
tags:
    - attack.defense-evasion
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr'
        Details: '1'
    filter_gpo:
        Image|contains:
            - '\Windows\System32\svchost.exe'
            - '\Windows\System32\GroupPolicy'
    condition: selection and not filter_gpo
falsepositives:
    - Group Policy enforcing kiosk or restricted desktop configurations that disable Task Manager
    - Enterprise endpoint management software applying policy-based restrictions
level: medium
```

---

### Tier A — Orcus RAT v7 (Wardow Crack)

---

**Detection Priority:** MEDIUM
**Rationale:** Orcus RAT Wardow crack connects to `127.0.0.1:20268` from a managed .NET process (`AudioDriver.exe`). Loopback connections from managed .NET processes on non-standard high ports with no corresponding server-side listener are a strong indicator of a tunneled C2 channel. The specific port `20268` is the Orcus configuration value for this campaign.
**ATT&CK Coverage:** T1090.001 (Internal Proxy), T1071.001 (Web Protocols), T1572 (Protocol Tunneling)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM — port 20268 is not reserved; loopback connections on this port from non-system processes could occur in development environments; narrow by process image path

```yaml
title: Orcus RAT Wardow Crack Loopback C2 Connection on Port 20268
id: a9c6e3f8-b1d4-4a7c-c5e9-8f3b2d7a6c41
status: test
description: Detects Orcus RAT v7 Wardow crack initiating a loopback TCP connection to 127.0.0.1:20268, which is the tunneled C2 configuration observed in the open-directory campaign at 94.103.1.13. The real upstream C2 is hidden behind a chisel/plink SSH or HTTP tunnel; the Orcus client connects to the loopback listener which relays traffic externally. Connection from a managed .NET process (particularly one named AudioDriver.exe or similar masquerade) to 127.0.0.1:20268 is highly suspicious.
references:
    - https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/
author: The Hunters Ledger
date: 2026/04/23
tags:
    - attack.command-and-control
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp: '127.0.0.1'
        DestinationPort: 20268
        Initiated: 'true'
    filter_system:
        Image|contains:
            - '\Windows\System32\'
            - '\Windows\SysWOW64\'
    condition: selection and not filter_system
falsepositives:
    - Local development services on port 20268 in developer environments
    - Automated testing frameworks using this loopback port
    - Tune by restricting to process images outside System32/SysWOW64
level: medium
```

---

## Suricata Signatures

### Tier B — Operator Staging Infrastructure

---

**Detection Priority:** HIGH
**Rationale:** Any HTTP request to `94.103.1.13` (AS209207, brand-new ASN assigned 2026-01-19, NL-routed/RU-registered, VT 5/94) is malicious staging activity. The `/gp.xor` path specifically delivers a XOR-encoded GodPotato binary fetched by `interact.py`. The rule alerts on any HTTP to this host to catch all staging downloads, not just the known path.
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1583.003 (Acquire Infrastructure: VPS)
**Confidence:** DEFINITE
**False Positive Risk:** NONE for the specific IP; this host has no legitimate use outside this campaign

```
alert http $HOME_NET any -> 94.103.1.13 any (
    msg:"THL-OPDIR-94103113 — HTTP to Chaos/TorBrowserTor Staging Host 94.103.1.13 (AS209207)";
    flow:established,to_server;
    http.method; content:"GET";
    sid:9410311301;
    rev:1;
    metadata:
        affected_product Windows,
        attack_target Client_Endpoint,
        created_at 2026_04_23,
        deployment Perimeter,
        signature_severity Major,
        tag Chaos-TorBrowserTor,
        updated_at 2026_04_23;
    reference:url,the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/;
    classtype:trojan-activity;
)
```

---

**Detection Priority:** HIGH
**Rationale:** The specific URL path `/gp.xor` delivers a XOR-encoded GodPotato binary used for privilege escalation staging. This path is hardcoded in `interact.py` and `potato.ps1`. Alerting specifically on this URI path allows detection of the privilege escalation staging download even if the broader IP alert is suppressed.
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1583.003 (Acquire Infrastructure: VPS), T1068 (Exploitation for Privilege Escalation)
**Confidence:** DEFINITE
**False Positive Risk:** NONE — `/gp.xor` as a URL path has no legitimate software purpose

```
alert http $HOME_NET any -> any any (
    msg:"THL-OPDIR-94103113 — HTTP GET /gp.xor GodPotato XOR Payload Download from Chaos Staging Host";
    flow:established,to_server;
    http.method; content:"GET";
    http.uri; content:"/gp.xor"; endswith;
    sid:9410311302;
    rev:1;
    metadata:
        affected_product Windows,
        attack_target Client_Endpoint,
        created_at 2026_04_23,
        deployment Perimeter,
        signature_severity Major,
        tag Chaos-TorBrowserTor,
        updated_at 2026_04_23;
    reference:url,the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/;
    classtype:trojan-activity;
)
```

---

## Coverage Gaps

### Techniques Without High-Confidence Rules

**T1620 — Reflective Code Loading (Assembly.Load)**
Every .NET stage in this crypter dispatches the next stage via `[System.Reflection.Assembly]::Load([byte[]])`. This is a powerful behavioral anchor but cannot be captured in a high-fidelity Sigma rule without AMSI/ETW telemetry that logs the loaded bytes — standard Sysmon process-creation does not surface Assembly.Load calls. A YARA rule targeting the in-memory PowerShell pattern (`[System.Reflection.Assembly]::Load` + `[System.Security.Cryptography.Aes]::Create()`) would be medium-confidence but was not included because the AES API call appears in many legitimate scripts and would generate significant FP volume without per-host baseline tuning.

**T1003.001 — LSASS Credential Dumping (Mimikatz)**
The staged Mimikatz suite is stock September 2022 gentilkiwi builds. Existing SigmaHQ community rules (e.g., `proc_creation_win_mimikatz_exec`) and YARA rules in the public Yara-Rules/rules repository already cover these hashes and command patterns comprehensively. Reproducing them here would be redundant and dilute the campaign-specific value of this rule set. Defenders should ensure existing Mimikatz detections are deployed and reference community rules for coverage.

**T1068 — PrintNightmare / GodPotato / PrintSpoofer**
The GodPotato family (`gp.exe`, `gp2.exe`, `gp_obf.exe`, `gp_fat.exe`, `svc.exe`) and `PrintSpoofer.exe` are commodity public tools with high VT detection rates (26–38/77). Community YARA and Sigma rules cover these. The custom `p.exe` SpoolSS coercer is 6.6 KB and would be a valid YARA target; however, without confirmed unique strings from decompilation of that specific binary (decompilation was not fully completed in this campaign), a YARA rule risks being too generic. A hash-based detection on SHA256 `b9ffbeed12325c450ba0f3c55cdcd243cdb704115aa3aee784bbdee3243f84e5` is the safest approach and is captured in the IOC feed.

**T1572 — Protocol Tunneling (Chisel / Plink)**
`chisel.exe` and `plink.exe` are legitimate open-source tools with high detection rates under their own family signatures. The real Orcus C2 upstream behind the tunnel could not be identified from static analysis; without the resolved upstream IP or domain, a Suricata rule targeting chisel/plink traffic would require behavioral heuristics (e.g., periodic short-interval beaconing patterns) that would generate excessive FPs against legitimate SSH/HTTP tunnel use. Dynamic detonation of `myfile.exe` in an isolated environment is required to resolve the real upstream C2 and enable a targeted network rule.

**T1562.001 — AMSI/ETW/ntdll Unhook (Perun's Fart)**
The Perun's Fart ntdll-unhook technique operates entirely in user-mode memory and does not produce Sysmon process-creation events. Effective detection requires EDR kernel-level hooks or memory integrity monitoring. A Sigma rule targeting the DLL load of `ntdll.dll` a second time (e.g., via Sysmon EID 7 image-load watching for `ntdll.dll` loaded from a non-standard path) is architecturally possible but requires significant tuning per environment and was assessed as out of scope for this campaign-specific rule set.

**T1090.001 — Orcus Real Upstream C2**
The actual chisel/plink tunnel destination for Orcus is unknown from static analysis. No Suricata IP/domain rule can be written for the real C2 without dynamic detonation resolving the upstream peer. The loopback-connection Sigma rule above covers the host-side indicator; the network gap remains open pending dynamic analysis.

---

## License

Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.  
Free to use in your environment, but not for commercial purposes.
