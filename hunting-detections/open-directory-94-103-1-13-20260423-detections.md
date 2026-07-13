---
title: "Detection Rules — Chaos Ransomware (TorBrowserTor) Multi-Stage Loader — Open Directory 94.103.1.13"
date: '2026-04-23'
layout: post
permalink: /hunting-detections/open-directory-94-103-1-13-20260423-detections/
thumbnail: /assets/images/cards/open-directory-94-103-1-13-20260423.png
hide: true
---

**Campaign:** open-directory-94-103-1-13-20260423
**Date:** 2026-04-23
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/open-directory-94-103-1-13-20260423/

---

## Detection Coverage Summary

This campaign delivers Chaos ransomware (TorBrowserTor variant) through a private batch-file crypter/loader observed in two parallel builds (`mymain.bat` and `myfile.bat`) staged from an open directory. The same loader also stages an Orcus RAT v7 instance cracked by "Wardow," a GodPotato-based privilege-escalation chain, and an operator-controlled backdoor local account. Coverage below is retiered into Detection (high-fidelity, alerting-grade) and Hunting (broader, analyst-triaged) rules.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 6 | 2 | T1027, T1027.011, T1053.005, T1056.001, T1059.001, T1059.003, T1071.001, T1112, T1113, T1134.004, T1140, T1486, T1490, T1491.001, T1547.001, T1548.002, T1573, T1620, T1657 | 0 |
| Sigma | 3 | 8 | T1027.011, T1036.005, T1053.005, T1071.001, T1078.003, T1090.001, T1112, T1134.004, T1136.001, T1486, T1490, T1497, T1547.001, T1548.002, T1685 | 0 |
| Suricata | 0 | 1 | T1071.001, T1105 | 1 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchors:**
- Stage-4 mutex GUID `9f67b5ed-6c10-4c53-818b-8d26be0d1339` and Stage-5b UAC-bypass PE hash `da302511ee77a4bb9371387ac9932e6431003c9c597ecbe0fd50364f4d7831a8` — byte-identical across both observed builds, zero public prior hits (YARA Detection).
- Stage-5b UAC-bypass process ancestry `taskmgr.exe` → `conhost.exe --headless` — a PPID-spoofing technique chokepoint that survives any future rebuild (Sigma Detection).
- `CrackedByWardow` AES key and fixed IV — hardcoded crack-tool-wide constants shared by every Orcus instance patched with this specific crack, not unique to this operator (YARA Detection).

**Atomics routed to the IOC feed:** the operator staging host `94.103.1.13` is a transient indicator — a Suricata signature keyed on the IP alone (with no content/protocol anchor beyond a bare HTTP GET) stops detecting the moment the host is abandoned. The underlying IP is already carried with full context in [`open-directory-94-103-1-13-20260423-iocs.json`](/ioc-feeds/open-directory-94-103-1-13-20260423-iocs.json) — no new feed entries were required. Block it via the feed.

---

## Multi-Family Organization

Rules are grouped by family within each Detection/Hunting subsection (this replaces the original Tier A / Tier B framing, which measured novelty rather than alerting fidelity):

- **Custom Crypter / Builder** — the private loader/crypter that stages and persists all subsequent payloads. Cross-build invariants (Stage-4 mutex GUID, Stage-5b UAC-bypass PE, structural decode-pipeline anchors) are Detection-grade; per-build in-memory key material (mymain/myfile) and masquerade artifact names chosen for this build only are Hunting-grade.
- **Chaos / TorBrowserTor Ransomware** — the Stage-5a encryption payload.
- **Orcus RAT v7 (Wardow Crack)** — the secondary RAT staged alongside the ransomware.
- **Operator Backdoor Account** — the Stage-2 GodPotato-privileged local account creation (added in the 2026-05-02 follow-up).

---

## YARA Rules

### Detection Rules

**Custom Crypter / Builder**

#### Stage-5b UAC Bypass PE (Cross-Build Invariant)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1548.002 (Bypass UAC), T1134.004 (Parent PID Spoofing)
**Confidence:** DEFINITE
**Rationale:** The AppInfo RPC interface GUID and `AiEnableDesktopRpcInterface` name are the fixed Windows chokepoint UACME technique #41 must call — an attacker cannot rename them without abandoning the technique. The rule additionally requires 2 of 3 corroborating strings ($ppid_anchor, $conhost_arg, $ntapi) tied to this specific loader's implementation choices (the NtApiDotNet library, the `--headless` conhost invocation, and the `IColorDataProxy` interface name), which is why this sits at Robustness 2 rather than 3: the technique-level anchor is durable, but the required corroboration is implementation-specific. This exact PE is byte-identical across both observed builds (mymain and myfile) with only 8/77 VT detections.
**False Positives:** Low — legitimate red-team or research tooling built on NtApiDotNet that implements the same UACME #41 technique with the same conhost `--headless` invocation would also match; no known legitimate production software does.
**Blind Spots:** A rebuild that drops NtApiDotNet in favor of raw RPC calls, or renames the `IColorDataProxy` interface and changes the conhost launch flag, would evade the corroborating-string requirement even though the core AppInfo GUID/RPC-name anchor remains.
**Validation:** Scan the Stage-5b PE (`hash1` below) or a memory dump containing it — must match; a benign NtApiDotNet-based admin utility that never calls `AiEnableDesktopRpcInterface` must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, memory scanner (Stage-5b is delivered encrypted and only exists in cleartext post-decryption).

```yara
/*
   Yara Rule Set
   Identifier: Chaos TorBrowserTor Multi-Stage Loader — Open Directory 94.103.1.13
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule MALW_ChaosLoader_Stage5b_UACBypass_CrossBuildInvariant {
   meta:
      description = "Detects the Stage-5b UAC bypass PE used by the Chaos/TorBrowserTor private crypter. This 986 KB .NET binary is byte-identical across both observed builds (mymain and myfile), implements UACME technique #41 via AppInfo RPC AiEnableDesktopRpcInterface with PPID spoofing off elevated taskmgr.exe, and has only 8/77 VT detections as of 2026-04-23"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/"
      date = "2026-04-23"
      hash1 = "da302511ee77a4bb9371387ac9932e6431003c9c597ecbe0fd50364f4d7831a8"
      family = "Chaos-TorBrowserTor-Crypter"
      id = "c285c670-de23-5ad9-b45b-3939751f50c2"
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

#### Stage-4 Mutex GUID (Cross-Build Invariant)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1027.011 (Fileless Storage), T1053.005 (Scheduled Task), T1112 (Modify Registry)
**Confidence:** DEFINITE
**Rationale:** The mutex GUID is byte-identical across two independently-compiled builds (mymain and myfile), which is strong evidence it is hardcoded in the crypter's shared Stage-4 source template rather than regenerated per build — a `Guid.NewGuid()` call would have produced two different values. That makes it a tool-family artifact rather than a one-off masquerade string.
**False Positives:** None known — the GUID has zero public prior hits and is not present in any known legitimate software.
**Blind Spots:** A future builder revision that regenerates this GUID per build would evade the rule; the non-PE branch of the condition matches on the mutex string alone, which is intentional (Stage-4 runs fileless and may only exist as a raw memory region).
**Validation:** Scan a memory region or extracted Stage-4 module — the mutex GUID must match; a benign .NET binary with an unrelated GUID mutex must NOT fire.
**Deployment:** Memory scanner (primary — Stage-4 runs fileless), EDR in-memory scan.

```yara
rule MALW_ChaosLoader_Stage4_MutexGUID_CrossBuildInvariant {
   meta:
      description = "Detects Stage-4 persistence installer of the Chaos/TorBrowserTor private crypter via its cross-build-invariant mutex GUID 9f67b5ed-6c10-4c53-818b-8d26be0d1339. This GUID is identical across all observed builds from this crypter, guards single-instance execution, and has zero public prior documentation"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/"
      date = "2026-04-23"
      hash1 = "36dc72542530ff9707e4c2dcd935edac71129fcb9b7122502a8295264e86a504"
      family = "Chaos-TorBrowserTor-Crypter"
      id = "7f048cca-1b0f-5c3e-8304-944fde6d4063"
   strings:
      $mutex_guid  = "9f67b5ed-6c10-4c53-818b-8d26be0d1339" ascii wide
      $task_name   = "Microsoft Defender" ascii wide
      $reg_payload = "Microsoft Defender\\Payload" ascii wide
   condition:
      $mutex_guid and
      (
         (uint16(0) == 0x5A4D and filesize < 3MB and 1 of ($task_name, $reg_payload)) or
         ($mutex_guid and not uint16(0) == 0x5A4D)
      )
}
```

#### Batch Dropper Structural Anchors

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1059.001 (PowerShell), T1059.003 (Windows Command Shell), T1027 (Obfuscation), T1140 (Deobfuscate/Decode)
**Confidence:** HIGH
**Rationale:** The forced SysWOW64 PowerShell launch line and the `.Replace('@','A').Replace('#','/')` alphabet-substitution trick are both flagged as builder-wide structural anchors present in both observed builds — these are decode-pipeline mechanics baked into the crypter's own code, not per-victim literals, so they survive a rebuild that only rotates keys and filenames.
**False Positives:** Low — the combination of forced 32-bit PowerShell invocation, the Console.Title self-read pattern, and the specific alphabet-substitution string is highly specific; individual components appear in legitimate scripts but not in this combination at this file size.
**Blind Spots:** A builder revision that changes the decode alphabet or drops the forced-SysWOW64 launch (e.g., moving to native 64-bit PowerShell) would evade this rule; targets on-disk `.bat` files only, not the loader once it has fully decoded into memory.
**Validation:** Scan `mymain.bat` / `myfile.bat` (hashes below) or a future build sharing the same decode pipeline — must match; a legitimate oversized PowerShell deployment script must NOT fire.
**Deployment:** Endpoint file-system scanner, gateway content inspection, AV on-access scan.

```yara
rule MALW_ChaosLoader_BatchDropper_StructuralAnchors {
   meta:
      description = "Detects on-disk DOSfuscated batch droppers from the Chaos/TorBrowserTor private crypter family (mymain.bat / myfile.bat and future builds sharing the same decode pipeline). Anchors on the forced 32-bit SysWOW64 PowerShell silent launch, the Console.Title-based self-read dropper technique, the magic-marker StartsWith/Substring(32) sentinel, and a filesize above 1 MB characteristic of these oversized encoded-payload carriers"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/"
      date = "2026-04-23"
      hash1 = "3b5d30e35f8e4f31a3e70d3754d02d0f045e39b6e0cfde22b1754667b7eb60a4"
      family = "Chaos-TorBrowserTor-Crypter"
      id = "d5623640-8394-5151-881a-f3c38ac12bcb"
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

**Chaos / TorBrowserTor Ransomware**

#### Stage-5a Ransomware Payload

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery), T1547.001 (Registry Run Keys), T1657 (Financial Theft — clipboard hijacker)
**Confidence:** DEFINITE
**Rationale:** `ConsoleApplication7` and `driveNotification` are Chaos-builder template artifacts, not indicators unique to this operator — a public sibling sample (`d0c78ca7...`) confirms the same namespace and class names appear across unrelated Chaos/TorBrowserTor deployments. That makes the combination a durable, family-wide anchor rather than a one-off literal: it survives this operator's key rotation and would also catch other operators using the same builder configuration.
**False Positives:** Low — `ConsoleApplication7` alone has FP potential in unrelated developer test binaries left at default Visual Studio naming; the required combination with `driveNotification` plus 2 of the remaining four strings is uniquely malicious.
**Blind Spots:** A Chaos builder release that changes its default namespace/class template would evade the mandatory anchors; targets on-disk or decrypted-in-memory PE content, not the on-disk `.bat` dropper before decode.
**Validation:** Scan the decrypted Stage-5a PE (hash below) — must match; an unrelated .NET console application using default Visual Studio naming alone must NOT fire (the `driveNotification` requirement prevents this).
**Deployment:** Memory scanner, endpoint AV, file-system scanner targeting `%APPDATA%`.

```yara
rule RANSOM_ChaosBuilder_TorBrowserTor_Stage5a {
   meta:
      description = "Detects the Chaos ransomware Stage-5a payload (TorBrowserTor variant) via builder-template namespace 'ConsoleApplication7', clipboard-hijacker class 'driveNotification', encrypted file extension '.torbrowsertor', and ransom note filename 'READ ME PLEASE.txt'. Both mymain and myfile builds share these strings, and a public sibling sample confirms they are invariant across Chaos/TorBrowserTor-configured builder outputs generally, not unique to this operator"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/"
      date = "2026-04-23"
      hash1 = "06f6df0f5e37620beb9e3e24a8d0f7742e7d5db7d0f8c1bd4fc10a869443e4e4"
      family = "Chaos-TorBrowserTor"
      id = "56ac337e-11e3-5cff-bfff-7a58bf113951"
   strings:
      $ns_template = "ConsoleApplication7" ascii wide
      $clip_class  = "driveNotification" ascii wide
      $ext         = ".torbrowsertor" ascii wide
      $ransom_note = "READ ME PLEASE.txt" ascii wide
      $telegram    = "@TorBrowserTor" ascii wide
      $vss_del     = "vssadmin delete shadows" ascii wide nocase
   condition:
      uint16(0) == 0x5A4D and
      filesize < 500KB and
      $ns_template and
      $clip_class and
      2 of ($ext, $ransom_note, $telegram, $vss_del)
}
```

#### Filesystem Artefacts (Post-Encryption)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1486 (Data Encrypted for Impact), T1491.001 (Internal Defacement)
**Confidence:** HIGH
**Rationale:** The `.torbrowsertor` extension is the defining marker of this Chaos-builder configuration and is shared across the family, not just this operator's two builds — durable against this operator's own key rotation. The two BTC wallets are confirmed builder defaults (reused across unrelated Chaos/TorBrowserTor campaigns per wallet-cluster analysis), which similarly makes them stable detection anchors even though they carry low attribution value for this specific operator.
**False Positives:** None known — `.torbrowsertor` is not a legitimate file extension; `READ ME PLEASE.txt` combined with this extension, or either wallet address, has no benign context.
**Blind Spots:** A builder release that changes the configured extension, note filename, or default wallets would evade the rule; scans filenames/content, not the live encryption process itself.
**Validation:** Scan a directory tree containing `.torbrowsertor`-suffixed files or the ransom note — must match; an unrelated `.torbrowsertor`-free directory must NOT fire.
**Deployment:** File-system scanner, EDR file-creation monitoring.

```yara
rule RANSOM_ChaosBuilder_TorBrowserTor_FilesystemArtefacts {
   meta:
      description = "Detects filesystem artefacts of Chaos/TorBrowserTor ransomware: the .torbrowsertor encrypted file extension, the READ ME PLEASE.txt ransom note, the @TorBrowserTor Telegram contact handle, and the two Chaos-builder default BTC wallets used by the clipboard hijacker. Useful for post-compromise triage when a decrypted PE is unavailable"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/"
      date = "2026-04-23"
      hash1 = "06f6df0f5e37620beb9e3e24a8d0f7742e7d5db7d0f8c1bd4fc10a869443e4e4"
      family = "Chaos-TorBrowserTor"
      id = "0e5f3296-dc2e-52ab-b565-d74d2fb92e3b"
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

**Orcus RAT v7 (Wardow Crack)**

#### Orcus RAT v7 Wardow Crack

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1573 (Encrypted Channel), T1056.001 (Keylogging), T1113 (Screen Capture), T1071.001 (Web Protocols)
**Confidence:** DEFINITE
**Rationale:** `CrackedByWardow`, the fixed IV, and the keyleak magic filename are hardcoded by the crack tool itself, not by any individual operator — every binary patched with this specific crack carries these same three constants regardless of which victim or campaign it is deployed against. This is as durable as a static-string anchor gets: renaming the payload or rotating C2 infrastructure has no effect on it.
**False Positives:** None known — `CrackedByWardow` is not used by any legitimate software; the required combination is unambiguous.
**Blind Spots:** Evaded by an un-cracked or differently-cracked Orcus v7 build, or a future crack revision that changes these constants; does not cover the underlying Orcus RAT family broadly, only this specific crack.
**Validation:** Scan `myfile.exe` (hash below) or any other Wardow-cracked Orcus sample — must match; a stock (non-cracked) Orcus v7 build must NOT fire.
**Deployment:** Endpoint AV/EDR, memory scanner, `%APPDATA%\Microsoft\Speech\` directory monitoring.

```yara
rule RAT_OrcusRAT_v7_WardowCrack {
   meta:
      description = "Detects Orcus RAT v7 cracked by 'Wardow' via three hardcoded crack-tool-wide secrets: AES key 'CrackedByWardow', fixed Rijndael-256 CBC IV '0sjufcjbsoyzube6', and keyleak backdoor magic filename 'e3c6cefd462d48f0b30a5ebcd238b5b1'. All three strings are present in every Wardow-cracked Orcus v7 instance regardless of operator configuration. The keyleak filename represents a supply-chain backdoor — the operator using this crack may themselves be compromised"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/"
      date = "2026-04-23"
      hash1 = "f7a4fe18d838e9d87db2db6378ffb21b90c3881d28d70871b8c2a661c6a78a6a"
      hash2 = "1e68314f5a42897cea61456add6ffdd6048a9c99"
      hash3 = "76007508b8317dd76e31996c6adc875a"
      family = "OrcusRAT-WardowCrack"
      id = "df88eae9-5f1a-5a5a-a162-643f53ce2ab8"
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

### Hunting Rules

**Custom Crypter / Builder — Build-Specific Anchors**

#### mymain Build In-Memory Crypter Keys

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1027 (Obfuscation), T1140 (Deobfuscate/Decode), T1620 (Reflective Code Loading)
**Confidence:** DEFINITE (behavior) / build-specific (durability)
**Rationale:** All four strings are randomized key material generated for the mymain build specifically (AES passphrase, XOR key, magic marker, and Stage-4 assembly name) — unlike the Stage-4 mutex GUID and Stage-5b PE hash, there is no cross-build evidence these are hardcoded builder constants rather than per-campaign key material. A future build would plausibly regenerate all four together, so durability governs over today's clean precision: this stays Hunting rather than Detection despite zero known false positives.
**False Positives:** None known — all three strings are random-looking private keys unique to this build with no collision against any known legitimate software.
**Deployment:** Memory scanner (primary — strings appear only in decrypted runtime stages, not in the on-disk `.bat`).

```yara
rule MALW_ChaosLoader_mymain_InMemory_CrypterKeys {
   meta:
      description = "Detects in-memory presence of the mymain build of the Chaos/TorBrowserTor private crypter via its triple-layer-reused AES passphrase (qDqHmNfeSyWJoyxDzR), XOR key (giXXxwxDxGrFeUjlxqLaLcb), and PS1 magic marker (aEVMeKDApIQzumcyjwpFSfqzEImqRdPQ). These strings are present only in the decrypted runtime stages, not in the on-disk .bat dropper, and are specific to this build — a future build would likely regenerate them"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/"
      date = "2026-04-23"
      hash1 = "36dc72542530ff9707e4c2dcd935edac71129fcb9b7122502a8295264e86a504"
      family = "Chaos-TorBrowserTor-Crypter"
      id = "7d4d1020-ee25-5033-85c6-0d865e59a31a"
   strings:
      $aes_pass     = "qDqHmNfeSyWJoyxDzR" ascii wide
      $xor_key      = "giXXxwxDxGrFeUjlxqLaLcb" ascii wide
      $magic_marker = "aEVMeKDApIQzumcyjwpFSfqzEImqRdPQ" ascii wide
      $s4_asm_name  = "HQpmBSUELAUUTkvFfUDMffBkXlu" ascii wide
   condition:
      2 of ($aes_pass, $xor_key, $magic_marker, $s4_asm_name)
}
```

#### myfile Build In-Memory Crypter Keys

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1027 (Obfuscation), T1140 (Deobfuscate/Decode), T1620 (Reflective Code Loading)
**Confidence:** DEFINITE (behavior) / build-specific (durability)
**Rationale:** Equivalent to the mymain rule above, targeting the myfile build's unique key material and its USB-spread self-copy typo filename `Recieve please.exe`. Same durability caveat: these are per-build literals, not confirmed cross-build invariants.
**False Positives:** None known — unique per-build private keys and filename with zero public occurrence.
**Deployment:** Memory scanner (primary).

```yara
rule MALW_ChaosLoader_myfile_InMemory_CrypterKeys {
   meta:
      description = "Detects in-memory presence of the myfile build of the Chaos/TorBrowserTor private crypter via its AES passphrase (jttZjrlmkrBAtCBAMjkbThHsSjVNMjLLyONafxIj), XOR key (cjJaThUwfQKxnHBm), and PS1 magic marker (HPGDxAzpymskcRJvELNmhQkWaTXguERQ). The assembly name 'fudkk' and USB-spread typo filename 'Recieve please.exe' are secondary anchors exclusive to this build. Strings are in-memory only — not present in the on-disk .bat dropper"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/"
      date = "2026-04-23"
      hash1 = "5b0f529d2834ddb678a309954476a113b1d77ea19bd2b30d299ceee6b06d55b9"
      family = "Chaos-TorBrowserTor-Crypter"
      id = "4c682cce-4c58-5a0f-b1c5-4f53afa5724e"
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

## Sigma Rules

### Detection Rules

**Custom Crypter / Builder**

#### Stage-5b UAC Bypass via PPID Spoof — Conhost Child of Taskmgr

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1548.002 (Bypass UAC), T1134.004 (Parent PID Spoofing)
**Confidence:** DEFINITE
**Rationale:** This keys on process ancestry and a command-line flag, not an attacker-chosen cosmetic name — `taskmgr.exe` is a fixed OS binary, and `conhost.exe --headless` spawned directly from it is the PPID-spoofing mechanics of UACME technique #41 itself. The rule survives any future rebuild that keeps using this specific bypass technique, regardless of file renaming or hash rotation.
**False Positives:** None known — `taskmgr.exe` spawning `conhost.exe --headless` has no legitimate software precedent.
**Blind Spots:** A rebuild that switches to a different UAC-bypass technique (a different auto-elevated donor process, or a technique that doesn't spawn conhost) evades this rule entirely.
**Validation:** Trigger the Stage-5b module — the process-ancestry match must fire; a user manually opening an elevated Task Manager for normal administration must NOT fire (Task Manager does not spawn conhost/cmd children during normal use).
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (process-creation telemetry).

```yaml
title: Chaos Loader Stage-5b UAC Bypass via PPID Spoof — Conhost Child of Taskmgr
id: 5e1a8d4c-b7f2-4a3e-c9d6-3f2b7e5a1c84
status: experimental
description: >-
  Detects the Stage-5b UAC bypass used by the Chaos/TorBrowserTor private
  crypter, which spawns conhost.exe with the --headless argument as a
  child of elevated taskmgr.exe. The parent-child relationship is
  established via PPID spoofing against an auto-elevated taskmgr.exe
  instance, and the conhost process in turn launches cmd.exe re-executing
  the dropper chain at HIGH integrity without triggering a UAC prompt.
  This is a UACME technique #41 family implementation with only 8/77 VT
  detections on the bypass module.
references:
    - https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/
    - https://github.com/hfiref0x/UACME
author: The Hunters Ledger
date: 2026-04-23
tags:
    - attack.stealth
    - attack.privilege-escalation
    - attack.t1548.002
    - attack.t1134.004
    - detection.emerging-threats
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
    - >-
      No known legitimate software spawns conhost.exe --headless as a
      child of taskmgr.exe; treat any match as a high-confidence UAC
      bypass event
level: high
```

**Chaos / TorBrowserTor Ransomware**

#### Encrypted File Extension Created + Anti-Recovery Command Correlation

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery)
**Confidence:** HIGH
**Rationale:** Corrected from the original: the published rule's title and description described a correlation between `.torbrowsertor` file creation and anti-recovery command execution, but the `detection:` block never implemented the extension-creation half — the condition matched only the generic anti-recovery commands (`selection_antirecovery`) alone, which is common to legitimate backup-cleanup activity as well as most ransomware families. This is now two base rules plus a genuine Sigma correlation: the `.torbrowsertor` extension is a durable, family-wide anchor (Chaos-builder invariant, not this operator's own choice — see the YARA filesystem-artefacts rule), and requiring it alongside an anti-recovery command on the same host within a 10-minute window is a materially higher-fidelity signal than either alone.
**False Positives:** None known — `.torbrowsertor` is not a legitimate extension, and the co-occurrence of a distinctive extension-creation burst with shadow-copy/backup destruction on the same host within minutes has no benign explanation.
**Blind Spots:** Requires both base rules' logsources (`file_event` and `process_creation`) to be collected and correlatable by `Computer`; a host with only one telemetry source enabled will not produce the correlation match (though the extension-creation base rule alone still fires as Detection-tier).
**Validation:** Trigger Stage-5a end-to-end — both the extension-creation and anti-recovery-command base rules must fire within the window and the correlation must match; a legitimate backup job deleting shadow copies with no `.torbrowsertor` files present anywhere on the host must NOT trigger the correlation.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (file-creation + process-creation telemetry, correlated).

```yaml
title: Chaos TorBrowserTor Ransomware Encrypted File Extension Created
name: chaos_torbrowsertor_extension_created
id: 3faf111a-bcf8-479e-9e7c-7e0ae94e0483
status: experimental
description: >-
  Detects creation of a file with the .torbrowsertor extension, the
  encrypted-file marker appended by Chaos/TorBrowserTor ransomware during
  its encryption routine. This extension is a Chaos-builder-configuration
  invariant confirmed on a public sibling sample, not specific to this
  operator, and has no legitimate use.
references:
    - https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/
author: The Hunters Ledger
date: 2026-04-23
tags:
    - attack.impact
    - attack.t1486
    - detection.emerging-threats
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '.torbrowsertor'
    condition: selection
falsepositives:
    - Unlikely — .torbrowsertor is not a legitimate file extension
level: high
---
title: Chaos TorBrowserTor Anti-Recovery / Shadow Copy Deletion Commands Executed
name: chaos_antirecovery_commands
id: 3b7e9f4a-c2d8-4b5e-e7a1-6c4f9b2e8d37
status: experimental
description: >-
  Detects execution of shadow-copy or backup-catalog deletion commands
  (vssadmin delete shadows, wmic shadowcopy delete, wbadmin delete
  catalog, bcdedit recoveryenabled no) associated with Stage-5a
  Chaos/TorBrowserTor ransomware anti-recovery behavior. Tier: Hunting
  standalone (see the Hunting Rules subsection below for the full
  Rationale/False Positives writeup) — a generic command pattern shared
  with legitimate backup tooling and most other ransomware families.
  Co-located in this YAML block, rather than presented only in the
  Hunting section, because the correlation rule that follows must
  resolve this rule by name within the same Sigma document.
references:
    - https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/
author: The Hunters Ledger
date: 2026-04-23
tags:
    - attack.impact
    - attack.t1490
    - detection.emerging-threats
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
    - >-
      Legitimate backup software cleanup operations (vssadmin, wbadmin)
      — correlate with concurrent .torbrowsertor file creation events for
      confirmation
    - System administrators running manual shadow copy management
level: medium
---
title: Chaos TorBrowserTor Ransomware Active Encryption — Extension and Anti-Recovery Command Correlation
id: ba89a60f-33f2-45aa-8a49-3beacdc24917
status: experimental
description: >-
  Correlates creation of .torbrowsertor-extension files with execution of
  shadow-copy or backup-catalog deletion commands on the same host within
  a 10-minute window, indicating active Chaos/TorBrowserTor ransomware
  encryption combined with anti-recovery measures. Either signal alone is
  a Hunting-tier lead (see the standalone base rules); the combination is
  Detection-grade.
references:
    - https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/
author: The Hunters Ledger
date: 2026-04-23
tags:
    - attack.impact
    - attack.t1486
    - attack.t1490
    - detection.emerging-threats
correlation:
    type: temporal
    rules:
        - chaos_torbrowsertor_extension_created
        - chaos_antirecovery_commands
    group-by:
        - Computer
    timespan: 10m
level: high
```

### Hunting Rules

**Custom Crypter / Builder**

#### Stage-4 Masquerade Scheduled Task Created at Root Path

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1053.005 (Scheduled Task), T1036.005 (Masquerading)
**Confidence:** DEFINITE (for this build) / build-specific (durability)
**Rationale:** "Microsoft Defender" is an attacker-chosen masquerade name picked purely for stealth — the operator has no functional reason to keep it stable, and a future build could trivially rename it to any other plausible system-component name. Durability governs over today's clean precision (no legitimate root-path task uses this exact name), so this is Hunting rather than Detection. No Sysmon/Security-log field reliably exposes the task's RunLevel or trigger type as a separate queryable field, so a name-independent technique-level rewrite (root-path + elevated + boot-trigger) was not attempted — it would require guessing at field availability rather than working from confirmed telemetry.
**False Positives:** No known legitimate software creates a root-path scheduled task named "Microsoft Defender" — but the anchor is a renameable literal, not a technique invariant.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (Windows Security auditing, Event 4698).

```yaml
title: Chaos Loader Stage-4 Masquerade Scheduled Task Created at Root Path
id: 7a3f9c12-e4b8-4d7a-a1f3-8c6e2b0d5f91
status: experimental
description: >-
  Detects creation of a scheduled task named 'Microsoft Defender' at the
  task-scheduler root path (\), which is the Stage-4 persistence
  mechanism of the Chaos/TorBrowserTor private crypter. Legitimate
  Windows Defender tasks reside at \Microsoft\Windows\Windows Defender\
  — a task at the root path with this name is always malicious for this
  build. The task is configured with a BOOT trigger, RunLevel HIGHEST,
  and Hidden=true to survive reboots and maintain elevated persistence.
  The task name is attacker-chosen and may rotate in a future build.
references:
    - https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/
author: The Hunters Ledger
date: 2026-04-23
tags:
    - attack.persistence
    - attack.stealth
    - attack.privilege-escalation
    - attack.execution
    - attack.t1053.005
    - attack.t1036.005
    - detection.emerging-threats
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
    - >-
      No known legitimate software creates a root-path scheduled task
      named Microsoft Defender for THIS build; a future build renaming
      the masquerade task name would evade this rule entirely
level: medium
```

#### Stage-4 Fileless Payload Written to Masquerade Registry Key

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1027.011 (Fileless Storage), T1112 (Modify Registry), T1036.005 (Masquerading)
**Confidence:** DEFINITE (for this build) / build-specific (durability)
**Rationale:** Same durability caveat as the scheduled-task rule above — `Microsoft Defender\Payload` is an attacker-chosen masquerade path with no functional reason to stay stable across builds. No reliable Sigma field exposes registry value *size*, which is the actual invariant of this technique (Stage-4 always writes a large blob for the boot re-loader to consume); a size-based rewrite could not be built from confirmed field availability.
**False Positives:** No known legitimate software writes to this exact registry path for THIS build; the masquerade path is structurally distinct from the legitimate Defender key.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (registry telemetry).

```yaml
title: Chaos Loader Stage-4 Fileless Payload Written to Masquerade Registry Key
id: 2d8b4e7f-a3c9-4f6b-b5d2-1e9a7c3f8b04
status: experimental
description: >-
  Detects a registry write to HKLM\Software\Microsoft Defender\Payload,
  which is the Stage-4 fileless storage location used by the
  Chaos/TorBrowserTor private crypter. The legitimate Windows Defender
  registry path is HKLM\Software\Microsoft\Windows Defender (note the
  extra \Windows\ path level). Stage-4 writes approximately 1.4 MB of
  encoded payload data to this masquerade key; the boot re-loader reads
  it back on every system startup. The masquerade path name is
  attacker-chosen and may rotate in a future build.
references:
    - https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/
author: The Hunters Ledger
date: 2026-04-23
tags:
    - attack.persistence
    - attack.stealth
    - attack.defense-impairment
    - attack.t1112
    - attack.t1027.011
    - attack.t1036.005
    - detection.emerging-threats
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
    - >-
      No known legitimate software writes to this registry path for THIS
      build; a future build renaming the masquerade key would evade this
      rule entirely
level: medium
```

#### Operator Tri-Artifact Anti-Sandbox Gate Artefacts Present

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1497 (Virtualization/Sandbox Evasion), T1036 (Masquerading)
**Confidence:** HIGH
**Rationale:** This combination is designed to identify the operator's own development/staging environment (the malware exits silently when it matches), not a victim infection — on a real victim host this combination should essentially never appear. Value is narrow and hunting-specific: confirming the operator's own fingerprint recurring in telemetry, or validating a suspected staging host.
**False Positives:** Legitimate VBScript Editor (VBE) installations on administrator accounts may create `%TEMP%\VBE\` directories; administrative accounts using tools that generate `mapping.csv` files in `%TEMP%`. Tune by excluding known-good admin workstations and software deployment systems.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (file-creation telemetry) — threat-hunting use only, not for direct alerting.

```yaml
title: Chaos Loader Operator Tri-Artifact Anti-Sandbox Gate Artefacts Present
id: c4f7b2a9-6d3e-4c8f-d1a5-7b9e4f2c6a18
status: experimental
description: >-
  Detects simultaneous presence of the three artefacts checked by the
  Chaos/TorBrowserTor crypter's inverted anti-sandbox gate — a process
  running as 'admin' combined with creation of %TEMP%\VBE\ or
  %TEMP%\mapping.csv. The gate exits the dropper silently when all three
  match, suggesting this is the operator's own development host
  signature rather than a victim-side artefact. Alert on the combination,
  not individual artefacts.
references:
    - https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/
author: The Hunters Ledger
date: 2026-04-23
tags:
    - attack.stealth
    - attack.discovery
    - attack.execution
    - attack.t1497
    - detection.emerging-threats
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
    - >-
      Legitimate VBScript Editor (VBE) installations on administrator
      accounts may create %TEMP%\VBE\ directories
    - Administrative accounts using tools that generate mapping.csv files in TEMP
    - Tune by excluding known-good admin workstations and software deployment systems
level: medium
```

**Chaos / TorBrowserTor Ransomware**

#### Masquerade Persistence via Run Key "Microsoft Store"

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1547.001 (Registry Run Keys), T1036.005 (Masquerading)
**Confidence:** HIGH (for these builds) / build-specific (durability)
**Rationale:** Both the Run-key value name ("Microsoft Store") and the self-copy filenames (`svchost.exe`, `projectxx.exe`) are choices specific to these two observed builds — a third build could rename either or both independently. No name-independent technique-level rewrite was attempted: `svchost.exe` masquerading outside `System32` is a durable general pattern, but `projectxx.exe` does not fit any system-process masquerade pattern, so a rewrite would only cover half the family.
**False Positives:** No known legitimate software creates a Run key named "Microsoft Store" pointing to `svchost.exe` or `projectxx.exe` in `%APPDATA%` for these builds; a future build renaming either value would evade this rule.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (registry telemetry).

```yaml
title: Chaos TorBrowserTor Stage-5a Masquerade Persistence via Run Key Microsoft Store
id: 8f2c5a1e-d4b7-4e9c-a6f3-2d8b1e7c4f96
status: experimental
description: >-
  Detects Stage-5a Chaos/TorBrowserTor ransomware persistence via a Run
  key value named 'Microsoft Store' under
  HKCU\Software\Microsoft\Windows\CurrentVersion\Run, pointing to
  svchost.exe or projectxx.exe in %APPDATA%. The mymain build copies
  itself to %APPDATA%\svchost.exe and the myfile build to
  %APPDATA%\projectxx.exe. Both the value name and the self-copy
  filenames are build-specific and may rotate in a future release.
references:
    - https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/
author: The Hunters Ledger
date: 2026-04-23
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1547.001
    - attack.t1036.005
    - detection.emerging-threats
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
    - >-
      No known legitimate software creates a Run key named 'Microsoft
      Store' pointing to svchost.exe or projectxx.exe in %APPDATA% for
      these builds; a future build renaming either value evades this rule
level: medium
```

#### Anti-Recovery / Shadow Copy Deletion Commands Executed

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1490 (Inhibit System Recovery)
**Confidence:** MODERATE (standalone) / HIGH when correlated with `.torbrowsertor` extension creation (see the Detection-tier correlation rule above)
**Rationale:** Rescoped from the original rule, which claimed (in its title and description) to require BOTH `.torbrowsertor` extension creation and an anti-recovery command, but whose actual `detection:` block only ever implemented the anti-recovery-command half. As a standalone signal, `vssadmin`/`wbadmin`/`bcdedit` shadow-copy and recovery-disabling commands are common to legitimate backup-cleanup activity and to the vast majority of ransomware families — genuinely useful for scoping, but not safe to alert on alone. This rule is now also referenced as a base rule by the Detection-tier correlation above (`name: chaos_antirecovery_commands`).
**False Positives:** Legitimate backup software cleanup operations (`vssadmin`, `wbadmin`); system administrators running manual shadow-copy management. Correlate with concurrent `.torbrowsertor` file creation for confirmation (see the correlation rule above).
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (process-creation telemetry).

> **YAML location note:** this rule's full definition (`name: chaos_antirecovery_commands`) is presented above under **Detection Rules → Chaos / TorBrowserTor Ransomware → "Encrypted File Extension Created + Anti-Recovery Command Correlation"**, in the same fenced YAML block as its correlation partner — Sigma correlation rules must resolve referenced base rules within the same document, so it cannot be duplicated here as a second copy. Its tier is Hunting, as documented in this entry; only the physical YAML placement differs from the type→tier layout.

#### Task Manager Disabled via Registry Policy

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1685 (Disable or Modify Tools)
**Confidence:** HIGH
**Rationale:** The original metadata's citation of "T1685 (Disable or Modify Tools)" is confirmed correct against the current MITRE ATT&CK technique catalog — verified directly against the installed `pySigma`/`sigma check` ATT&CK data rather than assumed from memory. ATT&CK has restructured what was previously T1562 (Impair Defenses) sub-techniques into standalone top-level techniques under a newer "Defense Impairment" tactic (TA0112): T1685 (Disable or Modify Tools), T1686 (Disable or Modify System Firewall), T1687 (Exploitation for Defense Impairment). `DisableTaskMgr` is a fixed, Windows-defined policy value name (not attacker-chosen), which gives the underlying artifact strong durability — Robustness 2. The tier stays Hunting on precision grounds: Group Policy sets this value legitimately, and the rule's own `filter_gpo` exclusion covers only two of the many legitimate deployment vectors (login scripts, SCCM/Intune-pushed reg.exe calls, and other administrative tooling are not filtered), so real enterprise false positives are expected without further tuning.
**False Positives:** Group Policy enforcing kiosk or restricted desktop configurations that disable Task Manager; enterprise endpoint management software applying policy-based restrictions through a path not covered by `filter_gpo`.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (registry telemetry), correlate the writing process image path with `%APPDATA%` to raise confidence.

```yaml
title: Chaos TorBrowserTor Stage-5a Disables Task Manager via Registry Policy
id: f1d4a8c3-7e2b-4f9a-b8d6-4a3c7f1e9b52
status: experimental
description: >-
  Detects Stage-5a Chaos/TorBrowserTor ransomware writing DisableTaskMgr=1
  to HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System to
  prevent the victim from using Task Manager to terminate the ransomware
  process. This value can be set legitimately by Group Policy; however,
  when written by a process running from %APPDATA% outside of a GPO
  context, it indicates active ransomware defense impairment. Correlate
  the writing process image path with %APPDATA% to confirm malicious
  origin.
references:
    - https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/
author: The Hunters Ledger
date: 2026-04-23
tags:
    - attack.defense-impairment
    - attack.t1685
    - detection.emerging-threats
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr'
        Details: 1
    filter_gpo:
        Image|contains:
            - '\Windows\System32\svchost.exe'
            - '\Windows\System32\GroupPolicy'
    condition: selection and not filter_gpo
falsepositives:
    - >-
      Group Policy enforcing kiosk or restricted desktop configurations
      that disable Task Manager
    - >-
      Enterprise endpoint management software applying policy-based
      restrictions through a deployment path not covered by filter_gpo
level: medium
```

**Orcus RAT v7 (Wardow Crack)**

#### Loopback C2 Connection on Port 20268

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1090.001 (Internal Proxy), T1071.001 (Web Protocols)
**Confidence:** HIGH (for this campaign) / port is campaign-configured, not crack-tool-hardcoded
**Rationale:** Unlike the family-wide `CrackedByWardow` crack constants (which the YARA rule above anchors on), port 20268 is an Orcus builder configuration value the operator set for this campaign specifically — it is not confirmed to be a crack-tool default. A future campaign from the same operator, or any other Wardow-crack user, could configure a different port. Removing the specific port would leave only "loopback connection from a non-system process," which is far too broad to be useful even as a Hunting signal (many legitimate applications use arbitrary localhost ports), so the port anchor is retained as the best available balance.
**False Positives:** Local development services or automated testing frameworks using port 20268 in developer environments. Tune by restricting to process images outside `System32`/`SysWOW64`, and treat as a lead requiring corroboration, not a standalone alert.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (network-connection telemetry).

```yaml
title: Orcus RAT Wardow Crack Loopback C2 Connection on Port 20268
id: a9c6e3f8-b1d4-4a7c-c5e9-8f3b2d7a6c41
status: experimental
description: >-
  Detects Orcus RAT v7 Wardow crack initiating a loopback TCP connection
  to 127.0.0.1:20268, the tunneled C2 configuration observed in this
  campaign at 94.103.1.13. The real upstream C2 is hidden behind a
  chisel/plink SSH or HTTP tunnel; the Orcus client connects to the
  loopback listener which relays traffic externally. The port number is
  an operator-configured value for this campaign, not a crack-tool-wide
  constant, and may differ in another deployment.
references:
    - https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/
author: The Hunters Ledger
date: 2026-04-23
tags:
    - attack.command-and-control
    - attack.t1090.001
    - attack.t1071.001
    - detection.emerging-threats
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
    - >-
      Tune by restricting to process images outside System32/SysWOW64;
      the port is operator-configured and may differ in other campaigns
level: medium
```

**Operator Backdoor Account**

#### Stage-2 Operator Backdoor Account "pentest" Created

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1136.001 (Create Account: Local Account), T1078.003 (Valid Accounts: Local Accounts)
**Confidence:** HIGH (behavior) / single-observation (durability)
**Rationale:** The username/password pair is hardcoded in the operator's own controller script (`interact.py`) rather than generated per-target, which plausibly makes it stable across this operator's victims — but that reuse is inferred from a single observed script, not confirmed across multiple campaigns the way the Stage-4 mutex GUID was confirmed across two independent builds. Removing the credential literal leaves only "net.exe invoked with 'user' and '/add'," which is far too generic to retain value, so the credential anchor is required; Gate-1 durability (single-observation evidence) keeps this at Hunting despite near-zero false-positive risk. Promote to Detection if the same credential pair is confirmed reused in a second, independent campaign.
**False Positives:** Implausible — the exact username "pentest" paired with password "Qwerty12345" in a `net user /add` invocation has no known benign explanation.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (process-creation telemetry); also hunt for successful logons and Administrators-group membership changes involving the username `pentest`.

```yaml
title: Chaos Loader Stage-2 Operator Backdoor Account 'Pentest' Created
id: 5e8c4f1b-2a9d-47b6-9c3e-7d1f8a2e6b54
status: experimental
description: >-
  Detects the hardcoded backdoor account creation command embedded in
  interact.py, the Stage-2 operator controller in the Chaos/TorBrowserTor
  multi-stage loader campaign at 94.103.1.13. The script downloads an
  XOR-encoded GodPotato assembly, decodes it with a single-byte XOR key,
  reflectively loads it as a .NET assembly, and invokes its EntryPoint
  with the argument string 'net user pentest Qwerty12345 /add' — running
  as NT AUTHORITY\SYSTEM via GodPotato impersonation. Detection keys on
  the literal username/password combination in the net.exe command line,
  observed hardcoded in one operator controller script; reuse across
  additional campaigns has not yet been confirmed.
references:
    - https://the-hunters-ledger.com/reports/open-directory-94-103-1-13-20260423/#12-addendum-2026-05-02-follow-up
    - https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/
author: The Hunters Ledger
date: 2026-05-02
tags:
    - attack.persistence
    - attack.stealth
    - attack.privilege-escalation
    - attack.initial-access
    - attack.t1136.001
    - attack.t1078.003
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection_image:
        Image|endswith:
            - '\net.exe'
            - '\net1.exe'
    selection_cmdline:
        CommandLine|contains|all:
            - 'user'
            - 'pentest'
            - 'Qwerty12345'
            - '/add'
    condition: selection_image and selection_cmdline
falsepositives:
    - >-
      Implausible — exact username 'pentest' paired with password
      'Qwerty12345' is operator-specific and has been observed in only
      one controller script to date
level: medium
```

---

## Suricata Signatures

### Hunting Rules

**Operator Staging Infrastructure**

#### XOR-Encoded Payload Staging Download (.xor URI Suffix)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer), T1071.001 (Web Protocols)
**Confidence:** MODERATE
**Rationale:** Salvaged via capability-abstraction from the original `/gp.xor`-specific rule (a single short URI-path literal with no corroborating anchor, which would have been Robustness 1). The underlying evidence in this investigation explicitly frames the `.xor`-suffixed download convention as surviving infrastructure rotation — any script performing a GET against an HTTP target ending in `.xor` followed by in-memory `Reflection.Assembly.Load` is the same loader pattern regardless of which IP or filename is used. Broadening the content match from `/gp.xor` to the `.xor` suffix keeps that durability while accepting a small increase in false-positive surface (matching any `.xor`-suffixed download, not only this campaign's specific payload), which is why this stays Hunting rather than Detection.
**False Positives:** Any unrelated HTTP download whose URI happens to end in `.xor` (uncommon — `.xor` is not a standard web content type, but other XOR-encoded stagers could also use this suffix); the `threshold` limits alert volume per source.
**Deployment:** Network IDS/IPS at perimeter and internal segmentation points; hunt-tune before alerting.

```suricata
alert http $HOME_NET any -> any any (msg:"THL OpenDirectory-94.103.1.13 XOR-Encoded Payload Staging Download via .xor URI Suffix (Loader Staging Indicator)"; flow:established,to_server; http.method; content:"GET"; http.uri; content:".xor"; endswith; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000001; rev:1; metadata:author The_Hunters_Ledger, date 2026-04-23, reference https://the-hunters-ledger.com/hunting-detections/open-directory-94-103-1-13-20260423-detections/;)
```

> **Cut — pure IP-match rule retired.** The original file also carried a Suricata signature keyed solely on the operator staging IP `94.103.1.13` (with only a bare `http.method; content:"GET"` alongside it, which matches essentially all HTTP GET traffic and adds no discriminating power). Per the routing test, a rule that detects nothing once its single hard-coded IP is removed is an IOC-feed entry, not a signature — `94.103.1.13` is already carried with full context in the campaign's IOC feed. See Coverage Gaps.

---

## Coverage Gaps

### Retiering Notes (2026-07-12 backfill)

**Cut: pure IP-match Suricata rule.** The original file's `THL-OPDIR-94103113 — HTTP to Chaos/TorBrowserTor Staging Host` signature keyed solely on the destination IP `94.103.1.13`, with a `http.method; content:"GET"` clause that adds no discriminating power (it matches virtually all HTTP GET traffic). This is a pure IOC-feed entry, not a signature; the IP is already present with full context (ASN, VT detections, first-seen dates) in `open-directory-94-103-1-13-20260423-iocs.json` — no feed edit was required.

**ATT&CK technique ID verified, not corrected: T1685.** The originally-published file cited "T1685 (Disable or Modify Tools)" in the Task Manager Disabled Sigma rule and the AMSI/ETW/ntdll Unhook gap below. An earlier pass of this backfill incorrectly "corrected" both to T1562.001 on the assumption that T1685 was invalid — that assumption was wrong. Checked directly against the current MITRE ATT&CK technique catalog (via the installed `pySigma`/`sigma check` data, not from memory), T1685 is a valid, current technique: ATT&CK restructured the former T1562 (Impair Defenses) sub-techniques into standalone top-level techniques under a newer "Defense Impairment" tactic (TA0112) — T1685 (Disable or Modify Tools), T1686 (Disable or Modify System Firewall), T1687 (Exploitation for Defense Impairment) — and T1562.001 no longer exists in that catalog. Both entries have been reverted to T1685. This is recorded as a methodology note: always verify technique IDs against the tool's live data, not training-era recall.

**Attacker-chosen masquerade literals do not survive a rebuild.** The Stage-4 scheduled-task name, the Stage-4 registry masquerade path, and the Stage-5a Run-key value name and self-copy filenames are all cosmetic choices with no functional reason to stay stable — a future build could rename any of them independently. These indicators remain genuinely useful Hunting leads for the two builds observed to date, but none of them qualify as Detection-tier since precision this clean is an artifact of having observed the operator's current naming choices, not of the underlying technique. No name-independent technique-level rewrite was attempted for any of them: Windows Security auditing does not reliably expose scheduled-task RunLevel/trigger type or registry-value size as separate queryable Sigma fields, and the two self-copy filenames (`svchost.exe`, `projectxx.exe`) don't share a common masquerade pattern that would let a single broader rule cover both. **What would raise confidence:** a third build reusing any of these literals unchanged, which would elevate that specific artifact to a cross-build invariant the way the Stage-4 mutex GUID and Stage-5b UAC-bypass PE already are.

### Techniques Without High-Confidence Rules (from original analysis)

**T1620 — Reflective Code Loading (Assembly.Load)**
Every .NET stage in this crypter dispatches the next stage via `[System.Reflection.Assembly]::Load([byte[]])`. This is a powerful behavioral anchor but cannot be captured in a high-fidelity Sigma rule without AMSI/ETW telemetry that logs the loaded bytes — standard Sysmon process-creation does not surface Assembly.Load calls. A YARA rule targeting the in-memory PowerShell pattern (`[System.Reflection.Assembly]::Load` + `[System.Security.Cryptography.Aes]::Create()`) would be medium-confidence but was not included because the AES API call appears in many legitimate scripts and would generate significant FP volume without per-host baseline tuning.

**T1003.001 — LSASS Credential Dumping (Mimikatz)**
The staged Mimikatz suite is stock September 2022 gentilkiwi builds. Existing SigmaHQ community rules (e.g., `proc_creation_win_mimikatz_exec`) and public YARA repositories already cover these hashes and command patterns comprehensively. Reproducing them here would be redundant and dilute the campaign-specific value of this rule set. Defenders should ensure existing Mimikatz detections are deployed and reference community rules for coverage.

**T1068 — PrintNightmare / GodPotato / PrintSpoofer**
The GodPotato family (`gp.exe`, `gp2.exe`, `gp_obf.exe`, `gp_fat.exe`, `svc.exe`) and `PrintSpoofer.exe` are commodity public tools with high VT detection rates (26–38/77). Community YARA and Sigma rules cover these. The custom `p.exe` SpoolSS coercer is 6.6 KB and would be a valid YARA target; however, without confirmed unique strings from full decompilation of that specific binary, a YARA rule risks being too generic. A hash-based detection on SHA256 `b9ffbeed12325c450ba0f3c55cdcd243cdb704115aa3aee784bbdee3243f84e5` is the safest approach and is captured in the IOC feed.

**T1572 — Protocol Tunneling (Chisel / Plink)**
`chisel.exe` and `plink.exe` are legitimate open-source tools with high detection rates under their own family signatures. The real Orcus C2 upstream behind the tunnel could not be identified from static analysis; without the resolved upstream IP or domain, a Suricata rule targeting chisel/plink traffic would require behavioral heuristics (e.g., periodic short-interval beaconing patterns) that would generate excessive FPs against legitimate SSH/HTTP tunnel use. Resolving the real upstream C2 requires observing the malware past the tunnel handshake.

**T1685 — AMSI/ETW/ntdll Unhook (Perun's Fart)**
The Perun's Fart ntdll-unhook technique operates entirely in user-mode memory and does not produce Sysmon process-creation events. Effective detection requires EDR kernel-level hooks or memory integrity monitoring. A Sigma rule targeting a second load of `ntdll.dll` from a non-standard path (e.g., via Sysmon Event ID 7 image-load) is architecturally possible but requires significant per-environment tuning and was assessed as out of scope for this campaign-specific rule set.

**T1090.001 — Orcus Real Upstream C2**
The actual chisel/plink tunnel destination for Orcus is unknown from static analysis. No Suricata IP/domain rule can be written for the real C2 without resolving the upstream peer. The loopback-connection Sigma rule above covers the host-side indicator; the network gap remains open.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
