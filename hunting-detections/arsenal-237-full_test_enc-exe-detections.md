---
title: "Detection Rules — full_test_enc.exe (Arsenal-237 Ransomware)"
date: '2026-01-27'
layout: post
permalink: /hunting-detections/arsenal-237-full_test_enc-exe-detections/
hide: true
redirect_from: /hunting-detections/arsenal-237-full_test_enc-exe/
thumbnail: /assets/images/cards/arsenal-237-new-files.png
---

**Campaign:** Arsenal-237-Lockbox-Ransomware
**Date:** 2026-01-27
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**IOC Feed:** https://the-hunters-ledger.com/ioc-feeds/arsenal-237-full_test_enc-exe.json

---

## Detection Coverage Summary

full_test_enc.exe is a 64-bit, Rust-compiled ransomware sample and the encryption module of the Arsenal-237 toolkit. It encrypts files with ChaCha20 and wraps the encryption key with RSA-OAEP via the RustCrypto crate family, uses the Rayon parallel-execution library to spread encryption across CPU cores, enumerates and encrypts reachable network shares via the Windows `net use` command, and marks encrypted output with a `.lockbox` extension alongside an on-screen ransom note. No command-and-control channel was identified — this build operates offline.

Coverage below is retiered from the original draft: every rule was re-scored for durability (does it survive infrastructure rotation and renaming?), precision (documented false-positive profile), and level discipline, per the project's Detection/Hunting split. The ransom-note text and the .lockbox marker anchor the strongest signatures; several Rust-crate and command-line strings that are common to unrelated legitimate software were narrowed or restructured into more durable combinations, and one network signature that could not fire under any real traffic condition was retired. The sample's confirmed file hashes are carried in the IOC feed rather than as standalone signatures.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 2 | 3 | T1135, T1486 | 0 |
| Sigma | 0 | 3 | T1135, T1486 | 0 |
| Suricata | 0 | 0 | — | 0 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Atomics routed to the IOC feed:** full_test_enc.exe's SHA256/SHA1/MD5 hashes, the `.lockbox` file extension, and the `C:\Windows\Temp` folder-option path were already present in [`arsenal-237-full_test_enc-exe.json`](/ioc-feeds/arsenal-237-full_test_enc-exe.json) before this retiering pass. No rule in this file was cut purely for reducing to a bare hash/IP/domain — the `.lockbox` extension instead survives as one leg of the Sigma correlation rule below, and the generic `C:\Windows\Temp` path was dropped as non-discriminating filler during a YARA salvage rather than cut for atomic-only status. See Coverage Gaps for the full reasoning on every retired or restructured rule.

---

## YARA Rules

### Detection Rules

#### Ransom Note, Ransom ID Label, and .lockbox Extension

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1486 (Data Encrypted for Impact)
**Confidence:** HIGH
**Rationale:** *Fix applied during retiering:* the source rule defined three ransom-ID strings — `$ransom2 = "Ransom ID:"` and `$ransom3 = "Ransom ID: "` — where `$ransom3` is a strict superset of `$ransom2` (the only difference is a trailing space). Because YARA matches by substring, any hit on `$ransom3` automatically also hits `$ransom2` at the same offset, which silently collapsed the intended "2 of 3 ransom strings" requirement into a rule that could fire on `$ransom3` alone. The redundant string has been removed and the condition rewritten to require the ransom-note banner and the Ransom ID label explicitly together. The banner text ("YOUR FILES HAVE BEEN ENCRYPTED!") is a coined phrase not expected in unrelated software, and this branch requires no debug/logging evidence — it is the ransomware's actual victim-facing output and should persist into any future, non-development build. The alternate branch (all four operational log strings) is specific to this non-stripped build; see Coverage Gaps.
**False Positives:** None known — the combination of this exact ransom-note banner, the Ransom ID label, and the `.lockbox` extension is not present in legitimate software.
**Blind Spots:** A rebuild that rewrites the ransom-note text and the Ransom ID label evades the primary branch entirely; a stripped/production build lacking the operational log strings would only match via the primary branch, not the alternate one.
**Validation:** Scan full_test_enc.exe (hash below) — must match; an unrelated ransomware family with different ransom-note text must NOT fire.
**Deployment:** Endpoint AV/EDR file scanning, email gateway attachment scanning, retroactive scan of file shares, IR artifact triage.

```yara
/*
   Yara Rule Set
   Identifier: Arsenal-237-Lockbox-Ransomware
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule TOOLKIT_Arsenal237_Ransom_Note_And_Lockbox_Extension {
   meta:
      description = "Detects the Arsenal-237 ransomware's ransom-note banner and Ransom ID victim-identifier label together with the .lockbox encrypted-file extension, or (an alternate path specific to this non-stripped build) its four operational logging strings."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-full_test_enc-exe-detections/"
      date = "2026-01-27"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      campaign = "Arsenal-237-Lockbox-Ransomware"
      id = "b4c73e5f-4092-4da3-9f28-6ea3d71a2c04"
      hash1 = "4d1fe7b54a0ce9ce2082c167b662ec138b890e3f305e67bdc13a5e9a24708518"
   strings:
      $ransom1 = "YOUR FILES HAVE BEEN ENCRYPTED!" ascii wide
      $ransom2 = "Ransom ID:" ascii wide
      $lockbox = ".lockbox" ascii wide

      $log1 = "[*] Encryptor starting..." ascii
      $log2 = "[*] Encrypting all drives..." ascii
      $log3 = "[+] Encryption complete!" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize > 10MB and filesize < 20MB and
      (
         ($ransom1 and $ransom2 and $lockbox) or
         (all of ($log*))
      )
}
```

#### Comprehensive Ransomware Indicator Combination

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1486 (Data Encrypted for Impact), T1135 (Network Share Discovery — secondary, one of three optional corroborating strings)
**Confidence:** HIGH
**Rationale:** Requires the coined ransom-note banner AND both the ChaCha20 and RSA crate-path prefixes together, plus at least one of three parallel-processing/system-enumeration crate paths, plus at least one of the `.lockbox` extension, the `net use` string, or the Ransom ID label. The mandatory ransom-note requirement governs this rule's overall precision — a legitimate Rust encryption tool would additionally need to embed that exact victim-facing banner text for this rule to false-positive, which is not a realistic scenario. This is the richest mandatory AND-combination in the file and the highest-confidence signature here.
**False Positives:** None known — no legitimate software is expected to combine a ChaCha20/RSA crypto stack with this specific ransom-note banner.
**Blind Spots:** A rebuild that rewrites the ransom-note text evades this rule entirely (its one mandatory, non-crypto anchor); a build using different RustCrypto crate versions still matches, since the crate-path strings here are unversioned prefixes rather than exact paths.
**Validation:** Scan full_test_enc.exe (hash below) — must match; a benign Rust encryption utility lacking the literal ransom-note text must NOT fire.
**Deployment:** Endpoint AV/EDR file scanning, retroactive scan of file shares, IR artifact triage.

```yara
rule TOOLKIT_Arsenal237_Ransomware_Comprehensive_Indicators {
   meta:
      description = "Detects Arsenal-237 ransomware samples via a mandatory combination of the ransom-note banner plus ChaCha20/RSA crypto crate-path evidence, corroborated by parallel-processing/system-enumeration crate evidence and by the .lockbox extension, net use string, or Ransom ID label."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-full_test_enc-exe-detections/"
      date = "2026-01-27"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      campaign = "Arsenal-237-Lockbox-Ransomware"
      id = "e7fa6182-7325-40d6-825b-91d6a04d5f37"
      hash1 = "4d1fe7b54a0ce9ce2082c167b662ec138b890e3f305e67bdc13a5e9a24708518"
   strings:
      $chacha = "/chacha20-" ascii
      $rsa_lib = "/rsa-" ascii

      $ransom = "YOUR FILES HAVE BEEN ENCRYPTED!" ascii wide
      $ransom_id = "Ransom ID" ascii

      $rayon = "/rayon-" ascii
      $walkdir = "/walkdir-" ascii
      $sysinfo = "/sysinfo-" ascii

      $lockbox = ".lockbox" ascii
      $netuse = "net use" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize > 10MB and filesize < 20MB and
      $chacha and $rsa_lib and $ransom and
      (1 of ($rayon, $walkdir, $sysinfo)) and
      ($lockbox or $netuse or $ransom_id)
}
```

### Hunting Rules

#### RustCrypto ChaCha20 + RSA Crate Combination

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1486 (Data Encrypted for Impact)
**Confidence:** MODERATE
**Rationale:** Requires 3 of 6 versioned crate-path strings from the RustCrypto ecosystem (chacha20, rsa, aead, cipher, digest, rand), combined with a >10MB PE size gate. The combination is distinctive enough to be a real, if imperfect, lead — but chacha20/rsa/aead/cipher/digest/rand are the RustCrypto organization's own standard, widely-used crate family, routinely bundled together by any legitimate Rust software implementing hybrid encryption (password managers, backup tools, encrypted-file utilities). No goodware-corpus validation has been performed against that population, so this does not clear the Detection precision bar on its own.
**False Positives:** Realistic overlap with legitimate Rust software built on the same RustCrypto crate family and performing similar hybrid ChaCha20+RSA encryption; not characterized against a broad clean-software corpus.
**Deployment:** Broad endpoint/EDR scanning sweep, retroactive hunt across file shares; treat hits as triage candidates pending goodware validation, not alerts.

```yara
rule TOOLKIT_Arsenal237_RustCrypto_ChaCha20_RSA_Combination {
   meta:
      description = "Detects Rust binaries embedding at least 3 of 6 versioned RustCrypto crate-path strings (chacha20, rsa, aead, cipher, digest, rand) observed in the Arsenal-237 ransomware's crypto stack. The RustCrypto crate family is also used by unrelated legitimate Rust encryption software; not goodware-validated."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-full_test_enc-exe-detections/"
      date = "2026-01-27"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      campaign = "Arsenal-237-Lockbox-Ransomware"
      id = "a1b62d4e-3f81-4c92-8e17-5d9a2c60f1b3"
      hash1 = "4d1fe7b54a0ce9ce2082c167b662ec138b890e3f305e67bdc13a5e9a24708518"
   strings:
      $chacha20 = "/chacha20-0.9.1/src/lib.rs" ascii
      $rsa = "/rsa-0.9.9/src/algorithms/" ascii
      $aead = "/aead-0.5.2/src/lib.rs" ascii
      $cipher = "/cipher-0.4.4/" ascii
      $digest = "/digest-0.10.7/" ascii
      $rand = "/rand-0.8.5/" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize > 10MB and
      3 of them
}
```

#### Custom Crypto-Engine Error Strings

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1486 (Data Encrypted for Impact)
**Confidence:** LOW
**Rationale:** Salvaged from a broader source rule ("Rayon_AntiAnalysis") that combined three unrelated signal families in one condition: a mandatory-looking `all of (rayon, walkdir, sysinfo)` branch built from three of the same common, widely-used Rust crate paths discussed above (no malware-specific signal — a generic parallel-file-processing-plus-system-info combination that plausibly matches legitimate Rust CLI tooling); a `2 of (VMware, VirtualBox, encrypt_error*)` branch that let two bare, un-fullword'd, `nocase` product-name strings ("VMware", "VirtualBox") satisfy the count alone with no crypto-error evidence required at all — both of these are exactly the ubiquitous-benign-string pattern the project's Cut checklist warns against. What survives salvage is the three bespoke crypto-engine error strings alone, requiring 2 of 3. These describe failure conditions specific to this codebase's ChaCha20/RSA error handling and are not generic library error text, but the phrasing has not been validated against a goodware corpus and is narrower than a coined ransom banner.
**False Positives:** Not characterized against a goodware corpus; residual risk is another custom Rust crypto tool using coincidentally similar error-handling phrasing.
**Deployment:** Broad endpoint/EDR scanning sweep, retroactive hunt across file shares; treat hits as triage candidates, not alerts.

```yara
rule TOOLKIT_Arsenal237_Custom_Crypto_Error_Strings {
   meta:
      description = "Detects at least two of three bespoke error-handling strings the Arsenal-237 ransomware's ChaCha20/RSA encryption engine emits on operation failure. Salvaged from a broader original rule that also combined generic Rust crate paths (rayon, walkdir, sysinfo) and bare, unqualified VMware/VirtualBox string matches -- both dropped for lacking malware-specific discriminating power."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-full_test_enc-exe-detections/"
      date = "2026-01-27"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      campaign = "Arsenal-237-Lockbox-Ransomware"
      id = "c5d84f60-5103-4eb4-a039-7fb4e82b3d15"
      hash1 = "4d1fe7b54a0ce9ce2082c167b662ec138b890e3f305e67bdc13a5e9a24708518"
   strings:
      $encrypt_error1 = "Failed to encrypt nonce" ascii
      $encrypt_error2 = "Failed to encrypt key" ascii
      $encrypt_error3 = "Block encryption failed" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize > 10MB and
      2 of them
}
```

#### net use Execution Error String

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1135 (Network Share Discovery)
**Confidence:** LOW
**Rationale:** Salvaged from a broader source rule ("NetworkShare_Enumeration") whose condition mandated a bare, `nocase` "SMB" match (3 bytes — under the project's 4-byte specificity floor and a common acronym in unrelated networking software) and offered a 2-byte UNC-backslash pattern (`"\\\\"`, i.e. two literal backslash bytes) as an alternate anchor — both are textbook Cut-grade, ubiquitous short strings. A generic `C:\Windows\Temp` path and a generic `--folder` CLI flag were also dropped as non-discriminating. What survives is the single bespoke error string "Failed to execute net use," a one-off literal with no supporting structure — Robustness 1, the brittle end of the scale. The `net use` execution behavior itself is more reliably covered at the correct telemetry layer by the Sigma correlation rule below (process-creation command-line evidence, not a static string reference).
**False Positives:** Narrow single-string coverage; not characterized against a goodware corpus. Limited standalone value given the overlapping, more reliable Sigma coverage.
**Deployment:** Broad endpoint/EDR scanning sweep, retroactive hunt across file shares; treat hits as triage candidates, not alerts.

```yara
rule TOOLKIT_Arsenal237_NetUse_Execution_Error_String {
   meta:
      description = "Detects the bespoke 'Failed to execute net use' error string the Arsenal-237 ransomware's network-share-enumeration routine emits when its net use invocation fails. Salvaged from a broader original rule that also mandated a bare 3-byte 'SMB' substring and offered a 2-byte UNC-backslash pattern as an alternate anchor, plus generic path/flag strings -- all dropped for falling under the project's 4-byte specificity floor or being common to unrelated software."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-full_test_enc-exe-detections/"
      date = "2026-01-27"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      campaign = "Arsenal-237-Lockbox-Ransomware"
      id = "d6e95071-6214-4fc5-b14a-80c5f93c4e26"
      hash1 = "4d1fe7b54a0ce9ce2082c167b662ec138b890e3f305e67bdc13a5e9a24708518"
   strings:
      $netuse_error = "Failed to execute net use" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize > 10MB and
      $netuse_error
}
```

---

## Sigma Rules

### Hunting Rules

#### Arsenal-237 Ransomware Chain: Net Use Execution + .lockbox Creation (Correlation)

**Tier:** Hunting (correlation rule) — bundled below with its 2 required non-alerting base rules
**Robustness:** 2 (correlation) / 2 and 1 (the net use base rule and the .lockbox base rule, individually)
**ATT&CK Coverage:** T1135 (Network Share Discovery), T1486 (Data Encrypted for Impact)
**Confidence:** MODERATE
**Rationale:** This pass restructures both of the source draft's Sigma rules together rather than tiering them independently. Source Rule 1 ("Mass .lockbox File Creation") titled itself as a mass-creation detector, but its actual `selection` block matched a single `TargetFilename` event with no count or aggregation logic at all — the title claimed behavior the logic never implemented. Taken alone, its sole discriminator is the renameable `.lockbox` extension (already in the IOC feed), a textbook single-literal Cut candidate. Source Rule 2 ("Unsigned Binary Executing Net Use") is a genuine behavioral selector — `net use` is a real Windows command tied to T1135 — but its own documented false positives ("Administrative tools," "Batch scripts") describe a real, non-trivial noise population that the path/parent-process filters do not meaningfully suppress, since legitimate drive-mapping scripts commonly also run from paths outside `C:\Windows\` and `C:\Program Files\`. Its source `level: high` overstated confidence for that FP profile. Rather than cut Rule 1 and separately demote Rule 2, both are folded into one temporal correlation: non-standard-path `net use` execution followed by `.lockbox` file creation on the same host within 15 minutes. Neither base signal is trustworthy alone, but a coincidental unrelated process satisfying the `.lockbox` condition on the same host shortly after an unrelated admin satisfies the `net use` condition is not a realistic benign scenario. The correlation still caps at Hunting rather than Detection: the `.lockbox` base rule's extension is exactly the kind of renameable literal that caps a rule's durability regardless of how compelling the surrounding combination looks — a future Arsenal-237 build that changes the output extension silences this correlation entirely, just as it would the standalone rule.
**False Positives:** The net use base rule alone: administrative tools and batch scripts (documented in the source). The .lockbox base rule alone: legitimate backup/database software choosing the same extension (documented in the source, though no such product is known to use it). The correlation itself: an administrator running `net use` for legitimate drive-mapping on a host that, within the same 15-minute window and by coincidence, also receives an unrelated file ending in `.lockbox` — both conditions co-occurring by chance is not expected but is not provably impossible.
**Deployment:** SIEM correlation engine with Sysmon/EDR process-creation and file-event telemetry ingested (15-minute temporal join on `host.name`); the two base rules alone feed process auditing and file-integrity monitoring as the underlying data sources.

```yaml
title: Non-Standard-Path Net Use Execution (Base Rule)
id: 3f8a1c2d-6b4e-4a91-9c73-1d5e8f2a6b90
name: arsenal237_netuse_nonstandard_exec
status: experimental
description: >-
  Base rule (not alerting on its own): execution of a process outside standard
  install directories with a command line containing "net use" -- network
  share discovery/mapping behavior. Paired with the .lockbox file-creation base
  rule below via the correlation rule, which flags co-occurrence of both
  Arsenal-237 ransomware-chain artifacts on the same host.
references:
  - https://the-hunters-ledger.com/hunting-detections/arsenal-237-full_test_enc-exe-detections/
author: The Hunters Ledger
date: '2026-01-27'
tags:
  - attack.discovery
  - attack.t1135
  - detection.emerging-threats
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'net use'
  filter_main_paths:
    Image|startswith:
      - 'C:\Windows\'
      - 'C:\Program Files'
  filter_admin:
    User|contains: 'SYSTEM'
    ParentImage|endswith:
      - 'svchost.exe'
      - 'lsass.exe'
  condition: selection and not 1 of filter_*
falsepositives:
  - >-
    Administrative tools and batch scripts routinely invoke net use for
    legitimate drive-mapping. Not alerting on its own -- reviewed only in
    combination with the paired .lockbox file-creation base rule.
level: informational
---
title: .lockbox File Creation (Base Rule)
id: 7e2b9d4f-1a83-46c5-b2e9-4f7c1a9d3e58
name: arsenal237_lockbox_file_creation
status: experimental
description: >-
  Base rule (not alerting on its own): creation of a file with the .lockbox
  extension used by Arsenal-237 to mark ransomware-encrypted output. Paired
  with the net use execution base rule above via the correlation rule below.
references:
  - https://the-hunters-ledger.com/hunting-detections/arsenal-237-full_test_enc-exe-detections/
author: The Hunters Ledger
date: '2026-01-27'
tags:
  - attack.impact
  - attack.t1486
  - detection.emerging-threats
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetFilename|endswith: '.lockbox'
  filter:
    Image|contains:
      - 'C:\Program Files'
      - 'C:\Program Files (x86)'
      - 'C:\Windows\System32'
      - 'C:\Windows\SysWOW64'
  condition: selection and not filter
falsepositives:
  - >-
    Legitimate backup software or database processes choosing a custom
    .lockbox extension is not expected but cannot be fully ruled out. Not
    alerting on its own -- reviewed only in combination with the paired net
    use base rule.
level: informational
---
title: 'Arsenal-237 Ransomware Chain: Net Use Execution + .lockbox Creation on Same Host'
id: 9c4d7e2a-5f13-48b6-a1d9-2e6b8c4f0a73
status: experimental
description: >-
  Fires when both non-standard-path net use execution and .lockbox file
  creation are observed on the same host within a short window. Neither base
  signal alone is reliable -- net use is a legitimate Windows command
  routinely used by administrative tooling, and a bare file-extension match is
  trivially evaded by an operator renaming the extension in a future build --
  but the combination of a network-share-discovery command followed by
  appearance of a distinctively-extensioned encrypted-file marker on the same
  host is a behavioral sequence not expected from unrelated benign activity.
references:
  - https://the-hunters-ledger.com/hunting-detections/arsenal-237-full_test_enc-exe-detections/
author: The Hunters Ledger
date: '2026-01-27'
tags:
  - attack.discovery
  - attack.impact
  - attack.t1135
  - attack.t1486
  - detection.emerging-threats
correlation:
  type: temporal
  rules:
    - arsenal237_netuse_nonstandard_exec
    - arsenal237_lockbox_file_creation
  group-by:
    - host.name
  timespan: 15m
falsepositives:
  - >-
    An administrator legitimately running net use for drive-mapping on a host
    that, coincidentally and within the same 15-minute window, also receives
    an unrelated file ending in .lockbox from unrelated legitimate software
    using that extension.
level: medium
```

---

## Coverage Gaps

### Retiering Fixes Applied

- **YARA duplicate ransom-ID string removed.** The source's "Ransomware_Lockbox_Strings" rule defined `$ransom2 = "Ransom ID:"` and `$ransom3 = "Ransom ID: "` — the latter a strict superset of the former (only a trailing space differs), so any match on `$ransom3` automatically satisfied `$ransom2` too. This silently weakened the intended "2 of 3 ransom strings" requirement to a de facto single-string condition. The redundant string was removed and the condition rewritten to require both remaining ransom strings explicitly (see the retiered "Ransom Note, Ransom ID Label, and .lockbox Extension" rule above).
- **YARA "Rayon_AntiAnalysis" salvaged, renamed.** The source rule combined a common Rust-crate-path branch (`rayon`+`walkdir`+`sysinfo`, all in wide legitimate use for parallel file processing and system-info gathering) with a branch that let two bare, un-fullword'd, `nocase` product-name strings ("VMware", "VirtualBox") satisfy a "2 of 3" count alone, with no crypto-error evidence required. Neither branch carries malware-specific signal on its own. Salvaged down to the three bespoke crypto-engine error strings, which are genuinely specific to this codebase; see the retiered "Custom Crypto-Engine Error Strings" rule above.
- **YARA "NetworkShare_Enumeration" salvaged, renamed.** The source rule's condition mandated a bare 3-byte `nocase` "SMB" match and offered a 2-byte UNC-backslash pattern (`"\\\\"`) as an alternate anchor — both fall under the project's 4-byte specificity floor and are common in unrelated software. A generic `C:\Windows\Temp` path and generic `--folder` flag were also dropped. What survives is the single bespoke error string "Failed to execute net use"; see the retiered "net use Execution Error String" rule above.
- **Sigma title/logic mismatch and inflated level, both folded into one correlation.** Source Sigma Rule 1 ("Mass .lockbox File Creation") claimed a mass-creation detector in its title but implemented a single-event extension match with no aggregation — a single-literal Cut candidate on its own. Source Sigma Rule 2 ("Unsigned Binary Executing Net Use") is a genuine T1135 behavioral selector, but its own documented false positives describe a real noise population its filters do not meaningfully suppress, and its source `level: high`/`critical` overstated confidence for that profile. Both were restructured into the temporal correlation above rather than tiered independently — full reasoning in the correlation rule's Rationale.

### Cut Rules (genuine noise — not routed to the feed)

- **Suricata "Arsenal-237 SMB Share Enumeration Attempt"** (source sid `1000001`) — cut. The rule matched `content:"net use"` against `alert smb` traffic with no sticky buffer, but "net use" is a Windows command-line string typed at a local prompt or invoked via `CreateProcess` — it is never transmitted as literal text within the SMB protocol wire format, which carries binary SMB2/3 protocol messages (negotiate, tree connect, read/write), not the command text that produced them. As written, this signature cannot fire under any real traffic condition. The rule's direction (`$HOME_NET any -> $EXTERNAL_NET any`) is also inverted for a share-enumeration/lateral-movement scenario, which is characteristically internal-to-internal, not internal-to-external. No salvage was attempted: a genuine SMB-protocol share-enumeration signature would need to match actual Tree Connect requests against administrative share names (`C$`, `ADMIN$`, `IPC$`), which is new detection content, not a restructuring of a match that is structurally impossible as written. The `net use` command itself is properly covered at the correct telemetry layer by the Sigma correlation rule's process-creation base rule above. Not a routable atomic — "net use" is a command name, not an indicator value.

### Atomics Already Present in the IOC Feed

- **full_test_enc.exe SHA256/SHA1/MD5** — never expressed as a standalone YARA/Sigma/Suricata rule in the source draft (referenced only in the deleted KQL/Splunk query sections); already present under `file_hashes`.
- **`.lockbox` file extension** — the sole discriminator of source Sigma Rule 1; already present under `host_indicators.file_extensions`. Rather than cut the rule outright, this pass folded it into the temporal correlation above (see Retiering Fixes); no fresh feed addition was required.
- **`C:\Windows\Temp`** — a generic system path referenced by the source's "NetworkShare_Enumeration" YARA rule; already present under `host_indicators.file_paths`. Dropped from the salvaged YARA rule as non-discriminating filler (the path is common across enormous amounts of unrelated software) rather than cut for atomic-only status.

### Anti-Analysis Capability Without Dedicated Rule Coverage

The sample's VM-detection and exception-handler-based anti-debugging capability (confirmed via `VMware`/`VirtualBox` string references and `SetUnhandledExceptionFilter`/`AddVectoredExceptionHandler` API usage) has no dedicated rule in this file. The underlying strings are common, single-purpose generic terms — bare `VMware`/`VirtualBox` substrings appear broadly across unrelated software, and the Windows exception-handling APIs are used throughout ordinary software for unrelated reasons — and no combination of them cleared even the Hunting precision bar on salvage. This capability is documented here for completeness; it has no dedicated event-level detection.

### Test-Build Status and What Would Survive a Production Rebuild

The sample's filename and several of its strings (`[*] Encryptor starting...`, `[*] Encrypting all drives...`, `[+] Encryption complete!`) indicate a non-stripped, pre-release development build rather than a hardened production release. Coverage in this file distinguishes what depends on that development-build status from what does not: the ransom-note text, the Ransom ID label, and the `.lockbox` extension are the ransomware's actual functional output and would be expected to persist into a production build; the operational log strings and the custom crypto-engine error strings are debug/error-path text that a stripped release build could plausibly omit. Coverage should be revisited if a non-development Arsenal-237 build is later recovered.

### What Would Enable Stronger Coverage

- **Goodware corpus validation** — none of the Hunting-tier YARA rules (RustCrypto combination, custom crypto-engine error strings, net use error string) have been run against a broad clean-software corpus; a documented zero-FP result is the explicit precondition for reconsidering Detection tier on the RustCrypto combination in particular, given the realistic overlap with legitimate Rust software built on the same crate family.
- **A non-development-build sample** — a stripped, production Arsenal-237 build would confirm which strings survive release and let coverage anchor on the durable subset with higher confidence.
- **Network/C2 artifacts** — this build is confirmed offline with no C2 infrastructure; no Suricata Detection or Hunting signature is possible without an observed network channel.
- **SMB-protocol-level share-enumeration telemetry** — a genuine network signature for share enumeration would need to match actual SMB Tree Connect requests against administrative share names, not a command-line string that never appears on the wire.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
