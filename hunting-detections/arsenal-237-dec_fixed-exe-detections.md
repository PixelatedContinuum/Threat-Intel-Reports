---
title: "Detection Rules — dec_fixed.exe (Arsenal-237 Ransomware Decryptor)"
date: '2026-01-27'
layout: post
permalink: /hunting-detections/arsenal-237-dec_fixed-exe-detections/
hide: true
redirect_from: /hunting-detections/arsenal-237-dec_fixed-exe/
thumbnail: /assets/images/cards/arsenal-237-new-files.png
---

**Campaign:** Arsenal-237-New-Files-109.230.231.37
**Date:** 2026-01-27
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**IOC Feed:** https://the-hunters-ledger.com/ioc-feeds/arsenal-237-dec_fixed-exe.json

---

## Detection Coverage Summary

dec_fixed.exe is a Rust-compiled, per-victim ransomware decryptor from the Arsenal-237 toolkit, reversing ChaCha20-Poly1305 AEAD encryption using a hardcoded, victim-specific 256-bit key. The key is confirmed distinct from the key embedded in the related new_enc.exe encryptor build, establishing a per-victim key architecture consistent with a professional ransomware-as-a-service operation. As a victim-facing recovery tool rather than an attack tool, a positive detection here indicates a prior successful Arsenal-237 infection and completed ransom payment, not an active intrusion — coverage below is scoped for victim identification and post-incident forensic value.

Coverage below is retiered from the original draft: every rule was re-scored for durability (does it survive a rebuild issuing a new victim's key?), precision (documented false-positive profile), and level discipline, per the project's Detection/Hunting split. The tool's per-build cryptographic material and exact file hashes are single-sample atomic values, already captured in the IOC feed rather than carried as standalone rules. dec_fixed.exe has no observed network behavior — it is a fully offline, single-process utility — so no Suricata signature is supported by this investigation's evidence.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 2 | 0 | T1059, T1070.004, T1083, T1486 | 3 |
| Sigma | 0 | 2 | T1059, T1070.004, T1083 | 3 |
| Suricata | 0 | 0 | — | 0 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Atomics routed to the IOC feed:** dec_fixed.exe's three file hashes (SHA256/MD5/SHA1) and its own hardcoded ChaCha20 victim key were already present in [`arsenal-237-dec_fixed-exe.json`](/ioc-feeds/arsenal-237-dec_fixed-exe.json) before this retiering pass; the related new_enc.exe encryptor's key referenced in the same source YARA rule is a secondary cross-reference in this feed and a first-class entry in the sibling `arsenal-237-new_enc-exe.json` feed. The rule branches and standalone signatures that added no detection value beyond these feed entries — a YARA hash-string rule, a YARA victim-key rule, a Sigma hash-match branch, and a speculative Suricata network signature — have been retired; see Coverage Gaps for the complete reasoning on every retired rule.

---

## YARA Rules

### Detection Rules

#### ChaCha20-Poly1305 AEAD Decryption Implementation

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1486 (Data Encrypted for Impact — decryption/reversal context)
**Confidence:** HIGH
**Rationale:** Requires the RFC 7539 ChaCha20 256-bit-key constant (`expand 32-byte k`) together with at least one of the tool's own bespoke decryption-failure error strings. The constant alone is common to any ChaCha20 implementation (WireGuard, TLS 1.3, numerous legitimate secure-communication and backup tools); requiring co-occurrence with the specific, developer-written error phrasing narrows the match to this tool family. The combination survives a rebuild that only rotates the embedded victim key — the crypto constant and error-handling text are unrelated to per-victim key material.
**False Positives:** None known for the full combination. The ChaCha20 constant by itself is ubiquitous, which is why the rule never matches on it alone.
**Blind Spots:** A source-level rebuild using different (e.g., localized) error message text would evade; a match does not by itself confirm coverage of the related encryptor variants unless they share this exact error phrasing.
**Validation:** Scan dec_fixed.exe (hash below) — must match; a generic ChaCha20/libsodium/WireGuard binary without this tool's specific error phrasing must NOT fire.
**Deployment:** Endpoint AV/EDR file scanning, IR artifact triage, retroactive scan of file shares for victim-side recovery tooling.

```yara
/*
   Yara Rule Set
   Identifier: Arsenal-237-New-Files-109.230.231.37
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule TOOLKIT_Arsenal237_ChaCha20_Poly1305_Decryptor {
   meta:
      description = "Detects Arsenal-237 ransomware decryptor tools implementing ChaCha20-Poly1305 AEAD decryption. Requires the RFC 7539 ChaCha20 constant alongside at least one of the tool's own bespoke decryption-failure error strings, distinguishing it from generic ChaCha20 implementations."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-dec_fixed-exe-detections/"
      date = "2026-01-27"
      family = "Arsenal-237"
      malware_type = "Ransomware-Decryptor"
      campaign = "Arsenal-237-New-Files-109.230.231.37"
      id = "34144aa0-31ce-46e0-a11e-37d129acb214"
      hash1 = "d73c4f127c5c0a7f9bf0f398e95dd55c7e8f6f6a5783c8cb314bd99c2d1c9802"
   strings:
      $constant1 = "expand 32-byte k" nocase
      $error1 = "Decryption failed - wrong key or corrupted file"
      $error2 = "File corrupted - encrypted size mismatch"
   condition:
      uint16(0) == 0x5A4D and
      $constant1 and
      any of ($error*)
}
```

#### Decryptor CLI + Error + Cleanup Combination

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1059 (Command and Scripting Interpreter), T1083 (File and Directory Discovery), T1070.004 (Indicator Removal: File Deletion)
**Confidence:** HIGH
**Rationale:** Combines the tool's distinctive `--folder-a` batch-decryption flag (not a generic argument name) with 2-of-3 file-format validation error strings and the readme.txt ransom-note cleanup marker, all required in the same binary. No single element is unique on its own, but the four-way combination is specific to this tool's implementation — an unrelated utility would need to coincidentally embed all of them together.
**False Positives:** readme.txt and generic-sounding error text are individually common, but the mandatory `--folder-a` flag anchors the combination to this specific tool family.
**Blind Spots:** A rebuild renaming the CLI flag or rewording the error strings evades; targets the on-disk PE, not a packed or obfuscated variant.
**Validation:** Scan dec_fixed.exe (hash below) — must match; an unrelated batch file-processing utility referencing a generic --folder argument or readme.txt alone must NOT fire.
**Deployment:** Endpoint AV/EDR file scanning, IR artifact triage, retroactive scan of file shares.

```yara
rule TOOLKIT_Arsenal237_Decryptor_CLI_Combination {
   meta:
      description = "Detects the Arsenal-237 dec_fixed.exe-class decryptor tool via its distinctive --folder-a batch-decryption CLI flag combined with the tool's own file-format validation error strings and its readme.txt ransom-note cleanup marker."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-dec_fixed-exe-detections/"
      date = "2026-01-27"
      family = "Arsenal-237"
      malware_type = "Ransomware-Decryptor"
      campaign = "Arsenal-237-New-Files-109.230.231.37"
      id = "9a04aca8-2158-4e46-b232-672b78e0fff2"
      hash1 = "d73c4f127c5c0a7f9bf0f398e95dd55c7e8f6f6a5783c8cb314bd99c2d1c9802"
   strings:
      $cmd1 = "--folder-a"
      $error1 = "File too small"
      $error2 = "Could not find filename"
      $error3 = "Invalid victim key hex"
      $cleanup = "readme.txt"
   condition:
      uint16(0) == 0x5A4D and
      $cmd1 and
      2 of ($error*) and
      $cleanup
}
```

---

## Sigma Rules

### Hunting Rules

#### dec_fixed.exe Execution with --folder-a Parameter

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1059 (Command and Scripting Interpreter), T1083 (File and Directory Discovery)
**Confidence:** LOW
**Rationale:** Requires both the exact filename (`dec_fixed.exe`) and the `--folder-a` CLI flag together — two literals from the same build. The "dec_fixed" name itself already signals a corrected/versioned build, so a renamed future build evades this rule entirely; kept as a Hunting lead for recurrence of this specific build rather than promoted to Detection. *Retiering note:* the source rule's hash-match branch has been removed — see Coverage Gaps.
**False Positives:** Legitimate victim-side decryption operations by IT/incident-response staff (the tool's designed use case), or manual testing of a recovered sample by an analyst.
**Deployment:** Sysmon/EDR process-creation monitoring, IR artifact triage, victim identification sweeps.

```yaml
title: Arsenal-237 dec_fixed.exe Decryptor Execution with Folder-A Parameter
id: f84722fb-218a-40e4-a976-18d6db0cec9b
status: experimental
description: >-
  Detects execution of the Arsenal-237 dec_fixed.exe per-victim ransomware decryptor
  with its --folder-a batch-decryption parameter. A positive hit indicates victim-side
  recovery activity following a prior Arsenal-237 ransomware infection and ransom
  payment, not an active intrusion.
references:
  - https://the-hunters-ledger.com/hunting-detections/arsenal-237-dec_fixed-exe-detections/
author: The Hunters Ledger
date: '2026-01-27'
tags:
  - attack.execution
  - attack.discovery
  - attack.t1059
  - attack.t1083
  - detection.emerging-threats
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\dec_fixed.exe'
    CommandLine|contains: '--folder-a'
  condition: selection
falsepositives:
  - Legitimate victim-side decryption operations by IT/incident-response staff (low probability, but the tool's designed use case).
  - Manual testing of a recovered decryptor sample by an analyst.
level: medium
```

#### readme.txt Ransom-Note Deletion by dec_fixed.exe

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1070.004 (Indicator Removal: File Deletion)
**Confidence:** LOW
**Rationale:** readme.txt is a common filename; requiring the deletion to be performed specifically by the decryptor's own process image narrows what would otherwise be baseline noise (any process deleting a file named readme.txt) to a lead tied to this tool's documented post-decryption cleanup behavior. *Retiering note:* the source rule's broader cmd.exe/powershell.exe selector branches have been removed — see Coverage Gaps.
**False Positives:** A rebuild of the decryptor under a different process name would evade this exact selector while performing the same cleanup; IT cleanup scripts deleting an unrelated readme.txt via a similarly-named tool are a coincidental collision risk.
**Deployment:** Sysmon/EDR file-deletion event monitoring (Sysmon Event ID 23 or equivalent), correlated with the process-execution rule above.

```yaml
title: Arsenal-237 readme.txt Ransom-Note Deletion by dec_fixed.exe
id: 1a079f87-721d-4bb4-a4c7-c43e5939c1ab
status: experimental
description: >-
  Detects deletion of a file named readme.txt specifically by the Arsenal-237
  dec_fixed.exe decryptor process, consistent with the tool's documented
  post-decryption ransom-note cleanup behavior. Narrowed from a broader original
  selector that also matched readme.txt deletion by cmd.exe or powershell.exe —
  see Coverage Gaps.
references:
  - https://the-hunters-ledger.com/hunting-detections/arsenal-237-dec_fixed-exe-detections/
author: The Hunters Ledger
date: '2026-01-27'
tags:
  - attack.stealth
  - attack.t1070.004
  - detection.emerging-threats
logsource:
  product: windows
  category: file_delete
detection:
  selection:
    TargetFilename|endswith: 'readme.txt'
    Image|endswith: '\dec_fixed.exe'
  condition: selection
falsepositives:
  - A rebuild of the decryptor under a different process name would evade this exact selector while still performing the same cleanup; readme.txt is otherwise a common filename.
level: low
```

---

## Coverage Gaps

### Retiering Fixes Applied

- **Sigma dec_fixed.exe execution rule narrowed to its behavioral selector (source Rule 1).** The original condition was `selection_process or selection_hash`, where `selection_hash` matched purely on the sample's SHA256/MD5/SHA1 process-creation hash fields — a pure-IOC selector per the project's Sigma Cut checklist. That branch added no detection value beyond a direct hash lookup and has been removed; all three hashes were already present in `arsenal-237-dec_fixed-exe.json`. The surviving `selection_process` branch (filename + `--folder-a` flag) is retained as a Hunting-tier rule.
- **Sigma readme.txt-deletion rule narrowed from a 3-process OR-list to dec_fixed.exe only (source Rule 3).** The original `selection_context` matched readme.txt deletion by `dec_fixed.exe`, `powershell.exe`, OR `cmd.exe`. Because readme.txt deletion via either general-purpose shell is routine, benign IT/scripting activity (acknowledged in the rule's own false positives list as a "common filename"), the two shell branches reduced the rule to near-pure baseline noise. Rather than cut the rule outright, it has been narrowed to require the deletion be performed by the decryptor process itself, salvaging a real, if brittle, lead. The rule's `attack.stealth` tactic tag (verified against the real `sigma check` tool as the correct ATT&CK-v19 pairing for `attack.t1070.004`) is retained unchanged from the source.
- **Sigma status normalized to `experimental`** on both surviving rules (source used `test` on Rule 1) — the project's standard status for newly re-authored site rules.
- **YARA MZ-header pre-gate added.** Both surviving YARA rules gained a `uint16(0) == 0x5A4D` pre-gate ahead of the string matching, following the project's cheap-before-expensive condition-ordering convention; this only excludes non-PE files and does not narrow true-positive coverage.

### Cut Rules (genuine noise or fabricated — not routed to the feed)

- **YARA "Rust-Compiled Arsenal-237 Tools"** (source Rule 5) — cut. Its condition combined a 900KB–1MB filesize window (fragile to any recompilation) with the generic Rust crate names `chacha20` and `poly1305` (widely used by legitimate Rust cryptographic software), a bare `"hex"` string below YARA's own 4-byte minimum-anchor guidance (matches almost any binary containing that 3-byte sequence), and a truncated, generic `"Decryption failed"` fragment — versus the full, bespoke phrase used in the surviving ChaCha20-Poly1305 rule. Every element of genuine value here is a strict subset of, and weaker than, the surviving `TOOLKIT_Arsenal237_ChaCha20_Poly1305_Decryptor` rule's anchors; salvage would only reconstruct that rule with worse precision. No atomic to route — this was a multi-condition combination, not a single hard-coded literal.
- **Sigma "ChaCha20-Poly1305 Cryptographic Operations"** (source Rule 4, id `fe86898b-5f79-4cee-b035-3cf967790ebb`) — cut. The rule hypothesized `image_load` events with `ImageLoaded` containing `chacha20`/`poly1305`/`aead` triggered by `cmd.exe`, `powershell.exe`, or `explorer.exe` loading such a module. Nothing in this investigation's confirmed static evidence supports that behavior: dec_fixed.exe is a statically-linked Rust binary (its crypto library names appear as strings embedded inside the executable itself, not as separately loadable DLLs), and there is no documented mechanism by which this offline, single-process decryptor would inject a crypto module into an unrelated shell or Explorer process. The rule's own description self-acknowledged a "high false positive rate." This echoes a prior finding in this malware family, where a ChaCha20 enc-dec rule was removed for using field names that could never fire — here the field name (`ImageLoaded`) is syntactically valid Sigma, but the behavioral claim itself is unverified and unsupported by the sample's own evidence, so it is treated the same way: cut with this coverage note rather than published. No salvage path exists (no image-load telemetry is documented for this tool) and no atomic to route.
- **Suricata "Arsenal-237 Decryptor Network Activity"** (source sid `20260126001`) — cut. The rule matched a `dec_fixed` substring in the HTTP User-Agent header, explicitly hedged by its own author as speculative ("if variant performs C2 check") and directly contradicted by this investigation's own finding that dec_fixed.exe exhibits no network activity. No confirmed protocol structure exists to anchor a real signature, and no atomic (IP/domain) is available to route to the feed.

### Atomics Routed to the IOC Feed

- **File hashes** (SHA256 `d73c4f12...c9802`, MD5 `7c5493a0...34601`, SHA1 `29014d4d...c14c2`) — the sole discriminator of YARA source Rule 1 (`Arsenal237_dec_fixed_exe`) and the `selection_hash` branch of Sigma source Rule 1. All three are already present in `arsenal-237-dec_fixed-exe.json` under `file_hashes`. *Note:* YARA source Rule 1 matched the SHA256 value as an ASCII **string** inside the file's own bytes rather than as an actual hash computation — this is not equivalent to hash verification and would not reliably fire even before retiering (see "A Note on Source Rule Soundness" below).
- **Hardcoded ChaCha20 decryption keys** — the sole discriminator of YARA source Rule 2 (`Arsenal237_Victim_Key_Decryptor`). `1e0d8597...2e73ba` (this sample's own victim-specific key) is present in `arsenal-237-dec_fixed-exe.json` under `cryptographic_indicators.hardcoded_keys`. `67e6096a...9cde05b` (the related new_enc.exe encryptor's key, embedded in this same YARA rule as an alternate match) is present in the same feed only as a secondary cross-reference (`hardcoded_keys[0].related_samples["new_enc.exe_key"]`), not as a first-class entry — its canonical home is the sibling `arsenal-237-new_enc-exe.json` feed, where it is a first-class `encryption_keys[0].key_hex` entry. Both keys are per-build, one-off cryptographic material (Robustness 0) rather than durable technique indicators.

### A Note on Source Rule Soundness

Two source rules had structural problems independent of tiering. YARA source Rule 1 (`Arsenal237_dec_fixed_exe`) searched for the sample's own SHA256 hash as a literal ASCII string within the file's bytes — functionally different from, and not a substitute for, an actual hash match; nothing in this investigation's evidence suggests the binary embeds a printable copy of its own hash, so the rule would not reliably fire against the sample it was built to detect even before this retiering pass. Sigma source Rule 4 (see Cut Rules above) hypothesized a dynamic module-load behavior with no supporting evidence. Both are addressed above via the atomics/feed and cut dispositions rather than repair, since the durable value in each case (the hash itself; the crypto capability) is already covered elsewhere in this file or in the IOC feed.

### No Network Coverage — Offline Tool

dec_fixed.exe is a fully offline, single-process utility with no observed network activity. No protocol, URI, header, or connection-endpoint structure is available from which to build a Suricata Detection or Hunting signature, and there is no confirmed C2 IP or domain associated with this specific artifact to route to the feed.

### Pre-Existing Gap: A Second Sigma Rule Removed Prior to This Pass

This file's Sigma coverage already numbered its rules 1, 3, and 4 before this retiering pass began — a prior pass (dated 2026-07-06) removed a second Sigma rule with the note: "Rules matching generic file paths or ubiquitous behaviors were removed as false-positive sources." That removal's original rule content was not available to re-evaluate here; this file's Sigma rule count and conservation accounting are based on the three rules that were actually present (the former Rules 1, 3, and 4).

### Family Context

dec_fixed.exe is the victim-facing decryptor half of the Arsenal-237 ransomware-as-a-service toolkit; the family's encryptor components (new_enc.exe, enc_c2.exe, full_test_enc.exe) and supporting toolkit modules carry their own, separate detection files. A positive hit against any rule in this file indicates a prior successful infection and ransom payment, not an active intrusion — coverage here supports victim identification and post-incident forensic investigation rather than intrusion prevention.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
