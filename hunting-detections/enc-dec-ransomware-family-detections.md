---
title: "Detection Rules — enc/dec Ransomware Family"
date: '2026-01-18'
layout: post
permalink: /hunting-detections/enc-dec-ransomware-family-detections/
hide: true
redirect_from: /hunting-detections/enc-dec-ransomware-family/
thumbnail: /assets/images/cards/109.230.231.37-Executive-Overview.png
---

**Campaign:** Arsenal-237-109.230.231.37-Malware-Repository
**Date:** 2026-01-18
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**IOC Feed:** https://the-hunters-ledger.com/ioc-feeds/enc-dec-ransomware-family.json

---

## Detection Coverage Summary

The enc/dec ransomware family is a custom-developed Rust toolkit (five encryptor variants, five decryptor variants, plus a GUI test build) recovered from the Arsenal-237 open directory at `109.230.231.37`, the same threat-actor R&D repository that also exposed the agent.exe RAT and its sibling components. The toolkit implements hybrid RSA-2048 + ChaCha20 encryption with hardware-optimized (AVX-512/AVX2/SSE) code paths and deletes Volume Shadow Copies via vssadmin.exe/wmic.exe ahead of file encryption.

Coverage below is retiered from the original draft: every rule was re-scored for durability (does it survive infrastructure rotation and recompilation?), precision (documented false-positive profile), and level discipline, per the project's Detection/Hunting split. Two rules did not survive this pass — see Coverage Gaps for the full reasoning.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 1 | 2 | T1486, T1490 | 0 |
| Sigma | 1 | 0 | T1490 | 0 |
| Suricata | 0 | 0 | — | 0 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Atomics routed to the IOC feed:** this retiering pass did not surface any new atomic indicators. The family's ten file hashes (SHA256/SHA1/MD5) and the distribution IP (`109.230.231.37`) were already present in [`enc-dec-ransomware-family.json`](/ioc-feeds/enc-dec-ransomware-family.json) before this pass, and neither retired rule reduced to a clean atomic value — see Coverage Gaps.

---

## YARA Rules

### Detection Rules

#### Rust Ransomware Artifacts Combination

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1486 (Data Encrypted for Impact)
**Confidence:** HIGH
**Rationale:** *Fix applied during retiering:* the original condition read `uint16(0) == 0x5A4D and 2 of ($rust_debug*) or ($rsa_key_marker and ($enc_message or $key_gen))`. YARA's `and` binds tighter than `or`, so this parsed as `(uint16(0)==0x5A4D and 2 of ($rust_debug*)) or ($rsa_key_marker and (...))` — the second branch carried no PE-header gate at all. Explicit parentheses now apply the MZ check to both branches. The two project-specific Rust source paths (`chacha20_pervictim.rs`, `netusesrc/modules/disks.rs`) are not generic crate names — they name this family's own per-victim-key and network-share modules — and combined 2-of-3 with the third-party `aead` crate dependency path, or alternatively the embedded RSA key marker paired with one of two bespoke operator console messages, this is a durable multi-signal combination that no single renameable literal carries alone.
**False Positives:** None known — the combination of project-specific Rust debug paths, or an embedded RSA public key alongside a bespoke encryption-status console message, is not expected in unrelated software.
**Blind Spots:** A build stripped of debug symbols (no embedded Rust source paths) and with rebranded console messages would evade every branch; the rule targets on-disk static artifacts, not in-memory-only execution.
**Validation:** Scan a captured enc/dec family sample (e.g., `enc_pervictim.exe`) — must match; an unrelated Rust cryptographic tool must NOT fire.
**Deployment:** Endpoint AV/EDR file scanning, email gateway attachment scanning, retroactive scan of file shares, IR artifact triage.

```yara
/*
   Yara Rule Set
   Identifier: Arsenal-237-109.230.231.37-Malware-Repository
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule MAL_EncDec_Rust_Ransomware_Artifacts {
   meta:
      description = "Detects enc/dec Rust ransomware variants via project-specific Rust source debug paths or the combination of an embedded RSA public key with the family's encryption-status and key-generation console messages. Corrects a missing-parentheses precedence bug in the original rule that left one branch without a PE-header gate."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/enc-dec-ransomware-family-detections/"
      date = "2026-01-18"
      family = "EncDec-Ransomware"
      malware_type = "Ransomware"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "8413bc6f-1109-4e62-a26b-f4e535c1c6ad"
   strings:
      $rust_debug1 = "chacha20_pervictim.rs" ascii wide
      $rust_debug2 = "netusesrc/modules/disks.rs" ascii wide
      $rust_debug3 = "/aead-0.5.2/src/lib.rs" ascii wide
      $rsa_key_marker = "-----BEGIN PUBLIC KEY-----" ascii wide
      $enc_message = "[*] Using RSA+ChaCha20 encryption" ascii wide
      $key_gen = "[*] Generating unique encryption key" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      (
         2 of ($rust_debug*) or
         ($rsa_key_marker and ($enc_message or $key_gen))
      )
}
```

### Hunting Rules

#### ChaCha20 Encryption Constant

**Tier:** Hunting
**Robustness:** 3
**ATT&CK Coverage:** T1486 (Data Encrypted for Impact)
**Confidence:** MODERATE
**Rationale:** "expand 32-byte k" is the RFC 8439 ChaCha20 initialization constant — the malware cannot substitute or rename it without breaking standard ChaCha20 interoperability, so this is a genuine technique-level invariant that survives recompilation and rebranding (Robustness 3). It fails the Detection bar on precision alone: the constant is a required component of any standard ChaCha20 implementation, and legitimate ChaCha20 consumers are a real, non-trivial population. No goodware-corpus validation has been performed to characterize the actual hit rate on a clean fleet, so this stays Hunting until that validation exists.
**False Positives:** Legitimate software statically linking a standard ChaCha20 implementation — VPN clients (WireGuard, OpenVPN with ChaCha20-Poly1305 cipher suites), SSH clients using the chacha20-poly1305@openssh.com cipher, TLS 1.3 stacks offering a ChaCha20-Poly1305 cipher suite, and secure-messaging applications are all expected to embed this exact string.
**Deployment:** Endpoint AV/EDR static file scanning, retroactive scan of file shares, IR artifact triage — correlate a hit with the Rust Artifacts or VSS Deletion rules before treating it as ransomware-indicative.

```yara
rule MAL_EncDec_ChaCha20_Constant {
   meta:
      description = "Detects the RFC 8439 ChaCha20 initialization constant (expand 32-byte k) in a PE file, confirmed present in the enc/dec ransomware family's encryptor and decryptor variants. The same constant is required by any standard ChaCha20 implementation, including legitimate VPN and secure-messaging software, so treat a hit as a scoping lead rather than a standalone alert."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/enc-dec-ransomware-family-detections/"
      date = "2026-01-18"
      family = "EncDec-Ransomware"
      malware_type = "Ransomware"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "d284edca-9974-4d43-8228-aa99da540697"
   strings:
      $chacha20_constant = "expand 32-byte k" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      $chacha20_constant
}
```

#### VSS Deletion Concatenated String

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1490 (Inhibit System Recovery)
**Confidence:** MODERATE
**Rationale:** This 47-byte string is not a command the malware issues as written — a real process-creation call to vssadmin/wmic requires space-delimited argv tokens, not a gapless concatenation. The more plausible explanation is that this reflects several short, adjacent string-table constants (`vssadmin`, `delete`, `shadows`, `/all`, `/quiet`, `wmic`, `shadowcopy`) packed back-to-back with no separating bytes by this family's Rust build toolchain, which a naive string-extraction pass then reads as one contiguous run. That gives it real value for recognizing this specific build lineage today, but a toolchain change, added dependency, or reordered source could shift the layout and break the exact match — it is not guaranteed to survive a genuine recompile the way the command-line-level Sigma detection below does, which is why the same underlying technique is carried at Detection tier there instead.
**False Positives:** None known — the exact 47-byte gapless concatenation of these seven tokens is not expected in unrelated software.
**Deployment:** Endpoint AV/EDR static file scanning, retroactive scan of file shares, IR artifact triage for recurrence of this specific build family.

```yara
rule MAL_EncDec_VSS_Deletion_Concatenated_String {
   meta:
      description = "Detects the enc/dec ransomware family's distinctive concatenated Volume Shadow Copy deletion string, observed packed with no separators in this family's builds. Most plausibly a string-table adjacency artifact of this family's Rust build toolchain rather than a runtime-constructed string, so it is not guaranteed to survive a future recompile."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/enc-dec-ransomware-family-detections/"
      date = "2026-01-18"
      family = "EncDec-Ransomware"
      malware_type = "Ransomware"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "31ef0486-276c-41b3-8de7-3bb8df7eaaf3"
   strings:
      $vss_sig = "vssadmindeleteshadows/all/quietwmicshadowcopy" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      $vss_sig
}
```

---

## Sigma Rules

### Detection Rules

#### enc/dec Ransomware VSS Deletion Activity

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1490 (Inhibit System Recovery)
**Confidence:** HIGH
**Rationale:** *Fixes applied during retiering:* `level` demoted from `critical` to `high` — the rule's own false-positive list concedes VSS deletion occurs, rarely, during legitimate system maintenance and backup-software uninstallation, which is inconsistent with `critical`'s never-FP bar; `high` ("rare FP after baselining; manual review") is the honest level. `status` changed from `stable` to `experimental` per project convention for a freshly-retiered rule. A `references:` entry pointing at this file was added — the original carried none. The underlying technique — invoking vssadmin.exe or wmic.exe with this specific delete-shadows/shadowcopy-delete argument combination — is a technique-level chokepoint for this recovery-inhibition mechanism: an attacker cannot rename vssadmin.exe's command syntax, so this survives infrastructure rotation and binary rebuilds untouched.
**False Positives:** Legitimate system maintenance and backup-software uninstallation routines occasionally invoke VSS deletion with these exact commands, though this is rare in most environments; review the parent process before treating a hit as confirmed malicious.
**Blind Spots:** Misses VSS deletion via PowerShell cmdlets, direct COM/WMI API calls that bypass vssadmin.exe/wmic.exe process creation, or a custom VSS-deletion implementation that does not shell out to either tool.
**Validation:** Trigger `vssadmin delete shadows /all /quiet` or `wmic shadowcopy delete` — must match; an unrelated vssadmin invocation without the delete-shadows/all combination (e.g., `vssadmin list shadows`) must NOT fire.
**Deployment:** SIEM/EDR process-creation telemetry (Sysmon Event ID 1, Windows Security 4688), real-time alerting — a well-established, high-value ransomware precursor signal.

```yaml
title: enc/dec Ransomware VSS Deletion Activity
id: ad52d938-ac86-4587-86c9-008ad0534b68
status: experimental
description: Detects Volume Shadow Copy deletion commands via vssadmin.exe or wmic.exe consistent with the enc/dec ransomware family's pre-encryption recovery-inhibition step.
references:
    - https://the-hunters-ledger.com/hunting-detections/enc-dec-ransomware-family-detections/
author: The Hunters Ledger
date: '2026-01-18'
tags:
    - attack.impact
    - attack.t1490
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection_vssadmin:
        CommandLine|contains|all:
            - 'vssadmin'
            - 'delete'
            - 'shadows'
            - '/all'
    selection_wmic:
        CommandLine|contains|all:
            - 'wmic'
            - 'shadowcopy'
            - 'delete'
    condition: selection_vssadmin or selection_wmic
falsepositives:
    - Legitimate system maintenance (rare)
    - Backup software uninstallation
level: high
```

---

## Coverage Gaps

### Retiering Fixes Applied

- **YARA operator-precedence bug fixed (Rust Ransomware Artifacts rule).** The original condition read `uint16(0) == 0x5A4D and 2 of ($rust_debug*) or ($rsa_key_marker and ($enc_message or $key_gen))`. YARA's `and` binds tighter than `or`, so this parsed as `(uint16(0)==0x5A4D and 2 of ($rust_debug*)) or ($rsa_key_marker and (...))` — the second branch carried no PE-header gate at all and could in principle match a non-PE file. Explicit parentheses now apply the MZ check to both branches; the corrected rule compiles cleanly against the real `yarac` engine.
- **Sigma level demoted, status corrected, reference added (VSS Deletion Activity rule).** See that rule's own Rationale above for the full reasoning.

### Cut Rules (This Pass — Genuine Noise / Unfireable)

- **YARA Anti-Debug Signature** (`EncDec_AntiDebug_Signature`) — cut. The byte pattern `{ E8 ?? ?? ?? ?? 6A 00 68 E8 03 00 00 }` was documented as matching a Sleep(1000) call in x64 assembly, but the pattern itself is a 32-bit push-based argument setup (`PUSH 0`, `PUSH 0x3E8`). The Windows x64 calling convention passes a function's first integer arguments in registers (RCX/RDX/R8/R9), not via PUSH — compiled x64 code, which is what every sample in this family is per the IOC feed's own file-type field, would not produce this instruction sequence for a genuine Sleep or SleepEx call. The pattern also places its CALL instruction before the two PUSH instructions that would need to precede it as that call's own arguments, which is not a coherent single call sequence. Both problems point to a pattern that was not derived from validated disassembly of these specific x64 samples and is unlikely to ever match them — the exact "compiles but cannot match" failure mode this retiering pass was directed to hunt for. The underlying anti-debugging technique it was meant to detect is real and independently confirmed — see "Coverage Lost," below — but a corrected signature requires fresh disassembly of the actual stack-check routine, which is outside the scope of this retiering pass. No atomic value survives to route to the feed; a broken byte pattern has no standalone indicator value.
- **YARA Comprehensive Family Detection** (`EncDec_enc_dec_Family_Comprehensive`) — cut. As written, the rule is only as strong as its weakest OR-branch: one branch is the bare ChaCha20 constant (already carried, at Hunting tier, by the standalone rule above — this branch duplicates it without adding value), and the third branch (`3 of ($ops*) and 1 of ($rust*)`) is built from README, decrypt, `--file`, and `--folder` — generic tokens expected in legitimate backup, archival, and encryption utilities — with `.rs` (a 3-byte string, under the project's 4-byte minimum anchor length) available to satisfy the same branch's Rust indicator. No goodware-corpus validation supports the rule's "comprehensive" framing. The distinctive, low-noise indicators this rule was reaching for (the project-specific Rust debug paths, the RSA-key-plus-bespoke-message combination) are already captured with tighter logic by the Rust Ransomware Artifacts rule above; salvage was considered and rejected because nothing in this rule's remaining branches adds coverage beyond what survives elsewhere in this file.

### Prior Retiering — Historical Context

A 2026-07-06 pass on this file already removed a Sigma rule ("enc/dec ChaCha20 Cryptographic Operations") that keyed on `Strings`, `MemoryAllocation|gt`, and `CPUUsage` fields — none of which exist on any Sigma logsource category, so the rule could never have matched real telemetry. That removal, and the accompanying note that other Sigma rules "matching generic file paths or ubiquitous behaviors were removed as false-positive sources," are preserved from the source file; this pass did not need to revisit that decision. The ChaCha20 constant indicator that removed rule targeted remains covered by the YARA rule above, which performs the equivalent string match against on-disk/in-memory file content.

### Coverage Lost: Debugger Evasion (T1622)

Cutting the Anti-Debug Signature rule removes this file's only coverage for the family's stack-base-check-plus-Sleep anti-debugging loop (T1622) and its companion vectored-exception-handling evasion. Both behaviors are independently confirmed as present across the family's samples, but no rule here currently detects either. A corrected static signature requires disassembly of the actual routine rather than the unverifiable pattern this file previously carried.

### No Suricata Coverage — C2 Not Directly Observed

This family's only network artifact is the distribution IP itself; no C2 protocol traffic has been observed, so no protocol, URI, or header structure exists from which to build a Suricata rule. The distribution IP is already routed to the IOC feed and was never packaged as a standalone signature in this file.

### What Would Enable Stronger Coverage

- **Goodware corpus validation** for the ChaCha20 constant rule — a documented zero-FP result against a broad clean-software corpus (VPN clients, TLS stacks, secure-messaging apps) is the explicit precondition for reconsidering Detection tier.
- **Fresh disassembly of the anti-debugging stack-check routine** — a byte-level or API-hook-based signature derived from validated x64 disassembly would restore T1622 coverage.
- **Observed C2 traffic** — protocol structure from an active session would enable a genuine Suricata signature beyond the feed-only IP coverage.
- **Build-to-build reproducibility check on the VSS-deletion concatenated string** — confirming the exact 47-byte sequence survives a toolchain or dependency change would support reconsidering that rule's durability score.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
