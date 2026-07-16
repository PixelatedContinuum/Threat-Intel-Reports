---
title: "Detection Rules — BdApiUtil64.sys (Arsenal-237 BYOVD Component)"
date: '2026-01-26'
layout: post
permalink: /hunting-detections/arsenal-237-BdApiUtil64-sys-detections/
hide: true
redirect_from: /hunting-detections/arsenal-237-BdApiUtil64-sys/
thumbnail: /assets/images/cards/arsenal-237-new-files.png
---

**Campaign:** Arsenal-237-109.230.231.37-Malware-Repository
**Date:** 2026-01-26
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**IOC Feed:** https://the-hunters-ledger.com/ioc-feeds/arsenal-237-BdApiUtil64-sys.json

---

## Detection Coverage Summary

BdApiUtil64.sys is a legitimately-signed Baidu Antivirus kernel driver (signed 2012, expired 2015, still loadable on unpatched Windows configurations) repurposed as a Bring-Your-Own-Vulnerable-Driver (BYOVD) component within the Arsenal-237 toolkit, recovered from the same open directory at `109.230.231.37` as the broader Arsenal-237 malware repository. Loaded with SYSTEM privileges via a service named Bprotect, the driver exposes IOCTL-driven capabilities for direct and SSDT-bypass security-product termination, kernel-privileged Windows service creation, and credential/file-store access — a Stage 3 defense-evasion enabler that operates ahead of ransomware or follow-on payload execution.

Coverage below is retiered from the original draft: every rule was re-scored for durability (does it survive infrastructure rotation and renaming?), precision (documented false-positive profile), and level discipline, per the project's Detection/Hunting split. For a signed vulnerable driver, the most durable anchors are the driver's own embedded signer identity and its IOCTL surface — properties baked into the code and digital-signature block that persist regardless of what filename or service name an operator deploys it under — rather than the on-disk filename or service name, which an operator can trivially rename. Coverage is scoped accordingly: driver-identity and IOCTL-surface signatures land Detection; the campaign's two generic kernel-technique rules (SSDT-bypass resolution, kernel-mode security-process termination) land Hunting because the same API combinations are dual-use in legitimate kernel security tooling; the file hashes and the distribution IP are carried in the IOC feed.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 2 | 2 | T1068, T1685, T1014 | 0 |
| Sigma | 1 | 1 | T1068, T1685, T1547.006 | 1 |
| Suricata | 0 | 0 | — | 0 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Atomics routed to the IOC feed:** the driver's file hashes (SHA256 `47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428`, plus MD5 and SHA1) and the Arsenal-237 distribution IP (`109.230.231.37`) were already present in [`arsenal-237-BdApiUtil64-sys.json`](/ioc-feeds/arsenal-237-BdApiUtil64-sys.json) before this retiering pass. The source draft's hash-based Sigma selector added no detection value beyond those feed entries and has been folded into a cleaner driver-identity selector — see Coverage Gaps for the full reasoning on every retired or restructured rule.

---

## YARA Rules

### Detection Rules

#### BdApiUtil64.sys Baidu Driver Identity (Signer, PDB, and Internal Object Names)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1068 (Exploitation for Privilege Escalation — BYOVD with a legitimately-signed driver)
**Confidence:** HIGH
**Rationale:** This rule fingerprints the BdApiUtil64.sys driver itself — the legitimate-but-weaponized artifact at the center of this BYOVD technique — by combining internal, code-embedded strings (a build-server PDB path, the vendor's legal signer name, the product name, and internal kernel object names the driver registers at load) rather than its on-disk filename. A signed driver's embedded identity is a materially more durable anchor than a filename: an operator can trivially rename BdApiUtil64.sys to any arbitrary path before dropping it, but cannot strip these strings without altering the driver's code, which would invalidate the Baidu digital signature and defeat the entire point of using a validly-signed driver for this technique. The 2-of-6 combination requirement means the rule does not hinge on any single string and would still fire against a partially-modified copy of the same driver.
**False Positives:** None expected outside a genuine Baidu Antivirus installation, which enterprise telemetry generally describes as very rare. A real Baidu AV install would trip all six strings, not just two.
**Blind Spots:** A fully recompiled variant of this driver with the identifying strings stripped or replaced would evade — not observed for this component, and doing so would require Baidu's original source or a binary patch sophisticated enough to preserve a valid Baidu signature, which is not how BYOVD abuse of this driver has been documented to work.
**Validation:** Scan the BdApiUtil64.sys sample (hash below) — must match; an unrelated signed kernel driver from a different vendor must NOT fire.
**Deployment:** Endpoint AV/EDR file scanning, driver-load-time scanning, retroactive scan of `System32\drivers` and temp directories, IR artifact triage on hosts where the driver may have loaded.

```yara
/*
   Yara Rule Set
   Identifier: Arsenal-237-109.230.231.37-Malware-Repository
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule TOOLKIT_BdApiUtil64_Baidu_Driver_Identity {
   meta:
      description = "Detects BdApiUtil64.sys, a legitimately-signed Baidu Antivirus kernel driver weaponized for BYOVD attacks, via its embedded PDB path, signer/product strings, and internal kernel object names. These anchors live inside the driver's own code and digital-signature block rather than in its on-disk filename, so the rule survives the driver being dropped or renamed to a different path."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-BdApiUtil64-sys-detections/"
      date = "2026-01-26"
      family = "Arsenal-237-BYOVD-Component"
      malware_type = "Vulnerable-Driver-BYOVD"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "b4f2a891-3c6d-4e17-9a52-8d1f6c3e9a04"
      hash1 = "47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428"
   strings:
      $pdb = "D:\\jenkins\\workspace\\bav_5.0_workspace\\BavOutput\\Pdb\\Release\\BdApiUtil64.pdb" ascii wide
      $signer = "Baidu Online Network Technology" ascii wide
      $product = "Baidu Antivirus" ascii wide
      $device = "\\Device\\BdApiUtil" ascii wide
      $service = "Bprotect" ascii wide
      $callback = "bdProtectExpCallBack" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      uint32(uint32(0x3C)) == 0x00004550 and
      (2 of ($*))
}
```

#### BdApiUtil64.sys IOCTL Abuse (DeviceIoControl + Documented IOCTL Codes)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1685 (Impair Defenses), T1068 (Exploitation for Privilege Escalation — BYOVD)
**Confidence:** HIGH
**Rationale:** This rule targets any tooling that abuses BdApiUtil64.sys's documented capabilities via DeviceIoControl, keyed on the driver's own device object name (`\.\BdApiUtil`, fixed by the driver's own code, not chosen by the calling malware's author) plus 2-of-5 of the driver's documented IOCTL codes as raw byte patterns. The IOCTL surface a vulnerable driver exposes is a durable anchor: a caller wanting to abuse this specific driver's kernel-termination, SSDT-bypass, service-manipulation, or file-access primitives must reference this exact device path and these exact codes — properties of the target driver, not choices the calling malware's operator can rename away.
**False Positives:** None known outside genuine Baidu Antivirus operations referencing their own device object — rare in enterprise environments per the driver vendor's general rarity.
**Blind Spots:** A caller that resolves the device path or IOCTL codes dynamically or in an obfuscated form (rather than embedding them as plain strings/bytes) would evade static detection; this rule targets on-disk/in-memory string and byte presence, not runtime IOCTL dispatch.
**Validation:** Scan a tool that calls DeviceIoControl against `\.\BdApiUtil` with 2 or more of the documented IOCTL codes — must match; unrelated software calling DeviceIoControl against a different device must NOT fire.
**Deployment:** Endpoint AV/EDR file scanning, IR artifact triage on hosts where BdApiUtil64.sys loaded, retroactive scan of file shares and staging directories.

```yara
rule TOOLKIT_BdApiUtil64_IOCTL_Abuse {
   meta:
      description = "Detects tooling that calls DeviceIoControl against the BdApiUtil64.sys driver's device object using its documented IOCTL codes (direct termination, SSDT-bypass termination, service manipulation, file access). The device name and IOCTL codes are fixed properties of the target driver's own dispatch interface, not choices the calling malware's author controls, so this survives the caller being renamed or recompiled."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-BdApiUtil64-sys-detections/"
      date = "2026-01-26"
      family = "Arsenal-237-BYOVD-Component"
      malware_type = "Vulnerable-Driver-BYOVD"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "c7e9d302-5a1b-4f83-8e64-1b9a7d4f2c56"
   strings:
      // Primary IOCTL codes
      $ioctl1 = { B4 24 00 80 }    // 0x800024b4 - Direct termination
      $ioctl2 = { B8 24 00 80 }    // 0x800024b8 - SSDT bypass
      $ioctl3 = { 24 23 00 80 }    // 0x80002324 - Service manipulation
      $ioctl4 = { 48 26 00 80 }    // 0x80002648 - File access 1
      $ioctl5 = { 4C 26 00 80 }    // 0x8000264c - File access 2

      // DeviceIoControl API
      $api = "DeviceIoControl" ascii wide

      // Device name
      $device = "\\\\.\\BdApiUtil" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      $api and $device and
      2 of ($ioctl*)
}
```

### Hunting Rules

#### Kernel SSDT Bypass Pattern (Generic Rootkit Technique)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1014 (Rootkit)
**Confidence:** LOW
**Rationale:** This rule targets the SSDT (System Service Descriptor Table) resolution, hook-detection, and indirect-syscall lookup pattern documented in BdApiUtil64.sys's advanced termination path, but the underlying strings are not specific to this campaign's driver. `MmGetSystemRoutineAddress` and `RtlInitUnicodeString` are near-universal kernel-driver imports, and legitimate kernel-mode anti-cheat and security-research tooling performs its own SSDT hook detection for defensive purposes using the same API combination. The two byte patterns add a technique signal (a hook-check comparison against `0xb8`, and a shift-by-2 array-indexing sequence typical of SSDT lookups) but both are short, generic instruction shapes that also occur outside SSDT-specific code. Durable in the sense that no campaign-specific literal is required, but not precise enough for alerting.
**False Positives:** Expected against legitimate kernel-mode anti-cheat and security-research tooling that performs its own SSDT hook detection; `MmGetSystemRoutineAddress` and `RtlInitUnicodeString` are routine imports across a wide range of unrelated kernel drivers, and the byte patterns are generic instruction shapes rather than anything unique to malicious SSDT bypass.
**Deployment:** Broad kernel-driver scanning sweep, IR artifact triage; treat hits as triage candidates requiring analyst review of the driver's signer and provenance, not alerts.

```yara
rule SUSP_Kernel_SSDT_Bypass_Pattern {
   meta:
      description = "Detects kernel-mode code implementing SSDT (System Service Descriptor Table) resolution combined with hook-detection and indirect-syscall lookup patterns, the EDR-evasion mechanism documented in the BdApiUtil64.sys driver. Not specific to this campaign's driver -- MmGetSystemRoutineAddress and RtlInitUnicodeString are near-universal kernel APIs also used by legitimate anti-cheat and security-research kernel drivers performing their own hook detection, so this is a technique-class hunting lead, not an alert."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-BdApiUtil64-sys-detections/"
      date = "2026-01-26"
      family = "Kernel-SSDT-Bypass-Generic"
      malware_type = "Rootkit-Technique-Pattern"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "d1a83f5c-7e29-4b06-a3d5-9f6e2c8b1a47"
   strings:
      $ssdt_string = "KeServiceDescriptorTable" ascii wide
      $api1 = "MmGetSystemRoutineAddress" ascii wide
      $api2 = "RtlInitUnicodeString" ascii wide

      // Hook detection pattern (checking for 0xb8 opcode)
      $hook_check = { 80 3? B8 }    // cmp byte ptr [reg], 0xb8

      // SSDT lookup pattern
      $ssdt_lookup = { 8B ?? ?? C1 E? 02 }    // mov reg, [reg+offset]; shl reg, 2
   condition:
      uint16(0) == 0x5A4D and
      $ssdt_string and
      all of ($api*) and
      1 of ($hook_check, $ssdt_lookup)
}
```

#### Kernel-Mode Security-Process Termination (Generic Rootkit Technique)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1685 (Impair Defenses)
**Confidence:** LOW
**Rationale:** This rule targets the process-management API combination (`PsLookupProcessByProcessId`, `ZwTerminateProcess`, `ObOpenObjectByPointer`, `ObDereferenceObject`) BdApiUtil64.sys uses to terminate security products from kernel mode, paired with named AV/EDR process strings. It is not specific to this campaign's driver, and the same four APIs are routinely imported by legitimate AV/EDR kernel components themselves for their own process-monitoring and competitor-compatibility logic — an EDR driver enumerating and inspecting process objects, including competitor products by name, is standard behavior for that product category, not a malicious tell on its own.
**False Positives:** Expected against legitimate AV/EDR kernel components, which routinely import all four process-management APIs for their own process-monitoring logic and may reference competitor product names for compatibility or conflict-detection purposes.
**Deployment:** Broad kernel-driver scanning sweep, IR artifact triage; treat hits as triage candidates, not alerts.

```yara
rule SUSP_Kernel_Driver_Security_Process_Termination {
   meta:
      description = "Detects kernel-mode drivers combining process-management APIs (PsLookupProcessByProcessId, ZwTerminateProcess, ObOpenObjectByPointer, ObDereferenceObject) with references to named AV/EDR process names, the pattern BdApiUtil64.sys uses to terminate security products from kernel mode. Not specific to this campaign's driver, and the same API combination is used by legitimate AV/EDR kernel components for their own process-monitoring and competitor-compatibility logic, so this is a technique-class hunting lead."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-BdApiUtil64-sys-detections/"
      date = "2026-01-26"
      family = "Kernel-Security-Process-Termination-Generic"
      malware_type = "Rootkit-Technique-Pattern"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "e5b6c914-2f8a-4d37-b1e9-3a7c5d0f8b62"
   strings:
      // Kernel APIs for process termination
      $api1 = "PsLookupProcessByProcessId" ascii
      $api2 = "ZwTerminateProcess" ascii
      $api3 = "ObOpenObjectByPointer" ascii
      $api4 = "ObDereferenceObject" ascii

      // Target security products
      $target1 = "MsMpEng.exe" ascii wide nocase
      $target2 = "CSFalconService.exe" ascii wide nocase
      $target3 = "ekrn.exe" ascii wide nocase
      $target4 = "avp.exe" ascii wide nocase
   condition:
      uint16(0) == 0x5A4D and
      3 of ($api*) and
      2 of ($target*)
}
```

---

## Sigma Rules

### Detection Rules

#### BdApiUtil64.sys BYOVD Kill Pattern — Driver Load Followed by Security-Product Termination (Correlation)

**Tier:** Detection (correlation rule) — bundled below with its 2 required non-alerting base rules
**Robustness:** 2 (correlation) — 2 for the driver-load base rule (anchored on signature identity), 1 for the termination base rule individually (anchored on a renameable process-name list)
**ATT&CK Coverage:** T1068 (Exploitation for Privilege Escalation — BYOVD), T1685 (Impair Defenses)
**Confidence:** HIGH
**Rationale:** Neither base signal is reliable alone — a Baidu-signed driver load can, rarely, reflect a genuine Baidu Antivirus install, and named security-product terminations happen during routine updates and uninstalls. But this driver's documented capability neutralizes a full security suite within 60 seconds of load, so the two events occurring on the same host inside that window is a BYOVD kill-chain signal a coincidental unrelated pairing would not produce. This operationalizes a correlation the source draft's own equivalent rule explicitly could not express in a single Sigma condition and left as a manual-correlation instruction to the analyst ("must manually correlate against a preceding BdApiUtil/Baidu driver load... within a short window"). *Retiering fixes applied:* the source draft's driver-load selector included a bare hash-match OR-branch (three hashes, already present in the IOC feed) that would trigger the rule alone with no behavioral corroboration — removed, since it added nothing beyond the feed entry. The same selector also carried a `selection_expired` branch that, despite its name, never actually tested certificate expiration (it checked `SignatureStatus: Valid`, not a date) and was otherwise a strictly broader, weaker duplicate of the signature-identity branch (`ImageLoaded endswith '.sys'` is true of every driver-load event) — merged away. See Coverage Gaps for full detail.
**False Positives:** A coincidental Baidu Antivirus install combined with an unrelated security-product restart in the same 60-second window is possible but highly unlikely — review the specific driver file hash and signature timestamp before dismissing a hit.
**Blind Spots:** An operator who first strips the driver's identifying signature/name strings (defeating the driver-load base rule — see the corresponding YARA rule's Blind Spots) or who spaces the two events more than 60 seconds apart evades the correlation.
**Validation:** Replay both base selectors against the same `host.name` within the 60-second window — the correlation must fire; a host showing only one signal type, or the two signals more than 60 seconds apart, must NOT trigger the correlation.
**Deployment:** SIEM correlation engine with Sysmon driver-load (Event ID 6) and process-termination (Event ID 5) telemetry ingested (60-second temporal join on `host.name`).

```yaml
title: Baidu-Signed Driver Load Outside Legitimate Antivirus Installation (Base Rule)
id: f3d8a726-4c1e-4a95-8b3d-6e2f9c7a1d40
name: baidu_signed_driver_load
status: experimental
description: >-
  Base rule (not alerting on its own): loading of a driver image whose filename
  contains "BdApiUtil" and whose digital signature validates as issued to Baidu,
  matching the legitimately-signed-but-weaponized BdApiUtil64.sys BYOVD driver.
  Paired with the security-product-termination base rule below via the
  correlation rule, which flags the two events occurring close together in
  time -- the actual BYOVD kill-chain signal.
references:
    - https://the-hunters-ledger.com/hunting-detections/arsenal-237-BdApiUtil64-sys-detections/
author: The Hunters Ledger
date: '2026-01-26'
tags:
    - attack.privilege-escalation
    - attack.t1068
    - detection.emerging-threats
logsource:
    product: windows
    category: driver_load
detection:
    selection:
        ImageLoaded|contains: 'BdApiUtil'
        Signed: 'true'
        Signature|contains: 'Baidu'
    condition: selection
falsepositives:
    - >-
      Legitimate Baidu Antivirus installation (very rare in enterprise environments).
      Not alerting on its own; reviewed only in combination with the paired
      security-product-termination base rule.
level: informational
---
title: Security Product Process Termination (Base Rule)
id: a9c4e158-6b3f-4d72-9e1a-8c5d3f7b2e61
name: security_product_termination
status: experimental
description: >-
  Base rule (not alerting on its own): termination of a named security-product
  process. Paired with the Baidu-signed-driver-load base rule above via the
  correlation rule below, which flags co-occurrence of both events on the
  same host -- the BYOVD kill pattern this campaign's driver is built to enable.
references:
    - https://the-hunters-ledger.com/hunting-detections/arsenal-237-BdApiUtil64-sys-detections/
author: The Hunters Ledger
date: '2026-01-26'
tags:
    - attack.defense-impairment
    - attack.t1685
    - detection.emerging-threats
logsource:
    product: windows
    category: process_termination
detection:
    selection:
        Image|endswith:
            - 'MsMpEng.exe'
            - 'CSFalconService.exe'
            - 'ekrn.exe'
            - 'avp.exe'
            - 'SophosHealth.exe'
            - 'cb.exe'
            - 'MBAMService.exe'
    condition: selection
falsepositives:
    - >-
      Legitimate service restarts during updates. Not alerting on its own; reviewed
      only in combination with the paired driver-load base rule.
level: informational
---
title: BdApiUtil64.sys BYOVD Kill Pattern -- Driver Load Followed by Security-Product Termination on Same Host
id: b2e7f043-9a5c-4e18-b6d2-4f8a1c3e7d95
status: experimental
description: >-
  Fires when a Baidu-signed BdApiUtil-named driver load and a named
  security-product process termination are observed on the same host within
  60 seconds. Neither base signal is reliable alone, but this driver's
  documented capability neutralizes a full security suite within 60 seconds
  of load, so the close-in-time co-occurrence is the BYOVD kill-chain signal
  a coincidental unrelated pairing would not produce.
references:
    - https://the-hunters-ledger.com/hunting-detections/arsenal-237-BdApiUtil64-sys-detections/
author: The Hunters Ledger
date: '2026-01-26'
tags:
    - attack.privilege-escalation
    - attack.t1068
    - attack.defense-impairment
    - attack.t1685
    - detection.emerging-threats
correlation:
    type: temporal
    rules:
        - baidu_signed_driver_load
        - security_product_termination
    group-by:
        - host.name
    timespan: 60s
falsepositives:
    - >-
      A coincidental Baidu Antivirus install combined with an unrelated security
      product restart in the same 60-second window is highly unlikely but not
      impossible -- review the specific driver file hash and signature timestamp
      before dismissing.
level: critical
```

### Hunting Rules

#### Bprotect Service Creation (BdApiUtil64.sys Deployment Marker)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1547.006 (Kernel Modules and Extensions)
**Confidence:** LOW
**Rationale:** Requires a Windows service named exactly `Bprotect` whose `ImagePath` references `BdApiUtil` — a specific two-field combination, but both values are chosen at deployment time (the `sc create` service name and the on-disk driver path) rather than baked into unmodifiable driver code. An operator sophisticated enough to expect this rule can rename the driver file and choose a different service name in the same `sc create` command, evading both anchors. Per the project's BYOVD durability guidance, deployment-time literals rank below the driver's own embedded signer identity, which is why this stays Hunting despite the source draft's `critical` rating.
**False Positives:** Legitimate Baidu Antivirus installation using this exact service name — rare outside a genuine Baidu AV deployment.
**Deployment:** Windows service-creation monitoring (Event ID 7045), SIEM correlation, IR artifact triage.

```yaml
title: Suspicious Bprotect Service Creation (BdApiUtil64.sys)
id: 3057b63c-4d7a-463b-aa1e-3252c63b0e9d
status: experimental
description: >-
  Detects creation of a Windows service named Bprotect with an ImagePath
  referencing BdApiUtil, the deployment pattern documented for the
  BdApiUtil64.sys BYOVD driver. Both the service name and image path are
  deployment-time choices rather than anchors embedded in the driver's own
  code, so this is a hunting lead rather than a high-fidelity alert.
references:
    - https://the-hunters-ledger.com/hunting-detections/arsenal-237-BdApiUtil64-sys-detections/
author: The Hunters Ledger
date: '2026-01-26'
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1547.006
    - detection.emerging-threats
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName: 'Bprotect'
        ImagePath|contains: 'BdApiUtil'
    condition: selection
falsepositives:
    - Legitimate Baidu Antivirus installation using this exact service name (rare outside a genuine Baidu AV deployment).
level: medium
```

---

## Coverage Gaps

### Retiering Fixes Applied

- **Sigma driver-load selector's bare hash-match branch removed.** The source draft's driver-load rule OR'd three conditions together (`1 of selection_*`), one of which (`selection_hash`) matched purely on SHA256/MD5/SHA1 hash values with no behavioral corroboration — a textbook pure-IOC selector per the project's Sigma Cut checklist. All three hashes were already present in `arsenal-237-BdApiUtil64-sys.json`; the branch added no detection value beyond those feed entries and has been removed from the retiered rule.
- **Sigma driver-load selector's mislabeled `selection_expired` branch merged away.** Despite its name, this branch never tested certificate expiration — it checked `SignatureStatus: Valid`, not a date field — and its only other condition (`ImageLoaded endswith '.sys'`) is true of every driver-load event by definition, since the `driver_load` logsource only fires on `.sys` files. As written it was a strictly broader, weaker duplicate of the signature-identity branch (`ImageLoaded contains 'BdApiUtil'` + `Signed: true` + `Signature contains 'Baidu'`). The two branches have been merged into a single clean selector.
- **Driver-load and security-product-termination rules restructured into a temporal correlation.** The source draft's security-product-termination rule explicitly documented a gap it could not close: "a single-rule Sigma condition can no longer express the 'termination shortly after driver load' timing correlation... requires a Sigma correlation rule instead," leaving the timing check as a manual instruction to the analyst. Sigma's native correlation syntax closes this gap directly — see the Detection-tier correlation above, built from the two source rules as non-alerting base rules plus a 60-second temporal join, matching the 60-second full-suite-neutralization window this driver's own documented capability supports.
- **Sigma DeviceIoControl and KeServiceDescriptorTable rules cut.** Both source Sigma rules matched literal API/device-path strings (`DeviceIoControl`, `\.\BdApiUtil`, `MmGetSystemRoutineAddress`, `KeServiceDescriptorTable`) against a `CallTrace` field. `CallTrace` in Windows telemetry is a resolved call-stack listing of module+offset pairs, not a text log of API names or device paths — neither string would ever appear there as written, so neither selector could fire on the behavior it was built to detect. The second rule additionally used `category: kernel_api`, which is not a recognized Sigma logsource category — no standard Windows/Sysmon telemetry channel logs raw kernel API invocations by function name. No clean fix exists within Sigma's standard logsource taxonomy for either gap (kernel-level API-call and IOCTL-call tracing is not exposed as queryable event fields on any generic Windows telemetry source), and the static equivalent of each behavior is already covered by a YARA rule above (IOCTL Abuse for the DeviceIoControl rule; SSDT Bypass Pattern for the KeServiceDescriptorTable rule) — so no unique detection value is lost. See Cut Rules below.

### Cut Rules (genuine noise — not routed to the feed)

- **DeviceIoControl Calls to BdApiUtil Driver** (source Sigma Rule 4, id `9a61d638-005d-41d4-acd4-de01013ae3b2`) — cut. Matched `DeviceIoControl` and `\.\BdApiUtil` against `CallTrace`, a resolved-stack field that does not contain API-name or device-path text; the `process_access` logsource category (Sysmon Event ID 10, handle-open events between processes) also has no relationship to IOCTL dispatch. Fails durability of purpose entirely — it does not detect the behavior it claims to. The static equivalent (BdApiUtil64.sys IOCTL Abuse, YARA) already covers this behavior.
- **KeServiceDescriptorTable Resolution (SSDT Bypass Attempt)** (source Sigma Rule 5, id `0c757672-f00b-49d6-9406-cb6179ba3eac`) — cut. Same `CallTrace`-field misuse as above, compounded by a `category: kernel_api` logsource that does not exist in Sigma's standard taxonomy — no generic Windows telemetry source logs kernel API invocations as a queryable event. The static equivalent (Kernel SSDT Bypass Pattern, YARA) already covers this behavior.

### Atomics Routed to the IOC Feed

- **File hashes** (SHA256 `47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428`, MD5 `ced47b89212f3260ebeb41682a4b95ec`, SHA1 `148c0cde4f2ef807aea77d7368f00f4c519f47ef`) — already present in `arsenal-237-BdApiUtil64-sys.json` under `file_hashes`. For a known-vulnerable signed driver, the hash is a legitimate blocklist/feed entry rather than a rule: it identifies this one build precisely, which is exactly what a blocklist wants and exactly what a rule should not depend on alone. Previously carried as a bare OR-branch inside the source Sigma driver-load rule (removed — see Retiering Fixes).
- **Distribution IP** (`109.230.231.37`) — already present in `arsenal-237-BdApiUtil64-sys.json` under `network_indicators.distribution_infrastructure`. This IP was never referenced inside any YARA or Sigma rule in the source draft (it appeared only in the deleted EDR/SIEM query examples), so no rule content was retired to reach this disposition — it is pre-existing feed coverage, confirmed still present.

### Driver Identity vs. Filename: Why the BYOVD Note Changes the Durability Call

A rule built entirely from strings found in one specific driver build can look, on the surface, like a hash-equivalent — the kind of single-sample match the project's Cut checklist reserves for the IOC feed. The distinguishing test here is what the strings are properties *of*. BdApiUtil64.sys's PDB path, signer name, product name, and internal object names are baked into the driver's own compiled code and its digital-signature block; an operator deploying this driver cannot alter them without breaking the Baidu signature that makes the whole BYOVD technique work in the first place. That is a fundamentally different durability profile from a masquerade filename or an attacker-chosen service name, both of which cost the operator nothing to change. The same logic extends to the driver's IOCTL surface (BdApiUtil64.sys IOCTL Abuse, YARA): the specific IOCTL codes and device object name are fixed properties of the target driver's dispatch interface, not choices available to whatever tool calls into it. Both rules cleared Gate 1 at Robustness 2 on that basis. By contrast, the Bprotect service-creation rule (Sigma) uses a service name and an on-disk image path — both deployment-time choices with no such constraint — and stays at Hunting despite the source draft rating it `critical`.

### Generic Kernel-Technique Rules — Why SSDT Bypass and Kernel Termination Cap at Hunting

The two remaining YARA rules (SSDT Bypass Pattern, Kernel-Mode Security-Process Termination) are durable in the sense that neither depends on a renameable literal — `MmGetSystemRoutineAddress`, `RtlInitUnicodeString`, `PsLookupProcessByProcessId`, and the other kernel APIs they key on are OS-level primitives no rebuild of this driver could remove. What keeps both at Hunting instead of Detection is precision: these exact API combinations are also standard in legitimate kernel-mode security tooling. Anti-cheat drivers and defensive EDR/AV kernel components routinely resolve the SSDT and check for hooks — for their own integrity-verification purposes, not to bypass anyone — and legitimate EDR/AV kernel drivers routinely import the same four process-management APIs and reference competitor product names for their own monitoring and compatibility logic. Neither rule is specific to BdApiUtil64.sys or the Arsenal-237 toolkit (neither references any Baidu-, Bprotect-, or BdApiUtil-related string), so both are retained as broad, technique-class hunting leads rather than campaign-specific signatures.

### No Suricata Coverage — No Network Protocol Artifact

BdApiUtil64.sys is a host-resident kernel driver with no C2 or network protocol of its own; its role in the attack chain is purely local defense evasion. The only network artifact associated with this component is the Arsenal-237 distribution IP from which the driver was recovered, which carries no distinguishing protocol structure beyond a bare IP match and is already feed-only coverage (see Atomics above). No Suricata signature — Detection or Hunting — can be built from this component's own behavior.

### What Would Enable Stronger Coverage

- **A captured malware sample that calls BdApiUtil64.sys's IOCTLs** would let the IOCTL Abuse YARA rule be validated against a real caller rather than the driver's own documented interface, and could surface additional durable anchors (a distinctive loader string, a consistent calling convention) specific to whatever tooling in the Arsenal-237 toolkit invokes this driver.
- **Goodware corpus validation** — none of the four YARA rules have been run against a broad clean-software corpus; a documented zero-FP result against legitimate kernel drivers and anti-cheat/EDR products is the explicit precondition for reconsidering the two Hunting-tier rules.
- **EDR-vendor kernel telemetry** (rather than generic Sysmon) would enable real IOCTL-call and SSDT-resolution event-level detection, closing the gap the two cut Sigma rules attempted and could not reach with standard Windows telemetry.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
