---
title: "Detection Rules — killer.dll (BYOVD Defense Evasion)"
date: '2026-01-25'
layout: post
permalink: /hunting-detections/arsenal-237-killer-dll-detections/
hide: true
redirect_from: /hunting-detections/arsenal-237-killer-dll/
thumbnail: /assets/images/cards/arsenal-237-new-files.png
---

**Campaign:** Arsenal-237-109.230.231.37-Malware-Repository
**Date:** 2026-01-25
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**IOC Feed:** https://the-hunters-ledger.com/ioc-feeds/arsenal-237-killer-dll.json

---

## Detection Coverage Summary

killer.dll is a Rust-compiled, 64-bit BYOVD (Bring Your Own Vulnerable Driver) defense-evasion module recovered from the same open directory at `109.230.231.37` as the broader Arsenal-237 threat-actor toolkit repository. It runs as the second stage in a two-stage chain, following privilege escalation via `lpe.exe`, and disables endpoint security products by staging two distinct, legitimately-signed vulnerable drivers (Baidu Antivirus's `BdApiUtil64.sys` and Sysinternals Process Explorer's `ProcExpDriver.sys`) as a kernel-mode service, then issuing driver-specific IOCTL codes to terminate AV/EDR processes from ring 0.

Coverage below is retiered from the original draft: every rule was re-scored for durability (does it survive infrastructure rotation and renaming?), precision (documented false-positive profile), and level discipline, per the project's Detection/Hunting split. The campaign's atomic indicators (the sample hash set and the distribution/C2 IP) are carried in the IOC feed rather than as standalone signatures. The surviving rules split between the driver-embedding structural signal, which is strongest when both vulnerable drivers are present together, and the service-lifecycle/IOCTL-abuse behavioral signal.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 1 | 2 | T1027.009, T1068, T1685 | 0 |
| Sigma | 3 | 4 | T1068, T1543.003, T1685 | 0 |
| Suricata | 0 | 0 | — | 3 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Atomics routed to the IOC feed:** the sample hash set (SHA256/MD5/SHA1), the distribution IP (`109.230.231.37`), and the hardcoded C2 URL (`http://109.230.231.37:8888/lpe.exe`) were already present in [`arsenal-237-killer-dll.json`](/ioc-feeds/arsenal-237-killer-dll.json) before this retiering pass. The three IP/URL-anchored Suricata signatures, a non-functional hash-as-string YARA branch, and a YARA branch requiring the C2 literal as a mandatory condition added no detection value beyond those feed entries and have been retired — see Coverage Gaps for the full reasoning on every retired branch.

---

## YARA Rules

### Detection Rules

#### BYOVD Dual Vulnerable-Driver Embedding (Baidu + Sysinternals ProcExp Combination)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1027.009 (Obfuscated Files or Information: Embedded Payloads), T1068 (Exploitation for Privilege Escalation)
**Confidence:** HIGH
**Rationale:** Merges the strongest logic from the original file's two overlapping embedded-driver rules. Requires the metadata of *both* vulnerable drivers — Baidu's `BdApiUtil64.sys` and Sysinternals' `ProcExpDriver.sys` — to be present together, alongside their driver-specific IOCTL byte codes. Deliberately pairing two unrelated vendors' vulnerable drivers inside one PE is not a pattern expected in legitimate software; a legitimate installation of either product alone does not satisfy this rule. *Fix applied during retiering:* the original "comprehensive" rule's hash-as-ASCII-string branch (`$hash = "10eb1fbb...788d" nocase`) searched the file's own content for its own SHA256 hex digest as text — not how a Rust-compiled binary would ever embed its own hash, and functionally dead logic. That branch has been dropped entirely (the real hash is already in the IOC feed); this rule instead carries the file's genuine embedded-driver combination forward as its own clean Detection-tier signature.
**False Positives:** None known — no legitimate software has a reason to embed both an antivirus vendor's kernel driver and a process-utility vendor's kernel driver together inside the same PE.
**Blind Spots:** A rebuild substituting a different pair of vulnerable drivers (a different LOLDrivers entry) evades; targets the on-disk dropper, not a memory-only variant.
**Validation:** Scan `killer.dll` (hash below) — must match; a standalone legitimate Process Explorer executable or Baidu Antivirus installer, containing only one driver family, must NOT fire.
**Deployment:** Endpoint AV/EDR file scanning, email gateway attachment scanning, retroactive scan of file shares, IR artifact triage.

```yara
/*
   Yara Rule Set
   Identifier: Arsenal-237-109.230.231.37-Malware-Repository
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule MAL_Windows_KillerDLL_BYOVD_Dual_Driver_Embedding
{
   meta:
      description = "Detects the killer.dll BYOVD defense-evasion module via simultaneous embedding of two distinct legitimately-signed vulnerable drivers -- Baidu Antivirus's BdApiUtil64.sys and Sysinternals Process Explorer's ProcExpDriver.sys -- inside a single PE, alongside their kernel-mode IOCTL abuse codes. Pairing two unrelated vendors' vulnerable drivers together is not a pattern expected in legitimate software."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-killer-dll-detections/"
      date = "2026-01-25"
      family = "Arsenal-237-BYOVD-Killer-DLL"
      malware_type = "Defense-Evasion-Module"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "acc310db-6c58-4169-856d-629bab1adb6d"
      hash1 = "10eb1fbb2be3a09eefb3d97112e42bb06cf029e6cac2a9fb891b8b89a25c788d"
   strings:
      $baidu_path = "\\SystemRoot\\System32\\Drivers\\BdApiUtil64.sys" ascii wide nocase
      $baidu_desc = "Baidu Antivirus BdApi Driver" ascii wide
      $baidu_ver  = "5.0.3.84333" ascii wide
      $baidu_dev  = "\\\\.\\BdApiUtil" ascii wide

      $procexp_path = "\\SystemRoot\\System32\\Drivers\\PROCEXP152.SYS" ascii wide nocase
      $procexp_ver  = "17.0.7" ascii wide
      $procexp_dev  = "\\\\.\\PROCEXP152" ascii wide

      $ioctl_baidu   = { B4 24 00 80 }
      $ioctl_procexp = { 3C 00 35 83 }

      $mz = "MZ"
   condition:
      uint16(0) == 0x5A4D and
      #mz >= 2 and
      (2 of ($baidu_*)) and
      (2 of ($procexp_*)) and
      (1 of ($ioctl_*))
}
```

### Hunting Rules

#### Single Vulnerable-Driver Embedding (Baidu OR ProcExp Alone)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1027.009 (Obfuscated Files or Information: Embedded Payloads), T1068 (Exploitation for Privilege Escalation)
**Confidence:** LOW
**Rationale:** *Retiering note:* the source file's `Embedded_Vulnerable_Driver_BdApi_ProcExp` rule OR'd "either driver family alone" branches together with the dual-family case, dragging the whole rule's precision down to its weakest path. Split out here as its own explicitly-labeled Hunting rule. Sysinternals Process Explorer legitimately bundles its own signed `PROCEXP152` driver as an embedded PE resource, so a genuine, unmodified Process Explorer executable independently satisfies `#mz >= 2` and `2 of ($procexp_*)` — this branch fires on one of the most widely deployed IT/security utilities in existence. The Baidu-alone branch is narrower (Baidu Antivirus has a smaller install base) but is not FP-free either, since a legitimate Baidu Antivirus deployment embeds the same path/description/version strings.
**False Positives:** Expected against legitimate, unmodified Sysinternals Process Explorer installations (any version bundling the PROCEXP152 driver, including 17.0.7). Lower but non-zero risk against legitimate Baidu Antivirus deployments.
**Deployment:** Broad endpoint/EDR scanning sweep, retroactive hunt across file shares; treat hits as triage candidates requiring host-context review (is Process Explorer or Baidu AV a known, sanctioned install on this host?), not alerts.

```yara
rule SUSP_Windows_KillerDLL_Single_Vulnerable_Driver_Embedded
{
   meta:
      description = "Detects a single embedded Baidu BdApiUtil64.sys OR Sysinternals ProcExpDriver.sys vulnerable-driver reference alone, without requiring both families together. Broader and noisier than the dual-driver combination rule -- fires on legitimate, unmodified installations of either product, most notably Sysinternals Process Explorer, which bundles its own signed driver as an embedded PE resource. Hunting lead, not an alert."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-killer-dll-detections/"
      date = "2026-01-25"
      family = "Arsenal-237-BYOVD-Killer-DLL"
      malware_type = "Defense-Evasion-Module"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "23a3919b-51cc-45db-9f67-4d2e725da63c"
   strings:
      $baidu_path    = "\\SystemRoot\\System32\\Drivers\\BdApiUtil64.sys" ascii wide nocase
      $baidu_company = "Baidu, Inc." ascii wide
      $baidu_desc    = "Baidu Antivirus BdApi Driver" ascii wide
      $baidu_ver     = "5.0.3.84333" ascii wide

      $procexp_path    = "\\SystemRoot\\System32\\Drivers\\PROCEXP152.SYS" ascii wide nocase
      $procexp_desc    = "Process Explorer" ascii wide
      $procexp_company = "Sysinternals - www.sysinternals.com" ascii wide
      $procexp_ver     = "17.0.7" ascii wide

      $mz = "MZ"
   condition:
      uint16(0) == 0x5A4D and
      #mz >= 2 and
      (
         (2 of ($baidu_*)) or
         (2 of ($procexp_*))
      )
}
```

#### Security-Product Termination + IOCTL Behavioral Combination

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1685 (Impair Defenses), T1068 (Exploitation for Privilege Escalation)
**Confidence:** LOW
**Rationale:** Carried forward from the source file's "behavioral pattern" branch of `Killer_DLL_BYOVD_Comprehensive`. Requires 3 of 5 targeted security-product filenames, 2 of 4 service-manipulation API strings, one driver-specific IOCTL byte code, and one driver-family reference. The IOCTL requirement gives this real discriminating power beyond generic AV-compatibility tooling, but the driver-family requirement can be satisfied by the bare "Baidu, Inc." or "Sysinternals - www.sysinternals.com" company-name strings alone, which a multi-vendor AV-management or compatibility utility could plausibly contain alongside common service-management API imports. That combination of generic elements keeps this at Hunting rather than Detection.
**False Positives:** Plausible against IT/security-compatibility tooling that legitimately enumerates multiple AV vendor process names and uses standard service-management APIs (uninstaller utilities, endpoint migration tools, asset-management scripts).
**Deployment:** Endpoint/EDR scanning sweep, memory scanning, IR artifact triage; corroborate with the dual-driver Detection rule or an actual mass-termination event before treating a hit as malicious.

```yara
rule SUSP_Windows_KillerDLL_SecurityProduct_Termination_IOCTL_Combo
{
   meta:
      description = "Detects a combination of targeted security-product process names, service-manipulation API imports, a killer.dll-class IOCTL byte code, and a Baidu/ProcExp driver-family reference. Broader than the dual-driver embedding rule -- the driver-family requirement can be satisfied by a generic vendor-name string alone. Hunting lead, not an alert."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-killer-dll-detections/"
      date = "2026-01-25"
      family = "Arsenal-237-BYOVD-Killer-DLL"
      malware_type = "Defense-Evasion-Module"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "c1b9b7e5-6058-4ee7-ae8f-c78d68db999c"
   strings:
      $target1 = "MsMpEng.exe" ascii wide nocase
      $target2 = "ekrn.exe" ascii wide nocase
      $target3 = "avp.exe" ascii wide nocase
      $target4 = "MBAMService.exe" ascii wide nocase
      $target5 = "bdservicehost.exe" ascii wide nocase

      $svc1 = "CreateServiceW" ascii wide
      $svc2 = "StartServiceW" ascii wide
      $svc3 = "DeleteService" ascii wide
      $svc4 = "NtUnloadDriver" ascii wide

      $ioctl_baidu   = { B4 24 00 80 }
      $ioctl_procexp = { 3C 00 35 83 }

      $baidu_ref   = "Baidu, Inc." ascii wide
      $procexp_ref = "Sysinternals - www.sysinternals.com" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      (3 of ($target*)) and
      (2 of ($svc*)) and
      (1 of ($ioctl_baidu, $ioctl_procexp)) and
      (1 of ($baidu_ref, $procexp_ref))
}
```

---

## Sigma Rules

### Detection Rules

#### Kernel Driver Service Creation by Rundll32 (Registry)

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1685 (Impair Defenses), T1068 (Exploitation for Privilege Escalation)
**Confidence:** HIGH
**Rationale:** `rundll32.exe` registering a `SERVICE_KERNEL_DRIVER`-type service is a rare, technique-level chokepoint for the BYOVD install step — legitimate driver installation goes through Plug-and-Play/INF-based setup or a dedicated installer executable, essentially never through `rundll32.exe`. Durable: keys on the parent-process/service-type pairing, not on killer.dll's name or hash. *Retiering note:* demoted from the source's `level: critical` to `high` — the rule's own documented false positives ("administrative scripts using rundll32 for driver deployment") mean this isn't strictly never-FP, and the project convention caps most Detection-tier rules at `high`.
**False Positives:** Legitimate software installation via rundll32 (extremely rare for kernel drivers); administrative scripts using rundll32 for driver deployment (should be reviewed).
**Blind Spots:** An installer that stages the driver directly under `System32\Drivers` is excluded by the legitimate-path filter by design; a rebuild avoiding `rundll32.exe` as the registering process evades. The `Details|contains: 'SERVICE_KERNEL_DRIVER'` selector assumes the registry-value telemetry renders the service Type as this symbolic string rather than a raw DWORD — confirm this against your specific registry-event data source before relying on this rule for alerting (see Coverage Gaps).
**Validation:** Trigger the killer.dll service-creation step (or a synthetic equivalent — rundll32.exe registering a kernel-driver-type service outside System32\Drivers) — must match; a signed installer registering a driver from its own Program Files path must NOT fire.
**Deployment:** Sysmon/EDR registry-event monitoring (Sysmon Event ID 13), Windows Event Log auditing on the Services registry hive.

```yaml
title: Kernel Driver Service Creation by Rundll32 (Registry)
id: 10eb1fbb-2be3-a09e-efb3-d97112e42bb0
status: experimental
description: >-
  Detects kernel driver service creation by rundll32.exe, the BYOVD install-step
  pattern used by the killer.dll defense-evasion module. rundll32.exe registering
  a SERVICE_KERNEL_DRIVER-type service is a rare event outside this specific
  technique -- legitimate driver installation goes through Plug-and-Play/INF setup
  or a dedicated installer, not rundll32.exe.
references:
  - https://the-hunters-ledger.com/hunting-detections/arsenal-237-killer-dll-detections/
author: The Hunters Ledger
date: '2026-01-25'
tags:
  - attack.defense-impairment
  - attack.t1685
  - attack.privilege-escalation
  - attack.t1068
logsource:
  product: windows
  category: registry_set
detection:
  selection_service_create:
    TargetObject|contains: '\System\CurrentControlSet\Services\'
    Details|contains: 'SERVICE_KERNEL_DRIVER'
  selection_parent:
    Image|endswith: '\rundll32.exe'
  filter_legitimate:
    TargetObject|contains: '\System32\Drivers\'
  condition: selection_service_create and selection_parent and not filter_legitimate
falsepositives:
  - Legitimate software installation via rundll32 (extremely rare for kernel drivers)
  - Administrative scripts using rundll32 for driver deployment (should be reviewed)
level: high
```

#### Mass Security-Product Termination — 3+ Distinct Products Within 60 Seconds (Correlation)

**Tier:** Detection (correlation rule) — bundled below with its 1 required Hunting-grade base rule, which does not alert on its own
**Robustness:** 3 (correlation) / 1 (base rule individually)
**ATT&CK Coverage:** T1685 (Impair Defenses)
**Confidence:** HIGH (correlation) / LOW (base rule alone)
**Rationale:** *Retiering note:* the source rule's own description explains that its intended volumetric threshold — 3 or more distinct security processes terminating within 60 seconds — could not be expressed as a single-event Sigma rule and was dropped, leaving a single-event selector that "should be correlated... at review time." Sigma's `value_count` correlation type expresses exactly this threshold natively: this rule counts distinct `Image` values matching the base selector, grouped by host, within a 60-second window, and fires only at 3 or more. This operationalizes the malware-analyst's own documented detection strategy ("Alert on simultaneous termination of 3+ security products within 60-second window") as a real correlation instead of a single-event selector with a manual-review caveat. A lone security-product termination (the base rule) is common and unremarkable; 3+ distinct vendors dying together in 60 seconds is not.
**False Positives:** A coordinated, scripted replacement or migration of multiple third-party security products within one maintenance window — uncommon outside a planned AV/EDR migration.
**Blind Spots:** An attacker who staggers terminations beyond 60 seconds, or who targets fewer than 3 distinct products from this specific 8-item list, evades the correlation.
**Validation:** Replay 3 or more distinct termination events from the target list against the same `host.name` within 60 seconds — the correlation must fire; 1–2 distinct terminations in the same window must NOT trigger the correlation.
**Deployment:** SIEM correlation engine with process-termination telemetry ingested (Sysmon Event ID 5 or EDR equivalent).

```yaml
title: Security Product Process Termination (Base Rule)
id: 1766d04f-4a4a-4e83-8052-de31857dd69c
name: security_product_process_termination
status: experimental
description: >-
  Base rule (not alerting on its own): termination of a single known
  security-product process. Paired with the correlation rule below, which
  flags 3 or more DISTINCT security-product terminations on the same host
  within 60 seconds -- the killer.dll behavior of shutting down AV/EDR ahead
  of payload deployment.
references:
  - https://the-hunters-ledger.com/hunting-detections/arsenal-237-killer-dll-detections/
author: The Hunters Ledger
date: '2026-01-25'
tags:
  - attack.defense-impairment
  - attack.t1685
logsource:
  product: windows
  category: process_termination
detection:
  selection:
    Image|endswith:
      - '\MsMpEng.exe'
      - '\ekrn.exe'
      - '\avp.exe'
      - '\MBAMService.exe'
      - '\bdservicehost.exe'
      - '\avguard.exe'
      - '\NisSrv.exe'
      - '\vsserv.exe'
  condition: selection
falsepositives:
  - >-
    Administrator manually stopping a single security service, or a legitimate
    software update/uninstall. Not alerting on its own; reviewed only in
    combination with 2 or more other distinct terminations via the correlation
    rule.
level: informational
---
title: Mass Security-Product Termination -- 3+ Distinct Products Within 60 Seconds
id: a4d50dbc-8a4c-4c6a-9dd5-93f567651a29
status: experimental
description: >-
  Fires when 3 or more DISTINCT security-product processes terminate on the
  same host within 60 seconds. A single termination event cannot distinguish
  an administrator stopping one product from a defense-evasion module shutting
  down endpoint protection ahead of payload deployment; killer.dll terminates
  its full target list in 2-8 seconds once active, so 3+ distinct vendors dying
  together in a 60-second window is the discriminating signal.
references:
  - https://the-hunters-ledger.com/hunting-detections/arsenal-237-killer-dll-detections/
author: The Hunters Ledger
date: '2026-01-25'
tags:
  - attack.defense-impairment
  - attack.t1685
correlation:
  type: value_count
  rules:
    - security_product_process_termination
  group-by:
    - host.name
  timespan: 60s
  condition:
    field: Image
    gte: 3
falsepositives:
  - >-
    A coordinated, scripted replacement or migration of multiple third-party
    security products in a single maintenance window -- uncommon outside a
    planned AV/EDR migration.
level: high
```

#### Baidu BdApiUtil Vulnerable Driver Load

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1068 (Exploitation for Privilege Escalation)
**Confidence:** HIGH
**Rationale:** *Retiering note:* the source rule ("DeviceIoControl Abuse with BYOVD IOCTL Codes") titled itself around raw IOCTL/DeviceIoControl telemetry, but its own description already explains that data requires kernel-callback/ETW-TI visibility with no standard Sigma logsource, and the actual `driver_load` selector logic detects the vulnerable driver load instead — the reliably observable precondition for the IOCTL abuse. That selector bundled both driver families (Baidu and ProcExp) into one rule at a single `level: high`, which mismatched their very different false-positive profiles. Split here: the Baidu half, where the underlying product has a materially smaller legitimate install base, retains Detection tier; the ProcExp half (below, Hunting) does not.
**False Positives:** Legitimate, currently-installed Baidu Antivirus software — baseline as expected in environments where this specific product is deployed; otherwise rare.
**Blind Spots:** Only covers this specific vulnerable driver; a rebuild substituting a different LOLDrivers entry evades.
**Validation:** Trigger a load of the BdApiUtil64.sys driver — must match; loads of unrelated drivers must NOT fire.
**Deployment:** Sysmon Event ID 6 (driver load) or EDR-equivalent driver-load telemetry.

```yaml
title: Baidu BdApiUtil Vulnerable Driver Load
id: 3567b2e8-eec0-497d-910a-905cee6c0c03
status: experimental
description: >-
  Detects loading of the Baidu Antivirus BdApiUtil64.sys kernel driver, a
  legitimately-signed but vulnerable driver abused by the killer.dll BYOVD
  module to issue kernel-mode process-termination IOCTLs against security
  products.
references:
  - https://the-hunters-ledger.com/hunting-detections/arsenal-237-killer-dll-detections/
author: The Hunters Ledger
date: '2026-01-25'
tags:
  - attack.privilege-escalation
  - attack.t1068
logsource:
  product: windows
  category: driver_load
detection:
  selection:
    ImageLoaded|contains: 'BdApiUtil'
  condition: selection
falsepositives:
  - >-
    Legitimate, currently-installed Baidu Antivirus software -- baseline as
    expected in environments where this product is deployed; otherwise rare.
level: high
```

### Hunting Rules

#### Sysinternals ProcExp152 Vulnerable Driver Load

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1068 (Exploitation for Privilege Escalation)
**Confidence:** LOW
**Rationale:** Split from the source "DeviceIoControl Abuse with BYOVD IOCTL Codes" rule (see the Baidu Detection rule above for the split rationale). Sysinternals Process Explorer is an extremely widely deployed IT/security utility that legitimately loads this exact driver during ordinary use — the source rule's own false-positives list already flagged this ("Legitimate use of Sysinternals Process Explorer (if version 17.0.7 - review required)"). *Retiering note:* demoted from the source's `level: high` to `medium` to reflect that this is a non-rare legitimate event, not an edge case.
**False Positives:** Legitimate, common use of Sysinternals Process Explorer (any version shipping the PROCEXP152 driver, including 17.0.7).
**Deployment:** Sysmon Event ID 6 (driver load) or EDR-equivalent driver-load telemetry; correlate with an actual IOCTL-abuse or mass-termination signal before treating a hit as malicious.

```yaml
title: Sysinternals ProcExp152 Vulnerable Driver Load
id: 48de755d-dd78-4f51-a9b7-864aa0763161
status: experimental
description: >-
  Detects loading of the Sysinternals Process Explorer PROCEXP152 kernel
  driver, a legitimately Microsoft-signed but vulnerable driver abused by the
  killer.dll BYOVD module. Process Explorer is an extremely widely deployed
  IT/security utility, so this driver load also occurs during entirely
  legitimate use -- treat as a hunting lead requiring host-context review, not
  an alert.
references:
  - https://the-hunters-ledger.com/hunting-detections/arsenal-237-killer-dll-detections/
author: The Hunters Ledger
date: '2026-01-25'
tags:
  - attack.privilege-escalation
  - attack.t1068
logsource:
  product: windows
  category: driver_load
detection:
  selection:
    ImageLoaded|contains: 'PROCEXP152'
  condition: selection
falsepositives:
  - >-
    Legitimate, common use of Sysinternals Process Explorer (any version that
    ships the PROCEXP152 driver, including version 17.0.7) -- correlate with
    an actual IOCTL-abuse or mass-termination signal before treating a hit as
    malicious.
level: medium
```

#### Kernel-Mode Driver Service Installed (Event 7045)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1068 (Exploitation for Privilege Escalation), T1543.003 (Windows Service)
**Confidence:** LOW
**Rationale:** Installation of a new kernel-mode driver service is a comparatively rare event on most endpoints and is the setup step of killer.dll's install-abuse-remove cleanup pattern, but the event alone does not distinguish a legitimate hardware or security-software driver install from this specific technique. *Retiering note:* the source rule's own description explains its intended correlation — pairing this with a matching service-deletion event within 30 seconds — was dropped because single-event Sigma rules cannot express cross-event timing. Unlike the mass-termination rule above, no concrete deletion-side selector existed anywhere in the source material to correlate against (Windows has no direct System-log analog to 7045 for service deletion), so fabricating one was avoided rather than guessed at; see Coverage Gaps. Demoted from the source's `level: high` to `medium` given the genuine, non-rare legitimate driver-install population.
**False Positives:** Driver installation testing by IT staff (should be reviewed); legitimate hardware or security-software driver installation.
**Deployment:** Windows Event Log 7045 (System log), Sysmon-augmented service monitoring.

```yaml
title: Kernel-Mode Driver Service Installed (Event 7045)
id: 10eb1fbb-2be3-a09e-efb3-d97112e42bb3
status: experimental
description: >-
  Detects installation of a new kernel-mode driver service via the Service
  Control Manager -- a comparatively rare event on most endpoints, and the
  setup step of the killer.dll BYOVD module's install-abuse-remove cleanup
  pattern. This event alone does not distinguish a legitimate hardware or
  security-software driver install from the BYOVD setup step; killer.dll's
  documented lifecycle removes the service within roughly 20 seconds, but no
  concrete Sigma-expressible deletion-side telemetry was available to
  correlate against (see Coverage Gaps), so this remains a single-event
  hunting lead.
references:
  - https://the-hunters-ledger.com/hunting-detections/arsenal-237-killer-dll-detections/
author: The Hunters Ledger
date: '2026-01-25'
tags:
  - attack.privilege-escalation
  - attack.t1068
  - attack.persistence
  - attack.t1543.003
logsource:
  product: windows
  service: system
detection:
  selection:
    Provider_Name: 'Service Control Manager'
    EventID: 7045
    ServiceType: 'kernel mode driver'
  condition: selection
falsepositives:
  - Driver installation testing by IT staff (should be reviewed)
  - Legitimate hardware or security-software driver installation
level: medium
```

#### Driver File (.sys) Created in Temp Directory

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1027 (Obfuscated Files or Information), T1068 (Exploitation for Privilege Escalation)
**Confidence:** LOW
**Rationale:** Detects `.sys` files created in temp directories, killer.dll's staging location for its randomized-filename embedded drivers before service installation. Durable in that it does not depend on any specific filename (the malware itself uses a randomized lowercase charset), but legitimate driver installers — particularly third-party hardware vendors and some VPN/virtualization tooling — commonly stage `.sys` files in temp directories before proper installation, a pattern the source rule's own false-positives list already documents. *Retiering note:* demoted from the source's `level: high` to `medium` given this acknowledged, non-rare legitimate population.
**False Positives:** Legitimate driver installers using temp staging (should extract to System32\Drivers); hardware vendor driver installers (review publisher signatures); a manually-run, downloaded driver installer executed directly from Downloads/Temp/AppData is not excluded by the parent-image filter.
**Deployment:** Sysmon Event ID 11 (file creation) or EDR-equivalent file-event telemetry, filtered to temp-path `.sys` creation.

```yaml
title: Driver File (.sys) Created in Temp Directory
id: 10eb1fbb-2be3-a09e-efb3-d97112e42bb4
status: experimental
description: >-
  Detects .sys driver files created in temp directories, the killer.dll BYOVD
  module's staging location for its randomized-filename embedded drivers
  before installation as a kernel service.
references:
  - https://the-hunters-ledger.com/hunting-detections/arsenal-237-killer-dll-detections/
author: The Hunters Ledger
date: '2026-01-25'
tags:
  - attack.stealth
  - attack.t1027
  - attack.privilege-escalation
  - attack.t1068
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|contains:
      - '\AppData\Local\Temp\'
      - '\Windows\Temp\'
      - '\Temp\'
    TargetFilename|endswith: '.sys'
  filter_legitimate:
    Image|contains:
      - '\Windows\System32\'
      - '\Program Files\'
  condition: selection and not filter_legitimate
falsepositives:
  - Legitimate driver installers using temp staging (should extract to System32\Drivers)
  - Hardware vendor driver installers (review publisher signatures)
  - >-
    A manually-run, downloaded driver installer executed directly from
    Downloads/Temp/AppData is not excluded by the parent-image filter.
level: medium
```

---

## Coverage Gaps

### Retiering Fixes Applied

- **YARA non-functional hash-as-string branch removed.** The source "comprehensive" rule's `$hash = "10eb1fbb...788d" nocase` string searched the sample's own content for its SHA256 hex digest as ASCII text — not a pattern a compiled Rust binary would produce (a file does not ordinarily embed its own hash as text), so this branch was dead logic that would essentially never contribute a match. Dropped; the real hash is already in the IOC feed.
- **YARA mandatory-C2-literal branch removed.** The same source rule's "configuration and infrastructure" branch required `($c2_url or $c2_ip)` as a *mandatory* AND term alongside `$export_func`, a Rust-compiler marker, and 2 target-process strings. Because the C2 literal was mandatory rather than an optional extra signal, this branch could never fire on a rebuild using different infrastructure — it added no detection value beyond an IP/URL match already covered by the IOC feed. Dropped rather than carried forward as a disguised atomic.
- **YARA embedded-driver logic consolidated and split by precision, not merged wholesale.** The source file had two overlapping embedded-driver rules: one branch of `Killer_DLL_BYOVD_Comprehensive` requiring both driver families together, and a standalone `Embedded_Vulnerable_Driver_BdApi_ProcExp` rule that OR'd "either family alone" branches into the same rule as the dual-family case. The OR-decomposition meant a single, entirely legitimate Process Explorer installation (which bundles its own signed PROCEXP152 driver as a PE resource) could satisfy the rule alone. Restructured into two rules: a Detection-tier rule requiring both driver families together (no legitimate reason to co-occur), and a separately labeled Hunting-tier rule for either family alone, with the Process Explorer false-positive risk documented explicitly rather than buried inside a nominally "comprehensive" rule.
- **YARA `BYOVD_Service_Creation_Memory` cut** — see Cut Rules below.
- **Sigma rule retitled to match its actual logic, not its title.** The source rule "DeviceIoControl Abuse with BYOVD IOCTL Codes" is titled around raw IOCTL/DeviceIoControl telemetry, but its own description already explains that data requires kernel-callback/ETW-TI visibility with no standard Sigma logsource, and the actual `driver_load` selector logic detects the vulnerable driver load instead. Retitled to "Baidu BdApiUtil Vulnerable Driver Load" / "Sysinternals ProcExp152 Vulnerable Driver Load" to describe what the rule logic actually checks, and split by precision — see next point.
- **Sigma driver-load rule split by false-positive profile.** The source rule bundled the Baidu and ProcExp driver-load selectors into one rule at a single `level: high`. Sysinternals Process Explorer's driver load is common and legitimate; Baidu Antivirus's is comparatively rare outside environments that run that specific product. Splitting let the Baidu half retain Detection tier while the ProcExp half was honestly demoted to Hunting at `level: medium`, rather than either inflating the noisy half or dragging the cleaner half down.
- **Sigma mass-termination rule rebuilt as a real correlation.** The source rule's own description states its intended 3-or-more-distinct-products-in-60-seconds threshold could not be expressed in single-event Sigma and was dropped, leaving a single-event selector annotated "should be correlated with other security-product terminations... at review time." This is exactly what Sigma's `value_count` correlation type expresses natively — this file replaces the informal review-time note with a base rule (informational, not alerting alone) plus a `value_count` correlation (`gte: 3` distinct `Image` values per host per 60s), operationalizing the malware-analyst's own documented detection strategy from the IOC feed's `mass_process_termination.detection` field.
- **Sigma level demotions.** Rule 1 (rundll32 kernel-driver service creation) demoted `critical` → `high`: its own false-positives list is non-empty, and the project convention reserves `critical` for near-certain, no-legitimate-path scenarios. The kernel-driver-service-install rule and the temp-directory driver-file rule were both demoted `high` → `medium`: both have acknowledged, non-rare legitimate populations (routine hardware/security-software driver installation; installer staging patterns) that place them at Hunting rather than Detection precision.
- **Suricata rules cut** — see Cut Rules below.

### Cut Rules (genuine noise or pure atomics — not carried forward as rules)

- **YARA `BYOVD_Service_Creation_Memory`** — cut. Every string in this rule (5 common service-management API names, the generic `SERVICE_KERNEL_DRIVER` constant name, the near-universal `.sys` substring, and 3 common temp-path substrings) is individually common in legitimate software, and the combination describes the mundane, entirely legitimate pattern used by countless hardware/VPN/virtualization driver installers: stage a `.sys` file in Temp, then call `CreateServiceW`/`StartServiceW` to install it. No goodware-differentiating anchor (no IOCTL code, no driver-specific string) is present. The genuine behavioral signal this rule was reaching for — the service create-then-rapid-delete lifecycle — is already covered more precisely at the event level by this file's Sigma rules, which have process-ancestry and timing context a static string rule cannot express. Not routed to the feed; there is no atomic value to route (it was a pure combination-of-commons rule, not a disguised IOC).
- **Suricata "Connection to Arsenal-237 C2 Infrastructure"** (source sids `2000001` and `2000002`, outbound/inbound pair) — pure IP-match rules (`alert tcp $HOME_NET any -> 109.230.231.37 any`, no content/protocol anchor). Textbook Suricata Cut per the project checklist. The IP is already present in `arsenal-237-killer-dll.json` under `network_indicators.distribution_infrastructure` and `network_indicators.c2_infrastructure`.
- **Suricata "lpe.exe Download Pattern"** (source sid `2000003`) — cut. Anchored on `http.uri contains "/lpe.exe"` AND `http.host contains "109.230.231.37"`, both mandatory. Removing either literal leaves nothing behavioral: there is no distinctive header, User-Agent, or protocol structure beyond "this exact path from this exact host." Both discriminating values are already captured together in the IOC feed's `c2_infrastructure.c2_url` (`http://109.230.231.37:8888/lpe.exe`), so the rule added no detection value beyond the feed entry. The source rule also contained a broken placeholder reference URL (`reference:url,https://github.com/[your-repo]/reports/killer-dll/`) that was never filled in — flagged separately below as a source defect.

### Atomics Routed to the IOC Feed

All atomics referenced by the retired branches and rules above — the SHA256/MD5/SHA1 hash set, the distribution IP `109.230.231.37`, and the C2 URL `http://109.230.231.37:8888/lpe.exe` — were already present in `arsenal-237-killer-dll.json` (under `file_hashes`, `network_indicators.distribution_infrastructure`, and `network_indicators.c2_infrastructure` respectively) prior to this retiering pass. No IOC feed edits were required.

### A Genuinely Close Call: The Dual-Purpose Nature of the ProcExp Driver

Sysinternals Process Explorer occupies an unusual position in this file's tiering: it is simultaneously a widely-deployed, entirely legitimate IT/security tool and a LOLDrivers-cataloged vulnerable driver actively abused for BYOVD attacks. That duality is why every rule anchored on the ProcExp driver *alone* caps at Hunting regardless of how it is packaged (embedded-PE string match or driver-load event), while the Baidu driver anchor — a real but far less universally deployed product — clears the Detection bar on the same logic. The distinguishing test is deployment base, not durability: both drivers are equally durable technique-level artifacts (an attacker cannot cheaply swap either without changing to a different known-vulnerable driver entirely), but ProcExp's enormous legitimate install base is what a goodware-validation pass would be expected to catch. The one context where the ProcExp signal reaches Detection tier is in combination with the Baidu driver together — no legitimate reason exists to embed both a Chinese antivirus vendor's driver and a Sysinternals utility driver in the same file, which is why the dual-driver combination rule, not either driver alone, carries this file's strongest YARA signature.

### What Would Enable Stronger Coverage

- **Confirmed registry telemetry format for the SERVICE_KERNEL_DRIVER value.** The rundll32 kernel-driver-service-creation Sigma rule assumes registry-event telemetry renders the service `Type` value as the symbolic string `SERVICE_KERNEL_DRIVER` rather than a raw DWORD. This should be validated against the specific registry-event data source before relying on it for alerting; see the rule's own Rationale.
- **A concrete, validated service/driver-deletion telemetry selector.** The source file's intended correlation for the short-lived kernel-driver-service pattern (install, then delete within ~20-30 seconds) could not be rebuilt here because no concrete deletion-side Sigma selector existed in the source material to correlate against, and Windows has no direct System-log analog to Event 7045 for service deletion. A validated selector (for example, Sysmon Event ID 12/14 registry-key-deletion under the service's own Services key) would enable a genuine temporal correlation mirroring the mass-termination rule's structure, promoting this signal toward Detection tier.
- **Goodware corpus validation.** None of this file's YARA rules have been run against a broad clean-software corpus; a documented zero-FP result — particularly confirming whether a stock Sysinternals Process Explorer download trips the dual-driver Detection rule — is the explicit precondition the project's YARA checklist requires before any further tier changes.
- **Anti-analysis and export-masquerade behavior remain undocumented at the rule level.** The IOC feed's `behavioral_indicators` documents TLS-based anti-debugging (crash-on-debugger-detection via `TlsAlloc`/`TlsGetValue`/SEH) and the `get_hostfxr_path` export-name masquerade used to launch the DLL via `rundll32.exe`. Neither has dedicated coverage in this file: the anti-debug behavior has no static string anchor distinctive enough to survive goodware validation, and `get_hostfxr_path` is itself a genuine Microsoft nethost API symbol name with its own false-positive exposure in legitimate .NET tooling, so neither was carried forward as a standalone rule.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
