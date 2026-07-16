---
title: "Detection Rules — killer_crowdstrike.dll (CrowdStrike Variant)"
date: '2026-01-25'
layout: post
permalink: /hunting-detections/arsenal-237-killer-crowdstrike-dll-detections/
hide: true
redirect_from: /hunting-detections/arsenal-237-killer-crowdstrike-dll/
thumbnail: /assets/images/cards/arsenal-237-new-files.png
---

**Campaign:** Arsenal-237-109.230.231.37-Malware-Repository
**Date:** 2026-01-25
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**IOC Feed:** https://the-hunters-ledger.com/ioc-feeds/arsenal-237-killer-crowdstrike-dll.json

---

## Detection Coverage Summary

killer_crowdstrike.dll is a CrowdStrike Falcon-specific variant of the Arsenal-237 toolkit's killer.dll BYOVD (Bring Your Own Vulnerable Driver) defense-evasion module, recovered from the same open directory at 109.230.231.37 as the rest of the toolkit. It reuses killer.dll's BYOVD engine unchanged (identical IOCTLs, identical embedded vulnerable drivers, identical C2 infrastructure) with its kill list reconfigured to add CrowdStrike Falcon's three core processes (CSFalconService.exe, csagent.exe, CSFalconContainer.exe) alongside the toolkit's existing Defender and third-party AV/EDR targets. Coverage in this file is scoped to that CrowdStrike-specific behavior; the toolkit's generic kill-list targeting and shared C2 infrastructure are out of scope here.

Coverage below is retiered from the original draft: every rule was re-scored for durability (does it survive infrastructure rotation and renaming?), precision (documented false-positive profile), and level discipline, per the project's Detection/Hunting split. All three original rules target Windows host telemetry. Two describe complementary halves of the same BYOVD sequence, kernel-mode driver service registration and CrowdStrike Falcon process termination, and are combined below into a single temporal-correlation rule that tracks this toolkit's own documented execution window from driver deployment through security-product termination. The third targets the two specific, legitimately-signed-but-vulnerable driver files this toolkit embeds, loaded from a Temp directory rather than a normal install path.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 0 | 0 | — | 0 |
| Sigma | 2 | 2 | T1685, T1068 | 0 |
| Suricata | 0 | 0 | — | 0 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Atomics routed to the IOC feed:** none of the three original rules keyed solely on a hard-coded atomic; all three encode multi-condition host behavior. The toolkit's atomic indicators, the shared distribution/C2 IP (`109.230.231.37`) and the sample's file hashes, are already present in [`arsenal-237-killer-crowdstrike-dll.json`](/ioc-feeds/arsenal-237-killer-crowdstrike-dll.json).

---

## Sigma Rules

### Detection Rules

#### BYOVD Kernel Driver Install + CrowdStrike Falcon Termination (Correlation)

**Tier:** Detection (correlation rule) — bundled below with its 2 required non-alerting base rules
**Robustness:** 3 (correlation) / 1 (Falcon-termination base) / 2 (driver-service-creation base)
**ATT&CK Coverage:** T1685 (Impair Defenses), T1068 (Exploitation for Privilege Escalation)
**Confidence:** HIGH
**Rationale:** Neither base signal is reliable alone. *Fix applied during retiering:* the Falcon-termination rule's original `filter_legitimate` clause checked `ParentImage` and `User` against the `process_termination` logsource, but Sysmon's process-termination event (EventID 5) is documented to carry only the `Image` field, with no parent-process or user-context attribution, so that filter cannot reliably separate a forced kill from a routine Falcon restart on this logsource. The driver-service-creation rule's own description already stated that its intended correlation with a CrowdStrike termination "within 60 seconds" had been dropped because "single-event Sigma rules cannot express cross-event correlation." Both problems share one fix: rebuilding the pairing as a genuine Sigma temporal correlation. Kernel-mode driver service registration is the mechanism BYOVD requires to load a vulnerable driver at all, and this toolkit's own documented execution timeline runs from driver deployment through security-product termination in well under a minute, so a same-host co-occurrence within the correlation window is a high-confidence pairing rather than two unrelated routine events.
**False Positives:** A coordinated security-product migration (uninstalling CrowdStrike while installing a different vendor's kernel-mode filter driver in the same maintenance window) could produce both artifacts together. Uncommon, and typically scheduled, documented change activity rather than silent background noise.
**Blind Spots:** A driver-mapping technique that loads the vulnerable driver without registering it as an SCM service (bypassing the classic CreateService/StartService BYOVD pattern) evades the driver-service-creation base entirely, defeating the correlation. Events spanning a host reboot or exceeding the 60-second window also evade.
**Validation:** Trigger a kernel-mode driver service installation (EventID 7045, ServiceType kernel mode driver) followed within 60 seconds by termination of csagent.exe, CSFalconService.exe, or CSFalconContainer.exe on the same host: the correlation must fire. A CrowdStrike sensor update or restart alone, or a routine third-party driver install alone, must NOT fire the correlation.
**Deployment:** Sysmon (or equivalent EDR telemetry covering process termination and kernel-driver-service creation) ingested into a SIEM correlation engine supporting Sigma temporal correlation, deployed on all CrowdStrike-protected endpoints.

```yaml
title: CrowdStrike Falcon Core Process Termination (Base Rule)
id: 7aba482e-4b15-44ca-b9e3-c85733066ced
name: crowdstrike_falcon_process_termination
status: experimental
description: >-
    Base rule (not alerting on its own): termination of one of CrowdStrike
    Falcon's three core processes (CSFalconService.exe, csagent.exe,
    CSFalconContainer.exe). Sysmon's process-termination event (EventID 5)
    is documented to carry only the Image field, with no parent-process or
    user-context attribution, so this selector alone cannot distinguish a
    forced kill from a routine Falcon restart or update. Paired with the
    kernel-driver-service-creation base rule below via the correlation
    rule, which flags co-occurrence of both BYOVD-EDR-kill artifacts on
    the same host.
references:
    - https://the-hunters-ledger.com/hunting-detections/arsenal-237-killer-crowdstrike-dll-detections/
author: The Hunters Ledger
date: '2026-01-25'
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
            - '\CSFalconService.exe'
            - '\csagent.exe'
            - '\CSFalconContainer.exe'
    condition: selection
falsepositives:
    - >-
        Legitimate CrowdStrike Falcon sensor restarts, version updates, and
        administrator-initiated service stops all produce this same event.
        Not alerting on its own; reviewed only in combination with the
        paired driver-service-creation base rule.
level: informational
---
title: Kernel-Mode Driver Service Creation (Base Rule)
id: bb877b05-3f32-4437-8365-35cd3b58f35f
name: kernel_driver_service_creation
status: experimental
description: >-
    Base rule (not alerting on its own): installation of a new kernel-mode
    driver service via the Service Control Manager, the mechanism the
    BYOVD (Bring Your Own Vulnerable Driver) technique requires to load a
    vulnerable driver at all. Rare on most endpoints, but common enough
    alone (hardware installs, security-product updates) to need
    corroboration before alerting. Paired with the CrowdStrike-termination
    base rule above via the correlation rule below.
references:
    - https://the-hunters-ledger.com/hunting-detections/arsenal-237-killer-crowdstrike-dll-detections/
author: The Hunters Ledger
date: '2026-01-25'
tags:
    - attack.privilege-escalation
    - attack.t1068
    - detection.emerging-threats
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
    - >-
        Legitimate driver installation (new hardware, security or
        monitoring software updates). Not alerting on its own; reviewed
        only in combination with the paired CrowdStrike-termination base
        rule.
level: low
---
title: BYOVD Kernel Driver Install Followed by CrowdStrike Falcon Termination on Same Host
id: e91a4c6d-7f28-4b53-a916-3d8f6c2b9e47
status: experimental
description: >-
    Fires when a new kernel-mode driver service is installed and one of
    CrowdStrike Falcon's core processes terminates on the same host within
    a short window. Neither base signal is reliable alone: the
    process-termination event carries no parent or user attribution to
    separate a forced kill from a routine restart, and a kernel-driver
    service install alone is common enough to need corroboration. This
    toolkit's documented execution timeline runs from driver deployment
    through security-product termination in well under a minute, so a
    same-host co-occurrence within the correlation window is a
    high-confidence pairing rather than two unrelated routine events.
references:
    - https://the-hunters-ledger.com/hunting-detections/arsenal-237-killer-crowdstrike-dll-detections/
author: The Hunters Ledger
date: '2026-01-25'
tags:
    - attack.defense-impairment
    - attack.t1685
    - attack.privilege-escalation
    - attack.t1068
    - detection.emerging-threats
correlation:
    type: temporal
    rules:
        - crowdstrike_falcon_process_termination
        - kernel_driver_service_creation
    group-by:
        - host.name
    timespan: 60s
falsepositives:
    - >-
        A coordinated security-product migration (uninstalling CrowdStrike
        while installing a different vendor's kernel-mode filter driver in
        the same maintenance window) could produce both artifacts
        together. Uncommon, and typically scheduled, documented change
        activity.
level: high
```

#### Known-Vulnerable Driver Loaded from Temporary Directory (BYOVD)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1685 (Impair Defenses), T1068 (Exploitation for Privilege Escalation)
**Confidence:** HIGH
**Rationale:** Anchors on the two specific, legitimately-signed-but-vulnerable driver files this toolkit embeds (BdApiUtil64.sys and the ProcExp-family driver), combined with a Temp-directory load path that is not how either product is normally installed. *Fix applied during retiering:* the original selector's driver-name list included the bare substring `.sys` alongside the two named drivers; since every kernel driver's filename ends in `.sys`, that entry alone satisfied the list for any driver load whatsoever, silently widening the rule from "these two named vulnerable drivers" to "any driver loaded from Temp." Removed, restoring the rule's intended scope. A different, unnamed vulnerable driver evades this rule entirely, since it depends on a curated pair of known driver identities rather than a generic "vulnerable driver" primitive; that curated-identity dependency is the ceiling on its durability. The rule's own description already correctly identified that its other intended correlation, CrowdStrike Falcon sensor-offline telemetry, is Falcon console/API-side data with no Windows/Sysmon expression and could not be rebuilt in Sigma; that portion stands as originally scoped.
**False Positives:** Legitimate use of Process Explorer (ProcExp) run directly from a temporary or download-extraction directory rather than an installed path is plausible among IT and security-savvy users. Baidu Antivirus's driver is a much rarer legitimate presence outside its home market.
**Blind Spots:** Any other cataloged vulnerable driver evades detection; the rule targets only the two specific drivers this toolkit's BYOVD engine embeds, not a generic vulnerable-driver primitive.
**Validation:** Trigger a load of BdApiUtil64.sys or a ProcExp-family driver from a path containing `\Temp\`: must match. A load of either driver from its normal installed path, or an unrelated driver loaded from Temp, must NOT fire.
**Deployment:** Sysmon EventID 6 (driver load) ingestion, EDR kernel-module monitoring, endpoint driver-load auditing on all Windows hosts.

```yaml
title: Known-Vulnerable Driver Loaded from Temporary Directory (BYOVD)
id: fddb4e86-c31e-4ccd-86d3-788882ef3d20
status: experimental
description: >-
    Detects loading of the BdApiUtil64.sys (Baidu Antivirus) or a
    ProcExp-family (Sysinternals Process Explorer) driver from a Temp
    directory, the BYOVD pattern this toolkit uses to disable EDR/AV
    kernel hooks. Both drivers are legitimately signed products with a
    known kernel vulnerability; loading either from a temporary directory
    rather than a normal install path is this toolkit's own deployment
    pattern.
references:
    - https://the-hunters-ledger.com/hunting-detections/arsenal-237-killer-crowdstrike-dll-detections/
author: The Hunters Ledger
date: '2026-01-25'
tags:
    - attack.defense-impairment
    - attack.t1685
    - attack.privilege-escalation
    - attack.t1068
    - detection.emerging-threats
logsource:
    category: driver_load
    product: windows
detection:
    selection_name:
        ImageLoaded|contains:
            - 'BdApiUtil64.sys'
            - 'ProcExp'
    selection_path:
        ImageLoaded|contains: '\Temp\'
    condition: selection_name and selection_path
falsepositives:
    - Legitimate use of Process Explorer (ProcExp) run directly from a temporary or extraction directory rather than an installed path.
level: high
```

---

## Coverage Gaps

### Retiering Fixes Applied

- **Sigma Falcon-termination filter removed a non-existent field dependency (source Rule 1).** The `filter_legitimate` clause checked `ParentImage` and `User` against the `process_termination` logsource, but Sysmon's process-termination event (EventID 5) is documented to carry only the `Image` field, with no parent-process or user-context attribution. As written, that filter cannot reliably distinguish a forced kill from a legitimate CrowdStrike-initiated restart on this logsource. The bare `Image` selection now stands as a silent correlation base rather than a standalone filtered alert.
- **Sigma driver-service-creation rule's dropped correlation rebuilt (source Rule 2).** The rule's own description already stated that its intended correlation, a CrowdStrike process termination within 60 seconds of the driver-service event, had been dropped because "single-event Sigma rules cannot express cross-event correlation." That correlation is expressible with Sigma's `correlation:` construct; rebuilt above as a temporal correlation combining this rule (now a silent base) with the fixed Falcon-termination base, closing the exact gap the original description named.
- **Sigma vulnerable-driver selector's tautological entry removed (source Rule 3).** The `selection_name.ImageLoaded|contains` list included the bare substring `.sys` alongside `BdApiUtil64.sys` and `ProcExp`. Every kernel driver's filename ends in `.sys`, so that entry alone satisfied the list for any driver load whatsoever, making the two named-driver entries redundant and silently widening the rule to "any driver loaded from a Temp directory." Removed, restoring the rule's intended scope to the two vulnerable drivers this toolkit actually embeds. The rule's own description also correctly identified that its other intended correlation, CrowdStrike sensor-offline telemetry, is Falcon console/API-side data with no Windows/Sysmon expression; that portion could not be rebuilt and stands as originally scoped.
- **Levels recalibrated.** Source Rule 1 (`critical`) already documented two real false-positive categories (legitimate updates, admin-initiated stops), which contradicts the near-never-FP bar `critical` requires even before the field-dependency fix; it now exists only as an informational correlation base. Source Rule 2 (`high`) is, alone, a broad "any kernel driver installed" selector; it now stands at `low` as a correlation base, with `high` reserved for the correlation itself.
- **References rewritten.** The original `references:` lists used non-resolvable descriptive strings ("killer_crowdstrike.dll analysis report", "Arsenal-237 malware toolkit investigation") rather than URLs; all rules now carry a single reference to this detections page, per the project's one-entry convention.
- **Tags verified, not assumed.** T1685 plus the `attack.defense-impairment` tactic tag (the ATT&CK v19 replacement for the old T1562.001 sub-technique tree) were already used correctly in two of the three source rules. Final tags across all rules were confirmed against the real `sigma check` validator rather than left as drafted.

### No CrowdStrike-Specific Network Signature

This variant's command-and-control channel is identical to killer.dll's, the same hardcoded URL (`http://109.230.231.37:8888/lpe.exe`), reused unchanged rather than reconfigured. It carries no protocol structure specific to the CrowdStrike-targeting behavior itself. The only network artifacts are the toolkit-wide distribution and C2 IP, already routed to the IOC feed (see Detection Coverage Summary above).

### Capabilities Documented in the IOC Feed Without Dedicated Rule Coverage

- **IOCTL-level process termination** (DeviceIoControl calls with IOCTL `0x800024B4` / `0x8335003C` against the `\\.\BdApiUtil` and `\\.\PROCEXP152` device handles) is a kernel-API detail invisible to standard Windows Event Log/Sysmon telemetry; no Sigma-expressible signal exists at this layer.
- **Anti-forensic cleanup** (service deletion, driver file deletion, and driver unload within seconds of termination) is a documented behavior with no dedicated rule in the source material. A rapid create-then-delete service-lifecycle correlation is plausible future coverage but was not part of the original three rules and has not been added here to avoid inventing coverage beyond the source's scope.
- **Generalized mass-termination coverage** ("3 or more security products terminated within 60 seconds," spanning Defender and third-party AV, not just CrowdStrike) belongs to the toolkit's generic killer.dll detection scope, not duplicated in this CrowdStrike-specific file.

### What Would Enable Stronger Coverage

- **CrowdStrike Falcon sensor-offline telemetry** (console/API-side, not Windows/Sysmon-expressible) would allow a genuinely EDR-native correlation, closer to source Rule 3's original intent than the Sysmon-side driver-service correlation built here.
- **Identification of the embedded, unknown-purpose Microsoft-signed binary** this variant carries (absent from killer.dll) would allow a dedicated signature for that component once its function is determined.
- **A broader, maintained vulnerable-driver name/hash catalog** (beyond the two drivers this specific toolkit embeds) would raise the standalone driver-load rule's durability from a curated pair of known identities toward a general BYOVD primitive.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
