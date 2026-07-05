---
title: "Detection Rules — EvilSoul-Engine Stealer-Builder MaaS"
date: '2026-07-03'
layout: post
permalink: /hunting-detections/evilsoul-engine-stealer-maas-detections/
hide: true
---

**Campaign:** KAIDO / EvilSoul-Engine Multi-Product MaaS Operator (144.172.103.98)
**Date:** 2026-07-03
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/evilsoul-engine-stealer-maas-144-172-103-98/

---

## Detection Coverage Summary

> **Scope note:** this file covers the **EvilSoul-Engine stealer-builder ecosystem only** — `stealer.js` (Node), the `299a2e7f` Socket.IO WebPanel variant, the Maploot/Tinarox Electron twins, and the commodity xaitax Chrome App-Bound-Encryption (ABE) bypass tool pair. The KAIDO Quasar-fork RAT product line is covered in a separate detection file to prevent duplication.

| Rule Type | Count | MITRE Techniques Covered | Overall FP Risk |
|---|---|---|---|
| YARA | 5 | T1027, T1555.003, T1539, T1620, T1055.012, T1588.002 | LOW |
| Sigma | 6 | T1185, T1003.001, T1562.001, T1053.005, T1036.004, T1564.001 | LOW–MEDIUM |
| Suricata | 6 | T1071.001, T1041, T1105 | LOW (1 validated) / MEDIUM (5 unvalidated) |

**Detection philosophy.** Every EvilSoul-Engine customer build is uniquely repacked at build time (js-confuser → AES-256-GCM → XOR → base64 → in-memory exec), so **hash-based detection has LOW durability** against new builds. The durable, build-independent signals are: the operator-signature XOR constant (survives js-confuser because it lives in the loader, not the packed payload), the CDP browser-relaunch cookie-theft pattern, the LSASS-impersonation Python stdin decryptor, and the Microsoft-masquerade hidden scheduled task. Deploy YARA string rules against source/staged JS and unpacked Electron `app.asar` archives; deploy Sigma rules for runtime behavioral detection that holds regardless of the specific build variant.

**Suricata validation note.** The DNS-based rule below is validated (`suricata -T` test-compile, PASS). The five `alert http`-keyword rules are flagged **Unvalidated**: an automated exclusive-ruleset test could not validate the bare `http` keyword used in these rules, so validate them with a full `suricata -T` run in your own environment before deployment. The match logic itself was manually reviewed against the `suricata-rule-formatting` skill spec.

---

## YARA Rules

### EvilSoul-Engine — Kit-Wide Anchors

**Detection Priority:** HIGH
**Rationale:** The obfuscator's XOR key literal `see-you-in-the-hellwizard-1082@239$328927bA` and catchphrase comment live in the loader stage, which every EvilSoul-Engine build carries pre-packing. They survive the js-confuser layer because the loader is what invokes the obfuscated payload, not what gets obfuscated itself. Combined with the split-domain anti-grep pattern, this is the single most durable EvilSoul-Engine anchor across all product tiers (`stealer.js`, `299a2e7f`, Maploot, Tinarox).
**ATT&CK Coverage:** T1027 (Obfuscated Files or Information), T1588.002 (Obtain Capabilities: Tool)
**Confidence:** HIGH
**False Positive Risk:** LOW — the XOR key string is a 44-character operator-chosen literal with zero plausible legitimate-software collision; the catchphrase comment is similarly distinctive.
**Deployment:** Endpoint file scan on staged/dropped JS, Electron `app.asar` archives, memory scanning during detonation.

```yara
/*
   Yara Rule Set
   Identifier: EvilSoul-Engine Stealer-Builder MaaS - Kit-Wide Obfuscator Anchors
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule EvilSoul_Engine_Obfuscator_XOR_Key {
   meta:
      description = "Detects EvilSoul-Engine stealer-builder MaaS output via the operator's hardcoded obfuscator XOR key constant and catchphrase comment, which survive js-confuser because they reside in the loader stage rather than the packed payload"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/evilsoul-engine-stealer-maas-detections/"
      date = "2026-07-03"
      hash1 = "940bdf8421ace41cd9a93957122feed9faf0db02016c4b9daf4aeac7c0c794ed"
      family = "EvilSoul-Engine"
      malware_type = "Stealer-Builder"
      campaign = "EvilSoul-Engine-Stealer-MaaS-144.172.103.98"
      id = "5dddfdb6-6a13-54aa-83ed-65e27f52ac3b"
   strings:
      $xor_key = "see-you-in-the-hellwizard-1082@239$328927bA" ascii wide
      $catchphrase = "wizard see you in the hell" ascii wide
      $debug_file = "kaido_debug.txt" ascii wide fullword
      $token_decoder = "D2VGTBwNZh8zV2A=" ascii wide
   condition:
      filesize < 200MB and
      ($xor_key or ($catchphrase and 1 of ($debug_file, $token_decoder)))
}

rule EvilSoul_Engine_SplitDomain_AntiGrep {
   meta:
      description = "Detects EvilSoul-Engine's split-string anti-grep evasion of its own backend domain, where 'evilsoul.xyz' is constructed at runtime as the concatenation 'evilso' + 'ul.xyz' to defeat static string-grep hunting for the plaintext domain"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/evilsoul-engine-stealer-maas-detections/"
      date = "2026-07-03"
      hash1 = "763303b69ad589bef248b66d1db93d5e567d9d60f95511806289289ff42a548e"
      family = "EvilSoul-Engine"
      malware_type = "Stealer-Builder"
      campaign = "EvilSoul-Engine-Stealer-MaaS-144.172.103.98"
      id = "b840f5f4-2278-5334-9567-825b5491553c"
   strings:
      $split1 = "'evilso'+'ul.xyz'" ascii wide
      $split2 = "\"evilso\"+\"ul.xyz\"" ascii wide
      $split3 = "'evilso' + 'ul.xyz'" ascii wide
      $split4 = "\"evilso\" + \"ul.xyz\"" ascii wide
   condition:
      filesize < 200MB and
      1 of them
}
```

**File name:** `mal_evilsoul_engine_kit_wide.yar`

---

### EvilSoul-Engine — Maploot / Tinarox Electron Twins

**Detection Priority:** HIGH
**Rationale:** The Maploot/Tinarox embed-title strings (`EvilSoul Stealer - (Discord ~`, `EvilSoul Stealer - (BrowserData ~`) are the literal text sent to the operator's Discord webhook as embed titles for each exfil category. These strings are unique to the EvilSoul-Engine Electron product line and were independently confirmed byte-for-byte identical between the two "twin" builds after webcrack de-obfuscation, meaning they are stable across the builder's per-build obfuscation-layer evolution.
**ATT&CK Coverage:** T1555.003 (Credentials from Web Browsers), T1528 (Steal Application Access Token)
**Confidence:** HIGH
**False Positive Risk:** LOW — "EvilSoul Stealer -" is a distinctive branded string with no legitimate-software collision risk.
**Deployment:** Endpoint file scan on Electron `app.asar` / unpacked `resources/app` directories, memory scanning during detonation.

```yara
/*
   Yara Rule Set
   Identifier: EvilSoul-Engine Stealer-Builder MaaS - Maploot/Tinarox Electron Builds
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule EvilSoul_Engine_Maploot_Tinarox_Embed_Titles {
   meta:
      description = "Detects EvilSoul-Engine Maploot/Tinarox Electron stealer builds via their branded Discord-embed exfil title strings, confirmed byte-for-byte shared across both game-masquerade builds after webcrack de-obfuscation"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/evilsoul-engine-stealer-maas-detections/"
      date = "2026-07-03"
      hash1 = "763303b69ad589bef248b66d1db93d5e567d9d60f95511806289289ff42a548e"
      hash2 = "fe55908030318879f08b185b9c5b6e6f9d6f691154c361d60cce80162d844212"
      family = "EvilSoul-Engine"
      malware_type = "Stealer (Electron)"
      campaign = "EvilSoul-Engine-Stealer-MaaS-144.172.103.98"
      id = "7c0ba54a-cfe9-5363-b03c-52a5b183535e"
   strings:
      $embed1 = "EvilSoul Stealer - (Discord ~" ascii wide
      $embed2 = "EvilSoul Stealer - (BrowserData ~" ascii wide
      $embed3 = "EvilSoul (Exodus Session and BruteForce)" ascii wide
      $embed4 = "EvilSoul (Steam Session)" ascii wide
      $embed5 = "EvilSoul (Minecraft Session)" ascii wide
      $masquerade = "Unreal Game Inc." ascii wide
      $endpoint1 = "dcinjection-send" ascii wide
      $endpoint2 = "upload-txts" ascii wide
   condition:
      filesize < 250MB and
      (2 of ($embed*) or (1 of ($embed*) and ($masquerade or 1 of ($endpoint*))))
}
```

**File name:** `mal_evilsoul_engine_maploot_tinarox.yar`

---

### EvilSoul-Engine — 299a2e7f Socket.IO WebPanel Variant

**Detection Priority:** HIGH
**Rationale:** The args-file suffix `evilsoulblockkstarjkjaksghjhsjkahjskjak81929ijsahsjkj` is a deliberately long, high-entropy operator-chosen string used as a temp-file naming suffix for the `299a2e7f` build's argument passing. Its length and entropy make it a near-zero-false-positive anchor — no legitimate software would coincidentally produce this exact 54-character token.
**ATT&CK Coverage:** T1071.001 (Web Protocols — C2), T1105 (Ingress Tool Transfer)
**Confidence:** HIGH
**False Positive Risk:** LOW — string is a long, operator-unique, non-dictionary token.
**Deployment:** Endpoint file scan (temp directories, staged payloads), memory scanning during detonation of pkg-Node single-EXE builds.

```yara
/*
   Yara Rule Set
   Identifier: EvilSoul-Engine Stealer-Builder MaaS - 299a2e7f Socket.IO WebPanel Variant
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule EvilSoul_Engine_299a2e7f_SocketIO_WebPanel {
   meta:
      description = "Detects the EvilSoul-Engine 299a2e7f Socket.IO WebPanel RAT build via its distinctive args-file suffix, WebPanel embed title, and webhook-resolution relay endpoint string, all recovered from the build's runtime memory"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/evilsoul-engine-stealer-maas-detections/"
      date = "2026-07-03"
      hash1 = "299a2e7fa8a69c495ec19fecf55d93bb766addaa78e89a4e1ad78a9cea59b31c"
      family = "EvilSoul-Engine"
      malware_type = "Stealer + Interactive RAT (Socket.IO)"
      campaign = "EvilSoul-Engine-Stealer-MaaS-144.172.103.98"
      id = "3e7ee8e6-dfb5-5e12-a5c4-60d1db53ee2b"
   strings:
      $argsfile = "evilsoulblockkstarjkjaksghjhsjkahjskjak81929ijsahsjkj" ascii wide fullword
      $panel = "EvilSoul ~ (WebPanel)" ascii wide
      $handle = "@evilsoulstealer" ascii wide
      $relay = "198.1.195.210:3000/tralalero" ascii wide
      $fallback_key = "6D479A7E665F" ascii wide fullword
      $update_cmd = "updatesystem.cmd" ascii wide fullword
   condition:
      filesize < 100MB and
      ($argsfile or $relay or (2 of ($panel, $handle, $fallback_key, $update_cmd)))
}
```

**File name:** `mal_evilsoul_engine_299a2e7f.yar`

---

### xaitax Chrome App-Bound-Encryption Bypass Tool Pair (Commodity Supply Chain)

**Detection Priority:** MEDIUM
**Rationale:** The `chromelevator.exe` + `chrome_decrypt.dll` pair is a public red-team tool (xaitax "Chrome-App-Bound-Encryption-Decryption") adopted by the EvilSoul-Engine operator as a supply-chain component rather than authored in-house. Detection value here is in flagging its presence regardless of delivery vector (this campaign's `github.com/sqlban` mirror, `evilsoul.xyz`, or any other actor's redistribution), since AV vendors already family-name close siblings as a generic hacktool. The rule anchors on the operator-fork banner strings unique to the `@breakingupslow`-attributed build, not the tool's stock upstream strings, to avoid over-broad matching against every public fork.
**ATT&CK Coverage:** T1555.003 (Credentials from Web Browsers), T1539 (Steal Web Session Cookie), T1055.012 (Process Hollowing), T1620 (Reflective Code Loading)
**Confidence:** HIGH
**False Positive Risk:** LOW — the co-credit banner and copyright-notice strings are specific to this fork; generic ABE-tool detection is intentionally avoided by anchoring on the fork attribution text rather than the underlying decryption logic (which is public prior art and would over-match on every xaitax fork in the wild).
**Deployment:** Endpoint AV/EDR scan on `%TEMP%\executor\`, memory scanning during detonation.

```yara
/*
   Yara Rule Set
   Identifier: EvilSoul-Engine Supply Chain - xaitax ChromElevator ABE-Bypass Fork
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule Tool_xaitax_ChromElevator_EvilSoul_Fork {
   meta:
      description = "Detects the @breakingupslow-forked build of the public xaitax Chrome-App-Bound-Encryption-Decryption (ChromElevator) tool pair, adopted by the EvilSoul-Engine operator as a runtime-fetched ABE-bypass supply-chain component; anchors on fork-specific attribution strings rather than the stock upstream tool's generic decryption logic"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/evilsoul-engine-stealer-maas-detections/"
      date = "2026-07-03"
      hash1 = "dd97278cc64d0a8fbdb66f177367c29d2557dd445b306e922e9ad5660ea233e2"
      hash2 = "928f2ffa7fc84b74941fb714455d7bc14847b3af"
      hash3 = "a567eab759a390a00b4605ea7d161b26"
      family = "EvilSoul-Engine (xaitax ChromElevator fork)"
      malware_type = "HackTool (ABE Bypass)"
      campaign = "EvilSoul-Engine-Stealer-MaaS-144.172.103.98"
      id = "69fc6b2f-9058-5fb8-802a-5e0559c9d881"
   strings:
      $banner = " by @xaitax / @breakingupslow" ascii wide
      $hollow_str = " Direct Syscall-Based Reflective Hollowing" ascii wide
      $pipe = "__DLL_PIPE_COMPLETION_SIGNAL__" ascii wide fullword
      $key_str = "\"app_bound_encrypted_key\":\"" ascii
      $gcm = "ChainingModeGCM" ascii wide fullword
      $copyright = "# Copyright (https://t.me/evilsoulstealer/)" ascii wide
      $resource = "PAYLOAD_DLL" ascii fullword
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      ($banner or $copyright or 2 of ($hollow_str, $pipe, $key_str, $gcm, $resource))
}
```

**File name:** `tool_xaitax_chromelevator_evilsoul_fork.yar`

---

## Sigma Rules

### CDP Browser-Relaunch Cookie Theft (ABE Bypass)

**Detection Priority:** HIGH
**Rationale:** Both the EvilSoul-Engine stealer payload and the xaitax ABE-bypass tools relaunch the victim's own installed browser headless with Chrome DevTools Protocol (CDP) debugging enabled, then pull already-decrypted cookies via `Network.getAllCookies` — defeating Chrome's App-Bound Encryption without requiring administrator rights. A browser binary launched with this exact flag combination by a non-browser, non-developer-tooling parent process is a high-confidence behavioral signal independent of the specific EvilSoul-Engine build variant.
**ATT&CK Coverage:** T1185 (Browser Session Hijacking), T1539 (Steal Web Session Cookie)
**Confidence:** HIGH
**False Positive Risk:** LOW-MEDIUM — legitimate browser automation/testing tools (Selenium, Puppeteer, Playwright) use the same flags, but are typically spawned by developer-tooling parents (`node.exe`, `python.exe` in a dev context, CI runners), not by an unrelated stealer/loader process. Tune the parent-process allowlist per environment.
**Deployment:** EDR process-creation monitoring, SIEM correlation on Sysmon Event ID 1 / Event ID 3.

```yaml
title: Browser Relaunched with Remote Debugging and Headless Flags by Non-Browser Parent
id: b788a75b-a966-47d5-b91b-5fb92b2e9571
status: test
description: >-
  Detects a Chromium-based browser process launched with --remote-debugging-port,
  --headless, and --user-data-dir simultaneously by a parent process that is not a
  known browser or developer-automation binary. This flag combination is used by the
  EvilSoul-Engine stealer-builder MaaS and its bundled xaitax ChromElevator tool to
  relaunch the victim's own browser under CDP control and pull already-decrypted
  cookies via Network.getAllCookies, bypassing Chrome App-Bound Encryption without
  administrator rights.
references:
    - https://the-hunters-ledger.com/hunting-detections/evilsoul-engine-stealer-maas-detections/
    - https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption
author: The Hunters Ledger
date: 2026-07-03
tags:
    - attack.credential-access
    - attack.t1539
    - attack.collection
    - attack.t1185
logsource:
    category: process_creation
    product: windows
detection:
    selection_flags:
        CommandLine|contains|all:
            - '--remote-debugging-port'
            - '--headless'
            - '--user-data-dir'
    filter_main_browser_parent:
        ParentImage|endswith:
            - '\chrome.exe'
            - '\msedge.exe'
            - '\brave.exe'
            - '\explorer.exe'
    filter_dev_tooling_parent:
        ParentImage|endswith:
            - '\node.exe'
            - '\python.exe'
            - '\pythonw.exe'
    condition: selection_flags and not 1 of filter_*
falsepositives:
    - Legitimate browser automation frameworks (Selenium, Puppeteer, Playwright) launched from a known developer-tooling parent process
    - QA/CI pipelines that headlessly drive a browser for testing
level: high
```

**File name:** `proc_creation_win_evilsoul_engine_cdp_cookie_theft.yml`

---

### LSASS-Impersonation Python Stdin ABE Decryptor

**Detection Priority:** HIGH
**Rationale:** The `stealer.js` build's most advanced credential-theft component downloads a portable Python interpreter, pipes a decryptor script over stdin (never touching disk as a `.py` file), enables `SeDebugPrivilege`, and impersonates the `lsass.exe` process token to decrypt the Chrome App-Bound-Encryption key via Windows CNG. The stdin-execution pattern (no script file to scan) combined with an `lsass.exe` handle open from a `python.exe`/`pythonw.exe` process is a distinctive, low-noise correlation across two Sysmon event types.
**ATT&CK Coverage:** T1003.001 (LSASS Memory), T1539 (Steal Web Session Cookie)
**Confidence:** HIGH
**False Positive Risk:** LOW — legitimate Python tooling rarely opens a handle to `lsass.exe`; this combination is a strong credential-theft signal. Some EDR/security-research tooling with LSASS-inspection features could trigger this — tune by known-good process hash if deployed in a security-research environment.
**Deployment:** EDR process-creation + process-access correlation, SIEM correlation on Sysmon Event ID 1 + Event ID 10.

```yaml
title: Python Process Opens LSASS Handle After Stdin Execution (ABE Decryptor Pattern)
id: e2ccff6f-eec8-4a34-a78e-4ac4bf5d50f3
status: test
description: >-
  Detects a python.exe or pythonw.exe process that opens a handle to lsass.exe
  shortly after being launched with the -u - stdin-execution flag combination
  (no script file argument). This is the EvilSoul-Engine stealer.js build's
  LSASS-impersonation App-Bound-Encryption decryptor, which enables SeDebugPrivilege
  and impersonates the lsass.exe token to decrypt Chrome's app-bound key via
  Windows CNG, leaving no decryptor script on disk.
references:
    - https://the-hunters-ledger.com/hunting-detections/evilsoul-engine-stealer-maas-detections/
author: The Hunters Ledger
date: 2026-07-03
tags:
    - attack.credential-access
    - attack.t1003.001
    - attack.t1539
logsource:
    category: process_access
    product: windows
detection:
    selection_access:
        TargetImage|endswith: '\lsass.exe'
        SourceImage|endswith:
            - '\python.exe'
            - '\pythonw.exe'
    condition: selection_access
falsepositives:
    - EDR or security-research tooling written in Python that legitimately inspects LSASS
    - Authorized credential-recovery or forensic tooling in incident-response workflows
level: high
```

**File name:** `proc_access_win_evilsoul_engine_lsass_python_decryptor.yml`

---

### Whole-Drive Defender Exclusion Plus Real-Time Monitoring Disable

**Detection Priority:** HIGH
**Rationale:** The `299a2e7f` build's `DisableProtections` function whole-drive-excludes `C:\` from Windows Defender and disables real-time monitoring via PowerShell cmdlets in the same script block. A whole-drive exclusion path (`C:\` specifically, not a narrow application directory) is a strong signal because legitimate software almost never excludes an entire drive letter — narrow, path-specific exclusions are the normal legitimate pattern.
**ATT&CK Coverage:** T1562.001 (Impair Defenses: Disable or Modify Tools)
**Confidence:** HIGH
**False Positive Risk:** LOW-MEDIUM — some IT-admin deployment scripts do configure Defender exclusions for performance reasons, but whole-drive `C:\` exclusion combined with real-time-monitoring disable in the same script block is uncommon in legitimate administration.
**Deployment:** SIEM correlation on PowerShell Script Block Logging (Windows Event ID 4104).

```yaml
title: Whole-Drive Windows Defender Exclusion Combined with Real-Time Monitoring Disable
id: fde077ad-0afc-4158-bff6-f4c80604d461
status: test
description: >-
  Detects PowerShell script block content that both adds a whole-drive
  (C:\) Windows Defender exclusion path and disables real-time monitoring in
  the same execution context. This is the AV/Defender-suppression chain used
  by the EvilSoul-Engine 299a2e7f Socket.IO WebPanel build's DisableProtections
  function, which also disables behavior monitoring and the Windows Firewall
  before running noisy credential-theft operations.
references:
    - https://the-hunters-ledger.com/hunting-detections/evilsoul-engine-stealer-maas-detections/
author: The Hunters Ledger
date: 2026-07-03
tags:
    - attack.defense-evasion
    - attack.t1562.001
logsource:
    category: ps_script
    product: windows
detection:
    selection_exclusion:
        ScriptBlockText|contains:
            - "Add-MpPreference -ExclusionPath 'C:\\'"
            - 'Add-MpPreference -ExclusionPath "C:\\"'
    selection_disable:
        ScriptBlockText|contains:
            - 'Set-MpPreference -DisableRealtimeMonitoring $true'
            - 'Set-MpPreference -DisableBehaviorMonitoring $true'
    condition: selection_exclusion and selection_disable
falsepositives:
    - IT-administration deployment scripts that legitimately exclude C:\ during imaging or migration (uncommon but not impossible)
level: high
```

**File name:** `ps_script_win_evilsoul_engine_defender_suppression.yml`

---

### Hidden Scheduled Task Authored as Microsoft Corporation

**Detection Priority:** HIGH
**Rationale:** The `stealer.js` build's persistence mechanism registers a scheduled task with Task XML `Author` field set to the literal string `Microsoft Corporation` while also setting the hidden flag — a masquerade pattern designed to blend into Task Scheduler listings alongside genuine Microsoft-authored tasks. Genuine Microsoft tasks are installed by the OS/Windows Update, not created ad hoc by a user-context process at runtime after malware execution.
**ATT&CK Coverage:** T1053.005 (Scheduled Task), T1036.004 (Masquerade Task or Service)
**Confidence:** HIGH
**False Positive Risk:** LOW — legitimate Microsoft-authored scheduled tasks are pre-installed by the OS image or Windows Update, not created at runtime by arbitrary user-context processes.
**Deployment:** SIEM correlation on Windows Event ID 4698 (Scheduled Task Created).

```yaml
title: Scheduled Task Created with Microsoft Corporation Author and Hidden Flag
id: c69291c1-70a6-4aa1-835f-bc26d4afcc2f
status: test
description: >-
  Detects creation of a new scheduled task whose Task XML Author field is set
  to the literal string "Microsoft Corporation" combined with the hidden
  flag enabled. This is the EvilSoul-Engine stealer.js build's persistence
  masquerade, designed to blend into Task Scheduler listings next to genuine
  Microsoft-authored tasks; legitimate Microsoft tasks are installed by the
  OS image or Windows Update rather than created at runtime.
references:
    - https://the-hunters-ledger.com/hunting-detections/evilsoul-engine-stealer-maas-detections/
author: The Hunters Ledger
date: 2026-07-03
tags:
    - attack.persistence
    - attack.t1053.005
    - attack.defense-evasion
    - attack.t1036.004
logsource:
    product: windows
    service: security
    definition: 'Requires Task Scheduler operational logging or Security auditing of Task Scheduler object creation (Event ID 4698) with TaskContent captured'
detection:
    selection:
        EventID: 4698
        TaskContent|contains:
            - '<Author>Microsoft Corporation</Author>'
            - '<Hidden>true</Hidden>'
    condition: selection
falsepositives:
    - None expected — genuine Microsoft Corporation-authored tasks are pre-installed by the OS, not created via runtime Event ID 4698 registration by a user-context process
level: high
```

**File name:** `win_security_evilsoul_engine_hidden_scheduled_task_masquerade.yml`

---

### ABE-Bypass Tool Drop to %TEMP%\executor\

**Detection Priority:** MEDIUM
**Rationale:** The `299a2e7f` build downloads the xaitax ChromElevator ABE-bypass tool pair (`chromelevator.exe` and `chrome_decrypt.dll`) from a GitHub-hosted supply-chain mirror to a consistent staging path, `%TEMP%\executor\`. A file creation event matching this exact filename-plus-directory pattern is a specific, low-noise indicator of this stage of the attack chain.
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer), T1555.003 (Credentials from Web Browsers)
**Confidence:** HIGH
**False Positive Risk:** LOW — `chromelevator.exe` and `chrome_decrypt.dll` are not legitimate Windows or common third-party software filenames; the `%TEMP%\executor\` directory name is also distinctive.
**Deployment:** EDR file-creation monitoring, SIEM correlation on Sysmon Event ID 11.

```yaml
title: ChromElevator ABE-Bypass Tool Dropped to TEMP Executor Directory
id: 2d54e3fa-a90b-4709-9521-b7a4ab95e76a
status: test
description: >-
  Detects file creation of chromelevator.exe or chrome_decrypt.dll under a
  TEMP\executor\ path, matching the staging location used by the EvilSoul-Engine
  299a2e7f Socket.IO WebPanel build when it downloads the xaitax
  Chrome-App-Bound-Encryption-Decryption tool pair from a GitHub supply-chain
  mirror at runtime.
references:
    - https://the-hunters-ledger.com/hunting-detections/evilsoul-engine-stealer-maas-detections/
    - https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption
author: The Hunters Ledger
date: 2026-07-03
tags:
    - attack.command-and-control
    - attack.t1105
    - attack.credential-access
    - attack.t1555.003
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\executor\'
        TargetFilename|endswith:
            - '\chromelevator.exe'
            - '\chrome_decrypt.dll'
    condition: selection
falsepositives:
    - Extremely unlikely — these are operator-chosen filenames with no legitimate software collision
level: high
```

**File name:** `file_event_win_evilsoul_engine_abe_tool_drop.yml`

---

### Hidden Persistence Artifacts Written to TEMP/Startup by Non-System Process

**Detection Priority:** MEDIUM
**Rationale:** The `299a2e7f` build layers redundant "persistence-of-persistence": a `update.bat` in the Startup folder plus a hidden random-named `.lnk`, a hidden `updatesystem.cmd`, and a `watcher.vbs` watchdog in `%TEMP%`, all attribute-flagged hidden (`attrib +h`) after creation. The combination of file creation in these specific locations/names followed by the hidden attribute being set is a distinctive two-step pattern.
**ATT&CK Coverage:** T1564.001 (Hidden Files and Directories), T1053.005 (Scheduled Task)
**Confidence:** MODERATE
**False Positive Risk:** MEDIUM — some legitimate installers write files to Startup and briefly set hidden attributes; the filename specificity (`updatesystem.cmd`, `watcher.vbs`) reduces but does not eliminate this risk. Recommend correlating with the Defender-suppression or CDP-cookie-theft rules above for higher-confidence alerting.
**Deployment:** SIEM correlation on Sysmon Event ID 11 (FileCreate) filtered to the named artifacts.

```yaml
title: EvilSoul-Engine Watchdog Persistence Files Created in TEMP or Startup
id: 5f925688-77fd-410a-9c8a-83ca801a5013
status: test
description: >-
  Detects file creation of the specific watchdog and persistence-chain
  filenames used by the EvilSoul-Engine 299a2e7f build's redundant
  persistence-of-persistence mechanism, including updatesystem.cmd,
  watcher.vbs, and update.bat, which are subsequently attribute-flagged
  hidden to survive casual folder inspection.
references:
    - https://the-hunters-ledger.com/hunting-detections/evilsoul-engine-stealer-maas-detections/
author: The Hunters Ledger
date: 2026-07-03
tags:
    - attack.defense-evasion
    - attack.t1564.001
    - attack.persistence
    - attack.t1053.005
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith:
            - '\updatesystem.cmd'
            - '\watcher.vbs'
            - '\update.bat'
    filter_common_update_paths:
        TargetFilename|contains:
            - '\Windows\System32\'
            - '\Program Files\'
    condition: selection and not filter_common_update_paths
falsepositives:
    - Legitimate software update scripts that happen to share these generic filenames outside protected system directories
    - Custom internal IT automation using similarly named watchdog scripts
level: medium
```

**File name:** `file_event_win_evilsoul_engine_watchdog_persistence.yml`

---

## Suricata Signatures

### DNS Query for EvilSoul Backend Domains — VALIDATED

**Detection Priority:** HIGH
**Rationale:** Both `evilsoul.cc` (299a2e7f Socket.IO C2) and `evilsoul.xyz` (Maploot/Tinarox backend) share the `evilsoul.` prefix. A DNS query for either domain from an internal host is a strong pre-connection signal that fires before any HTTP payload is even sent, making it resilient to payload-level evasion.
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positive Risk:** LOW — `evilsoul.` is not a substring of any known legitimate domain.
**Deployment:** Network IDS/IPS at DNS resolver egress point.
**Validation status:** PASS — validated via a `suricata -T` test-compile.

```
alert dns $HOME_NET any -> any any (msg:"THL EvilSoul-Engine DNS Query for evilsoul.cc or evilsoul.xyz Backend"; dns_query; content:"evilsoul."; nocase; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000006; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-03, reference https://the-hunters-ledger.com/hunting-detections/evilsoul-engine-stealer-maas-detections/;)
```

---

> **Unvalidated.** The five rules below use the `http` app-layer protocol keyword. Validate them with a full `suricata -T` run in your own environment before deployment — an automated exclusive-ruleset test could not validate the bare `http` keyword; the match logic was manually reviewed against the `suricata-rule-formatting` skill spec.

### EvilSoul-Engine Socket.IO C2 Handshake (299a2e7f WebPanel RAT)

**Detection Priority:** HIGH
**Rationale:** The `299a2e7f` build establishes its interactive-RAT channel via a Socket.IO v4 handshake (`/socket.io/?EIO=4&transport=polling`) to `evilsoul.cc` before upgrading to WebSocket. This is the C2 establishment step for the build's live screen-streaming, remote-control, and destructive-command capabilities.
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positive Risk:** LOW — the combination of `evilsoul.cc` host and Socket.IO polling URI is specific to this C2 channel.
**Deployment:** Network IDS/IPS at network egress.

```
alert http $HOME_NET any -> any any (msg:"THL EvilSoul-Engine Socket.IO C2 Handshake to evilsoul.cc (299a2e7f WebPanel RAT)"; flow:established,to_server; http.host; content:"evilsoul.cc"; nocase; http.uri; content:"/socket.io/"; nocase; content:"transport=polling"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000001; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-03, reference https://the-hunters-ledger.com/hunting-detections/evilsoul-engine-stealer-maas-detections/;)
```

### EvilSoul-Engine Webhook-Resolution Relay POST /tralalero

**Detection Priority:** HIGH
**Rationale:** The `299a2e7f` build hardcodes no Discord webhook directly — instead it POSTs `{key: <licenseKey>}` to `198.1.195.210:3000/tralalero` and receives the actual webhook URL back at runtime. This late-binding relay is a distinctive, single-purpose endpoint with no legitimate use.
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1041 (Exfiltration Over C2 Channel)
**Confidence:** HIGH
**False Positive Risk:** LOW — the destination IP and URI path combination is operator-specific infrastructure.
**Deployment:** Network IDS/IPS at network egress.

```
alert http $HOME_NET any -> 198.1.195.210 any (msg:"THL EvilSoul-Engine Webhook-Resolution Relay POST /tralalero (299a2e7f License-Gated C2)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/tralalero"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000002; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-03, reference https://the-hunters-ledger.com/hunting-detections/evilsoul-engine-stealer-maas-detections/;)
```

### EvilSoul-Engine Discord Webhook Exfiltration — Primary Sink (Maploot/Tinarox)

**Detection Priority:** MEDIUM
**Rationale:** Maploot and Tinarox share a confirmed, byte-for-byte identical primary Discord webhook ID for loot exfiltration (Discord token/billing/browser data zips). Anchoring on the specific webhook ID rather than the generic `discord.com/api/webhooks/` path avoids over-matching legitimate Discord-integrated applications.
**ATT&CK Coverage:** T1041 (Exfiltration Over C2 Channel)
**Confidence:** HIGH
**False Positive Risk:** LOW — the webhook ID is a 19-digit operator-specific Discord snowflake; collision with an unrelated legitimate webhook is effectively impossible.
**Deployment:** Network IDS/IPS at network egress.

```
alert http $HOME_NET any -> any any (msg:"THL EvilSoul-Engine Discord Webhook Exfiltration POST Primary Sink (Maploot/Tinarox)"; flow:established,to_server; http.host; content:"discord.com"; nocase; http.uri; content:"/api/webhooks/1391195207508295750"; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000003; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-03, reference https://the-hunters-ledger.com/hunting-detections/evilsoul-engine-stealer-maas-detections/;)
```

### EvilSoul-Engine Discord Webhook Exfiltration — Secondary Sink (Maploot/Tinarox)

**Detection Priority:** MEDIUM
**Rationale:** Companion rule for the secondary Discord webhook ID, dynamic-memory-resolved from Maploot and independently confirmed shared with Tinarox after webcrack de-obfuscation.
**ATT&CK Coverage:** T1041 (Exfiltration Over C2 Channel)
**Confidence:** HIGH
**False Positive Risk:** LOW — same rationale as the primary sink rule; webhook ID is operator-specific.
**Deployment:** Network IDS/IPS at network egress.

```
alert http $HOME_NET any -> any any (msg:"THL EvilSoul-Engine Discord Webhook Exfiltration POST Secondary Sink (Maploot/Tinarox)"; flow:established,to_server; http.host; content:"discord.com"; nocase; http.uri; content:"/api/webhooks/1401355074235793458"; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000004; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-03, reference https://the-hunters-ledger.com/hunting-detections/evilsoul-engine-stealer-maas-detections/;)
```

### EvilSoul-Engine Operator ngrok Tunnel Panel-Delivery Endpoint

**Detection Priority:** LOW
**Rationale:** Maploot and Tinarox share an un-rotated ngrok tunnel subdomain (`acf02ac96211.ngrok-free.app`) used for panel/build delivery. The specific subdomain is operator-unique even though `ngrok-free.app` itself is a shared legitimate tunneling service.
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer)
**Confidence:** MODERATE
**False Positive Risk:** MEDIUM — ngrok is a widely used legitimate tunneling service; this rule anchors on the specific operator subdomain to minimize FP, but any future subdomain rotation by the operator will require a rule update. Not durable as a long-term standalone indicator.
**Deployment:** Network IDS/IPS at network egress; treat as a time-boxed indicator requiring periodic review.

```
alert http $HOME_NET any -> any any (msg:"THL EvilSoul-Engine Operator ngrok Tunnel Panel-Delivery Endpoint (acf02ac96211)"; flow:established,to_server; http.host; content:"acf02ac96211.ngrok-free.app"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000005; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-03, reference https://the-hunters-ledger.com/hunting-detections/evilsoul-engine-stealer-maas-detections/;)
```

---

## Coverage Gaps

**gofile.io loot-upload sink — no dedicated rule.** The malware-analyst findings document `store8.gofile.io/uploadFile` and `api.gofile.io/servers` as an exfil path for Maploot/Tinarox/299a2e7f loot zips, explicitly flagged in the IOC feed as `false_positive_risk: HIGH — gofile.io is a shared legitimate file-hosting service`. No YARA/Sigma/Suricata rule was written against this endpoint alone because a domain-only match on a shared public file host would generate unacceptable noise. **What would raise confidence:** a captured multipart-upload request signature (specific field names, User-Agent, or file-naming convention used by the EvilSoul-Engine uploader) that could anchor a Suricata rule on upload *behavior* rather than the destination domain alone.

**`evilsoul.xyz` backend endpoint paths (`/dcinjection-send`, `/upload-txts`, `/download/panel`, `/download/decrypter/<ver>`) — not independently ruled.** These are documented in `detection_handoff` as network patterns but the domain itself (`evilsoul.xyz`) is already covered by the validated DNS rule above (`evilsoul.` prefix match), and a dedicated HTTP-path rule would duplicate that coverage without adding independent detection value given the domain-level DNS rule already fires earlier in the connection sequence. No additional rule was written to avoid redundant, unvalidatable HTTP-keyword rules beyond the five already documented.

**`x4m1k.com` / `pay.x4m1k.com` operator control-plane domains — not ruled.** These are attribution/infrastructure indicators (0xK41 Panel front, MaaS sales page) documented in the IOC feed but not present in `detection_handoff.by_family.EvilSoul-Engine`'s network_patterns list, meaning no specific malware-to-domain connection behavior was observed and documented by malware-analyst for this campaign's recovered samples. **What would raise confidence:** dynamic detonation evidence of a recovered build actually beaconing to `x4m1k.com`, rather than the domain's role being limited to the operator's sales/control front.

**Unrecovered `static/*.exe` builder outputs (4 hashes: `sv2.exe`, `snew.exe`, `sfix.exe`, `tpkg.exe`) — hash-only, no behavioral rule possible.** These builder outputs were never obtained for static or dynamic analysis (hash-only IOCs at MODERATE confidence in the IOC feed). No YARA byte-pattern or Sigma behavioral rule can be constructed without recovered content. **What would raise confidence:** obtaining a sample of any of these four builds for static/dynamic analysis.

**299a2e7f Socket.IO payload framing — not covered by a network-content Suricata rule beyond the handshake.** The malware-analyst findings note the Socket.IO event-driven command protocol (`screenData`, `downloadExe`, destructive commands) was recovered from process memory but "decode of the 299a2e7f Socket.IO payload framing" is listed as further analysis that would raise confidence. Without the wire-level event-name framing, a Suricata rule matching on in-session Socket.IO event content (as opposed to the initial handshake, which is covered) could not be constructed with current evidence.

**Whole-Drive Defender exclusion Sigma rule (ps_script category) FP tuning.** The rule is written at MEDIUM-tunable FP risk because legitimate whole-drive exclusion scripts, while uncommon, do exist in some enterprise imaging/migration workflows. No further narrowing was possible without additional context (e.g., a specific parent-process or user-context constraint) that malware-analyst's findings did not capture for this behavior.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
