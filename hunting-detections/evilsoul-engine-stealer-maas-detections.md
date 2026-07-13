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

EvilSoul-Engine is a Node/Electron stealer-builder MaaS kit distributed under multiple product tiers and rebuilt per customer; the durable detection surface is the kit's own compiled constants and behavioral chokepoints, not any single build's hash or its disposable network infrastructure.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 4 | 1 | T1027, T1588.002, T1555.003, T1539, T1071.001, T1105, T1055.012, T1620 | 0 |
| Sigma | 4 | 2 | T1185, T1539, T1003.001, T1685, T1053.005, T1036.004, T1105, T1555.003, T1564.001 | 0 |
| Suricata | 1 | 0 | T1071.001, T1041 | 5 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchors:**
- The obfuscator XOR key literal and catchphrase comment, embedded in every build's loader stage — survives js-confuser repacking because the loader invokes the obfuscated payload rather than being obfuscated itself (YARA Detection).
- The Maploot/Tinarox Discord-embed exfil titles, confirmed byte-for-byte identical across both Electron "twin" builds after de-obfuscation (YARA Detection).
- The `/tralalero` webhook-resolution relay URI — re-anchored off the single relay IP during this review so it now survives relay-infrastructure rotation (Suricata Detection).

**Atomics routed to the IOC feed:** the operator's disposable network layer — the `evilsoul.`-prefixed backend domains (`evilsoul.cc`, `evilsoul.xyz`), the Socket.IO C2 handshake host, both Discord webhook exfiltration sinks (Maploot/Tinarox primary + secondary), and the operator's ngrok panel-delivery subdomain — are transient indicators already carried in [`evilsoul-engine-stealer-maas-iocs.json`](/ioc-feeds/evilsoul-engine-stealer-maas-iocs.json) rather than as standalone signatures (removing each literal leaves no independent behavior to detect). Block them via the feed; only the `/tralalero` relay-URI pattern (Suricata Detection rule below) survives as a durable, host-independent network signature.

**Detection philosophy.** Every EvilSoul-Engine customer build is uniquely repacked at build time (js-confuser → AES-256-GCM → XOR → base64 → in-memory exec), so hash-based detection has LOW durability against new builds. The durable, build-independent signals are: the operator-signature XOR constant (survives js-confuser because it lives in the loader, not the packed payload), the Maploot/Tinarox Discord-embed exfil titles (shared across both Electron twins), the CDP browser-relaunch cookie-theft pattern, the LSASS-impersonation Python stdin decryptor, and the Microsoft-masquerade hidden scheduled task. The campaign's disposable domains, webhook IDs, and tunnel subdomains do not meet the durability bar for standalone network signatures and are tracked in the IOC feed instead. Deploy YARA string rules against source/staged JS and unpacked Electron `app.asar` archives; deploy Sigma rules for runtime behavioral detection that holds regardless of the specific build variant.

**Suricata validation note.** The single remaining Suricata Detection rule below was re-anchored during this review (its destination-IP pin was removed in favor of the durable `/tralalero` URI content). Validation status against the real `suricata -T` engine is recorded at the end of this backfill pass — see the rule's own metadata block for the result.

---

## YARA Rules

### Detection Rules

#### EvilSoul-Engine Obfuscator XOR Key and Catchphrase

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1027 (Obfuscated Files or Information), T1588.002 (Obtain Capabilities: Tool)
**Confidence:** HIGH
**Rationale:** The obfuscator's XOR key literal `see-you-in-the-hellwizard-1082@239$328927bA` and catchphrase comment live in the loader stage, which every EvilSoul-Engine build carries pre-packing. They survive the js-confuser layer because the loader is what invokes the obfuscated payload, not what gets obfuscated itself — an operator would have to modify the obfuscator's own source to evade, not just repack a build. Combined with the split-domain anti-grep pattern (Hunting rule below), this is the single most durable EvilSoul-Engine anchor across all product tiers (`stealer.js`, `299a2e7f`, Maploot, Tinarox).
**False Positives:** None known — the XOR key string is a 44-character operator-chosen literal with zero plausible legitimate-software collision; the catchphrase comment is similarly distinctive.
**Blind Spots:** A rewrite of the obfuscator itself (new XOR key, new catchphrase) evades this rule; memory-only variants that never touch disk need the memory-scan deployment path.
**Validation:** Scan a recovered EvilSoul-Engine loader stage (e.g. `hash1` below) — the XOR key or the catchphrase-plus-secondary-anchor combination must match; a benign obfuscated JS bundle from an unrelated project must NOT fire.
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
```

**File name:** `mal_evilsoul_engine_kit_wide.yar`

---

#### EvilSoul-Engine Maploot/Tinarox Discord-Embed Exfil Titles

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1555.003 (Credentials from Web Browsers), T1539 (Steal Web Session Cookie)
**Confidence:** HIGH
**Rationale:** The Maploot/Tinarox embed-title strings are the literal text sent to the operator's Discord webhook as embed titles for each exfil category (Discord tokens, browser data, Exodus wallet, Steam session, Minecraft session). Independently confirmed byte-for-byte identical between the two "twin" builds after de-obfuscation, meaning they are compiled into the product line's source rather than randomized per build — an operator would have to rebrand the entire product line to evade.
**False Positives:** LOW — "EvilSoul Stealer -" is a distinctive branded string with no legitimate-software collision risk.
**Blind Spots:** A full rebrand of the Electron product line (new embed titles, new masquerade name) evades this rule; targets on-disk `app.asar` archives, not memory-only variants.
**Validation:** Scan a Maploot or Tinarox `app.asar`/`resources/app` extraction — 2 of the embed-title strings, or 1 plus the masquerade/endpoint context, must match; a legitimate Electron game or utility must NOT fire.
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

#### EvilSoul-Engine 299a2e7f Socket.IO WebPanel Build

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols — C2), T1105 (Ingress Tool Transfer)
**Confidence:** HIGH
**Rationale:** The args-file suffix `evilsoulblockkstarjkjaksghjhsjkahjskjak81929ijsahsjkj` is a deliberately long, high-entropy operator-chosen string hardcoded into the 299a2e7f build's argument-passing convention — near-zero collision risk and present in every build sharing this codebase. The condition was tightened during this review: the originally-published rule let the webhook-relay IP:port string (`198.1.195.210:3000/tralalero`) trigger the rule on its own, which is an IP-anchored atomic that would break on relay-infrastructure rotation and fails durability (Gate 1) as a standalone trigger. It now only counts as one member of the multi-string combination requirement, so the rule can never fire on the bare IP literal alone.
**False Positives:** LOW — the args-file suffix is a long, operator-unique, non-dictionary token; the panel/handle/relay/fallback-key/update-cmd combination requires 2 independent matches.
**Blind Spots:** A rebuild that changes the args-file suffix convention evades the primary anchor; the secondary combination would need 2 of 5 members renamed simultaneously to fully evade.
**Validation:** Scan a 299a2e7f pkg-Node build or its runtime memory — the args-file suffix, or 2 of the secondary combination, must match; an unrelated Node.js single-EXE application must NOT fire.
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
      description = "Detects the EvilSoul-Engine 299a2e7f Socket.IO WebPanel RAT build via its distinctive args-file suffix, WebPanel embed title, and webhook-resolution relay endpoint string, all recovered from the build's runtime memory; the relay IP:port string is required in combination with another anchor rather than as a standalone trigger so the rule does not fire on the IP literal alone"
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
      ($argsfile or 2 of ($panel, $handle, $relay, $fallback_key, $update_cmd))
}
```

**File name:** `mal_evilsoul_engine_299a2e7f.yar`

---

#### xaitax ChromElevator ABE-Bypass Tool — @breakingupslow Fork

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1555.003 (Credentials from Web Browsers), T1539 (Steal Web Session Cookie), T1055.012 (Process Hollowing), T1620 (Reflective Code Loading)
**Confidence:** HIGH
**Rationale:** The `chromelevator.exe` + `chrome_decrypt.dll` pair is a public red-team tool (xaitax "Chrome-App-Bound-Encryption-Decryption") adopted by the EvilSoul-Engine operator as a supply-chain component rather than authored in-house. The rule anchors on the operator-fork banner and copyright strings unique to the `@breakingupslow`-attributed build — not the tool's stock upstream strings — so it stays precise to this fork's redistributions (by this operator or any other actor redistributing the same fork) without over-matching every public xaitax fork in the wild.
**False Positives:** LOW — the co-credit banner and copyright-notice strings are specific to this fork; generic ABE-tool detection is intentionally avoided by anchoring on the fork attribution text rather than the underlying decryption logic (public prior art that would over-match on every xaitax fork).
**Blind Spots:** A rebuild that strips the banner/copyright strings (reverting to stock xaitax or a differently-attributed fork) evades this specific rule; targets the on-disk EXE/DLL pair, not memory-only injection artifacts beyond what the combination strings capture.
**Validation:** Scan the analyzed `chromelevator.exe`/`chrome_decrypt.dll` pair — the banner or copyright string, or 2 of the hollowing/pipe/key/GCM/resource combination, must match; the stock upstream xaitax build without fork attribution must NOT fire.
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

### Hunting Rules

#### EvilSoul-Engine Split-Domain Anti-Grep Pattern

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1027 (Obfuscated Files or Information)
**Confidence:** HIGH (string match) / durability LOW (tied to one domain)
**Rationale:** All four string variants anchor on the same split fragments of one domain — `evilsoul.xyz`, broken as `'evilso'+'ul.xyz'` to defeat a plaintext grep for the domain. This is real evasion tradecraft (T1027) and the domain is already a BLOCK-listed IOC, but the rule's entire discriminating power is that one domain's substrings: an operator rotating to a new backend domain breaks this rule immediately, and no independent behavioral signal survives removing the literal. Durability, not current precision, governs the tier.
**False Positives:** None known against current samples — the split fragments are distinctive to `evilsoul.xyz`. The rule's value is in catching *obfuscated* occurrences of the domain in source that a plaintext string search would miss, not in surviving a domain rotation.
**Deployment:** Endpoint file scan on staged/dropped JS and Electron `app.asar` archives; static triage of suspected EvilSoul-Engine builds where a plaintext grep for `evilsoul.xyz` has already come back negative.

```yara
/*
   Yara Rule Set
   Identifier: EvilSoul-Engine Stealer-Builder MaaS - Kit-Wide Obfuscator Anchors
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

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

## Sigma Rules

### Detection Rules

#### Browser Relaunched with CDP Debugging by Non-Browser Parent

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1185 (Browser Session Hijacking), T1539 (Steal Web Session Cookie)
**Confidence:** HIGH
**Rationale:** Both the EvilSoul-Engine stealer payload and the xaitax ABE-bypass tools relaunch the victim's own installed browser headless with Chrome DevTools Protocol debugging enabled, then pull already-decrypted cookies via `Network.getAllCookies` — defeating Chrome's App-Bound Encryption without administrator rights. Requiring all three flags (`--remote-debugging-port`, `--headless`, `--user-data-dir`) together, while excluding both browser-self-relaunch and known dev-tooling parents, is a technique-level chokepoint: the capability cannot be achieved via CDP without this flag combination, regardless of the specific EvilSoul-Engine build variant.
**False Positives:** Legitimate browser automation frameworks (Selenium, Puppeteer, Playwright) launched from an unlisted parent process; QA/CI pipelines that headlessly drive a browser for testing from a non-standard automation harness.
**Blind Spots:** Misses CDP-based cookie theft that omits `--user-data-dir` (uses the default profile instead), or that spawns from an allow-listed parent process name the attacker has spoofed.
**Validation:** Launch a browser with all three flags from an unrelated parent (e.g. a script host) — must alert; the same flags launched by `node.exe` running a known test harness must NOT fire (filtered).
**Deployment:** EDR process-creation monitoring, SIEM correlation on Sysmon Event ID 1 / Event ID 3.

```yaml
title: Browser Relaunched with Remote Debugging and Headless Flags by Non-Browser Parent
id: b788a75b-a966-47d5-b91b-5fb92b2e9571
status: experimental
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
date: '2026-07-03'
tags:
    - attack.credential-access
    - attack.t1539
    - attack.collection
    - attack.t1185
    - detection.emerging-threats
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

#### Python Process Opens LSASS Handle (ABE Decryptor Pattern)

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1003.001 (LSASS Memory), T1539 (Steal Web Session Cookie)
**Confidence:** HIGH
**Rationale:** The `stealer.js` build's most advanced credential-theft component downloads a portable Python interpreter, pipes a decryptor script over stdin (never touching disk as a `.py` file), enables `SeDebugPrivilege`, and impersonates the `lsass.exe` process token to decrypt the Chrome App-Bound-Encryption key via Windows CNG. The rule matches on the process-access relationship alone (a Python-hosted process opening an LSASS handle), which is durable regardless of how the decryptor script reaches the interpreter — legitimate Python tooling rarely has any reason to touch LSASS. **Corrected during this review:** the originally-published title and description claimed to detect the `-u -` stdin-execution flag combination, but the `detection:` block never inspects the launch command line — only the process-access relationship. The description below has been rewritten to match the actual logic.
**False Positives:** EDR or security-research tooling written in Python that legitimately inspects LSASS; authorized credential-recovery or forensic tooling in incident-response workflows.
**Blind Spots:** Misses the technique entirely if reimplemented in a compiled language rather than Python, or if the LSASS access is proxied through a legitimate signed binary rather than a direct Python-to-LSASS handle.
**Validation:** Trigger a Python process opening a handle to `lsass.exe` — must alert; unrelated `python.exe` activity with no LSASS access must NOT fire.
**Deployment:** EDR process-creation + process-access correlation, SIEM correlation on Sysmon Event ID 1 + Event ID 10.

```yaml
title: Python Process Opens LSASS Handle (ABE Decryptor Pattern)
id: e2ccff6f-eec8-4a34-a78e-4ac4bf5d50f3
status: experimental
description: >-
  Detects a python.exe or pythonw.exe process that opens a handle to lsass.exe.
  This is the process-access signature of the EvilSoul-Engine stealer.js build's
  LSASS-impersonation App-Bound-Encryption decryptor, which is launched with a
  stdin-piped script (-u - flag, no script file argument) and enables
  SeDebugPrivilege to impersonate the lsass.exe token and decrypt Chrome's
  app-bound key via Windows CNG, leaving no decryptor script on disk. This rule
  matches on the LSASS handle-access behavior alone; it does not inspect the
  parent process's launch flags.
references:
    - https://the-hunters-ledger.com/hunting-detections/evilsoul-engine-stealer-maas-detections/
author: The Hunters Ledger
date: '2026-07-03'
tags:
    - attack.credential-access
    - attack.t1003.001
    - attack.t1539
    - detection.emerging-threats
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

#### Whole-Drive Defender Exclusion Combined with Real-Time Monitoring Disable

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1685 (Disable or Modify Tools)
**Confidence:** HIGH
**Rationale:** The `299a2e7f` build's `DisableProtections` function whole-drive-excludes `C:\` from Windows Defender and disables real-time monitoring via PowerShell cmdlets in the same script block. A whole-drive exclusion path (`C:\` specifically) combined with a real-time-monitoring disable in the same execution context is a strong, technique-level chokepoint — legitimate software almost never excludes an entire drive letter, and an attacker achieving the same suppression via PowerShell has no alternate cmdlet pairing that avoids both signals simultaneously. **Corrected during this review:** the originally-published markdown metadata cited the legacy technique ID `T1562.001 (Impair Defenses: Disable or Modify Tools)`, but the ATT&CK data used by `sigma check` has this technique renumbered to `T1685 (Disable or Modify Tools)`; the YAML tag `attack.t1685` was already correct, so the markdown label has been updated to match rather than the tag — a live-validator lesson in not hand-correcting a tag against a hardcoded assumption.
**False Positives:** IT-administration deployment scripts that legitimately exclude `C:\` during imaging or migration (uncommon but not impossible).
**Blind Spots:** Misses the same suppression achieved via the Windows Security Center API, a registry policy write, or a compiled binary rather than a PowerShell script block; requires Script Block Logging (Event ID 4104) to be enabled.
**Validation:** Run a PowerShell script block containing both cmdlet patterns — must alert; a script excluding only a narrow application directory must NOT fire.
**Deployment:** SIEM correlation on PowerShell Script Block Logging (Windows Event ID 4104).

```yaml
title: Whole-Drive Windows Defender Exclusion Combined with Real-Time Monitoring Disable
id: fde077ad-0afc-4158-bff6-f4c80604d461
status: experimental
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
date: '2026-07-03'
tags:
    - attack.stealth
    - attack.t1685
    - attack.defense-impairment
    - detection.emerging-threats
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

#### Scheduled Task Created with Microsoft Corporation Author and Hidden Flag

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1053.005 (Scheduled Task), T1036.004 (Masquerade Task or Service)
**Confidence:** HIGH
**Rationale:** The `stealer.js` build's persistence mechanism registers a scheduled task with Task XML `Author` set to the literal string `Microsoft Corporation` while also setting the hidden flag — a masquerade pattern designed to blend into Task Scheduler listings alongside genuine Microsoft-authored tasks. Genuine Microsoft tasks are installed by the OS image or Windows Update, not created ad hoc at runtime by a user-context process, which is what makes any Event ID 4698 registration carrying this exact Author string a near-certain fake regardless of the specific payload delivered.
**False Positives:** Unlikely — genuine Microsoft Corporation-authored tasks are pre-installed by the OS, not created via runtime Event ID 4698 registration by a user-context process.
**Blind Spots:** Misses persistence that spoofs a different vendor's authorship string, or that skips the hidden flag; requires Task Scheduler/Security auditing of object creation (Event ID 4698) with TaskContent captured.
**Validation:** Register a scheduled task with `<Author>Microsoft Corporation</Author>` and `<Hidden>true</Hidden>` — must alert; a genuine OS-installed Microsoft task (which is not created via this runtime event) must NOT fire.
**Deployment:** SIEM correlation on Windows Event ID 4698 (Scheduled Task Created).

```yaml
title: Scheduled Task Created with Microsoft Corporation Author and Hidden Flag
id: c69291c1-70a6-4aa1-835f-bc26d4afcc2f
status: experimental
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
date: '2026-07-03'
tags:
    - attack.persistence
    - attack.execution
    - attack.privilege-escalation
    - attack.t1053.005
    - attack.stealth
    - attack.t1036.004
    - detection.emerging-threats
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
    - Unlikely — genuine Microsoft Corporation-authored tasks are pre-installed by the OS, not created via runtime Event ID 4698 registration by a user-context process
level: high
```

**File name:** `win_security_evilsoul_engine_hidden_scheduled_task_masquerade.yml`

### Hunting Rules

#### ChromElevator ABE-Bypass Tool Dropped to TEMP Executor Directory

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer), T1555.003 (Credentials from Web Browsers)
**Confidence:** HIGH (string match) / durability LOW (renameable filenames + directory)
**Rationale:** The `299a2e7f` build downloads the xaitax ChromElevator ABE-bypass tool pair from a GitHub-hosted supply-chain mirror to a consistent staging path, `%TEMP%\executor\`. Both the filenames and the staging directory are download-script conventions the operator (or any other actor redistributing the same public tool) could trivially rename — durability, not today's low FP rate, governs the tier. **Corrected during this review:** demoted from the originally-published `level: high` to `medium` to match the Hunting tier.
**False Positives:** Extremely unlikely against current samples — `chromelevator.exe` and `chrome_decrypt.dll` are not legitimate Windows or common third-party software filenames; the `%TEMP%\executor\` directory name is also distinctive. Any operator or actor who renames the download destination evades entirely.
**Deployment:** EDR file-creation monitoring, SIEM correlation on Sysmon Event ID 11; use as a scoping lead for the broader ABE-bypass supply-chain pattern rather than a standalone alert.

```yaml
title: ChromElevator ABE-Bypass Tool Dropped to TEMP Executor Directory
id: 2d54e3fa-a90b-4709-9521-b7a4ab95e76a
status: experimental
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
date: '2026-07-03'
tags:
    - attack.command-and-control
    - attack.t1105
    - attack.credential-access
    - attack.t1555.003
    - detection.emerging-threats
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
level: medium
```

**File name:** `file_event_win_evilsoul_engine_abe_tool_drop.yml`

---

#### EvilSoul-Engine Watchdog Persistence Files Created in TEMP or Startup

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1564.001 (Hidden Files and Directories), T1053.005 (Scheduled Task)
**Confidence:** MODERATE
**Rationale:** The `299a2e7f` build layers redundant "persistence-of-persistence": a `update.bat` in the Startup folder plus a hidden random-named `.lnk`, a hidden `updatesystem.cmd`, and a `watcher.vbs` watchdog in `%TEMP%`, subsequently attribute-flagged hidden. These are plausible-sounding, genuinely generic filenames (unlike the bespoke component names elsewhere in this campaign) that a legitimate update script could coincidentally share — moderate FP risk was already acknowledged at publication and the tier reflects that.
**False Positives:** Legitimate software update scripts that happen to share these generic filenames outside protected system directories; custom internal IT automation using similarly named watchdog scripts.
**Deployment:** SIEM correlation on Sysmon Event ID 11 (FileCreate) filtered to the named artifacts; correlate with the Defender-suppression or CDP-cookie-theft Detection rules above for higher-confidence triage.

```yaml
title: EvilSoul-Engine Watchdog Persistence Files Created in TEMP or Startup
id: 5f925688-77fd-410a-9c8a-83ca801a5013
status: experimental
description: >-
  Detects file creation of the specific watchdog and persistence-chain
  filenames used by the EvilSoul-Engine 299a2e7f build's redundant
  persistence-of-persistence mechanism, including updatesystem.cmd,
  watcher.vbs, and update.bat, which are subsequently attribute-flagged
  hidden to survive casual folder inspection.
references:
    - https://the-hunters-ledger.com/hunting-detections/evilsoul-engine-stealer-maas-detections/
author: The Hunters Ledger
date: '2026-07-03'
tags:
    - attack.stealth
    - attack.t1564.001
    - attack.persistence
    - attack.execution
    - attack.privilege-escalation
    - attack.t1053.005
    - detection.emerging-threats
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

### Detection Rules

#### EvilSoul-Engine Webhook-Resolution Relay POST /tralalero

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1041 (Exfiltration Over C2 Channel)
**Confidence:** HIGH
**Rationale:** The `299a2e7f` build hardcodes no Discord webhook directly — instead it POSTs `{key: <licenseKey>}` to a relay and receives the actual webhook URL back at runtime. `/tralalero` is a distinctive, non-dictionary URI path with no legitimate-traffic collision risk. **Corrected during this review:** the originally-published rule pinned the destination to the single relay IP (`198.1.195.210`), which is an atomic that breaks the moment the operator moves the relay; the destination has been loosened to `$EXTERNAL_NET` so the rule survives relay-IP rotation while still keying on the durable URI content. `rev` bumped to 2 to reflect the change.
**False Positives:** None known — `/tralalero` combined with an HTTP POST method is not a pattern seen in legitimate web traffic.
**Blind Spots:** Misses the relay entirely if the operator changes the URI convention in a future build; does not by itself confirm which license key or webhook was resolved (see the IOC feed for the specific relay IP and license-key values).
**Validation:** Replay a POST request to any host with `/tralalero` in the URI — must alert; unrelated POST traffic to the same or a different host without that URI must NOT fire.
**Deployment:** Network IDS/IPS at network egress.

```
alert http $HOME_NET any -> any any (msg:"THL EvilSoul-Engine Webhook-Resolution Relay POST /tralalero (299a2e7f License-Gated C2)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/tralalero"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000002; rev:2; metadata:author The_Hunters_Ledger, date 2026-07-03, reference https://the-hunters-ledger.com/hunting-detections/evilsoul-engine-stealer-maas-detections/;)
```

---

## Coverage Gaps

**Atomics routed to the IOC feed (5 of the original file's 6 Suricata rules).** The DNS-query rule (`evilsoul.` prefix), the Socket.IO C2 handshake rule (host `evilsoul.cc` plus the generic Socket.IO v4 polling URI — a pattern shared by any Socket.IO application and made precise only by the domain), and both Discord webhook-exfiltration rules (each keyed on a single 19-digit webhook snowflake ID) and the ngrok tunnel rule (a single operator subdomain) each keyed solely on one hardcoded domain, host, or webhook-ID literal with no independent behavioral qualifier surviving its removal — per the tiering rubric's routing test, these are IOC-feed entries, not rules. All underlying values (`evilsoul.cc`, `evilsoul.xyz`, both Discord webhook IDs, the ngrok subdomain) were already present in [`evilsoul-engine-stealer-maas-iocs.json`](/ioc-feeds/evilsoul-engine-stealer-maas-iocs.json) from the original analysis — no feed edits were required. Only the webhook-resolution relay rule (`/tralalero`) survived as a Detection-grade Suricata signature, after its destination-IP pin was loosened to `$EXTERNAL_NET` in favor of the distinctive URI content.

**YARA 299a2e7f rule condition tightened during re-tiering.** The originally-published rule allowed the webhook-relay IP:port string (`198.1.195.210:3000/tralalero`) to trigger the rule standalone — an IP-anchored atomic with no durability against relay-infrastructure rotation. It has been folded into the rule's multi-string combination requirement so it can no longer fire on the bare IP literal alone; the underlying IP is separately tracked in the IOC feed.

**Split-domain anti-grep YARA rule demoted to Hunting.** The rule's entire discriminating power is the `evilsoul.xyz` domain fragments; it provides real value catching obfuscated occurrences of the domain that a plaintext grep would miss, but does not survive a domain rotation and is not a standalone Detection-grade signal on its own.

**gofile.io loot-upload sink — no dedicated rule.** The malware-analyst findings document `store8.gofile.io/uploadFile` and `api.gofile.io/servers` as an exfil path for Maploot/Tinarox/299a2e7f loot zips, explicitly flagged in the IOC feed as `false_positive_risk: HIGH — gofile.io is a shared legitimate file-hosting service`. No YARA/Sigma/Suricata rule was written against this endpoint alone because a domain-only match on a shared public file host would generate unacceptable noise. **What would raise confidence:** a captured multipart-upload request signature (specific field names, User-Agent, or file-naming convention used by the EvilSoul-Engine uploader) that could anchor a Suricata rule on upload *behavior* rather than the destination domain alone.

**`evilsoul.xyz` backend endpoint paths (`/dcinjection-send`, `/upload-txts`, `/download/panel`, `/download/decrypter/<ver>`) — not independently ruled.** These are documented in `detection_handoff` as network patterns, but the domain itself (`evilsoul.xyz`) is already an atomic BLOCK entry in the IOC feed (see Atomics routed to the IOC feed above), and a dedicated HTTP-path rule would require a host/domain qualifier to stay precise — folding it back into the same durability problem the domain-based rules already failed. No additional rule was written; the specific paths remain available as feed-level context for HUNT-tier correlation.

**`x4m1k.com` / `pay.x4m1k.com` operator control-plane domains — not ruled.** These are attribution/infrastructure indicators (0xK41 Panel front, MaaS sales page) documented in the IOC feed but not present in `detection_handoff.by_family.EvilSoul-Engine`'s network_patterns list, meaning no specific malware-to-domain connection behavior was observed and documented by malware-analyst for this campaign's recovered samples. **What would raise confidence:** dynamic detonation evidence of a recovered build actually beaconing to `x4m1k.com`, rather than the domain's role being limited to the operator's sales/control front.

**Unrecovered `static/*.exe` builder outputs (4 hashes: `sv2.exe`, `snew.exe`, `sfix.exe`, `tpkg.exe`) — hash-only, no behavioral rule possible.** These builder outputs were never obtained for static or dynamic analysis (hash-only IOCs at MODERATE confidence in the IOC feed). No YARA byte-pattern or Sigma behavioral rule can be constructed without recovered content. **What would raise confidence:** obtaining a sample of any of these four builds for static/dynamic analysis.

**299a2e7f Socket.IO payload framing — not covered by a network-content Suricata rule.** The malware-analyst findings note the Socket.IO event-driven command protocol (`screenData`, `downloadExe`, destructive commands) was recovered from process memory, but the wire-level event-name framing was not decoded. The initial Socket.IO handshake itself is now feed-only (see Atomics routed to the IOC feed) rather than a standalone rule, since the polling-transport URI pattern is generic to any Socket.IO v4 application and only the `evilsoul.cc` host made it precise. Without the wire-level event-name framing, a Suricata rule matching on in-session Socket.IO event content — which would be durable independent of host — could not be constructed with current evidence.

**Whole-Drive Defender exclusion Sigma rule (ps_script category) FP tuning.** The rule is written at a tunable FP risk because legitimate whole-drive exclusion scripts, while uncommon, do exist in some enterprise imaging/migration workflows. No further narrowing was possible without additional context (e.g., a specific parent-process or user-context constraint) that malware-analyst's findings did not capture for this behavior.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
