---
title: 'Detection Rules - WebServer Compromise Kit'
date: '2026-02-08'
layout: post
permalink: /hunting-detections/webserver-compromise-kit-91-236-230-250-detections/
thumbnail: /assets/images/cards/webserver-compromise-kit-91-236-230-250.png
hide: true
---

**Campaign:** WebServer-Compromise-Kit-91.236.230.250
**Date:** 2026-02-08
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/webserver-compromise-kit-91-236-230-250/

---

## Detection Coverage Summary

This campaign is a manual, multi-stage web server intrusion: an ASP.NET reverse shell disguised as an image file (`a.png`, InsomniaShell-variant), abuse of the Windows Print Spooler RPC service for SYSTEM-level privilege escalation (PrintSpoofer), and a Go-based reverse SOCKS5 proxy for network pivoting (revsocks). All three post-exploitation tools are legitimate, publicly available offensive-security utilities repurposed for malicious use. Coverage below spans the dropped-file artifacts (YARA), the process and named-pipe behavior they generate on the host (Sigma), and the network traffic they produce (Suricata).

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 3 | 0 | T1505.003, T1134.001, T1090.001, T1071.004 | 0 |
| Sigma | 3 | 0 | T1505.003, T1134.001, T1090.001 | 1 |
| Suricata | 1 | 1 | T1095, T1071.001, T1090.001 | 1 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchors:**
- The Print Spooler RPC named-pipe impersonation pattern (`\pipe\spoolss` created by a non-`spoolsv.exe` process, paired with `ImpersonateNamedPipeClient` and token-duplication APIs) — a technique chokepoint shared by the entire "Potato"-family of SeImpersonate privilege-escalation tools, not just PrintSpoofer itself (YARA + Sigma Detection).
- The ASP.NET P/Invoke reverse-shell combination (raw `WS2_32.dll` socket calls plus `CreateProcess` I/O-handle redirection inside genuine ASP.NET codebehind context) — survives payload recompilation because it targets the technique rather than a single string (YARA Detection).

**Atomics routed to the IOC feed:** the C2 IP `91.236.230.250` is a transient indicator — it is already carried in [`webserver-compromise-kit-91-236-230-250-iocs.json`](/ioc-feeds/webserver-compromise-kit-91-236-230-250-iocs.json) (BLOCK action, HIGH confidence) rather than as a standalone network signature, since a pure IP-match rule with no content anchor detects nothing once the operator rotates hosting. Block it via the feed.

---

## YARA Rules

### Detection Rules

#### ASP.NET Reverse Shell (InsomniaShell P/Invoke Pattern)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1505.003 (Server Software Component: Web Shell)
**Confidence:** HIGH
**Rationale:** Corrected from the original: a parenthesization bug let either the bare `<%` ASP-tag byte or the bare `MZ` PE header alone satisfy the top-level condition, bypassing every string check and matching virtually any Windows executable. Reparenthesized so the header check gates the full behavioral clause. The surviving logic requires raw P/Invoke socket APIs (not the managed .NET `Socket` class ASP.NET normally uses) combined with `CreateProcess` I/O-handle redirection inside genuine ASP.NET codebehind context — a combination distinct from the great majority of managed-code webshells (e.g. China Chopper, ASPXSpy) that shell out via `Process.Start` alone.
**False Positives:** None known — legitimate ASP.NET applications essentially never combine raw `WS2_32.dll` P/Invoke socket calls with `CreateProcess` I/O-handle redirection; a rare legitimate remote-console or diagnostic web tool built the same way could theoretically match.
**Blind Spots:** A webshell using only managed sockets (no P/Invoke) or that spawns processes without I/O-handle redirection evades this rule; the rule targets the on-disk/source artifact, not memory-only variants.
**Validation:** Scan the analyzed sample (`hash1` below) — must match; a legitimate ASP.NET page using `Page_Load`/`CodeBehind=` alone (the overwhelming majority of ASP.NET files) must NOT fire.
**Deployment:** IIS webroot file scanning, email/upload-gateway attachment scanning, endpoint AV/EDR file scan.

```yara
/*
   Yara Rule Set
   Identifier: WebServer Compromise Kit - 91.236.230.250 Campaign
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule Webshell_ASPNET_InsomniaShell_Reverse {
   meta:
      description = "Detects ASP.NET reverse shells using raw P/Invoke socket APIs combined with CreateProcess I/O-handle redirection inside genuine ASP.NET codebehind context, the pattern used by the InsomniaShell-variant webshell disguised as a.png"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/webserver-compromise-kit-91-236-230-250-detections/"
      date = "2026-02-08"
      hash1 = "238a9850787c9336ec56114f346e39088ad63de1c6a1d7d798292a7fb4577738"
      hash2 = ""
      hash3 = ""
      family = "InsomniaShell"
      malware_type = "Web Shell"
      campaign = "WebServer-Compromise-Kit-91.236.230.250"
      id = "88bfb597-bc7f-5c4b-ad3c-404493d47786"
   strings:
      // P/Invoke signature for low-level networking
      $pinvoke_ws2 = "[DllImport(\"WS2_32.dll\"" ascii wide
      $pinvoke_kernel = "[DllImport(\"kernel32.dll\"" ascii wide

      // Socket connection APIs
      $api_wsasocket = "WSASocket" ascii wide
      $api_connect = "connect(" ascii wide

      // Process I/O redirection (hallmark of reverse shells)
      $api_createprocess = "CreateProcess" ascii wide nocase
      $io_redirect1 = "hStdInput" ascii wide
      $io_redirect2 = "hStdOutput" ascii wide
      $io_redirect3 = "hStdError" ascii wide

      // ASP.NET context
      $aspnet_page = "Page_Load" ascii wide
      $aspnet_codebehind = "CodeBehind=" ascii wide nocase

      // Common banner (optional but high confidence)
      $banner = "Spawn Shell" ascii wide nocase

   condition:
      (
         uint16(0) == 0x253C or // ASP tag
         uint16(0) == 0x4D5A    // compiled DLL
      ) and
      filesize < 100KB and
      (
         (
            ($pinvoke_ws2 or $pinvoke_kernel) and
            ($api_wsasocket or $api_connect) and
            $api_createprocess and
            2 of ($io_redirect*)
         ) or
         (
            $banner and
            2 of ($io_redirect*)
         )
      ) and
      (
         $aspnet_page or $aspnet_codebehind
      )
}
```

#### PrintSpoofer Privilege Escalation Tool (SeImpersonate Abuse)

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1134.001 (Access Token Manipulation: Token Impersonation/Theft)
**Confidence:** HIGH
**Rationale:** Two of the three matching clauses anchor on technique-level artifacts rather than the tool name — the compiled named-pipe format string (`\pipe\%ws\pipe\spoolss`) used to build the exploitation pipe path, and two-or-more Print Spooler RPC function calls (`RpcOpenPrinter`, `RpcRemoteFindFirstPrinterChangeNotification`, `NdrClientCall3`) combined with token-impersonation and process-creation-as-user APIs. Both survive a rename/recompile of the tool because they reflect the underlying exploitation mechanism — the "Potato"-family Print Spooler RPC named-pipe impersonation trick — not attacker-chosen strings.
**False Positives:** None known — the required API combination (`ImpersonateNamedPipeClient` plus `OpenThreadToken`/`DuplicateTokenEx` plus `CreateProcessAsUserW`/`CreateProcessWithTokenW`) paired with either the pipe format string or two-plus Print Spooler RPC calls is not observed in legitimate software.
**Blind Spots:** Covers this specific Print Spooler RPC exploitation chain; does not cover SeImpersonate-abuse variants that trigger a different service (e.g. BITS- or DCOM/OXID-resolver-based "Potato" variants) or that bypass all listed APIs via direct syscalls.
**Validation:** Scan the analyzed sample (`hash1` below) or any renamed/recompiled PrintSpoofer build — must match via the pipe-format or RPC-cluster clause even without the tool-name string present; a benign administrative tool using `ImpersonateNamedPipeClient` alone (e.g. a legitimate named-pipe server) must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, static triage of unknown binaries dropped to web-accessible or user-writable paths.

```yara
rule PrivEsc_PrintSpoofer_SeImpersonate {
   meta:
      description = "Detects PrintSpoofer and renamed/recompiled variants that abuse the Print Spooler RPC named-pipe impersonation trick for SeImpersonate-based privilege escalation to SYSTEM"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/webserver-compromise-kit-91-236-230-250-detections/"
      date = "2026-02-08"
      hash1 = "8524fbc0d73e711e69d60c64f1f1b7bef35c986705880643dd4d5e17779e586d"
      hash2 = "188098b9caf3bc4d1b68dcad50d2e1cbd2e9d519"
      hash3 = "108da75de148145b8f056ec0827f1665"
      family = "PrintSpoofer"
      malware_type = "Privilege Escalation Tool"
      campaign = "WebServer-Compromise-Kit-91.236.230.250"
      id = "3ce2dd4b-56b0-5fe0-bc09-e2886267f50f"
   strings:
      // Privilege string (unique identifier)
      $priv = "SeImpersonatePrivilege" ascii wide

      // Named pipe pattern (exploitation signature)
      $pipe_format = "\\\\pipe\\\\%ws\\\\pipe\\\\spoolss" ascii wide
      $pipe_spoolss = "\\pipe\\spoolss" ascii wide

      // Token manipulation APIs
      $api_impersonate = "ImpersonateNamedPipeClient" ascii wide
      $api_opentoken = "OpenThreadToken" ascii wide
      $api_duptoken = "DuplicateTokenEx" ascii wide

      // Process creation with stolen token
      $api_createasuser = "CreateProcessAsUserW" ascii wide
      $api_createwithtoken = "CreateProcessWithTokenW" ascii wide

      // RPC functions (triggers Print Spooler)
      $rpc1 = "RpcOpenPrinter" ascii wide nocase
      $rpc2 = "RpcRemoteFindFirstPrinterChangeNotification" ascii wide nocase
      $rpc3 = "NdrClientCall3" ascii wide

      // Tool-specific strings
      $tool_name = "PrintSpoofer" ascii wide nocase
      $author_tag = "@itm4n" ascii wide

      // Security descriptor for pipe (world-readable)
      $sddl = "D:(A;OICI;GA;;;WD)" ascii wide

   condition:
      uint16(0) == 0x5A4D and // MZ header
      filesize < 500KB and
      (
         // High confidence: Tool name + core APIs
         (
            ($tool_name or $author_tag) and
            $priv and
            $api_impersonate and
            ($api_createasuser or $api_createwithtoken)
         ) or
         // Alternative: Pipe pattern + token APIs (survives rename)
         (
            ($pipe_format or ($pipe_spoolss and $sddl)) and
            $api_impersonate and
            $api_opentoken and
            $api_duptoken and
            2 of ($api_create*)
         ) or
         // Alternative: Print Spooler RPC trigger + token APIs (survives rename)
         (
            2 of ($rpc*) and
            $api_impersonate and
            ($api_createasuser or $api_createwithtoken)
         )
      )
}
```

#### revsocks Reverse SOCKS5 Proxy (Go Binary)

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1090.001 (Proxy: Internal Proxy), T1071.004 (Application Layer Protocol: DNS — MODERATE, DNS-tunneling clause only)
**Confidence:** HIGH
**Rationale:** Tightened from the original: the Go build-path string alone (`github.com/kost/revsocks`) was a standalone top-level disjunct, so that single string could fire the rule with no corroborating signal, and a trailing `($go_path and $version)` clause was fully redundant dead logic (already implied by the bare disjunct). Folded into one paired `go_path + version-string` requirement and removed the redundant clause, so every remaining disjunct now requires two or more independent artifacts — import-path clustering, CLI flag combinations, the hardcoded anachronistic User-Agent, or DNS-tunneling flag pairs. The rule still fires on a recompiled or rebranded fork that keeps the underlying revsocks source (retains the vendored libraries and flag names) even if the attacker strips the literal repository path.
**False Positives:** None known — the specific combinations required (3+ vendored tunneling-library import paths plus 2+ CLI flags; or the anachronistic IE11/Win7 User-Agent plus `-connect` and a proxy/tunnel flag; or DNS-tunneling flag pairs) are not observed in unrelated Go software.
**Blind Spots:** A from-scratch reimplementation of the same reverse-SOCKS concept using different libraries, flag names, and no shared User-Agent default would evade; the 5-15MB file-size bound assumes standard Go static linking and could miss an unusually stripped or packed build.
**Validation:** Scan the analyzed sample (`hash1` below) — must match; a generic unrelated Go binary that happens to embed one individual library path without flag/User-Agent corroboration must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, static triage of large (5-15MB) unsigned Go binaries dropped to user-writable paths.

```yara
rule Proxy_Revsocks_Go_Binary {
   meta:
      description = "Detects revsocks reverse SOCKS5 proxy Go binaries and rebranded forks via combinations of vendored tunneling-library import paths, characteristic CLI flag sets, the hardcoded anachronistic IE11/Win7 User-Agent, and DNS-tunneling flag pairs"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/webserver-compromise-kit-91-236-230-250-detections/"
      date = "2026-02-08"
      hash1 = "ffc6662c5d68db31b5d468460e4bc3be2090d7ba3ee1e47dbe2803217bf424a9"
      hash2 = "c745d65554d946702f4484d47d6a4606c12c53e9"
      hash3 = "032300082d8bc63b3d0a7f3f3f83f5d1"
      family = "revsocks"
      malware_type = "Reverse Proxy Tool"
      campaign = "WebServer-Compromise-Kit-91.236.230.250"
      id = "4587f937-0830-5331-a15b-517c42b3f271"
   strings:
      // Go build path (high confidence identifier, paired with $version below)
      $go_path = "github.com/kost/revsocks" ascii wide

      // Imported tunneling libraries
      $lib_chashell = "github.com/kost/chashell" ascii wide
      $lib_dnstun = "github.com/kost/dnstun" ascii wide
      $lib_socks5 = "github.com/armon/go-socks5" ascii wide
      $lib_yamux = "github.com/hashicorp/yamux" ascii wide
      $lib_ntlm = "github.com/kost/go-ntlmssp" ascii wide
      $lib_websocket = "nhooyr.io/websocket" ascii wide

      // Command-line flags (usage patterns)
      $flag_connect = "-connect" ascii wide
      $flag_listen = "-listen" ascii wide
      $flag_socks = "-socks" ascii wide
      $flag_dns = "-dns" ascii wide
      $flag_ws = "-ws" ascii wide
      $flag_pass = "-pass" ascii wide

      // Characteristic User-Agent
      $ua_ie11 = "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko" ascii wide

      // DNS tunneling artifacts
      $dns_delay = "-dnsdelay" ascii wide
      $dns_type = "dnstype" ascii wide

      // Version string pattern
      $version = /main\.Version=\d+\.\d+/ ascii

   condition:
      uint16(0) == 0x5A4D and // MZ header
      filesize > 5MB and filesize < 15MB and // Go binaries are large
      (
         // Build-provenance identification (both artifacts required)
         ($go_path and $version) or
         // Library clustering (3+ libraries + 2+ flags = high confidence)
         (
            3 of ($lib_*) and
            2 of ($flag_*)
         ) or
         // User-Agent + flags (behavioral pattern)
         (
            $ua_ie11 and
            $flag_connect and
            ($flag_socks or $flag_dns or $flag_ws)
         ) or
         // DNS tunneling artifacts (dnstun-specific configuration flags)
         (
            $flag_dns and
            ($dns_delay or $dns_type)
         )
      )
}
```

---

## Sigma Rules

### Detection Rules

#### IIS Worker Process Spawns Interactive Shell

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1505.003 (Server Software Component: Web Shell)
**Confidence:** HIGH
**Rationale:** Anchors on process ancestry (`w3wp.exe` spawning an interpreter) rather than any campaign-specific literal, so it detects the technique regardless of which webshell payload is used or how it is recompiled. Recalibrated from the original `critical` to `high`: the false-positives list below documents a real, if rare, legitimate path (administrative scripts invoked through an IIS management interface), so the "never-FP" bar for `critical` is not met.
**False Positives:** Legitimate administrative scripts invoked through an IIS-hosted management interface; scheduled tasks or health-check scripts running under an IIS application-pool identity (rare in well-managed environments).
**Blind Spots:** Misses a webshell that never spawns a native shell/interpreter (e.g. one that only reads files or uses in-process .NET reflection); misses interpreters not in the listed set.
**Validation:** Trigger command execution through the analyzed webshell — must match; normal IIS request handling with no shell spawn must NOT fire.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (process-creation telemetry).

```yaml
title: IIS Worker Process Spawns Interactive Shell
id: c4e3d3c7-9f89-4d1a-8b2c-3e5a6f7d8e9f
status: experimental
description: >-
  Detects w3wp.exe (the IIS worker process) spawning a command or
  scripting interpreter, a strong indicator of an active web shell
  executing operator-supplied commands.
references:
    - https://the-hunters-ledger.com/hunting-detections/webserver-compromise-kit-91-236-230-250-detections/
    - https://the-hunters-ledger.com/reports/webserver-compromise-kit-91-236-230-250/
author: The Hunters Ledger
date: 2026-02-08
tags:
    - attack.persistence
    - attack.t1505.003
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\w3wp.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wscript.exe'
            - '\cscript.exe'
    condition: selection
falsepositives:
    - Legitimate administrative scripts invoked through an IIS-hosted management interface (verify with process command line)
    - Scheduled tasks or health-check scripts running under an IIS application-pool identity (rare)
level: high
```

#### Named Pipe Created Matching Print Spooler RPC Impersonation Pattern

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1134.001 (Access Token Manipulation: Token Impersonation/Theft)
**Confidence:** HIGH
**Rationale:** Anchors on the named-pipe naming convention created by the Print Spooler RPC impersonation trick, filtering out the one legitimate cause (the spooler service itself). Not specific to PrintSpoofer by name — fires on any "Potato"-family tool using the same RPC trigger. Recalibrated from the original `critical` to `high` for consistency with the site's level convention (reserving `critical` for the rare case where no plausible benign path exists at all).
**False Positives:** Unlikely — this is a highly specific pattern with no known legitimate cause outside the Print Spooler service itself, which is explicitly excluded by the filter.
**Blind Spots:** Covers only the `spoolss`-suffixed pipe convention; a privilege-escalation tool using a different trigger service or a renamed pipe with no `spoolss` suffix is not covered.
**Validation:** Trigger the exploitation chain — the non-spooler pipe-creation event must match; the legitimate Print Spooler service creating its own pipe must NOT fire.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (named-pipe telemetry, Sysmon Event ID 17).

```yaml
title: Named Pipe Created Matching Print Spooler RPC Impersonation Pattern
id: 3e096e9e-0f1a-4f5c-b7c3-2d4a55b3792f
status: experimental
description: >-
  Detects creation of a named pipe ending in 'spoolss' by a process
  other than the legitimate Print Spooler service, the named-pipe
  impersonation trigger used by PrintSpoofer and related "Potato"-family
  SeImpersonate privilege-escalation tools.
references:
    - https://github.com/itm4n/PrintSpoofer
    - https://the-hunters-ledger.com/hunting-detections/webserver-compromise-kit-91-236-230-250-detections/
author: The Hunters Ledger
date: 2026-02-08
tags:
    - attack.stealth
    - attack.privilege-escalation
    - attack.t1134.001
    - detection.emerging-threats
logsource:
    product: windows
    category: pipe_created
    definition: 'Requires Sysmon Event ID 17 (Pipe Created)'
detection:
    selection:
        PipeName|endswith: '\spoolss'
    filter:
        Image|endswith: '\spoolsv.exe'
    condition: selection and not filter
falsepositives:
    - >-
      Unlikely — this is a highly specific pattern with no known
      legitimate cause outside the Print Spooler service itself,
      which is explicitly excluded by the filter
level: high
```

#### Reverse SOCKS Proxy Execution via Revsocks Command-Line Flags

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1090.001 (Proxy: Internal Proxy)
**Confidence:** HIGH
**Rationale:** Requires two of revsocks' distinctive CLI flags to co-occur (`-connect` with `-socks`, or `-dns` with `-listen`) rather than matching on any single flag, which meaningfully narrows the match versus generic proxy/tunnel tooling that may share one flag name in isolation.
**False Positives:** Legitimate authorized red-team or offensive-security exercises using revsocks under change control.
**Blind Spots:** A build that renames its CLI flags evades this rule entirely; covers command-line-visible execution only, not a variant that reads its configuration from a file or environment variable.
**Validation:** Execute revsocks (or a build sharing its flag set) with either flag pair — must match; unrelated process command lines using only one of the flags in isolation must NOT fire.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (process-creation / command-line telemetry).

```yaml
title: Reverse SOCKS Proxy Execution via Revsocks Command-Line Flags
id: 58c6a530-eeea-47e4-98f6-c16d4911b54a
status: experimental
description: >-
  Detects execution of revsocks or a tool sharing its reverse-proxy
  command-line flag conventions, based on the co-occurrence of
  connect+socks or dns+listen flag pairs.
references:
    - https://github.com/kost/revsocks
    - https://the-hunters-ledger.com/hunting-detections/webserver-compromise-kit-91-236-230-250-detections/
author: The Hunters Ledger
date: 2026-02-08
tags:
    - attack.command-and-control
    - attack.t1090.001
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection_flags:
        CommandLine|contains|all:
            - '-connect'
            - '-socks'
    selection_dns:
        CommandLine|contains|all:
            - '-dns'
            - '-listen'
    condition: selection_flags or selection_dns
falsepositives:
    - Legitimate authorized red team or offensive-security exercises using revsocks under change control
    - Authorized offensive-security assessments (verify against the engagement's rules of engagement)
level: high
```

---

## Suricata Signatures

### Detection Rules

#### Reverse Shell "Spawn Shell" Banner

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1095 (Non-Application Layer Protocol)
**Confidence:** HIGH
**Rationale:** Anchors on the reverse shell's own greeting banner within the first 20 bytes of an established outbound TCP stream — payload content, not infrastructure, so the signature survives a C2 IP or hosting-provider change. No standard application-layer buffer exists for this bespoke raw-socket protocol, so a depth-bounded raw content match is the correct scoping for this specific channel rather than a generic flow-only check.
**False Positives:** None known — the literal phrase "Spawn Shell" within the first 20 bytes of an established outbound TCP session to an external host is not observed in standard client/server software, common libraries, or legitimate remote-administration tools.
**Blind Spots:** Evaded by a variant that removes or relocates the banner beyond the first 20 bytes, or that wraps the channel in TLS; detects session-establishment only, not subsequent command traffic.
**Validation:** Replay a capture of the reverse shell's initial handshake — must alert; unrelated benign TCP sessions to external hosts must NOT fire.
**Deployment:** Network IDS/IPS at perimeter and internal segmentation points.

```suricata
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"THL WebServer-Compromise-Kit ASP.NET Reverse Shell Spawn-Shell Banner (C2 Session Establishment)"; flow:to_server,established; content:"Spawn Shell"; depth:20; nocase; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000001; rev:2; metadata:author The_Hunters_Ledger, date 2026-02-08, reference https://the-hunters-ledger.com/hunting-detections/webserver-compromise-kit-91-236-230-250-detections/;)
```

### Hunting Rules

#### Anachronistic IE11/Win7 User-Agent (Possible revsocks)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1090.001 (Proxy: Internal Proxy)
**Confidence:** MODERATE
**Rationale:** Anchors on the exact hardcoded default User-Agent string compiled into revsocks (`Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko`) in the correct app-layer buffer (`http.user_agent`) — durable against C2 infrastructure rotation. This specific "generic old IE11" User-Agent string, however, is a widely reused default across many unrelated HTTP client libraries and tools, and genuine legacy Windows 7/IE11 traffic still occurs in some environments, so it does not clear the Detection bar for rare/no false positives on its own. The YARA rule above carries Detection-grade coverage for the same artifact because it requires the User-Agent in combination with revsocks-specific CLI flags.
**False Positives:** Genuine (if increasingly rare) traffic from actual Windows 7/IE11 endpoints, particularly in long-lifecycle industrial-control or medical-device network segments; other unrelated tools and HTTP libraries that reuse this same widely-known default browser-like User-Agent string.
**Deployment:** Network IDS/IPS at perimeter and internal segmentation points; correlate hits with the revsocks YARA/Sigma indicators above before treating as high-confidence.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL WebServer-Compromise-Kit Anachronistic IE11/Win7 User-Agent (Possible revsocks Proxy Traffic)"; flow:to_server,established; http.user_agent; content:"Windows NT 6.1|3b| Trident/7.0"; nocase; threshold:type limit,track by_src,count 5,seconds 300; classtype:policy-violation; sid:1000003; rev:2; metadata:author The_Hunters_Ledger, date 2026-02-08, reference https://the-hunters-ledger.com/hunting-detections/webserver-compromise-kit-91-236-230-250-detections/;)
```

---

## Coverage Gaps

**C2 IP address routed to the IOC feed, not a rule.** `91.236.230.250` was previously published as both a Sigma rule (matching `DestinationIp`) and a pure `alert ip ... -> 91.236.230.250 any` Suricata rule with no content anchor — a textbook atomic indicator (Gate 1: removing the hardcoded IP leaves no detection logic at all). It is already carried in [`webserver-compromise-kit-91-236-230-250-iocs.json`](/ioc-feeds/webserver-compromise-kit-91-236-230-250-iocs.json) (BLOCK action, HIGH confidence) — no feed changes were required. Block it at the network layer directly rather than via a standalone signature.

**Duplicate EDR/hunting-playbook content retired in favor of the equivalent rule above.** The original file's vendor-specific KQL hunting queries and manual PowerShell hunting-playbook scripts duplicated the behavioral logic already captured by the rules above and are removed here as non-portable, vendor-specific query/script syntax rather than left in the file as pseudo-rules:
- The web-shell parent-child KQL query and the "masquerading ASP.NET files" PowerShell hunt duplicate, respectively, the *IIS Worker Process Spawns Interactive Shell* Sigma rule and the *ASP.NET Reverse Shell* YARA rule.
- The PrintSpoofer named-pipe KQL query and the "enumerate named pipes" PowerShell hunt duplicate the *Named Pipe Created Matching Print Spooler RPC Impersonation Pattern* Sigma rule. The KQL query's additional join against an `ImpersonateNamedPipeClient` API-call event is EDR-vendor-specific telemetry with no standard Sysmon/Sigma equivalent, so that corroborating signal could not be carried forward as a portable rule.
- The large-Go-binary-execution KQL query duplicates the *Reverse SOCKS Proxy Execution* Sigma rule; its hash-match clause is already covered by the revsocks SHA256 already present in the IOC feed.
- The "suspicious outbound from IIS" KQL query and the "baseline IIS network behavior" PowerShell hunt describe a connection-count/unique-destination anomaly check that depends on an environment-specific allow-list of known-good destinations. This is inherently organization-specific tuning, not a portable Sigma selector — as written it would fire on ordinary legitimate outbound API/update traffic from any IIS server with no distinguishing filter, failing the precision bar even at Hunting tier. **What would enable a rule:** a distinctive network behavioral signature specific to this campaign's traffic (e.g. a fixed destination port or timing pattern unique to the revsocks/DNS-tunneling channel) rather than a generic volumetric anomaly.

**Response Actions and Forensic Artifacts sections removed.** The original file's incident-response and forensic-collection guidance (process-termination steps, credential-reset guidance, artifact-location tables) is organization-specific remediation content, out of scope for a third-party detection-rule file; no detection coverage was lost, since every artifact referenced (`a.png`, `PrintSpoofer.exe`, `rev.exe`, the relevant Sysmon Event IDs) is already covered by the rules above.

**DNS-tunneling and WebSocket C2 channel behaviors (T1071.004, MODERATE).** The underlying investigation records revsocks' DNS-tunneling and WebSocket-upgrade capabilities as MEDIUM-confidence network patterns, but no specific query structure, TXT/NULL record cadence, or WebSocket handshake artifact was captured precisely enough to build a standalone Suricata signature beyond the DNS-flag-pair clause already folded into the YARA rule above. **What would enable a rule:** a packet capture of the DNS-tunneling or WebSocket C2 channel in active use, to characterize the query pattern or handshake precisely.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
