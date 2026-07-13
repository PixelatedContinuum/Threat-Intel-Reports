---
title: "Detection Rules — Korean Claude Code Allowlist + OpenClaw Operator (221.150.15.104)"
date: '2026-05-27'
layout: post
permalink: /hunting-detections/korean-claude-openclaw-221.150.15.104-detections/
thumbnail: /assets/images/cards/korean-claude-openclaw-221.150.15.104.png
hide: true
---

**Campaign:** Korean-ClaudeCode-Allowlist-OpenClaw-221.150.15.104
**Date:** 2026-05-27
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/korean-claude-openclaw-221.150.15.104/

---

## Detection Coverage Summary

No malware binary exists in this campaign — the primary evidence is the operator's `~/.claude/settings.local.json` configuration artifact. Detection coverage targets two surfaces that retain analyst value after tiering: (1) the configuration-file artifact itself (YARA file-content matching) and (2) behavioral execution patterns generated when Claude Code — or a human operator — acts under the attacker-customized allowlist (Sigma process/file rules). The campaign's network indicators, the OpenClaw distribution/documentation domains and the operator's open-directory IP, are bare atomic matches with no surviving behavioral signal once the domain or IP literal is removed, so all three original Suricata signatures and one Sigma DNS rule route to the IOC feed instead of standing as rules.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 1 | 1 | T1562.001, T1059.004 | 0 |
| Sigma | 0 | 4 | T1562.001, T1059.004, T1059.007, T1090.001 | 1 |
| Suricata | 0 | 0 | — | 3 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchor:** the 3-of-7 OpenClaw-specific allowlist string combination (YARA Detection rule below) is the campaign's one Detection-tier rule — no known legitimate Claude Code workflow pre-approves the full curl|bash-installer-through-gateway-launch chain in a single `settings.local.json`, and the combination requirement makes single-string FP collision negligible.

**Atomics routed to the IOC feed:** the OpenClaw distribution/documentation domains (`openclaw.ai`, `docs.openclaw.ai`), the adjacent-infrastructure domain (`lightmake.site`), and the operator's open-directory IP (`221.150.15.104`) each anchored a rule with no other discriminator — removing the domain or IP left nothing behavioral to detect. All four indicators were already present in [`korean-claude-openclaw-221.150.15.104-iocs.json`](/ioc-feeds/korean-claude-openclaw-221.150.15.104-iocs.json) prior to this pass; no feed edits were required. See Coverage Gaps for the full per-rule accounting.

**Key hunt anchor:** any `settings.local.json` (Claude Code global or per-project allowlist) whose `permissions.allow` array contains a `curl ... | bash` pattern, a global `npm i -g` of an unfamiliar package, or a local-listener invocation (`* --port <N>`) is worth reviewing regardless of which specific tooling is referenced. The specific OpenClaw strings are the precision anchor (Detection tier); the broader `curl|bash` pattern is the resilience anchor and is deliberately kept at Hunting tier because dual-use tool evaluation by legitimate developers produces the identical artifact.

---

## YARA Rules

### Detection Rules

#### OpenClaw-Specific Claude Code Allowlist

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1562.001 (Disable or Modify Tools), T1059.004 (Unix Shell)
**Confidence:** HIGH
**Rationale:** Detects the operator's exact `settings.local.json` allowlist pattern pre-authorizing the complete OpenClaw installation and gateway-bring-up workflow. Requiring 3 of 7 distinctive OpenClaw-specific allowlist entries makes this a durable multi-string combination — no known legitimate Claude Code workflow pre-approves `curl|bash` + `npm i -g openclaw` + `openclaw gateway` together in one file, and no single renameable literal carries the rule alone.
**False Positives:** None known — the combination of 3+ OpenClaw-specific allowlist strings in a `settings.local.json` file is not produced by any known legitimate developer workflow. Individual strings may appear separately in legitimate configurations; the 3-of-7 conjunction makes FP probability negligible.
**Blind Spots:** An operator who rewrites the allowlist to reference fewer than 3 of the 7 anchor strings (for example pre-authorizing only the npm path behind a generic command alias) evades this rule; misses non-JSON permission mechanisms if Claude Code's config format changes.
**Validation:** Scan a `settings.local.json` containing the documented 7-entry OpenClaw allowlist chain — must match; a stock or minimally-customized Claude Code `settings.local.json` with no `curl|bash` / `npm i -g` / gateway entries must NOT fire.
**Deployment:** Endpoint file scanner, YARA-over-filesystem hunt on developer and admin workstations, CI/CD pipeline scanning. Target file: `settings.local.json` anywhere under `.claude/` directories.

```yara
/*
   Yara Rule Set
   Identifier: Claude Code Attacker-Customized Allowlist — OpenClaw Operator (Korean-ClaudeCode-Allowlist-OpenClaw-221.150.15.104)
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule TOOL_ClaudeCode_OpenClaw_Allowlist_Specific {
   meta:
      description = "Detects attacker-customized Claude Code settings.local.json containing 3+ OpenClaw-specific permission allowlist entries pre-authorizing the OpenClaw curl|bash installer, npm global install, onboarding, docs fetch, gateway start, and UI launch — suppressing Claude Code safety prompts for the complete OpenClaw bring-up workflow"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/korean-claude-openclaw-221.150.15.104-detections/"
      date = "2026-05-27"
      family = "AI-Agent Allowlist Abuse"
      malware_type = "Operator Tradecraft / AI-Agent Permission Bypass"
      campaign = "Korean-ClaudeCode-Allowlist-OpenClaw-221.150.15.104"
      id = "98965454-3e39-59be-8b73-d9e5451d3a11"
   strings:
      $oc_install    = "Bash(curl -fsSL https://openclaw.ai/install.sh | bash)" ascii fullword
      $oc_npm        = "Bash(npm i -g openclaw)" ascii fullword
      $oc_onboard    = "Bash(openclaw onboard)" ascii fullword
      $oc_webfetch   = "WebFetch(domain:docs.openclaw.ai)" ascii fullword
      $oc_gateway    = "Bash(openclaw gateway --port" ascii
      $oc_openui     = "Bash(open http://127.0.0.1:18789/)" ascii fullword
      $oc_domain     = "openclaw.ai" ascii
   condition:
      filesize < 10KB and
      3 of ($oc_install, $oc_npm, $oc_onboard, $oc_webfetch, $oc_gateway, $oc_openui, $oc_domain)
}
```

### Hunting Rules

#### Generic Curl-Pipe-Bash Pattern in Claude Code Allowlist

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1562.001 (Disable or Modify Tools), T1059.004 (Unix Shell)
**Confidence:** MODERATE
**Rationale:** Detects any `settings.local.json` Claude Code permission file containing a `Bash(curl ... | bash)` or `Bash(curl ... | sh)` pattern within a `permissions` block — a durable structural pattern that catches any pipe-to-shell installer allowlist entry regardless of which specific tooling is referenced, so it survives the operator swapping OpenClaw for another framework. The tradeoff is precision: developer endpoints with legitimate internal installer allowlists (corporate package feeds delivered via `curl | bash`) trigger this identically to attacker customization, so it stays Hunting rather than Detection.
**False Positives:** Developer endpoints whose Claude Code allowlists include approved internal installer pipelines, for example corporate package feeds delivered via `curl | bash`.
**Deployment:** Server-class endpoints, CI/CD agents, jump hosts, finance/HR workstations for highest signal-to-noise ratio. On developer workstations, use as a delta-alert (new allowlist entry detected) routed to allowlist review rather than a block trigger.

```yara
rule TOOL_ClaudeCode_CurlBash_Allowlist_Generic {
   meta:
      description = "Detects any Claude Code settings.local.json permission allowlist containing a Bash(curl ... | bash) or Bash(curl ... | sh) pre-authorization pattern — a high-signal heuristic for attacker-customized AI-agent allowlist abuse regardless of which specific tooling is being installed"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/korean-claude-openclaw-221.150.15.104-detections/"
      date = "2026-05-27"
      family = "AI-Agent Allowlist Abuse"
      malware_type = "Operator Tradecraft / AI-Agent Permission Bypass"
      campaign = "Korean-ClaudeCode-Allowlist-OpenClaw-221.150.15.104"
      id = "ae126881-077c-513d-bd87-bd8b56944fcc"
   strings:
      $permissions_block = "\"permissions\"" ascii
      $allow_block       = "\"allow\"" ascii
      $curl_bash         = "| bash)" ascii
      $curl_sh           = "| sh)" ascii
      $bash_prefix       = "Bash(curl" ascii
   condition:
      filesize < 10KB and
      $permissions_block and
      $allow_block and
      $bash_prefix and
      ($curl_bash or $curl_sh)
}
```

---

## Sigma Rules

### Hunting Rules

#### Claude Code settings.local.json Written or Modified

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1562.001 (Disable or Modify Tools)
**Confidence:** MODERATE
**Rationale:** Sigma `file_event` rules match on path metadata, not file content, in most back ends, so this rule cannot itself confirm OpenClaw-specific allowlist strings are present — it only signals that the file was written. Because Claude Code writes this same path during routine, everyday interactive use (any time a user accepts a new tool permission), the rule fires on ubiquitous benign activity on any fleet with real Claude Code adoption. The path itself is durable (Claude Code, not the operator, dictates the filename), but precision fails Detection grade — this is a scoping lead that must be paired with the YARA content rule above, not an alert.
**False Positives:**
- Routine Claude Code operation on any developer host — this file is written or updated whenever a user accepts a new tool permission, which is common, everyday interactive activity, not evidence of attacker customization by itself.
- Legitimate OpenClaw adopters on developer-class workstations who have explicitly added OpenClaw allowlist entries to their own Claude Code configuration.
**Deployment:** Linux and macOS endpoints with file-event telemetry (auditd, Sysmon for Linux, ESA). Pair every hit with a YARA content scan (see YARA Detection rule above) before treating it as a finding; do not alert on this rule alone.

```yaml
title: Claude Code Permission Allowlist Modified with OpenClaw Installer Strings
id: 54d80e73-2b2d-4932-a97b-d431db41c501
status: experimental
description: >-
  Detects creation or modification of a Claude Code settings.local.json file. Sigma
  file_event rules match path metadata only in most back ends, so this rule alone cannot
  confirm OpenClaw-specific allowlist content is present — pair with a YARA content scan
  for that confirmation. Because Claude Code writes this path during routine interactive
  use, hits require triage rather than automatic alerting; this rule is a scoping lead,
  not a high-confidence indicator by itself.
references:
    - https://the-hunters-ledger.com/reports/korean-claude-openclaw-221.150.15.104/
    - https://the-hunters-ledger.com/hunting-detections/korean-claude-openclaw-221.150.15.104-detections/
author: The Hunters Ledger
date: '2026-05-27'
tags:
    - attack.stealth
    - attack.defense-impairment
    - attack.t1685
    - detection.emerging-threats
logsource:
    category: file_event
    product: linux
detection:
    selection_path:
        TargetFilename|contains: '/.claude/settings.local.json'
    condition: selection_path
falsepositives:
    - >-
      Routine Claude Code operation on any developer host — this file is written or
      updated whenever a user accepts a new tool permission, which is common, everyday
      interactive activity, not evidence of attacker customization by itself.
    - >-
      Legitimate OpenClaw adopters on developer-class workstations who have explicitly
      added OpenClaw allowlist entries to their own Claude Code configuration.
level: medium
```

> **Note on file-content matching:** this rule surfaces the write event only; it cannot confirm OpenClaw-specific content. Use the YARA Detection rule above for the content-level confirmation that makes a hit actionable.

#### OpenClaw Curl-Pipe-Bash Installer Execution

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1059.004 (Unix Shell), T1562.001 (Disable or Modify Tools)
**Confidence:** MODERATE
**Rationale:** Detects the process-creation event for the OpenClaw `curl|bash` installer pipeline — the AND-combination of `curl`, `openclaw.ai`, and `bash` in one command line has no legitimate use outside of OpenClaw installation, so precision is genuinely tight. It stays Hunting rather than Detection because that same command line is exactly what a legitimate developer or evaluator runs when installing OpenClaw manually — the rule cannot distinguish attacker-driven, allowlist-suppressed execution from a human deliberately typing the documented install command, and no parent-process (Claude Code) correlation is available in the captured evidence to make that distinction. It is also domain-anchored (`openclaw.ai`), so it does not survive the vendor rotating install infrastructure — see the broader curl|bash YARA Hunting rule for the domain-independent resilience anchor.
**False Positives:** Legitimate OpenClaw evaluation or installation on developer-class workstations, run manually and independent of any Claude Code allowlist.
**Deployment:** Linux and macOS endpoints with process-creation telemetry (auditd, Sysmon for Linux, ESA, EDR). Priority targets: CI/CD agents, build servers, server-class hosts with no expected reason to install AI-agent tooling.

```yaml
title: OpenClaw AI-Agent Framework Curl-Pipe-Bash Installer Execution
id: e02ddbf4-0a77-4c13-85ac-cd1ed9d8e66d
status: experimental
description: >-
  Detects execution of the OpenClaw AI-agent framework curl-pipe-bash installer pipeline.
  The command-line pattern (curl fetching from openclaw.ai piped to bash) is the primary
  distribution mechanism documented in the Korean-ClaudeCode-Allowlist-OpenClaw-221.150.15.104
  operator campaign. This rule cannot distinguish execution under an attacker-customized
  Claude Code allowlist from a legitimate developer manually installing OpenClaw — both
  produce the identical command line — so hits require review rather than automatic alerting.
references:
    - https://the-hunters-ledger.com/reports/korean-claude-openclaw-221.150.15.104/
    - https://the-hunters-ledger.com/hunting-detections/korean-claude-openclaw-221.150.15.104-detections/
author: The Hunters Ledger
date: '2026-05-27'
tags:
    - attack.execution
    - attack.stealth
    - attack.defense-impairment
    - attack.t1059.004
    - attack.t1685
    - detection.emerging-threats
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains|all:
            - 'curl'
            - 'openclaw.ai'
            - 'bash'
    condition: selection
falsepositives:
    - >-
      Legitimate OpenClaw evaluation or installation on developer-class workstations, run
      manually and independent of any Claude Code allowlist.
level: medium
```

#### OpenClaw Gateway Service Started

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1090.001 (Internal Proxy), T1562.001 (Disable or Modify Tools)
**Confidence:** MODERATE
**Rationale:** Detects invocation of the OpenClaw local-gateway service. The original selection OR-combined an image-name match with a bare `CommandLine` match on `gateway` + `--port` — the command-line branch alone is a generic pattern that would fire on any unrelated service using those two common tokens together, such as VPN gateways, API gateways, and countless other internal tools. Tightened here to require the `openclaw` binary image **and** the `gateway`/`--port` arguments together, removing the standalone false-positive-prone branch. Even tightened, legitimate OpenClaw adopters running the gateway locally trigger this identically to attacker-driven use, so it remains Hunting.
**False Positives:** Legitimate OpenClaw adopters on developer-class workstations running the gateway for sanctioned evaluation or use.
**Deployment:** Linux and macOS endpoints with process-creation telemetry. Cross-correlate with port-18789 listener inventory for confirmation; scope alerting priority to server-class, jump-host, and non-developer endpoints for highest signal-to-noise ratio.

```yaml
title: OpenClaw AI-Agent Gateway Service Started
id: f6a6901a-73dc-49c9-8c05-5ca64aa89d23
status: experimental
description: >-
  Detects invocation of the OpenClaw local-gateway service via the 'openclaw gateway
  --port' command pattern, requiring both the openclaw binary image and the gateway/port
  arguments together. The OpenClaw gateway functions as a local control-plane proxy
  between Claude Code and downstream OpenClaw skills — its startup indicates the operator
  has completed installation and is bringing up the AI-agent control plane. Observed as
  allowlist entry 6 in the Korean-ClaudeCode-Allowlist-OpenClaw-221.150.15.104 campaign.
  Legitimate adopters running the same gateway trigger this identically, so hits require
  review rather than automatic alerting.
references:
    - https://the-hunters-ledger.com/reports/korean-claude-openclaw-221.150.15.104/
    - https://the-hunters-ledger.com/hunting-detections/korean-claude-openclaw-221.150.15.104-detections/
author: The Hunters Ledger
date: '2026-05-27'
tags:
    - attack.command-and-control
    - attack.t1090.001
    - attack.stealth
    - attack.defense-impairment
    - attack.t1685
    - detection.emerging-threats
logsource:
    category: process_creation
    product: linux
detection:
    selection_image:
        Image|endswith: '/openclaw'
    selection_cmdline:
        CommandLine|contains|all:
            - 'gateway'
            - '--port'
    condition: selection_image and selection_cmdline
falsepositives:
    - >-
      Legitimate OpenClaw adopters on developer-class workstations running the gateway
      for sanctioned evaluation or use.
level: medium
```

#### NPM Registry Fetch for OpenClaw Package

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1059.007 (JavaScript), T1562.001 (Disable or Modify Tools)
**Confidence:** MODERATE
**Rationale:** Detects HTTP requests to the npm registry for the `openclaw` package name — the alternative installation path documented in the operator's allowlist (`npm i -g openclaw`). Requiring both the registry host and the package-name substring together is a reasonable combination, but it still cannot distinguish an attacker-driven install from a developer intentionally evaluating the framework, and npm proxy/HTTP-inspection telemetry is not universally available. Deployed as a Hunting lead on hosts with no expected reason to fetch AI-agent tooling.
**False Positives:** Legitimate developers evaluating or installing OpenClaw on sanctioned developer workstations.
**Deployment:** Web proxy logs, DNS-based npm monitoring. Highest value on server-class and CI/CD agent hosts with no legitimate reason to fetch this package.

```yaml
title: NPM Registry Fetch for OpenClaw Package
id: d3a240e8-79a9-44d7-8b51-199389276d28
status: experimental
description: >-
  Detects HTTP requests to the npm registry (registry.npmjs.org) for the openclaw package
  name — the alternative installation path for the OpenClaw AI-agent framework documented
  in the Korean-ClaudeCode-Allowlist-OpenClaw-221.150.15.104 operator campaign. Cannot
  distinguish attacker-driven installation from legitimate developer evaluation of the
  same dual-use package, so hits require review on developer-class hosts.
references:
    - https://the-hunters-ledger.com/reports/korean-claude-openclaw-221.150.15.104/
    - https://the-hunters-ledger.com/hunting-detections/korean-claude-openclaw-221.150.15.104-detections/
author: The Hunters Ledger
date: '2026-05-27'
tags:
    - attack.execution
    - attack.t1059.007
    - attack.stealth
    - attack.defense-impairment
    - attack.t1685
    - detection.emerging-threats
logsource:
    category: proxy
detection:
    selection:
        cs-host|contains: 'registry.npmjs.org'
        cs-uri-stem|contains: 'openclaw'
    condition: selection
falsepositives:
    - >-
      Legitimate developers evaluating or installing OpenClaw on sanctioned developer
      workstations.
level: medium
```

---

## Coverage Gaps

**Gap 1 — No malware binary; no PE-class YARA rule possible.**
This campaign produced no executable artifact. The analysis subject is the operator's `~/.claude/settings.local.json` configuration file (442 bytes, JSON). PE-class YARA rules (MZ header, section entropy, import hash) are not applicable. All YARA coverage in this file is scoped to text-format JSON configuration files.

**Gap 2 — Four atomics routed to the IOC feed (1 Sigma DNS rule + 3 Suricata signatures).**
Four of the file's original rules keyed solely on a hardcoded domain or IP with no surviving behavioral signal once the literal is removed — per the tiering rubric's routing test, these are IOC-feed entries, not rules:

- **DNS Resolution of OpenClaw AI-Agent Framework Distribution Domains** (Sigma) matched only `dns.question.name` containing `openclaw.ai` or `lightmake.site`, with no other selector. `openclaw.ai`, `docs.openclaw.ai`, and `lightmake.site` are already carried in [`korean-claude-openclaw-221.150.15.104-iocs.json`](/ioc-feeds/korean-claude-openclaw-221.150.15.104-iocs.json) (`network_indicators.domains`).
- **TLS SNI Match: openclaw.ai** and **TLS SNI Match: docs.openclaw.ai** (Suricata) each matched only an exact `tls.sni` string with no other content anchor. Both domains are already in the feed as above.
- **HTTP Host Match: Operator Open Directory** (Suricata) matched only the destination IP `221.150.15.104` plus a bare `GET` method — no distinguishing header, URI path, or payload content. `221.150.15.104` is already in the feed (`network_indicators.ipv4`), and the discovery URL `http://221.150.15.104:8080/` is separately carried in `network_indicators.urls`.

No feed edits were required — all four indicators were already present from the original analysis. Cutting these rules also removes the T1082 (System Information Discovery) mapping the docs.openclaw.ai rule previously carried; no surviving rule covers that technique, and the mapping was tangential (a WebFetch-to-docs-domain proxy for discovery) even when the rule existed.

**Gap 3 — No C2 protocol observed; no C2-traffic behavioral Sigma or Suricata rules possible.**
The operator's open directory and configuration artifact do not expose a C2 channel. The OpenClaw gateway (port 18789) is a local loopback service — its external C2 behavior, if any, is not documented in the captured evidence and should not be fabricated. If future evidence documents the OpenClaw gateway's external egress protocol, C2-traffic rules should be added.

**Gap 4 — OpenClaw skill execution behavior is undocumented in the captured evidence.**
The `settings.local.json` artifact documents the install and gateway-bring-up chain but does not specify which OpenClaw skills the operator deployed or what attack capabilities they exercised. Related investigation material documents OpenClaw's broader attack-capability ecosystem, but that evidence belongs to those cases, not this artifact. No rules have been written for specific OpenClaw skill execution behavior from this case's evidence.

**Gap 5 — Attacker evasion by tooling substitution.**
The allowlist-customization technique — pre-approving `curl|bash`, a global npm install, and listener bring-up in `settings.local.json` — is fully documented in this report. An operator who reads it can substitute any other AI-agent framework for OpenClaw and bypass every OpenClaw-specific string rule. The resilience detection anchor is the broader `curl|bash`-in-allowlist YARA Hunting rule and the generic process-creation pattern, which fire on the structural pattern regardless of tool name — neither can be evaded by swapping the domain or package name without also changing the `curl|bash` distribution model itself.

**Gap 6 — macOS-specific `open` command detection not covered.**
Allowlist entry 7 (`Bash(open http://127.0.0.1:18789/)`) uses the macOS `open` command to launch the OpenClaw gateway UI in the default browser. A Sigma rule for `process_creation` matching `Image|endswith: '/open'` with `CommandLine|contains: '127.0.0.1:18789'` is technically feasible on macOS with Sysmon for macOS or ESA telemetry, but was not written because the `open` command is extremely common on macOS (used by countless legitimate applications) and the port-specific matching alone would produce a high FP rate without additional context. This gap is best addressed by correlating port-18789 listener inventory (host level) with process logs rather than a standalone process-creation rule.

**Gap 7 — Parent-process correlation would raise the two Hunting-tier process-execution rules to Detection.**
Both the curl|bash installer rule and the gateway-startup rule cannot distinguish a legitimate developer manually running OpenClaw from Claude Code auto-executing the same command under the attacker-customized allowlist — the campaign's evidence is a static configuration-file artifact, not observed process telemetry, so no parent-process (Claude Code) chain is available to make that distinction. What would raise confidence: telemetry showing Claude Code's own process as the direct parent of the `curl|bash` installer or `openclaw gateway` invocation would support tightening both rules to Detection tier via a `ParentImage` constraint.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
