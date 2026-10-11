---
title: "Detection Rules — Korean Claude Code Allowlist + OpenClaw Operator (221.150.15.104)"
description: "Detection rules for Korean Claude Code OpenClaw operator config abuse (221.150.15.104). Two YARA and four Sigma rules on allowlist behavior."
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

No malware binary exists in this campaign. The primary evidence is the operator's `~/.claude/settings.local.json` configuration artifact. Detection coverage targets two surfaces that retain analyst value after tiering: (1) the configuration-file artifact itself (YARA file-content matching) and (2) behavioral execution patterns generated when Claude Code, or a human operator, acts under the attacker-customized allowlist (Sigma process/file rules). The campaign's network indicators, the OpenClaw distribution/documentation domains and the operator's open-directory IP, are bare atomic matches with no surviving behavioral signal once the domain or IP literal is removed, so all three original Suricata signatures and one Sigma DNS rule route to the IOC feed instead of standing as rules.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 0 | 2 | T1685, T1059.004 | 0 |
| Sigma | 0 | 4 | T1685, T1059.004, T1090.001, T1105 | 1 |
| Suricata | 0 | 0 | — | 3 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient, safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting. Expect to review the hits.

**Strongest anchor, still Hunting:** the OpenClaw allowlist rule (three of six distinct OpenClaw entries in one small file) is the most specific rule here, and it is Hunting tier. The report records that OpenClaw is publicly distributed with legitimate adopters, and a file cannot show who wrote its allowlist, so a hit is a lead to check the file's owner and not an alert. The campaign has no Detection-tier rule.

**Atomics routed to the IOC feed:** the OpenClaw distribution/documentation domains (`openclaw.ai`, `docs.openclaw.ai`), the adjacent-infrastructure domain (`lightmake.site`), and the operator's open-directory IP (`221.150.15.104`) each anchored a rule with no other discriminator, removing the domain or IP left nothing behavioral to detect. All four indicators were already present in [`korean-claude-openclaw-221.150.15.104-iocs.json`](/ioc-feeds/korean-claude-openclaw-221.150.15.104-iocs.json) prior to this pass; no feed edits were required. See Coverage Gaps for the full per-rule accounting.

**Key hunt anchor:** any `settings.local.json` (Claude Code global or per-project allowlist) whose `permissions.allow` array contains a `curl ... | bash` pattern, a global `npm i -g` of an unfamiliar package, or a local-listener invocation (`* --port <N>`) is worth reviewing regardless of which specific tooling is referenced. The specific OpenClaw strings are the precision anchor and the broader `curl|bash` pattern is the resilience anchor; both are Hunting tier because dual-use tool evaluation by legitimate developers produces the identical artifact.

---

## YARA Rules

### Hunting Rules

#### Generic Curl-Pipe-Bash Pattern in Claude Code Allowlist

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1685 (Disable or Modify Tools), T1059.004 (Unix Shell)
**Confidence:** MODERATE
**Rationale:** Matches a file under 10 KB (`filesize < 10KB`) that carries the `"permissions"` and `"allow"` keys and one quoted entry of the form `Bash(curl ... | bash)` or `Bash(curl ... | sh)`. Curl and the pipe must sit in the same entry: no double quote, carriage return or line feed may lie between `Bash(curl` and the pipe, and there is no limit on the distance between them, so a long URL or long arguments still match. The rule is a pattern match on those bytes and is not a JSON parser; an entry with an escaped quote (`\"`) between the curl and the pipe is read as two pieces and does not match. The rule does not check that the entry is inside the `permissions.allow` array, only that the file has both keys. It catches any pipe-to-shell installer allowlist entry regardless of which tooling is referenced, so it survives the operator swapping OpenClaw for another framework. The tradeoff is precision: developer endpoints with legitimate internal installer allowlists (corporate package feeds delivered via `curl | bash`) trigger this identically to attacker customization, so it stays Hunting rather than Detection.
**False Positives:** Developer endpoints whose Claude Code allowlists include approved internal installer pipelines, for example corporate package feeds delivered via `curl | bash`.
**Blind Spots:** An entry that downloads with `wget`, or pipes into a shell through `| zsh` or `| sudo bash`, does not match; an entry written as `curl ... | bash -s` does not match either, because the entry must end in `| bash)` or `| sh)`. A file of 10 KB or more is not scanned.
**Validation:** A `settings.local.json` holding `Bash(curl -fsSL https://example.test/install.sh | bash)` in its `allow` array must fire. A file whose `allow` array holds `Bash(curl https://example.test/status)` in one entry and a separate `Bash(echo done | bash)` entry must NOT fire. A single entry whose URL is 350 characters long must fire (no span limit).
**Deployment:** Server-class endpoints, CI/CD agents, jump hosts, finance/HR workstations for highest signal-to-noise ratio. On developer workstations, use as a delta-alert (new allowlist entry detected) routed to allowlist review rather than a block trigger.

```yara
rule TOOL_ClaudeCode_CurlBash_Allowlist_Generic {
   meta:
      description = "Detects a small file (under 10 KB) with the permissions and allow keys and a single allowlist entry of the form Bash(curl ... | bash) or Bash(curl ... | sh), a heuristic lead for attacker-customized AI-agent allowlists regardless of which tooling is being installed. Developers who pre-approve an internal installer produce the same entry"
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
      $curl_pipe         = /Bash\(curl[^\x22\r\n]*\| ?(ba)?sh\)/ ascii
   condition:
      filesize < 10KB and
      $permissions_block and
      $allow_block and
      $curl_pipe
}
```

#### OpenClaw-Specific Claude Code Allowlist

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1685 (Disable or Modify Tools), T1059.004 (Unix Shell)
**Confidence:** MODERATE
**Rationale:** Matches a file under 10 KB (`filesize < 10KB`) that carries at least three of the six distinct OpenClaw permission-allowlist entries found in the operator's `settings.local.json` (the `curl|bash` installer, `npm i -g openclaw`, `openclaw onboard`, the docs fetch, the gateway start, the UI open). Each of the six entries is its own string and no entry counts twice (the gateway string is the prefix `Bash(openclaw gateway --port`, so it confirms the start of that entry and not its port number or closing parenthesis), so the match needs three different allowlist lines and not one line repeated. The rule keys on those literal entry strings, which the operator or the OpenClaw project can change, so it is a scoping lead and not an alert. Anyone who adopts OpenClaw legitimately and pre-approves its documented install steps in Claude Code produces the same file: the report records that OpenClaw is a publicly distributed framework with legitimate adopters, and that a single file cannot show who wrote the allowlist.
**False Positives:**
- A legitimate OpenClaw adopter who pre-approved three or more of its documented install and start commands in their own Claude Code configuration.
- A security team or researcher holding a copy of the operator's file or a similar sample; the rule reads file bytes and cannot tell a live configuration from a stored copy.
**Blind Spots:** An operator who rewrites the allowlist to reference fewer than three of the six entries (for example pre-authorizing only the npm path behind a generic command alias) evades this rule. It does not test the file name or location, only a size limit and the strings. It misses non-JSON permission mechanisms if Claude Code's config format changes.
**Validation:** Scan a file holding the operator's documented allowlist (the installer, npm, onboard, docs fetch, gateway and UI entries) and confirm the rule fires. A `settings.local.json` holding only two of the six entries, or only the text `openclaw.ai` without an allowlist entry, must NOT fire. A stock Claude Code `settings.local.json` with no OpenClaw entries must NOT fire.
**Deployment:** Endpoint file scanner or YARA-over-filesystem hunt on developer and admin workstations, run against `settings.local.json` files under `.claude/` directories (the rule does not test the path, so the scan scope is what limits it). Treat a hit as a lead to review the file's owner, not as an alert.

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
      description = "Detects a small file (under 10 KB) that carries at least three of six distinct OpenClaw permission-allowlist entries as found in the operator's Claude Code settings.local.json: the curl|bash installer, npm global install, onboarding, docs fetch, gateway start, and UI launch. A legitimate OpenClaw adopter who allowlists the same documented steps produces the same file"
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
   condition:
      filesize < 10KB and
      3 of ($oc_install, $oc_npm, $oc_onboard, $oc_webfetch, $oc_gateway, $oc_openui)
}
```

---

## Sigma Rules

### Hunting Rules

#### Claude Code settings.local.json Written or Modified

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1685 (Disable or Modify Tools)
**Confidence:** MODERATE
**Rationale:** Sigma `file_event` rules match on path metadata, not file content, in most back ends, so this rule cannot itself confirm OpenClaw-specific allowlist strings are present — it only signals that the file was written. Because Claude Code writes this same path during routine, everyday interactive use (any time a user accepts a new tool permission), the rule fires on ubiquitous benign activity on any fleet with real Claude Code adoption. The path is pinned with `startswith`, `endswith` and a whole-field regex written without `^` or `$` (Elastic's regex engine has no anchors and would read them as literal characters). The path itself is durable (Claude Code, not the operator, dictates the filename), but precision fails Detection grade — this is a scoping lead that must be paired with the YARA content rule above, not an alert.
**False Positives:**
- Routine Claude Code operation on any developer host. This file is written or updated whenever a user accepts a new tool permission, which is common, everyday interactive activity, not evidence of attacker customization by itself.
- Legitimate OpenClaw adopters on developer-class workstations who have explicitly added OpenClaw allowlist entries to their own Claude Code configuration.
**Deployment:** Linux endpoints with file-event telemetry (Sysmon for Linux or an EDR file-event feed; raw auditd records carry the file name in a PATH record that a pipeline must normalize into a file event before this rule's `TargetFilename` field exists). Pair every hit with a YARA content scan (see the YARA allowlist rule above) before treating it as a finding; do not alert on this rule alone.

**FP remediation, 2026-08-13.** The selector was a bare `contains` on `/.claude/settings.local.json`, which matched the filename anywhere on disk. It fired 16 times on an inert forensic copy of a threat actor's own config sitting four directories deep under a collection tree, pulled down by `wget` and staged by `cp` and `python3.12`. That is not a quirk of one network. The same shape fires for any defender holding a malware corpus, any SOC storing collected artifacts, and any researcher who mirrors a compromised host's home directory, because a file-creation event cannot distinguish a live config controlling a host from an inert copy of one.

The selector is now anchored to the operative path, the account's real `~/.claude/settings.local.json` under `/root` or `/home/<user>`. An attacker tampering with an agent allowlist has to write there for the tampering to take effect, since Claude Code will never read a copy under a collection directory. Measured over 45 days on the rule's own source index: 16 matching events before, 0 after.

The rule is scoped to Linux: the logsource is `product: linux` and the path test needs `/root/` or `/home/<user>/`, so it does not match a macOS home directory under `/Users/<user>/`. The report reads the operator host as macOS (entry 7, `open`, in the seven-entry breakdown), so this rule does not cover the host the report most likely describes; no macOS selector is written because no macOS file-event profile was observed. The cost is small but real. Claude Code also supports a project-level `.claude/settings.local.json` at the root of any opened repository, and this anchor does not cover that. Poisoning a project directory is a genuine separate surface, outside this rule's campaign scope, and is recorded here as a known boundary rather than silently accepted. The pre-existing false positive on routine interactive use is untouched, so this stays a Hunting-tier lead that needs the YARA content pairing.

```yaml
title: Claude Code settings.local.json Written Under Root or a Home Directory
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
        TargetFilename|startswith:
            - '/root/'
            - '/home/'
        TargetFilename|endswith: '/.claude/settings.local.json'
        TargetFilename|re: '(/root|/home/[^/]+)/\.claude/settings\.local\.json'
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

> **Note on file-content matching:** this rule surfaces the write event only; it cannot confirm OpenClaw-specific content. Use the YARA allowlist rule above for the content-level check that makes a hit worth acting on.

#### Command Line With Curl, openclaw.ai and a Pipe-to-Shell Fragment (OpenClaw Installer Shape)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1059.004 (Unix Shell), T1685 (Disable or Modify Tools)
**Confidence:** MODERATE
**Rationale:** Detects a process-creation event whose command line holds the substrings `curl` and `openclaw.ai` and one of the fragments `| bash`, `|bash`, `| sh` or `|sh`, the shape of the OpenClaw `curl|bash` installer pipeline when one shell process carries the whole pipeline in its command line. The three tests are unordered substring tests with no token boundary: `curl https://x.test/a; echo openclaw.ai; echo "| bash"` satisfies them, and so does a command line that pipes into `bashful` or into `sha256sum` (the `| sh` fragment is a prefix of `| sha256sum`). The `openclaw.ai` literal keeps the match narrow in practice, and the rule makes no claim that the command downloads OpenClaw and pipes it to a shell. It stays Hunting rather than Detection because that same command line is exactly what a legitimate developer or evaluator runs when installing OpenClaw manually — the rule cannot distinguish attacker-driven, allowlist-suppressed execution from a human deliberately typing the documented install command, and no parent-process (Claude Code) correlation is available in the captured evidence to make that distinction. It is also domain-anchored (`openclaw.ai`), so it does not survive the vendor rotating install infrastructure — see the broader curl|bash YARA Hunting rule for the domain-independent resilience anchor.
**False Positives:** Legitimate OpenClaw evaluation or installation on developer-class workstations, run manually and independent of any Claude Code allowlist.
**Blind Spots:** The pipe has to appear in a command line, and nothing ties the `curl`, the host name and the pipe into one pipeline. When the shell starts `curl` and `bash` as two separate processes, neither command line carries the pipe and this rule does not fire. A mirrored or renamed installer host also evades the `openclaw.ai` literal.
**Validation:** Run `sh -c 'curl -fsSL https://openclaw.ai/install.sh | bash'` on a test host and confirm the rule fires. A `curl https://openclaw.ai/` download with no pipe into a shell, and a `curl | bash` pipeline for a different host, must NOT fire. A command line that merely mentions all three fragments in any order, for example `echo curl openclaw.ai '| bash'`, WILL fire.
**Deployment:** Linux endpoints with process-creation telemetry (auditd, Sysmon for Linux, ESA, EDR); the logsource is `product: linux`, so a macOS feed needs its own logsource mapping. Priority targets: CI/CD agents, build servers, server-class hosts with no expected reason to install AI-agent tooling.

```yaml
title: Command Line With Curl, openclaw.ai and a Pipe-to-Shell Fragment (OpenClaw Installer Shape)
id: e02ddbf4-0a77-4c13-85ac-cd1ed9d8e66d
status: experimental
description: >-
  Detects a command line that holds the substrings curl and openclaw.ai together with a
  pipe-to-shell fragment (| bash, |bash, | sh or |sh), in any order and without token
  boundaries. The pattern curl fetching from openclaw.ai piped to bash is the primary
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
        CommandLine|contains:
            - '| bash'
            - '|bash'
            - '| sh'
            - '|sh'
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
**ATT&CK Coverage:** T1090.001 (Internal Proxy), T1685 (Disable or Modify Tools)
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
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer)
**ATT&CK Note:** T1059.007 (JavaScript) and T1685 (Disable or Modify Tools) are withdrawn. The rule sees a proxy-logged request for a package name; it observes no script execution and no tampering with any tool. T1105 describes what the request is, a tool being pulled onto a host, at MODERATE because a developer fetching the same package produces the identical request.
**Confidence:** MODERATE
**Rationale:** Detects HTTP requests to the npm registry for the `openclaw` package name — the alternative installation path documented in the operator's allowlist (`npm i -g openclaw`). Requiring both the registry host and the package-name substring together is a reasonable combination, but it still cannot distinguish an attacker-driven install from a developer intentionally evaluating the framework, and npm proxy/HTTP-inspection telemetry is not universally available. Deployed as a Hunting lead on hosts with no expected reason to fetch AI-agent tooling.
**False Positives:** Legitimate developers evaluating or installing OpenClaw on sanctioned developer workstations.
**Blind Spots:** The host is matched exactly (`registry.npmjs.org`), so a proxy that logs the host with a port suffix, an npm mirror or a private registry proxy does not match. A package fetched from a cache the proxy never sees is not logged at all.
**Deployment:** Web proxy logs that record the requested host and URI path (`cs-host`, `cs-uri-stem`); DNS logs hold only hostnames and cannot show the package name. Highest value on server-class and CI/CD agent hosts with no legitimate reason to fetch this package.

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
    - attack.command-and-control
    - attack.t1105
    - detection.emerging-threats
logsource:
    category: proxy
detection:
    selection:
        cs-host: 'registry.npmjs.org'
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

**Gap 1: No malware binary; no PE-class YARA rule possible.**
This campaign produced no executable artifact. The analysis subject is the operator's `~/.claude/settings.local.json` configuration file (442 bytes, JSON). PE-class YARA rules (MZ header, section entropy, import hash) are not applicable. All YARA coverage in this file is scoped to text-format JSON configuration files.

**Gap 2: Four atomics routed to the IOC feed (1 Sigma DNS rule + 3 Suricata signatures).**
Four of the file's original rules keyed solely on a hardcoded domain or IP with no surviving behavioral signal once the literal is removed, per the tiering rubric's routing test, these are IOC-feed entries, not rules:

- **DNS Resolution of OpenClaw AI-Agent Framework Distribution Domains** (Sigma) matched only `dns.question.name` containing `openclaw.ai` or `lightmake.site`, with no other selector. `openclaw.ai`, `docs.openclaw.ai`, and `lightmake.site` are already carried in [`korean-claude-openclaw-221.150.15.104-iocs.json`](/ioc-feeds/korean-claude-openclaw-221.150.15.104-iocs.json) (`network_indicators.domains`).
- **TLS SNI Match: openclaw.ai** and **TLS SNI Match: docs.openclaw.ai** (Suricata) each matched only an exact `tls.sni` string with no other content anchor. Both domains are already in the feed as above.
- **HTTP Host Match: Operator Open Directory** (Suricata) matched only the destination IP `221.150.15.104` plus a bare `GET` method, no distinguishing header, URI path, or payload content. `221.150.15.104` is already in the feed (`network_indicators.ipv4`), and the discovery URL `http://221.150.15.104:8080/` is separately carried in `network_indicators.urls`.

No feed edits were required. All four indicators were already present from the original analysis. Cutting these rules also removes the T1082 (System Information Discovery) mapping the docs.openclaw.ai rule previously carried; no surviving rule covers that technique, and the mapping was tangential (a WebFetch-to-docs-domain proxy for discovery) even when the rule existed.

**Gap 3: No C2 protocol observed; no C2-traffic behavioral Sigma or Suricata rules possible.**
The operator's open directory and configuration artifact do not expose a C2 channel. The OpenClaw gateway (port 18789) is a local loopback service. Its external C2 behavior, if any, is not documented in the captured evidence and should not be fabricated. If future evidence documents the OpenClaw gateway's external egress protocol, C2-traffic rules should be added.

**Gap 4: OpenClaw skill execution behavior is undocumented in the captured evidence.**
The `settings.local.json` artifact documents the install and gateway-bring-up chain but does not specify which OpenClaw skills the operator deployed or what attack capabilities they exercised. Related investigation material documents OpenClaw's broader attack-capability ecosystem, but that evidence belongs to those cases, not this artifact. No rules have been written for specific OpenClaw skill execution behavior from this case's evidence.

**Gap 5: Attacker evasion by tooling substitution.**
The allowlist-customization technique, pre-approving `curl|bash`, a global npm install, and listener bring-up in `settings.local.json`, is fully documented in this report. An operator who reads it can substitute any other AI-agent framework for OpenClaw and bypass every OpenClaw-specific string rule. The resilience detection anchor is the broader `curl|bash`-in-allowlist YARA Hunting rule and the generic process-creation pattern, which fire on the structural pattern regardless of tool name. Neither can be evaded by swapping the domain or package name without also changing the `curl|bash` distribution model itself.

**Gap 6: macOS-specific `open` command detection not covered.**
Allowlist entry 7 (`Bash(open http://127.0.0.1:18789/)`) uses the macOS `open` command to launch the OpenClaw gateway UI in the default browser. A Sigma rule for `process_creation` matching `Image|endswith: '/open'` with `CommandLine|contains: '127.0.0.1:18789'` is technically feasible on macOS with Sysmon for macOS or ESA telemetry, but was not written because the `open` command is extremely common on macOS (used by countless legitimate applications) and the port-specific matching alone would produce a high FP rate without additional context. This gap is best addressed by correlating port-18789 listener inventory (host level) with process logs rather than a standalone process-creation rule.

**Gap 7: Parent-process correlation would raise the two Hunting-tier process-execution rules to Detection.**
Both the curl|bash installer rule and the gateway-startup rule cannot distinguish a legitimate developer manually running OpenClaw from Claude Code auto-executing the same command under the attacker-customized allowlist. The campaign's evidence is a static configuration-file artifact, not observed process telemetry, so no parent-process (Claude Code) chain is available to make that distinction. What would raise confidence: telemetry showing Claude Code's own process as the direct parent of the `curl|bash` installer or `openclaw gateway` invocation would support tightening both rules to Detection tier via a `ParentImage` constraint.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
