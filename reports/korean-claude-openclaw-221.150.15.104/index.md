---
title: Korean Claude Code + OpenClaw Operator (221.150.15.104) - Attacker-Customized AI-Agent Permission Allowlist
date: '2026-05-27'
layout: post
permalink: /reports/korean-claude-openclaw-221.150.15.104/
thumbnail: /assets/images/cards/korean-claude-openclaw-221.150.15.104.png
hide: true
unlisted: true
sponsored_by: hunt-io
category: "AI-Augmented Operator Tradecraft"
description: "Capsule sub-report (Case 4 of the AI-Agent-Frameworks investigation): a Korean-language operator's attacker-customized ~/.claude/settings.local.json permission allowlist that pre-approves the OpenClaw install-and-run chain, recovered from an open-directory exposure (221.150.15.104, Korea Telecom). UTA-2026-015."
detection_page: /hunting-detections/korean-claude-openclaw-221.150.15.104-detections/
ioc_feed: /ioc-feeds/korean-claude-openclaw-221.150.15.104-iocs.json
detection_sections:
  - label: "Detection Coverage Summary"
    anchor: "detection-coverage-summary"
  - label: "YARA Rules"
    anchor: "yara-rules"
  - label: "Sigma Rules"
    anchor: "sigma-rules"
  - label: "Coverage Gaps"
    anchor: "coverage-gaps"
ioc_highlights:
  - "221.150.15.104"
  - "openclaw.ai"
  - "~/.claude/settings.local.json"
---

**Campaign Identifier:** Korean-ClaudeCode-Allowlist-OpenClaw-221.150.15.104<br>
**Last Updated:** May 27, 2026<br>
**Threat Level:** MEDIUM

> **Risk vs. Campaign Threat Level:** The allowlist-bypass technique documented in this report scores **HIGH on tradecraft novelty** — it is the campaign's first DEFINITE artifact-level evidence of an attacker pre-customizing an AI-agent CLI's permission allowlist to silence safety prompts for a side-loaded toolkit install. The overall campaign threat level is rated **MEDIUM** because no victims, beacons, intrusions, or downstream impact were observed; the captured evidence is the operator's tradecraft footprint, not a malware sample or active campaign against a named victim. If future evidence ties this operator to a confirmed intrusion or to a named threat actor, the threat level should be reassessed to HIGH.

---

## Bottom Line Up Front

A misconfigured open directory leaked the operator's home filesystem, including co-located Claude Code (`~/.claude/`) and OpenClaw (`~/.openclaw/`) installations. The smoking-gun artifact is the operator's customized permission allowlist: seven pre-approved entries that collectively describe the full OpenClaw install-and-run chain, executed by Claude Code without any safety-prompt interruption.

This is the parent investigation's first DEFINITE artifact-level evidence of an operator deliberately pre-approving an AI-agent CLI's safety-prompt mechanism to streamline toolkit deployment. No malware binary was extracted; no victims were observed. The defender-relevant finding is the **hunt anchor**: any `~/.claude/settings.local.json` whose `permissions.allow` array contains `curl ... | bash`, global-npm-install-of-unfamiliar-package, or local-listener-bring-up entries is a high-priority finding regardless of which specific tooling is referenced.

---

## 1. Executive Summary

This report documents Case 4 of the parent investigation *OpenDirectory - AI-Agent-Frameworks - 2026-05-23*. The case answers a specific question: **how do AI-augmented operators reduce the safety friction of running attack-adjacent toolchains through mainstream AI-agent CLIs?** The captured artifact — the operator's customized `~/.claude/settings.local.json` — gives the first publicly-documented answer to that question at the artifact level.

### What Was Found

An open directory at `http://221.150.15.104:8080/` indexed by Hunt.io on 2026-03-11 exposed the operator's home filesystem, including:
- A complete Anthropic Claude Code installation under `~/.claude/` (Claude Code is Anthropic's command-line AI agent CLI)
- A complete OpenClaw installation under `~/.openclaw/` (OpenClaw is a third-party AI-agent framework distributed via `openclaw.ai` and the npm registry)
- The operator's **customized `~/.claude/settings.local.json`** — 442 bytes, downloadable, with seven pre-approved commands in its `permissions.allow` array

The seven entries collectively pre-authorize Claude Code to (1) fetch and execute the OpenClaw installer via `curl ... | bash`, (2) probe the local environment for Node/npm/brew/pnpm, (3) globally install OpenClaw via npm, (4) run OpenClaw's onboarding flow, (5) fetch the OpenClaw documentation site, (6) start the OpenClaw gateway listener on TCP port 18789, and (7) open the gateway web UI in the operator's default browser. The operator has pre-clicked "Always allow" for the entire OpenClaw bring-up workflow, in advance, before any Claude Code session begins.

### Why This Threat Is Significant

The parent investigation had identified a gap: no prior publicly-documented examples existed of an attacker artifact-level tampering with an AI-agent CLI's per-command safety prompt. This case fills that gap. The defender community had hypothesized this attack pattern based on the design of Claude Code's permission model; this report documents an in-the-wild operator implementation.

Key differentiators that make this case notable:
- **Artifact-level evidence, not theoretical capability.** The captured `settings.local.json` is the operator's actual on-disk configuration, not a security researcher's reconstruction.
- **Reproducible defender hunt anchor.** The file itself is the detection signal; defenders can sweep their developer-class endpoints for `~/.claude/settings.local.json` content matching the documented patterns regardless of whether the operator is targeting OpenClaw, some other tool, or a completely different attack chain.
- **Operator OPSEC paradox.** The same operator who carefully customized the allowlist exposed the entire home directory to the public internet via an open-directory misconfiguration. Allowlist sophistication coexists with residential-ISP exposure — a recurring "AI-integrated mature operator" profile across the parent investigation.

### Key Risk Factors

<table>
<colgroup>
<col style="width: 26%;">
<col style="width: 16%;">
<col style="width: 58%;">
</colgroup>
<thead>
<tr><th>Risk Dimension</th><th>Score (X/10)</th><th>Rationale</th></tr>
</thead>
<tbody>
<tr><td>AI-Safety-Control Tampering</td><td>9/10</td><td>Direct artifact-level evidence of attacker disabling Claude Code's per-command safety-prompt mechanism for the seven pre-authorized commands. The technique is reproducible by any operator who reads this report; the defensive value is the hunt anchor, not the technique-secrecy.</td></tr>
<tr><td>Tradecraft Novelty</td><td>9/10</td><td>First DEFINITE artifact-level documentation of attacker-customized AI-agent CLI allowlists in the public threat-intel corpus as of the parent investigation publication date.</td></tr>
<tr><td>Active-Intrusion Risk</td><td>3/10</td><td>No victims observed, no beacons, no C2 traffic, no exfiltration evidence. The captured artifact is the operator's local tradecraft footprint, not a campaign against a named target.</td></tr>
<tr><td>Defender-Hunt Utility</td><td>8/10</td><td>The artifact provides immediately-actionable filesystem and content hunt criteria deployable across developer endpoint estates without environment-specific tuning.</td></tr>
<tr><td>Operator Reproducibility</td><td>7/10</td><td>OpenClaw is publicly distributed; the allowlist technique is documented in Anthropic's Claude Code documentation. The combined technique requires only minutes of operator effort. Wider operator adoption is plausible going forward.</td></tr>
<tr><td>Attribution Confidence</td><td>3/10</td><td>UTA-2026-015 LOW (55%). Korean-language inference is curator-derived from Hunt.io; no independent corroboration in the captured artifact (file contents are English). Residential-ISP attribution carries no actor-clustering signal.</td></tr>
</tbody>
</table>

**Overall risk score: 6.0/10 (MEDIUM)** — the score weights tradecraft significance (AI-Safety-Control Tampering 9/10, Tradecraft Novelty 9/10, Defender-Hunt Utility 8/10) against the absence of active intrusion or named-victim evidence (Active-Intrusion Risk 3/10, Attribution Confidence 3/10). High novelty at low intrusion risk produces MEDIUM overall, not HIGH or CRITICAL.

### Threat Actor

The operator is tracked as **UTA-2026-015** *(an internal tracking label used by The Hunters Ledger — see Section 6)*. Confidence is **LOW (55%)**. The strongest attribution signal is the Korean-language curator label from Hunt.io and the Korea Telecom AS4766 residential exposure; the captured `settings.local.json` itself contains only English text and provides no independent attribution corroboration. No clustering with publicly-named threat actors was identified. **Disposition status:** The operator's residential exposure at `221.150.15.104:8080` remained reachable as of investigation close (2026-05-23); no vendor takedown action applies to this tradecraft-observation case, which has no named victim and no vendor-actionable artifact requiring removal.

### For Technical Teams

Immediate priorities for SOC and threat-hunting teams:

- **Filesystem hunt** — Inventory `~/.claude/settings.local.json` (and `<project>/.claude/settings.local.json`) presence and content across developer-class and admin-class endpoints. The detection rule file (see Section 8) provides ready-to-deploy YARA and Sigma patterns. Coverage starts at Section 4.1 and Section 4.2.
- **Network egress monitoring** — Add `openclaw.ai`, `docs.openclaw.ai`, and `lightmake.site` to DNS-monitoring watchlists. Coverage in Section 7 IOC summary.
- **Listening-port inventory** — Surface TCP port `18789` bindings on developer-class endpoints. Coverage in Section 4.5.
- **Tool-specific detection generalization** — The technique generalizes beyond OpenClaw. The hunt criteria documented in Section 4.2 catch any operator-customized allowlist of the same shape, not just this specific operator. Coverage in Section 8.
- **Disclosure coordination** — Anthropic and OpenClaw maintainers have been notified via the parent investigation's vendor notification process. No customer-side disclosure work is recommended at this report's scope.

---

## 2. Campaign Context

This report is a **capsule sub-report** of the parent investigation *OpenDirectory - AI-Agent-Frameworks - 2026-05-23*. Case 4 within that parent investigation captured the Korean operator's residential exposure as one of multiple cases documenting how AI-augmented operators integrate mainstream AI-agent CLIs (Claude Code, Gemini CLI) with side-loaded dual-use agent frameworks (OpenClaw, Hermes Agent). Section 4.4 of the umbrella report provides the capsule-depth coverage; this sub-report expands that coverage to the artifact level without contradicting the umbrella framing.

### Discovery Method

Hunt.io's open-directory crawler indexed the operator's exposed home directory at `http://221.150.15.104:8080/` on **2026-03-11**. The Hunt.io curator labelled the host "Korean operator" based on regional ISP and language-environment indicators. The case was selected during the parent investigation's host-prioritization review on 2026-05-23, which prioritized hosts exhibiting co-located mainstream + side-loaded AI-agent installations.

### Named-Victim Status

**None confirmed.** The captured filesystem evidence contains no victim identities, no exfiltrated data, no email targets, no compromised credentials, and no traffic logs against named victim infrastructure. The operator's `~/.claude/history.jsonl` (Claude Code session command history) and `~/.claude/projects/` (transcript directory) were deliberately not pulled per The Hunters Ledger credential-redaction discipline — pulling those files risked exposing the operator's session contents in a manner that risks surfacing third-party identities when the operator has used Claude Code against specific named targets. The decision to skip session-content extraction is consistent with the project standard: defenders gain nothing operationally usable from operator session transcripts in a tradecraft-observation case, and the privacy risk to incidentally-mentioned third parties is non-trivial.

### Operator Residential Exposure Pattern

The host is a **direct residential exposure**. AS4766 is Korea Telecom, the largest Korean ISP, and the IP block is consistent with a consumer broadband connection rather than a VPS, cloud-rented infrastructure, or anonymization tunnel exit. The operator did not use VPN, Tor, or proxy infrastructure to obscure the source — the open-directory was reachable directly at the operator's home IP for at least the 73-day window between Hunt.io first-seen (2026-03-11) and investigation close (2026-05-23). This residential exposure pattern is recurrent across the parent investigation's "AI-integrated mature operator" class — operators who exhibit allowlist-tuning sophistication coexisting with carelessness about wider OPSEC.

### Scope Boundary

This sub-report covers **only the operator tradecraft captured in the `settings.local.json` artifact** and its immediate filesystem context. Cross-cutting findings from the parent investigation (operator-class taxonomy, AI-vendor distribution analysis, the "5 novel TTPs" pattern) are out of scope and remain in the umbrella report. Where helpful, this sub-report references umbrella sections by number; it does not restate umbrella analysis.

---

## 3. Technical Classification

This case is **not a malware analysis report.** It is an **operator-tradecraft analysis report.** The captured evidence is not a malicious binary, an exploit payload, or a packed dropper — it is a 442-byte JSON configuration file that documents how the operator has reconfigured a mainstream AI-agent CLI to lower safety friction.

### Classification Attributes

| Attribute | Value | Confidence |
|---|---|---|
| Threat category | AI-augmented operator tradecraft (capability-building) | DEFINITE |
| Product type | Configuration artifact + co-located AI-agent framework toolkit | DEFINITE |
| Primary captured artifact | `~/.claude/settings.local.json` (442 bytes JSON) | DEFINITE |
| Secondary captured evidence | `~/.openclaw/` directory presence; `~/.openclaw/completions/openclaw.ps1` | DEFINITE |
| Malware binary | None extracted; analysis subject is configuration tradecraft | DEFINITE |
| Threat actor | UTA-2026-015 (internal designation) | LOW (55%) |
| Operator class | AI-integrated mature operator (per umbrella Section 4.10 taxonomy) | MODERATE |
| Sophistication | Mid-tier-selective (allowlist tuning + residential exposure paradox) | MODERATE |
| Target profile | Unknown — no victims observed | INSUFFICIENT |
| Primary motivation | Unknown — capability-building inference only | LOW |

### File Identifiers (Smoking-Gun Artifact)

| Field | Value |
|---|---|
| Filename | `settings.local.json` |
| Directory | `~/.claude/` |
| Size | 442 bytes |
| Format | UTF-8 JSON (RFC 8259) |
| Schema | Anthropic Claude Code per-directory or global permission allowlist schema |
| Discovery URL | `http://221.150.15.104:8080/.claude/settings.local.json` (via open directory) |
| Preserved at | Offline investigation evidence archive (The Hunters Ledger) |
| Hashable? | Yes, but hash-based detection is operationally less useful than content-based detection because operators can trivially produce per-host or per-project variants with different byte sequences |

### Why This Is a Capsule-Depth Case Rather Than a Full Malware Analysis

Standard Stages 1, 2-research, 2-infrastructure, and 3 of The Hunters Ledger workflow were intentionally skipped:

- **No malware binary** to reverse-engineer or sandbox. The smoking-gun artifact is a 442-byte text configuration file with no executable code.
- **Prior-art research is complete** in the parent investigation umbrella; no additional research-analyst work is required for this single sub-case.
- **Infrastructure has no pivot value.** The host is a single residential Korea Telecom IP. Infrastructure-pivoting playbooks against residential ISPs return no actor-clustering signal.
- **Attribution is already assigned.** UTA-2026-015 LOW (55%) was determined in the parent investigation; the sub-report reflects that determination without re-running the full attribution workflow.

### Architectural Pattern Summary

The operator's host runs two AI-agent CLIs side-by-side:

1. **Anthropic Claude Code** as the human-facing AI assistant (chat, planning, coding workflow). Claude Code is the mainstream agent CLI — it provides the natural-language interface and the underlying reasoning capability via Anthropic's Claude models.
2. **OpenClaw** as a local-gateway service on TCP port 18789. OpenClaw is an AI-agent framework that exposes additional skills and capabilities to the operator's agent workflow that mainstream Claude Code does not natively support.

The seven-entry `permissions.allow` array is the **glue** between the two: it is the operator's mechanism for telling Claude Code "install and run OpenClaw without asking me for confirmation." Section 4 documents the artifact and its mechanism in technical depth.

---

## 4. Technical Capabilities Deep-Dive

This section examines the smoking-gun artifact in detail, the permission-prompt bypass mechanism it abuses, the co-located Claude Code + OpenClaw architecture, the OpenClaw distribution ecosystem the allowlist points at, and the gateway service on port 18789 that the allowlist authorizes Claude Code to start.

### 4.1 The Smoking-Gun Artifact

The full content of the operator's `~/.claude/settings.local.json` (442 bytes, UTF-8 JSON, English-language values throughout):

```json
{
  "permissions": {
    "allow": [
      "Bash(curl -fsSL https://openclaw.ai/install.sh | bash)",
      "Bash(which node && node --version && which npm && npm --version 2>/dev/null; which brew 2>/dev/null; which pnpm 2>/dev/null)",
      "Bash(npm i -g openclaw)",
      "Bash(openclaw onboard)",
      "WebFetch(domain:docs.openclaw.ai)",
      "Bash(openclaw gateway --port 18789)",
      "Bash(open http://127.0.0.1:18789/)"
    ]
  }
}
```

The schema is Anthropic Claude Code's documented per-directory and global permission-allowlist format. The single top-level key `permissions` contains a sub-object whose `allow` array enumerates exact command strings that the operator has elected to pre-approve.

**Seven-entry breakdown:**

| # | Command | Purpose | Risk Category |
|---|---|---|---|
| 1 | `Bash(curl -fsSL https://openclaw.ai/install.sh \| bash)` | Fetch and pipe-execute the OpenClaw installer | Remote-code execution via the `curl \| bash` distribution pattern |
| 2 | `Bash(which node && node --version && which npm && npm --version 2>/dev/null; which brew 2>/dev/null; which pnpm 2>/dev/null)` | Environment probe — enumerate Node.js, npm, Homebrew, pnpm presence | System information discovery |
| 3 | `Bash(npm i -g openclaw)` | Globally install OpenClaw via npm (alternative install path) | Package-manager-mediated tool acquisition |
| 4 | `Bash(openclaw onboard)` | Run OpenClaw's first-run onboarding workflow | Toolkit bring-up |
| 5 | `WebFetch(domain:docs.openclaw.ai)` | Pre-authorize Claude Code to fetch the OpenClaw documentation site | Documentation consumption (informs subsequent operator actions) |
| 6 | `Bash(openclaw gateway --port 18789)` | Start the OpenClaw local gateway listener on TCP port 18789 | Local service / proxy bring-up |
| 7 | `Bash(open http://127.0.0.1:18789/)` | Open the OpenClaw gateway web UI in the operator's default browser | UI activation (macOS-specific — `open` is the macOS command for "open the default app for this URL") |

**The macOS signal.** Entry 7 uses the `open` command — the macOS equivalent of Linux `xdg-open` or Windows `start`. This strongly suggests the operator's host is macOS or a macOS-compatible environment. The presence of `~/.openclaw/completions/openclaw.ps1` (a PowerShell completion script) is initially confusing — it yields three candidate readings: (a) the operator uses PowerShell-on-macOS, (b) OpenClaw ships the PowerShell completion as part of its standard distribution regardless of host OS, or (c) the operator has also installed OpenClaw on a separate Windows host and the two installations have synced via some mechanism. The most parsimonious reading is (b): the file is part of OpenClaw's standard install layout, not affirmative evidence the operator runs PowerShell on this host. The macOS hypothesis remains the higher-confidence read based on entry 7.

**The collective effect.** The seven entries describe a complete sequence: probe the environment → fetch the installer → run the installer → globally install via npm (redundant with the curl install but pre-authorized as an alternative path) → run onboarding → fetch documentation → start the gateway service → open the UI. The operator has compressed what would normally be a multi-step interactive workflow with safety prompts at every step into a single pre-approved chain.

### 4.2 The Permission-Allowlist Bypass Mechanism

> **Analyst note:** This section explains *how* the operator's pre-approved allowlist defeats Claude Code's safety-prompt mechanism. The mechanism is documented in Anthropic's Claude Code reference material — it is not a vulnerability or a bug. It is a deliberate UX feature that the operator has weaponized against its intended purpose. Defenders need to understand the mechanism to recognize the abuse pattern at the file-content level.

#### How Claude Code's Per-Command Safety Prompt Normally Works

Claude Code, like other AI-agent CLIs that can execute arbitrary local commands, implements a safety-prompt mechanism before running potentially-dangerous operations. When the AI agent proposes to run a shell command, fetch a URL, or perform any action in a user-configurable category (Bash, WebFetch, file edit, etc.), Claude Code surfaces the proposed action to the operator and waits for an explicit approval ("yes/no") response. This is the per-command safety prompt.

The prompt is the user's safety gate. It is the single point where an operator can intervene if the AI proposes something unintended, malicious, or simply unwise. The prompt converts an autonomous AI agent into a supervised one — the user reviews and approves each potentially-impactful action.

#### How the Allowlist Pre-Approval Mechanism Works

The `settings.local.json` `permissions.allow` array is documented as a UX convenience: if a user knows in advance that they want a specific exact command string approved (for example, a repeated lint command in a development workflow), they can list that exact string in the allowlist. Claude Code then skips the prompt for matches against allowlist entries and runs the command directly.

The semantic is **exact-match against the command string** — entry `Bash(npm i -g openclaw)` will skip the prompt for that specific command, but not for `Bash(npm i -g something-else)` and not for `Bash(npm install openclaw)`. The operator must enumerate each exact form they want pre-approved.

The mechanism design choice is reasonable for the intended use case (repeated dev-loop commands a developer types dozens of times per day). It is the operator who turns it into a safety-control bypass by enumerating the install-and-run sequence for a side-loaded toolkit before the session begins.

#### How the Operator Weaponizes the Mechanism

The operator's strategy is straightforward: write the `settings.local.json` ahead of time, populate the `permissions.allow` array with every command needed to fetch and run OpenClaw, save the file, and start the Claude Code session. From that point on, when the operator asks Claude Code to install OpenClaw, Claude Code will run the entire seven-step chain without surfacing a single safety prompt.

The defender-relevant observation is that this is **not a Claude Code vulnerability** — it is operator misuse of a documented feature. Anthropic's per-command safety-prompt mechanism works as designed. The allowlist mechanism works as designed. The operator's `settings.local.json` file is the artifact that demonstrates the misuse pattern. The defensive opportunity is not to fix Claude Code (it is already correct) but to **hunt for the artifact** on hosts where the operator has applied the technique.

#### Why This Is the First DEFINITE Artifact-Level Evidence

The defender community has discussed the theoretical risk of attacker-customized AI-agent allowlists since Claude Code's permission model was first published. What was missing was an **in-the-wild operator-customized example** (in the surveyed public threat-intel corpus as of 2026-05-23) that defenders can point to as concrete documentation of "what the abuse pattern looks like on disk."

This case provides that example. The 442-byte file is downloadable, the seven-entry sequence is reproducible by any defender who reads it, and the pattern generalizes immediately — the same hunt approach finds operator-customized allowlists pointing at *any* side-loaded toolkit, not just OpenClaw. Sections 7 (IOCs) and 8 (detection) translate the artifact into concrete defender hunt queries.

#### Detection Strategy at the File Level

The most reliable detection signal is the **combination** of:

1. **File path** — `~/.claude/settings.local.json` (global) or `<project>/.claude/settings.local.json` (per-project), the canonical Claude Code allowlist locations.
2. **Content patterns inside `permissions.allow`** — any of the following:
   - `Bash(curl ... | bash)` or `Bash(curl ... | sh)` patterns
   - `Bash(wget ... | bash)` variations
   - Global npm install of an unfamiliar package (`Bash(npm i -g <package>)` or `Bash(npm install -g <package>)`)
   - WebFetch authorization for a non-vendor or non-corporate-allowlisted documentation domain (`WebFetch(domain:<unknown-domain>)`)
   - Local listener invocation patterns (`Bash(<tool> --port <N>)`, `Bash(<tool> serve)`, `Bash(<tool> gateway ...)` that bring up a listening service)
   - Direct browser-launch commands targeting `127.0.0.1` URLs (`Bash(open http://127.0.0.1:<N>/)`, `Bash(xdg-open http://localhost:<N>/)`)

The combination is more reliable than any single signal — defenders who hunt only for `curl | bash` patterns will catch legitimate developer workflows (e.g., a developer pre-approving a known internal-tooling installer). Defenders who hunt only for the file path will catch every Claude Code user. The combination catches operators who have configured a pre-approved install-and-run chain for unfamiliar software.

### 4.3 Co-Located Architecture (Claude Code + OpenClaw Side-by-Side)

The exposed home directory contains both `~/.claude/` (Anthropic Claude Code) and `~/.openclaw/` (OpenClaw). The architectural pattern observed:

1. **Claude Code** is the human-facing layer. The operator chats with Claude Code, requests tasks, reviews proposed actions (or in the pre-approved cases, doesn't review them), and consumes Claude's outputs. The operator's mental model is "I am working with Claude."
2. **OpenClaw** runs as a local gateway service on port 18789. Per the allowlist entry 6, Claude Code starts OpenClaw via `Bash(openclaw gateway --port 18789)`. Once started, OpenClaw provides additional skills and capabilities to the operator's workflow.
3. **The gateway pattern** means OpenClaw is positioned as a local backend that other tools (including Claude Code itself, in certain integration modes) can connect to. The operator's workflow is mediated by both — Claude Code provides reasoning and natural language; OpenClaw provides the extended skill set.

This co-location is the architectural model the parent investigation has independently observed in Case 2 (a Turkish operator targeting a regional insurance company with a similar Gemini CLI + Hermes Agent pairing) and in this case. The pattern is: combine a polished mainstream agent CLI with a dual-use side-loaded agent toolkit. The mainstream CLI provides operator polish; the side-loaded toolkit provides capabilities the mainstream CLI does not natively support.

**Why this matters at the architecture level.** Defenders who think "the operator's AI tool is Claude Code" or "the operator's AI tool is OpenClaw" — singular tool framing — will misjudge the threat surface. The operator's tool is **both, integrated**. Defenders need to inventory both, monitor both, and understand the integration pattern. A defensive posture that allows mainstream AI CLIs but blocks all side-loaded toolkits will fail to catch the integration pattern unless the side-loaded toolkit specifically is detected.

### 4.4 The OpenClaw Distribution Ecosystem

The allowlist references three distribution channels for OpenClaw, all owned or controlled by the OpenClaw maintainers:

| Channel | Indicator | Role |
|---|---|---|
| Shell installer | `https://openclaw.ai/install.sh` | Primary installer hosted on OpenClaw's product domain. Uses the `curl -fsSL <URL> \| bash` pattern, a well-documented high-risk distribution mechanism where the operator effectively grants the installer source full ability to write arbitrary code into the operator's environment. |
| npm registry | `npm i -g openclaw` (package name `openclaw`) | Global npm install — alternative path to the shell installer. Published to the public npmjs.com registry. |
| Documentation host | `docs.openclaw.ai` (referenced via Claude Code `WebFetch`) | Operator-pre-authorized doc fetch. The defender signal here is that Claude Code is being used to consume OpenClaw documentation, not just to install and run the tool — the operator is treating OpenClaw as a capability they will use via Claude Code's natural-language interface, with OpenClaw's docs as a contextual reference. |

The parent investigation additionally documents **`lightmake.site`** as an OpenClaw-adjacent infrastructure component referenced in the broader OpenClaw ecosystem's hosting-and-egress signature. It was observed in the umbrella report's multi-case OpenClaw ecosystem infrastructure analysis at MODERATE confidence — not in the Case 4 artifact itself. `lightmake.site` does not appear in the captured Case 4 allowlist, but is included in the IOC feed (see Section 7) as a documented OpenClaw-ecosystem domain that defenders should monitor alongside the Case-4-direct indicators; its evidentiary basis for this specific case is thinner than the DEFINITE-confidence Case 4 domains.

**Important framing — OpenClaw's public-distribution status.** OpenClaw is a **publicly-distributed AI-agent framework product.** Its existence and broad availability does not make installing it inherently malicious. The dual-use pattern is similar to other tools (Metasploit, Cobalt Strike, Sliver) that have legitimate-purpose adopters and abusive-use populations.

The defender-relevant finding is **not** "OpenClaw is malware." The defender-relevant finding is the **combination** of:

- An attacker-customized Claude Code allowlist (the artifact)
- The specific seven-command pre-approval sequence pointing at OpenClaw
- The host's broader operator-exposed contents (the open directory, the residential Korea Telecom ISP, the parent investigation's prior-art context tying this profile to operator-class behavior)

Any single element in isolation is ambiguous. The combination is the diagnostic signal.

### 4.5 Gateway Service on TCP Port 18789

Allowlist entries 6 and 7 collectively bring up the OpenClaw gateway service. The gateway is OpenClaw's local-control-plane component — it listens on a TCP port and exposes a web UI that the operator interacts with.

**What the gateway does (from operator-side evidence).** The captured artifact authorizes `Bash(openclaw gateway --port 18789)` and immediately follows it with `Bash(open http://127.0.0.1:18789/)` (open the gateway UI in the default browser). Together, these establish that:
- The gateway binds to a TCP port (default `18789`)
- The gateway exposes an HTTP web UI on that port at the root URL `/`
- The operator's intended next action after bring-up is to interact with the gateway via that web UI

The captured artifact does not document what the gateway UI **contains** — that would require running OpenClaw and observing the UI directly, which is out of scope for this report (the operator's instance was not analyzed live; only the operator's filesystem was inspected). The umbrella report's broader OpenClaw ecosystem documentation includes some additional context, but is similarly bounded by what is observable from operator-side artifacts.

**Defender implications of the gateway.**

- **Listening-port inventory.** TCP port `18789` bound on a developer-class or admin-class endpoint is a candidate signal. The port number is not standardized in any other widely-used service registry, so a 18789-binding is highly specific to OpenClaw's default configuration. (Operators can change the port — `--port` is configurable — but the default is documented and the captured operator's allowlist uses the default.)
- **Loopback-only scope.** The captured allowlist binds to `127.0.0.1:18789`, the loopback interface — meaning the gateway is reachable only from the host itself, not from the network. This is consistent with OpenClaw's typical deployment model (the gateway mediates between local tools, not network-remote callers). Defenders should not expect to find external port-18789 exposures unless the operator has deliberately bound to `0.0.0.0:18789` or set up a port-forward. The captured artifact has no such evidence.
- **Process-tree signal.** When the gateway starts via `Bash(openclaw gateway --port 18789)` executed by Claude Code, the process tree on the host will show a Claude Code parent process spawning a Bash subprocess that exec's `openclaw gateway`. Endpoint detection that traces process lineage can flag the pattern: Claude Code → Bash → unfamiliar gateway listener.

**Why this matters at the kill-chain level.** The gateway is the operational hub for the operator's tool integration. Detecting the gateway bring-up — either via the allowlist content scan, the listening-port inventory, or the process-tree lineage — gives defenders multiple independent detection paths against the same underlying operator workflow. Defense-in-depth is achievable here even without any of the individual signals being uniquely diagnostic in isolation.

---

## 5. MITRE ATT&CK Mapping

> **Analyst note:** This case's behaviors map to MITRE ATT&CK in the companion detection file, where each technique is tied to its detection logic. To keep this report focused, the full technique table is not duplicated inline.

The full ATT&CK technique mapping for this case is maintained alongside the detection rules on the **[detection rules page →](https://the-hunters-ledger.com/hunting-detections/korean-claude-openclaw-221.150.15.104-detections/)**.

---

## 6. Threat Actor Assessment

> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-2026-015 is an internal tracking designation assigned by The Hunters Ledger to actors observed across analysis who cannot yet be linked to a publicly named threat group. This label will not appear in external threat intelligence feeds or vendor reports — it is specific to this publication. If future evidence links this activity to a known named actor, the designation will be retired and updated accordingly.

### Confidence Statement

```
Threat Actor: UTA-2026-015 (Korean Claude Code + OpenClaw operator)
Confidence:   LOW (55%)

Why this confidence:
  - Operator language: Korean (inferred from Hunt.io curator label and regional ISP)
  - Operator infrastructure: residential Korea Telecom AS4766 IP
  - Operator tradecraft: documented (Claude Code allowlist + OpenClaw integration)
  - Operator-class taxonomy match: AI-integrated mature operator (per parent investigation)

What's missing:
  - Independent corroboration of Korean-language attribution from the captured artifact
    (the settings.local.json file content is English; Korean-language signal is curator-derived)
  - Operator-to-actor linkage: no clustering with publicly-named threat groups
  - Victim-side telemetry: no observed targeting allows TTPs-against-victim analysis
  - Cross-host overlaps: residential ISP carries no actor-clustering signal

What would increase confidence:
  - Live operator activity captured against a named victim (raises confidence to MODERATE)
  - Cross-host overlap with another residentially-exposed operator using the same allowlist
    template (raises confidence to HIGH if multiple hosts match)
  - Tier-1 attribution from government or major vendor (would raise to DEFINITE)
```

### Language Attribution

Per CLAUDE.md ATTRIBUTION CONFIDENCE SCALE language precision, the Korean-language attribution is at LOW confidence and is described as **"weak indicators suggest"** rather than any stronger claim:

- Weak indicators suggest the operator is Korean-speaking, based on (a) Hunt.io's curator-applied "Korean operator" label on the open-directory entry, and (b) the residential Korea Telecom AS4766 hosting.
- The captured `settings.local.json` content is entirely English-language. No Korean character strings, no Korean comments, no Korean filenames were captured in the artifact itself.
- Korean-language attribution at LOW confidence does not support any claim about Korean state-affiliated activity, North Korean actors (Lazarus, Kimsuky, ScarCruft), or South Korean criminal-actor clusters. Those associations would require substantially stronger evidence than this case provides.

### Operator-Class Taxonomy

UTA-2026-015 fits the **"AI-integrated mature operator"** profile from the parent investigation umbrella's Section 4.10 taxonomy:

- **Allowlist tuning sophistication.** The operator wrote a deliberate seven-entry pre-approval sequence covering the full OpenClaw bring-up workflow. This is not the work of an opportunistic scripter — it reflects planning, awareness of Claude Code's permission model, and deliberate friction-reduction.
- **Side-loaded toolkit adoption.** The operator chose Claude Code + OpenClaw together. Mainstream-only operators would use Claude Code alone; opportunistic operators would not install OpenClaw at all. This combined adoption is characteristic of operators who treat their AI tooling as a deliberate operational stack.
- **Wider-OPSEC gap.** The same operator exposed the entire home directory to the public internet via an open-directory misconfiguration. Sophisticated operators do not do this. The combination of allowlist-tuning sophistication + residential exposure carelessness is the "mature operator paradox" — competence in one area, complete failure in another.

This paradox is recurrent across the parent investigation's cases. The most parsimonious interpretation is that operators who specialize in AI-augmented offense are early in the discipline's maturity curve — the techniques are novel, the operators are technically capable in their specific niche, but the surrounding OPSEC tradecraft (compartmentalization, infrastructure hygiene, footprint minimization) is not yet caught up. Defenders benefit operationally from this immaturity gap; offenders eventually close it. The window for catching operators via residential-ISP open-directory exposures is finite.

### What This Assessment Does Not Claim

Per CLAUDE.md ATTRIBUTION CONFIDENCE SCALE, language precision at LOW confidence is "weak indicators suggest" and "insufficient evidence for attribution" beyond that. Specifically:

- **No state-actor attribution claimed.** The evidence does not support claims of state-sponsored activity, intelligence-service involvement, or alignment with any named APT.
- **No criminal-cluster attribution claimed.** The evidence does not support claims of involvement in any named criminal cluster (RaaS group, IAB ring, infostealer crew).
- **No victim attribution claimed.** No victims were observed. The case is tradecraft observation only.
- **No "first-of-kind operator" claim.** This is the first DEFINITE artifact-level evidence of the allowlist-bypass technique (in the surveyed public threat-intel corpus as of 2026-05-23). It is not necessarily the first operator to use the technique — earlier adopters may exist who were not caught with their home directory exposed.

---

## 7. Indicators of Compromise

> **Analyst note:** The complete IOC set for this case is published as a machine-readable JSON feed for direct SIEM/EDR ingestion — it is not duplicated inline here. The highest-priority indicators are also surfaced in the IOC panel (fingerprint icon) on this page.

**Full IOC feed:** [`/ioc-feeds/korean-claude-openclaw-221.150.15.104-iocs.json`](https://the-hunters-ledger.com/ioc-feeds/korean-claude-openclaw-221.150.15.104-iocs.json) — every indicator for this case, with type / confidence / recommended action.

---

## 8. Detection and Response Guidance

Detection rules (YARA, Sigma) covering the file-content patterns documented in Section 4.2 are provided in:

**[`/hunting-detections/korean-claude-openclaw-221.150.15.104-detections/`](https://the-hunters-ledger.com/hunting-detections/korean-claude-openclaw-221.150.15.104-detections/)**

The detection file follows The Hunters Ledger conventions (CC BY-NC 4.0 license, "The Hunters Ledger" author field on all rules, YAML front matter, no body H1 title). Defenders should deploy the rules per their internal detection-engineering processes; this report does not prescribe deployment specifics.

### Detection Strategy at the Category Level

**Deployment-scope discipline.** On developer-class endpoints (workstations where engineering, DevOps, or data-science staff routinely install third-party CLIs and SDKs), all three paths below will produce a non-trivial false-positive rate — developers legitimately install unfamiliar tools, and some `settings.local.json` allowlist entries reflect normal developer workflow. The highest-signal targets are **server-class endpoints, jump hosts, CI/CD agent nodes, and non-developer workstations** where Claude Code presence is itself anomalous, not just the allowlist content. For confirmed developer-class endpoints, the recommended approach is **allowlist content review** (is this a known-authorized package from a recognized vendor?) rather than automatic blocking or isolation.

The detection strategy is **three independent paths against the same operator workflow**, so defenders catch the activity even if any one path is missed:

**Path 1 — Filesystem content hunt.** YARA rule scanning `~/.claude/settings.local.json` and `<project>/.claude/settings.local.json` for the documented allowlist entry patterns. This is the primary detection path and has the broadest applicability — it catches operators using the technique against any tool, not just OpenClaw.

**Path 2 — Process-tree lineage.** Sigma rule for Claude Code parent process spawning Bash subprocesses that exec `curl ... | bash`, global npm installs of unfamiliar packages, or local listener bring-up commands. This is the runtime detection path — it catches the abuse pattern when the allowlist is actually being used, not just when the file is statically present.

**Path 3 — Listening-port inventory.** Endpoint inventory queries surfacing TCP port `18789` bindings on developer-class and admin-class endpoints. This is the post-hoc detection path — it catches a host where the OpenClaw gateway is currently running, regardless of how it was started.

### Response Orientation

This is not an incident response guide. Defenders with confirmed positive findings should engage their internal IR teams or external IR providers; that workflow is out of scope for this publication. The orientation below covers only what to address.

**Detection priorities (hunt these first):**
- Filesystem presence of `~/.claude/settings.local.json` and `<project>/.claude/settings.local.json` containing pre-approved `curl ... | bash` or global npm-install patterns
- Live process tree showing Claude Code → Bash → `openclaw` or comparable side-loaded toolkit invocation
- TCP port `18789` bindings on developer-class endpoints

**Persistence targets (look for and remove):**
- The `settings.local.json` allowlist file itself (the artifact lives on disk and persists across Claude Code sessions until removed)
- Any related `~/.openclaw/` installation if the host is not authorized to run OpenClaw
- The npm-global package directory entry for `openclaw` if installed via `npm i -g`

**Containment categories:**
- Isolate hosts where the abuse pattern is confirmed
- Add the documented tooling domains to network egress block lists for non-developer hosts
- Sweep adjacent developer endpoints in the same environment for the same allowlist pattern
- Capture forensic images of the affected host's home directory before remediation (`~/.claude/`, `~/.openclaw/`, `~/.bash_history`, `~/.zsh_history`)

**Vendor coordination (separate from per-host containment):** If the activity is part of a broader incident with identified victims or a vendor-actionable artifact, engage Anthropic and OpenClaw maintainers via their respective security disclosure channels. This is a coordination action distinct from per-host containment; it does not apply to tradecraft-observation cases without confirmed victims.

---

## 9. Confidence Summary

Findings organized by confidence level for the higher-level view. The body of the report attaches per-claim confidence inline; this summary is the consolidated index.

### DEFINITE (direct evidence, no ambiguity)

- The `~/.claude/settings.local.json` file exists at the captured location with the seven-entry `permissions.allow` array documented in Section 4.1
- The file size is 442 bytes (UTF-8 JSON)
- The host is `221.150.15.104` on AS4766 Korea Telecom
- The open directory was reachable at `http://221.150.15.104:8080/` as of Hunt.io first-seen 2026-03-11
- The host filesystem contains `~/.openclaw/` co-located with `~/.claude/`
- The host filesystem contains `~/.openclaw/completions/openclaw.ps1`
- The artifact is direct evidence of attacker-modified Claude Code permission-allowlist content (T1562.001 mapping)
- OpenClaw is publicly distributed via `openclaw.ai`, `docs.openclaw.ai`, and the npm registry

### HIGH (strong evidence, minor gaps)

- The seven allowlist entries collectively describe a complete OpenClaw install + bring-up workflow
- The operator's host is likely macOS (entry 7 uses the macOS-specific `open` command)
- The gateway service is intended to listen on TCP port 18789 with loopback scope
- The technique generalizes beyond OpenClaw — any side-loaded toolkit pre-approval follows the same artifact pattern
- The operator OPSEC paradox (allowlist sophistication + residential exposure) is consistent across the parent investigation's "AI-integrated mature operator" class

### MODERATE (reasonable evidence, notable gaps)

- The operator is Korean-speaking (inferred from Hunt.io curator label and regional ISP)
- The operator class is "AI-integrated mature operator" per the parent investigation taxonomy
- The PowerShell completion script is part of OpenClaw's standard distribution rather than evidence the operator runs PowerShell on this host

### LOW (weak or circumstantial evidence)

- Attribution to UTA-2026-015 at 55% confidence
- Operator motivation framing (capability-building inference based on tooling choice)

### INSUFFICIENT (cannot assess)

- Specific victim targeting — no victims observed
- Operator's broader toolkit beyond what the filesystem documents
- Specific OpenClaw skills the operator used (the allowlist documents installation, not specific skill invocations)
- Whether the operator is a single individual, a small team, or a larger group

---

## 10. Analysis Scope, Static and Dynamic Coverage, and Gaps

> **Analyst note:** Standard Hunters Ledger malware analysis reports include sample-level static analysis (binary unpacking, disassembly, string analysis) and dynamic analysis (sandbox detonation, behavioral observation, network capture). This case is a tradecraft-observation report rather than a sample analysis: the captured artifact is a 442-byte configuration JSON, not a malware binary. This section documents what analysis was performed, what was deliberately out of scope, and what evidence gaps remain — so defenders consuming this report can calibrate their reliance on the findings accurately.

### 10.1 Static Analysis Coverage

**Static analysis: not applicable in the traditional malware-RE sense.** No malware binary was captured. The smoking-gun artifact (`settings.local.json`, 442 bytes) is a text configuration file in JSON format. The static findings from that artifact — its full content, the 7-entry permission allowlist, the specific OpenClaw installation chain documented — are reproduced in Section 4.1 and broken down in Sections 4.2 through 4.5. No binary disassembly, packer analysis, or YARA-against-binaries work is in scope because there is no binary to analyze. The two YARA rules in the sister detection file operate against `settings.local.json` text content, not against PE / ELF / Mach-O binaries.

### 10.2 Dynamic Analysis Coverage

**Dynamic analysis: not applicable.** No malware binary was captured to detonate in a sandbox. No live operator-side traffic capture is available. No behavioral analysis from a sandbox detonation is in scope because there is nothing to detonate. The operator's `~/.claude/history.jsonl` (Claude Code session command history) and `~/.claude/projects/` (transcript directory containing operator-to-Claude-Code session content) were deliberately not pulled per The Hunters Ledger credential-redaction discipline — pulling those files would expose operator session contents in a form that risks surfacing third-party identities if the operator used Claude Code against specific named targets. The decision to skip session-content extraction is consistent with the project standard for tradecraft-observation cases.

### 10.3 Coverage Gaps and Open Questions

The following are explicitly out of scope and represent gaps the captured evidence does not close:

| Gap | What is unknown | Why it matters | Resolution path |
|---|---|---|---|
| Operator session content | The contents of `~/.claude/history.jsonl` and `~/.claude/projects/` (operator's actual interactions with Claude Code) were not extracted | These files would document the operator's natural-language prompts to Claude Code — which would in turn document what specific tasks the operator delegated to the AI agent | Not resolvable without re-pulling from the host; deliberately skipped per credential-redaction discipline |
| Specific OpenClaw skills used | The operator's allowlist documents OpenClaw installation, onboarding, and gateway startup — but does not document which specific OpenClaw skills were invoked through Claude Code post-install | Would inform which downstream attacker capabilities the operator wired through the Claude Code + OpenClaw bridge | Requires extraction of OpenClaw's local state directory (`~/.openclaw/` subdirectory contents) plus correlated Claude Code session transcripts |
| Active operations against named victims | No victim identifiers, exfiltrated data, target lists, or attack-against-specific-target evidence was observed in the captured filesystem scope | The capsule case documents tradecraft pre-staging; whether the operator has used the staged toolchain against any specific victim is unknown | Requires Claude Code session content or OpenClaw runtime logs, neither captured |
| Operator full toolkit | Co-located evidence is limited to Claude Code + OpenClaw + standard developer environment (Node, npm) | Operators commonly combine multiple AI agents and conventional tools; whether this operator runs additional tooling beyond what is captured is unknown | Requires deeper filesystem extraction; would require re-pulling additional `~/` subdirectories |
| Operator identity beyond UTA-2026-015 | Korean-language operator inferred from Hunt curator label and parent-investigation analysis; no Cyrillic / Korean text directly observed in the 442-byte allowlist artifact | The LOW 55% UTA confidence reflects this gap — language attribution is corroborated by parent-investigation language analysis but not directly by the smoking-gun artifact alone | Requires additional artifacts containing operator-native-language text |
| Whether OpenClaw skills themselves contain malicious capabilities | OpenClaw is publicly distributed at openclaw.ai with both legitimate-purpose adopters and confirmed-malicious operators across the parent investigation (Case 2 Turkish ARPA and this case) | Determines whether OpenClaw-the-product warrants treatment as a malicious tool, a dual-use tool, or a legitimate tool with abusive populations | Out of scope for this sub-report; would require independent OpenClaw skill catalog audit |

### 10.4 Behavioral Analysis Limits

No kill chain reconstruction is available because no attack chain against any victim was observed. The case documents the operator's pre-staging configuration only — Cyber Kill Chain Stage 1 (Reconnaissance / Weaponization), arguably Stage 2 (Delivery — operator weaponizes their own Claude Code installation as the delivery surface). Stages 3 through 7 (Exploitation through Actions on Objectives) are not in evidence and cannot be reconstructed from the captured artifact.

### 10.5 Confidence Caveats Carried Forward

All findings in this report should be read in light of the gaps above:
- **DEFINITE** confidence claims attach only to artifact-level observations (the JSON content, the 7 allowlist entries, the IP, the ASN, the file path, the port number, the distribution domains).
- **HIGH** confidence claims attach to the technique characterization (the allowlist customization as a Disable or Modify Tools pattern; the operator-class taxonomy fit; the OpenClaw architectural pattern).
- **MODERATE** confidence claims attach to the operator-attribution inferences (Korean language, residential exposure pattern, mid-tier-selective sophistication characterization).
- **LOW** confidence attaches to UTA-2026-015 itself (55% per parent investigation).
- **INSUFFICIENT** evidence is acknowledged for all the gap items in Section 10.3.

Defenders building hunt rules and detection logic from this report should anchor on the DEFINITE artifact-level observations (the file content, the path, the network indicators). The HIGH-and-below confidence content provides interpretive context — useful for understanding the technique, but not the basis for blocking or attribution decisions.

---

## 11. References and Appendices

### Parent Investigation

- **Parent investigation master findings** — the multi-case context for Case 4 (Korean operator with customized Claude Code allowlist) is summarized in the [parent report](/reports/ai-agent-frameworks-2026-05-23/); full working notes are held offline in the investigation archive.
- **Parent investigation host-prioritization working notes** — held offline in the investigation archive; this sub-report is a synthesis of the Host 1 content from that review.
- **Parent report:** [AI-Agent-Frameworks-MultiActor-2026-05-23](/reports/ai-agent-frameworks-2026-05-23/) — Section 4.4 provides the capsule-depth coverage this sub-report expands; Section 4.10 documents the operator-class taxonomy this case fits.
- **Smoking-gun artifact (preserved offline):** the 442-byte `settings.local.json` is held in the offline investigation evidence archive; full content is reproduced in Section 4.1.

### Sister Deliverables (canonical paths)

- **IOC feed:** [`/ioc-feeds/korean-claude-openclaw-221.150.15.104-iocs.json`](https://the-hunters-ledger.com/ioc-feeds/korean-claude-openclaw-221.150.15.104-iocs.json) — Machine-readable IOC package, 18 actionable indicators across 8 categories.
- **Detection rules:** [`/hunting-detections/korean-claude-openclaw-221.150.15.104-detections/`](https://the-hunters-ledger.com/hunting-detections/korean-claude-openclaw-221.150.15.104-detections/) — YARA and Sigma rules covering the file-content patterns documented in Section 4.2.

### External References

- **Anthropic Claude Code documentation** — `https://docs.anthropic.com/en/docs/claude-code` — The canonical reference for Claude Code's permission-allowlist mechanism, including the `settings.local.json` schema and the `permissions.allow` semantics. Defenders unfamiliar with the mechanism should consult this documentation directly to understand the legitimate use case the operator has weaponized.
- **OpenClaw product site** — `https://openclaw.ai/` — The OpenClaw maintainers' product page. Documents the legitimate installation paths (the same paths the operator's allowlist authorizes) and provides context on the framework's intended use.
- **OpenClaw documentation** — `https://docs.openclaw.ai/` — The documentation host referenced in the operator's `WebFetch(domain:docs.openclaw.ai)` allowlist entry.
- **MITRE ATT&CK T1562.001** — `https://attack.mitre.org/techniques/T1562/001/` — Reference for the Disable or Modify Tools technique that captures the allowlist-tampering pattern documented in this case.

### Appendix A — The Hunters Ledger UTA Designation System

UTA designations (Unattributed Threat Actor) are internal tracking labels used by The Hunters Ledger to track threat actors observed in analysis that cannot yet be linked to a publicly named threat group. UTAs are numbered sequentially per calendar year — UTA-2026-015 is the fifteenth UTA designation assigned in 2026 by The Hunters Ledger. The designation is internal: it will not appear in external threat-intelligence feeds, vendor reports, or government attribution statements. If future evidence ties UTA-2026-015 activity to a publicly named actor, the designation will be retired and the relevant The Hunters Ledger publications updated to reference the named actor instead. Defenders consuming The Hunters Ledger reports should treat UTA designations as a stable internal-tracking pointer, not as an external identifier.

### Appendix B — Why This Report Is Capsule-Depth Rather Than Full-Length

Standard Hunters Ledger threat-intel reports follow a multi-stage research pipeline (malware analysis → research → infrastructure analysis → attribution → detection engineering → report writing). For this case, Stages 1, 2-research, 2-infrastructure, and 3 were intentionally compressed:

- **No malware binary** — The smoking-gun artifact is a 442-byte text configuration file. No reverse engineering, sandbox detonation, or unpacker work is applicable.
- **Prior-art research is complete** — The parent investigation umbrella covers the OpenClaw distribution ecosystem, the dual-use framing, and the cross-case operator taxonomy. Repeating that research for a single capsule sub-report adds no value.
- **Infrastructure has no pivot value** — The host is a single residential Korea Telecom IP. Infrastructure-pivoting playbooks against residential ISPs return no actor-clustering signal because residential blocks are shared by tens of thousands of unrelated subscribers.
- **Attribution is already assigned** — UTA-2026-015 LOW 55% was determined in the parent investigation umbrella; the sub-report reflects that determination without re-running the full attribution workflow.

The compressed report structure (target 700–900 lines, focused on artifact analysis + defender hunt anchors) is appropriate for single-case tradecraft-observation sub-reports of a multi-case parent investigation. Defenders looking for full-length malware analysis depth in this report should redirect to other Hunters Ledger publications that cover sample-level malware analysis.

---

© 2026 Joseph. All rights reserved. See LICENSE for terms.





