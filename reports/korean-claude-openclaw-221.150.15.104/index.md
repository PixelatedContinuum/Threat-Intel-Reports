---
title: Korean Claude Code + OpenClaw Operator (221.150.15.104) - Attacker-Customized AI-Agent Permission Allowlist
date: '2026-05-27'
layout: post
permalink: /reports/korean-claude-openclaw-221.150.15.104/
thumbnail: /assets/images/cards/korean-claude-openclaw-221.150.15.104.png
hide: true
sponsored_by: hunt-io
category: "AI-Augmented Operator Tradecraft"
series: ai-agent-frameworks
series_role: member
series_order: 4
description: "Capsule sub-report (Case 4 of the AI-Agent-Frameworks investigation): a Korean-language operator's attacker-customized ~/.claude/settings.local.json permission allowlist that pre-approves the OpenClaw install-and-run chain, recovered from an open-directory exposure (221.150.15.104, Korea Telecom). UTA-2026-015."
detection_page: /hunting-detections/korean-claude-openclaw-221.150.15.104-detections/
ioc_feed: /ioc-feeds/korean-claude-openclaw-221.150.15.104-iocs.json
detection_sections:
  - label: "YARA Rules"
    anchor: "#yara-rules"
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
ioc_highlights:
  - "221.150.15.104"
  - "openclaw.ai"
  - "~/.claude/settings.local.json"
stix_bundle: /stix/korean-claude-openclaw-221.150.15.104.json
---

**Campaign Identifier:** Korean-ClaudeCode-Allowlist-OpenClaw-221.150.15.104<br>
**Last Updated:** May 27, 2026<br>
**Threat Level:** MEDIUM

> **Risk vs. Campaign Threat Level:** The allowlist-bypass technique documented in this report scores **HIGH on tradecraft novelty** — it is the campaign's first DEFINITE artifact-level evidence of an attacker pre-customizing an AI-agent CLI's permission allowlist to silence safety prompts for a side-loaded toolkit install. The overall campaign threat level is rated **MEDIUM** because no victims, beacons, intrusions, or downstream impact were observed; the captured evidence is the operator's tradecraft footprint, not a malware sample or active campaign against a named victim. If future evidence ties this operator to a confirmed intrusion or to a named threat actor, the threat level should be reassessed to HIGH.

---

> **Data source:** The open-directory intelligence behind this investigation was surfaced via [Hunt.io](https://hunt.io)'s [AttackCapture](https://hunt.io/features/attackcapture) platform, which sponsors this report series. The analysis, findings, and conclusions are The Hunters Ledger's own.

## Bottom Line Up Front

A Korean operator pre-approved an `openclaw.ai` installer in Claude Code's permission allowlist (`~/.claude/settings.local.json`), silencing every safety prompt for the full OpenClaw install-and-run chain. Seven pre-authorized entries — recovered from the operator's own open-directory exposure (`221.150.15.104`, Korea Telecom) — describe that chain end to end. This is the parent investigation's first DEFINITE artifact-level evidence of an operator deliberately customizing an AI-agent CLI's safety-prompt mechanism to streamline toolkit deployment.

No malware binary was extracted and no victims were observed; the captured artifact is the operator's tradecraft footprint. The defender-relevant finding is the **hunt anchor**: any `~/.claude/settings.local.json` whose `permissions.allow` array pre-approves `curl ... | bash`, a global npm install of an unfamiliar package, or a local-listener bring-up is a high-priority finding regardless of the specific tooling named (Section 4.2).

---

## 1. Executive Summary

An operator pre-approving an `openclaw.ai` installer in Claude Code's permission allowlist is the first DEFINITE artifact-level answer to a question the parent investigation could previously only pose: **how do AI-augmented operators silence the safety friction of running attack-adjacent toolchains through mainstream AI-agent CLIs?** The captured `~/.claude/settings.local.json` is the operator's actual on-disk configuration — not a researcher's reconstruction of a hypothesized attack.

What was found, each detailed in its home section:

- **The smoking-gun artifact** — a 442-byte, downloadable `~/.claude/settings.local.json` whose seven-entry `permissions.allow` array pre-authorizes Claude Code to run the full OpenClaw bring-up chain (environment probe → `curl ... | bash` install → global npm install → onboarding → docs fetch → gateway listener on TCP 18789 → browser UI launch) with no safety prompt. The operator pre-clicked "Always allow" for the entire workflow before any session began (full JSON and per-entry breakdown in Section 4.1).
- **The permission-allowlist-customization TTP** — operator misuse of a documented Claude Code feature, not a vulnerability. The mechanism, the weaponization, and the file-level detection signal are dissected in Section 4.2 (maps to T1562.001).
- **Co-located Claude Code + OpenClaw architecture** — the mainstream agent CLI glued to a side-loaded agent framework, a pattern the parent investigation also observed in Case 2 (Section 4.3).
- **Reproducible defender hunt anchor** — the file itself is the detection signal, and it generalizes: the same hunt catches operator-customized allowlists pointing at *any* side-loaded toolkit, not just OpenClaw (Sections 7–8).
- **Operator OPSEC paradox** — the operator who carefully tuned the allowlist exposed the whole home directory to the public internet, the recurring "AI-integrated mature operator" profile across the parent investigation (Section 6).

No malware binary was extracted and no victims were observed.

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

The operator is tracked as **UTA-2026-015** *(an internal tracking label used by The Hunters Ledger — see Section 6)* at **LOW (55%)** confidence. The strongest signals are Hunt.io's Korean-language curator label and the Korea Telecom AS4766 residential exposure; the `settings.local.json` content is English-only and corroborates neither, and no clustering with named threat actors was found. **Disposition:** the residential exposure at `221.150.15.104:8080` remained reachable at investigation close (2026-05-23). No vendor takedown applies — this tradecraft-observation case has no named victim and no removable artifact (Section 6).

### For Technical Teams

SOC and threat-hunting priorities:

- **Filesystem hunt** — inventory `~/.claude/settings.local.json` and `<project>/.claude/settings.local.json` presence and content across developer- and admin-class endpoints, using the ready-to-deploy YARA and Sigma patterns in the detection file (Sections 4.1, 4.2, 8).
- **Network egress monitoring** — add `openclaw.ai`, `docs.openclaw.ai`, and `lightmake.site` to DNS watchlists (Section 7).
- **Listening-port inventory** — surface TCP port `18789` bindings on developer-class endpoints (Section 4.5).
- **Detection generalization** — the same hunt criteria catch any operator-customized allowlist of this shape, not just OpenClaw (Sections 4.2, 8).
- **Disclosure** — Anthropic and OpenClaw maintainers were notified via the parent investigation's vendor process; no customer-side disclosure is in scope.

---

## 2. Campaign Context

Case 4 captured a Korean operator's residential open-directory exposure — one of several cases in the parent investigation on how AI-augmented operators pair mainstream AI-agent CLIs (Claude Code, Gemini CLI) with side-loaded dual-use frameworks (OpenClaw). This **capsule sub-report** expands that case to the artifact level, deepening what umbrella Section 4.4 covers at capsule depth. The parent owns the cross-case framing; this sub-report does not restate it (see the [parent report](/reports/ai-agent-frameworks-2026-05-23/)).

### Discovery Method

Hunt.io's open-directory crawler indexed the operator's exposed home directory at `http://221.150.15.104:8080/` on **2026-03-11**, with the curator labelling the host "Korean operator" on regional-ISP and language-environment indicators. The parent investigation's host-prioritization review selected the case on 2026-05-23, prioritizing hosts with co-located mainstream + side-loaded AI-agent installations.

### Named-Victim Status

**None confirmed.** The captured filesystem contains no victim identities, exfiltrated data, email targets, compromised credentials, or traffic logs against named infrastructure. The operator's `~/.claude/history.jsonl` (session command history) and `~/.claude/projects/` (transcript directory) were deliberately not pulled per The Hunters Ledger credential-redaction discipline — operator session transcripts can surface incidentally-mentioned third-party identities and yield defenders nothing operationally usable in a tradecraft-observation case (Section 10.2).

### Operator Residential Exposure Pattern

The host is a **direct residential exposure**: AS4766 Korea Telecom, the largest Korean ISP, on an IP block consistent with consumer broadband rather than a VPS, cloud-rented host, or tunnel exit. The operator used no VPN, Tor, or proxy — the open directory was reachable directly at the home IP for the 73-day window between Hunt.io first-seen (2026-03-11) and investigation close (2026-05-23).

This residential-exposure carelessness, paired with deliberate allowlist tuning, recurs across the parent investigation's "AI-integrated mature operator" class: tradecraft sophistication in one area coexisting with neglect of wider OPSEC.

### Scope Boundary

This sub-report covers **only the operator tradecraft in the `settings.local.json` artifact** and its immediate filesystem context. Parent-investigation cross-cutting findings (operator-class taxonomy, AI-vendor distribution, the "5 novel TTPs" pattern) remain in the umbrella report and are referenced by number, not restated.

---

## 3. Technical Classification

This is an **operator-tradecraft analysis report, not a malware analysis report.** The captured evidence is not a malicious binary, exploit payload, or packed dropper — it is a 442-byte JSON configuration file documenting how the operator reconfigured a mainstream AI-agent CLI to lower safety friction.

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

The standard malware-analysis stages do not apply: there is no binary to reverse or sandbox, prior-art research is complete in the parent umbrella, a single residential Korea Telecom IP carries no infrastructure-pivot value, and attribution (UTA-2026-015 LOW 55%) was already assigned in the parent investigation. Appendix B expands each point.

### Architectural Pattern Summary

The operator's host runs two AI-agent CLIs side-by-side:

1. **Anthropic Claude Code** as the human-facing AI assistant (chat, planning, coding) — the mainstream agent CLI providing the natural-language interface and reasoning via Anthropic's Claude models.
2. **OpenClaw** as a local-gateway service on TCP port 18789 — an AI-agent framework exposing skills Claude Code does not natively support.

The seven-entry `permissions.allow` array is the **glue**: the operator's mechanism for telling Claude Code "install and run OpenClaw without asking me for confirmation." Section 4 documents the artifact and mechanism in depth.

---

## 4. Technical Capabilities Deep-Dive

This section examines the smoking-gun artifact, the permission-prompt bypass it abuses, the co-located Claude Code + OpenClaw architecture, the OpenClaw distribution ecosystem the allowlist points at, and the gateway service on port 18789 the allowlist authorizes Claude Code to start.

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

The schema is Anthropic Claude Code's documented per-directory and global permission-allowlist format: the single top-level key `permissions` contains a sub-object whose `allow` array enumerates the exact command strings the operator pre-approved.

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

**The macOS signal.** Entry 7's `open` command — the macOS equivalent of Linux `xdg-open` or Windows `start` — strongly suggests a macOS or macOS-compatible host. The co-located `~/.openclaw/completions/openclaw.ps1` (a PowerShell completion script) yields three candidate readings: (a) the operator runs PowerShell-on-macOS, (b) OpenClaw ships the PowerShell completion in its standard distribution regardless of host OS, or (c) the operator also runs OpenClaw on a separate Windows host that synced here. Reading (b) is most parsimonious — the file is standard install layout, not affirmative evidence of PowerShell on this host — so the macOS read (entry 7) stays higher-confidence.

**The collective effect.** The seven entries form one complete sequence — probe, install (via both `curl | bash` and a redundant npm path), onboard, fetch docs, start the gateway, open the UI. The operator compressed what would normally be a multi-step interactive workflow, with a safety prompt at every step, into a single pre-approved chain.

### 4.2 The Permission-Allowlist Bypass Mechanism

> **Analyst note:** This section explains *how* the operator's pre-approved allowlist defeats Claude Code's safety-prompt mechanism. The mechanism is documented in Anthropic's Claude Code reference material — it is not a vulnerability or a bug. It is a deliberate UX feature that the operator has weaponized against its intended purpose. Defenders need to understand the mechanism to recognize the abuse pattern at the file-content level.

#### How Claude Code's Per-Command Safety Prompt Normally Works

Claude Code, like other AI-agent CLIs that execute arbitrary local commands, prompts before potentially-dangerous operations. When the agent proposes a shell command, a URL fetch, or any action in a user-configurable category (Bash, WebFetch, file edit), Claude Code surfaces it to the operator and waits for an explicit yes/no.

This per-command prompt is the user's safety gate — the single point to intervene if the AI proposes something unintended, malicious, or unwise. It converts an autonomous agent into a supervised one: the user reviews and approves each impactful action.

#### How the Allowlist Pre-Approval Mechanism Works

The `permissions.allow` array is a documented UX convenience: a user who knows in advance they want a specific command approved (for example, a repeated lint command) lists that exact string, and Claude Code thereafter skips the prompt for matches and runs the command directly.

The semantic is **exact-match against the command string** — `Bash(npm i -g openclaw)` skips the prompt for that exact command but not for `Bash(npm i -g something-else)` or `Bash(npm install openclaw)`. The operator must enumerate each exact form to pre-approve.

The design is reasonable for its intended use (dev-loop commands typed dozens of times a day). The operator turns it into a safety-control bypass by enumerating a side-loaded toolkit's install-and-run sequence before the session begins.

#### How the Operator Weaponizes the Mechanism

The operator's strategy is straightforward: write `settings.local.json` ahead of time, populate `permissions.allow` with every command needed to fetch and run OpenClaw, save it, and start the session. Thereafter, asking Claude Code to install OpenClaw runs the entire seven-step chain with no safety prompt.

The defender-relevant point: this is **not a Claude Code vulnerability** but operator misuse of a documented feature — both the safety prompt and the allowlist work as designed. The `settings.local.json` file is the artifact that demonstrates the misuse, so the defensive opportunity is not to fix Claude Code (already correct) but to **hunt for the artifact** wherever the operator applied the technique.

#### Why This Is the First DEFINITE Artifact-Level Evidence

This case supplies what the surveyed public threat-intel corpus lacked as of 2026-05-23: an **in-the-wild operator-customized allowlist** showing what the abuse pattern looks like on disk. The defender community had discussed the theoretical risk of attacker-customized AI-agent allowlists since Claude Code's permission model was published, but no captured example existed.

The artifact closes that gap with a downloadable 442-byte file, a seven-entry sequence reproducible by any defender who reads it, and a pattern that generalizes immediately to operator-customized allowlists pointing at *any* side-loaded toolkit. Sections 7 and 8 translate the artifact into concrete hunt queries.

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

The combination beats any single signal: hunting `curl | bash` alone catches legitimate workflows (a developer pre-approving a known internal-tooling installer); hunting the file path alone catches every Claude Code user. The combination catches operators who pre-approved an install-and-run chain for unfamiliar software.

### 4.3 Co-Located Architecture (Claude Code + OpenClaw Side-by-Side)

The operator's tool is not Claude Code or OpenClaw but **both, integrated** — and the exposed home directory contains both `~/.claude/` and `~/.openclaw/`. The observed pattern:

1. **Claude Code** is the human-facing layer. The operator chats, requests tasks, reviews proposed actions (or, in the pre-approved cases, doesn't), and consumes Claude's outputs. The mental model is "I am working with Claude."
2. **OpenClaw** runs as a local gateway on port 18789, started by Claude Code via allowlist entry 6 (`Bash(openclaw gateway --port 18789)`) and providing additional skills to the workflow.
3. **The gateway pattern** positions OpenClaw as a local backend other tools (including Claude Code itself, in some integration modes) connect to. Claude Code supplies reasoning and natural language; OpenClaw supplies the extended skill set.

The parent investigation independently observed this same model in Case 2: Case 2 ([Turkish ARPA](/reports/turkish-arpa-openclaw-state-insurer-209.38.205.158/) §4.3) shows the same side-loaded **OpenClaw** toolkit (over a Moonshot Kimi backend) — an ecosystem-level shared tool driven by the documented OpenClaw exposure crisis, not coordination (see the [parent](/reports/ai-agent-frameworks-2026-05-23/) §9.9).

**Why this matters.** Singular-tool framing misjudges the threat surface — defenders must inventory and monitor both and understand the integration. A posture that allows mainstream AI CLIs but blocks all side-loaded toolkits fails here unless the side-loaded toolkit itself is detected.

### 4.4 The OpenClaw Distribution Ecosystem

The allowlist references three distribution channels for OpenClaw, all owned or controlled by the OpenClaw maintainers:

| Channel | Indicator | Role |
|---|---|---|
| Shell installer | `https://openclaw.ai/install.sh` | Primary installer hosted on OpenClaw's product domain. Uses the `curl -fsSL <URL> \| bash` pattern, a well-documented high-risk distribution mechanism where the operator effectively grants the installer source full ability to write arbitrary code into the operator's environment. |
| npm registry | `npm i -g openclaw` (package name `openclaw`) | Global npm install — alternative path to the shell installer. Published to the public npmjs.com registry. |
| Documentation host | `docs.openclaw.ai` (referenced via Claude Code `WebFetch`) | Operator-pre-authorized doc fetch. The defender signal here is that Claude Code is being used to consume OpenClaw documentation, not just to install and run the tool — the operator is treating OpenClaw as a capability they will use via Claude Code's natural-language interface, with OpenClaw's docs as a contextual reference. |

The parent investigation additionally documents **`lightmake.site`** as an OpenClaw-adjacent infrastructure component in the ecosystem's hosting-and-egress signature, observed at MODERATE confidence in the umbrella's multi-case analysis — **not** in the Case 4 artifact itself. It does not appear in the captured allowlist, but is included in the IOC feed (Section 7) as a documented OpenClaw-ecosystem domain defenders should monitor alongside the Case-4-direct indicators; its evidentiary basis for this case is thinner than the DEFINITE-confidence Case 4 domains.

**Important framing — OpenClaw's public-distribution status.** OpenClaw is a **publicly-distributed AI-agent framework**; broad availability does not make installing it inherently malicious. The dual-use pattern mirrors tools like Metasploit, Cobalt Strike, and Sliver, which have both legitimate adopters and abusive-use populations.

The defender-relevant finding is **not** "OpenClaw is malware" but the **combination** of:

- an attacker-customized Claude Code allowlist (the artifact),
- the specific seven-command pre-approval sequence pointing at OpenClaw, and
- the host's broader exposed contents (the open directory, the residential Korea Telecom ISP, the parent investigation's prior-art tying this profile to operator-class behavior).

Any single element is ambiguous; the combination is the diagnostic signal.

### 4.5 Gateway Service on TCP Port 18789

Allowlist entries 6 and 7 bring up the OpenClaw gateway — OpenClaw's local-control-plane component, which listens on a TCP port and exposes a web UI the operator interacts with.

**What the gateway does (from operator-side evidence).** The artifact authorizes `Bash(openclaw gateway --port 18789)` immediately followed by `Bash(open http://127.0.0.1:18789/)`, which together establish that:
- the gateway binds to a TCP port (default `18789`),
- it exposes an HTTP web UI at the root URL `/`, and
- the operator's intended next action is to interact with that UI.

The artifact does not document what the gateway UI **contains** — that requires running OpenClaw and observing it live, which is out of scope (only the filesystem was inspected, not the running instance). The umbrella's broader OpenClaw documentation adds some context but is similarly bounded by what operator-side artifacts reveal.

**Defender implications of the gateway.**

- **Listening-port inventory.** TCP port `18789` on a developer- or admin-class endpoint is a candidate signal — the port is not registered to any other widely-used service, making a binding highly specific to OpenClaw's default config. (`--port` is configurable, but the default is documented and the captured allowlist uses it.)
- **Loopback-only scope.** The allowlist binds `127.0.0.1:18789`, the loopback interface, so the gateway is reachable only from the host — consistent with OpenClaw mediating between local tools, not remote callers. Expect no external port-18789 exposure unless the operator deliberately bound `0.0.0.0:18789` or set up a port-forward; the artifact shows neither.
- **Process-tree signal.** When Claude Code starts the gateway, the host's process tree shows Claude Code spawning a Bash subprocess that exec's `openclaw gateway`. Lineage-tracing endpoint detection can flag it: Claude Code → Bash → unfamiliar gateway listener.

**Why this matters at the kill-chain level.** The gateway is the operational hub for the operator's tool integration. Detecting its bring-up via any of three independent paths — allowlist content scan, listening-port inventory, or process-tree lineage — yields defense-in-depth even though no single signal is uniquely diagnostic in isolation.

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

Per CLAUDE.md ATTRIBUTION CONFIDENCE SCALE, the Korean-language attribution is LOW and stated as **"weak indicators suggest"**, no stronger:

- Weak indicators suggest the operator is Korean-speaking, from (a) Hunt.io's curator "Korean operator" label and (b) the residential Korea Telecom AS4766 hosting.
- The `settings.local.json` content is entirely English — no Korean strings, comments, or filenames in the artifact itself.
- This LOW-confidence language signal supports no claim of Korean state-affiliated activity, North Korean actors (Lazarus, Kimsuky, ScarCruft), or South Korean criminal clusters; those would require substantially stronger evidence.

### Operator-Class Taxonomy

UTA-2026-015 fits the **"AI-integrated mature operator"** profile from the umbrella's Section 4.10 taxonomy:

- **Allowlist-tuning sophistication.** The deliberate seven-entry sequence covering the full OpenClaw bring-up reflects planning and awareness of Claude Code's permission model — not opportunistic scripting.
- **Side-loaded toolkit adoption.** Choosing Claude Code + OpenClaw together is characteristic of operators who treat their AI tooling as a deliberate operational stack; mainstream-only operators use Claude Code alone, opportunistic ones never install OpenClaw.
- **Wider-OPSEC gap.** The same operator exposed the entire home directory via an open-directory misconfiguration — something sophisticated operators do not do. Competence in one area, complete failure in another: the "mature operator paradox."

This paradox recurs across the parent investigation's cases. The parsimonious read: operators specializing in AI-augmented offense are early in the discipline's maturity curve — technically capable in their niche, but with surrounding OPSEC tradecraft (compartmentalization, infrastructure hygiene, footprint minimization) not yet caught up.

Defenders benefit from this gap, but offenders eventually close it. The window for catching operators via residential-ISP open-directory exposures is therefore finite.

### What This Assessment Does Not Claim

At LOW confidence the evidence supports "weak indicators suggest" and no more. Specifically:

- **No state-actor attribution claimed.** The evidence does not support state-sponsored activity, intelligence-service involvement, or alignment with any named APT.
- **No criminal-cluster attribution claimed.** The evidence does not support involvement in any named criminal cluster (RaaS group, IAB ring, infostealer crew).
- **No victim attribution claimed.** No victims were observed; the case is tradecraft observation only.
- **No "first-of-kind operator" claim.** This is the first DEFINITE artifact-level evidence of the allowlist-bypass technique (surveyed public corpus as of 2026-05-23), not necessarily the first operator to use it — earlier adopters may exist who were never caught with an exposed home directory.

---

## 7. Indicators of Compromise

> **Analyst note:** The complete IOC set for this case is published as a machine-readable JSON feed for direct SIEM/EDR ingestion — it is not duplicated inline here. The highest-priority indicators are also surfaced in the IOC panel (fingerprint icon) on this page.

**Full IOC feed:** [`/ioc-feeds/korean-claude-openclaw-221.150.15.104-iocs.json`](https://the-hunters-ledger.com/ioc-feeds/korean-claude-openclaw-221.150.15.104-iocs.json) — every indicator for this case, with type / confidence / recommended action.

---

## 8. Detection and Response Guidance

Detection rules (YARA, Sigma) covering the file-content patterns documented in Section 4.2 are provided in:

**[`/hunting-detections/korean-claude-openclaw-221.150.15.104-detections/`](https://the-hunters-ledger.com/hunting-detections/korean-claude-openclaw-221.150.15.104-detections/)**

The detection file follows The Hunters Ledger conventions (CC BY 4.0 license, "The Hunters Ledger" author field on all rules, YAML front matter, no body H1 title). Deploy per your internal detection-engineering processes; this report does not prescribe deployment specifics.

### Detection Strategy at the Category Level

The strategy is **three independent paths against the same workflow**, so defenders catch the activity even if one path is missed.

**Deployment-scope discipline.** On developer-class endpoints (where engineering, DevOps, or data-science staff routinely install third-party CLIs), all three paths below carry a non-trivial false-positive rate — developers legitimately install unfamiliar tools, and some allowlist entries reflect normal workflow. Highest-signal targets are **server-class endpoints, jump hosts, CI/CD agent nodes, and non-developer workstations**, where Claude Code presence is itself anomalous. For confirmed developer endpoints, prefer **allowlist content review** (is this a known-authorized package from a recognized vendor?) over automatic blocking. The three paths:

**Path 1 — Filesystem content hunt.** YARA scanning `~/.claude/settings.local.json` and `<project>/.claude/settings.local.json` for the documented allowlist patterns. The primary path, broadest reach — it catches the technique against any tool, not just OpenClaw.

**Path 2 — Process-tree lineage.** Sigma for a Claude Code parent spawning Bash subprocesses that exec `curl ... | bash`, global npm installs of unfamiliar packages, or local listener bring-up. The runtime path — catches the abuse when the allowlist is actually used, not just statically present.

**Path 3 — Listening-port inventory.** Endpoint queries surfacing TCP port `18789` bindings on developer- and admin-class endpoints. The post-hoc path — catches a host where the gateway is currently running, regardless of how it started.

### Response Orientation

This is not an incident response guide. Defenders with confirmed findings should engage internal or external IR; that workflow is out of scope. The orientation below covers only what to address.

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

**Vendor coordination (separate from per-host containment):** if the activity is part of a broader incident with identified victims or a vendor-actionable artifact, engage Anthropic and OpenClaw maintainers via their security disclosure channels. This does not apply to tradecraft-observation cases without confirmed victims.

---

## 9. Confidence Summary

Findings organized by confidence level. The body attaches per-claim confidence inline; this is the consolidated index.

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

**Static analysis: not applicable in the traditional malware-RE sense.** No binary was captured; the artifact (`settings.local.json`, 442 bytes) is a JSON text file. Its static findings — full content, the 7-entry allowlist, the OpenClaw install chain — are in Section 4.1 and broken down in 4.2–4.5. No disassembly, packer analysis, or YARA-against-binaries applies because there is no binary. The two YARA rules in the sister detection file operate against `settings.local.json` text, not PE / ELF / Mach-O binaries.

### 10.2 Dynamic Analysis Coverage

**Dynamic analysis: not applicable.** No binary was captured to detonate, and no live operator-side traffic capture exists — there is nothing to sandbox. The operator's `~/.claude/history.jsonl` (session command history) and `~/.claude/projects/` (session-content transcripts) were deliberately not pulled per The Hunters Ledger credential-redaction discipline: those files would expose operator session contents that risk surfacing third-party identities if the operator used Claude Code against named targets, and they yield defenders nothing operationally usable in a tradecraft-observation case. This is consistent with the project standard.

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

No kill chain reconstruction is available — no attack chain against any victim was observed. The case documents the operator's pre-staging configuration only: Cyber Kill Chain Stage 1 (Reconnaissance / Weaponization), arguably Stage 2 (Delivery — the operator weaponizes their own Claude Code installation as the delivery surface). Stages 3 through 7 (Exploitation through Actions on Objectives) are not in evidence and cannot be reconstructed from the artifact.

### 10.5 Confidence Caveats Carried Forward

Read all findings in light of the gaps above:
- **DEFINITE** claims attach only to artifact-level observations (JSON content, the 7 allowlist entries, the IP, ASN, file path, port number, distribution domains).
- **HIGH** claims attach to the technique characterization (the allowlist customization as Disable or Modify Tools; the operator-class taxonomy fit; the OpenClaw architectural pattern).
- **MODERATE** claims attach to operator-attribution inferences (Korean language, residential exposure pattern, mid-tier-selective sophistication).
- **LOW** confidence attaches to UTA-2026-015 itself (55% per parent investigation).
- **INSUFFICIENT** evidence is acknowledged for all Section 10.3 gap items.

Defenders building hunt and detection logic should anchor on the DEFINITE artifact-level observations (file content, path, network indicators). HIGH-and-below content is interpretive context for the technique — not a basis for blocking or attribution.

---

## 11. References and Appendices

### Parent Investigation

- **Parent report:** [AI-Agent-Frameworks-MultiActor-2026-05-23](/reports/ai-agent-frameworks-2026-05-23/) — the multi-case context for Case 4. Section 4.4 provides the capsule-depth coverage this sub-report expands; Section 4.10 documents the operator-class taxonomy this case fits.
- **Host-prioritization working notes** — held offline in the investigation archive; this sub-report synthesizes the Host 1 content from that review.
- **Smoking-gun artifact (preserved offline):** the 442-byte `settings.local.json` is held in the offline evidence archive; full content is reproduced in Section 4.1.

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

Standard Hunters Ledger reports follow a multi-stage pipeline (malware analysis → research → infrastructure → attribution → detection engineering → report writing). For this case, Stages 1, 2-research, 2-infrastructure, and 3 were intentionally compressed:

- **No malware binary** — the artifact is a 442-byte text configuration file; no reverse engineering, sandbox detonation, or unpacking applies.
- **Prior-art research is complete** — the parent umbrella already covers the OpenClaw distribution ecosystem, the dual-use framing, and the cross-case operator taxonomy; repeating it adds no value.
- **Infrastructure has no pivot value** — a single residential Korea Telecom IP returns no actor-clustering signal, because residential blocks are shared by tens of thousands of unrelated subscribers.
- **Attribution is already assigned** — UTA-2026-015 LOW 55% was determined in the parent investigation; the sub-report reflects it without re-running the workflow.

This compressed structure (artifact analysis + defender hunt anchors) suits single-case tradecraft-observation sub-reports of a multi-case parent. Readers wanting full-length malware-analysis depth should consult other Hunters Ledger publications.

---

© 2026 Joseph, The Hunters Ledger. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — free to republish and adapt, including commercially, with attribution to The Hunters Ledger and a link to the original.





