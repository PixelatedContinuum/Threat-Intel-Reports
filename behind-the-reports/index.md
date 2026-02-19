---
title: "Behind the Reports: How a Solo Analyst Uses AI Agents to Produce Timely, Trustworthy Threat Intelligence"
date: '2026-02-18'
layout: page
permalink: /behind-the-reports/
hide: true
---

## What Is This, and Why Does It Exist?

When a security researcher analyzes malware, a malicious program, a suspicious file, a piece of code found in the wild, the raw output of that analysis is scattered and hard to make sense of. Numbers, strings, network addresses, behavioral observations. It's useful data, but it is not intelligence. It doesn't explain what the threat actually *means*, who is likely behind it, how defenders should detect it, or why it matters in the broader threat landscape.

Converting raw analysis into polished, accurate, threat intelligence is time-consuming work that requires multiple areas of expertise: deep technical knowledge, research skills, writing ability, quality review, and formatting discipline. Doing all of it well, alone, for every analysis, is genuinely difficult. This workflow exists because that problem was real for me, not theoretical. It was built and refined over months of actual analysis work, researched, tested, broken, and rebuilt, with every design decision shaped by what the practice of doing this work actually revealed. Where quality suffered, where time was lost, and where the process needed tighter guardrails to be trustworthy.

What emerged from that process is a team of AI agents, each with a defined role, and a custom set of instructions. These agents are supported by a structured skill framework of domain knowledge and standards to operate against, supported further by a layer of hooks and automated commands that keep the system honest, measurable, and resilient between every stage. The researcher provides the raw analysis data, along with the contextual thinking, investigative judgment, and analytical decisions that no automated system can replicate. The workflow handles the rest: organizing the findings, enriching them with threat intelligence context, writing the report, validating the quality, and producing three publication-ready output files.

The workflow is designed to produce intelligence that reads like it came from a professional third-party threat intelligence provider technically deep, but written to be understood and acted on. That balance is intentional. Most publicly available threat intelligence skews one way or the other: either too surface-level to be technically useful, or too dense to be actionable without significant interpretation. As a defender myself, I built this workflow to produce something I'd actually want to read, rigorous enough to trust, clear enough to use.

---

## A Note on What This Workflow Is Not

This workflow does not replace a human analyst. It handles the structured, repeatable parts of the intelligence production process. Parts including, aggregation, research, writing, formatting, and review. All wih the goal of allowing the human analyst can spend their time on the parts that require human judgment such as sample selection, data collection, interpreting ambiguous findings, deciding what analysis is worth doing, and understanding the organizational and strategic context that no AI agent can know.

Think of it as a very capable production team that supports what the analyst needs. The analyst is still the expert. The workflow is the infrastructure that turns expert judgment into professional output efficiently.

---

## What the Workflow Produces

No matter how much or how little data goes in, the workflow always targets three output files:

**1. A Threat Intelligence Report** (`reports/[malware-name]/index.md`)
A full written analysis, structured, professional, and publication-ready. This covers what the malware does technically, what it means for defenders, how it connects to known threats, and (when evidence supports it) who may be behind it. Written to be useful for both technical readers and strategic ones.

**2. A Machine-Readable IOC Feed** (`ioc-feeds/[malware-name]-iocs.json`)
All the indicators of compromise, file hashes, IP addresses, domain names, registry keys, and so on, formatted as a structured JSON file that security tools (SIEMs, EDRs, firewalls) can ingest directly, without manual reformatting.

**3. Detection Rules** (`hunting-detections/[malware-name]-detections.md`)
YARA rules (for file-based detection), Sigma rules (for log-based detection), and Suricata signatures (for network detection), all written to the submission standards of the public repositories where these rules are shared with the community.

---

## The Agents: Who Does What

Think of the workflow like a newsroom. There is an editor-in-chief who manages the overall process, and a team of specialists who each handle one part of the job.


| Agent                      | Role                                                                                         | Skill Framework                                            | Analogy                       |
| -------------------------- | -------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | ----------------------------- |
| **Orchestrator**           | Manages the whole process, moves data between stages, presents checkpoints to the researcher | ,                                                          | Editor-in-chief               |
| **Malware Analyst**        | Reads the raw analysis data and produces a structured technical findings document            | MITRE ATT&CK Mapping                                       | Investigative reporter        |
| **IOC Specialist**         | Validates and formats all the indicators of compromise                                       | IOC Formatting Standards                                   | Fact-checker / data desk      |
| **Research Analyst**       | Searches the threat intelligence landscape for context about the malware and its actors      | Source Credibility Assessment, Threat Intelligence Scoping | Research librarian            |
| **Detection Engineer**     | Writes the detection rules                                                                   | YARA Rule Formatting, SigmaHQ Rule Formatting              | Technical correspondent       |
| **Infrastructure Analyst** | Investigates the IP addresses and domains to find broader attacker infrastructure            | Infrastructure Pivoting Playbook                           | Investigative data journalist |
| **Attribution Analyst**    | Assesses who may be behind the malware and with what confidence                              | Attribution Analysis Framework                             | Expert analyst                |
| **Report Writer**          | Synthesizes all findings into the final written report                                       | Report Structure Template, Research Findings Synthesis     | Senior writer                 |
| **Report Reviewer**        | Reviews the report from three expert perspectives and scores it                              | Report Quality Standards                                   | Editorial board               |
| **Report Editor**          | Final formatting and polish pass                                                             | Report Quality Standards                                   | Copy editor                   |


## The Skill Framework: What Agents Know Before They Start

Each agent operates against a defined skill framework: a structured body of domain knowledge, methodology, and standards that exists independently of the agent's instructions. Skills are not prompts. They are reference documents that encode how the work should be done, built from real standards, real submission requirements, and real methodology from the threat intelligence field.

This distinction matters. Instructions tell an agent *what to do*. Skills tell it *how to do it correctly*. The difference shows up in the output.

A detection engineer without a skill framework might write a functional YARA rule. A detection engineer operating against the YARA Rule Formatting skill writes a rule that meets the exact submission standards of the public repository where it will be shared, correct metadata fields, properly scoped conditions, no string redundancy, attribution set to "The Hunters Ledger." Without the skill, those details get guessed at. With it, they're enforced.

The same principle applies across the workflow:

- The **Malware Analyst** uses the MITRE ATT&CK Mapping skill to ensure every technique observed in the sample maps to the correct framework ID with the right evidence level, not just the closest guess.
- The **Research Analyst** uses Source Credibility Assessment to apply a consistent credibility tier to every source it cites, so readers and downstream agents know whether a claim comes from a government advisory, a Tier-1 vendor, or an unverified blog post.
- The **Attribution Analyst** uses the Attribution Analysis Framework to apply structured evidence-weighting before making any actor assessment, preventing the overconfident claims that are one of the most credibility-damaging things a threat intelligence report can produce.
- The **Infrastructure Analyst** follows the Infrastructure Pivoting Playbook, a systematic methodology for moving from a single IP or domain to a broader picture of attacker infrastructure through passive DNS, WHOIS, SSL certificate analysis, and ASN enumeration.
- The **IOC Specialist** uses IOC Formatting Standards to validate and structure every indicator before it enters the machine-readable feed, including confidence ratings and false-positive checks.
- The **Report Writer** and **Report Reviewer** both operate against Report Quality Standards and the Report Structure Template, which define what a publication-ready threat intelligence report looks like and how to assess whether it actually meets that bar.

Skills also need to be enforced, not just defined. That's where hooks come in. Hooks are automated scripts that fire at every stage transition,when an agent starts, when it finishes, when a reviewer completes, without any manual trigger. One of those hooks, the Skill Validation Gate, fires after each agent completes and checks the state file to confirm the required skills were actually invoked. If the detection engineer finishes without YARA and Sigma skill validation recorded, that absence is flagged at the quality gate, not caught later by accident, but caught systematically, every time. Skills define the standard. Hooks make sure the standard was actually met.

---

## What Runs Beneath the Agents

Beneath the agents is a second layer of infrastructure, hooks and commands, that runs automatically, without instruction, at every stage transition. This is what makes the system behave reliably rather than just approximately.

**Hooks** fire on specific events (agent start, agent complete, reviewer complete) and handle coordination that would otherwise be manual. Three carry the most weight:

- **Quality Gate Checker** the enforcer. Fires when the reviewer completes, reads the quality score against the 8.0 threshold, and writes `REVISION_NEEDED` or `COMPLETE` to the state file. The orchestrator doesn't make this call, the hook does, based on defined criteria, every time.
- **Result Cache Manager** the time saver. When the research analyst finishes, this hook saves results by malware family. On any future analysis of the same family, those results are loaded directly and the research agent is skipped entirely, saving 15–20 minutes per re-analysis.
- **Skill Validation Gate** the standards enforcer. Fires after each agent completes and checks that required skills were invoked. Missing coverage is flagged before it can reach publication.

The remaining hooks keep the system instrumented and recoverable:

- **Workflow State Tracker** maintains a live JSON record of every agent run, in order, with timestamps
- **Dispatch Tracker** records precise launch times to verify parallel agents actually launched simultaneously
- **Token Usage Tracker** logs input, output, and total token consumption per agent into a structured metrics file
- **Session Milestone Saver** backs up workflow state at each major stage completion so an interrupted run is recoverable

**Commands** are invoked by the orchestrator at decision points. The primary one, **Parse Checkpoint Feedback**, takes your natural language input at Checkpoint 1 or 2 and converts it into a structured JSON decision, proceed, re-run an agent, request major revision, or ask for clarification so, routing is deterministic regardless of how feedback is phrased.

---

## How Agents Work Together: Parallel Vs. Sequential

One of the key design decisions in this workflow is **which agents run at the same time and which must wait for others**.

Some agents have dependencies, they genuinely cannot start until a previous agent finishes, because they need that output. The attribution analyst, for example, cannot assess who is behind the malware until the infrastructure analyst has mapped out the attacker's network infrastructure.

Other agents are independent, they can work with just the initial findings and don't need each other's output at all. The IOC specialist, the research analyst, the detection engineer, and the infrastructure analyst all only need the malware analyst's findings to start. They don't need each other.

This means those four agents can run **simultaneously**, in parallel, like four specialists working on different parts of the same investigation at the same time. This cuts what would otherwise be 30+ minutes of sequential waiting down to roughly 12 minutes (limited only by how long the slowest agent takes).

The orchestrator is responsible for understanding these dependencies and dispatching agents accordingly. Two hooks run silently in the background throughout this entire process: one logs the exact timestamp every agent is launched, and one logs when each agent completes. This gives the workflow a precise, timestamped record of the entire execution, how long each agent took, where time was spent, and whether the parallel batches actually ran simultaneously or drifted into sequence. It's not just automation; it's instrumented automation.

---

## Scenario 1: Five Analyzed Files

Imagine you have spent time analyzing five malware files, perhaps sandbox reports, memory dumps, network captures, and behavioral logs from an incident. You drop all five into the project directory and ask the orchestrator to run.

Here is exactly what happens, step by step.

---

### Step 1, Malware Analyst Reads Everything (~10 Minutes)

The orchestrator hands all five files to the malware analyst agent. This agent is the only one that reads the raw data. Its job is to produce a single, organized technical findings document from everything it was given.

That document covers:

- **File characteristics**, what type of files these are, how they're structured, whether they appear to be compressed or obfuscated, what software created them
- **Behavioral observations**, what the malware actually does when it runs: what files it creates, what registry keys it modifies, what processes it spawns, how it maintains persistence across reboots
- **Network activity**, IP addresses it connects to, domain names it resolves, the pattern, and timing of its communications
- **Techniques used**, mapped to the MITRE ATT&CK framework, which is an industry-standard catalog of attack techniques. This gives defenders a common language for what they're looking at.
- **Sophistication assessment**, is this amateur or professional tooling? Script-kiddie or nation-state?

Five files in, one structured findings document out. Everything downstream works from this.

---

### Step 2, Four Agents Launch Simultaneously (~12 Minutes)

Before dispatching any agents, the orchestrator runs two quick checks:

**Cache check:** Is there already research on this malware family from a recent analysis? If the research analyst ran on this same family within the last 30 days, those results are saved and can be reused, skipping 15-20 minutes of work.

**Network IOC check:** Did the malware analyst find any IP addresses, domain names, or URLs? If the malware had no network activity at all (it operates purely locally), there's nothing for the infrastructure analyst to investigate, so that agent is skipped.

Assuming both checks pass (new malware, with network activity), the orchestrator dispatches four agents in a single message. They all start at the same time:

**IOC Specialist** receives all the raw indicators, every hash, IP, domain, registry key, file path, and mutex found in the analysis. Its job is to validate that these are real, properly formatted, and not false positives (like system files or common software domains that might appear in any malware analysis). It produces `ioc-feeds/[malware-name]-iocs.json`, clean, confidence-rated, and ready for security tool ingestion.

**Research Analyst** receives a summary of the malware's capabilities and the suspected family name. It searches threat intelligence sources, public security research, government advisories, and vendor reports to answer: has this been seen before? Is there a known campaign? What do we know about who operates it? It applies a credibility rating to every source it uses, so downstream agents and readers know how much to trust each claim.

**Detection Engineer** receives the behavioral signatures, the specific API calls, file operations, registry changes, and network patterns that make this malware distinctive. It writes the detection rules: YARA rules for identifying the files themselves, Sigma rules for detecting the behavior in log data, and Suricata rules for catching it on the network. Every rule is written to the submission standards of the public repositories where they'll be shared.

**Infrastructure Analyst** receives all the network indicators, the IPs and domains. It runs structured open-source intelligence (OSINT) investigations: who registered these domains, who hosts these IPs, are they connected to each other or to known malicious infrastructure, what other malicious activity has been associated with these network resources? It produces a map of the attacker's infrastructure and identifies patterns that help attribution.

All four agents work independently and simultaneously. The orchestrator waits for all four to finish, then collects their results.

---

### Step 3, Attribution Analyst Assesses Who's Behind It (~6 Minutes)

Before invoking the attribution analyst, the orchestrator checks: is there actually enough evidence to make an attribution assessment? If the infrastructure confidence is low *and* the research confidence is low, attribution would just be speculation, so the agent is skipped and the report will honestly state "Unknown threat actor, insufficient evidence for attribution." Speculation is worse than honesty in this field.

If the evidence warrants it, the attribution analyst receives everything, the technical findings, the infrastructure map, the research context, and the validated IOCs, and produces a structured attribution assessment that always includes:

- The assessed threat actor (or "Unknown")
- A confidence level: DEFINITE, HIGH, MODERATE, LOW, or INSUFFICIENT
- The specific evidence supporting that confidence
- The gaps that prevent higher confidence
- What additional evidence would be needed to increase confidence

This structured format prevents overconfident attribution, which is one of the most damaging things a threat intelligence report can do. A wrong high-confidence attribution misleads defenders and damages credibility. An honest "MODERATE confidence, here's why" is far more valuable.

---

### Step 4, Report Writer Drafts All Three Deliverables (~7 Minutes)

The report writer receives everything produced so far, the technical findings, IOC validation results, research context, detection rules, infrastructure analysis, and attribution assessment, and produces the first drafts of all three output files simultaneously.

The main report is structured to serve multiple audiences:

- **Strategic layer**, a plain-language bottom line for decision-makers: what is this, what's the risk, what does it mean?
- **Operational layer**, for threat hunt team leads: what campaigns is this connected to, what should defenders be looking for?
- **Tactical layer**, for SOC analysts and detection engineers: specific detection opportunities and immediate actions

The report does not embed IOC tables or detection code blocks in the body, those stay in their dedicated files. The report references them and explains what they contain. This keeps the report readable and the data files machine-usable.

A key constraint: the report only includes claims that are supported by the actual analysis. If something wasn't observed, the report says so. Generic filler content, statements that would be true of any malware regardless of what was actually found, is not allowed. Every paragraph must connect to something that was actually found in this specific analysis.

---

### The Checkpoint: You Review the Draft

Immediately after the report writer finishes, the orchestrator does two things at once:

1. Launches the report reviewer as a **background task** (it starts working while you read)
2. Presents you with **Checkpoint 1**, a summary of what was produced and a prompt for your input

You see something like:

```
Draft complete. Files created:
  - reports/[malware-name]/index.md
  - ioc-feeds/[malware-name]-iocs.json
  - hunting-detections/[malware-name]-detections.md

Review the draft and respond:
  - "approved" to proceed
  - Request specific changes ("add more on the C2 infrastructure", "the attribution section is too thin")
  - "major revision needed" to return to Stage 1
```

While you are reading, the reviewer is already computing quality scores in the background. By the time you type "approved," the quality assessment is typically already done, no extra waiting.

Your options at this checkpoint:

- **Approve**, moves to quality gate check
- **Request targeted changes**, the orchestrator reruns the relevant agent(s), the report writer revises, and you see a new Checkpoint 1
- **Request major revision**, returns to Stage 1 for a full reanalysis pass

---

### Quality Gate (Automated)

When you approve, the orchestrator reads the quality gate results that the reviewer computed in the background. The reviewer scored the report across three expert perspectives:

- **Technical accuracy**, are the findings correct, is the MITRE mapping right, is confidence language calibrated?
- **Practitioner utility**, does every finding connect to a defender action, does the tactical layer actually answer what a SOC analyst needs?
- **Strategic clarity**, is the executive-level summary accessible, does it avoid jargon, does it connect to business risk?

**Score ≥ 8.0 with no critical issues:** Workflow proceeds to final polish.

**Score < 8.0 or critical issues found:** Report writer revises based on specific reviewer feedback and loops back. Maximum three revision cycles.

---

### Final Polish, Report Editor (~4 Minutes)

The report editor does a final formatting and consistency pass:

- Standardizes terminology throughout
- Verifies Markdown formatting is correct for publication
- Confirms third-party framing is maintained everywhere (no internal advisory language crept in)
- Removes any stale labels or placeholder text

---

### Checkpoint 2: Final Sign-Off

The orchestrator presents the polished files and waits for your final approval before marking the workflow complete.

---

### What You End up With

Three files, ready to publish or share:


| File                                              | What It Contains                 | Who Uses It                                      |
| ------------------------------------------------- | -------------------------------- | ------------------------------------------------ |
| `reports/[malware-name]/index.md`                 | Full threat intelligence report  | Security teams, management, the public community |
| `ioc-feeds/[malware-name]-iocs.json`              | Validated IOCs, machine-readable | SIEM platforms, EDR tools, firewalls             |
| `hunting-detections/[malware-name]-detections.md` | YARA, Sigma, Suricata rules      | Detection engineers, threat hunters              |


**Total agent work time (no revisions):** roughly 40–50 minutes.
**Your time investment:** Reading the draft at Checkpoint 1 and giving approval. Everything else is automated.

---

## Scenario 2: One Analyzed File

Everything described above still happens, the same agents, the same stages, the same three output files. The difference is that with less input data, the agents have less to work with, and the workflow adapts honestly rather than filling gaps with invented content.

Here is where the differences show up:

---

### Stage 1, Malware Analyst Has less to Work With

The malware analyst can only report what it finds. With one file instead of five, there are likely gaps: behavioral data may be limited if only a static sample was provided, network activity may be minimal or absent, and the overall picture is narrower.

The findings document is still structured the same way, but sections that cannot be filled from the available evidence are noted as such, "not observed in available samples," "insufficient data to assess." This feeds forward accurately into every downstream stage.

---

### Dispatch Checks Matter More

With a single file and limited behavioral data:

**If no network IOCs were found** (common with a single static sample), the infrastructure analyst is automatically skipped. There's nothing to pivot on. The dispatch becomes 3-way parallel instead of 4-way: IOC specialist, research analyst, and detection engineer only.

**If the malware family is known and recently cached**, the research analyst is also skipped. The workflow might run only the IOC specialist and detection engineer in parallel, 2-way, taking just a few minutes.

The workflow doesn't pad the process with agents that have nothing meaningful to contribute. It scales to the evidence.

---

### Attribution Is More Likely to Be Skipped

With one file and potentially no network infrastructure to analyze, the evidence base for attribution is thin. The orchestrator's feasibility check before invoking the attribution analyst is more likely to fail.

When attribution is skipped, the report doesn't speculate. It says: "Threat actor attribution was assessed as INSUFFICIENT based on available evidence. The following evidence gaps prevent meaningful attribution: [specific gaps]. Collection of [specific evidence types] would enable attribution assessment." This is more useful to the reader than a guess dressed up as analysis.

---

### The Report Is Honest About Its Scope

The report writer knows what evidence was available and what wasn't. It produces a complete report that is proportionally sized to the evidence, shorter where data is thin, candid about what couldn't be assessed, and explicit about what additional analysis would fill the gaps.

A single-file report with four well-evidenced findings and three clearly acknowledged gaps is more valuable and more credible than a padded multipage report that invented plausible-sounding content to fill the template. Honest gaps are a feature, not a failure.

The same quality gate applies, the reviewer still scores it against the same standards. A well-written, appropriately scoped single-file report can score 8.0+ just as easily as a multi-file one.

---

## The Design Principles Behind the Workflow

For those interested in why things work the way they do, here are the core principles that shaped every decision:

**Parallelism where possible, sequencing only where necessary.** Every minute spent waiting for a sequential agent that could have run in parallel is wasted time. The workflow maps dependencies carefully and runs anything that can run simultaneously in a single batch.

**Evidence first, always.** No agent is allowed to generate plausible-sounding content to fill a gap. If the evidence doesn't support a claim, the gap is documented explicitly. This is what makes the output trustworthy.

**Calibrated confidence, not false certainty.** Every significant claim in the output carries a confidence level with an explanation of what supports it and what's missing. "HIGH confidence, three independent sources corroborate, minor gaps in timeline" is more useful than "this is definitely APT28" with no evidence cited.

**Scale to the input.** The workflow doesn't run agents that have nothing to contribute. Two files with no network IOCs gets a different agent set than five files with rich behavioral data. The output is always proportional to what the input can actually support.

**Human checkpoints at key decisions.** The workflow automates the analytical work, but the researcher stays in control. Checkpoint 1 lets you redirect before the final report is locked in. Checkpoint 2 is your final sign-off. The automation handles the labor; you handle the judgment calls.

**Quality is gated, not assumed.** The report reviewer is not optional, it runs every time, scores against defined criteria, and the workflow will loop through revisions rather than publish a report that doesn't meet the threshold. Three revision cycles are allowed before escalation.

---

The goal of this workflow has always been the same: turn analysis into **intelligence the broader defender community can actually use**, intelligence that is **structured**, **repeatable**, and **evidence-based**, and that meets the **standard of accuracy and trust** readers need to feel confident acting on it. Threat intelligence published months after a threat is already active in the wild **isn't intelligence, it's history**. A raw analysis that never becomes a report, detection rules that never get shared, these are missed opportunities for **defenders who need them**. 

Everything built into this agentic system, from the multi-agent architecture and parallel dispatch logic, to evidence-gating and confidence calibration, to structured quality gates and human checkpoints, exists to close that gap. **The human analyst handles everything that requires judgment**. The workflow handles everything else. That division of labor is what makes it possible to publish findings while they still matter, **without cutting corners to get there**.

---

*Document and workflow is maintained by The Hunters Ledger, independent threat intelligence research.*