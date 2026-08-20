---
title: "Step 3: Verifying and Shipping It"
date: '2026-08-20'
layout: page
permalink: /behind-the-reports/gates-and-distribution/
hide: true
description: "The gates that stop the Hunters Ledger pipeline reporting success it has not earned, and where the finished intelligence goes after it publishes."
---

<div class="hl-page-header" style="--ph-accent: #f97316;">
  <div class="hl-page-header__label">Behind the Reports</div>
  <div class="hl-page-header__title">Verifying and Shipping It</div>
  <div class="hl-page-header__desc">The checks that stop the pipeline lying to me about its own work, and where the finished intelligence actually goes.</div>
</div>

<div class="hl-note" style="margin-bottom: 2rem;">
  <div class="hl-note__label">Step 3 of 3</div>
  <div class="hl-note__body">The target was <a href="{{ '/behind-the-reports/collection-platform/' | relative_url }}">found and chosen</a>, and the analysis became <a href="{{ '/behind-the-reports/ai-workflow/' | relative_url }}">a drafted report</a>. This page is everything after I sign it off. For the whole flow on one page, see <a href="{{ '/behind-the-reports/' | relative_url }}">the overview</a>.</div>
</div>

## The Problem This Page Is About

Every part of this pipeline reports on itself. Agents say their work went well, scripts exit zero, deploys report success.

For a long time I treated those reports as evidence, and every genuinely expensive mistake I have made here came from that assumption being wrong. Not from a check failing, but from a check passing without having looked at anything.

By the time a report reaches this stage it has survived a lot already. A target I chose deliberately, analysis I did by hand, and a workflow that drafted and scored it. What is left is proving the detection rules actually work, and then getting all of it to the people who need it.

---

{% include section-header.html label="Verification" accent="#4ade80" %}

## The Gates

Here is the rule the whole verification layer is built on.

> A gate that reports success without having verified anything is worse than no gate. It consumes the attention a real check would have earned, and it converts "unverified" into "verified clean" at the exact moment a human stops looking.

So every check here reports one of three outcomes, not two.

<div class="hl-feat-grid">
  <div class="hl-feat">
    <div class="hl-feat__title">PASS</div>
    <div class="hl-feat__desc">The check ran, against real input, and the input was good.</div>
  </div>
  <div class="hl-feat">
    <div class="hl-feat__title">FAIL</div>
    <div class="hl-feat__desc">The check ran and the input was bad.</div>
  </div>
  <div class="hl-feat">
    <div class="hl-feat__title">NOT CHECKED</div>
    <div class="hl-feat__desc">The check did not run, or ran against nothing. It carries a reason.</div>
  </div>
</div>

The whole rule is that **NOT CHECKED is never folded into PASS**, and almost every silent failure I have found here was a third state being quietly reported as the first.

### Rules are compiled, not inspected

The detection validation gate does not read the rules to see whether they look right. It compiles them.

Every YARA rule in a detection file goes through the real YARA compiler. Every Sigma rule goes through SigmaHQ's own validator with the official rule-checking plugins. Every Suricata signature is shipped to a live Suricata engine and parsed by it. Any compile or parse error fails the gate and sends the detection engineer back to fix it.

None of that executes anything malicious, which is worth saying plainly. Compiling rule *text* is not running malware. It just checks that the rule a defender is about to deploy is a rule at all.

This gate exists because inspection provably does not work. Before it, a batch of published YARA rules turned out not to compile, having shipped past several careful human readings. Missing imports, strings declared and never referenced, a brace in the wrong place. Every one of those looks completely fine to a reader and dies instantly at the compiler. The same applies on the Sigma side, where ATT&CK tag drift and field names that do not exist in the schema are invisible to inspection and obvious to the validator.

And when the sensor is unreachable, the Suricata check does not pass. It reports **CHECK NOT VERIFIED** with the reason, because a rule nobody could validate is not a validated rule.

### The question above that one

Gate honesty asks whether a check is truthful about having run. There is a question one level above it that took me longer to ask: does every capability I claim **actually have a gate behind it**?

Those two failures look identical from outside. A gate that lies about running and a claim with nothing behind it both present as a documented capability nobody has reason to doubt. Every expensive defect in this stack has been the second kind. A batch of Sigma rules that imported into the detection stack cleanly and then executed zero times, covered by a deploy procedure that said they were deployed. A Suricata rule whose pattern matched on every packet, shipped under a feed process that said it was validated. A data pipeline reporting success while silently dropping records.

So every capability claim is now written down in a matrix against the thing that enforces it, marked **GATED**, **PARTIAL**, or **NO GATE**. Those mirror the three outcomes above, and they inherit the same rule: NO GATE is never quietly written up as GATED. A checker verifies the shape of that matrix, refusing any row that claims enforcement without naming something that actually runs, and any row admitting a gap without describing it. Adding a new capability claim means adding a row.

### What none of this buys

It does not buy correctness, and pretending otherwise would be the same mistake in a new hat.

The Suricata rule that matched every packet passed both the engine parse and the false-positive lint, because both asked a different question than "is this rule right." No convention prevents that. These gates assert that a check is honest about *whether it ran*. They cannot assert that it asks the right question. That still needs a person, which is why there are still two human checkpoints in the workflow and an adversarial review pass over the conclusions.

---

{% include section-header.html label="Distribution" accent="#58a6ff" %}

## Where It Goes

A signed-off report is not a published report, and publishing is not one action.

### The site

Publication defaults to an unlisted preview. The pages are live and reachable by URL, but they are not in any listing and not indexed, so I can read the thing as it will actually render, share it with a CERT or an affected organization ahead of disclosure, and still change my mind. Going public is a separate, explicit step.

A single catalog entry drives everything. One record per campaign produces the report card, the detection page listing, the IOC feed listing, and the home page block, so the three deliverables cannot drift apart or go live half-listed.

Publishing also regenerates the consolidated public Suricata feed, currently 98 rules, and revalidates the whole thing against a live engine before staging it. That is a deliberate backstop. If a rule ever slipped past authoring, because the sensor was down or because I hand-edited something, it gets caught before it reaches anyone pointing an IDS at the feed. When the engine rejects the batch it suppresses per-rule errors, so the validator bisects the file to name exactly which rule failed rather than reporting that something, somewhere, is broken.

### Machine-readable, for the platforms that want it

Every published campaign also becomes a STIX 2.1 bundle, 38 of them so far, modelling the report as a linked graph of indicators, malware, tools, infrastructure, techniques, vulnerabilities, and the actor where one can be named. They import into OpenCTI, MISP, or anything else that speaks STIX.

Two design decisions in there matter more than the format. Object IDs are deterministic, so re-importing an updated bundle upserts rather than duplicating, and shared entities resolve to a single node across every campaign. That means a platform can answer "show me every report touching this technique, this address, this actor" instead of holding thirty-eight disconnected islands.

The second is a filter on what gets modelled as an indicator at all. Public and dual-use tooling, the privilege-escalation utilities and credential tools that turn up in half these toolkits, is modelled as something the actor *uses*, never as a detection indicator. Importing a bundle should never quietly poison a block list with a tool that also runs legitimately on the network. Anyone can ingest these feeds automatically, which means nothing in an indicator bucket is allowed to harm a bystander.

### Upstream, and into a real stack

Detection rules that hold up go upstream to the public repositories the community actually pulls from, which is where they get used by people who will never read this site.

They also go into my own detection stack, Sigma rules into the SIEM and YARA rules into the endpoint tooling as on-demand hunts. That is not a victory lap, it is the feedback loop. When one of my own rules generates a false positive during live triage, the first question is not how to tune it locally. It is whether the rule itself is defective, because if it is, every defender who deployed it has the same problem and cannot see it. A defective rule gets fixed at the source, revalidated, redeployed, and republished. Only a false positive that is genuinely specific to my network gets handled as a local exception.

Running detections I wrote against traffic I do not control is the only way I get to find that out.

### And to the people affected

Some findings are not a publication problem, they are somebody's incident. Credentials belonging to a real organization, a compromise in progress, a victim who does not know yet. Those go to national CERTs, incident response teams, and the organizations themselves, ahead of publication and through an encrypted channel where one is wanted.

That is why the preview-first default exists at all. The report needs to be readable and shareable before it is public, because the people who most need it are usually not the audience the front page is for.

---

## The Through-Line

None of this started as design. Every gate on this page is a scar. The compile gate exists because rules shipped broken, the three-state contract exists because passing checks turned out to have checked nothing, and the guard on STIX indicators exists because a feed that anyone can auto-ingest can do real damage to someone who trusted it.

The useful part is not any individual check. It is the habit underneath them, which is to keep asking what this system would look like if it were quietly wrong, and then go and build the thing that would tell me.

<div class="hl-note" style="margin-top: 2.5rem;">
  <div class="hl-note__label">That is the whole loop</div>
  <div class="hl-note__body">Back to <a href="{{ '/behind-the-reports/' | relative_url }}">the overview</a>, or straight to <a href="{{ '/reports/' | relative_url }}">the reports themselves</a>.</div>
</div>
