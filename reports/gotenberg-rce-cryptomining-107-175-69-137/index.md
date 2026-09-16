---
title: "Gotenberg CVE-2026-42589 Mass Exploitation and Cryptomining"
date: '2026-09-16'
layout: post
permalink: /reports/gotenberg-rce-cryptomining-107-175-69-137/
thumbnail: /assets/images/cards/gotenberg-rce-cryptomining-107-175-69-137.png
category: Mass Exploitation
description: One operator confirmed remote code execution on 198 internet-facing Gotenberg instances in 54 minutes and dropped a cryptominer, and the obvious network signature for the attack never fires because the injected newlines are JSON-escaped on the wire.
detection_page: /hunting-detections/gotenberg-rce-cryptomining-107-175-69-137-detections/
ioc_feed: /ioc-feeds/gotenberg-rce-cryptomining-107-175-69-137/
detection_sections:
  - label: "Detection Coverage Summary"
    anchor: "#detection-coverage-summary"
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "Suricata Signatures"
    anchor: "#suricata-signatures"
  - label: "Coverage Gaps"
    anchor: "#coverage-gaps"
ioc_highlights:
  - value: "107[.]175[.]69[.]137"
    note: "Operator host: open directory, payload staging, OOB listener and reverse-shell collector"
  - value: "456UWvWXto1PacXMu689Mghh2QWQg2amvapezv3HWucT2KiKz86VQYJZ9cHGha6NbuTyqrrRDrJKSPB2eS7BNwkhSuw5QQU"
    note: "Monero payout wallet, the only operator-unique indicator in the case"
  - value: "/usr/bin/polkitd.d/"
    note: "Persistent miner install path; a reboot does not clear this one"
  - value: "systemd-polkitd.service"
    note: "Root systemd unit, Restart=always, that makes the persistent mode survive"
hide: true
unlisted: true
figure_nav:
  - image: gotenberg-confirmation-funnel.svg
    parts:
      - label: RCE confirmed
        anchor: '#the-confirmation-method-is-also-not-the-operators-own-idea'
      - label: Miner installs verified
        anchor: '#two-install-modes-and-the-one-that-gets-missed-matters-more'
  - image: gotenberg-escalation-ladder.svg
    parts:
      - label: Timing-based RCE confirmation
        anchor: '#the-confirmation-method-is-also-not-the-operators-own-idea'
      - label: Deployment
        anchor: '#two-install-modes-and-the-one-that-gets-missed-matters-more'
---

**Campaign Identifier:** Gotenberg-RCE-Cryptomining-107.175.69.137<br>
**Last Updated:** September 16, 2026<br>
**Threat Level:** HIGH

---

## 1. Executive Summary
{: .hl-tier-1}

One disclosed CVE turned into a 198-host compromise in under an hour, and the obvious network
signature for this exact injection never fires on real traffic. That is the whole report in two
sentences, a near-zero-effort exploit chain and a detection trap that catches anyone who builds a
rule from the vendor advisory alone.

The vulnerability is CVE-2026-42589, an unauthenticated remote code execution flaw in
Gotenberg, an open-source document-conversion service. The payload does not go in
a metadata *value*, where any defender reading a request would expect an injection. It goes in
the metadata *key*, splitting ExifTool's argument parser and reaching a Perl `eval` through the
`-if` flag. This exact payload, down to its placeholder value, is copied verbatim from the
vendor's own security advisory (HIGH-to-DEFINITE). The barrier to entry for this attack is zero,
and the working exploit sits in a public document anyone can read, so expect unrelated copycats
to reach for the same primitive, not only this operator. What is not copied is the campaign built
around it: 206 candidates probed, 198 confirmed exploitable, and a cryptominer running on
somewhere between 148 and 151 of them, the whole thing inside a 54-minute window on 2026-08-31.

Then the finding that matters most for anyone defending against this exact CVE. The obvious
detection signature for this injection, a regex on the raw newline bytes that split the metadata
key, does not fire on a single real request. The metadata field travels as JSON, so the injected
newline never reaches the network as a raw newline byte. It reaches the wire as the two-byte
escape sequence backslash-then-`n`, and Gotenberg only converts it back to a real newline after
its own server has already parsed it, which is after any network sensor has already seen and
passed the packet. Anyone who writes a rule for this CVE straight from the advisory will build
one that parses cleanly, loads without error, and never once matches. Section 3 gives the rule
that actually works, and warns why the escaped bytes must never be "corrected" back to a literal
newline.

This campaign is also not the operator's main business. The exploit chain and the
cryptominer are the smallest, most fully automated line inside a larger criminal enterprise that
also runs mass web-application exploitation against named commercial platforms, an Android
device-farm operation, and a Telegram account farm selling verified accounts and OTP-bypass
inventory as a commercial product. I am not naming any of the targeted platforms in this report;
what matters for a defender is the shape of the operation, not who else got hit.

### The threat in clear terms

If your organization ran an internet-facing Gotenberg instance inside the affected version band
during the campaign window, the operator gained:

- **Unauthenticated remote code execution** through the metadata-write endpoint, with no
  authentication and no user interaction required (DEFINITE, the exploit chain reproduces cleanly
  and is measured against captured traffic).
- **A cryptominer install**, in one of two modes: an ephemeral drop that a reboot clears, or a
  persistent root-owned systemd service that does not (DEFINITE, both variants recovered from the
  operator's own staged payload).
- **A working blind-RCE confirmation channel** the operator can reuse against any other exploitable
  service, since the escalation ladder, the timing-based confirmation, and the out-of-band
  callback tagging are all generic infrastructure, not Gotenberg-specific code (HIGH, read
  directly from the operator's own scripts).
- A demonstrated willingness to take resources already claimed by a different intruder: the
  deploy script kills a named list of rival miners, including one already running on at least one
  victim, before installing its own (DEFINITE, observed in real deploy output from real victims).

### Classification

This is HIGH-severity, unauthenticated mass exploitation of a document-conversion service,
delivering a commodity cryptominer, **XMRig 6.26.0, unmodified**. It is not a targeted intrusion
against any single organization. If Gotenberg was internet-facing and unpatched in your
environment during the campaign window, code execution as the Gotenberg service account is a
DEFINITE conclusion rather than a risk to model.

### Risk Rating: HIGH

<table>
<colgroup>
<col style="width: 26%;">
<col style="width: 16%;">
<col style="width: 58%;">
</colgroup>
<thead>
<tr><th>Risk Factor</th><th>Score</th><th>Justification</th></tr>
</thead>
<tbody>
<tr><td>Data Exfiltration</td><td>5/10</td><td>The confirmed campaign, mining, exfiltrates nothing. The wider apparatus includes a live, unscoped credential-harvesting surface and data-theft tooling naming commercial platforms, but zero of those show content-level access; the risk is real but unconfirmed.</td></tr>
<tr><td>System Compromise</td><td>9/10</td><td>Unauthenticated remote code execution, confirmed on 198 of 205 probed hosts (96.6%), with a persistent, root-privileged install mode available.</td></tr>
<tr><td>Persistence Difficulty</td><td>7/10</td><td>Two install modes exist. The one the observed campaign actually deploys clears on reboot; a second, shipped in the same package, installs a root systemd unit with <code>Restart=always</code> that does not. "Reboot and it is gone" is the wrong advice for an unknown share of installs.</td></tr>
<tr><td>Evasion Capability</td><td>5/10</td><td>The binary itself carries no packing or custom obfuscation. The operational blind spot is structural instead: the natural detection signature for this exploit never matches real traffic, which functions as evasion without the operator doing anything to earn it.</td></tr>
<tr><td>Lateral Movement</td><td>3/10</td><td>Nothing in the recovered tooling moves laterally from a compromised Gotenberg host. This is scan-confirm-deploy against internet-facing instances, not an intrusion that pivots once inside a network.</td></tr>
<tr><td>Detection Difficulty</td><td>8/10</td><td>MEASURED, not inferred: a signature written by reading the operator's own source code fails against real captured traffic, because the injection travels JSON-escaped on the wire and is only decoded after any sensor has already seen it.</td></tr>
<tr><td><strong>OVERALL RISK</strong></td><td><strong>7.3/10</strong></td><td><strong>HIGH</strong></td></tr>
</tbody>
</table>

> This assessment rests on the operator's own recovered scripts and configuration files, a
> reproduction of the exploit chain verified against captured traffic, and passive infrastructure
> enrichment. Confidence levels are stated throughout to separate what was directly observed from
> what I am inferring.

> The investigation that produced this report is closed and the disclosure round to affected
> providers is complete. Two things remain genuinely open at publication: whether the persistent
> systemd install mode reached any of the 198 confirmed hosts, and what the operator's Android
> device-farm and Telegram account-management capability is actually for beyond existing.

---

## 2. What This Campaign Is
{: .hl-tier-2}

### Classification and Identification

<table>
<colgroup>
<col style="width: 22%;">
<col style="width: 40%;">
<col style="width: 20%;">
</colgroup>
<thead>
<tr><th>Attribute</th><th>Value</th><th>Confidence</th></tr>
</thead>
<tbody>
<tr><td><strong>Vulnerability</strong></td><td>CVE-2026-42589, Gotenberg ExifTool metadata-key injection, unauthenticated RCE (CVSS 9.8)</td><td>DEFINITE</td></tr>
<tr><td><strong>Payload family</strong></td><td>XMRig 6.26.0, stock and unmodified</td><td>DEFINITE (static analysis)</td></tr>
<tr><td><strong>Campaign type</strong></td><td>Automated mass exploitation against internet-facing instances of one vulnerable software version band</td><td>DEFINITE</td></tr>
<tr><td><strong>Operator sophistication</strong></td><td>LOW on vulnerability research; MODERATE-HIGH on operational engineering, never averaged</td><td>see Section 9</td></tr>
<tr><td><strong>Status</strong></td><td>The campaign-specific listeners are offline; the underlying host remains live and administered</td><td>DEFINITE</td></tr>
</tbody>
</table>

A second CVE identifier exists for a related bug, and this campaign is not that one.
CVE-2026-40281 also targets Gotenberg's ExifTool integration, but it injects into the metadata
**value**, reaching ExifTool pseudo-tags like `-FileName` and `-SymLink` for arbitrary file
rename, overwrite, and symlink creation (CVSS 10.0, fixed in 8.31.0). I fetched both advisories
directly rather than trust a secondary summary, because the two bugs are frequently discussed
together and conflating them would misdirect a defender's patching priority. This campaign's
injection is in the metadata **key**, reaches ExifTool's `-if` flag, and evaluates arbitrary Perl.
Every detection in this report and its companion detection file cites CVE-2026-42589, and that
citation is correct.

### Why this is HIGH-severity, unauthenticated mass exploitation

- No authentication of any kind is required. The vulnerable endpoint,
  `POST /forms/pdfengines/metadata/write`, accepts the injection from any client that can reach
  it.
- **The confirmation rate on probed, live targets was 96.6%** (198 of 205), which is not a scan
  result. It is a compromise count, and I return to why that number is credible in Section 4.
- **Full code execution** as the Gotenberg service account follows, not a
  denial-of-service or an information leak. Everything downstream, the miner, the recon, the rival
  displacement, follows from that.

---

## 3. The Exploitation Mechanism, and the Detection Signature That Never Fires
{: .hl-tier-3}

This is the report's most important technical finding, and it is a negative result: the obvious
detection rule for this exact injection does not work, and reading the operator's own source
code would never have told me that.

### How the injection actually works

Gotenberg hands user-supplied PDF metadata to ExifTool for writing. The operator's request is an
ordinary multipart form POST to `/forms/pdfengines/metadata/write`, carrying a PDF file and a
`metadata` field that is a JSON object. The injection does not sit in a metadata *value*, which is
where a defender reviewing the endpoint would look first. It sits in the metadata **key**:

```
Title\n-if\nsystem('sleep {N}')||1\n-Comment
```

The embedded newlines are the whole mechanism. When Gotenberg passes this key to ExifTool,
ExifTool's argument parser splits on the newlines, so `-if` stops being part of a literal key
name and becomes ExifTool's own command-line flag. `-if` evaluates its argument as Perl, so
`system('sleep 5')||1` runs an arbitrary shell command and the trailing `||1` keeps the
expression truthy, so ExifTool's processing continues normally and nothing about the response
looks wrong. A `q()`-wrapped variant, `system(q(...))||1`, is the operator's own fix for payloads
containing single quotes, which tells me this was iterated on rather than written once and left
alone.

I confirmed by direct comparison that this is not the operator's own discovery. I fetched
Gotenberg's own GitHub Security Advisory for CVE-2026-42589 and read its published
proof-of-concept payload against the operator's own. They match almost element for element: the
same key-position injection shape, the same `||1` truthiness suffix, the same trailing dummy
`-Comment` key, and even the advisory's own placeholder metadata value, the literal character
`"x"`, which I confirmed on the captured wire traffic. That value has no technical reason to
match by chance. Only the command inside `system()` differs, and that is exactly what changes
when a defender's demonstration marker becomes an attacker's operational timing probe. I hold
this at DEFINITE on the comparison itself; the one honest limitation is that only one public
proof-of-concept repository exists to compare against, so I cannot rule out a shared, unpublished
upstream source for both.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/gotenberg-rce-cryptomining-107-175-69-137/gotenberg-injection-metadata-key.png" | relative_url }}" alt="A test script builds an ExifTool metadata key containing embedded newlines, an -if flag, and a system() call wrapped in a sleep-based timing check, illustrating how the newlines split ExifTool's argument parser so -if evaluates arbitrary Perl.">
  <figcaption><em>Figure 1: The injection mechanism, shown as a standalone test script used to develop and confirm the technique. This is not the tool that drove the campaign itself; a separate, curl-based script issued all 198 confirmed requests. What matters here is the key construction: embedded newlines turn a metadata field name into an ExifTool command-line flag.</em></figcaption>
</figure>

### The confirmation method is also not the operator's own idea

Confirming the injection worked without leaving a payload behind is a genuinely elegant choice,
and I initially read it as operator engineering. It is not. The operator times a baseline
metadata write against an injected one and calls the target confirmed when the delta is at least
70% of the injected sleep duration, so a five-second sleep needs a 3.5-second delay to count. I
found the identical sleep-based blind-timing confirmation technique, with a duration-threshold
verdict, published in a public proof-of-concept repository's own detection template, created and
last pushed roughly three months before the operator staged this campaign's payload. The operator
did not invent a stealthier way to confirm remote code execution. They read one that was already
public, indexed, and three months old, and used it as written.

That distinction matters for how I read this operator's overall capability. Section 9 keeps the
two axes separate: the vulnerability-research side of this operation is copied, at or below the
public floor. What is not copied is everything built around it, which is the subject of the rest
of this report.

### Why the obvious detection signature never fires

The obvious detection signature, built straight from the operator's own scripts, is a regex on
the raw injection bytes: `\n-if\n[^\n]*system\s*\(`. Against real traffic, it does not match a
single request.

The reason is structural rather than a typo in the regex.
The `metadata` field travels as a JSON string, so before it ever leaves the client, JSON encoding
escapes the embedded newline to the two-byte ASCII sequence backslash and `n` (hex `5c 6e`).
Gotenberg's server only converts that escape sequence back into a real newline character *after*
its own HTTP layer has already parsed the request body, which is after any network sensor sitting
in front of it has already seen and passed the packet unmodified. A rule written against a literal
`0x0A` newline byte, whether as a raw Suricata `content` match or a PCRE `\n`, will parse cleanly,
load without error, and never once fire on real traffic. Both natural readings of the regex return
zero matches against the operator's own real request, measured directly against captured traffic
rather than inferred from the source alone.

<details markdown="1" class="hl-teardown">
<summary>The controls that proved it</summary>

Six legitimate metadata-write requests should never match this signature, and none of them did: a
single-key write, a multi-key write, a value containing a literal embedded newline, a key
containing the word "system" with no `-if` shape at all, and two fields exercising unicode and
heavy punctuation. One of the six, a metadata *value* carrying embedded newlines, triggers an
unrelated HTTP 500 from Gotenberg's own ExifTool wrapper. That failure is real and reproducible,
but it carries neither `-if` nor `system(`, so it is a separate, unrelated bug in how Gotenberg
handles that specific input shape, not a detection false positive.

</details>

**The corrected anchor**, matched against the JSON-escaped wire form and measured, not inferred:

```
content:"|5c 6e 2d 69 66 5c 6e 73 79 73 74 65 6d 28|"
```

This is the literal hex-escaped form of `\n-if\nsystem(`, matched against the HTTP request body on
POSTs to `/forms/pdfengines/metadata/write`. It survives every transport variant that could be
reproduced: a different sleep duration, and the base64-transported deploy shape the operator uses
for the actual miner drop. The three-transport retry ladder's exact command shape is not
byte-confirmed on the wire, though every script that builds this key produces the same invariant
`\n-if\nsystem(` prefix regardless of what the command inside it does, so I expect the anchor holds
there too (MODERATE on that one variant specifically, HIGH on the anchor generally).

One warning has to travel with this rule wherever it goes. The Suricata content match
above is a hex byte sequence, not readable text, and it looks wrong to anyone who has not read this
section. An analyst "tidying" `|5c 6e 2d 69 66 ...|` back into a literal newline byte, or into a
PCRE `\n`, produces a rule that parses cleanly, passes every syntax check, and never fires on real
traffic again. This is, in my judgment, the single most likely way this finding gets quietly
destroyed in a future edit, so the companion detection file carries the warning as a load-bearing
comment directly above the rule, not as a note someone can miss.

### What a defender actually sees, and its limits

HTTP status code never distinguishes a confirmed injection from an ordinary metadata write; both
return 200. Latency is the only observable signal, and the 70%-of-sleep threshold holds with real
margin against a measured clean baseline of roughly 250 to 650 milliseconds on this endpoint.
Gotenberg's own structured access log never records the metadata payload on a request that parses
as valid JSON, so content-based detection is not possible from Gotenberg's own logs at all; it
requires visibility at the network or reverse-proxy layer, wherever the raw request body is
actually captured.

A signature derived by reading source code, and never checked against real traffic, looks
finished. It parses cleanly and passes every syntax check. Only a test against real captured
bytes catches that it never fires. The only version of this signature worth deploying is the one
measured in this section against actual wire traffic, not one built from the advisory or the
operator's own scripts alone.

---

## 4. Campaign Scale, Timing, and Escalation Discipline
{: .hl-tier-3}

### The numbers, and why I trust them

<table>
<colgroup>
<col style="width: 30%;">
<col style="width: 14%;">
<col style="width: 56%;">
</colgroup>
<thead>
<tr><th>Figure</th><th>Value</th><th>Basis</th></tr>
</thead>
<tbody>
<tr><td>Targets listed</td><td>206</td><td>Row count of the operator's own target list, byte-verified</td></tr>
<tr><td>Targets probed alive</td><td>205</td><td>1 target was dead at probe time</td></tr>
<tr><td>RCE confirmed</td><td>198 (96.6% of probed)</td><td>Timing side-channel verdict, row count matched against the out-of-band sweep results</td></tr>
<tr><td>Distinct confirmed IPs</td><td>196</td><td>Two hosts each contributed two vulnerable ports</td></tr>
<tr><td>Called back, own address</td><td>167 OBSERVED</td><td>Direct IP match in the callback log</td></tr>
<tr><td>Called back, shared egress</td><td>17 INFERRED</td><td>Tag matched, but from a gateway or NAT address rather than the host's own</td></tr>
<tr><td>Never called back</td><td>14</td><td>Absent under every callback channel the operator built, including three retry transports</td></tr>
<tr><td>Miner install verified</td><td>148 to 151</td><td>See the derivation below; 28 hosts are permanently unattributable</td></tr>
</tbody>
</table>

I am stating this plainly rather than softening it into a hedge: **never write the callback total
as 184 alone.** The honest sentence names both populations, 167 confirmed from the host's own
address and a further 17 inferred through shared provider egress, because the two are different
grades of evidence and collapsing them into one number overstates the weaker of the two.

These are not estimates. Every count above is a row count from a surviving artifact whose parse I
verified byte-for-byte, not a figure someone remembered. That distinction matters here specifically
because two of these numbers moved during this investigation, and I want the record to show the
moves rather than hide them.

<details markdown="1" class="hl-teardown">
<summary>Two figures that changed during the investigation, and why the current ones are trustworthy</summary>

The miner-install figure was originally recorded as 158. A blind re-derivation from the raw
callback log, run without being shown the existing table, credited at most 147 to 149 installs,
a gap of nine to eighteen hosts. That gap does not resolve to a disagreement; it resolves to a
genuine limitation in the surviving evidence. The main deploy wave's own target-list ordering was
never preserved on disk, so the index that ties one deploy callback to one specific host is
unrecoverable for a meaningful fraction of the campaign. Every reconstructed ordering I tested,
and every one a prior pass tested, rejected at over 90% mismatch against the observed timing.
Timing correlation shows the deploy wave was dispatched roughly in the recorded order (r = 0.985),
but the log's one-second timestamp resolution cannot disambiguate individual hosts within that
order.

There is also a direct, byte-level explanation for part of the gap: the operator's own callback
listener writes two unlocked fields per request from a threaded server handling dozens of
simultaneous connections, and I found proof that this raced under load. One recorded response body
ends mid-token and runs directly into a different connection's success marker with no line break
between them. The operator built a pipeline good enough to confirm 198 exploits in 54 minutes and
instrumented it with a listener that loses its own data under the exact load it was designed to
create.

Given that, 148 is the defensible floor, 151 is the ceiling once two genuinely ambiguous
multi-port hosts are credited, and 28 hosts are permanently unattributable: 14 with no callback
under any channel, and 14 more where code execution is certain but no deploy record survives to
credit an install either way. A further group of 15 hosts shows a statistically suggestive pattern
(a 93% local tag-match rate against a 34.6% baseline for the shared-egress mechanism) that would
push the range toward 163 to 166 if credited. I am deliberately not crediting it: suggestive is not
verified, and this case has already had one number published on weaker grounds than that.

The callback total moved for a related reason. An earlier pass recorded 178, then 179, then a run
of intermediate values, before a full recount against the raw log settled on 184, split as stated
above. The instability across those early passes is exactly the kind of thing a published report
should never carry forward silently, which is why this section states the derivation rather than
just the final number.

</details>

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/gotenberg-rce-cryptomining-107-175-69-137/gotenberg-confirmation-funnel.svg" | relative_url }}" alt="Vertical seven-step infographic titled The confirmation funnel. Step 1, orange band: 206 targets listed, every host in the operator's own target list, verified byte for byte, version band Gotenberg 8.17.0 through 8.30.1. Step 2, orange band: 205 probed and fingerprinted, one listed target was already dead at probe time, liveness and fingerprinting ran through a local SOCKS5 proxy. Step 3, red band: 198 RCE confirmed, 96.6 percent of probed, timing side-channel verdict matched against the out-of-band sweep results, 196 distinct IPs with two hosts each contributing two vulnerable ports. Step 4, red band: 184 called back, never a single number, 167 OBSERVED meaning the callback arrived from the host's own IP address, 17 INFERRED meaning the tag matched but from a shared gateway or NAT address, with an orange emphasis line reading two grades of evidence, collapsing them overstates the weaker one. Step 5, grey band: 14 never called back, absent under every callback channel the operator built, including three retry transports, wget, curl, and nc. Step 6, deep red band: 148 to 151 miner installs verified, 148 is the floor and 151 the ceiling once two ambiguous hosts are credited, a further 15-host suggestive bucket is deliberately not credited. Step 7, grey band: 28 permanently unattributable, 14 with no callback plus 14 more with execution but no deploy record, because the main deploy wave's target-list ordering was never preserved on disk. Footer states never publish 158, 179, 178, 177 or 21, all are superseded above, with a legend mapping orange to target scoping, red to exploitation confirmed, grey to excluded from the count, and deep red to confirmed miner install.">
  <figcaption><em>Figure 2: The confirmation funnel from target list to verified miner install, using only the corrected figures from the table above. The 184 callback figure is deliberately shown split rather than as one number, because the 167 OBSERVED and 17 INFERRED hosts rest on different grades of evidence.</em></figcaption>
</figure>

### The window: 54 minutes, and the deliberate ordering around it

The campaign itself ran from 2026-08-31 02:50:03 to 03:44:22 UTC, read directly from the first and
last genuine lines of the operator's own callback log. I am treating the timezone as the writing
host's own system clock, since nothing in the corpus independently confirms it, but that caveat
does not touch the duration, which is internally consistent across every timestamped artifact I
checked.

The operator did not fire this blind. Before any exploit ran, the payload itself was staged five
days in advance: the miner binaries carry a build timestamp of 2026-08-26. Then, eleven minutes
into the campaign, both deployed miner configuration files were regenerated live, before the mass
deployment wave actually ran. I read that as a premeditated operation with a live tuning step in
the middle of execution, not an improvised one; the timestamps themselves are directly observed,
the reading of intent behind them is mine.

The stages ran in a fixed, escalating order, and each one gates the next:

1. **Liveness and fingerprinting** against all 206 candidates, through a local SOCKS5 proxy.
2. **Timing-based RCE confirmation**, the mechanism Section 3 covers in full.
3. **Out-of-band callback**, injecting a command that curls back to the operator's listener with a
   tag built from the victim's own hostname and numeric user ID, which is what makes 198
   simultaneous callbacks individually attributable to specific hosts.
4. **A three-transport retry** (wget, then curl, then `nc`) for any host that did not call back on
   the first attempt, with each transport tagging its own callback so the log itself records which
   binary existed on that host.
5. **A pre-deployment recon pass**, checking for rival miner processes, free space in `/tmp`, and,
   critically, actually touching `/tmp/.wt` to confirm the directory is writable before spending a
   payload there.
6. **Deployment**, only after every prior gate passed.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/gotenberg-rce-cryptomining-107-175-69-137/gotenberg-escalation-ladder.svg" | relative_url }}" alt="Vertical six-step infographic titled The escalation ladder. Step 1, orange band: liveness and fingerprinting, all 206 candidates probed through a local SOCKS5 proxy, confirming the host is up and selecting the Gotenberg version band. Step 2, red band: timing-based RCE confirmation, a baseline write timed against an injected one where 70 percent of the delay counts, the blind-timing method itself copied from a public proof-of-concept. Step 3, red band: out-of-band callback, the command curls back with a tag from the host's own hostname and user ID, which is what makes 198 simultaneous callbacks individually attributable. Step 4, red band: three-transport retry, wget then curl then nc for any host that missed the first callback, each transport tagging its own callback to record which binary existed. Step 5, yellow band: pre-deployment recon, checking for rival miners, free space in slash tmp, and actually touching slash tmp slash dot wt to confirm writability, noting one host returned permission denied and the operator logged it and moved on. Step 6, deep red band: deployment, only after every prior gate passed, yielding 148 to 151 confirmed installs. Footer reads skip any gate and the operator wastes a deploy slot, so none were skipped, with a legend mapping orange to scoping, red to confirmation, yellow to staging, and deep red to deployment.">
  <figcaption><em>Figure 3: The six-stage escalation ladder, each stage a precondition for the next. The discipline of gating every stage, including a live writability check before spending a payload, is itself one of this report's findings about the operator's capability.</em></figcaption>
</figure>

The writability probe is the detail that tells me this operator does not waste effort. I found
direct proof of why it matters: on the one host where the operator worked interactively rather
than through the automated pipeline, the same recon logic hit `touch: cannot touch
'/etc/.wtest': Permission denied` and recorded the failure rather than attempting a doomed write.
A payload deployment attempt against a read-only target produces nothing but a wasted deploy slot
and a callback that never resolves; this operator pays a cheap recon cost specifically to avoid
that outcome at scale.

This ordering, in my reading, is the single clearest piece of evidence for real operational
discipline in this campaign, and it stands in genuine tension with the operator's own front door: a
reverse-shell collector on port 13337 sat unauthenticated and reachable from the internet for the
entire campaign, and the log on it is full of unrelated scanner noise, meaning anyone who happened
to connect during the window could have watched the operator's own interactive sessions. Careful
about targeting, careless about their own exposure. Section 9 carries that same split forward as
two separate capability axes rather than averaging it into one adjective.

I want to close the recon-host question I raised, and how the evidence actually settled it.
Given that 205 targets were fingerprinted, timed, and had a version band selected before this 54-minute window
even started, my working assumption going in was that a serious recon phase must have happened
somewhere else, most likely on a separate host stood up for exactly that purpose, because 54
minutes of automated execution plainly could not have also produced that reconnaissance. The
infrastructure work in Section 7 answers this directly, and the answer reframes the question rather
than confirming my assumption: the operator's own box shows an unbroken tenancy record stretching
back roughly eleven weeks before the campaign, which is easily enough time to have run that
reconnaissance quietly, on this same host, with nothing surviving to prove it either way. I do not
have a separate recon host to report. What I have is evidence that I never needed one to explain
what I saw.

### What the version band does and does not tell me

The target list spans Gotenberg 8.17.0 through 8.30.1. I want to correct a reading I initially
found tempting: the lower bound is not a deliberate choice. Exactly one target sits at 8.17.0, with
the population rising smoothly from there; a single host at the floor is the signature of "this is
simply the oldest version still running in the population that was scanned," not evidence the
operator tested compatibility down to that exact release. There is nothing here to read as
operator skill, and I am not reading it that way.

The upper bound is more interesting, and I am leaving it as an open question rather than forcing an
answer the evidence does not support. CVE-2026-40281's own advisory states that the key-sanitization
fix which closes *this* campaign's vulnerability landed in version 8.30.1, precisely the top of the
operator's target band, and the largest single-version bucket in it. Two readings are both
consistent with what survives: either the operator picked a band that stops exactly where the
public fix does, which would make the ceiling derivable from release notes rather than private
knowledge, or the fix did not fully close key injection and those top-band targets were
independently exploitable regardless of the operator's intent. The outcome data leans against
neither cleanly: a 96.6% confirmation rate is hard to square with 30 genuinely patched targets
failing to confirm, but the version strings themselves may be unreliable banner reads rather than
ground truth, so I am not treating that lean as an answer. The join that would resolve this, target
version against per-host verdict, cannot be run from what survives in this corpus, so I am reporting
it as **NOT CHECKED** rather than guessing in either direction.

---

## 5. The Payload: Cryptomining, Install Modes, and Rival Displacement
{: .hl-tier-1}

### The miner itself is not the interesting part, and that is itself a finding

The dropped payload is **stock, unmodified XMRig 6.26.0**, an 8.35 MB Alpine-compiled Linux ELF
binary. The pool address and payout wallet are not compiled in; they live entirely in the dropped
configuration file, which is why the binary is byte-identical across both drop locations while the
two configs differ. Both configs pay the same Monero wallet through the same public MoneroOcean
pool, and both carry the identical rig identifier `worker-01` on every single deployment, which is
a real operational weakness on the operator's own side: their pool dashboard cannot distinguish one
infected host from another.

**The binary hash attributes nothing, and I want to be direct about why that matters for how this
report's indicators should be used.** The exact sha256 has 133 submissions from 107 independent,
unrelated sources on VirusTotal, re-verified live at publication. XMRig is free, open-source
software, and running the stock binary unmodified commits the operator to no supplier relationship
and provides no distinguishing fingerprint. **The Monero wallet is the one genuinely
operator-specific pivot in this entire case**, and as of this investigation it is a controlled zero
everywhere I can search it: no VirusTotal object and no Hunt.io indexed post references it. It is
clean, not because nobody has looked, but because nobody else appears to be using it.

I initially read the reliance on a stock, freely available miner as evidence this operator "rents
rather than builds," implying a supplier relationship for the payload itself. I am withdrawing that
framing. XMRig is free software used by the large majority of Linux cryptojacking activity
industry-wide; running it unmodified is not a purchase, it is a default choice, and it sits oddly
against the withdrawal to also call it evidence of low investment. The more accurate reading is
that this operator takes a widely available commodity payload and
invests their engineering effort in the delivery pipeline around it, which the escalation ladder in
Section 4 already demonstrates in detail. A drop layer serving this exact payload also appears
shared across multiple unrelated cryptojacking operators pulling from the same installer family,
which is consistent with that reading: shared infrastructure, not a paid or exclusive one.

### Two install modes, and the one that gets missed matters more

<table>
<colgroup>
<col style="width: 20%;">
<col style="width: 24%;">
<col style="width: 28%;">
<col style="width: 28%;">
</colgroup>
<thead>
<tr><th>Mode</th><th>Path</th><th>Persistence</th><th>Config</th></tr>
</thead>
<tbody>
<tr><td>Ephemeral drop</td><td><code>/tmp/polkitd/</code></td><td>None; cleared by any reboot</td><td><code>donate-level: 1</code></td></tr>
<tr><td>Systemd install</td><td><code>/usr/bin/polkitd.d/</code></td><td>Root service, <code>Restart=always</code>, survives reboot</td><td><code>donate-level: 0</code></td></tr>
</tbody>
</table>

Both modes ship in the same recovered package. The ephemeral drop is the only mode the observed
campaign's own deployment script actually installs; I confirmed this by reconstructing the deploy
script from its own strings and grepping all recoverable triage output for any systemd-enabling
command, which returned zero hits against a working control. The systemd unit exists in the
tarball. Nothing observed installs it, and nothing rules it out on a per-host basis either, which
is why the honest statement is "148 to 151 confirmed ephemeral installs; whether any host also
received the persistent mode is not measurable from this corpus," not a claim that most hosts got
one mode or the other.

**This is the single most actionable finding in this report for anyone responding to this
campaign.** "Reboot and it is gone" is correct for the drop everyone will find first and wrong for
the one that matters. Any remediation has to check for both: kill the process running
`/tmp/polkitd/polkitd`, and separately check for a `systemd-polkitd` (or `systemd-vconsole-setup`)
unit and the `/usr/bin/polkitd.d/` directory. If the systemd variant is present, disabling and
removing the unit, deleting the directory, and reloading the systemd daemon are all required; a
reboot alone leaves a root-owned, self-restarting miner running. One recovered host also carried a
watchdog script that should be removed alongside either mode.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/gotenberg-rce-cryptomining-107-175-69-137/gotenberg-two-install-modes.png" | relative_url }}" alt="Side-by-side comparison of the two miner install modes: an ephemeral drop at /tmp/polkitd/ that does not survive a reboot and runs as whoever got remote code execution, against a persistent systemd unit at /usr/bin/polkitd.d/ that runs as root with Restart=always and does survive a reboot.">
  <figcaption><em>Figure 4: The two install modes side by side. A reboot clears the ephemeral drop but leaves the persistent, root-owned systemd install running, so "reboot and it's gone" is correct for one mode and dangerously wrong for the other.</em></figcaption>
</figure>

**Linux-only is not remarkable, and I want to say so directly rather than let a reader assume
otherwise.** The recovered package contains only ELF binaries, and XMRig itself ships Windows
builds, so shipping only the Linux payload is a choice rather than a limitation of the tool. It is
also fully explained by the target: Gotenberg ships as a containerized Linux service, and every
recovered victim callback shows a Linux container environment. The platform followed directly from
the choice of vulnerability, and there is nothing here to read as a second, unseen Windows
operation running in parallel.

### The operator displaces other criminals, deliberately

The deployment script's first action on any target is to kill a named list of competing miner
processes before installing its own. I found direct proof this fired for real: two recorded deploy
outputs show the operator's kill command successfully terminating a rival's process, meaning at
least one of these victims was already compromised by a different actor and this operator took the
machine over rather than sharing it.

The detail worth carrying forward is that the kill list includes `polkitd`, the exact process name
this operator's own miner masquerades as. They know their chosen mask collides with a common
rival's naming convention and kill it anyway without hesitation, which tells me this is not their
first encounter with that collision. It is also a direct warning for anyone responding to this
campaign: the mere presence of a process named `polkitd` is not by itself proof of *this*
operator's compromise, since it is both this operator's mask and a name their own tooling expects
to find and remove from someone else.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/gotenberg-rce-cryptomining-107-175-69-137/gotenberg-rival-miner-displacement.png" | relative_url }}" alt="Excerpt of the deploy script's kill list, showing a sequence of pkill commands targeting xmrig, systemd-devd, polkitd, kworker, khovr, kdevtmpfsi, kswapd0, libgcrypt and systemd-d before the script downloads and installs its own miner.">
  <figcaption><em>Figure 5: The rival-miner kill list run before this operator's own install. The list includes &quot;polkitd&quot;, the exact process name this operator's own miner masquerades as, so its presence on a host does not by itself distinguish this operator's compromise from a prior one it displaced.</em></figcaption>
</figure>

Separately, on the one host where the operator worked interactively, I found two other criminal
operations present simultaneously: a distinct miner paying three different wallets to a different
pool, and an unrelated multi-architecture dropper fetching payloads with no connection to this
operator's own infrastructure. At least three separate operations were active on that single
machine at once, which is a reasonable expectation for any internet-facing host that stayed
vulnerable long enough, and it means a victim notification for this campaign may legitimately need
to mention that more than one actor was present.

---

## 6. The Wider Enterprise: Data Theft, Account Farms, and AI Touchpoints
{: .hl-tier-2}

### This campaign is the smallest thing this operator does

I want to lead with the finding that reframes everything above it. Reading the operator's full
working directory rather than just the Gotenberg-specific files, the cryptomining campaign this
report is named for occupies roughly 3% of the recovered file inventory. The larger share belongs
to a shared mass web-application exploitation engine targeting other named commercial platforms,
and a separately branded, commercially structured account-management and OTP-resale product running on
Telegram. I am naming no platform, no domain, and no organization in this report. What follows
is shape and count, because that is what the evidence actually supports publishing, and because a
count is more honest than a name I cannot back with content-level proof.

<table>
<colgroup>
<col style="width: 30%;">
<col style="width: 14%;">
<col style="width: 56%;">
</colgroup>
<thead>
<tr><th>Line of business</th><th>Confidence</th><th>What the evidence actually shows</th></tr>
</thead>
<tbody>
<tr><td>Mass web-app exploitation (the shared engine)</td><td>HIGH that the tooling exists; INFERRED that it serves one purpose throughout</td><td>The largest single share of the recovered inventory, feeding both the data-theft and cryptomining lines</td></tr>
<tr><td>Cryptomining on compromised hosts</td><td>DEFINITE</td><td>The subject of this report, and the smallest, most fully automated line</td></tr>
<tr><td>Data-theft tooling against named commercial platforms</td><td>HIGH that platforms were targeted; INFERRED on what any dump actually contains</td><td>The dump content died with the host before anyone read it</td></tr>
<tr><td>Telegram account-management and OTP-resale product</td><td>HIGH on existence and commercial shape; MODERATE on actual scale</td><td>136 extracted routes describe a real inventory-management system; no pricing, buyer, or completed-sale record survives</td></tr>
<tr><td>Channel-push advertising and monetization</td><td>MODERATE-HIGH on capability; INFERRED on whether it was ever monetized</td><td>Real routes for paid channel promotion and username brokering exist in the same panel</td></tr>
<tr><td>Android device farms</td><td>Existence OBSERVED; function UNRESOLVED</td><td>Separate panel software with no API surface connecting it to the account-management product</td></tr>
</tbody>
</table>

**One operator, or one enterprise, is the better-supported reading, and I hold that at MODERATE,
not higher.** Section 9 carries the full reasoning; the short version is that the strongest
evidence is structural rather than stylistic: the cryptomining campaign's own working files sit
physically inside the same directory tree as the Telegram service and card-shop toolchains, which ties
them to one point of control regardless of who typed which script.

### The account farm is a commercial product, not a script someone left running

The clearest evidence of real investment in this case sits outside the cryptomining campaign
entirely. I extracted 136 distinct routes from the operator's own account-management panel
software, and they describe a managed inventory business rather than a dump-and-sell operation:
bulk session-file import, batch identity manipulation across accounts (avatar, profile, recovery
email, forced device removal), a commercial OTP inventory system with sold and out-of-stock states
and bulk export, and a separate monetization suite for paid channel promotion and username
brokering. A dump-and-sell model does not need lifecycle management this thorough; retaining and
operating inventory does.

**I am holding two claims about this product apart on purpose, because collapsing them would
overstate what I actually know.** The commercial-inventory shape of the API is directly observed
and I hold it at HIGH: the route names themselves describe exactly this kind of system. Whether the
underlying accounts are farmed from compromised sources or legitimately provisioned through bulk
SIM registration is a separate question that the intake tooling alone cannot answer, because legal
SMS-verification services run structurally identical sold and out-of-stock inventory models over
properly registered numbers. I found nothing in the recovered evidence that resolves this either
way, and I am stating that plainly rather than assuming the less charitable reading because it fits
the rest of the case.

A separate Android device-farm control panel exists in the same operator's directory, with its own
UI referencing device counts, online status, and accessibility permissions on managed devices. I
looked for a direct connection between this and the Telegram account farm, since the two would
naturally complement each other, and found none: no shared API endpoint, no shared data format,
nothing beyond both existing on the same box. I am reporting the device farm as a real, separate
capability whose actual purpose I cannot currently determine, rather than assuming it feeds the
account operation just because that would make a tidier story.

### The named platforms were targeted, not compromised

Reading the operator's own scraped material against a corrected standard matters here. Seven
externally identifiable commercial platforms turn up by name in the operator's scraped frontend
bundles, and I want to be precise about what that evidence actually proves: **zero of the seven
show any content-level access.** The only artifact recovered per platform is a copy of that
platform's own publicly served frontend code, which by definition anyone can fetch without
authenticating. Three of the seven additionally show sustained, iterated attack tooling built
specifically against them, and one of those three includes several megabytes of files named as
extraction outputs. None of that tooling's actual output survives; the files were catalogued by a
crawler and their content is gone.

The honest sentence for any of the seven, and the one this report actually supports, is that a
public frontend was found in the operator's own directory, and for three of them, that attack
tooling referencing the platform also existed. Neither is proof that any data was actually taken,
and I am not implying otherwise anywhere in this report. I also want to flag a correction that
narrowed rather than widened my own read: several of what I initially counted as separate victim
platforms turned out to be the same site, scraped multiple times under different internal labels,
based on matching file sizes and build signatures. I did not independently verify that with a
direct byte comparison, so I am holding it as an inference rather than a confirmed fact, but it
means the true count of distinct named platforms is smaller than the raw file count first
suggested, which is the opposite of the direction these corrections usually run.

### The AI angle, and why it points the opposite way from where the case started

This investigation originally opened on the premise that an AI agent framework drove the
exploitation. That premise is refuted, not merely unconfirmed, on three independent checks.
The file the claim rested on was never actually fetched or read by anyone at any point in this
investigation's own history; the specific popularity figure cited for the framework in question is
off by roughly a factor of ten against the framework's own real numbers; and a full keyword sweep
of every script that actually produced the 198 confirmed exploits found zero model API calls, zero
API keys, and zero prompt or chat artifacts of any kind. I am treating this as a genuine finding
rather than an embarrassment: two independent checks, one on code structure and one testing the
framework claim directly against a primary source, reached the same conclusion from different
evidence. This is ordinary, competently engineered scripted exploitation of one vulnerability, not
anything agent-orchestrated.

What I found instead is more interesting, and it points the opposite direction. The operator does
not appear to use AI tooling to attack; the operator **attacks** AI infrastructure. One victim's
own callback log shows a single probe attempt against two LLM gateway endpoints discovered on that
host, and the attempt failed outright, with every injected command line recording no execution.
Separately, one of the scraped storefronts in the operator's own directory sells shared logins for
a commercial AI-subscription service, which is a data-theft target, not the operator's own
infrastructure. A third, much thinner data point exists inside the operator's own Telegram
panel: two API wrapper functions for saving and testing an AI provider connection, which tells me a
bring-your-own-key AI integration exists in that panel's settings, and nothing more. None of these
three threads support any claim that this operator uses AI to build or run their own attacks, and I
am keeping all three separate rather than merging them into one storyline that overstates any of
them individually.

---

## 7. Infrastructure
{: .hl-tier-2}

No victim IP, victim ASN, or named victim organization appears anywhere in this section.
Provider concentration is reported as counts and percentages; the small number of confirmed hosts
with no usable abuse contact are described by shape, not by address, since that detail belongs in
an operational disclosure document rather than a public report.

### The operator's host, and a channel this case had been collapsing into one

The operator's own infrastructure sits at `107.175.69.137`, in AS36352, registered today as
AS-COLOCROSSING, under HostPapa. I re-verified the ASN and current owner live against VirusTotal at
publication and it matches exactly what passive registry data showed during the investigation.

I want to correct something in how I had been describing this host's provider. I had associated
the IP's retail brand with RackNerd, a separate company that leases capacity inside ColoCrossing's
data centers. It does not hold its own ASN, which is why a
RackNerd-sold instance shows ColoCrossing as the network owner in registry data. That distinction
matters operationally: ColoCrossing's own abuse desk carries a documented, multi-source pattern of
slow-to-unresponsive handling, while RackNerd's own separate abuse channel has a real,
publicly documented escalation process with actual instances of enforcement. These are two
different organizations with two different track records, reachable through two different
addresses, and I had been treating them as one. Whether this specific instance is RackNerd-sold
rather than sold by another reseller on the same ColoCrossing infrastructure is not something I
independently confirmed, so I am flagging the distinction rather than asserting the better channel
with certainty.

### What is actually running on the host, port by port

I tested this from two independent network paths that agree exactly on every result, including
matching HTTP response codes, which rules out path-specific filtering as an explanation for
anything below.

<table>
<colgroup>
<col style="width: 12%;">
<col style="width: 20%;">
<col style="width: 14%;">
<col style="width: 54%;">
</colgroup>
<thead>
<tr><th>Port</th><th>Service</th><th>State</th><th>Detail</th></tr>
</thead>
<tbody>
<tr><td>22</td><td>SSH</td><td>Open</td><td>Banner dates the box to an Ubuntu 24.04 build</td></tr>
<tr><td>80</td><td>HTTP</td><td>Closed</td><td>Refused on both paths</td></tr>
<tr><td>443</td><td>HTTPS</td><td>Open</td><td>Fails without the correct hostname in the TLS handshake; succeeds cleanly with it</td></tr>
<tr><td>2096</td><td>cPanel webmail</td><td>Open</td><td>Actively administered: carries its own auto-renewing, short-lived certificate</td></tr>
<tr><td>8080</td><td>Former open directory</td><td>Gone</td><td>Consistent with the last successful crawl of its content</td></tr>
<tr><td>8088 / 8443</td><td>Unlabeled</td><td>Open</td><td>Both fronted by the same reverse proxy as the rest of the live host</td></tr>
<tr><td>12577</td><td>Unlabeled</td><td>Gone now</td><td>Carried a spoofed-identity certificate for exactly five days starting the campaign date; see below</td></tr>
</tbody>
</table>

The server fronting every live port is Caddy, doing hostname-based routing with a working default
page. Every path I tried on the live ports returned an empty body, and nothing malicious,
victim-identifying, or otherwise content-bearing was recoverable from any of them. Whether real
content sits behind an unguessable path is a genuine open question I cannot close from here, not a
resolved negative.

Port 12577 is worth naming even though I cannot publish it as a distinguishing indicator. For
exactly the five days spanning the campaign, this port carried a certificate whose subject claimed
to be a well-known CDN provider but was issued by an unrelated certificate authority, a combination
that never happens legitimately and is consistent with a self-signed or spoofed-identity proxy
tool. Its cryptographic fingerprint, though, shares a component with a fingerprint this
publication has already separately identified as ubiquitous across millions of unrelated devices,
so I cannot use it to identify what tool actually ran there. I am recording it only as an
unattributed lead: some proxy or tunneling tool ran on this box for exactly the campaign's active
window and was torn down afterward.

### The host was declared dark, and that was wrong in an instructive way

An earlier check in this investigation concluded the operator's host had gone fully dark, all six
ports it tested closed or filtered, with a working control confirming the test path itself was
functional. That conclusion does not hold up, and I want to walk through why, because the failure
mode is more valuable than the correction itself.

The evidence that the host is actually live and administered is a set of captured application-layer
banners, an SSH version string, an HTTP error response, all genuine service replies, not bare
timestamps claiming a port was "last seen" at some point. A scanner cannot fabricate a banner. The
tool that originally reported the host dark carries two separate fields both labeled something like
"last seen," one built from real captured service responses and one from scan-attempt telemetry
alone, and on this exact host and port those two fields disagreed by two and a half hours. The
earlier dark-check's own control was real, and it still produced the wrong conclusion, because it
tested reachability to a hyperscale, universally-peered target rather than to a target that shares
the operator's own hosting class: a cheap, single-tenant VPS on a provider with every incentive to
treat automated crawler traffic differently from ordinary internet traffic. A control has to vary
the same property the measurement actually depends on. Proving a path reaches the easiest possible
target on the internet proves nothing about whether it reaches the hardest one, and that is the
generalizable lesson I am carrying out of this specific mistake.

The corrected statement, and the one that should be used anywhere this campaign's collection status
comes up: the operator's exposed directories and campaign-specific listeners went offline sometime
between the end of the campaign and roughly a week later. The underlying machine did not, and it
remains live and actively administered as of this report.

### Tenancy history, and what it does and does not tell me

Passive host-key history shows four distinct tenancy periods on this IP going back to late 2024,
with the current tenant holding it continuously since roughly two and a half months before the
campaign, unbroken through today. That timeline is what let me retire my own recon-host hypothesis
in Section 4: eleven weeks is easily enough time to have quietly run the reconnaissance this
campaign clearly required, on this same box, with nothing surviving to prove it happened here
specifically.

**I want to name a limitation in this finding rather than let the tenancy argument read as more
solid than it is.** The continuity claim rests on a third party's own internal tracking of the
host's cryptographic key identity, and I could not independently reproduce it. I captured the live
host's actual key fingerprints myself and they do not match the tracking service's own opaque
identifier for the current era, which is not itself troubling, since that identifier does not
appear to be a standard fingerprint format to begin with, but it does mean this case is trusting a
third party's internal bookkeeping for a fact that several other findings, including the next one,
lean on.

### A co-located domain, and a grade I am actively pulling back rather than defending

A hostname resolving exclusively to this IP surfaced during the investigation, styled like a
payment or identity-verification page, with a currently valid certificate and an empty default
response on every path tried. An earlier pass in this investigation graded this domain's connection
to the operator at HIGH confidence, reasoning that the domain's presence sat inside an otherwise
unbroken tenancy window. **I am overturning that grade to NOT CHECKED, and I want to walk through
all four reasons rather than assert the downgrade, because each one independently would have been
enough on its own.**

First, the domain's own DNS record first appeared two days after the campaign ended, not during it
and not before it. What spans the campaign continuously is the host's tenancy, not this specific
domain, and I had let those two separate facts blur into one sentence in earlier drafts of this
finding. A domain created two days after a campaign ends, on a box whose tenant did not change, is
evidence about who held the box at two points in time. It is not, by itself, evidence that the same
person created the campaign and chose this domain name.

Second, the underlying evidence framework this case applies grades a shared hosting artifact by how
common the naming pattern is among unrelated users of the same free dynamic-DNS service, and I
never actually measured that narrower rate. An unmeasured denominator produces a NOT CHECKED
grade under this framework's own rule, not a default HIGH.

Third, the HIGH grade as originally written was already conditional on the same tenancy-continuity
claim the prior section just flagged as independently unverified. A conditional grade resting on an
unclosed condition was never a settled HIGH to begin with.

Fourth, and this is the mechanism I had not considered when the grade was first assigned: the
software serving this domain, Caddy, has a feature that will automatically issue a valid
certificate for any hostname pointed at it, with zero configuration from whoever runs the box. If
that feature is active here, and I could not test it without sending an unauthorized request to a
live host, a valid certificate for this domain would prove only that someone, anyone, pointed DNS
at this IP. It would not prove the box's own controller chose or even knows this name exists.

I found one additional related domain during this same pass, sitting behind a different provider's
proxy rather than resolving to this IP directly, managed inside the same DNS account as the first.
That does suggest one deliberately operated cluster of names rather than an accidental default page
someone stumbled onto, which raises my confidence that whoever runs this DNS zone is doing so on
purpose. It does not raise my confidence that this zone's owner is the Gotenberg operator
specifically, because the entire link back to this operator still runs through the same unverified
tenancy claim, and the second domain never touches this operator's IP, ASN, or anything else in the
recovered corpus at all.

### Where the 196 confirmed victim hosts are hosted, by provider only

Hosting for the 196 distinct confirmed IPs resolves into 64 provider groups. Forty-seven of those
groups are single-IP; the remaining seventeen account for the other 149 addresses. The top 25
provider groups alone cover 80.1% of every confirmed IP, and the concentration sharpens fast at the
top. The five largest providers together account for 51.5% of the confirmed population, and the
ten largest account for 65.8%. That concentration is the practical reason a disclosure
program built on this campaign needs only a small number of provider-level reports rather than 196
individual ones.

A small number of confirmed hosts, fewer than five, carry no usable abuse-role contact anywhere in
public registry data at all. They sit on a major cloud provider and a national telecom's network in
two different countries, and both require a direct CERT-style routing path rather than a standard
provider abuse address; I am describing them by shape only, since the addresses themselves belong
in an operational routing document, not this report. Every mainstream provider I reviewed among the
larger groups is a well-documented, responsive company with no history in bulletproof-hosting
literature, so nothing in this concentration argues against a routine disclosure to any of them; the
smaller single-IP tail was not individually reviewed and I am not implying it is clear by omission.

### What the shared miner infrastructure does and does not establish

The stock miner's own relationship graph on VirusTotal connects to a set of other files and domains
through a shared mining pool and a shared cryptojacking installer family. I want to be precise about
what that connection is worth. Contact with the public mining pool alone is evidence of using the
same commercial service every other unrelated cryptojacking operation on that pool also uses; it is
not evidence of a relationship to this specific operator, and I confirmed that by finding four
entirely unrelated, independently published campaigns dating back to 2024 that use the identical
pool endpoints with zero connection to this case. A shared installer family that serves the same
miner binary to two other domains also shows multiple independent submitters over time, and one of
the domains in that same cluster serves a completely unrelated scanning tool to what appears to be a
different customer entirely. My reading is that this is a shared drop layer serving several
unrelated cryptojacking operators, not infrastructure this specific operator built or exclusively
controls, and I am not treating the shared file match as a link to any of them.

### The negative results, stated with their controls

The Monero payout wallet returns zero results everywhere I searched it, across two independent
enrichment sources, and I validated both search tools against a known-positive query in the same
session before trusting either negative. This remains the cleanest operator-specific pivot in the
entire case; it has simply not surfaced anywhere else that is indexed yet. I did not re-run the
mining pool endpoints as bare searches beyond what already established their broad, unrelated
ubiquity, since doing so would only refine how common they are, not change whether they constitute a
link.

### Live re-verification at publication

<table>
<colgroup>
<col style="width: 34%;">
<col style="width: 33%;">
<col style="width: 33%;">
</colgroup>
<thead>
<tr><th>Claim</th><th>Live query result</th><th>Outcome</th></tr>
</thead>
<tbody>
<tr><td>Operator IP's ASN and current owner</td><td>AS36352, HostPapa, unchanged</td><td>Match</td></tr>
<tr><td>Co-located domain still resolves to the operator's host</td><td>Same single A record, no reputation signal either way</td><td>Match</td></tr>
</tbody>
</table>

I did not re-check whether the host still answers on the same live ports as of publication, since
doing so would mean sending a fresh probe to a live third party's infrastructure with no active
collection purpose remaining, and the two-path, twice-controlled results in this section already
rest on direct, dated observation rather than on a third party's report.

---

## 8. MITRE ATT&CK Mapping
{: .hl-tier-2}

> All rows below are HIGH confidence or better unless explicitly marked `(MODERATE)`. The
> Confidence Summary near the end of this report organizes findings by confidence level for the
> higher-level view.

| Tactic / Technique | Name | Evidence |
|---|---|---|
| Reconnaissance / T1595.002 | Vulnerability Scanning | 206 candidates fingerprinted for Gotenberg version band before any exploit ran |
| Initial Access / T1190 | Exploit Public-Facing Application | CVE-2026-42589 metadata-key injection, 198/205 confirmed |
| Execution / T1059.004 | Unix Shell | `system('sleep N')\|\|1` and payload commands run via ExifTool `-if` Perl `eval` |
| Discovery / T1082 | System Information Discovery | Pre-deploy check of `/tmp` free space and writability (`touch /tmp/.wt`) |
| Discovery / T1057 | Process Discovery | Recon greps for rival miner processes before spending a deploy |
| Defense Evasion / T1036.004 | Masquerade Task or Service | Miner process and systemd unit both named `polkitd`; a second VT-recorded alias uses `systemd-logind` (MODERATE) |
| Persistence / T1543.002 | Systemd Service | Root `systemd-polkitd.service`, `Restart=always`, shipped in the package; per-host deployment is NOT CHECKED (MODERATE) |
| Command and Control / T1071.001 | Web Protocols | Out-of-band callback listener, HTTP GET tagged with victim hostname and UID |
| Command and Control / T1105 | Ingress Tool Transfer | Deploy script base64-encodes and transfers the miner package to each confirmed host |
| Impact / T1496 | Resource Hijacking | XMRig cryptomining verified installed on 148 to 151 confirmed hosts |

---

## 9. Threat Actor Assessment
{: .hl-tier-2}

### No named actor, and that is the honest answer

Nothing in this investigation reaches even MODERATE confidence on a named threat actor, a known
group, a handle, or an overlap with a previously tracked operation. I am reporting this as an
**unknown operator**, and the rest of this section is about the shape of that operator rather than
their identity.

This is the first work I have published on this operator, and I checked rather than assumed it. My
own prior cases were searched for this host, its network, the co-located domain and the miner
family before any of this went out; two cases surfaced, and both matched only on the fact that
their operators are also unnamed, which is not a connection at all. So nothing here revises or
contradicts anything I have published before, and a reader should not go looking for an earlier
piece that this one supersedes.

### The falsified premise, and why I am treating the falsification itself as a finding

This case opened on the hypothesis that an autonomous AI-agent framework drove the exploitation.
Section 6 already covers why that premise does not survive, on three independent measurements
against primary sources rather than on impression. I am restating the conclusion here because it
governs how the rest of this assessment should be read: this is ordinary, competently engineered,
scripted mass exploitation of one disclosed vulnerability. The correction of the case's own
starting premise is, in my judgment, the most defensible single claim in this entire assessment,
precisely because it required admitting the original framing was wrong rather than quietly
narrowing it.

### One operator, at MODERATE, not higher

I hold "one operator" at MODERATE confidence, a deliberate demotion from an earlier, stronger read
in this same investigation. That demotion rests on catching an inconsistency in my own evidentiary
standard, not on new evidence pointing the other way, and I want to walk through why rather than
just state the new number.

The strongest style-based argument for a single author was a shared helper function that drifted
inconsistently across every Gotenberg-specific script, which reads as one person iterating solo
rather than a team coordinating changes. That reading is plausible, but the underlying pattern,
regenerate-with-drift bookkeeping, is also simply the most common shape any re-runnable batch job
takes regardless of who is writing it, and I never measured how distinctive that specific pattern
actually is against other operators' tooling. This case holds other unmeasured patterns to a
stricter standard elsewhere; letting this one carry a higher verdict without the same rigor was the
same failure in the opposite direction, and that inconsistency, not new contrary evidence, is the
actual reason for the demotion.

Two supporting observations from language analysis, that the Chinese and English toolsets read at
matching levels of formality and that the operator code-switches naturally between them, are
equally consistent with one bilingual person and with two closely collaborating, comparably fluent
operators splitting the work by language. Neither observation can discriminate between those two
possibilities, and I should not have let it carry the weight it originally did.

**What actually holds the verdict is structural rather than stylistic, and it is the one piece of
evidence in this section that does not depend on a judgment call about writing style.** The
Gotenberg campaign's own target list, state file, and deployment results sit physically inside the
same directory tree as the Telegram service and card-shop toolchains covered in Section 6. That
co-location ties every toolchain in this investigation to one point of control, regardless of
whose hands actually typed each one. It is enough, on its own, to hold "one controlling entity" at
MODERATE. It is not enough to hold it any higher.

### One clean, unmoved finding: neither language shows LLM authorship or non-native strain

This answers a specific question I set out to test directly, and I hold the answer at HIGH,
measured over a meaningful sample rather than a couple of lines: does either the Chinese or English
tooling read as more formal, more textbook, or less naturally fluent than the other, in a way that
would suggest LLM generation or a non-native writer? It does not.

The English scripts are uniformly terse and casually slang-inflected, with the kind of mid-thought,
self-questioning code comments a formal or generated writer would be unlikely to produce. The
Chinese material, checked with a round-trip encoding verification to rule out corruption, shows the
identical profile: colloquial gray-market slang, a contracted spoken-register phrasing rather than
the formal written equivalent, and native-typist punctuation inconsistencies. Neither language is
more polished than the other. Both read as native, casual, first-draft developer prose, and that
symmetry is itself the answer. This is the one finding in this assessment I would call least likely
to move with more evidence.

### Capability: two axes, never averaged into one adjective

An earlier pass on this case collapsed these into "medium sophistication." That collapse is wrong,
and I am keeping the two axes separate here on purpose, because they point in genuinely different
directions and averaging them would misrepresent both.

On vulnerability research I hold this operator at **LOW**, at or below the public floor, at
HIGH-to-DEFINITE confidence. Section 3 already walks through the direct comparison: the injection shape, the truthiness suffix,
the trailing dummy key, and the vendor advisory's own placeholder value all match verbatim, and the
timing-confirmation method is separately traceable to a public proof-of-concept published three
months before the campaign. This operator did not discover anything. I hold this just short of flat
DEFINITE only because a single comparison point cannot formally exclude every implausible
coincidence.

On operational engineering I hold this operator at **MODERATE-HIGH**, on what actually survives
scrutiny, which is three elements rather than the four I originally credited as evidence this
operator's real skill sits in campaign engineering rather than exploit research: the writability
probe, a relative rather than fixed timing threshold, a three-transport retry ladder, and
per-host callback tagging built from shell command substitution. A dedicated search of
Chinese-language security material, run with working controls proving the search itself could
surface real content, removed one of the four: per-host callback tagging this way is foundational,
widely taught technique in that literature, not an operator contribution. The other three survive
against that same working search, in either language, which is real evidence of absence rather than
an unchecked gap. Three of four elements standing against a search that demonstrably works is what
keeps this axis at MODERATE-HIGH rather than collapsing it to "they used someone else's tooling
end to end," which would be overclaiming in the opposite direction from the one this correction
exists to fix.

The honest, non-averaged statement is this: this operator did not need to be, and was not, a
vulnerability researcher for this campaign. They read a disclosed advisory closely, picked up a
publicly documented confirmation technique and a foundational tagging convention, and built a
reliable, proxied, 198-host automated pipeline around all three, with genuine engineering on the
parts that stayed undocumented anywhere I could search. That is a real, narrower capability than
"they wrote this exploit," and it is the capability I documented here.

### The one alternative I could rule out, and the ones I could not

**Authorized security testing does not survive, and I am excluding it rather than merely leaving
it unsupported.** Nothing in the readable corpus shows client-facing reporting, scoped-engagement
artifacts, or any authorization trail, and what the deployment scripts actually do is install a
cryptominer paying the operator's own wallet while killing a named list of competing miners
already running on the box. An authorized tester does not compete with other criminals for a
client's compute and walk away with the mining proceeds.

Three alternatives I could not kill, and I am naming them rather than smoothing past them:

- One operator versus two closely collaborating operators with indistinguishable habits.
  Register and habit analysis cannot resolve this from text alone; the structural directory tie
  survives this alternative, but it proves common control, not a single pair of hands, and I am
  not claiming it does.
- **The shared helper function's drift as solo hand-editing versus one person repeatedly
  prompting an LLM to regenerate the same file.** Both produce a nearly identical drift signature.
  This does not revive the falsified agent-framework premise, which was specifically about whether
  an autonomous agent orchestrated the exploitation itself, but it does mean I cannot rule out
  LLM-assisted authorship of individual files, and I am not claiming to.
- **The device-farm and Telegram account-management business as the same operational pipeline as this campaign,
  versus two business lines sharing a host only incidentally.** The device-farm panel's own API
  surface has no endpoint connecting it to the Telegram service's OTP or SIM data anywhere I could
  find. The link that exists is conceptual and structural, not a direct code path, and I am not
  asserting these are one pipeline.

### What would change each of these judgments

<table>
<colgroup>
<col style="width: 26%;">
<col style="width: 16%;">
<col style="width: 58%;">
</colgroup>
<thead>
<tr><th>Finding</th><th>Confidence</th><th>What would change it</th></tr>
</thead>
<tbody>
<tr><td>One operator (one controlling entity)</td><td>MODERATE</td><td>A second structural tie, such as a shared credential or a second campaign reusing this exact directory layout, would raise it. Content from any unrecovered file showing two distinct authorship voices would lower it.</td></tr>
<tr><td>Neither language shows LLM or non-native authorship</td><td>HIGH</td><td>Nothing currently visible would move this; I named the predicted signature in advance and found none of it. A much larger sample of the operator's own prose in either language, showing a different register, is the one thing that could.</td></tr>
<tr><td>Vulnerability research is copied, not discovered</td><td>HIGH-to-DEFINITE</td><td>A second, independent public source confirming the same copy would move this to flat DEFINITE.</td></tr>
<tr><td>Operational engineering exceeds the public baseline</td><td>MODERATE-HIGH</td><td>Recovery of the operator's own reconnaissance notes, or a private or paywalled writeup covering the writability check or the retry ladder, would lower this toward the copied-technique reading already applied to callback tagging.</td></tr>
<tr><td>Authorized testing is excluded</td><td>DEFINITE</td><td>Nothing I can foresee would revive it; a wallet-funded miner deployment with a rival-miner kill list is not consistent with any authorized-testing framing I can construct.</td></tr>
</tbody>
</table>

### Why I am not designating a new tracking identifier for this operator

This case's own designation gates, at least three distinctive characteristics with at least two
technical or infrastructure-based, and supporting evidence strong enough to trust, pass on a
literal count: the callback-tagging choice, the writability probe, the retry ladder, and the
structural co-location of three separate toolchains inside one directory all qualify, and the
supporting evidence is our own direct reading of the operator's recovered material rather than
secondhand reporting.

**I am recommending against creating one anyway, for three reasons that outweigh a literal pass on
the gates.** First, three of the four candidate characteristics are absence-of-evidence findings,
real evidence of no public match today, but a weaker foundation for a designation meant to let a
future, different campaign be recognized as the same actor than a positive, unique signature would
be. Second, the confidence underlying "one operator," the premise a tracking designation exists to
follow, sits at MODERATE here for reasons of evidentiary rigor rather than new contrary evidence,
and building a designation on top of a MODERATE cluster-consistency judgment invites exactly the
kind of drift this publication's own retirement discipline exists to catch. Third, the strongest
genuinely distinctive fact in this case, three business lines sharing one directory footprint, is a
fact about this specific, now-dark box. It would not by itself let a future campaign on different
infrastructure be recognized as the same operator without another full capture, and a tracking
designation that cannot travel is not doing the job a designation is for.

---

## 10. Indicators of Compromise
{: .hl-tier-2}

Full detail lives in the machine-readable feed referenced below; this section highlights what
actually distinguishes this operator from the surrounding commodity noise.

### The one genuinely operator-specific indicator

| Type | Value | Confidence | Note |
|---|---|---|---|
| Monero address | `456UWvWXto1PacXMu689Mghh2QWQg2amvapezv3HWucT2KiKz86VQYJZ9cHGha6NbuTyqrrRDrJKSPB2eS7BNwkhSuw5QQU` | DEFINITE | Identical across both dropped configs. Returns a controlled zero everywhere searchable as of this report. This, not the miner hash, is the pivot worth tracking. |

### Network indicators

| Type | Value | Confidence | Note |
|---|---|---|---|
| IPv4 | `107.175.69.137` | DEFINITE | The operator's own host. Served the exposed directory, the campaign toolkit, the OOB listener, and an unauthenticated reverse-shell collector. |
| Port | `18888` | DEFINITE | Out-of-band callback listener; victim callbacks tagged with hostname and UID |
| Port | `19999` | DEFINITE | Campaign toolkit and miner payload staging |
| Port | `13337` | DEFINITE | Unauthenticated reverse-shell collector, internet-reachable throughout |
| HTTP request | `POST /forms/pdfengines/metadata/write` with a JSON metadata key carrying the wire-escaped sequence `\n-if\nsystem(` | DEFINITE | The exploitation signature, measured against captured traffic; see Section 3 |

### Host indicators

| Type | Value | Confidence | Note |
|---|---|---|---|
| Path | `/tmp/polkitd/` | DEFINITE | Ephemeral drop, cleared by reboot |
| Path | `/usr/bin/polkitd.d/` | DEFINITE | Persistent install directory; survives reboot |
| Systemd unit | `systemd-polkitd.service` | DEFINITE | Root, `Restart=always`; the reason "reboot and it is gone" is wrong advice for this mode |
| Process name | `polkitd` | DEFINITE | The miner's masquerade name. Also appears on the operator's own rival-miner kill list, so its presence alone does not confirm this operator specifically |
| Process name | `systemd-logind` | INSUFFICIENT | A second VirusTotal-recorded alias for the same binary hash, with zero ties to this host, wallet, or corpus. Watchlist only |
| XMRig rig ID | `worker-01` | DEFINITE | Identical on every deployment; low fidelity alone |

### Commodity, explicitly non-attributing

| Type | Value | Note |
|---|---|---|
| SHA256 | `b20f39fc00d242e706b6c30367ad811c676e0575050a4ec2f30104b696944b49` | Stock, unmodified XMRig 6.26.0. 133 VirusTotal submissions from 107 unrelated sources, re-verified at publication. Do not use this hash to tie a host or campaign to this operator. |
| Mining pools | `gulf.moneroocean.stream:10032`, `ca.moneroocean.stream:10032` | Public, shared infrastructure used by unrelated operators. Hunt for it; never blocklist it as this operator's own infrastructure. |

### Full Feed Location

Complete machine-readable indicators, including the hunt-only shared infrastructure and every
excluded victim address, are maintained separately:
`ioc-feeds/gotenberg-rce-cryptomining-107-175-69-137-iocs.json`. No indicators are embedded
directly in this report body beyond the highlights above; the JSON feed is canonical, and it
excludes every victim address by design.

---

## 11. Detection and Response Guidance
{: .hl-tier-2}

### Network-based detection

The only reliable signature keys on the wire-escaped injection bytes, not on a raw newline. Full
Suricata and Sigma rules are in the companion detection file, and both carry the same load-bearing
warning this report does: the hex byte sequence in the rule is the intentional JSON-escaped form of
`\n-if\nsystem(`, and correcting it to a literal newline produces a rule that parses cleanly and
never fires. Where request-body visibility is unavailable, a secondary hunting rule watches for
latency spikes on Gotenberg's metadata-write endpoint against its own established baseline, at the
cost of a high false-positive rate against genuinely slow or malformed documents.

The Suricata rule loads and parses cleanly, but replay against this campaign's captured traffic is
NOT CHECKED. The companion detection file's Coverage Gaps section records that limit.

### Host-based detection

Check for both install modes independently, since only one leaves an obvious trace after a reboot.
Look for a process or systemd unit named `polkitd`, keeping in mind this operator's own tooling
also kills a rival using that same name, and separately for the `systemd-polkitd.service` unit and
the `/usr/bin/polkitd.d/` directory specifically. A single confirmed `MINER_OK`-style ephemeral
drop does not rule out the persistent mode also being present on the same host, since nothing in
the observed campaign's own telemetry can distinguish the two per host.

### Threat hunting approaches

#### Hunt 1: Confirm scope of the persistent install

Join any evidence of the ephemeral drop against a live check for the `systemd-polkitd.service`
unit and `/usr/bin/polkitd.d/`, since the campaign's own telemetry cannot answer this and every
confirmed host should be checked directly.

#### Hunt 2: Identify the confirmation timing pattern historically

Filter historical access logs for the metadata-write endpoint for requests whose response time
sits at or above 70% of a suspiciously round sleep duration, against an established clean baseline
for that endpoint.

#### Hunt 3: Check for co-tenant compromise

Where this campaign's miner is found, check for evidence of other, unrelated cryptomining or
dropper activity on the same host. This operator's own kill-list behavior and the interactive
session recovered in this investigation both show other criminal activity coexisting on the same
compromised machines.

### Response action categories

*(Counts against the shared 30-line response cap with Section 12's Immediate Actions.)*

As a third-party intelligence provider, I am naming action categories here, not procedures
specific to any organization's tooling, and I am ordering them by what this specific threat
actually requires rather than by a generic incident-response template.

The fact that matters most is the one from Section 5: this operator ships two install modes, and
only one of them clears on a reboot. Checking for the ephemeral `/tmp/polkitd/` drop and declaring
a host clean misses the persistent, root-owned systemd service entirely, so both modes have to be
checked on every affected host before anything is called resolved. Past that, patch Gotenberg
beyond the top of the version band this campaign actually confirmed against, and treat the
Gotenberg service account's own credentials and any secrets co-located with it as exposed rather
than merely at risk, since the operator had unauthenticated code execution as that account.

---

## 12. Recommendations
{: .hl-tier-1}

### Immediate actions

*(Counts against the same 30-line cap as Section 11's Response Action Categories.)*

If infection is confirmed, isolate the host, patch or take the Gotenberg instance offline until
patched, and check for the persistent systemd install specifically rather than assuming a reboot
resolved it. If infection is only suspected, deploy the provided detection rules and review
historical logs for the latency pattern in Section 11's second hunt.

### Short-term detection improvements

- Deploy the wire-escaped Suricata and Sigma rules from the companion detection file, with their
  load-bearing comments intact
- Enable request-body logging on any reverse proxy or WAF in front of a Gotenberg deployment,
  since Gotenberg's own application log cannot see this injection at all
- Alert on the specific latency signature in Section 11 only where body-level visibility is
  genuinely unavailable, given its high false-positive rate

### Prevention control categories

- Patch Gotenberg past the version that closes CVE-2026-42589, and separately confirm the fix
  actually blocks metadata-key injection rather than trusting the version number alone
- Do not expose a document-conversion service's metadata-write endpoint directly to the internet
  where a reverse proxy with body inspection can sit in front of it instead
- Apply outbound network controls that would catch an unexpected out-of-band callback from a
  document-processing service, which has no legitimate reason to make arbitrary outbound
  connections

### Long-term strategic changes

- Treat any internet-facing document, image, or media-processing service as a high-value target
  for this same injection-and-timing-confirmation pattern, since the technique itself is generic
  and not specific to Gotenberg
- Build detection validation into any workflow that derives a signature from source code alone;
  this report's own central finding is that such a signature failed silently until it was tested
  against real captured traffic

### Control effectiveness against this threat

| Control category | Effectiveness | Priority |
|---|---|---|
| Reverse proxy or WAF with request-body inspection | HIGH | CRITICAL |
| Timely patching of internet-facing document-processing services | HIGH | CRITICAL |
| Outbound network egress controls | HIGH | HIGH |
| Host-based detection for both miner install modes | HIGH | HIGH |
| Reliance on Gotenberg's own application log alone | LOW (cannot see this injection) | n/a |

---

## 13. Confidence Summary and Evidence Gaps
{: .hl-tier-2}

<table>
<colgroup>
<col style="width: 52%;">
<col style="width: 16%;">
<col style="width: 32%;">
</colgroup>
<thead>
<tr><th>Finding</th><th>Confidence</th><th>What would change it</th></tr>
</thead>
<tbody>
<tr><td>The exploitation mechanism, the CVE identity, and the wire-escaping detection failure</td><td>DEFINITE</td><td>A Gotenberg deployment that un-escapes before the sensor boundary; none is possible given the documented endpoint contract</td></tr>
<tr><td>The miner is stock XMRig; its hash attributes nothing; the wallet is operator-specific</td><td>DEFINITE</td><td>The wallet surfacing in an unrelated corpus, which would make it shared rather than unique</td></tr>
<tr><td>The AI-agent-driven premise the case opened on is refuted</td><td>DEFINITE</td><td>Recovery of the one unfetched file the original claim rested on, if it contained agent configuration; its bytes did not survive</td></tr>
<tr><td>The host's attack surface is gone but the machine is live and administered</td><td>DEFINITE</td><td>The captured banners ceasing across independent paths, tested with a control matched to the host's own hosting class</td></tr>
<tr><td>198 of 205 probed targets confirmed exploitable inside 54 minutes</td><td>DEFINITE</td><td>A surviving copy of the target list showing a materially different probe-to-confirm split</td></tr>
<tr><td>The corpus coverage gap is a collection failure, not a triage failure</td><td>DEFINITE</td><td>Enumeration of one unopened archive that could move up to three files into the held-but-untriaged bucket</td></tr>
<tr><td>184 confirmed hosts called back, split 167 observed and 17 inferred; 14 never did</td><td>HIGH</td><td>A fresh derivation from the raw callback log printing every host and donor explicitly</td></tr>
<tr><td>The seven named platforms were targeted, not compromised; zero show content-level access</td><td>HIGH</td><td>Recovery of any captured content from those platforms' own systems, which does not currently exist anywhere reachable</td></tr>
<tr><td>Vulnerability-research capability is copied from the public advisory, at or below the public floor</td><td>HIGH-to-DEFINITE</td><td>A second independent public source further confirming the copy would move this to flat DEFINITE</td></tr>
<tr><td>Neither the Chinese nor English tooling shows LLM authorship or non-native strain</td><td>HIGH</td><td>Nothing currently visible; a much larger sample showing a different register in either language</td></tr>
<tr><td>Victim scope for the credential-harvesting surface is permanently unknowable from this corpus</td><td>HIGH as a negative</td><td>A snapshot not currently mounted holding the missing bytes; verified absent three ways with a working control</td></tr>
<tr><td>148 to 151 confirmed miner installs, 28 permanently unattributable</td><td>MODERATE</td><td>Recovery of the main deploy wave's own target-list ordering, which would resolve the index-to-host mapping</td></tr>
<tr><td>Operational engineering exceeds the documented public baseline, on three of four originally claimed elements</td><td>MODERATE</td><td>Any of the three surviving elements appearing in published tooling in a language the searches did not reach</td></tr>
<tr><td>One operator (one controlling entity) rather than several</td><td>MODERATE</td><td>A measured denominator showing the shared bookkeeping habit is genuinely distinctive, or any artifact placing two hands on one toolchain</td></tr>
<tr><td>This is one multi-line criminal enterprise rather than several unrelated operations sharing a host</td><td>MODERATE</td><td>Evidence of data, credential, or customer flow between the lines, which no lane observed either way</td></tr>
<tr><td>The two install modes exist; which hosts received which is not measurable</td><td>HIGH on existence, NOT CHECKED on the split</td><td>A per-host record carrying an install-mode field, or a callback body distinguishing the two</td></tr>
<tr><td>The co-located domain is meaningful operator linkage</td><td>INSUFFICIENT / NOT CHECKED</td><td>A measured base rate for the naming pattern, or independent verification of the underlying tenancy claim; either alone would move it off NOT CHECKED</td></tr>
<tr><td>Attribution to any named actor</td><td>INSUFFICIENT</td><td>Any infrastructure, code, or TTP overlap with a previously tracked actor; none currently exists</td></tr>
</tbody>
</table>

### The two gaps that matter most, in plain terms

The gap between "148 to 151 confirmed installs" and "198 confirmed exploited" is the single most
important number in this report to hold apart correctly. Every one of the 198 got code execution.
Fewer than that have a verified miner running, because the operator's own callback infrastructure
lost data under load and the main deployment's target ordering was never preserved. That is a
genuine evidentiary limit, not a rounding choice, and I would rather publish an honest range with
its derivation than a single confident number I cannot actually defend.

The second gap is the co-located domain. I want to be direct that pulling a HIGH grade back to NOT
CHECKED, on a finding I originally found persuasive, is the correct outcome of applying this
publication's own evidence framework consistently, not a hedge. Where a judgment rests on
withdrawing a claim rather than merely declining to make one, that is often the stronger, more
defensible position, even though it reads as less satisfying than a confident answer would.

### What is missing

- Whether the persistent systemd install mode reached any of the confirmed hosts. The
  observed campaign's own deployment script only ever installs the ephemeral mode; a per-host
  telemetry record carrying an install-mode field would close this, and none currently exists.
- What the Android device-farm capability actually connects to. Its existence is confirmed;
  its function, and whether it feeds the Telegram account farm at all, is not, and closing it
  would need backend content this investigation never recovered.
- The exact scope of the credential-harvesting surface. Two live private keys are confirmed;
  the files that would establish how far that surface actually reaches were fetched once, hashed,
  and never retained, and are permanently unrecoverable.
- **Whether the top of the operator's target version band reflects deliberate targeting or an
  incomplete patch.** The join that would settle this cannot be run from what survives in this
  corpus; it is reported as an open, NOT CHECKED question rather than resolved in either
  direction.
- The cryptographic verification of the host's tenancy continuity, which several findings in
  Section 7 lean on and which rests on a third party's internal tracking that I could not
  independently reproduce against the live host's own key fingerprints.

### The source base, in short

Most of what this report rests on comes from artifacts recovered directly off the operator's own
infrastructure: their own scripts, their own configuration files, and their own logs, which is the
strongest source base available for a case like this. The exploit-provenance and prior-art claims
in Sections 3 and 9 are the exception, resting on primary vendor advisories and public repository
metadata I fetched and read directly rather than took on faith. Where the infrastructure section's
tenancy-continuity claim and a third party's passive enrichment data disagreed with what I could
verify myself, I have said so explicitly rather than picked the more convenient reading, and the
domain co-location grade in Section 7 is the direct consequence of following that disagreement
through rather than around it.

---

## 14. References
{: .hl-tier-3}

### Primary sources

- GitHub Security Advisory GHSA-rqgh-gxv4-6657, CVE-2026-42589, fetched and retained directly
- GitHub Security Advisory GHSA-q7r4-hc83-hf2q, CVE-2026-40281, fetched and retained directly, to
  confirm the two vulnerabilities are distinct
- A public proof-of-concept repository's own Nuclei detection template, dated via its own
  repository metadata

### Threat intelligence sources on account and device farms

- Group-IB, *Cloud Phones: The Invisible Threat*
- Group-IB, *Anatomy of a Fraud Operation*
- Europol, *Internet Organised Crime Threat Assessment 2023*
- USENIX Security 2025, *DarkGram* (academic, peer-reviewed)
- Push Security and Check Point Research, on compromised social-platform accounts used for
  malvertising and further phishing
- Telegram's own official platform documentation, on channel monetization and collectible-asset
  mechanics

### Standards and frameworks

- MITRE ATT&CK Enterprise: https://attack.mitre.org/

## Appendices
{: .hl-tier-3}

### Appendix A: Complete IOC List

Machine-readable indicators are maintained separately for ingestion:
`ioc-feeds/gotenberg-rce-cryptomining-107-175-69-137-iocs.json`

### Appendix B: Detection Rules

Detection rules are maintained separately:
`hunting-detections/gotenberg-rce-cryptomining-107-175-69-137-detections.md`

Includes eleven rules: four Sigma Detection rules, three Sigma Hunting rules, one Suricata
Detection signature and three Suricata Hunting signatures. The Sigma rules cover the exploit itself
at the ExifTool argv-split, the daemon-name-versus-location mismatch that both miner install modes
produce, the systemd wrapper shape behind the persistent install, the rival-miner kill sweep and the
base64-staged deploy. The Suricata rules cover the wire signature plus the operator's own callback
lane.

No YARA rule is shipped for the miner binary; the coverage gap is explained in that file rather than
left silent, since the miner is a commodity payload that a byte-pattern rule would only ever match
across an unrelated population, not this operator specifically. Three further candidates were
considered and deliberately cut, with the reasoning recorded there: a writability probe too
ubiquitous to carry signal, a payload-fetch pair whose only anchors are atomic indicators already in
the feed, and a watchdog script seen on a single host whose behaviour was never captured.

### Appendix C: Glossary

| Term | Definition |
|---|---|
| Blind RCE | remote code execution where the response gives no direct evidence the injected command ran, confirmed instead through a side channel like timing or an out-of-band callback. |
| Out-of-band (OOB) callback | a connection an exploited host makes back to infrastructure the attacker controls, used to confirm code execution when the original request's response reveals nothing. |
| Argv splitting | an injection technique where embedded delimiter characters, here newlines inside a metadata field, cause a program to parse part of an intended data value as a separate command-line argument. |
| Systemd unit | a Linux service definition that controls how a program starts, restarts, and persists across reboots; the mechanism behind this campaign's persistent miner install. |
| RDAP | Registration Data Access Protocol, the modern replacement for WHOIS, used here to identify hosting providers and abuse contacts for the confirmed victim population. |

---

© 2026 Joseph, The Hunters Ledger. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), free to republish and adapt, including commercially, with attribution to The Hunters Ledger and a link to the original.
