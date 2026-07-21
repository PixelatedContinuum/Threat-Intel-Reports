---
title: "Inside a Multi-Vector PII-Harvesting Operator Directory"
date: '2026-07-21'
layout: post
permalink: /reports/multivector-ecommerce-rce-toolkit-192-3-1-116/
hide: true
unlisted: true
category: "PII Harvesting Operation"
description: "An exposed operator working directory reveals which exploitation techniques in a multi-vector data-harvesting operation actually produced stolen customer records, which were only attempted, and why the difference is visible only in outcome artifacts."
detection_page: /hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/
ioc_feed: /ioc-feeds/multivector-ecommerce-rce-toolkit-192-3-1-116-iocs.json
detection_sections:
  - label: "Detection Coverage Summary"
    anchor: "detection-coverage-summary"
  - label: "YARA Rules"
    anchor: "yara-rules"
  - label: "Sigma Rules"
    anchor: "sigma-rules"
  - label: "Suricata Signatures"
    anchor: "suricata-signatures"
  - label: "Coverage Gaps"
    anchor: "coverage-gaps"
ioc_highlights:
  - "192.3.1[.]116"
  - "31.22.111[.]190"
  - "vpn932081317[.]softether[.]net"
  - "cs-pgcwufmiws[.]cn-hangzhou[.]fcapp[.]run"
---

**Campaign Identifier:** MultiVector-Ecommerce-RCE-Toolkit-192.3.1.116<br>
**Last Updated:** July 21, 2026<br>
**Threat Level:** HIGH

---

## 1. Executive Summary

None of this operator's five remote-code-execution technique classes produced a single byte of stolen data. Every confirmed record theft in this campaign came from exposed management interfaces, verbose application logs, and enumerable record identifiers, which are configuration failures rather than software vulnerabilities. That gap between what the operator built and what the operator achieved is the finding, and it is visible only because the operator's own working directory was left publicly readable, preserving the outcome artifacts alongside the tooling.

The subject is not malware. It is an exposed operator working directory at `192.3.1[.]116:7777` (AS36352, HostPapa, United States), served by a plain static HTTP server, holding a live multi-vector offensive toolkit aimed at roughly a dozen mainland-Chinese commercial platforms across five mapped corporate groups and several standalone threads. There is no implant, no loader, no command-and-control framework, and no malware family anywhere in the corpus. Detection value therefore lies in the exposure surfaces this operator consumes and the request patterns that consume them, not in file signatures.

This report exists because public reporting on this class of operator is thin. The activity was surfaced through open-directory monitoring rather than through an incident response engagement, and four independent checks found no public reporting tying this operator to any documented threat actor. The operation is tracked internally as UTA-2026-019 *(an internal tracking label used by The Hunters Ledger, see Section 10)*.

### What was confirmed

Real customer names plus order and financial records for at least five named individuals were harvested from `riverbaybuy[.]com`, a rent-to-own and installment commerce platform, through four independent sourcing channels operating in parallel. The operator's own scripts retain the extracted name-to-identifier mapping under a plaintext summary header, which is a record of a completed extraction rather than a plan for one. Fuller identity fields that the pipeline is written to pull, including national identity numbers, email addresses and emergency contacts, are highly likely but are not confirmed by any captured response.

The standout technique, and the single best detection opportunity in this campaign, is not an exploit at all. Through an unrestricted Jolokia management interface, the operator remotely raised the target application's own logging verbosity, deliberately triggered ordinary business transactions so that customer data would be written into the now-verbose logs, then read those logs back through the application's log-file endpoint. The operator did not find a place where the data already sat. The operator made the target produce it. Section 3.3 covers this in detail.

An unauthenticated Alibaba Druid monitoring console belonging to `web.51qzp[.]com` (Quanzipin) exposed, at time of capture, a production database connection string, the schema name, the fact that the application connects as `root`, a 93-table schema, 427 API endpoints and 830 real SQL statements. The database password was not disclosed. A read-only re-check on 2026-07-20 found the host resolving NXDOMAIN and the port closed, so the exposure appears remediated.

A complete, pre-staged account-takeover weapon sits armed against a real staff account: 10,000 individually pre-built requests covering the entire four-digit verification-code space, all sharing one genuine verification context, all carrying the same operator-chosen replacement password. Whether it was fired is unconfirmed. What separates it from the operator's exploratory scripts is that it required no further work to run.

### What was only attempted

The negative findings carry as much intelligence value as the positives here, and they bound the harm rather than qualifying it. A sustained effort to decrypt one specific individual's encrypted phone number and government identity number failed: the most sensitive fields the operator pursued were not obtained. The XStream engagement, the JNDI chain, a brute-force run and six management-endpoint probes all failed, were blocked, or produced no evidence of success. Section 6 gives each with its limits.

### Why this matters beyond these targets

All eight exploitation technique classes in this toolkit are well-documented public techniques with mature proof-of-concept code. None is novel. None is a zero-day. That is precisely what makes the campaign transferable: six of the eight had no existing published Sigma, Suricata or YARA coverage before this investigation. Commodity techniques with no shipped detection are a real gap for defenders, and closing it does not depend on this operator remaining active.

### Key takeaways

1. The confirmed theft came through information disclosure, not exploitation. Unauthenticated monitoring consoles, unrestricted management interfaces, heap dumps and predictable record identifiers did the work that five remote-code-execution chains failed to do.
2. Log verbosity is an attack surface. An attacker who can reach a management interface can manufacture sensitive data in logs and then read it, and that write-then-read sequence is rarely instrumented.
3. Capability is not outcome. This corpus is overwhelmingly capability, and separating the two required outcome artifacts that only an exposed operator directory provides. A capability catalog read as a breach report would overstate the harm by a wide margin.
4. Attribution to any named threat actor is not possible. The evidence supports the statement that no public reporting was found, which is a claim about catalogs, not about the world.
5. The exposure classes this operator hunts are widespread and are not specific to any organization named in this report.

Structured indicators are published in the machine-readable [IOC feed](/ioc-feeds/multivector-ecommerce-rce-toolkit-192-3-1-116-iocs.json). Detection content is published separately in the [detection rules file](/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/).

---

## 2. Threat Classification and Campaign Scope

This is an operator toolkit and captured-data cache, not a malware family, and the classification has direct consequences for how a defender should use this report.

| Field | Assessment |
|---|---|
| Type | Operator offensive toolkit and captured-data cache. No malware family, no implant, no persistence binary on any victim host. |
| Family | Not applicable. Bespoke Python and shell attack scripts wrapped around public exploitation payload classes. |
| Family confidence | Not applicable. Nothing in the corpus matches or resembles a tracked malware family. |
| Sophistication | Intermediate and genuinely uneven. Reported as two separate bands in Section 10.3, not as one averaged label. |
| Operator profile | An individual operator or a very small crew. Absent from both the Hunt.io and VirusTotal threat-actor catalogs. |
| Threat level | HIGH (overall risk score 7.2/10, see Section 11) |
| Activity window | Host re-provisioned around 2026-01-01. Earliest dated operator artifact 2026-05-31. Control-channel session anchor 2026-06-01. Operator access observed through 2026-07-06. Directory still live and growing as of July 21, 2026. |
| Target geography and sector | Mainland China. Rent-to-own and installment commerce, device rental, credit rental, gig work and recruitment, insurance asset management, loan referral, and a mobile-OEM developer platform. |

### 2.1 Why there are no file hashes in this report

The IOC feed for this campaign carries no `file_hashes` object, and that absence is deliberate rather than an omission. No malware sample exists. The only hash present anywhere in the evidence is the standard empty-file SHA256, which appears because a publicly available exploitation tool the operator downloaded arrived as zero bytes.

Five files in the corpus produced Cobalt Strike beacon-scanner hits. All five are confirmed false positives. Every real Cobalt Strike configuration field is null: version unknown, no domains, no URIs, no watermark, no kill date, no user agent and no public key. This is the classic empty-config scanner artifact on large, high-entropy files, and it is worth stating plainly because a "Cobalt Strike beacon" line item carried forward from an automated scan would completely misdescribe this campaign. Do not carry it forward.

A separate Android application package in the corpus, protected by a commercial packer, carries only generic and explicitly deprecated signature hits on near-uniform high-entropy content. It remains flagged and unverified, and it is deliberately excluded from the IOC feed. It is a third-party target application the operator pulled down for analysis, not operator tooling.

### 2.2 Why the evidence supports unauthorized activity

The operator self-labels consistently: throwaway accounts named `redteam01`, `redteam03`, `pentest_user_01` and `pentest_crack2`, and private key files named `pentest_key`, `pentest_ssh_key` and `ssrf_key`. That naming is recurring and deliberate enough that it is not casual, and it is the single strongest argument for an authorized-testing reading. It is outweighed.

**Judgment:** the observed activity is unauthorized and malicious, not authorized security testing.
**Confidence:** HIGH (approximately 85 percent).
**Why this confidence:** four strong and five moderate inconsistencies with the authorized-testing hypothesis, drawn from four independent evidence types. A sustained five-iteration effort was directed at decrypting one specific real individual's phone number and government identity number, which has no demonstrative value in any authorized engagement, since a test needs one attempt against any record rather than five against one person. The harvest script's own output header reads as a plaintext summary of real named individuals, retained across runs. Account-takeover tooling sits armed against a real staff account with an operator-chosen replacement password. Target breadth spans eight or more unrelated organizations with no client separation of any kind. And no engagement scope, authorization artifact, rules-of-engagement document, or client reference appears anywhere in roughly 450 files, despite this operator compartmentalizing nothing else: keys, tokens, harvested data, working notes and environment captures all sit in one publicly listable directory.
**What is missing:** absence of authorization cannot be positively proven from captured artifacts. No targeted platform has been asked to confirm that no engagement existed, which is the single cleanest test of the question and is structurally unavailable to a third-party intelligence provider.
**What would increase confidence:** a non-engagement confirmation from any one of the targeted platforms.

The weight of evidence points clearly to unauthorized data theft. The authorized-testing reading is formally open and unsupported. It is not stated as confirmed, because HIGH is not DEFINITE.

Between two remaining readings of the naming convention, operator vernacular is favoured over a deliberate false flag at MODERATE confidence (approximately 70 percent). The deciding observation is that the same vocabulary appears in the operator's own private key filenames, which no audience was ever meant to see. A false flag is a message to an audience, and it does not need to appear where there is no audience.

### 2.3 What the exposed directory is, and what it is not

`http://192.3.1[.]116:7777/` is a plain Python static file server of the `SimpleHTTP` class. Two consequences follow, and both are frequently misread.

First, every file in the operator's working tree was retrievable by anyone who found the port, including private SSH keys, captured victim data, and control-plane environment dumps. This is the operational-security failure that makes the entire investigation possible.

Second, requesting `hxxp://192.3.1[.]116:7777/cmd[.]jsp` returns the **source** of that file. The server does not execute JSP. The host is distributing a working web shell, not running one at that URL. Deployment of that web shell to any victim host is unconfirmed: it exists in the operator's own directory, and no captured artifact shows it present anywhere else.

### 2.4 Campaign complexity and how this report is organized

Multi-target, single-operator, no malware. Roughly five mapped corporate groups plus at least seven standalone or emerging target threads.

Depth in this report goes to the two anchors and is proportional to evidenced impact rather than to the number of entities involved. Section 3 covers `riverbaybuy[.]com`, the only target with confirmed data theft. Section 4 covers Quanzipin, the cleanest and most fixable exposure. Section 5 covers the exploitation toolkit as technique classes. Section 6 separates observed outcomes from capability. Section 8 characterizes the remaining landscape without enumerating every entity, because exhaustive enumeration of attempted-only targets would obscure the two findings that matter.

---

## 3. Anchor 1: riverbaybuy.com, Confirmed Multi-Victim Data Theft

> **Analyst note:** This section covers the one target where stolen customer data is confirmed rather than attempted. It walks through how the operator obtained it: not by breaking into the platform, but by using management and diagnostic features the platform left open to the internet. Readers who take away one thing from this report should take away Section 3.3.

Four independent data-sourcing channels converged on one platform, and the operator's own scripts retain the results of a completed extraction. That combination, planning plus a preserved outcome, is what separates this target from every other thread in the campaign.

### 3.1 The target

`riverbaybuy[.]com` is a rent-to-own and installment commerce platform. Its internal handle is `hzsx`, visible in both the API path prefix `/hzsx/` and the Java package namespace `com.hzsx.rent.*`. It runs a Spring Cloud microservice stack behind a Eureka service registry with Feign HTTP clients (`OrderClient`, `UserCenterClient`, `ProductClient`), uses Ant Group's AntChain service for contract signing, and includes a distributed identifier-generation component. It shares an internal address with a separate Eureka-engaged target elsewhere in the campaign, which is a HIGH-confidence inference rather than a DEFINITE link.

Confirmed here: real customer names plus order and financial records for at least five named individuals, an armed account-takeover weapon aimed at a staff account, and live-used database and cache credentials.

### 3.2 The kill chain

> **Analyst note:** This section walks the attack from first contact through to stolen records. The short version is that the operator never needed an exploit against this platform. A diagnostic interface left reachable from the internet handed over memory and logs, and everything that followed was a matter of reading what was already available.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/multivector-ecommerce-rce-toolkit-192-3-1-116/multivector-riverbaybuy-kill-chain.svg" | relative_url }}" alt="Vertical five-step infographic titled Confirmed Multi-Victim Harvest, showing how an exposed management interface became real customer records. Step one, orange band, Unrestricted management interface: Jolokia and Actuator were reachable externally with no access restrictor, quoting the captured string no access restrictor, access to any MBean is allowed; assessed as the likely master access vector; detection guidance is to alert on external Jolokia or JMX reachability. Step two, red band, Memory and log capture: Java heap dumps retrieved alongside application request and response logs via the heapdump and logfile endpoints, three heap snapshots captured; detection guidance is to alert on heap-dump retrieval success, meaning a 200 response with a large body. Step three, yellow band, Real order identifiers extracted: live order IDs mined from captured memory rather than guessed, fed by four independent sourcing channels; detection guidance is to watch sequential record-ID enumeration on detail endpoints. Step four, red band, Identifier resolved to user: each order ID resolved to a distinct platform user, built to iterate across up to thirty users in one pass. Step five, deep red band, Customer records harvested: real names tied to real order records for at least five named individuals, confirmed by an operator-authored identifier-to-name mapping and corroborated by live order IDs in captured memory, with the caveat that fuller identity fields are highly likely but not confirmed by any captured output.">
  <figcaption><em>Figure 1: The anchor finding end to end. The chain begins with a configuration failure rather than a software vulnerability, which is why none of the operator's remote-code-execution tooling appears anywhere in it.</em></figcaption>
</figure>

#### Stage 1: Service and exposure discovery

> **Analyst note:** Before attacking anything, the operator maps which management and diagnostic endpoints a target has left reachable from the internet. This stage produces no damage on its own, and it is also the cheapest stage for a defender to detect.

The operator's reconnaissance profile is not a generic port sweep. It targets a specific 14-port list: `22,80,443,3306,6379,8080,8443,8888,9000,9001,9002,9090,8848,8157`. Two of those entries are the operator's tell. Port 8848 is the default for the Nacos service-discovery console, and port 8157 is where this operator found an exposed Alibaba Druid monitoring console on a different target. This operator hunts exposed management planes specifically, and the port profile encodes which ones.

Full-range sweeps run at `-T5 --min-rate 10000` across all 65,535 ports. There is no attempt at stealth anywhere in the reconnaissance tooling, which makes this stage a reliable early tripwire in flow or firewall telemetry.

#### Stage 2: Reaching the unrestricted management interface

> **Analyst note:** Spring Boot applications ship with a management framework called Actuator, and an optional bridge called Jolokia that lets an operator read and change the application's live internal state over ordinary HTTP. When Jolokia is exposed without access restrictions, an outside party gains the same control an administrator would have.

The target's Jolokia surface reports, in its own configuration, that there is no access restrictor and that access to any managed bean is allowed. That single configuration state is the likely master access vector for this entire target, and it plausibly explains both the heap dumps the operator later mined and the database credential the operator later used.

Confidence for the Jolokia interface being unrestricted: HIGH, based on the interface's own captured self-description. Confidence that it is the specific origin of the credential and the heap dumps: MODERATE. No captured artifact records the retrieval itself, so this is a strong inference from mechanism and opportunity rather than a confirmed transfer.

#### Stage 3: Manufacturing the data

> **Analyst note:** This is the stage that makes this campaign worth publishing. Rather than searching for a location where customer data already sat, the operator changed the application's own settings so that the application would start writing customer data into its log file, then read the log file. Section 3.3 covers the mechanism.

#### Stage 4: Multi-channel harvesting

> **Analyst note:** With several sources of customer identifiers available at once, the operator built parallel pipelines rather than relying on one. This redundancy is what makes the extraction robust against any single surface being closed.

Four independent channels ran against the same target: mining a captured Java heap dump for live order identifiers, mining the verbose application log produced in Stage 3, pulling the framework's built-in request-history endpoint, and directly enumerating order identifiers by constructing them from a predictable format. Section 3.4 details each.

#### Stage 5: Escalation toward account takeover

> **Analyst note:** The final stage moves from reading data to attempting control of a staff account, which would convert an external data-theft problem into an internal one. This stage is armed and pre-staged but its execution is unconfirmed.

Section 3.5 covers the weapon. Section 3.6 covers a parallel escalation, an effort to decrypt one individual's protected identity fields, which is a confirmed failure and which bounds the harm.

### 3.3 The standout technique: elevating log verbosity to manufacture harvestable data

> **Analyst note:** Applications write log files, and how much detail they write is a setting that administrators can change while the application is running. This operator changed that setting from outside the organization, made the application busy itself with real customer transactions so the new detail level would capture them, then downloaded the resulting log. Nothing was exploited in the conventional sense. A management feature was used exactly as designed, by the wrong party.

The mechanism is a three-step sequence, and each step alone looks unremarkable in a log.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/multivector-ecommerce-rce-toolkit-192-3-1-116/multivector-manufactured-log-harvest.svg" | relative_url }}" alt="Vertical four-step infographic titled Manufacturing the Evidence, showing log-verbosity abuse. Step one, orange band, Reach the management interface: an externally reachable Jolokia or JMX endpoint with no access restriction, invoked by a POST to the jolokia path using the setProperty operation, requiring no exploit and no credential, only reachability. Step two, red band, Elevate log verbosity: an application logger raised to DEBUG and an HTTP client set to FULL body logging, described as a configuration change rather than an exploit, with nothing compromised at this point; detection guidance is to alert on remote log-level changes because they are rare and rarely instrumented. Step three, yellow band, The application writes the data itself: full request and response bodies, now including customer records, land in the log file, with the note that the sensitive data did not exist in the log before the operator asked for it. Step four, deep red band, Read the log back: the log file is retrieved through the same management interface using a GET to the actuator logfile path, with emphasis that the detection is the ordered sequence of a log-level change followed by a logfile read within minutes, published as a temporal correlation rule rather than two standalone alerts.">
  <figcaption><em>Figure 2: The campaign's standout technique. The operator did not find exposed data, it caused the application to write sensitive data into its own logs and then collected it, which is why each step looks benign in isolation.</em></figcaption>
</figure>

**Step one, the write.** Using Jolokia over HTTP, the operator invokes `setProperty` against the application's own managed beans to raise the Feign HTTP-client logging level to `FULL` and to set the application's loggers to `DEBUG`. Feign at `FULL` logs request and response headers and bodies for every inter-service call. In an enterprise Java application, those bodies are the customer records.

**Step two, the trigger.** With verbose logging now active, the operator deliberately performs an ordinary order lookup. This is not an attack request. It is a legitimate-looking transaction whose only purpose is to make the application generate trace traffic while the elevated logging captures it.

**Step three, the read.** The operator then reads `/actuator/logfile`, the framework's endpoint that serves the application's own log file over HTTP, and filters the result for the lines the trigger produced.

The same script separately queries Jolokia for raw configuration values including the datasource connection URL, the connection-pool JDBC URL, and service-registry configuration. Those are administrative reads through the same interface.

**Why this matters.** Most data-theft techniques are constrained by where the target already keeps its data: a database the attacker must reach, a file the attacker must read, an API the attacker must call with valid credentials. This technique removes that constraint. The attacker changes what the application chooses to record, and the application then writes the data to a place the attacker can already reach. It is a qualitative step above running published proof-of-concept code, and it is the item in this corpus that genuinely demonstrates capability, as distinct from the length of the technique list.

**Confidence.** DEFINITE that the tooling exists and is written to perform this sequence, based on direct inspection of the operator's own script. MODERATE that this specific script's own run succeeded, because no outcome artifact for it was captured. What it supplies is the missing mechanism behind an already-confirmed finding: the operator's separate log-mining channel demonstrably obtained genuine customer data from this target's application log, and this is the most plausible explanation for how that log came to contain it.

**Detection strategy.** The high-fidelity signal is the sequence and its timing, not any single event. A write to a Jolokia or JMX endpoint that changes a logging level, followed within minutes by a read of the application log-file endpoint from the same source, is a pattern with essentially no benign explanation from an external address. Both halves are individually low-value and jointly high-value, which is why the published detection content builds a correlation rule over two base rules rather than alerting on either alone. Coverage is in the [detection rules file](/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/#sigma-rules).

**Business impact.** An organization can be fully patched, run no vulnerable library version, and still lose customer records to this technique, because nothing here is a software vulnerability. The exposure is a management interface reachable from outside the management network. That places the remediation in configuration and network policy rather than in the patch cycle, and it means vulnerability-scan-driven assurance will not surface it.

### 3.4 Four independent PII-sourcing channels

> **Analyst note:** Rather than depending on one route to customer data, the operator built four that draw on different weaknesses. Understanding each separately matters because closing one does not close the others.


<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/multivector-ecommerce-rce-toolkit-192-3-1-116/multivector-four-pii-channels.svg" | relative_url }}" alt="Two-by-two grid infographic titled Four Independent Paths to the Same Customer Data. Channel one, red band, Heap-dump memory mining: live order identifiers recovered from Java heap snapshots pulled from the running application, described as real identifiers rather than guesses and as the channel that seeded the confirmed harvest. Channel two, red band, Manufactured log harvesting: log verbosity raised through the management interface so request and response bodies were written and then retrieved, confirmed effective because a captured session identifier taken from live logs was reused to pull that user's orders. Channel three, yellow band, Request-history endpoint: the framework's own recent-request trace surface exposing captured traffic, characterized as a built-in diagnostic surface that was exposed rather than exploited. Channel four, yellow band, Order-identifier enumeration: structured predictable record identifiers brute-forced across sequence ranges, which works with no access to memory or logs at all and operates purely against the public API. The footer notes that redundancy is the finding, since closing one channel leaves three.">
  <figcaption><em>Figure 3: Four routes to the same customer data, each usable on its own. The practical consequence is that remediating any single channel would not have stopped the harvest, so the fix has to address the class.</em></figcaption>
</figure>

**Channel one, heap-dump mining.** A Java heap dump is a snapshot of everything an application had in memory at one moment, and on a busy commerce platform that includes live customer records and live order identifiers. The operator's harvesting script regex-extracts every real order identifier matching the pattern `001OI\d{6}20\d{6}\d{7,10}` directly out of a captured heap dump, resolves each identifier to its owning user account, then for up to 30 distinct real users pulls both the full order history and the identity-verification record in a single pass. It prints customer name, order identifier, product and stock-keeping unit, rental amount, installment count, shop name, status and timestamps.

Three heap dumps were captured in total. Structurally they represent two distinct application processes. Two of them match each other closely across roughly a dozen independent metrics and represent the configuration-heavy and authentication-heavy backend tier. The third is the order-facing tier: it alone carries the literal platform hostname at 74 occurrences, the live order-identifier pattern at 51 occurrences, and the highest density of personally-identifying string shapes. That statistical profile independently corroborates that the third dump was the operator's actual harvesting source material. Confidence HIGH, resting on a statistical fingerprint rather than on direct process-identity metadata.

**Channel two, verbose application-log mining.** This is the channel Section 3.3 enabled. The operator pulls the framework's request-history endpoint and mines the application log for lines containing the enterprise-Java markers 入参为 and 出参为, meaning "input parameters are" and "output parameters are". That is a widespread convention in Chinese enterprise Java development which logs the request and response payload of every service call. The operator then explicitly filters **out** its own attack traffic, discarding lines containing `UNION SELECT` and the identity-verification and identity-document markers the operator's own probes generated, in order to isolate genuine successful responses containing real customer data.

That filter is analytically important. The operator was not collecting its own test noise. It was separating real production traffic from its own footprint, which is behaviour consistent with harvesting, and inconsistent with demonstrating a vulnerability.

**Channel three, request-history retrieval.** The Spring Boot framework retains a rolling history of recent HTTP exchanges and serves it over a management endpoint. Where that endpoint is reachable, an outside party gets a window into recent real traffic, including parameters, without needing to intercept anything.

**Channel four, order-identifier enumeration.** Date-targeted scripts escalate to direct brute force, constructing identifiers of the form `001OI{seq:06d}20260601000000000` across sequence ranges. That the operator could construct valid identifiers at all confirms the platform's order-identifier scheme is predictable enough to enumerate. This is a structural insecure-direct-object-reference risk, not merely an information-disclosure one, and it persists after every management endpoint is closed.

**Confirmed versus likely.** Real customer names plus order and financial records for at least five named individuals are CONFIRMED. The confirming artifact is a hardcoded dictionary in the operator's own script, commented as the known user-identifier set from an earlier run, mapping five real user identifiers to real personal names, four of them fully resolved, printed under a plaintext summary header. That is the operator's record of a completed extraction rather than a plan for one, and it is corroborated independently by the live order identifiers recovered from heap memory. The fuller identity fields the pipeline is written to pull, national identity number, email address, and parsed emergency-contact entries including third-party names and numbers, are HIGHLY LIKELY but are NOT confirmed by any captured response. No victim name, identifier or record is reproduced anywhere in this publication.

### 3.5 The armed account-takeover weapon

> **Analyst note:** Many platforms let a user reset a password by entering a short numeric code sent by SMS. A four-digit code has only 10,000 possible values, so an attacker who can submit guesses quickly enough can simply try them all. This operator prepared every one of those 10,000 guesses in advance against one specific staff account.

The file is 3.27 MB and it is not a loop. It is 10,000 individually pre-built `curl` commands, one per possible four-digit verification code from `0000` to `9999`, all targeting the same password-reset endpoint on `riverbaybuy[.]com`. Every command carries an identical verification-context pair, `codeKey` and `codeTime`, which means a single real SMS verification was triggered against one real phone number and this file is the complete, ready-to-execute brute force of the code space that could match it. The account type in the request is a staff or operator type rather than a customer, and the intended replacement password is a fixed operator-chosen string.

Whether this run was fired, and whether it succeeded, is not confirmed. Nothing in the corpus records the outcome. What distinguishes it from the operator's exploratory work is that it is complete, pre-staged and immediately executable against a specific real staff account, requiring no further development.

A parallel weapon exists against a different platform's supplier backend, brute-forcing a four-digit code on a password-recovery endpoint and chaining into a reset. That one targets a well-known placeholder phone number, so it reads as development work rather than as an armed weapon. The distinction is worth preserving: one of these two is a test, and one is not.

**Detection strategy.** The discriminator is the constant verification context across many requests. Ordinary users retry a code two or three times with a fresh context after each expiry. A brute force keeps one context constant while a short numeric field iterates. That shape is what the published Sigma correlation content keys on, and it generalizes to any platform with short numeric verification codes, not just this one.

**What this means.** Short numeric verification codes are only as strong as the rate limiting and attempt-count enforcement around them. The mathematics gives an attacker a certainty of success within 10,000 tries, so the entire control rests on the server refusing to accept try number six.

### 3.6 The decryption effort: a bounded, high-confidence negative

> **Analyst note:** Some of the most sensitive fields on this platform, a customer's phone number and government identity number, are stored encrypted. The operator spent five iterations of tooling trying to find the key that would decrypt them for one specific person. Independent testing shows that effort did not succeed, and that negative result is what limits how much harm this campaign actually caused.

The operator's scripts hold two hardcoded encrypted values, labelled in the operator's own code as an encrypted phone number and an encrypted national identity card number, belonging to one specific individual obtained through the platform's identity-verification flow. Five successive script iterations pursue the AES-128-ECB key, progressing from searching Jolokia properties, to dumping the framework's environment endpoint, to sweeping heap-dump strings, to hexadecimal brute force, to keys derived from hashed candidate strings.

Independent memory forensics across all three captured heap dumps, where the operator only ever checked one, tested 26,570 unique heap-derived 16-character candidates, 123 named-candidate variants in raw, MD5, SHA256 and truncated-SHA256 forms, and 408 context-adjacent substrings, for roughly 54,000 individual decryption attempts against both encrypted values. Zero successes.

**Confidence:** HIGH as a negative result, for the string-extraction approach the operator's own tooling used. It is not DEFINITE for three reasons: the key may never have existed as a contiguous printable string at the moment any of the three snapshots was taken; the key may be stored in non-printable byte form; and the cipher configuration could differ from the AES-128-ECB assumption baked into the operator's scripts. Full closure would require an object-graph heap parse rather than a string sweep.

**Why this is a finding and not a caveat.** In a campaign that is overwhelmingly capability rather than outcome, a well-tested negative bounds the harm. This one says that the most sensitive fields the operator was pursuing, one individual's phone number and government identity number, were not obtained through the route the operator took. That is a materially different harm profile from the one a capability catalog alone would imply. The sub-effort stays at attempted.

**A second-order observation.** The fact that the operator had to attack the encryption at all confirms the platform encrypted those two fields at rest, which is a design decision that worked. The platform's weakness was in what its management interfaces and logs exposed, not in how it stored its most sensitive fields.

---

## 4. Anchor 2: Quanzipin, the Clean and Fixable Exposure

> **Analyst note:** This section covers a single misconfigured monitoring page that gave an outside party the complete internal design of a production system. No password was disclosed and no customer records were proven to have been returned, which makes this the clearest teaching case in the campaign: the harm from an exposed monitoring console is what an attacker learns, and that knowledge does not expire when the console is closed.

An unauthenticated database-monitoring console handed a threat actor the full data model of a live production platform, and the platform has since closed it. This is the campaign's most actionable finding precisely because the fix is unambiguous and the boundary of the harm is precisely known.

### 4.1 The target

`web.51qzp[.]com` belongs to 全咨聘（雄安）科技有限公司, Quanzipin (Xiong'an) Technology Co., Ltd., a construction and engineering cost-consulting gig-work platform. It is the only target in this investigation with a confirmed registered legal entity, which is itself notable given Section 8.3.

The platform is built on RuoYi (若依), a widely used open-source Spring Boot and MyBatis application framework, deployed as a single fat JAR under a BT/aaPanel hosting convention. That stack combination is common across Chinese small and medium enterprise hosting, and its default component set is exactly what this operator's port profile hunts.

### 4.2 What the Druid console exposed

Alibaba Druid is a database connection pool, and it ships with an optional monitoring servlet that renders live statistics about every query the application runs. Where that servlet is reachable without authentication, anyone who finds it can read the application's entire database interaction history.

At time of capture, this console was reachable without authentication on port 8157 and exposed:

- The production database connection string, including host, port and the schema name.
- The fact that the application connects to its database as `root`, the account with unrestricted privileges.
- The full 93-table schema.
- 427 distinct API endpoints.
- 830 real SQL statements as executed by the application, with execution counts.

Real traffic counters confirm a live production system rather than a staging environment, showing 68,247 requests and 2,865,801 JDBC executions.

The highest-volume sensitive query, at more than 53,099 executions on its own plus tens of thousands more across near-duplicate variants, bulk-selects the password field, a separate financial PIN field, the national identity number field, the mobile number and a messaging identifier together from the member table. Eighty-two queries in the captured set touch credential-adjacent fields.

### 4.3 The distinction that carries this finding

This is where careless reporting would do real damage to a real company, so the boundary is drawn explicitly.

**CONFIRMED:** the query text, schema and execution statistics were exposed to anyone who could reach the unauthenticated monitor, and a threat actor accessed and retained what it exposed. The operator's own directory holds the full set of captured console pages. That is a genuine information-disclosure vulnerability on its own terms.

**CONFIRMED:** the data-access layer is written to fetch password hashes, wallet PINs and government identity numbers together, in bulk, at high frequency. That is a real design-risk indicator independent of any attacker.

**NOT CONFIRMED:** Druid displays query text and execution statistics, not returned data or bound parameter values. Parameters render as placeholder characters. This evidence does not prove that any password, identity number or financial PIN was returned to a client or exfiltrated.

**NOT DISCLOSED:** the database password. The console exposed the connection details, the schema, and the `root` **username**. It did not expose the password, and there is no evidence the operator obtained it. This report does not describe the operator as holding a compromised credential for this platform, because the operator does not.

### 4.4 Current status

The console appears remediated. A read-only re-check on 2026-07-20 found `web.51qzp[.]com` resolving NXDOMAIN and port 8157 closed. This exposure is described throughout as live at time of capture, never as currently live. The remediation is independent of this investigation's disclosure timing.

### 4.5 What else was directed at this platform

An insecure-direct-object-reference sweep against an engineer-detail endpoint walked consecutive record identifiers in the range 116270 to 116277. Those identifiers are consistent with real gig-worker records at MODERATE confidence. An arbitrary-file-retrieval test was directed at a document-download endpoint. A 248-entry brand-specific password wordlist was built for this target. Both the SnakeYAML and Logback payload chains described in Section 5 were aimed here.

The operator also used this platform as the source of a valid session token in a cross-platform token-replay test, registering a throwaway account here and then replaying the resulting token against an unrelated platform's user-information endpoint under four different header names, testing whether the two shared a backend or a token-signing key. No success artifact exists for that test.

### 4.6 What this means

**Business impact.** After a monitoring console is closed, the organization has fixed the exposure but not the consequence. The actor retains the complete schema, the API surface and the business logic. That knowledge supports precisely targeted future attempts against the same platform without any further reconnaissance, which is why credential rotation is a reasonable precaution here even though no password was disclosed. The knowledge does not expire when the port does.

**Detection strategy.** Any HTTP 200 response on a Druid console path from an external source is worth alerting on regardless of actor. Two design points matter for anyone writing that rule. Do not anchor it to ports 80 and 443, because this instance ran on 8157. And pair the path match with a response-body check for a Druid-specific field name, to avoid matching unrelated paths that happen to contain the same directory name. Published coverage is in the [detection rules file](/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/#sigma-rules).

**A useful negative from elsewhere in the campaign.** A second Druid instance was found on a different target in this investigation and was properly protected. The exposure is not inherent to the software. It is a deployment choice.

---

## 5. The Exploitation Toolkit: Eight Commodity Technique Classes

> **Analyst note:** This section inventories the attack code found in the operator's directory. Every technique here is publicly documented and has been for years, with working example code freely available. That is the point rather than a disappointment: these are the techniques a defender will actually meet, and most of them had no published detection rules before this investigation.

Nothing in this toolkit is novel and nothing is a zero-day. All eight exploitation technique classes are drawn from the well-documented public record with mature proof-of-concept code available. The intelligence value is not that the operator invented anything. It is that six of these eight had no existing published Sigma, Suricata or YARA coverage, which makes a fully commodity technique set an active defensive gap.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/multivector-ecommerce-rce-toolkit-192-3-1-116/multivector-eight-technique-classes.svg" | relative_url }}" alt="Three-column grid infographic titled Eight Commodity Technique Classes, arranged in rows of three, three and two. Six cards carry grey bands indicating no evidenced success: Logback insertFromJNDI, CVE-2021-42550, where the chain stalled at bind in both logged attempts; Logback FileAppender arbitrary file write aimed at dropping a JSP, with no victim deployment observed; SnakeYAML deserialization of the CVE-2022-1471 family using a ScriptEngineManager gadget, with no confirmed execution; Eureka with XStream service-registry deserialization, where a real target engaged and registered but the success callback was never observed; XXE to server-side request forgery including the cloud instance metadata endpoint, where payloads were crafted but no result was captured; and SSRF to Redis CONFIG abuse writing an authorized SSH key for passwordless root, attempted but not evidenced. Two cards carry red bands indicating they produced access or data: Jolokia and JMX abuse, management-interface access reached with no restrictor configured at time of capture, assessed as the likely master access vector; and the unauthenticated Druid console StatViewServlet exposure, which disclosed the full data model and the root username only, not the password.">
  <figcaption><em>Figure 4: Every technique class in the toolkit is public, documented and years old. The significant gap is not novelty but coverage: six of the eight had no public detection content identified during research.</em></figcaption>
</figure>

| Technique class | Public status | Existing published detection coverage before this work |
|---|---|---|
| Logback `insertFromJNDI` (CVE-2021-42550) | Disclosed 2021, mature proof-of-concept | None found |
| Logback `FileAppender` arbitrary file write | Documented framework behaviour | None found |
| SnakeYAML unsafe deserialization (CVE-2022-1471 family) | Disclosed 2022, mature proof-of-concept | None found |
| Spring Cloud Eureka with XStream deserialization | Documented technique, no assigned CVE for the delivery chain | None found |
| XXE to SSRF including cloud instance metadata | Documented since at least 2019 | None found |
| SSRF to Redis configuration abuse to SSH key write | Widely documented | Published Sigma rule from prior work in this research program |
| gopher-scheme protocol smuggling to MySQL | Widely documented | None found |
| Jolokia and JMX management-interface abuse | Documented; the log-verbosity variant is thinly covered | None found |

The one class with prior coverage is covered by a rule authored in an earlier investigation in this same research program, which is itself a small illustration of how narrow the published corpus is for this technique family.

### 5.1 Logback insertFromJNDI, CVE-2021-42550

> **Analyst note:** Java applications write logs through a logging library. Two of the most common libraries had a feature that let a log configuration file fetch a value from a remote directory server. An attacker who can influence that configuration can point it at their own server and cause the application to load and run hostile code. Log4Shell is the famous example. This is the other one.

Log4Shell dominates public discussion of logging-framework remote code execution. Logback's own JNDI-lookup vulnerability landed in the same disclosure window and is comparatively under-documented, which makes a captured working payload for it a genuinely useful artifact.

The captured payload is 220 bytes and points a vulnerable Logback-configured Java application at the operator's own rogue directory server on the standard rogue-JNDI port. The infrastructure link is what elevates this from a catalogued vulnerability to an observed technique: the callback target is this operator's own address, already backed by the operator's own directory-server scripts and setup tooling. The capability was not sitting unused. It was pointed at a real Logback-based target.

**Outcome:** not evidenced. The two logged engagements with the operator's directory server both stalled at the bind step without issuing a search request, and this payload depends on that same completion step. See Section 6.2.

**Detection design.** The two-string combination of the JNDI-insertion element together with an LDAP-scheme value inside a logging configuration element is the discriminator. The insertion element is rare in benign configuration, and pointing it at an attacker-controlled scheme is the exploit itself. This generalizes to any instance of the vulnerability, not to this operator.

### 5.2 Logback FileAppender arbitrary file write

> **Analyst note:** Logging libraries can be configured to write their output to any file path an administrator chooses. If an attacker can control that configuration remotely, the application itself writes the attacker's file into a location the web server will run as code.

An entirely separate route through the same logging library. Rather than fetching remote code, this payload configures the library's file-writing component to write its output to a path ending in `.jsp` inside a web server's temporary document directory. The application then, in the ordinary course of logging, writes an attacker-controlled file into a location the web server will execute.

The destination path in the captured payload includes a port number that matches the web-server connector port independently observed in a target's own management-endpoint log, which suggests this payload was tailored to a specific observed target rather than copied generically.

**Detection design.** A file-writing log appender configured with a destination ending in `.jsp` is never legitimate. The `.jsp` destination is the entire signal.

### 5.3 SnakeYAML unsafe deserialization

> **Analyst note:** YAML is a text format for configuration data. Some libraries that read YAML will, by design, construct whatever Java object the document asks for. An attacker who can get a crafted document into such a parser can ask it to construct an object that fetches and runs remote code.

The captured document is a textbook gadget chain combining a script-engine manager, a URL class loader and a URL, all on one line, pointing at the operator's shared proof-of-concept callback listener. It is the same technique family as CVE-2022-1471.

**Detection design.** A three-string combination of the script-engine manager, the URL class loader and the URL constructor is high precision. In transit this content most often arrives with a YAML or plain-text content type, and sometimes as multipart form data on file-upload endpoints, which is worth accounting for in any network rule.

### 5.4 Spring Cloud Eureka with XStream deserialization

> **Analyst note:** In a microservice architecture, a registry keeps a list of which services exist and where they are. Clients repeatedly ask the registry for updates. If an attacker can register a hostile entry, every client that fetches the update processes attacker-controlled data, and if the client deserializes it unsafely, the attacker gains code execution on the client rather than on the registry.

This is the technique class with the richest outcome evidence in the campaign, and it is covered in Section 6.1 because the outcome, not the payload, is the finding. The operator ran a three-stage escalation ladder of increasingly capable registry servers against a live target that was already polling for updates.

**Detection design.** The detection direction that matters is inbound to the registry client, not outbound from the attacker. A registry delta response whose body carries deserialization gadget markers such as a process-builder or runtime class reference is the high-value event, because it catches the payload arriving at the system that would execute it.

### 5.5 XXE to server-side request forgery, including cloud instance metadata

> **Analyst note:** XML documents can declare an external entity, which is effectively an instruction telling the parser to go fetch a resource and insert it. If an application parses attacker-supplied XML, the attacker can make the application's own server fetch things on the attacker's behalf, including internal services the attacker cannot reach directly.

Several XML and SVG payloads are present. Two are straightforward local file and process-environment reads, the second of which is the more consequential, since Linux application-server environments commonly carry API keys and database credentials.

The standout is a single SVG that probes four internal targets at once: the local management endpoint, the local Redis instance, the local database port, and the cloud instance metadata service at `169.254.169.254`. The metadata target is what separates this from routine internal port discovery. Reaching a cloud provider's instance metadata service through server-side request forgery is the technique class behind the Capital One breach: it can leak the host's own cloud identity credentials, not just internal service banners. In a toolkit whose quality is otherwise uneven, this specific payload shows real understanding of server-side request forgery impact.

**Outcome:** payload confirmed present and crafted, outcome unconfirmed. No captured response shows the metadata service was reached.

**Two implementation details worth recording.** The XML payloads use the sequential placeholder phone number `13912345678` and a password field carrying the well-known MD5 hash of the string `123456`, which confirms these are hand-crafted test documents rather than replayed real submissions. The second detail is also a finding about the target: its registration and login API expects a client-side MD5-hashed password, an unsalted anti-pattern that is independent of whatever the server does downstream.

**Detection design.** An external-entity declaration referencing the cloud metadata address inside an uploaded XML or SVG document is a high-precision signal. Broader variants covering entities that reference local Redis, local MySQL or local management endpoints are worth carrying as separate rules so severity can differ, since cloud credential theft is materially more serious than internal service discovery.

### 5.6 SSRF to Redis configuration abuse to SSH key write

> **Analyst note:** Redis is an in-memory data store. It can be told, at runtime, where to save its data and under what filename. An attacker who can send Redis commands can therefore make it write a file of the attacker's choosing to a path of the attacker's choosing. Point that at the system administrator account's list of authorized SSH keys, insert your own key, and you have password-free administrative access to the server.

This is the most technically advanced artifact in the corpus. The script injects Redis protocol commands, separated by carriage-return and line-feed sequences, through a server-side request forgery vector reachable from an image-processing feature. It issues the directory-set, filename-set, value-set and background-save sequence needed to write the operator's own SSH public key into `/root/.ssh/authorized_keys` on the target, aiming at passwordless root access.

The same script separately constructs raw `gopher://` payloads carrying a low-level MySQL client authentication handshake against an internal database address, and attempts file-scheme reads of the administrator's private SSH key and the system password file.

Chaining server-side request forgery into an in-memory data store's configuration commands to write into a privileged account's key file requires understanding three systems and the seam between them. Smuggling a raw database client handshake through a gopher-scheme request is uncommon and was correctly constructed here.

**Outcome:** attempted, HIGH confidence that it was attempted, no confirmation that the write succeeded on any target.

**Detection design.** Two independent signals. At the network layer, Redis configuration verbs arriving over a non-Redis transport, embedded in HTTP with carriage-return and line-feed separators, is the discriminator. On the host, a change to an in-memory data store's save directory or filename, or an unexpected new entry in a privileged account's authorized-keys file, is the outcome signal. The gopher scheme and a raw database client handshake preamble inside an HTTP parameter or body are rare enough in benign traffic to be high-precision on their own.

### 5.7 Jolokia and JMX management-interface abuse

Covered in full in Section 3.3, since its significance is inseparable from the confirmed harvest it enabled. Recorded here for completeness of the technique inventory.

### 5.8 The staged web shell

> **Analyst note:** A web shell is a small script that lets an attacker run commands on a server through an ordinary web request. This one exists only in the operator's own directory; whether it was ever placed on a real target is unconfirmed.

A minimal but fully functional generic JSP web shell sits in the operator's directory: it reads a single HTTP parameter, runs its contents through the shell, and returns standard output and standard error.

Two of the exploitation techniques above are armed to deliver this one payload. The Logback file-write route writes it directly. The Eureka registry-poisoning route causes a client to fetch it over HTTP from the operator's host.

**Deployment to any victim host is UNCONFIRMED.** It exists in the operator's own directory, which is DEFINITE, and it was never observed staged on any target. It is a hunt target, not an assumed finding, and any defender using it that way should treat a negative result as the expected outcome.

**Detection design.** Keep the string set generic. The parameter name will vary in the wild. The durable pair is the proximity of an HTTP parameter read to a runtime execution call.

### 5.9 What the toolkit's failures reveal

A recurring pattern in the corpus directly informs the capability assessment in Section 10.3: several files' names substantially overstate their contents.

| File | Actual content |
|---|---|
| A well-known JNDI exploitation archive | 9 bytes, a generic empty or error response blob rather than the real tool |
| A deserialization exploitation JAR | 0 bytes |
| Three separately named probe results | Byte-identical 1,747-byte generic blocked-response pages, not the application files their names imply |
| A database file | 14 bytes, containing the literal string `404: Not Found` |
| An Android application build | 430 bytes, a cloud object-storage "no such key" error, confirming the operator was pulling builds from cloud storage and that this request failed |
| A heap dump | 539 bytes, not a real heap dump |

Six confirmed failed fetches plus three duplicate generic responses. Real, working exploitation payloads coexist with a meaningfully unreliable download and tooling pipeline. One of the byte-identical files is worth a specific correction: its filename matches a production application JAR that genuinely exists on a target platform, which is why the operator tried to fetch it. The fetch was blocked. It is not a JAR and it is not a backdoor.

Also present are brute-force input wordlists, which are frequently misread as harvested credentials. A 28-line list mixes generic weak passwords with brand-customized guesses derived from the target's own name. Brand-specific lists exist for two further target clusters, including a 248-entry list for Quanzipin. A filename ending in `_pass.txt` is a shape heuristic, not a content verdict, and treating a guess list as stolen data is a known failure mode in this kind of analysis.

---

## 6. Observed Outcomes: What Was Achieved Versus What Was Built

> **Analyst note:** This section answers the question the whole report is built around. Most published threat reporting describes what an attacker's tools can do, because that is all a captured tool reveals. Here the operator's own logs, error messages and result files survived, so it is possible to say what actually happened. Most of what happened was failure.

Outcome artifacts exist for six separate exploitation efforts in this campaign, and five of the six are negative. That ratio is the single most important calibration in this report: a reader who treated the toolkit inventory in Section 5 as a breach summary would overstate the harm by a wide margin.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/multivector-ecommerce-rce-toolkit-192-3-1-116/multivector-built-vs-achieved.svg" | relative_url }}" alt="Two-column comparison infographic titled What Was Built Versus What Was Achieved. The left column, headed built with no evidenced success, holds five grey-banded cards: Logback insertFromJNDI with a rogue LDAP and JNDI server stood up on port 1389, where the chain stalled at BindRequest with no SearchRequest following in both logged attempts; Spring Cloud Eureka with XStream, where a rogue registry engaged a real target that registered a service but the success callback was never observed across roughly seventeen thousand access-log lines; SnakeYAML deserialization with a crafted ScriptEngineManager gadget document and no confirmed execution; XXE to server-side request forgery including cloud instance metadata, crafted and delivered with no captured outcome; and a staged JSP web shell existing only in the operator's own directory, with deployment to any victim host unconfirmed. The right column, headed achieved via misconfiguration, holds three cards: unrestricted Jolokia and Actuator in red, the likely master access vector that yielded heap dumps and a database credential; the unauthenticated Druid console in red, exposing the JDBC URL, ninety-three-table schema, four hundred and twenty-seven endpoints, eight hundred and thirty SQL statements and the root username but not the password, exposed at time of capture and later found remediated; and confirmed harvest in deep red, real customer names plus order and financial records for at least five named individuals.">
  <figcaption><em>Figure 5: The report's central inversion, in one view. Five remote-code-execution technique classes produced nothing, while every confirmed loss traces to a management interface someone left reachable.</em></figcaption>
</figure>

### 6.1 Eureka and XStream: engaged, outcome not evidenced

> **Analyst note:** This is the most complete attack sequence in the campaign, with a real target genuinely interacting with the operator's hostile server over several minutes. It is also the clearest example of why an attacker's own logs cannot be taken as proof of success.

A genuine multi-step protocol engagement occurred, spanning at least eight minutes of continuous interaction. The target registered a service named for a widely used API gateway component at an internal address, confirming it is a real Spring Cloud microservice deployment, polled the registry's delta endpoint repeatedly, then cleanly deregistered.

Across that window the operator swapped tool versions in real time while the target was already polling, running a three-stage escalation ladder on the same port:

1. An inert decoy server that serves a static application list and logs requests. It returns errors on write methods because it never overrides those handlers.
2. A verification tool whose default payload is a bare success-beacon request. It logged that it returned the deserialization payload eight times across the session.
3. The objective tool, with the same serving logic but a payload that downloads the staged web shell from the operator's own host.

All three share the same behaviour pattern: serve two legitimate application-list responses, then switch to the malicious payload on the third and subsequent polls.

The server's claim of what it sent is **not proof** of what the target did with it. The proof point would be the success callback, and the operator's own access log for the callback host, 17,087 lines covering roughly fourteen hours, contains zero matches for any of the three success-callback paths used across this campaign's exploitation classes.

**Confidence: MODERATE that the callback did not fire.** The honest gap is that the log window begins roughly 68 to 76 minutes after the engagement concluded, so a callback inside that earlier gap cannot be ruled out from the available files. This is not "remote code execution disproven". It is the strongest available negative evidence, and it should be read as exactly that.

A second evidence gap is self-inflicted and worth recording because it characterizes the operator. The objective tool's logging override contains a string-formatting defect that causes it to print literal placeholder text rather than the client address. Its logs therefore record that the malicious payload was served on the third, fourth and fifth requests, but cannot say which client received it. The only attributable addresses in those logs appear in connection-reset error traces, meaning clients that disconnected before completing a request. That is a permanent evidence gap created by the operator's own unfixed bug.

### 6.2 LDAP and JNDI: stalled at bind in both logged attempts

> **Analyst note:** The JNDI attack chain has two steps. The victim application first connects and authenticates to the attacker's directory server, then asks it for a specific entry, and the hostile code is delivered in the answer to that second step. Here the first step happened and the second never did.

Across the two attempts with full logging, the target connects, sends a real BER-encoded LDAP bind request, receives a bind response from the rogue server, and then the rogue server times out waiting for a search request and the connection closes.

The client bound but never issued the search request that would retrieve the malicious entry. The chain stalled before the payload could be delivered, in both logged attempts. This matters directly for the Logback JNDI payload in Section 5.1, which depends on the same completion step.

**Detection design point, and it is an important one.** Because the chain stalls after bind, the bind alone is the detectable event. A detection strategy that waits for a successful search would have missed this activity entirely. Any rule for outbound JNDI callbacks should fire on an LDAP bind request to a non-standard directory port from an application server, without requiring the follow-on search.

### 6.3 Brute force against a third platform: executed, defended successfully

A results file from a different target cluster is a clean outcome artifact. It records a password brute-force run reaching attempt seven of eight, receiving an HTTP 400 response with an account-lockout error and a vendor-specific error code, and the script stopping because of the rate limit.

Two facts separate cleanly here. The tooling was genuinely executed against a live production login endpoint, and the target's own rate limiting worked and stopped it. No successful login is shown or implied.

### 6.4 Management-endpoint probes against a fourth target: blocked cleanly

Six management-endpoint probes covering the environment, beans, conditions, configuration-properties, mappings and heap-dump endpoints all returned an identical custom-templated rejection with only the endpoint name substituted, carrying an HTTP 401 code and a message stating that authentication failed and the system resource could not be accessed.

This is not the framework's default error format. The target wraps its management endpoints in its own authentication filter, and that filter worked as intended across all six. Two further probes against upload and preview endpoints hit the same filter.

The methodological point is worth stating: mixed success against hardened management endpoints is the norm across this operator's target set, not the exception. Targets that closed their management planes were not compromised through them.

### 6.5 A second platform: authenticated access through a self-registered account, no confirmed theft

On `chengjiastore[.]cn`, the operator registered a real account. Registration and login both succeeded, and the returned token decodes to a real created account. A follow-on script then used that bearer token to enumerate administrative and system routes covering users, administration, orders, billing, configuration, system information and debug endpoints.

The register-then-authenticate-then-enumerate pattern is confirmed reused across at least two separate target platforms, which makes it a standing technique for this operator rather than a one-off. Four throwaway accounts are identified across the campaign, with tokens shared between scripts through a file on disk rather than each script re-authenticating.

**Status:** DEFINITE that the account registration succeeded, that the operator authenticated with the resulting token, and that administrative and system routes were then enumerated. No successful administrative access is recorded, and there is no confirmed data theft. Registration was open to the public by design, so characterizing this access as unauthorized is not itself an observation: it follows the HIGH (approximately 85 percent) conduct judgment in Section 2.2.

**Detection design.** An account registration followed within minutes by that same account's token probing administrative routes is a high-signal sequence, because ordinary new users do not visit administrative endpoints in their first session. This is one of the more transferable behaviours in the campaign and is covered by a published correlation rule.

### 6.6 Credentials the operator holds, and their status

Values are withheld from this report and from the IOC feed. Publishing a victim organization's live credential, even defanged, is a disclosure hazard rather than an intelligence contribution. What matters analytically is the status of each.

| Credential class | Status |
|---|---|
| A production database password on the confirmed-theft platform | Believed real and actively used, not a guess candidate. Embedded in the hex payload of a live raw protocol-smuggling handshake against an internal database address. Origin unresolved: it appears in none of the brute-force wordlists. |
| A cache password on the same platform | Believed real and actively used as a live credential in the server-side request forgery chain. A fragment appears twice in each of two heap dumps, the only credential with any memory footprint. |
| HTTP Basic Auth for an API documentation endpoint | Believed working, based on the operator's own annotation on a related endpoint. Not confirmed by any captured authenticated response. If genuine, it gives authenticated visibility into the complete administrative API surface. |
| An API request-signing key on a different target group | Confirmed cracked. Used directly and without further testing after a systematic seven-variant algorithm test, which implies the earlier signature-forgery effort succeeded. |
| An administrative password candidate | Used as a direct high-confidence login attempt. No confirmed success. The script is written to distinguish a definitive failure from a service-unavailable response, meaning the operator was waiting out a target outage rather than concluding the password was wrong. |
| The Quanzipin database `root` account | **Username only.** See Section 4.3. The password was not disclosed and there is no evidence the operator obtained it. |
| Six session tokens | Real-format tokens. Three decode to the operator's own throwaway accounts. One belongs to a system not otherwise mapped in this investigation. |

### 6.7 The outcome ledger

| Effort | What was built | What is evidenced |
|---|---|---|
| Customer-record harvest on the confirmed-theft platform | Four parallel sourcing pipelines | **CONFIRMED.** Names plus order and financial records for at least five named individuals |
| Identity-field decryption for one individual | Five successive key-hunting scripts | **NEGATIVE at HIGH confidence.** Roughly 54,000 attempts, zero successes |
| Eureka and XStream remote code execution | Three-stage server escalation ladder against a live polling target | **Not evidenced.** MODERATE that the callback did not fire; a timing gap remains |
| Logback JNDI remote code execution | Crafted payload plus rogue directory server | **Not evidenced.** The shared chain stalled at bind in both logged attempts |
| SnakeYAML deserialization | Crafted gadget document | **Not evidenced.** No callback recorded |
| SSRF to Redis to SSH key write | Complete working chain | **Attempted.** No confirmation of a successful write |
| Cloud metadata credential theft | Crafted multi-target payload | **Attempted.** No captured response |
| SMS account takeover of a staff account | 10,000 pre-built requests, armed | **Unconfirmed.** No execution or outcome artifact |
| Authenticated access on a second platform | Throwaway account plus route enumeration | **CONFIRMED.** Self-registered account authenticated and probed administrative routes; no confirmed data theft |
| Password brute force on a third platform | Brand-specific wordlist | **DEFEATED.** Target rate limiting stopped it at attempt seven of eight |
| Management-endpoint probing on a fourth target | Eight probes | **DEFEATED.** Custom authentication filter blocked all eight |
| Monitoring-console data-model capture | Direct unauthenticated retrieval | **CONFIRMED.** Full schema, endpoints and query set retained; no password disclosed |

The pattern in that table is the campaign's central lesson for defenders. Every confirmed loss came through a surface that was simply open. Every exploitation chain aimed at a software vulnerability either failed, was blocked, or produced no evidence of success.

---

## 7. Operator Infrastructure and Control Plane

The operator runs one host that does everything, wrapped in three independent and non-overlapping obfuscation choices. Consolidation on a single platform is why the exposure of one open port revealed the entire operation.

### 7.1 The platform

| Component | Detail | Confidence |
|---|---|---|
| Primary host | `192.3.1[.]116`, AS36352 (HostPapa), United States. Open directory on TCP/7777 served by a Python static HTTP server. | DEFINITE |
| Rogue directory server | `ldap://192.3.1[.]116:1389/cn=exploit`, backed by the operator's own directory-server scripts and setup tooling. | DEFINITE |
| Shared callback listener | TCP/9876, reused across otherwise unrelated exploitation classes: Eureka XStream, SnakeYAML and the JNDI chain. The operator runs a small reused listener set rather than one per technique. | DEFINITE |
| Success-beacon path | A dedicated path on TCP/7777, never observed hit. | DEFINITE |
| Staged payload URL | `hxxp://192.3.1[.]116:7777/cmd[.]jsp`, confirmed present and downloadable. Serves source only. | DEFINITE |
| Attack-traffic relay | `cs-pgcwufmiws[.]cn-hangzhou[.]fcapp[.]run`, a legitimate Alibaba Cloud Function Compute serverless endpoint reused as a proxy. Confirmed across two independent attack types against the same target. | DEFINITE |
| Operator VPN | Self-hosted SoftEther VPN on the same host, DDNS hostname `vpn932081317[.]softether[.]net`, still resolving to the platform address. | HIGH |
| Control-source address | `31.22.111[.]190`, the address the operator connects from to administer the host. Identical connection-environment values across two independent captures. Most likely shared rented proxy egress rather than operator-controlled infrastructure, so it is not an identity anchor and must not be used to cluster future activity (see the hosting assessment below). | HIGH that operator traffic originated here, MODERATE that the address is operator-controlled |
| Build-host identifier | An unmodified default SSH key comment referencing a budget VPS provider instance, shared across three distinct RSA-2048 key pairs with different fingerprints, and authoring the git clone records for the framework plugins. | HIGH |
| Control channel | A commercial messaging platform group chat with one identified controlling user, wired into an agent framework running as root on the host. | HIGH |


<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/multivector-ecommerce-rce-toolkit-192-3-1-116/multivector-operator-platform.svg" | relative_url }}" alt="Three-column grid infographic titled One Host, Five Roles, One Evasion Layer, arranged in rows of three, three and two. The first five cards describe what the single host ran. Three red cards: an open working directory on port 7777, a plain static file server that was publicly listable, which is why the outcome artifacts survived alongside the tooling, still serving as of 21 July 2026; a rogue directory server on port 1389 acting as the JNDI callback target for the Logback payload; and a shared callback listener on port 9876 reused across otherwise unrelated exploitation classes, indicating one listener set rather than one per technique. Two grey cards: a self-hosted VPN with a dynamic-DNS hostname resolving to the same address, described as operator convenience rather than victim-facing; and an agent framework running as root, off-the-shelf open-source software cloned from public repositories and driven from a consumer messaging platform, with execution of any attack explicitly unconfirmed. Three yellow cards describe the evasion layer: a proxied control source most likely shared rented proxy egress and therefore not an identity anchor; a serverless attack relay on legitimate cloud infrastructure confirmed across two independent attack types; and a budget hosting posture on a mainstream low-cost provider rather than bulletproof hosting.">
  <figcaption><em>Figure 6: The entire operation ran from one budget virtual private server. The three evasion elements are worth noting for what they are not: they do not connect to each other and none pivots to sibling infrastructure.</em></figcaption>
</figure>

**Hosting assessment.** AS36352 is not bulletproof hosting. It is a mainstream budget provider, assessed at HIGH confidence. The operator's control-source address sits on a small IP-leasing reseller network, and reverse resolution on it returned two hostnames whose numbered-node naming, privacy registration, regional DNS and CDN alias chain match the shape of a commercial proxy-subscription service. That reading is MODERATE, and it matters: it means the control-source address is most likely shared rented egress rather than operator-controlled infrastructure, so it should not be used as an identity anchor. Reverse-pivoting a shared proxy network returns other customers, which is a co-tenancy trap that produces false links.

**Three obfuscation choices that do not cluster.** The self-hosted VPN, the proxy egress and the serverless relay do not pivot to any sibling infrastructure and do not connect to each other technically. They read as three independent single-use decisions rather than a designed operational-security architecture.

**Operational tempo.** One host run continuously since at least April 2026 with no observed address rotation. A single SSH host-key rotation around 2026-01-01 reads as a rebuild or re-provision event. The directory was still live and growing as of July 21, 2026.

### 7.2 The agent framework, and a retraction that must be preserved

> **Analyst note:** An "agent framework" here means off-the-shelf software that lets a person drive an AI assistant which can run commands, browse, and use plugins. This operator installed a public open-source one on the attack host and controls it from a chat app. What it was used for is not established, and this report does not claim it ran the attacks.

The framework is **off-the-shelf open source**, not an operator creation. It is a publicly available agent project (identified in Reference 25) plus three public community plugins, cloned from public repositories by the same build identity that produced the operator's SSH keys. An earlier characterization of this as a novel operator-built framework is **retracted**, and it must not be reintroduced.

Two of the three plugins were independently verified as unmodified public clones. The third plugin's contents were not recovered.

What is established: the framework runs as root on the operator host under operator control, wired to a live messaging control channel with human-in-the-loop direction. Whether it ever executed an attack script is **UNCONFIRMED**. Nothing in the corpus shows it orchestrating any part of this campaign, and no such claim is made here. That question is fundamentally about host telemetry, which no public-research method can answer.

The framework use is also explicitly **not** an attribution signature. It appears in none of the characteristics used to scope the tracking designation in Section 10, precisely because commodity software that anyone can install distinguishes nobody.

For context rather than for this campaign's attribution: commodity agentic-AI adoption as a human-controlled operator console is an actively documented macro trend in 2026 threat-intelligence reporting, including examples using other named frameworks. This operator's particular combination of framework and actor tier was not found documented elsewhere, which should be read as no public reporting found, not as novel.

Note also that the public usernames appearing in the plugin repository records are the open-source plugin authors and are unrelated to the operator.

---

## 8. The Wider Target Landscape

> **Analyst note:** Beyond the two anchor targets, the operator touched roughly a dozen further entities. This section characterizes them by outcome rather than listing every asset, because most are reconnaissance-only and treating them as breaches would be wrong.

Roughly twelve to fourteen entities appear across five mapped corporate groups plus at least seven standalone or emerging threads. Outside the two anchors, every thread is attempted-only or reconnaissance-only. These are the assets of operating businesses, not blocklist entries, and none should be characterized as malicious.


<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/multivector-ecommerce-rce-toolkit-192-3-1-116/multivector-target-landscape.svg" | relative_url }}" alt="Process-tree infographic titled The Target Landscape, with the operator platform at 192.3.1.116 as the root node and six branches, each carrying a coloured side-rail indicating outcome. Branch A, deep red, a rent-to-own commerce platform with confirmed data theft: real names plus order and financial records for at least five named individuals, four independent sourcing channels, and an armed account-takeover weapon staged against a staff account that was never confirmed fired. Branch B, red, a construction-cost consulting platform with confirmed exposure: an unauthenticated database console disclosed a ninety-three-table schema, four hundred and twenty-seven endpoints, eight hundred and thirty SQL statements and the root username at time of capture, later found remediated, and it is the only target with a confirmed registered legal entity. Branch C, yellow, a four-product commerce group linked as sister products by shared frontend build artifacts, showing reconnaissance plus unconfirmed brute force and one confirmed information disclosure. Branch D, yellow, a second commerce platform where account registration, login and administrative-route enumeration occurred through a self-registered account with no successful administrative access and no confirmed data theft. Branch E, grey, insurance asset management and others including a ledger product, a dating platform, a mobile-OEM developer API and several unidentified probes, all attempted and none confirmed compromised. Branch F, grey, a loan-referral API with unresolved ownership where records were definitively returned but ownership and authenticity are insufficient, so no victim is named.">
  <figcaption><em>Figure 7: The full target set, colour-coded by what the evidence actually supports. Most branches are attempted rather than compromised, and the distinction between them is the discipline this report is built on.</em></figcaption>
</figure>

The target infrastructure concentrates on two large Chinese cloud providers with a common hosting-panel convention and recurring application-framework choices. That is commodity small and medium enterprise hosting, not a distinguishing single-broker pattern, and it should not be read as an infrastructure link between targets.

| Thread | Nature | Outcome status |
|---|---|---|
| Group A, a four-product sister estate covering device rental, an e-commerce mall, a consumer application and credit rental | The strongest infrastructure finding in the campaign. Linked by three independent evidence types: the operator's own labels, identical front-end production-build asset hashes across two administrative panels, and a live TLS certificate on the host the operator itself labelled as the main server. None of this depends on trusting the operator alone. | Recon, a four-phase kill chain, unconfirmed brute force, SQL injection routed through the serverless relay, and one confirmed information disclosure: uncaught framework routing exceptions leaked an internal deployment codename on five of thirteen probed routes during an automated discovery burst. No confirmed compromise. |
| Group C, a cluster spanning a ledger application, a store platform and a matchmaking platform | Confirmed as one cluster by a password list pairing candidates from all three brands against the same login endpoint. | Brute force, rate-limited and stopped. A phishing lure image. A planned but unattempted next password round. No confirmed compromise. |
| Group E, an insurance asset-management firm | Refined from a generic finance classification through the corporate portal's own footer links to the national financial regulator and the insurance asset-management association. The public application is a conference-booking system. | Attempted only. The evidence for controls holding here is **substantially silence** rather than a positive defensive result: eight of twelve captures are session-cookie churn with no recorded outcome. Login and injection attempts show clean rejections, and one probe triggered an unhandled server error, which is a stronger signal but not conclusive. A second, properly protected Druid instance was found here, which is useful negative evidence. |
| A mobile-OEM developer platform | A major smartphone manufacturer's developer API, fuzzed across 31 by 31 service and method combinations, plus two JavaScript secret-hunting scripts against downloaded bundles. | Attempted, no captured outcome. Three application pulls were blocked at what appears to be a content-delivery layer. **That attribution is apparent rather than confirmed:** the source URL that would identify which control blocked them was never captured. |
| A cross-platform token-replay target | Reached by replaying a token obtained from an unrelated platform under four different header names. | Relationship and outcome unresolved. |
| Standalone and emerging threads | An unnamed messaging-platform mini-program referenced only in code comments; a legacy PHP-framework host disclosing a full hosting-panel server path through verbose stack traces; a live-probed enterprise mail deployment whose operating organization is unidentified; a sustained single-target effort against a platform that was never identified; a loan and credit referral affiliate platform; and four unidentified web probes. | Attempted or reconnaissance only. Several unidentified. |

### 8.1 The loan-referral finding, with its ambiguity front and centre

A captured response from a cash-loan referral-commission backend returned a genuine paginated set of personally-identifying records and self-reported 70,859 records system-wide. Roughly twenty individual records appear in the captured page. The system-wide figure is the response's own claim, not a captured extraction.

**DEFINITE:** records were returned to a client.
**INSUFFICIENT:** ownership, and record authenticity.

The capture carries a logged-in session and no corresponding request was recorded, so an operator authenticating to their **own** lead-generation backend cannot be distinguished from a breached third party, and this operator runs several loan and affiliate-marketing threads. Independent threat-intelligence reporting on this ecosystem also documents that loan-referral customer lists are frequently recycled between brokers or fabricated outright, so the record count cannot be assumed to represent 70,859 distinct real people.

No victim is named. No record content is reproduced. The residential submitter addresses and personal records inside that response are personal data and are excluded from the IOC feed as non-indicators.

### 8.2 What the ecosystem context adds

The target mix, installment and rent-to-own commerce, credit rental, loan referral and recruitment, is structurally close to the documented Chinese grey-market personal-data-to-fraud ecosystem described in published research from multiple vendors. That is a useful placement of the **actor class**. It is not attribution, and Section 10 treats it accordingly. Targeting alone is the single most common route to a wrong actor name, and this target profile is shared by a large and diffuse population of operators.

### 8.3 The content-provider filing signal, hedged and single-source

None of four checked target domains returned a content-provider filing. Mainland-hosted sites legally require one, so its absence is a signal that several of these may be unregistered platforms, and it explains why there is no publicly registered legal entity to name for most of them.

This is **MODERATE confidence and single-source**. The check ran against a commercial lookup service, not the official national registry, and neither this nor any prior stage queried the official registry directly. Three innocent explanations remain fully open: the filing may sit under a parent or corporate domain while these are product domains; there may be a filing lag; or a platform may be non-compliant while otherwise operating legitimately.

**No target named in this report is asserted to be a grey-market operator on this basis.** The absence of a filing is a signal, not a finding, and it is not load-bearing for any conclusion in this report.

---

## 9. MITRE ATT&CK Mapping

Thirty-six techniques map across eleven tactics, and the attempted-versus-achieved split is carried inside the table rather than flattened out of it. That is why the per-row confidence column is retained here.

| Tactic / Technique | Name | Conf. | Evidence |
|---|---|---|---|
| Reconnaissance / T1595.002 | Vulnerability Scanning | HIGH | Actuator, Druid, Swagger and Nacos surface enumeration |
| Reconnaissance / T1595.003 | Wordlist Scanning | HIGH | 16-subdomain sweep plus common admin/login path probes |
| Reconnaissance / T1596.005 | Scan Databases | DEFINITE | Commercial reconnaissance-service subdomain enumeration |
| Reconnaissance / T1596.003 | Digital Certificates | DEFINITE | Certificate-transparency subdomain discovery |
| Reconnaissance / T1593.002 | Search Engines | DEFINITE | Site-scoped search queries; one hit bot detection |
| Reconnaissance / T1594 | Search Victim-Owned Websites | DEFINITE | JS bundle mining for base URLs, routes and secrets |
| Resource Development / T1583.003 | Virtual Private Server | DEFINITE | `192.3.1.116` on AS36352; budget-VPS build host |
| Resource Development / T1583.006 | Web Services | DEFINITE | Serverless function endpoint reused as attack relay |
| Resource Development / T1585 | Establish Accounts | DEFINITE | Four throwaway accounts self-registered on targets |
| Resource Development / T1588.002 | Tool | HIGH | Decompiler intact; two exploitation tools arrived broken |
| Resource Development / T1608.001 | Upload Malware | DEFINITE | `cmd.jsp` staged and downloadable on TCP/7777 |
| Initial Access / T1190 | Exploit Public-Facing Application | DEFINITE (attempted) | Logback, SnakeYAML, XXE, Eureka XStream, UNION SQLi. No success artifact for any (see §6) |
| Initial Access / T1078 | Valid Accounts | HIGH | Live-used database and cache credentials; cracked signing key. Also serves Privilege Escalation |
| Initial Access / T1566 | Phishing | MODERATE | Session-expiry lure image; no harvesting page recovered |
| Execution / T1059.004 | Unix Shell | DEFINITE | Web-shell `/bin/bash -c`; 10,000 pre-built shell requests |
| Execution / T1059.006 | Python | DEFINITE | The entire operator attack-script corpus |
| Persistence / T1505.003 | Web Shell | DEFINITE (staged) | `cmd.jsp` plus a FileAppender write route. **UNCONFIRMED on any victim host** |
| Persistence / T1098.004 | SSH Authorized Keys | HIGH (attempted) | SSRF-to-Redis chain writing operator pubkey to `/root/.ssh/authorized_keys` |
| Defense Evasion / T1090.002 | External Proxy | DEFINITE | Serverless relay used for SQLi and login probing |
| Defense Evasion / T1572 | Protocol Tunneling | HIGH | Self-hosted SoftEther VPN with an operator-chosen DDNS name |
| Defense Evasion / T1036 | Masquerading | MODERATE | `redteam*` / `pentest_*` naming; no authorization evidence exists |
| Credential Access / T1110.001 | Password Guessing | DEFINITE | 10,000-request 4-digit code space; 22 database guesses; 14-password cache sweep |
| Credential Access / T1110.003 | Password Spraying | HIGH | Brand-specific lists against two login endpoints; one run rate-limited |
| Credential Access / T1552.001 | Credentials In Files | HIGH | Environment-endpoint sweep testing every 8 to 64 character value as key material |
| Credential Access / T1552.004 | Private Keys | MODERATE (attempted) | `file://` read attempts of `/root/.ssh/id_rsa` |
| Credential Access / T1552.005 | Cloud Instance Metadata API | DEFINITE (payload) | XXE entity to `169.254.169.254/latest/meta-data/`. Outcome UNCONFIRMED |
| Credential Access / T1606.001 | Web Cookies | HIGH (attempted) | Forged admin-role token: HMAC brute force plus an `alg:none` variant |
| Discovery / T1046 | Network Service Discovery | DEFINITE | Full 65535-port `-T5 --min-rate 10000` sweep; 14-port management-plane profile |
| Discovery / T1518 | Software Discovery | HIGH | Framework and version fingerprinting across targets |
| Collection / T1213 | Data from Information Repositories | DEFINITE | Unauthenticated Druid console: 93-table schema, 427 endpoints, 830 SQL statements |
| Collection / T1119 | Automated Collection | DEFINITE | Harvest pipeline scaling to 30 real users per run, plus a retained record of a completed run |
| Collection / T1005 | Data from Local System | HIGH | Three Java heap dumps retrieved and mined for identifiers and key material |
| Command and Control / T1071.001 | Web Protocols | DEFINITE | HTTP callbacks on 7777 and 9876; rogue LDAP on 1389 |
| Command and Control / T1102.002 | Bidirectional Communication | HIGH | Messaging-platform-controlled agent framework running as root |
| Command and Control / T1105 | Ingress Tool Transfer | DEFINITE | XStream payload downloads the staged web shell over HTTP |
| Impact / T1531 | Account Access Removal | MODERATE (attempted) | Armed SMS reset of a real staff account; success unconfirmed |

### 9.1 Three mappings worth expanding

**T1119, and why it is DEFINITE rather than MODERATE.** Most of this campaign is capability without evidenced outcome, and this technique is the exception. The distinguishing artifact is not the harvesting script but the operator's own retained dictionary mapping five real user identifiers to real personal names, commented as the known set from an earlier run. That is a record of a completed extraction, corroborated independently by live order identifiers recovered from heap memory.

**T1531, and why it stays MODERATE.** The account-takeover weapon is complete, pre-staged and immediately executable against a specific real staff account, with the replacement password written into all 10,000 requests. Nothing in the corpus shows whether it was fired or whether it succeeded. Rating it higher on the strength of how ready it looks would be exactly the failure mode this investigation's three adversarial review passes existed to correct.

**T1552.005, and why the payload matters more than the outcome.** Reaching a cloud provider's instance metadata service through server-side request forgery is the technique class behind the Capital One breach. Even unconfirmed, the presence of a correctly constructed metadata entity alongside three internal-service entities in one document demonstrates real understanding of server-side request forgery impact, in a toolkit whose quality is otherwise uneven.

### 9.2 Deliberate coverage gaps

**Exfiltration (TA0010) is not mapped.** ATT&CK's exfiltration techniques presuppose data leaving a compromised host through a channel the adversary controls. Here the operator pulled data directly out of victim APIs over the victims' own HTTP interfaces, using valid or forged tokens and exposed management endpoints. The Collection techniques above describe that correctly. Forcing a T1041 or T1567 mapping would misrepresent the mechanism.

**Lateral Movement (TA0008) is not mapped.** No artifact shows movement between hosts inside any target environment. The internal addresses observed were reached from outside through server-side request forgery and protocol smuggling, not by pivoting from a foothold.

**No Impact technique beyond T1531.** There is no ransomware, no wiper, no destruction, no defacement and no service disruption anywhere in the corpus. The objective is data, not damage.

---

## 10. Threat Actor Assessment

> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-2026-019 is an internal tracking designation assigned by The Hunters Ledger to actors observed across analysis who cannot yet be linked to a publicly named threat group. This label will not appear in external threat intelligence feeds or vendor reports, it is specific to this publication. If future evidence links this activity to a known named actor, the designation will be retired and updated accordingly.

No named threat actor can be attributed to this activity, and the reasoning behind that failure is itself worth publishing, because four separate attribution dimensions are not merely thin here, they are structurally empty.

**Threat Actor:** Unknown.
**Confidence:** INSUFFICIENT (approximately 15 percent).
**Why this confidence:** every dimension that could produce a name is empty. Zero infrastructure overlaps across four independent checks. No code to compare. Commodity techniques that cannot cluster. No vendor or government attribution. The only evidence pointing at an operator identity consists of unresolved fragments whose resolution paths require law-enforcement or platform cooperation.
**What is missing:** any link, of any strength, between an operator artifact and a catalogued entity.
**What would increase confidence:** resolution of the build-host identifier against historical SSH host-key scan data; resolution of the messaging-platform identifiers through platform cooperation; or recurrence of this operator's account-naming convention and log-verbosity harvesting technique in an unrelated future investigation, which would let the operator be tracked as a consistent entity even while unnamed.

The correct phrasing throughout is that **no public reporting was found**. This report does not use the words undocumented, novel, or previously unknown actor, because those claim knowledge about the world while the evidence supports a claim only about four catalogs.

### 10.1 Why each attribution dimension is empty

**Infrastructure overlap: zero, across four checks, three of them independently re-run.** The operator platform returns zero related threat actors at VirusTotal, re-verified live during this investigation, and zero rows in the Hunt.io indicator feed. The Hunt.io threat-actor catalog was re-queried directly at the attribution stage and returns no actor association for either operator-side address, no indicator-feed rows for the operator platform, and no catalog match for the activity profile. That catalog does independently record the operator directory as a malicious open directory, observed on 2026-06-03, which corroborates the finding itself while attributing it to nobody. One check remains carried forward rather than re-run: the TLS-fingerprint reverse-pivot. The control-source address likewise returns zero related threat actors, with two generic vendor flags carrying no actor or campaign label, which is the signature of routine abuse listing. Neither operator-side address has a historical certificate record. A corpus search for the build-host identifier returns zero results. This is not thin overlap. It is complete absence of the dimension.

**TTP clustering: structurally unavailable.** All eight exploitation techniques are drawn from the well-documented public record with mature proof-of-concept code. Commodity techniques cannot cluster to an actor, because their availability to everyone is what makes them commodity. The two genuinely characteristic behaviours in this corpus, the log-verbosity harvesting technique and the register-a-throwaway-account-for-a-token technique reused across targets, are distinctive enough to serve as a tracking signature for this operator but match no reported actor's documented tradecraft.

**Code similarity: not applicable.** There is no malware in this campaign. No implant, no loader, no packer, no custom protocol, no persistence binary. There is nothing to compute a similarity percentage against, and no such percentage appears anywhere in this report.

**Vendor and government attribution: none.** No Tier 1 or Tier 2 source names an actor.

**The most likely explanation for the absence** is a catalog coverage gap rather than a genuinely unreported operator. Vendor catalogs are built around actors who cause reportable incidents at organizations that engage incident responders. An individual or very small crew harvesting personal data from small consumer platforms in one country generates neither.

### 10.2 State nexus: assessed and rejected

Nothing in this corpus supports a state nexus. **Confidence that this is not state-sponsored activity: HIGH (approximately 90 percent).**

This needs saying plainly, because a reader who sees "Chinese-language operator" beside a long exploitation-technique list may reach for a state framing unprompted. The operator's own labels, comments and target annotations are in Chinese and the targets are Chinese platforms. That supports a language and regional-orientation assessment. It supports nothing whatsoever about sponsorship, and conflating the two is one of the most common attribution failures in published reporting.

Six positive counter-indicators, not merely the absence of state indicators:

1. **Target selection is strategically worthless.** Rent-to-own consumer commerce, a matchmaking platform, credit rental, loan referral, a recruitment site. There is no government, defence, critical-infrastructure, technology-transfer or dissident-tracking target anywhere in the corpus.
2. **The targets are domestic.** A mainland-Chinese-oriented operator working almost exclusively against mainland Chinese small consumer platforms is directionally wrong for state-sponsored external collection, and the harvested material is monetizable rather than intelligence-bearing.
3. **The tooling is entirely commodity.** Eight documented public techniques, no zero-day, no bespoke implant, no custom protocol, no anti-analysis engineering.
4. **The infrastructure is budget-tier.** A low-cost virtual private server, an open directory left publicly listable, consumer proxy egress, a free dynamic-DNS hostname.
5. **The control channel is a consumer messaging account.** Live human-in-the-loop control through a personal account and group chat on a commercial platform is the operational security of an individual, not of a program.
6. **The outcome is personal data with resale value**, harvested individual by individual, with a persistent named-individual catalogue.

### 10.3 Sophistication: two bands, reported separately

Averaging this operator's capability into one label would misdescribe the threat in both directions, so the two bands are reported separately. **Confidence: HIGH.**

**The capable band, technique selection and chaining.** Chaining server-side request forgery into an in-memory data store's configuration commands to write a key into a privileged account's authorized-keys file requires understanding three systems and the seam between them. Smuggling a raw database client handshake through a gopher-scheme request is uncommon and was correctly constructed. Deriving and using a request-signing scheme, and forging tokens in two independent ways, shows genuine competence. Four independent sourcing channels converging on one target's customer data shows planning rather than opportunism. And above all, elevating an application's log verbosity through a management interface in order to manufacture the data the operator then harvests is not a published exploit chain, it is the operator reasoning about how to make a target produce what they want.

**The weak band, execution and operational discipline.** The operator's own working directory was left publicly listable on a non-standard port, and that single failure is why any of this is known. Downloads arrived broken. Zero-byte files were saved under names implying real content. A paid reconnaissance-service subscription key sits hard-coded in clear text. Working scripts carry unfixed defects, one of which permanently destroyed the operator's own evidence of who received a payload. Nothing is compartmentalized: keys, tokens, harvested data, working notes and environment captures all sit in one place. Several attack chains are left unresolved with no captured outcome and no follow-through.

**The read:** a capable consumer of public offensive technique with real chaining ability and poor operational discipline. This is consistent with a self-taught individual working from public research and inconsistent with a trained team operating to a standard. A long technique list assembled from public sources measures effort, not capability. The log-verbosity manipulation is the item that genuinely demonstrates capability, and it should carry that weight rather than the list length.

### 10.4 Solo operator versus small crew

**Assessment: a single operator is more likely than a small crew, but the distinction is not cleanly resolvable. Confidence: MODERATE (approximately 65 percent solo).**

For solo: one build environment produced all three key pairs with an unedited default comment; one identity authored the framework clone records; one control source is consistent across two independent captures; one continuous agent session appears in both captures; one controlling user is identified on the control channel; the account-naming series is a single sequential habit; and the unevenness of execution quality is uniform, where a crew usually shows at least two distinguishable standards of work.

For a small crew: the control channel is a group rather than a direct conversation; the target breadth and per-target tooling volume represent substantial working hours; and the account-naming series has a numbering gap.

The group-chat observation is weak, since single-participant groups are entirely normal for bot control, and it is the only artifact pointing to more than one person. The distinction does not change the risk to any defender.

### 10.5 Geographic and language orientation

**Assessment: a Chinese-language operator working against mainland Chinese platforms. Confidence: HIGH for the language and target orientation, MODERATE for the operator's own regional location.**

Supporting the language and orientation finding: the operator's own working labels, script comments and target annotations are in Chinese; brand-derived and pinyin-derived password guesses require familiarity with the target brands; the target set is near-exclusively mainland Chinese consumer platforms; and the control-source resolution pattern points at a proxy service sold into the Chinese consumer market.

Limiting the location finding to MODERATE: the platform is US-hosted, the control source is registered in the RIPE region, and the operator routes through proxy infrastructure by design, which is exactly the circumstance in which network-derived location assessments fail. Hosting jurisdiction is a purchasing decision and is **never stated here as operator nationality**. Language and targeting carry the regional assessment, and both language and targeting can be adopted.

### 10.6 What UTA-2026-019 is scoped to track

The designation is scoped to the **operator**, meaning the build environment and the platform, not to the toolkit. The toolkit is commodity and would false-match unrelated operators.

Five characteristics support the designation, three of them technical or infrastructure-based:

1. **Build-environment fingerprint.** One unmodified default key comment across three distinct key pairs and the framework clone records, tying key material and tooling deployment to one named build host.
2. **Operator platform composite.** A publicly listable working directory on a non-standard port, a rogue directory-service listener, a shared exploitation callback port, a self-hosted VPN with an operator-chosen instance identifier, and a root-privileged agent framework, all on one host.
3. **Technique composite.** Log-verbosity elevation through an exposed management interface to manufacture harvestable data and then read it back; register-a-throwaway-account-for-a-token reused across targets; and a serverless cloud function reused as an attack relay across two independent attack types.
4. **Account-naming series** reused across two unrelated target platforms and mirrored in private tooling filenames. Only the cross-target reuse pattern is distinctive, not the vocabulary itself.
5. **Targeting profile.** Mainland Chinese small and medium consumer platforms in installment and rent-to-own commerce, credit rental and loan referral, with personal-data harvest as the objective.

Future matching should anchor on characteristics one and three, which are infrastructure-independent and survive a rebuild or a takedown. The control-source address is deliberately **not** a defining discriminator, because it is probably shared proxy infrastructure. It is carried as a contextual indicator and as a victim-side log search term, with the co-tenancy caveat attached.

---

## 11. Risk Assessment

**Overall risk score: 7.2/10. Threat level: HIGH.**

### 11.1 Risk dimensions

<table>
<colgroup>
<col style="width: 30%;">
<col style="width: 12%;">
<col style="width: 12%;">
<col style="width: 46%;">
</colgroup>
<thead>
<tr><th>Dimension</th><th>Score</th><th>Weight</th><th>Rationale</th></tr>
</thead>
<tbody>
<tr><td>Data exfiltration</td><td>8/10</td><td>30%</td><td>Confirmed harvest of customer names and order/financial records for at least five named individuals, through four independent sourcing channels against one platform. A separate response returned roughly twenty personally-identifying records from a backend claiming far more system-wide, but its ownership and record authenticity are unresolved.</td></tr>
<tr><td>Account compromise</td><td>7/10</td><td>25%</td><td>An armed, pre-staged verification-code brute force against a real staff account with a chosen replacement password. Authenticated access to a second platform through a self-registered account, followed by administrative-route probing, with the unauthorized characterization following the HIGH conduct judgment in Section 2.2 rather than standing as a separate confirmed finding. Live-used database and cache credentials on a third surface. Outcomes for the reset and the administrative login are unconfirmed.</td></tr>
<tr><td>Scale of targeting</td><td>8/10</td><td>20%</td><td>Roughly five mapped corporate groups plus at least seven standalone or emerging threads, spanning e-commerce, device and credit rental, gig work, insurance asset management, loan referral and a mobile-OEM developer platform. No client separation of any kind.</td></tr>
<tr><td>Operator persistence and tempo</td><td>7/10</td><td>15%</td><td>The platform was still live and growing at the close of analysis, run continuously since at least April 2026 with no address rotation. Operator access observed across a multi-week span. A VPN and a serverless relay in place for source obscuration, plus an always-on control channel.</td></tr>
<tr><td>Remote code execution</td><td>4/10</td><td>10%</td><td>Genuine crafted payloads across five vulnerability classes, but no evidenced success for any of them. For two of the five, the strongest available evidence points the other way.</td></tr>
</tbody>
</table>

Two dimensions are recorded but **excluded from the weighted average**, because scoring them as near-zero drags would produce a MEDIUM label that materially understates confirmed theft of identifiable records. They are stated openly rather than hidden:

- **Lateral movement: 2/10.** No artifact shows movement inside any target environment. The internal addresses observed were reached from outside through server-side request forgery and protocol smuggling, not by pivoting from a foothold.
- **Destructive impact: 1/10.** None observed and none built.

These two are structurally inapplicable to an external, API-centric data-theft operation with no implant. Including them at equal weight would score the absence of a capability this threat class does not have.

### 11.2 Why HIGH and not CRITICAL

The case for CRITICAL is real: confirmed theft of identifiable personal and financial records belonging to named individuals, an armed account-takeover weapon aimed at a staff account, live-used database and cache credentials, roughly a dozen targeted organizations, and an operator platform still live at the close of analysis.

Three things hold it at HIGH.

**The harm is bounded by evidence rather than by assumption.** Five of the six efforts that left an outcome artifact are negative, among them the HIGH-confidence failure of the decryption effort against one individual's phone number and government identity number. Section 6 sets out each of the five with its evidentiary limits stated.

**Confirmed theft is scoped to one platform and at least five named individuals**, not to a population. The fuller identity field set is highly likely, not confirmed.

**No destructive capability exists anywhere in the corpus.** No ransomware, no wiper, no disruption. The objective is data.

### 11.3 What is at risk for an affected organization

**Customer identity and financial records.** Names, order and installment histories, and, on the platform where the harvest is confirmed, the identity-verification records that back them.

**Staff account control.** The reset weapon targets a staff or operator account type rather than a customer account. A staff takeover converts an external data-theft problem into an internal one, with access to whatever that role can see across all customers.

**The complete data model.** Where a monitoring console was exposed, the actor retains the full schema, the API surface and the business logic even after the console is closed. That knowledge does not expire when the port does, which is why credential rotation stands as a precaution even where no password was disclosed.

**Downstream exposure.** Emergency-contact fields inside identity-verification records mean third parties who never transacted with the platform sit inside the targeted data set.

### 11.4 Spread and current status

Spread capability is low. This is an external, API-centric operation. It exploits internet-facing management surfaces and authentication weaknesses. It does not carry implants, does not move host to host, and leaves nothing behind on victim systems except, potentially, an unconfirmed web shell.

**Status: active.** The operator directory was still live and growing as of July 21, 2026, and a hosting-provider takedown request had been filed but not actioned. Any blocklist entry for this platform should therefore be treated as perishable tradecraft rather than as durable coverage. The exposure classes the operator hunts, unauthenticated monitoring consoles, unrestricted management interfaces, verbose production stack traces, enumerable structured identifiers and four-digit verification codes, are widespread and are not specific to any organization named here.

---

## 12. Indicators of Compromise and Detection Coverage

Full machine-readable indicators are published separately in the [IOC feed](/ioc-feeds/multivector-ecommerce-rce-toolkit-192-3-1-116-iocs.json). Detection rules are published separately in the [detection rules file](/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/). Neither is reproduced here.

### 12.1 What the feed contains, and what it deliberately does not

The feed carries operator infrastructure (addresses, hostnames, callback URLs, ports), operator attribution artifacts (a build-host identifier, SSH key fingerprints, throwaway account names, messaging identifiers, a session identifier), operator file and path artifacts, behavioural indicators with log-source mappings, exploitation-payload signatures, and a separately structured target-asset list.

**It carries no file hashes**, for the reason given in Section 2.1.

Four categories present in the underlying evidence are deliberately excluded from both this report and the feed, recorded here so downstream consumers know they exist and were withheld rather than overlooked:

1. **Believed-real target credentials.** Database, cache, administrative and API-signing credentials belonging to victim organizations. Publishing them, even defanged, is a disclosure hazard rather than an intelligence contribution.
2. **The operator's live reconnaissance-service subscription key, and every raw session token in the corpus.**
3. **All victim personal data.** No customer or employee names, phone numbers, national identity numbers, order records, loan-applicant records, or their submitter addresses.
4. **Post-discovery crawler and scanner traffic.** Several cloud-provider addresses mass-downloaded every file in the open directory in tight repeating clusters after it was discovered, one of them accounting for 1,379 requests alone. That is researcher and scanner noise, and the feed marks it explicitly as non-indicators.

The feed also carries a `targeted_assets` structure listing victim-side and target-side assets **for correlation only**. Those are the assets of operating businesses. They are not blocklist entries and none should be characterized as malicious.

### 12.2 Published detection coverage

Coverage is behavioural and payload-class based, because there is no malware family to signature.

| Rule type | Detection tier | Hunting tier | Focus |
|---|---|---|---|
| YARA | 5 | 0 | Exploitation payload files recoverable from an upload directory, temp path or incident |
| Sigma | 5 | 7 | Behaviour visible in web access logs: management-interface abuse, unauthenticated console access, heap-dump retrieval, registration-then-probe, code brute force, scan profile |
| Suricata | 11 | 2 | Network traffic: JNDI callbacks, gadget chains and SSRF payloads in transit, forged tokens, registry poisoning |

No rule in the published set encodes this operator's address, hostnames or account names. Those are atomic indicators and they live in the feed. A rule pinned to `192.3.1[.]116` dies with the takedown that is already filed, while the techniques outlive the infrastructure.

### 12.3 The highest-value hunting targets

Ordered by durability rather than by how much this specific operator used them.

1. **A Jolokia or JMX write that changes a logging level, followed within minutes by a read of the application log-file endpoint.** The highest-fidelity signal in the campaign and the most under-instrumented. Section 3.3.
2. **Any HTTP 200 on an Alibaba Druid console path from an external source.** Do not anchor the rule to ports 80 and 443.
3. **A successful external retrieval of a Java heap dump**, detected on success with a large response body rather than on the request alone. Internal performance-monitoring and support tooling also retrieves heap dumps routinely, so a retrieval from an internal source is the expected benign case.
4. **Many requests to a verification or password-reset endpoint sharing one constant verification-context token while a short numeric field iterates.**
5. **An account registration followed within minutes by that account's token probing administrative routes.**
6. **An outbound LDAP bind request to a non-standard directory port from an application server, with no search request following.** The stall is the event, and waiting for the search would miss it.

### 12.4 Acknowledged coverage gaps

Four categories in this campaign are not detectable from a third-party network or log-telemetry perspective, and the published detection file states them rather than implying coverage that does not exist.

A session token signed with a correctly guessed secret is byte-for-byte indistinguishable from a legitimately issued one at the network layer. Detecting that requires the issuing application to log signing-key usage or to reject known-weak default secrets outright.

Verbose framework exception disclosure is a real defensive-hygiene signal, but standard access-log telemetry captures status codes and byte counts rather than response bodies, and a bare status-code selection would be far too broad to publish.

Structured record-identifier enumeration confirms the underlying platforms use predictable identifiers, but the exact format is platform-specific. A platform operator is better positioned to rate-limit or randomize its own identifiers than a third-party feed is to signature them.

Reused valid credentials produce traffic indistinguishable from their legitimate owner's.

---

## 13. Confidence Summary, Gaps and Calibration

In a corpus that is overwhelmingly capability rather than outcome, the difference between what an operator built and what an operator achieved is the entire intelligence value. This section records where that line sits.

### 13.1 Confidence by finding

This table indexes findings by confidence level rather than re-arguing them. Section 6 owns the evidence behind the bounded negatives, so the rows below carry the confidence label and its limiting condition without repeating the underlying artifacts.

| Finding | Confidence |
|---|---|
| Customer names plus order and financial records harvested for at least five named individuals | DEFINITE |
| Fuller identity fields (national identity number, email, emergency contacts) also obtained | HIGH, not confirmed by any captured response |
| Unauthenticated Druid console exposed a full production data model at time of capture | DEFINITE |
| That console disclosed the database password | Explicitly NOT the case. Username, connection details and schema only |
| That console now appears remediated | HIGH, based on a read-only re-check finding the host NXDOMAIN and the port closed |
| Log-verbosity elevation tooling exists and is written to manufacture harvestable data | DEFINITE |
| That specific technique produced the confirmed harvest | MODERATE. It is the mechanism that best explains an already-confirmed finding |
| An armed account-takeover weapon is staged against a real staff account | DEFINITE that it is armed. UNCONFIRMED that it was fired or succeeded |
| Account registration, authenticated login and administrative-route enumeration on a second platform | DEFINITE. No successful administrative access and no confirmed data theft there. Registration was public and self-service, so the unauthorized characterization of that access follows the conduct row below at HIGH, not this row |
| Identity-field decryption for one individual failed | HIGH as a negative result |
| Eureka XStream remote code execution did not fire | MODERATE, with a stated timing gap in the log window |
| JNDI chain stalled at bind in both logged attempts | DEFINITE for the two logged attempts |
| Web shell deployed to any victim host | UNCONFIRMED. It exists only in the operator's own directory |
| Conduct is unauthorized and malicious rather than authorized testing | HIGH (approximately 85 percent) |
| Attribution to any named threat actor | INSUFFICIENT (approximately 15 percent) |
| Activity is not state-sponsored | HIGH (approximately 90 percent) |
| Chinese-language operator working against mainland Chinese platforms | HIGH for language and targeting, MODERATE for operator location |
| Single operator rather than a small crew | MODERATE (approximately 65 percent) |
| Loan-referral API ownership and record authenticity | INSUFFICIENT. Records were definitely returned to a client |
| Content-provider filing absence as a grey-market signal | MODERATE, single-source, not load-bearing |

### 13.2 Assumptions that would change the picture if wrong

Three assumptions carry real weight, and each is stated so a reader can discount the analysis appropriately.

**All identity artifacts belong to one continuous operator.** The build-host identifier, control source, account-naming convention and messaging identifiers are treated as one party. Supporting that: three key pairs share one build environment, the same identity authored the framework clone records, the control source is identical across two independent captures, and one continuous session appears in both. Against it: a resold or shared virtual machine image would reproduce a build-host comment across unrelated users, and the control source is probably shared proxy infrastructure. Net effect, the single-operator reading is well supported for the platform-side artifacts and weaker for the control source, which is why the control source is not used as an identity anchor.

**The commercial lookup service used for the filing check is a reliable proxy for the official registry.** If it is not, that signal moves toward INSUFFICIENT. Nothing in this report depends on it.

**The agent framework never executed an exploitation script.** If that assumption is wrong, the classification would shift materially from an operator-scripted commodity-technique campaign to an AI-assisted exploitation campaign, which 2026 vendor reporting treats as a distinct and more advanced threat category. This is fundamentally a host-telemetry question that no public-research method can answer, and no claim is made in either direction.

### 13.3 Gaps in the evidence

The single highest-value missing artifact investigation-wide is an access log covering the callback listener during the JNDI engagement window. It would close the remote-code-execution outcome question that three separate techniques share. An earlier rotation of the operator's own web-server log would similarly close the timing gap in the XStream negative.

Further gaps, recorded rather than papered over: no captured output from the decryption effort showing a success line; no captured authenticated response proving the API documentation credential works; no confirmation of whether the staff account's password was actually reset; no business-registry resolution of the confirmed-theft platform's operating entity; and no recovery of the third framework plugin's contents, which bears directly on whether the framework ever executed anything.

On the attribution side: the JARM/JA4X reverse-pivot was not re-queried, so one of the four infrastructure-overlap checks in Section 10.1 is carried forward from the investigation baseline rather than independently re-run. The threat-actor-catalog check was re-run directly and returned no association, which is why the attribution conclusion no longer rests on a carried-forward absence. A second signal is worth recording for what it does not settle: that catalog does not classify the operator's control-source address as a commercial VPN or proxy service. That is weak evidence against the shared-egress reading in Section 7.1, but a small regional subscription service would not be expected to appear in a VPN-detection dataset, so the MODERATE assessment there is unchanged in either direction. The build-host identifier was never checked against historical SSH host-key scan data, which remains the strongest unperformed technical pivot. The messaging-platform control-channel identifiers were deliberately not pivoted, since doing so requires platform cooperation or channel interaction, both out of scope. Marketplace and data-trading presence was never investigated, and it would be the strongest independent corroboration available for the actor-class placement. And no targeted platform was contacted to confirm the absence of an engagement, which is the single cleanest test of the authorization question and is structurally unavailable to a third-party intelligence provider.

Several targets remain unidentified: a sustained single-target effort whose subject was never resolved, an enterprise mail deployment, an API gateway, and four unattributed web probes.

### 13.4 Calibration record

Three adversarial review passes were run over these conclusions before this report was written, and each retracted material overclaims. The retractions are published rather than quietly absorbed, because a reader has no way to assess calibration discipline that is invisible.

- A monitoring-console exposure was re-attributed to the correct platform. A second platform in the same thread has no confirmed exposure of its own.
- A novel operator-built AI framework claim was retracted once the framework was identified as public open source.
- A compromised production database credential claim was narrowed to connection details plus a username. No password was disclosed.
- A web shell described as deployed on a victim host was re-scoped to existing in the operator's own directory only.
- Five Cobalt Strike beacon hits were confirmed as scanner false positives.
- A directory of files named for human-resources contracts was confirmed to be human resources, not health records. There is no medical or healthcare target in this investigation.
- Two further wording corrections were directed at this report rather than at external recipients: the content-delivery block on the mobile-OEM thread is stated as apparent rather than confirmed, and the insurance-sector target's controls-held reading is stated as substantially silence rather than as a positive defensive result.

---

## Response Orientation

This is not an incident response guide. It is a short orientation on what to address. Readers with an active incident should engage their own response function.

**Detection priorities, highest value first:**

- Alert on any successful external access to a database monitoring console or an application heap-dump endpoint. Both are direct sources of the confirmed harvest in this campaign.
- Alert on remote log-level manipulation through a management interface followed by a log-file read. That sequence manufactures the data an attacker then collects, and it is rarely instrumented.
- Alert on sequential verification-code enumeration where the verification-context token stays constant across many requests.

**Persistence targets to look for, names and locations only:**

- A generic JSP web shell, and any similarly named file under a web-server temporary document path. Deployment to any victim host is unconfirmed, so treat these as hunt targets rather than as assumed findings.
- Unexpected entries in a privileged account's authorized-keys file on any host reachable from an application capable of server-side request forgery, and any in-memory data store whose save directory or filename configuration has been altered.
- Self-registered platform accounts matching this operator's naming series, and any account whose first session probed administrative routes.

**Containment categories:**

- Block the operator platform and its associated VPN hostname at the network edge, treating the entry as perishable.
- Close unauthenticated management surfaces: monitoring consoles, management and JMX endpoints, API documentation portals and service-discovery consoles.
- Rotate credentials on any platform where a monitoring console, an environment endpoint or a heap dump was externally reachable, as a precaution.
- Suppress framework stack traces in production.
- Review authentication logs for the enumeration and self-registration patterns above across the observed activity window.

---

## References

These sources support this report's central claim: that every technique class observed here is drawn from the well-documented public record, with mature proof-of-concept code already available. That claim is what makes the operator's failure to convert any of it into stolen data meaningful, so it is worth being able to check.

**Vulnerability and technique documentation**

1. NVD, CVE-2021-42550 (Logback `insertFromJNDI`). <https://nvd.nist.gov/vuln/detail/CVE-2021-42550>
2. GitHub Advisory Database, GHSA-mjmj-j48q-9wg2 (SnakeYAML deserialization). <https://github.com/advisories/GHSA-mjmj-j48q-9wg2>
3. Snyk, "Unsafe deserialization in SnakeYAML (CVE-2022-1471)." <https://snyk.io/blog/unsafe-deserialization-snakeyaml-java-cve-2022-1471/>
4. XStream project, security advisories and gadget documentation. <https://x-stream.github.io/security.html>
5. Baeldung, "Java XStream remote code execution." <https://www.baeldung.com/java-xstream-remote-code-execution>
6. Imperva community, Spring Boot Eureka XStream deserialization RCE. <https://community.imperva.com/discussion/spring-boot-eureka-xstream-deserialization-rce-vulnearbility>
7. Alibaba Druid project wiki, `StatViewServlet` configuration. <https://github.com/alibaba/druid/wiki/%E9%85%8D%E7%BD%AE_StatViewServlet%E9%85%8D%E7%BD%AE>
8. Beagle Security, "Druid monitor unauthorized access." <https://beaglesecurity.com/blog/vulnerability/druid-monitor-unauthorized-access.html>
9. DTS Solution, "Exposing the heap: Java heap dumps via Spring Actuators." <https://www.dts-solution.com/exposing-the-heap-a-security-deep-dive-into-java-heap-dumps-via-spring-actuators/>
10. Jolokia exploitation toolkit. <https://github.com/laluka/jolokia-exploitation-toolkit>
11. Acunetix, Jolokia XML external entity vulnerability. <https://www.acunetix.com/vulnerabilities/web/jolokia-xml-external-entity-xxe-vulnerability/>
12. HackTricks, Redis service exploitation reference. <https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis>
13. Chadwick, M., "SSRF exploits against Redis." <https://maxchadwick.xyz/blog/ssrf-exploits-against-redis>
14. Gopherus, gopher-protocol payload generator. <https://github.com/tarunkant/Gopherus>

**Detection prior art**

15. Fox-IT, "Log4Shell reconnaissance and post-exploitation network detection." <https://blog.fox-it.com/2021/12/12/log4shell-reconnaissance-and-post-exploitation-network-detection/>
16. Nuclei templates, Spring Boot heap-dump misconfiguration check. <https://github.com/projectdiscovery/nuclei-templates/blob/main/http/misconfiguration/springboot/springboot-heapdump.yaml>
17. Broadcom Security Center, attack signature reference. <https://www.broadcom.com/support/security-center/attacksignatures/detail?asid=34457>

**Ecosystem and regulatory context**

18. Recorded Future, "Restrictive laws push Chinese cybercrime toward novel monetization techniques." <https://www.recordedfuture.com/research/restrictive-laws-push-chinese-cybercrime-toward-novel-monetization-techniques>
19. SpyCloud, "Deep dive: the Chinese cybercrime ecosystem." <https://spycloud.com/blog/deep-dive-chinese-cybercrime-ecosystem/>
20. Group-IB, "Lead data obfuscation brokers." <https://www.group-ib.com/blog/lead-data-obfuscation-brokers/>
21. Cloudflare, ICP filing concepts and requirements. <https://developers.cloudflare.com/china-network/concepts/icp/>
22. PTS Consulting, "China ICP licence explained." <https://www.ptsconsulting.com.hk/blog/china-icp-licence-explained>

**Agentic-AI adoption in offensive operations**

23. Anthropic, "AI-enabled cyber threats and MITRE ATT&CK." <https://www.anthropic.com/news/AI-enabled-cyber-threats-mitre-attack>
24. Google Cloud Threat Intelligence, "AI vulnerability exploitation and initial access." <https://cloud.google.com/blog/topics/threat-intelligence/ai-vulnerability-exploitation-initial-access>
25. Nous Research, Hermes Agent project. <https://hermes-agent.nousresearch.com/>

Reference 25 is included because it identifies the agent framework found on the operator host as off-the-shelf open-source software. That identification is the basis for retracting an earlier characterization of the framework as operator-built, and readers should be able to verify it directly.

---

© 2026 Joseph, The Hunters Ledger. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — free to republish and adapt, including commercially, with attribution to The Hunters Ledger and a link to the original.
