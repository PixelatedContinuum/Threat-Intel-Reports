---
title: "Enough to Be Dangerous: The Mechanics of an LLM-Assisted Intrusion Campaign"
date: '2026-07-21'
layout: post
permalink: /reports/multivector-ecommerce-rce-toolkit-192-3-1-116/
hide: true
unlisted: true
category: "PII Harvesting Operation"
description: "An exposed staging directory shows how an ordinary operator now runs an intrusion campaign: a hundred-plus probably-generated attack scripts, an off-the-shelf agentic-AI framework wired in as the console, and a defensive lesson in what actually stopped it."
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

## 1. Operational Brief

I keep running into this same setup, in my own investigations and across public reporting, often enough now that I read it as a pattern and not a one-off. A low-skill operator stages a large pile of attack scripts they almost certainly did not hand-write, then wires an off-the-shelf agentic-AI framework in as the console they run the whole operation from.

`192.3.1[.]116:7777` is one working example, a staging directory left open to anyone who found the port. Inside sit roughly 450 files: a hundred-plus bespoke Python and shell attack scripts aimed at a dozen-odd mainland-Chinese commercial platforms, the harvested results, and Hermes, a public open-source agent framework, cloned onto the host, running as root and driven from a Telegram group. There is no malware, no implant, and no command-and-control framework of the operator's own making anywhere in the corpus.

The person behind it barely matters. What is worth your time is the *how*, a concrete and inspectable picture of the way an ordinary operator now puts LLM tooling to work, and the how is the part most "threat actors are using AI" reporting skips.

My read on the person behind it is that they know enough to be dangerous and the model does the rest. They have real intent and real working knowledge, and I do not think you get exploit chains like these without it. What the LLM adds is shape and scale, a hundred working scripts across many targets, faster than an operator at this skill level could ever hand-write them.

Where the tooling looks sharp, that is the amplification. Where it looks sloppy, the broken downloads, a logging bug that erased their own evidence, the world-readable directory itself, that is the operator showing through.

I cannot prove the scripts were LLM-generated and do not claim it as fact. But the volume, the uniformity, and small tells like the bracket-and-brace bugs I hit in my own LLM work all lean the same way, and Section 3 lays out that evidence with its limits.

The tell that this is amplification and not mastery is also the finding a defender should take from the case. This operator carried an eight-class exploitation toolkit, and every class in it built to get code running or a key written, the two Logback routes, SnakeYAML, Eureka with XStream, the XXE chains and the Redis-to-SSH-key chain, produced not a single byte of stolen data between them. Everything they actually took came through doors left open, an unauthenticated database console, an unrestricted management interface, verbose application logs, and guessable order numbers.

The one clever move in the whole corpus was not an exploit at all, and it is the piece that moved my read of this operator upward. Through an open management interface they raised the target application's own logging verbosity, made the application write customer records into its own logs, then read them back (Section 4.3). That one is real skill, and it is the exception in a corpus that otherwise ran on borrowed exploits that never landed.

That inversion is the good news here, and it does not last long. What stopped this operator was nothing exotic. Encryption at rest held the most sensitive fields out of reach even after five script iterations went after them (Section 4.6), and closed management planes and working rate limits turned whole attack chains into error pages (Section 7). Small, ordinary controls did the work.

Turn it around, though, and it is uncomfortable. This operation is cheap, repeatable, and becoming more common, and the organizations that fall to the next one will be the ones with foundational gaps, not the ones that missed a clever zero-day. An operator this ordinary does not have to be good if the target is soft.

### What was confirmed

Real customer names plus order and financial records for at least five named individuals were harvested from `riverbaybuy[.]com`, a rent-to-own and installment commerce platform, through four independent sourcing channels running in parallel. The operator's own scripts retain the extracted names alongside their platform identifiers, printed under a summary header in clear text. That is a record of a completed extraction, not a plan for one. Fuller identity fields that the pipeline is written to pull, including national identity numbers, email addresses and emergency contacts, are highly likely but are not confirmed by any captured response.

An unauthenticated Alibaba Druid monitoring console belonging to `web.51qzp[.]com` (Quanzipin) exposed, at time of capture, a production database connection string, the schema name, the fact that the application connects as `root`, a 93-table schema, 427 API endpoints and 830 real SQL statements. The database password was not disclosed. A read-only re-check on 2026-07-20 found the host resolving NXDOMAIN and the port closed, so the exposure appears remediated.

A complete, pre-staged account-takeover weapon sits armed against a real staff account: 10,000 individually pre-built requests covering the entire four-digit verification-code space, all tied to a single real password-reset code that was actually sent, all carrying the same operator-chosen replacement password. Whether it was fired is unconfirmed, and that is the gap in this case I most wanted to close (Section 4.5).

### What was only attempted

The negative findings carry as much intelligence value as the positives here, and they bound the harm, they do not qualify it. A sustained effort to decrypt one specific individual's encrypted phone number and government identity number failed, so the most sensitive fields the operator pursued were not obtained. The registry-poisoning run against a live target, the malicious directory-server chain behind two of the payloads, a password brute force and eight management-endpoint probes all failed, were blocked, or produced no evidence of success. Section 7 gives each with its limits.

### Threat level: HIGH

Rated on confirmed outcomes, not on the length of the technique list: confirmed theft of identifiable personal and financial records belonging to named individuals, an armed account-takeover weapon aimed at a staff account, live-used database and cache credentials, roughly a dozen targeted organizations, and an operator platform still live at the close of analysis. It is HIGH rather than CRITICAL because five of the six efforts that left an outcome artifact are negative, the confirmed theft covers one platform and five named individuals, not a population, and no destructive capability exists anywhere in the corpus. The full scoring is in Section 12.

### What to do first

If you run internet-facing Java applications, the exposure classes this operator hunts matter far more than this operator does:

- Close management planes to the internet. Unauthenticated monitoring consoles, unrestricted Jolokia and JMX endpoints, heap-dump endpoints, service-discovery consoles and API documentation portals did every piece of real damage in this campaign.
- Alert on a remote log-level change followed within minutes by a log-file read from the same source. That sequence manufactures the data an attacker then collects, and almost nobody instruments it. It is the highest-fidelity signal in this case.
- Check whether your record identifiers are enumerable and whether short verification codes have real attempt limits. Both did work here that five exploitation chains could not.

The actor stays unattributed. Every dimension that could produce a name is empty rather than merely thin, and the operation is tracked internally as **UTA-2026-019** *(an internal tracking label used by The Hunters Ledger, see Section 11)*. That is a claim about catalogs and not about the world, and Section 11 sets out why each dimension is structurally empty.

Structured indicators are published in the machine-readable [IOC feed](/ioc-feeds/multivector-ecommerce-rce-toolkit-192-3-1-116-iocs.json). Detection content is published separately in the [detection rules file](/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/).

---

## 2. Threat Classification and Campaign Scope

This is an operator toolkit and captured-data cache, not a malware family, and the classification has direct consequences for how a defender should use this report. There is nothing to signature. Detection value lies in the exposure surfaces this operator consumes and the request patterns that consume them.

| Field | Assessment |
|---|---|
| Type | Operator offensive toolkit and captured-data cache. No malware family, no implant, no persistence binary on any victim host. |
| Family | Not applicable. Bespoke Python and shell attack scripts wrapped around public exploitation payload classes. |
| Family confidence | Not applicable. Nothing in the corpus matches or resembles a tracked malware family. |
| Sophistication | Intermediate and very uneven. Reported as two separate bands in Section 11.2, not as one averaged label. |
| Operator profile | An individual operator or a very small crew. Absent from both the Hunt.io and VirusTotal threat-actor catalogs. |
| Threat level | HIGH (overall risk score 7.2/10, see Section 12) |
| Activity window | Host re-provisioned around 2026-01-01. Earliest dated operator artifact 2026-05-31. Control-channel session anchor 2026-06-01. Operator access observed through 2026-07-06. Directory still live and growing as of July 21, 2026. |
| Target geography and sector | Mainland China. Rent-to-own and installment commerce, device rental, credit rental, gig work and recruitment, insurance asset management, loan referral, and a mobile-OEM developer platform. |

### 2.1 Why there are no file hashes in this report

The IOC feed for this campaign carries no `file_hashes` object, and that absence is deliberate, not an omission. No malware sample exists. The only hash present anywhere in the evidence is the standard empty-file SHA256, which appears because a publicly available exploitation tool the operator downloaded arrived as zero bytes.

Five files in the corpus produced Cobalt Strike beacon-scanner hits. All five are confirmed false positives. Every real Cobalt Strike configuration field is null: version unknown, no domains, no URIs, no watermark, no kill date, no user agent and no public key. This is the classic empty-config scanner artifact on large, high-entropy files, and a "Cobalt Strike beacon" line item carried forward from an automated scan would completely misdescribe this campaign. Do not carry it forward.

A separate Android application package in the corpus, protected by a commercial packer, carries only generic and explicitly deprecated signature hits on near-uniform high-entropy content. It remains flagged and unverified, and it is deliberately excluded from the IOC feed. It is a third-party target application the operator pulled down for analysis, not operator tooling.

### 2.2 Why the evidence supports unauthorized activity

The operator self-labels consistently, with throwaway accounts named `redteam01`, `redteam03`, `pentest_user_01` and `pentest_crack2`, and private key files named `pentest_key`, `pentest_ssh_key` and `ssrf_key`. That naming is recurring and deliberate enough that it is not casual, and it is the single strongest argument for an authorized-testing reading. It is outweighed.

My judgment is that this is unauthorized, malicious activity and not authorized security testing. I hold that at HIGH confidence, around 85 percent.

<details markdown="1" class="hl-teardown">
<summary>The full weighing, including the strongest version of the authorized-testing case and why it loses. Click to expand.</summary>

That rests on four strong and five moderate inconsistencies with the authorized-testing hypothesis, drawn from four independent kinds of evidence.

The clearest is the decryption effort. Five successive iterations went after one specific real person's phone number and government identity number, and that has no demonstrative value in any authorized engagement, because a test needs one attempt against any record and not five against one individual.

The rest stack up alongside it. The harvest script's own output header reads as a plaintext summary of real named individuals and is retained across runs. Account-takeover tooling sits armed against a real staff account with an operator-chosen replacement password. The target breadth spans eight or more unrelated organizations with no client separation of any kind.

And nowhere in roughly 450 files is there an engagement scope, an authorization artifact, a rules-of-engagement document, or a client reference. That absence carries weight because this operator compartmentalizes nothing else. Keys, tokens, harvested data, working notes and environment captures all sit together in one publicly listable directory.

The strongest counter-case deserves stating fairly. Two configuration values in the operator's agent-framework environment are the best evidence an authorized reading has, because the framework runs with its execution-confirmation gate enabled and its secret-redaction setting on, and those are the settings a cautious professional would choose.

Both are stock defaults of the open-source project though, not operator choices, and both are equally compatible with a careful malicious operator who simply never changed them. That is the strongest version of the counter-case and it still loses to the destructive actions, the retained catalogue of real individuals, and the multi-organization breadth.

What I cannot do is prove the absence of authorization from captured artifacts alone. No targeted platform has been asked to confirm that no engagement existed, and that is the cleanest test of the question while being structurally out of reach for a third-party intelligence provider. A non-engagement confirmation from any one of those platforms is what would move this higher.

Between two remaining readings of the naming convention, operator vernacular is favoured over a deliberate false flag at MODERATE confidence (approximately 70 percent). The deciding observation is that the same vocabulary appears in the operator's own private key filenames, which no audience was ever meant to see. A false flag is a message to an audience, and it does not need to appear where there is no audience.

</details>

The weight of evidence points clearly to unauthorized data theft. The authorized-testing reading is formally open and unsupported. It is not stated as confirmed, because HIGH is not DEFINITE.

### 2.3 What the exposed directory is, and what it is not

`http://192.3.1[.]116:7777/` is a plain Python static file server of the `SimpleHTTP` class. Two consequences follow, and both are frequently misread.

First, every file in the operator's working tree was retrievable by anyone who found the port, including private SSH keys, captured victim data, and control-plane environment dumps. This is the operational-security failure that makes the entire investigation possible.

Second, requesting `hxxp://192.3.1[.]116:7777/cmd[.]jsp` returns the **source** of that file. The server does not execute JSP. The host is distributing a working web shell, not running one at that URL. Deployment of that web shell to any victim host is unconfirmed: it exists in the operator's own directory, and no captured artifact shows it present anywhere else.

---

## 3. The LLM-Assisted Operator: What the Staging Directory Shows About the How

Plenty of reporting now says threat actors are using AI. Very little of it shows the mechanics, because the mechanics normally sit on the attacker's own machine where no researcher can see them. This directory is one of the cases where they were left in the open.

The working method has two halves. First, volume, a hundred-plus attack scripts hand-tailored per target, written at a rate and a uniformity that reads as generated and not typed. Second, the console, an off-the-shelf open-source agent framework installed on the attack host, running as root, wired to a consumer messaging app so the operator can drive it from a phone. Neither half is exotic on its own. Together they describe how an operator of modest skill now fields an eight-class exploitation toolkit against a dozen organizations at once.

### 3.1 The agent framework, and a retraction that must be preserved

The framework is Hermes, the open-source agent project from Nous Research (Reference 25), plus three public community plugins, cloned from public repositories by the same build identity that produced the operator's SSH keys. It is off-the-shelf software, not an operator creation. An earlier characterization of this as a novel operator-built framework is **retracted**, and it must not be reintroduced.

None of that surprised me. I half expected it, having run into Hermes in other cases, and I was mostly waiting to find out which framework this one would turn out to be. I do not expect an operator at this tier to build their own, and I would not build my own either when something public already works. The off-the-shelf part is the finding, not a disappointment. Bespoke tooling would have made this a curiosity about one actor. Commodity tooling is what makes it a trend, because it means the barrier to running this playbook is a `git clone` and an API key.

<details markdown="1" class="hl-teardown">
<summary>How the framework was identified, what was verified, and the limits of that verification. Click to expand.</summary>

The identification came from the operator's own version-control metadata, left readable in the open directory alongside everything else. The plugin directories carry their `.git` state intact, and the remote-tracking configuration in each points at a public repository. The reference logs record ordinary clone operations, authored by the same build identity that signs the operator's SSH key material. The core framework was then identified from the plugin project's own documentation.

Two of the three plugins were independently verified as unmodified public clones. The third plugin's contents were not recovered, and that gap matters in one specific direction: it is the plugin that would hold custom capabilities if the operator wrote any. If it turns out to contain operator-authored offensive skills, "deployed off-the-shelf" would undersell what happened here. That question stays open.

Confidence splits here, and it should not be averaged. That the two examined plugins are public clones is DEFINITE. The core framework's identity rests on the plugin documentation naming it, which is HIGH rather than DEFINITE. The third plugin is unverified.

A note on the public usernames appearing in the plugin repository records: they belong to the open-source plugin authors and are unrelated to the operator, who is a user of their public work. A second naming collision is worth flagging so it is never conflated. One of the target applications in this corpus bundles a mobile JavaScript engine that shares a name with the operator's agent framework. The two are entirely unrelated.

</details>

What is established about how it was run comes down to four things. It operates as root on the operator host. It sits under a live messaging control channel with a single identified controlling user. It is driven interactively, human in the loop, not autonomously. And it lives on the staging box, never on a victim. A defender looking for this pattern is looking for an agent framework on attack infrastructure, not on their own estate.

This report does **not** claim the framework executed any attack script. Nothing in the corpus shows it orchestrating any part of this campaign, and that question is fundamentally about host telemetry, which no public-research method can answer. The distinction matters for classification: an operator-scripted campaign using an AI console is a different and less advanced thing than an AI-executed campaign, and the evidence here supports only the first.

The framework is also **not** an attribution discriminator on its own. Section 11.5 carries it only as one element of a platform composite, never as a standalone characteristic, because commodity software that anyone can install distinguishes nobody.

### 3.2 The tells that point to generated tooling

The scripts read as generated. I want to be careful about how much weight that carries, because it infers from shape and does not prove provenance, but three independent observations point the same way.

The first is volume and uniformity. More than a hundred bespoke scripts cover a dozen targets, each tailored to its target's endpoints, parameter names and response shapes, with recurring structural conventions across otherwise unrelated files. That is a lot of per-target work for a single operator whose operational discipline is otherwise poor.

The second is the kind of errors they contain. The clearest single tell sits in the operator's own registry-poisoning tool, and it cost them their best piece of evidence. The tool's logging line uses doubled braces inside a formatted string, so instead of printing the address of each client that connected, it printed the literal placeholder text. Its logs therefore record that the malicious payload was served on the third, fourth and fifth requests, but cannot say to whom. That is a permanent evidence gap the operator created for themselves and never noticed. It is also exactly the class of bracket-and-brace error I hit myself when working with generated code, which is why I read it as a tell and not as ordinary carelessness.

The third is the gap between design and execution. The technique chains are competently designed while the surrounding operational work is not, and Section 11.2 inventories that gap in full. Broken downloads got saved as though they had worked, and nothing anywhere was compartmentalized. That pattern fits a person whose ideas outrun their own implementation discipline, and who has a tool that closes the gap on the implementation side only.

Those three support the read in the Operational Brief, which is that this is not an LLM lifting a novice. The operator brings the intent and enough working knowledge to specify what they want. I do not think you get a server-side request forgery chain into a data-store configuration write without understanding why it would work in the first place. What the model contributes is turning that understanding into scaled, working tooling, and it contributes nothing at all to the operator's discipline, so the careless half of this corpus stays careless.

### 3.3 What this does not establish

Three limits bound all of this.

The scripts being LLM-generated is my assessment at MODERATE confidence, from volume, uniformity and error class. No generation artifact, prompt, session transcript or tool-call trace for the script corpus was recovered, and a capable human could have written all of it.

Whether the agent framework executed any part of the campaign is **UNCONFIRMED**, and no claim is made in either direction. If that assumption is wrong, the classification shifts materially from an operator-scripted commodity-technique campaign to an AI-assisted exploitation campaign, which 2026 vendor reporting treats as a distinct and more advanced category.

And none of this is novel to this operator. Commodity agentic-AI adoption as a human-controlled operator console is an actively documented trend in 2026 threat-intelligence reporting, including an independently reported case in the same month in which Hermes was found running unattended against a government ministry in a different country (Reference 26). I have also run into Hermes on other operator infrastructure in my own work, which is why the trend read here rests on more than this one box. What was not found documented elsewhere is this particular combination of framework and actor tier, and that should be read as no public reporting found, never as novel. The value here is the mechanics, not the discovery.

---

## 4. Anchor 1: riverbaybuy.com, Confirmed Multi-Victim Data Theft

Four independent data-sourcing channels converged on one platform, and the operator's own scripts retain the results of a completed extraction. That combination, planning plus a preserved outcome, is what separates this target from every other thread in the campaign. It is also the one target where the harm is real and named, not hypothetical.

### 4.1 The target

`riverbaybuy[.]com` is a rent-to-own and installment commerce platform. Its internal handle is `hzsx`, visible in both the API path prefix `/hzsx/` and the Java package namespace `com.hzsx.rent.*`. It runs a Spring Cloud microservice stack behind a Eureka service registry with Feign HTTP clients (`OrderClient`, `UserCenterClient`, `ProductClient`), uses Ant Group's AntChain service for contract signing, and includes a distributed identifier-generation component. It shares an internal address with a separate Eureka-engaged target elsewhere in the campaign, a HIGH-confidence inference and not a DEFINITE link.

Confirmed here: real customer names plus order and financial records for at least five named individuals, an armed account-takeover weapon aimed at a staff account, and live-used database and cache credentials.

### 4.2 The kill chain

The operator never needed an exploit against this platform. A diagnostic interface left reachable from the internet handed over memory and logs, and everything that followed was a matter of reading what was already available.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/multivector-ecommerce-rce-toolkit-192-3-1-116/multivector-riverbaybuy-kill-chain.svg" | relative_url }}" alt="Vertical five-step infographic titled Confirmed Multi-Victim Harvest, showing how an exposed management interface became real customer records. Step one, orange band, Unrestricted management interface: Jolokia and Actuator were reachable externally with no access restrictor, quoting the captured string no access restrictor, access to any MBean is allowed; assessed as the likely master access vector; detection guidance is to alert on external Jolokia or JMX reachability. Step two, red band, Memory and log capture: Java heap dumps retrieved alongside application request and response logs via the heapdump and logfile endpoints, three heap snapshots captured; detection guidance is to alert on heap-dump retrieval success, meaning a 200 response with a large body. Step three, yellow band, Real order identifiers extracted: live order IDs mined from captured memory rather than guessed, fed by four independent sourcing channels; detection guidance is to watch sequential record-ID enumeration on detail endpoints. Step four, red band, Identifier resolved to user: each order ID resolved to a distinct platform user, built to iterate across up to thirty users in one pass. Step five, deep red band, Customer records harvested: real names tied to real order records for at least five named individuals, confirmed by an operator-authored identifier-to-name mapping and corroborated by live order IDs in captured memory, with the caveat that fuller identity fields are highly likely but not confirmed by any captured output.">
  <figcaption><em>Figure 1: The anchor finding end to end. The chain begins with a configuration failure, not a software vulnerability, which is why none of the operator's remote-code-execution tooling appears anywhere in it.</em></figcaption>
</figure>

<details markdown="1" class="hl-teardown">
<summary>The five stages in detail, from reconnaissance through to the escalation attempts. Click to expand.</summary>

The operator opens by mapping what a target has left exposed, and their reconnaissance profile is not a generic port sweep. It targets a specific 14-port list: `22,80,443,3306,6379,8080,8443,8888,9000,9001,9002,9090,8848,8157`. Two of those entries are the operator's tell. Port 8848 is the default for the Nacos service-discovery console, and port 8157 is where this operator found an exposed Alibaba Druid monitoring console on a different target. This operator hunts exposed management planes specifically, and the port profile encodes which ones.

Full-range sweeps run at `-T5 --min-rate 10000` across all 65,535 ports. There is no attempt at stealth anywhere in the reconnaissance tooling, which makes this stage a reliable early tripwire in flow or firewall telemetry.

Next they reach the unrestricted management interface, and this is the stage that mattered. The target's Jolokia surface reports, in its own captured configuration, that there is no access restrictor and that access to any managed bean is allowed. That single configuration state is the likely master access vector for this entire target, and it plausibly explains both the heap dumps the operator later mined and the database credential the operator later used.

That the Jolokia interface was unrestricted is HIGH, because the interface says so itself in its own captured configuration. That it is the specific origin of the credential and the heap dumps is only MODERATE. No captured artifact records the retrieval itself, so this is a strong inference from mechanism and opportunity, not a confirmed transfer.

Then they manufacture the data. Instead of hunting for a place where customer records already sat, the operator changed the application's own settings so that the application would start writing customer data into its log file, then read the log file. Section 4.3 covers the mechanism, and it is the piece of this campaign worth a defender's attention.

Then they harvest, running four independent channels against the same target: mining a captured Java heap dump for live order identifiers, mining the verbose application log produced in Stage 3, pulling the framework's built-in request-history endpoint, and directly enumerating order identifiers by constructing them from a predictable format. Section 4.4 details each. The redundancy is deliberate and it is what makes the extraction robust against any single surface being closed.

Finally they escalate toward account takeover, moving from reading data to attempting control of a staff account, which would convert an external data-theft problem into an internal one. Section 4.5 covers the weapon, which is armed and pre-staged with its execution unconfirmed. Section 4.6 covers a parallel escalation, an effort to decrypt one individual's protected identity fields. That one is a confirmed failure, and it bounds the harm.

</details>

### 4.3 The standout technique: elevating log verbosity to manufacture harvestable data

Everything else in this toolkit is borrowed. This one is not, and it is the reason I revised my estimate of the operator upward.

Most data theft is constrained by where the target already keeps its data, a database the attacker has to reach, a file they have to read, an API they have to call with valid credentials. This operator removed that constraint. Instead of hunting for a place where customer records already sat exposed, they reached into the application's own configuration and turned up its logging until the application started writing customer records into its log file, generated some traffic to make sure it did, then read the log back out. Nothing was exploited in the conventional sense. A management feature was used exactly as designed, by the wrong party.

It changed the story for me on how much credit this operator deserves, and it is more skill than I had given them going in. That is also all it changes. One technique this good does not lift the rest of the corpus, and the overall read in Section 11.2 stays where the evidence puts it.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/multivector-ecommerce-rce-toolkit-192-3-1-116/multivector-manufactured-log-harvest.svg" | relative_url }}" alt="Vertical four-step infographic titled Manufacturing the Evidence, showing log-verbosity abuse. Step one, orange band, Reach the management interface: an externally reachable Jolokia or JMX endpoint with no access restriction, invoked by a POST to the jolokia path using the setProperty operation, requiring no exploit and no credential, only reachability. Step two, red band, Elevate log verbosity: an application logger raised to DEBUG and an HTTP client set to FULL body logging, described as a configuration change rather than an exploit, with nothing compromised at this point; detection guidance is to alert on remote log-level changes because they are rare and rarely instrumented. Step three, yellow band, The application writes the data itself: full request and response bodies, now including customer records, land in the log file, with the note that the sensitive data did not exist in the log before the operator asked for it. Step four, deep red band, Read the log back: the log file is retrieved through the same management interface using a GET to the actuator logfile path, with emphasis that the detection is the ordered sequence of a log-level change followed by a logfile read within minutes, published as a temporal correlation rule rather than two standalone alerts.">
  <figcaption><em>Figure 2: The campaign's standout technique. The operator did not find exposed data, it caused the application to write sensitive data into its own logs and then collected it, which is why each step looks benign in isolation.</em></figcaption>
</figure>

<details markdown="1" class="hl-teardown">
<summary>The three-step mechanism, the confidence split, and how to detect it. Click to expand.</summary>

First the operator writes. Reaching Jolokia over HTTP, they invoke `setProperty` against the application's own managed beans to raise the Feign HTTP-client logging level to `FULL` and to set the application's loggers to `DEBUG`. Feign at `FULL` logs request and response headers and bodies for every inter-service call. In an enterprise Java application, those bodies are the customer records.

Then they trigger the traffic. With verbose logging now active, the operator deliberately performs an ordinary order lookup against a real user identifier. This is not an attack request. It is a legitimate-looking transaction whose only purpose is to make the application generate trace traffic while the elevated logging captures it.

Then they read it back. The operator pulls `/actuator/logfile`, the endpoint that serves the application's own log over HTTP, and filters it for the lines their trigger produced.

The sequencing is the part that is hard to fault. Raise the level, then generate the traffic, then read: get that order wrong and you collect an empty log or you tip your hand with traffic nobody logged. Whoever built this understood that the application had to be given something to say before there was any point listening. That is a different kind of thinking from running someone else's exploit and hoping.

The same script separately queries Jolokia for raw configuration values including the datasource connection URL, the connection-pool JDBC URL, and service-registry configuration. Those are administrative reads through the same interface.

On confidence, I can say DEFINITE that the tooling exists and is written to perform this sequence, because I read the operator's own script. Whether this particular script's own run succeeded is only MODERATE, since no outcome artifact for it was captured.

What it supplies is the missing mechanism behind a finding that is already confirmed. The operator's separate log-mining channel demonstrably pulled genuine customer data out of this target's application log, and this is the most plausible explanation for how that log came to hold it in the first place.

To detect it, look for the sequence and its timing and not for any single event. A write to a Jolokia or JMX endpoint that changes a logging level, followed within minutes by a read of the application log-file endpoint from the same source, has essentially no benign explanation from an external address.

Both halves are individually low-value and jointly high-value, so the published detection content builds a correlation rule over two base rules instead of alerting on either alone. Coverage is in the [detection rules file](/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/#sigma-rules).

</details>

This matters well beyond this one platform. An organization can be fully patched, run no vulnerable library version, and still lose customer records this way, because nothing here is a software vulnerability. The exposure is a management interface reachable from outside the management network. That puts the remediation in configuration and network policy, not in the patch cycle, and it means vulnerability-scan-driven assurance will not surface it.

### 4.4 Four independent PII-sourcing channels

Closing one of these channels would not have stopped the harvest. The operator built four routes to the same customer data, each drawing on a different weakness and each usable on its own: mining captured heap memory, mining the manufactured verbose log, pulling the framework's request-history endpoint, and enumerating order identifiers directly. The fix has to address the class, not the instance.

The evidence that this worked, and the boundary on how far it worked, both sit in one artifact. A hardcoded dictionary in the operator's own script, commented as the known user-identifier set from an earlier run, maps five real user identifiers to five real personal names. That is a record of a completed extraction, not a plan for one, and live order identifiers recovered from heap memory corroborate it independently. The fuller identity fields the pipeline is written to pull, national identity number, email address and emergency contacts, are HIGHLY LIKELY but are **not** confirmed by any captured response. No victim name, identifier or record is reproduced anywhere in this publication.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/multivector-ecommerce-rce-toolkit-192-3-1-116/multivector-four-pii-channels.svg" | relative_url }}" alt="Two-by-two grid infographic titled Four Independent Paths to the Same Customer Data. Channel one, red band, Heap-dump memory mining: live order identifiers recovered from Java heap snapshots pulled from the running application, described as real identifiers rather than guesses and as the channel that seeded the confirmed harvest. Channel two, red band, Manufactured log harvesting: log verbosity raised through the management interface so request and response bodies were written and then retrieved, confirmed effective because a captured session identifier taken from live logs was reused to pull that user's orders. Channel three, yellow band, Request-history endpoint: the framework's own recent-request trace surface exposing captured traffic, characterized as a built-in diagnostic surface that was exposed rather than exploited. Channel four, yellow band, Order-identifier enumeration: structured predictable record identifiers brute-forced across sequence ranges, which works with no access to memory or logs at all and operates purely against the public API. The footer notes that redundancy is the finding, since closing one channel leaves three.">
  <figcaption><em>Figure 3: Four routes to the same customer data, each usable on its own. The practical consequence is that remediating any single channel would not have stopped the harvest, so the fix has to address the class.</em></figcaption>
</figure>

<details markdown="1" class="hl-teardown">
<summary>Each channel in detail, and the evidence separating what is confirmed from what is likely. Click to expand.</summary>

The operator's first channel mines heap dumps, and on a busy commerce platform those carry live customer records and live order identifiers. The operator's harvesting script regex-extracts every real order identifier matching the pattern `001OI\d{6}20\d{6}\d{7,10}` directly out of a captured heap dump, resolves each identifier to its owning user account, then for up to 30 distinct real users pulls both the full order history and the identity-verification record in a single pass. It prints customer name, order identifier, product and stock-keeping unit, rental amount, installment count, shop name, status and timestamps.

Three heap dumps were captured in total. Structurally they represent two distinct application processes. Two of them match each other closely across roughly a dozen independent metrics and represent the configuration-heavy and authentication-heavy backend tier. The third is the order-facing tier: it alone carries the literal platform hostname at 74 occurrences, the live order-identifier pattern at 51 occurrences, and the highest density of personally-identifying string shapes. That statistical profile independently corroborates that the third dump was the operator's actual harvesting source material. I hold that at HIGH, resting on a statistical fingerprint and not on direct process-identity metadata.

Their second channel mines the verbose application log that Section 4.3 enabled. The operator pulls the framework's request-history endpoint and mines the application log for lines containing the enterprise-Java markers 入参为 and 出参为, meaning "input parameters are" and "output parameters are". That is a widespread convention in Chinese enterprise Java development which logs the request and response payload of every service call. The operator then explicitly filters **out** its own attack traffic, discarding lines containing `UNION SELECT` and the identity-verification and identity-document markers the operator's own probes generated, in order to isolate genuine successful responses containing real customer data.

That filter is analytically important. The operator was not collecting its own test noise. It was separating real production traffic from its own footprint, which is behaviour consistent with harvesting, and inconsistent with demonstrating a vulnerability.

Their third channel is `/actuator/httptrace`, the rolling history of recent HTTP exchanges. Where a target leaves it reachable externally, it hands over recent real traffic and its parameters with nothing intercepted.

Their fourth channel needs no privileged access at all. Date-targeted scripts escalate to direct brute force, constructing identifiers of the form `001OI{seq:06d}20260601000000000` across sequence ranges. That the operator could construct valid identifiers at all confirms the platform's order-identifier scheme is predictable enough to enumerate. This is a structural insecure-direct-object-reference risk, not merely an information-disclosure one, and it persists after every management endpoint is closed.

On the confirming artifact itself, the operator's dictionary is printed under a plaintext summary header and carries five user identifiers against five real personal names, four of those names complete and one partial. The emergency-contact entries the pipeline targets also carry third-party names and numbers.

</details>

One consequence of that field set stands on its own. The emergency-contact entries mean third parties who never transacted with the platform, and who have no relationship with it at all, sit inside the targeted data set.

### 4.5 The armed account-takeover weapon

This is the finding I could not close. A complete, ready-to-fire account-takeover weapon sits in the directory aimed at a real staff account, and nothing anywhere in the corpus records whether it was ever fired. I kept looking for the outcome and there is not one. The honest position is that a weapon this finished and this specific, left unused, is itself a finding, but I would rather have known.

The file is 3.27 MB and it is not a loop. It is 10,000 individually pre-built `curl` commands, one per possible four-digit verification code from `0000` to `9999`, all targeting the same password-reset endpoint on `riverbaybuy[.]com`. Every command carries an identical verification-context pair, `codeKey` and `codeTime`, which means a single real SMS verification was triggered against one real phone number and this file is the complete, ready-to-execute brute force of the code space that could match it. The account type in the request is a staff or operator type, not a customer, and the intended replacement password is a fixed operator-chosen string.

What distinguishes it from the operator's exploratory work is that it is complete, pre-staged and immediately executable against a specific real staff account, requiring no further development. A parallel weapon exists against a different platform's supplier backend, brute-forcing a four-digit code on a password-recovery endpoint and chaining into a reset. That one targets a well-known placeholder phone number, so it reads as development work and not as an armed weapon. The distinction is worth preserving: one of these two is a test, and one is not.

The discriminator for detection is the constant verification context across many requests. Ordinary users retry a code two or three times, taking a fresh context after each expiry, while a brute force keeps one context constant and iterates a short numeric field. That shape is what the published Sigma correlation content keys on, and it generalizes to any platform with short numeric verification codes.

Short numeric verification codes are only as strong as the rate limiting and attempt-count enforcement around them. The mathematics gives an attacker certainty of success within 10,000 tries, so the entire control rests on the server refusing to accept try number six.

### 4.6 The decryption effort: a bounded, high-confidence negative

This one is good news, and there is not much of that in this case. The most sensitive fields the operator went after, one specific person's phone number and government identity number, were encrypted at rest, and that single ordinary control held against five successive iterations of tooling built to break it. It is a clean example of a small control stopping an attacker from accomplishing what they set out to do.

The operator's scripts hold two hardcoded encrypted values, labelled in the operator's own code as an encrypted phone number and an encrypted national identity card number, belonging to one specific individual obtained through the platform's identity-verification flow. Five successive script iterations pursue the AES-128-ECB key, progressing from searching Jolokia properties, to dumping the framework's environment endpoint, to sweeping heap-dump strings, to hexadecimal brute force, to keys derived from hashed candidate strings. One of them is named, in the operator's own filename, as the last resort.

<details markdown="1" class="hl-teardown">
<summary>The independent testing behind the negative result, and why it is HIGH rather than DEFINITE. Click to expand.</summary>

Independent memory forensics across all three captured heap dumps, where the operator only ever checked one, tested 26,570 unique heap-derived 16-character candidates, 123 named-candidate variants in raw, MD5, SHA256 and truncated-SHA256 forms, and 408 context-adjacent substrings, for roughly 54,000 individual decryption attempts against both encrypted values. Zero successes.

I put that at HIGH as a negative result, scoped to the string-extraction approach the operator's own tooling used.

It is not DEFINITE, for three reasons. The key may never have existed as a contiguous printable string at the moment any of the three snapshots was taken. It may be stored in non-printable byte form. And the cipher configuration could differ from the AES-128-ECB assumption baked into the operator's scripts. Full closure would need an object-graph heap parse and not a string sweep.

There is a second-order observation here. The fact that the operator had to attack the encryption at all confirms the platform encrypted those two fields at rest, a design decision that worked. The platform's weakness was in what its management interfaces and logs exposed, not in how it stored its most sensitive fields.

The five iterations read as an escalating search. The operator starts by asking the framework for its own configuration, then dumps the environment, then sweeps the heap, then brute-forces hex, then starts hashing anything that looks like a candidate. That progression is what running out of options looks like, and one ordinary control is what put them there.

</details>

This is a finding and not a caveat. In a campaign that is overwhelmingly capability and not outcome, a well-tested negative bounds the harm. This one says that the most sensitive fields the operator was pursuing were not obtained through the route the operator took. That is a materially different harm profile from the one a capability catalog alone would imply. The sub-effort stays at attempted.

---

## 5. Anchor 2: Quanzipin, the Clean and Fixable Exposure

An unauthenticated database-monitoring console handed a threat actor the full data model of a live production platform, and the platform has since closed it. This is the most actionable finding in the investigation. It is concrete, the fix is unambiguous, and the boundary of the harm is knowable. It is also the only target here with a registered legal entity behind it, which made it the one exposure that could actually be reported to someone. It is also the clearest teaching case here: the harm from an exposed monitoring console is what an attacker learns, and that knowledge does not expire when the console is closed.

### 5.1 The target

`web.51qzp[.]com` belongs to 全咨聘（雄安）科技有限公司, Quanzipin (Xiong'an) Technology Co., Ltd., a construction and engineering cost-consulting gig-work platform. It is the only target in this investigation with a confirmed registered legal entity, itself notable given Section 9.3.

The platform is built on RuoYi (若依), a widely used open-source Spring Boot and MyBatis application framework, deployed as a single fat JAR under a BT/aaPanel hosting convention. That stack combination is common across Chinese small and medium enterprise hosting, and its default component set is exactly what this operator's port profile hunts.

### 5.2 What the Druid console exposed

Alibaba Druid is a database connection pool, and it ships with an optional monitoring servlet that renders live statistics about every query the application runs. Where that servlet is reachable without authentication, anyone who finds it can read the application's entire database interaction history.

At time of capture, this console was reachable without authentication on port 8157 and exposed:

- The production database connection string, including host, port and the schema name.
- The fact that the application connects to its database as `root`.
- The full 93-table schema.
- 427 distinct API endpoints.
- 830 real SQL statements as executed by the application, with execution counts.

Real traffic counters confirm a live production system, not a staging environment, showing 68,247 requests and 2,865,801 JDBC executions against a pool whose activity records reach back to early May 2026.

The highest-volume sensitive query runs more than 53,099 times on its own, with tens of thousands more across near-duplicate variants, and it pulls the password field, a separate financial PIN, the national identity number, the mobile number and a messaging identifier together out of the member table in one go. Eighty-two queries in the captured set touch credential-adjacent fields.

An attacker reading that console does not need the data to benefit from it. They now know exactly which query to aim at.

### 5.3 The distinction that carries this finding

Careless reporting here would do real damage to a real company, so the boundary is explicit.

Two things are CONFIRMED. The query text, schema and execution statistics went to anyone who could reach the unauthenticated monitor, and this operator took them: their own directory holds the full set of captured console pages. That is a genuine information-disclosure vulnerability on its own terms. Separately, the data-access layer pulls password hashes, wallet PINs and government identity numbers together, in bulk, at high frequency, and no attacker is needed for that to be a problem. It is how the application was built, and it would be worth fixing even if nobody had ever found the console.

What the console never shows is returned data. Druid renders bound parameters as placeholder characters, so nothing captured here proves that a password, an identity number or a financial PIN ever reached a client.

And the database password was never disclosed at all. The console gave up the connection details, the schema and the `root` username, and stopped there. There is no evidence the operator obtained the password, so this report does not describe them as holding a working credential for this platform.

### 5.4 Current status

The console appears remediated. A read-only re-check on 2026-07-20 found `web.51qzp[.]com` resolving NXDOMAIN and port 8157 closed. This exposure is described throughout as live at time of capture, never as currently live. The remediation is independent of this investigation's disclosure timing.

### 5.5 What else was directed at this platform

The operator walked consecutive record identifiers from 116270 to 116277 against an engineer-detail endpoint. That range is too tidy to be guesswork, so they were almost certainly reading from a listing page or an earlier response, and the identifiers line up with real gig-worker records at MODERATE confidence.

They also pointed an arbitrary-file-retrieval test at a document-download endpoint, built a 248-entry password wordlist keyed to this brand, and aimed both the SnakeYAML and Logback chains from Section 6 here.

The operator also used this platform as the source of a valid session token in a cross-platform token-replay test, registering a throwaway account here and then replaying the resulting token against an unrelated platform's user-information endpoint under four different header names, testing whether the two shared a backend or a token-signing key. No success artifact exists for that test.

### 5.6 What this means

The business impact outlasts the fix. After a monitoring console is closed, the organization has fixed the exposure but not the consequence. The actor retains the complete schema, the API surface and the business logic. That knowledge supports precisely targeted future attempts against the same platform without any further reconnaissance, which is why credential rotation is a reasonable precaution here even though no password was disclosed. The knowledge does not expire when the port does.

For detection, any HTTP 200 response on a Druid console path from an external source is worth alerting on regardless of actor.

Two design points matter for anyone writing that rule. Do not anchor it to ports 80 and 443, because this instance ran on 8157. And pair the path match with a response-body check for a Druid-specific field name, so the rule does not fire on unrelated paths that happen to contain the same directory name. Published coverage is in the [detection rules file](/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/#sigma-rules).

One useful negative turned up elsewhere in the campaign. A second Druid instance was found on a different target in this investigation and was properly protected behind a real login. The exposure is not inherent to the software. It is a deployment choice.

---

## 6. The Exploitation Toolkit: Eight Commodity Technique Classes

No exploitation class in this toolkit is novel and none is a zero-day. All eight exploitation technique classes come from the well-documented public record with mature proof-of-concept code available, and that is what makes the campaign transferable instead of a curiosity: these are the techniques a defender will actually meet. The gap worth acting on is that six of the eight had no published Sigma, Suricata or YARA coverage before this investigation. A fully commodity technique set with no shipped detection is a live defensive hole, and closing it does not depend on this operator staying active.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/multivector-ecommerce-rce-toolkit-192-3-1-116/multivector-eight-technique-classes.svg" | relative_url }}" alt="Three-column grid infographic titled Eight Commodity Technique Classes, arranged in rows of three, three and two. Six cards carry grey bands indicating no evidenced success: Logback insertFromJNDI, CVE-2021-42550, where the chain stalled at bind in both logged attempts; Logback FileAppender arbitrary file write aimed at dropping a JSP, with no victim deployment observed; SnakeYAML deserialization of the CVE-2022-1471 family using a ScriptEngineManager gadget, with no confirmed execution; Eureka with XStream service-registry deserialization, where a real target engaged and registered but the success callback was never observed; XXE to server-side request forgery including the cloud instance metadata endpoint, where payloads were crafted but no result was captured; and SSRF to Redis CONFIG abuse writing an authorized SSH key for passwordless root, attempted but not evidenced. Two cards carry red bands indicating they produced access or data: Jolokia and JMX abuse, management-interface access reached with no restrictor configured at time of capture, assessed as the likely master access vector; and the unauthenticated Druid console StatViewServlet exposure, which disclosed the full data model and the root username only, not the password.">
  <figcaption><em>Figure 4: Every technique class in the toolkit is public, documented and years old. The significant gap is not novelty but coverage, and the table below records what existed for each class before this work.</em></figcaption>
</figure>

| Technique class | Public status | Existing published detection coverage before this work |
|---|---|---|
| Logback `insertFromJNDI` (CVE-2021-42550) | Disclosed 2021, mature proof-of-concept | None found |
| Logback `FileAppender` arbitrary file write | Documented framework behaviour | None found |
| SnakeYAML unsafe deserialization (CVE-2022-1471 family) | Disclosed 2022, mature proof-of-concept | None found |
| Spring Cloud Eureka with XStream deserialization | Documented technique, no assigned CVE for the delivery chain | None found |
| XXE to SSRF including cloud instance metadata | Documented since at least 2019 | None found |
| SSRF to Redis configuration abuse to SSH key write, including gopher-scheme smuggling to MySQL | Widely documented | Published Sigma rule from prior work in this research program |
| Unauthenticated Druid monitoring-console exposure | Documented misconfiguration class | None found |
| Jolokia and JMX management-interface abuse | Documented; the log-verbosity variant is thinly covered | Thin coverage for the general technique, none for the log-verbosity variant |

Only one of the eight had a rule published against it before this work, and that rule came out of an earlier investigation in this same research program. Jolokia is the thin case: the general technique has some coverage, the log-verbosity variant none. Between them they show how narrow the published corpus is for this technique family.

Two of the eight repay a close read even though neither produced a result. The Redis chain (Section 6.6) and the cloud-metadata payload (Section 6.5) both require understanding the seam between several systems, and both were correctly built. They sit a clear step below the log-verbosity technique in Section 4.3, the only thing here I would call original, but they are the best of the borrowed work. The rest is competent assembly of public material.

<details markdown="1" class="hl-teardown">
<summary>Expand the full per-class mechanics (6.1 to 6.8), including the payload construction and the detection design for each.</summary>

### 6.1 Logback insertFromJNDI, CVE-2021-42550

Log4Shell dominates public discussion of logging-framework remote code execution. Logback's own JNDI-lookup vulnerability landed in the same disclosure window and is comparatively under-documented, which makes a captured working payload for it a useful artifact.

A working captured payload for this one is more useful than another write-up of the vulnerability class, so it leads the teardown. It is 220 bytes and points a vulnerable Logback-configured Java application at the operator's own rogue directory server on the standard rogue-JNDI port. The infrastructure link is what elevates this from a catalogued vulnerability to an observed technique: the callback target is this operator's own address, already backed by the operator's own directory-server scripts and setup tooling. The capability was not sitting unused. It was pointed at a real Logback-based target.

It never landed. Both logged engagements with the operator's directory server stalled at the bind step without issuing a search request, and this payload depends on that same completion step (Section 7.2).

To detect it, the two-string combination of the JNDI-insertion element together with an LDAP-scheme value inside a logging configuration element is the discriminator. The insertion element is rare in benign configuration, and pointing it at an attacker-controlled scheme is the exploit itself. This generalizes to any instance of the vulnerability, not to this operator.

### 6.2 Logback FileAppender arbitrary file write

An entirely separate route through the same logging library. Rather than fetching remote code, this payload configures the library's file-writing component to write its output to a path ending in `.jsp` inside a web server's temporary document directory. The application then, in the ordinary course of logging, writes an attacker-controlled file into a location the web server will execute.

The destination path in the captured payload includes a port number that matches the web-server connector port independently observed in a target's own management-endpoint log, which suggests this payload was tailored to a specific observed target, not copied generically.

Detection here is unusually easy. A file-writing log appender configured with a destination ending in `.jsp` is never legitimate, and that destination is the entire signal.

### 6.3 SnakeYAML unsafe deserialization

The captured document is a textbook `ScriptEngineManager` / `URLClassLoader` gadget chain, all on one line, pointing at the operator's shared callback listener. It is the same technique family as CVE-2022-1471.

This is the one payload in the corpus with no sign of tailoring at all. The Logback file-write in 6.2 carries a destination port matched to a real observed target; this one is the public proof-of-concept with the callback host swapped in, nothing more. Its callback path even follows the same naming convention as the Eureka and JNDI callbacks, which is the operator's shared listener set showing through again.

For detection, the three-string combination of `ScriptEngineManager`, `URLClassLoader` and the URL constructor is high precision. In transit this content most often arrives with a YAML or plain-text content type, and sometimes as multipart form data on file-upload endpoints, which is worth accounting for in any network rule.

### 6.4 Spring Cloud Eureka with XStream deserialization

A hostile registry entry reaches every client that fetches the next delta, and where the client deserializes it unsafely the code runs on the client, not on the registry.

This is the technique class with the richest outcome evidence in the campaign, and it is covered in Section 7.1 because the outcome, not the payload, is the finding. The operator ran a three-stage escalation ladder of increasingly capable registry servers against a live target that was already polling for updates.

The detection direction that matters here is inbound to the registry client, not outbound from the attacker. A registry delta response whose body carries deserialization gadget markers such as a process-builder or runtime class reference is the high-value event, because it catches the payload arriving at the system that would execute it.

### 6.5 XXE to server-side request forgery, including cloud instance metadata

Several XML and SVG payloads are present. Two are straightforward local file and process-environment reads, the second of which is the more consequential, since Linux application-server environments commonly carry API keys and database credentials.

The standout is a single SVG that probes four internal targets at once: the local management endpoint, the local Redis instance, the local database port, and the cloud instance metadata service at `169.254.169.254`. The metadata target is what separates this from routine internal port discovery. Reaching a cloud provider's instance metadata service through server-side request forgery is the technique class behind the Capital One breach: it can leak the host's own cloud identity credentials, not just internal service banners. In a toolkit whose quality is otherwise uneven, this specific payload shows real understanding of server-side request forgery impact. A companion file is a single-entity version of the same idea, and a third is a minimal textbook cross-site-scripting proof, which together read as someone working up from the simple case to the one that matters.

The payload is confirmed present and crafted; its outcome is not. No captured response shows the metadata service was reached.

Two implementation details matter. The XML payloads use the sequential placeholder phone number `13912345678` and a password field carrying the well-known MD5 hash of the string `123456`, which confirms these are hand-crafted test documents, not replayed real submissions. The second detail is also a finding about the target: its registration and login API expects a client-side MD5-hashed password, an unsalted anti-pattern that is independent of whatever the server does downstream.

An external-entity declaration referencing the cloud metadata address inside an uploaded XML or SVG document is a high-precision signal. Broader variants covering entities that reference local Redis, local MySQL or local management endpoints are worth carrying as separate rules so severity can differ, since cloud credential theft is materially more serious than internal service discovery.

### 6.6 SSRF to Redis configuration abuse to SSH key write

This is the most technically advanced thing the operator borrowed, a clear step below the log-verbosity work in Section 4.3 but the best of the public material. The script injects Redis protocol commands, CRLF-separated, through an SSRF vector reachable from an image-processing feature. It issues `CONFIG SET dir`, `CONFIG SET dbfilename`, `SET` and `BGSAVE` in sequence to write the operator's own SSH public key into `/root/.ssh/authorized_keys` on the target, aiming at passwordless root access.

The same script builds raw `gopher://` payloads carrying a MySQL client auth handshake against an internal database address, and attempts `file://` reads of `/root/.ssh/id_rsa` and `/etc/passwd`.

Chaining SSRF into Redis `CONFIG SET` to land a key in `/root/.ssh/authorized_keys` requires understanding three systems and the seam between them. Smuggling a raw database client handshake through a gopher-scheme request is uncommon and was correctly constructed here. Of everything the operator borrowed, this is the file that best shows real knowledge underneath the generated bulk, the distinction Section 3.2 turns on.

It was attempted at HIGH confidence, with no confirmation that the write succeeded on any target.

Two independent signals catch it. At the network layer, Redis verbs arriving over a non-Redis transport, CRLF-embedded in HTTP, are the discriminator. On the host, a change to `dir` or `dbfilename`, or an unexpected entry in an `authorized_keys` file, is the outcome signal. The gopher scheme and a raw database client handshake preamble inside an HTTP parameter or body are rare enough in benign traffic to be high-precision on their own.

### 6.7 Jolokia and JMX management-interface abuse

This is the class that did the most damage in the campaign, and Section 4.3 covers the harvest it enabled in full. What belongs here is the surface itself. Jolokia exposes the application's managed beans over ordinary HTTP, so anyone who reaches it unauthenticated can read and write live configuration, which is how a logging level becomes an attacker's data-collection switch. The target's own captured configuration reported no access restrictor and access to any managed bean allowed. Detection splits the same way as the abuse: alert on any external write to a Jolokia or JMX endpoint, and alert far harder on one that changes a logging level.

### 6.8 The staged web shell

A minimal but fully functional generic JSP web shell sits in the operator's directory: it reads a single HTTP parameter, runs its contents through the shell, and returns standard output and standard error.

Two of the exploitation techniques above are armed to deliver this one payload. The Logback file-write route writes it directly. The Eureka registry-poisoning route causes a client to fetch it over HTTP from the operator's host.

Deployment to any victim host is UNCONFIRMED. It exists in the operator's own directory, which is DEFINITE, and it was never observed staged on any target. It is a hunt target, not an assumed finding, and any defender using it that way should treat a negative result as the expected outcome.

Any rule for it should keep the string set generic, because the parameter name will vary in the wild. The durable pair is the proximity of an HTTP parameter read to a runtime execution call.

</details>

### 6.9 What the toolkit's failures reveal

Real, working exploitation payloads coexist here with a download and tooling pipeline that plainly did not work, and that contrast feeds the capability assessment in Section 11.2 directly. Several files' names substantially overstate their contents.

| File | Actual content |
|---|---|
| A well-known JNDI exploitation archive | 9 bytes, a generic empty or error response blob, not the real tool |
| A deserialization exploitation JAR | 0 bytes |
| Three separately named probe results | Byte-identical 1,747-byte generic blocked-response pages, not the application files their names imply |
| A database file | 14 bytes, containing the literal string `404: Not Found` |
| An Android application build | 430 bytes, a cloud object-storage "no such key" error, confirming the operator was pulling builds from cloud storage and that this request failed |
| A heap dump | 539 bytes, not a real heap dump |

Six confirmed failed fetches plus three duplicate generic responses, all saved anyway under names implying real content, and most of the promising filenames dissolved into error pages once opened. One of the byte-identical files is worth a specific correction: its filename matches a production application JAR that genuinely exists on a target platform, and that is why the operator tried to fetch it. The fetch was blocked. It is not a JAR and it is not a backdoor.

Also present are brute-force input wordlists, which are frequently misread as harvested credentials. A 28-line list mixes generic weak passwords with brand-customized guesses derived from the target's own name. Brand-specific lists exist for two further target clusters, including a 248-entry list for Quanzipin. A filename ending in `_pass.txt` is a shape heuristic, not a content verdict, and treating a guess list as stolen data is a known failure mode in this kind of analysis.

---

## 7. Observed Outcomes: What Was Achieved Versus What Was Built

Outcome artifacts exist for six separate exploitation efforts in this campaign, and five of the six are negative. That ratio is the calibration that matters most here. Most published threat reporting describes what an attacker's tools can do, because a captured tool is all there is to describe. Here the operator's own logs, error messages and result files survived alongside the tooling, so it is possible to say what actually happened, and most of what happened was failure. A reader who treated the toolkit inventory in Section 6 as a breach summary would overstate the harm by a wide margin.

Nothing here is called a compromise unless a captured outcome backs it, and an operator's own optimistic comment in their own script counts for nothing. That rule is why the ledger at the end reads thinner than the technique list at the start. A capability catalog dressed up as a breach report is worse than useless to whoever has to act on it.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/multivector-ecommerce-rce-toolkit-192-3-1-116/multivector-built-vs-achieved.svg" | relative_url }}" alt="Two-column comparison infographic titled What Was Built Versus What Was Achieved. The left column, headed built with no evidenced success, holds five grey-banded cards: Logback insertFromJNDI with a rogue LDAP and JNDI server stood up on port 1389, where the chain stalled at BindRequest with no SearchRequest following in both logged attempts; Spring Cloud Eureka with XStream, where a rogue registry engaged a real target that registered a service but the success callback was never observed across roughly seventeen thousand access-log lines; SnakeYAML deserialization with a crafted ScriptEngineManager gadget document and no confirmed execution; XXE to server-side request forgery including cloud instance metadata, crafted and delivered with no captured outcome; and a staged JSP web shell existing only in the operator's own directory, with deployment to any victim host unconfirmed. The right column, headed achieved via misconfiguration, holds three cards: unrestricted Jolokia and Actuator in red, the likely master access vector that yielded heap dumps and a database credential; the unauthenticated Druid console in red, exposing the JDBC URL, ninety-three-table schema, four hundred and twenty-seven endpoints, eight hundred and thirty SQL statements and the root username but not the password, exposed at time of capture and later found remediated; and confirmed harvest in deep red, real customer names plus order and financial records for at least five named individuals.">
  <figcaption><em>Figure 5: The report's central inversion, in one view. Five remote-code-execution technique classes produced nothing, while every confirmed loss traces to a management interface someone left reachable.</em></figcaption>
</figure>

### 7.1 Eureka and XStream: engaged, outcome not evidenced

A real multi-step protocol engagement occurred here, spanning at least eight minutes of continuous interaction with a real target, which makes this the most complete attack sequence in the campaign. It is also the clearest example of why an attacker's own logs cannot be taken as proof of success.

The target, an unnamed Spring Cloud deployment sharing internal infrastructure with the confirmed-theft platform, registered a service named for a widely used API gateway component at an internal address, polled the registry's delta endpoint repeatedly, then cleanly deregistered.

Whether the payload ever executed is the open question, and the answer is a qualified no. Confidence sits at **MODERATE that the callback did not fire**, resting on the operator's own callback-host access log showing zero hits across 17,087 lines. The honest gap is that the log window begins roughly 68 to 76 minutes after the engagement concluded, so a callback inside that earlier window cannot be ruled out from the available files. This is not remote code execution disproven. It is the strongest available negative evidence, and it should be read as exactly that.

<details markdown="1" class="hl-teardown">
<summary>The three-stage escalation ladder, the negative evidence and its timing gap, and the self-inflicted evidence gap. Click to expand.</summary>

Across that window the operator swapped tool versions in real time while the target was already polling, running a three-stage escalation ladder on the same port:

They opened with an inert decoy, 684 bytes, serving a static application list and logging what asked for it. It threw errors on write methods because it never overrode those handlers.

They swapped in a verification tool next, one whose default payload is a bare success-beacon request, and its own log records it returning the deserialization payload eight times across the session.

Then they put up the objective tool: same serving logic, but the payload now pulls the staged web shell from the operator's own host.

All three share the same behaviour pattern: serve two legitimate application-list responses, then switch to the malicious payload on the third and subsequent polls.

The server's claim of what it sent is **not proof** of what the target did with it. The proof point would be the success callback, and the operator's own access log for the callback host, 17,087 lines covering roughly fourteen hours, contains zero matches for any of the three success-callback paths used across this campaign's exploitation classes. That is the basis for the MODERATE negative stated above.

A second evidence gap is self-inflicted, the one Section 3.2 reads as the clearest tell of generated code. The objective tool's logging override contains a string-formatting defect that causes it to print literal placeholder text instead of the client address. Its logs therefore record that the malicious payload was served on the third, fourth and fifth requests, but cannot say which client received it. The only attributable addresses in those logs appear in connection-reset error traces, meaning clients that disconnected before completing a request.

The operator destroyed their own best evidence and never noticed. Had that one line worked, this section would either confirm a remote code execution against a real target or rule it out, and the whole outcome ledger would read differently. A doubled brace is the reason it does neither. It is also the kind of mistake anyone who has shipped generated code has made, and that is why I read it the way Section 3.2 describes.

</details>

### 7.2 LDAP and JNDI: stalled at bind in both logged attempts

The chain needs a bind and then a search; the payload rides in the answer to the search. Here the bind happened and the search never did.

Across the two attempts with full logging, the target connects, sends a real BER-encoded LDAP bind request, receives a bind response from the rogue server, and then the rogue server times out waiting for a search request and the connection closes. The client bound but never issued the search request that would retrieve the malicious entry. This matters directly for the Logback JNDI payload in Section 6.1, which depends on the same completion step.

One detection point here matters more than it first appears. Because the chain stalls after bind, the bind alone is the detectable event. A detection strategy that waits for a successful search would have missed this activity entirely. Any rule for outbound JNDI callbacks should fire on an LDAP bind request to a non-standard directory port from an application server, without requiring the follow-on search.

### 7.3 Brute force against a third platform: executed, defended successfully

A results file from a different target cluster is a clean outcome artifact. It records a password brute-force run reaching attempt seven of eight, receiving an HTTP 400 response with an account-lockout error and a vendor-specific error code, and the script stopping because of the rate limit.

Two facts separate cleanly here. The tooling was executed against a live production login endpoint for real, and the target's own rate limiting worked and stopped it. No successful login is shown or implied.

### 7.4 Management-endpoint probes against a fourth target: blocked cleanly

The operator probed six management endpoints here, environment, beans, conditions, configuration-properties, mappings and heap-dump, and got the same answer six times. Each came back HTTP 401 with an identical custom rejection message, only the endpoint name changed, telling them authentication had failed and the resource could not be reached.

This is not the framework's default error format. The target wraps its management endpoints in its own authentication filter, and that filter worked as intended across all six. Two further probes against upload and preview endpoints hit the same filter.

Mixed success against hardened management endpoints is the norm across this operator's target set, not the exception. Targets that closed their management planes were not compromised through them.

### 7.5 A second platform: authenticated access through a self-registered account, no confirmed theft

On `chengjiastore[.]cn`, the operator registered a real account. Registration and login both succeeded, and the returned token decodes to a real created account. A follow-on script then used that bearer token to enumerate administrative and system routes covering users, administration, orders, billing, configuration, system information and debug endpoints.

The register-then-authenticate-then-enumerate pattern is confirmed reused across at least two separate target platforms, which makes it a standing technique for this operator and not a one-off. Four throwaway accounts are identified across the campaign, with tokens shared between scripts through a file on disk instead of each script re-authenticating.

I can call it DEFINITE that the registration succeeded, that the operator authenticated with the resulting token, and that administrative and system routes were then enumerated. No successful administrative access is recorded and there is no confirmed data theft.

Registration was open to the public by design, so calling this access unauthorized is not itself an observation. It follows from the conduct judgment in Section 2.2, which I hold at HIGH, around 85 percent.

An account registration followed within minutes by that same account's token probing administrative routes is a high-signal sequence, because ordinary new users do not visit administrative endpoints in their first session. This is one of the more transferable behaviours in the campaign and is covered by a published correlation rule.

### 7.6 Credentials the operator holds, and their status

Values are withheld from this report and from the IOC feed, because publishing a victim organization's live credential, even defanged, is a disclosure hazard and not an intelligence contribution. What matters analytically is the status of each, and one detail that runs across the table is worth stating first: the two credentials most clearly in live use appear in none of the operator's brute-force wordlists, so how they were obtained is undocumented anywhere in roughly 450 files. That unexplained origin is one of the still-open threads in this case, and the unrestricted management interface in Section 4.2 is the leading candidate, not a demonstrated answer.

<details markdown="1" class="hl-teardown">
<summary>The per-credential status table. Click to expand.</summary>

| Credential class | Status |
|---|---|
| A production database password on the confirmed-theft platform | Believed real and actively used, not a guess candidate. Embedded in the hex payload of a live raw protocol-smuggling handshake against an internal database address. Origin unresolved: it appears in none of the brute-force wordlists. |
| A cache password on the same platform | Believed real and actively used as a live credential in the server-side request forgery chain. A fragment appears twice in each of two heap dumps, the only credential with any memory footprint. |
| HTTP Basic Auth for an API documentation endpoint | Believed working, based on the operator's own annotation on a related endpoint. Not confirmed by any captured authenticated response. If genuine, it gives authenticated visibility into the complete administrative API surface. |
| An API request-signing key on a different target group | Confirmed cracked. Used directly and without further testing after a systematic seven-variant algorithm test, which implies the earlier signature-forgery effort succeeded. |
| An administrative password candidate | Used as a direct high-confidence login attempt. No confirmed success. The script is written to distinguish a definitive failure from a service-unavailable response, meaning the operator was waiting out a target outage instead of concluding the password was wrong. |
| The Quanzipin database `root` account | **Username only.** See Section 5.3. The password was not disclosed and there is no evidence the operator obtained it. |
| Six session tokens | Real-format tokens. Three decode to the operator's own throwaway accounts. One belongs to a system not otherwise mapped in this investigation, carrying a subject identifier that matches nothing else in the corpus and a validity window of roughly 208 days. |

</details>

### 7.7 The outcome ledger

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

## 8. Operator Infrastructure and Control Plane

The operator runs one host that does everything, wrapped in three independent and non-overlapping obfuscation choices. Consolidation on a single platform is why the exposure of one open port revealed the entire operation, including the agent console described in Section 3.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/multivector-ecommerce-rce-toolkit-192-3-1-116/multivector-operator-platform.svg" | relative_url }}" alt="Three-column grid infographic titled One Host, Five Roles, One Evasion Layer, arranged in rows of three, three and two. The first five cards describe what the single host ran. Three red cards: an open working directory on port 7777, a plain static file server that was publicly listable, which is why the outcome artifacts survived alongside the tooling, still serving as of 21 July 2026; a rogue directory server on port 1389 acting as the JNDI callback target for the Logback payload; and a shared callback listener on port 9876 reused across otherwise unrelated exploitation classes, indicating one listener set rather than one per technique. Two grey cards: a self-hosted VPN with a dynamic-DNS hostname resolving to the same address, described as operator convenience rather than victim-facing; and an agent framework running as root, off-the-shelf open-source software cloned from public repositories and driven from a consumer messaging platform, with execution of any attack explicitly unconfirmed. Three yellow cards describe the evasion layer: a proxied control source most likely shared rented proxy egress and therefore not an identity anchor; a serverless attack relay on legitimate cloud infrastructure confirmed across two independent attack types; and a budget hosting posture on a mainstream low-cost provider rather than bulletproof hosting.">
  <figcaption><em>Figure 6: The entire operation ran from one budget virtual private server. The three evasion elements are worth noting for what they are not: they do not connect to each other and none pivots to sibling infrastructure.</em></figcaption>
</figure>

<details markdown="1" class="hl-teardown">
<summary>The full platform inventory, component by component, with per-item confidence. Click to expand.</summary>

| Component | Detail | Confidence |
|---|---|---|
| Primary host | `192.3.1[.]116`, AS36352 (HostPapa), United States. Open directory on TCP/7777 served by a Python static HTTP server. | DEFINITE |
| Rogue directory server | `ldap://192.3.1[.]116:1389/cn=exploit`, backed by the operator's own directory-server scripts and setup tooling. | DEFINITE |
| Shared callback listener | TCP/9876, reused across otherwise unrelated exploitation classes: Eureka XStream, SnakeYAML and the JNDI chain. The operator runs a small reused listener set, not one per technique. | DEFINITE |
| Success-beacon path | A dedicated path on TCP/7777, never observed hit. | DEFINITE |
| Staged payload URL | `hxxp://192.3.1[.]116:7777/cmd[.]jsp`, confirmed present and downloadable. Serves source only. | DEFINITE |
| Attack-traffic relay | `cs-pgcwufmiws[.]cn-hangzhou[.]fcapp[.]run`, a legitimate Alibaba Cloud Function Compute serverless endpoint reused as a proxy. Confirmed across two independent attack types against the same target. | DEFINITE |
| Operator VPN | Self-hosted SoftEther VPN on the same host, DDNS hostname `vpn932081317[.]softether[.]net`, still resolving to the platform address. | HIGH |
| Control-source address | `31.22.111[.]190`, the address the operator connects from to administer the host. Identical connection-environment values across two independent captures. Most likely shared rented proxy egress, not operator-controlled infrastructure, so it is not an identity anchor and must not be used to cluster future activity. | HIGH that operator traffic originated here, MODERATE that the address is operator-controlled |
| Build-host identifier | An unmodified default SSH key comment referencing a budget VPS provider instance, shared across three distinct RSA-2048 key pairs with different fingerprints, and authoring the git clone records for the framework plugins. | HIGH |
| Control channel | A commercial messaging platform group chat with one identified controlling user, wired into the agent framework running as root on the host. | HIGH |

</details>

On the hosting, AS36352 is not bulletproof. It is a mainstream budget provider, assessed at HIGH confidence. The operator's control-source address sits on a small IP-leasing reseller network, and reverse resolution on it returned two hostnames whose numbered-node naming, privacy registration, regional DNS and CDN alias chain match the shape of a commercial proxy-subscription service. That reading is MODERATE, and it matters: it means the control-source address is most likely shared rented egress, not operator-controlled infrastructure, so it should not be used as an identity anchor. Reverse-pivoting a shared proxy network returns other customers, a co-tenancy trap that produces false links.

The three obfuscation choices do not cluster. The self-hosted VPN, the proxy egress and the serverless relay do not pivot to any sibling infrastructure and do not connect to each other technically. They read as three independent single-use decisions, not a designed operational-security architecture, which fits the rest of this operator's profile.

The tempo is steady and unhurried. One host has run continuously since at least April 2026 with no observed address rotation. A single SSH host-key rotation around 2026-01-01 reads as a rebuild or re-provision event. The directory was still live and growing as of July 21, 2026.

---

## 9. The Wider Target Landscape

Twelve to fourteen entities show up across five corporate groups and at least seven loose threads, and once you step outside the two anchors, none of them were compromised. The operator looked, probed, and moved on.

So this section sorts them by what actually happened instead of inventorying every asset, because the quickest way to write a misleading threat report is to list a dozen names under a heading and let the reader assume they all fell. Everything below belongs to a business that was targeted, not to the attacker. None of it belongs on a blocklist.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/multivector-ecommerce-rce-toolkit-192-3-1-116/multivector-target-landscape.svg" | relative_url }}" alt="Process-tree infographic titled The Target Landscape, with the operator platform at 192.3.1.116 as the root node and six branches, each carrying a coloured side-rail indicating outcome. Branch A, deep red, a rent-to-own commerce platform with confirmed data theft: real names plus order and financial records for at least five named individuals, four independent sourcing channels, and an armed account-takeover weapon staged against a staff account that was never confirmed fired. Branch B, red, a construction-cost consulting platform with confirmed exposure: an unauthenticated database console disclosed a ninety-three-table schema, four hundred and twenty-seven endpoints, eight hundred and thirty SQL statements and the root username at time of capture, later found remediated, and it is the only target with a confirmed registered legal entity. Branch C, yellow, a four-product commerce group linked as sister products by shared frontend build artifacts, showing reconnaissance plus unconfirmed brute force and one confirmed information disclosure. Branch D, yellow, a second commerce platform where account registration, login and administrative-route enumeration occurred through a self-registered account with no successful administrative access and no confirmed data theft. Branch E, grey, insurance asset management and others including a ledger product, a dating platform, a mobile-OEM developer API and several unidentified probes, all attempted and none confirmed compromised. Branch F, grey, a loan-referral API with unresolved ownership where records were definitively returned but ownership and authenticity are insufficient, so no victim is named.">
  <figcaption><em>Figure 7: The full target set, colour-coded by what the evidence actually supports. Most branches are attempted, not compromised, and the distinction between them is the discipline this report is built on.</em></figcaption>
</figure>

Nearly all of it sits on two large Chinese cloud providers, behind the same hosting panel, running the same handful of application frameworks. That looks like a connection until you remember that this is what ordinary small-business hosting in that market looks like. It says the operator picked targets from one ecosystem, and nothing more than that. Do not read it as a link between the targets themselves.

<details markdown="1" class="hl-teardown">
<summary>The per-thread breakdown: what each group is, how it was linked, and what the evidence supports. Click to expand.</summary>

| Thread | Nature | Outcome status |
|---|---|---|
| Group A, a four-product sister estate covering device rental, an e-commerce mall, a consumer application and credit rental | The strongest infrastructure finding in the campaign. Linked by three independent evidence types: the operator's own labels, identical front-end production-build asset hashes across two administrative panels, and a live TLS certificate on the host the operator itself labelled as the main server. The build-hash match is the one that carries it, because it does not depend on trusting the operator's labels at all. | Recon, a four-phase kill chain, unconfirmed brute force, SQL injection routed through the serverless relay, and one confirmed information disclosure: uncaught framework routing exceptions leaked an internal deployment codename on five of thirteen probed routes during an automated discovery burst. No confirmed compromise. |
| Group C, a cluster spanning a ledger application, a store platform and a matchmaking platform | Confirmed as one cluster by a password list pairing candidates from all three brands against the same login endpoint. A vendor-specific rate-limit error code separately tied an earlier, previously unattributed brute-force attempt to this same cluster. | Brute force, rate-limited and stopped. A phishing lure image. A planned but unattempted next password round. No confirmed compromise. |
| Group E, an insurance asset-management firm | Refined from a generic finance classification through the corporate portal's own footer links to the national financial regulator and the insurance asset-management association. The public application is a conference-booking system. | Attempted only. The evidence for controls holding here is **substantially silence** rather than a positive defensive result: eight of twelve captures are session-cookie churn with no recorded outcome. Login and injection attempts show clean rejections, and one probe triggered an unhandled server error, a stronger signal but not conclusive. A second, properly protected Druid instance was found here, which is useful negative evidence. |
| A mobile-OEM developer platform | A major smartphone manufacturer's developer API, fuzzed across 31 by 31 service and method combinations, plus two JavaScript secret-hunting scripts against downloaded bundles. This is a materially different class of target from the small and medium platforms everywhere else in the corpus. | Attempted, no captured outcome. Three application pulls were blocked at what appears to be a content-delivery layer. **That attribution is apparent rather than confirmed:** the source URL that would identify which control blocked them was never captured. |
| A cross-platform token-replay target | Reached by replaying a token obtained from an unrelated platform under four different header names. | Relationship and outcome unresolved. |
| Standalone and emerging threads | An unnamed messaging-platform mini-program referenced only in code comments; a legacy PHP-framework host disclosing a full hosting-panel server path through verbose stack traces; a live-probed enterprise mail deployment whose operating organization is unidentified despite fourteen reviewed files; a sustained single-target effort against a platform that was never identified, the deepest per-target tooling investment here, still with no name attached to it; a loan and credit referral affiliate platform; and four unidentified web probes. | Attempted or reconnaissance only. Several unidentified. |

</details>

### 9.1 The loan-referral finding, with its ambiguity front and centre

A captured response from a cash-loan referral backend came back holding real, paginated personal records, and the system reported 70,859 of them in total. About twenty are actually on the captured page. That 70,859 is the system describing itself, not a count of anything the operator carried away.

It is DEFINITE that records were returned to a client. Ownership and record authenticity are both INSUFFICIENT.

The problem is that the capture carries a logged-in session with no matching request, so there is no way to tell whether the operator broke into someone else's system or simply logged into their own. They run several loan and affiliate-marketing threads elsewhere in this corpus, which makes the second reading entirely plausible.

The records themselves deserve the same caution. Published research on this ecosystem documents that loan-referral lists get recycled between brokers and fabricated outright, so 70,859 rows is not 70,859 people until somebody proves it is.

So no victim gets named here and no record content is reproduced. The submitter addresses and personal details inside that response are somebody's private data, and they stay out of the IOC feed as non-indicators.

### 9.2 What the ecosystem context adds

The mix of targets, installment and rent-to-own commerce, credit rental, loan referral and recruitment, lines up closely with the Chinese grey-market personal-data-to-fraud ecosystem that several vendors have documented. That tells you what kind of operator this is, which is genuinely useful.

It tells you nothing about which one, and Section 11 keeps it that way. Reasoning from targeting to a name is the most reliable way to attribute activity to the wrong person, because thousands of operators share this exact target profile.

### 9.3 The content-provider filing signal, hedged and single-source

None of the four target domains checked came back with a content-provider filing. Mainland-hosted sites are legally required to carry one, so the absence hints that several of these platforms are unregistered, and it explains the practical problem that ran through the whole disclosure effort: for most of these targets there is no registered company to notify.

That is a MODERATE read on a single source, and it should be treated as one. The check ran against a commercial lookup service rather than the official national registry, which nobody queried directly at any stage.

Three innocent explanations are still wide open. The filing may sit under a parent domain while these are product domains, it may simply be lagging, or a platform may be non-compliant while otherwise running an ordinary legitimate business.

So no target in this report gets called a grey-market operator on the strength of a missing filing. It is a signal, it is not a finding, and nothing else in this report leans on it.

---

## 10. MITRE ATT&CK Mapping

Thirty-six techniques map across eleven tactics, and the attempted-versus-achieved split is carried inside the table rather than flattened out of it. That is why the per-row confidence column is retained here: a mapping that reads as thirty-six achieved techniques would describe a different and much worse campaign than the evidence supports.

<details markdown="1" class="hl-teardown">
<summary>The full technique mapping, with per-row confidence and evidence. Click to expand.</summary>

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
| Initial Access / T1190 | Exploit Public-Facing Application | DEFINITE (attempted) | Logback, SnakeYAML, XXE, Eureka XStream, UNION SQLi. No success artifact for any (see Section 7) |
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

</details>

### 10.1 Three mappings worth expanding

T1119 is DEFINITE, and it is the exception in a campaign that is otherwise capability without evidenced outcome. The distinguishing artifact is not the harvesting script but the operator's own retained dictionary mapping five real user identifiers to real personal names, commented as the known set from an earlier run. That is a record of a completed extraction, corroborated independently by live order identifiers recovered from heap memory.

T1531 stays MODERATE, and it is worth saying why. The account-takeover weapon is complete, pre-staged and immediately executable against a specific real staff account, with the replacement password written into all 10,000 requests. Nothing in the corpus shows whether it was fired or whether it succeeded. Rating it higher on the strength of how ready it looks is exactly the trap this report's calibration record in Section 14.4 exists to guard against.

T1552.005 is mapped on the payload and not the outcome. The metadata entity is unconfirmed as to result, but a correctly constructed one sitting alongside three internal-service entities in a single document is the mapping's whole justification. Section 6.5 covers why that combination is the serious one.

### 10.2 Deliberate coverage gaps

Exfiltration (TA0010) is not mapped, because those techniques presuppose data leaving a compromised host through a channel the adversary controls. Here the operator pulled data straight out of victim APIs over the victims' own HTTP interfaces, using valid or forged tokens and exposed management endpoints, which the Collection techniques above already describe correctly. Forcing T1041 or T1567 would misrepresent the mechanism.

Lateral Movement (TA0008) is not mapped either. No artifact shows movement between hosts inside any target environment, because every internal address in this corpus was reached from outside through server-side request forgery and protocol smuggling, never by pivoting from a foothold. Section 12 scores that absence at 2/10.

The agent framework has no clean mapping, and I did not force one. The closest candidates cover the messaging control channel and the framework's own execution backends, but none of them describes an AI console driving an operator's workflow, and stretching an existing technique to cover it would misrepresent both. The gap is recorded, not papered over.

Nothing under Impact maps beyond T1531. There is no ransomware, no wiper, no destruction, no defacement and no service disruption anywhere in the corpus. The objective is data, not damage.

---

## 11. Threat Actor Assessment

> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-2026-019 is an internal tracking designation assigned by The Hunters Ledger to actors observed across analysis who cannot yet be linked to a publicly named threat group. This label will not appear in external threat intelligence feeds or vendor reports, it is specific to this publication. If future evidence links this activity to a known named actor, the designation will be retired and updated accordingly.

No named threat actor can be attributed to this activity, and the reasoning behind that failure is itself worth publishing, because four separate attribution dimensions are not merely thin here, they are structurally empty.

The actor is unknown, and I put naming them at INSUFFICIENT, around 15 percent.

Every dimension that could produce a name comes back empty. There are zero infrastructure overlaps across four independent checks, no code to compare, commodity techniques that cannot cluster, and no vendor or government attribution to lean on. The only evidence pointing at an operator identity is a handful of unresolved fragments whose resolution paths run through law enforcement or platform cooperation.

What is missing is any link at all, of any strength, between an operator artifact and a catalogued entity.

Three things would move it. Resolving the build-host identifier against historical SSH host-key scan data. Resolving the messaging-platform identifiers through platform cooperation. Or seeing this operator's account-naming convention and log-verbosity harvesting technique recur in an unrelated future investigation, which would let them be tracked as a consistent entity even while unnamed.

The correct phrasing throughout is that **no public reporting was found**. This report does not use the words undocumented, novel, or previously unknown actor, because those claim knowledge about the world while the evidence supports a claim only about four catalogs.

<details markdown="1" class="hl-teardown">
<summary>Why each attribution dimension is empty, and what the emptiness itself indicates. Click to expand.</summary>

Infrastructure overlap comes back at zero across four checks, three of them independently re-run.

The operator platform returns no related threat actors at VirusTotal, re-verified live during this investigation, and no rows in the Hunt.io indicator feed. The Hunt.io threat-actor catalog was re-queried directly at the attribution stage and returns no actor association for either operator-side address, no indicator-feed rows for the platform, and no match for the activity profile. That catalog does independently record the operator directory as a malicious open directory, observed on 2026-06-03, which corroborates the finding itself while attributing it to nobody.

The control-source address likewise returns nothing, carrying two generic vendor flags with no actor or campaign label, which is the signature of routine abuse listing. Neither operator-side address has a historical certificate record, and a corpus search for the build-host identifier returns nothing at all. Only one check is carried forward instead of re-run, the TLS-fingerprint reverse-pivot.

This is not thin overlap. It is complete absence of the dimension.

TTP clustering is structurally unavailable. All eight exploitation techniques are drawn from the well-documented public record with mature proof-of-concept code. Commodity techniques cannot cluster to an actor, because their availability to everyone is what makes them commodity. The two most characteristic behaviours in this corpus, the log-verbosity harvesting technique and the register-a-throwaway-account-for-a-token technique reused across targets, are distinctive enough to serve as a tracking signature for this operator but match no reported actor's documented tradecraft.

Code similarity does not apply at all. There is no malware in this campaign. No implant, no loader, no packer, no custom protocol, no persistence binary. There is nothing to compute a similarity percentage against, and no such percentage appears anywhere in this report.

No Tier 1 or Tier 2 source names an actor.

**The most likely explanation for the absence** is a catalog coverage gap, not a genuinely unreported operator. Vendor catalogs are built around actors who cause reportable incidents at organizations that engage incident responders. An individual or very small crew harvesting personal data from small consumer platforms in one country generates neither.

</details>

### 11.1 State nexus: assessed and rejected

Nothing in this corpus supports a state nexus, and I hold that at **HIGH** confidence, around 90 percent.

This needs saying plainly, because a reader who sees "Chinese-language operator" beside a long exploitation-technique list may reach for a state framing unprompted. The operator's own labels, comments and target annotations are in Chinese and the targets are Chinese platforms. That supports a language and regional-orientation assessment. It supports nothing whatsoever about sponsorship, and conflating the two is one of the most common attribution failures in published reporting.

<details markdown="1" class="hl-teardown">
<summary>The six positive counter-indicators behind the HIGH confidence. Click to expand.</summary>

These are positive counter-indicators, not merely the absence of state indicators.

1. **Target selection is strategically worthless.** Rent-to-own consumer commerce, a matchmaking platform, credit rental, loan referral, a recruitment site. There is no government, defence, critical-infrastructure, technology-transfer or dissident-tracking target anywhere in the corpus.
2. **The targets are domestic.** A mainland-Chinese-oriented operator working almost exclusively against mainland Chinese small consumer platforms is directionally wrong for state-sponsored external collection, and the harvested material is monetizable, not intelligence-bearing.
3. **The tooling is entirely commodity.** Eight documented public techniques, no zero-day, no bespoke implant, no custom protocol, no anti-analysis engineering.
4. **The infrastructure is budget-tier.** A low-cost virtual private server, an open directory left publicly listable, consumer proxy egress, a free dynamic-DNS hostname.
5. **The control channel is a consumer messaging account.** Live human-in-the-loop control through a personal account and group chat on a commercial platform is the operational security of an individual, not of a program.
6. **The outcome is personal data with resale value**, harvested individual by individual, with a persistent named-individual catalogue.

</details>

### 11.2 Sophistication: two bands, reported separately

Averaging this operator's capability into one label would misdescribe the threat in both directions, so I report the two bands separately and hold that split at HIGH.

The capable band is technique selection and chaining. The Redis-to-SSH-key chain and the gopher-smuggled database handshake in Section 6.6 are correctly built and require understanding the seam between several systems. Deriving and using a request-signing scheme, and forging tokens in two independent ways, shows real competence. Four independent sourcing channels converging on one target's customer data shows planning, not opportunism. And above all, the log-verbosity technique in Section 4.3 is not a published exploit chain at all. It is the operator reasoning about how to make a target produce what they want.

The weak band is execution and operational discipline, and it is a long list. The operator's own working directory was left publicly listable on a non-standard port, and that single failure is why any of this is known.

Below that, downloads arrived broken, zero-byte files were saved under names implying real content, and a paid reconnaissance-service subscription key sits hard-coded in clear text. Working scripts carry unfixed defects, one of which permanently destroyed the operator's own evidence of who received a payload.

Nothing is compartmentalized either. Keys, tokens, harvested data, working notes and environment captures all sit in one place, and several attack chains trail off with no captured outcome and no follow-through.

My read is that those two bands are not a contradiction to be averaged away. They have different authors. The operator brings the intent and enough knowledge to specify what they want built, the model turns that into scaled working tooling, and nothing anywhere in that pipeline improves their operational discipline, so the ceiling rises and the floor does not. That is the whole shape of this actor, and it is why I would not put much weight on the length of the technique list. A list assembled this way measures how much the model wrote, not how good the operator is. The log-verbosity work is the one place I can see the operator's own ceiling instead of the model's, which is why I weigh it separately from the borrowed classes instead of averaging it in.

Where that leaves me: someone who knows enough to be dangerous, working well above their own unaided level, and held back more by their own carelessness than by any limit on what they could reach for. That combination is not rare and it is getting less rare. That is the argument of Section 3 and the reason this report leads with the method instead of the person.

### 11.3 Solo operator versus small crew

A single operator is more likely than a small crew, and I put that at MODERATE, around 65 percent solo, because the distinction does not resolve cleanly.

For solo: one build environment produced all three key pairs with an unedited default comment; one identity authored the framework clone records; one control source is consistent across two independent captures; one continuous agent session appears in both captures; one controlling user is identified on the control channel; the account-naming series is a single sequential habit; and the unevenness of execution quality is uniform, where a crew usually shows at least two distinguishable standards of work.

For a small crew: the control channel is a group and not a direct conversation; the target breadth and per-target tooling volume represent substantial working hours; and the account-naming series has a numbering gap.

The group-chat observation is weak, since single-participant groups are entirely normal for bot control, and it is the only artifact pointing to more than one person. The volume argument is weaker still under the Section 3 reading, since generated tooling decouples output volume from headcount. The distinction does not change the risk to any defender.

### 11.4 Geographic and language orientation

This is a Chinese-language operator working against mainland Chinese platforms. I hold the language and targeting at HIGH, and the operator's own location only at MODERATE.

Supporting the language and orientation finding: the operator's own working labels, script comments and target annotations are in Chinese; brand-derived and pinyin-derived password guesses require familiarity with the target brands; the target set is near-exclusively mainland Chinese consumer platforms; and the control-source resolution pattern points at a proxy service sold into the Chinese consumer market.

Limiting the location finding to MODERATE: the platform is US-hosted, the control source is registered in the RIPE region, and the operator routes through proxy infrastructure by design, the exact circumstance in which network-derived location assessments fail. Hosting jurisdiction is a purchasing decision and is **never stated here as operator nationality**. Language and targeting carry the regional assessment, and both language and targeting can be adopted.

### 11.5 What UTA-2026-019 is scoped to track

The designation tracks the **operator**, meaning the build environment and the platform, and deliberately not the toolkit. Track the toolkit and you will match half the people using public exploit code, which is worse than tracking nothing at all. The agent framework has the same problem, so it appears below only as one element of the platform composite and never as a discriminator by itself.

<details markdown="1" class="hl-teardown">
<summary>The five characteristics behind the designation, and which two should anchor future matching. Click to expand.</summary>

1. **Build-environment fingerprint.** One unmodified default key comment across three distinct key pairs and the framework clone records, tying key material and tooling deployment to one named build host.
2. **Operator platform composite.** A publicly listable working directory on a non-standard port, a rogue directory-service listener, a shared exploitation callback port, a self-hosted VPN with an operator-chosen instance identifier, and a root-privileged agent framework, all on one host.
3. **Technique composite.** Log-verbosity elevation through an exposed management interface to manufacture harvestable data and then read it back; register-a-throwaway-account-for-a-token reused across targets; and a serverless cloud function reused as an attack relay across two independent attack types.
4. **Account-naming series** reused across two unrelated target platforms and mirrored in private tooling filenames. Only the cross-target reuse pattern is distinctive, not the vocabulary itself.
5. **Targeting profile.** Mainland Chinese small and medium consumer platforms in installment and rent-to-own commerce, credit rental and loan referral, with personal-data harvest as the objective.

Future matching should anchor on characteristics one and three, which are infrastructure-independent and survive a rebuild or a takedown. The control-source address is deliberately **not** a defining discriminator, because it is probably shared proxy infrastructure. It is carried as a contextual indicator and as a victim-side log search term, with the co-tenancy caveat attached.

</details>

---

## 12. Risk Assessment

The overall risk score is **7.2/10**, which puts the threat level at **HIGH**.

Five dimensions carry that score, weighted toward what the evidence actually shows: confirmed data exfiltration and account compromise dominate, and remote code execution contributes least because none of it worked. Two further dimensions are recorded but deliberately excluded from the average. Lateral movement scores 2/10 and destructive impact 1/10, and including them at equal weight would produce a MEDIUM label by scoring the absence of capabilities this threat class does not have and never used. An external, API-centric data-theft operation with no implant does not move host to host, and that is a description of its shape, not a mitigating factor.

<details markdown="1" class="hl-teardown">
<summary>The per-dimension scoring behind the 7.2, and the two dimensions deliberately excluded from the weighted average. Click to expand.</summary>

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
<tr><td>Account compromise</td><td>7/10</td><td>25%</td><td>An armed, pre-staged verification-code brute force against a real staff account with a chosen replacement password. Authenticated access to a second platform through a self-registered account, followed by administrative-route probing, with the unauthorized characterization following the HIGH conduct judgment in Section 2.2, not standing as a separate confirmed finding. Live-used database and cache credentials on a third surface. Outcomes for the reset and the administrative login are unconfirmed.</td></tr>
<tr><td>Scale of targeting</td><td>8/10</td><td>20%</td><td>Roughly five mapped corporate groups plus at least seven standalone or emerging threads, spanning e-commerce, device and credit rental, gig work, insurance asset management, loan referral and a mobile-OEM developer platform. No client separation of any kind.</td></tr>
<tr><td>Operator persistence and tempo</td><td>7/10</td><td>15%</td><td>The platform was still live and growing at the close of analysis, run continuously since at least April 2026 with no address rotation. Operator access observed across a multi-week span. A VPN and a serverless relay in place for source obscuration, plus an always-on control channel.</td></tr>
<tr><td>Remote code execution</td><td>4/10</td><td>10%</td><td>Genuine crafted payloads across five vulnerability classes, but no evidenced success for any of them. For two of the five, the strongest available evidence points the other way.</td></tr>
</tbody>
</table>

</details>

### 12.1 Why HIGH and not CRITICAL

The case for CRITICAL is real: confirmed theft of identifiable personal and financial records belonging to named individuals, an armed account-takeover weapon aimed at a staff account, live-used database and cache credentials, roughly a dozen targeted organizations, and an operator platform still live at the close of analysis.

Three things hold it at HIGH. Evidence bounds the harm, not assumption, since five of the six efforts that left an outcome artifact are negative, among them the HIGH-confidence failure of the decryption effort. Confirmed theft covers one platform and at least five named individuals, not a population, and the fuller identity field set is highly likely, not confirmed. And no destructive capability exists anywhere in the corpus.

### 12.2 What is at risk for an affected organization

Customer identity and financial records are the obvious exposure: names, order and installment histories, and, on the platform where the harvest is confirmed, the identity-verification records behind them. Staff account control is the sharper one. The reset weapon targets a staff or operator account, not a customer, and a staff takeover turns an external data-theft problem into an internal one with access to whatever that role sees across every customer.

Two further exposures outlast the incident. Where a monitoring console was open, the actor keeps the full schema, the API surface and the business logic long after the console closes, which is why credential rotation is a reasonable precaution even with no password disclosed. And the emergency-contact fields inside identity-verification records pull in third parties who never transacted with the platform at all.

### 12.3 Spread and current status

Spread capability is low, and I would weight it that way even though the technique list looks alarming. This is an external, API-centric operation. It exploits internet-facing management surfaces and authentication weaknesses. It does not carry implants, does not move host to host, and leaves nothing behind on victim systems except, potentially, an unconfirmed web shell.

The operation was still running when the analysis closed. The directory was live and still growing on 21 July 2026, and the takedown request filed with the hosting provider had not been actioned.

So treat any blocklist entry for this platform as perishable. It buys time and nothing more, because the address is the cheapest thing the operator owns and the easiest to replace.

What outlasts the address is the shopping list. Unauthenticated monitoring consoles, unrestricted management interfaces, verbose production stack traces, enumerable record identifiers, four-digit verification codes: none of that is specific to the organizations named here, and all of it is what the next operator will go looking for.

---

## 13. Indicators of Compromise and Detection Coverage

The machine-readable indicators live in the [IOC feed](/ioc-feeds/multivector-ecommerce-rce-toolkit-192-3-1-116-iocs.json) and the rules live in the [detection file](/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/). Neither is reproduced here, so take them from the source rather than retyping anything out of this page.

Coverage is behavioural and payload-class based, because there is no malware family to signature. No rule in the published set encodes this operator's address, hostnames or account names: those are atomic indicators and they live in the feed. A rule pinned to `192.3.1[.]116` dies with the takedown that is already filed, while the techniques outlive the infrastructure.

| Rule type | Detection tier | Hunting tier | Focus |
|---|---|---|---|
| YARA | 5 | 0 | Exploitation payload files recoverable from an upload directory, temp path or incident |
| Sigma | 5 | 7 | Behaviour visible in web access logs: management-interface abuse, unauthenticated console access, heap-dump retrieval, registration-then-probe, code brute force, scan profile |
| Suricata | 11 | 2 | Network traffic: JNDI callbacks, gadget chains and SSRF payloads in transit, forged tokens, registry poisoning |

### 13.1 The highest-value hunting targets

Ordered by durability, not by how much this specific operator used them. If a defender instruments one thing off this report, make it the first.

1. **Log-level change then log read.** A Jolokia or JMX write that changes a logging level, followed within minutes by a read of the application log-file endpoint. The highest-fidelity signal in the campaign and the most under-instrumented. Section 4.3.
2. **External access to a Druid console.** Any HTTP 200 on an Alibaba Druid console path from an external source. Do not anchor the rule to ports 80 and 443.
3. **Successful external heap-dump retrieval**, detected on success with a large response body, not on the request alone. Internal performance-monitoring and support tooling also retrieves heap dumps routinely, so a retrieval from an internal source is the expected benign case.
4. **Code brute force against one reset context.** Many requests to a verification or password-reset endpoint sharing one constant verification-context token while a short numeric field iterates.
5. **Register then probe.** An account registration followed within minutes by that same account's token hitting administrative routes.
6. **A bind with no search.** An outbound LDAP bind request to a non-standard directory port from an application server, with no follow-on search. The stall is the event, and waiting for the search would miss it.

<details markdown="1" class="hl-teardown">
<summary>What the feed contains, the four categories deliberately excluded from it, and the acknowledged coverage gaps. Click to expand.</summary>

The feed carries operator infrastructure (addresses, hostnames, callback URLs, ports), operator attribution artifacts (a build-host identifier, SSH key fingerprints, throwaway account names, messaging identifiers, a session identifier), operator file and path artifacts, behavioural indicators with log-source mappings, exploitation-payload signatures, and a separately structured target-asset list. **It carries no file hashes**, for the reason given in Section 2.1.

**Four categories are deliberately excluded** from both this report and the feed, recorded here so downstream consumers know they exist and were withheld, not overlooked:

1. **Believed-real target credentials.** Database, cache, administrative and API-signing credentials belonging to victim organizations. Publishing them, even defanged, is a disclosure hazard, not an intelligence contribution.
2. The operator's live reconnaissance-service subscription key, and every raw session token in the corpus.
3. **All victim personal data.** No customer or employee names, phone numbers, national identity numbers, order records, loan-applicant records, or their submitter addresses.
4. **Post-discovery crawler and scanner traffic.** Several cloud-provider addresses mass-downloaded every file in the open directory in tight repeating clusters after it was discovered, one of them accounting for 1,379 requests alone. That is researcher and scanner noise, and the feed marks it explicitly as non-indicators.

The feed also carries a `targeted_assets` structure, and it exists **for correlation only**. Those hostnames and addresses belong to businesses that were attacked. Block them and you break somebody's shop, so use them to match your own telemetry and nothing else.

Four categories in this campaign are not detectable from a third-party network or log-telemetry perspective, and the published detection file states them instead of implying coverage that does not exist.

A session token signed with a correctly guessed secret is byte-for-byte indistinguishable from a legitimately issued one at the network layer. Detecting that requires the issuing application to log signing-key usage or to reject known-weak default secrets outright.

Verbose framework exception disclosure is a real defensive-hygiene signal, but standard access-log telemetry captures status codes and byte counts, not response bodies, and a bare status-code selection would be far too broad to publish.

Structured record-identifier enumeration confirms the underlying platforms use predictable identifiers, but the exact format is platform-specific. A platform operator is better positioned to rate-limit or randomize its own identifiers than a third-party feed is to signature them.

Reused valid credentials produce traffic indistinguishable from their legitimate owner's.

</details>

---

## 14. Confidence Summary, Gaps and Calibration

In a corpus that is overwhelmingly capability and not outcome, the difference between what an operator built and what an operator achieved is the entire intelligence value. Here is where that line sits.

### 14.1 Confidence by finding

| Finding | Confidence |
|---|---|
| Customer names plus order and financial records harvested for at least five named individuals | DEFINITE. Four of the five names are complete, one partial |
| Fuller identity fields (national identity number, email, emergency contacts) also obtained | HIGH, not confirmed by any captured response |
| Unauthenticated Druid console exposed a full production data model at time of capture | DEFINITE |
| That console disclosed the database password | Explicitly NOT the case. Username, connection details and schema only |
| That console now appears remediated | HIGH, based on a read-only re-check finding the host NXDOMAIN and the port closed |
| Log-verbosity elevation tooling exists and is written to manufacture harvestable data | DEFINITE |
| That specific technique produced the confirmed harvest | MODERATE. It is the mechanism that best explains an already-confirmed finding |
| An armed account-takeover weapon is staged against a real staff account | DEFINITE that it is armed. UNCONFIRMED that it was fired or succeeded |
| Account registration, authenticated login and administrative-route enumeration on a second platform | DEFINITE. No successful administrative access and no confirmed data theft there |
| Identity-field decryption for one individual failed | HIGH as a negative result |
| Eureka XStream remote code execution did not fire | MODERATE, with a stated timing gap in the log window |
| JNDI chain stalled at bind in both logged attempts | DEFINITE for the two logged attempts |
| Web shell deployed to any victim host | UNCONFIRMED. It exists only in the operator's own directory |
| The agent framework is off-the-shelf open source, not operator-built | DEFINITE for the two examined plugins; HIGH for the core framework's identity |
| The agent framework executed any attack script | UNCONFIRMED. No claim is made in either direction |
| The attack scripts were LLM-generated | MODERATE. Inferred from volume, uniformity and error class; no generation artifact recovered |
| Conduct is unauthorized and malicious rather than authorized testing | HIGH (approximately 85 percent) |
| Attribution to any named threat actor | INSUFFICIENT (approximately 15 percent) |
| Activity is not state-sponsored | HIGH (approximately 90 percent) |
| Chinese-language operator working against mainland Chinese platforms | HIGH for language and targeting, MODERATE for operator location |
| Single operator rather than a small crew | MODERATE (approximately 65 percent) |
| Loan-referral API ownership and record authenticity | INSUFFICIENT. Records were definitely returned to a client |
| Content-provider filing absence as a grey-market signal | MODERATE, single-source, not load-bearing |

### 14.2 Assumptions that would change the picture if wrong

The first assumption is that all the identity artifacts belong to one continuous operator. The build-host identifier, control source, account-naming convention and messaging identifiers are all treated as one party.

Supporting that: three key pairs share one build environment, the same identity authored the framework clone records, the control source is identical across two independent captures, and one continuous session appears in both. Against it: a resold or shared virtual machine image would reproduce a build-host comment across unrelated users, and the control source is probably shared proxy infrastructure.

The net effect is that the single-operator reading is well supported for the platform-side artifacts and weaker for the control source, so I do not use the control source as an identity anchor.

The second assumption is that the agent framework never executed an exploitation script. If that is wrong, the classification would shift materially from an operator-scripted commodity-technique campaign to an AI-assisted exploitation campaign, which 2026 vendor reporting treats as a distinct and more advanced threat category. This is fundamentally a host-telemetry question that no public-research method can answer, and no claim is made in either direction.

The third assumption is that the commercial lookup service used for the filing check is a reliable proxy for the official registry. If it is not, that signal moves toward INSUFFICIENT. Nothing in this report depends on it either way.

### 14.3 Gaps in the evidence

The single highest-value missing artifact investigation-wide is an access log covering the callback listener during the JNDI engagement window. It would close the remote-code-execution outcome question that three separate techniques share. An earlier rotation of the operator's own web-server log would similarly close the timing gap in the XStream negative.

Further gaps, recorded and not papered over: no captured output from the decryption effort showing a success line; no captured authenticated response proving the API documentation credential works; no confirmation of whether the staff account's password was actually reset; no business-registry resolution of the confirmed-theft platform's operating entity; and no recovery of the third framework plugin's contents, which bears directly on whether the operator wrote any custom capabilities for it.

On the attribution side, the JARM/JA4X reverse-pivot was not re-queried, so one of the four infrastructure-overlap checks in Section 11 is carried forward from the investigation baseline instead of being independently re-run. The threat-actor-catalog check was re-run directly and returned no association, so the attribution conclusion no longer rests on a carried-forward absence.

One further signal is worth recording for what it does not settle. That catalog does not classify the operator's control-source address as a commercial VPN or proxy service, which is weak evidence against the shared-egress reading in Section 8. A small regional subscription service would not be expected to appear in a VPN-detection dataset either way, so the MODERATE assessment there stands unchanged in both directions.

Three pivots were never run. The build-host identifier was never checked against historical SSH host-key scan data, and that remains the strongest unperformed technical lead. The messaging-platform control-channel identifiers were deliberately left alone, since pivoting them needs platform cooperation or channel interaction and both are out of scope. Marketplace and data-trading presence was never investigated at all, and it would be the strongest independent corroboration available for the actor-class placement.

And no targeted platform was contacted to confirm the absence of an engagement. That is the cleanest test of the authorization question and it is structurally unavailable to a third-party intelligence provider.

Several targets remain unidentified: a sustained single-target effort whose subject was never resolved, an enterprise mail deployment, an API gateway, and four unattributed web probes.

### 14.4 Calibration record

Several conclusions in this report were revised downward before publication. They are published, not quietly absorbed, because a reader has no way to assess calibration discipline that stays invisible.

- A novel operator-built AI framework claim was retracted once Hermes was identified as public open source. It was the intended headline, and losing it improved the report: the commodity finding is the more useful one, for the reasons in Section 3.1.
- A monitoring-console exposure was re-attributed to the correct platform. A second platform in the same thread has no confirmed exposure of its own.
- A compromised production database credential claim was narrowed to connection details plus a username. No password was disclosed.
- A web shell described as deployed on a victim host was re-scoped to existing in the operator's own directory only.
- Five Cobalt Strike beacon hits were confirmed as scanner false positives.
- A directory of files named for human-resources contracts was confirmed to be human resources, not health records. There is no medical or healthcare target in this investigation.
- Two further wording corrections were directed at this report, not at external recipients: the content-delivery block on the mobile-OEM thread is stated as apparent, not confirmed, and the insurance-sector target's controls-held reading is stated as substantially silence, not as a positive defensive result.

---

## Response Orientation

This is not an incident response guide. It is a short orientation on what to address. Readers with an active incident should engage their own response function.

Detection priorities, highest value first.

- Alert on any successful external access to a database monitoring console or an application heap-dump endpoint. Both are direct sources of the confirmed harvest in this campaign.
- Alert on remote log-level manipulation through a management interface followed by a log-file read. That sequence manufactures the data an attacker then collects, and it is rarely instrumented.
- Alert on sequential verification-code enumeration where the verification-context token stays constant across many requests.

Persistence targets to look for, names and locations only.

- A generic JSP web shell, and any similarly named file under a web-server temporary document path. Deployment to any victim host is unconfirmed, so treat these as hunt targets and not as assumed findings.
- Unexpected entries in a privileged account's authorized-keys file on any host reachable from an application capable of server-side request forgery, and any in-memory data store whose save directory or filename configuration has been altered.
- Self-registered platform accounts matching this operator's naming series, and any account whose first session probed administrative routes.

Containment categories.

- Block the operator platform and its associated VPN hostname at the network edge, treating the entry as perishable.
- Close unauthenticated management surfaces: monitoring consoles, management and JMX endpoints, API documentation portals and service-discovery consoles.
- Rotate credentials on any platform where a monitoring console, an environment endpoint or a heap dump was externally reachable, as a precaution.
- Suppress framework stack traces in production.
- Review authentication logs for the enumeration and self-registration patterns above across the observed activity window.

---

## References

These sources support this report's central claims: that every technique class observed here is drawn from the well-documented public record with mature proof-of-concept code already available, and that commodity agentic-AI adoption by offensive operators is an actively documented trend and not a novelty. Both claims are what make the operator's failure to convert any of it into stolen data meaningful, so they are worth being able to check.

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
26. Hunt.io, "Thailand's Ministry of Finance targeted with Hermes AI agent running unattended, Hades implant staged," 2026-07-23. <https://hunt.io/>

Reference 25 identifies the agent framework found on the operator host as off-the-shelf open-source software, and that identification is the basis for retracting an earlier characterization of it as operator-built. Reference 26 documents an independent case, reported in the same month by a separate research team, in which the same framework was found running against a government ministry in a different country. The two together are why Section 3 treats this working method as a pattern, not as one operator's quirk.

---

© 2026 Joseph, The Hunters Ledger. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), free to republish and adapt, including commercially, with attribution to The Hunters Ledger and a link to the original.
