---
title: "An AI Pentest Platform Drives Commodity Tooling Against Portuguese Government Targets"
date: '2026-11-12'
layout: post
permalink: /reports/inv-2026-080-cyberstrike-ad-workbench/
hide: true
unlisted: true
sitemap: false
preview_cover_label: "Agentic Intrusion"   # preview only: the header cover while the catalog entry is parked; drop at go-live (the catalog cover_label takes over)
preview_severity: high
category: "AI-Assisted Intrusion"
description: "One operator ran the public CyberStrikeAI agent platform from a Paris server against the Portuguese central government and a hosting provider, took and decrypted a government records application's user and password tables, and served them publicly, all with off-the-shelf tools a defender can detect."
detection_page: /hunting-detections/inv-2026-080-cyberstrike-ad-workbench-detections/
ioc_feed: /ioc-feeds/inv-2026-080-cyberstrike-ad-workbench-iocs.json
detection_sections:
  - label: "YARA Rules"
    anchor: "#yara-rules"
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "Suricata Signatures"
    anchor: "#suricata-signatures"
ioc_highlights:
  - value: "199[.]247[.]13[.]103"
    note: "Operator open directory and CyberStrikeAI workbench server (Vultr, Paris)"
  - value: "02a98b325408f623e192d569d6cb11a60aaf61a114a5c4f35bbfd1dcbe56d69c"
    note: "dnsplugin.dll, operator-built DNS plugin that would add a Domain Admins account (SHA-256)"
  - value: "1046cf19fb280684236193059805005bb8b1f3ad3b6fe7ca2b35d9dea8523273"
    note: "SvcUtil.exe, operator's GodPotato fork with an LSASS dump (SHA-256)"
  - value: "7033ee65a125bec39860af0cef8d64f46a0cf7e579baab5d57e31d83367333f9"
    note: "pwnkit.so, operator-built PwnKit gconv module (SHA-256)"
figure_nav:
  - image: cyberstrikeai-platform-to-victims-chain.svg
    parts:
      - label: "Operator and platform"
        anchor: "#4-technical-classification-an-ai-agent-platform-driving-stock-tools"
      - label: "The platform drives public tools"
        anchor: "#82-what-is-stock-and-what-the-operator-wrote"
      - label: "The tools reach the targets, by grade"
        anchor: "#3-victims-who-was-hit-and-how-far-the-operator-got"
      - label: "The defender point"
        anchor: "#14-recommendations"
---

**Campaign Identifier:** CyberStrikeAI-Workbench-PT-Government-199[.]247[.]13[.]103<br>
**Last Updated:** November 12, 2026<br>
**Threat Level:** HIGH

> **Risk vs. Campaign Threat Level:** The toolkit scores MEDIUM, 6.4 out of 10, because almost all of it is stock and detectable (Section 2). The campaign is HIGH because of what it reached and exposed: a central-government target set, a hosting provider's credentials and a decrypted password store published to the internet.

---

## 1. Executive Summary
{: .hl-tier-1}
{: .hl-tab-overview}

One operator used CyberStrikeAI, a public AI penetration-testing agent platform, to run off-the-shelf attack tools against the Portuguese central government and a Portuguese hosting provider in the same few days. It broke into a public-sector agency's records application through a JBoss flaw public for years, decrypted the application's stored passwords with a single fixed key, and had decrypted user-account passwords downloadable from its own open directory 5 h 17 min after its scanner flagged the server. Nothing in the toolkit is new. What the case shows is pace and reach: an agent platform let one operator work a national government estate and a hosting provider at once, and the wins it got came from weaknesses defenders have known about for years.

- The deepest result, which I hold at MODERATE, is a web shell on the agency's records application server, its user-account and password-backup tables pulled by SQL, 111,404 stored password values decrypted, and the export served from an unauthenticated directory to 10 distinct public addresses. Whether the operator also took the personal and health tables the schema lists is INSUFFICIENT: no file I hold contains them.
- Of 22 victim rows, 2 show host-level access, 3 are compromised on material the operator held (an Active Directory domain's member-server memory dump, a hosting provider's root credentials and SSH keys, a state agency site's administrator rows), 12 were reached from outside and 5 were only listed (Section 3). The provider's credentials reach its customers; no customer output is held.
- The tools are commodity and much of the work failed: chisel, PwnKit, GodPotato, Rubeus, a public Veeam proof of concept and operator-written glue, with no new malware. Five credential dumps on a second agency server, where the operator already had SYSTEM-level command execution, left no dump file, and a staged domain-admin DLL is not shown to have run. All of it is detectable (Sections 11 and 12).
- The "authorised pentest" label in the operator's reports carries no weight, because the platform's default prompt tells every model session it already holds full authorisation; it is framing aimed at the model. I read the activity as unauthorised, at MODERATE.
- I tie the operator to no named actor and to no other case I hold, and the motive is undetermined, at LOW.
- For defenders, in my read across the cases I have worked, which this case did not measure, agent platforms put this breadth and pace within reach of ordinary operators, so the time from an exposed flaw to public loss can be hours. A separate CyberStrikeAI case, published by Elastic on 13 November 2026, measured the platform working at machine speed (Section 4). The defence is the same basics, applied faster (Section 14).

CyberStrikeAI and its abuse are already publicly documented (Section 16). What this case adds is one operator's whole workbench, graded per victim.

## 2. Business Risk Assessment
{: .hl-tier-1}
{: .hl-tab-overview}

For an organisation outside this case, the lesson is less about this operator than about where the risk now sits.

Breadth is now cheap. A free, public agent platform let one operator survey a national government's estate (26 seed domains, 5,846 live hosts), break into one agency and work a hosting provider in the same days. Being one target among thousands is no longer cover when the survey, the exploit and the follow-up all run from one workspace. In a separate CyberStrikeAI intrusion against cloud accounts, Elastic measured one session making 56 API calls in 141 milliseconds.

Old weaknesses carried the loss, and nothing here needed new malware. The losses came from a deserialization flaw public for years, a password store one fixed key could decrypt, and credentials and keys an intruder could read. Exposure to this kind of operator tracks an organisation's unpatched internet-facing servers and how it stores secrets, not its exposure to advanced tooling.

Theft became publication within hours. The operator served what it took from an open directory, and decrypted user-account passwords were downloadable 5 h 17 min after its scanner flagged the server. A breach like this can be a public exposure before it is a known incident, and every account in a leaked store has to be treated as burned.

A provider's control plane reaches every tenant. The operator held a hosting provider's root session, root password hash, SSH keys and backup-server access, and scripted restores of customers' backups. A customer's exposure includes its hosting or managed-service provider's administrative credentials. No customer output is held here, so that reach is capability, not a shown result.

An "authorised pentest" label proves nothing either. The platform writes authorisation into its own prompt, so a report claiming a sanctioned test, found on a compromised host or in a leak, is not evidence that anyone sanctioned it.

The scores below rate the toolkit's technical risk to a defender.

| Risk dimension | Score | Rationale |
|---|---|---|
| Data exfiltration | 9/10 | The records application's user and password tables taken by SQL through the shell, decrypted, and served publicly |
| System compromise | 8/10 | A web shell on the records application's host, an SQL `sa` login to its database and a service run as SYSTEM on a second server |
| Persistence difficulty | 5/10 | Web shells and a staged domain-admin DLL; no persistence shown surviving on any host |
| Evasion capability | 4/10 | Renamed GodPotato forks, base64 chunking through `certutil`, hidden windows; antivirus detected one delivered fork |
| Lateral movement | 8/10 | Remote service creation, admin shares, an SSH jump host, SOCKS tunnelling and credential reuse |
| Detection challenge | 3/10 | Stock tools with public signatures, fixed shell paths and service names, and a fixed account name |

Weighted 20, 20, 15, 15, 15 and 15 percent, I score the toolkit's overall technical risk at 6.4 out of 10, MEDIUM. The campaign is HIGH for its reach and for what it exposed. I hold no victim-side telemetry, so nothing here is confirmed from a victim's own logs.

## 3. Victims: Who Was Hit and How Far the Operator Got
{: .hl-tier-2}
{: .hl-tab-victims}

This is the operator's target list, graded one organisation (or one group) per row, from what the operator's own files show. I do not name any victim. Each row carries a sector description instead, and the Portuguese central government as a target set is the only collective I name. Where two grades fit a row I record the lower one, and nothing is upgraded on inference.

The four grades mean different things, and the difference matters to a defender deciding what to do first. ACCESS SHOWN means host-side evidence: output of a command the operator ran on the victim's own system, or a file it stored there. COMPROMISED means the operator holds material only working access returns (a credential dump, administrator rows, root credentials), but the route that produced it is not in any file I hold. REACHED means the operator touched the system from outside and got a response, or holds copies whose origin is not shown, without access beyond that. LISTED means the organisation is named in the operator's targeting and nothing more.

Of the 22 rows, the grades are 2 ACCESS SHOWN, 3 COMPROMISED, 12 REACHED and 5 LISTED.

| Organisation | Grade | What the operator's files show | Latest dated evidence |
|---|---|---|---|
| V01, a Portuguese public-sector agency: its records application server and one internal application server | ACCESS SHOWN | Command output returned through an operator web shell on the records application's host; an SQL `sa` login to the records database on a separate database server; the application's user and password tables pulled by SQL and decrypted; a service run as SYSTEM on the second server, and a write test in its share | 2026-10-07, the write test in the second server's share (day-first reading of the target's listing; the operator's server log ends 2026-10-07 01:38:04) |
| V02, an Active Directory domain on the same network as V01 | COMPROMISED | A genuine Windows Server 2019 memory dump of a domain-joined member server, whose machine account is 1 of the 34,149 rows of the domain's own computer inventory and, by name, is the web-shell host's (MODERATE); no held output shows the command that wrote it; 55 Kerberoasted ticket records and 2 cracker candidates that an independent checksum check rejects | 2026-10-06 19:58:01 UTC, the dump's header time |
| V03, two further Portuguese AD domains | LISTED | Named in domain-controller discovery and trust-enumeration scripts only; no reply held | No dated evidence held |
| V04, a Portuguese hosting provider | COMPROMISED | A WHM root session URL, a root password hash and private SSH keys equal to the provider's Puppet-managed copies; 3 recorded provider addresses reached in a scan; authenticated replies from the provider's backup server carrying password fields; route not held | No clock in the held files |
| V05, the hosting provider's customers (15 named, 2 targeted by restores) | REACHED | Backup-restore scripts aimed at their data through the provider's backup API; the replies held are error pages; no customer output | No dated evidence held |
| V06, a Portuguese state IT body | REACHED | A password-change page returned twice with no success; a 10-file test-project copy from a code repository whose visibility is unchecked | No dated evidence held |
| V07, a Portuguese state agency's website | COMPROMISED | Two administrator rows with password hashes in an operator file named `sqli_users.json`; the SQL-injection route is inferred; a web shell dressed as a theme file prepared, not shown placed | No clock in the held files |
| V08, a Portuguese public-sector portal | REACHED | Seven scripts drive its sign-up, admin, recovery and user-enumeration paths; no reply held | No dated evidence held |
| V09, a Portuguese state institute and a ministry's address range | REACHED | Login tests and a self-registration step; a configuration-file copy carrying database connection fields, whose route of acquisition is not held | No dated evidence held |
| V10, a Brazilian commercial education-software site | REACHED | A UNION SQL-injection driver plus four dump scripts and a restore script; no result held | No dated evidence held |
| V11, the Portuguese central-government estate (26 seed domains in 15 ministry groups) | REACHED | 10,422 subdomains enumerated, 5,846 alive hosts, 25 hosts with 58 open ports; the vulnerability-scan result file is empty | No dated evidence held |
| V12, the owner of a web application whose daily logs the operator holds | REACHED | Copies of four daily application logs; the route is not shown and nothing shows a non-public pull | 2026-09-23 21:12:04, the latest log entry copied (application clock) |
| V13, owners of three SSH or login targets and two scanned ranges | REACHED | SSH and brute-force scripts; no login success | No dated evidence held |
| V14, the owner of a cloud access key | REACHED | One signed identity call; no result held | No dated evidence held |
| V15, a Portuguese state agency | REACHED | Two unauthenticated, read-only API replies listing 11 template nodes | No dated evidence held |
| V16, a Portuguese state-owned company | REACHED | A fingerprinting script names its website; a map-plugin export probably taken from that site is held (MODERATE) | No dated evidence held |
| V17, a Portuguese government online service | REACHED | A probe output lists its portal with a status, so a reply reached the operator | No dated evidence held |
| V18, a Portuguese private company | LISTED | Named in the ministry report only, after the report's own exclusion list names it | No dated evidence held |
| V19, a Portuguese association | LISTED | Named in the ministry report only, after the exclusion list names it | No dated evidence held |
| V20, a second Portuguese private company | LISTED | Named in the ministry report only, as excluded | No dated evidence held |
| V21, 27 government DNS zones hosted on the provider's DNS | LISTED | Administrative copies of the 27 zone files (827 records), not a zone transfer and not a zone change | No dated evidence held |
| V22, the unknown owner of the SSH jump host the operator scanned from | ACCESS SHOWN | Output of a command the operator ran on the host and an operator file stored on it: a 625-row scan of 78 private addresses in one /24 | No clock in the held files |

Two of those rows need a caveat a defender should carry with the grade. V22 is ACCESS SHOWN on its evidence, but I hold its owner only as unknown. It sits in a /24 registered to a Portuguese ISP whose network also announces 8 other recorded addresses of the hosting provider, and a certificate on it names a Portuguese government domain. I read it as a pivot through a victim-side Portuguese network at MODERATE. The operator also held a Puppet catalog, compiled on 25 September 2026, for a node of the jump host's name, which points to the jump host being enrolled in the provider's configuration management; it does not prove whose machine it is. That weakens the live alternative without excluding it: that the host is infrastructure the operator rented or controls, in which case it is not a victim and drops out of the count.

V04's grade is a judgment on credential material whose route I cannot show. The session URL has no held response, and the scan host is V22, not shown to be the provider's own machine. The operator does hold authenticated status-200 replies from the provider's backup server through its SOCKS tunnel: a user list with 12 complete user records and 12 password fields, and policy records with 3 non-empty database-password elements. Whether those password fields are usable plaintext is not confirmed. They are server replies rather than command output on a provider machine, so they do not make the row ACCESS SHOWN, but a provider rotating credentials would need to include the backup server's users and policy database passwords. What would settle it is host-side evidence on a provider system, such as the provider's own SSH log showing the operator's key.

Any wider theft of personal data, which the project report claims, or of the health tables the schema lists, is not in this table because no file I hold shows it. Section 6 sets out what the held export contains and what it does not, and names two result files that go beyond it. For the hosting provider's customers and the 27 DNS zone owners, I asked the national CERT to have the provider notify them; I hold no confirmation.

## 4. Technical Classification: An AI Agent Platform Driving Stock Tools
{: .hl-tier-2}
{: .hl-tab-chain}

The capability in this case is an AI agent platform steering stock public tools, not a malware family. The operator worked inside CyberStrikeAI, and the platform added pace and reach rather than new technique; it is the one part of this case I find genuinely worth a defender's attention. CyberStrikeAI is a public, Apache-2.0 licensed AI penetration-testing agent platform written in Go, published on GitHub since 8 November 2025 (now under `AIPentest/CyberStrikeAI`). It wraps a large language model in an agent loop with a catalogue of integrated offensive tools, a per-project workspace, and a findings store that records each verified vulnerability as a database entry with its own ID.

I state that an actor used AI tools only when I hold direct evidence of it, and here I do. The platform's workspace path, `/root/CyberStrikeAI/tmp/workspace/projects/<uuid>`, occurs 392 times in 103 of the first 1,743 files scanned, and `/root/CyberStrikeAI` itself 418 times in 116. The directory yielded 1,887 captured files in all as of 12 November 2026: the 1,743 files scanned and the 143 later files, which were phrase-scanned separately and add no workspace count, make 1,886, and the 1,887th is the operator's project report, read in full. Two workspace projects appear: the main one, `72995c0d-1e52-4f27-b754-a7d80c685421`, and a wordlist copy whose ID begins `6a86acd6`. The ministry report reproduces the platform's finding IDs and field labels, 23 distinct IDs that occur nowhere else in the capture. The work ran in this platform at HIGH confidence.

### The authorisation label is framing aimed at the model

The ministry report is 335 lines of Simplified Chinese. It calls itself an "authorised penetration test" and has a heading for test scope and authorisation. That heading carries scope and nothing else: no client, no authoriser, no contact, no date, no contract, no reference and no sign-off. The report also records two exploited findings against entities its own exclusion list names, 2 of its 22 findings, and a leaked database password tried against two other services. That is not how a sanctioned engagement keeps its own scope.

My read is that this is not the behaviour of a normal red team. The artefacts fit an operator using LLMs, with the pentest framing there to get the model to do what the operator wants under the belief that it is allowed. The platform makes that easy, because the framing is built in. Its default system prompt tells the model it holds full authorisation, that permission checks are already complete, and that it must not discuss or verify authorisation, and the same block opens every sub-agent prompt. I read that wording from the platform's raw source in versions v1.7.5, v1.7.17 and v1.7.24, every version I checked that carries the operator's workspace layout. I did not check v1.7.0, the first version with that layout.

So an "authorised penetration test" header in this operator's files carries no evidential weight for authorisation either way. The platform tells every session the work is authorised, whoever is driving it. I hold that at HIGH from the source text. It also means the label persuades the model and tells a defender nothing, which SOCs should know.

Two narrower questions stay open, and I state neither as fact. Whether the operator added its own authorisation or scope text on top of the default is INSUFFICIENT, because the platform's database, its `config.yaml`, its conversations and any agent trace are not in the capture I read (the evidence gaps give the bound). Whether a model rather than the operator wrote the ministry report's prose is a working hypothesis at MODERATE and no more. The ministry report reproduces the platform's findings store, but its scope table, organisation chart and asset map are composed text the platform's report generators do not emit, so it is not an unmodified export.

Public reporting already brackets this. Trend Micro's research describes an operator presenting "an authorized assessment" as a false premise to get past model guardrails, and the Cloud Security Alliance notes that the platform's safeguards can be switched off by whoever controls the deployment. I found no public source stating that the default prompt itself asserts authorisation, though the prompt sits in a public repository that anyone can read, so I do not offer that as a novelty claim.

Elastic Security Labs published a second CyberStrikeAI case on 13 November 2026: an operator on a Hong Kong server used stolen credentials against four AWS accounts between 30 September and 16 October, and one role session made 56 calls in 141 milliseconds, about 2.5 ms per call, with 65 of the case's 78 alerts on the first day. It is a different operator on different infrastructure (Section 13). It supplies the measured tempo this case lacks, and Elastic is careful to say it cannot prove a model was making the decisions, which is the same limit I hold here.

## 5. The Attack Chain
{: .hl-tier-2}
{: .hl-tab-chain}

The operator's work runs as one loose chain from a government-wide survey to a single deep win at the agency, with a second, shallower thread through the hosting provider. The chain below is the operator's, stage by stage, using the victim rows from Section 3. Most stages are stock technique driven through two Java web shells the operator held on victim Tomcat and JBoss servers.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/inv-2026-080-cyberstrike-ad-workbench/cyberstrikeai-platform-to-victims-chain.svg" | relative_url }}" alt="Vertical four-step flow on a dark background, titled An AI Agent Platform Drives Stock Tools. Step 1, orange band, Operator and platform: one operator runs CyberStrikeAI from a Paris server, a public AI penetration-testing agent platform written in Go, with its workspace path shown, and its default prompt tells the model the work is authorised. Step 2, red band, The platform drives public tools: off-the-shelf offensive tooling with no new malware found, listed as JexBoss, Kerberoasting, chisel, a GodPotato fork, PwnKit, Rubeus and a public Veeam proof of concept, with chisel, PwnKit and the Veeam proof of concept matching public sources. Step 3, deep red band, The tools reach the targets, by grade: 22 victim rows, with 2 ACCESS SHOWN (a public-sector agency's servers and an SSH jump host), 3 COMPROMISED (an AD domain, a hosting provider and a state agency site), 12 REACHED (government estate, hosting customers, state bodies and others) and 5 LISTED (AD domains, private firms and 27 DNS zones); where two grades fit a row I record the lower one. Step 4, grey band, The defender point: the tools are well documented and easy to detect, and an antivirus product detected the delivered GodPotato fork on a server where the operator held SYSTEM; I do not tie that to the five failed dump runs and did not test it as a defence. The footer lists four detection anchors: /sh/sh.jsp, /invoker/JMXInvokerServlet, the LsassDump service and the pentest@cyberstrike key comment.">
  <figcaption><em>Figure 1: The case in one flow. A public agent platform whose default prompt calls the work authorised drives public tools against 22 graded victim rows, and the same tools are documented and detectable, so that is where a defender can start.</em></figcaption>
</figure>

| Stage | What the operator did | Where it is shown |
|---|---|---|
| 1. Survey | Worked from the CyberStrikeAI workspace on its Paris server, built a seed list of 26 Portuguese government domains in 15 ministry groups, enumerated 10,422 subdomains to 5,846 alive hosts, port-scanned the agency's range and other targets, staged stock chisel for download and compiled its own DNS plugin DLL at 18:14:33 UTC on 5 October 2026 | Workspace paths in 103 files; the seed list, enumeration output and scan logs; the staged files and build artefacts |
| 2. Break in | Probed the agency's records application server (V01) with the public JexBoss tool, which logged its JBoss 4.2.3 `JMXInvokerServlet` VULNERABLE at 22:14:53 on 4 October; an operator web shell at `/sh/sh.jsp` then runs on that host. Held two administrator rows from a state agency's site (V07) and probed portals and login pages across the rest of the list | The JexBoss log and the shell drivers (how the shell was placed is not shown); the operator files listed per row in Section 3 |
| 3. Take the tables | Ran `sqlcmd` through the shell against the records database on a separate database server, pulled the user-account table (3,356 rows) and the password-backup table (166,970 rows), and decrypted 111,404 password values with one key | The collection and decryption scripts and the export they produced |
| 4. Serve them publicly | Moved the export out through the shell and served it from its own open directory: 19 responses with status 200 to 10 distinct public addresses between 10:25:32 on 6 October and 00:45:56 on 7 October; an earlier decrypted accounts file was served from 03:32:17 on 5 October | The operator's own HTTP server log |
| 5. Spread | Created a remote service over SCM on a second V01 server, which ran as SYSTEM, and read its output back over the C$ share; tunnelled through SOCKS and scanned 78 private addresses from an SSH jump host (V22) | The service result files read back over SMB; the jump host's scan output |
| 6. Go for the domain | Ran five LSASS dumps against the second server, none of which left a dump file, and delivered a GodPotato fork that an antivirus product detected; held a member-server memory dump from the V02 domain; Kerberoasted 55 AES256 records, and its cracker printed two candidate passwords that do not verify; built and staged a DNS Server plugin DLL that would create a domain account named `cyberstrike` and add it to Domain Admins | Dump listings ending "File Not Found", the antivirus error, the dump file, the cracking output; the DLL, its source and the upload and setter scripts, with no output in 2,372 held files (archive members included) |
| 7. The hosting provider | Held a WHM root session URL, a root password hash and SSH keys equal to the provider's Puppet-managed copies (V04), and scripted 26 backup API calls, 11 of them file restores and 3 scheduled MySQL restores, aimed at customer data (V05) | The credential files and the backup API scripts |

Read top to bottom, it is a competent but very ordinary intrusion run at breadth, and the platform's contribution was pace and reach. The one deep result sat on a host exposed to a JBoss flaw any scanner can find, and on a password store a single fixed key could open. Everything the operator tried beyond that point, privilege escalation, credential dumping on the second agency server, a domain-admin account, either failed or is not shown to have worked.

## 6. The Records Application Intrusion and the Exposed Credential Export
{: .hl-tier-2}
{: .hl-tab-chain}

The headline finding is narrower than the project report, and the difference is the whole point of this section. I hold at MODERATE that this operator intruded into the records application server and took and decrypted its user and password tables between 4 and 6 October. I hold at INSUFFICIENT any claim that this operator stole personal and health records: the project report claims citizen personal data on a far larger scale (it says nothing about health records), and no file I hold contains the personal or health fields of those tables. Those are two different statements, and the files support only the first.

### What the operator took

The export the operator held is a text dump of two tables from the records application's own database. The user-account table has 3,356 rows, with login, encrypted password, decrypted password, identity-card number, tax number, e-mail, name and phone. The password-backup table has 166,970 rows, each a numeric key, an encrypted password and a decrypted password. Neither table has a health or personal-record field beyond the identity, contact and tax fields listed.

Two held result files go beyond that two-table export. One is a 1,305-row username list with a numeric code column that the export lacks; 98 of its usernames are not in the user table, and I cannot say which population or state of the table it comes from.

The other is a list of 102,169 encrypted password values with a line-parallel decrypted copy. All 102,169 decrypt with the same fixed key, with 0 failures. Of them, 95,691 are values of the export (95,421 sit only in the password-backup table) and the other 6,478 lines, 6,451 distinct, are values that are not in the export.

The list's only header is a column name, and no held query or result set names the table it came from. Its line count matches the count the project report gives for a personnel table's passwords; I hold no file that shows the table it came from. So the held files show 111,404 decrypted values in the export plus 6,451 distinct further values in the separate list. These are values, not people, and the list carries no personal or health field.

The decryption is what turns a database dump into a working credential set. An 856-byte script with a single hard-coded key reproduces the plaintext column on 111,404 of 111,404 encrypted values, 2,088 in the user table and 109,316 in the backup table. The operator's scripts describe that key as the application's default string-encryption key. That is an inference: the extraction from the application's class files is not logged. Either way, a stored password column that one fixed key opens is a basic failure, and it is what made this theft valuable.

### Why I tie it to this records application

Three things line up. The operator pulled both tables by SQL through the web shell. The shell ran on the agency's records application host, and the database it queried sits on a separate agency server that the shell reached over SQL: the host name printed through the shell and the name the SQL session reports differ, and the project report also puts the two on separate machines (whether one name is an alias of the other I did not check). Both hosts sit under the agency's own domain, the database holds the application's schema (87 table and view names), and 16 of the 2,840 non-empty e-mail fields in the user table are on the agency's own domain. I hold the agency as the owner at HIGH, because the host names and the e-mail fields sit under the agency's own domain; I did not check the domain's registrant.

The timing fits as well. The operator's scanner logged the host VULNERABLE at 22:14:53 on 4 October, the decrypted export was being served from the open directory by 10:25:32 on 6 October, and the affected organisation made a public statement of an incident afterwards.

### What I do not hold

The schema list names the personnel and health tables, but no file I hold contains a row of their personal or health fields. The nearest thing is the password list described above, which carries only passwords. That negative is a keyword scan over 2,371 held files (archive members included, a different unit from the 1,887 captured files), and binaries, registry hives and the memory dump were counted by keyword rather than scanned for personal-data rows, so I hold it at MODERATE as a negative.

The host was also exposed to a JBoss deserialization route that anyone running the same public scanner could use. So the most credible alternative is alive: another actor used that route and took the personal and health tables. I cannot kill it, and that is why the attribution of any theft of those tables stays INSUFFICIENT. The agency's own web-server and SQL audit logs would settle it, by showing either a first request to the shell or queries against the personal tables from this operator's addresses, or access from other clients before the operator arrived.

### The export was served to the public internet

The operator did not keep the export to itself. Its open directory served the decrypted credential export 19 times with status 200 to 10 distinct public client addresses, over 14.3 hours of a server log that spans 51.2 hours (22:27:08 on 4 October to 01:38:04 on 7 October, server clock, timezone unstated). Registry-hive files, one of them (the SYSTEM hive) pulled from the agency's server, drew 152 such responses for 48 distinct clients over 45.2 hours; the source of the others is not determined. An earlier file of 3,356 rows holding only the user-account section, with decrypted passwords, was answered 50 times to 27 distinct clients from 03:32:17 on 5 October, so decrypted user-account passwords were public from then.

I do not add those client counts together, because no union of the clients across the paths is stored. The log carries no user agent and a `-` in the size column on every line, so I cannot say which client was the operator, a crawler, a scanner or a person, or whether anything was fetchable outside the logged window. What I can say is that the decrypted export was downloadable from an unauthenticated directory on the public internet, and that is an exposure on top of the theft.

## 7. Timeline
{: .hl-tier-2}
{: .hl-tab-timeline}

This is the dated record of the operator's server and its activity, from the platform's public release to the CERT notification. The operator's hands-on window against the agency is short: under three days, from the first vulnerability verdict on 4 October to the write test in the second server's share on 7 October 2026. Survey, break-in, decryption and publication all sit inside that window, which is what working from an agent platform looked like here. Times from the operator's server log are on its own clock, whose timezone is unstated; times marked UTC come from file metadata. The DLL's first fetch from the directory is at 18:37:32 on that log clock, 22 min 59 s after its 18:14:33 UTC compile time, so if the compile stamp is honest the log clock is not more than 23 minutes ahead of UTC. Before the operator, from 2019 to 2024, `199[.]247[.]13[.]103` served several unrelated earlier tenants, the last a French domain whose certificates run from March 2023 to February 2024.

| Date | Observation |
|---|---|
| 2025-11-08 | The CyberStrikeAI repository is created on GitHub |
| 2026-01-20 to 2026-02-26 | Team Cymru observes 21 IP addresses running CyberStrikeAI, none of them this host |
| 2026-09-20 to 2026-09-23 | The dates covered by the four application logs the operator holds for V12; the latest copied entry is at 21:12:04 on 23 September (application clock) |
| 2026-09-26 | An open-directory monitoring service first indexes the operator's directory on port 8000, with 3,037 items |
| 2026-10-04 22:14:53 | The operator's JexBoss scan logs the records application server VULNERABLE |
| 2026-10-04 22:27:08 | The operator's HTTP server log begins |
| 2026-10-05 03:32:17 | First status-200 response for an earlier accounts-and-passwords file of 3,356 rows (50 responses to 27 clients) |
| 2026-10-05 03:32:30 | First status-200 response for the registry-hive files in the operator's directory |
| 2026-10-05 18:14:33 UTC | `dnsplugin.dll` is compiled |
| 2026-10-06 10:25:32 | First status-200 response for the decrypted credential export |
| 2026-10-06 19:58:01 UTC | Creation time of the LSASS memory dump of the V02 member server |
| 2026-10-07 | Operator-staged files sit in the second V01 server's ProgramData share, with a write test there at 10:00 (target clock); a passive-DNS record pointing `fr[.]bastaniqifi[.]ir` at the host is last modified |
| 2026-10-07 00:45:56 | Last status-200 response for the decrypted export |
| 2026-10-07 01:38:04 | The operator's HTTP server log ends |
| 2026-10-18 | Shodan's last record of the host, with port 8081 answering HTTP 404 |
| 2026-10-31 | The directory is no longer reachable |
| 2026-11-10 | The national CERT is notified |

## 8. Technical Teardown: The Workbench
{: .hl-tier-3}
{: .hl-tab-chain}

The capture is an operator workbench, not a malware family. It is Python written to drive two Java web shells the operator already held on victim servers, plus host and directory reconnaissance, `certutil` and base64 staging, LSASS dumps through the built-in `comsvcs` MiniDump, and a short list of public tools. No malware family is established, and I do not assign one. Each block below opens on its finding; the detail sits behind the toggle.

### 8.1 The two shells, and the client that drives them

Most drivers in the set post to one of two endpoints, and those two paths are the most durable network handle in the case. The first is an HTTPS endpoint at `/sh/sh.jsp` that takes the command in a POST field named `c`; the second is a plain-HTTP `/shell/cmd.jsp?c=` on Tomcat 8.5, which the first shell reaches by running PowerShell `Invoke-WebRequest`.

<details markdown="1" class="hl-teardown">
<summary>The shell client, its transport and the tooling families it drives</summary>

The first shell path is named in 88 of 287 scanned text files and the second in 76, so no more than 164 of the 287 (57 percent) name either. Reaching the internal shell from the first host is a two-hop pivot, so the internal server sees the first shell host as its client, never the operator. The shells' own bytes are not in the capture, so how `/sh/sh.jsp` was placed on the records application server is not shown.

The shared client disables certificate checking, sends a bare `User-Agent: Mozilla/5.0`, and prints whatever the shell returns. Commands travel as PowerShell `-EncodedCommand` in 61 files, or as a base64 blob decoded by `Invoke-Expression` in 10. Files move the same way in both directions: pushed as repeated `echo` of 4,000-character base64 chunks into a staging file under `C:\ProgramData\`, then `certutil -decode`; pulled with `certutil -encode` and `type`.

| Family | Files | What it does |
|---|---|---|
| Web-shell drivers, AD and host reconnaissance | 74 | Send a command to the shell and print the answer; LDAP searches of users, groups, SPNs, delegation, AdminCount, certificate services and resource-based delegation |
| LSASS dumpers | 5 | Create a remote service named `LsassDump` over SCM and run `rundll32 comsvcs.dll, MiniDump` on a second host |
| Tomcat deploy and download drivers | 30 | Push JSPs into the victim application by base64 chunks and `certutil -decode`; pull compiled classes out by `certutil -encode` |
| Backup API scripts | 26 | R1Soft SOAP calls: 11 directory listings, 11 file restores, 3 scheduled MySQL restores and 1 instance listing |
| WHM and cPanel scripts | 4 | WHM `json-api` endpoints with a root authorisation header and a cPanel session path |
| Network probes, OSINT and public-style PoCs | 38 | Port, NFS, NRPE and SIP probes, certificate-transparency enumeration, and Fortinet CVE-2024-21762 scripts |
| Cracking, spray and web-application tests | 68 | hashcat runs and wordlist generators, SSH spraying, hand-rolled MySQL authentication, and Joomla, Moodle and Roundcube login probes |
| GIF-header PHP web shells | 4 | `GIF89a` followed by PHP with `eval` or `system`, under theme-style names |
| Zerologon check toolchain | 17 | Hand-built EPM and NRPC bytes in a C# program compiled on the target side; a check, not the password reset |
| Veeam probe and spray | 10 | Password guessing against Veeam's web and REST endpoints, port probes and SPN queries |
| Kerberos, pass-the-hash and SMB execution | 33 | Ticket requests, offline AES256 cracking, `Invoke-SMBExec`, `Invoke-SMBClient` and SQL `xp_cmdshell` tests |
| Python library tree | 195 | Stock: 179 match 42 public PyPI wheels by hash, 16 are install-generated, 0 are modified |

The family table counts 309 non-library files. The 394 used for the language count also include 85 files that are not tooling families: chisel, PwnKit and potato files, victim copies and logs, and non-root directories.

Chinese comments and variable labels appear in 188 of the 394 non-library files. That tells me who built the tooling, and nothing about nationality, location or authorisation.

</details>

### 8.2 What is stock and what the operator wrote

Nearly everything with a binary in it is a public build, and that is the most useful thing a defender can know about this toolkit. The public PwnKit files, GodPotato V1.20, the public watchtowr Veeam proof of concept and the Invoke-TheHash tree are hash-equal or byte-equal to a published release or source. Stock chisel and the Rubeus build are equal to widely circulating copies instead: the chisel hash is one that 178 VirusTotal sources have seen since 2024-10-07, and the Rubeus build is a circulating one with no official hash to compare. The operator's own work is glue plus a handful of small builds: a PwnKit module and driver, two renamed GodPotato forks and the DNS plugin.

<details markdown="1" class="hl-teardown">
<summary>Stock versus modified, tool by tool</summary>

| Item | Decision | Basis |
|---|---|---|
| `chisel.exe` (sha256 prefix e788f829) | Stock, built unmodified from `jpillora/chisel` commit 3208da3 | Go build info shows `vcs.modified=false` and 14 of 14 dependency versions equal upstream; the same hash 178 VirusTotal sources have seen since 2024-10-07; 56 of 72 engines on VirusTotal |
| `PwnKit.c`, `Makefile`, `ly4k_pwnkit.py` | Stock, byte-identical to `ly4k/PwnKit` | Hashes equal the public files; the prebuilt ELF has been renamed with a `.py` extension |
| Decoded `PwnKit.b64` (prefix cc3b5d07) | The operator's own compile of the stock program, MODERATE | The same 35 named dynamic symbols (36 table entries with the null entry) as the prebuilt, built with GCC Ubuntu 15.2.0 against the prebuilt's 12.1.0; not byte-rebuilt |
| `pwnkit.c`, `pwnkit.so`, `exploit_pwnkit.c`, `exploit_pwnkit_static` | Operator-written | Different source from upstream; the module writes `/tmp/pwned_root.txt` with `id`, 12 lines of `/etc/shadow` and a `/root` listing |
| `GodPotato-NET4.exe` (prefix 9a8e9d58) | Stock, hash-equal to `BeichenDream/GodPotato` V1.20 | Compared with the public release |
| `SvcUtil.exe` (prefix 1046cf19), `SvcUtil_clean.exe` (prefix fe0445f8) | Modified, renamed GodPotato forks; `SvcUtil.exe` adds `MiniDumpWriteDump` | Namespaces renamed, pipe `SvcUtil\pipe\epmapper`, and operator messages such as `[*] LSASS dumped to` |
| `Rubeus.exe` (prefix 1bfbefa4) | A public circulating build, not operator-compiled | Project GUID equals public Rubeus; 333 submissions from 310 sources |
| `dnsplugin.dll` (prefix 02a98b32, 90,947 bytes) | Operator-built and customised, MODERATE | Compiled beside its matching source; the account name it creates reuses the platform's name |
| watchtowr Veeam CVE-2024-40711 tree and its six DLLs | Stock as published | 113 of 113 files byte-equal to the public repository |
| `Invoke-TheHash` tree | Stock | 9 of 9 files byte-equal to the public tree |

All four operator-built ELF files carry the same compiler string, `GCC: (Ubuntu 15.2.0-16ubuntu1) 15.2.0`, which fits a single build workstation. The same unmodified chisel build recurs in other intrusions I have investigated, as do the same GodPotato and SweetPotato builds. None of that is a link between cases. It is simply what a stock toolchain looks like across a body of work, and it is the recognisable, off-the-shelf pattern that makes this operator detectable. SweetPotato is named here as recurring in other cases; it is not held in this case.

The Zerologon toolchain re-implements the constants of the public Secura tester without copying its function names, so I hold it as a re-implementation at MODERATE. It checks for the flaw without performing the password reset that exploits it, and no result is held.

</details>

### 8.3 The DNS plugin that would make a domain admin

`dnsplugin.dll` is the most purposeful thing the operator built, and nothing shows it ever ran. It is a Windows DNS Server `ServerLevelPluginDll` plugin whose attach handler creates a domain account named `cyberstrike`, adds it to Domain Admins and to the local Administrators group, and does nothing else. Built and staged is all I can say; no file holds the setter's output, no DNS service log is held, and no account creation is shown.

<details markdown="1" class="hl-teardown">
<summary>How the plugin is built and how it was meant to be delivered</summary>

The plugin's three exports, `DnsPluginInitialize`, `DnsPluginCleanup` and `DnsPluginQuery`, each return zero. They exist so the DNS service accepts the DLL, and they implement no DNS function. All of the behaviour is in the attach handler, which runs three hidden `WinExec` commands with a three-second sleep between them: a `net user` that creates `cyberstrike` with a 16-character password in the domain, a `net group` that adds it to Domain Admins, and a `net localgroup` that adds it to the local Administrators group. I am not reproducing the password.

Delivery is in two scripts. `upload_dll.py` pushes the DLL through the records application server's shell in 900-character base64 chunks and decodes it with `certutil`. `dnsadmins_attack.ps1` connects over WMI to `root\MicrosoftDNS` with a domain account, reads `MicrosoftDNS_Server.ServerLevelPluginDll`, sets it to a UNC path ending in `dnsplugin.dll` and calls `Put()`. Its target is a DNS server whose address is recorded in V02's row, not shown to be V02's own domain controller. The plugin loads only on the next restart of the DNS service, and a failed load logs DNS Server event 150.

The account name reuses the platform's own name, which ties the DLL to this workbench. Whether its skeleton comes from a public DnsAdmins proof of concept is not determined. A bounded public search read six public source files and found none matching its payload placement or its three-command chain, but the export trio and return-zero bodies are what the plugin API requires anyway, so they do not discriminate.

On a domain controller where this ran, the trace would be a short, fixed sequence: Event 4720, then 4728 and 4732 within about six seconds, with `dns.exe` starting `cmd.exe`, and `ServerLevelPluginDll` under `HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters` set to a UNC path. Any of those in a domain's logs would settle the question the capture cannot.

</details>

### 8.4 The second server at the agency, and the failed dumps

On the second V01 server the operator ran commands as SYSTEM, and the five credential dumps it aimed at the same server left no dump file. A service the operator created over remote SCM ran as SYSTEM and wrote `nt authority\system` to an output file the operator read back over C$. Separately, the operator delivered its GodPotato fork to that server's share and reading it back failed with a virus warning, so an antivirus product detected the tool (the read ran from the shell host over the share, so which host's product raised it is not shown). I do not tie that detection to the five dump runs.

<details markdown="1" class="hl-teardown">
<summary>The SYSTEM service, the failed dumps and the antivirus detection</summary>

The service that ran was `TstSvc2`, created with `sc \\host create`, started, read back and deleted. The dumpers used a service named `LsassDump`, created over SCM, deleted after 30 to 50 seconds, running `rundll32 comsvcs.dll, MiniDump <pid> C:\ProgramData\lsass.dmp full`. Start returned error 1053 (the service did not respond) four times and access denied once, and every listing of the dump path ends "File Not Found". No dump came out of them. The five runs failed for their own reasons: no response from the service, a script quoting fault in two runs, and access denied at service start in one run and inside the command in another. No held output attributes any of those failures to antivirus, and none of the five runs touches the GodPotato fork.

The GodPotato fork was a separate delivery to the same host: the copy into the C$ ProgramData share succeeded. Reading it back failed with a virus warning, `certutil -hashfile` printing `0x800700e1 (ERROR_VIRUS_INFECTED)`, and an in-memory load failed with `BadImageFormatException`. The delivered copy was already not byte-identical to its source before the antivirus step: the two MD5 lines differ, and the encoded file was 80,598 bytes against 80,577 expected. The held memory dump's header time is 19:58:01 UTC on 6 October, and the target lists the fork copy on 7 October on its own clock (day-first reading). On the face of the two clocks the delivery came later, and nothing I hold shows it produced the dump. Operator-staged files were still sitting in that ProgramData share on 7 October.

My read is narrower than it first looks. An antivirus signature fired on a stock tool's fork when it was read back, on a host where the operator already had SYSTEM-level command execution through SCM, and that is the kind of basic control the case keeps coming back to. It is not shown to have stopped anything: the intrusion had already happened, and the five dump runs failed for their own reasons.

| Attempt | What happened |
|---|---|
| Five LSASS dumps on the second V01 server | Service created; start failed with 1053 four times and access denied once; no dump file, cause not shown |
| GodPotato fork delivery | Copied; reading it back failed with `ERROR_VIRUS_INFECTED`, so antivirus detected the tool; the copy was already not byte-identical to its source; in-memory load failed |
| DNS plugin chain | DLL, source, upload tool and setter held; 0 of 2,372 held files (archive members included) hold any output |
| PwnKit | Chain complete; the proof file appears only in build artefacts, never as a result |
| Pass-the-hash, certificate requests, Zerologon checks | Drivers and requests held; no result |
| Credential spraying | 3,100 and 18,558 LDAP attempts with zero hits; 72 of 72 SSH or web attempts failed |
| Fortinet CVE-2024-21762 and Veeam CVE-2024-40711 | Version checks and proof-of-concept scripts held; no response held and no launch shown against a victim |

</details>

### 8.5 The V02 memory dump

The domain on V01's network is compromised on one artefact: a genuine memory dump of a domain-joined Windows Server 2019 member server. It parses to 36 logon sessions, and the dumped host's machine account is 1 of the 34,149 rows in the domain's own computer inventory, also held by the operator. By name, the dump is the web-shell host's: its own SYSTEM and NETWORK SERVICE sessions carry that host's machine account (MODERATE, because name equality is not machine identity). It is not the database server, whose name never appears in the dump as its own account. No held output shows the command that wrote the dump, and the five dump scripts in the capture left no dump file. I grade V02 COMPROMISED and not ACCESS SHOWN because the dump is a V01 host's memory, and what it gives the operator on V02's domain is credential material, not shown access.

<details markdown="1" class="hl-teardown">
<summary>What the dump holds, which is less than it first appears</summary>

The file is 72,374,897 bytes with a valid `MDMP` header, created at 19:58:01 UTC on 6 October 2026, from a server that is not a domain controller. As a control on the machine-account match, the dump's other machine account matches 0 of the 34,149 inventory rows.

It holds 33 NT entries, 59 Kerberos AES keys and 24 records labelled as passwords. Those 24 are not 24 user passwords. Two sit under user-account sessions, 16 under font-driver and window-manager sessions with 5 distinct values among them, 5 under NT SERVICE and 1 under a machine account, for 7 distinct values overall. The dump covers only 4 distinct user accounts across 6 sessions, and only 1 of those carries the V02 domain label.

Elsewhere in the same domain the operator Kerberoasted 55 AES256 ticket records (with 11 failures) and recovered 1 of 5 NTLM hashes offline. The operator's cracker printed two service-account passwords as found; its test checks one decrypted byte, and an independent checksum check rejects both against every held ticket, so no service-account password was cracked. Two LDAP password sprays of 3,100 and 18,558 attempts, separate nested-loop runs, got zero hits. The operator also fed the application's decrypted account export into LDAP binds against the domain, with no result held.

</details>

### 8.6 The hosting provider and the jump host

The hosting-provider thread is broad and shallow: root-level credential material, a backup API the operator could drive, and no customer output at all. The operator held a WHM root session URL, a root password hash for a DNS host, and private SSH keys equal to the provider's Puppet-managed copies, and it scripted 26 R1Soft backup API calls aimed at customer backups.

<details markdown="1" class="hl-teardown">
<summary>Backup restores, the DNS zones and the scan from the jump host</summary>

The backup scripts target customer servers for root keys and cPanel access hashes. They include restores to an alternate agent with destination `/var/www/html/` and overwrite set, and scheduled MySQL restores carrying `init-file` and `log-error` options, which is a way to plant files or run SQL on a customer's server through the provider's own backup system. The replies held show replication as RUNNING, never completed, and the restores aimed at one host returned error pages. The provider's backup service and WHM could reach 15 hosted customers and 27 government DNS zones. That is a capability the operator scripted and never showed working.

The 27 zone files (827 records) are administrative copies. They are not a zone-transfer transcript and not evidence that any zone was changed.

The scan output is the one host-side artefact on this thread, and it is not on a provider machine I can show. It is 629 lines: three OpenSSH client warnings, a line count of `/tmp/scan_4.log`, then 625 address and port rows over 78 private addresses in one /24, 3 of which are among the provider's 14 recorded addresses. Because it is the output of a command the operator ran on the jump host, that host is ACCESS SHOWN (V22) with its owner unknown. A Kerberos log that ran over a local SOCKS port is account enumeration: 2,115 error replies, 2,112 for unknown principals and 3 `KDC_ERR_CLIENT_REVOKED` replies, which confirm that three submitted names exist and are disabled or locked, and no AS-REP at all.

</details>

### 8.7 The operator's own environment

A few artefacts identify the operator's working environment. None of them names a person, a nationality or a publicly named actor.

<details markdown="1" class="hl-teardown">
<summary>Key comment, account name, ports and build toolchain</summary>

| Artefact | Value | What it tells a defender |
|---|---|---|
| SSH key comment | `pentest@cyberstrike` on the operator's ed25519 and RSA-4096 key pairs | A self-description on the operator's own key, worth searching for in `authorized_keys`; it is not authorisation |
| Account name | `cyberstrike`, the account the DNS plugin would create if loaded | Reuses the platform's name |
| Workspace projects | `72995c0d-1e52-4f27-b754-a7d80c685421` and one beginning `6a86acd6` | The operator's two platform projects |
| Server ports | 8000 open directory, 8081 stock chisel reverse server, 8090 tool staging | `daemon_chisel.py` starts `chisel server --reverse --port 8081` from the workspace directory, which fits the HTTP 404 seen on 8081 |
| Build toolchain | `GCC: (Ubuntu 15.2.0-16ubuntu1) 15.2.0` | One Ubuntu toolchain for all four operator-built ELF files |
| Working language | Chinese comments and labels in 188 of 394 non-library files | Who built the tooling, not who authorised it |

</details>

## 9. Infrastructure
{: .hl-tier-2}
{: .hl-tab-timeline}

The operator's server is ordinary commercial hosting, and nothing about it points to a particular actor. `199[.]247[.]13[.]103` is a Vultr address (The Constant Company, AS20473) in the 199[.]247[.]0[.]0/19 block, announced from Paris. I hold the ASN and block at HIGH. I found no bulletproof-hosting indicator, and I put "not bulletproof" at MODERATE because it rests on the provider's identity alone; I did not check reputation lists or cross-check the routing record. Whether the operator rented this instance or compromised someone else's is INSUFFICIENT: the evidence is consistent with a rental, and nothing in it tells the two apart.

The address has a history, which is the main reason not to over-read anything else that pointed at it. It served unrelated tenants in 2019, 2021 and 2023 to 2024, including a French domain whose certificates ran from March 2023 to February 2024. That is a domain of a prior tenant of the address, unrelated to the operator, and I do not name it or put it in the indicator feed, because blocking it would hit an innocent third party.

The one current tie is a passive-DNS record. `fr[.]bastaniqifi[.]ir` resolved to the host, with a TTL of 300 and a last-modified date of 7 October 2026, inside a set of country-labelled `.ir` hostnames that each point at a different host on a different network and look like a VPN or proxy node fleet. The record exists, at HIGH. Whether the operator runs that fleet, rents a node in it or merely shares an address with it is not established, so I hold it as a link at LOW. The record's first appearance is not known, so I cannot order it against the open directory. The hostname is in the feed as hunt-only and never block.

The three open ports tell the operator's working pattern. Port 8000 was the open directory. Port 8090 staged tools for download, `chisel.exe` and `dnsplugin.dll` among them, fetched by victims with `certutil`. Port 8081 answered plain HTTP with 404 on 7 October, which fits the stock chisel reverse server the operator's own script starts there; that inference is MODERATE, from the script and the sighting, with no packet capture.

Both TLS fingerprint (JARM) values in this case are common, each shared by more than 100,000 hosts, so neither carries a link to anything. I hold no packet capture of the operator's traffic and probed only a small part of the host's port range before it went dark.

## 10. MITRE ATT&CK Mapping
{: .hl-tier-2}
{: .hl-tab-chain}

The operator's behaviour maps to 69 procedure rows covering 66 distinct technique IDs in 13 tactics of ATT&CK Enterprise v20.0, every ID live and none revoked. The Status column uses three values. OBSERVED means I hold an operator-side result for the procedure, which includes a retained attempt that failed where the attempt is itself the procedure. INFERRED means the operator's tooling is built to do it and a driver or request is held, but no execution result is. NOT SHOWN would mark a boundary that claims no impact, and no row needs it here.

The counts are 42 OBSERVED and 27 INFERRED, and row confidence is HIGH on 29, MODERATE on 37 and LOW on 3. Three of the OBSERVED rows carry a qualifier in their evidence: the service-execution row, where the SYSTEM service ran and the dump runs on the same host failed; the password-spraying row, where every attempt failed; and the Windows-service row, where each service was transient.

OBSERVED never means a victim log or a victim grade: I hold no victim telemetry, so it is always the operator's own record of a result. No row maps Impact, phishing or supply chain, because nothing held shows encryption, wiping, defacement or a lure. The DNS Server plugin route has no dedicated technique in v20.0 and is recorded by its effects, under Windows Management Instrumentation, Domain Account and Account Manipulation. The attack chain above links each stage to its rows, and the full table is in the collapse below.

<details markdown="1" class="hl-teardown">
<summary>All 69 procedure rows, with status, confidence and evidence</summary>

| Tactic / Technique | Name | Status | Conf. | Evidence |
|---|---|---|---|---|
| Reconnaissance / T1595.001 | Scanning IP Blocks | OBSERVED | HIGH | nmap of V01 range; masscan and rustscan of two ranges |
| Reconnaissance / T1595.002 | Vulnerability Scanning | OBSERVED | HIGH | JexBoss VULNERABLE on V01; Struts and Fortinet probes |
| Reconnaissance / T1590.002 | DNS | OBSERVED | HIGH | 10,422 subdomains, 5,846 alive, 26 seed domains |
| Reconnaissance / T1596.003 | Digital Certificates | INFERRED | MODERATE | `crtsh_enum.py`; output not tied to a held file |
| Resource Development / T1588.007 | Artificial Intelligence | OBSERVED | HIGH | CyberStrikeAI workspace; platform finding IDs in report |
| Resource Development / T1588.002 | Tool | OBSERVED | HIGH | chisel, PwnKit, GodPotato V1.20, Rubeus, Invoke-TheHash |
| Resource Development / T1587.001 | Malware | OBSERVED | HIGH | DNS plugin, gconv module, static driver, SvcUtil forks |
| Resource Development / T1608.001 | Upload Malware | OBSERVED | HIGH | chisel on 8090; DLL and source served from 8000 |
| Initial Access / T1190 | Exploit Public-Facing Application (V01) | OBSERVED | MODERATE | JBoss `JMXInvokerServlet`; the scan is HIGH, how the shell was placed is not shown |
| Initial Access / T1190 | Exploit Public-Facing Application (V07) | OBSERVED | MODERATE | Two admin rows in `sqli_users.json`; route inferred |
| Initial Access / T1190 | Exploit Public-Facing Application (others) | INFERRED | MODERATE | UNION injection on a Brazilian site; four web-app probes |
| Initial Access / T1078.002 | Domain Accounts (V02) | OBSERVED | MODERATE | Working V02 identity used for roasting and the setter |
| Initial Access / T1078 | Valid Accounts (V04 backup API) | OBSERVED | MODERATE | Authenticated R1Soft replies, status 200 |
| Execution / T1059.003 | Windows Command Shell | OBSERVED | HIGH | `cmd`, `certutil`, `sc`, `rundll32`, `sqlcmd` via field `c` |
| Execution / T1059.001 | PowerShell | OBSERVED | HIGH | `-EncodedCommand` in 61 files; `Invoke-Expression` in 10 |
| Execution / T1059.004 | Unix Shell | INFERRED | MODERATE | PwnKit upload recipe; SSH-run scan inside V04 /24 |
| Execution / T1047 | Windows Management Instrumentation | INFERRED | MODERATE | WMI sets `ServerLevelPluginDll`; no output held |
| Execution / T1053.005 | Scheduled Task | OBSERVED | HIGH | SYSTEM tasks created, run and deleted via the shell |
| Execution / T1569.002 | Service Execution | OBSERVED | HIGH | SCM service ran as SYSTEM; five LsassDump runs failed |
| Persistence / T1505.003 | Web Shell | OBSERVED | HIGH | `/sh/sh.jsp`, `/shell/cmd.jsp`, `diag*.jsp` pushed by `certutil` |
| Persistence / T1505.001 | SQL Stored Procedures | OBSERVED | MODERATE | `xp_cmdshell` starts PowerShell; SQL-context `whoami` held |
| Persistence / T1136.002 | Domain Account | INFERRED | MODERATE | DLL runs `net user cyberstrike ... /add /domain` on load |
| Persistence / T1098 | Account Manipulation | INFERRED | MODERATE | Domain Admins add by the DLL; WHM root password change |
| Persistence / T1543.003 | Windows Service | OBSERVED | HIGH | `TstSvc2` and `LsassDump` created, then deleted |
| Privilege Escalation / T1068 | Exploitation for Privilege Escalation | INFERRED | MODERATE | PwnKit chain and operator gconv module; run not shown |
| Privilege Escalation / T1134.001 | Token Impersonation/Theft | INFERRED | MODERATE | `SvcUtil.exe` and `SvcUtil_clean.exe` pushed at V01 |
| Stealth / T1036.005 | Match Legitimate Resource Name or Location | INFERRED | MODERATE | GodPotato fork as `SvcUtil.exe` in `C:\ProgramData\` |
| Stealth / T1140 | Deobfuscate/Decode Files or Information | OBSERVED | HIGH | `certutil -decode` of 900 and 4,000-character chunks |
| Stealth / T1070.004 | File Deletion | INFERRED | MODERATE | `rm -rf` of `GCONV_PATH=.` directories; service deleted |
| Stealth / T1564.003 | Hidden Window | INFERRED | MODERATE | The DLL's three `WinExec` calls use a hidden window |
| Stealth / T1218.011 | Rundll32 | INFERRED | MODERATE | `rundll32 comsvcs.dll, MiniDump` in five dumpers |
| Credential Access / T1003.001 | LSASS Memory | OBSERVED | HIGH | 72 MB V02 dump: 36 sessions, 4 user accounts |
| Credential Access / T1003.002 | Security Account Manager | OBSERVED | HIGH | SAM and SYSTEM hive copies; six local accounts |
| Credential Access / T1003.004 | LSA Secrets | OBSERVED | MODERATE | SECURITY hive copies, 241 keys; origin host unknown |
| Credential Access / T1558.003 | Kerberoasting | OBSERVED | HIGH | 55 AES256 records, 11 failures |
| Credential Access / T1110.002 | Password Cracking | OBSERVED | HIGH | Kerberos cracking runs: 0 recovered, 2 false candidates refuted; 1 of 5 NTLM |
| Credential Access / T1110.003 | Password Spraying | OBSERVED | HIGH | 3,100 and 18,558 LDAP attempts in two separate nested-loop runs, zero hits (failed) |
| Credential Access / T1110.004 | Credential Stuffing | INFERRED | MODERATE | Application export fed to V02 LDAP binds; result not shown: no held output of a run |
| Credential Access / T1110.001 | Password Guessing | INFERRED | MODERATE | Webmail, MySQL on 22 addresses, SSH logins; no success |
| Credential Access / T1555 | Credentials from Password Stores | OBSERVED | HIGH | One key decrypts 111,404 of 111,404 values |
| Credential Access / T1552.004 | Private Keys | OBSERVED | MODERATE | Unencrypted keys from the V04 Puppet copy |
| Credential Access / T1552.006 | Group Policy Preferences | INFERRED | LOW | SYSVOL `cpassword` reader; no result |
| Credential Access / T1649 | Steal or Forge Authentication Certificates | INFERRED | MODERATE | Certificate request with alternate UPN; none issued |
| Credential Access / T1606 | Forge Web Credentials | INFERRED | MODERATE | `GenToken.java` bearer token; 4 of 4 answered 401 |
| Lateral Movement / T1021.002 | SMB/Windows Admin Shares | OBSERVED | HIGH | `C$\ProgramData` listing and SYSTEM-written file read |
| Lateral Movement / T1570 | Lateral Tool Transfer | OBSERVED | HIGH | 59,392 bytes pushed as reversed base64, copied to C$ |
| Lateral Movement / T1021.004 | SSH | OBSERVED | MODERATE | 625-row scan run from the jump host into a /24 |
| Lateral Movement / T1550.002 | Pass the Hash | INFERRED | MODERATE | `Invoke-SMBExec` with an NTLM hash, 17 hosts; no result |
| Lateral Movement / T1550.003 | Pass the Ticket | INFERRED | LOW | One driver requests `/ptt`; injection not seen |
| Lateral Movement / T1210 | Exploitation of Remote Services | INFERRED | LOW | Zerologon check loop; not the reset; no result |
| Discovery / T1087.002 | Domain Account | OBSERVED | HIGH | 66 account rows and 344 account-and-SPN rows |
| Discovery / T1087.002 | Domain Account (Kerberos enumeration) | OBSERVED | MODERATE | 3 KDC_ERR_CLIENT_REVOKED replies: 3 names exist and are disabled or locked; 2,112 unknown |
| Discovery / T1069.002 | Domain Groups | INFERRED | MODERATE | Domain Admins and DnsAdmins queries; no result |
| Discovery / T1482 | Domain Trust Discovery | INFERRED | MODERATE | Trust enumeration of two further domains |
| Discovery / T1018 | Remote System Discovery | OBSERVED | MODERATE | Backup agent inventory, 8 records; DC resolution |
| Discovery / T1046 | Network Service Discovery | OBSERVED | HIGH | 53 hosts over 31 ports; scan inside V04 |
| Discovery / T1033 | System Owner/User Discovery | OBSERVED | HIGH | `whoami` via the shell: SQL context on V01 |
| Discovery / T1007 | System Service Discovery | INFERRED | MODERATE | `sc` query of certificate service; Veeam probes |
| Discovery / T1083 | File and Directory Discovery | INFERRED | MODERATE | Backup directory listings; 40 customer home dirs |
| Collection / T1005 | Data from Local System | OBSERVED | HIGH | Application tables by SQL; an 18 MB hive; class files |
| Collection / T1119 | Automated Collection | OBSERVED | MODERATE | One scripted run pulls both tables and decrypts |
| Collection / T1074.001 | Local Data Staging | OBSERVED | MODERATE | `C:\ProgramData\` staging; encoded class files |
| Collection / T1074.002 | Remote Data Staging | INFERRED | MODERATE | Backup restore to `/var/www/html/`; never completed |
| Command and Control / T1071.001 | Web Protocols | OBSERVED | HIGH | HTTPS POST to `/sh/sh.jsp`; GET `/shell/cmd.jsp?c=` |
| Command and Control / T1090.001 | Internal Proxy | INFERRED | MODERATE | First shell fronts the internal shell |
| Command and Control / T1572 | Protocol Tunneling | OBSERVED | MODERATE | Replies over a local SOCKS port; chisel reverse server |
| Command and Control / T1105 | Ingress Tool Transfer | INFERRED | HIGH | `certutil -urlcache` of chisel from 8090; HIGH that the script issues it (read in full), execution output not held |
| Command and Control / T1132.001 | Standard Encoding | OBSERVED | MODERATE | 252 base64 segments pulled; 900 and 4,000-char pushes |
| Exfiltration / T1041 | Exfiltration Over C2 Channel | OBSERVED | HIGH | 252 of 252 segments of a 25 MB file via the shell |

</details>

## 11. Indicators of Compromise
{: .hl-tier-2}
{: .hl-tab-indicators}

The indicators for this case are operator-side only: the operator's server, the files it built or wrote, and its own labels. No victim value is in the feed, since I name no victim. The full machine-readable set is the IOC feed, [`inv-2026-080-cyberstrike-ad-workbench-iocs.json`](/ioc-feeds/inv-2026-080-cyberstrike-ad-workbench-iocs.json), at TLP:CLEAR. It carries 26 operator-side indicator entries: 14 SHA-256 file hashes, the operator's IP address, 3 host-and-port endpoints, 4 file or web paths, 1 named pipe and 3 behavioural entries.

Of the 14 hashes, 9 are files the operator built or wrote and 1 is its own compile of the stock PwnKit source. The other 4 are stock public tools, chisel, Rubeus, GodPotato V1.20 and the prebuilt PwnKit, marked HUNT rather than BLOCK because their hashes match anyone using the public tool. A short set worth acting on first:

| Indicator | What it is | Confidence | Action |
|---|---|---|---|
| `199[.]247[.]13[.]103` | Operator server on Vultr, Paris: open directory on 8000, chisel reverse server on 8081, tool staging on 8090 | HIGH | Block, time-boxed: the address has had other tenants and may be reassigned |
| `02a98b325408f623e192d569d6cb11a60aaf61a114a5c4f35bbfd1dcbe56d69c` | `dnsplugin.dll`, the DNS Server plugin that would create the `cyberstrike` domain admin | HIGH | Block |
| `1046cf19fb280684236193059805005bb8b1f3ad3b6fe7ca2b35d9dea8523273` | `SvcUtil.exe`, renamed GodPotato fork with an added LSASS minidump | HIGH | Block |
| `fe0445f870c905ff33fc75223ce709992f8bb219d2fff6acd3775518b894a025` | `SvcUtil_clean.exe`, renamed GodPotato fork | HIGH | Block |
| `7033ee65a125bec39860af0cef8d64f46a0cf7e579baab5d57e31d83367333f9` | `pwnkit.so`, operator-written PwnKit gconv module | HIGH | Block |
| `863a7a843b30d5252a84e5b03e850236fce4cac1954be4227c1cf396138759a5` | `exploit_pwnkit_static`, operator-written PwnKit driver | HIGH | Block |
| `e788f829b1a0141a488afb5f82b94f13035623609ca3b83f0c6985919cd9e83b` | Stock `chisel.exe` delivered to victims from port 8090 | HIGH | Hunt |
| `/sh/sh.jsp` and `/shell/cmd.jsp` | The operator's two JSP web shell paths, command in parameter `c` | HIGH | Hunt in web and proxy logs |
| `\\.\pipe\SvcUtil\pipe\epmapper` | Named pipe of the two GodPotato forks | HIGH | Hunt |
| `/tmp/pwned_root.txt` | Root proof file written by the operator's PwnKit module | HIGH | Hunt |
| `cyberstrike` | Domain account the DNS plugin would create if loaded, the platform's own name | HIGH | Hunt in directory and account-creation events |
| `pentest@cyberstrike` | Comment on the operator's ed25519 and RSA-4096 SSH keys | HIGH | Hunt in `authorized_keys`; the feed also carries the ed25519 public key |
| `fr[.]bastaniqifi[.]ir` | Passive-DNS name that pointed at the operator's address; tie to the operator LOW | LOW | Hunt only, never block |

Two things are deliberately left out of the indicator buckets. A domain of a prior tenant of the address, unrelated to the operator, is left out of the feed entirely, because blocking it would hit an innocent third party. A third party's loader host, found injected into a map-plugin export the operator took from a victim-side website, is also excluded: it is another actor's earlier modification of that site, not this operator's, and it occurs in no operator tooling.

The CyberStrikeAI workspace path is in the feed as a hunt value, and it needs care. It is the platform's default layout, not something the operator chose, and security teams run the platform on purpose, so a hit shows the platform in use on a host and nothing more.

## 12. Detection and Hunting Guidance
{: .hl-tier-2}
{: .hl-tab-indicators}

The [detection file](/hunting-detections/inv-2026-080-cyberstrike-ad-workbench-detections/) for this case carries 23 rules: 7 YARA (3 detection, 4 hunting), 11 Sigma (3 detection, 8 hunting) and 5 Suricata (1 detection, 4 hunting). The 7 Detection-tier rules are high-fidelity and safe to alert on; the 16 Hunting-tier rules key on broader behaviour or a name the operator can change, and their hits need review. Every rule validates in its engine, and none has been confirmed against live victim or sensor telemetry, because the case holds none.

I have not established that these Sigma rules are new upstream. The SigmaHQ rule "HackTool - Rubeus Execution" already covers `Rubeus.exe`, `kerberoast` and `asktgt`, so my Rubeus rule covers only the `asktgs` service-ticket request. Whether upstream already covers the Detection-tier rule on a `GCONV_PATH` directory (a Linux file event) or the rule on a user account named `cyberstrike` being created (Windows Security event 4720) is NOT CHECKED.

Two of the YARA rules are tested against the right negatives, and that bounds what they claim. The DNS-plugin rule hits `dnsplugin.dll` and misses four stock System32 DLLs. The GodPotato-fork rule hits both `SvcUtil` builds and misses stock GodPotato, so it finds this operator's fork rather than every use of the public tool.

What the case gives a detection engineer, in order of durability:

- The shell paths and their shape come first, as an HTTPS POST to `/sh/sh.jsp` with a single form field `c`, a bare `Mozilla/5.0` user agent and certificate checking off on the client; or a GET to `/shell/cmd.jsp?c=` on Tomcat 8.5, often from another internal server.
- The JBoss entry shows as requests to `/invoker/JMXInvokerServlet` carrying a serialized Java object, and the JexBoss shell page. The Suricata Detection rule covers a JSP write through the invoker servlet.
- Service-based credential dumping shows as a remote service named `LsassDump` created over SCM and deleted 30 to 50 seconds later, with an image path running `comsvcs.dll, MiniDump` into `C:\ProgramData\lsass.dmp`.
- Staging through `certutil` shows as repeated base64 `echo` appends to a file under `C:\ProgramData\`, followed by `certutil -decode` into a Tomcat webapps tree.
- The DNS plugin chain leaves a PE exporting exactly `DnsPluginInitialize`, `DnsPluginCleanup` and `DnsPluginQuery` with `WinExec` and `Sleep` imports; `ServerLevelPluginDll` set to a UNC path; and Events 4720, 4728 and 4732 within about six seconds with `dns.exe` starting `cmd.exe`.
- Backup-system abuse shows as R1Soft restores to an alternate agent with destination `/var/www/html/`, or scheduled MySQL restores carrying `init-file` and `log-error`. I have no rule for this; the backup server's own API audit log is where it shows.

Several behaviours are covered upstream already, so I did not duplicate them. The DnsAdmins registry and child-process rules, `comsvcs` MiniDump on a command line, a shell under `sqlservr.exe` and web-shell command words in access logs all have SigmaHQ rules. SigmaHQ also covers `Rubeus.exe` runs and the `kerberoast` and `asktgt` command lines, which is why my Rubeus rule keeps only `asktgs` with `/ticket:` and `/service:`. Stock chisel and Rubeus are matched by public signatures. The weakest handle in the set is the staging directory `C:\ProgramData\`, because the name is common.

The operator also tested a found AWS key with one signed `sts:GetCallerIdentity` call (V14). That is the first step of Elastic's CyberStrikeAI case too, and a first-time GetCallerIdentity call from an unfamiliar external address is the cloud-side handle for it. I wrote no cloud rule, because I hold no result of that call and no cloud telemetry.

Three gaps remain. The JSP shells' own bytes are not held, so there is no file rule for them, only the request path and parameter. Kerberoast volume needs a per-environment baseline I do not have; the operator used AES256 tickets, so the common RC4-downgrade rules will not fire on it. And the platform's own artefacts, its prompt and findings store, never cross a victim network, because the model calls run from the operator's server to its model provider.

## 13. Threat Actor Assessment
{: .hl-tier-2}
{: .hl-tab-attribution}

I cannot attribute this operator to a named actor or persona, and I am not creating a tracking designation for it; where a label is needed, it is the operator of this case. The operator is the person or team that ran the CyberStrikeAI workbench on `199[.]247[.]13[.]103` in early October 2026. The platform is public, the server is ordinary Vultr hosting, and every tool that recurs across my other cases is stock. That leaves nothing to tie the operator to anyone else. This is the first coverage The Hunters Ledger has published on this operator; the only overlap with earlier cases is shared commercial hosting and stock tooling, and neither gives an operator-specific link.

### Authorised or not: one verdict

My judgment is that this was unauthorised intrusion, not a sanctioned red team, and I hold that at MODERATE for the whole of the activity, with no split between the ministry work and everything else. None of the 1,887 files captured from the directory as of 12 November 2026 holds an engagement letter, scope file, rules of engagement, client name, authoriser or sign-off, and the ministry report crosses the exclusion list it sets itself. The target set is the central government of Portugal plus a hosting provider's tenants and unrelated third parties, which no single client could authorise. The project report's own scope table lists the hosting provider's estate, a private software vendor and a Brazilian commercial site, none of which a ministry can authorise. The "authorised penetration test" artefacts I read as framing aimed at the model, for the reasons in Section 4.

The calibration around that verdict matters as much as the verdict. That the platform's default prompt tells every model session it holds full authorisation is HIGH, from the raw source. Whether the operator added its own authorisation text is INSUFFICIENT. That a model wrote the ministry report is a MODERATE hypothesis, which I do not state as fact. What would change the verdict is the one version of the operator's ministry report I do not hold (29,979 bytes) naming a client, an authoriser, a scope and dates that match the victims, and even that could only change the ministry slice, not the provider, domain, state-agency-site or Brazilian-site work.

Unauthorised does not mean profit-driven. No resale list, extortion note, ransom text or wallet is held.

### Motive and operating model

The motive is undetermined, at LOW. Three readings survive without anything to choose between them. Money fits the credentials taken and one script that queries a payment gateway's merchant configuration, but no buyer, price or demand is held. A mission fits the government-wide seed list and the ministry report, but no tasking text or state-linked lineage is held. And practice fits an operator running an agent platform that grants itself authorisation, but nothing explains why it served the decrypted export publicly.

On operating model, the files show what I call espionage at MODERATE, and I mean that word narrowly here: observed data theft with no monetisation shown. It does not establish a state sponsor or a mission. They also show preparation for further attacks at MODERATE, in the jump-host pivot and the staged domain-admin DLL, which is staged capability and not a result. Theft for money stays a hypothesis at LOW.

### Linkage

No operator-side identifier recurs anywhere else I hold. I swept the operator's host, its SSH key pairs, its two workspace project IDs and its fleet names across 33,738 files from my other investigations, with a control that reproduced, and found 0 other-case hits. Public open-directory capture data shows the key blob and the project ID only on this host. What does recur is stock tooling: the same chisel, GodPotato and SweetPotato builds turn up in other intrusions I have investigated. That is the commodity pattern, not a link.

One other operator I investigated in the same period, on a different host, shares a single TLS fingerprint (JARM) value with a node of the `.ir` fleet. That value is shared by more than 100,000 hosts, so it carries no weight. Names, addresses and file hashes share nothing, and the working language, tooling, hosting and targeting differ. The two are not shown to be the same operator, and I do not say they are unrelated either.

Elastic's 13 November 2026 case is the same tool in another operator's hands. Its three server addresses, its hosting (AS133199, Hong Kong), its certificate serial and its FOFA fingerprint occur in none of the 33,805 files of my investigations, where this case's own address occurs in 17, and Elastic's article carries none of this operator's identifiers. The two windows overlap, 30 September to 16 October there and 4 to 7 October here, but the platform is public, so a shared tool and overlapping dates are not a link. I hold no certificate from this host's platform interface to set against Elastic's, so that one comparison is not made.

| Hypothesis | Inconsistencies | Where it stands |
|---|---|---|
| An unauthorised intruder, not a sanctioned engagement | None in the files held; one version of the operator's ministry report is unheld | Carried, MODERATE |
| A sanctioned red team or national exercise | No engagement document in 1,887 files; the report breaks its own exclusion list; the target set spans the central state and a provider's tenants; the authorisation label is the platform's default prompt | Not supported, and not killed outright while one report version is unheld |
| A model, not the operator, wrote the report | The report is not an unmodified platform export; no agent trace, conversation or database is held | MODERATE as a working hypothesis only |
| The same operator as that other case | Different language, tooling, hosting and targeting; 0 shared names, addresses or hashes; the shared JARM is common | INSUFFICIENT: not shown |
| The same operator as Elastic's AWS case | Different address, hosting and targets; 0 of Elastic's identifiers in 33,805 files; this host's platform certificate is not held | INSUFFICIENT: not shown |
| The operator runs the `.ir` node fleet | One A record, first appearance not known (last modified 7 October 2026); the address had earlier tenants | LOW as a link |
| The motive is financial | No buyer, price, demand or wallet; the payment-gateway script has no result | LOW, a hypothesis |

| Call | What would change it |
|---|---|
| No named actor or persona, INSUFFICIENT | A second case holding either SSH key pair or either workspace project ID, or the platform's own database |
| Unauthorised, MODERATE | The unheld 29,979-byte report version naming a client, authoriser, scope and dates matching the victims; it could move only the ministry slice |
| Motive undetermined, LOW | A buyer, price or demand; tasking text or a state-linked lineage; or the operator's reason for serving the export publicly |
| The `.ir` fleet tie, LOW | IP history for the host and the fleet nodes, DNS history, or a `.ir` hostname or panel in the operator's files |
| No link to that other case, INSUFFICIENT | A Farsi or `.ir` artefact in this operator's files, a CyberStrikeAI artefact in the other's, or a shared origin address behind the fleet domains |
| No link to Elastic's AWS case, INSUFFICIENT | This host's platform certificate matching Elastic's serial, or a shared address, credential or cloud account between the two |

## 14. Recommendations
{: .hl-tier-1}
{: .hl-tab-indicators}

These follow from what this operator did and where ordinary controls showed up. The operator ran the platform against commodity public tools, and an antivirus product detected a delivered GodPotato fork on a server where the operator already had SYSTEM. I do not tie that detection to the failed dumps, and protection did not stop the intrusion elsewhere, so these are the basics the case points at, not a tested defence. The tools are old, so the controls are too; what this case changes is how fast they have to work.

- Find and retire exposed JBoss invoker servlets (`/invoker/JMXInvokerServlet`) and other long-public deserialization entry points on internet-facing application servers. The operator's one deep win was on a host exposed this way, though how its shell was placed is not shown.
- Stop storing passwords with reversible encryption under a fixed or default application key. One key opened 111,404 of 111,404 stored values here.
- Keep endpoint protection current on internal servers, including the ones reached only from other servers. It detected the GodPotato fork the operator delivered to the second agency server; I do not tie that detection to the failed dumps.
- Treat SQL `xp_cmdshell`, the SQL `sa` login and remote service creation over SCM on application servers as alarms, not noise.
- Restrict DnsAdmins membership and alert on any change to `ServerLevelPluginDll`, and on account creation or Domain Admins changes with `dns.exe` as the caller.
- For hosting providers, protect the backup API and WHM root credentials as you would domain admin, since they reach the provider's customers, and watch for restores to a web root or MySQL restores carrying `init-file`.
- Hunt for the operator's SSH key comment `pentest@cyberstrike` in `authorized_keys`, the `cyberstrike` account name, and the two JSP shell paths in web logs.
- Block or hunt the stock tools in this toolkit by their public hashes and signatures (chisel, Rubeus, GodPotato, PwnKit), and the operator-built files by the hashes in the feed.

## 15. Confidence Summary and Evidence Gaps
{: .hl-tier-2}
{: .hl-tab-confidence}

The case rests on the operator's own files: its scripts, builds, logs, exports and report, captured from its open directory. That makes the evidence strong on what the operator did and built, and silent on what the victims' systems recorded, because I hold no victim-side telemetry at all. Each load-bearing judgment below carries its confidence and the observable that would move it.

The single source that would do the most damage if wrong is the operator's own server log, because the public-exposure claim and the 14.3-hour span rest on it alone; the application link rests on the operator's SQL output together with a public statement by the affected organisation, which is a second, independent source. No two sources I hold disagree on a fact. The project report claims far more than the two credential tables and no file I hold contains it, which is a gap in what I hold and not a contradiction.

| Claim | Confidence | What would change it |
|---|---|---|
| The 22 victim rows grade 2 ACCESS SHOWN, 3 COMPROMISED, 12 REACHED and 5 LISTED | HIGH | A held reply, victim-side log or script output that raises a row |
| The operator intruded into the records application and took and decrypted its user and password tables | MODERATE | The agency's web-server and SQL audit logs for the records application server |
| The operator took personal and health records beyond the two credential tables | INSUFFICIENT | A held file carrying personal or health fields of those tables, or the agency's SQL audit log showing this operator's queries against them |
| One key decrypts 111,404 of 111,404 stored password values | HIGH | A held ciphertext the key fails on |
| The decrypted export was served publicly to 10 distinct addresses | HIGH | A different parse of the operator's server log, or a size column showing truncated bodies |
| The work ran in the CyberStrikeAI platform | HIGH | The report's finding IDs found in another file or another platform |
| The "authorised" label is the platform's default prompt wording | HIGH | The prompt not carrying the assertion in the version the operator ran, which is not held |
| The activity is unauthorised | MODERATE | The unheld report version naming a client, authoriser, scope and dates matching the victims |
| Whether the operator added its own authorisation text | INSUFFICIENT | The platform's database, a project scope record or an agent trace from the operator's host |
| The V02 domain is COMPROMISED, not ACCESS SHOWN | MODERATE | The command that wrote the dump (not held), or the victim's process-creation log for 19:58 UTC on 6 October |
| The hosting provider is COMPROMISED | MODERATE | Host-side evidence on a provider machine, such as its SSH log showing the operator's key |
| The DNS plugin ran and the `cyberstrike` account exists | INSUFFICIENT | A `cyberstrike` account in the directory, or Events 4720, 4728 and 4732 under `dns.exe` |
| No link to a named actor or another case | HIGH as a negative over identifiers; INSUFFICIENT for any named actor | A second case holding either key pair or either project ID |
| The host was rented rather than compromised | INSUFFICIENT | A hosting-provider record of who held the instance |

### Evidence gaps

- No victim-side telemetry exists for any organisation, so no grade, rule or timeline here is confirmed from a victim's own logs.
- The JSP shells' own bytes, the command that wrote the V02 dump, the DNS plugin setter's output and one 29,979-byte version of the operator's ministry report are not held.
- The platform's database, configuration, conversations and any agent trace are not held, which is why the questions about operator-added authorisation and model-written prose stay open.
- The personal and health tables were checked by keyword over 2,371 held files (archive members included; the directory's 1,887 captured files are a different count); binaries, registry hives and the memory dump were counted by keyword, not scanned for personal-data rows.
- Compressed members inside the captured `.zip`, `.jar`, `.pack` and `.tgz` files were not opened in any signature, phrase or linkage scan.
- The context pass over the platform scan's 9 configuration-shaped, 9 `chat/completions` and 22 `mcp` hits was not finished, so an LLM configuration could still sit in a file I read only by name.
- Victim ownership is inferred from names everywhere except one passive registry lookup of the jump host and the provider's addresses; no registrant was checked.
- Which client in the operator's server log was a person, a crawler, a scanner or the operator is not known.
- The public prior-art search was bounded: several search engines blocked or rate-limited it, and the Kaspersky Securelist report on CyberStrikeAI attacks could not be read, so I do not rely on it.

## 16. References
{: .hl-tier-2}
{: .hl-tab-confidence}

- CyberStrikeAI source repository: [github.com/AIPentest/CyberStrikeAI](https://github.com/AIPentest/CyberStrikeAI), formerly `Ed1s0nZ/CyberStrikeAI`, Apache-2.0. The default system prompt and workspace layout discussed in Section 4 were read from this source at versions v1.7.5, v1.7.17 and v1.7.24.
- Team Cymru (2026): [Tracking CyberStrikeAI: AI-Native Offensive Tools & MSS Ties](https://www.team-cymru.com/post/tracking-cyberstrikeai-usage), 21 IP addresses running the platform between 20 January and 26 February 2026, none of them this host.
- Elastic Security Labs (13 November 2026), Samir Bousseaden, Bryan Porras Blanch and Terrance DeJesus: [56 AWS API calls in 141 milliseconds: Inside an AI-run intrusion](https://www.elastic.co/security-labs/threat-command/cyberstrikeai-aws-cloudtrail-intrusion), a separate CyberStrikeAI operator against four AWS accounts, with the detection rules that fired.
- BleepingComputer (2026): [CyberStrikeAI tool adopted by hackers for AI-powered attacks](https://www.bleepingcomputer.com/news/security/cyberstrikeai-tool-adopted-by-hackers-for-ai-powered-attacks/), a general-audience account of the Team Cymru findings.
- Cloud Security Alliance (2026): [Multi-Agent Offensive Frameworks in the Wild: CyberStrikeAI and ARTEX](https://labs.cloudsecurityalliance.org/research/csa-research-note-cyberstrikeai-artex-multi-agent-offense-20/), on 2026 campaigns using the platform and its disableable safeguards.
- Trend Micro TrendAI (2026): [Not Only ARTEX: The Different Levels AI is Used in Attacks Targeting Japan](https://www.trendaisecurity.com/en-us/resources-insights/deep-research/not-only-artex-the-different-levels-ai-is-used-in-attacks-targeting-japan), including a CyberStrikeAI operator's open directory and an operator presenting "an authorized assessment" as a false premise to a model.
- The DFIR Report (2026): [Bissa scanner exposed: AI-assisted mass exploitation and credential harvesting](https://thedfirreport.com/2026/04/22/bissa-scanner-exposed-ai-assisted-mass-exploitation-and-credential-harvesting/), another operator-side harness built on an AI coding agent.
- Sophos X-Ops: [Veeam exploit seen used again with a new ransomware](https://www.sophos.com/en-us/blog/veeam-exploit-seen-used-again-with-a-new-ransomware-frag), on in-the-wild use of Veeam CVE-2024-40711, the flaw behind the public proof of concept in this toolkit.

---

© 2026 Joseph, The Hunters Ledger. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), free to republish and adapt, including commercially, with attribution to The Hunters Ledger and a link to the original.
