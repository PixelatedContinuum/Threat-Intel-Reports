---
title: "Help Desks to Host Shells Across Brazil's Public Sector"
date: '2026-10-15'
layout: post
permalink: /reports/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015/
thumbnail: /assets/images/cards/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015.png
hide: true
unlisted: true
category: "Intrusion Toolkit"
description: "An unnamed operator's open directory shows command execution inside two Brazilian federal bodies, a stolen EDR console token, monitoring servers turned into a command plane and a plaintext relay on TCP 53, across 92 public-sector organisation rows."
detection_page: /hunting-detections/inv-2026-067-detections/
ioc_feed: /ioc-feeds/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015-iocs.json
detection_sections:
  - label: "Detection Coverage Summary"
    anchor: "#detection-coverage-summary"
  - label: "YARA Rules"
    anchor: "#yara-rules"
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "Suricata Signatures"
    anchor: "#suricata-signatures"
  - label: "Coverage Gaps"
    anchor: "#coverage-gaps"
ioc_highlights:
  - value: "38[.]180[.]16[.]98"
    note: "Operator open directory, relay controller on TCP 53, callback listeners"
  - value: "209[.]99[.]185[.]148"
    note: "Operator canary and the far end of the reverse-SOCKS tunnel"
  - value: "38[.]180[.]196[.]193"
    note: "Operator payload staging host (MODERATE, co-tenanted)"
  - value: "986f697d2ef67a38e25c6a17cdecd7bb50148f2c2993864c748e3504d3d747f0"
    note: "Relay.java.new, the plaintext TCP 53 relay (SHA256)"
figure_nav:
  - image: brazil-toolkit-operator-hosts-contacts.svg
    parts:
      - label: "The three hosts"
        anchor: "#6-infrastructure"
      - label: "The agency's help desk"
        anchor: "#8-the-social-security-agency-from-a-help-desk-test-page-to-the-internal-package-store"
      - label: "The bank's tunnel"
        anchor: "#9-the-development-bank-an-api-gateway-and-a-tunnel-out-through-the-banks-own-proxy"
      - label: "The finance secretariat"
        anchor: "#10-the-finance-secretariat-the-saved-page-victims-and-the-suppliers"
      - label: "The Zabbix callback"
        anchor: "#11-the-monitoring-server-as-a-command-plane"
      - label: "The port 53 relay"
        anchor: "#12-the-port-53-relay-and-the-weblogic-scripts-that-would-deliver-it"
---

**Campaign Identifier:** OpenDirectory-38.180.16.98-BrazilPublicSectorToolkit-20261015<br>
**Last Updated:** October 15, 2026<br>
**Threat Level:** CRITICAL

---

## 1. Executive Summary
{: .hl-tier-1}

The operator's own files show it running commands inside two Brazilian federal bodies, a federal social-security agency and a federal development bank, and working authenticated staff sessions at a state finance secretariat in the North region. Saved administrator pages from a state traffic department in the Northeast region and from a cloud services supplier sit in the same directory, though I cannot show the operator captured those itself. Beyond those five, the files name 87 more organisation rows across federal, state and municipal government, and every one of those stops at a probe reply, a refusal or a name on a list. Whether any of the access still works today is unknown. The latest dated host-side evidence at the bank is 2026-09-15, and the latest dated console replies at the agency are from 2026-10-02.

All of this came out of an open directory on 38.180.16[.]98, a hosted server the operator used as its working area, file store and listener. Nothing public names this operator. One press report from September 2026 describes an intrusion at the same agency and its federal IT provider that may or may not be the same actor, and it shares no hard indicator with what I hold. What I hold is the other side of the story: the operator's tooling, its output, and the data it took.

This is an operator early in its attack chain, not early in its life. Everything I can see is reconnaissance, footholds, exploration and collection, sustained since at least mid-September, and over that span the same behaviour also fits espionage. Its targets are Brazilian public-sector bodies broadly, with the agency at the centre. Once it got into a few it kept reaching outward, toward the agency's federal IT provider, the managed security provider that serves the agency and that provider's cloud supplier. Of those three, only the cloud supplier shows authenticated access, and only on saved pages.

The help desk was its richest reconnaissance source, and that is the finding I would put in front of any defender reading this. At the agency the operator's scripts searched the GLPI ticket database for SentinelOne, Intune, Entra, GlobalProtect and remote-shell terms, pulled deployment tickets naming internal hosts and repositories, and took a live SentinelOne console API token out of the settings of the help desk's own remote-support application. Tickets gave it hostnames, software, users, procedures and the security stack without a single noisy scan.

Where it built its own tools, it chose reliability over stealth. Its reverse relay talks plain ASCII to the operator's server on TCP port 53, announcing itself with the line `READY2` and taking orders of the form `DIAL host port`, with no encryption and no framing. The operator's own log records 1,051 relay check-ins out of a victim network's egress address. Where it could use the victim's own tools instead, it did. With one stolen staff account it turned an internal Zabbix monitoring server into a command plane, creating temporary scripts that ran on a monitoring proxy and sent root identity back to its own listener, then deleting them.

How far the operator got differs sharply from one organisation to the next.

- At the agency, graded ACCESS SHOWN, the operator ran unauthenticated commands through a renamed copy of GLPI's htmLawed test page (CVE-2022-35914). Fourteen pieces of command output, fetched from an internal file server, reassemble byte for byte into one of the agency's own 905,374-byte deployment packages. The operator also queued 4,675 distinct help-desk document paths for download, held the SentinelOne token and used it, and held temporary AWS credentials for an agency cloud account.
- At the bank, also ACCESS SHOWN, a process table captured inside the bank's WSO2 API Manager container shows a reverse-SOCKS client running as the WSO2 service account, aimed at the operator's 209.99.185[.]148 through the bank's own forward proxy. The operator held the unencrypted WSO2 private key and 608 OAuth client key and secret pairs.
- At the finance secretariat, graded COMPROMISED, authenticated staff pages echo the operator's own address, application edits were accepted, and a 49,131-row export of the state's main user account table sits in the directory beside a password-cracking input built from it.
- The traffic department and the cloud supplier are COMPROMISED at MODERATE, on saved authenticated administrator pages that carry no address, timestamp or capture route tying the capture to the operator.

I rate the campaign **CRITICAL**. Little about it is exotic. The entry points are public exploits from 2022 and the expansion runs on management tools the victims already own.

But the parts that matter worked: commands run on a help-desk host, a tunnel client running inside an API gateway, staff sessions and a full account-table export at a state secretariat, and a live EDR console token. They worked inside national institutions that hold benefit, tax and development-finance data. Inside or authenticated access is shown at five of the 92 organisation rows, and the other 87 stop at probes and names. Section 2 explains the score and why the campaign level sits above it.

No publicly named threat actor can be attached to this activity, and the evidence does not support a tracking designation of my own either, so I describe it as an unknown operator. I am confident it is not an authorised red team. A tester would not keep a victim's data in a publicly reachable directory, would prove access and stop rather than collect in bulk, and would not work inside several unrelated organisations while probing dozens more. It also looks too long-running and too evasive for a smash-and-grab access broker, though it could sit somewhere between a broker and something else. What it ultimately wants is still undetermined.

If you defend a Brazilian public body or a supplier to one, three checks are worth more than the rest of this report. Look for POST requests to GLPI's htmLawed test page under any name, including renamed copies. Look in your Zabbix audit log for global scripts or items created and deleted by one account in a short burst, especially names beginning `z-`, `wv3_` or `poc`. And look for any internal host holding a TCP connection to port 53 that carries no parseable DNS, which is how the relay looks to Zeek and Suricata.

---

## 2. Risk Assessment
{: .hl-tier-1}

I score the toolkit **7.8 out of 10, HIGH**, on what it can do, and I rate the campaign one level higher, at CRITICAL, on what it has already done. The gap between those two numbers is the point of this section. As software, almost nothing here is advanced. As an operation, it has shown command execution inside two federal institutions and holds key material that could still open doors if nobody has rotated it.

The weighting is the standard one used across these reports, with data exfiltration and system compromise at 20 percent each, and persistence, evasion, lateral movement and detection difficulty at 15 percent each.

<table>
<colgroup>
<col style="width: 22%;">
<col style="width: 10%;">
<col style="width: 12%;">
<col style="width: 56%;">
</colgroup>
<thead>
<tr><th>Risk Dimension</th><th>Weight</th><th>Score</th><th>Rationale</th></tr>
</thead>
<tbody>
<tr><td>Data Exfiltration</td><td>20%</td><td>9/10</td><td>A 49,131-row state user account table with password hashes, 4,675 queued help-desk document paths, two of the agency's application databases, a federal provider's directory export, an unencrypted WSO2 private key and 608 OAuth client credentials. How many of the agency's documents actually left is not measured, which is the only thing keeping this off 10.</td></tr>
<tr><td>System Compromise</td><td>20%</td><td>9/10</td><td>Host-side command output at the agency through an unauthenticated web flaw, and commands run as the WSO2 service account at the bank. Neither shows root on an operating system the operator owns outright, and no access is shown to be current.</td></tr>
<tr><td>Persistence Difficulty</td><td>15%</td><td>7/10</td><td>A reverse-SOCKS client running inside the bank's container, two relay lanes calling home from a victim estate, and JSP pages listed in the bank's web applications (operator placement a LOW-MODERATE inference). The WebLogic plant-and-scrub scripts would add more, but no run of them is held.</td></tr>
<tr><td>Evasion Capability</td><td>15%</td><td>6/10</td><td>It works through tools the victim already trusts: the help desk, the EDR console's own API, the monitoring server's script feature. It cleans up its own Zabbix objects and base64-wraps commands to get past input filtering. Its own relay, though, is plaintext and trivially signatured.</td></tr>
<tr><td>Lateral Movement</td><td>15%</td><td>9/10</td><td>A help-desk foothold reaching an internal file server, a monitoring server driven with one stolen staff account, relay lanes reaching 71 and 6 internal destinations, credentials reused against further services, and deliberate reach from the agency toward its IT provider, its security provider and that provider's vendor.</td></tr>
<tr><td>Detection Difficulty</td><td>15%</td><td>6/10</td><td>Help-desk queries and monitoring-script runs look like administration, and the relay hides on a port most networks let out. Each step still leaves a record somewhere a defender owns: web logs, the Zabbix audit log, the EDR console audit, and an unparseable TCP 53 flow.</td></tr>
</tbody>
</table>

> **Risk vs. Campaign Threat Level:** The toolkit analysed in this report scores **7.8/10 (HIGH)** on capability, because it is assembled from public exploits, a small relay and the victims' own management tools. The overall campaign threat level is rated **CRITICAL** because host-side command execution is demonstrated inside two federal institutions (the agency and the bank), the operator holds secrets and records whose validity nobody outside those institutions can check (a WSO2 private key, 608 OAuth client credentials, an EDR console token, a state account table), and the operator was reaching outward toward suppliers when the directory was captured. If the affected institutions confirm that the access is closed and the held credentials are rotated, the campaign level should be reassessed to **HIGH**.

The bank's OAuth material is the exposure I would worry about longest. Those client credentials belong to institutions that consume the bank's APIs, and if they are still valid they let someone act as those subscribers against the bank's gateway. I have no evidence that anyone did, and I am not claiming subscriber systems were touched. The point is that the exposure outlives the intrusion until the credentials are reissued.

The finance secretariat's account table carries a similar tail. Its passwords are stored as unsalted MD5, and one hash value is shared by 5,001 accounts, which looks like a default password. Whether that value is a default, and whether any account was cracked or used, is not shown. The cracking input exists; the cracking output does not appear anywhere I can see.

---

## 3. Who Was Hit, and How Far the Operator Got
{: .hl-tier-2}

Five organisations show inside or authenticated access, and the long list behind them is mostly probes. I grade every organisation on what the operator's own files prove, using four levels, and the levels matter because a name in a script is not a compromise.

**LISTED** means named only, in a target list or script. **REACHED** means an outside attempt or reply without working access, and a failed or blocked attempt counts. **COMPROMISED** means working external access, such as an authenticated session, or server material whose owner is established. **ACCESS SHOWN** means an identified network plus host-side execution or inside-position evidence. A separate CURRENT field records the last datable access, which is not the same as access today.

The assessment carries 92 organisation or group rows: 2 ACCESS SHOWN, 3 COMPROMISED, 66 REACHED and 21 LISTED. A group counts once, so 92 is not a count of distinct legal entities. I hold that tally at MODERATE, because 175 hostname candidates in the files have not all been reconciled into organisations, and a full reconciliation could move a row.

### The organisations with inside or authenticated access

| Organisation | Grade | What the operator's files show | Latest dated evidence |
|---|---|---|---|
| A federal social-security agency | ACCESS SHOWN | Command output from the GLPI help desk, a package pulled from an internal file server, bulk help-desk collection, a used EDR console token, cloud credentials | Console replies at or after 2026-10-02; GLPI command time unknown |
| A federal development bank | ACCESS SHOWN | A running reverse-SOCKS client and command output inside the WSO2 container; private key, OAuth clients, subscriptions | Container output 2026-09-15 17:06:41 UTC |
| A state finance secretariat in the North region | COMPROMISED, MODERATE capture provenance | Authenticated staff pages echoing the operator's address, accepted edits, a 49,131-row account export | Page clock 2026-09-30 17:57, zone unstated |
| A state traffic department in the Northeast region | COMPROMISED, MODERATE | A saved GLPI interface with an active Super-Admin profile | None in the page |
| A cloud services supplier | COMPROMISED, MODERATE capture provenance | Saved documentation pages with signed-in session indications | Unknown |

The two COMPROMISED rows at the bottom deserve their caveat in the same breath as their grade. Neither page set carries the operator's address, a timestamp or a capture route, so another collection method (a stealer log, a shared export, someone else's saved browser page) cannot be ruled out. The finance secretariat is on firmer ground, because its own pages print the operator's address as the client.

### The suppliers and the rest of the named parties

The agency's federal IT provider, the company that builds and runs its systems, stays at REACHED even though the operator holds a non-public export of part of its directory (2,538 entries in the portion read). Nothing places the operator inside the IT provider: the server that export came from, the route and the date are all unknown, and the export could be an old snapshot. The operator also cloned the 12 code repositories of the IT provider's public GitHub organisation in 21 seconds and scripted logins against its VPN and identity service, with no reply held for any of them.

The managed security provider that serves the agency is also REACHED. A request-forwarding flaw in a cloud portal built by the cloud supplier (whether the cloud supplier or the security provider owns the application is unestablished) exposed a backend API token in anonymous debug pages, and at least 29 operator scripts present that token onward. Holding a token is not using it, and across 534 file hashes I found no accepted login at the security provider. The help desk of a second state finance secretariat was the target of relay tooling that assumes a foothold already exists, but the only response held is a 285-byte 403 page, so it is REACHED. A state government and a federal health IT department are REACHED on saved public login pages only.

The remaining 55 REACHED rows split into 27 public or login-page replies, 21 denials or errors and 7 attempts with no reply. They span municipal governments, state secretariats, courts, federal regulators and state IT companies. None shows an objective result and none carries a dated access. The 21 LISTED rows (14 individual bodies and 7 groups, including ministries and federal agencies) are names on lists, with no access shown.

I do not read that long tail as proof of targeting. A sweep across a whole product class on `.gov.br` (GLPI, WSO2, JBoss, Tomcat, WebLogic) explains probe-level contact just as well as a hand-picked target list does. What I can say is that the core of the operation is directed. The agency-centred collection, the labelled probe sets, the extension to the IT provider, the security provider and the cloud supplier, and a 245,707-row extraction from an integration database whose owner I could not establish are not the output of an opportunist who stumbled in.

Seven further assessment blocks cover systems whose owner I could not establish. Two of them are COMPROMISED at MODERATE: the Zabbix monitoring proxy that returned root identity to the operator, and the Zabbix server behind it. Their estate association with the agency is conditional, so they are not added to the agency's row.

---

## 4. Technical Classification
{: .hl-tier-2}

This is an intrusion toolkit, not a malware family. There is no implant, no loader and no packed binary in the operator's own work. It is Python, PHP, shell and a little Java, wrapped around public exploits and legitimate management interfaces, and run from a hosted Linux server the operator used. I put family identification at INSUFFICIENT, because nothing in it matches a named family and nothing in it is distinctive enough to found one.

| Field | Assessment |
|---|---|
| Type | Operator toolkit for application exploitation, credential acquisition, reconnaissance, collection and access expansion |
| Family | None established (INSUFFICIENT) |
| Languages and platforms | Python, PHP, shell and Java on Linux; no Windows endpoint tooling of the operator's own |
| Entry points | GLPI htmLawed CVE-2022-35914; WSO2 CVE-2022-29464 (inferred from the operator's own script); valid staff accounts; an exposed backend token |
| Expansion | Help-desk mining, a stolen EDR console API token, Zabbix global scripts, credential reuse, a reverse-SOCKS client and a plaintext TCP 53 relay |
| First dated victim-side activity | The bank's tunnel process start labelled Sep 14 (year inferred); dated container output 2026-09-15 |
| Motive | Undetermined |

On sophistication I will not assign a grade. The tooling is iterative and practical rather than clever: numbered batch scripts, per-person cookie jars, certificate checks switched off, ISO-8859-1 decoding for Portuguese pages. Where it is good, it is good at using what the victim already runs. Turning a help desk into a reconnaissance source and a monitoring server into a command plane takes knowledge of how institutions actually operate, and no exploit development at all.

The toolkit is in a constant state of revision. Files appeared and disappeared from the live directory between captures, the served tree grew to 9,917 files by its last listing on 2026-10-08, and several helpers exist in numbered generations. The operator also downloaded clean copies of public tools to study them, including an unmodified clone of the public glpwnme GLPI exploitation tool and the stock GLPI 10.0.7 release, which is byte-identical to upstream across all 6,500 files. Neither is trojanised, and neither says anything about which GLPI version the agency runs.

Two Windows executables on the operator's second host, 209.99.185[.]148, sit apart from all of this. The two `bpupdate.exe` builds fetch from that host on port 8146 and launch Chrome Canary headlessly under a "BluePeak AppUpdater 2.4" identity. They share the operator's address and time window, so I rate a common controller at MODERATE. Against that, nothing in either build names the operator's canary, a Brazilian target or its tunnel listener, the BluePeak naming does not match the operator's Portuguese working style, and a co-tenant or later tenant is not excluded. Campaign authorship stays NOT CHECKED, and I map no campaign behaviour from them.

---

## 5. The Attack Chain at a Glance
{: .hl-tier-2}

The operation runs in a recognisable order: study the target's public code and products, get in through a public-facing application, mine the inside for access material, then use the victim's own management tools to spread. Collection runs alongside most stages rather than waiting for the end, and nothing in what I hold goes past collection into fraud, extortion, sale or destruction.

| Stage | What the operator did | Where it is shown |
|---|---|---|
| 1. Study | Cloned the 12 code repositories of the IT provider's public GitHub organisation in 21 seconds, then 10 and 7 GitLab projects from two large city governments; pulled public exploits and clean product releases for GLPI; fingerprinted GLPI help desks across 25 hosts | Reflog timestamps on the operator host; fingerprint output |
| 2. Entry | Unauthenticated commands through GLPI's htmLawed test page at the agency; command execution in the bank's WSO2 API Manager; staff logins and a database query page at the finance secretariat; a token read from anonymous debug pages in the supplier-built cloud portal | Command output, process tables, saved authenticated pages |
| 3. Foothold | A reverse-SOCKS client running as the WSO2 service account, aimed at 209.99.185[.]148 through the bank's own proxy; two relay lanes calling 38.180.16[.]98 on TCP 53 from a victim estate's egress address | Process table inside the container; the operator's relay log |
| 4. Mine the help desk | Ticket searches for security-stack terms, deployment tickets naming internal hosts, a live SentinelOne API token taken from the help desk's remote-support application settings, integration and database credentials | The operator's queries and the settings it held |
| 5. Spread | Authenticated SentinelOne console enumeration, including a refused request for agent uninstall passwords; temporary Zabbix scripts run on a monitoring proxy with one stolen staff account; the same account and password tried against further services | Console replies; a root-identity callback to the operator's port 9090 |
| 6. Collect | The agency's help-desk documents (4,675 distinct paths queued), its deployment packages from an internal file server and its application databases; the finance secretariat's account table; the bank's secrets and subscription data | Queue files, download logs, held exports |
| 7. Move it out | Command output returned base64-encoded in HTTP responses; onward traffic spliced through the TCP 53 relay | The operator's helpers and relay source |

Three things in this chain are worth more to a defender than the rest. The help desk is where the operator learned the environment, so it is where the earliest signal sits. The EDR console token turned a security product into a reconnaissance feed, and the uninstall-password request is exactly the kind of call a console audit can alert on. And the relay is easy to catch on the wire precisely because the operator chose not to hide it. Sections 8 to 12 take each in turn.

---

## 6. Infrastructure
{: .hl-tier-2}

Three hosted servers carry the operation, and they are joined by the operator's own documents rather than by any shared technical fingerprint. Its scripts call one of them "our IP", label another "nosso canary" ("our canary"), and point the bank's tunnel client at the third. No operator-owned domain exists anywhere in the evidence. Whether the operator rented these servers, compromised them or bought them second-hand is not established; only a provider's customer record would settle it.

| Address | Provider | Role in the operation | Operator control |
|---|---|---|---|
| 38.180.16[.]98 | 3NT Solutions LLP allocation, M247 Europe SRL (AS9009) | The open directory (port 80, earlier 8899), the relay controller on TCP 53, the Zabbix callback listener on 9090, an intended path-map listener on 9443, a scripted SMB listener on 445 | HIGH |
| 38.180.196[.]193 | Same allocation and provider, a separate block | Payload staging (operator label "vpsbr"), a Python directory listing, and a password-protected panel with the realm `cadsus-panel` | MODERATE (use HIGH) |
| 209.99.185[.]148 | SKN Subnet & Telecom Ltd (AS402253) | The canary that catches callbacks from injection tests, the far end of the bank's tunnel, and a TLS listener whose certificate names "Update Service" | HIGH |

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015/brazil-toolkit-operator-hosts-contacts.svg" | relative_url }}" alt="Three-column diagram of the operator's three hosts and the contacts around each. Column 1, deep red band, 38.180.16[.]98, operator control HIGH: open directory, relay controller on TCP 53, callback listener on 9090, SMB listener on 445 and an intended path-map listener on 9443; operator surface from 2026-09-26, address recycled. Under it, three orange contact cards: a victim estate's egress address calling home to port 53 over two relay lanes with 1,051 check-ins (pod announces READY, 648 check-ins to 71 destinations; wls announces READY2, 403 to 6); a Zabbix monitoring proxy of unestablished owner calling back to port 9090, join of script to callback MODERATE; and the agency's help desk plus the finance secretariat's pages, echoing the address as visitor or client. Column 2, yellow band, 38.180.196[.]193, control MODERATE: payload staging, a Python directory listing and a password-protected panel with realm cadsus-panel on port 8899; ten third-party parked domains also resolve there. A dashed card: the report names no victim-side contact. Column 3, deep red band, 209.99.185[.]148, control HIGH: canary on 8080, TLS listener with an Update Service certificate on 443 and 10443, and the target of the bank's tunnel client. Under it, dashed cards for the bank's WSO2 container (traffic NOT CHECKED) and two bpupdate.exe builds on the same address (common controller MODERATE, campaign authorship NOT CHECKED), and a card for injection-test callbacks caught by the canary. Footer anchors: a TCP 53 flow not parsing as DNS, and the READY or READY2 line followed by DIAL host port.">
  <figcaption><em>Figure 1: Where each operator host meets a victim estate, and how firmly the report holds each contact. The hosts are joined only by the operator's own documents (MODERATE), so the figure draws contacts per host and no line between hosts, and it keeps the bpupdate.exe builds outside the campaign because their authorship is NOT CHECKED.</em></figcaption>
</figure>

The first address is tied to the operator most directly: the agency's own help desk echoed it back as the visitor address, the secretariat's pages print it as the client, and the operator's tooling names its listeners. The address is recycled, though. Its port 443 certificate, its JARM and its SSH host key all belong to earlier tenants from 2024 and 2025, so none of them is an indicator for this operator. The operator's surface on it dates from 2026-09-26.

The second address is weaker for a specific reason. Ten third-party parked domains also resolve to it, and that co-tenancy is not resolved, so the host-level entry in the feed is MONITOR and only the operator's service ports are BLOCK. The `cadsus-panel` realm was visible from 2026-09-04 to 2026-09-14. CADSUS is the name of Brazil's national health-user register, but the word appears in none of the 973 files of the operator's archived directory, and I cannot say what the panel was for. Phishing is one possibility among several; without context I will not speculate further.

The 3NT and M247 allocation is commodity hosting, so the shared provider between the first two addresses is not a link on its own. I found no evidence either way on whether any of these providers runs a permissive hosting policy, and I make no bulletproof-hosting claim. An Amazon address that sent the operator 1,051 relay check-ins is the victim estate's egress rather than a fourth operator host, and it is deliberately absent from the indicator feed.

The build-up ran over about five weeks. The second server's configuration changed on 2026-08-20, its panel appeared in early September, the bank's tunnel started on Sep 14, the canary's certificate is dated 2026-09-21, and the first server's operator window opens on 2026-09-26. My read is planning and the need for scale: the operator laid out the infrastructure it expected to need and stood it up as the operation grew. Configuration dates are not tenancy records, so that is my read of a sequence and no more.

| Date (UTC) | Observation |
|---|---|
| 2026-08-20 | Configuration change on 38.180.196[.]193 |
| 2026-09-04 to 2026-09-14 | `cadsus-panel` realm visible on 38.180.196[.]193 port 8899 |
| Sep 14 (year inferred) | The bank's tunnel client process start |
| 2026-09-15 17:06:41 | Latest dated command output inside the bank's container |
| 2026-09-21 | "Update Service" certificate on 209.99.185[.]148 becomes valid |
| 2026-09-26 / 2026-09-27 | 38.180.16[.]98 port 8899 directory first observed (sources disagree by a day) |
| 2026-10-02 | The agency's console replies and cloud-credential reply |
| 2026-10-07 | Last canary response on 209.99.185[.]148 port 8080 |
| 2026-10-08 19:45 | Last positive directory listing on 38.180.16[.]98, 9,917 files |
| 2026-10-14 | 38.180.16[.]98 accepts connections on ports 22, 443 and 4000 while port 80 times out; 209.99.185[.]148 still presents the "Update Service" certificate on ports 443 and 10443 |

When the directory went silent, and why, is undated. A server that still answers on other ports says nothing about whether any of the victim access still works, and a quiet directory is not evidence of a takedown.

---

## 7. What the Public Record Holds
{: .hl-tier-2}

Nothing public that I found names this operator or describes its combined activity, and I hold that at MODERATE. That is bounded by what was searched. Searches for the bare addresses and file hashes did not return a known positive control, so those negatives are not reliable, and the relay's protocol strings were never searched at all. I make no claim to be first to publish any of it.

Others could see the raw material before I did. A commercial capture service archived the operator's directory on 2026-09-27, before this investigation began, and its automated summaries described the bank's WSO2 activity and the agency's GLPI exploitation from that capture. That is machine-written description behind a login rather than published analysis, but it means the raw material was visible to that service's customers.

Most of the techniques are known. GLPI's htmLawed flaw (CVE-2022-35914) has been mass-exploited since 2022, as [VulnCheck's write-up](https://www.vulncheck.com/blog/glpi-exploitation) describes. WSO2's file-upload flaw (CVE-2022-29464) was under wide exploitation by April 2022, according to a [Deepwatch advisory](https://www.deepwatch.com/labs/customer-advisory-threat-actors-exploiting-critical-wso2-vulnerability/) that itself relies on Rapid7's reporting. Another operator taking a Brazilian government GLPI compromise through to the directory service has been described by CyberCyber Labs in [Inside an Exposed C2 Server](https://cybercyberlabs.com/reports/Inside-Exposed-C2.pdf) (CCL-2026-07-EXC2, sections 1 to 4).

That makes the vector and target combination partially covered, with no shared infrastructure in a controlled comparison. Abuse of Zabbix global scripts and API-driven remote commands is documented prior art, as Section 11 explains. I found no prior report of a SentinelOne console API token being used this way against a Brazilian agency, or of this relay protocol, at the depth I searched.

A September press report is the one piece of context I have to address directly. [Cybernews published on 2026-09-09](https://cybernews.com/security/brazil-data-breach-government-employee-logins/) an account of an actor it found on 2026-07-06 inside the same social-security agency and its federal IT provider: an AI agent on cloud infrastructure, remote management access into an agency Windows machine, credential collection against the IT provider's VPN, reverse tunnels, and a claimed bypass of SentinelOne. It shares victims, interest in the IT provider's VPN and SentinelOne as the obstacle with what I hold. It shares no hard indicator, and a byte search of the files I hold for the article's named tool strings found none.

So the link stays NOT CHECKED and a same-operator assessment stays INSUFFICIENT.

I can see two readings. It could be the same actor, never fully removed after that July discovery. Or it could be a different actor using the published story as a playbook. The infrastructure dates do not settle it either. The second server and its panel predate the article, so I will not claim that everything began after publication. A matching command server, SSH key or file hash from the article's unredacted material would settle it, and I do not have that material.

---

## 8. The Social-Security Agency: From a Help-Desk Test Page to the Internal Package Store
{: .hl-tier-3}

The agency is the centre of this operation, and the finding that moved it from "targeted" to "inside" is a single shell script. The operator sent commands through a vulnerable test page that ships with GLPI, had each command fetch one 64 KiB slice of a file from an internal file server and print it as base64, and saved the fourteen answers. Those fourteen answers decode, slice by slice, into 905,374 bytes that are byte-identical to an agency deployment package and match the MD5 in the agency's own package manifest. Nobody can hold those slices without running commands on a host that can reach that file server, and that is what makes this an intrusion rather than a target list.

Around that proof sits everything else: a bulk pull of the help desk's document store, the help desk mined for the security stack, a live EDR console token, cloud credentials and two internal application databases. What is not shown is just as important. I cannot date the GLPI commands, I cannot say how many documents actually left, and I cannot say whether a credential-capture hook the operator wrote was ever installed.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015/brazil-toolkit-agency-help-desk-tree.svg" | relative_url }}" alt="Tree diagram with an orange root and two columns of branches, rooted at the agency's help desk (GLPI). Root: a renamed copy of GLPI's htmLawed test page, CVE-2022-35914, on the public help desk, unauthenticated with a dummy session cookie; who renamed it and when the commands ran are not established. Left column, joined by a trunk to the command channel: svc.py and pull.py send base64-wrapped commands and read the output from the HTTP response body (red); a package pulled from an internal file server, 14 slices of 64 KiB decoding to 905,374 bytes byte-identical to an agency deployment package and equal to its manifest MD5, which carries the ACCESS SHOWN grade but is not independent authentication (yellow, outlined); and the bulk document pull, 4,675 distinct paths queued and 4,997 download events, with documents that left NOT MEASURED (yellow). Right column: the help desk as a reconnaissance source, with ticket searches, deployment tickets and a SentinelOne API token read from the remote-support application's settings (red), leading to the EDR console queried with that token: 12 service users, 44 human users, 6,823 agents stated, two rogue-device lists, uninstall-password request refused, remote shell a capability only (red). A dashed orange card holds temporary AWS credentials from 2026-10-02, expired 2026-10-03, no use shown and tied to no route. Footer: not shown are command dates, documents that left, credential-hook installation and current access.">
  <figcaption><em>Figure 2: Everything at the agency hangs off one help desk, but each branch is graded on its own evidence. Only the package decode is host-side proof of command execution, the cloud credentials are held with no route shown, and how many documents left is not measured.</em></figcaption>
</figure>

<details markdown="1" class="hl-teardown">
<summary>The command channel, the package that proves it, and the second route into the same network</summary>

Two small Python helpers, `svc.py` (1,244 bytes) and `pull.py` (2,700 bytes), each hard-code exactly one URL: a copy of GLPI's bundled htmLawed test page on the agency's public help desk, under a renamed filename. Both name CVE-2022-35914 in their own text. The request carries a dummy session cookie and no credential, so the execution is unauthenticated. The command is base64-wrapped and piped to a shell to get past htmLawed's character filtering, and the remote output comes back in the response body, where the helper parses it off the page. `svc.py` takes a command as an argument or from a file and defaults to `id`.

Who renamed the test page, and why, is not established. The renamed filename reads in Portuguese as a defensive rename, which would mean someone tried to neutralise the page by renaming it and left it reachable. That is only a reading of the filename, but it is worth any GLPI administrator's attention, because renaming a vulnerable file does not remove it.

The proof is a 563-byte shell script named for the package it pulls. It loops from 0 to 13, and on each pass asks `svc.py` to run a command on the help-desk host that pulls an agency installer from an internal SFTP server, cuts out one 64 KiB block with `dd`, base64-encodes it and deletes the temporary file. Each pass's output is appended to one file on the operator's server. Decoded line by line and concatenated, that file is 905,374 bytes, byte-identical to the installer the operator also held and equal to the hash the agency's own manifest lists for it. A naive single-pass decode of the same file yields only 65,536 bytes, which shows the fourteen pieces were encoded independently.

Two limits travel with that proof. The manifest and the package came from the same server, so their agreement is not independent authentication by the agency. And the decode shows fourteen independently padded segments matching what the script would produce; it is not a capture of fourteen HTTP transactions. Neither limit touches the core point: the operator holds output that only command execution on that host could have produced.

A second route reached the same internal file server. Three batch scripts make 45 named file requests (with some filename collisions, so not 45 distinct files) through a SOCKS5 proxy on the operator's own host, which means the operator expected that proxy's far side to sit inside the agency's network. The proxy process itself is not shown. The SFTP login used throughout is one service account whose password is the same as its username, which is the process failure the agency has to close alongside the technology one.

</details>

<details markdown="1" class="hl-teardown">
<summary>The bulk pull of the help-desk document store, the packages and the databases, with every count and its limit</summary>

`pull_mass.py` runs through the same command channel. For each queued entry it runs a remote `stat` and then `cat | base64` on a file under GLPI's document store, skips anything over 8 MiB as too large, and logs progress every 50 files. A wrapper chains it over five queue files, and the queues themselves are in the directory: 5,036 lines naming 4,675 distinct document-store paths. By type they are mostly spreadsheets and PDFs (2,018 XLSX, 1,173 PDF and 1,129 CSV lead the list), followed by images and office documents.

The three main download logs line up with three of the queues: 3,370 downloaded of 3,378 processed, 1,310 of 1,330, and 303 of 307. A separate large-file log records 14 files between 8.6 MB and 79.7 MB pulled in chunks with a per-file digest check, matching the 14 entries of the large-file queue by document id. That is 4,997 download events in all, and it is not a count of distinct documents, because the logs overlap and do not say which event belongs to which path. The number of documents that actually left the agency is not measured. Two 2025 benefit and credit table backups were queued and deferred as too large, and are not among the files the large-file log records as pulled.

The internal package store yielded 87 files with 65 distinct hashes. All 23 packages that the agency's manifest lists match their listed MD5, and 8 held files have no manifest entry to test against. No package was altered, as far as that comparison can show, so I treat the packages as copied and unaltered. What makes them matter is what they carry: Microsoft Entra bulk-enrolment tokens, database connection credentials inside client binaries, the file server's service account, and the SentinelOne site configuration for the agency's deployment. That last item comes back below.

The operator also held two of the agency's application databases whose owner is established from their content: an engineering and property database of 22,765 rows, with current and historic staff contact data, and an asset-inventory Redmine export of 43,097 rows, with network and issue metadata and a small amount of authentication material. How either left the agency is not shown. It held 38 help-desk ticket objects with 52 follow-ups, and a zip of the source code for the agency's own remote-support agent, a developer's working clone of an internal repository dated 2024. How that source tree left the agency is not determined; the internal file server is my working guess, and other stores are not excluded.

The source code is part of a pattern I am confident in. This operator collects source code wherever it finds it, from the IT provider's and two city governments' public repositories to the agency's internal one. Whether that is reconnaissance for vulnerabilities, code fed to a model for bug-hunting, or indiscriminate collection of anything governmental, it could be all three at once.

A download log in the directory also records 21 zip archives, 160,063,450 bytes in all, sitting root-owned in a temporary directory and each fetched over an authenticated HTTP session with a 200 and its exact size. Their names point at the agency's systems (post-death benefit data and its credit backup, digital services, an internal audit portal, a deployment package), at MODERATE. The host is not named and the archive bodies are absent. My read is that the operator staged them, because legitimate backups live on backup machines rather than in a temp directory being pulled over HTTP, but I hold that as my hypothesis. The exfiltration itself is not shown.

</details>

<details markdown="1" class="hl-teardown">
<summary>The help desk as a reconnaissance source, the EDR console token, and the cloud credentials</summary>

The operator's scripts treated the agency's help desk as a map of the organisation. `q_ts1.php` queries the GLPI ticket database for SentinelOne, Intune, Entra, GlobalProtect and remote-shell terms. Another query searches the support entity for documents titled as database dumps and returned 5 rows. Deployment tickets the operator pulled name internal hosts and code repositories. A further script runs 16 searches for network terms across ticket titles, ticket contents and knowledge-base titles, and a SQL set selects the SNMP credential tables and discovered address ranges of GLPI's inventory plugin.

This one landed hard with me. I had not thought about it this way before: a help desk gives an intruder hostnames, software inventory, user names, the procedures an organisation follows and its security stack, all without a scan, from a system that exists to be read. The scan-shaped detections most teams tune for reconnaissance rarely fire. It was new to me; I have not researched how widely it is documented, and I make no novelty claim for it.

The most valuable thing the help desk gave up was an EDR console token. The settings of the agency's remote-support application display a truncated prefix that matches the operator's SentinelOne API token, and the support application is the token's source at HIGH. The token was issued on 2025-10-22 with a one-year life. With it, the operator queried the SentinelOne management console as an account-scope service user and saved what came back: 12 service users, 44 human users with their roles and two-factor settings, an agent page stating 6,823 agents, and two inventories of agentless "rogue" devices, of 4,663 and 8,817 records. The returned record clocks put that activity at or after 01:20:28 UTC on 2026-10-02.

It then asked the console for agent uninstall passwords, and the console refused. Remote shell was enabled on all 372 agent records I could analyse, which is a capability and not a use: no remote-shell session is shown, and no endpoint protection was disabled. My read of the rogue-device pull is that the operator was looking for unmonitored machines where it could hold a quieter foothold that would be harder to remove. Asking an EDR console for uninstall passwords is about as basic a detection opportunity as exists, and I hope someone's console audit caught it.

How the operator knew the agency ran SentinelOne at all has a plain answer. The agency's own deployment packages, pulled from the internal file server, carry the SentinelOne install configuration. That explains knowing the product, though not the API token, which belongs to a different console from the site token in the packages and came from the support application's settings instead.

On 2026-10-02 the operator also held a set of temporary AWS credentials returned by an instance metadata service. The session token's account matches the cloud account the agency's console records for one of its production hosts, so the account association is HIGH, with a negative control. That identifies the account, not the instance or role the credentials were fetched from. They expired at 01:29:17 UTC on 2026-10-03, and no use of them is shown.

</details>

<details markdown="1" class="hl-teardown">
<summary>The credential-capture hook that may never have been installed, and what the operator pointed its foothold at</summary>

A set of PHP helpers writes a hook into GLPI's authentication class, `inc/auth.class.php`, that base64-encodes each login's identity and password into GLPI's event log, checks the marker is there, harvests matching lines from the event and web access logs, and removes the hook-marked lines again. Test scripts submit synthetic logins to the login page and REST API of the agency's help desk and then read the local event log for capture entries, which places that family on this host.

Whether the hook was ever installed, and whether it is there now, is NOT SHOWN. Code is not installation output. The target path does not exist in GLPI 10.x, where authentication lives in `src/Auth.php`, but the agency's help desk answered as GLPI 9.5.6 in one read and 9.5.9 in another, and both use the older layout the hook targets. So the hook could have installed as written. It is the first thing I would ask the agency to look for.

The operator also pointed its foothold at a lot of the agency's interior, with output held for some of it. A family of "pod" scripts shares the `svc.py` helper and the operator's own comments, and covers resolution of about 570 host names at the agency, its IT provider and a second federal IT company, connection scans of 315 to 331 mostly internal addresses, a labelled reachability sweep across the monitoring stack, benefit and finance systems, an intranet portal, an automation server and a Kubernetes production API, and a reuse test of 17 credential pairs against three internal database servers. The resolution output is held (579 distinct names), and two encoded scan outputs list host-and-port pairs across 19 internal addresses. Whether those pairs are results or targets cannot be decided from the files. The outputs of the credential-reuse test and of the labelled sweep are not held, so what they found is NOT CHECKED.

One more piece of tooling, a shell and PHP survey of the agency's internal directory, databases and configuration with three hard-coded credential pairs, has no output at all. It sits at LISTED. I mention it because it shows the operator built tooling for the agency's internal directory as well as its help desk.

</details>

---

## 9. The Development Bank: An API Gateway and a Tunnel Out Through the Bank's Own Proxy
{: .hl-tier-3}

At the bank the operator got command execution inside the bank's WSO2 API Manager and left a tunnel client running there, aimed at its own server through the bank's own forward proxy. A process table captured inside the container shows the client as PID 7519, running as the WSO2 service account, started on "Sep 14" (the table carries no year or zone), with a proxy credential of the bank's on its command line. I hold at HIGH that the process exists and at MODERATE that the operator started it, because the operator's own capture commands sit beside it and the destination is the operator's 209.99.185[.]148.

That is a big finding with a lot of fallout, and it is also not complicated. Nobody needed a zero-day here. The operator's scripts aim at a public flaw from 2022, and while no response shows that flaw working, I infer it as the way in. That, a service account and a reverse proxy client were enough to put the operator inside a national development bank's API layer and walk away with its signing key and its subscribers' credentials. That is how most of this threat landscape actually works, and it is worth saying plainly.

The question I cannot answer yet is whether the API gateway was the goal. It could have been the target from the start, a door the operator happened to find, or a way to reach the OAuth clients and the APIs behind them specifically. The operator's discovery script scoped its search to the bank's own domains, which leans toward deliberate interest in the bank, but that is all it shows.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015/brazil-toolkit-bank-tunnel-chain.svg" | relative_url }}" alt="Vertical chain of four steps and one separate card, with dashed connectors where the link is inferred or NOT CHECKED. Step 1, orange: entry into the WSO2 API Manager is inferred from scripts aimed at CVE-2022-29464; no response shows the flaw working; four JSPs listed in the authenticationendpoint and oauth2 web applications are placement LOW-MODERATE and do not carry the grade. Dashed arrow labelled inferred route. Step 2, red: command output inside the container as the WSO2 service account, stamped 2026-09-15 17:06:41 UTC, HIGH, with the same process in three process tables and a compiled /tmp/Q.class; this evidence grades the bank ACCESS SHOWN. Step 3, red: reverse-SOCKS client /tmp/upd, PID 7519, start labelled Sep 14, chisel-style, aimed at 209.99.185[.]148 over HTTPS through the bank's forward proxy; process exists HIGH, operator started it MODERATE. Dashed arrow labelled NOT CHECKED beyond this line. Step 4, deep red, dashed: the operator's server; acceptance of the connection, acceptance of the proxy credential and any traffic are NOT CHECKED. Separate dashed yellow card: gateway material held, an unencrypted private key, 608 OAuth client key and secret pairs, a 966-row subscription dump, with validity and exit route unchecked. Footer anchors: an application service account holding HTTPS to a hard-coded external address through the forward proxy.">
  <figcaption><em>Figure 3: The bank's ACCESS SHOWN grade rests on the command output in the container (step 2), not on the tunnel. Entry is inferred and nothing shows the tunnel carried traffic, which only the bank's proxy logs can settle, so the dashed parts carry no weight in the grade.</em></figcaption>
</figure>

<details markdown="1" class="hl-teardown">
<summary>The process tables, the command output, the listed JSPs and how far each one carries</summary>

The ACCESS SHOWN grade at the bank rests on host-side evidence only. The same tunnel process, with the same PID and start stamp, appears in three process tables most likely taken from one container at 16:25, 16:26 and 17:06, and the last of those sits beside the operator's own capture commands. Identity, host and date output run inside the container as the service account is stamped 2026-09-15 17:06:41 UTC, with a second container's output at 17:06:04 UTC. An `id` reply came back through a helper page (MODERATE, because no HTTP status was stored), and a compiled class, `/tmp/Q.class`, is owned by the service account in its temp directory.

The tunnel client is `/tmp/upd`. By its flags it is a chisel-style reverse-SOCKS client configured to reach 209.99.185[.]148 over HTTPS through the bank's forward proxy, which is the clever part: outbound traffic from an application server through the organisation's own sanctioned proxy looks like any other update check. A running client is not a working tunnel, though. Whether the operator's server accepted the connection, whether the proxy accepted the credential, and whether any traffic crossed it are all NOT CHECKED. Only the bank's proxy logs can answer that.

The entry route is an inference. The operator's scripts are aimed at CVE-2022-29464, an unauthenticated file-upload flaw in WSO2 products, and name it in their own docstring. No response in the directory shows the flaw working, so I hold entry by that CVE as an inference.

The JSPs carry less weight than they appear to. A directory listing from inside the container shows three 226-byte JSP files in the `authenticationendpoint` and `oauth2` web applications and a 34-byte JSP, timestamped Sep 15 16:22 and 16:35 and requested afterwards. Two of the names are `init-url-helper.jsp` and `svc.jsp`. Their contents and their creator were never seen, so I hold operator placement at LOW-MODERATE. I do not let them carry the grade, and the `changed` objective result at the bank rests on them alone.

</details>

<details markdown="1" class="hl-teardown">
<summary>What the operator took from the gateway, counted against the populations it came from</summary>

The operator held the unencrypted private key of the WSO2 service keystore, along with a keystore listing. It held 608 OAuth client key and secret pairs carrying 460 owner labels, and a 966-row API subscription dump covering 480 subscriber identities across 25 APIs. It held a 200-line user listing from a population the export reports as 1,077 users, an 80-token sample of what the operator's own count gives as 833 active tokens, and a 5-row sample of account digest and salt pairs.

Those samples are smaller than their populations, and the sizes should not be added together, because several configuration exports overlap. Whether any of these credentials is still valid, and whether they belong to the production instance, are both unchecked. How the key material left the host is not shown either, which is why the secrets support the COMPROMISED-level outcome but do not carry the ACCESS SHOWN grade on their own.

The directory also holds the console listing of an archive named `lula2026.zip` that I never held as a file: 19,892 entries, every one under a top-level folder named for the bank, 14,091 of them under a `loot/gitlab` path. The other 1,206 files include 523 scripts and folders named for configuration, identity, deployment and financial-system material. This is a list of names, with no contents, sizes or extraction time, and only 77 of the non-GitLab names match files I hold. Names alone do not establish directory-service control, cracked accounts, repository counts or payment-system access, so the listing adds apparent breadth without changing the bank's grade. Dates embedded in the names run from 2026-09-18 to 2026-09-23, and they do not extend the CURRENT date. The archive's name is not evidence of political motive.

</details>

---

## 10. The Finance Secretariat, the Saved-Page Victims and the Suppliers
{: .hl-tier-3}

The finance secretariat is the clearest case of the operator working as an ordinary user and leaving with the user table. Its saved staff pages print the operator's own address, 38.180.16[.]98, as the client in the application banner, so these are sessions the operator ran. Through a database query page reachable from outside, it exported the state's main user account table, and the export sits in its directory with exactly the row count its own log reports. What I cannot show is any command execution on a host of the secretariat's, which is why the grade stops at COMPROMISED.

The other saved-page victims and the suppliers are weaker, each for a specific reason, and I give each its reason below rather than letting them borrow the secretariat's footing.

<details markdown="1" class="hl-teardown">
<summary>The finance secretariat: the account table export, the cracking input built from it, and the edits that were accepted</summary>

The chain runs through the operator's own tools in order. `sca_dump2.py` hard-codes a row total of 49,130 for the user table, measured through a query page on a public database host of the secretariat. `sca_dump.log` counts up in steps of 1,000 "of 49130" and ends "DUMP DONE: 49131 fails: 0". The output file, `sca_dump.txt`, holds 49,131 lines. So the log's denominator is the operator's own measurement of that specific table, which ties the log to it, and the output file matches the log line for line.

A count-only read of the export found eight fields and 49,130 unique identity numbers with no duplicates. MD5-format hashes sit in 46,979 rows, with 36,567 distinct values, and one value is shared by 5,001 accounts. A second, separately labelled export lists 1,451 privileged role assignments over 1,080 accounts across 20 of the secretariat's systems. The two agree record for record: 1,079 of the 1,080 privileged identifiers are logins in the main export, 1,027 of those carry the identical hash on both sides, and status flags agree on all 1,038 comparable records. Two independent query outputs that agree like that are stronger evidence of real database access than either alone. I hold "data taken" at HIGH, with one caveat: the counts come from a single reader.

The operator then built a cracking input from the export. `john_in.txt` has 48,341 lines and covers every one of the 43,630 hash-bearing rows that carry a login, plus 2,727 empty-login hashes and 2 extras. Of the privileged accounts, 198 carry the most common hash in the whole table. The cracking input exists and the order is clear (export first, cracking input second). One retained cracking run ended in a device-memory error, and its account set is not attributed. Cracked or used accounts are INSUFFICIENT: no cracking output appears anywhere I can see.

The sessions themselves were working sessions. Login-success pages exist for at least four staff accounts. Five edits in one application returned "Registro alterado com sucesso!", three formula saves were accepted on 30 September, a password change returned a success message, and an upload returned a success alert for a file named `svc.jsp`, the same name as one of the JSPs listed at the bank. Whether that upload was stored or ever ran is not shown, and a shared filename is not a byte match. An administrator page refused one request with a 403. The purpose of the edits is not shown either, which is why the ATT&CK impact row for stored data manipulation stays NOT SHOWN.

One identity number recurs across three of the operator's tools for the secretariat, a second appears in another script family, and a third is in a further login list. My guess is that one of these was the first account the operator got, and the rest are the usual insecure accounts any large organisation carries: weak or reused passwords, no second factor, stale service accounts. That is a guess, and I give it no confidence label.

</details>

<details markdown="1" class="hl-teardown">
<summary>The traffic department, the second finance secretariat, the security provider and the cloud supplier: four different reasons the evidence stops where it does</summary>

At the traffic department the operator held a saved GLPI central interface for one of the department's systems, showing an active Super-Admin profile and a named account context. That is an authenticated administrator page, so the grade is COMPROMISED. The page carries no client address, no timestamp and no capture route, so I hold the grade at MODERATE. Alongside it sit operator clients for a command page they assume exists on the department's help desk and for direct SQL as the database administrator, each with an embedded credential and none with any output. The help desk itself stays LISTED.

The second state finance secretariat shows tooling that only makes sense with a foothold already in place. A pair of scripts sends commands through a relay script at a fixed path on the state's GLPI help desk, using a hard-coded key, and tests internal directory services through it, while a status script re-checks the relay plus a database, a directory and 13 internal services with embedded credentials. They read as though the operator already holds something on that help desk. The only response the directory holds, though, is a 285-byte 403 page saved under a configuration-like name, so the grade stays REACHED. A help desk that receives requests to a script path it does not ship is the thing to look for.

The managed security provider and the cloud supplier, the company that built a cloud portal used in the security provider's estate, share one exposure. A request-forwarding flaw in that portal returned anonymous debug pages, and 22 of them hold the same backend API token. At least 29 operator scripts present that token onward. Possession is not use: I found no accepted login at the security provider or the cloud supplier across 534 file hashes, and password-spraying against the security provider's mail accounts was denied. The security provider stays REACHED.

The cloud supplier is COMPROMISED on a separate basis, saved documentation pages for a Django application with signed-in session indications, and that basis carries the same provenance caveat as the traffic department. If those pages turned out to be an unrelated or edited copy, the cloud supplier would fall back to REACHED. The operator also wrote scripts that imitate a login page to capture credentials; no rendering or submission of that imitation is shown.

</details>

<details markdown="1" class="hl-teardown">
<summary>The IT provider: a directory export, a code-forge sweep and VPN scripts, none of which put the operator inside</summary>

The operator holds an LDIF export of part of the IT provider's directory, under the provider's own organisational unit: 2,538 entries in the portion read, mostly machine accounts with some staff identity data. Whole-file counts give 262 distinct identity-number-shaped values and 1,121 distinct e-mail-shaped values, all withheld. The data owner is the IT provider at HIGH. Which server it came from, by what route and when are unknown, and the latest dated note inside it is from February 2019, so it may be an old snapshot. The objective result is "exfiltrated" at MODERATE, and the grade stays REACHED, because nothing places the operator inside the IT provider.

Around that sit the code-forge clones (12 repositories in 21 seconds at 2026-09-30 00:19 UTC on the operator's host clock), public and error replies from the IT provider's portals, and script-only attempts with held credentials: a GlobalProtect-style VPN login, a password-grant test against the IT provider's identity service, and a loop of 15 candidate client identifiers against its token path. None has a reply.

The IT provider builds and runs the agency's systems, and the operator cloned its code within a day of re-cloning a GLPI exploit and while it held tooling aimed at the agency's help desk. I lean toward a supply-chain approach, studying the provider's code as a way into the client, because that is a common vector now. I cannot say it with certainty. What the sequence does show is deliberate targeting, not an opportunist who stumbled into these organisations.

</details>

---

## 11. The Monitoring Server as a Command Plane
{: .hl-tier-3}

With one stolen staff account, the operator logged into an internal Zabbix monitoring server and used its own script feature to run commands on the machines it monitors. Its scripts create temporary global scripts and command items, run them on a monitoring proxy, receive the result on the operator's own listener, and delete the objects afterwards. One of those callbacks returned root identity and a hostname from the proxy to 38.180.16[.]98 on port 9090. I hold the join between that script and that callback at MODERATE, and I cannot name the network that owns the proxy, so it is graded COMPROMISED rather than added to the agency.

The technique is not a mark of special skill. It has been publicly documented since at least 2013, in a [Metasploit module](https://www.rapid7.com/db/modules/exploit/multi/http/zabbix_script_exec/) (CVE-2013-3628), a [published exploit](https://www.exploit-db.com/exploits/39937) that drives the same thing over the JSON-RPC API, and the vendor's own [documentation of remote commands](https://www.zabbix.com/documentation/7.0/en/manual/config/notifications/action/operation/remote_command). Its value is as defender guidance, and it fingerprints nobody. What is less documented is the combination here: execution through a proxy, objects created in bulk and cleaned up, driven by an ordinary stolen account rather than an administrator.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015/brazil-toolkit-zabbix-command-plane.svg" | relative_url }}" alt="Vertical chain of five steps and one dashed card. Step 1, orange: one stolen staff account on the Zabbix server, appearing in 110 of 534 file hashes in the later script batches, reached through a local SOCKS listener on the operator's own host; its name matches the local part of an agency e-mail address in the EDR console user list, MODERATE, an association and not proof of ownership. Step 2, red: temporary global scripts and command items; of 76 scripts read in full, 36 read or poll, 37 create items or scripts that run commands, 3 delete the operator's own objects; names z-revtest, z-dbcred, z-srvrec4, z-satsudo and diag-04 to diag-06, prefixes z-, wv3_ and poc, item identifiers 96795 and 96797 to 96802. Step 3, red: commands run on the monitoring proxy, whose network is not established, graded COMPROMISED at MODERATE and not added to the agency's row. Step 4, deep red: root identity and a hostname returned to 38.180.16[.]98 on port 9090; join of script to callback MODERATE. Step 5, red: the operator deletes its own objects, the only anti-forensic step that left a trace. Dashed red card: intent only, shell histories, directory-service and database configuration, SSH material, SNMP community strings, instance-metadata roles and egress tests requested, with no output held. Footer anchors: Zabbix audit log entries for scripts or items created, run and deleted by one account in a short window.">
  <figcaption><em>Figure 4: The monitoring-server technique in the order a Zabbix owner would see it in the audit log. The proxy's network is not established, so the activity is not added to the agency's row, and the dashed card shows intent where no output is held.</em></figcaption>
</figure>

<details markdown="1" class="hl-teardown">
<summary>The account, the script families, the object names a Zabbix owner can search for, and what was asked of monitored hosts</summary>

One staff-style account and its password appear in 110 of the 534 file hashes in the operator's later script batches. The account name matches the local part of an agency e-mail address in the SentinelOne console's user list, so the association with the agency is MODERATE: an association, not proof of ownership. The scripts reach the Zabbix server's API and web frontend through a local SOCKS listener on the operator's own host.

Of 76 Zabbix scripts read in full, 36 only read inventory or poll, 37 create items or scripts that run commands on monitored hosts, and 3 delete the operator's own objects. A wider itemisation over 91 files puts 38 in the middle class; the one-script difference is unreconciled, and I report both splits rather than pick one. The objects carry names the operator chose, which makes them the most useful thing in this section for anyone who runs Zabbix. Global scripts named `z-revtest`, `z-dbcred`, `z-srvrec4` and `z-satsudo`; object name prefixes `z-`, `wv3_` and `poc`; three scripts named `diag-04` to `diag-06`; and item identifiers 96795 and 96797 to 96802. The operator labelled some of them "NOSSO" ("ours") and "red team".

The commands it asked monitored hosts to run go well past identity checks. They request shell histories, directory-service and database configuration, SSH material, SNMP community strings and cloud instance-metadata roles, and they test egress to the operator's servers. No output of those requests is held, so this shows intent and capability, with no harvested credentials. A separate listener on 38.180.16[.]98 port 9443 was meant to receive a path map of the proxy host; only its startup line is held, and no arrival is shown.

The same account and password were tried elsewhere: at a VPN gateway script for the IT provider, an LDAP bind script, the IT provider's identity service, an IT inventory host and a container-management API, and the same password at five MySQL hosts. No reply to any of those is held. This is access built from access. A credential taken once is reused to run commands, test egress and look for more credentials, and the cleanup of its own monitoring objects is the only anti-forensic step that left a trace.

The operator also held Zabbix inventory exports: 8,017 host records, and 13,445 `system.run` items across 1,569 hosts with 11,240 non-empty values. Who produced those exports, and from which instance, is not resolved.

</details>

---

## 12. The Port 53 Relay, and the WebLogic Scripts That Would Deliver It
{: .hl-tier-3}

The operator's reverse relay is a 3,219-byte, 83-line Java source file, `Relay.java.new`, that calls home to 38.180.16[.]98 on TCP port 53 and does exactly what it is told. It announces itself, waits, opens a connection to whatever host and port the controller names, and then copies bytes in both directions until either side closes. There is no encryption, no authentication and no framing. Port 53 is the DNS port, which many networks let out when they block most other ports, but nothing about the traffic is DNS.

That design tells me what the operator cared about. Encryption and stealth layers add errors, truncation and dropped sessions; a bare line protocol does not. This operator wanted relayed traffic to arrive complete, and it accepted being easy to see on the wire in exchange. For defenders that is a gift, and Section 16 turns it into rules.

The operator's own relay log shows the relay in use, with 1,051 check-ins from a single victim estate's egress address, split into two labelled lanes. One lane, "pod", announces `READY` and logs 648 check-ins with 272 tunnel-up events to 71 destinations. The other, "wls", announces `READY2` and logs 403 check-ins with 143 tunnel-up events to 6 destinations. There are 618 failed dials. The log has clock times but no date or zone, and it proves connection setup, not logins or transferred content.

<details markdown="1" class="hl-teardown">
<summary>The relay protocol step by step, as it runs on the wire, and how common network tooling sees it</summary>

The file I examined matches the "wls" lane: its announce string is `READY2`, which is that lane's label in the operator's log, and I hold that match at HIGH. That this exact file was the one deployed is not established. I never read a source for the "pod" lane, so everything below describes the wls variant. The file sits in the operator's directory; that the operator wrote it is not established either.

When it runs, the sequence is fixed:

1. The relay opens a TCP connection to the literal address 38.180.16[.]98 on port 53, with no DNS lookup and a 15-second connect timeout.
2. Immediately after the handshake it sends `READY2` and a newline, 7 bytes, hex `52 45 41 44 59 32 0a`. Every one of 22 sessions observed on the wire opened with that line and nothing else.
3. It waits for one line from the controller with a 15-second read timeout. Each time the timeout expires it sends `PING` and a newline, 5 bytes, so an idle session carries a keepalive every 15 seconds.
4. The controller sends one line of the form `DIAL <host> <port>`, ended by a newline and capped at about 200 characters. Anything else makes the relay close the socket, sleep one second and reconnect. The relay holds no target list of its own; the controller chooses every destination.
5. The relay opens a fresh connection to that host and port, with a 10-second timeout, and replies `OK` (3 bytes) if it succeeds or `FAIL` (5 bytes) if it does not. On the wire the onward connection began 2 milliseconds after the instruction arrived.
6. After `OK` there is no further protocol. The controller socket and the onward socket are spliced byte for byte, through a 64 KiB buffer and one extra thread, until either side closes. On the wire, bytes crossed the splice unchanged within a millisecond.
7. When a session ends the relay reconnects at once and announces again. After an error it waits 5 seconds first.

The controller in that observation was not the operator's, so the controller-side timings are not evidence of operator behaviour. How the real controller paces its instructions, and whether it ever sends anything before `DIAL`, is unknown. The wire observations come from the relay running under Java on Windows; the operator ran it on Linux hosts, and while the application bytes should not depend on the platform, I have not seen that.

Common tooling notices it without knowing any of the strings. Zeek attempts its DNS analyzer on TCP 53, cannot parse a 7-byte ASCII line as a DNS-over-TCP message (the first two bytes, `52 45`, would claim a 21,061-byte message), raises a DNS `weird` on every relay flow (`DNS_truncated_len_lt_hdr_len` or `DNS_Conn_count_too_large`) and leaves the service field empty. Suricata leaves the application protocol as `none` or `failed`. A TCP 53 flow with no parsed DNS is therefore a generic hunt that would have caught this relay on its own.

</details>

<details markdown="1" class="hl-teardown">
<summary>The WebLogic plant-and-scrub scripts, which exist only as scripts</summary>

A set of operator scripts targets an Oracle WebLogic environment whose owner I could not establish. One sends a WS-AT SOAP envelope that writes a command-execution JSP named `health.jsp` into every subdirectory of every `_WL_internal` or `stage` directory in the domain tree. A second deletes one planted copy and rewrites every log file under the user-projects tree without the lines that name it. A third counts the logs that mention the plant names by sleeping one second per match, a timing side channel that reads the answer without returning any output.

A relay delivery script, `q_uprelay.php`, writes `Relay.java` in chunks through `health.jsp` and launches three background Java relays. The operator's relay log does show a wls lane reaching six destinations behind that environment, which fits, but no write, compile, plant or process output from these scripts is held. The plant, the scrub and the delivery are all script-only.

I can read them two ways. One is fast, fire-and-forget spreading of access: plant everywhere, report nothing, and use a separate tool later to find where it landed. The other is persistence: plant, wipe the traces and wait until it is needed. Both remain readings of scripts. Neither is a shown plant, and the WebLogic systems stay REACHED.

The relay and the bank's tunnel client do the same job in different languages toward different servers. My read is that the relay is either a fallback for when the primary tunnel fails, or something built for one specific target. What would separate those two (a victim configuration naming it, or a script choosing between it and the SOCKS client) is not in the directory.

</details>

---

## 13. MITRE ATT&CK Mapping
{: .hl-tier-2}

The mapping covers 70 procedure rows across 57 distinct technique IDs (Enterprise ATT&CK v19.2): 51 OBSERVED, 17 INFERRED and 2 NOT SHOWN. OBSERVED includes a retained attempt that failed, where the attempt is the procedure. INFERRED means the operator's tooling is built to do it but no execution result is held. NOT SHOWN rows mark a boundary and claim no impact. Confidence grades the mapping and its evidence. On an INFERRED row, HIGH means I am confident the tooling does this; whether it ran is a separate question.

The techniques that carry the case are below. The full table follows in the collapse.

| Tactic / Technique | Name | Status | Conf. | Evidence |
|---|---|---|---|---|
| Initial Access / T1190 | Exploit Public-Facing Application | OBSERVED | HIGH | Agency GLPI htmLawed, CVE-2022-35914 |
| Initial Access / T1078 | Valid Accounts | OBSERVED | MODERATE | Finance secretariat staff sessions; traffic department admin page |
| Execution / T1059.004 | Unix Shell | OBSERVED | HIGH | Agency GLPI host; bank WSO2 container |
| Credential Access / T1528 | Steal Application Access Token | OBSERVED | HIGH | SentinelOne token from support-app settings |
| Lateral Movement / T1550.001 | Application Access Token | OBSERVED | HIGH | SentinelOne console API queries |
| Discovery / T1518.001 | Security Software Discovery | OBSERVED | HIGH | SentinelOne agent and rogue inventories |
| Collection / T1213 | Data from Information Repositories | OBSERVED | HIGH | GLPI tickets; finance secretariat account table |
| Collection / T1119 | Automated Collection | OBSERVED | HIGH | `pull_mass.py` over the GLPI file store |
| Execution / T1072 | Software Deployment Tools | INFERRED | MODERATE | Zabbix global scripts on a monitoring proxy |
| Command and Control / T1090.001 | Internal Proxy | OBSERVED | HIGH | Two relay lanes, 1,051 check-ins |
| Command and Control / T1095 | Non-Application Layer Protocol | OBSERVED | HIGH | `READY2` / `DIAL` line protocol |
| Command and Control / T1571 | Non-Standard Port | OBSERVED | HIGH | Plaintext relay on TCP 53 |
| Command and Control / T1572 | Protocol Tunneling | OBSERVED | MODERATE | `/tmp/upd` reverse-SOCKS client at the bank |
| Exfiltration / T1041 | Exfiltration Over C2 Channel | OBSERVED | MODERATE | 905,374-byte agency package as command output |
| Defense Impairment / T1685 | Disable or Modify Tools | NOT SHOWN | HIGH | Uninstall-password request refused |
| Impact / T1565.001 | Stored Data Manipulation | NOT SHOWN | MODERATE | Finance secretariat edits accepted; purpose not shown |

Port 53 here does not mean DNS tunnelling, and root identity returned from a monitoring proxy does not mean privilege escalation; I map neither. The help desk as a reconnaissance source sits under T1213, which is where ATT&CK puts it.

<details markdown="1" class="hl-teardown">
<summary>All 70 procedure rows, with status, confidence and scope</summary>

| Tactic / Technique | Name | Status | Conf. | Scope |
|---|---|---|---|---|
| Reconnaissance / T1595 | Active Scanning | OBSERVED | HIGH | IT provider public hostnames; no compromise implied |
| Reconnaissance / T1593.003 | Code Repositories | OBSERVED | MODERATE | IT provider public code clones |
| Initial Access / T1190 | Exploit Public-Facing Application | OBSERVED | HIGH | Agency GLPI; not every scanned GLPI site |
| Initial Access / T1078 | Valid Accounts | OBSERVED | MODERATE | Finance secretariat; traffic department |
| Execution / T1059.004 | Unix Shell | OBSERVED | HIGH | Agency GLPI; bank WSO2 containers |
| Persistence / T1505.003 | Web Shell | OBSERVED | MODERATE | Bank WSO2 helper-page `id` reply; operator placement of the listed JSPs only LOW-MODERATE |
| Persistence / T1098 | Account Manipulation | OBSERVED | MODERATE | Finance secretariat application, owner inferred |
| Stealth / T1027.010 | Command Obfuscation | OBSERVED | HIGH | Base64-wrapped commands, bank and agency |
| Stealth / T1140 | Deobfuscate/Decode Files or Information | OBSERVED | HIGH | Bank WSO2 |
| Credential Access / T1552.001 | Credentials In Files | OBSERVED | HIGH | Agency support-app settings; bank WSO2 |
| Credential Access / T1552.004 | Private Keys | OBSERVED | HIGH | Bank WSO2 keystore; route unknown |
| Credential Access / T1552.005 | Cloud Instance Metadata API | OBSERVED | HIGH | Agency-associated AWS account |
| Credential Access / T1555 | Credentials from Password Stores | OBSERVED | HIGH | Finance secretariat account table; agency Redmine |
| Credential Access / T1528 | Steal Application Access Token | OBSERVED | HIGH | Agency SentinelOne integration token |
| Credential Access / T1110.002 | Password Cracking (attempted) | OBSERVED | HIGH | One run ended in a memory error; success not shown |
| Credential Access / T1056.003 | Web Portal Capture | INFERRED | HIGH | GLPI auth hook; installation not shown |
| Lateral Movement / T1550.001 | Application Access Token | OBSERVED | HIGH | SentinelOne console; no remote-shell use |
| Lateral Movement / T1210 | Exploitation of Remote Services | INFERRED | HIGH | Owner-unknown internal WebLogic host |
| Discovery / T1082 | System Information Discovery | OBSERVED | HIGH | Bank WSO2; agency console inventory |
| Discovery / T1033 | System Owner/User Discovery | OBSERVED | HIGH | Bank WSO2 |
| Discovery / T1087.001 | Local Account | OBSERVED | HIGH | Bank WSO2 |
| Discovery / T1087.004 | Cloud Account | OBSERVED | HIGH | Agency SentinelOne console users |
| Discovery / T1057 | Process Discovery | OBSERVED | HIGH | Bank WSO2 |
| Discovery / T1016 | System Network Configuration Discovery | OBSERVED | HIGH | Bank WSO2 |
| Discovery / T1049 | System Network Connections Discovery | OBSERVED | HIGH | Bank WSO2 |
| Discovery / T1018 | Remote System Discovery | OBSERVED | HIGH | Agency console and container environment |
| Discovery / T1046 | Network Service Discovery | OBSERVED | HIGH | Owner-unknown internal estate |
| Discovery / T1613 | Container and Resource Discovery | OBSERVED | HIGH | Agency-associated container metadata |
| Discovery / T1518.001 | Security Software Discovery | OBSERVED | HIGH | Agency SentinelOne inventory |
| Collection / T1005 | Data from Local System | OBSERVED | HIGH | Agency GLPI and package store |
| Collection / T1213 | Data from Information Repositories | OBSERVED | HIGH | Finance secretariat accounts; agency engineering and Redmine databases |
| Collection / T1119 | Automated Collection | OBSERVED | HIGH | Agency GLPI file store |
| Command and Control / T1090.001 | Internal Proxy | OBSERVED | HIGH | Pod and wls relay lanes |
| Command and Control / T1095 | Non-Application Layer Protocol | OBSERVED | HIGH | Same relay lanes |
| Command and Control / T1572 | Protocol Tunneling | OBSERVED | MODERATE | Bank client invoked; tunnel not shown |
| Command and Control / T1071.001 | Web Protocols | OBSERVED | HIGH | Agency GLPI command channel |
| Command and Control / T1132.001 | Standard Encoding | OBSERVED | HIGH | Base64 command output |
| Exfiltration / T1041 | Exfiltration Over C2 Channel | OBSERVED | MODERATE | Agency package product, not all held copies |
| Exfiltration / T1020 | Automated Exfiltration | OBSERVED | HIGH | Agency GLPI; counts overlap |
| Defense Impairment / T1685 | Disable or Modify Tools | NOT SHOWN | HIGH | No endpoint impairment established |
| Impact / T1565.001 | Stored Data Manipulation | NOT SHOWN | MODERATE | Accepted writes; impact purpose not shown |
| Reconnaissance / T1595.001 | Scanning IP Blocks | OBSERVED | HIGH | Security provider address space; no compromise implied |
| Reconnaissance / T1595.002 | Vulnerability Scanning | OBSERVED | MODERATE | Security provider webmail; a 401, not access |
| Initial Access / T1190 | Exploit Public-Facing Application | OBSERVED | HIGH | Supplier-built cloud portal, request forwarding |
| Credential Access / T1528 | Steal Application Access Token | OBSERVED | HIGH | Backend token from debug pages |
| Credential Access / T1110.003 | Password Spraying | OBSERVED | HIGH | Security provider mail accounts; denied |
| Credential Access / T1110.001 | Password Guessing | OBSERVED | MODERATE | Security provider monitoring portal |
| Lateral Movement / T1550.001 | Application Access Token | INFERRED | HIGH | Cloud portal backend API; validity unproven |
| Initial Access / T1078 | Valid Accounts | INFERRED | MODERATE | Zabbix staff account; agency link MODERATE |
| Execution / T1072 | Software Deployment Tools | INFERRED | MODERATE | Monitoring proxy; owner open |
| Execution / T1072 | Software Deployment Tools | INFERRED | HIGH | Zabbix server and agent; script-only |
| Discovery / T1083 | File and Directory Discovery | OBSERVED | MODERATE | Same proxy; contents not held |
| Command and Control / T1095 | Non-Application Layer Protocol | OBSERVED | MODERATE | Proxy callback to port 9090; undated |
| Discovery / T1018 | Remote System Discovery | OBSERVED | MODERATE | Unattributed monitoring estate |
| Collection / T1602.001 | SNMP (MIB Dump) | INFERRED | HIGH | Zabbix-named network devices |
| Discovery / T1016.001 | Internet Connection Discovery | INFERRED | HIGH | Egress tests to operator servers |
| Credential Access / T1552.003 | Shell History | INFERRED | HIGH | Proxy and server; script-only |
| Credential Access / T1552.001 | Credentials In Files | INFERRED | HIGH | Proxy and server; script-only |
| Credential Access / T1552.005 | Cloud Instance Metadata API | INFERRED | HIGH | Proxy and server; script-only |
| Credential Access / T1003.008 | /etc/passwd and /etc/shadow | INFERRED | HIGH | Proxy and server; script-only |
| Stealth / T1070 | Indicator Removal | INFERRED | MODERATE | Deletion of the operator's own Zabbix objects |
| Credential Access / T1110.004 | Credential Stuffing | INFERRED | MODERATE | IT provider, agency-named and MySQL hosts; no reply |
| Initial Access / T1133 | External Remote Services | INFERRED | HIGH | IT provider VPN portal; script-only |
| Discovery / T1087.002 | Domain Account | OBSERVED | MODERATE | IT provider directory export; route unknown |
| Collection / T1213 | Data from Information Repositories | OBSERVED | MODERATE | Owner-unattributed integration database |
| Collection / T1213 | Data from Information Repositories | OBSERVED | HIGH | Agency GLPI document search |
| Collection / T1213 | Data from Information Repositories | INFERRED | HIGH | Agency GLPI REST searches; script-only |
| Credential Access / T1552.001 | Credentials In Files | OBSERVED | HIGH | Agency integration settings |
| Command and Control / T1571 | Non-Standard Port | OBSERVED | HIGH | Relay lanes on TCP 53 |
| Command and Control / T1105 | Ingress Tool Transfer | INFERRED | HIGH | Relay delivery via `health.jsp`; script-only |

</details>

---

## 14. Threat Actor Assessment
{: .hl-tier-2}

I cannot attribute this activity to any publicly named actor or persona, and I put named-actor attribution at INSUFFICIENT. What I can describe with confidence is the operation: a sustained campaign of collection and access expansion across Brazilian public bodies and their suppliers, whose ultimate purpose is undetermined. The evidence for what the operator did is far stronger than the evidence for who it is. This is the first coverage The Hunters Ledger has published on this operator: no earlier case of mine touches its three addresses or the `bpupdate.exe` builds.

Nothing in the directory authenticates an identity. The operator's git clones carry a root account on a provider-style host-local name, `v487918523.local`, which is a pivot candidate whose owner I have not checked, not a persona. Its working labels and comments are in Portuguese, mixed with English, which says what language it works in and nothing about nationality or location; I have no measured base rate for that and no working-hours analysis. Its self-labels ("red team", "NOSSO", test strings like `PROVA123`) are statements by the operator, and an intruder calling itself a red team is not evidence of permission. None of my other 69 investigations shares a recorded key, address or artifact with this one, though that comparison covered what I recorded for each case, not every byte of their tooling.

In my judgment this is not an authorised test, and I base that on three things I see constantly in my day job running a managed detection and response team. An authorised tester would not keep a victim's data in a publicly reachable directory. A red team proves access and stops, and does not queue 4,675 documents for download or export a whole account table. And an engagement covers one organisation, perhaps one connected organisation.

This operator shows inside or authenticated access at five organisations, two of them only on saved pages whose capture route is unknown, and some of the five have no connection to each other at all. The other 87 of the 92 rows are probes, refusals and names on lists, so they say nothing about access, and it is the five that carry this point. The formal analysis leaves that hypothesis at LOW rather than excluded, because no owner has yet told me there was no engagement, and I cannot rule one out until they do.

It does not behave like a smash-and-grab access broker either. I would expect a broker holding what this operator held by early October to sell it and move on to the next target. This operator instead mapped the EDR estate for unmonitored machines, asked for agent uninstall passwords, kept a tunnel running and kept widening access. That points to someone who intends to act inside these networks itself. It is too long-running and too evasive to be a bulk collector, though it could sit somewhere between a broker and something else, so I hold access brokering at LOW rather than ruling it out.

On motive, my read is that it cannot be pinned down yet because the operator is early in its attack chain: still doing reconnaissance, setting up footholds, exploring and collecting. Sustained over weeks, from at least mid-September, the same behaviour is also consistent with espionage. The counter-evidence travels with that read. Across the whole directory the operator builds new access and uses access it already holds in similar measure (252 files against 213), and a sale made somewhere else would not appear in this directory. So collection may already be the objective, or a buyer may simply not be visible to me.

The competing-hypotheses analysis agrees with that uncertainty. Intelligence-purpose collection and direct financial use of benefit and tax data tie, with nothing to separate them: the source code and network inventories fit the first, and the account tables and a cracking pipeline fit the second. Nothing in the directory shows a recipient, a demand, a sale, a fraud transaction, a publication or destruction. My first reaction to the bank's material was that it looked like extortion being prepared; nothing shows a demand, and I no longer rank that read above the others.

<details markdown="1" class="hl-teardown">
<summary>The competing hypotheses, why no tracking designation, and what would change each call</summary>

I tested six hypotheses about who is behind this and five about why, scoring only observations, never missing documents or an absent buyer.

| Hypothesis | Inconsistencies | Where it stands |
|---|---|---|
| A single independent criminal operator | 0 | Survives; criminal purpose and a single principal are unproved |
| A state-directed espionage operator | 0 | Survives; collection from government alone is not evidence of tasking |
| An access broker | 0 | Survives at LOW; access mapping can precede a sale, and an off-box sale is invisible |
| Authorised testing | 1 | LOW; contradicted by retained, publicly exposed data, but not conclusively falsified |
| The actor Cybernews reported in September | Not measurable | NOT CHECKED; no shared hard indicator to compare |
| Several unrelated operators sharing the hosts | Not measurable | Unresolved; earlier tenants on the addresses are a reason to partition evidence, not proof of multiple controllers |

I do not assign a tracking designation of my own. My threshold for one is three characteristics that are distinctive to this operator, at least two of them technical, each with provenance. Only one candidate meets it, the relay's `READY2` / `DIAL` line protocol. The reverse-SOCKS client is a generic pattern, the Zabbix technique is documented public tradecraft, the `bpupdate.exe` builds are tied to the operator by address only, the help-desk mining has no measured distinctiveness, and the target set is shared with other operators reported against Brazilian public bodies. Counting a protocol's banner, port and grammar as three characteristics would be cheating. Until two more distinctive, operator-bound characteristics turn up, this stays an unknown operator.

| Call | What would change it |
|---|---|
| Unknown actor | An operator-owned key or account, or a custom code lineage, matched externally with compatible tenancy |
| State direction versus independent crime | Controller-bound tasking or delivery records, or verified criminal use of the holdings |
| Collection versus financial use | A recipient or tasking record, or a fraud transaction tied to these holdings |
| Access brokering | A listing, an offer, a buyer or a second party using the same access |
| Authorised testing | A rights-holder's scope covering this controller, these dates and these estates, or a rights-holder's statement that no engagement existed |
| The Cybernews actor | A matching command server, SSH key or file hash from that report's unredacted material |
| A tracking designation | Two further distinctive, operator-bound characteristics, at least one of them technical |

</details>

---

## 15. Indicators of Compromise
{: .hl-tier-2}

The machine-readable indicator set is published separately as a [JSON IOC feed](/ioc-feeds/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015/), undefanged and ready for ingestion. It carries 41 operator-side indicator entries: 2 full SHA-256 file hashes, 9 address and port entries over the three operator servers, 4 URLs, 12 file paths, 1 mutex, 1 TLS certificate, 3 service fingerprints, 6 relay network signatures, 2 behavioural patterns and 1 operator host-name fingerprint. Every entry carries its own confidence and action, and those govern over the feed-level label. The feed's validator parsed 30 entries in 4 of its 10 containers; the other containers were not machine-checked.

| Indicator | What it is | Confidence | Action |
|---|---|---|---|
| `38.180.16[.]98` | Open directory, relay controller (TCP 53), callback listeners (9090, 9443), SMB listener (445) | HIGH | BLOCK on the listed ports from 2026-09-26 |
| `38.180.16[.]98:53` | Relay controller for both logged lanes, "pod" (announces `READY`) and "wls" (announces `READY2`) | HIGH | BLOCK |
| `209.99.185[.]148` | Canary (8080), the bank's tunnel destination, "Update Service" TLS listener (443, 10443) | HIGH | BLOCK |
| `38.180.196[.]193:8899` | Payload staging, later the `cadsus-panel` | MODERATE | BLOCK the port; MONITOR the host |
| `986f697d2ef67a38e25c6a17cdecd7bb50148f2c2993864c748e3504d3d747f0` | `Relay.java.new`, the TCP 53 relay source | DEFINITE | HUNT, BLOCK |
| `0ce2e8a961c564e9d76c2f59662c1107b33e2c32922e39a4c0d900e79722e7bc` | SHA-256 of the "Update Service" certificate on 209.99.185[.]148 | HIGH | HUNT for reissues |

Read the context fields before blocking. The port 53 entry is a historical operator role, held at HIGH. The `READY2` first payload is DEFINITE only for the contained run of the wls-variant file, and which file was actually deployed is not established. The feed carries the same HIGH with the same scope note. A connection that announces only `READY` is the pod lane, whose source I never read, and it matters just as much.

The first address is recycled: its port 443 certificate, JARM and SSH key belong to earlier tenants, and ports 4000 and 111 were seen on it in the window but no operator file names them, so their role is unestablished. The second address also hosts ten third-party parked domains. The two URLs on port 8146 belong to the `bpupdate.exe` builds, whose tie to the operator is address-only, and they are carried at MODERATE.

Several things are deliberately not in the feed. The victim estate's egress address, every victim-internal range, a victim's external directory server and the unresolved peer of one Zabbix callback are excluded, because blocking a victim's address harms the victim. Five operator tool hash sets known only by truncated prefixes are excluded by the full-hash rule. JARM values and SSH host keys are excluded because they either belong to earlier tenants or have no measured base rate. No credential, token, key or victim personal data appears anywhere in the feed.

The Zabbix object names (`z-` and `wv3_` prefixes, `poc` items, `diag-04` to `diag-06`, item identifiers 96795 and 96797 to 96802) live inside a victim's monitoring server. They are in the feed as behavioural patterns for a Zabbix owner to search for in their audit log, never as blocklist entries.

---

## 16. Detection and Hunting Guidance
{: .hl-tier-2}

The full rule set is published separately at [Detection Rules, Brazil Public-Sector Toolkit](/hunting-detections/inv-2026-067-detections/): 13 rules, 5 Sigma (3 detection, 2 hunting) and 8 Suricata (3 detection, 5 hunting), with no YARA. All 13 pass syntax validation. None has been measured for prevalence against real traffic, and the coverage-gaps section of that page is worth reading before deploying any of them.

The relay rules are the only ones I could fire against a real capture of the threat behaving, and the numbers belong to two different rules, so I keep them apart. The published announce rule fired on 22 of 22 relay sessions in the filtered capture (the relay sessions plus the one onward connection, on which it stayed silent), and on none of 2,411 TCP flows from seven unrelated captures. None of that traffic contains real DNS over TCP, so how the three port 53 rules behave against it is NOT CHECKED.

An earlier, scratch version of the announce rule, written from the same contained capture, fired on all 22 relay sessions and on none of the other 37 TCP flows in the unfiltered capture. Those 37 flows were the capture's own background traffic, so that is a measurement against the scratch rule and not a false-positive rate. The full capture did not survive, so the published rule was never run against those 37 flows.

Everything built from the operator's scripts (the WebLogic plant, the log scrub, the Zabbix commands) is grounded in what the scripts ask for, and has not been seen firing on victim telemetry.

### Where to look first

Start with the help desk. Requests to GLPI's `vendor/htmlawed/htmlawed/` directory, and any POST to a test page there under any filename, are the agency's entry point. Ticket and knowledge-base searches for security-stack terms (SentinelOne, Intune, Entra, GlobalProtect, remote shell) or for documents titled as database dumps, run in bulk by one session, are the reconnaissance. If you run GLPI 9.5.x, check `inc/auth.class.php` for code that writes submitted passwords to `files/_log/event.log`.

In the EDR console, SentinelOne's management audit trail will show an API user enumerating service users, human users, the agent list and the rogue-device inventory, and asking for agent uninstall passwords. The last of those is the one to alert on. The token in this case came from a help-desk application's integration settings, so any console token stored in a third-party application's settings deserves rotation and an owner.

On the monitoring plane, the Zabbix audit log is where to look for global scripts or command items created, executed and deleted by one ordinary account within a short window, and for the object names in Section 15. On monitored hosts, a Zabbix agent or proxy process spawning a shell that reads shell histories, `/etc/shadow`, SSH keys or the cloud metadata endpoint is covered by one of the hunting rules.

At the egress, any internal host holding a TCP connection to port 53 whose payload does not parse as DNS deserves a look; Zeek and Suricata both flag it without knowing this relay's strings. An application service account (in this case the WSO2 one) running a client that holds HTTPS to a hard-coded external address through the organisation's own forward proxy is the bank's pattern, and the proxy's CONNECT log is where it shows.

For WebLogic, a shell spawned by the WebLogic Java process that writes a JSP into a `_WL_internal` or `stage` directory, or that rewrites log files under the domain tree, is covered by the Sigma rules. These come from scripts with no run evidence, so treat them as a hunt for the intent the scripts describe.

### Response orientation

- Hunt first for POSTs to GLPI's htmLawed test page under any name; SentinelOne console API enumeration and uninstall-password requests; Zabbix script creation and deletion bursts by one account; TCP 53 flows with no DNS.
- Look for and remove `/tmp/upd` running as an application service account; `/tmp/Q.class`; unexplained JSPs in WSO2 `authenticationendpoint` and `oauth2` web applications; `health.jsp` or `decrypt*.jsp` under WebLogic `_WL_internal`; a password-logging hook in GLPI's authentication class; Zabbix objects named `z-*`, `wv3_*`, `poc*` or `diag-04` to `diag-06`.
- Contain by removing or patching GLPI's htmLawed test page and any renamed copy, rotating the WSO2 keystore and reissuing the exposed OAuth clients, revoking console API tokens held in third-party settings, resetting accounts in the secretariat's exposed account table (privileged and shared-hash accounts first), and blocking egress as the indicator table bounds it: the first address on its listed ports from 2026-09-26, the third address, and on the co-tenanted second address only port 8899, with the host itself monitored rather than blocked.

---

## 17. Notification
{: .hl-tier-2}

The bank and the agency were notified through CTIR Gov, Brazil's federal government incident response centre, starting in early October. The bank received an early notice on 2026-10-04 and a full encrypted evidence package on 2026-10-09. The agency received an early notice on 2026-10-05, with CERT.br copied, and follow-ups after it. The other organisations for which I hold specific, actionable information are notified in a separate round before this report is published, and the indicator feed and rules go public together with the report.

I do not contact the institutions whose API credentials were exposed at the bank. Those subscribers are the bank's to notify, and I gave the bank what it needs to do it. Organisations that appear here only at REACHED or LISTED, with nothing I can give them beyond the fact that they were probed, learn of it from this report.

---

## 18. Confidence Summary, Gaps, and What Would Change This
{: .hl-tier-2}

My findings sort cleanly by strength, and the table keeps each claim beside the observation that would move it.

| Claim | Confidence | What would change it |
|---|---|---|
| Host-side command output at the agency and the bank | HIGH | A host record showing the output or process came from another operator or another environment |
| The operator started the bank's tunnel process | MODERATE | The bank's process or proxy records naming a different source |
| Operator placement of the bank's JSPs | LOW-MODERATE | A placement record tying the JSPs to the operator, or creator and content evidence |
| The bank's entry through CVE-2022-29464 | Inferred | A preserved response showing the flaw worked |
| Finance secretariat COMPROMISED; data taken | MODERATE provenance; data taken HIGH | Request or host records tying the pages to another source; host execution would raise it |
| Traffic department and cloud supplier COMPROMISED | MODERATE | A capture route tying the pages to the operator, or proof they are unrelated copies |
| 92-row victim tally | MODERATE | A full reconciliation of the 175 hostname candidates |
| Infrastructure clustering of the three addresses | MODERATE | A shared, operator-bound fingerprint or provider record |
| `bpupdate.exe` under common control | MODERATE | A configuration lineage or service record binding the builds to the operator, or ruling it out |
| Relay protocol bytes, contained run of the wls-variant file | DEFINITE | A capture session whose first payload is not `READY2` |
| The run file is the wls lane's variant; deployed identity not established | HIGH | A pod-lane source announcing `READY2`, or a deployed-file hash that differs |
| Combined campaign absent from public reporting | MODERATE | A public report or feed record naming the combined activity |
| Named-actor attribution | INSUFFICIENT | An authenticated, operator-bound identity artifact |
| Malware family | INSUFFICIENT | A verified lineage to a named family |
| CRITICAL campaign severity | HIGH | Owner confirmation that the access is closed and the credentials rotated, or evidence the host execution was misattributed |

The largest open questions are all things only the affected organisations can answer. Whether any access is current, whether the bank's tunnel ever carried traffic, whether the GLPI credential hook was installed at the agency, whether any held credential or token is still accepted, and who owns the Zabbix servers, the integration database and the hosts the relay ran on are all NOT CHECKED. How many of the agency's documents actually left is NOT MEASURED, though a join of the operator's queue and log records could settle it.

Several things limit what I can say from the operator's side as well. I never read the "pod" lane relay source. The real controller's behaviour is unknown. The WebLogic plant, log scrub and relay delivery exist only as scripts. Some counts in this report come from a single reader of a large file, including the finance secretariat's export figures, and the five largest counts (4,675 paths, the 905,374-byte decode, 1,051 check-ins, 245,707 rows, 49,131 lines) rest on their recorded methods rather than an independent recount. The prior-art searches were not refreshed between 2026-10-09 and publication beyond a check on 2026-10-15 that found nothing new naming this operator.

Of the hypotheses I could not kill, three matter most for a reader. The saved-page grades at the traffic department and the cloud supplier may reflect someone else's collection. The long tail of REACHED and LISTED rows may be a product-class sweep rather than targeting. And collection may already be the objective, or a broker may simply not have listed yet. I would rather leave those open than pick the most satisfying answer for any of them.

---

## 19. References
{: .hl-tier-2}

- Cybernews (2026-09-09, updated 2026-09-10), [report on an intrusion at a Brazilian federal agency and its IT provider](https://cybernews.com/security/brazil-data-breach-government-employee-logins/); context only, no shared hard indicator.
- CyberCyber Labs (2026-07-28), ["Inside an Exposed C2 Server"](https://cybercyberlabs.com/reports/Inside-Exposed-C2.pdf) (CCL-2026-07-EXC2), sections 1 to 4; a different operator's GLPI compromise of a Brazilian public body.
- Rapid7 (2013-10-30), [Metasploit module `zabbix_script_exec`](https://www.rapid7.com/db/modules/exploit/multi/http/zabbix_script_exec/) (CVE-2013-3628); authenticated Zabbix server-script execution.
- [Exploit-DB 39937](https://www.exploit-db.com/exploits/39937) (2016-06-06); Zabbix JSON-RPC script update and execution.
- Zabbix documentation, [remote commands](https://www.zabbix.com/documentation/7.0/en/manual/config/notifications/action/operation/remote_command); vendor description of server, proxy and agent execution.
- CISA [Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (catalog version 2026.10.08); two Zabbix vulnerabilities listed, no post-exploitation pattern.
- VulnCheck, [GLPI exploitation](https://www.vulncheck.com/blog/glpi-exploitation), CVE-2022-35914 (GLPI htmLawed) background; quoted passages read.
- Deepwatch (April 2022), [advisory on exploitation of CVE-2022-29464](https://www.deepwatch.com/labs/customer-advisory-threat-actors-exploiting-critical-wso2-vulnerability/) (WSO2), itself quoting Rapid7.

---

© 2026 Joseph, The Hunters Ledger. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), free to republish and adapt, including commercially, with attribution to The Hunters Ledger and a link to the original.

