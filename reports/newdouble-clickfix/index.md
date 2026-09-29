---
title: "FACEIT ClickFix Pages Point CS2 Players to a Script URL That VirusTotal Ties to a Steam-Focused Executable"
date: '2026-09-28'
layout: post
permalink: /reports/newdouble-clickfix/
category: "ClickFix Delivery Chain"
description: "Fake FACEIT verification pages direct CS2 players to run a PowerShell downloader that, as held by VirusTotal on September 25, 2026, downloaded an executable built for Steam account theft."
hide: true
detection_page: /hunting-detections/newdouble-clickfix-detections/
ioc_feed: /ioc-feeds/newdouble-clickfix-iocs.json
unlisted: true
sitemap: false
detection_sections:
  - label: "YARA Rules"
    anchor: "#yara-rules"
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "Suricata Signatures"
    anchor: "#suricata-signatures"
ioc_highlights:
  - "202[.]71[.]14[.]31"
  - "newdoubleauthentification[.]com"
  - "newdouble-authentification[.]com"
  - "dd29536b27649fa897d39198f3ec32d05215b9c6d2864acc32f51de648a25e25"
  - "1366b8ca7f315142ba9989241402758cf2a86e5568a28da0942e1810fe12c324"
---

**Campaign Identifier:** Newdouble-ClickFix-202.71.14.31<br>
**Last Updated:** September 29, 2026<br>
**Threat Level:** HIGH

---

## BLUF (Bottom Line Up Front)
{: .hl-tier-1}

Two saved FACEIT-themed pages instruct Counter-Strike 2 players to paste and run a PowerShell command. The command names a script URL at `202.71.14.31`; the script VirusTotal held for that URL on September 25, 2026 was designed to install a Steam-focused executable. On September 29, 2026 the same host was still serving that script, byte for byte unchanged. Whether the lure pages and the executable URL are still live is NOT CHECKED. Which script a visitor received on either page's scan date, including the August 26 page, is NOT CHECKED.

That executable contains capabilities for Steam sign-in capture, Steam Guard removal, a fake VAC-ban screen, browser traffic redirection and an in-game CS2 module, but successful use against a victim is NOT CHECKED. I rate the threat HIGH for players who run the command because their Steam accounts are at risk. Inventory and skin loss would be a general consequence of account access rather than a kit capability, and the evidence does not establish a victim count.

Why that matters is set out in Section 1. Valve describes criminals stripping stolen Steam accounts to resell their items, Malwarebytes adds scamming the owner's friends, Kaspersky's Discord-linked detections of fake gaming software alone were more than fourteen times their 2024 level in 2025, and several vendors each count ClickFix among the most common ways in on their own customers. None of that is evidence of what this operator does with an account; I hold nothing that shows it.

## 1. Executive Summary
{: .hl-tier-1}

I found this on [Webamon](https://intel.webamon.com/), in saved scans of fake FACEIT verification pages. I'm a gamer myself, as plenty of people in security are, so this one hit home. With so many recent attacks aimed at gamers, I wanted players, and the people who look after their machines, to know what to watch for.

Steam accounts are worth stealing because of what they hold. In December 2015 Valve wrote that a compromised account's items "would be quickly cleaned out", traded on "eventually being sold to an innocent user", and that "Essentially all Steam accounts are now targets"; at the time it saw "around 77,000 accounts hijacked and pillaged each month" ([Valve, 2015](https://store.steampowered.com/news/19618/)). That figure is Valve's from 2015, not a current one. Writing in June 2026 about the same fake FACEIT verification theme, Malwarebytes lists what criminals do next: "steal items, scam friends, or sell the account on criminal marketplaces" ([Malwarebytes, 2026](https://www.malwarebytes.com/blog/threat-intel/2026/06/fake-verification-pages-are-stealing-steam-accounts-from-players)). That is what other criminals are documented doing with Steam accounts. Nothing I hold shows what this operator does with an account, or that it has taken one.

Gamers are a population attackers keep coming back to. Kaspersky's own 2025 telemetry counted 2,054,336 phishing attempts impersonating gaming platforms such as Steam, PlayStation and Xbox, and 20,188,897 attempted infections by malware disguised as gaming software, 18,556,566 of them tied to Discord and "more than 14 times higher than in 2024" ([Kaspersky, 2025](https://www.kaspersky.com/about/press-releases/kaspersky-reports-64-million-shopping-phishing-attempts-and-over-20-million-gaming-attacks-detected-in-2025)). Those are detections on Kaspersky's users, not victims, and the release gives no Steam-only figure. Malware has also reached players through the Steam store itself, in the PirateFi game ([SECUINFRA, 2025](https://www.secuinfra.com/en/techtalk/infostealer-malware-vidar-spread-via-the-steam-store/)) and a BlockBlasters patch ([G DATA, 2025](https://blog.gdatasoftware.com/2025/09/38265-steam-blockblasters-game-downloads-malware)).

ClickFix has not gone away either. ESET says its ClickFix detections grew 108 percent between the second half of 2025 and the first half of 2026, while still sitting below its early-2025 peak ([ESET, 2026](https://www.welivesecurity.com/en/eset-research/eset-threat-report-h1-2026/)). ReliaQuest calls it "the top delivery technique" in its customers' incidents for March to May 2026 ([ReliaQuest, 2026](https://reliaquest.com/blog/threat-spotlight-whats-trending-top-cyber-attacker-techniques-march-may-2026/)), and Microsoft's Digital Defense Report 2025 names it the most common initial access method in its Defender Experts notifications over the prior year. Each vendor is counting something different on its own customers, so I read them for direction, not as one number. In August 2026 Kaspersky described ClickFix commands posted on Steam forums, and that payload was a Monero miner ([Kaspersky, 2026](https://www.kaspersky.com.au/blog/steam-forum-clickfix-attack-irm-iex/36479/)), so a ClickFix aimed at gamers does not by itself mean account theft. What sets this kit apart is a payload built for Steam accounts.

The [August](https://intel.webamon.com/report/4298d731-f038-458a-8b67-f6d6497e5e84) and [September](https://intel.webamon.com/report/92202cbe-dbfe-4124-8883-2907424b4ed4) Webamon records show fake verification pages at `newdoubleauthentification.com` and `newdouble-authentification.com`. Both present `faceit.com` branding and put a command for `http://202.71.14.31/y/y.ps1` on the clipboard after a checkbox click. The visitor must still paste and run it. These are saved page observations from August 26 and September 26, 2026, not evidence that a player executed the command.

The script as held on September 25 pointed to `http://202.71.14.31/x/x.exe`, saved the executable as `steamwebhelper.exe` and attempted to launch it and keep it available at sign-in. A historical sandbox record observed a request for `/x/x.exe`; the exact script and executable bytes are identified by the hashes in Section 3. The executable is built to interfere with Steam sign-in and Steam Guard, show a fake VAC-ban notice, install a root certificate, change browser proxy settings and place a module into the CS2 game process. These are capability findings. A completed account takeover, successful placement of the CS2 module and successful traffic interception on a real victim remain unverified.

I found earlier FACEIT-themed verification abuse, gamer ClickFix delivery and a public account of a Steam-focused stealer whose behavior overlaps this kit substantially. That account, relayed in a forum thread on August 25, 2026, already describes Steam client debugging abuse, a trusted mitmproxy root certificate, local proxy redirection and a fake suspension notice in the Steam window. Its four published script hashes were first seen between August 17 and 22, before the earliest `newdouble` page, and VirusTotal associates two of them with FACEIT-named domains in the wild. The fake-ban screen and the certificate and proxy pair are therefore not new.

What I did not find in public reporting at the time of my bounded search is the `newdouble` domains or `202.71.14.31`, the only one of the four payload IPs that belongs to the September Steam kit chain. The search for the payload hashes is NOT CHECKED because its control failed, and URLhaus is NOT CHECKED. The other three IPs (`93.183.93.9`, `212.113.98.10` and `185.209.30.61`) are older payload hosts that used the same page template and path layout, with operator link INSUFFICIENT. Novelty is **MODERATE** and scoped to the domain and IP strings I could search. The relationship between that public neighbor and this kit is NOT CHECKED.

## 2. Business Risk Assessment
{: .hl-tier-1}

The lure is aimed at people who play CS2 and may treat a FACEIT verification prompt as part of normal competitive play. Running the supplied command places their Steam account at risk; if an account were lost, its inventory and skins would be exposed as a general consequence of account access, not as a kit capability. Removing Steam Guard would weaken a key account protection if the malware completes that action. The available evidence establishes the kit's intended effects, not that any particular player lost an account or item.

My assessment is that the fake VAC-ban notice is meant to pressure a player to engage with the attacker-controlled flow while the account-focused code operates; the evidence shows the notice, not its purpose. The proxy and root-certificate capability would also put browser traffic on the affected Windows host at risk if enabled. Those host changes matter beyond the game client, so a confirmed infection warrants both account and endpoint scoping. No financial loss, affected population or completed browser interception has been established.

## 3. Delivery Chain and Technical Classification
{: .hl-tier-2}

The saved `newdouble` pages show a checkbox security check using Cloudflare imagery under FACEIT branding. Their page code writes a PowerShell command to the clipboard when the visitor clicks the checkbox, then directs the visitor to open Windows Run and paste it. The page cannot execute the command itself. This is a ClickFix delivery step that depends on a person running the pasted text.

The command fetches `/y/y.ps1` from `202.71.14.31` and runs the saved script. The script is a downloader and launcher that requests `/x/x.exe`, names the local copy `steamwebhelper.exe`, and attempts to keep it available through a Startup entry. The historical records associate the script with SHA-256 `dd29536b27649fa897d39198f3ec32d05215b9c6d2864acc32f51de648a25e25` and the executable with SHA-256 `1366b8ca7f315142ba9989241402758cf2a86e5568a28da0942e1810fe12c324`. The exact script bytes a visitor would have received at either Webamon scan time are NOT CHECKED: the cached URL content hash reflects a later analysis, while the file was first seen on September 25.

On September 29, 2026 the host exposed `http://202.71.14.31/y/` as an open directory listing one file, `y.ps1`, with that same SHA-256. So the script VirusTotal first saw on September 25 was still being served unchanged four days later. That brackets the September 26 scan but does not prove what its visitor received, and whether `/x/x.exe` is still served is NOT CHECKED.

Six saved Webamon reports across five domains share one link, which is only a favicon and proves little on its own. The page scripts are the stronger comparison: all six match after replacing their single payload URL. That supports reuse of a lure template, not a common operator. The four earlier reports cover [`faceitanticheat.com`](https://intel.webamon.com/report/18db694f-a11f-4298-8988-cf7fdec587db) on February 1, [`xplayduels.com`](https://intel.webamon.com/report/905d3450-5211-4478-bdb7-3b1e399cc9fd) on February 22 and [February 23](https://intel.webamon.com/report/237569af-66d4-417e-9df2-600c28ed0752), and [`faceitanticheat.support`](https://intel.webamon.com/report/d106ca91-1912-4344-9157-7eaa6d59bd54) on March 4, 2026.

One older URL has enough historical payload evidence to classify its chain. The script body recorded for `http://93.183.93.9/y/y.ps1` contacted `/x/qwe.exe` and an XMRig miner download, with miner configuration and a Monero pool lookup. It is a **different payload** from the Steam-focused `x.exe`; the page template and `/y/y.ps1` to `/x/*.exe` path convention are shared, and the two first-stage scripts also share host-side paths and persistence. The VirusTotal sandbox record for the February script shows it writing `%APPDATA%\MyApp\y.ps1`, staging under `Microsoft\Windows\Libraries\Cache\` and adding a Startup shortcut, and the September `y.ps1` source does the same (a sandbox observation on one side, script source on the other). That points to a shared script template, which is stronger kit evidence but still not operator evidence.

The dates matter here. The URL was first seen on February 21 and last analyzed on February 23, and the miner script itself was first seen on February 24, three weeks after the February 1 Webamon scan. Its exact bytes at that scan are NOT CHECKED. The URL also lists a second record named `y.ps1` from February 21 (SHA-256 `bf7d24c60ae4c71426036103d7138d89bcc86811e6ea69d737473513b63a8649`), an untyped stub whose type and content are NOT CHECKED.

Historical response bodies and second stages for `212.113.98.10/resources/12/y.ps1` and `185.209.30.61/y/y.ps1` were not obtained. A shared or copied kit remains as plausible as one operator, leaving operator linkage **INSUFFICIENT**.

## 4. Hosting and Campaign Scope
{: .hl-tier-2}

The four payload hosts are ordinary rented virtual servers, with plain HTTP URLs on raw IP addresses. The two `newdouble` pages point to `202.71.14.31`, in a block routed by Sollutium EU (AS43641) and sold under the `servers.guru` brand. The February `faceitanticheat.com` page points to `93.183.93.9`, and the March `faceitanticheat.support` page points to `185.209.30.61`; both are on VDSINA (AS48282). The February `xplayduels.com` pages point to `212.113.98.10`, on Nekobyte International (AS206134) under the IT-GARAGE VPS brand. Only `202.71.14.31` belongs to the September Steam kit chain; `93.183.93.9`, `212.113.98.10` and `185.209.30.61` are older payload hosts that used the same page template and path layout, with operator link INSUFFICIENT, and `93.183.93.9` served a different payload (a miner).

RIPE routing and registration records support these provider assignments across the observed campaign windows. They do not identify the customers who rented the servers.

The lure pages themselves sit behind Cloudflare, while their clipboard commands name the payload IPs directly. Cloudflare edge addresses are not the payload hosts and do not identify an origin or operator. The repeated VDSINA provider, default Apache banners on two hosts and shared page paths are weak identity clues because many customers can rent the same service or copy a kit. Later gambling domains seen on `93.183.93.9` and older names seen on the other servers are excluded from this campaign, with one exception: `wt.seudad.ru` appeared on `212.113.98.10` on 2026-03-22, inside the window, and is an unchecked in-window hostname (NOT CHECKED). A VPS address can be reassigned between tenants.

The certificates change nothing either. For the campaign period, public certificate-transparency logs for four of the five lure domains hold only Cloudflare's own Universal SSL certificates (older certificates on `faceitanticheat.com` belong to earlier owners of the name), so there is no operator-chosen certificate to pivot on; the logs for `newdouble-authentification.com` could not be read and are NOT CHECKED.

No evidence here establishes bulletproof hosting. The one thing that has moved is time. On September 29, 2026, `202.71.14.31` was still up and serving the same `y.ps1` from an open directory at `/y/`, at least 34 days after the first `newdouble` lure scan on August 26. On the same day `faceitanticheat.com` and `faceitanticheat.support` no longer resolved, while `xplayduels.com` and both `newdouble` domains still resolved through Cloudflare; what those pages serve now is NOT CHECKED. No open directory was found on the campaign paths of the other three payload hosts, which does not mean they are down, so their liveness stays **NOT CHECKED**.

That continuity strengthens the link between the two `newdouble` pages and their one payload host over time. It does not touch the February to September question. No new host came out of these checks, so there was nothing new to grade, and a shared template or hoster is still not an operator link. Operator linkage across the older chains stays **INSUFFICIENT**. Historical port, TLS-fingerprint and co-hosting records for the four payload hosts, the kind of pivot most likely to surface a new host, are NOT CHECKED.

## 5. Capabilities and Defender Observables
{: .hl-tier-2}

The Steam-focused executable is designed to capture sign-in material and session access, and remove Steam Guard protections. I assess at **HIGH** that it is built to capture Steam sign-in material on the host and that it contains account-protection removal code. That it forwards the captured material to a remote panel, the step a takeover by someone else needs, I rate **MODERATE**: the code that sends account material to a panel exists, but the path from capture to that sender was not traced. Successful takeover or removal on a victim account is **INSUFFICIENT** without a runtime or incident record. A defender can look for unexpected changes to Steam account protection, session state and the `Accounts` entry in Steam's `config.vdf`, while treating those traces as hunting leads until validated against normal client behavior.

The kit carries a fake VAC-ban screen aimed at the player. That screen is a lure and an observable change to the Steam-facing experience, not evidence that Valve imposed a ban. It also carries an in-game CS2 module built to be placed into the game process (**HIGH** for code presence). Its names and text fit a module that makes the game show a fake VAC ban or matchmaking penalty, the same story as the Steam-side screen, at **LOW** to **MODERATE**; this is a proposed reading that rests on names alone, the direction of the hooks is not established, and nothing shows it gives the player any gameplay advantage. A defender may see a process that is not a known game or anti-cheat component opening `cs2.exe`; the executable's signing status is a provisional triage result, and whether the module reached a victim game process is NOT CHECKED.

The executable contains code to install a root certificate and change browser traffic routing through proxy and PAC settings. On an affected host, a new root-store certificate and changes to `ProxyEnable`, `ProxyServer` or `AutoConfigURL` under Internet Settings would be useful leads. The certificate's source and thumbprint, and the values written to the proxy or PAC settings, are **NOT CHECKED**. The strings referring to `mitmproxy` do not by themselves prove which certificate was installed. The payload also references a kernel driver, and whether that driver was loaded was not confirmed.

A panel API exists in the executable, which supports an operator-control purpose at **MODERATE** confidence. The external panel address and successful delivery of account material to it are **NOT CHECKED**. The report does not treat ordinary Steam sites, a loopback address or unexplained sandbox contacts as that panel.

## 6. Static and Behavioral Findings
{: .hl-tier-3}

The hash-matched `y.ps1` source expresses a download from `/x/x.exe`, an attempted launch, a Startup entry and changes meant to weaken Windows defenses. Those instructions support **HIGH** confidence in what the script is designed to do. They do not prove that elevation, defense changes, the download or persistence succeeded on a player's machine. A historical sandbox record supports one request from the script to `/x/x.exe`; a separate three-page sandbox report lists the URL but does not show an HTTP transaction.

The hash-matched `x.exe` contains Steam account and Guard handling, the fake VAC-ban content, certificate and proxy changes, a panel API and a bundled CS2 module. I treat these as built-in capabilities rather than completed victim effects. The evidence does not include a Steam-equipped execution trace of the executable or a confirmed affected account. The difference between capability and outcome is material here: neither an antivirus label nor a readable string is a victim record.

## 7. MITRE ATT&CK Mapping
{: .hl-tier-2}

These mappings describe the saved lure and the recovered script, not completed actions on a victim host. The technique names and IDs follow the current [MITRE ATT&CK catalog](https://attack.mitre.org/).

| Tactic / Technique | Name | Conf. | Evidence |
|---|---|---|---|
| Execution / [T1204.004](https://attack.mitre.org/techniques/T1204/004/) | Malicious Copy and Paste | HIGH | Fake verification page supplies a command for Windows Run |
| Execution / [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | HIGH | Saved command and hash-matched `y.ps1` source |
| Persistence / [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder | HIGH | Script attempts a Startup shortcut or fallback copy |
| Defense Impairment / [T1685](https://attack.mitre.org/techniques/T1685/) | Disable or Modify Tools | HIGH | Script requests broad Defender exclusions and an AMSI bypass |

## 8. Indicators of Compromise
{: .hl-tier-2}

The machine-readable [IOC feed]({{ "/ioc-feeds/newdouble-clickfix-iocs.json" | relative_url }}) is maintained separately. Its two `newdouble` domains, the raw-IP delivery URLs and the script and executable hashes represent historical observations. They should be matched to the dated lure and file records in this report. The exception is `http://202.71.14.31/y/y.ps1`, still served on September 29, 2026 from the open directory `http://202.71.14.31/y/`; no other URL is established as still active. `faceitanticheat.com` and `faceitanticheat.support` no longer resolved on that date and are historical.

The older `93.183.93.9` miner chain is a different payload and belongs in a historical template comparison, not in the Steam kit's blocklist. The other two older script URLs have no recovered response bodies. Cloudflare edge IPs, the shared favicon, ordinary Steam web destinations and the executable's loopback address are also unsuitable as standalone malicious indicators.

## 9. Detection and Hunting Guidance
{: .hl-tier-2}

The [IOC feed]({{ "/ioc-feeds/newdouble-clickfix-iocs.json" | relative_url }}) contains the historical domains, delivery URLs and file hashes, and the [detection package]({{ "/hunting-detections/newdouble-clickfix-detections/" | relative_url }}) holds the YARA, Sigma and Suricata rules. The following are hunting leads from the recovered script and executable, not claims of observed victim activity or validated alert rules.

Search process and network telemetry for PowerShell launched from the Windows Run flow with a command that downloads a `.ps1` file and then runs that file. The saved pages put `http://202.71.14.31/y/y.ps1` in that flow, and the recovered script requests `http://202.71.14.31/x/x.exe`. Pair a URL hit with process execution and file creation on the same host. The exact addresses are historical and can change without changing the delivery pattern.

On a host with a matching script or executable, look for `%APPDATA%\MyApp\y.ps1`, `%APPDATA%\MyApp\y.dat`, a `steamwebhelper.exe` copy under `%APPDATA%\Microsoft\Windows\Libraries\Cache\`, or a Startup entry. These paths come from the script's intended behavior; their presence on a victim host is NOT CHECKED. Hunt for broad Defender exclusions only with surrounding process and timing context, because the action alone does not identify this kit.

For the executable stage, correlate changes to Steam's `config.vdf` `Accounts` entry with a new root-store certificate and changes to `ProxyEnable`, `ProxyServer` or `AutoConfigURL` under Internet Settings. The executable also contains Steam CEF debugging and `cs2.exe` access capabilities. A certificate subject containing `mitmproxy`, an unexpected process opening `cs2.exe`, or a proxy change by itself is a lead to investigate, not proof of this infection. The certificate thumbprint, its source and the proxy values are NOT CHECKED, so exact-match rules for them would be premature.

Where a match suggests execution, preserve the relevant process, file, certificate, proxy and Steam account-change evidence before scoping affected accounts and sessions. The priority is to establish whether the command ran, whether the Steam protection changes completed and whether account access was lost. No panel address is available for a network rule, and the local callback address is not an external indicator.

## 10. Recommendations
{: .hl-tier-1}

Treat a FACEIT-branded page that asks a player to paste a command into Windows Run as an execution risk. For prevention, make the legitimate account-verification path clear to players and restrict untrusted script execution where practical. The saved pages depend on the player running the command; visiting the page alone does not establish infection.

For suspected execution, use the historical delivery indicators to find the initiating host, then check for the script, executable, Startup entry and Steam or browser-setting changes described in Section 9. If those changes are confirmed, contain the host, preserve evidence, review Steam account sessions and protection state, and coordinate account recovery with the affected player. A block on the listed IP or domains covers the observed delivery path but cannot cover a copied page or a changed server.

Prioritize behavior-based hunting around the download-and-run command and the combination of Steam account changes with certificate and proxy changes. Validate candidate alerts against legitimate administrative scripts, Steam updates and normal proxy management before treating a single match as a case.

## 11. Threat Actor Assessment
{: .hl-tier-2}

I cannot attribute this activity to a named actor. Attribution is **INSUFFICIENT**, below 50 percent. The available pages, payload URLs and file evidence identify an operation aimed at CS2 players, but they do not identify who controlled the domains, rented the servers or received account material. There is no authenticated operator account, private configuration or distinctive shared build artifact that would support a named-actor claim. I assign no UTA designation.

The six saved pages reuse a lure template after their payload URLs are changed. That supports template reuse, not a single operator. The `93.183.93.9` script URL served a Monero miner chain at its February 23 analysis (the URL also lists a second record named `y.ps1`, dated February 21, an untyped stub `bf7d24c6` whose type and content are NOT CHECKED), while the `202.71.14.31` chain points to an executable built for Steam account theft. A copied or shared kit and one operator using both remain unresolved alternatives. Shared ordinary hosting and path conventions do not settle them.

The closest public account, relayed on August 25, 2026, describes Steam client debugging abuse, a mitmproxy root certificate, local proxy redirection and a fake suspension notice, and its four published scripts were first seen August 17 to 22, days before the earliest `newdouble` page; VirusTotal associates two of them with FACEIT-named domains in the wild. That account rests on a forum relay of a social media post I did not read. None of its six published IOCs matches this kit. Two overlapping dropped-file hashes are generic sandbox residue and do not link the operations. A comparison of operator-only configuration, authenticated panel control or distinctive payload bytes across the chains would change this assessment. Until then, the operator identity and the relationship to the older template chains remain **INSUFFICIENT**, and the relationship to the public neighbor is NOT CHECKED.

## 12. Confidence Summary and Evidence Gaps
{: .hl-tier-2}

| Finding | Confidence | What would change it |
|---|---|---|
| The two saved `newdouble` pages supplied a command naming `/y/y.ps1` on `202.71.14.31` | DEFINITE for the saved pages | A contradictory raw page export would require correction |
| `202.71.14.31` still served the same `y.ps1` on September 29, 2026 | HIGH, observed that day | A later fetch returning different bytes would change the current state, not the historical match |
| The recovered script is designed to obtain `/x/x.exe`, launch it and add persistence | HIGH for intended behavior | A complete host trace would show which steps succeed |
| The executable contains Steam sign-in capture, Guard removal, fake VAC-ban, certificate, proxy and in-game CS2 module capabilities | HIGH for code presence | A contained run would establish which effects occur |
| The executable forwards captured account material to a remote panel | MODERATE | Tracing capture to sender, or a contained run reaching a panel, would raise it |
| The CS2 module's purpose is a fake in-game ban or penalty display (a proposed reading; hook direction not established) | LOW to MODERATE, from names only | Reading the module's hooked functions would confirm or overturn it |
| The `newdouble` domains and `202.71.14.31` were absent from the bounded public coverage found (hash search and URLhaus NOT CHECKED) | MODERATE novelty | A dated public report matching this kit or its indicators would lower it |
| The same operator ran the older miner and recent Steam chains | INSUFFICIENT | Operator-only configuration or authenticated control spanning both would raise it |

The gap that matters most to a player is between the executable's capability and a completed theft. I can identify the command, script and an executable built for Steam account theft, but I cannot identify a victim account or a successful Guard removal. The two `newdouble` pages are dated snapshots. Their saved command is solid evidence of the lure, while the exact script bytes served at each page's scan time are NOT CHECKED.

### What is missing

- No player execution, account takeover, CS2 module placement or browser interception is confirmed. A consented incident record or contained runtime trace would establish which actions completed.
- The cached script hash does not prove which bytes either saved page served at its scan time. The script URL was live on September 29, 2026, but the executable URL, the lure pages' current content and the other three payload hosts are NOT CHECKED. Timestamped response bodies and hashes would resolve each question.
- Historical port, TLS-fingerprint and co-hosting records for the four payload hosts are NOT CHECKED. They could surface a host that ties the chains together or separates them.
- The February `93.183.93.9` miner response was first seen after the earliest saved page, so its bytes at that scan are NOT CHECKED. Two other older script response bodies and their second stages were not obtained. Dated response bodies and second-stage hashes would delimit template and payload reuse.
- The panel address, its runtime source and successful data delivery are NOT CHECKED. A contained network trace tied to the executable would establish the destination and any transfer.
- The root-certificate source and thumbprint, the proxy and PAC values, and the driver load path are NOT CHECKED. A host trace with certificate and settings records would settle the written values and whether the actions succeeded.
- No operator-only artifact links the chains or the closest public neighbor. The public coverage search was bounded and did not establish first discovery: web search failed a control test on an exact file hash, so a bare-hash negative is NOT CHECKED, and URLhaus could not be read for the four IPs I searched. Search also does not reach sandbox pages, private feeds or closed channels. A distinctive cross-chain artifact or a matching dated publication would revise those judgments.

### The source base

The strongest evidence is the saved page code, the hash-matched script and executable, and the historical response records that connect the delivery paths. The main source weakness is time: a cached URL body can postdate a saved lure, so I do not project its bytes backward to every scan. Public reporting establishes nearby FACEIT abuse and Steam account theft behavior, but no independent source confirms this kit's victim outcomes or operator identity. The older payload URL named on the February 1 page served a miner chain in records dated February 23 to 24, 2026 (a February 21 record of the same name is an untyped stub, NOT CHECKED), so the six pages cannot all be assumed to have led to the same payload; I follow that recovered body for that narrow historical chain.

## 13. References
{: .hl-tier-2}

- Webamon saved reports: [`newdoubleauthentification.com`, August 26, 2026](https://intel.webamon.com/report/4298d731-f038-458a-8b67-f6d6497e5e84); [`newdouble-authentification.com`, September 26, 2026](https://intel.webamon.com/report/92202cbe-dbfe-4124-8883-2907424b4ed4). These are historical page records, not live-site checks.
- Webamon older template records: [`faceitanticheat.com`, February 1](https://intel.webamon.com/report/18db694f-a11f-4298-8988-cf7fdec587db); [`xplayduels.com`, February 22](https://intel.webamon.com/report/905d3450-5211-4478-bdb7-3b1e399cc9fd) and [February 23](https://intel.webamon.com/report/237569af-66d4-417e-9df2-600c28ed0752); [`faceitanticheat.support`, March 4](https://intel.webamon.com/report/d106ca91-1912-4344-9157-7eaa6d59bd54). Their shared page form does not establish a shared payload or operator.
- Prior public context: [Malwarebytes on FACEIT-themed Steam phishing](https://www.malwarebytes.com/blog/threat-intel/2026/06/fake-verification-pages-are-stealing-steam-accounts-from-players); [Kaspersky on gamer ClickFix leading to a miner](https://www.kaspersky.com.au/blog/steam-forum-clickfix-attack-irm-iex/36479/); [MalwareTips discussion of a Steam CEF and proxy stealer](https://malwaretips.com/threads/steam-session-hijacking-malware-via-mitm-proxy-and-cef-debugger-abuse.142938/). These describe neighboring activity, not this campaign; the MalwareTips thread relays a researcher post that was not independently read.
- Context on Steam account theft, attacks on gamers and ClickFix prevalence: [Valve, "Security and Trading" (December 2015)](https://store.steampowered.com/news/19618/); [Kaspersky, 2025 gaming attack figures (November 2025)](https://www.kaspersky.com/about/press-releases/kaspersky-reports-64-million-shopping-phishing-attempts-and-over-20-million-gaming-attacks-detected-in-2025); [SECUINFRA on Vidar via the Steam store (2025)](https://www.secuinfra.com/en/techtalk/infostealer-malware-vidar-spread-via-the-steam-store/); [G DATA on BlockBlasters (2025)](https://blog.gdatasoftware.com/2025/09/38265-steam-blockblasters-game-downloads-malware); [ESET Threat Report H1 2026](https://www.welivesecurity.com/en/eset-research/eset-threat-report-h1-2026/); [ReliaQuest, March to May 2026](https://reliaquest.com/blog/threat-spotlight-whats-trending-top-cyber-attacker-techniques-march-may-2026/); Microsoft Digital Defense Report 2025. Each figure is that vendor's own telemetry and describes the wider ecosystem, not this operator.
- VirusTotal file and URL records for the script, executable and older payload URLs listed in Section 3, and RIPE routing and registration records for the payload IPs listed in Section 4.

---

© 2026 Joseph, The Hunters Ledger. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), free to republish and adapt, including commercially, with attribution to The Hunters Ledger and a link to the original.
