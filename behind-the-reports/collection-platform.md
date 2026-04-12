---
title: "How Threats Are Found: The Collection Platform"
date: '2026-04-12'
layout: page
permalink: /behind-the-reports/collection-platform/
hide: true
---

<div class="hl-page-header" style="border-left-color: #f97316;">
  <div class="hl-page-header__label" style="color: #f97316;">Behind the Reports</div>
  <div class="hl-page-header__title">How Threats Are Found</div>
  <div class="hl-page-header__desc">The collection platform that discovers malware on adversary infrastructure — what it does, why it exists, and how it works.</div>
</div>

<div class="hl-note" style="margin-bottom: 2rem;">
  <div class="hl-note__label">Part 1 of 2</div>
  <div class="hl-note__body">This page covers how threats are found. For how findings become finished intelligence, see <a href="{{ '/behind-the-reports/ai-workflow/' | relative_url }}">How Reports Are Made</a>.</div>
</div>

## The Problem

Before I can analyze malware, write detection rules, or publish a report, I need to find the malware in the first place. That sounds obvious, but the logistics are harder than they appear.

Commercial internet scanning services map the entire IPv4 address space and surface what they find, but professional-tier access is priced for enterprise security teams — not independent research. More fundamentally, they're general-purpose reconnaissance tools: broad visibility across the whole internet, optimized for asset discovery and attack surface management rather than persistent monitoring of the specific hostile infrastructure that threat actors actually use. The data is filtered through someone else's priorities and collection model.

Open-source threat intelligence feeds exist but tend to be reactive — they publish indicators for threats that have already been deployed, detected, and catalogued by someone else. By the time something shows up in a public feed, the window for early warning has often closed. A server hosting novel malware today may be wiped clean, repurposed, or rotated to a new IP range before any feed indexes it.

What I wanted was something different: continuous, focused visibility into the specific infrastructure where malware actually lives. Not the whole internet — just the parts that matter most. The bulletproof hosting providers, the sanctioned networks, the abuse-tolerant datacenters where threat actors stage and distribute payloads with minimal risk of takedown.

So I built a platform to do exactly that.

---

## What It Looks For

Two concepts are central to understanding what this platform does: **open directories** and **bulletproof hosting**.

### Open Directories

An open directory is a web server where the file listing is exposed. Instead of a website, you see a raw index of folders and files — like browsing a shared network drive. Threat actors use these as cheap, disposable staging infrastructure. A typical open directory might contain a remote access trojan (RAT) builder, a credential stealer, a batch of phishing kits, and a folder of stolen credentials — all sitting on a bare IP address with no domain name, no authentication, and no attempt to hide any of it.

These directories are valuable to threat intelligence because they expose an attacker's full operational toolkit in one place. A single directory can reveal which malware families are being deployed together, what configuration files they use, what credentials they've already stolen, and sometimes even their build tools and operational notes. It's the kind of access that normally requires a law enforcement operation or an insider compromise — except the attacker left the front door open.

The challenge is that open directories are ephemeral. A server hosting a stealer today may be wiped and repurposed tomorrow. Catching them requires continuous scanning, not periodic checks.

### Bulletproof Hosting

Bulletproof hosting (BPH) providers are companies that knowingly host malicious content and ignore or refuse abuse complaints. Some are formally sanctioned by governments — the U.S. Treasury's OFAC, the UK, Australia. Some operate in jurisdictions that make enforcement effectively impossible. Some simply don't respond when security researchers or law enforcement report malware on their networks.

These providers are where a disproportionate share of malware infrastructure lives. Not all of it — threat actors also abuse legitimate cloud providers — but BPH networks have the highest signal-to-noise ratio for this kind of collection. If you scan a bulletproof hoster and find an open directory, the odds that it contains something malicious are very high. If you scan a mainstream cloud provider, you're mostly finding legitimate file servers, personal projects, and misconfigured development environments.

The platform currently monitors **65 autonomous systems** — the network-level identifier for a hosting provider — selected through documented threat intelligence sources: government sanctions lists, established threat intelligence feeds, published cybercrime infrastructure research, and quarterly rankings from cybercrime tracking organizations. Each target is annotated with the specific source that justified its inclusion and the malware families that have been observed operating there, creating an auditable record of why every target was selected.

---

## How It Finds Things

The platform uses three independent discovery methods that run continuously. Each one catches threats the others would miss, and together they provide overlapping coverage of the target infrastructure.

### Nightly Port Scanning

The primary discovery engine. Every night during a configurable window — currently 2 AM to 7 AM local time, when household network activity is at its lowest — the platform scans the announced IP space of all 65 target autonomous systems across 28 ports commonly used for web services.

To understand the scale: those 65 networks contain roughly 13.8 million IP addresses. Scanning all of them across 28 ports means probing hundreds of millions of address-port combinations. On consumer hardware and a residential internet connection, that's too much to complete in a single night.

So the scan is organized into **priority batches**. Small, dedicated bulletproof hosting providers — the ones where nearly everything hosted is malicious — are grouped into a single batch and scanned first. These are the networks with the highest signal-to-noise ratio, and they typically finish in 2–3 hours. Larger, legitimate-but-abused providers run as separate batches afterward, filling whatever time remains.

A hard cutoff stops scanning 5 minutes before the window closes, regardless of progress. This guarantees zero network impact during daytime hours when other people in the house need the connection. Coverage metrics log exactly which providers were scanned, which were deferred, and what percentage of the target space was reached — data that shows empirically how the tool is performing and where adjustments might be needed.

Every discovered web server is immediately probed for open directory signatures. Confirmed open directories are queued for full crawling at the highest processing priority.

### BGP Monitoring

Bulletproof hosting providers frequently rotate their infrastructure, announcing new IP ranges and withdrawing old ones as they move operations between network blocks. The platform polls global routing databases every 30 minutes for prefix changes across all 65 target networks.

When a new IP range appears — typically a /24, which is 256 addresses — the platform triggers an immediate targeted scan of that space. This catches new infrastructure the moment it comes online, hours or sometimes days before the next scheduled nightly sweep would reach it.

This is particularly valuable for catching short-lived infrastructure that's spun up for a campaign and torn down before the next nightly scan runs.

### Certificate Transparency Monitoring

When someone registers an SSL certificate (the "https" padlock on a website), that registration is recorded in public Certificate Transparency (CT) logs — append-only public records designed to make certificate issuance auditable. The platform monitors nine active CT logs in real time, watching for certificates issued to domains that match suspicious patterns: high-entropy hostnames (random-looking strings that suggest automated generation), known-abused top-level domains (.top, .xyz, .tk), and phishing-related keywords.

When a suspicious certificate is detected, the associated domain is resolved to an IP address. If that IP falls within any of the 65 target networks, the domain gets priority boosting and is queued ahead of normal CT traffic. This catches domain-fronted malware staging that wouldn't appear in IP-only scanning — a threat actor might register a domain, point it at their bulletproof hosting server, and use it for a few hours before abandoning it. The CT log captures the certificate the moment it's issued.

### How They Work Together

All three discovery sources feed into a single priority queue. The crawling engine processes them in order of expected value:

| Priority | Source | Rationale |
|---|---|---|
| Highest | Port scan / BGP | Confirmed BPH infrastructure — almost certainly hosting malware |
| High | CT domain on target network | Suspicious domain on known-bad infrastructure — elevated signal |
| Normal | CT domain (general) | May or may not be malicious — routine processing |
| Lowest | Scheduled recrawl | Re-checking a known directory — only if workers are idle |

This ensures the most valuable discoveries are always processed first, regardless of how busy the system is.

---

## What Happens After Discovery

### Crawling and File Classification

When the platform confirms an open directory, a pool of 50 persistent crawl workers walks the full directory structure — following links, checking subdirectories, and cataloguing every file. Each file is evaluated through multiple classifiers:

**Extension filtering** narrows focus to 46 malware-relevant file types: Windows executables (.exe, .dll, .sys), scripts (PowerShell, batch, VBScript, JavaScript), Office documents with macro capability, archives (.zip, .rar, .7z), and Mark-of-the-Web bypass containers (.iso, .img, .vhd) — the disk image formats attackers increasingly use to evade Windows security prompts that would normally warn users about files downloaded from the internet.

**Credential detection** runs independently of file type. The platform checks filenames against 50+ patterns that indicate exposed credentials: environment files (.env), SSH private keys, browser credential databases, stealer log archives, combo lists (username/password dumps), cloud access keys, WordPress configurations, and Windows registry hives. A 400-byte .env file with database credentials sitting on a threat actor's staging server is exactly the kind of finding this platform is built to surface.

**Size filtering** keeps files between 1 KB and 50 MB — small enough to exclude empty placeholders, large enough to include most payloads. Credential files bypass size filtering entirely, because their value is independent of file size.

### Multi-Engine Reputation Enrichment

Every file the platform finds needs context. Is this a known piece of malware? Is it something new? Is the security industry already aware of it?

A multi-engine file reputation service answers those questions — scanning each file against dozens of antivirus and threat detection engines and reporting how many flag it as malicious. The platform operates within a daily API quota. That's a real constraint, so every lookup has to count.

A **two-tier extension system** manages this budget. Tier 1 includes 17 high-signal extensions — executables, DLLs, scripts, disk images — that get immediate lookup when found on confirmed BPH infrastructure. These are the files most likely to be malware, and they consume API quota first. Tier 2 covers 29 lower-priority extensions — archives, Office documents, less common formats — that queue for lookup when daily quota allows.

Files discovered through lower-confidence sources (Certificate Transparency logs rather than direct infrastructure scanning) are deprioritized further. This prevents noise from consuming quota that should go to confirmed BPH discoveries.

Each enrichment response classifies the file into a priority tier:

| Priority | Criteria | What It Means |
|---|---|---|
| **NOVEL** | 0 detections | Unknown to the security industry — potentially unreported malware |
| **LOW_DETECT** | 1–3 detections | Evasive — bypassing most antivirus engines |
| **KNOWN_BAD** | 20+ detections | Well-known malware — useful for tracking active campaigns |
| **SKIP** | 4–19 detections | Detected by enough engines — lower research value |

**NOVEL** and **LOW_DETECT** files are the highest-value findings. These represent malware that the broader security industry hasn't catalogued yet — the kind of early warning that threat intelligence consumers need most.

---

## The Triage Dashboard

The platform surfaces everything it finds through a dark-themed analyst dashboard. This is where automated collection ends and human judgment takes over — the platform finds and organizes, I decide what's worth investigating.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/behind-the-reports/opendir-hunter-dashboard.png" | relative_url }}" alt="OpenDir Hunter dashboard showing the main triage view with severity-tiered directory cards (6 HIGH, 5 MEDIUM, 45 LOW), workflow status filters, global statistics bar displaying 74,492 total directories and 27 novel detections, a global search bar with database and live scan modes, and the high-priority hosts table listing active hosts with file counts and last activity timestamps">
  <figcaption><em>Figure 1: The main dashboard view — severity-tiered directory counts at top, global statistics and search in the middle, and the high-priority hosts table showing hosts with novel or low-detection files awaiting triage.</em></figcaption>
</figure>

### Tiered Host View

The home page organizes all discovered hosts into severity tiers based on their highest-signal files:

- **HIGH** — Hosts with NOVEL files (zero detections across the engine fleet) in untriaged directories
- **MEDIUM** — Confirmed BPH infrastructure with low-detection payloads, or files still awaiting enrichment
- **LOW** — Certificate Transparency-sourced hosts where enrichment hasn't completed yet
- **CREDENTIALS** — A cross-cutting view showing any host with exposed credential files, regardless of tier

I work top-down: high-tier hosts first, then medium, then low as time allows. Each host card shows a count of interesting files, credential indicators, and current triage status.

### Host Deep-Dive

Clicking into a host shows the full picture: a directory tree visualization showing every path the crawler found, with file counts and status indicators per directory. A master file table lists every file across all directories, priority-sorted, with columns for filename, extension, detection score, threat family label, download status, credential indicators, and source directory.

Bulk actions let me move fast. Set all directories on a host to a workflow status in one click. Download all interesting files as a priority-sorted ZIP. Reset download tracking for re-investigation.

### Download Manager

Files download as password-protected ZIPs, sorted by analysis value: executables and DLLs first (highest priority for reverse engineering), scripts second (stagers and droppers), everything else third. A checkmark tracks what's already been downloaded so I can work in batches — download a set, transfer to the malware analysis VM, analyze, clear the VM, download the next batch.

### Manual Scanner

The search bar accepts any indicator format — bare IP, domain, URL, or host:port — and offers two modes. **Database search** runs a substring match across everything already indexed. **Live scan** probes the target with the same detection engine the automated scanners use, persists any findings to the database, and triggers background reputation enrichment. This is how I investigate tips from other tools, colleagues, or community reporting — check if the platform already has it, or scan it live and add it.

### System Health

A dedicated health page shows real-time status of all six services (running state, uptime, last log line), VPN tunnel health (public IP, handshake recency, route verification), port scanner sweep progress and coverage metrics, and 30-day trend graphs for directories discovered, novel files, low-detection files, credential files, and confirmed malicious files. Service restart and VPN profile rotation controls are available directly from the dashboard.

---

## Why It's Built This Way

Every design decision reflects the same constraint: this is a solo research operation running on a single repurposed tower server with a consumer internet connection.

**Focused scope instead of broad scanning.** I can't scan the entire IPv4 address space — I don't have the bandwidth, the hardware, or the IP reputation. Instead, the platform concentrates on 65 autonomous systems where malware actually lives. This trades breadth for depth: I can't see everything, but I can see the infrastructure that matters most with enough frequency to catch servers that rotate quickly.

**SQLite instead of a database server.** The entire data layer is a single SQLite file. No external database server to install and maintain, no separate cache layer to manage, no additional credentials to secure. It handles concurrent access from 50+ crawl workers without contention, and the entire database can be backed up by copying one file.

**Night-only scanning with a hard cutoff.** The platform shares a home network with other people. Scanning at 10,000 packets per second during the day would noticeably degrade internet for everyone in the house. The nightly scan window, priority batch ordering, and hard cutoff before morning ensure the scanning never impacts normal usage — and coverage logs show exactly what was and wasn't reached each night.

**VPN tunnel with a kill switch.** All scanner traffic routes through an encrypted VPN tunnel with a firewall rule that blocks all traffic if the tunnel drops. My home IP never appears in target server logs. An hourly watchdog verifies tunnel health and auto-restarts on failure. VPN profiles are rotatable from the dashboard for IP diversity.

**Free-tier reputation enrichment with intelligent rationing.** The daily API quota is a real constraint, but the two-tier extension system and source-based prioritization ensure the highest-value files always get enrichment first. On a typical day, every Tier 1 file from BPH infrastructure is checked within hours of discovery. Tier 2 files catch up gradually over the following days.

**Per-host connection throttling.** A semaphore limits concurrent connections to any single target, with optional per-request delay. This prevents triggering web application firewalls or generating abuse complaints — it keeps the scanning polite, even when scanning infrastructure operated by people who don't extend the same courtesy.

---

## What It Produces

The platform is the first stage of a larger pipeline. What it finds feeds directly into the analysis and reporting workflow described in [How Reports Are Made]({{ '/behind-the-reports/ai-workflow/' | relative_url }}).

**Novel malware samples.** Files with zero detections across the engine fleet — payloads the security industry hasn't catalogued yet. Early discovery means detection rules can be written and shared before the malware is widely deployed.

**Low-detection payloads.** Malware evading most antivirus engines. The gap between "detected by 1 engine" and "detected by 40 engines" is where defenders are most exposed and where early intelligence has the most impact.

**Campaign infrastructure mapping.** A single open directory often hosts multiple malware families, phishing kits, and command-and-control panel artifacts side by side. Indexing the full directory structure reveals operational relationships between tools, campaigns, and actors that wouldn't be visible from a single indicator alone.

**Credential exposure.** Stealer logs, combo lists, and configuration files with embedded credentials found on staging servers. These provide early warning of compromised credentials before they're traded on underground forums or pasted publicly.

**Continuous temporal coverage.** Because the platform runs every night, it tracks how infrastructure changes over time — which servers are active, which have been torn down, which are being repurposed with new payloads. That temporal dimension is something periodic manual hunting can't replicate, and it adds context that makes individual findings more meaningful.

---

The platform doesn't try to scan the whole internet, and it doesn't try to replace commercial tools that do. It does one thing well: persistent, focused monitoring of the infrastructure where malware lives, designed to be sustained indefinitely by a single researcher with commodity hardware. The samples and intelligence it surfaces are what start the investigation pipeline — each report published on this site begins with something this platform found.

---

*Collection platform is built and operated by Joseph as part of The Hunter's Ledger research infrastructure.*