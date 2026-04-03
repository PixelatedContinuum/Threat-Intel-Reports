---
title: IOC Feeds
layout: page
permalink: /ioc-feeds/
position: 4
---

<div class="hl-page-header" style="border-left-color: #f87171;">
  <div class="hl-page-header__label" style="color: #f87171;">IOC Feeds</div>
  <div class="hl-page-header__title">Indicators of Compromise</div>
  <div class="hl-page-header__desc">Structured feeds ready for ingestion into your SIEM, EDR, or CTI platform. Licensed under <strong>CC BY-NC 4.0</strong>.</div>
</div>

{% include section-header.html label="Recent" accent="#f87171" %}

<div class="hl-grid">
{% include report-card.html title="Open Directory at 193.56.255.154 — XiebroC2 and Covenant C2 IOC Feed" date="Apr 2026" severity="high" tags="C2,Multi-Family,Open Dir" url="/ioc-feeds/opendirectory-193-56-255-154-20260403-iocs.json" %}
{% include report-card.html title="ZeroTrace Multi-Family MaaS Operation — IOC Feed" date="Mar 2026" severity="high" tags="MaaS,Multi-Family,C2" url="/ioc-feeds/opendirectory-74-0-42-25-20260316-iocs.json" %}
{% include report-card.html title="Sliver C2 / ScareCrow Loader Open Directory — IOC Feed" date="Mar 2026" severity="high" tags="C2,Loader,Go" url="/ioc-feeds/sliver-open-directory-iocs.json" %}
{% include report-card.html title="Webserver Compromise Kit 91.236.230.250 — IOC Feed" date="Feb 2026" severity="high" tags="Toolkit,Priv Esc,RCE" url="/ioc-feeds/webserver-compromise-kit-91-236-230-250-iocs.json" %}
</div>

{% include section-header.html label="All Feeds" accent="#444444" %}

<div class="hl-row-list">
{% include report-row.html title="Remcos RAT OpenDirectory Campaign — IOC Feed" date="Feb 2026" severity="med" tags="RAT,Cred Theft" url="/ioc-feeds/remcos-opendirectory-campaign.json" %}
{% include report-row.html title="NsMiner Cryptojacker — IOC Feed" date="Feb 2026" severity="med" tags="Cryptominer,Dropper" url="/ioc-feeds/nsminer-cryptojacker.json" %}
{% include report-row.html title="Arsenal-237 New Files: full_test_enc.exe — IOC Feed" date="Jan 2026" severity="high" tags="Ransomware,Rust" url="/ioc-feeds/arsenal-237-full_test_enc-exe.json" %}
{% include report-row.html title="Arsenal-237 New Files: new_enc.exe — IOC Feed" date="Jan 2026" severity="high" tags="Ransomware,Rust" url="/ioc-feeds/arsenal-237-new_enc-exe.json" %}
{% include report-row.html title="Arsenal-237 New Files: dec_fixed.exe — IOC Feed" date="Jan 2026" severity="high" tags="Ransomware,Rust" url="/ioc-feeds/arsenal-237-dec_fixed-exe.json" %}
{% include report-row.html title="Arsenal-237 New Files: enc_c2.exe — IOC Feed" date="Jan 2026" severity="high" tags="Ransomware,C2" url="/ioc-feeds/arsenal-237-enc_c2-exe.json" %}
{% include report-row.html title="Arsenal-237 New Files: chromelevator.exe — IOC Feed" date="Jan 2026" severity="high" tags="Cred Theft,.NET" url="/ioc-feeds/arsenal-237-chromelevator-exe.json" %}
{% include report-row.html title="Arsenal-237 New Files: nethost.dll — IOC Feed" date="Jan 2026" severity="high" tags="DLL Hijack,Persistence" url="/ioc-feeds/arsenal-237-nethost-dll.json" %}
{% include report-row.html title="Arsenal-237 New Files: rootkit.dll — IOC Feed" date="Jan 2026" severity="high" tags="Rootkit,Evasion" url="/ioc-feeds/arsenal-237-rootkit-dll.json" %}
{% include report-row.html title="Arsenal-237 New Files: BdApiUtil64.sys — IOC Feed" date="Jan 2026" severity="high" tags="BYOVD,Priv Esc" url="/ioc-feeds/arsenal-237-BdApiUtil64-sys.json" %}
{% include report-row.html title="Arsenal-237 New Files: lpe.exe — IOC Feed" date="Jan 2026" severity="high" tags="Priv Esc" url="/ioc-feeds/arsenal-237-lpe-exe.json" %}
{% include report-row.html title="Arsenal-237 New Files: killer_crowdstrike.dll — IOC Feed" date="Jan 2026" severity="high" tags="Evasion,BYOVD" url="/ioc-feeds/arsenal-237-killer-crowdstrike-dll.json" %}
{% include report-row.html title="Arsenal-237 New Files: killer.dll — IOC Feed" date="Jan 2026" severity="high" tags="BYOVD,Evasion" url="/ioc-feeds/arsenal-237-killer-dll.json" %}
{% include report-row.html title="Arsenal-237: enc/dec Ransomware Family — IOC Feed" date="Jan 2026" severity="high" tags="Ransomware,Rust" url="/ioc-feeds/enc-dec-ransomware-family.json" %}
{% include report-row.html title="Arsenal-237: uac_test.exe — IOC Feed" date="Jan 2026" severity="med" tags="Priv Esc,Evasion" url="/ioc-feeds/uac-test-exe.json" %}
{% include report-row.html title="Arsenal-237: FleetAgentFUD.exe — IOC Feed" date="Jan 2026" severity="med" tags="Dropper,Evasion" url="/ioc-feeds/fleetagentfud-exe.json" %}
{% include report-row.html title="Arsenal-237: FleetAgentAdvanced.exe — IOC Feed" date="Jan 2026" severity="med" tags="Dropper,Persistence" url="/ioc-feeds/fleetagentadvanced-exe.json" %}
{% include report-row.html title="Arsenal-237: agent_xworm_v2.exe — IOC Feed" date="Jan 2026" severity="med" tags="RAT,C2" url="/ioc-feeds/agent-xworm-v2-exe.json" %}
{% include report-row.html title="Arsenal-237: agent_xworm.exe — IOC Feed" date="Jan 2026" severity="med" tags="RAT,C2" url="/ioc-feeds/agent-xworm-exe.json" %}
{% include report-row.html title="Arsenal-237: agent.exe (PoetRAT) — IOC Feed" date="Jan 2026" severity="med" tags="RAT,C2" url="/ioc-feeds/agent-exe.json" %}
{% include report-row.html title="Dual-RAT Analysis: Pulsar RAT vs. NjRAT/XWorm — IOC Feed" date="Dec 2025" severity="med" tags="RAT,.NET" url="/ioc-feeds/dual-rat-analysis.json" %}
{% include report-row.html title="PULSAR RAT (server.exe) — IOC Feed" date="Dec 2025" severity="med" tags="RAT,Cred Theft" url="/ioc-feeds/PULSAR-RAT.json" %}
{% include report-row.html title="Hybrid Loader/Stealer Ecosystem Masquerading as Sogou — IOC Feed" date="Nov 2025" severity="med" tags="Loader,Stealer" url="/ioc-feeds/Hybrid-Loader-Stealer-Sogou.json" %}
{% include report-row.html title="Houselet.exe — IOC Feed" date="Nov 2025" severity="med" tags="Loader,Stealer,Go" url="/ioc-feeds/malware-analysis-houselet.json" %}
{% include report-row.html title="AdvancedRouterScanner — IOC Feed" date="Oct 2025" severity="med" tags="Scanner,Exploitation" url="/ioc-feeds/AdvancedRouterScanner.json" %}
{% include report-row.html title="From Webshells to The Cloud — IOC Feed" date="Oct 2025" severity="high" tags="Webshell,Exfil" url="/ioc-feeds/webshells-to-the-cloud.json" %}
{% include report-row.html title="QuasarRAT + XWorm + PowerShell Loader — IOC Feed" date="Oct 2025" severity="med" tags="RAT,Loader" url="/ioc-feeds/quasar-xworm-powershell.json" %}
</div>
