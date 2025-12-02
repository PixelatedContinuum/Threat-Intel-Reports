---
title: From Webshells to the Cloud - A Modular Intrusion Chain
date: '2025-10-20'
layout: post
permalink: /reports/webshells-to-the-cloud/
hide: true
---

# BLUF (Bottom Line Up Front)

## Executive Summary

### Business Impact Summary
The "From Webshells to the Cloud" campaign represents a sophisticated, multi-phase intrusion chain that compromises web servers and pivots to cloud infrastructure abuse. This modular attack demonstrates advanced persistence capabilities and strong attribution fingerprints, indicating an organized threat operation with systematic exploitation methodologies.

### Key Risk Factors
<table class="professional-table">
  <thead>
    <tr>
      <th>Risk Factor</th>
      <th class="numeric">Score</th>
      <th>Business Impact</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Web Server Compromise</strong></td>
      <td class="numeric high">9/10</td>
      <td>Complete server control with data exfiltration and lateral movement capabilities</td>
    </tr>
    <tr>
      <td><strong>Cloud Infrastructure Abuse</strong></td>
      <td class="numeric high">8/10</td>
      <td>Legitimate cloud services abused for C2, exfiltration, and attack infrastructure</td>
    </tr>
    <tr>
      <td><strong>Persistence Mechanisms</strong></td>
      <td class="numeric high">8/10</td>
      <td>Multiple backdoors with RSA encryption ensuring exclusive attacker access</td>
    </tr>
    <tr>
      <td><strong>Attribution Fingerprints</strong></td>
      <td class="numeric medium">7/10</td>
      <td>Strong attribution evidence but may indicate shared tools across threat groups</td>
    </tr>
  </tbody>
</table>

### Recommended Actions
1. **SCAN** all web servers for PHP backdoors and suspicious files
2. **BLOCK** known malicious infrastructure (45.118.144.151:8081, 152.32.191.156:8081)
3. **ISOLATE** potentially compromised web servers from internal networks
4. **AUDIT** cloud service usage for unauthorized access and data exfiltration
5. **COLLECT** forensic evidence including web server logs and memory dumps
6. **RESET** all credentials for potentially compromised systems and cloud accounts

---

## Table of Contents
* This will be replaced with automatic TOC - Major Sections Only
{:toc_levels: 2}

---

## Quick Reference

**Detections & IOCs:**
- [Webshells to the Cloud Detections]({{ "/hunting-detections/webshells-to-the-cloud/" | relative_url }})
- [Webshells to the Cloud IOCs]({{ "/ioc-feeds/webshells-to-the-cloud.json" | relative_url }})

---

## Executive Summary
This campaign demonstrates a modular intrusion chain leveraging PHP backdoors, exploit kits, and cloud abuse. Attackers pivot from initial webshell deployment to exploitation, persistence, exfiltration, and infrastructure automation. The reuse of RSA keys, cookie names, and file paths provides strong attribution fingerprints.

---

## Technical Details

# Technical Analysis

## Infrastructure Overview
<table class="professional-table">
  <thead>
    <tr>
      <th>Infrastructure Component</th>
      <th>Value</th>
      <th>Role in Attack Chain</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Primary C2 Server</strong></td>
      <td>45.118.144[.]151:8081</td>
      <td>Initial webshell deployment and backdoor hosting</td>
    </tr>
    <tr>
      <td><strong>Exploitation Server</strong></td>
      <td>152.32.191[.]156:8081</td>
      <td>Exploit kits, payload delivery, and automation</td>
    </tr>
    <tr>
      <td><strong>Content Delivery</strong></td>
      <td>juyu1[.]yifanyi.app</td>
      <td>Malicious content distribution and SEO poisoning</td>
    </tr>
    <tr>
      <td><strong>Command Infrastructure</strong></td>
      <td>shellcp[.]info</td>
      <td>Remote content injection and proxy services</td>
    </tr>
  </tbody>
</table>

---

### Phase 1: Initial Discovery (45.118.144[.]151)

**File: pg-politica-de-privacidade.php**  
- Trojanized Privacy Policy page.  
- PHP class `A` with `__wakeup()` method.  
- Hardcoded RSA public key → only attacker‑encrypted payloads execute.  
- Trigger: `$_POST['mxx']`.  
- Obfuscation: dynamically builds function names (`openssl_public_decrypt`, `base64_decode`).  
- Executes decrypted payload via `eval()`.  
- Camouflage: Legitimate Portuguese Privacy Policy appended.  
- **Implication:** Exclusive access backdoor; RSA key is a campaign fingerprint.  
- **Hunting Highlights:**  
  - PHP files with `__wakeup()` + `unserialize()` + `eval()`  
  - POST requests with parameter `mxx`  
  - Embedded RSA public key blocks in PHP code  

**File: upnimix.php**  
- Full‑featured PHP webshell.  
- Capabilities: command execution, file upload/edit/delete/rename, directory listing.  
- **Implication:** Persistence and full remote control.  
- **Hunting Highlights:**  
  - PHP files with `goto` + `exec/system/shell_exec/passthru`  
  - POSTs with parameters like `cmd`, `file_content`, `upload`  
  - PHP spawning OS processes (`/bin/sh`, `cmd.exe`)  

**File: video.php**  
- Remote content injector.  
- Behavior: proxies requests to `shellcp[.]info/api.php`.  
- Cloaks behavior for Googlebot (`?googlebot`).  
- **Implication:** SEO poisoning, phishing, or malware delivery.  
- **Hunting Highlights:**  
  - PHP files with `file_get_contents("http://shellcp.info/...")`  
  - Outbound HTTP requests to `shellcp[.]info`  
  - Cloaking logic tied to “oogle” in User‑Agent  

---

### Phase 2: Pivot & Exploitation (152.32.191[.]156)

**Exploit Kits**  
- Scripts: 测试.py, exploit.py, exploit2.py.  
- Helper: Crypto.php (forged `clp-fm` cookie).  
- Exploit chain: forge cookie → access `/file-manager/` → create file → upload shell → set permissions → verify at `/htdocs/app/files/public/shell.php`.  
- Variants: batch exploitation, version‑specific (CloudPanel 0day Version : 2.0.0 >= 2.3.0).  
- Persistence variant: creates user `zeroday` / password `Etharus@1337`.  

**Webshells**  
- One‑liner (`?cmd=` → system execution, fallback to phpinfo()).  
- `shell.php` uploaded with 0777 permissions.  

**Hunting Highlights**  
- Web logs with cookie header `clp-fm`.  
- Access to `/file-manager/backend/makefile` or `/phpmyadmin/js/`.  
- New privileged accounts (`zeroday`).  
- File creation in `/htdocs/app/files/public/`.  
- Requests with `?cmd=` in query strings.  

---

### Phase 3: Exfiltration & Cloud Abuse

**Modules**  
- **Dropbox:** Client.php, AccessCodeValidator.php → API abuse for stealthy uploads.  
- **Rclone:** Rclone.php, TarCreator.php → bulk data theft, retries, throttling.  
- **AWS:** Ami.php, Instance.php, Regions.php → S3 exfiltration, destructive actions possible.  

**Hunting Highlights**  
- Outbound traffic to `api.dropboxapi.com`.  
- Rclone process execution (`rclone`, `rclone.exe`).  
- Unexpected S3 PutObject/DeleteObject events in CloudTrail.  
- Large outbound transfers to cloud storage from servers without backup roles.  

---

### Phase 4: Infrastructure Automation

**Site Builder Framework (Site/ directory)**  
- Installers: WordPressInstaller.php, PhpSite.php, NodejsSite.php, PythonSite.php.  
- Reverse Proxy: ReverseProxySite.php → traffic redirection.  
- Domain Automation: DomainName.php.  
- Scaling: VarnishCache/Creator.php.  

**Hunting Highlights**  
- Automated WordPress installs from non‑admin sources.  
- Sudden creation of reverse proxy configs in Nginx/Apache.  
- Varnish cache deployments on non‑web infra.  
- Suspicious PHP files named WordPressInstaller.php, ReverseProxySite.php.  

---

# Attack Chain Analysis

## Campaign Structure Summary
<table class="professional-table">
  <thead>
    <tr>
      <th>Attack Phase</th>
      <th>Primary Techniques</th>
      <th>Infrastructure Used</th>
      <th>Business Impact</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Initial Access</strong></td>
      <td>CloudPanel 0-day exploit kits, PHP backdoors</td>
      <td>45.118.144[.]151:8081</td>
      <td class="high">CRITICAL - Server compromise</td>
    </tr>
    <tr>
      <td><strong>Persistence</strong></td>
      <td>Webshells, backdoor accounts, RSA-encrypted payloads</td>
      <td>Multiple compromised servers</td>
      <td class="high">HIGH - Long-term access</td>
    </tr>
    <tr>
      <td><strong>Exfiltration</strong></td>
      <td>Dropbox API abuse, Rclone, AWS S3 exploitation</td>
      <td>Legitimate cloud services</td>
      <td class="high">HIGH - Data theft</td>
    </tr>
    <tr>
      <td><strong>Infrastructure Scaling</strong></td>
      <td>Automated site builder framework, reverse proxies</td>
      <td>Compromised web infrastructure</td>
      <td class="medium">MEDIUM - Attack expansion</td>
    </tr>
  </tbody>
</table>

## Attribution Fingerprints
<table class="professional-table">
  <thead>
    <tr>
      <th>Fingerprint Type</th>
      <th>Value</th>
      <th>Confidence Level</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>RSA Public Key</strong></td>
      <td>Reused across multiple IPs and backdoors</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Cookie Names</strong></td>
      <td>clp-fm (consistent across exploit kits)</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>File Paths</strong></td>
      <td>/htdocs/app/files/public/shell.php</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Account Patterns</strong></td>
      <td>zeroday/Etharus@1337 (consistent credentials)</td>
      <td class="likely">LIKELY</td>
    </tr>
  </tbody>
</table>

---

## Incident Response Procedures

### Priority 1: Initial Response (First 60 Minutes)
1. **ISOLATE** all web servers with potential PHP backdoor infections
2. **BLOCK** known malicious infrastructure at network perimeter
3. **SCAN** all web servers for suspicious PHP files and backdoors
4. **AUDIT** cloud service access logs for unauthorized API usage
5. **COLLECT** forensic evidence including web server logs and memory dumps
6. **RESET** all credentials for potentially compromised systems and cloud accounts

### Priority 2: Investigation & Analysis (Hours 1-6)
1. **FORENSIC ANALYSIS** of web server logs for exploitation patterns
2. **LOG ANALYSIS** for connections to known malicious infrastructure
3. **CLOUD AUDIT** for unauthorized API access and data exfiltration
4. **MALWARE ANALYSIS** of recovered PHP backdoors and exploit kits
5. **THREAT HUNTING** for additional compromised systems and lateral movement

### Priority 3: Remediation & Recovery (Hours 6-24)
1. **REBUILD** compromised web servers from known-good images
2. **UPDATE** all web applications and frameworks to latest versions
3. **IMPLEMENT** web application firewalls with PHP backdoor detection
4. **DEPLOY** enhanced monitoring for cloud service API abuse
5. **ESTABLISH** secure coding practices and code review processes

---

## Business Risk Assessment

### Financial Impact Scenarios
<table class="professional-table">
  <thead>
    <tr>
      <th>Impact Category</th>
      <th>Low Estimate</th>
      <th>High Estimate</th>
      <th>Time to Recovery</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Data Breach Costs</strong></td>
      <td>$100,000</td>
      <td>$1,000,000+</td>
      <td>3-6 months</td>
    </tr>
    <tr>
      <td><strong>System Remediation</strong></td>
      <td>$50,000</td>
      <td>$500,000</td>
      <td>1-2 weeks</td>
    </tr>
    <tr>
      <td><strong>Cloud Service Abuse</strong></td>
      <td>$25,000</td>
      <td>$250,000</td>
      <td>1-4 weeks</td>
    </tr>
    <tr>
      <td><strong>Business Disruption</strong></td>
      <td>$75,000</td>
      <td>$750,000</td>
      <td>2-4 weeks</td>
    </tr>
  </tbody>
</table>

### Operational Impact Timeline
- **Immediate (0-24 hours):** Web server isolation, service disruption, emergency response
- **Short-term (1-7 days):** System rebuilding, security hardening, enhanced monitoring
- **Medium-term (1-4 weeks):** Process improvements, cloud security implementation
- **Long-term (1-3 months):** Security architecture review, compliance activities

---

## Long-term Defensive Strategy

### Technology Enhancements
1. **Web Application Firewall (WAF)** with PHP backdoor detection capabilities
2. **Cloud Security Posture Management (CSPM)** for continuous cloud monitoring
3. **Runtime Application Self-Protection (RASP)** for real-time threat detection
4. **Security Information and Event Management (SIEM)** with cloud integration
5. **API Security Gateway** for cloud service access control

### Process Improvements
1. **Secure Software Development Lifecycle (SSDLC)** implementation
2. **Regular Security Assessments** including penetration testing of web applications
3. **Cloud Access Security Broker (CASB)** deployment for cloud service monitoring
4. **Incident Response Playbooks** specific to web application compromises
5. **Change Management** procedures with security approval requirements

### Organizational Measures
1. **Security Awareness Training** for development and operations teams
2. **Regular Security Assessments** including code reviews and architecture reviews
3. **Threat Intelligence Subscription** for emerging web application threats
4. **Executive Security Briefings** on cloud security risks and mitigation strategies
5. **Investment in Security Tools** and personnel training for advanced threat detection

---

## Frequently Asked Questions

### Technical Questions
**Q: What makes the RSA encryption backdoor particularly dangerous?**  
A: It ensures exclusive attacker access - only payloads encrypted with the corresponding private key will execute, preventing other attackers or security tools from utilizing the backdoor.

**Q: How does cloud service abuse work in this campaign?**  
A: Attackers abuse legitimate cloud APIs (Dropbox, AWS S3) for data exfiltration and infrastructure, making detection difficult as traffic appears to be normal cloud usage.

**Q: What are the key hunting indicators for this campaign?**  
A: PHP files with `__wakeup()` methods, POST requests with `mxx` parameter, embedded RSA keys, and access to `/file-manager/` endpoints with forged cookies.

### Business Questions
**Q: What are the regulatory implications of cloud service abuse?**  
A: Significant - unauthorized cloud access can trigger data breach notifications, compliance violations, and potential liability for customer data exposure.

**Q: Should we rebuild or patch compromised web servers?**  
A: **REBUILD** is strongly recommended due to the sophistication of backdoors and potential for additional hidden compromise mechanisms.

**Q: How can we prevent similar cloud abuse?**  
A: Implement cloud access monitoring, API security controls, regular access reviews, and principle of least privilege for cloud service accounts.

---

## IOCs
- [From Webshells to The Cloud IOCs]({{ "/ioc-feeds/webshells-to-the-cloud.json" | relative_url }})

## Detections
- [From Webshells to The Cloud Detections]({{ "/hunting-detections/webshells-to-the-cloud/" | relative_url }})

---

## License
© 2025 Joseph. All rights reserved.  
Free to read, but reuse requires written permission.
