---
title: "Detection Rules: MultiVector Grey-Market PII Harvesting Operation (192.3.1.116)"
date: '2026-07-21'
layout: post
permalink: /hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/
hide: true
unlisted: true
---

**Campaign:** MultiVector-Ecommerce-RCE-Toolkit-192.3.1.116
**Date:** 2026-07-21
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/multivector-ecommerce-rce-toolkit-192-3-1-116/

---

## Detection Coverage Summary

> **No malware sample exists in this campaign.** The evidence base is an exposed operator working directory holding crafted exploitation payloads, captured probe responses, and outcome artifacts, not an implant, packer, or C2 protocol. Detection value here is behavioral and payload-class based, not hash- or family-based. Coverage below targets the exploitation techniques and request patterns the operator used, which generalize far beyond this specific operator and this specific infrastructure. Atomic indicators (the operator IP, VPN hostname, relay subdomain, SSH key fingerprints, Telegram identifiers, throwaway account names) are already carried in the campaign IOC feed and are deliberately **not** re-encoded as rule logic here: a rule pinned to `192.3.1.116` dies with the takedown that is already filed; the techniques outlive the infrastructure.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 5 | 0 | T1190, T1505.003, T1552.005 | 0 (all atomics already carried in the campaign IOC feed) |
| Sigma | 5 | 7 | T1190, T1213, T1596.005, T1005, T1552.001, T1110.001, T1078, T1585, T1046 | 0 (all atomics already carried in the campaign IOC feed) |
| Suricata | 11 | 2 | T1190, T1552.005, T1098.004, T1105, T1606.001, T1596.005, T1110.001 | 0 (all atomics already carried in the campaign IOC feed) |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient, safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting: expect to review the hits. Several Sigma rules below are **base rules that do not alert on their own**; they exist to feed a correlation rule that fires on the sequence or volume of events, and are explicitly labeled Hunting/informational in isolation. The correlation built from them is the alerting-grade Detection rule.

**Layered coverage.** YARA targets the exploitation payload *files* a defender may recover from an upload directory, temp path, or incident (Logback JNDI/FileAppender configs, a SnakeYAML gadget document, a generic JSP web shell, an XXE-to-SSRF document). Sigma targets the *behavior* visible in web-server access logs (Jolokia log manipulation, unauthenticated Druid/heap-dump retrieval, account-registration-then-probe, verification-code brute force, port-scan profile). Suricata targets the *network* traffic (LDAP JNDI callback, gadget chains and SSRF payloads in transit, forged-JWT headers, Eureka poisoning). No single technique in this campaign relies on only one layer where more than one is available.

---

## YARA Rules

All five rules below target the **payload class**, not this operator's specific file: each is anchored on the exploitation technique's structural markers so it fires against any instance of the same CVE/gadget/web-shell pattern, not just the copy recovered from this operator's directory. None reference this operator's IP, hostnames, or account names.

### Detection Rules

#### Logback insertFromJNDI RCE (CVE-2021-42550)

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1190 (Exploit Public-Facing Application)
**Confidence:** HIGH
**False Positives:** None known. `insertFromJNDI` combined with a `ldap://`/`rmi://` scheme inside a Logback `<configuration>` element is not a pattern that occurs in legitimate logging configuration; the JNDI lookup feature exists specifically to be pointed at a directory service, and pointing it at an attacker-controlled scheme is the exploit itself.
**Blind Spots:** Misses payloads that use a different JNDI scheme unlikely to be blocked by allowlists (e.g. `dns://`, `corba://`), and misses the exploit entirely if delivered as a compiled/serialized configuration rather than the plaintext XML form matched here.
**Validation:** Scan the `logback-rce.xml`-style payload (an XML file containing an `<insertFromJNDI env-entry-name="ldap://...">` element) and confirm a match; a stock, unmodified Logback `logback.xml` with no JNDI lookups must NOT fire.
**Deployment:** File/attachment scanning, upload-directory sweeps, incident-response triage of recovered configuration files.

```yara
/*
   Yara Rule Set
   Identifier: Logback insertFromJNDI RCE (CVE-2021-42550)
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule EXPL_Logback_InsertFromJNDI_CVE_2021_42550 {
   meta:
      description = "Detects a Logback XML configuration using insertFromJNDI to trigger a JNDI lookup against an attacker-controlled ldap:// or rmi:// URI, the mechanism behind CVE-2021-42550. The insertFromJNDI element paired with a JNDI scheme in an env-entry-name attribute is not a pattern seen in legitimate logging configuration."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/"
      date = "2026-07-21"
      family = "Logback insertFromJNDI RCE (CVE-2021-42550)"
      malware_type = "Exploitation payload -- Java logging-framework RCE"
      id = "ace3c6c6-23e3-500a-8ade-a75d8209a06b"
   strings:
      $config = "<configuration" ascii
      $jndi = "insertFromJNDI" ascii
      $ldap = "env-entry-name=\"ldap://" ascii
      $rmi = "env-entry-name=\"rmi://" ascii
   condition:
      filesize < 50KB and
      $config and $jndi and
      1 of ($ldap, $rmi)
}
```

#### Logback FileAppender Arbitrary File Write to JSP

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1190 (Exploit Public-Facing Application), T1505.003 (Web Shell)
**Confidence:** HIGH
**False Positives:** None known. A Logback `FileAppender` writing its output to a `.jsp` destination is never legitimate: appenders write log text, not application code, and no production logging configuration targets a servlet-container-executable extension.
**Blind Spots:** Misses the technique if the target extension is renamed away from `.jsp` (e.g. `.jspx`, `.jsp.bak` moved into place by a second step) or if a different appender class is used to the same effect.
**Validation:** Scan the `logback-evil.xml`-style payload (a `FileAppender` whose `<file>` value ends in `.jsp`) and confirm a match; a normal Logback configuration writing to a `.log` or `.txt` destination must NOT fire.
**Deployment:** File/attachment scanning, upload-directory sweeps, incident-response triage of recovered configuration files.

```yara
/*
   Yara Rule Set
   Identifier: Logback FileAppender Arbitrary File Write
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule EXPL_Logback_FileAppender_JSP_ArbitraryWrite {
   meta:
      description = "Detects a Logback XML configuration defining a FileAppender whose file destination ends in .jsp, an arbitrary-file-write technique that abuses a legitimate logging framework to drop a JSP web shell rather than using a conventional upload vector."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/"
      date = "2026-07-21"
      family = "Logback FileAppender Arbitrary File Write"
      malware_type = "Exploitation payload -- Java logging-framework arbitrary file write"
      id = "37a281e7-61d6-5287-81af-9a6bcfd3a5b5"
   strings:
      $config = "<configuration" ascii
      $appender = "ch.qos.logback.core.FileAppender" ascii
      $jsp_ext = /<file>[^<]{1,200}\.jsp<\/file>/ ascii
   condition:
      filesize < 50KB and
      $config and $appender and $jsp_ext
}
```

#### SnakeYAML Deserialization Gadget (CVE-2022-1471 Family)

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1190 (Exploit Public-Facing Application)
**Confidence:** HIGH
**False Positives:** None known. The three-string combination is the textbook SnakeYAML unsafe-deserialization gadget chain (`ScriptEngineManager` loading a remote `URLClassLoader`); no legitimate YAML document constructs a scripting engine via a remote class loader.
**Blind Spots:** Misses gadget chains built from a different base class (e.g. `javax.naming.InitialContext`, other CVE-2022-1471-family variants that avoid `ScriptEngineManager`), and misses payloads that obfuscate the YAML tags.
**Validation:** Scan the `poc.yml`-style payload (containing all three `!!javax.script.ScriptEngineManager`, `!!java.net.URLClassLoader` and `!!java.net.URL` tags) and confirm a match; an ordinary application YAML configuration file must NOT fire.
**Deployment:** File/attachment scanning, upload-directory sweeps, incident-response triage of recovered configuration files.

```yara
/*
   Yara Rule Set
   Identifier: SnakeYAML Deserialization Gadget (CVE-2022-1471 family)
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule EXPL_SnakeYAML_ScriptEngineManager_Gadget_CVE_2022_1471_Family {
   meta:
      description = "Detects a SnakeYAML unsafe-deserialization payload using the classic javax.script.ScriptEngineManager plus java.net.URLClassLoader gadget chain (the CVE-2022-1471 family) to achieve remote code execution from an untrusted YAML document."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/"
      date = "2026-07-21"
      family = "SnakeYAML Deserialization Gadget (CVE-2022-1471 family)"
      malware_type = "Exploitation payload -- Java deserialization RCE"
      id = "914b2554-4595-586e-92e9-b29f6a9ec60e"
   strings:
      $x1 = "!!javax.script.ScriptEngineManager" ascii
      $x2 = "!!java.net.URLClassLoader" ascii
      $x3 = "!!java.net.URL" ascii
   condition:
      filesize < 20KB and
      all of ($x*)
}
```

#### Generic JSP Web Shell (Bash-Exec via HTTP Parameter)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1505.003 (Web Shell)
**Confidence:** HIGH
**False Positives:** Low but not zero: a small number of legitimate diagnostic or internal-tooling JSP pages in development environments do shell out to `/bin/bash -c` using a request parameter; these are themselves poor practice and worth flagging even when not attacker-authored.
**Blind Spots:** Misses web shells built on a different execution primitive (`ProcessBuilder`, reflection-based invocation), a different shell (`/bin/sh`, `cmd.exe`), or that separate the parameter read from the exec call across multiple lines/methods beyond what the proximity-free string set here tolerates.
**Validation:** Scan the `cmd.jsp`-style payload (`request.getParameter` combined with `Runtime.getRuntime().exec` and a `/bin/bash -c` invocation) and confirm a match; a normal JSP page that reads a parameter for display purposes only, with no exec call, must NOT fire.
**Deployment:** Web-root/upload-directory scanning, incident-response triage, webshell-hunting sweeps of Java application servers.

```yara
/*
   Yara Rule Set
   Identifier: Generic JSP Web Shell
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule WEBSHELL_Generic_JSP_Bash_Exec_Parameter {
   meta:
      description = "Detects a minimal JSP web shell that reads a single HTTP request parameter and passes it directly to /bin/bash -c via Runtime.getRuntime().exec. The parameter name is kept generic since it varies by deployment; the proximity of getParameter to a bash -c exec call is the durable indicator of a functioning command-execution shell rather than legitimate application code."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/"
      date = "2026-07-21"
      family = "Generic JSP Web Shell"
      malware_type = "Web shell"
      id = "61eeb62a-80ed-5a4d-b709-0ac11517a820"
   strings:
      $getparam = /request\.getParameter\([^)]{0,40}\)/ ascii
      $exec = "Runtime.getRuntime().exec" ascii
      $bash = "/bin/bash" ascii
      $dashc = "\"-c\"" ascii
   condition:
      filesize < 30KB and
      $getparam and $exec and $bash and $dashc
}
```

#### XXE-to-SSRF Internal/Cloud-Metadata Probe

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1190 (Exploit Public-Facing Application), T1552.005 (Cloud Instance Metadata API)
**Confidence:** HIGH
**False Positives:** None known. An XML external-entity declaration whose `SYSTEM` target is the cloud instance-metadata address or a well-known internal service port has no legitimate purpose in a document a server is expected to parse.
**Blind Spots:** Misses XXE payloads targeting a different internal address/port than the four covered here, misses parameter-entity or out-of-band (blind) XXE variants that reference an external DTD instead of embedding the target directly, and misses the plain local-file-read XXE variant (e.g. `file:///etc/passwd`) which is a much older, already broadly-signatured technique not re-covered here.
**Validation:** Scan the `internal_scan.svg`-style payload (an `<!ENTITY ... SYSTEM "http://169.254.169.254/...">` declaration, or the Redis/MySQL/Actuator internal-service variants) and confirm a match; an ordinary SVG or XML document with no external entity declarations must NOT fire.
**Deployment:** File-upload scanning (especially SVG/XML upload features), incident-response triage of recovered documents.

```yara
/*
   Yara Rule Set
   Identifier: XXE-to-SSRF Internal/Cloud-Metadata Probe
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule EXPL_XXE_SSRF_Cloud_Metadata_Internal_Service_Probe {
   meta:
      description = "Detects an XML or SVG document declaring an external entity (XXE) that resolves to the cloud instance metadata service or a well-known internal service port, a server-side request forgery technique used to pivot from a file-upload or XML-parsing feature into internal-network and cloud-credential reconnaissance."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/"
      date = "2026-07-21"
      family = "XXE-to-SSRF Internal/Cloud-Metadata Probe"
      malware_type = "Exploitation payload -- XML External Entity SSRF"
      id = "c643375b-9567-5b36-abf2-8db9880f4f5b"
   strings:
      $entity = "<!ENTITY" ascii
      $system = "SYSTEM" ascii
      $meta = "169.254.169.254" ascii
      $redis = "127.0.0.1:6379" ascii
      $mysql = "127.0.0.1:3306" ascii
      $actuator = ":8080/actuator" ascii
   condition:
      filesize < 20KB and
      $entity and $system and
      1 of ($meta, $redis, $mysql, $actuator)
}
```

### Hunting Rules

_None. All five YARA rules authored for this campaign cleared the Detection bar (Robustness ≥ 2, zero or near-zero characterized false-positive scenarios); no YARA candidate was demoted to Hunting._

---

## Sigma Rules

Web-access-log telemetry (`logsource.category: webserver`) covers most of this campaign's durable behavioral signal. Several rules below are **base rules that do not alert on their own**; each exists to feed a Sigma correlation rule that fires on the *sequence* or *volume* of events, not on any single request. This mirrors how the standout technique in this campaign actually works: neither "someone wrote a Jolokia logging property" nor "someone read a log file" is suspicious alone, but the pairing is.

### Detection Rules

#### Manufactured Log-Data Harvesting via Jolokia Logger Manipulation Then Actuator Logfile Read (Correlation)

**Tier:** Detection (correlation), bundled below with its 2 required Hunting-grade base rules, which do not alert on their own
**Robustness:** 3 (correlation) / 1 (each base rule individually)
**ATT&CK Coverage:** T1213 (Data from Information Repositories), T1190 (Exploit Public-Facing Application)
**Confidence:** HIGH (correlation) / LOW (either base rule alone)
**False Positives:** A single operations engineer legitimately using Jolokia to raise logging for live debugging from the same source IP as their own log review, within the same short window, uncommon outside a genuine incident-response or troubleshooting session, and should be corroborated against known management-network IP ranges.
**Blind Spots:** An operator who manipulates logging and reads the log file from two different source IPs (e.g. via a proxy chain) evades the `c-ip` grouping; an operator who waits longer than 15 minutes between the write and the read also evades this specific window.
**Validation:** Replay a Jolokia logger/logging-level write request followed by an actuator logfile GET from the same source IP within 15 minutes: the correlation must fire; either event alone, or the same two events from two different source IPs, must NOT trigger the correlation.
**Deployment:** SIEM correlation engine ingesting web/proxy access-log telemetry (`cs-uri-stem`, `cs-uri`, `sc-status`, `c-ip`).

```yaml
title: External HTTP Request to Jolokia JMX Write Endpoint Targeting Logging Configuration
id: 00a7fbb6-7f52-4153-96cd-41042f0090eb
name: jolokia_logger_write_base
status: experimental
description: >-
    Base rule (not alerting on its own): an external HTTP request to a Jolokia
    (JMX-over-HTTP) write endpoint targeting a Logger or logging-level
    attribute. Jolokia exposes JMX management operations over plain HTTP, and a
    write operation against logging configuration lets a remote caller raise a
    target application's log verbosity to manufacture sensitive data in the
    log file for later retrieval. Paired below with a rule for the follow-on
    actuator logfile read.
references:
    - https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/
author: The Hunters Ledger
date: '2026-07-21'
tags:
    - attack.initial-access
    - attack.t1190
logsource:
    category: webserver
detection:
    selection_endpoint:
        cs-uri-stem|contains: '/jolokia/write/'
    selection_target:
        cs-uri|contains:
            - 'Logger'
            - 'logging.level'
    condition: selection_endpoint and selection_target
falsepositives:
    - >-
        Authorized internal application-performance-monitoring tooling that
        manages Jolokia over HTTP from a trusted management network. Reviewed
        only in combination with the follow-on logfile-read rule via the
        correlation below.
level: medium
---
title: External HTTP GET of the Spring Boot Actuator Log File Endpoint
id: 9e4e2540-95c5-44a6-a433-add2bcba903f
name: actuator_logfile_read_base
status: experimental
description: >-
    Base rule (not alerting on its own): an external HTTP GET of the Spring
    Boot Actuator logfile endpoint. Reading the live application log is
    unremarkable in isolation, since operations teams do this routinely, but
    paired with a preceding Jolokia logger-level write it is the retrieval
    step of a log-manufacturing technique that turns verbose request and
    response tracing into a harvestable data source.
references:
    - https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/
author: The Hunters Ledger
date: '2026-07-21'
tags:
    - attack.collection
    - attack.t1213
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains: '/actuator/logfile'
    selection_success:
        sc-status: 200
    condition: selection and selection_success
falsepositives:
    - >-
        Authorized operations or monitoring staff retrieving the log file from
        an approved management network. Not alerting on its own; reviewed
        only in combination with the preceding logger-level-write event via
        the correlation rule.
level: informational
---
title: Manufactured Log-Data Harvesting via Jolokia Logger Manipulation Then Actuator Logfile Read
id: 9df4b43e-0124-4eff-b32c-b6cfbaddf527
status: experimental
description: >-
    Fires when the same external source both writes a Jolokia logger or
    logging-level attribute, raising verbosity to DEBUG or FULL, and retrieves
    the actuator logfile within a short window. Neither event alone is
    unusual; the sequence is the signature of an operator manufacturing
    sensitive data in application logs and then reading it back out, rather
    than a routine operations workflow.
references:
    - https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/
author: The Hunters Ledger
date: '2026-07-21'
tags:
    - attack.collection
    - attack.t1213
    - attack.initial-access
    - attack.t1190
correlation:
    type: temporal_ordered
    rules:
        - jolokia_logger_write_base
        - actuator_logfile_read_base
    group-by:
        - c-ip
    timespan: 15m
falsepositives:
    - >-
        A single operations engineer using Jolokia for legitimate live
        debugging from the same source IP as their log review, within the
        same window. Uncommon outside a real incident-response or
        troubleshooting session.
level: high
```

#### Unauthenticated External Access to an Apache Druid Monitoring Console

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1596.005 (Scan Databases)
**Confidence:** HIGH
**False Positives:** Authorized internal monitoring dashboards or an approved attack-surface-management scan intentionally checking for this exposure. Any external hit on these paths still warrants confirming the console is properly restricted.
**Blind Spots:** Misses the exposure if the console is mounted under a non-default path, or if the environment logs status codes as a string field the ingestion pipeline doesn't map cleanly to `sc-status`.
**Validation:** Replay an external GET to `/druid/index.html` (or the other listed paths) that returns 200: the rule must fire; the same request returning 401/403/404 must NOT fire.
**Deployment:** Web/proxy access-log ingestion, WAF log ingestion.

```yaml
title: Unauthenticated External Access to an Apache Druid Monitoring Console
id: b2857306-3872-446e-a6cf-f093e48e3252
status: experimental
description: >-
    Detects a successful external request to an Apache Druid StatViewServlet
    monitoring path. An unauthenticated Druid console exposes the production
    JDBC connection string, full database schema and executed SQL statement
    history to anyone who can reach it; a single request returning 200 on
    these paths from outside the management network is a real
    information-disclosure event regardless of who sent it. Frequently served
    on a non-standard port, so this rule does not restrict to 80 or 443.
references:
    - https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/
author: The Hunters Ledger
date: '2026-07-21'
tags:
    - attack.reconnaissance
    - attack.t1596.005
logsource:
    category: webserver
detection:
    selection_path:
        cs-uri-stem|contains:
            - '/druid/index.html'
            - '/druid/basic.json'
            - '/druid/sql.json'
            - '/druid/weburi.json'
            - '/druid/datasource.json'
    selection_success:
        sc-status: 200
    condition: selection_path and selection_success
falsepositives:
    - >-
        Authorized internal monitoring dashboards or an approved
        attack-surface-management scan intentionally checking for this
        exposure. Any external hit on these paths still warrants confirming
        the console is properly restricted.
level: high
```

#### Successful External Retrieval of a Spring Boot Actuator Heap Dump

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1005 (Data from Local System), T1552.001 (Credentials In Files)
**Confidence:** HIGH
**False Positives:** Authorized developer or support engineer pulling a heap dump for legitimate memory-leak diagnosis from an approved internal source.
**Blind Spots:** The 1,000,000-byte response-size threshold is a reasonable default, not a universal one: a small heap or an aggressively-compressed response could fall under it; tune `sc-bytes` against the target environment's own actuator response sizes.
**Validation:** Replay an external GET to `/actuator/heapdump` that returns 200 with a response body over 1MB: the rule must fire; the same request blocked with a 401/403, or returning a small error body, must NOT fire.
**Deployment:** Web/proxy access-log ingestion.

```yaml
title: Successful External Retrieval of a Spring Boot Actuator Heap Dump
id: f872347d-00cd-463e-9817-96d4ef96f205
status: experimental
description: >-
    Detects a successful, large-bodied external response from the Spring Boot
    Actuator heapdump endpoint, or a Jolokia HotSpotDiagnostic dumpHeap
    invocation. A heap dump commonly contains in-memory credentials, session
    tokens and business data; this rule keys on confirmed success, a 200
    status with a large response body, rather than the request alone, since
    the request is trivially made and often blocked by an auth filter.
references:
    - https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/
author: The Hunters Ledger
date: '2026-07-21'
tags:
    - attack.collection
    - attack.t1005
    - attack.credential-access
    - attack.t1552.001
logsource:
    category: webserver
detection:
    selection_path:
        cs-uri-stem|contains:
            - '/actuator/heapdump'
            - '/heapdump'
    selection_jolokia_dumpheap:
        cs-uri|contains: 'HotSpotDiagnostic'
    selection_success:
        sc-status: 200
    selection_large_body:
        sc-bytes|gte: 1000000
    condition: (selection_path or selection_jolokia_dumpheap) and selection_success and selection_large_body
falsepositives:
    - >-
        Authorized developer or support engineer pulling a heap dump for
        legitimate memory-leak diagnosis from an approved internal source.
level: high
```

#### High-Volume Distinct Requests Against a Password-Reset or Verification-Code Endpoint (Correlation)

**Tier:** Detection (correlation), bundled below with its Hunting-grade base rule, which does not alert on its own
**Robustness:** 2 (correlation) / 1 (base rule individually)
**ATT&CK Coverage:** T1110.001 (Password Guessing)
**Confidence:** HIGH (correlation) / LOW (base rule alone)
**False Positives:** A misbehaving client retry loop or a load-testing script exercising the same endpoint. Uncommon in normal user behavior at this volume.
**Blind Spots:** Cannot confirm the ideal discriminator (one constant verification-context token paired with only the numeric code changing) because standard web-access-log telemetry does not expose individual query parameters by name; volume alone is the available proxy, so a low-and-slow brute force spread across many hours evades the 10-minute window. A defender with parsed API-gateway or WAF logs exposing the context-token parameter directly should key on "one constant token value, many distinct code values" instead, for materially higher precision.
**Validation:** Replay 50 or more distinct requests to the same password-reset endpoint from one source within 10 minutes: the correlation must fire; fewer than 50, or the same volume spread across multiple source IPs, must NOT trigger the correlation.
**Deployment:** SIEM correlation engine ingesting web/proxy access-log telemetry.

```yaml
title: HTTP POST to a Password-Reset or Verification-Code Endpoint
id: fec7253f-ea82-48f6-97fb-b8ca61c293f8
name: password_reset_endpoint_request_base
status: experimental
description: >-
    Base rule (not alerting on its own): a single POST to a password-reset or
    SMS/OTP verification-code endpoint. Ordinary and expected in isolation.
    Paired below with a correlation that flags an abnormal volume of distinct
    requests against the same endpoint in a short window, the shape of a
    4-digit verification-code brute force run against one fixed context
    token, as opposed to a user's occasional retry.
references:
    - https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/
author: The Hunters Ledger
date: '2026-07-21'
tags:
    - attack.credential-access
    - attack.t1110.001
logsource:
    category: webserver
detection:
    selection:
        cs-method: POST
        cs-uri-stem|contains:
            - 'restPassword'
            - 'forgetPwd'
    condition: selection
falsepositives:
    - >-
        A user repeatedly retrying a forgotten-password flow. Not alerting on
        its own; reviewed only through the volume threshold in the
        correlation rule below.
level: informational
---
title: High-Volume Distinct Requests Against a Password-Reset or Verification-Code Endpoint
id: 275a038d-07da-4c8c-9db0-fdf3f3a7106d
status: experimental
description: >-
    Fires when 50 or more distinct query strings hit the same password-reset
    or verification-code endpoint from one source within 10 minutes, the
    volumetric shape of exhausting a short numeric code space such as all
    10,000 four-digit combinations. This rule cannot confirm the ideal
    discriminator, a constant verification-context token paired with only the
    numeric code changing, because standard web-access-log telemetry does not
    expose individual query parameters by name; volume against a fixed
    endpoint is the available proxy. A defender with parsed API-gateway or WAF
    logs exposing the context-token parameter directly should key on one
    constant token value with many distinct code values instead, for
    materially higher precision.
references:
    - https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/
author: The Hunters Ledger
date: '2026-07-21'
tags:
    - attack.credential-access
    - attack.t1110.001
correlation:
    type: value_count
    rules:
        - password_reset_endpoint_request_base
    group-by:
        - c-ip
        - cs-uri-stem
    timespan: 10m
    condition:
        field: cs-uri-query
        gte: 50
falsepositives:
    - >-
        A misbehaving client retry loop or a load-testing script exercising
        the same endpoint. Uncommon in normal user behavior at this volume.
level: high
```

#### Newly Registered Account Probing Administrative Routes Within Minutes (Correlation)

**Tier:** Detection (correlation), bundled below with its 2 required Hunting-grade base rules, which do not alert on their own
**Robustness:** 2 (correlation) / 1 (each base rule individually)
**ATT&CK Coverage:** T1585 (Establish Accounts), T1078 (Valid Accounts)
**Confidence:** HIGH (correlation) / LOW (either base rule alone)
**False Positives:** A legitimate new employee or partner account being set up and then immediately granted admin access by design. Uncommon for a genuine self-service signup flow.
**Blind Spots:** An operator who registers the account from one source IP and probes admin routes from another (e.g. via a proxy or a serverless relay, both patterns observed elsewhere in this campaign) evades the `c-ip` grouping; misses probing that starts more than 15 minutes after registration.
**Validation:** Replay an account-registration POST followed by a request to one of the listed administrative routes from the same source IP within 15 minutes: the correlation must fire; either event alone must NOT trigger it.
**Deployment:** SIEM correlation engine ingesting web/proxy access-log telemetry.

```yaml
title: Application Account Registration Request
id: e346cdb5-37c0-4bda-a4ad-2f36fe22c0e2
name: account_registration_base
status: experimental
description: >-
    Base rule (not alerting on its own): an HTTP request to an account
    registration or signup endpoint. Ordinary and expected on any application
    with self-service signup. Paired below with a rule for sensitive
    administrative route probing and a correlation that flags the same
    source registering an account and then probing administrative routes
    within minutes, a standing technique observed reused across multiple
    targets: register a throwaway account, then use its token to walk admin,
    config and system-information routes.
references:
    - https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/
author: The Hunters Ledger
date: '2026-07-21'
tags:
    - attack.resource-development
    - attack.t1585
logsource:
    category: webserver
detection:
    selection:
        cs-method: POST
        cs-uri-stem|contains:
            - 'register'
            - 'signup'
    condition: selection
falsepositives:
    - >-
        Ordinary customer or user self-service account creation. Not
        alerting on its own; reviewed only in combination with the
        admin-route-probe rule via the correlation below.
level: informational
---
title: HTTP Request to a Sensitive Administrative or System-Information Route
id: bdad563c-44c7-45f1-9a39-d8a1d31081bf
name: sensitive_admin_route_probe_base
status: experimental
description: >-
    Base rule (not alerting on its own): an HTTP request to an
    administrative, configuration, debug or system-information API route.
    Legitimate admin users browse these routes routinely. Paired above with
    the account registration rule and a correlation that flags the same
    source registering a new account and then probing these routes within
    minutes, since administrative routes should not be the first thing a
    brand-new account touches.
references:
    - https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/
author: The Hunters Ledger
date: '2026-07-21'
tags:
    - attack.initial-access
    - attack.stealth
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1078
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains:
            - '/api/admin'
            - '/api/users'
            - '/api/config'
            - '/api/system/info'
            - '/api/debug'
    condition: selection
falsepositives:
    - >-
        A legitimate administrator's normal use of the application's own
        admin panel. Not alerting on its own; reviewed only in combination
        with the preceding registration event via the correlation rule.
level: informational
---
title: Newly Registered Account Probing Administrative Routes Within Minutes
id: bd3e7b1b-7a0c-4713-8f2b-8dcece54d8de
status: experimental
description: >-
    Fires when the same source registers an application account and then
    requests an administrative, configuration, debug or system-information
    route within 15 minutes. A brand-new self-service account has no
    legitimate reason to immediately probe administrative surfaces; this
    sequence was confirmed reused across multiple unrelated target platforms
    by the same operator, making it a standing technique rather than a
    one-off.
references:
    - https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/
author: The Hunters Ledger
date: '2026-07-21'
tags:
    - attack.resource-development
    - attack.t1585
    - attack.initial-access
    - attack.stealth
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1078
correlation:
    type: temporal_ordered
    rules:
        - account_registration_base
        - sensitive_admin_route_probe_base
    group-by:
        - c-ip
    timespan: 15m
falsepositives:
    - >-
        A legitimate new employee or partner account being set up and then
        immediately granted admin access by design. Uncommon for a genuine
        self-service signup flow.
level: high
```

### Hunting Rules

#### Single Source Touching Many Distinct Ports From a Fixed Service-Discovery Profile (Correlation)

**Tier:** Hunting
**Robustness:** 2 (correlation) / 1 (base rule individually)
**ATT&CK Coverage:** T1046 (Network Service Discovery)
**Confidence:** MODERATE
**False Positives:** Routine internal vulnerability scanning or asset-discovery tooling covering the same common service ports; the underlying ports are also touched individually by ordinary traffic and legitimate scanning. Confirm against known scanner IP ranges before treating as hostile.
**Deployment:** Firewall/flow-log correlation engine; useful as an early tripwire for a low-sophistication, unstealthy sweep rather than a standalone high-confidence alert.

```yaml
title: External Connection Attempt to a Service-Discovery-Profile Port
id: a3f1f3b3-98a1-402a-a979-bce509a2bfb1
name: firewall_scan_target_port_base
status: experimental
description: >-
    Base rule (not alerting on its own): an inbound connection attempt on one
    of a fixed 14-port profile this operator scans across multiple targets:
    22, 80, 443, 3306, 6379, 8080, 8443, 8888, 9000, 9001, 9002, 9090, 8848
    and 8157, a mix of standard admin, database and cache ports plus the
    Nacos and Druid management consoles this operator specifically exploits
    elsewhere. Paired below with a correlation that flags a single source
    touching many distinct ports from this profile within a short window.
references:
    - https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/
author: The Hunters Ledger
date: '2026-07-21'
tags:
    - attack.discovery
    - attack.t1046
logsource:
    category: firewall
detection:
    selection:
        dst_port:
            - 22
            - 80
            - 443
            - 3306
            - 6379
            - 8080
            - 8443
            - 8888
            - 9000
            - 9001
            - 9002
            - 9090
            - 8848
            - 8157
    condition: selection
falsepositives:
    - >-
        Routine internal vulnerability scanning or asset-discovery tooling
        covering the same common service ports. Not alerting on its own;
        reviewed only through the distinct-port-count threshold in the
        correlation rule below.
level: informational
---
title: Single Source Touching Many Distinct Ports From a Fixed Service-Discovery Profile
id: 3e5e5239-e952-41ef-a287-05ab2a6301fd
status: experimental
description: >-
    Fires when one source touches 8 or more of the 14 profiled ports within 5
    minutes, an aggressive, unstealthy service-discovery sweep rather than
    incidental traffic on one or two of these common ports. Low
    sophistication and easy to detect; useful as an early tripwire rather
    than a high-confidence standalone alert, since the underlying ports are
    also touched individually by ordinary traffic and legitimate scanning.
references:
    - https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/
author: The Hunters Ledger
date: '2026-07-21'
tags:
    - attack.discovery
    - attack.t1046
correlation:
    type: value_count
    rules:
        - firewall_scan_target_port_base
    group-by:
        - src_ip
    timespan: 5m
    condition:
        field: dst_port
        gte: 8
falsepositives:
    - >-
        An authorized internal vulnerability scanner or asset-inventory tool
        covering the same port profile. Confirm against known scanner IP
        ranges before treating as hostile.
level: medium
```

---

## Suricata Signatures

> **Validated against the real engine.** All 13 rules below were compiled against the live `suricata -T` (8.0.5) engine on the deployed sensor and accepted with zero errors. Two rules (Eureka Apps-Delta and the Druid network-layer check) were originally authored as single rules combining `http.uri` (request-side) with `http.response_body` (response-side), a combination the engine rejects, and were corrected to flowbits-linked setter/checker pairs; see each rule's Deployment note for the pairing requirement.

Network-layer coverage below intentionally duplicates a few techniques already covered by Sigma (Druid exposure); this is deliberate layered coverage, since a network IDS at the perimeter catches these independent of whether web/proxy access-log ingestion exists in a given environment. Every Suricata rule keys on a protocol- or payload-structure marker; none reference this operator's IP or infrastructure.

### Detection Rules

#### LDAP Anonymous BindRequest to a Non-Standard Directory Port

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1190 (Exploit Public-Facing Application)
**Confidence:** HIGH
**False Positives:** None known on ports 1389/1099 specifically: these are not standard LDAP/RMI-registry ports in most environments, so legitimate directory-service traffic is unlikely to appear there. An internal LDAP proxy or test harness deliberately using these ports would be the only expected exception.
**Blind Spots:** Only matches the anonymous/simple-bind, LDAPv3, empty-DN BER encoding captured in evidence; a bind using SASL, a non-empty DN, or LDAPv2 produces different bytes and will not match. Misses the technique entirely if the target server enforces TLS (LDAPS) before any bind bytes are sent in cleartext.
**Validation:** Replay a raw anonymous LDAPv3 BindRequest (`30 0c 02 01 01 60 07 02 01 03 04 00 80 00`) to TCP/1389 or TCP/1099: the rule must fire; the same byte sequence on TCP/389 (standard LDAP) must NOT fire, since this rule is deliberately scoped to the non-standard ports observed in evidence.
**Deployment:** Network IDS at the network egress point, positioned to see outbound application-server traffic.

```
alert tcp $HOME_NET any -> $EXTERNAL_NET [1389,1099] (msg:"THL DETECT MultiVector-192.3.1.116 LDAP Anonymous BindRequest to Non-Standard Directory Port (JNDI Callback Indicator)"; flow:established,to_server; content:"|30 0c 02 01 01 60 07 02 01 03 04 00 80 00|"; classtype:attempted-admin; sid:1000001; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-21, reference https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/;)
```

#### SnakeYAML Gadget Chain in HTTP Request Body

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1190 (Exploit Public-Facing Application)
**Confidence:** HIGH
**False Positives:** None known. Same reasoning as the YARA equivalent: no legitimate YAML document constructs a scripting engine via a remote class loader.
**Blind Spots:** Only matches the request body; a payload delivered via a different transport (raw TCP to a non-HTTP deserialization endpoint) is not covered. Misses obfuscated or split-tag variants.
**Validation:** Replay a POST containing both `!!javax.script.ScriptEngineManager` and `!!java.net.URLClassLoader` in the body: the rule must fire; an ordinary YAML/JSON POST body must NOT fire.
**Deployment:** Network IDS in front of Java application servers accepting YAML input.

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"THL DETECT MultiVector-192.3.1.116 SnakeYAML ScriptEngineManager Gadget Chain in HTTP Request Body (CVE-2022-1471 Family)"; flow:established,to_server; http.request_body; content:"!!javax.script.ScriptEngineManager"; content:"!!java.net.URLClassLoader"; classtype:attempted-user; sid:1000002; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-21, reference https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/;)
```

#### XXE Entity Declaration Targeting Cloud Metadata in Upload

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1190 (Exploit Public-Facing Application), T1552.005 (Cloud Instance Metadata API)
**Confidence:** HIGH
**False Positives:** None known. No legitimate uploaded XML/SVG document declares an external entity resolving to the cloud metadata address.
**Blind Spots:** Scoped to the cloud-metadata variant only; the internal-service variants observed in evidence (`127.0.0.1:6379`, `127.0.0.1:3306`, `:8080/actuator/`) share the same `<!ENTITY ... SYSTEM` structure and can be added as additional `content` alternatives by a defender extending this signature. Misses out-of-band/blind XXE that references an external DTD instead of embedding the target address directly.
**Validation:** Replay an upload containing `<!ENTITY xxe SYSTEM "http://169.254.169.254/...">`: the rule must fire; an ordinary SVG/XML upload with no entity declarations must NOT fire.
**Deployment:** Network IDS in front of any file-upload feature accepting XML or SVG.

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"THL DETECT MultiVector-192.3.1.116 XXE Entity Declaration Targeting Cloud Metadata in Upload"; flow:established,to_server; http.request_body; content:"<!ENTITY"; content:"SYSTEM"; content:"169.254.169.254"; classtype:attempted-admin; sid:1000003; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-21, reference https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/;)
```

#### Gopher-Scheme SSRF Protocol Smuggling in HTTP URI

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1190 (Exploit Public-Facing Application)
**Confidence:** HIGH
**False Positives:** None known. Modern browsers and clients do not construct `gopher://` URIs; its appearance in an HTTP URI parameter is a protocol-smuggling technique, not organic traffic.
**Blind Spots:** Misses the same technique if the gopher URI is percent-encoded (`gopher%3A%2F%2F`) or split across multiple parameters/requests.
**Validation:** Replay a request with `gopher://` inside a URI parameter: the rule must fire; a URI with no `gopher://` substring must NOT fire.
**Deployment:** Network IDS in front of any application feature that accepts a URL as a parameter (SSRF-prone image fetchers, webhook validators, OCR/preview services).

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"THL DETECT MultiVector-192.3.1.116 Gopher-Scheme SSRF Protocol Smuggling in HTTP URI"; flow:established,to_server; http.uri; content:"gopher://"; classtype:attempted-admin; sid:1000004; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-21, reference https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/;)
```

#### Gopher-Scheme SSRF Protocol Smuggling in HTTP Request Body

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1190 (Exploit Public-Facing Application)
**Confidence:** HIGH
**False Positives:** None known; same reasoning as the URI variant, applied to POST-body delivery.
**Blind Spots:** Same as the URI variant; misses percent-encoded or split delivery.
**Validation:** Replay a POST body containing `gopher://`: the rule must fire; an ordinary POST body with no `gopher://` substring must NOT fire.
**Deployment:** Network IDS in front of any application feature that accepts a URL in a POST body.

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"THL DETECT MultiVector-192.3.1.116 Gopher-Scheme SSRF Protocol Smuggling in HTTP Request Body"; flow:established,to_server; http.request_body; content:"gopher://"; classtype:attempted-admin; sid:1000005; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-21, reference https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/;)
```

#### SSRF-to-Redis CONFIG/BGSAVE Command Sequence via HTTP

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1190 (Exploit Public-Facing Application), T1098.004 (SSH Authorized Keys)
**Confidence:** HIGH
**False Positives:** None known. Raw Redis protocol verbs (`CONFIG SET dir`, `BGSAVE`) embedded inside an HTTP request body are not organic web traffic under any legitimate use this rule is aware of.
**Blind Spots:** Misses the technique if the operator uses a different Redis command sequence to the same effect (e.g. `MODULE LOAD` in newer Redis versions), or CRLF-encodes the commands in a way that splits them across the matched substrings.
**Validation:** Replay an HTTP POST body containing both `CONFIG SET dir` and `BGSAVE`: the rule must fire; an ordinary POST body must NOT fire.
**Deployment:** Network IDS in front of any application feature with a known or suspected SSRF vector (URL fetchers, OCR/image services, webhook validators).

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"THL DETECT MultiVector-192.3.1.116 SSRF-to-Redis CONFIG/BGSAVE Command Sequence via HTTP (SSH Key Write Chain)"; flow:established,to_server; http.request_body; content:"CONFIG SET dir"; content:"BGSAVE"; classtype:attempted-admin; sid:1000006; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-21, reference https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/;)
```

#### Eureka Apps-Delta Response Containing XStream Gadget Markers (Flowbits Pair)

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1190 (Exploit Public-Facing Application), T1105 (Ingress Tool Transfer)
**Confidence:** HIGH
**False Positives:** None known. A legitimate Eureka service registry never returns `java.lang.ProcessBuilder` inside an `/eureka/apps/delta` response body; this string only appears as an XStream deserialization gadget marker.
**Blind Spots:** Misses gadget chains built on a different marker class (`AnnotationInvocationHandler`, `PriorityQueue`, and others named in evidence but not repeated in this single rule); a defender should add those as OR'd companion rules for full coverage of the gadget-marker family.
**Validation:** Replay an `/eureka/apps/delta` request followed by a same-flow response containing `java.lang.ProcessBuilder` in the body: the checker rule must fire; the response alone on a flow where the setter never matched, or the request alone with a clean response, must NOT fire.
**Deployment:** Network IDS positioned to see traffic between an internal Eureka client and any Eureka registry, including external ones. **Ships as a linked flowbits pair, deploy both rules together.** `http.uri` (request-side) and `http.response_body` (response-side) cannot be combined in a single rule on the deployed Suricata engine (8.0.5), so the original single-rule design is split into a silent setter (sid:1000007, matches the `/eureka/apps/delta` request and sets flowbit `thl.mvec.eureka.delta`, `flowbits:noalert` so it never alerts on its own) and a checker (sid:1000008, matches the gadget marker in the response body of the same flow, but only if the setter's flowbit is set). **If sid:1000007 is not loaded, sid:1000008 will never fire**; it silently depends on its setter being present in the same ruleset.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL DETECT MultiVector-192.3.1.116 Eureka Apps-Delta Request (Flowbits Setter -- pairs with sid:1000008)"; flow:established,to_server; http.uri; content:"/eureka/apps/delta"; flowbits:set,thl.mvec.eureka.delta; flowbits:noalert; classtype:trojan-activity; sid:1000007; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-21, reference https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"THL DETECT MultiVector-192.3.1.116 Eureka Apps-Delta Response Containing XStream Gadget Markers (requires flowbits setter sid:1000007)"; flow:established,to_client; flowbits:isset,thl.mvec.eureka.delta; http.response_body; content:"java.lang.ProcessBuilder"; classtype:trojan-activity; sid:1000008; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-21, reference https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/;)
```

#### JWT alg-none Authentication Bypass Attempt

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1606.001 (Web Cookies, forged/manipulated web credential)
**Confidence:** HIGH
**False Positives:** None known. `eyJhbGciOiJub25lIn0` is the fixed, deterministic base64 encoding of the JSON header `{"alg":"none"}`; it is a mathematical constant of that exact header text, not an operator-specific string, and its presence in an `Authorization: Bearer` value is the signature of the well-documented "alg:none" JWT signature-bypass technique. No legitimately-issued production JWT uses an unsigned `none` algorithm.
**Blind Spots:** Misses the companion technique observed in this campaign (an HMAC-secret brute force that successfully forges a *signed* token with a guessed weak key), since a successfully-forged, properly-signed JWT is byte-for-byte indistinguishable from a legitimate one at the network layer (see Coverage Gaps).
**Validation:** Replay a request with header `Authorization: Bearer eyJhbGciOiJub25lIn0...`: the rule must fire; a normal signed `Authorization: Bearer eyJhbGciOiJIUzI1NiIs...` header must NOT fire.
**Deployment:** Network IDS or API gateway in front of any JWT-authenticated API.

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"THL DETECT MultiVector-192.3.1.116 JWT alg-none Authentication Bypass Attempt (Forged Token Header)"; flow:established,to_server; http.header; content:"Bearer eyJhbGciOiJub25lIn0"; classtype:attempted-admin; sid:1000009; rev:2; metadata:author The_Hunters_Ledger, date 2026-07-21, reference https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/;)
```

#### Unauthenticated External Access to Apache Druid Monitoring Console (Network Layer, Flowbits Pair)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1596.005 (Scan Databases)
**Confidence:** HIGH
**False Positives:** Authorized internal monitoring dashboards or an approved attack-surface scan. The `JavaClassPath` response-body check narrows this considerably compared to a bare URI match.
**Blind Spots:** Misses the exposure if the console is mounted under a non-default path, or if a proxy strips/alters the response body before it reaches the sensor.
**Validation:** Replay a GET to a `/druid/` path on a flow that then returns HTTP 200 with `JavaClassPath` in the response body: the checker rule must fire; the same request blocked with 401/403, or a `/druid/` request on a flow that never sets the setter's flowbit, must NOT fire.
**Deployment:** Network IDS at the perimeter, as a complement to the Sigma access-log rule for environments without centralized web-log ingestion. **Ships as a linked flowbits pair, deploy both rules together.** `http.uri` (request-side) and `http.response_body` (response-side) cannot be combined in a single rule on the deployed Suricata engine (8.0.5), so the original single-rule design is split into a silent setter (sid:1000010, matches the external `/druid/` request and sets flowbit `thl.mvec.druid.uri`, `flowbits:noalert` so it never alerts on its own) and a checker (sid:1000011, matches the 200-status, `JavaClassPath`-bearing response on the same flow, but only if the setter's flowbit is set). **If sid:1000010 is not loaded, sid:1000011 will never fire**; it silently depends on its setter being present in the same ruleset. This split also corrects a directionality slip in the original single-rule version, which mixed a request-only buffer into a response-direction (`to_client`) declaration; the setter below correctly matches the external client's request (`to_server`, since the victim's Druid console is the TCP server) and the checker matches the victim's response (`to_client`).

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"THL DETECT MultiVector-192.3.1.116 Apache Druid Console Path Request (Flowbits Setter -- pairs with sid:1000011)"; flow:established,to_server; http.uri; content:"/druid/"; flowbits:set,thl.mvec.druid.uri; flowbits:noalert; classtype:attempted-recon; sid:1000010; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-21, reference https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL DETECT MultiVector-192.3.1.116 Unauthenticated External Access to Apache Druid Monitoring Console (requires flowbits setter sid:1000010)"; flow:established,to_client; flowbits:isset,thl.mvec.druid.uri; http.stat_code; content:"200"; http.response_body; content:"JavaClassPath"; classtype:attempted-recon; sid:1000011; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-21, reference https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/;)
```

### Hunting Rules

#### Password-Reset Endpoint POST Burst (restPassword Variant)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1110.001 (Password Guessing)
**Confidence:** MODERATE
**False Positives:** A legitimate high-traffic password-reset flow, a retry loop in a buggy client, or load-testing traffic. Unlike the Sigma correlation equivalent, this rule's `threshold` counts raw match volume and cannot confirm that the requests are distinct (only that 50+ matched within the window), so it is coarser and kept at Hunting rather than Detection.
**Deployment:** Network IDS at the perimeter; review hits rather than auto-alert.

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"THL HUNT MultiVector-192.3.1.116 Password-Reset Endpoint POST Burst (restPassword Verification-Code Brute-Force Indicator)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"restPassword"; nocase; threshold:type threshold,track by_src,count 50,seconds 600; classtype:attempted-admin; sid:1000012; rev:2; metadata:author The_Hunters_Ledger, date 2026-07-21, reference https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/;)
```

#### Password-Reset Endpoint POST Burst (forgetPwd Variant)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1110.001 (Password Guessing)
**Confidence:** MODERATE
**False Positives:** Same as the `restPassword` variant above: a legitimate high-traffic reset flow or retry loop, kept at Hunting for the same coarse-volumetric reason.
**Deployment:** Network IDS at the perimeter; review hits rather than auto-alert.

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"THL HUNT MultiVector-192.3.1.116 Password-Reset Endpoint POST Burst (forgetPwd Verification-Code Brute-Force Indicator)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"forgetPwd"; nocase; threshold:type threshold,track by_src,count 50,seconds 600; classtype:attempted-admin; sid:1000013; rev:2; metadata:author The_Hunters_Ledger, date 2026-07-21, reference https://the-hunters-ledger.com/hunting-detections/multivector-ecommerce-rce-toolkit-192-3-1-116-detections/;)
```

---

## Coverage Gaps

**No file-hash coverage exists, because no malware sample exists.** This campaign is an exposed operator working directory, not an implant. There is no file-hash IOC list to carry, and no YARA rule in this file is hash-based; all five are payload-class signatures built on structural/behavioral markers. If a future investigation recovers an actual implant delivered through one of these exploitation chains, hash-based coverage belongs in that investigation's own IOC feed, not retrofitted here.

**Two sub-efforts produced confirmed negative outcomes; there is nothing to detect on the success side.** The AES-128-ECB decryption attempt against one individual's encrypted phone number and national ID (roughly 54,000 candidate keys tested across all three captured heap dumps) is a high-confidence negative; no rule can be written for a decryption that did not succeed. The Eureka/XStream RCE engagement against `1.13.253.113` is similarly unresolved: the operator's own port-7777 access log shows zero hits on the `xstream_rce_success` callback across ~17,000 lines, so no artifact exists to confirm the payload executed. The Suricata rule above for Eureka gadget markers detects the *delivery* of the hostile response (which is confirmed), not proof of successful code execution on the receiving end; that distinction should be preserved by any analyst reviewing a hit.

**The LDAP/JNDI chain never completed past the bind in either logged attempt**, so the only detectable event is the BindRequest itself (covered above). No rule exists for "successful JNDI payload delivery via LDAP search response" because no such completion was ever observed to model a signature against.

**Several techniques are only detectable at the victim's application layer, beyond what a third-party network/log-telemetry feed can reach:**

- **JWT forgery via a successfully brute-forced HMAC signing secret.** This campaign built two JWT-forgery variants: an `alg:none` bypass (covered above by a Suricata rule, since the unsigned-header base64 constant is a network-visible, deterministic marker) and a separate HMAC-secret brute force against a forged `role:"admin"` claim using a candidate list including the well-known `your-256-bit-secret` default. A JWT signed with a correctly-guessed key is byte-for-byte indistinguishable from a legitimately-issued one at the network layer; there is no external signal that separates it from a normal authenticated request. Detecting this requires the issuing application to log signing-key usage or reject known-weak default secrets outright; it is not visible to a perimeter feed.
- **HTTP 500 responses carrying a stack trace, absolute filesystem path, or deployment codename.** This is a real defensive-hygiene signal independent of any actor, but standard web-access-log telemetry (the `sc-status` field this file's Sigma rules rely on) does not capture response *body content*, only status codes and byte counts. A bare `sc-status: 500` selection would be far too broad to publish (every application has occasional legitimate 500s). Detecting the disclosure itself requires response-body inspection tied to the specific internal-path or stack-trace format of the target framework, which is application-specific and outside what this feed can generalize.
- **Structured numeric record-ID / IDOR enumeration** (the `001OI\d{6}20\d{6}\d{7,10}` order-ID scheme, and the `/api/engineer/detail?mid=` sequential-ID sweep observed on a different target). Both confirm the underlying platforms use predictable, enumerable identifiers, but the exact ID format is platform-specific; there is no generalizable signature that would not also need per-platform tuning to avoid matching normal sequential browsing. A defender operating the specific platform is better positioned to rate-limit or randomize these identifiers directly than a third-party feed is to signature them.
- **Reused Swagger/HTTP Basic Auth or database credentials.** The operator holds several credentials believed real and actively used (a MySQL password, a Redis password, HTTP Basic Auth for a Swagger docs endpoint); these are held in the campaign's IOC feed, not reproduced here, and there is no generalizable rule to write against "a correct password was used," since a valid credential produces indistinguishable traffic from its legitimate owner using it.

**A raw MySQL client authentication handshake preamble** was observed built inside a `gopher://` SSRF payload, but no concrete byte sequence for that specific handshake was captured with enough precision to anchor a dedicated signature beyond the `gopher://` scheme rule already covering the delivery mechanism. A defender with a captured sample of that exact handshake could extend the gopher-scheme Suricata rules above with a companion `content` match on the MySQL protocol preamble bytes.

**Six Spring Boot Actuator probes and two upload/preview probes were blocked cleanly by the target's own authentication filter, and a separate brute force was stopped by the target's own rate limiting at attempt 7 of 8.** These are not coverage gaps (they demonstrate existing defenses working as intended) but are noted here because they explain why this file does not attempt to build detection rules around those specific blocked endpoints: the observed outcome in each case was a defended surface, not a successful technique to model.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.

