---
title: "Detection Rules — Inkognito Russian VPN Phishing & Brand-Impersonation Infrastructure"
date: '2026-05-16'
layout: post
permalink: /hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/
thumbnail: /assets/images/cards/inkognito-russian-vpn-phishing-185-221-196-118-20260516.png
hide: true
---

**Campaign:** Inkognito-Russian-VPN-Phishing-185.221.196.118-20260516<br>
**Date:** 2026-05-16
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/inkognito-russian-vpn-phishing-185-221-196-118-20260516/

---

## Detection Coverage Summary

> **Scope note:** Inkognito (UTA-2026-009) is a web-application fraud operation — there are no PE binaries. Detection coverage is entirely at the network, DNS, proxy, and web-content-inspection layers. YARA rules target static web assets (JS bundle, brand-logo PNG, favicon SVG) scraped from the live operator infrastructure. This file does NOT duplicate Cluster A (BellaMain) or Cluster C (Rhadamanthys) detection content from the 2026-05-15 multi-cluster report.

| Rule Type | Count | MITRE Techniques Covered | Overall FP Risk |
|---|---|---|---|
| YARA | 3 | T1583.006, T1608.005, T1036.005 | LOW–MEDIUM |
| Sigma | 8 | T1583.001, T1071.001, T1036.005, T1656, T1566.002 | LOW–MEDIUM |
| Suricata | 5 | T1071.001, T1090.002, T1036.005 | LOW |

**Total rules:** 16 across three detection layers.

**Priority hierarchy:**
1. `SIG_Inkognito_KittenX_Tombstone` (Suricata) — operator decommission fingerprint, unique and directly pivots to additional infrastructure
2. `SIG_Inkognito_XAdminToken_Request` (Suricata) — custom admin-auth header, non-standard and high-fidelity
3. `sigma_inkognito_dns_brand_impersonation` (Sigma) — brand-impersonation subdomain hunts, high-fidelity for enterprise environments

---

## YARA Rules

> **Deployment note:** These YARA rules target static web assets served by the Inkognito operator — a JavaScript application bundle, a brand-logo PNG, and an SVG favicon. They are NOT PE-targeting rules (there are no Inkognito binaries). Deploy in web-proxy DLP pipelines, threat-hunting tools that scan cached web content, or endpoint DLP systems that inspect downloaded files. Memory-scanner deployment is not applicable.

```
/*
    Name: Inkognito Fraud Operation — Web Asset Detection
    Author: The Hunters Ledger
    Date: 2026-05-16
    Identifier: Inkognito-FraudOperation-WebAssets
    Reference: https://the-hunters-ledger.com/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/
    License: https://creativecommons.org/licenses/by/4.0/
*/
```

---

### MALW_Inkognito_JSBundle_VPN_SPA

**Detection Priority:** HIGH
**Rationale:** Detects the INK VPN Vite/React SPA production JS bundle by exact SHA256 hash and size. This bundle is the operator's primary application payload — not on VirusTotal as of 2026-05-07. Any web-proxy or DLP match on this hash identifies a client that fetched the INK VPN application from the operator's live infrastructure.
**ATT&CK Coverage:** T1036.005 (Masquerading: Match Legitimate Resource Name or Location), T1608.005 (Stage Capabilities: Link Target)
**Confidence:** HIGH
**False Positive Risk:** NONE — exact SHA256 hash match on a 261,587-byte file uniquely identifies this specific build artifact. Hash is not present on VirusTotal as of evidence cutoff.
**Deployment:** Web-proxy DLP pipeline; threat-hunting tool HTTP-response body hash comparison; endpoint DLP on downloaded-file hash.

```yara
rule MALW_Inkognito_JSBundle_VPN_SPA
{
    meta:
        description = "Detects the Inkognito INK VPN Vite/React SPA production JavaScript bundle (inkconnect.ru/assets/index-CoeWw2zM.js, 261,587 bytes). The operator's primary application payload — contains hardcoded API endpoint list, operator brand strings, and Russian-language taglines. Not found on VirusTotal as of 2026-05-07."
        author = "The Hunters Ledger"
        date = "2026-05-16"
        reference = "https://the-hunters-ledger.com/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/"
        hash_sha256 = "8a69fe67a7e9908aa1248c632ffd784033fc4dc613d0b5589279ccc62f717978"
        family = "Inkognito-FraudOperation"

    strings:
        $api_auth     = "/api/auth/login" ascii
        $api_vpn      = "/api/vpn-hosts" ascii
        $api_sub      = "/api/subscriptions" ascii
        $brand_ink    = "INK VPN" ascii
        $brand_inkogn = "Inkognito" ascii
        $bundle_name  = "index-CoeWw2zM.js" ascii
        $tagline_ru   = "\xd0\x9d\xd0\xb0\xd0\xb4\xd0\xb5\xd0\xb6\xd0\xbd\xd1\x8b\xd0\xb9 VPN \xd0\xbe\xd1\x82 Inkognito" ascii

    condition:
        filesize == 261587 and
        5 of ($api_auth, $api_vpn, $api_sub, $brand_ink, $brand_inkogn, $bundle_name, $tagline_ru)
}
```

---

### MALW_Inkognito_BrandLogo_PNG

**Detection Priority:** HIGH
**Rationale:** Exact hash match on the Inkognito hooded-figure-with-eye brand logo PNG. This asset is served at inkconnect.ru/logo.png and is the operator's primary visual brand identifier. A match indicates the INK VPN / Inkognito brand assets have been fetched or cached. Not on VirusTotal as of 2026-05-07.
**ATT&CK Coverage:** T1036.005 (Masquerading: Match Legitimate Resource Name or Location), T1656 (Impersonation)
**Confidence:** HIGH
**False Positive Risk:** NONE — exact SHA256 hash match uniquely identifies this specific image file.
**Deployment:** Web-proxy DLP pipeline; endpoint DLP on downloaded-file hash; threat-hunting tool HTTP-response body hash comparison.

```yara
rule MALW_Inkognito_BrandLogo_PNG
{
    meta:
        description = "Detects the Inkognito hooded-figure-with-eye brand logo PNG (inkconnect.ru/logo.png). Operator's primary visual brand identifier across the INK VPN and INK Lens product portfolio. Exact hash match — not on VirusTotal as of 2026-05-07."
        author = "The Hunters Ledger"
        date = "2026-05-16"
        reference = "https://the-hunters-ledger.com/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/"
        hash_sha256 = "d1ae63c928fd07d51cf79c5165e4431765201ca04a2bee3c309dc00092c4de7c"
        family = "Inkognito-FraudOperation"

    strings:
        $png_magic = { 89 50 4E 47 0D 0A 1A 0A }

    condition:
        filesize < 500KB and
        $png_magic at 0 and
        hash.sha256(0, filesize) == "d1ae63c928fd07d51cf79c5165e4431765201ca04a2bee3c309dc00092c4de7c"
}
```

---

### MALW_Inkognito_Favicon_SVG

**Detection Priority:** HIGH
**Rationale:** Detects the INK VPN favicon SVG by exact hash and SVG content characteristics. The favicon is a unique operator brand asset. An exact-hash rule catches the known file; the SVG-content strings provide a variant rule for modified versions that preserve the Inkognito branding markers. Not on VirusTotal as of 2026-05-07.
**ATT&CK Coverage:** T1036.005 (Masquerading: Match Legitimate Resource Name or Location)
**Confidence:** HIGH (exact hash) / MODERATE (string-only variant path)
**False Positive Risk:** LOW — SVG files matching Inkognito-specific brand strings combined with the operator domain reference are highly specific. Pure string-only path has MEDIUM FP risk if operator reuses SVG strings across variant domains.
**Deployment:** Web-proxy DLP pipeline; endpoint DLP on downloaded-file hash.

```yara
rule MALW_Inkognito_Favicon_SVG
{
    meta:
        description = "Detects the INK VPN favicon SVG (inkconnect.ru/favicon.svg) by exact SHA256 hash. The SVG contains Inkognito brand markers and is served as the browser-tab favicon across the operator's web fronts. Not on VirusTotal as of 2026-05-07. String conditions provide additional variant coverage if the operator modifies the file while retaining core brand markers."
        author = "The Hunters Ledger"
        date = "2026-05-16"
        reference = "https://the-hunters-ledger.com/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/"
        hash_sha256 = "53b3515fda56dbbd1f8071a9ef3dc3be80cb7994df22ce8afc2e79147e899b70"
        family = "Inkognito-FraudOperation"

    strings:
        $svg_open     = "<svg" ascii
        $brand_inkogn = "Inkognito" ascii nocase
        $brand_ink    = "INK" ascii
        $inkconnect   = "inkconnect" ascii nocase

    condition:
        filesize < 100KB and
        $svg_open at 0 and
        (
            hash.sha256(0, filesize) == "53b3515fda56dbbd1f8071a9ef3dc3be80cb7994df22ce8afc2e79147e899b70"
            or
            ($brand_inkogn and $brand_ink and $inkconnect)
        )
}
```

---

## Sigma Rules

> **Deployment note:** Sigma rules in this section target DNS resolver logs, web-proxy logs, and web-content-inspection pipelines. No Sysmon process-creation rules are included — Inkognito has no on-host malware execution surface. Translate rules to your SIEM query language using pySigma or Sigma CLI before deployment.

---

### sigma_inkognito_dns_brand_impersonation

**Detection Priority:** HIGH
**Rationale:** DNS query for any of the Inkognito brand-impersonation subdomains under inklens.ru or inklens.co.uk. These subdomains exist solely for fraudulent credential-harvest campaigns — there is no legitimate reason for an enterprise endpoint to query them. A match is high-fidelity regardless of whether the subdomain is currently returning 404 or a live phishing page, because the operator can activate any subdomain into a live credential-harvest endpoint with zero warning.
**ATT&CK Coverage:** T1566.002 (Phishing: Spearphishing Link), T1656 (Impersonation), T1036.005 (Masquerading)
**Confidence:** HIGH
**False Positive Risk:** LOW — these subdomains are operator-controlled and exist only for brand-impersonation use. No legitimate business application resolves wellsfargo.inklens.ru, owa2013.inklens.ru, or anydesk.inklens.ru.
**Deployment:** Windows DNS debug logs (Event ID 5158 / DNS Analytic), Zeek dns.log, Sysmon Event ID 22, Cloudflare Gateway, Cisco Umbrella.


```yaml
title: Inkognito Brand-Impersonation Subdomain DNS Query
id: 4a7b2e1d-8f3c-4a5b-9c0d-6e2f1a8b3c7d
status: test
description: >-
  Detects DNS queries for Inkognito operator brand-impersonation subdomains under inklens.ru
  and inklens.co.uk. The Inkognito fraud operator (UTA-2026-009) pre-stages 467+ subdomains
  targeting Wells Fargo, Tencent, AnyDesk, Outlook Web Access 2013, Jenkins, Asana, Tele2,
  and other enterprise/consumer brands. These subdomains have no legitimate use - any
  resolution from an enterprise endpoint is high-fidelity evidence of phishing link access.
references:
  - https://the-hunters-ledger.com/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/
author: The Hunters Ledger
date: 2026/05/16
tags:
  - attack.initial-access
  - attack.command-and-control
logsource:
  category: dns_query
  product: windows
detection:
  selection_brand_impersonation:
    QueryName|contains:
      - wellsfargo.inklens.ru
      - accenture.inklens.ru
      - adyen-no-stripe.inklens.ru
      - asana.inklens.ru
      - tele2.inklens.ru
      - tencent.inklens.ru
      - sina.inklens.ru
      - siri-search.inklens.ru
      - stanley.inklens.ru
      - rafael.inklens.ru
      - anydesk.inklens.ru
      - autodiscover.blog.inklens.ru
      - owa2013.inklens.ru
      - espace-client.inklens.ru
      - swdcdownloads.inklens.ru
      - development-jenkins.inklens.ru
      - signals.inklens.ru
      - connect-pro-portal.inklens.ru
      - democrm.inklens.ru
      - demo-insights.inklens.ru
      - travel.inklens.ru
      - travelid.inklens.ru
      - weatherzone.inklens.ru
      - e-shop.inklens.ru
      - onlineforms.inklens.ru
  condition: selection_brand_impersonation
falsepositives:
  - Security researchers or threat hunters explicitly querying these subdomains for investigation purposes
  - Automated scanner infrastructure probing known-bad domain lists
level: high
```

---

### sigma_inkognito_dns_operator_domains

**Detection Priority:** HIGH
**Rationale:** DNS query for any confirmed Inkognito operator apex domain or infrastructure subdomain. Operator domains have no legitimate enterprise use. Queries may indicate phishing link clicks, VPN enrollment (employee using an operator-sold VPN service), or active communication through an operator-controlled proxy.
**ATT&CK Coverage:** T1071.001 (Application Layer Protocol: Web Protocols), T1090.003 (Multi-hop Proxy)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM - inkconnect.ru and unloki.ru are commercial VPN brands. Employees who have independently subscribed to the INK VPN or Unloki VPN services will generate queries. Tune by correlating with HR-approved VPN vendor list; flag unlisted queries.
**Deployment:** Windows DNS debug logs, Zeek dns.log, Sysmon Event ID 22, Cloudflare Gateway, Cisco Umbrella.

```yaml
title: Inkognito Operator Infrastructure Domain DNS Query
id: 9c3d5f2a-1b4e-4d7c-8a6f-3e0b2c9d4f1e
status: test
description: >-
  Detects DNS queries for confirmed Inkognito operator-controlled domains including the INK
  VPN flagship (inkconnect.ru), phishing infrastructure (inklens.ru), fake crypto exchange
  (cryptone.bot), Marzban VPN panel (marzban.inklens.co.uk), and long-term VPN brands
  (unloki.ru, bigass.monster). Inkognito is a Russian-speaking multi-product fraud operator
  (UTA-2026-009) with 0/92 VirusTotal detections as of 2026-05-07. Commercial VPN front
  may generate legitimate queries from subscribed employees.
references:
  - https://the-hunters-ledger.com/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/
author: The Hunters Ledger
date: 2026/05/16
tags:
  - attack.command-and-control
  - attack.initial-access
logsource:
  category: dns_query
  product: windows
detection:
  selection_operator_subdomains:
    QueryName|endswith:
      - .inkconnect.ru
      - .inklens.ru
      - .inklens.co.uk
      - .bikaf.ru
      - .unloki.ru
      - .bigass.monster
  selection_operator_apex:
    QueryName|contains:
      - inkconnect.ru
      - inklens.ru
      - cryptone.bot
      - bikaf.ru
      - unloki.ru
      - bigass.monster
      - 00000xtrading.ru
  condition: 1 of selection_*
falsepositives:
  - Employees who have independently enrolled in the INK VPN or Unloki VPN commercial service
  - Security researchers investigating the Inkognito operator cluster
  - Automated domain reputation scanners processing IOC feeds
level: medium
```

---

### sigma_inkognito_proxy_kittenx_tombstone

**Detection Priority:** HIGH
**Rationale:** Detects the Inkognito operator decommission tombstone HTTP signature: Server header kittenx + HTTP 404 + Content-Length 148. This exact combination is the operator standard retired domain marker, observed on at least two decommissioned Inkognito domains (00000xtrading.ru, bikaf.ru). Any other domain returning this triplet is a strong candidate for additional operator-controlled decommissioned infrastructure not yet linked to the known brand portfolio.
**ATT&CK Coverage:** T1583.001 (Acquire Infrastructure: Domains), T1583.004 (Server)
**Confidence:** HIGH
**False Positive Risk:** LOW - the kittenx web server is not a commodity server (not nginx, Apache, Caddy, IIS, or any common framework). The specific combination with 404 and content-length 148 has not been observed outside Inkognito infrastructure.
**Deployment:** Web-proxy logs, Zeek http.log, Suricata (see companion Suricata rule for network-layer detection).

```yaml
title: Inkognito Operator KittenX Decommission Tombstone HTTP Response
id: 7f1a3c8b-2d5e-4b9a-8c0f-1e6d3a7b2c4f
status: test
description: >-
  Detects the Inkognito fraud operator standard HTTP decommission tombstone: a response with
  Server header value kittenx, HTTP status 404, and Content-Length 148. This signature is
  applied to retired Inkognito-controlled domains (observed on 00000xtrading.ru and bikaf.ru
  after decommission). Any domain returning this exact triplet is a candidate for additional
  Inkognito infrastructure not yet linked to the known brand portfolio. The kittenx server
  is not a commodity web server and is absent from any public open-source project index.
references:
  - https://the-hunters-ledger.com/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/
author: The Hunters Ledger
date: 2026/05/16
tags:
  - attack.resource-development
  - attack.defense-evasion
logsource:
  category: proxy
  product: windows
detection:
  selection_kittenx_response:
    sc-status: 404
    r-server: kittenx
    sc-bytes: 148
  condition: selection_kittenx_response
falsepositives:
  - Any legitimate application or CDN service that happens to use a web server named kittenx (no known instances as of 2026-05-16)
  - Security scanners replaying captured Inkognito HTTP responses in test environments
level: high
```

---

### sigma_inkognito_proxy_xadmintoken

**Detection Priority:** HIGH
**Rationale:** Detects any outbound HTTP request or CORS response carrying the custom X-Admin-Token header. This header is not defined by any public RFC - the Inkognito operator added it to the CORS allow-list of api.inkconnect.ru as their admin API authentication primitive. Any external domain accepting or returning X-Admin-Token is a strong cluster-expansion candidate for additional operator-controlled API infrastructure.
**ATT&CK Coverage:** T1071.001 (Application Layer Protocol: Web Protocols), T1583.004 (Server)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM - X-Admin-Token is a custom header any developer could independently invent. Tune to external destinations only in large enterprise environments with internally-developed APIs.
**Deployment:** Web-proxy logs with header inspection enabled, Zeek http.log, WAF logs (AWS WAF, Cloudflare WAF, Zscaler). Requires proxy with full-header logging enabled.

```yaml
title: HTTP Request or Response Carrying Custom X-Admin-Token Header
id: 2e8d4f6a-3c7b-4a1d-9e5f-8b0c2d6a4f3e
status: test
description: >-
  Detects HTTP requests or CORS responses carrying the custom X-Admin-Token header, the
  Inkognito fraud operator admin API authentication primitive exposed via CORS configuration
  on api.inkconnect.ru. This header is not defined in any public RFC and is absent from any
  major web framework defaults. Any external domain accepting or returning this header is a
  strong expansion candidate for additional Inkognito-controlled API infrastructure. Tune
  to external destinations only in environments with internally-developed APIs using this
  header name.
references:
  - https://the-hunters-ledger.com/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/
author: The Hunters Ledger
date: 2026/05/16
tags:
  - attack.command-and-control
  - attack.resource-development
logsource:
  category: proxy
  product: windows
detection:
  selection_xadmin_request:
    cs-headers|contains: X-Admin-Token
  selection_xadmin_cors_response:
    sc-headers|contains: X-Admin-Token
  condition: 1 of selection_*
falsepositives:
  - Internally-developed web applications that independently use X-Admin-Token as a custom auth header name
  - Developer workstations testing API endpoints during authorized threat hunting exercises
  - Security research or penetration testing of Inkognito-controlled domains
level: medium
```

---

### sigma_inkognito_webcontent_yandex_verification

**Detection Priority:** HIGH
**Rationale:** Detects any web page carrying the Inkognito operator Yandex Webmaster verification ID 98466329 in an HTML meta tag. This ID is tied to a specific operator-controlled Yandex account and was recovered from inklens.ru HTML. Any page carrying this exact verification tag is operator-controlled and not yet catalogued in the known IOC feed.
**ATT&CK Coverage:** T1585.003 (Establish Accounts: Cloud Accounts), T1608.005 (Stage Capabilities: Link Target)
**Confidence:** HIGH
**False Positive Risk:** LOW - Yandex Webmaster verification IDs are unique to the account that generated them. Collision probability with a legitimate site is negligible.
**Deployment:** Web-proxy content inspection (TLS-inspecting proxy with HTML body parsing enabled), internal site-audit tooling, Censys/Shodan automated HTTP search.

```yaml
title: Inkognito Operator Yandex Webmaster Verification ID in HTTP Response Body
id: 3a6d9c1f-5e2b-4f7a-8d0c-2b4e7f1a9c5d
status: test
description: >-
  Detects HTTP responses from a TLS-inspecting proxy containing the Inkognito operator
  Yandex Webmaster verification meta tag (content value 98466329). This ID is tied to an
  operator-controlled Yandex account recovered from inklens.ru HTML. Any domain serving
  this tag is operator-controlled and not yet catalogued in the known Inkognito IOC feed.
  This is the highest-value HTML-level cluster-expansion detection for surfacing previously
  unknown operator-controlled domains.
references:
  - https://the-hunters-ledger.com/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/
author: The Hunters Ledger
date: 2026/05/16
tags:
  - attack.resource-development
logsource:
  category: proxy
  product: windows
detection:
  selection_yandex_meta:
    sc-body|contains|all:
      - yandex-verification
      - '98466329'
  condition: selection_yandex_meta
falsepositives:
  - Yandex Webmaster ID collision with a different operator account (negligible probability)
  - Security researchers hosting a copy of inklens.ru HTML in a controlled lab environment
level: high
```

---

### sigma_inkognito_proxy_inkconnect_api_auth

**Detection Priority:** HIGH
**Rationale:** Detects outbound HTTP requests to the INK VPN backend authentication endpoint at api.inkconnect.ru. Enterprise endpoint traffic indicates either an employee enrolled in the operator VPN service or, in higher-risk scenarios, a phishing victim submitting credentials to the operator backend.
**ATT&CK Coverage:** T1071.001 (Application Layer Protocol: Web Protocols), T1657 (Financial Theft), T1566.002 (Phishing: Spearphishing Link)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM - employees who have independently subscribed to INK VPN will generate authentication traffic to this endpoint. Correlate with known-enrolled employee VPN vendor list.
**Deployment:** Web-proxy logs with URL inspection, Zeek http.log.

```yaml
title: HTTP Request to Inkognito INK VPN Backend Authentication Endpoint
id: 8f4c1a2e-7d3b-4e6f-9a0c-5b8d2f4e1c7a
status: test
description: >-
  Detects outbound HTTP requests to the Inkognito INK VPN backend API login endpoint at
  api.inkconnect.ru. This endpoint handles user authentication for the INK VPN commercial
  service operated by the Inkognito fraud operator (UTA-2026-009). Traffic indicates either
  an employee enrolled in the operator VPN service or, in higher-severity scenarios,
  credential submission from a phishing victim. The operator integrates Russian payment
  systems (SBP, T-Pay) and is not an approved enterprise VPN vendor.
references:
  - https://the-hunters-ledger.com/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/
author: The Hunters Ledger
date: 2026/05/16
tags:
  - attack.initial-access
  - attack.credential-access
logsource:
  category: proxy
  product: windows
detection:
  selection_api_auth:
    r-dns|endswith: api.inkconnect.ru
    cs-uri-stem|startswith: /api/auth
  selection_inkconnect_auth:
    r-dns|endswith: inkconnect.ru
    cs-uri-stem|contains: /api/auth/login
  condition: 1 of selection_*
falsepositives:
  - Employees who have independently subscribed to the INK VPN commercial service
  - Security researchers testing Inkognito operator infrastructure during authorized investigation
level: high
```

---

### sigma_inkognito_dns_cryptone

**Detection Priority:** HIGH
**Rationale:** Detects DNS queries for cryptone.bot, the Inkognito operator fake cryptocurrency exchange. Victim visits indicate potential onboarding to a fraudulent exchange that is expected to steal deposited crypto assets. No legitimate financial institution operates under this brand or TLD.
**ATT&CK Coverage:** T1657 (Financial Theft), T1656 (Impersonation), T1036.005 (Masquerading)
**Confidence:** HIGH
**False Positive Risk:** LOW - cryptone.bot has no legitimate use. The .bot TLD under a cryptocurrency brand name not associated with any registered exchange is a strong FP-reduction filter.
**Deployment:** Windows DNS debug logs, Zeek dns.log, Sysmon Event ID 22, Cloudflare Gateway.

```yaml
title: DNS Query for Inkognito CryptOne Fake Cryptocurrency Exchange
id: 1d7e3b9f-6a2c-4f8d-b1e5-9c0f4a7b2e8d
status: test
description: >-
  Detects DNS queries for cryptone.bot, the Inkognito fraud operator fake cryptocurrency
  exchange registered 2026-03-02 and Cloudflare-fronted with Turnstile bot challenge.
  Victims onboarding to this exchange risk theft of deposited cryptocurrency assets.
  No legitimate financial institution or registered exchange operates under this domain.
  Any enterprise endpoint resolving cryptone.bot warrants high-priority phishing investigation.
references:
  - https://the-hunters-ledger.com/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/
author: The Hunters Ledger
date: 2026/05/16
tags:
  - attack.impact
  - attack.initial-access
logsource:
  category: dns_query
  product: windows
detection:
  selection_cryptone:
    QueryName|contains: cryptone.bot
  condition: selection_cryptone
falsepositives:
  - Security researchers investigating the Inkognito operator cluster or the CryptOne fake exchange
  - Automated threat intelligence scanners resolving known-bad domains from IOC feeds
level: high
```

---

## Suricata Signatures

> **Deployment note:** All HTTP rules use the `http` application-layer keyword with destination port `any` per the workflow standard — Suricata matches by protocol recognition, not port number. SNI rules use `tls` keyword for TLS-layer matching. Rules targeting operator-specific response headers (kittenx, Caddy) are highest-confidence; IP-based rules should be combined with the operator domain/SNI rules to reduce false positives from IP reassignment. All SIDs are in the 9001000-9001999 range (local deployment range).

---

### SIG_Inkognito_KittenX_Tombstone_Response

**Detection Priority:** HIGH
**Rationale:** Detects the Inkognito operator decommission tombstone at the network layer: HTTP response with Server header "kittenx", status 404, and Content-Length 148. This rule is the network-layer complement to the Sigma proxy rule. It fires on any outbound HTTP session where the remote server returns this exact signature, enabling pivot to additional operator-controlled decommissioned infrastructure.
**ATT&CK Coverage:** T1583.001 (Acquire Infrastructure: Domains), T1583.004 (Server)
**Confidence:** HIGH
**False Positive Risk:** LOW - "kittenx" is not a known commodity web server. The triplet (kittenx + 404 + content-length 148) has not been observed outside Inkognito infrastructure.
**Deployment:** Suricata IDS/IPS at perimeter or inline network tap; Zeek complement via http.log.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (\
    msg:"THE HUNTERS LEDGER - Inkognito Operator KittenX Decommission Tombstone Response"; \
    flow:established,to_server; \
    http.method; content:"GET"; \
    flowbits:set,inkognito.kittenx.request; \
    flowbits:noalert; \
    sid:9001001; rev:1; \
    classtype:trojan-activity; \
    metadata:affected_product Web_Browser, attack_target Client_Endpoint, \
              created_at 2026_05_16, deployment Perimeter, \
              signature_severity Major, tag Inkognito;)

alert http $EXTERNAL_NET any -> $HOME_NET any (\
    msg:"THE HUNTERS LEDGER - Inkognito Operator KittenX Decommission Tombstone Response"; \
    flow:established,to_client; \
    http.response_line; content:"404"; \
    http.header; content:"Server: kittenx"; nocase; \
    http.header; content:"Content-Length: 148"; \
    sid:9001002; rev:1; \
    classtype:trojan-activity; \
    metadata:affected_product Web_Browser, attack_target Client_Endpoint, \
              created_at 2026_05_16, deployment Perimeter, \
              signature_severity Major, tag Inkognito;)
```

---

### SIG_Inkognito_XAdminToken_Request

**Detection Priority:** HIGH
**Rationale:** Detects any outbound HTTP request carrying the custom X-Admin-Token header. This non-standard header is the Inkognito operator admin API authentication primitive exposed on api.inkconnect.ru. Network-level detection fires regardless of which domain is being accessed, enabling cluster expansion to operator-controlled API surfaces not in the known IOC feed.
**ATT&CK Coverage:** T1071.001 (Application Layer Protocol: Web Protocols), T1583.004 (Server)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM - X-Admin-Token is a custom header that could be used by other developers. Tune with a threshold statement for high-traffic environments.
**Deployment:** Suricata IDS/IPS at perimeter or inline; tune to external-only traffic (exclude RFC1918 destinations).

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (\
    msg:"THE HUNTERS LEDGER - Inkognito Operator Custom X-Admin-Token Header in HTTP Request"; \
    flow:established,to_server; \
    http.header; content:"X-Admin-Token"; nocase; \
    sid:9001003; rev:1; \
    classtype:trojan-activity; \
    metadata:affected_product Web_Browser, attack_target Client_Endpoint, \
              created_at 2026_05_16, deployment Perimeter, \
              signature_severity Major, tag Inkognito;)
```

---

### SIG_Inkognito_XAdminToken_CORS_Response

**Detection Priority:** HIGH
**Rationale:** Detects HTTP responses containing X-Admin-Token in the Access-Control-Allow-Headers CORS header. This is the operator's characteristic CORS fingerprint observed on api.inkconnect.ru. A match on any other domain indicates additional operator-controlled API infrastructure not yet linked to the brand portfolio.
**ATT&CK Coverage:** T1071.001 (Application Layer Protocol: Web Protocols), T1583.004 (Server)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM - same header-name collision risk as the request rule. Externally-facing traffic only.
**Deployment:** Suricata IDS/IPS at perimeter; requires inline traffic inspection for HTTPS (TLS inspection or plain HTTP).

```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (\
    msg:"THE HUNTERS LEDGER - Inkognito Operator X-Admin-Token in CORS Allow-Headers Response"; \
    flow:established,to_client; \
    http.header; content:"Access-Control-Allow-Headers"; nocase; \
    http.header; content:"X-Admin-Token"; nocase; \
    sid:9001004; rev:1; \
    classtype:trojan-activity; \
    metadata:affected_product Web_Browser, attack_target Client_Endpoint, \
              created_at 2026_05_16, deployment Perimeter, \
              signature_severity Major, tag Inkognito;)
```

---

### SIG_Inkognito_Via_Caddy_Operator_IPs

**Detection Priority:** MEDIUM
**Rationale:** Detects HTTP responses carrying the "Via: 1.1 Caddy" reverse-proxy header from known Inkognito operator infrastructure IP addresses. Caddy is the operator's consistent reverse-proxy component. The rule is IP-scoped to reduce false positives from Caddy used by unrelated legitimate sites. Fires on the response path to catch Caddy from the operator's IPs regardless of domain.
**ATT&CK Coverage:** T1071.001 (Application Layer Protocol: Web Protocols), T1090.002 (Proxy: External Proxy)
**Confidence:** MODERATE - Caddy is common; IP-scoping to confirmed operator addresses raises confidence.
**False Positive Risk:** LOW when IP-scoped to confirmed operator addresses. MEDIUM risk if Aeza/Timeweb reassign the IPs after operator departure.
**Deployment:** Suricata IDS/IPS at perimeter. Update operator IP list as new infrastructure IPs are confirmed.

```suricata
alert http [185.221.196.118,176.124.211.174,77.239.101.23,193.46.56.182,79.137.203.87] any -> $HOME_NET any (\
    msg:"THE HUNTERS LEDGER - Inkognito Operator Via Caddy Header from Known Operator IPs"; \
    flow:established,to_client; \
    http.header; content:"Via"; http.header; content:"1.1 Caddy"; nocase; \
    sid:9001005; rev:1; \
    classtype:trojan-activity; \
    metadata:affected_product Web_Browser, attack_target Client_Endpoint, \
              created_at 2026_05_16, deployment Perimeter, \
              signature_severity Minor, tag Inkognito;)
```

---

### SIG_Inkognito_TLS_SNI_Operator_Domains

**Detection Priority:** HIGH
**Rationale:** Detects TLS connections with SNI matching confirmed Inkognito operator domains. Fires on outbound TLS from enterprise endpoints to the operator's VPN, phishing, back-office, and fake-exchange infrastructure. SNI-based detection is effective even when the IP destination is Cloudflare-fronted (cryptone.bot) because the SNI is sent in plaintext during the TLS handshake.
**ATT&CK Coverage:** T1071.001 (Application Layer Protocol: Web Protocols), T1090.002 (Proxy: External Proxy), T1090.003 (Multi-hop Proxy)
**Confidence:** HIGH
**False Positive Risk:** LOW - confirmed operator domains with no legitimate enterprise use. MEDIUM for inkconnect.ru and unloki.ru (commercial VPN brands with potential employee subscribers).
**Deployment:** Suricata IDS/IPS at perimeter; TLS inspection not required (SNI is sent pre-handshake in ClientHello). Highest-priority Suricata rule in this set.

```suricata
alert tls $HOME_NET any -> $EXTERNAL_NET any (\
    msg:"THE HUNTERS LEDGER - Inkognito Operator Domain TLS SNI Match"; \
    flow:established,to_server; \
    tls.sni; content:"inkconnect.ru"; endswith; nocase; \
    sid:9001006; rev:1; \
    classtype:trojan-activity; \
    metadata:affected_product Web_Browser, attack_target Client_Endpoint, \
              created_at 2026_05_16, deployment Perimeter, \
              signature_severity Major, tag Inkognito;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (\
    msg:"THE HUNTERS LEDGER - Inkognito Operator INK Lens Domain TLS SNI Match"; \
    flow:established,to_server; \
    tls.sni; content:"inklens.ru"; endswith; nocase; \
    sid:9001007; rev:1; \
    classtype:trojan-activity; \
    metadata:affected_product Web_Browser, attack_target Client_Endpoint, \
              created_at 2026_05_16, deployment Perimeter, \
              signature_severity Major, tag Inkognito;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (\
    msg:"THE HUNTERS LEDGER - Inkognito Operator INK Lens UK Domain TLS SNI Match"; \
    flow:established,to_server; \
    tls.sni; content:"inklens.co.uk"; endswith; nocase; \
    sid:9001008; rev:1; \
    classtype:trojan-activity; \
    metadata:affected_product Web_Browser, attack_target Client_Endpoint, \
              created_at 2026_05_16, deployment Perimeter, \
              signature_severity Major, tag Inkognito;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (\
    msg:"THE HUNTERS LEDGER - Inkognito CryptOne Fake Exchange TLS SNI Match"; \
    flow:established,to_server; \
    tls.sni; content:"cryptone.bot"; endswith; nocase; \
    sid:9001009; rev:1; \
    classtype:trojan-activity; \
    metadata:affected_product Web_Browser, attack_target Client_Endpoint, \
              created_at 2026_05_16, deployment Perimeter, \
              signature_severity Critical, tag Inkognito;)

alert tls $HOME_NET any -> $EXTERNAL_NET any (\
    msg:"THE HUNTERS LEDGER - Inkognito Operator Unloki VPN Domain TLS SNI Match"; \
    flow:established,to_server; \
    tls.sni; content:"unloki.ru"; endswith; nocase; \
    sid:9001010; rev:1; \
    classtype:trojan-activity; \
    metadata:affected_product Web_Browser, attack_target Client_Endpoint, \
              created_at 2026_05_16, deployment Perimeter, \
              signature_severity Major, tag Inkognito;)
```

---

## Coverage Gaps

### Gap 1: No PE/Binary YARA Rules

**Status:** Intentional — not a gap in detection methodology.

Inkognito has no PE binary samples. The operator runs a web-application stack (Vite/React SPA, nginx + Caddy reverse-proxy, EspoCRM back-office, Marzban Xray/V2Ray panel). There are no executables, DLLs, shellcode stubs, or malware droppers to write YARA binary patterns for. The three YARA rules in this file target web-asset file types (JavaScript bundle, PNG, SVG) — this is the correct coverage posture for a web-application fraud operation.

**What would enable binary YARA coverage:** Discovery of a PE binary associated with the Inkognito operator (a VPN client installer, a downloader, or a credential-stealer deployed against phishing victims). None were recovered in this investigation.

### Gap 2: 467+ Subdomain Inventory Partial Coverage

**Status:** Gap — DNS Sigma rules cover 25 enumerated brand-impersonation subdomains; the full operator inventory exceeds 467.

The DomainTools reverse-IP enumeration on the operator's previous U1host endpoint (77.239.101.23) recovered 468 unique inklens.ru rrnames. The current Timeweb host (176.124.211.174) holds 165 with 95 new subdomains added post-migration. The Sigma rule `sigma_inkognito_dns_brand_impersonation` includes the 25 highest-value brand-impersonation subdomains documented in the malware-analyst output but does not enumerate the full 467+ set.

**What would enable full coverage:** Export of the complete subdomain inventory from DomainTools (or equivalent PDNS source) for all operator-controlled *.inklens.ru rrnames. The Sigma rule QueryName|contains list can be extended to include all enumerated subdomains. A higher-coverage alternative is a wildcard DNS detection on the parent zone: any DNS query with QueryName ending in `.inklens.ru` that does not match an operator-side DevOps subdomain pattern (staging-, uat-, prod-, argo-cd, redis-commander, etc.) is a high-fidelity brand-impersonation indicator.

**Wildcard detection recommendation (supplemental — partial snippet, not a complete rule):**
```text
# Supplemental: wildcard inklens.ru DNS query (all subdomains)
# Deploy if DNS logging supports wildcard matching without significant FP from
# operator-side DevOps subdomains (staging-agent, uat-analytics, etc.)
# Drop into the `detection:` block of any DNS-querytype Sigma rule:
detection:
  selection_wildcard:
    QueryName|endswith: .inklens.ru
  filter_known_devops:
    QueryName|startswith:
      - staging-
      - uat-
      - prod-
      - redis-
      - argo-
      - dashboard-
      - report-sandbox
      - cloud-test
  condition: selection_wildcard and not filter_known_devops
```

### Gap 3: Live JARM Hash Not Recovered

**Status:** Gap — JARM fingerprinting of operator TLS stack not completed.

JARM (https://github.com/salesforce/jarm) produces a deterministic fingerprint of a TLS server's implementation from its handshake response. The Inkognito operator's nginx + Caddy stack would produce a distinctive JARM hash recoverable by active probing of the live endpoints (185.221.196.118, 176.124.211.174). A JARM hash provides a passive TLS-layer pivot for surfacing additional operator-controlled servers not linked to the known domain/IP inventory.

**What would enable JARM coverage:** Active JARM probe of operator IPs 185.221.196.118 and 176.124.211.174. Note that inklens.ru deliberately rejects non-browser TLS clients (tlsv1 alert internal error) — JARM probing of that host may return a rejection fingerprint rather than the full stack JARM. VirusTotal MCP JARM lookup on inkconnect.ru (Cloudflare-fronted) would return a Cloudflare JARM, not the operator's backend JARM.

### Gap 4: BEC Burn-Domain WHOIS SOA Monitoring

**Status:** Partial gap — behavioral indicator documented; automated WHOIS monitoring rule not producible in Sigma/Suricata format.

The operator's BEC burn-domain WHOIS fingerprint (`admin@<domain>.eu` SOA email on .eu domains hosted on Stark Industries AS44477/AS209847) is documented in the stage1 analysis but cannot be expressed as a standard Sigma or Suricata rule because WHOIS SOA data is not captured in standard enterprise log sources (DNS logs do not include WHOIS SOA fields).

**What would enable coverage:** Integration with a WHOIS monitoring feed (DomainTools Iris Monitor, SecurityTrails API) that can alert on new .eu domain registrations where the SOA email matches the `admin@*.eu` pattern AND the authoritative NS points to Stark Industries IP ranges (193.46.56.0/24, 77.239.101.0/24). This is a proactive threat-intel feed task, not an endpoint/network detection task.

### Gap 5: Google Search Console TXT Record Pivot

**Status:** Gap — infrastructure pivot documented; no standard Sigma/Suricata rule type applicable.

The two operator-controlled Google Search Console verification TXT records (`_Lq_FX-CDt3OmZqq5PNFfmQTZtLSHTNsVkViLTzpTwk` for inkconnect.ru and `xskfj4k4tX_-enfPvu9WrUiWauHFlbuVmyV7thcjwds` for inklens.ru) are high-value pivots for surfacing additional operator-controlled domains where the operator verified the same Google account. These are DNS TXT records queried via external DNS resolvers — not observable in standard enterprise DNS query logs because they are not triggered by victim browsing activity.

**What would enable coverage:** SecurityTrails / Censys TXT record reverse-lookup for both verification strings. New operator domains where the same Google account is verified would surface as sibling infrastructure.

### Gap 6: CryptOne Fake Exchange — Origin IP Not Recovered

**Status:** Gap — Cloudflare-fronted origin not demasked.

The CryptOne fake exchange at cryptone.bot is fully Cloudflare-fronted with a Turnstile bot challenge. The operator's origin IP behind the Cloudflare proxy was not recovered from passive DNS history (domain registered 2026-03-02; Cloudflare fronting in place from first observation). Suricata SNI-based detection fires on the Cloudflare edge, not the operator origin — so the network-layer detection is complete, but the origin IP for direct-IP blocking is not available.

**What would enable coverage:** Origin demasking via certificate transparency logs (search for TLS certificates issued to cryptone.bot before Cloudflare fronting was applied — narrow window between 2026-03-02 registration and first Cloudflare observation), or via HTTP response header fingerprinting that Cloudflare passes through from the origin.

---

## License

Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.
Free to use, including commercially, with attribution to The Hunters Ledger.
