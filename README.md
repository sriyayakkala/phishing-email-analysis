# Phishing Email Triage & Header Analysis

## Executive Summary
This repository documents a Security Operations Center (SOC) investigation into a targeted executive credential-harvesting attempt. The analysis walks through extracting raw email headers, evaluating authentication protocols (SPF, DKIM, DMARC), enriching Indicators of Compromise (IOCs), and executing standard containment playbooks.

---

## Analysis Methodology & Findings

### 1. Header & Authentication Verification
Raw RFC 822 headers were analyzed using **MXToolbox Header Analyzer** to evaluate sender authenticity:

* **From Header:** `IT Service Desk <support@company-update-portal.com>`
* **Return-Path:** `phisher-collect@malicious-domain.com` *(Header mismatch flagged)*
* **SPF Check:** `FAIL` — Originating IP (`185.220.101.5`) is not authorized to send mail on behalf of `company-update-portal.com`.
* **DKIM Check:** `FAIL` — Signature verification failed or missing cryptographic header.
* **DMARC Check:** `FAIL` — Failed domain alignment checks; triggered domain quarantine policy[cite: 1].

---

### 2. Extracted Indicators of Compromise (IOCs)
All extracted links and domains were defanged (`[.]`) to prevent accidental execution[cite: 1]:

| Indicator Type | Defanged Value | Threat Intelligence Source | Severity |
| :--- | :--- | :--- | :--- |
| **Originating IP** | `185.220.101.5` | AbuseIPDB (High Abuse Confidence) | High |
| **Malicious URL** | `hxxp[://]login-company-portal[.]com/auth/login.php` | VirusTotal (Malicious / Phishing) | Critical |
| **Sender Domain** | `company-update-portal.com` | CentralOps / WHOIS Lookup | High |

---

## Containment & Incident Response Playbook

1. **Perimeter Block:** Pushed `company-update-portal.com` and `185.220.101.5` to perimeter firewall, proxy, and DNS sinkhole blocklists[cite: 1].
2. **Gateway Purge:** Initiated message hash search and purge across Microsoft 365 / Email Gateway to remove matching delivered emails from user inboxes[cite: 1].
3. **Account Protection:** Revoked active session tokens and forced password resets for any users who interacted with the link[cite: 1].

---

## MITRE ATT&CK Mapping
* **Tactics:** Initial Access (`TA0001`), Credential Access (`TA0006`)
* **Technique:** Phishing: Spearphishing Link (`T1566.002`)
