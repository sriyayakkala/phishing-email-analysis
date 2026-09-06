# Phishing Email Triage & Incident Analysis Report

## 1. Executive Summary
Investigated a targeted email phishing campaign attempting to harvest employee corporate credentials under the guise of an urgent IT password reset notification.

## 2. Header & Authentication Findings
Analysis of raw message headers revealed multi-layer authentication failures:

* **From Display:** `IT Service Desk <support@company-update-portal.com>`
* **Return-Path / Reply-To:** `phisher-collect@malicious-domain.com` (Header mismatch)
* **SPF Check:** `FAIL` — Sending server IP (`185.220.101.5`) is not listed in SPF TXT records for `company-update-portal.com`.
* **DKIM Check:** `FAIL` — Missing/corrupted cryptographic signature.
* **DMARC Check:** `FAIL` — Triggered domain quarantine policy due to alignment failure between visible `From` address and envelope sender.

## 3. Extracted Indicators of Compromise (IOCs)
* **Originating IP:** `185.220.101.5` (Checked via AbuseIPDB)
* **Malicious Link (Defanged):** `hxxp[://]login-company-portal[.]com/auth/login.php`
* **Sending Domain:** `company-update-portal.com`

## 4. Remediation & Containment Actions
1. **Perimeter Action:** Added `login-company-portal.com` to proxy/DNS sinkhole blocklists.
2. **Mailbox Purge:** Initiated message hash purge across Office 365 / Email Security Gateway to remove copies delivered to other employees.
3. **Account Protection:** Reset credentials and revoked active session tokens for users who clicked the link.
