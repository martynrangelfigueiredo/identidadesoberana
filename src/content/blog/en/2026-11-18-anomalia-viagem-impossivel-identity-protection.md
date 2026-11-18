---
title: "Triaging Impossible Travel and Anonymous IP Alerts in Microsoft Security with Entra ID Protection and KQL"
description: "Operational playbook for the Microsoft Security ecosystem to investigate Impossible Travel and Anonymous IP alerts in Microsoft Entra ID Protection and Microsoft Sentinel."
date: 2026-11-18
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, identity-protection, kql, soc, impossible-travel, playbook]
nivel: Intermediário
---

**Impossible Travel** and **Anonymous IP Address** alerts are among the most common incidents landing in the Tier 1 and Tier 2 queues of any Security Operations Center (SOC) operating within the **Microsoft Security** ecosystem.

These detections trigger when **Microsoft Entra ID Protection** observes two sign-in events for the same identity from geographically distant locations within a timeframe physically impossible for commercial air travel — or connections originating from known Tor exit nodes and anonymous VPNs. However, modern enterprise architectures relying on split tunneling, cloud proxies (Zscaler, Netskope), and mobile carriers routinely generate false positives that require careful triage before locking out legitimate users.

This operational guide walks through the end-to-end investigation workflow to distinguish benign corporate traffic from genuine account compromise in **Microsoft Security**.

> **SOC Analyst TL;DR:** Before resetting passwords or revoking sessions on an Impossible Travel alert, always compare `UserAgent`, `DeviceDetail` (managed Intune device ID), and MFA method (`AuthenticationDetails`) across both sessions in `SigninLogs`. Distinct unmanaged devices coupled with MFA bypass or an abrupt ASN shift strongly indicate a true incident.

> 📘 **Official Microsoft Learn Reference:** This playbook is built upon native detections and official Microsoft Security documentation:
> - [Microsoft Learn — What are Microsoft Entra ID Protection risks?](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)
> - [Microsoft Learn — Microsoft Sentinel built-in threat detection catalog](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)

---

## 1. Understanding the Incident Context in Microsoft Security

In **Microsoft Sentinel**, impossible travel and anonymous IP alerts typically arrive via **Microsoft Entra ID Protection** connectors or correlated analytics rules in **Microsoft Defender XDR**.

The two primary scenarios encountered in daily operations are:
1. **Corporate VPN / Cloud Proxy Routing (Common False Positive):** A user signs in from the office (local ISP IP), and five minutes later a background client refreshes an OAuth token through a SASE/SSE egress gateway located in another country.
2. **Credential Theft or Session Hijacking (True Positive):** An attacker uses leaked credentials or a stolen session token (via AiTM phishing) from a foreign VPS, residential proxy, or Tor exit node.

---

## 2. KQL Tip: Correlating SigninLogs and risk events in Sentinel

The query below helps contextualize the alert by listing recent sign-ins in `SigninLogs` along with device compliance, client app, and risk attributes for the investigated user.

```kql
let AlvoUsuario = "usuario.suporte@contoso.com";
let JanelaTempo = 24h;
SigninLogs
| where TimeGenerated > ago(JanelaTempo)
| where tolower(UserPrincipalName) == tolower(AlvoUsuario)
| extend DeviceOS = tostring(DeviceDetail.operatingSystem)
| extend Browser = tostring(DeviceDetail.browser)
| extend IsCompliant = tostring(DeviceDetail.isCompliant)
| extend IsManaged = tostring(DeviceDetail.isManaged)
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend City = tostring(LocationDetails.city)
| project TimeGenerated, UserPrincipalName, IPAddress, Country, City, AppDisplayName, ClientAppUsed, UserAgent, DeviceOS, Browser, IsCompliant, IsManaged, ResultType, RiskLevelDuringSignIn
| order by TimeGenerated desc
```

To complement the triage and inspect the exact risk detections flagged by **Microsoft Entra ID Protection**, query the `AADUserRiskEvents` table:

```kql
let AlvoUsuario = "usuario.suporte@contoso.com";
AADUserRiskEvents
| where TimeGenerated > ago(7d)
| where tolower(UserPrincipalName) == tolower(AlvoUsuario)
| project TimeGenerated, RiskEventType, RiskLevel, RiskState, DetectionTimingType, IpAddress, Location, Source
| order by TimeGenerated desc
```

---

## 3. Standard Six-Step SOC Investigation Playbook

Follow these six structured steps for a consistent, auditable investigation:

### 1. What was done?
- Identify both source IP addresses, exact UTC timestamps, and targeted applications (`AppDisplayName`).
- Verify whether the sign-in **succeeded (`ResultType == 0`)** or was blocked by Conditional Access (`ResultType == 53003`).
- Record the `CorrelationId` for both sessions and calculate the geodesic distance and required speed (you can use our [Impossible Travel Calculator](/util/distance/) and [IP Lookup](/util/ipinfo/) to inspect both ASNs).

### 2. Who did it?
- Inspect `DeviceDetail.isCompliant` and `DeviceDetail.isManaged`. If both sign-ins originate from the **same managed Intune/Entra-joined corporate device**, VPN or cloud proxy routing is the most likely explanation.
- Review `AuthenticationDetails` to confirm whether MFA (`mfa`, `fido`) was satisfied or if an existing token was replayed.
- An unfamiliar VPS/hosting ASN paired with an anomalous `UserAgent` (such as `python-requests` or `curl`) is a high-confidence compromise indicator.

### 3. Could they have done it?
- Check if the account holds privileged roles in **Microsoft Entra ID** (Global Administrator, Privileged Role Administrator, Exchange Administrator) or critical Azure RBAC permissions.
- Verify whether organizational **Conditional Access** policies permit sign-ins from those countries or from unmanaged devices.

### 4. Is there a formal ticket?
- Query ITSM platforms (ServiceNow, Jira, Freshservice, Zendesk) or HR records to verify if the employee registered **international travel** or a VPN exception.
- If the egress IP belongs to an approved corporate SASE/SSE provider (e.g., Zscaler, Cloudflare Gateway, GlobalProtect), document the ASN as expected traffic.

### 5. Where to investigate in the portal?
To inspect full risk telemetry directly in the **Microsoft Security** consoles:
- **Identity Risks:** `Microsoft Entra admin center > Protection > Identity Protection > Risky users` and `Risk detections`.
- **Sign-in Telemetry:** `Microsoft Entra admin center > Identity > Monitoring & health > Sign-in logs` (filtered by `CorrelationId` or `UserPrincipalName`).
- **Unified Incident View:** `Microsoft Defender XDR Portal (security.microsoft.com) > Incidents & alerts > Incidents`.

### 6. Response and containment procedure
If triage confirms an actual compromise (True Positive):
1. **Revoke all active sessions immediately** (invalidating Refresh Tokens and session cookies):
   ```powershell
   Connect-MgGraph -Scopes "User.ReadWrite.All"
   Revoke-MgUserSignSession -UserId "usuario.suporte@contoso.com"
   ```
2. **Flag the user as compromised** in Entra ID Protection (`Confirm user compromised`) to trigger automated high-risk policies.
3. **Reset the account password** and audit registered MFA methods (`Authentication methods`) to ensure no attacker-controlled authenticator or phone number was added.
4. **Audit post-compromise activity** across `AuditLogs` and `OfficeActivity` (suspicious inbox forwarding rules, OAuth consent grants, and SharePoint/OneDrive bulk downloads).

---

## 4. Quick Triage Decision Matrix

| Triage Evidence Observed | Classification | Immediate Action |
| :--- | :--- | :--- |
| Identical managed `DeviceId` (Intune), IP change solely to approved corporate SASE gateway | **False Positive (FP)** | Document approved gateway ASN and close incident as benign. |
| New VPS/Tor IP, unmanaged device (`IsManaged == false`), anomalous `UserAgent` | **True Positive (Critical)** | Revoke sessions (`Revoke-MgUserSignSession`), reset password, confirm user compromised, and audit MFA/mailbox rules. |
| Confirmed international travel in ITSM ticket using managed corporate mobile device | **Expected Benign** | Confirm Conditional Access compliance and close with ticket reference. |
