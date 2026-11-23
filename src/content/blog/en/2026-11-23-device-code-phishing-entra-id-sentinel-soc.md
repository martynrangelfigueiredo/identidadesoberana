---
title: "Device Code Authentication in Microsoft Security: Investigation Guide with Sentinel and KQL"
description: "Operational Microsoft Security playbook for SOC analysts to investigate Device Code Phishing and anomalous deviceCode flows in Entra ID with Sentinel and KQL."
date: 2026-11-23
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, device-code, kql, soc, dfir]
nivel: Avançado
draft: false
---

> **TL;DR:** The OAuth 2.0 *Device Code* flow was designed for input-constrained devices (TVs, printers, and CLIs), yet attackers abuse it in *Device Code Phishing* campaigns to obtain valid MFA-satisfied tokens. This playbook covers triage in **Microsoft Security** using Microsoft Sentinel, KQL (`SigninLogs`), ITSM validation, and containment in Entra ID.

---

## 1. What does this incident mean?

Within the **Microsoft Security** ecosystem, Microsoft Sentinel monitors `SigninLogs` for sign-ins with `AuthenticationProtocol == "deviceCode"` from unexpected applications, atypical external IPs, or users with no administrative CLI history.

In this attack (`MITRE ATT&CK T1528`), an adversary initiates a device code request against Entra ID (often impersonating Microsoft Graph PowerShell or Azure CLI), sends the 8–9 character code to the victim via email or chat, and tricks them into visiting `microsoft.com/devicelogin`. Once the victim completes login and MFA in their browser, Entra ID issues the *access token* and *refresh token* directly to the attacker's host.

As documented in the [Microsoft Sentinel built-in detections catalog on Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) and the [Entra ID device authorization flow documentation](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code), this enables practical *bypass* of session-bound protections unless restricted by *Conditional Access*.

### Benign vs. malicious scenarios

| Scenario | Common Indicators | Classification |
|---|---|---|
| **Administrator using Azure CLI / PowerShell** | Known IT/DevOps user, corporate IP or VPN, expected `AppDisplayName`. | False Positive (Benign) |
| **Legitimate IoT / conference room provisioning** | Resource or Teams Rooms account on a dedicated internal network. | False Positive (Benign) |
| **Device Code Phishing** | Non-technical user (Finance, HR, Executive) authenticating to `Microsoft Azure CLI` or `Microsoft Graph PowerShell` from a VPS or commercial VPN IP. | Critical True Positive (T1528) |
| **Multi-account token harvesting** | Same external `IPAddress` receiving successful `deviceCode` sessions from multiple employees in one campaign. | Critical True Positive |

---

## 2. KQL Tip: Identifying deviceCode Flows in SigninLogs

When triaging this incident in Microsoft Sentinel, the query below projects additional columns from `SigninLogs` to highlight the target application, authentication protocol, *User-Agent*, and device trust status, making it easy to separate legitimate CLI usage from phishing.

```kql
let Lookback = 7d;
SigninLogs
| where TimeGenerated >= ago(Lookback)
| where AuthenticationProtocol == "deviceCode" or ClientAppUsed == "Mobile Apps and Desktop clients"
| where AuthenticationProtocol == "deviceCode"
| extend DeviceTrust = tostring(DeviceDetail.trustType)
| extend IsCompliant = tostring(DeviceDetail.isCompliant)
| project
    TimeGenerated,
    UserPrincipalName,
    ResultType,
    AppDisplayName,
    ResourceDisplayName,
    IPAddress,
    Location,
    UserAgent,
    DeviceTrust,
    IsCompliant,
    RiskLevelDuringSignIn,
    CorrelationId
| order by TimeGenerated desc
```

---

## 3. Investigation Roadmap: The 5 Mandatory Questions

To classify the incident accurately as a True Positive (TP) or False Positive (FP), answer these five questions:

### 1. What happened?
- Check `ResultType` (`0` means the victim entered the code and completed sign-in; `50140` or `70016` may indicate an aborted or expired attempt).
- Inspect `AppDisplayName` and `ResourceDisplayName` (attacks commonly request `Microsoft Graph` access via `Microsoft Azure CLI` or `Microsoft Office`).

### 2. Who did it?
- Evaluate the `UserPrincipalName` profile: a Finance or Sales employee rarely needs `Azure CLI` via `deviceCode`.
- Inspect the source `IPAddress` (in the `deviceCode` flow, the logged IP belongs to the token requester/attacker and often differs completely from the victim's normal IP!).
- Check the *User-Agent* in `SigninLogs` (Python/Go/cURL on Linux strengthens suspicion).

### 3. Should they have been able to do it?
- Verify whether the *tenant* enforces a *Conditional Access* policy blocking *Authentication flows > Device code flow* for standard users.
- Check whether compliant (`IsCompliant == "true"`) or hybrid-joined devices (`DeviceTrust`) were required.

### 4. Is there a formal change ticket?
- For legitimate remote support or CLI automation, cross-check your **ITSM** platform (**ServiceNow**, **Jira Service Management**, **Freshservice**, or **Zendesk**).
- Also verify directly with the affected user over a trusted out-of-band channel whether they entered a code at `microsoft.com/devicelogin`.

### 5. Was the session legitimate?
- Check Microsoft Entra ID Protection for concurrent alerts (`Risky sign-ins`, unfamiliar sign-in properties, or impossible travel between the user's normal IP and the `deviceCode` `IPAddress`).
- If the user confirms entering a code from a suspicious email or chat message, treat it immediately as a **True Positive**.

---

## 4. Where to Investigate in the Portal (Microsoft Entra admin center)

To inspect the event visually in `entra.microsoft.com`:

1. **Inspect Device Code sign-ins:**
   `Identity > Monitoring & health > Sign-in logs` (filter by **Authentication protocol: Device code** or by **Correlation ID**).
2. **Review authentication flow policies:**
   `Protection > Conditional Access > Policies` (verify whether *Authentication flows: Device code flow* is blocked).
3. **Risky users:**
   `Protection > Identity Protection > Risky users`.

---

## 5. MITRE ATT&CK and Control Mapping

| Framework | Reference | Description |
|---|---|---|
| **MITRE ATT&CK** | `T1528` | *Steal Application Access Token* (fraudulent OAuth token acquisition via *Device Code Phishing*). |
| **MITRE ATT&CK** | `T1566.002` | *Phishing: Spearphishing Link* (delivering `devicelogin` links and codes). |
| **NIST CSF** | `PR.AA-03` / `PR.AA-05` | Restricting special or legacy authentication flows via *Conditional Access*. |
| **CIS Controls v8** | `6.5` / `6.3` | Enforcing managed devices and phishing-resistant MFA for administrative access. |

---

## 6. Response and Containment Procedure

Once *Device Code Phishing* is confirmed, execute this *playbook* immediately:

1. **Revoke sessions and tokens immediately:** Under `Identity > Users > All users`, select the affected user and click **Revoke sessions** (invalidates the attacker's *refresh token*).
2. **Block Device Code Flow via Conditional Access:** In `Protection > Conditional Access > Policies`, block `Authentication flows > Device code flow` for all users, allowing only tightly scoped IT exceptions.
3. **Post-incident KQL audit:** Run the query below to inspect whether affected accounts performed sensitive `AuditLogs` actions after the `deviceCode` sign-in (such as modifying *secrets* or registering new MFA methods):

```kql
let IncidentWindow = 24h;
let DeviceCodeUsers = SigninLogs
    | where TimeGenerated >= ago(IncidentWindow)
    | where AuthenticationProtocol == "deviceCode" and ResultType == 0
    | distinct UserPrincipalName;
AuditLogs
| where TimeGenerated >= ago(IncidentWindow)
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| where Actor in (DeviceCodeUsers)
| project
    TimeGenerated,
    OperationName,
    Category,
    Result,
    Actor,
    SourceIP = tostring(InitiatedBy.user.ipAddress),
    CorrelationId
| order by TimeGenerated desc
```

---

## References

- [Microsoft Learn — Built-in detections in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Microsoft Learn — Microsoft identity platform and the OAuth 2.0 device authorization grant flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code)
- [MITRE ATT&CK — T1528: Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)

