---
title: "Legacy Authentication in Microsoft Security: Investigating MFA Bypass with Entra ID and Sentinel"
description: "Microsoft Security playbook for SOC analysts to investigate legacy protocol sign-ins and MFA bypass attempts in Entra ID using Microsoft Sentinel and KQL."
date: 2026-11-25
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, mfa, kql, soc, dfir]
nivel: Intermediário
draft: false
---

> **TL;DR:** Legacy protocols such as IMAP4, POP3, SMTP AUTH, and Exchange ActiveSync do not support modern authentication or interactive MFA challenges. When left enabled in a tenant, they become prime targets for password spraying and MFA bypass. This playbook walks through investigating these events in **Microsoft Security** using Microsoft Sentinel, KQL (`SigninLogs` and `OfficeActivity`), ITSM correlation, and containment in Microsoft Entra ID.

---

## 1. What does this incident mean?

Within the **Microsoft Security** ecosystem, Microsoft Sentinel monitors `SigninLogs` for authentication attempts originating from clients that lack OAuth 2.0 and modern MFA support. These appear in the `ClientAppUsed` field as `IMAP4`, `POP3`, `Authenticated SMTP`, `Exchange ActiveSync`, `MAPI Over HTTP`, or `Other clients`.

As detailed in the [Microsoft Sentinel built-in threat detection catalog on Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) and the official guide on [blocking legacy authentication in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication), attackers target these endpoints to test leaked credentials or run password spray campaigns (`MITRE ATT&CK T1110.003` and `T1078`), bypassing interactive protections enforced on modern browsers.

### Benign vs. malicious scenarios

| Scenario | Common Indicators | Classification |
|---|---|---|
| **Corporate multifunction printer or scanner** | `Authenticated SMTP` from a known internal/NAT IP, dedicated service account, no bulk failures. | False Positive (Benign — migrate to OAuth or secure relay) |
| **Legacy ERP or CRM integration** | Recurring `IMAP4` or `POP3` access by a documented technical account with a formal Conditional Access exclusion. | False Positive (Benign — tracked technical debt) |
| **Password spray via IMAP/POP3** | Dozens of failures (`ResultType` 50126 or 50053) across multiple accounts from external VPS IPs or unusual residential ranges. | True Positive (T1110.003) |
| **Successful sign-in without MFA (MFA bypass)** | `ResultType == "0"` with a legacy `ClientAppUsed` and `AuthenticationRequirement == "singleFactorAuthentication"` on a standard or privileged user. | Critical True Positive (T1078) |

---

## 2. KQL Tip: filtering legacy protocols and MFA status in SigninLogs

When triaging the incident in Microsoft Sentinel, the query below projects extra columns from `SigninLogs` to highlight the legacy protocol used, result code (`ResultType`), MFA requirement, and source IP geolocation.

```kql
let Lookback = 7d;
SigninLogs
| where TimeGenerated >= ago(Lookback)
| where ClientAppUsed in ("IMAP4", "POP3", "Authenticated SMTP", "SMTP", "Exchange ActiveSync", "Exchange Web Services", "AutoDiscover", "MAPI Over HTTP", "Offline Address Book", "Other clients")
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend City = tostring(LocationDetails.city)
| extend DeviceOS = tostring(DeviceDetail.operatingSystem)
| project
    TimeGenerated,
    UserPrincipalName,
    ClientAppUsed,
    AppDisplayName,
    ResultType,
    ResultDescription,
    ConditionalAccessStatus,
    AuthenticationRequirement,
    IPAddress,
    Country,
    City,
    DeviceOS,
    UserAgent,
    CorrelationId
| order by TimeGenerated desc
```

---

## 3. Investigation Roadmap: the 5 mandatory questions

### 1. What was done?
Check `SigninLogs` to determine whether the attempt was **blocked or successful**:
- **`ResultType == "0"`:** Sign-in succeeded without an interactive MFA prompt. Treat immediately as a potential compromise.
- **`ResultType == "53003"`:** Conditional Access blocked the legacy protocol (expected defensive behavior).
- **`ResultType == "50126"`:** Invalid password (strong indicator of brute force or password spraying against legacy endpoints).
- **`ResultType == "50053"`:** Account locked by Smart Lockout after repeated failures.
- Record `CorrelationId` and `UniqueTokenIdentifier` to correlate across related telemetry.

### 2. Who did it?
Inspect `UserPrincipalName`, `IPAddress`, and `UserAgent`:
- Does the targeted account hold privileged Entra ID roles (such as `Global Administrator` or `Exchange Administrator`) or access to sensitive mailboxes?
- Does the `IPAddress` belong to a cloud/VPS provider, an anonymous VPN exit, or an ASN inconsistent with the employee's normal office or ISP?
- Were there simultaneous attempts against other tenant accounts from the same IP or subnet?

### 3. Should they have been able to do it?
Determine why legacy authentication was still available for that account:
- Is there an active Conditional Access policy blocking `Legacy authentication clients` for all users, or was the account placed in an exclusion group?
- In Exchange Online, were `SmtpClientAuthenticationDisabled`, `ImapEnabled`, or `PopEnabled` still enabled on the mailbox (`CASMailbox`)?

### 4. Is there a formal ticket?
Before classifying as a legitimate internal integration, cross-check `UserPrincipalName` and `IPAddress` against your **ITSM** platform (ServiceNow, Jira Service Management, Freshservice, or Zendesk):
- Is there an approved change ticket for a scanner, ticketing connector, or legacy application polling that mailbox?
- If an approved exclusion exists, confirm that the source IP matches the exact static IP authorized in the ticket.

### 5. Was the session legitimate?
Even if the user reports using an older mail client on a phone or workstation, verify:
- Does the `UserAgent` match an approved corporate client (modern Outlook uses modern authentication rather than `IMAP4` or `Other clients`)?
- Is there another modern sign-in from the same user in a distant geographic location within the same time window?

---

## 4. Where to investigate in the portal

To review policies, exclusions, and account history directly in the admin portals:

1. **Filter sign-in logs by legacy client in Entra ID:**
   - Open the Microsoft Entra admin center (`entra.microsoft.com`).
   - Navigate to: `Identity > Monitoring & health > Sign-in logs`.
   - Add the `Client app` filter and select `Exchange ActiveSync`, `IMAP4`, `POP3`, `Authenticated SMTP`, and `Other clients`.
2. **Review Conditional Access policies:**
   - Navigate to: `Protection > Conditional Access > Policies`.
   - Verify that an active policy targets `All cloud apps` with `Client apps = Exchange ActiveSync clients` and `Other clients` set to `Grant = Block access`.
3. **Check per-mailbox protocol settings in Exchange Online:**
   - Open the Exchange admin center (`admin.exchange.microsoft.com`).
   - Navigate to: `Recipients > Mailboxes > [User] > Manage email apps settings` to verify POP3, IMAP, and Authenticated SMTP are disabled.

---

## 5. Response, Containment, and Post-Incident Audit

If you confirm an unauthorized successful sign-in (`ResultType == "0"`) over a legacy protocol:

1. **Revoke sessions and reset credentials:**
   - In the Microsoft Entra admin center (`Users > [User]`), run **Revoke sessions** immediately and enforce a strong, unique password reset.
2. **Disable legacy protocols at the account and tenant levels:**
   - Disable `IMAP`, `POP`, and `Authenticated SMTP` on the Exchange Online mailbox and remove the user from any Conditional Access exclusion groups.
3. **Audit post-sign-in mailbox activity:**
   - Run the query below against `OfficeActivity` to check whether the attacker accessed messages, created forwarding rules, or sent emails after the legacy sign-in.

```kql
let TargetUser = "usuario@contoso.com";
let Lookback = 48h;
OfficeActivity
| where TimeGenerated >= ago(Lookback)
| where UserId == TargetUser
| where Operation in (
    "MailItemsAccessed",
    "New-InboxRule",
    "Set-InboxRule",
    "Set-Mailbox",
    "Add-MailboxPermission",
    "Send",
    "SendAs"
)
| project
    TimeGenerated,
    UserId,
    Operation,
    ClientIP,
    ClientInfoString,
    ResultStatus,
    Parameters
| order by TimeGenerated desc
```

---

## 6. Control Mapping and Compliance

| Framework / Standard | Related Control | Practical Implementation |
|---|---|---|
| **MITRE ATT&CK** | `T1078` (Valid Accounts), `T1110.003` (Password Spraying) | Detection of attempts and access over protocols lacking MFA support. |
| **NIST CSF 2.0** | `PR.AA-03` (Access Management), `DE.CM-03` (Identity Monitoring) | Blocking legacy authentication via Conditional Access and alerting in Sentinel. |
| **CIS Controls v8** | `6.3` / `6.5` (MFA for Applications and Admin Access) | Eliminating MFA bypass paths over IMAP/POP3/SMTP. |
| **ISO/IEC 27001:2022** | `A.8.5` (Secure Authentication) | Enforcing consistent strong authentication across all entry points. |
| **LGPD / GDPR** | LGPD Art. 46 / GDPR Art. 32 | Protecting mailboxes and personal data from unauthorized access. |
