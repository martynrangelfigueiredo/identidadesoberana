---
title: "Suspicious Inbox Rules in Microsoft Security: Investigation Guide with Sentinel and KQL"
description: "Operational Microsoft Security playbook for SOC analysts to investigate suspicious Exchange Online Inbox Rules and external forwarding using Sentinel and KQL."
date: 2026-11-21
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, exchange-online, kql, soc, dfir]
nivel: Intermediário
draft: false
---

> **TL;DR:** After compromising an account via *phishing* or *Adversary-in-the-Middle (AitM)*, attackers frequently create *Inbox Rules* to hide security alerts or exfiltrate emails outside the *tenant*. This playbook shows how to investigate the incident in **Microsoft Security** using Microsoft Sentinel, KQL (`OfficeActivity` and `SigninLogs`), and containment in Entra ID.

---

## 1. What does this incident mean?

Within the **Microsoft Security** ecosystem, Microsoft Sentinel monitors the `OfficeActivity` table (Exchange Online logs) for `New-InboxRule`, `Set-InboxRule`, or `Enable-InboxRule` operations containing hiding or exfiltration indicators — such as moving messages to *RSS Subscriptions* or *Deleted Items*, marking messages as read automatically, or configuring `ForwardTo` / `RedirectTo` to external domains.

According to the [Microsoft Sentinel built-in detections catalog on Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) and the [Microsoft Purview mailbox auditing documentation](https://learn.microsoft.com/en-us/purview/audit-mailboxes), this technique (`MITRE ATT&CK T1114.003` and `T1564.008`) is widely used in *Business Email Compromise (BEC)* to intercept invoices and conceal alerts sent to the victim.

### Benign vs. malicious scenarios

| Scenario | Common Indicators | Classification |
|---|---|---|
| **Personal newsletter organization** | Rule created by the user from a habitual corporate/home IP moving notification emails into an internal folder. | False Positive (Benign) |
| **Documented internal forwarding** | Rule routing requests to an approved shared mailbox or internal ticketing system. | False Positive (Benign) |
| **Silent hiding (BEC / AitM)** | Rule with cryptic names (`.`, `..`, `a`, `zzz`), sets `MarkAsRead: True`, and moves emails containing *"invoice"*, *"password"*, or *"alert"* to *Deleted Items*. | True Positive (T1564.008) |
| **External exfiltration** | Rule configured with `ForwardTo` or `RedirectTo` to an external webmail provider shortly after an anomalous IP sign-in. | Critical True Positive (T1114.003) |

---

## 2. KQL Tip: Inspecting Inbox Rules in OfficeActivity

When triaging this incident in Microsoft Sentinel, the query below projects additional columns from `OfficeActivity` using `mv-expand` on `Parameters` so you can immediately inspect the rule parameters, source IP, and configured actions.

```kql
let Lookback = 7d;
OfficeActivity
| where TimeGenerated >= ago(Lookback)
| where RecordType == "ExchangeAdmin" or Workload == "Exchange"
| where Operation in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule")
| mv-expand Param = Parameters
| extend ParamName = tostring(Param.Name)
| extend ParamValue = tostring(Param.Value)
| project
    TimeGenerated,
    UserId,
    Operation,
    ClientIP,
    ResultStatus,
    ParamName,
    ParamValue,
    OfficeObjectId
| order by TimeGenerated desc
```

---

## 3. Investigation Roadmap: The 5 Mandatory Questions

To classify the incident accurately as a True Positive (TP) or False Positive (FP), answer these five questions:

### 1. What was done?
- Inspect the `ParamName` and `ParamValue` pairs returned by KQL:
  - `MoveToFolder` pointing to *Deleted Items*, *Junk Email*, or *RSS Subscriptions*.
  - `MarkAsRead = True` or `DeleteMessage = True`.
  - `ForwardTo`, `ForwardAsAttachmentTo`, or `RedirectTo` pointing to an external recipient.
  - Suspicious keywords in `SubjectContainsWords` or `BodyContainsWords` (e.g., `invoice`, `payment`, `bank`, `security`, `MFA`).

### 2. Who did it?
- Confirm `UserId` and `ClientIP` in `OfficeActivity`.
- Correlate `ClientIP` against Entra ID `SigninLogs` in the same time window to check:
  - ASN, country, and network type (e.g., VPS, residential proxy, or commercial VPN).
  - *User-Agent* used (anomalous web session vs. standard corporate Outlook client).
  - Recent changes to *secrets* or MFA devices on the account.

### 3. Should they have been able to do it?
- By default, authenticated users can create *Inbox Rules* in their own mailbox, but **automatic external forwarding** should be blocked by outbound anti-spam policies in Microsoft Defender for Office 365.
- If an admin or *Service Principal* created the rule via remote PowerShell, verify operational necessity.

### 4. Is there a formal change ticket?
- If the rule was created by IT support or automation (e.g., forwarding a mailbox after offboarding), cross-check your **ITSM** platform (**ServiceNow**, **Jira Service Management**, **Freshservice**, or **Zendesk**).
- Verify that the ticket documents the destination address, requester, and manager approval.

### 5. Was the session legitimate?
- Check `SigninLogs` to see whether the session originating from `ClientIP`:
  - Satisfied phishing-resistant MFA (*Passkey* / FIDO2) or relied on a stolen session token (*AitM*).
  - Triggered alerts in Microsoft Entra ID Protection (`Risky sign-ins`, unfamiliar location, or impossible travel).

---

## 4. Where to Investigate in the Portal (Microsoft Entra & Defender)

To visually verify details in the admin portals:

1. **Entra ID sign-in logs (`entra.microsoft.com`):**
   `Identity > Monitoring & health > Sign-in logs` (filter by `UserId` and the `ClientIP` observed in `OfficeActivity`).
2. **Risky users in Entra ID:**
   `Protection > Identity Protection > Risky users`.
3. **Unified audit log in Microsoft Purview / Defender (`security.microsoft.com`):**
   `Audit` (search for **New-InboxRule** and **Set-InboxRule** activities for the affected user).

---

## 5. MITRE ATT&CK and Control Mapping

| Framework | Reference | Description |
|---|---|---|
| **MITRE ATT&CK** | `T1114.003` | *Email Collection: Email Forwarding Rule* (automated forwarding for exfiltration). |
| **MITRE ATT&CK** | `T1564.008` | *Hide Artifacts: Email Hiding Rules* (concealing replies and alerts in folders). |
| **NIST CSF** | `DE.CM-03` / `RS.MI-02` | Monitoring user account actions and rapid exfiltration containment. |
| **CIS Controls v8** | `9.7` / `8.5` | Controlling email forwarding and collecting detailed audit logs. |

---

## 6. Response and Containment Procedure

Once a malicious rule is confirmed, execute this *playbook* immediately:

1. **Revoke active sessions in Entra ID:** Under `Identity > Users > All users`, select the user, click **Revoke sessions**, reset the password, and remove unrecognized MFA methods.
2. **Remove the malicious rule:** In Exchange Online PowerShell (`Remove-InboxRule -Identity "<RuleId>" -Mailbox "<UPN>"`) or the Exchange Admin Center, delete the rule and review *Transport Rules* across the *tenant*.
3. **Check mailbox-level forwarding:** Verify whether `ForwardingSmtpAddress` was set (`Get-Mailbox <UPN> | fl ForwardingSmtpAddress,DeliverToMailboxAndForward`).
4. **Post-incident KQL audit:** Run the query below to see whether the same `ClientIP` accessed other accounts over the past 48 hours:

```kql
let IncidentWindow = 48h;
let SuspectIPs = OfficeActivity
    | where TimeGenerated >= ago(IncidentWindow)
    | where Operation in ("New-InboxRule", "Set-InboxRule")
    | distinct ClientIP;
SigninLogs
| where TimeGenerated >= ago(IncidentWindow)
| where IPAddress in (SuspectIPs)
| project
    TimeGenerated,
    UserPrincipalName,
    AppDisplayName,
    IPAddress,
    ResultType,
    UserAgent,
    RiskLevelDuringSignIn,
    CorrelationId
| order by TimeGenerated desc
```

---

## References

- [Microsoft Learn — Built-in detections in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Microsoft Learn — Audit mailbox activity in Microsoft Purview](https://learn.microsoft.com/en-us/purview/audit-mailboxes)
- [MITRE ATT&CK — T1114.003: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003/)

