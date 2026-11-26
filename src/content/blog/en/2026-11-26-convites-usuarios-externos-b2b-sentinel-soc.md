---
title: "External B2B Guest Invitations in Microsoft Security: Investigating with Entra ID and Sentinel"
description: "Microsoft Security playbook for SOC analysts to investigate suspicious external B2B guest invitations in Entra ID using Microsoft Sentinel and KQL."
date: 2026-11-26
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, b2b, iam, kql, soc, dfir]
nivel: Intermediário
draft: false
---

> **TL;DR:** B2B collaboration in Microsoft Entra ID streamlines partner work, but unauthorized invitations to personal email accounts (`gmail.com`, `outlook.com`) or subsequent role assignments to `#EXT#` users create quiet cross-tenant persistence paths. This playbook covers investigating these events in **Microsoft Security** using Microsoft Sentinel, KQL (`AuditLogs` and `SigninLogs`), ITSM correlation, and containment in Entra ID.

---

## 1. What does this incident mean?

Within the **Microsoft Security** ecosystem, Microsoft Sentinel monitors `AuditLogs` for events involving the creation, redemption, and privilege elevation of external guest accounts (*B2B Guest*), including `Invite external user`, `Redeem external user invite`, `Add user` with an `#EXT#` suffix, and subsequent group or role changes.

As documented in the [Microsoft Sentinel built-in threat detection catalog on Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) and the official [Microsoft Entra ID B2B collaboration documentation](https://learn.microsoft.com/en-us/entra/external-id/b2b-quickstart-add-guest-users-portal), attackers who compromise an internal account with invitation rights (`Guest Inviter`) can invite an external account under their control (`MITRE ATT&CK T1136.003` / `T1098`) to retain access even after the original password is reset.

### Benign vs. malicious scenarios

| Scenario | Common Indicators | Classification |
|---|---|---|
| **Approved partner collaboration** | Known corporate domain (`partner.com`), invited by a project lead, scoped to a single Teams channel or SharePoint folder. | False Positive (Benign) |
| **Temporary contractor with approved ticket** | Invited by IAM/Helpdesk with a linked change ticket and an active access review policy. | False Positive (Benign) |
| **Invitation to consumer webmail (`gmail.com` / `proton.me`)** | Internal account with no external-facing role invites a personal email off-hours or shortly after an anomalous sign-in. | True Positive (Investigate immediately) |
| **`#EXT#` guest added to privileged role or group** | Newly invited external user receives an Entra ID role, Azure RBAC (`Contributor`/`Owner`), or membership in a critical app group. | Critical True Positive (`T1098`) |

---

## 2. KQL Tip: tracking external guest invitations and assignments in AuditLogs

When triaging the incident in Microsoft Sentinel, the query below projects additional columns from `AuditLogs` to highlight who sent the invitation, the external guest address, operation outcome, and `CorrelationId` for cross-log tracing.

```kql
let Lookback = 7d;
AuditLogs
| where TimeGenerated >= ago(Lookback)
| where OperationName in ("Invite external user", "Redeem external user invite", "Bulk invite users")
| mv-expand Target = TargetResources
| mv-expand ModProp = Target.modifiedProperties
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend SourceIP = tostring(InitiatedBy.user.ipAddress)
| extend GuestUPN = tostring(Target.userPrincipalName)
| extend PropName = tostring(ModProp.displayName)
| extend NewValue = tostring(ModProp.newValue)
| project
    TimeGenerated,
    OperationName,
    Result,
    ResultReason,
    InitiatorUPN,
    SourceIP,
    GuestUPN,
    PropName,
    NewValue,
    CorrelationId
| order by TimeGenerated desc
```

---

## 3. Investigation Roadmap: the 5 mandatory questions

### 1. What was done?
Review the full guest lifecycle in `AuditLogs`:
- Was the invitation only sent (`Invite external user`) or already redeemed (`Redeem external user invite`)?
- Shortly after the invite, were there `Add member to group` or `Add member to role` events targeting the same `#EXT#` user?
- Record `CorrelationId` and `GuestUPN` for correlation.

### 2. Who did it?
Inspect `InitiatorUPN` and `SourceIP` in `AuditLogs` and check recent sign-ins for the initiating account in `SigninLogs`:
- Does the inviting employee work in procurement, legal, IT, or vendor management?
- Did the session originate from a compliant device (`IsCompliant == true`) and usual corporate IP, or did it follow a location/MFA anomaly?

### 3. Should they have been able to do it?
Assess the tenant's B2B governance configuration:
- In Entra ID external collaboration settings, can any standard member invite guests, or is it restricted to `Guest Inviter` / `User Administrator`?
- Is there an allow list or deny list blocking consumer webmail domains?

### 4. Is there a formal ticket?
Cross-check `InitiatorUPN` and the invited domain against your **ITSM** platform (ServiceNow, Jira Service Management, Freshservice, or Zendesk):
- Is there an approved vendor/third-party onboarding ticket tied to an active contract?
- For Azure RBAC or privileged group assignments, is there a documented change approval?

### 5. Was the session legitimate?
Validate both the inviter's session and the guest's first sign-in:
- If the guest already redeemed the invite, did Conditional Access for external users enforce MFA in the resource tenant?
- Did the guest access only the shared resource, or enumerate directories, users, and internal applications?

---

## 4. Where to investigate in the portal

To inspect B2B settings and guest history directly in the Microsoft Entra admin center (`entra.microsoft.com`):

1. **Inspect the guest account:**
   - Navigate to: `Identity > Users > All users`.
   - Filter by `User type == Guest` and open the user profile to inspect `Creation type` (`Invitation`), `External user state` (`Accepted` or `PendingAcceptance`), groups, and app assignments.
2. **Review external collaboration settings:**
   - Navigate to: `Identity > External Identities > External collaboration settings`.
   - Check **Guest user access**, **Guest invite settings** (who can invite), and **Collaboration restrictions** (domain allow/deny lists).
3. **Audit guest sign-in logs:**
   - Navigate to: `Identity > Monitoring & health > Sign-in logs` and filter `User` by `#EXT#`.

---

## 5. Response, Containment, and Post-Incident Audit

If the external invitation or privilege elevation is confirmed unauthorized:

1. **Block and remove the guest account:**
   - In Entra ID (`Users > [User #EXT#]`), run **Revoke sessions** immediately, disable sign-in (`Account enabled = No`), strip groups/roles, and delete the account.
2. **Contain the internal inviting account:**
   - If `InitiatorUPN` shows signs of compromise, run **Revoke sessions**, reset the password, and audit registered MFA methods.
3. **Audit all recent `#EXT#` sign-ins:**
   - Run the query below against `SigninLogs` to see which applications external users accessed over the last 7 days and whether Conditional Access applied.

```kql
let Lookback = 7d;
SigninLogs
| where TimeGenerated >= ago(Lookback)
| where UserType == "Guest" or UserPrincipalName contains "#EXT#"
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend City = tostring(LocationDetails.city)
| project
    TimeGenerated,
    UserPrincipalName,
    AppDisplayName,
    ResourceDisplayName,
    ResultType,
    ResultDescription,
    ConditionalAccessStatus,
    AuthenticationRequirement,
    IPAddress,
    Country,
    City,
    CorrelationId
| order by TimeGenerated desc
```

---

## 6. Control Mapping and Compliance

| Framework / Standard | Related Control | Practical Implementation |
|---|---|---|
| **MITRE ATT&CK** | `T1136.003` (Cloud Account), `T1098` (Account Manipulation) | Detecting unauthorized creation and elevation of external accounts for persistence. |
| **NIST CSF 2.0** | `PR.AA-01` (Identity Management), `PR.AA-05` (Least Privilege) | Restricting B2B invitation rights and enforcing periodic access reviews. |
| **CIS Controls v8** | `5.3` / `6.8` (Dormant Accounts & RBAC) | Removing expired guest accounts and blocking non-corporate email domains. |
| **ISO/IEC 27001:2022** | `A.5.18` (Access Rights), `A.5.19` (Supplier Security) | Formal governance of third-party identities in the tenant. |
| **LGPD / GDPR** | LGPD Art. 46 / GDPR Art. 32 | Preventing unauthorized external access to repositories holding personal data. |

