---
title: "Service Principal API Permission Grants in Microsoft Security: Investigation Guide with Sentinel and KQL"
description: "Operational Microsoft Security playbook for SOC analysts to investigate App Role assignments and Graph API permissions granted to Service Principals with Sentinel and KQL."
date: 2026-11-22
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, service-principal, kql, soc, dfir]
nivel: Avançado
draft: false
---

> **TL;DR:** Granting *Application Permissions* (such as `Mail.Read` or `RoleManagement.ReadWrite.Directory`) to a *Service Principal* provides broad access across the *tenant* without user interaction or MFA. This playbook covers investigating this incident in **Microsoft Security** using Microsoft Sentinel, KQL (`AuditLogs` and `AADServicePrincipalSignInLogs`), ITSM validation, and containment in Entra ID.

---

## 1. What does this incident mean?

Within the **Microsoft Security** ecosystem, Microsoft Sentinel monitors `AuditLogs` to detect when a privileged API permission (*App Role Assignment*) is granted to a *Service Principal* (`Add app role assignment to service principal`). Unlike delegated permissions (which act on behalf of a signed-in user), **application permissions** allow autonomous read or write access to corporate data across Microsoft Graph, Exchange, or Entra ID.

As documented in the [Microsoft Sentinel built-in detections catalog on Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) and the [Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference), attackers who compromise an administrator or automation identity leverage this technique (`MITRE ATT&CK T1098.003`) for silent persistence and *bypass* of human session controls.

### Benign vs. malicious scenarios

| Scenario | Common Indicators | Classification |
|---|---|---|
| **Planned SaaS / SIEM integration rollout** | Known cloud administrator, approved change ticket, least-privilege scopes (e.g., `SecurityEvents.Read.All`). | False Positive (Benign) |
| **Authorized CI/CD pipeline** | Grant executed by a known automation *Service Principal* within a scheduled deployment window. | False Positive (Benign) |
| **Silent post-compromise privilege escalation** | High-impact permission (`RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `Mail.ReadWrite`) granted to a newly created or obscure app. | Critical True Positive (T1098.003) |
| **Backdoor on an existing application** | Compromised admin adds mail or file read permissions to an established, previously trusted app. | True Positive (T1098 / T1114) |

---

## 2. KQL Tip: Inspecting App Role Assignments in AuditLogs

When triaging this incident in Microsoft Sentinel, the query below projects additional columns from `AuditLogs` by expanding `TargetResources` and `modifiedProperties` so you can immediately see which *Service Principal* received the permission, which target resource was authorized, and who initiated the consent.

```kql
let Lookback = 7d;
AuditLogs
| where TimeGenerated >= ago(Lookback)
| where OperationName has_any ("Add app role assignment to service principal", "Add app role assignment grant to user", "Consent to application")
| mv-expand Target = TargetResources
| mv-expand ModProp = Target.modifiedProperties
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatorApp = tostring(InitiatedBy.app.displayName)
| extend SourceIP = tostring(InitiatedBy.user.ipAddress)
| extend TargetName = tostring(Target.displayName)
| extend PropName = tostring(ModProp.displayName)
| extend NewValue = tostring(ModProp.newValue)
| project
    TimeGenerated,
    OperationName,
    Result,
    TargetName,
    Initiator = coalesce(InitiatorUPN, InitiatorApp),
    SourceIP,
    PropName,
    NewValue,
    CorrelationId
| order by TimeGenerated desc
```

---

## 3. Investigation Roadmap: The 5 Mandatory Questions

To classify the incident accurately as a True Positive (TP) or False Positive (FP), answer these five questions:

### 1. What was done?
- Inspect `OperationName`, `TargetName`, and `NewValue` in the KQL output.
- Identify the exact **permission (`AppRole`)** granted and the target API (`Microsoft Graph`, `Office 365 Exchange Online`, `Windows Azure Active Directory`).
- Permissions such as `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, and `Mail.Read` require immediate escalation.

### 2. Who did it?
- Review `InitiatorUPN` (human user) or `InitiatorApp` (*Service Principal*).
- For human actors, check `SigninLogs` around the event timestamp for `SourceIP`, geolocation, and phishing-resistant MFA (*Passkey* / FIDO2).
- Also verify whether *client secrets* or certificates were recently added to the application.

### 3. Should they have been able to do it?
- Only highly privileged roles can grant *Admin Consent* for application permissions in the *tenant*:
  - **Global Administrator**
  - **Privileged Role Administrator**
  - **Cloud Application Administrator** or **Application Administrator**
- If managed via PIM (*Privileged Identity Management*), confirm a prior documented activation.

### 4. Is there a formal change ticket?
- Cross-check your **ITSM** platform (**ServiceNow**, **Jira Service Management**, **Freshservice**, or **Zendesk**).
- Verify an approved change record signed off by Security/IAM justifying least-privilege scope for that exact permission.

### 5. Was the session legitimate?
- Check Microsoft Entra ID Protection for session risk (`RiskLevelDuringSignIn`) or anomalous *User-Agent* strings (CLI scripts outside approved runners).
- Confirm whether the receiving application belongs to a vetted vendor (*Publisher* and source *Tenant ID*).

---

## 4. Where to Investigate in the Portal (Microsoft Entra admin center)

To visually inspect granted permissions in `entra.microsoft.com`:

1. **Inspect application permissions:**
   `Identity > Applications > Enterprise applications > All applications` (search for `TargetName` and open **Security > Permissions**).
2. **Review app registration owners and credentials:**
   `Identity > Applications > App registrations` (check **Certificates & secrets** and **Owners**).
3. **Full portal audit trail:**
   `Identity > Monitoring & health > Audit logs` (filter by **Correlation ID**).

---

## 5. MITRE ATT&CK and Control Mapping

| Framework | Reference | Description |
|---|---|---|
| **MITRE ATT&CK** | `T1098.003` | *Account Manipulation: Additional Cloud Roles* (assigning privileged API permissions to workload identities). |
| **MITRE ATT&CK** | `T1550.001` | *Use Alternate Authentication Material: Application Access Token* (using app access tokens for persistent access). |
| **NIST CSF** | `PR.AA-05` | Continuous review of permissions assigned to human and non-human identities. |
| **CIS Controls v8** | `6.8` | Strict least-privilege governance for service accounts and *Service Principals*. |

---

## 6. Response and Containment Procedure

If the grant lacks formal approval or indicates compromise, execute this *playbook* immediately:

1. **Revoke the permission immediately:** Under `Enterprise applications > [App] > Security > Permissions`, remove the unauthorized permission (or disable sign-in under **Properties > Enabled for users to sign-in? = No** if the entire app is malicious).
2. **Revoke initiator sessions:** In `Identity > Users > All users`, select `InitiatorUPN`, click **Revoke sessions**, reset the password, and audit MFA methods.
3. **Rotate or remove secrets:** Under `App registrations > Certificates & secrets`, remove any suspicious *client secrets* or certificates added recently.
4. **Post-incident KQL audit:** Run the query below against `AADServicePrincipalSignInLogs` to check whether the *Service Principal* already authenticated from external IPs:

```kql
let IncidentWindow = 48h;
AADServicePrincipalSignInLogs
| where TimeGenerated >= ago(IncidentWindow)
| project
    TimeGenerated,
    ServicePrincipalName,
    ServicePrincipalId,
    AppId,
    IPAddress,
    ResourceDisplayName,
    ResultType,
    CorrelationId
| order by TimeGenerated desc
```

---

## References

- [Microsoft Learn — Built-in detections in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Microsoft Learn — Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [MITRE ATT&CK — T1098.003: Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/)

