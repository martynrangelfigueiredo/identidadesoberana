---
title: "Conditional Access Policy Changes in Microsoft Security: Investigation Guide with Sentinel and KQL"
description: "Operational Microsoft Security playbook for SOC analysts to investigate Conditional Access policy modifications or disables in Entra ID using Sentinel and KQL."
date: 2026-11-19
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, conditional-access, kql, soc, dfir]
nivel: Intermediário
draft: false
---

> **TL;DR:** Unplanned changes to *Conditional Access* policies can silently open gaps for MFA *bypass* or unrestricted access to critical applications. This playbook covers Microsoft Sentinel triage, KQL queries for `AuditLogs` and `SigninLogs`, ITSM cross-checking, and containment steps in Entra ID.

---

## 1. What does this incident mean?

Within the **Microsoft Security** ecosystem, Microsoft Sentinel continuously monitors administrative events recorded in Microsoft Entra ID's `AuditLogs` table. When a *Conditional Access* policy is modified, switched to *Report-only*, disabled (*Off*), or deleted — or when a new exclusion (user, group, or *Named Location*) is added — a built-in analytics rule triggers a high-priority incident.

The official documentation in the [Microsoft Sentinel built-in detections catalog on Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) and the [Microsoft Entra ID Conditional Access overview](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview) highlights that changes to this control plane directly impact the *tenant*'s Zero Trust posture.

### Benign vs. malicious scenarios

| Scenario | Common Indicators | Classification |
|---|---|---|
| **Approved maintenance window / Change ticket** | Known administrator, open ITSM ticket, adjustment during business hours, session protected by phishing-resistant MFA. | False Positive (Benign) |
| **Automation via Infrastructure as Code (IaC)** | Change executed by an authorized *Service Principal* (e.g., Terraform/Bicep pipeline) from a corporate IP or known runner. | False Positive (Benign) |
| **Silent exclusion post-compromise** | Attacker with privileged credentials adds a backdoor account to the *Exclude* list or disables MFA enforcement. | True Positive (T1562.001) |
| **Addition of a malicious Named Location** | External IP block marked as a *Trusted Location* to facilitate access control *bypass*. | True Positive (T1562 / T1098) |

---

## 2. KQL Tip: Contextualizing Conditional Access Changes

When triaging this incident in Microsoft Sentinel, the query below projects a few additional columns from `AuditLogs` to help you quickly see which policy changed, what operation occurred, and who initiated it without manually parsing raw JSON.

```kql
let Lookback = 7d;
AuditLogs
| where TimeGenerated >= ago(Lookback)
| where Category == "Policy"
| where OperationName has_any ("Add conditional access policy", "Update conditional access policy", "Delete conditional access policy", "Add policy", "Update policy", "Delete policy")
| mv-expand Target = TargetResources
| mv-expand ModProp = Target.modifiedProperties
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatorApp = tostring(InitiatedBy.app.displayName)
| extend SourceIP = tostring(InitiatedBy.user.ipAddress)
| extend PolicyName = tostring(Target.displayName)
| extend PropertyName = tostring(ModProp.displayName)
| extend OldValue = tostring(ModProp.oldValue)
| extend NewValue = tostring(ModProp.newValue)
| project
    TimeGenerated,
    OperationName,
    Result,
    PolicyName,
    Initiator = coalesce(InitiatorUPN, InitiatorApp),
    SourceIP,
    PropertyName,
    OldValue,
    NewValue,
    CorrelationId
| order by TimeGenerated desc
```

---

## 3. Investigation Roadmap: The 5 Mandatory Questions

To classify the incident accurately as a True Positive (TP) or False Positive (FP), answer these five questions:

### 1. What was done?
- Check `OperationName`, `OldValue`, and `NewValue` in the KQL output.
- **Key red flags:**
  - Did the policy state shift from `enabled` to `disabled` or `enabledForReportingButNotEnforced` (*Report-only*)?
  - Were accounts or groups added under `excludeUsers` / `excludeGroups`?
  - Was a new IP range marked as `isTrusted: true` under *Named Locations*?
- Save the `CorrelationId` to trace correlated actions within the same administrative session.

### 2. Who did it?
- Inspect `InitiatorUPN` (human user) or `InitiatorApp` (*Service Principal*).
- For human accounts, pivot to `SigninLogs` around the event timestamp to verify:
  - Source IP (`SourceIP`), geolocation, and ASN.
  - Whether phishing-resistant MFA (*Passkey* / FIDO2) or a weaker method was used.
  - Recent modifications to the operator's *secrets* or authentication methods.

### 3. Should they have been able to do it?
- Not every user should be able to edit *Conditional Access* policies. Confirm whether the actor holds an authorized Entra ID role:
  - **Conditional Access Administrator**
  - **Security Administrator**
  - **Global Administrator**
- If managed via PIM (*Privileged Identity Management*), verify a prior activation with a valid justification.

### 4. Is there a formal change ticket?
- Cross-check with your organization's **ITSM** platform (**ServiceNow**, **Jira Service Management**, **Freshservice**, or **Zendesk**).
- Confirm an approved change record matches the exact policy, scope, and execution window.
- Check whether `ResultReason` or the PIM activation justification references the ticket ID.

### 5. Was the session legitimate?
- Check Microsoft Entra ID Protection for elevated user or session risk (`RiskLevelDuringSignIn` or `RiskState`).
- Inspect the *User-Agent* in `SigninLogs`: automated scripts (`python-requests`, `curl`, `PowerShell`) originating outside approved runners or from residential/commercial VPN IPs strongly indicate compromise.

---

## 4. Where to Investigate in the Portal (Microsoft Entra admin center)

To visually verify the current policy state and audit trail in `entra.microsoft.com`:

1. **Inspect the modified policy:**
   `Protection > Conditional Access > Policies` (select the policy by `PolicyName` and review *Users*, *Target resources*, *Conditions*, and *Grant*).
2. **Review Named Locations:**
   `Protection > Conditional Access > Named locations` (verify whether new trusted IP ranges or countries were added).
3. **Portal audit logs:**
   `Identity > Monitoring & health > Audit logs` (filter by **Category: Policy** and the **Correlation ID**).

---

## 5. MITRE ATT&CK and Control Mapping

| Framework | Reference | Description |
|---|---|---|
| **MITRE ATT&CK** | `T1562.001` | *Impair Defenses: Disable or Modify Tools* (weakening access control policies). |
| **MITRE ATT&CK** | `T1098` | *Account Manipulation* (adding accounts or groups to exclusion lists). |
| **NIST CSF** | `PR.AA-05` | Continuous review of access permissions and least privilege. |
| **CIS Controls v8** | `6.3` / `6.5` | Enforce MFA for administrative and remote access without undocumented exceptions. |

---

## 6. Response and Containment Procedure

If the investigation confirms the change lacks an authorized ticket or originated from a suspicious session, execute this *playbook* immediately:

1. **Revert the policy immediately:** Under `Protection > Conditional Access > Policies`, restore the previous state (`On`) or remove unauthorized users/IPs from *Exclude*.
2. **Revoke sessions:** In `Identity > Users > All users`, open the actor's profile, click **Revoke sessions**, and reset credentials/MFA if compromise is suspected.
3. **Audit Service Principals:** If initiated by an application, review *client secrets* and permissions (`Policy.ReadWrite.ConditionalAccess`) assigned to that *Service Principal*.
4. **Post-incident KQL audit:** Run the query below to detect any successful logins without MFA or from suspicious IPs after the policy modification:

```kql
let IncidentWindow = 24h;
SigninLogs
| where TimeGenerated >= ago(IncidentWindow)
| where ResultType == 0
| where ConditionalAccessStatus == "notApplied" or AuthenticationRequirement != "multiFactorAuthentication"
| project
    TimeGenerated,
    UserPrincipalName,
    AppDisplayName,
    IPAddress,
    ConditionalAccessStatus,
    AuthenticationRequirement,
    UserAgent,
    CorrelationId
| order by TimeGenerated desc
```

---

## References

- [Microsoft Learn — Built-in detections in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Microsoft Learn — What is Conditional Access in Microsoft Entra ID?](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview)
- [MITRE ATT&CK — T1562.001: Impair Defenses](https://attack.mitre.org/techniques/T1562/001/)

