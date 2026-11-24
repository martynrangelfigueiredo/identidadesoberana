---
title: "New MFA Method Registration in Microsoft Security: Investigation Guide with Sentinel and KQL"
description: "Operational Microsoft Security playbook for SOC analysts to investigate suspicious MFA method registrations in Entra ID using Microsoft Sentinel and KQL."
date: 2026-11-24
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, mfa, kql, soc, dfir]
nivel: Intermediário
draft: false
---

> **TL;DR:** Once an attacker obtains valid credentials or an initial token, registering a new MFA method (Authenticator App, phone number, or *Passkey*) is a primary post-compromise persistence step. This playbook covers investigating this event in **Microsoft Security** with Microsoft Sentinel, KQL (`AuditLogs` and `SigninLogs`), ITSM validation, and containment in Entra ID.

---

## 1. What does this incident mean?

Within the **Microsoft Security** ecosystem, Microsoft Sentinel monitors `AuditLogs` for `UserManagement` events related to registering or modifying security info — such as `User registered security info`, `Admin registered security info`, or `User deleted security info`.

As documented in the [Microsoft Sentinel built-in detections catalog on Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) and the [Entra ID authentication methods activity documentation](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity), this technique (`MITRE ATT&CK T1098.005` / `T1556.006`) allows an adversary to retain access even after a password reset if the rogue MFA method is not removed.

### Benign vs. malicious scenarios

| Scenario | Common Indicators | Classification |
|---|---|---|
| **Employee onboarding or device upgrade** | Registration from a known corporate IP/VPN on a compliant device (`IsCompliant == true`) during business hours. | False Positive (Benign) |
| **Helpdesk-assisted reset (TAP)** | Authorized admin issued a *Temporary Access Pass* under an open ticket, and the user registered a new *Passkey* / FIDO2 key. | False Positive (Benign) |
| **Post-phishing / AitM persistence** | New method registered minutes after a sign-in from an anomalous IP (VPS, commercial VPN, or unusual country) without a managed device. | Critical True Positive (T1098.005) |
| **Deletion of legitimate methods** | Removal of the employee's prior authenticator immediately after adding an unknown device. | Critical True Positive |

---

## 2. KQL Tip: Inspecting Security Info Changes in AuditLogs

When triaging this incident in Microsoft Sentinel, the query below projects additional columns from `AuditLogs` to display the target user, initiator, `ResultReason`, and modified property details.

```kql
let Lookback = 7d;
AuditLogs
| where TimeGenerated >= ago(Lookback)
| where OperationName has_any ("security info", "authentication method", "strong authentication")
| mv-expand Target = TargetResources
| mv-expand ModProp = Target.modifiedProperties
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend SourceIP = tostring(InitiatedBy.user.ipAddress)
| extend TargetUser = tostring(Target.userPrincipalName)
| extend PropName = tostring(ModProp.displayName)
| extend NewValue = tostring(ModProp.newValue)
| project
    TimeGenerated,
    OperationName,
    Result,
    ResultReason,
    TargetUser,
    InitiatorUPN,
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
- Inspect `OperationName`, `ResultReason`, and `NewValue` in the KQL output.
- Identify **which method** was added or removed (e.g., *Microsoft Authenticator App*, *PhoneAppNotification*, *PhoneNumber*, *FIDO2*).
- Pay close attention if `User registered security info` is followed by `User deleted security info`.

### 2. Who did it?
- Compare `InitiatorUPN` and `TargetUser`:
  - If identical, the user (or an active session hijacker) performed the registration.
  - If different, an authentication administrator or *Service Principal* executed the change.
- Correlate `SourceIP` and timestamp against `SigninLogs` to check country, ASN, *User-Agent*, and any prior *Temporary Access Pass* or `deviceCode` flow.

### 3. Should they have been able to do it?
- Verify whether the *tenant* protects **Combined Registration** with *Conditional Access*:
  - Does *Register security information* require a trusted network, compliant device, or *Temporary Access Pass*?
  - Allowing external IPs to bind a second factor using only a password or stolen token creates high *bypass* risk.

### 4. Is there a formal ticket?
- For phone replacements or Helpdesk resets, cross-check your **ITSM** platform (**ServiceNow**, **Jira Service Management**, **Freshservice**, or **Zendesk**).
- Also confirm directly with the affected employee over a verified out-of-band channel whether they registered a new device at that time.

### 5. Was the session legitimate?
- Check Microsoft Entra ID Protection for risk alerts tied to `SourceIP` (`Risky sign-ins`, unfamiliar sign-in properties, or impossible travel).
- Verify `DeviceDetail.isCompliant` and `DeviceDetail.trustType` in `SigninLogs` for the same session.

---

## 4. Where to Investigate in the Portal (Microsoft Entra admin center)

To inspect registered methods and history in `entra.microsoft.com`:

1. **User authentication methods:**
   `Identity > Users > All users > [User] > Authentication methods` (review each device, registration timestamp, and phone number).
2. **Registration activity report:**
   `Protection > Authentication methods > Activity` (*Registration* and *Usage* tabs).
3. **Portal audit logs:**
   `Identity > Monitoring & health > Audit logs` (filter by **Target** = affected user or **Correlation ID**).

---

## 5. MITRE ATT&CK and Control Mapping

| Framework | Reference | Description |
|---|---|---|
| **MITRE ATT&CK** | `T1098.005` | *Account Manipulation: Device Registration* (unauthorized MFA/device registration for persistence). |
| **MITRE ATT&CK** | `T1556.006` | *Modify Authentication Process: Multi-Factor Authentication* (tampering with authentication factors). |
| **NIST SP 800-63B** | `AAL2` / `AAL3` | Secure authenticator binding and phishing-resistant *Passkeys* / FIDO2. |
| **CIS Controls v8** | `6.3` / `6.5` | Protecting MFA registration flows with trusted network/device requirements. |

---

## 6. Response and Containment Procedure

If the employee does not recognize the registration or the session is suspicious, execute this *playbook* immediately:

1. **Remove the rogue MFA method:** Under `Identity > Users > All users > [User] > Authentication methods`, delete the unrecognized authenticator or phone number immediately.
2. **Revoke sessions and reset credentials:** Click **Revoke sessions** on the user's profile and force a password reset; if their legitimate MFA method was deleted, issue a one-time *Temporary Access Pass* after identity verification.
3. **Harden Conditional Access:** Configure a policy targeting the **Register security information** user action requiring a compliant device or corporate location.
4. **Post-incident KQL audit:** Run the query below to review all sign-ins for the affected account over the past 48 hours and check for downstream app *secrets* or inbox rules:

```kql
let IncidentWindow = 48h;
let TargetAccount = "usuario@contoso.com";
SigninLogs
| where TimeGenerated >= ago(IncidentWindow)
| where UserPrincipalName == TargetAccount
| project
    TimeGenerated,
    ResultType,
    AppDisplayName,
    IPAddress,
    Location,
    UserAgent,
    AuthenticationRequirement,
    RiskLevelDuringSignIn,
    CorrelationId
| order by TimeGenerated desc
```

---

## References

- [Microsoft Learn — Built-in detections in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Microsoft Learn — Authentication methods activity in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity)
- [MITRE ATT&CK — T1098.005: Device Registration](https://attack.mitre.org/techniques/T1098/005/)
