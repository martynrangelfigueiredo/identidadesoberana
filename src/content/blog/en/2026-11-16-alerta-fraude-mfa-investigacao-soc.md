---
title: "MFA Fraud Alert in Microsoft Security: Triage and Incident Response Playbook for SOC Analysts"
description: "Hands-on Microsoft Security guide to investigating user-reported MFA fraud and explicit deny alerts in Microsoft Sentinel, analyzing SigninLogs, AuditLogs, and Entra ID containment."
date: 2026-11-16
categoria: SOC
tags: [microsoft-security, sentinel, soc, entra-id, mfa, kql, incident-response, playbooks, investigacao]
nivel: Intermediário
---

In a Security Operations Center (SOC), few alerts demand faster response than a **user-reported MFA fraud alert** (*user reported suspicious MFA prompt* or *Explicit MFA Deny*). Unlike generic brute-force or password spray attempts that fail at the first step, this alert indicates a critical condition: **the adversary already holds the legitimate primary credentials (username and password)**. The single barrier that blocked unauthorized access was the user's active refusal during the second factor challenge.

When an employee receives a number matching push notification on Microsoft Authenticator and selects "No, it's not me", Microsoft Entra ID records the authentication failure and creates security audit events that trigger analytical detection rules in Microsoft Sentinel.

> 📘 **Official Microsoft Learn References:**
> - [Microsoft Entra ID sign-in error codes — Error 500121](https://learn.microsoft.com/entra/identity/monitoring-health/concept-sign-ins#sign-in-error-codes)
> - [Investigating incidents in Microsoft Sentinel](https://learn.microsoft.com/azure/sentinel/investigate-incidents)
> - [Microsoft Sentinel built-in analytics rule template catalog](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in)

---

## 1. What Does an MFA Fraud Alert Signify?

When a user flags a prompt as fraud in their authenticator app, Entra ID logs the event in `SigninLogs` under error code **500121** (*Authentication failed during strong authentication request*), accompanied by a result detail specifying that fraud was reported or the challenge was denied.

For the SOC team, this event must be treated as a high-priority incident (P1 or P2) without delay, as it proves three critical facts:
1. **Valid credentials are in adversary hands:** The attacker completed the first authentication stage successfully (valid username and password).
2. **Active real-time engagement:** The attacker is actively interacting with the sign-in endpoint or enterprise application right now.
3. **Immediate follow-up risk:** The adversary may pivot to other attack vectors, such as MFA fatigue (*push bombing*), Adversary-in-the-Middle (AitM) attacks to capture session tokens, or targeting legacy protocols where MFA is not enforced.

---

## 2. KQL Tip: Investigating denied and fraud-reported MFA requests

The query below projects useful columns to contextualize the authentication event, mapping the source IP address, requested application, and detailed MFA step result:

```kql
// ====================================================================================
// Consulta: Identificando alertas de fraude em MFA e tentativas de logon bloqueadas
// Objetivo: Mapear usuario alvo, IP de origem da tentativa, localizacao e detalhes de autenticacao
// ====================================================================================
let JanelaTempo = 24h;
SigninLogs
| where TimeGenerated >= ago(JanelaTempo)
| where ResultType == 500121
| mv-expand AuthDetail = AuthenticationDetails
| extend DetalhePasso = tostring(AuthDetail.authenticationStepResultDetail)
| where ResultDescription has "fraud" 
     or DetalhePasso has "fraud" 
     or ResultDescription has "denied" 
     or DetalhePasso has "denied"
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    AppDisplayName,
    ClientAppUsed,
    ResultType,
    ResultDescription,
    DetalhePasso,
    RiskLevelDuringSignIn,
    CorrelationId
| order by TimeGenerated desc
```

### Key observations in the results:
- **`IPAddress` and `Location`:** Compare the IP address that triggered the MFA prompt against the user's typical sign-in baseline. Commercial VPNs, anonymizing proxies, Tor exit nodes, or unfamiliar countries strongly indicate external malicious activity.
- **`AppDisplayName`:** Reveals whether the attacker attempted to access the `Azure Portal`, corporate email (`Office 365 Exchange Online`), or a third-party federated SaaS app.
- **`CorrelationId`:** Vital correlation key used to cross-reference concurrent events in `AuditLogs` across the tenant.

---

## 3. Investigation Playbook: The 5 Mandatory Questions

When triaging the incident in Microsoft Sentinel, analysts should systematically answer the following questions:

### 1. What was done?
Examine the telemetry. Did the challenge employ number matching? Did the employee simply click "Deny" or explicitly select "Report Fraud"? Does the timestamp align with the employee's typical working hours?

### 2. Who initiated it?
Inspect the target account (`UserPrincipalName`). Is this an executive (VIP), a developer with CI/CD pipeline access, or an identity holding directory roles (such as *Global Administrator* or *Privileged Role Administrator*)?

### 3. Was it potentially legitimate?
Verify whether the employee was traveling or configuring a new mobile device. If the request originated from an unfamiliar residential ISP abroad while the user is actively working in their home office, external compromise is strongly confirmed.

### 4. Is there an existing ticket in the ITSM platform?
Check the ticketing system (ServiceNow, Jira Service Management, Freshservice, or Zendesk). Did the employee submit a support request reporting an unsolicited prompt on their phone? An active report provides immediate validation of legitimate user rejection.

### 5. Was there prior or subsequent successful access?
Did the attacker manage to sign in successfully minutes before or after the alert (e.g., via a legacy protocol lacking MFA enforcement, or from a previously trusted device)?

---

## 4. Investigating in the Microsoft Entra Admin Center

For Tier 1 and Tier 2 analysts verifying telemetry directly within the identity portal:

1. Open the **Microsoft Entra admin center** (`entra.microsoft.com`).
2. Navigate to **Identity > Monitoring & health > Sign-in logs**.
3. Under **User sign-ins (interactive)**, apply filters:
   - **Status:** *Failure*
   - **Error code:** *500121*
4. Select the incident entry and review:
   - **Basic info:** Correlation ID, IP address, and physical location.
   - **Authentication Details:** Confirm the challenge method (e.g., *Mobile app notification*) and the exact step outcome (*Fraud reported by user*).
   - **Conditional Access:** Review which Conditional Access policies were evaluated during the request.
5. Next, open **Identity > Protection > Risky users**:
   - Check whether the account was elevated to **Medium** or **High** risk state.
   - In **Risk detections**, inspect linked signals such as *Unfamiliar sign-in properties* or *Suspicious user reported activity*.

---

## 5. Containment and Immediate Response Procedures

Once credential compromise is verified, the SOC incident response playbook must execute immediate containment:

1. **Revoke active sessions (*Revoke sessions*):**
   - On the user profile blade in Entra ID, click **Revoke sessions** (or execute PowerShell `Revoke-MgUserSignOut -UserId <UPN>`). This invalidates all active refresh tokens issued for the account.
2. **Force an emergency password reset:**
   - Because the attacker knows the current password, execute a mandatory password reset and deliver the temporary credentials via a secure, out-of-band communication channel.
3. **Audit registered authentication methods (*Authentication methods*):**
   - Navigate to **Identity > Users > [User] > Authentication methods**. Ensure no rogue methods (secondary phone numbers, unauthorized authenticator apps, or unfamiliar FIDO2 keys) were registered prior to containment.
4. **Inspect for persistence in email and OAuth apps:**
   - Review Exchange Online inbox rules for unauthorized external forwarding (`ForwardTo`).
   - Audit `AuditLogs` for any suspicious OAuth application consent granted by the user before the alert.

---

## 6. Post-Incident KQL Query: Auditing Concurrent Sign-In Activity

After executing containment, run the query below to audit all authentication attempts for the target identity over the last 48 hours to confirm whether any attempt succeeded (`ResultType == 0`):

```kql
// ====================================================================================
// Verificacao Pos-Incidente: Investigando atividade da conta e tentativas com sucesso
// Objetivo: Confirmar se o atacante obteve acesso previo ou posterior ao alerta de fraude
// ====================================================================================
let JanelaAnalise = 48h;
let UsuarioInvestigado = "usuario.alvo@contoso.com";
SigninLogs
| where TimeGenerated >= ago(JanelaAnalise)
| where tolower(UserPrincipalName) == tolower(UsuarioInvestigado)
| extend StatusAuth = iff(ResultType == 0, "Sucesso", "Falha")
| project
    TimeGenerated,
    UserPrincipalName,
    AppDisplayName,
    IPAddress,
    Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    StatusAuth,
    ResultType,
    ResultDescription,
    RiskLevelDuringSignIn,
    RiskState
| order by TimeGenerated desc
```

### Incident Classification Matrix (TP vs. FP):

| Analysis Scenario | Classification | SOC Action |
|---|---|---|
| Employee did not initiate attempt, foreign suspicious IP, primary password valid | **True Positive (TP)** | Isolate account, revoke sessions, reset password, and initiate endpoint malware/phishing triage. |
| Employee accidentally tapped "No, it's not me" on their own phone while accessing work apps | **False Positive (FP)** | Confirm with the employee via corporate channel, provide guidance, and close the Sentinel alert with documentation. |
| Unfamiliar IP triggers fraud alert, followed by successful logon via legacy protocol | **Critical Incident (TP)** | Escalate to Tier 3 / DFIR for threat hunting, forensic examination, and block legacy protocols via Conditional Access. |
