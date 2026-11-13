---
title: "Investigating MFA Fatigue and Second-Factor Bypasses: SOC Playbook"
description: "Comprehensive SOC playbook for triaging and containing MFA Fatigue and AitM reverse-proxy incidents in Microsoft Sentinel: Enriched KQL, sign-in and audit logs correlation, and immediate response."
date: 2026-11-09
categoria: SOC
tags: [sentinel, mfa, entra-id, kql, aitm, incident-response, soc, iam]
nivel: Intermediate
---

Attacks targeting Multi-Factor Authentication (MFA) have drastically evolved. While enforcing a second factor was once sufficient to neutralize credential stuffing, threat actors now actively bypass legacy authenticators via **MFA fatigue (*push spamming*)** and **Adversary-in-the-Middle (AitM)** reverse proxies.

In Microsoft Sentinel, incidents triggered by MFA anomalies represent critical emergencies for response teams: the user's primary password is confirmed compromised, and the attacker is actively pushing to breach the final barrier.

> **TL;DR for SOC Analysts:** Treat this incident as a confirmed credential compromise. If multiple MFA rejections are followed by a successful sign-in from an unfamiliar IP, initiate immediate containment: revoke active sessions (`Revoke sessions`), enforce a password reset, and verify if new authentication methods were registered on the account.

> 📘 **Microsoft Learn Official Reference:** This playbook is aligned with Microsoft Sentinel built-in detection rules and Microsoft Entra ID hardening guidelines:
> - [Microsoft Sentinel — Built-in scheduled analytics rules catalog (Learn)](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in)
> - [Microsoft Entra ID — Protecting against MFA fatigue and deploying phishing-resistant methods (Learn)](https://learn.microsoft.com/azure/active-directory/authentication/concept-authentication-methods)

---

## 1. Understanding the Incident

When an MFA anomaly detection rule triggers in Microsoft Sentinel, it typically points to one of the following intrusion stages:

1. **MFA Fatigue Attack (*Push Bombing*):** The attacker has the valid password and floods the user's Microsoft Authenticator app with repeated approval prompts, often late at night, until the employee inadvertently accepts.
2. **Session Interception via AitM Proxy (e.g., Evilginx / Modlishka):** The victim browsed to a cloned sign-in page that proxied and captured credentials and session cookies in real time.
3. **Repeated Failures Followed by Anomalous Success:** The alert captures multiple `500121` (MFA denied) error events immediately succeeded by a `0` (success) from an unusual ASN or geo-location.
4. **Benign False Positive:** Temporary network drops or multiple user re-prompts during traveling.

---

## 2. Dica de KQL: Correlating MFA fatigue with subsequent successful logon

The following query correlates denied authentication attempts with subsequent successful sign-ins within a given time frame, projecting valuable context such as authentication methods, location, operating system, and session risk levels:

```kql
// ====================================================================================
// Detecção & Enriquecimento: MFA Fatigue seguida de Logon Bem-Sucedido
// Autor: Identidade Soberana (identidadesoberana.com.br)
// Goal: Track repeated MFA denials culminating in successful sign-in from anomalous IP
// ====================================================================================
let janelaAnalise = 24h;
let limiarFalhasMFA = 3;
// 1. Identify accounts with repeated MFA denials or challenges not completed (ResultType 500121 / 50074)
let NegacoesMFA = SigninLogs
| where TimeGenerated >= ago(janelaAnalise)
| where ResultType in (500121, 50074)
| summarize 
    QtdNegacoes = count(),
    PrimeiraFalha = min(TimeGenerated),
    UltimaFalha = max(TimeGenerated),
    IPsFalha = make_set(IPAddress, 5),
    LocaisFalha = make_set(Location, 5),
    UserAgentsFalha = make_set(UserAgent, 3)
    by UserPrincipalName, bin(TimeGenerated, 15m)
| where QtdNegacoes >= limiarFalhasMFA;
// 2. Query subsequent successful logons for the same account
let LogonsSucesso = SigninLogs
| where TimeGenerated >= ago(janelaAnalise)
| where ResultType == 0
| mv-expand AuthDetail = AuthenticationDetails
| project 
    HoraSucesso = TimeGenerated,
    UserPrincipalName,
    IPSucesso = IPAddress,
    LocalSucesso = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    Dispositivo = DeviceDetail.operatingSystem,
    Navegador = ClientAppUsed,
    MetodoMFA = tostring(AuthDetail.authenticationMethod),
    DetalheMFA = tostring(AuthDetail.authenticationStepResultDetail),
    RiscoSessao = RiskLevelDuringSignIn,
    IDCorrelacao = CorrelationId;
// 3. Temporal cross-correlation: Success within 30 minutes of repeated denials
NegacoesMFA
| join kind=inner (LogonsSucesso) on UserPrincipalName
| where HoraSucesso between (UltimaFalha .. (UltimaFalha + 30m))
| project
    DataHoraAlerta = UltimaFalha,
    DataHoraSucesso = HoraSucesso,
    UsuarioAlvo = UserPrincipalName,
    TentativasNegadas = QtdNegacoes,
    MetodoAutenticacao = MetodoMFA,
    ResultadoMFA = DetalheMFA,
    IPLogonSucesso = IPSucesso,
    LocalizacaoSucesso = LocalSucesso,
    IPsAtaque = IPsFalha,
    RiscoSessao = iff(isempty(RiscoSessao), "none", tostring(RiscoSessao)),
    IDCorrelacao = IDCorrelacao
| order by DataHoraSucesso desc
```

---

## 3. Investigation Matrix: 5 Mandatory Questions

| Question | Where to Validate | What to Inspect |
|---|---|---|
| **1. What occurred?** | `SigninLogs` / `AuthenticationDetails` | How many prompts were issued? Did approval follow consecutive rejections? |
| **2. Who initiated it?** | `IPAddress`, `LocationDetails`, ASN | Does the IP belong to corporate VPN or commercial hosting / proxy services (AWS, Tor)? |
| **3. Was it authorized?** | User activity history | Did this take place during working hours? Has the employee traveled to this location? |
| **4. Is there an out-of-band check?** | Direct user confirmation | Reach the employee through an **alternative channel** (phone call or corporate chat) to verify the login attempt. |
| **5. Was the session legitimate?** | `AADUserRiskEvents` & `AuditLogs` | Were alerts like *Anomalous Token*, *Unfamiliar sign-in*, or new device registrations raised? |

---

## 4. Microsoft Entra Admin Center Workflow

1. Navigate to:
   > **Identity** > **Users** > Select affected user > **Sign-in logs**.
2. Select the **Interactive user sign-ins** tab and review the successful event immediately following the failures.
3. Check under **Identity Protection** > **Risk detections** for correlated threats.

---

## 5. Containment & Response Procedure

```
[MFA Fatigue Incident Confirmed]
        │
        ├── 1. Revoke active sessions immediately:
        │      Microsoft Entra > Users > [User] > "Revoke sessions"
        │
        ├── 2. Force an immediate account password reset
        │
        ├── 3. Audit and purge authentication methods:
        │      Verify if new phone numbers or rogue authenticator apps were registered
        │
        ├── 4. Block malicious IPs in firewall / Conditional Access policies
        │
        └── 5. Execute post-compromise forensic KQL query
```

### Forensic KQL: Actions Following MFA Bypass

```kql
let usuarioComprometido = "colaborador@seudominio.com.br";
let inicioIncidente = datetime(2026-11-09T00:00:00Z);
AuditLogs
| where TimeGenerated >= inicioIncidente
| mv-expand Target = TargetResources
| where InitiatedBy.user.userPrincipalName == usuarioComprometido
   or Target.userPrincipalName == usuarioComprometido
| where ActivityDisplayName in (
    "User registered security info",
    "User deleted security info",
    "User registered all required security info",
    "Admin registered security info",
    "Add member to role completed (PIM activation)",
    "Add application",
    "Add service principal credentials"
)
| project 
    DataHora = TimeGenerated,
    Operacao = ActivityDisplayName,
    Ator = tostring(InitiatedBy.user.userPrincipalName),
    Alvo = tostring(Target.userPrincipalName),
    PropriedadesModificadas = Target.modifiedProperties,
    IDCorrelacao = CorrelationId
| order by DataHora asc
```

---

## 6. Root-Cause Mitigation Controls

1. **Enforce Number Matching:** Eliminate blind push approvals across all user populations.
2. **Show Geographic Context:** Display application name and requester location in push notifications.
3. **Transition to FIDO2 / Passkeys:** Hardware security keys (YubiKey, Windows Hello for Business) cryptographically tie challenges to legitimate origins, preventing AitM and push bombing completely.

