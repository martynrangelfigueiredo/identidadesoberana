---
title: "Privilege Escalation via PIM: Operational Investigation Guide for SOC Analysts"
description: "Comprehensive guide to investigating Microsoft Entra privileged role assignments and PIM activations in Microsoft Sentinel: Enriched KQL and ITSM ticket validation."
date: 2026-11-09
categoria: IAM
tags: [sentinel, azure, entra-id, pim, iam, soc, rbac, kql]
nivel: Advanced
---

Assigning high-privilege directory roles (such as *Global Administrator*, *Privileged Role Administrator*, or *Security Administrator*) represents one of the most sensitive operations in Microsoft Entra ID. When such assignments occur outside standard change windows or lack an associated change ticket, it signals either a severe identity governance failure or an active threat actor seeking tenant-wide persistence.

> **TL;DR for SOC Analysts:** Immediately check `AuditLogs` to verify who assigned the role (`InitiatedBy`), which role was granted, and whether a valid ticket ID is present in `ResultReason`. In the absence of an authorized ticket, revoke the assignment in PIM and invalidate the user's active sessions.

> 📘 **Microsoft Learn Official Reference:** This playbook is built upon Microsoft Sentinel built-in detection rules:
> - [Microsoft Sentinel — Built-in scheduled analytics rules catalog (Learn)](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in)
> - [Microsoft Entra Privileged Identity Management — Audit logs and assignment monitoring (Learn)](https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-use-audit-log)

---

## 1. Understanding the Incident

Microsoft Sentinel raises this alert whenever an administrator or service principal activates or assigns a privileged role through Microsoft Entra PIM:
1. **Legitimate PIM Activation:** An eligible administrator activates their role for a time-bound window backed by a ticket.
2. **Direct Permanent Role Assignment:** A bypass of PIM governance by granting permanent administrative rights directly.
3. **Malicious Persistence:** A compromised identity elevating permissions on a secondary account to retain tenant control.

---

## 2. Dica de KQL: Enriching PIM AuditLogs with Signin Context

The following query correlates PIM role assignment events with the initiator's interactive sign-in logs to capture IP address, MFA requirements, and risk level:

```kql
// ====================================================================================
// Deteccao & Enriquecimento: Privileged Role Assignment via PIM
// Autor: Identidade Soberana (identidadesoberana.com.br)
// Goal: Map actor, target account, role, justification, IP, MFA, and risk level
// ====================================================================================
let tempoAnalise = 24h;
// 1. Extract PIM audit events
let EventosPIM = AuditLogs
| where TimeGenerated >= ago(tempoAnalise)
| where LoggedByService == "Privileged Identity Management" or LoggedByService == "Core Directory"
| where ActivityDisplayName in (
    "Add member to role in PIM completed (permanent)",
    "Add member to role in PIM completed (time-bound)",
    "Add member to role completed (PIM activation)",
    "Add eligible member to role in PIM completed",
    "Add member to role in PIM request approved"
)
| mv-expand Target = TargetResources
| mv-expand ModProp = Target.modifiedProperties
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName),
         InitiatorIP = tostring(InitiatedBy.user.ipAddress),
         InitiatorApp = tostring(InitiatedBy.app.displayName),
         TargetUPN = tostring(Target.userPrincipalName),
         RoleAssigned = tostring(ModProp.newValue)
| where RoleAssigned in (
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "User Administrator",
    "Cloud Application Administrator",
    "Application Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Intune Administrator",
    "Conditional Access Administrator"
) or isempty(RoleAssigned)
| extend JustificativaFinal = iff(isempty(ResultReason), "Nenhuma justificativa informada", tostring(ResultReason))
| project 
    TimeGenerated,
    CorrelationId,
    ActivityDisplayName,
    RoleAssigned,
    TargetUPN,
    InitiatorUPN = iff(isempty(InitiatorUPN), InitiatorApp, InitiatorUPN),
    JustificativaFinal,
    Result;
// 2. Cross-correlate with SigninLogs for authentication signals
let SinaisLogon = SigninLogs
| where TimeGenerated >= ago(tempoAnalise)
| mv-expand AuthDetail = AuthenticationDetails
| project 
    CorrelationId,
    UserPrincipalName,
    IPAddress,
    Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    AuthMFA = AuthenticationRequirement,
    MfaResult = tostring(AuthDetail.authenticationStepResultDetail),
    ClientApp = ClientAppUsed,
    UserAgent = DeviceDetail.operatingSystem,
    RiskLevel = RiskLevelDuringSignIn;
EventosPIM
| join kind=leftouter (SinaisLogon) on CorrelationId
| project
    DataHora = TimeGenerated,
    Acao = ActivityDisplayName,
    RoleAtribuida = RoleAssigned,
    UsuarioAlvo = TargetUPN,
    AtorOriginador = InitiatorUPN,
    Justificativa = JustificativaFinal,
    IPOrigem = iff(isempty(IPAddress), "N/A", IPAddress),
    Localizacao = iff(isempty(Location), "N/A", Location),
    MFAStatus = iff(isempty(AuthMFA), "N/A", AuthMFA),
    NivelRiscoSessao = iff(isempty(RiskLevel), "none", tostring(RiskLevel)),
    IDCorrelacao = CorrelationId
| order by DataHora desc
```

---

## 3. Investigation Checklist

| Focus Area | Evidence Source | What to Verify |
|---|---|---|
| **1. What role was granted?** | `AuditLogs` / `RoleAssigned` | Permanent or eligible? Does it match expected operational duties? |
| **2. Who granted it?** | `InitiatedBy` & `SigninLogs` | Which account performed the approval? Did sign-in pass MFA without risk flags? |
| **3. Authorization check?** | Entra Role Permissions | Did the caller hold *Privileged Role Administrator* status? |
| **4. ITSM cross-reference?** | ServiceNow, Jira, Zendesk | Is there an approved ticket associated with this specific elevation? |
| **5. Portal audit route?** | Entra Admin Center | PIM > Microsoft Entra Roles > Resource Audit. |

---

## 4. Containment Procedure

1. **Remove role assignment:** In PIM console, click *Remove assignment*.
2. **Invalidate tokens:** Execute `Revoke sessions` against the elevated account.
3. **Execute forensic KQL:**

```kql
let usuarioSuspeito = "usuario.alvo@seudominio.com.br";
let inicioJanela = datetime(2026-11-09T14:00:00Z);
let fimJanela = datetime(2026-11-09T18:00:00Z);
AuditLogs
| where TimeGenerated between (inicioJanela .. fimJanela)
| mv-expand Target = TargetResources
| where InitiatedBy.user.userPrincipalName == usuarioSuspeito
| project 
    TimeGenerated,
    OperationName = ActivityDisplayName,
    Category,
    Target = tostring(Target.displayName),
    TargetType = tostring(Target.type),
    ModifiedProperties = Target.modifiedProperties,
    Result
| order by TimeGenerated asc
```
