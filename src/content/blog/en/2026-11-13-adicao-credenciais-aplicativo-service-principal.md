---
title: "Addition of Secrets and Credentials to Entra ID Applications: SOC Investigation Guide"
description: "SOC operational playbook for triaging and containing suspicious client secrets and certificates added to Microsoft Entra ID Service Principals and App Registrations."
date: 2026-11-13
categoria: IAM
tags: [sentinel, azure, entra-id, service-principal, oauth, soc, iam, dfir, kql]
nivel: Advanced
---

The unauthorized creation of a new client secret (*client secret*) or digital certificate on a registered application within Microsoft Entra ID is one of the most critical indicators of persistence and privilege escalation in cloud environments (**MITRE ATT&CK T1098.001**). Experienced adversaries leverage this vector to establish secondary access pathways that do not depend on human user credentials and bypass Multi-Factor Authentication (MFA).

> **TL;DR for SOC Analysts:** If the creation of the secret is not linked to an approved change request or automated CI/CD pipeline, treat it as a **True Positive (High/Critical)**. Immediately delete the newly added secret in *App registrations*, inspect workload sign-ins in `AADServicePrincipalSignInLogs`, and revoke active sessions for the operator account.

> 📘 **Microsoft Learn Official Reference:** This playbook is aligned with Microsoft Sentinel built-in detection rules and workload identity security architecture:
> - [Microsoft Sentinel — Built-in scheduled analytics rules catalog (Learn)](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in)
> - [Microsoft Entra ID — Securing and monitoring workload identities (Learn)](https://learn.microsoft.com/entra/architecture/protect-workload-identities)

---

## 1. Understanding the Incident

In Microsoft Entra ID, automated applications utilize **Workload Identities (Service Principals)** to query Microsoft Graph, databases, and Azure resources without human intervention.

To authenticate against Microsoft identity endpoints (`login.microsoftonline.com`), a Service Principal supplies:
1. A plaintext secret (*Client Secret*);
2. An asymmetric certificate (*X.509 Certificate*);
3. An OIDC federated credential (such as GitHub Actions).

When an adversary compromises an account holding the **Application Administrator** or **Cloud Application Administrator** role, they frequently generate a long-lived client secret on a pre-existing trusted application that already possesses high-privilege permissions (such as `Directory.ReadWrite.All`). Once generated, the attacker connects directly through APIs, completely bypassing user-targeted MFA and Conditional Access device requirements.

---

## 2. Dica de KQL: Tracking new secrets and operator context

The query below correlates application credential update events with the initiator's interactive sign-in logs to extract IP address, geo-location, MFA, and session risk levels:

```kql
// ====================================================================================
// Deteccao & Enriquecimento: Nova credencial adicionada a aplicativo ou Service Principal
// Autor: Identidade Soberana (identidadesoberana.com.br)
// Goal: Map actor, target application, secret type, IP, and sign-in context
// ====================================================================================
let tempoAnalise = 24h;
let EventosCredencial = AuditLogs
| where TimeGenerated >= ago(tempoAnalise)
| where ActivityDisplayName in (
    "Update application - Certificates and secrets management ",
    "Add service principal credentials",
    "Add service principal",
    "Update application"
)
| mv-expand Target = TargetResources
| mv-expand ModProp = Target.modifiedProperties
| where ModProp.displayName in ("KeyDescription", "CredentialData", "TargetId.KeyDescription") 
     or ActivityDisplayName == "Add service principal credentials"
| extend AtorUPN = tostring(InitiatedBy.user.userPrincipalName),
         AtorIP = tostring(InitiatedBy.user.ipAddress),
         AtorApp = tostring(InitiatedBy.app.displayName),
         NomeApp = tostring(Target.displayName),
         AppIdAlvo = tostring(Target.id),
         DetalheModificacao = tostring(ModProp.newValue)
| extend AtorFinal = iff(isempty(AtorUPN), AtorApp, AtorUPN)
| project
    TimeGenerated,
    CorrelationId,
    ActivityDisplayName,
    NomeApp,
    AppIdAlvo,
    AtorFinal,
    DetalheModificacao,
    Result;
let SinaisLogon = SigninLogs
| where TimeGenerated >= ago(tempoAnalise)
| mv-expand AuthDetail = AuthenticationDetails
| project
    CorrelationId,
    UserPrincipalName,
    IPAddress,
    Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    MFAStatus = AuthenticationRequirement,
    DetalheMFA = tostring(AuthDetail.authenticationStepResultDetail),
    RiskLevel = RiskLevelDuringSignIn;
EventosCredencial
| join kind=leftouter (SinaisLogon) on CorrelationId
| project
    DataHora = TimeGenerated,
    Acao = ActivityDisplayName,
    AplicativoAlvo = NomeApp,
    IdAplicativo = AppIdAlvo,
    AtorOriginador = AtorFinal,
    DetalheCredencial = DetalheModificacao,
    IPOrigem = iff(isempty(IPAddress), "N/A", IPAddress),
    Localizacao = iff(isempty(Location), "N/A", Location),
    MFA = iff(isempty(MFAStatus), "N/A", MFAStatus),
    NivelRisco = iff(isempty(RiskLevel), "none", tostring(RiskLevel)),
    IDCorrelacao = CorrelationId
| order by DataHora desc
```

---

## 3. Investigation Matrix

| Question | Validation Source | Inspection Focus |
|---|---|---|
| **1. What was created?** | `AuditLogs` / `TargetResources` | Client secret or X.509 certificate? What is the expiration date? |
| **2. Who generated it?** | `InitiatedBy` & `SigninLogs` | Human user or automated pipeline? What was the source IP? |
| **3. Authorization check?** | Entra Role Permissions | Did the caller hold *Application Administrator* rights or App ownership? |
| **4. Ticket verification?** | ServiceNow, Jira, Freshservice | Is there an approved change record for credential rotation? |
| **5. Portal route?** | Entra Admin Center | App registrations > API permissions and Service principal sign-in logs. |

---

## 4. Response & Containment Procedure

1. **Delete rogue secret immediately:** In *App registrations* > *Certificates & secrets*, locate and delete the unauthorized secret.
2. **Contain initiator account:** Perform `Revoke sessions` and reset the user's password.
3. **Execute forensic KQL:**

```kql
let appIdSuspeito = "00000000-0000-0000-0000-000000000000";
let inicioJanela = datetime(2026-11-13T00:00:00Z);
AADServicePrincipalSignInLogs
| where TimeGenerated >= inicioJanela
| where AppId == appIdSuspeito
| project
    DataHora = TimeGenerated,
    NomeApp = ServicePrincipalName,
    IdApp = AppId,
    IPOrigem = IPAddress,
    Localizacao = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    RecursoAcessado = ResourceDisplayName,
    StatusResultado = ResultType,
    DescricaoResultado = ResultDescription,
    IDCorrelacao = CorrelationId
| order by DataHora asc
```

