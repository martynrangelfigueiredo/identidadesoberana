---
title: "Rechteausweitung via PIM: Praktischer Untersuchungsleitfaden für SOC-Analysten"
description: "Vollständiger Leitfaden zur Untersuchung von Rollenzuweisungen und PIM-Aktivierungen im Microsoft Sentinel: KQL-Anreicherung, AuditLogs- und SigninLogs-Abgleich."
date: 2026-11-09
categoria: IAM
tags: [sentinel, azure, entra-id, pim, iam, soc, rbac, kql]
nivel: Fortgeschritten
---

Die Zuweisung privilegierter Administratorrollen (wie *Global Administrator*, *Privileged Role Administrator* oder *Security Administrator*) stellt eine der kritischsten Operationen im Microsoft Entra ID dar. Wenn solche Zuweisungen außerhalb von Wartungsfenstern oder ohne verknüpftes Änderungsticket erfolgen, signalisiert dies im SOC entweder ein schwerwiegendes Governance-Versäumnis oder einen aktiven Angreifer, der versucht, Persistenz auf Tenant-Ebene zu sichern.

> **TL;DR für das SOC:** Prüfen Sie sofort in `AuditLogs`, wer die Rolle zugewiesen hat (`InitiatedBy`), welche Rolle vergeben wurde und ob im Feld `ResultReason` eine gültige Ticketnummer hinterlegt ist. Bei fehlendem Ticket oder verdächtigem Benutzerkonto sperren Sie die Rollenzuweisung sofort im PIM und widerrufen die Benutzersitzungen.

> 📘 **Referenz in Microsoft Learn:** Dieses Playbook basiert auf den nativen Überwachungsregeln von Microsoft Sentinel:
> - [Microsoft Sentinel — Katalog integrierter Analyse-Erkennungsregeln (Learn)](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in)
> - [Microsoft Entra Privileged Identity Management — Überwachung und Auditverlauf (Learn)](https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-use-audit-log)

---

## 1. Was bedeutet dieser Vorfall?

Microsoft Sentinel löst diesen Vorfall aus, wenn ein Administrator oder ein Dienstprinzipal einem Benutzer eine privilegierte Verzeichnisrolle über Microsoft Entra PIM zuweist oder aktiviert:
1. **Reguläre PIM-Aktivierung:** Ein berechtigter Benutzer aktiviert seine Rolle für ein zeitlich begrenztes Fenster mit Ticketnummer.
2. **Direkte dauerhafte Rollenzuweisung:** Umgehung des PIM-Prinzips durch direkte Vergabe permanenter Administratorrechte.
3. **Böswillige Persistenz:** Ein kompromittiertes Konto weist einer Zweitidentität uneingeschränkte Rechte zu.

---

## 2. Dica de KQL: Anreicherung von AuditLogs und SigninLogs

Die folgende Abfrage projiziert zusätzliche Informationen zur Kontextualisierung des Ereignisses, indem sie PIM-Auditereignisse mit Anmeldedaten korreliert:

```kql
// ====================================================================================
// Deteccao & Enriquecimento: Privileged Role Assignment via PIM
// Autor: Identidade Soberana (identidadesoberana.com.br)
// Ziel: Akteur, Zielkonto, Rolle, Begründung, IP, MFA und Risikostufe abbilden
// ====================================================================================
let tempoAnalise = 24h;
// 1. PIM-Auditereignisse erfassen
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
// 2. Anmeldekontext aus SigninLogs hinzufügen
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

## 3. Untersuchungsmatrix: 5 obligatorische Leitfragen

| Leitfrage | Wo validieren | Zu prüfende Punkte |
|---|---|---|
| **1. Was wurde getan?** | `AuditLogs` / `RoleAssigned` | Welche Rolle wurde vergeben? Permanent oder zeitlich begrenzt? |
| **2. Wer hat es getan?** | `InitiatedBy` & `SigninLogs` | Welcher Administrator hat die Genehmigung erteilt? IP und MFA prüfen. |
| **3. War die Aktion autorisiert?** | PIM-Rollenberechtigungen | Besitzt der Ausführende die Rolle *Privileged Role Administrator*? |
| **4. Gibt es ein Ticket?** | ServiceNow, Jira, Zendesk | Existiert ein genehmigtes Ticket mit passendem Zeitfenster? |
| **5. Untersuchung im Portal?** | Entra Admin Center | PIM > Microsoft Entra Roles > Resource Audit aufrufen. |

---

## 4. Untersuchung im Portal

Navigieren Sie im Microsoft Entra Admin Center zu:
> **Identity Governance** > **Privileged Identity Management** > **Microsoft Entra Roles** > **Assignments**.

Prüfen Sie, ob die Zuweisung aktiv ist, welche Endzeit definiert wurde und welche Begründung der Antragsteller angegeben hat.

---

## 5. Reaktions- und Eindämmungsverfahren

1. **Rolle sofort entziehen:** Im PIM die Zuweisung widerrufen (*Remove assignment*).
2. **Sitzungen beenden:** `Revoke sessions` für das begünstigte Konto ausführen.
3. **Forensische KQL-Abfrage ausführen:**

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
