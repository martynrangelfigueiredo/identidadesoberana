---
title: "Hinzufügen von Secrets und Anmeldedaten zu Entra ID-Apps: Untersuchungsleitfaden für das SOC"
description: "Vollständiges SOC-Playbook zur Untersuchung neuer Client Secrets und Zertifikate in Service Principals und App Registrations im Microsoft Entra ID."
date: 2026-11-13
categoria: IAM
tags: [sentinel, azure, entra-id, service-principal, oauth, soc, iam, dfir, kql]
nivel: Fortgeschritten
---

Die undokumentierte Erstellung eines neuen Client Secrets (*Client Secret*) oder digitalen Zertifikats in einer registrierten App im Microsoft Entra ID ist einer der kritischsten Indikatoren für Persistenz und Rechteausweitung in Cloud-Umgebungen (**MITRE ATT&CK T1098.001**). Angreifer nutzen diese Methode, um sekundäre Zugänge einzurichten, die weder von Passwörtern noch von MFA abhängen.

> **TL;DR für das SOC:** Wenn die Erstellung des Secrets nicht mit einem genehmigten Change-Ticket verknüpft ist, behandeln Sie den Vorfall sofort als **True Positive (High/Critical)**. Löschen Sie das hinzugefügte Secret in *App registrations*, prüfen Sie Logons in `AADServicePrincipalSignInLogs` und widerrufen Sie die Sitzungen des ausführenden Kontos.

> 📘 **Referenz in Microsoft Learn:** Dieses Playbook basiert auf den Standardregeln des Microsoft Sentinel-Katalogs:
> - [Katalog integrierter Erkennungsregeln in Microsoft Sentinel (Learn)](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in)
> - [Sicherheit und Überwachung von Workload-Identitäten im Entra ID (Learn)](https://learn.microsoft.com/entra/architecture/protect-workload-identities)

---

## 1. Was bedeutet dieser Vorfall?

Im Microsoft Entra ID nutzen Anwendungen **Workload Identities (Service Principals)**, um automatisierte Zugriffe auf APIs, Datenbanken oder Azure-Ressourcen ohne Benutzerinteraktion durchzuführen.

Zur Authentifizierung verwendet der Service Principal:
1. Ein Kennwort (*Client Secret*);
2. Ein asymmetrisches Zertifikat (*X.509 Certificate*);
3. Eine OIDC-Identitätsföderation (z. B. GitHub Actions).

Erlangt ein Angreifer Kontrolle über ein Konto mit den Rollen **Application Administrator** oder **Cloud Application Administrator**, generiert er häufig ein langlebiges neues Client Secret in einer bestehenden, vertrauenswürdigen App mit weitreichenden Graph-Berechtigungen (wie `Directory.ReadWrite.All`). Dadurch umgeht er MFA und Gerätekontrollen vollständig.

---

## 2. Dica de KQL: Neue Secrets und Akteurskontext nachverfolgen

Die folgende Abfrage projiziert zusätzliche Informationen, um das Ereignis im Microsoft Sentinel zu analysieren:

```kql
// ====================================================================================
// Deteccao & Enriquecimento: Nova credencial adicionada a aplicativo ou Service Principal
// Autor: Identidade Soberana (identidadesoberana.com.br)
// Ziel: Akteur, Ziel-App, Secret-Typ, IP und Anmeldekontext abbilden
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

## 3. Untersuchungsmatrix: 5 obligatorische Leitfragen

| Leitfrage | Wo validieren | Zu prüfende Punkte |
|---|---|---|
| **1. Was wurde getan?** | `AuditLogs` / `TargetResources` | Wurde ein Client Secret oder ein X.509-Zertifikat hinzugefügt? Wann läuft es ab? |
| **2. Wer hat es getan?** | `InitiatedBy` & `SigninLogs` | Erfolgte die Aktion durch einen Benutzer oder eine CI/CD-Pipeline? |
| **3. War die Aktion autorisiert?** | Microsoft Entra ID Roles | Besitzt der Benutzer Administratorrechte für Anwendungen oder ist er Owner? |
| **4. Gibt es ein Ticket?** | ServiceNow, Jira, Freshservice | Liegt ein genehmigter Change-Request für Secret-Rotation vor? |
| **5. Wo im Portal untersuchen?** | Entra Admin Center | App registrations > API permissions und Service principal sign-ins prüfen. |

---

## 4. Untersuchung im Portal

1. Navigieren Sie zu:
   > **Identity** > **Applications** > **App registrations** > **All applications**.
2. Suchen Sie nach der App und prüfen Sie unter **Certificates & secrets** die aktiven Secrets.
3. Kontrollieren Sie unter **Monitoring & health** > **Sign-in logs** > **Service principal sign-ins**, ob bereits Logons mit dem neuen Secret stattfanden.

---

## 5. Reaktions- und Eindämmungsverfahren

1. **Secret sofort löschen:** Unter *App registrations* > *Certificates & secrets* entfernen.
2. **Konto des Akteurs isolieren:** `Revoke sessions` ausführen und Kennwort zurücksetzen.
3. **Forensische KQL-Abfrage ausführen:**

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

