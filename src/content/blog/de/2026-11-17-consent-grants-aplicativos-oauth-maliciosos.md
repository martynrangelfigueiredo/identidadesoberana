---
title: "Missbräuchliche Consent Grants in Microsoft Security: Threat Hunting und Response-Playbook in Microsoft Sentinel"
description: "Vollständiges Playbook im Microsoft Security-Ökosystem zur Untersuchung von OAuth-Anwendungen mit übermäßigen Berechtigungen, Consent-Phishing und Entra ID-Eindämmung."
date: 2026-11-17
categoria: IAM
tags: [microsoft-security, sentinel, entra-id, oauth, consent-grant, soc, iam, dfir, kql]
nivel: Avançado
---

Die missbräuchliche Erteilung von Berechtigungen an OAuth-Anwendungen — häufig als **Consent-Phishing (*illicit consent grant*)** bezeichnet — ist einer der gefährlichsten und am schwersten zu erkennenden Angriffsvektoren in Cloud-Umgebungen. Anders als herkömmliche Angriffe, die auf Kennwortdiebstahl oder das Umgehen von MFA abzielen, täuscht diese Methode den Benutzer (oder einen Administrator) so, dass er einer bösartigen Drittanbieter-Anwendung Zugriff auf Unternehmensressourcen in seinem Namen gewährt.

Sobald die Zustimmung (*Consent*) erteilt wurde, erhält die Anwendung Zugriffstoken der Microsoft Graph API mit weitreichenden Rechten (wie `Mail.ReadWrite`, `Files.ReadWrite.All` oder `User.ReadWrite.All`). Ab diesem Moment **benötigt der Angreifer weder das Kennwort noch den zweiten Faktor des Benutzers** und kann unbemerkt Daten abgreifen.

Innerhalb des **Microsoft Security**-Ökosystems liefert das Zusammenspiel von **Microsoft Entra ID** und **Microsoft Sentinel** detaillierte Telemetrie, um verdächtige Genehmigungen aufzudecken, API-Aufrufe zu auditieren und kompromittierte Apps sofort zu isolieren.

> 📘 **Offizielle Referenz auf Microsoft Learn:**
> - [Schutz vor unberechtigten Einwilligungserteilungen in Microsoft Entra ID (Learn)](https://learn.microsoft.com/entra/identity/enterprise-apps/manage-consent-requests)
> - [Untersuchung verdächtiger Anwendungen in Microsoft Sentinel (Learn)](https://learn.microsoft.com/azure/sentinel/investigate-incidents)
> - [Katalog integrierter Analyse-Erkennungsregeln in Microsoft Sentinel (Learn)](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in)

---

## 1. Wie funktioniert der Angriff des Consent-Phishing?

Das Angriffsmuster wird im **MITRE ATT&CK-Framework als T1528 (Steal Application Access Token)** und **T1204.001 (User Execution: Malicious Link)** geführt:

1. **Phishing-Köder:** Der Mitarbeiter erhält eine scheinbar legitime E-Mail (z. B. „Aktualisierung der internen Richtlinien“, „Ausstehende elektronische Signatur“ oder „Freigegebener Finanzbericht“).
2. **Offizieller Microsoft-Anmeldebildschirm:** Beim Klick auf den Link öffnet sich die echte Anmeldeseite von Microsoft (`login.microsoftonline.com`). Da die Domain absolut legitim ist, schlagen Webfilter und Browserwarnungen nicht an.
3. **Anforderung weitreichender Scopes:** Die App fordert delegierte Berechtigungen an, um E-Mails zu lesen (`Mail.Read`), Dateien in OneDrive/SharePoint zu verändern (`Files.ReadWrite.All`) oder Teams-Nachrichten abzurufen (`Chat.Read`).
4. **Stille Persistenz:** Klickt der Benutzer auf „Akzeptieren“, erhält der Angreifer ein langlebiges Refresh-Token, mit dem er dauerhaft ohne erneute Anmeldealarme spionieren kann.

---

## 2. KQL-Tipp: Zuordnung von OAuth-Anwendungsberechtigungen im Entra ID

Die folgende Abfrage projiziert nützliche Spalten, um Zustimmungsereignisse in den `AuditLogs` zu kontextualisieren und den Anwendungsnamen, die erteilten Berechtigungen sowie das genehmigende Konto zu identifizieren:

```kql
// ====================================================================================
// Consulta: Mapeando consentimentos de aplicativos OAuth no Entra ID
// Objetivo: Identificar aplicacao alvo, permissoes concedidas, usuario originador e data
// ====================================================================================
let JanelaTempo = 30d;
AuditLogs
| where TimeGenerated >= ago(JanelaTempo)
| where ActivityDisplayName in (
    "Consent to application",
    "Add delegated permission grant",
    "Add app role assignment to service principal"
)
| mv-expand Target = TargetResources
| mv-expand ModProp = Target.modifiedProperties
| where ModProp.displayName in ("ConsentAction.Permissions", "DelegatedPermissionGrant.Scope", "AppRole.Value")
| extend AtorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend NomeAplicativo = tostring(Target.displayName)
| extend IdAplicativo = tostring(Target.id)
| extend Permissoes = tostring(ModProp.newValue)
| project
    TimeGenerated,
    ActivityDisplayName,
    NomeAplicativo,
    IdAplicativo,
    Permissoes,
    AtorUPN,
    Result,
    CorrelationId
| order by TimeGenerated desc
```

### Wichtige Prüfpunkte:
- **`Permissoes`:** Scopes wie `Mail.ReadWrite`, `Mail.Send`, `Files.ReadWrite.All` und `Directory.AccessAsUser.All` sind extrem riskant, wenn sie Anwendungen von nicht verifizierten Herausgebern (*Unverified Publisher*) erteilt werden.
- **`AtorUPN`:** Handelt es sich um einen regulären Benutzer (*User Consent*) oder einen Administrator (*Admin Consent* auf Tenant-Ebene)?
- **`IdAplicativo`:** Eindeutige Kennung des Service Principals im Tenant, erforderlich für Sperr- und Löschbefehle.

---

## 3. Untersuchungsleitfaden: Die 5 obligatorischen Fragen

Beantworten Sie bei der Vorfallanalyse in Microsoft Sentinel folgende Fragen:

### 1. Was wurde getan?
Welche Anwendung wurde registriert? Handelt es sich um eine externe Multitenant-App oder eine interne Eigenentwicklung? Wurden delegierte Berechtigungen oder Anwendungsrechte auf Tenant-Ebene vergeben?

### 2. Wer hat die Zustimmung erteilt?
Prüfen Sie das Konto in `AtorUPN`. Hat der Mitarbeiter eine geschäftliche Notwendigkeit für diese Software? Handelt es sich um Führungskräfte, Personal- oder Rechtsabteilungen mit vertraulichen E-Mail-Inhalten?

### 3. Ist der Herausgeber von Microsoft verifiziert?
Besitzt die Anwendung den blauen Haken für *Verified Publisher*? Unverifizierte Herausgeber oder neu registrierte Domains stellen ein ernstes Warnsignal dar.

### 4. Liegt ein formelles Ticket im ITSM vor?
Gibt es im ITSM (ServiceNow, Jira Service Management) ein genehmigtes Integrations-Ticket der IT-Sicherheit? Fehlt ein solches Ticket, ist von einem echten Angriff auszugehen.

### 5. Wurden bereits API-Aufrufe verzeichnet?
Prüfen Sie in `AADServicePrincipalSignInLogs`, ob der Service Principal bereits Zugriffstoken angefordert und API-Abfragen im Tenant durchgeführt hat.

---

## 4. Untersuchung im Microsoft Entra Admin Center

Für SOC-Analysten, die die Überprüfung direkt im Identitätsportal durchführen:

1. Öffnen Sie das **Microsoft Entra Admin Center** (`entra.microsoft.com`).
2. Navigieren Sie zu **Identity > Applications > Enterprise applications**.
3. Suchen Sie die verdächtige Anwendung in der Liste.
4. Klicken Sie unter **Security** auf **Permissions**:
   - Unter **Admin consent** prüfen, ob unternehmensweite Vollmachten erteilt wurden.
   - Unter **User consent** einsehen, welche Benutzer der App Berechtigungen übertragen haben.
5. Öffnen Sie die **Audit logs** der Anwendung, um den Verlauf von Berechtigungsänderungen und Secrets zu prüfen.

---

## 5. Sofortige Eindämmungs- und Reaktionsmaßnahmen

Wurde die Anwendung als bösartig oder unautorisiert eingestuft, führen Sie unverzüglich folgende Schritte durch:

1. **Benutzeranmeldung für die App deaktivieren:**
   - In den **Properties** der Enterprise-App die Option **Enabled for users to sign-in?** auf **No** setzen.
2. **Erteilte Berechtigungen via PowerShell widerrufen:**
   ```powershell
   Connect-MgGraph -Scopes "Application.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All"

   $AppObjId = "SERVICE-PRINCIPAL-OBJECT-ID"
   Get-MgServicePrincipalOAuth2PermissionGrant -ServicePrincipalId $AppObjId | ForEach-Object {
       Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $_.Id
   }
   ```
3. **Anwendung aus dem Tenant löschen:**
   - Unter **Enterprise applications > Properties** auf **Delete** klicken, um den Service Principal vollständig zu entfernen.
4. **Benutzersitzungen widerrufen:**
   - Für alle betroffenen Benutzer `Revoke-MgUserSignOut` ausführen und das Kennwort zurücksetzen.
5. **Einwilligungseinstellungen des Tenants härten:**
   - Unter **Enterprise applications > Consent and permissions > User consent settings** die Option **Do not allow user consent** wählen und den **Admin consent workflow** aktivieren.

---

## 6. KQL-Abfrage nach dem Vorfall: API-Aufrufe des Service Principals prüfen

Überprüfen Sie, ob der Service Principal in den letzten 14 Tagen erfolgreich mit Tenant-Ressourcen kommuniziert hat:

```kql
// ====================================================================================
// Verificacao Pos-Incidente: Rastreando tokens e logons do Service Principal suspeito
// Objetivo: Verificar se a aplicacao com consentimento abusivo consumiu APIs do tenant
// ====================================================================================
let JanelaAnalise = 14d;
let AppIdSuspeito = "00000000-0000-0000-0000-000000000000";
AADServicePrincipalSignInLogs
| where TimeGenerated >= ago(JanelaAnalise)
| where tolower(AppId) == tolower(AppIdSuspeito)
| extend StatusAutenticacao = iff(ResultType == 0, "Sucesso", "Falha")
| project
    TimeGenerated,
    ServicePrincipalName,
    AppId,
    IPAddress,
    ResourceDisplayName,
    StatusAutenticacao,
    ResultType,
    ResultDescription,
    CorrelationId
| order by TimeGenerated desc
```

### Entscheidungsmatrix für das SOC (TP vs. FP):

| Analyse-Szenario | Klassifizierung | Operative SOC-Maßnahme |
|---|---|---|
| Unbekannte App, nicht verifizierter Herausgeber, E-Mail-Leserechte (`Mail.ReadWrite`) | **True Positive (Kritisch)** | App sofort sperren und löschen, Benutzersitzungen widerrufen, Mailbox-Logs analysieren und Datenabfluss ermitteln. |
| Autorisierte Unternehmens-App (z. B. offizielle Jira- oder Power BI-Integration) | **False Positive (FP)** | Ticketnummer im ITSM gegenprüfen, verifizierten Herausgeber bestätigen und Ausnahme in Sentinel dokumentieren. |
| Tenant-weite Zustimmung durch Administrator für verdächtige Drittanbieter-App | **Schwerer Vorfall (P1)** | Sofortige Eskalation an DFIR, App isolieren, alle Administrator-Aktivitäten auditieren und Tenant-Sicherheit überprüfen. |

