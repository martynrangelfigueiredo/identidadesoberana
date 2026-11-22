---
title: "API-Berechtigungen für Service Principals in Microsoft Security: Leitfaden für Sentinel und KQL"
description: "Operatives Microsoft Security Playbook für SOC-Analysten zur Untersuchung von App-Role-Zuweisungen und Graph-API-Rechten für Service Principals mit Sentinel und KQL."
date: 2026-11-22
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, service-principal, kql, soc, dfir]
nivel: Avançado
draft: false
---

> **TL;DR:** Die Zuweisung von Anwendungsberechtigungen (*Application Permissions*, z. B. `Mail.Read` oder `RoleManagement.ReadWrite.Directory`) an einen *Service Principal* gewährt weitreichenden Zugriff auf den *Tenant* ohne Benutzerinteraktion oder MFA. Dieses Playbook beschreibt die Untersuchung in **Microsoft Security** mit Microsoft Sentinel, KQL (`AuditLogs` und `AADServicePrincipalSignInLogs`), ITSM-Abgleich und Eindämmung in Entra ID.

---

## 1. Was bedeutet dieser Vorfall?

Im **Microsoft Security**-Ökosystem überwacht Microsoft Sentinel die Tabelle `AuditLogs`, um zu erkennen, wenn einem *Service Principal* eine privilegierte API-Berechtigung (*App Role Assignment*) zugewiesen wird (`Add app role assignment to service principal`). Anders als delegierte Berechtigungen erlauben **Anwendungsberechtigungen** den autonomen Zugriff auf Unternehmensdaten in Microsoft Graph, Exchange oder Entra ID.

Wie im [Erkennungskatalog von Microsoft Sentinel auf Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) und in der [Microsoft-Graph-Berechtigungsreferenz](https://learn.microsoft.com/en-us/graph/permissions-reference) beschrieben, nutzen Angreifer nach Kompromittierung eines Admins diese Technik (`MITRE ATT&CK T1098.003`) für stille Persistenz und den *Bypass* menschlicher Sitzungskontrollen.

### Gutartige vs. bösartige Szenarien

| Szenario | Typische Indikatoren | Klassifizierung |
|---|---|---|
| **Geplante SaaS-/SIEM-Integration** | Bekannter Cloud-Admin, genehmigtes Change-Ticket, eng gefasste Rechte (z. B. `SecurityEvents.Read.All`). | False Positive (Gutartig) |
| **Autorisierte CI/CD-Pipeline** | Zuweisung durch bekannten Automatisierungs-*Service Principal* im Wartungsfenster. | False Positive (Gutartig) |
| **Stille Rechteausweitung nach Kompromittierung** | Kritische Berechtigung (`RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `Mail.ReadWrite`) für neu erstellte oder unbekannte App. | Kritisches True Positive (T1098.003) |
| **Backdoor in bestehender Anwendung** | Kompromittierter Admin ergänzt Lesezugriff auf Mails oder Dateien bei einer bereits etablierten App. | True Positive (T1098 / T1114) |

---

## 2. KQL-Tipp: App-Role-Zuweisungen in AuditLogs detailliert prüfen

Beim Öffnen des Incidents in Microsoft Sentinel projiziert die folgende Abfrage zusätzliche Spalten aus `AuditLogs`, indem `TargetResources` und `modifiedProperties` expandiert werden, um sofort den begünstigten *Service Principal*, die zugewiesene Rolle und den Initiator anzuzeigen.

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

## 3. Untersuchungsleitfaden: die 5 Pflichtfragen

Um den Vorfall sicher als True Positive (TP) oder False Positive (FP) einzustufen, beantworten Sie diese fünf Fragen:

### 1. Was wurde getan?
- Prüfen Sie `OperationName`, `TargetName` und `NewValue` in der KQL-Ausgabe.
- Bestimmen Sie genau, **welche Berechtigung (`AppRole`)** für welche API (`Microsoft Graph`, `Office 365 Exchange Online`, `Windows Azure Active Directory`) erteilt wurde.
- Rechte wie `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All` und `Mail.Read` erfordern sofortige Prüfung.

### 2. Wer hat es getan?
- Analysieren Sie `InitiatorUPN` (menschlicher Benutzer) oder `InitiatorApp` (*Service Principal*).
- Prüfen Sie bei Benutzern die zeitnahen `SigninLogs` auf `SourceIP`, Geolokalisierung und Phishing-resistente MFA (*Passkey* / FIDO2).
- Prüfen Sie zudem, ob kürzlich neue *Client Secrets* oder Zertifikate für die App angelegt wurden.

### 3. Durfte die Person das tun?
- Nur hochprivilegierte Rollen können *Admin Consent* für Anwendungsberechtigungen im *Tenant* erteilen:
  - **Global Administrator**
  - **Privileged Role Administrator**
  - **Cloud Application Administrator** oder **Application Administrator**
- Falls PIM (*Privileged Identity Management*) genutzt wird, prüfen Sie die vorherige Aktivierung.

### 4. Gibt es ein formelles Change-Ticket?
- Führen Sie einen verpflichtenden Abgleich im **ITSM**-System durch (**ServiceNow**, **Jira Service Management**, **Freshservice** oder **Zendesk**).
- Verifizieren Sie, ob ein durch Security/IAM genehmigter Change exakt diese Berechtigung nach Least-Privilege rechtfertigt.

### 5. War die Sitzung legitim?
- Prüfen Sie in Microsoft Entra ID Protection, ob die Sitzung von `InitiatorUPN` ein Risiko (`RiskLevelDuringSignIn`) oder ungewöhnliche *User-Agents* aufwies.
- Prüfen Sie, ob die Ziel-App von einem verifizierten Anbieter stammt (*Publisher* und Herkunfts-*Tenant-ID*).

---

## 4. Wo im Portal untersuchen (Microsoft Entra admin center)

Zur visuellen Überprüfung in `entra.microsoft.com`:

1. **App-Berechtigungen prüfen:**
   `Identity > Applications > Enterprise applications > All applications` (`TargetName` öffnen und **Security > Permissions** prüfen).
2. **Besitzer und Zugangsdaten kontrollieren:**
   `Identity > Applications > App registrations` (**Certificates & secrets** und **Owners** prüfen).
3. **Vollständige Audit-Logs:**
   `Identity > Monitoring & health > Audit logs` (nach **Correlation ID** filtern).

---

## 5. MITRE ATT&CK und Kontrollen

| Framework | Referenz | Beschreibung |
|---|---|---|
| **MITRE ATT&CK** | `T1098.003` | *Account Manipulation: Additional Cloud Roles* (Zuweisung privilegierter API-Rechte an Workload-Identitäten). |
| **MITRE ATT&CK** | `T1550.001` | *Use Alternate Authentication Material: Application Access Token* (Nutzung von App-Tokens für dauerhaften Zugriff). |
| **NIST CSF** | `PR.AA-05` | Laufende Überprüfung von Berechtigungen menschlicher und nicht-menschlicher Identitäten. |
| **CIS Controls v8** | `6.8` | Strenge Kontrolle von Dienstkonten und *Service Principals* nach Least Privilege. |

---

## 6. Reaktions- und Eindämmungsverfahren

Liegt **keine** formelle Genehmigung vor oder besteht Kompromittierungsverdacht, führen Sie umgehend dieses *Playbook* aus:

1. **Berechtigung sofort entziehen:** Unter `Enterprise applications > [App] > Security > Permissions` die unbefugte Berechtigung widerrufen (oder bei komplett bösartiger App unter **Properties > Enabled for users to sign-in? = No** deaktivieren).
2. **Sitzungen des Initiators widerrufen:** Unter `Identity > Users > All users` für `InitiatorUPN` auf **Revoke sessions** klicken, Passwort zurücksetzen und MFA-Methoden prüfen.
3. **Secrets rotieren oder entfernen:** Unter `App registrations > Certificates & secrets` verdächtige *Client Secrets* oder Zertifikate löschen.
4. **Post-Incident-Audit mit KQL:** Prüfen Sie mit folgender Abfrage in `AADServicePrincipalSignInLogs`, ob der *Service Principal* bereits Authentifizierungen von externen IPs durchgeführt hat:

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

## Referenzen

- [Microsoft Learn — Built-in detections in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Microsoft Learn — Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [MITRE ATT&CK — T1098.003: Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/)

