---
title: "Externe B2B-Benutzereinladungen in Microsoft Security: Untersuchung mit Entra ID und Sentinel"
description: "Operatives Microsoft Security Playbook für SOC-Analysten zur Untersuchung verdächtiger B2B-Gasteinladungen in Entra ID mit Microsoft Sentinel und KQL."
date: 2026-11-26
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, b2b, iam, kql, soc, dfir]
nivel: Intermediário
draft: false
---

> **TL;DR:** B2B-Zusammenarbeit in Microsoft Entra ID erleichtert die Arbeit mit Partnern, doch unautorisierte Einladungen an private Konten (`gmail.com`, `outlook.com`) oder anschließende Rollenzuweisungen an `#EXT#`-Konten schaffen unauffällige Persistenzpfade über Tenant-Grenzen hinweg. Dieses Playbook zeigt die Untersuchung in **Microsoft Security** mit Microsoft Sentinel, KQL (`AuditLogs` und `SigninLogs`), ITSM-Abgleich und Eindämmung in Entra ID.

---

## 1. Was bedeutet dieser Vorfall?

Im **Microsoft Security**-Ökosystem überwacht Microsoft Sentinel die Tabelle `AuditLogs` auf Ereignisse rund um Erstellung, Einlösung und Berechtigungsänderung externer Gastkonten (*B2B Guest*), darunter `Invite external user`, `Redeem external user invite`, `Add user` mit `#EXT#`-Suffix sowie nachfolgende Gruppen- oder Rollenzuweisungen.

Wie im [Erkennungskatalog von Microsoft Sentinel auf Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) und der [Dokumentation zur B2B-Zusammenarbeit in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/external-id/b2b-quickstart-add-guest-users-portal) beschrieben, können Angreifer über ein kompromittiertes internes Konto mit Einladungsrechten (`Guest Inviter`) ein eigenes externes Konto einladen (`MITRE ATT&CK T1136.003` / `T1098`), um selbst nach einem Passwort-Reset dauerhaft Zugriff zu behalten.

### Gutartige vs. bösartige Szenarien

| Szenario | Typische Indikatoren | Klassifizierung |
|---|---|---|
| **Projektarbeit mit verifiziertem Partner** | Bekannte Unternehmensdomain (`partner.de`), Einladung durch Projektleitung, Zugriff auf einen einzelnen Teams-Kanal oder SharePoint-Ordner. | False Positive (Gutartig) |
| **Temporäre Beratung mit genehmigtem Ticket** | Einladung durch IAM/Helpdesk mit verknüpftem Change-Ticket und aktiver Zugriffsüberprüfung. | False Positive (Gutartig) |
| **Einladung an kostenlosen E-Mail-Anbieter (`gmail.com` / `proton.me`)** | Internes Konto ohne Partnerfunktion lädt private E-Mail außerhalb der Arbeitszeit oder kurz nach verdächtiger Anmeldung ein. | True Positive (Sofort prüfen) |
| **`#EXT#`-Gast in privilegierter Rolle oder Gruppe** | Neu eingeladener externer Benutzer erhält Entra-ID-Rolle, Azure RBAC (`Contributor`/`Owner`) oder Mitgliedschaft in kritischer App-Gruppe. | Kritisches True Positive (`T1098`) |

---

## 2. KQL-Tipp: Externe Einladungen und Rollenzuweisungen in AuditLogs prüfen

Bei der Übernahme des Incidents in Microsoft Sentinel projiziert die folgende Abfrage zusätzliche Spalten aus `AuditLogs`, um Einladenden, eingeladene externe Adresse, Ergebnisstatus und `CorrelationId` schnell sichtbar zu machen.

```kql
let Lookback = 7d;
AuditLogs
| where TimeGenerated >= ago(Lookback)
| where OperationName in ("Invite external user", "Redeem external user invite", "Bulk invite users")
| mv-expand Target = TargetResources
| mv-expand ModProp = Target.modifiedProperties
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend SourceIP = tostring(InitiatedBy.user.ipAddress)
| extend GuestUPN = tostring(Target.userPrincipalName)
| extend PropName = tostring(ModProp.displayName)
| extend NewValue = tostring(ModProp.newValue)
| project
    TimeGenerated,
    OperationName,
    Result,
    ResultReason,
    InitiatorUPN,
    SourceIP,
    GuestUPN,
    PropName,
    NewValue,
    CorrelationId
| order by TimeGenerated desc
```

---

## 3. Untersuchungsleitfaden: die 5 Pflichtfragen

### 1. Was wurde getan?
Prüfen Sie in `AuditLogs` den gesamten Lebenszyklus des Gastkontos:
- Wurde die Einladung nur versendet (`Invite external user`) oder bereits eingelöst (`Redeem external user invite`)?
- Gab es kurz nach der Einladung Ereignisse wie `Add member to group` oder `Add member to role` für denselben `#EXT#`-Benutzer?
- Notieren Sie `CorrelationId` und `GuestUPN` zur weiteren Korrelation.

### 2. Wer hat es getan?
Analysieren Sie `InitiatorUPN` und `SourceIP` in `AuditLogs` sowie die jüngsten Anmeldungen des Initiators in `SigninLogs`:
- Arbeitet der einladende Mitarbeiter im Einkauf, der Rechtsabteilung, der IT oder im Partnermanagement?
- Stammte die Sitzung von einem konformen Gerät (`IsCompliant == true`) und einer bekannten IP oder folgte sie auf eine Standort-/MFA-Anomalie?

### 3. Hätte die Person das tun dürfen?
Bewerten Sie die B2B-Governance-Einstellungen des Tenants:
- Darf in den externen Zusammenarbeitseinstellungen von Entra ID jeder normale Benutzer (`Member`) Gäste einladen, oder nur die Rolle `Guest Inviter` / `User Administrator`?
- Existiert eine Allow- oder Deny-List für private E-Mail-Domains?

### 4. Gibt es ein formelles Change-Ticket?
Gleiche `InitiatorUPN` und die eingeladene Domain mit dem **ITSM**-System (ServiceNow, Jira Service Management, Freshservice oder Zendesk) ab:
- Liegt ein genehmigtes Onboarding-Ticket für einen Dienstleister mit gültigem Vertrag vor?
- Gibt es bei Azure-RBAC- oder privilegierten Gruppen eine dokumentierte Genehmigung?

### 5. War die Sitzung legitim?
Prüfen Sie sowohl die Sitzung des Einladenden als auch die erste Anmeldung des Gastes:
- Falls die Einladung eingelöst wurde: Grift Conditional Access für externe Benutzer (z. B. MFA-Pflicht im Ressourcen-Tenant)?
- Hat der Gast nur die freigegebene Ressource geöffnet oder Verzeichnisse und Anwendungen enumeriert?

---

## 4. Wo im Portal untersuchen?

Zur direkten Prüfung von B2B-Richtlinien und Gastverlauf im Microsoft Entra admin center (`entra.microsoft.com`):

1. **Gastkonto inspizieren:**
   - Pfad: `Identity > Users > All users`.
   - Nach `User type == Guest` filtern und das Profil öffnen, um `Creation type` (`Invitation`), `External user state` (`Accepted` oder `PendingAcceptance`), Gruppen und App-Zuweisungen zu prüfen.
2. **Einstellungen für externe Zusammenarbeit prüfen:**
   - Pfad: `Identity > External Identities > External collaboration settings`.
   - Prüfen Sie **Guest user access**, **Guest invite settings** und **Collaboration restrictions** (Domain-Allow-/Deny-Listen).
3. **Gastanmeldungen auditieren:**
   - Pfad: `Identity > Monitoring & health > Sign-in logs` und nach `#EXT#` im Feld `User` filtern.

---

## 5. Reaktion, Eindämmung und Post-Incident-Audit

Bei bestätigter unbefugter Einladung oder Privilegienerweiterung eines externen Kontos:

1. **Gastkonto sperren und entfernen:**
   - In Entra ID (`Users > [Benutzer #EXT#]`) sofort **Revoke sessions** ausführen, Anmeldung deaktivieren (`Account enabled = No`), Gruppen/Rollen entziehen und das Konto löschen.
2. **Einladendes internes Konto eindämmen:**
   - Bei Verdacht auf Kompromittierung von `InitiatorUPN` sofort **Revoke sessions** ausführen, Passwort zurücksetzen und registrierte MFA-Methoden prüfen.
3. **Alle jüngsten `#EXT#`-Anmeldungen prüfen:**
   - Führen Sie die folgende Abfrage auf `SigninLogs` aus, um zu sehen, auf welche Apps externe Konten in den letzten 7 Tagen zugegriffen haben.

```kql
let Lookback = 7d;
SigninLogs
| where TimeGenerated >= ago(Lookback)
| where UserType == "Guest" or UserPrincipalName contains "#EXT#"
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend City = tostring(LocationDetails.city)
| project
    TimeGenerated,
    UserPrincipalName,
    AppDisplayName,
    ResourceDisplayName,
    ResultType,
    ResultDescription,
    ConditionalAccessStatus,
    AuthenticationRequirement,
    IPAddress,
    Country,
    City,
    CorrelationId
| order by TimeGenerated desc
```

---

## 6. Kontroll-Mapping und Compliance

| Framework / Standard | Zugehörige Kontrolle | Praktische Umsetzung |
|---|---|---|
| **MITRE ATT&CK** | `T1136.003` (Cloud Account), `T1098` (Account Manipulation) | Erkennung unbefugter Erstellung und Erweiterung externer Konten. |
| **NIST CSF 2.0** | `PR.AA-01` (Identitätsverwaltung), `PR.AA-05` (Least Privilege) | Einschränkung von B2B-Einladungsrechten und regelmäßige Access Reviews. |
| **CIS Controls v8** | `5.3` / `6.8` (Inaktive Konten & RBAC) | Entfernen abgelaufener Gastkonten und Sperren privater Domains. |
| **ISO/IEC 27001:2022** | `A.5.18` (Zugriffsrechte), `A.5.19` (Lieferantensicherheit) | Formale Governance externer Identitäten im Tenant. |
| **DSGVO / LGPD** | Art. 32 DSGVO / Art. 46 LGPD | Schutz personenbezogener Daten vor unbefugtem Zugriff durch Dritte. |

