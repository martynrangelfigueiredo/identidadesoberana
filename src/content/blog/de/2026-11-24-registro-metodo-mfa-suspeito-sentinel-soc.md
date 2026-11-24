---
title: "Registrierung neuer MFA-Methoden in Microsoft Security: Leitfaden für Sentinel und KQL"
description: "Operatives Microsoft Security Playbook für SOC-Analysten zur Untersuchung verdächtiger MFA-Registrierungen in Entra ID mit Microsoft Sentinel und KQL."
date: 2026-11-24
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, mfa, kql, soc, dfir]
nivel: Intermediário
draft: false
---

> **TL;DR:** Sobald ein Angreifer gültige Zugangsdaten oder ein erstes Token erlangt, registriert er häufig eine eigene MFA-Methode (Authenticator App, Telefonnummer oder *Passkey*), um dauerhaften Zugriff zu sichern. Dieses Playbook zeigt die Untersuchung in **Microsoft Security** mit Microsoft Sentinel, KQL (`AuditLogs` und `SigninLogs`), ITSM-Abgleich und Eindämmung in Entra ID.

---

## 1. Was bedeutet dieser Vorfall?

Im **Microsoft Security**-Ökosystem überwacht Microsoft Sentinel `AuditLogs` auf Ereignisse der Kategorie `UserManagement` zur Registrierung oder Änderung von Sicherheitsinformationen (*Security Info*), wie `User registered security info`, `Admin registered security info` oder `User deleted security info`.

Wie im [Erkennungskatalog von Microsoft Sentinel auf Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) und der [Dokumentation zur Aktivität von Authentifizierungsmethoden](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity) beschrieben, ermöglicht diese Technik (`MITRE ATT&CK T1098.005` / `T1556.006`) dem Angreifer, selbst nach einem Passwort-Reset angemeldet zu bleiben, solange seine MFA-Methode aktiv bleibt.

### Gutartige vs. bösartige Szenarien

| Szenario | Typische Indikatoren | Klassifizierung |
|---|---|---|
| **Mitarbeiter-Onboarding oder Gerätewechsel** | Registrierung von bekannter Unternehmens-IP/VPN, konformes Gerät (`IsCompliant == true`), während der Arbeitszeit. | False Positive (Gutartig) |
| **Helpdesk-gestützter Reset (TAP)** | Autorisierter Admin hat einen *Temporary Access Pass* mit offenem Ticket ausgestellt; Nutzer registriert neuen *Passkey* / FIDO2. | False Positive (Gutartig) |
| **Persistenz nach Phishing / AitM** | Neue Methode kurz nach Anmeldung von untypischer IP (VPS, kommerzielles VPN oder fremdes Land) ohne verwaltetes Gerät. | Kritisches True Positive (T1098.005) |
| **Löschen legitimer Methoden** | Entfernen des bisherigen Authenticators kurz nach Hinzufügen eines unbekannten Geräts. | Kritisches True Positive |

---

## 2. KQL-Tipp: Änderungen an Sicherheitsmethoden in AuditLogs detailliert prüfen

Beim Öffnen des Incidents in Microsoft Sentinel projiziert die folgende Abfrage zusätzliche Spalten aus `AuditLogs`, um betroffenen Benutzer, Initiator, Begründung (`ResultReason`) und geänderte Eigenschaften direkt sichtbar zu machen.

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

## 3. Untersuchungsleitfaden: die 5 Pflichtfragen

Um den Vorfall sicher als True Positive (TP) oder False Positive (FP) einzustufen, beantworten Sie diese fünf Fragen:

### 1. Was wurde getan?
- Prüfen Sie `OperationName`, `ResultReason` und `NewValue` in der KQL-Ausgabe.
- Bestimmen Sie **welche Methode** hinzugefügt oder entfernt wurde (z. B. *Microsoft Authenticator App*, *PhoneAppNotification*, *PhoneNumber*, *FIDO2*).
- Besondere Vorsicht bei einer Abfolge von `User registered security info` und `User deleted security info`.

### 2. Wer hat es getan?
- Vergleichen Sie `InitiatorUPN` mit `TargetUser`:
  - Sind beide identisch, erfolgte die Registrierung durch den Benutzer selbst (oder eine aktive Sitzung).
  - Weichen sie ab, handelte ein Administrator oder ein *Service Principal*.
- Korrelieren Sie `SourceIP` und Zeitstempel mit `SigninLogs` (Land, ASN, *User-Agent*, vorherige Nutzung von *Temporary Access Pass* oder `deviceCode`).

### 3. Durfte die Person das tun?
- Prüfen Sie, ob *Combined Registration* im *Tenant* durch *Conditional Access* geschützt ist:
  - Erfordert *Register security information* ein vertrauenswürdiges Netz, ein konformes Gerät oder einen *Temporary Access Pass*?
  - Kann sich jede externe IP mit Passwort/Erst-Token registrieren, besteht ein hohes *Bypass*-Risiko.

### 4. Gibt es ein formelles Change-Ticket?
- Bei Smartphone-Tausch oder Helpdesk-Eingriff prüfen Sie zwingend das **ITSM**-System (**ServiceNow**, **Jira Service Management**, **Freshservice** oder **Zendesk**).
- Bestätigen Sie zudem direkt telefonisch oder über einen verifizierten Zweitkanal beim Mitarbeiter, ob er tatsächlich ein neues Gerät registriert hat.

### 5. War die Sitzung legitim?
- Prüfen Sie in Microsoft Entra ID Protection auf Warnungen zur Sitzung von `SourceIP` (`Risky sign-ins`, *Impossible Travel*).
- Kontrollieren Sie `DeviceDetail.isCompliant` und `DeviceDetail.trustType` in `SigninLogs`.

---

## 4. Wo im Portal untersuchen (Microsoft Entra admin center)

Zur Überprüfung in `entra.microsoft.com`:

1. **Authentifizierungsmethoden des Benutzers:**
   `Identity > Users > All users > [Benutzer] > Authentication methods` (Geräte, Registrierungsdatum und Rufnummern prüfen).
2. **Aktivitätsbericht der Registrierungen:**
   `Protection > Authentication methods > Activity` (Reiter *Registration* und *Usage*).
3. **Audit-Logs im Portal:**
   `Identity > Monitoring & health > Audit logs` (nach **Target** = betroffener Benutzer oder **Correlation ID** filtern).

---

## 5. MITRE ATT&CK und Kontrollen

| Framework | Referenz | Beschreibung |
|---|---|---|
| **MITRE ATT&CK** | `T1098.005` | *Account Manipulation: Device Registration* (unbefugte MFA-/Geräteregistrierung zur Persistenz). |
| **MITRE ATT&CK** | `T1556.006` | *Modify Authentication Process: Multi-Factor Authentication* (Manipulation von Authentifizierungsfaktoren). |
| **NIST SP 800-63B** | `AAL2` / `AAL3` | Sichere Bindung bei der Registrierung von Authentifikatoren und Einsatz Phishing-resistenter *Passkeys* / FIDO2. |
| **CIS Controls v8** | `6.3` / `6.5` | Absicherung des MFA-Registrierungsflows durch vertrauenswürdige Netze/Geräte. |

---

## 6. Reaktions- und Eindämmungsverfahren

Erkennt der Mitarbeiter die Registrierung nicht an oder ist die Sitzung verdächtig, führen Sie sofort dieses *Playbook* aus:

1. **Unbefugte MFA-Methode entfernen:** Unter `Identity > Users > All users > [Benutzer] > Authentication methods` den unbekannten Authenticator bzw. die Rufnummer sofort löschen.
2. **Sitzungen widerrufen und Passwort zurücksetzen:** Auf **Revoke sessions** klicken und Passwort ändern; wurde die legitime Methode gelöscht, nach Identitätsprüfung einen einmaligen *Temporary Access Pass* ausstellen.
3. **Conditional Access nachschärfen:** Richtlinie für die Benutzeraktion **Register security information** mit Anforderung an konforme Geräte oder Firmenstandort aktivieren.
4. **Post-Incident-Audit mit KQL:** Prüfen Sie alle Logins des betroffenen Kontos in den letzten 48 Stunden (sowie mögliche Änderungen an *Secrets* oder Posteingangsregeln):

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

## Referenzen

- [Microsoft Learn — Built-in detections in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Microsoft Learn — Authentication methods activity in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity)
- [MITRE ATT&CK — T1098.005: Device Registration](https://attack.mitre.org/techniques/T1098/005/)
