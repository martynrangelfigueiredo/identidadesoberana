---
title: "Device-Code-Authentifizierung in Microsoft Security: Leitfaden für Sentinel und KQL"
description: "Operatives Microsoft Security Playbook für SOC-Analysten zur Untersuchung von Device Code Phishing und anomalen deviceCode-Flows in Entra ID mit Sentinel und KQL."
date: 2026-11-23
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, device-code, kql, soc, dfir]
nivel: Avançado
draft: false
---

> **TL;DR:** Der OAuth-2.0-*Device-Code*-Flow wurde für Geräte ohne Browser (TVs, Drucker, CLI) entwickelt, wird aber bei *Device Code Phishing* missbraucht, um gültige Tokens inklusive erfüllter MFA abzugreifen. Dieses Playbook zeigt die Triage im **Microsoft Security**-Ökosystem mit Microsoft Sentinel, KQL (`SigninLogs`), ITSM-Abgleich und Eindämmung in Entra ID.

---

## 1. Was bedeutet dieser Vorfall?

Im **Microsoft Security**-Ökosystem überwacht Microsoft Sentinel `SigninLogs` auf Anmeldungen mit `AuthenticationProtocol == "deviceCode"` über unerwartete Apps, untypische externe IPs oder Benutzer ohne administrative CLI-Historie.

Bei diesem Angriff (`MITRE ATT&CK T1528`) initiiert der Angreifer eine Code-Anfrage bei Entra ID (oft als Microsoft Graph PowerShell oder Azure CLI getarnt), sendet den 8–9-stelligen Code per E-Mail oder Chat an das Opfer und verleitet es zum Aufruf von `microsoft.com/devicelogin`. Nach Abschluss von Login und MFA erhält der Server des Angreifers direkt das *Access Token* und *Refresh Token*.

Wie im [Erkennungskatalog von Microsoft Sentinel auf Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) und der [Dokumentation zum Device Authorization Flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code) beschrieben, ermöglicht dies einen faktischen *Bypass* der Sitzungskontrolle ohne entsprechende *Conditional-Access*-Sperre.

### Gutartige vs. bösartige Szenarien

| Szenario | Typische Indikatoren | Klassifizierung |
|---|---|---|
| **Administrator nutzt Azure CLI / PowerShell** | Bekannter IT-/DevOps-Benutzer, Unternehmens-IP oder VPN, passender `AppDisplayName`. | False Positive (Gutartig) |
| **Legitimes IoT- / Konferenzraum-Gerät** | Ressourcenkonto oder Teams-Rooms-System im dedizierten internen Netz. | False Positive (Gutartig) |
| **Device Code Phishing** | Nicht-technischer Benutzer (Finanzen, HR, Management) authentifiziert `Microsoft Azure CLI` oder `Microsoft Graph PowerShell` mit Quell-IP bei VPS/VPN. | Kritisches True Positive (T1528) |
| **Token-Abgriff über mehrere Konten** | Dieselbe externe `IPAddress` erhält in einer Kampagne mehrere erfolgreiche `deviceCode`-Sitzungen. | Kritisches True Positive |

---

## 2. KQL-Tipp: Device-Code-Flows in SigninLogs identifizieren

Beim Öffnen des Incidents in Microsoft Sentinel projiziert die folgende Abfrage einige zusätzliche Spalten aus `SigninLogs`, um App, Authentifizierungsprotokoll, *User-Agent* und Gerätevertrauensstatus direkt sichtbar zu machen.

```kql
let Lookback = 7d;
SigninLogs
| where TimeGenerated >= ago(Lookback)
| where AuthenticationProtocol == "deviceCode" or ClientAppUsed == "Mobile Apps and Desktop clients"
| where AuthenticationProtocol == "deviceCode"
| extend DeviceTrust = tostring(DeviceDetail.trustType)
| extend IsCompliant = tostring(DeviceDetail.isCompliant)
| project
    TimeGenerated,
    UserPrincipalName,
    ResultType,
    AppDisplayName,
    ResourceDisplayName,
    IPAddress,
    Location,
    UserAgent,
    DeviceTrust,
    IsCompliant,
    RiskLevelDuringSignIn,
    CorrelationId
| order by TimeGenerated desc
```

---

## 3. Untersuchungsleitfaden: die 5 Pflichtfragen

Um den Vorfall sicher als True Positive (TP) oder False Positive (FP) einzustufen, beantworten Sie diese fünf Fragen:

### 1. Was wurde getan?
- Prüfen Sie `ResultType` (`0` bedeutet erfolgreiche Code-Eingabe und Anmeldung; `50140` oder `70016` weisen auf abgebrochene oder abgelaufene Versuche hin).
- Prüfen Sie `AppDisplayName` und `ResourceDisplayName` (Angriffe zielen häufig auf `Microsoft Graph` über `Microsoft Azure CLI` oder `Microsoft Office`).

### 2. Wer hat es getan?
- Bewerten Sie das Profil von `UserPrincipalName`: Ein Mitarbeiter aus Vertrieb oder Buchhaltung benötigt im Alltag keine `Azure CLI` via `deviceCode`.
- Analysieren Sie `IPAddress` (im `deviceCode`-Flow stammt die protokollierte IP vom Token-Empfänger/Angreifer und weicht oft stark von der üblichen IP des Opfers ab!).
- Prüfen Sie den *User-Agent* (Python/Go/cURL unter Linux verstärkt den Verdacht).

### 3. Durfte die Person das tun?
- Prüfen Sie, ob der *Tenant* eine *Conditional-Access*-Richtlinie nutzt, die *Authentication flows > Device code flow* für reguläre Benutzer blockiert.
- Prüfen Sie, ob ein konformes Gerät (`IsCompliant == "true"`) vorausgesetzt wurde.

### 4. Gibt es ein formelles Change-Ticket?
- Bei Support- oder Automatisierungsvorgängen prüfen Sie zwingend das **ITSM**-System (**ServiceNow**, **Jira Service Management**, **Freshservice** oder **Zendesk**).
- Verifizieren Sie zudem direkt beim Benutzer über einen sicheren Zweitkanal, ob er einen Code auf `microsoft.com/devicelogin` eingegeben hat.

### 5. War die Sitzung legitim?
- Prüfen Sie in Microsoft Entra ID Protection auf parallele Warnungen (`Risky sign-ins`, *Impossible Travel* zwischen regulärer Benutzer-IP und der `deviceCode`-`IPAddress`).
- Bestätigt der Benutzer eine Code-Anfrage aus einer verdächtigen Nachricht, stufen Sie den Fall sofort als **True Positive** ein.

---

## 4. Wo im Portal untersuchen (Microsoft Entra admin center)

Zur Überprüfung in `entra.microsoft.com`:

1. **Device-Code-Anmeldungen prüfen:**
   `Identity > Monitoring & health > Sign-in logs` (Filter **Authentication protocol: Device code** oder nach **Correlation ID**).
2. **Richtlinien für Authentifizierungsflows:**
   `Protection > Conditional Access > Policies` (prüfen, ob *Authentication flows: Device code flow* blockiert ist).
3. **Riskante Benutzer:**
   `Protection > Identity Protection > Risky users`.

---

## 5. MITRE ATT&CK und Kontrollen

| Framework | Referenz | Beschreibung |
|---|---|---|
| **MITRE ATT&CK** | `T1528` | *Steal Application Access Token* (Token-Diebstahl über *Device Code Phishing*). |
| **MITRE ATT&CK** | `T1566.002` | *Phishing: Spearphishing Link* (Versand von Links/Codes zu `devicelogin`). |
| **NIST CSF** | `PR.AA-03` / `PR.AA-05` | Einschränkung spezieller Authentifizierungsflows durch *Conditional Access*. |
| **CIS Controls v8** | `6.5` / `6.3` | Verwaltete Geräte und Phishing-resistente MFA für privilegierte Zugriffe. |

---

## 6. Reaktions- und Eindämmungsverfahren

Bestätigt sich *Device Code Phishing*, führen Sie sofort dieses *Playbook* aus:

1. **Sitzungen und Tokens sofort widerrufen:** Unter `Identity > Users > All users` den betroffenen Benutzer öffnen und auf **Revoke sessions** klicken (macht das *Refresh Token* des Angreifers ungültig).
2. **Device Code Flow per Conditional Access sperren:** Unter `Protection > Conditional Access > Policies` `Authentication flows > Device code flow` für alle Benutzer blockieren (mit eng dokumentierter Ausnahme für berechtigte IT-Gruppen).
3. **Post-Incident-Audit mit KQL:** Prüfen Sie mit folgender Abfrage, ob nach dem `deviceCode`-Logon verdächtige Änderungen in `AuditLogs` stattfanden (z. B. Änderungen an *Secrets* oder MFA-Methoden):

```kql
let IncidentWindow = 24h;
let DeviceCodeUsers = SigninLogs
    | where TimeGenerated >= ago(IncidentWindow)
    | where AuthenticationProtocol == "deviceCode" and ResultType == 0
    | distinct UserPrincipalName;
AuditLogs
| where TimeGenerated >= ago(IncidentWindow)
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| where Actor in (DeviceCodeUsers)
| project
    TimeGenerated,
    OperationName,
    Category,
    Result,
    Actor,
    SourceIP = tostring(InitiatedBy.user.ipAddress),
    CorrelationId
| order by TimeGenerated desc
```

---

## Referenzen

- [Microsoft Learn — Built-in detections in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Microsoft Learn — Microsoft identity platform and the OAuth 2.0 device authorization grant flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code)
- [MITRE ATT&CK — T1528: Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)

