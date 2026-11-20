---
title: "Erkennung von Password Spraying in Microsoft Security: Praxis-Leitfaden für Entra ID mit Sentinel und KQL"
description: "Operatives Microsoft Security Playbook für SOC-Analysten zur Untersuchung von Password-Spraying-Kampagnen in Entra ID mit Microsoft Sentinel und KQL."
date: 2026-11-20
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, password-spraying, kql, soc, dfir]
nivel: Intermediário
draft: false
---

> **TL;DR:** Bei *Password-Spraying*-Kampagnen testen Angreifer wenige häufige Passwörter gegen Dutzende oder Hunderte Konten, um Kontosperrungen zu umgehen. Dieses Playbook zeigt die Untersuchung im **Microsoft Security**-Ökosystem mit Microsoft Sentinel, KQL-Abfragen auf `SigninLogs`, Prüfung erfolgreicher Logins nach dem Angriff sowie Eindämmung in Entra ID.

---

## 1. Was bedeutet dieser Vorfall?

Im **Microsoft Security**-Ökosystem überwacht Microsoft Sentinel die Tabelle `SigninLogs` auf IP-Adressen, die Authentifizierungsfehler (wie `50126` — ungültiger Benutzername/Passwort — und `50053` — *Smart Lockout*) über viele verschiedene `UserPrincipalName` in einem kurzen Zeitfenster erzeugen.

Anders als klassisches Brute-Force gegen ein einzelnes Konto verteilt *Password Spraying* (`MITRE ATT&CK T1110.003`) die Versuche horizontal über den *Tenant*. Laut dem [Erkennungskatalog von Microsoft Sentinel auf Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) und der [Dokumentation zu Microsoft Entra Password Protection](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-combined-policy) entsteht das höchste Risiko, wenn ein Versuch ein Konto ohne MFA oder mit aktiver Legacy-Authentifizierung trifft.

### Gutartige vs. bösartige Szenarien

| Szenario | Typische Indikatoren | Klassifizierung |
|---|---|---|
| **Unternehmens-Proxy / gemeinsames NAT** | IP gehört zum eigenen Unternehmens-ASN; mehrere Konten schlagen nach Passwortablauf oder Sammel-Reset fehl. | False Positive (Gutartig) |
| **Legacy-Anwendung mit veralteten Zugangsdaten** | Gleicher `AppDisplayName` und bekannter `UserAgent` nach Passwortrotation. | False Positive (Gutartig) |
| **Verteilter Spray-Angriff** | IP eines VPS/kommerziellen VPNs oder Wohnanschlusses testet Dutzende Konten je 1–2 Mal mit Skript-`UserAgent` (`python-requests`, `curl`). | True Positive (T1110.003) |
| **Treffer mit anschließender aktiver Sitzung** | Dieselbe IP erzeugt `ResultType == 50126` bei vielen Konten und kurz darauf `ResultType == 0` bei einem Konto. | Kritisches True Positive |

---

## 2. KQL-Tipp: Fehlversuche nach IP und betroffenen Konten korrelieren

Beim Öffnen des Incidents in Microsoft Sentinel projiziert die folgende Abfrage einige zusätzliche Spalten aus `SigninLogs`, um schnell zusammenzufassen, wie viele eindeutige Konten pro IP getestet wurden, welche Fehlercodes auftraten und ob erfolgreiche Logins stattfanden.

```kql
let Lookback = 24h;
SigninLogs
| where TimeGenerated >= ago(Lookback)
| where ResultType in ("50126", "50053", "50055", "50057", "0")
| summarize
    TotalAttempts = count(),
    DistinctAccounts = dcount(UserPrincipalName),
    FailedAttempts = countif(ResultType != "0"),
    SuccessCount = countif(ResultType == "0"),
    ErrorCodes = make_set(ResultType, 10),
    SampleApps = make_set(AppDisplayName, 5),
    SampleAgents = make_set(UserAgent, 5),
    TargetedUsers = make_set(UserPrincipalName, 10)
    by IPAddress
| where DistinctAccounts >= 5 and FailedAttempts >= 10
| project
    IPAddress,
    DistinctAccounts,
    TotalAttempts,
    FailedAttempts,
    SuccessCount,
    TargetedUsers,
    ErrorCodes,
    SampleApps,
    SampleAgents
| order by SuccessCount desc, DistinctAccounts desc
```

---

## 3. Untersuchungsleitfaden: die 5 Pflichtfragen

Um den Vorfall sicher als True Positive (TP) oder False Positive (FP) einzustufen, beantworten Sie diese fünf Fragen:

### 1. Was wurde getan?
- Prüfen Sie die Anzahl betroffener Konten (`DistinctAccounts`) und die `AADSTS`-Codes:
  - `50126`: falsches Passwort.
  - `50053`: Konto durch *Smart Lockout* gesperrt.
  - `0`: **höchste Priorität** — das Passwort war korrekt.
- Prüfen Sie, ob moderne Endpunkte oder Legacy-Protokolle (`ClientAppUsed` wie IMAP, POP3, SMTP) genutzt wurden.

### 2. Wer hat es getan?
- Untersuchen Sie die Quell-`IPAddress`, deren ASN und Reputation in *Threat-Intelligence*-Quellen.
- Günstige Cloud-Hoster, Tor-Exit-Nodes oder private IPs außerhalb des Betriebsgebiets sprechen stark für einen Angriff.
- Falls ein *Service Principal* betroffen ist, prüfen Sie `AADServicePrincipalSignInLogs` auf Versuche gegen *Client Secrets*.

### 3. Durfte die Person das tun? (Schutzlage)
- Prüfen Sie, ob die Angriffsfläche geschützt war:
  - Haben die betroffenen Konten Phishing-resistente MFA (*Passkey* / FIDO2) aktiv?
  - Blockieren *Conditional-Access*-Richtlinien Legacy-Authentifizierung?
  - Ist *Microsoft Entra Password Protection* im *Tenant* aktiviert?

### 4. Gibt es ein formelles Change-Ticket?
- Bei autorisierten Tests (*Pentest* oder internes *Red Team*) prüfen Sie zwingend das **ITSM**-System (**ServiceNow**, **Jira Service Management**, **Freshservice** oder **Zendesk**).
- Verifizieren Sie, ob Quell-IP, Zeitfenster und Umfang in einem genehmigten Ticket dokumentiert sind.

### 5. War die Sitzung legitim?
- Prüfen Sie für jedes Konto in `SuccessfulUsers` (`ResultType == 0`):
  - Wurde MFA erfüllt (`AuthenticationRequirement == "multiFactorAuthentication"`)?
  - Hat Entra ID Protection ein Sitzungsrisiko (`RiskLevelDuringSignIn`) gemeldet?
  - Weichen *UserAgent* und Standort vom historischen Muster des Benutzers ab?

---

## 4. Wo im Portal untersuchen (Microsoft Entra admin center)

Zur Überprüfung in `entra.microsoft.com`:

1. **Detaillierte Anmeldeprotokolle:**
   `Identity > Monitoring & health > Sign-in logs` (nach verdächtiger `IPAddress` sowie **Status: Failure** oder **Success** filtern).
2. **Riskante Benutzer und Sitzungen:**
   `Protection > Identity Protection > Risky sign-ins` und `Risky users`.
3. **Smart Lockout und gesperrte Passwörter:**
   `Protection > Authentication methods > Password protection`.

---

## 5. MITRE ATT&CK und Kontrollen

| Framework | Referenz | Beschreibung |
|---|---|---|
| **MITRE ATT&CK** | `T1110.003` | *Brute Force: Password Spraying* (horizontales Testen häufiger Passwörter). |
| **MITRE ATT&CK** | `T1078.004` | *Valid Accounts: Cloud Accounts* (Nutzung eines erfolgreich erratenen Kontos). |
| **NIST CSF** | `PR.AA-03` | Phishing-resistente MFA und Schutz vor Passwort-Raten. |
| **CIS Controls v8** | `6.3` / `5.2` | Verpflichtende MFA und starke Passwortrichtlinien. |

---

## 6. Reaktions- und Eindämmungsverfahren

Bestätigt sich eine bösartige Kampagne — insbesondere bei `SuccessCount > 0` — führen Sie sofort dieses *Playbook* aus:

1. **Betroffene Konten eindämmen:** Für jeden Benutzer in `SuccessfulUsers` unter `Identity > Users > All users` auf **Revoke sessions** klicken, Passwortwechsel erzwingen und registrierte MFA-Methoden bereinigen.
2. **Quell-IP blockieren:** Sofern passend, verdächtige IPs über eine blockierte *Named Location* in *Conditional Access* oder am Perimeter-WAF/Firewall sperren.
3. **Legacy-Protokolle sperren:** Sicherstellen, dass *Conditional Access* *Legacy Authentication* blockiert, um einen MFA-*Bypass* zu verhindern.
4. **Post-Incident-Audit mit KQL:** Prüfen Sie mit folgender Abfrage, ob in den Folgestunden verdächtige Audit-Aktionen von diesen IPs ausgingen:

```kql
let IncidentWindow = 24h;
let SuspectIPs = SigninLogs
    | where TimeGenerated >= ago(IncidentWindow)
    | where ResultType in ("50126", "50053")
    | summarize Accounts = dcount(UserPrincipalName) by IPAddress
    | where Accounts >= 5
    | project IPAddress;
AuditLogs
| where TimeGenerated >= ago(IncidentWindow)
| extend ActorIP = tostring(InitiatedBy.user.ipAddress)
| where ActorIP in (SuspectIPs)
| project
    TimeGenerated,
    OperationName,
    Category,
    Result,
    Actor = tostring(InitiatedBy.user.userPrincipalName),
    ActorIP,
    CorrelationId
| order by TimeGenerated desc
```

---

## Referenzen

- [Microsoft Learn — Built-in detections in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Microsoft Learn — Password protection in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-combined-policy)
- [MITRE ATT&CK — T1110.003: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
