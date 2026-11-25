---
title: "Legacy-Authentifizierung in Microsoft Security: MFA-Bypass-Untersuchung mit Entra ID und Sentinel"
description: "Operatives Microsoft Security Playbook für SOC-Analysten zur Untersuchung von Legacy-Protokoll-Anmeldungen in Entra ID mit Microsoft Sentinel und KQL."
date: 2026-11-25
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, mfa, kql, soc, dfir]
nivel: Intermediário
draft: false
---

> **TL;DR:** Ältere Protokolle wie IMAP4, POP3, SMTP AUTH und Exchange ActiveSync unterstützen weder moderne Authentifizierung noch interaktive MFA-Abfragen. Sind sie im Tenant aktiv, werden sie zum bevorzugten Ziel für *Password Spraying* und *MFA-Bypass*. Dieses Playbook zeigt die Untersuchung in **Microsoft Security** mit Microsoft Sentinel, KQL (`SigninLogs` und `OfficeActivity`), ITSM-Abgleich und Eindämmung in Microsoft Entra ID.

---

## 1. Was bedeutet dieser Vorfall?

Im **Microsoft Security**-Ökosystem überwacht Microsoft Sentinel die Tabelle `SigninLogs` auf Anmeldungen über Clients, die weder OAuth 2.0 noch moderne Multi-Faktor-Authentifizierung unterstützen. Diese erscheinen im Feld `ClientAppUsed` als `IMAP4`, `POP3`, `Authenticated SMTP`, `Exchange ActiveSync`, `MAPI Over HTTP` oder `Other clients`.

Wie im [Erkennungskatalog von Microsoft Sentinel auf Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) und im Leitfaden zum [Blockieren von Legacy-Authentifizierung in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication) beschrieben, nutzen Angreifer diese Endpunkte, um geleakte Passwörter oder *Password-Spraying*-Kampagnen (`MITRE ATT&CK T1110.003` und `T1078`) zu testen – oft ohne die Schutzmechanismen moderner Browser.

### Gutartige vs. bösartige Szenarien

| Szenario | Typische Indikatoren | Klassifizierung |
|---|---|---|
| **Multifunktionsdrucker oder Unternehmensscanner** | Protokoll `Authenticated SMTP` von bekannter interner/NAT-IP, dediziertes Dienstkonto, keine Massen-Fehlversuche. | False Positive (Gutartig – Migration auf OAuth/sicheres Relay nötig) |
| **Ältere ERP- oder CRM-Anwendung** | Wiederkehrende Nutzung von `IMAP4` oder `POP3` durch dokumentiertes technisches Konto mit formeller Conditional-Access-Ausnahme. | False Positive (Gutartig – kontrollierte technische Schuld) |
| ***Password-Spraying*-Kampagne über IMAP/POP3** | Dutzende Fehlversuche (`ResultType` 50126 oder 50053) gegen mehrere Konten von externen IPs, VPS oder untypischen Wohnungsnetzen. | True Positive (T1110.003) |
| **Erfolgreiche Anmeldung ohne MFA (*MFA-Bypass*)** | `ResultType == "0"` mit Legacy-`ClientAppUsed` und `AuthenticationRequirement == "singleFactorAuthentication"` bei regulärem oder privilegiertem Konto. | Kritisches True Positive (T1078) |

---

## 2. KQL-Tipp: Legacy-Protokolle und MFA-Status in SigninLogs filtern

Bei der Übernahme des Incidents in Microsoft Sentinel projiziert die folgende Abfrage zusätzliche Spalten aus `SigninLogs`, um verwendetes Legacy-Protokoll, Ergebniscode (`ResultType`), MFA-Anforderung sowie Herkunfts-IP und Land hervorzuheben.

```kql
let Lookback = 7d;
SigninLogs
| where TimeGenerated >= ago(Lookback)
| where ClientAppUsed in ("IMAP4", "POP3", "Authenticated SMTP", "SMTP", "Exchange ActiveSync", "Exchange Web Services", "AutoDiscover", "MAPI Over HTTP", "Offline Address Book", "Other clients")
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend City = tostring(LocationDetails.city)
| extend DeviceOS = tostring(DeviceDetail.operatingSystem)
| project
    TimeGenerated,
    UserPrincipalName,
    ClientAppUsed,
    AppDisplayName,
    ResultType,
    ResultDescription,
    ConditionalAccessStatus,
    AuthenticationRequirement,
    IPAddress,
    Country,
    City,
    DeviceOS,
    UserAgent,
    CorrelationId
| order by TimeGenerated desc
```

---

## 3. Untersuchungsleitfaden: die 5 Pflichtfragen

### 1. Was wurde getan?
Prüfen Sie in `SigninLogs`, ob der Versuch **blockiert oder erfolgreich** war:
- **`ResultType == "0"`:** Anmeldung erfolgreich ohne interaktive MFA-Prüfung abgeschlossen. Sofort als potenzielle Kompromittierung behandeln.
- **`ResultType == "53003"`:** Conditional Access hat das Legacy-Protokoll blockiert (erwartetes Abwehrverhalten).
- **`ResultType == "50126"`:** Ungültiges Passwort (starker Hinweis auf *Brute Force* oder *Password Spraying* gegen Legacy-Endpunkte).
- **`ResultType == "50053"`:** Konto durch Smart Lockout nach mehreren Fehlversuchen gesperrt.
- Notieren Sie `CorrelationId` und `UniqueTokenIdentifier` zur Korrelation mit weiteren Logs.

### 2. Wer hat es getan?
Analysieren Sie `UserPrincipalName`, `IPAddress` und `UserAgent`:
- Besitzt der betroffene Benutzer privilegierte Rollen in Entra ID (z. B. `Global Administrator` oder `Exchange Administrator`) oder Zugriff auf sensible Postfächer?
- Stammt die `IPAddress` von einem Cloud-/VPS-Anbieter, einem unbekannten VPN-Exit oder einem ungewöhnlichen ASN?
- Gab es zeitgleiche Anmeldeversuche gegen weitere Konten im Tenant von derselben IP?

### 3. Hätte die Person das tun dürfen?
Prüfen Sie, warum Legacy-Authentifizierung für dieses Konto noch verfügbar war:
- Existiert eine Conditional-Access-Richtlinie zum Blockieren von `Legacy authentication clients` für alle Benutzer, oder war das Konto in einer Ausnahmegruppe?
- Waren in Exchange Online Parameter wie `SmtpClientAuthenticationDisabled`, `ImapEnabled` oder `PopEnabled` am Postfach (`CASMailbox`) noch aktiv?

### 4. Gibt es ein formelles Change-Ticket?
Gleiche `UserPrincipalName` und `IPAddress` mit dem **ITSM**-System (ServiceNow, Jira Service Management, Freshservice oder Zendesk) ab:
- Liegt ein genehmigtes Ticket für einen Scanner, ein Ticketsystem oder eine Legacy-Integration vor, die dieses Postfach abruft?
- Falls eine Ausnahme genehmigt wurde, prüfen Sie, ob die Quell-IP exakt der freigegebenen statischen IP entspricht.

### 5. War die Sitzung legitim?
Selbst wenn der Benutzer einen älteren Mail-Client angibt, verifizieren Sie:
- Passt der `UserAgent` zu einer freigegebenen Unternehmenssoftware (aktuelles Outlook nutzt moderne Authentifizierung, nicht `IMAP4` oder `Other clients`)?
- Gibt es im gleichen Zeitraum eine moderne Anmeldung desselben Benutzers aus einer weit entfernten Region?

---

## 4. Wo im Portal untersuchen?

Zur Überprüfung von Richtlinien, Ausnahmen und Kontoverlauf direkt in den Admin-Portalen:

1. **Anmeldeprotokolle nach Legacy-Clients in Entra ID filtern:**
   - Öffnen Sie das Microsoft Entra admin center (`entra.microsoft.com`).
   - Pfad: `Identity > Monitoring & health > Sign-in logs`.
   - Setzen Sie den Filter `Client app` auf `Exchange ActiveSync`, `IMAP4`, `POP3`, `Authenticated SMTP` und `Other clients`.
2. **Conditional-Access-Richtlinien prüfen:**
   - Pfad: `Protection > Conditional Access > Policies`.
   - Prüfen Sie, ob eine aktive Richtlinie für `All cloud apps` mit Bedingung `Client apps = Exchange ActiveSync clients` und `Other clients` auf `Grant = Block access` konfiguriert ist.
3. **Protokoll-Einstellungen pro Postfach in Exchange Online:**
   - Öffnen Sie das Exchange admin center (`admin.exchange.microsoft.com`).
   - Pfad: `Recipients > Mailboxes > [Benutzer] > Manage email apps settings`, um POP3, IMAP und Authenticated SMTP zu prüfen.

---

## 5. Reaktion, Eindämmung und Post-Incident-Audit

Bei bestätigtem unbefugtem Erfolg (`ResultType == "0"`) über ein Legacy-Protokoll:

1. **Sitzungen widerrufen und Passwort zurücksetzen:**
   - Führen Sie im Microsoft Entra admin center (`Users > [Benutzer]`) sofort **Revoke sessions** aus und setzen Sie ein starkes, eindeutiges Passwort.
2. **Legacy-Protokolle auf Konto- und Tenant-Ebene deaktivieren:**
   - Deaktivieren Sie `IMAP`, `POP` und `Authenticated SMTP` am Postfach in Exchange Online und entfernen Sie das Konto aus Ausnahmegruppen im Conditional Access.
3. **Postfachaktivitäten nach dem Zugriff prüfen:**
   - Führen Sie die folgende Abfrage auf `OfficeActivity` aus, um zu erkennen, ob Nachrichten abgerufen, Weiterleitungsregeln erstellt oder E-Mails versendet wurden.

```kql
let TargetUser = "usuario@contoso.com";
let Lookback = 48h;
OfficeActivity
| where TimeGenerated >= ago(Lookback)
| where UserId == TargetUser
| where Operation in (
    "MailItemsAccessed",
    "New-InboxRule",
    "Set-InboxRule",
    "Set-Mailbox",
    "Add-MailboxPermission",
    "Send",
    "SendAs"
)
| project
    TimeGenerated,
    UserId,
    Operation,
    ClientIP,
    ClientInfoString,
    ResultStatus,
    Parameters
| order by TimeGenerated desc
```

---

## 6. Kontroll-Mapping und Compliance

| Framework / Standard | Zugehörige Kontrolle | Praktische Umsetzung |
|---|---|---|
| **MITRE ATT&CK** | `T1078` (Valid Accounts), `T1110.003` (Password Spraying) | Erkennung von Anmeldeversuchen über Protokolle ohne MFA-Unterstützung. |
| **NIST CSF 2.0** | `PR.AA-03` (Zugriffsverwaltung), `DE.CM-03` (Identitätsüberwachung) | Blockierung von Legacy-Authentifizierung per Conditional Access und Sentinel-Alerting. |
| **CIS Controls v8** | `6.3` / `6.5` (MFA für Anwendungen und Admin-Zugriffe) | Beseitigung von MFA-Bypass-Pfaden über IMAP/POP3/SMTP. |
| **ISO/IEC 27001:2022** | `A.8.5` (Sichere Authentifizierung) | Konsistente Durchsetzung starker Authentifizierung an allen Zugangspunkten. |
| **DSGVO / LGPD** | Art. 32 DSGVO / Art. 46 LGPD | Schutz von Postfächern und personenbezogenen Daten vor unbefugtem Zugriff. |
