---
title: "Verdächtige Posteingangsregeln in Microsoft Security: Leitfaden für Sentinel und KQL"
description: "Operatives Microsoft Security Playbook für SOC-Analysten zur Untersuchung verdächtiger Inbox Rules und externer Weiterleitungen in Exchange Online mit Sentinel und KQL."
date: 2026-11-21
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, exchange-online, kql, soc, dfir]
nivel: Intermediário
draft: false
---

> **TL;DR:** Nach einer Kontokompromittierung via *Phishing* oder *Adversary-in-the-Middle (AitM)* erstellen Angreifer häufig Posteingangsregeln (*Inbox Rules*), um Sicherheitswarnungen zu verbergen oder E-Mails aus dem *Tenant* auszuleiten. Dieses Playbook zeigt die Untersuchung im **Microsoft Security**-Ökosystem mit Microsoft Sentinel, KQL (`OfficeActivity` und `SigninLogs`) sowie die Eindämmung in Entra ID.

---

## 1. Was bedeutet dieser Vorfall?

Im **Microsoft Security**-Ökosystem überwacht Microsoft Sentinel die Tabelle `OfficeActivity` (Exchange-Online-Protokolle) auf Operationen wie `New-InboxRule`, `Set-InboxRule` oder `Enable-InboxRule` mit typischen Verschleierungs- oder Exfiltrationsmerkmalen — etwa das Verschieben von Nachrichten in *RSS Subscriptions* oder *Deleted Items*, automatisches Markieren als gelesen oder Weiterleitungen (`ForwardTo`, `RedirectTo`) an externe Domains.

Laut dem [Erkennungskatalog von Microsoft Sentinel auf Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) und der [Dokumentation zum Postfach-Auditing in Microsoft Purview](https://learn.microsoft.com/en-us/purview/audit-mailboxes) wird diese Technik (`MITRE ATT&CK T1114.003` und `T1564.008`) häufig bei *Business Email Compromise (BEC)* eingesetzt.

### Gutartige vs. bösartige Szenarien

| Szenario | Typische Indikatoren | Klassifizierung |
|---|---|---|
| **Persönliche Newsletter-Sortierung** | Regel vom Benutzer selbst über gewohnte IP erstellt, um Benachrichtigungen in einen internen Ordner zu verschieben. | False Positive (Gutartig) |
| **Dokumentierte interne Weiterleitung** | Regel leitet Anfragen an ein genehmigtes internes Postfach oder Ticketsystem weiter. | False Positive (Gutartig) |
| **Stilles Verbergen (BEC / AitM)** | Regel mit kryptischem Namen (`.`, `..`, `a`, `zzz`), setzt `MarkAsRead: True` und verschiebt Mails mit Begriffen wie *"Rechnung"*, *"Passwort"* oder *"Alert"* nach *Deleted Items*. | True Positive (T1564.008) |
| **Externe Exfiltration** | Regel mit `ForwardTo` oder `RedirectTo` an kostenlosen externen Maildienst kurz nach Anmeldung von einer ungewöhnlichen IP. | Kritisches True Positive (T1114.003) |

---

## 2. KQL-Tipp: Posteingangsregeln in OfficeActivity detailliert prüfen

Beim Öffnen des Incidents in Microsoft Sentinel projiziert die folgende Abfrage einige zusätzliche Spalten aus `OfficeActivity`, um die Regelparameter via `mv-expand` aufzulösen und Regelname, Quell-IP sowie Aktionen direkt anzuzeigen.

```kql
let Lookback = 7d;
OfficeActivity
| where TimeGenerated >= ago(Lookback)
| where RecordType == "ExchangeAdmin" or Workload == "Exchange"
| where Operation in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule")
| mv-expand Param = Parameters
| extend ParamName = tostring(Param.Name)
| extend ParamValue = tostring(Param.Value)
| project
    TimeGenerated,
    UserId,
    Operation,
    ClientIP,
    ResultStatus,
    ParamName,
    ParamValue,
    OfficeObjectId
| order by TimeGenerated desc
```

---

## 3. Untersuchungsleitfaden: die 5 Pflichtfragen

Um den Vorfall zuverlässig als True Positive (TP) oder False Positive (FP) einzustufen, beantworten Sie diese fünf Fragen:

### 1. Was wurde getan?
- Prüfen Sie die Paare `ParamName` und `ParamValue` in der KQL-Ausgabe:
  - `MoveToFolder` nach *Deleted Items*, *Junk Email* oder *RSS Subscriptions*.
  - `MarkAsRead = True` oder `DeleteMessage = True`.
  - `ForwardTo`, `ForwardAsAttachmentTo` oder `RedirectTo` an externe Empfänger.
  - Verdächtige Schlüsselwörter in `SubjectContainsWords` oder `BodyContainsWords` (z. B. `invoice`, `payment`, `bank`, `security`, `MFA`).

### 2. Wer hat es getan?
- Prüfen Sie `UserId` und `ClientIP` in `OfficeActivity`.
- Korrelieren Sie die `ClientIP` mit `SigninLogs` in Entra ID im selben Zeitfenster:
  - ASN, Land und Provider der IP (z. B. VPS, Residential Proxy oder kommerzielles VPN).
  - Verwendeter *User-Agent* (ungewöhnliche Web-Sitzung vs. regulärer Outlook-Client).
  - Gab es kürzlich Änderungen an *Secrets* oder MFA-Geräten des Kontos?

### 3. Durfte die Person das tun?
- Standardmäßig kann jeder angemeldete Benutzer eigene *Inbox Rules* anlegen, doch **automatische externe Weiterleitungen** sollten durch Outbound-Anti-Spam-Richtlinien in Microsoft Defender for Office 365 blockiert sein.
- Falls ein Admin oder *Service Principal* die Regel per Remote-PowerShell erstellt hat, prüfen Sie die betriebliche Notwendigkeit.

### 4. Gibt es ein formelles Change-Ticket?
- Wurde die Regel durch den IT-Support oder eine Automatisierung eingerichtet (z. B. Postfach-Weiterleitung nach Austritt), prüfen Sie zwingend das **ITSM**-System (**ServiceNow**, **Jira Service Management**, **Freshservice** oder **Zendesk**).
- Verifizieren Sie Zieladresse, Antragsteller und Genehmigung.

### 5. War die Sitzung legitim?
- Prüfen Sie in `SigninLogs`, ob die Sitzung der `ClientIP`:
  - Phishing-resistente MFA (*Passkey* / FIDO2) nutzte oder auf einem gestohlenen Session-Token (*AitM*) basierte.
  - Warnungen in Microsoft Entra ID Protection (`Risky sign-ins`, untypischer Standort oder unmögliche Reise) ausgelöst hat.

---

## 4. Wo im Portal untersuchen (Microsoft Entra & Defender)

Zur visuellen Überprüfung im Portal:

1. **Anmeldeprotokolle in Entra ID (`entra.microsoft.com`):**
   `Identity > Monitoring & health > Sign-in logs` (nach `UserId` und der in `OfficeActivity` gesehenen `ClientIP` filtern).
2. **Riskante Benutzer in Entra ID:**
   `Protection > Identity Protection > Risky users`.
3. **Einheitliches Audit-Log in Microsoft Purview / Defender (`security.microsoft.com`):**
   `Audit` (nach **New-InboxRule** und **Set-InboxRule** für den betroffenen Benutzer suchen).

---

## 5. MITRE ATT&CK und Kontrollen

| Framework | Referenz | Beschreibung |
|---|---|---|
| **MITRE ATT&CK** | `T1114.003` | *Email Collection: Email Forwarding Rule* (automatische Weiterleitung zur Exfiltration). |
| **MITRE ATT&CK** | `T1564.008` | *Hide Artifacts: Email Hiding Rules* (Verbergen von Antworten und Warnungen in Ordnern). |
| **NIST CSF** | `DE.CM-03` / `RS.MI-02` | Überwachung von Benutzeraktivitäten und schnelle Eindämmung von Datenabfluss. |
| **CIS Controls v8** | `9.7` / `8.5` | Kontrolle von E-Mail-Weiterleitungen und detaillierte Audit-Protokollierung. |

---

## 6. Reaktions- und Eindämmungsverfahren

Bestätigt sich eine bösartige Regel, führen Sie sofort dieses *Playbook* aus:

1. **Aktive Sitzungen widerrufen:** Unter `Identity > Users > All users` den Benutzer öffnen, auf **Revoke sessions** klicken, Passwort zurücksetzen und unbekannte MFA-Methoden entfernen.
2. **Bösartige Regel löschen:** In Exchange Online PowerShell (`Remove-InboxRule -Identity "<RuleId>" -Mailbox "<UPN>"`) oder im Exchange Admin Center die Regel entfernen und *Transport Rules* im *Tenant* prüfen.
3. **Postfach-Weiterleitung prüfen:** Kontrollieren, ob `ForwardingSmtpAddress` gesetzt wurde (`Get-Mailbox <UPN> | fl ForwardingSmtpAddress,DeliverToMailboxAndForward`).
4. **Post-Incident-Audit mit KQL:** Prüfen Sie mit folgender Abfrage, ob dieselbe `ClientIP` in den letzten 48 Stunden auf weitere Konten zugegriffen hat:

```kql
let IncidentWindow = 48h;
let SuspectIPs = OfficeActivity
    | where TimeGenerated >= ago(IncidentWindow)
    | where Operation in ("New-InboxRule", "Set-InboxRule")
    | distinct ClientIP;
SigninLogs
| where TimeGenerated >= ago(IncidentWindow)
| where IPAddress in (SuspectIPs)
| project
    TimeGenerated,
    UserPrincipalName,
    AppDisplayName,
    IPAddress,
    ResultType,
    UserAgent,
    RiskLevelDuringSignIn,
    CorrelationId
| order by TimeGenerated desc
```

---

## Referenzen

- [Microsoft Learn — Built-in detections in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Microsoft Learn — Audit mailbox activity in Microsoft Purview](https://learn.microsoft.com/en-us/purview/audit-mailboxes)
- [MITRE ATT&CK — T1114.003: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003/)

