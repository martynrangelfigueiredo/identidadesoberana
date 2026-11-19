---
title: "Änderungen an Conditional-Access-Richtlinien in Microsoft Security: Leitfaden für Sentinel und KQL"
description: "Operatives Microsoft Security Playbook für SOC-Analysten zur Untersuchung von Änderungen oder Deaktivierungen von Conditional Access in Entra ID mit Sentinel und KQL."
date: 2026-11-19
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, conditional-access, kql, soc, dfir]
nivel: Intermediário
draft: false
---

> **TL;DR:** Ungeplante Änderungen an *Conditional-Access*-Richtlinien können stille Lücken für einen MFA-*Bypass* oder unkontrollierten Zugriff auf kritische Anwendungen öffnen. Dieses Playbook beschreibt die Triage in Microsoft Sentinel, KQL-Abfragen für `AuditLogs` und `SigninLogs`, ITSM-Prüfung sowie Eindämmungsschritte in Entra ID.

---

## 1. Was bedeutet dieser Vorfall?

Im **Microsoft Security**-Ökosystem überwacht Microsoft Sentinel kontinuierlich administrative Ereignisse in der Tabelle `AuditLogs` von Microsoft Entra ID. Wird eine *Conditional-Access*-Richtlinie geändert, in den Modus *Report-only* versetzt, deaktiviert (*Off*) oder gelöscht — oder wird eine neue Ausnahme (Benutzer, Gruppe oder *Named Location*) hinzugefügt —, löst eine Standard-*Analytics Rule* einen Incident mit hoher Priorität aus.

Die offizielle Dokumentation im [Erkennungskatalog von Microsoft Sentinel auf Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) sowie die [Übersicht zu Conditional Access in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview) betonen, dass Änderungen an dieser Ebene direkt die Zero-Trust-Posture des *Tenants* beeinflussen.

### Gutartige vs. bösartige Szenarien

| Szenario | Typische Indikatoren | Klassifizierung |
|---|---|---|
| **Genehmigtes Wartungsfenster / Change-Ticket** | Bekannter Administrator, offenes Ticket im ITSM, Anpassung während der Geschäftszeiten, Sitzung mit Phishing-resistenter MFA. | False Positive (Gutartig) |
| **Automatisierung über Infrastructure as Code (IaC)** | Änderung durch autorisierten *Service Principal* (z. B. Terraform/Bicep-Pipeline) von einer bekannten Unternehmens-IP oder einem Runner. | False Positive (Gutartig) |
| **Stille Ausnahme nach Kompromittierung** | Angreifer mit privilegierten Rechten fügt ein *Backdoor*-Konto zur *Exclude*-Liste hinzu oder deaktiviert die MFA-Pflicht. | True Positive (T1562.001) |
| **Hinzufügen einer bösartigen Named Location** | Aufnahme eines unbekannten externen IP-Blocks als vertrauenswürdiger Standort (*Trusted Location*), um einen *Bypass* zu ermöglichen. | True Positive (T1562 / T1098) |

---

## 2. KQL-Tipp: Änderungen an Conditional Access im Kontext analysieren

Beim Öffnen eines solchen Incidents in Microsoft Sentinel projiziert die folgende Abfrage einige zusätzliche Spalten aus `AuditLogs`, um schnell nachzuvollziehen, welche Richtlinie geändert wurde, welche Aktion stattfand und wer sie ausgelöst hat, ohne lange JSON-Strukturen manuell durchsuchen zu müssen.

```kql
let Lookback = 7d;
AuditLogs
| where TimeGenerated >= ago(Lookback)
| where Category == "Policy"
| where OperationName has_any ("Add conditional access policy", "Update conditional access policy", "Delete conditional access policy", "Add policy", "Update policy", "Delete policy")
| mv-expand Target = TargetResources
| mv-expand ModProp = Target.modifiedProperties
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatorApp = tostring(InitiatedBy.app.displayName)
| extend SourceIP = tostring(InitiatedBy.user.ipAddress)
| extend PolicyName = tostring(Target.displayName)
| extend PropertyName = tostring(ModProp.displayName)
| extend OldValue = tostring(ModProp.oldValue)
| extend NewValue = tostring(ModProp.newValue)
| project
    TimeGenerated,
    OperationName,
    Result,
    PolicyName,
    Initiator = coalesce(InitiatorUPN, InitiatorApp),
    SourceIP,
    PropertyName,
    OldValue,
    NewValue,
    CorrelationId
| order by TimeGenerated desc
```

---

## 3. Untersuchungsleitfaden: die 5 Pflichtfragen

Um den Incident zuverlässig als True Positive (TP) oder False Positive (FP) einzustufen, beantworten Sie die folgenden fünf Fragen:

### 1. Was wurde getan?
- Prüfen Sie `OperationName` sowie `OldValue` und `NewValue` in der KQL-Abfrage.
- **Kritische Prüfpunkte:**
  - Wurde die Richtlinie von `enabled` auf `disabled` oder `enabledForReportingButNotEnforced` (*Report-only*) geändert?
  - Wurden Konten oder Gruppen zu `excludeUsers` / `excludeGroups` hinzugefügt?
  - Wurde ein neuer IP-Bereich in *Named Locations* als `isTrusted: true` markiert?
- Notieren Sie die `CorrelationId`, um zusammenhängende Aktionen derselben Verwaltungssitzung zu verfolgen.

### 2. Wer hat es getan?
- Analysieren Sie `InitiatorUPN` (menschlicher Benutzer) oder `InitiatorApp` (*Service Principal*).
- Prüfen Sie bei Benutzern die zeitnahen `SigninLogs`:
  - Quell-IP (`SourceIP`), Geolokalisierung und ASN.
  - Wurde Phishing-resistente MFA (*Passkey* / FIDO2) oder eine schwächere Methode genutzt?
  - Gab es kürzlich Änderungen an *Secrets* oder Authentifizierungsmethoden dieses Kontos?

### 3. Durfte die Person das tun?
- Nicht jeder Benutzer sollte *Conditional-Access*-Richtlinien ändern dürfen. Prüfen Sie, ob der Autor über eine autorisierte Rolle in Entra ID verfügt:
  - **Conditional Access Administrator**
  - **Security Administrator**
  - **Global Administrator**
- Falls PIM (*Privileged Identity Management*) im Einsatz ist, prüfen Sie die vorherige Aktivierung samt Begründung.

### 4. Gibt es ein formelles Change-Ticket?
- Führen Sie einen verpflichtenden Abgleich mit dem **ITSM**-System durch (**ServiceNow**, **Jira Service Management**, **Freshservice** oder **Zendesk**).
- Bestätigen Sie, ob ein genehmigter Change exakt die geänderte Richtlinie, den Umfang und das Zeitfenster abdeckt.
- Prüfen Sie, ob `ResultReason` oder die PIM-Begründung auf die Ticketnummer verweist.

### 5. War die Sitzung legitim?
- Prüfen Sie in Microsoft Entra ID Protection, ob für Benutzer oder Sitzung ein erhöhtes Risiko (`RiskLevelDuringSignIn` oder `RiskState`) vorlag.
- Bewerten Sie den *User-Agent* in `SigninLogs`: Automatisierte Skripte (`python-requests`, `curl`, `PowerShell`) außerhalb bekannter Runner oder von privaten IPs/kommerziellen VPNs sind starke Hinweise auf eine Kompromittierung.

---

## 4. Wo im Portal untersuchen (Microsoft Entra admin center)

Zur visuellen Überprüfung im Portal (`entra.microsoft.com`) nutzen Sie diese Pfade:

1. **Geänderte Richtlinie prüfen:**
   `Protection > Conditional Access > Policies` (Richtlinie anhand von `PolicyName` öffnen und *Users*, *Target resources*, *Conditions* sowie *Grant* prüfen).
2. **Named Locations kontrollieren:**
   `Protection > Conditional Access > Named locations` (prüfen, ob neue IP-Blöcke oder Länder als vertrauenswürdig eingetragen wurden).
3. **Audit-Logs im Portal:**
   `Identity > Monitoring & health > Audit logs` (nach **Category: Policy** und der **Correlation ID** filtern).

---

## 5. MITRE ATT&CK und Kontrollen

| Framework | Referenz | Beschreibung |
|---|---|---|
| **MITRE ATT&CK** | `T1562.001` | *Impair Defenses: Disable or Modify Tools* (Schwächung von Zugriffsrichtlinien). |
| **MITRE ATT&CK** | `T1098` | *Account Manipulation* (Aufnahme von Konten/Gruppen in Ausnahmelisten). |
| **NIST CSF** | `PR.AA-05` | Kontinuierliche Überprüfung von Zugriffsrechten und Least Privilege. |
| **CIS Controls v8** | `6.3` / `6.5` | MFA-Pflicht für administrativen und Remote-Zugriff ohne undokumentierte Ausnahmen. |

---

## 6. Reaktions- und Eindämmungsverfahren

Bestätigt die Untersuchung, dass **kein** autorisiertes Ticket vorliegt oder die Sitzung verdächtig ist, führen Sie umgehend dieses *Playbook* aus:

1. **Richtlinie sofort wiederherstellen:** Unter `Protection > Conditional Access > Policies` den vorherigen Zustand (`On`) aktivieren bzw. unbefugte Einträge aus *Exclude* entfernen.
2. **Sitzungen widerrufen (*Revoke sessions*):** Im Benutzerprofil unter `Identity > Users > All users` auf **Revoke sessions** klicken und Zugangsdaten/MFA zurücksetzen.
3. **Service Principals auditieren:** Falls die Änderung über eine App erfolgte, *Client Secrets* und Berechtigungen (`Policy.ReadWrite.ConditionalAccess`) des *Service Principals* prüfen.
4. **Post-Incident-Audit mit KQL:** Prüfen Sie mit der folgenden Abfrage, ob nach der Richtlinienänderung Anmeldungen ohne MFA oder von verdächtigen IPs erfolgreich waren:

```kql
let IncidentWindow = 24h;
SigninLogs
| where TimeGenerated >= ago(IncidentWindow)
| where ResultType == 0
| where ConditionalAccessStatus == "notApplied" or AuthenticationRequirement != "multiFactorAuthentication"
| project
    TimeGenerated,
    UserPrincipalName,
    AppDisplayName,
    IPAddress,
    ConditionalAccessStatus,
    AuthenticationRequirement,
    UserAgent,
    CorrelationId
| order by TimeGenerated desc
```

---

## Referenzen

- [Microsoft Learn — Built-in detections in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Microsoft Learn — What is Conditional Access in Microsoft Entra ID?](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview)
- [MITRE ATT&CK — T1562.001: Impair Defenses](https://attack.mitre.org/techniques/T1562/001/)

