---
title: "MFA-Betrugswarnung in Microsoft Security: Playbook zur Triage und Incident Response für SOC-Analysten"
description: "Praxisnaher Leitfaden im Microsoft Security-Ökosystem zur Untersuchung von MFA Deny- und Betrugswarnungen in Microsoft Sentinel unter Analyse von SigninLogs und AuditLogs."
date: 2026-11-16
categoria: SOC
tags: [microsoft-security, sentinel, soc, entra-id, mfa, kql, incident-response, playbooks, investigacao]
nivel: Intermediário
---

In einem Security Operations Center (SOC) erfordern nur wenige Benachrichtigungen eine so schnelle Reaktion wie eine **vom Benutzer gemeldete MFA-Betrugswarnung** (*user reported suspicious MFA prompt* oder *Explicit MFA Deny*). Anders als bei generischen Brute-Force-Versuchen oder Password Spraying, die bereits beim ersten Faktor scheitern, signalisiert diese Warnung einen kritischen Zustand: **Der Angreifer besitzt bereits die legitimen primären Anmeldedaten (Benutzername und Passwort)**. Die einzige Barriere, die den Zugriff verhinderte, war die aktive Ablehnung durch den Benutzer beim zweiten Faktor.

Wenn ein Mitarbeiter eine Benachrichtigung zum Nummernvergleich (*Number Matching*) in Microsoft Authenticator erhält und „Das bin ich nicht“ auswählt, protokolliert Microsoft Entra ID den Authentifizierungsfehler und erzeugt Audit-Ereignisse, die die Analyseregeln von Microsoft Sentinel speisen.

> 📘 **Offizielle Referenz auf Microsoft Learn:**
> - [Microsoft Entra ID-Anmeldefehlercodes — Fehler 500121](https://learn.microsoft.com/entra/identity/monitoring-health/concept-sign-ins#sign-in-error-codes)
> - [Untersuchung von Vorfällen in Microsoft Sentinel](https://learn.microsoft.com/azure/sentinel/investigate-incidents)
> - [Integrierte Erkennungs- und Analyseregeln in Microsoft Sentinel](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in)

---

## 1. Was bedeutet die MFA-Betrugswarnung?

Wenn ein Benutzer im Authentifikator Betrug meldet, klassifiziert Entra ID das Ereignis in den `SigninLogs` unter dem Fehlercode **500121** (*Authentication failed during strong authentication request*), ergänzt durch die Detailbeschreibung des gemeldeten Betrugs oder der abgelehnten Anfrage.

Für das SOC-Team muss dieses Ereignis unverzüglich als Vorfall hoher Priorität (P1 oder P2) behandelt werden, da es drei Tatsachen belegt:
1. **Gültige Anmeldedaten in den Händen des Angreifers:** Der Angreifer hat die erste Authentifizierungsphase erfolgreich durchlaufen (Passwort ist kompromittiert).
2. **Aktiver Zugriffsversuch in Echtzeit:** Der Angreifer interagiert genau in diesem Moment mit dem Portal oder Dienst.
3. **Unmittelbares Folgerisiko:** Der Angreifer könnte alternative Vektoren versuchen, wie MFA-Fatigue (*Push-Bombing*), Adversary-in-the-Middle (AitM) zur Sitzungstoken-Übernahme oder Zugriffe über Legacy-Protokolle ohne MFA.

---

## 2. KQL-Tipp: Untersuchung abgelehnter und als Betrug gemeldeter MFA-Anfragen

Die folgende Abfrage projiziert einige nützliche Spalten, um das Authentifizierungsereignis zu kontextualisieren, die Quell-IP des Versuchs zuzuordnen und Details der MFA-Schritte zu prüfen:

```kql
// ====================================================================================
// Consulta: Identificando alertas de fraude em MFA e tentativas de logon bloqueadas
// Objetivo: Mapear usuario alvo, IP de origem da tentativa, localizacao e detalhes de autenticacao
// ====================================================================================
let JanelaTempo = 24h;
SigninLogs
| where TimeGenerated >= ago(JanelaTempo)
| where ResultType == 500121
| mv-expand AuthDetail = AuthenticationDetails
| extend DetalhePasso = tostring(AuthDetail.authenticationStepResultDetail)
| where ResultDescription has "fraud" 
     or DetalhePasso has "fraud" 
     or ResultDescription has "denied" 
     or DetalhePasso has "denied"
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    AppDisplayName,
    ClientAppUsed,
    ResultType,
    ResultDescription,
    DetalhePasso,
    RiskLevelDuringSignIn,
    CorrelationId
| order by TimeGenerated desc
```

### Wichtige Prüfpunkte in den Ergebnissen:
- **`IPAddress` und `Location`:** Vergleichen Sie die Quell-IP mit dem regulären Anmeldeverlauf des Benutzers. Kommerzielle VPNs, Tor-Knoten oder ungewöhnliche Länder weisen eindeutig auf externe Bedrohungen hin.
- **`AppDisplayName`:** Zeigt an, ob der Angreifer auf das `Azure Portal`, `Office 365 Exchange Online` oder eine angebundene Enterprise-Applikation zugreifen wollte.
- **`CorrelationId`:** Zentraler Schlüssel zur Korrelation mit Ereignissen in den `AuditLogs` desselben Tenants.

---

## 3. Untersuchungsleitfaden: Die 5 obligatorischen Fragen

Bei der Bearbeitung des Vorfalls in Microsoft Sentinel sollte der Analyst folgende Fragen strukturiert beantworten:

### 1. Was wurde getan?
Prüfen Sie die Ereignistelemetrie. Wurde der Nummernvergleich (*Number Matching*) ausgelöst? Hat der Benutzer lediglich auf „Ablehnen“ geklickt oder explizit „Betrug melden“ ausgewählt? Fand der Versuch während der üblichen Arbeitszeit statt?

### 2. Wer hat es getan?
Überprüfen Sie das betroffene Konto (`UserPrincipalName`). Handelt es sich um ein VIP-Konto, einen Entwickler mit Pipeline-Zugriff oder ein Konto mit privilegierten Rollen (wie *Global Administrator* oder *Privileged Role Administrator*)?

### 3. War die Aktion legitim möglich?
Prüfen Sie, ob der Mitarbeiter sich auf einer Geschäftsreise befindet oder ein neues Mobilgerät eingerichtet hat. Stammt der Versuch aus einem ausländischen ASN, während der Benutzer im Büro arbeitet, erhärtet sich der Angriffsverdacht.

### 4. Liegt ein formelles Ticket im ITSM vor?
Prüfen Sie das ITSM-System (ServiceNow, Jira Service Management, Freshservice oder Zendesk). Hat der Benutzer ein Support-Ticket eröffnet, um eine verdächtige Push-Benachrichtigung zu melden? Eine aktive Meldung liefert sofortige Bestätigung der Abwehr.

### 5. Gab es vor oder nach der Warnung erfolgreiche Logons?
Konnte der Angreifer kurz vor oder nach der Warnung über einen anderen Kanal erfolgreich auf das Konto zugreifen (z. B. Legacy-Authentifizierung ohne MFA oder ein zuvor als vertrauenswürdig eingestufter Browser)?

---

## 4. Untersuchung im Microsoft Entra Admin Center

Für SOC-Analysten, die Sentinel-Alarme direkt im Identitätsportal verifizieren:

1. Öffnen Sie das **Microsoft Entra Admin Center** (`entra.microsoft.com`).
2. Navigieren Sie zu **Identity > Monitoring & health > Sign-in logs**.
3. Fügen Sie unter **User sign-ins (interactive)** folgende Filter hinzu:
   - **Status:** *Failure*
   - **Error code:** *500121*
4. Öffnen Sie den Vorfallseintrag und prüfen Sie:
   - **Basic info:** Correlation ID, IP-Adresse und Standort.
   - **Authentication Details:** Überprüfen Sie die Methode (z. B. *Mobile app notification*) und das Einzelergebnis (*Fraud reported by user*).
   - **Conditional Access:** Prüfen Sie, welche Richtlinien für bedingten Zugriff ausgewertet wurden.
5. Wechseln Sie zu **Identity > Protection > Risky users**:
   - Prüfen Sie, ob das Benutzerkonto auf das Risikoniveau **Mittel** oder **Hoch** hochgestuft wurde.
   - Prüfen Sie in **Risk detections** verknüpfte Erkennungen wie *Unfamiliar sign-in properties* oder *Suspicious user reported activity*.

---

## 5. Sofortige Eindämmungs- und Reaktionsmaßnahmen

Sobald feststeht, dass das Kennwort kompromittiert ist, muss das SOC folgende Schritte im Playbook ausführen:

1. **Aktive Sitzungen widerrufen (*Revoke sessions*):**
   - Im Benutzerprofil im Entra ID-Portal auf **Revoke sessions** klicken (oder via PowerShell: `Revoke-MgUserSignOut -UserId <UPN>`). Dies entwertet sofort alle ausgestellten Refresh-Tokens.
2. **Passwort-Reset erzwingen:**
   - Da das Kennwort dem Angreifer bekannt ist, muss ein sofortiger Kennwortwechsel über einen sicheren Out-of-Band-Kanal durchgeführt werden.
3. **Registrierte Authentifizierungsmethoden prüfen (*Authentication methods*):**
   - Unter **Identity > Users > [Benutzer] > Authentication methods** sicherstellen, dass keine unbefugten Zweitfaktoren (fremde Mobilfunknummern, zusätzliche Authenticator-Apps oder nicht autorisierte FIDO2-Sicherheitsschlüssel) hinterlegt wurden.
4. **Persistenz in E-Mail und Apps ausschließen:**
   - Prüfen Sie Exchange Online auf verdächtige Weiterleitungsregeln (`ForwardTo`).
   - Prüfen Sie die `AuditLogs` auf neu erteilte OAuth-Zustimmungen für fremde Applikationen.

---

## 6. KQL-Abfrage nach dem Vorfall: Parallele Erfolge und Fehlschläge prüfen

Führen Sie nach der Eindämmung folgende Abfrage aus, um alle Anmeldeversuche der letzten 48 Stunden zu überprüfen und etwaige Erfolge (`ResultType == 0`) zu identifizieren:

```kql
// ====================================================================================
// Verificacao Pos-Incidente: Investigando atividade da conta e tentativas com sucesso
// Objetivo: Confirmar se o atacante obteve acesso previo ou posterior ao alerta de fraude
// ====================================================================================
let JanelaAnalise = 48h;
let UsuarioInvestigado = "usuario.alvo@contoso.com";
SigninLogs
| where TimeGenerated >= ago(JanelaAnalise)
| where tolower(UserPrincipalName) == tolower(UsuarioInvestigado)
| extend StatusAuth = iff(ResultType == 0, "Sucesso", "Falha")
| project
    TimeGenerated,
    UserPrincipalName,
    AppDisplayName,
    IPAddress,
    Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    StatusAuth,
    ResultType,
    ResultDescription,
    RiskLevelDuringSignIn,
    RiskState
| order by TimeGenerated desc
```

### Vorfall-Klassifizierungsmatrix (TP vs. FP):

| Analyse-Szenario | Klassifizierung | Operative SOC-Maßnahme |
|---|---|---|
| Benutzer kennt den Versuch nicht, verdächtige Auslands-IP, korrektes Erstkennwort | **True Positive (TP)** | Konto isolieren, Sitzungen widerrufen, Kennwort zurücksetzen und Endpoint-Untersuchung auf Malware/Phishing einleiten. |
| Benutzer hat versehentlich auf dem eigenen Mobiltelefon „Das bin ich nicht“ angetippt | **False Positive (FP)** | Rücksprache mit dem Benutzer über offizielle Kanäle, Sensibilisierung und Abschluss des Alarms in Sentinel mit Dokumentation. |
| Verdächtige Quell-IP gefolgt von erfolgreichem Logon über Legacy-Protokolle | **Kritischer Vorfall (TP)** | Sofortige Eskalation an N3/DFIR für Threat Hunting und Durchsetzung von Richtlinien gegen Legacy-Authentifizierung. |
