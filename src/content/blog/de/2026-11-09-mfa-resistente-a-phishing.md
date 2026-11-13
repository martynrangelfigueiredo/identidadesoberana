---
title: "MFA-Fatigue und Phishing-Bypasses untersuchen: Playbook für das SOC"
description: "Vollständiges Playbook zur Triage und Eindämmung von MFA-Fatigue- und AitM-Vorfällen in Microsoft Sentinel: Angereichertes KQL, SigninLogs- und AuditLogs-Korrelation."
date: 2026-11-09
categoria: SOC
tags: [sentinel, mfa, entra-id, kql, aitm, incident-response, soc, iam]
nivel: Mittelstufe
---

Angriffe auf Multi-Faktor-Authentifizierungsmechanismen (MFA) haben sich drastisch weiterentwickelt. Reichte es früher aus, einen zweiten Faktor zu verlangen, um kompromittierte Passwörter abzuwehren, umgehen Angreifer Legacy-Authentifikatoren heute aktiv durch **MFA-Fatigue (*Push-Spamming*)** und Reverse-Proxies vom Typ **Adversary-in-the-Middle (AitM)**.

In Microsoft Sentinel signalisieren Vorfälle durch MFA-Anomalien eine der dringendsten Situationen für das Response-Team: Das Kennwort des Kontos ist bereits kompromittiert, und der Angreifer versucht, die letzte Zugangsbarriere zu überwinden.

> **TL;DR für das SOC:** Wenn dieser Vorfall ausgelöst wird, behandeln Sie ihn als bestätigte Zugangsdaten-Kompromittierung. Wenn nach mehreren MFA-Ablehnungen eine erfolgreiche Anmeldung von einer unbekannten IP erfolgt, leiten Sie sofortige Eindämmung ein: Aktive Sitzungen widerrufen (`Revoke sessions`), Kennwort-Reset erzwingen und prüfen, ob der Angreifer zusätzliche Authentifizierungsmethoden registriert hat.

> 📘 **Referenz in Microsoft Learn:** Dieses Playbook basiert auf den nativen Authentifizierungsanomalie-Erkennungen in Microsoft Sentinel und den Härtungsrichtlinien von Microsoft Entra ID:
> - [Microsoft Sentinel — Katalog integrierter Analyse-Erkennungsregeln (Learn)](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in)
> - [Microsoft Entra ID — Schutz vor MFA-Fatigue und Phishing-resistenten Methoden (Learn)](https://learn.microsoft.com/azure/active-directory/authentication/concept-authentication-methods)

---

## 1. Was bedeutet dieser Vorfall?

Wenn eine MFA-Anomalie-Erkennungsregel in Microsoft Sentinel anschlägt, spiegelt das Szenario typischerweise eine der folgenden Angriffsphasen wider:

1. **MFA-Fatigue-Angriff (*Push-Bombing*):** Der Angreifer besitzt das gültige Kennwort und löst Dutzende Benachrichtigungen in der Microsoft Authenticator App des Opfers aus, oft mitten in der Nacht, bis der Benutzer die Anfrage aus Müdigkeit oder Ablenkung bestätigt.
2. **Sitzungsabfängung via AitM-Proxy (z. B. Evilginx / Modlishka):** Das Opfer rief eine geklonte Anmeldeseite auf, die sowohl das Passwort als auch das Sitzungstoken in Echtzeit abfing.
3. **Wiederholte Fehler gefolgt von anomalem Erfolg:** Die Regel erfasst den Moment, in dem eine Serie von Fehlercodes `500121` (MFA abgelehnt) plötzlich von `0` (Erfolg) von einer ungewöhnlichen IP oder ASN gefolgt wird.
4. **Benignes False Positive:** Der Benutzer hatte Netzwerkschwankungen oder forderte den Code mehrfach an.

---

## 2. KQL-Tipp: Korrelation von MFA-Fatigue mit nachfolgender Anmeldung

Die folgende Abfrage korreliert abgelehnte Authentifizierungsversuche mit nachfolgenden erfolgreichen Anmeldungen innerhalb eines Zeitfensters und projiziert nützliche Kontextinformationen wie Authentifizierungsmethode, Standort, Betriebssystem und Sitzungsrisikostufe:

```kql
// ====================================================================================
// Detektion & Anreicherung: MFA Fatigue gefolgt von erfolgreichem Logon
// Autor: Identidade Soberana (identidadesoberana.com.br)
// Ziel: Wiederholte MFA-Ablehnungen mit nachfolgendem Erfolg anomaler IPs korrelieren
// ====================================================================================
let janelaAnalise = 24h;
let limiarFalhasMFA = 3;
// 1. Konten mit wiederholten MFA-Fehlern identifizieren (ResultType 500121 / 50074)
let NegacoesMFA = SigninLogs
| where TimeGenerated >= ago(janelaAnalise)
| where ResultType in (500121, 50074)
| summarize 
    QtdNegacoes = count(),
    PrimeiraFalha = min(TimeGenerated),
    UltimaFalha = max(TimeGenerated),
    IPsFalha = make_set(IPAddress, 5),
    LocaisFalha = make_set(Location, 5),
    UserAgentsFalha = make_set(UserAgent, 3)
    by UserPrincipalName, bin(TimeGenerated, 15m)
| where QtdNegacoes >= limiarFalhasMFA;
// 2. Erfolgreiche Logons desselben Kontos nach den Ablehnungen abrufen
let LogonsSucesso = SigninLogs
| where TimeGenerated >= ago(janelaAnalise)
| where ResultType == 0
| mv-expand AuthDetail = AuthenticationDetails
| project 
    HoraSucesso = TimeGenerated,
    UserPrincipalName,
    IPSucesso = IPAddress,
    LocalSucesso = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    Dispositivo = DeviceDetail.operatingSystem,
    Navegador = ClientAppUsed,
    MetodoMFA = tostring(AuthDetail.authenticationMethod),
    DetalheMFA = tostring(AuthDetail.authenticationStepResultDetail),
    RiscoSessao = RiskLevelDuringSignIn,
    IDCorrelacao = CorrelationId;
// 3. Zeitliche Korrelation: Erfolg innerhalb von 30 Minuten nach wiederholten Ablehnungen
NegacoesMFA
| join kind=inner (LogonsSucesso) on UserPrincipalName
| where HoraSucesso between (UltimaFalha .. (UltimaFalha + 30m))
| project
    DataHoraAlerta = UltimaFalha,
    DataHoraSucesso = HoraSucesso,
    UsuarioAlvo = UserPrincipalName,
    TentativasNegadas = QtdNegacoes,
    MetodoAutenticacao = MetodoMFA,
    ResultadoMFA = DetalheMFA,
    IPLogonSucesso = IPSucesso,
    LocalizacaoSucesso = LocalSucesso,
    IPsAtaque = IPsFalha,
    RiscoSessao = iff(isempty(RiscoSessao), "none", tostring(RiscoSessao)),
    IDCorrelacao = IDCorrelacao
| order by DataHoraSucesso desc
```

---

## 3. Untersuchungsmatrix: 5 obligatorische Leitfragen

| Leitfrage | Wo validieren | Zu prüfende Punkte |
|---|---|---|
| **1. Was wurde getan?** | `SigninLogs` / `AuthenticationDetails` | Wie viele MFA-Prompts wurden ausgelöst? Gab es eine Genehmigung nach wiederholten Ablehnungen? |
| **2. Wer hat es getan?** | `IPAddress`, `LocationDetails`, ASN | Stammt die IP aus dem Unternehmensnetz/VPN oder von einem kommerziellen VPN/Rechenzentrum (AWS, Tor)? |
| **3. War die Aktion autorisiert?** | Benutzerprofil | Stimmt die Uhrzeit mit der Arbeitszeit überein? Reist der Benutzer regelmäßig in das Herkunftsland? |
| **4. Gibt es ein Ticket / Kontakt?** | ITSM / Out-of-Band-Kontakt | Kontaktieren Sie den Benutzer über einen **alternativen Kanal** (Telefon oder Teams), um die Anmeldung zu verifizieren. |
| **5. War die Sitzung legitim?** | `AADUserRiskEvents` & `AuditLogs` | Wurden Anomalien wie *Anomalous Token*, *Unfamiliar sign-in* oder neue Geräteregistrierungen gemeldet? |

---

## 4. Untersuchung im Microsoft Entra Admin Center

1. Navigieren Sie zu:
   > **Identity** > **Users** > Betroffenen Benutzer wählen > **Sign-in logs**.
2. Wechseln Sie zum Reiter **Interactive user sign-ins** und prüfen Sie die erfolgreiche Anmeldung nach den Fehlern.
3. Überprüfen Sie unter **Identity Protection** > **Risk detections**, ob korrelierte Risikoereignisse vorliegen.

---

## 5. Validierung mit dem Kontoinhaber

> ⚠️ **Kritischer Hinweis:** **Senden Sie niemals eine E-Mail an das untersuchte Konto**, um die Anmeldung zu erfragen. Ist das Konto kompromittiert, bestätigt der Angreifer die Legitimität. Nutzen Sie Telefon oder direkte Vorgesetzten-Eskalation.

---

## 6. Reaktions- und Eindämmungsverfahren

```
[MFA-Fatigue-Warnung bestätigt]
        │
        ├── 1. Sofort alle aktiven Sitzungen widerrufen:
        │      Microsoft Entra > Users > [Benutzer] > "Revoke sessions"
        │
        ├── 2. Kennwort-Reset erzwingen
        │
        ├── 3. Authentifizierungsmethoden prüfen und bereinigen:
        │      Prüfen, ob neue Telefonnummern oder Authenticator-Apps hinterlegt wurden
        │
        ├── 4. Bösartige IPs in Firewall / Conditional Access blockieren
        │
        └── 5. Forensische KQL-Query für Post-Compromise-Aktivitäten ausführen
```

### KQL-Forensik: Aktionen nach Überwindung des MFA

```kql
let usuarioComprometido = "colaborador@seudominio.com.br";
let inicioIncidente = datetime(2026-11-09T00:00:00Z);
AuditLogs
| where TimeGenerated >= inicioIncidente
| mv-expand Target = TargetResources
| where InitiatedBy.user.userPrincipalName == usuarioComprometido
   or Target.userPrincipalName == usuarioComprometido
| where ActivityDisplayName in (
    "User registered security info",
    "User deleted security info",
    "User registered all required security info",
    "Admin registered security info",
    "Add member to role completed (PIM activation)",
    "Add application",
    "Add service principal credentials"
)
| project 
    DataHora = TimeGenerated,
    Operacao = ActivityDisplayName,
    Ator = tostring(InitiatedBy.user.userPrincipalName),
    Alvo = tostring(Target.userPrincipalName),
    PropriedadesModificadas = Target.modifiedProperties,
    IDCorrelacao = CorrelationId
| order by DataHora asc
```

---

## 7. Nachhaltige Kontrollen zur Ursachenbeseitigung

1. **Number Matching erzwingen:** Stellen Sie sicher, dass der Nummernabgleich im Microsoft Authenticator ausnahmslos aktiviert ist.
2. **Geografischer Kontext:** App-Name und Standortkarte in Push-Benachrichtigungen aktivieren.
3. **Migration zu FIDO2 und Passkeys:** Phishing-resistente FIDO2-Sicherheitsschlüssel (z. B. Yubikey, Windows Hello) binden die Authentifizierung kryptografisch an die legitime Domäne.

