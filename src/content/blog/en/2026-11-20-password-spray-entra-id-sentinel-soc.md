---
title: "Detecting Password Spraying in Microsoft Security: Practical Entra ID Investigation with Sentinel and KQL"
description: "Operational Microsoft Security playbook for SOC analysts to investigate Password Spraying campaigns in Entra ID using Microsoft Sentinel and KQL."
date: 2026-11-20
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, password-spraying, kql, soc, dfir]
nivel: Intermediário
draft: false
---

> **TL;DR:** *Password Spraying* campaigns test a few common passwords across dozens or hundreds of accounts to evade per-account lockout thresholds. This playbook walks through investigating this incident in the **Microsoft Security** ecosystem using Microsoft Sentinel, KQL queries on `SigninLogs`, checking for post-spray successful logins, and containing compromised accounts in Entra ID.

---

## 1. What does this incident mean?

Within the **Microsoft Security** ecosystem, Microsoft Sentinel continuously monitors `SigninLogs` for IP addresses generating authentication failures (such as `50126` — invalid username or password — and `50053` — *Smart Lockout*) distributed across many distinct `UserPrincipalName` values over a short window.

Unlike traditional brute force targeting a single account, *Password Spraying* (`MITRE ATT&CK T1110.003`) spreads attempts horizontally across the *tenant*. According to the [Microsoft Sentinel built-in detections catalog on Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) and the [Microsoft Entra ID password protection documentation](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-combined-policy), the highest risk occurs when an attempt guesses the password of an account without MFA or with legacy authentication enabled.

### Benign vs. malicious scenarios

| Scenario | Common Indicators | Classification |
|---|---|---|
| **Corporate proxy / shared NAT** | IP belongs to your organization's ASN; multiple users mistype passwords after a bulk reset or expiration. | False Positive (Benign) |
| **Legacy application with stale credentials** | Same `AppDisplayName` and known corporate `UserAgent` failing after credential rotation. | False Positive (Benign) |
| **Distributed spray campaign** | VPS, commercial VPN, or residential IP testing dozens of accounts 1–2 times each with script `UserAgent` (`python-requests`, `curl`). | True Positive (T1110.003) |
| **Successful hit followed by active session** | Same IP generates `ResultType == 50126` across many accounts and shortly after achieves `ResultType == 0` on one account. | Critical True Positive |

---

## 2. KQL Tip: Correlating Failures by Source IP and Distinct Accounts

When triaging this incident in Microsoft Sentinel, the query below projects a few additional columns from `SigninLogs` to summarize how many distinct accounts each IP targeted, which error codes were returned, and whether any successful sign-ins occurred in the same window.

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

## 3. Investigation Roadmap: The 5 Mandatory Questions

To classify the incident accurately as a True Positive (TP) or False Positive (FP), answer these five questions:

### 1. What happened?
- Check the count of distinct accounts (`DistinctAccounts`) targeted and the `AADSTS` codes:
  - `50126`: invalid password.
  - `50053`: account locked by *Smart Lockout*.
  - `0`: **top priority** — indicates the password matched.
- Verify whether attempts hit modern endpoints or legacy protocols (`ClientAppUsed` such as IMAP, POP3, SMTP).

### 2. Who did it?
- Inspect the source `IPAddress`, its ASN, and *Threat Intelligence* reputation.
- Low-cost cloud hosters, Tor exit nodes, or residential IPs outside your operating region strongly indicate malicious activity.
- If a *Service Principal* is involved, also inspect `AADServicePrincipalSignInLogs` for attempts against *client secrets*.

### 3. Was the exposure controlled?
- Assess the targeted accounts' defensive posture:
  - Do they enforce phishing-resistant MFA (*Passkey* / FIDO2)?
  - Do *Conditional Access* policies block legacy authentication?
  - Is *Microsoft Entra Password Protection* enabled in the *tenant*?

### 4. Is there a formal ticket?
- For suspected authorized testing (*Pentest* or internal *Red Team*), cross-check your **ITSM** platform (**ServiceNow**, **Jira Service Management**, **Freshservice**, or **Zendesk**).
- Confirm the source IP, time window, and scope match an approved change or security assessment ticket.

### 5. Was the session legitimate?
- For any account listed in `SuccessfulUsers` (`ResultType == 0`), immediately verify:
  - Whether MFA was satisfied (`AuthenticationRequirement == "multiFactorAuthentication"`).
  - Whether Entra ID Protection flagged elevated sign-in risk (`RiskLevelDuringSignIn`).
  - Whether the *UserAgent* and geolocation deviate from the user's historical baseline.

---

## 4. Where to Investigate in the Portal (Microsoft Entra admin center)

To inspect logs and account protection settings in `entra.microsoft.com`:

1. **Detailed sign-in logs:**
   `Identity > Monitoring & health > Sign-in logs` (filter by the suspect `IPAddress` and **Status: Failure / Success**).
2. **Risky sign-ins and users:**
   `Protection > Identity Protection > Risky sign-ins` and `Risky users`.
3. **Smart Lockout and banned passwords:**
   `Protection > Authentication methods > Password protection`.

---

## 5. MITRE ATT&CK and Control Mapping

| Framework | Reference | Description |
|---|---|---|
| **MITRE ATT&CK** | `T1110.003` | *Brute Force: Password Spraying* (horizontal guessing of common passwords). |
| **MITRE ATT&CK** | `T1078.004` | *Valid Accounts: Cloud Accounts* (leveraging a valid credential found during spray). |
| **NIST CSF** | `PR.AA-03` | Phishing-resistant MFA and protection against password guessing. |
| **CIS Controls v8** | `6.3` / `5.2` | Mandatory MFA and strong unique password policies. |

---

## 6. Response and Containment Procedure

If malicious activity is confirmed — especially when `SuccessCount > 0` — execute this *playbook* immediately:

1. **Contain matched accounts:** For every user in `SuccessfulUsers` from the attacker IP, open `Identity > Users > All users`, click **Revoke sessions**, force a password reset, and audit/remove unknown MFA methods.
2. **Block source IPs:** Where appropriate, add offending IPs to a blocked *Named Location* in *Conditional Access* or your perimeter firewall/WAF.
3. **Block legacy protocols:** Ensure a *Conditional Access* policy blocks *Legacy Authentication* to prevent MFA *bypass*.
4. **Post-incident KQL audit:** Run the query below to check whether any suspect IP performed sensitive directory actions in the hours following the spray:

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

## References

- [Microsoft Learn — Built-in detections in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Microsoft Learn — Password protection in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-combined-policy)
- [MITRE ATT&CK — T1110.003: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
