---
title: "Detecção de Password Spraying no Microsoft Security: investigação prática no Entra ID com Sentinel e KQL"
description: "Playbook de Microsoft Security para analistas de SOC investigarem campanhas de Password Spraying no Entra ID usando Microsoft Sentinel e KQL."
date: 2026-11-20
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, password-spraying, kql, soc, dfir]
nivel: Intermediário
draft: false
---

> **TL;DR:** Campanhas de *Password Spraying* testam poucas senhas comuns contra dezenas ou centenas de contas para evitar bloqueios por tentativa excessiva. Este playbook mostra como investigar esse incidente no ecossistema **Microsoft Security** usando o Microsoft Sentinel, consultas KQL em `SigninLogs`, verificação de logins bem-sucedidos pós-ataque e contenção no Entra ID.

---

## 1. O que significa este incidente?

No ecossistema **Microsoft Security**, o Microsoft Sentinel monitora a tabela `SigninLogs` em busca de endereços IP que geram erros de autenticação (como `50126` — usuário ou senha inválidos — e `50053` — *Smart Lockout*) distribuídos por múltiplos `UserPrincipalName` em uma janela curta de tempo.

Diferente da força bruta tradicional contra uma única conta, o *Password Spraying* (`MITRE ATT&CK T1110.003`) distribui as tentativas horizontalmente pelo *tenant*. Segundo o [catálogo de detecções do Microsoft Sentinel no Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) e a [documentação de proteção de senha no Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-combined-policy), o maior risco ocorre quando uma dessas tentativas acerta a senha de uma conta sem MFA ou com autenticação legada habilitada.

### Cenários benignos vs. cenários maliciosos

| Cenário | Indicadores Comuns | Classificação |
|---|---|---|
| **Proxy corporativo / NAT compartilhado** | IP pertencente ao ASN da própria empresa, múltiplas contas errando senhas após expiração ou troca em lote. | Falso Positivo (Benigno) |
| **Aplicação legada com credenciais antigas** | Mesmo `AppDisplayName` e `UserAgent` corporativo tentando autenticar em serviço após rotação de senha. | Falso Positivo (Benigno) |
| **Varredura distribuída (Spray real)** | IP de provedor VPS/VPN comercial ou rede residencial testando 1–2 vezes dezenas de contas distintas com `UserAgent` de script (`python-requests`, `curl`) ou cliente antigo. | Verdadeiro Positivo (T1110.003) |
| **Acerto seguido de sessão ativa** | Mesmo IP do spray apresenta `ResultType == 50126` em várias contas e, minutos depois, `ResultType == 0` para uma delas. | Verdadeiro Positivo Crítico |

---

## 2. Dica de KQL: correlacionando falhas por IP e contas distintas

Ao abrir o incidente no Microsoft Sentinel, a consulta abaixo projeta algumas colunas adicionais da tabela `SigninLogs` para resumir quantas contas únicas foram testadas por cada IP, os códigos de erro retornados e se houve algum logon bem-sucedido na mesma janela.

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

## 3. Roteiro de Investigação: as 5 perguntas obrigatórias

Para classificar o incidente com precisão entre Verdadeiro Positivo (TP) e Falso Positivo (FP), responda às cinco perguntas abaixo:

### 1. O que foi feito?
- Verifique o volume de contas distintas (`DistinctAccounts`) atingidas e os códigos `AADSTS`:
  - `50126`: senha incorreta.
  - `50053`: conta bloqueada pelo *Smart Lockout*.
  - `0`: **atenção máxima** — indica que a senha estava correta (ou que o usuário concluiu o logon).
- Confirme se o ataque mirou endpoints modernos ou protocolos legados (`ClientAppUsed` como IMAP, POP3, SMTP).

### 2. Quem fez?
- Analise o `IPAddress` de origem, seu ASN e reputação em fontes de *Threat Intelligence*.
- IPs de hospedagens em nuvem baratas, nós de saída Tor ou redes residenciais fora da região de operação da empresa reforçam atividade maliciosa.
- Caso o incidente envolva um *Service Principal*, verifique também `AADServicePrincipalSignInLogs` para descartar tentativas contra *client secrets*.

### 3. Poderia ter feito?
- Avalie se a superfície de exposição estava protegida:
  - As contas atingidas possuem MFA resistente a phishing (*Passkey* / FIDO2) ativo?
  - Há políticas de *Conditional Access* bloqueando autenticação legada e exigindo dispositivos gerenciados ou MFA?
  - O *Microsoft Entra Password Protection* (lista de senhas banidas) está ativo no *tenant*?

### 4. Há chamado formal / ticket?
- Em casos de testes autorizados (*Pentest* ou *Red Team* interno), valide obrigatoriamente na ferramenta de **ITSM** (**ServiceNow**, **Jira Service Management**, **Freshservice** ou **Zendesk**).
- Confirme se o IP de origem, a janela de horário e o escopo constam em um ticket aprovado ou em comunicação formal registrada com o time de segurança.

### 5. A sessão foi legítima?
- Para qualquer conta listada em `SuccessfulUsers` (`ResultType == 0`), verifique imediatamente:
  - Se houve desafio de MFA satisfeito (`AuthenticationRequirement == "multiFactorAuthentication"`).
  - Se o Entra ID Protection marcou risco elevado na sessão (`RiskLevelDuringSignIn`).
  - Se o `UserAgent` e a localização geográfica fogem do padrão histórico daquele colaborador.

---

## 4. Onde investigar no portal (Microsoft Entra admin center)

Para inspecionar visualmente os registros e o estado de proteção das contas em `entra.microsoft.com`, acesse:

1. **Logs de entrada detalhados:**
   `Identity > Monitoring & health > Sign-in logs` (filtre pelo `IPAddress` suspeito e por **Status: Failure** ou **Success**).
2. **Usuários e sessões em risco:**
   `Protection > Identity Protection > Risky sign-ins` e `Risky users`.
3. **Configuração de Smart Lockout e senhas banidas:**
   `Protection > Authentication methods > Password protection`.

---

## 5. Mapeamento MITRE ATT&CK e Controles

| Framework | Referência | Descrição |
|---|---|---|
| **MITRE ATT&CK** | `T1110.003` | *Brute Force: Password Spraying* (teste horizontal de senhas comuns). |
| **MITRE ATT&CK** | `T1078.004` | *Valid Accounts: Cloud Accounts* (uso de credencial válida obtida no spray). |
| **NIST CSF** | `PR.AA-03` | Autenticação multifator resistente a phishing e proteção contra adivinhação de senhas. |
| **CIS Controls v8** | `6.3` / `5.2` | Exigência de MFA e política robusta de senhas únicas. |

---

## 6. Procedimento de resposta e contenção

Se houver confirmação de campanha maliciosa — especialmente se `SuccessCount > 0` — execute imediatamente este *playbook*:

1. **Conter contas com logon bem-sucedido:** Para todo usuário em `SuccessfulUsers` vindo do IP do atacante, acesse `Identity > Users > All users`, clique em **Revoke sessions**, force a troca imediata de senha e valide os métodos de MFA registrados (removendo dispositivos desconhecidos).
2. **Bloquear o IP de origem:** Se aplicável na arquitetura do *tenant*, adicione os IPs ofensores em uma *Named Location* bloqueada via *Conditional Access* ou no firewall/WAF de borda.
3. **Bloquear protocolos legados:** Garanta que exista política de *Conditional Access* bloqueando *Legacy Authentication* para evitar *bypass* de MFA.
4. **Auditoria pós-incidente em KQL:** Execute a consulta abaixo para verificar se alguma conta atingida pelo spray apresentou ações suspeitas (ex.: registro de novo método MFA, criação de regra de caixa de entrada ou consentimento OAuth) nas horas seguintes:

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

## Referências

- [Microsoft Learn — Built-in detections in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Microsoft Learn — Password protection in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-combined-policy)
- [MITRE ATT&CK — T1110.003: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
