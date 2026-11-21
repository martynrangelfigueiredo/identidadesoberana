---
title: "Regras suspeitas de caixa de entrada no Microsoft Security: guia de investigação com Sentinel e KQL"
description: "Playbook de Microsoft Security para analistas de SOC investigarem criação de Inbox Rules suspeitas e encaminhamentos externos no Exchange Online com Sentinel e KQL."
date: 2026-11-21
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, exchange-online, kql, soc, dfir]
nivel: Intermediário
draft: false
---

> **TL;DR:** Após obter acesso a uma conta via *phishing* ou *Adversary-in-the-Middle (AitM)*, invasores costumam criar regras na caixa de entrada (*Inbox Rules*) para ocultar respostas de segurança ou encaminhar e-mails para fora do *tenant*. Este playbook mostra como investigar o incidente no ecossistema **Microsoft Security** usando Microsoft Sentinel, KQL (`OfficeActivity` e `SigninLogs`) e contenção no Entra ID.

---

## 1. O que significa este incidente?

No ecossistema **Microsoft Security**, o Microsoft Sentinel monitora a tabela `OfficeActivity` (logs do Exchange Online) em busca de operações `New-InboxRule`, `Set-InboxRule` ou `Enable-InboxRule` contendo condições típicas de ocultação ou exfiltração — como mover mensagens para *RSS Subscriptions*, *Deleted Items*, marcar como lidas automaticamente ou encaminhar (`ForwardTo`, `RedirectTo`) para domínios externos.

Segundo o [catálogo de detecções do Microsoft Sentinel no Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) e a [documentação de auditoria de caixas de correio no Microsoft Purview](https://learn.microsoft.com/en-us/purview/audit-mailboxes), essa técnica (`MITRE ATT&CK T1114.003` e `T1564.008`) é amplamente utilizada em fraudes de *Business Email Compromise (BEC)* para interceptar faturas e esconder alertas enviados à vítima.

### Cenários benignos vs. cenários maliciosos

| Cenário | Indicadores Comuns | Classificação |
|---|---|---|
| **Organização pessoal de newsletters** | Regra criada pelo próprio usuário em IP corporativo/residencial habitual movendo e-mails de notificações para uma pasta interna. | Falso Positivo (Benigno) |
| **Encaminhamento corporativo documentado** | Regra direcionando chamados para caixa compartilhada ou sistema de tickets interno aprovado. | Falso Positivo (Benigno) |
| **Ocultação silenciosa (BEC / AitM)** | Regra com nomes genéricos (`.`, `..`, `a`, `zzz`) que marca como lida (`MarkAsRead: True`) e move mensagens com palavras como *"fatura"*, *"senha"* ou *"alerta"* para *Deleted Items*. | Verdadeiro Positivo (T1564.008) |
| **Exfiltração externa** | Regra configurada com `ForwardTo` ou `RedirectTo` para e-mail gratuito externo logo após logon de IP anômalo. | Verdadeiro Positivo Crítico (T1114.003) |

---

## 2. Dica de KQL: detalhando regras de caixa de entrada na OfficeActivity

Ao assumir o incidente no Microsoft Sentinel, a consulta abaixo projeta algumas colunas adicionais da tabela `OfficeActivity` para expandir os parâmetros da regra criada (`mv-expand`) e exibir o nome da regra, o IP de origem e as ações configuradas.

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

## 3. Roteiro de Investigação: as 5 perguntas obrigatórias

Para classificar o incidente com precisão entre Verdadeiro Positivo (TP) e Falso Positivo (FP), responda às cinco perguntas abaixo:

### 1. O que foi feito?
- Analise os pares `ParamName` e `ParamValue` retornados pela consulta KQL:
  - `MoveToFolder` para *Deleted Items*, *Junk Email* ou *RSS Feeds* / *RSS Subscriptions*.
  - `MarkAsRead = True` ou `DeleteMessage = True`.
  - `ForwardTo`, `ForwardAsAttachmentTo` ou `RedirectTo` apontando para destinatário externo.
  - Palavras-chave suspeitas em `SubjectContainsWords` ou `BodyContainsWords` (ex.: `invoice`, `payment`, `bank`, `security`, `MFA`).

### 2. Quem fez?
- Confirme o `UserId` e o `ClientIP` na `OfficeActivity`.
- Cruze o `ClientIP` com a tabela `SigninLogs` do Entra ID na mesma janela de horário para identificar:
  - ASN, país e provedor do IP (ex.: VPS, proxy residencial ou VPN comercial).
  - *User-Agent* utilizado (sessões web anômalas vs. Outlook desktop corporativo).
  - Se houve alteração recente de *secrets* ou registro de novo dispositivo MFA para a conta.

### 3. Poderia ter feito?
- Qualquer usuário autenticado pode criar *Inbox Rules* na própria caixa postal por padrão, mas **encaminhamentos externos automáticos** deveriam estar bloqueados pelas políticas anti-spam de saída (*Outbound spam filter policy*) no Microsoft Defender for Office 365.
- Caso a regra tenha sido criada por um administrador ou *Service Principal* via PowerShell remoto, valide se havia necessidade operacional.

### 4. Há chamado formal / ticket?
- Se a regra foi criada por suporte de TI ou automação (ex.: redirecionamento de caixa funcional após desligamento), confirme obrigatoriamente na ferramenta de **ITSM** (**ServiceNow**, **Jira Service Management**, **Freshservice** ou **Zendesk**).
- Verifique se o ticket documenta a conta de destino, o solicitante e a aprovação do gestor.

### 5. A sessão foi legítima?
- Verifique nos `SigninLogs` se a sessão que originou o `ClientIP` tinha:
  - MFA resistente a phishing (*Passkey* / FIDO2) ou apenas token de sessão roubado (*session replay* / AitM).
  - Alertas correlatos no Microsoft Entra ID Protection (`Risky sign-ins`, localização atípica ou viagem impossível).

---

## 4. Onde investigar no portal (Microsoft Entra & Defender)

Para confirmar os detalhes visuais no portal:

1. **Sessões e logs de entrada no Entra ID (`entra.microsoft.com`):**
   `Identity > Monitoring & health > Sign-in logs` (filtre pelo `UserId` e `ClientIP` observado na `OfficeActivity`).
2. **Usuários em risco no Entra ID:**
   `Protection > Identity Protection > Risky users`.
3. **Auditoria unificada no Microsoft Purview / Defender (`security.microsoft.com`):**
   `Audit` (pesquise pelas atividades **New-InboxRule** e **Set-InboxRule** para o usuário afetado).

---

## 5. Mapeamento MITRE ATT&CK e Controles

| Framework | Referência | Descrição |
|---|---|---|
| **MITRE ATT&CK** | `T1114.003` | *Email Collection: Email Forwarding Rule* (encaminhamento automático para exfiltração). |
| **MITRE ATT&CK** | `T1564.008` | *Hide Artifacts: Email Hiding Rules* (ocultação de respostas e alertas em pastas). |
| **NIST CSF** | `DE.CM-03` / `RS.MI-02` | Monitoramento de ações em contas de usuário e contenção rápida de exfiltração. |
| **CIS Controls v8** | `9.7` / `8.5` | Controle de encaminhamento de e-mails e coleta detalhada de logs de auditoria. |

---

## 6. Procedimento de resposta e contenção

Confirmada a criação maliciosa da regra, execute imediatamente este *playbook* de contenção:

1. **Revogar sessões ativas no Entra ID:** Em `Identity > Users > All users`, selecione o usuário, clique em **Revoke sessions**, redefina a senha e remova métodos de MFA adicionados recentemente sem reconhecimento do colaborador.
2. **Remover a regra maliciosa:** No Exchange Online PowerShell (`Remove-InboxRule -Identity "<RuleId>" -Mailbox "<UPN>"`) ou no portal do Exchange, exclua a regra suspeita e revise regras de transporte (*Transport Rules*) no *tenant*.
3. **Verificar encaminhamento no nível da caixa postal:** Valide se `ForwardingSmtpAddress` foi preenchido (`Get-Mailbox <UPN> | fl ForwardingSmtpAddress,DeliverToMailboxAndForward`).
4. **Auditoria pós-incidente em KQL:** Execute a consulta abaixo para verificar se o mesmo `ClientIP` acessou outros usuários ou realizou operações sensíveis no Exchange/Entra ID nas últimas 48 horas:

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

## Referências

- [Microsoft Learn — Built-in detections in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Microsoft Learn — Audit mailbox activity in Microsoft Purview](https://learn.microsoft.com/en-us/purview/audit-mailboxes)
- [MITRE ATT&CK — T1114.003: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003/)

