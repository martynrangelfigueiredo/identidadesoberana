---
title: "Autenticação legada no Microsoft Security: investigação de bypass de MFA com Entra ID e Sentinel"
description: "Playbook de Microsoft Security para analistas de SOC investigarem tentativas e acessos via protocolos legados no Entra ID usando Microsoft Sentinel e KQL."
date: 2026-11-25
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, mfa, kql, soc, dfir]
nivel: Intermediário
draft: false
---

> **TL;DR:** Protocolos antigos como IMAP4, POP3, SMTP AUTH e Exchange ActiveSync não suportam autenticação moderna nem desafios interativos de MFA. Quando habilitados no tenant, tornam-se o caminho preferido para *password spray* e *bypass* de MFA. Este playbook mostra como investigar esses eventos no ecossistema **Microsoft Security** com Microsoft Sentinel, KQL (`SigninLogs` e `OfficeActivity`), ITSM e contenção no Microsoft Entra ID.

---

## 1. O que significa este incidente?

No ecossistema **Microsoft Security**, o Microsoft Sentinel monitora a tabela `SigninLogs` em busca de autenticações realizadas por clientes que não suportam OAuth 2.0 nem autenticação multifator moderna, identificados na propriedade `ClientAppUsed` por valores como `IMAP4`, `POP3`, `Authenticated SMTP`, `Exchange ActiveSync`, `MAPI Over HTTP` ou `Other clients`.

Conforme documentado no [catálogo de detecções padrão do Microsoft Sentinel no Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) e no guia oficial sobre [bloqueio de autenticação legada no Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication), invasores exploram esses endpoints para validar senhas obtidas em vazamentos ou campanhas de *password spray* (`MITRE ATT&CK T1110.003` e `T1078`), muitas vezes sem acionar os mesmos controles de proteção aplicados a navegadores modernos.

### Cenários benignos vs. cenários maliciosos

| Cenário | Indicadores Comuns | Classificação |
|---|---|---|
| **Impressora multifuncional ou scanner corporativo** | Protocolo `Authenticated SMTP` a partir de IP interno/NAT conhecido, conta de serviço dedicada, sem falhas em massa. | Falso Positivo (Benigno — requer migração para OAuth/relay seguro) |
| **Aplicação legada de ERP ou CRM** | Uso recorrente de `IMAP4` ou `POP3` por conta técnica documentada em inventário e com exceção formal em Conditional Access. | Falso Positivo (Benigno — dívida técnica controlada) |
| **Campanha de *password spray* via IMAP/POP3** | Dezenas de falhas (`ResultType` 50126 ou 50053) em múltiplas contas vindas de IPs externos, VPS ou redes residenciais anômalas. | Verdadeiro Positivo (T1110.003) |
| **Acesso bem-sucedido sem MFA (*bypass* de MFA)** | `ResultType == "0"` com `ClientAppUsed` legado e `AuthenticationRequirement == "singleFactorAuthentication"` para usuário comum ou privilegiado. | Verdadeiro Positivo Crítico (T1078) |

---

## 2. Dica de KQL: filtrando protocolos legados e status de MFA na SigninLogs

Ao assumir o incidente no Microsoft Sentinel, a consulta abaixo projeta algumas colunas da tabela `SigninLogs` para destacar o protocolo legado utilizado, o código de resultado (`ResultType`), se houve exigência de MFA e o país/IP de origem.

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

## 3. Roteiro de Investigação: as 5 perguntas obrigatórias

### 1. O que foi feito?
Verifique na `SigninLogs` se a tentativa foi **bloqueada ou bem-sucedida**:
- **`ResultType == "0"`:** O logon foi concluído com sucesso sem desafio de MFA interativo. Trate como comprometimento potencial imediato.
- **`ResultType == "53003"`:** A política de Conditional Access bloqueou o protocolo legado (comportamento esperado de defesa).
- **`ResultType == "50126"`:** Senha inválida (forte indicador de *brute force* ou *password spray* contra protocolo legado).
- **`ResultType == "50053"`:** Conta bloqueada pelo Smart Lockout após múltiplas tentativas.
- Guarde o `CorrelationId` e o `UniqueTokenIdentifier` para rastrear o evento em logs relacionados.

### 2. Quem fez?
Analise o `UserPrincipalName`, o `IPAddress` e o `UserAgent`:
- O usuário afetado possui papéis privilegiados no Entra ID (como `Global Administrator` ou `Exchange Administrator`) ou acesso a caixas financeiras/diretoria?
- O `IPAddress` pertence a um provedor de nuvem (VPS), saída de VPN anônima ou infraestrutura incompatível com o escritório ou provedor habitual do colaborador?
- Houve tentativas simultâneas contra outros usuários do tenant a partir do mesmo IP ou bloco ASN?

### 3. Poderia ter feito?
Avalie por que o protocolo legado estava disponível para aquela conta:
- Existe alguma política de Conditional Access bloqueando `Legacy authentication clients` para todos os usuários, ou a conta estava em um grupo de exceção?
- No Exchange Online, os parâmetros `SmtpClientAuthenticationDisabled`, `ImapEnabled` ou `PopEnabled` ainda estavam ativos para a caixa postal (`CASMailbox`)?

### 4. Há chamado formal/ticket?
Antes de concluir por uso legítimo de integração interna, cruze o `UserPrincipalName` e o `IPAddress` com sua ferramenta de **ITSM** (ServiceNow, Jira Service Management, Freshservice ou Zendesk):
- Há algum ticket ou GMUD aprovada para uma aplicação de scanner, sistema de chamados ou conector legado lendo aquela caixa postal?
- Caso exista exceção aprovada, confirme se a origem coincide exatamente com o IP estático autorizado no chamado.

### 5. A sessão foi legítima?
Mesmo quando o usuário relata que usa cliente de e-mail antigo no celular ou estação, valide:
- O `UserAgent` corresponde ao cliente corporativo homologado (por exemplo, Outlook moderno deveria usar autenticação moderna, não `IMAP4` ou `Other clients`)?
- Existe outro logon moderno recente do mesmo usuário em localização geográfica distante no mesmo intervalo de tempo?

---

## 4. Onde investigar no portal

Para inspecionar políticas, exceções e o histórico completo da conta sem depender apenas do SIEM:

1. **Logs de entrada filtrados por cliente legado no Entra ID:**
   - Acesse o Microsoft Entra admin center (`entra.microsoft.com`).
   - Navegue até: `Identity > Monitoring & health > Sign-in logs`.
   - Adicione o filtro `Client app` selecionando `Exchange ActiveSync`, `IMAP4`, `POP3`, `Authenticated SMTP` e `Other clients`.
2. **Políticas de Conditional Access:**
   - Navegue até: `Protection > Conditional Access > Policies`.
   - Verifique se existe política ativa mirando `All cloud apps` com condição `Client apps = Exchange ActiveSync clients` e `Other clients` configurada com `Grant = Block access`.
3. **Configuração de protocolos por caixa postal no Exchange Online:**
   - Acesse o Exchange admin center (`admin.exchange.microsoft.com`).
   - Navegue até: `Recipients > Mailboxes > [Usuário] > Manage email apps settings` para conferir se POP3, IMAP e Authenticated SMTP estão desabilitados.

---

## 5. Procedimento de Resposta, Contenção e Auditoria Pós-Incidente

Se confirmar um acesso bem-sucedido (`ResultType == "0"`) não autorizado via protocolo legado:

1. **Revogar sessões e redefinir credenciais:**
   - No Microsoft Entra admin center (`Users > [Usuário]`), execute **Revoke sessions** imediatamente e force a troca de senha por uma credencial forte e exclusiva.
2. **Bloquear protocolos legados na conta e no tenant:**
   - Desative `IMAP`, `POP` e `Authenticated SMTP` nas propriedades da caixa postal no Exchange Online e remova o usuário de eventuais grupos de exceção do Conditional Access.
3. **Auditar atividade pós-acesso no Exchange / Microsoft 365:**
   - Execute a consulta abaixo na tabela `OfficeActivity` para verificar se o invasor listou mensagens, criou regras de encaminhamento ou acessou itens após o logon legado.

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

## 6. Mapeamento de Controles e Conformidade

| Framework / Norma | Controle Relacionado | Aplicação Prática |
|---|---|---|
| **MITRE ATT&CK** | `T1078` (Valid Accounts), `T1110.003` (Password Spraying) | Detecção de tentativas e acessos em protocolos sem suporte a MFA. |
| **NIST CSF 2.0** | `PR.AA-03` (Gestão de acessos), `DE.CM-03` (Monitoramento de identidade) | Bloqueio de autenticação legada via Conditional Access e alerta contínuo no Sentinel. |
| **CIS Controls v8** | `6.3` / `6.5` (MFA para aplicações e acesso administrativo) | Eliminação de caminhos de *bypass* de MFA em clientes IMAP/POP3/SMTP. |
| **ISO/IEC 27001:2022** | `A.8.5` (Autenticação segura) | Garantia de autenticação forte consistente em todos os pontos de entrada. |
| **LGPD** | Art. 46 (Medidas técnicas de segurança) | Proteção de caixas postais e dados pessoais contra acesso não autorizado. |
