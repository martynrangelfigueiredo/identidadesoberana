---
title: "Autenticação por código de dispositivo no Microsoft Security: guia de investigação com Sentinel e KQL"
description: "Playbook de Microsoft Security para analistas de SOC investigarem Device Code Phishing e uso anômalo do fluxo deviceCode no Entra ID com Sentinel e KQL."
date: 2026-11-23
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, device-code, kql, soc, dfir]
nivel: Avançado
draft: false
---

> **TL;DR:** O fluxo OAuth 2.0 *Device Code* foi projetado para dispositivos sem navegador (TVs, impressoras e CLI), mas invasores o exploram em campanhas de *Device Code Phishing* para obter tokens válidos com MFA já satisfeito pela vítima. Este playbook detalha a triagem no ecossistema **Microsoft Security** com Microsoft Sentinel, consultas KQL em `SigninLogs`, checagem em ITSM e contenção no Entra ID.

---

## 1. O que significa este incidente?

No ecossistema **Microsoft Security**, o Microsoft Sentinel monitora a tabela `SigninLogs` em busca de autenticações com `AuthenticationProtocol == "deviceCode"` vindas de aplicativos inesperados, IPs externos atípicos ou usuários sem histórico de uso de CLI administrativa.

Nesse ataque (`MITRE ATT&CK T1528`), o adversário inicia uma solicitação de código na API do Entra ID (frequentemente se passando pelo Microsoft Graph PowerShell ou Azure CLI), envia o código de 8–9 caracteres à vítima por e-mail ou chat corporativo e a induz a acessar `microsoft.com/devicelogin`. Ao concluir o login e o MFA no navegador, a vítima entrega indiretamente o *access token* e o *refresh token* diretamente para o servidor do atacante.

Conforme descrito no [catálogo de detecções do Microsoft Sentinel no Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) e na [documentação do fluxo Device Authorization no Entra ID](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code), esse mecanismo permite *bypass* prático da proteção de sessão se não houver restrição via *Conditional Access*.

### Cenários benignos vs. cenários maliciosos

| Cenário | Indicadores Comuns | Classificação |
|---|---|---|
| **Administrador usando Azure CLI / PowerShell em terminal** | Usuário de TI/DevOps conhecido, IP corporativo ou VPN da empresa, `AppDisplayName` compatível com ferramenta de gestão. | Falso Positivo (Benigno) |
| **Provisionamento legítimo de sala de reunião / IoT** | Conta de recurso ou dispositivo Teams Rooms em rede interna dedicada. | Falso Positivo (Benigno) |
| **Device Code Phishing** | Usuário de área não técnica (Financeiro, RH, Diretoria) autenticando no `Microsoft Azure CLI` ou `Microsoft Graph PowerShell` com IP de origem em VPS/VPN comercial. | Verdadeiro Positivo Crítico (T1528) |
| **Token Replay em múltiplas contas** | Mesmo `IPAddress` externo recebendo sessões `deviceCode` bem-sucedidas de vários colaboradores na mesma campanha. | Verdadeiro Positivo Crítico |

---

## 2. Dica de KQL: identificando fluxos deviceCode na SigninLogs

Ao abrir o incidente no Microsoft Sentinel, a consulta abaixo projeta algumas colunas adicionais da tabela `SigninLogs` para destacar o aplicativo usado, o protocolo de autenticação, o *User-Agent* e o status de dispositivo gerenciado, facilitando a separação entre uso legítimo de CLI e *phishing*.

```kql
let Lookback = 7d;
SigninLogs
| where TimeGenerated >= ago(Lookback)
| where AuthenticationProtocol == "deviceCode" or ClientAppUsed == "Mobile Apps and Desktop clients"
| where AuthenticationProtocol == "deviceCode"
| extend DeviceTrust = tostring(DeviceDetail.trustType)
| extend IsCompliant = tostring(DeviceDetail.isCompliant)
| project
    TimeGenerated,
    UserPrincipalName,
    ResultType,
    AppDisplayName,
    ResourceDisplayName,
    IPAddress,
    Location,
    UserAgent,
    DeviceTrust,
    IsCompliant,
    RiskLevelDuringSignIn,
    CorrelationId
| order by TimeGenerated desc
```

---

## 3. Roteiro de Investigação: as 5 perguntas obrigatórias

Para classificar o incidente com precisão entre Verdadeiro Positivo (TP) e Falso Positivo (FP), responda às cinco perguntas abaixo:

### 1. O que foi feito?
- Verifique `ResultType` (`0` indica que o usuário inseriu o código e concluiu o logon; `50140` ou `70016` podem indicar tentativa interrompida ou expirada).
- Analise `AppDisplayName` e `ResourceDisplayName`: ataques comuns solicitam acesso ao `Microsoft Graph` usando IDs públicos como `Microsoft Azure CLI` ou `Microsoft Office`.

### 2. Quem fez?
- Avalie o perfil do `UserPrincipalName`: um analista de finanças ou vendas raramente precisa autenticar no `Azure CLI` via `deviceCode`.
- Analise o `IPAddress` de origem (o IP que **recebeu** o token no fluxo `deviceCode` é o do solicitante/atacante, que pode divergir completamente do IP habitual da vítima!).
- Verifique o `UserAgent` nos `SigninLogs`: clientes Python/Go/cURL em Linux ou máquinas fora do padrão corporativo reforçam o alerta.

### 3. Poderia ter feito?
- Confirme se o *tenant* possui política de *Conditional Access* bloqueando o fluxo *Device code flow* (`Grant / Authentication flows > Device code flow`) para usuários comuns.
- Verifique se o acesso exigia dispositivo compatível (`IsCompliant == "true"`) ou híbrido (`DeviceTrust`).

### 4. Há chamado formal / ticket?
- Em casos de automação ou suporte remoto usando CLI, valide obrigatoriamente na ferramenta de **ITSM** (**ServiceNow**, **Jira Service Management**, **Freshservice** ou **Zendesk**).
- Confirme também diretamente com o usuário afetado (por canal alternativo seguro, nunca pelo mesmo e-mail suspeito) se ele inseriu um código em `microsoft.com/devicelogin`.

### 5. A sessão foi legítima?
- Verifique no Microsoft Entra ID Protection se houve alertas paralelos (`Risky sign-ins`, `Unfamiliar sign-in properties` ou *Impossible Travel* entre o IP habitual do usuário e o `IPAddress` do fluxo `deviceCode`).
- Caso o usuário afirme ter recebido um pedido de código via Teams/E-mail de um remetente externo ou colega comprometido, trate imediatamente como **Verdadeiro Positivo**.

---

## 4. Onde investigar no portal (Microsoft Entra admin center)

Para validar o evento visualmente em `entra.microsoft.com`, siga estes caminhos:

1. **Inspecionar o logon por Device Code:**
   `Identity > Monitoring & health > Sign-in logs` (adicione o filtro **Authentication protocol: Device code** ou filtre pelo **Correlation ID**).
2. **Revisar políticas de fluxo de autenticação:**
   `Protection > Conditional Access > Policies` (confira se existe regra bloqueando *Authentication flows: Device code flow*).
3. **Sessões e usuários em risco:**
   `Protection > Identity Protection > Risky users`.

---

## 5. Mapeamento MITRE ATT&CK e Controles

| Framework | Referência | Descrição |
|---|---|---|
| **MITRE ATT&CK** | `T1528` | *Steal Application Access Token* (obtenção fraudulenta de tokens OAuth via *Device Code Phishing*). |
| **MITRE ATT&CK** | `T1566.002` | *Phishing: Spearphishing Link* (envio de link/código para `devicelogin`). |
| **NIST CSF** | `PR.AA-03` / `PR.AA-05` | Restrição de fluxos legados/especiais de autenticação via *Conditional Access*. |
| **CIS Controls v8** | `6.5` / `6.3` | Exigência de dispositivos gerenciados e MFA resistente a phishing em acessos administrativos. |

---

## 6. Procedimento de resposta e contenção

Confirmado o *Device Code Phishing*, execute imediatamente este *playbook* de contenção:

1. **Revogar sessões e tokens imediatamente:** Em `Identity > Users > All users`, selecione o usuário afetado e clique em **Revoke sessions** (isso invalida o *refresh token* obtido pelo atacante).
2. **Bloquear Device Code Flow via Conditional Access:** Crie ou ative uma política em `Protection > Conditional Access > Policies` bloqueando `Authentication flows > Device code flow` para todos os usuários, liberando apenas exceções estritamente documentadas em grupo específico de TI.
3. **Auditar atividades pós-token em KQL:** Como o atacante recebe acesso ao Microsoft Graph / Exchange, execute a consulta abaixo para verificar ações realizadas pelo usuário afetado após o horário do `deviceCode` (como criação de regras de caixa de entrada, download de arquivos no SharePoint/OneDrive ou alteração de *secrets*):

```kql
let IncidentWindow = 24h;
let DeviceCodeUsers = SigninLogs
    | where TimeGenerated >= ago(IncidentWindow)
    | where AuthenticationProtocol == "deviceCode" and ResultType == 0
    | distinct UserPrincipalName;
AuditLogs
| where TimeGenerated >= ago(IncidentWindow)
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| where Actor in (DeviceCodeUsers)
| project
    TimeGenerated,
    OperationName,
    Category,
    Result,
    Actor,
    SourceIP = tostring(InitiatedBy.user.ipAddress),
    CorrelationId
| order by TimeGenerated desc
```

---

## Referências

- [Microsoft Learn — Built-in detections in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Microsoft Learn — Microsoft identity platform and the OAuth 2.0 device authorization grant flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code)
- [MITRE ATT&CK — T1528: Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)

