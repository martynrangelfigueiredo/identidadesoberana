---
title: "Cadastro de novos métodos de MFA no Microsoft Security: guia de investigação com Sentinel e KQL"
description: "Playbook de Microsoft Security para analistas de SOC investigarem registros suspeitos de métodos de MFA no Entra ID usando Microsoft Sentinel e KQL."
date: 2026-11-24
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, mfa, kql, soc, dfir]
nivel: Intermediário
draft: false
---

> **TL;DR:** Quando um atacante obtém credenciais ou um token inicial válido, uma das primeiras ações pós-comprometimento é cadastrar um novo método de MFA (Authenticator App, telefone ou *Passkey*) na conta da vítima para garantir acesso persistente. Este playbook mostra como investigar esse evento no ecossistema **Microsoft Security** com Microsoft Sentinel, KQL (`AuditLogs` e `SigninLogs`), ITSM e contenção no Entra ID.

---

## 1. O que significa este incidente?

No ecossistema **Microsoft Security**, o Microsoft Sentinel monitora a tabela `AuditLogs` em busca de eventos da categoria `UserManagement` relacionados ao registro ou atualização de informações de segurança (*Security Info*), como `User registered security info`, `Admin registered security info` ou `User deleted security info`.

Conforme descrito no [catálogo de detecções do Microsoft Sentinel no Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) e na [documentação de atividade de métodos de autenticação no Entra ID](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity), essa técnica (`MITRE ATT&CK T1098.005` / `T1556.006`) permite que o invasor sobreviva mesmo após uma simples troca de senha caso o método de MFA cadastrado por ele não seja removido.

### Cenários benignos vs. cenários maliciosos

| Cenário | Indicadores Comuns | Classificação |
|---|---|---|
| **Onboarding de colaborador ou troca de aparelho** | Cadastro feito a partir de IP corporativo/VPN conhecido, dispositivo gerenciado (`IsCompliant == true`), horário comercial. | Falso Positivo (Benigno) |
| **Reset assistido pelo Helpdesk (TAP)** | Administrador autorizado emitiu *Temporary Access Pass* com ticket aberto e o usuário registrou nova *Passkey* / FIDO2. | Falso Positivo (Benigno) |
| **Persistência pós-phishing / AitM** | Novo método registrado minutos após logon de IP anômalo (VPS, VPN comercial ou país incomum) sem dispositivo gerenciado. | Verdadeiro Positivo Crítico (T1098.005) |
| **Exclusão de métodos legítimos** | Remoção do autenticador anterior do colaborador logo após inclusão de dispositivo desconhecido. | Verdadeiro Positivo Crítico |

---

## 2. Dica de KQL: detalhando alterações de métodos de segurança na AuditLogs

Ao assumir o incidente no Microsoft Sentinel, a consulta abaixo projeta algumas colunas adicionais da tabela `AuditLogs` para mostrar qual usuário teve o método alterado, quem iniciou a ação, o motivo registrado (`ResultReason`) e os detalhes das propriedades modificadas.

```kql
let Lookback = 7d;
AuditLogs
| where TimeGenerated >= ago(Lookback)
| where OperationName has_any ("security info", "authentication method", "strong authentication")
| mv-expand Target = TargetResources
| mv-expand ModProp = Target.modifiedProperties
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend SourceIP = tostring(InitiatedBy.user.ipAddress)
| extend TargetUser = tostring(Target.userPrincipalName)
| extend PropName = tostring(ModProp.displayName)
| extend NewValue = tostring(ModProp.newValue)
| project
    TimeGenerated,
    OperationName,
    Result,
    ResultReason,
    TargetUser,
    InitiatorUPN,
    SourceIP,
    PropName,
    NewValue,
    CorrelationId
| order by TimeGenerated desc
```

---

## 3. Roteiro de Investigação: as 5 perguntas obrigatórias

Para classificar o incidente com segurança entre Verdadeiro Positivo (TP) e Falso Positivo (FP), responda às cinco perguntas abaixo:

### 1. O que foi feito?
- Verifique `OperationName`, `ResultReason` e `NewValue` na consulta KQL.
- Identifique **qual método** foi adicionado ou removido (ex.: *Microsoft Authenticator App*, *PhoneAppNotification*, *PhoneNumber*, *FIDO2*).
- Atenção especial se houver sequência de `User registered security info` seguida de `User deleted security info`.

### 2. Quem fez?
- Compare `InitiatorUPN` com `TargetUser`:
  - Se forem iguais, o próprio usuário (ou alguém com sua sessão ativa) realizou o cadastro.
  - Se forem diferentes, um administrador de autenticação ou *Service Principal* realizou a ação.
- Cruze `SourceIP` e o horário do evento com `SigninLogs` para checar país, ASN, *User-Agent* e se houve uso anterior de *Temporary Access Pass* ou fluxo `deviceCode`.

### 3. Poderia ter feito?
- Valide se as políticas do *tenant* exigem **Combined Registration** protegido por *Conditional Access*:
  - O registro de informações de segurança (*Register security information*) exige rede confiável, dispositivo compatível ou *Temporary Access Pass*?
  - Se qualquer IP externo puder cadastrar um segundo fator apenas com senha ou token inicial, o risco de *bypass* de proteção é alto.

### 4. Há chamado formal / ticket?
- Em trocas de celular corporativo ou atuação de Helpdesk, valide obrigatoriamente na ferramenta de **ITSM** (**ServiceNow**, **Jira Service Management**, **Freshservice** ou **Zendesk**).
- Também confirme diretamente com o colaborador afetado (via ligação ou canal secundário validado) se ele realmente cadastrou um novo dispositivo naquele horário.

### 5. A sessão foi legítima?
- Verifique no Microsoft Entra ID Protection se a sessão associada ao `SourceIP` apresentou alertas (`Risky sign-ins`, `Unfamiliar sign-in properties` ou *Impossible Travel*).
- Confira `DeviceDetail.isCompliant` e `DeviceDetail.trustType` nos `SigninLogs` da mesma sessão.

---

## 4. Onde investigar no portal (Microsoft Entra admin center)

Para inspecionar visualmente os métodos cadastrados e o histórico em `entra.microsoft.com`:

1. **Métodos de autenticação do usuário:**
   `Identity > Users > All users > [Usuário] > Authentication methods` (revise cada dispositivo, data de cadastro e número de telefone).
2. **Relatório de atividades de registro:**
   `Protection > Authentication methods > Activity` (abas *Registration* e *Usage*).
3. **Auditoria de logs no portal:**
   `Identity > Monitoring & health > Audit logs` (filtre por **Target** = usuário afetado ou **Correlation ID**).

---

## 5. Mapeamento MITRE ATT&CK e Controles

| Framework | Referência | Descrição |
|---|---|---|
| **MITRE ATT&CK** | `T1098.005` | *Account Manipulation: Device Registration* (cadastro de dispositivo/MFA não autorizado para persistência). |
| **MITRE ATT&CK** | `T1556.006` | *Modify Authentication Process: Multi-Factor Authentication* (alteração de fatores de autenticação). |
| **NIST SP 800-63B** | `AAL2` / `AAL3` | Vinculação segura no registro de autenticadores e uso de *Passkeys* / FIDO2 resistentes a phishing. |
| **CIS Controls v8** | `6.3` / `6.5` | Proteção do fluxo de registro de MFA com exigência de rede/dispositivo confiável. |

---

## 6. Procedimento de resposta e contenção

Se o colaborador não reconhecer o cadastro ou a sessão for suspeita, execute imediatamente este *playbook*:

1. **Remover o método de MFA invasor:** Em `Identity > Users > All users > [Usuário] > Authentication methods`, exclua imediatamente o autenticador ou telefone desconhecido.
2. **Revogar sessões e redefinir credenciais:** Clique em **Revoke sessions** no perfil do usuário e execute a troca de senha. Caso o método legítimo do usuário tenha sido excluído, emita um *Temporary Access Pass* de uso único após validação de identidade.
3. **Reforçar Conditional Access:** Configure uma política visando a ação de usuário **Register security information**, exigindo dispositivo compatível ou localização corporativa.
4. **Auditoria pós-incidente em KQL:** Execute a consulta abaixo para verificar todos os logins da conta afetada nas últimas 48 horas e checar se houve criação de *secrets* em aplicativos ou regras de caixa de entrada:

```kql
let IncidentWindow = 48h;
let TargetAccount = "usuario@contoso.com";
SigninLogs
| where TimeGenerated >= ago(IncidentWindow)
| where UserPrincipalName == TargetAccount
| project
    TimeGenerated,
    ResultType,
    AppDisplayName,
    IPAddress,
    Location,
    UserAgent,
    AuthenticationRequirement,
    RiskLevelDuringSignIn,
    CorrelationId
| order by TimeGenerated desc
```

---

## Referências

- [Microsoft Learn — Built-in detections in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Microsoft Learn — Authentication methods activity in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity)
- [MITRE ATT&CK — T1098.005: Device Registration](https://attack.mitre.org/techniques/T1098/005/)
