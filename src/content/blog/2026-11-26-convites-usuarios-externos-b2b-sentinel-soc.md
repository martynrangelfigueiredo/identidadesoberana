---
title: "Convites de usuários externos (B2B) no Microsoft Security: investigação com Entra ID e Sentinel"
description: "Playbook de Microsoft Security para analistas de SOC investigarem convites suspeitos de usuários externos B2B no Entra ID usando Microsoft Sentinel e KQL."
date: 2026-11-26
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, b2b, iam, kql, soc, dfir]
nivel: Intermediário
draft: false
---

> **TL;DR:** A colaboração B2B no Microsoft Entra ID facilita o trabalho com parceiros, mas convites não autorizados para contas pessoais (`gmail.com`, `outlook.com`) ou a atribuição posterior de papéis administrativos a usuários `#EXT#` criam rotas silenciosas de persistência entre tenants. Este playbook mostra como investigar esses eventos no ecossistema **Microsoft Security** com Microsoft Sentinel, KQL (`AuditLogs` e `SigninLogs`), ITSM e contenção no Entra ID.

---

## 1. O que significa este incidente?

No ecossistema **Microsoft Security**, o Microsoft Sentinel monitora a tabela `AuditLogs` em busca de eventos de criação, resgate e elevação de contas convidadas (*B2B Guest*), como `Invite external user`, `Redeem external user invite`, `Add user` com sufixo `#EXT#` e alterações subsequentes de grupo ou papel administrativo.

Conforme descrito no [catálogo de detecções padrão do Microsoft Sentinel no Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) e na [documentação oficial de colaboração B2B do Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/external-id/b2b-quickstart-add-guest-users-portal), invasores que comprometem uma conta interna com permissão de convite (`Guest Inviter`) podem convidar uma conta externa sob seu controle (`MITRE ATT&CK T1136.003` / `T1098`) para manter acesso mesmo após redefinição da senha original.

### Cenários benignos vs. cenários maliciosos

| Cenário | Indicadores Comuns | Classificação |
|---|---|---|
| **Colaboração em projeto com parceiro homologado** | Domínio corporativo conhecido (`parceiro.com.br`), convite feito por gestor de área, acesso restrito a um canal do Teams ou pasta do SharePoint. | Falso Positivo (Benigno) |
| **Consultoria temporária com ticket aprovado** | Convite emitido por IAM/Helpdesk com GMUD registrada e política de revisão de acesso configurada. | Falso Positivo (Benigno) |
| **Convite para domínio gratuito (`gmail.com` / `proton.me`)** | Conta interna sem perfil de atendimento convida e-mail pessoal fora do expediente ou logo após logon suspeito. | Verdadeiro Positivo (Investigar imediatamente) |
| **Convidado `#EXT#` adicionado a papel ou grupo privilegiado** | Usuário externo recém-convidado recebe papel do Entra ID, Azure RBAC (`Contributor`/`Owner`) ou entra em grupo com acesso a aplicações críticas. | Verdadeiro Positivo Crítico (`T1098`) |

---

## 2. Dica de KQL: rastreando convites externos e atribuições na AuditLogs

Ao assumir o incidente no Microsoft Sentinel, a consulta abaixo projeta algumas colunas da tabela `AuditLogs` para mostrar quem enviou o convite, o endereço externo convidado, o resultado da operação e o `CorrelationId` para rastreamento.

```kql
let Lookback = 7d;
AuditLogs
| where TimeGenerated >= ago(Lookback)
| where OperationName in ("Invite external user", "Redeem external user invite", "Bulk invite users")
| mv-expand Target = TargetResources
| mv-expand ModProp = Target.modifiedProperties
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend SourceIP = tostring(InitiatedBy.user.ipAddress)
| extend GuestUPN = tostring(Target.userPrincipalName)
| extend PropName = tostring(ModProp.displayName)
| extend NewValue = tostring(ModProp.newValue)
| project
    TimeGenerated,
    OperationName,
    Result,
    ResultReason,
    InitiatorUPN,
    SourceIP,
    GuestUPN,
    PropName,
    NewValue,
    CorrelationId
| order by TimeGenerated desc
```

---

## 3. Roteiro de Investigação: as 5 perguntas obrigatórias

### 1. O que foi feito?
Verifique na `AuditLogs` toda a cadeia do ciclo de vida do convidado:
- O convite foi apenas enviado (`Invite external user`) ou já foi resgatado (`Redeem external user invite`)?
- Logo após o convite, houve eventos como `Add member to group` ou `Add member to role` tendo o mesmo usuário `#EXT#` como alvo?
- Salve o `CorrelationId` e o `GuestUPN` para cruzar com os logs de acesso.

### 2. Quem fez?
Analise `InitiatorUPN` e `SourceIP` na `AuditLogs` e consulte os eventos recentes da conta iniciadora na `SigninLogs`:
- O colaborador que enviou o convite atua em compras, jurídico, TI ou projetos com fornecedores externos?
- A sessão de origem do convite veio de dispositivo gerenciado (`IsCompliant == true`) e IP corporativo habitual, ou ocorreu minutos após uma anomalia de localização/MFA?

### 3. Poderia ter feito?
Avalie as configurações de governança B2B do tenant:
- Nas configurações de colaboração externa do Entra ID, qualquer usuário comum (`Member`) tem permissão para convidar convidados, ou apenas quem possui o papel `Guest Inviter` / `User Administrator`?
- Existe lista de permissão (*Allow list*) ou bloqueio (*Deny list*) para domínios de e-mail gratuitos?

### 4. Há chamado formal/ticket?
Cruze o `InitiatorUPN` e o domínio convidado com a plataforma de **ITSM** (ServiceNow, Jira Service Management, Freshservice ou Zendesk):
- Existe solicitação formal de onboarding de fornecedor ou terceiro vinculada a um contrato vigente?
- Em caso de acesso a recursos Azure ou grupos privilegiados, há aprovação documentada em GMUD?

### 5. A sessão foi legítima?
Valide tanto a sessão de quem convidou quanto o primeiro logon do convidado:
- Se o convidado já resgatou o convite, o acesso dele respeitou o Conditional Access para usuários externos (por exemplo, exigência de MFA no tenant de recurso)?
- O convidado acessou apenas o recurso compartilhado ou enumerou diretórios, usuários e aplicações internas?

---

## 4. Onde investigar no portal

Para revisar as configurações B2B e o histórico do convidado diretamente no Microsoft Entra admin center (`entra.microsoft.com`):

1. **Inspecionar o usuário convidado:**
   - Navegue até: `Identity > Users > All users`.
   - Filtre por `User type == Guest` e abra o perfil do usuário para verificar `Creation type` (`Invitation`), `External user state` (`Accepted` ou `PendingAcceptance`), grupos e atribuições de aplicativos.
2. **Revisar políticas de colaboração externa:**
   - Navegue até: `Identity > External Identities > External collaboration settings`.
   - Verifique **Guest user access** (se convidados têm acesso restrito apenas às propriedades próprias) e **Guest invite settings** (quem pode convidar) e **Collaboration restrictions** (domínios bloqueados ou permitidos).
3. **Auditar acessos de convidados:**
   - Navegue até: `Identity > Monitoring & health > Sign-in logs` e filtre por `User` contendo `#EXT#`.

---

## 5. Procedimento de Resposta, Contenção e Auditoria Pós-Incidente

Se o convite ou a elevação de privilégios do usuário externo for confirmada como não autorizada:

1. **Bloquear e remover a conta convidada:**
   - No Entra ID (`Users > [Usuário #EXT#]`), execute **Revoke sessions**, bloqueie o logon (`Account enabled = No`) e remova-o de todos os grupos/papéis antes de excluir a conta.
2. **Conter a conta interna que emitiu o convite:**
   - Caso haja indício de comprometimento do iniciador (`InitiatorUPN`), execute **Revoke sessions**, redefina a senha e audite métodos de MFA cadastrados.
3. **Auditar todos os acessos recentes de contas `#EXT#`:**
   - Execute a consulta abaixo na `SigninLogs` para identificar quais aplicações usuários externos acessaram nos últimos 7 dias e se políticas de Conditional Access foram aplicadas.

```kql
let Lookback = 7d;
SigninLogs
| where TimeGenerated >= ago(Lookback)
| where UserType == "Guest" or UserPrincipalName contains "#EXT#"
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend City = tostring(LocationDetails.city)
| project
    TimeGenerated,
    UserPrincipalName,
    AppDisplayName,
    ResourceDisplayName,
    ResultType,
    ResultDescription,
    ConditionalAccessStatus,
    AuthenticationRequirement,
    IPAddress,
    Country,
    City,
    CorrelationId
| order by TimeGenerated desc
```

---

## 6. Mapeamento de Controles e Conformidade

| Framework / Norma | Controle Relacionado | Aplicação Prática |
|---|---|---|
| **MITRE ATT&CK** | `T1136.003` (Cloud Account), `T1098` (Account Manipulation) | Detecção de criação e elevação de contas externas para persistência. |
| **NIST CSF 2.0** | `PR.AA-01` (Gestão de identidades), `PR.AA-05` (Menor privilégio) | Restrição de quem pode convidar usuários B2B e revisão periódica de acessos. |
| **CIS Controls v8** | `5.3` / `6.8` (Contas inativas e RBAC) | Remoção de convidados expirados e bloqueio de domínios não corporativos. |
| **ISO/IEC 27001:2022** | `A.5.18` (Direitos de acesso), `A.5.19` (Segurança com fornecedores) | Governança formal de identidades de terceiros no tenant. |
| **LGPD** | Art. 46 (Medidas de segurança) | Prevenção contra acesso externo indevido a repositórios com dados pessoais. |

