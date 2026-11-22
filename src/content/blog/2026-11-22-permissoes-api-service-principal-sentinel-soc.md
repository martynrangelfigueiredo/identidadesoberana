---
title: "Concessão de permissões a Service Principals no Microsoft Security: guia de investigação com Sentinel e KQL"
description: "Playbook de Microsoft Security para analistas de SOC investigarem concessões de App Roles e permissões Graph API a Service Principals com Sentinel e KQL."
date: 2026-11-22
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, service-principal, kql, soc, dfir]
nivel: Avançado
draft: false
---

> **TL;DR:** Atribuir permissões de aplicação (*Application Permissions*, como `Mail.Read` ou `RoleManagement.ReadWrite.Directory`) a um *Service Principal* concede acesso amplo ao *tenant* sem interação de usuário ou MFA. Este playbook detalha a investigação no ecossistema **Microsoft Security** usando Microsoft Sentinel, KQL (`AuditLogs` e `AADServicePrincipalSignInLogs`), checagem em ITSM e contenção no Entra ID.

---

## 1. O que significa este incidente?

No ecossistema **Microsoft Security**, o Microsoft Sentinel monitora a tabela `AuditLogs` para detectar quando uma permissão privilegiada de API (*App Role Assignment*) é concedida a um *Service Principal* (`Add app role assignment to service principal`). Diferente de permissões delegadas (que atuam em nome de um usuário autenticado), permissões de **aplicação** permitem leitura ou modificação direta de dados corporativos no Microsoft Graph, Exchange ou Entra ID de forma autônoma.

Conforme documentado no [catálogo de detecções do Microsoft Sentinel no Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) e na [referência de permissões do Microsoft Graph](https://learn.microsoft.com/en-us/graph/permissions-reference), invasores que comprometem um administrador ou uma identidade de automação utilizam essa técnica (`MITRE ATT&CK T1098.003`) para garantir persistência silenciosa e *bypass* de controles baseados em sessão humana.

### Cenários benignos vs. cenários maliciosos

| Cenário | Indicadores Comuns | Classificação |
|---|---|---|
| **Implantação planejada de integração SaaS / SIEM** | Administrador de nuvem conhecido, ticket de mudança aprovado, permissões restritas (ex.: `SecurityEvents.Read.All`). | Falso Positivo (Benigno) |
| **Pipeline de CI/CD autorizado** | Concessão realizada por *Service Principal* de automação conhecido em janela de deploy. | Falso Positivo (Benigno) |
| **Escalonamento silencioso pós-comprometimento** | Permissão crítica (`RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `Mail.ReadWrite`) concedida a aplicativo recém-criado ou obscuro. | Verdadeiro Positivo Crítico (T1098.003) |
| **Backdoor em aplicação existente** | Administrador comprometido adiciona permissão de leitura de e-mails ou arquivos em um aplicativo antigo já aprovado pelos usuários. | Verdadeiro Positivo (T1098 / T1114) |

---

## 2. Dica de KQL: detalhando concessões de App Role na AuditLogs

Ao abrir o incidente no Microsoft Sentinel, a consulta abaixo projeta algumas colunas adicionais da tabela `AuditLogs` expandindo `TargetResources` e `modifiedProperties` para exibir rapidamente qual *Service Principal* recebeu a permissão, qual recurso alvo foi autorizado e quem aprovou o consentimento.

```kql
let Lookback = 7d;
AuditLogs
| where TimeGenerated >= ago(Lookback)
| where OperationName has_any ("Add app role assignment to service principal", "Add app role assignment grant to user", "Consent to application")
| mv-expand Target = TargetResources
| mv-expand ModProp = Target.modifiedProperties
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatorApp = tostring(InitiatedBy.app.displayName)
| extend SourceIP = tostring(InitiatedBy.user.ipAddress)
| extend TargetName = tostring(Target.displayName)
| extend PropName = tostring(ModProp.displayName)
| extend NewValue = tostring(ModProp.newValue)
| project
    TimeGenerated,
    OperationName,
    Result,
    TargetName,
    Initiator = coalesce(InitiatorUPN, InitiatorApp),
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
- Verifique `OperationName`, `TargetName` e `NewValue` na saída KQL.
- Identifique exatamente **qual permissão (`AppRole`)** foi concedida e em qual API (`Microsoft Graph`, `Office 365 Exchange Online`, `Windows Azure Active Directory`).
- Permissões como `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All` e `Mail.Read` exigem atenção imediata.

### 2. Quem fez?
- Analise `InitiatorUPN` (usuário humano) ou `InitiatorApp` (*Service Principal*).
- Caso seja um usuário, inspecione os `SigninLogs` no horário do evento para verificar `SourceIP`, geolocalização e se houve satisfação de MFA resistente a phishing (*Passkey* / FIDO2).
- Verifique também se o mesmo ator criou recentemente *client secrets* ou certificados no aplicativo.

### 3. Poderia ter feito?
- Apenas papéis altamente privilegiados podem conceder *Admin Consent* para permissões de aplicação no *tenant*:
  - **Global Administrator**
  - **Privileged Role Administrator**
  - **Cloud Application Administrator** ou **Application Administrator** (para permissões não privilegiadas ou conforme política)
- Se o papel for gerenciado via PIM (*Privileged Identity Management*), confirme se houve ativação prévia documentada.

### 4. Há chamado formal / ticket?
- Cruze obrigatoriamente com a plataforma de **ITSM** (**ServiceNow**, **Jira Service Management**, **Freshservice** ou **Zendesk**).
- Valide se existe uma solicitação formal aprovada pela área de Segurança/IAM justificando o princípio do menor privilégio para aquela permissão específica.

### 5. A sessão foi legítima?
- Confira no Microsoft Entra ID Protection se a sessão do `InitiatorUPN` apresentava risco (`RiskLevelDuringSignIn`) ou anomalias de *User-Agent* (scripts CLI fora de servidores autorizados).
- Avalie se o aplicativo receptor pertence a um fornecedor homologado (verificando o `Publisher` e o *Tenant ID* de origem em aplicativos *multi-tenant*).

---

## 4. Onde investigar no portal (Microsoft Entra admin center)

Para validar visualmente as permissões atribuídas em `entra.microsoft.com`:

1. **Inspecionar permissões do aplicativo:**
   `Identity > Applications > Enterprise applications > All applications` (pesquise pelo `TargetName` e abra **Security > Permissions**).
2. **Revisar proprietários e credenciais do registro:**
   `Identity > Applications > App registrations` (verifique **Certificates & secrets** e **Owners**).
3. **Auditoria completa no portal:**
   `Identity > Monitoring & health > Audit logs` (filtre por **Correlation ID**).

---

## 5. Mapeamento MITRE ATT&CK e Controles

| Framework | Referência | Descrição |
|---|---|---|
| **MITRE ATT&CK** | `T1098.003` | *Account Manipulation: Additional Cloud Roles* (atribuição de permissões privilegiadas a identidades de carga de trabalho). |
| **MITRE ATT&CK** | `T1550.001` | *Use Alternate Authentication Material: Application Access Token* (uso de tokens de aplicativo para acesso persistente). |
| **NIST CSF** | `PR.AA-05` | Revisão contínua de permissões atribuídas a identidades humanas e não humanas. |
| **CIS Controls v8** | `6.8` | Gestão rigorosa de contas de serviço e *Service Principals* com menor privilégio. |

---

## 6. Procedimento de resposta e contenção

Se a concessão **não** tiver aprovação formal ou indicar comprometimento, execute imediatamente este *playbook*:

1. **Remover a permissão imediatamente:** Em `Enterprise applications > [App] > Security > Permissions`, revogue a permissão concedida indevidamente (ou desative o login do aplicativo em **Properties > Enabled for users to sign-in? = No** se o app inteiro for malicioso).
2. **Revogar sessões do administrador iniciador:** Em `Identity > Users > All users`, selecione `InitiatorUPN`, clique em **Revoke sessions**, redefina a senha e audite métodos de MFA.
3. **Rotacionar ou remover secrets:** Em `App registrations > Certificates & secrets`, remova *client secrets* ou certificados suspeitos adicionados recentemente.
4. **Auditoria pós-incidente em KQL:** Execute a consulta abaixo na tabela `AADServicePrincipalSignInLogs` para verificar se o *Service Principal* já utilizou o acesso recém-concedido para autenticar a partir de IPs externos:

```kql
let IncidentWindow = 48h;
AADServicePrincipalSignInLogs
| where TimeGenerated >= ago(IncidentWindow)
| project
    TimeGenerated,
    ServicePrincipalName,
    ServicePrincipalId,
    AppId,
    IPAddress,
    ResourceDisplayName,
    ResultType,
    CorrelationId
| order by TimeGenerated desc
```

---

## Referências

- [Microsoft Learn — Built-in detections in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Microsoft Learn — Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [MITRE ATT&CK — T1098.003: Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/)

