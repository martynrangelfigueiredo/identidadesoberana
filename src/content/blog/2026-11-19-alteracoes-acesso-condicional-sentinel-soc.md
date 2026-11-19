---
title: "Alterações em políticas de Conditional Access no Microsoft Security: guia de investigação com Sentinel e KQL"
description: "Playbook operacional de Microsoft Security para analistas de SOC investigarem alterações ou desativações de Conditional Access no Entra ID com Sentinel e KQL."
date: 2026-11-19
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, conditional-access, kql, soc, dfir]
nivel: Intermediário
draft: false
---

> **TL;DR:** Alterações não planejadas em políticas de *Conditional Access* (Acesso Condicional) podem abrir brechas silenciosas para *bypass* de MFA ou acesso irrestrito a aplicativos críticos. Este playbook detalha a triagem de incidentes no Microsoft Sentinel, consultas KQL para `AuditLogs` e `SigninLogs`, validação em ITSM e passos de contenção no Entra ID.

---

## 1. O que significa este incidente?

No ecossistema **Microsoft Security**, o Microsoft Sentinel monitora continuamente eventos administrativos registrados na tabela `AuditLogs` do Microsoft Entra ID. Quando uma política de *Conditional Access* é modificada, colocada em modo *Report-only*, desabilitada (*Off*) ou excluída — ou quando uma nova exceção (usuário, grupo ou *Named Location*) é adicionada —, uma *analytics rule* padrão dispara um incidente de alta prioridade.

A documentação oficial do [catálogo de detecções do Microsoft Sentinel no Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) e da [visão geral do Conditional Access no Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview) destaca que alterações nessa camada afetam diretamente a postura de Zero Trust do *tenant*.

### Cenários benignos vs. cenários maliciosos

| Cenário | Indicadores Comuns | Classificação |
|---|---|---|
| **Janela de manutenção / GMUD aprovada** | Administrador conhecido, ticket aberto no ITSM, política ajustada em horário comercial, sessão com MFA resistente a phishing. | Falso Positivo (Benigno) |
| **Automação via Infrastructure as Code (IaC)** | Alteração executada por *Service Principal* autorizado (ex.: pipeline de Terraform/Bicep) a partir de IP corporativo ou runner conhecido. | Falso Positivo (Benigno) |
| **Exclusão silenciosa pós-comprometimento** | Atacante com credencial privilegiada inclui uma conta de *backdoor* na lista de *Exclude* ou desativa a exigência de MFA. | Verdadeiro Positivo (T1562.001) |
| **Adição de Named Location maliciosa** | Inclusão de bloco IP externo desconhecido como local confiável (*Trusted Location*) para facilitar *bypass* de controles. | Verdadeiro Positivo (T1562 / T1098) |

---

## 2. Dica de KQL: contextualizando alterações de Conditional Access

Ao abrir um incidente desse tipo no Microsoft Sentinel, a consulta abaixo traz algumas colunas adicionais úteis da tabela `AuditLogs` para contextualizar rapidamente qual política foi alterada, qual operação ocorreu e quem iniciou a ação, evitando a navegação manual em JSONs extensos.

```kql
let Lookback = 7d;
AuditLogs
| where TimeGenerated >= ago(Lookback)
| where Category == "Policy"
| where OperationName has_any ("Add conditional access policy", "Update conditional access policy", "Delete conditional access policy", "Add policy", "Update policy", "Delete policy")
| mv-expand Target = TargetResources
| mv-expand ModProp = Target.modifiedProperties
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatorApp = tostring(InitiatedBy.app.displayName)
| extend SourceIP = tostring(InitiatedBy.user.ipAddress)
| extend PolicyName = tostring(Target.displayName)
| extend PropertyName = tostring(ModProp.displayName)
| extend OldValue = tostring(ModProp.oldValue)
| extend NewValue = tostring(ModProp.newValue)
| project
    TimeGenerated,
    OperationName,
    Result,
    PolicyName,
    Initiator = coalesce(InitiatorUPN, InitiatorApp),
    SourceIP,
    PropertyName,
    OldValue,
    NewValue,
    CorrelationId
| order by TimeGenerated desc
```

---

## 3. Roteiro de Investigação: as 5 perguntas obrigatórias

Para classificar o incidente com segurança como Verdadeiro Positivo (TP) ou Falso Positivo (FP), responda às cinco perguntas abaixo:

### 1. O que foi feito?
- Verifique o campo `OperationName` e os valores `OldValue` e `NewValue` na consulta KQL.
- **Pontos críticos de atenção:**
  - A política mudou de `enabled` para `disabled` ou `enabledForReportingButNotEnforced` (*Report-only*)?
  - Houve adição de contas ou grupos no bloco `excludeUsers` / `excludeGroups`?
  - Um novo intervalo IP foi marcado como `isTrusted: true` em *Named Locations*?
- Guarde o `CorrelationId` para rastrear ações correlatas na mesma sessão administrativa.

### 2. Quem fez?
- Analise `InitiatorUPN` (usuário humano) ou `InitiatorApp` (*Service Principal*).
- Caso seja um usuário, consulte os `SigninLogs` próximos ao horário do evento para verificar:
  - Endereço IP (`SourceIP`) e geolocalização/ASN.
  - Se a sessão utilizou MFA resistente a phishing (*Passkey* / FIDO2) ou métodos mais fracos.
  - Se houve alteração recente de *secrets* ou métodos de autenticação desse operador.

### 3. Poderia ter feito?
- Nem todo usuário deveria conseguir alterar políticas de *Conditional Access*. Confirme se o autor possui um dos papéis autorizados no Entra ID:
  - **Conditional Access Administrator**
  - **Security Administrator**
  - **Global Administrator**
- Caso o papel seja gerenciado via PIM (*Privileged Identity Management*), valide se houve ativação prévia com justificativa válida.

### 4. Há chamado formal / ticket de mudança?
- Realize o cruzamento obrigatório com a ferramenta de **ITSM** da organização (**ServiceNow**, **Jira Service Management**, **Freshservice** ou **Zendesk**).
- Confirme se existe uma **GMUD** aprovada descrevendo exatamente a política alterada, o escopo e a janela de execução.
- Verifique se o campo `ResultReason` ou a justificativa de ativação no PIM referencia o número do ticket.

### 5. A sessão foi legítima?
- Verifique no Microsoft Entra ID Protection se o usuário ou a sessão apresentava nível de risco (`RiskLevelDuringSignIn` ou `RiskState`) elevado.
- Avalie o *User-Agent* nos `SigninLogs`: scripts automatizados (`python-requests`, `curl`, `PowerShell`) originados fora de servidores de automação ou IPs residenciais/VPNs comerciais são fortes indícios de comprometimento.

---

## 4. Onde investigar no portal (Microsoft Entra admin center)

Caso precise validar visualmente o estado atual da política e o histórico no portal (`entra.microsoft.com`), siga os caminhos exatos:

1. **Inspecionar a política alterada:**
   `Protection > Conditional Access > Policies` (selecione a política pelo `PolicyName` e revise *Users*, *Target resources*, *Conditions* e *Grant*).
2. **Revisar Named Locations:**
   `Protection > Conditional Access > Named locations` (confira se novos blocos IP ou países confiáveis foram adicionados).
3. **Auditoria de logs no portal:**
   `Identity > Monitoring & health > Audit logs` (filtre por **Category: Policy** e pelo **Correlation ID**).

---

## 5. Mapeamento MITRE ATT&CK e Controles

| Framework | Referência | Descrição |
|---|---|---|
| **MITRE ATT&CK** | `T1562.001` | *Impair Defenses: Disable or Modify Tools* (enfraquecimento de políticas de acesso). |
| **MITRE ATT&CK** | `T1098` | *Account Manipulation* (inclusão de contas ou grupos em listas de exceção). |
| **NIST CSF** | `PR.AA-05` | Controle de acesso e privilégios mínimos revisados continuamente. |
| **CIS Controls v8** | `6.3` / `6.5` | Exigência de MFA para acesso administrativo e remoto sem exceções não documentadas. |

---

## 6. Procedimento de resposta e contenção

Se a investigação confirmar que a alteração **não** possui chamado autorizado ou partiu de sessão suspeita, execute imediatamente o *playbook* de contenção:

1. **Reverter a política imediatamente:** Em `Protection > Conditional Access > Policies`, restaure o estado anterior (`On`) ou remova usuários/IPs inseridos indevidamente em *Exclude*.
2. **Revogar sessões do autor:** No perfil do usuário em `Identity > Users > All users`, clique em **Revoke sessions** e redefina credenciais/MFA se houver suspeita de comprometimento.
3. **Auditar Service Principals:** Caso a ação tenha sido via aplicação, verifique os *client secrets* e permissões (`Policy.ReadWrite.ConditionalAccess`) atribuídas ao *Service Principal*.
4. **Auditoria pós-incidente em KQL:** Execute a consulta abaixo para identificar se houve logins bem-sucedidos sem MFA ou vindos do IP suspeito após a modificação da política:

```kql
let IncidentWindow = 24h;
SigninLogs
| where TimeGenerated >= ago(IncidentWindow)
| where ResultType == 0
| where ConditionalAccessStatus == "notApplied" or AuthenticationRequirement != "multiFactorAuthentication"
| project
    TimeGenerated,
    UserPrincipalName,
    AppDisplayName,
    IPAddress,
    ConditionalAccessStatus,
    AuthenticationRequirement,
    UserAgent,
    CorrelationId
| order by TimeGenerated desc
```

---

## Referências

- [Microsoft Learn — Built-in detections in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Microsoft Learn — What is Conditional Access in Microsoft Entra ID?](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview)
- [MITRE ATT&CK — T1562.001: Impair Defenses](https://attack.mitre.org/techniques/T1562/001/)

