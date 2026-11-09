---
title: "Elevação de privilégios via PIM: guia prático de investigação para o SOC"
description: "Guia técnico de investigação para alertas de atribuição de privilégios no Microsoft Entra via PIM: KQL enriquecido, cruzamento de AuditLogs e SigninLogs, validação em ITSM e trilha de auditoria no portal."
date: 2026-11-09
categoria: SOC
tags: [sentinel, pim, entra-id, kql, incident-response, iam, soc]
nivel: Intermediário
---

Incidentes de elevação de privilégios e atribuição de funções administrativas são os mais sensíveis no radar de um Security Operations Center (SOC). O alerta originado pela atribuição de funções via **Privileged Identity Management (PIM)** sinaliza que uma função de alto impacto (como *Global Administrator*, *Privileged Role Administrator* ou *User Administrator*) foi concedida ou ativada no Microsoft Entra ID.

> **TL;DR para o SOC:** Nunca encerre esse alerta apenas verificando se o usuário é conhecido. A missão do analista é provar a legitimidade da cadeia: **Quem solicitou?** **Quem aprovou?** **Havia ticket pré-aprovado no ITSM?** **A sessão do originador apresentava risco no SigninLogs?** Siga o passo a passo abaixo para triagem e validação forense.

> 📘 **Referência no Microsoft Learn:** Este playbook baseia-se nos incidentes modelados pelas detecções nativas de identidade do Azure Sentinel e pelas trilhas de auditoria do Entra ID. Para consultar as especificações oficiais no Microsoft Learn:
> - [Microsoft Sentinel — Built-in scheduled analytics rules catalog (Learn)](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in)
> - [Microsoft Entra ID — Configurar alertas de segurança no Privileged Identity Management (Learn)](https://learn.microsoft.com/azure/active-directory/privileged-identity-management/pim-how-to-configure-security-alerts)

---

## 1. O que significa esse incidente?

O serviço **MS-PIM (Microsoft Entra Privileged Identity Management)** atua como o corretor de acesso *just-in-time* (JIT). Quando uma regra de detecção no Microsoft Sentinel dispara este incidente, um dos seguintes cenários acabou de acontecer:

1. **Ativação legítima de elegibilidade (*Role Activation*):** Um operador elegível ativou uma função para uma atividade pontual.
2. **Atribuição direta de elegibilidade ou permanência (*Role Assignment*):** Um administrador adicionou um usuário como elegível ou ativo em uma função privilegiada.
3. **Aprovação de solicitação de terceiro:** Um aprovador concedeu acesso solicitado por outro usuário.
4. **Persistência pós-comprometimento (Ataque real):** Um ator de ameaça que obteve credenciais de uma conta com permissão de aprovação no PIM (ou ativou um usuário fantasma) para garantir persistência administrativa no tenant.

---

## 2. KQL Avançado: Enriquecimento de AuditLogs + SigninLogs

Geralmente, o log de auditoria do PIM registra o evento `Add member to role completed (PIM activation)` ou `Add eligible member to role in PIM completed`. Porém, analisar apenas o evento bruto deixa pontos cegos sobre o contexto de rede do ator.

A query abaixo extrai a atribuição privilegiada em `AuditLogs`, parseia justificativa, função e alvos, e faz **join correlato** com os `SigninLogs` pelo `CorrelationId` ou pela janela temporal da conta originadora para trazer contexto de IP, Cidade, MFA e Nível de Risco em uma visão consolidada:

```kql
// ====================================================================================
// Detecção & Enriquecimento: Privileged Role Assignment via PIM
// Autor: Identidade Soberana (identidadesoberana.com.br)
// Objetivo: Mapear ator, alvo, role, justificativa, IP, MFA e correlação de risco
// ====================================================================================
let tempoAnalise = 24h;
let rolesCriticas = dynamic([
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "User Administrator",
    "Cloud Application Administrator",
    "Application Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Intune Administrator",
    "Conditional Access Administrator"
]);
// 1. Extração dos eventos de auditoria do PIM
let EventosPIM = AuditLogs
| where TimeGenerated >= ago(tempoAnalise)
| where LoggedByService =~ "Privileged Identity Management" or LoggedByService =~ "Core Directory"
| where ActivityDisplayName in~ (
    "Add member to role in PIM completed (permanent)",
    "Add member to role in PIM completed (time-bound)",
    "Add member to role completed (PIM activation)",
    "Add eligible member to role in PIM completed",
    "Add member to role in PIM request approved"
)
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName),
         InitiatorIP = tostring(InitiatedBy.user.ipAddress),
         InitiatorApp = tostring(InitiatedBy.app.displayName),
         TargetUPN = tostring(TargetResources[0].userPrincipalName),
         RoleAssigned = tostring(TargetResources[0].modifiedProperties[1].newValue)
| extend RoleAssigned = trim(@'["\\]', RoleAssigned)
| where RoleAssigned in~ (rolesCriticas) or isempty(RoleAssigned) or RoleAssigned has_any (rolesCriticas)
| extend ResultReason = tostring(ResultReason)
| extend AdditionalDetailsDynamic = parse_json(AdditionalDetails)
| mv-apply Detail = AdditionalDetailsDynamic on (
    where Detail.key in~ ("Justification", "TicketNumber", "TicketSystem")
    | summarize Justification = take_anyif(tostring(Detail.value), Detail.key =~ "Justification"),
                TicketNumber = take_anyif(tostring(Detail.value), Detail.key =~ "TicketNumber")
)
| extend JustificativaFinal = coalesce(Justification, ResultReason, "Nenhuma justificativa informada")
| project 
    TimeGenerated,
    CorrelationId,
    ActivityDisplayName,
    RoleAssigned,
    TargetUPN,
    InitiatorUPN = iff(isempty(InitiatorUPN), InitiatorApp, InitiatorUPN),
    JustificativaFinal,
    TicketNumber,
    Result;
// 2. Cruzamento com SigninLogs para capturar contexto de autenticação e risco
EventosPIM
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated >= ago(tempoAnalise)
    | project 
        CorrelationId,
        UserPrincipalName,
        IPAddress,
        Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
        AuthMFA = AuthenticationRequirement,
        MfaResult = AuthenticationDetails[0].authenticationStepResultDetail,
        ClientApp = ClientAppUsed,
        UserAgent = DeviceDetail.operatingSystem,
        RiskLevel = RiskLevelDuringSignIn
) on CorrelationId
| project
    DataHora = TimeGenerated,
    Acao = ActivityDisplayName,
    RoleAtribuida = RoleAssigned,
    UsuarioAlvo = TargetUPN,
    AtorOriginador = InitiatorUPN,
    Justificativa = JustificativaFinal,
    TicketReferencia = TicketNumber,
    IPOrigem = coalesce(IPAddress, "N/A"),
    Localizacao = coalesce(Location, "N/A"),
    MFAStatus = coalesce(AuthMFA, "N/A"),
    NivelRiscoSessao = coalesce(RiskLevel, "none"),
    IDCorrelacao = CorrelationId
| order by DataHora desc
```

### O que essa query traz a mais:
* **`Justificativa` & `TicketReferencia`:** Extrai os campos preenchidos pelo operador durante o wizard do PIM.
* **`MFAStatus` & `NivelRiscoSessao`:** Identifica se a sessão que realizou a operação passou por MFA e se a Proteção de Identidade (Entra ID Protection) considerou o login anômalo.
* **`IDCorrelacao`:** Chave canônica para o analista rastrear tudo o que aconteceu naquela mesma janela de autenticação.

---

## 3. Matriz de Investigação Técnica: 5 Perguntas Obrigatórias

Durante a triagem no Sentinel, o analista deve responder estruturadamente a 5 perguntas:

| Pergunta | Onde Validar | O que verificar |
|---|---|---|
| **1. O que foi feito?** | `AuditLogs` / PIM Audit | Qual a Role exata? Foi **ativação temporária** (ex.: 4 horas) ou **atribuição de elegibilidade permanente**? |
| **2. Quem fez?** | `InitiatedBy` | Foi o próprio usuário (auto-ativação) ou um terceiro? Se foi terceiro, quem é a conta originadora? |
| **3. Poderia ter feito?** | Entra ID Roles & Approvers | O originador é aprovador oficial daquela função ou *Privileged Role Admin*? |
| **4. Há chamado formal?** | ITSM da empresa (ServiceNow, Jira, Freshservice) | O número do ticket informado existe? Foi aprovado pela liderança/segurança? |
| **5. A sessão foi legítima?** | `SigninLogs` & `AADUserRiskEvents` | IP conhecido? País habitual? Houve falha de MFA prévia ou *Impossible Travel*? |

---

## 4. Onde Investigar no Portal do Microsoft Entra

Nem toda informação está consolidada de imediato na tela de incidentes do Sentinel. Siga esta rota dentro do **Microsoft Entra admin center** (`entra.microsoft.com`):

### Passo 1: Trilha do PIM (Resource Audit)
1. Navegue até:
   > **Identity Governance** > **Privileged Identity Management** > **Microsoft Entra roles**
2. No menu lateral esquerdo, selecione:
   > **Resource audit** *(Auditoria de recursos)*
3. Utilize os filtros:
   * **Role:** Filtre pela função envolvida no incidente (ex.: *Global Administrator*).
   * **Time range:** Janela do alerta.
   * **Search:** Cole o `CorrelationId` obtido no Sentinel.
4. Inspecione o card detalhado: verifique o **Requestor**, o **Approver** (se exigido aprovação em dois estágios) e o campo **Reason**.

### Passo 2: Trilha de Autenticação do Ator (Sign-in Logs)
1. Navegue até:
   > **Identity** > **Users** > Selecione o usuário originador > **Sign-in logs**
2. Alterne para a aba **Interactive user sign-ins** e filtre pela data/hora exata.
3. Clique no evento e revise:
   * **Conditional Access:** Se a política de PIM exigiu conformidade do dispositivo (*Compliant device*) ou *Phishing-resistant MFA*.
   * **Device info:** Dispositivo corporativo gerenciado pelo Intune ou equipamento pessoal desconhecido (*BYOD/Unmanaged*).

---

## 5. Validação em Ferramentas de ITSM (Chamados & Mudanças)

Um dos maiores erros operacionais em SOC é fechar incidentes com justificativa vaga como *"atividade operacional de rotina"*. 

A regra de ouro de conformidade (ISO 27001 A.9 / SOC 2 CC6.1 / LGPD Art. 46) exige **rastreabilidade independente**:
* **ServiceNow:** Verifique se o RITM (Request Item) ou CHG (Change Request) está com status **Approved** e dentro da janela de manutenção programada.
* **Jira Service Management:** Cheque o ticket vinculado, aprovação explícita do gestor de segurança e data de expiração da demanda.
* **Freshservice / Zendesk:** Confirme se o autor do chamado confere com a identidade que ativou o privilégio.

> ⚠️ **Ponto de Atenção:** Se o usuário colocou no campo de justificativa do PIM apenas *"urgente"*, *"teste"*, *"ajuste"* ou números genéricos (ex: `12345`), entre em contato com o gestor do titular antes de aprovar/manter o acesso.

---

## 6. Procedimento de Resposta e Contenção

Se a atribuição **não possuir aprovação formal**, se o titular **negar a autoria**, ou se houver **indicadores de comprometimento (IoC)** na sessão de origem:

```
[Alerta Disparado]
        │
        ├──> Há chamado válido no ITSM e IP legítimo?
        │       ├──> SIM: Documentar evidências e encerrar como "Benign Positive".
        │
        └──> NÃO / SUSPEITO:
                │
                ├── 1. Revogar Role imediatamente no PIM:
                │      Entra Admin Center > PIM > Roles > Assignments > Remove
                │
                ├── 2. Revogar todas as sessões ativas (Tokens OAuth/Refresh):
                │      Revoke Sessions (User > Revoke sessions)
                │
                ├── 3. Resetar credenciais & forçar novo registro de MFA
                │
                ├── 4. Auditar ações executadas durante a janela com privilégio elevado:
                │      Buscar criação de novas credenciais de app, consentimentos OAuth
                │      ou criação de novos usuários no tenant
                │
                └── 5. Escalar para incidente de segurança (N2/CSIRT)
```

### KQL para Auditar o que o usuário fez após a ativação
Execute esta query para listar todas as modificações no tenant realizadas pelo usuário suspeito nas horas subsequentes à ativação da função:

```kql
let usuarioSuspeito = "usuario.alvo@seudominio.com.br";
let inicioJanela = datetime(2026-11-09T14:00:00Z);
let fimJanela = datetime(2026-11-09T18:00:00Z);
AuditLogs
| where TimeGenerated between (inicioJanela .. fimJanela)
| where InitiatedBy.user.userPrincipalName =~ usuarioSuspeito
| project 
    TimeGenerated,
    OperationName = ActivityDisplayName,
    Category,
    Target = tostring(TargetResources[0].displayName),
    TargetType = tostring(TargetResources[0].type),
    ModifiedProperties = TargetResources[0].modifiedProperties,
    Result
| order by TimeGenerated asc
```

---

## 7. Mapeamento de Controles e Boas Práticas

Para evitar reincidência de incidentes não documentados:
* **Obrigar Ticket Number nas configurações de Role do PIM:** Em cada função no PIM, habilite a flag *"Require ticket information on activation"*.
* **Aprovação Dual (*Two-Person Rule*):** Funções como *Global Admin* devem sempre requerer aprovação de um membro do time de Segurança da Informação ou SOC N3.
* **Alerta no Microsoft Sentinel:** Mantenha a regra de analytics ativa com severidade **Medium** para ativações e **High** para novas atribuições diretas de elegibilidade permanente.

