---
title: "通过 PIM 进行权限提升的应急响应指南：SOC 分析师实战手册"
description: "排查 Microsoft Entra ID 特权角色分配与 PIM 激活异常：利用 KQL 关联 AuditLogs 与 SigninLogs，快速验证审批工单并实施即时遏制。"
date: 2026-11-09
categoria: IAM
tags: [sentinel, azure, entra-id, pim, iam, soc, rbac, kql]
nivel: 高级
---

在 Microsoft Entra ID 中，分配高特权目录角色（如*全局管理员 Global Administrator*、*特权角色管理员 Privileged Role Administrator* 或 *安全管理员 Security Administrator*）是风险最高的操作之一。一旦此类分配发生在既定变更窗口之外或缺失工单关联，通常意味着租户治理失控或存在恶意攻击者试图建立特权持久化。

> **SOC 应急摘要（TL;DR）：** 立即在 `AuditLogs` 中核对分配发起人（`InitiatedBy`）、目标角色以及 `ResultReason` 字段中的工单编号。若无合规工单或发起人账户存在异常，请在 PIM 中立即撤销该角色分配，并强制注销用户会话。

> 📘 **Microsoft Learn 官方参考文档：** 本手册基于 Microsoft Sentinel 内置安全监控规则与 Entra ID 最佳实践：
> - [Microsoft Sentinel — 内置定时分析规则目录 (Learn)](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in)
> - [Microsoft Entra PIM — 审核历史与角色分配监控 (Learn)](https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-use-audit-log)

---

## 1. 该安全事件意味着什么？

当管理员或服务主体通过 PIM 授予或激活高特权角色时，通常包含以下情形：
1. **正常合规激活：** 具备资格的管理员依据工单临时申请限时激活。
2. **违规绕过 PIM 直接指派永久角色：** 破坏最小权限原则，直接配置永久特权。
3. **恶意攻击持久化：** 被盗取的管理员账户为攻击者暗中建立的备用账号授予全局权限。

---

## 2. Dica de KQL: 关联 PIM 审计日志与登录上下文

以下查询抓取 PIM 操作记录并关联操作者的交互式登录数据，提取 IP、MFA 与会话风险评分：

```kql
// ====================================================================================
// Deteccao & Enriquecimento: Privileged Role Assignment via PIM
// Autor: Identidade Soberana (identidadesoberana.com.br)
// 目标: 映射发起人、目标账户、角色、理由、IP、MFA 与风险评级
// ====================================================================================
let tempoAnalise = 24h;
// 1. 获取 PIM 审计事件
let EventosPIM = AuditLogs
| where TimeGenerated >= ago(tempoAnalise)
| where LoggedByService == "Privileged Identity Management" or LoggedByService == "Core Directory"
| where ActivityDisplayName in (
    "Add member to role in PIM completed (permanent)",
    "Add member to role in PIM completed (time-bound)",
    "Add member to role completed (PIM activation)",
    "Add eligible member to role in PIM completed",
    "Add member to role in PIM request approved"
)
| mv-expand Target = TargetResources
| mv-expand ModProp = Target.modifiedProperties
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName),
         InitiatorIP = tostring(InitiatedBy.user.ipAddress),
         InitiatorApp = tostring(InitiatedBy.app.displayName),
         TargetUPN = tostring(Target.userPrincipalName),
         RoleAssigned = tostring(ModProp.newValue)
| where RoleAssigned in (
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
) or isempty(RoleAssigned)
| extend JustificativaFinal = iff(isempty(ResultReason), "Nenhuma justificativa informada", tostring(ResultReason))
| project 
    TimeGenerated,
    CorrelationId,
    ActivityDisplayName,
    RoleAssigned,
    TargetUPN,
    InitiatorUPN = iff(isempty(InitiatorUPN), InitiatorApp, InitiatorUPN),
    JustificativaFinal,
    Result;
// 2. 关联 SigninLogs 提取认证与风险信息
let SinaisLogon = SigninLogs
| where TimeGenerated >= ago(tempoAnalise)
| mv-expand AuthDetail = AuthenticationDetails
| project 
    CorrelationId,
    UserPrincipalName,
    IPAddress,
    Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    AuthMFA = AuthenticationRequirement,
    MfaResult = tostring(AuthDetail.authenticationStepResultDetail),
    ClientApp = ClientAppUsed,
    UserAgent = DeviceDetail.operatingSystem,
    RiskLevel = RiskLevelDuringSignIn;
EventosPIM
| join kind=leftouter (SinaisLogon) on CorrelationId
| project
    DataHora = TimeGenerated,
    Acao = ActivityDisplayName,
    RoleAtribuida = RoleAssigned,
    UsuarioAlvo = TargetUPN,
    AtorOriginador = InitiatorUPN,
    Justificativa = JustificativaFinal,
    IPOrigem = iff(isempty(IPAddress), "N/A", IPAddress),
    Localizacao = iff(isempty(Location), "N/A", Location),
    MFAStatus = iff(isempty(AuthMFA), "N/A", AuthMFA),
    NivelRiscoSessao = iff(isempty(RiskLevel), "none", tostring(RiskLevel)),
    IDCorrelacao = CorrelationId
| order by DataHora desc
```

---

## 3. 核心调查核实矩阵

| 排查方向 | 证据来源 | 核实要点 |
|---|---|---|
| **1. 具体操作行为？** | `AuditLogs` / `RoleAssigned` | 分配了何种角色？是永久还是限时？ |
| **2. 发起人身份？** | `InitiatedBy` & `SigninLogs` | 由哪位管理员发起？登录时是否满足强 MFA 条件？ |
| **3. 是否具备权限？** | Entra ID 目录角色 | 操作者是否具备合法的特权分配权限？ |
| **4. 是否有关联工单？** | ServiceNow, Jira, Zendesk | 是否在合法变更窗口内？工单状态是否已获审批？ |
| **5. 门户中核查路径？** | Entra 管理中心 | Identity Governance > Privileged Identity Management > Microsoft Entra Roles > Resource Audit。 |

---

## 4. 应急响应与处置流程

1. **立即移除违规分配：** 在 PIM 控制台中直接点击 *Remove assignment*。
2. **注销会话：** 对目标账户执行 `Revoke sessions` 阻断后续操作。
3. **事后取证审计：**

```kql
let usuarioSuspeito = "usuario.alvo@seudominio.com.br";
let inicioJanela = datetime(2026-11-09T14:00:00Z);
let fimJanela = datetime(2026-11-09T18:00:00Z);
AuditLogs
| where TimeGenerated between (inicioJanela .. fimJanela)
| mv-expand Target = TargetResources
| where InitiatedBy.user.userPrincipalName == usuarioSuspeito
| project 
    TimeGenerated,
    OperationName = ActivityDisplayName,
    Category,
    Target = tostring(Target.displayName),
    TargetType = tostring(Target.type),
    ModifiedProperties = Target.modifiedProperties,
    Result
| order by TimeGenerated asc
```
