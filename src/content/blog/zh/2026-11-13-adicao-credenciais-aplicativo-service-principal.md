---
title: "在 Entra ID 应用程序中新增 Secrets 与凭据排查指南：SOC 分析师实战手册"
description: "排查 Microsoft Entra ID 服务主体（Service Principal）与应用程序注册中非预期新增 Secrets 或证书：SOC 处置与关联取证手册。"
date: 2026-11-13
categoria: IAM
tags: [sentinel, azure, entra-id, service-principal, oauth, soc, iam, dfir, kql]
nivel: 高级
---

在 Microsoft Entra ID 已注册的应用中，未经验证新增客户端机密（*Client Secrets*）或数字证书是云端环境中最危险的权限维持与特权提升指标之一（**MITRE ATT&CK T1098.001**）。资深攻击者常利用该手段建立不受用户密码及 MFA 限制的隐蔽后门。

> **SOC 应急摘要（TL;DR）：** 一旦发现未关联审批工单的 Secret 新增行为，应直接定性为**真正阳性告警（True Positive - High/Critical）**。立即在 *App registrations* 中删除对应 Secret，检查 `AADServicePrincipalSignInLogs` 排查近期的接口调用，并对发起账户执行会话注销与密码重置。

> 📘 **Microsoft Learn 官方参考文档：** 本手册基于 Microsoft Sentinel 内置检测规则与工作负荷标识安全指南：
> - [Microsoft Sentinel — 内置定时分析规则目录 (Learn)](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in)
> - [Microsoft Entra ID — 保护与监控工作负荷标识 (Learn)](https://learn.microsoft.com/entra/architecture/protect-workload-identities)

---

## 1. 该安全事件意味着什么？

在 Microsoft Entra ID 中，自动化集成程序通过**工作负荷标识（Service Principal）**在无人值守的情况下访问 Microsoft Graph 或各类云资源。

服务主体使用以下方式完成接口认证：
1. 客户端机密文本（*Client Secret*）；
2. 非对称数字证书（*X.509 Certificate*）；
3. OIDC 工作负荷身份联合（如 GitHub Actions）。

若攻击者攻破了具备 **Application Administrator** 权限的账号，通常会为租户中已具有高权限（如 `Directory.ReadWrite.All`）的存量应用添加一个有效期极长的新 Client Secret，从而避开 MFA 与条件访问策略，持续调用 API。

---

## 2. KQL 查询提示：追踪新增 Secrets 与操作者会话上下文

以下查询关联应用凭据新增审计与发起人员的登录记录，提取操作者 IP、地理位置与认证信息：

```kql
// ====================================================================================
// Deteccao & Enriquecimento: Nova credencial adicionada a aplicativo ou Service Principal
// Autor: Identidade Soberana (identidadesoberana.com.br)
// 目标: 映射发起人、目标应用、Secret 类型、IP 与登录上下文
// ====================================================================================
let tempoAnalise = 24h;
let EventosCredencial = AuditLogs
| where TimeGenerated >= ago(tempoAnalise)
| where ActivityDisplayName in (
    "Update application - Certificates and secrets management ",
    "Add service principal credentials",
    "Add service principal",
    "Update application"
)
| mv-expand Target = TargetResources
| mv-expand ModProp = Target.modifiedProperties
| where ModProp.displayName in ("KeyDescription", "CredentialData", "TargetId.KeyDescription") 
     or ActivityDisplayName == "Add service principal credentials"
| extend AtorUPN = tostring(InitiatedBy.user.userPrincipalName),
         AtorIP = tostring(InitiatedBy.user.ipAddress),
         AtorApp = tostring(InitiatedBy.app.displayName),
         NomeApp = tostring(Target.displayName),
         AppIdAlvo = tostring(Target.id),
         DetalheModificacao = tostring(ModProp.newValue)
| extend AtorFinal = iff(isempty(AtorUPN), AtorApp, AtorUPN)
| project
    TimeGenerated,
    CorrelationId,
    ActivityDisplayName,
    NomeApp,
    AppIdAlvo,
    AtorFinal,
    DetalheModificacao,
    Result;
let SinaisLogon = SigninLogs
| where TimeGenerated >= ago(tempoAnalise)
| mv-expand AuthDetail = AuthenticationDetails
| project
    CorrelationId,
    UserPrincipalName,
    IPAddress,
    Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    MFAStatus = AuthenticationRequirement,
    DetalheMFA = tostring(AuthDetail.authenticationStepResultDetail),
    RiskLevel = RiskLevelDuringSignIn;
EventosCredencial
| join kind=leftouter (SinaisLogon) on CorrelationId
| project
    DataHora = TimeGenerated,
    Acao = ActivityDisplayName,
    AplicativoAlvo = NomeApp,
    IdAplicativo = AppIdAlvo,
    AtorOriginador = AtorFinal,
    DetalheCredencial = DetalheModificacao,
    IPOrigem = iff(isempty(IPAddress), "N/A", IPAddress),
    Localizacao = iff(isempty(Location), "N/A", Location),
    MFA = iff(isempty(MFAStatus), "N/A", MFAStatus),
    NivelRisco = iff(isempty(RiskLevel), "none", tostring(RiskLevel)),
    IDCorrelacao = CorrelationId
| order by DataHora desc
```

---

## 3. 调查排查矩阵

| 排查方向 | 证据来源 | 重点核实项 |
|---|---|---|
| **1. 增加了何种凭据？** | `AuditLogs` / `TargetResources` | 是 Client Secret 还是 X.509 证书？设定的有效期限是多久？ |
| **2. 发起人是谁？** | `InitiatedBy` & `SigninLogs` | 是人工后台操作还是自动化流水线行为？ |
| **3. 是否具备审批工单？** | ServiceNow, Jira, Freshservice | 是否有计划中的 Secret 轮换变更工单？ |
| **4. 门户中核查路径？** | Entra 管理中心 | App registrations > API permissions 与 Service principal sign-ins。 |

---

## 4. 应急响应与处置流程

1. **立即删除异常凭据：** 访问 *App registrations* > *Certificates & secrets* 移除未经授权的 Secret。
2. **隔离发起者身份：** 执行 `Revoke sessions` 阻断其所有会话并强制重置密码。
3. **事后取证审计：**

```kql
let appIdSuspeito = "00000000-0000-0000-0000-000000000000";
let inicioJanela = datetime(2026-11-13T00:00:00Z);
AADServicePrincipalSignInLogs
| where TimeGenerated >= inicioJanela
| where AppId == appIdSuspeito
| project
    DataHora = TimeGenerated,
    NomeApp = ServicePrincipalName,
    IdApp = AppId,
    IPOrigem = IPAddress,
    Localizacao = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    RecursoAcessado = ResourceDisplayName,
    StatusResultado = ResultType,
    DescricaoResultado = ResultDescription,
    IDCorrelacao = CorrelationId
| order by DataHora asc
```

