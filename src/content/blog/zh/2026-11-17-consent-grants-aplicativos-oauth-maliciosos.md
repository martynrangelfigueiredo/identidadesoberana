---
title: "Microsoft Security 恶意 OAuth 应用授权调查：基于 Microsoft Sentinel 的威胁狩猎与应急响应剧本"
description: "Microsoft Security 生态实战剧本：深入排查非预期的高危 OAuth 授权、恶意同意钓鱼（Consent Phishing）并实施 Entra ID 应急阻断。"
date: 2026-11-17
categoria: IAM
tags: [microsoft-security, sentinel, entra-id, oauth, consent-grant, soc, iam, dfir, kql]
nivel: Avançado
---

滥用 OAuth 应用程序授权——业内通常称为**同意钓鱼（Consent Phishing）**或非法同意授权（Illicit Consent Grant），是云端身份体系中最隐蔽且危害极大的攻击向量之一。与依赖盗取用户密码或绕过多因子验证（MFA）的传统手法不同，该攻击利用精心伪装的欺诈诱饵，诱骗普通员工（甚至管理员）向攻击者控制的第三方恶意应用程序授予代表其访问云端资产的权限。

一旦授权成功，恶意应用程序即可通过 Microsoft Graph API 获取包含高危权限作用域（如 `Mail.ReadWrite`、`Files.ReadWrite.All` 或 `User.ReadWrite.All`）的访问令牌。**攻击者无需掌握受害者的登录密码，也无需面临任何二次验证挑战**，即可隐蔽且持久地读取企业邮件、窃取敏感文件及监控即时通讯。

在 **Microsoft Security** 整体防御架构中，**Microsoft Entra ID** 与 **Microsoft Sentinel** 的深度联动，为 SOC 团队提供了排查可疑授权、审计 API 流量及阻断恶意应用程序的完整能力。

> 📘 **Microsoft Learn 官方参考文档：**
> - [防范 Microsoft Entra ID 中的非法授权攻击 (Learn)](https://learn.microsoft.com/entra/identity/enterprise-apps/manage-consent-requests)
> - [在 Microsoft Sentinel 中排查可疑应用程序事件 (Learn)](https://learn.microsoft.com/azure/sentinel/investigate-incidents)
> - [Microsoft Sentinel 定时威胁分析规则参考目录 (Learn)](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in)

---

## 1. 同意钓鱼（Consent Phishing）的攻击机理

该战术在 **MITRE ATT&CK 框架中被归类为 T1528（窃取应用程序访问令牌）**与 **T1204.001（用户执行：恶意链接）**：

1. **钓鱼诱饵投放：** 员工收到一封看似合规的企业内部邮件（例如“HR 制度更新确认”、“待处理电子签署”或“财报报表共享”）。
2. **微软官方登录认证页：** 点击链接后，页面直接跳转至微软官方认证终端（`login.microsoftonline.com`）。由于域名真实合法，企业网关与浏览器安全机制均不会触发拦截。
3. **索取高危权限：** 应用程序要求用户确认授予读取邮件（`Mail.Read`）、访问网盘与 SharePoint（`Files.ReadWrite.All`）或访问团队聊天（`Chat.Read`）等委托权限。
4. **长期静默维持：** 用户一旦点击“接受”，攻击者即刻获取具备长有效期的刷新令牌（Refresh Token），实现长期后门驻留，且不会在后续访问中产生任何用户登录告警。

---

## 2. KQL 查询提示：排查 Entra ID 中的 OAuth 应用授权记录

以下 KQL 查询通过投影关键字段，帮助分析师快速梳理 `AuditLogs` 中记录的应用程序授权事件，明确被授权的应用名称、权限范围及审批人：

```kql
// ====================================================================================
// Consulta: Mapeando consentimentos de aplicativos OAuth no Entra ID
// Objetivo: Identificar aplicacao alvo, permissoes concedidas, usuario originador e data
// ====================================================================================
let JanelaTempo = 30d;
AuditLogs
| where TimeGenerated >= ago(JanelaTempo)
| where ActivityDisplayName in (
    "Consent to application",
    "Add delegated permission grant",
    "Add app role assignment to service principal"
)
| mv-expand Target = TargetResources
| mv-expand ModProp = Target.modifiedProperties
| where ModProp.displayName in ("ConsentAction.Permissions", "DelegatedPermissionGrant.Scope", "AppRole.Value")
| extend AtorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend NomeAplicativo = tostring(Target.displayName)
| extend IdAplicativo = tostring(Target.id)
| extend Permissoes = tostring(ModProp.newValue)
| project
    TimeGenerated,
    ActivityDisplayName,
    NomeAplicativo,
    IdAplicativo,
    Permissoes,
    AtorUPN,
    Result,
    CorrelationId
| order by TimeGenerated desc
```

### 研判核心关注点：
- **`Permissoes`（权限范围）：** 若发现未验证发布者（*Unverified Publisher*）的应用被授予了 `Mail.ReadWrite`、`Mail.Send`、`Files.ReadWrite.All` 或 `Directory.AccessAsUser.All`，极具攻击嫌疑。
- **`AtorUPN`（授权发起人）：** 判断是普通员工授权（*User Consent*），还是全局管理员执行的全租户范围管理员同意（*Admin Consent*）。
- **`IdAplicativo`（服务主体 ID）：** 在租户（Tenant）内生成的 Service Principal 唯一标识符，后续实施隔离阻断时必须使用。

---

## 3. 研判剧本：SOC 分析师的 5 个必答问题

在 Microsoft Sentinel 控制台中调查此类事件时，请逐项核对：

### 1. 实际被授予了哪些权限？
注册的应用程序是何属性？是来自外部的多租户应用还是内部自研？授予的属于仅代表当前用户的委托权限，还是覆盖企业所有邮箱的应用程序级权限？

### 2. 是谁批准了该请求？
查验 `AtorUPN` 对应的员工身份。该员工是否存在业务合理性需要使用此工具？是否属于掌握核心商密的高管、财务或法务人员？

### 3. 应用发布者是否经过微软官方验证？
该应用是否带有蓝色的“已验证发布者（*Verified Publisher*）”徽标？未经验证的开发者、新注册的域名以及仿冒知名工具名称（如“DocuSign Secure Portal”）通常是高危特征。

### 4. ITSM 工单系统中是否有审批依据？
在企业工单系统（ServiceNow、Jira Service Management 等）中检索，是否存在安全团队对该集成的预先评审记录？若无任何合规审批工单，应直接升级为疑似真实攻击。

### 5. 应用程序是否已经开始调用 Graph API？
排查 `AADServicePrincipalSignInLogs` 日志，确认该服务主体在授权发生后，是否已经开始向 Microsoft Graph 发送接口请求并拉取数据。

---

## 4. 在 Microsoft Entra 管理中心深入核查

一线及二线安全分析师可在 Entra ID 门户执行以下排查步骤：

1. 打开 **Microsoft Entra 管理中心**（`entra.microsoft.com`）。
2. 导航至 **标识（Identity） > 应用程序（Applications） > 企业应用程序（Enterprise applications）**。
3. 在列表中找到涉事应用程序，进入其详情面板。
4. 在左侧菜单点击 **安全性（Security） > 权限（Permissions）**：
   - 查验 **管理员同意（Admin consent）** 列表中是否存在全员范围的高危权限。
   - 查验 **用户同意（User consent）** 列表中具体包含哪些受害员工账号。
5. 查阅该应用专属的 **审计日志（Audit logs）**，排查其近期是否发生过添加机密（Secret）或修改回调地址的操作。

---

## 5. 应急响应与即时处置流程

一旦确认为恶意或违规应用程序，SOC 必须立刻实施阻断：

1. **禁用该应用程序的用户登录入口：**
   - 进入该企业应用程序的 **属性（Properties）** 界面，将 **已启用以供用户登录? (Enabled for users to sign-in?)** 设置为 **否 (No)**。
2. **通过 PowerShell 强制撤销已授予的全部权限：**
   ```powershell
   Connect-MgGraph -Scopes "Application.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All"

   $AppObjId = "SERVICE-PRINCIPAL-OBJECT-ID"
   Get-MgServicePrincipalOAuth2PermissionGrant -ServicePrincipalId $AppObjId | ForEach-Object {
       Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $_.Id
   }
   ```
3. **从租户中彻底删除该应用：**
   - 在 **企业应用程序 > 属性** 界面点击 **删除 (Delete)**，彻底移除该服务主体（Service Principal）。
4. **强制注销受害用户会话并修改口令：**
   - 对曾点击授权的所有员工执行 `Revoke-MgUserSignOut`，使已签发的令牌立即失效。
5. **收紧租户的应用程序同意策略（加固配置）：**
   - 访问 **企业应用程序 > 同意和权限 > 用户同意设置**，将其调整为 **不允许用户同意 (Do not allow user consent)**，并开启 **管理员同意工作流 (Admin consent workflow)**。

---

## 6. 事件后 KQL 复盘查询：审计服务主体调用行为

阻断恶意应用后，执行以下查询确认其在过去 14 天内是否在租户中留存调用轨迹：

```kql
// ====================================================================================
// Verificacao Pos-Incidente: Rastreando tokens e logons do Service Principal suspeito
// Objetivo: Verificar se a aplicacao com consentimento abusivo consumiu APIs do tenant
// ====================================================================================
let JanelaAnalise = 14d;
let AppIdSuspeito = "00000000-0000-0000-0000-000000000000";
AADServicePrincipalSignInLogs
| where TimeGenerated >= ago(JanelaAnalise)
| where tolower(AppId) == tolower(AppIdSuspeito)
| extend StatusAutenticacao = iff(ResultType == 0, "Sucesso", "Falha")
| project
    TimeGenerated,
    ServicePrincipalName,
    AppId,
    IPAddress,
    ResourceDisplayName,
    StatusAutenticacao,
    ResultType,
    ResultDescription,
    CorrelationId
| order by TimeGenerated desc
```

### 研判决策矩阵（TP 与 FP 对比）：

| 研判场景 | 结论分类 | SOC 处置动作 |
|---|---|---|
| 未知第三方应用、发布者未验证、申请邮件读取权限（`Mail.ReadWrite`） | **真实阳性 (严重级)** | 立即阻断并删除应用、撤销受害员工会话、开展邮箱取证并评估数据泄露范围。 |
| 企业已采购的合规商业应用（如 Jira 官方集成插件），由工程师合规配置 | **虚假阳性 (FP)** | 比对 ITSM 工单信息，核实开发者官方验证标识，在 Sentinel 告警规则中添加合规白名单。 |
| 管理员账号被钓鱼，导致为未知外部应用签署全租户级管理员同意 | **重大安全事故 (P1)** | 立即通报 DFIR，阻断涉事应用，对所有管理员账户展开全面凭据审计与安全巡检。 |

