---
title: "Microsoft Security 中的 Service Principal 权限授予：使用 Sentinel 与 KQL 的调查指南"
description: "面向 SOC 分析师的 Microsoft Security 实战剧本，结合 Microsoft Sentinel 与 KQL 调查为 Service Principal 授予高危 App Role 与 Graph API 权限事件。"
date: 2026-11-22
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, service-principal, kql, soc, dfir]
nivel: Avançado
draft: false
---

> **TL;DR：** 为 *Service Principal*（服务主体）授予应用程序权限（*Application Permissions*，如 `Mail.Read` 或 `RoleManagement.ReadWrite.Directory`），可在无需用户交互或 MFA 的情况下直接访问租户（*Tenant*）数据。本 *Playbook* 介绍如何在 **Microsoft Security** 生态中使用 Microsoft Sentinel、KQL（`AuditLogs` 与 `AADServicePrincipalSignInLogs`）开展调查与遏制。

---

## 1. 该事件意味着什么？

在 **Microsoft Security** 生态系统中，Microsoft Sentinel 会持续监控 `AuditLogs` 表，检测何时向 *Service Principal* 授予了高危 API 权限（`Add app role assignment to service principal`）。与代表已登录用户行事的委托权限（Delegated）不同，**应用程序权限**允许在 Microsoft Graph、Exchange 或 Entra ID 中以无人值守方式直接读写企业数据。

根据 [Microsoft Learn 上的 Microsoft Sentinel 内置检测目录](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)与 [Microsoft Graph 权限参考文档](https://learn.microsoft.com/en-us/graph/permissions-reference)，攻击者在控制管理员或自动化凭据后，常利用此手法（`MITRE ATT&CK T1098.003`）建立静默持久化并实现基于人类会话策略的 *绕过 (Bypass)*。

### 良性场景与恶意场景对比

| 场景 | 常见特征 | 分类 |
|---|---|---|
| **已规划的 SaaS / SIEM 集成上线** | 已知云管理员操作、已审批变更工单、仅授予最小必要权限（如 `SecurityEvents.Read.All`）。 | 虚假阳性 (False Positive) |
| **授权的 CI/CD 流水线** | 由已知自动化 *Service Principal* 在预定发布窗口内执行授权。 | 虚假阳性 (False Positive) |
| **入侵后的静默提权** | 向新建或不明应用授予极高危权限（`RoleManagement.ReadWrite.Directory`、`AppRoleAssignment.ReadWrite.All`、`Mail.ReadWrite`）。 | 严重真正阳性 (T1098.003) |
| **在现有应用中植入后门** | 失陷管理员向企业内部原本已获信任的旧应用追加邮件或文件读取权限。 | 真正阳性 (T1098 / T1114) |

---

## 2. KQL 查询提示：在 AuditLogs 中关联分析 App Role 授权详情

在 Microsoft Sentinel 中接手该事件时，以下查询会利用 `mv-expand` 展开 `TargetResources` 与 `modifiedProperties`，投影出若干辅助字段，直接展示获得权限的 *Service Principal*、具体授权内容以及审批发起者。

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

## 3. 调查路线图：5 个必问核心问题

为准确判定事件属于真正阳性 (TP) 还是虚假阳性 (FP)，请逐一核实以下五个问题：

### 1. 具体授予了什么权限？
- 检查 KQL 输出中的 `OperationName`、`TargetName` 与 `NewValue`。
- 明确具体授予了哪个 `AppRole` 以及对应哪项 API（`Microsoft Graph`、`Office 365 Exchange Online`、`Windows Azure Active Directory`）。
- 涉及 `Directory.ReadWrite.All`、`RoleManagement.ReadWrite.Directory`、`AppRoleAssignment.ReadWrite.All` 和 `Mail.Read` 时需立即升级排查。

### 2. 是谁发起的授权？
- 检查 `InitiatorUPN`（人类管理员）或 `InitiatorApp`（*Service Principal*）。
- 若为人类管理员，核查相近时间 `SigninLogs` 中的 `SourceIP`、地理位置及是否通过抗钓鱼 MFA（*Passkey* / FIDO2）。
- 同步排查近期是否为该应用新增了 *Client Secret* 或证书凭据。

### 3. 发起者是否有权执行管理员同意？
- 在 *Tenant* 中只有高权限角色才能为应用程序权限授予 *Admin Consent*：
  - **Global Administrator**
  - **Privileged Role Administrator**
  - **Cloud Application Administrator** 或 **Application Administrator**
- 若角色受 PIM（*Privileged Identity Management*）保护，需核实是否存在合规的事前激活记录。

### 4. 是否有正式变更工单？
- 必须与组织的 **ITSM** 平台（**ServiceNow**、**Jira Service Management**、**Freshservice** 或 **Zendesk**）交叉核对。
- 确认存在经安全与 IAM 团队批准的变更单，明确说明该权限符合最小权限原则。

### 5. 该管理会话是否合法？
- 在 Microsoft Entra ID Protection 中核查 `InitiatorUPN` 的会话是否存在登录风险（`RiskLevelDuringSignIn`）或异常 *User-Agent*。
- 核实接收权限的应用是否来自合规供应商（检查 *Publisher* 与源 *Tenant ID*）。

---

## 4. 在管理门户中的排查路径 (Microsoft Entra admin center)

在 `entra.microsoft.com` 中直观核查权限配置：

1. **检查企业应用权限：**
   `Identity > Applications > Enterprise applications > All applications`（按 `TargetName` 搜索并查看 **Security > Permissions**）。
2. **核查应用注册凭据与所有者：**
   `Identity > Applications > App registrations`（检查 **Certificates & secrets** 与 **Owners**）。
3. **门户审计日志：**
   `Identity > Monitoring & health > Audit logs`（按 **Correlation ID** 过滤）。

---

## 5. MITRE ATT&CK 与安全控制映射

| 框架 | 编号 | 说明 |
|---|---|---|
| **MITRE ATT&CK** | `T1098.003` | *Account Manipulation: Additional Cloud Roles*（向工作负载标识授予高危云端角色/API 权限）。 |
| **MITRE ATT&CK** | `T1550.001` | *Use Alternate Authentication Material: Application Access Token*（利用应用访问令牌实现持久化访问）。 |
| **NIST CSF** | `PR.AA-05` | 持续审计人类与非人类标识的权限分配。 |
| **CIS Controls v8** | `6.8` | 严格依据最小权限原则管控服务账户与 *Service Principal*。 |

---

## 6. 应急响应与遏制流程

若确认未经正式审批或存在账户失陷迹象，请立即执行以下 *Playbook*：

1. **立即撤销 API 权限：** 在 `Enterprise applications > [App] > Security > Permissions` 中撤销未授权权限；若整个应用均为恶意应用，直接在 **Properties** 中将 **Enabled for users to sign-in?** 设为 **No**。
2. **撤销发起者会话：** 在 `Identity > Users > All users` 中找到 `InitiatorUPN`，点击 **Revoke sessions**，强制重置密码并审计 MFA 方式。
3. **轮换或删除 Secrets：** 在 `App registrations > Certificates & secrets` 中清理近期新增的可疑 *Client Secret* 或证书。
4. **事后 KQL 审计：** 在 `AADServicePrincipalSignInLogs` 表中运行以下查询，核实该 *Service Principal* 是否已从外部 IP 成功发起令牌认证：

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

## 参考资料

- [Microsoft Learn — Built-in detections in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Microsoft Learn — Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [MITRE ATT&CK — T1098.003: Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/)

