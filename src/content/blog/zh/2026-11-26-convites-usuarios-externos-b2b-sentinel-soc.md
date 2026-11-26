---
title: "Microsoft Security 中的外部来宾 (B2B) 邀请：结合 Entra ID 与 Sentinel 开展调查"
description: "面向 SOC 分析师的 Microsoft Security 应急响应剧本，演示如何使用 Microsoft Sentinel 和 KQL 排查 Entra ID 中的可疑 B2B 外部用户邀请。"
date: 2026-11-26
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, b2b, iam, kql, soc, dfir]
nivel: Intermediário
draft: false
---

> **TL;DR：** Microsoft Entra ID 的 B2B 协作方便了跨组织合作，但未经授权向个人邮箱（`gmail.com`、`outlook.com`）发送邀请或随后为 `#EXT#` 账户分配管理角色，会形成跨租户（Tenant）的隐蔽持久化通道。本指南演示如何在 **Microsoft Security** 生态下结合 Microsoft Sentinel、KQL（`AuditLogs` 与 `SigninLogs`）、ITSM 核对以及 Entra ID 遏制措施开展调查。

---

## 1. 该事件意味着什么？

在 **Microsoft Security** 体系中，Microsoft Sentinel 会持续监控 `AuditLogs` 表中与外部来宾（*B2B Guest*）创建、兑换及提权相关的事件，例如 `Invite external user`、`Redeem external user invite`、带有 `#EXT#` 后缀的 `Add user`，以及随后的组或角色变更。

正如 [Microsoft Learn 上的 Microsoft Sentinel 内置检测目录](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) 和 [Microsoft Entra ID B2B 协作官方文档](https://learn.microsoft.com/en-us/entra/external-id/b2b-quickstart-add-guest-users-portal) 所述，攻击者在控制具备邀请权限（`Guest Inviter`）的内部账号后，可邀请其掌控的外部账号（`MITRE ATT&CK T1136.003` / `T1098`），从而在原密码重置后仍保留访问能力。

### 良性场景与恶意场景对比

| 场景 | 常见指标 | 判定分类 |
|---|---|---|
| **已认证合作伙伴项目协作** | 已知企业域名（如合作方官方域），由业务负责人发起邀请，仅访问特定 Teams 频道或 SharePoint 文件夹。 | 虚假阳性（良性） |
| **已获工单审批的临时顾问** | 由 IAM/服务台在关联变更工单下发起邀请，并配置了定期访问评审策略。 | 虚假阳性（良性） |
| **向免费个人邮箱发送邀请（`gmail.com` / `proton.me`）** | 无对外协作职责的内部账号在非工作时间或异常登录之后邀请个人邮箱。 | 真正阳性（立即排查） |
| **`#EXT#` 来宾被加入特权角色或高权限组** | 新邀请的外部用户获批 Entra ID 角色、Azure RBAC（`Contributor`/`Owner`）或进入关键应用访问组。 | 严重真正阳性（`T1098`） |

---

## 2. KQL 查询提示：在 AuditLogs 中追踪外部来宾邀请与权限分配

在 Microsoft Sentinel 中接手事件后，以下查询会从 `AuditLogs` 投影更多上下文列，用于快速确认发起邀请的账号、被邀请的外部地址、操作结果以及用于关联追踪的 `CorrelationId`。

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

## 3. 调查路线图：5 个必查问题

### 1. 发生了什么操作？
在 `AuditLogs` 中核查来宾账号的完整生命周期：
- 邀请是仅已发送（`Invite external user`）还是已被兑换（`Redeem external user invite`）？
- 邀请之后是否紧接着出现针对同一 `#EXT#` 用户的 `Add member to group` 或 `Add member to role`？
- 记录 `CorrelationId` 与 `GuestUPN` 以便跨表关联。

### 2. 是谁发起的？
检查 `AuditLogs` 中的 `InitiatorUPN` 和 `SourceIP`，并在 `SigninLogs` 中核对发起者近期的登录活动：
- 发起邀请的员工是否属于采购、法务、IT 或外部供应商管理岗位？
- 发起邀请的会话是否来自受管合规设备（`IsCompliant == true`）及常规办公 IP，还是紧随异地或 MFA 异常之后？

### 3. 该账号本应具备邀请权限吗？
评估租户（Tenant）的 B2B 治理配置：
- 在 Entra ID 外部协作设置中，是否所有普通成员（`Member`）都能邀请来宾，还是仅限 `Guest Inviter` / `User Administrator` 角色？
- 是否配置了针对免费邮箱域名的允许列表（Allow list）或阻止列表（Deny list）？

### 4. 是否有正式工单或变更记录？
将 `InitiatorUPN` 与受邀域名与 **ITSM** 平台（ServiceNow、Jira Service Management、Freshservice 或 Zendesk）进行交叉核对：
- 是否存在关联有效合同的供应商/第三方入职审批工单？
- 若涉及 Azure RBAC 或特权组授权，是否有已批准的变更工单（Change Ticket）？

### 5. 该会话是否合法？
同时验证邀请发起者与来宾首次登录的会话安全性：
- 若来宾已完成兑换，其登录是否受针对外部用户的条件访问策略保护（例如资源租户强制 MFA）？
- 来宾是否仅访问了共享资源，还是存在目录、用户和内部应用的枚举行为？

---

## 4. 在管理门户中的排查路径

如需直接在 Microsoft Entra admin center（`entra.microsoft.com`）核实 B2B 策略与来宾记录：

1. **检查来宾用户详情：**
   - 路径：`Identity > Users > All users`。
   - 按 `User type == Guest` 筛选并打开目标用户，核对 `Creation type`（`Invitation`）、`External user state`（`Accepted` 或 `PendingAcceptance`）、所属组及应用分配。
2. **核查外部协作策略：**
   - 路径：`Identity > External Identities > External collaboration settings`。
   - 检查 **Guest user access**、**Guest invite settings**（谁可以邀请来宾）以及 **Collaboration restrictions**（域名限制）。
3. **审计来宾登录日志：**
   - 路径：`Identity > Monitoring & health > Sign-in logs`，在 `User` 筛选框中检索 `#EXT#`。

---

## 5. 应急响应、遏制与事后审计

一旦确认外部账号邀请或提权属于未授权行为：

1. **封禁并清理来宾账号：**
   - 在 Entra ID（`Users > [用户 #EXT#]`）中立即执行 **Revoke sessions**（撤销会话），禁用登录（`Account enabled = No`），移除其所有组和角色后再删除账号。
2. **遏制发起邀请的内部账号：**
   - 若怀疑 `InitiatorUPN` 已沦陷，立即执行 **Revoke sessions**、重置密码并核查其已注册的 MFA 方式。
3. **审计近期所有 `#EXT#` 账号的访问记录：**
   - 在 `SigninLogs` 中运行以下 KQL 查询，排查过去 7 天外部用户访问过哪些应用以及条件访问策略是否生效。

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

## 6. 控制映射与合规性

| 框架 / 标准 | 关联控制项 | 实践落地 |
|---|---|---|
| **MITRE ATT&CK** | `T1136.003`（云账号）、`T1098`（账号操纵） | 检测用于持久化的未授权外部账号创建与提权行为。 |
| **NIST CSF 2.0** | `PR.AA-01`（身份管理）、`PR.AA-05`（最小权限） | 限制 B2B 邀请权限并定期开展外部访问评审。 |
| **CIS Controls v8** | `5.3` / `6.8`（休眠账号清理与 RBAC） | 清理过期来宾账号并限制非企业邮箱域名。 |
| **ISO/IEC 27001:2022** | `A.5.18`（访问权限）、`A.5.19`（供应商安全） | 对租户内第三方外部身份实施规范化治理。 |
| **LGPD / GDPR** | LGPD 第 46 条 / GDPR 第 32 条 | 防止外部第三方未授权访问包含个人数据的存储库。 |

