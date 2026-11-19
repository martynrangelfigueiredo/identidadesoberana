---
title: "Microsoft Security 中的条件访问策略变更：使用 Sentinel 与 KQL 的调查指南"
description: "面向 SOC 分析师的 Microsoft Security 实战应急响应剧本，结合 Microsoft Sentinel 与 KQL 调查 Entra ID 条件访问策略变更或停用事件。"
date: 2026-11-19
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, conditional-access, kql, soc, dfir]
nivel: Intermediário
draft: false
---

> **TL;DR：** 未经计划的 *Conditional Access*（条件访问）策略变更可能会悄悄打开 MFA *绕过 (Bypass)* 或无限制访问关键应用的缺口。本 *Playbook* 详细介绍如何在 Microsoft Sentinel 中进行事件分诊、编写针对 `AuditLogs` 和 `SigninLogs` 的 KQL 查询、关联 ITSM 工单并在 Entra ID 中执行遏制措施。

---

## 1. 该事件意味着什么？

在 **Microsoft Security** 生态系统中，Microsoft Sentinel 会持续监控 Microsoft Entra ID `AuditLogs` 表中的管理操作事件。当某条条件访问策略被修改、切换为 *Report-only*（仅报告）模式、被停用 (*Off*) 或删除，或者新增了排除项（用户、组或 *Named Location*）时，标准分析规则会触发高优先级事件。

[Microsoft Learn 上的 Microsoft Sentinel 内置检测目录](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)与[Microsoft Entra ID 条件访问概述](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview)均指出，该控制平面的变更会直接影响整个租户 (*Tenant*) 的零信任安全基线。

### 良性场景与恶意场景对比

| 场景 | 常见特征 | 分类 |
|---|---|---|
| **已批准的维护窗口 / 变更工单** | 已知管理员操作、ITSM 存在对应审批工单、工作时间内执行、会话采用抗钓鱼 MFA。 | 虚假阳性 (False Positive) |
| **通过 IaC（基础设施即代码）自动化变更** | 由授权的 *Service Principal*（如 Terraform/Bicep 流水线）从企业固定 IP 或已知 Runner 发起。 | 虚假阳性 (False Positive) |
| **入侵后的静默排除** | 攻击者利用高权限凭据将后门账户加入 *Exclude* 列表，或关闭 MFA 强制要求。 | 真正阳性 (T1562.001) |
| **添加恶意 Named Location** | 将未知外部 IP 段标记为可信位置 (*Trusted Location*)，以方便后续策略 *绕过 (Bypass)*。 | 真正阳性 (T1562 / T1098) |

---

## 2. KQL 查询提示：关联分析条件访问变更上下文

在 Microsoft Sentinel 中接手此类事件时，以下查询会从 `AuditLogs` 投影出若干实用字段，帮助快速定位被修改的策略名称、具体操作类型及发起者，无需手动翻阅冗长的 JSON。

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

## 3. 调查路线图：5 个必问核心问题

为准确判定事件属于真正阳性 (TP) 还是虚假阳性 (FP)，请逐一核实以下五个问题：

### 1. 具体做了什么操作？
- 查看 KQL 结果中的 `OperationName`、`OldValue` 和 `NewValue`。
- **重点排查项：**
  - 策略状态是否从 `enabled` 变为 `disabled` 或 `enabledForReportingButNotEnforced` (*Report-only*)？
  - `excludeUsers` / `excludeGroups` 中是否新增了账户或安全组？
  - *Named Locations* 中是否将新的 IP 段标记为 `isTrusted: true`？
- 记录 `CorrelationId`，以便追踪同一管理会话中的关联操作。

### 2. 是谁发起的操作？
- 检查 `InitiatorUPN`（人类用户）或 `InitiatorApp`（服务主体 / *Service Principal*）。
- 若为用户操作，请关联相近时间的 `SigninLogs` 核实：
  - 源 IP (`SourceIP`)、地理位置与 ASN。
  - 该会话是否通过抗钓鱼 MFA（*Passkey* / FIDO2）或较弱的认证方式完成。
  - 该操作员账户近期是否发生过 *Secret* 或认证方式变更。

### 3. 该主体是否有权执行此操作？
- 并非所有用户都应具备修改条件访问策略的权限。确认发起者是否在 Entra ID 中拥有以下授权角色之一：
  - **Conditional Access Administrator**
  - **Security Administrator**
  - **Global Administrator**
- 若角色通过 PIM (*Privileged Identity Management*) 托管，需确认是否存在合法的事前激活记录与理由。

### 4. 是否有正式的变更工单？
- 必须与组织的 **ITSM** 平台（**ServiceNow**、**Jira Service Management**、**Freshservice** 或 **Zendesk**）进行交叉核对。
- 确认是否存在已获批的变更工单，且其范围、策略名称与执行窗口完全匹配。
- 检查 `ResultReason` 或 PIM 激活理由中是否注明了工单编号。

### 5. 该会话是否合法？
- 在 Microsoft Entra ID Protection 中核查用户或会话是否存在高风险标记（`RiskLevelDuringSignIn` 或 `RiskState`）。
- 检查 `SigninLogs` 中的 *User-Agent*：来自非自动化服务器、住宅 IP 或商业 VPN 的自动化脚本请求（`python-requests`、`curl`、`PowerShell`）通常是账户失陷的强烈信号。

---

## 4. 在管理门户中的排查路径 (Microsoft Entra admin center)

如需在门户 (`entra.microsoft.com`) 中直观核对策略当前状态与历史记录，请按以下路径导航：

1. **检查被修改的策略：**
   `Protection > Conditional Access > Policies`（按 `PolicyName` 找到策略，核对 *Users*、*Target resources*、*Conditions* 和 *Grant*）。
2. **核查 Named Locations：**
   `Protection > Conditional Access > Named locations`（检查是否新增了可信 IP 段或国家/地区）。
3. **门户审计日志：**
   `Identity > Monitoring & health > Audit logs`（按 **Category: Policy** 和 **Correlation ID** 过滤）。

---

## 5. MITRE ATT&CK 与安全控制映射

| 框架 | 编号 | 说明 |
|---|---|---|
| **MITRE ATT&CK** | `T1562.001` | *Impair Defenses: Disable or Modify Tools*（削弱或停用访问控制策略）。 |
| **MITRE ATT&CK** | `T1098` | *Account Manipulation*（将账户或组加入策略排除列表）。 |
| **NIST CSF** | `PR.AA-05` | 持续审查访问控制与最小权限原则。 |
| **CIS Controls v8** | `6.3` / `6.5` | 管理员与远程访问强制实施 MFA，禁止未经记录的例外。 |

---

## 6. 应急响应与遏制流程

若调查确认该变更**没有**对应授权工单或源自可疑会话，请立即执行以下应急响应剧本 (*Playbook*)：

1. **立即回滚策略：** 在 `Protection > Conditional Access > Policies` 中恢复原有状态 (`On`)，或从 *Exclude* 列表中移除未授权的用户/IP。
2. **撤销会话 (*Revoke sessions*)：** 在 `Identity > Users > All users` 中打开涉事用户页面，点击 **Revoke sessions**，并在怀疑凭据泄露时重置密码及 MFA。
3. **审计 Service Principal：** 若操作来自应用程序，请立即检查该 *Service Principal* 的 *Client Secret* 及权限（`Policy.ReadWrite.ConditionalAccess`）。
4. **事后 KQL 审计：** 运行以下查询，排查策略变更后是否已有无 MFA 验证或来自可疑 IP 的成功登录：

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

## 参考资料

- [Microsoft Learn — Built-in detections in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Microsoft Learn — What is Conditional Access in Microsoft Entra ID?](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview)
- [MITRE ATT&CK — T1562.001: Impair Defenses](https://attack.mitre.org/techniques/T1562/001/)

