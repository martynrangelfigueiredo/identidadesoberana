---
title: "Microsoft Security 中的可疑收件箱规则：使用 Sentinel 与 KQL 的调查指南"
description: "面向 SOC 分析师的 Microsoft Security 实战剧本，结合 Microsoft Sentinel 与 KQL 调查 Exchange Online 中的可疑 Inbox Rule 及外部转发事件。"
date: 2026-11-21
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, exchange-online, kql, soc, dfir]
nivel: Intermediário
draft: false
---

> **TL;DR：** 攻击者通过网络钓鱼或 *Adversary-in-the-Middle (AitM)* 获取账户访问权限后，通常会创建收件箱规则（*Inbox Rules*）以隐藏安全告警或将邮件转发至租户（*Tenant*）外部。本 *Playbook* 演示如何在 **Microsoft Security** 生态中使用 Microsoft Sentinel、KQL（`OfficeActivity` 与 `SigninLogs`）开展调查并在 Entra ID 中实施遏制。

---

## 1. 该事件意味着什么？

在 **Microsoft Security** 生态系统中，Microsoft Sentinel 会持续监控 `OfficeActivity` 表（Exchange Online 审计日志），捕获包含隐藏或数据外泄特征的 `New-InboxRule`、`Set-InboxRule` 或 `Enable-InboxRule` 操作——例如将邮件移至 *RSS Subscriptions* 或 *Deleted Items*、自动标记为已读，或配置 `ForwardTo` / `RedirectTo` 转发到外部域名。

根据 [Microsoft Learn 上的 Microsoft Sentinel 内置检测目录](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)以及 [Microsoft Purview 邮箱审计文档](https://learn.microsoft.com/en-us/purview/audit-mailboxes)，该手法（`MITRE ATT&CK T1114.003` 与 `T1564.008`）常见于商业邮件欺诈（*BEC*），用于拦截发票往来并掩盖安全团队发送给受害者的提醒。

### 良性场景与恶意场景对比

| 场景 | 常见特征 | 分类 |
|---|---|---|
| **个人订阅分类整理** | 用户本人在常用公司或家庭 IP 下创建规则，将通知邮件归档至内部文件夹。 | 虚假阳性 (False Positive) |
| **已备案的内部邮件转发** | 规则将业务邮件转发至经审批的共享邮箱或内部工单系统。 | 虚假阳性 (False Positive) |
| **静默隐藏邮件 (BEC / AitM)** | 规则名称简短异常（`.`、`..`、`a`、`zzz`），启用 `MarkAsRead: True`，并将包含 *"invoice"*、*"password"* 或 *"alert"* 的邮件移入 *Deleted Items*。 | 真正阳性 (T1564.008) |
| **外部自动外泄** | 异常 IP 登录后不久即创建指向外部免费邮箱的 `ForwardTo` 或 `RedirectTo` 规则。 | 严重真正阳性 (T1114.003) |

---

## 2. KQL 查询提示：深入分析 OfficeActivity 中的收件箱规则

在 Microsoft Sentinel 中接手该事件时，以下查询会从 `OfficeActivity` 投影出若干辅助列，利用 `mv-expand` 展开规则参数，直接呈现规则名称、源 IP 和具体配置动作。

```kql
let Lookback = 7d;
OfficeActivity
| where TimeGenerated >= ago(Lookback)
| where RecordType == "ExchangeAdmin" or Workload == "Exchange"
| where Operation in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule")
| mv-expand Param = Parameters
| extend ParamName = tostring(Param.Name)
| extend ParamValue = tostring(Param.Value)
| project
    TimeGenerated,
    UserId,
    Operation,
    ClientIP,
    ResultStatus,
    ParamName,
    ParamValue,
    OfficeObjectId
| order by TimeGenerated desc
```

---

## 3. 调查路线图：5 个必问核心问题

为准确判定事件属于真正阳性 (TP) 还是虚假阳性 (FP)，请逐一核实以下五个问题：

### 1. 具体创建了什么规则？
- 检查 KQL 返回结果中的 `ParamName` 与 `ParamValue`：
  - `MoveToFolder` 指向 *Deleted Items*、*Junk Email* 或 *RSS Subscriptions*。
  - `MarkAsRead = True` 或 `DeleteMessage = True`。
  - `ForwardTo`、`ForwardAsAttachmentTo` 或 `RedirectTo` 指向外部收件人。
  - `SubjectContainsWords` 或 `BodyContainsWords` 中包含敏感词（如 `invoice`、`payment`、`bank`、`security`、`MFA`）。

### 2. 是谁执行的操作？
- 确认 `OfficeActivity` 中的 `UserId` 与 `ClientIP`。
- 将 `ClientIP` 与同一时间窗口内的 Entra ID `SigninLogs` 关联，核实：
  - IP 所属 ASN、国家及网络类型（如 VPS、住宅代理或商业 VPN）。
  - 所用 *User-Agent*（异常浏览器会话 vs. 企业标准 Outlook 客户端）。
  - 该账户近期是否发生过 *Secret* 变更或新增 MFA 设备。

### 3. 该操作是否符合策略基线？
- 默认情况下已登录用户均可为自己的邮箱创建 *Inbox Rules*，但**自动外部转发**应通过 Microsoft Defender for Office 365 的出站反垃圾邮件策略予以阻断。
- 若规则是由管理员或服务主体（*Service Principal*）通过远程 PowerShell 创建，请核实其业务合理性。

### 4. 是否有正式变更工单？
- 若规则由 IT 支持团队或自动化流程配置（例如员工离职后的邮箱转交），必须在 **ITSM** 平台（**ServiceNow**、**Jira Service Management**、**Freshservice** 或 **Zendesk**）中交叉核对。
- 确认工单中明确记录了目标邮箱、申请人与主管审批。

### 5. 该登录会话是否合法？
- 在 `SigninLogs` 中核查对应 `ClientIP` 的会话：
  - 是否通过抗钓鱼 MFA（*Passkey* / FIDO2）认证，还是疑似被窃取的会话令牌（*AitM*）。
  - Microsoft Entra ID Protection 是否触发了风险告警（`Risky sign-ins`、异常地理位置或不可能的旅行）。

---

## 4. 在管理门户中的排查路径 (Microsoft Entra & Defender)

在门户中直观核查相关信息：

1. **Entra ID 登录日志 (`entra.microsoft.com`)：**
   `Identity > Monitoring & health > Sign-in logs`（按 `UserId` 和 `OfficeActivity` 中出现的 `ClientIP` 筛选）。
2. **Entra ID 风险用户：**
   `Protection > Identity Protection > Risky users`。
3. **Microsoft Purview / Defender 统一审计日志 (`security.microsoft.com`)：**
   `Audit`（搜索受影响用户的 **New-InboxRule** 与 **Set-InboxRule** 活动）。

---

## 5. MITRE ATT&CK 与安全控制映射

| 框架 | 编号 | 说明 |
|---|---|---|
| **MITRE ATT&CK** | `T1114.003` | *Email Collection: Email Forwarding Rule*（通过自动转发规则窃取邮件）。 |
| **MITRE ATT&CK** | `T1564.008` | *Hide Artifacts: Email Hiding Rules*（利用规则隐藏回复与安全告警）。 |
| **NIST CSF** | `DE.CM-03` / `RS.MI-02` | 监控用户账户活动并快速遏制数据外泄。 |
| **CIS Controls v8** | `9.7` / `8.5` | 管控邮件自动转发并收集详尽的审计日志。 |

---

## 6. 应急响应与遏制流程

一旦确认存在恶意收件箱规则，请立即执行以下 *Playbook*：

1. **在 Entra ID 中撤销活动会话：** 进入 `Identity > Users > All users` 选择该用户，点击 **Revoke sessions**，强制重置密码并清除未确认的新增 MFA 方式。
2. **删除恶意规则：** 通过 Exchange Online PowerShell（`Remove-InboxRule -Identity "<RuleId>" -Mailbox "<UPN>"`）或 Exchange 管理中心删除可疑规则，并检查租户（*Tenant*）级的传输规则（*Transport Rules*）。
3. **核查邮箱级转发设置：** 检查是否被设置了 `ForwardingSmtpAddress`（`Get-Mailbox <UPN> | fl ForwardingSmtpAddress,DeliverToMailboxAndForward`）。
4. **事后 KQL 审计：** 运行以下查询，排查同一 `ClientIP` 在过去 48 小时内是否还访问了其他账户：

```kql
let IncidentWindow = 48h;
let SuspectIPs = OfficeActivity
    | where TimeGenerated >= ago(IncidentWindow)
    | where Operation in ("New-InboxRule", "Set-InboxRule")
    | distinct ClientIP;
SigninLogs
| where TimeGenerated >= ago(IncidentWindow)
| where IPAddress in (SuspectIPs)
| project
    TimeGenerated,
    UserPrincipalName,
    AppDisplayName,
    IPAddress,
    ResultType,
    UserAgent,
    RiskLevelDuringSignIn,
    CorrelationId
| order by TimeGenerated desc
```

---

## 参考资料

- [Microsoft Learn — Built-in detections in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Microsoft Learn — Audit mailbox activity in Microsoft Purview](https://learn.microsoft.com/en-us/purview/audit-mailboxes)
- [MITRE ATT&CK — T1114.003: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003/)

