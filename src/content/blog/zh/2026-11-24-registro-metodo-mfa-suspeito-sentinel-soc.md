---
title: "Microsoft Security 中的新 MFA 方法注册：使用 Sentinel 与 KQL 的调查指南"
description: "面向 SOC 分析师的 Microsoft Security 实战剧本，结合 Microsoft Sentinel 与 KQL 调查 Entra ID 中的可疑 MFA 方法注册事件。"
date: 2026-11-24
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, mfa, kql, soc, dfir]
nivel: Intermediário
draft: false
---

> **TL;DR：** 当攻击者获取有效凭据或初始访问令牌后，通常会在第一时间向受害者账户注册新的 MFA 验证方式（如 Authenticator 应用、手机号或 *Passkey*），以确保持久化控制。本 *Playbook* 介绍如何在 **Microsoft Security** 生态中使用 Microsoft Sentinel、KQL（`AuditLogs` 与 `SigninLogs`）开展排查与遏制。

---

## 1. 该事件意味着什么？

在 **Microsoft Security** 生态系统中，Microsoft Sentinel 会持续监控 `AuditLogs` 表中 `UserManagement` 类别下与安全信息注册或变更相关的事件（例如 `User registered security info`、`Admin registered security info` 或 `User deleted security info`）。

根据 [Microsoft Learn 上的 Microsoft Sentinel 内置检测目录](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)与 [Entra ID 身份验证方法活动文档](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity)，该手法（`MITRE ATT&CK T1098.005` / `T1556.006`）可使攻击者在受害者修改密码后依然维持访问权限，除非管理员同步清除其绑定的 MFA 设备。

### 良性场景与恶意场景对比

| 场景 | 常见特征 | 分类 |
|---|---|---|
| **新员工入职或更换手机** | 从公司已知出口 IP/VPN 发起、使用合规托管设备（`IsCompliant == true`）且发生在工作时间。 | 虚假阳性 (False Positive) |
| **服务台协助重置 (TAP)** | 授权管理员在有正式工单的前提下签发 *Temporary Access Pass*，用户随后注册新 *Passkey* / FIDO2。 | 虚假阳性 (False Positive) |
| **钓鱼 / AitM 后的持久化** | 在异常 IP（VPS、商业 VPN 或非常用国家）登录后不久即绑定新 MFA 方法，且无托管设备。 | 严重真正阳性 (T1098.005) |
| **删除原有合法验证方式** | 添加未知设备后紧接着删除员工原本使用的验证器。 | 严重真正阳性 |

---

## 2. KQL 查询提示：在 AuditLogs 中分析安全信息变更细节

在 Microsoft Sentinel 中接手该事件时，以下查询会从 `AuditLogs` 投影出若干辅助列，直接显示被修改的用户、操作发起者、结果原因（`ResultReason`）以及具体变更的属性详情。

```kql
let Lookback = 7d;
AuditLogs
| where TimeGenerated >= ago(Lookback)
| where OperationName has_any ("security info", "authentication method", "strong authentication")
| mv-expand Target = TargetResources
| mv-expand ModProp = Target.modifiedProperties
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend SourceIP = tostring(InitiatedBy.user.ipAddress)
| extend TargetUser = tostring(Target.userPrincipalName)
| extend PropName = tostring(ModProp.displayName)
| extend NewValue = tostring(ModProp.newValue)
| project
    TimeGenerated,
    OperationName,
    Result,
    ResultReason,
    TargetUser,
    InitiatorUPN,
    SourceIP,
    PropName,
    NewValue,
    CorrelationId
| order by TimeGenerated desc
```

---

## 3. 调查路线图：5 个必问核心问题

为准确判定事件属于真正阳性 (TP) 还是虚假阳性 (FP)，请逐一核实以下五个问题：

### 1. 具体做了什么变更？
- 查看 KQL 结果中的 `OperationName`、`ResultReason` 与 `NewValue`。
- 确认**新增或删除了哪种方法**（例如 *Microsoft Authenticator App*、*PhoneAppNotification*、*PhoneNumber*、*FIDO2*）。
- 若同时出现 `User registered security info` 与 `User deleted security info`，需高度警惕。

### 2. 是谁执行的操作？
- 对比 `InitiatorUPN` 与 `TargetUser`：
  - 若一致，说明由用户本人（或持有其活跃会话的攻击者）发起。
  - 若不一致，则由身份管理员或服务主体（*Service Principal*）代为操作。
- 将 `SourceIP` 与时间点关联至 `SigninLogs`，核查国家、ASN、*User-Agent* 以及是否使用了 *Temporary Access Pass* 或 `deviceCode` 流。

### 3. 策略是否允许在外部注册？
- 核实租户（*Tenant*）是否通过 *Conditional Access* 保护安全信息注册（*Register security information*）：
  - 是否要求受信任网络、合规设备或 *Temporary Access Pass*？
  - 若任意外部 IP 仅凭密码或初始令牌即可绑定第二因素，则存在明显的防御 *绕过 (Bypass)* 风险。

### 4. 是否有正式变更工单？
- 若涉及更换公司手机或服务台协助，必须在 **ITSM** 平台（**ServiceNow**、**Jira Service Management**、**Freshservice** 或 **Zendesk**）中核对工单。
- 通过电话或其他可信带外渠道直接向员工确认是否曾在该时间点绑定新设备。

### 5. 该会话是否合法？
- 在 Microsoft Entra ID Protection 中核查 `SourceIP` 对应会话是否触发风险告警（`Risky sign-ins`、异常登录属性或不可能的旅行）。
- 核查同一会话在 `SigninLogs` 中的 `DeviceDetail.isCompliant` 与 `DeviceDetail.trustType`。

---

## 4. 在管理门户中的排查路径 (Microsoft Entra admin center)

在 `entra.microsoft.com` 中按以下路径核查：

1. **查看用户已绑定的 MFA 方法：**
   `Identity > Users > All users > [用户] > Authentication methods`（逐一核对设备名称、注册时间与电话号码）。
2. **认证方法注册活动报告：**
   `Protection > Authentication methods > Activity`（查看 *Registration* 与 *Usage* 选项卡）。
3. **门户审计日志：**
   `Identity > Monitoring & health > Audit logs`（按 **Target** 或 **Correlation ID** 筛选）。

---

## 5. MITRE ATT&CK 与安全控制映射

| 框架 | 编号 | 说明 |
|---|---|---|
| **MITRE ATT&CK** | `T1098.005` | *Account Manipulation: Device Registration*（未授权注册 MFA/设备以维持持久化）。 |
| **MITRE ATT&CK** | `T1556.006` | *Modify Authentication Process: Multi-Factor Authentication*（篡改多因素认证配置）。 |
| **NIST SP 800-63B** | `AAL2` / `AAL3` | 安全绑定身份验证器，并优先采用抗钓鱼 *Passkeys* / FIDO2。 |
| **CIS Controls v8** | `6.3` / `6.5` | 通过受信任网络或托管设备策略保护 MFA 注册流程。 |

---

## 6. 应急响应与遏制流程

若员工否认曾进行过该操作或会话存在可疑迹象，请立即执行以下 *Playbook*：

1. **删除恶意 MFA 方法：** 在 `Identity > Users > All users > [用户] > Authentication methods` 中立即移除未知的验证器或手机号码。
2. **撤销会话并重置密码：** 点击 **Revoke sessions** 并立即更改密码；若员工原有合法 MFA 已被删除，可在核验身份后签发一次性 *Temporary Access Pass*。
3. **加固 Conditional Access：** 针对用户操作 **Register security information** 配置策略，要求必须来自企业网络或合规设备。
4. **事后 KQL 审计：** 运行以下查询，核查受影响账户过去 48 小时的全部登录记录，并排查是否衍生出应用 *Secrets* 变更或邮箱转发规则：

```kql
let IncidentWindow = 48h;
let TargetAccount = "usuario@contoso.com";
SigninLogs
| where TimeGenerated >= ago(IncidentWindow)
| where UserPrincipalName == TargetAccount
| project
    TimeGenerated,
    ResultType,
    AppDisplayName,
    IPAddress,
    Location,
    UserAgent,
    AuthenticationRequirement,
    RiskLevelDuringSignIn,
    CorrelationId
| order by TimeGenerated desc
```

---

## 参考资料

- [Microsoft Learn — Built-in detections in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Microsoft Learn — Authentication methods activity in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity)
- [MITRE ATT&CK — T1098.005: Device Registration](https://attack.mitre.org/techniques/T1098/005/)
