---
title: "Microsoft Security 中的设备代码身份验证：使用 Sentinel 与 KQL 的调查指南"
description: "面向 SOC 分析师的 Microsoft Security 实战剧本，结合 Microsoft Sentinel 与 KQL 调查 Entra ID 中的设备代码钓鱼（Device Code Phishing）及异常登录。"
date: 2026-11-23
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, device-code, kql, soc, dfir]
nivel: Avançado
draft: false
---

> **TL;DR：** OAuth 2.0 *Device Code*（设备代码）流原本面向无浏览器设备（电视、打印机及 CLI）设计，但攻击者常在 *Device Code Phishing* 钓鱼活动中诱导受害者完成认证，从而直接获取已通过 MFA 的有效令牌。本 *Playbook* 介绍如何在 **Microsoft Security** 生态中使用 Microsoft Sentinel、KQL（`SigninLogs`）开展排查并在 Entra ID 中实施遏制。

---

## 1. 该事件意味着什么？

在 **Microsoft Security** 生态系统中，Microsoft Sentinel 会持续监控 `SigninLogs` 表，检测来自非预期应用、异常外部 IP 或无管理员 CLI 历史用户的 `AuthenticationProtocol == "deviceCode"` 登录记录。

在此类攻击（`MITRE ATT&CK T1528`）中，攻击者向 Entra ID 发起设备代码请求（常伪装为 Microsoft Graph PowerShell 或 Azure CLI），随后通过邮件或即时通讯工具将 8–9 位代码发送给受害者，诱导其访问 `microsoft.com/devicelogin`。一旦受害者在浏览器中完成登录和 MFA，其 *Access Token* 和 *Refresh Token* 便会直接下发至攻击者服务器。

如 [Microsoft Learn 上的 Microsoft Sentinel 内置检测目录](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)与 [Entra ID 设备授权流文档](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code)所述，若未通过 *Conditional Access* 限制该流程，攻击者即可实现事实上的会话策略 *绕过 (Bypass)*。

### 良性场景与恶意场景对比

| 场景 | 常见特征 | 分类 |
|---|---|---|
| **管理员在终端使用 Azure CLI / PowerShell** | 已知 IT/DevOps 人员、公司出口 IP 或企业 VPN、`AppDisplayName` 与管理工具一致。 | 虚假阳性 (False Positive) |
| **合法会议室或物联网设备配网** | 位于专用内网网段的会议室系统或资源账户。 | 虚假阳性 (False Positive) |
| **Device Code Phishing 钓鱼** | 非技术岗位员工（财务、人事、高管）的账号从 VPS 或商业 VPN IP 登录 `Microsoft Azure CLI` 或 `Microsoft Graph PowerShell`。 | 严重真正阳性 (T1528) |
| **针对多账户的令牌窃取活动** | 同一外部 `IPAddress` 在同一时段内收到多名员工的成功 `deviceCode` 会话。 | 严重真正阳性 |

---

## 2. KQL 查询提示：在 SigninLogs 中排查 deviceCode 登录流

在 Microsoft Sentinel 中接手该事件时，以下查询会从 `SigninLogs` 投影出若干辅助列，直观呈现所用应用、认证协议、*User-Agent* 以及设备托管合规状态，帮助快速区分正常 CLI 使用与钓鱼攻击。

```kql
let Lookback = 7d;
SigninLogs
| where TimeGenerated >= ago(Lookback)
| where AuthenticationProtocol == "deviceCode" or ClientAppUsed == "Mobile Apps and Desktop clients"
| where AuthenticationProtocol == "deviceCode"
| extend DeviceTrust = tostring(DeviceDetail.trustType)
| extend IsCompliant = tostring(DeviceDetail.isCompliant)
| project
    TimeGenerated,
    UserPrincipalName,
    ResultType,
    AppDisplayName,
    ResourceDisplayName,
    IPAddress,
    Location,
    UserAgent,
    DeviceTrust,
    IsCompliant,
    RiskLevelDuringSignIn,
    CorrelationId
| order by TimeGenerated desc
```

---

## 3. 调查路线图：5 个必问核心问题

为准确判定事件属于真正阳性 (TP) 还是虚假阳性 (FP)，请逐一核实以下五个问题：

### 1. 具体发生了什么？
- 查看 `ResultType`（`0` 表示受害者已输入代码并完成登录；`50140` 或 `70016` 表示流程中断或已过期）。
- 检查 `AppDisplayName` 与 `ResourceDisplayName`（攻击者常借 `Microsoft Azure CLI` 或 `Microsoft Office` 申请 `Microsoft Graph` 权限）。

### 2. 是谁发起的？
- 评估 `UserPrincipalName` 的岗位画像：财务或销售人员通常极少通过 `deviceCode` 使用 `Azure CLI`。
- 检查源 `IPAddress`（在 `deviceCode` 流程中，日志记录的 IP 属于令牌接收方即攻击者，往往与受害者日常 IP 截然不同！）。
- 检查 *User-Agent*（如 Linux 上的 Python/Go/cURL 请求会显著提高恶意概率）。

### 3. 流程是否受到策略限制？
- 核实租户（*Tenant*）是否已配置 *Conditional Access* 策略，禁止普通用户使用 *Authentication flows > Device code flow*。
- 检查是否强制要求合规设备（`IsCompliant == "true"`）或混合加入设备（`DeviceTrust`）。

### 4. 是否有正式变更工单？
- 若涉及远程运维或自动化脚本使用 CLI，必须在 **ITSM** 平台（**ServiceNow**、**Jira Service Management**、**Freshservice** 或 **Zendesk**）中核对工单。
- 通过安全的带外渠道直接向相关员工确认是否在 `microsoft.com/devicelogin` 输入过代码。

### 5. 会话是否合法？
- 在 Microsoft Entra ID Protection 中检查是否伴随风险告警（`Risky sign-ins`、异常登录属性或员工常用 IP 与 `deviceCode` `IPAddress` 之间的不可能的旅行）。
- 若员工确认系收到可疑邮件或消息后输入代码，应立即定性为**真正阳性**。

---

## 4. 在管理门户中的排查路径 (Microsoft Entra admin center)

在 `entra.microsoft.com` 中按以下路径核查：

1. **查看 Device Code 登录记录：**
   `Identity > Monitoring & health > Sign-in logs`（添加筛选条件 **Authentication protocol: Device code** 或按 **Correlation ID** 查询）。
2. **检查认证流条件访问策略：**
   `Protection > Conditional Access > Policies`（确认是否已阻断 *Authentication flows: Device code flow*）。
3. **风险用户列表：**
   `Protection > Identity Protection > Risky users`。

---

## 5. MITRE ATT&CK 与安全控制映射

| 框架 | 编号 | 说明 |
|---|---|---|
| **MITRE ATT&CK** | `T1528` | *Steal Application Access Token*（通过 *Device Code Phishing* 骗取 OAuth 访问令牌）。 |
| **MITRE ATT&CK** | `T1566.002` | *Phishing: Spearphishing Link*（发送 `devicelogin` 链接与验证码）。 |
| **NIST CSF** | `PR.AA-03` / `PR.AA-05` | 通过 *Conditional Access* 严格限制特殊或高风险认证流。 |
| **CIS Controls v8** | `6.5` / `6.3` | 管理访问强制要求受管设备与抗钓鱼 MFA。 |

---

## 6. 应急响应与遏制流程

一旦确认发生 *Device Code Phishing*，请立即执行以下 *Playbook*：

1. **立即撤销会话与令牌：** 在 `Identity > Users > All users` 中选中受影响用户并点击 **Revoke sessions**（使攻击者持有的 *Refresh Token* 立即失效）。
2. **通过 Conditional Access 禁用 Device Code 流：** 在 `Protection > Conditional Access > Policies` 中面向全体用户阻断 `Authentication flows > Device code flow`，仅对确有需求的 IT 运维组放行。
3. **事后 KQL 审计：** 运行以下查询，核实受影响用户在 `deviceCode` 登录之后是否在 `AuditLogs` 中产生了可疑操作（如修改 *Secrets* 或注册新 MFA 设备）：

```kql
let IncidentWindow = 24h;
let DeviceCodeUsers = SigninLogs
    | where TimeGenerated >= ago(IncidentWindow)
    | where AuthenticationProtocol == "deviceCode" and ResultType == 0
    | distinct UserPrincipalName;
AuditLogs
| where TimeGenerated >= ago(IncidentWindow)
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| where Actor in (DeviceCodeUsers)
| project
    TimeGenerated,
    OperationName,
    Category,
    Result,
    Actor,
    SourceIP = tostring(InitiatedBy.user.ipAddress),
    CorrelationId
| order by TimeGenerated desc
```

---

## 参考资料

- [Microsoft Learn — Built-in detections in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Microsoft Learn — Microsoft identity platform and the OAuth 2.0 device authorization grant flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code)
- [MITRE ATT&CK — T1528: Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)

