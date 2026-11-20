---
title: "Microsoft Security 中的密码喷洒检测：使用 Sentinel 与 KQL 排查 Entra ID 实战指南"
description: "面向 SOC 分析师的 Microsoft Security 实战剧本，结合 Microsoft Sentinel 与 KQL 调查 Entra ID 中的密码喷洒（Password Spraying）攻击。"
date: 2026-11-20
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, password-spraying, kql, soc, dfir]
nivel: Intermediário
draft: false
---

> **TL;DR：** 密码喷洒（*Password Spraying*）攻击会针对数十甚至上百个账户尝试少量常见密码，以规避单账户锁定策略。本 *Playbook* 介绍如何在 **Microsoft Security** 生态中利用 Microsoft Sentinel 对 `SigninLogs` 执行 KQL 关联分析、排查攻击后的成功登录并在 Entra ID 中实施遏制。

---

## 1. 该事件意味着什么？

在 **Microsoft Security** 生态系统中，Microsoft Sentinel 会持续监控 `SigninLogs` 表，检测短时间内来自同一 IP、分散在多个不同 `UserPrincipalName` 上的身份验证失败事件（如 `50126` 用户名或密码无效、`50053` 触发 *Smart Lockout*）。

与针对单一账户的传统暴力破解不同，密码喷洒（`MITRE ATT&CK T1110.003`）是在整个租户（*Tenant*）范围内横向尝试。根据 [Microsoft Learn 上的 Microsoft Sentinel 内置检测目录](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)与 [Microsoft Entra ID 密码保护文档](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-combined-policy)，最大风险在于攻击命中未启用 MFA 或仍开启旧版身份验证的账户。

### 良性场景与恶意场景对比

| 场景 | 常见特征 | 分类 |
|---|---|---|
| **企业代理 / 共享出口 NAT** | 源 IP 属于企业自有 ASN，多个账户在批量密码过期或重置后集中输错密码。 | 虚假阳性 (False Positive) |
| **旧版应用缓存过期凭据** | 同一 `AppDisplayName` 与已知企业 `UserAgent` 在密码轮换后持续报错。 | 虚假阳性 (False Positive) |
| **分布式密码喷洒攻击** | 来自廉价 VPS、商业 VPN 或住宅宽带的 IP 对数十个账户各尝试 1–2 次，常伴随脚本 `UserAgent`（如 `python-requests`、`curl`）。 | 真正阳性 (T1110.003) |
| **撞库/喷洒命中并成功登录** | 同一 IP 先对大量账户产生 `ResultType == 50126`，随后对某个账户返回 `ResultType == 0`。 | 严重真正阳性 |

---

## 2. KQL 查询提示：按源 IP 与受影响账户关联失败登录

在 Microsoft Sentinel 中处理该事件时，以下查询会从 `SigninLogs` 投影出若干辅助列，帮助快速汇总每个 IP 测试的唯一账户数、错误代码分布以及同一时间窗口内是否出现成功登录。

```kql
let Lookback = 24h;
SigninLogs
| where TimeGenerated >= ago(Lookback)
| where ResultType in ("50126", "50053", "50055", "50057", "0")
| summarize
    TotalAttempts = count(),
    DistinctAccounts = dcount(UserPrincipalName),
    FailedAttempts = countif(ResultType != "0"),
    SuccessCount = countif(ResultType == "0"),
    ErrorCodes = make_set(ResultType, 10),
    SampleApps = make_set(AppDisplayName, 5),
    SampleAgents = make_set(UserAgent, 5),
    TargetedUsers = make_set(UserPrincipalName, 10)
    by IPAddress
| where DistinctAccounts >= 5 and FailedAttempts >= 10
| project
    IPAddress,
    DistinctAccounts,
    TotalAttempts,
    FailedAttempts,
    SuccessCount,
    TargetedUsers,
    ErrorCodes,
    SampleApps,
    SampleAgents
| order by SuccessCount desc, DistinctAccounts desc
```

---

## 3. 调查路线图：5 个必问核心问题

为准确判定事件属于真正阳性 (TP) 还是虚假阳性 (FP)，请逐一核实以下五个问题：

### 1. 具体发生了什么？
- 统计受波及的独立账户数量（`DistinctAccounts`）及 `AADSTS` 错误码：
  - `50126`：密码错误。
  - `50053`：账户被 *Smart Lockout* 锁定。
  - `0`：**最高优先级告警** — 表明密码已猜中。
- 检查攻击目标是现代认证端点还是旧版协议（`ClientAppUsed` 如 IMAP、POP3、SMTP）。

### 2. 是谁发起的？
- 分析源 `IPAddress`、所属 ASN 及威胁情报（*Threat Intelligence*）信誉评分。
- 若源 IP 来自廉价云主机、Tor 出口节点或企业业务区域以外的住宅网络，恶意可能性极高。
- 若涉及服务主体（*Service Principal*），需同步排查 `AADServicePrincipalSignInLogs` 是否存在针对 *Client Secret* 的试探。

### 3. 暴露面是否受控？
- 评估受影响账户的防御基线：
  - 账户是否已启用抗钓鱼 MFA（*Passkey* / FIDO2）？
  - *Conditional Access* 策略是否已彻底禁用旧版身份验证？
  - 租户（*Tenant*）是否已开启 *Microsoft Entra Password Protection* 弱密码拦截？

### 4. 是否有正式工单？
- 若怀疑为授权渗透测试（*Pentest* 或内部 *Red Team*），必须与 **ITSM** 平台（**ServiceNow**、**Jira Service Management**、**Freshservice** 或 **Zendesk**）交叉核对。
- 确认源 IP、时间窗口与测试范围是否与已批准的变更或安全测试工单完全一致。

### 5. 成功会话是否合法？
- 对 `SuccessfulUsers`（`ResultType == 0`）中的所有账户立即核查：
  - 是否通过了 MFA 校验（`AuthenticationRequirement == "multiFactorAuthentication"`）？
  - Entra ID Protection 是否标记了高登录风险（`RiskLevelDuringSignIn`）？
  - *UserAgent* 与地理位置是否偏离该员工的历史登录基线？

---

## 4. 在管理门户中的排查路径 (Microsoft Entra admin center)

在 `entra.microsoft.com` 中可直接查看以下页面：

1. **详细登录日志：**
   `Identity > Monitoring & health > Sign-in logs`（按可疑 `IPAddress` 以及 **Status: Failure / Success** 筛选）。
2. **风险用户与风险登录：**
   `Protection > Identity Protection > Risky sign-ins` 与 `Risky users`。
3. **Smart Lockout 与禁用密码策略：**
   `Protection > Authentication methods > Password protection`。

---

## 5. MITRE ATT&CK 与安全控制映射

| 框架 | 编号 | 说明 |
|---|---|---|
| **MITRE ATT&CK** | `T1110.003` | *Brute Force: Password Spraying*（针对多账户横向试探常见密码）。 |
| **MITRE ATT&CK** | `T1078.004` | *Valid Accounts: Cloud Accounts*（利用喷洒命中的有效云端账户）。 |
| **NIST CSF** | `PR.AA-03` | 实施抗钓鱼多因素认证与防密码猜测保护。 |
| **CIS Controls v8** | `6.3` / `5.2` | 强制启用 MFA 并实施强唯一密码策略。 |

---

## 6. 应急响应与遏制流程

若确认为恶意喷洒活动（尤其是 `SuccessCount > 0`），请立即执行以下 *Playbook*：

1. **遏制已命中账户：** 针对来自攻击 IP 的 `SuccessfulUsers`，进入 `Identity > Users > All users` 点击 **Revoke sessions**，强制重置密码并清理未知的 MFA 注册设备。
2. **封锁源 IP：** 在条件允许的情况下，通过 *Conditional Access* 的受阻 *Named Location* 或边界防火墙/WAF 封禁攻击源 IP。
3. **阻断旧版协议：** 确保已部署阻止 *Legacy Authentication* 的 *Conditional Access* 策略，防止 MFA *绕过 (Bypass)*。
4. **事后 KQL 审计：** 运行以下查询，核实攻击 IP 在喷洒期间及之后是否触发了敏感审计操作（如注册新 MFA 方式或异常应用授权）：

```kql
let IncidentWindow = 24h;
let SuspectIPs = SigninLogs
    | where TimeGenerated >= ago(IncidentWindow)
    | where ResultType in ("50126", "50053")
    | summarize Accounts = dcount(UserPrincipalName) by IPAddress
    | where Accounts >= 5
    | project IPAddress;
AuditLogs
| where TimeGenerated >= ago(IncidentWindow)
| extend ActorIP = tostring(InitiatedBy.user.ipAddress)
| where ActorIP in (SuspectIPs)
| project
    TimeGenerated,
    OperationName,
    Category,
    Result,
    Actor = tostring(InitiatedBy.user.userPrincipalName),
    ActorIP,
    CorrelationId
| order by TimeGenerated desc
```

---

## 参考资料

- [Microsoft Learn — Built-in detections in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Microsoft Learn — Password protection in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-combined-policy)
- [MITRE ATT&CK — T1110.003: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
