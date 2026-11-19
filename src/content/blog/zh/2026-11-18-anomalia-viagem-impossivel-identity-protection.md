---
title: "Microsoft Security 实战：基于 Entra ID Protection 与 KQL 研判不可能旅行与匿名 IP 告警"
description: "面向 Microsoft Security 生态系统的操作 playbook，全面指导如何在 Microsoft Entra ID Protection 和 Microsoft Sentinel 中研判不可能旅行与匿名 IP 告警。"
date: 2026-11-18
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, identity-protection, kql, soc, impossible-travel, playbook]
nivel: Intermediário
---

在采用 **Microsoft Security** 体系的安全运营中心（SOC）中，**不可能旅行**（*Impossible Travel*）与**匿名 IP 地址**（*Anonymous IP Address*）告警是 N1/N2 分析师日常队列中最常遇到的高优先级事件。

当 **Microsoft Entra ID Protection** 检测到同一身份在极短时间内从地理距离极远的两个位置成功登录（或尝试登录），或者登录请求来自已知的 Tor 出口节点与匿名 VPN 时，就会触发此类告警。然而，在配置了 Split Tunneling（分流隧道）、云代理（Zscaler、Netskope）或移动漫游网络的现代企业中，这类规则也常产生误报，因此需要分析师在封禁账号前进行精准研判。

本指南为您梳理了在 **Microsoft Security** 体系下区分正常办公流量与真实账号失陷的标准化调查流程。

> **SOC 分析师速览（TL;DR）：** 在针对不可能旅行告警执行密码重置或会话吊销前，请务必在 `SigninLogs` 中比对两次会话的 `UserAgent`、`DeviceDetail`（Intune 受管设备 ID）及 MFA 认证方式（`AuthenticationDetails`）。若出现非受管异构设备、MFA bypass 迹象或 ASN 突变，则极可能为真实安全事件。

> 📘 **Microsoft Learn 官方参考：** 本文基于 Microsoft Security 原生检测机制与官方文档编写：
> - [Microsoft Learn — 什么是 Microsoft Entra ID Protection 风险](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)
> - [Microsoft Learn — Microsoft Sentinel 内置威胁检测目录](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)

---

## 1. 理解 Microsoft Security 中的告警上下文

在 **Microsoft Sentinel** 中，不可能旅行与匿名 IP 事件通常由 **Microsoft Entra ID Protection** 数据连接器或 **Microsoft Defender XDR** 的关联分析规则生成。

实战中最常见的两类场景包括：
1. **企业 VPN / 云代理切换（常见误报）：** 员工在本地办公室登录，几分钟后后台应用通过位于另一国家的 SASE/SSE 网关刷新令牌。
2. **凭证窃取或会话劫持（真实阳性）：** 攻击者利用泄露密码或通过 AiTM 钓鱼截获的会话令牌，从境外 VPS、住宅代理或 Tor 网络发起访问。

---

## 2. KQL 查询提示：在 Sentinel 中关联 SigninLogs 与风险事件

以下 KQL 查询可用于快速提取目标账号在 `SigninLogs` 中的近期登录上下文，包括设备合规状态、客户端应用与风险级别：

```kql
let AlvoUsuario = "usuario.suporte@contoso.com";
let JanelaTempo = 24h;
SigninLogs
| where TimeGenerated > ago(JanelaTempo)
| where tolower(UserPrincipalName) == tolower(AlvoUsuario)
| extend DeviceOS = tostring(DeviceDetail.operatingSystem)
| extend Browser = tostring(DeviceDetail.browser)
| extend IsCompliant = tostring(DeviceDetail.isCompliant)
| extend IsManaged = tostring(DeviceDetail.isManaged)
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend City = tostring(LocationDetails.city)
| project TimeGenerated, UserPrincipalName, IPAddress, Country, City, AppDisplayName, ClientAppUsed, UserAgent, DeviceOS, Browser, IsCompliant, IsManaged, ResultType, RiskLevelDuringSignIn
| order by TimeGenerated desc
```

同时，可查询 `AADUserRiskEvents` 表以核实 **Microsoft Entra ID Protection** 为该账号触发的具体风险检测类型：

```kql
let AlvoUsuario = "usuario.suporte@contoso.com";
AADUserRiskEvents
| where TimeGenerated > ago(7d)
| where tolower(UserPrincipalName) == tolower(AlvoUsuario)
| project TimeGenerated, RiskEventType, RiskLevel, RiskState, DetectionTimingType, IpAddress, Location, Source
| order by TimeGenerated desc
```

---

## 3. SOC 标准化六步调查流程

请按以下六个标准化步骤开展规范且可审计的事件调查：

### 1. 发生了什么操作？
- 提取两次登录的源 IP 地址、精确时间（UTC）以及访问的目标应用（`AppDisplayName`）。
- 确认登录是否**成功（`ResultType == 0`）**，或是已被条件访问策略阻断（`ResultType == 53003`）。
- 记录两次会话的 `CorrelationId`，并测算两地地理距离与所需时速（可配合本站 [不可能旅行计算器](/util/distance/) 与 [IP 详情查询](/util/ipinfo/) 核查 ASN）。

### 2. 是谁执行的操作？
- 检查 `DeviceDetail.isCompliant` 和 `DeviceDetail.isManaged`。如果两次请求均来自**同一台已加入 Entra/Intune 的受管企业设备**，则通常是正常的 VPN 或代理路由切换。
- 核对 `AuthenticationDetails`，确认是否经过 MFA 验证（`mfa` / `fido`），还是直接复用了既有令牌。
- 若源 IP 属于境外 VPS/数据中心且伴有异常 `UserAgent`（如 `python-requests`、`curl`），应立即按高危事件处理。

### 3. 账号是否具备相关权限？
- 确认该账号是否在 **Microsoft Entra ID** 中担任高权限角色（如 Global Administrator、Privileged Role Administrator）或拥有关键 Azure 订阅权限。
- 核查组织现有的**条件访问（Conditional Access）**策略是否允许境外登录或非受管设备接入。

### 4. 是否有正式的工单审批？
- 查询 ITSM 系统（ServiceNow、Jira、Freshservice、Zendesk）或向 HR 核实员工是否提交过**跨国差旅报备**。
- 若源 IP 属于企业已备案的 SASE/SSE 网关（如 Zscaler、Cloudflare Gateway），应记录其 ASN 并归档为合规流量。

### 5. 在门户的何处深入排查？
可在 **Microsoft Security** 官方控制台中查看完整的风险上下文：
- **身份风险明细：** `Microsoft Entra admin center > Protection > Identity Protection > Risky users` 与 `Risk detections`。
- **登录审计日志：** `Microsoft Entra admin center > Identity > Monitoring & health > Sign-in logs`（按 `CorrelationId` 或 `UserPrincipalName` 过滤）。
- **关联安全事件：** `Microsoft Defender XDR Portal (security.microsoft.com) > Incidents & alerts > Incidents`。

### 6. 响应与遏制处置规程
一旦研判确认为真实账号失陷（True Positive）：
1. **立即吊销所有活跃会话**（使 Refresh Token 与会话 Cookie 立即失效）：
   ```powershell
   Connect-MgGraph -Scopes "User.ReadWrite.All"
   Revoke-MgUserSignSession -UserId "usuario.suporte@contoso.com"
   ```
2. 在 Entra ID Protection 中**将用户标记为已失陷**（`Confirm user compromised`），触发高风险自动阻断策略。
3. **重置账号密码**并审计已注册的 MFA 认证方式（`Authentication methods`），排查攻击者是否偷偷绑定了新的验证器或手机号。
4. **审计登录后行为：** 在 `AuditLogs` 和 `OfficeActivity` 中排查邮箱自动转发规则、异常 OAuth 授权及 SharePoint/OneDrive 批量下载记录。

---

## 4. SOC 快速研判决策表

| 排查发现的证据 | 研判分类 | 立即处置动作 |
| :--- | :--- | :--- |
| 同一台 Intune 受管 `DeviceId`，仅 IP 切换至企业授权 SASE 网关 | **虚假阳性 (FP)** | 记录合规网关 ASN，按正常办公流量关闭工单。 |
| 新增境外 VPS/Tor IP、非受管设备（`IsManaged == false`）、异常 `UserAgent` | **真实阳性 (严重)** | 吊销会话（`Revoke-MgUserSignSession`）、重置密码、标记账号失陷并全面审计 MFA 与邮箱。 |
| ITSM 工单已确认跨国差旅，且使用受管企业移动设备登录 | **预期合规行为** | 核验条件访问策略执行状态，关联工单号后结案。 |

