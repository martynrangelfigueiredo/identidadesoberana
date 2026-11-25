---
title: "Microsoft Security 中的旧版身份验证：结合 Entra ID 与 Sentinel 排查 MFA 绕过"
description: "面向 SOC 分析师的 Microsoft Security 应急响应剧本，演示如何使用 Microsoft Sentinel 和 KQL 排查 Entra ID 中的旧版协议登录。"
date: 2026-11-25
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, mfa, kql, soc, dfir]
nivel: Intermediário
draft: false
---

> **TL;DR：** IMAP4、POP3、SMTP AUTH 和 Exchange ActiveSync 等旧版协议不支持现代身份验证或交互式 MFA 质询。一旦在租户（Tenant）中保持启用，便容易成为密码喷洒（*Password Spray*）和 MFA 绕过（*Bypass*）的突破口。本指南介绍如何在 **Microsoft Security** 体系下结合 Microsoft Sentinel、KQL（`SigninLogs` 与 `OfficeActivity`）、ITSM 工单核对以及 Microsoft Entra ID 遏制措施开展调查。

---

## 1. 该事件意味着什么？

在 **Microsoft Security** 生态中，Microsoft Sentinel 会持续监控 `SigninLogs` 表中不支持 OAuth 2.0 和现代多因素身份验证的客户端登录行为。这类事件在 `ClientAppUsed` 字段中通常表现为 `IMAP4`、`POP3`、`Authenticated SMTP`、`Exchange ActiveSync`、`MAPI Over HTTP` 或 `Other clients`。

正如 [Microsoft Learn 上的 Microsoft Sentinel 内置检测目录](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) 以及 [在 Microsoft Entra ID 中阻止旧版身份验证指南](https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication) 所述，攻击者常利用这些接口验证泄露密码或发起密码喷洒攻击（`MITRE ATT&CK T1110.003` 与 `T1078`），从而避开现代浏览器端的保护策略。

### 良性场景与恶意场景对比

| 场景 | 常见指标 | 判定分类 |
|---|---|---|
| **企业多功能打印机或扫描仪** | 来自已知内网/NAT IP 的 `Authenticated SMTP` 请求，使用专用服务账号，无批量失败。 | 虚假阳性（良性——建议迁移至 OAuth 或安全中继） |
| **旧版 ERP 或 CRM 集成应用** | 已登记的技术账号周期性使用 `IMAP4` 或 `POP3`，并在条件访问中拥有正式例外审批。 | 虚假阳性（良性——受控技术债务） |
| **针对 IMAP/POP3 的密码喷洒** | 来自外部 IP、VPS 或异常住宅网络的大量失败尝试（`ResultType` 50126 或 50053），覆盖多个账号。 | 真正阳性（T1110.003） |
| **无 MFA 的成功登录（MFA 绕过）** | `ResultType == "0"` 且 `ClientAppUsed` 为旧版协议、`AuthenticationRequirement == "singleFactorAuthentication"`。 | 严重真正阳性（T1078） |

---

## 2. KQL 查询提示：在 SigninLogs 中筛选旧版协议与 MFA 状态

在 Microsoft Sentinel 中接手事件后，以下查询会从 `SigninLogs` 投影更多上下文列，用于快速确认所使用的旧版协议、结果代码（`ResultType`）、MFA 要求以及源 IP 与国家/地区信息。

```kql
let Lookback = 7d;
SigninLogs
| where TimeGenerated >= ago(Lookback)
| where ClientAppUsed in ("IMAP4", "POP3", "Authenticated SMTP", "SMTP", "Exchange ActiveSync", "Exchange Web Services", "AutoDiscover", "MAPI Over HTTP", "Offline Address Book", "Other clients")
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend City = tostring(LocationDetails.city)
| extend DeviceOS = tostring(DeviceDetail.operatingSystem)
| project
    TimeGenerated,
    UserPrincipalName,
    ClientAppUsed,
    AppDisplayName,
    ResultType,
    ResultDescription,
    ConditionalAccessStatus,
    AuthenticationRequirement,
    IPAddress,
    Country,
    City,
    DeviceOS,
    UserAgent,
    CorrelationId
| order by TimeGenerated desc
```

---

## 3. 调查路线图：5 个必查问题

### 1. 发生了什么操作？
在 `SigninLogs` 中确认该次尝试是**被阻止还是已成功**：
- **`ResultType == "0"`：** 登录已成功且未经过交互式 MFA 验证，应立即按潜在沦陷处置。
- **`ResultType == "53003"`：** 条件访问策略已成功拦截该旧版协议（正常防御状态）。
- **`ResultType == "50126"`：** 密码错误（常见于针对旧版协议的暴力破解或密码喷洒）。
- **`ResultType == "50053"`：** 多次失败后触发 Smart Lockout 锁定。
- 记录 `CorrelationId` 与 `UniqueTokenIdentifier`，便于后续跨日志关联。

### 2. 是谁发起的？
检查 `UserPrincipalName`、`IPAddress` 与 `UserAgent`：
- 受影响账号是否在 Entra ID 中拥有特权角色（如 `Global Administrator`、`Exchange Administrator`）或高敏感邮箱权限？
- `IPAddress` 是否归属云主机（VPS）、匿名代理或与员工日常办公网络不符的自治系统（ASN）？
- 同一 IP 是否同时对租户（Tenant）内的其他账号发起了类似尝试？

### 3. 该账号本应被允许使用吗？
核查旧版协议为何仍对该账号开放：
- 是否已部署面向所有用户的条件访问策略来拦截 `Legacy authentication clients`，或者该账号是否被加入了排除组？
- 在 Exchange Online 中，该邮箱（`CASMailbox`）的 `SmtpClientAuthenticationDisabled`、`ImapEnabled` 或 `PopEnabled` 参数是否仍处于启用状态？

### 4. 是否有正式工单或变更记录？
在认定为内部合法集成前，将 `UserPrincipalName` 与 `IPAddress` 与 **ITSM** 系统（ServiceNow、Jira Service Management、Freshservice 或 Zendesk）进行交叉核对：
- 是否有已批准的变更工单（Change Ticket），记录扫描仪、工单系统或旧版连接器读取该邮箱？
- 若存在已审批例外，请确认事件源 IP 与工单中登记的固定 IP 完全一致。

### 5. 该会话是否合法？
即使员工表示手机或桌面端使用了较旧的邮件客户端，也需验证：
- `UserAgent` 是否符合企业批准的客户端标准（新版 Outlook 应使用现代身份验证，而非 `IMAP4` 或 `Other clients`）？
- 同一时间窗口内，该用户是否存在来自遥远地理位置的其他现代登录会话？

---

## 4. 在管理门户中的排查路径

如需直接在管理后台核对策略、例外配置与完整登录历史：

1. **在 Entra ID 中按旧版客户端筛选登录日志：**
   - 登录 Microsoft Entra admin center（`entra.microsoft.com`）。
   - 路径：`Identity > Monitoring & health > Sign-in logs`。
   - 添加 `Client app` 筛选条件，勾选 `Exchange ActiveSync`、`IMAP4`、`POP3`、`Authenticated SMTP` 和 `Other clients`。
2. **核查条件访问策略：**
   - 路径：`Protection > Conditional Access > Policies`。
   - 确认是否存在针对 `All cloud apps`、条件为 `Client apps = Exchange ActiveSync clients` 与 `Other clients` 且操作为 `Grant = Block access` 的启用策略。
3. **检查 Exchange Online 单邮箱协议开关：**
   - 登录 Exchange admin center（`admin.exchange.microsoft.com`）。
   - 路径：`Recipients > Mailboxes > [用户] > Manage email apps settings`，核实 POP3、IMAP 和 Authenticated SMTP 是否已禁用。

---

## 5. 应急响应、遏制与事后审计

如果确认存在未经授权的旧版协议成功登录（`ResultType == "0"`）：

1. **撤销会话并重置凭据：**
   - 在 Microsoft Entra admin center（`Users > [用户]`）中立即执行 **Revoke sessions**（撤销会话），并强制更换高强度唯一密码。
2. **在账号和租户层面禁用旧版协议：**
   - 在 Exchange Online 中关闭该邮箱的 `IMAP`、`POP` 和 `Authenticated SMTP`，并将该用户移出条件访问的例外组。
3. **审计登录后的邮箱操作：**
   - 在 `OfficeActivity` 表中运行以下 KQL 查询，排查攻击者是否在旧版登录后访问了邮件、创建了转发规则或发送了邮件。

```kql
let TargetUser = "usuario@contoso.com";
let Lookback = 48h;
OfficeActivity
| where TimeGenerated >= ago(Lookback)
| where UserId == TargetUser
| where Operation in (
    "MailItemsAccessed",
    "New-InboxRule",
    "Set-InboxRule",
    "Set-Mailbox",
    "Add-MailboxPermission",
    "Send",
    "SendAs"
)
| project
    TimeGenerated,
    UserId,
    Operation,
    ClientIP,
    ClientInfoString,
    ResultStatus,
    Parameters
| order by TimeGenerated desc
```

---

## 6. 控制映射与合规性

| 框架 / 标准 | 关联控制项 | 实践落地 |
|---|---|---|
| **MITRE ATT&CK** | `T1078`（有效账号）、`T1110.003`（密码喷洒） | 检测不支持 MFA 的旧版协议登录尝试与成功访问。 |
| **NIST CSF 2.0** | `PR.AA-03`（访问管理）、`DE.CM-03`（身份监控） | 通过条件访问阻断旧版认证并在 Sentinel 持续告警。 |
| **CIS Controls v8** | `6.3` / `6.5`（应用与管理员 MFA） | 消除 IMAP/POP3/SMTP 带来的 MFA 绕过路径。 |
| **ISO/IEC 27001:2022** | `A.8.5`（安全身份验证） | 在所有接入入口统一落实强身份验证机制。 |
| **LGPD / GDPR** | LGPD 第 46 条 / GDPR 第 32 条 | 采取技术措施保护邮箱及个人数据免遭未授权访问。 |
