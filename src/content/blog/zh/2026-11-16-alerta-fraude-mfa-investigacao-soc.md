---
title: "Microsoft Security 恶意认证拦截：MFA 欺诈告警的 SOC 排查与应急响应剧本"
description: "基于 Microsoft Security 生态的实战指南：在 Microsoft Sentinel 中深入排查用户上报欺诈与 MFA 拒绝告警，全面掌握 SigninLogs 与应急处置。"
date: 2026-11-16
categoria: SOC
tags: [microsoft-security, sentinel, soc, entra-id, mfa, kql, incident-response, playbooks, investigacao]
nivel: Intermediário
---

在安全运营中心（SOC）的日常告警中，很少有通知能像**用户主动上报的 MFA 欺诈告警**（*user reported suspicious MFA prompt* 或 *Explicit MFA Deny*）那样需要极高时效的处置响应。与那些在第一阶段就因密码错误而中断的暴力破解或密码喷洒攻击不同，此类告警表明一个极其危险的现状：**攻击者已经掌握了用户的合法主凭据（用户名和密码）**，阻挡攻击者入侵企业环境的唯一屏障，仅仅是用户在二次验证步骤中的主动拒绝。

当员工在 Microsoft Authenticator 移动端收到数字匹配（Number Matching）提示并点击“不是我”时，Microsoft Entra ID 会将此认证失败记录在案，并触发安全审计事件，进而触发 Microsoft Sentinel 的分析检测规则。

> 📘 **Microsoft Learn 官方参考文档：**
> - [Microsoft Entra ID 登录错误代码 — 错误 500121](https://learn.microsoft.com/entra/identity/monitoring-health/concept-sign-ins#sign-in-error-codes)
> - [在 Microsoft Sentinel 中调查突发安全事件](https://learn.microsoft.com/azure/sentinel/investigate-incidents)
> - [Microsoft Sentinel 内置威胁检测规则目录](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in)

---

## 1. MFA 欺诈告警的核心威胁本质

当用户在验证器应用中上报欺诈时，Entra ID 会在 `SigninLogs` 中将其归类为错误代码 **500121**（*Authentication failed during strong authentication request*），并在详细描述中注明用户上报了欺诈或拒绝了提示。

对于 SOC 团队而言，此告警必须立即按高优先级事件（P1 或 P2）进行响应，因为它揭示了三项确凿事实：
1. **凭据已被攻击者掌握：** 攻击者已成功通过第一道身份验证（正确的用户名与密码）。
2. **正在发生的实时交互攻击：** 攻击者当前正驻留在登录网关或企业门户前端发起认证。
3. **后续威胁迫在眉睫：** 攻击者可能转向其他攻击路径，例如 MFA 疲劳轰炸（*push bombing*）、中间人攻击（AitM）截获会话令牌，或尝试未受条件访问 MFA 保护的旧版协议通道。

---

## 2. KQL 查询提示：排查被拒绝和上报为欺诈的 MFA 请求

以下 KQL 查询通过投影关键字段，帮助分析师快速了解认证事件的来龙去脉，定位发起请求的源 IP、目标应用程序以及多因子验证的具体步骤细节：

```kql
// ====================================================================================
// Consulta: Identificando alertas de fraude em MFA e tentativas de logon bloqueadas
// Objetivo: Mapear usuario alvo, IP de origem da tentativa, localizacao e detalhes de autenticacao
// ====================================================================================
let JanelaTempo = 24h;
SigninLogs
| where TimeGenerated >= ago(JanelaTempo)
| where ResultType == 500121
| mv-expand AuthDetail = AuthenticationDetails
| extend DetalhePasso = tostring(AuthDetail.authenticationStepResultDetail)
| where ResultDescription has "fraud" 
     or DetalhePasso has "fraud" 
     or ResultDescription has "denied" 
     or DetalhePasso has "denied"
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    AppDisplayName,
    ClientAppUsed,
    ResultType,
    ResultDescription,
    DetalhePasso,
    RiskLevelDuringSignIn,
    CorrelationId
| order by TimeGenerated desc
```

### 分析要点：
- **`IPAddress` 与 `Location`：** 将触发 MFA 的源 IP 地址与该用户历史的日常登录基线进行对比。若来自未知的异地、数据中心网段、公共代理或 Tor 节点，通常是明确的恶意信号。
- **`AppDisplayName`：** 确认攻击者试图访问的目标，例如 `Azure Portal`、`Office 365 Exchange Online` 或企业内部的单点登录集成应用。
- **`CorrelationId`：** 关联合并字段，可用于在 `AuditLogs` 中快速查找该时间点在租户（Tenant）内产生的联动审计事件。

---

## 3. 研判剧本：SOC 分析师的 5 个必答问题

在 Microsoft Sentinel 界面调查该事件时，分析师应逐项核实以下 5 个关键问题：

### 1. 实际发生了什么动作？
检查事件详细遥测。是否启用了数字匹配（Number Matching）？用户是仅仅点了“拒绝”还是点击了“上报欺诈”？尝试登录的时间是否符合员工的正常工作时段？

### 2. 是谁的操作？涉及哪个账户？
核实受影响的主体（`UserPrincipalName`）。该用户是否属于高管、拥有云基础设施流水线权限的开发人员，或者拥有目录特权（如 *Global Administrator* 或 *Privileged Role Administrator*）的管理员？

### 3. 该行为是否有业务合理性？
确认该员工是否出差或正在配置新的移动设备。如果请求来自于国外的异常自治系统网络（ASN），而员工本人正在国内工位办公，则可直接证实为外部攻击。

### 4. ITSM 工单系统中是否有相关记录？
查询企业的工单系统（ServiceNow、Jira Service Management、Freshservice 或 Zendesk）。员工是否主动向服务台报告自己手机弹出了异常提示？若员工主动提交了工单，有助于快速核实拒绝行为的准确性。

### 5. 账户在告警前后是否发生过已成功的登录？
攻击者在告警触发的前后几分钟内，是否曾通过其他路径（例如缺乏 MFA 策略的旧版协议，或已受信任的设备）成功登入系统？

---

## 4. 在 Microsoft Entra 管理中心深入核查

一线（N1）和二线（N2）分析师若需要直接在 Entra 门户核实底层数据，可执行以下步骤：

1. 打开 **Microsoft Entra 管理中心**（`entra.microsoft.com`）。
2. 进入 **标识（Identity） > 监视与运行状况（Monitoring & health） > 登录日志（Sign-in logs）**。
3. 在**用户登录(交互式)**视图中添加过滤条件：
   - **状态（Status）：** *失败 (Failure)*
   - **错误代码（Error code）：** *500121*
4. 点开对应事件，重点查看：
   - **基本信息（Basic info）：** 关联 ID（Correlation ID）、IP 与物理地理位置。
   - **身份验证详细信息（Authentication Details）：** 确认验证方式（如 *Mobile app notification*）与步骤结果详情（*Fraud reported by user*）。
   - **条件访问（Conditional Access）：** 查看本次登录触发了哪些条件访问策略。
5. 导航至 **标识（Identity） > 保护（Protection） > 风险用户（Risky users）**：
   - 查看该账户是否已被系统标记为**高风险**或**中风险**。
   - 在**风险检测（Risk detections）**中核实是否存在关联事件，如 *Unfamiliar sign-in properties* 或 *Suspicious user reported activity*。

---

## 5. 应急响应与即时处置流程

一旦确认账户密码已经泄露，SOC 团队应按照应急剧本（Playbook）迅速执行阻断动作：

1. **撤销活动会话（*Revoke sessions*）：**
   - 在 Entra 门户的用户面板中点击 **Revoke sessions**（或在 PowerShell 中调用 `Revoke-MgUserSignOut -UserId <UPN>`），使该账户当前所有已签发的刷新令牌（Refresh Token）立即失效。
2. **强制重置登录密码：**
   - 由于攻击者已掌握该口令，必须立即重置密码，并通过安全可靠的带外渠道（Out-of-band）将临时口令通知员工。
3. **核查已注册的身份验证方式（*Authentication methods*）：**
   - 进入 **Identity > Users > [用户] > Authentication methods**，严格核实攻击者是否已提前登记了恶意的备用手机号、第三方 Authenticator 实例或未授权的 FIDO2 安全密钥。
4. **排查持久化后门与邮件转发：**
   - 检查 Exchange Online 中是否被新建了外部邮件自动转发规则（`New-InboxRule` 中的 `ForwardTo`）。
   - 在 `AuditLogs` 中核查该账户在拦截前是否曾向可疑的第三方应用程序授予 OAuth 权限许可。

---

## 6. 事件后 KQL 复盘查询：核对前后并发登录行为

完成处置后，运行以下查询回溯受检账户在过去 48 小时内的完整登录记录，核实是否存在任何成功登录（`ResultType == 0`）：

```kql
// ====================================================================================
// Verificacao Pos-Incidente: Investigando atividade da conta e tentativas com sucesso
// Objetivo: Confirmar se o atacante obteve acesso previo ou posterior ao alerta de fraude
// ====================================================================================
let JanelaAnalise = 48h;
let UsuarioInvestigado = "usuario.alvo@contoso.com";
SigninLogs
| where TimeGenerated >= ago(JanelaAnalise)
| where tolower(UserPrincipalName) == tolower(UsuarioInvestigado)
| extend StatusAuth = iff(ResultType == 0, "Sucesso", "Falha")
| project
    TimeGenerated,
    UserPrincipalName,
    AppDisplayName,
    IPAddress,
    Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    StatusAuth,
    ResultType,
    ResultDescription,
    RiskLevelDuringSignIn,
    RiskState
| order by TimeGenerated desc
```

### 事件定性分析矩阵（TP 与 FP 对比）：

| 研判场景 | 结论分类 | SOC 处置动作 |
|---|---|---|
| 员工本人未发起操作，源 IP 来自异常境外，首次密码验证成功 | **真实阳性 (True Positive)** | 阻断会话、撤销令牌、重置密码，并在终端设备上发起钓鱼与恶意软件排查。 |
| 员工在操作自己手机登录企业应用时不小心误触了“不是我” | **虚假阳性 (False Positive)** | 通过公司内部渠道与员工核实，提供正确使用指导，在 Sentinel 中填写研判记录并关闭告警。 |
| 异常 IP 触发欺诈告警后，随后在旧版未受保护协议中登入成功 | **重大安全事件 (TP)** | 升级至 N3 及数字取证（DFIR）团队进行深入威胁狩猎（Threat Hunting），并在条件访问中封锁旧版协议。 |
