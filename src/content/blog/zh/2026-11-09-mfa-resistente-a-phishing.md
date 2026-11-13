---
title: "排查 MFA 疲劳轰炸与双因子绕过：SOC 分析师实战演练手册"
description: "Microsoft Sentinel 中 MFA 疲劳攻击（MFA Fatigue）与中间人代理（AitM）事件的排查与处置全流程手册：KQL 日志关联与即时应急响应。"
date: 2026-11-09
categoria: SOC
tags: [sentinel, mfa, entra-id, kql, aitm, incident-response, soc, iam]
nivel: 中级
---

针对多因子身份验证（MFA）的攻击方式已经发生了巨大变化。过去，只要强制开启第二因子即可防范密码泄露；而如今，攻击者已广泛采用 **MFA 疲劳攻击（MFA Fatigue / Push Bombing）** 以及 **中间人反向代理（AitM）** 来绕过传统的二次验证手段。

在 Microsoft Sentinel 中，因 MFA 异常触发的安全警报意味着应急响应团队面临极高风险：该账户的主密码已经泄露，攻击者正试图通过轰炸或欺诈突破最后的访问屏障。

> **SOC 应急摘要（TL;DR）：** 一旦此规则报警，请按凭据已泄露处置。若在连续多次 MFA 拒绝后出现来自未知 IP 的成功登录，应立即执行遏制：撤销活跃会话（`Revoke sessions`）、强制重置密码，并检查攻击者是否在租户中注册了新的身份验证方式。

> 📘 **Microsoft Learn 官方参考文档：** 本演练手册基于 Microsoft Sentinel 内置检测规则与 Entra ID 身份加固最佳实践：
> - [Microsoft Sentinel — 内置定时分析规则目录 (Learn)](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in)
> - [Microsoft Entra ID — 防范 MFA 疲劳攻击与抗钓鱼认证方式 (Learn)](https://learn.microsoft.com/azure/active-directory/authentication/concept-authentication-methods)

---

## 1. 该安全事件意味着什么？

当 Microsoft Sentinel 触发 MFA 异常检测警报时，通常对应以下攻击场景之一：

1. **MFA 疲劳轰炸（Push Bombing）：** 攻击者掌握正确密码，并在深夜向受害者的 Microsoft Authenticator 连续发送数十次推送通知，诱骗员工误触或因烦躁而确认登录。
2. **中间人代理凭据拦截（如 Evilginx / Modlishka）：** 受害者访问了伪造的钓鱼登录页，反向代理实时窃取了密码及 Entra ID 下发的会话 Cookie。
3. **连续拒绝后异常成功登录：** 日志中多次出现错误码 `500121`（MFA 被用户拒绝），随后突然出现状态码 `0`（登录成功），且伴随异常地理位置或 ASN。
4. **正常业务误报：** 员工网络波动或多次重复点击重发验证码。

---

## 2. Dica de KQL: 关联 MFA 拒绝记录与后续成功登录

以下查询在指定时间窗口内关联失败尝试与后续成功登录，提取认证方式、城市、操作系统及风险级别等上下文信息：

```kql
// ====================================================================================
// Detecção & Enriquecimento: MFA Fatigue seguida de Logon Bem-Sucedido
// Autor: Identidade Soberana (identidadesoberana.com.br)
// 目标: 追踪连续被拒的 MFA 并在其后成功登录的异常 IP
// ====================================================================================
let janelaAnalise = 24h;
let limiarFalhasMFA = 3;
// 1. 筛选遭受连续 MFA 拒绝或失败的账户 (ResultType 500121 / 50074)
let NegacoesMFA = SigninLogs
| where TimeGenerated >= ago(janelaAnalise)
| where ResultType in (500121, 50074)
| summarize 
    QtdNegacoes = count(),
    PrimeiraFalha = min(TimeGenerated),
    UltimaFalha = max(TimeGenerated),
    IPsFalha = make_set(IPAddress, 5),
    LocaisFalha = make_set(Location, 5),
    UserAgentsFalha = make_set(UserAgent, 3)
    by UserPrincipalName, bin(TimeGenerated, 15m)
| where QtdNegacoes >= limiarFalhasMFA;
// 2. 检索同一账户在拒绝后的成功登录记录
let LogonsSucesso = SigninLogs
| where TimeGenerated >= ago(janelaAnalise)
| where ResultType == 0
| mv-expand AuthDetail = AuthenticationDetails
| project 
    HoraSucesso = TimeGenerated,
    UserPrincipalName,
    IPSucesso = IPAddress,
    LocalSucesso = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    Dispositivo = DeviceDetail.operatingSystem,
    Navegador = ClientAppUsed,
    MetodoMFA = tostring(AuthDetail.authenticationMethod),
    DetalheMFA = tostring(AuthDetail.authenticationStepResultDetail),
    RiscoSessao = RiskLevelDuringSignIn,
    IDCorrelacao = CorrelationId;
// 3. 时间关联：在连续拒绝后的 30 分钟内发生成功登录
NegacoesMFA
| join kind=inner (LogonsSucesso) on UserPrincipalName
| where HoraSucesso between (UltimaFalha .. (UltimaFalha + 30m))
| project
    DataHoraAlerta = UltimaFalha,
    DataHoraSucesso = HoraSucesso,
    UsuarioAlvo = UserPrincipalName,
    TentativasNegadas = QtdNegacoes,
    MetodoAutenticacao = MetodoMFA,
    ResultadoMFA = DetalheMFA,
    IPLogonSucesso = IPSucesso,
    LocalizacaoSucesso = LocalSucesso,
    IPsAtaque = IPsFalha,
    RiscoSessao = iff(isempty(RiscoSessao), "none", tostring(RiscoSessao)),
    IDCorrelacao = IDCorrelacao
| order by DataHoraSucesso desc
```

---

## 3. 调查排查矩阵：五项核心要点

| 核心问题 | 排查位置 | 重点验证内容 |
|---|---|---|
| **1. 发生了什么操作？** | `SigninLogs` / `AuthenticationDetails` | 触发了多少次 MFA？在连续拒绝后是否有用户主动点击批准？ |
| **2. 谁发起的登录？** | `IPAddress`, `LocationDetails`, ASN | 成功登录的 IP 是属于企业内网/VPN，还是来自公共云或代理节点（AWS、Tor）？ |
| **3. 是否符合常理？** | 用户工作习惯 | 登录时间是否在员工工作时段内？该用户近期是否有差旅记录？ |
| **4. 是否有工单或二次核实？** | ITSM / 跨渠道核实 | 通过**备用通信渠道**（直接电话或企业内部通信）与员工本人确认登录请求。 |
| **5. 会话是否合法？** | `AADUserRiskEvents` & `AuditLogs` | 是否出现*令牌异常（Anomalous Token）*、*陌生登录*或新设备注册？ |

---

## 4. Microsoft Entra 门户排查路径

1. 前往 **Microsoft Entra 管理中心** (`entra.microsoft.com`)。
2. 访问：
   > **Identity** > **Users** > 选择目标用户 > **Sign-in logs**。
3. 查看 **Interactive user sign-ins** 标签页，核对认证方式与条件访问策略执行状态。
4. 在 **Identity Protection** > **Risk detections** 中确认是否存在关联风险。

---

## 5. 处置与遏制响应流程

```
[MFA 疲劳轰炸警报已确认]
        │
        ├── 1. 立即吊销当前所有活跃会话：
        │      Microsoft Entra > Users > [目标用户] > "Revoke sessions"
        │
        ├── 2. 强制重置该账户主密码
        │
        ├── 3. 审计并清理认证方式：
        │      排查是否被绑定了未经授权的新电话号码或 Authenticator 凭证
        │
        ├── 4. 在防火墙 / 条件访问中封禁攻击源 IP
        │
        └── 5. 执行事后取证 KQL 查询
```

### 事后取证 KQL：攻击者在通过 MFA 后执行了什么？

```kql
let usuarioComprometido = "colaborador@seudominio.com.br";
let inicioIncidente = datetime(2026-11-09T00:00:00Z);
AuditLogs
| where TimeGenerated >= inicioIncidente
| mv-expand Target = TargetResources
| where InitiatedBy.user.userPrincipalName == usuarioComprometido
   or Target.userPrincipalName == usuarioComprometido
| where ActivityDisplayName in (
    "User registered security info",
    "User deleted security info",
    "User registered all required security info",
    "Admin registered security info",
    "Add member to role completed (PIM activation)",
    "Add application",
    "Add service principal credentials"
)
| project 
    DataHora = TimeGenerated,
    Operacao = ActivityDisplayName,
    Ator = tostring(InitiatedBy.user.userPrincipalName),
    Alvo = tostring(Target.userPrincipalName),
    PropriedadesModificadas = Target.modifiedProperties,
    IDCorrelacao = CorrelationId
| order by DataHora asc
```

---

## 6. 根治威胁的防御措施

1. **强制开启数字匹配（Number Matching）：** 消除无脑点击批准的安全漏洞。
2. **推送地理位置上下文：** 在移动端推送通知中显示应用名称及发起请求的城市地图。
3. **推进 FIDO2 与 Passkey（抗钓鱼认证）：** 采用与域绑定的物理密钥（YubiKey、Windows Hello），从密码学层面彻底防范 AitM 与疲劳攻击。
