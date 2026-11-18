---
title: "Triagem de Viagem Impossível e IP Anônimo no Microsoft Security com Entra ID Protection e KQL"
description: "Playbook operacional do ecossistema Microsoft Security para investigar alertas de Viagem Impossível e IP Anônimo no Microsoft Entra ID Protection e Microsoft Sentinel."
date: 2026-11-18
categoria: SOC
tags: [microsoft-security, microsoft-sentinel, entra-id, identity-protection, kql, soc, impossible-travel, playbook]
nivel: Intermediário
---

Alertas de **Viagem Impossível** (*Impossible Travel*) e **Uso de IP Anônimo** (*Anonymous IP Address*) estão entre os incidentes mais frequentes na fila de triagem N1 e N2 de qualquer Centro de Operações de Segurança (SOC) que opera o ecossistema **Microsoft Security**.

Na prática, esses alertas surgem quando o **Microsoft Entra ID Protection** identifica duas autenticações bem-sucedidas (ou tentativas) da mesma identidade a partir de localizações geograficamente distantes em um intervalo de tempo fisicamente incompatível com um deslocamento aéreo comercial — ou originadas a partir de nós de saída Tor e VPNs anônimas conhecidas. Contudo, ambientes corporativos modernos com *Split Tunneling*, proxies em nuvem (Zscaler, Netskope) e operadoras móveis geram falsos positivos recorrentes que exigem triagem criteriosa antes de bloquear um usuário.

Este guia apresenta o roteiro completo para diferenciar tráfego corporativo legítimo de um comprometimento real de conta no **Microsoft Security**.

> **TL;DR para o Analista de SOC:** Antes de redefinir a senha ou revogar sessões em um alerta de Viagem Impossível, compare o `UserAgent`, o `DeviceDetail` (ID do dispositivo gerenciado/Intune) e o método de MFA (`AuthenticationDetails`) entre as duas sessões no `SigninLogs`. Dispositivos distintos com bypass de MFA ou mudança abrupta de ASN indicam incidente real.

> 📘 **Referência Oficial no Microsoft Learn:** Este artigo baseia-se nas detecções nativas e documentação oficial do Microsoft Security:
> - [Microsoft Learn — O que são riscos do Microsoft Entra ID Protection](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)
> - [Microsoft Learn — Catálogo de detecções padrão do Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)

---

## 1. Entendendo o Contexto do Incidente no Microsoft Security

No **Microsoft Sentinel**, incidentes de viagem impossível e IP anônimo chegam frequentemente por meio dos conectores do **Microsoft Entra ID Protection** ou regras analíticas correlacionadas no **Microsoft Defender XDR**.

Os cenários principais observados pelos analistas incluem:
1. **Acesso via VPN/Proxy Corporativo (Falso Positivo comum):** O usuário autentica no escritório (IP local) e, 5 minutos depois, um aplicativo em segundo plano renova token passando por um gateway de SASE/SSE em outro país.
2. **Roubo de Credenciais ou Session Hijacking (Verdadeiro Positivo):** Um atacante utiliza credenciais vazadas ou um token roubado (via AiTM phishing) a partir de um servidor VPS, proxy residencial ou rede Tor em outra região.

---

## 2. Dica de KQL: Correlação de SigninLogs e eventos de risco no Sentinel

A consulta abaixo ajuda a contextualizar o incidente listando os eventos recentes do `AADUserRiskEvents` e cruzando com os detalhes de dispositivo, aplicativo e autenticação no `SigninLogs` para o usuário investigado.

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

Para complementar a investigação e visualizar exatamente quais detecções de risco o **Microsoft Entra ID Protection** registrou para a conta, utilize também a tabela `AADUserRiskEvents`:

```kql
let AlvoUsuario = "usuario.suporte@contoso.com";
AADUserRiskEvents
| where TimeGenerated > ago(7d)
| where tolower(UserPrincipalName) == tolower(AlvoUsuario)
| project TimeGenerated, RiskEventType, RiskLevel, RiskState, DetectionTimingType, IpAddress, Location, Source
| order by TimeGenerated desc
```

---

## 3. Roteiro Padrão de Investigação no SOC

Siga os seis passos estruturados abaixo para conduzir uma investigação consistente e auditável:

### 1. O que foi feito?
- Identifique os dois endereços IP envolvidos, os horários exatos (em UTC) e os aplicativos acessados (`AppDisplayName`).
- Verifique se o logon foi **bem-sucedido (`ResultType == 0`)** ou bloqueado por Acesso Condicional (`ResultType == 53003`).
- Anote o `CorrelationId` das duas sessões suspeitas e valide a distância geodésica entre as cidades (você pode usar nossa [Calculadora de Viagem Impossível](/util/distance/) e o [IP Lookup](/util/ipinfo/) para checar o ASN dos dois IPs).

### 2. Quem fez?
- Analise `DeviceDetail.isCompliant` e `DeviceDetail.isManaged`. Se ambos os acessos vieram do **mesmo dispositivo corporativo ingressado no Entra / Intune**, a probabilidade de ser apenas roteamento de VPN ou proxy corporativo é muito alta.
- Verifique `AuthenticationDetails` para confirmar se houve desafio de MFA (`mfa` ou `fido`) ou se a sessão reutilizou um token antigo.
- Se um dos IPs pertence a uma operadora residencial/VPS estrangeira e usa um `UserAgent` incomum (como `python-requests`, `curl` ou navegador distinto do padrão do usuário), trate como suspeito.

### 3. Poderia ter feito?
- Verifique se a conta possui papéis privilegiados no **Microsoft Entra ID** (Global Administrator, Privileged Role Administrator, Exchange Administrator) ou acessos críticos em assinaturas do Azure.
- Confirme se a política de **Acesso Condicional** da organização permite acessos fora do país de origem ou a partir de dispositivos não gerenciados.

### 4. Há chamado formal / ticket?
- Consulte ferramentas de ITSM (ServiceNow, Jira, Freshservice, Zendesk) ou o RH para confirmar se o colaborador registrou aviso de **viagem internacional** ou solicitação de uso de VPN específica.
- Caso o IP pertença ao range oficial de um provedor SASE/SSE homologado pela empresa (ex.: Zscaler, Cloudflare Gateway, GlobalProtect), documente o ASN como tráfego esperado.

### 5. Onde investigar no portal?
Para auditar o histórico completo de risco diretamente na interface do **Microsoft Security**:
- **Riscos da Identidade:** `Microsoft Entra admin center > Protection > Identity Protection > Risky users` e `Risk detections`.
- **Logs de Entrada:** `Microsoft Entra admin center > Identity > Monitoring & health > Sign-in logs` (filtrando pelo `CorrelationId` ou `UserPrincipalName`).
- **Incidente Consolidado:** `Microsoft Defender XDR Portal (security.microsoft.com) > Incidents & alerts > Incidents`.

### 6. Procedimento de resposta e contenção
Se a triagem confirmar comprometimento real (Verdadeiro Positivo):
1. **Revogue todas as sessões ativas imediatamente** (invalidando Refresh Tokens e cookies de sessão):
   ```powershell
   Connect-MgGraph -Scopes "User.ReadWrite.All"
   Revoke-MgUserSignSession -UserId "usuario.suporte@contoso.com"
   ```
2. **Marque o usuário como comprometido** no Entra ID Protection (`Confirm user compromised`), acionando políticas automáticas de risco alto.
3. **Redefina a senha** da conta e audite os métodos de MFA registrados (`Authentication methods`) para garantir que o atacante não cadastrou um novo aplicativo autenticador ou número de telefone.
4. **Audite atividades pós-logon** em `AuditLogs` e `OfficeActivity` (regras de encaminhamento de e-mail, concessões OAuth e downloads no SharePoint/OneDrive).

---

## 4. Tabela de Decisão Rápida para o Analista

| Evidência Encontrada na Triagem | Classificação | Ação Imediata |
| :--- | :--- | :--- |
| Mesmo `DeviceId` gerenciado (Intune), mudança apenas de IP para gateway corporativo/SASE | **Falso Positivo (FP)** | Documentar ASN do gateway homologado e encerrar incidente como benigno. |
| Novo IP em VPS/Tor, dispositivo não gerenciado (`IsManaged == false`), `UserAgent` anômalo | **Verdadeiro Positivo (Crítico)** | Revogar sessões (`Revoke-MgUserSignSession`), redefinir senha, marcar usuário comprometido e auditar MFA/e-mails. |
| Usuário em viagem internacional confirmada em ticket de ITSM utilizando celular corporativo | **Benigno Esperado** | Validar conformidade da política de Acesso Condicional e encerrar com registro do ticket. |
