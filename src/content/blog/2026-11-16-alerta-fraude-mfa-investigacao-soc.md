---
title: "Alerta de fraude no MFA no Microsoft Security: playbook de triagem e resposta a incidentes para analistas de SOC"
description: "Roteiro prático no ecossistema Microsoft Security para investigar alertas de MFA Deny e fraude reportada no Microsoft Sentinel, analisando SigninLogs, AuditLogs e contenção no Entra ID."
date: 2026-11-16
categoria: SOC
tags: [microsoft-security, sentinel, soc, entra-id, mfa, kql, incident-response, playbooks, investigacao]
nivel: Intermediário
---

Em um Centro de Operações de Segurança (SOC), poucas notificações exigem uma resposta tão ágil quanto um alerta de **fraude reportada no MFA** (*user reported suspicious MFA prompt* ou *Explicit MFA Deny*). Diferente de tentativas genéricas de força bruta ou varreduras de senhas que falham no primeiro fator, este alerta indica uma condição crítica: **o atacante já possui as credenciais primárias legítimas (usuário e senha)** e a única barreira que impediu o acesso foi a recusa ativa do usuário no segundo fator.

Quando o colaborador recebe uma notificação de correspondência de números (*number matching*) no Microsoft Authenticator e seleciona "Não sou eu", o Microsoft Entra ID registra a falha de autenticação e gera eventos de auditoria que alimentam as regras analíticas do Microsoft Sentinel. 

> 📘 **Referência Oficial no Microsoft Learn:**
> - [Códigos de erro de entrada do Microsoft Entra ID — Erro 500121](https://learn.microsoft.com/entra/identity/monitoring-health/concept-sign-ins#sign-in-error-codes)
> - [Investigação de incidentes no Microsoft Sentinel](https://learn.microsoft.com/azure/sentinel/investigate-incidents)
> - [Catálogo de detecções e regras analíticas do Microsoft Sentinel](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in)

---

## 1. O que o Alerta de Fraude no MFA Representa?

Quando um usuário reporta fraude no aplicativo autenticador, o Entra ID classifica o evento no `SigninLogs` sob o código de erro **500121** (*Authentication failed during strong authentication request*), acompanhado da descrição específica de fraude reportada ou solicitação negada.

Para a equipe de SOC, esse evento deve ser tratado imediatamente como um incidente de alta prioridade (P1 ou P2), pois revela três certezas:
1. **Credenciais válidas em mãos do adversário:** O invasor autenticou com sucesso na primeira etapa (usuário e senha corretos).
2. **Tentativa ativa e em tempo real:** O atacante está interagindo com o portal ou aplicação naquele exato momento.
3. **Alvo sob risco iminente:** O invasor pode tentar outros vetores, como fadiga de MFA (*push bombing*), ataques Adversary-in-the-Middle (AitM) para captura de tokens de sessão, ou pulverização em serviços legados que não exigem MFA.

---

## 2. Dica de KQL: Investigando solicitações de MFA negadas e reportadas como fraude

A consulta abaixo projeta algumas colunas úteis para contextualizar o evento de autenticação, mapeando o IP de origem da tentativa, a aplicação solicitada e o detalhe do passo de MFA:

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

### O que observar nos resultados:
- **`IPAddress` e `Location`:** Compare o endereço IP que originou o disparo do MFA com o histórico habitual do usuário. Endereços de VPN comerciais, proxies anônimos, nós Tor ou países não usuais são fortes indicadores de atividade maliciosa externa.
- **`AppDisplayName`:** Identifica se o atacante tentou acessar o portal corporativo (`Azure Portal`), o e-mail (`Office 365 Exchange Online`) ou uma aplicação de terceiros federada.
- **`CorrelationId`:** Chave fundamental para cruzar este evento no `AuditLogs` e rastrear ações simultâneas no tenant.

---

## 3. Roteiro de Investigação: As 5 Perguntas Obrigatórias

Durante o atendimento do incidente no Microsoft Sentinel, o analista deve responder às seguintes perguntas para determinar se houve comprometimento parcial ou total:

### 1. O que foi feito?
Verifique a telemetria do evento. A tentativa utilizou correspondência de números (*number matching*)? O colaborador apenas clicou em "Negar" ou selecionou explicitamente "Reportar Fraude"? O horário da tentativa coincide com o expediente normal do colaborador?

### 2. Quem fez?
Analise a conta afetada (`UserPrincipalName`). Trata-se de um usuário VIP, membro da diretoria, desenvolvedor com acesso a pipelines ou analista com papéis administrativos (como *Global Administrator* ou *Privileged Role Administrator*)?

### 3. Poderia ter feito?
Verifique se o colaborador estava viajando a trabalho ou realizando alguma configuração legítima em novo dispositivo móvel. Se a tentativa partiu de um ASN residencial comum no exterior enquanto o usuário trabalha presencialmente no Brasil, a hipótese de ataque externo é reforçada.

### 4. Há chamado formal ou ticket no ITSM?
Consulte a ferramenta de ITSM (ServiceNow, Jira Service Management, Freshservice ou Zendesk). O colaborador abriu algum chamado para reportar que recebeu uma notificação estranha no celular? Se o usuário reportou ativamente para a central de suporte, o analista ganha contexto imediato sobre a legitimidade da recusa.

### 5. A conta sofreu comprometimento prévio ou posterior?
O atacante conseguiu obter sucesso minutos antes ou depois do alerta? Por exemplo, o invasor pode ter tentado múltiplos logons até conseguir acesso via outro protocolo ou dispositivo previamente confiável.

---

## 4. Onde Investigar no Microsoft Entra admin center

Para analistas de N1 e N2 que precisam confrontar a telemetria do Sentinel diretamente no portal de identidade:

1. Acesse o **Microsoft Entra admin center** (`entra.microsoft.com`).
2. Navegue até **Identity > Monitoring & health > Sign-in logs**.
3. Na aba **User sign-ins (interactive)**, adicione os filtros:
   - **Status:** *Failure*
   - **Error code:** *500121*
4. Abra o registro correspondente e inspecione as abas:
   - **Basic info:** Correlation ID, IP e localização.
   - **Authentication Details:** confirme o método acionado (ex.: *Mobile app notification*) e o resultado do passo (*Fraud reported by user*).
   - **Conditional Access:** veja quais políticas de Acesso Condicional foram avaliadas durante a tentativa.
5. Em seguida, acesse **Identity > Protection > Risky users**:
   - Verifique se a identidade foi automaticamente elevada para nível de risco **Alto** ou **Médio**.
   - Na lâmina **Risk detections**, inspecione se há detecções associadas, como *Unfamiliar sign-in properties*, *Anomalous Token* ou *Suspicious user reported activity*.

---

## 5. Procedimento de Resposta e Contenção Imediata

Diante da confirmação de que a senha da conta está comprometida, o playbook de SOC deve executar a contenção em cadeia:

1. **Revogar sessões ativas (*Revoke sessions*):**
   - No portal do Entra ID, abra o perfil do usuário e clique em **Revoke sessions** (ou execute via CLI/PowerShell `Revoke-MgUserSignOut -UserId <UPN>`). Isso invalida imediatamente todos os refresh tokens ativos emitidos para a conta.
2. **Redefinição emergencial de senha:**
   - Como o invasor possui a senha atual, efetue o reset forçado de senha ou force a alteração no próximo logon através de canal seguro e fora de banda (out-of-band).
3. **Auditoria de métodos de autenticação (*Authentication methods*):**
   - Acesse **Identity > Users > [Usuário] > Authentication methods**. Verifique se nenhum método não autorizado (telefone celular secundário, app de autenticação de terceiro ou chave FIDO2 desconhecida) foi cadastrado recentemente.
4. **Inspeção de persistência em e-mail e aplicativos:**
   - Verifique se foram criadas regras de encaminhamento externo no Exchange Online (`New-InboxRule` com `ForwardTo`).
   - Verifique no `AuditLogs` se a conta consentiu permissões OAuth para algum aplicativo desconhecido antes do bloqueio.

---

## 6. Consulta KQL Pós-Incidente: Verificando Sucessos e Falhas Concorrentes

Após aplicar a contenção, execute a consulta abaixo para auditar toda a atividade da conta nas últimas 48 horas, identificando se alguma tentativa obteve êxito (`ResultType == 0`):

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

### Matriz de Classificação de Incidentes (TP vs FP):

| Cenário Analisado | Classificação | Ação Operacional do SOC |
|---|---|---|
| Colaborador desconhece a tentativa, IP suspeito no exterior, senha primária correta | **Verdadeiro Positivo (TP)** | Isolar conta, revogar sessões, redefinir senha e iniciar investigação de malware/phishing no endpoint. |
| Colaborador clicou em "Não sou eu" por engano enquanto tentava acessar pelo celular próprio | **Falso Positivo (FP)** | Confirmar com o colaborador via canal corporativo, orientar sobre o uso do autenticador e fechar o alerta no Sentinel com notas claras. |
| Tentativa de IP anômalo seguida por logon bem-sucedido via legado sem MFA | **Incidente Crítico (TP)** | Escalar para N3/DFIR para caça a ameaças (*threat hunting*), análise forense e bloqueio de protocolos legados via Acesso Condicional. |
