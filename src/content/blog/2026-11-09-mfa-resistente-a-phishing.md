---
title: "Investigando fadiga de MFA e bypass de segundo fator: playbook para o SOC"
description: "Playbook completo para triagem e contenção de incidentes de MFA Fatigue e AitM no Microsoft Sentinel: KQL enriquecido, correlação de SigninLogs e AuditLogs, análise de sessões e resposta imediata."
date: 2026-11-09
categoria: SOC
tags: [sentinel, mfa, entra-id, kql, aitm, incident-response, soc, iam]
nivel: Intermediário
---

Ataques contra mecanismos de autenticação multifator evoluíram drasticamente. Se antes bastava exigir um segundo fator para mitigar credenciais vazadas, hoje atores de ameaça contornam ativamente autenticadores legados por meio de **fadiga de MFA (*MFA fatigue / push spamming*)** e proxies reversos **Adversary-in-the-Middle (AitM)**.

No Microsoft Sentinel, incidentes originados por anomalias de MFA sinalizam uma das situações mais urgentes para o time de resposta: a senha da conta já foi comprometida e o invasor está forçando ou enganando o usuário para transpor a barreira final de acesso.

> **TL;DR para o SOC:** Quando este incidente dispara, trate como credencial vazada confirmada. Se após várias rejeições de MFA houver um logon bem-sucedido de IP desconhecido, acione contenção imediata: revogue as sessões ativas (`Revoke sessions`), force a redefinição de senha e audite se o atacante cadastrou métodos de autenticação adicionais no tenant.

> 📘 **Referência no Microsoft Learn:** Este playbook baseia-se nas detecções nativas de anomalias de autenticação do Microsoft Sentinel e nas diretrizes de endurecimento de identidade do Entra ID:
> - [Microsoft Sentinel — Built-in scheduled analytics rules catalog (Learn)](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in)
> - [Microsoft Entra ID — Proteger contra ataques de fadiga de MFA e métodos resistentes a phishing (Learn)](https://learn.microsoft.com/azure/active-directory/authentication/concept-authentication-methods)

---

## 1. O que significa esse incidente?

Quando uma regra de detecção de anomalias de MFA dispara no Microsoft Sentinel, o cenário típico reflete uma das seguintes etapas de invasão:

1. **Ataque de Fadiga de MFA (*Push Bombing*):** O invasor possui a senha correta (obtida em vazamentos, infecções por *infostealer* ou phishing prévio) e dispara dezenas de notificações no aplicativo Microsoft Authenticator da vítima, muitas vezes de madrugada, até que o colaborador aprove por engano, cansaço ou distração.
2. **Interceptação de Sessão via Proxy AitM (ex.: Evilginx / Modlishka):** A vítima acessou uma página de login clonada que interceptou em tempo real tanto a senha quanto o código OTP/cookie de sessão emitido pelo Microsoft Entra ID.
3. **Falhas Repetidas Seguidas de Sucesso Anômalo:** O alerta captura o momento exato em que uma série de eventos com código de erro `500121` (MFA negado) é subitamente sucedida por um código `0` (logon bem-sucedido) a partir de um IP de geolocalização ou ASN incomum.
4. **Falso Positivo Benigno:** O próprio colaborador teve instabilidade de rede ou tocou repetidamente para reenviar código após demora no recebimento de SMS/push.

---

## 2. Dica de KQL: Correlação de fadiga de MFA com logon consequente

A query abaixo correlaciona tentativas negadas com o logon subsequente bem-sucedido dentro de uma janela temporal, trazendo algumas informações adicionais úteis para contextualizar o evento, como detalhes do método de autenticação, cidade, sistema operacional e nível de risco da sessão:

```kql
// ====================================================================================
// Detecção & Enriquecimento: MFA Fatigue seguida de Logon Bem-Sucedido
// Autor: Identidade Soberana (identidadesoberana.com.br)
// Objetivo: Rastrear negações repetidas de MFA culminando em sucesso de IP anômalo
// ====================================================================================
let janelaAnalise = 24h;
let limiarFalhasMFA = 3;
// 1. Identificar contas que sofreram falhas ou negações repetidas de MFA (ResultType 500121 / 50074)
let NegacoesMFA = SigninLogs
| where TimeGenerated >= ago(janelaAnalise)
| where ResultType in (500121, 50074) // MFA negado pelo usuário ou desafio não completado
| summarize 
    QtdNegacoes = count(),
    PrimeiraFalha = min(TimeGenerated),
    UltimaFalha = max(TimeGenerated),
    IPsFalha = make_set(IPAddress, 5),
    LocaisFalha = make_set(Location, 5),
    UserAgentsFalha = make_set(UserAgent, 3)
    by UserPrincipalName, bin(TimeGenerated, 15m)
| where QtdNegacoes >= limiarFalhasMFA;
// 2. Buscar logons bem-sucedidos da mesma conta após as negações
let LogonsSucesso = SigninLogs
| where TimeGenerated >= ago(janelaAnalise)
| where ResultType == 0 // Sucesso
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
// 3. Cruzamento temporal: Sucesso nos 30 minutos seguintes às negações repetidas
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

### O que essa query revela de imediato ao analista:
* **`TentativasNegadas` vs `DataHoraSucesso`:** Revela a cadência temporal do ataque (ex.: 5 pushes negados às 03:12 e aceitação forçada às 03:17).
* **`IPLogonSucesso` vs `IPsAtaque`:** Mostra se o IP que conseguiu acesso final é idêntico ao IP que originou o bombardeio de requisições.
* **`ResultadoMFA`:** Distingue se o sucesso foi obtido via notificação push simples, correspondência de números (*number matching*) ou código OTP.

---

## 3. Matriz de Investigação Técnica: 5 Perguntas Obrigatórias

Durante a triagem no Sentinel, o analista deve responder estruturadamente aos seguintes pontos:

| Pergunta | Onde Validar | O que verificar |
|---|---|---|
| **1. O que foi feito?** | `SigninLogs` / `AuthenticationDetails` | Quantos prompts de MFA foram emitidos? Houve aprovação após sucessivas recusas? |
| **2. Quem fez?** | `IPAddress`, `LocationDetails`, ASN | O IP de origem do sucesso pertence à rede corporativa/VPN ou vem de datacenter/VPN comercial (ex: NordVPN, Tor, AWS)? |
| **3. Poderia ter feito?** | Perfil do usuário | O horário coincide com a jornada de trabalho do titular? O usuário costuma viajar para o país de origem do login? |
| **4. Há chamado formal / contato com o titular?** | ITSM / Contato Out-of-Band | Fale com o colaborador por **canal alternativo** (ligação telefônica ou Teams corporativo) perguntando se ele estava tentando logar. |
| **5. A sessão foi legítima?** | `AADUserRiskEvents` & `AuditLogs` | Houve detecção de *Anomalous Token*, *Unfamiliar sign-in* ou cadastramento de novo dispositivo? |

---

## 4. Onde Investigar no Portal do Microsoft Entra

Siga este roteiro no **Microsoft Entra admin center** (`entra.microsoft.com`):

### Passo 1: Inspecionar Sign-in Logs da Conta
1. Acesse:
   > **Identity** > **Users** > Selecione o usuário afetado > **Sign-in logs**
2. Alterne para a aba **Interactive user sign-ins** e filtre pela data/hora exata do incidente.
3. Abra o evento de sucesso subsequente às falhas e verifique:
   * **Authentication Details:** Revise o método exato utilizado (se foi SMS, Push ou FIDO2).
   * **Conditional Access:** Qual política concedeu acesso? Exigia dispositivo compatível (*Compliant*)?
   * **Device info:** Dispositivo não gerenciado (*Unmanaged*) ou sistema operacional incomum para o perfil do usuário.

### Passo 2: Verificar Detecções de Risco no Identity Protection
1. Navegue até:
   > **Identity Protection** > **Risk detections**
2. Filtre pelo UPN do usuário e busque por detecções correlatas no mesmo horário:
   * *AitM Phishing*
   * *Anomalous Token*
   * *Suspected Brute Force / Password Spray*
   * *Impossible travel*

---

## 5. Validação com o Titular & Ferramentas de ITSM

Diferente de alertas de PIM onde há um número de ticket prévio, em ataques de fadiga de MFA a validação requer contato imediato com o usuário:

> ⚠️ **Regra Crítica de Contato:** **NUNCA envie e-mail para a conta investigada** perguntando se foi ela quem logou. Se a conta estiver comprometida, o atacante responderá confirmando que a ação foi legítima. Faça contato telefônico direto, via chefia imediata ou mensagem confirmada por canal fora da banda de risco.

Perguntas diretas para o titular:
1. *"Você recebeu notificações repetidas de aprovação de login no seu celular recentemente?"*
2. *"Você clicou em algum link de e-mail solicitando confirmação de senha ou atualização cadastral?"*
3. *"Você aprovou alguma notificação apenas para fazê-la parar de tocar no seu aparelho?"*

Se a resposta for afirmativa para qualquer uma delas, trate o incidente como **Verdadeiro Positivo (True Positive)** com comprometimento de credencial.

---

## 6. Procedimento de Resposta e Contenção

Se o acesso foi confirmado como fraudulento ou se o titular não reconhecer o login:

```
[Alerta de Fadiga de MFA Confirmado]
        │
        ├── 1. Revogar todas as sessões ativas imediatamente:
        │      Microsoft Entra > Users > [Usuário] > "Revoke sessions"
        │      (Invalida tokens de acesso e refresh tokens ativos)
        │
        ├── 2. Forçar reset de senha da conta
        │
        ├── 3. Auditar e purgar métodos de autenticação:
        │      Checar se o invasor cadastrou novo número de telefone,
        │      app autenticador próprio ou chave FIDO2
        │
        ├── 4. Bloquear IPs maliciosos no firewall / Acesso Condicional
        │
        └── 5. Executar KQL forense pós-comprometimento
```

### KQL Forense: O que o atacante fez após transpor o MFA?
Execute imediatamente no Sentinel para checar se o invasor registrou novos métodos de autenticação ou criou regras de encaminhamento de e-mails em caixas postais:

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

## 7. Mapeamento de Controles para Eliminar a Causa Raiz

Para erradicar definitivamente ataques de fadiga de MFA no tenant:
1. **Obrigar Correspondência de Números (*Number Matching*):** Já é padrão no Entra ID, mas garanta que esteja ativo sem exceções para todos os usuários em *Authentication Methods*.
2. **Contexto Geográfico no Push:** Exiba o nome do aplicativo e o mapa com a localização do solicitante na notificação do Microsoft Authenticator.
3. **Migração para FIDO2 e Passkeys (Resistente a Phishing):** Autenticadores FIDO2 (YubiKeys, Windows Hello for Business e Passkeys) vinculam criptograficamente o desafio ao domínio legítimo (`login.microsoftonline.com`), tornando ataques de AitM e fadiga tecnicamente impossíveis.
