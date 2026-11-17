---
title: "Consent Grants abusivos no Microsoft Security: caça a ameaças e playbook de resposta no Microsoft Sentinel"
description: "Playbook completo de investigação no Microsoft Security para identificar aplicativos OAuth com permissões excessivas, phishing de consentimento e contenção no Entra ID."
date: 2026-11-17
categoria: IAM
tags: [microsoft-security, sentinel, entra-id, oauth, consent-grant, soc, iam, dfir, kql]
nivel: Avançado
---

A concessão abusiva de permissões a aplicativos OAuth — frequentemente chamada de **phishing de consentimento (*consent phishing*)** ou *illicit consent grant* — é um dos vetores de ataque em nuvem mais perigosos e difíceis de conter. Ao contrário de invasões tradicionais que dependem do roubo de senhas ou contorno de MFA, esse ataque engana o usuário (ou um administrador) para que autorize um aplicativo malicioso a acessar recursos em seu nome.

Uma vez concedido o consentimento, o aplicativo recebe tokens de acesso da API do Microsoft Graph com escopos de alto privilégio (como `Mail.ReadWrite`, `Files.ReadWrite.All` ou `User.ReadWrite.All`). A partir desse momento, **o atacante não precisa mais da senha nem do segundo fator do usuário**, operando de forma invisível diretamente contra a nuvem da organização.

Dentro do ecossistema **Microsoft Security**, a integração entre o **Microsoft Entra ID** e o **Microsoft Sentinel** fornece telemetria detalhada para detectar consentimentos anômalos, auditar chamadas de API e isolar imediatamente aplicativos comprometidos.

> 📘 **Referência Oficial no Microsoft Learn:**
> - [Proteger contra ataques de consentimento ilícito no Microsoft Entra ID (Learn)](https://learn.microsoft.com/entra/identity/enterprise-apps/manage-consent-requests)
> - [Investigação de aplicativos suspeitos no Microsoft Sentinel (Learn)](https://learn.microsoft.com/azure/sentinel/investigate-incidents)
> - [Catálogo de regras analíticas agendadas do Microsoft Sentinel (Learn)](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in)

---

## 1. Como Funciona o Ataque de Consent Phishing?

O ciclo de exploração típico é catalogado no **MITRE ATT&CK como T1528 (Steal Application Access Token)** e **T1204.001 (User Execution: Malicious Link)**:

1. **Isca por E-mail:** O colaborador recebe um e-mail com aparência legítima (ex.: "Atualização de Políticas Internas", "Assinatura Eletrônica Pendente" ou "Relatório Financeiro Compartilhado").
2. **Tela de Consentimento Real:** Ao clicar no link, o usuário é direcionado para a página de autenticação legítima da Microsoft (`login.microsoftonline.com`). Como a página é autêntica, navegadores e soluções de segurança não bloqueiam a URL.
3. **Solicitação de Escopos Abusivos:** O aplicativo solicita permissões delegadas para ler e-mails (`Mail.Read`), acessar arquivos no OneDrive/SharePoint (`Files.ReadWrite.All`) ou ler mensagens do Teams (`Chat.Read`).
4. **Persistência Silenciosa:** Assim que o usuário clica em "Aceitar", o invasor obtém um *refresh token* de longa duração, permitindo exfiltrar dados e espionar comunicações sem disparar alertas de logon subsequentes.

---

## 2. Dica de KQL: Mapeando consentimentos de aplicativos OAuth no Entra ID

A consulta abaixo traz algumas colunas úteis para contextualizar os eventos de consentimento registrados no `AuditLogs`, correlacionando o nome da aplicação, as permissões concedidas e a conta que efetuou a aprovação:

```kql
// ====================================================================================
// Consulta: Mapeando consentimentos de aplicativos OAuth no Entra ID
// Objetivo: Identificar aplicacao alvo, permissoes concedidas, usuario originador e data
// ====================================================================================
let JanelaTempo = 30d;
AuditLogs
| where TimeGenerated >= ago(JanelaTempo)
| where ActivityDisplayName in (
    "Consent to application",
    "Add delegated permission grant",
    "Add app role assignment to service principal"
)
| mv-expand Target = TargetResources
| mv-expand ModProp = Target.modifiedProperties
| where ModProp.displayName in ("ConsentAction.Permissions", "DelegatedPermissionGrant.Scope", "AppRole.Value")
| extend AtorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend NomeAplicativo = tostring(Target.displayName)
| extend IdAplicativo = tostring(Target.id)
| extend Permissoes = tostring(ModProp.newValue)
| project
    TimeGenerated,
    ActivityDisplayName,
    NomeAplicativo,
    IdAplicativo,
    Permissoes,
    AtorUPN,
    Result,
    CorrelationId
| order by TimeGenerated desc
```

### O que avaliar nos resultados:
- **`Permissoes`:** Escopos como `Mail.ReadWrite`, `Mail.Send`, `Files.ReadWrite.All` e `Directory.AccessAsUser.All` são extremamente perigosos quando concedidos a aplicativos de desenvolvedores não verificados (*Unverified Publisher*).
- **`AtorUPN`:** Se o autor for um usuário comum, trata-se de permissão delegada (*User Consent*). Se for um administrador (como *Global Administrator*), o consentimento pode ter sido concedido em nível de tenant (*Admin Consent*), afetando todas as contas da organização.
- **`IdAplicativo`:** Identificador do Service Principal criado no tenant, indispensável para os comandos de contenção e bloqueio imediato.

---

## 3. Roteiro de Investigação: As 5 Perguntas Obrigatórias

Durante a triagem no Microsoft Sentinel, o analista deve responder estruturadamente:

### 1. O que foi feito?
Qual aplicação foi registrada? Trata-se de um aplicativo multitenant externo ou desenvolvido internamente? As permissões concedidas foram delegadas (acessam apenas os dados do próprio usuário) ou de aplicação/tenant (acesso irrestrito a todas as caixas de correio da empresa)?

### 2. Quem fez?
Identifique o usuário em `AtorUPN`. O colaborador possui justificativa de negócio para autorizar esse software? Trata-se de um colaborador de perfil executivo, jurídico ou financeiro cujos e-mails contêm dados confidenciais?

### 3. O aplicativo é verificado pela Microsoft?
O aplicativo possui o selo azul de *Verified Publisher* (editor verificado)? Desenvolvedores sem verificação, domínios recém-criados ou nomes que imitam ferramentas corporativas legítimas (ex.: "DocuSign Secure Document Portal" hospedado em tenant desconhecido) são fortes indícios de ataque.

### 4. Há chamado formal ou aprovação no ITSM?
Consulte a ferramenta de ITSM (ServiceNow, Jira Service Management ou Central de Serviços). Há solicitação formal de integração de software ou homologação de arquitetura de segurança prévia? Se não houver chamado corporativo documentado, a hipótese de ataque deve ser mantida como prioritária.

### 5. A aplicação já realizou requisições à API Graph?
Inspecione se o Service Principal já utilizou os tokens para realizar chamadas de API no tenant, consultando a tabela `AADServicePrincipalSignInLogs` e os logs de atividade do Office 365.

---

## 4. Onde Investigar no Microsoft Entra admin center

Para analistas de SOC que precisam verificar o aplicativo diretamente no portal:

1. Acesse o **Microsoft Entra admin center** (`entra.microsoft.com`).
2. Navegue até **Identity > Applications > Enterprise applications**.
3. Localize o aplicativo suspeito na lista e abra a sua lâmina.
4. Na seção **Security**, clique em **Permissions**:
   - Em **Admin consent**, verifique se há permissões amplas concedidas para toda a empresa.
   - Em **User consent**, inspecione quais usuários individuais autorizaram o aplicativo e quais escopos específicos foram delegados.
5. Acesse a aba **Audit logs** do próprio aplicativo para verificar o histórico de criação de credenciais, certificados ou alterações de permissão.

---

## 5. Procedimento de Resposta e Contenção Imediata

Confirmada a natureza maliciosa ou não autorizada do aplicativo, execute a contenção no SOC sem hesitar:

1. **Desativar a entrada de usuários no aplicativo:**
   - Na lâmina do aplicativo corporativo, vá em **Properties** e alterne **Enabled for users to sign-in?** para **No**. Isso impede novos logons imediatamente.
2. **Revogar todas as permissões concedidas via PowerShell:**
   - Utilize o módulo Microsoft Graph PowerShell para remover os consentimentos delegados:
   ```powershell
   # Conectando com permissões administrativas de aplicativo
   Connect-MgGraph -Scopes "Application.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All"

   # Localizando e removendo a concessao delegada
   $AppObjId = "ID-DO-SERVICE-PRINCIPAL"
   Get-MgServicePrincipalOAuth2PermissionGrant -ServicePrincipalId $AppObjId | ForEach-Object {
       Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $_.Id
   }
   ```
3. **Excluir o aplicativo do tenant:**
   - Em **Enterprise applications**, clique em **Manage > Properties > Delete** para remover completamente o Service Principal do seu diretório.
4. **Revogar sessões dos usuários afetados:**
   - Para todos os colaboradores que autorizaram o app, execute `Revoke-MgUserSignOut` para invalidar tokens de sessão e force a troca de senha.
5. **Endurecer a política de consentimento do Entra ID:**
   - Acesse **Enterprise applications > Consent and permissions > User consent settings**.
   - Defina como **Do not allow user consent** (não permitir consentimento do usuário) e ative o **Admin consent workflow** para que qualquer novo app exija aprovação prévia da equipe de segurança.

---

## 6. Consulta KQL Pós-Incidente: Rastreando Tráfego do Service Principal

Após isolar o aplicativo, audite se ele chegou a autenticar e consumir recursos da organização nos últimos 14 dias:

```kql
// ====================================================================================
// Verificacao Pos-Incidente: Rastreando tokens e logons do Service Principal suspeito
// Objetivo: Verificar se a aplicacao com consentimento abusivo consumiu APIs do tenant
// ====================================================================================
let JanelaAnalise = 14d;
let AppIdSuspeito = "00000000-0000-0000-0000-000000000000";
AADServicePrincipalSignInLogs
| where TimeGenerated >= ago(JanelaAnalise)
| where tolower(AppId) == tolower(AppIdSuspeito)
| extend StatusAutenticacao = iff(ResultType == 0, "Sucesso", "Falha")
| project
    TimeGenerated,
    ServicePrincipalName,
    AppId,
    IPAddress,
    ResourceDisplayName,
    StatusAutenticacao,
    ResultType,
    ResultDescription,
    CorrelationId
| order by TimeGenerated desc
```

### Matriz de Decisão do SOC (TP vs. FP):

| Cenário Analisado | Classificação | Ação Operacional do SOC |
|---|---|---|
| Aplicativo desconhecido, editor não verificado, permissões de leitura de e-mails (`Mail.ReadWrite`) | **Verdadeiro Positivo (Crítico)** | Isolar e excluir o app, revogar sessões dos usuários, analisar logs de e-mail e iniciar contenção de exfiltração de dados. |
| Ferramenta corporativa homologada (ex.: integração oficial do Jira ou Power BI) adicionada por engenheiro | **Falso Positivo (FP)** | Confirmar número do ticket no ITSM, validar o editor verificado e documentar a exceção na regra analítica do Sentinel. |
| Consentimento concedido por administrador em nível de tenant para aplicativo externo suspeito | **Incidente Grave (P1)** | Escalar imediatamente para DFIR, isolar o aplicativo, auditar todas as contas de administrador e revisar integridade do tenant. |
