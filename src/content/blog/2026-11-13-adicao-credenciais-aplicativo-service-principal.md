---
title: "Adição de segredos e credenciais em aplicativos do Entra ID: guia prático de investigação para analistas de SOC"
description: "Playbook completo de triagem e contenção no SOC para o alerta de novas credenciais ou certificados gerados em Service Principals e App Registrations no Entra ID."
date: 2026-11-13
categoria: IAM
tags: [sentinel, azure, entra-id, service-principal, oauth, soc, iam, dfir, kql]
nivel: Avançado
---

A criação não documentada de um novo segredo de cliente (*client secret*) ou certificado digital em um aplicativo registrado no Microsoft Entra ID é um dos indicadores mais críticos de persistência e elevação de privilégios em ambientes de nuvem. Adversários experientes utilizam essa técnica (catalogada no **MITRE ATT&CK como T1098.001**) para estabelecer acessos secundários que não dependem de senhas de usuários e não são desafiados por autenticação multifator (MFA).

> **TL;DR para o SOC:** Se a criação do segredo não estiver associada a uma GMUD/chamado formal de manutenção de integrações ou esteira de CI/CD, trate imediatamente como **Verdadeiro Positivo (High/Critical)**. Revogue o segredo adicionado em *App registrations*, audite os logons do Service Principal em `AADServicePrincipalSignInLogs` e revogue as sessões da conta operadora via Entra ID Protection.

> 📘 **Referência no Microsoft Learn:** Este playbook baseia-se nas regras analíticas nativas do catálogo do Microsoft Sentinel:
> - [Catálogo de regras de detecção agendadas do Microsoft Sentinel (Learn)](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in)
> - [Diretrizes de segurança e monitoramento de identidades de carga de trabalho no Entra ID (Learn)](https://learn.microsoft.com/entra/architecture/protect-workload-identities)

---

## 1. O que significa esse incidente?

No Microsoft Entra ID, quando uma aplicação precisa consultar o Microsoft Graph, acessar bancos de dados, caixas postais do Exchange ou gerenciar recursos do Azure sem intervenção humana, ela utiliza uma **Workload Identity (Service Principal)**. 

Para se autenticar nos endpoints da Microsoft (`login.microsoftonline.com`), o Service Principal apresenta uma credencial:
1. Uma senha de texto (*Client Secret*);
2. Um certificado assimétrico (*X.509 Certificate*);
3. Uma federação de identidade federada OIDC (como GitHub Actions ou Kubernetes).

### O vetor de persistência silenciosa
Quando um atacante obtém controle de uma conta com papel de **Application Administrator**, **Cloud Application Administrator** ou mesmo um usuário comum definido como **Owner (Proprietário)** daquele App Registration específico, ele não precisa criar um novo usuário no domínio. 

O adversário simplesmente gera um novo client secret com validade longa (ex.: 24 meses) em um aplicativo pré-existente e confiável da organização (muitas vezes uma aplicação legada que já possui consentimento de permissões de alto privilégio como `Directory.ReadWrite.All` ou `Mail.ReadWrite`).

A partir desse momento, o atacante passa a se conectar diretamente via APIs, contornando:
* Desafios de MFA (Service Principals não passam por MFA interativo de usuário);
* Políticas de Acesso Condicional baseadas em conformidade de dispositivos de usuário (*Compliant Devices*);
* Bloqueios de expiração de senha ou trocas forçadas de senha de colaboradores.

---

## 2. Dica de KQL: Rastreamento de novas credenciais e contexto do operador

A query abaixo traz algumas informações adicionais para contextualizar o evento no Microsoft Sentinel, identificando quem gerou o segredo ou certificado, em qual aplicação ocorreu a modificação e correlacionando o evento de auditoria com os logs de logon interativo do operador para capturar IP, MFA e nível de risco:

```kql
// ====================================================================================
// Deteccao & Enriquecimento: Nova credencial adicionada a aplicativo ou Service Principal
// Autor: Identidade Soberana (identidadesoberana.com.br)
// Objetivo: Mapear ator, aplicativo alvo, tipo de segredo, IP e contexto de logon
// ====================================================================================
let tempoAnalise = 24h;
let EventosCredencial = AuditLogs
| where TimeGenerated >= ago(tempoAnalise)
| where ActivityDisplayName in (
    "Update application - Certificates and secrets management ",
    "Add service principal credentials",
    "Add service principal",
    "Update application"
)
| mv-expand Target = TargetResources
| mv-expand ModProp = Target.modifiedProperties
| where ModProp.displayName in ("KeyDescription", "CredentialData", "TargetId.KeyDescription") 
     or ActivityDisplayName == "Add service principal credentials"
| extend AtorUPN = tostring(InitiatedBy.user.userPrincipalName),
         AtorIP = tostring(InitiatedBy.user.ipAddress),
         AtorApp = tostring(InitiatedBy.app.displayName),
         NomeApp = tostring(Target.displayName),
         AppIdAlvo = tostring(Target.id),
         DetalheModificacao = tostring(ModProp.newValue)
| extend AtorFinal = iff(isempty(AtorUPN), AtorApp, AtorUPN)
| project
    TimeGenerated,
    CorrelationId,
    ActivityDisplayName,
    NomeApp,
    AppIdAlvo,
    AtorFinal,
    DetalheModificacao,
    Result;
let SinaisLogon = SigninLogs
| where TimeGenerated >= ago(tempoAnalise)
| mv-expand AuthDetail = AuthenticationDetails
| project
    CorrelationId,
    UserPrincipalName,
    IPAddress,
    Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    MFAStatus = AuthenticationRequirement,
    DetalheMFA = tostring(AuthDetail.authenticationStepResultDetail),
    RiskLevel = RiskLevelDuringSignIn;
EventosCredencial
| join kind=leftouter (SinaisLogon) on CorrelationId
| project
    DataHora = TimeGenerated,
    Acao = ActivityDisplayName,
    AplicativoAlvo = NomeApp,
    IdAplicativo = AppIdAlvo,
    AtorOriginador = AtorFinal,
    DetalheCredencial = DetalheModificacao,
    IPOrigem = iff(isempty(IPAddress), "N/A", IPAddress),
    Localizacao = iff(isempty(Location), "N/A", Location),
    MFA = iff(isempty(MFAStatus), "N/A", MFAStatus),
    NivelRisco = iff(isempty(RiskLevel), "none", tostring(RiskLevel)),
    IDCorrelacao = CorrelationId
| order by DataHora desc
```

### O que essa query traz a mais:
* **`NomeApp` & `IdAplicativo`:** Identifica exatamente qual Service Principal recebeu a credencial para busca rápida no portal.
* **`AtorOriginador` & `IPOrigem`:** Revela a identidade que executou a ação e a localização geográfica de onde o comando partiu.
* **`DetalheCredencial`:** Contém o nome de identificação (*KeyDescription*), data de início e expiração do segredo.
* **`NivelRisco` & `MFA`:** Ajuda a evidenciar se a conta do operador estava sob ataque de fadiga de MFA, logon anômalo (*Unfamiliar sign-in properties*) ou sem MFA ativo no momento da ação.

---

## 3. Matriz de Investigação Técnica: 5 Perguntas Obrigatórias

Durante a triagem no Sentinel, o analista de SOC deve preencher estruturadamente os seguintes pontos:

| Pergunta | Onde Validar | O que verificar |
|---|---|---|
| **1. O que foi feito?** | `AuditLogs` / `TargetResources` | Foi adicionado um Client Secret de texto ou um Certificado X.509? Qual o prazo de expiração definido? |
| **2. Quem fez?** | `InitiatedBy` & `SigninLogs` | A ação foi executada por um usuário humano ou por uma pipeline de automação (Service Principal/DevOps)? |
| **3. Poderia ter feito?** | `Microsoft Entra ID > Roles and administrators` | O usuário possui a role de *Cloud Application Administrator* ou consta na lista de *Owners* do aplicativo? |
| **4. Há chamado formal / ticket?** | Ferramentas de ITSM (ServiceNow, Jira, Freshservice) | Existe GMUD ou chamado aprovado para rotação ou criação de credencial de aplicação neste horário? |
| **5. Onde investigar no portal?** | Entra Admin Center (`entra.microsoft.com`) | Inspecionar permissões da API concedidas ao App em *API permissions* e logons recentes em *Service principal sign-ins*. |

---

## 4. Onde Investigar no Portal do Microsoft Entra

Siga este roteiro detalhado no **Microsoft Entra admin center** (`entra.microsoft.com`):

### Passo 1: Inspecionar o Aplicativo e suas Permissões
1. Acesse:
   > **Identity** > **Applications** > **App registrations** > Selecione a aba **All applications**.
2. Pesquise pelo nome ou pelo `AppId` obtido na query de KQL.
3. No menu lateral do aplicativo:
   * **Certificates & secrets:** Compare as credenciais ativas. Verifique a data de criação (*Created*) e o identificador do segredo recente.
   * **API permissions:** Avalie o risco das permissões concedidas. Permissões do tipo **Application** com privilégios como `Mail.ReadWrite`, `User.ReadWrite.All`, `RoleManagement.ReadWrite.Directory` ou `Files.ReadWrite.All` concedem controle total sobre o tenant sem depender de usuário.
   * **Owners:** Verifique quem tem autorização para gerenciar a aplicação sem ter função administrativa no diretório.

### Passo 2: Auditar os Logons da Carga de Trabalho
1. Navegue até:
   > **Identity** > **Monitoring & health** > **Sign-in logs**
2. Clique na aba **Service principal sign-ins**.
3. Filtre pelo `AppId` investigado e configure a janela de tempo desde o momento da geração do segredo até o presente.
4. Verifique:
   * Houve logins bem-sucedidos (`ResultType == 0`) utilizando a nova credencial?
   * Quais endereços de IP originaram a conexão? Pertencem aos datacenters conhecidos da empresa ou a provedores de hospedagem/VPNs anônimas (ex: DigitalOcean, Linode, AWS, Tor)?

---

## 5. Validação com o Titular & Ferramentas de ITSM

A criação ou renovação de credenciais de serviço deve seguir processos formais de governança. O analista deve cruzar:

1. **Número de Mudança (GMUD/Change Management):**
   * Verifique no ServiceNow/Jira se há registro de manutenção programada de integração (ex.: expiração anual de segredo de integração ERP/CRM).
2. **Contato com a equipe responsável:**
   * Se o ator for um desenvolvedor ou engenheiro de DevOps, confirme se ele executou a ação manualmente pelo portal ou se ocorreu por meio de scripts autorizados.
   * Questione: *"Você reconhece a adição deste segredo no aplicativo [Nome] às [Data/Hora] a partir do IP [Endereço]?"*
3. **Validação de escopo:**
   * Mesmo que a intenção tenha sido legítima, a aplicação possui permissões excessivas (*Over-privileged permissions*)? Essa é uma oportunidade imediata de adequação ao princípio do menor privilégio (*Least Privilege*).

---

## 6. Procedimento de Resposta e Contenção

Se a atividade for confirmada como não autorizada ou se a conta do operador estiver comprometida:

```
[Alerta de Credencial Não Autorizada em Service Principal]
        │
        ├── 1. Excluir imediatamente a credencial recém-criada:
        │      App registrations > [App] > Certificates & secrets > Delete
        │
        ├── 2. Desabilitar a conta de serviço / Service Principal (se aplicável):
        │      Enterprise applications > [App] > Properties > "Enabled for users to sign-in?" = NO
        │
        ├── 3. Conter a identidade do operador que adicionou a chave:
        │      Microsoft Entra > Users > [Operador] > "Revoke sessions"
        │      Forçar reset de senha e verificar métodos de MFA
        │
        ├── 4. Auditar logons recentes em busca de exfiltração:
        │      Executar KQL forense em AADServicePrincipalSignInLogs
        │
        └── 5. Escalar para incidente de segurança (N2/CSIRT)
```

### KQL Forense: O que o aplicativo executou após a criação da credencial?

Execute esta consulta no Microsoft Sentinel para rastrear todos os logons realizados pelo Service Principal após a inserção do segredo, mapeando quais recursos e APIs foram alvos da sessão:

```kql
let appIdSuspeito = "00000000-0000-0000-0000-000000000000";
let inicioJanela = datetime(2026-11-13T00:00:00Z);
AADServicePrincipalSignInLogs
| where TimeGenerated >= inicioJanela
| where AppId == appIdSuspeito
| project
    DataHora = TimeGenerated,
    NomeApp = ServicePrincipalName,
    IdApp = AppId,
    IPOrigem = IPAddress,
    Localizacao = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    RecursoAcessado = ResourceDisplayName,
    StatusResultado = ResultType,
    DescricaoResultado = ResultDescription,
    IDCorrelacao = CorrelationId
| order by DataHora asc
```

---

## 7. Mapeamento de Controles para Eliminar a Causa Raiz

Para mitigar permanentemente o risco de credenciais maliciosas em aplicações:
1. **Adotar Microsoft Entra Workload ID Protection:** Ative detecções automatizadas de risco para identidades de carga de trabalho, como *Service Principal high-risk sign-in* e *Unusual service principal usage*.
2. **Priorizar Identidades Federadas (Workload Identity Federation):** Substitua segredos de cliente fixos (*Client Secrets*) por federação OIDC baseada em tokens transitórios com provedores como GitHub Actions, GitLab CI ou Azure DevOps.
3. **Restringir Criação de Aplicativos por Usuários Comuns:** No Microsoft Entra Admin Center, desabilite a opção *"Users can register applications"*, canalizando todas as solicitações via fluxo de aprovação com aprovação de segurança da informação.
4. **Revisões de Acesso de Privilégio (PIM for Groups / Applications):** Conceda a função de *Application Administrator* exclusivamente sob demanda via PIM (*Privileged Identity Management*), com justificativa obrigatória e aprovação de duplo fator.
