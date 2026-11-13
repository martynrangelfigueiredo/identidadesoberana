---
name: criar-post
description: Procedimento operacional e padrão de qualidade para criação e tradução de artigos técnicos (SOC, IAM, Compliance) e carrosséis no Identidade Soberana, com glossário multilíngue obrigatório (Microsoft Learn, Linux Foundation), playbooks de resposta a incidentes do Microsoft Sentinel e testes automatizados de KQL.
---

# Skill: Criação de Conteúdo Técnico — Identidade Soberana

Este guia define o padrão operacional obrigatório para criar artigos no site (`src/content/blog/`) e carrosséis do Instagram (`instagram/posts/`), garantindo consistência terminológica multilíngue baseada em padrões do **Microsoft Learn**, **Linux Foundation** (CNCF, OpenSSF), **NIST SP 800-63** e **MITRE ATT&CK**.

---

## 1. Tabela Oficial de Terminologia Multilíngue

Em artigos técnicos de SOC, Engenharia de Identidades (IAM) e Compliance, termos de arquitetura e computação em nuvem possuem convenções consolidadas. **Siga rigorosamente a matriz abaixo:**

| Conceito / Termo Base | Português (PT-BR) | Alemão (DE) | Mandarim (ZH) | Regra de Tradução & Padrão de Mercado |
|---|---|---|---|---|
| **Secret / Client Secret** | **Secret(s)** / **Client Secret(s)** | **Secret(s)** / **Client Secret(s)** | **Secret(s)** / **客户端密码 (Client Secret)** / **机密 (Secret)** | **NUNCA traduzir para "segredo"** em PT-BR nem "Geheimnis" em DE técnico. Em nuvem/DevSecOps (Azure Key Vault, Entra ID, Kubernetes Secrets, HashiCorp Vault), o termo canônico é **Secret / Client Secret**. Em ZH, usa-se 客户端密码 ou 机密 com Secret. |
| **Service Principal** | **Service Principal** (pl: *Service Principals*) | **Service Principal** (pl: *Service Principals*) | **服务主体 (Service Principal)** | **MANTÉM em inglês** em PT e DE. Em ZH: 服务主体. NUNCA use "entidade de serviço" isolado em PT (no máximo *Entidade de serviço (Service Principal)* na primeira menção explicativa). |
| **Tenant** | **Tenant** (pl: *Tenants*) | **Tenant** (pl: *Tenants*) | **租户 (Tenant)** | **MANTÉM em inglês** em PT e DE. O termo "locatário" do Learn PT formal não é adotado pela comunidade operacional de SOC. Em ZH: 租户. |
| **Playbook / Runbook** | **Playbook** / **Runbook** | **Playbook** / **Runbook** | **应急响应剧本 (Playbook)** / **Playbook** | **MANTÉM em inglês** em PT e DE. NUNCA traduzir como "livro de jogadas" ou "roteiro de jogadas". |
| **Bypass** | **Bypass** (ex: *bypass de MFA*) | **Bypass** (ex: *MFA-Bypass*) | **绕过 (Bypass)** | **MANTÉM em inglês** em PT e DE. NUNCA traduzir como "desvio" ou "contorno" em contexto de invasão ou controle de acesso. |
| **Token / Access / Refresh** | **Token** / **Token de acesso** / **Refresh token** | **Token** / **Zugriffstoken** / **Refresh-Token** | **令牌 (Token)** / **访问令牌 (Access Token)** / **刷新令牌 (Refresh Token)** | **MANTÉM token** em PT e DE. |
| **Key Vault** | **Key Vault** (Azure Key Vault) | **Key Vault** | **Key Vault** | **NUNCA traduzir** o nome do produto/serviço da Microsoft (nunca "Cofre de Chaves"). |
| **App Registration** | **App Registration** / **Registro de aplicativo** | **App-Registrierung** | **应用程序注册 (App Registration)** | Em caminhos de navegação do portal, use a lâmina oficial: *App registrations*. |
| **Workload Identity** | **Workload Identity** / **Identidade de carga de trabalho** | **Workload-Identität (Workload Identity)** | **工作负载标识 (Workload Identity)** | Mantenha preferencialmente em inglês em contextos de nuvem e microsserviços. |
| **Managed Identity** | **Managed Identity** / **Identidade Gerenciada** | **Verwaltete Identität (Managed Identity)** | **托管标识 (Managed Identity)** | Tradução técnica oficial da Microsoft. |
| **Tabelas KQL & Logs** | **AuditLogs**, **SigninLogs**, **AADServicePrincipalSignInLogs** | **AuditLogs**, **SigninLogs**, **AADServicePrincipalSignInLogs** | **AuditLogs**, **SigninLogs**, **AADServicePrincipalSignInLogs** | **SEMPRE em inglês** verbatim. Nunca altere nomes de tabelas, colunas ou APIs. |
| **Pipeline / CI/CD** | **Pipeline** / **esteira de CI/CD** | **Pipeline** / **CI/CD-Pipeline** | **流水线 (Pipeline)** / **CI/CD** | Termo padrão CNCF / Linux Foundation. |
| **Hardcoded** | **Hardcoded** / **embutido no código** | **Hardcoded** / **fest codiert** | **硬编码 (Hardcoded)** | Jargão técnico padrão de segurança e desenvolvimento. |
| **Privileged Roles** | **Global Administrator**, **Privileged Role Administrator**, etc. | **Global Administrator**, **Privileged Role Administrator**, etc. | **全局管理员 (Global Administrator)**, etc. | **SEMPRE manter os nomes oficiais em inglês** dos papéis do Entra ID, facilitando localização no portal e filtros KQL. |
| **Correlation ID** | **Correlation ID** / `CorrelationId` | **Korrelations-ID (Correlation ID)** / `CorrelationId` | **关联 ID (Correlation ID)** / `CorrelationId` | Chave de rastreamento de telemetria forense. |
| **AitM** | **Adversary-in-the-Middle (AitM)** | **Adversary-in-the-Middle (AitM)** | **中间人攻击 (AitM / Adversary-in-the-Middle)** | Definição padrão NIST / MITRE. |
| **Push Bombing / MFA Fatigue** | **Fadiga de MFA (*Push bombing / push spamming*)** | **MFA-Fatigue (*Push-Bombing*)** | **MFA 疲劳攻击 (*Push Bombing*)** | MITRE ATT&CK T1621. |
| **Passkey / FIDO2** | **Passkey** / **Chave de segurança FIDO2** | **Passkey** / **FIDO2-Sicherheitsschlüssel** | **Passkey** / **FIDO2 安全密钥** | Padrão FIDO Alliance / W3C. |
| **Revoke sessions** | **Revoke sessions** / **revogar sessões ativas** | **Sitzungen widerrufen (Revoke sessions)** | **撤销会话 (Revoke sessions)** | Comando/ação exata na lâmina do Microsoft Entra ID. |
| **Threat Intelligence / Hunting** | **Threat Intelligence** / **Threat Hunting** | **Threat Intelligence** / **Threat Hunting** | **威胁情报 (Threat Intelligence)** / **威胁搜寻 (Threat Hunting)** | MANTÉM em inglês nas operações de SOC. |
| **True Positive / False Positive** | **Verdadeiro Positivo (TP)** / **Falso Positivo (FP)** | **True Positive (TP)** / **False Positive (FP)** | **真正阳性 (True Positive)** / **虚假阳性 (False Positive)** | Padrão analítico de SOC e SIEM. |
| **ITSM & Mudança** | **ITSM**, **GMUD (Gestão de Mudanças)**, **Ticket de chamado** | **ITSM**, **Change-Ticket**, **Ticket** | **ITSM**, **变更工单 (Change Ticket)**, **工单 (Ticket)** | ServiceNow, Jira Service Management, Freshservice, Zendesk. |

---

## 2. Estrutura Obrigatória de Artigos do Site

Todo post técnico relacionado a incidentes no Microsoft Azure deve ser modelado a partir de um incidente real do **Microsoft Sentinel** (baseado em regras analíticas padrão):

1. **Título Suave, Autoral e Profissional em Português:**
   - **NUNCA** use o nome cru da regra ou alerta do Sentinel (ex: NUNCA *"Incidente: User Assigned Privileged Role by MS-PIM"*).
   - Use títulos convidativos e práticos (ex: *"Elevação de privilégios via PIM: guia prático de investigação para o SOC"*).
2. **Referência ao Microsoft Learn:**
   - Link explícito para a documentação oficial ou catálogo de regras do Sentinel.
3. **Seção de KQL — Título Humilde por Idioma:**
   - 🇧🇷 Português: `## 2. Dica de KQL: [Foco da consulta]`
   - 🇩🇪 Alemão: `## 2. KQL-Tipp: [Fokus der Abfrage]`
   - 🇨🇳 Mandarim: `## 2. KQL 查询提示：[查询要点]`
   - 🇺🇸 Inglês: `## 2. KQL Tip: [Query focus]`
   - **Tom humilde e direto:** Diga apenas que a consulta projeta algumas colunas úteis para contextualizar o evento. NUNCA use palavras grandiosas como *"KQL Avançado"*, *"inovador"* ou *"revolucionário"*.
4. **Matriz das 5 Perguntas Obrigatórias da Investigação:**
   - *O que foi feito?* (Ação, CorrelationId, permanente vs temporário).
   - *Quem fez?* (InitiatedBy, histórico da conta, IP, MFA, SigninLogs).
   - *Poderia ter feito?* (Permissões no Entra ID, aprovação de PIM).
   - *Há chamado formal/ticket?* (Cruzamento com ITSM: ServiceNow, Jira, etc. e justificativa).
   - *A sessão foi legítima?* (Nível de risco da sessão, anomalias de localização, MFA resistente a phishing).
5. **Caminho Exato no Portal:**
   - Indicação passo a passo no Microsoft Entra admin center (`entra.microsoft.com`).
6. **Procedimento de Resposta e Contenção:**
   - Passos imediatos de isolamento, revogação de credenciais/sessões e query KQL pós-incidente.

---

## 3. Regras Estritas de KQL (Kusto Query Language)

1. **Sintaxe Estritamente ASCII:**
   - NUNCA utilize caracteres acentuados ou cedilha (`ç`, `ã`, `õ`, `é`, `á`, etc.) em nomes de variáveis (`let`), aliases ou colunas projetadas.
   - Acentos só são permitidos dentro de comentários `//` ou strings literais `"..."`.
2. **Estrutura de Indexação Segura:**
   - O compilador do Kusto rejeita indexação direta `ModProp[0]`. Utilize `mv-expand Target = TargetResources` seguido de `mv-expand ModProp = Target.modifiedProperties`.
3. **Instruções `let`:**
   - Toda declaração `let` DEVE ser finalizada com ponto e vírgula `;`.
4. **Validação Obrigatória:**
   - Antes de salvar ou comitar, SEMPRE execute:
     ```bash
     npm run test:kql
     ```
   - O teste valida a sintaxe completa contra o parser do KQL Playground (Bryce Maxheimer) e o linter interno.

---

## 4. Tradução Multilíngue Nativa

O site opera com seletor estático nativo nos seguintes caminhos:
- 🇧🇷 **Português (Padrão):** `src/content/blog/AAAA-MM-DD-slug.md` (`/blog/slug/`)
- 🇩🇪 **Alemão (1º no seletor):** `src/content/blog/de/AAAA-MM-DD-slug.md` (`/de/blog/slug/`)
- 🇨🇳 **Mandarim (2º no seletor):** `src/content/blog/zh/AAAA-MM-DD-slug.md` (`/zh/blog/slug/`)
- 🇺🇸 **Inglês (3º no seletor):** `src/content/blog/en/AAAA-MM-DD-slug.md` (`/en/blog/slug/`)

**Regra de Ouro:** O nome **Identidade Soberana** permanece idêntico em qualquer idioma (nunca traduzir para "Sovereign Identity", "Souveräne Identität" ou "主权身份").
