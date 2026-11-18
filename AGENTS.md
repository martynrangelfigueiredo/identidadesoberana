# Instruções para IA — Identidade Soberana

Este repositório produz artigos técnicos de alta profundidade para o site **`identidadesoberana.com.br`**, cobrindo dois pilares complementares de engenharia:
1. **Operação Enterprise & Cloud SecOps:** Microsoft Sentinel, Microsoft Entra ID, Defender XDR, KQL e playbooks táticos de resposta a incidentes.
2. **Nuvem Soberana & Ecossistema Aberto:** Gestão de identidades com Keycloak, SIEM aberto com Wazuh, automação com TheHive/Shuffle, federação OIDC e laboratórios locais em Docker/WSL2 para Windows Enterprise.

Público-alvo: Analistas de SOC (N1–N3), engenheiros de IAM, arquitetos de segurança e profissionais de compliance.

## Antes de criar QUALQUER conteúdo, leia:
1. [`brand/BRAND.md`](brand/BRAND.md) — identidade visual (logo, cores, fontes, efeitos, ilustrações).
2. [`brand/CONTEUDO.md`](brand/CONTEUDO.md) — tom de voz, regras e diretrizes dos artigos técnicos.
3. [`.agents/skills/criar-post/SKILL.md`](.agents/skills/criar-post/SKILL.md) — procedimento operacional de redação técnica e matriz de terminologia.

## Regras inegociáveis
- Fundo **branco**; verde `#009C3B` é a cor principal; amarelo `#FFDF00` só em destaques; vermelho `#E1251B` **só na estrela do logo**.
- Fontes: Nunito (títulos), Inter (texto), JetBrains Mono (código).
- Cores/fontes vêm de `brand/tokens.css`. Nunca invente cores nem escreva estilos dentro dos posts `.md`.
- Tom profissional, amigável e direto, **nunca alarmista**. Sem mascote, sem rosto, sem "hacker de capuz".
- **Foco Técnico e Zero Auto-Promoção:** A missão dos artigos é ser 100% útil, didático e operacional para quem está na ponta defendendo ambientes. **NÃO fique dizendo "soberano" ou "soberana" a toda hora** em títulos, descrições ou no corpo do texto (prefira "local", "open-source", "isolamento local", etc.). Não use o texto para se auto-promover nem coloque comentários de autoria (`// Autor: Identidade Soberana`) dentro de blocos de código/queries. O nome "Identidade Soberana" deve constar apenas como a marca institucional do site.
- **Padrão de Terminologia Técnica (Microsoft Learn & Linux Foundation):**
  - **Secrets:** Use SEMPRE **"secret / secrets"** ou **"client secrets"**. NUNCA traduza para "segredo / segredos" em português ou "Geheimnis" em alemão.
  - **Service Principal:** Mantenha **"Service Principal"** (pl: *Service Principals*). NUNCA use "entidade de serviço" isolado.
  - **Tenant:** Use **"tenant"** (pl: *tenants*). NUNCA use "locatário".
  - **Playbook:** Use **"playbook / playbooks"** (nunca "livro de jogadas").
  - **Bypass:** Use **"bypass"** (ex: bypass de MFA; nunca "desvio").
  - **Títulos KQL por Idioma:**
    - 🇧🇷 Português: `## 2. Dica de KQL: [Foco da consulta]`
    - 🇩🇪 Alemão: `## 2. KQL-Tipp: [Fokus der Abfrage]`
    - 🇨🇳 Mandarim: `## 2. KQL 查询提示：[查询要点]`
    - 🇺🇸 Inglês: `## 2. KQL Tip: [Query focus]`
  - Consulte a matriz completa na skill `.agents/skills/criar-post/SKILL.md`.
- **Site (Regra para Posts de Azure/Incidentes):**
  - Todo post relacionado a Azure no site deve ser modelado a partir de um **incidente real gerado pelo Microsoft Sentinel** (tendo como base uma *analytics rule* padrão/default do Azure Sentinel, sem precisar citar explicitamente o nome da regra padrão).
  - **Identificação Explícita do Ecossistema Microsoft Security:**
    Todo post que abordar tecnologias de nuvem e defesa da Microsoft (Microsoft Sentinel, Microsoft Entra ID, Defender XDR, PIM, KQL, etc.) DEVE explicitar claramente no título, na descrição e nas tags (`microsoft-security`) que se trata do ecossistema **Microsoft Security** (ex.: use *"Elevação de privilégios no Microsoft Security: guia prático de investigação com PIM e Sentinel para analistas de SOC"*).
  - **Título SEMPRE suave, autoral e em português:** **NUNCA** coloque o nome literal do incidente ou regra no título. Crie um título autoral, claro e fluído em português, contextualizando com o ecossistema Microsoft Security.
  - **Referência no Microsoft Learn:** Sempre referencie a página oficial da analytics rule ou catálogo no Microsoft Learn (ex.: catálogo de detecções padrão do Microsoft Sentinel no Learn).
  - **Tradução multilíngue:** O site possui seletor de tradução obrigatório na ordem exata: **1º Alemão (Deutsch)**, **2º Mandarim da China continental (简体中文)**, **3º Inglês (English)**.
  - Posts devem ser **completos, profundos e sem cortes**, servindo como playbooks operacionais de SOC/DFIR.
  - **Seção e Tom do KQL (Dica de KQL):**
    - **NUNCA** use títulos grandiosos como "KQL Avançado" ou "KQL Inovador". Use títulos simples e operacionais como: `## 2. Dica de KQL: [Foco da consulta]`.
    - **Tom humilde e direto:** Não enalteça a query com frases do tipo *"A query abaixo vai muito além..."* ou *"revolucionária"*. Apenas diga que a query traz algumas informações a mais ou colunas úteis para contextualizar o evento.
    - **Sintaxe KQL Estritamente ASCII:** NUNCA use caracteres acentuados ou cedilha (`ç`, `ã`, `õ`, `é`, `á`, etc.) em nomes de variáveis (`let`), aliases de tabelas ou colunas projetadas. Caracteres especiais quebram o compilador do Kusto (ex: use `NegacoesMFA`, e nunca `NegaçõesMFA`). Acentos só são aceitos dentro de strings `"..."` ou comentários `//`.
    - **Validação de Sintaxe Obrigatória:** Toda query KQL DEVE ser testada e passar com sucesso pelo comando `npm run test:kql` antes de ser comitada ou publicada.
  - **Roteiro padrão de investigação obrigatório:**
    1. *O que foi feito?* (Ação detalhada, temporária vs permanente, Correlation ID).
    2. *Quem fez?* (InitiatedBy, histórico da conta, MFA, SigninLogs).
    3. *Poderia ter feito?* (Papéis, permissões de atribuição/aprovação no Entra ID).
    4. *Há chamado formal/ticket?* (Ferramentas de ITSM como ServiceNow, Jira, Freshservice, Zendesk e cruzamento com justificativa/ResultReason).
    5. *Onde investigar no portal?* (Caminho exato no Microsoft Entra admin center, ex: `Identity Governance > Privileged Identity Management > Microsoft Entra Roles > Resource Audit`).
    6. *Procedimento de resposta e contenção* (Revogação, revoke sessions, auditoria de pós-elevação).

## AI Skills do Repositório (Validações Pré-Build Obrigatórias)
Antes de qualquer build ou deploy, o pipeline de validação unificado DEVE ser executado e passar com 100% de sucesso (`npm run validate` ou `npm run build` que o invoca automaticamente via `prebuild`):
1. **`criar-post`** ([`.agents/skills/criar-post/SKILL.md`](.agents/skills/criar-post/SKILL.md)): Procedimento operacional de redação técnica e matriz de terminologia.
2. **`validar-seguranca`** ([`.agents/skills/validar-seguranca/SKILL.md`](.agents/skills/validar-seguranca/SKILL.md)): Bloqueio de secrets, tokens ou chaves privadas vazadas e links com `rel="noopener noreferrer"`.
3. **`validar-fact-checking`** ([`.agents/skills/validar-fact-checking/SKILL.md`](.agents/skills/validar-fact-checking/SKILL.md)): Verificação de citações oficiais ao Microsoft Learn, tabelas reais do Sentinel e terminologia canônica.
4. **`validar-performance`** ([`.agents/skills/validar-performance/SKILL.md`](.agents/skills/validar-performance/SKILL.md)): Bloqueio de scripts pesados de terceiros, fontes assíncronas e orçamento de ativos.
5. **`validar-compliance`** ([`.agents/skills/validar-compliance/SKILL.md`](.agents/skills/validar-compliance/SKILL.md)): Bloqueio de dados pessoais reais (PII), conformidade LGPD e cookie-less.
6. **`validar-kql`** ([`.agents/skills/validar-kql/SKILL.md`](.agents/skills/validar-kql/SKILL.md)): Compilação e validação das queries KQL no parser do Bryce Maxheimer Playground.
7. **`validar-i18n`** ([`.agents/skills/validar-i18n/SKILL.md`](.agents/skills/validar-i18n/SKILL.md)): Paridade de artigos nos 4 idiomas (DE, ZH, EN, PT) e preservação estrita do nome da marca.
8. **`validar-ux-copiabilidade`** ([`.agents/skills/validar-ux-copiabilidade/SKILL.md`](.agents/skills/validar-ux-copiabilidade/SKILL.md)): Garante cópia em 1 clique de códigos, tabelas (Markdown), âncoras de seção e saídas das ferramentas `/util/`, além de legibilidade otimizada.

## Fluxos
- **Novo artigo:** criar `src/content/blog/<data>-<slug>.md` com o frontmatter de `brand/CONTEUDO.md` → `npm run dev` para revisar.
- **Nova ilustração:** SVG 400x400 em `brand/ilustracoes/`, seguindo o estilo e o prompt da seção 6 de `BRAND.md`.

