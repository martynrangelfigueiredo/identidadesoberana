# Instruções para IA — Identidade Soberana

Este repositório produz conteúdo para **dois canais com a MESMA identidade visual**:

| Canal | Público | Formato | Onde |
|---|---|---|---|
| Instagram `@identidadesoberana` | **Leigos** — linguagem extremamente simples, dicas básicas | **Sempre carrossel** 4:5 (1080x1350), 6–8 slides | `instagram/posts/AAAA-MM-DD-slug/post.json` |
| Site `identidadesoberana.com.br` | **SOC Analysts, IAM, Compliance** — técnico | Artigo Markdown (Astro) | `src/content/blog/AAAA-MM-DD-slug.md` |

Tema comum: tecnologia, operações de segurança, conformidade e proteção de dados pessoais.

## Antes de criar QUALQUER conteúdo, leia:
1. [`brand/BRAND.md`](brand/BRAND.md) — identidade visual (logo, cores, fontes, efeitos, ilustrações).
2. [`brand/CONTEUDO.md`](brand/CONTEUDO.md) — tom de voz e regras de cada canal.
3. Para carrosséis: [`instagram/README.md`](instagram/README.md) — formato do `post.json` e limites de texto.

## Regras inegociáveis
- Fundo **branco**; verde `#009C3B` é a cor principal; amarelo `#FFDF00` só em destaques; vermelho `#E1251B` **só na estrela do logo**.
- Fontes: Nunito (títulos), Inter (texto), JetBrains Mono (código).
- Cores/fontes vêm de `brand/tokens.css`. Nunca invente cores nem escreva estilos dentro de `post.json` ou dos posts `.md`.
- Tom leve e amigável, **nunca alarmista**. Sem mascote, sem rosto, sem "hacker de capuz".
- Instagram: zero jargão, focado em dicas práticas do dia a dia.
- **Site (Regra para Posts de Azure/Incidentes):**
  - Todo post relacionado a Azure no site deve ser modelado a partir de um **incidente real gerado pelo Microsoft Sentinel** (tendo como base uma *analytics rule* padrão/default do Azure Sentinel, sem precisar citar explicitamente o nome da regra padrão).
  - **Título SEMPRE suave, autoral e em português:** **NUNCA** coloque o nome literal do incidente ou regra no título. Crie um título autoral, claro e fluído em português (ex.: use *"Elevação de privilégios via PIM: guia prático de investigação para analistas de SOC"*, e nunca *"Incidente: User Assigned Privileged Role by MS-PIM"*).
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

## Fluxos
- **Novo carrossel:** criar `instagram/posts/<data>-<slug>/post.json` → `npm run carrossel -- <data>-<slug>` → revisar `carrossel.html` → `--png` para exportar.
- **Novo artigo:** criar `src/content/blog/<data>-<slug>.md` com o frontmatter de `brand/CONTEUDO.md` → `npm run dev` para revisar.
- **Nova ilustração:** SVG 400x400 em `brand/ilustracoes/`, seguindo o estilo e o prompt da seção 6 de `BRAND.md`.

