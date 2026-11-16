# Identidade Soberana — Voz e Conteúdo

Site técnico de operações de segurança, governança de identidades e soberania digital: **`identidadesoberana.com.br`**.

---

## 💻 Linha Editorial e Pilares Técnicos

O projeto cobre dois pilares complementares de engenharia:
1. **Operação Enterprise & Cloud SecOps:** Microsoft Sentinel, Microsoft Entra ID, Defender XDR, KQL e playbooks táticos de resposta a incidentes.
2. **Nuvem Soberana & Ecossistema Aberto:** Gestão de identidades com Keycloak, SIEM aberto com Wazuh, automação com TheHive/Shuffle, federação OIDC e laboratórios locais em Docker/WSL2 para Windows Enterprise.

**Para quem:** SOC Analysts (N1–N3), times de Identity & Access Management, Engenheiros de Segurança em Nuvem, Compliance/GRC e DPOs.

**Voz:** colega sênior generoso. Técnico, preciso, direto ao ponto, sem arrogância. Ainda leve — sem sensacionalismo.

### Regras de escrita
- Comece com **TL;DR** (blockquote) quando o artigo for longo.
- Termos técnicos em inglês são OK (SIEM, IGA, PAM, AitM), em *itálico* na primeira vez.
- **Padrão de Terminologia Multilíngue (Microsoft Learn & Linux Foundation):**
  - **Secrets:** Use SEMPRE **"secret / secrets"** ou **"client secrets"**. NUNCA use "segredo / segredos" em PT-BR nem "Geheimnis" em DE técnico.
  - **Service Principal:** Mantenha **"Service Principal"** (pl: *Service Principals*). NUNCA use "entidade de serviço" isolado.
  - **Tenant:** Use **"tenant"** (pl: *tenants*). NUNCA use "locatário".
  - **Playbook:** Use **"playbook / playbooks"** (nunca "livro de jogadas").
  - **Bypass:** Use **"bypass"** (ex: bypass de MFA; nunca "desvio").
  - Matriz completa de termos disponível na skill `.agents/skills/criar-post/SKILL.md`.
- **Padrão de Artigos de Azure / Sentinel (Obrigatório):**
  - Os posts relacionados a Azure devem ser estruturados a partir de **incidentes reais gerados pelo Microsoft Sentinel** (baseados nas *analytics rules* nativas do Azure Sentinel, sem precisar citar explicitamente a regra nativa).
  - **Título suave, autoral e SEMPRE em português:** **NUNCA** use o nome literal do incidente no título. Escreva um título convidativo, natural e profissional (ex.: *"Elevação de privilégios via PIM: guia prático de investigação para analistas de SOC"*).
  - **Referência no Microsoft Learn:** Todo artigo deve referenciar a documentação oficial da regra/catálogo no Microsoft Learn (ex.: catálogo de detecções padrão do Microsoft Sentinel).
  - **Tradução:** O site fornece tradução na ordem: **1. Alemão (Deutsch)**, **2. Mandarim da China continental (简体中文)**, **3. Inglês (English)**.
  - Devem ser artigos extensos, completos e práticos — verdadeiros playbooks de SOC.
  - **Seção de KQL (Título Humilde por Idioma e Tom):**
    - 🇧🇷 Português: `## 2. Dica de KQL: [Foco da consulta]`
    - 🇩🇪 Alemão: `## 2. KQL-Tipp: [Fokus der Abfrage]`
    - 🇨🇳 Mandarim: `## 2. KQL 查询提示：[查询要点]`
    - 🇺🇸 Inglês: `## 2. KQL Tip: [Query focus]`
    - Tom humilde e objetivo: não enalteça a query com frases do tipo *"vai muito além..."* ou *"revolucionária"*. Apenas diga que ela projeta informações a mais para ajudar a contextualizar o evento.
    - **Sintaxe KQL Estritamente ASCII:** NUNCA use acentos ou cedilha (`ç`, `ã`, `õ`, `é`, `á`, etc.) em nomes de variáveis (`let`), aliases ou colunas projetadas. O compilador Kusto rejeita caracteres especiais.
    - **Testar queries:** Execute `npm run test:kql` para validar toda a sintaxe KQL antes de publicar.
  - **Roteiro estruturado de investigação:**
    1. *O que significa o incidente?* (Cenários benignos vs maliciosos).
    2. *Query KQL completa com colunas projetadas*.
    3. *As 5 perguntas da investigação:* O que foi feito? Quem fez? Poderia ter feito? Há chamado/ticket formal? A sessão foi legítima?
    4. *Onde investigar no portal:* Rotas exatas no Microsoft Entra admin center / Azure Portal (ex: `Identity Governance > Privileged Identity Management > Microsoft Entra Roles > Resource Audit`).
    5. *Validação em ITSM:* Checagem cruzada com ServiceNow, Jira Service Management, Freshservice ou Zendesk (e campos como `ResultReason`/justificativa).
    6. *Procedimento técnico de resposta & contenção:* Playbook com passos imediatos e KQL para auditoria pós-incidente.
- Sempre que possível traga: **queries de detecção** (KQL, SPL, Sigma), **tabelas comparativas**,
  **mapeamento de controles** (ISO 27001, NIST CSF, CIS, LGPD, SOC 2), **MITRE ATT&CK IDs** e **passos acionáveis**.
- Cite fontes primárias (docs de fornecedores, NIST, ANPD, CERT.br).
- Títulos de seção curtos. Um H2 a cada ~300 palavras.

### Frontmatter obrigatório (`src/content/blog/AAAA-MM-DD-slug.md`)
```yaml
---
title: "Título claro e específico"
description: "1–2 frases, até ~160 caracteres (vira o resumo e a meta description)."
date: 2026-11-09
categoria: SOC        # SOC | IAM | Compliance | Privacidade
tags: [tag1, tag2]
nivel: Intermediário  # Intermediário | Avançado
draft: false
---
```

### Categorias
- **SOC** — detecção, resposta a incidentes, SIEM/SOAR, threat hunting, playbooks.
- **IAM** — IGA, PAM, SSO, MFA, Zero Trust, ciclo de vida de identidades (JML).
- **Compliance** — LGPD, ISO 27001, SOC 2, PCI DSS, auditoria, evidências.
- **Privacidade** — proteção de dados pessoais na prática, direitos do titular, DPIA/RIPD.

