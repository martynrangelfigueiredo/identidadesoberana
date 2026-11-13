---
name: validar-compliance
description: Auditoria de conformidade com LGPD, GDPR e proteção de dados pessoais. Garante zero vazamento de PII em artigos/queries, arquitetura cookie-less e menção obrigatória à data de fundação no rodapé.
---

# Skill: Validar Compliance & Privacidade — Identidade Soberana

Esta skill zela pela conformidade legal, respeito à privacidade do titular e ausência de dados pessoais identificáveis no código e nos conteúdos.

## 1. Diretrizes de Compliance & Privacidade
- **Zero Vazamento de PII (Personally Identifiable Information):**
  - Nenhum CPF, RG, telefone ou endereço residencial real pode constar em exemplos, tabelas ou capturas de tela.
  - Endereços de e-mail utilizados em queries de KQL e playbooks devem pertencer estritamente a domínios fictícios padronizados (`@contoso.com`, `@onmicrosoft.com`, `@example.com` ou `@seudominio.com.br`).
- **Arquitetura Cookie-less:** O site não utiliza cookies de rastreamento de comportamento nem armazena telemetria não consentida.
- **Transparência e Identidade:**
  - O rodapé deve obrigatoriamente exibir a data de fundação: *"Desde 2026"* (e suas traduções em DE, ZH, EN).
  - A página *"Sobre"* deve estar acessível e detalhar a governança e autoria do projeto.

## 2. Como Rodar a Validação Automatizada
```bash
node scripts/validators/compliance.mjs
```
