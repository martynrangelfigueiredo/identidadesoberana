---
name: validar-i18n
description: Validação de paridade multilíngue e integridade de internacionalização. Garante que todo artigo em português possui traduções em alemão, mandarim e inglês, preserva o nome da marca e valida o seletor.
---

# Skill: Validar i18n & Internacionalização — Identidade Soberana

Esta skill assegura a consistência e paridade das traduções entre todos os 4 idiomas suportados.

## 1. Diretrizes de Paridade Linguística
- **Paridade 1:1:** Cada artigo em `src/content/blog/<slug>.md` deve obrigatoriamente possuir versões correspondentes em:
  - `src/content/blog/de/<slug>.md` (Alemão)
  - `src/content/blog/zh/<slug>.md` (Mandarim da China continental)
  - `src/content/blog/en/<slug>.md` (Inglês)
- **Integridade Absoluta da Marca:** O nome **Identidade Soberana** NUNCA deve ser traduzido (proibido "Souveräne Identität", "主权身份" ou "Sovereign Identity").
- **Ordem Oficial do Seletor:**
  - 1º 🇩🇪 **Alemão** (`/de/...`, DE de)
  - 2º 🇨🇳 **Mandarim** (`/zh/...`, CN zh)
  - 3º 🇺🇸 **Inglês** (`/en/...`, US en)
  - 4º 🇧🇷 **Português** (`/...`, BR pt - padrão)

## 2. Como Rodar a Validação Automatizada
```bash
node scripts/validators/i18n.mjs
```
