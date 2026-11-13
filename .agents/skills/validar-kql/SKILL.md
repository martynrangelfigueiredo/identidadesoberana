---
name: validar-kql
description: Validação automatizada de sintaxe KQL (Kusto Query Language) contra o engine do KQL Playground (Bryce Maxheimer) e linter estrito de caracteres ASCII para consultas do Microsoft Sentinel.
---

# Skill: Validar KQL — Identidade Soberana

Esta skill valida todas as consultas KQL (Kusto) presentes nos artigos técnicos de SOC e IAM antes de qualquer publicação ou build.

## 1. Regras Mandatórias de Sintaxe KQL
- **Caracteres Estritamente ASCII:** NUNCA utilize caracteres acentuados ou cedilha (`ç`, `ã`, `õ`, `é`, `á`, etc.) em nomes de variáveis (`let`), aliases ou colunas projetadas. Acentos só são permitidos dentro de strings `"..."` ou comentários `//`.
- **Declarações `let`:** Toda linha de `let <var> = <exp>;` DEVE ser finalizada com ponto e vírgula `;`.
- **Indexação Segura de Arrays Dinâmicos:** O compilador Kusto rejeita `ModProp[0]`. Utilize `mv-expand` para desdobrar arrays dinâmicos de auditoria (ex.: `mv-expand Target = TargetResources | mv-expand ModProp = Target.modifiedProperties`).
- **Tom Humilde na Seção:**
  - 🇧🇷 `## 2. Dica de KQL: [Foco da consulta]`
  - 🇩🇪 `## 2. KQL-Tipp: [Fokus der Abfrage]`
  - 🇨🇳 `## 2. KQL 查询提示：[查询要点]`
  - 🇺🇸 `## 2. KQL Tip: [Query focus]`

## 2. Como Rodar o Teste Automatizado de KQL
```bash
npm run test:kql
```
O script compila todas as queries encontradas em `src/content/blog/**/*.md` e garante 100% de conformidade com o parser do Bryce Maxheimer Playground.
