---
name: validar-performance
description: Auditoria de performance web, métricas Core Web Vitals e política de zero bloat. Garante ausência de scripts externos pesados de terceiros, fontes não-bloqueantes e otimização de ativos.
---

# Skill: Validar Performance — Identidade Soberana

Esta skill garante que o site mantenha tempos de carregamento instantâneos e pontuação 99-100 no Lighthouse/PageSpeed.

## 1. Diretrizes de Performance
- **Zero Bloat de Terceiros:** Não utilizar scripts externos de tradução automática (`translate.google.com`), widgets sociais pesados ou SDKs de rastreamento. Toda tradução e botões de compartilhamento devem ser 100% estáticos e nativos.
- **Fontes Não-Bloqueantes:** Google Fonts deve ser carregado com `preconnect` e `display=swap`, utilizando media="print" onload="this.media='all'" ou técnicas assíncronas similares.
- **Orçamento de Ativos (Asset Budget):**
  - Ícones e imagens devem ser leves (< 150 KB).
  - SVG otimizado e minificado inline.
  - CSS global enxuto (< 60 KB).
- **Sem Layout Shift (CLS = 0):** Todos os containers de cabeçalho, navegação e botões devem possuir dimensões mínimas reservadas.

## 2. Como Rodar a Validação Automatizada
```bash
node scripts/validators/performance.mjs
```
