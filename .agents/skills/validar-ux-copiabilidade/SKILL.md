---
name: validar-ux-copiabilidade
description: Auditoria de copiabilidade e otimização de visualização (UX) para o Identidade Soberana. Garante botões de cópia em códigos, tabelas, cabeçalhos e ferramentas, além de leitura otimizada.
---

# Skill: Validar UX & Copiabilidade

Esta skill garante que todo o conteúdo técnico do **Identidade Soberana** (artigos e ferramentas `/util/`) seja facilmente copiável e visualmente legível em desktop e dispositivos móveis.

## Critérios Verificados Automaticamente
1. **Blocos de Código e Queries (`.prosa pre`):**
   - Presença do botão `.copy-code-btn` em `src/layouts/Base.astro`.
   - Padding superior adequado em `src/styles/global.css` (`padding: 2.4rem...` ou equivalente) para evitar que o botão sobreponha a primeira linha do código.
   - Cópia limpa (sem capturar o texto do próprio botão).
2. **Tabelas Copiáveis e Legíveis (`.prosa table` / `.table-wrapper`):**
   - Presença do botão `.copy-table-btn` para copiar tabelas no formato Markdown.
   - Quebra de linha habilitada nas células `td` (`white-space: normal`) para evitar scroll horizontal excessivo no desktop.
3. **Links de Seção (`.heading-copy-btn`):**
   - Títulos `h2` e `h3` com ID devem oferecer botão `#` para cópia rápida do link direto da seção.
4. **Ferramentas Úteis (`/util/` em `ToolShell.astro`):**
   - Todas as caixas `.kv-box` (IPs, hashes, timestamps, claims) e saídas `.code-out` devem receber automaticamente botões de cópia via `MutationObserver`.
5. **Proibição de Bloqueio de Seleção:**
   - Proibido aplicar `user-select: none` sobre textos de artigos (`.prosa`), código (`pre`, `code`), tabelas ou resultados de ferramentas (`.kv-value`).

## Execução
Integrada ao pipeline `npm run validate` via `scripts/validators/ux-copiabilidade.mjs`.

