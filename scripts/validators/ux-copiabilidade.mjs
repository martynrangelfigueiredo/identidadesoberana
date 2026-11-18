#!/usr/bin/env node
/**
 * scripts/validators/ux-copiabilidade.mjs
 * Validador da AI Skill: UX, Copiabilidade & Visualização
 */
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

async function validateUxCopyability() {
  console.log("📋 [Skill: Validar UX & Copiabilidade] Verificando recursos de cópia e legibilidade...");
  let errors = 0;

  const baseAstro = await readFile(path.join(ROOT, "src", "layouts", "Base.astro"), "utf-8");
  const globalCss = await readFile(path.join(ROOT, "src", "styles", "global.css"), "utf-8");
  const toolShell = await readFile(path.join(ROOT, "src", "components", "ToolShell.astro"), "utf-8");

  // 1. Verificar botões de cópia em Base.astro
  if (!baseAstro.includes("copy-code-btn")) {
    console.error("❌ [UX/Copiabilidade] Botão .copy-code-btn ausente em src/layouts/Base.astro.");
    errors++;
  }
  if (!baseAstro.includes("copy-table-btn")) {
    console.error("❌ [UX/Copiabilidade] Botão .copy-table-btn para tabelas ausente em src/layouts/Base.astro.");
    errors++;
  }
  if (!baseAstro.includes("heading-copy-btn")) {
    console.error("❌ [UX/Copiabilidade] Botão .heading-copy-btn para links de seção ausente em src/layouts/Base.astro.");
    errors++;
  }
  if (!baseAstro.includes("reading-progress")) {
    console.error("❌ [UX/Copiabilidade] Barra de progresso de leitura (#reading-progress) ausente em src/layouts/Base.astro.");
    errors++;
  }

  // 2. Verificar copiabilidade automática nas ferramentas (/util/)
  if (!toolShell.includes("kv-copy-btn") || !toolShell.includes("out-copy-btn") || !toolShell.includes("MutationObserver")) {
    console.error("❌ [UX/Copiabilidade] Cópia automática (.kv-copy-btn / .out-copy-btn + MutationObserver) ausente em src/components/ToolShell.astro.");
    errors++;
  }

  // 3. Verificar otimização visual no CSS e ausência de user-select: none indevido
  if (/\.prosa[\s\S]{0,120}user-select:\s*none/i.test(globalCss)) {
    console.error("❌ [UX/Copiabilidade] 'user-select: none' bloqueando seleção em .prosa detectado em global.css.");
    errors++;
  }
  if (!globalCss.includes("white-space: normal")) {
    console.error("❌ [UX/Copiabilidade] Células .prosa td devem permitir quebra de linha (white-space: normal) para leitura otimizada.");
    errors++;
  }

  if (errors > 0) {
    console.error(`\n❌ Falha em UX & Copiabilidade: ${errors} erro(s) encontrado(s).`);
    process.exit(1);
  }

  console.log("✔ [UX & Copiabilidade] Códigos, tabelas, links de seção e saídas das ferramentas 100% copiáveis e otimizados.");
}

validateUxCopyability();
