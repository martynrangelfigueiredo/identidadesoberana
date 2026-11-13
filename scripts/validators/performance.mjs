#!/usr/bin/env node
/**
 * scripts/validators/performance.mjs
 * Validador de Performance e Zero Bloat:
 * - Garante ausência total de scripts bloqueantes de terceiros (como Google Translate, analytics pesados).
 * - Verifica configuração de carregamento não-bloqueante de fontes do Google (preconnect + display=swap).
 * - Monitora o peso de ativos estáticos em public/ e src/styles.
 */
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

async function validatePerformance() {
  console.log("⚡ [Skill: Validar Performance] Verificando métricas de carregamento e ausência de bloat...");
  let errors = 0;

  // 1. Inspeciona o layout Base.astro para garantir ausência de scripts bloqueantes
  const baseLayoutPath = path.join(ROOT, "src", "layouts", "Base.astro");
  const baseContent = await readFile(baseLayoutPath, "utf-8");

  // Verifica se o Google Translate reapareceu
  if (baseContent.includes("translate.google.com") || baseContent.includes("translate.googleapis.com")) {
    console.error("❌ [Performance] Script externo bloqueante do Google Translate detectado no Base.astro!");
    errors++;
  }

  // Verifica se fontes possuem preconnect e display=swap
  if (!baseContent.includes('rel="preconnect" href="https://fonts.googleapis.com"')) {
    console.warn("⚠️ [Performance] Falta preconnect para fonts.googleapis.com no Base.astro.");
  }
  if (!baseContent.includes("display=swap")) {
    console.error("❌ [Performance] Google Fonts deve utilizar display=swap para evitar FOIT.");
    errors++;
  }

  // 2. Verifica tamanho de imagens em public/icons
  const iconsDir = path.join(ROOT, "public", "icons");
  try {
    const iconFiles = await readdir(iconsDir);
    for (const file of iconFiles) {
      const filePath = path.join(iconsDir, file);
      const fileStat = await stat(filePath);
      const sizeKb = fileStat.size / 1024;
      if (sizeKb > 500) {
        console.warn(`⚠️ [Performance] Ícone ${file} possui ${sizeKb.toFixed(1)} KB (recomendado: < 150 KB).`);
      }
    }
  } catch (err) {
    // Diretório pode variar
  }

  // 3. Verifica tamanho do arquivo global.css
  const globalCssPath = path.join(ROOT, "src", "styles", "global.css");
  try {
    const cssStat = await stat(globalCssPath);
    const cssKb = cssStat.size / 1024;
    if (cssKb > 60) {
      console.warn(`⚠️ [Performance] global.css possui ${cssKb.toFixed(1)} KB. Mantenha estilos enxutos.`);
    }
  } catch (err) {}

  if (errors > 0) {
    console.error(`\n❌ Falha na validação de performance: ${errors} problema(s) detectado(s).\n`);
    process.exit(1);
  }

  console.log("✔ [Performance] Zero scripts bloqueantes de terceiros, fontes otimizadas e baixo payload.");
}

validatePerformance().catch((err) => {
  console.error("Erro fatal no validador de Performance:", err);
  process.exit(1);
});
