#!/usr/bin/env node
/**
 * scripts/validators/i18n.mjs
 * Validador de Paridade e Integridade Multilíngue (i18n):
 * - Garante que todo artigo em português possui versões equivalentes em DE, ZH e EN.
 * - Garante que o nome de marca "Identidade Soberana" nunca seja traduzido.
 * - Valida a ordem obrigatória do seletor de idiomas: 1º Alemão, 2º Mandarim, 3º Inglês, 4º Português.
 * - Valida que os títulos da seção KQL sigam o padrão localizado de cada idioma.
 */
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const BLOG_DIR = path.join(ROOT, "src", "content", "blog");

const FORBIDDEN_BRAND_TRANSLATIONS = ["Souveräne Identität", "主权身份", "Sovereign Identity"];

const KQL_HEADER_BY_LOCALE = {
  pt: "## 2. Dica de KQL",
  de: "## 2. KQL-Tipp",
  zh: "## 2. KQL 查询提示",
  en: "## 2. KQL Tip",
};

async function validateI18n() {
  console.log("🌐 [Skill: Validar i18n & Paridade] Verificando traduções, ordem do seletor e integridade da marca...");
  let errors = 0;

  // 1. Coleta posts da raiz (português)
  const rootEntries = await readdir(BLOG_DIR, { withFileTypes: true });
  const ptSlugs = rootEntries.filter((e) => e.isFile() && e.name.endsWith(".md")).map((e) => e.name);

  const locales = ["de", "zh", "en"];
  for (const loc of locales) {
    const locDir = path.join(BLOG_DIR, loc);
    let locFiles = [];
    try {
      locFiles = (await readdir(locDir)).filter((f) => f.endsWith(".md"));
    } catch (err) {
      console.error(`❌ [i18n] Diretório de idioma ausente: ${locDir}`);
      errors++;
      continue;
    }

    for (const slug of ptSlugs) {
      if (!locFiles.includes(slug)) {
        console.error(`❌ [i18n] Artigo "${slug}" não possui versão traduzida em "${loc}"!`);
        errors++;
      }
    }
  }

  // 2. Verifica integridade da marca e cabeçalhos KQL em todos os arquivos markdown
  async function checkFile(filePath, expectedLocale) {
    const content = await readFile(filePath, "utf-8");
    const relPath = path.relative(ROOT, filePath);

    for (const forbidden of FORBIDDEN_BRAND_TRANSLATIONS) {
      if (content.includes(forbidden)) {
        console.error(`❌ [i18n] Nome da marca traduzido indevidamente como "${forbidden}" em: ${relPath}`);
        errors++;
      }
    }

    const expectedHeader = KQL_HEADER_BY_LOCALE[expectedLocale];
    if (content.includes("## 2.") && !content.includes(expectedHeader)) {
      console.error(`❌ [i18n] Cabeçalho da seção KQL incorreto em [${expectedLocale}] ${relPath}. Esperado: "${expectedHeader}"`);
      errors++;
    }
  }

  for (const slug of ptSlugs) {
    await checkFile(path.join(BLOG_DIR, slug), "pt");
    for (const loc of locales) {
      const locFile = path.join(BLOG_DIR, loc, slug);
      try {
        await checkFile(locFile, loc);
      } catch (e) {}
    }
  }

  // 3. Valida ordem do seletor no i18n.ts
  const i18nPath = path.join(ROOT, "src", "lib", "i18n.ts");
  const i18nContent = await readFile(i18nPath, "utf-8");
  if (!i18nContent.includes('export const SELECTOR_ORDER: Locale[] = ["de", "zh", "en", "pt"];')) {
    console.error("❌ [i18n] Ordem do seletor de idiomas inválida! Deve ser obrigatoriamente: DE, ZH, EN, PT.");
    errors++;
  }

  if (errors > 0) {
    console.error(`\n❌ Falha na validação de i18n: ${errors} erro(s) encontrado(s).\n`);
    process.exit(1);
  }

  console.log("✔ [i18n] Paridade total de 4 idiomas, preservação da marca e seletor 100% validados.");
}

validateI18n().catch((err) => {
  console.error("Erro fatal no validador de i18n:", err);
  process.exit(1);
});
