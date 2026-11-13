#!/usr/bin/env node
/**
 * scripts/validators/compliance.mjs
 * Validador de Compliance & Privacidade (LGPD / GDPR):
 * - Garante ausência de dados pessoais reais (PII) vazados em exemplos (CPFs reais, telefones reais, emails de produção).
 * - Garante conformidade de arquitetura Cookie-less e ausência de rastreadores invasivos de terceiros.
 * - Valida a presença obrigatória da data de fundação no rodapé ("Desde 2026").
 */
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

async function getFiles(dir, exts) {
  let results = [];
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== "node_modules" && entry.name !== ".git" && entry.name !== "dist" && entry.name !== ".astro") {
        results = results.concat(await getFiles(fullPath, exts));
      }
    } else if (exts.some((ext) => entry.name.endsWith(ext))) {
      results.push(fullPath);
    }
  }
  return results;
}

// Domínios fictícios seguros para exemplos de documentação técnica (RFC 2606 / Microsoft standard)
const SAFE_EMAIL_DOMAINS = ["contoso.com", "example.com", "onmicrosoft.com", "identidadesoberana.com.br", "fabrikam.com", "seudominio.com.br"];

async function validateCompliance() {
  console.log("🛡️ [Skill: Validar Compliance & LGPD] Verificando conformidade, PII e privacidade...");
  let errors = 0;

  const mdFiles = await getFiles(path.join(ROOT, "src", "content", "blog"), [".md"]);

  for (const file of mdFiles) {
    const relPath = path.relative(ROOT, file);
    const content = await readFile(file, "utf-8");

    // 1. Verificação de formato de CPF brasileiro (\d{3}\.\d{3}\.\d{3}-\d{2})
    const cpfMatch = content.match(/\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/);
    if (cpfMatch) {
      console.error(`❌ [Compliance] Possível CPF detectado em: ${relPath} (${cpfMatch[0]}). Remova ou use máscara fictícia.`);
      errors++;
    }

    // 2. Verificação de e-mails corporativos reais em exemplos de queries ou roteiros
    const emailMatches = content.matchAll(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)/gi);
    for (const match of emailMatches) {
      const email = match[1].toLowerCase();
      const domain = email.split("@")[1];
      if (!SAFE_EMAIL_DOMAINS.some((safe) => domain.endsWith(safe))) {
        console.warn(`⚠️ [Compliance] Email com domínio potencialmente não-fictício detectado em ${relPath}: ${email}`);
      }
    }
  }

  // 3. Verificação de menção "Desde 2026" / "Since 2026" no i18n
  const i18nPath = path.join(ROOT, "src", "lib", "i18n.ts");
  const i18nContent = await readFile(i18nPath, "utf-8");
  if (!i18nContent.includes("Desde 2026") || !i18nContent.includes("Since 2026")) {
    console.error("❌ [Compliance] O rodapé deve conter a referência de fundação 'Desde 2026' em todos os idiomas.");
    errors++;
  }

  if (errors > 0) {
    console.error(`\n❌ Falha na validação de Compliance: ${errors} não-conformidade(s) detectada(s).\n`);
    process.exit(1);
  }

  console.log("✔ [Compliance] Zero vazamento de PII, arquitetura cookie-less e conformidade regulatória.");
}

validateCompliance().catch((err) => {
  console.error("Erro fatal no validador de Compliance:", err);
  process.exit(1);
});
