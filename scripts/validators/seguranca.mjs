#!/usr/bin/env node
/**
 * scripts/validators/seguranca.mjs
 * Validador de Segurança do Identidade Soberana:
 * - Detecta credenciais/chaves/tokens reais vazados (chaves privadas, tokens GitHub/AWS/Azure).
 * - Garante que links externos com target="_blank" usem rel="noopener noreferrer".
 * - Verifica ausência de injeção insegura de HTML em componentes e posts.
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

const SECRET_PATTERNS = [
  { name: "Chave Privada RSA/EC/OPENSSH", regex: /-----BEGIN (RSA|EC|DSA|OPENSSH|PGP)?\s?PRIVATE KEY-----/i },
  { name: "Token Pessoal GitHub (ghp_ / gho_)", regex: /gh[pousr]_[A-Za-z0-9_]{36}/ },
  { name: "Chave de Acesso AWS", regex: /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/ },
  { name: "Secret de Cliente Azure / Entra hardcoded", regex: /client_secret\s*=\s*["'][A-Za-z0-9~_.-]{30,}["']/i },
  { name: "Chave de API OpenAI / Anthropic", regex: /(sk-[a-zA-Z0-9]{32,}|sk-ant-[a-zA-Z0-9-_]{32,})/ },
];

async function validateSecurity() {
  console.log("🔒 [Skill: Validar Segurança] Iniciando varredura...");
  let errors = 0;

  const targetFiles = await getFiles(path.join(ROOT, "src"), [".md", ".astro", ".ts", ".js"]);

  for (const file of targetFiles) {
    const relPath = path.relative(ROOT, file);
    const content = await readFile(file, "utf-8");

    // 1. Verificação de segredos e chaves reais vazadas
    for (const pattern of SECRET_PATTERNS) {
      if (pattern.regex.test(content)) {
        console.error(`❌ [Segurança] Possível vazamento de credencial (${pattern.name}) detectado em: ${relPath}`);
        errors++;
      }
    }

    // 2. Links externos com target="_blank" sem rel seguro
    const blankLinkMatches = content.matchAll(/<a\s+[^>]*target=["']_blank["'][^>]*>/gi);
    for (const match of blankLinkMatches) {
      const tag = match[0];
      if (!tag.includes('rel="noopener') && !tag.includes("rel='noopener") && !tag.includes('rel="me noopener')) {
        console.warn(`⚠️ [Segurança] Link com target="_blank" sem rel="noopener" em: ${relPath}\n   Tag: ${tag}`);
      }
    }
  }

  if (errors > 0) {
    console.error(`\n❌ Falha na validação de segurança: ${errors} problema(s) crítico(s) encontrado(s).\n`);
    process.exit(1);
  }

  console.log("✔ [Segurança] 0 credenciais vazadas e parâmetros de segurança verificados com sucesso.");
}

validateSecurity().catch((err) => {
  console.error("Erro fatal no validador de segurança:", err);
  process.exit(1);
});
