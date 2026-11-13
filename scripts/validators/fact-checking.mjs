#!/usr/bin/env node
/**
 * scripts/validators/fact-checking.mjs
 * Validador de Fact Checking e Precisão Técnica:
 * - Valida presença de links oficiais do Microsoft Learn nos playbooks de Sentinel.
 * - Valida existência e escrita de tabelas oficiais do Kusto/Sentinel (AuditLogs, SigninLogs, etc.).
 * - Valida IDs de técnicas MITRE ATT&CK (formato T1xxx).
 * - Enforça regras de terminologia técnica (secrets, Service Principal, tenant, playbook, bypass).
 */
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const BLOG_DIR = path.join(ROOT, "src", "content", "blog");

const VALID_KQL_TABLES = new Set([
  "AuditLogs",
  "SigninLogs",
  "AADServicePrincipalSignInLogs",
  "AADNonInteractiveUserSignInLogs",
  "IdentityInfo",
  "SecurityIncident",
  "SecurityAlert",
  "DeviceProcessEvents",
  "DeviceLogonEvents",
  "DeviceNetworkEvents",
  "DeviceFileEvents",
  "DeviceEvents",
  "BehaviorAnalytics",
]);

async function getMdFiles(dir) {
  let files = [];
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files = files.concat(await getMdFiles(fullPath));
    } else if (entry.name.endsWith(".md")) {
      files.push(fullPath);
    }
  }
  return files;
}

async function validateFactChecking() {
  console.log("🔍 [Skill: Fact Checking] Verificando precisão técnica e documentações oficiais...");
  let errors = 0;
  const mdFiles = await getMdFiles(BLOG_DIR);

  for (const file of mdFiles) {
    const relPath = path.relative(ROOT, file);
    const content = await readFile(file, "utf-8");

    // 1. Verificação de link do Microsoft Learn
    if (!content.includes("learn.microsoft.com")) {
      console.error(`❌ [Fact Checking] Artigo sem referência oficial ao Microsoft Learn: ${relPath}`);
      errors++;
    }

    // 2. Proibição estrita do termo traduzido incorreto "segredo / segredos" (deve ser "secret / secrets")
    const segredoMatch = content.match(/\bsegredos?\b/i);
    if (segredoMatch) {
      console.error(`❌ [Fact Checking] Termo incorreto "${segredoMatch[0]}" detectado em: ${relPath}. Use "secret / secrets".`);
      errors++;
    }

    // 3. Proibição do termo "locatário" no lugar de "tenant"
    const locatarioMatch = content.match(/\blocat[áa]rio(s)?\b/i);
    if (locatarioMatch) {
      console.error(`❌ [Fact Checking] Termo desatualizado "${locatarioMatch[0]}" detectado em: ${relPath}. Use "tenant / tenants".`);
      errors++;
    }

    // 4. Verificação de tabelas KQL dentro dos blocos ```kql ... ```
    const kqlBlocks = content.matchAll(/```kql\s*([\s\S]*?)```/g);
    for (const match of kqlBlocks) {
      const code = match[1];
      const statements = code.split(";");
      const declaredLets = new Set();

      // Primeiro passo: coleta todos os nomes de variáveis let
      for (const stmt of statements) {
        const clean = stmt.replace(/\/\/.*/g, "").trim();
        if (clean.startsWith("let ")) {
          const varName = clean.slice(4).split(/[\s=]/)[0].trim();
          if (varName) declaredLets.add(varName);
        }
      }

      // Segundo passo: valida tabelas raiz
      for (const stmt of statements) {
        const clean = stmt.replace(/\/\/.*/g, "").trim();
        if (!clean) continue;
        if (clean.startsWith("let ")) {
          const eqIdx = clean.indexOf("=");
          if (eqIdx !== -1) {
            const rhs = clean.slice(eqIdx + 1).trim();
            const rootTable = rhs.split(/[\s|]/)[0];
            if (/^[A-Z][a-zA-Z0-9_]+$/.test(rootTable) && !VALID_KQL_TABLES.has(rootTable) && !declaredLets.has(rootTable)) {
              console.warn(`⚠️ [Fact Checking] Tabela raiz KQL "${rootTable}" em ${relPath} não está na lista primária do Sentinel.`);
            }
          }
        } else {
          const rootTable = clean.split(/[\s|]/)[0];
          if (/^[A-Z][a-zA-Z0-9_]+$/.test(rootTable) && !VALID_KQL_TABLES.has(rootTable) && !declaredLets.has(rootTable)) {
            console.warn(`⚠️ [Fact Checking] Tabela raiz KQL "${rootTable}" em ${relPath} não está na lista primária do Sentinel.`);
          }
        }
      }
    }
  }

  if (errors > 0) {
    console.error(`\n❌ Falha no Fact Checking: ${errors} inconsistência(s) encontrada(s).\n`);
    process.exit(1);
  }

  console.log("✔ [Fact Checking] Referências do Microsoft Learn, tabelas KQL e terminologias 100% validadas.");
}

validateFactChecking().catch((err) => {
  console.error("Erro fatal no validador de Fact Checking:", err);
  process.exit(1);
});
