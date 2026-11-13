#!/usr/bin/env node
/**
 * scripts/validar-tudo.mjs
 * Orquestrador Central de Validação Pré-Build do Identidade Soberana:
 * Executa todas as skills/validadores antes de compilar o site:
 * 1. Segurança (chaves/tokens vazados, links seguros)
 * 2. Fact Checking (Microsoft Learn, tabelas Sentinel, terminologia)
 * 3. Performance (Zero bloat, fontes não-bloqueantes)
 * 4. Compliance & Privacidade (Zero PII, LGPD, desde 2026)
 * 5. KQL Syntax (24 queries testadas contra Bryce Maxheimer Engine)
 * 6. i18n & Paridade (4 idiomas, seletor DE->ZH->EN->PT, marca intacta)
 */
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const VALIDATORS = [
  { name: "Segurança", script: "scripts/validators/seguranca.mjs" },
  { name: "Fact Checking", script: "scripts/validators/fact-checking.mjs" },
  { name: "Performance", script: "scripts/validators/performance.mjs" },
  { name: "Compliance & Privacidade", script: "scripts/validators/compliance.mjs" },
  { name: "Sintaxe KQL (Bryce Engine)", script: "scripts/test-kql.mjs" },
  { name: "i18n & Integridade", script: "scripts/validators/i18n.mjs" },
];

function runScript(scriptPath) {
  return new Promise((resolve, reject) => {
    const fullPath = path.join(ROOT, scriptPath);
    const proc = spawn(process.execPath, [fullPath], { stdio: "inherit" });
    proc.on("close", (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`Validador ${scriptPath} falhou com código ${code}`));
      }
    });
  });
}

async function main() {
  console.log("\n🚀 ===================================================================");
  console.log("   IDENTIDADE SOBERANA — PIPELINE DE VALIDAÇÃO PRÉ-BUILD (AI SKILLS)");
  console.log("===================================================================\n");

  const startTime = Date.now();

  for (const v of VALIDATORS) {
    try {
      await runScript(v.script);
      console.log("");
    } catch (err) {
      console.error(`\n❌ [BLOQUEIO PRÉ-BUILD] A validação "${v.name}" reprovou.`);
      console.error("Corrija as inconsistências acima antes de rodar o build de produção.\n");
      process.exit(1);
    }
  }

  const duration = ((Date.now() - startTime) / 1000).toFixed(2);
  console.log("===================================================================");
  console.log(`🎉 TODAS AS VALIDAÇÕES APROVADAS COM SUCESSO! (${duration}s)`);
  console.log("   O projeto está pronto e seguro para o build de produção.");
  console.log("===================================================================\n");
}

main().catch((err) => {
  console.error("Erro inesperado no pipeline de validação:", err);
  process.exit(1);
});
