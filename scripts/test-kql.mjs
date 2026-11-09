#!/usr/bin/env node
/**
 * test-kql.mjs — Linter e Validador de Sintaxe KQL (Kusto Query Language)
 *
 * Valida todas as queries KQL em src/content/blog/*.md:
 * 1. Proíbe caracteres não-ASCII (ç, ã, é, etc.) fora de strings/comentários.
 * 2. Valida balanceamento de parênteses, colchetes e chaves.
 * 3. Valida se declarações 'let' terminam com ponto-e-vírgula ';'.
 * 4. Valida operadores canônicos de pipeline (| where, | project, | summarize, etc.).
 *
 * Uso: node scripts/test-kql.mjs
 */
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BLOG_DIR = path.join(ROOT, "src", "content", "blog");

const KQL_OPERATORS = new Set([
  "where", "project", "project-away", "project-keep", "project-rename", "project-reorder",
  "extend", "summarize", "join", "lookup", "union", "mv-apply", "mv-expand",
  "order", "sort", "top", "take", "limit", "distinct", "count",
  "parse", "parse-where", "extract", "search", "find", "sample",
  "render", "make-series", "serialize", "as", "evaluate", "mvexpand"
]);

function stripCommentsAndStrings(code) {
  // Substitui strings e comentários por espaços para preservar linha/coluna exata
  let inString = null;
  let inLineComment = false;
  let inBlockComment = false;
  let isEscaped = false;
  let result = "";

  for (let i = 0; i < code.length; i++) {
    const ch = code[i];
    const next = code[i + 1];

    if (inLineComment) {
      if (ch === "\n") {
        inLineComment = false;
        result += "\n";
      } else {
        result += " ";
      }
      continue;
    }

    if (inBlockComment) {
      if (ch === "*" && next === "/") {
        inBlockComment = false;
        result += "  ";
        i++;
      } else {
        result += ch === "\n" ? "\n" : " ";
      }
      continue;
    }

    if (inString) {
      if (isEscaped) {
        isEscaped = false;
        result += " ";
      } else if (ch === "\\") {
        isEscaped = true;
        result += " ";
      } else if (ch === inString) {
        inString = null;
        result += " ";
      } else {
        result += ch === "\n" ? "\n" : " ";
      }
      continue;
    }

    // Abertura de comentários
    if (ch === "/" && next === "/") {
      inLineComment = true;
      result += "  ";
      i++;
      continue;
    }
    if (ch === "/" && next === "*") {
      inBlockComment = true;
      result += "  ";
      i++;
      continue;
    }

    // Abertura de strings
    if (ch === '"' || ch === "'") {
      inString = ch;
      result += " ";
      continue;
    }

    result += ch;
  }

  return result;
}

function validateKql(query, fileName, blockIndex) {
  const errors = [];
  const lines = query.split("\n");
  const stripped = stripCommentsAndStrings(query);
  const strippedLines = stripped.split("\n");

  // 1. Verificação de caracteres não-ASCII fora de strings e comentários
  for (let l = 0; l < strippedLines.length; l++) {
    const line = strippedLines[l];
    for (let c = 0; c < line.length; c++) {
      const code = line.charCodeAt(c);
      // Qualquer caractere fora da tabela ASCII padrão (0 a 127)
      if (code > 127) {
        const char = lines[l][c] || line[c];
        errors.push(
          `Caractere inválido em identificador KQL: '${char}' (linha ${l + 1}, col ${c + 1}). Identificadores, aliases e variáveis devem ser estritamente ASCII (sem acentos ou cedilha).`
        );
      }
    }
  }

  // 2. Balanceamento de parênteses, colchetes e chaves
  const stack = [];
  const pairs = { ")": "(", "]": "[", "}": "{" };
  for (let l = 0; l < strippedLines.length; l++) {
    const line = strippedLines[l];
    for (let c = 0; c < line.length; c++) {
      const ch = line[c];
      if (ch === "(" || ch === "[" || ch === "{") {
        stack.push({ ch, line: l + 1, col: c + 1 });
      } else if (ch === ")" || ch === "]" || ch === "}") {
        if (stack.length === 0) {
          errors.push(`Fechamento inesperado de '${ch}' sem abertura correspondente (linha ${l + 1}, col ${c + 1}).`);
        } else {
          const top = stack.pop();
          if (top.ch !== pairs[ch]) {
            errors.push(`Esperava fechar '${top.ch}', mas encontrou '${ch}' (linha ${l + 1}, col ${c + 1}).`);
          }
        }
      }
    }
  }
  while (stack.length > 0) {
    const unclosed = stack.pop();
    errors.push(`Abertura de '${unclosed.ch}' não foi fechada (linha ${unclosed.line}, col ${unclosed.col}).`);
  }

  // 3. Validação de declarações 'let'
  const letRegex = /^\s*let\s+([A-Za-z0-9_]+)\s*=/gm;
  let match;
  while ((match = letRegex.exec(stripped)) !== null) {
    const varName = match[1];
    // Procura o fechamento ';' correspondente
    const rest = stripped.slice(match.index);
    const semiIndex = rest.indexOf(";");
    if (semiIndex === -1) {
      errors.push(`Declaração 'let ${varName}' não é finalizada com ponto-e-vírgula ';'.`);
    }
  }

  // 4. Validação de operadores de pipe '|'
  const pipeRegex = /\|\s*([a-zA-Z_-]+)/g;
  while ((match = pipeRegex.exec(stripped)) !== null) {
    const op = match[1].toLowerCase();
    if (!KQL_OPERATORS.has(op)) {
      errors.push(`Operador de pipeline desconhecido após '|': '${match[1]}'.`);
    }
  }

  return errors;
}

const files = (await readdir(BLOG_DIR)).filter((f) => f.endsWith(".md"));
let totalQueries = 0;
let totalErrors = 0;

console.log(`\n🔍 Validando sintaxe KQL nos artigos em ${path.relative(ROOT, BLOG_DIR)}...\n`);

for (const file of files) {
  const content = await readFile(path.join(BLOG_DIR, file), "utf8");
  const kqlRegex = /```kql\r?\n([\s\S]*?)```/g;
  let match;
  let blockIndex = 0;

  while ((match = kqlRegex.exec(content)) !== null) {
    blockIndex++;
    totalQueries++;
    const query = match[1];
    const errors = validateKql(query, file, blockIndex);

    if (errors.length > 0) {
      totalErrors += errors.length;
      console.error(`❌ [${file}] Query #${blockIndex} com erro:`);
      for (const err of errors) {
        console.error(`   - ${err}`);
      }
    } else {
      console.log(`✔ [${file}] Query #${blockIndex} validada com sucesso.`);
    }
  }
}

console.log(`\n--------------------------------------------------`);
if (totalErrors === 0) {
  console.log(`🎉 Todas as ${totalQueries} queries KQL passaram nos testes com sucesso!\n`);
  process.exit(0);
} else {
  console.error(`💥 Encontrados ${totalErrors} erros em ${totalQueries} queries KQL testadas.\n`);
  process.exit(1);
}
