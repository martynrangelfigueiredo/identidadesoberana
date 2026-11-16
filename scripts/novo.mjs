#!/usr/bin/env node
/**
 * Scaffold de novos artigos técnicos para a Identidade Soberana.
 * Uso:
 *   npm run novo:artigo -- <slug> "Título Autoral"
 */
import { writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const [rawSlug, ...tituloRest] = process.argv.slice(2);
const titulo = tituloRest.join(" ");

if (!rawSlug) {
  console.log(`Uso:
  npm run novo:artigo -- <slug> "Título Autoral"`);
  process.exit(1);
}

const hoje = new Date().toISOString().slice(0, 10);
const slug = rawSlug.startsWith("20") ? rawSlug : `${hoje}-${rawSlug}`;

const file = path.join(ROOT, "src", "content", "blog", `${slug}.md`);
if (existsSync(file)) {
  console.error(`Erro: o artigo "${slug}.md" já existe.`);
  process.exit(1);
}

const template = `---
title: "${titulo || "Título suave, autoral e em português"}"
description: "Resumo executivo do incidente e escopo da investigação (até 160 caracteres)."
date: ${hoje}
categoria: SOC
tags: [sentinel, azure, soc, incident-response, kql]
nivel: Intermediário
---

Breve introdução contextualizando o comportamento suspeito detectado pelo Microsoft Sentinel no tenant e o impacto para a operação de segurança.

> **TL;DR para o SOC:** Resumo prático de 2 a 3 linhas com o que deve ser feito com urgência caso o alerta seja verdadeiro positivo.

> 📘 **Referência no Microsoft Learn:** Este playbook baseia-se nas regras analíticas nativas de detecção do Microsoft Sentinel:
> - [Microsoft Sentinel — Built-in scheduled analytics rules catalog (Learn)](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in)

---

## 1. O que significa esse incidente?

Explicação detalhada dos vetores de ameaça: cenários legítimos de falsos positivos versus atividade de um adversário buscando persistência ou evasão.

---

## 2. Dica de KQL: [Foco da consulta]

A query abaixo projeta algumas colunas úteis para contextualizar o evento no Sentinel:

\`\`\`kql
let tempoAnalise = 24h;
// Substitua pela tabela e filtros adequados
AuditLogs
| where TimeGenerated >= ago(tempoAnalise)
| mv-expand Target = TargetResources
| project
    DataHora = TimeGenerated,
    Acao = ActivityDisplayName,
    Ator = tostring(InitiatedBy.user.userPrincipalName),
    Alvo = tostring(Target.userPrincipalName),
    IDCorrelacao = CorrelationId
| order by DataHora desc
\`\`\`

---

## 3. Matriz das 5 Perguntas Obrigatórias

| Pergunta | Onde Validar | O que verificar |
|---|---|---|
| **1. O que foi feito?** | AuditLogs / Activity | Ação exata e escopo da alteração. |
| **2. Quem fez?** | InitiatedBy | Identidade originadora e histórico da conta. |
| **3. Poderia ter feito?** | Roles & Permissões | A conta possuía autorização formal para a ação? |
| **4. Há chamado formal?** | ITSM (ServiceNow / Jira) | Validação cruzada com ticket aprovado e justificativa. |
| **5. A sessão foi legítima?** | SigninLogs / Entra ID Protection | Validação de MFA, IP, país habitual e risco de sessão. |

---

## 4. Onde Investigar no Portal do Microsoft Entra / Azure

Caminho exato no portal:
1. Navegue até:
   > **Portal / Centro de Administração** > **Caminho exato da funcionalidade**
2. Inspecione os logs de auditoria e filtre pelo \`CorrelationId\`.

---

## 5. Validação em Ferramentas de ITSM

Cruze o evento com as solicitações formais registradas em ITSM (ServiceNow, Jira Service Management, Freshservice ou Zendesk):
* Número da GMUD / Change Request ou Ticket de incidente;
* Justificativa informada no campo \`ResultReason\`;
* Usuário que aprovou o ticket no sistema corporativo.

---

## 6. Procedimento Técnico de Resposta & Contenção

Se a atividade for confirmada como não autorizada ou maliciosa, execute o playbook imediato de contenção:
1. Revogue as sessões ativas do usuário originador (\`Revoke sessions\` no Entra ID Protection);
2. Force a redefinição de senha e alterne para métodos de autenticação resistentes a phishing (FIDO2 / Passkey);
3. Reverta as permissões ou configurações alteradas;
4. Bloqueie IPs anômalos no firewall perimetral ou Conditional Access.
`;

await writeFile(file, template, "utf8");
console.log(`✔ Novo artigo criado: src/content/blog/${slug}.md`);
