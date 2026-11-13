#!/usr/bin/env node
/**
 * Scaffold de novos conteúdos para a Identidade Soberana.
 * Uso:
 *   node scripts/novo.mjs artigo <slug> "Título Suave e Autoral"
 *   node scripts/novo.mjs carrossel <slug> "Título da Capa"
 */
import { writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const [tipo, rawSlug, ...tituloRest] = process.argv.slice(2);
const titulo = tituloRest.join(" ");

if (!tipo || !rawSlug) {
  console.log(`Uso:
  npm run novo:artigo -- <slug> "Título Autoral"
  npm run novo:carrossel -- <slug> "Título da Capa"`);
  process.exit(1);
}

const hoje = new Date().toISOString().slice(0, 10);
const slug = rawSlug.startsWith("20") ? rawSlug : `${hoje}-${rawSlug}`;

if (tipo === "artigo") {
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

Confirmação de aprovações prévias e rastreabilidade independente de chamados (ServiceNow, Jira Service Management, Zendesk ou Freshservice).

---

## 6. Procedimento de Resposta e Contenção

Passos imediatos caso a ação seja confirmada como não autorizada:
1. Contenção imediata (revogação de sessão, bloqueio temporário ou reset de credenciais).
2. KQL para auditoria pós-incidente.
`;

  await writeFile(file, template);
  console.log(`✔ Novo artigo criado: src/content/blog/${slug}.md`);
} else if (tipo === "carrossel") {
  const dir = path.join(ROOT, "instagram", "posts", slug);
  if (existsSync(dir)) {
    console.error(`Erro: o carrossel "${slug}" já existe.`);
    process.exit(1);
  }
  await mkdir(dir, { recursive: true });

  const postJson = {
    titulo: titulo || "Título da Capa",
    categoria: "Segurança",
    data: hoje,
    slides: [
      {
        tipo: "capa",
        titulo: titulo ? `*${titulo}*` : "Sua conta está *segura*?",
        subtitulo: "Dicas simples para proteger seu dia a dia.",
        ilustracao: "escudo"
      },
      {
        tipo: "dica",
        numero: 1,
        titulo: "Primeira dica *importante*",
        texto: "Explicação simples e sem jargão com foco na ação prática que o usuário comum deve tomar.",
        sabia: "Curiosidade rápida sobre como os golpistas agem.",
        ilustracao: "celular"
      },
      {
        tipo: "dica",
        numero: 2,
        titulo: "Segunda dica *prática*",
        texto: "Mais uma orientação direta e amigável.",
        ilustracao: "cadeado"
      },
      {
        tipo: "comparacao",
        titulo: "O que fazer?",
        faca: [
          "Verificar conexões ativas",
          "Ativar verificação em duas etapas"
        ],
        evite: [
          "Clicar em links suspeitos",
          "Passar códigos recebidos por SMS"
        ],
        ilustracao: "senha"
      },
      {
        tipo: "resumo",
        itens: [
          "Ponto principal do post",
          "Ação rápida para fazer hoje",
          "Segurança sem complicação"
        ]
      },
      {
        tipo: "cta",
        titulo: "Gostou? *Salva* esse post!",
        texto: "E mande para amigos e familiares que precisam saber disso! 💚💛"
      }
    ],
    legenda: `${titulo || "Dica de segurança importante!"} 🔐\n\nArrasta pro lado pra ver como se proteger no dia a dia. 👉\n\nSalva pra consultar depois e compartilha com quem precisa! 💚💛`,
    hashtags: ["segurancadigital", "dicasdeseguranca", "privacidade", "identidadesoberana", "protecaodedados"]
  };

  await writeFile(path.join(dir, "post.json"), JSON.stringify(postJson, null, 2));
  console.log(`✔ Novo carrossel criado: instagram/posts/${slug}/post.json`);
}

