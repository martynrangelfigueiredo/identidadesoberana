# Identidade Soberana — Voz e Conteúdo

Mesmo objetivo (tecnologia, operações de segurança, conformidade e proteção de dados pessoais),
**dois públicos, duas linguagens**, **uma identidade visual**.

---

## 📱 Instagram — `@identidadesoberana` (público leigo)

**Para quem:** qualquer pessoa — sua mãe, seu tio, o vizinho. Nenhum conhecimento técnico.

**Voz:** amigo que entende do assunto. Simples, direto, um pouco de humor, carinhoso. Nunca dá bronca, nunca assusta.

### Regras de escrita
- Frases curtas (até ~20 palavras). Uma ideia por slide.
- **Zero jargão.** Se precisar de um termo, explique: "verificação em duas etapas (aquele código que chega no celular)".
- Fale com "você". Pode usar "pra", "tá", "né" com moderação.
- Humor leve, nunca às custas da vítima de golpe.
- Sempre termine com algo **prático** que a pessoa consegue fazer hoje.
- Use `*palavra*` para o marca-texto amarelo (1–3 por slide, só no que importa).
- Emojis: até 1 por slide no texto; na legenda, moderado (💚💛🔐👉).

| Em vez de… | Escreva… |
|---|---|
| Autenticação multifator | Verificação em duas etapas |
| Phishing | Golpe da mensagem falsa / link falso |
| Malware | Programa espião / vírus |
| Vazamento de credenciais | Sua senha foi parar na mão de outra pessoa |
| Engenharia social | Golpista que te enrola na conversa |
| "ALERTA! Você está em perigo!" | "Bora deixar isso mais seguro?" |

### Estrutura do carrossel (6–8 slides)
1. **Capa** — pergunta ou promessa curiosa + ilustração. Ex.: "Sua senha é *forte* mesmo?"
2. **Dicas** — uma por slide, numeradas, com ilustração ou caixa "Você sabia?".
3. **Faça / Evite** (opcional).
4. **Resumo** — checklist com ✓.
5. **CTA** — salvar, compartilhar, seguir.

### Legenda
Gancho na 1ª linha → 2–3 linhas de contexto → "Arrasta pro lado 👉" → CTA → 5–8 hashtags em português.

### Pilares de pauta
Senhas e gerenciadores · Golpes (WhatsApp, Pix, falso atendente, boleto) · Privacidade nas redes ·
Celular seguro · Compras online · LGPD explicada pro cidadão (seus direitos) · Crianças e idosos na internet.

---

## 💻 Site — `identidadesoberana.com.br` (público técnico)

**Para quem:** SOC Analysts (N1–N3), times de Identity & Access Management, Compliance/GRC, DPOs.

**Voz:** colega sênior generoso. Técnico, preciso, direto ao ponto, sem arrogância. Ainda leve — sem sensacionalismo.

### Regras de escrita
- Comece com **TL;DR** (blockquote) quando o artigo for longo.
- Termos técnicos em inglês são OK (SIEM, IGA, PAM, AitM), em *itálico* na primeira vez.
- Sempre que possível traga: **queries de detecção** (KQL, SPL, Sigma), **tabelas comparativas**,
  **mapeamento de controles** (ISO 27001, NIST CSF, CIS, LGPD, SOC 2), **MITRE ATT&CK IDs** e **passos acionáveis**.
- Cite fontes primárias (docs de fornecedores, NIST, ANPD, CERT.br).
- Títulos de seção curtos. Um H2 a cada ~300 palavras.

### Frontmatter obrigatório (`src/content/blog/AAAA-MM-DD-slug.md`)
```yaml
---
title: "Título claro e específico"
description: "1–2 frases, até ~160 caracteres (vira o resumo e a meta description)."
date: 2026-11-09
categoria: SOC        # SOC | IAM | Compliance | Privacidade
tags: [tag1, tag2]
nivel: Intermediário  # Intermediário | Avançado
draft: false
---
```

### Categorias
- **SOC** — detecção, resposta a incidentes, SIEM/SOAR, threat hunting, playbooks.
- **IAM** — IGA, PAM, SSO, MFA, Zero Trust, ciclo de vida de identidades (JML).
- **Compliance** — LGPD, ISO 27001, SOC 2, PCI DSS, auditoria, evidências.
- **Privacidade** — proteção de dados pessoais na prática, direitos do titular, DPIA/RIPD.

---

## 🔁 Mesmo tema, dois canais (exemplo)

| Tema | Instagram | Site |
|---|---|---|
| MFA | "Ative a verificação em duas etapas no WhatsApp" | "MFA resistente a phishing: por que push já não basta" |
| Vazamentos | "Como saber se seus dados vazaram" | "Monitorando credenciais vazadas: fontes, automação e resposta" |
| LGPD | "A LGPD te dá esses 5 direitos" | "Atendendo requisições de titulares em escala" |

