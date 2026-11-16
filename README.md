# Identidade Soberana

**Segurança digital sem complicação.**

- 💻 Site técnico de SOC, IAM e Nuvem Soberana: https://identidadesoberana.com.br

| Pasta | Conteúdo |
|---|---|
| `brand/` | Manual da marca ([BRAND.md](brand/BRAND.md)), diretrizes de conteúdo ([CONTEUDO.md](brand/CONTEUDO.md)), tokens e logos |
| `src/` | Site em Astro (artigos em `src/content/blog/` com i18n nativo em DE, ZH, EN e PT) |
| `scripts/` | Validadores de segurança, KQL, conformidade e scaffolding (`novo:artigo`) |
| `.agents/skills/` | AI Skills do repositório para criação e auditoria de conteúdo |

```bash
npm install
npm run dev          # ambiente local em http://localhost:4321
npm run validate     # pipeline de validação de AI Skills
npm run build        # build estático de produção
```

Instruções para IA e automações: [AGENTS.md](AGENTS.md).
