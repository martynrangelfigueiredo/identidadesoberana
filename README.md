# identidade soberana

**Segurança digital sem complicação.**

- 💻 Site/blog técnico (SOC, IAM, Compliance): https://identidadesoberana.com.br
- 📱 Instagram para todo mundo: [@identidadesoberana](https://instagram.com/identidadesoberana)

| Pasta | Conteúdo |
|---|---|
| `brand/` | Manual da marca ([BRAND.md](brand/BRAND.md)), voz ([CONTEUDO.md](brand/CONTEUDO.md)), tokens, logos e ilustrações |
| `instagram/` | Template e posts de carrossel ([como usar](instagram/README.md)) |
| `src/` | Site em Astro (posts em `src/content/blog/`) |
| `scripts/` | Gerador de carrosséis |

```bash
npm install
npm run dev                                    # site em http://localhost:4321
npm run carrossel -- 2026-11-09-senha-forte --png   # exporta carrossel
```

Instruções para IA: [AGENTS.md](AGENTS.md).
