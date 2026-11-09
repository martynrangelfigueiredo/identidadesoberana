# Instruções para IA — Identidade Soberana

Este repositório produz conteúdo para **dois canais com a MESMA identidade visual**:

| Canal | Público | Formato | Onde |
|---|---|---|---|
| Instagram `@identidadesoberana` | **Leigos** — linguagem extremamente simples, dicas básicas | **Sempre carrossel** 4:5 (1080x1350), 6–8 slides | `instagram/posts/AAAA-MM-DD-slug/post.json` |
| Site `identidadesoberana.com.br` | **SOC Analysts, IAM, Compliance** — técnico | Artigo Markdown (Astro) | `src/content/blog/AAAA-MM-DD-slug.md` |

Tema comum: tecnologia, operações de segurança, conformidade e proteção de dados pessoais.

## Antes de criar QUALQUER conteúdo, leia:
1. [`brand/BRAND.md`](brand/BRAND.md) — identidade visual (logo, cores, fontes, efeitos, ilustrações).
2. [`brand/CONTEUDO.md`](brand/CONTEUDO.md) — tom de voz e regras de cada canal.
3. Para carrosséis: [`instagram/README.md`](instagram/README.md) — formato do `post.json` e limites de texto.

## Regras inegociáveis
- Fundo **branco**; verde `#009C3B` é a cor principal; amarelo `#FFDF00` só em destaques; vermelho `#E1251B` **só na estrela do logo**.
- Fontes: Nunito (títulos), Inter (texto), JetBrains Mono (código).
- Cores/fontes vêm de `brand/tokens.css`. Nunca invente cores nem escreva estilos dentro de `post.json` ou dos posts `.md`.
- Tom leve e amigável, **nunca alarmista**. Sem mascote, sem rosto, sem "hacker de capuz".
- Instagram: zero jargão. Site: técnico, com queries, tabelas e mapeamento de controles quando fizer sentido.

## Fluxos
- **Novo carrossel:** criar `instagram/posts/<data>-<slug>/post.json` → `npm run carrossel -- <data>-<slug>` → revisar `carrossel.html` → `--png` para exportar.
- **Novo artigo:** criar `src/content/blog/<data>-<slug>.md` com o frontmatter de `brand/CONTEUDO.md` → `npm run dev` para revisar.
- **Nova ilustração:** SVG 400x400 em `brand/ilustracoes/`, seguindo o estilo e o prompt da seção 6 de `BRAND.md`.

