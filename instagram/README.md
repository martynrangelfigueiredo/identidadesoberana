# Carrosséis do Instagram

Cada post é uma pasta em `instagram/posts/AAAA-MM-DD-slug/` com um `post.json`.
O gerador monta os slides com a identidade visual da marca (não há estilo dentro do JSON).

```bash
npm install                                   # 1ª vez
npm run carrossel -- 2026-11-09-senha-forte          # gera carrossel.html (preview) + legenda.txt
npm run carrossel -- 2026-11-09-senha-forte --png    # + png/01.png … (1080x1350, prontos pra postar)
```

## Formato do `post.json`

```jsonc
{
  "titulo": "Título interno",
  "categoria": "Senhas",          // aparece no chip de todos os slides (pode sobrescrever com "chip" no slide)
  "data": "2026-11-09",
  "slides": [ /* 6 a 8 slides */ ],
  "legenda": "Texto da legenda...\n\nCom quebras de linha",
  "hashtags": ["segurancadigital", "privacidade"]
}
```

Marcação nos textos: `*palavra*` = marca-texto amarelo · `**palavra**` = negrito · `\n` = quebra de linha.

### Tipos de slide

| tipo | campos | uso |
|---|---|---|
| `capa` | `titulo`, `subtitulo`, `ilustracao` | 1º slide |
| `dica` | `numero`, `titulo`, `texto` (string ou lista), `sabia` (opcional), `ilustracao` | 1 dica por slide |
| `lista` | `titulo`, `texto` (opcional), `itens[]`, `ilustracao` | passo a passo numerado |
| `comparacao` | `titulo`, `faca[]`, `evite[]`, `ilustracao` | Faça / Evite |
| `texto` | `titulo`, `texto`, `ilustracao` | explicação curta em card |
| `resumo` | `titulo` (padrão "Resumindo"), `itens[]` | checklist ✓ |
| `cta` | `titulo`, `texto` | último slide (salvar/compartilhar/seguir) |

`ilustracao` = nome de um SVG em `brand/ilustracoes/` (ou um `.svg` na própria pasta do post):
`celular`, `cadeado`, `cartao`, `email`, `senha`, `escudo`.

### Limites para caber no slide
- Título de capa: até ~45 caracteres. Título de dica: até ~40.
- Texto de dica: até ~180 caracteres. Itens de lista/resumo: até 5 itens de ~50 caracteres.
- Se usar `sabia` **e** `ilustracao` no mesmo slide, mantenha o texto curto (~120 caracteres).
- Sempre confira o `carrossel.html` antes de exportar.

