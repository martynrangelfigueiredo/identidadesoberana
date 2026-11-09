# Identidade Soberana — Manual da Marca

> Este arquivo é a **fonte de verdade** da identidade visual. Qualquer IA ou pessoa que criar conteúdo
> (site ou Instagram) DEVE seguir este manual. Valores de cor/fonte em código ficam em [`tokens.css`](tokens.css).

---

## 1. Essência

| Item | Definição |
|---|---|
| **Nome** | Identidade Soberana (escrito em minúsculas no logo: `identidade soberana`) |
| **Slogan** | **Segurança digital sem complicação.** |
| **Instagram** | `@identidadesoberana` (público leigo, sempre carrossel) |
| **Site / blog** | `identidadesoberana.com.br` (público técnico: SOC, IAM, Compliance) |
| **Missão** | Tornar segurança, identidade e proteção de dados acessíveis: simples para quem é leigo, profunda para quem opera. |
| **Personalidade** | Leve, amigável, confiável, brasileira. Nunca alarmista, nunca "hacker sombrio". |
| **Quem fala** | A marca (sem rosto, sem mascote). Voz de "amigo que entende do assunto". |

### O que a marca NÃO é
- ❌ Tom de medo, ameaça, "ALERTA!", caveiras, hackers encapuzados, fundo preto com código verde.
- ❌ Mascote/personagem.
- ❌ Fotos de banco de imagem genéricas.

---

## 2. Logo

**Conceito:** um **selo** circular verde com uma **impressão digital** (a identidade de cada pessoa) no centro,
um **arco amarelo** na base (toque Brasil) e uma **estrela vermelha de 5 pontas** no canto superior direito,
"carimbando" o selo. A estrela é um aceno sutil ao Brasil/à esquerda — **ela só aparece no logo**, nunca como
elemento decorativo solto.

| Arquivo | Uso |
|---|---|
| [`logo/logo-icone.svg`](logo/logo-icone.svg) | Selo principal (fundos brancos/claros), favicon |
| [`logo/logo-icone-branco.svg`](logo/logo-icone-branco.svg) | Sobre fundo verde (rodapé do site, fita dos carrosséis) |
| [`logo/logo-horizontal.svg`](logo/logo-horizontal.svg) | Selo + nome + slogan (cabeçalhos, banners, capa) |
| [`logo/avatar-instagram.svg`](logo/avatar-instagram.svg) | Foto de perfil do Instagram (exportar 1080x1080 PNG) |

**Regras:**
- Área de respiro mínima ao redor do selo = 1/4 do diâmetro.
- Tamanho mínimo: 24 px (digital).
- Não distorcer, não girar, não trocar cores, não aplicar sombra pesada, não remover a estrela.
- Wordmark: `identidade` em Verde Profundo + `soberana` em Verde Soberano, Nunito 900, minúsculas.

---

## 3. Cores

Fundo é **sempre branco**. Verde é a cor da marca, amarelo é tempero, vermelho é só a estrela.

| Nome | HEX | Token | Uso | Proporção |
|---|---|---|---|---|
| Branco | `#FFFFFF` | `--is-branco` | Fundo de tudo | ~60% |
| Verde Soberano | `#009C3B` | `--is-verde` | Cor principal, botões, fita, números | ~20% |
| Verde Profundo | `#00612A` | `--is-verde-escuro` | Links, texto verde, sombras de ilustração | |
| Verde Médio | `#00B347` | `--is-verde-medio` | Brilho em ilustrações | |
| Verde Claro | `#E6F5EC` | `--is-verde-claro` | Blobs, chips, fundos suaves | ~10% |
| Verde Névoa | `#F3FAF5` | `--is-verde-nevoa` | Superfície alternativa, blocos de código | |
| Amarelo Ouro | `#FFDF00` | `--is-amarelo` | **Só destaques**: marca-texto, check, linha da fita | ~5% |
| Amarelo Claro | `#FFF7CC` | `--is-amarelo-claro` | Caixas "Você sabia?" / citações | |
| Vermelho Estrela | `#E1251B` | `--is-vermelho` | **Exclusivo da estrela do logo** | <1% |
| Tinta | `#1B2B22` | `--is-tinta` | Texto principal | |
| Cinza | `#5B6B62` | `--is-cinza` | Texto secundário | |
| Cinza Claro | `#9AA8A0` | `--is-cinza-claro` | Metadados | |
| Borda | `#DDE7E0` | `--is-borda` | Bordas, divisórias, pontos do grid | |

**Acessibilidade:**
- Texto corrido: sempre `Tinta` ou `Cinza` sobre branco.
- `Verde Soberano` como texto só em tamanhos grandes (≥ 24 px, negrito). Para links use `Verde Profundo`.
- **Nunca** texto amarelo sobre branco. Amarelo é fundo (marca-texto) com texto escuro por cima.
- Vermelho **nunca** para erro/alerta (evita tom de medo e preserva a estrela).

---

## 4. Tipografia (Google Fonts, gratuitas)

| Papel | Fonte | Pesos | Observação |
|---|---|---|---|
| Títulos | **Nunito** | 800 / 900 | Arredondada e amigável. `letter-spacing` levemente negativo |
| Texto | **Inter** | 400 / 500 / 600 / 700 | Legibilidade máxima |
| Código (só site) | **JetBrains Mono** | 400 / 600 | Blocos de código, KQL, SPL, YAML |

Escala nos carrosséis (1080x1350): capa 104 px · título 72 px · texto 40 px · listas 38 px · chip 28 px.
Escala no site: H1 `clamp(2rem, 4.5vw, 3rem)` · H2 1.75rem · texto 1.0625rem / 1.7.

---

## 5. Forma e estilo (Material + GNOME)

- **Cantos arredondados** em tudo: 12 px (pequeno), 20 px (médio), 28 px (cards grandes), pílula para chips/botões.
- **Superfícies brancas elevadas** com borda `#DDE7E0` e sombra suave esverdeada (`--is-sombra-1/2/3`).
- **Flat**: sem gradientes chamativos, sem glassmorphism pesado, sem neon.
- Ícones/emojis: permitidos com moderação (1 por item no máximo).

### Efeitos-assinatura (usar sempre — é o que torna a marca reconhecível)
1. **Marca-texto amarelo** em 1–3 palavras-chave por título (`*palavra*` no post.json; `<span class="hl">` no site).
2. **Fita verde/amarela ondulada** no rodapé — nos carrosséis ela é **contínua entre os slides** (efeito panorâmico ao arrastar); no site aparece no footer.
3. **Grid de pontos sutil** no topo, sumindo em degradê (toque "tech" leve).
4. **Blob orgânico verde-claro** num canto (alterna esquerda/direita entre slides).
5. **Número da dica em quadrado arredondado verde**, levemente inclinado (−4°).
6. **Chip** de categoria no canto superior esquerdo + **contador** `2/7` no direito.

---

## 6. Ilustrações

**Estilo:** flat, "objetos + mãos". Objetos do dia a dia (celular, cadeado, cartão, e-mail, campo de senha,
escudo, Wi-Fi, QR code…) às vezes segurados/tocados por **mãos** — humanos sem rosto. Sem contorno preto,
sombras feitas com tons mais escuros da mesma cor. Sempre sobre um **círculo Verde Claro** de fundo, com
1–2 "confetes" (círculos pequenos amarelo/verde médio).

- Paleta restrita: verdes da marca, amarelo, branco, Tinta, peles `#E8B98F` / `#A86B43` (alternar tons de pele).
- Formato: SVG `viewBox="0 0 400 400"`, salvo em [`ilustracoes/`](ilustracoes/) com nome em português minúsculo (`wifi.svg`).
- Existentes: `celular`, `cadeado`, `cartao`, `email`, `senha`, `escudo`.

**Prompt base para gerar novas ilustrações com IA:**
> Flat vector illustration, minimal, friendly, Material Design / GNOME style. [OBJETO] [com uma mão segurando/tocando,
> sem rosto]. Colors only: green #009C3B, dark green #00612A, light green #E6F5EC circle background, yellow #FFDF00 accents,
> white, skin tone #E8B98F. No outlines, no text, no gradients, soft simple shapes, rounded corners, white background, centered, square.

---

## 7. Instagram (carrossel)

- Formato **4:5 — 1080 x 1350 px**, **6 a 8 slides**.
- Estrutura padrão: **Capa → Dicas (1 por slide) → Faça/Evite (opcional) → Resumo → CTA**.
- Gerado por código (consistência 100%): veja [`../instagram/README.md`](../instagram/README.md).
- Foto de perfil: `avatar-instagram.svg`. Nome no perfil: **Identidade Soberana | Segurança digital**.
- Bio sugerida:
  ```
  🔐 Segurança digital sem complicação
  💚 Dicas simples pra proteger seus dados
  💛 Golpes, senhas, privacidade e mais
  👇 Conteúdo técnico no site
  ```
- Capas de Destaques: círculo Verde Claro + ícone/ilustração + rótulo curto (Senhas, Golpes, WhatsApp, Banco, Privacidade).

## 8. Site

- Mesma identidade, versão **sóbria**: mais tipografia, tabelas, código e diagramas; ilustrações raras.
- Sem modo escuro (fundo branco é parte da marca).
- Implementação: Astro em [`../src`](../src), estilos em [`../src/styles/global.css`](../src/styles/global.css).

Tom de voz e regras de conteúdo dos dois canais: [`CONTEUDO.md`](CONTEUDO.md).

