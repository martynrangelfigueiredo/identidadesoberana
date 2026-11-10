#!/usr/bin/env node
/**
 * Identidade Soberana — gerador de carrosséis do Instagram
 *
 * Uso:
 *   npm run carrossel -- <slug>          -> gera instagram/posts/<slug>/carrossel.html (preview)
 *   npm run carrossel -- <slug> --png    -> também exporta PNGs 1080x1350 em instagram/posts/<slug>/png/
 *
 * Conteúdo: instagram/posts/<slug>/post.json (veja instagram/README.md para o formato).
 * Visual: brand/tokens.css + instagram/template/carrossel.css. NÃO coloque estilos no post.json.
 */
import { readFile, writeFile, mkdir, readdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const HANDLE = "@identidadesoberana";
const W = 1080;

const args = process.argv.slice(2);
const slug = args.find((a) => !a.startsWith("--"));
const exportPng = args.includes("--png");

if (!slug) {
  const dir = path.join(ROOT, "instagram", "posts");
  const posts = existsSync(dir) ? await readdir(dir) : [];
  console.error("Informe o slug do post. Disponíveis:\n  " + posts.join("\n  "));
  process.exit(1);
}

const postDir = path.join(ROOT, "instagram", "posts", slug);
const post = JSON.parse(await readFile(path.join(postDir, "post.json"), "utf8"));
const tokens = await readFile(path.join(ROOT, "brand", "tokens.css"), "utf8");
const css = await readFile(path.join(ROOT, "instagram", "template", "carrossel.css"), "utf8");
const logo = await readFile(path.join(ROOT, "brand", "logo", "logo-icone.svg"), "utf8");
const logoBranco = await readFile(path.join(ROOT, "brand", "logo", "logo-icone-branco.svg"), "utf8");

// ---------- helpers ----------
const esc = (s = "") =>
  String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/** *texto* = marca-texto amarelo | **texto** = negrito | \n = quebra de linha */
const md = (s = "") =>
  esc(s)
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/\*(.+?)\*/g, '<span class="hl">$1</span>')
    .replace(/\n/g, "<br>");

const stripSvgHeader = (svg) => svg.replace(/<\?xml[^>]*>/, "").replace(/<title[^>]*>.*?<\/title>/s, "");

async function ilustracao(nome) {
  if (!nome) return "";
  const local = path.join(postDir, `${nome}.svg`);
  const global = path.join(ROOT, "brand", "ilustracoes", `${nome}.svg`);
  const file = existsSync(local) ? local : global;
  if (!existsSync(file)) {
    console.warn(`⚠ ilustração "${nome}" não encontrada (brand/ilustracoes/${nome}.svg)`);
    return "";
  }
  return `<div class="ilustra">${stripSvgHeader(await readFile(file, "utf8"))}</div>`;
}

/** Onda contínua: cada slide mostra um "pedaço" da mesma onda -> efeito panorâmico ao arrastar. */
function fita(i, total) {
  const full = W * total;
  const y = (x, base, amp) => (base + amp * Math.sin((2 * Math.PI * x) / 1700)).toFixed(1);
  let verde = `M0 210 L0 ${y(0, 110, 26)}`;
  let amarelo = `M0 ${y(0, 92, 26)}`;
  for (let x = 0; x <= full; x += 30) {
    verde += ` L${x} ${y(x, 110, 26)}`;
    amarelo += ` L${x} ${y(x, 92, 26)}`;
  }
  verde += ` L${full} 210 Z`;
  return `<div class="fita"><svg viewBox="${i * W} 0 ${W} 210" preserveAspectRatio="none">
    <path d="${amarelo}" fill="none" stroke="#FFDF00" stroke-width="14" stroke-linecap="round"/>
    <path d="${verde}" fill="#009C3B"/></svg></div>`;
}

// ---------- tipos de slide ----------
const tipos = {
  async capa(s) {
    return `<h1>${md(s.titulo)}</h1>
      ${s.subtitulo ? `<p class="sub">${md(s.subtitulo)}</p>` : ""}
      ${await ilustracao(s.ilustracao)}`;
  },
  async dica(s) {
    return `${s.numero != null ? `<div class="numero">${esc(s.numero)}</div>` : ""}
      <h2>${md(s.titulo)}</h2>
      ${(Array.isArray(s.texto) ? s.texto : [s.texto]).filter(Boolean).map((t) => `<p>${md(t)}</p>`).join("")}
      ${s.sabia ? `<div class="sabia"><b>Você sabia?</b> ${md(s.sabia)}</div>` : ""}
      ${await ilustracao(s.ilustracao)}`;
  },
  async lista(s, check = false) {
    return `<h2>${md(s.titulo)}</h2>
      ${s.texto ? `<p style="margin-bottom:36px">${md(s.texto)}</p>` : ""}
      <ul class="lista ${check ? "check" : ""}">
        ${s.itens.map((it, n) => `<li><span class="marca">${check ? "✓" : n + 1}</span><span>${md(it)}</span></li>`).join("")}
      </ul>
      ${await ilustracao(s.ilustracao)}`;
  },
  async resumo(s) {
    return tipos.lista({ titulo: "Resumindo", ...s }, true);
  },
  async comparacao(s) {
    return `<h2>${md(s.titulo)}</h2>
      <div class="compara">
        <div class="col faca"><h3>👍 Faça</h3><ul>${s.faca.map((t) => `<li>${md(t)}</li>`).join("")}</ul></div>
        <div class="col evite"><h3>✋ Evite</h3><ul>${s.evite.map((t) => `<li>${md(t)}</li>`).join("")}</ul></div>
      </div>
      ${await ilustracao(s.ilustracao)}`;
  },
  async texto(s) {
    return `<h2>${md(s.titulo)}</h2>
      <div class="card">${(Array.isArray(s.texto) ? s.texto : [s.texto]).map((t) => `<p>${md(t)}</p>`).join("")}</div>
      ${await ilustracao(s.ilustracao)}`;
  },
  async cta(s) {
    return `<div class="selo">${stripSvgHeader(logo)}</div>
      <h2>${md(s.titulo || "Gostou? *Salva* esse post!")}</h2>
      <p>${md(s.texto || "Segurança digital sem complicação.")}</p>
      <div class="acoes">
        <div class="acao"><span>🔖</span> Salve para lembrar depois</div>
        <div class="acao"><span>📤</span> Mande para quem precisa ver</div>
        <div class="acao"><span>➕</span> Siga ${HANDLE}</div>
      </div>`;
  },
};

// ---------- montagem ----------
const total = post.slides.length;
const slidesHtml = [];
for (const [i, s] of post.slides.entries()) {
  const render = tipos[s.tipo];
  if (!render) throw new Error(`Tipo de slide desconhecido: "${s.tipo}" (slide ${i + 1})`);
  const ultimo = i === total - 1;
  slidesHtml.push(`
  <section class="slide ${s.tipo}" data-n="${i + 1}">
    <div class="topo">
      <span class="chip"><span class="ponto"></span>${esc(s.chip || post.categoria || "Dica")}</span>
      <span class="contador">${i + 1}/${total}</span>
    </div>
    ${await render(s)}
    ${fita(i, total)}
    <div class="rodape">
      <span class="marca-rodape">${stripSvgHeader(logoBranco)}${HANDLE}</span>
      ${ultimo ? "" : `<span class="arrasta">${i === 0 ? "Arrasta pro lado" : "Continua"} →</span>`}
    </div>
  </section>`);
}

const html = (exportMode) => `<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8">
<title>${esc(post.titulo)} — ${HANDLE}</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Nunito:wght@600;700;800;900&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap">
<style>${tokens}\n${css}</style></head>
<body><main class="preview ${exportMode ? "export" : ""}">${slidesHtml.join("\n")}</main></body></html>`;

await writeFile(path.join(postDir, "carrossel.html"), html(false));
console.log(`✔ Preview: instagram/posts/${slug}/carrossel.html`);

if (post.legenda) {
  const legenda = `${post.legenda.trim()}\n\n${(post.hashtags || []).map((h) => "#" + h.replace(/^#/, "")).join(" ")}\n`;
  await writeFile(path.join(postDir, "legenda.txt"), legenda);
  console.log(`✔ Legenda: instagram/posts/${slug}/legenda.txt`);
}

if (exportPng) {
  let puppeteer;
  try {
    puppeteer = (await import("puppeteer")).default;
  } catch {
    console.error("✖ Para exportar PNG instale o puppeteer: npm install");
    process.exit(1);
  }
  const candidatos = [
    process.env.PUPPETEER_EXECUTABLE_PATH,
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
  ].filter(Boolean);
  let executablePath;
  try {
    if (!existsSync(puppeteer.executablePath())) throw new Error();
  } catch {
    executablePath = candidatos.find((c) => existsSync(c));
  }
  const outDir = path.join(postDir, "png");
  await mkdir(outDir, { recursive: true });

  const browser = await puppeteer.launch({
    executablePath,
    args: ["--no-sandbox", "--disable-setuid-sandbox"]
  });
  const page = await browser.newPage();
  await page.setViewport({ width: W, height: 1350, deviceScaleFactor: 1 });
  
  const content = html(true);
  await page.setContent(content, { waitUntil: "domcontentloaded" });
  await page.evaluate(() => Promise.race([document.fonts.ready, new Promise((r) => setTimeout(r, 6000))]));

  const slides = await page.$$(".slide");
  for (const [i, el] of slides.entries()) {
    const file = path.join(outDir, `${String(i + 1).padStart(2, "0")}.png`);
    await el.screenshot({ path: file });
    console.log(`✔ ${path.relative(ROOT, file)}`);
  }
  await browser.close();
}

