import puppeteer from "puppeteer";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const svg = await readFile(path.join(ROOT, "brand", "logo", "logo-icone.svg"), "utf8");

const candidatos = [
  process.env.PUPPETEER_EXECUTABLE_PATH,
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
  "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
].filter(Boolean);

let executablePath;
try {
  if (!puppeteer.executablePath()) throw new Error();
} catch {
  executablePath = candidatos.find((c) => Boolean(c));
}

const browser = await puppeteer.launch({
  executablePath,
  args: ["--no-sandbox", "--disable-setuid-sandbox"]
});

async function renderIcon(size, padding, outFile) {
  const page = await browser.newPage();
  await page.setViewport({ width: size, height: size });
  const pad = Math.round(size * padding);
  const iconSize = size - (pad * 2);

  const html = `<!doctype html>
  <html>
    <head>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
          width: ${size}px;
          height: ${size}px;
          display: flex;
          align-items: center;
          justify-content: center;
          background: #FFFFFF;
        }
        svg {
          width: ${iconSize}px;
          height: ${iconSize}px;
        }
      </style>
    </head>
    <body>${svg}</body>
  </html>`;

  await page.setContent(html);
  await page.screenshot({ path: outFile, omitBackground: false });
  await page.close();
  console.log(`✔ Gerado: ${path.relative(ROOT, outFile)} (${size}x${size})`);
}

await renderIcon(192, 0.08, path.join(ROOT, "public", "icons", "icon-192.png"));
await renderIcon(512, 0.08, path.join(ROOT, "public", "icons", "icon-512.png"));
await renderIcon(512, 0.16, path.join(ROOT, "public", "icons", "icon-maskable.png"));

await browser.close();

