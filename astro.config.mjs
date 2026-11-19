// @ts-check
import { defineConfig } from "astro/config";

export default defineConfig({
  site: "https://identidadesoberana.com.br",
  prefetch: {
    defaultStrategy: "hover",
  },
  build: {
    inlineStylesheets: "auto",
  },
  i18n: {
    defaultLocale: "pt",
    locales: ["pt", "de", "zh", "en"],
    routing: {
      prefixDefaultLocale: false,
    },
  },
  markdown: {
    shikiConfig: { theme: "github-light", wrap: true },
  },
});

