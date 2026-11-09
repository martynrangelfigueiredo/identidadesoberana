// @ts-check
import { defineConfig } from "astro/config";

export default defineConfig({
  site: "https://identidadesoberana.com.br",
  markdown: {
    shikiConfig: { theme: "github-light", wrap: true },
  },
});

