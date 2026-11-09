import { defineCollection, z } from "astro:content";
import { glob } from "astro/loaders";

/** Posts do blog: src/content/blog/AAAA-MM-DD-slug.md */
const blog = defineCollection({
  loader: glob({ pattern: "**/*.{md,mdx}", base: "./src/content/blog" }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    date: z.coerce.date(),
    categoria: z.enum(["SOC", "IAM", "Compliance", "Privacidade"]),
    tags: z.array(z.string()).default([]),
    nivel: z.enum(["Intermediário", "Avançado"]).default("Intermediário"),
    draft: z.boolean().default(false),
  }),
});

export const collections = { blog };

