import type { APIRoute } from "astro";
import { getCollection } from "astro:content";
import { LOCALES, type Locale } from "../lib/i18n";
import { UTIL_TOOLS } from "../lib/tools";

export function getStaticPaths() {
  return LOCALES.map((locale) => ({ params: { locale } }));
}

export const GET: APIRoute = async ({ params }) => {
  const locale = (params.locale || "pt") as Locale;
  const allPosts = await getCollection("blog");

  const localePosts = allPosts
    .filter((p) => {
      const id = p.id;
      if (locale === "pt") return !id.startsWith("de/") && !id.startsWith("zh/") && !id.startsWith("en/");
      return id.startsWith(`${locale}/`);
    })
    .sort((a, b) => b.data.date.getTime() - a.data.date.getTime())
    .map((p) => {
      const cleanSlug = p.id.replace(/^(de|zh|en)\//, "").replace(/\.md$/, "");
      const href = locale === "pt" ? `/blog/${cleanSlug}/` : `/${locale}/blog/${cleanSlug}/`;
      return {
        title: p.data.title,
        type: p.data.categoria,
        href,
        keywords: `${p.data.title} ${p.data.categoria} ${(p.data.tags || []).join(" ")}`.toLowerCase(),
      };
    });

  const toolTypeLabel = locale === "de" ? "Tool" : locale === "zh" ? "工具" : locale === "en" ? "Tool" : "Ferramenta";
  const toolItems = UTIL_TOOLS.map((t) => ({
    title: `${t.icon} ${t.title[locale]}`,
    type: toolTypeLabel,
    href: locale === "pt" ? t.slug : `/${locale}${t.slug}`,
    keywords: `${t.id} ${t.title[locale]} ${t.description[locale]}`.toLowerCase(),
  }));

  return new Response(JSON.stringify([...toolItems, ...localePosts]), {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "public, max-age=3600",
    },
  });
};

