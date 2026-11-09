import type { APIRoute } from "astro";
import { getPosts, CATEGORIAS } from "../lib/posts";

export const GET: APIRoute = async (context) => {
  const posts = await getPosts();
  const siteUrl = context.site?.toString().replace(/\/$/, "") || "https://identidadesoberana.com.br";
  const hoje = new Date().toISOString().slice(0, 10);

  const staticPages = [
    { url: "/", priority: "1.0", changefreq: "daily" },
    { url: "/blog/", priority: "0.9", changefreq: "daily" },
    { url: "/sobre/", priority: "0.8", changefreq: "monthly" },
  ];

  const categoryPages = Object.keys(CATEGORIAS).map((cat) => ({
    url: `/categoria/${cat}/`,
    priority: "0.8",
    changefreq: "weekly",
  }));

  const postPages = posts.map((post) => ({
    url: `/blog/${post.id}/`,
    lastmod: post.data.date.toISOString().slice(0, 10),
    priority: "0.85",
    changefreq: "monthly",
  }));

  const allEntries = [...staticPages, ...categoryPages, ...postPages];

  const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${allEntries
  .map(
    (e) => `  <url>
    <loc>${siteUrl}${e.url}</loc>
    <lastmod>${"lastmod" in e && e.lastmod ? e.lastmod : hoje}</lastmod>
    <changefreq>${e.changefreq}</changefreq>
    <priority>${e.priority}</priority>
  </url>`
  )
  .join("\n")}
</urlset>`;

  return new Response(sitemap.trim(), {
    headers: {
      "Content-Type": "application/xml; charset=utf-8",
      "X-Robots-Tag": "all",
    },
  });
};

