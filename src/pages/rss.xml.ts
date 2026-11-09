import type { APIRoute } from "astro";
import { getPosts } from "../lib/posts";

export const GET: APIRoute = async (context) => {
  const posts = await getPosts();
  const siteUrl = context.site?.toString().replace(/\/$/, "") || "https://identidadesoberana.com.br";

  const items = posts
    .map(
      (post) => `
    <item>
      <title><![CDATA[${post.data.title}]]></title>
      <link>${siteUrl}/blog/${post.id}/</link>
      <guid isPermaLink="true">${siteUrl}/blog/${post.id}/</guid>
      <description><![CDATA[${post.data.description}]]></description>
      <pubDate>${post.data.date.toUTCString()}</pubDate>
      <category>${post.data.categoria}</category>
    </item>`
    )
    .join("");

  const rss = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>Identidade Soberana</title>
    <link>${siteUrl}</link>
    <description>Segurança digital sem complicação. Conteúdo técnico para SOC, IAM e Compliance.</description>
    <language>pt-BR</language>
    <atom:link href="${siteUrl}/rss.xml" rel="self" type="application/rss+xml"/>
    ${items}
  </channel>
</rss>`;

  return new Response(rss.trim(), {
    headers: { "Content-Type": "application/xml; charset=utf-8" },
  });
};
