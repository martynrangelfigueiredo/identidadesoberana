import { getCollection, type CollectionEntry } from "astro:content";

export const CATEGORIAS = {
  soc: { nome: "SOC", desc: "Detecção, resposta a incidentes, SIEM, threat hunting e playbooks." },
  iam: { nome: "IAM", desc: "Identidade, acesso, IGA, PAM, SSO, MFA e Zero Trust." },
  compliance: { nome: "Compliance", desc: "LGPD, ISO 27001, SOC 2, PCI DSS, auditoria e controles." },
  privacidade: { nome: "Privacidade", desc: "Proteção de dados pessoais na prática, do titular ao DPO." },
} as const;

export async function getPosts(locale: string = "pt"): Promise<CollectionEntry<"blog">[]> {
  const posts = await getCollection("blog", ({ data, id }) => {
    if (!import.meta.env.DEV && data.draft) return false;
    if (locale === "pt") {
      return !id.startsWith("de/") && !id.startsWith("zh/") && !id.startsWith("en/");
    }
    return id.startsWith(`${locale}/`);
  });
  return posts.sort((a, b) => b.data.date.valueOf() - a.data.date.valueOf());
}
