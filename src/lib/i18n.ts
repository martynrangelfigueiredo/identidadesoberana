/**
 * i18n.ts — Configurações, traduções de interface e rotas multilíngues da Identidade Soberana.
 * Idiomas: 1º Alemão (de), 2º Mandarim (zh), 3º Inglês (en), com Português (pt) como padrão.
 * Regra inegociável: O nome "Identidade Soberana" permanece idêntico em qualquer idioma.
 */

export const LOCALES = ["pt", "de", "zh", "en"] as const;
export type Locale = (typeof LOCALES)[number];

export const DEFAULT_LOCALE: Locale = "pt";

export const LOCALE_LABELS: Record<Locale, { country: string; langCode: string; name: string; flag: string }> = {
  de: { country: "DE", langCode: "de", name: "Deutsch", flag: "🇩🇪" },
  zh: { country: "CN", langCode: "zh", name: "简体中文", flag: "🇨🇳" },
  en: { country: "US", langCode: "en", name: "English", flag: "🇺🇸" },
  pt: { country: "BR", langCode: "pt", name: "Português", flag: "🇧🇷" },
};

/** Ordem oficial de exibição no seletor: 1º Alemão, 2º Mandarim, 3º Inglês, seguido de Português */
export const SELECTOR_ORDER: Locale[] = ["de", "zh", "en", "pt"];

export function getLocaleFromPath(pathname: string): Locale {
  const segment = pathname.split("/").filter(Boolean)[0];
  if (segment === "de" || segment === "zh" || segment === "en") {
    return segment;
  }
  return "pt";
}

export function getLocalizedPath(pathname: string, targetLocale: Locale): string {
  // Remove prefixo de idioma existente se houver
  const segments = pathname.split("/").filter(Boolean);
  if (segments[0] === "de" || segments[0] === "zh" || segments[0] === "en") {
    segments.shift();
  }
  const cleanPath = "/" + segments.join("/") + (segments.length > 0 ? "/" : "");

  if (targetLocale === "pt") {
    return cleanPath;
  }
  return `/${targetLocale}${cleanPath}`;
}

export const UI = {
  pt: {
    siteName: "Identidade Soberana",
    tagline: "Segurança digital sem complicação. Conteúdo para SOC, IAM e Compliance.",
    footerText: "Desde 2026 · Segurança digital sem complicação.",
    nav: [
      { href: "/blog/", label: "Blog" },
      { href: "/categoria/soc/", label: "SOC" },
      { href: "/categoria/iam/", label: "IAM" },
      { href: "/categoria/compliance/", label: "Compliance" },
      { href: "/categoria/privacidade/", label: "Privacidade" },
      { href: "/sobre/", label: "Sobre" },
    ],
    hero: {
      chip: "Segurança na prática",
      titleStart: "Segurança digital ",
      titleHighlight: "sem complicação",
      description: "Conteúdo prático para quem opera segurança no dia a dia: analistas de SOC, times de IAM e profissionais de compliance. Playbooks, detecções e boas práticas prontas para aplicar.",
      btnBlog: "Ver artigos",
      btnAbout: "Conhecer o projeto",
    },
    sections: {
      latest: "Últimos artigos",
      viewAll: "Ver todos os artigos →",
      categories: "Categorias",
      whyTitle: "Por que a Identidade Soberana?",
      why1Title: "100% técnico e aplicável",
      why1Desc: "Sem enrolação: playbooks reais, queries de KQL prontas e passo a passo de contenção no Microsoft Entra e Sentinel.",
      why2Title: "Operação e conformidade",
      why2Desc: "Unimos a visão do analista de SOC (detecção e resposta) com a governança de IAM e requisitos de LGPD/ISO 27001.",
      why3Title: "Linguagem direta e autoral",
      why3Desc: "Produzido por quem atua na área, com referências oficiais ao Microsoft Learn e foco na maturidade de segurança.",
    },
    blog: {
      title: "Blog",
      description: "Playbooks operacionais, dicas de KQL e investigações práticas de segurança e governança de identidade.",
      allArticles: "Todos os artigos",
    },
    categoriesDesc: {
      soc: { nome: "SOC", desc: "Detecção, resposta a incidentes, SIEM, threat hunting e playbooks." },
      iam: { nome: "IAM", desc: "Identidade, acesso, IGA, PAM, SSO, MFA e Zero Trust." },
      compliance: { nome: "Compliance", desc: "LGPD, ISO 27001, SOC 2, PCI DSS, auditoria e controles." },
      privacidade: { nome: "Privacidade", desc: "Proteção de dados pessoais na prática, do titular ao DPO." },
    },
    readingTime: "min de leitura",
  },
  de: {
    siteName: "Identidade Soberana",
    tagline: "Digitale Sicherheit ohne Komplikationen. Inhalte für SOC, IAM und Compliance.",
    footerText: "Seit 2026 · Digitale Sicherheit ohne Komplikationen.",
    nav: [
      { href: "/de/blog/", label: "Blog" },
      { href: "/de/categoria/soc/", label: "SOC" },
      { href: "/de/categoria/iam/", label: "IAM" },
      { href: "/de/categoria/compliance/", label: "Compliance" },
      { href: "/de/categoria/privacidade/", label: "Datenschutz" },
      { href: "/de/sobre/", label: "Über uns" },
    ],
    hero: {
      chip: "Sicherheit in der Praxis",
      titleStart: "Digitale Sicherheit ",
      titleHighlight: "ohne Komplikationen",
      description: "Praxisnahe Inhalte für Sicherheitsexperten im Alltag: SOC-Analysten, IAM-Teams und Compliance-Verantwortliche. Playbooks, Detektionen und Best Practices direkt anwendbar.",
      btnBlog: "Artikel lesen",
      btnAbout: "Über das Projekt",
    },
    sections: {
      latest: "Neueste Artikel",
      viewAll: "Alle Artikel anzeigen →",
      categories: "Kategorien",
      whyTitle: "Warum Identidade Soberana?",
      why1Title: "100% technisch und anwendbar",
      why1Desc: "Auf den Punkt gebracht: Echte Playbooks, einsatzbereite KQL-Queries und Schritt-für-Schritt-Anleitungen für Microsoft Entra und Sentinel.",
      why2Title: "Betrieb und Compliance",
      why2Desc: "Wir verbinden die Perspektive des SOC-Analysten (Erkennung und Reaktion) mit IAM-Governance und DSGVO/ISO 27001-Anforderungen.",
      why3Title: "Klare und fundierte Sprache",
      why3Desc: "Erstellt von Praktikern mit offiziellen Microsoft Learn-Referenzen und Fokus auf Sicherheitsreife.",
    },
    blog: {
      title: "Blog",
      description: "Operative Playbooks, KQL-Tipps und praxisnahe Untersuchungen zur Identitätssicherheit und Governance.",
      allArticles: "Alle Artikel",
    },
    categoriesDesc: {
      soc: { nome: "SOC", desc: "Erkennung, Incident Response, SIEM, Threat Hunting und Playbooks." },
      iam: { nome: "IAM", desc: "Identität, Zugriff, IGA, PAM, SSO, MFA und Zero Trust." },
      compliance: { nome: "Compliance", desc: "DSGVO, ISO 27001, SOC 2, PCI DSS, Audits und Kontrollen." },
      privacidade: { nome: "Datenschutz", desc: "Praktischer Schutz personenbezogener Daten, vom Betroffenen bis zum DPO." },
    },
    readingTime: "Min. Lesezeit",
  },
  zh: {
    siteName: "Identidade Soberana",
    tagline: "简单实用的数字安全。面向 SOC、IAM 和合规性团队的实战指南。",
    footerText: "始于 2026 · 简单实用的数字安全。",
    nav: [
      { href: "/zh/blog/", label: "博客" },
      { href: "/zh/categoria/soc/", label: "SOC" },
      { href: "/zh/categoria/iam/", label: "IAM" },
      { href: "/zh/categoria/compliance/", label: "合规" },
      { href: "/zh/categoria/privacidade/", label: "隐私" },
      { href: "/zh/sobre/", label: "关于" },
    ],
    hero: {
      chip: "实战安全知识",
      titleStart: "简单实用的",
      titleHighlight: "数字安全",
      description: "面向安全一线运维人员的实战内容：SOC 分析师、IAM 团队与合规专业人员。提供开箱即用的应急响应流程、KQL 查询与最佳实践。",
      btnBlog: "阅读文章",
      btnAbout: "了解项目",
    },
    sections: {
      latest: "最新文章",
      viewAll: "查看全部文章 →",
      categories: "分类浏览",
      whyTitle: "为什么选择 Identidade Soberana？",
      why1Title: "100% 技术实战与可落地",
      why1Desc: "拒绝空话：真实的应急演练指南、可直接复制的 KQL 查询以及 Microsoft Entra 和 Sentinel 的处置步骤。",
      why2Title: "兼顾安全运营与合规要求",
      why2Desc: "融合 SOC 分析师的检测与响应视角，以及 IAM 身份治理与 ISO 27001/隐私保护法规的要求。",
      why3Title: "权威且清晰的内容表述",
      why3Desc: "由行业从业者精心打造，结合 Microsoft Learn 官方文档，助力企业提升云上身份安全成熟度。",
    },
    blog: {
      title: "博客",
      description: "实战应急指南、KQL 查询技巧以及云身份安全与治理的深度解析。",
      allArticles: "全部文章",
    },
    categoriesDesc: {
      soc: { nome: "SOC", desc: "威胁检测、应急响应、SIEM、威胁狩猎与应急演练流程。" },
      iam: { nome: "IAM", desc: "身份认证、权限访问、IGA、PAM、SSO、MFA 与零信任体系。" },
      compliance: { nome: "合规", desc: "网络安全合规、ISO 27001、SOC 2、PCI DSS、审计与合规控制。" },
      privacidade: { nome: "隐私", desc: "个人信息与数据隐私保护实践，赋能个人与数据保护官。" },
    },
    readingTime: "分钟阅读",
  },
  en: {
    siteName: "Identidade Soberana",
    tagline: "Digital security made simple. Practical guides for SOC, IAM, and Compliance.",
    footerText: "Since 2026 · Digital security made simple.",
    nav: [
      { href: "/en/blog/", label: "Blog" },
      { href: "/en/categoria/soc/", label: "SOC" },
      { href: "/en/categoria/iam/", label: "IAM" },
      { href: "/en/categoria/compliance/", label: "Compliance" },
      { href: "/en/categoria/privacidade/", label: "Privacy" },
      { href: "/en/sobre/", label: "About" },
    ],
    hero: {
      chip: "Hands-on Security",
      titleStart: "Digital security ",
      titleHighlight: "made simple",
      description: "Practical guides for daily security operations: SOC analysts, IAM teams, and compliance professionals. Production-ready playbooks, detections, and battle-tested best practices.",
      btnBlog: "Explore articles",
      btnAbout: "About the project",
    },
    sections: {
      latest: "Latest articles",
      viewAll: "View all articles →",
      categories: "Categories",
      whyTitle: "Why Identidade Soberana?",
      why1Title: "100% technical & actionable",
      why1Desc: "No fluff: real-world playbooks, ready-to-run KQL queries, and clear containment steps in Microsoft Entra and Sentinel.",
      why2Title: "Bridging SecOps and compliance",
      why2Desc: "Connecting SOC detection & response engineering with IAM identity governance and GDPR/ISO 27001 compliance.",
      why3Title: "Authoritative & clear perspective",
      why3Desc: "Crafted by practitioners with direct Microsoft Learn citations, focusing on operational security maturity.",
    },
    blog: {
      title: "Blog",
      description: "SOC operational playbooks, KQL tips, and hands-on cloud identity threat investigations.",
      allArticles: "All articles",
    },
    categoriesDesc: {
      soc: { nome: "SOC", desc: "Detection, incident response, SIEM, threat hunting, and playbooks." },
      iam: { nome: "IAM", desc: "Identity, access management, IGA, PAM, SSO, MFA, and Zero Trust." },
      compliance: { nome: "Compliance", desc: "GDPR, ISO 27001, SOC 2, PCI DSS, security audits, and controls." },
      privacidade: { nome: "Privacy", desc: "Practical privacy and personal data protection, from users to DPOs." },
    },
    readingTime: "min read",
  },
} as const;

