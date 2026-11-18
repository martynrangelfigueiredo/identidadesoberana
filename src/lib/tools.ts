export interface UtilTool {
  id: string;
  slug: string;
  category: "network" | "identity" | "dfir" | "osint";
  badge: string;
  icon: string;
  title: {
    pt: string;
    de: string;
    zh: string;
    en: string;
  };
  description: {
    pt: string;
    de: string;
    zh: string;
    en: string;
  };
  highlights: {
    pt: string[];
    de: string[];
    zh: string[];
    en: string[];
  };
}

export const UTIL_TOOLS: UtilTool[] = [
  {
    id: "ipinfo",
    slug: "/util/ipinfo/",
    category: "network",
    badge: "IP & Geo",
    icon: "🌐",
    title: {
      pt: "IP, IPv6, CIDR & Threat Lookup",
      de: "IP, IPv6, CIDR & Threat Lookup",
      zh: "IP、IPv6、CIDR 与威胁查询",
      en: "IP, IPv6, CIDR & Threat Lookup",
    },
    description: {
      pt: "Detecta IPv4/IPv6, geolocalização completa, rDNS (PTR), ASN, bloco RDAP, contato de abuso, faixa Cloud (Azure/AWS), expansor de IPv6, calculadora CIDR e filtros KQL/Wazuh.",
      de: "Erkennt IPv4/IPv6, vollständige Geolokalisierung, rDNS (PTR), ASN, RDAP-Block, Abuse-Kontakt, Cloud-Ranges, IPv6-Expander, CIDR-Rechner und KQL/Wazuh-Filter.",
      zh: "检测 IPv4/IPv6、完整地理位置、rDNS (PTR)、ASN、RDAP 网段与滥用邮箱、云网段识别、IPv6 展开、CIDR 计算及 KQL/Wazuh 语句导出。",
      en: "Detects IPv4/IPv6, full geolocation, rDNS (PTR), ASN, RDAP netblock, abuse contact, cloud ranges, IPv6 expander, CIDR calculator, and ready-to-use KQL/Wazuh filters.",
    },
    highlights: {
      pt: ["IPv4 / IPv6 + CIDR", "Mapa OpenStreetMap", "Exportação KQL & Pivot"],
      de: ["IPv4 / IPv6 + CIDR", "OpenStreetMap", "KQL-Export & Pivot"],
      zh: ["IPv4 / IPv6 + CIDR", "OpenStreetMap 地图", "KQL 导出与关联分析"],
      en: ["IPv4 / IPv6 + CIDR", "OpenStreetMap", "KQL Export & Pivot"],
    },
  },
  {
    id: "jwt",
    slug: "/util/jwt/",
    category: "identity",
    badge: "100% Local",
    icon: "🔑",
    title: {
      pt: "Inspetor de JWT & Tokens OAuth",
      de: "JWT & OAuth Token-Inspektor",
      zh: "JWT 与 OAuth 令牌解析器",
      en: "JWT & OAuth Token Inspector",
    },
    description: {
      pt: "Decodifica tokens JWT 100% no seu navegador sem enviar dados pela rede. Realça claims do Microsoft Entra ID e Keycloak (amr, roles, scp, wids, tid, exp).",
      de: "Dekodiert JWT-Tokens zu 100% lokal im Browser ohne Netzwerkübertragung. Hebt Claims von Microsoft Entra ID und Keycloak hervor.",
      zh: "100% 在浏览器本地解码 JWT 令牌，绝不上传至任何服务器。高亮展示 Microsoft Entra ID 与 Keycloak 核心声明（amr、roles、scp、exp）。",
      en: "Decodes JWT tokens 100% locally in your browser with zero network transmission. Highlights Microsoft Entra ID and Keycloak claims (amr, roles, scp, exp).",
    },
    highlights: {
      pt: ["Zero envio de rede", "Claims Entra ID / Keycloak", "Contagem de expiração"],
      de: ["Keine Netzwerkanfragen", "Entra ID / Keycloak Claims", "Ablauf-Countdown"],
      zh: ["零网络传输", "Entra ID / Keycloak 声明", "过期倒计时"],
      en: ["Zero network calls", "Entra ID / Keycloak Claims", "Expiration countdown"],
    },
  },
  {
    id: "dns",
    slug: "/util/dns/",
    category: "network",
    badge: "DoH Aberto",
    icon: "📡",
    title: {
      pt: "DNS, MX, SPF & DMARC Inspector",
      de: "DNS, MX, SPF & DMARC-Inspektor",
      zh: "DNS、MX、SPF 与 DMARC 检测",
      en: "DNS, MX, SPF & DMARC Inspector",
    },
    description: {
      pt: "Consulta registros A, AAAA, MX, NS e TXT via DNS-over-HTTPS (DoH) e audita automaticamente políticas SPF e DMARC contra spoofing e phishing.",
      de: "Fragt A-, AAAA-, MX-, NS- und TXT-Records per DNS-over-HTTPS (DoH) ab und prüft SPF- und DMARC-Richtlinien automatisch auf Schwachstellen.",
      zh: "通过 DNS-over-HTTPS (DoH) 查询 A、AAAA、MX、NS、TXT 记录，并自动审计 SPF 与 DMARC 策略，识别钓鱼与伪造风险。",
      en: "Queries A, AAAA, MX, NS, and TXT records over DNS-over-HTTPS (DoH) and automatically audits SPF & DMARC policies for spoofing risks.",
    },
    highlights: {
      pt: ["Auditoria SPF/DMARC", "DNS-over-HTTPS", "Pivot MXToolbox / urlscan"],
      de: ["SPF/DMARC-Audit", "DNS-over-HTTPS", "MXToolbox / urlscan Pivot"],
      zh: ["SPF/DMARC 审计", "DNS-over-HTTPS", "一键关联外部平台"],
      en: ["SPF/DMARC Audit", "DNS-over-HTTPS", "MXToolbox / urlscan Pivot"],
    },
  },
  {
    id: "rdap",
    slug: "/util/rdap/",
    category: "osint",
    badge: "IETF RDAP",
    icon: "📋",
    title: {
      pt: "RDAP / WHOIS Aberto",
      de: "Offenes RDAP / WHOIS",
      zh: "开放 RDAP / WHOIS 查询",
      en: "Open RDAP / WHOIS Lookup",
    },
    description: {
      pt: "Consulta titularidade de IPs e domínios utilizando o protocolo aberto RDAP (JSON sobre HTTPS), exibindo registrador, datas, ASN e contato de abuso.",
      de: "Ermittelt Eigentümerdaten von IPs und Domains über das offene RDAP-Protokoll inklusive Registrar, Registrierungsdaten und Abuse-Kontakt.",
      zh: "使用标准开放协议 RDAP 查询 IP 与域名注册信息、注册商、到期时间及滥用举报邮箱（abuse@）。",
      en: "Queries IP and domain ownership using the open IETF RDAP protocol, displaying registrar, registration dates, ASN, and abuse contacts.",
    },
    highlights: {
      pt: ["Protocolo oficial IETF", "IPs e Domínios", "Contato Abuse direto"],
      de: ["Offizielles IETF-Protokoll", "IPs & Domains", "Direkter Abuse-Kontakt"],
      zh: ["IETF 官方标准协议", "支持 IP 与域名", "提取 Abuse 联系邮箱"],
      en: ["Official IETF standard", "IPs & Domains", "Direct Abuse contact"],
    },
  },
  {
    id: "epoch",
    slug: "/util/epoch/",
    category: "dfir",
    badge: "DFIR & KQL",
    icon: "⏱️",
    title: {
      pt: "Conversor Epoch, FILETIME & Timeline",
      de: "Epoch-, FILETIME- & Timeline-Konverter",
      zh: "Epoch、FILETIME 与时间线转换",
      en: "Epoch, FILETIME & Timeline Converter",
    },
    description: {
      pt: "Conversão instantânea entre Unix Epoch (s/ms/µs), Windows FILETIME (18 dígitos do AD/Entra), UTC, horário local e formato datetime() do KQL.",
      de: "Sofortige Umrechnung zwischen Unix-Epoch, Windows FILETIME (AD/Entra), UTC, Ortszeit und KQL datetime().",
      zh: "实时互转 Unix Epoch、Windows FILETIME（AD/Entra 18位时间戳）、UTC、本地时间以及 KQL datetime() 语句。",
      en: "Instant conversion between Unix Epoch, Windows FILETIME (AD/Entra 18-digit ticks), UTC, local time, and KQL datetime() format.",
    },
    highlights: {
      pt: ["Unix s / ms / µs", "Windows FILETIME", "Formato KQL pronto"],
      de: ["Unix s / ms / µs", "Windows FILETIME", "KQL-Format bereit"],
      zh: ["支持 s / ms / µs", "Windows FILETIME", "生成 KQL 时间格式"],
      en: ["Unix s / ms / µs", "Windows FILETIME", "Ready for KQL"],
    },
  },
  {
    id: "distance",
    slug: "/util/distance/",
    category: "dfir",
    badge: "Geo Risk",
    icon: "✈️",
    title: {
      pt: "Calculadora de Viagem Impossível",
      de: "Impossible-Travel-Rechner",
      zh: "不可能旅行距离与速度计算",
      en: "Impossible Travel Calculator",
    },
    description: {
      pt: "Calcula distância (Haversine) e velocidade necessária em km/h entre dois pontos geográficos para validar alertas de Viagem Impossível no SOC.",
      de: "Berechnet Distanz (Haversine) und benötigte Geschwindigkeit (km/h) zwischen zwei Standorten zur Validierung von Impossible-Travel-Alarmen.",
      zh: "基于 Haversine 公式计算两点地理距离与所需飞行时速（km/h），辅助研判 Entra ID 等平台的不可能旅行告警。",
      en: "Calculates geographic distance (Haversine) and required travel speed (km/h) between two logins to triage Impossible Travel alerts.",
    },
    highlights: {
      pt: ["Presets de cidades", "Velocidade km/h", "Avaliação de plausibilidade"],
      de: ["Städte-Presets", "Geschwindigkeit km/h", "Plausibilitätsprüfung"],
      zh: ["内置城市坐标预设", "自动计算所需时速", "可信度智能研判"],
      en: ["City presets", "Speed in km/h", "Plausibility verdict"],
    },
  },
  {
    id: "defang",
    slug: "/util/defang/",
    category: "dfir",
    badge: "100% Local",
    icon: "🛡️",
    title: {
      pt: "IoC Defang, Base64/PS & Hash Local",
      de: "IoC Defang, Base64/PS & Lokaler Hash",
      zh: "IoC 脱敏、Base64/PS 解码与本地哈希",
      en: "IoC Defang, Base64/PS & Local Hash",
    },
    description: {
      pt: "Sanitize URLs e IPs maliciosos (defang/refang), decodifique comandos PowerShell -EncodedCommand (UTF-16LE) e calcule SHA-256 de textos/arquivos localmente.",
      de: "Entschärft URLs/IPs (Defang), dekodiert PowerShell -EncodedCommand (UTF-16LE) und berechnet SHA-256-Hashes lokal ohne Upload.",
      zh: "对恶意 URL/IP 进行安全脱敏（Defang），原生解码 PowerShell UTF-16LE 载荷，并在本地计算文本或文件的 SHA-256 哈希。",
      en: "Defang/refang malicious URLs & IPs, decode PowerShell -EncodedCommand (UTF-16LE) payloads, and compute local SHA-256 hashes with zero upload.",
    },
    highlights: {
      pt: ["Defang / Refang IoCs", "PowerShell UTF-16LE", "SHA-256 sem upload"],
      de: ["Defang / Refang IoCs", "PowerShell UTF-16LE", "SHA-256 ohne Upload"],
      zh: ["IoC 脱敏与还原", "PowerShell UTF-16LE", "本地零上传算哈希"],
      en: ["Defang / Refang IoCs", "PowerShell UTF-16LE", "Zero-upload SHA-256"],
    },
  },
  {
    id: "ua",
    slug: "/util/ua/",
    category: "dfir",
    badge: "Logs & Web",
    icon: "🕵️",
    title: {
      pt: "User-Agent Parser & Detector",
      de: "User-Agent Parser & Detektor",
      zh: "User-Agent 解析与脚本检测",
      en: "User-Agent Parser & Detector",
    },
    description: {
      pt: "Analisa strings de User-Agent em logs de autenticação e proxy, identificando SO, navegador e alertando sobre clientes automatizados (curl, python, PowerShell).",
      de: "Analysiert User-Agent-Strings aus Auth- und Proxy-Logs und erkennt automatisierte Tools (curl, Python, PowerShell).",
      zh: "解析登录与代理日志中的 User-Agent 字段，识别操作系统、浏览器版本，并标记 curl、Python、PowerShell 等自动化异常客户端。",
      en: "Parses User-Agent strings from sign-in and proxy logs, identifying OS, browser, and flagging automated/offensive clients (curl, Python, PowerShell).",
    },
    highlights: {
      pt: ["Auto-preenchimento", "Detecção de CLI/Bots", "100% no navegador"],
      de: ["Auto-Erkennung", "CLI/Bot-Warnung", "100% im Browser"],
      zh: ["自动识别本机 UA", "异常脚本与爬虫预警", "纯本地解析"],
      en: ["Auto-fill current UA", "CLI/Bot detection", "100% in-browser"],
    },
  },
  {
    id: "aadsts",
    slug: "/util/aadsts/",
    category: "identity",
    badge: "Entra ID",
    icon: "📘",
    title: {
      pt: "Consulta Rápida de Erros AADSTS",
      de: "AADSTS-Fehlercode-Referenz",
      zh: "AADSTS 错误代码速查",
      en: "AADSTS Error Code Lookup",
    },
    description: {
      pt: "Base pesquisável com os códigos de erro AADSTS mais comuns em investigações do Microsoft Entra ID (MFA, Conditional Access, tokens e credenciais).",
      de: "Durchsuchbare Wissensdatenbank der häufigsten Microsoft Entra ID AADSTS-Fehlercodes inklusive SOC-Handlungsempfehlungen.",
      zh: "支持快速检索 Microsoft Entra ID 常见 AADSTS 认证错误代码（MFA、条件访问、凭证异常），附带 SOC 排查建议。",
      en: "Instant searchable reference for the most common Microsoft Entra ID AADSTS authentication error codes with SOC triage guidance.",
    },
    highlights: {
      pt: ["Busca instantânea", "Ação recomendada SOC", "Offline-ready"],
      de: ["Sofortsuche", "SOC-Empfehlung", "Offline verfügbar"],
      zh: ["秒级检索", "附带 SOC 处置建议", "离线可用"],
      en: ["Instant search", "SOC triage action", "Offline-ready"],
    },
  },
  {
    id: "portals",
    slug: "/util/portals/",
    category: "osint",
    badge: "Diretório",
    icon: "🧭",
    title: {
      pt: "Hub de Portais Security & OSINT",
      de: "Security- & OSINT-Portal-Hub",
      zh: "安全运营与 OSINT 权威导航",
      en: "Security & OSINT Portals Hub",
    },
    description: {
      pt: "Diretório curado com atalhos diretos para portais Microsoft Security, Entra ID, Azure RBAC, bases CVE abertas (OSV.dev/CIRCL) e Threat Intelligence.",
      de: "Kuratierte Linksammlung zu Microsoft Security-Portalen, Entra ID, Azure RBAC, offenen CVE-Datenbanken und Threat-Intelligence-Quellen.",
      zh: "精选汇总 Microsoft Security 管理门户、Entra ID、Azure RBAC、开源漏洞库（OSV.dev/CIRCL）及主流威胁情报平台入口。",
      en: "Curated directory with direct links to Microsoft Security portals, Entra ID, Azure RBAC, open CVE databases (OSV.dev/CIRCL), and Threat Intel feeds.",
    },
    highlights: {
      pt: ["Portais Microsoft", "Bases CVE/OSV", "Fontes Threat Intel"],
      de: ["Microsoft-Portale", "CVE/OSV-Datenbanken", "Threat-Intel-Quellen"],
      zh: ["Microsoft 官方门户", "开源 CVE/OSV 库", "权威威胁情报"],
      en: ["Microsoft portals", "CVE/OSV databases", "Threat Intel feeds"],
    },
  },
];

