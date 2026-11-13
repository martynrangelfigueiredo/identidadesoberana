---
name: validar-fact-checking
description: Fact-checking e validação de precisão técnica para artigos de SOC, IAM e Sentinel. Verifica citações ao Microsoft Learn, veracidade de tabelas Kusto/Sentinel, IDs do MITRE ATT&CK e conformidade terminológica.
---

# Skill: Validar Fact Checking — Identidade Soberana

Esta skill assegura a precisão técnica, veracidade de fontes primárias e rigor terminológico dos artigos publicados.

## 1. Diretrizes de Fact Checking
- **Referência Oficial no Microsoft Learn:** Todo playbook ou artigo de detecção baseado em Microsoft Sentinel/Entra ID deve conter links oficiais para o catálogo de detecções ou páginas de referência no Microsoft Learn (`learn.microsoft.com`).
- **Veracidade de Tabelas e Esquemas Kusto:** Queries em KQL devem utilizar tabelas oficiais existentes no Microsoft Sentinel (`AuditLogs`, `SigninLogs`, `AADServicePrincipalSignInLogs`, `IdentityInfo`, etc.).
- **Mapeamento MITRE ATT&CK:** Técnicas citadas devem estar no formato canônico oficial (ex.: `T1098.001`, `T1621`).
- **Rigor Terminológico Obrigatório:**
  - "secrets" / "client secrets" (NUNCA traduzir para "segredos").
  - "Service Principal" (NUNCA "entidade de serviço" isolado).
  - "tenant" (NUNCA "locatário").
  - "playbook" e "bypass" (MANTIDOS em inglês).

## 2. Como Rodar a Validação Automatizada
```bash
node scripts/validators/fact-checking.mjs
```
