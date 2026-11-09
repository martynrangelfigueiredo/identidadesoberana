---
title: "MFA resistente a phishing: por que push notification já não basta"
description: "Como ataques de MFA fatigue e AitM contornam o segundo fator, o que monitorar no SOC e como migrar para FIDO2/passkeys."
date: 2026-11-09
categoria: IAM
tags: [mfa, fido2, passkeys, aitm, detection]
nivel: Intermediário
---

Ter MFA habilitado deixou de ser diferencial. O que importa agora é **qual** MFA: fatores baseados em OTP e push continuam vulneráveis a *MFA fatigue* e a proxies *Adversary-in-the-Middle* (AitM).

> **TL;DR** — Priorize FIDO2/passkeys para contas privilegiadas, ative *number matching* onde ainda houver push e crie detecções para negações de MFA em sequência.

## O problema

| Método | Phishing simples | MFA fatigue | AitM (Evilginx etc.) |
|---|---|---|---|
| SMS / OTP | Vulnerável | — | Vulnerável |
| Push simples | Resistente | Vulnerável | Vulnerável |
| Push + number matching | Resistente | Mitigado | Vulnerável |
| FIDO2 / Passkeys | Resistente | Resistente | Resistente |

## O que o SOC deve monitorar

Exemplo de detecção (KQL, Microsoft Entra ID) para múltiplas negações de MFA em curto intervalo:

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == 500121 // MFA negado / falhou
| summarize Tentativas = count(), IPs = make_set(IPAddress) by UserPrincipalName, bin(TimeGenerated, 10m)
| where Tentativas >= 5
```

## Plano de migração

1. Inventariar contas privilegiadas e de *break-glass*.
2. Exigir FIDO2 via política de acesso condicional para esses grupos.
3. Habilitar *number matching* e contexto geográfico no push para o restante.
4. Medir adoção e reduzir gradualmente os métodos legados.

