---
name: validar-seguranca
description: Auditoria de segurança para o Identidade Soberana. Valida ausência de chaves, secrets e credenciais vazadas em arquivos markdown/código, assegura rel="noopener noreferrer" em links externos e garante práticas defensivas.
---

# Skill: Validar Segurança — Identidade Soberana

Esta skill orienta o agente e os scripts de CI na auditoria estrita de segurança do repositório.

## 1. Diretrizes de Auditoria
- **Zero Segredos Vazados:** Nunca commite ou publique chaves privadas (RSA/OPENSSH), tokens de acesso GitHub/AWS/Azure ou `client_secrets` reais.
- **Exemplos e Mockups Seguros:** Sempre utilize placeholders claramente fictícios em artigos técnicos (ex: `client_secret = "********"` ou `secret_placeholder`).
- **Segurança de Navegação Externa:** Todo link `<a target="_blank">` deve obrigatoriamente incluir `rel="noopener noreferrer"` ou `rel="noopener"`.
- **Proteção contra Injeção:** Tags `<Fragment set:html>` e blocos Markdown nunca devem renderizar entradas arbitrárias de terceiros.

## 2. Como Rodar a Validação Automatizada
```bash
node scripts/validators/seguranca.mjs
```
Se qualquer padrão de chave ou credencial for detectado, o validador falha com exit code `1` e interrompe o build.
