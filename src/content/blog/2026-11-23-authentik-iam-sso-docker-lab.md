---
title: "Authentik em laboratório local com Docker e WSL2: SSO, OIDC e políticas de MFA para o time"
description: "Guia passo a passo para implantar o Authentik localmente via Docker no WSL2 (Windows Enterprise), configurar OIDC, Passkeys e auditoria de eventos."
date: 2026-11-23
categoria: IAM
tags: [authentik, iam, oidc, sso, mfa, docker, wsl2, open-source]
nivel: Intermediário
draft: false
---

> **TL;DR:** Testar fluxos de autenticação moderna (*OIDC*, *SAML*, *Passkeys* e políticas de acesso condicional) sem depender de ambientes externos agiliza a engenharia de IAM. Este guia mostra como subir o **Authentik** em laboratório local isolado com Docker e WSL2 no Windows Enterprise, configurar um provedor OIDC e inspecionar logs de autenticação.

---

## 1. Por que testar o Authentik em laboratório local?

O **Authentik** é um provedor de identidade (*IdP*) *open-source* focado em flexibilidade para ambientes híbridos e aplicações internas. Com suporte nativo a **OIDC**, **SAML 2.0**, **LDAP**, **SCIM** e **WebAuthn/FIDO2**, ele permite que engenheiros de IAM e analistas de segurança validem:
- Fluxos de autenticação (*Flows*) em etapas visuais, incluindo bloqueio por reputação ou exigência de MFA resistente a phishing (*Passkey*).
- Emissão de tokens JWT para ferramentas do SOC (como Shuffle, Wazuh Dashboard ou portais internos).
- Geração de eventos estruturados de login e alterações administrativas para correlação no SIEM.

Executar a pilha em **isolamento local** (`127.0.0.1`) no WSL2 garante controle total dos *client secrets* e certificados de teste sem expor o ambiente na rede corporativa.

---

## 2. Pré-requisitos e arquitetura do laboratório

| Componente | Especificação Mínima | Observação |
|---|---|---|
| **Sistema Host** | Windows 10/11 Enterprise com WSL2 | Virtualização ativa e distro Ubuntu atualizada no WSL2. |
| **Container Engine** | Docker Desktop ou Docker Engine no WSL2 | Compose v2 ativo (`docker compose version`). |
| **Portas Locais** | `127.0.0.1:9000` (HTTP) e `127.0.0.1:9443` (HTTPS) | Bind exclusivo em loopback para isolamento local. |

---

## 3. Subindo o Authentik com Docker Compose

Crie um diretório dedicado no WSL2 (ex.: `~/iam-labs/authentik`) e defina os *secrets* em um arquivo `.env` local (nunca comite este arquivo):

```bash
mkdir -p ~/iam-labs/authentik/media ~/iam-labs/authentik/custom-templates
```

Exemplo de `.env`:

```env
PG_PASS=SUBSTITUA_POR_SECRET_POSTGRES_FORTE
AUTHENTIK_SECRET_KEY=SUBSTITUA_POR_CHAVE_ALEATORIA_64_CHARS
AUTHENTIK_BOOTSTRAP_PASSWORD=SUBSTITUA_POR_SENHA_ADMIN_LAB
AUTHENTIK_BOOTSTRAP_EMAIL=iam-lab@contoso.local
```

Arquivo `compose.yml` com PostgreSQL, Redis, Server e Worker vinculados apenas a `127.0.0.1`:

```yaml
services:
  postgresql:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_PASSWORD: ${PG_PASS}
      POSTGRES_USER: authentik
      POSTGRES_DB: authentik
    volumes:
      - database:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -d authentik -U authentik"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    command: --save 60 1 --loglevel warning
    restart: unless-stopped
    volumes:
      - redis:/data

  server:
    image: ghcr.io/goauthentik/server:latest
    restart: unless-stopped
    command: server
    depends_on:
      postgresql:
        condition: service_healthy
      redis:
        condition: service_started
    environment:
      AUTHENTIK_REDIS__HOST: redis
      AUTHENTIK_POSTGRESQL__HOST: postgresql
      AUTHENTIK_POSTGRESQL__USER: authentik
      AUTHENTIK_POSTGRESQL__NAME: authentik
      AUTHENTIK_POSTGRESQL__PASSWORD: ${PG_PASS}
      AUTHENTIK_SECRET_KEY: ${AUTHENTIK_SECRET_KEY}
      AUTHENTIK_BOOTSTRAP_PASSWORD: ${AUTHENTIK_BOOTSTRAP_PASSWORD}
      AUTHENTIK_BOOTSTRAP_EMAIL: ${AUTHENTIK_BOOTSTRAP_EMAIL}
    volumes:
      - ./media:/media
      - ./custom-templates:/templates
    ports:
      - "127.0.0.1:9000:9000"
      - "127.0.0.1:9443:9443"

  worker:
    image: ghcr.io/goauthentik/server:latest
    restart: unless-stopped
    command: worker
    depends_on:
      postgresql:
        condition: service_healthy
      redis:
        condition: service_started
    environment:
      AUTHENTIK_REDIS__HOST: redis
      AUTHENTIK_POSTGRESQL__HOST: postgresql
      AUTHENTIK_POSTGRESQL__USER: authentik
      AUTHENTIK_POSTGRESQL__NAME: authentik
      AUTHENTIK_POSTGRESQL__PASSWORD: ${PG_PASS}
      AUTHENTIK_SECRET_KEY: ${AUTHENTIK_SECRET_KEY}
    volumes:
      - ./media:/media
      - ./custom-templates:/templates

volumes:
  database:
  redis:
```

Inicie os serviços:

```bash
cd ~/iam-labs/authentik
docker compose up -d
docker compose logs -f server
```

Acesse `http://127.0.0.1:9000/if/admin/` no navegador e entre com o usuário padrão `akadmin` e a senha configurada em `AUTHENTIK_BOOTSTRAP_PASSWORD`.

---

## 4. Configurando um Provedor OIDC e Passkeys (FIDO2)

1. **Criar aplicação e provedor OIDC:**
   No painel administrativo, vá em `Applications > Applications > Create with Provider`.
   - Escolha **OAuth2/OpenID Provider**.
   - Anote o **Client ID** e o **Client Secret** gerados para uso na sua aplicação de teste (ex.: Grafana, Shuffle ou app local em `http://127.0.0.1:3000/callback`).
2. **Habilitar Passkey / WebAuthn:**
   Navegue até `Flows and Stages > Stages > Create > Authenticator WebAuthn Stage` e associe o estágio ao seu fluxo padrão de autenticação (`default-authentication-flow`) para testar logins resistentes a phishing.

---

## 5. Auditoria de Eventos e Correlação no SIEM

Cada autenticação bem-sucedida, falha de senha ou alteração de *client secret* fica registrada em `Events > Logs` no painel e também é emitida em formato estruturado pelo contêiner `server`. Você pode consultar os eventos mais recentes via API REST usando um token de API de laboratório:

```bash
curl -s http://127.0.0.1:9000/api/v3/events/events/ \
  -H "Authorization: Bearer SEU_TOKEN_API_AQUI" | jq '.results[:5] | .[] | {action, created, client_ip, user: .user.username}'
```

Esse padrão facilita o envio de eventos como `login_failed`, `authorize_application` e `model_updated` para um SIEM local (como o Wazuh), permitindo detectar tentativas de *bypass* de MFA ou alterações não autorizadas de *secrets*.

---

## 6. Mapeamento de Controles e Boas Práticas

| Framework | Referência | Aplicação Prática |
|---|---|---|
| **NIST SP 800-63B** | *Digital Identity Guidelines (AAL2 / AAL3)* | Uso de autenticadores criptográficos FIDO2 / *Passkeys* em fluxos críticos. |
| **NIST CSF** | `PR.AA-01` / `PR.AA-03` | Gestão centralizada de identidades, SSO e autenticação multifator. |
| **ISO/IEC 27001:2022** | `A.5.16` / `A.8.5` | Gestão do ciclo de vida de identidades e autenticação segura. |

---

## Referências

- [Authentik — Official Documentation (Docker Compose & OIDC)](https://docs.goauthentik.io/docs/)
- [Microsoft Learn — Install WSL 2 on Windows Enterprise](https://learn.microsoft.com/en-us/windows/wsl/install)
- [NIST SP 800-63B — Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)

