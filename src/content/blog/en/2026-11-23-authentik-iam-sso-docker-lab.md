---
title: "Authentik in a Local Docker & WSL2 Lab: SSO, OIDC, and MFA Policies"
description: "Step-by-step guide to deploy Authentik locally via Docker on WSL2 (Windows Enterprise), configure OIDC, Passkeys, and audit event logs."
date: 2026-11-23
categoria: IAM
tags: [authentik, iam, oidc, sso, mfa, docker, wsl2, open-source]
nivel: Intermediário
draft: false
---

> **TL;DR:** Testing modern authentication flows (*OIDC*, *SAML*, *Passkeys*, and conditional access policies) locally without external dependencies speeds up IAM engineering. This guide shows how to deploy **Authentik** in an isolated Docker & WSL2 lab on Windows Enterprise, configure an OIDC provider, and inspect authentication logs.

---

## 1. Why test Authentik in a local lab?

**Authentik** is an open-source Identity Provider (*IdP*) built for hybrid environments and internal applications. With native support for **OIDC**, **SAML 2.0**, **LDAP**, **SCIM**, and **WebAuthn/FIDO2**, IAM engineers and security analysts can validate:
- Visual authentication *Flows*, including reputation checks or phishing-resistant MFA (*Passkey*) enforcement.
- JWT token issuance for SOC tools (such as Shuffle, Wazuh Dashboard, or internal portals).
- Structured audit events for every sign-in and administrative change ready for SIEM correlation.

Running the stack in **local isolation** (`127.0.0.1`) on WSL2 ensures complete control over *client secrets* and test certificates without exposing services to the corporate LAN.

---

## 2. Prerequisites and Lab Architecture

| Component | Minimum Requirement | Notes |
|---|---|---|
| **Host OS** | Windows 10/11 Enterprise with WSL2 | Hardware virtualization enabled; updated Ubuntu WSL2 distro. |
| **Container Engine** | Docker Desktop or Docker Engine on WSL2 | Compose v2 enabled (`docker compose version`). |
| **Local Ports** | `127.0.0.1:9000` (HTTP) and `127.0.0.1:9443` (HTTPS) | Bound exclusively to loopback for local isolation. |

---

## 3. Deploying Authentik with Docker Compose

Create a dedicated directory in WSL2 (e.g., `~/iam-labs/authentik`) and store all *secrets* in a local `.env` file (never commit this file):

```bash
mkdir -p ~/iam-labs/authentik/media ~/iam-labs/authentik/custom-templates
```

Sample `.env` file:

```env
PG_PASS=REPLACE_WITH_STRONG_POSTGRES_SECRET
AUTHENTIK_SECRET_KEY=REPLACE_WITH_64_CHAR_RANDOM_KEY
AUTHENTIK_BOOTSTRAP_PASSWORD=REPLACE_WITH_LAB_ADMIN_PASSWORD
AUTHENTIK_BOOTSTRAP_EMAIL=iam-lab@contoso.local
```

`compose.yml` with PostgreSQL, Redis, Server, and Worker bound strictly to `127.0.0.1`:

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

Start the stack:

```bash
cd ~/iam-labs/authentik
docker compose up -d
docker compose logs -f server
```

Open `http://127.0.0.1:9000/if/admin/` in your browser and sign in with the default username `akadmin` and the password set in `AUTHENTIK_BOOTSTRAP_PASSWORD`.

---

## 4. Configuring an OIDC Provider and Passkeys (FIDO2)

1. **Create an application and OIDC provider:**
   In the admin interface, go to `Applications > Applications > Create with Provider`.
   - Choose **OAuth2/OpenID Provider**.
   - Record the generated **Client ID** and **Client Secret** for your test application (e.g., Grafana, Shuffle, or a local app at `http://127.0.0.1:3000/callback`).
2. **Enable Passkey / WebAuthn:**
   Navigate to `Flows and Stages > Stages > Create > Authenticator WebAuthn Stage` and attach it to your default authentication flow (`default-authentication-flow`) to test phishing-resistant sign-ins.

---

## 5. Event Auditing and SIEM Correlation

Every successful login, password failure, or *client secret* change is recorded under `Events > Logs` and emitted in structured form by the `server` container. You can query recent events via REST API using a lab API token:

```bash
curl -s http://127.0.0.1:9000/api/v3/events/events/ \
  -H "Authorization: Bearer YOUR_API_TOKEN_HERE" | jq '.results[:5] | .[] | {action, created, client_ip, user: .user.username}'
```

This makes it straightforward to forward events such as `login_failed`, `authorize_application`, and `model_updated` into a local SIEM (like Wazuh) to detect MFA *bypass* attempts or unauthorized *secret* changes.

---

## 6. Control Mapping and Best Practices

| Framework | Reference | Practical Application |
|---|---|---|
| **NIST SP 800-63B** | *Digital Identity Guidelines (AAL2 / AAL3)* | Enforcing cryptographic FIDO2 authenticators / *Passkeys* for critical flows. |
| **NIST CSF** | `PR.AA-01` / `PR.AA-03` | Centralized identity management, SSO, and multi-factor authentication. |
| **ISO/IEC 27001:2022** | `A.5.16` / `A.8.5` | Identity lifecycle governance and secure authentication. |

---

## References

- [Authentik — Official Documentation (Docker Compose & OIDC)](https://docs.goauthentik.io/docs/)
- [Microsoft Learn — Install WSL 2 on Windows Enterprise](https://learn.microsoft.com/en-us/windows/wsl/install)
- [NIST SP 800-63B — Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)

