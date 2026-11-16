---
title: "Sovereign IAM Lab: Setting Up Keycloak on Windows Enterprise with Docker and WSL 2"
description: "A hands-on guide to building a local sovereign IAM lab on Windows Enterprise using Docker Desktop, WSL 2, Keycloak 26, and persistent PostgreSQL."
date: 2026-11-16
categoria: IAM
tags: [keycloak, iam, docker, windows-enterprise, wsl2, lab, oidc, open-source]
nivel: Intermediário
---

For SOC analysts, identity security engineers, and compliance professionals, mastering the inner workings of Single Sign-On (SSO), OIDC federation, and fine-grained access control is critical. However, experimenting with complex authentication flows, MFA enforcement, and token issuance directly inside production enterprise cloud tenants is rarely practical or permissible.

Spinning up a local laboratory powered by **Keycloak** — the industry-standard open-source identity and access management solution backed by CNCF standards — allows security teams to simulate identity architectures, test integrations, and dissect authentication mechanics with zero cloud hosting costs and absolute data custody.

> **Lab TL;DR:** To run Keycloak 26+ and PostgreSQL smoothly on Windows Enterprise without exhausting your workstation's RAM, cap WSL 2 memory usage inside `.wslconfig` (e.g. 4 GB to 6 GB), leverage Docker Desktop's WSL 2 engine, and execute the stack in local development mode (`start-dev`) backed by named volumes.

> 📘 **Official Documentation & Technical Reference:** This guide is built strictly on upstream documentation and Linux Foundation / CNCF guidelines:
> - [Keycloak — Running Keycloak in a container (Official Guides)](https://www.keycloak.org/guides#server)
> - [Keycloak — Getting started with Keycloak and Docker](https://www.keycloak.org/getting-started/getting-started-docker)

---

## 1. Why Build This Lab on Windows Enterprise?

In enterprise environments, modern Windows 10/11 Enterprise workstations are typically equipped with robust hardware, Hyper-V, and WSL 2 capabilities. Running a containerized IAM lab locally delivers distinct advantages:

1. **Total Data Sovereignty and Isolation:** No authentication requests, password hashes, or session tokens leave your workstation.
2. **Zero Licensing Costs:** Keycloak is distributed under the Apache 2.0 license and serves as the open-source upstream core for Red Hat build of Keycloak (formerly RH-SSO).
3. **Protocol Parity with Enterprise Hyperscalers:** The exact standard protocols used by Microsoft Entra ID (OpenID Connect, OAuth 2.0, SAML 2.0) are fully configurable in Keycloak, allowing you to inspect JWT tokens, claims, and authorization code flows down to the wire.

---

## 2. Critical Tuning: Capping WSL 2 Memory Consumption

By default, WSL 2 dynamically allocates up to 50% or more of your physical system memory. To prevent workstation lag while running corporate security tools and containers side-by-side, configure a `.wslconfig` file in your Windows user profile:

1. Open PowerShell and edit your configuration:
   ```powershell
   notepad "$env:USERPROFILE\.wslconfig"
   ```
2. Insert the following recommended hardware limits:
   ```ini
   [wsl2]
   memory=4GB       # Caps max memory allocated to WSL 2
   processors=2     # Restricts CPU core allocation
   swap=2GB         # Linux swap file size
   localhostForwarding=true
   ```
3. Restart WSL 2 to apply the memory boundaries:
   ```powershell
   wsl --shutdown
   ```

---

## 3. The `docker-compose.yml` Architecture for Local Labs

Create an isolated directory on your workstation (e.g. `mkdir keycloak-lab && cd keycloak-lab`) and populate `docker-compose.yml` with the following configuration.

We utilize the official Quarkus-based Keycloak image attached to a PostgreSQL 16 container inside an isolated bridge network:

```yaml
services:
  postgres:
    image: postgres:16-alpine
    container_name: keycloak-db
    restart: unless-stopped
    environment:
      POSTGRES_DB: keycloak
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: keycloak_lab_password_2026
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - keycloak-net
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U keycloak -d keycloak"]
      interval: 10s
      timeout: 5s
      retries: 5

  keycloak:
    image: quay.io/keycloak/keycloak:26.0
    container_name: keycloak-server
    restart: unless-stopped
    command: start-dev
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: keycloak_lab_password_2026
      KC_BOOTSTRAP_ADMIN_USERNAME: admin
      KC_BOOTSTRAP_ADMIN_PASSWORD: admin_lab_password_2026
      KC_HTTP_ENABLED: "true"
      KC_HOSTNAME_STRICT: "false"
      KC_HOSTNAME_STRICT_HTTPS: "false"
    ports:
      - "127.0.0.1:8080:8080"
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - keycloak-net

volumes:
  postgres_data:
    driver: local

networks:
  keycloak-net:
    driver: bridge
```

> 🔒 **Operational Security Tip:** Note the loopback binding (`127.0.0.1:8080:8080`). This ensures your Keycloak instance cannot be probed or accessed by other hosts on your corporate network.

---

## 4. Booting the Containers and Logging In

With Docker Desktop running on Windows, start the stack from your terminal:

```bash
docker compose up -d
```

Monitor initialization logs until the services indicate ready status:

```bash
docker compose logs -f keycloak
```

Once the log outputs `Listening on: http://0.0.0.0:8080`:
1. Open your browser and navigate to: `http://localhost:8080`
2. Select **Administration Console**
3. Authenticate using your lab administrative credentials:
   * **Username:** `admin`
   * **Password:** `admin_lab_password_2026`

---

## 5. First Steps: IAM Configuration in Keycloak

### 1. Create a Dedicated Realm
Never register test users or client applications inside the `master` realm. The `master` realm is strictly reserved for managing Keycloak itself.
* In the top-left realm selector, click **Create Realm**.
* Name it `lab-corporativo` and click **Create**.

### 2. Register an Application Client (OIDC Client)
* Navigate to **Clients** > **Create client**.
* **Client type:** `OpenID Connect`.
* **Client ID:** `app-portal-interno`.
* Under **Capability config**:
  * Enable **Client authentication** to simulate confidential client workloads (*client secrets*), or leave disabled for single-page applications (SPAs) utilizing PKCE.
* In **Login settings**, specify:
  * **Valid redirect URIs:** `http://localhost:3000/*` (or the local URL of the service you are integrating).

### 3. Provision a Test User and Enforce Local MFA
* Navigate to **Users** > **Add user**.
* Enter a username (e.g. `colaborador.teste`) and an email (`colaborador@contoso.com`).
* Under the **Credentials** tab, establish a temporary password and toggle *Temporary* off.
* To simulate free multi-factor authentication enforcement, add the **Configure OTP** action under **Required Actions**. Upon next login, Keycloak will mandate pairing with an authenticator app (such as Google Authenticator, FreeOTP, or Microsoft Authenticator).

---

## 6. Teardown and Daily Lab Maintenance

When concluding your daily security tests, shut down the containers while safeguarding persistent data:

```bash
# Gracefully stop the lab while preserving database state:
docker compose down

# Fast relaunch for your next testing session:
docker compose up -d

# Complete reset back to clean slate (deletes volumes):
docker compose down -v
```

With this foundation running on Windows Enterprise, you have an autonomous playground ready to test OIDC flows, SAML 2.0 assertions, and Zero Trust identity architectures.
