---
title: "在 Docker 与 WSL2 中搭建本地 Authentik 实验环境：SSO、OIDC 与团队 MFA 策略实战"
description: "在 Windows Enterprise 的 WSL2 中通过 Docker 本地部署 Authentik，配置 OIDC 单点登录、Passkey 认证与事件审计日志。"
date: 2026-11-23
categoria: IAM
tags: [authentik, iam, oidc, sso, mfa, docker, wsl2, open-source]
nivel: Intermediário
draft: false
---

> **TL;DR：** 在不依赖外部云环境的情况下本地验证现代身份认证流程（*OIDC*、*SAML*、*Passkeys* 与条件访问策略），能大幅提升 IAM 工程效率。本文演示如何在 Windows Enterprise 的 WSL2 中使用 Docker 本地隔离部署 **Authentik**，配置 OIDC 提供程序并查询认证审计事件。

---

## 1. 为什么在本地实验室测试 Authentik？

**Authentik** 是一款面向混合环境与内部应用的开源身份提供程序（*IdP*）。它原生支持 **OIDC**、**SAML 2.0**、**LDAP**、**SCIM** 与 **WebAuthn/FIDO2**，非常适合 IAM 工程师与安全分析师用来验证：
- 可视化认证流程（*Flows*），包括信誉检查或抗钓鱼 MFA（*Passkey*）强制要求。
- 为 SOC 工具（如 Shuffle、Wazuh Dashboard 或内部门户）签发 JWT 令牌。
- 生成结构化的登录与管理变更事件，便于直接关联至 SIEM。

在 WSL2 中以**本地回环隔离**（`127.0.0.1`）方式运行整套服务，可确保 *Client Secrets* 与测试证书完全受控，不会暴露到公司内网。

---

## 2. 前置条件与实验环境架构

| 组件 | 最低要求 | 说明 |
|---|---|---|
| **宿主机系统** | Windows 10/11 Enterprise + WSL2 | 开启硬件虚拟化并更新 Ubuntu WSL2 发行版。 |
| **容器引擎** | Docker Desktop 或 WSL2 中的 Docker Engine | 确保启用 Compose v2 (`docker compose version`)。 |
| **本地端口** | `127.0.0.1:9000` (HTTP) 与 `127.0.0.1:9443` (HTTPS) | 严格绑定本地回环地址，防止暴露到局域网。 |

---

## 3. 使用 Docker Compose 启动 Authentik

在 WSL2 中创建专用目录（例如 `~/iam-labs/authentik`），并将所有 *Secrets* 存放在本地 `.env` 文件中（切勿提交到版本库）：

```bash
mkdir -p ~/iam-labs/authentik/media ~/iam-labs/authentik/custom-templates
```

`.env` 配置示例：

```env
PG_PASS=请替换为高强度POSTGRES_SECRET
AUTHENTIK_SECRET_KEY=请替换为64位随机密钥
AUTHENTIK_BOOTSTRAP_PASSWORD=请替换为实验管理员密码
AUTHENTIK_BOOTSTRAP_EMAIL=iam-lab@contoso.local
```

编写 `compose.yml`，将 PostgreSQL、Redis、Server 与 Worker 仅绑定至 `127.0.0.1`：

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

启动服务：

```bash
cd ~/iam-labs/authentik
docker compose up -d
docker compose logs -f server
```

在浏览器打开 `http://127.0.0.1:9000/if/admin/`，使用默认管理员账号 `akadmin` 及 `AUTHENTIK_BOOTSTRAP_PASSWORD` 登录。

---

## 4. 配置 OIDC 提供程序与 Passkeys (FIDO2)

1. **创建应用与 OIDC 提供程序：**
   在管理后台进入 `Applications > Applications > Create with Provider`。
   - 选择 **OAuth2/OpenID Provider**。
   - 记录生成的 **Client ID** 与 **Client Secret**，用于测试应用（如 Grafana、Shuffle 或运行在 `http://127.0.0.1:3000/callback` 的本地应用）。
2. **启用 Passkey / WebAuthn：**
   进入 `Flows and Stages > Stages > Create > Authenticator WebAuthn Stage`，将该阶段绑定到默认认证流程（`default-authentication-flow`），即可演练抗钓鱼登录。

---

## 5. 事件审计与 SIEM 关联分析

每次成功登录、密码错误或 *Client Secret* 变更都会记录在后台 `Events > Logs` 中，并由 `server` 容器输出结构化日志。你也可以通过 REST API 直接拉取近期事件：

```bash
curl -s http://127.0.0.1:9000/api/v3/events/events/ \
  -H "Authorization: Bearer 替换为你的_API_TOKEN" | jq '.results[:5] | .[] | {action, created, client_ip, user: .user.username}'
```

借助该接口，可将 `login_failed`、`authorize_application` 与 `model_updated` 等事件无缝接入本地 SIEM（如 Wazuh），用于检测 MFA *绕过 (Bypass)* 尝试或未经授权的 *Secret* 修改。

---

## 6. 安全控制映射与最佳实践

| 标准框架 | 条款编号 | 实践落地 |
|---|---|---|
| **NIST SP 800-63B** | *Digital Identity Guidelines (AAL2 / AAL3)* | 在关键登录流程中强制使用 FIDO2 硬件密钥 / *Passkeys*。 |
| **NIST CSF** | `PR.AA-01` / `PR.AA-03` | 集中化身份管理、单点登录 (SSO) 与多因素认证。 |
| **ISO/IEC 27001:2022** | `A.5.16` / `A.8.5` | 身份全生命周期管理与安全身份验证机制。 |

---

## 参考资料

- [Authentik — Official Documentation (Docker Compose & OIDC)](https://docs.goauthentik.io/docs/)
- [Microsoft Learn — Install WSL 2 on Windows Enterprise](https://learn.microsoft.com/en-us/windows/wsl/install)
- [NIST SP 800-63B — Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)

