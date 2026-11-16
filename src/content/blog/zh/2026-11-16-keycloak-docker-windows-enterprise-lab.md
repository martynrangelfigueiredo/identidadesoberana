---
title: "本地 IAM 实验环境：在 Windows 企业版上通过 Docker 与 WSL 2 搭建 Keycloak"
description: "实战指南：在 Windows 企业版上使用 Docker Desktop、WSL 2 和持久化 PostgreSQL 快速搭建 Keycloak 26 本地 IAM 实验环境。"
date: 2026-11-16
categoria: IAM
tags: [keycloak, iam, docker, windows-enterprise, wsl2, lab, oidc, open-source]
nivel: 中级
---

对于 SOC 分析师、身份安全工程师和合规专家而言，掌握单点登录（SSO）、OIDC 联合身份验证以及精细化访问控制至关重要。然而，直接在企业云端生产租户（tenant）中测试身份验证流程、MFA 策略与跨域联合往往存在合规风险与操作门槛。

在本地搭建 **Keycloak** — 作为云原生计算基金会（CNCF）生态与工业界标准开源身份提供商（IdP）和访问管理中心，能够让安全团队在完全隔离的环境下模拟复杂的认证机制、验证前后端集成，并在无需消耗任何公有云额度的情况下验证底层鉴权流程。

> **实验环境速览（TL;DR）：** 为了在 Windows 企业版上平稳运行 Keycloak 26 与 PostgreSQL 且不消耗过多工作站内存，请在 `.wslconfig` 中将 WSL 2 内存限制为 4 GB 至 6 GB，在 Docker Desktop 中启用 WSL 2 引擎，并使用开发模式（`start-dev`）配合命名数据卷（named volumes）实现数据持久化。

> 📘 **官方权威参考：** 本指南严格参考 Keycloak 官方技术文档及 Linux Foundation / CNCF 规范：
> - [Keycloak — Running Keycloak in a container (Official Guides)](https://www.keycloak.org/guides#server)
> - [Keycloak — Getting started with Keycloak and Docker](https://www.keycloak.org/getting-started/getting-started-docker)

---

## 1. 为什么在 Windows 企业版上搭建该实验环境？

在现代企业办公环境中，Windows 10/11 企业版（Enterprise）工作站普遍已内置 Hyper-V 与 WSL 2 虚拟化能力。通过容器运行该实验架构具有显著优势：

1. **完全的本地隔离：** 所有凭据、密码哈希、会话 token 和私有配置均留在本地工作站，零外流风险。
2. **零许可成本：** Keycloak 遵循 Apache 2.0 开源协议，也是 Red Hat build of Keycloak 的上游核心。
3. **与现代云端架构无缝对称：** 无论是 Microsoft Entra ID 还是主流公有云使用的标准协议（OpenID Connect、OAuth 2.0、SAML 2.0），均可在 Keycloak 中逐项拆解与深度调试。

---

## 2. 关键优化：限制 WSL 2 的内存开销

默认情况下，WSL 2 会动态申请主机高达 50% 甚至更多的物理内存。为防止企业工作站在同时运行 IDE、EDR 和安全代理时发生卡顿，建议在 Windows 用户根目录配置 `.wslconfig`：

1. 打开 PowerShell 并编辑配置文件：
   ```powershell
   notepad "$env:USERPROFILE\.wslconfig"
   ```
2. 填入以下经过验证的硬件隔离参数：
   ```ini
   [wsl2]
   memory=4GB       # 限制 WSL 2 最大内存占用
   processors=2     # 限制使用的 CPU 核心数
   swap=2GB         # Linux 交换分区大小
   localhostForwarding=true
   ```
3. 重启 WSL 2 以使资源限制即刻生效：
   ```powershell
   wsl --shutdown
   ```

---

## 3. 本地实验环境的 `docker-compose.yml` 架构

在终端中为实验项目创建独立目录（例如 `mkdir keycloak-lab && cd keycloak-lab`），并创建如下 `docker-compose.yml` 文件。

我们采用基于 Quarkus 的官方 Keycloak 镜像，并连接到运行在独立容器网络中的 PostgreSQL 16 数据库：

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

> 🔒 **实战安全准则：** 端口映射务必绑定在本地回环地址（`127.0.0.1:8080:8080`），防止企业局域网内的其它设备访问你工作站上的本地实验环境。

---

## 4. 启动容器并登录管理控制台

确保 Docker Desktop 正常运行，在包含 compose 文件的目录下执行：

```bash
docker compose up -d
```

查看容器日志直至初始化完成：

```bash
docker compose logs -f keycloak
```

当终端出现 `Listening on: http://0.0.0.0:8080` 提示时：
1. 打开浏览器并访问：`http://localhost:8080`
2. 点击 **Administration Console**
3. 输入初始管理凭据：
   * **用户名：** `admin`
   * **密码：** `admin_lab_password_2026`

---

## 5. Keycloak IAM 基础架构配置指南

### 1. 创建独立 Realm（领域）
在 Keycloak 中，严禁将业务用户或测试应用直接配置在 `master` realm 中。`master` 应仅用于管理 Keycloak 服务本身。
* 在左上角 Realm 下拉框中点击 **Create Realm**。
* 输入 Realm 名称（如 `lab-corporativo`），点击 **Create**。

### 2. 注册客户端应用（OIDC Client）
* 导航至 **Clients** > **Create client**。
* **Client type:** `OpenID Connect`。
* **Client ID:** `app-portal-interno`。
* 在 **Capability config** 界面：
  * 如需模拟应用身份与凭据（*client secrets*），请开启 **Client authentication**；如为基于 PKCE 的单页前端应用（SPA），则可保持关闭。
* 在 **Login settings** 页面配置：
  * **Valid redirect URIs:** `http://localhost:3000/*`（或测试应用的本地回调地址）。

### 3. 创建测试用户并强制启用本地 MFA
* 导航至 **Users** > **Add user**。
* 填写用户名（如 `colaborador.teste`）及虚拟邮箱（如 `colaborador@contoso.com`）。
* 在 **Credentials** 选项卡下设置初始密码，并取消勾选 *Temporary*。
* 为模拟多因素身份验证（MFA），在 **Required Actions** 中添加 **Configure OTP**。当该用户下次登录时，系统将强制要求使用 Google Authenticator 或 Microsoft Authenticator 扫码绑定，全程无需支付商业 MFA 授权费用。

---

## 6. 环境维护与资源释放

完成日常安全测试后，按以下方式优雅终止服务以保留持久化数据：

```bash
# 停止容器并保留数据库数据：
docker compose down

# 下次继续实验时快速拉起：
docker compose up -d

# 若需彻底清空所有测试数据重新开始：
docker compose down -v
```

通过这一本地 IAM 环境，安全分析师可以随时针对 OIDC 授权码流程、SAML 断言劫持以及零信任条件访问策略展开深度实验，全面掌控底层鉴权机理。

