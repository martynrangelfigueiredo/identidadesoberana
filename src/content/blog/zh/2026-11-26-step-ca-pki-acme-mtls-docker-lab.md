---
title: "在 Docker 和 WSL2 中部署 Smallstep (step-ca)：内部 PKI、ACME 与短生命周期证书"
description: "在 Windows Enterprise 的 Docker 和 WSL2 环境中搭建基于 Smallstep step-ca 的本地 PKI，自动签发 ACME 与 mTLS 证书的实战指南。"
date: 2026-11-26
categoria: IAM
tags: [pki, mtls, acme, smallstep, zero-trust, docker, wsl2, open-source]
nivel: Intermediário
draft: false
---

> **TL;DR：** 本地实验环境中的 SOC 与 IAM 服务（如 Keycloak、Wazuh、自动化 API）往往只运行明文 HTTP 或缺乏信任链的自签名证书。本文演示如何在 Docker 和 WSL2 中使用 **Smallstep (`step-ca`)** 搭建内部证书颁发机构（CA），通过 **ACME** 自动签发短生命周期证书，并在不依赖公网 CA 的前提下启用 **mTLS**。

---

## 1. 为什么在零信任实验环境中运行内部 PKI？

在 Windows Enterprise 的 WSL2 本地实验环境中，零散的自签名证书会导致浏览器频繁告警、破坏 OIDC/SAML 集成，并让团队习惯性忽略 TLS 警告；而为内网主机（如 `*.lab.local`）申请公网证书又会将内部命名暴露在公共证书透明度（*Certificate Transparency*）日志中。

**Smallstep (`step-ca`)** 提供了轻量级开源 PKI 方案：
- **原生支持 ACME 协议（RFC 8555）：** 让 Caddy、Traefik 或 Nginx 等反向代理能够自动续期内部证书。
- **短生命周期证书：** 默认签发 24 小时（或更短）有效期证书，大幅降低私钥泄露后的风险窗口。
- **mTLS（双向 TLS）：** 在微服务、日志采集器与 API 之间实现强双向身份认证，无需仅依赖静态 *Secret*。
- **完全本地运行：** 整个证书层级（Root CA 与 Intermediate CA）均保留在 WSL2 本地实验目录中。

---

## 2. 前置条件与 WSL2 隔离配置

| 组件 | 最低配置要求 | 说明 |
|---|---|---|
| **宿主机系统** | Windows 10/11 Enterprise（启用 WSL2） | WSL2 中运行已更新的 Ubuntu 22.04/24.04。 |
| **容器引擎** | Docker Desktop 或 WSL2 内置 Docker Engine | 专用本地实验网络。 |
| **官方镜像** | `smallstep/step-ca` 与 `smallstep/step-cli` | 严格绑定至 `127.0.0.1` 的 `9000` 端口。 |

---

## 3. 使用 Docker Compose 在回环地址启动 step-ca

创建实验目录并编写 `compose.yml`，将端口严格绑定到回环接口（`127.0.0.1`），避免暴露到 Windows 外部网络：

```yaml
services:
  step-ca:
    image: smallstep/step-ca:latest
    container_name: lab-step-ca
    restart: unless-stopped
    ports:
      - "127.0.0.1:9000:9000"
    environment:
      - DOCKER_STEPCA_INIT_NAME=Lab Internal CA
      - DOCKER_STEPCA_INIT_DNS_NAMES=localhost,step-ca,127.0.0.1
      - DOCKER_STEPCA_INIT_PROVISIONER_NAME=admin@lab.local
    volumes:
      - step_data:/home/step

volumes:
  step_data:
```

启动服务并查看 Root CA 与 Intermediate CA 的初始化日志：

```bash
mkdir -p ~/lab-pki && cd ~/lab-pki
docker compose up -d
docker compose logs -f step-ca
```

首次启动时，容器会自动在 `step_data` 卷中（`/home/step/secrets/password`）生成 CA 私钥随机密码。请记录日志中输出的 Root CA 指纹（*Fingerprint*），以便客户端校验证书信任链。

---

## 4. 启用 ACME Provisioner 并签发证书

为使反向代理与本地服务能够通过 **ACME** 自动申请证书，可在容器内添加 ACME Provisioner：

```bash
docker exec -it lab-step-ca step ca provisioner add acme --type ACME
docker compose restart step-ca
```

随后验证健康检查接口与当前启用的 Provisioner 列表：

```bash
curl -sk https://127.0.0.1:9000/health
docker exec -it lab-step-ca step ca provisioner list
```

### 按需签发服务端证书

如需快速为本地服务（例如 `keycloak.lab.local`）签发有效期 24 小时的 TLS 证书，可执行：

```bash
docker exec -it lab-step-ca step ca certificate \
  "keycloak.lab.local" \
  /home/step/keycloak.crt \
  /home/step/keycloak.key \
  --provisioner admin@lab.local \
  --password-file /home/step/secrets/password
```

导出根证书公钥（`root_ca.crt`），仅在实验环境内用于信任校验：

```bash
docker cp lab-step-ca:/home/step/certs/root_ca.crt ./root_ca.crt
```

在 Ubuntu/WSL2 中，可直接通过 `curl` 指定实验根证书验证信任链，而无需修改整个系统的根证书存储：

```bash
curl --cacert ./root_ca.crt https://127.0.0.1:9000/health
```

---

## 5. 安全最佳实践与 mTLS

| 控制项 | 实践建议 | 安全收益 |
|---|---|---|
| **短有效期** | 将服务端证书有效期控制在 12–24 小时并通过 ACME 自动续期。 | 减少对庞大 CRL 的依赖并压缩密钥泄露窗口。 |
| **Root CA 保护** | 隔离保存 Root CA 私钥，日常仅由 Intermediate CA 签发证书。 | 无需重新分发根证书即可轮换中间 CA。 |
| **服务间 mTLS** | 要求管理类 API 强制校验同一内部 CA 签发的客户端证书。 | 即使内部端口意外可达，也能有效阻止横向移动。 |
| **卷权限卫生** | 限制 `step_data` 卷权限，切勿将 `/home/step/secrets/` 提交到 Git。 | 防止证书颁发机构私钥泄露。 |

---

## 6. 控制映射与参考资料

- **Smallstep 官方文档：** [step-ca Overview & ACME Provisioner](https://smallstep.com/docs/step-ca/)
- **Microsoft Learn (WSL2)：** [Windows Subsystem for Linux 官方文档](https://learn.microsoft.com/en-us/windows/wsl/)
- **IETF RFC 8555：** Automatic Certificate Management Environment (ACME)
- **NIST SP 800-57 / CSF 2.0 (`PR.DS-02`)：** 采用强加密与密钥生命周期管理保护传输中的数据。
- **CIS Controls v8 (`3.10` / `12.2`)：** 传输层数据加密及基于 mTLS 的安全网络架构。
