---
title: "在 Docker 与 WSL2 本地实验中使用 Trivy：扫描 CVE 漏洞、Secrets 与生成 SBOM"
description: "在 Windows Enterprise 的 WSL2 与 Docker 环境中本地运行 Trivy，检测镜像漏洞、硬编码 Secrets 并生成合规 SBOM 清单。"
date: 2026-11-25
categoria: Compliance
tags: [trivy, sbom, devsecops, docker, wsl2, open-source, secrets, compliance]
nivel: Intermediário
draft: false
---

> **TL;DR：** 在 SOC 实验室或生产环境中运行任何容器镜像前，先排查高危 CVE 漏洞、遗漏在镜像层中的 *Secrets* 并生成 **SBOM**（软件物料清单），能够有效防范供应链风险。本文演示如何在 Windows Enterprise 的 WSL2 中完全本地运行 **Trivy**，无需将代码或镜像上传至外部服务。

---

## 1. 为什么在本地使用 Trivy 审计镜像与代码库？

在 WSL2 中快速拉起容器能加速 Keycloak、Wazuh 或 Shuffle 等工具的测试，但陈旧镜像或配置不当的 `compose.yml` 往往潜藏高危组件或意外泄露的 *Secrets*。

**Trivy**（由 Aqua Security 维护的开源安全扫描器）将多项能力集成于单一工具中：
- **漏洞扫描 (CVE)**：覆盖操作系统软件包（Debian、Alpine、Ubuntu）及应用依赖（`npm`、`pip`、`go`）。
- **Secrets 检测 (*Secret Scanning*)**：扫描本地文件系统、Git 仓库与容器镜像层。
- **SBOM 生成**：支持 **CycloneDX** 与 **SPDX**（Linux Foundation）等标准审计格式。
- **错误配置检查**：审计 `Dockerfile`、`compose.yml` 与 Kubernetes 清单。

---

## 2. 前置条件与 WSL2 隔离要求

| 组件 | 最低要求 | 说明 |
|---|---|---|
| **宿主机系统** | Windows 10/11 Enterprise + WSL2 | 建议使用更新后的 Ubuntu 22.04/24.04 WSL2。 |
| **容器引擎** | Docker Desktop 或 WSL2 中的 Docker Engine | 在 WSL2 终端内可访问本地 Docker Socket。 |
| **运行方式** | 官方镜像 `aquasec/trivy` 或本地二进制 | CVE 漏洞库本地缓存在 `~/.cache/trivy`。 |

---

## 3. 本地扫描 Docker 镜像并检测 Secrets

无需在宿主机安装任何软件包，直接将 Docker Socket 以只读方式挂载即可审计本地镜像：

```bash
mkdir -p ~/.cache/trivy
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v ~/.cache/trivy:/root/.cache/ \
  aquasec/trivy:latest image --severity HIGH,CRITICAL nginx:alpine
```

在提交代码前扫描本地项目目录（如 `compose.yml`、脚本和 `Dockerfile`）中的 *Hardcoded Secrets* 与配置隐患：

```bash
docker run --rm \
  -v $(pwd):/workspace:ro \
  -v ~/.cache/trivy:/root/.cache/ \
  aquasec/trivy:latest fs --scanners vuln,misconfig,secret /workspace
```

> **离线隔离提示：** 首次下载漏洞库缓存后，只需在 `docker run` 中加上 `--skip-db-update --offline-scan` 与 `--network none`，即可在完全断网的隔离环境中运行 Trivy。

---

## 4. 生成用于合规审计的 SBOM (CycloneDX / SPDX)

遵循 ISO 27001、SOC 2 或 NIST SSDF 的软件供应链审计通常要求提供正式的软件组件清单。使用一条命令即可导出 **CycloneDX JSON** 格式的 **SBOM**：

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v $(pwd):/output \
  -v ~/.cache/trivy:/root/.cache/ \
  aquasec/trivy:latest image --format cyclonedx --output /output/sbom-lab.cdx.json nginx:alpine
```

生成的 `sbom-lab.cdx.json` 完整记录了镜像内所有依赖库、版本号与开源许可证，可直接归档作为合规证据。

---

## 5. 本地预检与流水线阻断策略示例

在本地 pre-commit 脚本或 CI/CD 流水线中，可在发现泄露的 *Secrets* 或存在修复补丁的严重漏洞（`--ignore-unfixed`）时自动阻断构建：

```bash
trivy fs --exit-code 1 --severity CRITICAL --ignore-unfixed --scanners vuln,secret .
```

从而防止 *Client Secrets*、令牌或高危镜像流入共享测试环境。

---

## 6. 安全控制映射与最佳实践

| 标准框架 | 条款编号 | 实践落地 |
|---|---|---|
| **NIST SP 800-218 (SSDF)** | `PW.4` / `RV.1` | 持续检查第三方组件漏洞并维护完整的 SBOM 清单。 |
| **NIST CSF** | `ID.AM-02` / `PR.DS-05` | 软件资产盘点与防范源码中的 *Secrets* 泄露。 |
| **ISO/IEC 27001:2022** | `A.8.8` / `A.8.28` | 技术漏洞管理与安全编码实践。 |

---

## 参考资料

- [Aqua Security — Trivy Official Documentation](https://trivy.dev/latest/)
- [Microsoft Learn — Install WSL 2 on Windows Enterprise](https://learn.microsoft.com/en-us/windows/wsl/install)
- [NIST SP 800-218 — Secure Software Development Framework (SSDF)](https://csrc.nist.gov/pubs/sp/800/218/final)
- [Linux Foundation — SPDX & CycloneDX Standards](https://spdx.dev/)

