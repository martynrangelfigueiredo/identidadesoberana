---
title: "基于 Shuffle SOAR 的安全编排自动化：Docker 环境下打通 Wazuh 与 TheHive"
description: "在 Windows Enterprise 环境下使用 Docker 和 WSL 2 部署开源 SOAR 平台 Shuffle，构建 Wazuh SIEM 与 TheHive 之间的自动化联动工作流。"
date: 2026-11-19
categoria: SOC
tags: [shuffle, soar, wazuh, thehive, docker, windows-enterprise, wsl2, lab, open-source, soc]
nivel: Intermediário
---

在之前的实验指南中，我们陆续搭建了开放安全运营的核心基石：基于 **Keycloak** 的身份管理、基于 **Wazuh** 的 SIEM/XDR 检测以及基于 **TheHive 与 Cortex** 的案件响应管理。但随着告警数量的增长，完全依赖人工分流并在多个控制台之间复制威胁指标会消耗分析师大量宝贵时间。

**Shuffle** 正是解决这一痛点的开源 **SOAR（安全编排、自动化与响应）** 平台。它支持通过 REST API、Webhook 和可视化拖拽工作流（Workflow）连接各类安全工具，无需商业授权，且所有流程与数据均可保留在本地环境中。

本指南将带领您在 Windows Enterprise 上结合 Docker Desktop 与 WSL 2 部署 Shuffle，并搭建从 Wazuh 接收高危告警、自动在 TheHive 中创建关联案件的实战自动化 playbook。

> **实验室速览（TL;DR）：** Shuffle 依赖 OpenSearch 存储执行记录与应用数据。在 Windows Enterprise 的 WSL 2 环境下运行 Docker Compose 前，请确保内核参数 `vm.max_map_count` 已设为 `262144`，并在 `.wslconfig` 中分配至少 6 GB 内存。

> 📘 **官方参考文档：** 本文基于 Shuffle、Wazuh 与 TheHive 官方技术文档编写：
> - [Shuffle Documentation (shuffler.io)](https://shuffler.io/docs/about)
> - [Shuffle GitHub Repository](https://github.com/Shuffle/Shuffle)
> - [Wazuh Documentation — Integrator](https://documentation.wazuh.com/current/user-manual/manager/manual-integration.html)

---

## 1. Shuffle 在开源 SOC 架构中的定位

Shuffle 充当串联各防御组件的自动化中枢：

1. **基于 OpenAPI/Swagger 的编排：** 可直接导入几乎任何系统（Wazuh、TheHive、Cortex、Keycloak、防火墙或 Jira）的 OpenAPI 规范，自动生成可视化操作节点。
2. **Webhook 与定时触发器：** 支持在 SIEM 触发高危规则时通过 HTTP POST 秒级响应，或定期执行威胁狩猎任务。
3. **容器化隔离执行（Orborus & Workers）：** 每个工作流步骤都在独立容器中运行，确保凭据、secret 及内部网络通信的安全隔离。

---

## 2. Windows Enterprise 与 WSL 2 前置准备

与 Wazuh 和 TheHive 相同，Shuffle 底层同样使用 **OpenSearch**。如果您在之前的实验中已配置好 `.wslconfig` 与 `vm.max_map_count`，相关参数已经就绪；若需确认，可在 PowerShell 中运行：

```powershell
wsl -d Ubuntu -u root sysctl -w vm.max_map_count=262144
```

同时确保 Docker Desktop 已启用 WSL 2 集成并拥有至少 **6 GB 可用内存**。

---

## 3. 使用 Docker Compose 启动 Shuffle SOAR

Shuffle 官方仓库提供了完整的 `docker-compose.yml`，涵盖 **shuffle-frontend**、**shuffle-backend**、**shuffle-orborus** 与 **shuffle-opensearch** 等核心服务。

1. 在 WSL 2 终端创建实验目录并克隆仓库：
   ```bash
   mkdir -p ~/shuffle-lab && cd ~/shuffle-lab
   git clone https://github.com/Shuffle/Shuffle.git --depth=1
   cd Shuffle
   ```

2. 创建 OpenSearch 数据目录并赋予正确权限：
   ```bash
   mkdir -p shuffle-database
   sudo chown -R 1000:1000 shuffle-database
   ```

3. 检查 `.env` 文件中的端口设置（如 `FRONTEND_PORT=3001` 与 `FRONTEND_PORT_HTTPS=3443`），确保不与 TheHive（`9000`）或 Wazuh（`443`）产生冲突。

4. 在后台启动服务栈：
   ```bash
   docker compose up -d
   ```

5. 检查容器运行状态：
   ```bash
   docker compose ps
   ```

---

## 4. 初始访问与管理员配置

等待约 60 秒待 OpenSearch 完成初始化后：

1. 在 Windows 浏览器访问：
   ```text
   https://localhost:3443
   ```
   *（接受实验室自签名证书，或访问 `http://localhost:3001`）。*

2. 根据引导界面创建初始管理员账号（例如 `soc-admin@contoso.com`）及高强度密码。

3. 登录后点击顶部导航栏的 **Workflows** 进入编排画布。

---

## 5. 构建首个联动 Playbook：Wazuh → Shuffle → TheHive

下面构建一个典型的自动化响应流程：每当 **Wazuh** 检出高风险事件（`rule.level >= 10`），告警将自动推送至 **Shuffle**，提取源 IP 并在 **TheHive** 中自动立案。

### 步骤 1：在 Shuffle 中创建 Webhook 触发器
1. 进入 **Workflows > New Workflow**，命名为 `Wazuh-Auto-Triage-TheHive`。
2. 将 **Webhook** 触发器节点拖入画布。
3. 复制生成的本地 Webhook URL（例如 `http://localhost:5001/api/v1/hooks/webhook_...`）。
4. 点击 Webhook 节点的 **Start** 按钮使其进入监听状态。

### 步骤 2：配置 Wazuh 向 Shuffle 推送告警
在 Wazuh Manager 配置文件（`/var/ossec/etc/ossec.conf`）中添加 `<integration>` 配置块：

```xml
<integration>
  <name>custom-shuffle</name>
  <hook_url>http://host.docker.internal:5001/api/v1/hooks/webhook_your_id_here</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

重启 Wazuh Manager 使 JSON 告警推送生效。

### 步骤 3：提取 IP 并在 TheHive 自动建案
1. 在 Shuffle 编辑器中将 **Webhook** 节点连接至内置的 **TheHive** 应用节点。
2. 将 TheHive 容器（`http://host.docker.internal:9000`）生成的 API Key 作为加密 *secret* 保存在 Shuffle 认证配置中。
3. 选择 **`Create Case`** 动作并映射 Webhook 传入的 JSON 字段：
   - **Title:** `[Wazuh] $exec.all_fields.rule.description`
   - **Severity:** `2`（Medium）
   - **Description:** `Agent: $exec.all_fields.agent.name | Source IP: $exec.all_fields.data.srcip`
   - **Tags:** `["wazuh", "auto-triage", "shuffle"]`
4. 再串联一个 **`Create Observable`** 节点，自动将 `$exec.all_fields.data.srcip` 作为 `ip` 类型指标附加到新建案件中。

---

## 6. 安全最佳实践与后续演进

在运行自动化 SOAR playbook 时建议遵循以下原则：

- **妥善保护 Secret：** 切勿在代码块或手动 HTTP 请求中硬编码明文 API Key，务必统一使用 Shuffle 原生加密凭据库。
- **循环与重复控制（去重）：** 在 TheHive 创建新案件前增加条件分支（`Branch / Condition`），检查过去 24 小时内是否已存在针对同一 IP 或用户的未关闭案件，防止告警风暴生成大量重复工单。
- **流程扩展：** 在创建可观察对象后直接联动 **Cortex** 节点自动运行威胁情报分析器，并仅在确认高风险时通过内部即时通讯 Webhook 通知 SOC 值班团队。
