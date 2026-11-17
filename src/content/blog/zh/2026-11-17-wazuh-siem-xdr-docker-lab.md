---
title: "基于 Wazuh 的 SIEM 与 XDR：在 Windows Enterprise 上使用 Docker 本地部署实战"
description: "详细实操指南：在 Windows Enterprise 上通过 Docker Desktop 与 WSL 2 部署 Wazuh 完整技术栈（Manager、Indexer 与 Dashboard），用于本地 SOC 攻防演练。"
date: 2026-11-17
categoria: SOC
tags: [wazuh, siem, xdr, docker, windows-enterprise, wsl2, lab, open-source, soc]
nivel: Intermediário
---

对于 SOC 分析师、威胁检测工程师以及应急响应人员而言，深入掌握安全日志如何被采集、解码与关联分析，与熟悉主流商业云平台同样重要。在许多情况下，出于企业合规与安全防护策略的要求，直接在生产环境中测试全新的检测规则、执行防御绕过脚本或模拟高危攻击是不被允许的。

搭建一个本地的 **Wazuh** 实验环境——全球采用率最高且完全开源的 **SIEM（安全信息与事件管理）** 与 **XDR（扩展检测与响应）** 平台，能让分析师在零云端账单、零数据外泄风险的前提下，实时采集终端遥测、验证自定义规则并研判各类战术告警。

> **极简配置要点（TL;DR）：** 要在 Windows Enterprise 环境中通过 Docker 稳定运行 Wazuh 完整技术栈（Manager、Indexer 和 Dashboard），请在 `.wslconfig` 中为 WSL 2 分配至少 6 GB 内存，并在 Linux 内核中将 `vm.max_map_count` 参数上调至 `262144`，以确保底层的 OpenSearch 搜索引擎正常初始化。

> 📘 **官方参考文档：** 本指南严格遵循 Wazuh 官方项目文档标准：
> - [Wazuh Documentation — Deployment with Docker](https://documentation.wazuh.com/current/deployment-options/docker/index.html)
> - [Wazuh Agent installation on Windows endpoints](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html)

---

## 1. 为什么在企业级工作站上本地运行 Wazuh？

在采用 Windows 10/11 Enterprise 系统的企业环境中，安全从业人员的工作站通常具备多核处理器以及 16 GB 至 32 GB 的充足物理内存。结合 Docker Desktop 与 WSL 2 运行该环境具备显著优势：

1. **绝对的数据主权与本地隔离：** 测试期间产生的所有日志、文件哈希与告警事件均严格限定在本地环境（localhost），杜绝隐私泄露。
2. **完整的 SIEM 与 XDR 一体化能力：** Wazuh 在统一的控制台中集成了日志集中审计、文件完整性监控（FIM）、脆弱性扫描以及主动响应阻断机制。
3. **原生映射 MITRE ATT&CK 框架：** Wazuh 触发的每一条威胁告警均已预先关联到 MITRE ATT&CK 的具体战术与技术编号。

---

## 2. Windows Enterprise 与 WSL 2 必备前置调优

Wazuh Indexer 构建于 OpenSearch 基础之上，对 Linux 虚拟内存映射空间有硬性要求，必须进行相应调优以避免容器因内存不足（OOM）而异常崩溃。

### 步骤 1：在 `.wslconfig` 中配置资源上限
在 Windows 宿主机中打开 PowerShell，编辑全局 WSL 2 配置文件：

```powershell
notepad "$env:USERPROFILE\.wslconfig"
```

写入适用于单节点实验环境的建议配置：

```ini
[wsl2]
memory=6GB            # 运行 Wazuh 单节点容器的推荐最小内存
processors=4          # 分配 4 个虚拟 CPU 核心
swap=2GB              # 磁盘虚拟交换分区
localhostForwarding=true
```

### 步骤 2：在 WSL 2 中调优 `vm.max_map_count`
OpenSearch 要求底层 Linux 系统支持至少 262,144 个内存映射区。在 WSL 2 终端或 PowerShell 中执行：

```powershell
wsl -d Ubuntu -u root sysctl -w vm.max_map_count=262144
```

为使此配置永久生效，请将其追加至 `/etc/sysctl.conf` 文件中：

```bash
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

执行重启以应用内核参数：

```powershell
wsl --shutdown
```

---

## 3. 使用 Docker Compose 启动 Wazuh 单节点集群

Wazuh 官方在代码仓库中提供了专供测试和单机部署的 Docker Compose 模板：

1. 在 WSL 2 终端中克隆代码仓库：
   ```bash
   git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.2 --depth=1
   cd wazuh-docker/single-node
   ```

2. 生成组件间双向加密通信所需的内部 TLS 证书：
   ```bash
   docker compose -f generate-indexer-certs.yml run --rm generator
   ```

3. 在后台启动全部核心服务容器：
   ```bash
   docker compose up -d
   ```

4. 验证服务运行状态：
   ```bash
   docker compose ps
   ```

启动的三个核心容器如下：
- **`single-node-wazuh.manager-1`：** 负责规则匹配、事件解码以及 Agent 注册通信（监听 1514/TCP、1515/TCP 与 55000/TCP）。
- **`single-node-wazuh.indexer-1`：** 基于 OpenSearch 的索引分析引擎（监听 9200/TCP）。
- **`single-node-wazuh.dashboard-1`：** 分析师 Web 界面（监听 443/TCP）。

---

## 4. 访问仪表盘并在 Windows 宿主机上注册 Agent

等待约 2 分钟以完成索引初始化：

1. 打开浏览器并访问：
   ```text
   https://localhost
   ```
2. 忽略自签名证书的安全告警（本地实验环境）。
3. 使用默认账户登录：
   - **用户名：** `admin`
   - **默认密码：** `SecretPassword***`（可在部署前的 `.env` 文件中自行重命名）。

### 在 Windows 本机上安装并连接 Agent

为了向你的 Wazuh 集群持续输送真实的 Windows 安全遥测数据：

1. 下载官方的 Wazuh Agent Windows MSI 安装包（4.9+ 版本）。
2. 以管理员权限运行 PowerShell 并静默安装，目标指向本地容器：
   ```powershell
   .\wazuh-agent-4.9.2-1.msi /q WAZUH_MANAGER="127.0.0.1" WAZUH_REGISTRATION_SERVER="127.0.0.1" WAZUH_AGENT_NAME="WIN-LAB-ENTERPRISE"
   ```
3. 启动 Windows 本地服务：
   ```powershell
   NET START WazuhSvc
   ```
4. 进入 Wazuh Dashboard 的 **Endpoints Summary** 界面，几秒钟后即可看到该主机状态变为 **Active**。

---

## 5. SOC 威胁检测实战演练：捕获可疑提权命令

当 Agent 成功运行并持续捕获 Windows 安全事件日志（*Security Event Log* 与 *Sysmon*）：

1. **模拟攻击探测：** 在 Windows 命令行中执行攻击者常用的侦察命令：
   ```cmd
   net user Administrator
   net localgroup Administrators
   ```
2. **在仪表盘中查验：**
   - 进入 **Wazuh Dashboard > Security events**。
   - 在搜索栏中使用 Lucene 语法检索：
     ```lucene
     agent.name: "WIN-LAB-ENTERPRISE" AND rule.level: >= 3
     ```
   - Wazuh 将会自动捕获 Windows 审计事件（事件 ID 4798 和 4799——本地用户组枚举），并关联到 MITRE ATT&CK 的 **T1087 (Account Discovery)** 技术。

3. **创建自定义检测规则：**
   在 Manager 容器内的 `/var/ossec/etc/rules/local_rules.xml` 文件中，分析师可自定义告警逻辑。例如，针对执行 `whoami /priv` 的行为定义规则：
   ```xml
   <group name="windows,powershell,">
     <rule id="100002" level="7">
       <if_sid>60103</if_sid>
       <field name="win.eventdata.commandLine">whoami /priv</field>
       <description>检测到本地特权枚举尝试: whoami /priv</description>
       <mitre>
         <id>T1033</id>
       </mitre>
     </rule>
   </group>
   ```

---

## 6. 构建本地可信安全试验场的后续演进

当 Wazuh 在 Docker Desktop 环境中稳定运行后，你便拥有了一个完整的 SIEM 与 XDR 基础设施，可继续探索：
- 接入其他本地容器日志（如前文构建的 Keycloak 认证中心）。
- 联动 **Shuffle** 或 **TheHive** 构建全自动化的 SOAR 响应编排剧本（Playbook）。
- 模拟安全防御的规避与绕过（Bypass）技术，在完全无害的环境中夯实威胁检测工程能力。

