---
title: "基于 TheHive 和 Cortex 的 SOAR 架构：Docker 环境下的应急响应实验室"
description: "在 Windows Enterprise 环境下利用 Docker 和 WSL 2 搭建 TheHive 与 Cortex 平台，系统化开展事件分流、案件管理与安全编排自动化（SOAR）。"
date: 2026-11-18
categoria: SOC
tags: [thehive, cortex, soar, docker, windows-enterprise, wsl2, lab, open-source, soc]
nivel: Intermediário
---

在安全运营中心（SOC）的日常实战中，通过 SIEM（如 Wazuh 或 Microsoft Sentinel）检出威胁仅仅是安全防御的第一步。接下来的阶段——告警研判分流、威胁指标（IoC）深度研判、事件时间线还原、分析师任务协作以及遏制处置——必须依赖专业的安全事件响应平台（**SIRP - Security Incident Response Platform**）与安全编排自动化与响应（**SOAR - Security Orchestration, Automation, and Response**）能力的深度融合。

在开源技术与开放基础设施领域，**TheHive**（安全案件与事件管理平台）与 **Cortex**（可观察对象自动化分析与主动响应引擎）的协同组合是业内公认的标准架构。

本实操指南将指导您在 Windows Enterprise 环境下，结合 Docker Desktop 与 WSL 2 搭建一套完整的 TheHive 和 Cortex 本地实验室。您可以在 100% 本地化且安全隔离的环境中测试应急响应 playbook、进行指标自动化研判并建立规范化的案件处置流。

> **实验室速览（TL;DR）：** 在 Windows Enterprise 环境下通过 WSL 2 运行由 TheHive、Cortex、Cassandra、Elasticsearch 和 MinIO 组成的容器集群时，请在 `.wslconfig` 中至少分配 6 GB 至 8 GB 内存，并在 Docker Compose 中使用内部 bridge 网桥以保障容器间稳定通信。

> 📘 **官方参考文档：** 本实验基于 TheHive 与 Cortex 官方技术指南构建：
> - [TheHive Project Documentation (StrangeBee)](https://docs.strangebee.com/)
> - [TheHive GitHub Repository](https://github.com/TheHive-Project/TheHive)
> - [Cortex Project Documentation](https://github.com/TheHive-Project/Cortex)

---

## 1. 为什么在 SOC 运营中引入 TheHive 与 Cortex？

在应急响应团队（CSIRT/CERT）与企业级 SOC 中，通用的工单系统或 IT 服务管理（ITSM）软件无法满足网络安全调查的严苛要求。TheHive 与 Cortex 具备专门面向防御作战的核心能力：

1. **面向威胁的案件协同管理：** 每个案件均聚合了告警日志、精确时间线、分级任务树以及可观察对象目录（IP 地址、文件哈希、域名、URL 和用户账号）。
2. **Cortex 自动化威胁研判：** Cortex 集成了数十种分析器（analyzer），可一键或全自动向威胁情报（Threat Intelligence）平台（如 VirusTotal、AbuseIPDB、Shodan、MISP）发起富化查询。
3. **基于案件模板（Case Templates）的标准化：** 为高频事件（如钓鱼邮件攻击、勒索软件感染、凭证泄露）定义标准化的 playbook，确保全体分析师遵循规范化的处置与遏制流程。
4. **数据完全自主与隔离：** 在满足严格合规（如 LGPD/GDPR）的场景下，调查过程产生的所有敏感取证数据均完全保留在本地。

---

## 2. Windows Enterprise 与 WSL 2 的前置配置

TheHive 架构高度稳健，底层依托分布式数据库（Apache Cassandra）、全文检索与分析引擎（Elasticsearch）以及兼容 S3 的对象存储（MinIO）来保存附件与取证证据。

### 步骤 1：在 `.wslconfig` 中调整资源配额

在 PowerShell 中打开 WSL 2 全局配置文件：

```powershell
notepad "$env:USERPROFILE\.wslconfig"
```

配置满足多容器并发运行的硬件资源：

```ini
[wsl2]
memory=8GB            # 推荐为 TheHive、Cortex、Cassandra 和 Elasticsearch 分配的内存
processors=4          # 分配 4 个虚拟核心
swap=4GB              # 磁盘交换分区
localhostForwarding=true
```

### 步骤 2：调整 Elasticsearch 虚拟内存上限

Elasticsearch 要求 Linux 内核提供足够的内存映射区域：

```powershell
wsl -d Ubuntu -u root sysctl -w vm.max_map_count=262144
```

将参数持久化写入 WSL 2 内部的 `/etc/sysctl.conf`：

```bash
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

在 PowerShell 中重启 WSL 2 以使配置生效：

```powershell
wsl --shutdown
```

---

## 3. 利用 Docker Compose 编排实验室集群

在本地环境中创建专用的实验工作目录（例如在 WSL 2 终端或 PowerShell 中）：

```bash
mkdir -p ~/thehive-lab && cd ~/thehive-lab
```

编写 `docker-compose.yml` 编排文件：

```yaml
version: "3.8"

networks:
  soar-net:
    driver: bridge

volumes:
  cassandra-data:
  elasticsearch-data:
  minio-data:
  thehive-data:
  cortex-data:

services:
  # 1. 元数据与时间线 NoSQL 数据库
  cassandra:
    image: cassandra:4.1
    container_name: cassandra-thehive
    restart: unless-stopped
    networks:
      - soar-net
    environment:
      - CASSANDRA_START_RPC=true
      - CASSANDRA_CLUSTER_NAME=thehive
      - HEAP_NEWSIZE=256M
      - MAX_HEAP_SIZE=1024M
    volumes:
      - cassandra-data:/var/lib/cassandra

  # 2. 全文索引与高效检索引擎
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.9
    container_name: elasticsearch-thehive
    restart: unless-stopped
    networks:
      - soar-net
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    volumes:
      - elasticsearch-data:/usr/share/elasticsearch/data

  # 3. 证据与附件对象存储（本地 S3）
  minio:
    image: minio/minio:RELEASE.2023-09-07T02-05-02Z
    container_name: minio-thehive
    restart: unless-stopped
    networks:
      - soar-net
    command: server /data --console-address ":9001"
    environment:
      - MINIO_ROOT_USER=thehive-admin
      - MINIO_ROOT_PASSWORD=InitLabPasswordSecure123!
    volumes:
      - minio-data:/data

  # 4. 自动化分析与响应引擎（Cortex）
  cortex:
    image: thehiveproject/cortex:3.1.8-1
    container_name: cortex-engine
    restart: unless-stopped
    networks:
      - soar-net
    depends_on:
      - elasticsearch
    ports:
      - "9001:9001"
    environment:
      - "JAVA_OPTS=-Xms512m -Xmx512m"
    volumes:
      - cortex-data:/etc/cortex

  # 5. 安全案件响应与调查主平台（TheHive）
  thehive:
    image: thehiveproject/thehive:5.2.0-1
    container_name: thehive-app
    restart: unless-stopped
    networks:
      - soar-net
    depends_on:
      - cassandra
      - elasticsearch
      - minio
      - cortex
    ports:
      - "9000:9000"
    environment:
      - "JAVA_OPTS=-Xms1024m -Xmx1024m"
    volumes:
      - thehive-data:/etc/thehive
```

在后台启动集群：

```bash
docker compose up -d
```

查看初始化日志：

```bash
docker compose logs -f thehive
```

> **实操提示：** 首次运行时，Cassandra 和 Elasticsearch 通常需要 1 至 2 分钟初始化表结构与索引，TheHive 会在数据库就绪后正式开放 9000/TCP 端口。

---

## 4. 控制台访问与基础配置

当所有容器均正常就绪（`docker compose ps`）后，在 Windows 浏览器中访问：

### 访问 TheHive
1. 访问地址：`http://localhost:9000`
2. 初始登录凭据：
   - **用户名：** `admin@thehive.local`
   - **密码：** `secret`
3. 登录后按要求更新为高强度的实验室密码。

### 访问 Cortex
1. 访问地址：`http://localhost:9001`
2. 在数据库引导页面点击 **Update Database** 完成 Elasticsearch 表结构注册。
3. 创建初始管理员账户。

---

## 5. SOC 典型实战流程：从告警研判到结案处置

### 步骤 1：创建案件模板（Case Template）

规范化的 playbook 能够防止分析师在紧急响应中遗漏关键操作。在 TheHive 菜单中：
1. 进入 **Admin > Case Templates**。
2. 创建名为 **"案件：疑似用户凭证泄露"** 的模板。
3. 预置标准化处置任务：
   - `任务 1：验证登录日志（SigninLogs）与 MFA 状态`。
   - `任务 2：提取源 IP 地址并进行威胁情报研判`。
   - `任务 3：撤销活跃会话（Revoke-MgUserSignSession）`。
   - `任务 4：强制重置凭证`。

### 步骤 2：立案与关联调查

1. 基于上述模板快速建立调查案件：
   - **标题：** `SOC 告警：来自异常地理位置的登录活动`
   - **严重等级：** `Medium`
   - **TLP 分级：** `TLP:AMBER`
   - **PAP 分级：** `PAP:GREEN`

2. 添加收集到的可观察对象：
   - 类型 `ip`：`198.51.100.45`（RFC 5737 测试 IP）。
   - 类型 `user`：`usuario.suporte@contoso.com`。

### 步骤 3：利用 Cortex 联动分析器

在案件详情页中选中 IP 指标并点击 **Run Analyzer**：
- Cortex 将调用配置好的分析模块（如 AbuseIPDB 或本地 GeoIP 库）。
- 分析报告将在数秒内回传至案件页面，直观呈现归属国家、ASN 与恶意滥用评分。
- 若判定风险极高，分析师可将案件等级提升至 `High` 并立即执行会话撤销处置任务。

---

## 6. 后续演进：打通 Wazuh、TheHive 与 Shuffle 闭环

完成 TheHive 与 Cortex 的本地部署后，您已具备构建完整自动化防御体系的核心基石：

- **Wazuh 告警直接转案：** 利用 Wazuh 原生集成组件（`wazuh-integrator`）通过 REST API 将高危告警秒级推送到 TheHive。
- **结合 Shuffle 实现全面 SOAR 闭环：** 引入开源编排引擎 Shuffle，在 Wazuh 告警、TheHive 案件与本地防火墙之间执行自动化联动遏制。
- **运营效能度量：** 借助 TheHive 仪表板持续追踪 **MTTD（平均检出时间）** 与 **MTTR（平均响应时间）**，量化提升实战防护水平。

