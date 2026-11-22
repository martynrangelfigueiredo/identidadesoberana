---
title: "在 Docker 与 WSL2 中搭建本地 Velociraptor 实验环境：Windows 终端 DFIR 与威胁搜寻指南"
description: "在 Windows Enterprise 的 WSL2 上使用 Docker 本地部署 Velociraptor，并对终端执行 VQL 数字取证与威胁搜寻。"
date: 2026-11-22
categoria: SOC
tags: [velociraptor, dfir, threat-hunting, docker, wsl2, open-source, soc]
nivel: Intermediário
draft: false
---

> **TL;DR：** 当安全告警需要立即排查内存、Windows 注册表或实时进程状态时，仅靠传统日志往往远远不够。本文演示如何在 Windows Enterprise 的 WSL2 中使用 Docker 本地隔离部署 **Velociraptor**，并在几分钟内执行 VQL（*Velociraptor Query Language*）取证采集。

---

## 1. 为什么在 SOC 实验室中引入 Velociraptor？

**Velociraptor** 是一款开源的 **DFIR**（数字取证与应急响应）及 **Threat Hunting** 平台。当 Wazuh 等 SIEM 负责持续收集日志时，Velociraptor 能够按需直接深入 Windows 终端采集高价值取证指标——包括自启动持久化项（`Run`/`RunOnce`）、活跃网络连接、计划任务、Prefetch 以及 `EVTX` 事件日志。

通过 WSL2 中的 Docker 在**本地回环隔离环境**（`127.0.0.1`）运行服务端具有以下优势：
- 安全编写并测试自定义 VQL 取证工件，不影响生产终端。
- 配合 Shuffle *Playbook* 或 TheHive 工单实现自动化远程取证。
- 通过本地 Web 控制台即可快速演练 Windows Enterprise 终端的应急分诊。

---

## 2. 前置条件与实验环境架构

| 组件 | 最低要求 | 说明 |
|---|---|---|
| **宿主机系统** | Windows 10/11 Enterprise + WSL2 | 开启硬件虚拟化并更新 Ubuntu WSL2 发行版。 |
| **容器引擎** | Docker Desktop 或 WSL2 中的 Docker Engine | 确保启用 Compose v2 (`docker compose version`)。 |
| **本地端口** | `127.0.0.1:8889` (Web GUI) 与 `127.0.0.1:8000` (客户端通信) | 严格绑定本地回环接口，避免暴露到局域网。 |

---

## 3. 使用 Docker Compose 启动 Velociraptor

在 WSL2 中创建工作目录（如 `~/soc-labs/velociraptor`），并将 *Secret* 存放在本地 `.env` 文件中：

```bash
mkdir -p ~/soc-labs/velociraptor/config ~/soc-labs/velociraptor/datastore
```

`.env` 示例：

```env
VELO_ADMIN_USER=soc-admin
VELO_ADMIN_PASSWORD=请替换为高强度实验_SECRET
```

编写 `compose.yml`，端口仅绑定 `127.0.0.1`：

```yaml
services:
  velociraptor:
    image: wlambert/velociraptor:latest
    container_name: velociraptor-lab
    restart: unless-stopped
    ports:
      - "127.0.0.1:8889:8889"
      - "127.0.0.1:8000:8000"
    volumes:
      - ./config:/velociraptor
      - ./datastore:/opt/velociraptor/datastore
    environment:
      - VELOX_USER=${VELO_ADMIN_USER}
      - VELOX_PASSWORD=${VELO_ADMIN_PASSWORD}
```

> **操作提示：** 如需使用官方二进制手动生成 `server.config.yaml`，可在 WSL2 运行 `velociraptor config generate -i`，将 `Client.server_urls` 设为 `https://127.0.0.1:8000/` 并挂载到 `/velociraptor/server.config.yaml`。

启动容器：

```bash
cd ~/soc-labs/velociraptor
docker compose up -d
docker compose logs -f velociraptor
```

在浏览器访问 `https://127.0.0.1:8889`（接受实验室自签名证书），使用 `.env` 中的管理员凭据登录。

---

## 4. 接入测试用 Windows Enterprise 终端

在当前 Windows 主机或实验虚拟机上测试真实取证采集：

1. 通过 Web 界面或 CLI 导出客户端配置文件：
   ```bash
   docker exec velociraptor-lab velociraptor --config /velociraptor/server.config.yaml config client > client.config.yaml
   ```
2. 从官方 GitHub Releases 下载 Windows 版可执行文件（`velociraptor-vX.X.X-windows-amd64.exe`）。
3. 在 PowerShell 中指定配置文件启动本地测试代理：
   ```powershell
   .\velociraptor-windows-amd64.exe --config .\client.config.yaml client -v
   ```
4. 数秒后，该终端将在 Web 界面的 **Search Clients** 中显示为 **Online**。

---

## 5. 使用 VQL 快速搜寻异常进程与持久化

点击在线客户端进入控制台，打开 **Collected > Collect new artifact** 或新建 **VQL Notebook**，排查从非常规路径运行的进程：

```sql
SELECT Pid, Ppid, Name, Exe, CommandLine
FROM pslist()
WHERE Exe =~ "(?i)(Users\\\\Public|AppData\\\\Local\\\\Temp|ProgramData)"
```

同时可直接调用内置取证工件：
- **`Windows.Sys.StartupItems`**：枚举开机启动项及 `Run`/`RunOnce` 注册表键值。
- **`Windows.Network.NetstatEnriched`**：将活跃 TCP/UDP 连接关联至具体进程（`Pid` 与 `Name`）。
- **`Windows.Detection.Amcache`**：检查终端近期执行过的二进制文件记录。

---

## 6. 安全控制映射与最佳实践

| 标准框架 | 条款编号 | 实践落地 |
|---|---|---|
| **NIST SP 800-86** | *Guide to Integrating Forensic Techniques into Incident Response* | 规范化采集终端易失性与非易失性取证工件。 |
| **NIST CSF** | `DE.AE-02` / `RS.AN-01` | 对异常安全事件开展主机级深度取证分析。 |
| **ISO/IEC 27001:2022** | `A.5.28` (*Collection of Evidence*) | 安全事件期间电子证据的识别、采集与保全。 |

---

## 参考资料

- [Velociraptor — Official Documentation & VQL Reference](https://docs.velociraptor.app/)
- [Microsoft Learn — Install WSL 2 on Windows Enterprise](https://learn.microsoft.com/en-us/windows/wsl/install)
- [NIST SP 800-86 — Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final)

