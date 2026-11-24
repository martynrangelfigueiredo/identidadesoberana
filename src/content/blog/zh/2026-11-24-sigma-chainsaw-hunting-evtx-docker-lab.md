---
title: "在 WSL2 本地实验室中使用 Sigma 与 Chainsaw：快速搜寻 Windows Enterprise EVTX 日志"
description: "在 Windows Enterprise 的 WSL2 与 Docker 环境中本地运行 Sigma 规则和 Chainsaw，离线高速分析 EVTX 取证日志。"
date: 2026-11-24
categoria: SOC
tags: [sigma, chainsaw, evtx, detection-as-code, docker, wsl2, open-source, soc]
nivel: Intermediário
draft: false
---

> **TL;DR：** 在对 Windows 终端开展应急响应时，攻击发生时的完整日志未必已经实时同步到 SIEM。本文演示如何在 Windows Enterprise 的 WSL2 本地实验室中结合开源 **Sigma** 规则与 **Chainsaw**，在数秒内离线扫描 `.evtx` 日志，快速发现持久化、横向移动与防御 *绕过 (Bypass)* 痕迹。

---

## 1. 为什么在 SOC 实验室中结合 Sigma 与 Chainsaw？

**Sigma** 是业界通用的开源 *Detection as Code*（检测即代码）YAML 格式，用于以厂商无关的方式描述威胁检测规则。**Chainsaw**（由 WithSecure Labs 基于 Rust 开发）则无需搭建完整 SIEM，即可直接在本地磁盘上的 Windows 事件日志（`.evtx`）中批量匹配数百条 Sigma 规则。

在 **WSL2**（或完全断网隔离的 Docker 容器）中本地执行该流程具有显著优势：
- 极速完成 `Security.evtx`、`Microsoft-Windows-PowerShell%4Operational.evtx` 与 `Sysmon.evtx` 的取证初筛。
- 检测规则可无缝复用于生产环境（Wazuh、Elastic 或通过工具转换为 Microsoft Sentinel 的 KQL 查询）。
- 隐私与数据安全可控：所有事件日志始终保留在本地磁盘。

---

## 2. 前置条件与实验环境架构

| 组件 | 最低要求 | 说明 |
|---|---|---|
| **宿主机系统** | Windows 10/11 Enterprise + WSL2 | 建议在 WSL2 中更新 Ubuntu 22.04/24.04。 |
| **分析引擎** | Chainsaw（Linux 二进制或 Docker 容器） | Rust 编写，内存占用极低。 |
| **规则库** | 官方 `SigmaHQ/sigma` 仓库 | 开源 YAML 规则，完整映射 MITRE ATT&CK。 |

---

## 3. 在 WSL2 与 Docker 中搭建离线分析环境

在 WSL2 中创建专用目录，用于存放 Sigma 规则与从测试终端导出的 `.evtx` 文件：

```bash
mkdir -p ~/dfir-labs/chainsaw/evtx ~/dfir-labs/chainsaw/rules
cd ~/dfir-labs/chainsaw
```

拉取官方 Sigma 规则库（或挂载经过审核的离线规则目录）：

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma.git rules/sigma
```

若希望在无宿主机依赖的一次性容器中运行 Chainsaw，可编写一个精简的 `Dockerfile`：

```dockerfile
FROM rust:1.82-slim AS builder
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
RUN cargo install chainsaw

FROM debian:bookworm-slim
COPY --from=builder /usr/local/cargo/bin/chainsaw /usr/local/bin/chainsaw
WORKDIR /workspace
ENTRYPOINT ["chainsaw"]
```

在本地构建镜像：

```bash
docker build -t local/chainsaw:latest .
```

---

## 4. 复制测试 EVTX 日志并执行搜寻

在 Windows Enterprise 测试环境中，通过管理员 PowerShell 将事件日志复制到 WSL2 目录：

```powershell
Copy-Item "C:\Windows\System32\Winevt\Logs\Security.evtx" "\\wsl$\Ubuntu\home\$env:USERNAME\dfir-labs\chainsaw\evtx\"
Copy-Item "C:\Windows\System32\Winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx" "\\wsl$\Ubuntu\home\$env:USERNAME\dfir-labs\chainsaw\evtx\"
```

随后在完全断网（`--network none`）模式下使用 Windows Sigma 规则扫描 `.evtx`：

```bash
docker run --rm --network none \
  -v ~/dfir-labs/chainsaw/evtx:/evtx:ro \
  -v ~/dfir-labs/chainsaw/rules/sigma:/sigma:ro \
  local/chainsaw:latest hunt /evtx \
  -s /sigma/rules/windows \
  --mapping /sigma/tools/config/generic/windows-audit.yml \
  --json --output /evtx/findings.json
```

> **操作提示：** 如果想在终端直接查看可读表格而非导出 JSON，只需去掉 `--json --output ...` 参数，Chainsaw 便会按时间顺序输出触发的规则、Event ID 以及 `CommandLine` 或 `TargetUserName`。

---

## 5. 自定义 Sigma 规则示例：检测指向临时目录的计划任务

你可以在 `~/dfir-labs/chainsaw/rules/custom/` 中编写自定义 YAML 规则，检测利用 `schtasks.exe` 建立持久化（`MITRE ATT&CK T1053.005`）：

```yaml
title: Scheduled Task Creation Pointing to Temp Directory
id: 7b4e1a20-8f12-4c9a-9c2e-11a2b3c4d5e6
status: experimental
description: Detects schtasks creating tasks that execute binaries inside AppData or Temp.
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith: '\schtasks.exe'
  selection_cmd:
    CommandLine|contains|all:
      - '/create'
    CommandLine|contains:
      - '\AppData\'
      - '\Users\Public\'
      - '\Temp\'
  condition: selection_img and selection_cmd
level: high
tags:
  - attack.persistence
  - attack.t1053.005
```

同一份 YAML 规则后续也可使用 `sigma-cli` 直接转换为 Wazuh 规则或 Microsoft Sentinel 的 KQL 查询。

---

## 6. 安全控制映射与最佳实践

| 标准框架 | 条款编号 | 实践落地 |
|---|---|---|
| **MITRE ATT&CK** | `T1053.005` / `T1059.001` | 标准化检测异常计划任务与混淆 PowerShell 执行。 |
| **NIST SP 800-86** | *Guide to Integrating Forensic Techniques into Incident Response* | 在 DFIR 初筛阶段对操作系统事件日志开展结构化取证分析。 |
| **CIS Controls v8** | `8.2` / `8.5` | 采集并深度审计 Windows 进程创建与安全审计日志。 |

---

## 参考资料

- [Microsoft Learn — Install WSL 2 on Windows Enterprise](https://learn.microsoft.com/en-us/windows/wsl/install)
- [Microsoft Learn — Advanced security auditing in Windows](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing-faq)
- [SigmaHQ — Sigma Generic Signature Format](https://sigmahq.io/)
- [WithSecure Labs — Chainsaw EVTX Hunting Tool](https://github.com/WithSecureLabs/chainsaw)

