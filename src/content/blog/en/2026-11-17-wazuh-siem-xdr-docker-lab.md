---
title: "SIEM and XDR with Wazuh: Local Deployment on Windows Enterprise via Docker"
description: "Step-by-step guide to deploying the Wazuh stack (Manager, Indexer, and Dashboard) on Windows Enterprise with Docker Desktop and WSL 2 for hands-on SOC testing."
date: 2026-11-17
categoria: SOC
tags: [wazuh, siem, xdr, docker, windows-enterprise, wsl2, lab, open-source, soc]
nivel: Intermediário
---

For SOC analysts, detection engineers, and incident responders, understanding how security telemetry is ingested, decoded, and correlated is just as critical as mastering commercial cloud platforms. In many enterprise settings, testing experimental detection rules, defense evasion techniques, or simulated attacks on production infrastructure is strictly prohibited.

Building a local **Wazuh** laboratory — the world's most widely adopted open-source platform combining **SIEM (Security Information and Event Management)** and **XDR (Extended Detection and Response)** — enables practitioners to analyze endpoint telemetry in real time, build custom detection rules, and investigate tactical alerts with zero cloud licensing costs and total data isolation.

> **Lab TL;DR:** To run the complete Wazuh stack (Manager, Indexer, and Dashboard) on Windows Enterprise using Docker, configure WSL 2 with at least 6 GB of RAM and increase the Linux kernel parameter `vm.max_map_count` to `262144` to ensure the OpenSearch search engine initializes properly.

> 📘 **Official References:** This guide follows official Wazuh documentation standards:
> - [Wazuh Documentation — Deployment with Docker](https://documentation.wazuh.com/current/deployment-options/docker/index.html)
> - [Wazuh Agent installation on Windows endpoints](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html)

---

## 1. Why Run Wazuh Locally on Enterprise Workstations?

In enterprise environments powered by Windows 10/11 Enterprise, security workstations frequently feature multi-core CPUs and between 16 GB and 32 GB of RAM. Utilizing Docker Desktop backed by WSL 2 delivers distinct operational advantages:

1. **Complete Data Sovereignty & Local Isolation:** All telemetry, alert payloads, and forensic artifacts remain strictly on your local host (localhost).
2. **Unified SIEM and XDR Lifecycle:** Wazuh integrates centralized log analysis, file integrity monitoring (FIM), vulnerability detection, and automated active response into a single pane of glass.
3. **Native MITRE ATT&CK Mapping:** Every detection rule in Wazuh is pre-mapped to corresponding MITRE ATT&CK tactics and techniques.

---

## 2. Essential WSL 2 Tuning on Windows Enterprise

Because the Wazuh Indexer is built on OpenSearch, specific memory allocation and kernel parameters must be adjusted in WSL 2 to prevent out-of-memory (OOM) container crashes.

### Step 1: Configure memory in `.wslconfig`
On your Windows host, open your user-profile WSL 2 configuration file via PowerShell:

```powershell
notepad "$env:USERPROFILE\.wslconfig"
```

Apply recommended resource limits:

```ini
[wsl2]
memory=6GB            # Recommended minimum for single-node Wazuh stack
processors=4          # Allocate 4 virtual CPU cores
swap=2GB              # Disk swap partition
localhostForwarding=true
```

### Step 2: Tune `vm.max_map_count` in WSL 2
OpenSearch requires at least 262,144 memory-mapped areas. In your WSL 2 terminal or via PowerShell, execute:

```powershell
wsl -d Ubuntu -u root sysctl -w vm.max_map_count=262144
```

To make this setting persistent across reboots, append the parameter to `/etc/sysctl.conf`:

```bash
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

Restart WSL 2 to apply changes:

```powershell
wsl --shutdown
```

---

## 3. Deploying the Single-Node Wazuh Stack with Docker Compose

The official Wazuh repository provides a tested single-node Docker Compose blueprint ideal for local research workstations.

1. Clone the repository in your WSL 2 environment:
   ```bash
   git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.2 --depth=1
   cd wazuh-docker/single-node
   ```

2. Generate internal TLS certificates required for encrypted communication between services:
   ```bash
   docker compose -f generate-indexer-certs.yml run --rm generator
   ```

3. Launch the core stack in detached mode:
   ```bash
   docker compose up -d
   ```

4. Confirm container health:
   ```bash
   docker compose ps
   ```

The running services include:
- **`single-node-wazuh.manager-1`:** Analysis engine, rule processor, and agent communications (ports 1514/TCP, 1515/TCP, and 55000/TCP).
- **`single-node-wazuh.indexer-1`:** OpenSearch analytics and storage engine (port 9200/TCP).
- **`single-node-wazuh.dashboard-1`:** Web management and threat hunting interface (port 443/TCP).

---

## 4. Accessing the Dashboard and Enrolling the Windows Agent

After approximately 2 minutes for cluster initialization:

1. Open your browser on Windows and navigate to:
   ```text
   https://localhost
   ```
2. Acknowledge the self-signed certificate warning for the local lab.
3. Sign in using the default compose credentials:
   - **Username:** `admin`
   - **Password:** `SecretPassword***` (can be configured in the `.env` file prior to launch).

### Installing the Wazuh Agent on the Windows Host

To start ingesting live Windows telemetry into your local cluster:

1. Download the official Wazuh Agent MSI installer (v4.9+).
2. Open PowerShell as Administrator and run the silent installation targeting localhost:
   ```powershell
   .\wazuh-agent-4.9.2-1.msi /q WAZUH_MANAGER="127.0.0.1" WAZUH_REGISTRATION_SERVER="127.0.0.1" WAZUH_AGENT_NAME="WIN-LAB-ENTERPRISE"
   ```
3. Start the agent service:
   ```powershell
   NET START WazuhSvc
   ```
4. In the Wazuh Dashboard under **Endpoints Summary**, the host will appear with an **Active** status within seconds.

---

## 5. Practical SOC Detection Simulation: Catching Suspicious Commands

With the agent actively streaming Windows security telemetry (*Security Event Log* and *Sysmon*):

1. **Simulation:** Open a command prompt on Windows and execute typical adversary reconnaissance commands:
   ```cmd
   net user Administrator
   net localgroup Administrators
   ```
2. **Dashboard Verification:**
   - Navigate to **Wazuh Dashboard > Security events**.
   - In the search bar, filter using Lucene syntax:
     ```lucene
     agent.name: "WIN-LAB-ENTERPRISE" AND rule.level: >= 3
     ```
   - Wazuh automatically correlates Windows audit events (Event IDs 4798 and 4799 — Local Group Enumeration) to MITRE ATT&CK technique **T1087 (Account Discovery)**.

3. **Writing a Custom Detection Rule:**
   Inside the manager container (`/var/ossec/etc/rules/local_rules.xml`), analysts can craft tailored rules. For instance, to flag privilege enumeration using `whoami /priv`:
   ```xml
   <group name="windows,powershell,">
     <rule id="100002" level="7">
       <if_sid>60103</if_sid>
       <field name="win.eventdata.commandLine">whoami /priv</field>
       <description>Local privilege enumeration attempt detected: whoami /priv</description>
       <mitre>
         <id>T1033</id>
       </mitre>
     </rule>
   </group>
   ```

---

## 6. Next Steps for Your Open Security Lab

With Wazuh running smoothly on Docker Desktop, your local SIEM/XDR foundation is ready to:
- Ingest logs from other containerized services (such as the Keycloak lab built previously).
- Test automated SOAR playbooks with **Shuffle** and **TheHive**.
- Simulate control bypass techniques and refine custom detection engineering safely.
