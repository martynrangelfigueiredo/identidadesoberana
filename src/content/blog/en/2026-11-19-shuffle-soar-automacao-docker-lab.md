---
title: "SOC Automation with Shuffle SOAR: Integrating Wazuh and TheHive in Docker"
description: "Practical guide to deploying Shuffle SOAR on Windows Enterprise with Docker and WSL 2 to build automated workflows between Wazuh SIEM and TheHive."
date: 2026-11-19
categoria: SOC
tags: [shuffle, soar, wazuh, thehive, docker, windows-enterprise, wsl2, lab, open-source, soc]
nivel: Intermediário
---

In our previous lab guides, we established the core pillars of an open-source security stack: identity management with **Keycloak**, endpoint detection with **Wazuh (SIEM/XDR)**, and incident case management with **TheHive and Cortex**. However, as alert volume grows, manually triaging events and copying Indicators of Compromise (IoCs) across consoles consumes valuable analyst time.

**Shuffle** bridges that gap as an open-source **SOAR (Security Orchestration, Automation, and Response)** platform. It connects security tools via REST APIs, webhooks, and visual workflows without proprietary licensing or sending telemetry to external clouds.

In this hands-on walkthrough, you will deploy Shuffle on Windows Enterprise using Docker Desktop and WSL 2, and build your first automation workflow that ingests Wazuh alerts and automatically creates enriched cases in TheHive.

> **Lab TL;DR:** Shuffle relies on OpenSearch to store workflow executions and app metadata. On Windows Enterprise via WSL 2, ensure `vm.max_map_count` is set to `262144` and allocate at least 6 GB of RAM in `.wslconfig` before starting the Docker Compose stack.

> 📘 **Official References:** This guide is based on the official documentation of Shuffle, Wazuh, and TheHive:
> - [Shuffle Documentation (shuffler.io)](https://shuffler.io/docs/about)
> - [Shuffle GitHub Repository](https://github.com/Shuffle/Shuffle)
> - [Wazuh Documentation — Integrator](https://documentation.wazuh.com/current/user-manual/manager/manual-integration.html)

---

## 1. Shuffle's Role in an Open SOC Architecture

Shuffle acts as the automation nervous system connecting defensive tools through visual playbooks:

1. **OpenAPI/Swagger-Driven Orchestration:** Import OpenAPI specifications for nearly any tool (Wazuh, TheHive, Cortex, Keycloak, firewalls, or Jira) to convert endpoints into drag-and-drop workflow actions.
2. **Webhook and Scheduled Triggers:** Receive real-time alerts via HTTP POST the moment a critical SIEM rule fires, or schedule recurring threat-hunting jobs.
3. **Isolated Container Execution (Orborus & Workers):** Each workflow action runs inside isolated containers, maintaining strict control over credentials, secrets, and internal network traffic.

---

## 2. Prerequisites on Windows Enterprise and WSL 2

Like Wazuh and TheHive, Shuffle uses **OpenSearch** under the hood. If you configured `.wslconfig` and `vm.max_map_count` in previous labs, those settings are already in place. Otherwise, verify in PowerShell:

```powershell
wsl -d Ubuntu -u root sysctl -w vm.max_map_count=262144
```

Ensure Docker Desktop has WSL 2 integration enabled and at least **6 GB of available RAM**.

---

## 3. Deploying Shuffle SOAR with Docker Compose

The official Shuffle repository includes a complete `docker-compose.yml` orchestrating **shuffle-frontend**, **shuffle-backend**, **shuffle-orborus**, and **shuffle-opensearch**.

1. In your WSL 2 terminal, create a workspace and clone the official repository:
   ```bash
   mkdir -p ~/shuffle-lab && cd ~/shuffle-lab
   git clone https://github.com/Shuffle/Shuffle.git --depth=1
   cd Shuffle
   ```

2. Create the OpenSearch database directory with proper ownership to avoid permission errors:
   ```bash
   mkdir -p shuffle-database
   sudo chown -R 1000:1000 shuffle-database
   ```

3. Review `.env` to ensure the web UI ports (`FRONTEND_PORT=3001` and `FRONTEND_PORT_HTTPS=3443`) do not conflict with other local services (such as TheHive on `9000` or Wazuh on `443`).

4. Start the containers in detached mode:
   ```bash
   docker compose up -d
   ```

5. Verify container health:
   ```bash
   docker compose ps
   ```

---

## 4. Initial Access and Administrator Setup

After roughly 60 seconds for OpenSearch initialization:

1. Open your browser on Windows and navigate to:
   ```text
   https://localhost:3443
   ```
   *(Accept the self-signed lab certificate; alternatively, use HTTP at `http://localhost:3001`).*

2. Create the initial administrator account (e.g., `soc-admin@contoso.com`) with a strong lab password.

3. Once logged in, navigate to **Workflows** in the top menu.

---

## 5. Building Your First Playbook: Wazuh → Shuffle → TheHive

Let's build a tactical incident response workflow: whenever **Wazuh** triggers a high-severity alert (`rule.level >= 10`), it forwards the JSON payload to **Shuffle**, which extracts the source IP and automatically opens a case in **TheHive**.

### Step 1: Create the Webhook Trigger in Shuffle
1. Under **Workflows > New Workflow**, name your flow `Wazuh-Auto-Triage-TheHive`.
2. Drag a **Webhook** trigger onto the canvas.
3. Copy the generated local Webhook URL (e.g., `http://localhost:5001/api/v1/hooks/webhook_...`).
4. Click **Start** on the Webhook node to put it in listening mode.

### Step 2: Configure Wazuh to Forward Alerts to Shuffle
In the Wazuh Manager configuration (`/var/ossec/etc/ossec.conf`), add an `<integration>` block pointing to Shuffle's Webhook URL:

```xml
<integration>
  <name>custom-shuffle</name>
  <hook_url>http://host.docker.internal:5001/api/v1/hooks/webhook_your_id_here</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

Restart the Wazuh Manager to enable real-time JSON alert forwarding.

### Step 3: Extract the IP and Create a Case in TheHive
1. In Shuffle's visual editor, connect the **Webhook** node to the built-in **TheHive** app.
2. Authenticate the **TheHive** app using an API key from your TheHive container (`http://host.docker.internal:9000`), storing it securely as an encrypted *secret* in Shuffle's authentication settings.
3. Select the **`Create Case`** action and map the incoming Webhook JSON fields:
   - **Title:** `[Wazuh] $exec.all_fields.rule.description`
   - **Severity:** `2` (Medium)
   - **Description:** `Agent: $exec.all_fields.agent.name | Source IP: $exec.all_fields.data.srcip`
   - **Tags:** `["wazuh", "auto-triage", "shuffle"]`
4. Chain a second TheHive node with **`Create Observable`** to automatically attach `$exec.all_fields.data.srcip` as an `ip` observable inside the newly created case.

---

## 6. Security Best Practices and Next Steps

When operating automated SOAR playbooks in a lab or production environment:

- **Protect Secrets:** Never hardcode API keys in plaintext inside code blocks or raw HTTP requests; always use Shuffle's native encrypted secret store.
- **Loop & Deduplication Control:** Before creating a new TheHive case, add a conditional branch checking whether an open case already exists for the same IP or user within the last 24 hours to prevent ticket floods.
- **Workflow Expansion:** Chain the **Cortex** app immediately after observable creation to trigger threat intelligence analyzers automatically and alert the SOC team only when high risk is confirmed.

