---
title: "SOAR with TheHive and Cortex: Incident Response Lab in Docker"
description: "Comprehensive guide to deploying TheHive and Cortex on Windows Enterprise using Docker and WSL 2 for incident triage, case management, and SOC automation."
date: 2026-11-18
categoria: SOC
tags: [thehive, cortex, soar, docker, windows-enterprise, wsl2, lab, open-source, soc]
nivel: Intermediário
---

In the daily routine of a Security Operations Center (SOC), detecting a threat through a SIEM (such as Wazuh or Microsoft Sentinel) is merely the initial phase of defense. The subsequent stage — triaging alerts, qualifying Indicators of Compromise (IoCs), tracking investigation timelines, coordinating tasks among analysts, and triggering containment actions — demands a dedicated Security Incident Response Platform (**SIRP**) combined with Security Orchestration, Automation, and Response (**SOAR**) capabilities.

Across the open-source and sovereign infrastructure landscape, the pairing of **TheHive** (security incident and case management platform) and **Cortex** (observable analysis and active response engine) stands as the definitive industry standard.

In this practical walkthrough, you will learn how to architect and deploy a complete TheHive and Cortex laboratory on Windows Enterprise using Docker Desktop and WSL 2. This setup empowers you to test incident response playbooks, automate observable enrichment, and structure security governance in an isolated, 100% local environment.

> **Lab TL;DR:** When running the cluster composed of TheHive, Cortex, Cassandra, Elasticsearch, and MinIO on Windows Enterprise via WSL 2, allocate at least 6 GB to 8 GB of RAM in `.wslconfig` and utilize Docker Compose bridge networking for reliable inter-container communication.

> 📘 **Official References:** This guide is built upon the official documentation of the TheHive and Cortex projects:
> - [TheHive Project Documentation (StrangeBee)](https://docs.strangebee.com/)
> - [TheHive GitHub Repository](https://github.com/TheHive-Project/TheHive)
> - [Cortex Project Documentation](https://github.com/TheHive-Project/Cortex)

---

## 1. Why Integrate TheHive and Cortex in SOC Operations?

Within incident response teams (CSIRT/CERT) and enterprise SOCs, standard IT ticketing systems fail to deliver the domain-specific tooling required for cyber investigations. TheHive and Cortex offer capabilities designed specifically for defensive operations:

1. **Threat-Centric Case Management:** Every case aggregates alerts, an immutable chronological timeline, structured task trees, and an organized observable catalog (IP addresses, file hashes, domains, URLs, and user accounts).
2. **Automated Threat Intelligence via Cortex:** Cortex provides dozens of modular analyzers that query threat intelligence platforms (such as VirusTotal, AbuseIPDB, Shodan, and MISP) either manually or automatically through webhooks.
3. **Consistency Through Case Templates:** Define standardized playbooks for high-frequency incidents (e.g., phishing campaigns, ransomware outbreaks, credential compromise) ensuring every analyst follows uniform containment and eradication procedures.
4. **Data Sovereignty and Isolation:** For environments governed by strict compliance frameworks (LGPD/GDPR), investigative forensics and telemetry remain strictly on-premises under organizational custody.

---

## 2. Windows Enterprise & WSL 2 Prerequisites

The TheHive stack is resilient and relies on a distributed NoSQL database (Apache Cassandra), an indexing engine (Elasticsearch), and an S3-compatible object store (MinIO) for storing case evidence and attachments.

### Step 1: Configure Memory in `.wslconfig`

From an elevated PowerShell prompt, edit your global WSL 2 configuration file:

```powershell
notepad "$env:USERPROFILE\.wslconfig"
```

Allocate sufficient compute and memory resources:

```ini
[wsl2]
memory=8GB            # Recommended for TheHive, Cortex, Cassandra, and Elasticsearch
processors=4          # 4 virtual CPU cores
swap=4GB              # Disk swap allocation
localhostForwarding=true
```

### Step 2: Configure Virtual Memory Limits for Elasticsearch

Elasticsearch requires an elevated memory-mapped area count in the Linux kernel:

```powershell
wsl -d Ubuntu -u root sysctl -w vm.max_map_count=262144
```

Persist the setting by adding it to `/etc/sysctl.conf` inside WSL 2:

```bash
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

Restart WSL 2 via PowerShell to apply the changes:

```powershell
wsl --shutdown
```

---

## 3. Laboratory Architecture with Docker Compose

Create a dedicated workspace directory in your WSL 2 or PowerShell terminal:

```bash
mkdir -p ~/thehive-lab && cd ~/thehive-lab
```

Create the `docker-compose.yml` file:

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
  # 1. NoSQL Database for Metadata and Timeline
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

  # 2. Fast Search and Indexing Engine
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

  # 3. Object Storage for Case Attachments and Forensics (Local S3)
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

  # 4. Observable Analysis and Active Response Engine (Cortex)
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

  # 5. Security Incident Response Platform (TheHive)
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

Launch the cluster in the background:

```bash
docker compose up -d
```

Monitor initial service provisioning:

```bash
docker compose logs -f thehive
```

> **Operational Note:** During the first startup, Cassandra and Elasticsearch require 1 to 2 minutes to provision schemas and initialize indices. TheHive waits for database readiness before binding port 9000/TCP.

---

## 4. Console Access and Initial Configuration

Once containers report healthy status (`docker compose ps`), launch your browser on Windows:

### TheHive Web Interface
1. Navigate to: `http://localhost:9000`
2. Default initial credentials:
   - **Username:** `admin@thehive.local`
   - **Password:** `secret`
3. Update default credentials upon initial login.

### Cortex Web Interface
1. Navigate to: `http://localhost:9001`
2. On the database setup page, click **Update Database** to apply Elasticsearch schemas.
3. Create your administrative Cortex user.

---

## 5. Practical SOC Workflow: From Triage to Resolution

### Step 1: Create a Case Template

Structured playbooks prevent analysts from skipping critical actions during emergency investigations. Under TheHive's administration menu:
1. Navigate to **Admin > Case Templates**.
2. Create a template named **"Incident: Suspected Account Compromise"**.
3. Add standard response tasks:
   - `Task 1: Verify authentication logs (SigninLogs) and MFA status`.
   - `Task 2: Identify source IP and query reputation`.
   - `Task 3: Revoke active user sessions (Revoke-MgUserSignSession)`.
   - `Task 4: Enforce credential reset`.

### Step 2: Open and Investigate an Incident

1. Open a new case based on the template:
   - **Title:** `SOC Alert: Suspicious sign-in from anomalous IP`
   - **Severity:** `Medium`
   - **TLP:** `TLP:AMBER`
   - **PAP:** `PAP:GREEN`

2. Populate incident observables:
   - Type `ip`: `198.51.100.45` (RFC 5737 documentation address).
   - Type `user`: `usuario.suporte@contoso.com`.

### Step 3: Run Threat Intelligence Analyzers via Cortex

Within the case observable view, select the IP address and click **Run Analyzer**:
- Cortex executes configured lookups (e.g., AbuseIPDB, VirusTotal, or local GeoIP databases).
- Within seconds, a tactical report is appended directly to the case timeline displaying country of origin, autonomous system number (ASN), and abuse confidence score.
- If high risk is confirmed, escalate case severity to `High` and execute session revocation containment.

---

## 6. Next Steps: Unifying Wazuh, TheHive, and Shuffle

With TheHive and Cortex operational in your local Docker environment, you have established the core foundation for end-to-end security automation:

- **Direct Ingestion from Wazuh:** Configure `wazuh-integrator` to push high-severity alerts directly into TheHive via REST APIs.
- **Full-Stack SOAR with Shuffle:** Introduce Shuffle to orchestrate actions between Wazuh alerts, TheHive cases, and network firewalls to automatically isolate compromised hosts.
- **SOC Metrics and KPIs:** Utilize native TheHive dashboards to monitor vital operational indicators including **MTTD (Mean Time to Detect)** and **MTTR (Mean Time to Respond)**.

