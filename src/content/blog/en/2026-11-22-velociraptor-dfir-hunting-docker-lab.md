---
title: "Velociraptor in a Local Docker & WSL2 Lab: DFIR and Threat Hunting on Windows Endpoints"
description: "Practical guide to deploy Velociraptor locally via Docker on WSL2 and run forensic VQL collections on Windows Enterprise endpoints."
date: 2026-11-22
categoria: SOC
tags: [velociraptor, dfir, threat-hunting, docker, wsl2, open-source, soc]
nivel: Intermediário
draft: false
---

> **TL;DR:** When an alert demands fast inspection of memory, Windows Registry keys, or active processes, relying solely on traditional logs limits your visibility. This guide shows how to deploy **Velociraptor** in an isolated Docker & WSL2 lab on Windows Enterprise and run VQL (*Velociraptor Query Language*) collections in minutes.

---

## 1. Why add Velociraptor to your SOC lab?

**Velociraptor** is an open-source platform built for **DFIR** (*Digital Forensics and Incident Response*) and **Threat Hunting** at scale. While a SIEM like Wazuh centralizes continuous event streams, Velociraptor lets analysts query live Windows artifacts on demand — including persistence keys (`Run`/`RunOnce`), active network sockets, scheduled tasks, prefetch, and `EVTX` logs.

Running the server in **local isolation** (`127.0.0.1`) via Docker on WSL2 enables you to:
- Author and test custom VQL artifacts without touching production endpoints.
- Trigger automated forensic collections from Shuffle *playbooks* or TheHive cases.
- Practice rapid endpoint triage on Windows Enterprise using a local web console.

---

## 2. Prerequisites and Lab Architecture

| Component | Minimum Requirement | Notes |
|---|---|---|
| **Host OS** | Windows 10/11 Enterprise with WSL2 | Hardware virtualization enabled; updated Ubuntu WSL2 distro. |
| **Container Engine** | Docker Desktop or Docker Engine on WSL2 | Compose v2 enabled (`docker compose version`). |
| **Local Ports** | `127.0.0.1:8889` (GUI) and `127.0.0.1:8000` (Frontend/Agent) | Bound exclusively to loopback to prevent LAN exposure. |

---

## 3. Deploying Velociraptor with Docker Compose

Create a dedicated directory in WSL2 (e.g., `~/soc-labs/velociraptor`) and keep *secrets* in a local `.env` file:

```bash
mkdir -p ~/soc-labs/velociraptor/config ~/soc-labs/velociraptor/datastore
```

Sample `.env` file:

```env
VELO_ADMIN_USER=soc-admin
VELO_ADMIN_PASSWORD=REPLACE_WITH_STRONG_LAB_SECRET
```

Create `compose.yml` bound strictly to `127.0.0.1`:

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

> **Operational tip:** If you prefer generating `server.config.yaml` manually with the official Velociraptor binary, run `velociraptor config generate -i` in WSL2, set `Client.server_urls` to `https://127.0.0.1:8000/`, and mount it at `/velociraptor/server.config.yaml`.

Start the container:

```bash
cd ~/soc-labs/velociraptor
docker compose up -d
docker compose logs -f velociraptor
```

Open `https://127.0.0.1:8889` in your browser (accepting the self-signed lab certificate) and sign in with the credentials from `.env`.

---

## 4. Connecting a Test Windows Enterprise Endpoint

To test live forensic collections on the same Windows host or a lab VM:

1. Generate the client configuration via GUI or CLI:
   ```bash
   docker exec velociraptor-lab velociraptor --config /velociraptor/server.config.yaml config client > client.config.yaml
   ```
2. Download the official Windows executable (`velociraptor-vX.X.X-windows-amd64.exe`) from the official GitHub releases.
3. Run the agent in PowerShell pointing to the generated config:
   ```powershell
   .\velociraptor-windows-amd64.exe --config .\client.config.yaml client -v
   ```
4. Within seconds, the endpoint appears as **Online** under **Search Clients**.

---

## 5. Running a Quick VQL Hunt (Persistence & Processes)

Select the client ID and open **Collected > Collect new artifact** or a **VQL Notebook** to hunt for processes running from non-standard directories:

```sql
SELECT Pid, Ppid, Name, Exe, CommandLine
FROM pslist()
WHERE Exe =~ "(?i)(Users\\\\Public|AppData\\\\Local\\\\Temp|ProgramData)"
```

You can also collect built-in artifacts immediately:
- **`Windows.Sys.StartupItems`**: enumerates startup entries and `Run` / `RunOnce` keys.
- **`Windows.Network.NetstatEnriched`**: correlates active TCP/UDP sockets with process `Pid` and `Name`.
- **`Windows.Detection.Amcache`**: inspects recently executed binaries on the endpoint.

---

## 6. Control Mapping and Best Practices

| Framework | Reference | Practical Application |
|---|---|---|
| **NIST SP 800-86** | *Guide to Integrating Forensic Techniques into Incident Response* | Standardized collection of volatile and non-volatile endpoint artifacts. |
| **NIST CSF** | `DE.AE-02` / `RS.AN-01` | Forensic analysis of anomalous events on hosts. |
| **ISO/IEC 27001:2022** | `A.5.28` (*Collection of Evidence*) | Identification, collection, and preservation of digital evidence. |

---

## References

- [Velociraptor — Official Documentation & VQL Reference](https://docs.velociraptor.app/)
- [Microsoft Learn — Install WSL 2 on Windows Enterprise](https://learn.microsoft.com/en-us/windows/wsl/install)
- [NIST SP 800-86 — Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final)

