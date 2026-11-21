---
title: "OpenBao in a Local Docker & WSL2 Lab: Secrets Management and Access Auditing"
description: "Practical guide to deploy OpenBao locally with Docker and WSL2 on Windows Enterprise, enable JSON audit logs, and retrieve secrets via API."
date: 2026-11-21
categoria: IAM
tags: [openbao, iam, secrets, docker, wsl2, open-source, devsecops]
nivel: Intermediário
draft: false
---

> **TL;DR:** Centralizing *secrets* for applications and automation prevents *hardcoded* credentials in repositories and SOC scripts. This guide shows how to deploy **OpenBao** (a Linux Foundation open-source project) in an isolated Docker & WSL2 lab on Windows Enterprise, enable structured JSON audit logs, and read *secrets* via CLI/API.

---

## 1. Why run a local secrets vault in your lab?

While building *playbooks* in Shuffle, collection scripts in Wazuh, or enrichment workflows against MISP, analysts routinely handle API keys, OAuth tokens, and *client secrets*. Storing those values in plain text files or static configs increases the risk of accidental leaks in commits or logs.

**OpenBao** is an open-source solution governed by the Linux Foundation (API-compatible with the Vault ecosystem) that lets you:
- Store *secrets* encrypted at rest with granular *least-privilege* policies.
- Issue short-lived tokens (TTL) with immediate revocation capability.
- Log every read, authentication failure, and rotation event into a structured JSON *audit log*.

---

## 2. Prerequisites and Lab Isolation

| Component | Minimum Requirement | Notes |
|---|---|---|
| **Host OS** | Windows 10/11 Enterprise with WSL2 | Hardware virtualization enabled; updated Ubuntu WSL2 distro. |
| **Container Engine** | Docker Desktop or Docker Engine on WSL2 | Compose v2 available (`docker compose version`). |
| **Network Bind** | `127.0.0.1:8200` (local lab HTTP) | Strict loopback binding to prevent LAN exposure. |

---

## 3. Deploying OpenBao with Docker Compose

Create a dedicated directory in WSL2 (e.g., `~/iam-labs/openbao`) for configuration and audit logs:

```bash
mkdir -p ~/iam-labs/openbao/config ~/iam-labs/openbao/logs
```

Create `~/iam-labs/openbao/config/bao.hcl` for local file persistence (TLS disabled strictly for local loopback lab testing):

```hcl
ui = true

storage "file" {
  path = "/openbao/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}
```

Create `~/iam-labs/openbao/compose.yml` binding the port exclusively to `127.0.0.1`:

```yaml
services:
  openbao:
    image: quay.io/openbao/openbao:latest
    container_name: openbao-lab
    restart: unless-stopped
    cap_add:
      - IPC_LOCK
    ports:
      - "127.0.0.1:8200:8200"
    volumes:
      - ./config:/openbao/config:ro
      - ./logs:/openbao/logs
      - openbao-data:/openbao/file
    command: server -config=/openbao/config/bao.hcl

volumes:
  openbao-data:
```

Start the service:

```bash
cd ~/iam-labs/openbao
docker compose up -d
```

---

## 4. Initialization, Unseal, and Enabling Audit Logs

In persistent mode, OpenBao starts *sealed*. Initialize the vault inside the container to generate your *unseal key* and initial root token:

```bash
docker exec -e BAO_ADDR='http://127.0.0.1:8200' openbao-lab bao operator init -key-shares=1 -key-threshold=1
```

Keep the printed `Unseal Key` and `Initial Root Token` strictly within your local lab session (never commit them to Git) and unseal the instance:

```bash
docker exec -e BAO_ADDR='http://127.0.0.1:8200' openbao-lab bao operator unseal YOUR_UNSEAL_KEY_HERE
```

Immediately enable the JSON file audit backend (essential for downstream SIEM correlation):

```bash
export BAO_ADDR='http://127.0.0.1:8200'
docker exec -e BAO_ADDR=$BAO_ADDR -e BAO_TOKEN=YOUR_ROOT_TOKEN openbao-lab bao audit enable file file_path=/openbao/logs/audit.log
```

---

## 5. Storing and Consuming Secrets with Least Privilege

Enable the *KV v2* engine and store a sample *secret* for SOC integration:

```bash
docker exec -e BAO_ADDR=$BAO_ADDR -e BAO_TOKEN=YOUR_ROOT_TOKEN openbao-lab bao secrets enable -path=soc kv-v2
docker exec -e BAO_ADDR=$BAO_ADDR -e BAO_TOKEN=YOUR_ROOT_TOKEN openbao-lab bao kv put soc/misp api_key="SAMPLE_LOCAL_LAB_TOKEN"
```

Retrieve the *secret* via REST API from a Shuffle *playbook* or Python script in WSL2:

```bash
curl -s http://127.0.0.1:8200/v1/soc/data/misp \
  -H "X-Vault-Token: YOUR_READ_TOKEN" | jq '.data.data'
```

Each request appends a JSON line to `~/iam-labs/openbao/logs/audit.log` containing `request.path`, `auth.display_name`, `remote_address`, and `response`, allowing a Wazuh agent to ingest and alert on anomalous access to sensitive *secrets*.

---

## 6. Control Mapping and Best Practices

| Framework | Reference | Practical Application |
|---|---|---|
| **NIST SP 800-57** | *Recommendation for Key Management* | Lifecycle, rotation, and cryptographic protection of keys and *secrets*. |
| **CIS Controls v8** | `3.11` / `6.8` | Encryption of sensitive data and role-based access control for credentials. |
| **ISO/IEC 27001:2022** | `A.5.17` / `A.8.24` | Management of authentication information and cryptographic controls. |

---

## References

- [OpenBao — Official Documentation (Linux Foundation)](https://openbao.org/docs/)
- [Microsoft Learn — Install WSL 2 on Windows Enterprise](https://learn.microsoft.com/en-us/windows/wsl/install)
- [NIST SP 800-57 Part 1 — Recommendation for Key Management](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)

