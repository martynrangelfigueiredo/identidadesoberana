---
title: "Smallstep (step-ca) on Docker and WSL2: Internal PKI, ACME, and Short-Lived Certificates"
description: "Practical guide to running an internal PKI with Smallstep step-ca on Docker and WSL2 (Windows Enterprise) for automated ACME and mTLS certificates."
date: 2026-11-26
categoria: IAM
tags: [pki, mtls, acme, smallstep, zero-trust, docker, wsl2, open-source]
nivel: Intermediário
draft: false
---

> **TL;DR:** Internal SOC and IAM lab services (Keycloak, Wazuh, automation APIs) often run over plain HTTP or untrusted self-signed certificates. This guide shows how to deploy an internal Certificate Authority (CA) with **Smallstep (`step-ca`)** on Docker and WSL2, issue short-lived certificates via **ACME**, and enforce **mTLS** without relying on public CAs.

---

## 1. Why run an internal PKI in a Zero Trust lab?

In enterprise workstations and local WSL2 labs on Windows Enterprise, ad-hoc self-signed certificates trigger constant browser warnings, break OIDC/SAML integrations, and train teams to click past TLS errors. Conversely, requesting public certificates for internal hosts (`*.lab.local`) leaks internal naming into public Certificate Transparency logs.

**Smallstep (`step-ca`)** solves this with a lightweight open-source PKI:
- **Native ACME support (RFC 8555):** Allows reverse proxies such as Caddy, Traefik, or Nginx to automatically renew internal certificates.
- **Short-lived certificates:** Default 24-hour lifetimes (or shorter) limit blast radius if a private key is compromised.
- **mTLS (Mutual TLS):** Strong mutual authentication between microservices, log collectors, and APIs without relying solely on static secrets.
- **100% local execution:** The entire hierarchy (Root CA and Intermediate CA) remains confined to your WSL2 lab directory.

---

## 2. Prerequisites and WSL2 isolation

| Component | Minimum Specification | Notes |
|---|---|---|
| **Host OS** | Windows 10/11 Enterprise with WSL2 | Updated Ubuntu 22.04/24.04 inside WSL2. |
| **Container Engine** | Docker Desktop or Docker Engine on WSL2 | Dedicated local lab network. |
| **Official Image** | `smallstep/step-ca` and `smallstep/step-cli` | Bound strictly to `127.0.0.1` on port `9000`. |

---

## 3. Running step-ca with Docker Compose on loopback

Create a dedicated lab directory and define `compose.yml` bound strictly to the loopback interface (`127.0.0.1`) so nothing is exposed to the external Windows host network:

```yaml
services:
  step-ca:
    image: smallstep/step-ca:latest
    container_name: lab-step-ca
    restart: unless-stopped
    ports:
      - "127.0.0.1:9000:9000"
    environment:
      - DOCKER_STEPCA_INIT_NAME=Lab Internal CA
      - DOCKER_STEPCA_INIT_DNS_NAMES=localhost,step-ca,127.0.0.1
      - DOCKER_STEPCA_INIT_PROVISIONER_NAME=admin@lab.local
    volumes:
      - step_data:/home/step

volumes:
  step_data:
```

Start the service and inspect the Root CA and Intermediate CA initialization logs:

```bash
mkdir -p ~/lab-pki && cd ~/lab-pki
docker compose up -d
docker compose logs -f step-ca
```

On first boot, the container automatically generates a random password for the CA key inside the `step_data` volume (`/home/step/secrets/password`). Record the Root CA fingerprint printed in the logs to verify client trust.

---

## 4. Enabling the ACME provisioner and issuing certificates

To let reverse proxies and local services request certificates automatically via **ACME**, add the ACME provisioner inside the container:

```bash
docker exec -it lab-step-ca step ca provisioner add acme --type ACME
docker compose restart step-ca
```

Then verify the health endpoint and active provisioners:

```bash
curl -sk https://127.0.0.1:9000/health
docker exec -it lab-step-ca step ca provisioner list
```

### Issuing an on-demand server certificate

To quickly issue a 24-hour TLS certificate for a local service (such as `keycloak.lab.local`), run:

```bash
docker exec -it lab-step-ca step ca certificate \
  "keycloak.lab.local" \
  /home/step/keycloak.crt \
  /home/step/keycloak.key \
  --provisioner admin@lab.local \
  --password-file /home/step/secrets/password
```

Extract the public root certificate (`root_ca.crt`) to trust it within your lab scope:

```bash
docker cp lab-step-ca:/home/step/certs/root_ca.crt ./root_ca.crt
```

On Ubuntu/WSL2, validate the chain with `curl` pointing directly to the lab CA without altering system-wide trust stores:

```bash
curl --cacert ./root_ca.crt https://127.0.0.1:9000/health
```

---

## 5. Security Best Practices and mTLS

| Control | Practical Recommendation | Benefit |
|---|---|---|
| **Short lifetimes** | Keep server certificates between 12h and 24h with automated ACME renewal. | Removes reliance on heavy CRLs and limits abuse windows. |
| **Root CA protection** | Isolate the Root CA key; issue leaf certificates strictly from the Intermediate CA. | Enables rotating the intermediate CA without redeploying the root. |
| **Service-to-service mTLS** | Require client certificates issued by the same internal CA on admin APIs. | Blocks lateral movement even if an internal port becomes reachable. |
| **Volume hygiene** | Restrict permissions on `step_data` and never commit `/home/step/secrets/` to Git. | Prevents exposure of the Certificate Authority private key. |

---

## 6. Control Mapping and References

- **Smallstep Documentation:** [step-ca Overview & ACME Provisioner](https://smallstep.com/docs/step-ca/)
- **Microsoft Learn (WSL2):** [Windows Subsystem for Linux Documentation](https://learn.microsoft.com/en-us/windows/wsl/)
- **IETF RFC 8555:** Automatic Certificate Management Environment (ACME)
- **NIST SP 800-57 / CSF 2.0 (`PR.DS-02`):** Protecting data in transit with strong cryptography and key lifecycle management.
- **CIS Controls v8 (`3.10` / `12.2`):** Encrypting data in transit and enforcing secure network architecture with mTLS.
