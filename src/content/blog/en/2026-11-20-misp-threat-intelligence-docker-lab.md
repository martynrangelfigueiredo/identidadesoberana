---
title: "MISP in a Local Docker & WSL2 Lab: Practical Threat Intelligence Management for the SOC"
description: "Step-by-step technical guide to deploy MISP locally via Docker on WSL2 (Windows Enterprise) and integrate IOCs with Wazuh and Shuffle."
date: 2026-11-20
categoria: SOC
tags: [misp, threat-intelligence, docker, wsl2, open-source, soc, ioc]
nivel: Intermediário
draft: false
---

> **TL;DR:** Centralizing Indicators of Compromise (IOCs) in an open platform eliminates scattered spreadsheets and speeds up SOC triage. This guide walks through deploying **MISP** in a locally isolated Docker & WSL2 lab on Windows Enterprise, enabling starter OSINT feeds, and querying attributes via API for Wazuh or Shuffle enrichment.

---

## 1. Why run MISP locally in your SOC lab?

**MISP** (*Malware Information Sharing Platform*) is the open standard for sharing and correlating *Threat Intelligence* (CTI). Instead of manually checking dozens of external portals for every suspicious IP, domain, or hash, analysts maintain a structured repository of events, attributes, and taxonomies (such as TLP and MITRE ATT&CK).

Running the platform in **local isolation** (`127.0.0.1`) via Docker Desktop / WSL2 on Windows Enterprise allows you to:
- Test public feeds (CIRCL OSINT, abuse.ch, ThreatFox) without leaking internal lookup targets externally.
- Automatically correlate IOCs observed in Wazuh alerts or TheHive cases.
- Validate enrichment *playbooks* in Shuffle before promoting them to production.

---

## 2. Prerequisites and Lab Architecture

| Component | Minimum Requirement | Notes |
|---|---|---|
| **Host OS** | Windows 10/11 Enterprise with WSL2 | Hardware virtualization enabled in BIOS/UEFI. |
| **Container Engine** | Docker Desktop or Docker Engine on Ubuntu WSL2 | Allocate at least 4 GB RAM in `.wslconfig`. |
| **Local Ports** | `127.0.0.1:8443` (HTTPS) | Bound exclusively to loopback to prevent LAN exposure. |

---

## 3. Deploying MISP with Docker Compose (Loopback Isolation)

Create a dedicated directory in WSL2 (e.g., `~/soc-labs/misp`) and define a clean `compose.yml` containing the core services (`misp-core`, `db` MariaDB, and `redis`).

> **Important:** Never use default passwords in shared environments. Store all *secrets* in a local `.env` file excluded from version control.

Sample `.env` file:

```env
MYSQL_ROOT_PASSWORD=REPLACE_WITH_STRONG_ROOT_SECRET
MYSQL_PASSWORD=REPLACE_WITH_STRONG_DB_SECRET
MISP_ADMIN_EMAIL=soc-lab@contoso.local
MISP_ADMIN_PASSPHRASE=REPLACE_WITH_STRONG_ADMIN_SECRET
MISP_BASEURL=https://127.0.0.1:8443
```

`compose.yml` file:

```yaml
services:
  redis:
    image: redis:7-alpine
    restart: unless-stopped
    networks:
      - misp-net

  db:
    image: mariadb:10.11
    restart: unless-stopped
    environment:
      MYSQL_DATABASE: misp
      MYSQL_USER: misp
      MYSQL_PASSWORD: ${MYSQL_PASSWORD}
      MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD}
    volumes:
      - misp-db:/var/lib/mysql
    networks:
      - misp-net

  misp-core:
    image: ghcr.io/misp/misp-docker/misp-core:latest
    restart: unless-stopped
    depends_on:
      - db
      - redis
    ports:
      - "127.0.0.1:8443:443"
    environment:
      MYSQL_HOST: db
      MYSQL_DATABASE: misp
      MYSQL_USER: misp
      MYSQL_PASSWORD: ${MYSQL_PASSWORD}
      REDIS_HOST: redis
      BASE_URL: ${MISP_BASEURL}
      ADMIN_EMAIL: ${MISP_ADMIN_EMAIL}
      ADMIN_PASSPHRASE: ${MISP_ADMIN_PASSPHRASE}
      INIT: "true"
    volumes:
      - misp-configs:/var/www/MISP/app/Config
      - misp-files:/var/www/MISP/app/files
    networks:
      - misp-net

volumes:
  misp-db:
  misp-configs:
  misp-files:

networks:
  misp-net:
    driver: bridge
```

Start the containers and monitor database initialization:

```bash
docker compose up -d
docker compose logs -f misp-core
```

Once Apache/PHP-FPM is up, open `https://127.0.0.1:8443` in your browser (accepting the self-signed lab certificate) and sign in with the credentials defined in `.env`.

---

## 4. Enabling Starter Feeds and Generating an API Key

After logging into the admin console:

1. **Enable trusted OSINT feeds:**
   Go to `Sync Actions > List Feeds`. Enable **CIRCL OSINT Feed** and **The Botvrij.eu Data**, then click **Fetch and store all feed data** to populate your local instance with up-to-date IOCs.
2. **Generate an AuthKey for automation:**
   Navigate to `Global Actions > My Profile > Auth Keys > Add authentication key`. Copy the generated key once and store it in Shuffle's *secrets* vault or your lab script environment.

---

## 5. Querying IOCs via API (Shuffle and Wazuh Integration)

With your *AuthKey* ready, any Shuffle *playbook* or Python/PowerShell script can check whether a suspicious IP (such as `198.51.100.42` from the RFC 5737 documentation range) appears in known threat events:

```bash
curl -k -X POST https://127.0.0.1:8443/attributes/restSearch \
  -H "Authorization: YOUR_AUTHKEY_HERE" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{
    "returnFormat": "json",
    "type": "ip-dst",
    "value": "198.51.100.42"
  }'
```

If `response.Attribute` returns matches, your automated Shuffle workflow can:
- Automatically escalate alert severity in **TheHive**.
- Attach campaign tags (`tlp:amber`, `mitre-attack-pattern`) directly to the case.
- Trigger a temporary block on perimeter firewalls or *Conditional Access*.

---

## 6. Control Mapping and Best Practices

| Framework | Reference | Practical Application |
|---|---|---|
| **NIST SP 800-150** | *Guide to Cyber Threat Information Sharing* | Standardized management of IOCs, TLP, and trusted feeds. |
| **NIST CSF** | `DE.CM-01` / `RS.AN-03` | Continuous correlation of external indicators against internal telemetry. |
| **ISO/IEC 27001:2022** | `A.5.7` (*Threat Intelligence*) | Collection, analysis, and operational use of threat intelligence. |

---

## References

- [Microsoft Learn — Install WSL 2 on Windows Enterprise](https://learn.microsoft.com/en-us/windows/wsl/install)
- [Docker Docs — Docker Compose Overview](https://docs.docker.com/compose/)
- [MISP Project — Official Documentation & Docker Images](https://www.misp-project.org/documentation/)
- [NIST SP 800-150 — Guide to Cyber Threat Information Sharing](https://csrc.nist.gov/pubs/sp/800/150/final)
- [FIRST — Traffic Light Protocol (TLP) Standard](https://www.first.org/tlp/)
