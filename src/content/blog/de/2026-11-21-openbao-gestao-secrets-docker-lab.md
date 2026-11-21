---
title: "OpenBao im lokalen Labor mit Docker und WSL2: Secrets-Management und Zugriffs-Auditing"
description: "Praxisleitfaden zur lokalen Bereitstellung von OpenBao mit Docker und WSL2 unter Windows Enterprise inklusive Audit-Logging und API-Abruf von Secrets."
date: 2026-11-21
categoria: IAM
tags: [openbao, iam, secrets, docker, wsl2, open-source, devsecops]
nivel: Intermediário
draft: false
---

> **TL;DR:** Die Zentralisierung von *Secrets* für Anwendungen und Automatisierungen verhindert *hardcoded* Zugangsdaten in Repositories und SOC-Skripten. Dieser Leitfaden zeigt, wie Sie **OpenBao** (ein Projekt der Linux Foundation) isoliert mit Docker und WSL2 unter Windows Enterprise starten, JSON-Audit-Logs aktivieren und *Secrets* per CLI/API abrufen.

---

## 1. Warum ein lokaler Secrets-Tresor im Labor?

Beim Aufbau von *Playbooks* in Shuffle, Skripten in Wazuh oder Abfragen gegen MISP fallen regelmäßig *API-Keys*, OAuth-Tokens und *Client Secrets* an. Werden diese Werte im Klartext oder fest im Code abgelegt, steigt das Risiko versehentlicher Offenlegung enorm.

**OpenBao** ist eine *Open-Source*-Lösung unter dem Dach der Linux Foundation (API-kompatibel zum Vault-Ökosystem) und bietet:
- Verschlüsselte Speicherung von *Secrets* im Ruhezustand mit granularen Richtlinien (*Least Privilege*).
- Kurzlebige Tokens mit definierter TTL und sofortigem Widerruf.
- Strukturierte JSON-Audit-Logs für jeden Lesezugriff, fehlgeschlagene Logins oder Rotationen.

---

## 2. Voraussetzungen und Labor-Isolation

| Komponente | Mindestanforderung | Hinweis |
|---|---|---|
| **Host-System** | Windows 10/11 Enterprise mit WSL2 | Virtualisierung aktiviert und Ubuntu in WSL2 aktuell. |
| **Container Engine** | Docker Desktop oder Docker Engine in WSL2 | Compose v2 verfügbar (`docker compose version`). |
| **Netzwerk-Bind** | `127.0.0.1:8200` (lokales Lab-HTTP) | Strikte Loopback-Bindung ohne Exposition im LAN. |

---

## 3. OpenBao mit Docker Compose starten

Erstellen Sie ein Verzeichnis in WSL2 (z. B. `~/iam-labs/openbao`) für Konfiguration und Audit-Logs:

```bash
mkdir -p ~/iam-labs/openbao/config ~/iam-labs/openbao/logs
```

Legen Sie `~/iam-labs/openbao/config/bao.hcl` für lokale Dateipersistenz an (TLS im reinen Loopback-Testlabor deaktiviert):

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

Erstellen Sie `~/iam-labs/openbao/compose.yml` mit Portbindung ausschließlich auf `127.0.0.1`:

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

Dienst starten:

```bash
cd ~/iam-labs/openbao
docker compose up -d
```

---

## 4. Initialisierung, Unseal und Audit-Logs aktivieren

Im persistenten Modus startet OpenBao versiegelt (*sealed*). Initialisieren Sie den Tresor im Container, um *Unseal-Key* und initialen Root-Token zu erzeugen:

```bash
docker exec -e BAO_ADDR='http://127.0.0.1:8200' openbao-lab bao operator init -key-shares=1 -key-threshold=1
```

Bewahren Sie `Unseal Key` und `Initial Root Token` nur in Ihrer lokalen Labor-Session auf (niemals in Git committen) und entsiegeln Sie den Tresor:

```bash
docker exec -e BAO_ADDR='http://127.0.0.1:8200' openbao-lab bao operator unseal IHR_UNSEAL_KEY_HIER
```

Aktivieren Sie anschließend direkt das JSON-Audit-Logging (ideal für spätere SIEM-Korrelation):

```bash
export BAO_ADDR='http://127.0.0.1:8200'
docker exec -e BAO_ADDR=$BAO_ADDR -e BAO_TOKEN=IHR_ROOT_TOKEN openbao-lab bao audit enable file file_path=/openbao/logs/audit.log
```

---

## 5. Secrets speichern und mit minimalen Rechten abrufen

Aktivieren Sie die *KV v2*-Engine und legen Sie ein Beispiel-*Secret* für das SOC ab:

```bash
docker exec -e BAO_ADDR=$BAO_ADDR -e BAO_TOKEN=IHR_ROOT_TOKEN openbao-lab bao secrets enable -path=soc kv-v2
docker exec -e BAO_ADDR=$BAO_ADDR -e BAO_TOKEN=IHR_ROOT_TOKEN openbao-lab bao kv put soc/misp api_key="BEISPIEL_LAB_TOKEN"
```

Abruf des *Secrets* über die REST-API aus einem Shuffle-*Playbook* oder Python-Skript in WSL2:

```bash
curl -s http://127.0.0.1:8200/v1/soc/data/misp \
  -H "X-Vault-Token: IHR_LESE_TOKEN" | jq '.data.data'
```

Jede Anfrage schreibt eine JSON-Zeile in `~/iam-labs/openbao/logs/audit.log` mit `request.path`, `auth.display_name`, `remote_address` und `response`, sodass ein Wazuh-Agent ungewöhnliche Zugriffe auf sensible *Secrets* direkt erkennen kann.

---

## 6. Kontroll-Mapping und Best Practices

| Framework | Referenz | Praktische Anwendung |
|---|---|---|
| **NIST SP 800-57** | *Recommendation for Key Management* | Lebenszyklus, Rotation und kryptografischer Schutz von Schlüsseln und *Secrets*. |
| **CIS Controls v8** | `3.11` / `6.8` | Verschlüsselung sensibler Daten und rollenbasierter Zugriff auf Zugangsdaten. |
| **ISO/IEC 27001:2022** | `A.5.17` / `A.8.24` | Verwaltung von Authentifizierungsinformationen und kryptografischen Kontrollen. |

---

## Referenzen

- [OpenBao — Official Documentation (Linux Foundation)](https://openbao.org/docs/)
- [Microsoft Learn — Install WSL 2 on Windows Enterprise](https://learn.microsoft.com/en-us/windows/wsl/install)
- [NIST SP 800-57 Part 1 — Recommendation for Key Management](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)

