---
title: "MISP im lokalen Labor mit Docker und WSL2: Praktisches Threat-Intelligence-Management für das SOC"
description: "Technische Schritt-für-Schritt-Anleitung zur lokalen Bereitstellung von MISP via Docker in WSL2 (Windows Enterprise) und Integration mit Wazuh und Shuffle."
date: 2026-11-20
categoria: SOC
tags: [misp, threat-intelligence, docker, wsl2, open-source, soc, ioc]
nivel: Intermediário
draft: false
---

> **TL;DR:** Die Zentralisierung von Indicators of Compromise (IOCs) auf einer offenen Plattform vermeidet isolierte Tabellen und beschleunigt die SOC-Triage. Dieser Leitfaden zeigt, wie Sie **MISP** lokal und isoliert mit Docker und WSL2 unter Windows Enterprise starten, erste Feeds einrichten und Attribute per API für Wazuh oder Shuffle abfragen.

---

## 1. Warum MISP lokal im SOC-Labor betreiben?

**MISP** (*Malware Information Sharing Platform*) ist der offene Standard für den Austausch und die Korrelation von *Threat Intelligence* (CTI). Anstatt für jede verdächtige IP, Domain oder jeden Hash dutzende Portale manuell abzufragen, pflegt das Team eine strukturierte Basis aus Events, Attributen und Taxonomien (wie TLP und MITRE ATT&CK).

Der Betrieb in **lokaler Isolation** (`127.0.0.1`) über Docker Desktop / WSL2 unter Windows Enterprise ermöglicht:
- Öffentliche Feeds (CIRCL OSINT, abuse.ch, ThreatFox) zu testen, ohne interne Abfragen nach außen preiszugeben.
- IOCs aus Wazuh-Alarmen oder TheHive-Fällen automatisch zu korrelieren.
- Anreicherungs-*Playbooks* in Shuffle vor dem Produktiveinsatz zu validieren.

---

## 2. Voraussetzungen und Labor-Architektur

| Komponente | Mindestanforderung | Hinweis |
|---|---|---|
| **Host-System** | Windows 10/11 Enterprise mit WSL2 | Virtualisierung im BIOS/UEFI aktiviert. |
| **Container Engine** | Docker Desktop oder Docker Engine in Ubuntu WSL2 | Mindestens 4 GB RAM in `.wslconfig` zugewiesen. |
| **Lokale Ports** | `127.0.0.1:8443` (HTTPS) | Ausschließliche Bindung an Loopback gegen LAN-Exposition. |

---

## 3. MISP mit Docker Compose starten (Loopback-Isolation)

Erstellen Sie ein Verzeichnis in Ihrer WSL2-Umgebung (z. B. `~/soc-labs/misp`) und legen Sie eine schlanke `compose.yml` mit den Kernkomponenten (`misp-core`, `db` MariaDB und `redis`) an.

> **Wichtig:** Verwenden Sie niemals Standardpasswörter in geteilten Umgebungen. Hinterlegen Sie alle *Secrets* in einer lokalen `.env`-Datei (außerhalb der Versionskontrolle).

Beispiel für `.env`:

```env
MYSQL_ROOT_PASSWORD=DURCH_STARKES_ROOT_SECRET_ERSETZEN
MYSQL_PASSWORD=DURCH_STARKES_DB_SECRET_ERSETZEN
MISP_ADMIN_EMAIL=soc-lab@contoso.local
MISP_ADMIN_PASSPHRASE=DURCH_STARKES_ADMIN_SECRET_ERSETZEN
MISP_BASEURL=https://127.0.0.1:8443
```

Datei `compose.yml`:

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

Container starten und Initialisierung verfolgen:

```bash
docker compose up -d
docker compose logs -f misp-core
```

Sobald Apache/PHP-FPM bereit ist, öffnen Sie `https://127.0.0.1:8443` im Browser (selbstsigniertes Labor-Zertifikat akzeptieren) und melden sich mit den Daten aus `.env` an.

---

## 4. Erste Feeds aktivieren und API-Schlüssel erzeugen

Nach der ersten Anmeldung im Admin-Panel:

1. **Vertrauenswürdige OSINT-Feeds aktivieren:**
   Navigieren Sie zu `Sync Actions > List Feeds`. Aktivieren Sie **CIRCL OSINT Feed** sowie **The Botvrij.eu Data** und klicken Sie auf **Fetch and store all feed data**, um die lokale Datenbank mit aktuellen IOCs zu füllen.
2. **AuthKey für Automatisierung erstellen:**
   Öffnen Sie `Global Actions > My Profile > Auth Keys > Add authentication key`. Kopieren Sie den Schlüssel einmalig und speichern Sie ihn im *Secrets*-Tresor von Shuffle oder Ihrem Lab-Skript.

---

## 5. IOCs per API abfragen (Integration mit Shuffle und Wazuh)

Mit dem *AuthKey* kann jedes Shuffle-*Playbook* oder Python-/PowerShell-Skript prüfen, ob eine verdächtige IP (z. B. `198.51.100.42`, Dokumentationsbereich nach RFC 5737) in bekannten Events vorkommt:

```bash
curl -k -X POST https://127.0.0.1:8443/attributes/restSearch \
  -H "Authorization: IHR_AUTHKEY_HIER" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{
    "returnFormat": "json",
    "type": "ip-dst",
    "value": "198.51.100.42"
  }'
```

Liefert `response.Attribute` Treffer zurück, kann der automatisierte Shuffle-Workflow:
- Den Schweregrad des Alarms in **TheHive** automatisch erhöhen.
- Kampagnen-Tags (`tlp:amber`, `mitre-attack-pattern`) direkt am Fall anhängen.
- Eine temporäre Sperre auf Perimeter-Firewalls oder via *Conditional Access* anstoßen.

---

## 6. Kontroll-Mapping und Best Practices

| Framework | Referenz | Praktische Anwendung |
|---|---|---|
| **NIST SP 800-150** | *Guide to Cyber Threat Information Sharing* | Strukturierte Verwaltung von IOCs, TLP und vertrauenswürdigen Feeds. |
| **NIST CSF** | `DE.CM-01` / `RS.AN-03` | Kontinuierliche Korrelation externer Indikatoren mit interner Telemetrie. |
| **ISO/IEC 27001:2022** | `A.5.7` (*Threat Intelligence*) | Sammlung, Analyse und operative Nutzung von Bedrohungsinformationen. |

---

## Referenzen

- [Microsoft Learn — WSL 2 unter Windows Enterprise installieren](https://learn.microsoft.com/en-us/windows/wsl/install)
- [Docker Docs — Docker Compose Overview](https://docs.docker.com/compose/)
- [MISP Project — Official Documentation & Docker Images](https://www.misp-project.org/documentation/)
- [NIST SP 800-150 — Guide to Cyber Threat Information Sharing](https://csrc.nist.gov/pubs/sp/800/150/final)
- [FIRST — Traffic Light Protocol (TLP) Standard](https://www.first.org/tlp/)
