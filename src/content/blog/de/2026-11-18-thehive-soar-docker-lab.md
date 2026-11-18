---
title: "SOAR mit TheHive und Cortex: Incident-Response-Labor in Docker"
description: "Vollständige Anleitung zur Bereitstellung von TheHive und Cortex auf Windows Enterprise mit Docker und WSL 2 für Triage, Fallmanagement und SOC-Automatisierung."
date: 2026-11-18
categoria: SOC
tags: [thehive, cortex, soar, docker, windows-enterprise, wsl2, lab, open-source, soc]
nivel: Intermediário
---

Im täglichen Betrieb eines Security Operations Centers (SOC) ist das Erkennen einer Bedrohung über ein SIEM (wie Wazuh oder Microsoft Sentinel) nur der erste Schritt der Abwehrarbeit. Die anschließende Phase – die Triage des Alarms, die Qualifizierung von Indicators of Compromise (IoCs), die Dokumentation der Zeitleiste, die Aufgabenkoordination zwischen Analysten und das Einleiten von Eindämmungsmaßnahmen – erfordert eine dedizierte Incident-Response-Plattform (**SIRP - Security Incident Response Platform**) kombiniert mit Orchestrierungs- und Automatisierungsfunktionen (**SOAR - Security Orchestration, Automation, and Response**).

Im Open-Source-Ökosystem und der offenen Infrastruktur ist die Kombination aus **TheHive** (Plattform für Sicherheitsfallmanagement) und **Cortex** (Analyse- und aktive Reaktions-Engine zur Anreicherung von Observables) die führende Branchenreferenz.

In dieser praktischen Anleitung lernen Sie, wie Sie ein vollständiges Labor mit TheHive und Cortex unter Windows Enterprise mit Docker Desktop und WSL 2 einrichten. Dies ermöglicht es Ihnen, Incident-Response-Playbooks zu testen, Observables anzureichern und das Fallmanagement in einer vollständig lokalen und isolierten Umgebung zu strukturieren.

> **TL;DR für das Labor:** Um den Cluster bestehend aus TheHive, Cortex, Cassandra, Elasticsearch und MinIO unter Windows Enterprise mit WSL 2 auszuführen, weisen Sie in der `.wslconfig` mindestens 6 GB bis 8 GB RAM zu und nutzen Sie ein internes Bridge-Netzwerk in Docker Compose für die sichere Kommunikation zwischen den Containern.

> 📘 **Offizielle Referenzen:** Diese Anleitung basiert auf der offiziellen Dokumentation der Projekte TheHive und Cortex:
> - [TheHive Project Documentation (StrangeBee)](https://docs.strangebee.com/)
> - [TheHive GitHub Repository](https://github.com/TheHive-Project/TheHive)
> - [Cortex Project Documentation](https://github.com/TheHive-Project/Cortex)

---

## 1. Warum TheHive und Cortex im SOC-Betrieb integrieren?

In Incident-Response-Teams (CSIRT/CERT) und Unternehmens-SOCs bieten Standard-Helpdesk-Systeme und generische ITSM-Tools nicht die erforderlichen Werkzeuge für Cyber-Ermittlungen. TheHive und Cortex bieten speziell für Verteidigungsoperationen entwickelte Kernfunktionen:

1. **Bedrohungsorientiertes Fallmanagement:** Jeder Fall vereint eingehende Alarme, eine detaillierte Zeitleiste, operative Aufgabenbäume und einen Katalog von Observables (IP-Adressen, Datei-Hashes, Domänen, URLs und Benutzerkonten).
2. **Automatisierte Anreicherung mit Cortex:** Cortex stellt Dutzende von Analyzern bereit, die Threat-Intelligence-Quellen wie VirusTotal, AbuseIPDB, Shodan und MISP mit einem einzigen Klick oder per Automatisierung abfragen.
3. **Standardisierung durch Vorlagen (Case Templates):** Definieren Sie standardisierte Playbooks für wiederkehrende Vorfälle (z. B. Phishing, Ransomware-Infektionen, kompromittierte Zugangsdaten), um sicherzustellen, dass jeder Analyst die gleichen Eindämmungs- und Behebungsschritte befolgt.
4. **Vollständige Datenkontrolle und Isolation:** In Umgebungen mit strengen Compliance-Vorgaben (DSGVO/GDPR) verbleiben interne Ermittlungsdaten vollständig unter der Kontrolle des lokalen Teams.

---

## 2. Voraussetzungen und Anpassungen unter Windows Enterprise (WSL 2)

Der TheHive-Stack ist robust und basiert auf einer verteilten Datenbank (Apache Cassandra), einer Suchmaschine (Elasticsearch) und einem S3-kompatiblen Objektspeicher (MinIO) für Fallanhänge und Beweismittel.

### Schritt 1: Speicher in der `.wslconfig` anpassen

Öffnen Sie in PowerShell die globale Konfigurationsdatei von WSL 2:

```powershell
notepad "$env:USERPROFILE\.wslconfig"
```

Konfigurieren Sie die erforderlichen Ressourcengrenzen:

```ini
[wsl2]
memory=8GB            # Empfohlen für TheHive, Cortex, Cassandra und Elasticsearch
processors=4          # 4 Rechenkerne
swap=4GB              # Auslagerungsspeicher
localhostForwarding=true
```

### Schritt 2: Virtuelle Speichergrenzen für Elasticsearch konfigurieren

Elasticsearch erfordert eine erhöhte Anzahl gemappter Speicherbereiche im Linux-Kernel:

```powershell
wsl -d Ubuntu -u root sysctl -w vm.max_map_count=262144
```

Machen Sie die Einstellung dauerhaft, indem Sie sie in `/etc/sysctl.conf` innerhalb von WSL 2 eintragen:

```bash
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

Starten Sie WSL 2 über PowerShell neu:

```powershell
wsl --shutdown
```

---

## 3. Laborstruktur mit Docker Compose

Erstellen Sie ein Arbeitsverzeichnis für das Labor (z. B. im WSL 2-Terminal oder der PowerShell):

```bash
mkdir -p ~/thehive-lab && cd ~/thehive-lab
```

Erstellen Sie die Datei `docker-compose.yml`:

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
  # 1. NoSQL-Datenbank für Metadaten und Zeitleiste
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

  # 2. Such- und Indexierungs-Engine
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

  # 3. S3-kompatibler Objektspeicher für Beweismittel und Anhänge
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

  # 4. Analyse- und Response-Engine (Cortex)
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

  # 5. Fallmanagement- und Incident-Response-Plattform (TheHive)
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

Starten Sie den Cluster im Hintergrund:

```bash
docker compose up -d
```

Verfolgen Sie den Initialisierungsprozess:

```bash
docker compose logs -f thehive
```

> **Betriebshinweis:** Beim ersten Start benötigen Cassandra und Elasticsearch ca. 1 bis 2 Minuten, um Schemas und Initialindizes anzulegen. TheHive wartet auf die Datenbankbereitschaft, bevor Port 9000/TCP geöffnet wird.

---

## 4. Zugriff auf die Konsole und Ersteinrichtung

Sobald alle Container den Status healthy aufweisen (`docker compose ps`):

### Zugriff auf TheHive
1. Rufen Sie im Browser auf: `http://localhost:9000`
2. Standardzugangsdaten:
   - **Benutzer:** `admin@thehive.local`
   - **Passwort:** `secret`
3. Ändern Sie das Initialpasswort direkt nach dem ersten Login.

### Zugriff auf Cortex
1. Rufen Sie im Browser auf: `http://localhost:9001`
2. Klicken Sie auf **Update Database**, um die Schemas in Elasticsearch anzuwenden.
3. Erstellen Sie den initialen Administrator für Cortex mit einem sicheren Lab-Passwort.

---

## 5. Praktischer SOC-Workflow: Von der Triage bis zum Abschluss

### Schritt 1: Erstellung eines Fall-Templates (Case Template)

Strukturierte Playbooks verhindern, dass Analysten in Stresssituationen entscheidende Schritte übersehen. Im TheHive-Menü:
1. Navigieren Sie zu **Admin > Case Templates**.
2. Erstellen Sie ein Template mit dem Namen **"Vorfall: Verdacht auf kompromittiertes Benutzerkonto"**.
3. Fügen Sie vordefinierte Aufgaben hinzu:
   - `Aufgabe 1: Anmeldeereignisse (SigninLogs) und MFA prüfen`.
   - `Aufgabe 2: Quell-IP identifizieren und Reputation prüfen`.
   - `Aufgabe 3: Aktive Sitzungen widerrufen (Revoke-MgUserSignSession)`.
   - `Aufgabe 4: Passwort-Reset erzwingen`.

### Schritt 2: Untersuchung eines neuen Falles

1. Erstellen Sie einen neuen Fall basierend auf der Vorlage:
   - **Titel:** `SOC-Alarm: Verdächtige Anmeldung von anomaler IP`
   - **Schweregrad:** `Mittel`
   - **TLP:** `TLP:AMBER`
   - **PAP:** `PAP:GREEN`

2. Fügen Sie erfasste Observables hinzu:
   - Typ `ip`: `198.51.100.45` (RFC 5737 Testadresse).
   - Typ `user`: `usuario.suporte@contoso.com`.

### Schritt 3: Ausführung von Analyzern über Cortex

Klicken Sie im Fall auf das IP-Observable und wählen Sie **Run Analyzer**:
- Cortex führt Abfragen an konfigurierte Dienste durch (z. B. AbuseIPDB oder lokale GeoIP-Datenbanken).
- Nach wenigen Sekunden wird der Analysebericht direkt an den Fall angehängt (Herkunftsland, ASN, Missbrauchs-Score).
- Weist die IP ein hohes Risikoniveau auf, stuft der Analyst den Fall auf `Hoch` und initiiert die Sitzungswiderrufung.

---

## 6. Nächste Schritte: Integration von Wazuh, TheHive und Shuffle

Mit einem lokal betriebenen TheHive- und Cortex-Labor verfügen Sie über die Basis für eine vollständige Verteidigungsautomatisierung:

- **Direkte Wazuh-Anbindung:** Konfigurieren Sie den nativen `wazuh-integrator`, um Alarme hoher Priorität automatisch als Fälle in TheHive anzulegen.
- **Automatisierung mit Shuffle:** Nutzen Sie die Open-Source-SOAR-Plattform Shuffle, um Aktionen zwischen Wazuh, TheHive und lokalen Firewalls zu orchestrieren.
- **SOC-Kennzahlen:** Nutzen Sie integrierte TheHive-Dashboards zur Messung von Reaktionsmetriken wie **MTTD (Mean Time to Detect)** und **MTTR (Mean Time to Respond)**.

