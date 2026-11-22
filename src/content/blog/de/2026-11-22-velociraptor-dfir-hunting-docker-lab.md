---
title: "Velociraptor im lokalen Labor mit Docker und WSL2: DFIR und Threat Hunting auf Windows-Endpoints"
description: "Praxisleitfaden zur lokalen Bereitstellung von Velociraptor via Docker in WSL2 sowie zur forensischen Artefaktsammlung (VQL) auf Windows Enterprise."
date: 2026-11-22
categoria: SOC
tags: [velociraptor, dfir, threat-hunting, docker, wsl2, open-source, soc]
nivel: Intermediário
draft: false
---

> **TL;DR:** Wenn ein Vorfall schnelle Analysen von Arbeitsspeicher, Windows-Registry oder laufenden Prozessen erfordert, reichen klassische Logs oft nicht aus. Dieser Leitfaden zeigt, wie Sie **Velociraptor** isoliert mit Docker und WSL2 unter Windows Enterprise starten und in Minuten erste VQL-Abfragen (*Velociraptor Query Language*) ausführen.

---

## 1. Warum Velociraptor im SOC-Labor einsetzen?

**Velociraptor** ist eine *Open-Source*-Plattform für **DFIR** (*Digital Forensics and Incident Response*) und **Threat Hunting**. Während ein SIEM wie Wazuh kontinuierliche Ereignisse sammelt, ermöglicht Velociraptor die gezielte On-Demand-Inspektion von Windows-Artefakten — etwa Persistenzschlüssel (`Run`/`RunOnce`), aktive Netzwerkverbindungen, geplante Aufgaben, Prefetch und *Event Logs* (`EVTX`).

Der Betrieb in **lokaler Isolation** (`127.0.0.1`) per Docker in WSL2 bietet folgende Vorteile:
- Entwicklung und Test eigener VQL-Artefakte ohne Risiko für Produktivsysteme.
- Automatisierte Auslösung forensischer Sammlungen über Shuffle-*Playbooks* oder TheHive-Fälle.
- Schnelle Triage auf Windows-Enterprise-Testsystemen über die lokale Weboberfläche.

---

## 2. Voraussetzungen und Labor-Architektur

| Komponente | Mindestanforderung | Hinweis |
|---|---|---|
| **Host-System** | Windows 10/11 Enterprise mit WSL2 | Virtualisierung aktiviert und Ubuntu in WSL2 aktuell. |
| **Container Engine** | Docker Desktop oder Docker Engine in WSL2 | Compose v2 aktiv (`docker compose version`). |
| **Lokale Ports** | `127.0.0.1:8889` (GUI) und `127.0.0.1:8000` (Frontend/Agent) | Ausschließliche Bindung an Loopback zur Isolation im LAN. |

---

## 3. Konfiguration erzeugen und Velociraptor mit Docker Compose starten

Legen Sie ein Verzeichnis in WSL2 an (z. B. `~/soc-labs/velociraptor`) und speichern Sie *Secrets* in einer lokalen `.env`-Datei:

```bash
mkdir -p ~/soc-labs/velociraptor/config ~/soc-labs/velociraptor/datastore
```

Beispiel für `.env`:

```env
VELO_ADMIN_USER=soc-admin
VELO_ADMIN_PASSWORD=DURCH_STARKES_LAB_SECRET_ERSETZEN
```

Erstellen Sie die `compose.yml` mit strikter Bindung auf `127.0.0.1`:

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

> **Praxis-Tipp:** Wenn Sie `server.config.yaml` manuell mit dem Velociraptor-Binary erzeugen möchten, führen Sie `velociraptor config generate -i` in WSL2 aus, setzen Sie `Client.server_urls` auf `https://127.0.0.1:8000/` und mounten die Datei nach `/velociraptor/server.config.yaml`.

Container starten:

```bash
cd ~/soc-labs/velociraptor
docker compose up -d
docker compose logs -f velociraptor
```

Öffnen Sie `https://127.0.0.1:8889` im Browser (selbstsigniertes Labor-Zertifikat akzeptieren) und melden Sie sich mit den Daten aus `.env` an.

---

## 4. Einen Windows-Enterprise-Test-Endpoint verbinden

Um reale Sammlungen auf demselben Windows-Host oder einer Labor-VM zu testen:

1. Erzeugen Sie die Client-Konfiguration über die GUI oder per CLI:
   ```bash
   docker exec velociraptor-lab velociraptor --config /velociraptor/server.config.yaml config client > client.config.yaml
   ```
2. Laden Sie das offizielle Windows-Binary (`velociraptor-vX.X.X-windows-amd64.exe`) von den GitHub-Releases herunter.
3. Starten Sie den Agenten in PowerShell mit der erzeugten Konfiguration:
   ```powershell
   .\velociraptor-windows-amd64.exe --config .\client.config.yaml client -v
   ```
4. Wenige Sekunden später erscheint der Endpoint unter **Search Clients** als **Online**.

---

## 5. Schnelles Hunting mit VQL (Persistenz und Prozesse)

Klicken Sie auf die Client-ID und öffnen Sie **Collected > Collect new artifact** oder ein **VQL Notebook**, um Prozesse außerhalb von Standard-Windows-Verzeichnissen aufzuspüren:

```sql
SELECT Pid, Ppid, Name, Exe, CommandLine
FROM pslist()
WHERE Exe =~ "(?i)(Users\\\\Public|AppData\\\\Local\\\\Temp|ProgramData)"
```

Zudem stehen sofort einsatzbereite Standard-Artefakte zur Verfügung:
- **`Windows.Sys.StartupItems`**: listet Autostart-Einträge sowie `Run`/`RunOnce`-Schlüssel auf.
- **`Windows.Network.NetstatEnriched`**: verknüpft aktive TCP/UDP-Verbindungen mit Prozess-ID und Namen.
- **`Windows.Detection.Amcache`**: prüft kürzlich ausgeführte Binärdateien auf dem Endpoint.

---

## 6. Kontroll-Mapping und Best Practices

| Framework | Referenz | Praktische Anwendung |
|---|---|---|
| **NIST SP 800-86** | *Guide to Integrating Forensic Techniques into Incident Response* | Standardisierte Erfassung flüchtiger und nicht-flüchtiger Artefakte. |
| **NIST CSF** | `DE.AE-02` / `RS.AN-01` | Forensische Analyse anomaler Ereignisse auf Endpoints. |
| **ISO/IEC 27001:2022** | `A.5.28` (*Collection of Evidence*) | Identifikation, Sammlung und Sicherung digitaler Beweismittel. |

---

## Referenzen

- [Velociraptor — Official Documentation & VQL Reference](https://docs.velociraptor.app/)
- [Microsoft Learn — Install WSL 2 on Windows Enterprise](https://learn.microsoft.com/en-us/windows/wsl/install)
- [NIST SP 800-86 — Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final)

