---
title: "SOC-Automatisierung mit Shuffle SOAR: Integration von Wazuh und TheHive in Docker"
description: "Praxisleitfaden zur Bereitstellung von Shuffle SOAR unter Windows Enterprise mit Docker und WSL 2 für automatisierte Workflows zwischen Wazuh SIEM und TheHive."
date: 2026-11-19
categoria: SOC
tags: [shuffle, soar, wazuh, thehive, docker, windows-enterprise, wsl2, lab, open-source, soc]
nivel: Intermediário
---

In den vorherigen Laboren haben wir die Grundpfeiler eines offenen Sicherheitsbetriebs aufgebaut: Identitätsmanagement mit **Keycloak**, Erkennung und Telemetrie mit **Wazuh (SIEM/XDR)** sowie Fallmanagement mit **TheHive und Cortex**. Mit steigendem Alarmvolumen kostet das manuelle Triagieren und Kopieren von Indikatoren zwischen verschiedenen Konsolen jedoch wertvolle Analystenzeit.

Hier setzt **Shuffle** an – eine Open-Source-Plattform für **SOAR (Security Orchestration, Automation, and Response)**, mit der sich Sicherheitstools über REST-APIs, Webhooks und visuelle Workflows verknüpfen lassen, ohne proprietäre Lizenzen oder Datenabfluss an externe Clouds.

In dieser Anleitung erfahren Sie, wie Sie Shuffle unter Windows Enterprise mit Docker Desktop und WSL 2 bereitstellen und Ihren ersten Automatisierungs-Workflow zwischen Wazuh-Warnungen und TheHive-Fällen erstellen.

> **TL;DR für das Labor:** Shuffle nutzt OpenSearch als Datenbank für Ausführungen und Apps. Stellen Sie unter Windows Enterprise mit WSL 2 sicher, dass `vm.max_map_count` auf `262144` gesetzt ist und in `.wslconfig` mindestens 6 GB RAM zugewiesen sind.

> 📘 **Offizielle Referenzen:** Diese Anleitung basiert auf der offiziellen Dokumentation von Shuffle, Wazuh und TheHive:
> - [Shuffle Documentation (shuffler.io)](https://shuffler.io/docs/about)
> - [Shuffle GitHub Repository](https://github.com/Shuffle/Shuffle)
> - [Wazuh Documentation — Integrator](https://documentation.wazuh.com/current/user-manual/manager/manual-integration.html)

---

## 1. Die Rolle von Shuffle in einer offenen SOC-Architektur

Shuffle fungiert als zentrales Nervensystem, das Verteidigungstools über visuelle Playbooks verbindet:

1. **API-basierte Orchestrierung (OpenAPI/Swagger):** Importieren Sie OpenAPI-Spezifikationen nahezu jedes Tools (Wazuh, TheHive, Cortex, Keycloak, Firewalls oder ITSM-Systeme wie Jira), um Endpunkte in wiederverwendbare Bausteine zu verwandeln.
2. **Webhook- und Zeitplan-Trigger:** Empfangen Sie Alarme in Echtzeit per HTTP POST, sobald eine kritische SIEM-Regel auslöst, oder starten Sie periodische Threat-Hunting-Routinen.
3. **Isolierte Ausführung (Orborus & Workers):** Jeder Workflow-Schritt läuft in isolierten Containern, was eine strikte Kontrolle über Zugangsdaten, Secrets und den internen Netzwerkverkehr ermöglicht.

---

## 2. Voraussetzungen unter Windows Enterprise und WSL 2

Wie Wazuh und TheHive verwendet auch Shuffle **OpenSearch**. Falls Sie `.wslconfig` und `vm.max_map_count` bereits in den vorherigen Laboren konfiguriert haben, sind die Parameter schon gesetzt. Überprüfen Sie dies bei Bedarf in PowerShell:

```powershell
wsl -d Ubuntu -u root sysctl -w vm.max_map_count=262144
```

Stellen Sie zudem sicher, dass Docker Desktop Zugriff auf das lokale WSL 2-Netzwerk und mindestens **6 GB RAM** besitzt.

---

## 3. Shuffle SOAR mit Docker Compose starten

Das offizielle Shuffle-Repository bietet ein vollständiges `docker-compose.yml` mit **shuffle-frontend**, **shuffle-backend**, **shuffle-orborus** und **shuffle-opensearch**.

1. Erstellen Sie im WSL 2-Terminal das Arbeitsverzeichnis und klonen Sie das Repository:
   ```bash
   mkdir -p ~/shuffle-lab && cd ~/shuffle-lab
   git clone https://github.com/Shuffle/Shuffle.git --depth=1
   cd Shuffle
   ```

2. Erstellen Sie das Datenbankverzeichnis für OpenSearch mit passenden Berechtigungen:
   ```bash
   mkdir -p shuffle-database
   sudo chown -R 1000:1000 shuffle-database
   ```

3. Prüfen Sie die Datei `.env` und stellen Sie sicher, dass die Web-Ports (`FRONTEND_PORT=3001` und `FRONTEND_PORT_HTTPS=3443`) nicht mit anderen lokalen Diensten kollidieren (z. B. TheHive auf `9000` oder Wazuh auf `443`).

4. Starten Sie die Container im Hintergrund:
   ```bash
   docker compose up -d
   ```

5. Überprüfen Sie den Container-Status:
   ```bash
   docker compose ps
   ```

---

## 4. Erster Zugriff und Admin-Einrichtung

Nach etwa 60 Sekunden für die Initialisierung von OpenSearch:

1. Öffnen Sie im Windows-Browser:
   ```text
   https://localhost:3443
   ```
   *(Akzeptieren Sie das selbstsignierte Labor-Zertifikat; alternativ via HTTP unter `http://localhost:3001`).*

2. Legen Sie im ersten Schritt das Admin-Konto an (z. B. `soc-admin@contoso.com`) mit einem sicheren Labor-Passwort.

3. Wechseln Sie im oberen Menü zu **Workflows**.

---

## 5. Ihr erstes Playbook: Wazuh → Shuffle → TheHive

Wir erstellen einen taktischen Incident-Response-Workflow: Sobald **Wazuh** verdächtige Ereignisse (`rule.level >= 10`) meldet, wird der Alarm an **Shuffle** gesendet, der die Quell-IP extrahiert und automatisch einen Fall in **TheHive** eröffnet.

### Schritt 1: Webhook-Trigger in Shuffle anlegen
1. Erstellen Sie unter **Workflows > New Workflow** den Flow `Wazuh-Auto-Triage-TheHive`.
2. Ziehen Sie einen **Webhook**-Trigger auf die Arbeitsfläche.
3. Kopieren Sie die generierte Webhook-URL (z. B. `http://localhost:5001/api/v1/hooks/webhook_...`).
4. Klicken Sie am Webhook-Knoten auf **Start**, um ihn in den Empfangsmodus zu versetzen.

### Schritt 2: Wazuh für den Versand an Shuffle konfigurieren
Fügen Sie in der Wazuh-Manager-Konfiguration (`/var/ossec/etc/ossec.conf`) einen `<integration>`-Block hinzu:

```xml
<integration>
  <name>custom-shuffle</name>
  <hook_url>http://host.docker.internal:5001/api/v1/hooks/webhook_ihre_id_hier</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

Starten Sie den Wazuh Manager neu, um den automatischen JSON-Versand zu aktivieren.

### Schritt 3: IP extrahieren und Fall in TheHive anlegen
1. Verbinden Sie im Shuffle-Editor den **Webhook**-Knoten mit der nativen **TheHive**-App.
2. Hinterlegen Sie den API-Key Ihres TheHive-Containers (`http://host.docker.internal:9000`) als verschlüsseltes *Secret* in den Shuffle-Authentifizierungseinstellungen.
3. Wählen Sie die Aktion **`Create Case`** und mappen Sie die JSON-Felder:
   - **Title:** `[Wazuh] $exec.all_fields.rule.description`
   - **Severity:** `2` (Mittel)
   - **Description:** `Agent: $exec.all_fields.agent.name | Quell-IP: $exec.all_fields.data.srcip`
   - **Tags:** `["wazuh", "auto-triage", "shuffle"]`
4. Fügen Sie einen zweiten TheHive-Knoten mit **`Create Observable`** hinzu, um `$exec.all_fields.data.srcip` automatisch als Observable vom Typ `ip` anzuhängen.

---

## 6. Sicherheits-Best-Practices und nächste Schritte

Beim Betrieb automatisierter SOAR-Playbooks im Labor oder Produktivbetrieb:

- **Schutz von Secrets:** Speichern Sie API-Keys niemals im Klartext in Code-Blöcken oder manuellen HTTP-Requests; nutzen Sie stets den integrierten Secret-Speicher von Shuffle.
- **Deduplizierung (Loop-Kontrolle):** Prüfen Sie vor dem Anlegen eines neuen TheHive-Falls per Bedingung (`Branch / Condition`), ob innerhalb der letzten 24 Stunden bereits ein offener Fall für dieselbe IP existiert.
- **Erweiterung:** Verknüpfen Sie direkt nach der Observable-Erstellung die **Cortex**-App, um automatisch Threat-Intel-Analyzer auszuführen und das SOC-Team erst bei bestätigtem Risiko zu benachrichtigen.
