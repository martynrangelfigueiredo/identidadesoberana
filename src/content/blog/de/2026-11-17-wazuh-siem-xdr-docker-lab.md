---
title: "SIEM und XDR mit Wazuh: Lokale Bereitstellung auf Windows Enterprise via Docker"
description: "Schritt-für-Schritt-Anleitung zur Bereitstellung von Wazuh (Manager, Indexer und Dashboard) unter Windows Enterprise mit Docker Desktop und WSL 2 für praxisnahe SOC-Tests."
date: 2026-11-17
categoria: SOC
tags: [wazuh, siem, xdr, docker, windows-enterprise, wsl2, lab, open-source, soc]
nivel: Intermediário
---

Für SOC-Analysten, Detection Engineers und Incident Responder ist das Verständnis dafür, wie Logs gesammelt, decodiert und korreliert werden, genauso wichtig wie die Beherrschung von Cloud-Plattformen. In vielen Fällen verbieten Unternehmensrichtlinien jedoch das Testen neuer Erkennungsregeln, Defense-Evasion-Skripte oder simulierter Angriffe in produktiven Umgebungen.

Der Aufbau eines lokalen **Wazuh**-Labors — der weltweit meistgenutzten Open-Source-Plattform für **SIEM (Security Information and Event Management)** und **XDR (Extended Detection and Response)** — ermöglicht es, Endpoint-Telemetrie in Echtzeit zu analysieren, eigene Regeln zu testen und taktische Alarme zu untersuchen, ohne externe Telemetrie zu übertragen oder Lizenzkosten zu verursachen.

> **TL;DR für das Labor:** Um den vollständigen Wazuh-Stack (Manager, Indexer und Dashboard) unter Windows Enterprise über Docker auszuführen, konfigurieren Sie WSL 2 mit mindestens 6 GB RAM und setzen Sie den Linux-Kernelparameter `vm.max_map_count` auf `262144`, damit die OpenSearch-Suchmaschine fehlerfrei startet.

> 📘 **Offizielle Referenz:** Dieser Leitfaden basiert auf der offiziellen Wazuh-Dokumentation:
> - [Wazuh Documentation — Deployment with Docker](https://documentation.wazuh.com/current/deployment-options/docker/index.html)
> - [Wazuh Agent installation on Windows endpoints](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html)

---

## 1. Warum Wazuh lokal auf Unternehmens-Workstations betreiben?

In Unternehmensumgebungen mit Windows 10/11 Enterprise verfügen Sicherheitsanalysten typischerweise über leistungsfähige Multi-Core-Prozessoren und 16 GB bis 32 GB RAM. Der Einsatz von Docker Desktop mit WSL 2 bietet entscheidende Vorteile:

1. **Vollständige Datensouveränität und lokale Isolation:** Sämtliche Test-Ereignisse, Hashes und Logdateien verbleiben strikt auf Ihrer lokalen Maschine (localhost).
2. **Vollständiger SIEM- und XDR-Zyklus:** Wazuh vereint zentrale Log-Analyse, Dateiintegritätsüberwachung (FIM), Schwachstellenerkennung und automatisierte aktive Reaktionen in einer einheitlichen Konsole.
3. **Natives MITRE ATT&CK-Mapping:** Jeder in Wazuh generierte Alarm wird automatisch den entsprechenden Taktiken und Techniken des MITRE ATT&CK-Frameworks zugeordnet.

---

## 2. Erforderliche Anpassungen in Windows Enterprise und WSL 2

Der Wazuh Indexer basiert auf OpenSearch und benötigt spezielle Speicherkonfigurationen in WSL 2, um Abbrüche durch Speichermangel (OOM) zu vermeiden.

### Schritt 1: RAM-Limit in `.wslconfig` anpassen
Öffnen Sie in Windows die globale Konfigurationsdatei für WSL 2 über PowerShell:

```powershell
notepad "$env:USERPROFILE\.wslconfig"
```

Hinterlegen Sie die empfohlenen Grenzwerte:

```ini
[wsl2]
memory=6GB            # Empfohlenes Minimum für den Wazuh Single-Node-Stack
processors=4          # Zuweisung von 4 virtuellen Prozessorkernen
swap=2GB              # Auslagerungsdatei auf der Festplatte
localhostForwarding=true
```

### Schritt 2: `vm.max_map_count` in WSL 2 konfigurieren
OpenSearch verlangt, dass das Linux-Subsystem mindestens 262.144 gemappte Speicherbereiche unterstützt. Führen Sie im WSL 2-Terminal oder via PowerShell aus:

```powershell
wsl -d Ubuntu -u root sysctl -w vm.max_map_count=262144
```

Um diese Einstellung dauerhaft zu speichern, fügen Sie die Zeile in `/etc/sysctl.conf` ein:

```bash
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

Starten Sie WSL neu, um die Änderungen zu aktivieren:

```powershell
wsl --shutdown
```

---

## 3. Bereitstellung des Wazuh Single-Node-Stacks mit Docker Compose

Das offizielle Wazuh-Repository stellt ein Single-Node Docker Compose-Template bereit, das sich ideal für Test-Workstations eignet.

1. Klonen Sie im WSL 2-Terminal das offizielle Repository:
   ```bash
   git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.2 --depth=1
   cd wazuh-docker/single-node
   ```

2. Generieren Sie die internen TLS-Zertifikate für die verschlüsselte Kommunikation der Komponenten:
   ```bash
   docker compose -f generate-indexer-certs.yml run --rm generator
   ```

3. Starten Sie die drei Hauptdienste im Hintergrund:
   ```bash
   docker compose up -d
   ```

4. Überprüfen Sie den Status der Container:
   ```bash
   docker compose ps
   ```

Folgende Dienste sind aktiv:
- **`single-node-wazuh.manager-1`:** Regelverarbeitung, Decodierung und Agent-Kommunikation (Ports 1514/TCP, 1515/TCP und 55000/TCP).
- **`single-node-wazuh.indexer-1`:** OpenSearch-Engine für die Indexierung (Port 9200/TCP).
- **`single-node-wazuh.dashboard-1`:** Web-Oberfläche für Analysten (Port 443/TCP).

---

## 4. Zugriff auf die Konsole und Agent-Registrierung unter Windows

Nach ca. 2 Minuten Initialisierungszeit:

1. Öffnen Sie Ihren Browser unter Windows und navigieren Sie zu:
   ```text
   https://localhost
   ```
2. Akzeptieren Sie die Warnung wegen des selbstsignierten Zertifikats (Laborumgebung).
3. Melden Sie sich mit den Standard-Zugangsdaten an:
   - **Benutzer:** `admin`
   - **Passwort:** `SecretPassword***` (kann vorab in der `.env`-Datei angepasst werden).

### Installation des Wazuh Agents auf dem Windows-Host

Damit Ihr Labor echte Sicherheits-Telemetrie Ihres Windows-Betriebssystems erfasst:

1. Laden Sie das offizielle Wazuh Agent MSI-Paket herunter.
2. Öffnen Sie PowerShell als Administrator und installieren Sie den Agenten mit Ziel auf Ihren lokalen Container:
   ```powershell
   .\wazuh-agent-4.9.2-1.msi /q WAZUH_MANAGER="127.0.0.1" WAZUH_REGISTRATION_SERVER="127.0.0.1" WAZUH_AGENT_NAME="WIN-LAB-ENTERPRISE"
   ```
3. Starten Sie den Agenten-Dienst:
   ```powershell
   NET START WazuhSvc
   ```
4. Im Wazuh Dashboard erscheint der Agent unter **Endpoints Summary** nach wenigen Sekunden mit dem Status **Active**.

---

## 5. Praktische Erkennungssimulation im SOC

Sobald der Agent aktiv ist und die Windows-Ereignisprotokolle (*Security Event Log* und *Sysmon*) überwacht:

1. **Simulation:** Führen Sie in einer Eingabeaufforderung typische Reconnaissance-Befehle aus:
   ```cmd
   net user Administrator
   net localgroup Administrators
   ```
2. **Inspektion im Dashboard:**
   - Öffnen Sie **Wazuh Dashboard > Security events**.
   - Filtern Sie in der OpenSearch-Suchleiste nach:
     ```lucene
     agent.name: "WIN-LAB-ENTERPRISE" AND rule.level: >= 3
     ```
   - Wazuh korreliert die Windows-Audit-Ereignisse (IDs 4798 und 4799 — Enumeration lokaler Gruppen) direkt mit der MITRE ATT&CK-Technik **T1087 (Account Discovery)**.

3. **Eigene Erkennungsregel definieren:**
   In der Konfigurationsdatei des Managers (`/var/ossec/etc/rules/local_rules.xml`) können Sie eigene Erkennungen definieren, z. B. für den Aufruf von `whoami /priv`:
   ```xml
   <group name="windows,powershell,">
     <rule id="100002" level="7">
       <if_sid>60103</if_sid>
       <field name="win.eventdata.commandLine">whoami /priv</field>
       <description>Lokale Privilegien-Enumeration erkannt: whoami /priv</description>
       <mitre>
         <id>T1033</id>
       </mitre>
     </rule>
   </group>
   ```

---

## 6. Nächste Schritte im offenen Sicherheitslabor

Mit Wazuh auf Docker Desktop verfügen Sie über ein vollständiges SIEM- und XDR-System für:
- Die Anbindung von Logs weiterer Container (wie dem zuvor erstellten Keycloak-Labor).
- Das Testen automatisierter SOAR-Playbooks mit **Shuffle** oder **TheHive**.
- Das Simulieren von Bypass-Techniken und Verfeinern Ihrer Detection Engineering-Fähigkeiten ohne Risiko für Unternehmensnetzwerke.
