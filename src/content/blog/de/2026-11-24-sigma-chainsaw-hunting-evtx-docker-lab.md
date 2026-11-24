---
title: "Sigma und Chainsaw im lokalen WSL2-Labor: Schnelles Hunting in EVTX-Logs unter Windows Enterprise"
description: "Praxisleitfaden zur lokalen Nutzung von Sigma-Regeln und Chainsaw in WSL2/Docker für schnelle DFIR-Analysen von Windows-EVTX-Dateien ohne Cloud-SIEM."
date: 2026-11-24
categoria: SOC
tags: [sigma, chainsaw, evtx, detection-as-code, docker, wsl2, open-source, soc]
nivel: Intermediário
draft: false
---

> **TL;DR:** Bei der Incident Response auf Windows-Workstations lagen zum Angriffszeitpunkt nicht immer alle Logs vollständig im SIEM vor. Dieser Leitfaden zeigt, wie Sie das offene **Sigma**-Format gemeinsam mit **Chainsaw** lokal in WSL2 (Windows Enterprise) nutzen, um `.evtx`-Dateien in Sekunden auf Persistenz, Lateral Movement und Abwehr-*Bypass* zu durchsuchen.

---

## 1. Warum Sigma und Chainsaw im SOC-Labor kombinieren?

**Sigma** ist der universelle Open-Source-Standard für *Detection as Code*, um Erkennungsregeln herstellerunabhängig in YAML zu beschreiben. **Chainsaw** (von WithSecure Labs in Rust entwickelt) wendet Hunderte Sigma-Regeln direkt auf native Windows-Event-Log-Dateien (`.evtx`) an — ohne dass für die Erst-Triage ein komplettes SIEM aufgebaut werden muss.

Der lokale Betrieb in **WSL2** (oder in einem isolierten Docker-Container ohne Internetzugriff) bietet klare Vorteile:
- Sehr schnelle forensische Auswertung von `Security.evtx`, `Microsoft-Windows-PowerShell%4Operational.evtx` und `Sysmon.evtx`.
- Portabilität derselben Regeln in Produktionsumgebungen (Wazuh, Elastic oder KQL-Konvertierungen für Microsoft Sentinel).
- Volle Datenkontrolle: Gesammelte Vorfallslogs verlassen niemals das lokale System.

---

## 2. Voraussetzungen und Labor-Architektur

| Komponente | Mindestanforderung | Hinweis |
|---|---|---|
| **Host-System** | Windows 10/11 Enterprise mit WSL2 | Aktuelles Ubuntu 22.04/24.04 in WSL2. |
| **Analyse-Engine** | Chainsaw (Linux-Binary oder Docker-Container) | In Rust geschrieben; geringer RAM-Bedarf. |
| **Regelbasis** | Offizielles `SigmaHQ/sigma`-Repository | Offene YAML-Regeln mit MITRE-ATT&CK-Mapping. |

---

## 3. Isolierte Umgebung in WSL2 und Docker vorbereiten

Erstellen Sie ein Verzeichnis in WSL2 für Sigma-Regeln und exportierte `.evtx`-Dateien von Testsystemen:

```bash
mkdir -p ~/dfir-labs/chainsaw/evtx ~/dfir-labs/chainsaw/rules
cd ~/dfir-labs/chainsaw
```

Laden Sie die offiziellen Sigma-Regeln herunter (oder binden Sie eine bereits geprüfte Offline-Kopie ein):

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma.git rules/sigma
```

Falls Sie Chainsaw in einem kurzlebigen Container ohne Host-Installation ausführen möchten, erstellen Sie ein schlankes `Dockerfile`:

```dockerfile
FROM rust:1.82-slim AS builder
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
RUN cargo install chainsaw

FROM debian:bookworm-slim
COPY --from=builder /usr/local/cargo/bin/chainsaw /usr/local/bin/chainsaw
WORKDIR /workspace
ENTRYPOINT ["chainsaw"]
```

Image lokal bauen:

```bash
docker build -t local/chainsaw:latest .
```

---

## 4. Test-EVTX-Logs kopieren und Hunting starten

Kopieren Sie im Testlabor unter Windows Enterprise die Event-Logs in das WSL2-Verzeichnis (in PowerShell mit Adminrechten im Testsystem):

```powershell
Copy-Item "C:\Windows\System32\Winevt\Logs\Security.evtx" "\\wsl$\Ubuntu\home\$env:USERNAME\dfir-labs\chainsaw\evtx\"
Copy-Item "C:\Windows\System32\Winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx" "\\wsl$\Ubuntu\home\$env:USERNAME\dfir-labs\chainsaw\evtx\"
```

Führen Sie anschließend den Scan vollständig offline (`--network none`) mit den Windows-Sigma-Regeln aus:

```bash
docker run --rm --network none \
  -v ~/dfir-labs/chainsaw/evtx:/evtx:ro \
  -v ~/dfir-labs/chainsaw/rules/sigma:/sigma:ro \
  local/chainsaw:latest hunt /evtx \
  -s /sigma/rules/windows \
  --mapping /sigma/tools/config/generic/windows-audit.yml \
  --json --output /evtx/findings.json
```

> **Praxis-Tipp:** Für eine schnelle Terminal-Tabelle statt JSON lassen Sie `--json --output ...` einfach weg; Chainsaw gibt dann Zeitstempel, Event-ID, ausgelöste Regel und `CommandLine` bzw. `TargetUserName` übersichtlich aus.

---

## 5. Beispiel einer eigenen Sigma-Regel für geplante Aufgaben

Eigene YAML-Regeln in `~/dfir-labs/chainsaw/rules/custom/` erkennen z. B. Persistenz über `schtasks.exe` (`MITRE ATT&CK T1053.005`):

```yaml
title: Scheduled Task Creation Pointing to Temp Directory
id: 7b4e1a20-8f12-4c9a-9c2e-11a2b3c4d5e6
status: experimental
description: Detects schtasks creating tasks that execute binaries inside AppData or Temp.
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith: '\schtasks.exe'
  selection_cmd:
    CommandLine|contains|all:
      - '/create'
    CommandLine|contains:
      - '\AppData\'
      - '\Users\Public\'
      - '\Temp\'
  condition: selection_img and selection_cmd
level: high
tags:
  - attack.persistence
  - attack.t1053.005
```

Dieselbe YAML-Regel lässt sich später mit `sigma-cli` problemlos für Wazuh oder KQL in Microsoft Sentinel konvertieren.

---

## 6. Kontroll-Mapping und Best Practices

| Framework | Referenz | Praktische Anwendung |
|---|---|---|
| **MITRE ATT&CK** | `T1053.005` / `T1059.001` | Standardisierte Erkennung geplanter Aufgaben und verschleierter PowerShell-Ausführung. |
| **NIST SP 800-86** | *Guide to Integrating Forensic Techniques into Incident Response* | Strukturierte Auswertung von OS-Event-Logs bei der DFIR-Triage. |
| **CIS Controls v8** | `8.2` / `8.5` | Erfassung und Prüfung detaillierter Prozess- und Sicherheits-Audit-Logs unter Windows. |

---

## Referenzen

- [Microsoft Learn — Install WSL 2 on Windows Enterprise](https://learn.microsoft.com/en-us/windows/wsl/install)
- [Microsoft Learn — Advanced security auditing in Windows](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing-faq)
- [SigmaHQ — Sigma Generic Signature Format](https://sigmahq.io/)
- [WithSecure Labs — Chainsaw EVTX Hunting Tool](https://github.com/WithSecureLabs/chainsaw)

