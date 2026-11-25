---
title: "Trivy im lokalen Labor mit Docker und WSL2: CVEs, Secrets und SBOM scannen"
description: "Praxisleitfaden zur lokalen Nutzung von Trivy in WSL2 und Docker (Windows Enterprise) für Schwachstellen-Scans, Secret-Erkennung und SBOM-Erstellung."
date: 2026-11-25
categoria: Compliance
tags: [trivy, sbom, devsecops, docker, wsl2, open-source, secrets, compliance]
nivel: Intermediário
draft: false
---

> **TL;DR:** Bevor ein Docker-Image im SOC-Labor oder produktiv eingesetzt wird, verhindert die Prüfung auf kritische CVEs, versehentlich eingebundene *Secrets* und die Erstellung eines **SBOM** (*Software Bill of Materials*) Risiken in der Lieferkette. Dieser Leitfaden zeigt, wie Sie **Trivy** lokal in WSL2 (Windows Enterprise) ohne Datenabfluss an externe Dienste nutzen.

---

## 1. Warum Images und Repositories lokal mit Trivy prüfen?

Container in WSL2 beschleunigen Tests von Tools wie Keycloak, Wazuh oder Shuffle enorm. Veraltete Images oder unachtsam gepflegte `compose.yml`-Dateien können jedoch anfällige Bibliotheken oder versehentlich offengelegte *Secrets* enthalten.

**Trivy** (*Open-Source*-Projekt von Aqua Security) vereint in einem einzigen Werkzeug:
- **Schwachstellen-Scan (CVEs)** in OS-Paketen (Debian, Alpine, Ubuntu) und App-Abhängigkeiten (`npm`, `pip`, `go`).
- **Secret-Erkennung (*Secret Scanning*)** in Dateisystemen, Git-Repositories und Docker-Image-Layern.
- **SBOM-Generierung** in den Audit-Formaten **CycloneDX** und **SPDX** (Linux Foundation).
- **Prüfung auf Fehlkonfigurationen** in `Dockerfile`, `compose.yml` und Kubernetes-Manifesten.

---

## 2. Voraussetzungen und Isolation in WSL2

| Komponente | Mindestanforderung | Hinweis |
|---|---|---|
| **Host-System** | Windows 10/11 Enterprise mit WSL2 | Aktuelles Ubuntu 22.04/24.04 in WSL2. |
| **Container Engine** | Docker Desktop oder Docker Engine in WSL2 | Lokaler Docker-Socket im WSL2-Terminal verfügbar. |
| **Ausführungsmodus** | Offizielles Image `aquasec/trivy` oder lokales Binary | CVE-Datenbank lokal unter `~/.cache/trivy` gecacht. |

---

## 3. Docker-Images scannen und Secrets lokal aufspüren

Um ein bereits lokal geladenes Docker-Image ohne Host-Installation zu prüfen, binden Sie den Docker-Socket schreibgeschützt ein:

```bash
mkdir -p ~/.cache/trivy
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v ~/.cache/trivy:/root/.cache/ \
  aquasec/trivy:latest image --severity HIGH,CRITICAL nginx:alpine
```

Um ein lokales Projektverzeichnis (z. B. `compose.yml`, Skripte und `Dockerfile`) vor einem Commit auf *hardcoded Secrets* und Fehlkonfigurationen zu prüfen:

```bash
docker run --rm \
  -v $(pwd):/workspace:ro \
  -v ~/.cache/trivy:/root/.cache/ \
  aquasec/trivy:latest fs --scanners vuln,misconfig,secret /workspace
```

> **Air-Gap-Tipp:** Nach dem ersten Download der Schwachstellen-Datenbank lässt sich Trivy komplett offline ausführen — fügen Sie einfach `--skip-db-update --offline-scan` und `--network none` zu `docker run` hinzu.

---

## 4. SBOM (CycloneDX / SPDX) für Audits und Compliance erstellen

Audits zur Software-Lieferkette (ISO 27001, SOC 2 oder NIST SSDF) verlangen ein formales Komponentenverzeichnis. Erstellen Sie ein **SBOM** im Format **CycloneDX JSON** mit einem einzigen Befehl:

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v $(pwd):/output \
  -v ~/.cache/trivy:/root/.cache/ \
  aquasec/trivy:latest image --format cyclonedx --output /output/sbom-lab.cdx.json nginx:alpine
```

Die Datei `sbom-lab.cdx.json` listet sämtliche Bibliotheken, Versionen und Lizenzen des Images auf und dient als belastbarer Compliance-Nachweis.

---

## 5. Beispiel einer lokalen Policy für Pre-Commit oder Pipelines

In lokalen Skripten oder CI/CD-Pipelines lässt sich der Build automatisch abbrechen, sobald offene *Secrets* oder behebbare kritische CVEs (`--ignore-unfixed`) vorliegen:

```bash
trivy fs --exit-code 1 --severity CRITICAL --ignore-unfixed --scanners vuln,secret .
```

So gelangen weder *Client Secrets* noch kritisch verwundbare Images in geteilte Testumgebungen.

---

## 6. Kontroll-Mapping und Best Practices

| Framework | Referenz | Praktische Anwendung |
|---|---|---|
| **NIST SP 800-218 (SSDF)** | `PW.4` / `RV.1` | Kontinuierliche Prüfung von Drittkomponenten und Pflege eines SBOM-Inventars. |
| **NIST CSF** | `ID.AM-02` / `PR.DS-05` | Software-Inventarisierung und Schutz vor *Secret*-Lecks im Quellcode. |
| **ISO/IEC 27001:2022** | `A.8.8` / `A.8.28` | Management technischer Schwachstellen und sichere Entwicklung. |

---

## Referenzen

- [Aqua Security — Trivy Official Documentation](https://trivy.dev/latest/)
- [Microsoft Learn — Install WSL 2 on Windows Enterprise](https://learn.microsoft.com/en-us/windows/wsl/install)
- [NIST SP 800-218 — Secure Software Development Framework (SSDF)](https://csrc.nist.gov/pubs/sp/800/218/final)
- [Linux Foundation — SPDX & CycloneDX Standards](https://spdx.dev/)

