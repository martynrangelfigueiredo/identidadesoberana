---
title: "Smallstep (step-ca) in Docker und WSL2: Interne PKI, ACME und kurzlebige Zertifikate"
description: "Praxisleitfaden für eine lokale PKI mit Smallstep step-ca in Docker und WSL2 (Windows Enterprise) zur Ausstellung von ACME- und mTLS-Zertifikaten."
date: 2026-11-26
categoria: IAM
tags: [pki, mtls, acme, smallstep, zero-trust, docker, wsl2, open-source]
nivel: Intermediário
draft: false
---

> **TL;DR:** Interne SOC- und IAM-Dienste im Labor (Keycloak, Wazuh, Automations-APIs) laufen oft über einfaches HTTP oder selbstsignierte Zertifikate ohne Vertrauenskette. Dieser Leitfaden zeigt, wie Sie mit **Smallstep (`step-ca`)** in Docker und WSL2 eine interne Zertifizierungsstelle (CA) aufbauen, kurzlebige Zertifikate per **ACME** ausstellen und **mTLS** ohne öffentliche CAs nutzen.

---

## 1. Warum eine interne PKI im Zero-Trust-Labor betreiben?

In Unternehmensumgebungen und lokalen WSL2-Laboren unter Windows Enterprise führen einzelne selbstsignierte Zertifikate zu ständigen Browser-Warnungen, brechen OIDC-/SAML-Integrationen und gewöhnen Teams daran, TLS-Fehler wegzuklicken. Öffentliche Zertifikate für interne Hosts (`*.lab.local`) wiederum legen interne Hostnamen in öffentlichen *Certificate-Transparency*-Logs offen.

**Smallstep (`step-ca`)** löst dieses Problem mit einer schlanken *Open-Source*-PKI:
- **Native ACME-Unterstützung (RFC 8555):** Reverse Proxies wie Caddy, Traefik oder Nginx erneuern interne Zertifikate vollautomatisch.
- **Kurzlebige Zertifikate:** Standardgültigkeit von 24 Stunden (oder weniger) minimiert den Schaden bei kompromittierten privaten Schlüsseln.
- **mTLS (*Mutual TLS*):** Starke gegenseitige Authentifizierung zwischen Microservices, Log-Kollektoren und APIs ohne statische *Secrets*.
- **100 % lokaler Betrieb:** Die gesamte Hierarchie (Root CA und Intermediate CA) verbleibt lokal im WSL2-Laborverzeichnis.

---

## 2. Voraussetzungen und Isolation in WSL2

| Komponente | Mindestanforderung | Hinweis |
|---|---|---|
| **Host-System** | Windows 10/11 Enterprise mit WSL2 | Aktuelles Ubuntu 22.04/24.04 in WSL2. |
| **Container Engine** | Docker Desktop oder Docker Engine in WSL2 | Dediziertes lokales Labor-Netzwerk. |
| **Offizielles Image** | `smallstep/step-ca` und `smallstep/step-cli` | Bindung strikt auf `127.0.0.1`, Port `9000`. |

---

## 3. step-ca mit Docker Compose im Loopback starten

Erstellen Sie ein Laborverzeichnis und definieren Sie `compose.yml` mit strikter Bindung an die Loopback-Schnittstelle (`127.0.0.1`), um keine Ports im externen Windows-Netzwerk freizugeben:

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

Starten Sie den Dienst und verfolgen Sie die Initialisierung von Root CA und Intermediate CA:

```bash
mkdir -p ~/lab-pki && cd ~/lab-pki
docker compose up -d
docker compose logs -f step-ca
```

Beim ersten Start erzeugt der Container automatisch ein Zufallspasswort für den CA-Schlüssel im Volume `step_data` (unter `/home/step/secrets/password`). Notieren Sie den im Log angezeigten *Fingerprint* der Root CA zur Client-Verifizierung.

---

## 4. ACME-Provisioner aktivieren und Zertifikate ausstellen

Damit Reverse Proxies und lokale Dienste Zertifikate automatisch über **ACME** anfordern können, fügen Sie den ACME-Provisioner im Container hinzu:

```bash
docker exec -it lab-step-ca step ca provisioner add acme --type ACME
docker compose restart step-ca
```

Prüfen Sie anschließend den Health-Endpunkt und die aktiven Provisioner:

```bash
curl -sk https://127.0.0.1:9000/health
docker exec -it lab-step-ca step ca provisioner list
```

### Serverzertifikat bei Bedarf ausstellen

Um schnell ein 24 Stunden gültiges TLS-Zertifikat für einen lokalen Dienst (z. B. `keycloak.lab.local`) zu erzeugen:

```bash
docker exec -it lab-step-ca step ca certificate \
  "keycloak.lab.local" \
  /home/step/keycloak.crt \
  /home/step/keycloak.key \
  --provisioner admin@lab.local \
  --password-file /home/step/secrets/password
```

Extrahieren Sie das öffentliche Root-Zertifikat (`root_ca.crt`), um es gezielt in Ihrer Laborumgebung zu verwenden:

```bash
docker cp lab-step-ca:/home/step/certs/root_ca.crt ./root_ca.crt
```

In Ubuntu/WSL2 testen Sie die Vertrauenskette mit `curl` direkt gegen die Labor-CA, ohne das gesamte System zu verändern:

```bash
curl --cacert ./root_ca.crt https://127.0.0.1:9000/health
```

---

## 5. Sicherheits-Best-Practices und mTLS

| Kontrolle | Praktische Empfehlung | Nutzen |
|---|---|---|
| **Kurze Laufzeiten** | Serverzertifikate auf 12–24 Stunden begrenzen und per ACME automatisch erneuern. | Reduziert Abhängigkeit von großen CRLs und begrenzt Missbrauchsfenster. |
| **Root-CA-Schutz** | Root-CA-Schlüssel isolieren; Ausstellung ausschließlich über die Intermediate CA. | Ermöglicht Rotation der Intermediate CA ohne Neuverteilung der Root CA. |
| **mTLS zwischen Diensten** | Client-Zertifikate derselben internen CA für Admin-APIs erzwingen. | Verhindert Lateral Movement selbst bei erreichbaren internen Ports. |
| **Volume-Hygiene** | Zugriffsrechte auf `step_data` einschränken und `/home/step/secrets/` niemals in Git einchecken. | Schützt den privaten Schlüssel der Zertifizierungsstelle. |

---

## 6. Kontroll-Mapping und Referenzen

- **Smallstep-Dokumentation:** [step-ca Overview & ACME Provisioner](https://smallstep.com/docs/step-ca/)
- **Microsoft Learn (WSL2):** [Offizielle Dokumentation zu Windows Subsystem for Linux](https://learn.microsoft.com/en-us/windows/wsl/)
- **IETF RFC 8555:** Automatic Certificate Management Environment (ACME)
- **NIST SP 800-57 / CSF 2.0 (`PR.DS-02`):** Schutz von Daten während der Übertragung durch starke Kryptografie und Schlüssel-Lifecycle-Management.
- **CIS Controls v8 (`3.10` / `12.2`):** Verschlüsselung von Daten im Transit und sichere Netzwerkarchitektur mit mTLS.
