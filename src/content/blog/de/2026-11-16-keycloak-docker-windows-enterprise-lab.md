---
title: "Lokales IAM-Labor: Keycloak unter Windows Enterprise mit Docker und WSL 2 einrichten"
description: "Praxisleitfaden zur Einrichtung eines lokalen IAM-Labors unter Windows Enterprise mit Docker Desktop, WSL 2, Keycloak 26 und persistentem PostgreSQL."
date: 2026-11-16
categoria: IAM
tags: [keycloak, iam, docker, windows-enterprise, wsl2, lab, oidc, open-source]
nivel: Mittelstufe
---

Für SOC-Analysten, Identity Engineers und Compliance-Verantwortliche ist das Verständnis von Single Sign-On (SSO), OIDC-Föderation und Zugriffskontrollen essenziell. Authentifizierungs- und MFA-Workflows direkt in Produktiv-Tenants von Enterprise-Clouds zu testen, ist jedoch oft mit hohen Risiken und administrativen Hürden verbunden.

Der Aufbau eines lokalen Labors mit **Keycloak** — dem branchenweiten Open-Source-Standard für Identitäts- und Zugriffsmanagement — ermöglicht es, komplexe Authentifizierungsabläufe und Zero-Trust-Architekturen vollständig offline und ohne Cloud-Kosten zu simulieren.

> **TL;DR für das Labor:** Um Keycloak 26+ mit PostgreSQL unter Windows Enterprise ressourcenschonend zu betreiben, beschränken Sie den WSL 2-Arbeitsspeicher in der Datei `.wslconfig` auf 4 GB bis 6 GB, nutzen Sie die WSL 2-Engine in Docker Desktop und starten Sie den Stack im Entwicklungsmodus (`start-dev`) mit benannten Volumes.

> 📘 **Offizielle Referenz:** Dieser Leitfaden basiert auf der offiziellen Dokumentation des Keycloak-Projekts sowie Standards der Linux Foundation / CNCF:
> - [Keycloak — Running Keycloak in a container (Official Guides)](https://www.keycloak.org/guides#server)
> - [Keycloak — Getting started with Keycloak and Docker](https://www.keycloak.org/getting-started/getting-started-docker)

---

## 1. Warum dieses Labor unter Windows Enterprise betreiben?

Auf modernen Unternehmens-Workstations mit Windows 10/11 Enterprise stehen Hyper-V und WSL 2 standardmäßig zur Verfügung. Die Vorteile einer containerisierten Laborumgebung liegen auf der Hand:

1. **Vollständige lokale Isolation:** Keine Anmeldedaten, Kennwort-Hashes oder Token verlassen Ihre lokale Workstation.
2. **Keine Lizenzkosten:** Keycloak steht unter der Apache 2.0-Lizenz und bildet die technologische Basis des Red Hat build of Keycloak (ehemals RH-SSO).
3. **Konformität zu Industriestandards:** Dieselben Protokolle, die auch in Microsoft Entra ID genutzt werden (OpenID Connect, OAuth 2.0, SAML 2.0), lassen sich im Keycloak im Detail analysieren.

---

## 2. Wesentliche Optimierung: WSL 2-Speicherverbrauch begrenzen

WSL 2 reserviert standardmäßig dynamisch bis zu 50 % oder mehr des physischen Arbeitsspeichers. Um Leistungseinbrüche auf Unternehmens-Laptops zu vermeiden, konfigurieren Sie die Datei `.wslconfig` in Ihrem Windows-Benutzerverzeichnis:

1. Öffnen Sie die PowerShell und bearbeiten Sie die Konfiguration:
   ```powershell
   notepad "$env:USERPROFILE\.wslconfig"
   ```
2. Tragen Sie die folgenden ressourcenschonenden Grenzwerte ein:
   ```ini
   [wsl2]
   memory=4GB       # Maximale RAM-Zuweisung für WSL 2
   processors=2     # CPU-Kerne begrenzen
   swap=2GB         # Linux-Auslagerungsdatei
   localhostForwarding=true
   ```
3. Starten Sie WSL 2 neu, um die Einstellungen wirksam zu machen:
   ```powershell
   wsl --shutdown
   ```

---

## 3. `docker-compose.yml` für das lokale Labor

Erstellen Sie ein Verzeichnis für Ihr Labor (z. B. `mkdir keycloak-lab && cd keycloak-lab`) und legen Sie die folgende `docker-compose.yml` an.

Wir verwenden das offizielle, Quarkus-basierte Keycloak-Image in Verbindung mit einer isolierten PostgreSQL 16-Datenbank:

```yaml
services:
  postgres:
    image: postgres:16-alpine
    container_name: keycloak-db
    restart: unless-stopped
    environment:
      POSTGRES_DB: keycloak
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: keycloak_lab_password_2026
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - keycloak-net
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U keycloak -d keycloak"]
      interval: 10s
      timeout: 5s
      retries: 5

  keycloak:
    image: quay.io/keycloak/keycloak:26.0
    container_name: keycloak-server
    restart: unless-stopped
    command: start-dev
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: keycloak_lab_password_2026
      KC_BOOTSTRAP_ADMIN_USERNAME: admin
      KC_BOOTSTRAP_ADMIN_PASSWORD: admin_lab_password_2026
      KC_HTTP_ENABLED: "true"
      KC_HOSTNAME_STRICT: "false"
      KC_HOSTNAME_STRICT_HTTPS: "false"
    ports:
      - "127.0.0.1:8080:8080"
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - keycloak-net

volumes:
  postgres_data:
    driver: local

networks:
  keycloak-net:
    driver: bridge
```

> 🔒 **Sicherheitshinweis für das Firmennetzwerk:** Durch das Binding an `127.0.0.1:8080:8080` wird verhindert, dass andere Geräte im internen Firmennetzwerk auf Ihren lokalen Keycloak-Server zugreifen können.

---

## 4. Container starten und Administrationskonsole aufrufen

Starten Sie die Umgebung über das Terminal:

```bash
docker compose up -d
```

Überprüfen Sie die Protokolle bis zur Betriebsbereitschaft:

```bash
docker compose logs -f keycloak
```

Sobald die Meldung `Listening on: http://0.0.0.0:8080` erscheint:
1. Rufen Sie im Browser `http://localhost:8080` auf.
2. Klicken Sie auf **Administration Console**.
3. Melden Sie sich mit den Labor-Zugangsdaten an:
   * **Benutzername:** `admin`
   * **Passwort:** `admin_lab_password_2026`

---

## 5. Erste IAM-Konfigurationsschritte

### 1. Dedizierten Realm erstellen
Nutzen Sie niemals den Realm `master` für Anwendungs- oder Benutzertests. Der `master`-Realm dient ausschließlich der Verwaltung von Keycloak selbst.
* Wählen Sie im linken Menü **Create Realm**.
* Tragen Sie `lab-corporativo` ein und bestätigen Sie mit **Create**.

### 2. OIDC-Client anlegen
* Navigieren Sie zu **Clients** > **Create client**.
* **Client type:** `OpenID Connect`.
* **Client ID:** `app-portal-interno`.
* In den **Capability configs**:
  * Aktivieren Sie **Client authentication**, wenn Sie Anwendungssitzungen mit Secrets (*Client Secrets*) testen möchten, oder deaktivieren Sie diese für Public SPAs mit PKCE.
* Unter **Login settings**:
  * **Valid redirect URIs:** `http://localhost:3000/*`.

### 3. Benutzer anlegen und MFA aktivieren
* Gehen Sie auf **Users** > **Add user**.
* Erfassen Sie Testdaten (z. B. Benutzername `colaborador.teste` und E-Mail `colaborador@contoso.com`).
* Setzen Sie unter **Credentials** ein initiales Passwort.
* Fügen Sie unter *Required Actions* die Aktion **Configure OTP** hinzu. Beim nächsten Login erzwingt Keycloak die Kopplung mit einer Authenticator-App (z. B. FreeOTP, Google Authenticator oder Microsoft Authenticator).

---

## 6. Labor stoppen und Daten erhalten

Nach Abschluss Ihrer Tests können Sie die Container stoppen, ohne Ihre Konfiguration zu verlieren:

```bash
# Labor pausieren (Daten bleiben in Docker-Volumes erhalten):
docker compose down

# Am nächsten Tag wieder starten:
docker compose up -d

# Labor vollständig zurücksetzen (löscht alle Volumes):
docker compose down -v
```

