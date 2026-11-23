---
title: "Authentik im lokalen Labor mit Docker und WSL2: SSO, OIDC und MFA-Richtlinien für das Team"
description: "Schritt-für-Schritt-Anleitung zur lokalen Bereitstellung von Authentik via Docker in WSL2 (Windows Enterprise) inklusive OIDC, Passkeys und Event-Auditing."
date: 2026-11-23
categoria: IAM
tags: [authentik, iam, oidc, sso, mfa, docker, wsl2, open-source]
nivel: Intermediário
draft: false
---

> **TL;DR:** Moderne Authentifizierungsflows (*OIDC*, *SAML*, *Passkeys* und bedingte Zugriffsrichtlinien) lokal zu testen beschleunigt jedes IAM-Projekt. Dieser Leitfaden zeigt, wie Sie **Authentik** isoliert mit Docker und WSL2 unter Windows Enterprise starten, einen OIDC-Provider einrichten und Authentifizierungs-Logs auswerten.

---

## 1. Warum Authentik im lokalen Labor testen?

**Authentik** ist ein flexibler *Open-Source*-Identity-Provider (*IdP*) für hybride Umgebungen und interne Anwendungen. Mit nativer Unterstützung für **OIDC**, **SAML 2.0**, **LDAP**, **SCIM** und **WebAuthn/FIDO2** können IAM-Engineers und Sicherheitsanalysten Folgendes validieren:
- Visuelle Authentifizierungs-*Flows*, inklusive Reputationsprüfungen oder Phishing-resistenter MFA (*Passkey*).
- Ausstellung von JWT-Tokens für SOC-Tools (wie Shuffle, Wazuh Dashboard oder interne Portale).
- Strukturierte Audit-Events für jede Anmeldung und administrative Änderung zur Korrelation im SIEM.

Der Betrieb in **lokaler Isolation** (`127.0.0.1`) in WSL2 garantiert volle Kontrolle über *Client Secrets* und Testzertifikate ohne Exposition im Unternehmensnetz.

---

## 2. Voraussetzungen und Labor-Architektur

| Komponente | Mindestanforderung | Hinweis |
|---|---|---|
| **Host-System** | Windows 10/11 Enterprise mit WSL2 | Virtualisierung aktiviert und Ubuntu in WSL2 aktuell. |
| **Container Engine** | Docker Desktop oder Docker Engine in WSL2 | Compose v2 aktiv (`docker compose version`). |
| **Lokale Ports** | `127.0.0.1:9000` (HTTP) und `127.0.0.1:9443` (HTTPS) | Ausschließliche Bindung an Loopback zur lokalen Isolation. |

---

## 3. Authentik mit Docker Compose starten

Erstellen Sie ein Verzeichnis in WSL2 (z. B. `~/iam-labs/authentik`) und hinterlegen Sie alle *Secrets* in einer lokalen `.env`-Datei (niemals committen):

```bash
mkdir -p ~/iam-labs/authentik/media ~/iam-labs/authentik/custom-templates
```

Beispiel für `.env`:

```env
PG_PASS=DURCH_STARKES_POSTGRES_SECRET_ERSETZEN
AUTHENTIK_SECRET_KEY=DURCH_64_ZEICHEN_ZUFALLSSCHLUESSEL_ERSETZEN
AUTHENTIK_BOOTSTRAP_PASSWORD=DURCH_LAB_ADMIN_PASSWORT_ERSETZEN
AUTHENTIK_BOOTSTRAP_EMAIL=iam-lab@contoso.local
```

Datei `compose.yml` mit PostgreSQL, Redis, Server und Worker ausschließlich auf `127.0.0.1`:

```yaml
services:
  postgresql:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_PASSWORD: ${PG_PASS}
      POSTGRES_USER: authentik
      POSTGRES_DB: authentik
    volumes:
      - database:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -d authentik -U authentik"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    command: --save 60 1 --loglevel warning
    restart: unless-stopped
    volumes:
      - redis:/data

  server:
    image: ghcr.io/goauthentik/server:latest
    restart: unless-stopped
    command: server
    depends_on:
      postgresql:
        condition: service_healthy
      redis:
        condition: service_started
    environment:
      AUTHENTIK_REDIS__HOST: redis
      AUTHENTIK_POSTGRESQL__HOST: postgresql
      AUTHENTIK_POSTGRESQL__USER: authentik
      AUTHENTIK_POSTGRESQL__NAME: authentik
      AUTHENTIK_POSTGRESQL__PASSWORD: ${PG_PASS}
      AUTHENTIK_SECRET_KEY: ${AUTHENTIK_SECRET_KEY}
      AUTHENTIK_BOOTSTRAP_PASSWORD: ${AUTHENTIK_BOOTSTRAP_PASSWORD}
      AUTHENTIK_BOOTSTRAP_EMAIL: ${AUTHENTIK_BOOTSTRAP_EMAIL}
    volumes:
      - ./media:/media
      - ./custom-templates:/templates
    ports:
      - "127.0.0.1:9000:9000"
      - "127.0.0.1:9443:9443"

  worker:
    image: ghcr.io/goauthentik/server:latest
    restart: unless-stopped
    command: worker
    depends_on:
      postgresql:
        condition: service_healthy
      redis:
        condition: service_started
    environment:
      AUTHENTIK_REDIS__HOST: redis
      AUTHENTIK_POSTGRESQL__HOST: postgresql
      AUTHENTIK_POSTGRESQL__USER: authentik
      AUTHENTIK_POSTGRESQL__NAME: authentik
      AUTHENTIK_POSTGRESQL__PASSWORD: ${PG_PASS}
      AUTHENTIK_SECRET_KEY: ${AUTHENTIK_SECRET_KEY}
    volumes:
      - ./media:/media
      - ./custom-templates:/templates

volumes:
  database:
  redis:
```

Dienste starten:

```bash
cd ~/iam-labs/authentik
docker compose up -d
docker compose logs -f server
```

Öffnen Sie `http://127.0.0.1:9000/if/admin/` im Browser und melden Sie sich mit dem Standardbenutzer `akadmin` und dem Passwort aus `AUTHENTIK_BOOTSTRAP_PASSWORD` an.

---

## 4. OIDC-Provider und Passkeys (FIDO2) einrichten

1. **Anwendung und OIDC-Provider anlegen:**
   Öffnen Sie im Admin-Panel `Applications > Applications > Create with Provider`.
   - Wählen Sie **OAuth2/OpenID Provider**.
   - Notieren Sie **Client ID** und **Client Secret** für Ihre Test-App (z. B. Grafana, Shuffle oder eine lokale App unter `http://127.0.0.1:3000/callback`).
2. **Passkey / WebAuthn aktivieren:**
   Navigieren Sie zu `Flows and Stages > Stages > Create > Authenticator WebAuthn Stage` und binden Sie die Stage in den Standard-Anmeldeflow (`default-authentication-flow`) ein.

---

## 5. Event-Auditing und SIEM-Korrelation

Jede erfolgreiche Anmeldung, fehlgeschlagene Passwortprüfung oder Änderung eines *Client Secrets* wird unter `Events > Logs` protokolliert und strukturiert ausgegeben. Über die REST-API lassen sich aktuelle Ereignisse direkt abrufen:

```bash
curl -s http://127.0.0.1:9000/api/v3/events/events/ \
  -H "Authorization: Bearer IHR_API_TOKEN_HIER" | jq '.results[:5] | .[] | {action, created, client_ip, user: .user.username}'
```

So lassen sich Ereignisse wie `login_failed`, `authorize_application` und `model_updated` nahtlos an ein lokales SIEM (etwa Wazuh) weiterleiten, um MFA-*Bypass*-Versuche oder unbefugte *Secret*-Änderungen zu erkennen.

---

## 6. Kontroll-Mapping und Best Practices

| Framework | Referenz | Praktische Anwendung |
|---|---|---|
| **NIST SP 800-63B** | *Digital Identity Guidelines (AAL2 / AAL3)* | Einsatz kryptografischer FIDO2-Authentifikatoren / *Passkeys* für kritische Flows. |
| **NIST CSF** | `PR.AA-01` / `PR.AA-03` | Zentrales Identitätsmanagement, SSO und Multi-Faktor-Authentifizierung. |
| **ISO/IEC 27001:2022** | `A.5.16` / `A.8.5` | Identitätslebenszyklus-Management und sichere Authentifizierung. |

---

## Referenzen

- [Authentik — Official Documentation (Docker Compose & OIDC)](https://docs.goauthentik.io/docs/)
- [Microsoft Learn — Install WSL 2 on Windows Enterprise](https://learn.microsoft.com/en-us/windows/wsl/install)
- [NIST SP 800-63B — Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)

