---
title: "Trivy in a Local Docker & WSL2 Lab: Scanning CVEs, Secrets, and SBOM"
description: "Practical guide to run Trivy locally on WSL2 and Docker (Windows Enterprise) to detect container vulnerabilities, hardcoded secrets, and generate SBOMs."
date: 2026-11-25
categoria: Compliance
tags: [trivy, sbom, devsecops, docker, wsl2, open-source, secrets, compliance]
nivel: Intermediário
draft: false
---

> **TL;DR:** Before running any container image in your SOC lab or production, checking for critical CVEs, accidentally committed *secrets*, and generating an **SBOM** (*Software Bill of Materials*) mitigates supply-chain risk. This guide shows how to run **Trivy** locally on WSL2 (Windows Enterprise) without uploading code or images externally.

---

## 1. Why audit images and repositories locally with Trivy?

Spinning up containers in WSL2 accelerates testing tools like Keycloak, Wazuh, or Shuffle, but outdated images or hasty `compose.yml` files can introduce vulnerable libraries or leaked *secrets*.

**Trivy** (an open-source scanner maintained by Aqua Security) combines in one tool:
- **Vulnerability scanning (CVEs)** across OS packages (Debian, Alpine, Ubuntu) and app dependencies (`npm`, `pip`, `go`).
- **Secret scanning** across local filesystems, Git repositories, and Docker image layers.
- **SBOM generation** in standard audit formats **CycloneDX** and **SPDX** (Linux Foundation).
- **Misconfiguration checks** for `Dockerfile`, `compose.yml`, and Kubernetes manifests.

---

## 2. Prerequisites and WSL2 Isolation

| Component | Minimum Requirement | Notes |
|---|---|---|
| **Host OS** | Windows 10/11 Enterprise with WSL2 | Updated Ubuntu 22.04/24.04 distro in WSL2. |
| **Container Engine** | Docker Desktop or Docker Engine on WSL2 | Local Docker socket accessible inside WSL2. |
| **Execution Mode** | Official `aquasec/trivy` image or local binary | Vulnerability DB cached locally in `~/.cache/trivy`. |

---

## 3. Scanning Docker Images and Detecting Secrets Locally

To audit an image already pulled into your local Docker daemon without installing anything on the host, mount the Docker socket read-only:

```bash
mkdir -p ~/.cache/trivy
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v ~/.cache/trivy:/root/.cache/ \
  aquasec/trivy:latest image --severity HIGH,CRITICAL nginx:alpine
```

To scan a local project directory (e.g., `compose.yml`, scripts, and `Dockerfile`) for *hardcoded secrets* and misconfigurations before committing:

```bash
docker run --rm \
  -v $(pwd):/workspace:ro \
  -v ~/.cache/trivy:/root/.cache/ \
  aquasec/trivy:latest fs --scanners vuln,misconfig,secret /workspace
```

> **Air-gapped tip:** After the initial vulnerability database download, you can run Trivy completely offline by adding `--skip-db-update --offline-scan` and `--network none` to `docker run`.

---

## 4. Generating an SBOM (CycloneDX / SPDX) for Audits & Compliance

Supply-chain compliance audits (ISO 27001, SOC 2, or NIST SSDF) increasingly require a formal software component inventory. Generate a **CycloneDX JSON SBOM** with one command:

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v $(pwd):/output \
  -v ~/.cache/trivy:/root/.cache/ \
  aquasec/trivy:latest image --format cyclonedx --output /output/sbom-lab.cdx.json nginx:alpine
```

The resulting `sbom-lab.cdx.json` lists every library, version, and license inside the image, ready to be archived as compliance evidence or ingested into vulnerability management tools.

---

## 5. Sample Local Pre-Commit / Pipeline Policy

In pre-commit hooks or CI/CD pipelines, fail builds automatically when exposed *secrets* or fixable critical CVEs (`--ignore-unfixed`) are detected:

```bash
trivy fs --exit-code 1 --severity CRITICAL --ignore-unfixed --scanners vuln,secret .
```

This prevents *client secrets*, tokens, or critically vulnerable images from reaching shared test environments.

---

## 6. Control Mapping and Best Practices

| Framework | Reference | Practical Application |
|---|---|---|
| **NIST SP 800-218 (SSDF)** | `PW.4` / `RV.1` | Continuous verification of third-party components and SBOM maintenance. |
| **NIST CSF** | `ID.AM-02` / `PR.DS-05` | Software inventory tracking and preventing *secret* leaks in source code. |
| **ISO/IEC 27001:2022** | `A.8.8` / `A.8.28` | Technical vulnerability management and secure coding practices. |

---

## References

- [Aqua Security — Trivy Official Documentation](https://trivy.dev/latest/)
- [Microsoft Learn — Install WSL 2 on Windows Enterprise](https://learn.microsoft.com/en-us/windows/wsl/install)
- [NIST SP 800-218 — Secure Software Development Framework (SSDF)](https://csrc.nist.gov/pubs/sp/800/218/final)
- [Linux Foundation — SPDX & CycloneDX Standards](https://spdx.dev/)

