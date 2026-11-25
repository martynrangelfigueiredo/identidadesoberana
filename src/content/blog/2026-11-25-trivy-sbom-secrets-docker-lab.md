---
title: "Trivy em laboratório local com Docker e WSL2: varredura de CVEs, secrets e SBOM"
description: "Guia prático para usar o Trivy localmente no WSL2 e Docker (Windows Enterprise) na detecção de vulnerabilidades, secrets hardcoded e geração de SBOM."
date: 2026-11-25
categoria: Compliance
tags: [trivy, sbom, devsecops, docker, wsl2, open-source, secrets, compliance]
nivel: Intermediário
draft: false
---

> **TL;DR:** Antes de subir qualquer imagem Docker no laboratório do SOC ou em produção, validar CVEs críticas, *secrets* esquecidos em camadas e gerar um **SBOM** (*Software Bill of Materials*) evita riscos na cadeia de suprimentos. Este guia mostra como usar o **Trivy** localmente no WSL2 (Windows Enterprise) sem enviar código ou imagens para serviços externos.

---

## 1. Por que auditar imagens e repositórios localmente com o Trivy?

Subir contêineres rapidamente no WSL2 acelera testes de ferramentas como Keycloak, Wazuh ou Shuffle, mas imagens desatualizadas ou arquivos `compose.yml` mal configurados podem carregar bibliotecas vulneráveis ou *secrets* expostos acidentalmente.

O **Trivy** (projeto *open-source* mantido pela Aqua Security) reúne em um único binário:
- **Varredura de vulnerabilidades (CVEs)** em pacotes de SO (Debian, Alpine, Ubuntu) e dependências de aplicação (`npm`, `pip`, `go`).
- **Detecção de secrets (*Secret Scanning*)** em sistemas de arquivos, repositórios Git e camadas de imagens Docker.
- **Geração de SBOM** nos formatos padrão de auditoria **CycloneDX** e **SPDX** (Linux Foundation).
- **Checagem de *misconfigurations*** em `Dockerfile`, `compose.yml` e manifestos Kubernetes.

---

## 2. Pré-requisitos e isolamento no WSL2

| Componente | Especificação Mínima | Observação |
|---|---|---|
| **Sistema Host** | Windows 10/11 Enterprise com WSL2 | Ubuntu 22.04/24.04 atualizado no WSL2. |
| **Container Engine** | Docker Desktop ou Docker Engine no WSL2 | Socket local acessível no terminal WSL2. |
| **Modo de Execução** | Imagem oficial `aquasec/trivy` ou binário local | Cache de CVEs mantido localmente em `~/.cache/trivy`. |

---

## 3. Varrendo imagens Docker e detectando secrets localmente

Para auditar uma imagem já baixada no seu Docker local sem instalar nada no sistema operacional, monte o socket do Docker em modo somente leitura e mantenha o cache em volume local:

```bash
mkdir -p ~/.cache/trivy
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v ~/.cache/trivy:/root/.cache/ \
  aquasec/trivy:latest image --severity HIGH,CRITICAL nginx:alpine
```

Para inspecionar um diretório de projeto local (por exemplo, seus arquivos `compose.yml`, scripts e `Dockerfile`) em busca de *secrets* *hardcoded* e erros de configuração antes de um commit:

```bash
docker run --rm \
  -v $(pwd):/workspace:ro \
  -v ~/.cache/trivy:/root/.cache/ \
  aquasec/trivy:latest fs --scanners vuln,misconfig,secret /workspace
```

> **Dica de isolamento (Air-Gapped):** Após o primeiro download do banco de vulnerabilidades, você pode rodar o Trivy completamente sem acesso à rede adicionando `--skip-db-update --offline-scan` e `--network none` no comando `docker run`.

---

## 4. Gerando SBOM (CycloneDX / SPDX) para auditoria e compliance

Empresas sujeitas a auditorias de cadeia de suprimentos de software (ISO 27001, SOC 2 ou NIST SSDF) exigem inventário formal de componentes. Gere um **SBOM** em formato **CycloneDX JSON** com um único comando:

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v $(pwd):/output \
  -v ~/.cache/trivy:/root/.cache/ \
  aquasec/trivy:latest image --format cyclonedx --output /output/sbom-lab.cdx.json nginx:alpine
```

O arquivo `sbom-lab.cdx.json` lista todas as bibliotecas, versões e licenças presentes na imagem, podendo ser arquivado como evidência de conformidade ou ingerido em plataformas de gestão de vulnerabilidades.

---

## 5. Exemplo de política prática para esteiras locais

Em scripts de pré-commit ou esteiras de CI/CD, você pode falhar automaticamente o build caso existam *secrets* expostos ou CVEs críticas com correção já disponível (`--ignore-unfixed`):

```bash
trivy fs --exit-code 1 --severity CRITICAL --ignore-unfixed --scanners vuln,secret .
```

Isso impede que *client secrets*, tokens ou imagens com falhas críticas conhecidas cheguem ao ambiente de testes compartilhado.

---

## 6. Mapeamento de Controles e Boas Práticas

| Framework | Referência | Aplicação Prática |
|---|---|---|
| **NIST SP 800-218 (SSDF)** | `PW.4` / `RV.1` | Verificação contínua de componentes de terceiros e manutenção de inventário SBOM. |
| **NIST CSF** | `ID.AM-02` / `PR.DS-05` | Inventário de software e prevenção contra vazamento de *secrets* no código. |
| **ISO/IEC 27001:2022** | `A.8.8` / `A.8.28` | Gestão de vulnerabilidades técnicas e codificação segura. |

---

## Referências

- [Aqua Security — Trivy Official Documentation](https://trivy.dev/latest/)
- [Microsoft Learn — Install WSL 2 on Windows Enterprise](https://learn.microsoft.com/en-us/windows/wsl/install)
- [NIST SP 800-218 — Secure Software Development Framework (SSDF)](https://csrc.nist.gov/pubs/sp/800/218/final)
- [Linux Foundation — SPDX & CycloneDX Standards](https://spdx.dev/)

