---
title: "Velociraptor em laboratório local com Docker e WSL2: DFIR e Threat Hunting em endpoints Windows"
description: "Guia prático para subir o servidor Velociraptor localmente via Docker no WSL2 e executar coletas forenses (VQL) em estações Windows Enterprise."
date: 2026-11-22
categoria: SOC
tags: [velociraptor, dfir, threat-hunting, docker, wsl2, open-source, soc]
nivel: Intermediário
draft: false
---

> **TL;DR:** Quando um alerta exige resposta rápida em memória, registro do Windows ou histórico de processos, depender apenas de logs tradicionais limita a investigação. Este guia mostra como implantar o **Velociraptor** em laboratório local isolado com Docker e WSL2 no Windows Enterprise e executar coletas VQL (*Velociraptor Query Language*) em minutos.

---

## 1. Por que adicionar o Velociraptor ao laboratório de SOC?

O **Velociraptor** é uma plataforma *open-source* voltada para **DFIR** (*Digital Forensics and Incident Response*) e **Threat Hunting** em escala. Enquanto um SIEM como o Wazuh centraliza eventos contínuos, o Velociraptor permite inspecionar artefatos sob demanda diretamente no endpoint Windows — como chaves de persistência (`Run`/`RunOnce`), conexões de rede ativas, tarefas agendadas, prefetch e *Event Logs* (`EVTX`).

Rodar o servidor em **isolamento local** (`127.0.0.1`) via Docker no WSL2 permite:
- Testar artefatos VQL personalizados sem impactar máquinas de produção.
- Integrar coletas forenses disparadas por *playbooks* do Shuffle ou casos do TheHive.
- Simular triagem rápida de endpoints Windows Enterprise usando apenas a interface web local e um agente de teste.

---

## 2. Pré-requisitos e arquitetura do laboratório

| Componente | Especificação Mínima | Observação |
|---|---|---|
| **Sistema Host** | Windows 10/11 Enterprise com WSL2 | Virtualização habilitada e Ubuntu atualizado no WSL2. |
| **Container Engine** | Docker Desktop ou Docker Engine no WSL2 | Compose v2 ativo (`docker compose version`). |
| **Portas Locais** | `127.0.0.1:8889` (GUI) e `127.0.0.1:8000` (Frontend/Agente) | Bind exclusivo em loopback para isolamento na rede local. |

---

## 3. Gerando configuração e subindo o Velociraptor com Docker Compose

Crie um diretório dedicado no WSL2 (ex.: `~/soc-labs/velociraptor`) e um arquivo `.env` local para não deixar *secrets* ou senhas *hardcoded* no repositório:

```bash
mkdir -p ~/soc-labs/velociraptor/config ~/soc-labs/velociraptor/datastore
```

Exemplo de `.env`:

```env
VELO_ADMIN_USER=soc-admin
VELO_ADMIN_PASSWORD=SUBSTITUA_POR_SECRET_FORTE_LAB
```

Crie o `compose.yml` utilizando a imagem oficial mantida pela comunidade/projeto e expondo apenas em `127.0.0.1`:

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

> **Dica operacional:** Caso prefira gerar manualmente o `server.config.yaml` com o binário oficial do Velociraptor, execute `velociraptor config generate -i` no WSL2, aponte `Client.server_urls` para `https://127.0.0.1:8000/` e monte o arquivo gerado em `/velociraptor/server.config.yaml`.

Inicie o contêiner:

```bash
cd ~/soc-labs/velociraptor
docker compose up -d
docker compose logs -f velociraptor
```

Acesse a interface web em `https://127.0.0.1:8889` (aceitando o certificado autoassinado de laboratório) e faça login com o usuário definido no `.env`.

---

## 4. Conectando um endpoint Windows Enterprise de teste

Para testar coletas reais no mesmo host Windows (ou em uma VM de laboratório):

1. Na GUI do Velociraptor, abra o menu **Server Artifacts** (`Configure Server > Generate Client`) ou gere o configurador de cliente pelo CLI:
   ```bash
   docker exec velociraptor-lab velociraptor --config /velociraptor/server.config.yaml config client > client.config.yaml
   ```
2. Baixe o executável oficial do Velociraptor para Windows (`velociraptor-vX.X.X-windows-amd64.exe`) a partir das *releases* oficiais no GitHub.
3. No PowerShell (em modo de laboratório local), execute o agente apontando para o arquivo de configuração gerado:
   ```powershell
   .\velociraptor-windows-amd64.exe --config .\client.config.yaml client -v
   ```
4. Em poucos segundos, o endpoint aparecerá como **Online** na aba **Search Clients** da interface web.

---

## 5. Executando uma caça rápida com VQL (Persistência e Processos)

Com o cliente conectado, clique no ID do host e abra **Collected > Collect new artifact** ou inicie um **Notebook VQL** para consultar processos com executáveis fora de diretórios padrão do Windows:

```sql
SELECT Pid, Ppid, Name, Exe, CommandLine
FROM pslist()
WHERE Exe =~ "(?i)(Users\\\\Public|AppData\\\\Local\\\\Temp|ProgramData)"
```

Você também pode coletar automaticamente artefatos prontos da biblioteca embutida, como:
- **`Windows.Sys.StartupItems`**: enumera entradas de inicialização e chaves `Run` / `RunOnce`.
- **`Windows.Network.NetstatEnriched`**: lista conexões TCP/UDP ativas associadas ao processo (`Pid` e `Name`).
- **`Windows.Detection.Amcache`**: inspeciona binários executados recentemente no endpoint.

---

## 6. Mapeamento de Controles e Boas Práticas

| Framework | Referência | Aplicação Prática |
|---|---|---|
| **NIST SP 800-86** | *Guide to Integrating Forensic Techniques into Incident Response* | Coleta padronizada de artefatos voláteis e não voláteis em endpoints. |
| **NIST CSF** | `DE.AE-02` / `RS.AN-01` | Análise forense de eventos anômalos e investigação aprofundada em hosts. |
| **ISO/IEC 27001:2022** | `A.5.28` (*Collection of Evidence*) | Identificação, coleta e preservação de evidências digitais durante incidentes. |

---

## Referências

- [Velociraptor — Official Documentation & VQL Reference](https://docs.velociraptor.app/)
- [Microsoft Learn — Install WSL 2 on Windows Enterprise](https://learn.microsoft.com/en-us/windows/wsl/install)
- [NIST SP 800-86 — Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final)

