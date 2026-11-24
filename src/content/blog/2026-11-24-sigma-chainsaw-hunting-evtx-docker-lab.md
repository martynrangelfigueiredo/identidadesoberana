---
title: "Sigma e Chainsaw em laboratório local no WSL2: caça rápida em logs EVTX do Windows Enterprise"
description: "Guia prático para converter regras Sigma e executar o Chainsaw localmente no WSL2 sobre arquivos EVTX de estações Windows Enterprise sem depender de SIEM pago."
date: 2026-11-24
categoria: SOC
tags: [sigma, chainsaw, evtx, detection-as-code, docker, wsl2, open-source, soc]
nivel: Intermediário
draft: false
---

> **TL;DR:** Durante uma resposta a incidentes em estações Windows, nem sempre o endpoint estava enviando logs completos para o SIEM na hora do ataque. Este guia mostra como usar o padrão aberto **Sigma** junto com o **Chainsaw** em laboratório local no WSL2 (Windows Enterprise) para varrer arquivos `.evtx` em segundos e detectar persistência, movimento lateral e *bypass* de defesas.

---

## 1. Por que combinar Sigma e Chainsaw no laboratório do SOC?

O **Sigma** é o formato aberto universal de *Detection as Code* para descrever assinaturas de detecção em arquivos YAML independentes de fornecedor. Já o **Chainsaw** (mantido pela WithSecure Labs em Rust) permite aplicar centenas de regras Sigma diretamente sobre arquivos nativos do Windows Event Log (`.evtx`) em disco, sem precisar subir um SIEM completo antes da triagem inicial.

Rodar esse fluxo localmente no **WSL2** (ou em um contêiner Docker isolado sem acesso à internet) oferece ao analista:
- Velocidade extrema na análise forense de arquivos `Security.evtx`, `Microsoft-Windows-PowerShell%4Operational.evtx` e `Sysmon.evtx`.
- Portabilidade das mesmas regras usadas em produção (Wazuh, Elastic ou conversões para KQL no Microsoft Sentinel).
- Privacidade total: os logs coletados do incidente permanecem 100% no disco local.

---

## 2. Pré-requisitos e estrutura do laboratório

| Componente | Especificação Mínima | Observação |
|---|---|---|
| **Sistema Host** | Windows 10/11 Enterprise com WSL2 | Ubuntu 22.04/24.04 atualizado no WSL2. |
| **Motor de Análise** | Chainsaw (binário Linux ou container Docker) | Escrito em Rust; baixo consumo de memória. |
| **Base de Regras** | Repositório oficial `SigmaHQ/sigma` | Regras YAML abertas mapeadas para MITRE ATT&CK. |

---

## 3. Preparando o ambiente isolado no WSL2 e Docker

Crie uma pasta dedicada no WSL2 para armazenar as regras Sigma e os arquivos `.evtx` exportados de máquinas de teste (nunca misture evidências reais com diretórios públicos):

```bash
mkdir -p ~/dfir-labs/chainsaw/evtx ~/dfir-labs/chainsaw/rules
cd ~/dfir-labs/chainsaw
```

Baixe o repositório oficial de regras Sigma (ou monte uma versão já auditada offline):

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma.git rules/sigma
```

Caso prefira rodar o Chainsaw em um contêiner efêmero sem instalar dependências no host WSL2, crie um `Dockerfile` mínimo:

```dockerfile
FROM rust:1.82-slim AS builder
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
RUN cargo install chainsaw

FROM debian:bookworm-slim
COPY --from=builder /usr/local/cargo/bin/chainsaw /usr/local/bin/chainsaw
WORKDIR /workspace
ENTRYPOINT ["chainsaw"]
```

Compile a imagem localmente:

```bash
docker build -t local/chainsaw:latest .
```

---

## 4. Copiando logs EVTX de teste e executando o Hunting

Em um cenário de laboratório no próprio Windows Enterprise, copie os logs de teste para a pasta compartilhada no WSL2 (ex.: via PowerShell como administrador em ambiente de teste):

```powershell
Copy-Item "C:\Windows\System32\Winevt\Logs\Security.evtx" "\\wsl$\Ubuntu\home\$env:USERNAME\dfir-labs\chainsaw\evtx\"
Copy-Item "C:\Windows\System32\Winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx" "\\wsl$\Ubuntu\home\$env:USERNAME\dfir-labs\chainsaw\evtx\"
```

Agora execute a varredura em modo completamente offline (`--network none`) aplicando as regras Sigma de Windows sobre os `.evtx`:

```bash
docker run --rm --network none \
  -v ~/dfir-labs/chainsaw/evtx:/evtx:ro \
  -v ~/dfir-labs/chainsaw/rules/sigma:/sigma:ro \
  local/chainsaw:latest hunt /evtx \
  -s /sigma/rules/windows \
  --mapping /sigma/tools/config/generic/windows-audit.yml \
  --json --output /evtx/findings.json
```

> **Dica operacional:** Para visualização rápida no terminal em vez de JSON, remova `--json --output ...` e o Chainsaw imprimirá uma tabela ASCII estruturada com timestamp, Event ID, regra acionada e campo `CommandLine` ou `TargetUserName`.

---

## 5. Exemplo de regra Sigma local para detectar criação suspeita de tarefa agendada

Você pode criar regras YAML próprias em `~/dfir-labs/chainsaw/rules/custom/` para detectar persistência via `schtasks.exe` (`MITRE ATT&CK T1053.005`):

```yaml
title: Criacao de Tarefa Agendada Apontando para Diretorio Temporario
id: 7b4e1a20-8f12-4c9a-9c2e-11a2b3c4d5e6
status: experimental
description: Detecta schtasks criando tarefas que executam binarios em AppData ou Temp.
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

Essa mesma regra YAML pode ser convertida depois para o formato de pesquisa do Wazuh ou para KQL no Microsoft Sentinel usando o `sigma-cli`.

---

## 6. Mapeamento de Controles e Boas Práticas

| Framework | Referência | Aplicação Prática |
|---|---|---|
| **MITRE ATT&CK** | `T1053.005` / `T1059.001` | Detecção padronizada de tarefas agendadas e execução ofuscada em PowerShell. |
| **NIST SP 800-86** | *Guide to Integrating Forensic Techniques into Incident Response* | Inspeção estruturada de logs de eventos do sistema operacional em triagem DFIR. |
| **CIS Controls v8** | `8.2` / `8.5` | Coleta e revisão detalhada de logs de auditoria de processo e segurança no Windows. |

---

## Referências

- [Microsoft Learn — Install WSL 2 on Windows Enterprise](https://learn.microsoft.com/en-us/windows/wsl/install)
- [Microsoft Learn — Advanced security auditing in Windows](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing-faq)
- [SigmaHQ — Sigma Generic Signature Format](https://sigmahq.io/)
- [WithSecure Labs — Chainsaw EVTX Hunting Tool](https://github.com/WithSecureLabs/chainsaw)

