---
title: "OpenBao em laboratório local com Docker e WSL2: gestão de secrets e auditoria de acesso"
description: "Guia prático para subir o OpenBao localmente com Docker e WSL2 no Windows Enterprise, configurar logs de auditoria e rotacionar secrets via API."
date: 2026-11-21
categoria: IAM
tags: [openbao, iam, secrets, docker, wsl2, open-source, devsecops]
nivel: Intermediário
draft: false
---

> **TL;DR:** Centralizar *secrets* de aplicações e automações evita credenciais *hardcoded* em repositórios e scripts do SOC. Este guia demonstra como implantar o **OpenBao** (projeto da Linux Foundation) em laboratório local isolado com Docker e WSL2 no Windows Enterprise, habilitar *audit logs* em JSON e ler *secrets* via CLI/API sem expor portas na rede.

---

## 1. Por que utilizar um cofre local de secrets em laboratório?

Durante a criação de *playbooks* no Shuffle, scripts de coleta no Wazuh ou automações de *Threat Intelligence* no MISP, é comum o analista lidar com *API keys*, tokens OAuth e *client secrets*. Manter esses valores em arquivos de texto ou variáveis fixas aumenta o risco de vazamento acidental em commits ou logs.

O **OpenBao** é uma solução *open-source* mantida sob a governança da Linux Foundation (compatível com a API do ecossistema Vault) que permite:
- Armazenar *secrets* criptografados em repouso com controle granular por políticas (*least privilege*).
- Emitir tokens temporários com tempo de vida (TTL) curto e revogação imediata.
- Registrar cada leitura, falha de autenticação ou rotação em um *audit log* estruturado em JSON.

---

## 2. Pré-requisitos e isolamento do laboratório

| Componente | Especificação Mínima | Observação |
|---|---|---|
| **Sistema Host** | Windows 10/11 Enterprise com WSL2 | Virtualização ativa e Ubuntu atualizado no WSL2. |
| **Container Engine** | Docker Desktop ou Docker Engine no WSL2 | Compose v2 habilitado (`docker compose version`). |
| **Bind de Rede** | `127.0.0.1:8200` (HTTP local de lab) | Isolamento estrito em loopback, sem exposição na LAN. |

---

## 3. Subindo o OpenBao com Docker Compose

Crie um diretório dedicado no WSL2 (ex.: `~/iam-labs/openbao`) e prepare a estrutura para configuração e logs de auditoria:

```bash
mkdir -p ~/iam-labs/openbao/config ~/iam-labs/openbao/logs
```

Crie o arquivo `~/iam-labs/openbao/config/bao.hcl` para persistência local em disco (`raft` ou `file`) sem *tls* na interface loopback apenas para testes locais:

```hcl
ui = true

storage "file" {
  path = "/openbao/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}
```

Crie o arquivo `~/iam-labs/openbao/compose.yml` mapeando a porta exclusivamente para `127.0.0.1`:

```yaml
services:
  openbao:
    image: quay.io/openbao/openbao:latest
    container_name: openbao-lab
    restart: unless-stopped
    cap_add:
      - IPC_LOCK
    ports:
      - "127.0.0.1:8200:8200"
    volumes:
      - ./config:/openbao/config:ro
      - ./logs:/openbao/logs
      - openbao-data:/openbao/file
    command: server -config=/openbao/config/bao.hcl

volumes:
  openbao-data:
```

Inicie o serviço:

```bash
cd ~/iam-labs/openbao
docker compose up -d
```

---

## 4. Inicialização, Unseal e habilitação de Audit Logs

Em modo persistente, o OpenBao inicia lacrado (*sealed*). Execute a inicialização pela CLI dentro do contêiner para gerar as chaves de *unseal* e o token raiz inicial (apenas para bootstrap do laboratório):

```bash
docker exec -e BAO_ADDR='http://127.0.0.1:8200' openbao-lab bao operator init -key-shares=1 -key-threshold=1
```

Guarde a `Unseal Key` e o `Initial Root Token` exibidos no terminal apenas na sua sessão de laboratório (nunca os comite no Git) e desbloqueie o cofre:

```bash
docker exec -e BAO_ADDR='http://127.0.0.1:8200' openbao-lab bao operator unseal SUA_UNSEAL_KEY_AQUI
```

Autentique-se e ative imediatamente o dispositivo de auditoria em arquivo JSON (essencial para correlação posterior em SIEM):

```bash
export BAO_ADDR='http://127.0.0.1:8200'
docker exec -e BAO_ADDR=$BAO_ADDR -e BAO_TOKEN=SEU_ROOT_TOKEN openbao-lab bao audit enable file file_path=/openbao/logs/audit.log
```

---

## 5. Armazenando e consumindo secrets com políticas mínimas

Habilite o motor *KV v2* (`kv-v2`), grave um *secret* de exemplo para integração do SOC e crie uma política de somente leitura:

```bash
docker exec -e BAO_ADDR=$BAO_ADDR -e BAO_TOKEN=SEU_ROOT_TOKEN openbao-lab bao secrets enable -path=soc kv-v2
docker exec -e BAO_ADDR=$BAO_ADDR -e BAO_TOKEN=SEU_ROOT_TOKEN openbao-lab bao kv put soc/misp api_key="EXEMPLO_TOKEN_LAB_LOCAL"
```

Para consultar o *secret* via API REST a partir de um *playbook* do Shuffle ou script Python no WSL2:

```bash
curl -s http://127.0.0.1:8200/v1/soc/data/misp \
  -H "X-Vault-Token: SEU_TOKEN_DE_LEITURA" | jq '.data.data'
```

Cada chamada gera uma linha JSON em `~/iam-labs/openbao/logs/audit.log` contendo `request.path`, `auth.display_name`, `remote_address` e `response`, permitindo que o agente do Wazuh ingira e alerte sobre acessos anômalos a *secrets* sensíveis.

---

## 6. Mapeamento de Controles e Boas Práticas

| Framework | Referência | Aplicação Prática |
|---|---|---|
| **NIST SP 800-57** | *Recommendation for Key Management* | Ciclo de vida, rotação e proteção criptográfica de chaves e *secrets*. |
| **CIS Controls v8** | `3.11` / `6.8` | Criptografia de dados sensíveis e controle de acesso baseado em função para credenciais. |
| **ISO/IEC 27001:2022** | `A.5.17` / `A.8.24` | Gestão de informações de autenticação e uso de controles criptográficos. |

---

## Referências

- [OpenBao — Official Documentation (Linux Foundation)](https://openbao.org/docs/)
- [Microsoft Learn — Install WSL 2 on Windows Enterprise](https://learn.microsoft.com/en-us/windows/wsl/install)
- [NIST SP 800-57 Part 1 — Recommendation for Key Management](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)

