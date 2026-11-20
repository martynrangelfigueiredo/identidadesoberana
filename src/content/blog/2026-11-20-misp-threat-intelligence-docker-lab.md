---
title: "MISP em laboratório local com Docker e WSL2: gestão prática de Threat Intelligence para o SOC"
description: "Guia técnico passo a passo para implantar o MISP localmente via Docker no WSL2 (Windows Enterprise) e integrar IOCs com Wazuh e Shuffle."
date: 2026-11-20
categoria: SOC
tags: [misp, threat-intelligence, docker, wsl2, open-source, soc, ioc]
nivel: Intermediário
draft: false
---

> **TL;DR:** Centralizar Indicadores de Comprometimento (IOCs) em uma plataforma aberta evita dependência de planilhas isoladas e acelera a triagem no SOC. Este guia mostra como subir o **MISP** em laboratório local isolado com Docker e WSL2 no Windows Enterprise, configurar feeds iniciais e consultar atributos via API para enriquecimento no Wazuh ou Shuffle.

---

## 1. Por que rodar o MISP localmente no laboratório do SOC?

O **MISP** (*Malware Information Sharing Platform*) é o padrão aberto de mercado para compartilhamento e correlação de *Threat Intelligence* (CTI). Em vez de consultar manualmente dezenas de portais para cada IP, domínio ou hash suspeito, o analista mantém uma base estruturada de eventos, atributos e taxonomias (como TLP e MITRE ATT&CK).

Subir o serviço em **isolamento local** (`127.0.0.1`) via Docker Desktop / WSL2 no Windows Enterprise permite:
- Testar feeds públicos (CIRCL OSINT, abuse.ch, ThreatFox) sem expor consultas internas para fora da rede.
- Correlacionar automaticamente IOCs observados em alertas do Wazuh ou casos do TheHive.
- Validar *playbooks* de enriquecimento no Shuffle antes de levá-los para produção.

---

## 2. Pré-requisitos e arquitetura do laboratório

| Componente | Especificação Mínima | Observação |
|---|---|---|
| **Sistema Host** | Windows 10/11 Enterprise com WSL2 | Virtualização habilitada no BIOS/UEFI. |
| **Container Engine** | Docker Desktop ou Docker Engine no Ubuntu WSL2 | Mínimo de 4 GB de RAM alocados no `.wslconfig`. |
| **Portas Locais** | `127.0.0.1:8443` (HTTPS) | Bind exclusivo em loopback para evitar exposição na LAN. |

---

## 3. Subindo o MISP com Docker Compose (isolamento em loopback)

Crie um diretório dedicado no seu ambiente WSL2 (ex.: `~/soc-labs/misp`) e defina um arquivo `compose.yml` enxuto com os serviços essenciais (`misp-core`, `db` MariaDB e `redis`).

> **Importante:** Nunca utilize senhas padrão em ambientes compartilhados. Defina os *secrets* em um arquivo `.env` local (fora do controle de versão).

Exemplo de `.env` para o laboratório:

```env
MYSQL_ROOT_PASSWORD=SUBSTITUA_POR_SECRET_ROOT_FORTE
MYSQL_PASSWORD=SUBSTITUA_POR_SECRET_DB_FORTE
MISP_ADMIN_EMAIL=soc-lab@contoso.local
MISP_ADMIN_PASSPHRASE=SUBSTITUA_POR_SECRET_ADMIN_FORTE
MISP_BASEURL=https://127.0.0.1:8443
```

Arquivo `compose.yml`:

```yaml
services:
  redis:
    image: redis:7-alpine
    restart: unless-stopped
    networks:
      - misp-net

  db:
    image: mariadb:10.11
    restart: unless-stopped
    environment:
      MYSQL_DATABASE: misp
      MYSQL_USER: misp
      MYSQL_PASSWORD: ${MYSQL_PASSWORD}
      MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD}
    volumes:
      - misp-db:/var/lib/mysql
    networks:
      - misp-net

  misp-core:
    image: ghcr.io/misp/misp-docker/misp-core:latest
    restart: unless-stopped
    depends_on:
      - db
      - redis
    ports:
      - "127.0.0.1:8443:443"
    environment:
      MYSQL_HOST: db
      MYSQL_DATABASE: misp
      MYSQL_USER: misp
      MYSQL_PASSWORD: ${MYSQL_PASSWORD}
      REDIS_HOST: redis
      BASE_URL: ${MISP_BASEURL}
      ADMIN_EMAIL: ${MISP_ADMIN_EMAIL}
      ADMIN_PASSPHRASE: ${MISP_ADMIN_PASSPHRASE}
      INIT: "true"
    volumes:
      - misp-configs:/var/www/MISP/app/Config
      - misp-files:/var/www/MISP/app/files
    networks:
      - misp-net

volumes:
  misp-db:
  misp-configs:
  misp-files:

networks:
  misp-net:
    driver: bridge
```

Inicie os contêineres e acompanhe a inicialização do banco e das tabelas:

```bash
docker compose up -d
docker compose logs -f misp-core
```

Quando os logs indicarem que o Apache/PHP-FPM está ativo, acesse `https://127.0.0.1:8443` no navegador (aceitando o certificado autoassinado de laboratório) e autentique-se com o e-mail e a senha configurados no `.env`.

---

## 4. Ativando feeds iniciais e gerando chave de API

Após o primeiro login no painel administrativo:

1. **Habilitar feeds OSINT confiáveis:**
   Navegue até `Sync Actions > List Feeds`. Ative os feeds **CIRCL OSINT Feed** e **The Botvrij.eu Data** e clique em **Fetch and store all feed data** para popular a base local com IOCs reais e atualizados.
2. **Gerar AuthKey para automação:**
   Acesse `Global Actions > My Profile > Auth Keys > Add authentication key`. Copie o valor gerado apenas uma vez e armazene-o no cofre de *secrets* do seu Shuffle ou script de laboratório.

---

## 5. Consultando IOCs via API (integração com Shuffle e Wazuh)

Com a *AuthKey* em mãos, qualquer *playbook* do Shuffle ou script Python/PowerShell pode consultar se um IP suspeito (por exemplo, `198.51.100.42`, faixa reservada de documentação RFC 5737) já consta em eventos de inteligência:

```bash
curl -k -X POST https://127.0.0.1:8443/attributes/restSearch \
  -H "Authorization: SUA_AUTHKEY_AQUI" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{
    "returnFormat": "json",
    "type": "ip-dst",
    "value": "198.51.100.42"
  }'
```

Se a resposta retornar objetos no array `response.Attribute`, o fluxo automatizado no Shuffle pode:
- Elevar automaticamente a severidade do alerta no **TheHive**.
- Anexar as tags de campanha (`tlp:amber`, `mitre-attack-pattern`) diretamente no caso.
- Disparar bloqueio temporário em firewall de borda ou *Conditional Access*.

---

## 6. Mapeamento de Controles e Boas Práticas

| Framework | Referência | Aplicação Prática |
|---|---|---|
| **NIST SP 800-150** | *Guide to Cyber Threat Information Sharing* | Estruturação padronizada de IOCs, TLP e feeds confiáveis. |
| **NIST CSF** | `DE.CM-01` / `RS.AN-03` | Correlação contínua de indicadores externos contra telemetria interna. |
| **ISO/IEC 27001:2022** | `A.5.7` (*Threat Intelligence*) | Coleta, análise e uso operacional de inteligência contra ameaças. |

---

## Referências

- [Microsoft Learn — Instalar o WSL 2 no Windows Enterprise](https://learn.microsoft.com/en-us/windows/wsl/install)
- [Docker Docs — Docker Compose Overview](https://docs.docker.com/compose/)
- [MISP Project — Official Documentation & Docker Images](https://www.misp-project.org/documentation/)
- [NIST SP 800-150 — Guide to Cyber Threat Information Sharing](https://csrc.nist.gov/pubs/sp/800/150/final)
- [FIRST — Traffic Light Protocol (TLP) Standard](https://www.first.org/tlp/)
