---
title: "Automação de SOC com Shuffle SOAR: integrando Wazuh e TheHive no Docker"
description: "Guia prático para implantar o Shuffle SOAR no Windows Enterprise com Docker e WSL 2 e construir workflows automatizados entre Wazuh SIEM e TheHive."
date: 2026-11-19
categoria: SOC
tags: [shuffle, soar, wazuh, thehive, docker, windows-enterprise, wsl2, lab, open-source, soc]
nivel: Intermediário
---

Nos laboratórios anteriores, estruturamos os pilares fundamentais de uma operação de segurança aberta: gerenciamento de identidades com **Keycloak**, detecção e telemetria com **Wazuh (SIEM/XDR)** e gestão de casos com **TheHive e Cortex**. Contudo, à medida que o volume de alertas cresce, triar manualmente cada evento e copiar indicadores entre consoles consome tempo precioso da equipe de SOC.

É nesse ponto que entra o **Shuffle**, uma plataforma **SOAR (Security Orchestration, Automation, and Response)** de código aberto que permite conectar ferramentas de segurança por meio de APIs REST, webhooks e blocos visuais (*workflows*), sem exigir licenciamento proprietário ou envio de dados para nuvens externas.

Neste guia prático, você aprenderá a implantar o Shuffle no Windows Enterprise usando Docker Desktop e WSL 2 e criar seu primeiro workflow de automação recebendo alertas do Wazuh para abrir casos enriquecidos no TheHive.

> **TL;DR para o Laboratório:** O Shuffle utiliza o OpenSearch como banco de dados para armazenar execuções e apps. No Windows Enterprise com WSL 2, garanta que `vm.max_map_count` esteja definido como `262144` e aloque pelo menos 6 GB de RAM no `.wslconfig` antes de subir o stack via Docker Compose.

> 📘 **Referências Oficiais:** Este guia baseia-se na documentação oficial dos projetos Shuffle, Wazuh e TheHive:
> - [Shuffle Documentation (shuffler.io)](https://shuffler.io/docs/about)
> - [Shuffle GitHub Repository](https://github.com/Shuffle/Shuffle)
> - [Wazuh Documentation — Integrator](https://documentation.wazuh.com/current/user-manual/manager/manual-integration.html)

---

## 1. O Papel do Shuffle na Arquitetura de SOC Aberta

O Shuffle atua como o "sistema nervoso" que interliga suas ferramentas defensivas por meio de playbooks visuais:

1. **Orquestração Baseada em APIs (OpenAPI/Swagger):** Importe especificações OpenAPI de praticamente qualquer ferramenta (Wazuh, TheHive, Cortex, Keycloak, firewalls ou ITSMs como Jira) para transformar endpoints em blocos arrastáveis.
2. **Gatilhos por Webhook e Agendamento:** Receba alertas em tempo real via HTTP POST assim que uma regra crítica dispara no SIEM, ou agende rotinas periódicas de caça a ameaças.
3. **Execução Isolada (Orborus & Workers):** Cada etapa do workflow roda em contêineres isolados (apps), garantindo controle estrito sobre credenciais, secrets e tráfego de rede interno.

---

## 2. Pré-requisitos no Windows Enterprise e WSL 2

Assim como o Wazuh e o TheHive, o Shuffle utiliza o **OpenSearch** para persistência de dados. Se você já configurou o `.wslconfig` e o `vm.max_map_count` nos laboratórios anteriores, os parâmetros já estarão prontos. Caso contrário, confirme no PowerShell:

```powershell
wsl -d Ubuntu -u root sysctl -w vm.max_map_count=262144
```

Certifique-se também de que o Docker Desktop tenha acesso à rede local do WSL 2 e pelo menos **6 GB de RAM** disponíveis.

---

## 3. Subindo o Shuffle SOAR com Docker Compose

O repositório oficial do Shuffle fornece um `docker-compose.yml` completo com os serviços **shuffle-frontend** (interface web), **shuffle-backend** (motor de APIs), **shuffle-orborus** (orquestrador de workers) e **shuffle-opensearch**.

1. No terminal do WSL 2, crie a pasta de trabalho e clone o repositório oficial:
   ```bash
   mkdir -p ~/shuffle-lab && cd ~/shuffle-lab
   git clone https://github.com/Shuffle/Shuffle.git --depth=1
   cd Shuffle
   ```

2. Crie o diretório de banco de dados do OpenSearch com as permissões adequadas para evitar falhas de escrita:
   ```bash
   mkdir -p shuffle-database
   sudo chown -R 1000:1000 shuffle-database
   ```

3. Edite o arquivo `.env` (ou revise as variáveis padrão) garantindo que a porta da interface web (`FRONTEND_PORT=3001` e `FRONTEND_PORT_HTTPS=3443`) não colida com outros serviços locais (como o TheHive na `9000` ou Wazuh na `443`).

4. Inicie os contêineres em segundo plano:
   ```bash
   docker compose up -d
   ```

5. Acompanhe os logs para confirmar que o backend e o OpenSearch subiram sem erros:
   ```bash
   docker compose ps
   ```

---

## 4. Acesso Inicial e Criação da Conta de Administrador

Após cerca de 60 segundos para a inicialização do OpenSearch:

1. Abra o navegador no Windows e acesse:
   ```text
   https://localhost:3443
   ```
   *(Aceite o certificado autoassinado de laboratório; opcionalmente, acesse via HTTP em `http://localhost:3001`).*

2. Na primeira tela, crie o usuário administrador inicial (ex.: `soc-admin@contoso.com`) com uma senha forte de laboratório.

3. Ao entrar no painel, navegue até **Workflows** no menu superior.

---

## 5. Construindo seu Primeiro Playbook: Wazuh → Shuffle → TheHive

Vamos estruturar um workflow tático de resposta a incidentes: sempre que o **Wazuh** detectar múltiplas falhas de autenticação ou enumeração de contas (`rule.level >= 10`), o alerta é enviado ao **Shuffle**, que extrai o IP de origem, verifica se é um IP público e cria automaticamente um caso no **TheHive**.

### Passo 1: Criar o Gatilho (Webhook Trigger) no Shuffle
1. Em **Workflows > New Workflow**, nomeie o fluxo como `Wazuh-Auto-Triage-TheHive`.
2. Arraste o gatilho **Webhook** para a área de trabalho.
3. Copie a URL do Webhook gerada localmente (ex.: `http://localhost:5001/api/v1/hooks/webhook_...`).
4. Clique em **Start** no nó do Webhook para deixá-lo em modo de escuta.

### Passo 2: Configurar o Wazuh para Enviar Alertas ao Shuffle
No arquivo de configuração do Wazuh Manager (`/var/ossec/etc/ossec.conf`), adicione um bloco `<integration>` apontando para a URL do Webhook do Shuffle (usando o IP da rede Docker ou `host.docker.internal`):

```xml
<integration>
  <name>custom-shuffle</name>
  <hook_url>http://host.docker.internal:5001/api/v1/hooks/webhook_seu_id_aqui</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

Reinicie o Wazuh Manager para ativar o envio automático dos eventos em JSON.

### Passo 3: Extrair o IP e Criar o Caso no TheHive
1. No editor visual do Shuffle, conecte o nó **Webhook** a um nó do app **TheHive** (já nativo na biblioteca do Shuffle).
2. Configure a autenticação do app **TheHive** utilizando uma API Key gerada no seu container do TheHive (`http://host.docker.internal:9000`), armazenando o valor de forma segura como um *secret* criptografado nas configurações de autenticação do Shuffle.
3. Selecione a ação **`Create Case`** e mapeie os campos recebidos do JSON do Webhook:
   - **Title:** `[Wazuh] $exec.all_fields.rule.description`
   - **Severity:** `2` (Média) ou mapeamento dinâmico por nível da regra
   - **Description:** `Agente: $exec.all_fields.agent.name | IP Origem: $exec.all_fields.data.srcip`
   - **Tags:** `["wazuh", "auto-triage", "shuffle"]`
4. Adicione um segundo nó do TheHive com a ação **`Create Observable`** para anexar `$exec.all_fields.data.srcip` automaticamente como observável do tipo `ip` dentro do caso recém-criado.

---

## 6. Boas Práticas de Segurança e Próximos Passos

Ao operar playbooks automatizados de SOAR em laboratório ou produção:

- **Proteção de Secrets:** Nunca deixe chaves de API em texto puro dentro de blocos de código ou requisições HTTP manuais no workflow; utilize sempre o cofre de autenticação nativo do Shuffle.
- **Controle de Loop (Deduplicação):** Antes de criar um novo caso no TheHive, adicione uma condição (`Branch / Condition`) verificando se já existe um caso aberto nas últimas 24 horas para o mesmo IP ou usuário, evitando enxurradas de tickets duplicados.
- **Evolução do Fluxo:** Conecte o nó do **Cortex** logo após a criação do observável para disparar analisadores de reputação automaticamente e notificar o time de SOC via webhook interno (Mattermost, Teams ou Slack) apenas quando o risco for confirmado.
