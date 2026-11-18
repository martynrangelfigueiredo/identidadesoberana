---
title: "SOAR com TheHive e Cortex: laboratório de resposta a incidentes no Docker"
description: "Guia completo para implantar TheHive e Cortex no Windows Enterprise com Docker e WSL 2, estruturando triagem, gestão de casos e automação de SOC."
date: 2026-11-18
categoria: SOC
tags: [thehive, cortex, soar, docker, windows-enterprise, wsl2, lab, open-source, soc]
nivel: Intermediário
---

No dia a dia de um Centro de Operações de Segurança (SOC), detectar uma ameaça por meio de um SIEM (como Wazuh ou Microsoft Sentinel) é apenas a primeira etapa do trabalho defensivo. A fase seguinte — triar o alerta, qualificar os indicadores de comprometimento (IoCs), registrar a linha do tempo, coordenar tarefas entre analistas e acionar contenções — exige uma plataforma dedicada de resposta a incidentes (**SIRP - Security Incident Response Platform**) integrada a recursos de orquestração e automação (**SOAR - Security Orchestration, Automation, and Response**).

No ecossistema de software livre e de infraestrutura aberta, a combinação entre o **TheHive** (plataforma de gerenciamento de casos de segurança) e o **Cortex** (motor de análise e resposta ativa para enriquecimento de observáveis) é a principal referência da indústria.

Neste guia prático, você aprenderá a arquitetar e implantar um laboratório completo de TheHive e Cortex no Windows Enterprise com Docker Desktop e WSL 2, permitindo testar playbooks de resposta a incidentes, enriquecer observáveis e estruturar a governança de casos em um ambiente 100% local e isolado.

> **TL;DR para o Laboratório:** Para executar o cluster composto por TheHive, Cortex, Cassandra, Elasticsearch e MinIO no Windows Enterprise com WSL 2, certifique-se de alocar ao menos 6 GB a 8 GB de memória RAM no `.wslconfig` e utilize a rede interna em modo ponte no Docker Compose para comunicação segura entre os contêineres.

> 📘 **Referências Oficiais:** Este guia baseia-se na documentação oficial dos projetos TheHive e Cortex:
> - [TheHive Project Documentation (StrangeBee)](https://docs.strangebee.com/)
> - [TheHive GitHub Repository](https://github.com/TheHive-Project/TheHive)
> - [Cortex Project Documentation](https://github.com/TheHive-Project/Cortex)

---

## 1. Por que Integrar TheHive e Cortex na Operação de SOC?

Em equipes de resposta a incidentes (CSIRT/CERT) e SOCs corporativos, planilhas de chamados comuns e sistemas genéricos de ITSM não oferecem os recursos necessários para investigações cibernéticas. O TheHive e o Cortex trazem funcionalidades projetadas especificamente para operações defensivas:

1. **Gestão de Casos Orientada a Ameaças:** Cada caso reúne alertas recebidos, linha do tempo detalhada, árvore de tarefas operacionais e catálogo de observáveis (endereços IP, hashes de arquivos, domínios, URLs e contas de usuário).
2. **Enriquecimento Automatizado com Cortex:** O Cortex expõe dezenas de analisadores (*analyzers*) que consultam bases de inteligência de ameaças (Threat Intelligence) como VirusTotal, AbuseIPDB, Shodan e MISP com um único clique ou via automação.
3. **Padronização com Modelos de Casos (Case Templates):** Defina playbooks padronizados para incidentes recorrentes (ex.: phishing, infecção por ransomware, vazamento de credenciais), garantindo que todo analista siga o mesmo procedimento de contenção e erradicação.
4. **Isolamento e Controle Total dos Dados:** Em ambientes com restrições rígidas de conformidade (LGPD/GDPR), dados de investigações internas permanecem sob custódia estrita do time local.

---

## 2. Pré-requisitos e Ajustes no Windows Enterprise (WSL 2)

O stack do TheHive é robusto e depende de um banco de dados distribuído (Apache Cassandra), um motor de indexação (Elasticsearch) e um armazenamento de objetos compatível com S3 (MinIO) para armazenar evidências e anexos de casos.

### Passo 1: Ajustar a memória no `.wslconfig`

No PowerShell, abra o arquivo global do WSL 2:

```powershell
notepad "$env:USERPROFILE\.wslconfig"
```

Configure a alocação de memória necessária para suportar os contêineres:

```ini
[wsl2]
memory=8GB            # Recomendado para TheHive, Cortex, Cassandra e Elasticsearch
processors=4          # 4 núcleos de processamento
swap=4GB              # Área de swap em disco
localhostForwarding=true
```

### Passo 2: Configurar limites de memória virtual do Elasticsearch

O Elasticsearch exige um limite elevado de áreas de memória mapeadas no kernel Linux:

```powershell
wsl -d Ubuntu -u root sysctl -w vm.max_map_count=262144
```

Persista a configuração adicionando ao `/etc/sysctl.conf` dentro do WSL 2:

```bash
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

Reinicie o WSL 2 pelo PowerShell para aplicar os limites:

```powershell
wsl --shutdown
```

---

## 3. Estrutura do Laboratório com Docker Compose

Crie um diretório de trabalho dedicado para o laboratório no seu ambiente local (ex.: no terminal do WSL 2 ou PowerShell):

```bash
mkdir -p ~/thehive-lab && cd ~/thehive-lab
```

Crie o arquivo `docker-compose.yml` que orquestra a infraestrutura necessária:

```yaml
version: "3.8"

networks:
  soar-net:
    driver: bridge

volumes:
  cassandra-data:
  elasticsearch-data:
  minio-data:
  thehive-data:
  cortex-data:

services:
  # 1. Banco de Dados NoSQL para Metadados e Linha do Tempo
  cassandra:
    image: cassandra:4.1
    container_name: cassandra-thehive
    restart: unless-stopped
    networks:
      - soar-net
    environment:
      - CASSANDRA_START_RPC=true
      - CASSANDRA_CLUSTER_NAME=thehive
      - HEAP_NEWSIZE=256M
      - MAX_HEAP_SIZE=1024M
    volumes:
      - cassandra-data:/var/lib/cassandra

  # 2. Motor de Indexação e Busca Rápida
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.9
    container_name: elasticsearch-thehive
    restart: unless-stopped
    networks:
      - soar-net
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    volumes:
      - elasticsearch-data:/usr/share/elasticsearch/data

  # 3. Armazenamento de Objetos para Evidências e Anexos (S3 local)
  minio:
    image: minio/minio:RELEASE.2023-09-07T02-05-02Z
    container_name: minio-thehive
    restart: unless-stopped
    networks:
      - soar-net
    command: server /data --console-address ":9001"
    environment:
      - MINIO_ROOT_USER=thehive-admin
      - MINIO_ROOT_PASSWORD=InitLabPasswordSecure123!
    volumes:
      - minio-data:/data

  # 4. Motor de Análise e Resposta Ativa (Cortex)
  cortex:
    image: thehiveproject/cortex:3.1.8-1
    container_name: cortex-engine
    restart: unless-stopped
    networks:
      - soar-net
    depends_on:
      - elasticsearch
    ports:
      - "9001:9001"
    environment:
      - "JAVA_OPTS=-Xms512m -Xmx512m"
    volumes:
      - cortex-data:/etc/cortex

  # 5. Plataforma de Gestão de Casos e Resposta a Incidentes (TheHive)
  thehive:
    image: thehiveproject/thehive:5.2.0-1
    container_name: thehive-app
    restart: unless-stopped
    networks:
      - soar-net
    depends_on:
      - cassandra
      - elasticsearch
      - minio
      - cortex
    ports:
      - "9000:9000"
    environment:
      - "JAVA_OPTS=-Xms1024m -Xmx1024m"
    volumes:
      - thehive-data:/etc/thehive
```

Inicie o cluster em segundo plano com o comando:

```bash
docker compose up -d
```

Acompanhe o processo de inicialização dos serviços com o log:

```bash
docker compose logs -f thehive
```

> **Dica de Operação:** Na primeira inicialização, o Cassandra e o Elasticsearch levam de 1 a 2 minutos para criar os esquemas e índices iniciais. O TheHive aguarda a disponibilidade do banco de dados antes de abrir a porta 9000/TCP.

---

## 4. Acesso ao Console e Configuração Inicial

Com todos os contêineres saudáveis (`docker compose ps`), abra seu navegador no Windows:

### Acesso ao TheHive
1. Acesse: `http://localhost:9000`
2. Credenciais padrão de primeiro acesso:
   - **Usuário:** `admin@thehive.local`
   - **Senha:** `secret`
3. Altere a senha inicial no primeiro login para um padrão seguro de laboratório.

### Acesso ao Cortex
1. Acesse: `http://localhost:9001`
2. Na tela de inicialização, clique em **Update Database** para aplicar as tabelas no Elasticsearch.
3. Crie o usuário administrador inicial do Cortex com credenciais fortes de laboratório.

---

## 5. Fluxo de Trabalho Prático no SOC: Da Triagem ao Encerramento

Para ilustrar o ciclo de vida operacional dentro do TheHive, vamos simular a triagem de um alerta de segurança:

### Etapa 1: Criação de um Modelo de Caso (Case Template)

Playbooks estruturados evitam que analistas esqueçam passos críticos em momentos de crise. No menu do TheHive:
1. Navegue até **Admin > Case Templates**.
2. Crie um modelo denominado **"Incidente: Suspeita de Comprometimento de Conta"**.
3. Adicione as seguintes tarefas pré-definidas:
   - `Tarefa 1: Validar registros de autenticação (SigninLogs) e MFA`.
   - `Tarefa 2: Identificar endereço IP de origem e verificar reputação`.
   - `Tarefa 3: Revogar sessões ativas (Revoke-MgUserSignSession)`.
   - `Tarefa 4: Forçar redefinição de credenciais`.

### Etapa 2: Abertura e Investigação do Caso

1. Crie um novo caso a partir do modelo criado:
   - **Título:** `Alerta SOC: Logon suspeito a partir de IP anômalo`
   - **Severidade:** `Média`
   - **TLP (Traffic Light Protocol):** `TLP:AMBER`
   - **PAP (Permissible Actions Protocol):** `PAP:GREEN`

2. Adicione os observáveis coletados:
   - Tipo `ip`: `198.51.100.45` (endereço de teste RFC 5737).
   - Tipo `user`: `usuario.suporte@contoso.com`.

### Etapa 3: Execução de Analisadores via Cortex

Quando o Cortex está integrado ao TheHive, o analista clica sobre o observável do endereço IP e seleciona **Run Analyzer**:
- O Cortex consulta serviços configurados (como AbuseIPDB ou MaxMind GeoIP local).
- Em poucos segundos, um relatório tático é anexado ao caso, exibindo país de origem, ASN e histórico de abuso recente.
- Caso o IP possua pontuação de risco elevada, o analista eleva a severidade do caso para `Alta` e executa a tarefa de contenção de sessões.

---

## 6. Próximos Passos: Integrando Wazuh, TheHive e Shuffle

Com o laboratório de TheHive e Cortex funcionando localmente, você já possui a fundação para estruturar uma esteira completa de automação defensiva:

- **Ingestão Direta do Wazuh:** Configure o integrador nativo do Wazuh (`wazuh-integrator`) para enviar alertas de severidade alta diretamente como casos no TheHive via API REST.
- **Automação com Shuffle:** Adicione o motor de SOAR aberto Shuffle para orquestrar ações entre o Wazuh, TheHive e firewalls locais, isolando endpoints automaticamente diante de ameaças confirmadas.
- **Governança e Métricas de SOC:** Utilize os dashboards nativos do TheHive para mensurar indicadores fundamentais de resposta, como **MTTD (Mean Time to Detect)** e **MTTR (Mean Time to Respond)**.

