---
title: "SIEM e XDR com Wazuh: implantação local no Windows Enterprise via Docker"
description: "Guia passo a passo para implantar o Wazuh (Manager, Indexer e Dashboard) no Windows Enterprise com Docker Desktop e WSL 2 para testes práticos de SOC."
date: 2026-11-17
categoria: SOC
tags: [wazuh, siem, xdr, docker, windows-enterprise, wsl2, lab, open-source, soc]
nivel: Intermediário
---

Para analistas de SOC, engenheiros de detecção e profissionais de resposta a incidentes, compreender como logs são coletados, decodificados e correlacionados é tão importante quanto dominar plataformas de nuvem corporativa. Em muitas situações, experimentar novas regras de detecção, testar scripts de evasão de defesas ou simular ataques em ambientes corporativos de produção não é permitido por políticas de segurança.

Criar um laboratório local de **Wazuh** — a plataforma de código aberto mais adotada no mundo para **SIEM (Security Information and Event Management)** e **XDR (Extended Detection and Response)** — permite analisar telemetria de endpoints em tempo real, testar regras personalizadas e investigar alertas táticos sem depender de telemetria externa ou custos de licenciamento.

> **TL;DR para o Laboratório:** Para rodar o stack completo do Wazuh (Manager, Indexer e Dashboard) no Windows Enterprise via Docker, configure o WSL 2 com no mínimo 6 GB de memória RAM e eleve o parâmetro `vm.max_map_count` para `262144` no kernel do Linux, garantindo que o motor de busca do OpenSearch inicialize sem falhas.

> 📘 **Referência Oficial:** Este guia baseia-se na documentação oficial do projeto Wazuh:
> - [Wazuh Documentation — Deployment with Docker](https://documentation.wazuh.com/current/deployment-options/docker/index.html)
> - [Wazuh Agent installation on Windows endpoints](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html)

---

## 1. Por que Rodar o Wazuh Localmente em Estações Corporativas?

Em ambientes corporativos baseados em Windows 10/11 Enterprise, analistas de segurança geralmente contam com processadores multithread e memórias entre 16 GB e 32 GB. Utilizar o Docker Desktop apoiado no WSL 2 para orquestrar o Wazuh traz vantagens diretas:

1. **Soberania e Isolamento Total dos Dados:** Os eventos, hashes e logs gerados durante os testes permanecem estritamente restritos à sua máquina local (localhost).
2. **Ciclo Completo de SIEM e XDR:** O Wazuh integra análise de logs, integridade de arquivos (FIM), detecção de vulnerabilidades e resposta ativa em um único console.
3. **Mapeamento Nativo com o MITRE ATT&CK:** Todo alerta gerado no Wazuh já é automaticamente associado a táticas e técnicas do framework MITRE ATT&CK.

---

## 2. Ajustes Obrigatórios no Windows Enterprise e WSL 2

O Wazuh Indexer é construído sobre o OpenSearch e exige configurações específicas de paginação de memória e limites no WSL 2 para evitar que o container seja finalizado com erro de falta de memória (OOM).

### Passo 1: Ajustar a memória no `.wslconfig`
No seu Windows, abra o arquivo de configuração global do WSL 2 via PowerShell:

```powershell
notepad "$env:USERPROFILE\.wslconfig"
```

Configure os limites adequados para o stack:

```ini
[wsl2]
memory=6GB            # Mínimo recomendado para o stack single-node do Wazuh
processors=4          # Alocação de 4 núcleos virtuais
swap=2GB              # Paginação adicional em disco
localhostForwarding=true
```

### Passo 2: Configurar o `vm.max_map_count` no WSL 2
O motor de indexação exige que o Linux suporte ao menos 262.144 áreas de memória mapeadas. Abra seu terminal WSL 2 (ex.: Ubuntu) ou execute direto pelo PowerShell:

```powershell
wsl -d Ubuntu -u root sysctl -w vm.max_map_count=262144
```

Para tornar essa alteração persistente no WSL 2, adicione a linha no arquivo `/etc/sysctl.conf`:

```bash
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

Reinicie o subsistema WSL para aplicar as mudanças:

```powershell
wsl --shutdown
```

---

## 3. Subindo o Stack Wazuh Single-Node com Docker Compose

O repositório oficial do Wazuh disponibiliza um modelo de Docker Compose para implantação em nó único (*single-node*), ideal para estações de trabalho e laboratórios.

1. No terminal do WSL 2 ou PowerShell, clone o repositório de containers do Wazuh:
   ```bash
   git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.2 --depth=1
   cd wazuh-docker/single-node
   ```

2. Gere os certificados TLS internos necessários para a comunicação criptografada entre os componentes:
   ```bash
   docker compose -f generate-indexer-certs.yml run --rm generator
   ```

3. Inicie os três serviços principais em segundo plano:
   ```bash
   docker compose up -d
   ```

4. Verifique se os três containers estão em execução saudável:
   ```bash
   docker compose ps
   ```

Os serviços inicializados são:
- **`single-node-wazuh.manager-1`:** Processador de regras, decodificadores e porta de comunicação com os agentes (portas 1514/TCP, 1515/TCP e 55000/TCP).
- **`single-node-wazuh.indexer-1`:** Motor OpenSearch para indexação de alertas (porta 9200/TCP).
- **`single-node-wazuh.dashboard-1`:** Interface web do analista (porta 443/TCP).

---

## 4. Acessando o Console e Registrando o Agente no Windows

Após cerca de 2 minutos para a inicialização completa dos índices:

1. Abra seu navegador no Windows e acesse:
   ```text
   https://localhost
   ```
2. Aceite o aviso de certificado autoassinado (ambiente de laboratório).
3. Efetue o logon com as credenciais padrão do compose:
   - **Usuário:** `admin`
   - **Senha:** `SecretPassword***` (consulte ou altere no arquivo `.env` antes do deploy).

### Instalando o Agente Wazuh no próprio Windows

Para que o seu laboratório comece a receber telemetria de segurança real do seu sistema operacional Windows:

1. Baixe o instalador MSI do Wazuh Agent oficial (versão 4.9+).
2. Abra o PowerShell como Administrador e instale o agente apontando para o seu container local:
   ```powershell
   .\wazuh-agent-4.9.2-1.msi /q WAZUH_MANAGER="127.0.0.1" WAZUH_REGISTRATION_SERVER="127.0.0.1" WAZUH_AGENT_NAME="WIN-LAB-ENTERPRISE"
   ```
3. Inicie o serviço do agente no Windows:
   ```powershell
   NET START WazuhSvc
   ```
4. No Wazuh Dashboard, acesse a lâmina **Endpoints Summary**: em poucos segundos o agente aparecerá com status **Active**.

---

## 5. Simulação Prática de Detecção: Execução Suspeita no SOC

Com o agente conectado e monitorando o canal de eventos de segurança do Windows (*Security Event Log* e *Sysmon*):

1. **Simulação:** Abra um prompt de comando no Windows e execute uma consulta de reconhecimento de contas locais típica de invasores:
   ```cmd
   net user Administrator
   net localgroup Administrators
   ```
2. **Inspeção no Dashboard:**
   - Acesse **Wazuh Dashboard > Security events**.
   - Na barra de pesquisa do OpenSearch, filtre por:
     ```lucene
     agent.name: "WIN-LAB-ENTERPRISE" AND rule.level: >= 3
     ```
   - O Wazuh correlacionará os eventos de auditoria do Windows (IDs 4798 e 4799 - Enumeração de grupos locais) com a regra de reconhecimento do MITRE ATT&CK **T1087 (Account Discovery)**.

3. **Criação de Regra Personalizada:**
   No diretório do container do manager (`/var/ossec/etc/rules/local_rules.xml`), analistas podem criar detecções próprias. Por exemplo, para alertar sobre a execução do `whoami /priv`:
   ```xml
   <group name="windows,powershell,">
     <rule id="100002" level="7">
       <if_sid>60103</if_sid>
       <field name="win.eventdata.commandLine">whoami /priv</field>
       <description>Tentativa de enumeracao de privilegios locais detectada: whoami /priv</description>
       <mitre>
         <id>T1033</id>
       </mitre>
     </rule>
   </group>
   ```

---

## 6. Próximos Passos no Laboratório de Segurança Aberta

Com o Wazuh em operação estável no Docker Desktop, você dispõe de uma infraestrutura completa de SIEM e XDR para:
- Conectar logs de outros containers (como o laboratório de Keycloak criado anteriormente).
- Testar integrações de automação com ferramentas de SOAR como o **Shuffle** e **TheHive**.
- Simular técnicas de bypass de controles e aprimorar a engenharia de detecção sem riscos a ambientes produtivos.
