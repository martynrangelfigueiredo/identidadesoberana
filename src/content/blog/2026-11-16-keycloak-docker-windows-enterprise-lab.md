---
title: "Laboratório local de IAM: subindo o Keycloak no Windows Enterprise com Docker e WSL 2"
description: "Guia prático para criar um laboratório local de IAM no Windows Enterprise com Docker Desktop, WSL 2 e Keycloak 26 com PostgreSQL persistente."
date: 2026-11-16
categoria: IAM
tags: [keycloak, iam, docker, windows-enterprise, wsl2, lab, oidc, open-source]
nivel: Intermediário
---

Para analistas de SOC, engenheiros de identidade e arquitetos de conformidade, dominar a teoria de Single Sign-On (SSO), federação OIDC e controle de acessos é indispensável. No entanto, testar fluxos de autenticação, políticas de MFA e federação diretamente em tenants de nuvem corporativa nem sempre é viável ou seguro.

Montar um laboratório local de **Keycloak** — o provedor de identidade (IdP) e gerenciador de acessos de código aberto padrão da indústria — permite simular fluxos complexos de autenticação, testar integrações com aplicações locais e compreender a arquitetura de federação de identidades sem gastar créditos de nuvem.

> **TL;DR para o Laboratório:** Para rodar o Keycloak 26+ com PostgreSQL no Windows Enterprise sem sobrecarregar sua máquina corporativa, limite a memória do WSL 2 no arquivo `.wslconfig` (ex.: 4 GB a 6 GB), utilize a engine WSL 2 no Docker Desktop e execute o stack em modo de desenvolvimento local (`start-dev`) com volumes nomeados para persistência.

> 📘 **Referência Oficial:** Este guia baseia-se na documentação oficial do projeto Keycloak e nos padrões da Linux Foundation / CNCF:
> - [Keycloak — Running Keycloak in a container (Official Guides)](https://www.keycloak.org/guides#server)
> - [Keycloak — Getting started with Keycloak and Docker](https://www.keycloak.org/getting-started/getting-started-docker)

---

## 1. Por que montar esse laboratório no Windows Enterprise?

Em ambientes corporativos com Windows 10/11 Enterprise, a maioria dos profissionais de segurança possui estações de trabalho potentes com Hyper-V e WSL 2 disponíveis. A vantagem de utilizar containers nesse cenário inclui:

1. **Isolamento Local Completo:** Nenhum dado de autenticação, hash de senha ou token transita fora da sua máquina local.
2. **Custo Zero de Licenciamento:** O Keycloak é distribuído sob licença Apache 2.0, sendo a base tecnológica do Red Hat build of Keycloak (antigo RH-SSO).
3. **Simetria com Padrões de Mercado:** Os mesmos protocolos implementados pelo Microsoft Entra ID (OpenID Connect, OAuth 2.0, SAML 2.0) são configuráveis no Keycloak, permitindo entender o que ocorre "debaixo do capô" dos tokens JWT e das requisições de autorização.

---

## 2. Ajuste Essencial: Limitando o consumo de RAM no WSL 2

O subsistema WSL 2 aloca dinamicamente até 50% ou mais da memória RAM física da máquina hospedeira. Para evitar travamentos em laptops corporativos enquanto o Docker roda o Keycloak e o PostgreSQL, configure o arquivo `.wslconfig` no seu diretório de usuário do Windows:

1. Abra o PowerShell ou Executar (`Win + R`) e crie/edite o arquivo:
   ```powershell
   notepad "$env:USERPROFILE\.wslconfig"
   ```
2. Adicione os limites abaixo recomendados para uma estação corporativa:
   ```ini
   [wsl2]
   memory=4GB       # Limita a memória máxima do WSL 2
   processors=2     # Limita a quantidade de núcleos de CPU
   swap=2GB         # Arquivo de paginação do Linux
   localhostForwarding=true
   ```
3. Reinicie o WSL 2 para aplicar a restrição:
   ```powershell
   wsl --shutdown
   ```

---

## 3. Arquivo `docker-compose.yml` para Laboratório Local

Crie uma pasta para o seu laboratório no terminal (ex.: `mkdir keycloak-lab && cd keycloak-lab`) e adicione o arquivo `docker-compose.yml` a seguir.

Utilizamos a imagem oficial do Keycloak baseada em Quarkus conectada a um banco de dados PostgreSQL 16 isolado em uma rede interna de bridge:

```yaml
services:
  postgres:
    image: postgres:16-alpine
    container_name: keycloak-db
    restart: unless-stopped
    environment:
      POSTGRES_DB: keycloak
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: keycloak_lab_password_2026
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - keycloak-net
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U keycloak -d keycloak"]
      interval: 10s
      timeout: 5s
      retries: 5

  keycloak:
    image: quay.io/keycloak/keycloak:26.0
    container_name: keycloak-server
    restart: unless-stopped
    command: start-dev
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: keycloak_lab_password_2026
      KC_BOOTSTRAP_ADMIN_USERNAME: admin
      KC_BOOTSTRAP_ADMIN_PASSWORD: admin_lab_password_2026
      KC_HTTP_ENABLED: "true"
      KC_HOSTNAME_STRICT: "false"
      KC_HOSTNAME_STRICT_HTTPS: "false"
    ports:
      - "127.0.0.1:8080:8080"
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - keycloak-net

volumes:
  postgres_data:
    driver: local

networks:
  keycloak-net:
    driver: bridge
```

> 🔒 **Dica de Segurança Operacional:** Note que amarramos a porta exclusivamente ao loopback (`127.0.0.1:8080:8080`). Isso impede que outros computadores da rede interna da sua empresa acessem o servidor do Keycloak rodando no seu notebook.

---

## 4. Subindo o Container e Acessando o Console

Com o Docker Desktop rodando no Windows, execute no terminal:

```bash
docker compose up -d
```

Acompanhe os logs de inicialização até que o servidor reporte prontidão:

```bash
docker compose logs -f keycloak
```

Assim que a mensagem `Listening on: http://0.0.0.0:8080` for exibida:
1. Abra o navegador e acesse: `http://localhost:8080`
2. Clique em **Administration Console**
3. Faça login com as credenciais administrativas de laboratório:
   * **Usuário:** `admin`
   * **Senha:** `admin_lab_password_2026`

---

## 5. Primeiros Passos de IAM no Keycloak

Para iniciar suas simulações de arquitetura de identidade:

### 1. Crie um Realm Dedicado
Nunca utilize o realm `master` para cadastrar usuários ou aplicações de teste. O `master` deve ser reservado estritamente para a administração do próprio Keycloak.
* No menu superior esquerdo, clique no seletor de realms e escolha **Create Realm**.
* Nomeie como `lab-corporativo` e clique em **Create**.

### 2. Cadastre uma Aplicação Cliente (Client OIDC)
* Navegue até **Clients** > **Create client**.
* **Client type:** `OpenID Connect`.
* **Client ID:** `app-portal-interno`.
* Avance para **Capability config**:
  * Mantenha **Client authentication** ativado caso queira simular credenciais de aplicação (*client secrets*) ou desative para SPAs/Front-ends públicos utilizando PKCE.
* Em **Login settings**, defina:
  * **Valid redirect URIs:** `http://localhost:3000/*` (ou a URL da aplicação que você for testar).

### 3. Cadastre um Usuário e Ative MFA Local
* Navegue até **Users** > **Add user**.
* Preencha o nome de usuário (ex.: `colaborador.teste`) e e-mail fictício (`colaborador@contoso.com`).
* Na aba **Credentials**, defina uma senha inicial e desmarque *Temporary*.
* Para simular enforcement de MFA sem custos, adicione a ação obrigatória **Configure OTP** (*Required Actions*). No próximo login desse usuário, o Keycloak exigirá o pareamento com um aplicativo autenticador como Google Authenticator, FreeOTP ou Microsoft Authenticator.

---

## 6. Procedimento de Encerramento e Manutenção do Lab

Quando terminar os testes do dia, encerre os containers sem perder suas configurações salvas no banco de dados:

```bash
# Para pausar o laboratório mantendo os dados persistidos:
docker compose down

# Para reiniciar rapidamente no dia seguinte:
docker compose up -d

# Caso queira resetar o laboratório do zero apagando os volumes:
docker compose down -v
```

Com essa base em execução no seu Windows Enterprise, você possui uma plataforma de estudos de IAM pronta para testar federações OIDC, SAML 2.0 e simulações de Zero Trust sem qualquer dependência externa.

