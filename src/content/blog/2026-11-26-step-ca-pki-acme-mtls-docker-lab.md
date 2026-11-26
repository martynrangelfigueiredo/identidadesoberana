---
title: "Smallstep (step-ca) em Docker e WSL2: PKI interna, ACME e certificados de curta duração"
description: "Guia prático para montar uma PKI local com Smallstep step-ca no Docker e WSL2 (Windows Enterprise), emitindo certificados ACME e mTLS em ambiente isolado."
date: 2026-11-26
categoria: IAM
tags: [pki, mtls, acme, smallstep, zero-trust, docker, wsl2, open-source]
nivel: Intermediário
draft: false
---

> **TL;DR:** Serviços internos de SOC e IAM em laboratório (Keycloak, Wazuh, APIs de automação) frequentemente rodam com HTTP simples ou certificados autoassinados sem confiança. Este guia mostra como subir uma Autoridade Certificadora (CA) interna com **Smallstep (`step-ca`)** no Docker e WSL2, emitir certificados de curta duração via **ACME** e configurar **mTLS** sem depender de CAs públicas.

---

## 1. Por que operar uma PKI interna em laboratório Zero Trust?

Em ambientes corporativos e laboratórios locais no Windows Enterprise com WSL2, usar certificados autoassinados avulsos gera alertas constantes nos navegadores, quebra integrações OIDC/SAML e acostuma a equipe a ignorar avisos de TLS. Por outro lado, emitir certificados públicos para hosts internos (`*.lab.local`) expõe nomes de infraestrutura em logs públicos de *Certificate Transparency*.

O **Smallstep (`step-ca`)** resolve esse cenário com uma infraestrutura de chaves públicas (*PKI*) leve e *open-source*:
- **Suporte nativo ao protocolo ACME (RFC 8555):** Permite que proxies reversos como Caddy, Traefik ou Nginx renovem certificados internos automaticamente.
- **Certificados de curta duração:** Emissão padrão com validade de 24 horas (ou menos), reduzindo o impacto caso uma chave privada seja comprometida.
- **mTLS (*Mutual TLS*):** Autenticação forte entre microsserviços, coletores de logs e APIs sem depender apenas de *secrets* estáticos.
- **Execução 100% local:** Toda a hierarquia (Root CA e Intermediate CA) permanece restrita ao diretório do laboratório no WSL2.

---

## 2. Pré-requisitos e isolamento no WSL2

| Componente | Especificação Mínima | Observação |
|---|---|---|
| **Sistema Host** | Windows 10/11 Enterprise com WSL2 | Ubuntu 22.04/24.04 atualizado no WSL2. |
| **Container Engine** | Docker Desktop ou Docker Engine no WSL2 | Rede local dedicada para o laboratório. |
| **Imagem Oficial** | `smallstep/step-ca` e `smallstep/step-cli` | Vinculação restrita a `127.0.0.1` na porta `9000`. |

---

## 3. Subindo o step-ca com Docker Compose em loopback

Crie um diretório dedicado para o laboratório e defina o arquivo `compose.yml` com vínculo estrito à interface de loopback (`127.0.0.1`) para evitar exposição na rede externa do host Windows:

```yaml
services:
  step-ca:
    image: smallstep/step-ca:latest
    container_name: lab-step-ca
    restart: unless-stopped
    ports:
      - "127.0.0.1:9000:9000"
    environment:
      - DOCKER_STEPCA_INIT_NAME=Lab Internal CA
      - DOCKER_STEPCA_INIT_DNS_NAMES=localhost,step-ca,127.0.0.1
      - DOCKER_STEPCA_INIT_PROVISIONER_NAME=admin@lab.local
    volumes:
      - step_data:/home/step

volumes:
  step_data:
```

Inicie o serviço e acompanhe a inicialização da Root CA e da Intermediate CA:

```bash
mkdir -p ~/lab-pki && cd ~/lab-pki
docker compose up -d
docker compose logs -f step-ca
```

Na primeira execução, o contêiner gera automaticamente uma senha aleatória para a chave da CA dentro do volume `step_data` (em `/home/step/secrets/password`). Guarde o *fingerprint* da Root CA exibido nos logs para validar a confiança do cliente.

---

## 4. Habilitando o provisioner ACME e emitindo certificados

Para permitir que proxies reversos e serviços locais solicitem certificados automaticamente via **ACME**, adicione o provisioner ACME dentro do contêiner:

```bash
docker exec -it lab-step-ca step ca provisioner add acme --type ACME
docker compose restart step-ca
```

Em seguida, valide o endpoint de saúde e a lista de provisioners ativos:

```bash
curl -sk https://127.0.0.1:9000/health
docker exec -it lab-step-ca step ca provisioner list
```

### Emitindo um certificado de servidor sob demanda

Para gerar rapidamente um certificado TLS válido por 24 horas para um serviço local (por exemplo, `keycloak.lab.local`), execute:

```bash
docker exec -it lab-step-ca step ca certificate \
  "keycloak.lab.local" \
  /home/step/keycloak.crt \
  /home/step/keycloak.key \
  --provisioner admin@lab.local \
  --password-file /home/step/secrets/password
```

Para extrair o certificado raiz público (`root_ca.crt`) e instalá-lo apenas no ambiente do seu laboratório (ou no repositório de confiança do usuário no WSL2):

```bash
docker cp lab-step-ca:/home/step/certs/root_ca.crt ./root_ca.crt
```

No Ubuntu/WSL2, você pode testar a cadeia com `curl` apontando explicitamente para a CA do laboratório sem alterar o sistema inteiro:

```bash
curl --cacert ./root_ca.crt https://127.0.0.1:9000/health
```

---

## 5. Boas práticas de segurança e mTLS

| Controle | Recomendação Prática | Benefício |
|---|---|---|
| **Validade curta** | Manter certificados de servidor entre 12h e 24h com renovação automática via ACME. | Elimina dependência de CRLs pesadas e limita janela de abuso. |
| **Proteção da Root CA** | Manter a chave da Root CA offline ou isolada; operar emissões apenas pela Intermediate CA. | Permite revogar ou girar a intermediária sem reimplantar a raiz. |
| **mTLS entre serviços** | Exigir certificado de cliente emitido pela mesma CA interna em APIs administrativas. | Impede acesso lateral mesmo se uma porta interna ficar acessível. |
| **Higiene de volume** | Restringir permissões do volume `step_data` e nunca versionar arquivos de `/home/step/secrets/` em Git. | Evita vazamento da chave privada da Autoridade Certificadora. |

---

## 6. Mapeamento de Controles e Referências

- **Smallstep Documentation:** [step-ca Overview & ACME Provisioner](https://smallstep.com/docs/step-ca/)
- **Microsoft Learn (WSL2):** [Documentação oficial do Windows Subsystem for Linux](https://learn.microsoft.com/en-us/windows/wsl/)
- **IETF RFC 8555:** Automatic Certificate Management Environment (ACME)
- **NIST SP 800-57 / CSF 2.0 (`PR.DS-02`):** Proteção de dados em trânsito com criptografia forte e gestão de ciclo de vida de chaves.
- **CIS Controls v8 (`3.10` / `12.2`):** Criptografia de dados em trânsito e arquitetura segura de rede com mTLS.
