# 🛡️ Cyber Threat Intel Pipeline

> Um pipeline de dados de ponta a ponta construído para extrair, processar e analisar vulnerabilidades de cibersegurança (CVEs) em tempo real.

Este projeto foi desenvolvido estrategicamente como um **MVP (Produto Mínimo Viável) de 5 dias**, projetado para demonstrar a integração de engenharia de dados, cloud computing e desenvolvimento full-stack. 

O sistema consome dados brutos da base global do NIST, utiliza matemática de arrays para identificar ameaças críticas e serve esses dados em um dashboard na nuvem.

## 🚀 Arquitetura e Tecnologias (Tech Stack)

O projeto foi desenhado para simular um ambiente corporativo real de Threat Intelligence, utilizando as seguintes tecnologias:

* **Motor de Dados (Data Pipeline):** `Python` + `NumPy` (Extração via API REST, transformação e análise vetorial de risco).
* **Armazenamento e Cloud (Database):** `PostgreSQL` hospedado no `Google Cloud Platform (GCP)`.
* **Backend:** API REST construída com `Node.js` (Express).
* **Frontend:** Dashboard dinâmico construído com `React`.

## ⚙️ Funcionalidades e Componentes da Arquitetura

O ecossistema foi projetado de ponta a ponta, dividindo responsabilidades em microsserviços para garantir escalabilidade e foco em *Data Visualization* e inteligência acionável:

* **Automated Data Engine (Python + NumPy):** Pipeline de ingestão que consome a API REST do NIST, realizando *parsing* de objetos JSON aninhados e limpeza estrutural. Utiliza operações vetoriais do `NumPy` para filtragem de alta performance e cálculo estatístico da matriz de risco (CVSS), isolando automaticamente ameaças de nível Alto e Crítico.
* **Cloud Data Storage (GCP + PostgreSQL):** Arquitetura de banco de dados relacional hospedada nativamente no Google Cloud Platform. Garante persistência segura dos dados de inteligência, com modelagem de tabelas otimizada para consultas `SQL` analíticas e inserções massivas.
* **RESTful API Bridge (Node.js):** Microsserviço de backend estruturado com Express, atuando como ponte de leitura entre o banco na nuvem e o cliente. Fornece rotas assíncronas e estruturadas para servir os dados de vulnerabilidades já lapidados.
* **Threat Intelligence Dashboard (React):** Interface de usuário dinâmica que consome a API Node.js. Apresenta os indicadores de risco e CVEs de forma clara e visual, permitindo que analistas e equipes de segurança corporativa monitorem o cenário de ameaças com agilidade.

## 💻 Como rodar o projeto localmente

### Pré-requisitos
* Sistema Operacional (macOS/Linux preferencialmente)
* Python 3.10 ou superior
* Chave de API gratuita do [NIST NVD](https://nvd.nist.gov/developers/request-an-api-key)

### Passo a Passo da Instalação

1. Clone o repositório e entre na pasta:
```bash
git clone [https://github.com/SEU_USUARIO_AQUI/Cyber-Threat-Intel.git](https://github.com/SEU_USUARIO_AQUI/Cyber-Threat-Intel.git)
cd Cyber-Threat-Intel
