# Cyber Threat Intelligence Platform

[![Daily ETL Pipeline](https://github.com/Sanak3/Cyber-Threat-Intel/actions/workflows/etl_pipeline.yml/badge.svg)](https://github.com/Sanak3/Cyber-Threat-Intel/actions)
[![Frontend - Vercel](https://img.shields.io/badge/Frontend-Vercel-black?style=flat&logo=vercel)](https://cyber-threat-intel-three.vercel.app)
[![API - Render](https://img.shields.io/badge/Backend-Render-46E3B7?style=flat&logo=render)](https://cyber-threat-intel-mmks.onrender.com)
[![Database - AWS RDS](https://img.shields.io/badge/AWS-RDS%20PostgreSQL-FF9900?style=flat&logo=amazon-aws)](https://aws.amazon.com/rds/)

Plataforma integrada de inteligência contra ameaças cibernéticas (**CTI - Cyber Threat Intelligence**) de nível corporativo. Automatiza a extração incremental de vulnerabilidades críticas (**10.000+ CVEs recentes**) da API oficial do **NIST NVD**, enriquecimento com dados estruturados (**CWE**, **CPE**, catálogo **CISA KEV**), motor de **Machine Learning (TF-IDF + K-Means)**, detecção de caminhos de ataque (**Exploit Chains em Grafos com NetworkX**) e um painel interativo de SOC em **React 19**.

---

## Live Demo

- **SOC Dashboard (Frontend):** [cyber-threat-intel-three.vercel.app](https://cyber-threat-intel-three.vercel.app)
- **API Health Check (Backend):** [cyber-threat-intel-mmks.onrender.com/api/health](https://cyber-threat-intel-mmks.onrender.com/api/health)
- **API Overview Consolidado:** [cyber-threat-intel-mmks.onrender.com/api/threats/overview](https://cyber-threat-intel-mmks.onrender.com/api/threats/overview)

---

## Arquitetura do Sistema

```text
       [ NIST NVD API 2.0 ] ── (Offset das 10k CVEs Recentes + CWE + CPE + CISA KEV)
                │
                ▼ (Paginação com Pooling TLS / Rate Limit / Backoff Exponencial)
      [ Data Pipeline ETL ] ── (NumPy Vectorized Risk Engine)
                │
                ├─► [ ML Engine: TF-IDF + K-Means ] (Clusterização Semântica de Ameaças)
                ├─► [ ML Engine: Primitivas ] (Mapeamento Cyber Kill Chain Stages 1 a 5)
                └─► [ ML Engine: NetworkX Graphs ] (Detecção de Exploit Chains & Blueprints)
                │
                ▼ (Upsert Atômico em Lote / Índices B-Tree + GIN FTS)
      [ AWS RDS PostgreSQL ] ── (Tabelas: threats + exploit_chains)
                │
                ▼ (SQL Connection Pool / Cache TTL em RAM / Webhook Invalidation)
   [ Backend Node.js / Express ] ── (Deploy no Render / Pré-aquecimento no Boot)
                │
                ▼ (REST API / Compressão / ETag / CORS)
     [ SOC Dashboard React 19 ] ── (Deploy na Vercel / Recharts / Terminal Dark Style)
```

---

## Principais Recursos e Diferenciais de Engenharia

### 1. Ingestão de Dados Resiliente (NIST NVD API 2.0)
- **Offset Dinâmico de CVEs Recentes:** Calcula `startIndex = totalResults - 10000` via chamada leve de descoberta, garantindo a ingestão das ameaças mais recentes em vez de registros legados de 1999.
- **Suporte a Janela Incremental:** Compatível com parâmetros de janela temporal (`lastModStartDate` / `lastModEndDate`), respeitando estritamente o limite de 120 dias da API v2.0.
- **Enriquecimento Estruturado:** Parsing direto de fraquezas (`weaknesses` -> CWE), configurações de software (`configurations` -> fabricante e produto CPE) e marcação do catálogo **CISA KEV** (*Known Exploited Vulnerabilities - Exploited in the Wild*).

### 2. Motor de Machine Learning & Grafos (`ml_engine`)
- **Primitivas Táticas da Cyber Kill Chain:** Classificação determinística com base em CWE estruturado (com fallback heurístico) em 5 estágios: Recon/Info Leak (1), Auth Bypass (2), Injection/RCE (3), PrivEsc (4) e DoS (5).
- **Clusterização Semântica (Scikit-Learn):** Vetorização de texto técnico com **TF-IDF** e agrupamento via **K-Means**, identificando padrões temáticos de vulnerabilidades e persistindo o modelo com `joblib`.
- **Detecção de Exploit Chains (NetworkX):** Modela o espaço de ameaças como um grafo direcionado ($DiGraph$), conecta vulnerabilidades do mesmo ecossistema/CPE com transições de ataque viáveis e consome caminhos sob demanda (`nx.all_simple_paths`) com *degree bounding* para evitar explosão combinatória.
- **Writeup Blueprints Automatizados:** Gera relatórios simulados de exploração contendo contexto da cadeia, comandos de prova de conceito (PoC), impacto cumulativo e recomendações de mitigação.

### 3. Banco de Dados e AppSec (AWS RDS PostgreSQL)
- **Busca de Alta Performance (GIN Full-Text Search):** Consultas textuais aceleradas por índice GIN (`to_tsvector`) sem regressão de desempenho por sequential scans.
- **Proteção contra SQL Wildcard Injection:** Sanitização e escape automático de metacaracteres `%`, `_` e `\` nos filtros de busca textual.
- **Conexão SSL Resiliente:** Configuração segura com suporte a certificados personalizados (`DB_SSL_CA`) e proteção contra falhas de cadeia autoassinada em instâncias cloud.
- **Idempotência de Dados:** Upsert em lote via `psycopg2.extras.execute_values` com cláusulas `ON CONFLICT (cve_id) DO UPDATE`.

### 4. Back-End Otimizado (Node.js & Express)
- **Sub-Millisecond RAM Cache:** Cache em memória com TTL de 60 minutos para endpoints consolidados, reduzindo latência para < 2ms nas consultas em regime.
- **Webhook de Invalidação Ativa:** Rota autenticada `POST /api/internal/cache-flush` disparada ao final da execução do pipeline ETL para garantir dados sempre atualizados sem reiniciar o servidor.
- **Pré-Aquecimento no Boot:** População automática de métricas críticas na inicialização da instância para eliminar gargalos de *cold-start*.

### 5. SOC Dashboard (React 19 + Recharts)
- **Interface Terminal Dark:** Visual voltado a operações de segurança cibernética (SOC/CTI), com gráficos de distribuição de severidade, matriz de ecossistemas tecnológicos e tabela de ameaças.
- **Navegação Server-Side Otimizada:** Paginação dinâmica, filtros por severidade e primitiva de ataque, e pesquisa Full-Text em tempo real.

### 6. Engenharia de Software, Testes & CI/CD
- **Testes Automatizados (Pytest):** Cobertura unitária para parsers de métricas CVSS (v3.1, v3.0, v2.0), classificação de primitivas, enriquecimento de CPE e detecção de cadeias no grafo.
- **Pipeline no GitHub Actions:** Workflow agendado diariamente via cron job (03:00 BRT) que roda a suíte de testes antes de persistir os novos dados no banco de produção.
- **Dependências Congeladas:** `requirements.txt` com restrições explícitas de versão para garantir reprodutibilidade matemática dos modelos de ML.

---

## Endpoints da API

| Método | Endpoint | Descrição | Cache RAM |
| :--- | :--- | :--- | :---: |
| `GET` | `/api/health` | Healthcheck do serviço | — |
| `GET` | `/api/threats/overview` | Payload consolidado (Analytics, Chains, Clusters, Threats iniciais) | Sim (TTL) |
| `GET` | `/api/threats/stats` | Resumo estatístico (Total, Média CVSS, Contagem por severidade) | Sim (TTL) |
| `GET` | `/api/threats/analytics` | Distribuição por severidade e Top ecossistemas afetados | Sim (TTL) |
| `GET` | `/api/threats/chains` | Cadeias de exploração correlacionadas pelo NetworkX | Sim (TTL) |
| `GET` | `/api/threats/clusters` | Agrupamentos semânticos (K-Means) e distribuição de primitivas | Sim (TTL) |
| `GET` | `/api/threats/critical` | Vulnerabilidades de alta criticidade ($CVSS \ge 7.0$) | Sim (TTL) |
| `GET` | `/api/threats` | Catálogo paginado com busca Full-Text (GIN) e filtros táticos | Parcial (Pág 1) |
| `POST` | `/api/internal/cache-flush` | Invalidação do cache em RAM (Protegido por `X-Webhook-Secret`) | — |

---

## Stack Tecnológica

| Camada | Tecnologias |
| :--- | :--- |
| **Pipeline & ML** | Python 3.12, NumPy, Pandas, Scikit-Learn, NetworkX, Joblib, Requests, Psycopg2 |
| **Testes & Qualidade** | Pytest, Unittest |
| **Banco de Dados** | AWS RDS (PostgreSQL 16) com índices B-Tree e GIN FTS |
| **Backend** | Node.js 20+, Express, pg (Connection Pool), CORS, Dotenv |
| **Frontend** | React 19, Vite, Recharts, Axios, CSS3 Cyberpunk/SOC Style |
| **DataOps & Deploy** | GitHub Actions (CI/CD + Cron ETL), Vercel, Render.com |

---

## Estrutura do Repositório

```bash
Cyber-Threat-Intel/
├── .github/
│   └── workflows/
│       └── etl_pipeline.yml         # Testes Pytest + Pipeline diário (GitHub Actions)
├── data_pipeline/
│   ├── extract.py                   # Ingestão de CVEs recentes da API NIST NVD v2.0
│   ├── transform.py                 # Análise matricial NumPy, parsing CVSS e metadados
│   ├── upload_aws.py                # Carga em lote no AWS RDS PostgreSQL e trigger de cache
│   ├── requirements.txt             # Dependências congeladas Python
│   └── ml_engine/                   # Motor de Inteligência Artificial e Grafos
│       ├── __init__.py
│       ├── primitives.py            # Mapeamento CWE e Cyber Kill Chain
│       ├── clusterizer.py           # Clusterização semântica (TF-IDF + K-Means)
│       ├── chain_detector.py        # Detecção de Exploit Chains com NetworkX
│       └── writeup_builder.py       # Gerador de relatórios e Blueprints táticos
├── tests/
│   └── test_pipeline.py             # Testes unitários do pipeline e motor de grafos
├── backend/
│   ├── src/
│   │   ├── db_connect.js            # Pool de conexão PostgreSQL com SSL resiliente
│   │   └── server.js                # API REST com Cache em RAM, FTS e Webhook
│   ├── .env.example                 # Template de variáveis do backend
│   └── package.json                 # Dependências Node.js
├── frontend/
│   ├── src/
│   │   ├── App.jsx                  # SOC Dashboard (Recharts, busca e filtros)
│   │   ├── App.css                  # Estilização Cyber / SOC Dark
│   │   └── main.jsx                 # Entrada React 19
│   ├── index.html                   # HTML base
│   └── package.json                 # Dependências React/Vite
├── .env.example                     # Template de variáveis de ambiente do projeto
├── .gitignore                       # Regras de exclusão Git otimizadas
└── README.md                        # Documentação técnica completa da plataforma
```

---

<div align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=17&pause=1000&color=00FF00&background=0D111700&center=true&vCenter=true&width=450&lines=developer%40Sanak3%3A~%24+Igor+Araujo" alt="developer@Sanak3:~$ Igor Araujo" />
</div>
