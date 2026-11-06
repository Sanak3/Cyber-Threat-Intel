# Cyber Threat Intelligence Platform

[![CI Full-Stack Quality Gate](https://github.com/Sanak3/Cyber-Threat-Intel/actions/workflows/ci.yml/badge.svg)](https://github.com/Sanak3/Cyber-Threat-Intel/actions/workflows/ci.yml)
[![Daily ETL Pipeline](https://github.com/Sanak3/Cyber-Threat-Intel/actions/workflows/etl_pipeline.yml/badge.svg)](https://github.com/Sanak3/Cyber-Threat-Intel/actions/workflows/etl_pipeline.yml)
[![Frontend - Vercel](https://img.shields.io/badge/Frontend-Vercel-black?style=flat&logo=vercel)](https://cyber-threat-intel-three.vercel.app)
[![API - Render](https://img.shields.io/badge/Backend-Render-46E3B7?style=flat&logo=render)](https://cyber-threat-intel-mmks.onrender.com)
[![Database - AWS RDS](https://img.shields.io/badge/AWS-RDS%20PostgreSQL-FF9900?style=flat&logo=amazon-aws)](https://aws.amazon.com/rds/)

Plataforma integrada de inteligência contra ameaças cibernéticas (**CTI - Cyber Threat Intelligence**) de nível corporativo. Automatiza a extração resiliente das vulnerabilidades mais recentes (**10.000+ CVEs ativas**) da API oficial do **NIST NVD v2.0**, enriquecimento com metadados estruturados (**CVSS v4.0/v3.x/v2.0**, **CWE**, **CPE** e catálogo **CISA KEV**), motor de **Machine Learning (TF-IDF + K-Means)**, detecção de caminhos de ataque (**Exploit Chains em Grafos com NetworkX**) e um painel tático de SOC em **React 19**.

---

## Live Demo

- **SOC Dashboard (Frontend):** [cyber-threat-intel-three.vercel.app](https://cyber-threat-intel-three.vercel.app)
- **API Health Check (Backend):** [cyber-threat-intel-mmks.onrender.com/api/health](https://cyber-threat-intel-mmks.onrender.com/api/health)
- **API Overview Consolidado:** [cyber-threat-intel-mmks.onrender.com/api/threats/overview](https://cyber-threat-intel-mmks.onrender.com/api/threats/overview)

---

## Arquitetura do Sistema

```text
   [ NIST NVD API 2.0 ] ── (Offset das 10k CVEs Recentes + ?noRejected + CWE + CPE + CISA KEV)
            │
            ▼ (Paginação com Pooling TLS / Rate Limit Dinâmico / Backoff Exponencial)
  [ Data Pipeline ETL ] ── (NumPy Vectorized Risk Engine + CVSS v4.0 / v3.x / v2.0)
            │
            ├─► [ ML Engine: Primitivas ] (Mapeamento Determinístico CWE -> Kill Chain 1 a 5)
            ├─► [ ML Engine: TF-IDF + K-Means ] (Clusterização Semântica Anti-Colisão)
            └─► [ ML Engine: NetworkX DiGraph ] (Exploit Chains por CPE & Writeup Blueprints)
            │
            ▼ (TRUNCATE Transacional / Upsert execute_values / Índices B-Tree + COALESCE + GIN)
  [ AWS RDS PostgreSQL ] ── (Tabelas: threats + exploit_chains)
            │
            ▼ (Connection Pool SSL / Cache TTL em RAM / Webhook SHA-256 timingSafeEqual)
[ Backend Node 20 / Express 5 ] ── (Deploy no Render / Pré-aquecimento / Graceful Shutdown)
            │
            ▼ (Single Round-Trip Bootstrap / Compressão Gzip / Helmet / Rate Limit)
 [ SOC Dashboard React 19 ] ── (Deploy na Vercel / Vite 8 / Recharts 3 / Cache Local v2)
```

---

## Principais Recursos e Diferenciais de Engenharia

### 1. Ingestão de Dados Resiliente (NIST NVD API 2.0)
- **Offset Dinâmico de CVEs Recentes:** Calcula `startIndex = totalResults - 10000` via descoberta com retentativas resilientes (abortando com segurança em falhas críticas para impedir ingestão acidental de CVEs legadas de 1999).
- **Filtragem Dupla de CVEs Revogadas:** Exclui candidatos rejeitados diretamente na requisição (`?noRejected`) e valida `vulnStatus == REJECTED` / prefixos `** REJECT **` na transformação.
- **Cascata Completa de Métricas CVSS:** Suporte nativo a **CVSS v3.1 → CVSS v4.0 → CVSS v3.0 → CVSS v2.0**, priorizando avaliações `Primary` (NIST NVD) sobre `Secondary` (CNA/ADP) e normalizando notas $\ge 9.0$ legadas do v2 para `CRITICAL`.
- **Sincronização Incremental e Metadados Oficiais:** Suporte a janelas temporais (`lastModStartDate` / `lastModEndDate` até 120 dias), persistência de datas oficiais (`published` / `lastModified`), extração de **CWE**, **CPE 2.3** (`vendor` / `product`) e flag **CISA KEV** (*Known Exploited Vulnerabilities*).

### 2. Motor de Machine Learning & Grafos (`ml_engine`)
- **Primitivas Táticas da Cyber Kill Chain:** Classificação determinística baseada em 30+ CWEs críticas (com fallback heurístico em regex) nos 5 estágios táticos: `RECON_INFO_LEAK` (1), `AUTH_BYPASS` (2), `INJECTION_RCE` (3), `PRIV_ESC` (4) e `DENIAL_OF_SERVICE` (5).
- **Clusterização Semântica (Scikit-Learn):** Vetorização com **TF-IDF** (`ngram_range=(1, 2)`) e agrupamento **K-Means** ($k=6$), avaliação automática de *Silhouette Score*, precedência semântica de rótulos (evitando falsos positivos entre RCE e Path Traversal), desambiguação de colisões e serialização via `joblib`.
- **Detecção de Exploit Chains (NetworkX):** Constrói um grafo direcionado (`nx.DiGraph`) conectando vulnerabilidades compatíveis por ecossistema e produto CPE, aplicando *degree bounding* (`max_arestas_por_no=6`), iteração sob demanda de `nx.all_simple_paths` e balanceamento multi-ecossistema.
- **Writeup Blueprints Automatizados:** Gera relatórios estruturados para o SOC contendo título tático, resumo executivo, sequência passo a passo de *pivoting*, impacto técnico consolidado e recomendações de mitigação.

### 3. Banco de Dados e AppSec (AWS RDS PostgreSQL & Express 5)
- **Full-Text Search GIN & Ordenação Funcional Indexada:** Buscas textuais aceleradas por índice GIN (`to_tsvector('english', coalesce(descricao, ''))`) combinadas ao índice composto `(nota_cvss DESC, COALESCE(data_publicacao, data_extracao) DESC)` sem *Sequential Scans*.
- **Atomicidade Transacional na Carga:** Substituição limpa de dados legados via `TRUNCATE TABLE threats, exploit_chains` na mesma transação do `execute_values` (`ON CONFLICT DO UPDATE`), garantindo *rollback* integral em falhas de rede ou banco.
- **Blindagem de API:** Headers HTTP seguros com `helmet`, `express-rate-limit` (300 req/15 min por IP real via `trust proxy`), CORS restrito com suporte a Vercel Previews, validação estrita por *allowlist* e escape de curingas SQL (`%`, `_`, `\`).

### 4. Back-End de Alta Performance (Node.js 20 & Express 5)
- **Sub-Millisecond RAM Cache & Bootstrap Consolidado:** Cache em memória (TTL de 60 min) com pré-aquecimento automático no boot (`preAquecerCache`) e endpoint `/api/threats/overview` para carregamento completo do dashboard em um único *round-trip* (< 2ms em regime).
- **Webhook Autenticado em Tempo Constante:** Endpoint interno `POST /api/internal/cache-flush` protegido por `crypto.timingSafeEqual` sobre digests `SHA-256` de tamanho fixo (sem vazamento de comprimento do segredo), invalidando e reaquecendo o cache imediatamente após o ETL.
- **Graceful Shutdown:** Tratamento de sinais `SIGTERM` e `SIGINT` para encerramento ordenado do servidor HTTP e drenagem segura do pool de conexões PostgreSQL (`pg.Pool`).

### 5. SOC Dashboard Interativo (React 19 + Vite 8 + Recharts 3)
- **Hidratação Instantânea Versionada (`v2`):** Renderização imediata (`0ms`) via cache local versionado no `localStorage`, com expurgo automático de chaves legadas e sincronização silenciosa em segundo plano.
- **Filtros Táticos Combináveis:** Filtragem server-side em tempo real por severidade CVSS, catálogo **CISA KEV**, estágios da **Kill Chain**, **ML Clusters** e Full-Text Search (com *debounce* de 400ms e cancelamento via `AbortController`).
- **Modal Split-View de Exploit Chains:** Inspeção interativa de cadeias de ataque e *Writeup Blueprints* integrada diretamente aos cards de ecossistemas mais afetados.

### 6. Qualidade de Código, Testes & CI/CD (GitHub Actions)
- **CI Full-Stack Quality Gate (`ci.yml`):** Pipeline paralelo disparado em todo push/PR validando sintaxe e suíte `pytest` (Python 3.12), integridade sintática dos módulos da API (Node.js 20) e `eslint` + build de produção Vite 8 no frontend.
- **DataOps Diário com Controle de Concorrência (`etl_pipeline.yml`):** Execução agendada diariamente às 03:00 BRT (06:00 UTC) com `concurrency` dedicado (impedindo corridas de *rate limit* na NIST API e *locks* concorrentes no RDS), permissões mínimas (`contents: read`) e validação prévia por testes unitários.

---

## Endpoints da API

| Método | Endpoint | Parâmetros Suportados | Descrição | Cache RAM |
| :--- | :--- | :--- | :--- | :---: |
| `GET` | `/api/health` | — | Healthcheck operacional da API | — |
| `GET` | `/api/threats/overview` | — | Bootstrap consolidado (`stats`, `topTecnologias`, `chains`, `clusters`, `initialThreats`) | Sim (TTL) |
| `GET` | `/api/threats/stats` | — | KPIs globais (Total, Severidades, CISA KEV, Pior Risco e Média CVSS) | Sim (TTL) |
| `GET` | `/api/threats/analytics` | — | Estatísticas globais + Top 10 ecossistemas tecnológicos afetados | Sim (TTL) |
| `GET` | `/api/threats/chains` | `limit` (1–100) | Cadeias de ataque e Writeup Blueprints gerados pelo motor de grafos | Sim (TTL) |
| `GET` | `/api/threats/clusters` | — | Distribuição de clusters semânticos (K-Means) e primitivas da Kill Chain | Sim (TTL) |
| `GET` | `/api/threats/critical` | `limit` (1–1000) | Vulnerabilidades críticas e altas ($\text{CVSS} \ge 7.0$) | — |
| `GET` | `/api/threats` | `page`, `limit`, `search`, `severity`, `kev`, `primitive`, `cluster` | Catálogo paginado server-side com Full-Text Search (GIN) e filtros táticos | Pág. 1 padrão |
| `POST` | `/api/internal/cache-flush` | Header `X-Webhook-Secret` ou `Bearer` | Invalidação imediata e reaquecimento do cache em RAM pós-ETL | — |

---

## Stack Tecnológica

| Camada | Tecnologias |
| :--- | :--- |
| **Pipeline & ML** | Python 3.12, NumPy, Pandas, Scikit-Learn, NetworkX, Joblib, Requests, Psycopg2, Python-Dotenv |
| **Banco de Dados** | AWS RDS (PostgreSQL 16) com índices compostos B-Tree, funcionais (`COALESCE`) e GIN FTS |
| **Backend** | Node.js 20+, Express 5, pg (Connection Pool), Helmet, Express-Rate-Limit, Compression, CORS |
| **Frontend** | React 19, Vite 8, Recharts 3, Axios, ESLint 10, CSS3 Cyberpunk / SOC Dark Style |
| **CI/CD & Cloud** | GitHub Actions (Quality Gate + Cron ETL), Pytest / Unittest, Vercel (Frontend), Render (API) |

---

## Estrutura do Repositório

```text
Cyber-Threat-Intel/
├── .github/
│   └── workflows/
│       ├── ci.yml                       # Quality Gate Full-Stack (Pytest, Node Check, ESLint & Vite Build)
│       └── etl_pipeline.yml             # Cron diário (03:00 BRT) NIST -> AWS RDS + Cache Flush
├── data_pipeline/
│   ├── extract.py                       # Coleta resiliente de CVEs recentes na API NIST NVD v2.0
│   ├── transform.py                     # Matriz vetorial NumPy, cascata CVSS v4/v3/v2 e metadados CWE/CPE/KEV
│   ├── upload_aws.py                    # Carga atômica no AWS RDS, criação de índices e webhook de cache
│   ├── requirements.txt                 # Dependências Python congeladas
│   └── ml_engine/                       # Motor de Inteligência Artificial e Grafos
│       ├── __init__.py
│       ├── primitives.py                # Mapeamento determinístico CWE/CPE e estágios da Cyber Kill Chain
│       ├── clusterizer.py               # Clusterização semântica (TF-IDF + K-Means)
│       ├── chain_detector.py            # Detecção de Exploit Chains em grafos direcionados (NetworkX)
│       └── writeup_builder.py           # Gerador automatizado de Writeup Blueprints para o SOC
├── tests/
│   └── test_pipeline.py                 # Suíte de testes unitários do pipeline ETL e motor de ML/Grafos
├── backend/
│   ├── src/
│   │   ├── db_connect.js                # Pool PostgreSQL com suporte resiliente a SSL/TLS na AWS RDS
│   │   └── server.js                    # API Express 5 com Cache TTL em RAM, GIN FTS, Webhook e Graceful Shutdown
│   ├── .env.example                     # Template de variáveis de ambiente do backend
│   └── package.json                     # Dependências e scripts de verificação Node.js
├── frontend/
│   ├── src/
│   │   ├── App.jsx                      # SOC Dashboard (Recharts, filtros KEV/Clusters/Kill Chain e Modal Chains)
│   │   ├── App.css                      # Sistema de design Cyber / SOC Dark responsivo
│   │   ├── index.css                    # Reset global e tipografia base
│   │   └── main.jsx                     # Ponto de entrada React 19
│   ├── index.html                       # Template HTML com fontes JetBrains Mono e Inter
│   └── package.json                     # Dependências React 19 / Vite 8 / ESLint 10
├── .env.example                         # Template global unificado de variáveis de ambiente
├── .gitignore                           # Regras de exclusão de artefatos (.env, .joblib, builds e caches)
└── README.md                            # Documentação técnica oficial da plataforma
```

---

## Execução Local (Quickstart)

1. **Configurar Variáveis de Ambiente:**
   ```bash
   cp .env.example .env
   # Preencha NIST_API_KEY, credenciais PostgreSQL (DB_*) e INTERNAL_WEBHOOK_SECRET
   ```

2. **Executar Testes e Pipeline ETL / ML (Python 3.12+):**
   ```bash
   python -m venv .venv && source .venv/bin/activate
   pip install -r data_pipeline/requirements.txt
   pytest tests/ -v
   python data_pipeline/upload_aws.py
   ```

3. **Iniciar API Backend e Dashboard Frontend (Node.js 20+):**
   ```bash
   # Terminal 1 - Backend Express (porta 5001)
   cd backend && npm ci && npm start

   # Terminal 2 - Frontend Vite + React 19 (porta 5173)
   cd frontend && npm ci && npm run dev
   ```

---

<div align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=17&pause=1000&color=00FF00&background=0D111700&center=true&vCenter=true&width=450&lines=developer%40Sanak3%3A~%24+Igor+Araujo" alt="developer@Sanak3:~$ Igor Araujo" />
</div>
