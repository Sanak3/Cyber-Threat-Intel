# Cyber Threat Intelligence Platform

[![CI Full-Stack Quality Gate](https://github.com/Sanak3/Cyber-Threat-Intel/actions/workflows/ci.yml/badge.svg)](https://github.com/Sanak3/Cyber-Threat-Intel/actions/workflows/ci.yml)
[![Daily ETL Pipeline](https://github.com/Sanak3/Cyber-Threat-Intel/actions/workflows/etl_pipeline.yml/badge.svg)](https://github.com/Sanak3/Cyber-Threat-Intel/actions/workflows/etl_pipeline.yml)
[![Frontend - Vercel](https://img.shields.io/badge/Frontend-Vercel-black?style=flat&logo=vercel)](https://cyber-threat-intel-three.vercel.app)
[![API - Render](https://img.shields.io/badge/Backend-Render-46E3B7?style=flat&logo=render)](https://cyber-threat-intel-mmks.onrender.com)
[![Database - AWS RDS](https://img.shields.io/badge/AWS-RDS%20PostgreSQL-FF9900?style=flat&logo=amazon-aws)](https://aws.amazon.com/rds/)

Plataforma integrada de inteligência contra ameaças cibernéticas (**CTI - Cyber Threat Intelligence**) de nível corporativo. Automatiza a extração resiliente das vulnerabilidades mais recentes (**20.000+ CVEs ativas**) da API oficial do **NIST NVD v2.0**, mesclagem integral do catálogo **CISA KEV**, enriquecimento com metadados estruturados (**CVSS v4.0/v3.x/v2.0**, **CWE**, **CPE** e probabilidades **EPSS FIRST.org**), motor de **Machine Learning (TF-IDF + K-Means)**, detecção de caminhos de ataque (**Exploit Chains em Grafos com NetworkX** mapeadas ao **MITRE ATT&CK Enterprise**) e um painel tático de SOC em **React 19**.

---

## Live Demo

- **SOC Dashboard (Frontend):** [cyber-threat-intel-three.vercel.app](https://cyber-threat-intel-three.vercel.app)
- **API Health Check (Backend):** [cyber-threat-intel-mmks.onrender.com/api/health](https://cyber-threat-intel-mmks.onrender.com/api/health)
- **API Overview Consolidado:** [cyber-threat-intel-mmks.onrender.com/api/threats/overview](https://cyber-threat-intel-mmks.onrender.com/api/threats/overview)

---

## Arquitetura do Sistema

```text
   [ NIST NVD API 2.0 + CISA KEV + FIRST.org EPSS ] ── (20k+ CVEs Recentes + ?hasKev + ?noRejected + Probabilidade 30d)
            │
            ▼ (Paginação com Pooling TLS / Rate Limit Dinâmico / Enriquecimento em Lotes)
  [ Data Pipeline ETL ] ── (NumPy Vectorized Risk Engine + CVSS v4.0 / v3.x / v2.0 + CWE + CPE)
            │
            ├─► [ ML Engine: Primitivas & MITRE ] (Kill Chain 1 a 5 + Táticas/Técnicas ATT&CK)
            ├─► [ ML Engine: TF-IDF + K-Means ] (Clusterização Semântica Anti-Colisão)
            └─► [ ML Engine: NetworkX DiGraph ] (Exploit Chains Ponderadas por KEV/EPSS & Blueprints)
            │
            ▼ (TRUNCATE Transacional / Upsert execute_values / Índices B-Tree + COALESCE + GIN)
  [ AWS RDS PostgreSQL ] ── (Tabelas: threats + exploit_chains)
            │
            ▼ (Pool SSL / Schema Guard Zero-Downtime / Cache TTL em RAM / Webhook SHA-256)
[ Backend Node 20 / Express 5 ] ── (Deploy no Render / Filtros & Sort Whitelist / Node Test Suite)
            │
            ▼ (Single Round-Trip Bootstrap / Export CSV & JSON / Links MITRE ATT&CK)
 [ SOC Dashboard React 19 ] ── (Deploy na Vercel / Vite 8 / Recharts 3 / Cache Local v2)
```

---

## Principais Recursos e Diferenciais de Engenharia

### 1. Ingestão Multi-Fonte Resiliente (NIST NVD + CISA KEV + FIRST.org EPSS)
- **Offset Dinâmico de 20.000+ CVEs Recentes:** Calcula `startIndex = totalResults - 20000` via descoberta com retentativas resilientes (abortando com segurança em falhas críticas para impedir ingestão acidental de CVEs legadas de 1999) e incorpora integralmente o catálogo complementar `?hasKev` (resultando em ~21,7k CVEs únicas ativas).
- **Filtragem Dupla de CVEs Revogadas:** Exclui candidatos rejeitados diretamente na requisição (`?noRejected`) e valida `vulnStatus == REJECTED` / prefixos `** REJECT **` na transformação.
- **Cascata Completa de Métricas CVSS:** Suporte nativo a **CVSS v3.1 → CVSS v4.0 → CVSS v3.0 → CVSS v2.0**, priorizando avaliações `Primary` (NIST NVD) sobre `Secondary` (CNA/ADP) e normalizando notas $\ge 9.0$ legadas do v2 para `CRITICAL`.
- **Enriquecimento Oficial CISA KEV & EPSS:** Cruzamento direto com o feed oficial **CISA Known Exploited Vulnerabilities** e consulta paginada em lotes na API do **FIRST.org EPSS**, agregando probabilidade empírica de exploração nos próximos 30 dias (`epss_score` e `epss_percentile`) junto a **CWE** e **CPE 2.3**.

### 2. Motor de Machine Learning, MITRE ATT&CK & Grafos (`ml_engine`)
- **Primitivas Táticas & MITRE ATT&CK Enterprise:** Classificação determinística baseada em 30+ CWEs críticas nos 5 estágios da Cyber Kill Chain (`RECON_INFO_LEAK`, `AUTH_BYPASS`, `INJECTION_RCE`, `PRIV_ESC` e `DENIAL_OF_SERVICE`) com resolução automática de Táticas e Técnicas oficiais do **MITRE ATT&CK** (`TA0001`–`TA0040`, ex: `T1190`, `T1059`, `T1068`, `T1552`).
- **Clusterização Semântica (Scikit-Learn):** Vetorização com **TF-IDF** (`ngram_range=(1, 2)`) e agrupamento **K-Means** ($k=6$), avaliação automática de *Silhouette Score*, precedência semântica de rótulos (evitando falsos positivos entre RCE e Path Traversal), desambiguação de colisões e serialização via `joblib`.
- **Detecção de Exploit Chains Ponderada por KEV/EPSS (NetworkX):** Constrói um grafo direcionado (`nx.DiGraph`) conectando vulnerabilidades compatíveis por ecossistema e subproduto CPE, aplicando *degree bounding* (`max_arestas_por_no=6`), bônus de priorização para elos com **CISA KEV** ativo e **EPSS** elevado, e balanceamento multi-ecossistema.
- **Writeup Blueprints Automatizados:** Gera relatórios estruturados para o SOC contendo título tático, resumo executivo, mapeamento MITRE ATT&CK por passo, probabilidade EPSS máxima, impacto técnico consolidado e plano de mitigação.

### 3. Banco de Dados e AppSec (AWS RDS PostgreSQL & Express 5)
- **Full-Text Search GIN & Ordenação Dinâmica Segura:** Buscas textuais aceleradas por índice GIN (`to_tsvector('english', coalesce(descricao, ''))`), índices compostos para CVSS/datas/EPSS e ordenação server-side validada por *whitelist* (`cvss_desc`, `epss_desc`, `kev_first`, `recent`).
- **Atomicidade Transacional & Zero-Downtime Schema Guard:** Substituição limpa via `TRUNCATE TABLE threats, exploit_chains` na mesma transação do `execute_values` no ETL, aliada a verificação resiliente de colunas (`garantirSchemaRecente`) na API para compatibilidade retroativa sem indisponibilidade.
- **Blindagem de API:** Headers HTTP seguros com `helmet`, `express-rate-limit` (300 req/15 min por IP real via `trust proxy`), CORS restrito com suporte a Vercel Previews, validação estrita por *allowlist* e escape de curingas SQL (`%`, `_`, `\`).

### 4. Back-End de Alta Performance (Node.js 20 & Express 5)
- **Sub-Millisecond RAM Cache & Bootstrap Consolidado:** Cache em memória (TTL de 60 min) com pré-aquecimento automático no boot (`preAquecerCache`) e endpoint `/api/threats/overview` para carregamento completo do dashboard em um único *round-trip* (< 2ms em regime).
- **Webhook Autenticado em Tempo Constante:** Endpoint interno `POST /api/internal/cache-flush` protegido por `crypto.timingSafeEqual` sobre digests `SHA-256` de tamanho fixo (sem vazamento de comprimento do segredo), invalidando e reaquecendo o cache imediatamente após o ETL.
- **Graceful Shutdown:** Tratamento de sinais `SIGTERM` e `SIGINT` para encerramento ordenado do servidor HTTP e drenagem segura do pool de conexões PostgreSQL (`pg.Pool`).

### 5. SOC Dashboard Interativo (React 19 + Vite 8 + Recharts 3)
- **Hidratação Instantânea Versionada (`v2`):** Renderização imediata (`0ms`) via cache local versionado no `localStorage`, com expurgo automático de chaves legadas e sincronização silenciosa em segundo plano.
- **Filtros Táticos, Pivoting & Exportação Segura:** Filtragem server-side combinável por severidade CVSS (inclusive clicando nos KPIs ou nas barras do gráfico), **CISA KEV**, **EPSS ≥ 10%** (`?min_epss=0.1`), **Kill Chain**, **ML Clusters**, **Ecossistema Tecnológico**, tags interativas por linha, cabeçalhos ordenáveis (`CVSS`, `EPSS`, `KEV`, `NIST`), atalhos globais de teclado (`/` ou `Ctrl+K`), accordion desktop/mobile com ações rápidas (NIST NVD, MITRE ATT&CK, MITRE CWE e Blueprint) e exportação em **CSV** (sanitizada contra *CSV Formula Injection*) e **JSON**.
- **Modal Split-View de Exploit Chains & MITRE ATT&CK:** Inspeção interativa de *Attack Blueprints* com navegação por teclado (`↑`/`↓` e `ESC`), topologia clicável sincronizada com a timeline tática, badges de probabilidade **EPSS**, links diretos para técnicas oficiais no `attack.mitre.org` / `cwe.mitre.org` e exportação individual em **Markdown** e **JSON**.

### 6. Qualidade de Código, Testes & CI/CD (GitHub Actions)
- **CI Full-Stack Quality Gate (`ci.yml`):** Pipeline paralelo disparado em todo push/PR executando suíte `pytest` (Python 3.12), verificação sintática + testes de integração da API com `node --test` (Node.js 20) e `eslint` + build de produção Vite 8 no frontend.
- **DataOps Diário com Controle de Concorrência (`etl_pipeline.yml`):** Execução agendada diariamente às 03:00 BRT (06:00 UTC) com `concurrency` dedicado (impedindo corridas de *rate limit* na NIST API e *locks* concorrentes no RDS), permissões mínimas (`contents: read`) e validação prévia por testes unitários.

---

## Endpoints da API

| Método | Endpoint | Parâmetros Suportados | Descrição | Cache RAM |
| :--- | :--- | :--- | :--- | :---: |
| `GET` | `/api/health` | — | Healthcheck operacional da API | — |
| `GET` | `/api/threats/overview` | — | Bootstrap consolidado (`stats`, `topTecnologias`, `chains`, `clusters`, `initialThreats`) | Sim (TTL) |
| `GET` | `/api/threats/stats` | — | KPIs globais (Total, Severidades, CISA KEV, Alto EPSS, Pior Risco e Média CVSS) | Sim (TTL) |
| `GET` | `/api/threats/analytics` | — | Estatísticas globais + Top 10 ecossistemas tecnológicos afetados | Sim (TTL) |
| `GET` | `/api/threats/chains` | `limit` (1–100) | Cadeias de ataque enriquecidas com MITRE ATT&CK, EPSS e Writeup Blueprints | Sim (TTL) |
| `GET` | `/api/threats/clusters` | — | Distribuição de clusters semânticos (K-Means) e primitivas da Kill Chain | Sim (TTL) |
| `GET` | `/api/threats/critical` | `limit` (1–1000) | Vulnerabilidades críticas e altas ($\text{CVSS} \ge 7.0$) | — |
| `GET` | `/api/threats` | `page`, `limit`, `search`, `severity`, `kev`, `primitive`, `cluster`, `technology`, `min_epss`, `sort` | Catálogo paginado server-side com Full-Text Search (GIN), filtros táticos e ordenação | Pág. 1 padrão |
| `POST` | `/api/internal/cache-flush` | Header `X-Webhook-Secret` ou `Bearer` | Invalidação imediata e reaquecimento do cache em RAM pós-ETL | — |

---

## Stack Tecnológica

| Camada | Tecnologias |
| :--- | :--- |
| **Pipeline & ML** | Python 3.12, NumPy, Pandas, Scikit-Learn, NetworkX, Joblib, Requests, Psycopg2, Python-Dotenv |
| **Banco de Dados** | AWS RDS (PostgreSQL 16) com índices compostos B-Tree, funcionais (`COALESCE`) e GIN FTS |
| **Backend** | Node.js 20+, Express 5, pg (Connection Pool), Helmet, Express-Rate-Limit, Compression, CORS |
| **Frontend** | React 19, Vite 8, Recharts 3, Axios, ESLint 10, CSS3 Cyberpunk / SOC Dark Style |
| **CI/CD & Cloud** | GitHub Actions (Quality Gate + Cron ETL), Pytest, Node Test Runner, Vercel (Frontend), Render (API) |

---

## Estrutura do Repositório

```text
Cyber-Threat-Intel/
├── .github/
│   └── workflows/
│       ├── ci.yml                       # Quality Gate Full-Stack (Pytest, Node Tests, ESLint & Vite Build)
│       └── etl_pipeline.yml             # Cron diário (03:00 BRT) NIST/KEV/EPSS -> AWS RDS + Cache Flush
├── data_pipeline/
│   ├── extract.py                       # Coleta resiliente NIST NVD v2.0 + catálogo CISA KEV + FIRST.org EPSS
│   ├── transform.py                     # Matriz vetorial NumPy, cascata CVSS v4/v3/v2 e metadados CWE/CPE/KEV/EPSS
│   ├── upload_aws.py                    # Carga atômica no AWS RDS, criação de índices e webhook de cache
│   ├── requirements.txt                 # Dependências Python congeladas
│   └── ml_engine/                       # Motor de Inteligência Artificial e Grafos
│       ├── __init__.py
│       ├── primitives.py                # Mapeamento CWE/CPE, estágios da Kill Chain e MITRE ATT&CK Enterprise
│       ├── clusterizer.py               # Clusterização semântica (TF-IDF + K-Means)
│       ├── chain_detector.py            # Detecção de Exploit Chains ponderadas por KEV/EPSS (NetworkX)
│       └── writeup_builder.py           # Gerador automatizado de Writeup Blueprints com MITRE ATT&CK e EPSS
├── tests/
│   └── test_pipeline.py                 # Suíte Pytest do pipeline ETL (NIST/KEV/EPSS) e motor de ML/Grafos
├── backend/
│   ├── src/
│   │   ├── db_connect.js                # Pool PostgreSQL com suporte resiliente a SSL/TLS na AWS RDS
│   │   └── server.js                    # API Express 5 com Cache TTL em RAM, GIN FTS, Sort/Filtros e Webhook
│   ├── tests/
│   │   └── server.test.js               # Suíte de testes de integração da API Express (node:test)
│   ├── .env.example                     # Template de variáveis de ambiente do backend
│   └── package.json                     # Dependências e scripts de verificação e testes Node.js
├── frontend/
│   ├── src/
│   │   ├── App.jsx                      # SOC Dashboard (Filtros, Sort, Export CSV/JSON e Blueprints MITRE/EPSS)
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
   cd backend && npm ci && npm test && npm start

   # Terminal 2 - Frontend Vite + React 19 (porta 5173)
   cd frontend && npm ci && npm run dev
   ```

---

<div align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=17&pause=1000&color=00FF00&background=0D111700&center=true&vCenter=true&width=450&lines=developer%40Sanak3%3A~%24+Igor+Araujo" alt="developer@Sanak3:~$ Igor Araujo" />
</div>
