# Cyber Threat Intelligence Platform

[![Daily ETL Pipeline](https://github.com/Sanak3/Cyber-Threat-Intel/actions/workflows/etl_pipeline.yml/badge.svg)](https://github.com/Sanak3/Cyber-Threat-Intel/actions)
[![Frontend - Vercel](https://img.shields.io/badge/Frontend-Vercel-black?style=flat&logo=vercel)](https://cyber-threat-intel-three.vercel.app)
[![API - Render](https://img.shields.io/badge/Backend-Render-46E3B7?style=flat&logo=render)](https://cyber-threat-intel-mmks.onrender.com)
[![Database - AWS RDS](https://img.shields.io/badge/AWS-RDS%20PostgreSQL-FF9900?style=flat&logo=amazon-aws)](https://aws.amazon.com/rds/)

Plataforma integrada de inteligência contra ameaças cibernéticas (CTI) que automatiza a extração paginada de larga escala (**10.000+ CVEs**), análise estatística vetorial com **NumPy** e visualização em tempo real de vulnerabilidades críticas catalogadas pela base global do **NIST NVD (National Institute of Standards and Technology)**.

---

## Live Demo

- **Dashboard (Frontend):** [cyber-threat-intel-three.vercel.app](https://cyber-threat-intel-three.vercel.app)
- **API Health Check (Backend):** [cyber-threat-intel-mmks.onrender.com/api/health](https://cyber-threat-intel-mmks.onrender.com/api/health)

---

## Arquitetura do Sistema

```text
  [ NIST NVD API 2.0 (10.000 CVEs) ]
                 │
                 ▼ (Paginação Inteligente / Rate Limit / Backoff)
        [ Data Pipeline ETL ] ─── (NumPy Vectorized Risk Engine)
                 │
                 ▼ (Upsert em Lote via execute_values / SSL)
       [ AWS RDS PostgreSQL ]
                 │
                 ▼ (SQL Connection Pool / Queries Agregadas)
    [ Backend Node.js / Express ] ─── (Deploy no Render)
                 │
                 ▼ (REST API / CORS / Paginação)
      [ SOC Dashboard React 19 ] ─── (Deploy na Vercel / Recharts)
```

---

## Funcionalidades

- **Pipeline de Dados Escalável (10.000+ CVEs):** Extração paginada com controle estrito de *rate limit* (delays dinâmicos com/sem API Key) e retentativas com *backoff* para códigos 429/503/504.
- **Análise Vetorial de Alta Performance (NumPy):** Parsing em cascata de métricas CVSS v3.1, v3.0 e v2.0, cálculo de desvio padrão, média global, score máximo/mínimo e indexação booleana instantânea.
- **Carga em Lote Otimizada (AWS RDS):** Inserção massiva com `psycopg2.extras.execute_values` (`page_size=1000`) e cláusulas `ON CONFLICT` para sincronização atômica e idempotente.
- **DataOps & Automação (GitHub Actions):** Cron job diário (03:00 BRT / 06:00 UTC) para sincronização e atualização contínua do banco.
- **API RESTful (Node.js/Express):** Endpoints agregados (`/api/threats/stats`), catálogo paginado (`/api/threats`) e lista de alta severidade (`/api/threats/critical`).
- **SOC Dashboard (React 19 + Recharts):** Interface estilo terminal hacker dark com busca em tempo real, filtros rápidos por severidade, paginação dinâmica, ordenação interativa de colunas e gráficos responsivos.

---

## Tecnologias Utilizadas

| Camada | Tecnologias |
| :--- | :--- |
| **Pipeline ETL** | Python 3.12, NumPy, Requests, Psycopg2, Python-Dotenv |
| **Banco de Dados** | AWS RDS (PostgreSQL 16) |
| **Backend** | Node.js, Express, pg (PostgreSQL Client), CORS, Dotenv |
| **Frontend** | React 19, Vite, Recharts, Axios, CSS3 Moderno |
| **CI/CD & Deploy** | GitHub Actions, Vercel, Render.com |

---

## Estrutura do Repositório

```bash
Cyber-Threat-Intel/
├── .github/
│   └── workflows/
│       └── etl_pipeline.yml   # Rotina diária de ingestão (GitHub Actions)
├── data_pipeline/
│   ├── extract.py             # Coleta de 10k registros na API NVD do NIST
│   ├── transform.py           # Análise vetorial com NumPy e parsing CVSS
│   ├── upload_aws.py          # Carga em lote no AWS RDS PostgreSQL
│   └── requirements.txt       # Dependências Python
├── backend/
│   ├── src/
│   │   ├── db_connect.js      # Pool de conexão PostgreSQL com SSL
│   │   └── server.js          # API REST com suporte a paginação e estatísticas
│   ├── .env.example           # Template de variáveis de ambiente do backend
│   └── package.json           # Dependências Node.js
├── frontend/
│   ├── src/
│   │   ├── App.jsx            # SOC Dashboard com filtros, busca e paginação
│   │   ├── App.css            # Estilização Cyber / SOC Dark
│   │   └── main.jsx           # Ponto de entrada React 19
│   ├── index.html             # HTML com fontes JetBrains Mono e Inter
│   └── package.json           # Dependências React/Vite
├── .env.example               # Template global de variáveis
└── README.md
```

---

<div align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=17&pause=1000&color=00FF00&background=0D111700&center=true&vCenter=true&width=450&lines=developer%40Sanak3%3A~%24+Igor+Araujo" alt="developer@Sanak3:~$ Igor Araujo" />
</div>
