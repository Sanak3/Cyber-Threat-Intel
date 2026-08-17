# 🛡️ Cyber Threat Intelligence Platform

[![Daily ETL Pipeline](https://github.com/Sanak3/Cyber-Threat-Intel/actions/workflows/etl_pipeline.yml/badge.svg)](https://github.com/Sanak3/Cyber-Threat-Intel/actions)
[![Frontend - Vercel](https://img.shields.io/badge/Frontend-Vercel-black?style=flat&logo=vercel)](https://cyber-threat-intel-three.vercel.app)
[![API - Render](https://img.shields.io/badge/Backend-Render-46E3B7?style=flat&logo=render)](https://cyber-threat-intel-mmks.onrender.com)
[![Database - AWS RDS](https://img.shields.io/badge/AWS-RDS%20PostgreSQL-FF9900?style=flat&logo=amazon-aws)](https://aws.amazon.com/rds/)

Plataforma integrada de inteligência contra ameaças cibernéticas (CTI) que automatiza a extração, análise estatística vetorial e visualização em tempo real de vulnerabilidades críticas (**CVEs**) catalogadas pela base do **NIST (National Institute of Standards and Technology)**.

---

## 🚀 Live Demo

- **Dashboard (Frontend):** [cyber-threat-intel-three.vercel.app](https://cyber-threat-intel-three.vercel.app)
- **API Health Check (Backend):** [cyber-threat-intel-mmks.onrender.com/api/health](https://cyber-threat-intel-mmks.onrender.com/api/health)

---

## 🏗️ Arquitetura do Sistema

```text
  [ NIST NVD API 2.0 ]
           │
           ▼ (HTTP GET / Python)
  [ Data Pipeline ETL ] ─── (NumPy Vectorized Engine)
           │
           ▼ (Upsert / SSL)
  [ AWS RDS PostgreSQL ]
           │
           ▼ (SQL Query / Connection Pool)
  [ Backend Node.js / Express ] ─── (Deploy no Render)
           │
           ▼ (REST API / CORS)
  [ Dashboard React / Vite ] ─── (Deploy na Vercel / Recharts)
```
---

## ⚡ Funcionalidades
- Pipeline de Dados Automatizado (ETL): Extração em lote via API 2.0 do NIST com sanitização e normalização de registros.

- Análise Vetorial com NumPy: Processamento de métricas CVSS (Common Vulnerability Scoring System), cálculo de scores médios, dispersão e categorização por severidade (Crítico, Alto, Médio, Baixo).

- Persistência em Nuvem (AWS RDS): Armazenamento em banco PostgreSQL gerenciado com suporte a conexões seguras (SSL) e rotinas de Upsert para evitar duplicidade.

- DevOps & DataOps (GitHub Actions): Cron job configurado para sincronização diária autônoma de novos feeds de ameaças.

- API RESTful (Node.js/Express): Endpoints com pooling de conexões para agregação estatística e consulta de ameaças críticas.

- SOC Dashboard (React + Recharts): Interface no formato Dark Mode com cards de métricas (KPIs), gráfico de distribuição de severidade e listagem direta para documentação oficial dos CVEs.

---

## 🛠️ Tecnologias Utilizadas

| Camada | Tecnologias |
| :--- | :--- |
| **Pipeline ETL** | Python 3.12, NumPy, Requests, Psycopg2, Python-Dotenv |
| **Banco de Dados** | AWS RDS (PostgreSQL 16) |
| **Backend** | Node.js, Express, pg (PostgreSQL Client), CORS, Dotenv |
| **Frontend** | React 18, Vite, Recharts, Axios, CSS3 Moderno |
| **CI/CD & Deploy** | GitHub Actions, Vercel, Render.com |

---

## 📂 Estrutura do Repositório

```bash
Cyber-Threat-Intel/
├── .github/
│   └── workflows/
│       └── etl_pipeline.yml   # Rotina diária de ingestão (GitHub Actions)
├── data_pipeline/
│   ├── extract.py             # Coleta de dados na API NVD do NIST
│   ├── transform.py           # Processamento estatístico via NumPy
│   ├── upload_aws.py          # Carga e sincronização no AWS RDS
│   └── requirements.txt       # Dependências Python
├── backend/
│   ├── src/
│   │   ├── db_connect.js      # Pool de conexão PostgreSQL
│   │   └── server.js          # Rotas e regras de negócio da API
│   └── package.json           # Dependências Node.js
├── frontend/
│   ├── src/
│   │   ├── App.jsx            # Interface e visualização com gráficos
│   │   └── App.css            # Estilização SOC
│   └── package.json           # Dependências React/Vite
└── README.md
```

---

```text
┌──[ developer@sanak3 ]
└─$ whoami
    > Igor Araujo
```
