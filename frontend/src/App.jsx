import { useState, useEffect, useMemo } from 'react'
import axios from 'axios'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
  CartesianGrid
} from 'recharts'
import './App.css'

// Tooltip customizado com estética Cyber/SOC Dark
const CustomChartTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload
    return (
      <div className="custom-recharts-tooltip">
        <div className="tooltip-title" style={{ color: data.cor }}>
          {data.nome.toUpperCase()} ({data.faixa})
        </div>
        <div className="tooltip-value">
          Total de Ameaças: <span>{data.valor.toLocaleString()}</span>
        </div>
      </div>
    )
  }
  return null
}

function App() {
  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5001'

  // Estados de dados da API
  const [apiStatus, setApiStatus] = useState('VERIFICANDO')
  const [dbConectado, setDbConectado] = useState(false)
  const [estatisticas, setEstatisticas] = useState(null)
  const [ameacasCriticas, setAmeacasCriticas] = useState([])
  const [ultimaAtualizacao, setUltimaAtualizacao] = useState(null)

  // Estados de busca e filtros
  const [termoBusca, setTermoBusca] = useState('')
  const [filtroSeveridade, setFiltroSeveridade] = useState('TODOS')

  // Efeito de montagem para carga inicial de dados
  useEffect(() => {
    let isMounted = true

    const carregarDadosIniciais = async () => {
      try {
        const [healthRes, statsRes, criticalRes] = await Promise.allSettled([
          axios.get(`${API_URL}/api/health`),
          axios.get(`${API_URL}/api/threats/stats`),
          axios.get(`${API_URL}/api/threats/critical`)
        ])

        if (!isMounted) return

        if (healthRes.status === 'fulfilled') {
          setApiStatus(healthRes.value.data.status === 'OK' ? 'ONLINE' : 'DEGRADADO')
        } else {
          setApiStatus('OFFLINE')
        }

        if (statsRes.status === 'fulfilled') {
          setEstatisticas(statsRes.value.data)
          setDbConectado(true)
        } else {
          setDbConectado(false)
        }

        if (criticalRes.status === 'fulfilled') {
          setAmeacasCriticas(criticalRes.value.data || [])
        }

        setUltimaAtualizacao(new Date().toLocaleTimeString('pt-BR'))
      } catch (err) {
        console.error('[-] Erro ao carregar dados do dashboard:', err)
      }
    }

    carregarDadosIniciais()

    return () => {
      isMounted = false
    }
  }, [API_URL])


  // Filtragem dinâmica e reativa em tempo real
  const ameacasFiltradas = useMemo(() => {
    return ameacasCriticas.filter(item => {
      const termo = termoBusca.toLowerCase().trim()
      const cveMatch = item.cve_id ? item.cve_id.toLowerCase().includes(termo) : false
      const descMatch = item.descricao ? item.descricao.toLowerCase().includes(termo) : false
      const sevMatch = item.severidade ? item.severidade.toLowerCase().includes(termo) : false

      const matchesBusca = !termo || cveMatch || descMatch || sevMatch

      const matchesSeveridade =
        filtroSeveridade === 'TODOS' ||
        (item.severidade && item.severidade.toUpperCase() === filtroSeveridade)

      return matchesBusca && matchesSeveridade
    })
  }, [ameacasCriticas, termoBusca, filtroSeveridade])

  // Formatação dos dados para o gráfico Recharts
  const dadosGrafico = useMemo(() => {
    if (!estatisticas) return []
    return [
      {
        nome: 'Crítico',
        faixa: 'CVSS 9.0 - 10.0',
        valor: Number(estatisticas.criticas) || 0,
        cor: 'var(--critical-red)'
      },
      {
        nome: 'Alto',
        faixa: 'CVSS 7.0 - 8.9',
        valor: Number(estatisticas.altas) || 0,
        cor: 'var(--high-orange)'
      },
      {
        nome: 'Médio',
        faixa: 'CVSS 4.0 - 6.9',
        valor: Number(estatisticas.medias) || 0,
        cor: 'var(--medium-yellow)'
      },
      {
        nome: 'Baixo',
        faixa: 'CVSS 0.1 - 3.9',
        valor: Number(estatisticas.baixas) || 0,
        cor: 'var(--neon-green)'
      }
    ]
  }, [estatisticas])

  // Helper para obter a classe de severidade do score CVSS
  const getScoreClass = (score) => {
    const num = Number(score)
    if (num >= 9.0) return 'score-critical'
    if (num >= 7.0) return 'score-high'
    if (num >= 4.0) return 'score-medium'
    return 'score-low'
  }

  // Helper para formatar data ISO
  const formatarData = (dataStr) => {
    if (!dataStr) return 'N/D'
    try {
      const d = new Date(dataStr)
      return d.toLocaleDateString('pt-BR', {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      })
    } catch {
      return dataStr
    }
  }

  return (
    <div className="soc-dashboard-container">
      {/* --------------------------------------------------------------------
          1. HEADER & STATUS DE TELEMETRIA
          -------------------------------------------------------------------- */}
      <header className="soc-header">
        <div className="header-brand">
          <h1 className="brand-title">
            <span className="brand-shield">🛡️</span>
            <span>CYBER THREAT INTEL</span>
            <span className="brand-tag">SOC ENGINE</span>
            <span className="brand-tag author-tag">BY SANAK3</span>
          </h1>
          <p className="brand-subtitle">
            &gt;_ NIST NVD Threat Feed &amp; CVSS Vulnerability Matrix
          </p>
        </div>

        <div className="header-telemetry">
          {/* Status da API Node.js */}
          <div className="status-badge">
            <span className={`led-indicator ${apiStatus === 'ONLINE' ? 'led-green' : 'led-red'}`} />
            <span className="status-label">API EXPRESS:</span>
            <span className="status-value">{apiStatus}</span>
          </div>

          {/* Status do Banco AWS RDS PostgreSQL */}
          <div className="status-badge">
            <span className={`led-indicator ${dbConectado ? 'led-green' : 'led-red'}`} />
            <span className="status-label">AWS RDS PG:</span>
            <span className="status-value">{dbConectado ? 'CONECTADO' : 'DESCONECTADO'}</span>
          </div>
        </div>
      </header>

      {/* --------------------------------------------------------------------
          2. CARDS DE KPIS (MÉTRICAS CONSOLIDADAS)
          -------------------------------------------------------------------- */}
      <section className="kpi-grid">
        <div className="kpi-card kpi-total">
          <div className="kpi-card-header">
            <span className="kpi-title">Total Ingerido</span>
            <span className="kpi-icon">📦</span>
          </div>
          <div className="kpi-value">
            {estatisticas ? Number(estatisticas.total_ameacas).toLocaleString() : '---'}
          </div>
          <div className="kpi-footer">
            <span>Base Global NIST NVD</span>
          </div>
        </div>

        <div className="kpi-card kpi-critical">
          <div className="kpi-card-header">
            <span className="kpi-title">Ameaças Críticas</span>
            <span className="kpi-icon">🔥</span>
          </div>
          <div className="kpi-value">
            {estatisticas ? Number(estatisticas.criticas).toLocaleString() : '---'}
          </div>
          <div className="kpi-footer">
            <span>CVSS Score &ge; 9.0</span>
          </div>
        </div>

        <div className="kpi-card kpi-high">
          <div className="kpi-card-header">
            <span className="kpi-title">Ameaças Altas</span>
            <span className="kpi-icon">⚠️</span>
          </div>
          <div className="kpi-value">
            {estatisticas ? Number(estatisticas.altas).toLocaleString() : '---'}
          </div>
          <div className="kpi-footer">
            <span>CVSS Score 7.0 - 8.9</span>
          </div>
        </div>

        <div className="kpi-card kpi-score">
          <div className="kpi-card-header">
            <span className="kpi-title">Pior Risco Detectado</span>
            <span className="kpi-icon">⚡</span>
          </div>
          <div className="kpi-value">
            {estatisticas?.pior_risco ? Number(estatisticas.pior_risco).toFixed(1) : '0.0'}
          </div>
          <div className="kpi-footer">
            <span>Escala Máxima 10.0</span>
          </div>
        </div>
      </section>

      {/* --------------------------------------------------------------------
          3. GRÁFICO DE DISTRIBUIÇÃO CVSS (RECHARTS)
          -------------------------------------------------------------------- */}
      <section className="analytics-section">
        <div className="chart-card">
          <div className="section-header">
            <h2 className="section-title">
              <span className="section-title-prefix">&gt;_</span>
              <span>MATRIZ DE DISTRIBUIÇÃO DE SEVERIDADE (CVSS v3.x)</span>
            </h2>
            {ultimaAtualizacao && (
              <span className="filter-stats-text">
                Última sincronização: <span className="filter-stats-highlight">{ultimaAtualizacao}</span>
              </span>
            )}
          </div>

          <div className="chart-wrapper">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={dadosGrafico} margin={{ top: 15, right: 20, left: -15, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis
                  dataKey="nome"
                  stroke="#64748b"
                  tick={{ fill: '#94a3b8', fontSize: 12, fontFamily: 'var(--font-mono)' }}
                />
                <YAxis
                  stroke="#64748b"
                  tick={{ fill: '#94a3b8', fontSize: 12, fontFamily: 'var(--font-mono)' }}
                />
                <Tooltip content={<CustomChartTooltip />} cursor={{ fill: 'rgba(255, 255, 255, 0.03)' }} />
                <Bar dataKey="valor" radius={[6, 6, 0, 0]}>
                  {dadosGrafico.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.cor} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>

      {/* --------------------------------------------------------------------
          4. CAMPO DE BUSCA E FILTROS EM TEMPO REAL (TERMINAL STYLE)
          -------------------------------------------------------------------- */}
      <section className="filter-panel">
        <div className="search-terminal-box">
          <span className="terminal-prompt">&gt;_</span>
          <input
            type="text"
            className="terminal-input"
            placeholder="Buscar por CVE (ex: CVE-2024), componente afetado ou termo técnico..."
            value={termoBusca}
            onChange={(e) => setTermoBusca(e.target.value)}
          />
          {termoBusca && (
            <button
              className="btn-clear-search"
              onClick={() => setTermoBusca('')}
              title="Limpar busca"
            >
              ✕
            </button>
          )}
        </div>

        <div className="filter-controls">
          <div className="filter-pills-group">
            <button
              className={`filter-pill ${filtroSeveridade === 'TODOS' ? 'active' : ''}`}
              onClick={() => setFiltroSeveridade('TODOS')}
            >
              TODOS <span className="pill-count">{ameacasCriticas.length}</span>
            </button>
            <button
              className={`filter-pill pill-critical ${filtroSeveridade === 'CRITICAL' ? 'active' : ''}`}
              onClick={() => setFiltroSeveridade('CRITICAL')}
            >
              CRITICAL
            </button>
            <button
              className={`filter-pill pill-high ${filtroSeveridade === 'HIGH' ? 'active' : ''}`}
              onClick={() => setFiltroSeveridade('HIGH')}
            >
              HIGH
            </button>
            <button
              className={`filter-pill pill-medium ${filtroSeveridade === 'MEDIUM' ? 'active' : ''}`}
              onClick={() => setFiltroSeveridade('MEDIUM')}
            >
              MEDIUM
            </button>
            <button
              className={`filter-pill pill-low ${filtroSeveridade === 'LOW' ? 'active' : ''}`}
              onClick={() => setFiltroSeveridade('LOW')}
            >
              LOW
            </button>
          </div>

          <div className="filter-stats-text">
            Exibindo <span className="filter-stats-highlight">{ameacasFiltradas.length}</span> de {ameacasCriticas.length} vulnerabilidades registradas
          </div>
        </div>
      </section>

      {/* --------------------------------------------------------------------
          5. TABELA DE INTELIGÊNCIA DE AMEAÇAS
          -------------------------------------------------------------------- */}
      <section className="threat-table-card">
        <div className="section-header">
          <h2 className="section-title">
            <span className="section-title-prefix">&gt;_</span>
            <span>FEED DE VULNERABILIDADES CRÍTICAS / ALTAS DETECTADAS</span>
          </h2>
        </div>

        <div className="table-responsive">
          <table className="soc-table">
            <thead>
              <tr>
                <th>IDENTIFICADOR</th>
                <th>SCORE CVSS</th>
                <th>SEVERIDADE</th>
                <th>DESCRIÇÃO TÉCNICA</th>
                <th>DATA INGESTÃO</th>
              </tr>
            </thead>
            <tbody>
              {ameacasFiltradas.length > 0 ? (
                ameacasFiltradas.map((item) => (
                  <tr key={item.cve_id}>
                    <td className="cve-id-cell">
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${item.cve_id}`}
                        target="_blank"
                        rel="noreferrer"
                        title="Abrir detalhes no NIST NVD"
                      >
                        <span>{item.cve_id}</span>
                        <span>↗</span>
                      </a>
                    </td>
                    <td>
                      <span className={`cve-score-badge ${getScoreClass(item.nota_cvss)}`}>
                        {Number(item.nota_cvss).toFixed(1)}
                      </span>
                    </td>
                    <td>
                      <span className={`cve-severity-badge ${getScoreClass(item.nota_cvss)}`}>
                        {item.severidade || 'N/A'}
                      </span>
                    </td>
                    <td className="cve-desc-cell" title={item.descricao}>
                      {item.descricao}
                    </td>
                    <td className="cve-date-cell">
                      {formatarData(item.data_extracao)}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5}>
                    <div className="table-empty-state">
                      <div className="empty-state-icon">🔍</div>
                      <div className="empty-state-text">
                        NENHUMA VULNERABILIDADE LOCALIZADA
                      </div>
                      <div className="empty-state-subtext">
                        Tente ajustar o termo digitado no terminal ou selecionar outro filtro de severidade.
                      </div>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* --------------------------------------------------------------------
          6. FOOTER
          -------------------------------------------------------------------- */}
      <footer className="soc-footer">
        <div>
          CYBER THREAT INTEL SYSTEM // <span className="footer-tech">BY SANAK3 // PYTHON NUMPY + AWS RDS + NODE EXPRESS + REACT 19</span>
        </div>
        <div>
          STATUS DA BASE: <span style={{ color: 'var(--neon-green)' }}>SYNC ATIVO</span>
        </div>
      </footer>
    </div>
  )
}

export default App