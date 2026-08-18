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

// Tooltip customizado para o gráfico de severidade
const CustomSeverityTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload
    return (
      <div className="custom-recharts-tooltip">
        <div className="tooltip-title" style={{ color: data.cor }}>
          {data.nome.toUpperCase()} ({data.faixa})
        </div>
        <div className="tooltip-value">
          Total de Ameaças: <span>{Number(data.valor).toLocaleString('pt-BR')}</span>
        </div>
      </div>
    )
  }
  return null
}

function App() {
  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5001'

  // 1. Estados de Telemetria e Analytics Globais
  const [apiStatus, setApiStatus] = useState('VERIFICANDO')
  const [dbConectado, setDbConectado] = useState(false)
  const [analyticsData, setAnalyticsData] = useState({
    stats: null,
    topTecnologias: []
  })
  const [ultimaAtualizacao, setUltimaAtualizacao] = useState(null)

  // 2. Estados da Tabela Paginada no Servidor (Server-Side)
  const [ameacas, setAmeacas] = useState([])
  const [totalRegistros, setTotalRegistros] = useState(0)
  const [totalPaginas, setTotalPaginas] = useState(1)
  const [carregandoTabela, setCarregandoTabela] = useState(false)

  // 3. Estados de Filtros e Paginação
  const [termoBusca, setTermoBusca] = useState('')
  const [debouncedBusca, setDebouncedBusca] = useState('')
  const [filtroSeveridade, setFiltroSeveridade] = useState('TODOS')
  const [paginaAtual, setPaginaAtual] = useState(1)
  const [itensPorPagina, setItensPorPagina] = useState(25)

  // ---------------------------------------------------------------------------
  // EFEITO 1: Debounce de 500ms no termo de busca (Full-Text Search)
  // ---------------------------------------------------------------------------
  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedBusca(termoBusca)
    }, 500)

    return () => {
      clearTimeout(handler)
    }
  }, [termoBusca])

  // ---------------------------------------------------------------------------
  // EFEITO 2: Carga de Telemetria e Analytics Avançado de CTI
  // ---------------------------------------------------------------------------
  useEffect(() => {
    let isMounted = true

    const carregarAnalytics = async () => {
      try {
        const [healthRes, analyticsRes] = await Promise.allSettled([
          axios.get(`${API_URL}/api/health`),
          axios.get(`${API_URL}/api/threats/analytics`)
        ])

        if (!isMounted) return

        if (healthRes.status === 'fulfilled') {
          setApiStatus(healthRes.value.data.status === 'OK' ? 'ONLINE' : 'DEGRADADO')
        } else {
          setApiStatus('OFFLINE')
        }

        if (analyticsRes.status === 'fulfilled' && analyticsRes.value.data) {
          const res = analyticsRes.value.data
          setAnalyticsData({
            stats: res.stats || null,
            topTecnologias: res.topTecnologias || []
          })
          setDbConectado(true)
        } else {
          setDbConectado(false)
        }

        setUltimaAtualizacao(new Date().toLocaleTimeString('pt-BR'))
      } catch (err) {
        console.error('[-] Erro ao carregar analytics do SOC:', err)
      }
    }

    carregarAnalytics()

    return () => {
      isMounted = false
    }
  }, [API_URL])

  // ---------------------------------------------------------------------------
  // EFEITO 3: Consulta Server-Side com GIN Full-Text Search e Paginação
  // ---------------------------------------------------------------------------
  useEffect(() => {
    let isMounted = true
    const controller = new AbortController()

    const carregarAmeacasPaginadas = async () => {
      setCarregandoTabela(true)
      try {
        const params = {
          page: paginaAtual,
          limit: itensPorPagina
        }

        if (debouncedBusca.trim()) {
          params.search = debouncedBusca.trim()
        }

        if (filtroSeveridade && filtroSeveridade !== 'TODOS') {
          params.severity = filtroSeveridade
        }

        const res = await axios.get(`${API_URL}/api/threats`, {
          params,
          signal: controller.signal
        })

        if (!isMounted) return

        const dadosResposta = res.data
        if (dadosResposta) {
          setAmeacas(dadosResposta.dados || [])
          setTotalRegistros(Number(dadosResposta.total) || 0)
          setTotalPaginas(Math.max(1, Number(dadosResposta.totalPaginas) || 1))
        }
      } catch (err) {
        if (axios.isCancel(err) || err.name === 'CanceledError') {
          return
        }
        console.error('[-] Erro ao carregar catálogo da API:', err)
      } finally {
        if (isMounted) {
          setCarregandoTabela(false)
        }
      }
    }

    carregarAmeacasPaginadas()

    return () => {
      isMounted = false
      controller.abort()
    }
  }, [API_URL, paginaAtual, itensPorPagina, debouncedBusca, filtroSeveridade])

  // Dados consolidados para o gráfico de severidade
  const dadosSeveridade = useMemo(() => {
    const s = analyticsData.stats
    if (!s) return []
    return [
      {
        nome: 'Crítico',
        faixa: 'CVSS 9.0 - 10.0',
        valor: Number(s.criticas) || 0,
        cor: 'var(--critical-red)'
      },
      {
        nome: 'Alto',
        faixa: 'CVSS 7.0 - 8.9',
        valor: Number(s.altas) || 0,
        cor: 'var(--high-orange)'
      },
      {
        nome: 'Médio',
        faixa: 'CVSS 4.0 - 6.9',
        valor: Number(s.medias) || 0,
        cor: 'var(--medium-yellow)'
      },
      {
        nome: 'Baixo',
        faixa: 'CVSS 0.1 - 3.9',
        valor: Number(s.baixas) || 0,
        cor: 'var(--neon-green)'
      }
    ]
  }, [analyticsData.stats])

  // Maior valor entre as tecnologias para escala percentual da barra
  const maxTechCount = useMemo(() => {
    if (!analyticsData.topTecnologias.length) return 1
    return Math.max(...analyticsData.topTecnologias.map(t => t.total), 1)
  }, [analyticsData.topTecnologias])

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

  // Cálculos de paginação
  const indiceInicio = totalRegistros === 0 ? 0 : (paginaAtual - 1) * itensPorPagina + 1
  const indiceFim = Math.min(paginaAtual * itensPorPagina, totalRegistros)

  return (
    <div className="soc-dashboard-container">
      {/* --------------------------------------------------------------------
          1. HEADER & TELEMETRIA LIMPA
          -------------------------------------------------------------------- */}
      <header className="soc-header">
        <div className="header-brand">
          <h1 className="brand-title">
            <span className="brand-shield">🛡️</span>
            <span>CYBER THREAT INTEL</span>
            <span className="brand-tag">SOC ENGINE</span>
            <span className="brand-tag author-tag">BY SANAK3</span>
            <span className="brand-tag volume-tag">10.000+ CVEs</span>
          </h1>
          <p className="brand-subtitle">
            &gt;_ Full-Text Search Intelligence &amp; Real-Time Threat Telemetry
          </p>
        </div>

        <div className="header-telemetry">
          <div className="status-badge">
            <span className={`led-indicator ${apiStatus === 'ONLINE' ? 'led-green' : 'led-red'}`} />
            <span className="status-label">API EXPRESS:</span>
            <span className="status-value">{apiStatus}</span>
          </div>

          <div className="status-badge">
            <span className={`led-indicator ${dbConectado ? 'led-green' : 'led-red'}`} />
            <span className="status-label">AWS RDS PG:</span>
            <span className="status-value">{dbConectado ? 'CONECTADO' : 'DESCONECTADO'}</span>
          </div>
        </div>
      </header>

      {/* --------------------------------------------------------------------
          2. CARDS DE KPIS CONSOLIDADOS
          -------------------------------------------------------------------- */}
      <section className="kpi-grid">
        <div className="kpi-card kpi-total">
          <div className="kpi-card-header">
            <span className="kpi-title">Total Ingerido</span>
            <span className="kpi-icon">📦</span>
          </div>
          <div className="kpi-value">
            {analyticsData.stats ? Number(analyticsData.stats.total_ameacas).toLocaleString('pt-BR') : '---'}
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
            {analyticsData.stats ? Number(analyticsData.stats.criticas).toLocaleString('pt-BR') : '---'}
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
            {analyticsData.stats ? Number(analyticsData.stats.altas).toLocaleString('pt-BR') : '---'}
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
            {analyticsData.stats?.pior_risco ? Number(analyticsData.stats.pior_risco).toFixed(1) : '0.0'}
          </div>
          <div className="kpi-footer">
            <span>Escala Máxima 10.0</span>
          </div>
        </div>
      </section>

      {/* --------------------------------------------------------------------
          3. SEÇÃO ANALÍTICA DUAL (RETÂNGULO 2x + QUADRADO 1x)
          -------------------------------------------------------------------- */}
      <section className="analytics-dual-grid">
        {/* Bloco 1 (Retângulo Largo 2x): Distribuição de Severidade CVSS */}
        <div className="analytics-card card-wide">
          <div className="analytics-card-header">
            <h3 className="analytics-card-title">
              <span className="section-title-prefix">&gt;_</span>
              <span>DISTRIBUIÇÃO DE SEVERIDADE CVSS (v3.x / v2.0)</span>
            </h3>
            <span className="analytics-badge">MATRIZ DE RISCO GLOBAL</span>
          </div>
          <div className="chart-container-inner chart-wide">
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={dadosSeveridade} margin={{ top: 15, right: 20, left: -10, bottom: 5 }}>
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
                <Tooltip content={<CustomSeverityTooltip />} cursor={{ fill: 'rgba(255, 255, 255, 0.03)' }} />
                <Bar dataKey="valor" radius={[6, 6, 0, 0]}>
                  {dadosSeveridade.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.cor} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Bloco 2 (Quadrado 1x): Top Tecnologias e Ecossistemas Mais Afetados */}
        <div className="analytics-card card-compact">
          <div className="analytics-card-header">
            <h3 className="analytics-card-title">
              <span className="section-title-prefix">&gt;_</span>
              <span>ECOSSISTEMAS MAIS AFETADOS</span>
            </h3>
            <span className="analytics-badge">VENDORS / SO</span>
          </div>
          <div className="tech-ranking-list">
            {analyticsData.topTecnologias.map((tech) => {
              const porcentagem = Math.round((tech.total / maxTechCount) * 100)
              return (
                <div key={tech.nome} className="tech-ranking-item">
                  <div className="tech-ranking-info">
                    <span className="tech-ranking-name">{tech.nome}</span>
                    <span className="tech-ranking-count" style={{ color: tech.cor }}>
                      {tech.total.toLocaleString('pt-BR')} CVEs
                    </span>
                  </div>
                  <div className="tech-progress-bg">
                    <div
                      className="tech-progress-fill"
                      style={{ width: `${porcentagem}%`, backgroundColor: tech.cor }}
                    />
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </section>

      {/* --------------------------------------------------------------------
          4. CAMPO DE BUSCA FULL-TEXT SEARCH & FILTROS EM TEMPO REAL
          -------------------------------------------------------------------- */}
      <section className="filter-panel">
        <div className="search-terminal-box">
          <span className="terminal-prompt">&gt;_</span>
          <input
            type="text"
            className="terminal-input"
            placeholder="Full-Text Search: digite termo técnico (ex: Remote Code Execution, Buffer Overflow, Apache, Windows)..."
            value={termoBusca}
            onChange={(e) => {
              setTermoBusca(e.target.value)
              setPaginaAtual(1)
            }}
          />
          {termoBusca && (
            <button
              className="btn-clear-search"
              onClick={() => {
                setTermoBusca('')
                setPaginaAtual(1)
              }}
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
              onClick={() => {
                setFiltroSeveridade('TODOS')
                setPaginaAtual(1)
              }}
            >
              TODOS <span className="pill-count">{analyticsData.stats ? Number(analyticsData.stats.total_ameacas).toLocaleString('pt-BR') : '---'}</span>
            </button>
            <button
              className={`filter-pill pill-critical ${filtroSeveridade === 'CRITICAL' ? 'active' : ''}`}
              onClick={() => {
                setFiltroSeveridade('CRITICAL')
                setPaginaAtual(1)
              }}
            >
              CRITICAL <span className="pill-count">{analyticsData.stats ? Number(analyticsData.stats.criticas).toLocaleString('pt-BR') : ''}</span>
            </button>
            <button
              className={`filter-pill pill-high ${filtroSeveridade === 'HIGH' ? 'active' : ''}`}
              onClick={() => {
                setFiltroSeveridade('HIGH')
                setPaginaAtual(1)
              }}
            >
              HIGH <span className="pill-count">{analyticsData.stats ? Number(analyticsData.stats.altas).toLocaleString('pt-BR') : ''}</span>
            </button>
            <button
              className={`filter-pill pill-medium ${filtroSeveridade === 'MEDIUM' ? 'active' : ''}`}
              onClick={() => {
                setFiltroSeveridade('MEDIUM')
                setPaginaAtual(1)
              }}
            >
              MEDIUM <span className="pill-count">{analyticsData.stats ? Number(analyticsData.stats.medias).toLocaleString('pt-BR') : ''}</span>
            </button>
            <button
              className={`filter-pill pill-low ${filtroSeveridade === 'LOW' ? 'active' : ''}`}
              onClick={() => {
                setFiltroSeveridade('LOW')
                setPaginaAtual(1)
              }}
            >
              LOW <span className="pill-count">{analyticsData.stats ? Number(analyticsData.stats.baixas).toLocaleString('pt-BR') : ''}</span>
            </button>
          </div>

          <div className="filter-stats-text">
            {carregandoTabela ? (
              <span style={{ color: 'var(--electric-cyan)' }}>Executando Full-Text Search no PostgreSQL...</span>
            ) : (
              <span>
                Exibindo <span className="filter-stats-highlight">{ameacas.length}</span> nesta página (Total: <span className="filter-stats-highlight">{totalRegistros.toLocaleString('pt-BR')}</span>)
              </span>
            )}
          </div>
        </div>
      </section>

      {/* --------------------------------------------------------------------
          5. TABELA DE INTELIGÊNCIA DE AMEAÇAS (PAGINAÇÃO SERVER-SIDE)
          -------------------------------------------------------------------- */}
      <section className="threat-table-card">
        <div className="section-header">
          <h2 className="section-title">
            <span className="section-title-prefix">&gt;_</span>
            <span>FEED DE VULNERABILIDADES (CATÁLOGO DE ALTA PERFORMANCE)</span>
          </h2>
          <span className="filter-stats-text">
            Página <span className="filter-stats-highlight">{paginaAtual}</span> de {totalPaginas}
          </span>
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
              {ameacas.length > 0 ? (
                ameacas.map((item) => (
                  <tr key={item.cve_id}>
                    <td className="cve-id-cell">
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(item.cve_id)}`}
                        target="_blank"
                        rel="noopener noreferrer"
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
                      <div className="empty-state-icon">
                        {carregandoTabela ? '⏳' : '🔍'}
                      </div>
                      <div className="empty-state-text">
                        {carregandoTabela
                          ? 'EXECUTANDO CONSULTA NO BANCO DE DADOS...'
                          : 'NENHUMA VULNERABILIDADE LOCALIZADA'}
                      </div>
                      <div className="empty-state-subtext">
                        {carregandoTabela
                          ? 'Processando consulta indexada com GIN no AWS RDS'
                          : 'Tente ajustar os termos da pesquisa ou selecionar outro filtro de severidade.'}
                      </div>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Barra de Paginação Server-Side */}
        {totalRegistros > 0 && (
          <div className="table-pagination-bar">
            <div className="pagination-size-selector">
              <span>Registros por página:</span>
              <select
                className="pagination-select"
                value={itensPorPagina}
                onChange={(e) => {
                  setItensPorPagina(Number(e.target.value))
                  setPaginaAtual(1)
                }}
              >
                <option value={15}>15</option>
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
              <span>
                (Mostrando {indiceInicio} - {indiceFim} de {totalRegistros.toLocaleString('pt-BR')})
              </span>
            </div>

            <div className="pagination-controls-group">
              <button
                className="btn-page"
                onClick={() => setPaginaAtual(1)}
                disabled={paginaAtual <= 1 || carregandoTabela}
                title="Primeira página"
              >
                &laquo;
              </button>
              <button
                className="btn-page"
                onClick={() => setPaginaAtual(prev => Math.max(1, prev - 1))}
                disabled={paginaAtual <= 1 || carregandoTabela}
                title="Página anterior"
              >
                &lsaquo; Anterior
              </button>
              <span className="pagination-page-indicator">
                {paginaAtual} / {totalPaginas}
              </span>
              <button
                className="btn-page"
                onClick={() => setPaginaAtual(prev => Math.min(totalPaginas, prev + 1))}
                disabled={paginaAtual >= totalPaginas || carregandoTabela}
                title="Próxima página"
              >
                Próxima &rsaquo;
              </button>
              <button
                className="btn-page"
                onClick={() => setPaginaAtual(totalPaginas)}
                disabled={paginaAtual >= totalPaginas || carregandoTabela}
                title="Última página"
              >
                &raquo;
              </button>
            </div>
          </div>
        )}
      </section>

      {/* --------------------------------------------------------------------
          6. FOOTER
          -------------------------------------------------------------------- */}
      <footer className="soc-footer">
        <div>
          CYBER THREAT INTEL // <span className="footer-tech">BY SANAK3 // FULL-TEXT SEARCH GIN // NUMPY + AWS RDS + NODE EXPRESS + REACT 19</span>
        </div>
        {ultimaAtualizacao && (
          <div>
            SINCRONIZAÇÃO: <span style={{ color: 'var(--neon-green)' }}>{ultimaAtualizacao}</span>
          </div>
        )}
      </footer>
    </div>
  )
}

export default App