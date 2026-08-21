import { useState, useEffect, useMemo, useRef } from 'react'
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

  // 1. Estados de Telemetria e Analytics Globais (Instant Hydration no F5 via sessionStorage)
  const [apiStatus, setApiStatus] = useState('ONLINE')
  const [dbConectado, setDbConectado] = useState(true)
  const [analyticsData, setAnalyticsData] = useState(() => {
    try {
      const cached = sessionStorage.getItem('cti_analytics_cache')
      if (cached) return JSON.parse(cached)
    } catch {
      // fallback gracioso
    }
    return { stats: null, topTecnologias: [] }
  })
  const [ultimaAtualizacao, setUltimaAtualizacao] = useState(() => {
    try {
      return sessionStorage.getItem('cti_last_sync') || null
    } catch {
      return null
    }
  })

  // 2. Estados da Tabela Paginada no Servidor (Instant Hydration para Página 1)
  const [ameacas, setAmeacas] = useState(() => {
    try {
      const cached = sessionStorage.getItem('cti_threats_page1')
      if (cached) return JSON.parse(cached)
    } catch {
      // fallback gracioso
    }
    return []
  })
  const [totalRegistros, setTotalRegistros] = useState(() => {
    try {
      const cached = sessionStorage.getItem('cti_total_registros')
      if (cached) return Number(cached) || 0
    } catch {
      return 0
    }
    return 0
  })
  const [totalPaginas, setTotalPaginas] = useState(1)
  const [carregandoTabela, setCarregandoTabela] = useState(false)

  // 3. Estados de Filtros e Paginação
  const [termoBusca, setTermoBusca] = useState('')
  const [debouncedBusca, setDebouncedBusca] = useState('')
  const [filtroSeveridade, setFiltroSeveridade] = useState('TODOS')
  const [paginaAtual, setPaginaAtual] = useState(1)
  const [itensPorPagina, setItensPorPagina] = useState(() => {
    if (typeof window !== 'undefined' && window.innerWidth <= 768) {
      return 10
    }
    return 25
  })

  // 4. Estados de Usabilidade e Navegação Mobile
  const [expandedCves, setExpandedCves] = useState({})
  const [mostrarGraficosMobile, setMostrarGraficosMobile] = useState(true)
  const [mostrarVoltarTopo, setMostrarVoltarTopo] = useState(false)
  const threatTableRef = useRef(null)

  // ---------------------------------------------------------------------------
  // EFEITO 1: Debounce de 400ms no termo de busca (Full-Text Search)
  // ---------------------------------------------------------------------------
  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedBusca(termoBusca)
    }, 400)

    return () => {
      clearTimeout(handler)
    }
  }, [termoBusca])

  // ---------------------------------------------------------------------------
  // EFEITO 2: Listener de Scroll para Botão Flutuante 'Voltar ao Topo'
  // ---------------------------------------------------------------------------
  useEffect(() => {
    const handleScroll = () => {
      if (window.scrollY > 280) {
        setMostrarVoltarTopo(true)
      } else {
        setMostrarVoltarTopo(false)
      }
    }

    window.addEventListener('scroll', handleScroll, { passive: true })
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  // ---------------------------------------------------------------------------
  // EFEITO 3: Carga em Background de Telemetria e Analytics (Stale-While-Revalidate)
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
          const novoPayload = {
            stats: res.stats || null,
            topTecnologias: res.topTecnologias || []
          }
          setAnalyticsData(novoPayload)
          setDbConectado(true)

          const horaFormatada = new Date().toLocaleTimeString('pt-BR')
          setUltimaAtualizacao(horaFormatada)

          // Persiste no cache da sessão para carregamento instantâneo no F5
          try {
            sessionStorage.setItem('cti_analytics_cache', JSON.stringify(novoPayload))
            sessionStorage.setItem('cti_last_sync', horaFormatada)
          } catch {
            // ignore storage full
          }
        } else {
          setDbConectado(false)
        }
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
  // EFEITO 3: Consulta Server-Side com GIN Full-Text Search e Cache de Página 1
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
          const listaRecebida = dadosResposta.dados || []
          const totalRecebido = Number(dadosResposta.total) || 0
          const paginasRecebidas = Math.max(1, Number(dadosResposta.totalPaginas) || 1)

          setAmeacas(listaRecebida)
          setTotalRegistros(totalRecebido)
          setTotalPaginas(paginasRecebidas)

          // Salva página padrão no cache para acelerar F5
          if (paginaAtual === 1 && !debouncedBusca && filtroSeveridade === 'TODOS') {
            try {
              sessionStorage.setItem('cti_threats_page1', JSON.stringify(listaRecebida))
              sessionStorage.setItem('cti_total_registros', String(totalRecebido))
            } catch {
              // ignore
            }
          }
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

  // ---------------------------------------------------------------------------
  // AÇÕES DE NAVEGAÇÃO E EXPANSÃO ACCORDION
  // ---------------------------------------------------------------------------
  const mudarPagina = (novaPagina) => {
    setPaginaAtual(novaPagina)
    if (threatTableRef.current) {
      const topOffset = threatTableRef.current.getBoundingClientRect().top + window.scrollY - 20
      window.scrollTo({ top: topOffset, behavior: 'smooth' })
    }
  }

  const irParaTopo = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  const toggleExpandCve = (cveId) => {
    setExpandedCves(prev => ({
      ...prev,
      [cveId]: !prev[cveId]
    }))
  }

  const expandirTodos = () => {
    const todos = {}
    ameacas.forEach(item => {
      todos[item.cve_id] = true
    })
    setExpandedCves(todos)
  }

  const recolherTodos = () => {
    setExpandedCves({})
  }

  const expandedCount = useMemo(() => {
    return Object.values(expandedCves).filter(Boolean).length
  }, [expandedCves])

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
            &gt;_ High-Performance GIN Search Intelligence &amp; Real-Time Threat Telemetry
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
          1.1. BARRA DE NAVEGAÇÃO RÁPIDA (ACESSO DIRETO ÀS SEÇÕES)
          -------------------------------------------------------------------- */}
      <nav className="soc-quick-nav" aria-label="Navegação Rápida">
        <a href="#metricas" className="quick-nav-pill">
          <span>⚡</span> Métricas
        </a>
        <a href="#graficos" className="quick-nav-pill">
          <span>📊</span> Gráficos
        </a>
        <a href="#filtros" className="quick-nav-pill">
          <span>🔍</span> Busca &amp; Filtros
        </a>
        <a href="#feed-cves" className="quick-nav-pill">
          <span>📋</span> Feed CVEs
        </a>
      </nav>

      {/* --------------------------------------------------------------------
          2. CARDS DE KPIS CONSOLIDADOS
          -------------------------------------------------------------------- */}
      <section id="metricas" className="kpi-grid">
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
          3. SEÇÃO ANALÍTICA DUAL (COM ACCORDION EM MOBILE PARA REDUZIR SCROLL)
          -------------------------------------------------------------------- */}
      <div 
        className="mobile-accordion-toggle" 
        onClick={() => setMostrarGraficosMobile(prev => !prev)}
        role="button"
        tabIndex={0}
        aria-expanded={mostrarGraficosMobile}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault()
            setMostrarGraficosMobile(prev => !prev)
          }
        }}
      >
        <div className="accordion-title">
          <span>📊</span>
          <span>ANALYTICS &amp; MATRIZ DE RISCO</span>
        </div>
        <span className="accordion-action">
          {mostrarGraficosMobile ? '▲ Ocultar' : '▼ Visualizar'}
        </span>
      </div>

      <section 
        id="graficos" 
        className={`analytics-dual-grid ${mostrarGraficosMobile ? '' : 'analytics-hidden-mobile'}`}
      >
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
      <section id="filtros" className="filter-panel">
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
          5. TABELA DE INTELIGÊNCIA DE AMEAÇAS (PAGINAÇÃO DUPLA SERVER-SIDE)
          -------------------------------------------------------------------- */}
      <section id="feed-cves" className="threat-table-card" ref={threatTableRef}>
        <div className="section-header">
          <div className="section-header-left">
            <h2 className="section-title">
              <span className="section-title-prefix">&gt;_</span>
              <span>FEED DE VULNERABILIDADES (CATÁLOGO DE ALTA PERFORMANCE)</span>
            </h2>
            <span className="filter-stats-text">
              Página <span className="filter-stats-highlight">{paginaAtual}</span> de {totalPaginas}
            </span>
          </div>

          {/* Ações Rápidas de Visualização e Paginação no Topo */}
          {totalRegistros > 0 && (
            <div className="section-header-actions">
              <button
                type="button"
                className="btn-view-toggle"
                onClick={expandedCount > 0 ? recolherTodos : expandirTodos}
                title={expandedCount > 0 ? 'Recolher detalhes de todos os cards' : 'Expandir detalhes de todos os cards'}
              >
                {expandedCount > 0 ? '▲ Recolher Todos' : '▼ Expandir Todos'}
              </button>

              <div className="top-mini-pagination">
                <button
                  className="btn-mini-page"
                  onClick={() => mudarPagina(Math.max(1, paginaAtual - 1))}
                  disabled={paginaAtual <= 1 || carregandoTabela}
                  title="Página anterior"
                >
                  ‹
                </button>
                <span className="mini-page-indicator">
                  {paginaAtual}/{totalPaginas}
                </span>
                <button
                  className="btn-mini-page"
                  onClick={() => mudarPagina(Math.min(totalPaginas, paginaAtual + 1))}
                  disabled={paginaAtual >= totalPaginas || carregandoTabela}
                  title="Próxima página"
                >
                  ›
                </button>
              </div>
            </div>
          )}
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
                ameacas.map((item) => {
                  const isExpanded = !!expandedCves[item.cve_id]
                  return (
                    <tr
                      key={item.cve_id}
                      className={`threat-row ${isExpanded ? 'is-expanded' : 'is-collapsed'}`}
                      onClick={() => toggleExpandCve(item.cve_id)}
                      tabIndex={0}
                      role="button"
                      aria-expanded={isExpanded}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault()
                          toggleExpandCve(item.cve_id)
                        }
                      }}
                    >
                      <td className="cve-id-cell">
                        <div className="cve-id-content">
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(item.cve_id)}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            title="Abrir detalhes no NIST NVD"
                            onClick={(e) => e.stopPropagation()}
                          >
                            <span>{item.cve_id}</span>
                            <span>↗</span>
                          </a>
                          <button
                            type="button"
                            className="btn-card-expand"
                            aria-label={isExpanded ? 'Recolher detalhes' : 'Expandir detalhes'}
                            tabIndex={-1}
                          >
                            {isExpanded ? '▲' : '▼'}
                          </button>
                        </div>
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
                        <div className="cve-desc-body">
                          {item.descricao}
                        </div>
                        <div className="cve-expanded-actions">
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(item.cve_id)}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="btn-nvd-action"
                            onClick={(e) => e.stopPropagation()}
                          >
                            <span>Consultar CVE no NIST NVD</span>
                            <span>↗</span>
                          </a>
                        </div>
                      </td>
                      <td className="cve-date-cell">
                        {formatarData(item.data_extracao)}
                      </td>
                    </tr>
                  )
                })
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

        {/* Barra de Paginação Inferior Server-Side */}
        {totalRegistros > 0 && (
          <div className="table-pagination-bar">
            <div className="pagination-size-selector">
              <span>Registros:</span>
              <select
                className="pagination-select"
                value={itensPorPagina}
                onChange={(e) => {
                  setItensPorPagina(Number(e.target.value))
                  setPaginaAtual(1)
                }}
              >
                <option value={10}>10</option>
                <option value={15}>15</option>
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
              <span className="pagination-range-text">
                ({indiceInicio} - {indiceFim} de {totalRegistros.toLocaleString('pt-BR')})
              </span>
            </div>

            <div className="pagination-controls-group">
              <button
                className="btn-page"
                onClick={() => mudarPagina(1)}
                disabled={paginaAtual <= 1 || carregandoTabela}
                title="Primeira página"
              >
                &laquo;
              </button>
              <button
                className="btn-page"
                onClick={() => mudarPagina(Math.max(1, paginaAtual - 1))}
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
                onClick={() => mudarPagina(Math.min(totalPaginas, paginaAtual + 1))}
                disabled={paginaAtual >= totalPaginas || carregandoTabela}
                title="Próxima página"
              >
                Próxima &rsaquo;
              </button>
              <button
                className="btn-page"
                onClick={() => mudarPagina(totalPaginas)}
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

      {/* --------------------------------------------------------------------
          7. BOTÃO FLUTUANTE VOLTAR AO TOPO (MOBILE & DESKTOP)
          -------------------------------------------------------------------- */}
      {mostrarVoltarTopo && (
        <button
          type="button"
          className="btn-floating-top"
          onClick={irParaTopo}
          title="Voltar ao topo"
          aria-label="Voltar ao topo da página"
        >
          <span className="floating-top-arrow">▲</span>
          <span className="floating-top-label">TOPO</span>
        </button>
      )}
    </div>
  )
}

export default App