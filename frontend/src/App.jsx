import { useState, useEffect, useMemo, useRef, Fragment } from 'react'
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
          {data.percentual !== undefined && (
            <span className="tooltip-pct"> ({data.percentual}%)</span>
          )}
        </div>
        <div className="tooltip-hint">
          {data.ativa ? '✓ Filtro ativo — clique para limpar' : 'Clique na barra para filtrar o feed'}
        </div>
      </div>
    )
  }
  return null
}

const CACHE_KEYS = {
  overview: 'cti_overview_cache_v2',
  analytics: 'cti_analytics_cache_v2',
  threatsPage1: 'cti_threats_page1_v2',
  totalRegistros: 'cti_total_registros_v2',
  lastSync: 'cti_last_sync_v2'
}

const LEGACY_CACHE_KEYS = [
  'cti_overview_cache',
  'cti_analytics_cache',
  'cti_threats_page1',
  'cti_total_registros',
  'cti_last_sync'
]

const PRIMITIVE_LABELS = {
  RECON_INFO_LEAK: 'Recon & Info Leak',
  AUTH_BYPASS: 'Auth Bypass',
  INJECTION_RCE: 'Injection / RCE',
  PRIV_ESC: 'Privilege Escalation',
  DENIAL_OF_SERVICE: 'Denial of Service',
  GENERIC_VULN: 'Generic Vulnerability'
}

const formatarPrimitivaLabel = (prim) => {
  if (!prim) return 'Tática'
  return PRIMITIVE_LABELS[prim] || String(prim).replace(/_/g, ' ')
}

const chainTemKev = (chain) => {
  if (!chain) return false
  if (chain.writeup?.tem_kev) return true
  return Boolean(chain.writeup?.passos_ataque?.some((p) => p.cisa_kev))
}

const correspondeEcossistema = (chainTech, filtro) => {
  const a = String(chainTech || '').trim().toLowerCase()
  const b = String(filtro || '').trim().toLowerCase()
  if (!a || !b) return false
  return a === b
}

const limparTituloBlueprint = (titulo) => {
  if (!titulo) return 'Blueprint de Cadeia de Exploração'
  return String(titulo).replace(/^(?:\s*\[[^\]]+\]\s*)+/, '').trim()
}

const separarResumoEAlertaKev = (resumo) => {
  const texto = String(resumo || '').trim()
  const marcador = 'ALERTA SOC:'
  const idx = texto.indexOf(marcador)
  if (idx === -1) {
    return { textoPrincipal: texto, alertaSoc: null }
  }
  return {
    textoPrincipal: texto.slice(0, idx).trim(),
    alertaSoc: texto.slice(idx + marcador.length).trim()
  }
}

const obterPapelPasso = (idx, total) => {
  if (idx === 0) return 'Vetor Inicial'
  if (idx === total - 1) return 'Impacto Final'
  return 'Pivoting Tático'
}

const MITRE_FALLBACK_PRIMITIVE = {
  RECON_INFO_LEAK: {
    tactic_id: 'TA0001',
    tactic: 'Initial Access',
    technique_id: 'T1190',
    technique: 'Exploit Public-Facing Application'
  },
  AUTH_BYPASS: {
    tactic_id: 'TA0006',
    tactic: 'Credential Access',
    technique_id: 'T1078',
    technique: 'Valid Accounts / Auth Bypass'
  },
  INJECTION_RCE: {
    tactic_id: 'TA0002',
    tactic: 'Execution',
    technique_id: 'T1059',
    technique: 'Command and Scripting Interpreter'
  },
  PRIV_ESC: {
    tactic_id: 'TA0004',
    tactic: 'Privilege Escalation',
    technique_id: 'T1068',
    technique: 'Exploitation for Privilege Escalation'
  },
  DENIAL_OF_SERVICE: {
    tactic_id: 'TA0040',
    tactic: 'Impact',
    technique_id: 'T1499',
    technique: 'Endpoint Denial of Service'
  },
  GENERIC_VULN: {
    tactic_id: 'TA0001',
    tactic: 'Initial Access',
    technique_id: 'T1190',
    technique: 'Exploit Public-Facing Application'
  }
}

const MITRE_FALLBACK_CWE = {
  'CWE-22': { tactic_id: 'TA0009', tactic: 'Collection', technique_id: 'T1005', technique: 'Data from Local System' },
  'CWE-200': { tactic_id: 'TA0009', tactic: 'Collection', technique_id: 'T1005', technique: 'Data from Local System' },
  'CWE-532': { tactic_id: 'TA0006', tactic: 'Credential Access', technique_id: 'T1552', technique: 'Unsecured Credentials' },
  'CWE-798': { tactic_id: 'TA0006', tactic: 'Credential Access', technique_id: 'T1552', technique: 'Unsecured Credentials' },
  'CWE-89': { tactic_id: 'TA0001', tactic: 'Initial Access', technique_id: 'T1190', technique: 'Exploit Public-Facing Application' },
  'CWE-918': { tactic_id: 'TA0001', tactic: 'Initial Access', technique_id: 'T1190', technique: 'Exploit Public-Facing Application' },
  'CWE-502': { tactic_id: 'TA0002', tactic: 'Execution', technique_id: 'T1203', technique: 'Exploitation for Client/Server Execution' },
  'CWE-79': { tactic_id: 'TA0002', tactic: 'Execution', technique_id: 'T1059.007', technique: 'JavaScript Execution' }
}

const obterMitrePasso = (passo) => {
  if (passo?.mitre_attack?.technique_id) {
    return passo.mitre_attack
  }
  const cweKey = String(passo?.cwe || '').trim().toUpperCase()
  if (MITRE_FALLBACK_CWE[cweKey]) {
    return MITRE_FALLBACK_CWE[cweKey]
  }
  return MITRE_FALLBACK_PRIMITIVE[passo?.primitiva] || MITRE_FALLBACK_PRIMITIVE.GENERIC_VULN
}

const obterUrlMitreTechnique = (techniqueId) => {
  const bruto = String(techniqueId || '').trim()
  const validado = /^T\d{4}(?:\.\d{3})?$/i.test(bruto) ? bruto.toUpperCase() : 'T1190'
  return `https://attack.mitre.org/techniques/${validado.replace('.', '/')}/`
}

const obterUrlMitreCwe = (cweStr) => {
  const match = String(cweStr || '').trim().match(/^CWE-(\d+)$/i)
  if (!match) return null
  return `https://cwe.mitre.org/data/definitions/${match[1]}.html`
}

const formatarEpssPercent = (val) => {
  const num = Number(val)
  if (!Number.isFinite(num) || num <= 0) return null
  const pct = num * 100
  if (pct < 0.1) return '<0.1%'
  return `${pct.toFixed(1)}%`
}

const sanitizarCelulaCsv = (valor) => {
  if (valor === null || valor === undefined) return '""'
  let str = String(valor).replace(/\0/g, '').replace(/\r?\n/g, ' ').trim()
  if (/^[=+\-@\t\r]/.test(str)) {
    str = `'${str}`
  }
  return `"${str.replace(/"/g, '""')}"`
}

function App() {
  const PROD_API_URL = 'https://cyber-threat-intel-mmks.onrender.com'
  const [apiUrl, setApiUrl] = useState(() => {
    return import.meta.env.VITE_API_URL || PROD_API_URL
  })

  // Leitura segura do cache local versionado (v2) para renderização instantânea (0ms)
  const cachedOverview = useMemo(() => {
    try {
      const item = localStorage.getItem(CACHE_KEYS.overview) || sessionStorage.getItem(CACHE_KEYS.overview)
      if (item) return JSON.parse(item)
    } catch {
      // fallback gracioso
    }
    return null
  }, [])

  // 1. Estados de Telemetria e Analytics Globais (Instant Hydration via localStorage)
  const [apiStatus, setApiStatus] = useState('ONLINE')
  const [dbConectado, setDbConectado] = useState(true)
  const [sincronizandoNuvem, setSincronizandoNuvem] = useState(false)
  const [exploitChains, setExploitChains] = useState(() => {
    return cachedOverview?.chains || []
  })
  const [selectedChainId, setSelectedChainId] = useState(() => {
    return cachedOverview?.chains?.[0]?.chain_id || null
  })
  const [clustersData, setClustersData] = useState(() => {
    return cachedOverview?.clusters || { clusters: [], primitivas: [] }
  })
  const [analyticsData, setAnalyticsData] = useState(() => {
    if (cachedOverview?.stats) {
      return {
        stats: cachedOverview.stats,
        topTecnologias: cachedOverview.topTecnologias || []
      }
    }
    try {
      const legacy = localStorage.getItem(CACHE_KEYS.analytics) || sessionStorage.getItem(CACHE_KEYS.analytics)
      if (legacy) return JSON.parse(legacy)
    } catch {
      // fallback
    }
    return { stats: null, topTecnologias: [] }
  })
  const [ultimaAtualizacao, setUltimaAtualizacao] = useState(() => {
    try {
      return localStorage.getItem(CACHE_KEYS.lastSync) || sessionStorage.getItem(CACHE_KEYS.lastSync) || null
    } catch {
      return null
    }
  })

  // 2. Estados da Tabela Paginada no Servidor (Instant Hydration para Página 1)
  const [ameacas, setAmeacas] = useState(() => {
    const limiteInicial = typeof window !== 'undefined' && window.innerWidth <= 768 ? 10 : 25
    if (cachedOverview?.initialThreats?.dados) {
      return cachedOverview.initialThreats.dados.slice(0, limiteInicial)
    }
    try {
      const cached = localStorage.getItem(CACHE_KEYS.threatsPage1) || sessionStorage.getItem(CACHE_KEYS.threatsPage1)
      if (cached) {
        const parsed = JSON.parse(cached)
        return Array.isArray(parsed) ? parsed.slice(0, limiteInicial) : []
      }
    } catch {
      // fallback gracioso
    }
    return []
  })
  const [totalRegistros, setTotalRegistros] = useState(() => {
    if (cachedOverview?.initialThreats?.total) {
      return Number(cachedOverview.initialThreats.total) || 0
    }
    try {
      const cached = localStorage.getItem(CACHE_KEYS.totalRegistros) || sessionStorage.getItem(CACHE_KEYS.totalRegistros)
      if (cached) return Number(cached) || 0
    } catch {
      return 0
    }
    return 0
  })
  const [totalPaginas, setTotalPaginas] = useState(() => {
    const limiteInicial = typeof window !== 'undefined' && window.innerWidth <= 768 ? 10 : 25
    if (cachedOverview?.initialThreats?.total) {
      return Math.max(1, Math.ceil(Number(cachedOverview.initialThreats.total) / limiteInicial))
    }
    if (cachedOverview?.initialThreats?.totalPaginas) {
      return Number(cachedOverview.initialThreats.totalPaginas) || 1
    }
    return 1
  })
  const [carregandoTabela, setCarregandoTabela] = useState(false)

  // 3. Estados de Filtros, Ordenação e Paginação
  const [termoBusca, setTermoBusca] = useState('')
  const [debouncedBusca, setDebouncedBusca] = useState('')
  const [filtroSeveridade, setFiltroSeveridade] = useState('TODOS')
  const [filtroKev, setFiltroKev] = useState(false)
  const [filtroEpssAlto, setFiltroEpssAlto] = useState(false)
  const [filtroPrimitiva, setFiltroPrimitiva] = useState('TODOS')
  const [filtroCluster, setFiltroCluster] = useState('TODOS')
  const [filtroTecnologia, setFiltroTecnologia] = useState('TODOS')
  const [ordenacao, setOrdenacao] = useState('cvss_desc')
  const [paginaAtual, setPaginaAtual] = useState(1)
  const [itensPorPagina, setItensPorPagina] = useState(() => {
    if (typeof window !== 'undefined' && window.innerWidth <= 768) {
      return 10
    }
    return 25
  })

  // 4. Estados de Usabilidade, Atalhos e Navegação Mobile
  const [expandedCves, setExpandedCves] = useState({})
  const [copiadoCveId, setCopiadoCveId] = useState(null)
  const [mostrarGraficosMobile, setMostrarGraficosMobile] = useState(true)
  const [mostrarVoltarTopo, setMostrarVoltarTopo] = useState(false)
  const [refreshTick, setRefreshTick] = useState(0)
  const threatTableRef = useRef(null)
  const searchInputRef = useRef(null)

  // Estados e controle do Modal de Exploit Chains
  const [modalChainsAberto, setModalChainsAberto] = useState(false)
  const [filtroEcoChain, setFiltroEcoChain] = useState('TODOS')
  const [filtroKevChain, setFiltroKevChain] = useState(false)
  const [buscaChain, setBuscaChain] = useState('')
  const [copiadoWriteup, setCopiadoWriteup] = useState(false)
  const [highlightedStepIdx, setHighlightedStepIdx] = useState(null)
  const detailPanelRef = useRef(null)

  // Índice rápido CVE -> Exploit Chain para correlação direta na tabela
  const cveParaChainMap = useMemo(() => {
    const mapa = new Map()
    exploitChains.forEach((chain) => {
      ;(chain.cves || []).forEach((cveId) => {
        if (cveId && !mapa.has(cveId)) {
          mapa.set(cveId, chain)
        }
      })
    })
    return mapa
  }, [exploitChains])

  const ecossistemasDisponiveis = useMemo(() => {
    const setEcos = new Set()
    exploitChains.forEach((c) => {
      if (c.tecnologia && c.tecnologia !== 'Desconhecido / Geral') {
        setEcos.add(c.tecnologia)
      }
    })
    return Array.from(setEcos)
  }, [exploitChains])

  const totalChainsKev = useMemo(() => {
    return exploitChains.filter((c) => chainTemKev(c)).length
  }, [exploitChains])

  const totalChainsCriticas = useMemo(() => {
    return exploitChains.filter((c) => c.severidade === 'CRITICAL').length
  }, [exploitChains])

  const chainsFiltradas = useMemo(() => {
    if (!exploitChains || exploitChains.length === 0) return []
    const termo = buscaChain.trim().toLowerCase()
    return exploitChains.filter((c) => {
      const okEco = filtroEcoChain === 'TODOS' || correspondeEcossistema(c.tecnologia, filtroEcoChain)
      const okKev = !filtroKevChain || chainTemKev(c)
      if (!okEco || !okKev) return false
      if (!termo) return true

      const textoAlvo = [
        c.chain_id,
        c.tecnologia,
        ...(c.cves || []),
        c.writeup?.titulo,
        ...(c.writeup?.passos_ataque || []).flatMap((p) => {
          const mitre = obterMitrePasso(p)
          return [p.primitiva, p.cwe, p.acao, mitre.tactic_id, mitre.tactic, mitre.technique_id, mitre.technique]
        })
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()

      return textoAlvo.includes(termo)
    })
  }, [exploitChains, filtroEcoChain, filtroKevChain, buscaChain])

  const activeChain = useMemo(() => {
    if (!chainsFiltradas || chainsFiltradas.length === 0) {
      return null
    }
    return chainsFiltradas.find((c) => c.chain_id === selectedChainId) || chainsFiltradas[0]
  }, [chainsFiltradas, selectedChainId])

  const activeBlueprintMeta = useMemo(() => {
    if (!activeChain || !activeChain.writeup) return null
    const passos = activeChain.writeup.passos_ataque || []
    const scoreVal = Number(activeChain.score_cvss || 10.0)
    const scorePct = Math.min(100, Math.max(10, Math.round(scoreVal * 10)))
    const isHigh = activeChain.severidade === 'HIGH'
    const temKevAtivo = chainTemKev(activeChain)
    const maxEpssVal = Math.max(
      Number(activeChain.writeup.max_epss || 0),
      ...passos.map((p) => Number(p.epss_score || 0))
    )
    const maxEpssFmt = formatarEpssPercent(maxEpssVal)
    const { textoPrincipal, alertaSoc } = separarResumoEAlertaKev(activeChain.writeup.resumo_executivo)
    return { passos, scoreVal, scorePct, isHigh, temKevAtivo, maxEpssFmt, textoPrincipal, alertaSoc }
  }, [activeChain])

  const selecionarChainCard = (chainId) => {
    setSelectedChainId(chainId)
    setCopiadoWriteup(false)
    setHighlightedStepIdx(null)
    if (detailPanelRef.current) {
      detailPanelRef.current.scrollTo({ top: 0, behavior: 'smooth' })
    }
  }

  const resetarFiltrosModalChains = () => {
    setFiltroEcoChain('TODOS')
    setFiltroKevChain(false)
    setBuscaChain('')
    setCopiadoWriteup(false)
    if (exploitChains.length > 0) {
      setSelectedChainId(exploitChains[0].chain_id)
    }
  }

  const selecionarEcoNoModal = (ecoNome) => {
    setFiltroEcoChain(ecoNome)
    setCopiadoWriteup(false)
    if (!exploitChains || exploitChains.length === 0) return
    const match = exploitChains.find((c) => {
      const okEco = ecoNome === 'TODOS' || correspondeEcossistema(c.tecnologia, ecoNome)
      const okKev = !filtroKevChain || chainTemKev(c)
      return okEco && okKev
    })
    if (match) {
      setSelectedChainId(match.chain_id)
      if (detailPanelRef.current) {
        detailPanelRef.current.scrollTo({ top: 0, behavior: 'smooth' })
      }
    }
  }

  const abrirModalPorEcossistema = (techNome) => {
    setFiltroEcoChain(techNome)
    setFiltroKevChain(false)
    setBuscaChain('')
    setCopiadoWriteup(false)
    setModalChainsAberto(true)
    if (exploitChains && exploitChains.length > 0) {
      const match = exploitChains.find((c) => correspondeEcossistema(c.tecnologia, techNome))
      if (match) {
        setSelectedChainId(match.chain_id)
      }
    }
  }

  const abrirChainEspecifica = (chain) => {
    if (!chain) return
    setFiltroEcoChain('TODOS')
    setFiltroKevChain(false)
    setBuscaChain('')
    setCopiadoWriteup(false)
    setHighlightedStepIdx(null)
    setSelectedChainId(chain.chain_id)
    setModalChainsAberto(true)
  }

  const focarPassoTimeline = (idx) => {
    setHighlightedStepIdx(idx)
    const el = document.getElementById(`chain-step-${idx}`)
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
    }
    setTimeout(() => {
      setHighlightedStepIdx((atual) => (atual === idx ? null : atual))
    }, 1500)
  }

  const copiarIdCve = async (e, cveId) => {
    if (e) e.stopPropagation()
    if (!cveId) return
    try {
      await navigator.clipboard.writeText(cveId)
      setCopiadoCveId(cveId)
      setTimeout(() => {
        setCopiadoCveId((atual) => (atual === cveId ? null : atual))
      }, 1500)
    } catch {
      // fallback silencioso em contextos sem permissão de clipboard
    }
  }

  const inspecionarCveNoFeed = (cveId) => {
    if (!cveId) return
    setModalChainsAberto(false)
    setFiltroSeveridade('TODOS')
    setFiltroKev(false)
    setFiltroEpssAlto(false)
    setFiltroPrimitiva('TODOS')
    setFiltroCluster('TODOS')
    setFiltroTecnologia('TODOS')
    setPaginaAtual(1)
    setTermoBusca(cveId)
    setDebouncedBusca(cveId)
    setTimeout(() => {
      if (threatTableRef.current) {
        const topOffset = threatTableRef.current.getBoundingClientRect().top + window.scrollY - 20
        window.scrollTo({ top: topOffset, behavior: 'smooth' })
      }
    }, 60)
  }

  const selecionarTecnologiaNoFeed = (techNome) => {
    const proximo = filtroTecnologia === techNome ? 'TODOS' : techNome
    setFiltroTecnologia(proximo)
    setPaginaAtual(1)
    if (proximo !== 'TODOS' && threatTableRef.current) {
      const topOffset = threatTableRef.current.getBoundingClientRect().top + window.scrollY - 20
      window.scrollTo({ top: topOffset, behavior: 'smooth' })
    }
  }

  const alternarSeveridadeNoFeed = (sevKey, scrollFeed = false) => {
    if (!sevKey) return
    const proximo = filtroSeveridade === sevKey ? 'TODOS' : sevKey
    setFiltroSeveridade(proximo)
    setPaginaAtual(1)
    if (scrollFeed && proximo !== 'TODOS' && threatTableRef.current) {
      const topOffset = threatTableRef.current.getBoundingClientRect().top + window.scrollY - 20
      window.scrollTo({ top: topOffset, behavior: 'smooth' })
    }
  }

  const alternarOrdenacaoColuna = (modoAlvo) => {
    setOrdenacao((atual) => (atual === modoAlvo ? 'cvss_desc' : modoAlvo))
    setPaginaAtual(1)
  }

  const forcarSincronizacao = () => {
    setRefreshTick((prev) => prev + 1)
  }

  const dispararDownloadArquivo = (conteudo, nomeArquivo, mimeType) => {
    const blob = new Blob([conteudo], { type: mimeType })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = nomeArquivo
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
  }

  const exportarFeedCsv = () => {
    if (!ameacas.length) return
    const cabecalhos = [
      'CVE_ID',
      'CVSS_SCORE',
      'EPSS_PROBABILITY',
      'SEVERIDADE',
      'CISA_KEV',
      'CWE',
      'PRIMITIVA_KILL_CHAIN',
      'TECNOLOGIA',
      'ML_CLUSTER',
      'PUBLICACAO_NIST',
      'DESCRICAO'
    ]
    const linhas = ameacas.map((item) => [
      sanitizarCelulaCsv(item.cve_id),
      sanitizarCelulaCsv(Number(item.nota_cvss || 0).toFixed(1)),
      sanitizarCelulaCsv(formatarEpssPercent(item.epss_score) || '0.0%'),
      sanitizarCelulaCsv(item.severidade || 'UNKNOWN'),
      sanitizarCelulaCsv(item.cisa_kev ? 'TRUE' : 'FALSE'),
      sanitizarCelulaCsv(item.cwe || 'NVD-CWE-noinfo'),
      sanitizarCelulaCsv(item.primitiva || 'GENERIC_VULN'),
      sanitizarCelulaCsv(item.tecnologia || 'Desconhecido / Geral'),
      sanitizarCelulaCsv(item.cluster_label || 'Geral / Não Clusterizado'),
      sanitizarCelulaCsv(item.data_publicacao || item.data_extracao || ''),
      sanitizarCelulaCsv(item.descricao || '')
    ].join(','))

    const csvFinal = `\uFEFF${[cabecalhos.join(','), ...linhas].join('\n')}`
    const stamp = new Date().toISOString().slice(0, 10)
    dispararDownloadArquivo(csvFinal, `cti-threats-p${paginaAtual}-${stamp}.csv`, 'text/csv;charset=utf-8;')
  }

  const exportarFeedJson = () => {
    if (!ameacas.length) return
    const payload = {
      exported_at: new Date().toISOString(),
      page: paginaAtual,
      total_matching_records: totalRegistros,
      filters: {
        search: debouncedBusca || null,
        severity: filtroSeveridade,
        cisa_kev_only: filtroKev,
        high_epss_only: filtroEpssAlto,
        primitive: filtroPrimitiva,
        cluster: filtroCluster,
        technology: filtroTecnologia,
        sort: ordenacao
      },
      vulnerabilities: ameacas
    }
    const stamp = new Date().toISOString().slice(0, 10)
    dispararDownloadArquivo(
      JSON.stringify(payload, null, 2),
      `cti-threats-p${paginaAtual}-${stamp}.json`,
      'application/json;charset=utf-8;'
    )
  }

  const exportarChainJson = (chain) => {
    if (!chain?.writeup) return
    const passosEnriquecidos = (chain.writeup.passos_ataque || []).map((p) => ({
      ...p,
      mitre_attack: obterMitrePasso(p)
    }))
    const payload = {
      exported_at: new Date().toISOString(),
      chain_id: chain.chain_id,
      target_ecosystem: chain.tecnologia,
      severity: chain.severidade,
      composite_cvss: Number(chain.score_cvss || 10.0),
      cves: chain.cves || [],
      blueprint: {
        ...chain.writeup,
        passos_ataque: passosEnriquecidos
      }
    }
    const slug = String(chain.chain_id || 'chain').toLowerCase().replace(/[^a-z0-9_-]/g, '-')
    dispararDownloadArquivo(
      JSON.stringify(payload, null, 2),
      `cti-blueprint-${slug}.json`,
      'application/json;charset=utf-8;'
    )
  }

  const copiarWriteupMarkdown = async (chain) => {
    if (!chain?.writeup) return
    const w = chain.writeup
    const passosMd = (w.passos_ataque || [])
      .map((p) => {
        const mitre = obterMitrePasso(p)
        const epssFmt = formatarEpssPercent(p.epss_score)
        const tags = [
          p.primitiva,
          `${mitre.technique_id} (${mitre.tactic})`,
          p.nota_cvss ? `CVSS ${Number(p.nota_cvss).toFixed(1)}` : null,
          epssFmt ? `EPSS ${epssFmt}` : null,
          p.cwe && p.cwe !== 'NVD-CWE-noinfo' ? p.cwe : null,
          p.cisa_kev ? 'CISA KEV' : null
        ].filter(Boolean).join(' | ')
        return `### Passo ${p.passo}: ${p.cve_id} (${tags})\n- **MITRE ATT&CK:** ${mitre.tactic_id} - ${mitre.tactic} / ${mitre.technique_id} - ${mitre.technique}\n- **Ação:** ${p.acao}\n- **Detalhe:** ${p.detalhe}`
      })
      .join('\n\n')

    const mitigacoesMd = (w.mitigacoes_recomendadas || [])
      .map((m) => `- ${m}`)
      .join('\n')

    const taticasChain = Array.from(
      new Set((w.passos_ataque || []).map((p) => {
        const m = obterMitrePasso(p)
        return `${m.tactic_id} (${m.technique_id})`
      }))
    )

    const markdown = [
      `# ${w.titulo}`,
      `- **Chain ID:** ${chain.chain_id}`,
      `- **Alvo / Ecossistema:** ${chain.tecnologia}`,
      `- **Score Composto:** ${Number(chain.score_cvss || 10.0).toFixed(1)} (${chain.severidade})`,
      taticasChain.length ? `- **MITRE ATT&CK:** ${taticasChain.join(' -> ')}` : null,
      `- **Fluxo de CVEs:** ${(chain.cves || []).join(' -> ')}`,
      '',
      '## Resumo Executivo',
      w.resumo_executivo,
      '',
      '## Fluxo Tático de Ataque',
      passosMd,
      '',
      '## Impacto Técnico Consolidado',
      w.impacto_tecnico,
      '',
      '## Mitigações Recomendadas pelo SOC',
      mitigacoesMd
    ].filter((l) => l !== null).join('\n')

    try {
      await navigator.clipboard.writeText(markdown)
      setCopiadoWriteup(true)
      setTimeout(() => setCopiadoWriteup(false), 2200)
    } catch {
      // ignore clipboard errors in non-HTTPS contexts
    }
  }

  // Listener para fechar o modal com ESC, navegar cadeias com ↑/↓ e travar scroll do fundo
  useEffect(() => {
    if (!modalChainsAberto) return undefined

    document.body.classList.add('soc-modal-open')

    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        setModalChainsAberto(false)
        return
      }
      if ((e.key === 'ArrowDown' || e.key === 'ArrowUp') && chainsFiltradas.length > 0) {
        const tag = e.target?.tagName?.toLowerCase()
        if (tag !== 'input' && tag !== 'textarea') {
          e.preventDefault()
          const idRef = activeChain?.chain_id || selectedChainId
          const idxAtual = chainsFiltradas.findIndex((c) => c.chain_id === idRef)
          const delta = e.key === 'ArrowDown' ? 1 : -1
          const proximoIdx = idxAtual === -1 ? 0 : (idxAtual + delta + chainsFiltradas.length) % chainsFiltradas.length
          const proximaChain = chainsFiltradas[proximoIdx]
          if (proximaChain) {
            setSelectedChainId(proximaChain.chain_id)
            setCopiadoWriteup(false)
            setHighlightedStepIdx(null)
            if (detailPanelRef.current) {
              detailPanelRef.current.scrollTo({ top: 0, behavior: 'smooth' })
            }
          }
        }
      }
    }
    window.addEventListener('keydown', handleKeyDown)

    return () => {
      document.body.classList.remove('soc-modal-open')
      window.removeEventListener('keydown', handleKeyDown)
    }
  }, [modalChainsAberto, chainsFiltradas, activeChain, selectedChainId])

  // Atalho global '/' ou Ctrl+K / Cmd+K para focar o terminal de Full-Text Search
  useEffect(() => {
    const handleGlobalShortcut = (e) => {
      if (modalChainsAberto) return
      const tag = document.activeElement?.tagName?.toLowerCase()
      const editandoTexto =
        tag === 'input' ||
        tag === 'textarea' ||
        tag === 'select' ||
        document.activeElement?.isContentEditable

      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        searchInputRef.current?.focus()
        searchInputRef.current?.select()
        return
      }

      if (!editandoTexto && !e.ctrlKey && !e.metaKey && !e.altKey && e.key === '/') {
        e.preventDefault()
        searchInputRef.current?.focus()
      }
    }

    window.addEventListener('keydown', handleGlobalShortcut)
    return () => window.removeEventListener('keydown', handleGlobalShortcut)
  }, [modalChainsAberto])

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

  // Limpeza automática de chaves antigas não versionadas (remove CVEs legadas de 1999 do cache local)
  useEffect(() => {
    try {
      LEGACY_CACHE_KEYS.forEach((key) => {
        localStorage.removeItem(key)
        sessionStorage.removeItem(key)
      })
    } catch {
      // ignore storage errors
    }
  }, [])

  // Snapshot reativo do estado de filtros/paginação para leitura segura em efeitos assíncronos
  const uiStateRef = useRef({
    paginaAtual,
    debouncedBusca,
    filtroSeveridade,
    filtroKev,
    filtroEpssAlto,
    filtroPrimitiva,
    filtroCluster,
    filtroTecnologia,
    ordenacao,
    itensPorPagina,
    temAmeacas: ameacas.length > 0
  })

  useEffect(() => {
    uiStateRef.current = {
      paginaAtual,
      debouncedBusca,
      filtroSeveridade,
      filtroKev,
      filtroEpssAlto,
      filtroPrimitiva,
      filtroCluster,
      filtroTecnologia,
      ordenacao,
      itensPorPagina,
      temAmeacas: ameacas.length > 0
    }
  }, [
    paginaAtual,
    debouncedBusca,
    filtroSeveridade,
    filtroKev,
    filtroEpssAlto,
    filtroPrimitiva,
    filtroCluster,
    filtroTecnologia,
    ordenacao,
    itensPorPagina,
    ameacas.length
  ])

  // ---------------------------------------------------------------------------
  // EFEITO 3: Carga em Background de Telemetria e Overview Consolidado (Single Round-Trip)
  // ---------------------------------------------------------------------------
  useEffect(() => {
    let isMounted = true

    const aplicarOverviewConsolidado = (data) => {
      setApiStatus('ONLINE')
      setDbConectado(true)
      setSincronizandoNuvem(false)

      const novoPayload = {
        stats: data.stats || null,
        topTecnologias: data.topTecnologias || []
      }
      setAnalyticsData(novoPayload)

      if (Array.isArray(data.chains) && data.chains.length > 0) {
        setExploitChains(data.chains)
        setSelectedChainId((prev) => prev || data.chains[0].chain_id)
      }

      if (data.clusters) {
        setClustersData(data.clusters)
      }

      const ui = uiStateRef.current
      const semFiltrosAtivos =
        ui.paginaAtual === 1 &&
        !ui.debouncedBusca &&
        ui.filtroSeveridade === 'TODOS' &&
        !ui.filtroKev &&
        !ui.filtroEpssAlto &&
        ui.filtroPrimitiva === 'TODOS' &&
        ui.filtroCluster === 'TODOS' &&
        ui.filtroTecnologia === 'TODOS' &&
        ui.ordenacao === 'cvss_desc'

      if (data.initialThreats?.dados && semFiltrosAtivos && (ui.itensPorPagina === 25 || ui.itensPorPagina === 10)) {
        const total = Number(data.initialThreats.total) || 0
        setAmeacas(data.initialThreats.dados.slice(0, ui.itensPorPagina))
        setTotalRegistros(total)
        setTotalPaginas(Math.max(1, Math.ceil(total / ui.itensPorPagina)))
      }

      const horaFormatada = new Date().toLocaleTimeString('pt-BR')
      setUltimaAtualizacao(horaFormatada)

      try {
        localStorage.setItem(CACHE_KEYS.overview, JSON.stringify(data))
        localStorage.setItem(CACHE_KEYS.lastSync, horaFormatada)
      } catch {
        // ignore storage errors
      }
    }

    const carregarTelemetriaEOverview = async () => {
      let activeUrl = apiUrl
      setSincronizandoNuvem(true)

      try {
        // 1. Tenta a rota consolidada de alta velocidade (/api/threats/overview)
        try {
          const overviewRes = await axios.get(`${activeUrl}/api/threats/overview`, { timeout: 25000 })
          if (overviewRes.data && overviewRes.data.status === 'OK') {
            if (!isMounted) return
            aplicarOverviewConsolidado(overviewRes.data)
            return
          }
        } catch {
          // Se falhar no localhost, tenta fallback para a URL de produção na nuvem
          if (activeUrl.includes('localhost')) {
            activeUrl = PROD_API_URL
            setApiUrl(PROD_API_URL)
            try {
              const prodOverview = await axios.get(`${PROD_API_URL}/api/threats/overview`, { timeout: 25000 })
              if (prodOverview.data && prodOverview.data.status === 'OK') {
                if (!isMounted) return
                aplicarOverviewConsolidado(prodOverview.data)
                return
              }
            } catch {
              // segue para fallback nos endpoints individuais
            }
          }
        }

        // 2. Fallback resiliente: consulta endpoints individuais caso o servidor esteja em deploy
        let [healthRes, analyticsRes, chainsRes, clustersRes] = await Promise.allSettled([
          axios.get(`${activeUrl}/api/health`, { timeout: 15000 }),
          axios.get(`${activeUrl}/api/threats/analytics`, { timeout: 15000 }),
          axios.get(`${activeUrl}/api/threats/chains`, { timeout: 15000 }),
          axios.get(`${activeUrl}/api/threats/clusters`, { timeout: 15000 })
        ])

        if (!isMounted) return
        setSincronizandoNuvem(false)

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

          try {
            localStorage.setItem(CACHE_KEYS.analytics, JSON.stringify(novoPayload))
            localStorage.setItem(CACHE_KEYS.lastSync, horaFormatada)
          } catch {
            // ignore
          }
        } else {
          setDbConectado(false)
        }

        if (chainsRes.status === 'fulfilled' && Array.isArray(chainsRes.value.data)) {
          setExploitChains(chainsRes.value.data)
          if (chainsRes.value.data.length > 0) {
            setSelectedChainId((prev) => prev || chainsRes.value.data[0].chain_id)
          }
        }

        if (clustersRes.status === 'fulfilled' && clustersRes.value.data) {
          setClustersData(clustersRes.value.data)
        }
      } catch (err) {
        console.error('[-] Erro ao carregar telemetria da API:', err)
        setDbConectado(false)
        setSincronizandoNuvem(false)
      }
    }

    carregarTelemetriaEOverview()

    return () => {
      isMounted = false
    }
  }, [apiUrl, refreshTick])

  // ---------------------------------------------------------------------------
  // EFEITO 4: Consulta Server-Side com GIN Full-Text Search e Cache de Página 1
  // ---------------------------------------------------------------------------
  useEffect(() => {
    let isMounted = true
    const controller = new AbortController()

    const carregarAmeacasPaginadas = async () => {
      const semFiltrosAtivos =
        paginaAtual === 1 &&
        !debouncedBusca &&
        filtroSeveridade === 'TODOS' &&
        !filtroKev &&
        !filtroEpssAlto &&
        filtroPrimitiva === 'TODOS' &&
        filtroCluster === 'TODOS' &&
        filtroTecnologia === 'TODOS' &&
        ordenacao === 'cvss_desc'

      // Se já temos a página 1 em memória via cache instantâneo e não há busca/filtro ativa,
      // não exibe spinner intrusivo
      const temCacheValido = semFiltrosAtivos && uiStateRef.current.temAmeacas && refreshTick === 0
      if (!temCacheValido) {
        setCarregandoTabela(true)
      }

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

        if (filtroKev) {
          params.kev = 'true'
        }

        if (filtroEpssAlto) {
          params.min_epss = 0.1
        }

        if (filtroPrimitiva && filtroPrimitiva !== 'TODOS') {
          params.primitive = filtroPrimitiva
        }

        if (filtroCluster && filtroCluster !== 'TODOS') {
          params.cluster = filtroCluster
        }

        if (filtroTecnologia && filtroTecnologia !== 'TODOS') {
          params.technology = filtroTecnologia
        }

        if (ordenacao && ordenacao !== 'cvss_desc') {
          params.sort = ordenacao
        }

        const res = await axios.get(`${apiUrl}/api/threats`, {
          params,
          signal: controller.signal,
          timeout: 20000
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

          // Salva página padrão no cache do localStorage para acelerar recargas futuras
          if (semFiltrosAtivos) {
            try {
              localStorage.setItem(CACHE_KEYS.threatsPage1, JSON.stringify(listaRecebida))
              localStorage.setItem(CACHE_KEYS.totalRegistros, String(totalRecebido))
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
  }, [apiUrl, paginaAtual, itensPorPagina, debouncedBusca, filtroSeveridade, filtroKev, filtroEpssAlto, filtroPrimitiva, filtroCluster, filtroTecnologia, ordenacao, refreshTick])

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

  const limparTodosFiltros = () => {
    setTermoBusca('')
    setDebouncedBusca('')
    setFiltroSeveridade('TODOS')
    setFiltroKev(false)
    setFiltroEpssAlto(false)
    setFiltroPrimitiva('TODOS')
    setFiltroCluster('TODOS')
    setFiltroTecnologia('TODOS')
    setOrdenacao('cvss_desc')
    setPaginaAtual(1)
  }

  const temFiltroAtivo = Boolean(
    filtroKev ||
    filtroEpssAlto ||
    filtroPrimitiva !== 'TODOS' ||
    filtroCluster !== 'TODOS' ||
    filtroSeveridade !== 'TODOS' ||
    filtroTecnologia !== 'TODOS' ||
    ordenacao !== 'cvss_desc' ||
    termoBusca
  )

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
    const totalBase = Math.max(1, Number(s.total_ameacas) || 0)
    const calcPct = (v) => ((Number(v || 0) / totalBase) * 100).toFixed(1)
    return [
      {
        nome: 'Crítico',
        severidadeKey: 'CRITICAL',
        faixa: 'CVSS 9.0 - 10.0',
        valor: Number(s.criticas) || 0,
        percentual: calcPct(s.criticas),
        ativa: filtroSeveridade === 'CRITICAL',
        cor: 'var(--critical-red)'
      },
      {
        nome: 'Alto',
        severidadeKey: 'HIGH',
        faixa: 'CVSS 7.0 - 8.9',
        valor: Number(s.altas) || 0,
        percentual: calcPct(s.altas),
        ativa: filtroSeveridade === 'HIGH',
        cor: 'var(--high-orange)'
      },
      {
        nome: 'Médio',
        severidadeKey: 'MEDIUM',
        faixa: 'CVSS 4.0 - 6.9',
        valor: Number(s.medias) || 0,
        percentual: calcPct(s.medias),
        ativa: filtroSeveridade === 'MEDIUM',
        cor: 'var(--medium-yellow)'
      },
      {
        nome: 'Baixo',
        severidadeKey: 'LOW',
        faixa: 'CVSS 0.1 - 3.9',
        valor: Number(s.baixas) || 0,
        percentual: calcPct(s.baixas),
        ativa: filtroSeveridade === 'LOW',
        cor: 'var(--low-blue)'
      }
    ]
  }, [analyticsData.stats, filtroSeveridade])

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
            <span className={`led-indicator ${apiStatus === 'ONLINE' ? 'led-green' : sincronizandoNuvem ? 'led-yellow' : 'led-red'}`} />
            <span className="status-label">API EXPRESS:</span>
            <span className="status-value">{sincronizandoNuvem && apiStatus !== 'ONLINE' ? 'SINCRONIZANDO...' : apiStatus}</span>
          </div>

          <div className="status-badge">
            <span className={`led-indicator ${dbConectado ? 'led-green' : sincronizandoNuvem ? 'led-yellow' : 'led-red'}`} />
            <span className="status-label">AWS RDS PG:</span>
            <span className="status-value">{dbConectado ? 'CONECTADO' : sincronizandoNuvem ? 'CONECTANDO...' : 'DESCONECTADO'}</span>
          </div>

          <button
            type="button"
            className="status-badge status-badge-btn"
            onClick={() => {
              setFiltroEcoChain('TODOS')
              setModalChainsAberto(true)
            }}
            title="Abrir Exploit Chains e Blueprints de Ataque"
          >
            <span className="led-indicator led-chains" />
            <span className="status-label">EXPLOIT CHAINS:</span>
            <span className="status-value status-chains-val">{exploitChains.length}</span>
          </button>
        </div>
      </header>

      {/* --------------------------------------------------------------------
          1.1. BARRA DE NAVEGAÇÃO RÁPIDA (ACESSO DIRETO ÀS SEÇÕES)
          -------------------------------------------------------------------- */}
      <nav className="soc-quick-nav" aria-label="Navegação Rápida">
        <a href="#metricas" className="quick-nav-pill">
          Métricas
        </a>
        <a href="#graficos" className="quick-nav-pill">
          Gráficos
        </a>
        <a href="#filtros" className="quick-nav-pill">
          Busca &amp; Filtros
        </a>
        <a href="#feed-cves" className="quick-nav-pill">
          Feed CVEs
        </a>
        <button
          type="button"
          className="quick-nav-pill quick-nav-chains"
          onClick={() => {
            setFiltroEcoChain('TODOS')
            setModalChainsAberto(true)
          }}
          title="Ver Exploit Chains Correlacionadas"
        >
          Exploit Chains ({exploitChains.length})
        </button>
      </nav>

      {/* --------------------------------------------------------------------
          2. CARDS DE KPIS CONSOLIDADOS
          -------------------------------------------------------------------- */}
      <section id="metricas" className="kpi-grid">
        <div
          className={`kpi-card kpi-total ${temFiltroAtivo ? 'kpi-interactive' : ''}`}
          onClick={temFiltroAtivo ? limparTodosFiltros : undefined}
          role={temFiltroAtivo ? 'button' : undefined}
          tabIndex={temFiltroAtivo ? 0 : undefined}
          title={temFiltroAtivo ? 'Clique para limpar todos os filtros ativos' : 'Total de vulnerabilidades indexadas na base global'}
          onKeyDown={
            temFiltroAtivo
              ? (e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault()
                    limparTodosFiltros()
                  }
                }
              : undefined
          }
        >
          <div className="kpi-card-header">
            <span className="kpi-title">Total Ingerido</span>
            {Number(analyticsData.stats?.cisa_kev_total) > 0 && (
              <span className="kpi-mini-pill pill-kev-mini" title="Vulnerabilidades exploradas ativamente (Catálogo CISA KEV)">
                {Number(analyticsData.stats.cisa_kev_total).toLocaleString('pt-BR')} KEV
              </span>
            )}
          </div>
          <div className="kpi-value">
            {analyticsData.stats ? Number(analyticsData.stats.total_ameacas).toLocaleString('pt-BR') : '---'}
          </div>
          <div className="kpi-footer">
            <span>{temFiltroAtivo ? '✕ Clique p/ restaurar visão global' : 'Base Global NIST NVD'}</span>
          </div>
        </div>

        <div
          className={`kpi-card kpi-critical kpi-interactive ${filtroSeveridade === 'CRITICAL' ? 'is-kpi-active' : ''}`}
          onClick={() => alternarSeveridadeNoFeed('CRITICAL', true)}
          role="button"
          tabIndex={0}
          title="Clique para filtrar ameaças CRITICAL no feed"
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault()
              alternarSeveridadeNoFeed('CRITICAL', true)
            }
          }}
        >
          <div className="kpi-card-header">
            <span className="kpi-title">Ameaças Críticas</span>
            {Number(analyticsData.stats?.total_ameacas) > 0 && (
              <span className="kpi-mini-pill pill-crit-mini">
                {((Number(analyticsData.stats.criticas || 0) / Math.max(1, Number(analyticsData.stats.total_ameacas))) * 100).toFixed(1)}%
              </span>
            )}
          </div>
          <div className="kpi-value">
            {analyticsData.stats ? Number(analyticsData.stats.criticas).toLocaleString('pt-BR') : '---'}
          </div>
          <div className="kpi-footer">
            <span>{filtroSeveridade === 'CRITICAL' ? '✓ Filtro ativo no feed' : 'CVSS Score ≥ 9.0'}</span>
          </div>
        </div>

        <div
          className={`kpi-card kpi-high kpi-interactive ${filtroSeveridade === 'HIGH' ? 'is-kpi-active' : ''}`}
          onClick={() => alternarSeveridadeNoFeed('HIGH', true)}
          role="button"
          tabIndex={0}
          title="Clique para filtrar ameaças HIGH no feed"
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault()
              alternarSeveridadeNoFeed('HIGH', true)
            }
          }}
        >
          <div className="kpi-card-header">
            <span className="kpi-title">Ameaças Altas</span>
            {Number(analyticsData.stats?.total_ameacas) > 0 && (
              <span className="kpi-mini-pill pill-high-mini">
                {((Number(analyticsData.stats.altas || 0) / Math.max(1, Number(analyticsData.stats.total_ameacas))) * 100).toFixed(1)}%
              </span>
            )}
          </div>
          <div className="kpi-value">
            {analyticsData.stats ? Number(analyticsData.stats.altas).toLocaleString('pt-BR') : '---'}
          </div>
          <div className="kpi-footer">
            <span>{filtroSeveridade === 'HIGH' ? '✓ Filtro ativo no feed' : 'CVSS Score 7.0 - 8.9'}</span>
          </div>
        </div>

        <div className="kpi-card kpi-score">
          <div className="kpi-card-header">
            <span className="kpi-title">Pior Risco Detectado</span>
            {Number(analyticsData.stats?.media_score) > 0 && (
              <span className="kpi-mini-pill pill-avg-mini" title="Score CVSS médio de todas as vulnerabilidades do catálogo">
                MÉDIA {Number(analyticsData.stats.media_score).toFixed(1)}
              </span>
            )}
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
              <span>DISTRIBUIÇÃO DE SEVERIDADE CVSS (v4.0 / v3.x / v2.0)</span>
            </h3>
            <span className="analytics-badge">MATRIZ DE RISCO GLOBAL</span>
          </div>
          <div className="chart-container-inner chart-wide">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={dadosSeveridade}
                margin={{ top: 15, right: 20, left: 0, bottom: 5 }}
              >
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
                <Bar
                  dataKey="valor"
                  radius={[6, 6, 0, 0]}
                  maxBarSize={52}
                  style={{ cursor: 'pointer' }}
                  onClick={(barData) => {
                    const sevKey = barData?.severidadeKey || barData?.payload?.severidadeKey
                    if (sevKey) alternarSeveridadeNoFeed(sevKey)
                  }}
                >
                  {dadosSeveridade.map((entry, index) => (
                    <Cell
                      key={`cell-${index}`}
                      fill={entry.cor}
                      fillOpacity={filtroSeveridade === 'TODOS' || filtroSeveridade === entry.severidadeKey ? 1 : 0.32}
                    />
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
            <button
              type="button"
              className="analytics-chains-shortcut"
              onClick={() => {
                setFiltroEcoChain('TODOS')
                setModalChainsAberto(true)
              }}
              title="Abrir Exploit Chains correlacionadas"
            >
              <span>CHAINS</span>
            </button>
          </div>
          <div className="tech-ranking-list">
            {analyticsData.topTecnologias.map((tech) => {
              const porcentagem = Math.round((tech.total / maxTechCount) * 100)
              const techAtiva = filtroTecnologia === tech.nome
              return (
                <div
                  key={tech.nome}
                  className={`tech-ranking-item tech-clickable ${techAtiva ? 'is-active-tech' : ''}`}
                  onClick={() => selecionarTecnologiaNoFeed(tech.nome)}
                  role="button"
                  tabIndex={0}
                  title={`Filtrar feed por ${tech.nome} (ou clique em Chains para ver cadeias de ataque)`}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault()
                      selecionarTecnologiaNoFeed(tech.nome)
                    }
                  }}
                >
                  <div className="tech-ranking-info">
                    <span className="tech-ranking-name">
                      {tech.nome}
                    </span>
                    <div className="tech-ranking-right">
                      <button
                        type="button"
                        className="tech-chain-tag"
                        onClick={(e) => {
                          e.stopPropagation()
                          abrirModalPorEcossistema(tech.nome)
                        }}
                        title={`Abrir Exploit Chains de ${tech.nome}`}
                      >
                        Chains
                      </button>
                      <span className="tech-ranking-count" style={{ color: tech.cor }}>
                        {tech.total.toLocaleString('pt-BR')} CVEs
                      </span>
                    </div>
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
            ref={searchInputRef}
            type="text"
            className="terminal-input"
            placeholder="Full-Text Search: digite termo técnico (ex: Remote Code Execution, Buffer Overflow, Apache, Windows)..."
            value={termoBusca}
            onChange={(e) => {
              setTermoBusca(e.target.value)
              setPaginaAtual(1)
            }}
            onKeyDown={(e) => {
              if (e.key === 'Escape') {
                if (termoBusca) {
                  setTermoBusca('')
                  setDebouncedBusca('')
                  setPaginaAtual(1)
                } else {
                  e.currentTarget.blur()
                }
              }
            }}
          />
          {!termoBusca ? (
            <kbd className="terminal-kbd-hint" title="Atalho rápido: pressione / ou Ctrl+K para pesquisar">
              /
            </kbd>
          ) : (
            <button
              type="button"
              className="btn-clear-search"
              onClick={() => {
                setTermoBusca('')
                setDebouncedBusca('')
                setPaginaAtual(1)
              }}
              title="Limpar busca (ESC)"
            >
              &times;
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
            <button
              type="button"
              className={`filter-pill pill-kev ${filtroKev ? 'active' : ''}`}
              onClick={() => {
                setFiltroKev((prev) => !prev)
                setPaginaAtual(1)
              }}
              title="Filtrar vulnerabilidades exploradas ativamente no mundo real (Catálogo CISA KEV)"
            >
              CISA KEV
              {analyticsData.stats?.cisa_kev_total !== undefined && (
                <span className="pill-count">
                  {Number(analyticsData.stats.cisa_kev_total).toLocaleString('pt-BR')}
                </span>
              )}
            </button>
            <button
              type="button"
              className={`filter-pill pill-epss ${filtroEpssAlto ? 'active' : ''}`}
              onClick={() => {
                setFiltroEpssAlto((prev) => !prev)
                setPaginaAtual(1)
              }}
              title="Filtrar vulnerabilidades com probabilidade EPSS ≥ 10% nos próximos 30 dias (FIRST.org)"
            >
              EPSS &ge; 10%
              {Number(analyticsData.stats?.epss_alto_total) > 0 && (
                <span className="pill-count">
                  {Number(analyticsData.stats.epss_alto_total).toLocaleString('pt-BR')}
                </span>
              )}
            </button>
          </div>

          <div className="filter-right-controls">
            <div className="sort-selector-group">
              <label htmlFor="soc-sort-select" className="sort-selector-label">ORDEM:</label>
              <select
                id="soc-sort-select"
                className="soc-sort-select"
                value={ordenacao}
                onChange={(e) => {
                  setOrdenacao(e.target.value)
                  setPaginaAtual(1)
                }}
              >
                <option value="cvss_desc">Maior Risco (CVSS)</option>
                <option value="epss_desc">Maior Probab. (EPSS)</option>
                <option value="kev_first">CISA KEV Primeiro</option>
                <option value="recent">Mais Recentes (NIST)</option>
              </select>
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
        </div>

        {(clustersData.primitivas?.length > 0 || clustersData.clusters?.length > 0 || temFiltroAtivo) && (
          <div className="ml-clusters-bar">
            {filtroTecnologia !== 'TODOS' && (
              <div className="ml-clusters-row">
                <span className="ml-clusters-label">ECOSSISTEMA:</span>
                <div className="ml-clusters-group">
                  <button
                    type="button"
                    className="cluster-chip chip-tech-active active"
                    onClick={() => {
                      setFiltroTecnologia('TODOS')
                      setPaginaAtual(1)
                    }}
                    title="Remover filtro de tecnologia"
                  >
                    <span>{filtroTecnologia}</span>
                    <span>✕</span>
                  </button>
                </div>
              </div>
            )}
            {clustersData.primitivas?.length > 0 && (
              <div className="ml-clusters-row">
                <span className="ml-clusters-label">KILL CHAIN:</span>
                <div className="ml-clusters-group">
                  {clustersData.primitivas.slice(0, 6).map((item) => {
                    const ativo = filtroPrimitiva === item.primitiva
                    return (
                      <button
                        key={item.primitiva}
                        type="button"
                        className={`cluster-chip chip-primitive ${ativo ? 'active' : ''}`}
                        onClick={() => {
                          setFiltroPrimitiva(ativo ? 'TODOS' : item.primitiva)
                          setPaginaAtual(1)
                        }}
                      >
                        <span>{item.primitiva}</span>
                        <span className="cluster-chip-count">({Number(item.total).toLocaleString('pt-BR')})</span>
                      </button>
                    )
                  })}

                  {!(clustersData.clusters?.length > 0) && temFiltroAtivo && (
                    <button
                      type="button"
                      className="btn-reset-ml-filters"
                      onClick={limparTodosFiltros}
                    >
                      ✕ Limpar Filtros
                    </button>
                  )}
                </div>
              </div>
            )}

            {clustersData.clusters?.length > 0 ? (
              <div className="ml-clusters-row">
                <span className="ml-clusters-label">ML CLUSTERS:</span>
                <div className="ml-clusters-group">
                  {clustersData.clusters.slice(0, 6).map((c) => {
                    const ativo = filtroCluster === c.cluster_label
                    return (
                      <button
                        key={c.cluster_label}
                        type="button"
                        className={`cluster-chip ${ativo ? 'active' : ''}`}
                        onClick={() => {
                          setFiltroCluster(ativo ? 'TODOS' : c.cluster_label)
                          setPaginaAtual(1)
                        }}
                      >
                        <span>{c.cluster_label}</span>
                        <span className="cluster-chip-count">({Number(c.total).toLocaleString('pt-BR')})</span>
                      </button>
                    )
                  })}

                  {temFiltroAtivo && (
                    <button
                      type="button"
                      className="btn-reset-ml-filters"
                      onClick={limparTodosFiltros}
                    >
                      ✕ Limpar Filtros
                    </button>
                  )}
                </div>
              </div>
            ) : (
              !(clustersData.primitivas?.length > 0) && temFiltroAtivo && (
                <div className="ml-clusters-row">
                  <div className="ml-clusters-group">
                    <button
                      type="button"
                      className="btn-reset-ml-filters"
                      onClick={limparTodosFiltros}
                    >
                      ✕ Limpar Filtros
                    </button>
                  </div>
                </div>
              )
            )}
          </div>
        )}
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

          {/* Ações Rápidas de Exportação, Visualização e Paginação no Topo */}
          {totalRegistros > 0 && (
            <div className="section-header-actions">
              <div className="export-actions-group">
                <button
                  type="button"
                  className="btn-export-feed"
                  onClick={exportarFeedCsv}
                  disabled={!ameacas.length}
                  title="Exportar página atual em CSV (protegido contra Formula Injection)"
                >
                  ⬇ CSV
                </button>
                <button
                  type="button"
                  className="btn-export-feed"
                  onClick={exportarFeedJson}
                  disabled={!ameacas.length}
                  title="Exportar página atual em JSON estruturado"
                >
                  ⬇ JSON
                </button>
              </div>
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

        <div className={`table-responsive ${carregandoTabela && ameacas.length > 0 ? 'is-fetching' : ''}`}>
          {carregandoTabela && ameacas.length > 0 && (
            <div className="table-loading-bar" aria-hidden="true" />
          )}
          <table className="soc-table">
            <thead>
              <tr>
                <th>IDENTIFICADOR</th>
                <th
                  className="sortable"
                  onClick={() => alternarOrdenacaoColuna(ordenacao === 'cvss_desc' ? 'epss_desc' : 'cvss_desc')}
                  title="Clique para alternar ordenação entre Maior CVSS e Maior Probabilidade EPSS"
                >
                  SCORE CVSS
                  {(ordenacao === 'cvss_desc' || ordenacao === 'epss_desc') && (
                    <span className="sort-icon">{ordenacao === 'epss_desc' ? '⚡' : '▼'}</span>
                  )}
                </th>
                <th
                  className="sortable"
                  onClick={() => alternarOrdenacaoColuna('kev_first')}
                  title="Clique para priorizar vulnerabilidades exploradas ativamente (CISA KEV)"
                >
                  SEVERIDADE
                  {ordenacao === 'kev_first' && <span className="sort-icon">▼</span>}
                </th>
                <th>DESCRIÇÃO TÉCNICA</th>
                <th
                  className="sortable"
                  onClick={() => alternarOrdenacaoColuna('recent')}
                  title="Clique para ordenar pelas vulnerabilidades mais recentes (NIST NVD)"
                >
                  PUBLICAÇÃO NIST
                  {ordenacao === 'recent' && <span className="sort-icon">▼</span>}
                </th>
              </tr>
            </thead>
            <tbody>
              {ameacas.length > 0 ? (
                ameacas.map((item) => {
                  const isExpanded = !!expandedCves[item.cve_id]
                  const chainRelacionada = cveParaChainMap.get(item.cve_id) || null
                  const mitreItem = obterMitrePasso(item)
                  const cweValido = Boolean(item.cwe && item.cwe !== 'NVD-CWE-noinfo' && item.cwe !== 'NVD-CWE-Other')
                  const cweUrl = cweValido ? obterUrlMitreCwe(item.cwe) : null
                  const epssPct = formatarEpssPercent(item.epss_score)
                  const epssPercentilFmt =
                    Number(item.epss_percentile) > 0
                      ? ` (Percentil ${(Number(item.epss_percentile) * 100).toFixed(1)}%)`
                      : ''
                  const copiadoEste = copiadoCveId === item.cve_id

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
                            className={`btn-copy-cve-inline ${copiadoEste ? 'is-copied' : ''}`}
                            onClick={(e) => copiarIdCve(e, item.cve_id)}
                            title={copiadoEste ? 'ID copiado!' : `Copiar ${item.cve_id}`}
                            aria-label={`Copiar ${item.cve_id}`}
                          >
                            {copiadoEste ? '✓' : '⎘'}
                          </button>
                          <span className="desktop-row-chevron" aria-hidden="true">
                            {isExpanded ? '▴' : '▾'}
                          </span>
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
                      <td className="cve-desc-cell" title={isExpanded ? undefined : item.descricao}>
                        <div className="cve-desc-body">
                          {item.descricao}
                        </div>
                        {(
                          item.cisa_kev ||
                          epssPct ||
                          cweValido ||
                          (item.primitiva && item.primitiva !== 'GENERIC_VULN') ||
                          (item.cluster_label && item.cluster_label !== 'Geral / Não Clusterizado') ||
                          (item.tecnologia && item.tecnologia !== 'Desconhecido / Geral') ||
                          chainRelacionada
                        ) && (
                          <div className="cve-ml-tags">
                            {item.cisa_kev && (
                              <button
                                type="button"
                                className={`cve-kev-tag tag-interactive ${filtroKev ? 'is-tag-active' : ''}`}
                                onClick={(e) => {
                                  e.stopPropagation()
                                  setFiltroKev((prev) => !prev)
                                  setPaginaAtual(1)
                                }}
                                title="Confirmada no catálogo CISA KEV (Explorada Ativamente) — clique para filtrar por KEV"
                              >
                                CISA KEV
                              </button>
                            )}
                            {epssPct && (
                              <button
                                type="button"
                                className={`cve-epss-tag tag-interactive ${Number(item.epss_score) >= 0.1 ? 'is-high-epss' : ''} ${filtroEpssAlto ? 'is-tag-active' : ''}`}
                                onClick={(e) => {
                                  e.stopPropagation()
                                  setFiltroEpssAlto((prev) => !prev)
                                  setPaginaAtual(1)
                                }}
                                title={`Probabilidade EPSS FIRST.org em 30 dias: ${epssPct}${epssPercentilFmt} — clique para filtrar EPSS ≥ 10%`}
                              >
                                EPSS {epssPct}
                              </button>
                            )}
                            {cweValido && (
                              <button
                                type="button"
                                className="cve-cwe-tag tag-interactive"
                                onClick={(e) => {
                                  e.stopPropagation()
                                  const proximo = termoBusca.trim().toUpperCase() === String(item.cwe).toUpperCase() ? '' : item.cwe
                                  setTermoBusca(proximo)
                                  setDebouncedBusca(proximo)
                                  setPaginaAtual(1)
                                }}
                                title={`Filtrar catálogo por ${item.cwe}`}
                              >
                                {item.cwe}
                              </button>
                            )}
                            {item.primitiva && item.primitiva !== 'GENERIC_VULN' && (
                              <button
                                type="button"
                                className={`cve-primitive-tag tag-interactive primitive-${String(item.primitiva).toLowerCase()} ${filtroPrimitiva === item.primitiva ? 'is-tag-active' : ''}`}
                                onClick={(e) => {
                                  e.stopPropagation()
                                  setFiltroPrimitiva((prev) => (prev === item.primitiva ? 'TODOS' : item.primitiva))
                                  setPaginaAtual(1)
                                }}
                                title={`Filtrar Kill Chain por ${item.primitiva}`}
                              >
                                {item.primitiva}
                              </button>
                            )}
                            {item.cluster_label && item.cluster_label !== 'Geral / Não Clusterizado' && (
                              <button
                                type="button"
                                className={`cve-cluster-tag tag-interactive ${filtroCluster === item.cluster_label ? 'is-tag-active' : ''}`}
                                onClick={(e) => {
                                  e.stopPropagation()
                                  setFiltroCluster((prev) => (prev === item.cluster_label ? 'TODOS' : item.cluster_label))
                                  setPaginaAtual(1)
                                }}
                                title={`Filtrar ML Cluster: ${item.cluster_label}`}
                              >
                                {item.cluster_label}
                              </button>
                            )}
                            {item.tecnologia && item.tecnologia !== 'Desconhecido / Geral' && (
                              <button
                                type="button"
                                className={`cve-tech-tag tag-interactive ${filtroTecnologia === item.tecnologia ? 'is-tag-active' : ''}`}
                                onClick={(e) => {
                                  e.stopPropagation()
                                  setFiltroTecnologia((prev) => (prev === item.tecnologia ? 'TODOS' : item.tecnologia))
                                  setPaginaAtual(1)
                                }}
                                title={`Filtrar ecossistema: ${item.tecnologia}`}
                              >
                                {item.tecnologia}
                              </button>
                            )}
                            {chainRelacionada && (
                              <button
                                type="button"
                                className="cve-chain-tag tag-interactive"
                                onClick={(e) => {
                                  e.stopPropagation()
                                  abrirChainEspecifica(chainRelacionada)
                                }}
                                title={`Esta vulnerabilidade compõe a Exploit Chain #${chainRelacionada.chain_id} — clique para abrir o Attack Blueprint`}
                              >
                                ⚡ CHAIN #{chainRelacionada.chain_id}
                              </button>
                            )}
                          </div>
                        )}
                        <div className="cve-expanded-actions">
                          <button
                            type="button"
                            className={`btn-action-secondary ${copiadoEste ? 'is-copied' : ''}`}
                            onClick={(e) => copiarIdCve(e, item.cve_id)}
                          >
                            <span>{copiadoEste ? '✓ ID Copiado' : `⎘ Copiar ${item.cve_id}`}</span>
                          </button>
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(item.cve_id)}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="btn-nvd-action"
                            onClick={(e) => e.stopPropagation()}
                          >
                            <span>NIST NVD</span>
                            <span>↗</span>
                          </a>
                          <a
                            href={obterUrlMitreTechnique(mitreItem.technique_id)}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="btn-action-secondary btn-mitre-action"
                            title={`MITRE ATT&CK ${mitreItem.tactic_id} (${mitreItem.tactic}) — ${mitreItem.technique}`}
                            onClick={(e) => e.stopPropagation()}
                          >
                            <span>MITRE {mitreItem.technique_id}</span>
                            <span>↗</span>
                          </a>
                          {cweUrl && (
                            <a
                              href={cweUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="btn-action-secondary"
                              title={`Definição oficial ${item.cwe} no MITRE`}
                              onClick={(e) => e.stopPropagation()}
                            >
                              <span>{item.cwe}</span>
                              <span>↗</span>
                            </a>
                          )}
                          {chainRelacionada && (
                            <button
                              type="button"
                              className="btn-action-secondary btn-chain-action"
                              onClick={(e) => {
                                e.stopPropagation()
                                abrirChainEspecifica(chainRelacionada)
                              }}
                            >
                              <span>⚡ Blueprint #{chainRelacionada.chain_id}</span>
                            </button>
                          )}
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
                        {carregandoTabela ? '[...]' : '[!]'}
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
                      {!carregandoTabela && temFiltroAtivo && (
                        <button
                          type="button"
                          className="btn-empty-reset"
                          onClick={limparTodosFiltros}
                        >
                          ✕ Limpar Filtros Ativos
                        </button>
                      )}
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
        <div className="footer-sync-group">
          {ultimaAtualizacao && (
            <span>
              SINCRONIZAÇÃO: <span style={{ color: 'var(--neon-green)' }}>{ultimaAtualizacao}</span>
            </span>
          )}
          <button
            type="button"
            className="btn-footer-sync"
            onClick={forcarSincronizacao}
            disabled={sincronizandoNuvem}
            title="Forçar ressincronização imediata com a API e banco PostgreSQL"
          >
            {sincronizandoNuvem ? '↻ Sincronizando...' : '↻ Atualizar'}
          </button>
        </div>
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

      {/* --------------------------------------------------------------------
          8. MODAL DE EXPLOIT CHAINS & WRITEUP BLUEPRINTS (IA & NETWORKX)
          -------------------------------------------------------------------- */}
      {modalChainsAberto && (
        <div
          className="chains-modal-overlay"
          onClick={() => setModalChainsAberto(false)}
          role="dialog"
          aria-modal="true"
          aria-label="Exploit Chains e Attack Blueprints"
        >
          <div
            className="chains-modal-content"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Cabeçalho Executivo com Mini-KPIs */}
            <div className="chains-modal-header">
              <div className="chains-modal-title-group">
                <div className="modal-badge-row">
                  <span className="modal-live-dot" />
                  <span className="modal-prefix">&gt;_ GRAPH INTELLIGENCE ENGINE</span>
                  <span className="modal-engine-tag">NETWORKX + CPE 2.3</span>
                </div>
                <h2 className="chains-modal-title">
                  EXPLOIT CHAINS &amp; ATTACK BLUEPRINTS
                </h2>
                <span className="chains-modal-subtitle">
                  Cadeias multi-estágio correlacionadas por compatibilidade de ativo, transição tática e exploração ativa
                </span>
              </div>

              <div className="chains-header-right">
                <div className="chains-kpi-strip">
                  <div className="chains-mini-kpi">
                    <span className="mini-kpi-val">{exploitChains.length}</span>
                    <span className="mini-kpi-lbl">Cadeias</span>
                  </div>
                  <div className="chains-mini-kpi is-critical">
                    <span className="mini-kpi-val">{totalChainsCriticas}</span>
                    <span className="mini-kpi-lbl">Críticas</span>
                  </div>
                  <div className="chains-mini-kpi is-kev">
                    <span className="mini-kpi-val">{totalChainsKev}</span>
                    <span className="mini-kpi-lbl">CISA KEV</span>
                  </div>
                  <div className="chains-mini-kpi is-eco">
                    <span className="mini-kpi-val">{ecossistemasDisponiveis.length}</span>
                    <span className="mini-kpi-lbl">Alvos</span>
                  </div>
                </div>

                <button
                  type="button"
                  className="btn-close-modal"
                  onClick={() => setModalChainsAberto(false)}
                  title="Fechar janela (ESC)"
                >
                  <span className="close-esc-hint">ESC</span>
                  <span>✕</span>
                </button>
              </div>
            </div>

            {/* Barra Unificada de Busca Rápida e Filtros por Ecossistema */}
            <div className="chains-toolbar">
              <div className="chains-toolbar-top">
                <div className="chains-search-box">
                  <span className="chains-search-prompt">&gt;_</span>
                  <input
                    type="text"
                    className="chains-search-input"
                    placeholder="Filtrar cadeias por CVE, MITRE (ex: T1190), ecossistema, CWE ou primitiva..."
                    value={buscaChain}
                    onChange={(e) => setBuscaChain(e.target.value)}
                  />
                  {buscaChain && (
                    <button
                      type="button"
                      className="chains-search-clear"
                      onClick={() => setBuscaChain('')}
                      title="Limpar filtro de texto"
                    >
                      &times;
                    </button>
                  )}
                </div>

                <div className="chains-toolbar-actions">
                  {totalChainsKev > 0 && (
                    <button
                      type="button"
                      className={`eco-filter-btn eco-filter-kev ${filtroKevChain ? 'active' : ''}`}
                      onClick={() => {
                        setFiltroKevChain((prev) => !prev)
                        setCopiadoWriteup(false)
                      }}
                      title="Exibir apenas cadeias com vulnerabilidades confirmadas no CISA KEV"
                    >
                      <span className="kev-dot" />
                      <span>CISA KEV</span>
                      <span className="eco-pill-count">{totalChainsKev}</span>
                    </button>
                  )}

                  {(filtroEcoChain !== 'TODOS' || filtroKevChain || buscaChain.trim()) && (
                    <button
                      type="button"
                      className="btn-clear-chain-filters"
                      onClick={resetarFiltrosModalChains}
                    >
                      ✕ Limpar
                    </button>
                  )}
                </div>
              </div>

              <div className="modal-eco-filters">
                <button
                  type="button"
                  className={`eco-filter-btn ${filtroEcoChain === 'TODOS' ? 'active' : ''}`}
                  onClick={() => selecionarEcoNoModal('TODOS')}
                >
                  <span>Todos</span>
                  <span className="eco-pill-count">{exploitChains.length}</span>
                </button>
                {ecossistemasDisponiveis.map((eco) => {
                  const count = exploitChains.filter((c) => correspondeEcossistema(c.tecnologia, eco)).length
                  return (
                    <button
                      key={eco}
                      type="button"
                      className={`eco-filter-btn ${correspondeEcossistema(filtroEcoChain, eco) ? 'active' : ''}`}
                      onClick={() => selecionarEcoNoModal(eco)}
                    >
                      <span>{eco}</span>
                      <span className="eco-pill-count">{count}</span>
                    </button>
                  )
                })}
              </div>
            </div>

            {/* Corpo do Modal em Split-View com Scrolls Independentes */}
            <div className="chains-modal-body">
              {/* Coluna Esquerda: Catálogo de Cadeias */}
              <aside className="chains-sidebar-list" aria-label="Lista de cadeias correlacionadas">
                <div className="sidebar-list-header">
                  <span className="sidebar-list-title">CADEIAS CORRELACIONADAS</span>
                  <span className="sidebar-list-counter">
                    {chainsFiltradas.length} / {exploitChains.length}
                  </span>
                </div>

                <div className="chains-sidebar-cards">
                  {chainsFiltradas.length > 0 ? (
                    chainsFiltradas.map((chain) => {
                      const isSelected = activeChain && activeChain.chain_id === chain.chain_id
                      const temKev = chainTemKev(chain)
                      const isCritical = chain.severidade === 'CRITICAL'
                      const elosTotal = chain.writeup?.elos_count || (chain.cves ? chain.cves.length : 0)
                      const scoreNum = Number(chain.score_cvss || 10.0)

                      return (
                        <div
                          key={chain.chain_id}
                          className={`chain-sidebar-card ${isSelected ? 'is-selected' : ''} ${isCritical ? 'sev-critical' : 'sev-high'}`}
                          onClick={() => selecionarChainCard(chain.chain_id)}
                          role="button"
                          tabIndex={0}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter' || e.key === ' ') {
                              e.preventDefault()
                              selecionarChainCard(chain.chain_id)
                            }
                          }}
                        >
                          <div className="chain-card-header">
                            <div className="chain-card-badges-left">
                              <span className="chain-card-id">#{chain.chain_id}</span>
                              <span className={`chain-card-badge ${isCritical ? 'badge-critical' : 'badge-high'}`}>
                                {chain.severidade}
                              </span>
                              {temKev && (
                                <span className="chain-kev-mini" title="Contém CVE confirmada no catálogo CISA KEV">
                                  KEV
                                </span>
                              )}
                            </div>
                            <span className={`chain-card-score ${isCritical ? 'is-critical' : 'is-high'}`}>
                              {scoreNum.toFixed(1)}
                            </span>
                          </div>

                          <div className="chain-card-tech-row">
                            <span className="chain-card-tech">{chain.tecnologia}</span>
                            {elosTotal > 0 && (
                              <span className="chain-elos-mini">{elosTotal} elos</span>
                            )}
                          </div>

                          <div className="chain-card-cve-pills">
                            {(chain.cves || []).map((cveId, cIdx) => (
                              <Fragment key={`${chain.chain_id}-${cveId}-${cIdx}`}>
                                <span className="sidebar-cve-chip">{cveId}</span>
                                {cIdx < (chain.cves?.length || 0) - 1 && (
                                  <span className="sidebar-cve-arrow">→</span>
                                )}
                              </Fragment>
                            ))}
                          </div>
                        </div>
                      )
                    })
                  ) : (
                    <div className="chains-empty-sidebar">
                      <div className="empty-sidebar-icon">[!]</div>
                      <p>Nenhuma cadeia corresponde aos filtros aplicados.</p>
                      <button
                        type="button"
                        className="btn-reset-chain-filter"
                        onClick={resetarFiltrosModalChains}
                      >
                        Restaurar todas ({exploitChains.length})
                      </button>
                    </div>
                  )}
                </div>
              </aside>

              {/* Coluna Direita: Attack Blueprint Detalhado */}
              <div className="chains-detail-panel" ref={detailPanelRef}>
                {activeChain && activeBlueprintMeta ? (
                  <div className="writeup-blueprint-container">
                    {/* 1. Hero Card do Blueprint */}
                    <div className="writeup-hero-card">
                      <div className="writeup-top-bar">
                        <div className="writeup-meta-tags">
                          <span className="writeup-label">ATTACK BLUEPRINT</span>
                          <span className="writeup-chain-id">{activeChain.chain_id}</span>
                          <span className="writeup-target-tag">{activeChain.tecnologia}</span>
                          <span className="writeup-elos-tag">
                            {activeChain.writeup.elos_count || activeBlueprintMeta.passos.length} Elos Encadeados
                          </span>
                          {activeBlueprintMeta.maxEpssFmt && (
                            <span
                              className="writeup-epss-tag"
                              title="Maior probabilidade EPSS (FIRST.org) entre os elos da cadeia"
                            >
                              EPSS MÁX {activeBlueprintMeta.maxEpssFmt}
                            </span>
                          )}
                          {activeBlueprintMeta.temKevAtivo && (
                            <span className="writeup-kev-alert">CISA KEV ACTIVE</span>
                          )}
                        </div>

                        <div className="writeup-actions-group">
                          <button
                            type="button"
                            className="btn-export-chain-json"
                            onClick={() => exportarChainJson(activeChain)}
                            title="Baixar Attack Blueprint completo em JSON estruturado (STIX-friendly / SIEM)"
                          >
                            ⬇ JSON
                          </button>
                          <button
                            type="button"
                            className={`btn-copy-writeup ${copiadoWriteup ? 'is-copied' : ''}`}
                            onClick={() => copiarWriteupMarkdown(activeChain)}
                            title="Copiar relatório técnico em Markdown para Jira / Slack / TheHive"
                          >
                            {copiadoWriteup ? '✓ Markdown Copiado' : '⎘ Exportar Markdown'}
                          </button>
                        </div>
                      </div>

                      <div className="writeup-header">
                        <div className="writeup-title-block">
                          <h3 className="writeup-title">
                            {limparTituloBlueprint(activeChain.writeup.titulo)}
                          </h3>
                          <p className="writeup-summary">{activeBlueprintMeta.textoPrincipal}</p>

                          {activeBlueprintMeta.alertaSoc && (
                            <div className="writeup-soc-callout">
                              <span className="soc-callout-badge">ALERTA SOC</span>
                              <span className="soc-callout-text">{activeBlueprintMeta.alertaSoc}</span>
                            </div>
                          )}
                        </div>

                        <div className={`writeup-score-block ${activeBlueprintMeta.isHigh ? 'is-high' : ''}`}>
                          <span className="writeup-score-title">SCORE COMPOSTO</span>
                          <div className="writeup-score-main">
                            <span className="writeup-score-number">{activeBlueprintMeta.scoreVal.toFixed(1)}</span>
                            <span className="writeup-score-max">/10</span>
                          </div>
                          <div className="writeup-score-meter">
                            <div
                              className="writeup-score-meter-fill"
                              style={{ width: `${activeBlueprintMeta.scorePct}%` }}
                            />
                          </div>
                          <span className="writeup-score-sub">{activeChain.severidade} RISK</span>
                        </div>
                      </div>
                    </div>

                    {/* 2. Topologia Visual da Kill Chain */}
                    {activeBlueprintMeta.passos.length > 0 && (
                      <div className="killchain-topology-box">
                        <div className="blueprint-section-title">
                          <span className="section-dot dot-purple" />
                          <span>TOPOLOGIA DA CADEIA DE EXPLORAÇÃO</span>
                        </div>

                        <div className="killchain-topology-track">
                          {activeBlueprintMeta.passos.map((passo, idx) => {
                            const mitreTopo = obterMitrePasso(passo)
                            return (
                              <Fragment key={`topo-${passo.cve_id}-${idx}`}>
                                <div
                                  className={`topology-node topology-node-clickable primitive-border-${String(passo.primitiva || '').toLowerCase()} ${highlightedStepIdx === idx ? 'is-node-active' : ''}`}
                                  onClick={() => focarPassoTimeline(idx)}
                                  role="button"
                                  tabIndex={0}
                                  title={`Ir para detalhes táticos do Elo 0${passo.passo || idx + 1} (${passo.cve_id})`}
                                  onKeyDown={(e) => {
                                    if (e.key === 'Enter' || e.key === ' ') {
                                      e.preventDefault()
                                      focarPassoTimeline(idx)
                                    }
                                  }}
                                >
                                  <div className="topology-node-top">
                                    <span className="topology-step-num">ELO 0{passo.passo || idx + 1}</span>
                                    <div className="topology-top-pills">
                                      <span className="topology-mitre-id" title={`${mitreTopo.tactic}: ${mitreTopo.technique}`}>
                                        {mitreTopo.technique_id}
                                      </span>
                                      {Number(passo.nota_cvss) > 0 && (
                                        <span className={`topology-cvss ${getScoreClass(passo.nota_cvss)}`}>
                                          {Number(passo.nota_cvss).toFixed(1)}
                                        </span>
                                      )}
                                    </div>
                                  </div>
                                  <div className="topology-cve-id">{passo.cve_id}</div>
                                  <div className="topology-prim-row">
                                    <span className={`step-primitive-pill primitive-${String(passo.primitiva || '').toLowerCase()}`}>
                                      {formatarPrimitivaLabel(passo.primitiva)}
                                    </span>
                                    {passo.cisa_kev && (
                                      <span className="topology-kev-dot" title="CISA KEV">KEV</span>
                                    )}
                                  </div>
                                </div>

                                {idx < activeBlueprintMeta.passos.length - 1 && (
                                  <div className="topology-connector" aria-hidden="true">
                                    <span className="topology-connector-line" />
                                    <span className="topology-connector-arrow">▶</span>
                                  </div>
                                )}
                              </Fragment>
                            )
                          })}
                        </div>
                      </div>
                    )}

                    {/* 3. Timeline Tática Vertical Conectada */}
                    <div className="chain-timeline-section">
                      <div className="blueprint-section-title">
                        <span className="section-dot dot-cyan" />
                        <span>PROGRESSÃO TÁTICA PASSO A PASSO</span>
                      </div>

                      <div className="chain-timeline-list">
                        {activeBlueprintMeta.passos.map((passo, idx) => {
                          const ultimoPasso = idx === activeBlueprintMeta.passos.length - 1
                          const cweValido = passo.cwe && passo.cwe !== 'NVD-CWE-noinfo' && passo.cwe !== 'NVD-CWE-Other'
                          const cweStepUrl = cweValido ? obterUrlMitreCwe(passo.cwe) : null
                          const primSlug = String(passo.primitiva || '').toLowerCase()
                          const mitrePasso = obterMitrePasso(passo)
                          const epssPassoFmt = formatarEpssPercent(passo.epss_score)

                          return (
                            <div
                              key={`step-${passo.cve_id}-${idx}`}
                              id={`chain-step-${idx}`}
                              className="timeline-item"
                            >
                              <div className="timeline-rail" aria-hidden="true">
                                <span className={`timeline-node-badge ${passo.cisa_kev ? 'is-kev' : ''}`}>
                                  0{passo.passo || idx + 1}
                                </span>
                                {!ultimoPasso && <span className="timeline-rail-line" />}
                              </div>

                              <div className={`timeline-step-card primitive-accent-${primSlug} ${highlightedStepIdx === idx ? 'is-step-highlighted' : ''}`}>
                                <div className="step-card-top">
                                  <div className="step-card-meta-left">
                                    <span className="step-role-tag">
                                      {obterPapelPasso(idx, activeBlueprintMeta.passos.length)}
                                    </span>
                                    <a
                                      href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(passo.cve_id)}`}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="step-cve-link"
                                      title={`Consultar ${passo.cve_id} no NIST NVD`}
                                    >
                                      <span>{passo.cve_id}</span>
                                      <span>↗</span>
                                    </a>
                                    <span
                                      className={`step-primitive-pill primitive-${primSlug}`}
                                      title={passo.primitiva}
                                    >
                                      {formatarPrimitivaLabel(passo.primitiva)}
                                    </span>
                                    <a
                                      href={obterUrlMitreTechnique(mitrePasso.technique_id)}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="step-mitre-pill"
                                      title={`MITRE ATT&CK ${mitrePasso.tactic_id} (${mitrePasso.tactic}) — ${mitrePasso.technique_id}: ${mitrePasso.technique}`}
                                    >
                                      <span>{mitrePasso.technique_id} · {mitrePasso.tactic}</span>
                                      <span>↗</span>
                                    </a>
                                    {cweValido && (
                                      cweStepUrl ? (
                                        <a
                                          href={cweStepUrl}
                                          target="_blank"
                                          rel="noopener noreferrer"
                                          className="cve-cwe-tag cwe-link-tag"
                                          title={`Consultar definição oficial ${passo.cwe} no MITRE`}
                                        >
                                          <span>{passo.cwe}</span>
                                          <span>↗</span>
                                        </a>
                                      ) : (
                                        <span className="cve-cwe-tag">{passo.cwe}</span>
                                      )
                                    )}
                                    {epssPassoFmt && (
                                      <span
                                        className={`cve-epss-tag ${Number(passo.epss_score) >= 0.1 ? 'is-high-epss' : ''}`}
                                        title={`Probabilidade EPSS FIRST.org em 30 dias: ${epssPassoFmt}`}
                                      >
                                        EPSS {epssPassoFmt}
                                      </span>
                                    )}
                                    {passo.cisa_kev && (
                                      <span className="cve-kev-tag" title="Exploração ativa confirmada no catálogo CISA KEV">
                                        CISA KEV
                                      </span>
                                    )}
                                  </div>

                                  <div className="step-card-meta-right">
                                    {Number(passo.nota_cvss) > 0 && (
                                      <span className={`step-cvss-pill ${getScoreClass(passo.nota_cvss)}`}>
                                        CVSS {Number(passo.nota_cvss).toFixed(1)}
                                      </span>
                                    )}
                                    <button
                                      type="button"
                                      className="btn-step-feed"
                                      onClick={() => inspecionarCveNoFeed(passo.cve_id)}
                                      title={`Localizar ${passo.cve_id} na tabela principal`}
                                    >
                                      Ver no Feed →
                                    </button>
                                  </div>
                                </div>

                                <div className="step-action-text">{passo.acao}</div>
                                <div className="step-detail-text">{passo.detalhe}</div>
                              </div>
                            </div>
                          )
                        })}
                      </div>
                    </div>

                    {/* 4. Impacto Consolidado & Plano de Mitigação SOC */}
                    <div className="writeup-footer-grid">
                      <div className="writeup-impact-box">
                        <div className="footer-box-header">
                          <span className="section-dot dot-red" />
                          <span className="footer-box-title">IMPACTO TÉCNICO CONSOLIDADO</span>
                        </div>
                        <div className="footer-box-content">
                          {activeChain.writeup.impacto_tecnico}
                        </div>
                      </div>

                      <div className="writeup-mitigation-box">
                        <div className="footer-box-header">
                          <span className="section-dot dot-green" />
                          <span className="footer-box-title">PLANO DE MITIGAÇÃO RECOMENDADO (SOC)</span>
                        </div>
                        <ul className="footer-mitigation-list">
                          {(activeChain.writeup.mitigacoes_recomendadas || []).map((mit, i) => {
                            const isPrioridadeKev = String(mit).includes('CISA KEV')
                            return (
                              <li
                                key={i}
                                className={`mitigation-item ${isPrioridadeKev ? 'is-kev-priority' : ''}`}
                              >
                                <span className="mitigation-bullet" aria-hidden="true">
                                  {isPrioridadeKev ? '!' : '✓'}
                                </span>
                                <span>{mit}</span>
                              </li>
                            )
                          })}
                        </ul>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="no-chain-selected">
                    <div className="empty-sidebar-icon">[!]</div>
                    <p>Nenhuma cadeia selecionada ou disponível para os filtros atuais.</p>
                    {(filtroEcoChain !== 'TODOS' || filtroKevChain || buscaChain.trim()) && (
                      <button
                        type="button"
                        className="btn-reset-chain-filter"
                        onClick={resetarFiltrosModalChains}
                      >
                        Restaurar todas as cadeias ({exploitChains.length})
                      </button>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default App