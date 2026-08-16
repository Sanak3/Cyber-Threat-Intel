
import { useState, useEffect } from 'react'
import axios from 'axios'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell
} from 'recharts'
import './App.css'

function App() {
  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5001';
  const [apiStatus, setApiStatus] = useState('Verificando API...')
  const [dbConectado, setDbConectado] = useState(false)
  const [estatisticas, setEstatisticas] = useState(null)
  const [ameacasCriticas, setAmeacasCriticas] = useState([])

useEffect(() => {
    // 1. Healthcheck da API
    axios.get(`${API_URL}/api/health`)
      .then(res => setApiStatus(res.data.message))
      .catch(() => setApiStatus('API Offline'))

    // 2. Estatísticas consolidadas para os gráficos
    axios.get(`${API_URL}/api/threats/stats`)
      .then(res => {
        setEstatisticas(res.data)
        setDbConectado(true)
      })
      .catch(() => setDbConectado(false))

    // 3. Lista das maiores ameaças
    axios.get(`${API_URL}/api/threats/critical`)
      .then(res => setAmeacasCriticas(res.data))
      .catch(err => console.error('Erro ao buscar críticas:', err))
  }, [API_URL])

  // Dados formatados para o gráfico de barras
  const dadosGrafico = estatisticas ? [
    { nome: 'Crítico', valor: Number(estatisticas.criticas) || 0, cor: '#dc2626' },
    { nome: 'Alto', valor: Number(estatisticas.altas) || 0, cor: '#ea580c' },
    { nome: 'Médio', valor: Number(estatisticas.medias) || 0, cor: '#ca8a04' },
    { nome: 'Baixo', valor: Number(estatisticas.baixas) || 0, cor: '#16a34a' }
  ] : []

  return (
    <div style={{ padding: '2rem', maxWidth: '1200px', margin: '0 auto', color: '#f8fafc', fontFamily: 'system-ui, sans-serif' }}>

      {/* Header */}
      <header style={{ marginBottom: '2rem', borderBottom: '1px solid #334155', paddingBottom: '1rem' }}>
        <h1 style={{ margin: 0, fontSize: '1.8rem' }}>🛡️ Cyber Threat Intelligence Dashboard</h1>
        <div style={{ display: 'flex', gap: '1.5rem', marginTop: '0.8rem', fontSize: '0.85rem' }}>
          <span>
            <strong>API Node.js:</strong>{' '}
            <span style={{ color: apiStatus.includes('sucesso') ? '#4ade80' : '#f87171' }}>{apiStatus}</span>
          </span>
          <span>
            <strong>AWS RDS:</strong>{' '}
            <span style={{ color: dbConectado ? '#4ade80' : '#f87171' }}>
              {dbConectado ? 'Conectado (PostgreSQL)' : 'Desconectado'}
            </span>
          </span>
        </div>
      </header>

      {/* Cards de Métricas (KPIs) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '2rem' }}>
        <div style={{ background: '#1e293b', padding: '1.2rem', borderRadius: '8px', border: '1px solid #334155' }}>
          <span style={{ fontSize: '0.85rem', color: '#94a3b8' }}>Total Coletado</span>
          <h2 style={{ margin: '0.4rem 0 0', fontSize: '1.8rem', color: '#38bdf8' }}>
            {estatisticas?.total_ameacas || 0}
          </h2>
        </div>

        <div style={{ background: '#1e293b', padding: '1.2rem', borderRadius: '8px', border: '1px solid #334155' }}>
          <span style={{ fontSize: '0.85rem', color: '#94a3b8' }}>Ameaças Críticas</span>
          <h2 style={{ margin: '0.4rem 0 0', fontSize: '1.8rem', color: '#f87171' }}>
            {estatisticas?.criticas || 0}
          </h2>
        </div>

        <div style={{ background: '#1e293b', padding: '1.2rem', borderRadius: '8px', border: '1px solid #334155' }}>
          <span style={{ fontSize: '0.85rem', color: '#94a3b8' }}>Ameaças Altas</span>
          <h2 style={{ margin: '0.4rem 0 0', fontSize: '1.8rem', color: '#fb923c' }}>
            {estatisticas?.altas || 0}
          </h2>
        </div>

        <div style={{ background: '#1e293b', padding: '1.2rem', borderRadius: '8px', border: '1px solid #334155' }}>
          <span style={{ fontSize: '0.85rem', color: '#94a3b8' }}>Pior CVSS Detectado</span>
          <h2 style={{ margin: '0.4rem 0 0', fontSize: '1.8rem', color: '#ef4444' }}>
            {estatisticas?.pior_risco || '0.0'}
          </h2>
        </div>
      </div>

      {/* Gráfico de Distribuição */}
      <div style={{ background: '#1e293b', padding: '1.5rem', borderRadius: '8px', border: '1px solid #334155', marginBottom: '2rem' }}>
        <h3 style={{ margin: '0 0 1.5rem', fontSize: '1.1rem' }}>Distribuição de Severidade (CVSS v3.x)</h3>
        <div style={{ width: '100%', height: 260 }}>
          <ResponsiveContainer>
            <BarChart data={dadosGrafico} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
              <XAxis dataKey="nome" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip contentStyle={{ background: '#0f172a', borderColor: '#334155', borderRadius: '6px' }} />
              <Bar dataKey="valor" radius={[4, 4, 0, 0]}>
                {dadosGrafico.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.cor} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Tabela de Ameaças Críticas */}
      <div style={{ background: '#1e293b', padding: '1.5rem', borderRadius: '8px', border: '1px solid #334155' }}>
        <h3 style={{ margin: '0 0 1rem', fontSize: '1.1rem' }}>Últimas Ameaças Críticas / Altas Registradas</h3>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.9rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #334155', color: '#94a3b8' }}>
                <th style={{ padding: '0.75rem' }}>CVE ID</th>
                <th style={{ padding: '0.75rem' }}>Score</th>
                <th style={{ padding: '0.75rem' }}>Severidade</th>
                <th style={{ padding: '0.75rem' }}>Descrição</th>
              </tr>
            </thead>
            <tbody>
              {ameacasCriticas.map((item) => (
                <tr key={item.cve_id} style={{ borderBottom: '1px solid #334155' }}>
                  <td style={{ padding: '0.75rem', fontWeight: 'bold' }}>
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${item.cve_id}`}
                      target="_blank"
                      rel="noreferrer"
                      style={{ color: '#38bdf8', textDecoration: 'none' }}
                    >
                      {item.cve_id}
                    </a>
                  </td>
                  <td style={{ padding: '0.75rem', fontWeight: 'bold', color: item.nota_cvss >= 9 ? '#f87171' : '#fb923c' }}>
                    {Number(item.nota_cvss).toFixed(1)}
                  </td>
                  <td style={{ padding: '0.75rem' }}>
                    <span style={{
                      padding: '0.2rem 0.6rem',
                      borderRadius: '4px',
                      fontSize: '0.75rem',
                      fontWeight: 'bold',
                      background: item.nota_cvss >= 9 ? 'rgba(239, 68, 68, 0.2)' : 'rgba(249, 115, 22, 0.2)',
                      color: item.nota_cvss >= 9 ? '#f87171' : '#fb923c',
                      border: `1px solid ${item.nota_cvss >= 9 ? '#ef4444' : '#f97316'}`
                    }}>
                      {item.severidade}
                    </span>
                  </td>
                  <td style={{ padding: '0.75rem', color: '#cbd5e1', maxWidth: '450px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {item.descricao}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  )
}

export default App