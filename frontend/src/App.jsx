import { useState, useEffect } from 'react'
import axios from 'axios'
import './App.css' // mantem o css padrao do vite por enquanto

function App() {
  const [apiStatus, setApiStatus] = useState('verificando api node...')
  const [dbErro, setDbErro] = useState(false)
  const [estatisticas, setEstatisticas] = useState(null)

  useEffect(() => {
    // 1. testa se a ponte com o backend node esta funcionando
    axios.get('http://localhost:5001/api/health')
      .then(response => {
        setApiStatus(response.data.message)
      })
      .catch(() => {
        setApiStatus('api offline - verifique o terminal do node')
      })

    // 2. tenta buscar os dados do banco de dados relacional
    axios.get('http://localhost:5000/api/threats/stats')
      .then(response => {
        setEstatisticas(response.data)
        setDbErro(false)
      })
      .catch(() => {
        setDbErro(true)
      })
  }, [])

  return (
    <div className="dashboard-container" style={{ padding: '2rem', fontFamily: 'sans-serif' }}>
      <h1>Painel de Inteligência de Ameaças</h1>

      <div style={{ background: '#1e1e1e', color: '#fff', padding: '1rem', borderRadius: '8px', marginBottom: '2rem' }}>
        <h3>⚙️ Diagnóstico do Ecossistema</h3>
        <p><strong>Backend (Node.js):</strong> {apiStatus}</p>
        <p>
          <strong>Database (PostgreSQL):</strong>{' '}
          {dbErro ? (
            <span style={{ color: '#ff4444' }}>desconectado (aguardando ambiente cloud)</span>
          ) : (
            <span style={{ color: '#00cc66' }}>conectado e recebendo dados</span>
          )}
        </p>
      </div>

      <div style={{ border: '1px solid #ccc', padding: '1rem', borderRadius: '8px' }}>
        <h2>📊 Visão Geral (CVSS v3.x)</h2>

        {dbErro ? (
          <p style={{ color: '#666' }}>
            os graficos de severidade serao renderizados aqui assim que a arquitetura for plugada no google cloud gcp.
          </p>
        ) : (
          <p>dados carregados com sucesso! (preparando graficos...)</p>
        )}
      </div>
    </div>
  )
}

export default App