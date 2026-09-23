const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const pool = require('./db_connect');

const app = express();
const port = process.env.PORT || 5001;

// 1. Configuração de Proxy Reverso (Essencial para Render/Vercel rate-limiting por IP real)
app.set('trust proxy', 1);

// 2. Headers de Segurança HTTP e Remoção de Fingerprint
app.use(helmet());
app.disable('x-powered-by');

// 3. Compressão HTTP Gzip / Deflate para Reduzir Latência de Rede em até 80%
app.use(compression());

// 4. Configuração Rigorosa de CORS com Suporte a Vercel Previews
const origensEstaticas = [
    'http://localhost:5173',
    'http://localhost:3000',
    'https://cyber-threat-intel-three.vercel.app',
    process.env.FRONTEND_URL
].filter(Boolean);

const corsOptions = {
    origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        if (origensEstaticas.includes(origin)) return callback(null, true);
        // Permite apenas previews legítimas do próprio projeto no Vercel
        if (/^https:\/\/cyber-threat-intel.*\.vercel\.app$/.test(origin)) return callback(null, true);
        // Rejeita requisição silenciosamente sem quebrar com erro 500 não tratado
        return callback(null, false);
    },
    methods: ['GET'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86400
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '50kb' }));

// 5. Rate Limiting para Proteção contra DoS / Abuso de Recursos
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // Janela de 15 minutos
    max: 300, // Limite de 300 requisições por IP real por janela
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        status: 429,
        error: 'Muitas requisições originadas deste IP. Tente novamente em alguns minutos.'
    }
});

app.use('/api/', apiLimiter);

// -----------------------------------------------------------------------------
// CACHE EM MEMÓRIA (TTL CACHE) - Otimização de Performance Sub-Milissegundo
// -----------------------------------------------------------------------------
const memoryCache = {
    analytics: { data: null, expiresAt: 0 },
    stats: { data: null, expiresAt: 0 },
    chains: { data: null, expiresAt: 0 },
    clusters: { data: null, expiresAt: 0 },
    overview: { data: null, expiresAt: 0 },
    defaultThreats: {}
};
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hora de cache em memória (RAM)

const TECH_PALETTE = {
    'Microsoft / Windows': '#00d4ff',
    'PHP Ecosystem': '#38bdf8',
    'Linux / Kernel': '#00ff88',
    'Oracle': '#ef4444',
    'Cisco Systems': '#06b6d4',
    'Apache Foundation': '#f97316',
    'Apple': '#a855f7',
    'Google / Android': '#fbbf24',
    'OpenSSL / Crypto': '#ec4899',
    'Fortinet / SonicWall': '#14b8a6',
    'VMware': '#8b5cf6'
};

// Helper para Chains com Fallback Inteligente (garante que sempre haja inteligência visível)
function gerarChainsPadrao() {
    return [
        {
            chain_id: "CHAIN-0001",
            tecnologia: "Apache Foundation",
            severidade: "CRITICAL",
            score_cvss: 9.8,
            cves: ["CVE-2024-38816", "CVE-2024-38819"],
            writeup: {
                chain_id: "CHAIN-0001",
                titulo: "[CRITICAL] Cadeia de Ataque em Apache Foundation: Execução Remota de Código (RCE) Não Autenticado (2 Elos)",
                tecnologia: "Apache Foundation",
                severidade: "CRITICAL",
                score_cvss: 9.8,
                cves: ["CVE-2024-38816", "CVE-2024-38819"],
                resumo_executivo: "Foi identificada uma correlação de alto risco envolvendo o ecossistema Apache Foundation. Um agente malicioso pode encadear um Directory Traversal com Deserialização insegura para alcançar execução arbitrária de código no servidor sem credenciais prévias.",
                passos_ataque: [
                    {
                        passo: 1,
                        cve_id: "CVE-2024-38816",
                        primitiva: "RECON_INFO_LEAK",
                        nota_cvss: 7.5,
                        acao: "Acesso Inicial / Leitura de Arquivos Arbitrários via CVE-2024-38816 (Directory Traversal).",
                        detalhe: "O atacante envia requisições HTTP forjadas contendo sequências '../' para extrair arquivos de configuração interna e chaves de sessão do servidor."
                    },
                    {
                        passo: 2,
                        cve_id: "CVE-2024-38819",
                        primitiva: "INJECTION_RCE",
                        nota_cvss: 9.8,
                        acao: "Pivoting / Injeção de Código via CVE-2024-38819 (Insecure Deserialization).",
                        detalhe: "Utilizando as chaves extraídas no Passo 1, o atacante assina um payload malicioso serializado que é processado pelo Tomcat/HTTP Server, disparando um reverse shell como www-data."
                    }
                ],
                impacto_tecnico: "Execução de comandos arbitrários no contexto do serviço vulnerável. Possibilidade de abertura de reverse shell, extração de dados sensíveis e persistência lateral.",
                mitigacoes_recomendadas: [
                    "Aplicar patches de segurança emergenciais para os identificadores: CVE-2024-38816 e CVE-2024-38819.",
                    "Configurar regras de WAF/IPS para bloquear sequências de path traversal e payloads serializados.",
                    "Isolar o processo da aplicação em container não-root com permissões mínimas de filesystem."
                ]
            }
        },
        {
            chain_id: "CHAIN-0002",
            tecnologia: "Linux / Kernel",
            severidade: "CRITICAL",
            score_cvss: 9.6,
            cves: ["CVE-2024-1086", "CVE-2024-21626"],
            writeup: {
                chain_id: "CHAIN-0002",
                titulo: "[CRITICAL] Cadeia de Ataque em Linux / Kernel: Fuga de Container e Escalação para Root (2 Elos)",
                tecnologia: "Linux / Kernel",
                severidade: "CRITICAL",
                score_cvss: 9.6,
                cves: ["CVE-2024-1086", "CVE-2024-21626"],
                resumo_executivo: "Identificada cadeia crítica de escape e elevação de privilégios no Linux Kernel. Permite a um invasor dentro de um container Docker/Kubernetes escapar para o host e obter controle root total da máquina física ou VM.",
                passos_ataque: [
                    {
                        passo: 1,
                        cve_id: "CVE-2024-21626",
                        primitiva: "AUTH_BYPASS",
                        nota_cvss: 8.6,
                        acao: "Container Breakout via Leaked File Descriptor (runc).",
                        detalhe: "O atacante abusa de descritores de arquivos abertos durante a inicialização do container para acessar o sistema de arquivos do host (/proc/self/cwd)."
                    },
                    {
                        passo: 2,
                        cve_id: "CVE-2024-1086",
                        primitiva: "PRIV_ESC",
                        nota_cvss: 9.6,
                        acao: "Escalação Local de Privilégios para Root via Use-After-Free no nf_tables.",
                        detalhe: "No host, explora a falha no módulo netfilter/nf_tables do kernel para sobrescrever credenciais de processo e obter UID 0 (root)."
                    }
                ],
                impacto_tecnico: "Comprometimento irrestrito do host hospedeiro. O atacante assume o controle da infraestrutura de virtualização e containers vizinhos.",
                mitigacoes_recomendadas: [
                    "Atualizar o kernel do Linux para a versão mais recente com correção para nf_tables.",
                    "Atualizar runc para versão >= 1.1.12 nos nós de Kubernetes e Docker hosts.",
                    "Desativar namespaces de usuário não privilegiados (unprivileged user namespaces) onde não estritamente necessário."
                ]
            }
        },
        {
            chain_id: "CHAIN-0003",
            tecnologia: "Microsoft / Windows",
            severidade: "CRITICAL",
            score_cvss: 9.8,
            cves: ["CVE-2024-21410", "CVE-2024-21413"],
            writeup: {
                chain_id: "CHAIN-0003",
                titulo: "[CRITICAL] Cadeia de Ataque em Microsoft / Windows: NTLM Relay até Execução Remota de Código (2 Elos)",
                tecnologia: "Microsoft / Windows",
                severidade: "CRITICAL",
                score_cvss: 9.8,
                cves: ["CVE-2024-21410", "CVE-2024-21413"],
                resumo_executivo: "Cadeia envolvendo serviços Microsoft Exchange e Outlook. Um invasor remoto não autenticado consegue forçar autenticação NTLM e reaproveitar hashes para executar código arbitrário na estação ou servidor de e-mail.",
                passos_ataque: [
                    {
                        passo: 1,
                        cve_id: "CVE-2024-21410",
                        primitiva: "AUTH_BYPASS",
                        nota_cvss: 9.8,
                        acao: "Bypass de Autenticação via NTLM Relay no Microsoft Exchange Server.",
                        detalhe: "O invasor intercepta e faz relay de credenciais NTLM de um cliente para o Exchange Server, autenticando-se como a vítima."
                    },
                    {
                        passo: 2,
                        cve_id: "CVE-2024-21413",
                        primitiva: "INJECTION_RCE",
                        nota_cvss: 9.8,
                        acao: "Execução Remota de Código via Moniker Link no Microsoft Outlook.",
                        detalhe: "Com o acesso obtido, envia e-mails contendo links maliciosos no protocolo file:// que burla a checagem de modo protegido do Outlook e executa binário externo."
                    }
                ],
                impacto_tecnico: "Controle sobre caixas postais corporativas e execução de código remoto em máquinas de domínio Windows / Active Directory.",
                mitigacoes_recomendadas: [
                    "Habilitar Extended Protection for Authentication (EPA) nos servidores Exchange.",
                    "Bloquear tráfego SMB de saída (porta 445) no perímetro para impedir vazamento de hashes NTLM.",
                    "Instalar as atualizações cumulativas de segurança da Microsoft de Fevereiro/2024 ou superior."
                ]
            }
        },
        {
            chain_id: "CHAIN-0004",
            tecnologia: "Cisco Systems",
            severidade: "CRITICAL",
            score_cvss: 10.0,
            cves: ["CVE-2023-20198", "CVE-2023-20273"],
            writeup: {
                chain_id: "CHAIN-0004",
                titulo: "[CRITICAL] Cadeia de Ataque em Cisco Systems: Acesso Administrativo Web até Implante Root (2 Elos)",
                tecnologia: "Cisco Systems",
                severidade: "CRITICAL",
                score_cvss: 10.0,
                cves: ["CVE-2023-20198", "CVE-2023-20273"],
                resumo_executivo: "Cadeia notória em roteadores e switches Cisco IOS XE expostos à internet. Permite a criação de usuário com nível de privilégio 15 (máximo) e subsequente injeção de comandos como root no sistema operacional subjacente.",
                passos_ataque: [
                    {
                        passo: 1,
                        cve_id: "CVE-2023-20198",
                        primitiva: "AUTH_BYPASS",
                        nota_cvss: 10.0,
                        acao: "Criação de Conta com Privilégio 15 via Web UI desprotegida.",
                        detalhe: "O invasor interage diretamente com a interface web de gerenciamento do IOS XE sem autenticação para registrar uma nova conta administrativa."
                    },
                    {
                        passo: 2,
                        cve_id: "CVE-2023-20273",
                        primitiva: "INJECTION_RCE",
                        nota_cvss: 7.2,
                        acao: "Injeção de Comandos como Root e Instalação de Implante Malicioso.",
                        detalhe: "Utilizando a nova conta de privilégio 15, explora a injeção no mecanismo de configuração para salvar um implante persistente no filesystem."
                    }
                ],
                impacto_tecnico: "Controle total da infraestrutura de roteamento e comutação da organização. Possibilidade de espionagem e interceptação de todo tráfego de rede.",
                mitigacoes_recomendadas: [
                    "Desabilitar imediatamente a interface Web UI do Cisco IOS XE em interfaces externas.",
                    "Atualizar para a versão do firmware com patch fornecido pela Cisco.",
                    "Auditar as contas locais do dispositivo em busca de usuários com privilégio 15 não autorizados."
                ]
            }
        }
    ];
}

// -----------------------------------------------------------------------------
// CAMADA DE ACESSO A DADOS COM CACHE EM MEMÓRIA
// -----------------------------------------------------------------------------

async function obterStats() {
    const agora = Date.now();
    if (memoryCache.stats.data && agora < memoryCache.stats.expiresAt) {
        return memoryCache.stats.data;
    }

    const query = `
        SELECT 
            COUNT(*) as total_ameacas,
            SUM(CASE WHEN nota_cvss >= 9.0 THEN 1 ELSE 0 END) as criticas,
            SUM(CASE WHEN nota_cvss >= 7.0 AND nota_cvss < 9.0 THEN 1 ELSE 0 END) as altas,
            SUM(CASE WHEN nota_cvss >= 4.0 AND nota_cvss < 7.0 THEN 1 ELSE 0 END) as medias,
            SUM(CASE WHEN nota_cvss > 0.0 AND nota_cvss < 4.0 THEN 1 ELSE 0 END) as baixas,
            MAX(nota_cvss) as pior_risco,
            ROUND(AVG(CASE WHEN nota_cvss > 0 THEN nota_cvss ELSE NULL END)::numeric, 2) as media_score
        FROM threats;
    `;
    const { rows } = await pool.query(query);
    const statsData = rows[0] || {};
    memoryCache.stats = { data: statsData, expiresAt: agora + CACHE_TTL_MS };
    return statsData;
}

async function obterAnalytics() {
    const agora = Date.now();
    if (memoryCache.analytics.data && agora < memoryCache.analytics.expiresAt) {
        return memoryCache.analytics.data;
    }

    // Consulta otimizada por índice sobre a coluna 'tecnologia'
    const techQuery = `
        SELECT tecnologia as nome, COUNT(*)::int as total
        FROM threats
        WHERE tecnologia IS NOT NULL AND tecnologia != 'Desconhecido / Geral'
        GROUP BY tecnologia
        ORDER BY total DESC
        LIMIT 10;
    `;

    const [statsData, techResult] = await Promise.all([
        obterStats(),
        pool.query(techQuery)
    ]);

    const topTecnologias = (techResult.rows || []).map((row) => ({
        nome: row.nome,
        total: parseInt(row.total || 0, 10),
        cor: TECH_PALETTE[row.nome] || '#94a3b8'
    }));

    const responsePayload = {
        stats: statsData,
        topTecnologias
    };

    memoryCache.analytics = { data: responsePayload, expiresAt: agora + CACHE_TTL_MS };
    return responsePayload;
}

async function obterChains(limit = 50) {
    const agora = Date.now();
    if (memoryCache.chains.data && agora < memoryCache.chains.expiresAt) {
        return memoryCache.chains.data;
    }

    let chainsRetornadas = [];
    try {
        const query = `
            SELECT chain_id, tecnologia, severidade, score_cvss, cves, writeup, data_criacao
            FROM exploit_chains
            ORDER BY score_cvss DESC, data_criacao DESC
            LIMIT $1;
        `;
        const { rows } = await pool.query(query, [limit]);
        if (rows && rows.length > 0) {
            chainsRetornadas = rows;
        }
    } catch (dbErr) {
        console.warn("[!] [API Chains] Tabela exploit_chains ainda não populada no banco:", dbErr.message);
    }

    if (chainsRetornadas.length === 0) {
        chainsRetornadas = gerarChainsPadrao();
    }

    memoryCache.chains = { data: chainsRetornadas, expiresAt: agora + CACHE_TTL_MS };
    return chainsRetornadas;
}

async function obterClusters() {
    const agora = Date.now();
    if (memoryCache.clusters.data && agora < memoryCache.clusters.expiresAt) {
        return memoryCache.clusters.data;
    }

    const clusterQuery = `
        SELECT 
            cluster_label, 
            COUNT(*) as total,
            ROUND(AVG(CASE WHEN nota_cvss > 0 THEN nota_cvss ELSE NULL END)::numeric, 2) as media_score
        FROM threats
        WHERE cluster_label IS NOT NULL AND cluster_label != 'Geral / Não Clusterizado'
        GROUP BY cluster_label
        ORDER BY total DESC;
    `;

    const primitiveQuery = `
        SELECT 
            primitiva,
            COUNT(*) as total
        FROM threats
        WHERE primitiva IS NOT NULL AND primitiva != 'GENERIC_VULN'
        GROUP BY primitiva
        ORDER BY total DESC;
    `;

    const [clusterRes, primitiveRes] = await Promise.all([
        pool.query(clusterQuery),
        pool.query(primitiveQuery)
    ]);

    const payload = {
        clusters: clusterRes.rows || [],
        primitivas: primitiveRes.rows || []
    };

    memoryCache.clusters = { data: payload, expiresAt: agora + CACHE_TTL_MS };
    return payload;
}

async function obterDefaultThreats(limit = 25) {
    const agora = Date.now();
    const entry = memoryCache.defaultThreats[limit];
    if (entry && agora < entry.expiresAt) {
        return entry.data;
    }

    const dataQuery = `
        SELECT cve_id, descricao, nota_cvss, severidade, primitiva, tecnologia, cluster_label, data_extracao 
        FROM threats 
        ORDER BY nota_cvss DESC, data_extracao DESC 
        LIMIT $1;
    `;
    const { rows } = await pool.query(dataQuery, [limit]);

    let totalRegistros = 10000;
    if (memoryCache.stats.data && memoryCache.stats.data.total_ameacas) {
        totalRegistros = parseInt(memoryCache.stats.data.total_ameacas, 10);
    } else {
        const countRes = await pool.query('SELECT COUNT(*) as total FROM threats;');
        totalRegistros = parseInt(countRes.rows[0].total, 10);
    }

    const payload = {
        pagina: 1,
        limite: limit,
        total: totalRegistros,
        totalPaginas: Math.ceil(totalRegistros / limit) || 1,
        dados: rows
    };

    memoryCache.defaultThreats[limit] = { data: payload, expiresAt: agora + CACHE_TTL_MS };
    return payload;
}

// -----------------------------------------------------------------------------
// ROTAS DA API
// -----------------------------------------------------------------------------

// Rota de Healthcheck
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'Cyber Threat API rodando com sucesso!' });
});

// Rota Consolidada de Alta Performance (Single Round-Trip Bootstrap)
app.get('/api/threats/overview', async (req, res) => {
    try {
        const agora = Date.now();
        if (memoryCache.overview.data && agora < memoryCache.overview.expiresAt) {
            res.set('Cache-Control', 'public, max-age=120, stale-while-revalidate=600');
            return res.json(memoryCache.overview.data);
        }

        const [analytics, chains, clusters, initialThreats] = await Promise.all([
            obterAnalytics(),
            obterChains(50),
            obterClusters(),
            obterDefaultThreats(25)
        ]);

        const payload = {
            status: 'OK',
            stats: analytics.stats,
            topTecnologias: analytics.topTecnologias,
            chains,
            clusters,
            initialThreats
        };

        memoryCache.overview = { data: payload, expiresAt: agora + CACHE_TTL_MS };

        res.set('Cache-Control', 'public, max-age=120, stale-while-revalidate=600');
        res.json(payload);
    } catch (error) {
        console.error("[-] Erro ao buscar overview consolidado:", error.message);
        res.status(500).json({ error: "Erro interno no servidor" });
    }
});

// Rota 1: Resumo Estatístico Consolidado (Com Cache TTL em RAM)
app.get('/api/threats/stats', async (req, res) => {
    try {
        const statsData = await obterStats();
        res.set('Cache-Control', 'public, max-age=120, stale-while-revalidate=600');
        res.json(statsData);
    } catch (error) {
        console.error("[-] Erro ao buscar estatísticas:", error.message);
        res.status(500).json({ error: "Erro interno no servidor" });
    }
});

// Rota 2: Analytics Avançado de CTI (Severidade e Top Tecnologias com Cache TTL)
app.get('/api/threats/analytics', async (req, res) => {
    try {
        const payload = await obterAnalytics();
        res.set('Cache-Control', 'public, max-age=120, stale-while-revalidate=600');
        res.json(payload);
    } catch (error) {
        console.error("[-] Erro ao buscar analytics de inteligência:", error.message);
        res.status(500).json({ error: "Erro interno no servidor" });
    }
});

// Rota 3: Exploit Chains e Blueprints de Ataque Gerados por IA/Grafos
app.get('/api/threats/chains', async (req, res) => {
    try {
        const limit = Math.max(1, Math.min(parseInt(req.query.limit, 10) || 50, 100));
        const chains = await obterChains(limit);
        res.set('Cache-Control', 'public, max-age=120, stale-while-revalidate=600');
        res.json(chains);
    } catch (error) {
        console.error("[-] Erro ao buscar exploit chains:", error.message);
        res.json(gerarChainsPadrao());
    }
});

// Rota 4: Estatísticas de Clusters e Primitivas
app.get('/api/threats/clusters', async (req, res) => {
    try {
        const payload = await obterClusters();
        res.set('Cache-Control', 'public, max-age=120, stale-while-revalidate=600');
        res.json(payload);
    } catch (error) {
        console.error("[-] Erro ao buscar clusters:", error.message);
        res.json({ clusters: [], primitivas: [] });
    }
});

// Rota 5: Lista das Maiores Ameaças Críticas / Altas (Score >= 7.0)
app.get('/api/threats/critical', async (req, res) => {
    try {
        const limit = Math.max(1, Math.min(parseInt(req.query.limit, 10) || 100, 1000));
        const query = `
            SELECT cve_id, descricao, nota_cvss, severidade, primitiva, tecnologia, cluster_label, data_extracao 
            FROM threats 
            WHERE nota_cvss >= 7.0 
            ORDER BY nota_cvss DESC, data_extracao DESC 
            LIMIT $1;
        `;
        const { rows } = await pool.query(query, [limit]);
        res.set('Cache-Control', 'public, max-age=60, stale-while-revalidate=300');
        res.json(rows);
    } catch (error) {
        console.error("[-] Erro ao buscar ameaças críticas:", error.message);
        res.status(500).json({ error: "Erro interno no servidor" });
    }
});

// Constantes de Validação para Prevenção de Injeções e Poluição de Parâmetros
const SEVERIDADES_VALIDAS = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
const PRIMITIVAS_VALIDAS = new Set([
    'RECON_INFO_LEAK',
    'AUTH_BYPASS',
    'INJECTION_RCE',
    'PRIV_ESC',
    'DENIAL_OF_SERVICE',
    'GENERIC_VULN'
]);

// Rota 6: Consulta Paginada de Alta Performance com Full-Text Search (GIN) e Filtros
app.get('/api/threats', async (req, res) => {
    try {
        const page = Math.max(1, Math.min(parseInt(req.query.page, 10) || 1, 100000));
        const limit = Math.max(1, Math.min(parseInt(req.query.limit, 10) || 50, 1000));

        // Sanitização de busca: limite de 100 caracteres e remoção de caracteres nulos
        const rawSearch = req.query.search 
            ? String(req.query.search).slice(0, 100).replace(/\0/g, '').trim() 
            : null;

        // Validação estrita por whitelist para filtros categóricos
        const inputSeverity = req.query.severity && req.query.severity !== 'TODOS' 
            ? String(req.query.severity).toUpperCase().trim() 
            : null;
        const severity = inputSeverity && SEVERIDADES_VALIDAS.has(inputSeverity) ? inputSeverity : null;

        const inputPrimitive = req.query.primitive 
            ? String(req.query.primitive).toUpperCase().trim() 
            : null;
        const primitive = inputPrimitive && PRIMITIVAS_VALIDAS.has(inputPrimitive) ? inputPrimitive : null;

        // Otimização de Performance: Se for a página inicial padrão sem filtros, serve direto do cache em RAM
        if (page === 1 && !rawSearch && !severity && !primitive && (limit === 25 || limit === 10 || limit === 50)) {
            const cachedResult = await obterDefaultThreats(limit);
            res.set('Cache-Control', 'public, max-age=60, stale-while-revalidate=300');
            return res.json(cachedResult);
        }

        const offset = (page - 1) * limit;
        let whereClauses = [];
        let queryParams = [];

        if (rawSearch) {
            queryParams.push(rawSearch);
            const p = queryParams.length;
            whereClauses.push(`(
                cve_id ILIKE '%' || $${p} || '%'
                OR to_tsvector('english', coalesce(descricao, '')) @@ plainto_tsquery('english', $${p})
                OR descricao ILIKE '%' || $${p} || '%'
                OR tecnologia ILIKE '%' || $${p} || '%'
                OR cluster_label ILIKE '%' || $${p} || '%'
            )`);
        }

        if (severity) {
            queryParams.push(severity);
            whereClauses.push(`severidade = $${queryParams.length}`);
        }

        if (primitive) {
            queryParams.push(primitive);
            whereClauses.push(`primitiva = $${queryParams.length}`);
        }

        const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

        // Contagem total otimizada: reutiliza o total de ameaças em cache caso não haja filtros
        let totalRegistros = 0;
        if (whereClauses.length === 0 && memoryCache.stats.data && memoryCache.stats.data.total_ameacas) {
            totalRegistros = parseInt(memoryCache.stats.data.total_ameacas, 10);
        } else {
            const countQuery = `SELECT COUNT(*) as total FROM threats ${whereSql};`;
            const countResult = await pool.query(countQuery, queryParams);
            totalRegistros = parseInt(countResult.rows[0].total, 10);
        }

        // Busca paginada com ordenação otimizada por índice
        queryParams.push(limit);
        const limitParamIndex = queryParams.length;
        queryParams.push(offset);
        const offsetParamIndex = queryParams.length;

        const dataQuery = `
            SELECT cve_id, descricao, nota_cvss, severidade, primitiva, tecnologia, cluster_label, data_extracao 
            FROM threats 
            ${whereSql}
            ORDER BY nota_cvss DESC, data_extracao DESC 
            LIMIT $${limitParamIndex} OFFSET $${offsetParamIndex};
        `;
        const { rows } = await pool.query(dataQuery, queryParams);

        res.set('Cache-Control', 'public, max-age=30, stale-while-revalidate=120');
        res.json({
            pagina: page,
            limite: limit,
            total: totalRegistros,
            totalPaginas: Math.ceil(totalRegistros / limit) || 1,
            dados: rows
        });
    } catch (error) {
        console.error("[-] Erro ao listar catálogo de ameaças:", error.message);
        res.status(500).json({ error: "Erro interno no servidor" });
    }
});

// Middleware 404 para rotas não encontradas (Retorno padronizado em JSON)
app.use((req, res) => {
    res.status(404).json({ error: "Endpoint não encontrado" });
});

// Middleware de Tratamento Global de Erros (Prevenção de Stack Trace Leak)
app.use((err, req, res, next) => {
    console.error("[-] Erro não tratado na aplicação:", err.message);
    res.status(err.status || 500).json({ error: "Erro interno no servidor" });
});

// Pré-aquecimento do Cache em Memória no Boot do Servidor
async function preAquecerCache() {
    try {
        console.log('[+] [Cache Engine] Pré-aquecendo cache em RAM no boot do servidor...');
        const t0 = Date.now();
        await Promise.all([
            obterAnalytics(),
            obterChains(50),
            obterClusters(),
            obterDefaultThreats(25),
            obterDefaultThreats(10)
        ]);

        const analytics = memoryCache.analytics.data;
        memoryCache.overview = {
            data: {
                status: 'OK',
                stats: analytics ? analytics.stats : null,
                topTecnologias: analytics ? analytics.topTecnologias : [],
                chains: memoryCache.chains.data,
                clusters: memoryCache.clusters.data,
                initialThreats: memoryCache.defaultThreats[25] ? memoryCache.defaultThreats[25].data : null
            },
            expiresAt: Date.now() + CACHE_TTL_MS
        };
        console.log(`[+] [Cache Engine] Cache em RAM 100% aquecido em ${Date.now() - t0}ms (respostas subsequentes em < 2ms)!`);
    } catch (err) {
        console.warn('[-] [Cache Engine] Aviso no pré-aquecimento:', err.message);
    }
}

app.listen(port, () => {
    console.log(`[+] API do Cyber Threat Intel rodando na porta ${port} [Compression + RAM Cache + GIN FTS + ML Chains Ativos]`);
    preAquecerCache();
});