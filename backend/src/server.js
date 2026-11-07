const crypto = require('crypto');
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

function limparCache() {
    memoryCache.analytics = { data: null, expiresAt: 0 };
    memoryCache.stats = { data: null, expiresAt: 0 };
    memoryCache.chains = { data: null, expiresAt: 0 };
    memoryCache.clusters = { data: null, expiresAt: 0 };
    memoryCache.overview = { data: null, expiresAt: 0 };
    memoryCache.defaultThreats = {};
}

// -----------------------------------------------------------------------------
// GUARDA ZERO-DOWNTIME DE SCHEMA POSTGRESQL (Compatibilidade EPSS)
// -----------------------------------------------------------------------------
let schemaSuportaEpss = true;
let promessaSchema = null;

function resetarEstadoSchema(suporta = true) {
    schemaSuportaEpss = Boolean(suporta);
    promessaSchema = Promise.resolve(schemaSuportaEpss);
}

async function garantirSchemaRecente() {
    if (promessaSchema) return promessaSchema;
    promessaSchema = (async () => {
        try {
            await pool.query(`
                ALTER TABLE threats ADD COLUMN IF NOT EXISTS epss_score FLOAT DEFAULT 0.0;
                ALTER TABLE threats ADD COLUMN IF NOT EXISTS epss_percentile FLOAT DEFAULT 0.0;
            `);
            schemaSuportaEpss = true;
        } catch (alterErr) {
            try {
                const checkRes = await pool.query(`
                    SELECT COUNT(*)::int AS cols
                    FROM information_schema.columns
                    WHERE table_name = 'threats' AND column_name IN ('epss_score', 'epss_percentile');
                `);
                schemaSuportaEpss = ((checkRes.rows && checkRes.rows[0] && checkRes.rows[0].cols) || 0) >= 2;
            } catch {
                schemaSuportaEpss = false;
            }
            console.warn('[!] [Schema Guard] Aviso ao verificar colunas EPSS:', alterErr.message);
        }
        return schemaSuportaEpss;
    })();
    return promessaSchema;
}

function colunasEpssSelect() {
    return schemaSuportaEpss
        ? 'COALESCE(epss_score, 0) AS epss_score, COALESCE(epss_percentile, 0) AS epss_percentile'
        : '0.0::float AS epss_score, 0.0::float AS epss_percentile';
}

const MITRE_POR_PRIMITIVA = {
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
};

const MITRE_POR_CWE = {
    'CWE-22': { tactic_id: 'TA0009', tactic: 'Collection', technique_id: 'T1005', technique: 'Data from Local System' },
    'CWE-200': { tactic_id: 'TA0009', tactic: 'Collection', technique_id: 'T1005', technique: 'Data from Local System' },
    'CWE-532': { tactic_id: 'TA0006', tactic: 'Credential Access', technique_id: 'T1552', technique: 'Unsecured Credentials' },
    'CWE-798': { tactic_id: 'TA0006', tactic: 'Credential Access', technique_id: 'T1552', technique: 'Unsecured Credentials' },
    'CWE-89': { tactic_id: 'TA0001', tactic: 'Initial Access', technique_id: 'T1190', technique: 'Exploit Public-Facing Application' },
    'CWE-918': { tactic_id: 'TA0001', tactic: 'Initial Access', technique_id: 'T1190', technique: 'Exploit Public-Facing Application' },
    'CWE-502': { tactic_id: 'TA0002', tactic: 'Execution', technique_id: 'T1203', technique: 'Exploitation for Client/Server Execution' },
    'CWE-79': { tactic_id: 'TA0002', tactic: 'Execution', technique_id: 'T1059.007', technique: 'JavaScript Execution' }
};

function resolverMitrePasso(primitiva, cwe) {
    const cweKey = typeof cwe === 'string' ? cwe.trim().toUpperCase() : '';
    if (MITRE_POR_CWE[cweKey]) return { ...MITRE_POR_CWE[cweKey] };
    return { ...(MITRE_POR_PRIMITIVA[primitiva] || MITRE_POR_PRIMITIVA.GENERIC_VULN) };
}

function normalizarChainRow(chainRow) {
    if (!chainRow || typeof chainRow !== 'object') return chainRow;
    const writeup = chainRow.writeup && typeof chainRow.writeup === 'object' ? { ...chainRow.writeup } : null;
    if (!writeup || !Array.isArray(writeup.passos_ataque)) return chainRow;

    const passosNormalizados = writeup.passos_ataque.map((p) => ({
        ...p,
        epss_score: typeof p.epss_score === 'number' ? p.epss_score : Number(p.epss_score || 0),
        mitre_attack: p.mitre_attack || resolverMitrePasso(p.primitiva, p.cwe)
    }));

    const taticas = Array.isArray(writeup.taticas_mitre) && writeup.taticas_mitre.length > 0
        ? writeup.taticas_mitre
        : [...new Set(passosNormalizados.map((p) => `${p.mitre_attack.tactic_id} (${p.mitre_attack.technique_id})`))];

    const maxEpss = typeof writeup.max_epss === 'number'
        ? writeup.max_epss
        : Math.max(0, ...passosNormalizados.map((p) => Number(p.epss_score || 0)));

    return {
        ...chainRow,
        writeup: {
            ...writeup,
            max_epss: maxEpss,
            taticas_mitre: taticas,
            passos_ataque: passosNormalizados
        }
    };
}

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
    'VMware': '#8b5cf6',
    'GitLab / DevOps': '#fb7185',
    'WordPress': '#60a5fa',
    'Ivanti / Pulse Secure': '#f43f5e',
    'Palo Alto / Juniper': '#f59e0b',
    'Citrix / NetScaler': '#2dd4bf',
    'Atlassian': '#818cf8',
    'Nginx / F5': '#34d399'
};

// Helper para Chains com Fallback Inteligente (garante que sempre haja inteligência visível)
function gerarChainsPadrao() {
    return [
        {
            chain_id: "CHAIN-0001",
            tecnologia: "Cisco Systems",
            severidade: "CRITICAL",
            score_cvss: 10.0,
            cves: ["CVE-2023-20198", "CVE-2023-20273"],
            writeup: {
                chain_id: "CHAIN-0001",
                titulo: "[CRITICAL] [CISA KEV] Cadeia em Cisco Systems: Bypass de Autenticação até Execução Remota de Código (RCE) (2 Elos)",
                tecnologia: "Cisco Systems",
                severidade: "CRITICAL",
                score_cvss: 10.0,
                elos_count: 2,
                kev_count: 2,
                tem_kev: true,
                cves: ["CVE-2023-20198", "CVE-2023-20273"],
                resumo_executivo: "Correlação tática identificada no ecossistema Cisco Systems encadeando CVE-2023-20198 ➔ CVE-2023-20273. O vetor inicia com contorno direto de mecanismos de autenticação na Web UI do IOS XE e progride por pivoting até implante root persistente (Score Composto: 10.0/10.0). ALERTA SOC: 2 elo(s) desta cadeia constam no catálogo CISA KEV com exploração ativa confirmada in-the-wild.",
                passos_ataque: [
                    {
                        passo: 1,
                        cve_id: "CVE-2023-20198",
                        primitiva: "AUTH_BYPASS",
                        nota_cvss: 10.0,
                        cwe: "CWE-306",
                        cisa_kev: true,
                        epss_score: 0.9421,
                        acao: "Criação de Conta com Privilégio 15 via Web UI desprotegida.",
                        detalhe: "O invasor interage diretamente com a interface web de gerenciamento do IOS XE sem autenticação para registrar uma nova conta administrativa."
                    },
                    {
                        passo: 2,
                        cve_id: "CVE-2023-20273",
                        primitiva: "INJECTION_RCE",
                        nota_cvss: 7.2,
                        cwe: "CWE-78",
                        cisa_kev: true,
                        epss_score: 0.9185,
                        acao: "Injeção de Comandos como Root e Instalação de Implante Malicioso.",
                        detalhe: "Utilizando a nova conta de privilégio 15, explora a injeção no mecanismo de configuração para salvar um implante persistente no filesystem."
                    }
                ],
                impacto_tecnico: "Controle total da infraestrutura de roteamento e comutação da organização. Possibilidade de espionagem e interceptação de todo tráfego de rede.",
                mitigacoes_recomendadas: [
                    "PRIORIDADE MÁXIMA (CISA KEV): Aplicar correções emergenciais imediatas para CVE-2023-20198, CVE-2023-20273.",
                    "Desabilitar imediatamente a interface HTTP/HTTPS Server (Web UI) do Cisco IOS XE em interfaces voltadas à internet.",
                    "Auditar contas locais em busca de usuários nível 15 não autorizados e artefatos de implante no servidor web."
                ]
            }
        },
        {
            chain_id: "CHAIN-0002",
            tecnologia: "Microsoft / Windows",
            severidade: "CRITICAL",
            score_cvss: 9.9,
            cves: ["CVE-2024-21410", "CVE-2024-21413"],
            writeup: {
                chain_id: "CHAIN-0002",
                titulo: "[CRITICAL] [CISA KEV] Cadeia em Microsoft / Windows: NTLM Relay até Execução Remota de Código (2 Elos)",
                tecnologia: "Microsoft / Windows",
                severidade: "CRITICAL",
                score_cvss: 9.9,
                elos_count: 2,
                kev_count: 2,
                tem_kev: true,
                cves: ["CVE-2024-21410", "CVE-2024-21413"],
                resumo_executivo: "Cadeia envolvendo serviços Microsoft Exchange e Outlook. Um invasor remoto não autenticado força autenticação NTLM e reaproveita credenciais para executar código arbitrário no ambiente corporativo. ALERTA SOC: 2 elo(s) desta cadeia constam no catálogo CISA KEV com exploração ativa confirmada in-the-wild.",
                passos_ataque: [
                    {
                        passo: 1,
                        cve_id: "CVE-2024-21410",
                        primitiva: "AUTH_BYPASS",
                        nota_cvss: 9.8,
                        cwe: "CWE-287",
                        cisa_kev: true,
                        epss_score: 0.8934,
                        acao: "Bypass de Autenticação via NTLM Relay no Microsoft Exchange Server.",
                        detalhe: "O invasor intercepta e faz relay de credenciais NTLM de um cliente para o Exchange Server, autenticando-se como a vítima."
                    },
                    {
                        passo: 2,
                        cve_id: "CVE-2024-21413",
                        primitiva: "INJECTION_RCE",
                        nota_cvss: 9.8,
                        cwe: "CWE-94",
                        cisa_kev: true,
                        epss_score: 0.9312,
                        acao: "Execução Remota de Código via Moniker Link no Microsoft Outlook.",
                        detalhe: "Com o acesso obtido, envia e-mails contendo links maliciosos no protocolo file:// que burla o Modo Protegido do Outlook e executa binário externo."
                    }
                ],
                impacto_tecnico: "Controle sobre caixas postais corporativas e execução de código remoto em estações de domínio Windows / Active Directory.",
                mitigacoes_recomendadas: [
                    "PRIORIDADE MÁXIMA (CISA KEV): Instalar atualizações cumulativas da Microsoft para CVE-2024-21410 e CVE-2024-21413.",
                    "Habilitar Extended Protection for Authentication (EPA) nos servidores Exchange.",
                    "Bloquear tráfego SMB de saída (porta 445/TCP) no perímetro para impedir vazamento de hashes NTLM."
                ]
            }
        },
        {
            chain_id: "CHAIN-0003",
            tecnologia: "Linux / Kernel",
            severidade: "CRITICAL",
            score_cvss: 9.7,
            cves: ["CVE-2024-21626", "CVE-2024-1086"],
            writeup: {
                chain_id: "CHAIN-0003",
                titulo: "[CRITICAL] [CISA KEV] Cadeia em Linux / Kernel: Fuga de Container até Escalação Root (2 Elos)",
                tecnologia: "Linux / Kernel",
                severidade: "CRITICAL",
                score_cvss: 9.7,
                elos_count: 2,
                kev_count: 2,
                tem_kev: true,
                cves: ["CVE-2024-21626", "CVE-2024-1086"],
                resumo_executivo: "Cadeia crítica de escape de container e elevação local de privilégios no Linux Kernel. Permite a um invasor escapar de um pod Docker/Kubernetes e assumir UID 0 (root) no host físico/VM. ALERTA SOC: 2 elo(s) desta cadeia constam no catálogo CISA KEV.",
                passos_ataque: [
                    {
                        passo: 1,
                        cve_id: "CVE-2024-21626",
                        primitiva: "AUTH_BYPASS",
                        nota_cvss: 8.6,
                        cwe: "CWE-200",
                        cisa_kev: true,
                        epss_score: 0.8415,
                        acao: "Container Breakout via Leaked File Descriptor (runc).",
                        detalhe: "O atacante abusa de descritores de arquivos abertos durante a inicialização do container para acessar o filesystem do host (/proc/self/cwd)."
                    },
                    {
                        passo: 2,
                        cve_id: "CVE-2024-1086",
                        primitiva: "PRIV_ESC",
                        nota_cvss: 7.8,
                        cwe: "CWE-416",
                        cisa_kev: true,
                        epss_score: 0.8764,
                        acao: "Escalação Local de Privilégios para Root via Use-After-Free no nf_tables.",
                        detalhe: "No host, explora corrupção de memória no netfilter/nf_tables do kernel para sobrescrever credenciais de processo e obter UID 0."
                    }
                ],
                impacto_tecnico: "Comprometimento irrestrito do nó hospedeiro e de todos os containers/workloads co-alocados no cluster.",
                mitigacoes_recomendadas: [
                    "PRIORIDADE MÁXIMA (CISA KEV): Atualizar Linux Kernel (patch nf_tables) e runc >= 1.1.12 para corrigir CVE-2024-1086 e CVE-2024-21626.",
                    "Desativar namespaces de usuário não privilegiados (kernel.unprivileged_userns_clone=0) nos nós de produção.",
                    "Monitorar eventos de runtime (Falco/Tetragon) para acessos anômalos a /proc/self/fd e elevação súbita de UID."
                ]
            }
        },
        {
            chain_id: "CHAIN-0004",
            tecnologia: "Apache Foundation",
            severidade: "CRITICAL",
            score_cvss: 9.6,
            cves: ["CVE-2024-38816", "CVE-2024-38819"],
            writeup: {
                chain_id: "CHAIN-0004",
                titulo: "[CRITICAL] [CISA KEV] Cadeia em Apache Foundation: Exposição de Artefatos até Execução Remota de Código (2 Elos)",
                tecnologia: "Apache Foundation",
                severidade: "CRITICAL",
                score_cvss: 9.6,
                elos_count: 2,
                kev_count: 1,
                tem_kev: true,
                cves: ["CVE-2024-38816", "CVE-2024-38819"],
                resumo_executivo: "Correlação de alto risco no ecossistema Java/Apache Tomcat. O atacante encadeia leitura arbitrária de arquivos via Path Traversal para extrair segredos de aplicação e alcançar RCE não autenticado.",
                passos_ataque: [
                    {
                        passo: 1,
                        cve_id: "CVE-2024-38816",
                        primitiva: "RECON_INFO_LEAK",
                        nota_cvss: 7.5,
                        cwe: "CWE-22",
                        cisa_kev: false,
                        epss_score: 0.4210,
                        acao: "Acesso Inicial / Leitura de Arquivos Sensíveis via Directory Traversal.",
                        detalhe: "Requisições HTTP forjadas exploram roteamento estático mal configurado para extrair variáveis de ambiente e chaves de sessão."
                    },
                    {
                        passo: 2,
                        cve_id: "CVE-2024-38819",
                        primitiva: "INJECTION_RCE",
                        nota_cvss: 9.8,
                        cwe: "CWE-22",
                        cisa_kev: true,
                        epss_score: 0.8842,
                        acao: "Pivoting / Execução Arbitrária com Credenciais Exfiltradas.",
                        detalhe: "Utilizando os artefatos exfiltrados no Passo 1, forja requisições autenticadas/assinadas que disparam execução remota no container web."
                    }
                ],
                impacto_tecnico: "Execução de comandos no contexto da aplicação web, exfiltração de credenciais de banco de dados e persistência lateral.",
                mitigacoes_recomendadas: [
                    "Aplicar patches emergenciais para CVE-2024-38816 e CVE-2024-38819.",
                    "Configurar regras de WAF/IPS bloqueando sequências codificadas de path traversal (%2e%2e/) e sanitizar rotas estáticas.",
                    "Executar o servidor de aplicação sob usuário não-root com filesystem somente leitura."
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

    await garantirSchemaRecente();
    const epssAggSql = schemaSuportaEpss
        ? 'COALESCE(SUM(CASE WHEN epss_score >= 0.1 THEN 1 ELSE 0 END), 0) as epss_alto_total,'
        : '0 as epss_alto_total,';

    const query = `
        SELECT 
            COUNT(*) as total_ameacas,
            COALESCE(SUM(CASE WHEN nota_cvss >= 9.0 THEN 1 ELSE 0 END), 0) as criticas,
            COALESCE(SUM(CASE WHEN nota_cvss >= 7.0 AND nota_cvss < 9.0 THEN 1 ELSE 0 END), 0) as altas,
            COALESCE(SUM(CASE WHEN nota_cvss >= 4.0 AND nota_cvss < 7.0 THEN 1 ELSE 0 END), 0) as medias,
            COALESCE(SUM(CASE WHEN nota_cvss > 0.0 AND nota_cvss < 4.0 THEN 1 ELSE 0 END), 0) as baixas,
            COALESCE(SUM(CASE WHEN cisa_kev = TRUE THEN 1 ELSE 0 END), 0) as cisa_kev_total,
            ${epssAggSql}
            COALESCE(MAX(nota_cvss), 0) as pior_risco,
            COALESCE(ROUND(AVG(CASE WHEN nota_cvss > 0 THEN nota_cvss ELSE NULL END)::numeric, 2), 0) as media_score
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

const MAX_CHAINS_CACHE = 100;

async function obterChains(limit = 50) {
    const limiteSeguro = Math.max(1, Math.min(Number(limit) || 50, MAX_CHAINS_CACHE));
    const agora = Date.now();
    if (memoryCache.chains.data && agora < memoryCache.chains.expiresAt) {
        return memoryCache.chains.data.slice(0, limiteSeguro);
    }

    let chainsRetornadas = [];
    try {
        const query = `
            SELECT chain_id, tecnologia, severidade, score_cvss, cves, writeup, data_criacao
            FROM exploit_chains
            ORDER BY COALESCE((writeup->>'tem_kev')::boolean, false) DESC, score_cvss DESC, data_criacao DESC
            LIMIT $1;
        `;
        const { rows } = await pool.query(query, [MAX_CHAINS_CACHE]);
        if (rows && rows.length > 0) {
            chainsRetornadas = rows;
        }
    } catch (dbErr) {
        console.warn("[!] [API Chains] Tabela exploit_chains ainda não populada no banco:", dbErr.message);
    }

    if (chainsRetornadas.length === 0) {
        chainsRetornadas = gerarChainsPadrao();
    }

    chainsRetornadas = chainsRetornadas.map(normalizarChainRow);
    memoryCache.chains = { data: chainsRetornadas, expiresAt: agora + CACHE_TTL_MS };
    return chainsRetornadas.slice(0, limiteSeguro);
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

    await garantirSchemaRecente();
    const dataQuery = `
        SELECT 
            cve_id, descricao, nota_cvss, severidade, primitiva, tecnologia, cluster_label, 
            COALESCE(data_publicacao, data_extracao) AS data_extracao,
            data_publicacao, data_modificacao, cwe, cisa_kev,
            ${colunasEpssSelect()}
        FROM threats 
        ORDER BY nota_cvss DESC, COALESCE(data_publicacao, data_extracao) DESC 
        LIMIT $1;
    `;
    const { rows } = await pool.query(dataQuery, [limit]);

    let totalRegistros = 20000;
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

function compararSegredoSeguro(recebido, esperado) {
    if (typeof recebido !== 'string' || typeof esperado !== 'string') return false;
    if (!recebido.length || !esperado.length) return false;
    // Compara digests SHA-256 de tamanho fixo (32 bytes) para evitar vazamento do tamanho do segredo por timing
    const hashRecebido = crypto.createHash('sha256').update(recebido, 'utf8').digest();
    const hashEsperado = crypto.createHash('sha256').update(esperado, 'utf8').digest();
    return crypto.timingSafeEqual(hashRecebido, hashEsperado);
}

// Endpoint Interno: Invalidação de Cache disparada por Webhook Seguro (ETL Pipeline)
app.post('/api/internal/cache-flush', (req, res) => {
    const configuredSecret = process.env.INTERNAL_WEBHOOK_SECRET;
    const rawHeaderSecret = Array.isArray(req.headers['x-webhook-secret'])
        ? req.headers['x-webhook-secret'][0]
        : req.headers['x-webhook-secret'];
    const bearerSecret = typeof req.headers.authorization === 'string' && req.headers.authorization.startsWith('Bearer ')
        ? req.headers.authorization.slice(7)
        : null;
    const incomingSecret = rawHeaderSecret || bearerSecret;

    if (!compararSegredoSeguro(incomingSecret, configuredSecret)) {
        return res.status(401).json({ error: 'Acesso não autorizado: segredo do webhook inválido ou não configurado.' });
    }

    limparCache();
    console.log('[+] [Cache Engine] Cache em RAM invalidado com sucesso via Webhook Interno.');
    preAquecerCache().catch((err) => {
        console.warn('[!] [Cache Engine] Falha ao reaquecer cache após flush:', err.message);
    });
    res.json({ status: 'OK', message: 'Cache em RAM invalidado e reaquecimento disparado com sucesso.' });
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
        res.json(gerarChainsPadrao().map(normalizarChainRow));
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
        await garantirSchemaRecente();
        const limit = Math.max(1, Math.min(parseInt(req.query.limit, 10) || 100, 1000));
        const query = `
            SELECT 
                cve_id, descricao, nota_cvss, severidade, primitiva, tecnologia, cluster_label, 
                COALESCE(data_publicacao, data_extracao) AS data_extracao,
                data_publicacao, data_modificacao, cwe, cisa_kev,
                ${colunasEpssSelect()}
            FROM threats 
            WHERE nota_cvss >= 7.0 
            ORDER BY nota_cvss DESC, COALESCE(data_publicacao, data_extracao) DESC 
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

const ORDENACOES_VALIDAS = new Set(['cvss_desc', 'recent', 'epss_desc', 'kev_first']);

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

        const inputPrimitive = req.query.primitive && req.query.primitive !== 'TODOS'
            ? String(req.query.primitive).toUpperCase().trim() 
            : null;
        const primitive = inputPrimitive && PRIMITIVAS_VALIDAS.has(inputPrimitive) ? inputPrimitive : null;

        const kevOnly = req.query.kev === 'true' || req.query.kev === '1';
        const cluster = req.query.cluster && req.query.cluster !== 'TODOS'
            ? String(req.query.cluster).slice(0, 150).replace(/\0/g, '').trim()
            : null;
        const technology = req.query.technology && req.query.technology !== 'TODOS'
            ? String(req.query.technology).slice(0, 100).replace(/\0/g, '').trim()
            : null;

        const parsedMinEpss = req.query.min_epss !== undefined ? parseFloat(req.query.min_epss) : 0;
        const minEpss = Number.isFinite(parsedMinEpss) && parsedMinEpss > 0
            ? Math.min(1.0, parsedMinEpss)
            : 0;

        const inputSort = req.query.sort ? String(req.query.sort).toLowerCase().trim() : 'cvss_desc';
        const sortMode = ORDENACOES_VALIDAS.has(inputSort) ? inputSort : 'cvss_desc';

        // Otimização de Performance: Se for a página inicial padrão sem filtros, serve direto do cache em RAM
        if (
            page === 1 &&
            !rawSearch &&
            !severity &&
            !primitive &&
            !kevOnly &&
            !cluster &&
            !technology &&
            !(minEpss > 0) &&
            sortMode === 'cvss_desc' &&
            (limit === 25 || limit === 10 || limit === 50)
        ) {
            const cachedResult = await obterDefaultThreats(limit);
            res.set('Cache-Control', 'public, max-age=60, stale-while-revalidate=300');
            return res.json(cachedResult);
        }

        await garantirSchemaRecente();

        const offset = (page - 1) * limit;
        let whereClauses = [];
        let queryParams = [];

        if (rawSearch) {
            // Escapa curingas SQL (% e _) para prevenir degradação de performance por wildcard injection
            const escapedLikeSearch = rawSearch.replace(/([%_\\])/g, '\\$1');

            queryParams.push(escapedLikeSearch);
            const pLike = queryParams.length;

            queryParams.push(rawSearch);
            const pFts = queryParams.length;

            // Busca otimizada: FTS utiliza o índice GIN (idx_threats_fts) sem o OR descricao ILIKE que forçava Seq Scan
            whereClauses.push(`(
                cve_id ILIKE '%' || $${pLike} || '%' ESCAPE '\\'
                OR to_tsvector('english', coalesce(descricao, '')) @@ plainto_tsquery('english', $${pFts})
                OR tecnologia ILIKE '%' || $${pLike} || '%' ESCAPE '\\'
                OR cluster_label ILIKE '%' || $${pLike} || '%' ESCAPE '\\'
                OR cwe ILIKE '%' || $${pLike} || '%' ESCAPE '\\'
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

        if (kevOnly) {
            whereClauses.push('cisa_kev = TRUE');
        }

        if (cluster) {
            queryParams.push(cluster);
            whereClauses.push(`cluster_label = $${queryParams.length}`);
        }

        if (technology) {
            queryParams.push(technology);
            whereClauses.push(`tecnologia = $${queryParams.length}`);
        }

        if (minEpss > 0 && schemaSuportaEpss) {
            queryParams.push(minEpss);
            whereClauses.push(`COALESCE(epss_score, 0) >= $${queryParams.length}`);
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

        // Busca paginada com ordenação dinâmica por whitelist segura
        let orderBySql = 'nota_cvss DESC, COALESCE(data_publicacao, data_extracao) DESC';
        if (sortMode === 'recent') {
            orderBySql = 'COALESCE(data_publicacao, data_extracao) DESC, nota_cvss DESC';
        } else if (sortMode === 'epss_desc') {
            orderBySql = schemaSuportaEpss
                ? 'COALESCE(epss_score, 0) DESC, nota_cvss DESC, COALESCE(data_publicacao, data_extracao) DESC'
                : 'nota_cvss DESC, COALESCE(data_publicacao, data_extracao) DESC';
        } else if (sortMode === 'kev_first') {
            orderBySql = schemaSuportaEpss
                ? 'cisa_kev DESC, COALESCE(epss_score, 0) DESC, nota_cvss DESC'
                : 'cisa_kev DESC, nota_cvss DESC';
        }

        queryParams.push(limit);
        const limitParamIndex = queryParams.length;
        queryParams.push(offset);
        const offsetParamIndex = queryParams.length;

        const dataQuery = `
            SELECT 
                cve_id, descricao, nota_cvss, severidade, primitiva, tecnologia, cluster_label, 
                COALESCE(data_publicacao, data_extracao) AS data_extracao,
                data_publicacao, data_modificacao, cwe, cisa_kev,
                ${colunasEpssSelect()}
            FROM threats 
            ${whereSql}
            ORDER BY ${orderBySql}
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
        await garantirSchemaRecente();
        const [analytics, chains, clusters, initialThreats] = await Promise.all([
            obterAnalytics(),
            obterChains(50),
            obterClusters(),
            obterDefaultThreats(25),
            obterDefaultThreats(10)
        ]);

        memoryCache.overview = {
            data: {
                status: 'OK',
                stats: analytics ? analytics.stats : null,
                topTecnologias: analytics ? analytics.topTecnologias : [],
                chains,
                clusters,
                initialThreats
            },
            expiresAt: Date.now() + CACHE_TTL_MS
        };
        console.log(`[+] [Cache Engine] Cache em RAM 100% aquecido em ${Date.now() - t0}ms (respostas subsequentes em < 2ms)!`);
    } catch (err) {
        console.warn('[-] [Cache Engine] Aviso no pré-aquecimento:', err.message);
    }
}

if (require.main === module) {
    const server = app.listen(port, () => {
        console.log(`[+] API do Cyber Threat Intel rodando na porta ${port} [Compression + RAM Cache + GIN FTS + ML Chains Ativos]`);
        preAquecerCache();
    });

    let encerrando = false;
    function encerrarServidorGraciosamente(sinal) {
        if (encerrando) return;
        encerrando = true;
        console.log(`[!] Sinal ${sinal} recebido. Encerrando conexões HTTP e pool PostgreSQL...`);
        server.close(async () => {
            try {
                await pool.end();
                console.log('[+] Pool PostgreSQL encerrado com sucesso.');
            } catch (err) {
                console.error('[-] Erro ao encerrar pool PostgreSQL:', err.message);
            } finally {
                process.exit(0);
            }
        });

        setTimeout(() => {
            console.warn('[!] Tempo limite de shutdown atingido. Forçando encerramento.');
            process.exit(1);
        }, 10000).unref();
    }

    process.on('SIGTERM', () => encerrarServidorGraciosamente('SIGTERM'));
    process.on('SIGINT', () => encerrarServidorGraciosamente('SIGINT'));
}

module.exports = {
    app,
    limparCache,
    compararSegredoSeguro,
    preAquecerCache,
    garantirSchemaRecente,
    resetarEstadoSchema,
    resolverMitrePasso,
    normalizarChainRow
};