const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const pool = require('./db_connect');

const app = express();
const port = process.env.PORT || 5001;

// 1. Headers de Segurança HTTP e Remoção de Fingerprint
app.use(helmet());
app.disable('x-powered-by');

// 2. Configuração Dinâmica de CORS com Suporte a Vercel Previews
const origensEstaticas = [
    'http://localhost:5173',
    'http://localhost:3000',
    process.env.FRONTEND_URL
].filter(Boolean);

const corsOptions = {
    origin: (origin, callback) => {
        // Permite requisições sem origin (como mobile apps, curl, ferramentas backend)
        if (!origin) {
            return callback(null, true);
        }

        // Permite origens locais configuradas
        if (origensEstaticas.includes(origin)) {
            return callback(null, true);
        }

        // Permite qualquer deploy em produção ou preview da Vercel (*.vercel.app)
        if (/\.vercel\.app$/.test(origin) || origin === 'https://vercel.app') {
            return callback(null, true);
        }

        return callback(new Error(`Acesso bloqueado pela política de CORS para a origem: ${origin}`));
    },
    methods: ['GET'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86400
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '50kb' }));

// 3. Rate Limiting para Proteção contra DoS / Abuso de Recursos
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // Janela de 15 minutos
    max: 300, // Limite de 300 requisições por IP por janela
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        status: 429,
        error: 'Muitas requisições originadas deste IP. Tente novamente em alguns minutos.'
    }
});

app.use('/api/', apiLimiter);

// -----------------------------------------------------------------------------
// ROTAS DA API
// -----------------------------------------------------------------------------

// Rota de Healthcheck
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'Cyber Threat API rodando com sucesso!' });
});

// Rota 1: Resumo Estatístico Consolidado (Legado & Leve)
app.get('/api/threats/stats', async (req, res) => {
    try {
        const query = `
            SELECT 
                COUNT(*) as total_ameacas,
                SUM(CASE WHEN nota_cvss >= 9.0 THEN 1 ELSE 0 END) as criticas,
                SUM(CASE WHEN nota_cvss >= 7.0 AND nota_cvss < 9.0 THEN 1 ELSE 0 END) as altas,
                SUM(CASE WHEN nota_cvss >= 4.0 AND nota_cvss < 7.0 THEN 1 ELSE 0 END) as medias,
                SUM(CASE WHEN nota_cvss > 0.0 AND nota_cvss < 4.0 THEN 1 ELSE 0 END) as baixas,
                MAX(nota_cvss) as pior_risco
            FROM threats;
        `;
        const { rows } = await pool.query(query);
        res.json(rows[0]);
    } catch (error) {
        console.error("[-] Erro ao buscar estatísticas:", error.message);
        res.status(500).json({ error: "Erro interno no servidor" });
    }
});

// Rota 2: Analytics Avançado de CTI (Severidade, Tendência Temporal e Top Tecnologias)
app.get('/api/threats/analytics', async (req, res) => {
    try {
        const statsQuery = `
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

        const timelineQuery = `
            SELECT 
                substring(cve_id from 'CVE-([0-9]{4})-') as ano,
                COUNT(*) as total,
                SUM(CASE WHEN nota_cvss >= 9.0 THEN 1 ELSE 0 END) as criticas
            FROM threats
            WHERE cve_id ~ '^CVE-[0-9]{4}-'
            GROUP BY ano
            HAVING substring(cve_id from 'CVE-([0-9]{4})-') >= '2016'
            ORDER BY ano ASC;
        `;

        const techQuery = `
            SELECT 
                SUM(CASE WHEN descricao ILIKE '%windows%' OR descricao ILIKE '%microsoft%' THEN 1 ELSE 0 END) as microsoft,
                SUM(CASE WHEN descricao ILIKE '%linux%' OR descricao ILIKE '%kernel%' THEN 1 ELSE 0 END) as linux,
                SUM(CASE WHEN descricao ILIKE '%android%' OR descricao ILIKE '%google%' THEN 1 ELSE 0 END) as google,
                SUM(CASE WHEN descricao ILIKE '%apple%' OR descricao ILIKE '%macos%' OR descricao ILIKE '%ios%' THEN 1 ELSE 0 END) as apple,
                SUM(CASE WHEN descricao ILIKE '%apache%' THEN 1 ELSE 0 END) as apache,
                SUM(CASE WHEN descricao ILIKE '%cisco%' THEN 1 ELSE 0 END) as cisco,
                SUM(CASE WHEN descricao ILIKE '%oracle%' THEN 1 ELSE 0 END) as oracle
            FROM threats;
        `;

        const [statsResult, timelineResult, techResult] = await Promise.all([
            pool.query(statsQuery),
            pool.query(timelineQuery),
            pool.query(techQuery)
        ]);

        const rawTech = techResult.rows[0] || {};
        const topTecnologias = [
            { nome: 'Microsoft / Windows', total: parseInt(rawTech.microsoft || 0, 10), cor: '#00d4ff' },
            { nome: 'Linux / Kernel', total: parseInt(rawTech.linux || 0, 10), cor: '#00ff88' },
            { nome: 'Google / Android', total: parseInt(rawTech.google || 0, 10), cor: '#fbbf24' },
            { nome: 'Apple / iOS / macOS', total: parseInt(rawTech.apple || 0, 10), cor: '#a855f7' },
            { nome: 'Apache Foundation', total: parseInt(rawTech.apache || 0, 10), cor: '#f97316' },
            { nome: 'Cisco Systems', total: parseInt(rawTech.cisco || 0, 10), cor: '#06b6d4' },
            { nome: 'Oracle', total: parseInt(rawTech.oracle || 0, 10), cor: '#ef4444' }
        ].sort((a, b) => b.total - a.total);

        res.json({
            stats: statsResult.rows[0],
            timeline: timelineResult.rows,
            topTecnologias
        });
    } catch (error) {
        console.error("[-] Erro ao buscar analytics de inteligência:", error.message);
        res.status(500).json({ error: "Erro interno no servidor" });
    }
});

// Rota 3: Lista das Maiores Ameaças Críticas / Altas (Score >= 7.0)
app.get('/api/threats/critical', async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit, 10) || 100, 1000);
        const query = `
            SELECT cve_id, descricao, nota_cvss, severidade, data_extracao 
            FROM threats 
            WHERE nota_cvss >= 7.0 
            ORDER BY nota_cvss DESC, data_extracao DESC 
            LIMIT $1;
        `;
        const { rows } = await pool.query(query, [limit]);
        res.json(rows);
    } catch (error) {
        console.error("[-] Erro ao buscar ameaças críticas:", error.message);
        res.status(500).json({ error: "Erro interno no servidor" });
    }
});

// Rota 4: Consulta Paginada de Alta Performance com Full-Text Search (GIN) e Filtros
app.get('/api/threats', async (req, res) => {
    try {
        const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
        const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 1000);
        const offset = (page - 1) * limit;

        const rawSearch = req.query.search ? String(req.query.search).trim() : null;
        const severity = req.query.severity && req.query.severity !== 'TODOS' ? String(req.query.severity).toUpperCase() : null;

        let whereClauses = [];
        let queryParams = [];

        if (rawSearch) {
            queryParams.push(rawSearch);
            const p = queryParams.length;
            // Busca Híbrida: Full-Text Search no GIN Index + ILIKE para substrings parciais de CVE IDs
            whereClauses.push(`(
                cve_id ILIKE '%' || $${p} || '%'
                OR to_tsvector('english', coalesce(descricao, '')) @@ plainto_tsquery('english', $${p})
                OR descricao ILIKE '%' || $${p} || '%'
            )`);
        }

        if (severity) {
            queryParams.push(severity);
            whereClauses.push(`severidade = $${queryParams.length}`);
        }

        const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

        // Contagem total para paginação
        const countQuery = `SELECT COUNT(*) as total FROM threats ${whereSql};`;
        const countResult = await pool.query(countQuery, queryParams);
        const totalRegistros = parseInt(countResult.rows[0].total, 10);

        // Busca paginada com ordenação otimizada por índice
        queryParams.push(limit);
        const limitParamIndex = queryParams.length;
        queryParams.push(offset);
        const offsetParamIndex = queryParams.length;

        const dataQuery = `
            SELECT cve_id, descricao, nota_cvss, severidade, data_extracao 
            FROM threats 
            ${whereSql}
            ORDER BY nota_cvss DESC, data_extracao DESC 
            LIMIT $${limitParamIndex} OFFSET $${offsetParamIndex};
        `;
        const { rows } = await pool.query(dataQuery, queryParams);

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

app.listen(port, () => {
    console.log(`[+] API do Cyber Threat Intel rodando na porta ${port} [Full-Text Search & Analytics Ativos]`);
});