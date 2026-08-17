const express = require('express');
const cors = require('cors');
const pool = require('./db_connect');

const app = express();
const port = process.env.PORT || 5001;

// Middlewares
app.use(cors());
app.use(express.json());

// Rota de Healthcheck
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'Cyber Threat API rodando com sucesso!' });
});

// Rota 1: Resumo Estatístico Consolidado (10k+ CVEs)
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

// Rota 2: Lista das Maiores Ameaças Críticas / Altas (com suporte a limite dinâmico)
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

// Rota 3: Consulta Paginada e Busca no Catálogo Completo (Escala 10.000+ registros)
app.get('/api/threats', async (req, res) => {
    try {
        const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
        const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 500);
        const offset = (page - 1) * limit;

        const search = req.query.search ? `%${req.query.search.trim()}%` : null;
        const severity = req.query.severity && req.query.severity !== 'TODOS' ? req.query.severity.toUpperCase() : null;

        let whereClauses = [];
        let queryParams = [];

        if (search) {
            queryParams.push(search);
            whereClauses.push(`(cve_id ILIKE $${queryParams.length} OR descricao ILIKE $${queryParams.length})`);
        }

        if (severity) {
            queryParams.push(severity);
            whereClauses.push(`severidade = $${queryParams.length}`);
        }

        const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

        // Contagem total para metadados de paginação
        const countQuery = `SELECT COUNT(*) as total FROM threats ${whereSql};`;
        const countResult = await pool.query(countQuery, queryParams);
        const totalRegistros = parseInt(countResult.rows[0].total, 10);

        // Busca paginada
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
    console.log(`[+] API do Cyber Threat Intel rodando na porta ${port} [Escala 10k+]`);
});