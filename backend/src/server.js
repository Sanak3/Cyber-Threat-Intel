const express = require('express');
const cors = require('cors');
const pool = require('./db_connect'); // importa a conexao modular do arquivo vizinho

const app = express();
const port = process.env.PORT || 5000;

// middlewares
app.use(cors());
app.use(express.json());

// rota de teste de saude da api healthcheck
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'Cyber Threat API rodando com sucesso!' });
});

// rota 1 resumo estatistico para os graficos do dashboard
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
        console.error("erro ao buscar estatisticas", error);
        res.status(500).json({ error: "erro interno no servidor" });
    }
});

// rota 2 lista das ameacas mais criticas para a tabela do frontend
app.get('/api/threats/critical', async (req, res) => {
    try {
        const query = `
            SELECT cve_id, descricao, nota_cvss, severidade, data_extracao 
            FROM threats 
            WHERE nota_cvss >= 7.0 
            ORDER BY nota_cvss DESC 
            LIMIT 20;
        `;
        const { rows } = await pool.query(query);
        res.json(rows);
    } catch (error) {
        console.error("erro ao buscar ameacas criticas", error);
        res.status(500).json({ error: "erro interno no servidor" });
    }
});

app.listen(port, () => {
    console.log(`[+] API do Cyber Threat Intel rodando na porta ${port}`);
});