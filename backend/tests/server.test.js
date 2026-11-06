const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

process.env.INTERNAL_WEBHOOK_SECRET = 'segredo-teste-automatizado-cti-2026';

const pool = require('../src/db_connect');
const {
    app,
    limparCache,
    compararSegredoSeguro,
    resetarEstadoSchema,
    resolverMitrePasso
} = require('../src/server');

describe('Cyber Threat Intel Backend API', () => {
    let server;
    let baseUrl;
    let queriesCapturadas = [];
    const queryOriginal = pool.query.bind(pool);

    before(async () => {
        pool.query = async (sql, params = []) => {
            const sqlNormalizado = String(sql).replace(/\s+/g, ' ').trim();
            queriesCapturadas.push({ sql: sqlNormalizado, params });

            if (sqlNormalizado.includes('FROM exploit_chains')) {
                return { rows: [] };
            }
            if (sqlNormalizado.includes('COUNT(*) as total_ameacas')) {
                return {
                    rows: [{
                        total_ameacas: '10420',
                        criticas: '1520',
                        altas: '3410',
                        medias: '4200',
                        baixas: '1290',
                        cisa_kev_total: '1185',
                        epss_alto_total: '640',
                        pior_risco: 10.0,
                        media_score: '7.42'
                    }]
                };
            }
            if (sqlNormalizado.includes('GROUP BY tecnologia')) {
                return {
                    rows: [
                        { nome: 'Microsoft / Windows', total: 420 },
                        { nome: 'Linux / Kernel', total: 380 }
                    ]
                };
            }
            if (sqlNormalizado.includes('GROUP BY cluster_label') || sqlNormalizado.includes('GROUP BY primitiva')) {
                return { rows: [] };
            }
            if (sqlNormalizado.startsWith('SELECT COUNT(*) as total FROM threats')) {
                return { rows: [{ total: '2' }] };
            }
            return {
                rows: [
                    {
                        cve_id: 'CVE-2026-9001',
                        descricao: 'Remote code execution in Fortinet FortiOS SSL-VPN',
                        nota_cvss: 9.8,
                        severidade: 'CRITICAL',
                        primitiva: 'INJECTION_RCE',
                        tecnologia: 'Fortinet / SonicWall',
                        cluster_label: 'Remote Code Execution (RCE)',
                        cwe: 'CWE-78',
                        cisa_kev: true,
                        epss_score: 0.9412,
                        epss_percentile: 0.9985
                    },
                    {
                        cve_id: 'CVE-2026-9002',
                        descricao: 'Authentication bypass in Fortinet FortiGate',
                        nota_cvss: 8.4,
                        severidade: 'HIGH',
                        primitiva: 'AUTH_BYPASS',
                        tecnologia: 'Fortinet / SonicWall',
                        cluster_label: 'Authentication Bypass & Access Control',
                        cwe: 'CWE-287',
                        cisa_kev: false,
                        epss_score: 0.6120,
                        epss_percentile: 0.9650
                    }
                ]
            };
        };

        await new Promise((resolve) => {
            server = app.listen(0, '127.0.0.1', () => {
                const addr = server.address();
                baseUrl = `http://127.0.0.1:${addr.port}`;
                resolve();
            });
        });
    });

    beforeEach(() => {
        queriesCapturadas = [];
        limparCache();
        resetarEstadoSchema(true);
    });

    after(async () => {
        pool.query = queryOriginal;
        if (server) {
            await new Promise((resolve) => server.close(resolve));
        }
        await pool.end().catch(() => {});
    });

    it('GET /api/health retorna status OK e aplica headers de seguranca Helmet', async () => {
        const res = await fetch(`${baseUrl}/api/health`);
        assert.equal(res.status, 200);
        assert.equal(res.headers.get('x-powered-by'), null);
        assert.equal(res.headers.get('x-content-type-options'), 'nosniff');

        const body = await res.json();
        assert.equal(body.status, 'OK');
    });

    it('compararSegredoSeguro e POST /api/internal/cache-flush validam autenticacao timing-safe', async () => {
        assert.equal(compararSegredoSeguro('abc', 'abc'), true);
        assert.equal(compararSegredoSeguro('abc', 'def'), false);
        assert.equal(compararSegredoSeguro('', 'abc'), false);
        assert.equal(compararSegredoSeguro(null, 'abc'), false);

        const resSemSegredo = await fetch(`${baseUrl}/api/internal/cache-flush`, { method: 'POST' });
        assert.equal(resSemSegredo.status, 401);

        const resSegredoInvalido = await fetch(`${baseUrl}/api/internal/cache-flush`, {
            method: 'POST',
            headers: { 'X-Webhook-Secret': 'segredo-incorreto' }
        });
        assert.equal(resSegredoInvalido.status, 401);

        const resHeaderValido = await fetch(`${baseUrl}/api/internal/cache-flush`, {
            method: 'POST',
            headers: { 'X-Webhook-Secret': process.env.INTERNAL_WEBHOOK_SECRET }
        });
        assert.equal(resHeaderValido.status, 200);

        const resBearerValido = await fetch(`${baseUrl}/api/internal/cache-flush`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${process.env.INTERNAL_WEBHOOK_SECRET}` }
        });
        assert.equal(resBearerValido.status, 200);
    });

    it('GET /api/threats/chains retorna cadeias enriquecidas com MITRE ATT&CK e EPSS respeitando limit', async () => {
        const mitreDeser = resolverMitrePasso('INJECTION_RCE', 'CWE-502');
        assert.equal(mitreDeser.technique_id, 'T1203');

        const res = await fetch(`${baseUrl}/api/threats/chains?limit=2`);
        assert.equal(res.status, 200);
        const chains = await res.json();

        assert.equal(chains.length, 2);
        assert.equal(chains[0].chain_id, 'CHAIN-0001');
        assert.equal(chains[0].writeup.tem_kev, true);
        assert.ok(chains[0].writeup.max_epss > 0.9);
        assert.ok(Array.isArray(chains[0].writeup.taticas_mitre));
        assert.ok(chains[0].writeup.taticas_mitre.length >= 2);
        assert.equal(chains[0].writeup.passos_ataque[0].mitre_attack.technique_id, 'T1078');
    });

    it('GET /api/threats aplica filtros parametrizados (technology, kev, min_epss), escape de wildcards e sort dinamico', async () => {
        const params = new URLSearchParams({
            page: '1',
            limit: '20',
            search: '100%_rce',
            severity: 'CRITICAL',
            primitive: 'INJECTION_RCE',
            kev: 'true',
            technology: 'Fortinet / SonicWall',
            min_epss: '0.5',
            sort: 'epss_desc'
        });

        const res = await fetch(`${baseUrl}/api/threats?${params.toString()}`);
        assert.equal(res.status, 200);
        const payload = await res.json();

        assert.equal(payload.pagina, 1);
        assert.equal(payload.limite, 20);
        assert.equal(payload.dados.length, 2);
        assert.equal(payload.dados[0].epss_score, 0.9412);

        const dataQuery = queriesCapturadas.find((q) => q.sql.startsWith('SELECT cve_id, descricao'));
        assert.ok(dataQuery, 'Deve executar query parametrizada de listagem');
        assert.ok(dataQuery.sql.includes('cisa_kev = TRUE'));
        assert.ok(dataQuery.sql.includes('tecnologia = $'));
        assert.ok(dataQuery.sql.includes('COALESCE(epss_score, 0) >= $'));
        assert.ok(dataQuery.sql.includes('ORDER BY COALESCE(epss_score, 0) DESC'));
        assert.equal(dataQuery.params[0], '100\\%\\_rce');
    });

    it('GET /api/threats descarta filtros fora da whitelist e mantem fallback zero-downtime sem colunas EPSS', async () => {
        resetarEstadoSchema(false);

        const res = await fetch(
            `${baseUrl}/api/threats?page=2&limit=15&severity=DROP_TABLE&primitive=INVALIDA&min_epss=0.8&sort=epss_desc`
        );
        assert.equal(res.status, 200);

        const dataQuery = queriesCapturadas.find((q) => q.sql.startsWith('SELECT cve_id, descricao'));
        assert.ok(dataQuery);
        assert.ok(!dataQuery.sql.includes('severidade ='));
        assert.ok(!dataQuery.sql.includes('primitiva ='));
        assert.ok(dataQuery.sql.includes('0.0::float AS epss_score'));
        assert.ok(!dataQuery.sql.includes('COALESCE(epss_score, 0)'));
    });

    it('Rota inexistente retorna HTTP 404 padronizado em JSON', async () => {
        const res = await fetch(`${baseUrl}/api/rota-inexistente`);
        assert.equal(res.status, 404);
        const body = await res.json();
        assert.equal(body.error, 'Endpoint não encontrado');
    });
});
