const { Pool } = require('pg');
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });

// Configuração do pool de conexão com suporte a SSL seguro
const sslConfig = process.env.DB_SSL_CA
    ? { ca: process.env.DB_SSL_CA, rejectUnauthorized: true }
    : { rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED === 'true' };

const pool = new Pool({
    host: process.env.DB_HOST,
    database: process.env.DB_NAME || 'postgres',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD,
    port: Number(process.env.DB_PORT) || 5432,
    ssl: sslConfig,
    connectionTimeoutMillis: 10000,
    idleTimeoutMillis: 30000,
    max: 20
});

// Tratamento de erro assíncrono para evitar crashes em segundo plano
pool.on('error', (err) => {
    console.error('[-] Erro no pool de conexões PostgreSQL:', err.message);
});

module.exports = pool;