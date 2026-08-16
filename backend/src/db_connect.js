const { Pool } = require('pg');
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') }); // puxa env da raiz

// configuracao do pool de conexao para aws rds postgresql
const pool = new Pool({
    host: process.env.DB_HOST,
    database: process.env.DB_NAME || 'postgres',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD,
    port: Number(process.env.DB_PORT) || 5432,
    ssl: {
        rejectUnauthorized: false // obrigatorio para conexoes remotas seguras no aws rds
    }
});

// previne crash em background
pool.on('error', (err) => {
    console.error('[-] erro no pool da aws em segundo plano:', err.message);
});

module.exports = pool;