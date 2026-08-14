const { Pool } = require('pg');
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') }); // puxa o env da raiz com seguranca

// configuracao do pool de conexao modular
const pool = new Pool({
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

// previne que o servidor node crache e desligue se o banco ficar offline em background
pool.on('error', (err) => {
    console.error('[-] erro no banco em segundo plano:', err.message);
});

module.exports = pool;