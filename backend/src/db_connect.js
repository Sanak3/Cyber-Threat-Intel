const { Pool } = require('pg');
require('dotenv').config({ path: '../../.env' }); // puxa o env da raiz do projeto

// configuracao do pool de conexao modular
const pool = new Pool({
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

// testando a conexao ao iniciar
pool.connect((err, client, release) => {
    if (err) {
        console.error('erro ao conectar no banco de dados', err.stack);
    } else {
        console.log('[+] modulo de banco de dados conectado com sucesso');
        release();
    }
});

module.exports = pool;