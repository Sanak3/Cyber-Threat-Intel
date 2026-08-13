import os
import psycopg2
from psycopg2.extras import execute_batch
from dotenv import load_dotenv

# Importando de forma modular
from extract import extrair_dados_nist
from transform import transformar_dados

# carrega as variaveis de ambiente
load_dotenv()


def conectar_banco():
    print("[+] Conectando ao banco de dados no GCP...")
    try:
        conn = psycopg2.connect(
            host=os.getenv("DB_HOST"),
            database=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            port=os.getenv("DB_PORT")
        )
        return conn
    except Exception as e:
        print(f"[-] Erro ao conectar no banco de dados: {e}")
        return None


def criar_tabela_se_nao_existir(conn):
    # SQL limpo e sem barras invertidas quebrando o código
    query = """
            CREATE TABLE IF NOT EXISTS threats \
            ( \
                id \
                SERIAL \
                PRIMARY \
                KEY, \
                cve_id \
                VARCHAR \
            ( \
                50 \
            ) UNIQUE NOT NULL,
                descricao TEXT,
                nota_cvss NUMERIC \
            ( \
                4, \
                2 \
            ),
                severidade VARCHAR \
            ( \
                20 \
            ),
                data_extracao TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ); \
            """
    try:
        cursor = conn.cursor()
        cursor.execute(query)
        conn.commit()
        cursor.close()
        print("[+] Tabela 'threats' verificada/criada com sucesso.")
    except Exception as e:
        print(f"[-] Erro ao criar tabela: {e}")
        conn.rollback()


def enviar_dados_para_gcp(conn, dados_limpos):
    print(f"[+] Iniciando envio de {len(dados_limpos)} registros para o GCP...")

    # Query de inserção limpa
    query = """
            INSERT INTO threats (cve_id, descricao, nota_cvss, severidade)
            VALUES (%(id_cve)s, %(descricao)s, %(nota_cvss)s, %(severidade)s) ON CONFLICT (cve_id) DO NOTHING; \
            """

    try:
        cursor = conn.cursor()
        # execute_batch é infinitamente mais rápido que fazer um loop de inserts
        execute_batch(cursor, query, dados_limpos)
        conn.commit()
        cursor.close()
        print("[+] CARGA CONCLUÍDA! Dados inseridos com sucesso no PostgreSQL.")
    except Exception as e:
        print(f"[-] Erro durante a inserção de dados: {e}")
        conn.rollback()


if __name__ == "__main__":
    # 1. Processo de Extração (Extract)
    dados_brutos = extrair_dados_nist()

    if dados_brutos:
        # 2. Processo de Transformação (Transform)
        dados_tratados = transformar_dados(dados_brutos)

        if dados_tratados:
            # 3. Processo de Carga (Load)
            conexao = conectar_banco()
            if conexao:
                criar_tabela_se_nao_existir(conexao)
                enviar_dados_para_gcp(conexao, dados_tratados)
                conexao.close()
                print("[+] Conexão com o banco encerrada. Pipeline ETL finalizado.")