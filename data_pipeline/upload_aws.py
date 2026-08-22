import os
import time
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv

from extract import extrair_dados_nist
from transform import transformar_dados

# Carrega as variáveis de ambiente do .env na raiz do projeto
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))
load_dotenv()


def upload_to_aws(total_registros=10000, batch_size=1000):
    """
    Executa o pipeline ETL ponta a ponta:
    1. Extração paginada de até N registros da API do NIST NVD.
    2. Transformação e análise de risco matricial com NumPy.
    3. Deduplicação em memória para prevenir conflito de linhas duplicadas no mesmo batch.
    4. Criação da tabela e índices de alta performance (B-Tree + GIN Full-Text Search) no AWS RDS PostgreSQL.
    5. Carga massiva em lote via psycopg2.extras.execute_values.
    """
    inicio_total = time.time()
    print("=" * 65)
    print("      CYBER THREAT INTEL // PIPELINE ETL (NIST -> AWS RDS)       ")
    print("=" * 65)

    # 1. Extração dos dados brutos com paginação
    dados_brutos = extrair_dados_nist(total_desejado=total_registros)
    if not dados_brutos or not dados_brutos.get("vulnerabilities"):
        print("[-] [ETL Load] Falha na extração de dados do NIST. Abortando carga.")
        return False

    # 2. Transformação e análise matemática
    vulnerabilidades = transformar_dados(dados_brutos)
    if not vulnerabilidades:
        print("[-] [ETL Load] Nenhuma vulnerabilidade processada para upload.")
        return False

    # 3. Deduplicação em memória por id_cve (Impede erro de colisão no mesmo comando ON CONFLICT)
    mapa_dedup = {item["id_cve"]: item for item in vulnerabilidades if item.get("id_cve")}
    vulnerabilidades_unicas = list(mapa_dedup.values())
    total_duplicados = len(vulnerabilidades) - len(vulnerabilidades_unicas)

    if total_duplicados > 0:
        print(f"[!] [ETL Load] Deduplicação em memória: {total_duplicados:,} CVEs repetidos descartados ({len(vulnerabilidades_unicas):,} únicos para gravação).")

    # 4. Preparação das tuplas para inserção em lote
    registros_tuplas = [
        (
            item["id_cve"],
            item["descricao"],
            float(item["nota_cvss"]),
            item["severidade"]
        )
        for item in vulnerabilidades_unicas
    ]

    # 5. Conexão e Carga no AWS RDS PostgreSQL
    conn = None
    cursor = None
    try:
        print("[+] [ETL Load] Conectando ao banco PostgreSQL na AWS RDS...")
        conn = psycopg2.connect(
            host=os.getenv("DB_HOST"),
            database=os.getenv("DB_NAME", "postgres"),
            user=os.getenv("DB_USER", "postgres"),
            password=os.getenv("DB_PASSWORD"),
            port=os.getenv("DB_PORT", "5432"),
            sslmode="require",
            connect_timeout=15
        )
        cursor = conn.cursor()

        # Garante a existência da tabela threats
        create_table_query = """
        CREATE TABLE IF NOT EXISTS threats (
            cve_id VARCHAR(50) PRIMARY KEY,
            descricao TEXT,
            nota_cvss FLOAT,
            severidade VARCHAR(20),
            data_extracao TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        cursor.execute(create_table_query)

        # Criação de índices B-Tree e GIN Full-Text Search para queries ultra-rápidas
        create_indexes_query = """
        CREATE INDEX IF NOT EXISTS idx_threats_cvss_data ON threats (nota_cvss DESC, data_extracao DESC);
        CREATE INDEX IF NOT EXISTS idx_threats_severidade ON threats (severidade);
        CREATE INDEX IF NOT EXISTS idx_threats_fts ON threats USING GIN (to_tsvector('english', coalesce(descricao, '')));
        """
        cursor.execute(create_indexes_query)

        # Query de Upsert em lote de alta performance
        upsert_query = """
        INSERT INTO threats (cve_id, descricao, nota_cvss, severidade)
        VALUES %s
        ON CONFLICT (cve_id) DO UPDATE SET
            descricao = EXCLUDED.descricao,
            nota_cvss = EXCLUDED.nota_cvss,
            severidade = EXCLUDED.severidade,
            data_extracao = CURRENT_TIMESTAMP;
        """

        print(f"[+] [ETL Load] Gravando {len(registros_tuplas):,} registros únicos via execute_values (lotes de {batch_size:,})...")
        inicio_banco = time.time()

        execute_values(
            cur=cursor,
            sql=upsert_query,
            argslist=registros_tuplas,
            page_size=batch_size
        )

        conn.commit()
        duracao_banco = time.time() - inicio_banco

        print(f"[+] [ETL Load] SUCESSO: {len(registros_tuplas):,} registros sincronizados no AWS RDS em {duracao_banco:.2f}s!")

        duracao_total = time.time() - inicio_total
        print(f"\n[+] Pipeline ETL concluído com êxito em {duracao_total:.1f}s.")
        return True

    except psycopg2.Error as db_err:
        if conn:
            conn.rollback()
        print(f"[-] [ETL Load - ERRO POSTGRESQL] Falha na operação do banco: {db_err}")
        return False
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"[-] [ETL Load - ERRO INESPERADO] {e}")
        return False
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
            print("[*] Conexão com AWS RDS encerrada com segurança.")


if __name__ == "__main__":
    upload_to_aws(total_registros=10000, batch_size=1000)