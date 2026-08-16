import os
import psycopg2
from dotenv import load_dotenv
from extract import extrair_dados_nist
from transform import transformar_dados

# Carrega as credenciais do .env na raiz do projeto
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

def upload_to_aws():
    # 1. Extracao via API do NIST
    dados_brutos = extrair_dados_nist()
    if not dados_brutos:
        print("[-] Falha na extracao de dados do NIST.")
        return

    # 2. Transformacao e analise vetorial com NumPy
    vulnerabilidades = transformar_dados(dados_brutos)
    if not vulnerabilidades:
        print("[-] Nenhuma vulnerabilidade processada para upload.")
        return

    # 3. Carga no banco PostgreSQL gerenciado na AWS RDS
    try:
        print("[+] Conectando ao AWS RDS PostgreSQL...")
        conn = psycopg2.connect(
            host=os.getenv("DB_HOST"),
            database=os.getenv("DB_NAME", "postgres"),
            user=os.getenv("DB_USER", "postgres"),
            password=os.getenv("DB_PASSWORD"),
            port=os.getenv("DB_PORT", "5432"),
            sslmode="require"
        )
        cursor = conn.cursor()

        # Criacao da tabela threats
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

        # Upsert: insere novos registros ou atualiza existentes
        insert_query = """
        INSERT INTO threats (cve_id, descricao, nota_cvss, severidade)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (cve_id) DO UPDATE SET
            descricao = EXCLUDED.descricao,
            nota_cvss = EXCLUDED.nota_cvss,
            severidade = EXCLUDED.severidade;
        """

        for item in vulnerabilidades:
            cursor.execute(insert_query, (
                item['id_cve'],
                item['descricao'],
                float(item['nota_cvss']),
                item['severidade']
            ))

        conn.commit()
        cursor.close()
        conn.close()
        print(f"[+] SUCESSO: {len(vulnerabilidades)} registros sincronizados no AWS RDS.")

    except Exception as e:
        print(f"[-] Erro de conexao ou escrita no AWS RDS: {e}")

if __name__ == "__main__":
    upload_to_aws()