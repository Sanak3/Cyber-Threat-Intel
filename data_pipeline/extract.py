import os
import requests
from dotenv import load_dotenv

# carrega as variaveis do arquivo env para a memoria
load_dotenv()

def extrair_dados_nist():
    print("[+] Iniciando extração de dados do NIST...")

    # buscando a chave na variavel de ambiente de forma segura
    api_key = os.getenv("NIST_API_KEY")

    if not api_key:
        print("[-] ERRO CRÍTICO: Chave NIST_API_KEY não encontrada no ambiente.")
        print("[-] Verifique seu arquivo .env. Abortando execução.")
        return None

    # parametros da api puxando 2000 registros
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=2000"
    headers = {
        "apiKey": api_key
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()

        dados = response.json()
        total_cves = len(dados.get('vulnerabilities', []))
        print(f"[+] Extração concluída: {total_cves} CVEs coletados com sucesso.\n")
        return dados

    except requests.exceptions.HTTPError as err:
        print(f"[-] Erro de HTTP: {err}")
        return None
    except Exception as e:
        print(f"[-] Erro na conexão: {e}")
        return None