import os
import requests
import numpy as np
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

    # parametros da api
    # puxando 2k de registros
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=2000"
    headers = {
        "apiKey": api_key
    }

    try:
        # passando o header com a chave de forma segura
        response = requests.get(url, headers=headers)

        # levanta um erro se o status http nao for 200 ok
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


def transformar_dados(dados_brutos):
    print("[+] Iniciando transformação e análise com NumPy...")
    vulnerabilidades_limpas = []
    notas_cvss = []

    for item in dados_brutos.get("vulnerabilities", []):
        cve = item.get("cve", {})
        id_cve = cve.get("id")

        descricoes = cve.get("descriptions", [])
        descricao = next((d.get("value") for d in descricoes if d.get("lang") == "en"), "Sem descrição")

        metrics = cve.get("metrics", {})
        # a nvd usa cvssmetricv31 ou cvssmetricv30 dependendo da cve
        cvss_data = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})

        if not cvss_data:
            cvss_data = metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})

        nota = cvss_data.get("baseScore", 0.0)
        severidade = cvss_data.get("baseSeverity", "UNKNOWN")

        vulnerabilidades_limpas.append({
            "id_cve": id_cve,
            "descricao": descricao,
            "nota_cvss": nota,
            "severidade": severidade
        })

        if nota > 0.0:
            notas_cvss.append(nota)

    # analise matematica de risco com numpy
    array_notas = np.array(notas_cvss)

    if len(array_notas) > 0:
        media_risco = np.mean(array_notas)
        risco_maximo = np.max(array_notas)
        ameacas_criticas = np.sum(array_notas >= 7.0)

        print("-" * 40)
        print("  INTELIGÊNCIA DE AMEAÇAS (NumPy Engine)  ")
        print("-" * 40)
        print(f"[*] Média de Risco Global: {media_risco:.2f}")
        print(f"[*] Pior Risco Detectado:  {risco_maximo}")
        print(f"[*] Ameaças Altas/Críticas (CVSS >= 7): {ameacas_criticas}")
        print("-" * 40 + "\n")

    return vulnerabilidades_limpas


if __name__ == "__main__":
    dados_nist = extrair_dados_nist()
    if dados_nist:
        dados_tratados = transformar_dados(dados_nist)
        print(f"[+] Script finalizado. {len(dados_tratados)} registros na agulha para o banco de dados.")